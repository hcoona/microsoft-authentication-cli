"""Inactive, one-use fixed 0061 failure-evidence copy; no diagnostic retry."""

ACTIVE = False
if not ACTIVE:
    raise RuntimeError('Inactive: independent exact recovery admission is required')

import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
from contextlib import contextmanager, ExitStack

ROOT = Path('/var/tmp/azureauth-windows-slice-108')
ACTION = ROOT / 'windows-actions' / '0061'
HELPERS = Path('/var/tmp/azureauth-compiler-verifiers-108-0061')
WINDOWS_ACTION = Path('/mnt/c/Temp/azureauth-windows-slice-108/actions/0061')
OUTPUT = Path('/tmp/windows-compiler-0061-failure-offline-root-v1')
ADMISSION = Path('/tmp/windows-compiler-0061-failure-recovery-admission-root-v1.json')
TRANSPORT = {'bytes': 2852, 'sha256': 'd44d45d01696f9e5c02bd80002292b1a1f662c7db0472af20ccb3c308998b9f5'}
ACTION_SLOTS = (('started', 'started.json', 8192),
                ('reservationFailure', 'reservation-failure.json', 4096),
                ('result', 'result.json', 65536),
                ('invocation', 'invocation.json', 1114112),
                ('controllerStartAttempt', 'controller-start-attempt.json', 4096),
                ('bootstrapStdout', 'bootstrap-stdout.bin', 4096),
                ('bootstrapStderr', 'bootstrap-stderr.bin', 4096),
                ('bootstrapTransport', 'bootstrap-transport.json', 4096))
HELPER_SLOTS = (('started', 'started.json', 4096),
                ('identity', 'identity.json', 4096),
                ('result', 'result.json', 32768))
WINDOWS_SLOTS = (('started', 'started.json', 8192),
                 ('invocation', 'invocation.json', 1114112),
                 ('clockReady', 'clock-ready.json', 4096),
                 ('clockRemaining', 'clock-remaining.json', 4096),
                 ('guardLoad', 'guard-load.json', 16384),
                 ('subjectStartAttempt', 'subject-start-attempt.json', 4096),
                 ('result', 'windows-result.json', 1048576),
                 ('stdout', 'stdout.bin', 8396800),
                 ('stderr', 'stderr.bin', 8396800))
# Forty-two slots total 20,533,248 bytes and 1,274 chunks of at most 16 KiB.
# Each present slot has two original reads and one private-copy readback.
# Admission (16 KiB) and inventory (64 KiB) add two reads and five chunks.
# Short reads may exhaust the fixed call/request limits and reject the copy.
LIMITS = {'fileReads': 128, 'readCalls': 3955, 'requestedBytes': 61681792,
          'returnedBytes': 61681664, 'outputBytes': 20598784,
          'pathOperations': 4096, 'writeCalls': 1278}
SMALL = 16384
INVENTORY_LIMIT = 65536


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def fail():
    raise ValueError('Fixed recovery contract rejected')


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail()
        result[key] = value
    return result


def check(state):
    if state['cancelled']:
        raise InterruptedError('Recovery cancelled')
    if time.monotonic_ns() >= state['deadline']:
        raise TimeoutError('Original recovery deadline expired')


def charge(state, key, amount=1):
    check(state)
    state[key] += amount
    if state[key] > LIMITS[key]:
        fail()


def identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'bytes': info.st_size, 'mtimeNanoseconds': info.st_mtime_ns,
            'ctimeNanoseconds': info.st_ctime_ns}


def operation(state, function, *args, **kwargs):
    charge(state, 'pathOperations')
    value = function(*args, **kwargs)
    check(state)
    return value


@contextmanager
def directory(path, state):
    if not path.is_absolute() or '..' in path.parts:
        fail()
    fd = operation(state, os.open, '/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = operation(state, os.open, name,
                              os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)
    check(state)


def snapshot(parent, name, state):
    try:
        return identity(operation(state, os.stat, name, dir_fd=parent, follow_symlinks=False))
    except FileNotFoundError:
        check(state)
        return None


def raw_read(parent, name, ceiling, state, expected=None):
    charge(state, 'fileReads')
    fd = operation(state, os.open, name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                   dir_fd=parent)
    try:
        before = identity(operation(state, os.fstat, fd))
        if (not stat.S_ISREG(before['mode']) or not 0 <= before['bytes'] <= ceiling or
                (expected is not None and before != expected)):
            fail()
        chunks = []
        total = 0
        while True:
            requested = min(SMALL, before['bytes'] - total) if total < before['bytes'] else 1
            charge(state, 'readCalls')
            charge(state, 'requestedBytes', requested)
            chunk = os.read(fd, requested)
            charge(state, 'returnedBytes', len(chunk))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > before['bytes']:
                fail()
        after = identity(operation(state, os.fstat, fd))
        leaf = snapshot(parent, name, state)
        if total != before['bytes'] or before != after or before != leaf:
            fail()
        return b''.join(chunks), before
    finally:
        os.close(fd)


def write_new(parent, name, raw, state):
    charge(state, 'outputBytes', len(raw))
    fd = operation(state, os.open, name,
                   os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        offset = 0
        while offset < len(raw):
            check(state)
            chunk = raw[offset:offset + SMALL]
            charge(state, 'writeCalls')
            count = os.write(fd, chunk)
            check(state)
            if count != len(chunk):
                fail()
            offset += count
        check(state)
        os.fsync(fd)
        check(state)
        os.fchmod(fd, 0o444)
        check(state)
        os.fsync(fd)
        check(state)
    finally:
        os.close(fd)
    check(state)
    os.fsync(parent)
    check(state)
    return {'bytes': len(raw), 'sha256': digest(raw)}


def admission(state, admitted_sha):
    if len(admitted_sha) != 64 or any(c not in '0123456789abcdef' for c in admitted_sha):
        fail()
    with directory(ADMISSION.parent, state) as parent:
        raw, _ = raw_read(parent, ADMISSION.name, SMALL, state)
    if digest(raw) != admitted_sha:
        fail()
    value = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                       parse_constant=lambda _: fail())
    fields = {'schema', 'action', 'originalTransport', 'oneInvocation',
              'acceptedTarget', 'sourceSha256', 'runtimeReviewSha256'}
    if (type(value) is not dict or set(value) != fields or encoded(value) != raw or
            value['schema'] != 'compiler-0061-fixed-receipt-recovery-admission-v1' or
            value['action'] != '0061' or value['originalTransport'] != TRANSPORT or
            value['oneInvocation'] is not True):
        fail()
    target = value['acceptedTarget']
    if type(target) is not dict or set(target) != {'commit', 'tree', 'protocolSha256', 'waveSha256'}:
        fail()
    for key, size in (('commit', 40), ('tree', 40), ('protocolSha256', 64), ('waveSha256', 64)):
        item = target[key]
        if type(item) is not str or len(item) != size or any(c not in '0123456789abcdef' for c in item):
            fail()
    for key in ('sourceSha256', 'runtimeReviewSha256'):
        item = value[key]
        if type(item) is not str or len(item) != 64 or any(c not in '0123456789abcdef' for c in item):
            fail()
    # Independent literal admission binds this DATA to source/runtime and failure.
    # No source/runtime/transport reread, Git helper or candidate is selected here.
    return value


def optional_directory(parent, leaf, role, state, held):
    before = snapshot(parent, leaf, state) if parent is not None else None
    fd = None
    if before is not None:
        if not stat.S_ISDIR(before['mode']):
            fail()
        fd = operation(state, os.open, leaf,
                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        held.append(fd)
        if identity(operation(state, os.fstat, fd)) != before:
            fail()
    return {'role': role, 'leaf': leaf, 'parent': parent, 'fd': fd, 'before': before}


def collect(state):
    state.update(stage='admission', role=None)
    admitted = admission(state, sys.argv[1])
    state.update(stage='lock', role=None)
    with directory(ROOT, state) as root:
        root_identity = identity(operation(state, os.fstat, root))
        lock = operation(state, os.open, 'action.lock',
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        try:
            lock_identity = identity(operation(state, os.fstat, lock))
            if not stat.S_ISREG(lock_identity['mode']) or snapshot(root, 'action.lock', state) != lock_identity:
                fail()
            check(state)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            check(state)
            with ExitStack() as stack:
                history = stack.enter_context(directory(ACTION.parent, state))
                helper_parent = stack.enter_context(directory(HELPERS.parent, state))
                # Every Windows ancestor is mandatory and opened without following
                # links. Only the literal 0061 child and its fixed leaves are optional.
                windows_parent = stack.enter_context(directory(WINDOWS_ACTION.parent, state))
                history_identity = identity(operation(state, os.fstat, history))
                helper_parent_identity = identity(operation(state, os.fstat, helper_parent))
                windows_parent_identity = identity(operation(state, os.fstat, windows_parent))
                held = []
                try:
                    state.update(stage='directory-selection', role=None)
                    action = optional_directory(history, ACTION.name, 'action', state, held)
                    helper = optional_directory(helper_parent, HELPERS.name, 'helpers', state, held)
                    windows_action = optional_directory(windows_parent, WINDOWS_ACTION.name,
                                                        'windows-action', state, held)
                    directories = [action, helper, windows_action]
                    slots = [(action, 'action-' + role, leaf, cap) for role, leaf, cap in ACTION_SLOTS]
                    slots.append((helper, 'helpers-started', 'started.json', 4096))
                    for number in range(1, 9):
                        name = f'{number:02d}'
                        current = optional_directory(helper['fd'], name, 'helper-' + name, state, held)
                        directories.append(current)
                        slots.extend((current, 'helper-' + name + '-' + role, leaf, cap)
                                     for role, leaf, cap in HELPER_SLOTS)
                    slots.extend((windows_action, 'windows-action-' + role, leaf, cap)
                                 for role, leaf, cap in WINDOWS_SLOTS)
                    if len(slots) != 42 or len(directories) != 11:
                        fail()
                    selected = []
                    for current, role, leaf, cap in slots:
                        state.update(stage='initial-read', role=role)
                        parent = current['fd']
                        before = snapshot(parent, leaf, state) if parent is not None else None
                        raw = None
                        if before is not None:
                            raw, before = raw_read(parent, leaf, cap, state, before)
                        selected.append((current, role, leaf, cap, before, raw))
                    state.update(stage='output-create', role=None)
                    with directory(OUTPUT.parent, state) as destination:
                        destination_identity = identity(operation(state, os.fstat, destination))
                        operation(state, os.mkdir, OUTPUT.name, mode=0o700, dir_fd=destination)
                        output = operation(state, os.open, OUTPUT.name,
                                           os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination)
                        try:
                            output_id = identity(operation(state, os.fstat, output))
                            if output_id != snapshot(destination, OUTPUT.name, state):
                                fail()
                            rows = []
                            for current, role, leaf, cap, before, raw in selected:
                                row = {'role': role, 'directoryRole': current['role'], 'leaf': leaf,
                                       'maximumBytes': cap, 'initialIdentity': before,
                                       'status': ('directory-absent' if current['fd'] is None else
                                                  'absent' if raw is None else 'copied')}
                                if raw is not None:
                                    state.update(stage='copy-write', role=role)
                                    pin = write_new(output, role + '.bin', raw, state)
                                    state.update(stage='copy-readback', role=role)
                                    reread, _ = raw_read(output, role + '.bin', cap, state)
                                    if reread != raw:
                                        fail()
                                    row['copy'] = dict(pin, file=role + '.bin')
                                rows.append(row)
                            for current, role, leaf, cap, before, raw in selected:
                                state.update(stage='original-continuity', role=role)
                                if current['fd'] is not None:
                                    if raw is None:
                                        if snapshot(current['fd'], leaf, state) is not None:
                                            fail()
                                    else:
                                        reread, _ = raw_read(current['fd'], leaf, cap, state, before)
                                        if reread != raw:
                                            fail()
                            state.update(stage='directory-continuity', role=None)
                            directory_rows = []
                            for current in reversed(directories):
                                after = snapshot(current['parent'], current['leaf'], state) if current['parent'] is not None else None
                                if after != current['before']:
                                    fail()
                                if current['fd'] is not None and identity(operation(state, os.fstat, current['fd'])) != after:
                                    fail()
                                directory_rows.append({'role': current['role'], 'leaf': current['leaf'],
                                                       'before': current['before'], 'after': after,
                                                       'ancestorAbsent': current['parent'] is None})
                            with directory(ACTION.parent, state) as current_history:
                                if identity(operation(state, os.fstat, current_history)) != history_identity:
                                    fail()
                            with directory(HELPERS.parent, state) as current_parent:
                                # Unrelated /var/tmp entries may change; bind only its directory identity.
                                now = identity(operation(state, os.fstat, current_parent))
                                if any(now[k] != helper_parent_identity[k] for k in ('device', 'inode', 'mode')):
                                    fail()
                            with directory(WINDOWS_ACTION.parent, state) as current_windows_parent:
                                # Rebind the mandatory parent chain after the optional
                                # action and leaf continuity checks; no enumeration.
                                if identity(operation(state, os.fstat, current_windows_parent)) != windows_parent_identity:
                                    fail()
                            report = {'schema': 'compiler-0061-fixed-receipt-recovery-inventory-v1',
                                      'action': '0061', 'admission': admitted, 'directories': directory_rows,
                                      'files': rows, 'originalOutcome': 'failed',
                                      'originalReservationReached': 'unresolved', 'originalLifetime': 'unresolved',
                                      'graphAccepted': False, 'artifactAccepted': False,
                                      'continuation_allowed': False, 'independentObservationAccepted': False,
                                      'sourceLimits': LIMITS, 'normalCompletion': False,
                                      'finalOriginalToolExitRequired': True}
                            raw_report = encoded(report)
                            if len(raw_report) > INVENTORY_LIMIT:
                                fail()
                            state.update(stage='inventory-write', role=None)
                            pin = write_new(output, 'inventory.json', raw_report, state)
                            state.update(stage='inventory-readback', role=None)
                            reread, _ = raw_read(output, 'inventory.json', INVENTORY_LIMIT, state)
                            if reread != raw_report:
                                fail()
                            state.update(stage='output-finalization', role=None)
                            check(state)
                            os.fsync(output)
                            check(state)
                            final_output = identity(operation(state, os.fstat, output))
                            if (snapshot(destination, OUTPUT.name, state) != final_output or
                                    any(final_output[k] != output_id[k] for k in ('device', 'inode', 'mode'))):
                                fail()
                            with directory(OUTPUT.parent, state) as current_destination:
                                current_identity = identity(operation(state, os.fstat, current_destination))
                                if (any(current_identity[k] != destination_identity[k] for k in ('device', 'inode', 'mode')) or
                                        snapshot(current_destination, OUTPUT.name, state) != final_output):
                                    fail()
                        finally:
                            os.close(output)
                        check(state)
                        os.fsync(destination)
                        check(state)
                finally:
                    for fd in reversed(held):
                        os.close(fd)
            state.update(stage='lock-finalization', role=None)
            if (identity(operation(state, os.fstat, lock)) != lock_identity or
                    snapshot(root, 'action.lock', state) != lock_identity):
                fail()
            with directory(ROOT, state) as current_root:
                if (identity(operation(state, os.fstat, current_root)) != root_identity or
                        snapshot(current_root, 'action.lock', state) != lock_identity):
                    fail()
        finally:
            os.close(lock)
    check(state)
    return pin


def main():
    began = time.monotonic_ns()
    state = dict.fromkeys(LIMITS, 0)
    state.update(deadline=began + 90_000_000_000, cancelled=False, stage='admission', role=None)
    handlers = {}
    def cancel(_number, _frame):
        state['cancelled'] = True
    pin = None
    error_type = None
    try:
        if len(sys.argv) != 2:
            fail()
        for number in (signal.SIGTERM, signal.SIGINT):
            handlers[number] = signal.signal(number, cancel)
        pin = collect(state)
        state.update(stage='finalization', role=None)
    except BaseException as error:
        error_type = type(error).__name__
    finally:
        for number, handler in handlers.items():
            try:
                signal.signal(number, handler)
            except BaseException:
                error_type = 'HandlerRestoreFailure'
                state.update(stage='finalization', role=None)
    if state['cancelled'] or time.monotonic_ns() >= state['deadline']:
        error_type = 'CancelledOrLate'
    allowed = {'ValueError', 'OSError', 'FileNotFoundError', 'PermissionError',
               'BlockingIOError', 'FileExistsError', 'InterruptedError', 'TimeoutError',
               'HandlerRestoreFailure', 'CancelledOrLate'}
    frame = {'schema': 'compiler-0061-fixed-receipt-recovery-transport-v1',
             'normalCompletion': error_type is None,
             'stage': state['stage'], 'role': state['role'],
             'exceptionType': error_type if error_type in allowed or error_type is None else 'OtherException',
             'inventory': pin, 'counters': {key: state[key] for key in LIMITS}}
    try:
        sys.stdout.buffer.write(encoded(frame))
        sys.stdout.buffer.flush()
        check(state)
    except BaseException:
        return 1
    return 0 if error_type is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
