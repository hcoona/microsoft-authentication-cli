"""Inactive ordinal-2 narrow 0061 evidence copy and guard metadata observation."""

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
WINDOWS_ACTION = Path('/mnt/c/Temp/azureauth-windows-slice-108/actions/0061')
OUTPUT = Path('/tmp/windows-compiler-0061-narrow-failure-offline-root-v1')
ADMISSION = Path('/tmp/windows-compiler-0061-narrow-failure-admission-root-v1.json')
TRANSPORT = {'bytes': 2852, 'sha256': 'd44d45d01696f9e5c02bd80002292b1a1f662c7db0472af20ccb3c308998b9f5'}
PRIOR_COLLECTION = {'bytes': 1554, 'sha256': '20968d35a4d61d7da2f4d02aa2dc503fba5d70e9df7e78e40418fb9709e34908'}
ACTION_SLOTS = (('result', 'result.json', 65536),
                ('bootstrapStdout', 'bootstrap-stdout.bin', 4096),
                ('bootstrapStderr', 'bootstrap-stderr.bin', 4096),
                ('bootstrapTransport', 'bootstrap-transport.json', 4096))
WINDOWS_SLOTS = (('result', 'windows-result.json', 1048576),
                 ('stdout', 'stdout.bin', 8396800),
                 ('stderr', 'stderr.bin', 8396800),
                 ('subjectStartAttempt', 'subject-start-attempt.json', 4096))
# Eight content slots total 17,924,096 bytes and 1,098 chunks of at most 16 KiB.
# Each present slot has two original reads and one private-copy readback.
# Admission (16 KiB) and inventory (64 KiB) add two reads and five chunks.
# Short reads may exhaust the fixed call/request limits and reject the copy.
LIMITS = {'fileReads': 26, 'readCalls': 3325, 'requestedBytes': 53854234,
          'returnedBytes': 53854208, 'outputBytes': 17989632,
          'pathOperations': 4096, 'writeCalls': 1102}
SMALL = 16384
INVENTORY_LIMIT = 65536
METADATA_LIMIT = 4096
TRANSPORT_LIMIT = 8192
REJECTION_REASONS = frozenset((
    'contract', 'counter-limit', 'admission-hash', 'admission-shape',
    'directory-selector', 'directory-type', 'directory-identity',
    'file-type', 'file-size', 'initial-identity', 'content-growth',
    'final-continuity', 'short-write', 'copy-readback',
    'content-absence-changed', 'original-content-changed',
    'parent-continuity', 'output-continuity', 'lock-type', 'lock-continuity',
    'inventory-size', 'inventory-readback', 'metadata-size', 'metadata-order',
    'argument-count', 'cancelled', 'deadline', 'handler-restore', 'runtime-error',
))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def fail(reason='contract'):
    error = ValueError('Fixed recovery contract rejected')
    error.rejectionReason = reason if reason in REJECTION_REASONS else 'contract'
    raise error


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail('admission-shape')
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
        fail('counter-limit')


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
        fail('directory-selector')
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
        if not stat.S_ISREG(before['mode']):
            fail('file-type')
        if not 0 <= before['bytes'] <= ceiling:
            fail('file-size')
        if expected is not None and before != expected:
            fail('initial-identity')
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
                fail('content-growth')
        after = identity(operation(state, os.fstat, fd))
        leaf = snapshot(parent, name, state)
        if total != before['bytes'] or before != after or before != leaf:
            fail('final-continuity')
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
                fail('short-write')
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
        fail('admission-shape')
    with directory(ADMISSION.parent, state) as parent:
        raw, _ = raw_read(parent, ADMISSION.name, SMALL, state)
    if digest(raw) != admitted_sha:
        fail('admission-hash')
    value = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                       parse_constant=lambda _: fail())
    fields = {'schema', 'action', 'ordinal', 'originalTransport', 'priorCollectionTransport', 'oneInvocation',
              'acceptedTarget', 'sourceSha256', 'runtimeReviewSha256'}
    if (type(value) is not dict or set(value) != fields or encoded(value) != raw or
            value['schema'] != 'compiler-0061-narrow-failure-admission-v1' or
            value['action'] != '0061' or value['originalTransport'] != TRANSPORT or
            type(value['ordinal']) is not int or value['ordinal'] != 2 or
            value['priorCollectionTransport'] != PRIOR_COLLECTION or
            value['oneInvocation'] is not True):
        fail('admission-shape')
    target = value['acceptedTarget']
    if type(target) is not dict or set(target) != {'commit', 'tree', 'protocolSha256', 'waveSha256'}:
        fail('admission-shape')
    for key, size in (('commit', 40), ('tree', 40), ('protocolSha256', 64), ('waveSha256', 64)):
        item = target[key]
        if type(item) is not str or len(item) != size or any(c not in '0123456789abcdef' for c in item):
            fail('admission-shape')
    for key in ('sourceSha256', 'runtimeReviewSha256'):
        item = value[key]
        if type(item) is not str or len(item) != 64 or any(c not in '0123456789abcdef' for c in item):
            fail('admission-shape')
    # sourceSha256 binds the activated inline bytes through independent literal
    # admission, which also binds the tracked source and both failed transports.
    # No source/runtime/transport reread, Git helper or candidate is selected here.
    return value


def optional_directory(parent, leaf, role, state, held):
    before = snapshot(parent, leaf, state) if parent is not None else None
    fd = None
    if before is not None:
        if not stat.S_ISDIR(before['mode']):
            fail('directory-type')
        fd = operation(state, os.open, leaf,
                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        held.append(fd)
        if identity(operation(state, os.fstat, fd)) != before:
            fail('directory-identity')
    return {'role': role, 'leaf': leaf, 'parent': parent, 'fd': fd, 'before': before}


def guard_metadata_checkpoint(current, point, state):
    """Two named no-follow stats only; never open or read the guard-load leaf."""
    prior = state['guardMetadata']
    if (point not in ('first', 'second') or prior[point] is not None or
            (point == 'second' and prior['first'] is None)):
        fail('metadata-order')
    info = snapshot(current['fd'], 'guard-load.json', state) if current['fd'] is not None else None
    kind = 'directory-absent' if current['fd'] is None else 'absent'
    if info is not None:
        kind = 'other'
        for predicate, name in ((stat.S_ISREG, 'regular'), (stat.S_ISDIR, 'directory'),
                                (stat.S_ISLNK, 'symlink'), (stat.S_ISFIFO, 'fifo'),
                                (stat.S_ISSOCK, 'socket'), (stat.S_ISCHR, 'character-device'),
                                (stat.S_ISBLK, 'block-device')):
            if predicate(info['mode']):
                kind = name
                break
    observation = {'directoryAbsent': current['fd'] is None, 'fileType': kind, 'identity': info}
    updated = dict(prior)
    updated[point] = observation
    if point == 'second':
        if prior['first']['identity'] is None and info is None:
            updated['comparison'] = 'absent'
        else:
            updated['comparison'] = 'same' if prior['first'] == observation else 'different'
    # Types, sizes and changes are observations, never copied-file acceptance.
    # A later content/parent continuity failure still rejects the collection.
    if len(encoded(updated)) > METADATA_LIMIT:
        fail('metadata-size')
    state['guardMetadata'] = updated


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
            if not stat.S_ISREG(lock_identity['mode']):
                fail('lock-type')
            if snapshot(root, 'action.lock', state) != lock_identity:
                fail('lock-continuity')
            check(state)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            check(state)
            with ExitStack() as stack:
                history = stack.enter_context(directory(ACTION.parent, state))
                # Every Windows ancestor is mandatory and opened without following
                # links. Only the literal 0061 child and its fixed leaves are optional.
                windows_parent = stack.enter_context(directory(WINDOWS_ACTION.parent, state))
                history_identity = identity(operation(state, os.fstat, history))
                windows_parent_identity = identity(operation(state, os.fstat, windows_parent))
                held = []
                try:
                    state.update(stage='directory-selection', role=None)
                    action = optional_directory(history, ACTION.name, 'action', state, held)
                    windows_action = optional_directory(windows_parent, WINDOWS_ACTION.name,
                                                        'windows-action', state, held)
                    directories = [action, windows_action]
                    slots = [(action, 'action-' + role, leaf, cap) for role, leaf, cap in ACTION_SLOTS]
                    slots.extend((windows_action, 'windows-action-' + role, leaf, cap)
                                 for role, leaf, cap in WINDOWS_SLOTS)
                    if len(slots) != 8 or len(directories) != 2:
                        fail('contract')
                    state.update(stage='guard-metadata-first', role='windows-action-guardLoad')
                    guard_metadata_checkpoint(windows_action, 'first', state)
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
                                fail('output-continuity')
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
                                        fail('copy-readback')
                                    row['copy'] = dict(pin, file=role + '.bin')
                                rows.append(row)
                            for current, role, leaf, cap, before, raw in selected:
                                state.update(stage='original-continuity', role=role)
                                if current['fd'] is not None:
                                    if raw is None:
                                        if snapshot(current['fd'], leaf, state) is not None:
                                            fail('content-absence-changed')
                                    else:
                                        reread, _ = raw_read(current['fd'], leaf, cap, state, before)
                                        if reread != raw:
                                            fail('original-content-changed')
                            state.update(stage='guard-metadata-second', role='windows-action-guardLoad')
                            guard_metadata_checkpoint(windows_action, 'second', state)
                            state.update(stage='directory-continuity', role=None)
                            directory_rows = []
                            for current in reversed(directories):
                                after = snapshot(current['parent'], current['leaf'], state) if current['parent'] is not None else None
                                if after != current['before']:
                                    fail('directory-identity')
                                if current['fd'] is not None and identity(operation(state, os.fstat, current['fd'])) != after:
                                    fail('directory-identity')
                                directory_rows.append({'role': current['role'], 'leaf': current['leaf'],
                                                       'before': current['before'], 'after': after,
                                                       'ancestorAbsent': current['parent'] is None})
                            with directory(ACTION.parent, state) as current_history:
                                if identity(operation(state, os.fstat, current_history)) != history_identity:
                                    fail('parent-continuity')
                            with directory(WINDOWS_ACTION.parent, state) as current_windows_parent:
                                # Rebind the mandatory parent chain after the optional
                                # action and leaf continuity checks; no enumeration.
                                if identity(operation(state, os.fstat, current_windows_parent)) != windows_parent_identity:
                                    fail('parent-continuity')
                            report = {'schema': 'compiler-0061-narrow-failure-inventory-v1',
                                      'action': '0061', 'ordinal': 2,
                                      'admission': admitted, 'directories': directory_rows,
                                      'guardMetadata': state['guardMetadata'],
                                      'files': rows, 'originalOutcome': 'failed',
                                      'originalReservationReached': 'unresolved', 'originalLifetime': 'unresolved',
                                      'graphAccepted': False, 'artifactAccepted': False,
                                      'continuation_allowed': False, 'independentObservationAccepted': False,
                                      'sourceLimits': LIMITS, 'normalCompletion': False,
                                      'finalOriginalToolExitRequired': True}
                            raw_report = encoded(report)
                            if len(raw_report) > INVENTORY_LIMIT:
                                fail('inventory-size')
                            state.update(stage='inventory-write', role=None)
                            pin = write_new(output, 'inventory.json', raw_report, state)
                            state.update(stage='inventory-readback', role=None)
                            reread, _ = raw_read(output, 'inventory.json', INVENTORY_LIMIT, state)
                            if reread != raw_report:
                                fail('inventory-readback')
                            state.update(stage='output-finalization', role=None)
                            check(state)
                            os.fsync(output)
                            check(state)
                            final_output = identity(operation(state, os.fstat, output))
                            if (snapshot(destination, OUTPUT.name, state) != final_output or
                                    any(final_output[k] != output_id[k] for k in ('device', 'inode', 'mode'))):
                                fail('output-continuity')
                            with directory(OUTPUT.parent, state) as current_destination:
                                current_identity = identity(operation(state, os.fstat, current_destination))
                                if (any(current_identity[k] != destination_identity[k] for k in ('device', 'inode', 'mode')) or
                                        snapshot(current_destination, OUTPUT.name, state) != final_output):
                                    fail('output-continuity')
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
                fail('lock-continuity')
            with directory(ROOT, state) as current_root:
                if (identity(operation(state, os.fstat, current_root)) != root_identity or
                        snapshot(current_root, 'action.lock', state) != lock_identity):
                    fail('parent-continuity')
        finally:
            os.close(lock)
    check(state)
    return pin


def main():
    began = time.monotonic_ns()
    state = dict.fromkeys(LIMITS, 0)
    state.update(deadline=began + 90_000_000_000, cancelled=False, stage='admission', role=None)
    state['guardMetadata'] = {'role': 'windows-action-guardLoad', 'leaf': 'guard-load.json',
                              'contentRead': False, 'first': None, 'second': None,
                              'comparison': 'incomplete', 'historicalCause': 'unresolved',
                              'identityAccepted': False, 'quiescenceEstablished': False}
    handlers = {}
    def cancel(_number, _frame):
        state['cancelled'] = True
    pin = None
    error_type = None
    rejection_reason = None
    try:
        if len(sys.argv) != 2:
            fail('argument-count')
        for number in (signal.SIGTERM, signal.SIGINT):
            handlers[number] = signal.signal(number, cancel)
        pin = collect(state)
        state.update(stage='finalization', role=None)
    except BaseException as error:
        error_type = type(error).__name__
        reason = getattr(error, 'rejectionReason', None)
        if type(reason) is str and reason in REJECTION_REASONS:
            rejection_reason = reason
        elif isinstance(error, TimeoutError):
            rejection_reason = 'deadline'
        elif isinstance(error, InterruptedError):
            rejection_reason = 'cancelled'
        else:
            rejection_reason = 'runtime-error'
    finally:
        for number, handler in handlers.items():
            try:
                signal.signal(number, handler)
            except BaseException:
                error_type = 'HandlerRestoreFailure'
                rejection_reason = 'handler-restore'
                state.update(stage='finalization', role=None)
    if state['cancelled'] or time.monotonic_ns() >= state['deadline']:
        error_type = 'CancelledOrLate'
        rejection_reason = 'cancelled' if state['cancelled'] else 'deadline'
    allowed = {'ValueError', 'OSError', 'FileNotFoundError', 'PermissionError',
               'BlockingIOError', 'FileExistsError', 'InterruptedError', 'TimeoutError',
               'HandlerRestoreFailure', 'CancelledOrLate'}
    frame = {'schema': 'compiler-0061-narrow-failure-transport-v1', 'ordinal': 2,
             'normalCompletion': error_type is None,
             'stage': state['stage'], 'role': state['role'],
             'exceptionType': error_type if error_type in allowed or error_type is None else 'OtherException',
             'rejectionReason': rejection_reason, 'guardMetadata': state['guardMetadata'],
             'inventory': pin, 'counters': {key: state[key] for key in LIMITS}}
    try:
        raw_frame = encoded(frame)
        if len(raw_frame) > TRANSPORT_LIMIT:
            return 1
        sys.stdout.buffer.write(raw_frame)
        sys.stdout.buffer.flush()
        check(state)
    except BaseException:
        return 1
    return 0 if error_type is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
