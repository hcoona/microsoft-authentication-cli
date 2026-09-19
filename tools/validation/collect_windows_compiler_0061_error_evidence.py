"""Inactive ordinal-5 copy of eight fixed Windows 0061 error-evidence leaves."""

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
OUTPUT = Path('/tmp/windows-compiler-0061-opened-evidence-offline-root-v1')
ADMISSION = Path('/tmp/windows-compiler-0061-opened-evidence-admission-root-v1.json')
TRANSPORT = {'bytes': 2852, 'sha256': 'd44d45d01696f9e5c02bd80002292b1a1f662c7db0472af20ccb3c308998b9f5'}
PRIOR_COLLECTION = {'bytes': 1554, 'sha256': '20968d35a4d61d7da2f4d02aa2dc503fba5d70e9df7e78e40418fb9709e34908'}
PRIOR_NARROW_COLLECTION = {'bytes': 2094, 'sha256': '16423d8db8796194af410cc983980fc503f5505f6538fd6be2d5ef0e5aa1a69d'}
PRIOR_METADATA_OBSERVATION = {'bytes': 2531, 'sha256': 'd024efcb6f90bd48c3eb871c2fc194f504fd45d0330b471f0cffcd939a41ed1e'}
PRIOR_ERROR_COLLECTION = {'bytes': 1783, 'sha256': '8cd4245f6b7f22584ce5efd79f353fd4714a3ec6610c33a9ae1bad88697e0817'}
IDENTITY_FIELDS = ('device', 'inode', 'mode', 'bytes', 'mtimeNanoseconds', 'ctimeNanoseconds')
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
TRANSPORT_LIMIT = 8192
REJECTION_REASONS = frozenset((
    'contract', 'counter-limit', 'admission-hash', 'admission-shape',
    'directory-selector', 'directory-type', 'directory-identity',
    'file-type', 'file-size', 'initial-identity', 'content-growth',
    'final-continuity', 'short-write', 'copy-readback',
    'content-absence-changed', 'original-content-changed',
    'parent-continuity', 'output-continuity', 'lock-type', 'lock-continuity',
    'inventory-size', 'inventory-readback',
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


def reject_identity(state, role, checkpoint, expected, observed, reason):
    # The caller has already obtained and rejected this pair. Preserve only the
    # first pair, without another read, stat, open or change to comparison rules.
    if state['bindingMismatch'] is None:
        state['bindingMismatch'] = {
            'role': role, 'checkpoint': checkpoint,
            'expected': expected, 'observed': observed,
            # An observed absence has no integer fields to compare.
            'differentFields': (None if expected is None or observed is None else
                                [key for key in IDENTITY_FIELDS if expected[key] != observed[key]]),
        }
    fail(reason)


def raw_read(parent, name, ceiling, state, expected=None, allow_absent=False):
    # Charge every logical read attempt, including an absent initial open.
    charge(state, 'fileReads')
    try:
        fd = operation(state, os.open, name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=parent)
    except FileNotFoundError:
        check(state)
        if allow_absent and expected is None:
            return None, None
        raise
    try:
        before = identity(operation(state, os.fstat, fd))
        if not stat.S_ISREG(before['mode']):
            fail('file-type')
        if not 0 <= before['bytes'] <= ceiling:
            fail('file-size')
        role = state['role'] or ('admission' if state['stage'] == 'admission' else 'inventory')
        if expected is not None and before != expected:
            reject_identity(state, role, 'read-initial-opened', expected, before, 'initial-identity')
        named = snapshot(parent, name, state)
        if named != before:
            reject_identity(state, role, 'read-initial-named', before, named, 'initial-identity')
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
        if total != before['bytes']:
            fail('final-continuity')
        if before != after:
            reject_identity(state, role, 'read-final-opened', before, after, 'final-continuity')
        if before != leaf:
            reject_identity(state, role, 'read-final-named', before, leaf, 'final-continuity')
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
    fields = {'schema', 'action', 'ordinal', 'originalTransport', 'priorCollectionTransport',
              'priorNarrowCollectionTransport', 'priorMetadataObservationTransport',
              'priorErrorCollectionTransport', 'oneInvocation',
              'acceptedTarget', 'sourceSha256', 'runtimeReviewSha256'}
    if (type(value) is not dict or set(value) != fields or encoded(value) != raw or
            value['schema'] != 'compiler-0061-opened-evidence-admission-v1' or
            value['action'] != '0061' or value['originalTransport'] != TRANSPORT or
            type(value['ordinal']) is not int or value['ordinal'] != 5 or
            value['priorCollectionTransport'] != PRIOR_COLLECTION or
            value['priorNarrowCollectionTransport'] != PRIOR_NARROW_COLLECTION or
            value['priorMetadataObservationTransport'] != PRIOR_METADATA_OBSERVATION or
            value['priorErrorCollectionTransport'] != PRIOR_ERROR_COLLECTION or
            value['oneInvocation'] is not True):
        fail('admission-shape')
    for key in ('originalTransport', 'priorCollectionTransport',
                'priorNarrowCollectionTransport', 'priorMetadataObservationTransport',
                'priorErrorCollectionTransport'):
        item = value[key]
        if (type(item) is not dict or set(item) != {'bytes', 'sha256'} or
                type(item['bytes']) is not int or type(item['sha256']) is not str):
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
    # admission, which also binds the tracked source and all five prior transports.
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
        opened = identity(operation(state, os.fstat, fd))
        if opened != before:
            reject_identity(state, role, 'directory-initial-opened', before, opened, 'directory-identity')
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
            if not stat.S_ISREG(lock_identity['mode']):
                fail('lock-type')
            named_lock = snapshot(root, 'action.lock', state)
            if named_lock != lock_identity:
                reject_identity(state, 'action-lock', 'lock-initial-named',
                                lock_identity, named_lock, 'lock-continuity')
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
                    selected = []
                    for current, role, leaf, cap in slots:
                        state.update(stage='initial-read', role=role)
                        parent = current['fd']
                        before = None
                        raw = None
                        if parent is not None:
                            raw, before = raw_read(parent, leaf, cap, state, allow_absent=True)
                        selected.append((current, role, leaf, cap, before, raw))
                    state.update(stage='output-create', role=None)
                    with directory(OUTPUT.parent, state) as destination:
                        destination_identity = identity(operation(state, os.fstat, destination))
                        operation(state, os.mkdir, OUTPUT.name, mode=0o700, dir_fd=destination)
                        output = operation(state, os.open, OUTPUT.name,
                                           os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination)
                        try:
                            output_id = identity(operation(state, os.fstat, output))
                            named_output = snapshot(destination, OUTPUT.name, state)
                            if output_id != named_output:
                                reject_identity(state, 'output', 'output-initial-named',
                                                output_id, named_output, 'output-continuity')
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
                                        now = snapshot(current['fd'], leaf, state)
                                        if now is not None:
                                            reject_identity(state, role, 'read-absence-continuity',
                                                            None, now, 'content-absence-changed')
                                    else:
                                        reread, _ = raw_read(current['fd'], leaf, cap, state, before)
                                        if reread != raw:
                                            fail('original-content-changed')
                            state.update(stage='directory-continuity', role=None)
                            directory_rows = []
                            for current in reversed(directories):
                                after = snapshot(current['parent'], current['leaf'], state) if current['parent'] is not None else None
                                if after != current['before']:
                                    reject_identity(state, current['role'], 'directory-final-named',
                                                    current['before'], after, 'directory-identity')
                                if current['fd'] is not None:
                                    opened = identity(operation(state, os.fstat, current['fd']))
                                    if opened != after:
                                        reject_identity(state, current['role'], 'directory-final-opened',
                                                        after, opened, 'directory-identity')
                                directory_rows.append({'role': current['role'], 'leaf': current['leaf'],
                                                       'before': current['before'], 'after': after,
                                                       'ancestorAbsent': current['parent'] is None})
                            with directory(ACTION.parent, state) as current_history:
                                current_history_identity = identity(operation(state, os.fstat, current_history))
                                if current_history_identity != history_identity:
                                    reject_identity(state, 'action-parent', 'parent-final-opened',
                                                    history_identity, current_history_identity, 'parent-continuity')
                            with directory(WINDOWS_ACTION.parent, state) as current_windows_parent:
                                # Rebind the mandatory parent chain after the optional
                                # action and leaf continuity checks; no enumeration.
                                current_windows_identity = identity(operation(state, os.fstat, current_windows_parent))
                                if current_windows_identity != windows_parent_identity:
                                    reject_identity(state, 'windows-action-parent', 'parent-final-opened',
                                                    windows_parent_identity, current_windows_identity, 'parent-continuity')
                            report = {'schema': 'compiler-0061-opened-evidence-inventory-v1',
                                      'action': '0061', 'ordinal': 5,
                                      'admission': admitted, 'directories': directory_rows,
                                      'bindingMismatch': state['bindingMismatch'],
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
                            named_output = snapshot(destination, OUTPUT.name, state)
                            if named_output != final_output:
                                reject_identity(state, 'output', 'output-final-named',
                                                final_output, named_output, 'output-continuity')
                            if any(final_output[k] != output_id[k] for k in ('device', 'inode', 'mode')):
                                reject_identity(state, 'output', 'output-stable-fields',
                                                output_id, final_output, 'output-continuity')
                            with directory(OUTPUT.parent, state) as current_destination:
                                current_identity = identity(operation(state, os.fstat, current_destination))
                                if any(current_identity[k] != destination_identity[k] for k in ('device', 'inode', 'mode')):
                                    reject_identity(state, 'output-parent', 'output-parent-stable-fields',
                                                    destination_identity, current_identity, 'output-continuity')
                                named_output = snapshot(current_destination, OUTPUT.name, state)
                                if named_output != final_output:
                                    reject_identity(state, 'output', 'output-parent-final-named',
                                                    final_output, named_output, 'output-continuity')
                        finally:
                            os.close(output)
                        check(state)
                        os.fsync(destination)
                        check(state)
                finally:
                    for fd in reversed(held):
                        os.close(fd)
            state.update(stage='lock-finalization', role=None)
            opened_lock = identity(operation(state, os.fstat, lock))
            if opened_lock != lock_identity:
                reject_identity(state, 'action-lock', 'lock-final-opened',
                                lock_identity, opened_lock, 'lock-continuity')
            named_lock = snapshot(root, 'action.lock', state)
            if named_lock != lock_identity:
                reject_identity(state, 'action-lock', 'lock-final-named',
                                lock_identity, named_lock, 'lock-continuity')
            with directory(ROOT, state) as current_root:
                current_root_identity = identity(operation(state, os.fstat, current_root))
                if current_root_identity != root_identity:
                    reject_identity(state, 'root', 'root-final-opened',
                                    root_identity, current_root_identity, 'parent-continuity')
                named_lock = snapshot(current_root, 'action.lock', state)
                if named_lock != lock_identity:
                    reject_identity(state, 'action-lock', 'root-lock-final-named',
                                    lock_identity, named_lock, 'parent-continuity')
        finally:
            os.close(lock)
    check(state)
    return pin


def main():
    began = time.monotonic_ns()
    state = dict.fromkeys(LIMITS, 0)
    state.update(deadline=began + 90_000_000_000, cancelled=False, stage='admission', role=None)
    state['bindingMismatch'] = None
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
    frame = {'schema': 'compiler-0061-opened-evidence-transport-v1', 'ordinal': 5,
             'normalCompletion': error_type is None,
             'stage': state['stage'], 'role': state['role'],
             'exceptionType': error_type if error_type in allowed or error_type is None else 'OtherException',
             'rejectionReason': rejection_reason, 'bindingMismatch': state['bindingMismatch'],
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
