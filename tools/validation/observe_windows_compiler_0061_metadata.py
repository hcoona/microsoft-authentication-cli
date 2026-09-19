"""Inactive, single current metadata comparison for Windows action 0061."""

ACTIVE = False
if not ACTIVE:
    raise RuntimeError('Inactive: independent exact observation admission is required')

import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

ROOT = Path('/var/tmp/azureauth-windows-slice-108')
WINDOWS_ACTION = Path('/mnt/c/Temp/azureauth-windows-slice-108/actions/0061')
LEAF = 'windows-result.json'
PRIOR_OBSERVATION = {
    'bytes': 2094,
    'sha256': '16423d8db8796194af410cc983980fc503f5505f6538fd6be2d5ef0e5aa1a69d',
}
DATA_LIMIT = 16384
FRAME_LIMIT = 16384
PATH_LIMIT = 128
IDENTITY_FIELDS = ('device', 'inode', 'mode', 'bytes',
                   'mtimeNanoseconds', 'ctimeNanoseconds')
REJECTION_REASONS = frozenset((
    'contract', 'argument-count', 'admission-size', 'admission-hash',
    'admission-shape', 'path-limit', 'directory-selector', 'directory-type',
    'directory-identity', 'lock-type', 'lock-identity', 'leaf-absent',
    'leaf-type', 'leaf-identity-different', 'cancelled', 'deadline',
    'handler-restore', 'descriptor-close', 'runtime-error',
))


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def fail(reason='contract'):
    error = ValueError('Fixed metadata observation contract rejected')
    error.rejectionReason = reason if reason in REJECTION_REASONS else 'contract'
    raise error


def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            fail('admission-shape')
        value[key] = item
    return value


def hex_string(value, size):
    return (type(value) is str and len(value) == size and
            all(char in '0123456789abcdef' for char in value))


def admission(state):
    # Exact independent literal admission binds these argv bytes, the activated
    # inline source, the tracked source and runtime. No source or DATA file opens.
    if len(sys.argv) != 3:
        fail('argument-count')
    expected, text = sys.argv[1:]
    if not hex_string(expected, 64):
        fail('admission-shape')
    if len(text) > DATA_LIMIT:
        fail('admission-size')
    raw = text.encode('ascii')
    if hashlib.sha256(raw).hexdigest() != expected:
        fail('admission-hash')
    value = json.loads(text, object_pairs_hook=pairs,
                       parse_constant=lambda _: fail('admission-shape'))
    fields = {'schema', 'action', 'ordinal', 'oneInvocation', 'acceptedTarget',
              'sourceSha256', 'runtimeReviewSha256', 'priorObservationTransport'}
    if (type(value) is not dict or set(value) != fields or encoded(value) != raw or
            value['schema'] != 'compiler-0061-metadata-admission-v1' or
            value['action'] != '0061' or type(value['ordinal']) is not int or
            value['ordinal'] != 3 or value['oneInvocation'] is not True):
        fail('admission-shape')
    prior = value['priorObservationTransport']
    if (type(prior) is not dict or set(prior) != {'bytes', 'sha256'} or
            type(prior['bytes']) is not int or prior != PRIOR_OBSERVATION):
        fail('admission-shape')
    target = value['acceptedTarget']
    if type(target) is not dict or set(target) != {'commit', 'tree', 'protocolSha256', 'waveSha256'}:
        fail('admission-shape')
    for key, size in (('commit', 40), ('tree', 40), ('protocolSha256', 64), ('waveSha256', 64)):
        if not hex_string(target[key], size):
            fail('admission-shape')
    if any(not hex_string(value[key], 64) for key in ('sourceSha256', 'runtimeReviewSha256')):
        fail('admission-shape')
    state['admissionSha256'] = expected


def check(state):
    if state['cancelled']:
        raise InterruptedError('Metadata observation cancelled')
    if time.monotonic_ns() >= state['deadline']:
        raise TimeoutError('Original metadata observation deadline expired')


def charge_path(state):
    check(state)
    if state['pathOperations'] >= PATH_LIMIT:
        fail('path-limit')
    state['pathOperations'] += 1


def identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'bytes': info.st_size, 'mtimeNanoseconds': info.st_mtime_ns,
            'ctimeNanoseconds': info.st_ctime_ns}


def operation(state, function, *args, **kwargs):
    charge_path(state)
    value = function(*args, **kwargs)
    check(state)
    return value


def owned_open(state, held, name, flags, parent=None):
    charge_path(state)
    fd = os.open(name, flags, dir_fd=parent)
    # Register ownership before a post-open deadline/cancellation check can fail.
    held.append(fd)
    check(state)
    return fd


def named_identity(parent, name, state):
    return identity(operation(state, os.stat, name, dir_fd=parent, follow_symlinks=False))


def require_identity(state, role, checkpoint, expected, observed, reason):
    if observed != expected:
        # Keep only the already obtained pair that triggers the original stop.
        # This helper performs no observation and never resumes after a mismatch.
        if state['bindingMismatch'] is None:
            state['bindingMismatch'] = {
                'role': role, 'checkpoint': checkpoint,
                'expected': expected, 'observed': observed,
                'differentFields': [key for key in IDENTITY_FIELDS if expected[key] != observed[key]],
            }
        fail(reason)


def directory(path, state, held, components, role):
    if not path.is_absolute() or '..' in path.parts:
        fail('directory-selector')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = owned_open(state, held, '/', flags)
    before = identity(operation(state, os.fstat, fd))
    if not stat.S_ISDIR(before['mode']):
        fail('directory-type')
    components.append((None, None, fd, before, role))
    for name in path.parts[1:]:
        before = named_identity(fd, name, state)
        if not stat.S_ISDIR(before['mode']):
            fail('directory-type')
        child = owned_open(state, held, name, flags, fd)
        require_identity(state, role, 'initial-opened', before,
                         identity(operation(state, os.fstat, child)), 'directory-identity')
        components.append((fd, name, child, before, role))
        fd = child
    return fd


def file_type(info):
    if info is None:
        return None
    for predicate, name in ((stat.S_ISREG, 'regular'), (stat.S_ISDIR, 'directory'),
                            (stat.S_ISLNK, 'symlink'), (stat.S_ISFIFO, 'fifo'),
                            (stat.S_ISSOCK, 'socket'), (stat.S_ISCHR, 'character-device'),
                            (stat.S_ISBLK, 'block-device')):
        if predicate(info['mode']):
            return name
    return 'other'


def sample(parent, state, held):
    state['stage'] = 'leaf-named-stat'
    charge_path(state)
    state['namedStatCalls'] += 1
    try:
        named = identity(os.stat(LEAF, dir_fd=parent, follow_symlinks=False))
    except FileNotFoundError:
        state['comparison'] = 'absent'
        check(state)
        fail('leaf-absent')
    # Preserve returned metadata before any deadline or cancellation rejection.
    state['namedIdentity'] = named
    check(state)
    if not stat.S_ISREG(named['mode']):
        state['comparison'] = 'nonregular'
        fail('leaf-type')
    state['stage'] = 'leaf-open'
    charge_path(state)
    state['leafOpenCalls'] += 1
    fd = os.open(LEAF, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    held.append(fd)
    check(state)
    state['stage'] = 'leaf-opened-fstat'
    charge_path(state)
    state['openedFstatCalls'] += 1
    opened = identity(os.fstat(fd))
    state['openedIdentity'] = opened
    state['differentFields'] = [key for key in IDENTITY_FIELDS if named[key] != opened[key]]
    state['comparison'] = 'different' if state['differentFields'] else 'same'
    check(state)
    if not stat.S_ISREG(opened['mode']):
        fail('leaf-type')
    if state['differentFields']:
        fail('leaf-identity-different')
    state['stage'] = 'sample-complete'


def observe(state, held):
    admission(state)
    check(state)
    components = []
    state['stage'] = 'root-selection'
    root = directory(ROOT, state, held, components, 'wsl-root-chain')
    state['stage'] = 'lock-selection'
    lock_identity = named_identity(root, 'action.lock', state)
    if not stat.S_ISREG(lock_identity['mode']):
        fail('lock-type')
    lock = owned_open(state, held, 'action.lock',
                      os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, root)
    require_identity(state, 'action-lock', 'initial-opened', lock_identity,
                     identity(operation(state, os.fstat, lock)), 'lock-identity')
    operation(state, fcntl.flock, lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state['stage'] = 'windows-directory-selection'
    parent = directory(WINDOWS_ACTION, state, held, components, 'windows-action-chain')
    state['stage'] = 'component-continuity'
    for owner, name, fd, before, role in components:
        if owner is not None:
            require_identity(state, role, 'pre-sample-named', before,
                             named_identity(owner, name, state), 'directory-identity')
        require_identity(state, role, 'pre-sample-opened', before,
                         identity(operation(state, os.fstat, fd)), 'directory-identity')
    state['stage'] = 'lock-continuity'
    require_identity(state, 'action-lock', 'pre-sample-named', lock_identity,
                     named_identity(root, 'action.lock', state), 'lock-identity')
    require_identity(state, 'action-lock', 'pre-sample-opened', lock_identity,
                     identity(operation(state, os.fstat, lock)), 'lock-identity')
    sample(parent, state, held)
    # No later named stat, fstat, directory traversal or retry, on any path.


def main():
    began = time.monotonic_ns()
    state = {'deadline': began + 30_000_000_000, 'cancelled': False,
             'stage': 'admission', 'admissionSha256': None,
             'pathOperations': 0, 'namedStatCalls': 0, 'leafOpenCalls': 0,
             'openedFstatCalls': 0, 'namedIdentity': None, 'openedIdentity': None,
             'differentFields': [], 'comparison': 'incomplete', 'bindingMismatch': None}
    held = []
    handlers = {}
    error_type = None
    rejection_reason = None

    def cancel(_number, _frame):
        state['cancelled'] = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            handlers[number] = signal.signal(number, cancel)
        observe(state, held)
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
        # Closing the owned lock descriptor releases its lease. Cleanup never
        # probes a pathname, retries an operation or closes an unrelated handle.
        for fd in reversed(held):
            try:
                os.close(fd)
            except BaseException:
                error_type = 'DescriptorCloseFailure'
                rejection_reason = 'descriptor-close'
        for number, handler in handlers.items():
            try:
                signal.signal(number, handler)
            except BaseException:
                error_type = 'HandlerRestoreFailure'
                rejection_reason = 'handler-restore'
    if state['cancelled'] or time.monotonic_ns() >= state['deadline']:
        error_type = 'CancelledOrLate'
        rejection_reason = 'cancelled' if state['cancelled'] else 'deadline'
    allowed = {'ValueError', 'OSError', 'FileNotFoundError', 'PermissionError',
               'BlockingIOError', 'InterruptedError', 'TimeoutError',
               'DescriptorCloseFailure', 'HandlerRestoreFailure', 'CancelledOrLate'}
    frame = {
        'schema': 'compiler-0061-metadata-transport-v1', 'action': '0061', 'ordinal': 3,
        'normalCompletion': error_type is None, 'stage': state['stage'],
        'exceptionType': error_type if error_type in allowed or error_type is None else 'OtherException',
        'rejectionReason': rejection_reason, 'admissionSha256': state['admissionSha256'],
        'namedIdentity': state['namedIdentity'], 'openedIdentity': state['openedIdentity'],
        'namedFileType': file_type(state['namedIdentity']),
        'openedFileType': file_type(state['openedIdentity']),
        'differentFields': state['differentFields'], 'comparison': state['comparison'],
        'bindingMismatch': state['bindingMismatch'],
        'contentRead': False, 'identityAccepted': False, 'quiescenceEstablished': False,
        'historicalCause': 'unresolved', 'continuation_allowed': False,
        'independentObservationAccepted': False, 'finalOriginalToolExitRequired': True,
        'counters': {key: state[key] for key in
                     ('pathOperations', 'namedStatCalls', 'leafOpenCalls', 'openedFstatCalls')},
    }
    try:
        raw = encoded(frame)
        if len(raw) > FRAME_LIMIT:
            return 1
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        check(state)
    except BaseException:
        return 1
    return 0 if error_type is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
