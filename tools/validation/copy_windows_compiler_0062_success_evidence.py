"""Inactive, one-attempt copy of three fixed original 0062 evidence leaves."""

ACTIVE = False
if not ACTIVE:
    raise RuntimeError('Inactive: independent exact success-evidence admission is required')

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
OUTPUT = Path('/tmp/windows-compiler-0062-success-evidence-stage1-root-v1')
SLOTS = (
    ('wsl-result', Path('/var/tmp/azureauth-windows-slice-108/windows-actions/0062/result.json'), 1048576),
    ('windows-result', Path('/mnt/c/Temp/azureauth-windows-slice-108/actions/0062/windows-result.json'), 1048576),
    ('binlog', Path('/mnt/c/Temp/azureauth-windows-slice-108/compiler-native-inputs-5033607-v6/compiler-native-inputs.binlog'), 67108864),
)
CHUNK = 65536
DATA_LIMIT = 16384
START_LIMIT = 4096
INVENTORY_LIMIT = 16384
TERMINAL_LIMIT = 8192
FRAME_LIMIT = 8192
ORIGINAL_TRANSPORT = {'bytes': 1882, 'sha256': '94e0b366303545115199ce67490ab4d0b7510f7d7a93b3e37fcf57f50e58f338'}
ORIGINAL_COMPLETION_ACCEPTANCE = {'bytes': 18085, 'sha256': '751129179c9fc62af104e3a7764bea374a5d70b170d1d96ee18c9e87f1cbecef'}
IDENTITY_FIELDS = ('device', 'inode', 'mode', 'bytes', 'mtimeNanoseconds', 'ctimeNanoseconds')
# Content: 1 + 1 + 64 MiB, two source passes and one copy readback pass.
# Each pass has at most 1,056 chunks and three additional one-byte EOF reads.
# Records are write-only: one start, one inventory and at most one terminal.
# Short reads/writes reject; no retries. These records have no readback pass.
LIMITS = {'fileReads': 9, 'readCalls': 3177, 'requestedBytes': 207618057,
          'returnedBytes': 207618048, 'outputBytes': 69234688,
          'writeCalls': 1059, 'pathOperations': 1024, 'descriptorCloses': 96}
REASONS = frozenset((
    'contract', 'argument-count', 'admission-size', 'admission-hash', 'admission-shape',
    'counter-limit', 'directory-selector', 'directory-type', 'directory-identity',
    'file-type', 'file-size', 'file-identity', 'content-length', 'copy-readback',
    'output-identity', 'short-write', 'record-size', 'lock-type', 'lock-identity',
    'cancelled', 'deadline', 'descriptor-close', 'handler-restore', 'runtime-error',
))


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def fail(reason='contract'):
    error = ValueError('Fixed success-evidence copy rejected')
    error.rejectionReason = reason if reason in REASONS else 'contract'
    raise error


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail('admission-shape')
        result[key] = value
    return result


def hex_string(value, size):
    return (type(value) is str and len(value) == size and
            all(char in '0123456789abcdef' for char in value))


def admission(state):
    # Independent exact literal admission binds argv, activated inline source,
    # tracked source, runtime and accepted original completion/lifetime evidence.
    # This collector opens none of those files and cannot grant its own admission.
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
              'sourceSha256', 'trackedSourceSha256', 'runtimeReviewSha256',
              'originalTransport', 'originalCompletionAcceptance'}
    if (type(value) is not dict or set(value) != fields or encoded(value) != raw or
            value['schema'] != 'compiler-0062-success-evidence-stage1-admission-v1' or
            value['action'] != '0062' or type(value['ordinal']) is not int or
            value['ordinal'] != 1 or value['oneInvocation'] is not True):
        fail('admission-shape')
    target = value['acceptedTarget']
    if type(target) is not dict or set(target) != {'commit', 'tree', 'protocolSha256', 'waveSha256'}:
        fail('admission-shape')
    for key, size in (('commit', 40), ('tree', 40), ('protocolSha256', 64), ('waveSha256', 64)):
        if not hex_string(target[key], size):
            fail('admission-shape')
    for key in ('sourceSha256', 'trackedSourceSha256', 'runtimeReviewSha256'):
        if not hex_string(value[key], 64):
            fail('admission-shape')
    for key, expected_original in (('originalTransport', ORIGINAL_TRANSPORT),
                                   ('originalCompletionAcceptance', ORIGINAL_COMPLETION_ACCEPTANCE)):
        original = value[key]
        if (type(original) is not dict or set(original) != {'bytes', 'sha256'} or
                type(original['bytes']) is not int or original != expected_original):
            fail('admission-shape')
    state['admissionSha256'] = expected
    return value


def check(state):
    now = time.monotonic_ns()
    if state['terminalOnly']:
        if now >= state['hardDeadline']:
            raise TimeoutError('Terminal persistence deadline expired')
    else:
        if state['cancelled']:
            raise InterruptedError('Success-evidence copy cancelled')
        if now >= state['deadline']:
            raise TimeoutError('Success-evidence copy deadline expired')


def charge(state, key, amount=1):
    check(state)
    state[key] += amount
    if state[key] > LIMITS[key]:
        fail('counter-limit')


def operation(state, function, *args, **kwargs):
    charge(state, 'pathOperations')
    value = function(*args, **kwargs)
    check(state)
    return value


def opened(state, name, flags, parent=None, mode=0o600):
    charge(state, 'pathOperations')
    fd = os.open(name, flags, mode, dir_fd=parent)
    # Own every returned descriptor before a cancellation/deadline check.
    state['held'].append(fd)
    check(state)
    return fd


def identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'bytes': info.st_size, 'mtimeNanoseconds': info.st_mtime_ns,
            'ctimeNanoseconds': info.st_ctime_ns}


def named(state, parent, leaf):
    return identity(operation(state, os.stat, leaf, dir_fd=parent, follow_symlinks=False))


def held_identity(state, fd):
    return identity(operation(state, os.fstat, fd))


def same(state, role, checkpoint, expected, observed, reason):
    if expected != observed:
        if state['bindingMismatch'] is None:
            state['bindingMismatch'] = {
                'role': role, 'checkpoint': checkpoint,
                'expected': expected, 'observed': observed,
                'differentFields': [key for key in IDENTITY_FIELDS if expected[key] != observed[key]],
            }
        fail(reason)


def directory(state, path, components, role):
    if not path.is_absolute() or '..' in path.parts:
        fail('directory-selector')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = opened(state, '/', flags)
    before = held_identity(state, fd)
    if not stat.S_ISDIR(before['mode']):
        fail('directory-type')
    components.append([None, None, fd, before, role])
    for leaf in path.parts[1:]:
        before = named(state, fd, leaf)
        if not stat.S_ISDIR(before['mode']):
            fail('directory-type')
        child = opened(state, leaf, flags, fd)
        same(state, role, 'directory-opened', before,
             held_identity(state, child), 'directory-identity')
        components.append([fd, leaf, child, before, role])
        fd = child
    return fd


def continuity(state, components):
    for parent, leaf, fd, before, role in reversed(components):
        same(state, role, 'final-held', before,
             held_identity(state, fd), 'directory-identity')
        if parent is not None:
            same(state, role, 'final-named', before,
                 named(state, parent, leaf), 'directory-identity')


def own_directory_change(state, component):
    # Only a known mkdir or exclusive file creation may change this output
    # directory's size/timestamps. Original-source identities are never rebased.
    parent, leaf, fd, before, role = component
    after = held_identity(state, fd)
    if any(before[key] != after[key] for key in ('device', 'inode', 'mode')):
        same(state, role, 'owned-directory-change', before, after, 'output-identity')
    if parent is not None:
        same(state, role, 'owned-directory-named', after,
             named(state, parent, leaf), 'output-identity')
    component[3] = after


def new_output(state, leaf):
    component = state['outputComponent']
    continuity(state, [component])
    fd = opened(state, leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                component[2])
    own_directory_change(state, component)
    before = held_identity(state, fd)
    if not stat.S_ISREG(before['mode']) or before['bytes'] != 0:
        fail('output-identity')
    same(state, leaf, 'output-initial', before,
         named(state, component[2], leaf), 'output-identity')
    return fd


def write(state, fd, raw):
    charge(state, 'writeCalls')
    charge(state, 'outputBytes', len(raw))
    count = os.write(fd, raw)
    check(state)
    if count != len(raw):
        fail('short-write')


def seal(state, fd, leaf, size):
    operation(state, os.fsync, fd)
    operation(state, os.fchmod, fd, 0o400)
    operation(state, os.fsync, fd)
    info = held_identity(state, fd)
    if (not stat.S_ISREG(info['mode']) or stat.S_IMODE(info['mode']) != 0o400 or
            info['bytes'] != size):
        fail('output-identity')
    same(state, leaf, 'sealed-named', info,
         named(state, state['outputComponent'][2], leaf), 'output-identity')
    operation(state, os.fsync, state['outputComponent'][2])
    state['outputs'].append((leaf, fd, info))
    return info


def record(state, leaf, value, ceiling):
    raw = encoded(value)
    if len(raw) > ceiling:
        fail('record-size')
    fd = new_output(state, leaf)
    write(state, fd, raw)
    seal(state, fd, leaf, len(raw))
    return {'file': leaf, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read_pass(state, fd, size, destination=None):
    charge(state, 'fileReads')
    total = 0
    result = hashlib.sha256()
    first_chunks = []
    while total < size:
        requested = min(CHUNK, size - total)
        charge(state, 'readCalls')
        charge(state, 'requestedBytes', requested)
        raw = os.read(fd, requested)
        charge(state, 'returnedBytes', len(raw))
        if len(raw) != requested:
            fail('content-length')
        result.update(raw)
        first_chunks.append(raw)
        total += len(raw)
        if destination is not None:
            write(state, destination, raw)
    charge(state, 'readCalls')
    charge(state, 'requestedBytes', 1)
    extra = os.read(fd, 1)
    charge(state, 'returnedBytes', len(extra))
    if extra:
        fail('content-length')
    return result.hexdigest(), first_chunks


def compare_passes(state, source, target, size, original_sha, first_chunks):
    # Keep only this slot's first-read chunks (at most 64 MiB), then compare both
    # later streams directly to those exact bytes. No fourth read is required.
    charge(state, 'fileReads', 2)
    source_sha = hashlib.sha256()
    copy_sha = hashlib.sha256()
    total = 0
    index = 0
    while total < size:
        requested = min(CHUNK, size - total)
        chunks = []
        for fd in (source, target):
            charge(state, 'readCalls')
            charge(state, 'requestedBytes', requested)
            raw = os.read(fd, requested)
            charge(state, 'returnedBytes', len(raw))
            if len(raw) != requested:
                fail('content-length')
            chunks.append(raw)
        if index >= len(first_chunks) or chunks[0] != first_chunks[index] or chunks[1] != first_chunks[index]:
            fail('copy-readback')
        source_sha.update(chunks[0])
        copy_sha.update(chunks[1])
        total += requested
        index += 1
    for fd in (source, target):
        charge(state, 'readCalls')
        charge(state, 'requestedBytes', 1)
        extra = os.read(fd, 1)
        charge(state, 'returnedBytes', len(extra))
        if extra:
            fail('content-length')
    if (index != len(first_chunks) or source_sha.hexdigest() != original_sha or
            copy_sha.hexdigest() != original_sha):
        fail('copy-readback')


def copy(state, role, parent, source, ceiling):
    state.update(stage='source-open', role=role)
    before = named(state, parent, source.name)
    if not stat.S_ISREG(before['mode']):
        fail('file-type')
    if not 0 < before['bytes'] <= ceiling:
        fail('file-size')
    fd = opened(state, source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, parent)
    same(state, role, 'source-opened', before,
         held_identity(state, fd), 'file-identity')
    state['sources'].append((role, parent, source.name, fd, before))
    leaf = role + '.bin'
    target = new_output(state, leaf)
    state['stage'] = 'source-copy'
    sha, first_chunks = read_pass(state, fd, before['bytes'], target)
    same(state, role, 'source-after-held', before,
         held_identity(state, fd), 'file-identity')
    same(state, role, 'source-after-named', before,
         named(state, parent, source.name), 'file-identity')
    info = seal(state, target, leaf, before['bytes'])
    operation(state, os.lseek, fd, 0, os.SEEK_SET)
    operation(state, os.lseek, target, 0, os.SEEK_SET)
    state['stage'] = 'original-reread-and-copy-readback'
    same(state, role, 'reread-before-held', before,
         held_identity(state, fd), 'file-identity')
    same(state, role, 'reread-before-named', before,
         named(state, parent, source.name), 'file-identity')
    compare_passes(state, fd, target, before['bytes'], sha, first_chunks)
    same(state, role, 'reread-after-held', before,
         held_identity(state, fd), 'file-identity')
    same(state, role, 'reread-after-named', before,
         named(state, parent, source.name), 'file-identity')
    same(state, role, 'readback-held', info,
         held_identity(state, target), 'output-identity')
    same(state, role, 'readback-named', info,
         named(state, state['outputComponent'][2], leaf), 'output-identity')
    return {'role': role, 'source': str(source), 'maximumBytes': ceiling,
            'sourceIdentity': before, 'copyIdentity': info,
            'copy': {'file': leaf, 'bytes': before['bytes'], 'sha256': sha}}


def collect(state):
    admitted = admission(state)
    state['stage'] = 'output-create'
    destination = directory(state, OUTPUT.parent, state['outputParents'], 'output-parent')
    operation(state, os.mkdir, OUTPUT.name, mode=0o700, dir_fd=destination)
    own_directory_change(state, state['outputParents'][-1])
    output = opened(state, OUTPUT.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, destination)
    output_id = held_identity(state, output)
    if not stat.S_ISDIR(output_id['mode']) or stat.S_IMODE(output_id['mode']) != 0o700:
        fail('output-identity')
    same(state, 'output', 'initial-named', output_id,
         named(state, destination, OUTPUT.name), 'output-identity')
    state['outputComponent'] = [destination, OUTPUT.name, output, output_id, 'output']
    state['stage'] = 'start-record'
    state['start'] = record(state, 'started.json', {
        'schema': 'compiler-0062-success-evidence-stage1-start-v1', 'action': '0062',
        'ordinal': 1, 'admissionSha256': state['admissionSha256'],
        'oneInvocation': True, 'normalCompletion': False,
        'originalToolExitRequired': True,
    }, START_LIMIT)
    operation(state, os.fsync, destination)
    state['stage'] = 'lock'
    root = directory(state, ROOT, state['sourceDirectories'], 'wsl-root')
    before = named(state, root, 'action.lock')
    if not stat.S_ISREG(before['mode']):
        fail('lock-type')
    lock = opened(state, 'action.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, root)
    same(state, 'action-lock', 'initial-held', before,
         held_identity(state, lock), 'lock-identity')
    operation(state, fcntl.flock, lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state['sources'].append(('action-lock', root, 'action.lock', lock, before))
    rows = []
    for role, source, ceiling in SLOTS:
        parent = directory(state, source.parent, state['sourceDirectories'], role)
        rows.append(copy(state, role, parent, source, ceiling))
    state.update(stage='original-continuity', role=None)
    for role, parent, leaf, fd, before in state['sources']:
        same(state, role, 'final-held', before, held_identity(state, fd), 'file-identity')
        same(state, role, 'final-named', before, named(state, parent, leaf), 'file-identity')
    continuity(state, state['sourceDirectories'])
    continuity(state, state['outputParents'])
    state['stage'] = 'inventory'
    state['inventory'] = record(state, 'inventory.json', {
        'schema': 'compiler-0062-success-evidence-stage1-inventory-v1',
        'action': '0062', 'ordinal': 1, 'admission': admitted,
        'admissionSha256': state['admissionSha256'], 'files': rows,
        'hashMeaning': 'Retained copy-time snapshot; not an original runtime hash.',
        'contentInterpretationPerformed': False, 'graphAccepted': False,
        'artifactAccepted': False, 'continuation_allowed': False,
        'normalCompletion': False, 'originalToolExitRequired': True, 'limits': LIMITS,
    }, INVENTORY_LIMIT)
    state['stage'] = 'output-continuity'
    for leaf, fd, before in state['outputs']:
        same(state, leaf, 'final-held', before, held_identity(state, fd), 'output-identity')
        same(state, leaf, 'final-named', before, named(state, output, leaf), 'output-identity')
    continuity(state, state['outputParents'] + [state['outputComponent']])
    check(state)


def classify(error):
    reason = getattr(error, 'rejectionReason', None)
    if reason in REASONS:
        return reason
    if isinstance(error, TimeoutError):
        return 'deadline'
    if isinstance(error, InterruptedError):
        return 'cancelled'
    return 'runtime-error'


def main():
    began = time.monotonic_ns()
    state = dict.fromkeys(LIMITS, 0)
    state.update(deadline=began + 120_000_000_000, hardDeadline=began + 122_000_000_000,
                 cancelled=False, terminalOnly=False, stage='admission', role=None,
                 held=[], sources=[], outputs=[], sourceDirectories=[], outputParents=[],
                 outputComponent=None, admissionSha256=None, bindingMismatch=None,
                 start=None, inventory=None)
    handlers = {}
    reason = None
    terminal = None

    def cancel(_number, _frame):
        state['cancelled'] = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            handlers[number] = signal.signal(number, cancel)
        collect(state)
    except BaseException as error:
        reason = classify(error)
    if reason is None:
        try:
            check(state)
        except BaseException as error:
            reason = classify(error)
    # After a stop, only bounded terminal persistence and descriptor closure are
    # allowed. No original path, lock or source content is observed again.
    state['terminalOnly'] = reason is not None
    if state['start'] is not None:
        try:
            terminal = record(state, 'complete.json' if reason is None else 'failure.json', {
                'schema': 'compiler-0062-success-evidence-stage1-terminal-v1',
                'action': '0062', 'ordinal': 1, 'admissionSha256': state['admissionSha256'],
                'normalCompletionCandidate': reason is None, 'originalToolExitRequired': True,
                'stage': state['stage'], 'role': state['role'], 'rejectionReason': reason,
                'bindingMismatch': state['bindingMismatch'], 'inventory': state['inventory'],
                'countersBeforeTerminal': {key: state[key] for key in LIMITS},
            }, TERMINAL_LIMIT)
        except BaseException as error:
            reason = reason or classify(error)
    # Every owned descriptor is closed once, including when post-open checks fail.
    for fd in reversed(state['held']):
        state['descriptorCloses'] += 1
        try:
            if state['descriptorCloses'] > LIMITS['descriptorCloses']:
                reason = reason or 'counter-limit'
            os.close(fd)
        except BaseException:
            reason = reason or 'descriptor-close'
    for number, handler in handlers.items():
        try:
            signal.signal(number, handler)
        except BaseException:
            reason = reason or 'handler-restore'
    if state['cancelled'] or time.monotonic_ns() >= state['deadline']:
        reason = reason or ('cancelled' if state['cancelled'] else 'deadline')
    frame = {'schema': 'compiler-0062-success-evidence-stage1-transport-v1',
             'action': '0062', 'ordinal': 1, 'normalCompletion': reason is None,
             'stage': state['stage'], 'role': state['role'], 'rejectionReason': reason,
             'admissionSha256': state['admissionSha256'], 'start': state['start'],
             'inventory': state['inventory'], 'terminal': terminal,
             'bindingMismatch': state['bindingMismatch'],
             'counters': {key: state[key] for key in LIMITS},
             'graphAccepted': False, 'artifactAccepted': False, 'continuation_allowed': False}
    try:
        raw = encoded(frame)
        if len(raw) > FRAME_LIMIT or time.monotonic_ns() >= state['hardDeadline']:
            return 1
        if os.write(1, raw) != len(raw):
            return 1
    except BaseException:
        return 1
    if time.monotonic_ns() >= state['deadline'] or state['cancelled']:
        return 1
    return 0 if reason is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
