"""Inactive fixed second failure observation; accepted protocol and exact review precede use."""

SECOND_OBSERVATION_ADMISSION = None
if SECOND_OBSERVATION_ADMISSION is None:
    raise RuntimeError('Inactive: no accepted second-observation admission is bound')

from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

REPOSITORY = Path('/home/shuaizhang/s/github.com/hcoona/microsoft-authentication-cli')
OUTPUT = Path('/tmp/windows-final-guard-failure-observation2-offline-v1')
ADMISSION_PATH = Path('/tmp/windows-final-guard-failure-observation2-admission-v1.json')
CANDIDATE_ACTION_NUMBER = '0054'
LIMITS = {'milliseconds': 30000, 'fileReads': 64, 'readBytes': 2097152,
          'outputBytes': 1048576, 'pathChecks': 1024, 'chunkBytes': 16384,
          'journalBytes': 262144, 'inventoryBytes': 262144}
CUMULATIVE_LIMITS = {'diagnosticInvocations': 2, 'milliseconds': 45000, 'fileReads': 128,
                     'readBytes': 4194304, 'outputBytes': 2097152, 'pathChecks': 2048}
# Preserve the first observer's path-comparison predicate; atime is observational only.
COMPARISON_FIELDS = ('status', 'type', 'device', 'inode', 'bytes', 'mode',
                     'mtimeNanoseconds', 'ctimeNanoseconds')
FIXED_INPUTS = {
    'guardFailure': {'path': '/tmp/windows-final-guard-preparation-original-call-failure-v1.json', 'bytes': 1551,
                     'sha256': '2e2b3cd67bb32d4c19ba8eb8b45b91f00a04249925fd4b1db5abe52848af385b'},
    'guardOutput': {'path': '/tmp/windows-final-guard-preparation-original-output-v1.txt', 'bytes': 169,
                    'sha256': '99263a024b0463175678aa46330b36f830f5501845ae28caa92730320b37222c'},
    'authority': {'path': '/tmp/windows-final-guard-execution-authority.json', 'bytes': 7161,
                  'sha256': 'eab860fa6249ec583e33a637c2c9b0c12ae3302d3b1d2ae4bd3278fb729a55cc'},
    'manifest': {'path': '/tmp/windows-final-guard-authority-inputs/post0053-handoff.json', 'bytes': 172997,
                 'sha256': 'e3668dc613dac94bdfeaad6dc7f64db4abf54297b5249d2b42055556a105f175'},
    'firstObserverFailure': {'path': '/tmp/windows-final-guard-failure-observer-original-call-v1.json', 'bytes': 1459,
                             'sha256': 'e10c1d0c105e8a64b6c47bfe2659979998c93548a2685da9a1eacd3c64339b7f'},
    'partialWslStarted': {'path': '/tmp/windows-final-guard-failure-observation-offline-v1/wslStarted.bin', 'bytes': 1632,
                          'sha256': '3ed0846d150abd790c9a0793df686d04a3e924eaccaca68f96f802c67ae89a07'},
    'partialWslResult': {'path': '/tmp/windows-final-guard-failure-observation-offline-v1/wslResult.bin', 'bytes': 194,
                         'sha256': 'feee51e22fab6207ddc7f9ec7c0a2db03b038a9a350cad4c1f050f7750c10d58'},
    'partialWindowsInput': {'path': '/tmp/windows-final-guard-failure-observation-offline-v1/windowsInput.bin', 'bytes': 83,
                            'sha256': '77031c737e1dc79a1201be35503c10ca9a11b29fdf592e69062d59714c157193'},
}
CONTENT = {'wslStarted': ('wsl', 'started.json', 8192), 'wslResult': ('wsl', 'result.json', 4096), 'windowsInput': ('wsl', 'windows-input.json', 2048), 'windowsStarted': ('windows', 'started.json', 8192), 'invocation': ('windows', 'invocation.json', 32768), 'authority': ('windows', 'authority.json', 16384), 'controller': ('windows', 'final-guard/controller/Invoke-WindowsFinalGuardPrepare.ps1', 65536), 'ready': ('windows', 'clock-ready.json', 2048), 'readyPending': ('windows', 'clock-ready.json.pending', 2048), 'reply': ('windows', 'clock-remaining.json', 2048), 'compiler': ('windows', 'compiler.json', 4096), 'compilerPending': ('windows', 'compiler.json.pending', 4096), 'windowsResult': ('windows', 'windows-result.json', 16384), 'windowsResultPending': ('windows', 'windows-result.json.pending', 16384)}
METADATA = {'wslDirectory': ('wsl', ''), 'windowsDirectory': ('windows', ''), 'wslCancel': ('wsl', 'cancel'), 'windowsCancel': ('windows', 'cancel'), 'hostSafetyStop': ('windows', 'temp/owned-host-safety-stop.json'), 'processSafetyStop': ('windows', 'temp/process-safety-stop.json'), 'guardBuild': ('windows', 'guard-build.json'), 'stdout': ('windows', 'stdout.bin'), 'stderr': ('windows', 'stderr.bin'), 'dll': ('windows', 'final-guard/WindowsFinalPublishGuard.dll')}


def fail(message):
    raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False) + '\n').encode('ascii')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail('Duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                      parse_constant=lambda value: fail('Nonfinite JSON value'))


def check(state):
    if state['cancelled']:
        raise InterruptedError('Collector cancelled; preserve all outputs')
    if time.monotonic_ns() >= state['deadline']:
        raise TimeoutError('Original collector deadline expired; preserve all outputs')


def shape(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        fail('Unexpected closed record fields')


def descriptor(value, expected_path):
    shape(value, ('path', 'bytes', 'sha256'))
    if value['path'] != str(expected_path) or type(value['bytes']) is not int or value['bytes'] < 0:
        fail('Fixed input descriptor changed')
    if type(value['sha256']) is not str or re.fullmatch('[0-9a-f]{64}', value['sha256']) is None:
        fail('Invalid SHA256')
    return value


def path_operation(state):
    check(state)
    state['pathChecks'] += 1
    if state['pathChecks'] > LIMITS['pathChecks']:
        fail('Path operation bound exceeded')


@contextmanager
def directory(path, state):
    # Open every component relative to the retained no-follow parent descriptor.
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        fail('Only fixed absolute paths are permitted')
    path_operation(state)
    if path in state['outputDirectories']:
        fd = os.dup(state['outputDirectories'][path])
    else:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        check(state)
        if path not in state['outputDirectories']:
            for name in path.parts[1:]:
                path_operation(state)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                check(state)
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            fail('Non-directory ancestor')
        check(state)
        yield fd
    finally:
        os.close(fd)
    check(state)


def read(path, limit, state, expected=None):
    path = Path(path)
    state['fileReads'] += 1
    if state['fileReads'] > LIMITS['fileReads']:
        fail('File read count exceeded')
    with directory(path.parent, state) as parent:
        path_operation(state)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            check(state)
            before = os.fstat(fd)
            check(state)
            if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > limit:
                fail('Nonregular or oversized input: ' + str(path))
            pieces = []
            size = 0
            while True:
                check(state)
                part = os.read(fd, min(LIMITS['chunkBytes'], limit - size + 1))
                state['readBytes'] += len(part)
                size += len(part)
                if state['readBytes'] > LIMITS['readBytes'] or size > limit:
                    fail('Read byte bound exceeded')
                check(state)
                if not part:
                    break
                pieces.append(part)
            after = os.fstat(fd)
            check(state)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or size != before.st_size:
                fail('Input changed during read')
            raw = b''.join(pieces)
        finally:
            os.close(fd)
        check(state)
    if expected is not None:
        descriptor(expected, path)
        if len(raw) != expected['bytes'] or digest(raw) != expected['sha256']:
            fail('Pinned input changed')
    return raw


def create_directory(path, state):
    if path != OUTPUT or path in state['outputDirectories']:
        fail('Only one new fixed output directory is permitted')
    with directory(path.parent, state) as parent:
        path_operation(state)
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        check(state)
        path_operation(state)
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        check(state)
        if not stat.S_ISDIR(before.st_mode):
            fail('New output directory changed')
        path_operation(state)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            check(state)
            after = os.fstat(fd)
            check(state)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                fail('New output directory identity changed')
            state['outputDirectories'][path] = fd
            fd = None
            os.fsync(parent)
            check(state)
        finally:
            if fd is not None:
                os.close(fd)


def create(path, raw, state):
    if path.parent not in state['outputDirectories']:
        fail('Output parent was not created by this collector')
    state['outputBytes'] += len(raw)
    if state['outputBytes'] > LIMITS['outputBytes']:
        fail('Output byte bound exceeded')
    with directory(path.parent, state) as parent:
        path_operation(state)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            check(state)
            offset = 0
            while offset < len(raw):
                check(state)
                count = os.write(fd, raw[offset:offset + LIMITS['chunkBytes']])
                check(state)
                if count <= 0:
                    fail('Output write made no progress')
                offset += count
            os.fchmod(fd, 0o444)
            check(state)
            os.fsync(fd)
            check(state)
        finally:
            os.close(fd)
        check(state)
        os.fsync(parent)
        check(state)
    return {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw)}


def sync_directory(path, state):
    with directory(path, state) as fd:
        check(state)
        os.fsync(fd)
        check(state)

def error_data(error):
    # Deadline, cancellation and resource exhaustion stop the whole invocation.
    if (isinstance(error, (TimeoutError, InterruptedError)) or
            error.errno in (errno.ENOMEM, errno.EMFILE, errno.ENFILE, errno.ENOSPC, errno.EDQUOT, errno.ENOBUFS)):
        raise error
    return {'status': 'unavailable', 'exceptionType': type(error).__name__, 'errno': error.errno}


def metadata(info):
    kind = ('file' if stat.S_ISREG(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode)
            else 'link' if stat.S_ISLNK(info.st_mode) else 'other')
    return {'status': 'present', 'type': kind, 'device': info.st_dev, 'inode': info.st_ino,
            'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode),
            'mtimeNanoseconds': info.st_mtime_ns, 'ctimeNanoseconds': info.st_ctime_ns,
            'atimeNanoseconds': info.st_atime_ns}


def path_snapshot(path, state):
    parent_info = None
    try:
        with directory(path.parent, state) as parent:
            parent_info = metadata(os.fstat(parent))
            path_operation(state)
            try:
                value = metadata(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
            except FileNotFoundError:
                value = {'status': 'absent'}
            check(state)
            return {'leaf': value, 'parent': parent_info}
    except FileNotFoundError:
        check(state)
        return {'leaf': {'status': 'unresolved-missing-ancestor'}, 'parent': None}
    except OSError as error:
        return {'leaf': error_data(error), 'parent': parent_info}


def start_journal(state):
    with directory(OUTPUT, state) as parent:
        path_operation(state)
        fd = os.open('events.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=parent)
        state['journalFd'] = fd
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        os.fsync(parent)
        check(state)


def event(role, phase, value, state):
    raw = canonical({'ordinal': len(state['events']) + 1, 'role': role, 'phase': phase, 'value': value})
    if state['journalBytes'] + len(raw) > LIMITS['journalBytes']:
        fail('Metadata journal byte bound exceeded')
    state['outputBytes'] += len(raw)
    if state['outputBytes'] > LIMITS['outputBytes']:
        fail('Output byte bound exceeded')
    offset = 0
    try:
        while offset < len(raw):
            check(state)
            count = os.write(state['journalFd'], raw[offset:offset + LIMITS['chunkBytes']])
            if count <= 0:
                fail('Metadata journal write made no progress')
            offset += count
        os.fsync(state['journalFd'])
    except (TimeoutError, InterruptedError):
        raise
    except OSError as error:
        # This must bypass the input-only per-role OSError recovery.
        raise RuntimeError('Metadata journal durability failed; preserve all outputs') from error
    state['journalBytes'] += len(raw)
    state['events'].append(raw)
    check(state)


def opened_snapshot(fd):
    try:
        return metadata(os.fstat(fd))
    except OSError as error:
        return error_data(error)


def read_observed(role, path, before_path, limit, state):
    state['fileReads'] += 1
    if state['fileReads'] > LIMITS['fileReads']:
        fail('File read count exceeded')
    raw = None
    opened_before = opened_after = None
    read_state = {'status': 'not-read'}
    try:
        with directory(path.parent, state) as parent:
            path_operation(state)
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                opened_before = opened_snapshot(fd)
                event(role, 'fd-before', opened_before, state)
                if (opened_before.get('type') != 'file' or
                        not 0 <= opened_before.get('bytes', -1) <= limit):
                    read_state = {'status': 'skipped', 'reason': 'opened-type-or-size'}
                elif any(opened_before.get(key) != before_path['leaf'].get(key) for key in ('device', 'inode')):
                    read_state = {'status': 'skipped', 'reason': 'opened-identity-differs'}
                else:
                    chunks = []
                    size = 0
                    read_state = {'status': 'read', 'eof': False, 'sizeExceeded': False}
                    while size <= limit:
                        check(state)
                        try:
                            part = os.read(fd, min(LIMITS['chunkBytes'], limit + 1 - size))
                        except OSError as error:
                            read_state = {'status': 'read-error', 'error': error_data(error)}
                            break
                        state['readBytes'] += len(part)
                        size += len(part)
                        if state['readBytes'] > LIMITS['readBytes']:
                            fail('Read byte bound exceeded')
                        if part:
                            chunks.append(part)
                        if not part:
                            read_state['eof'] = True
                            break
                        if size > limit:
                            read_state['sizeExceeded'] = True
                            break
                    raw = b''.join(chunks)
                    read_state.update(bytes=len(raw), sha256=digest(raw))
                event(role, 'read-result', read_state, state)
                opened_after = opened_snapshot(fd)
                event(role, 'fd-after', opened_after, state)
            finally:
                os.close(fd)
    except OSError as error:
        read_state = {'status': 'open-or-metadata-error', 'error': error_data(error)}
        event(role, 'read-unavailable', read_state, state)
    return raw, opened_before, opened_after, read_state


def changed_fields(left, right):
    if left is None or right is None:
        return ['unavailable']
    return [key for key in COMPARISON_FIELDS if left.get(key) != right.get(key)]


def observe_role(role, path, limit, state):
    before = path_snapshot(path, state)
    event(role, 'path-before', before, state)
    raw = None
    fd_before = fd_after = None
    read_state = {'status': 'metadata-only' if limit is None else 'not-read'}
    if (limit is not None and before['leaf'].get('type') == 'file' and
            0 <= before['leaf'].get('bytes', -1) <= limit):
        raw, fd_before, fd_after, read_state = read_observed(role, path, before, limit, state)
    after = path_snapshot(path, state)
    event(role, 'path-after', after, state)
    # Every obtained path/fd dictionary has been persisted before classification.
    differences = {'path': changed_fields(before['leaf'], after['leaf']),
                   'opened': changed_fields(fd_before, fd_after) if fd_before is not None else [],
                   'pathToOpened': changed_fields(before['leaf'], fd_before) if fd_before is not None else [],
                   'openedToPath': changed_fields(fd_after, after['leaf']) if fd_after is not None else []}
    anomalies = []
    if before['leaf']['status'] != 'present':
        anomalies.append('before-' + before['leaf']['status'])
    if after['leaf']['status'] != 'present':
        anomalies.append('after-' + after['leaf']['status'])
    if limit is not None and raw is None:
        anomalies.append('content-unavailable-or-ineligible')
    if any(differences.values()):
        anomalies.append('metadata-difference')
    if raw is not None and (read_state.get('status') != 'read' or read_state.get('eof') is not True or
                            read_state.get('sizeExceeded') is True or len(raw) != (fd_before or {}).get('bytes')):
        anomalies.append('incomplete-or-changing-read')
    row = {'path': str(path), 'contentLimit': limit, 'before': before, 'after': after,
           'fdBefore': fd_before, 'fdAfter': fd_after, 'read': read_state,
           'differences': differences, 'anomalies': anomalies, 'stableEvidenceAccepted': False}
    event(role, 'classification', {'differences': differences, 'anomalies': anomalies,
                                 'stableEvidenceAccepted': False}, state)
    if raw is not None:
        item = create(OUTPUT / (role + '.bin'), raw, state)
        if read(Path(item['path']), limit + 1, state, item) != raw:
            fail('Private raw copy readback changed')
        row['rawCopy'] = item
    return row


def observe(state):
    prerequisites = []
    def bind(item, expected_path, limit):
        descriptor(item, expected_path)
        raw = read(expected_path, limit, state, item)
        prerequisites.append((item, expected_path, limit, raw))
        return raw
    admission = decode(bind(SECOND_OBSERVATION_ADMISSION, ADMISSION_PATH, 16384))
    shape(admission, ('schema', 'accepted', 'scope', 'protocol', 'originalFailure', 'firstObserverFailure',
                      'authority', 'observationOrdinal', 'candidateActionNumber', 'limits', 'cumulativeLimits'))
    if (admission['schema'] != 'final-guard-failure-observation-admission-v1' or admission['accepted'] is not True or
            admission['scope'] != 'one-additional-read-only-failure-observation' or admission['observationOrdinal'] != 2 or
            admission['candidateActionNumber'] != CANDIDATE_ACTION_NUMBER or admission['limits'] != LIMITS or
            admission['cumulativeLimits'] != CUMULATIVE_LIMITS):
        fail('Second-observation admission changed')
    shape(admission['protocol'], ('commit', 'tree', 'path', 'sha256'))
    if (admission['protocol']['path'] != 'docs/research/experiments/windows-slice-validation.md' or
            any(type(admission['protocol'][key]) is not str or re.fullmatch('[0-9a-f]{40}', admission['protocol'][key]) is None
                for key in ('commit', 'tree')) or re.fullmatch('[0-9a-f]{64}', admission['protocol']['sha256']) is None):
        fail('Accepted diagnostic protocol binding is missing')
    for key, role in (('originalFailure', 'guardFailure'), ('firstObserverFailure', 'firstObserverFailure'), ('authority', 'authority')):
        if admission[key] != FIXED_INPUTS[role]:
            fail('Original failed inputs were replaced')
    values = {role: bind(item, Path(item['path']), 262144) for role, item in FIXED_INPUTS.items()}
    guard_failure = decode(values['guardFailure'])
    observer_failure = decode(values['firstObserverFailure'])
    if (guard_failure.get('exitCode') != 1 or guard_failure.get('sessionId') != 71202 or
            guard_failure.get('fullyCollected') is not True or observer_failure.get('exitCode') != 1 or
            observer_failure.get('fullyCollected') is not True or observer_failure.get('retryPermitted') is not False):
        fail('Both original failed invocations must remain failed and complete')
    if decode(values['partialWslResult']) != decode(values['guardOutput']):
        fail('Partial original result join changed')
    if decode(values['partialWindowsInput']) != {'sha256': digest(values['partialWslStarted'])}:
        fail('Partial original reservation join changed')
    manifest = decode(values['manifest'])
    authority = decode(values['authority'])
    if (authority['handoffManifest'] != FIXED_INPUTS['manifest'] or len(manifest['histories']['windows']) != 53 or
            CANDIDATE_ACTION_NUMBER != format(len(manifest['histories']['windows']) + 1, '04d')):
        fail('Original candidate action binding changed')
    roots = {'wsl': Path('/var/tmp/azureauth-windows-slice-108/windows-actions') / CANDIDATE_ACTION_NUMBER,
             'windows': Path('/mnt/c/Temp/azureauth-windows-slice-108/actions') / CANDIDATE_ACTION_NUMBER}
    create_directory(OUTPUT, state)
    start_journal(state)
    rows = {}
    for role, (platform, relative, limit) in CONTENT.items():
        rows[role] = observe_role(role, roots[platform] / relative, limit, state)
    for role, (platform, relative) in METADATA.items():
        rows[role] = observe_role(role, roots[platform] / relative, None, state)
    for item, path, limit, expected in prerequisites:
        if read(path, limit, state, item) != expected:
            fail('Private original prerequisite changed during observation')
    output_info = path_snapshot(OUTPUT, state)['leaf']
    held = os.fstat(state['outputDirectories'][OUTPUT])
    if output_info.get('device') != held.st_dev or output_info.get('inode') != held.st_ino:
        fail('Held output directory path changed')
    os.fsync(state['journalFd'])
    os.close(state['journalFd'])
    state['journalFd'] = None
    check(state)
    journal_raw = b''.join(state['events'])
    journal = {'path': str(OUTPUT / 'events.jsonl'), 'bytes': len(journal_raw), 'sha256': digest(journal_raw)}
    if read(OUTPUT / 'events.jsonl', LIMITS['journalBytes'], state, journal) != journal_raw:
        fail('Metadata journal readback changed')
    result = {'schema': 'private-final-guard-second-failure-observation-v1',
              'observationOrdinal': 2, 'candidateActionNumber': CANDIDATE_ACTION_NUMBER,
              'admission': SECOND_OBSERVATION_ADMISSION, 'journal': journal, 'roles': rows,
              'comparisonFields': COMPARISON_FIELDS, 'limits': LIMITS, 'cumulativeLimits': CUMULATIVE_LIMITS,
              'countsBeforeFinalPersistence': {key: state[key] for key in ('fileReads', 'readBytes', 'outputBytes', 'pathChecks')},
              'transportComplete': True, 'stableEvidenceAccepted': False, 'originalFailuresUnchanged': True,
              'originalRejectingRoleKnown': False, 'stageAccepted': False, 'consumptionAccepted': False,
              'processOwnershipEstablished': False, 'quiescenceEstablished': False,
              'artifactAccepted': False, 'continuation_allowed': False}
    encoded = canonical(result)
    if len(encoded) > LIMITS['inventoryBytes']:
        fail('Final observation byte bound exceeded')
    binding = create(OUTPUT / 'observation.json', encoded, state)
    if read(OUTPUT / 'observation.json', LIMITS['inventoryBytes'], state, binding) != encoded:
        fail('Final observation readback changed')
    sync_directory(OUTPUT, state)
    check(state)
    return {'schema': 'private-final-guard-second-failure-observation-result-v1', 'observation': binding,
            'transportComplete': True, 'stableEvidenceAccepted': False, 'originalFailuresUnchanged': True,
            'rolesAttempted': len(rows), 'rolesWithAnomalies': sum(bool(row['anomalies']) for row in rows.values()),
            'quiescenceEstablished': False, 'artifactAccepted': False, 'continuation_allowed': False}


def main():
    if len(sys.argv) != 1 or Path.cwd() != REPOSITORY or not sys.flags.isolated or not sys.dont_write_bytecode or sys.flags.optimize:
        fail('Fixed isolated no-bytecode, nonoptimized invocation only')
    started = time.monotonic_ns()
    state = {'started': started, 'deadline': started + LIMITS['milliseconds'] * 1000000,
             'cancelled': False, 'fileReads': 0, 'readBytes': 0, 'outputBytes': 0, 'pathChecks': 0,
             'outputDirectories': {}, 'journalFd': None, 'journalBytes': 0, 'events': []}
    handlers = {}
    def cancel(_number, _frame):
        state['cancelled'] = True
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            handlers[number] = signal.signal(number, cancel)
        result = observe(state)
    finally:
        try:
            if state['journalFd'] is not None:
                os.close(state['journalFd'])
            for fd in state['outputDirectories'].values():
                os.close(fd)
        finally:
            for number, handler in handlers.items():
                signal.signal(number, handler)
    check(state)
    print(canonical(result).decode('ascii'), end='', flush=True)
    check(state)


if __name__ == '__main__':
    main()
