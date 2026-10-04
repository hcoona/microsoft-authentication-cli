"""Collect fixed public copy results; every call needs admission."""
import hashlib
import json
import os
import resource
import re
import signal
import stat
import sys
import time

ADMISSION = None
RECOVERY = '/home/shuaizhang/.local/state/azureauth-108-recovery-20260929'
STAGE = '/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0193'
FILES = (('launcher.jsonl', 65536), ('materialization-result.json', 262144),
         ('launcher.stdout.bin', 65536), ('launcher.stderr.bin', 65536))
EVENT_FIELDS = {
    'bootstrap': 'pid creationFileTime session jobName authoritySha256',
    'job-ready': 'queryAndTerminateAccess',
    'root-suspended': 'pid creationFileTime session inJob',
    'resume-requested': '',
    'resumed': '',
    'completed': 'rootExited rootExitCode activeProcesses totalProcesses stdoutEof stderrEof capturedBytes',
    'cleanup': 'terminationRequested terminationSucceeded terminationError rootExited activeProcesses stdoutEof stderrEof capturedBytes failureType',
    'failed': 'stage resumed failureType hresult nativeError',
    'launcher-exit': 'passed capturedBytes',
}
CAPTURE_FIELDS = ('stream initialized readBytes confirmedFlushedBytes eof overflowDetected '
                  'failureStage failureType failureHresult failureNativeError closeFailureType')
BOOL_FIELDS = set(('queryAndTerminateAccess inJob rootExited stdoutEof stderrEof '
                   'terminationRequested terminationSucceeded resumed passed initialized '
                   'eof overflowDetected').split())
INT_FIELDS = set(('pid session rootExitCode activeProcesses totalProcesses capturedBytes '
                  'terminationError hresult nativeError readBytes confirmedFlushedBytes '
                  'failureHresult failureNativeError').split())
NULLABLE_FIELDS = {'activeProcesses', 'nativeError', 'failureHresult', 'failureNativeError'}
EXCEPTION_TYPES = {
    'ArgumentException', 'ArgumentOutOfRangeException', 'InvalidOperationException',
    'Win32Exception', 'IOException', 'UnauthorizedAccessException', 'TimeoutException',
    'ObjectDisposedException', 'NotSupportedException', 'OverflowException',
    'OutOfMemoryException', 'FileNotFoundException', 'DirectoryNotFoundException',
    'SecurityException', 'CryptographicException',
}
PHASES = {
    'inputs', 'job-create', 'capture-create', 'process-create', 'resume', 'running',
    'pipe-peek', 'output-limit', 'pipe-read', 'file-write', 'file-flush',
    'writer-close', 'reader-close', 'file-close',
}


def full9(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate diagnostic key')
            result[key] = value
        return result
    def reject(_):
        raise ValueError('Noninteger diagnostic number')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                      parse_float=reject, parse_constant=reject)


def journal_record(record):
    if type(record) is not dict or type(record.get('event')) is not str:
        raise ValueError('Diagnostic event shape')
    event = record['event']
    fields = EVENT_FIELDS.get(event)
    if event == 'capture':
        fields = CAPTURE_FIELDS if record.get('initialized') is True else 'stream initialized'
    if fields is None or set(record) != {'event', 'elapsedMilliseconds', *fields.split()}:
        raise ValueError('Diagnostic event fields')
    elapsed = record['elapsedMilliseconds']
    if type(elapsed) is not int or not 0 <= elapsed <= 340000:
        raise ValueError('Diagnostic event time')
    for key in fields.split():
        value = record[key]
        if key in BOOL_FIELDS:
            valid = type(value) is bool
        elif key in INT_FIELDS:
            valid = ((value is None and key in NULLABLE_FIELDS) or
                     (type(value) is int and -(1 << 63) <= value < (1 << 64)))
        elif key == 'creationFileTime':
            valid = type(value) is str and value.isascii() and value.isdecimal() and 1 <= len(value) <= 20
        elif key == 'jobName':
            valid = value == 'Local\\azureauth-controller-108-0193-' + ADMISSION['nonce']
        elif key == 'authoritySha256':
            valid = value == ADMISSION['authoritySha256']
        elif key == 'stream':
            valid = value in ('stdout', 'stderr')
        elif key in ('failureType', 'closeFailureType'):
            valid = value is None or (type(value) is str and value in EXCEPTION_TYPES)
        elif key in ('stage', 'failureStage'):
            valid = (value is None and key == 'failureStage') or (type(value) is str and value in PHASES)
        else:
            valid = False
        if not valid:
            raise ValueError('Diagnostic public value')
    return record


def exact_int(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def output_sealing(diagnostic, maximum, completed, qualified=False):
    stage = diagnostic['outputStage']
    changed, sealed = diagnostic['firstReadChangeCount'], diagnostic['sealedOutputs']
    if (not exact_int(stage, 0, 3) or not exact_int(changed, 0, maximum) or
            not exact_int(sealed, completed, min(maximum, completed + 1)) or
            changed > sealed + (1 if stage in (1, 2) else 0) or
            (stage == 3 and sealed == 0) or
            (diagnostic['nativePhase'] in (220, 270, 271, 272, 273, 274) and stage != 1) or
            (diagnostic['nativePhase'] in (230, 240, 280, 281, 282, 283, 284) and stage != 2)):
        raise ValueError('Public output sealing context')
    if qualified and (not exact_int(diagnostic['outputChangeTimeDifferenceCount'], 0, 32768) or
            diagnostic['outputChangeTimeDifferenceCount'] > diagnostic['metadata']):
        raise ValueError('Public output ChangeTime observation context')


def public_receipt(result):
    keys = {'schema', 'passed', 'authoritySha256', 'target', 'rows', 'failure',
            'allHandlesClosed', 'noExperimentLive', 'productStarted', 'accountAccess', 'diagnostic'}
    counters = {'opens': 4097, 'metadata': 32770, 'reads': 32769, 'writes': 32769,
                'requestedReadBytes': 469762048 + 65536, 'writtenBytes': 134217728 + 65536}
    if type(result) is not dict or set(result) not in (keys, keys | {'counts'}):
        raise ValueError('Copy receipt fields')
    if (result['schema'] not in ('selected-account-public-materialization-v2',
                                'selected-account-public-materialization-v3',
                                'selected-account-public-materialization-v4') or
            result['authoritySha256'] != ADMISSION['authoritySha256'] or
            result['target'] != 'C:\\Temp\\azureauth-windows-slice-108\\confidential-native-account-v5' or
            type(result['rows']) is not list or len(result['rows']) not in (0, 200) or
            result['failure'] not in ('admission', 'native-source', 'create', 'copy', 'none') or
            any(type(result[key]) is not bool for key in
                ('passed', 'allHandlesClosed', 'noExperimentLive', 'productStarted', 'accountAccess')) or
            result['productStarted'] or result['accountAccess'] or result['noExperimentLive']):
        raise ValueError('Copy receipt values')
    phases = {0, 100, 200, 301, 302, 303, 304, 305, 306, 307, 308, 309,
              310, 311, 313, 315, 317, 318, 405, 500}
    phases.update(base + offset for base in (100, 200) for offset in (1, 2, 3, 4, 5, 6, 7, 9))
    phases.update(base + offset for base in (170, 270, 320, 400) for offset in range(5))
    qualified = result['schema'] == 'selected-account-public-materialization-v4'
    establishing = result['schema'] in ('selected-account-public-materialization-v3',
                                       'selected-account-public-materialization-v4')
    if establishing:
        phases.update((220, 230, 240))
        phases.update(280 + offset for offset in range(5))
    diagnostic = result['diagnostic']
    if diagnostic is not None:
        limits = {'copyOrdinal': 200, 'completedCopies': 200, 'wrapperPhase': 4,
                  'heldOrdinal': 400, 'errorKind': 3, **counters}
        fields = {*limits, 'nativePhase', 'errorCode'}
        shapes = (fields, fields | {'identityMismatchMask', 'snapshotMismatchMask'})
        if establishing:
            shapes = (fields | {'identityMismatchMask', 'snapshotMismatchMask',
                               'outputStage', 'firstReadChangeCount', 'sealedOutputs'},)
        if qualified:
            shapes = (shapes[0] | {'outputChangeTimeDifferenceCount'},)
        if (type(diagnostic) is not dict or
                set(diagnostic) not in shapes or
                any(not exact_int(diagnostic[key], 0, maximum) for key, maximum in limits.items()) or
                type(diagnostic['nativePhase']) is not int or diagnostic['nativePhase'] not in phases or
                not exact_int(diagnostic['errorCode'], -(1 << 31), (1 << 31) - 1) or
                (diagnostic['errorKind'] == 0 and diagnostic['errorCode'] != 0) or
                (diagnostic['errorKind'] == 1 and diagnostic['errorCode'] != diagnostic['nativePhase'])):
            raise ValueError('Copy diagnostic values')
        if establishing:
            output_sealing(diagnostic, 200, diagnostic['completedCopies'], qualified)
        mask = diagnostic.get('identityMismatchMask', 0)
        identity_phases = (170, 174, 270, 274, 320, 324, 400, 404)
        if establishing:
            identity_phases += (220, 230, 280, 284)
        if (not exact_int(mask, 0, 255) or
                (establishing and diagnostic['nativePhase'] in (220, 230) and mask & 64) or
                (qualified and diagnostic['nativePhase'] in (270, 274, 280, 284) and mask & 64) or
                (qualified and diagnostic['nativePhase'] in (400, 404) and
                 diagnostic['heldOrdinal'] > 0 and diagnostic['heldOrdinal'] % 2 == 0 and mask & 64) or
                (mask != 0 and (diagnostic['errorKind'] != 1 or
                 diagnostic['nativePhase'] not in identity_phases))):
            raise ValueError('Copy identity difference context')
        snapshot_mask = diagnostic.get('snapshotMismatchMask', 0)
        snapshot_phases = (104, 204, 305, 170, 174, 270, 274, 320, 324, 400, 404)
        if establishing:
            snapshot_phases += (220, 230, 280, 284)
        if (not exact_int(snapshot_mask, 0, 15) or
                (snapshot_mask & 8 and snapshot_mask != 8) or
                (snapshot_mask != 0 and (mask != 0 or diagnostic['errorKind'] != 1 or
                 diagnostic['nativePhase'] not in snapshot_phases))):
            raise ValueError('Copy snapshot predicate context')
    if 'counts' in result:
        limits = {**counters, 'bootstrapReads': 8193, 'bootstrapRequestedReadBytes': 8388608 + 65536}
        counts = result['counts']
        if (type(counts) is not dict or set(counts) != set(limits) or
                any(not exact_int(counts[key], 0, maximum) for key, maximum in limits.items())):
            raise ValueError('Copy receipt counters')
    identities = {'volume': (1 << 32) - 1, 'attributes': (1 << 32) - 1,
                  'links': (1 << 32) - 1, 'index': (1 << 64) - 1,
                  'created': (1 << 63) - 1, 'modified': (1 << 63) - 1,
                  'changed': (1 << 63) - 1, 'length': 67108864}
    seen = set()
    expected_rows = ADMISSION['expectedRows']
    for index, row in enumerate(result['rows']):
        if (type(row) is not dict or
                set(row) != {'relative', 'bytes', 'sha256', 'identity', 'sourceIdentity', 'role'} or
                type(row['relative']) is not str or not 1 <= len(row['relative']) <= 1024 or
                not re.fullmatch(r'(?:toolchain|source|control|artifact|product)\\[a-zA-Z0-9_.\\-]+', row['relative']) or
                any(part in ('', '.', '..') or part.endswith('.') for part in row['relative'].split('\\')) or
                row['relative'].lower() in seen or not exact_int(row['bytes'], 1, 67108864) or
                type(row['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', row['sha256']) or
                row['role'] not in ('caller', 'product', 'profile', 'controller', 'template')):
            raise ValueError('Copy public row')
        if {key: row[key] for key in ('relative', 'bytes', 'sha256', 'role')} != expected_rows[index]:
            raise ValueError('Copy row outside admitted public inventory')
        seen.add(row['relative'].lower())
        for key in ('identity', 'sourceIdentity'):
            identity = row[key]
            if (type(identity) is not dict or set(identity) != set(identities) or
                    any(not exact_int(identity[field], 0, maximum) for field, maximum in identities.items()) or
                    identity['links'] != 1 or identity['attributes'] & 0x410 or identity['length'] != row['bytes']):
                raise ValueError('Copy native identity')
    if sum(row['bytes'] for row in result['rows']) > 100663296:
        raise ValueError('Copy payload total')
    if result['passed'] and (len(result['rows']) != 200 or result['failure'] != 'none' or
            not result['allHandlesClosed'] or diagnostic is None or 'counts' not in result or
            diagnostic['copyOrdinal'] != 0 or diagnostic['completedCopies'] != 200 or
            diagnostic['wrapperPhase'] != 4 or diagnostic['nativePhase'] != 405 or
            diagnostic['heldOrdinal'] != 400 or diagnostic['errorKind'] != 0):
        raise ValueError('Copy provisional success fields')
    if result['passed'] and establishing and (diagnostic['outputStage'] != 3 or diagnostic['sealedOutputs'] != 200 or
            diagnostic['identityMismatchMask'] != 0 or diagnostic['snapshotMismatchMask'] != 0):
        raise ValueError('Copy provisional sealing fields')
    return result


def public_single_copy_receipt(result):
    keys = {'schema', 'passed', 'authoritySha256', 'failure', 'copyCompleted',
            'allHandlesClosed', 'noExperimentLive', 'productStarted', 'accountAccess', 'diagnostic'}
    if type(result) is not dict or set(result) != keys:
        raise ValueError('Single-copy receipt shape')
    if (result['schema'] not in ('selected-account-single-copy-diagnosis-v1',
                                'selected-account-single-copy-diagnosis-v2',
                                'selected-account-single-copy-diagnosis-v3') or
            result['authoritySha256'] != ADMISSION['authoritySha256'] or
            any(type(result[key]) is not bool for key in ('passed', 'copyCompleted', 'allHandlesClosed',
                                                        'noExperimentLive', 'productStarted', 'accountAccess')) or
            result['noExperimentLive'] or result['productStarted'] or result['accountAccess'] or
            result['failure'] not in ('admission', 'native-source', 'create', 'copy', 'none')):
        raise ValueError('Single-copy receipt values')
    diagnostic = result['diagnostic']
    if diagnostic is not None:
        fields = {'wrapperPhase', 'nativePhase', 'heldOrdinal', 'errorKind', 'errorCode',
                  'identityMismatchMask', 'snapshotMismatchMask', 'opens', 'metadata', 'reads',
                  'writes', 'requestedReadBytes', 'writtenBytes'}
        qualified = result['schema'] == 'selected-account-single-copy-diagnosis-v3'
        establishing = result['schema'] in ('selected-account-single-copy-diagnosis-v2',
                                           'selected-account-single-copy-diagnosis-v3')
        if establishing:
            fields |= {'outputStage', 'firstReadChangeCount', 'sealedOutputs'}
        if qualified:
            fields.add('outputChangeTimeDifferenceCount')
        if (type(diagnostic) is not dict or set(diagnostic) != fields or
                not exact_int(diagnostic['wrapperPhase'], 0, 3) or
                not exact_int(diagnostic['heldOrdinal'], 0, 2)):
            raise ValueError('Single-copy diagnostic shape')
        if establishing:
            output_sealing(diagnostic, 1, 1 if result['copyCompleted'] else 0, qualified)
            if result['copyCompleted'] and (diagnostic['outputStage'] != 3 or diagnostic['sealedOutputs'] != 1):
                raise ValueError('Single-copy sealing completion')
        # Reuse the existing numeric failure-context checks. This synthetic object
        # remains local: it is never emitted or treated as materialization evidence.
        public_receipt(dict(schema='selected-account-public-materialization-v4' if qualified else
            'selected-account-public-materialization-v3' if establishing else
            'selected-account-public-materialization-v2', passed=False,
            authoritySha256=result['authoritySha256'], target='C:\\Temp\\azureauth-windows-slice-108\\confidential-native-account-v5', rows=[], failure='copy',
            allHandlesClosed=result['allHandlesClosed'], noExperimentLive=False,
            productStarted=False, accountAccess=False,
            diagnostic=dict(diagnostic, copyOrdinal=1 if diagnostic['wrapperPhase'] == 1 else 0,
                            completedCopies=1 if result['copyCompleted'] else 0)))
    elif result['copyCompleted']:
        raise ValueError('Single-copy completion without diagnostic')
    if result['passed'] and (not result['copyCompleted'] or not result['allHandlesClosed'] or
            result['failure'] != 'none' or diagnostic is None or diagnostic['wrapperPhase'] != 3 or
            diagnostic['nativePhase'] != 405 or diagnostic['heldOrdinal'] != 2 or
            diagnostic['errorKind'] != 0 or diagnostic['errorCode'] != 0 or
            diagnostic['identityMismatchMask'] != 0 or diagnostic['snapshotMismatchMask'] != 0):
        raise ValueError('Single-copy provisional success fields')
    return result


def interpret(name, raw):
    if name.endswith('.bin'):
        return {'interpretation': 'contents-suppressed', 'empty': not raw}
    try:
        if name == 'launcher.jsonl':
            lines = raw.splitlines()
            if len(lines) > 128:
                raise ValueError('Diagnostic event count')
            records = [journal_record(decode(line)) for line in lines]
            return {'interpretation': 'validated-public-journal', 'records': records,
                    'newlineTerminated': not raw or raw.endswith(b'\n')}
        decoded = decode(raw)
        if type(decoded) is dict and decoded.get('schema') in ('selected-account-single-copy-diagnosis-v1',
                                                             'selected-account-single-copy-diagnosis-v2',
                                                             'selected-account-single-copy-diagnosis-v3'):
            return {'interpretation': 'validated-public-single-copy-diagnosis',
                    'receipt': public_single_copy_receipt(decoded), 'diagnosisOnly': True}
        result = public_receipt(decoded)
        return {'interpretation': 'validated-public-copy-receipt', 'receipt': result,
                'rowCount': len(result['rows'])}
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return {'interpretation': 'invalid-public-shape'}


def main():
    if ADMISSION is None:
        return 125
    epoch = time.monotonic()
    cancelled = False
    owned, directories, leaves, missing = [], {}, [], []
    requested, operations = 0, 0
    output = None
    phase, ordinal, failure_phase, failure_kind = 0, 0, 0, 0

    def before():
        nonlocal operations
        operations += 1
        if cancelled or operations > 512 or time.monotonic() - epoch >= 25:
            raise TimeoutError('Diagnostic collection bound')

    def stop(*_):
        nonlocal cancelled
        cancelled = True

    def opened(name, flags, parent=None):
        before()
        if len(owned) >= 64:
            raise ValueError('Diagnostic resources')
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        owned.append(fd)
        return fd

    def directory(path):
        if path in directories:
            return directories[path][0]
        if len(directories) >= 32:
            raise ValueError('Diagnostic directories')
        if path == '/':
            fd = opened('/', os.O_RDONLY | os.O_DIRECTORY)
        else:
            parent, name = path.rsplit('/', 1)
            pfd = directory(parent or '/')
            before()
            named = full9(os.stat(name, dir_fd=pfd, follow_symlinks=False))[:5]
            fd = opened(name, os.O_RDONLY | os.O_DIRECTORY, pfd)
            if full9(os.fstat(fd))[:5] != named:
                raise ValueError('Diagnostic ancestry')
        directories[path] = (fd, full9(os.fstat(fd))[:5])
        return fd

    def stable(pfd, name, fd, expected):
        before()
        if full9(os.fstat(fd)) != expected:
            raise ValueError('Diagnostic held identity')
        before()
        if full9(os.stat(name, dir_fd=pfd, follow_symlinks=False)) != expected:
            raise ValueError('Diagnostic named identity')

    def read(fd, length):
        nonlocal requested
        before()
        requested += length + 1
        if requested > 1048576:
            raise ValueError('Diagnostic read bound')
        raw = os.read(fd, length)
        before()
        if len(raw) != length or os.read(fd, 1):
            raise ValueError('Diagnostic read/EOF')
        return raw

    def check_all():
        for args in leaves:
            stable(*args)
        for pfd, name in missing:
            before()
            try:
                os.stat(name, dir_fd=pfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError('Diagnostic missing leaf changed')
        for path, (fd, identity) in directories.items():
            before()
            if full9(os.fstat(fd))[:5] != identity:
                raise ValueError('Diagnostic held ancestry')
            if path != '/':
                parent, name = path.rsplit('/', 1)
                before()
                if full9(os.stat(name, dir_fd=directories[parent or '/'][0],
                                 follow_symlinks=False))[:5] != identity:
                    raise ValueError('Diagnostic named ancestry')

    try:
        phase = 1
        if (sys.executable != '/usr/bin/python3.14' or len(sys.argv) != 1 or
                not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode):
            raise ValueError('Diagnostic runtime')
        phase = 2
        keys = {'stageFull5', 'retentionParentFull5', 'nonce', 'originalEpochMonotonicNs',
                'authoritySha256', 'passNumber', 'expectedRows'}
        if type(ADMISSION) is not dict or set(ADMISSION) != keys:
            raise ValueError('Diagnostic admission')
        if (type(ADMISSION['passNumber']) is not int or not 1 <= ADMISSION['passNumber'] <= 4 or
                type(ADMISSION['originalEpochMonotonicNs']) is not int or
                ADMISSION['originalEpochMonotonicNs'] <= 0 or
                any(type(ADMISSION[key]) is not str or len(ADMISSION[key]) != length or
                    any(c not in '0123456789abcdef' for c in ADMISSION[key])
                    for key, length in (('nonce', 32), ('authoritySha256', 64))) or
                any(type(ADMISSION[key]) is not list or len(ADMISSION[key]) != 5 or
                    any(type(value) is not int for value in ADMISSION[key])
                    for key in ('stageFull5', 'retentionParentFull5'))):
            raise ValueError('Diagnostic admission values')
        expected = ADMISSION['expectedRows']
        phase = 3
        if type(expected) is not list or len(expected) != 200:
            raise ValueError('Copy expected inventory shape')
        expected_seen = set()
        for ordinal, row in enumerate(expected, 1):
            if (type(row) is not dict or set(row) != {'relative', 'bytes', 'sha256', 'role'} or
                    type(row['relative']) is not str or not 1 <= len(row['relative']) <= 1024 or
                    not re.fullmatch(r'(?:toolchain|source|control|artifact|product)\\[a-zA-Z0-9_.\\-]+', row['relative']) or
                    any(part in ('', '.', '..') or part.endswith('.') for part in row['relative'].split('\\')) or
                    row['relative'].lower() in expected_seen or not exact_int(row['bytes'], 1, 67108864) or
                    type(row['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', row['sha256']) or
                    row['role'] not in ('caller', 'product', 'profile', 'controller', 'template')):
                raise ValueError('Copy expected public row')
            expected_seen.add(row['relative'].lower())
        if sum(row['bytes'] for row in expected) > 100663296:
            raise ValueError('Copy expected payload limit')
        phase, ordinal = 4, 0
        resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
        resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, stop)
        phase = 5
        stage, parent = directory(STAGE), directory(RECOVERY)
        if (full9(os.fstat(stage))[:5] != ADMISSION['stageFull5'] or
                full9(os.fstat(parent))[:5] != ADMISSION['retentionParentFull5']):
            raise ValueError('Diagnostic parents')
        rows = []
        phase = 6
        for ordinal, (name, maximum) in enumerate(FILES, 1):
            before()
            try:
                named = full9(os.stat(name, dir_fd=stage, follow_symlinks=False))
            except FileNotFoundError:
                missing.append((stage, name))
                rows.append({'name': name, 'status': 'missing-under-validated-parent'})
                continue
            if not stat.S_ISREG(named[2]) or named[8] != 1 or not 0 <= named[5] <= maximum:
                raise ValueError('Diagnostic leaf shape')
            fd = opened(name, os.O_RDONLY | os.O_NONBLOCK, stage)
            stable(stage, name, fd, named)
            raw = read(fd, named[5])
            stable(stage, name, fd, named)
            leaves.append((stage, name, fd, named))
            rows.append({'name': name, 'status': 'collected', 'bytes': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest(), 'full9': named,
                         **interpret(name, raw)})
        phase, ordinal = 7, 0
        check_all()
        phase = 8
        snapshot = (json.dumps({'schema': 'selected-account-public-copy-result-snapshot-v1',
                    'nonce': ADMISSION['nonce'], 'originalEpochMonotonicNs': ADMISSION['originalEpochMonotonicNs'],
                    'authoritySha256': ADMISSION['authoritySha256'], 'passNumber': ADMISSION['passNumber'],
                    'stageFull5': ADMISSION['stageFull5'], 'rows': rows,
                    'publicRecordsOnly': True, 'priorMaterializationFailurePreserved': True,
                    'materializationAccepted': False, 'nativeClosureAccepted': False},
                    sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
        if len(snapshot) > 524288:
            raise ValueError('Diagnostic snapshot bound')
        phase = 9
        name = 'selected-account-public-copy-result-snapshot-' + str(ADMISSION['passNumber']) + '.json'
        fd = opened(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, parent)
        before()
        if os.write(fd, snapshot) != len(snapshot):
            raise ValueError('Diagnostic snapshot write')
        before()
        os.fsync(fd)
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        current = full9(os.fstat(fd))
        if current[2] != stat.S_IFREG | 0o444 or current[8] != 1 or current[5] != len(snapshot):
            raise ValueError('Diagnostic snapshot identity')
        os.lseek(fd, 0, os.SEEK_SET)
        if read(fd, len(snapshot)) != snapshot:
            raise ValueError('Diagnostic snapshot readback')
        leaves.append((parent, name, fd, current))
        before()
        os.fsync(parent)
        check_all()
        phase = 10
        output = (json.dumps({'schema': 'selected-account-public-copy-result-collection-v1',
                    'name': name, 'bytes': len(snapshot), 'sha256': hashlib.sha256(snapshot).hexdigest(),
                    'full9': current, 'requestedReadBytes': requested, 'publicRecordsOnly': True},
                    sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
        if len(output) > 2048:
            raise ValueError('Diagnostic transport')
    except Exception as error:
        failure_phase = phase
        # Only a fixed category is public; never serialize exception text or errno.
        if isinstance(error, TimeoutError):
            failure_kind = 1
        elif isinstance(error, FileNotFoundError):
            failure_kind = 2
        elif isinstance(error, PermissionError):
            failure_kind = 3
        elif isinstance(error, OSError):
            failure_kind = 4
        elif isinstance(error, ValueError):
            failure_kind = 5
        elif isinstance(error, MemoryError):
            failure_kind = 6
        else:
            failure_kind = 7
        output = None
    finally:
        close_failed = False
        while owned:
            try:
                before()
                os.close(owned.pop())
            except Exception:
                close_failed = True
                # If the bound fired before close, retain the descriptor until
                # this original process exits; do not loop beyond its deadline.
                break
    if close_failed or output is None:
        # The same cancellation, checkpoint and original deadline still apply.
        try:
            before()
            marker = (json.dumps({
                'schema': 'selected-account-public-copy-collection-failure-v1',
                'phase': 11 if close_failed else failure_phase,
                'ordinal': 0 if close_failed else ordinal,
                'kind': 0 if close_failed else failure_kind,
                'closeFailed': close_failed,
            }, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
            if len(marker) <= 192:
                os.write(1, marker)
                before()
        except Exception:
            pass
        return 1
    try:
        before()
        if os.write(1, output) != len(output):
            return 1
        before()
    except Exception:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
