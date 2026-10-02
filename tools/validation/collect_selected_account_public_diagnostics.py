"""Collect fixed public materialization diagnostics; every call needs admission."""
import hashlib
import json
import os
import resource
import signal
import stat
import sys
import time

ADMISSION = None
RECOVERY = '/home/shuaizhang/.local/state/azureauth-108-recovery-20260929'
STAGE = '/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0186'
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
            valid = value == 'Local\\azureauth-controller-108-0186-' + ADMISSION['nonce']
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
        result = decode(raw)
        keys = {'schema', 'passed', 'authoritySha256', 'target', 'rows', 'failure',
                'allHandlesClosed', 'noExperimentLive', 'productStarted', 'accountAccess'}
        if type(result) is not dict or set(result) != keys:
            raise ValueError('Diagnostic receipt fields')
        if (result['schema'] != 'selected-account-public-materialization-v1' or
                result['authoritySha256'] != ADMISSION['authoritySha256'] or
                result['target'] != 'C:\\Temp\\azureauth-windows-slice-108\\confidential-native-account-v1' or
                type(result['rows']) is not list or len(result['rows']) > 200 or
                result['failure'] not in ('admission', 'native-source', 'create', 'copy', 'none') or
                any(type(result[key]) is not bool for key in
                    ('passed', 'allHandlesClosed', 'noExperimentLive', 'productStarted', 'accountAccess')) or
                result['productStarted'] or result['accountAccess']):
            raise ValueError('Diagnostic public receipt')
        return {'interpretation': 'validated-public-summary', 'rowCount': len(result['rows']),
                **{key: result[key] for key in ('schema', 'passed', 'authoritySha256', 'failure',
                                               'allHandlesClosed', 'noExperimentLive',
                                               'productStarted', 'accountAccess')}}
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
        if (sys.executable != '/usr/bin/python3.14' or len(sys.argv) != 1 or
                not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode):
            raise ValueError('Diagnostic runtime')
        keys = {'stageFull5', 'retentionParentFull5', 'nonce', 'originalEpochMonotonicNs',
                'authoritySha256', 'passNumber'}
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
        resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
        resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, stop)
        stage, parent = directory(STAGE), directory(RECOVERY)
        if (full9(os.fstat(stage))[:5] != ADMISSION['stageFull5'] or
                full9(os.fstat(parent))[:5] != ADMISSION['retentionParentFull5']):
            raise ValueError('Diagnostic parents')
        rows = []
        for name, maximum in FILES:
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
        check_all()
        snapshot = (json.dumps({'schema': 'selected-account-public-diagnostic-snapshot-v1',
                    'nonce': ADMISSION['nonce'], 'originalEpochMonotonicNs': ADMISSION['originalEpochMonotonicNs'],
                    'authoritySha256': ADMISSION['authoritySha256'], 'passNumber': ADMISSION['passNumber'],
                    'stageFull5': ADMISSION['stageFull5'], 'rows': rows,
                    'diagnosticOnly': True, 'originalFailurePreserved': True,
                    'materializationAccepted': False, 'nativeClosureAccepted': False},
                    sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
        if len(snapshot) > 32768:
            raise ValueError('Diagnostic snapshot bound')
        name = 'selected-account-public-diagnostic-snapshot-' + str(ADMISSION['passNumber']) + '.json'
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
        output = (json.dumps({'schema': 'selected-account-public-diagnostic-collection-v1',
                    'name': name, 'bytes': len(snapshot), 'sha256': hashlib.sha256(snapshot).hexdigest(),
                    'full9': current, 'requestedReadBytes': requested, 'diagnosticOnly': True},
                    sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
        if len(output) > 2048:
            raise ValueError('Diagnostic transport')
    except Exception:
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
