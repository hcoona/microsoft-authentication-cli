"""Inert, one-use Linux observation of two freshly owned projected files."""

ADMITTED = False
if not ADMITTED:
    raise RuntimeError('Inert fresh-file identity diagnostic; exact admission required')

import fcntl
import hashlib
import json
import os
import signal
import stat
import sys
import time

LOCAL = '/var/tmp/azureauth-windows-slice-108/windows-actions/0112'
ROOT = '/mnt/c/Temp/azureauth-windows-slice-108/metadata-identity-0112'
LOCK = '/var/tmp/azureauth-windows-slice-108/action.lock'
CASES = (('packages.lock.json', b'{"schema":"public-synthetic-identity-v1","case":1}\n'),
         ('plain.txt', b'PUBLIC SYNTHETIC FILE IDENTITY OBSERVATION\n'))
FIELDS = ('dev', 'ino', 'mode', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns', 'nlink')
BEFORE = [22, 106, 6, 164]
AFTER = [23, 106, 6, 164]
DEADLINE = 0


class PredicateFailure(ValueError):
    """A source-defined label, never arbitrary operating-system error text."""


def require(condition, label):
    if not condition:
        raise PredicateFailure(label)


def check(terminal=False):
    require(time.monotonic_ns() < DEADLINE - (0 if terminal else 5_000_000_000),
            'Original diagnostic interval expired')


def interrupted(signum, frame):
    raise TimeoutError('Original diagnostic interrupted')


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def parent(path):
    parts = path.split('/')
    require(parts[0] == '' and all(p not in ('', '.', '..') for p in parts[1:]), 'Fixed absolute path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in parts[1:-1]:
            check()
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def fresh_directory(path):
    directory, name = parent(path)
    try:
        check()
        os.mkdir(name, 0o700, dir_fd=directory)
        os.fsync(directory)
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=directory)
    finally:
        os.close(directory)


def new_file(directory, name):
    check()
    return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                   0o600, dir_fd=directory)


def persist(fd, directory, raw, maximum, terminal=False):
    check(terminal)
    require(len(raw) <= maximum, 'Fixed output cap')
    require(os.write(fd, raw) == len(raw), 'Complete single write')
    os.fsync(fd)
    os.fsync(directory)
    check(terminal)
    return identity(os.fstat(fd))


def observe(directory, name, payload, row):
    row.update(name=name, expectedBytes=len(payload), expectedSha256=hashlib.sha256(payload).hexdigest(),
               samples={}, differences={}, payloadRead=False)
    fd = new_file(directory, name)
    try:
        check()
        require(len(payload) <= 256, 'Fixed fresh payload cap')
        require(os.write(fd, payload) == len(payload), 'Complete single fresh write')
        os.fsync(fd)
        row['samples']['writerAfterFsync'] = identity(os.fstat(fd))
    finally:
        os.close(fd)
    os.fsync(directory)
    # Same named observation point as materialize_inputs after write_new closes.
    check()
    named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    row['samples']['pathAfterWriteClose'] = identity(named)
    row['differences']['writerFdToClosedPath'] = differences(
        row['samples']['writerAfterFsync'], row['samples']['pathAfterWriteClose'])
    require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and named.st_size == len(payload),
            'Fresh fixed regular file')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        opened = os.fstat(fd)
        row['samples']['fdImmediatelyOpened'] = identity(opened)
        row['differences']['pathToOpenedFd'] = differences(identity(named), identity(opened))
        # This diagnostic observes timestamps, not production input eligibility.
        # Reading is confined to the just-created inode and fixed public byte cap.
        owned = row['samples']['writerAfterFsync']
        for sampled in (identity(named), identity(opened)):
            require(all(sampled[i] == owned[i] for i in (0, 1, 2, 3, 4, 5, 8)),
                    'Fresh held-file ownership changed')
        check()
        raw = os.read(fd, len(payload) + 1)
        row.update(payloadRead=True, readBytes=len(raw), readSha256=hashlib.sha256(raw).hexdigest(),
                   expectedPayloadMatched=raw == payload)
        row['samples']['fdAfterRead'] = identity(os.fstat(fd))
        row['samples']['pathWhileOpenAfterRead'] = identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
        row['differences']['openedFdToReadFd'] = differences(
            row['samples']['fdImmediatelyOpened'], row['samples']['fdAfterRead'])
        row['differences']['readFdToNamedPath'] = differences(
            row['samples']['fdAfterRead'], row['samples']['pathWhileOpenAfterRead'])
        require(raw == payload, 'Fresh public payload changed or incomplete')
        for sampled in (row['samples']['fdAfterRead'], row['samples']['pathWhileOpenAfterRead']):
            require(all(sampled[i] == owned[i] for i in (0, 1, 2, 3, 4, 5, 8)),
                    'Fresh ownership changed after read')
    finally:
        os.close(fd)
    check()
    row['samples']['pathAfterReadClose'] = identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
    row['differences']['readFdToClosedPath'] = differences(
        row['samples']['fdAfterRead'], row['samples']['pathAfterReadClose'])
    require(all(row['samples']['pathAfterReadClose'][i] == owned[i] for i in (0, 1, 2, 3, 4, 5, 8)),
            'Fresh ownership changed after close')


def differences(left, right):
    return [name for name, a, b in zip(FIELDS, left, right, strict=True) if a != b]


def main():
    global DEADLINE
    require(len(sys.argv) == 1, 'No alternative paths or parameters')
    began = time.monotonic_ns()
    DEADLINE = began + 25_000_000_000
    for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    signal.setitimer(signal.ITIMER_REAL, 25)
    directory, name = parent(LOCK)
    try:
        lease = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
    local = projected = output = None
    result = {'schema': 'fresh-projected-file-identity-result-v1', 'action': '0112',
              'stage': 'lease', 'complete': False, 'cases': [], 'full9Fields': FIELDS,
              'productionIdentityAcceptance': False, 'causeOf0111Established': False,
              'continuationAllowed': False, 'noExperimentLive': False}
    try:
        require(stat.S_ISREG(os.fstat(lease).st_mode), 'Regular shared lease')
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result['stage'] = 'original-reservation'
        local = fresh_directory(LOCAL)
        marker = new_file(local, 'started.json')
        try:
            persist(marker, local, encode({'schema': 'fresh-projected-file-identity-start-v1',
                    'action': '0112', 'before': BEFORE, 'charge': [1, 0, 0, 0], 'after': AFTER,
                    'hostPreparations': {'linux': [12, 18], 'windows': [11, 17]},
                    'protectedAfter': [12, 35, 0, 113], 'originalStartNanoseconds': began,
                    'originalDeadlineNanoseconds': DEADLINE, 'retryAllowed': False,
                    'noExperimentLive': False}), 4096)
        finally:
            os.close(marker)
        output = new_file(local, 'result.json')
        result['stage'] = 'fresh-projection'
        projected = fresh_directory(ROOT)
        for name, payload in CASES:
            result['stage'] = 'fixed-file-observation'
            row = {}
            result['cases'].append(row)
            observe(projected, name, payload, row)
        result['complete'] = True
        result['disposition'] = ('observed-full9-difference' if any(
            fields for row in result['cases'] for fields in row['differences'].values()) else 'observed-full9-equality')
    except BaseException as error:
        result['failureType'] = type(error).__name__
        # Only this helper's typed literal labels may be retained.
        result['failurePredicate'] = str(error) if type(error) is PredicateFailure else None
    finally:
        try:
            if output is not None:
                result['elapsedNanoseconds'] = time.monotonic_ns() - began
                raw = encode(result)
                result_identity = persist(output, local, raw, 32768, terminal=True)
                print(json.dumps({'path': LOCAL + '/result.json', 'bytes': len(raw),
                                  'sha256': hashlib.sha256(raw).hexdigest(), 'identity': result_identity,
                                  'complete': result['complete'], 'continuationAllowed': False}), flush=True)
        finally:
            for fd in (output, projected, local, lease):
                if fd is not None:
                    os.close(fd)
    check(terminal=True)
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    try:
        status = main()
    except Exception as error:
        sys.stderr.write(encode({'failureType': type(error).__name__,
                                'failurePredicate': str(error) if type(error) is PredicateFailure else None}).decode('ascii'))
        status = 1
    sys.exit(status)
