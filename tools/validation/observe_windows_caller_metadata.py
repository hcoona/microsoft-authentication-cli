"""Inert five-file public compiler/runtime metadata observation proposal."""
ADMITTED = False
if not ADMITTED:
    raise RuntimeError('Inert local observation; exact outcome and call admission required')

import base64
import hashlib
import json
import os
import signal
import stat
import sys
import time

INPUTS = [{'path': '/mnt/c/Program Files/dotnet/sdk/10.0.401/Roslyn/bincore/csc.deps.json', 'bytes': 5981, 'sha256': 'b50fdc9d35fa4d9e23343a3ebafe1a9dc19a39c31701af192b1d54c16a9e1e27'}, {'path': '/mnt/c/Program Files/dotnet/sdk/10.0.401/Roslyn/bincore/csc.runtimeconfig.json', 'bytes': 405, 'sha256': '11744d1d8ad57c8906cc665166f240157ca4a62824043e5c8e3c2b48f2176b58'}, {'path': '/mnt/c/Temp/azureauth-windows-slice-108/packages/microsoft.netcore.app.runtime.win-x64/10.0.12/data/RuntimeList.xml', 'bytes': 40666, 'sha256': '6395fa09954f9a4c78be52d894dbb331f0019d51ea8b03fbd5846ac4125ac73a'}, {'path': '/mnt/c/Temp/azureauth-windows-slice-108/packages/microsoft.netcore.app.runtime.win-x64/10.0.12/runtimes/win-x64/lib/net10.0/Microsoft.NETCore.App.deps.json', 'bytes': 29720, 'sha256': 'db6bf68420f350411629571d31aea9232f05e9464e0f48f306041efd0971615d'}, {'path': '/mnt/c/Temp/azureauth-windows-slice-108/packages/microsoft.netcore.app.runtime.win-x64/10.0.12/runtimes/win-x64/lib/net10.0/Microsoft.NETCore.App.runtimeconfig.json', 'bytes': 54, 'sha256': '31c8ce517cddc0deaceb26b5dff6ba5df55ac4e06e9afd0026e51faca23dc8a4'}]
SNAPSHOT = '/tmp/windows-real-caller-five-metadata-snapshot-root-v1.json'
DEADLINE = 0


class PredicateFailure(ValueError):
    pass


def require(condition, label):
    if not condition:
        raise PredicateFailure(label)


def check(terminal=False):
    require(time.monotonic_ns() < DEADLINE - (0 if terminal else 5_000_000_000),
            'Original local observation interval expired')


def interrupted(signum, frame):
    raise TimeoutError('Original local observation interrupted')


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size,
            s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]


def directory(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in path.split('/')[1:]:
            check()
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def observe(parent, name, pin, records):
    maximum = pin['bytes']
    check()
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and 0 < named.st_size == maximum,
            'Exact bounded regular control leaf')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        require(identity(before) == identity(named), 'Named and opened full9 differ')
        check()
        raw = os.read(fd, before.st_size + 1)  # Sole read, requesting one byte beyond the fixed size.
        row = {'path': pin['path'], 'rawBase64': base64.b64encode(raw).decode('ascii'),
               'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
               'identity': identity(before), 'acceptedObservedRecord': False}
        records.append(row)
        row['fdAfterRead'] = identity(os.fstat(fd))
        row['pathAfterRead'] = identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
        require(len(raw) == before.st_size and identity(before) == row['fdAfterRead'] == row['pathAfterRead'],
                'Incomplete read or changed control full9')
        require(row['sha256'] == pin['sha256'], 'Pinned public metadata digest differs')
        check()
        row['acceptedObservedRecord'] = True
    finally:
        os.close(fd)


def main():
    global DEADLINE
    require(len(sys.argv) == 1, 'No arguments or alternative paths')
    DEADLINE = time.monotonic_ns() + 30_000_000_000
    for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    signal.setitimer(signal.ITIMER_REAL, 30)
    local = directory('/tmp')
    output = parent = None
    record = {'schema': 'windows-real-caller-five-metadata-snapshot-v1', 'complete': False,
              'records': [], 'outcomeAccepted': False,
              'continuationAllowed': False, 'retryAllowed': False, 'noExperimentLive': False}
    try:
        output = os.open('windows-real-caller-five-metadata-snapshot-root-v1.json',
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=local)
        for pin in INPUTS:
            path, name = pin['path'].rsplit('/', 1)
            parent = directory(path)
            try:
                observe(parent, name, pin, record['records'])
            finally:
                os.close(parent)
                parent = None
        record['complete'] = True
    except BaseException as error:
        record['failureType'] = type(error).__name__
        record['failurePredicate'] = str(error) if type(error) is PredicateFailure else None
    finally:
        try:
            if output is not None:
                check(terminal=True)
                raw = encode(record)
                require(len(raw) <= 131072, 'Fixed retained snapshot cap')
                require(os.write(output, raw) == len(raw), 'Complete single snapshot write')
                os.fchmod(output, 0o444)
                os.fsync(output)
                os.fsync(local)
                check(terminal=True)
                print(json.dumps({'path': SNAPSHOT, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                  'identity': identity(os.fstat(output)), 'complete': record['complete']}), flush=True)
        finally:
            for fd in (parent, output, local):
                if fd is not None:
                    os.close(fd)
    check(terminal=True)
    return 0 if record['complete'] else 1


if __name__ == '__main__':
    try:
        status = main()
    except Exception as error:
        sys.stderr.write(encode({'failureType': type(error).__name__,
                                'failurePredicate': str(error) if type(error) is PredicateFailure else None}).decode('ascii'))
        status = 1
    sys.exit(status)
