"""Inert one-file deployment of the retained normal launcher; never executes it."""
ADMITTED = False
if not ADMITTED:
    raise RuntimeError('Inert deployment; accepted protocol and exact call required')

import hashlib
import json
import os
import signal
import stat
import sys
import time

SOURCE = '/var/tmp/azureauth-windows-slice-108/windows-actions/0070/WindowsScriptJobLauncher.exe'
SOURCE_IDENTITY = [2096, 4511336, 33204, 1000, 1000, 23040,
                   1790051284975599576, 1790051284975599576, 1]
SIZE = 23040
SHA256 = '5b018f38669fd6ca3cec8f760533af392e0265280047bfb5c531dd41a349690a'
PARENT = '/mnt/c/Temp/azureauth-windows-slice-108'
DIRECTORY = 'normal-launcher-dispatch-v1'
LEAF = 'WindowsScriptJobLauncher.exe'
RESULT = '/tmp/windows-normal-launcher-deployment-result-root-v1.json'
DEADLINE = 0


class PredicateFailure(ValueError):
    pass


def require(condition, label):
    if not condition:
        raise PredicateFailure(label)


def check(terminal=False):
    require(time.monotonic_ns() < DEADLINE - (0 if terminal else 5_000_000_000),
            'Original deployment interval expired')


def interrupted(signum, frame):
    raise TimeoutError('Original deployment interrupted')


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


def same_copy(identities):
    first = identities[0]
    return all(all(value[i] == first[i] for i in (0, 1, 2, 3, 4, 5, 6, 8))
               for value in identities[1:])


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def main():
    global DEADLINE
    require(len(sys.argv) == 1, 'No arguments or alternative paths')
    DEADLINE = time.monotonic_ns() + 55_000_000_000
    for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    signal.setitimer(signal.ITIMER_REAL, 55)
    local = directory('/tmp')
    output = parent = destination = source_parent = None
    record = {'schema': 'windows-normal-launcher-passive-deployment-v1', 'complete': False,
              'outcomeAccepted': False, 'continuationAllowed': False, 'retryAllowed': False,
              'noExperimentLive': False, 'requestedReadBytesMaximum': 46082,
              'writtenPayloadBytesMaximum': 23040}
    try:
        output = os.open(RESULT.rsplit('/', 1)[1],
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=local)
        source_path, source_name = SOURCE.rsplit('/', 1)
        source_parent = directory(source_path)
        check()
        named = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1 and
                identity(named) == SOURCE_IDENTITY, 'Exact retained source identity')
        fd = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=source_parent)
        try:
            require(identity(os.fstat(fd)) == SOURCE_IDENTITY, 'Opened retained source identity')
            check()
            raw = os.read(fd, SIZE + 1)
            record['sourceReturnedBytes'] = len(raw)
            record['sourceSha256'] = hashlib.sha256(raw).hexdigest()
            record['sourceAfterRead'] = identity(os.fstat(fd))
            record['sourceNamedAfterRead'] = identity(os.stat(source_name, dir_fd=source_parent, follow_symlinks=False))
            require(len(raw) == SIZE and record['sourceSha256'] == SHA256 and
                    record['sourceAfterRead'] == record['sourceNamedAfterRead'] == SOURCE_IDENTITY,
                    'Retained source content and full9 unchanged')
        finally:
            os.close(fd)
        os.close(source_parent)
        source_parent = None
        parent = directory(PARENT)
        check()
        os.mkdir(DIRECTORY, 0o700, dir_fd=parent)
        record['directoryCreated'] = True
        destination = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=parent)
        created_directory = os.fstat(destination)
        record['directoryIdentity'] = identity(created_directory)
        check()
        fd = os.open(LEAF, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o700, dir_fd=destination)
        try:
            record['fileCreated'] = True
            require(os.write(fd, raw) == SIZE, 'Complete sole executable write')
            os.fsync(fd)
            record['writerIdentity'] = identity(os.fstat(fd))
        finally:
            os.close(fd)
        os.fsync(destination)
        os.fsync(parent)
        check()
        record['writeClosedIdentity'] = identity(os.stat(LEAF, dir_fd=destination, follow_symlinks=False))
        fd = os.open(LEAF, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=destination)
        try:
            before = os.fstat(fd)
            record['readbackInitialIdentity'] = identity(before)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == SIZE and
                    same_copy([record['writerIdentity'], record['writeClosedIdentity'], identity(before)]),
                    'Owned created-copy shape and lineage')
            check()
            copied = os.read(fd, SIZE + 1)
            record['readbackReturnedBytes'] = len(copied)
            record['readbackSha256'] = hashlib.sha256(copied).hexdigest()
            record['readbackFinalIdentity'] = identity(os.fstat(fd))
            record['namedFinalIdentity'] = identity(os.stat(LEAF, dir_fd=destination, follow_symlinks=False))
            require(len(copied) == SIZE and copied == raw and record['readbackSha256'] == SHA256 and
                    same_copy([record['writerIdentity'], record['writeClosedIdentity'], identity(before),
                               record['readbackFinalIdentity'], record['namedFinalIdentity']]) and
                    record['readbackFinalIdentity'] == record['namedFinalIdentity'],
                    'Exact owned copy content and final full9')
            require(record['namedFinalIdentity'][2] & 0o111, 'Created executable mode')
            record['effectiveUserExecuteAccess'] = os.access(
                LEAF, os.X_OK, dir_fd=destination, effective_ids=True, follow_symlinks=False)
            require(record['effectiveUserExecuteAccess'], 'Created executable access')
            require(identity(os.fstat(fd)) == record['namedFinalIdentity'] ==
                    identity(os.stat(LEAF, dir_fd=destination, follow_symlinks=False)),
                    'Executable full9 after access check')
            record['descriptor'] = {'path': PARENT + '/' + DIRECTORY + '/' + LEAF,
                                    'bytes': SIZE, 'sha256': SHA256, 'identity': record['namedFinalIdentity']}
        finally:
            os.close(fd)
        named_directory = os.stat(DIRECTORY, dir_fd=parent, follow_symlinks=False)
        held_directory = os.fstat(destination)
        require(stat.S_ISDIR(named_directory.st_mode) and
                (named_directory.st_dev, named_directory.st_ino) ==
                (held_directory.st_dev, held_directory.st_ino) ==
                (created_directory.st_dev, created_directory.st_ino), 'Owned destination directory binding')
        check()
        record['complete'] = True
    except BaseException as error:
        record['failureType'] = type(error).__name__
        record['failurePredicate'] = str(error) if type(error) is PredicateFailure else None
    finally:
        try:
            if output is not None:
                check(terminal=True)
                encoded = encode(record)
                require(len(encoded) <= 16384, 'Deployment result cap')
                require(os.write(output, encoded) == len(encoded), 'Complete sole result write')
                os.fchmod(output, 0o444)
                os.fsync(output)
                os.fsync(local)
                check(terminal=True)
                print(json.dumps({'path': RESULT, 'bytes': len(encoded),
                                  'sha256': hashlib.sha256(encoded).hexdigest(),
                                  'identity': identity(os.fstat(output)), 'complete': record['complete']}), flush=True)
        finally:
            for fd in (source_parent, destination, parent, output, local):
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
