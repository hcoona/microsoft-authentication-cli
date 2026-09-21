"""Collect one fixed, fresh-file metadata comparison; never inspect old fixtures."""

import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time


BEGAN = time.monotonic()
ROOTS = (
    Path('/tmp/windows-named-fixtures0067-metadata-diagnostic-v1'),
    Path('/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures0067-metadata-diagnostic-v1'),
)
START = Path('/tmp/windows-named-fixtures0067-metadata-start-v1.json')
RESULT = Path('/tmp/windows-named-fixtures0067-metadata-result-v1.json')
CONTENT = b'Credential-free fixture metadata diagnostic.\n'
FIELDS = ('device', 'inode', 'mode', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns', 'nlink')
METADATA = OPENS = WRITTEN = 0


def check():
    if time.monotonic() - BEGAN >= 30:
        raise TimeoutError('Original metadata diagnostic deadline')


def info(*args, **kwargs):
    global METADATA
    check()
    METADATA += 1
    if METADATA > 256:
        raise ValueError('Metadata observation ceiling')
    value = os.fstat(args[0]) if type(args[0]) is int else os.stat(*args, **kwargs)
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink]


def opened(*args, **kwargs):
    global OPENS
    check()
    OPENS += 1
    if OPENS > 64:
        raise ValueError('Descriptor-open ceiling')
    return os.open(*args, **kwargs)


def parent(path):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Nonliteral diagnostic path')
    fd = opened('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            named = info(component, dir_fd=fd, follow_symlinks=False)
            child = opened(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            if named[:5] != info(child)[:5]:
                os.close(child)
                raise ValueError('Diagnostic parent correspondence')
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_bytes(fd, raw):
    global WRITTEN
    WRITTEN += len(raw)
    if WRITTEN > 65536:
        raise ValueError('Diagnostic aggregate output ceiling')
    offset = 0
    while offset < len(raw):
        check()
        count = os.write(fd, raw[offset:])
        if count <= 0:
            raise OSError('Incomplete diagnostic write')
        offset += count
    os.fsync(fd)
    check()


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
    if len(raw) > 32768:
        raise ValueError('Diagnostic receipt ceiling')
    pfd = parent(path)
    try:
        fd = opened(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=pfd)
        try:
            write_bytes(fd, raw)
        finally:
            os.close(fd)
        os.fsync(pfd)
    finally:
        os.close(pfd)
    check()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def observe(root, record):
    pfd = parent(root)
    rootfd = writefd = readfd = None
    try:
        os.mkdir(root.name, mode=0o700, dir_fd=pfd)
        record['rootCreated'] = True
        rootfd = opened(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
        original = info(rootfd)[:5]
        if original != info(root.name, dir_fd=pfd, follow_symlinks=False)[:5]:
            raise ValueError('Created diagnostic root correspondence')
        writefd = opened('sample.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=rootfd)
        record['fileCreated'] = True
        write_bytes(writefd, CONTENT)
        record['afterWriteHandle'] = info(writefd)
        record['afterWriteNamed'] = info('sample.bin', dir_fd=rootfd, follow_symlinks=False)
        os.fchmod(writefd, 0o444)
        os.fsync(writefd)
        record['afterChmodHandle'] = info(writefd)
        record['afterChmodNamed'] = info('sample.bin', dir_fd=rootfd, follow_symlinks=False)
        os.close(writefd)
        writefd = None
        record['afterCloseNamed'] = info('sample.bin', dir_fd=rootfd, follow_symlinks=False)
        os.fsync(rootfd)
        record['beforeReadOpenNamed'] = info('sample.bin', dir_fd=rootfd, follow_symlinks=False)
        readfd = opened('sample.bin', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=rootfd)
        record['afterReadOpenHandle'] = info(readfd)
        record['afterReadOpenNamed'] = info('sample.bin', dir_fd=rootfd, follow_symlinks=False)
        # The opened file supplies metadata only; no file payload is read.
        os.close(readfd)
        readfd = None
        record['afterReadCloseNamed'] = info('sample.bin', dir_fd=rootfd, follow_symlinks=False)
        record['differingFieldsAtReadOpen'] = [name for index, name in enumerate(FIELDS)
            if record['beforeReadOpenNamed'][index] != record['afterReadOpenHandle'][index]]
        if original != info(rootfd)[:5] or original != info(root.name, dir_fd=pfd, follow_symlinks=False)[:5]:
            raise ValueError('Original diagnostic root correspondence lost')
        os.fsync(pfd)
        record['complete'] = True
        check()
    finally:
        for fd in (readfd, writefd, rootfd, pfd):
            if fd is not None:
                os.close(fd)


def main():
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('Original diagnostic clock')))
    signal.setitimer(signal.ITIMER_REAL, max(0.001, 30 - (time.monotonic() - BEGAN)))
    if len(sys.argv) != 1 or sys.executable != '/usr/bin/python3.14' or \
            not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode:
        raise ValueError('Fixed isolated diagnostic runtime required')
    start = save(START, {'schema': 'fixture-metadata-diagnostic-start-v1', 'maximumInvocations': 1,
        'originalSeconds': 30, 'metadataCap': 256, 'openCap': 64, 'writeCap': 65536,
        'payloadReads': 0, 'subjectProcesses': 0, 'continuation_allowed': False})
    result = {'schema': 'fixture-metadata-diagnostic-result-v1', 'start': start,
        'complete': False, 'failureType': None, 'fields': FIELDS, 'observations': [],
        'originalMaterializerCauseEstablished': False, 'continuation_allowed': False}
    try:
        for role, root in zip(('linux', 'windows-drive'), ROOTS, strict=True):
            record = {'role': role, 'rootCreated': False, 'fileCreated': False, 'complete': False}
            result['observations'].append(record)
            observe(root, record)
        result['complete'] = True
    except BaseException as error:
        result['failureType'] = type(error).__name__
    result['beforeResult'] = {'metadata': METADATA, 'opens': OPENS, 'writtenBytes': WRITTEN,
                             'elapsedMilliseconds': int((time.monotonic() - BEGAN) * 1000)}
    result_pin = save(RESULT, result)
    print(json.dumps({'start': start, 'result': result_pin, 'complete': result['complete'],
                      'continuation_allowed': False}, sort_keys=True), flush=True)
    check()
    signal.setitimer(signal.ITIMER_REAL, 0)
    if not result['complete']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
