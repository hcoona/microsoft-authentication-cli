"""Prepare fresh 0067 inputs with bounded, original-comparison failure context."""

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time


MANIFEST = Path('/tmp/windows-named-fixtures0067-v2-materialization-manifest.json')
OUTPUTS = (Path('/tmp/windows-named-fixtures0067-v2-inputs'),
           Path('/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0067-v2'))
RECEIPT = Path('/tmp/windows-named-fixtures0067-v2-materialized.json')
READS = 0
REQUESTED = 0
WRITTEN = 0
STARTED = time.monotonic()
FIELDS = ('device', 'inode', 'mode', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns', 'nlink')
CONTEXT = {'phase': 'startup'}
MISMATCH = None


def context(phase, path):
    global CONTEXT
    item = Path(path)
    role = next((label for label, root in zip(('linux-inputs', 'windows-inputs'), OUTPUTS, strict=True)
                 if item == root or item.parent == root), 'source-or-receipt')
    CONTEXT = {'phase': phase, 'role': role, 'leaf': item.name}


def same(expected, observed, phase):
    global MISMATCH
    if expected != observed:
        MISMATCH = {'phase': phase, 'fields': FIELDS[:len(expected)],
                    'expected': expected, 'observed': observed,
                    'differingFields': [field for field, left, right in
                        zip(FIELDS, expected, observed, strict=False) if left != right]}
        raise ValueError('Materialization identity mismatch')


def check():
    if time.monotonic() - STARTED >= 30:
        raise TimeoutError('Original materialization deadline')


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def directory_identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]


def parent(path):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Nonliteral copy path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            check()
            named = os.stat(component, dir_fd=fd, follow_symlinks=False)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                same(directory_identity(named), directory_identity(os.fstat(child)), 'parent-open')
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, maximum, pinned=None, held_parent=None, expected_identity=None):
    global READS, REQUESTED
    context('read', path)
    check()
    READS += 1
    if READS > 24:
        raise ValueError('Materialization read count')
    pfd = parent(path) if held_parent is None else held_parent
    fd = None
    try:
        before = os.stat(path.name, dir_fd=pfd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError('Materialization source kind or size')
        if expected_identity is not None:
            same(expected_identity, identity(before), 'created-before-readback')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
        same(identity(before), identity(os.fstat(fd)), 'named-before-open-vs-opened')
        raw = bytearray()
        while len(raw) < before.st_size:
            check()
            request = min(65536, before.st_size - len(raw))
            REQUESTED += request
            if REQUESTED > 4194304:
                raise ValueError('Materialization requested bytes')
            chunk = os.read(fd, request)
            if not chunk:
                raise ValueError('Short copy input')
            raw.extend(chunk)
        REQUESTED += 1
        if REQUESTED > 4194304 or os.read(fd, 1):
            raise ValueError('Materialization EOF or requested bytes')
        same(identity(before), identity(os.fstat(fd)), 'handle-after-read')
        same(identity(before), identity(os.stat(path.name, dir_fd=pfd, follow_symlinks=False)),
             'named-after-read')
        data = bytes(raw)
        if pinned is not None and (len(data) != pinned['bytes'] or hashlib.sha256(data).hexdigest() != pinned['sha256']):
            raise ValueError('Unadmitted materialization bytes')
        check()
        return data, identity(before)
    finally:
        if fd is not None:
            os.close(fd)
        if held_parent is None:
            os.close(pfd)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate copy field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite copy field')))


def write(pfd, name, raw, expected_parent, output_path):
    global WRITTEN
    context('write', output_path)
    check()
    if '/' in name or name in ('', '.', '..'):
        raise ValueError('Nonliteral copy output leaf')
    same(expected_parent, directory_identity(os.fstat(pfd)), 'write-parent-handle')
    WRITTEN += len(raw)
    if WRITTEN > 327680:
        raise ValueError('Materialization output bytes')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=pfd)
    try:
        offset = 0
        while offset < len(raw):
            check()
            count = os.write(fd, raw[offset:offset + 65536])
            if count <= 0:
                raise OSError('Materialization write made no progress')
            offset += count
        os.fsync(fd)
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        created = identity(os.fstat(fd))
        same(created, identity(os.stat(name, dir_fd=pfd, follow_symlinks=False)),
             'created-handle-vs-named')
    finally:
        os.close(fd)
    os.fsync(pfd)
    check()
    return created


def join_roots(held):
    check()
    for root, pfd, rootfd, original in held:
        context('root-continuity', root)
        same(original, directory_identity(os.fstat(rootfd)), 'root-handle')
        same(original, directory_identity(os.stat(root.name, dir_fd=pfd, follow_symlinks=False)),
             'root-held-parent')
        same(original, directory_identity(root.lstat()), 'root-absolute-name')


def materialize():
    if sys.executable != '/usr/bin/python3.14' or not sys.flags.isolated or \
            not sys.flags.no_site or not sys.flags.dont_write_bytecode:
        raise ValueError('Fixed isolated materialization runtime required')
    if len(sys.argv) != 2 or len(sys.argv[1]) != 64 or \
            any(character not in '0123456789abcdef' for character in sys.argv[1]):
        raise ValueError('Pinned copy manifest SHA required')
    manifest_raw, manifest_identity = read(MANIFEST, 65536)
    if hashlib.sha256(manifest_raw).hexdigest() != sys.argv[1]:
        raise ValueError('Materialization manifest changed')
    manifest = decode(manifest_raw)
    if encode(manifest) != manifest_raw or set(manifest) != {'schema', 'acceptedCommit', 'sources'} or \
            manifest['schema'] != 'named-fixtures0067-materialization-v1' or \
            set(manifest['sources']) != {'authority', 'checkpoint', 'runner', 'controller', 'guard'}:
        raise ValueError('Unexpected materialization scope')
    data = {}
    source_identities = {}
    for role, binding in manifest['sources'].items():
        if set(binding) != {'path', 'bytes', 'sha256'}:
            raise ValueError('Unexpected copy binding')
        data[role], source_identities[role] = read(Path(binding['path']), 65536, binding)
    authority = decode(data['authority'])
    if authority['acceptedCommit'] != manifest['acceptedCommit'] or authority['action'] != '0067':
        raise ValueError('Copy authority/commit mismatch')
    roles = (('authority.json', 'authority'), ('checkpoint.json', 'checkpoint'),
             ('run_windows_named_guard_fixtures.py', 'runner'))
    windows_roles = (('authority.json', 'authority'), ('Invoke-WindowsNamedGuardFixtures.ps1', 'controller'),
                     ('WindowsFinalPublishGuard.dll', 'guard'))
    total_copy_bytes = sum(len(data[role]) for _, role in (*roles, *windows_roles))
    if total_copy_bytes > 262144:
        raise ValueError('Copied output allowance')
    directories = []
    copies = []
    held = []
    try:
        for root, selected in zip(OUTPUTS, (roles, windows_roles), strict=True):
            context('create-root', root)
            pfd = parent(root)
            rootfd = None
            try:
                os.mkdir(root.name, mode=0o700, dir_fd=pfd)
                created = os.stat(root.name, dir_fd=pfd, follow_symlinks=False)
                rootfd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
                original = directory_identity(created)
                same(original, directory_identity(os.fstat(rootfd)), 'created-root-vs-opened')
                held.append((root, pfd, rootfd, original))
                directories.append({'path': str(root), 'identity': original})
                for leaf, role in selected:
                    join_roots(held)
                    created_leaf = write(rootfd, leaf, data[role], original, root / leaf)
                    actual, observed = read(root / leaf, 65536, held_parent=rootfd, expected_identity=created_leaf)
                    if actual != data[role]:
                        raise ValueError('Materialization readback mismatch')
                    join_roots(held)
                    copies.append({'path': str(root / leaf), 'bytes': len(actual),
                                   'sha256': hashlib.sha256(actual).hexdigest(), 'identity': observed})
                os.fsync(pfd)
            except BaseException:
                if not any(item[1] == pfd for item in held):
                    if rootfd is not None:
                        os.close(rootfd)
                    os.close(pfd)
                raise
        join_roots(held)
        receipt = {'schema': 'named-fixtures0067-materialized-v1', 'manifestSha256': sys.argv[1],
                   'manifestIdentity': manifest_identity, 'sourceIdentities': source_identities,
                   'directories': directories, 'copies': copies,
                   'beforeReceipt': {'reads': READS, 'requestedBytes': REQUESTED, 'writtenBytes': WRITTEN,
                                     'elapsedMilliseconds': int((time.monotonic() - STARTED) * 1000)},
                   'executionAdmitted': False}
        raw = encode(receipt)
        if len(raw) > 65536:
            raise ValueError('Materialization receipt bound')
        pfd = parent(RECEIPT)
        try:
            receipt_identity = write(pfd, RECEIPT.name, raw, directory_identity(os.fstat(pfd)), RECEIPT)
            join_roots(held)
            observed, _ = read(RECEIPT, 65536, held_parent=pfd, expected_identity=receipt_identity)
            if observed != raw:
                raise ValueError('Materialization receipt readback')
            join_roots(held)
        finally:
            os.close(pfd)
        check()
        print(json.dumps({'complete': True, 'materialization': {'bytes': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest()},
                         'continuation_allowed': False}, sort_keys=True), flush=True)
        check()
    finally:
        for _, pfd, rootfd, _ in reversed(held):
            os.close(rootfd)
            os.close(pfd)


def main():
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('Original materialization clock')))
    signal.setitimer(signal.ITIMER_REAL, max(0.001, 30 - (time.monotonic() - STARTED)))
    try:
        try:
            materialize()
            check()
        except Exception as error:
            # Report only values already sampled by the rejected operation.
            # Failure never reopens or observes a partial output to enrich evidence.
            check()
            failure = {'complete': False, 'continuation_allowed': False,
                       'failureType': type(error).__name__, 'context': CONTEXT,
                       'comparison': MISMATCH,
                       'reads': READS, 'requestedBytes': REQUESTED, 'writtenBytes': WRITTEN}
            raw = encode(failure)
            if len(raw) > 4096:
                raise ValueError('Original failure output ceiling') from None
            print(raw.decode('ascii'), end='', flush=True)
            check()
            raise SystemExit(1) from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    main()
