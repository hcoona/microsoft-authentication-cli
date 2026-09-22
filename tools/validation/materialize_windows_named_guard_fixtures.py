"""Prepare fresh 0072 inputs with continuous created-file handles and bounded failure context."""

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time


MANIFEST = Path('/tmp/windows-named-fixtures0072-materialization-manifest.json')
OUTPUTS = (Path('/tmp/windows-named-fixtures0072-inputs'),
           Path('/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0072'),
           *(Path('/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-' + number)
             for number in ('0073', '0074', '0075', '0076')))
RECEIPT = Path('/tmp/windows-named-fixtures0072-materialized.json')
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
    role = next((label for label, root in zip(('linux-inputs', 'windows-inputs', 'cancel-inputs',
                 'collision-inputs', 'overflow-inputs', 'journal-inputs'), OUTPUTS, strict=True)
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


def close_owned(descriptors):
    # Each detached descriptor gets exactly one attempt, including after failure.
    first_error = None
    for fd in descriptors:
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as error:
                if first_error is None:
                    first_error = error
    if first_error is not None:
        raise first_error


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def directory_identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]


def parent(path):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Nonliteral copy path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    child = None
    try:
        for component in path.parts[1:-1]:
            check()
            named = os.stat(component, dir_fd=fd, follow_symlinks=False)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            same(directory_identity(named), directory_identity(os.fstat(child)), 'parent-open')
            closing = fd
            fd = child
            child = None
            os.close(closing)
        return fd
    except BaseException:
        closing = (fd, child)
        fd = child = None
        close_owned(closing)
        raise


def read(path, maximum, pinned=None, held_parent=None, expected_identity=None, held_file=None):
    global READS, REQUESTED
    context('read', path)
    check()
    READS += 1
    if READS > 32:
        raise ValueError('Materialization read count')
    pfd = parent(path) if held_parent is None else held_parent
    fd = None
    try:
        before = os.stat(path.name, dir_fd=pfd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError('Materialization source kind or size')
        if expected_identity is not None:
            same(expected_identity, identity(before), 'created-before-readback')
        fd = held_file if held_file is not None else os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
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
        closing = (fd if held_file is None else None,
                   pfd if held_parent is None else None)
        fd = None
        close_owned(closing)


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


def write_readback(pfd, name, raw, expected_parent, output_path):
    global WRITTEN
    context('write', output_path)
    check()
    if '/' in name or name in ('', '.', '..'):
        raise ValueError('Nonliteral copy output leaf')
    same(expected_parent, directory_identity(os.fstat(pfd)), 'write-parent-handle')
    WRITTEN += len(raw)
    if WRITTEN > 327680:
        raise ValueError('Materialization output bytes')
    writer = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=pfd)
    reader = None
    try:
        initial = os.fstat(writer)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise ValueError('Created file kind or link count')
        offset = 0
        while offset < len(raw):
            check()
            count = os.write(writer, raw[offset:offset + 65536])
            if count <= 0:
                raise OSError('Materialization write made no progress')
            offset += count
        os.fsync(writer)
        os.fchmod(writer, 0o444)
        os.fsync(writer)
        # Establish overlap before releasing the exclusive-create descriptor.
        # Mutable write-stage timestamps are not a future object-identity token.
        reader = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
        current = os.fstat(writer)
        same(identity(initial)[:2], identity(current)[:2], 'creator-object-continuity')
        same(identity(current), identity(os.fstat(reader)), 'creator-vs-overlapping-reader')
        same(identity(current), identity(os.stat(name, dir_fd=pfd, follow_symlinks=False)),
             'overlapping-handles-vs-named')
        closing_writer = writer
        writer = None
        os.close(closing_writer)
        os.fsync(pfd)
        check()
        baseline = os.fstat(reader)
        same(identity(initial)[:2], identity(baseline)[:2], 'reader-object-continuity')
        if (not stat.S_ISREG(baseline.st_mode) or baseline.st_mode & 0o222 or
                baseline.st_nlink != 1 or baseline.st_size != len(raw) or
                (baseline.st_uid, baseline.st_gid) != (initial.st_uid, initial.st_gid) or
                (current.st_mode, current.st_uid, current.st_gid, current.st_size,
                 current.st_nlink) != (baseline.st_mode, baseline.st_uid, baseline.st_gid,
                                      baseline.st_size, baseline.st_nlink)):
            raise ValueError('Final copied-file protection, ownership, size or links')
        # The only new read baseline follows our final mutating-handle close.
        # All nine fields must now agree with the name and remain stable.
        actual, observed = read(output_path, len(raw), held_parent=pfd,
                                expected_identity=identity(baseline), held_file=reader)
        if actual != raw:
            raise ValueError('Materialization readback mismatch')
        check()
        retained = reader
        reader = None
        return observed, retained
    finally:
        closing = (writer, reader)
        writer = reader = None
        close_owned(closing)


def join_files(files):
    for path, pfd, fd, original in files:
        context('copied-file-continuity', path)
        check()
        same(original, identity(os.fstat(fd)), 'retained-reader')
        same(original, identity(os.stat(path.name, dir_fd=pfd, follow_symlinks=False)),
             'retained-reader-vs-named')


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
            manifest['schema'] != 'named-fixtures0072-materialization-v1' or \
            set(manifest['sources']) != {'authority', 'checkpoint', 'runner', 'controller', 'guard', 'launcher',
                                        'failureDriver', 'failureController'}:
        raise ValueError('Unexpected materialization scope')
    data = {}
    source_identities = {}
    for role, binding in manifest['sources'].items():
        if set(binding) != {'path', 'bytes', 'sha256'}:
            raise ValueError('Unexpected copy binding')
        data[role], source_identities[role] = read(Path(binding['path']), 65536, binding)
    authority = decode(data['authority'])
    if authority['acceptedCommit'] != manifest['acceptedCommit'] or authority['action'] != '0072':
        raise ValueError('Copy authority/commit mismatch')
    roles = (('authority.json', 'authority'), ('checkpoint.json', 'checkpoint'),
             ('run_windows_named_guard_fixtures.py', 'runner'))
    windows_roles = (('authority.json', 'authority'), ('Invoke-WindowsNamedGuardFixtures.ps1', 'controller'),
                     ('WindowsFinalPublishGuard.dll', 'guard'), ('WindowsScriptJobLauncher.exe', 'launcher'),
                     ('WindowsLauncherFailureFixtures.ps1', 'failureDriver'))
    inner_roles = (('authority.json', 'authority'), ('Invoke-WindowsNamedGuardFixtures.ps1', 'failureController'))
    plans = (roles, windows_roles, inner_roles, inner_roles, inner_roles, inner_roles)
    total_copy_bytes = sum(len(data[role]) for plan in plans for _, role in plan)
    if total_copy_bytes > 262144:
        raise ValueError('Copied output allowance')
    directories = []
    copies = []
    held = []
    files = []
    receipt_parent = None
    try:
        for root, selected in zip(OUTPUTS, plans, strict=True):
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
                    observed, reader = write_readback(rootfd, leaf, data[role], original, root / leaf)
                    files.append((root / leaf, rootfd, reader, observed))
                    join_roots(held)
                    join_files(files)
                    copies.append({'path': str(root / leaf), 'bytes': len(data[role]),
                                   'sha256': hashlib.sha256(data[role]).hexdigest(), 'identity': observed})
                os.fsync(pfd)
            except BaseException:
                if not any(item[1] == pfd for item in held):
                    closing = (rootfd, pfd)
                    rootfd = pfd = None
                    close_owned(closing)
                raise
        join_roots(held)
        join_files(files)
        receipt = {'schema': 'named-fixtures0072-materialized-v1', 'manifestSha256': sys.argv[1],
                   'manifestIdentity': manifest_identity, 'sourceIdentities': source_identities,
                   'directories': directories, 'copies': copies,
                   'beforeReceipt': {'reads': READS, 'requestedBytes': REQUESTED, 'writtenBytes': WRITTEN,
                                     'elapsedMilliseconds': int((time.monotonic() - STARTED) * 1000)},
                   'executionAdmitted': False}
        raw = encode(receipt)
        if len(raw) > 65536:
            raise ValueError('Materialization receipt bound')
        receipt_parent = parent(RECEIPT)
        receipt_identity, reader = write_readback(receipt_parent, RECEIPT.name, raw,
            directory_identity(os.fstat(receipt_parent)), RECEIPT)
        files.append((RECEIPT, receipt_parent, reader, receipt_identity))
        join_roots(held)
        join_files(files)
        check()
        print(json.dumps({'complete': True, 'materialization': {'bytes': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest()},
                         'continuation_allowed': False}, sort_keys=True), flush=True)
        check()
    finally:
        closing = [fd for _, _, fd, _ in reversed(files)]
        closing.append(receipt_parent)
        for _, pfd, rootfd, _ in reversed(held):
            closing.extend((rootfd, pfd))
        files.clear()
        held.clear()
        receipt_parent = None
        close_owned(closing)


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
