"""Inert bounded recovery of six public cutoff compilation leaves; no subject execution."""
import hashlib
import json
import os
import resource
import signal
import stat
import sys
import time

ADMISSION = None
RECOVERY = None
STAGE = '/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0188'
FILES = (('cutoff.generated.dll', 1048576), ('SelectedAccountControllerCutoff.dll', 1048576),
         ('cutoff-compilation-result.json', 8192), ('launcher.jsonl', 65536),
         ('launcher.stdout.bin', 65536), ('launcher.stderr.bin', 65536))


def full9(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]


def main():
    if ADMISSION is None or RECOVERY is None:
        return 125
    epoch = time.monotonic()
    owned, directories, leaves, absent = [], {}, [], []
    requested = 0
    cancelled = False
    output = None
    phase, leaf = 'startup', None

    def before():
        if cancelled or time.monotonic() - epoch >= 25:
            raise TimeoutError('Public result collection deadline')

    def stop(*_):
        nonlocal cancelled
        cancelled = True

    def opened(name, flags, parent=None, mode=0o600):
        before()
        if len(owned) >= 64:
            raise ValueError('Public result collection resources')
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        owned.append(fd)
        return fd

    def directory(path):
        if path in directories:
            return directories[path][0]
        if path == '/':
            fd = opened('/', os.O_RDONLY | os.O_DIRECTORY)
        else:
            parent, name = path.rsplit('/', 1)
            pfd = directory(parent or '/')
            named = full9(os.stat(name, dir_fd=pfd, follow_symlinks=False))[:5]
            fd = opened(name, os.O_RDONLY | os.O_DIRECTORY, pfd)
            if full9(os.fstat(fd))[:5] != named:
                raise ValueError('Public result collection ancestry')
        directories[path] = (fd, full9(os.fstat(fd))[:5])
        return fd

    def stable(pfd, name, fd, expected):
        before()
        if full9(os.fstat(fd)) != expected or full9(os.stat(name, dir_fd=pfd, follow_symlinks=False)) != expected:
            raise ValueError('Public result collection leaf changed')

    def read(fd, length):
        nonlocal requested
        before()
        requested += length + 1
        if requested > 4194304:
            raise ValueError('Public result collection byte limit')
        raw = os.read(fd, length)
        before()
        if len(raw) != length or os.read(fd, 1):
            raise ValueError('Public result collection read/EOF')
        return raw

    def decode(raw):
        def unique(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise ValueError('Duplicate public result key')
                d[k] = v
            return d
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                          parse_float=lambda _: (_ for _ in ()).throw(ValueError('Noninteger result')),
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite result')))

    def check_all():
        for name in absent:
            before()
            try:
                os.stat(name, dir_fd=directories[STAGE][0], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('Absent public leaf appeared during collection')
        for args in leaves:
            stable(*args)
        for path, (fd, ident) in directories.items():
            before()
            if full9(os.fstat(fd))[:5] != ident:
                raise ValueError('Public result collection held directory')
            if path != '/':
                parent, name = path.rsplit('/', 1)
                if full9(os.stat(name, dir_fd=directories[parent or '/'][0], follow_symlinks=False))[:5] != ident:
                    raise ValueError('Public result collection named directory')

    try:
        if sys.executable != '/usr/bin/python3.14' or not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode or len(sys.argv) != 1:
            raise ValueError('Public result collection runtime')
        if set(ADMISSION) != {'stageFull5', 'retentionParentFull5'}:
            raise ValueError('Public result collection admission')
        resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
        resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, stop)
        stage = directory(STAGE)
        parent = directory(RECOVERY)
        if full9(os.fstat(stage))[:5] != ADMISSION['stageFull5'] or full9(os.fstat(parent))[:5] != ADMISSION['retentionParentFull5']:
            raise ValueError('Public result collection parents')
        records, rows = {'absentLeaves': absent, 'captureDispositions': {}}, []
        phase = 'fixed-leaf-collection'
        for name, maximum in FILES:
            before()
            leaf = name
            try:
                named = full9(os.stat(name, dir_fd=stage, follow_symlinks=False))
            except FileNotFoundError:
                records['absentLeaves'].append(name)
                continue
            if not stat.S_ISREG(named[2]) or named[8] != 1 or not 0 <= named[5] <= maximum:
                raise ValueError('Public result collection file shape')
            fd = opened(name, os.O_RDONLY | os.O_NONBLOCK, stage)
            stable(stage, name, fd, named)
            if name.endswith('.bin') and named[5]:
                stable(stage, name, fd, named)
                leaves.append((stage, name, fd, named))
                records['captureDispositions'][name] = 'nonempty-suppressed-without-content-read'
                continue
            raw = read(fd, named[5])
            stable(stage, name, fd, named)
            leaves.append((stage, name, fd, named))
            rows.append(dict(name=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), full9=named))
            if name.endswith('.dll'):
                records.setdefault('artifacts', {})[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            elif name.endswith('.bin'):
                records['captureDispositions'][name] = 'empty-exact-eof'
            elif name == 'launcher.jsonl':
                records['launcher'] = [decode(line) for line in raw.splitlines()]
            else:
                records['compilation'] = decode(raw)
        check_all()
        snapshot = (json.dumps({'schema': 'selected-account-cutoff-compilation-recovery-snapshot-v1',
                                'stageFull5': ADMISSION['stageFull5'], 'windowsRows': rows,
                                'records': records, 'accountAccess': False, 'productStarted': False},
                               sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
        if len(snapshot) > 524288:
            raise ValueError('Public result collection snapshot bound')
        phase, leaf = 'exclusive-snapshot', None
        name = 'selected-account-cutoff-compilation-recovery-snapshot-v1.json'
        fd = opened(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, parent)
        before()
        if os.write(fd, snapshot) != len(snapshot):
            raise ValueError('Public result collection snapshot write')
        os.fsync(fd); os.fchmod(fd, 0o444); os.fsync(fd)
        current = full9(os.fstat(fd))
        if current[2] != stat.S_IFREG | 0o444 or current[8] != 1 or current[5] != len(snapshot):
            raise ValueError('Public result collection snapshot identity')
        os.lseek(fd, 0, os.SEEK_SET)
        if read(fd, len(snapshot)) != snapshot:
            raise ValueError('Public result collection snapshot readback')
        stable(parent, name, fd, current)
        leaves.append((parent, name, fd, current))
        os.fsync(parent); check_all()
        output = (json.dumps({'schema': 'selected-account-cutoff-compilation-recovery-collection-v1',
                              'name': name, 'bytes': len(snapshot), 'sha256': hashlib.sha256(snapshot).hexdigest(),
                              'full9': current, 'requestedReadBytes': requested,
                              'accountAccess': False, 'productStarted': False},
                             sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
        if len(output) > 2048:
            raise ValueError('Public result collection transport')
    except Exception:
        output = None
    finally:
        closefailed = False
        while owned:
            try:
                os.close(owned.pop())
            except OSError:
                closefailed = True
    if closefailed or output is None:
        failure = (json.dumps({'schema': 'selected-account-cutoff-compilation-recovery-failure-v1',
                               'phase': phase, 'leaf': leaf, 'allRegisteredDescriptorsClosed': not closefailed,
                               'accountAccess': False, 'productStarted': False},
                              sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
        try:
            if len(failure) <= 2048:
                os.write(1, failure)
        except OSError:
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
