"""Transfer ten admitted public preparation leaves; never start a Windows subject."""

import hashlib
import json
import os
import resource
import signal
import stat
import sys
import time

ADMISSION = None
STAGE = '/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0189'
LEAVES = (
    'authority.json', 'Invoke-WindowsNamedGuardFixtures.ps1',
    'SelectedAccountMaterializationPins.cs', 'caller-inventory.json',
    'Authentication.Cli.exe', 'msalruntime.dll', 'selected-account-profile.json',
    'Invoke-WindowsSelectedAccount.ps1', 'R1.template.json', 'R6.template.json',
)
RECOVERY = '/home/shuaizhang/.local/state/azureauth-108-recovery-20260929'
SOURCE_PATHS = {name: RECOVERY + '/selected-account-public-inputs-v2/' + name for name in LEAVES}
for _name in ('Authentication.Cli.exe', 'msalruntime.dll'):
    SOURCE_PATHS[_name] = RECOVERY + '/selected-account-product-bytes-v1/' + _name


def full9(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def full5(info):
    return full9(info)[:5]


class Transfer:
    def __init__(self):
        self.epoch = time.monotonic()
        self.cancelled = False
        self.owned = []
        self.directories = {}
        self.files = []
        self.counts = dict(opens=0, metadata=0, reads=0, writes=0,
                           requestedReadBytes=0, writtenBytes=0)

    def before(self):
        if self.cancelled or time.monotonic() - self.epoch >= 170:
            raise TimeoutError('Public transfer deadline')

    def charge(self, name, count, maximum):
        self.before()
        self.counts[name] += count
        if self.counts[name] > maximum:
            raise ValueError('Public transfer limit')

    def open(self, name, flags, parent=None, mode=0o600):
        self.charge('opens', 1, 128)
        fd = os.open(name, flags, mode, dir_fd=parent)
        self.owned.append(fd)
        return fd

    def close(self, fd):
        self.owned.remove(fd)
        os.close(fd)

    def metadata(self, fd, name=None):
        self.charge('metadata', 1, 1024)
        return os.fstat(fd) if name is None else os.stat(name, dir_fd=fd, follow_symlinks=False)

    def directory(self, path):
        if path in self.directories:
            return self.directories[path][0]
        if not path.startswith('/') or any(p in ('', '.', '..') for p in path[1:].split('/')):
            if path != '/':
                raise ValueError('Nonliteral transfer ancestry')
        if path == '/':
            fd = self.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = self.metadata(fd)
        else:
            parent, leaf = path.rsplit('/', 1)
            pfd = self.directory(parent or '/')
            info = self.metadata(pfd, leaf)
            fd = self.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, pfd)
            if full5(self.metadata(fd)) != full5(info):
                raise ValueError('Transfer ancestry changed')
        self.directories[path] = (fd, full5(info))
        return fd

    def stable(self, pfd, name, fd, expected):
        if full9(self.metadata(fd)) != expected or full9(self.metadata(pfd, name)) != expected:
            raise ValueError('Transfer file changed')

    def read(self, fd, length):
        data = bytearray()
        while len(data) < length:
            count = min(65536, length - len(data))
            self.charge('reads', 1, 8192)
            self.charge('requestedReadBytes', count, 33554432)
            block = os.read(fd, count)
            if not block:
                raise ValueError('Incomplete public transfer')
            data.extend(block)
        self.charge('reads', 1, 8192)
        self.charge('requestedReadBytes', 1, 33554432)
        if os.read(fd, 1):
            raise ValueError('Transfer EOF refused')
        return bytes(data)

    def write(self, pfd, name, raw):
        fd = self.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, pfd)
        initial = full9(self.metadata(fd))
        if not stat.S_ISREG(initial[2]) or initial[8] != 1 or initial[5] != 0:
            raise ValueError('Unexpected public output')
        offset = 0
        while offset < len(raw):
            block = raw[offset:offset + 65536]
            self.charge('writes', 1, 8192)
            self.charge('writtenBytes', len(block), 16777216)
            used = os.write(fd, block)
            if used <= 0:
                raise ValueError('Incomplete public write')
            offset += used
        os.fsync(fd)
        # Close the mutating descriptor before taking the read-only baseline.
        # Created-copy ctime observations are retained; strict read continuity
        # starts at this new reader, without relaxing any source comparison.
        self.close(fd)
        reader = self.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, pfd)
        current = full9(self.metadata(reader))
        if current[:2] != initial[:2] or current[3:5] != initial[3:5] or \
                not stat.S_ISREG(current[2]) or current[5] != len(raw) or current[8] != 1:
            raise ValueError('Created transfer identity changed')
        self.stable(pfd, name, reader, current)
        if self.read(reader, len(raw)) != raw:
            raise ValueError('Public transfer readback refused')
        self.stable(pfd, name, reader, current)
        self.files.append((pfd, name, reader, current))
        os.fsync(pfd)
        return dict(name=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                    full9=current, createdFull9=initial)

    def check_all(self):
        for path, (fd, expected) in self.directories.items():
            if full5(self.metadata(fd)) != expected:
                raise ValueError('Held transfer directory changed')
            if path != '/':
                parent, leaf = path.rsplit('/', 1)
                if full5(self.metadata(self.directories[parent or '/'][0], leaf)) != expected:
                    raise ValueError('Named transfer directory changed')
        for pfd, name, fd, expected in self.files:
            self.stable(pfd, name, fd, expected)

    def run(self):
        if sys.executable != '/usr/bin/python3.14' or not sys.flags.isolated or \
                not sys.flags.no_site or not sys.flags.dont_write_bytecode or len(sys.argv) != 1:
            raise ValueError('Unadmitted transfer runtime')
        if not isinstance(ADMISSION, dict) or set(ADMISSION) != {'stageParentFull5', 'sources'} or \
                not isinstance(ADMISSION['sources'], dict) or set(ADMISSION['sources']) != set(LEAVES):
            raise ValueError('Transfer admission absent')
        resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
        resource.setrlimit(resource.RLIMIT_CPU, (170, 170))
        parent, leaf = STAGE.rsplit('/', 1)
        pfd = self.directory(parent)
        if full5(self.metadata(pfd)) != ADMISSION['stageParentFull5']:
            raise ValueError('Transfer parent changed')
        self.before(); os.mkdir(leaf, 0o700, dir_fd=pfd)
        stage = self.directory(STAGE)
        start = (json.dumps({'schema': 'selected-account-public-transfer-start-v1',
                            'admission': ADMISSION, 'epochMonotonic': self.epoch},
                            sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
        if len(start) > 16384:
            raise ValueError('Transfer start bound')
        self.write(stage, 'transfer-started.json', start)
        os.fsync(pfd)
        rows = []
        for name in LEAVES:
            row = ADMISSION['sources'][name]
            if set(row) != {'path', 'bytes', 'sha256', 'full9'} or not isinstance(row['bytes'], int) or \
                    row['path'] != SOURCE_PATHS[name] or not 0 < row['bytes'] <= 10485760 or len(row['sha256']) != 64:
                raise ValueError('Unbounded public input')
            source_parent, source_leaf = row['path'].rsplit('/', 1)
            source_pfd = self.directory(source_parent)
            named = full9(self.metadata(source_pfd, source_leaf))
            if named != row['full9'] or not stat.S_ISREG(named[2]) or named[8] != 1 or named[5] != row['bytes']:
                raise ValueError('Public input identity changed')
            source_fd = self.open(source_leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, source_pfd)
            self.stable(source_pfd, source_leaf, source_fd, named)
            raw = self.read(source_fd, row['bytes'])
            self.stable(source_pfd, source_leaf, source_fd, named)
            if hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('Public input hash changed')
            self.files.append((source_pfd, source_leaf, source_fd, named))
            rows.append(self.write(stage, name, raw))
        self.check_all()
        receipt = (json.dumps({'schema': 'selected-account-public-transfer-v1', 'rows': rows,
                              'stageFull5': full5(self.metadata(stage)), 'countsBeforeReceipt': self.counts,
                              'productStarted': False, 'accountAccess': False},
                             sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
        if len(receipt) > 32768:
            raise ValueError('Transfer receipt bound')
        result = self.write(stage, 'transfer-result.json', receipt)
        self.check_all(); self.before()
        return result

    def dispose(self):
        failure = None
        while self.owned:
            fd = self.owned.pop()
            try:
                os.close(fd)
            except OSError as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure


def main():
    if ADMISSION is None:
        return 125
    transfer = Transfer()
    signal.signal(signal.SIGTERM, lambda *_: setattr(transfer, 'cancelled', True))
    signal.signal(signal.SIGINT, lambda *_: setattr(transfer, 'cancelled', True))
    try:
        try:
            result = transfer.run()
        finally:
            transfer.dispose()
        transfer.before()
        raw = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
        if len(raw) > 2048:
            raise ValueError('Transfer frame bound')
        transfer.charge('writes', 1, 8192); transfer.charge('writtenBytes', len(raw), 16777216)
        if os.write(1, raw) != len(raw):
            raise ValueError('Transfer frame incomplete')
        transfer.before(); return 0
    except Exception:
        failure = b'Public transfer failed.\n'
        if not transfer.cancelled and time.monotonic() - transfer.epoch < 170 and \
                transfer.counts['writes'] < 8192 and transfer.counts['writtenBytes'] <= 16777216 - len(failure):
            try:
                transfer.charge('writes', 1, 8192)
                transfer.charge('writtenBytes', len(failure), 16777216)
                os.write(2, failure)
            except Exception:
                pass
        return 1


if __name__ == '__main__':
    sys.exit(main())
