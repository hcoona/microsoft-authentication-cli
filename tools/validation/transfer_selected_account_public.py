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
STAGE = '/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0193'
LEAVES = (
    'authority.json', 'Invoke-WindowsNamedGuardFixtures.ps1',
    'SelectedAccountMaterializationPins.cs', 'caller-inventory.json',
    'Authentication.Cli.exe', 'msalruntime.dll', 'selected-account-profile.json',
    'Invoke-WindowsSelectedAccount.ps1', 'R1.template.json', 'R6.template.json',
)
RECOVERY = '/home/shuaizhang/.local/state/azureauth-108-recovery-20260929'
SOURCE_PATHS = {name: RECOVERY + '/selected-account-public-inputs-v4/' + name for name in LEAVES}
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
        self.file_roles = {}
        self.created_content = {}
        self.copy_checks = []
        self.phase = 0
        self.role = 0
        self.ordinal = 0
        self.operation = 0
        self.mismatch = None
        self.first_fault = None
        self.cleanup_attempted = False
        self.cleanup_completed = False
        self.counts = dict(opens=0, metadata=0, reads=0, writes=0,
                           requestedReadBytes=0, writtenBytes=0, createdChecks=0)

    def native(self, operation, function, *args, **kwargs):
        self.operation = operation
        return function(*args, **kwargs)

    def same(self, expected, observed):
        self.operation = 10
        if expected != observed:
            self.mismatch = dict(expected=expected, observed=observed,
                                 differingFields=[index for index, (left, right) in
                                                  enumerate(zip(expected, observed)) if left != right])
            raise ValueError('Public transfer identity mismatch')

    def held(self, pfd, name, fd, expected):
        self.files.append((pfd, name, fd, expected))
        self.file_roles[fd] = (self.role, self.ordinal)

    def capture_fault(self, error):
        if self.first_fault is None:
            code = error.errno if isinstance(error, OSError) else None
            numeric = type(code) is int and 0 <= code <= 65535
            self.first_fault = dict(phase=self.phase, role=self.role, ordinal=self.ordinal,
                                    operation=self.operation, kind=2 if numeric else 1,
                                    errno=code if numeric else None, mismatch=self.mismatch,
                                    counts=dict(self.counts))

    def before(self):
        if self.cancelled or time.monotonic() - self.epoch >= 170:
            raise TimeoutError('Public transfer deadline')

    def charge(self, name, count, maximum):
        self.before()
        self.counts[name] += count
        if self.counts[name] > maximum:
            raise ValueError('Public transfer limit')
        if name in ('requestedReadBytes', 'writtenBytes') and \
                self.counts['requestedReadBytes'] + self.counts['writtenBytes'] > 67108864 - 32768:
            raise ValueError('Public transfer aggregate limit')

    def open(self, name, flags, parent=None, mode=0o600):
        self.charge('opens', 1, 128)
        fd = self.native(2, os.open, name, flags, mode, dir_fd=parent)
        self.owned.append(fd)
        return fd

    def close(self, fd):
        self.owned.remove(fd)
        self.native(9, os.close, fd)

    def metadata(self, fd, name=None):
        self.charge('metadata', 1, 1024)
        return self.native(3, os.fstat, fd) if name is None else \
            self.native(1, os.stat, name, dir_fd=fd, follow_symlinks=False)

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
            self.same(full5(info), full5(self.metadata(fd)))
        self.directories[path] = (fd, full5(info))
        return fd

    def stable(self, pfd, name, fd, expected):
        self.same(expected, full9(self.metadata(fd)))
        self.same(expected, full9(self.metadata(pfd, name)))

    def read(self, fd, length):
        data = bytearray()
        while len(data) < length:
            count = min(65536, length - len(data))
            self.charge('reads', 1, 8192)
            self.charge('requestedReadBytes', count, 67108864)
            block = self.native(5, os.read, fd, count)
            if not block:
                raise ValueError('Incomplete public transfer')
            data.extend(block)
        self.charge('reads', 1, 8192)
        self.charge('requestedReadBytes', 1, 67108864)
        if self.native(5, os.read, fd, 1):
            raise ValueError('Transfer EOF refused')
        return bytes(data)

    def write(self, pfd, name, raw):
        self.role = 3
        fd = self.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, pfd)
        initial = full9(self.metadata(fd))
        if not stat.S_ISREG(initial[2]) or initial[8] != 1 or initial[5] != 0:
            raise ValueError('Unexpected public output')
        offset = 0
        while offset < len(raw):
            block = raw[offset:offset + 65536]
            self.charge('writes', 1, 8192)
            self.charge('writtenBytes', len(block), 16777216)
            used = self.native(6, os.write, fd, block)
            if used <= 0:
                raise ValueError('Incomplete public write')
            offset += used
        self.native(7, os.fsync, fd)
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
        self.held(pfd, name, reader, current)
        digest = hashlib.sha256(raw).hexdigest()
        self.created_content[reader] = (len(raw), digest)
        self.native(8, os.fsync, pfd)
        self.operation = 11
        return dict(name=name, bytes=len(raw), sha256=digest,
                    full9=current, createdFull9=initial)

    def check_created(self, pfd, name, fd, original):
        self.charge('createdChecks', 1, 23)
        current = full9(self.metadata(fd))
        # Preserve the original descriptor and diagnose every other-field change.
        if any(original[index] != current[index] for index in (0, 1, 2, 3, 4, 5, 6, 8)):
            self.same(original, current)
        self.same(current, full9(self.metadata(pfd, name)))
        reread = current[7] != original[7]
        if reread:
            length, digest = self.created_content[fd]
            if self.native(14, os.lseek, fd, 0, os.SEEK_SET) != 0:
                raise ValueError('Public transfer seek refused')
            self.stable(pfd, name, fd, current)
            raw = self.read(fd, length)
            self.stable(pfd, name, fd, current)
            self.operation = 11
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('Public transfer qualified hash changed')
        self.copy_checks.append([self.phase, self.ordinal, original[7], current[7], reread])

    def check_all(self):
        self.role = 1
        self.ordinal = 0
        for path, (fd, expected) in self.directories.items():
            self.same(expected, full5(self.metadata(fd)))
            if path != '/':
                parent, leaf = path.rsplit('/', 1)
                self.same(expected, full5(self.metadata(self.directories[parent or '/'][0], leaf)))
        for pfd, name, fd, expected in self.files:
            self.role, self.ordinal = self.file_roles[fd]
            if self.role == 3 and fd in self.created_content:
                self.check_created(pfd, name, fd, expected)
            else:
                self.stable(pfd, name, fd, expected)

    def run(self):
        self.phase = 1
        if sys.executable != '/usr/bin/python3.14' or not sys.flags.isolated or \
                not sys.flags.no_site or not sys.flags.dont_write_bytecode or len(sys.argv) != 1:
            raise ValueError('Unadmitted transfer runtime')
        if not isinstance(ADMISSION, dict) or set(ADMISSION) != {'stageParentFull5', 'sources'} or \
                not isinstance(ADMISSION['sources'], dict) or set(ADMISSION['sources']) != set(LEAVES):
            raise ValueError('Transfer admission absent')
        self.native(13, resource.setrlimit, resource.RLIMIT_AS, (134217728, 134217728))
        self.native(13, resource.setrlimit, resource.RLIMIT_CPU, (170, 170))
        self.phase = 2
        self.role = 1
        parent, leaf = STAGE.rsplit('/', 1)
        pfd = self.directory(parent)
        self.same(ADMISSION['stageParentFull5'], full5(self.metadata(pfd)))
        self.phase = 3
        self.before(); self.native(4, os.mkdir, leaf, 0o700, dir_fd=pfd)
        stage = self.directory(STAGE)
        self.phase = 4
        self.operation = 12
        start = (json.dumps({'schema': 'selected-account-public-transfer-start-v1',
                            'admission': ADMISSION, 'epochMonotonic': self.epoch},
                            sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
        if len(start) > 16384:
            raise ValueError('Transfer start bound')
        start_row = self.write(stage, 'transfer-started.json', start)
        self.native(8, os.fsync, pfd)
        rows = []
        self.phase = 5
        for ordinal, name in enumerate(LEAVES, 1):
            self.role = 2
            self.ordinal = ordinal
            row = ADMISSION['sources'][name]
            if set(row) != {'path', 'bytes', 'sha256', 'full9'} or not isinstance(row['bytes'], int) or \
                    row['path'] != SOURCE_PATHS[name] or not 0 < row['bytes'] <= 10485760 or len(row['sha256']) != 64:
                raise ValueError('Unbounded public input')
            source_parent, source_leaf = row['path'].rsplit('/', 1)
            source_pfd = self.directory(source_parent)
            named = full9(self.metadata(source_pfd, source_leaf))
            self.same(row['full9'], named)
            if not stat.S_ISREG(named[2]) or named[8] != 1 or named[5] != row['bytes']:
                raise ValueError('Public input identity changed')
            source_fd = self.open(source_leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, source_pfd)
            self.stable(source_pfd, source_leaf, source_fd, named)
            raw = self.read(source_fd, row['bytes'])
            self.stable(source_pfd, source_leaf, source_fd, named)
            self.operation = 11
            if hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('Public input hash changed')
            self.held(source_pfd, source_leaf, source_fd, named)
            rows.append(self.write(stage, name, raw))
        self.phase = 6
        self.check_all()
        self.phase = 7
        stage_identity = full5(self.metadata(stage))
        self.operation = 12
        receipt = (json.dumps({'schema': 'selected-account-public-transfer-v2', 'rows': rows,
                              'startRow': start_row,
                              'copyChecks': self.copy_checks,
                              'stageFull5': stage_identity, 'countsBeforeReceipt': self.counts,
                              'productStarted': False, 'accountAccess': False},
                             sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
        if len(receipt) > 32768:
            raise ValueError('Transfer receipt bound')
        self.phase = 8
        self.ordinal = 11
        result = self.write(stage, 'transfer-result.json', receipt)
        self.phase = 9
        self.check_all(); self.before()
        result.update(schema='selected-account-public-transfer-result-v2',
                      copyChecks=self.copy_checks, countsAfterChecks=dict(self.counts))
        return result

    def dispose(self):
        self.phase = 10
        self.role = 5
        self.ordinal = 0
        self.cleanup_attempted = True
        failure = None
        while self.owned:
            fd = self.owned.pop()
            try:
                self.native(9, os.close, fd)
            except OSError as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure
        self.cleanup_completed = True


def main():
    if ADMISSION is None:
        return 125
    transfer = Transfer()
    signal.signal(signal.SIGTERM, lambda *_: setattr(transfer, 'cancelled', True))
    signal.signal(signal.SIGINT, lambda *_: setattr(transfer, 'cancelled', True))
    try:
        try:
            result = transfer.run()
        except Exception as error:
            transfer.capture_fault(error)
            raise
        finally:
            transfer.dispose()
        transfer.phase = 11
        transfer.role = 4
        transfer.ordinal = 0
        transfer.before()
        transfer.operation = 12
        raw = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
        if len(raw) > 8192:
            raise ValueError('Transfer frame bound')
        transfer.charge('writes', 1, 8192); transfer.charge('writtenBytes', len(raw), 16777216)
        if transfer.native(6, os.write, 1, raw) != len(raw):
            raise ValueError('Transfer frame incomplete')
        transfer.before(); return 0
    except Exception as error:
        transfer.capture_fault(error)
        transfer.operation = 12
        try:
            failure = (json.dumps(dict(schema='selected-account-public-transfer-failure-v2',
                                      firstFault=transfer.first_fault,
                                      cleanupAttempted=transfer.cleanup_attempted,
                                      cleanupCompleted=transfer.cleanup_completed),
                                  sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
            if len(failure) > 4096:
                failure = b'Public transfer failed.\n'
        except Exception:
            failure = b'Public transfer failed.\n'
        if not transfer.cancelled and time.monotonic() - transfer.epoch < 170 and \
                len(failure) <= 4096 and transfer.counts['writes'] < 8192 and \
                transfer.counts['writtenBytes'] <= 16777216 - len(failure):
            try:
                transfer.charge('writes', 1, 8192)
                transfer.charge('writtenBytes', len(failure), 16777216)
                transfer.native(6, os.write, 2, failure)
            except Exception:
                pass
        return 1


if __name__ == '__main__':
    sys.exit(main())
