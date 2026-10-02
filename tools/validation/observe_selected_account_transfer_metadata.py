"""Observe only fixed names beneath the ended public transfer's retained stage."""

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
    'transfer-started.json', 'authority.json', 'Invoke-WindowsNamedGuardFixtures.ps1',
    'SelectedAccountMaterializationPins.cs', 'caller-inventory.json',
    'Authentication.Cli.exe', 'msalruntime.dll', 'selected-account-profile.json',
    'Invoke-WindowsSelectedAccount.ps1', 'R1.template.json', 'R6.template.json',
    'transfer-result.json',
)


def full9(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


class Observation:
    def __init__(self):
        self.epoch = time.monotonic()
        self.cancelled = False
        self.owned = []
        self.directories = {}
        self.opens = 0
        self.metadata_calls = 0

    def before(self):
        if self.cancelled or time.monotonic() - self.epoch >= 25:
            raise TimeoutError('Transfer metadata deadline')

    def metadata(self, fd, name=None):
        self.before()
        self.metadata_calls += 1
        if self.metadata_calls > 256:
            raise ValueError('Transfer metadata limit')
        return os.fstat(fd) if name is None else os.stat(name, dir_fd=fd, follow_symlinks=False)

    def opened(self, name, parent=None):
        self.before()
        self.opens += 1
        if self.opens > 32:
            raise ValueError('Transfer metadata opens')
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        self.owned.append(fd)
        return fd

    def directory(self, path):
        if path in self.directories:
            return self.directories[path][0]
        if path == '/':
            fd = self.opened('/')
            identity = full9(self.metadata(fd))[:5]
        else:
            parent, name = path.rsplit('/', 1)
            pfd = self.directory(parent or '/')
            identity = full9(self.metadata(pfd, name))[:5]
            fd = self.opened(name, pfd)
            if full9(self.metadata(fd))[:5] != identity:
                raise ValueError('Transfer metadata ancestry')
        self.directories[path] = (fd, identity)
        return fd

    def named(self, fd, name):
        try:
            return full9(self.metadata(fd, name))
        except FileNotFoundError:
            return None

    def stable(self):
        for path, (fd, identity) in self.directories.items():
            if full9(self.metadata(fd))[:5] != identity:
                raise ValueError('Held metadata ancestry changed')
            if path != '/':
                parent, name = path.rsplit('/', 1)
                pfd = self.directories[parent or '/'][0]
                if full9(self.metadata(pfd, name))[:5] != identity:
                    raise ValueError('Named metadata ancestry changed')

    def run(self):
        if sys.executable != '/usr/bin/python3.14' or not sys.flags.isolated or \
                not sys.flags.no_site or not sys.flags.dont_write_bytecode or len(sys.argv) != 1:
            raise ValueError('Unadmitted metadata runtime')
        if not isinstance(ADMISSION, dict) or set(ADMISSION) != {'stageParentFull5'}:
            raise ValueError('Metadata admission absent')
        identity = ADMISSION['stageParentFull5']
        if not isinstance(identity, list) or len(identity) != 5 or \
                any(type(value) is not int or value < 0 for value in identity):
            raise ValueError('Metadata admission shape')
        resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
        resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
        parent, name = STAGE.rsplit('/', 1)
        pfd = self.directory(parent)
        if full9(self.metadata(pfd))[:5] != identity:
            raise ValueError('Metadata parent changed')
        stage = self.named(pfd, name)
        rows = []
        if stage is not None:
            if not stat.S_ISDIR(stage[2]):
                raise ValueError('Metadata stage is not a directory')
            fd = self.directory(STAGE)
            if full9(self.metadata(fd))[:5] != stage[:5]:
                raise ValueError('Metadata stage changed')
            for leaf in LEAVES:
                rows.append(dict(name=leaf, namedFull9=self.named(fd, leaf)))
            for row in rows:
                if self.named(fd, row['name']) != row['namedFull9']:
                    raise ValueError('Named transfer metadata changed')
        elif self.named(pfd, name) is not None:
            raise ValueError('Absent metadata stage changed')
        self.stable()
        self.before()
        return dict(schema='selected-account-transfer-metadata-v1',
                    stagePresent=stage is not None, stageFull5=None if stage is None else stage[:5],
                    stageParentFull5=identity, rows=rows, opens=self.opens,
                    metadataCalls=self.metadata_calls, payloadReadCalls=0,
                    productStarted=False, accountAccess=False)

    def dispose(self):
        failure = None
        while self.owned:
            try:
                os.close(self.owned.pop())
            except OSError as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure


def main():
    if ADMISSION is None:
        return 125
    observation = Observation()
    signal.signal(signal.SIGTERM, lambda *_: setattr(observation, 'cancelled', True))
    signal.signal(signal.SIGINT, lambda *_: setattr(observation, 'cancelled', True))
    try:
        try:
            result = observation.run()
        finally:
            observation.dispose()
        observation.before()
        raw = (json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
        if len(raw) > 8192:
            raise ValueError('Metadata frame bound')
        if os.write(1, raw) != len(raw):
            raise ValueError('Metadata frame incomplete')
        observation.before()
        return 0
    except Exception:
        if not observation.cancelled and time.monotonic() - observation.epoch < 25:
            try:
                os.write(2, b'Transfer metadata failed.\n')
            except Exception:
                pass
        return 1


if __name__ == '__main__':
    sys.exit(main())
