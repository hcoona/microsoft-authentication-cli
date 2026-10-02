"""Inert, fixed two-leaf acquisition; authority and exact-call gates precede use."""

ADMISSION = None

import hashlib
import json
import os
import resource
import signal
import stat
import sys
import time

RETENTION_PARENT = "/home/shuaizhang/.local/state/azureauth-108-recovery-20260929"
DESTINATION = "selected-account-product-bytes-v1"
SOURCE_PARENT = "/mnt/c/Temp/azureauth-windows-slice-108/actions/0110/publish"
PRODUCT_COMMIT = "503360753accd0829801953823b1b57a4f852440"
PRODUCT_TREE = "8506cdd9781c8a331ea12ea8fe27a55292eec073"
LEAVES = (
    ("Authentication.Cli.exe", 8885248,
     "02993d94c5145f32274a8763f27d632e2dcc8e6a06d257551b1501eed9689cc7"),
    ("msalruntime.dll", 2949656,
     "9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79"),
)
LIMITS = {"opens": 32, "metadata": 256, "reads": 10,
          "requestedReadBytes": 23686197, "writes": 6,
          "writtenBytes": 11861784, "seeks": 5, "chmods": 4,
          "fsyncs": 12, "directories": 16}


def full9(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_nlink]


def dir5(value):
    return full9(value)[:5]


def need(condition):
    if not condition:
        raise RuntimeError("Acquisition refused")


class Acquisition:
    def __init__(self):
        self.epoch = time.monotonic_ns()
        self.cancelled = False
        self.counts = dict.fromkeys(LIMITS, 0)
        self.fds = []
        self.directories = []
        self.files = []
        self.path_fds = {}

    def check(self):
        need(not self.cancelled and time.monotonic_ns() - self.epoch < 60_000_000_000)

    def charge(self, key, amount=1):
        self.check()
        self.counts[key] += amount
        need(self.counts[key] <= LIMITS[key])

    def cancelled_signal(self, *_):
        self.cancelled = True

    def open(self, name, flags, parent=None, mode=0o600):
        self.charge("opens")
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=parent)
        self.fds.append(fd)
        need(len(self.fds) <= 32)
        return fd

    def held(self, fd):
        self.charge("metadata")
        return os.fstat(fd)

    def named(self, parent, name):
        self.charge("metadata")
        return os.stat(name, dir_fd=parent, follow_symlinks=False)

    def directory(self, path):
        if path in self.path_fds:
            return self.path_fds[path]
        if path == "/":
            parent, name = None, "/"
        else:
            parent = self.directory(os.path.dirname(path))
            name = os.path.basename(path)
        fd = self.open(name, os.O_RDONLY | os.O_DIRECTORY, parent)
        value = self.held(fd)
        need(stat.S_ISDIR(value.st_mode))
        need(dir5(value) == dir5(self.named(parent, name)))
        self.charge("directories")
        self.directories.append((fd, parent, name, dir5(value)))
        self.path_fds[path] = fd
        return fd

    def synchronize(self, fd):
        self.charge("fsyncs")
        os.fsync(fd)

    def write(self, fd, data):
        self.charge("writes")
        self.charge("writtenBytes", len(data))
        need(os.write(fd, data) == len(data))

    def read(self, fd, length):
        # Short reads fail; there is no retry or renewed requested-byte allowance.
        self.charge("reads")
        self.charge("requestedReadBytes", length)
        return os.read(fd, length)

    def exact_read(self, fd, length, expected_hash):
        before = full9(self.held(fd))
        need(stat.S_ISREG(before[2]) and before[8] == 1 and before[5] == length)
        data = self.read(fd, length)
        need(len(data) == length and hashlib.sha256(data).hexdigest() == expected_hash)
        need(self.read(fd, 1) == b"")
        need(full9(self.held(fd)) == before)
        return data, before

    def output(self, parent, name, data, readback):
        fd = self.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, parent)
        created = full9(self.held(fd))
        need(stat.S_ISREG(created[2]) and created[8] == 1 and created[5] == 0)
        need(created == full9(self.named(parent, name)))
        self.write(fd, data)
        self.synchronize(fd)
        self.charge("chmods")
        os.fchmod(fd, 0o444)
        self.synchronize(fd)
        sealed = full9(self.held(fd))
        need(sealed[0:2] == created[0:2] and sealed[3:5] == created[3:5])
        need(stat.S_ISREG(sealed[2]) and stat.S_IMODE(sealed[2]) == 0o444)
        need(sealed[5] == len(data) and sealed[8] == 1)
        need(sealed == full9(self.named(parent, name)))
        digest = hashlib.sha256(data).hexdigest()
        if readback:
            self.charge("seeks")
            need(os.lseek(fd, 0, os.SEEK_SET) == 0)
            checked, observed = self.exact_read(fd, len(data), digest)
            need(checked == data and observed == sealed)
        self.files.append((fd, parent, name, sealed))
        return {"name": name, "bytes": len(data), "sha256": digest,
                "full9": sealed}

    def continuity(self):
        for fd, parent, name, expected in self.directories:
            need(dir5(self.held(fd)) == expected)
            need(dir5(self.named(parent, name)) == expected)
        for fd, parent, name, expected in self.files:
            need(full9(self.held(fd)) == expected)
            need(full9(self.named(parent, name)) == expected)

    def run(self):
        signal.signal(signal.SIGTERM, self.cancelled_signal)
        signal.signal(signal.SIGINT, self.cancelled_signal)
        resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        need(isinstance(ADMISSION, dict) and set(ADMISSION) == {
            "waveSha256", "safetySha256", "protocolSha256",
            "retentionParentFull5", "sourceAdmissionSha256"})
        for key in ("waveSha256", "safetySha256", "protocolSha256", "sourceAdmissionSha256"):
            value = ADMISSION[key]
            need(type(value) is str and len(value) == 64 and
                 all(character in "0123456789abcdef" for character in value))
        pin = ADMISSION["retentionParentFull5"]
        need(type(pin) is list and len(pin) == 5 and
             all(type(value) is int for value in pin))
        parent = self.directory(RETENTION_PARENT)
        need(dir5(self.held(parent)) == pin)
        self.check()
        os.mkdir(DESTINATION, mode=0o700, dir_fd=parent)
        root = self.directory(RETENTION_PARENT + "/" + DESTINATION)
        need(self.held(root).st_uid == os.getuid())
        start = {"schema": "selected-account-product-acquisition-start-v1",
                 "admission": ADMISSION, "epochMonotonicNs": self.epoch,
                 "sourceParent": SOURCE_PARENT,
                 "destination": RETENTION_PARENT + "/" + DESTINATION,
                 "sourceCommit": PRODUCT_COMMIT, "sourceTree": PRODUCT_TREE}
        start_data = encoded(start, 8192)
        start_row = self.output(root, "started.json", start_data, False)
        self.synchronize(root)
        self.synchronize(parent)
        # No original-output ancestry or payload is opened before durable start.
        donor = self.directory(SOURCE_PARENT)
        rows = []
        for name, length, digest in LEAVES:
            fd = self.open(name, os.O_RDONLY | os.O_NONBLOCK, donor)
            current = full9(self.held(fd))
            need(current == full9(self.named(donor, name)))
            data, observed = self.exact_read(fd, length, digest)
            need(observed == current)
            self.files.append((fd, donor, name, current))
            output = self.output(root, name, data, True)
            rows.append({"literalSource": SOURCE_PARENT + "/" + name,
                         "currentSourceFull9": current, "retained": output})
        self.continuity()
        manifest = {"schema": "selected-account-product-acquisition-v1",
                    "admission": ADMISSION, "started": start_row,
                    "sourceCommit": PRODUCT_COMMIT, "sourceTree": PRODUCT_TREE,
                    "rows": rows, "provenanceJoinAccepted": False,
                    "noExperimentLive": False,
                    "claim": "Current exact-byte correspondence only; original exit and timing required."}
        manifest_data = encoded(manifest, 16384)
        manifest_row = self.output(root, "manifest.json", manifest_data, True)
        self.synchronize(root)
        self.synchronize(parent)
        self.continuity()
        self.check()
        return manifest_row

    def close(self):
        # Close every owned descriptor even after the deadline or cancellation.
        failed = False
        for fd in reversed(self.fds):
            try:
                os.close(fd)
            except OSError:
                failed = True
        self.fds.clear()
        need(not failed)


def encoded(value, cap):
    data = (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    need(len(data) <= cap)
    return data


def main():
    if ADMISSION is None:
        return 125
    acquisition = Acquisition()
    try:
        result = acquisition.run()
        acquisition.close()
        acquisition.check()
        frame = encoded({"schema": "selected-account-product-acquisition-return-v1",
                         "manifest": result, "counts": acquisition.counts,
                         "noExperimentLive": False}, 2048)
        acquisition.write(1, frame)
        acquisition.check()
        return 0
    except BaseException:
        try:
            acquisition.close()
        except BaseException:
            pass
        # Fixed text only, never path-selected data, exceptions or payload bytes.
        try:
            acquisition.write(2, b"selected-account-product-acquisition-failed\n")
        except BaseException:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
