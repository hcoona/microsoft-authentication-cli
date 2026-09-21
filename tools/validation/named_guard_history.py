"""Prospective, preparation-only reservation comparison; no executable entry point.

The exact accepted protocol and independently reviewed fixed-copy manifest must
admit every path before this module is called. It never inspects past outputs or
processes and does not establish historical quiescence.
"""

import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import time


ROOTS = {
    'linux': '/var/tmp/azureauth-windows-slice-108/actions',
    'wsl': '/var/tmp/azureauth-windows-slice-108/windows-actions',
    'windows': '/mnt/c/Temp/azureauth-windows-slice-108/actions',
}
COUNTS = {'preparation': 16, 'buildTest': 94, 'publication': 2, 'synthetic': 52}
MAX_LEAVES = 192
MAX_LEAF_BYTES = 16384
MAX_HISTORICAL_WINDOWS_BYTES = 1048576
MAX_READS = 2 * MAX_LEAVES + 2
MAX_READ_BYTES = 48 * 1024 * 1024


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate history field')
        result[key] = value
    return result


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _keys(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('History shape changed')


class ReservationComparison:
    """One before/after-reservation comparison under the caller's existing lock."""

    def __init__(self, manifest_bytes, expected_sha256, deadline_ns, cancelled, record_stage):
        if hashlib.sha256(manifest_bytes).hexdigest() != expected_sha256:
            raise ValueError('Fixed-copy manifest hash changed')
        if not 1 <= len(manifest_bytes) <= 1048576:
            raise ValueError('Fixed-copy manifest size')
        self.record_stage = record_stage
        self.stage = 'history-manifest'
        self.record_stage(self.stage, 'framing')
        self.manifest = json.loads(manifest_bytes.decode('utf-8'), object_pairs_hook=_pairs,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite history')))
        _keys(self.manifest, ('schema', 'scope', 'counts', 'nextAction', 'parents',
                              'reservations', 'acceptedBasis'))
        if (self.manifest['schema'] != 'named-guard-reservation-history-v1' or
                self.manifest['scope'] != 'one-compiler-only-preparation-after0065' or
                self.manifest['counts'] != COUNTS or self.manifest['nextAction'] != '0066'):
            raise ValueError('Fixed history scope or capacity changed')
        if any(type(self.manifest['counts'][key]) is not int for key in COUNTS):
            raise ValueError('History counter type')
        # Meaning and complete provenance of this fixed evidence basis belong to
        # its independent admission, not to a runtime boolean or this comparison.
        if type(self.manifest['acceptedBasis']) is not list or not self.manifest['acceptedBasis']:
            raise ValueError('Missing accepted fixed-copy basis')
        _keys(self.manifest['parents'], ROOTS)
        self.deadline_ns = min(deadline_ns, time.monotonic_ns() + 30_000_000_000)
        self.cancelled = cancelled
        self.passes = 0
        self.failed = False
        self.reads = 0
        self.requested_bytes = 0
        self.observed = {}
        self.actions = {}
        self.parents = {}
        self.record_stage(self.stage, 'slots')
        self._validate_manifest()

    def _budget(self):
        if self.cancelled():
            self.record_stage(self.stage, 'cancelled')
            raise InterruptedError('Original reservation comparison cancelled')
        if time.monotonic_ns() >= self.deadline_ns:
            self.record_stage(self.stage, 'deadline')
            raise TimeoutError('Original reservation comparison expired')

    def _validate_manifest(self):
        for role, root in ROOTS.items():
            parent = self.manifest['parents'][role]
            _keys(parent, ('path', 'names'))
            names = parent['names']
            if (parent['path'] != root or type(names) is not list or
                    not 1 <= len(names) <= 64 or
                    any(type(name) is not str or re.fullmatch(r'(?!0000)[0-9]{4}', name) is None
                        for name in names) or names != sorted(set(names)) or '0066' in names):
                raise ValueError('Exact physical history parent set changed')
        leaves = self.manifest['reservations']
        if type(leaves) is not list or not 1 <= len(leaves) <= MAX_LEAVES:
            raise ValueError('Reservation leaf bound')
        seen = set()
        for leaf in leaves:
            _keys(leaf, ('parent', 'number', 'status', 'sha256'))
            role, number = leaf['parent'], leaf['number']
            if role not in ROOTS or number not in self.manifest['parents'][role]['names']:
                raise ValueError('Reservation is outside an admitted physical slot')
            if (role, number) in seen:
                raise ValueError('Duplicate reservation slot')
            seen.add((role, number))
            if leaf['status'] == 'absent':
                if leaf['sha256'] is not None:
                    raise ValueError('Absent historical reservation has a hash')
            elif (leaf['status'] != 'present' or type(leaf['sha256']) is not str or
                  re.fullmatch('[0-9a-f]{64}', leaf['sha256']) is None):
                raise ValueError('Invalid reservation evidence')
        wanted = {(role, number) for role in ROOTS for number in self.manifest['parents'][role]['names']}
        if seen != wanted:
            raise ValueError('Incomplete physical reservation correspondence')

    def _open_directory(self, path):
        self._budget()
        if str(PurePosixPath(path)) != path or not path.startswith('/'):
            raise ValueError('Noncanonical reservation path')
        held = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in PurePosixPath(path).parts[1:]:
                self._budget()
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                dir_fd=held)
                os.close(held)
                held = child
            return held
        except BaseException:
            os.close(held)
            raise

    def _check_directory(self, held, parent, name):
        self._budget()
        actual = os.fstat(held)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode) or named.st_uid != os.getuid() or
                _directory_identity(actual) != _directory_identity(named)):
            raise ValueError('Named reservation directory changed')
        return _directory_identity(actual)

    def _inventory(self, fd, wanted):
        self._budget()
        with os.scandir(fd) as entries:
            names = []
            for entry in entries:
                self._budget()
                names.append(entry.name)
                if len(names) > 65:
                    raise ValueError('Unexpected history directory count')
        if sorted(names) != sorted(wanted):
            raise ValueError('Intervening, missing or unexplained action')

    def _read_reservation(self, action, leaf):
        self.record_stage(self.stage, 'reservation-presence')
        self._budget()
        fd = None
        try:
            if os.fstat(action).st_uid != os.getuid():
                raise ValueError('Unowned reservation directory')
            try:
                fd = os.open('started.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=action)
            except FileNotFoundError:
                if leaf['status'] == 'absent':
                    return None
                raise ValueError('Previously present reservation is missing') from None
            if leaf['status'] != 'present':
                raise ValueError('Previously absent reservation now exists')
            self.record_stage(self.stage, 'reservation-file-shape')
            before = os.fstat(fd)
            leaf_limit = (MAX_HISTORICAL_WINDOWS_BYTES
                          if leaf['parent'] == 'windows' and leaf['number'] != '0066'
                          else MAX_LEAF_BYTES)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                    before.st_nlink != 1):
                raise ValueError('Reservation file shape')
            self.record_stage(self.stage, 'reservation-size')
            if not 1 <= before.st_size <= leaf_limit:
                raise ValueError('Reservation file size')
            self.record_stage(self.stage, 'reservation-read-count')
            self.reads += 1
            if self.reads > MAX_READS:
                raise ValueError('Reservation comparison read bound')
            raw = bytearray()
            while len(raw) <= before.st_size:
                self._budget()
                requested = min(4096, max(1, before.st_size - len(raw)))
                self.record_stage(self.stage, 'reservation-byte-budget')
                self.requested_bytes += requested
                if self.requested_bytes > MAX_READ_BYTES:
                    raise ValueError('Reservation comparison requested-byte bound')
                self.record_stage(self.stage, 'reservation-read')
                part = os.read(fd, requested)
                if not part:
                    break
                raw.extend(part)
            self.record_stage(self.stage, 'reservation-identity')
            after = os.fstat(fd)
            named = os.stat('started.json', dir_fd=action, follow_symlinks=False)
            if _identity(before) != _identity(after) or _identity(after) != _identity(named):
                raise ValueError('Original reservation incarnation changed')
            self.record_stage(self.stage, 'reservation-hash')
            if len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != leaf['sha256']:
                raise ValueError('Original reservation bytes changed')
            self._budget()
            return _identity(after)
        finally:
            if fd is not None:
                os.close(fd)

    def compare(self, *, new_reservation_sha256=None):
        expected_pass = 0 if new_reservation_sha256 is None else 1
        self.stage = 'history-before' if expected_pass == 0 else 'history-after'
        self.record_stage(self.stage, 'pass-order')
        if self.failed or self.passes != expected_pass:
            raise ValueError('Repeated or reordered reservation comparison')
        if new_reservation_sha256 is not None and (type(new_reservation_sha256) is not str or
                re.fullmatch('[0-9a-f]{64}', new_reservation_sha256) is None):
            raise ValueError('Unbound new reservation')
        self.failed = True
        opened = {}
        actions = {}
        leaves = list(self.manifest['reservations'])
        if expected_pass:
            leaves.extend({'parent': role, 'number': '0066', 'status': 'present',
                           'sha256': new_reservation_sha256} for role in ('wsl', 'windows'))
        wanted_sets = {}
        try:
            self.record_stage(self.stage, 'parent-inventory')
            for role, root in ROOTS.items():
                fd = self._open_directory(root)
                opened[role] = fd
                info = os.fstat(fd)
                if info.st_uid != os.getuid():
                    raise ValueError('Unowned history parent')
                identity = _directory_identity(info)
                if expected_pass and self.parents.get(role) != identity:
                    raise ValueError('History parent was replaced')
                self.parents[role] = identity
                wanted = list(self.manifest['parents'][role]['names'])
                if expected_pass and role in ('wsl', 'windows'):
                    wanted.append('0066')
                wanted_sets[role] = wanted
                self._inventory(fd, wanted)
            for leaf in leaves:
                self.record_stage(self.stage, 'action-directory')
                key = (leaf['parent'], leaf['number'])
                self._budget()
                parent = opened[leaf['parent']]
                action = os.open(leaf['number'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=parent)
                actions[key] = action
                directory = self._check_directory(action, parent, leaf['number'])
                if expected_pass and leaf['number'] != '0066' and self.actions.get(key) != directory:
                    raise ValueError('Action directory replaced between passes')
                self.actions[key] = directory
                identity = self._read_reservation(action, leaf)
                self.record_stage(self.stage, 'action-and-leaf-continuity')
                self._check_directory(action, parent, leaf['number'])
                if expected_pass and leaf['number'] != '0066' and self.observed.get(key) != identity:
                    raise ValueError('Reservation identity changed between passes')
                self.observed[key] = identity
            self.record_stage(self.stage, 'final-continuity')
            # Recheck held action names and leaf incarnations after all reads.
            # These bounded sequential observations do not form an atomic snapshot.
            for leaf in leaves:
                key = (leaf['parent'], leaf['number'])
                action = actions[key]
                self._check_directory(action, opened[leaf['parent']], leaf['number'])
                self._budget()
                try:
                    named = _identity(os.stat('started.json', dir_fd=action, follow_symlinks=False))
                except FileNotFoundError:
                    named = None
                if named != self.observed[key]:
                    raise ValueError('Reservation changed during comparison pass')
            for role, root in ROOTS.items():
                self._inventory(opened[role], wanted_sets[role])
                fresh = self._open_directory(root)
                try:
                    if _directory_identity(os.fstat(fresh)) != self.parents[role]:
                        raise ValueError('Named history parent changed during comparison pass')
                finally:
                    os.close(fresh)
            self._budget()
            self.passes += 1
            self.failed = False
            return dict(COUNTS)
        finally:
            for fd in actions.values():
                os.close(fd)
            for fd in opened.values():
                os.close(fd)
