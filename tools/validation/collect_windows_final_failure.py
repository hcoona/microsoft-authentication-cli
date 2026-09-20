"""Inactive, fixed 0063 control-record observer; requires an admitted literal.

The literal must load the exact retained source, bind the accepted protocol and
Wave, and consume the one observation before calling collect_final_failure.
This module has no executable command-line entry point and never launches work.
"""

import errno
import hashlib
import json
import os
import re
import signal
import stat
import time


DESTINATION = '/tmp/windows-final-publish0063-failure-observation-root-v1'
VERIFIERS = '/var/tmp/azureauth-final-publish-verifiers-108-post0062-v1'
LOCAL = '/var/tmp/azureauth-windows-slice-108/windows-actions/0063'
WINDOWS = '/mnt/c/Temp/azureauth-windows-slice-108/actions/0063'
SOURCE_PATH = 'tools/validation/collect_windows_final_failure.py'
PROTOCOL_PATH = 'docs/research/experiments/windows-slice-validation.md'
TRANSPORT = {
    'bytes': 1309,
    'sha256': 'b058a465019a252fa4c6f07637f470631d1a7f772168ee1e8f6da139e3400024',
}
LIMITS = {
    'seconds': 30, 'jsonLeaves': 208, 'contentBytes': 3956736,
    'requestedBytes': 3956944, 'manifestBytes': 262144,
    'outputBytes': 4218880, 'snapshots': 208,
}
IDENTITY_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size',
                   'st_mtime_ns', 'st_ctime_ns', 'st_nlink', 'st_uid', 'st_gid')
_USED = False


def _leaves():
    values = [('verifiers-start', VERIFIERS + '/started.json', 4096)]
    for number in range(1, 99):
        prefix = f'{number:02d}'
        for name, maximum in (('started', 4096), ('result', 32768)):
            values.append((f'verifier-{prefix}-{name}',
                           f'{VERIFIERS}/{prefix}/{name}.json', maximum))
    for label, root, names in (
        ('wsl', LOCAL, (('started', 16384), ('controller-exit', 16384),
                        ('windows-input', 4096), ('result', 65536),
                        ('windows-result', 65536))),
        ('windows', WINDOWS, (('started', 16384), ('controller-exit', 16384),
                              ('invocation', 65536), ('windows-result', 65536),
                              ('clock-ready', 4096), ('clock-remaining', 4096))),
    ):
        values.extend((f'{label}-{name}', f'{root}/{name}.json', maximum)
                      for name, maximum in names)
    return tuple(values)


LEAVES = _leaves()


def _json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _identity(info):
    return [getattr(info, field) for field in IDENTITY_FIELDS]


def _directory_identity(info):
    # Directory timestamps and size can change when an original writer adds a
    # file. Identity checks do not claim that those writers have stopped.
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]


def _descriptor(value, repository_path, maximum):
    expected = {'commit', 'tree', 'gitBlob', 'repositoryPath', 'bytes', 'sha256'}
    if type(value) is not dict or set(value) != expected:
        raise ValueError('Admission descriptor shape')
    if value['repositoryPath'] != repository_path:
        raise ValueError('Admission repository path')
    for name in ('commit', 'tree', 'gitBlob', 'sha256'):
        length = 64 if name == 'sha256' else 40
        if type(value[name]) is not str or re.fullmatch(f'[0-9a-f]{{{length}}}', value[name]) is None:
            raise ValueError('Admission digest')
    if type(value['bytes']) is not int or not 1 <= value['bytes'] <= maximum:
        raise ValueError('Admission length')


def _admission(value):
    expected = {'schema', 'scope', 'action', 'destination', 'limits',
                'collectorSource', 'protocol', 'wave', 'originalTransport'}
    if type(value) is not dict or set(value) != expected:
        raise ValueError('Admission shape')
    if (value['schema'] != 'final-0063-failure-observation-admission-v1'
            or value['scope'] != 'one-passive-control-record-observation'
            or value['action'] != '0063' or value['destination'] != DESTINATION
            or _json(value['limits']) != _json(LIMITS)
            or _json(value['originalTransport']) != _json(TRANSPORT)):
        raise ValueError('Admission scope')
    _descriptor(value['collectorSource'], SOURCE_PATH, 65536)
    _descriptor(value['protocol'], PROTOCOL_PATH, 2097152)
    _descriptor(value['wave'], 'docs/delivery-wave.md', 65536)
    if any(value[role][key] != value['protocol'][key]
           for role in ('collectorSource', 'wave') for key in ('commit', 'tree')):
        raise ValueError('Admission accepted revision')
    if len(_json(value)) > 16384:
        raise ValueError('Admission size')
    # Detach the admitted descriptors from caller-owned mutable dictionaries.
    return json.loads(_json(value))


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('Duplicate JSON key')
        value[key] = item
    return value


def _constant(_value):
    raise ValueError('Nonfinite JSON value')


def _json_shape(data):
    if not data:
        return 'empty-json'
    try:
        text = data.decode('utf-8-sig')
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
        return 'json-object' if type(value) is dict else 'invalid-json-root'
    except UnicodeError:
        return 'invalid-json-encoding'
    except json.JSONDecodeError as error:
        # This records the parser's EOF position, not a claim about why the
        # original file is incomplete or whether its writer remains alive.
        return 'json-error-at-eof' if error.pos >= len(text.rstrip()) else 'invalid-json'
    except (ValueError, RecursionError):
        return 'invalid-json'


class _Observation:
    def __init__(self, began):
        self.began = began
        self.deadline = began + LIMITS['seconds']
        self.interrupted = False
        self.uid = os.geteuid()
        self.directories = {}
        self.unavailable = {}
        self.destination = None
        self.destination_identity = None
        self.manifest_attempted = False
        self.manifest_descriptor = None
        self.output_bytes = 0
        self.reads = 0
        self.requested_bytes = 0
        self.content_bytes = 0
        self.snapshots = 0
        self.records = []
        self.admission = None

    def check(self):
        if self.interrupted or time.monotonic() >= self.deadline:
            raise TimeoutError('Observation ended')

    def interrupt(self, _number, _frame):
        self.interrupted = True
        raise InterruptedError('Observation interrupted')

    def _owner(self, path, info):
        if path in ('/', '/var', '/var/tmp', '/tmp', '/mnt'):
            return info.st_uid == 0
        if path in ('/mnt/c', '/mnt/c/Temp'):
            return info.st_uid in (0, self.uid)
        return info.st_uid == self.uid

    def check_directory(self, path):
        fd, expected = self.directories[path]
        self.check()
        held = os.fstat(fd)
        if path == '/':
            named = os.stat('/', follow_symlinks=False)
        else:
            parent, leaf = path.rsplit('/', 1)
            named = os.stat(leaf, dir_fd=self.directories[parent or '/'][0], follow_symlinks=False)
        self.check()
        if (_directory_identity(held) != expected
                or _directory_identity(named) != expected):
            raise RuntimeError('Ancestor changed')

    def directory(self, path):
        self.check()
        if path in self.unavailable:
            return None, self.unavailable[path]
        if path in self.directories:
            self.check_directory(path)
            return self.directories[path][0], None
        parent_fd = None
        leaf = '/'
        if path != '/':
            parent, leaf = path.rsplit('/', 1)
            parent_fd, unavailable = self.directory(parent or '/')
            if unavailable is not None:
                self.unavailable[path] = unavailable
                return None, unavailable
        fd = None
        try:
            self.check()
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=parent_fd)
            self.check()
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or not self._owner(path, info):
                raise PermissionError(errno.EPERM, 'Ancestor owner or type')
            self.directories[path] = (fd, _directory_identity(info))
            fd = None
            self.check_directory(path)
            return self.directories[path][0], None
        except OSError as error:
            if isinstance(error, (InterruptedError, TimeoutError)):
                raise
            kind = 'missing-ancestor' if error.errno == errno.ENOENT else 'inaccessible-ancestor'
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                kind = 'rejected-ancestor'
            value = {'status': kind, 'ancestor': path, 'errno': error.errno}
            self.unavailable[path] = value
            return None, value
        finally:
            if fd is not None:
                os.close(fd)

    def create_destination(self):
        parent, unavailable = self.directory('/tmp')
        if unavailable is not None:
            raise RuntimeError('Output parent unavailable')
        name = DESTINATION.rsplit('/', 1)[1]
        self.check()
        # mkdir itself is the exclusive existence check. Never preview/reuse it.
        os.mkdir(name, mode=0o700, dir_fd=parent)
        self.check()
        self.destination = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                   dir_fd=parent)
        info = os.fstat(self.destination)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise RuntimeError('Output directory identity')
        self.destination_identity = _directory_identity(info)
        self.check_destination()
        os.fsync(parent)
        self.check()

    def check_destination(self):
        self.check()
        named = os.stat(DESTINATION.rsplit('/', 1)[1],
                        dir_fd=self.directories['/tmp'][0], follow_symlinks=False)
        if (_directory_identity(named) != self.destination_identity
                or _directory_identity(os.fstat(self.destination)) != self.destination_identity):
            raise RuntimeError('Output directory changed')
        self.check()

    def save(self, name, data):
        self.check_destination()
        if self.output_bytes + len(data) > LIMITS['outputBytes']:
            raise ValueError('Output byte ceiling')
        self.output_bytes += len(data)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=self.destination)
        try:
            self.check()
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_nlink != 1:
                raise RuntimeError('Output file identity')
            offset = 0
            while offset < len(data):
                self.check()
                written = os.write(fd, data[offset:])
                self.check()
                if written <= 0:
                    raise OSError('Incomplete output')
                offset += written
            os.fsync(fd)
            self.check()
            os.fchmod(fd, 0o400)
            os.fsync(fd)
            self.check()
            held = os.fstat(fd)
            named = os.stat(name, dir_fd=self.destination, follow_symlinks=False)
            if (held.st_dev != info.st_dev or held.st_ino != info.st_ino
                    or held.st_size != len(data) or stat.S_IMODE(held.st_mode) != 0o400
                    or held.st_uid != self.uid or held.st_nlink != 1
                    or _identity(held) != _identity(named)):
                raise RuntimeError('Output continuity')
            os.fsync(self.destination)
            self.check_destination()
            return {'name': name, 'bytes': len(data), 'sha256': _sha(data)}
        finally:
            os.close(fd)

    def observe(self, label, path, maximum, metadata_only=False):
        self.check()
        record = {'label': label, 'path': path, 'limit': maximum, 'status': 'not-completed'}
        self.records.append(record)
        parent_path, name = path.rsplit('/', 1)
        parent, unavailable = self.directory(parent_path)
        if unavailable is not None:
            record.update(unavailable)
            return
        self.check_directory(parent_path)
        fd = None
        try:
            self.check()
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            record['before'] = _identity(before)
            self.check()
            if not stat.S_ISREG(before.st_mode):
                record['status'] = 'rejected-leaf-type'
                return
            if before.st_uid != self.uid or before.st_nlink != 1:
                record['status'] = 'rejected-leaf-owner-or-links'
                return
            if metadata_only:
                after = os.stat(name, dir_fd=parent, follow_symlinks=False)
                record['after'] = _identity(after)
                record['status'] = ('changed' if _identity(before) != _identity(after)
                                    else 'zero-byte-marker' if before.st_size == 0
                                    else 'nonempty-marker')
                return
            if before.st_size > maximum:
                record['status'] = 'oversized'
                return
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            self.check()
            held_before = os.fstat(fd)
            record['opened'] = _identity(held_before)
            if _identity(held_before) != _identity(before):
                record['status'] = 'changed-before-read'
                return
            self.reads += 1
            self.requested_bytes += maximum + 1
            if self.reads > LIMITS['jsonLeaves'] or self.requested_bytes > LIMITS['requestedBytes']:
                raise ValueError('Read ceiling')
            self.check()
            data = os.read(fd, maximum + 1)
            self.check()
            record['readBytes'] = len(data)
            self.content_bytes += min(len(data), maximum)
            held_after = os.fstat(fd)
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self.check()
            record['heldAfter'] = _identity(held_after)
            record['after'] = _identity(after)
            stable = _identity(before) == _identity(held_after) == _identity(after)
            if len(data) > maximum:
                record['status'] = 'oversized-after-open'
                return
            record['status'] = ('changed' if not stable else 'short-read'
                                if len(data) != before.st_size else 'stable-read')
            record['jsonShape'] = _json_shape(data)
            self.check()
            self.snapshots += 1
            if self.snapshots > LIMITS['snapshots'] or self.content_bytes > LIMITS['contentBytes']:
                raise ValueError('Snapshot ceiling')
            record['outputAttempted'] = True
            record['snapshot'] = self.save(label + '.json.bin', data)
        except OSError as error:
            if isinstance(error, (InterruptedError, TimeoutError)):
                raise
            if record.get('outputAttempted'):
                record['status'] = 'snapshot-write-failed'
                raise
            record['status'] = ('changed-or-disappeared' if 'before' in record
                                else 'missing-leaf' if error.errno == errno.ENOENT
                                else 'inaccessible-leaf')
            record['errno'] = error.errno
        finally:
            if fd is not None:
                os.close(fd)
            self.check_directory(parent_path)
            self.check()

    def manifest(self, complete, failure):
        self.check()
        if self.manifest_attempted:
            raise RuntimeError('Manifest already attempted')
        self.manifest_attempted = True
        value = {
            'schema': 'final-0063-failure-observation-v1',
            'observationComplete': complete, 'failureType': failure,
            'originalInvocationFailed': True, 'artifactEligible': False,
            'continuation_allowed': False, 'lifetimeEstablished': False,
            'admission': self.admission, 'records': self.records,
            'directories': {path: identity for path, (_fd, identity) in self.directories.items()},
            'identityFields': list(IDENTITY_FIELDS),
            'reads': self.reads, 'requestedBytes': self.requested_bytes,
            'contentBytes': self.content_bytes, 'snapshotAttempts': self.snapshots,
            'snapshotBytesReserved': self.output_bytes,
            'elapsedMillisecondsAtSerialization': int((time.monotonic() - self.began) * 1000),
        }
        data = _json(value)
        if len(data) > LIMITS['manifestBytes']:
            raise ValueError('Manifest ceiling')
        self.manifest_descriptor = self.save('manifest.json', data)

    def close(self):
        failed = False
        descriptors = [fd for fd, _identity_value in self.directories.values()]
        self.directories.clear()
        if self.destination is not None:
            descriptors.append(self.destination)
            self.destination = None
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except OSError:
                failed = True
        if failed:
            raise OSError('Descriptor finalization')


def collect_final_failure(*, reviewed_admission):
    """Observe once under a separately accepted literal, never from record paths.

    The literal binds the exact embedded source bytes and accepted protocol.
    Descriptor shape checks here neither perform Git queries nor grant acceptance.
    Every complete/incomplete return preserves the failed original invocation.
    """
    global _USED
    if _USED:
        raise RuntimeError('Observation already consumed')
    _USED = True
    observation = _Observation(time.monotonic())
    previous = {}
    alarm_installed = False
    failure = None
    complete = False
    try:
        if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
            raise RuntimeError('Existing alarm')
        for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, observation.interrupt)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, observation.deadline - time.monotonic()))
        alarm_installed = True
        observation.check()
        observation.admission = _admission(reviewed_admission)
        observation.check()
        if len(LEAVES) != 208 or sum(item[2] for item in LEAVES) != LIMITS['contentBytes']:
            raise RuntimeError('Closed read set')
        observation.create_destination()
        for label, path, maximum in LEAVES:
            observation.observe(label, path, maximum)
        observation.observe('windows-cancel', WINDOWS + '/cancel', 0, metadata_only=True)
        for path in observation.directories:
            observation.check_directory(path)
        observation.manifest(True, None)
        observation.close()
        observation.check()
        complete = True
    except BaseException as error:
        failure = type(error).__name__
        if (observation.destination is not None and observation.destination_identity is not None
                and not observation.manifest_attempted and not observation.interrupted
                and time.monotonic() < observation.deadline):
            try:
                observation.manifest(False, failure)
            except BaseException:
                pass
    finally:
        try:
            observation.close()
        except BaseException as error:
            complete = False
            failure = type(error).__name__
        if alarm_installed:
            signal.setitimer(signal.ITIMER_REAL, 0)
        for number, handler in previous.items():
            signal.signal(number, handler)
    if observation.interrupted or time.monotonic() >= observation.deadline:
        complete = False
        failure = failure or 'ObservationDeadline'
    result = {'observationComplete': complete, 'failureType': failure,
              'manifest': observation.manifest_descriptor,
              'originalInvocationFailed': True, 'artifactEligible': False,
              'continuation_allowed': False, 'lifetimeEstablished': False}
    # The admitted literal owns transport and must reject any incomplete return,
    # late finalization, nonzero exit, or incomplete frame. Never print raw input.
    return result


if __name__ == '__main__':
    raise RuntimeError('Inactive: a separately admitted exact literal is required')
