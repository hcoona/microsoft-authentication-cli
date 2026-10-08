"""Inert retained-launcher offline restore/managed build caller and dedicated cgroup worker.

Source proposal only. Activation requires accepted source, artifact, checkpoint,
protocol and exact-call reviews. No history reader or legacy runner is imported.
"""

ADMITTED = False
if not ADMITTED:
    raise RuntimeError('Source-only final scenario caller; no execution is admitted')

import base64
from decimal import Decimal
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

LINUX = Path('/var/tmp/azureauth-windows-slice-108')
PROJECTION = Path('/mnt/c/Temp/azureauth-windows-slice-108')
WINDOWS = r'C:\Temp\azureauth-windows-slice-108'
CEILINGS = [100, 400, 60, 1200]  # Accepted shared pool; exact batch admission remains required.
HISTORICAL_UNKNOWN = ['0057', '0064', '0068', '0093', '0107', '0110']
PRODUCT = None  # Set to the accepted commit only in the exact admitted projection.
NORMAL_LAUNCHER = (23040, '5b018f38669fd6ca3cec8f760533af392e0265280047bfb5c531dd41a349690a')
LAUNCHER_PROJECTION = PROJECTION / 'normal-launcher-dispatch-v1' / 'WindowsScriptJobLauncher.exe'
CHARGES = {'restore': 1, 'build': 1, 'test': 1, 'publish': 1}
SERVICE_SECONDS = 550
PARENTS = {'linuxActions': LINUX / 'actions', 'windowsActions': LINUX / 'windows-actions',
           'windowsProjectionActions': PROJECTION / 'actions', 'windowsProjectionRoot': PROJECTION}


class PredicateFailure(ValueError):
    """Only require's fixed source labels are eligible for retained diagnostics."""

    def __init__(self, label, read_observation=None, pin_observation=None):
        super().__init__(label)
        self.read_observation = read_observation
        self.pin_observation = pin_observation


def require(condition, label, *, read_observation=None, pin_observation=None):
    if not condition:
        raise PredicateFailure(label, read_observation, pin_observation)


def failure_identity(error):
    # Inspect numeric locations in this source only, without formatting traceback
    # text, filenames, arbitrary exception messages, or rejected input payloads.
    line, trace = None, error.__traceback__
    for _ in range(64):
        if trace is None:
            break
        code = trace.tb_frame.f_code
        if code.co_filename == __file__ and code.co_name != 'require':
            line = trace.tb_lineno
        trace = trace.tb_next
    result = {'type': type(error).__name__, 'sourceLine': line,
              'predicate': str(error) if type(error) is PredicateFailure else None}
    if type(error) is PredicateFailure and error.read_observation is not None:
        observation = error.read_observation
        result['readObservation'] = (observation if len(encode(observation)) <= 2048 else
                                     {'omitted': 'serialization-bound'})
    if type(error) is PredicateFailure and error.pin_observation is not None:
        observation = error.pin_observation
        result['pinObservation'] = (observation if len(encode(observation)) <= 2048 else
                                    {'omitted': 'serialization-bound'})
    return result


def strict_json(raw, transport_numbers=False, ledger_numbers=False):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            assert k not in out
            out[k] = v
        return out
    def reject(_):
        raise ValueError('Noninteger/nonfinite numeric token')
    def finite_decimal(token):
        value = Decimal(token)
        assert value.is_finite()
        return value
    assert not (transport_numbers and ledger_numbers)
    return json.loads(raw, object_pairs_hook=unique,
                      parse_float=finite_decimal if ledger_numbers else float if transport_numbers else reject,
                      parse_constant=reject)

def exact_json_text(value, level=0):
    """Carry exact finite decimal primitives; ordinary records keep JSON types."""
    assert level <= 256
    if value is None or type(value) in (bool, int, str, float):
        return json.dumps(value, ensure_ascii=True, allow_nan=False)
    if type(value) is Decimal:
        assert value.is_finite()
        return str(value)
    assert type(value) in (list, dict)
    if type(value) is dict:
        assert all(type(key) is str for key in value)
        entries = [json.dumps(key, ensure_ascii=True) + ': ' + exact_json_text(value[key], level+1)
                   for key in sorted(value)]
        opening, closing = '{', '}'
    else:
        entries = [exact_json_text(item, level+1) for item in value]
        opening, closing = '[', ']'
    if not entries:
        return opening + closing
    indentation = '  ' * (level+1)
    return opening + '\n' + indentation + (',\n' + indentation).join(entries) + '\n' + '  '*level + closing

def typed(value):
    if isinstance(value, dict):
        return (dict, tuple((key, typed(value[key])) for key in sorted(value)))
    if isinstance(value, list):
        return (list, tuple(map(typed, value)))
    return (type(value), value)

def encode(value):
    return (exact_json_text(value) + '\n').encode('ascii')


def decode(raw):
    return strict_json(raw, ledger_numbers=True)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def direct(path):
    require(path.is_absolute(), 'Absolute path required')
    for parent in reversed(path.parents):
        require(not stat.S_ISLNK(parent.lstat().st_mode), 'Linked ancestor')
    require(not stat.S_ISLNK(path.lstat().st_mode), 'Linked path')
    return path


class Budget:
    def __init__(self, began, deadline, terminal_deadline):
        self.began, self.deadline = began, deadline
        self.terminal_deadline = terminal_deadline
        self.terminal_mode = False
        self.requested = 0
        self.reads = 0
        self.writes = 0
        self.written = 0
        self.created_directories = 0
        self.cancelled = False
        self.ctime_observations = []

    def enter_terminal(self):
        # Use the reserved final interval with the SAME aggregate counters. This
        # permits only terminal evidence/cancel attempts, never resumed main work.
        if not self.terminal_mode:
            self.terminal_deadline = min(self.terminal_deadline, time.monotonic_ns() + 10_000_000_000)
        self.terminal_mode = True
        self.deadline = self.terminal_deadline

    def check(self, reserve=0):
        require(not self.cancelled and time.monotonic_ns() + reserve < self.deadline,
                'Original interval expired or cancelled')

    def read(self, path, maximum):
        raw, observed, _ = self._read(path, maximum)
        return raw, observed

    def read_created_copy(self, path, maximum, created_identity, expected_payload):
        # Immediate readback requires complete admitted bytes, including an
        # explicitly empty payload for empty cache leaves.
        require(type(expected_payload) is bytes and type(created_identity) is list and
                len(created_identity) == 9 and all(type(x) is int for x in created_identity),
                'Created copy requires admitted payload and identity')
        _, observed, read_observation = self._read(
            path, maximum, created_identity=created_identity, expected_payload=expected_payload)
        return observed, read_observation

    def pin_created_copy(self, created, source, maximum, *, paired_build=False):
        # Restore copies and their explicitly bound paired build use this rule.
        # The original creation lineage remains the baseline; never refresh it.
        pin = qualified_created_descriptor(created, source, paired_build=paired_build)
        raw, _, observation = self._read(Path(pin['path']), maximum,
                                         created_identity=pin['identity'], created_copy_pin=True)
        require(len(raw) == pin['bytes'] and digest(raw) == pin['sha256'],
                'Created deployment differs from admitted content', read_observation=observation)
        return raw

    def _read(self, path, maximum, *, created_identity=None, expected_payload=None,
              created_copy_pin=False):
        self.check()
        direct(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, 'Regular bounded input')
            if created_identity is not None:
                # Every qualified copy read retains the original eight fields.
                # Its caller also requires exact admitted bytes or their digest.
                require(before.st_nlink == 1 and all(identity(before)[i] == created_identity[i]
                        for i in (0, 1, 2, 3, 4, 5, 6, 8)),
                        'Created deployment changed before pin' if created_copy_pin else
                        'Created copy changed before readback')
            self.reads += 1
            self.requested += before.st_size + 1
            require(self.reads <= 8192 and self.requested <= 4 * 1024 * 1024 * 1024, 'Aggregate read budget')
            parts, remaining = [], before.st_size + 1
            while remaining:
                self.check()
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                parts.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(parts)
            initial_identity = identity(before)
            final_identity = named_identity = None
            fields = (0, 1, 2, 3, 4, 5, 6, 8)

            def matches(observed):
                return all(initial_identity[i] == observed[i] for i in fields)

            # Preserve the existing short-circuit observations. A length failure
            # skips both metadata calls; a descriptor mismatch skips the path call.
            stable = (len(raw) == before.st_size and
                      matches(final_identity := identity(os.fstat(fd))) and
                      matches(named_identity := identity(path.lstat())))
            read_observation = {
                'readOrdinal': self.reads,
                'createdCopyReadback': created_identity is not None and not created_copy_pin,
                'expectedBytes': before.st_size, 'returnedBytes': len(raw),
                'initialDescriptor': initial_identity, 'finalDescriptor': final_identity,
                'namedPath': named_identity}
            if created_copy_pin:
                read_observation['createdCopyPin'] = True
            if not stable:
                require(False, 'Unstable descriptor/path identity', read_observation=read_observation)
            first_ordinal = self.reads
            require(os.lseek(fd, 0, os.SEEK_SET) == 0, 'Same-descriptor rewind')
            self.reads += 1
            self.requested += before.st_size + 1
            require(self.reads <= 8192 and self.requested <= 4 * 1024 * 1024 * 1024,
                    'Aggregate repeated-read budget')
            repeated, remaining = [], before.st_size + 1
            while remaining:
                self.check()
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                repeated.append(chunk)
                remaining -= len(chunk)
            second = b''.join(repeated)
            second_descriptor, second_named = identity(os.fstat(fd)), identity(path.lstat())
            require(len(second) == before.st_size and second == raw and digest(second) == digest(raw) and
                    matches(second_descriptor) and matches(second_named), 'Repeated content/non-ctime identity')
            read_observation.update(readOrdinal=first_ordinal, secondReadOrdinal=self.reads,
                                    secondDescriptor=second_descriptor, secondNamedPath=second_named,
                                    contentVerifiedTwice=True)
            if len({row[7] for row in (initial_identity, final_identity, named_identity,
                                      second_descriptor, second_named)}) > 1:
                self.ctime_observations.append({'path': str(path), 'read': read_observation})
                require(len(self.ctime_observations) <= 8192, 'Ctime observation bound')
            if created_identity is not None and not created_copy_pin:
                require(raw == expected_payload, 'Created copy differs from admitted payload')
            self.check()
            return (raw, named_identity if created_identity is not None else initial_identity,
                    read_observation)
        finally:
            os.close(fd)

    def pin(self, value, maximum):
        require(set(value) == {'path', 'bytes', 'sha256', 'identity'}, 'Exact descriptor fields')
        raw, observed = self.read(Path(value['path']), maximum)
        length_matches = len(raw) == value['bytes']
        digest_matches = digest(raw) == value['sha256'] if length_matches else None
        identity_matches = all(observed[i] == value['identity'][i] for i in (0, 1, 2, 3, 4, 5, 6, 8)) if digest_matches else None
        if identity_matches and observed[7] != value['identity'][7]:
            self.ctime_observations.append({'path': value['path'], 'expectedIdentity': value['identity'],
                                           'observedIdentity': observed})
            require(len(self.ctime_observations) <= 8192, 'Ctime observation bound')
        if identity_matches is not True:
            # Only already observed operands are retained. Preserve short-circuit
            # comparisons and omit malformed/unbounded descriptor values entirely.
            def bounded_integer(item):
                return type(item) is int and -(1 << 127) <= item < (1 << 127)

            expected_identity = value['identity']
            numeric_identity = (type(expected_identity) is list and len(expected_identity) == 9 and
                                all(bounded_integer(item) for item in expected_identity))
            require(False, 'Admitted descriptor changed', pin_observation={
                'readOrdinal': self.reads,
                'expectedBytes': value['bytes'] if bounded_integer(value['bytes']) else None,
                'returnedBytes': len(raw), 'lengthMatches': length_matches,
                'digestMatches': digest_matches, 'identityMatches': identity_matches,
                'expectedIdentity': expected_identity if numeric_identity else None,
                'observedIdentity': observed})
        return raw


def qualified_created_descriptor(created, source, *, paired_build=False):
    """Validate retained immediate-copy lineage without observing any file."""
    require(type(paired_build) is bool and source['materialize'] is (not paired_build) and
            source['role'] in ('source', 'cache') and
            set(created) == {'role', 'windowsPath', 'descriptor', 'writeClosedIdentity', 'readbackObservation'} and
            created['role'] == source['role'] and created['windowsPath'] == source['windowsPath'],
            'Created deployment lineage role')
    pin, observation = created['descriptor'], created['readbackObservation']
    require(set(pin) == {'path', 'bytes', 'sha256', 'identity'} and
            pin['bytes'] == source['descriptor']['bytes'] and pin['sha256'] == source['descriptor']['sha256'] and
            set(observation) == {'readOrdinal', 'createdCopyReadback', 'expectedBytes', 'returnedBytes',
                                 'initialDescriptor', 'finalDescriptor', 'namedPath', 'secondReadOrdinal',
                                 'secondDescriptor', 'secondNamedPath', 'contentVerifiedTwice'} and
            observation['contentVerifiedTwice'] is True and
            type(observation['secondReadOrdinal']) is int and
            observation['secondReadOrdinal'] == observation['readOrdinal'] + 1 and
            observation['createdCopyReadback'] is True and
            type(observation['readOrdinal']) is int and 1 <= observation['readOrdinal'] <= 8192 and
            observation['expectedBytes'] == observation['returnedBytes'] == pin['bytes'],
            'Created deployment lineage content')
    identities = [created['writeClosedIdentity'], observation['initialDescriptor'],
                  observation['finalDescriptor'], observation['namedPath'], observation['secondDescriptor'],
                  observation['secondNamedPath'], pin['identity']]
    require(all(type(value) is list and len(value) == 9 and all(type(x) is int for x in value)
                for value in identities), 'Created deployment lineage identities')
    baseline = identities[0]
    require(stat.S_ISREG(baseline[2]) and baseline[5] == pin['bytes'] and baseline[8] == 1 and
            all(all(value[i] == baseline[i] for i in (0, 1, 2, 3, 4, 5, 6, 8)) for value in identities[1:]) and
            pin['identity'] == observation['namedPath'], 'Created deployment lineage continuity')
    return pin


def paired_restore_copy(a, item):
    """Join only the accepted paired restore's original creation evidence."""
    qualified = a['suite'] != 'restore' and item['role'] in ('source', 'cache')
    fields = {'role', 'windowsPath', 'descriptor', 'materialize'}
    require(set(item) == fields | ({'restoreCreation'} if qualified else set()), 'Inventory fields')
    if not qualified:
        return None
    lineage = item['restoreCreation']
    require(type(lineage) is dict and set(lineage) == {'action', 'slot', 'deployment'} and
            item['materialize'] is False and lineage['action'] == a['subjectAction'] and
            lineage['slot'] == a['slot'] and int(a['subjectAction']) < int(a['action']),
            'Paired restore creation binding')
    created = lineage['deployment']
    require(type(created) is dict and created.get('descriptor') == item['descriptor'] and
            Path(item['descriptor']['path']) == project(item['windowsPath']) and
            project(item['windowsPath']).is_relative_to(
                subject_root(a) / ('subject' if item['role'] == 'source' else 'packages')),
            'Paired restore original descriptor and destination')
    qualified_created_descriptor(created, item, paired_build=True)
    return created


def pin_input(a, item, budget):
    created = paired_restore_copy(a, item)
    if created is not None:
        return budget.pin_created_copy(created, item, 134217728, paired_build=True)
    return budget.pin(item['descriptor'], 134217728)


def write_new(path, raw, budget, maximum=65536):
    budget.check()
    require(len(raw) <= maximum, 'Output bound')
    limit = 8192 if budget.terminal_mode else 8188
    capacity = 3 * 1024 * 1024 * 1024 - (0 if budget.terminal_mode else 262144)
    require(budget.writes + 1 <= limit and budget.written + len(raw) <= capacity,
            'Aggregate write budget with terminal reserve')
    budget.writes += 1
    budget.written += len(raw)
    direct(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    budget.check()


def names(path, maximum, budget):
    budget.check()
    direct(path)
    result = []
    with os.scandir(path) as entries:
        for item in entries:
            budget.check()
            result.append(item.name)
            require(len(result) <= maximum, 'Directory membership bound')
    return sorted(result)


def project(path):
    require(type(path) is str and '\x00' not in path and '\t' not in path and '\n' not in path and
            re.fullmatch(r'C:\\(?:Temp\\azureauth-windows-slice-108\\|Program Files\\dotnet\\|Program Files\\Microsoft Visual Studio\\18\\Enterprise\\VC\\Tools\\MSVC\\14\.51\.36231\\|Program Files \(x86\)\\Windows Kits\\10\\(?:Include|Lib|bin)\\10\.0\.26100\.0\\)[A-Za-z0-9 _.,=\\-]+', path) and
            all(0 < len(x) <= 128 and x not in ('.', '..') and not x.endswith(('.', ' ')) and
                x.split('.')[0].upper() not in ('CON', 'PRN', 'AUX', 'NUL',
                    *('COM' + str(i) for i in range(1, 10)), *('LPT' + str(i) for i in range(1, 10)))
                for x in path[3:].split('\\')), 'Windows projection boundary')
    return Path('/mnt/c') / path[3:].replace('\\', '/')


def load_admission(path, expected, budget):
    require(re.fullmatch(r'/home/shuaizhang/\.local/state/azureauth-108-recovery-20260929/windows-managed-harness-[0-9]{4}-admission\.json', str(path)), 'Admission leaf')
    raw, full9 = budget.read(path, 65536)
    require(digest(raw) == expected, 'Original admission hash')
    value = decode(raw)
    require(set(value) == {'schema', 'action', 'suite', 'nonce', 'product', 'checkpoint', 'checkpointAcceptance',
                          'inputAcceptance', 'sourceCommit', 'subjectAction', 'slot', 'sourceReview', 'exactCallReview', 'inventory',
                          'controller', 'windowsAuthority', 'caller', 'launcher', 'python', 'systemdRun',
                          'interop', 'runtimeDirectory', 'accounting'},
            'Admission fields')
    require(value['schema'] == 'windows-diagnostic-build-admission-v1' and value['product'] == PRODUCT and
            re.fullmatch(r'[0-9]{4}', value['action']) and int(value['action']) > 110 and
            value['suite'] in CHARGES and
            value['sourceCommit'] == PRODUCT and re.fullmatch(r'[0-9a-f]{40}', value['sourceCommit']) and
            re.fullmatch(r'[0-9]{4}', value['subjectAction']) and int(value['subjectAction']) > 110 and
            value['slot'] in ('primary', 'c1-a', 'c1-b', 'c2-a', 'c2-b', 'c3-a', 'c3-b', 'supplemental') and
            ((value['suite'] == 'restore' and value['subjectAction'] == value['action']) or
             (value['suite'] != 'restore' and int(value['subjectAction']) < int(value['action']))) and
            re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', value['nonce']), 'Admission identity')
    value['_raw'], value['_identity'], value['_path'] = raw, full9, str(path)
    return value


def acceptance(pin, schema, subjects, budget):
    value = decode(budget.pin(pin, 65536))
    require(value == {'schema': schema, 'accepted': True, 'subjects': subjects}, 'Independent acceptance binding')


def require_executable_launcher(a, budget):
    """Check executable use of the independently admitted fixed Windows copy."""
    budget.check()
    pin = a['launcher']
    require(pin['path'] == str(LAUNCHER_PROJECTION), 'Fixed Windows launcher projection')
    path = direct(LAUNCHER_PROJECTION)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_mode & 0o111 and all(identity(before)[i] == pin['identity'][i]
                    for i in (0, 1, 2, 3, 4, 5, 6, 8)),
                'Admitted executable launcher identity and mode')
        require(os.access(path, os.X_OK, effective_ids=True, follow_symlinks=False),
                'Effective-user launcher execute access')
        require(all(identity(os.fstat(fd))[i] == pin['identity'][i] == identity(path.lstat())[i]
                    for i in (0, 1, 2, 3, 4, 5, 6, 8)),
                'Executable launcher non-ctime identity unchanged')
        budget.check()
    finally:
        os.close(fd)


def verify_admission(a, budget):
    acceptance(a['checkpointAcceptance'], 'windows-diagnostic-build-checkpoint-acceptance-v1',
               {'checkpoint': a['checkpoint'], 'accounting': a['accounting']}, budget)
    acceptance(a['inputAcceptance'], 'windows-managed-harness-input-acceptance-v1',
               {'sourceCommit': a['sourceCommit'], 'inventory': a['inventory'], 'slot': a['slot'],
                'subjectAction': a['subjectAction'], 'operation': a['suite'],
                'completePublicCacheOnly': True, 'emptyFeedOnly': True,
                'restoreIndependentlyAccepted': a['suite'] != 'restore',
                'noOriginalRuntimeOrRestoreReads': True}, budget)
    acceptance(a['sourceReview'], 'windows-managed-harness-source-acceptance-v1',
               {'caller': a['caller'], 'launcher': a['launcher'], 'controller': a['controller'],
                'inventory': a['inventory'], 'unchangedNormalLauncher': True,
                'exemptOuterPowerShellCount': 1, 'syntheticCharge': CHARGES[a['suite']],
                'ordinaryToolDescendantsChargedToSelectedPhase': True, 'operation': a['suite']}, budget)
    acceptance(a['exactCallReview'], 'windows-managed-harness-exact-call-acceptance-v1',
               {key: value for key, value in a.items() if key != 'exactCallReview' and not key.startswith('_')}, budget)
    for key, maximum in (('caller', 131072), ('controller', 65536), ('launcher', 8388608), ('python', 33554432),
                         ('systemdRun', 8388608)):
        budget.pin(a[key], maximum)
    require(Path(a['caller']['path']) == Path(__file__).absolute() and
            re.fullmatch(r'/usr/bin/python3\.[0-9]+', a['python']['path']) and
             a['systemdRun']['path'] == '/usr/bin/systemd-run', 'Original entry tools')
    require((a['launcher']['bytes'], a['launcher']['sha256']) == NORMAL_LAUNCHER,
            'Retained normal launcher artifact only')
    require_executable_launcher(a, budget)
    interop = a['interop']
    require(set(interop) == {'path', 'identity'} and re.fullmatch(r'/run/WSL/[0-9]{1,10}_interop', interop['path']),
            'Original WSL interop selector')
    sock = direct(Path(interop['path'])).lstat()
    require(stat.S_ISSOCK(sock.st_mode) and identity(sock) == interop['identity'], 'Original interop identity')
    runtime = a['runtimeDirectory']
    require(set(runtime) == {'path', 'identity'} and runtime['path'] == '/run/user/' + str(os.getuid()) and
            identity(direct(Path(runtime['path'])).lstat()) == runtime['identity'], 'User manager directory')
    inventory = decode(budget.pin(a['inventory'], 4194304))
    require(set(inventory) == {'schema', 'files'} and inventory['schema'] == 'windows-managed-harness-files-v1' and
            20 <= len(inventory['files']) <= 4096, 'Complete deployment inventory')
    roles, paths, tsv = {}, set(), []
    total = 0
    for item in inventory['files']:
        paired_restore_copy(a, item)
        role, path, pin = item['role'], item['windowsPath'], item['descriptor']
        require(role in ('dotnet', 'tool', 'source', 'cache', 'metadata') and path.casefold() not in paths and
                type(item['materialize']) is bool and set(pin) == {'path', 'bytes', 'sha256', 'identity'},
                'Inventory path/role')
        destination = project(path)
        if item['materialize']:
            relative = destination.relative_to(subject_root(a))
            require(a['suite'] == 'restore' and 2 <= len(relative.parts) <= 16 and
                    ((role == 'source' and relative.parts[0] == 'subject') or
                     (role == 'cache' and relative.parts[0] == 'packages')),
                    'Dedicated deployment subdirectory')
        else:
            require(destination == Path(pin['path']) and
                    ((role in ('dotnet', 'tool') and not destination.is_relative_to(PROJECTION)) or
                     (a['suite'] != 'restore' and role in ('source', 'cache', 'metadata') and
                      destination.is_relative_to(subject_root(a)))), 'Installed runtime input only')
        paths.add(path.casefold())
        if role == 'dotnet':
            require(role not in roles, 'Duplicate entry role')
            roles[role] = path
        require(type(pin['bytes']) is int and 0 <= pin['bytes'] <= 134217728 and
                re.fullmatch(r'[0-9a-f]{64}', pin['sha256']) and
                type(pin['identity']) is list and len(pin['identity']) == 9 and
                all(type(x) is int for x in pin['identity']), 'Bounded source descriptor')
        require(pin['bytes'] > 0 or (role == 'cache' and
                pin['sha256'] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
                'Only exact admitted empty cache leaves may have zero size')
        total += pin['bytes']
        require(total <= 2147483648, 'Inventory aggregate size')
        # The original materializer reads each source exactly once below. The
        # worker later validates the resulting deployment, not another source copy.
        tsv.append('\t'.join((role, path, str(pin['bytes']), pin['sha256'])))
    require(set(roles) == {'dotnet'} and roles['dotnet'] == r'C:\Program Files\dotnet\dotnet.exe',
            'One admitted installed SDK host')
    source_paths = [x['windowsPath'] for x in inventory['files'] if x['role'] == 'source']
    cache_paths = [x['windowsPath'] for x in inventory['files'] if x['role'] == 'cache']
    require(len(source_paths) >= 10 and len(cache_paths) >= 1 and
            all(project(x).is_relative_to(subject_root(a) / 'subject') for x in source_paths) and
            all(project(x).is_relative_to(subject_root(a) / 'packages') for x in cache_paths),
            'Fresh source and complete public cache roles')
    for x in inventory['files']:
        if x['role'] == 'metadata':
            require(a['suite'] != 'restore' and project(x['windowsPath']).is_relative_to(subject_root(a) / 'subject'),
                    'Separately admitted new restore metadata')
    bindings = ('\n'.join(tsv) + '\n').encode('utf-8')
    authority_raw = budget.pin(a['windowsAuthority'], 65536)
    authority = decode(authority_raw)
    expected = {
        'schema': 'retained-windows-managed-build-authority-v1', 'accepted': True,
        'action': a['action'], 'operation': a['suite'], 'sourceCommit': a['sourceCommit'],
        'subjectAction': a['subjectAction'], 'preparationCharge': int(a['suite'] == 'restore'),
        'buildTestCharge': int(a['suite'] in ('build', 'test')),
        'publicationCharge': int(a['suite'] == 'publish'), 'syntheticCharge': 1,
        'exemptOuterPowerShellCount': 1, 'runnerSeconds': 190, 'wrapperSeconds': 300,
        'maximumCaptureBytes': 8388608, 'noExperimentLive': False,
        'checkpointSha256': a['checkpoint']['sha256'],
        'checkpointAcceptanceSha256': a['checkpointAcceptance']['sha256'],
        'inputAcceptanceSha256': a['inputAcceptance']['sha256'],
        'sourceReviewSha256': a['sourceReview']['sha256'], 'inventorySha256': digest(bindings),
        'controllerSha256': a['controller']['sha256'],
    }
    require(authority == expected, 'Exact finite Windows authority')
    return roles, bindings, authority_raw


def windows_root_name(a):
    return WINDOWS + '\\named-fixtures-' + a['action']


def windows_root(a):
    return PROJECTION / ('named-fixtures-' + a['action'])


def subject_root(a):
    return PROJECTION / ('named-fixtures-' + a['subjectAction'])


def subject_root_name(a):
    return WINDOWS + '\\named-fixtures-' + a['subjectAction']


def materialize_inputs(a, root, local, budget):
    inventory = decode(budget.pin(a['inventory'], 4194304))
    deployed = []
    for item in inventory['files']:
        raw = pin_input(a, item, budget)
        destination = project(item['windowsPath'])
        write_closed_identity = None
        if item['materialize']:
            relative = destination.relative_to(root)
            parent = root
            for segment in relative.parts[:-1]:
                parent = parent / segment
                try:
                    require(budget.created_directories < 4096, 'Created deployment directory bound')
                    parent.mkdir(mode=0o700)
                    budget.created_directories += 1
                except FileExistsError:
                    require(stat.S_ISDIR(direct(parent).lstat().st_mode), 'Owned deployment directory')
            write_new(destination, raw, budget, 134217728)
            info = destination.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_size == len(raw), 'Created deployment file')
            write_closed_identity = identity(info)
            reader_identity, read_observation = budget.read_created_copy(
                destination, 134217728, write_closed_identity, raw)
            descriptor = {'path': str(destination), 'bytes': len(raw), 'sha256': digest(raw),
                          'identity': reader_identity}
        else:
            descriptor = item['descriptor']
        created = {'role': item['role'], 'windowsPath': item['windowsPath'], 'descriptor': descriptor}
        if write_closed_identity is not None:
            created['writeClosedIdentity'] = write_closed_identity
            created['readbackObservation'] = read_observation
        deployed.append(created)
    evidence = encode({'schema': 'windows-managed-harness-deployment-v1',
                       'inventorySha256': a['inventory']['sha256'], 'files': deployed})
    write_new(local / 'deployment.json', evidence, budget, 4194304)
    write_new(root / 'deployment.json', evidence, budget, 4194304)


def verify_deployment(a, root, local, budget):
    raw = budget.read(local / 'deployment.json', 4194304)[0]
    require(budget.read(root / 'deployment.json', 4194304)[0] == raw, 'Original deployment receipt copies')
    deployment = decode(raw)
    inventory = decode(budget.pin(a['inventory'], 4194304))
    require(deployment['schema'] == 'windows-managed-harness-deployment-v1' and
            deployment['inventorySha256'] == a['inventory']['sha256'] and
            len(deployment['files']) == len(inventory['files']), 'Complete deployment receipt')
    for created, source in zip(deployment['files'], inventory['files'], strict=True):
        pin = created['descriptor']
        require(created['role'] == source['role'] and created['windowsPath'] == source['windowsPath'] and
                Path(pin['path']) == project(source['windowsPath']) and
                pin['bytes'] == source['descriptor']['bytes'] and
                pin['sha256'] == source['descriptor']['sha256'], 'Bound source/deployment correspondence')
        if source['materialize']:
            require(a['suite'] == 'restore' and a['subjectAction'] == a['action'] and
                    Path(pin['path']).is_relative_to(root / ('subject' if source['role'] == 'source' else 'packages')),
                    'Only this restore created the qualified deployment')
            budget.pin_created_copy(created, source, 134217728)
        else:
            require(pin == source['descriptor'], 'Uncopied deployment retains admitted descriptor')
            pin_input(a, source, budget)


def checkpoint(a, budget, reserved=False):
    # The reviewed writer precharges the canonical COMPLETE ledger. This caller
    # verifies every typed field and never maintains a second accounting system.
    accounting = a['accounting']
    require(type(accounting) is dict and set(accounting) == {'prior', 'recordKey', 'protectedAfter'},
            'Whole-ledger accounting binding')
    key = 'mechanismDiagnosticBuild' + a['action']
    require(accounting['recordKey'] == key, 'Fixed batch intent key')
    prior = decode(budget.pin(accounting['prior'], 4194304))
    current = decode(budget.pin(a['checkpoint'], 4194304))
    before = prior['consumed']
    require(type(before) is list and len(before) == 4 and
            all(type(value) is int and value >= 0 for value in before), 'Complete prior counters')
    charge = [int(a['suite'] == 'restore'), int(a['suite'] in ('build', 'test')),
              int(a['suite'] == 'publish'), 1]
    after = [value + debit for value, debit in zip(before, charge, strict=True)]
    stamp = current['recordedUtc']
    require(type(stamp) is str and len(stamp) <= 64 and
            re.fullmatch(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.+Z-]{8,40}', stamp), 'Recorded UTC bound')
    row = {'schema': 'mechanism-diagnostic-build-start-intent-v1', 'action': a['action'],
           'operation': a['suite'], 'sourceCommit': PRODUCT, 'subjectAction': a['subjectAction'],
           'before': before, 'charge': charge, 'after': after, 'submissionSpent': True, 'recordedUtc': stamp}
    protected = accounting['protectedAfter']
    require(type(protected) is list and len(protected) == 4 and
            all(type(value) is int and value >= 0 for value in protected) and protected[1] >= 12 and
            all(value + remaining <= ceiling for value, remaining, ceiling in
                zip(after, protected, CEILINGS, strict=True)), 'Shared capacity/protected remainder')
    expected = decode(encode(prior))
    require(key not in expected and prior['ceilings'] == CEILINGS and
            prior['noExperimentLive'] is False and prior['realStage']['executionAdmitted'] is False,
            'Preserved global gates and unused intent')
    expected.update(consumed=after, combinedRemaining=[ceiling - value for ceiling, value in
                    zip(CEILINGS, after, strict=True)], recordedUtc=stamp,
                    purpose='Precharge one fixed Windows diagnostic ' + a['suite'] +
                            ' call; preserve history and all real-stage gates',
                    priorRecoveryAccounting={name: accounting['prior'][name] for name in ('path', 'bytes', 'sha256')})
    expected['newExperimentChargesDuringRecovery'] = [value + debit for value, debit in
        zip(prior['newExperimentChargesDuringRecovery'], charge, strict=True)]
    expected[key] = row
    require(typed(expected) == typed(current), 'Complete finite Decimal/int ledger transition')
    return before, charge, after


def transport(argv, environment, cwd, deadline, budget):
    """One original process, finite pipe capture; no retry or fallback launcher."""
    budget.check()
    parts, eof = {'stdout': bytearray(), 'stderr': bytearray()}, set()
    process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    with selectors.DefaultSelector() as selection:
        for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selection.register(stream, selectors.EVENT_READ, name)
        error = None
        caught_failure = None
        cancel_error = None
        try:
            while process.poll() is None or len(eof) != 2:
                budget.check()
                require(time.monotonic_ns() < deadline, 'Original transport deadline')
                for key, _ in selection.select(0.05):
                    remaining = 16384 - sum(map(len, parts.values()))
                    block = os.read(key.fileobj.fileno(), min(4096, remaining + 1))
                    if not block:
                        eof.add(key.data)
                        selection.unregister(key.fileobj)
                    else:
                        parts[key.data].extend(block[:remaining])
                        require(len(block) <= remaining, 'Complete transport output bound')
        except BaseException as caught:
            error = type(caught).__name__
            caught_failure = failure_identity(caught)
            # Return the original cause before cancellation. The owner persists
            # its first-failure receipt, then attempts cancellation independently.
        finally:
            # Closing a Linux proxy pipe establishes no Windows termination.
            for stream in (process.stdout, process.stderr):
                stream.close()
        return {'pid': process.pid, 'exitCode': process.poll(), 'eof': sorted(eof), 'failure': error,
                'cancelFailure': cancel_error, 'caughtFailure': caught_failure,
                'stdout': base64.b64encode(parts['stdout']).decode('ascii'),
                'stderr': base64.b64encode(parts['stderr']).decode('ascii')}


def exact_transport(result):
    require(result['exitCode'] == 0 and result['eof'] == ['stderr', 'stdout'] and result['failure'] is None and
            result['cancelFailure'] is None and result['stdout'] == result['stderr'] == '',
            'Original transport is incomplete or nonzero')


def validate_journal(raw, a, stdout, stderr):
    require(raw.endswith(b'\n'), 'Complete final controller journal')
    records = [decode(line) for line in raw.splitlines()]
    require([x['event'] for x in records] == ['bootstrap', 'job-ready', 'root-suspended', 'resume-requested',
            'resumed', 'completed', 'capture', 'capture', 'launcher-exit'], 'Original controller event sequence')
    times = [x['elapsedMilliseconds'] for x in records]
    require(all(type(x) is int and 0 <= x < 340000 for x in times) and times == sorted(times), 'Retained launcher clock')
    owner, ready, root, completed = records[0], records[1], records[2], records[5]
    for item in (owner, root):
        require(type(item['pid']) is int and item['pid'] > 0 and type(item['session']) is int and item['session'] >= 0 and
                re.fullmatch(r'[1-9][0-9]{1,19}', item['creationFileTime']), 'Original process identity')
    require(owner['authoritySha256'] == a['windowsAuthority']['sha256'] and
            owner['jobName'] == 'Local\\azureauth-controller-108-' + a['action'] + '-' + a['nonce'] and
            owner['pid'] != root['pid'] and owner['session'] == root['session'] and root['inJob'] is True and
            ready['queryAndTerminateAccess'] is True, 'Creation-time named Job binding')
    require(completed['rootExited'] is True and completed['rootExitCode'] == 0 and completed['activeProcesses'] == 0 and
            type(completed['totalProcesses']) is int and 2 <= completed['totalProcesses'] <= 32 and
            completed['stdoutEof'] is True and completed['stderrEof'] is True and
            completed['capturedBytes'] == len(stdout) + len(stderr), 'Original whole scenario Job completion')
    for item, name, raw_capture in zip(records[6:8], ('stdout', 'stderr'), (stdout, stderr), strict=True):
        require(item['stream'] == name and item['initialized'] is True and item['eof'] is True and
                item['overflowDetected'] is False and item['readBytes'] == item['confirmedFlushedBytes'] == len(raw_capture) and
                all(item[k] is None for k in ('failureStage', 'failureType', 'failureHresult', 'failureNativeError',
                                              'closeFailureType')), 'Original controller capture')
    require(records[-1]['passed'] is True and records[-1]['capturedBytes'] == len(stdout) + len(stderr),
            'Original controller terminal')
    return {'rootPid': root['pid'], 'rootCreationFileTime': root['creationFileTime'], 'jobName': owner['jobName']}


def managed_evidence(root, a, roles, budget, controller):
    result = decode(budget.read(root / 'managed-result.json', 32768)[0])
    operation = a['suite']
    require(set(result) == {'schema', 'authoritySha256', 'sourceCommit', 'operation', 'phases', 'passed',
            'cancellationRequested', 'cancellationMarkerConfirmed', 'failureType', 'failureLine',
            'finalizationFailureType', 'phase', 'elapsedMilliseconds', 'scopedJobQuiescenceEstablished',
            'noExperimentLive'}, 'Single phase lifecycle evidence schema')
    require(result['schema'] == 'retained-windows-managed-build-result-v1' and
            result['authoritySha256'] == a['windowsAuthority']['sha256'] and
            result['operation'] == operation and result['sourceCommit'] == a['sourceCommit'] and
            result['passed'] is True and result['cancellationRequested'] is False and
            result['cancellationMarkerConfirmed'] is False and result['failureLine'] is None and
            result['scopedJobQuiescenceEstablished'] is False and
            result['failureType'] is None and result['finalizationFailureType'] is None and
            result['phase'] == 'captured' and 0 <= result['elapsedMilliseconds'] < 300000 and
            result['noExperimentLive'] is False and len(result['phases']) == 1,
            'Original managed phase completion')
    phase = result['phases'][0]
    require(phase['phase'] == operation and phase['exited'] is True and phase['exitCode'] == 0 and
            phase['stdoutEof'] is True and phase['stderrEof'] is True and
            phase['captureDisposition'] == 'complete', 'Original phase exit and EOF')
    require(decode(budget.read(root / (operation + '-result.json'), 8192)[0]) == phase,
            'Original phase receipt correspondence')
    started = decode(budget.read(root / (operation + '-started.json'), 8192)[0])
    require(started['schema'] == 'retained-windows-build-started-v1' and
            started['authoritySha256'] == a['windowsAuthority']['sha256'] and
            type(started['pid']) is int and started['pid'] > 0 and started['pid'] != controller['rootPid'] and
            re.fullmatch(r'[1-9][0-9]{1,19}', started['creationFileTime']) and
            started['phase'] == operation and started['handleRetained'] is True and
            started['creationMode'] == 'ordinary-child-without-breakaway' and
            started['executable'] == roles['dotnet'], 'Original managed identity')
    invocation = decode(budget.read(root / (operation + '-invocation.json'), 32768)[0])
    require(invocation['schema'] == 'retained-windows-build-invocation-v1' and
            invocation['authoritySha256'] == a['windowsAuthority']['sha256'] and
            invocation['executable'] == roles['dotnet'] and
            invocation['workingDirectory'] == subject_root_name(a) + '\\subject' and
            invocation['runnerSeconds'] == 190 and invocation['expectedExitCode'] == 0 and
            invocation['phase'] == operation, 'Original managed invocation binding')
    # Exact command/environment equality is independently checked against the
    # pinned controller during outcome acceptance; this helper admits no artifact.
    captures = {name: budget.read(root / (operation + '.' + name + '.bin'), 8388608)[0]
                for name in ('stdout', 'stderr')}
    require(sum(map(len, captures.values())) <= 8388608 and
            all(len(captures[name]) == phase[name + 'Bytes'] for name in captures), 'Complete phase capture')
    inventory_raw = budget.read(root / 'output-inventory.json', 4194304)[0]
    inventory = decode(inventory_raw)
    require(type(inventory) is dict and set(inventory) == {'schema', 'directories', 'files',
            'newlyRetainedBytes', 'entries', 'atomicSnapshot', 'diskQuota'} and
            inventory['schema'] == 'retained-windows-new-output-inventory-v1' and
            inventory['atomicSnapshot'] is False and inventory['diskQuota'] is False,
            'Finite observed output inventory')
    require(all(type(inventory[key]) is int for key in ('directories', 'files', 'newlyRetainedBytes')) and
            0 <= inventory['directories'] <= 4096 and 0 <= inventory['files'] <= 8192 and
            0 <= inventory['newlyRetainedBytes'] <= 2147418112 and
            inventory['newlyRetainedBytes'] + len(inventory_raw) + 32768 <= 2147483648 and
            type(inventory['entries']) is list and len(inventory['entries']) <= inventory['files'],
            'Finite output inventory counts and bytes')
    seen, total = set(), 0
    for entry in inventory['entries']:
        require(type(entry) is dict and set(entry) == {'path', 'bytes'} and
                type(entry['path']) is str and type(entry['bytes']) is int and entry['bytes'] >= 0,
                'Output entry schema')
        path = project(entry['path'])
        require(entry['path'].casefold() not in seen and
                (path.is_relative_to(root) or path.is_relative_to(subject_root(a) / 'subject')),
                'Unique owned output entry')
        seen.add(entry['path'].casefold())
        total += entry['bytes']
        require(total <= 2147418112, 'Observed output aggregate')
    require(total == inventory['newlyRetainedBytes'], 'Observed output total correspondence')
    if operation == 'test':
        reports = [name for name in names(root / 'results', 32, budget) if name.endswith('.trx')]
        require(len(reports) == 1, 'One diagnostic TRX report')
        diagnostic_test_report(budget.read(root / 'results' / reports[0], 1048576)[0])
    return {'pid': started['pid'], 'creationFileTime': started['creationFileTime'],
            'operation': operation, 'requiresIndependentOutputAcceptance': True}


def diagnostic_test_report(raw):
    # Reuse the existing TRX identity/counter/result join, with a fixed selection.
    require(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw, 'TRX declarations not admitted')
    report = ET.fromstring(raw)
    prefix = 'Authentication.Windows.Scenarios.'
    cases = {prefix + name: 'Passed' for name in (
        'WindowsHostAdmissionScenarios.FixedDiagnosticsIdentifyRejectedGateWithoutProviderEffects',
        'WindowsHostAdmissionScenarios.CancelledObservationDoesNotPublishRejectedGate',
        'MsalAdapterScenarios.MechanismTraceKeepsFirstFixedCauseAndNeverProviderText')}
    required = {'total': '3', 'executed': '3', 'passed': '3', 'failed': '0'}
    required.update({name: '0' for name in ('error', 'timeout', 'aborted', 'inconclusive', 'passedButRunAborted',
        'notRunnable', 'notExecuted', 'disconnected', 'warning', 'completed', 'inProgress', 'pending')})
    counters = report.findall('.//{*}Counters')
    require(len(counters) == 1 and counters[0].attrib == required, 'Exact diagnostic test counters')
    identities = {}
    for item in report.findall('.//{*}UnitTest'):
        methods = item.findall('{*}TestMethod')
        require(item.attrib['id'] not in identities and len(methods) == 1 and
                item.attrib['name'] == methods[0].attrib['name'], 'Diagnostic test definition identity')
        identities[item.attrib['id']] = (methods[0].attrib['className'] + '.' + methods[0].attrib['name'],
                                        methods[0].attrib['name'])
    observed, identifiers = {}, set()
    for item in report.findall('.//{*}UnitTestResult'):
        key = item.attrib['testId']
        require(key in identities and key not in identifiers, 'Diagnostic test result identity')
        identifiers.add(key)
        qualified, name = identities[key]
        require(qualified not in observed and item.attrib['testName'] == name, 'Diagnostic expanded test identity')
        observed[qualified] = item.attrib['outcome']
    require(len(identities) == 3 and identifiers == set(identities) and observed == cases,
            'Exactly three diagnostic tests passed')
    return {'rows': 3, 'passed': 3}


def unit_name(a):
    return 'azureauth-retained-scenarios-108-' + a['action'] + '-' + a['nonce'] + '.service'


def replacement_environment(a):
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'WSL_INTEROP': a['interop']['path'], 'XDG_RUNTIME_DIR': a['runtimeDirectory']['path'],
            'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + a['runtimeDirectory']['path'] + '/bus',
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}


def request_cancel(root, budget):
    try:
        write_new(root / 'cancel', b'', budget)
    except FileExistsError:
        pass


def retain_failure(local, root, budget, result, prefix, result_leaf):
    """At most three writes, using reserved time/bytes and the original counters."""
    budget.enter_terminal()
    result['passed'] = False
    result['scopedJobQuiescent'] = False
    first = {key: result[key] for key in ('schema', 'stage', 'failureType', 'caughtFailure')}
    first.update(noExperimentLive=False, continuationAllowed=False, capacityRefundAllowed=False)
    # Persistence may itself fail. Preserve the in-memory first cause and expose
    # each independent failure rather than promising storage cannot fail.
    try:
        write_new(local / (prefix + '-first-failure.json'), encode(first), budget)
    except BaseException as retention_error:
        result['firstFailureRetentionFailure'] = type(retention_error).__name__
    try:
        request_cancel(root, budget)
    except BaseException as cancellation_error:
        result['cancelFailure'] = type(cancellation_error).__name__
    try:
        write_new(local / result_leaf, encode(result), budget)
    except BaseException as result_error:
        result['resultRetentionFailure'] = type(result_error).__name__
        sys.stderr.write('Retained scenario first failure: ' + result['failureType'] +
                         '; first retention: ' + result.get('firstFailureRetentionFailure', 'none') +
                         '; cancel: ' + result.get('cancelFailure', 'none') +
                         '; result retention: ' + result['resultRetentionFailure'] + '\n')
    return 1


def worker(a, began, deadline, service_intent, service_deadline, budget):
    root, local = windows_root(a), LINUX / 'windows-actions' / a['action']
    result = {'schema': 'windows-managed-harness-worker-result-v1', 'passed': False,
              'noExperimentLive': False, 'historicalLifetimeUnknown': HISTORICAL_UNKNOWN,
              'stage': 'worker-admission'}
    try:
        # The conservative service clock began BEFORE systemd-run was created;
        # service startup, Python startup and admission have consumed it already.
        budget.check()
        with open('/proc/self/cgroup', 'rb', buffering=0) as stream:
            group = stream.read(4097).decode('ascii')
        require(len(group) <= 4096 and group.count('\n') == 1 and group.startswith('0::/') and
                group.rstrip('\n').endswith('/' + unit_name(a)), 'Dedicated creation-time Linux cgroup')
        timing = decode(budget.read(local / 'service-intent.json', 8192)[0])
        require(timing == {'schema': 'windows-managed-harness-service-intent-v1',
                'admissionSha256': digest(a['_raw']), 'originalStartNanoseconds': began,
                'originalDeadlineNanoseconds': deadline, 'serviceIntentNanoseconds': service_intent,
                'serviceDeadlineLowerBoundNanoseconds': service_deadline,
                'serviceRuntimeSeconds': SERVICE_SECONDS, 'workerTerminalSeconds': 10},
                'Conservative service clock binding')
        roles, bindings, authority_raw = verify_admission(a, budget)
        started_raw, _ = budget.read(local / 'started.json', 65536)
        started = decode(started_raw)
        require(started['admissionSha256'] == digest(a['_raw']) and started['originalStartNanoseconds'] == began and
                started['originalDeadlineNanoseconds'] == deadline and
                budget.read(root / 'started.json', 65536)[0] == started_raw and
                budget.read(root / 'authority.json', 65536)[0] == authority_raw and
                budget.read(root / 'inventory.tsv', 1048576)[0] == bindings and
                digest(budget.read(root / 'Invoke-WindowsNamedGuardFixtures.ps1', 65536)[0]) == a['controller']['sha256'],
                'Durable original binding')
        verify_deployment(a, root, local, budget)
        checkpoint(a, budget, reserved=True)
        command = [a['launcher']['path'], windows_root_name(a), a['nonce'],
                   a['windowsAuthority']['sha256'], a['controller']['sha256']]
        write_new(local / 'worker-started.json', encode({'schema': 'windows-managed-harness-worker-v1',
                  'cgroup': group.strip(), 'argv': command, 'admissionSha256': digest(a['_raw']),
                  'serviceIntentNanoseconds': service_intent,
                  'serviceDeadlineLowerBoundNanoseconds': service_deadline,
                  'workerWorkDeadlineNanoseconds': budget.deadline,
                  'workerTerminalDeadlineNanoseconds': budget.terminal_deadline}), budget)
        # 360 transport + 30 evidence must fit the earlier work deadline; its
        # already-withheld 10 terminal seconds also fit both enclosing clocks.
        budget.check(390_000_000_000)
        require_executable_launcher(a, budget)
        result['stage'] = 'native-launch'
        capture = transport(command, replacement_environment(a), str(root),
                            min(budget.deadline - 30_000_000_000,
                                time.monotonic_ns() + 360_000_000_000), budget)
        result['transport'] = capture
        if capture['failure'] is not None:
            result['failureType'] = capture['failure']
        write_new(local / 'native-transport.json', encode(capture), budget)
        exact_transport(capture)
        budget.deadline = min(budget.deadline, time.monotonic_ns() + 30_000_000_000)
        result['stage'] = 'original-evidence'
        stdout = budget.read(root / 'launcher.stdout.bin', 16384)[0]
        stderr = budget.read(root / 'launcher.stderr.bin', 16384)[0]
        require(stdout == b'' and stderr == b'', 'Empty successful PowerShell transport')
        result['controller'] = validate_journal(budget.read(root / 'launcher.jsonl', 65536)[0], a, stdout, stderr)
        result['managed'] = managed_evidence(root, a, roles, budget, result['controller'])
        write_new(local / 'input-ctime-observations.json', encode(budget.ctime_observations), budget, 4194304)
        result['artifactAccepted'] = False
        result['restoreAccepted'] = False
        result.update(passed=True, stage='worker-result-retention', scopedJobQuiescent=True)
        budget.enter_terminal()
        write_new(local / 'worker-result.json', encode(result), budget)
        return 0
    except BaseException as error:
        result.setdefault('failureType', type(error).__name__)
        result['caughtFailure'] = failure_identity(error)
        return retain_failure(local, root, budget, result, 'worker', 'worker-result.json')


def original(a, began, deadline, budget):
    root, local = windows_root(a), LINUX / 'windows-actions' / a['action']
    reserved_local = False
    stage = 'original-admission'
    capture = None
    fd = os.open(direct(LINUX / 'action.lock'), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'Shared action lock file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        roles, bindings, authority_raw = verify_admission(a, budget)
        before, charge, after = checkpoint(a, budget)
        # Both exclusive roots and the first durable debit precede any launch.
        # Any partial reservation is retained and never refunded automatically.
        direct(local.parent)
        local.mkdir(mode=0o700)
        reserved_local = True
        started = {'schema': 'windows-managed-harness-started-v1', 'action': a['action'], 'suite': a['suite'],
                   'admissionSha256': digest(a['_raw']), 'before': before, 'charge': charge, 'after': after,
                   'originalStartNanoseconds': began, 'originalDeadlineNanoseconds': deadline,
                   'noExperimentLive': False, 'historicalLifetimeUnknown': HISTORICAL_UNKNOWN}
        reservation = encode(started)
        write_new(local / 'started.json', reservation, budget)
        direct(root.parent)
        root.mkdir(mode=0o700)
        write_new(root / 'started.json', reservation, budget)
        for name in ('temp', 'results', 'home', 'empty-program-files'):
            (root / name).mkdir(mode=0o700)
        for name in ('roaming', 'local', 'http', 'plugins'):
            (root / 'home' / name).mkdir(mode=0o700)
        if a['suite'] == 'restore':
            for name in ('subject', 'packages', 'empty-feed'):
                (root / name).mkdir(mode=0o700)
        else:
            direct(subject_root(a))
        write_new(root / 'authority.json', authority_raw, budget)
        write_new(root / 'inventory.tsv', bindings, budget, 1048576)
        write_new(root / 'Invoke-WindowsNamedGuardFixtures.ps1', budget.pin(a['controller'], 65536), budget)
        stage = 'original-materialization'
        materialize_inputs(a, root, local, budget)
        checkpoint(a, budget, reserved=True)
        # Service + 5 service termination + 5 transport slack + 15 original
        # evidence; original terminal 10 is withheld in budget.deadline already.
        budget.check((SERVICE_SECONDS + 25) * 1_000_000_000)
        service_intent = time.monotonic_ns()
        service_deadline = service_intent + SERVICE_SECONDS * 1_000_000_000
        write_new(local / 'service-intent.json', encode({
            'schema': 'windows-managed-harness-service-intent-v1',
            'admissionSha256': digest(a['_raw']), 'originalStartNanoseconds': began,
            'originalDeadlineNanoseconds': deadline, 'serviceIntentNanoseconds': service_intent,
            'serviceDeadlineLowerBoundNanoseconds': service_deadline,
            'serviceRuntimeSeconds': SERVICE_SECONDS, 'workerTerminalSeconds': 10}), budget)
        command = [a['systemdRun']['path'], '--user', '--no-ask-password', '--quiet', '--wait', '--pipe',
                   '--collect', '--expand-environment=no', '--job-mode=fail',
                   '--unit=' + unit_name(a), '--service-type=exec', '--property=ExitType=cgroup',
                   '--property=KillMode=control-group', '--property=Restart=no',
                   '--property=JobRunningTimeoutSec=2s', '--property=TimeoutStartSec=2s',
                   '--property=RuntimeMaxSec=' + str(SERVICE_SECONDS),
                   '--property=TimeoutStopSec=5', '--property=SendSIGKILL=yes',
                   '--property=TasksMax=32', '--property=MemoryMax=512M', '--working-directory=' + str(local)]
        environment = replacement_environment(a)
        command += ['--setenv=' + key + '=' + value for key, value in sorted(environment.items())]
        command += [a['python']['path'], '-I', '-B', a['caller']['path'], '--worker', a['_path'],
                    digest(a['_raw']), str(began), str(deadline), str(service_intent), str(service_deadline)]
        write_new(local / 'invocation.json', encode({'argv': command, 'environment': environment}), budget)
        stage = 'service-transport'
        budget.check()
        require(time.monotonic_ns() < service_deadline - 400_000_000_000,
                'Service launch retains complete worker reservation')
        capture = transport(command, environment, str(local),
                            min(budget.deadline - 15_000_000_000,
                                service_intent + (SERVICE_SECONDS + 10) * 1_000_000_000), budget)
        write_new(local / 'service-transport.json', encode(capture), budget)
        exact_transport(capture)
        budget.deadline = min(budget.deadline, time.monotonic_ns() + 15_000_000_000)
        stage = 'original-evidence'
        witness = decode(budget.read(local / 'worker-started.json', 65536)[0])
        require(witness['admissionSha256'] == digest(a['_raw']) and
                witness['cgroup'].startswith('0::/') and
                witness['cgroup'].endswith('/' + unit_name(a)), 'Original dedicated group witness')
        group = witness['cgroup'][3:]
        require('..' not in Path(group).parts, 'Dedicated group path')
        events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
        try:
            with events.open('rb') as stream:
                group_state = stream.read(4097)
            require(len(group_state) <= 4096 and
                    dict(line.split() for line in group_state.decode('ascii').splitlines()).get('populated') == '0',
                    'Original dedicated group is populated')
            group_disposition = 'observed-unpopulated'
        except FileNotFoundError:
            group_disposition = 'absent-after-original-zero-exit'
        write_new(local / 'service-cgroup-result.json', encode({'unit': unit_name(a),
                  'cgroup': group, 'disposition': group_disposition}), budget)
        result = decode(budget.read(local / 'worker-result.json', 65536)[0])
        require(result['passed'] is True and result['scopedJobQuiescent'] is True and
                result['noExperimentLive'] is False, 'Original worker completion')
        checkpoint(a, budget, reserved=True)
        write_new(local / 'original-input-ctime-observations.json', encode(budget.ctime_observations), budget, 4194304)
        stage = 'original-result-retention'
        budget.enter_terminal()
        write_new(local / 'original-result.json', encode({'schema': 'windows-managed-harness-original-result-v1',
                  'complete': True, 'action': a['action'], 'suite': a['suite'], 'admissionSha256': digest(a['_raw']),
                  'accounting': {'before': before, 'charge': charge, 'after': after},
                  'scopedJobQuiescent': True, 'noExperimentLive': False,
                  'historicalLifetimeUnknown': HISTORICAL_UNKNOWN, 'requiresIndependentOutcomeAcceptance': True}), budget)
        return 0
    except BaseException as error:
        if reserved_local:
            result = {'schema': 'windows-managed-harness-original-failure-v1',
                      'action': a['action'], 'admissionSha256': digest(a['_raw']),
                      'stage': stage, 'failureType': type(error).__name__, 'complete': False,
                      'caughtFailure': failure_identity(error),
                      'noExperimentLive': False, 'retainedLiveWorkOrUnknown': True,
                      'historicalLifetimeUnknown': HISTORICAL_UNKNOWN,
                      'continuationAllowed': False, 'capacityRefundAllowed': False}
            if capture is not None:
                result['transport'] = capture
                if capture['failure'] is not None:
                    result['failureType'] = capture['failure']
            return retain_failure(local, root, budget, result, 'original', 'original-failure.json')
        raise
    finally:
        # Lease covers reservation, execution, original evidence and terminal write.
        os.close(fd)


def main():
    entered = time.monotonic_ns()
    require(ADMITTED, 'Source-only entry')
    def interrupted(signum, frame):
        raise InterruptedError('Original invocation interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    require(len(sys.argv) in (4, 8) and sys.argv[1] in ('--original', '--worker'), 'Exact caller argv')
    if sys.argv[1] == '--worker':
        require(len(sys.argv) == 8, 'Worker argv')
        began, deadline = int(sys.argv[4]), int(sys.argv[5])
        service_intent, service_deadline = int(sys.argv[6]), int(sys.argv[7])
        require(began <= service_intent <= entered < service_deadline and
                service_deadline - service_intent == SERVICE_SECONDS * 1_000_000_000,
                'Single conservative service clock')
        terminal_deadline = min(service_deadline, deadline - 25_000_000_000)
        budget = Budget(began, terminal_deadline - 10_000_000_000, terminal_deadline)
    else:
        require(len(sys.argv) == 4, 'Original argv')
        began, deadline = entered, entered + 900_000_000_000
        budget = Budget(began, deadline - 10_000_000_000, deadline)
    require(deadline - began == 900_000_000_000, 'Single original clock')
    # Admission uses the SAME bounded counters and service-relative clock as the
    # rest of the worker. No fresh work budget begins after admission or failure.
    budget.check()
    a = load_admission(Path(sys.argv[2]), sys.argv[3], budget)
    if sys.argv[1] == '--worker':
        return worker(a, began, deadline, service_intent, service_deadline, budget)
    return original(a, began, deadline, budget)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        # Complete transport retains this fixed sanitized failure, never arbitrary
        # provider, subprocess or environment text. No exception starts a retry.
        sys.stderr.write(encode({'failure': failure_identity(error)}).decode('ascii'))
        sys.exit(1)
