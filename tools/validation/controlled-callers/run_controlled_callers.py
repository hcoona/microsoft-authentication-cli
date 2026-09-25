"""Inert controlled compile/native caller and dedicated cgroup worker.

Source proposal only. Activation requires accepted source, artifact, checkpoint,
protocol and exact-call reviews. No history reader or legacy runner is imported.
"""

ADMITTED = False
if not ADMITTED:
    raise RuntimeError('Source-only final scenario caller; no execution is admitted')

import base64
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

LINUX = Path('/var/tmp/azureauth-windows-slice-108')
PROJECTION = Path('/mnt/c/Temp/azureauth-windows-slice-108')
WINDOWS = r'C:\Temp\azureauth-windows-slice-108'
CEILINGS = [36, 147, 30, 302]  # Proposed ceilings; guard remains closed until amended authority.
HISTORICAL_UNKNOWN = ['0057', '0064', '0068', '0093', '0107', '0110']
PRODUCT = '503360753accd0829801953823b1b57a4f852440'
NORMAL_LAUNCHER = (23040, '5b018f38669fd6ca3cec8f760533af392e0265280047bfb5c531dd41a349690a')
LAUNCHER_PROJECTION = PROJECTION / 'normal-launcher-dispatch-v1' / 'WindowsScriptJobLauncher.exe'
CHARGES = {'compile': 1, 'native': 12}
STAGE = PROJECTION / 'confidential-checks-v7'
STAGE_WINDOWS = WINDOWS + r'\confidential-checks-v7'
CATALOG = (87398, 'ba96e46f4c70b508605ebef73e9f674b074adfa03704732aea1781dd62da779c')
TARGETS = ('NativeCaller', 'DirectObserver', 'SyntheticSubject', 'FixtureDriver')
SERVICE_SECONDS = 1200
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


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate JSON member')
            value[key] = item
        return value
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'Nonfinite JSON'))


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

    def pin_created_copy(self, created, source, maximum):
        # Only this controlled compilation's exact freshly materialized inputs
        # carry the accepted copy qualification and original retained lineage.
        pin = qualified_created_descriptor(created, source)
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
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                    0 <= before.st_size <= maximum, 'Regular single-link bounded input')
            if created_identity is not None:
                # Every qualified copy read retains the original eight fields.
                # Its caller also requires exact admitted bytes or their digest.
                require(before.st_nlink == 1 and all(identity(before)[i] == created_identity[i]
                        for i in (0, 1, 2, 3, 4, 5, 6, 8)),
                        'Created deployment changed before pin' if created_copy_pin else
                        'Created copy changed before readback')
            self.reads += 1
            self.requested += before.st_size + 1
            require(self.reads <= 2048 and self.requested <= 1024 * 1024 * 1024, 'Aggregate read budget')
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
            fields = range(9) if created_identity is None else (0, 1, 2, 3, 4, 5, 6, 8)

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
        identity_matches = observed == value['identity'] if digest_matches else None
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



def qualified_created_descriptor(created, source):
    """Join this compile's original copied input; never qualify generated output."""
    require(set(source) == {'relativePath', 'descriptor'} and
            set(created) == {'relativePath', 'descriptor', 'writeClosedIdentity', 'readbackObservation'} and
            created['relativePath'] == source['relativePath'], 'Controlled copy lineage role')
    pin, observation = created['descriptor'], created['readbackObservation']
    require(set(pin) == {'path', 'bytes', 'sha256', 'identity'} and
            Path(pin['path']) == project(STAGE_WINDOWS + '\\' + source['relativePath']) and
            pin['bytes'] == source['descriptor']['bytes'] and pin['sha256'] == source['descriptor']['sha256'] and
            set(observation) == {'readOrdinal', 'createdCopyReadback', 'expectedBytes', 'returnedBytes',
                                 'initialDescriptor', 'finalDescriptor', 'namedPath'} and
            observation['createdCopyReadback'] is True and type(observation['readOrdinal']) is int and
            1 <= observation['readOrdinal'] <= 2048 and
            observation['expectedBytes'] == observation['returnedBytes'] == pin['bytes'],
            'Controlled copied content and four observations')
    identities = [created['writeClosedIdentity'], observation['initialDescriptor'],
                  observation['finalDescriptor'], observation['namedPath'], pin['identity']]
    require(all(type(value) is list and len(value) == 9 and all(type(x) is int for x in value)
                for value in identities), 'Controlled copy full9 shapes')
    baseline = identities[0]
    require(stat.S_ISREG(baseline[2]) and baseline[5] == pin['bytes'] and baseline[8] == 1 and
            all(all(value[i] == baseline[i] for i in (0, 1, 2, 3, 4, 5, 6, 8)) for value in identities[1:]) and
            pin['identity'] == observation['namedPath'], 'Controlled copy eight-field/content qualification')
    return pin


def carried_compile_copy(a, item):
    if a['suite'] == 'compile' or item['compileCreation'] is None:
        return None
    lineage = item['compileCreation']
    require(type(lineage) is dict and set(lineage) == {'action', 'inventorySha256', 'source', 'deployment'} and
            re.fullmatch(r'[0-9]{4}', lineage['action']) and 120 < int(lineage['action']) < int(a['action']) and
            re.fullmatch(r'[0-9a-f]{64}', lineage['inventorySha256']) and
            lineage['source']['relativePath'] == item['relativePath'] and
            lineage['deployment']['descriptor'] == item['descriptor'], 'Original accepted compile copy binding')
    qualified_created_descriptor(lineage['deployment'], lineage['source'])
    return lineage


def pin_input(a, item, budget):
    lineage = carried_compile_copy(a, item)
    if lineage is not None:
        return budget.pin_created_copy(lineage['deployment'], lineage['source'], 67108864)
    return budget.pin(item['descriptor'], 67108864)


def write_new(path, raw, budget, maximum=65536):
    budget.check()
    require(len(raw) <= maximum, 'Output bound')
    limit = 512 if budget.terminal_mode else 508
    capacity = 256 * 1024 * 1024 - (0 if budget.terminal_mode else 262144)
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
            re.fullmatch(r'C:\\(?:Temp\\azureauth-windows-slice-108\\|Program Files\\dotnet\\)[A-Za-z0-9 _.,=\\-]+', path) and
            all(0 < len(x) <= 128 and x not in ('.', '..') and not x.endswith(('.', ' ')) and
                x.split('.')[0].upper() not in ('CON', 'PRN', 'AUX', 'NUL',
                    *('COM' + str(i) for i in range(1, 10)), *('LPT' + str(i) for i in range(1, 10)))
                for x in path[3:].split('\\')), 'Windows projection boundary')
    return Path('/mnt/c') / path[3:].replace('\\', '/')



def load_admission(path, expected, budget):
    require(re.fullmatch(r'/tmp/windows-controlled-harness-[0-9]{4}-admission\.json', str(path)), 'Admission leaf')
    raw, full9 = budget.read(path, 65536)
    require(digest(raw) == expected, 'Original admission hash')
    value = decode(raw)
    require(set(value) == {'schema', 'action', 'suite', 'nonce', 'product', 'checkpoint', 'checkpointAcceptance',
                          'inputAcceptance', 'sourceCommit', 'protocol', 'sourceMap', 'catalog',
                          'fixtureAdmission', 'compileOutputAcceptance', 'sourceReview', 'exactCallReview',
                          'inventory', 'controller', 'windowsAuthority', 'caller', 'launcher', 'python',
                          'systemdRun', 'interop', 'runtimeDirectory'}, 'Admission fields')
    require(value['schema'] == 'windows-controlled-harness-admission-v1' and value['product'] == PRODUCT and
            re.fullmatch(r'[0-9]{4}', value['action']) and int(value['action']) > 120 and
            value['suite'] in ('compile', 'native') and
            re.fullmatch(r'[0-9a-f]{40}', value['sourceCommit']) and
            re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', value['nonce']), 'Admission identity')
    require((value['suite'] == 'compile' and value['fixtureAdmission'] is None and
             value['compileOutputAcceptance'] is None) or
            (value['suite'] == 'native' and type(value['fixtureAdmission']) is dict and
             type(value['compileOutputAcceptance']) is dict), 'Compile/native prerequisite split')
    value['_raw'], value['_identity'], value['_path'] = raw, full9, str(path)
    return value

def acceptance(pin, schema, subjects, budget):
    raw = budget.pin(pin, 65536)
    require(raw == encode({'schema': schema, 'accepted': True, 'subjects': subjects}),
            'Independent exact-byte acceptance binding')


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
                before.st_mode & 0o111 and identity(before) == pin['identity'],
                'Admitted executable launcher identity and mode')
        require(os.access(path, os.X_OK, effective_ids=True, follow_symlinks=False),
                'Effective-user launcher execute access')
        require(identity(os.fstat(fd)) == pin['identity'] == identity(path.lstat()),
                'Executable launcher full9 unchanged')
        budget.check()
    finally:
        os.close(fd)



def inventory_rows(a, budget):
    inventory = decode(budget.pin(a['inventory'], 4194304))
    require(set(inventory) == ({'schema', 'files'} if a['suite'] == 'compile' else {'schema', 'identityMode', 'files'}) and
            inventory['schema'] == ('windows-controlled-harness-files-v1' if a['suite'] == 'compile' else
                                    'windows-controlled-harness-files-v2'), 'Exact inventory schema')
    if a['suite'] == 'native':
        require(inventory['identityMode'] == 'synthetic-first-held-v1', 'Explicit synthetic native admission')
    catalog_raw = budget.pin(a['catalog'], 131072)
    require((len(catalog_raw), digest(catalog_raw)) == CATALOG and catalog_raw.endswith(b'\n') and
            b'\r' not in catalog_raw, 'Literal public catalog')
    catalog_lines = catalog_raw.decode('ascii').splitlines()
    require(len(catalog_lines) == 615, 'Catalog row count')
    catalog = {}
    for row in catalog_lines:
        fields = row.split('\t')
        require(len(fields) == 5, 'Catalog fields')
        if fields[0] == a['suite']:
            require(fields[1] not in catalog, 'Unique catalog path')
            catalog[fields[1]] = (int(fields[2]), fields[3], int(fields[4]))
    count = 413 if a['suite'] == 'compile' else 202
    require(len(catalog) == len(inventory['files']) == count, 'Exact controlled input count')
    paths, tsv, total = set(), [], 0
    for item in inventory['files']:
        require(set(item) == ({'relativePath', 'descriptor'} if a['suite'] == 'compile' else
                              {'relativePath', 'descriptor', 'compileCreation'}), 'Inventory row fields')
        relative, pin = item['relativePath'], item['descriptor']
        require(relative in catalog and relative not in paths and
                set(pin) == {'path', 'bytes', 'sha256', 'identity'}, 'Exact selected input')
        destination = project(STAGE_WINDOWS + '\\' + relative)
        require(destination.is_relative_to(STAGE), 'Fixed compile/native destination')
        length, sha256, maximum = catalog[relative]
        require(type(pin['bytes']) is int and 0 < pin['bytes'] <= maximum and
                (length < 0 or pin['bytes'] == length) and
                re.fullmatch(r'[0-9a-f]{64}', pin['sha256']) and
                (sha256 == '-' or pin['sha256'] == sha256) and
                type(pin['identity']) is list and len(pin['identity']) == 9 and
                all(type(x) is int for x in pin['identity']), 'Exact literal input pins')
        require(a['suite'] == 'compile' or Path(pin['path']) == destination,
                'Native reuses only accepted exact staged artifacts')
        if a['suite'] == 'native':
            require((relative.startswith('toolchain\\') and item['compileCreation'] is not None) or
                    (relative.startswith('artifact\\') and item['compileCreation'] is None),
                    'Only original copied runtime inputs carry lineage')
            carried_compile_copy(a, item)
        paths.add(relative)
        total += pin['bytes']
        require(total <= (134217728 if a['suite'] == 'compile' else 100663296), 'Input payload aggregate')
        tsv.append('\t'.join((relative, str(pin['bytes']), pin['sha256'])))
    return inventory['files'], ('\n'.join(tsv) + '\n').encode('ascii')


def verify_admission(a, budget):
    acceptance(a['checkpointAcceptance'], 'windows-controlled-harness-checkpoint-acceptance-v1',
               {'checkpoint': a['checkpoint']}, budget)
    acceptance(a['inputAcceptance'], 'windows-controlled-harness-input-acceptance-v1',
               {'sourceCommit': a['sourceCommit'], 'inventory': a['inventory'], 'sourceMap': a['sourceMap'],
                'catalog': a['catalog'], 'operation': a['suite'], 'publicSyntheticOnly': True,
                'compileOutputAcceptance': a['compileOutputAcceptance'],
                'fixtureAdmission': a['fixtureAdmission'], 'noOriginalRuntimeOrRestoreReads': True}, budget)
    acceptance(a['sourceReview'], 'windows-controlled-harness-source-acceptance-v1',
               {'caller': a['caller'], 'launcher': a['launcher'], 'controller': a['controller'],
                'inventory': a['inventory'], 'sourceMap': a['sourceMap'], 'protocol': a['protocol'],
                'catalog': a['catalog'], 'unchangedNormalLauncher': True,
                'exemptOuterPowerShellCount': 1, 'syntheticCharge': CHARGES[a['suite']],
                'ordinaryToolDescendantsChargedToSelectedPhase': True, 'operation': a['suite']}, budget)
    acceptance(a['exactCallReview'], 'windows-controlled-harness-exact-call-acceptance-v1',
               {key: value for key, value in a.items() if key != 'exactCallReview' and not key.startswith('_')}, budget)
    for key, maximum in (('caller', 131072), ('controller', 65536), ('launcher', 8388608),
                         ('python', 33554432), ('systemdRun', 8388608), ('sourceMap', 131072),
                         ('protocol', 2097152)):
        pinned = budget.pin(a[key], maximum)
        if key == 'sourceMap':
            source_map = decode(pinned)
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
    rows, bindings = inventory_rows(a, budget)
    if a['suite'] == 'compile':
        require(source_map['schema'] == 'controlled-callers-source-response-map-v1' and
                source_map['compileStagingRoot'] == STAGE_WINDOWS and len(source_map['sourceMappings']) == 36,
                'Exact accepted compile source mapping')
        selected_sources = {item['relativePath']: item['descriptor'] for item in rows
                            if item['relativePath'].startswith('source\\')}
        require(len(selected_sources) == 36, 'Complete staged source closure')
        for mapping in source_map['sourceMappings']:
            require(set(mapping) == {'authoredSource', 'stagedRelativePath'}, 'Exact source mapping fields')
            relative = mapping['stagedRelativePath'].replace('/', '\\')
            require(relative in selected_sources, 'Unique mapped staging source')
            selected = selected_sources.pop(relative)
            authored = mapping['authoredSource']
            require(set(authored) == {'path', 'bytes', 'sha256'} and
                    authored['bytes'] == selected['bytes'] and authored['sha256'] == selected['sha256'],
                    'Source placeholders resolved by independently accepted exact source map')
        require(not selected_sources, 'No unmapped source placeholder')
    if a['suite'] == 'native':
        acceptance(a['compileOutputAcceptance'], 'windows-controlled-compile-output-acceptance-v1',
                   {'inventory': a['inventory'], 'sourceMap': a['sourceMap'],
                    'allFourTargetsAccepted': True, 'accountEffectsAdmitted': False}, budget)
        fixture = decode(budget.pin(a['fixtureAdmission'], 262144))
        require(set(fixture) == {'schema', 'admitted', 'scope', 'identityMode', 'batchNonce', 'caseNonces', 'protocolSha256', 'pins'} and
                fixture['schema'] == 'confidential-fixture-admission-v2' and fixture['admitted'] is True and
                fixture['identityMode'] == 'synthetic-first-held-v1' and
                fixture['scope'] == 'synthetic-native-only' and fixture['batchNonce'] == a['nonce'] and
                fixture['protocolSha256'] == a['protocol']['sha256'] and
                type(fixture['caseNonces']) is dict and set(fixture['caseNonces']) == {'N1', 'N2', 'N3'},
                'Native synthetic-only control')
        nonces = [fixture['batchNonce'], *(fixture['caseNonces'][x] for x in ('N1', 'N2', 'N3'))]
        require(len(set(nonces)) == 4 and all(re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', n)
                                            for n in nonces), 'Four distinct case identities')
        expected_pins = [{'relative': x['relativePath'], 'bytes': x['descriptor']['bytes'],
                          'sha256': x['descriptor']['sha256'], 'linuxIdentity': x['descriptor']['identity']} for x in rows]
        require(fixture['pins'] == expected_pins, 'Native admission and held inventory correspondence')
    authority_raw = budget.pin(a['windowsAuthority'], 65536)
    expected = {
        'schema': 'controlled-callers-controller-authority-v1', 'accepted': True,
        'action': a['action'], 'nonce': a['nonce'], 'operation': a['suite'], 'sourceCommit': a['sourceCommit'],
        'protocolSha256': a['protocol']['sha256'], 'checkpointSha256': a['checkpoint']['sha256'],
        'checkpointAcceptanceSha256': a['checkpointAcceptance']['sha256'],
        'sourceReviewSha256': a['sourceReview']['sha256'],
        'inputAcceptanceSha256': a['inputAcceptance']['sha256'], 'inventorySha256': digest(bindings),
        'controllerSha256': a['controller']['sha256'], 'sourceMapSha256': a['sourceMap']['sha256'],
        'fixtureAdmissionSha256': None if a['suite'] == 'compile' else a['fixtureAdmission']['sha256'],
        'compileOutputAcceptanceSha256': None if a['suite'] == 'compile' else a['compileOutputAcceptance']['sha256'],
        'preparationCharge': 0, 'buildTestCharge': 1, 'syntheticCharge': CHARGES[a['suite']],
        'exemptOuterPowerShellCount': 1, 'accountEffectsAdmitted': False, 'noExperimentLive': False,
    }
    # Exact canonical bytes also reject Boolean/integer confusion and duplicate members.
    require(authority_raw == encode(expected), 'Exact finite Windows authority bytes')
    return rows, bindings, authority_raw


def windows_root_name(a):
    return WINDOWS + '\\named-fixtures-' + a['action']


def windows_root(a):
    return PROJECTION / ('named-fixtures-' + a['action'])



def materialize_inputs(a, root, local, budget):
    rows, _ = inventory_rows(a, budget)
    deployed = []
    if a['suite'] == 'compile':
        direct(STAGE.parent)
        STAGE.mkdir(mode=0o700)
        for name in ('artifact', 'records'):
            (STAGE / name).mkdir(mode=0o700)
    else:
        direct(STAGE)
    for item in rows:
        raw = pin_input(a, item, budget)
        destination = project(STAGE_WINDOWS + '\\' + item['relativePath'])
        if a['suite'] == 'compile':
            parent = STAGE
            for segment in destination.relative_to(STAGE).parts[:-1]:
                parent = parent / segment
                try:
                    require(budget.created_directories < 64, 'Created deployment directory bound')
                    parent.mkdir(mode=0o700)
                    budget.created_directories += 1
                except FileExistsError:
                    require(stat.S_ISDIR(direct(parent).lstat().st_mode), 'Owned deployment directory')
            write_new(destination, raw, budget, 67108864)
            closed = identity(destination.lstat())
            observed, readback = budget.read_created_copy(destination, 67108864, closed, raw)
            descriptor = {'path': str(destination), 'bytes': len(raw), 'sha256': digest(raw), 'identity': observed}
        else:
            descriptor = item['descriptor']
        created = {'relativePath': item['relativePath'], 'descriptor': descriptor}
        if a['suite'] == 'compile':
            created.update(writeClosedIdentity=closed, readbackObservation=readback)
        deployed.append(created)
    if a['suite'] == 'native':
        fixture_path = STAGE / 'control' / 'fixture-admission.json'
        raw = budget.pin(a['fixtureAdmission'], 262144)
        write_new(fixture_path, raw, budget, 262144)
        closed = identity(fixture_path.lstat())
        copy, observed = budget.read(fixture_path, 262144)
        require(copy == raw and observed == closed, 'Strict fixture-control copy')
        fixture = {'path': str(fixture_path), 'bytes': len(raw), 'sha256': digest(raw), 'identity': observed}
    else:
        fixture = None
    evidence = encode({'schema': 'windows-controlled-harness-deployment-v1',
                       'inventorySha256': a['inventory']['sha256'], 'files': deployed, 'fixtureAdmission': fixture})
    write_new(local / 'deployment.json', evidence, budget, 4194304)
    write_new(root / 'deployment.json', evidence, budget, 4194304)


def verify_deployment(a, root, local, budget):
    raw = budget.read(local / 'deployment.json', 4194304)[0]
    require(budget.read(root / 'deployment.json', 4194304)[0] == raw, 'Original deployment receipt copies')
    deployment = decode(raw)
    rows, _ = inventory_rows(a, budget)
    require(set(deployment) == {'schema', 'inventorySha256', 'files', 'fixtureAdmission'} and
            deployment['schema'] == 'windows-controlled-harness-deployment-v1' and
            deployment['inventorySha256'] == a['inventory']['sha256'] and
            len(deployment['files']) == len(rows), 'Complete deployment receipt')
    for created, source in zip(deployment['files'], rows, strict=True):
        pin = created['descriptor']
        require(set(created) == ({'relativePath', 'descriptor', 'writeClosedIdentity', 'readbackObservation'}
                                 if a['suite'] == 'compile' else {'relativePath', 'descriptor'}) and
                created['relativePath'] == source['relativePath'] and
                Path(pin['path']) == project(STAGE_WINDOWS + '\\' + source['relativePath']) and
                pin['bytes'] == source['descriptor']['bytes'] and
                pin['sha256'] == source['descriptor']['sha256'], 'Bound source/deployment correspondence')
        if a['suite'] == 'native':
            require(pin == source['descriptor'], 'Native input retains its exact accepted descriptor')
            pin_input(a, source, budget)
        else:
            budget.pin_created_copy(created, source, 67108864)
    fixture = deployment['fixtureAdmission']
    if a['suite'] == 'compile':
        require(fixture is None, 'Compile has no runtime admission')
    else:
        require(Path(fixture['path']) == STAGE / 'control' / 'fixture-admission.json' and
                fixture['bytes'] == a['fixtureAdmission']['bytes'] and
                fixture['sha256'] == a['fixtureAdmission']['sha256'], 'Staged native admission binding')
        budget.pin(fixture, 262144)


def checkpoint(a, budget, reserved=False):
    c = decode(budget.pin(a['checkpoint'], 65536))
    require(set(c) == {'schema', 'counters', 'ceilings', 'nextAction', 'historyParents',
                      'historicalLifetimeUnknown', 'noExperimentLive', 'knownEndpoints', 'predecessorAccepted',
                      'protectedAfter', 'capacityAmendmentAccepted', 'historicalDispositionsExtended', 'hostPreparations',
                      'reservation'},
            'Current checkpoint fields')
    require(c['schema'] == 'windows-controlled-harness-current-checkpoint-v1' and c['nextAction'] == a['action'] and
            c['ceilings'] == CEILINGS and c['historicalLifetimeUnknown'] == HISTORICAL_UNKNOWN and
            c['noExperimentLive'] is False and c['predecessorAccepted'] is True and
            c['capacityAmendmentAccepted'] is True and
            c['historicalDispositionsExtended'] == HISTORICAL_UNKNOWN and
            c['reservation'] == 'controlled-' + a['suite'], 'Current checkpoint acceptance')
    before = c['counters']
    require(type(before) is list and len(before) == 4 and all(type(x) is int and x >= 0 for x in before) and
            before[0] >= 20 and before[1] >= 106 and before[2] >= 6 and
            before[3] >= 163, 'Current nonrefundable accounting')
    charge = [0, 1, 0, CHARGES[a['suite']]]
    after = [x + y for x, y in zip(before, charge, strict=True)]
    hosts = c['hostPreparations']
    require(type(hosts) is dict and set(hosts) == {'linux', 'windows'}, 'Preparation host allocation')
    for name, ceiling in (('linux', 18), ('windows', 18)):
        v = hosts[name]
        require(type(v) is list and len(v) == 2 and all(type(n) is int for n in v) and
                v[1] == ceiling and 0 <= v[0] <= ceiling, 'Host preparation ceiling')
    require(hosts['linux'][0] + hosts['windows'][0] == before[0] and
            hosts['windows'][0] + charge[0] <= 18, 'Windows preparation debit')
    protected = c['protectedAfter']
    require(type(protected) is list and len(protected) == 4 and
            all(type(x) is int and x >= 0 for x in protected) and protected[1] >= 12 and
            all(x + p <= y for x, p, y in zip(after, protected, CEILINGS, strict=True)),
            'Current ceiling and independently protected remaining reservations')
    require(type(c['knownEndpoints']) is list and 5 <= len(c['knownEndpoints']) <= 128 and
            len(set(c['knownEndpoints'])) == len(c['knownEndpoints']), 'Preserve retained endpoints')
    require(set(c['historyParents']) == set(PARENTS), 'Current four-parent projection')
    for role, path in PARENTS.items():
        expected = c['historyParents'][role]
        require(type(expected) is list and len(expected) <= 128 and expected == sorted(set(expected)),
                'Parent projection schema')
        if reserved and role == 'windowsActions':
            expected = sorted([*expected, a['action']])
        if reserved and role == 'windowsProjectionRoot':
            expected = sorted([*expected, 'named-fixtures-' + a['action'],
                               *(['confidential-checks-v7'] if a['suite'] == 'compile' else [])])
        require(names(path, 128, budget) == expected, 'Current parent membership changed')
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
            type(completed['totalProcesses']) is int and
            completed['totalProcesses'] == (5 if a['suite'] == 'compile' else 12) and
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



def native_baseline_evidence(a, rows, budget):
    directory = STAGE / 'records' / a['nonce']
    raw, file_identity = budget.read(directory / 'native-baseline.json', 262144)
    value = decode(raw)
    require(set(value) == {'schema', 'identityMode', 'root', 'original', 'admissionSha256', 'protocolSha256', 'rows'} and
            value['schema'] == 'synthetic-native-baseline-v1' and value['identityMode'] == 'synthetic-first-held-v1' and
            value['root'] == STAGE_WINDOWS and value['original'] == a['nonce'] and
            value['admissionSha256'] == a['fixtureAdmission']['sha256'] and
            value['protocolSha256'] == a['protocol']['sha256'] and
            type(value['rows']) is list and len(value['rows']) == 202, 'Bound original native baseline')
    for admitted, actual in zip(sorted(rows, key=lambda x: x['relativePath']), value['rows'], strict=True):
        budget.check()
        require(set(actual) == {'relative', 'bytes', 'sha256', 'identity'} and
                actual['relative'] == admitted['relativePath'] and type(actual['bytes']) is int and
                actual['bytes'] == admitted['descriptor']['bytes'] and actual['sha256'] == admitted['descriptor']['sha256'],
                'Closed baseline catalog correspondence')
        native = actual['identity']
        require(type(native) is dict and
                set(native) == {'volume', 'index', 'attributes', 'created', 'modified', 'changed', 'links'} and
                all(type(x) is int for x in native.values()) and
                0 <= native['volume'] < 2 ** 32 and 0 <= native['attributes'] < 2 ** 32 and
                native['attributes'] & 0x410 == 0 and 0 < native['index'] < 2 ** 64 and native['links'] == 1 and
                all(0 < native[x] < 2 ** 63 for x in ('created', 'modified', 'changed')), 'Observed native snapshot shape')
    batch = decode(budget.read(directory / 'batch.json', 4096)[0])
    require(set(batch) == {'schema', 'passed', 'nativeBaselineSha256', 'completedPureRows', 'completedNativeCases', 'noExperimentLive'} and
            batch['schema'] == 'synthetic-caller-batch-v1' and batch['passed'] is True and
            batch['nativeBaselineSha256'] == digest(raw) and type(batch['completedPureRows']) is int and
            batch['completedPureRows'] == 84 and type(batch['completedNativeCases']) is int and
            batch['completedNativeCases'] == 3 and batch['noExperimentLive'] is False, 'Batch terminal baseline binding')
    return {'path': str(directory / 'native-baseline.json'), 'bytes': len(raw), 'sha256': digest(raw), 'identity': file_identity}


def controlled_evidence(root, a, rows, budget, controller):
    result = decode(budget.read(root / 'controlled-result.json', 32768)[0])
    require(result['schema'] == 'controlled-callers-controller-result-v1' and
            result['authoritySha256'] == a['windowsAuthority']['sha256'] and
            result['operation'] == a['suite'] and result['sourceCommit'] == a['sourceCommit'] and
            result['nonce'] == a['nonce'] and result['passed'] is True and
            result['cancellationRequested'] is False and result['cancellationMarkerConfirmed'] is False and
            result['failureType'] is None and result['failureLine'] is None and result['finalizationFailureType'] is None and
            result['phase'] == 'captured' and 0 <= result['elapsedMilliseconds'] < 325000 and
            result['artifactAccepted'] is False and result['scenarioAccepted'] is False and
            result['scopedJobQuiescenceEstablished'] is False and result['noExperimentLive'] is False,
            'Complete original controlled receipt')
    phases = ['compile-' + x.lower() for x in TARGETS] if a['suite'] == 'compile' else ['native-batch']
    require(len(result['phases']) == result['startsAttempted'] == len(phases), 'Exact original phase starts')
    identities, captured = [], 0
    for name, phase in zip(phases, result['phases'], strict=True):
        require(phase['phase'] == name and phase['exited'] is True and phase['exitCode'] == 0 and
                phase['stdoutEof'] is True and phase['stderrEof'] is True and
                phase['captureDisposition'] == 'complete' and phase['unexpectedReadBytes'] == 0,
                'Controlled phase normal exit and complete EOF')
        require(decode(budget.read(root / (name + '-result.json'), 32768)[0]) == phase,
                'Distinct phase/aggregate correspondence')
        started = decode(budget.read(root / (name + '-started.json'), 32768)[0])
        require(started['schema'] == 'controlled-callers-started-v1' and
                started['authoritySha256'] == a['windowsAuthority']['sha256'] and started['phase'] == name and
                type(started['pid']) is int and started['pid'] > 0 and started['pid'] != controller['rootPid'] and
                re.fullmatch(r'[1-9][0-9]{1,19}', started['creationFileTime']) and
                started['handleRetained'] is True and started['creationMode'] == 'ordinary-child-without-breakaway',
                'Original retained controlled child identity')
        pair = [started['pid'], started['creationFileTime']]
        require(pair not in identities, 'Distinct controlled phase identity')
        identities.append(pair)
        if a['suite'] == 'compile':
            target = next(x for x in TARGETS if name == 'compile-' + x.lower())
            executable = STAGE_WINDOWS + r'\toolchain\dotnet.exe'
            arguments = ('exec --fx-version 10.0.12 --roll-forward Disable "' + STAGE_WINDOWS +
                         r'\toolchain\compiler\csc.dll" /noconfig "@' + STAGE_WINDOWS + '\\control\\' + target + '.rsp"')
        else:
            executable = STAGE_WINDOWS + r'\artifact\FixtureDriver.exe'
            arguments = '"' + STAGE_WINDOWS + r'\control\fixture-admission.json" ' + a['fixtureAdmission']['sha256']
        require(decode(budget.read(root / (name + '-invocation.json'), 32768)[0]) == {
            'schema': 'controlled-callers-invocation-v1', 'authoritySha256': a['windowsAuthority']['sha256'],
            'executable': executable, 'arguments': arguments, 'workingDirectory': STAGE_WINDOWS,
            'originalControllerCutoffMilliseconds': 240000 if a['suite'] == 'compile' else 310000,
            'expectedExitCode': 0, 'environmentMode': 'unchanged-normal-launcher-bootstrap', 'phase': name},
            'Exact finite controlled command')
        for stream in ('stdout', 'stderr'):
            raw = budget.read(root / (name + '.' + stream + '.bin'), 65536)[0]
            require(len(raw) == phase[stream + 'Bytes'], 'Complete phase capture correspondence')
            captured += len(raw)
    require(captured <= (65536 if a['suite'] == 'compile' else 0), 'Aggregate compiler/native transport bound')
    require((a['suite'] == 'compile' and [x['target'] for x in result['apphosts']] == list(TARGETS) and
             all(x['bytes'] == 160768 and re.fullmatch(r'[0-9a-f]{64}', x['sha256']) for x in result['apphosts'])) or
            (a['suite'] == 'native' and result['apphosts'] == []), 'Four constructed apphost receipts')
    baseline = native_baseline_evidence(a, rows, budget) if a['suite'] == 'native' else None
    return {'phaseIdentities': identities, 'operation': a['suite'], 'nativeBaseline': baseline,
            'requiresIndependentOutputAcceptance': True}

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
    result = {'schema': 'windows-controlled-harness-worker-result-v1', 'passed': False,
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
        require(timing == {'schema': 'windows-controlled-harness-service-intent-v1',
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
                digest(budget.read(root / 'Invoke-WindowsNamedGuardFixtures.ps1', 65536)[0]) == a['controller']['sha256'] and
                budget.read(root / 'controller-input-catalog.tsv', 131072)[0] == budget.pin(a['catalog'], 131072),
                'Durable original binding')
        verify_deployment(a, root, local, budget)
        checkpoint(a, budget, reserved=True)
        command = [a['launcher']['path'], windows_root_name(a), a['nonce'],
                   a['windowsAuthority']['sha256'], a['controller']['sha256']]
        write_new(local / 'worker-started.json', encode({'schema': 'windows-controlled-harness-worker-v1',
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
        result['controlled'] = controlled_evidence(root, a, roles, budget, result['controller'])
        result['artifactAccepted'] = False
        result['scenarioAccepted'] = False
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
        started = {'schema': 'windows-controlled-harness-started-v1', 'action': a['action'], 'suite': a['suite'],
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
        write_new(root / 'authority.json', authority_raw, budget)
        write_new(root / 'inventory.tsv', bindings, budget, 1048576)
        write_new(root / 'Invoke-WindowsNamedGuardFixtures.ps1', budget.pin(a['controller'], 65536), budget)
        write_new(root / 'controller-input-catalog.tsv', budget.pin(a['catalog'], 131072), budget, 131072)
        stage = 'original-materialization'
        materialize_inputs(a, root, local, budget)
        checkpoint(a, budget, reserved=True)
        # Service + 5 service termination + 5 transport slack + 15 original
        # evidence; original terminal 10 is withheld in budget.deadline already.
        budget.check((SERVICE_SECONDS + 25) * 1_000_000_000)
        service_intent = time.monotonic_ns()
        service_deadline = service_intent + SERVICE_SECONDS * 1_000_000_000
        write_new(local / 'service-intent.json', encode({
            'schema': 'windows-controlled-harness-service-intent-v1',
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
        stage = 'original-result-retention'
        budget.enter_terminal()
        write_new(local / 'original-result.json', encode({'schema': 'windows-controlled-harness-original-result-v1',
                  'complete': True, 'action': a['action'], 'suite': a['suite'], 'admissionSha256': digest(a['_raw']),
                  'accounting': {'before': before, 'charge': charge, 'after': after},
                  'scopedJobQuiescent': True, 'noExperimentLive': False,
                  'historicalLifetimeUnknown': HISTORICAL_UNKNOWN, 'requiresIndependentOutcomeAcceptance': True}), budget)
        return 0
    except BaseException as error:
        if reserved_local:
            result = {'schema': 'windows-controlled-harness-original-failure-v1',
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
        began, deadline = entered, entered + 3_600_000_000_000
        budget = Budget(began, deadline - 10_000_000_000, deadline)
    require(deadline - began == 3_600_000_000_000, 'Single original clock')
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
