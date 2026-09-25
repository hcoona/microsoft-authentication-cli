"""Inert retained-launcher CLI22/Profile2 caller and dedicated cgroup worker.

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
import xml.etree.ElementTree as ET

LINUX = Path('/var/tmp/azureauth-windows-slice-108')
PROJECTION = Path('/mnt/c/Temp/azureauth-windows-slice-108')
WINDOWS = r'C:\Temp\azureauth-windows-slice-108'
CEILINGS = [35, 141, 30, 277]  # Proposed ceilings; guard remains closed until amended authority.
HISTORICAL_UNKNOWN = ['0057', '0064', '0068', '0093', '0107', '0110']
PRODUCT = '503360753accd0829801953823b1b57a4f852440'
NORMAL_LAUNCHER = (23040, '5b018f38669fd6ca3cec8f760533af392e0265280047bfb5c531dd41a349690a')
SNAPSHOT = '5ae614051b512ad9d372f29cf20719e8e0e33e3329b3c4af4a4d0020b8f77413'
CHARGES = {'cli': 14, 'profile': 4}
PARENTS = {'linuxActions': LINUX / 'actions', 'windowsActions': LINUX / 'windows-actions',
           'windowsProjectionActions': PROJECTION / 'actions', 'windowsProjectionRoot': PROJECTION}
PROFILE_CASES = ('native-profile-duplicate', 'native-profile-unknown')
PROFILE_HASHES = {
    'native-profile-duplicate': (363, 'b6ca405ce7966ff7453243d5e098663e25b09c31fb20a2bfb1830a9c746c1865'),
    'native-profile-unknown': (389, '34d3a16209321b97f37edf5f39d3059a3a64adf4ff11f64a5a0daab059414081'),
}
# Exact expanded CLI cases and selectors are copied as data from the accepted runner.
FILE_CASES = ['ExplicitFilePreservesSelectedProfileAndRequest ("personal@example.test")',
 'ExplicitFilePreservesSelectedProfileAndRequest ("work@example.test")',
 'FileSizeLimitAppliesBeforeAuthentication (65536)',
 'FileSizeLimitAppliesBeforeAuthentication (65537)',
 'ReplacingFileAfterAdmissionCannotChangeTheInFlightProfile',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("missing")',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("directory")',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("malformed-json")',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("invalid-utf8")',
 'UnreadableOrInvalidFileStopsBeforeProviderConstruction ("sharing-denied")']
PROCESS_CASES = {'RootHelpCompletesWithoutAuthentication': 'help',
 'MalformedAuthenticationReturnsTheBootstrapFailure': 'malformed',
 'SelectedRequestReturnsOneSuccessDespiteBrokenDiagnostics': 'success',
 'FlaggedRegularFileStopsBeforeProfileAndProvider': 'file-stdin',
 'AlreadyClosedLifetimePipeCancelsBeforeAuthentication': 'closed-stdin',
 'WriterClosureRejectsLateSuccessAndEndsTheProcess': 'close-pending',
 'ClosedStdinWithoutTheFlagDoesNotCancel': 'unused-stdin',
 'LifetimePipePayloadIsIgnoredAndClosureStillCancels': 'data-close',
 'DeadlineEndsUncooperativeWorkWithinTheProcessBound': 'deadline',
 'BrokenResultReaderEndsWithTransportFailure': 'broken-output',
 'UndrainedResultPipeCannotKeepTheProcessAlive': 'blocked-output',
 'BlockedDiagnosticsDoNotChangeTheAuthenticationResultOrKeepTheProcessAlive': 'blocked-diagnostics'}


def require(condition, label):
    if not condition:
        raise ValueError(label)


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
        self.check()
        direct(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, 'Regular bounded input')
            self.reads += 1
            self.requested += before.st_size + 1
            require(self.reads <= 1024 and self.requested <= 768 * 1024 * 1024, 'Aggregate read budget')
            parts, remaining = [], before.st_size + 1
            while remaining:
                self.check()
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                parts.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(parts)
            require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
                    'Unstable descriptor/path identity')
            self.check()
            return raw, identity(before)
        finally:
            os.close(fd)

    def pin(self, value, maximum):
        require(set(value) == {'path', 'bytes', 'sha256', 'identity'}, 'Exact descriptor fields')
        raw, observed = self.read(Path(value['path']), maximum)
        require(len(raw) == value['bytes'] and digest(raw) == value['sha256'] and observed == value['identity'],
                'Admitted descriptor changed')
        return raw


def write_new(path, raw, budget, maximum=65536):
    budget.check()
    require(len(raw) <= maximum, 'Output bound')
    limit = 256 if budget.terminal_mode else 252
    capacity = 544 * 1024 * 1024 - (0 if budget.terminal_mode else 262144)
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
    require(re.fullmatch(r'/tmp/windows-retained-scenarios-[0-9]{4}-admission\.json', str(path)), 'Admission leaf')
    raw, full9 = budget.read(path, 65536)
    require(digest(raw) == expected, 'Original admission hash')
    value = decode(raw)
    require(set(value) == {'schema', 'action', 'suite', 'nonce', 'product', 'checkpoint', 'checkpointAcceptance',
                          'nativeAcceptance', 'buildAcceptance', 'sourceReview', 'exactCallReview', 'inventory',
                          'controller', 'windowsAuthority', 'caller', 'launcher', 'python', 'systemdRun',
                          'interop', 'runtimeDirectory'},
            'Admission fields')
    require(value['schema'] == 'windows-retained-scenarios-admission-v1' and value['product'] == PRODUCT and
            re.fullmatch(r'[0-9]{4}', value['action']) and int(value['action']) > 110 and
            value['suite'] in ('cli', 'profile') and
            re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', value['nonce']), 'Admission identity')
    value['_raw'], value['_identity'], value['_path'] = raw, full9, str(path)
    return value


def acceptance(pin, schema, subjects, budget):
    value = decode(budget.pin(pin, 65536))
    require(value == {'schema': schema, 'accepted': True, 'subjects': subjects}, 'Independent acceptance binding')


def verify_admission(a, budget):
    # Independent snapshot/artifact acceptance never turns original 0110 into a
    # successful publication. Exact-call review is outside the Windows authority
    # object, avoiding an authority/review content-hash cycle.
    acceptance(a['checkpointAcceptance'], 'windows-retained-scenarios-checkpoint-acceptance-v1',
               {'checkpoint': a['checkpoint']}, budget)
    acceptance(a['nativeAcceptance'], 'windows-retained-scenarios-native-acceptance-v1',
               {'product': PRODUCT, 'inventory': a['inventory'], 'basis': 'original-0110-retained-candidate',
                'snapshotManifestSha256': SNAPSHOT, 'originalPublicationPassed': False,
                'snapshotCollectionAccepted': True, 'artifactAccepted': True}, budget)
    acceptance(a['buildAcceptance'], 'windows-retained-scenarios-build-acceptance-v1',
               {'inventory': a['inventory'], 'harnessPreservesCli22AndControlled10': True,
                'explicitMstestAndTrxOnly': True, 'runtime': '10.0.12'}, budget)
    acceptance(a['sourceReview'], 'windows-retained-scenarios-source-acceptance-v1',
               {'caller': a['caller'], 'launcher': a['launcher'], 'controller': a['controller'],
                'inventory': a['inventory'], 'unchangedNormalLauncher': True,
                'exemptOuterPowerShellCount': 1, 'syntheticCharge': CHARGES[a['suite']],
                'noUncountedWindowsStarts': True}, budget)
    acceptance(a['exactCallReview'], 'windows-retained-scenarios-exact-call-acceptance-v1',
               {key: value for key, value in a.items() if key != 'exactCallReview' and not key.startswith('_')}, budget)
    for key, maximum in (('caller', 131072), ('controller', 65536), ('launcher', 8388608), ('python', 33554432),
                         ('systemdRun', 8388608)):
        budget.pin(a[key], maximum)
    require(Path(a['caller']['path']) == Path(__file__).absolute() and
            re.fullmatch(r'/usr/bin/python3\.[0-9]+', a['python']['path']) and
             a['systemdRun']['path'] == '/usr/bin/systemd-run', 'Original entry tools')
    require((a['launcher']['bytes'], a['launcher']['sha256']) == NORMAL_LAUNCHER,
            'Retained normal launcher artifact only')
    interop = a['interop']
    require(set(interop) == {'path', 'identity'} and re.fullmatch(r'/run/WSL/[0-9]{1,10}_interop', interop['path']),
            'Original WSL interop selector')
    sock = direct(Path(interop['path'])).lstat()
    require(stat.S_ISSOCK(sock.st_mode) and identity(sock) == interop['identity'], 'Original interop identity')
    runtime = a['runtimeDirectory']
    require(set(runtime) == {'path', 'identity'} and runtime['path'] == '/run/user/' + str(os.getuid()) and
            identity(direct(Path(runtime['path'])).lstat()) == runtime['identity'], 'User manager directory')
    inventory = decode(budget.pin(a['inventory'], 65536))
    require(set(inventory) == {'schema', 'files'} and inventory['schema'] == 'windows-retained-scenarios-files-v1' and
            4 <= len(inventory['files']) <= 128, 'Complete deployment inventory')
    roles, paths, tsv = {}, set(), []
    total = 0
    for item in inventory['files']:
        require(set(item) == {'role', 'windowsPath', 'descriptor', 'materialize'}, 'Inventory fields')
        role, path, pin = item['role'], item['windowsPath'], item['descriptor']
        require(role in ('dotnet', 'runner', 'native', 'asset') and path.casefold() not in paths and
                type(item['materialize']) is bool and set(pin) == {'path', 'bytes', 'sha256', 'identity'},
                'Inventory path/role')
        destination = project(path)
        if item['materialize']:
            relative = destination.relative_to(windows_root(a))
            require(2 <= len(relative.parts) <= 8 and relative.parts[0] in ('managed', 'native'),
                    'Dedicated deployment subdirectory')
        else:
            require(destination == Path(pin['path']) and
                    path.startswith('C:\\Program Files\\dotnet\\'), 'Installed runtime input only')
        paths.add(path.casefold())
        if role != 'asset':
            require(role not in roles, 'Duplicate entry role')
            roles[role] = path
        require(type(pin['bytes']) is int and 0 < pin['bytes'] <= 134217728 and
                re.fullmatch(r'[0-9a-f]{64}', pin['sha256']) and
                type(pin['identity']) is list and len(pin['identity']) == 9 and
                all(type(x) is int for x in pin['identity']), 'Bounded source descriptor')
        total += pin['bytes']
        require(total <= 536870912, 'Inventory aggregate size')
        # The original materializer reads each source exactly once below. The
        # worker later validates the resulting deployment, not another source copy.
        tsv.append('\t'.join((role, path, str(pin['bytes']), pin['sha256'])))
    require(set(roles) == {'dotnet', 'runner', 'native'} and
            roles['dotnet'] == r'C:\Program Files\dotnet\dotnet.exe' and
            roles['runner'] == windows_root_name(a) + r'\managed\Authentication.Windows.Scenarios.dll' and
            roles['native'] == windows_root_name(a) + r'\native\azureauth.exe', 'Inventory entry identities')
    require(project(roles['native']) != project(roles['runner']) and
            a['launcher']['path'].startswith('/mnt/c/Temp/azureauth-windows-slice-108/') and
            a['launcher']['path'].lower().endswith('.exe'), 'Separate native/managed/controller identities')
    bindings = ('\n'.join(tsv) + '\n').encode('utf-8')
    authority_raw = budget.pin(a['windowsAuthority'], 65536)
    authority = decode(authority_raw)
    expected = {
        'schema': 'retained-windows-scenarios-authority-v1', 'accepted': True,
        'action': a['action'], 'suite': 'cli22' if a['suite'] == 'cli' else 'native-profile2',
        'productCommit': PRODUCT, 'nativeEvidenceBasis': 'original-0110-retained-candidate',
        'nativeArtifactAccepted': True, 'buildTestCharge': 1,
        'syntheticCharge': CHARGES[a['suite']], 'deliberateWindowsStarts': CHARGES[a['suite']] + 1,
        'expectedJobTotalProcesses': CHARGES[a['suite']], 'exemptOuterPowerShellCount': 1,
        'runnerSeconds': 240, 'wrapperSeconds': 300, 'maximumCaptureBytes': 8388608,
        'noExperimentLive': False, 'checkpointSha256': a['checkpoint']['sha256'],
        'checkpointAcceptanceSha256': a['checkpointAcceptance']['sha256'],
        'nativeAcceptanceSha256': a['nativeAcceptance']['sha256'],
        'managedBuildAcceptanceSha256': a['buildAcceptance']['sha256'],
        'sourceReviewSha256': a['sourceReview']['sha256'], 'inventorySha256': digest(bindings),
        'controllerSha256': a['controller']['sha256'],
    }
    require(authority == expected, 'Exact finite Windows authority')
    return roles, bindings, authority_raw


def windows_root_name(a):
    return WINDOWS + '\\named-fixtures-' + a['action']


def windows_root(a):
    return PROJECTION / ('named-fixtures-' + a['action'])


def materialize_inputs(a, root, local, budget):
    inventory = decode(budget.pin(a['inventory'], 65536))
    deployed = []
    for item in inventory['files']:
        raw = budget.pin(item['descriptor'], 134217728)
        destination = project(item['windowsPath'])
        if item['materialize']:
            relative = destination.relative_to(root)
            parent = root
            for segment in relative.parts[:-1]:
                parent = parent / segment
                try:
                    require(budget.created_directories < 128, 'Created deployment directory bound')
                    parent.mkdir(mode=0o700)
                    budget.created_directories += 1
                except FileExistsError:
                    require(stat.S_ISDIR(direct(parent).lstat().st_mode), 'Owned deployment directory')
            write_new(destination, raw, budget, 134217728)
            info = destination.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_size == len(raw), 'Created deployment file')
            descriptor = {'path': str(destination), 'bytes': len(raw), 'sha256': digest(raw),
                          'identity': identity(info)}
        else:
            descriptor = item['descriptor']
        deployed.append({'role': item['role'], 'windowsPath': item['windowsPath'], 'descriptor': descriptor})
    evidence = encode({'schema': 'windows-retained-scenarios-deployment-v1',
                       'inventorySha256': a['inventory']['sha256'], 'files': deployed})
    write_new(local / 'deployment.json', evidence, budget)
    write_new(root / 'deployment.json', evidence, budget)


def verify_deployment(a, root, local, budget):
    raw = budget.read(local / 'deployment.json', 65536)[0]
    require(budget.read(root / 'deployment.json', 65536)[0] == raw, 'Original deployment receipt copies')
    deployment = decode(raw)
    inventory = decode(budget.pin(a['inventory'], 65536))
    require(deployment['schema'] == 'windows-retained-scenarios-deployment-v1' and
            deployment['inventorySha256'] == a['inventory']['sha256'] and
            len(deployment['files']) == len(inventory['files']), 'Complete deployment receipt')
    for created, source in zip(deployment['files'], inventory['files'], strict=True):
        pin = created['descriptor']
        require(created['role'] == source['role'] and created['windowsPath'] == source['windowsPath'] and
                Path(pin['path']) == project(source['windowsPath']) and
                pin['bytes'] == source['descriptor']['bytes'] and
                pin['sha256'] == source['descriptor']['sha256'], 'Bound source/deployment correspondence')
        budget.pin(pin, 134217728)


def checkpoint(a, budget, reserved=False):
    c = decode(budget.pin(a['checkpoint'], 65536))
    require(set(c) == {'schema', 'counters', 'ceilings', 'nextAction', 'historyParents',
                      'historicalLifetimeUnknown', 'noExperimentLive', 'knownEndpoints', 'predecessorAccepted',
                      'protectedAfter', 'capacityAmendmentAccepted', 'historicalDispositionsExtended'},
            'Current checkpoint fields')
    require(c['schema'] == 'windows-retained-scenarios-current-checkpoint-v1' and c['nextAction'] == a['action'] and
            c['ceilings'] == CEILINGS and c['historicalLifetimeUnknown'] == HISTORICAL_UNKNOWN and
            c['noExperimentLive'] is False and c['predecessorAccepted'] is True and
            c['capacityAmendmentAccepted'] is True and
            c['historicalDispositionsExtended'] == HISTORICAL_UNKNOWN, 'Current checkpoint acceptance')
    before = c['counters']
    require(type(before) is list and len(before) == 4 and all(type(x) is int and x >= 0 for x in before) and
            before[0] >= 20 and before[1] >= 106 and before[2] >= 6 and
            before[3] >= 163, 'Current nonrefundable accounting')
    charge = [0, 1, 0, CHARGES[a['suite']]]
    after = [x + y for x, y in zip(before, charge, strict=True)]
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
            expected = sorted([*expected, 'named-fixtures-' + a['action']])
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
            # Return the original cause before cancellation. The owner persists
            # its first-failure receipt, then attempts cancellation independently.
        finally:
            # Closing a Linux proxy pipe establishes no Windows termination.
            for stream in (process.stdout, process.stderr):
                stream.close()
        return {'pid': process.pid, 'exitCode': process.poll(), 'eof': sorted(eof), 'failure': error,
                'cancelFailure': cancel_error,
                'stdout': base64.b64encode(parts['stdout']).decode('ascii'),
                'stderr': base64.b64encode(parts['stderr']).decode('ascii')}


def exact_transport(result):
    require(result['exitCode'] == 0 and result['eof'] == ['stderr', 'stdout'] and result['failure'] is None and
            result['cancelFailure'] is None and result['stdout'] == result['stderr'] == '',
            'Original transport is incomplete or nonzero')


def validate_cli_report(raw):
    require(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw, 'TRX declarations not admitted')
    report = ET.fromstring(raw)
    prefix = 'Authentication.Windows.Scenarios.'
    cases = {prefix + 'ProfileFileScenarios.' + name: 'Passed' for name in FILE_CASES}
    cases.update({prefix + 'ProcessScenarios.' + name: 'Passed' for name in PROCESS_CASES})
    required = {'total': '22', 'executed': '22', 'passed': '22', 'failed': '0'}
    required.update({name: '0' for name in ('error', 'timeout', 'aborted', 'inconclusive', 'passedButRunAborted',
                     'notRunnable', 'notExecuted', 'disconnected', 'warning', 'completed', 'inProgress', 'pending')})
    counters = report.findall('.//{*}Counters')
    require(len(counters) == 1 and counters[0].attrib == required, 'Exact CLI22 counters')
    identities = {}
    for item in report.findall('.//{*}UnitTest'):
        methods = item.findall('{*}TestMethod')
        require(item.attrib['id'] not in identities and len(methods) == 1 and
                item.attrib['name'] == methods[0].attrib['name'], 'CLI definition identity')
        identities[item.attrib['id']] = (methods[0].attrib['className'] + '.' + methods[0].attrib['name'],
                                        methods[0].attrib['name'])
    observed, identifiers = {}, set()
    for item in report.findall('.//{*}UnitTestResult'):
        key = item.attrib['testId']
        require(key in identities and key not in identifiers, 'CLI result identity')
        identifiers.add(key)
        qualified, name = identities[key]
        require(qualified not in observed and item.attrib['testName'] == name, 'CLI expanded identity')
        observed[qualified] = item.attrib['outcome']
    require(len(identities) == 22 and identifiers == set(identities) and observed == cases, 'Exact CLI22 outcomes')
    return {'rows': 22, 'passed': 22}


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
            completed['totalProcesses'] == CHARGES[a['suite']] and
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
    result = decode(budget.read(root / 'scenario-result.json', 32768)[0])
    suite = 'cli22' if a['suite'] == 'cli' else 'native-profile2'
    require(result['schema'] == 'retained-windows-scenarios-result-v1' and
            result['authoritySha256'] == a['windowsAuthority']['sha256'] and result['suite'] == suite and
            result['passed'] is True and result['managedProcessStarted'] is True and
            result['managedHandleRetained'] is True and result['managedExited'] is True and
            result['exitCode'] == 0 and result['stdoutEof'] is True and result['stderrEof'] is True and
            result['captureDisposition'] == 'complete' and result['cancellationRequested'] is False and
            result['cancellationMarkerConfirmed'] is False and result['failureType'] is None and
            result['failureLine'] is None and result['finalizationFailureType'] is None and
            result['phase'] == 'captured' and 0 <= result['elapsedMilliseconds'] < 300000 and
            result['scopedJobQuiescenceEstablished'] is False and result['noExperimentLive'] is False,
            'Original managed controller completion')
    started = decode(budget.read(root / 'managed-started.json', 8192)[0])
    require(started['schema'] == 'retained-windows-managed-started-v1' and
            started['authoritySha256'] == a['windowsAuthority']['sha256'] and
            type(started['pid']) is int and started['pid'] > 0 and started['pid'] != controller['rootPid'] and
            re.fullmatch(r'[1-9][0-9]{1,19}', started['creationFileTime']) and started['handleRetained'] is True and
            started['creationMode'] == 'ordinary-child-without-breakaway' and
            started['executable'] == roles['dotnet'], 'Original retained managed identity')
    invocation = decode(budget.read(root / 'managed-invocation.json', 32768)[0])
    require(invocation['schema'] == 'retained-windows-managed-invocation-v1' and
            invocation['authoritySha256'] == a['windowsAuthority']['sha256'] and
            invocation['executable'] == roles['dotnet'] and
            invocation['workingDirectory'] == windows_root_name(a) + '\\managed' and
            invocation['runnerSeconds'] == 240 and invocation['expectedExitCode'] == 0 and
            invocation['syntheticCharge'] == CHARGES[a['suite']] and
            invocation['deliberateWindowsStarts'] == CHARGES[a['suite']] + 1,
            'Original finite managed invocation')
    file_methods = ('ExplicitFilePreservesSelectedProfileAndRequest', 'FileSizeLimitAppliesBeforeAuthentication',
                    'ReplacingFileAfterAdmissionCannotChangeTheInFlightProfile',
                    'UnreadableOrInvalidFileStopsBeforeProviderConstruction')
    selectors = ['FullyQualifiedName=Authentication.Windows.Scenarios.ProfileFileScenarios.' + x for x in file_methods]
    selectors += ['FullyQualifiedName=Authentication.Windows.Scenarios.ProcessScenarios.' + x for x in PROCESS_CASES]
    expected_arguments = '"' + roles['runner'] + '" --native-profile-cases "' + roles['native'] + '"'
    if a['suite'] == 'cli':
        expected_arguments = ('"' + roles['runner'] + '" --native-cli-executable "' + roles['native'] +
                              '" --report-trx --results-directory "' + windows_root_name(a) +
                              '\\results" --filter "' + '|'.join(selectors) + '"')
    require(invocation['arguments'] == expected_arguments, 'Exact finite managed argv')
    environment = invocation['environment']
    require(environment['DOTNET_ROLL_FORWARD'] == 'Disable' and
            environment['TESTINGPLATFORM_TELEMETRY_OPTOUT'] == '1' and
            environment['DOTNET_CLI_TELEMETRY_OPTOUT'] == '1' and
            all(not key.startswith('TESTINGPLATFORM_') or key == 'TESTINGPLATFORM_TELEMETRY_OPTOUT'
                for key in environment), 'No external MTP runsettings/process-hook injection')
    captures = {}
    for name in ('stdout', 'stderr'):
        captures[name] = budget.read(root / ('managed.' + name + '.bin'), 8388608)[0]
        require(len(captures[name]) == result[name + 'Bytes'], 'Complete managed capture')
    require(sum(map(len, captures.values())) <= 8388608, 'Combined managed capture limit')
    if a['suite'] == 'profile':
        require(captures == {'stdout': b'', 'stderr': b''}, 'Finite Profile runner emits no success output')
    return {'pid': started['pid'], 'creationFileTime': started['creationFileTime'],
            'stdoutBytes': len(captures['stdout']), 'stderrBytes': len(captures['stderr'])}


def process_receipts(root, a, roles, budget):
    cases = tuple(PROCESS_CASES.values()) if a['suite'] == 'cli' else PROFILE_CASES
    temporary = root / 'temp'
    contents = names(temporary, 128, budget)
    require('process-safety-stop.json' not in contents and
            sorted(x for x in contents if x.startswith('process-')) == sorted('process-' + x for x in cases),
            'Exact process reservations and no safety stop')
    receipts = {}
    for case in cases:
        directory = temporary / ('process-' + case)
        reserved = decode(budget.read(directory / 'reserved.json', 8192)[0])
        started = decode(budget.read(directory / 'started.json', 16384)[0])
        receipt = decode(budget.read(directory / 'result.json', 8192)[0])
        native = case in ('help', 'malformed', *PROFILE_CASES)
        require(reserved.get('scenario') == case and type(started.get('pid')) is int and started['pid'] > 0 and
                started.get('executable') == roles['native' if native else 'dotnet'] and
                receipt.get('quiescent') is True and receipt.get('forced') is False and
                type(receipt.get('exitObservedTimestamp')) is int and receipt['exitObservedTimestamp'] > 0,
                'Process ownership and unforced completion')
        captures = {}
        for stream in ('stdout', 'stderr'):
            captures[stream] = budget.read(directory / (stream + '.bin'), 524288)[0]
            require(len(captures[stream]) == receipt.get(stream + 'Bytes'), 'Complete scenario capture')
        if not native:
            entered = int(budget.read(directory / 'entered', 32)[0].decode('ascii'))
            require(entered > 0 and receipt.get('entryTimestamp') == entered and
                    receipt['exitObservedTimestamp'] >= entered and receipt.get('timestampFrequency', 0) > 0,
                    'Controlled managed child entered')
        if a['suite'] == 'profile':
            validate_profile_case(case, directory, receipt, captures, budget)
        receipts[case] = receipt
    return receipts


def validate_profile_case(case, directory, receipt, captures, budget):
    # Native Profile cases are process evidence, never fabricated TRX rows.
    raw, _ = budget.read(directory / 'profile.json', 1024)
    require((len(raw), digest(raw)) == PROFILE_HASHES[case], 'Exact native Profile payload')
    output = captures['stdout']
    require(receipt['exitCode'] == 1 and captures['stderr'] == b'' and
            receipt.get('bufferedOutput') == 0 and receipt.get('diagnosticPrefill') == 0 and
            output.endswith(b'\n') and output.count(b'\n') == 1 and not output.startswith(b'\xef\xbb\xbf') and
            b'SYNTHETIC_NATIVE_PROFILE_SECRET' not in output, 'Safe native Profile terminal')
    value = decode(output)
    require(type(value.get('protocol')) is int and value == {'protocol': 1, 'outcome': 'invalid_request',
            'reason': 'invalid_configuration'}, 'Exact native Profile rejection')


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
    first = {key: result[key] for key in ('schema', 'stage', 'failureType')}
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
    result = {'schema': 'windows-retained-scenarios-worker-result-v1', 'passed': False,
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
        require(timing == {'schema': 'windows-retained-scenarios-service-intent-v1',
                'admissionSha256': digest(a['_raw']), 'originalStartNanoseconds': began,
                'originalDeadlineNanoseconds': deadline, 'serviceIntentNanoseconds': service_intent,
                'serviceDeadlineLowerBoundNanoseconds': service_deadline,
                'serviceRuntimeSeconds': 450, 'workerTerminalSeconds': 10}, 'Conservative service clock binding')
        roles, bindings, authority_raw = verify_admission(a, budget)
        started_raw, _ = budget.read(local / 'started.json', 65536)
        started = decode(started_raw)
        require(started['admissionSha256'] == digest(a['_raw']) and started['originalStartNanoseconds'] == began and
                started['originalDeadlineNanoseconds'] == deadline and
                budget.read(root / 'started.json', 65536)[0] == started_raw and
                budget.read(root / 'authority.json', 65536)[0] == authority_raw and
                budget.read(root / 'inventory.tsv', 65536)[0] == bindings and
                digest(budget.read(root / 'Invoke-WindowsNamedGuardFixtures.ps1', 65536)[0]) == a['controller']['sha256'],
                'Durable original binding')
        verify_deployment(a, root, local, budget)
        checkpoint(a, budget, reserved=True)
        command = [a['launcher']['path'], windows_root_name(a), a['nonce'],
                   a['windowsAuthority']['sha256'], a['controller']['sha256']]
        write_new(local / 'worker-started.json', encode({'schema': 'windows-retained-scenarios-worker-v1',
                  'cgroup': group.strip(), 'argv': command, 'admissionSha256': digest(a['_raw']),
                  'serviceIntentNanoseconds': service_intent,
                  'serviceDeadlineLowerBoundNanoseconds': service_deadline,
                  'workerWorkDeadlineNanoseconds': budget.deadline,
                  'workerTerminalDeadlineNanoseconds': budget.terminal_deadline}), budget)
        # 360 transport + 30 evidence must fit the earlier work deadline; its
        # already-withheld 10 terminal seconds also fit both enclosing clocks.
        budget.check(390_000_000_000)
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
        result['processReceipts'] = process_receipts(root, a, roles, budget)
        reports = names(root / 'results', 32, budget)
        if a['suite'] == 'cli':
            trx = [x for x in reports if x.endswith('.trx')]
            require(len(trx) == 1, 'One exact CLI TRX report')
            result['cli'] = validate_cli_report(budget.read(root / 'results' / trx[0], 1048576)[0])
        else:
            require(reports == [], 'Profile uses separate process evidence')
            result['profile'] = {'cases': list(PROFILE_CASES), 'passed': 2}
        result.update(passed=True, stage='worker-result-retention', scopedJobQuiescent=True)
        budget.enter_terminal()
        write_new(local / 'worker-result.json', encode(result), budget)
        return 0
    except BaseException as error:
        result.setdefault('failureType', type(error).__name__)
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
        started = {'schema': 'windows-retained-scenarios-started-v1', 'action': a['action'], 'suite': a['suite'],
                   'admissionSha256': digest(a['_raw']), 'before': before, 'charge': charge, 'after': after,
                   'originalStartNanoseconds': began, 'originalDeadlineNanoseconds': deadline,
                   'noExperimentLive': False, 'historicalLifetimeUnknown': HISTORICAL_UNKNOWN}
        reservation = encode(started)
        write_new(local / 'started.json', reservation, budget)
        direct(root.parent)
        root.mkdir(mode=0o700)
        write_new(root / 'started.json', reservation, budget)
        for name in ('temp', 'results', 'home', 'empty-program-files', 'managed', 'native'):
            (root / name).mkdir(mode=0o700)
        for name in ('roaming', 'local'):
            (root / 'home' / name).mkdir(mode=0o700)
        write_new(root / 'authority.json', authority_raw, budget)
        write_new(root / 'inventory.tsv', bindings, budget)
        write_new(root / 'Invoke-WindowsNamedGuardFixtures.ps1', budget.pin(a['controller'], 65536), budget)
        stage = 'original-materialization'
        materialize_inputs(a, root, local, budget)
        checkpoint(a, budget, reserved=True)
        # 450 service + 5 service termination + 5 transport slack + 15 original
        # evidence; original terminal 10 is withheld in budget.deadline already.
        budget.check(475_000_000_000)
        service_intent = time.monotonic_ns()
        service_deadline = service_intent + 450_000_000_000
        write_new(local / 'service-intent.json', encode({
            'schema': 'windows-retained-scenarios-service-intent-v1',
            'admissionSha256': digest(a['_raw']), 'originalStartNanoseconds': began,
            'originalDeadlineNanoseconds': deadline, 'serviceIntentNanoseconds': service_intent,
            'serviceDeadlineLowerBoundNanoseconds': service_deadline,
            'serviceRuntimeSeconds': 450, 'workerTerminalSeconds': 10}), budget)
        command = [a['systemdRun']['path'], '--user', '--no-ask-password', '--quiet', '--wait', '--pipe',
                   '--collect', '--expand-environment=no', '--job-mode=fail',
                   '--unit=' + unit_name(a), '--service-type=exec', '--property=ExitType=cgroup',
                   '--property=KillMode=control-group', '--property=Restart=no',
                   '--property=JobRunningTimeoutSec=2s', '--property=TimeoutStartSec=2s',
                   '--property=RuntimeMaxSec=450', '--property=TimeoutStopSec=5', '--property=SendSIGKILL=yes',
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
                            min(budget.deadline - 15_000_000_000, service_intent + 460_000_000_000), budget)
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
        write_new(local / 'original-result.json', encode({'schema': 'windows-retained-scenarios-original-result-v1',
                  'complete': True, 'action': a['action'], 'suite': a['suite'], 'admissionSha256': digest(a['_raw']),
                  'accounting': {'before': before, 'charge': charge, 'after': after},
                  'scopedJobQuiescent': True, 'noExperimentLive': False,
                  'historicalLifetimeUnknown': HISTORICAL_UNKNOWN, 'requiresIndependentOutcomeAcceptance': True}), budget)
        return 0
    except BaseException as error:
        if reserved_local:
            result = {'schema': 'windows-retained-scenarios-original-failure-v1',
                      'action': a['action'], 'admissionSha256': digest(a['_raw']),
                      'stage': stage, 'failureType': type(error).__name__, 'complete': False,
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
                service_deadline - service_intent == 450_000_000_000,
                'Single conservative service clock')
        terminal_deadline = min(service_deadline, deadline - 25_000_000_000)
        budget = Budget(began, terminal_deadline - 10_000_000_000, terminal_deadline)
    else:
        require(len(sys.argv) == 4, 'Original argv')
        began, deadline = entered, entered + 550_000_000_000
        budget = Budget(began, deadline - 10_000_000_000, deadline)
    require(deadline - began == 550_000_000_000, 'Single original clock')
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
        sys.stderr.write('Retained scenario original failed: ' + type(error).__name__ + '\n')
        sys.exit(1)
