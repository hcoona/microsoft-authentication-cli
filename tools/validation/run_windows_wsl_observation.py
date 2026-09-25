"""Inert retained-launcher calibration4/directWSL3 caller and dedicated cgroup worker.

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
CHARGES = {'calibration': 4, 'direct-wsl': 3}
JOB_TOTAL = {'calibration': 4, 'direct-wsl': 2}
ZERO = '0' * 64
PRODUCT_SHA = '02993d94c5145f32274a8763f27d632e2dcc8e6a06d257551b1501eed9689cc7'
MSAL_SHA = '9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79'
CANCELLED = b'{"protocol":1,"outcome":"cancelled","reason":"cancelled"}\n'
PARENTS = {'linuxActions': LINUX / 'actions', 'windowsActions': LINUX / 'windows-actions',
           'windowsProjectionActions': PROJECTION / 'actions', 'windowsProjectionRoot': PROJECTION}
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
    require(re.fullmatch(r'/tmp/windows-wsl-observation-[0-9]{4}-admission\.json', str(path)), 'Admission leaf')
    raw, full9 = budget.read(path, 65536)
    require(digest(raw) == expected, 'Original admission hash')
    value = decode(raw)
    require(set(value) == {'schema', 'action', 'suite', 'nonce', 'product', 'checkpoint', 'checkpointAcceptance',
                          'nativeAcceptance', 'buildAcceptance', 'sourceReview', 'exactCallReview', 'inventory',
                          'controller', 'windowsAuthority', 'caller', 'launcher', 'python', 'systemdRun',
                          'interop', 'runtimeDirectory', 'calibrationAcceptance', 'calibrationOutcome', 'observerSource', 'sessionGuid'},
            'Admission fields')
    require(value['schema'] == 'windows-wsl-observation-admission-v1' and value['product'] == PRODUCT and
            re.fullmatch(r'[0-9]{4}', value['action']) and int(value['action']) > 110 and
            value['suite'] in CHARGES and
            re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', value['nonce']), 'Admission identity')
    require(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
                         value['sessionGuid']), 'Fresh explicit trace session UUID')
    value['_raw'], value['_identity'], value['_path'] = raw, full9, str(path)
    return value


def acceptance(pin, schema, subjects, budget):
    value = decode(budget.pin(pin, 65536))
    require(value == {'schema': schema, 'accepted': True, 'subjects': subjects}, 'Independent acceptance binding')


def verify_admission(a, budget):
    acceptance(a['checkpointAcceptance'], 'windows-wsl-observation-checkpoint-acceptance-v1',
               {'checkpoint': a['checkpoint']}, budget)
    acceptance(a['sourceReview'], 'windows-wsl-observation-source-acceptance-v1',
               {'caller': a['caller'], 'launcher': a['launcher'], 'controller': a['controller'],
                'inventory': a['inventory'], 'observerSource': a['observerSource'], 'unchangedNormalLauncher': True,
                'exemptOuterPowerShellCount': 1, 'syntheticCharge': CHARGES[a['suite']],
                'expectedJobTotal': JOB_TOTAL[a['suite']], 'noUncountedWindowsStarts': True,
                'etwEffectsAccepted': True, 'inheritedWindowsRelayEnvironmentAccepted': True}, budget)
    acceptance(a['exactCallReview'], 'windows-wsl-observation-exact-call-acceptance-v1',
               {key: value for key, value in a.items() if key != 'exactCallReview' and not key.startswith('_')}, budget)
    if a['suite'] == 'direct-wsl':
        acceptance(a['nativeAcceptance'], 'windows-wsl-observation-native-acceptance-v1',
                   {'product': PRODUCT, 'inventory': a['inventory'], 'basis': 'original-0110-retained-candidate',
                    'snapshotManifestSha256': SNAPSHOT, 'originalPublicationPassed': False,
                    'snapshotCollectionAccepted': True, 'artifactAccepted': True,
                    'completeCompanionInventory': True}, budget)
    else:
        require(a['nativeAcceptance'] is None and a['calibrationAcceptance'] is None and
                a['calibrationOutcome'] is None, 'Control-only calibration')
    for key, maximum in (('caller', 131072), ('observerSource', 131072), ('controller', 65536), ('launcher', 8388608), ('python', 33554432),
                         ('systemdRun', 8388608)):
        budget.pin(a[key], maximum)
    require(Path(a['caller']['path']) == Path(__file__).absolute() and
            re.fullmatch(r'/usr/bin/python3\.[0-9]+', a['python']['path']) and
            a['systemdRun']['path'] == '/usr/bin/systemd-run', 'Original entry tools')
    require((a['launcher']['bytes'], a['launcher']['sha256']) == NORMAL_LAUNCHER, 'Retained normal launcher only')
    interop = a['interop']
    require(set(interop) == {'path', 'identity'} and re.fullmatch(r'/run/WSL/[0-9]{1,10}_interop', interop['path']),
            'Original WSL interop selector')
    sock = direct(Path(interop['path'])).lstat()
    require(stat.S_ISSOCK(sock.st_mode) and identity(sock) == interop['identity'], 'Original interop identity')
    runtime = a['runtimeDirectory']
    require(set(runtime) == {'path', 'identity'} and runtime['path'] == '/run/user/' + str(os.getuid()) and
            identity(direct(Path(runtime['path'])).lstat()) == runtime['identity'], 'User manager directory')
    inventory = decode(budget.pin(a['inventory'], 65536))
    require(set(inventory) == {'schema', 'files'} and inventory['schema'] == 'windows-wsl-observation-files-v1' and
            3 <= len(inventory['files']) <= 128, 'Complete deployment inventory')
    roles, hashes, paths, tsv = {}, {}, set(), []
    total = 0
    for item in inventory['files']:
        require(set(item) == {'role', 'windowsPath', 'descriptor', 'materialize'}, 'Inventory fields')
        role, path, pin = item['role'], item['windowsPath'], item['descriptor']
        require(role in ('observer', 'control-gated', 'control-fast', 'native', 'msalruntime', 'asset') and
                path.casefold() not in paths and item['materialize'] is True and
                set(pin) == {'path', 'bytes', 'sha256', 'identity'}, 'Inventory path/role')
        destination = project(path)
        relative = destination.relative_to(windows_root(a))
        require((len(relative.parts) == 1 and relative.name in ('observer.exe', 'control-gated.exe', 'control-fast.exe')) or
                (2 <= len(relative.parts) <= 8 and relative.parts[0] == 'native'), 'Fresh executable/companion path')
        paths.add(path.casefold())
        if role != 'asset':
            require(role not in roles, 'Duplicate entry role')
            roles[role], hashes[role] = path, pin['sha256']
        require(type(pin['bytes']) is int and 0 < pin['bytes'] <= 134217728 and
                re.fullmatch(r'[0-9a-f]{64}', pin['sha256']) and
                type(pin['identity']) is list and len(pin['identity']) == 9 and
                all(type(x) is int for x in pin['identity']), 'Bounded source descriptor')
        total += pin['bytes']
        require(total <= 536870912, 'Inventory aggregate size')
        tsv.append('\t'.join((role, path, str(pin['bytes']), pin['sha256'])))
    require(roles.get('observer') == windows_root_name(a) + r'\observer.exe', 'Observer deployment identity')
    if a['suite'] == 'calibration':
        require(set(roles) == {'observer', 'control-gated', 'control-fast'} and len(inventory['files']) == 3 and
                roles['control-gated'] == windows_root_name(a) + r'\control-gated.exe' and
                roles['control-fast'] == windows_root_name(a) + r'\control-fast.exe' and
                len(set(hashes.values())) == 1, 'Distinct-path same-artifact control topology')
    else:
        require(set(roles) == {'observer', 'native', 'msalruntime'} and
                roles['native'] == windows_root_name(a) + r'\native\azureauth.exe' and
                roles['msalruntime'] == windows_root_name(a) + r'\native\msalruntime.dll' and
                hashes['native'] == PRODUCT_SHA and hashes['msalruntime'] == MSAL_SHA, 'Native roles')
    acceptance(a['buildAcceptance'], 'windows-wsl-observer-build-acceptance-v1',
               {'observerSha256': hashes['observer'], 'observerSource': a['observerSource'],
                'frameworkCSharp5X64': True, 'references': ['mscorlib.dll', 'System.dll', 'System.Core.dll'],
                'sameObserverAndControlArtifact': True, 'noRestore': True}, budget)
    if a['suite'] == 'direct-wsl':
        budget.pin(a['calibrationOutcome'], 65536)
        acceptance(a['calibrationAcceptance'], 'windows-wsl-calibration-outcome-acceptance-v1',
                   {'observerSha256': hashes['observer'], 'observerSource': a['observerSource'],
                    'originalOutcome': a['calibrationOutcome'], 'retainedOriginalOutcome': True,
                    'gatePassed': True, 'fastAssociationPassed': True, 'traceStoppedAndDrained': True,
                    'zeroLoss': True, 'sameInstalledPlatformScope': True}, budget)
    bindings = ('\n'.join(tsv) + '\n').encode('utf-8')
    authority_raw = budget.pin(a['windowsAuthority'], 16384)
    authority = decode(authority_raw)
    require(authority == {
        'schema': 'wsl-observer-authority-v1', 'mode': a['suite'], 'root': windows_root_name(a),
        'nonce': a['nonce'], 'sessionGuid': a['sessionGuid'], 'observerSha256': hashes['observer'],
        'productSha256': PRODUCT_SHA if a['suite'] == 'direct-wsl' else ZERO,
        'msalruntimeSha256': MSAL_SHA if a['suite'] == 'direct-wsl' else ZERO,
        'artifactAcceptanceSha256': a['nativeAcceptance']['sha256'] if a['suite'] == 'direct-wsl' else ZERO,
        'calibrationAcceptanceSha256': a['calibrationAcceptance']['sha256'] if a['suite'] == 'direct-wsl' else ZERO,
        'inventorySha256': digest(bindings), 'controllerSha256': a['controller']['sha256']},
        'Exact flat-string observer authority')
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
    evidence = encode({'schema': 'windows-wsl-observation-deployment-v1',
                       'inventorySha256': a['inventory']['sha256'], 'files': deployed})
    write_new(local / 'deployment.json', evidence, budget)
    write_new(root / 'deployment.json', evidence, budget)


def verify_deployment(a, root, local, budget):
    raw = budget.read(local / 'deployment.json', 65536)[0]
    require(budget.read(root / 'deployment.json', 65536)[0] == raw, 'Original deployment receipt copies')
    deployment = decode(raw)
    inventory = decode(budget.pin(a['inventory'], 65536))
    require(deployment['schema'] == 'windows-wsl-observation-deployment-v1' and
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
    require(c['schema'] == 'windows-wsl-observation-current-checkpoint-v1' and c['nextAction'] == a['action'] and
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
            completed['totalProcesses'] == JOB_TOTAL[a['suite']] and
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


def product_arguments(a):
    root = windows_root_name(a)
    return [root + r'\native\azureauth.exe', 'authenticate', '--protocol', '1', '--profile',
            root + r'\gate-product.json', '--account-email', 'wsl-synthetic@example.invalid',
            '--scope', 'https://example.invalid/wsl-cancel', '--interaction', 'non-interactive-only',
            '--timeout-seconds', '4', '--cancel-on-stdin-close', '--telemetry', 'off']


def product_environment(a):
    root = windows_root_name(a)
    overlays = {'SystemRoot': r'C:\Windows', 'WINDIR': r'C:\Windows', 'SystemDrive': 'C:',
                'ComSpec': r'C:\Windows\System32\cmd.exe', 'OS': 'Windows_NT',
                'PROCESSOR_ARCHITECTURE': 'AMD64', 'PATH': r'C:\Windows\System32',
                'PROGRAMFILES': root + r'\empty-program-files',
                'PROGRAMFILES(X86)': root + r'\empty-program-files',
                'USERPROFILE': root + r'\home', 'APPDATA': root + r'\home\roaming',
                'LOCALAPPDATA': root + r'\home\local', 'TMP': root + r'\temp', 'TEMP': root + r'\temp'}
    # WSL BuildEnvironment starts with its Windows relay environment, then applies
    # these explicit overlays. This is NOT a full replacement Windows environment.
    return {**overlays, 'WSLENV': ':'.join(key + '/w' for key in sorted(overlays)),
            'WSL_INTEROP': a['interop']['path'], 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def flat_record(raw, schema, a):
    value = decode(raw)
    require(type(value) is dict and all(type(k) is str and type(v) is str for k, v in value.items()),
            'Observer flat string record')
    require(value.get('schema') == schema and value.get('mode') == a['suite'] and
            value.get('root') == windows_root_name(a) and value.get('nonce') == a['nonce'] and
            value.get('authoritySha256') == a['windowsAuthority']['sha256'] and
            re.fullmatch(r'[0-9]{1,6}', value.get('elapsedMilliseconds', '')), 'Original observer binding')
    return value


def readiness_record(raw, a):
    value = flat_record(raw, 'wsl-observer-readiness-v1', a)
    require(set(value) == {'schema', 'mode', 'root', 'nonce', 'authoritySha256', 'elapsedMilliseconds',
            'traceStarted', 'consumerThreadStarted', 'gateGranted', 'supportedVersions', 'deviceMappingSha256'} and
            all(value[k] == 'true' for k in ('traceStarted', 'consumerThreadStarted', 'gateGranted')) and
            value['supportedVersions'] == '3,4' and int(value['elapsedMilliseconds']) < 5000 and
            re.fullmatch(r'[0-9a-f]{64}', value['deviceMappingSha256']), 'Observer readiness gate')
    return value


def observation_transport(argv, a, root, local, deadline, budget):
    """One retained launcher and, only after readiness, one direct native interop."""
    budget.check()
    began = time.monotonic_ns()
    launcher = subprocess.Popen(argv, cwd=str(root), env=replacement_environment(a), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    processes = {'launcher': launcher}
    parts = {'launcher.stdout': bytearray(), 'launcher.stderr': bytearray(),
             'product.stdout': bytearray(), 'product.stderr': bytearray()}
    eof, ready_raw, product_result = set(), None, None
    failure, release_failure, persistence_failures = None, None, []
    ready_observed, product_before, product_after, first_lf, release_before, release_after = (None,) * 6
    release_reason = None
    product_completed = None
    drain_deadline = deadline
    launch_intent_written = False
    polls = 0
    next_readiness_poll = began
    with selectors.DefaultSelector() as selection:
        def attach(name, process):
            for stream_name in ('stdout', 'stderr'):
                stream = getattr(process, stream_name)
                os.set_blocking(stream.fileno(), False)
                selection.register(stream, selectors.EVENT_READ, name + '.' + stream_name)
        def release(reason):
            nonlocal release_failure, release_reason, release_before, release_after
            if release_reason is not None:
                return
            release_reason, release_before = reason, time.monotonic_ns()
            try:
                write_new(root / 'release.marker', b'', budget)
                release_after = time.monotonic_ns()
            except BaseException as error:
                release_failure = type(error).__name__
        def fail(kind):
            nonlocal failure, drain_deadline
            if failure is None:
                failure = kind
                drain_deadline = min(deadline, time.monotonic_ns() + 40_000_000_000)
                # Never wait for EOF, an exit event or an oplock break before release.
                if a['suite'] == 'direct-wsl':
                    release('error')
        attach('launcher', launcher)
        try:
            while True:
                polls += 1
                if polls > 15000:
                    fail('ObservationPollBound')
                    break
                now = time.monotonic_ns()
                if now >= min(deadline, drain_deadline):
                    fail('ObservationTransportDeadline')
                    break
                try:
                    budget.check()
                    if failure is None and ready_raw is None and now >= next_readiness_poll:
                        next_readiness_poll = now + 50_000_000
                        try:
                            raw, _ = budget.read(root / 'readiness.json', 8192)
                        except FileNotFoundError:
                            raw = None
                        if raw is not None:
                            readiness_record(raw, a)
                            ready_raw, ready_observed = raw, time.monotonic_ns()
                        elif now - began >= 45_000_000_000 or launcher.poll() is not None:
                            fail('ReadinessUnavailable')
                    if failure is None and a['suite'] == 'direct-wsl' and ready_raw is not None and 'product' not in processes:
                        args = product_arguments(a)
                        require(all(token.isascii() and not any(c.isspace() or c == '"' for c in token)
                                    for token in args), 'Exact whitespace-free direct argv')
                        environment = product_environment(a)
                        write_new(local / 'direct-invocation.json', encode({'argv': args,
                            'executable': str(project(args[0])), 'environment': environment,
                            'windowsEnvironment': 'inherited-relay-baseline-with-listed-overlays',
                            'linuxClosedPipeBeforePopen': True, 'nativePrecreationClosureClaimed': False}), budget)
                        intent = {'schema': 'wsl-product-launch-intent-v1', 'root': windows_root_name(a),
                                  'nonce': a['nonce'], 'authoritySha256': a['windowsAuthority']['sha256'],
                                  'readinessSha256': digest(ready_raw), 'productPath': args[0],
                                  'productCommandLine': ' '.join(args), 'expectedExit': '1'}
                        write_new(root / 'product-launch-intent.json', encode(intent), budget, 8192)
                        launch_intent_written = True
                        require(time.monotonic_ns() - ready_observed < 2_000_000_000,
                                'Readiness-to-launch preparation deadline')
                        read_end, write_end = os.pipe2(os.O_CLOEXEC)
                        try:
                            os.close(write_end)
                            # Explicit distinct Windows argv0 survives the public WSL
                            # binfmt route. executable selects the Linux projection.
                            product_before = time.monotonic_ns()
                            processes['product'] = subprocess.Popen(args=args, executable=str(project(args[0])),
                                cwd=str(root), env=environment, stdin=read_end, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, close_fds=True)
                            product_after = time.monotonic_ns()
                        finally:
                            os.close(read_end)
                        attach('product', processes['product'])
                    if failure is None and 'product' in processes:
                        product_done = processes['product'].poll() is not None and \
                            {'product.stdout', 'product.stderr'} <= eof
                        if not product_done and now - product_before >= 6_000_000_000:
                            fail('ProductProxyDeadline')
                    for key, _ in selection.select(0.025):
                        name = key.data
                        if name.startswith('launcher.'):
                            remaining = 16384 - len(parts['launcher.stdout']) - len(parts['launcher.stderr'])
                        else:
                            remaining = 524288 - len(parts[name])
                        block = os.read(key.fileobj.fileno(), min(4096, remaining + 1))
                        if not block:
                            eof.add(name)
                            selection.unregister(key.fileobj)
                            continue
                        parts[name].extend(block[:remaining])
                        if name == 'product.stdout' and first_lf is None and b'\n' in parts[name]:
                            first_lf = time.monotonic_ns()
                            # This precedes line validation, EOF, proxy/native exit,
                            # ETW END and any held-break requirement.
                            release('first-lf')
                            if release_failure is not None:
                                fail('ReleaseMarkerFailure')
                            if parts[name].index(10) >= 4096:
                                fail('FirstLineBound')
                        if len(block) > remaining:
                            fail('CaptureOverflow')
                            selection.unregister(key.fileobj)
                            key.fileobj.close()
                        if name == 'product.stderr' and block:
                            fail('UnexpectedProductDiagnostics')
                        if name == 'product.stdout' and first_lf is None and len(parts[name]) >= 4096:
                            fail('FirstLineBound')
                    if 'product' in processes and product_completed is None and \
                            processes['product'].poll() is not None and {'product.stdout', 'product.stderr'} <= eof:
                        product_completed = time.monotonic_ns()
                    done = all(process.poll() is not None and {name + '.stdout', name + '.stderr'} <= eof
                               for name, process in processes.items())
                    if done and (failure is not None or a['suite'] == 'calibration' or 'product' in processes):
                        break
                except BaseException as error:
                    fail(type(error).__name__)
                    # A failed budget cannot authorize continued drain or reads.
                    try:
                        budget.check()
                    except BaseException:
                        break
        finally:
            if a['suite'] == 'direct-wsl' and release_reason is None:
                release('error' if failure else 'missing-first-lf')
            for process in processes.values():
                for stream in (process.stdout, process.stderr):
                    if not stream.closed:
                        stream.close()
    launcher_result = {'pid': launcher.pid, 'exitCode': launcher.poll(),
        'eof': sorted(name.split('.')[1] for name in eof if name.startswith('launcher.')),
        'failure': None, 'cancelFailure': None,
        'stdout': base64.b64encode(parts['launcher.stdout']).decode('ascii'),
        'stderr': base64.b64encode(parts['launcher.stderr']).decode('ascii')}
    if 'product' in processes:
        product = processes['product']
        product_result = {'linuxProxyPid': product.pid, 'exitCode': product.poll(),
            'eof': sorted(name.split('.')[1] for name in eof if name.startswith('product.')),
            'launchBeforeNanoseconds': product_before, 'launchAfterNanoseconds': product_after,
            'proxyCompletedNanoseconds': product_completed,
            'firstLfNanoseconds': first_lf, 'releaseBeforeNanoseconds': release_before,
            'releaseAfterNanoseconds': release_after, 'releaseReason': release_reason,
            'stdoutBytes': len(parts['product.stdout']), 'stderrBytes': len(parts['product.stderr']),
            'linuxClosedPipeBeforePopen': True, 'nativePrecreationClosureClaimed': False}
        if failure is None and (product.poll() != 1 or product_result['eof'] != ['stderr', 'stdout'] or
                bytes(parts['product.stdout']) != CANCELLED or parts['product.stderr'] or
                release_reason != 'first-lf' or release_failure is not None or product_completed is None or
                product_completed - product_before >= 6_000_000_000):
            failure = 'ProductContractOrLifetimeIncomplete'
        for stream in ('stdout', 'stderr'):
            try:
                write_new(local / ('direct.' + stream + '.bin'), bytes(parts['product.' + stream]), budget, 524288)
            except BaseException as error:
                persistence_failures.append(type(error).__name__)
                failure = failure or 'ProductCaptureRetention'
    if ready_raw is None:
        failure = failure or 'ReadinessUnavailable'
    if a['suite'] == 'direct-wsl' and product_result is None:
        failure = failure or 'ProductNotStarted'
    return {'failure': failure, 'releaseFailure': release_failure, 'persistenceFailures': persistence_failures,
            'launcher': launcher_result, 'product': product_result, 'launchIntentWritten': launch_intent_written,
            'readinessSha256': digest(ready_raw) if ready_raw is not None else None,
            'readinessObservedNanoseconds': ready_observed,
            'traceClosureClaimedByLinuxProxy': False, 'noExperimentLive': False}


def observer_evidence(root, a, roles, budget, controller, capture):
    result = decode(budget.read(root / 'observer-controller-result.json', 32768)[0])
    require(result['schema'] == 'retained-wsl-controller-result-v1' and
            result['authoritySha256'] == a['windowsAuthority']['sha256'] and result['mode'] == a['suite'] and
            all(result[k] is True for k in ('passed', 'observerProcessStarted', 'observerHandleRetained',
                                           'observerExited', 'stdoutEof', 'stderrEof')) and
            result['exitCode'] == 0 and result['captureDisposition'] == 'complete' and
            all(result[k] is False for k in ('cancellationRequested', 'cancellationMarkerConfirmed',
                                            'scopedJobQuiescenceEstablished', 'noExperimentLive')) and
            all(result[k] is None for k in ('failureType', 'failureLine', 'finalizationFailureType')) and
            result['phase'] == 'captured' and 0 <= result['elapsedMilliseconds'] < 90000 and
            0 <= result['observerElapsedMilliseconds'] < 40000, 'Observer controller completion')
    require(budget.read(root / 'observer.stdout.bin', 16384)[0] == b'' and
            budget.read(root / 'observer.stderr.bin', 16384)[0] == b'' and
            result['stdoutBytes'] == result['stderrBytes'] == 0, 'Empty complete observer capture')
    started = decode(budget.read(root / 'observer-started.json', 8192)[0])
    require(started['schema'] == 'retained-wsl-observer-started-v1' and
            started['authoritySha256'] == a['windowsAuthority']['sha256'] and
            type(started['pid']) is int and started['pid'] > 0 and started['pid'] != controller['rootPid'] and
            re.fullmatch(r'[1-9][0-9]{1,19}', started['creationFileTime']) and
            started['handleRetained'] is True and started['creationMode'] == 'ordinary-child-without-breakaway' and
            started['executable'] == roles['observer'], 'Original retained observer handle')
    invocation = decode(budget.read(root / 'observer-invocation.json', 32768)[0])
    expected_args = '--mode ' + a['suite'] + ' --root "' + windows_root_name(a) + '" --authority-sha256 ' + a['windowsAuthority']['sha256']
    require(invocation['schema'] == 'retained-wsl-observer-invocation-v1' and
            invocation['authoritySha256'] == a['windowsAuthority']['sha256'] and
            invocation['executable'] == roles['observer'] and invocation['arguments'] == expected_args and
            invocation['workingDirectory'] == windows_root_name(a) and invocation['observerSeconds'] == 30 and
            invocation['transportSeconds'] == 40 and invocation['controllerSeconds'] == 90 and
            invocation['expectedExitCode'] == 0 and invocation['syntheticCharge'] == CHARGES[a['suite']] and
            invocation['deliberateWindowsStarts'] == CHARGES[a['suite']] + 1 and
            invocation['expectedJobTotalProcesses'] == JOB_TOTAL[a['suite']], 'Finite observer invocation')
    raw = budget.read(root / 'readiness.json', 8192)[0]
    ready = readiness_record(raw, a)
    require(digest(raw) == capture['readinessSha256'], 'Same original readiness')
    final = flat_record(budget.read(root / 'final.json', 8192)[0], 'wsl-observer-final-v1', a)
    common = {'schema', 'mode', 'root', 'nonce', 'authoritySha256', 'elapsedMilliseconds', 'passed', 'failure',
              'resourceUncertain', 'intentAccepted', 'releaseSeen', 'readinessPublished', 'gateGranted',
              'gateHeldBreak', 'gateReleased', 'gateCompleted', 'traceStopped', 'consumerCompleted',
              'eventsLost', 'logBuffersLost', 'realTimeBuffersLost', 'callbacks', 'artifactAccepted', 'continuationAllowed'}
    suffixes = ('Starts', 'Ends', 'Pid', 'Exit', 'StartQpc', 'EndQpc', 'PointerBytes', 'Version', 'HandleOpened',
                'CreationFileTime', 'HandleSignaled', 'Forced', 'ObjectKeySha256', 'ObjectKeyNonzero',
                'CreationHandle', 'LateHandleAttempted', 'CreationPidMatched', 'ExpectedImageSha256', 'ExpectedCommandSha256')
    child_suffixes = ('InputClosed', 'FirstLf', 'StreamsEnded', 'StreamError', 'ExactOutput', 'StdoutBytes', 'StderrBytes')
    target_roles = ('gated', 'fast') if a['suite'] == 'calibration' else ('product',)
    expected_keys = common | {role + suffix for role in target_roles for suffix in suffixes}
    if a['suite'] == 'calibration':
        expected_keys |= {role + suffix for role in target_roles for suffix in child_suffixes}
    require(set(final) == expected_keys and int(final['elapsedMilliseconds']) < 40000 and
            all(final[k] == 'true' for k in ('passed', 'readinessPublished', 'gateGranted', 'gateReleased',
                                          'gateCompleted', 'traceStopped', 'consumerCompleted')) and
            all(final[k] == 'false' for k in ('resourceUncertain', 'artifactAccepted', 'continuationAllowed')) and
            final['failure'] == 'none' and
            all(final[k] == '0' for k in ('eventsLost', 'logBuffersLost', 'realTimeBuffersLost')) and
            re.fullmatch(r'[0-9]{1,5}', final['callbacks']) and 1 <= int(final['callbacks']) <= 65536,
            'Original observer resource closure and zero-loss outcome')
    for role in target_roles:
        for field in ('Starts', 'Ends', 'Pid', 'StartQpc', 'EndQpc', 'CreationFileTime'):
            require(re.fullmatch(r'[0-9]{1,20}', final[role + field]), 'Target numeric field')
        require(final[role + 'Starts'] == final[role + 'Ends'] == '1' and int(final[role + 'Pid']) > 0 and
                0 < int(final[role + 'StartQpc']) <= int(final[role + 'EndQpc']) and
                final[role + 'Exit'] == ('1' if role == 'product' else '0') and
                final[role + 'PointerBytes'] == '8' and final[role + 'Version'] in ('3', '4') and
                final[role + 'Forced'] == 'false' and final[role + 'ObjectKeyNonzero'] == 'true' and
                re.fullmatch(r'[0-9a-f]{64}', final[role + 'ObjectKeySha256']), 'Exact matching target START/END')
        if role == 'product':
            image = product_arguments(a)[0]
            command = ' '.join(product_arguments(a))
            require(final['productCreationHandle'] == final['productCreationPidMatched'] == 'false' and
                    final['productHandleOpened'] in ('true', 'false') and
                    final['productLateHandleAttempted'] in ('true', 'false'), 'Direct product association path')
            if final['productHandleOpened'] == 'true':
                require(final['productHandleSignaled'] == 'true' and int(final['productCreationFileTime']) > 0,
                        'Retained direct product handle completion')
        else:
            image = windows_root_name(a) + '\\control-' + role + '.exe'
            command = '"' + image + '" --control-' + role + ' "' + windows_root_name(a) + '" ' + a['nonce']
            if role == 'gated':
                command += ' gate-calibration.json'
            require(all(final[role + suffix] == 'true' for suffix in ('CreationHandle', 'CreationPidMatched',
                        'HandleOpened', 'HandleSignaled', 'InputClosed', 'FirstLf', 'StreamsEnded', 'ExactOutput')) and
                    final[role + 'StreamError'] == 'false' and final[role + 'StderrBytes'] == '0',
                    'Independent creation-handle control ground truth')
            expected_line = ('{"protocol":1,"control":"' + role + '","outcome":"' +
                             ('cancelled' if role == 'gated' else 'completed') + '"}\n').encode('ascii')
            require(final[role + 'StdoutBytes'] == str(len(expected_line)), 'Exact control output length')
            if role == 'fast':
                require(final['fastLateHandleAttempted'] == 'false', 'Event-only fast association')
        require(final[role + 'ExpectedImageSha256'] == digest(image.encode('utf-8')) and
                final[role + 'ExpectedCommandSha256'] == digest(command.encode('utf-8')), 'Exact image and command binding')
    if a['suite'] == 'calibration':
        require(final['gateHeldBreak'] == 'true' and final['intentAccepted'] == final['releaseSeen'] == 'false' and
                capture['product'] is None and capture['launchIntentWritten'] is False, 'Control-only calibration')
    else:
        require(final['intentAccepted'] == final['releaseSeen'] == 'true' and
                final['gateHeldBreak'] in ('true', 'false'), 'Direct gate permits no-break cancellation')
        direct_result = capture['product']
        require(direct_result['exitCode'] == 1 and direct_result['eof'] == ['stderr', 'stdout'] and
                direct_result['releaseReason'] == 'first-lf' and
                direct_result['launchBeforeNanoseconds'] <= direct_result['launchAfterNanoseconds'] <=
                direct_result['firstLfNanoseconds'] <= direct_result['releaseBeforeNanoseconds'] <=
                direct_result['releaseAfterNanoseconds'] <= direct_result['proxyCompletedNanoseconds'] and
                direct_result['proxyCompletedNanoseconds'] - direct_result['launchBeforeNanoseconds'] < 6_000_000_000 and
                direct_result['linuxClosedPipeBeforePopen'] is True and
                direct_result['nativePrecreationClosureClaimed'] is False and
                budget.read(local_root(a) / 'direct.stdout.bin', 524288)[0] == CANCELLED and
                budget.read(local_root(a) / 'direct.stderr.bin', 524288)[0] == b'', 'Direct cancellation protocol and release order')
    return {'observerPid': started['pid'], 'observerCreationFileTime': started['creationFileTime'],
            'readiness': ready, 'final': final, 'independentOutcomeAcceptanceRequired': True}


def local_root(a):
    return LINUX / 'windows-actions' / a['action']


def unit_name(a):
    return 'azureauth-wsl-observation-108-' + a['action'] + '-' + a['nonce'] + '.service'


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
    result = {'schema': 'windows-wsl-observation-worker-result-v1', 'passed': False,
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
        require(timing == {'schema': 'windows-wsl-observation-service-intent-v1',
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
        gate = 'gate-calibration.json' if a['suite'] == 'calibration' else 'gate-product.json'
        require(budget.read(root / gate, 2)[0] == b'{}', 'Exact inert Profile gate before launch')
        checkpoint(a, budget, reserved=True)
        command = [a['launcher']['path'], windows_root_name(a), a['nonce'],
                   a['windowsAuthority']['sha256'], a['controller']['sha256']]
        write_new(local / 'worker-started.json', encode({'schema': 'windows-wsl-observation-worker-v1',
                  'cgroup': group.strip(), 'argv': command, 'admissionSha256': digest(a['_raw']),
                  'serviceIntentNanoseconds': service_intent,
                  'serviceDeadlineLowerBoundNanoseconds': service_deadline,
                  'workerWorkDeadlineNanoseconds': budget.deadline,
                  'workerTerminalDeadlineNanoseconds': budget.terminal_deadline}), budget)
        # 360 transport + 30 evidence must fit the earlier work deadline; its
        # already-withheld 10 terminal seconds also fit both enclosing clocks.
        budget.check(390_000_000_000)
        result['stage'] = 'native-launch'
        capture = observation_transport(command, a, root, local,
                                        min(budget.deadline - 30_000_000_000,
                                            time.monotonic_ns() + 360_000_000_000), budget)
        result['observation'] = capture
        if capture['failure'] is not None:
            result['failureType'] = capture['failure']
        write_new(local / 'observation-transport.json', encode(capture), budget)
        require(capture['failure'] is None and capture['releaseFailure'] is None,
                'Original observation transport failed')
        exact_transport(capture['launcher'])
        budget.deadline = min(budget.deadline, time.monotonic_ns() + 30_000_000_000)
        result['stage'] = 'original-evidence'
        stdout = budget.read(root / 'launcher.stdout.bin', 16384)[0]
        stderr = budget.read(root / 'launcher.stderr.bin', 16384)[0]
        require(stdout == b'' and stderr == b'', 'Empty successful observer controller transport')
        result['controller'] = validate_journal(budget.read(root / 'launcher.jsonl', 65536)[0], a, stdout, stderr)
        result['observer'] = observer_evidence(root, a, roles, budget, result['controller'], capture)
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
        started = {'schema': 'windows-wsl-observation-started-v1', 'action': a['action'], 'suite': a['suite'],
                   'admissionSha256': digest(a['_raw']), 'before': before, 'charge': charge, 'after': after,
                   'originalStartNanoseconds': began, 'originalDeadlineNanoseconds': deadline,
                   'noExperimentLive': False, 'historicalLifetimeUnknown': HISTORICAL_UNKNOWN}
        reservation = encode(started)
        write_new(local / 'started.json', reservation, budget)
        direct(root.parent)
        root.mkdir(mode=0o700)
        write_new(root / 'started.json', reservation, budget)
        for name in ('temp', 'home', 'empty-program-files', 'native'):
            (root / name).mkdir(mode=0o700)
        for name in ('roaming', 'local'):
            (root / 'home' / name).mkdir(mode=0o700)
        write_new(root / 'authority.json', authority_raw, budget)
        write_new(root / 'inventory.tsv', bindings, budget)
        write_new(root / 'Invoke-WindowsNamedGuardFixtures.ps1', budget.pin(a['controller'], 65536), budget)
        stage = 'original-materialization'
        materialize_inputs(a, root, local, budget)
        gate = 'gate-calibration.json' if a['suite'] == 'calibration' else 'gate-product.json'
        write_new(root / gate, b'{}', budget)
        checkpoint(a, budget, reserved=True)
        # 450 service + 5 service termination + 5 transport slack + 15 original
        # evidence; original terminal 10 is withheld in budget.deadline already.
        budget.check(475_000_000_000)
        service_intent = time.monotonic_ns()
        service_deadline = service_intent + 450_000_000_000
        write_new(local / 'service-intent.json', encode({
            'schema': 'windows-wsl-observation-service-intent-v1',
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
        write_new(local / 'original-result.json', encode({'schema': 'windows-wsl-observation-original-result-v1',
                  'complete': True, 'action': a['action'], 'suite': a['suite'], 'admissionSha256': digest(a['_raw']),
                  'accounting': {'before': before, 'charge': charge, 'after': after},
                  'scopedJobQuiescent': True, 'noExperimentLive': False,
                  'historicalLifetimeUnknown': HISTORICAL_UNKNOWN, 'requiresIndependentOutcomeAcceptance': True}), budget)
        return 0
    except BaseException as error:
        if reserved_local:
            result = {'schema': 'windows-wsl-observation-original-failure-v1',
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
