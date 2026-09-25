"""INERT PROPOSAL: one separately admitted Linux compilation of the WSL observer.

This is a prospective helper. An accepted protocol and independent exact-call
admission are required; invoking this file cannot grant either prerequisite.
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import uuid

EXECUTION_ADMITTED = False
SLOTS = ('primary', 'c1-a', 'c1-b', 'c2-a', 'c2-b', 'c3-a', 'c3-b')
ROOT = CHARGE = FINAL = None
SLOT = None
SDK_ROOT = Path('/home/shuaizhang/.local/share/mise/http-tarballs/febf8b0ab0361bac936d0b20567a85f89e667d4f4ff0067e0ed9a9f58ae45e28')
SDK_PINS = {'dotnet': {'bytes': 71808, 'sha256': '01d89e0a0191052bfea616cd4ce624c8faf13b05bbddf7f64499c23e2a9d9269'}, 'sdk/10.0.401/Roslyn/bincore/Microsoft.CodeAnalysis.CSharp.dll': {'bytes': 19758376, 'sha256': 'be9abcea80916e2022dd5ab3428ba4413454a46ea77cee45730987552e9328f1'}, 'sdk/10.0.401/Roslyn/bincore/Microsoft.CodeAnalysis.dll': {'bytes': 8466768, 'sha256': 'aeb569d31340ad9db97a185f8c9d376382add37afed215b495c72044c57f1824'}, 'sdk/10.0.401/Roslyn/bincore/csc.deps.json': {'bytes': 5789, 'sha256': 'bb3c7c6cde340201441d3d06bb1eef2b29ae24ab7f5d3e655be735516b568b03'}, 'sdk/10.0.401/Roslyn/bincore/csc.dll': {'bytes': 141096, 'sha256': '28a84f96c8d4c768fd3b620b3e312c281316d3392390b609b03dd9356ae098df'}, 'sdk/10.0.401/Roslyn/bincore/csc.runtimeconfig.json': {'bytes': 391, 'sha256': '29a1fe16a1a2c5728b1b526fe1e273e5978049946cfd6b70c26617bb05e992cb'}, 'shared/Microsoft.NETCore.App/10.0.12/System.Private.CoreLib.dll': {'bytes': 15576872, 'sha256': '26304a2985357b9ee277f273667fcd9c892edae3ee6eba76f739033e95eb39b3'}}
FRAMEWORK = Path('/mnt/c/Windows/Microsoft.NET/Framework64/v4.0.30319')
BEFORE = AFTER = None
FRAMEWORK_PINS = {
    'mscorlib.dll': '5bffb20e1217bad314143d7e5c4c809bf9f522e8a0a063c8e7e9b25113de26eb',
    'System.dll': '2b3c17c6208a0b4b6beb94e1a066f99ba06cdb2ea919479e99d47e8c6d96dc71',
    'System.Core.dll': 'fd1097aed825d392a5dc8d19384381d4bb2a43498ea1c9d917f5d80c66600e1b',
}


def select_slot(slot):
    global ROOT, CHARGE, FINAL, SLOT
    if slot not in SLOTS:
        raise ValueError('Unallocated observer build slot')
    SLOT = slot
    ROOT = Path('/var/tmp/azureauth-windows-slice-108/windows-actions/wsl-observer-build-' + slot)
    CHARGE = Path('/tmp/windows-wsl-observer-build-' + slot + '-original-charge.json')
    FINAL = Path('/tmp/windows-wsl-observer-build-' + slot + '-original-result.json')


def configure(config):
    global BEFORE, AFTER
    keys = {'schema', 'slot', 'acceptedCommit', 'candidateCommit', 'candidateTree',
            'waveSha256', 'protocolSha256', 'observerReviewSha256', 'buildReviewSha256',
            'sourcePath', 'sourceSha256', 'runnerSha256', 'countsBefore', 'countsAfter',
            'hostPreparationBefore', 'hostPreparationAfter'}
    if set(config) not in (keys, keys | {'unit'}):
        raise ValueError('Configuration keys')
    if config['schema'] != 'windows-wsl-observer-build-v1':
        raise ValueError('Configuration schema')
    select_slot(config['slot'])
    for key in ('acceptedCommit', 'candidateCommit', 'candidateTree'):
        if not isinstance(config[key], str) or len(config[key]) != 40 or any(c not in '0123456789abcdef' for c in config[key]):
            raise ValueError('Configuration commit pin')
    for key in ('waveSha256', 'protocolSha256', 'observerReviewSha256', 'buildReviewSha256', 'sourceSha256', 'runnerSha256'):
        if not isinstance(config[key], str) or len(config[key]) != 64 or config[key] == '0' * 64 or any(c not in '0123456789abcdef' for c in config[key]):
            raise ValueError('Configuration source or review pin')
    if config['sourcePath'] != '/tmp/windows-wsl-observer-build-' + SLOT + '-activated-source.cs':
        raise ValueError('Nonliteral observer source path')
    BEFORE, AFTER = config['countsBefore'], config['countsAfter']
    if not isinstance(BEFORE, list) or not isinstance(AFTER, list) or len(BEFORE) != 4 or len(AFTER) != 4 or any(type(n) is not int or n < 0 for n in BEFORE + AFTER):
        raise ValueError('Category counts')
    if AFTER != [BEFORE[0] + 1, *BEFORE[1:]] or AFTER[0] > 35:
        raise ValueError('Preparation debit')
    before, after = config['hostPreparationBefore'], config['hostPreparationAfter']
    if not isinstance(before, dict) or not isinstance(after, dict) or set(before) != {'linux', 'windows'} or set(after) != {'linux', 'windows'}:
        raise ValueError('Host preparation keys')
    for host, ceiling in (('linux', 18), ('windows', 17)):
        for counts in (before[host], after[host]):
            if not isinstance(counts, list) or len(counts) != 2 or any(type(n) is not int for n in counts) or counts[1] != ceiling or not 0 <= counts[0] <= ceiling:
                raise ValueError('Host preparation ceiling')
    if after['linux'][0] != before['linux'][0] + 1 or after['windows'] != before['windows'] or before['linux'][0] + before['windows'][0] != BEFORE[0] or after['linux'][0] + after['windows'][0] != AFTER[0]:
        raise ValueError('Host preparation debit')
    if SLOT == 'primary' and (BEFORE != [20, 106, 6, 163] or before != {'linux': [11, 18], 'windows': [9, 17]}):
        raise ValueError('Primary preparation baseline')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def direct(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Nonliteral path')
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError('Linked input or output')
    return path


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path, maximum, expected=None):
    path = direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise ValueError('Input type or size')
        raw = stream.read(maximum + 1)
        if len(raw) != before.st_size or identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError('Input changed during read')
        if identity(before) != identity(path.lstat()):
            raise ValueError('Named input changed')
    if expected is not None and digest(raw) != expected:
        raise ValueError('Input hash mismatch')
    return raw


def write(path, raw):
    path = direct(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return digest(raw)


def budget(deadline_ns, reserve_ns=0):
    if time.monotonic_ns() >= deadline_ns - reserve_ns:
        raise TimeoutError('Original action deadline')


def own_virtual(path, maximum):
    # Kernel virtual files have no useful regular-file length; cap the actual read.
    with open(path, 'rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('Own-process metadata limit')
    return raw.decode('ascii')


def capture(command, environment, deadline_ns, maximum, output):
    """Preserve sampled process state independently from fallible persistence."""
    process = None
    observed = bytearray()
    report = {'exitCode': None, 'eof': False, 'failure': None,
              'observedBytes': 0, 'savedBytes': None, 'sha256': None,
              'persistenceFailure': None, 'partialFileState': 'not-attempted'}
    try:
        budget(deadline_ns, 2000000000)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=environment, cwd=ROOT)
        os.set_blocking(process.stdout.fileno(), False)
        while time.monotonic_ns() < deadline_ns - 2000000000:
            if not report['eof']:
                try:
                    chunk = os.read(process.stdout.fileno(), min(4096, maximum - len(observed) + 1))
                except BlockingIOError:
                    chunk = None
                if chunk == b'':
                    report['eof'] = True
                elif chunk:
                    observed.extend(chunk)
                    if len(observed) > maximum:
                        raise ValueError('Output limit exceeded')
            report['exitCode'] = process.poll()
            if report['exitCode'] is not None and report['eof']:
                break
            time.sleep(0.025)
        if report['exitCode'] is None or not report['eof']:
            raise TimeoutError('Process or output deadline')
    except BaseException as error:
        report['failure'] = type(error).__name__
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                    left = max(0, deadline_ns - time.monotonic_ns()) / 1000000000
                    process.wait(timeout=min(2, left))
                report['exitCode'] = process.poll()
            except BaseException as error:
                report['failure'] = report['failure'] or type(error).__name__
            try:
                process.stdout.close()
            except BaseException as error:
                report['failure'] = report['failure'] or type(error).__name__
        report['observedBytes'] = len(observed)
        # Failed write/flush/close leaves an unknown file prefix; never retry it.
        raw = bytes(observed[:maximum])
        report['partialFileState'] = 'unknown'
        try:
            saved_hash = write(output, raw)
            report.update(savedBytes=len(raw), sha256=saved_hash, partialFileState='complete')
        except BaseException as error:
            report['persistenceFailure'] = type(error).__name__
            report['failure'] = report['failure'] or type(error).__name__
    return report


def worker(config_hash, expires_ns):
    if time.monotonic_ns() >= expires_ns:
        raise TimeoutError('Queued worker expired')
    config = json.loads(read(ROOT / 'config.json', 65536, config_hash))
    if config['slot'] != SLOT:
        raise ValueError('Worker slot mismatch')
    configure(config)
    groups = [line[3:] for line in own_virtual('/proc/self/cgroup', 4096).splitlines()
              if line.startswith('0::')]
    if len(groups) != 1 or Path(groups[0]).name != config['unit']:
        raise ValueError('Worker is not in its original named cgroup')
    fields = own_virtual('/proc/self/stat', 4096).rsplit(')', 1)[1].split()
    write(ROOT / 'worker-start.json', encode({'pid': os.getpid(), 'startTicks': int(fields[19]),
                                             'cgroup': groups[0], 'configSha256': config_hash}))
    result = {'passed': False, 'failure': None, 'compiler': None, 'artifact': None}
    try:
        read(Path(__file__), 65536, config['runnerSha256'])
        sdk = direct(SDK_ROOT)
        for relative, pin in SDK_PINS.items():
            budget(expires_ns)
            raw = read(sdk / relative, 33554432, pin['sha256'])
            if len(raw) != pin['bytes']:
                raise ValueError('SDK file length mismatch')
        budget(expires_ns)
        source = read(Path(config['sourcePath']), 65536, config['sourceSha256'])
        if source.count(b'private const bool Admitted = true;') != 1 or b'private const bool Admitted = false;' in source:
            raise ValueError('Exactly admitted validation source required')
        write(ROOT / 'WindowsWslObserver.cs', source)
        for name, pin in FRAMEWORK_PINS.items():
            budget(expires_ns)
            raw = read(FRAMEWORK / name, 16777216, pin)
            budget(expires_ns)
            write(ROOT / name, raw)
        for directory in ('home', 'temp'):
            budget(expires_ns)
            (ROOT / directory).mkdir(mode=0o700)
        compiler = sdk / 'sdk/10.0.401/Roslyn/bincore'
        command = [str(sdk / 'dotnet'), 'exec', '--runtimeconfig', str(compiler / 'csc.runtimeconfig.json'),
                   '--fx-version', '10.0.12', '--roll-forward', 'Disable', str(compiler / 'csc.dll'),
                   '-noconfig', '-nostdlib+', '-nologo', '-target:exe', '-platform:x64', '-langversion:5',
                   '-optimize+', '-debug-', '-deterministic+', '-out:' + str(ROOT / 'observer.exe')]
        command += ['-reference:' + str(ROOT / name) for name in FRAMEWORK_PINS]
        command.append(str(ROOT / 'WindowsWslObserver.cs'))
        environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'HOME': str(ROOT / 'home'),
                       'TMPDIR': str(ROOT / 'temp'), 'DOTNET_ROOT': str(sdk),
                       'DOTNET_CLI_HOME': str(ROOT / 'home'), 'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
                       'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1', 'DOTNET_NOLOGO': '1',
                       'DOTNET_ADD_GLOBAL_TOOLS_TO_PATH': 'false',
                       'DOTNET_GENERATE_ASPNET_CERTIFICATE': 'false',
                       'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE': 'true',
                       'DOTNET_ROLL_FORWARD': 'Disable', 'DOTNET_CLI_UI_LANGUAGE': 'en-US'}
        write(ROOT / 'command.json', encode({'argv': command, 'environment': environment}))
        if time.monotonic_ns() >= expires_ns:
            raise TimeoutError('Compilation preparation deadline')
        result['compiler'] = capture(command, environment, expires_ns,
                                     65536, ROOT / 'compiler-output.bin')
        observed = result['compiler']
        if observed['exitCode'] != 0 or not observed['eof'] or observed['failure'] is not None:
            raise ValueError('Compiler did not complete')
        raw = read(ROOT / 'observer.exe', 2097152)
        if not raw or not raw.startswith(b'MZ'):
            raise ValueError('Missing executable output')
        result['artifact'] = {'bytes': len(raw), 'sha256': digest(raw), 'executed': False}
        read(Path(config['sourcePath']), 65536, config['sourceSha256'])
        budget(expires_ns)
        result['passed'] = True
    except BaseException as error:
        result['failure'] = type(error).__name__
    write(ROOT / 'worker-result.json', encode(result))
    # The receipt is provisional until persistence and its owned closes finish.
    budget(expires_ns)
    return 0 if result['passed'] else 1


def execute(config_path, config_hash):
    began_ns = time.monotonic_ns()
    expires_ns = began_ns + 100000000000
    client_deadline_ns = began_ns + 145000000000
    # The admitted original invocation spends its unit even if configuration/debit persistence fails.
    original = json.loads(read(Path(config_path), 65536, config_hash))
    if 'unit' in original:
        raise ValueError('Original configuration must not preselect a worker unit')
    configure(original)
    # Exact external admission binds these original inputs and current authority.
    write(CHARGE, encode({'slot': SLOT, 'countsBefore': BEFORE, 'countsAfter': AFTER,
                         'configSha256': config_hash, 'startedMonotonicNs': time.monotonic_ns()}))
    result = {'passed': False, 'failure': None, 'client': None, 'groupEmpty': False,
              'countsAfter': AFTER, 'configSha256': config_hash, 'continuationAllowed': False}
    lock = None
    try:
        budget(expires_ns)
        lock = os.open(direct(ROOT.parent.parent / 'action.lock'), os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        budget(expires_ns)
        ROOT.mkdir(mode=0o700)
        unit = 'azureauth-wsl-observer-build-108-' + SLOT + '-' + uuid.uuid4().hex + '.service'
        config = dict(original, unit=unit)
        copied_hash = write(ROOT / 'config.json', encode(config))
        source = Path(__file__).resolve()
        read(source, 65536, original['runnerSha256'])
        runtime = '/run/user/' + str(os.getuid())
        environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'XDG_RUNTIME_DIR': runtime,
                       'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus'}
        budget(expires_ns, 5000000000)
        command = ['/usr/bin/systemd-run', '--user', '--no-ask-password', '--quiet', '--wait', '--pipe',
                   '--collect', '--expand-environment=no', '--job-mode=fail', '--unit=' + unit,
                   '--service-type=exec', '--property=ExitType=cgroup', '--property=KillMode=control-group',
                   '--property=SendSIGKILL=yes', '--property=Restart=no', '--property=TimeoutStartSec=10s',
                   '--property=RuntimeMaxSec=120s', '--property=TimeoutStopSec=5s',
                   '--working-directory=' + str(ROOT), '--', '/usr/bin/env', '-i',
                   'PATH=/usr/bin:/bin', 'LC_ALL=C.UTF-8', '/usr/bin/python3', '-I', '-B', '-S',
                   str(source), '--worker', SLOT, copied_hash, str(expires_ns)]
        write(ROOT / 'service-start.json', encode({'unit': unit, 'command': command, 'countsAfter': AFTER}))
        budget(expires_ns, 5000000000)
        result['client'] = capture(command, environment, client_deadline_ns, 16384, ROOT / 'client-output.bin')
        start = json.loads(read(ROOT / 'worker-start.json', 4096))
        if start['configSha256'] != copied_hash or Path(start['cgroup']).name != unit:
            raise ValueError('Original worker binding mismatch')
        events = Path('/sys/fs/cgroup') / start['cgroup'].lstrip('/') / 'cgroup.events'
        if not start['cgroup'].startswith('/') or '..' in Path(start['cgroup']).parts:
            raise ValueError('Unexpected owned cgroup path')
        try:
            # Kernel virtual files report size zero; use a separate bounded read.
            with events.open('rb') as stream:
                data = stream.read(4097)
            if len(data) > 4096:
                raise ValueError('Cgroup event output limit')
            values = dict(line.split() for line in data.decode('ascii').splitlines())
            result['groupEmpty'] = values.get('populated') == '0'
        except FileNotFoundError:
            result['groupEmpty'] = True
        completed = read(ROOT / 'worker-result.json', 8192)
        result['workerResultSha256'] = digest(completed)
        result['workerPassed'] = json.loads(completed)['passed']
        client = result['client']
        if client['exitCode'] != 0 or not client['eof'] or client['failure'] is not None or \
                not result['groupEmpty'] or not result['workerPassed']:
            raise ValueError('Original compilation or containment incomplete')
        budget(client_deadline_ns)
        result['passed'] = True
    except BaseException as error:
        result['failure'] = type(error).__name__
    finally:
        if lock is not None:
            os.close(lock)
        result['elapsedMilliseconds'] = (time.monotonic_ns() - began_ns) // 1000000
        if result['elapsedMilliseconds'] >= 150000:
            result['passed'] = False
            result['failure'] = result['failure'] or 'OriginalDeadlineExpired'
        result_hash = write(FINAL, encode(result))
    budget(began_ns + 150000000000)
    print(json.dumps({'passed': result['passed'], 'resultSha256': result_hash,
                      'countsAfter': AFTER, 'continuationAllowed': False}, sort_keys=True), flush=True)
    budget(began_ns + 150000000000)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    if not EXECUTION_ADMITTED:
        raise SystemExit('INERT: accepted build protocol, source activation and exact-call admission required.')
    if len(sys.argv) == 5 and sys.argv[1] == '--worker':
        select_slot(sys.argv[2])
        raise SystemExit(worker(sys.argv[3], int(sys.argv[4])))
    if len(sys.argv) == 4 and sys.argv[1] == '--execute':
        raise SystemExit(execute(sys.argv[2], sys.argv[3]))
    raise SystemExit('Requires an independently admitted exact command.')
