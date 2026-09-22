"""Single admitted Linux compilation of the inactive Windows launcher.

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

ROOT = Path('/var/tmp/azureauth-windows-slice-108/windows-actions/0069')
CHARGE = Path('/tmp/windows-launcher0069-original-charge.json')
FINAL = Path('/tmp/windows-launcher0069-original-result.json')
FRAMEWORK = Path('/mnt/c/Windows/Microsoft.NET/Framework64/v4.0.30319')
BEFORE = [17, 96, 2, 70]
AFTER = [18, 96, 2, 70]
FRAMEWORK_PINS = {
    'mscorlib.dll': '5bffb20e1217bad314143d7e5c4c809bf9f522e8a0a063c8e7e9b25113de26eb',
    'System.dll': '2b3c17c6208a0b4b6beb94e1a066f99ba06cdb2ea919479e99d47e8c6d96dc71',
    'System.Core.dll': 'fd1097aed825d392a5dc8d19384381d4bb2a43498ea1c9d917f5d80c66600e1b',
}


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
    sdk = direct(Path(config['sdkRoot']))
    groups = [line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
              if line.startswith('0::')]
    if len(groups) != 1 or Path(groups[0]).name != config['unit']:
        raise ValueError('Worker is not in its original named cgroup')
    fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
    write(ROOT / 'worker-start.json', encode({'pid': os.getpid(), 'startTicks': int(fields[19]),
                                             'cgroup': groups[0], 'configSha256': config_hash}))
    result = {'passed': False, 'failure': None, 'compiler': None, 'artifact': None}
    try:
        for relative, pin in config['sdkPins'].items():
            budget(expires_ns)
            raw = read(sdk / relative, 33554432, pin['sha256'])
            if len(raw) != pin['bytes']:
                raise ValueError('SDK file length mismatch')
        budget(expires_ns)
        source = read(Path(config['sourcePath']), 65536, config['sourceSha256'])
        if b'private static readonly bool ExecutionAdmitted = false;' not in source:
            raise ValueError('Inactive source required')
        write(ROOT / 'WindowsScriptJobLauncher.cs', source)
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
                   '-optimize+', '-debug-', '-deterministic+', '-out:' + str(ROOT / 'WindowsScriptJobLauncher.exe')]
        command += ['-reference:' + str(ROOT / name) for name in FRAMEWORK_PINS]
        command.append(str(ROOT / 'WindowsScriptJobLauncher.cs'))
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
        raw = read(ROOT / 'WindowsScriptJobLauncher.exe', 2097152)
        if not raw or not raw.startswith(b'MZ'):
            raise ValueError('Missing executable output')
        result['artifact'] = {'bytes': len(raw), 'sha256': digest(raw), 'executed': False}
        read(Path(config['sourcePath']), 65536, config['sourceSha256'])
        budget(expires_ns)
        result['passed'] = True
    except BaseException as error:
        result['failure'] = type(error).__name__
    write(ROOT / 'worker-result.json', encode(result))
    return 0 if result['passed'] else 1


def execute(config_path, config_hash):
    began_ns = time.monotonic_ns()
    expires_ns = began_ns + 100000000000
    client_deadline_ns = began_ns + 145000000000
    # Exact external admission binds these original inputs and current authority.
    write(CHARGE, encode({'countsBefore': BEFORE, 'countsAfter': AFTER,
                         'configSha256': config_hash, 'startedMonotonicNs': time.monotonic_ns()}))
    result = {'passed': False, 'failure': None, 'client': None, 'groupEmpty': False,
              'countsAfter': AFTER, 'configSha256': config_hash, 'continuationAllowed': False}
    lock = None
    try:
        original = json.loads(read(Path(config_path), 65536, config_hash))
        budget(expires_ns)
        lock = os.open(direct(ROOT.parent.parent / 'action.lock'), os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        budget(expires_ns)
        ROOT.mkdir(mode=0o700)
        unit = 'azureauth-launcher-build-108-0069-' + uuid.uuid4().hex + '.service'
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
                   str(source), '--worker', copied_hash, str(expires_ns)]
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
    print(json.dumps({'passed': result['passed'], 'resultSha256': result_hash,
                      'countsAfter': AFTER, 'continuationAllowed': False}, sort_keys=True), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--worker':
        raise SystemExit(worker(sys.argv[2], int(sys.argv[3])))
    if len(sys.argv) == 4 and sys.argv[1] == '--execute':
        raise SystemExit(execute(sys.argv[2], sys.argv[3]))
    raise SystemExit('Requires an independently admitted exact command.')
