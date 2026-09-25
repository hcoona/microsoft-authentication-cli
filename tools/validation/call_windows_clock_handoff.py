"""Inert single-use clock0108 caller; only separately admitted CONFIG may activate it."""

import base64
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
import urllib.request

CONFIG = None
BEFORE = [20, 105, 4, 157]
AFTER = [20, 106, 4, 161]
UNIT = 'azureauth-clock-handoff-108-0108.service'
ROOT = Path('/var/tmp/azureauth-windows-slice-108/windows-actions/0108')
WINDOWS = Path('/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0108')
LINUX_INPUTS = Path('/tmp/windows-clock-handoff0108-inputs')
WINDOWS_ROLES = {WINDOWS / name: role for name, role in (
    ('authority.json', 'authority'), ('Invoke-WindowsNamedGuardFixtures.ps1', 'harness'),
    ('WindowsScriptJobLauncher.exe', 'launcher'), ('bootstrap.source.txt', 'bootstrap'),
    ('controller.source.txt', 'controller'))}
COPY_PATHS = [str(LINUX_INPUTS / name) for name in (
    'authority.json', 'run_windows_clock_handoff.py', 'clock_handoff_cases.py', 'publisher.source.txt')
] + [str(path) for path in WINDOWS_ROLES]
START = ROOT / 'started.json'
RESULT = ROOT / 'caller-result.json'
BEGAN_NS = time.monotonic_ns()
BEGAN = BEGAN_NS / 1_000_000_000
WINDOWS_HANDOFFS = []
STAGE = 'entry'
READS = REQUESTED = WRITTEN = 0
BOOTSTRAP = """import os,sys,time
if time.monotonic_ns() >= int(sys.argv[1]):
    raise SystemExit(125)
os.execve(sys.executable,[sys.executable,'-I','-B','-S',sys.argv[2],sys.argv[3]],dict(os.environ))
"""


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate original caller field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite caller field')))


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def directory_identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]


def check(limit=430):
    if time.monotonic() - BEGAN >= limit:
        raise TimeoutError('Original caller deadline')


def stage(value):
    global STAGE
    STAGE = value


def parent(path):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Nonliteral original caller path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            check()
            named = os.stat(component, dir_fd=fd, follow_symlinks=False)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            if directory_identity(named) != directory_identity(os.fstat(child)):
                os.close(child)
                raise ValueError('Original caller parent changed')
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, maximum, binding=None, rootfd=None, windows_role=None):
    global READS, REQUESTED
    if windows_role is not None and (WINDOWS_ROLES.get(path) != windows_role or binding is None):
        raise ValueError('Unknown Windows handoff role')
    prefix = 'read:' + path.name + ':'
    stage(prefix + 'parent')
    check()
    READS += 1
    if READS > 40:
        raise ValueError('Original caller logical read ceiling')
    pfd = parent(path) if rootfd is None else rootfd
    fd = None
    try:
        stage(prefix + 'shape')
        named = os.stat(path.name, dir_fd=pfd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or named.st_size > maximum:
            raise ValueError('Original caller file kind or size')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
        stage(prefix + 'opened-identity')
        if identity(named) != identity(os.fstat(fd)):
            raise ValueError('Original caller opened leaf changed')
        raw = bytearray()
        stage(prefix + 'payload')
        while len(raw) < named.st_size:
            check()
            count = min(65536, named.st_size - len(raw))
            REQUESTED += count
            if REQUESTED > 4194304:
                raise ValueError('Original caller requested-byte ceiling')
            part = os.read(fd, count)
            if not part:
                raise ValueError('Original caller short input')
            raw.extend(part)
        REQUESTED += 1
        stage(prefix + 'eof')
        if REQUESTED > 4194304 or os.read(fd, 1):
            raise ValueError('Original caller EOF or requested-byte ceiling')
        stage(prefix + 'current-identity')
        if identity(named) != identity(os.fstat(fd)) or \
                identity(named) != identity(os.stat(path.name, dir_fd=pfd, follow_symlinks=False)):
            raise ValueError('Original caller leaf changed during read')
        stage(prefix + 'accepted-binding')
        if binding is not None:
            observed = identity(named)
            expected = binding['identity']
            fields = tuple(range(9))
            if windows_role is not None:
                fields = (0, 1, 2, 3, 4, 5, 6, 8)
                WINDOWS_HANDOFFS.append({'role': windows_role, 'expectedCtimeNs': expected[7],
                                         'observedCtimeNs': observed[7]})
            if (any(observed[index] != expected[index] for index in fields) or
                    len(raw) != binding['bytes'] or hashlib.sha256(raw).hexdigest() != binding['sha256']):
                raise ValueError('Original caller admitted input changed')
        return bytes(raw)
    finally:
        if fd is not None:
            os.close(fd)
        if rootfd is None:
            os.close(pfd)


def write(path, value, rootfd=None):
    global WRITTEN
    raw = encode(value)
    WRITTEN += len(raw)
    if len(raw) > 65536 or WRITTEN > 196608:
        raise ValueError('Original caller output ceiling')
    pfd = parent(path) if rootfd is None else rootfd
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=pfd)
        try:
            offset = 0
            while offset < len(raw):
                check()
                count = os.write(fd, raw[offset:])
                if count <= 0:
                    raise OSError('Original caller incomplete write')
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(pfd)
    finally:
        if rootfd is None:
            os.close(pfd)
    return hashlib.sha256(raw).hexdigest()


def join_windows(fd, original):
    if directory_identity(os.fstat(fd)) != original or directory_identity(WINDOWS.lstat()) != original:
        raise ValueError('Original Windows root continuity lost')


def join_history(fd, original):
    if directory_identity(os.fstat(fd)) != original or directory_identity(ROOT.lstat()) != original:
        raise ValueError('Original dispatcher history root continuity lost')


def group_empty(group):
    global READS, REQUESTED
    path = Path(group)
    if not path.is_absolute() or '..' in path.parts or path.name != UNIT:
        raise ValueError('Original cgroup does not bind this unit')
    READS += 1
    REQUESTED += 4097
    if READS > 40 or REQUESTED > 4194304:
        raise ValueError('Original cgroup observation budget')
    # The exact dispatcher recorded this group from its own /proc/self/cgroup.
    events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
    try:
        pfd = parent(events)
    except FileNotFoundError:
        return True
    try:
        try:
            fd = os.open(events.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
        except FileNotFoundError:
            return True
        try:
            raw = os.read(fd, 4096)
            if os.read(fd, 1):
                raise ValueError('Original cgroup observation size')
        finally:
            os.close(fd)
    finally:
        os.close(pfd)
    return dict(line.split() for line in raw.decode('ascii').splitlines()).get('populated') == '0'


def verify_public_ref(expected):
    # One public, unauthenticated observation; no Git/credential helper subprocess.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, stream, code, message, headers, new_url):
            raise ValueError('Public reference redirect is not admitted')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(
        'https://api.github.com/repos/hcoona/microsoft-authentication-cli/git/ref/heads/main-v2',
        headers={'User-Agent': 'azureauth-public-validation', 'Accept': 'application/vnd.github+json'})
    request_end = min(time.monotonic() + 10, BEGAN + 20)
    remaining = request_end - time.monotonic()
    if remaining <= 0 or any(signal.getitimer(signal.ITIMER_REAL)):
        raise ValueError('Original request deadline or timer ownership changed')
    def expired(_number, _frame):
        raise TimeoutError('Original public reference deadline')
    previous_handler = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining)
        with opener.open(request, timeout=remaining) as response:
            if response.status != 200:
                raise ValueError('Public reference unavailable')
            raw = response.read(65537)
        if time.monotonic() >= request_end:
            raise TimeoutError('Original public reference deadline')
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
    if len(raw) > 65536 or decode(raw)['object']['sha'] != expected:
        raise ValueError('Accepted target changed')
    return hashlib.sha256(raw).hexdigest()


def main():
    if CONFIG is None:
        raise ValueError('Unbound inert clock caller')
    if sys.executable != '/usr/bin/python3.14' or len(sys.argv) != 1 or \
            not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode:
        raise ValueError('Fixed isolated caller runtime required')
    # The external admitted call-start is durable before entry, including failed starts.
    # This same-attempt full debit is durable before currentness or service creation.
    lock_parent = parent(ROOT.parent.parent / 'action.lock')
    lock_fd = os.open('action.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=lock_parent)
    os.close(lock_parent)
    if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
        os.close(lock_fd)
        raise ValueError('Existing action lock is not regular')
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    history_parent = parent(START.parent)
    try:
        os.mkdir(ROOT.name, mode=0o700, dir_fd=history_parent)
        history_fd = os.open(ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=history_parent)
        history_identity = directory_identity(os.fstat(history_fd))
        join_history(history_fd, history_identity)
        os.fsync(history_parent)
    finally:
        os.close(history_parent)
    original_start = {'schema': 'clock-handoff0108-started-v1', 'action': '0108', 'unit': UNIT,
        'countsBefore': BEFORE, 'countsAfter': AFTER, 'charge': [0, 1, 0, 4],
        'authoritySha256': CONFIG['authority']['sha256'], 'startedMonotonicNs': BEGAN_NS,
        'deadlineMonotonicNs': BEGAN_NS + 430_000_000_000}
    start_hash = write(START, original_start, history_fd)
    result = {'schema': 'clock-handoff0108-caller-result-v1', 'startSha256': start_hash,
        'authoritySha256': CONFIG['authority']['sha256'], 'countsAfter': AFTER,
        'passed': False, 'continuation_allowed': False, 'failureType': None,
        'secondaryErrors': [], 'clientExit': None, 'groupEmpty': None, 'serviceAttempted': False,
        'workerEvidence': {}}
    process = None
    windows_fd = None
    windows_identity = None
    cancelled = [False]
    eof = [False, False]
    observed = [0, 0]
    captured = [bytearray(), bytearray()]
    overflow = [False, False]
    read_errors = [None, None]
    signal.signal(signal.SIGTERM, lambda *_: cancelled.__setitem__(0, True))
    signal.signal(signal.SIGINT, lambda *_: cancelled.__setitem__(0, True))

    def failure(error):
        result['passed'] = False
        if result['failureType'] is None:
            result['failureType'] = type(error).__name__
            result['failureStage'] = STAGE
        elif len(result['secondaryErrors']) < 8:
            result['secondaryErrors'].append({'stage': STAGE, 'errorType': type(error).__name__})

    def drain(index, stream):
        if eof[index] or read_errors[index] is not None:
            return
        if sum(observed) >= 1048576:
            read_errors[index] = 'observation-limit'
            raise ValueError('Original service observation ceiling')
        try:
            chunk = os.read(stream.fileno(), min(4096, 1048576 - sum(observed)))
        except BlockingIOError:
            return
        except OSError as error:
            read_errors[index] = type(error).__name__
            raise
        if not chunk:
            eof[index] = True
            return
        observed[index] += len(chunk)
        remaining = max(0, 16384 - sum(map(len, captured)))
        captured[index].extend(chunk[:remaining])
        if len(chunk) > remaining:
            overflow[index] = True
            raise ValueError('Original service capture overflow')

    try:
        stage('installed-tools')
        for binding in CONFIG['tools']:
            if str(Path(binding['path']).resolve(strict=True)) != binding['resolved'] or \
                    identity(Path(binding['resolved']).lstat()) != binding['identity']:
                raise ValueError('Admitted installed tool changed')
        authority_raw = read(Path(CONFIG['authority']['path']), 65536, CONFIG['authority'])
        authority = decode(authority_raw)
        if encode(authority) != authority_raw or authority['schema'] != 'clock-handoff-0108-v1' or \
                authority['accepted'] is not True or authority['action'] != '0108' or \
                authority['countsBefore'] != BEFORE or authority['countsAfter'] != AFTER or \
                authority['buildTestCharge'] != 1 or authority['syntheticCharge'] != 4:
            raise ValueError('Original caller authority mismatch')
        receipt = decode(read(Path(CONFIG['materialization']['path']), 65536, CONFIG['materialization']))
        if receipt['manifestSha256'] != CONFIG['manifestSha256'] or \
                [item['path'] for item in receipt['copies']] != COPY_PATHS:
            raise ValueError('Original materialization mismatch')
        for binding in receipt['copies']:
            path = Path(binding['path'])
            if path.name == 'WindowsScriptJobLauncher.exe' and (
                    not stat.S_ISREG(binding['identity'][2]) or binding['identity'][3] != os.getuid() or
                    not binding['identity'][2] & stat.S_IXUSR):
                raise ValueError('Materialized launcher owner or mode mismatch')
            read(path, 262144, binding, windows_role=WINDOWS_ROLES.get(path))
        expected_windows = [item['identity'] for item in receipt['directories'] if item['path'] == str(WINDOWS)]
        if len(expected_windows) != 1:
            raise ValueError('Original Windows root missing')
        windows_fd = os.open(WINDOWS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        windows_identity = expected_windows[0]
        join_windows(windows_fd, windows_identity)
        interop = authority['wslInterop']['path']
        if os.environ.get('WSL_INTEROP') != interop:
            raise ValueError('Original caller endpoint mismatch')
        stage('accepted-currentness')
        result['acceptedRefSha256'] = verify_public_ref(authority['acceptedCommit'])
        runner = str(LINUX_INPUTS / 'run_windows_clock_handoff.py')
        command = ['/usr/bin/systemd-run', '--user', '--no-ask-password', '--quiet', '--wait', '--pipe',
            '--expand-environment=no', '--job-mode=fail', '--unit=' + UNIT, '--service-type=exec',
            '--property=ExitType=cgroup', '--property=KillMode=control-group', '--property=SendSIGKILL=yes',
            '--property=Restart=no', '--property=JobRunningTimeoutSec=5s', '--property=TimeoutStartSec=5s',
            '--property=RuntimeMaxSec=390s', '--property=TimeoutStopSec=5s', '--working-directory=/tmp', '--',
            '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'WSL_INTEROP=' + interop,
            '/usr/bin/python3.14', '-I', '-B', '-S', '-c', BOOTSTRAP,
            str(BEGAN_NS + 30_000_000_000), runner, CONFIG['authority']['sha256']]
        runtime = '/run/user/' + str(os.getuid())
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'XDG_RUNTIME_DIR': runtime,
                       'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus'}
        check(20)
        if cancelled[0]:
            raise InterruptedError('Cancelled before service creation')
        result['commandSha256'] = hashlib.sha256(encode(command)).hexdigest()
        result['serviceAttempted'] = True
        stage('service-start')
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment, cwd='/tmp')
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        stage('service-transport')
        while time.monotonic() - BEGAN < 420:
            if cancelled[0]:
                raise InterruptedError('Original caller cancelled')
            for index, stream in enumerate((process.stdout, process.stderr)):
                drain(index, stream)
            if process.poll() is not None and all(eof):
                break
            time.sleep(0.025)
        if process.poll() != 0 or not all(eof) or any(captured):
            raise ValueError('Original service did not complete cleanly')
        result['passed'] = True
    except BaseException as error:
        failure(error)
    finally:
        if process is not None and (process.poll() is None or not all(eof)):
            stage('original-cancellation')
            try:
                join_windows(windows_fd, windows_identity)
                write(WINDOWS / 'cancel', {'cancelled': True}, windows_fd)
                join_windows(windows_fd, windows_identity)
            except BaseException as error:
                failure(error)
            while time.monotonic() - BEGAN < 425 and (process.poll() is None or not all(eof)):
                for index, stream in enumerate((process.stdout, process.stderr)):
                    try:
                        drain(index, stream)
                    except BaseException as error:
                        failure(error)
                time.sleep(0.025)
            if process.poll() is None:
                # This is only the directly retained service client. The service
                # retains its own cgroup deadline; Linux kill is not Windows closure.
                try:
                    process.kill()
                    process.wait(timeout=max(0.001, min(1, 427 - (time.monotonic() - BEGAN))))
                except BaseException as error:
                    failure(error)
        result['clientExit'] = None if process is None else process.poll()
        result['eof'] = eof
        result['observedBytes'] = observed
        result['retainedBytes'] = list(map(len, captured))
        result['overflow'] = overflow
        result['truncated'] = [observed[i] != len(captured[i]) for i in range(2)]
        result['readErrors'] = read_errors
        result['captureComplete'] = all(eof) and not any(overflow) and all(x is None for x in read_errors)
        result['stdoutBase64'], result['stderrBase64'] = (
            base64.b64encode(bytes(value)).decode('ascii') for value in captured)
        if not result['captureComplete']:
            stage('service-capture-completion')
            failure(ValueError('Original service capture incomplete'))
        # Read only this invocation's fixed Linux receipts once, including on failure.
        # The worker's retained snapshot is the only copy of new Windows outputs.
        leaves = {'worker-entered.json': 8192, 'producer-cases.json': 65536,
                  'proxy-transport.json': 65536, 'snapshot.json': 524288, 'worker-result.json': 65536}
        retained = {}
        for name, maximum in leaves.items():
            stage('original-receipt:' + name)
            try:
                check(428)
                join_history(history_fd, history_identity)
                raw = read(ROOT / name, maximum, rootfd=history_fd)
                retained[name] = decode(raw)
                result['workerEvidence'][name] = {'status': 'present', 'bytes': len(raw),
                    'sha256': hashlib.sha256(raw).hexdigest()}
            except FileNotFoundError:
                result['workerEvidence'][name] = {'status': 'absent-at-observation'}
                failure(ValueError('Required original worker evidence absent'))
            except BaseException as error:
                result['workerEvidence'][name] = {'status': 'error', 'errorType': type(error).__name__}
                failure(error)
        stage('scoped-completion')
        try:
            entered = retained['worker-entered.json']
            worker = retained['worker-result.json']
            if entered['authoritySha256'] != CONFIG['authority']['sha256']:
                raise ValueError('Original worker cgroup binding mismatch')
            result['groupEmpty'] = group_empty(entered['cgroup'])
            if result['groupEmpty'] is not True or worker['passed'] is not True or \
                    worker['scopedJobClosed'] is not True or worker['captureComplete'] is not True or \
                    worker['authoritySha256'] != CONFIG['authority']['sha256'] or worker['countsAfter'] != AFTER:
                raise ValueError('Scoped original completion missing')
        except BaseException as error:
            failure(error)
        result['elapsedMilliseconds'] = int((time.monotonic_ns() - BEGAN_NS) // 1_000_000)
        result['selectedReads'] = READS
        result['requestedBytes'] = REQUESTED
        result['windowsInputHandoffs'] = WINDOWS_HANDOFFS
        try:
            stage('caller-result-persistence')
            join_history(history_fd, history_identity)
            result_hash = write(RESULT, result, history_fd)
            join_history(history_fd, history_identity)
            print(json.dumps({'passed': result['passed'], 'startSha256': start_hash,
                              'resultSha256': result_hash, 'continuation_allowed': False}), flush=True)
        finally:
            if process is not None:
                process.stdout.close()
                process.stderr.close()
            if windows_fd is not None:
                os.close(windows_fd)
            os.close(history_fd)
            os.close(lock_fd)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
