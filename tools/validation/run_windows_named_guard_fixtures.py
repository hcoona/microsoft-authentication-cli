"""One prospective credential-free named-Job fixture batch; never an automatic retry."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.request


INPUTS = Path('/tmp/windows-named-fixtures0071-inputs')
WINDOWS = Path('/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0071')
HISTORY = Path('/var/tmp/azureauth-windows-slice-108/windows-actions/0071')
SHELL = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
LAUNCHER = WINDOWS / 'WindowsScriptJobLauncher.exe'
LAUNCHER_BYTES = 23040
LAUNCHER_SHA256 = '5b018f38669fd6ca3cec8f760533af392e0265280047bfb5c531dd41a349690a'
UNIT = 'azureauth-named-fixtures-108-0071.service'
BEFORE = {'preparation': 19, 'buildTest': 96, 'publication': 2, 'synthetic': 70}
AFTER = {'preparation': 19, 'buildTest': 97, 'publication': 2, 'synthetic': 80}
GUARD_COUNTERS = {'preparation': 17, 'buildTest': 94, 'publication': 2, 'synthetic': 52}
FAILURE_DISPOSITION_SHA256 = '1ecb4ef1ec1c0eea1afeaa71c6e705dd3962e6998a582bc118780d983e812dcf'
CASES = ('collision', 'live', 'disposed', 'callback', 'missing', 'session')
READ_LIMIT = 16 * 1024 * 1024
read_requested = 0


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate fixture field')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite fixture value')))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def direct(path):
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('Linked fixture input')


def read(path, maximum, root_fd=None, root_expected=None):
    global read_requested
    direct(path)
    if root_fd is not None:
        if path.parent != WINDOWS or directory_identity(os.fstat(root_fd)) != root_expected or \
                directory_identity(WINDOWS.lstat()) != root_expected:
            raise ValueError('Original read root continuity lost')
    fd = os.open(path if root_fd is None else path.name,
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError('Fixture file bound')
        data = bytearray()
        while len(data) < before.st_size:
            count = min(65536, before.st_size - len(data))
            read_requested += count
            if read_requested > READ_LIMIT:
                raise ValueError('Fixture requested-byte limit')
            part = os.read(fd, count)
            if not part:
                raise ValueError('Short fixture file')
            data.extend(part)
        read_requested += 1
        if read_requested > READ_LIMIT or os.read(fd, 1):
            raise ValueError('Fixture EOF/byte limit')
        fields = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                               item.st_mtime_ns, item.st_ctime_ns, item.st_nlink)
        named = path.lstat() if root_fd is None else os.stat(path.name, dir_fd=root_fd, follow_symlinks=False)
        if fields(before) != fields(os.fstat(fd)) or fields(before) != fields(named):
            raise ValueError('Fixture input identity changed')
        if root_fd is not None and (directory_identity(os.fstat(root_fd)) != root_expected or
                                    directory_identity(WINDOWS.lstat()) != root_expected):
            raise ValueError('Original read root changed during observation')
        return bytes(data)
    finally:
        os.close(fd)


def write_root_json(root, held, expected, name, value):
    raw = encode(value)
    if len(raw) > 262144:
        raise ValueError('Fixture output bound')
    if directory_identity(os.fstat(held)) != expected or directory_identity(root.lstat()) != expected:
        raise ValueError('Original output root continuity lost')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=held)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(held)
    if directory_identity(os.fstat(held)) != expected or directory_identity(root.lstat()) != expected:
        raise ValueError('Original output root changed during persistence')
    return sha(raw)


def group_identity():
    global read_requested
    # procfs reports size zero; one finite read plus a debited EOF probe is enough.
    fd = os.open('/proc/self/cgroup', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        read_requested += 4097
        if read_requested > READ_LIMIT:
            raise ValueError('Fixture requested-byte limit')
        raw = os.read(fd, 4096)
        if os.read(fd, 1):
            raise ValueError('Own cgroup record exceeds fixed bound')
    finally:
        os.close(fd)
    lines = raw.decode('ascii').splitlines()
    groups = [line[3:] for line in lines if line.startswith('0::')]
    if len(groups) != 1 or Path(groups[0]).name != UNIT:
        raise ValueError('Dedicated original cgroup missing')
    return groups[0]


def verify_public_ref(expected):
    # One public, unauthenticated observation; no Git/credential helper subprocess.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, stream, code, message, headers, new_url):
            raise ValueError('Public reference redirect is not admitted')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(
        'https://api.github.com/repos/hcoona/microsoft-authentication-cli/git/ref/heads/main-v2',
        headers={'User-Agent': 'azureauth-public-validation', 'Accept': 'application/vnd.github+json'})
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise ValueError('Public reference unavailable')
        raw = response.read(65537)
    if len(raw) > 65536 or decode(raw)['object']['sha'] != expected:
        raise ValueError('Accepted target changed')
    return sha(raw)


def directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def verify_interop(authority):
    binding = authority['wslInterop']
    path = Path(binding['path'])
    number = path.name.removesuffix('_interop')
    if str(path) != binding['path'] or path.parent != Path('/run/WSL') or \
            not path.name.endswith('_interop') or not number or len(number) > 10 or \
            any(character not in '0123456789' for character in number) or \
            os.environ.get('WSL_INTEROP') != str(path):
        raise ValueError('Original caller interop endpoint is not bound')
    # Metadata only: no connection, process discovery or alternate endpoint.
    direct(path)
    info = path.lstat()
    observed = [*directory_identity(info), str(info.st_mtime_ns), str(info.st_ctime_ns)]
    if not stat.S_ISSOCK(info.st_mode) or observed != binding['identity']:
        raise ValueError('Original caller interop endpoint changed')
    return str(path)


def cancel_original_root(held, expected):
    if held is None or directory_identity(os.fstat(held)) != expected or \
            directory_identity(WINDOWS.lstat()) != expected:
        raise ValueError('Original Windows root continuity lost; no cancellation written')
    # Descriptor-relative creation cannot target a replacement directory after this check.
    write_root_json(WINDOWS, held, expected, 'cancel', {'cancelled': True})


def accept_launcher_journal(raw, authority, authority_hash):
    records = [decode(line) for line in raw.splitlines()]
    expected = ('bootstrap', 'job-ready', 'root-suspended', 'resume-requested', 'resumed',
                'completed', 'capture', 'capture', 'launcher-exit')
    if tuple(item['event'] for item in records) != expected:
        raise ValueError('Incomplete normal launcher journal')
    times = [item['elapsedMilliseconds'] for item in records]
    if any(type(value) is not int or not 0 <= value < 340000 for value in times) or times != sorted(times):
        raise ValueError('Launcher journal clock mismatch')
    bootstrap, ready, root = records[:3]
    for identity in (bootstrap, root):
        if type(identity['pid']) is not int or identity['pid'] <= 0 or \
                type(identity['session']) is not int or identity['session'] < 0 or \
                not re.fullmatch(r'[1-9][0-9]{1,19}', identity['creationFileTime']):
            raise ValueError('Launcher process identity missing')
    expected_name = 'Local\\azureauth-controller-108-0071-' + authority['launcherSuffix']
    if bootstrap['authoritySha256'] != authority_hash or bootstrap['jobName'] != expected_name or \
            ready['queryAndTerminateAccess'] is not True or root['inJob'] is not True or \
            root['pid'] == bootstrap['pid'] or root['session'] != bootstrap['session']:
        raise ValueError('Launcher creation-time containment mismatch')
    completed = records[5]
    if completed['rootExited'] is not True or completed['rootExitCode'] != 0 or \
            completed['activeProcesses'] != 0 or completed['totalProcesses'] != 10 or \
            completed['stdoutEof'] is not True or completed['stderrEof'] is not True or \
            completed['capturedBytes'] != 0:
        raise ValueError('Launcher workload completion mismatch')
    for record, stream in zip(records[6:8], ('stdout', 'stderr'), strict=True):
        if record['stream'] != stream or record['initialized'] is not True or \
                record['readBytes'] != 0 or record['confirmedFlushedBytes'] != 0 or \
                record['eof'] is not True or record['overflowDetected'] is not False or \
                any(record[key] is not None for key in ('failureStage', 'failureType',
                    'failureHresult', 'failureNativeError', 'closeFailureType')):
            raise ValueError('Launcher output capture incomplete')
    if records[-1]['passed'] is not True or records[-1]['capturedBytes'] != 0:
        raise ValueError('Launcher terminal record mismatch')
    return root


def main():
    began = time.monotonic()
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('Original fixture clock')))
    signal.setitimer(signal.ITIMER_REAL, 30)
    if len(sys.argv) != 2 or len(sys.argv[1]) != 64 or any(c not in '0123456789abcdef' for c in sys.argv[1]):
        raise ValueError('Exact authority hash required')
    authority_hash = sys.argv[1]
    authority_bytes = read(INPUTS / 'authority.json', 65536)
    if sha(authority_bytes) != authority_hash:
        raise ValueError('Authority changed')
    authority = decode(authority_bytes)
    if encode(authority) != authority_bytes or authority['schema'] != 'named-guard-fixtures-0071-v1' or \
            authority['accepted'] is not True or authority['action'] != '0071' or \
            authority['countsBefore'] != BEFORE or authority['buildTestCharge'] != 1 or authority['syntheticCharge'] != 10 or \
            authority['failedFixtureDispositionSha256'] != FAILURE_DISPOSITION_SHA256:
        raise ValueError('Fixture allocation not admitted')
    if sha(read(Path(__file__), 65536)) != authority['runnerSha256']:
        raise ValueError('Dispatcher changed')
    if not re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', authority['launcherSuffix']) or \
            authority['launcherBytes'] != LAUNCHER_BYTES or authority['launcherSha256'] != LAUNCHER_SHA256:
        raise ValueError('Unaccepted launcher input')
    group = group_identity()
    # The singleton debit precedes network preflight and every Windows process start.
    direct(HISTORY.parent)
    HISTORY.mkdir(mode=0o700)
    created_history_identity = directory_identity(HISTORY.lstat())
    history_fd = os.open(HISTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if created_history_identity != directory_identity(os.fstat(history_fd)):
        raise ValueError('Original history root changed during open')
    start = {'schema': 'named-guard-fixtures-started-v1', 'action': '0071', 'countsBefore': BEFORE,
             'countsAfter': AFTER, 'authoritySha256': authority_hash, 'cgroup': group,
             'startedMonotonicNs': time.monotonic_ns(), 'buildTestCharge': 1, 'syntheticCharge': 10}
    start_hash = write_root_json(HISTORY, history_fd, created_history_identity, 'started.json', start)
    result = {'schema': 'named-guard-fixtures-result-v1', 'passed': False, 'continuation_allowed': False,
              'authoritySha256': authority_hash, 'countsAfter': AFTER, 'proxyExit': None,
              'stdoutEof': False, 'stderrEof': False, 'windowsQuiescent': False, 'failureType': None}
    cancelled = [False]
    def cancel(_number, _frame):
        cancelled[0] = True
    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    process = None
    windows_fd = None
    windows_identity = None
    cancellation_sent = False
    captured = [bytearray(), bytearray()]
    eof = [False, False]
    try:
        interop = verify_interop(authority)
        direct(WINDOWS)
        windows_fd = os.open(WINDOWS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        windows_identity = directory_identity(os.fstat(windows_fd))
        if windows_identity != directory_identity(WINDOWS.lstat()):
            raise ValueError('Windows root changed during original open')
        checkpoint = read(INPUTS / 'checkpoint.json', 32768)
        if sha(checkpoint) != authority['checkpointSha256']:
            raise ValueError('Accepted consumption checkpoint changed')
        prior = decode(checkpoint)
        # The guard retains its immutable original checkpoint; authority owns this batch's current allocation.
        if prior['originalPreparationJoin']['counterState'] != GUARD_COUNTERS or prior['decision']['artifactAccepted'] is not True:
            raise ValueError('Accepted guard/counter prerequisite changed')
        if read(WINDOWS / 'authority.json', 65536) != authority_bytes:
            raise ValueError('Windows authority copy changed')
        if sha(read(WINDOWS / 'Invoke-WindowsNamedGuardFixtures.ps1', 65536)) != authority['controllerSha256']:
            raise ValueError('Windows fixture source changed')
        launcher = read(LAUNCHER, 2097152)
        if len(launcher) != LAUNCHER_BYTES or sha(launcher) != LAUNCHER_SHA256:
            raise ValueError('Accepted launcher artifact changed')
        guard = read(WINDOWS / 'WindowsFinalPublishGuard.dll', 24576)
        if len(guard) != 24576 or sha(guard) != 'a18302e4658afc08b564be23c9b52995fba85c1a3345fba19662008efe30ae58':
            raise ValueError('Accepted guard bytes changed')
        if sha(read(Path(SHELL), 1048576)) != '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e':
            raise ValueError('Pinned Windows shell changed')
        if any((WINDOWS / leaf).exists() for leaf in (*CASES, 'windows-started.json', 'windows-result.json',
                'cancel', 'launcher.jsonl', 'launcher.stdout.bin', 'launcher.stderr.bin')):
            raise ValueError('Original fixture evidence already exists')
        result['acceptedRefSha256'] = verify_public_ref(authority['acceptedCommit'])
        if cancelled[0] or time.monotonic() - began >= 30:
            raise TimeoutError('Fixture preflight exceeded original bound')
        if windows_identity != directory_identity(os.fstat(windows_fd)) or \
                windows_identity != directory_identity(WINDOWS.lstat()):
            raise ValueError('Windows root changed before process start')
        if verify_interop(authority) != interop:
            raise ValueError('Original caller interop binding changed')
        signal.setitimer(signal.ITIMER_REAL, max(0.001, 420 - (time.monotonic() - began)))
        command = [str(LAUNCHER), r'C:\Temp\azureauth-windows-slice-108\named-fixtures-0071',
                   authority['launcherSuffix'], authority_hash, authority['controllerSha256']]
        process = subprocess.Popen(command, cwd=WINDOWS, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                                        'WSLENV': 'PSModuleAnalysisCachePath/w', 'PSModuleAnalysisCachePath': 'NUL',
                                        'WSL_INTEROP': interop})
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        while time.monotonic() - began < 400:
            if (cancelled[0] or time.monotonic() - began >= 330) and not cancellation_sent:
                cancel_original_root(windows_fd, windows_identity)
                cancellation_sent = True
            for index, stream in enumerate((process.stdout, process.stderr)):
                if eof[index]:
                    continue
                try:
                    chunk = os.read(stream.fileno(), 4096)
                except BlockingIOError:
                    continue
                if chunk == b'':
                    eof[index] = True
                else:
                    remaining = 16384 - sum(map(len, captured))
                    captured[index].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        result['outputOverflow'] = True
                        raise ValueError('Fixture output limit')
            if process.poll() is not None and all(eof):
                break
            time.sleep(0.025)
        result['proxyExit'] = process.poll()
        result['stdoutEof'], result['stderrEof'] = eof
        if result['proxyExit'] != 0 or not all(eof) or any(captured) or cancellation_sent:
            raise ValueError('Original fixture proxy did not complete normally')
        # WSL's original console-process exit status follows its Windows process-handle
        # wait. Join it with the source-bound journal; the journal alone is insufficient.
        journal = read(WINDOWS / 'launcher.jsonl', 16384, windows_fd, windows_identity)
        root = accept_launcher_journal(journal, authority, authority_hash)
        result['launcherJournalSha256'] = sha(journal)
        for leaf in ('launcher.stdout.bin', 'launcher.stderr.bin'):
            if read(WINDOWS / leaf, 16384, windows_fd, windows_identity):
                raise ValueError('Unexpected controller output')
        started = decode(read(WINDOWS / 'windows-started.json', 65536, windows_fd, windows_identity))
        if started['controllerPid'] != root['pid'] or started['controllerCreationFileTime'] != root['creationFileTime'] or \
                started['controllerSession'] != root['session'] or started['authoritySha256'] != authority_hash:
            raise ValueError('Suspended controller identity join failed')
        result['launcherCompletionAccepted'] = True
        windows_bytes = read(WINDOWS / 'windows-result.json', 262144, windows_fd, windows_identity)
        windows = decode(windows_bytes)
        result['windowsResultSha256'] = sha(windows_bytes)
        if windows['passed'] is not True or windows['quiescent'] is not True or \
                windows['authoritySha256'] != authority_hash or tuple(item['case'] for item in windows['cases']) != CASES or \
                any(item['quiescent'] is not True or item['activeAfterStop'] != 0 or
                    item['stdoutEof'] is not True or item['stderrEof'] is not True for item in windows['cases']):
            raise ValueError('Original fixture Windows outcome failed')
        result['windowsQuiescent'] = True
        result['passed'] = True
    except Exception as error:
        result['failureType'] = type(error).__name__
        if process is not None and process.poll() is None:
            # A cooperative Windows cancel is the only Windows-side failure request.
            # Cgroup cleanup of the Linux proxy never establishes Windows termination.
            if not cancellation_sent:
                try:
                    cancel_original_root(windows_fd, windows_identity)
                    cancellation_sent = True
                except Exception as cancellation_error:
                    result['cancellationFailureType'] = type(cancellation_error).__name__
    finally:
        result['elapsedNanoseconds'] = int((time.monotonic() - began) * 1000000000)
        result['requestedFileBytes'] = read_requested
        result['capturedBytes'] = sum(map(len, captured))
        # Preserve bounded original bytes on failure, without reopening diagnostic files.
        result['proxyStdoutBase64'], result['proxyStderrBase64'] = (
            base64.b64encode(bytes(value)).decode('ascii') for value in captured)
        result['stdoutEof'], result['stderrEof'] = eof
        try:
            result_hash = write_root_json(HISTORY, history_fd, created_history_identity, 'result.json', result)
        finally:
            if windows_fd is not None:
                os.close(windows_fd)
            os.close(history_fd)
    print(json.dumps({'passed': result['passed'], 'continuation_allowed': False,
                      'historyIdentity': created_history_identity, 'startSha256': start_hash,
                      'resultSha256': result_hash}, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
