"""Fixed, single-use clock fixture worker; requires a separately admitted caller.

The caller owns the durable full debit, original deadline, dedicated systemd unit,
materialization, and complete service transport. This worker starts no compiler.
"""

DRAFT_ONLY = True
if DRAFT_ONLY:
    raise RuntimeError('DRAFT_ONLY: clock worker is not admitted')

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

INPUTS = Path('/tmp/windows-clock-handoff0108-inputs')
WINDOWS = Path('/mnt/c/Temp/azureauth-windows-slice-108/named-fixtures-0108')
HISTORY = Path('/var/tmp/azureauth-windows-slice-108/windows-actions/0108')
UNIT = 'azureauth-clock-handoff-108-0108.service'
BEFORE = [20, 105, 4, 157]
AFTER = [20, 106, 4, 161]
LAUNCHER_HASH = '5b018f38669fd6ca3cec8f760533af392e0265280047bfb5c531dd41a349690a'
SENTINEL = b'fixed-diagnostic-collision-sentinel\n'
CASES = ('success', 'diagnostic', 'persistence')
READ_LIMIT = 8 * 1024 * 1024
requested = 0
evidence_deadline = None


class EvidenceLimitError(ValueError):
    pass


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def decode(raw):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError('Duplicate clock-fixture field')
            result[name] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite clock-fixture value')))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def direct(path):
    for item in (path, *path.parents):
        if stat.S_ISLNK(item.lstat().st_mode):
            raise ValueError('Linked clock-fixture input')


def read(path, maximum):
    global requested
    if evidence_deadline is not None and time.monotonic() >= evidence_deadline:
        raise EvidenceLimitError('Original evidence deadline expired')
    direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise ValueError('Clock-fixture file bound')
        if requested + before.st_size + 1 > READ_LIMIT:
            raise EvidenceLimitError('Clock-fixture cumulative read bound')
        requested += before.st_size + 1
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        if len(raw) != before.st_size or identity(before) != identity(os.fstat(fd)) or \
                identity(before) != identity(path.lstat()):
            raise ValueError('Clock-fixture input changed')
        return raw
    finally:
        os.close(fd)


def write(path, raw):
    if len(raw) > 524288:
        raise ValueError('Clock-fixture output bound')
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


def pin(path, value, maximum):
    raw = read(path, maximum)
    if len(raw) != value['bytes'] or sha(raw) != value['sha256']:
        raise ValueError('Clock-fixture component changed')
    return raw


def verify_interop(binding):
    path = Path(binding['path'])
    if path.parent != Path('/run/WSL') or not re.fullmatch(r'[0-9]{1,10}_interop', path.name) or \
            os.environ.get('WSL_INTEROP') != str(path):
        raise ValueError('Clock-fixture interop binding changed')
    direct(path)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or identity(info) != binding['identity']:
        raise ValueError('Clock-fixture interop identity changed')
    return str(path)


def validate_diagnostic(value):
    if set(value) != {'phase', 'line', 'exceptions', 'truncated', 'incomplete'} or \
            value['phase'] != 'clock-reply-validation' or value['incomplete'] is not False or \
            value['truncated'] is not False or not 1 <= len(value['exceptions']) <= 4:
        raise ValueError('Incomplete bounded diagnostic')
    if value['line'] is not None and (type(value['line']) is not int or not 1 <= value['line'] <= 100000):
        raise ValueError('Diagnostic source line bound')
    for frame in value['exceptions']:
        if set(frame) != {'kind', 'hresult', 'nativeCode'} or \
                frame['kind'] not in ('System.Management.Automation.RuntimeException', 'other') or \
                type(frame['hresult']) is not int or not -(2 ** 31) <= frame['hresult'] < 2 ** 31 or \
                frame['nativeCode'] is not None:
            raise ValueError('Unexpected controlled first cause')


def accept_journal(raw, authority, authority_hash):
    records = [decode(line) for line in raw.splitlines()]
    expected = ('bootstrap', 'job-ready', 'root-suspended', 'resume-requested', 'resumed',
                'completed', 'capture', 'capture', 'launcher-exit')
    if tuple(x['event'] for x in records) != expected:
        raise ValueError('Original launcher journal is not complete normal execution')
    times = [x['elapsedMilliseconds'] for x in records]
    if any(type(x) is not int or not 0 <= x < 340000 for x in times) or times != sorted(times):
        raise ValueError('Original launcher clock mismatch')
    owner, ready, root = records[:3]
    for item in (owner, root):
        if type(item['pid']) is not int or item['pid'] <= 0 or type(item['session']) is not int or \
                item['session'] < 0 or not re.fullmatch(r'[1-9][0-9]{1,19}', item['creationFileTime']):
            raise ValueError('Original launcher identity missing')
    if owner['authoritySha256'] != authority_hash or \
            owner['jobName'] != 'Local\\azureauth-controller-108-0108-' + authority['launcherSuffix'] or \
            ready['queryAndTerminateAccess'] is not True or root['inJob'] is not True or \
            owner['pid'] == root['pid'] or owner['session'] != root['session']:
        raise ValueError('Original named Job containment mismatch')
    completed = records[5]
    if completed['rootExited'] is not True or completed['rootExitCode'] != 0 or completed['activeProcesses'] != 0 or \
            type(completed['totalProcesses']) is not int or not 4 <= completed['totalProcesses'] <= 32 or \
            completed['stdoutEof'] is not True or completed['stderrEof'] is not True or completed['capturedBytes'] != 0:
        raise ValueError('Original scoped Job completion missing')
    for item, stream in zip(records[6:8], ('stdout', 'stderr'), strict=True):
        if item['stream'] != stream or item['initialized'] is not True or item['readBytes'] != 0 or \
                item['confirmedFlushedBytes'] != 0 or item['eof'] is not True or item['overflowDetected'] is not False or \
                any(item[k] is not None for k in ('failureStage', 'failureType', 'failureHresult',
                                                'failureNativeError', 'closeFailureType')):
            raise ValueError('Original launcher capture incomplete')
    if records[-1]['passed'] is not True or records[-1]['capturedBytes'] != 0:
        raise ValueError('Original launcher terminal mismatch')
    return root


def snapshot_outputs():
    # This is the sole fixed snapshot of this new invocation, on success or failure.
    limits = {name: 16384 for name in ('launcher.jsonl', 'launcher.stdout.bin', 'launcher.stderr.bin')}
    for leaf in ('windows-started.json', 'windows-result.json'):
        limits[leaf] = limits[leaf + '.pending'] = 8192
    limits['cancel'] = 128
    for case in CASES:
        names = ['clock-ready.json', 'clock-remaining.json', 'controller-startup-failure.json', 'transport.json']
        if case == 'success':
            names += ['reader.json', 'bootstrap-reader.json', 'release.json']
        for name in names:
            limits[f'{case}/{name}'] = limits[f'{case}/{name}.pending'] = 8192
    entries = {}
    exhausted = False
    for relative, maximum in limits.items():
        if exhausted or requested >= READ_LIMIT or time.monotonic() >= evidence_deadline:
            exhausted = True
            entries[relative] = {'status': 'not-attempted', 'reason': 'original-evidence-limit'}
            continue
        path = WINDOWS / relative
        try:
            raw = read(path, maximum)
            entries[relative] = {'status': 'present', 'present': True, 'bytes': len(raw), 'sha256': sha(raw),
                                 'base64': base64.b64encode(raw).decode(), 'identity': identity(path.lstat())}
        except FileNotFoundError:
            entries[relative] = {'status': 'absent-at-observation', 'present': False}
        except EvidenceLimitError:
            exhausted = True
            entries[relative] = {'status': 'error', 'errorType': 'EvidenceLimitError'}
        except (OSError, ValueError) as error:
            entries[relative] = {'status': 'error', 'errorType': type(error).__name__}
    return entries


def main():
    global evidence_deadline
    if len(sys.argv) != 2 or not re.fullmatch(r'[0-9a-f]{64}', sys.argv[1]):
        raise ValueError('Fixed clock authority hash required')
    authority_hash = sys.argv[1]
    raw = read(INPUTS / 'authority.json', 65536)
    authority = decode(raw)
    if sha(raw) != authority_hash or encode(authority) != raw or authority['schema'] != 'clock-handoff-0108-v1' or \
            authority['accepted'] is not True or authority['action'] != '0108' or authority['countsBefore'] != BEFORE or \
            authority['countsAfter'] != AFTER or authority['buildTestCharge'] != 1 or authority['syntheticCharge'] != 4:
        raise ValueError('Unaccepted clock allocation')
    pin(Path(__file__), authority['worker'], 65536)
    start = decode(read(HISTORY / 'started.json', 8192))
    if start['authoritySha256'] != authority_hash or start['countsBefore'] != BEFORE or start['countsAfter'] != AFTER or \
            start['charge'] != [0, 1, 0, 4] or start['unit'] != UNIT:
        raise ValueError('Original full debit is missing')
    original_deadline = start['deadlineMonotonicNs'] / 1_000_000_000
    if type(start['deadlineMonotonicNs']) is not int or type(start['startedMonotonicNs']) is not int or \
            start['deadlineMonotonicNs'] - start['startedMonotonicNs'] != 430_000_000_000 or \
            not 0 < original_deadline - time.monotonic() <= 430:
        raise ValueError('Original caller deadline changed')
    evidence_deadline = original_deadline - 5
    group_raw = Path('/proc/self/cgroup').read_bytes()
    if len(group_raw) > 4096:
        raise ValueError('Own cgroup bound')
    groups = [line[3:] for line in group_raw.decode('ascii').splitlines() if line.startswith('0::')]
    if len(groups) != 1 or Path(groups[0]).name != UNIT:
        raise ValueError('Original dedicated cgroup missing')
    write(HISTORY / 'worker-entered.json', encode({'authoritySha256': authority_hash, 'cgroup': groups[0]}))
    began = time.monotonic()
    work_end = min(original_deadline - 60, began + 330)
    cancelled = [False]
    signal.signal(signal.SIGTERM, lambda *_: cancelled.__setitem__(0, True))
    signal.signal(signal.SIGINT, lambda *_: cancelled.__setitem__(0, True))
    result = {'schema': 'clock-handoff-worker-result-v1', 'authoritySha256': authority_hash,
              'countsAfter': AFTER, 'passed': False, 'scopedJobClosed': False,
              'proxyExit': None, 'stdoutEof': False, 'stderrEof': False, 'failureType': None,
              'secondaryErrors': [], 'transportPersisted': False, 'snapshotPersisted': False,
              'launchAttempted': False}
    process = None
    captured = [bytearray(), bytearray()]
    eof = [False, False]
    observed = [0, 0]
    overflow = [False, False]
    read_error = [None, None]
    replies = {}

    def note_failure(stage, error):
        result['passed'] = False
        if result['failureType'] is None:
            result['failureType'] = type(error).__name__
            result['failureStage'] = stage
        elif len(result['secondaryErrors']) < 8:
            result['secondaryErrors'].append({'stage': stage, 'errorType': type(error).__name__})

    def drain_stream(index, stream):
        if eof[index] or read_error[index] is not None:
            return
        if sum(observed) >= 1048576:
            read_error[index] = 'capture-observation-limit'
            raise ValueError('Capture observation ceiling')
        try:
            chunk = os.read(stream.fileno(), min(4096, 1048576 - sum(observed)))
        except BlockingIOError:
            return
        except OSError as error:
            read_error[index] = type(error).__name__
            raise
        if not chunk:
            eof[index] = True
            return
        observed[index] += len(chunk)
        remaining = max(0, 16384 - sum(map(len, captured)))
        captured[index].extend(chunk[:remaining])
        if len(chunk) > remaining:
            overflow[index] = True
            raise ValueError('Native proxy output overflow')
    try:
        if read(WINDOWS / 'authority.json', 65536) != raw:
            raise ValueError('Windows authority copy changed')
        launcher = read(WINDOWS / 'WindowsScriptJobLauncher.exe', 65536)
        if len(launcher) != 23040 or sha(launcher) != LAUNCHER_HASH:
            raise ValueError('Original normal launcher artifact changed')
        if sha(read(WINDOWS / 'Invoke-WindowsNamedGuardFixtures.ps1', 65536)) != authority['harnessSha256']:
            raise ValueError('Clock harness changed')
        for role in ('bootstrap', 'controller'):
            pin(WINDOWS / (role + '.source.txt'), authority['extraction'][role], 131072)
        helpers = pin(INPUTS / 'clock_handoff_cases.py', authority['cases'], 65536)
        fixture = {'__name__': 'fixed_clock_fixture'}
        exec(compile(helpers, '<fixed-clock-cases>', 'exec'), fixture)
        publisher_raw = pin(INPUTS / 'publisher.source.txt', authority['extraction']['publisher'], 262144)
        namespace = fixture['publisher_namespace'](publisher_raw, authority['extraction']['publisher'])
        producer = fixture['run_producer_cases'](WINDOWS, namespace, min(work_end, began + 25))
        write(HISTORY / 'producer-cases.json', encode(producer))
        if time.monotonic() - began >= 30 or cancelled[0]:
            raise TimeoutError('Clock fixture preflight expired')
        interop = verify_interop(authority['wslInterop'])
        command = [str(WINDOWS / 'WindowsScriptJobLauncher.exe'),
                   r'C:\Temp\azureauth-windows-slice-108\named-fixtures-0108',
                   authority['launcherSuffix'], authority_hash, authority['harnessSha256']]
        result['launchAttempted'] = True
        process = subprocess.Popen(command, cwd=WINDOWS, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'WSL_INTEROP': interop,
                                        'WSLENV': 'PSModuleAnalysisCachePath/w', 'PSModuleAnalysisCachePath': 'NUL'})
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        while time.monotonic() < work_end:
            if cancelled[0]:
                raise InterruptedError('Clock fixture cancelled')
            for case in CASES:
                path = WINDOWS / case
                if case not in replies and (path / 'clock-ready.json').exists():
                    ready_raw = read(path / 'clock-ready.json', 4096)
                    ready = decode(ready_raw)
                    if ready['schema'] != 'final-publish-clock-ready-v1' or ready['action'] != '0108' or \
                            ready['reservationSha256'] != authority['reservationSha256'] or \
                            ready['invocationSha256'] != authority['invocationSha256'] or ready['endpoint'] != authority['endpoint']:
                        raise ValueError('Synthetic readiness identity changed')
                    if case == 'persistence':
                        write(path / 'controller-startup-failure.json', SENTINEL)
                    reply = {'schema': 'final-publish-clock-remaining-v1', 'action': '0108',
                             'reservationSha256': authority['reservationSha256'],
                             'invocationSha256': authority['invocationSha256'], 'endpoint': authority['endpoint'],
                             'readySha256': sha(ready_raw) if case == 'success' else '0' * 64,
                             'remainingMilliseconds': min(120000, int((work_end - time.monotonic()) * 1000))}
                    reply_raw = encode(reply)
                    namespace['publish_clock_reply'](path, reply_raw, min(work_end, time.monotonic() + 20), lambda: cancelled[0])
                    replies[case] = {'readySha256': sha(ready_raw), 'replySha256': sha(reply_raw),
                                     'deadlineCounter': ready['windowsReadyCounter'] +
                                     reply['remainingMilliseconds'] * ready['windowsClockFrequency'] // 1000 - 1}
            for index, stream in enumerate((process.stdout, process.stderr)):
                drain_stream(index, stream)
            if process.poll() is not None and all(eof):
                break
            time.sleep(0.025)
        if process.poll() != 0 or not all(eof) or any(captured) or set(replies) != set(CASES):
            raise ValueError('Native proxy did not complete the fixed cases')
        result['replies'] = replies
        result['passed'] = True
    except (OSError, ValueError, RuntimeError, AssertionError, KeyError) as error:
        note_failure('worker', error)
    finally:
        if process is not None and (process.poll() is None or not all(eof)):
            # Request cancellation only through this fresh owned root. Never reopen
            # an old process, Job or service; let the original launcher own cleanup.
            try:
                write(WINDOWS / 'cancel', b'fixed-clock-cancel\n')
            except (OSError, ValueError) as error:
                note_failure('cancel-persistence', error)
            end = min(original_deadline - 10, time.monotonic() + 40)
            while time.monotonic() < end and (process.poll() is None or not all(eof)):
                for index, stream in enumerate((process.stdout, process.stderr)):
                    try:
                        drain_stream(index, stream)
                    except (OSError, ValueError) as error:
                        note_failure('failure-drain', error)
                time.sleep(0.025)
        result['proxyExit'] = None if process is None else process.poll()
        result['stdoutEof'], result['stderrEof'] = eof
        capture_complete = all(eof) and not any(overflow) and all(x is None for x in read_error)
        result['captureComplete'] = capture_complete
        transport = {'exitCode': result['proxyExit'], 'eof': eof, 'observedBytes': observed,
                     'retainedBytes': list(map(len, captured)), 'overflow': overflow,
                     'truncated': [observed[i] != len(captured[i]) for i in range(2)],
                     'readError': read_error, 'captureComplete': capture_complete,
                     'stdoutBase64': base64.b64encode(captured[0]).decode(),
                     'stderrBase64': base64.b64encode(captured[1]).decode()}
        try:
            if time.monotonic() >= evidence_deadline:
                raise EvidenceLimitError('Original finalization deadline expired')
            write(HISTORY / 'proxy-transport.json', encode(transport))
            result['transportPersisted'] = True
        except (OSError, ValueError) as error:
            note_failure('transport-persistence', error)
        entries = {}
        try:
            entries = snapshot_outputs()
            if time.monotonic() >= evidence_deadline:
                raise EvidenceLimitError('Original snapshot persistence deadline expired')
            write(HISTORY / 'snapshot.json', encode({'schema': 'clock-handoff-fixed-snapshot-v1', 'entries': entries}))
            result['snapshotPersisted'] = True
        except (OSError, ValueError) as error:
            note_failure('snapshot-persistence', error)
        if not capture_complete:
            note_failure('capture-completion', ValueError('Original capture incomplete'))
        if result['passed']:
            try:
                def raw_leaf(name):
                    item = entries[name]
                    if item['present'] is not True:
                        raise ValueError('Required original clock evidence absent')
                    return base64.b64decode(item['base64'], validate=True)
                root_identity = accept_journal(raw_leaf('launcher.jsonl'), authority, authority_hash)
                started = decode(raw_leaf('windows-started.json'))
                if any(started[k] != root_identity[k] for k in ('pid', 'creationFileTime', 'session')) or \
                        started['authoritySha256'] != authority_hash:
                    raise ValueError('Original suspended harness identity mismatch')
                windows = decode(raw_leaf('windows-result.json'))
                if windows['authoritySha256'] != authority_hash or windows['passed'] is not True or \
                        windows['completedCases'] != list(CASES) or windows['failureDiagnostic'] is not None:
                    raise ValueError('Windows clock cases incomplete')
                if raw_leaf('launcher.stdout.bin') or raw_leaf('launcher.stderr.bin'):
                    raise ValueError('Unexpected original launcher capture')
                for name in ('success/reader.json', 'success/bootstrap-reader.json'):
                    clock = decode(raw_leaf(name))
                    if any(clock[k] != replies['success'][k] for k in replies['success']):
                        raise ValueError('Reader hash or integer deadline mismatch')
                for case in CASES:
                    pending, final = [entries[f'{case}/clock-remaining.json' + suffix] for suffix in ('.pending', '')]
                    if pending['sha256'] != replies[case]['replySha256'] or final['sha256'] != pending['sha256'] or \
                            pending['identity'][:2] != final['identity'][:2] or pending['identity'][-1] != 2 or final['identity'][-1] != 2:
                        raise ValueError('Original complete aliases disagree')
                diagnostics = []
                for case in ('diagnostic', 'persistence'):
                    transport = decode(raw_leaf(case + '/transport.json'))
                    frame = decode(base64.b64decode(transport['stderrBase64'], validate=True))
                    validate_diagnostic(frame)
                    receipt_name = case + '/controller-startup-failure.json' + ('.pending' if case == 'persistence' else '')
                    receipt = decode(raw_leaf(receipt_name))
                    if receipt['schema'] != 'final-publish-controller-startup-failure-v1' or receipt['action'] != '0108' or \
                            receipt['reservationSha256'] != authority['reservationSha256'] or \
                            receipt['invocationSha256'] != authority['invocationSha256'] or receipt['failureDiagnostic'] != frame or \
                            any(receipt[k] is not False for k in ('enteredCandidate', 'normalCompletion', 'continuationAllowed')):
                        raise ValueError('First cause or failed-candidate binding mismatch')
                    diagnostics.append(frame)
                if diagnostics[0] != diagnostics[1] or raw_leaf('persistence/controller-startup-failure.json') != SENTINEL:
                    raise ValueError('Persistence failure replaced first cause or collision sentinel')
                result['scopedJobClosed'] = True
            except (OSError, ValueError, KeyError) as error:
                note_failure('outcome-validation', error)
        try:
            if time.monotonic() >= evidence_deadline:
                raise EvidenceLimitError('Original result persistence deadline expired')
            write(HISTORY / 'worker-result.json', encode(result))
        except (OSError, ValueError) as error:
            note_failure('worker-result-persistence', error)
            # One fixed bounded fallback; no messages, paths, retry or fresh clock.
            sys.stderr.write('Clock fixture result persistence failed; retain the original full debit.\n')
    return 0 if result['passed'] and result['scopedJobClosed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
