"""One admitted infrastructure-only systemd lifecycle check for Issue #108.

The accepted Windows Slice protocol and independent exact-source admission are
required before --execute. This script grants no authority and never runs a build,
Windows process, authentication command, or original experiment helper.
"""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid


ROOT = Path('/var/tmp/azureauth-systemd-supervision-108-0001')
CASES = ('success', 'command-failure', 'descendant-timeout', 'client-loss')
RUNTIME_SECONDS = 3
STOP_SECONDS = 2
CASE_SECONDS = 15
OUTPUT_BYTES = 16384
TOOLS = {
    '/usr/bin/timeout': '48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0',
    '/usr/bin/systemd-run': '03a68bafb0ebc0f5eff41cbdf3cbbdf126a3bb87e21140f9147bf78edce36d88',
    '/usr/bin/env': '48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0',
    '/usr/bin/python3': '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41',
    '/usr/lib/systemd/systemd': '3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3',
}


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new(path, value):
    pending = path.with_name(path.name + '.pending')
    with pending.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.link(pending, path)
    pending.unlink()
    sync_directory(path.parent)


def identity():
    # These are exclusively the controlled fixture's own Linux identities.
    fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
    group = Path('/proc/self/cgroup').read_text().splitlines()
    group = [line[3:] for line in group if line.startswith('0::')]
    if len(group) != 1:
        raise RuntimeError('Unified cgroup membership unavailable')
    return {'pid': os.getpid(), 'startTicks': int(fields[19]),
            'cgroup': group[0], 'observedMonotonicNs': time.monotonic_ns()}


def fixture(role, case, directory):
    if case not in CASES or directory != ROOT / case or role not in ('root', 'leaf'):
        raise ValueError('Unknown fixture')
    if role == 'leaf':
        os.setsid()
        if case != 'success':
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        write_new(directory / 'leaf.json', identity())
        time.sleep(0.5 if case == 'success' else 30)
        print('leaf-finished', flush=True)
        return 0
    write_new(directory / 'root.json', identity())
    if case == 'command-failure':
        return 7
    # The child changes session; process-group-only cleanup would miss it.
    subprocess.Popen([sys.executable, '-I', '-S', str(Path(__file__).resolve()),
                      '--fixture', 'leaf', case, str(directory)],
                     stdin=subprocess.DEVNULL)
    return 0


def group_empty(group, unit):
    parts = Path(group).parts
    if not group.startswith('/') or '..' in parts or parts[-1] != unit:
        raise ValueError('Unexpected owned cgroup')
    events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
    try:
        values = dict(line.split() for line in events.read_text().splitlines())
    except FileNotFoundError:
        # The fixture already recorded this unique unit's membership. The kernel
        # permits removal of its cgroup only after its processes have exited.
        return True
    return values.get('populated') == '0'


def run_case(case, run_id, source, environment):
    directory = ROOT / case
    directory.mkdir(mode=0o700)
    sync_directory(ROOT)
    unit = f'azureauth-supervision-108-{run_id}-{case}.service'
    command = [
        '/usr/bin/systemd-run', '--user', '--no-ask-password', '--quiet',
        '--wait', '--pipe', '--collect', '--expand-environment=no', '--job-mode=fail', '--unit=' + unit,
        '--service-type=exec', '--property=ExitType=cgroup',
        '--property=KillMode=control-group', '--property=SendSIGKILL=yes',
        '--property=Restart=no', '--property=TimeoutStartSec=3s',
        '--property=RuntimeMaxSec=3s', '--property=TimeoutStopSec=2s',
        '--working-directory=' + str(directory), '--',
        '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C.UTF-8',
        '/usr/bin/python3', '-I', '-S', str(source), '--fixture', 'root', case, str(directory),
    ]
    began = time.monotonic()
    end = began + CASE_SECONDS
    write_new(directory / 'started.json', {'case': case, 'unit': unit, 'command': command,
                                         'startedMonotonicNs': time.monotonic_ns()})
    process = None
    result = {'case': case, 'passed': False, 'clientExit': None,
              'clientKilled': False, 'groupEmpty': False, 'failure': None}
    output_path = directory / 'output.txt'
    try:
        with output_path.open('xb', buffering=0) as output:
            if time.monotonic() >= end - 2:
                raise TimeoutError('Observation budget exhausted before start')
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       env=environment)
            # Keep this client in the outer timeout's process group. The manager
            # starts the separately supervised fixture; it inherits this pipe.
            os.set_blocking(process.stdout.fileno(), False)
            captured = bytearray()
            eof = False
            root = leaf = None
            while time.monotonic() < end - 2:
                if not eof:
                    try:
                        chunk = os.read(process.stdout.fileno(),
                                        min(4096, OUTPUT_BYTES - len(captured) + 1))
                    except BlockingIOError:
                        chunk = None
                    if chunk == b'':
                        eof = True
                    elif chunk:
                        retained = chunk[:OUTPUT_BYTES - len(captured)]
                        output.write(retained)
                        captured.extend(retained)
                        if len(retained) != len(chunk):
                            raise RuntimeError('Output limit')
                if root is None and (directory / 'root.json').exists():
                    root = json.loads((directory / 'root.json').read_text())
                if leaf is None and (directory / 'leaf.json').exists():
                    leaf = json.loads((directory / 'leaf.json').read_text())
                ready = root is not None and (case == 'command-failure' or leaf is not None)
                if ready and leaf is not None and root['cgroup'] != leaf['cgroup']:
                    raise RuntimeError('Descendant left unit')
                if ready and case == 'client-loss' and not result['clientKilled']:
                    if process.poll() is not None or group_empty(root['cgroup'], unit):
                        raise RuntimeError('Client-loss fixture ended before intervention')
                    process.kill()
                    process.wait(timeout=min(2, max(0.001, end - time.monotonic())))
                    result['clientKilled'] = True
                result['clientExit'] = process.poll()
                if ready and result['clientExit'] is not None:
                    result['groupEmpty'] = group_empty(root['cgroup'], unit)
                    if result['groupEmpty'] and eof:
                        break
                if result['clientExit'] is not None and not ready:
                    raise RuntimeError('Fixture did not initialize')
                time.sleep(0.025)
            if not result['groupEmpty'] or process.poll() is None or not eof:
                raise TimeoutError('Lifecycle did not complete')
            os.fsync(output.fileno())
            code = result['clientExit']
            elapsed = time.monotonic() - began
            if time.monotonic() >= end:
                raise TimeoutError('Observation budget exhausted before acceptance')
            if case == 'success':
                passed = code == 0 and captured == b'leaf-finished\n'
            elif case == 'command-failure':
                passed = code == 7 and captured == b''
            elif case == 'descendant-timeout':
                passed = code == 1 and elapsed >= RUNTIME_SECONDS and captured == b''
            else:
                passed = (code == -signal.SIGKILL and result['clientKilled'] and
                          elapsed >= RUNTIME_SECONDS and captured == b'')
            result['passed'] = passed
            if not passed:
                result['failure'] = 'UnexpectedOutcome'
    except BaseException as error:
        result['failure'] = type(error).__name__
    finally:
        # This is only our systemd-run client. Its unit retains its independent
        # manager deadline. Never signal a PID recovered from fixture evidence.
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=min(2, max(0.001, end - time.monotonic())))
            except subprocess.TimeoutExpired:
                result['failure'] = 'ClientReapTimeout'
        if process is not None and process.stdout is not None:
            process.stdout.close()
        if time.monotonic() >= end:
            result['failure'] = 'CaseBudgetExpired'
        if result['failure'] is not None:
            result['passed'] = False
        result['elapsedMilliseconds'] = int((time.monotonic() - began) * 1000)
        write_new(directory / 'result.json', result)
    return result


def execute():
    # The root is a one-use attempt marker. Never resume or replace it.
    ROOT.mkdir(mode=0o700)
    sync_directory(ROOT.parent)
    began = time.monotonic_ns()
    write_new(ROOT / 'started.json', {'buildTestCharge': 1, 'priorCombinedBuildTest': 88,
                                     'syntheticProcessCharge': 4, 'priorSyntheticProcess': 48,
                                     'cases': CASES, 'startedMonotonicNs': began})
    results = []
    failure = None
    try:
        for path, expected in TOOLS.items():
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
                raise ValueError('Installed tool changed')
        source = Path(__file__).resolve()
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        write_new(ROOT / 'source.json', {'sha256': before,
                  'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
        runtime = f'/run/user/{os.getuid()}'
        environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8',
                       'XDG_RUNTIME_DIR': runtime, 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus'}
        run_id = uuid.uuid4().hex
        for case in CASES:
            result = run_case(case, run_id, source, environment)
            results.append(result)
            if not result['passed']:
                break
        if hashlib.sha256(source.read_bytes()).hexdigest() != before:
            raise ValueError('Source changed')
    except BaseException as error:
        failure = type(error).__name__
    passed = failure is None and len(results) == len(CASES) and all(r['passed'] for r in results)
    summary = {'passed': passed, 'failure': failure, 'cases': results,
               'buildTestCharge': 1, 'combinedBuildTestAfter': 89,
               'syntheticProcessCharge': 4, 'syntheticProcessAfter': 52,
               'elapsedMilliseconds': (time.monotonic_ns() - began) // 1_000_000}
    write_new(ROOT / 'result.json', summary)
    print(json.dumps(summary, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--fixture':
        raise SystemExit(fixture(sys.argv[2], sys.argv[3], Path(sys.argv[4])))
    if sys.argv[1:] == ['--execute']:
        raise SystemExit(execute())
    raise SystemExit('Use only the exact command in the accepted protocol and source admission.')
