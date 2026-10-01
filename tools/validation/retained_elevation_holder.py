"""Fixed retained-entry holder. No command queue; no authentication or ETW."""

import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import signal
import stat
import subprocess
import sys
import time

EXECUTION_ADMITTED = False
LIMIT = 16384
EPOCH = 116444736000000000


def boot():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def direct(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Literal path required')
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError('Linked path')
    return path


def read(path, maximum, expected=None):
    path = direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise ValueError('Input type or size')
        raw = stream.read(maximum + 1)
        if len(raw) != before.st_size or identity(before) != identity(os.fstat(stream.fileno())) or \
                identity(before) != identity(path.lstat()):
            raise ValueError('Input changed')
    if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Input hash')
    return raw


LINUX_EXECUTABLES = {'/usr/bin/env': 33554432, '/usr/bin/python3.14': 33554432,
                    '/usr/bin/systemd-run': 33554432, '/usr/bin/systemctl': 33554432}


def linux_executable_pin(logical, check_clock=lambda: None):
    # Only these four roles admit bounded terminal aliases. Ancestors never do.
    if logical not in LINUX_EXECUTABLES:
        raise ValueError('Linux executable selection')
    maximum = LINUX_EXECUTABLES[logical]
    current = logical
    held = []
    aliases = []
    directories = []
    leaf = None
    try:
        for _ in range(5):
            check_clock()
            p = Path(current)
            if not p.is_absolute() or '..' in p.parts or len(json.dumps(current).encode('ascii')) > 1024:
                raise ValueError('Executable path bound')
            directory = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            directories.append(directory)
            for part in p.parts[1:-1]:
                check_clock()
                directory = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=directory)
                directories.append(directory)
            leaf = os.open(p.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            first = identity(os.fstat(leaf))
            held.append((directory, p.name, leaf, first))
            leaf = None
            if stat.S_ISLNK(first[2]):
                if len(aliases) == 4 or not 0 < first[6] <= 1024:
                    raise ValueError('Executable alias bound')
                link = os.readlink('', dir_fd=held[-1][2])
                if len(os.fsencode(link)) != first[6] or len(json.dumps(link).encode('ascii')) > 1024:
                    raise ValueError('Executable link bound')
                absolute = link.startswith('/')
                components = link.split('/')[1:] if absolute else link.split('/')
                if any(part in ('', '.') for part in components):
                    raise ValueError('Executable link syntax')
                ascents = 0
                if not absolute:
                    while ascents < len(components) and components[ascents] == '..':
                        ascents += 1
                if ascents > len(p.parent.parts) - 1 or ascents == len(components) or \
                        '..' in components[ascents:]:
                    raise ValueError('Executable link ascent')
                # Only the already held no-follow parent chain may be collapsed.
                # Every newly supplied suffix ancestor is walked on the next hop.
                aliases.append({'path': current, 'identity': first, 'link': link})
                if len(json.dumps(aliases).encode('ascii')) > 2048:
                    raise ValueError('Executable alias metadata bound')
                current = posixpath.normpath(posixpath.join(str(p.parent), link))
                continue
            if not stat.S_ISREG(first[2]) or not 0 < first[6] <= maximum:
                raise ValueError('Executable type or size')
            leaf = os.open(p.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=directory)
            if identity(os.fstat(leaf)) != first:
                raise ValueError('Executable replaced')
            digest = hashlib.sha256()
            count = 0
            while count < first[6]:
                check_clock()
                requested = min(65536, first[6] - count)
                raw = os.read(leaf, requested)
                if len(raw) != requested:
                    raise ValueError('Short executable')
                count += len(raw)
                digest.update(raw)
            check_clock()
            if os.read(leaf, 1) != b'' or identity(os.fstat(leaf)) != first:
                raise ValueError('Executable changed')
            for index, (parent, name, descriptor, original) in enumerate(held):
                check_clock()
                if identity(os.fstat(descriptor)) != original or \
                        identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != original:
                    raise ValueError('Executable mapping changed')
                # Bind the absolute name as well as each held-parent-relative name.
                direct(Path(aliases[index]['path'] if index < len(aliases) else current).parent)
                named = aliases[index]['path'] if index < len(aliases) else current
                if identity(Path(named).lstat()) != original:
                    raise ValueError('Executable named object changed')
                if index < len(aliases) and os.readlink('', dir_fd=descriptor) != aliases[index]['link']:
                    raise ValueError('Executable alias changed')
            result = {'path': logical, 'type': 'regular', 'resolvedPath': current, 'aliases': aliases,
                      'identity': first, 'bytes': count, 'sha256': digest.hexdigest(),
                      'readBytes': count, 'requestedBytes': count + 1, 'eof': True, 'passed': True}
            if len(json.dumps(result).encode('ascii')) > 4096:
                raise ValueError('Executable metadata bound')
            return result
        raise ValueError('Executable alias depth')
    finally:
        if leaf is not None:
            os.close(leaf)
        for _, _, descriptor, _ in reversed(held):
            os.close(descriptor)
        for directory in reversed(directories):
            os.close(directory)


def write(path, raw):
    path = direct(path)
    if len(raw) > 65536:
        raise ValueError('Evidence limit')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def record(path, value):
    write(path, (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii'))


def virtual(path):
    with open(path, 'rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError('Own-process record limit')
    return raw.decode('ascii')


def stop(root, nonce):
    try:
        info = (root / 'stop').lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('Stop marker type')
    return True


def request_stop(root, nonce):
    try:
        (root / 'stop').mkdir(mode=0o700)
    except FileExistsError:
        if not stop(root, nonce):
            raise


def capture_check(argv, root):
    # The native parent separately holds and observes the actual Windows child.
    began = boot()
    child = None
    streams = []
    result = {'exitCode': None, 'eof': [False, False], 'bytes': [0, 0], 'failure': None}
    data = [bytearray(), bytearray()]
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, cwd=root, env=dict(os.environ))
        streams = [child.stdout, child.stderr]
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        while boot() < began + 10:
            for index, stream in enumerate(streams):
                if result['eof'][index]:
                    continue
                try:
                    chunk = os.read(stream.fileno(), min(4096, LIMIT + 1 - len(data[index])))
                except BlockingIOError:
                    continue
                if not chunk:
                    result['eof'][index] = True
                data[index].extend(chunk)
                if len(data[index]) > LIMIT:
                    raise ValueError('Context output limit')
            result['exitCode'] = child.poll()
            if result['exitCode'] is not None and all(result['eof']):
                break
            time.sleep(0.025)
        if result['exitCode'] != 0 or not all(result['eof']):
            raise RuntimeError('Context check incomplete')
    except BaseException as error:
        result['failure'] = type(error).__name__
    finally:
        if child is not None:
            try:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=max(0.001, began + 15 - boot()))
                result['exitCode'] = child.returncode
            except BaseException as error:
                result['failure'] = result['failure'] or type(error).__name__
        for stream in streams:
            stream.close()
        for index, name in enumerate(('context.stdout.bin', 'context.stderr.bin')):
            result['bytes'][index] = len(data[index])
            write(root / name, bytes(data[index][:LIMIT]))
    result['elapsedSeconds'] = boot() - began
    record(root / 'context-transport.json', result)
    if result['failure'] or result['exitCode'] != 0 or not all(result['eof']) or result['elapsedSeconds'] >= 15:
        raise RuntimeError('Context transport failed')


def main(nonce, manifest_hash, deadline_filetime):
    root = direct(Path(__file__).absolute().parent)
    if not re.fullmatch(r'/mnt/c/Temp/azureauth-windows-slice-108/elevation-entry-[0-9]{4}', str(root)) or \
            not re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', nonce) or \
            not re.fullmatch(r'[0-9a-f]{64}', manifest_hash):
        raise ValueError('Entry arguments')
    inputs = read(root / 'entry-inputs.txt', 65536, manifest_hash).decode('ascii').split('\n')
    if len(inputs) != 12 or inputs[0] != 'azureauth-retained-elevation-v1' or inputs[1] != nonce or \
            inputs[10:] != ['END', ''] or int(inputs[4]) != os.getuid() or \
            inputs[9] != '/var/tmp/azureauth-windows-slice-108/' + root.name:
        raise ValueError('Entry manifest')
    read(root / 'retained_elevation_holder.py', 65536, inputs[6])
    read(root / 'RetainedElevationEntry.exe', 2097152, inputs[7])
    deadline_ns = (int(deadline_filetime) - EPOCH) * 100
    remaining = (deadline_ns - time.time_ns()) / 1e9
    if not 20 < remaining <= 86400:
        raise ValueError('Fixed deadline')
    boot_deadline = boot() + remaining
    group = [line[3:] for line in virtual('/proc/self/cgroup').splitlines() if line.startswith('0::')]
    unit = 'azureauth-elevation-108-' + nonce + '.scope'
    if len(group) != 1 or not group[0].startswith('/') or '..' in Path(group[0]).parts or Path(group[0]).name != unit:
        raise ValueError('Holder scope')
    relay = os.environ.get('WSL_INTEROP', '')
    if not re.fullmatch(r'/run/WSL/[1-9][0-9]*_interop', relay) or relay == inputs[8]:
        raise ValueError('Distinct inherited relay required')
    relay_stat = direct(relay).lstat()
    if not stat.S_ISSOCK(relay_stat.st_mode):
        raise ValueError('Relay socket required')
    local = direct(inputs[9])
    fields = virtual('/proc/self/stat').rsplit(')', 1)[1].split()
    start = {'nonce': nonce, 'pid': os.getpid(), 'startTicks': int(fields[19]), 'scope': unit,
             'cgroup': group[0], 'relay': relay, 'relayIdentity': identity(relay_stat),
             'deadlineFileTime': deadline_filetime, 'deadlineBoot': boot_deadline,
             'manifestSha256': manifest_hash}
    record(local / 'holder-start.json', start)
    failed = None
    requested = False
    def signal_stop(_signum, _frame):
        nonlocal requested
        requested = True
    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGINT, signal_stop)
    try:
        if stop(root, nonce):
            raise RuntimeError('Entry already stopped')
        windows_root = 'C:\\Temp\\azureauth-windows-slice-108\\' + root.name
        capture_check([str(root / 'RetainedElevationEntry.exe'), '--context-check', windows_root,
                       nonce, manifest_hash], root)
        (root / 'linux-ready').mkdir(mode=0o700)
        # No further child dispatch. The stop marker is checked at most once a second.
        for _ in range(86400):
            if requested or stop(root, nonce) or boot() >= boot_deadline - 20 or time.time_ns() >= deadline_ns - 20000000000:
                break
            time.sleep(1)
    except BaseException as error:
        failed = type(error).__name__
    finally:
        request_stop(root, nonce)
        record(local / 'holder-final.json', {'nonce': nonce, 'failure': failed, 'stopRequested': True,
                                             'beforeDeadline': boot() < boot_deadline and time.time_ns() < deadline_ns})
    return 0 if failed is None else 1


def bounded_command(argv, seconds):
    began = boot()
    child = None
    data = bytearray()
    result = {'argv': argv, 'exitCode': None, 'eof': False, 'failure': None}
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, env=dict(os.environ))
        os.set_blocking(child.stdout.fileno(), False)
        while boot() < began + seconds - 1:
            try:
                chunk = os.read(child.stdout.fileno(), min(4096, 4097 - len(data)))
            except BlockingIOError:
                chunk = None
            if chunk == b'':
                result['eof'] = True
            if chunk:
                data.extend(chunk)
            if len(data) > 4096:
                raise ValueError('Control output limit')
            result['exitCode'] = child.poll()
            if result['exitCode'] is not None and result['eof']:
                break
            time.sleep(0.025)
        if result['exitCode'] is None or not result['eof']:
            raise TimeoutError('Control deadline')
    except BaseException as error:
        result['failure'] = type(error).__name__
    finally:
        if child is not None:
            try:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=max(0.001, began + seconds - boot()))
                result['exitCode'] = child.returncode
            except BaseException as error:
                result['failure'] = result['failure'] or type(error).__name__
            child.stdout.close()
    result['output'] = data[:4096].decode('utf-8', errors='replace')
    result['observedBytes'] = len(data)
    result['elapsedSeconds'] = boot() - began
    return result


INPUT_CHECK_SLOTS = ('0160', '0162', '0164', '0166', '0168',
                     '0170', '0172', '0174', '0176', '0178')


def input_check_configuration(config, slot):
    keys = {'schema', 'slot', 'acceptedCommit', 'protocolSha256', 'sourceReviewSha256',
            'artifactReviewSha256', 'holderSha256', 'manifestSha256', 'infrastructureSha256',
            'nonce', 'countsBefore', 'countsAfter', 'outsideHostsBefore', 'outsideHostsAfter'}
    if not isinstance(config, dict) or set(config) != keys or \
            config['schema'] != 'windows-retained-entry-input-check-v1' or \
            slot not in INPUT_CHECK_SLOTS or config['slot'] != slot:
        raise ValueError('Input-check configuration')
    if not isinstance(config['acceptedCommit'], str) or not re.fullmatch(r'[0-9a-f]{40}', config['acceptedCommit']):
        raise ValueError('Input-check accepted source')
    for key in ('protocolSha256', 'sourceReviewSha256', 'artifactReviewSha256',
                'holderSha256', 'manifestSha256', 'infrastructureSha256'):
        if not isinstance(config[key], str) or not re.fullmatch(r'[0-9a-f]{64}', config[key]) or \
                config[key] == '0' * 64:
            raise ValueError('Input-check evidence hash')
    if not isinstance(config['nonce'], str) or not re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', config['nonce']):
        raise ValueError('Input-check nonce')
    before, after = config['countsBefore'], config['countsAfter']
    if any(not isinstance(v, list) or len(v) != 4 or any(type(n) is not int or n < 0 for n in v)
           for v in (before, after)):
        raise ValueError('Input-check counts')
    pair_index = INPUT_CHECK_SLOTS.index(slot)
    checks_spent = before[1] - 140
    if not 0 <= checks_spent <= pair_index or \
            before != [34 + pair_index, 140 + checks_spent, 6, 403 + 2 * checks_spent] or \
            after != [before[0], before[1] + 1, before[2], before[3] + 2]:
        raise ValueError('Input-check debit')
    if type(config['outsideHostsBefore']) is not int or type(config['outsideHostsAfter']) is not int or \
            config['outsideHostsBefore'] != 27 + checks_spent or \
            config['outsideHostsAfter'] != 28 + checks_spent or config['outsideHostsAfter'] > 46:
        raise ValueError('Input-check console debit')
    return config


def input_check(slot, nonce, manifest_hash, infrastructure_hash, config_hash, expires_ns):
    # One source-corresponded normal return; a killed proxy never proves native exit.
    began = boot()
    if slot not in INPUT_CHECK_SLOTS or not re.fullmatch(r'[1-9][0-9]{1,19}', expires_ns):
        raise ValueError('Input-check arguments')
    deadline = int(expires_ns) / 1000000000
    if not began < deadline <= began + 25:
        raise ValueError('Input-check absolute deadline')
    root = direct(Path(__file__).absolute().parent)
    if str(root) != '/mnt/c/Temp/azureauth-windows-slice-108/elevation-entry-' + slot:
        raise ValueError('Input-check fixed payload root')
    local = direct('/var/tmp/azureauth-windows-slice-108/windows-actions/retained-elevation-check-' + slot)
    config = input_check_configuration(json.loads(read(local / 'config.json', 65536, config_hash)), slot)
    if (nonce, manifest_hash, infrastructure_hash) != \
            (config['nonce'], config['manifestSha256'], config['infrastructureSha256']):
        raise ValueError('Input-check argument binding')
    record(local / 'original-charge.json', {'slot': slot, 'countsBefore': config['countsBefore'],
                                           'countsAfter': config['countsAfter'], 'configSha256': config_hash,
                                           'outsideHostsBefore': config['outsideHostsBefore'],
                                           'outsideHostsAfter': config['outsideHostsAfter']})
    child = None
    streams = []
    data = [bytearray(), bytearray()]
    eof = [False, False]
    failure = None
    forced = False
    signal_seen = False
    returned = False

    def signal_stop(_signum, _frame):
        nonlocal signal_seen
        signal_seen = True

    def work_budget():
        if signal_seen or boot() >= deadline - 3:
            raise TimeoutError('Input-check work deadline')

    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGINT, signal_stop)
    try:
        work_budget()
        read(Path(__file__), 65536, config['holderSha256'])
        groups = [line[3:] for line in virtual('/proc/self/cgroup').splitlines() if line.startswith('0::')]
        unit = 'azureauth-elevation-inputcheck-108-' + nonce + '.service'
        if len(groups) != 1 or Path(groups[0]).name != unit:
            raise ValueError('Input-check service identity')
        fields = virtual('/proc/self/stat').rsplit(')', 1)[1].split()
        record(local / 'check-start.json', {'slot': slot, 'nonce': nonce, 'pid': os.getpid(),
                                           'startTicks': int(fields[19]), 'cgroup': groups[0],
                                           'configSha256': config_hash, 'deadlineBootNs': expires_ns})
        inputs = read(root / 'entry-inputs.txt', 65536, manifest_hash).decode('ascii').split('\n')
        if len(inputs) != 12 or inputs[0] != 'azureauth-retained-elevation-v1' or inputs[1] != nonce or \
                inputs[10:] != ['END', ''] or inputs[8] != os.environ.get('WSL_INTEROP') or \
                int(inputs[4]) != os.getuid() or inputs[6] != config['holderSha256'] or \
                inputs[9] != '/var/tmp/azureauth-windows-slice-108/' + root.name:
            raise ValueError('Input-check manifest binding')
        infrastructure = json.loads(read(direct(inputs[9]) / 'infrastructure.json', 65536, infrastructure_hash))
        if set(infrastructure) != set(LINUX_EXECUTABLES):
            raise ValueError('Input-check infrastructure selection')
        for name, pin in infrastructure.items():
            work_budget()
            if linux_executable_pin(name, work_budget) != pin:
                raise ValueError('Input-check infrastructure identity')
        work_budget()
        read(root / 'RetainedElevationEntry.exe', 2097152, inputs[7])
        work_budget()
        windows_root = 'C:\\Temp\\azureauth-windows-slice-108\\' + root.name
        child = subprocess.Popen([str(root / 'RetainedElevationEntry.exe'), '--input-check',
                                  windows_root, nonce, manifest_hash], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root,
                                 env=dict(os.environ))
        streams = [child.stdout, child.stderr]
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        for _ in range(2500):
            work_budget()
            for index, stream in enumerate(streams):
                if eof[index]:
                    continue
                try:
                    chunk = os.read(stream.fileno(), min(4096, LIMIT + 1 - len(data[index])))
                except BlockingIOError:
                    continue
                if not chunk:
                    eof[index] = True
                data[index].extend(chunk)
                if len(data[index]) > LIMIT:
                    raise ValueError('Input-check stream overflow')
            if child.poll() is not None and all(eof):
                returned = True
                break
            time.sleep(0.01)
        if not returned:
            raise TimeoutError('Input-check return incomplete')
        if any(data):
            raise ValueError('Unexpected input-check output')
        if child.returncode != 0:
            raise RuntimeError('Input-check predicate rejected')
    except BaseException as error:
        failure = type(error).__name__
    finally:
        if child is not None and child.poll() is None:
            forced = True
            try:
                child.kill()
            except BaseException as error:
                failure = failure or type(error).__name__
            try:
                child.wait(timeout=min(1, max(0.001, deadline - boot())))
            except BaseException as error:
                failure = failure or type(error).__name__
        for stream in streams:
            stream.close()
        # Unexpected stream contents are never persisted as diagnostics.
        for name in ('check.stdout.bin', 'check.stderr.bin'):
            write(local / name, b'')
        code = None if child is None else child.poll()
        normal = returned and not forced and not signal_seen and all(eof) and not any(data) and \
            code in (0, 1, 101, 102, 103, 104, 105, 110, 111, 112, 113, 114, 115, 116,
                     117, 118, 119, 120, 121, 122, 123, 124, 125, 126)
        result = {'slot': slot, 'nonce': nonce, 'configSha256': config_hash,
                  'manifestSha256': manifest_hash, 'proxyStarted': child is not None,
                  'proxyExit': code, 'eof': eof, 'observedBytes': [len(v) for v in data],
                  'forcedProxyTermination': forced, 'signalReceived': signal_seen,
                  'sourceCorrespondedNormalReturn': normal,
                  'nativeLifetimeUnknown': child is not None and not normal,
                  'failure': failure, 'elapsedSeconds': boot() - began,
                  'beforeDeadline': boot() < deadline}
        result['passed'] = normal and code == 0 and failure is None and result['beforeDeadline']
        record(local / 'check-final.json', result)
    # The closed receipt is provisional until persistence and the final clock/signal gate end.
    return 0 if result['passed'] and not signal_seen and boot() < deadline else 1


def transport(nonce, manifest_hash, infrastructure_hash):
    began = boot()
    root = direct(Path(__file__).absolute().parent)
    if not re.fullmatch(r'/mnt/c/Temp/azureauth-windows-slice-108/elevation-entry-[0-9]{4}', str(root)) or \
            not re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', nonce):
        raise ValueError('Transport arguments')
    inputs = read(root / 'entry-inputs.txt', 65536, manifest_hash).decode('ascii').split('\n')
    if len(inputs) != 12 or inputs[0] != 'azureauth-retained-elevation-v1' or inputs[1] != nonce or \
            inputs[10:] != ['END', ''] or inputs[9] != '/var/tmp/azureauth-windows-slice-108/' + root.name or \
            inputs[8] != os.environ.get('WSL_INTEROP') or int(inputs[4]) != os.getuid():
        raise ValueError('Original transport manifest')
    local = direct(inputs[9])
    group = [line[3:] for line in virtual('/proc/self/cgroup').splitlines() if line.startswith('0::')]
    unit = 'azureauth-elevation-transport-108-' + nonce + '.service'
    if len(group) != 1 or Path(group[0]).name != unit:
        raise ValueError('Original transport cgroup')
    infrastructure = json.loads(read(local / 'infrastructure.json', 65536, infrastructure_hash))
    if set(infrastructure) != set(LINUX_EXECUTABLES):
        raise ValueError('Infrastructure selection')
    def check_infrastructure_clock():
        if boot() >= began + 30:
            raise TimeoutError('Infrastructure verification deadline')
    for name, pin in infrastructure.items():
        if linux_executable_pin(name, check_infrastructure_clock) != pin:
            raise ValueError('Infrastructure identity')
    read(root / 'retained_elevation_holder.py', 65536, inputs[6])
    read(root / 'RetainedElevationEntry.exe', 2097152, inputs[7])
    fields = virtual('/proc/self/stat').rsplit(')', 1)[1].split()
    record(local / 'transport-start.json', {'nonce': nonce, 'pid': os.getpid(), 'startTicks': int(fields[19]),
                                           'cgroup': group[0], 'manifestSha256': manifest_hash})
    windows_root = 'C:\\Temp\\azureauth-windows-slice-108\\' + root.name
    scope = 'azureauth-elevation-108-' + nonce + '.scope'
    child = None
    streams = []
    data = [bytearray(), bytearray()]
    eof = [False, False]
    ready = False
    ready_record = None
    holder = None
    failure = None
    stopping = False
    stop_control = None
    scope_control = None
    group_empty = False
    relay_absent = False
    signaled = False
    def signal_stop(_signum, _frame):
        nonlocal signaled
        signaled = True
    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGINT, signal_stop)
    try:
        if stop(root, nonce):
            raise RuntimeError('Entry already stopped')
        child = subprocess.Popen([str(root / 'RetainedElevationEntry.exe'), '--launch', windows_root,
                                  nonce, manifest_hash], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, cwd=root, env=dict(os.environ))
        streams = [child.stdout, child.stderr]
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        for _ in range(86550):
            now = boot()
            for index, stream in enumerate(streams):
                if eof[index]:
                    continue
                try:
                    chunk = os.read(stream.fileno(), min(4096, LIMIT + 1 - len(data[index])))
                except BlockingIOError:
                    continue
                if not chunk:
                    eof[index] = True
                data[index].extend(chunk)
                if len(data[index]) > LIMIT:
                    raise ValueError('Launcher output limit')
            if not ready and (root / 'entry-ready').is_dir():
                direct(root / 'entry-ready')
                ready_record = json.loads(read(root / 'entry-ready.json', 4096))
                holder = json.loads(read(local / 'holder-start.json', 4096))
                if ready_record.get('nonce') != nonce or ready_record.get('contextElevated') is not True or \
                        ready_record.get('contextNativeExited') is not True or holder.get('nonce') != nonce or \
                        holder.get('scope') != scope or not re.fullmatch(r'/run/WSL/[1-9][0-9]*_interop', holder['relay']) or \
                        holder['relay'] == inputs[8] or not holder['cgroup'].startswith('/') or \
                        '..' in Path(holder['cgroup']).parts or Path(holder['cgroup']).name != scope:
                    raise ValueError('Entry readiness binding')
                observed = direct(holder['relay']).lstat()
                if not stat.S_ISSOCK(observed.st_mode) or identity(observed) != holder['relayIdentity']:
                    raise ValueError('Entry relay identity')
                record(local / 'ready.json', {'nonce': nonce, 'entry': ready_record, 'holder': holder})
                ready = True
                print('Retained entry ready; fixed child elevation and native exit observed.', flush=True)
            if not ready and now >= began + 185:
                raise TimeoutError('Entry readiness deadline')
            if now >= began + 86530 or signaled:
                request_stop(root, nonce)
            if stop(root, nonce) and not stopping:
                stopping = True
                # Exact same-user scope only. Complete this before native Job fallback.
                stop_control = bounded_command(['/usr/bin/systemctl', '--user', '--no-ask-password',
                                                'stop', scope], 7)
            if child.poll() is not None and all(eof):
                break
            if now >= began + 86540:
                raise TimeoutError('Original transport deadline')
            time.sleep(1)
        if child.poll() != 0 or not all(eof) or not ready:
            raise RuntimeError('Launcher did not complete successfully')
    except BaseException as error:
        failure = type(error).__name__
    finally:
        request_stop(root, nonce)
        if not stopping:
            stopping = True
            stop_control = bounded_command(['/usr/bin/systemctl', '--user', '--no-ask-password', 'stop', scope], 7)
        if child is not None:
            try:
                if child.poll() is None:
                    child.wait(timeout=min(10, max(0.001, began + 86550 - boot())))
            except BaseException as error:
                failure = failure or type(error).__name__
            if child.poll() is None:
                child.kill()
                try:
                    child.wait(timeout=1)
                except BaseException:
                    pass
                failure = failure or 'ProxyTerminationRequiredNativeLifetimeUnconfirmed'
        # One exact named-unit query covers early failures without holder evidence.
        scope_control = bounded_command(['/usr/bin/systemctl', '--user', '--no-ask-password', 'show', scope,
                                         '--property=LoadState', '--property=ActiveState', '--property=ControlGroup'], 3)
        if scope_control['failure'] is None and scope_control['eof']:
            values = dict(line.split('=', 1) for line in scope_control['output'].splitlines() if '=' in line)
            group_empty = values.get('LoadState') == 'not-found' or \
                values.get('ActiveState') == 'inactive' and values.get('ControlGroup') == ''
        if holder is not None:
            path = Path('/sys/fs/cgroup') / holder['cgroup'].lstrip('/') / 'cgroup.events'
            try:
                values = dict(line.split() for line in virtual(path).splitlines())
                group_empty = group_empty and values.get('populated') == '0'
            except FileNotFoundError:
                pass
            try:
                Path(holder['relay']).lstat()
            except FileNotFoundError:
                relay_absent = True
        for stream in streams:
            stream.close()
        for index, name in enumerate(('launcher.stdout.bin', 'launcher.stderr.bin')):
            write(local / name, bytes(data[index][:LIMIT]))
        result = {'nonce': nonce, 'ready': ready, 'failure': failure, 'groupEmpty': group_empty,
                  'relayAbsent': relay_absent, 'proxyExit': None if child is None else child.poll(),
                  'eof': eof, 'observedBytes': [len(item) for item in data],
                  'stopControl': stop_control, 'scopeControl': scope_control, 'elapsedSeconds': boot() - began}
        result['passed'] = ready and failure is None and group_empty and relay_absent and all(eof)
        record(local / 'transport-final.json', result)
    return 0 if result['passed'] else 1


def closure_configuration(config):
    hashes = {'selectorSha256', 'infrastructureSha256', 'holderSha256', 'observerSha256',
              'frozenSelectorSha256', 'protocolSha256', 'sourceReviewSha256',
              'artifactReviewSha256', 'originSnapshotSha256', 'originOutcomeSha256',
              'originTriageSha256', 'accountingSha256'}
    keys = hashes | {'schema', 'nonce', 'acceptedCommit', 'invokeRelay', 'subjectRelay',
                     'relayIdentity', 'pids', 'creationFileTimes', 'countsBefore',
                     'countsAfter', 'outsideHostsBefore', 'outsideHostsAfter'}
    if not isinstance(config, dict) or set(config) != keys or \
            config['schema'] != 'windows-retained-closure-observation-v1':
        raise ValueError('Closure configuration')
    for key in hashes:
        value = config[key]
        if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) or value == '0' * 64:
            raise ValueError('Closure evidence hash')
    if not isinstance(config['acceptedCommit'], str) or not re.fullmatch(r'[0-9a-f]{40}', config['acceptedCommit']):
        raise ValueError('Closure accepted source')
    if not isinstance(config['nonce'], str) or not re.fullmatch(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}', config['nonce']):
        raise ValueError('Closure nonce')
    for key in ('invokeRelay', 'subjectRelay'):
        if not isinstance(config[key], str) or not re.fullmatch(r'/run/WSL/[1-9][0-9]*_interop', config[key]):
            raise ValueError('Closure relay selection')
    if config['invokeRelay'] == config['subjectRelay']:
        raise ValueError('Subject relay cannot be used for invocation')
    pids, creations, socket = config['pids'], config['creationFileTimes'], config['relayIdentity']
    if not isinstance(pids, list) or len(pids) != 2 or len(set(pids)) != 2 or \
            any(type(v) is not int or not 4 < v <= 0xffffffff for v in pids):
        raise ValueError('Closure PID pair')
    if not isinstance(creations, list) or len(creations) != 2 or \
            any(not isinstance(v, str) or not re.fullmatch(r'[1-9][0-9]{16,18}', v) or
                int(v) > 2650467743999999999 for v in creations):
        raise ValueError('Closure creation pair')
    if not isinstance(socket, list) or len(socket) != 9 or any(type(v) is not int or v < 0 for v in socket) or \
            not stat.S_ISSOCK(socket[2]):
        raise ValueError('Closure original socket identity')
    for key, value in [('countsBefore', [37, 144, 6, 415]), ('countsAfter', [37, 145, 6, 417])]:
        if config[key] != value or any(type(v) is not int for v in config[key]):
            raise ValueError('Closure exact debit')
    if type(config['outsideHostsBefore']) is not int or type(config['outsideHostsAfter']) is not int or \
            (config['outsideHostsBefore'], config['outsideHostsAfter']) != (31, 32):
        raise ValueError('Closure outside host debit')
    return config


def closure_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate closure JSON key')
            result[key] = value
        return result
    def invalid(_value):
        raise ValueError('Nonfinite closure JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def closure_relay_sample(path, expected):
    # Do not call direct(path): its is_symlink would add a second leaf sample.
    descriptors = []
    try:
        parent = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(parent)
        for part in ('run', 'WSL'):
            parent = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            descriptors.append(parent)
        try:
            observed = identity(os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False))
        except FileNotFoundError:
            return {'state': 'absent', 'identity': None, 'error': None}
        return {'state': 'present-matching' if observed == expected and stat.S_ISSOCK(observed[2])
                else 'present-changed', 'identity': observed, 'error': None}
    except OSError as error:
        return {'state': 'metadata-failed', 'identity': None, 'error': error.errno}
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def closure_infrastructure_equal(expected, observed):
    # The existing pin routine proves fresh content and strict within-read full9.
    # Qualify only historical ctime, retaining both original and observed records.
    def comparison(value):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == 'identity':
                    if not isinstance(item, list) or len(item) != 9 or \
                            any(type(n) is not int for n in item) or item[5] != 1:
                        raise ValueError('Closure infrastructure identity shape')
                    result[key] = item[:8]
                else:
                    result[key] = comparison(item)
            return result
        if isinstance(value, list):
            return [comparison(item) for item in value]
        return value
    return comparison(expected) == comparison(observed)


def closure_native_rows(raw, config):
    fields = raw.decode('ascii').split('\n')
    if len(fields) != 7 or fields[0] != 'azureauth-retained-closure-result-v1' or \
            fields[1] != config['nonce'] or fields[2] != config['selectorSha256'] or fields[5:] != ['END', '']:
        raise ValueError('Closure native record binding')
    rows = []
    for index, text in enumerate(fields[3:5]):
        parts = text.split(',')
        if len(parts) != 7 or any(not re.fullmatch(r'-?(?:0|[1-9][0-9]{0,18})', v) for v in parts):
            raise ValueError('Closure native numeric record')
        state, status, created, wait, code, stage, error = map(int, parts)
        if state not in range(5) or not 0 <= status <= 0xffffffff or not 0 <= stage <= 4 or \
                not -1 <= wait <= 0xffffffff or not -1 <= code <= 0xffffffff or not 0 <= error <= 0x7fffffff:
            raise ValueError('Closure native record range')
        expected = int(config['creationFileTimes'][index])
        if state == 0 and (status, created, wait, code, stage, error) != (0xc000000b, 0, -1, -1, 1, 0):
            raise ValueError('Closure absent status')
        if state in (1, 2, 3):
            if status != 0 or created <= 0 or stage != 0 or error != 0 or wait not in (0, 258) or \
                    (wait == 0 and code < 0) or (wait == 258 and code != -1) or \
                    (state == 1 and created == expected) or \
                    (state == 2 and (created != expected or wait != 0)) or \
                    (state == 3 and (created != expected or wait != 258)):
                raise ValueError('Closure process classification')
        rows.append({'state': ('absent', 'reused', 'matching-exited', 'matching-live', 'query-failed')[state],
                     'openStatus': status, 'creationFileTime': created, 'wait': wait,
                     'exitCode': code, 'failureStage': stage, 'nativeError': error})
    return rows


def closure_check(config_hash, expires_ns):
    began = boot()
    if not re.fullmatch(r'[0-9a-f]{64}', config_hash) or not re.fullmatch(r'[1-9][0-9]{1,19}', expires_ns):
        raise ValueError('Closure arguments')
    deadline = int(expires_ns) / 1000000000
    if not began < deadline <= began + 25:
        raise ValueError('Closure original deadline')
    root = direct(Path(__file__).absolute().parent)
    if str(root) != '/mnt/c/Temp/azureauth-windows-slice-108/closure-observer-0181':
        raise ValueError('Closure payload root')
    local = direct('/var/tmp/azureauth-windows-slice-108/windows-actions/closure-observer-0181')
    config = closure_configuration(closure_json(read(local / 'config.json', 65536, config_hash)))
    record(local / 'original-charge.json', {'countsBefore': config['countsBefore'], 'countsAfter': config['countsAfter'],
                                           'outsideHostsBefore': 31, 'outsideHostsAfter': 32, 'configSha256': config_hash})
    child = None
    streams, data, eof = [], [bytearray(), bytearray()], [False, False]
    failure = None
    forced = signal_seen = returned = False
    relay, rows = None, None
    def signal_stop(_signum, _frame):
        nonlocal signal_seen
        signal_seen = True
    def work_budget():
        if signal_seen or boot() >= deadline - 5:
            raise TimeoutError('Closure work deadline')
    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGINT, signal_stop)
    try:
        work_budget()
        read(Path(__file__), 65536, config['holderSha256'])
        if os.environ.get('WSL_INTEROP') != config['invokeRelay']:
            raise ValueError('Closure original invocation relay')
        groups = [line[3:] for line in virtual('/proc/self/cgroup').splitlines() if line.startswith('0::')]
        unit = 'azureauth-closure-observer-108-' + config['nonce'] + '.service'
        if len(groups) != 1 or Path(groups[0]).name != unit:
            raise ValueError('Closure named service')
        fields = virtual('/proc/self/stat').rsplit(')', 1)[1].split()
        record(local / 'observer-start.json', {'nonce': config['nonce'], 'pid': os.getpid(),
                                              'startTicks': int(fields[19]), 'cgroup': groups[0],
                                              'configSha256': config_hash, 'deadlineBootNs': expires_ns})
        selector = read(root / 'selector.txt', 4096, config['selectorSha256']).decode('ascii').split('\n')
        expected = ['azureauth-retained-closure-v1', config['nonce'], config['originSnapshotSha256'],
                    str(config['pids'][0]), config['creationFileTimes'][0], str(config['pids'][1]),
                    config['creationFileTimes'][1], config['observerSha256'], 'END', '']
        if selector != expected:
            raise ValueError('Closure selector binding')
        infrastructure = closure_json(read(local / 'infrastructure.json', 65536, config['infrastructureSha256']))
        if set(infrastructure) != set(LINUX_EXECUTABLES):
            raise ValueError('Closure infrastructure selection')
        observations = {}
        for name, pin in infrastructure.items():
            work_budget()
            actual = linux_executable_pin(name, work_budget)
            if not closure_infrastructure_equal(pin, actual):
                raise ValueError('Closure infrastructure identity')
            observations[name] = {'expected': pin, 'observed': actual,
                                  'historicalCtimeQualified': pin != actual}
        record(local / 'infrastructure-observations.json', observations)
        read(root / 'RetainedClosureObserver.exe', 2097152, config['observerSha256'])
        work_budget()
        # Sample only the subject relay once; never use it as a transport endpoint.
        relay = closure_relay_sample(config['subjectRelay'], config['relayIdentity'])
        work_budget()
        native_seconds = min(20, deadline - 5 - boot())
        native_expiry = EPOCH + (time.time_ns() + int(native_seconds * 1000000000)) // 100
        child = subprocess.Popen([str(root / 'RetainedClosureObserver.exe'), '--observe',
                                  'C:\\Temp\\azureauth-windows-slice-108\\closure-observer-0181',
                                  config['selectorSha256'], str(native_expiry)], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root, env=dict(os.environ))
        streams = [child.stdout, child.stderr]
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        for _ in range(2500):
            work_budget()
            for index, stream in enumerate(streams):
                if eof[index]:
                    continue
                try:
                    chunk = os.read(stream.fileno(), min(4096, LIMIT + 1 - len(data[index])))
                except BlockingIOError:
                    continue
                if not chunk:
                    eof[index] = True
                data[index].extend(chunk)
                if len(data[index]) > LIMIT:
                    raise ValueError('Closure stream overflow')
            if child.poll() is not None and all(eof):
                returned = True
                break
            time.sleep(0.01)
        if not returned or any(data) or child.returncode != 0:
            raise RuntimeError('Closure native observation incomplete')
        work_budget()
        rows = closure_native_rows(read(root / 'native-result.txt', 4096), config)
    except BaseException as error:
        failure = type(error).__name__
    finally:
        if child is not None and child.poll() is None:
            forced = True
            try:
                child.kill()
                child.wait(timeout=min(1, max(0.001, deadline - boot())))
            except BaseException as error:
                failure = failure or type(error).__name__
        for stream in streams:
            stream.close()
        for name in ('observer.stdout.bin', 'observer.stderr.bin'):
            write(local / name, b'')
        code = None if child is None else child.poll()
        normal = returned and not forced and not signal_seen and all(eof) and not any(data) and \
            code in (0, 1, 101, 102, 103, 104, 125)
        result = {'nonce': config['nonce'], 'configSha256': config_hash, 'proxyStarted': child is not None,
                  'proxyExit': code, 'eof': eof, 'observedBytes': [len(v) for v in data],
                  'forcedProxyTermination': forced, 'signalReceived': signal_seen,
                  'sourceCorrespondedNormalReturn': normal,
                  'nativeLifetimeUnknown': child is not None and not normal, 'relay': relay, 'processes': rows,
                  'failure': failure, 'elapsedSeconds': boot() - began, 'beforeDeadline': boot() < deadline}
        result['passed'] = normal and code == 0 and failure is None and result['beforeDeadline'] and \
            relay is not None and relay['state'] == 'absent' and rows is not None and \
            all(row['state'] in ('absent', 'reused', 'matching-exited') for row in rows)
        record(local / 'observer-final.json', result)
    return 0 if result['passed'] and not signal_seen and boot() < deadline else 1


if __name__ == '__main__':
    if not EXECUTION_ADMITTED:
        raise SystemExit('INERT: independent source and exact-call admission required.')
    try:
        if len(sys.argv) == 4 and sys.argv[1] == '--closure-check':
            raise SystemExit(closure_check(*sys.argv[2:]))
        if len(sys.argv) == 8 and sys.argv[1] == '--input-check':
            raise SystemExit(input_check(*sys.argv[2:]))
        if len(sys.argv) == 5 and sys.argv[1] == '--transport':
            raise SystemExit(transport(*sys.argv[2:]))
        if len(sys.argv) == 4:
            raise SystemExit(main(*sys.argv[1:]))
        raise SystemExit(125)
    except Exception:
        raise SystemExit(1)
