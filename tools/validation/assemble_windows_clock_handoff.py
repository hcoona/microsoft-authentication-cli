"""Inert 0108 template; accepted revision remains unbound; no candidate execution, network, or socket probe."""

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import time
import uuid

ACCEPTED_COMMIT = None
CHECKOUT = Path('/tmp/azureauth-clock0108-accepted-108')
OUTPUT = Path('/tmp/windows-clock-handoff0108-authority-source.json')
MANIFEST = Path('/tmp/windows-clock-handoff0108-materialization-manifest.json')
HOST = Path('/tmp/windows-clock-handoff0108-host-bindings.json')
STARTED = time.monotonic()
READS = REQUESTED = WRITTEN = 0
TOOLS = {
    '/usr/bin/python3.14': (7477160, '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41'),
    '/usr/bin/systemd-run': (97272, '03a68bafb0ebc0f5eff41cbdf3cbbdf126a3bb87e21140f9147bf78edce36d88'),
    '/usr/bin/env': (11352352, '48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0'),
    '/usr/bin/timeout': (11352352, '48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0'),
    '/usr/lib/systemd/systemd': (141776, '3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3'),
}
SOURCES = {
    'worker': (CHECKOUT / 'tools/validation/run_windows_clock_handoff.py', 25267, '26c9e3cb985372b8979525d90e38a893d3e156c2d825f5c78f36ecf40dc9b7f4'),
    'harness': (CHECKOUT / 'tools/validation/Invoke-WindowsClockHandoff.ps1', 13897, 'b4515ce29fd8d7fd35bf1eb038bf897c34ae145543a0640ac3d12549c824b2dd'),
    'cases': (CHECKOUT / 'tools/validation/clock_handoff_cases.py', 7636, '9c1ef6e31bccafb54ba02a2ddd65d3c515986e12a8554d68988629bfa0a09728'),
    'publisher': (CHECKOUT / 'tools/validation/final_publish_contracts.py', 204188, '9a502cd13442b15313f657eed004cf7afda89e65b58c3cd570ef3b72d635087c'),
    'controller': (CHECKOUT / 'tools/validation/Invoke-WindowsFinalPublish.ps1', 96759, '815cceec7473b760e7cb82fb3da1e6cc706965f3969bb1c796dace9527dc245d'),
    'bootstrap': (CHECKOUT / 'tools/validation/Start-WindowsFinalPublish.ps1', 16072, '3e6f112a8d93c64462a9875b6b1a676136bb392284ced487f0ee99240aaa430e'),
    'extraction': (CHECKOUT / 'tools/validation/windows_clock_handoff_extraction.json', 4338, 'db7852f3664659bb7958614badb78cf5321b97f3358a3f8cf33c11623a6b16d6'),
    'launcher': (Path('/var/tmp/azureauth-windows-slice-108/windows-actions/0070/WindowsScriptJobLauncher.exe'), 23040,
                 '5b018f38669fd6ca3cec8f760533af392e0265280047bfb5c531dd41a349690a'),
    'launcherAcceptance': (Path('/tmp/windows-launcher0070-build-acceptance-budget-v1.json'), 5968, 'd73d0b2dca8d96cfcc581c4883b06884292c69f6ac8b85aa1aa77d364c905d89'),
}


def check():
    if time.monotonic() - STARTED >= 30:
        raise TimeoutError('Original assembly deadline')


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def parent(path):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Nonliteral assembly path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            check()
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, size, digest=None):
    global READS, REQUESTED
    check()
    READS += 1
    if READS > 31:
        raise ValueError('Assembly logical read ceiling')
    pfd = parent(path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                raise ValueError('Assembly source kind or size')
            raw = bytearray()
            while len(raw) < size:
                check()
                count = min(65536, size - len(raw))
                REQUESTED += count
                if REQUESTED > 33554432:
                    raise ValueError('Assembly requested-byte ceiling')
                part = os.read(fd, count)
                if not part:
                    raise ValueError('Assembly source incomplete')
                raw.extend(part)
            REQUESTED += 1
            if REQUESTED > 33554432 or os.read(fd, 1):
                raise ValueError('Assembly EOF or requested-byte ceiling')
            if identity(before) != identity(os.fstat(fd)) or \
                    identity(before) != identity(os.stat(path.name, dir_fd=pfd, follow_symlinks=False)):
                raise ValueError('Assembly source changed')
            actual = hashlib.sha256(raw).hexdigest()
            if digest is not None and actual != digest:
                raise ValueError('Assembly source digest mismatch')
            return bytes(raw), {'path': str(path), 'bytes': size, 'sha256': actual, 'identity': identity(before)}
        finally:
            os.close(fd)
    finally:
        os.close(pfd)


def write_payload(path, raw):
    global WRITTEN
    check()
    WRITTEN += len(raw)
    if len(raw) > 65536 or WRITTEN > 196608:
        raise ValueError('Assembly output ceiling')
    pfd = parent(path)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=pfd)
        try:
            position = 0
            while position < len(raw):
                check()
                count = os.write(fd, raw[position:])
                if count <= 0:
                    raise OSError('Assembly output incomplete')
                position += count
            os.fsync(fd)
            os.fchmod(fd, 0o444)
            os.fsync(fd)
            created = identity(os.fstat(fd))
        finally:
            os.close(fd)
        os.fsync(pfd)
    finally:
        os.close(pfd)
    observed, binding = read(path, len(raw), hashlib.sha256(raw).hexdigest())
    if observed != raw or binding['identity'] != created:
        raise ValueError('Assembly output readback mismatch')
    return binding


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def main():
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('Original assembly clock')))
    signal.setitimer(signal.ITIMER_REAL, max(0.001, 30 - (time.monotonic() - STARTED)))
    if type(ACCEPTED_COMMIT) is not str or len(ACCEPTED_COMMIT) != 40 or \
            any(character not in '0123456789abcdef' for character in ACCEPTED_COMMIT):
        raise ValueError('Unbound accepted source revision')
    tools = []
    for path, (size, digest) in TOOLS.items():
        resolved = Path(path).resolve(strict=True)
        _, binding = read(resolved, size, digest)
        binding.update(path=path, resolved=str(resolved))
        tools.append(binding)
    data = {}
    bindings = {}
    for role, (path, size, digest) in SOURCES.items():
        data[role], bindings[role] = read(path, size, digest)
    extraction = json.loads(data['extraction'])
    for role in ('bootstrap', 'controller', 'publisher'):
        spec = extraction[role]
        if spec['bytes'] != len(data[role]) or spec['sha256'] != bindings[role]['sha256']:
            raise ValueError('Extraction source mismatch')
        data[role].decode('ascii')
        for span in spec['spans'].values():
            body = data[role][span['offset']:span['offset'] + span['bytes']]
            if len(body) != span['bytes'] or hashlib.sha256(body).hexdigest() != span['sha256']:
                raise ValueError('Extraction span mismatch')
    artifact = json.loads(data['launcherAcceptance'])['artifact']
    if artifact['bytes'] != 23040 or artifact['sha256'] != bindings['launcher']['sha256'] or \
            artifact['sourceSha256'] != '32e92ca5bfd683fa4c9f3119ce0e55c353d0b092aaebbe54aac6941e01650bb6':
        raise ValueError('Retained normal launcher acceptance mismatch')
    socket_path = Path(os.environ['WSL_INTEROP'])
    number = socket_path.name.removesuffix('_interop')
    if str(socket_path) != os.environ['WSL_INTEROP'] or socket_path.parent != Path('/run/WSL') or \
            not socket_path.name.endswith('_interop') or not number or len(number) > 10 or \
            any(character not in '0123456789' for character in number):
        raise ValueError('Original interop endpoint grammar')
    pfd = parent(socket_path)
    try:
        info = os.stat(socket_path.name, dir_fd=pfd, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or identity(info) != identity(socket_path.lstat()):
            raise ValueError('Original interop endpoint correspondence')
        interop = {'path': str(socket_path), 'identity': identity(info)}
    finally:
        os.close(pfd)
    source_bindings = dict(bindings)
    for role, old, new, destination in (
        ('worker', b'DRAFT_ONLY = True\n', b'DRAFT_ONLY = False\n',
         '/tmp/windows-clock-handoff0108-worker-source.py'),
        ('harness', b'$ClockFixtureDraftOnly = $true\n', b'$ClockFixtureDraftOnly = $false\n',
         '/tmp/windows-clock-handoff0108-harness-source.ps1')):
        if data[role].count(old) != 1:
            raise ValueError('Fixture-only activation marker changed')
        bindings[role] = write_payload(Path(destination), data[role].replace(old, new, 1))
    suffix = uuid.uuid4().hex
    reservation = {'schema': 'clock-handoff-synthetic-reservation-v1', 'action': '0108', 'suffix': suffix,
                   'countsBefore': [20, 105, 4, 157], 'countsAfter': [20, 106, 4, 161], 'charge': [0, 1, 0, 4]}
    reservation_hash = hashlib.sha256(encode(reservation)).hexdigest()
    invocation = {'schema': 'clock-handoff-synthetic-invocation-v1', 'action': '0108',
                  'reservationSha256': reservation_hash, 'acceptedCommit': ACCEPTED_COMMIT}
    authority = {'schema': 'clock-handoff-0108-v1', 'accepted': True, 'action': '0108',
        'acceptedCommit': ACCEPTED_COMMIT, 'countsBefore': reservation['countsBefore'],
        'countsAfter': reservation['countsAfter'], 'buildTestCharge': 1, 'syntheticCharge': 4,
        'syntheticReservation': reservation, 'syntheticInvocation': invocation,
        'reservationSha256': reservation_hash, 'invocationSha256': hashlib.sha256(encode(invocation)).hexdigest(),
        'endpoint': 'clock-fixture-' + suffix, 'launcherSuffix': suffix, 'wslInterop': interop,
        'extraction': extraction, 'harnessSha256': bindings['harness']['sha256'],
        'worker': {k: bindings['worker'][k] for k in ('bytes', 'sha256')},
        'cases': {k: bindings['cases'][k] for k in ('bytes', 'sha256')},
        'launcherAcceptanceSha256': bindings['launcherAcceptance']['sha256']}
    bindings['authority'] = write_payload(OUTPUT, encode(authority))
    roles = ('authority', 'worker', 'harness', 'cases', 'publisher', 'bootstrap', 'controller', 'launcher')
    manifest = {'schema': 'clock-handoff0108-materialization-v1', 'acceptedCommit': ACCEPTED_COMMIT,
                'sources': {role: {k: bindings[role][k] for k in ('path', 'bytes', 'sha256')} for role in roles}}
    manifest_binding = write_payload(MANIFEST, encode(manifest))
    host_binding = write_payload(HOST, encode({'schema': 'clock-handoff0108-host-bindings-v1',
        'acceptedCommit': ACCEPTED_COMMIT, 'tools': tools, 'sources': bindings,
        'inertSourceBindings': source_bindings, 'manifest': manifest_binding, 'wslInterop': interop,
        'socketLivenessClaimed': False, 'subjectExecuted': False, 'materializationAdmitted': False,
        'beforeHostReceiptReads': READS, 'beforeHostReceiptRequestedBytes': REQUESTED,
        'beforeHostReceiptWrittenBytes': WRITTEN}))
    check()
    transport = {role: {k: binding[k] for k in ('bytes', 'sha256')}
                 for role, binding in (('authority', bindings['authority']),
                                       ('manifest', manifest_binding), ('host', host_binding))}
    transport['continuation_allowed'] = False
    print(json.dumps(transport, sort_keys=True), flush=True)
    check()
    signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    main()
