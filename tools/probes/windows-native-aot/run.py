"""Issue #76 only: accepted-source gate, bounded public fetch, Windows handoff."""

import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess
import time
import urllib.request


ROOT = pathlib.Path('/mnt/c/Temp/azureauth-native-aot-76')
REL = 'tools/probes/windows-native-aot/'
PROTOCOL = 'docs/research/experiments/windows-native-aot.md'
FILES = ['run.py', 'Invoke-Action.ps1', 'Program.cs', 'NativeAotProbe.csproj',
         'global.json', 'nuget.config']
PACKAGES = {
    'Microsoft.Identity.Client': '4.83.1',
    'Microsoft.Identity.Client.Broker': '4.83.1',
    'Microsoft.Identity.Client.NativeInterop': '0.20.3',
    'Microsoft.IdentityModel.Abstractions': '8.14.0',
    'System.Diagnostics.DiagnosticSource': '6.0.1',
    'System.Runtime.CompilerServices.Unsafe': '6.0.0',
    'System.ValueTuple': '4.5.0',
    **{name: '10.0.12' for name in (
        'Microsoft.DotNet.ILCompiler', 'runtime.win-x64.Microsoft.DotNet.ILCompiler',
        'Microsoft.NETCore.App.Runtime.NativeAOT.win-x64',
        'Microsoft.NETCore.App.Runtime.win-x64', 'Microsoft.NETCore.App.Ref',
        'Microsoft.NETCore.App.Host.win-x64', 'Microsoft.NET.ILLink.Tasks')},
}
LIMITS = {'fetch': 1, 'restore': 2, 'publish': 2, 'positive': 1,
          'missing': 1, 'decoy': 1}


def git(*args):
    return subprocess.check_output(['git', *args])


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=LIMITS)
    parser.add_argument('--accepted', required=True, help='Merged protocol commit')
    args = parser.parse_args()
    accepted = git('rev-parse', args.accepted).decode().strip()
    target = git('rev-parse', 'origin/main-v2').decode().strip()
    git('merge-base', '--is-ancestor', accepted, target)
    expected_wave = git('show', '5e1d0055e3ca933a23b3082283ab9cd28f4d88dc:docs/delivery-wave.md')
    if git('show', target + ':docs/delivery-wave.md') != expected_wave:
        raise SystemExit('Wave changed: refresh authorization and review before execution.')
    # Run from a detached accepted checkout. Never build the evolving repository root.
    if git('rev-parse', 'HEAD').decode().strip() != accepted:
        raise SystemExit('A detached checkout of the accepted protocol is required.')
    if subprocess.run(['git', 'symbolic-ref', '-q', 'HEAD'], capture_output=True).returncode == 0:
        raise SystemExit('A detached checkout is required.')
    paths = [REL + name for name in FILES] + [PROTOCOL]
    sources = {path: git('show', accepted + ':' + path) for path in paths}
    for path, content in sources.items():
        if pathlib.Path(path).is_symlink() or pathlib.Path(path).read_bytes() != content:
            raise SystemExit('Accepted source mismatch.')
    if ROOT.is_symlink():
        raise SystemExit('Experiment root must not be a link.')
    if args.action == 'fetch':
        ROOT.mkdir()  # An existing root cannot be silently adopted or replayed.
        write(ROOT / 'identity.json', {'accepted': accepted, 'created': now()})
        for name in ('feed', 'src', 'attempts', 'home', 'temp', 'packages', 'http', 'out'):
            (ROOT / name).mkdir()
        for name in FILES:
            (ROOT / 'src' / name).write_bytes(sources[REL + name])
    if json.loads((ROOT / 'identity.json').read_text())['accepted'] != accepted:
        raise SystemExit('Root belongs to another subject; amendment must preserve capacity.')
    for name in FILES:
        if (ROOT / 'src' / name).read_bytes() != sources[REL + name]:
            raise SystemExit('Windows source copy mismatch.')
    attempts = sorted((ROOT / 'attempts').iterdir())
    counts = {key: 0 for key in LIMITS}
    completed = []
    for attempt in attempts:
        started = json.loads((attempt / 'started.json').read_text())
        counts[started['action']] += 1
        result = json.loads((attempt / 'result.json').read_text())
        if result.get('safetyStop') or not result.get('quiescent'):
            raise SystemExit('Previous safety stop or uncertain termination; no continuation.')
        completed.append((started['action'], result))
    if counts[args.action] >= LIMITS[args.action]:
        raise SystemExit('Cumulative attempt capacity exhausted.')
    prerequisite = 'fetch' if args.action == 'restore' else (
        'restore' if args.action == 'publish' else 'publish')
    if args.action != 'fetch' and not any(
            action == prerequisite and result['exitCode'] == 0
            for action, result in completed):
        raise SystemExit('Prerequisite has no successful recorded outcome.')
    if args.action != 'fetch':
        fetched = next(result for action, result in completed if action == 'fetch')
        for package in fetched['packages']:
            name = f"{package['id'].lower()}.{package['version']}.nupkg"
            if hashlib.sha512((ROOT / 'feed' / name).read_bytes()).hexdigest() != package['sha512']:
                raise SystemExit('Public feed artifact changed.')
    if args.action == 'publish':
        assets = json.loads((ROOT / 'src' / 'obj' / 'project.assets.json').read_text())
        for name_version, library in assets['libraries'].items():
            name, version = name_version.rsplit('/', 1)
            if library['type'] != 'package' or PACKAGES.get(name) != version:
                raise SystemExit('Resolved dependency outside accepted closure.')
    # mkdir is the sequential reservation. Missing results block all later invocations.
    attempt = ROOT / 'attempts' / f'{len(attempts) + 1:02d}'
    attempt.mkdir()
    write(attempt / 'started.json', {'action': args.action, 'accepted': accepted,
          'target': target, 'started': now(), 'priorConsumption': counts,
          'sourceSha256': {path: hashlib.sha256(data).hexdigest()
                           for path, data in sources.items()}})
    if args.action == 'fetch':
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        downloaded = []
        start = time.monotonic()
        total = 0
        try:
            for name, version in PACKAGES.items():
                filename = f'{name.lower()}.{version}.nupkg'
                url = f'https://api.nuget.org/v3-flatcontainer/{name.lower()}/{version}/{filename}'
                size = 0
                digest = hashlib.sha512()
                with opener.open(url, timeout=30) as response, (ROOT / 'feed' / filename).open('xb') as output:
                    if response.url != url:
                        raise RuntimeError('Unexpected redirect')
                    while chunk := response.read(1024 * 1024):
                        size += len(chunk)
                        total += len(chunk)
                        if size > 300 * 1024**2 or total > 1536 * 1024**2 or time.monotonic() - start > 600:
                            raise RuntimeError('Download bound')
                        digest.update(chunk)
                        output.write(chunk)
                downloaded.append({'id': name, 'version': version, 'bytes': size,
                                   'sha512': digest.hexdigest()})
            result = {'exitCode': 0, 'quiescent': True, 'safetyStop': False,
                      'packages': downloaded, 'ended': now()}
        except BaseException as error:
            result = {'exitCode': 1, 'quiescent': True, 'safetyStop': True,
                      'errorType': type(error).__name__, 'packages': downloaded, 'ended': now()}
        write(attempt / 'result.json', result)
    else:
        powershell = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
        cmd = [powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
               r'C:\Temp\azureauth-native-aot-76\src\Invoke-Action.ps1',
               '-Action', args.action, '-AttemptName', attempt.name]
        # PowerShell owns Windows process termination. Interrupting this wait is a stop,
        # not proof that the Windows child was killed. Recover its local PID receipt.
        subprocess.run(cmd, check=False, timeout=1300)
        result = json.loads((attempt / 'result.json').read_text(encoding='utf-8-sig'))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
