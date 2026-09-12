"""Issue #76 only: preserve accepted attempts and hand off remaining Windows actions."""

import argparse
import datetime
import hashlib
import json
import pathlib
import signal
import subprocess
import urllib.error
import urllib.request


ROOT = pathlib.Path('/mnt/c/Temp/azureauth-native-aot-76')
INITIAL = '3f21223c0d83aa8d2bb872499c40a4b08de1dcfe'
PREVIOUS = '4cfde18c1e7348ca1341e50829b1a031af071dac'
ENVIRONMENT_MARKER_SHA256 = '810f4a5b7d8cf90c7fe03fae16607674cd7a5673edf44773afbd12c03f04e718'
PREVIOUS_MARKER_SHA256 = '60ef44676aa3285735a73e7adbf8e7ca9dc06780a9e9a3296c7083dff9208dda'
DIAGNOSTIC_MARKER_SHA256 = '64e44d686794942c7ea03b86cf675348104070e33e5a04783cbf4a23975aab96'
INITIAL_RECEIPTS = {
    '05/started.json': '4dc9b666df2d38d68aaff0a307e9f97ced505568a14b14928eccf56c3d3d9df2',
    '05/result.json': 'b75eb2f1892c251a34538fe86e63860fd04174c44a6d8d7b3f05e8de3532407d',
    '01/started.json': '979db8fdf83c0435a32c74c7458b4f6686dc8dd31e8f6fc10179fd335832c820',
    '01/result.json': '8d5e5176aaa1c157338c1988c253b539a84f9fd48437b979e61eea723bfb47a5',
    '02/started.json': 'f10a9936a7c417a89f9194823879fd0d83ff31bcf9655b933296013493fba97e',
    '02/result.json': 'aa3358a4bc992d6fec9d36687d759a5eb0f4ff2dbfab03c58492936d97c62606',
    '03/started.json': 'ed065255c3cc5031051004714724e50f6591aa14cfad2ab6d70b771a6e6b8be7',
    '03/result.json': '918a0425d6bb178815385ec6e8572fc6b0d1ba8e16a2abf45aaa2ae76107e7cd',
    '04/started.json': '645d18bfd5a205ed2d049b4178a3fe152b53bafa934e08c1da5bd28e005c1ce4',
    '04/result.json': 'c594fd661df111688de8c34c015829472fb70ac1a0fabc1387cac6ef392c3406',
}
REL = 'tools/probes/windows-native-aot/'
PROTOCOL = 'docs/research/experiments/windows-native-aot.md'
FILES = ['run.py', 'Invoke-Action.ps1', 'WindowsJob.cs', 'Program.cs', 'NativeAotProbe.csproj',
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
SUPPLEMENTAL = {
    'Microsoft.WindowsDesktop.App.Runtime.win-x64': '10.0.12',
    'Microsoft.AspNetCore.App.Runtime.win-x64': '10.0.12',
}
PACKAGES.update(SUPPLEMENTAL)
LIMITS = {'fetch': 1, 'supplemental-fetch': 1, 'restore': 6, 'publish': 2, 'positive': 1,
          'missing': 1, 'decoy': 1}


def git(*args):
    return subprocess.check_output(['git', *args])


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('Redirect rejected before another request')


def fetch_deadline(signum, frame):
    raise TimeoutError('Public fetch deadline reached')


def supplemental_fetch(attempt):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    downloaded = []
    total = 0
    current_package = ''
    previous_handler = signal.signal(signal.SIGALRM, fetch_deadline)
    signal.setitimer(signal.ITIMER_REAL, 600)
    try:
        for name, version in SUPPLEMENTAL.items():
            current_package = name
            filename = f'{name.lower()}.{version}.nupkg'
            url = f'https://api.nuget.org/v3-flatcontainer/{name.lower()}/{version}/{filename}'
            size = 0
            digest = hashlib.sha512()
            with opener.open(url, timeout=30) as response:
                if response.url != url or response.status != 200:
                    raise RuntimeError('Unexpected public response')
                expected = int(response.headers['Content-Length'])
                if expected <= 0 or expected > 256 * 1024**2 - total:
                    raise RuntimeError('Download length outside remaining bound')
                with (ROOT / 'feed' / filename).open('xb') as output:
                    while size < expected:
                        chunk = response.read(min(1024 * 1024, expected - size))
                        if not chunk:
                            raise RuntimeError('Incomplete public archive')
                        size += len(chunk)
                        total += len(chunk)
                        digest.update(chunk)
                        output.write(chunk)
            downloaded.append({'id': name, 'version': version, 'bytes': size,
                               'sha512': digest.hexdigest()})
        result = {'exitCode': 0, 'quiescent': True, 'safetyStop': False,
                  'packages': downloaded, 'downloadBytes': total, 'ended': now()}
    except BaseException as error:
        result = {'exitCode': 1, 'quiescent': True, 'safetyStop': True,
                  'errorType': type(error).__name__, 'package': current_package,
                  'httpStatus': error.code if isinstance(error, urllib.error.HTTPError) else None,
                  'packages': downloaded, 'downloadBytes': total, 'ended': now()}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
    write(attempt / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=[key for key in LIMITS if key != 'fetch'])
    parser.add_argument('--accepted', required=True, help='Merged protocol commit')
    args = parser.parse_args()
    accepted = git('rev-parse', args.accepted).decode().strip()
    target = git('rev-parse', 'origin/main-v2').decode().strip()
    git('merge-base', '--is-ancestor', INITIAL, accepted)
    git('merge-base', '--is-ancestor', accepted, target)
    expected_wave = git('show', '801b1bb3cf5c79f7dcd8897cae2e4e94379d02c3:docs/delivery-wave.md')
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
    if json.loads((ROOT / 'identity.json').read_text())['accepted'] != INITIAL:
        raise SystemExit('The original experiment root is required.')
    for path, digest in INITIAL_RECEIPTS.items():
        if hashlib.sha256((ROOT / 'attempts' / path).read_bytes()).hexdigest() != digest:
            raise SystemExit('Original attempt evidence changed.')
    original_revision = ROOT / 'source-revision.json'
    if hashlib.sha256(original_revision.read_bytes()).hexdigest() != PREVIOUS_MARKER_SHA256:
        raise SystemExit('Previous accepted source-revision evidence changed.')
    if hashlib.sha256((ROOT / 'diagnostic-revision.json').read_bytes()).hexdigest() != DIAGNOSTIC_MARKER_SHA256:
        raise SystemExit('Accepted diagnostic source-revision evidence changed.')
    if hashlib.sha256((ROOT / 'environment-revision.json').read_bytes()).hexdigest() != ENVIRONMENT_MARKER_SHA256:
        raise SystemExit('Accepted environment-revision evidence changed.')
    revision_file = ROOT / 'runtime-pack-revision.json'
    prior_revision = json.loads(revision_file.read_text())['accepted'] if revision_file.exists() else PREVIOUS
    if prior_revision not in (PREVIOUS, accepted):
        raise SystemExit('Another amendment needs explicit acceptance.')
    for name in FILES:
        copied = ROOT / 'src' / name
        if copied.is_symlink() or copied.read_bytes() != git('show', prior_revision + ':' + REL + name):
            raise SystemExit('Windows source copy mismatch.')
    attempts = sorted((ROOT / 'attempts').iterdir())
    counts = {key: 0 for key in LIMITS}
    completed = []
    for attempt in attempts:
        started = json.loads((attempt / 'started.json').read_text())
        counts[started['action']] += 1
        result = json.loads((attempt / 'result.json').read_text(encoding='utf-8-sig'))
        if result.get('safetyStop') or not result.get('quiescent'):
            raise SystemExit('Previous safety stop or uncertain termination; no continuation.')
        completed.append((started['action'], result))
    if counts[args.action] >= LIMITS[args.action]:
        raise SystemExit('Cumulative attempt capacity exhausted.')
    if sum(count for action, count in counts.items() if action not in ('fetch', 'supplemental-fetch')) >= 11:
        raise SystemExit('Cumulative guard bootstrap capacity exhausted.')
    prerequisite = 'fetch' if args.action == 'supplemental-fetch' else (
        'supplemental-fetch' if args.action == 'restore' else (
            'restore' if args.action == 'publish' else 'publish'))
    if not any(
            action == prerequisite and result['exitCode'] == 0
            for action, result in completed):
        raise SystemExit('Prerequisite has no successful recorded outcome.')
    for action, fetched in completed:
        if action not in ('fetch', 'supplemental-fetch'):
            continue
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
    # NuGet needs these roots even with an explicit config file. Avoid host defaults.
    empty_program_files = ROOT / 'empty-program-files'
    if empty_program_files.is_symlink():
        raise SystemExit('Owned program-files root must not be a link.')
    if not empty_program_files.is_dir() or any(empty_program_files.iterdir()):
        raise SystemExit('Recorded program-files root must exist and remain empty.')
    retained_inputs = {}
    for path, digest in {
        'src/obj/project.assets.json': '82bf316e8f0c6d71c78e4612880764256956b6d6da2940702d85541e022dda6f',
        'src/packages.lock.json': '606af5113f23548d1bc87c55657f1c1f7e4ffa017557e8cb9c7f342690cb84a3',
    }.items():
        retained = ROOT / 'attempts' / '05' / pathlib.Path(path).name
        if retained.is_symlink() or (prior_revision == PREVIOUS and retained.exists()):
            raise SystemExit('Unexpected retained failed-restore artifact.')
        content = (ROOT / path if prior_revision == PREVIOUS else retained).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise SystemExit('Failed-restore evidence changed.')
        retained_inputs[retained] = content
    if prior_revision == PREVIOUS:
        if args.action != 'supplemental-fetch' or [path.name for path in attempts] != ['01', '02', '03', '04', '05']:
            raise SystemExit('Only the recorded runtime-pack amendment is supported.')
        for name, version in SUPPLEMENTAL.items():
            archive = ROOT / 'feed' / f'{name.lower()}.{version}.nupkg'
            if archive.exists() or archive.is_symlink():
                raise SystemExit('Supplemental archive already exists.')
        # Retain the two verified outputs before restore can replace their active paths.
        for retained, content in retained_inputs.items():
            with retained.open('xb') as output:
                output.write(content)
        # Preserve all prior markers and receipts; partial migration fails closed.
        for name in FILES:
            (ROOT / 'src' / name).write_bytes(sources[REL + name])
        write(revision_file, {'initial': INITIAL, 'previous': PREVIOUS, 'accepted': accepted,
                             'changed': now(), 'priorConsumption': counts})
    # mkdir is the sequential reservation. Missing results block all later invocations.
    attempt = ROOT / 'attempts' / f'{len(attempts) + 1:02d}'
    attempt.mkdir()
    write(attempt / 'started.json', {'action': args.action, 'accepted': accepted,
          'target': target, 'started': now(), 'priorConsumption': counts,
          'sourceSha256': {path: hashlib.sha256(data).hexdigest()
                           for path, data in sources.items()}})
    if args.action == 'supplemental-fetch':
        result = supplemental_fetch(attempt)
    else:
        powershell = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
        cmd = [powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
               r'C:\Temp\azureauth-native-aot-76\src\Invoke-Action.ps1',
               '-Action', args.action, '-AttemptName', attempt.name]
        # Windows owns termination; a WSL interruption is not a termination receipt.
        subprocess.run(cmd, check=False, timeout=1300)
        result = json.loads((attempt / 'result.json').read_text(encoding='utf-8-sig'))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
