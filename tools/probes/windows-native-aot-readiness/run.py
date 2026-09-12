"""Issue #92: bounded supplemental Native AOT evidence; no authentication execution."""

import argparse
import datetime
import hashlib
import json
import pathlib
import platform
import subprocess
import zipfile
import re
import base64
from urllib.parse import unquote

ROOT = pathlib.Path('/mnt/c/Temp/azureauth-native-aot-readiness')
OLD = pathlib.Path('/mnt/c/Temp/azureauth-native-aot-76')
WAVE = '968b0cf0a09f33ffc85648ecacc330feb9e7dda1'
REL = 'tools/probes/windows-native-aot-readiness/'
PROTOCOL = 'docs/research/experiments/windows-native-aot.md'
SOURCES = {name: REL + name for name in (
    'run.py', 'Program.cs', 'NativeAotReadinessProbe.csproj', 'global.json',
    'nuget.config', 'Invoke-Action.ps1', 'Stop-Controller.ps1')}
SOURCES['WindowsJob.cs'] = 'tools/probes/windows-native-aot/WindowsJob.cs'
SOURCES['protocol.md'] = PROTOCOL
LIMITS = {'restore': 2, 'publish': 2, 'cleanup': 2, 'wrong-architecture': 2}
OLD_COUNTS = {'fetch': 1, 'supplemental-fetch': 1, 'restore': 6, 'publish': 2,
              'positive': 1, 'missing': 1, 'decoy': 1, 'guard': 11}
WRONG_ASSET = 'runtimes/win-x86/native/msalruntime_x86.dll'
WRONG_HASH = 'ed45298d791cc6509ca5cdc3ed497b77ddfe6b5c1475c7fe9470b5c0e0f41c28'

HISTORY_FILES = ['identity.json',
 'diagnostic-revision.json',
 'environment-revision.json',
 'host-os-revision.json',
 'runtime-pack-revision.json',
 'runtime-revision.json',
 'source-revision.json',
 'attempts/01/started.json',
 'attempts/01/result.json',
 'attempts/02/started.json',
 'attempts/02/result.json',
 'attempts/03/started.json',
 'attempts/03/result.json',
 'attempts/04/started.json',
 'attempts/04/result.json',
 'attempts/05/started.json',
 'attempts/05/result.json',
 'attempts/06/started.json',
 'attempts/06/result.json',
 'attempts/07/started.json',
 'attempts/07/result.json',
 'attempts/08/started.json',
 'attempts/08/result.json',
 'attempts/09/started.json',
 'attempts/09/result.json',
 'attempts/10/started.json',
 'attempts/10/result.json',
 'attempts/11/started.json',
 'attempts/11/result.json',
 'attempts/12/started.json',
 'attempts/12/result.json',
 'attempts/13/started.json',
 'attempts/13/result.json']
HISTORY_SHA256 = 'ecda3b3331289a54b0e0b3eb96883a14d9f305990d4656e678bfd60fbebd7b9e'
FEED = {'microsoft.aspnetcore.app.runtime.win-x64.10.0.12.nupkg': '9fca92913dca9245d2a6ef5453be3cc3311bac3c0b3890a4386c58d03fedbd63b051751b4b6a9193989c606d92ba447bfa2d5e3bc605e2c3a5fa2bdba218513c',
 'microsoft.dotnet.ilcompiler.10.0.12.nupkg': 'a9e3932bd0d16d6c78fde79b5c6d6fe74ca4104983f54be9f09d62085aa7cf7d1683cb3cbdf3dddad3e9a9a7b4c0c9d262676f28299308483afd96b34acba562',
 'microsoft.identity.client.4.83.1.nupkg': '692ae5e6b961a2ef71b747a9877f7a7f0460a03f9fb2edc0fa7e4d457a5419a0f564afae53c6296b7e75e0ab2b1c61b3f621a9d56e99945bb047b02dcfe9a2bd',
 'microsoft.identity.client.broker.4.83.1.nupkg': '9923928bde2049ed3ec125f871eb37f125a2bb28d20e0d5ebdf59d1a7cb1f37858f4c7d818dd25fd72f1fa7ae96a01a1320d1a21bb3ba3a1379d3fe37463f2ec',
 'microsoft.identity.client.nativeinterop.0.20.3.nupkg': 'e8d30c22acc6c14d91f09c9e8204278357f2500a11e1e7befb1443f0e806a9dd5522938d37733bfe3de11a1c4e30ccea4755f80fcd1f9de6d8c87a88910ae5cd',
 'microsoft.identitymodel.abstractions.8.14.0.nupkg': '175ef8bf78b63f3c327e680d5cf7721d74f29e96460e686b22b4e67c264fb036a7a9bea1473f4a5b487337ab7a560c861b51ed1aa744777f303362262b01a8b4',
 'microsoft.net.illink.tasks.10.0.12.nupkg': 'a294f93f5a7e086ef4c466af79382add0e4e64a77b319d11b35d31e137b097a6dc3dbbb848ba381749fa4410889ef04ac68475d13d75f97d0cf5d8232847ee73',
 'microsoft.netcore.app.host.win-x64.10.0.12.nupkg': '33c2760f5936e1eb30609fc368974761bc331eb720fa0593bf92f9f050c6d91d67f673a22783160ab84c16d6736e8c02c10066ced6c06cceed378f5cbaa78588',
 'microsoft.netcore.app.ref.10.0.12.nupkg': 'b8df7c98c76bba344b41d20151dc79e5a4dc764b5fdb893844fdfdb895be05247d31cb4e93452ba668beb2f3f62a3f30ed8b1242e06b7a0c53b11125fc69ba28',
 'microsoft.netcore.app.runtime.nativeaot.win-x64.10.0.12.nupkg': 'bc56dd1d11b4a49874cc12cfa66f0163fa1a353fb84d8158e336e2eb779ebd7ae0aa487d660bc85043c833589a33f348ea6674cf1bf61744fe1ae9d38168e9c8',
 'microsoft.netcore.app.runtime.win-x64.10.0.12.nupkg': '39afcb222032eabebe2c7fa51a37c491c6b0f456796ad7888431971b8eef4f689caee5454260398ce0ffafe491c565891b35e73afc67585a3e4c4bde995710ee',
 'microsoft.windowsdesktop.app.runtime.win-x64.10.0.12.nupkg': '05e188fca4c105c6b8a5dbaed677dfeb556f640c25cd5c2a366a3e795a93dba96db0026c42c17ffc308f26cb30f9f5e9011abe150ee954a89079de6282ff0a61',
 'runtime.win-x64.microsoft.dotnet.ilcompiler.10.0.12.nupkg': '3875d56e9404026f57c1b1a0673c722b5485340b693422c7c9ea118f40301b51ed173871ee525818080de8230ee0ac6147c56e352d4da8929532b3b3959d684d',
 'system.diagnostics.diagnosticsource.6.0.1.nupkg': '80a0f9bf3a7afdb28d9f00e1f301feeacb39c34fe4ac8f55a392377e2e018fb546fc3fc56e2fe4336dea222b7ab3f4bab58a0b8d86eb18c71951ef2e1c752789',
 'system.runtime.compilerservices.unsafe.6.0.0.nupkg': 'd4057301be4ec4936f24b9ce003b5ec4d99681ab6d9b65d5393dd38d04cdec37784aaa12c1a8b50ac3767ed878dae425749490773fec01e734f93cf1045822b3',
 'system.valuetuple.4.5.0.nupkg': 'fa00ebb5045d12c51274f64411c551981beceb1266a8606a4731063109b95ea1f15939197bf3d2ba899db61e593dc39bfce876908bba34286823525093ae3d8e'}


def git(*args):
    return subprocess.check_output(['git', *args])


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def read(path):
    direct(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4194304:
        raise SystemExit('Missing, linked, or oversized receipt.')
    return json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=strict_pairs)


def write_new(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, indent=2)
        output.write('\n')


def digest(path, algorithm='sha256'):
    direct(path)
    if path.is_symlink() or not path.is_file():
        raise SystemExit('Missing or linked input.')
    result = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            result.update(block)
    return result.hexdigest()


def direct(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise SystemExit('Linked path or ancestor.')


def source_identity(accepted):
    if not isinstance(accepted, str) or not re.fullmatch('[0-9a-f]{40}', accepted):
        raise SystemExit('Invalid accepted revision.')
    return {name: hashlib.sha256(git('show', accepted + ':' + path)).hexdigest()
            for name, path in SOURCES.items()}


def source_inventory(source, expected):
    direct(source)
    if {p.name for p in source.iterdir()} - set(expected) - {'bin', 'obj', 'packages.lock.json'}:
        raise SystemExit('Unexpected source input.')
    for name, value in expected.items():
        if digest(source / name) != value:
            raise SystemExit('Dedicated source changed.')


def windows_paths():
    # Read-only host preflight precedes all dedicated-root writes, including initial copy.
    script = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    $queue = New-Object 'Collections.Generic.Queue[string]'
    foreach ($path in @('C:\', 'C:\Temp', 'C:\Temp\azureauth-native-aot-76',
                       'C:\Temp\azureauth-native-aot-76\feed')) {
        if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Linked prerequisite'
        }
    }
    $root = 'C:\Temp\azureauth-native-aot-readiness'
    if (Test-Path -LiteralPath $root) { $queue.Enqueue($root) }
    while ($queue.Count -gt 0) {
        $item = Get-Item -LiteralPath $queue.Dequeue() -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked input' }
        if ($item.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force) {
                $queue.Enqueue($child.FullName)
            }
        }
    }
    [Console]::Out.Write('direct-paths')
} catch { exit 1 }
'''
    result = subprocess.run([
        '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe', '-NoLogo', '-NoProfile',
        '-NonInteractive', '-EncodedCommand', base64.b64encode(script.encode('utf-16-le')).decode()],
        capture_output=True, timeout=60)
    if result.returncode != 0 or result.stdout != b'direct-paths' or result.stderr:
        raise SystemExit('Windows path ownership preflight failed.')


def restore_evidence(source):
    """Read new resolved artifacts as data; never infer new restore from old evidence."""
    assets = read(source / 'obj/project.assets.json')
    lock = read(source / 'packages.lock.json')
    imports = {'NativeAotReadinessProbe.csproj.nuget.g.props',
               'NativeAotReadinessProbe.csproj.nuget.g.targets'}
    actual_imports = {path.name for path in (source / 'obj').iterdir()
                      if path.name.endswith(('.props', '.targets'))}
    if actual_imports != imports:
        raise SystemExit('Unexpected generated NuGet import.')
    import_hashes = {name: digest(source / 'obj' / name) for name in sorted(imports)}
    if any(item.get('level') == 'Error' for item in assets.get('logs', [])):
        raise SystemExit('Restore errors in assets.')
    libraries = assets['libraries']
    expected_libraries = {
        'Microsoft.Identity.Client/4.83.1', 'Microsoft.Identity.Client.Broker/4.83.1',
        'Microsoft.Identity.Client.NativeInterop/0.20.3', 'Microsoft.IdentityModel.Abstractions/8.14.0',
        'System.Diagnostics.DiagnosticSource/6.0.1', 'System.Runtime.CompilerServices.Unsafe/6.0.0',
        'System.ValueTuple/4.5.0', 'Microsoft.NET.ILLink.Tasks/10.0.12',
        'Microsoft.DotNet.ILCompiler/10.0.12', 'runtime.win-x64.Microsoft.DotNet.ILCompiler/10.0.12'}
    if set(libraries) != expected_libraries:
        raise SystemExit('Unexpected resolved libraries.')
    target_names = [name for name in assets['targets'] if name.endswith('/win-x64')]
    if len(target_names) != 1:
        raise SystemExit('Unexpected runtime target.')
    selected = {}
    payloads = {}
    for name, library in libraries.items():
        package_id, version = name.rsplit('/', 1)
        archive_name = package_id.lower() + '.' + version + '.nupkg'
        package_root = ROOT / 'packages' / library['path']
        if package_root != ROOT / 'packages' / package_id.lower() / version:
            raise SystemExit('Unexpected resolved package path.')
        if digest(package_root / archive_name, 'sha512') != FEED[archive_name]:
            raise SystemExit('Restored archive changed.')
        metadata = read(package_root / '.nupkg.metadata')
        if library['sha512'] != metadata['contentHash']:
            raise SystemExit('Resolved content hash changed.')
        paths = set()
        entry = assets['targets'][target_names[0]].get(name, {})
        for category in ('compile', 'runtime', 'native', 'runtimeTargets'):
            paths.update(entry.get(category, {}))
        selected[name] = {}
        with zipfile.ZipFile(ROOT / 'feed' / archive_name) as archive:
            # NuGet decodes ZIP package-part names, including portable TFM %2B.
            members = {unquote(member).lower(): member for member in archive.namelist()}
            if len(members) != len(archive.namelist()):
                raise SystemExit('Ambiguous archive part names.')
            payloads[name] = {}
            for path in library['files']:
                if path in ('.nupkg.metadata', archive_name + '.sha512'):
                    continue
                if '..' in pathlib.PurePosixPath(path).parts or pathlib.PurePosixPath(path).is_absolute():
                    raise SystemExit('Unexpected package file path.')
                if path.lower() not in members:
                    raise SystemExit('Unexpected restored payload.')
                expected = hashlib.sha256(archive.read(members[path.lower()])).hexdigest()
                if digest(package_root / path) != expected:
                    raise SystemExit('Restored package payload changed.')
                payloads[name][path] = expected
            for path in sorted(paths):
                if '..' in pathlib.PurePosixPath(path).parts or pathlib.PurePosixPath(path).is_absolute():
                    raise SystemExit('Unexpected selected asset path.')
                expected = hashlib.sha256(archive.read(path)).hexdigest()
                if digest(package_root / path) != expected:
                    raise SystemExit('Restored selected asset changed.')
                selected[name][path] = expected
    if set(selected['Microsoft.Identity.Client/4.83.1']) != {'lib/net8.0/Microsoft.Identity.Client.dll'} or set(
            selected['Microsoft.Identity.Client.Broker/4.83.1']) != {'lib/netstandard2.0/Microsoft.Identity.Client.Broker.dll'} or set(
            selected['Microsoft.Identity.Client.NativeInterop/0.20.3']) != {
                'lib/net9.0/Microsoft.Identity.Client.NativeInterop.dll', 'runtimes/win-x64/native/msalruntime.dll'}:
        raise SystemExit('Unexpected provider asset selection.')
    for framework in lock['dependencies'].values():
        for name, entry in framework.items():
            if name + '/' + entry['resolved'] not in libraries:
                raise SystemExit('Unexpected locked package.')
    if set(assets['packageFolders']) != {'C:\\Temp\\azureauth-native-aot-readiness\\packages'}:
        # NuGet normalizes its package root with a trailing directory separator.
        if set(assets['packageFolders']) != {'C:\\Temp\\azureauth-native-aot-readiness\\packages\\'}:
            raise SystemExit('Unexpected package folder.')
    framework = assets['project']['frameworks']['net10.0-windows']
    downloads = framework['downloadDependencies']
    expected_downloads = {'Microsoft.AspNetCore.App.Runtime.win-x64',
                          'Microsoft.NETCore.App.Runtime.NativeAOT.win-x64',
                          'Microsoft.NETCore.App.Runtime.win-x64',
                          'Microsoft.WindowsDesktop.App.Runtime.win-x64',
                          'runtime.win-x64.Microsoft.DotNet.ILCompiler'}
    if {entry['name'] for entry in downloads} != expected_downloads or any(
            entry['version'] != '[10.0.12, 10.0.12]' for entry in downloads):
        raise SystemExit('Unexpected downloaded pack selection.')
    downloaded_payloads = {}
    for entry in downloads:
        name = entry['name']
        archive_name = name.lower() + '.10.0.12.nupkg'
        package_root = ROOT / 'packages' / name.lower() / '10.0.12'
        if digest(package_root / archive_name, 'sha512') != FEED[archive_name]:
            raise SystemExit('Restored download archive changed.')
        downloaded_payloads[name] = {}
        with zipfile.ZipFile(ROOT / 'feed' / archive_name) as archive:
            for member in archive.namelist():
                path = unquote(member)
                # NuGet omits OPC package-container metadata when extracting payloads.
                if path.endswith('/') or path in ('[Content_Types].xml', '_rels/.rels') or path.startswith(
                        'package/services/metadata/core-properties/'):
                    continue
                if path.endswith('.nuspec'):
                    path = path.lower()
                if '..' in pathlib.PurePosixPath(path).parts or pathlib.PurePosixPath(path).is_absolute():
                    raise SystemExit('Unexpected downloaded pack path.')
                expected = hashlib.sha256(archive.read(member)).hexdigest()
                if digest(package_root / path) != expected:
                    raise SystemExit('Restored download payload changed.')
                downloaded_payloads[name][path] = expected
    return {'assetsSha256': digest(source / 'obj/project.assets.json'),
            'lockSha256': digest(source / 'packages.lock.json'),
            'nugetImportSha256': import_hashes,
            'libraries': sorted(libraries), 'selectedAssetsSha256': selected,
            'packagePayloadSha256': payloads, 'downloadDependencies': downloads,
            'downloadPayloadSha256': downloaded_payloads,
            'frameworkReferences': framework['frameworkReferences']}


def evidence_map(completion, action, code):
    expected = {'restore.json'} if action == 'restore' and code == 0 else (
        {'artifacts.json'} if action == 'publish' and code == 0 else set())
    actual = completion.get('evidenceSha256')
    if not isinstance(actual, dict) or set(actual) != expected or any(
            not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) for value in actual.values()):
        raise SystemExit('Required preparation evidence binding is missing or invalid.')
    return actual


def history():
    if OLD.is_symlink():
        raise SystemExit('Historical root changed.')
    value = hashlib.sha256()
    for name in HISTORY_FILES:
        value.update(name.encode() + b'\0' + bytes.fromhex(digest(OLD / name)))
    if value.hexdigest() != HISTORY_SHA256:
        raise SystemExit('Historical evidence changed; no continuation.')
    if [p.name for p in sorted((OLD / 'attempts').iterdir())] != [f'{i:02}' for i in range(1, 14)]:
        raise SystemExit('Historical consumption changed.')
    for name, expected in FEED.items():
        if digest(OLD / 'feed' / name, 'sha512') != expected:
            raise SystemExit('Historical public archive changed.')


def completed(result, action):
    if not isinstance(result, dict):
        return False
    for key, expected in {'safetyStop': False, 'quiescent': True,
                          'captureCompleted': True, 'compilerTerminationRequested': False,
                          'jobTerminationRequested': False, 'jobTerminationSucceeded': False}.items():
        if result.get(key) is not expected:
            return False
    if result.get('stage') != 'completed':
        return False
    if not isinstance(result.get('ended'), str) or type(result.get('seconds')) not in (int, float):
        return False
    if not 0 <= result['seconds'] <= {'restore': 181, 'publish': 601, 'cleanup': 31, 'wrong-architecture': 31}[action]:
        return False
    for key in ('guardCompilerExitCode', 'activeProcessesAtNormalExit', 'jobActiveBeforeStop'):
        if type(result.get(key)) is not int or result[key] != 0:
            return False
    if type(result.get('exitCode')) is not int:
        return False
    if action in ('restore', 'publish'):
        if result.get('diagnosticsComplete') is not True:
            return False
        for stream in ('stdoutDiagnostic', 'stderrDiagnostic'):
            item = result.get(stream)
            if not isinstance(item, dict) or item.get('sensitiveOutput') is not False or item.get('truncated') is not False:
                return False
            if type(item.get('suppressedLines')) is not int or item['suppressedLines'] != 0 or not isinstance(item.get('text'), str):
                return False
        return True
    observation = result.get('observation', {})
    if not isinstance(observation, dict):
        return False
    for key in ('nativeAot', 'restrictedSearch', 'firstChanceSelfCheck', 'builderCreated'):
        if observation.get(key) is not True:
            return False
    if observation.get('unexpectedPreload') is not False:
        return False
    if action == 'cleanup':
        return result['exitCode'] == 0 and all(observation.get(key) is True for key in (
            'allocated', 'cleanupExportsPresent', 'disposeReturned', 'secondDisposeReturned',
            'nativeModuleLoaded', 'moduleInApplicationDirectory')) and type(observation.get(
            'cleanupFirstChanceExceptions')) is int and observation['cleanupFirstChanceExceptions'] == 0 and observation.get(
            'exceptionType') == '' and observation.get('innerExceptionType') == ''
    return result['exitCode'] == 1 and all(observation.get(key) is False for key in (
        'allocated', 'cleanupExportsPresent', 'disposeReturned', 'secondDisposeReturned',
        'nativeModuleLoaded', 'moduleInApplicationDirectory')) and type(observation.get(
        'cleanupFirstChanceExceptions')) is int and observation['cleanupFirstChanceExceptions'] == -1 and (
        observation.get('exceptionType') in ('System.BadImageFormatException', 'System.DllNotFoundException') or
        (observation.get('exceptionType') == 'System.TypeInitializationException' and
         observation.get('innerExceptionType') in ('System.BadImageFormatException', 'System.DllNotFoundException')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=tuple(LIMITS))
    parser.add_argument('--accepted', required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or 'microsoft' not in platform.release().lower():
        raise SystemExit('Only the designated WSL x64 environment is covered.')
    accepted = git('rev-parse', args.accepted).decode().strip()
    target = git('rev-parse', 'origin/main-v2').decode().strip()
    git('merge-base', '--is-ancestor', WAVE, accepted)
    git('merge-base', '--is-ancestor', accepted, target)
    if git('show', target + ':docs/delivery-wave.md') != git('show', WAVE + ':docs/delivery-wave.md'):
        raise SystemExit('Wave changed; refresh authorization.')
    if git('rev-parse', 'HEAD').decode().strip() != accepted or subprocess.run(
            ['git', 'symbolic-ref', '-q', 'HEAD'], capture_output=True).returncode == 0:
        raise SystemExit('Use the exact detached accepted checkout.')
    if git('status', '--porcelain'):
        raise SystemExit('The accepted checkout must be clean.')
    sources = {name: git('show', accepted + ':' + path) for name, path in SOURCES.items()}
    for name, path in SOURCES.items():
        if pathlib.Path(path).is_symlink() or pathlib.Path(path).read_bytes() != sources[name] or git('show', target + ':' + path) != sources[name]:
            raise SystemExit('Source or current prerequisite drift.')
    source_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()}
    history()
    direct(ROOT)
    windows_paths()
    if not ROOT.exists():
        if args.action != 'restore':
            raise SystemExit('Start with the reserved restore/preparation.')
        ROOT.mkdir()
        write_new(ROOT / 'preparation-started.json', {'accepted': accepted, 'started': now(),
                  'historicalSha256': HISTORY_SHA256, 'priorConsumption': OLD_COUNTS})
        for directory in ('attempts', 'source', 'feed', 'negative', 'home', 'temp', 'packages', 'http',
                          'empty-program-files', 'home/AppData/Roaming', 'home/AppData/Local'):
            (ROOT / directory).mkdir(parents=True, exist_ok=True)
        for name, expected in FEED.items():
            with (ROOT / 'feed' / name).open('xb') as output:
                output.write((OLD / 'feed' / name).read_bytes())
            if digest(ROOT / 'feed' / name, 'sha512') != expected:
                raise SystemExit('Copied public archive changed.')
        with zipfile.ZipFile(ROOT / 'feed/microsoft.identity.client.nativeinterop.0.20.3.nupkg') as archive:
            data = archive.read(WRONG_ASSET)
        if hashlib.sha256(data).hexdigest() != WRONG_HASH:
            raise SystemExit('Wrong-architecture input identity changed.')
        (ROOT / 'negative' / 'msalruntime.dll').write_bytes(data)
        write_new(ROOT / 'identity.json', {'accepted': accepted, 'prepared': now(),
                  'historicalSha256': HISTORY_SHA256, 'priorConsumption': OLD_COUNTS})
    identity = read(ROOT / 'identity.json')
    if (ROOT / 'stopped.json').exists():
        raise SystemExit('A prior interruption or safety stop ends this sequence.')
    if identity.get('historicalSha256') != HISTORY_SHA256 or identity.get('priorConsumption') != OLD_COUNTS:
        raise SystemExit('Root identity or consumption changed.')
    for name, expected in FEED.items():
        if digest(ROOT / 'feed' / name, 'sha512') != expected:
            raise SystemExit('Dedicated public feed changed.')
    if (ROOT / 'empty-program-files').is_symlink() or any((ROOT / 'empty-program-files').iterdir()):
        raise SystemExit('Dedicated program-files directory changed.')
    source = ROOT / 'source' / accepted
    if not source.exists():
        source.mkdir()
        for name, data in sources.items():
            (source / name).write_bytes(data)
    source_inventory(source, source_hashes)
    direct(ROOT / 'attempts')
    attempts = sorted((ROOT / 'attempts').iterdir())
    if len(attempts) > 8 or [p.name for p in attempts] != [f'{i:02}' for i in range(14, 14 + len(attempts))]:
        raise SystemExit('New attempt sequence changed.')
    counts = dict.fromkeys(LIMITS, 0)
    previous = []
    for attempt in attempts:
        if attempt.is_symlink():
            raise SystemExit('Linked attempt.')
        start, result = read(attempt / 'started.json'), read(attempt / 'result.json')
        prior_accepted = start.get('accepted')
        prior_sources = source_identity(prior_accepted)
        git('merge-base', '--is-ancestor', prior_accepted, target)
        prior_target = start.get('target')
        if not isinstance(prior_target, str) or not re.fullmatch('[0-9a-f]{40}', prior_target):
            raise SystemExit('Invalid prior target binding.')
        git('merge-base', '--is-ancestor', prior_accepted, prior_target)
        git('merge-base', '--is-ancestor', prior_target, target)
        if start.get('sourceSha256') != prior_sources or result.get('reservationSha256') != digest(attempt / 'started.json'):
            raise SystemExit('Prior source/result binding changed.')
        source_inventory(ROOT / 'source' / prior_accepted, prior_sources)
        completion = read(attempt / 'completion.json')
        if completion.get('resultSha256') != digest(attempt / 'result.json'):
            raise SystemExit('Prior result changed.')
        for name, expected in evidence_map(completion, start['action'], result['exitCode']).items():
            if name not in ('restore.json', 'artifacts.json') or digest(attempt / name) != expected:
                raise SystemExit('Prior preparation evidence changed.')
        if start['action'] == 'restore' and result['exitCode'] == 0:
            restored = read(attempt / 'restore.json')
            if digest(attempt / 'project.assets.json') != restored['assetsSha256'] or digest(
                    attempt / 'packages.lock.json') != restored['lockSha256']:
                raise SystemExit('Retained restore evidence changed.')
            for name, expected in restored['nugetImportSha256'].items():
                if name not in ('NativeAotReadinessProbe.csproj.nuget.g.props',
                                'NativeAotReadinessProbe.csproj.nuget.g.targets') or digest(attempt / name) != expected:
                    raise SystemExit('Retained NuGet import changed.')
        action = start['action']
        if action not in counts or not completed(result, action) or start['priorConsumption'] != counts:
            raise SystemExit('Prior action incomplete, stopped, or inconsistent.')
        if start['historicalSha256'] != HISTORY_SHA256:
            raise SystemExit('Prior historical binding changed.')
        counts[action] += 1
        previous.append((attempt, start, result))
    if any(counts[key] > LIMITS[key] for key in counts) or counts[args.action] >= LIMITS[args.action] or len(attempts) >= 8:
        raise SystemExit('Cumulative capacity exhausted.')
    if counts[args.action] and any(s['action'] == args.action and s['accepted'] == accepted for _, s, _ in previous):
        raise SystemExit('Repeating an action requires a new reviewed protocol amendment, never an incidental retry.')
    case_inputs = {}
    if args.action != 'restore':
        needed = 'restore' if args.action == 'publish' else 'publish'
        eligible = [(p, s, r) for p, s, r in previous if s['action'] == needed and s['accepted'] == accepted]
        if not eligible or eligible[-1][2]['exitCode'] != 0:
            raise SystemExit('Current accepted source lacks its successful preparation.')
        restores = [p for p, s, r in previous if s['action'] == 'restore' and
                    s['accepted'] == accepted and r['exitCode'] == 0]
        if not restores or restore_evidence(source) != read(restores[-1] / 'restore.json'):
            raise SystemExit('Restored prerequisite changed.')
        if args.action != 'publish':
            published = eligible[-1][0]
            artifacts = read(published / 'artifacts.json')
            for name in ('NativeAotReadinessProbe.exe', 'msalruntime.dll'):
                path = published / 'out' / name
                if digest(path) != artifacts[name]:
                    raise SystemExit('Published prerequisite changed.')
                case_inputs[name] = {'path': str(path.relative_to(ROOT)), 'sha256': artifacts[name]}
            if args.action == 'wrong-architecture':
                if digest(ROOT / 'negative/msalruntime.dll') != WRONG_HASH:
                    raise SystemExit('Negative input changed.')
                case_inputs['msalruntime.dll'] = {'path': 'negative/msalruntime.dll', 'sha256': WRONG_HASH}
    attempt = ROOT / 'attempts' / f'{14 + len(attempts):02}'
    attempt.mkdir()
    write_new(attempt / 'started.json', {'action': args.action, 'accepted': accepted, 'target': target,
              'started': now(), 'priorConsumption': counts, 'historicalSha256': HISTORY_SHA256,
              'sourceSha256': source_hashes, 'caseInputs': case_inputs})
    powershell = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
    command = [powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
               'C:\\Temp\\azureauth-native-aot-readiness\\source\\' + accepted + '\\Invoke-Action.ps1',
               '-Action', args.action, '-AttemptName', attempt.name, '-Accepted', accepted]
    try:
        subprocess.run(command, check=False, timeout=700, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        write_new(ROOT / 'stopped.json', {'attempt': attempt.name, 'ended': now(),
                  'reason': 'controller-wait-interrupted', 'quiescenceConfirmed': False})
        emergency = [powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                     'C:\\Temp\\azureauth-native-aot-readiness\\source\\' + accepted + '\\Stop-Controller.ps1',
                     '-AttemptName', attempt.name]
        try:
            subprocess.run(emergency, check=False, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            pass  # No termination claim follows an incomplete emergency action.
        raise SystemExit('Windows recovery attempted; retain uncertainty and stop all execution.')
    result = read(attempt / 'result.json')
    print(json.dumps(result, indent=2))
    if not completed(result, args.action) or result.get('reservationSha256') != digest(attempt / 'started.json'):
        write_new(ROOT / 'stopped.json', {'attempt': attempt.name, 'ended': now(), 'reason': 'incomplete-action'})
        raise SystemExit('Action lacks explicit bounded completion; stop.')
    evidence = {}
    if args.action == 'restore' and result['exitCode'] == 0:
        write_new(attempt / 'restore.json', restore_evidence(source))
        for destination, original in (('project.assets.json', 'obj/project.assets.json'),
                                      ('packages.lock.json', 'packages.lock.json'),
                                      ('NativeAotReadinessProbe.csproj.nuget.g.props',
                                       'obj/NativeAotReadinessProbe.csproj.nuget.g.props'),
                                      ('NativeAotReadinessProbe.csproj.nuget.g.targets',
                                       'obj/NativeAotReadinessProbe.csproj.nuget.g.targets')):
            with (attempt / destination).open('xb') as output:
                output.write((source / original).read_bytes())
        evidence['restore.json'] = digest(attempt / 'restore.json')
    if args.action == 'publish' and result['exitCode'] == 0:
        files = sorted((attempt / 'out').iterdir())
        if {p.name for p in files} != {'NativeAotReadinessProbe.exe', 'NativeAotReadinessProbe.pdb', 'msalruntime.dll'}:
            raise SystemExit('Unexpected publish inventory; retain and stop.')
        if digest(attempt / 'out/msalruntime.dll') != '9df30b54b7af974a072b1d55fee3590a5562c77ebc46f47016f0dd5199cd0c79':
            raise SystemExit('Published native library differs from selected public x64 input.')
        write_new(attempt / 'artifacts.json', {p.name: digest(p) for p in files})
        evidence['artifacts.json'] = digest(attempt / 'artifacts.json')
    history()
    write_new(attempt / 'completion.json', {'resultSha256': digest(attempt / 'result.json'),
              'evidenceSha256': evidence, 'ended': now()})


if __name__ == '__main__':
    main()
