"""Private source candidate; no accepted entry point, imports or execution.

The accepted post-GREEN handoff manifest is an input binding of the original
histories, not a replacement ledger. It must preserve every original disposition.
"""

DRAFT_ONLY = False
if DRAFT_ONLY:
    raise RuntimeError("DRAFT_ONLY: final guard preparation is not admitted")

import contextlib
import base64
from dataclasses import dataclass
from types import MappingProxyType
import selectors
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import time


LINUX = Path("/var/tmp/azureauth-windows-slice-108")
HISTORY = LINUX / "windows-actions"
WINDOWS = "C:\\Temp\\azureauth-windows-slice-108"
PROJECTION = Path("/mnt/c/Temp/azureauth-windows-slice-108")
POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
PROTOCOL_PATH = "docs/research/experiments/windows-slice-validation.md"
ACTION = "final-guard-prepare"
SOURCE_SHA256 = "d38846b080d5ee092fae9e21c9031712b56289093b50ca048d50589cca50ff4b"
RECIPE = {'paths': {'compiledArtifactReceiptTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\guard-build.json', 'compiledArtifactTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\WindowsFinalPublishGuard.dll', 'compilerWorkingDirectoryTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source', 'copiedSourceTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs', 'guardActionFourDigits': None, 'onlyDynamicPathSubstitution': 'GUARD_ACTION4; derive once from the fresh contiguous durable Windows reservation, not from this proposal.', 'preparationControllerDirectoryTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\controller', 'sharedActionLock': '/var/tmp/azureauth-windows-slice-108/action.lock', 'windowsActionTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}', 'windowsRoot': 'C:\\Temp\\azureauth-windows-slice-108', 'wslActionTemplate': '/var/tmp/azureauth-windows-slice-108/windows-actions/${GUARD_ACTION4}', 'wslHistoryRoot': '/var/tmp/azureauth-windows-slice-108/windows-actions', 'wslWindowsProjectionTemplate': '/mnt/c/Temp/azureauth-windows-slice-108/actions/${GUARD_ACTION4}'}, 'compilerInvocation': {'analyzers': [], 'argumentVectorTemplate': ['/noconfig', '/nologo', '/target:library', '/out:C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\WindowsFinalPublishGuard.dll', '/reference:C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll', '/reference:C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll', 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs'], 'callerArgumentOrEnvironmentOverridesAllowed': False, 'clearInheritedEnvironment': True, 'compilerConfiguration': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe.config', 'customTasks': [], 'executable': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe', 'explicitReferences': ['C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll'], 'generators': [], 'implicitMscorlibReference': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.dll', 'nativeAotLinkerOrPdbServiceSelected': False, 'nativeArgumentsTemplate': '/noconfig /nologo /target:library /out:"C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\WindowsFinalPublishGuard.dll" /reference:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll" /reference:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll" "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs"', 'packageRestoreOrCopy': False, 'preservesOriginalBootstrapEnvironmentRecipe': True, 'productSymbolPolicyChanged': False, 'replacementEnvironmentEntryCount': 30, 'replacementEnvironmentTemplate': {'APPDATA': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\roaming', 'ComSpec': 'C:\\Windows\\System32\\cmd.exe', 'DOTNET_ADD_GLOBAL_TOOLS_TO_PATH': 'false', 'DOTNET_CLI_HOME': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1', 'DOTNET_CLI_UI_LANGUAGE': 'en-US', 'DOTNET_CLI_USE_MSBUILD_SERVER': '0', 'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE': 'true', 'DOTNET_GENERATE_ASPNET_CERTIFICATE': 'false', 'DOTNET_NOLOGO': '1', 'DOTNET_ROLL_FORWARD': 'Disable', 'DOTNET_ROOT': 'C:\\Program Files\\dotnet', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1', 'LOCALAPPDATA': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\local', 'MSBUILDDISABLENODEREUSE': '1', 'MSBuildEnableWorkloadResolver': 'false', 'NUGET_HTTP_CACHE_PATH': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\http', 'NUGET_PACKAGES': 'C:\\Temp\\azureauth-windows-slice-108\\packages', 'NUGET_PLUGINS_CACHE_PATH': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\plugins', 'OS': 'Windows_NT', 'PATH': 'C:\\Program Files\\dotnet;C:\\Windows\\System32', 'PROCESSOR_ARCHITECTURE': 'AMD64', 'PROGRAMFILES': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\empty-program-files', 'PROGRAMFILES(X86)': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\empty-program-files', 'SystemRoot': 'C:\\Windows', 'TEMP': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\temp', 'TESTINGPLATFORM_TELEMETRY_OPTOUT': '1', 'TMP': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\temp', 'USERPROFILE': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home', 'WINDIR': 'C:\\Windows'}, 'resolvedArgumentStringBytesAndHash': None, 'resolvedEnvironmentBytesAndHash': None, 'responseFiles': [], 'sharedCompiler': False, 'sourceFiles': ['C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs'], 'workingDirectoryTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source'}, 'tools': {'installedToolReadPerformed': False, 'newToolInstallationOrRepairAllowed': False, 'sha256': {'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll': 'fd1097aed825d392a5dc8d19384381d4bb2a43498ea1c9d917f5d80c66600e1b', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll': '2b3c17c6208a0b4b6beb94e1a066f99ba06cdb2ea919479e99d47e8c6d96dc71', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe': '46809206887326d2d24db1eff1f3064de972c3451abe766b49111450a5e08e00', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe.config': '2d4610ade011e530d817dd3ba4fc787e5dc0c2297cc520c30a643b8fb13f9093', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.dll': '5bffb20e1217bad314143d7e5c4c809bf9f522e8a0a063c8e7e9b25113de26eb', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe': '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e'}, 'source': 'Accepted immutable tools/validation/run_windows.py TOOLS entries'}}

# The final independently reviewed launcher must pin this one fixed envelope.
# It is deliberately absent. Neither filling an old ACCEPTED dictionary nor a
# caller URL/boolean creates authority. No own-source or future-review hash lives
# in this dispatcher. The launcher, source review and publication precede use.
REVIEWED_LAUNCH = None
AUTHORITY_PATH = Path('/tmp/windows-final-guard-0055-execution-authority.json')
EVIDENCE_ROOT = Path('/tmp/windows-final-guard-0055-authority-inputs')
REPOSITORY = Path('/home/shuaizhang/s/github.com/hcoona/microsoft-authentication-cli')
FORK = 'hcoona/microsoft-authentication-cli'
GITHUB_CLI_PATH = '/home/shuaizhang/.local/share/mise/installs/github-cli/2.88.0/gh_2.88.0_linux_amd64/bin/gh'
GITHUB_CLI_BYTES = 38613154
GITHUB_CLI_SHA256 = '8854d3cbf95e3a426df6e47e9471c7d2e4d33d2815813229b078283a55a6cb0a'
GRANT = 'a0f741b59e09f1eb95594dbfde7a6e634d962210'
PACKAGE = Path(__file__).parent.parent
PREFLIGHT_BODY_SHA256 = '11a93b9504b70e2caf1e7e6c2f333f1cda178e0adcf88d5998d3eca83450e8b9'
PREFLIGHT_ARGV_SHA256 = '47a11709b88178a0963d560b866a79d20d9e9310407c8e161365344870897bfb'
RECIPE_SHA256 = 'ed0fa260a638d3594a18dc51cbc87b588bdfa45f4fd90c7b9ce2fec501e65bcc'
COMPONENT_SELECTORS = {
    'dispatcher': 'candidate/run_windows_final_guard_prepare.draft.py',
    'controller': 'candidate/Invoke-WindowsFinalGuardPrepare.draft.ps1',
    'guard': 'candidate/WindowsValidationJob.cs',
    'preflight': 'candidate/WindowsFinalGuardPreflight.body.txt',
    'finalPublishDispatcher': 'candidate/run_windows_final_publish.draft.py',
    'finalPublishController': 'candidate/Invoke-WindowsFinalPublish.draft.ps1',
    'guardHistory': 'authority-inputs/final_guard_history.py',
    'linuxHistoryReader': 'authority-inputs/run_managed.py',
    'windowsHistoryReader': 'authority-inputs/run_windows.py',
    'windowsHistoryController': 'authority-inputs/Invoke-WindowsValidation.ps1',
}
COMPONENT_REPOSITORY_PATHS = {
    'dispatcher': 'tools/validation/run_windows_final_guard_prepare.py',
    'controller': 'tools/validation/Invoke-WindowsFinalGuardPrepare.ps1',
    'guard': 'tools/validation/WindowsFinalPublishGuard.cs',
    'preflight': 'tools/validation/WindowsFinalGuardPreflight.body.txt',
    'finalPublishDispatcher': 'tools/validation/run_windows_final_publish.py',
    'finalPublishController': 'tools/validation/Invoke-WindowsFinalPublish.ps1',
    'guardHistory': 'tools/validation/final_guard_history.py',
    'linuxHistoryReader': 'tools/validation/run_managed.py',
    'windowsHistoryReader': 'tools/validation/run_windows.py',
    'windowsHistoryController': 'tools/validation/Invoke-WindowsValidation.ps1',
}
EVIDENCE_SELECTORS = {
    'sourceReview': 'source-review-v2.json',
    'handoffManifest': '/tmp/windows-final-guard-authority-inputs/post0053-handoff.json',
    'handoffAcceptance': '/tmp/windows-final-guard-authority-inputs/post0053-handoff-acceptance.json',
    'executionAdmission': 'execution-admission-v2.json',
    'publication': 'publication-v2.json',
    'receiptPolicy': '/tmp/windows-final-guard-authority-inputs/receipt-artifact-policy.json',
    'failedGuardDisposition': '/tmp/windows-final-guard-0054-failed-history-disposition-v1.json',
    'fixtureDisposition': 'fixture-disposition.json',
}
LIMITS = {
    'guardPreparations': 2, 'linuxPreparationCeiling': 9,
    'windowsPreparationCeiling': 7, 'combinedPreparationCeiling': 16, 'fixtureBuildTestCharge': 1,
    'windowsBuildTestCeiling': 48, 'combinedBuildTestCeiling': 120,
    'reservedProcessScenarios': 0, 'preparationCharge': 1,
    'buildTestCharge': 0, 'publishCharge': 0,
    'outerMilliseconds': 230000, 'preflightMilliseconds': 20000,
    'handshakeMilliseconds': 20000, 'compilerMilliseconds': 30000,
    'cleanupMillisecondsWithinOriginal': 10000, 'externalCallMilliseconds': 30000,
    'accountEffects': False, 'installation': False, 'retry': False,
}
ROOT_MARKER = {'grant': GRANT, 'issue': 108, 'protocol_family': PROTOCOL_PATH}


def binding_spec(path):
    return {'path': str(path), 'bytes': '@size', 'sha256': '@hash'}


ENVELOPE_SPEC = {
    'schema': 'final-guard-external-authority-v2',
    'repository': FORK, 'branch': 'main-v2', 'scope': 'compiler-only-final-guard-prepare',
    'target': {'commit': '@rev', 'tree': '@rev'},
    'wave': {'path': 'docs/delivery-wave.md', 'blob': '@rev', 'sha256': '@hash'},
    'protocol': {'commit': '@rev', 'tree': '@rev', 'path': PROTOCOL_PATH,
                 'blob': '@rev', 'sha256': '@hash'},
    'source': {'commit': '@rev', 'tree': '@rev'},
    'handoffSource': {'commit': '@rev', 'tree': '@rev'},
    'handoffProtocol': {'commit': '@rev', 'sha256': '@hash'},
    'components': {role: {'commit': '@rev', 'tree': '@rev', 'repositoryPath': path,
                           'gitBlob': '@rev', 'bytes': '@size', 'sha256': '@hash'}
                   for role, path in COMPONENT_REPOSITORY_PATHS.items()},
    **{role: binding_spec(EVIDENCE_ROOT / name) for role, name in EVIDENCE_SELECTORS.items()},
    'rootMarkers': {'linuxOwnerSha256': '@hash', 'windowsOwnerSha256': '@hash',
                    'semanticMarker': ROOT_MARKER},
    'recipeSha256': RECIPE_SHA256, 'toolSha256': RECIPE['tools']['sha256'],
    'preflight': {'bodySha256': PREFLIGHT_BODY_SHA256, 'argvSha256': PREFLIGHT_ARGV_SHA256},
    'limits': LIMITS,
}


@dataclass(frozen=True)
class VerifiedAdmission:
    envelope_bytes: bytes
    envelope_sha256: str
    envelope: object
    accepted: object
    handoff_bytes: bytes
    handoff_acceptance_bytes: bytes
    component_bytes: object
    continuity: tuple
    preflight_command: tuple
    guard_module: object
    guard_state: dict


def freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze(item) for item in value)
    return value


def compact(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def assert_shape(value, spec):
    if type(spec) is dict:
        if type(value) is not dict or set(value) != set(spec):
            raise ValueError('Unknown or missing authority fields')
        for key in spec:
            assert_shape(value[key], spec[key])
    elif spec in ('@rev', '@hash', '@size', '@positive', '@login', '@timestamp'):
        if spec in ('@size', '@positive'):
            upper = 8 * 1024 * 1024 if spec == '@size' else 9223372036854775807
            if type(value) is not int or not 0 < value <= upper:
                raise ValueError('Invalid authority integer')
        else:
            expression = {'@rev': '[0-9a-f]{40}', '@hash': '[0-9a-f]{64}',
                          '@login': '[A-Za-z0-9_-]{1,100}',
                          '@timestamp': '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z'}[spec]
            if type(value) is not str or re.fullmatch(expression, value) is None:
                raise ValueError('Invalid authority string')
    elif type(value) is not type(spec) or value != spec:
        raise ValueError('Fixed authority value changed')


def check_time(deadline, cancelled):
    if cancelled():
        raise InterruptedError('External verification cancelled')
    return remaining(deadline)


def authority_bytes(path, deadline, cancelled, limit=1024 * 1024):
    check_time(deadline, cancelled)
    data = read_bytes(path, limit)
    check_time(deadline, cancelled)
    return data


class AdmissionContinuity(list):
    def __init__(self):
        super().__init__()
        self.reads = 0
        self.bytes = 0


def bound_input(binding, deadline, cancelled, continuity, limit=1024 * 1024):
    continuity.reads += 1
    continuity.bytes += binding['bytes'] + 1
    if continuity.reads > 128 or continuity.bytes > 67108864:
        raise ValueError('Shared guard-validation input bound exceeded')
    data = authority_bytes(binding['path'], deadline, cancelled, limit)
    if len(data) != binding['bytes'] or hash_bytes(data) != binding['sha256']:
        raise ValueError('External input binding changed')
    continuity.append((str(binding['path']), len(data), hash_bytes(data)))
    return data


def verify_github_cli(deadline, cancelled):
    check_time(deadline, cancelled)
    path = direct(GITHUB_CLI_PATH)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != GITHUB_CLI_BYTES or not info.st_mode & 0o111:
            raise ValueError('Fixed GitHub CLI type, size or executable mode changed')
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                check_time(deadline, cancelled)
                total += len(chunk)
                if total > GITHUB_CLI_BYTES:
                    raise ValueError('Fixed GitHub CLI exceeded its exact size')
                digest.update(chunk)
        if total != GITHUB_CLI_BYTES or digest.hexdigest() != GITHUB_CLI_SHA256:
            raise ValueError('Fixed GitHub CLI identity changed')
    finally:
        os.close(fd)
    check_time(deadline, cancelled)


def public_read(argv, deadline, cancelled, output_limit=1024 * 1024):
    """One fixed local Git/GET process; never a Windows proxy or subject runner."""
    check_time(deadline, cancelled)
    end = min(deadline, time.monotonic_ns() + 30_000_000_000)
    if argv[0] not in ('/usr/bin/git', GITHUB_CLI_PATH):
        raise ValueError('Unknown fixed local verification executable')
    if argv[0] == GITHUB_CLI_PATH:
        verify_github_cli(end, cancelled)
    check_time(end, cancelled)
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={
                                   **{key: value for key, value in os.environ.items()
                                      if not key.startswith(('GIT_', 'GH_'))},
                                   **({'GH_TOKEN': os.environ['GH_TOKEN']} if 'GH_TOKEN' in os.environ else {}),
                                   'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1',
                                   'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
                                   'GH_PROMPT_DISABLED': '1', 'GH_PAGER': 'cat', 'GIT_PAGER': 'cat'},
                               start_new_session=True)
    selector = selectors.DefaultSelector()
    captured = bytearray()
    total = 0
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            available = check_time(end, cancelled)
            for key, _mask in selector.select(min(0.025, available)):
                data = os.read(key.fileobj.fileno(), 8192)
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    total += len(data)
                    if total > output_limit:
                        raise ValueError('External output exceeded bound')
                    if key.fileobj is process.stdout:
                        captured.extend(data)
        check_time(end, cancelled)
        if process.returncode != 0:
            raise RuntimeError('Fixed read-only Git or GitHub GET failed')
        return bytes(captured)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            # Local read-only verifier only. No kill of an interop/Windows proxy.
            process.kill()
            left = max(0.0, (end - time.monotonic_ns()) / 1_000_000_000)
            if left:
                try:
                    process.wait(timeout=left)
                except subprocess.TimeoutExpired:
                    pass


def git_read(arguments, deadline, cancelled):
    return public_read(['/usr/bin/git', '--no-replace-objects', '-C', str(REPOSITORY),
                        *arguments], deadline, cancelled)


def github_get(endpoint, deadline, cancelled):
    # Endpoints are constructed only below from the fixed fork and checked IDs.
    return public_read([GITHUB_CLI_PATH, 'api', '--hostname', 'github.com', '--method', 'GET',
                        '-H', 'Accept: application/vnd.github+json',
                        '-H', 'X-GitHub-Api-Version: 2022-11-28', endpoint], deadline, cancelled)


def assert_target_current(envelope, deadline, cancelled):
    record = decode(github_get('repos/' + FORK + '/git/ref/heads/main-v2', deadline, cancelled))
    if (record.get('ref') != 'refs/heads/main-v2' or
            record.get('object', {}).get('type') != 'commit' or
            record.get('object', {}).get('sha') != envelope['target']['commit']):
        raise ValueError('Accepted target changed; refresh admission without retry')


def verify_git_object(commit, tree, path, blob, data, deadline, cancelled):
    resolved_tree = git_read(['rev-parse', '--verify', commit + '^{tree}'], deadline, cancelled)
    if resolved_tree != (tree + '\n').encode('ascii'):
        raise ValueError('Immutable Git tree changed')
    entry = git_read(['ls-tree', commit, '--', path], deadline, cancelled)
    entries = [b'100644 blob ' + blob.encode('ascii') + b'\t' + path.encode('ascii') + b'\n',
               b'100755 blob ' + blob.encode('ascii') + b'\t' + path.encode('ascii') + b'\n']
    if entry not in entries:
        raise ValueError('Missing, linked or wrong Git component')
    actual = git_read(['cat-file', 'blob', blob], deadline, cancelled)
    if actual != data:
        raise ValueError('Materialized bytes differ from immutable Git source')


def verify_public_review(binding, expected_body, deadline, cancelled):
    spec = {'commentId': '@positive', 'pullRequest': '@positive', 'userId': '@positive',
            'userLogin': '@login', 'createdAt': '@timestamp', 'updatedAt': '@timestamp',
            'bodyBytes': '@size', 'bodySha256': '@hash', 'apiBytes': '@size', 'apiSha256': '@hash',
            'publicUrl': 'https://github.com/' + FORK + '/pull/' + str(binding.get('pullRequest')) +
                         '#issuecomment-' + str(binding.get('commentId'))}
    assert_shape(binding, spec)
    raw = github_get('repos/' + FORK + '/issues/comments/' + str(binding['commentId']), deadline, cancelled)
    if len(raw) != binding['apiBytes'] or hash_bytes(raw) != binding['apiSha256']:
        raise ValueError('Public review GET representation changed')
    review = decode(raw)
    if (type(review) is not dict or type(review.get('body')) is not str or
            type(review.get('id')) is not int or type(review.get('user', {}).get('id')) is not int or
            review.get('id') != binding['commentId'] or review.get('html_url') != binding['publicUrl'] or
            review.get('issue_url') != 'https://api.github.com/repos/' + FORK + '/issues/' + str(binding['pullRequest']) or
            review.get('user', {}).get('id') != binding['userId'] or
            review.get('user', {}).get('login') != binding['userLogin'] or
            review.get('created_at') != binding['createdAt'] or review.get('updated_at') != binding['updatedAt']):
        raise ValueError('Public review provenance changed')
    body = review['body'].encode('utf-8')
    if body != expected_body or len(body) != binding['bodyBytes'] or hash_bytes(body) != binding['bodySha256']:
        raise ValueError('Public review body differs from pinned acceptance')
    # Exact evidence/provenance continuity is mechanical. Independence, meaning
    # and risk disposition must already be accepted in the final launcher review.


def validate_handoff(manifest, acceptance, envelope):
    if type(manifest) is not dict or set(manifest) != {
            'schema', 'source', 'protocol', 'histories', 'recomputedCounters', 'defaultHttpGreenAccepted'}:
        raise ValueError('Invalid evidence-only handoff or reverse review binding')
    if (manifest['schema'] != 'final-guard-original-history-handoff-v1' or
            manifest['source'] != envelope['handoffSource'] or manifest['protocol'] != envelope['handoffProtocol'] or
            manifest['defaultHttpGreenAccepted'] is not True):
        raise ValueError('Post-GREEN evidence identity changed')
    if type(manifest['histories']) is not dict or set(manifest['histories']) != {'linux', 'windows'}:
        raise ValueError('Incomplete original history')
    if type(manifest['recomputedCounters']) is not dict or set(manifest['recomputedCounters']) != {'linux', 'windows'}:
        raise ValueError('Invalid original counters')
    for platform in ('linux', 'windows'):
        entries = manifest['histories'][platform]
        counters = manifest['recomputedCounters'][platform]
        if type(entries) is not list or not 1 <= len(entries) <= 9999:
            raise ValueError('Invalid original history length')
        if type(counters) is not list or len(counters) != 4 or any(type(n) is not int or n < 0 for n in counters):
            raise ValueError('Invalid original counter types')
        for number, item in enumerate(entries, 1):
            if type(item) is not dict or set(item) != {'number', 'localEntryNames', 'localFiles', 'windowsFiles', 'safetyMarkers'}:
                raise ValueError('Invalid pinned action fields')
            if item['number'] != f'{number:04d}':
                raise ValueError('Noncontiguous handoff')
            if type(item['localEntryNames']) is not list or item['localEntryNames'] != sorted(set(item['localEntryNames'])):
                raise ValueError('Invalid original entry inventory')
            for name in item['localEntryNames']:
                if len(safe_relative(name).parts) != 1:
                    raise ValueError('Invalid original entry name')
            for field in ('localFiles', 'windowsFiles'):
                if type(item[field]) is not dict or len(item[field]) > 10000:
                    raise ValueError('Invalid original file inventory')
                for path, digest in item[field].items():
                    safe_relative(path)
                    assert_shape(digest, '@hash')
            if 'started.json' not in item['localFiles']:
                raise ValueError('Missing original reservation')
            if type(item['safetyMarkers']) is not dict or set(item['safetyMarkers']) != {
                    'owned-host-safety-stop.json', 'process-safety-stop.json'}:
                raise ValueError('Incomplete historical stop disposition')
            for digest in item['safetyMarkers'].values():
                if digest is not None:
                    assert_shape(digest, '@hash')
    expected = {'schema': 'final-guard-handoff-acceptance-v1', 'accepted': True,
                'scope': 'complete-original-post0053-history', 'source': envelope['handoffSource'],
                'protocol': envelope['handoffProtocol'], 'manifestBinding': envelope['handoffManifest'],
                'completeHistoryAccepted': True, 'dispositionsAccepted': True, 'greenAccepted': True}
    assert_shape(acceptance, expected)


def fixed_preflight(body):
    if hash_bytes(body) != PREFLIGHT_BODY_SHA256:
        raise ValueError('Fixed preflight body changed')
    text = body.decode('utf-8')
    command = [POWERSHELL, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
               base64.b64encode(text.encode('utf-16-le')).decode('ascii')]
    if hash_bytes(compact(command)[:-1]) != PREFLIGHT_ARGV_SHA256:
        raise ValueError('Fixed preflight argv changed')
    pins = re.findall(r"^Assert-FixedTool '([^']+)' '([0-9a-f]{64})'$", text, re.MULTILINE)
    if len(pins) != 6 or dict(pins) != RECIPE['tools']['sha256']:
        raise ValueError('Fixed preflight six-tool definitions changed')
    return tuple(command)


def load_external_admission(deadline, cancelled):
    """One bounded admission load under the original WSL clock; no history reads."""
    check_time(deadline, cancelled)
    if DRAFT_ONLY or REVIEWED_LAUNCH is None:
        raise RuntimeError('UNBOUND: separately reviewed literal envelope launcher')
    assert_shape(REVIEWED_LAUNCH, binding_spec(AUTHORITY_PATH))
    continuity = AdmissionContinuity()
    envelope_bytes = bound_input(REVIEWED_LAUNCH, deadline, cancelled, continuity)
    envelope = decode(envelope_bytes)
    assert_shape(envelope, ENVELOPE_SPEC)
    if compact(envelope) != envelope_bytes:
        raise ValueError('Noncanonical authority envelope')
    assert_target_current(envelope, deadline, cancelled)
    # P may differ from S/T. No fetch, checkout, mutation, subject or SDK call.
    revisions = {envelope[key]['commit'] for key in ('target', 'protocol', 'source', 'handoffSource', 'handoffProtocol')}
    for revision in sorted(revisions):
        if git_read(['cat-file', '-t', revision], deadline, cancelled) != b'commit\n':
            raise ValueError('Full immutable commit object required')
    git_read(['merge-base', '--is-ancestor', envelope['protocol']['commit'], envelope['target']['commit']], deadline, cancelled)
    git_read(['merge-base', '--is-ancestor', GRANT, envelope['source']['commit']], deadline, cancelled)
    for key in ('wave', 'protocol'):
        binding = envelope[key]
        owner = envelope['target'] if key == 'wave' else envelope['protocol']
        data = git_read(['cat-file', 'blob', binding['blob']], deadline, cancelled)
        if hash_bytes(data) != binding['sha256']:
            raise ValueError('Accepted Wave or protocol bytes changed')
        verify_git_object(owner['commit'], owner['tree'], binding['path'], binding['blob'], data, deadline, cancelled)
        if key == 'protocol':
            # An ancestral P is insufficient if T has replaced its current protocol.
            verify_git_object(envelope['target']['commit'], envelope['target']['tree'],
                              binding['path'], binding['blob'], data, deadline, cancelled)
    handoff_tree = git_read(['rev-parse', '--verify', envelope['handoffSource']['commit'] + '^{tree}'], deadline, cancelled)
    if handoff_tree != (envelope['handoffSource']['tree'] + '\n').encode('ascii'):
        raise ValueError('Original GREEN source tree changed')
    handoff_protocol = git_read(['show', envelope['handoffProtocol']['commit'] + ':' + PROTOCOL_PATH], deadline, cancelled)
    if hash_bytes(handoff_protocol) != envelope['handoffProtocol']['sha256']:
        raise ValueError('Original GREEN protocol identity changed')
    components = {}
    for role, selector in COMPONENT_SELECTORS.items():
        item = envelope['components'][role]
        if role in ('dispatcher', 'controller', 'guard', 'preflight', 'finalPublishDispatcher', 'finalPublishController'):
            owner = envelope['source']
        else:
            owner = envelope['protocol']
        if item['commit'] != owner['commit'] or item['tree'] != owner['tree']:
            raise ValueError('Component protocol/source role changed')
        binding = {'path': str(PACKAGE / selector), 'bytes': item['bytes'], 'sha256': item['sha256']}
        data = bound_input(binding, deadline, cancelled, continuity)
        verify_git_object(item['commit'], item['tree'], item['repositoryPath'], item['gitBlob'], data, deadline, cancelled)
        components[role] = data
    if Path(__file__).absolute() != PACKAGE / COMPONENT_SELECTORS['dispatcher']:
        raise ValueError('Dispatcher is not the fixed materialized source')
    if hash_bytes(components['guard']) != SOURCE_SHA256:
        raise ValueError('Guard activation source changed')
    recipe_binding = {'path': str(PACKAGE / 'recipe.json'),
                      'bytes': 6720, 'sha256': RECIPE_SHA256}
    recipe_bytes = bound_input(recipe_binding, deadline, cancelled, continuity)
    if decode(recipe_bytes) != RECIPE:
        raise ValueError('Embedded compiler recipe differs from sealed recipe')
    command = fixed_preflight(components['preflight'])
    evidence_bytes = {role: bound_input(envelope[role], deadline, cancelled, continuity,
                                       8 * 1024 * 1024 if role == 'handoffManifest' else 1024 * 1024)
                      for role in EVIDENCE_SELECTORS}
    evidence = {role: decode(data) for role, data in evidence_bytes.items()}
    source_review = {'schema': 'final-guard-source-acceptance-v2', 'accepted': True,
                     'scope': 'guard-preparation-source-activation-and-final-callers',
                     'source': envelope['source'], 'components': envelope['components'],
                     'callerPolicy': 'fixed-final-only-callers-no-generic-helper-use',
                     'protocol': envelope['protocol'], 'recipeSha256': RECIPE_SHA256,
                     'preflight': envelope['preflight'], 'toolSha256': envelope['toolSha256'],
                     'failedGuardDisposition': envelope['failedGuardDisposition'],
                     'fixtureDisposition': envelope['fixtureDisposition']}
    assert_shape(evidence['sourceReview'], source_review)
    validate_handoff(evidence['handoffManifest'], evidence['handoffAcceptance'], envelope)
    policy = {'schema': 'final-guard-receipt-artifact-policy-v1', 'scope': ACTION,
              'originalCompletionRequired': True, 'managedArtifactReviewRequired': True,
              'artifactAcceptedOnCollection': False, 'continuationAllowedOnCollection': False}
    assert_shape(evidence['receiptPolicy'], policy)
    admission = {key: envelope[key] for key in ('repository', 'branch', 'scope', 'target', 'wave', 'protocol',
                  'source', 'handoffSource', 'handoffProtocol', 'components', 'sourceReview', 'handoffManifest', 'handoffAcceptance',
                  'receiptPolicy', 'rootMarkers', 'recipeSha256', 'toolSha256', 'preflight', 'limits',
                  'failedGuardDisposition', 'fixtureDisposition')}
    admission.update(schema='final-guard-execution-admission-v2', accepted=True)
    assert_shape(evidence['executionAdmission'], admission)
    publication = evidence['publication']
    roles = ('sourceReview', 'handoffAcceptance', 'executionAdmission')
    if type(publication) is not dict or set(publication) != {'schema', 'repository', *roles}:
        raise ValueError('Invalid publication inventory')
    if publication['schema'] != 'final-guard-publication-binding-v1' or publication['repository'] != FORK:
        raise ValueError('Invalid publication repository')
    for role in roles:
        verify_public_review(publication[role], evidence_bytes[role], deadline, cancelled)
    accepted = {
        'protocolCommit': envelope['protocol']['commit'], 'protocolSha256': envelope['protocol']['sha256'],
        'waveBlob': envelope['wave']['blob'], 'sourceCommit': envelope['source']['commit'],
        'sourceTree': envelope['source']['tree'], 'sourceBlob': envelope['components']['guard']['gitBlob'],
        'sourceAcceptanceSha256': envelope['sourceReview']['sha256'],
        'executionAdmissionSha256': envelope['executionAdmission']['sha256'],
        'preparationControllerSha256': envelope['components']['controller']['sha256'],
        'dispatcherSha256': envelope['components']['dispatcher']['sha256'],
        'handoffManifestSha256': envelope['handoffManifest']['sha256'],
        'handoffIndependentAcceptanceSha256': envelope['handoffAcceptance']['sha256'],
        'linuxOwnerSha256': envelope['rootMarkers']['linuxOwnerSha256'],
        'windowsOwnerSha256': envelope['rootMarkers']['windowsOwnerSha256'],
    }
    import importlib.util
    module_path = PACKAGE / COMPONENT_SELECTORS['guardHistory']
    spec = importlib.util.spec_from_file_location('accepted_final_guard_history', module_path)
    guard_module = importlib.util.module_from_spec(spec)
    exec(compile(components['guardHistory'], str(module_path), 'exec', dont_inherit=True), guard_module.__dict__)
    if Path(guard_module.__file__).absolute() != module_path:
        raise ValueError('Actual guard-history module source changed')
    guard_state = guard_module.new_state(deadline=deadline / 1_000_000_000)
    guard_state['deadline'] = deadline / 1_000_000_000
    guard_state['moduleBinding'] = {'path': str(module_path), 'bytes': len(components['guardHistory']), 'sha256': hash_bytes(components['guardHistory'])}
    guard_state['reads'] = continuity.reads
    guard_state['bytes'] = continuity.bytes
    guard_module.load_context(envelope['failedGuardDisposition'], envelope['fixtureDisposition'], guard_state)
    guard_state['checkpoints'] = 0
    check_time(deadline, cancelled)
    return VerifiedAdmission(envelope_bytes, hash_bytes(envelope_bytes), freeze(envelope), freeze(accepted),
                             evidence_bytes['handoffManifest'], evidence_bytes['handoffAcceptance'],
                             freeze(components), tuple(continuity), command, guard_module, guard_state)


def assert_descriptor_continuity(descriptor, deadline, cancelled):
    if type(descriptor) is not VerifiedAdmission:
        raise ValueError('Original verified descriptor required')
    state = descriptor.guard_state
    state['checkpoints'] += 1
    if state['checkpoints'] > 3:
        raise ValueError('No fourth private continuity checkpoint')
    fixed = {path: ({'path': path, 'bytes': size, 'sha256': digest},
                   8388608 if path.endswith('/post0053-handoff.json') else 1048576)
             for path, size, digest in descriptor.continuity}
    for path, value in state['continuity'].items():
        if path in fixed and fixed[path][0] != value[0]:
            raise ValueError('Conflicting fixed private dependency')
        fixed[path] = value
    for path, (item, limit) in fixed.items():
        check_time(deadline, cancelled)
        descriptor.guard_module._guard_file(path, item, state, limit, track=False)
    if hash_bytes(descriptor.envelope_bytes) != descriptor.envelope_sha256:
        raise ValueError('Immutable envelope continuity changed')


def assert_owner_markers(descriptor, deadline, cancelled):
    for path, key in ((LINUX / 'owner.json', 'linuxOwnerSha256'),
                      (PROJECTION / 'owner.json', 'windowsOwnerSha256')):
        data = authority_bytes(path, deadline, cancelled)
        if hash_bytes(data) != descriptor.accepted[key] or decode(data) != ROOT_MARKER:
            raise ValueError('Original root owner marker changed')


# Actual later evidence and final entrypoints are still unresolved/rejecting.
ACCEPTED_TAIL = None
ACCEPTED_FINAL_ALLOCATION = None
_retained_proxies = []


def direct(path):
    path = Path(path)
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("Linked input or output")
    return path


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def read_bytes(path, limit=8 * 1024 * 1024):
    path = direct(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError("Missing, nonregular or oversized input")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Input exceeded bound")
    return data


def exact_bytes(path, expected, limit=8 * 1024 * 1024):
    if not isinstance(expected, str) or re.fullmatch("[0-9a-f]{64}", expected) is None:
        raise ValueError("Unbound exact hash")
    data = read_bytes(path, limit)
    if hash_bytes(data) != expected:
        raise ValueError("Input identity changed")
    return data


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate receipt field")
        result[key] = value
    return result


def decode(data):
    return json.loads(data.decode("utf-8-sig"), object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_new(path, data):
    path = direct(path)
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    # Reserve durability on the original filesystem, not a shadow counter file.
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("Invalid relative evidence path")
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("Evidence escapes action")
    return path


def names(directory):
    directory = direct(directory)
    values = sorted(path.name for path in directory.iterdir())
    if values != [f"{index:04d}" for index in range(1, len(values) + 1)]:
        raise ValueError("Noncontiguous original history")
    # Exact0054 leaf kind/link checks belong to the shared D54 transaction.
    if any(not direct(directory / value).is_dir() for value in values
           if not (directory in (HISTORY, PROJECTION / "actions") and value == "0054")):
        raise ValueError("Non-directory history entry")
    return values


def classify(platform, start):
    """No unknown-kind fallback; fixed units apply even to failed reservations."""
    kind = start.get("action")
    if platform == "linux":
        if kind in ("fetch", "restore"):
            return (1, 0, 0, 0)
        if kind in ("build", "test"):
            return (0, 1, 0, 0)
        raise ValueError("Unknown Linux allocation")
    if kind in ("bootstrap", "restore", ACTION):
        expected = 0
        charge = (1, 0, 0)
    elif kind == "final-publish":
        expected = 0
        charge = (0, 0, 1)
    elif kind in ("build", "test"):
        expected = start.get("reservedProcessScenarios", 0)
        charge = (0, 1, 0)
    else:
        raise ValueError("Unknown Windows allocation")
    if type(expected) is not int or expected < 0:
        raise ValueError("Invalid process charge")
    if kind in (ACTION, "final-publish") and start.get("reservedProcessScenarios") != 0:
        raise ValueError("Preparation/publish is not a synthetic case")
    return (*charge, expected)


def verify_pinned_action(platform, number, item):
    """Exact accepted maps preserve old failed receipts; no new failure bypass."""
    local = (LINUX / "actions" if platform == "linux" else HISTORY) / number
    if item.get("number") != number:
        raise ValueError("Handoff order changed")
    if sorted(path.name for path in direct(local).iterdir()) != item["localEntryNames"]:
        raise ValueError("Original local receipt inventory changed")
    for relative, digest in item["localFiles"].items():
        exact_bytes(local / safe_relative(relative), digest)
    start = decode(exact_bytes(local / "started.json", item["localFiles"]["started.json"]))
    # Actual Windows files include the original result.evidence map, reservation
    # pair, bootstrap artifacts and disposed-action bindings admitted at handoff.
    if platform == "windows":
        owned = PROJECTION / "actions" / number
        for relative, digest in item["windowsFiles"].items():
            exact_bytes(owned / safe_relative(relative), digest)
        for marker in ("owned-host-safety-stop.json", "process-safety-stop.json"):
            # An accepted historical stopped case can have an exactly bound marker;
            # absence or presence must match its unchanged manifest disposition.
            path = owned / "temp" / marker
            expected = item["safetyMarkers"].get(marker)
            if expected is None:
                if path.exists() or path.is_symlink():
                    raise ValueError("Unadmitted fixture safety stop")
            else:
                exact_bytes(path, expected)
    return start


def refresh_histories_under_lock(descriptor, deadline, cancelled):
    assert_descriptor_continuity(descriptor, deadline, cancelled)
    manifest = decode(descriptor.handoff_bytes)
    validate_handoff(manifest, decode(descriptor.handoff_acceptance_bytes),
                     decode(descriptor.envelope_bytes))
    original = manifest["histories"]
    actual_linux = names(LINUX / "actions")
    actual_windows = names(HISTORY)
    if actual_linux != [item["number"] for item in original["linux"]]:
        raise ValueError("Intervening Linux history needs fresh admission")
    prefix = [item["number"] for item in original["windows"]]
    if actual_windows[:len(prefix)] != prefix or len(actual_windows) < len(prefix):
        raise ValueError("Windows prefix changed")
    if names(PROJECTION / "actions") != actual_windows:
        raise ValueError("Windows/WSL action directories disagree")
    totals = {"linux": [0, 0, 0, 0], "windows": [0, 0, 0, 0]}
    starts = []
    for platform in ("linux", "windows"):
        for item in original[platform]:
            start = verify_pinned_action(platform, item["number"], item)
            totals[platform] = [a + b for a, b in zip(totals[platform], classify(platform, start))]
            if platform == "windows":
                starts.append(start)
    if totals != manifest["recomputedCounters"]:
        raise ValueError("Handoff counters do not match original reservations")
    # This exact prefix must have an independently accepted completed GREEN;
    # merely assigning its boolean in an unpinned caller object has no effect.
    if manifest.get("defaultHttpGreenAccepted") is not True:
        raise ValueError("Dependent ordinary GREEN validation is incomplete")
    tail = actual_windows[len(prefix):]
    if not tail or tail[0] != '0054':
        raise ValueError('Exact disposed0054 successor prefix required')
    guard = descriptor.guard_module
    state = descriptor.guard_state
    state['deadline'] = min(deadline / 1_000_000_000, time.monotonic() + 30.0)
    # The fixed validator owns exactly two0054 content/metadata passes.
    guard.validate_history_action('dispatcher', HISTORY / '0054', PROJECTION / 'actions' / '0054',
                                 None, None, state)
    state['deadline'] = deadline / 1_000_000_000
    totals['windows'][0] += 1
    starts.append(state['failedStarted'])
    tail = tail[1:]
    if tail:
        if ACCEPTED_TAIL is None or ACCEPTED_FINAL_ALLOCATION is None or tail != [item["number"] for item in ACCEPTED_TAIL]:
            raise ValueError("UNBOUND: final-stage completion/artifact acceptance")
        required_sequence = [(ACTION, None, 0), ("final-publish", None, 0),
                             ("test", "cli", 12), ("test", "wsl-preclosed-lifetime", 1)]
        if len(ACCEPTED_TAIL) > len(required_sequence):
            raise ValueError("No retry or extra final action")
        for item, expected in zip(ACCEPTED_TAIL, required_sequence):
            start = verify_pinned_action("windows", item["number"], item)
            if (start["action"], start.get("testSuite"), start["reservedProcessScenarios"]) != expected:
                raise ValueError("Final-stage ordering or category changed")
            # Each accepted tail map must include the original paired completion,
            # independent artifact acceptance and exact scenario-specific result.
            if not item.get("independentFinalStageAcceptanceSha256"):
                raise ValueError("Unaccepted final-stage action")
            totals["windows"] = [a + b for a, b in zip(totals["windows"], classify("windows", start))]
            starts.append(start)
        lp, lb, _, _ = totals["linux"]
        wp, wb, publish, processes = totals["windows"]
        # The 48->50 Windows build/test proposal and 60->61 Wave proposal are
        # distinct authorities. A preparation transfer supplies neither one.
        if ACCEPTED_FINAL_ALLOCATION.get("windowsBuildTest") != 50 or ACCEPTED_FINAL_ALLOCATION.get("combinedBuildTest") != 120:
            raise ValueError("UNBOUND: two additional Windows test actions")
        process_ceiling = ACCEPTED_FINAL_ALLOCATION.get("syntheticProcessScenarios")
        if process_ceiling not in (60, 61) or processes > process_ceiling:
            raise ValueError("Unaccepted synthetic process allocation")
        if processes > 60 and not ACCEPTED_FINAL_ALLOCATION.get("wave61AcceptanceSha256"):
            raise ValueError("W01 needs its separate accepted Wave amendment")
        if lp > 9 or wp > 7 or lp + wp > 16 or wb > 50 or lb + wb + 1 > 120 or publish > 1:
            raise ValueError("Final-stage allocation exceeded")
    return totals, starts, len(actual_windows), manifest


def reserve_guard_under_lock(totals, starts, count, manifest, clock_started, descriptor, deadline, cancelled):
    accepted = descriptor.accepted
    number = descriptor.guard_module.successor_reservation(totals, starts, count, descriptor.guard_state)
    if len(number) != 4:
        raise ValueError("Action number overflow")
    local = direct(HISTORY / number)
    # Exactly one freshness GET immediately before the durable reservation.
    assert_target_current(descriptor.envelope, deadline, cancelled)
    check_time(deadline, cancelled)
    local.mkdir(mode=0o700)
    start = {
        "action": ACTION, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "protocol": accepted["protocolCommit"], "source": accepted["sourceCommit"],
        "sourceTree": accepted["sourceTree"], "waveBlob": accepted["waveBlob"],
        "reviewSha256": accepted["executionAdmissionSha256"],
        "handoffSha256": accepted["handoffManifestSha256"],
        "priorCounters": totals, "reservedProcessScenarios": 0,
        "preparationCharge": 1, "buildTestCharge": 0, "publishCharge": 0,
        "sourceSha256": SOURCE_SHA256, "sourceBlob": accepted["sourceBlob"],
        "preparationControllerSha256": accepted["preparationControllerSha256"],
        "authoritySha256": descriptor.envelope_sha256,
        "sourceReviewSha256": accepted["sourceAcceptanceSha256"],
        "dispatcherSha256": accepted["dispatcherSha256"],
        "preflightBodySha256": PREFLIGHT_BODY_SHA256,
        "preflightArgvSha256": PREFLIGHT_ARGV_SHA256,
        "clockNonce": secrets.token_hex(32),
        "originalClockStartNanoseconds": clock_started,
        "originalClockDeadlineNanoseconds": clock_started + 230_000_000_000,
    }
    write_new(local / "started.json", encode(start))
    # Charge is durable now. All later failures retain this directory and receipt.
    return number, local, start


def remaining(deadline):
    value = (deadline - time.monotonic_ns()) / 1_000_000_000
    if value <= 0:
        raise TimeoutError("Original 230-second outer allowance expired")
    return value


def exchange_original_clock(owned, start, invocation, original_proxy, deadline, handshake_deadline, cancelled):
    """One reply from the original WSL clock; no receive-time deadline restart."""
    if (deadline != start["originalClockDeadlineNanoseconds"] or
            deadline - start["originalClockStartNanoseconds"] != 230_000_000_000 or
            handshake_deadline > deadline):
        raise ValueError("Original WSL clock binding changed")
    ready_path = direct(owned / "clock-ready.json")
    reply_path = direct(owned / "clock-remaining.json")
    while True:
        if cancelled():
            raise InterruptedError("Cancelled during clock handoff")
        remaining(handshake_deadline)
        if original_proxy.poll() is not None:
            raise RuntimeError("Original controller exited before clock handoff")
        if ready_path.exists():
            ready_bytes = read_bytes(ready_path, 2048)
            ready = decode(ready_bytes)
            break
        time.sleep(min(0.025, remaining(handshake_deadline)))
    expected_keys = {"schema", "action", "nonce", "reservationSha256", "invocationSha256",
                     "originalOuterLimitMilliseconds", "windowsReadyElapsedTicks", "windowsClockFrequency"}
    if type(ready) is not dict or set(ready) != expected_keys:
        raise ValueError("Unexpected ready fields")
    for key, wanted in {"schema": "final-guard-clock-ready-v1", "action": invocation["action"],
                        "nonce": start["clockNonce"], "reservationSha256": hash_bytes(encode(start)),
                        "invocationSha256": hash_bytes(encode(invocation)),
                        "originalOuterLimitMilliseconds": 230000}.items():
        if type(ready[key]) is not type(wanted) or ready[key] != wanted:
            raise ValueError("Ready identity changed")
    ticks, frequency = ready["windowsReadyElapsedTicks"], ready["windowsClockFrequency"]
    if type(ticks) is not int or not 0 <= ticks <= 9223372036854775807:
        raise ValueError("Invalid ready timestamp")
    if type(frequency) is not int or not 1 <= frequency <= 9223372036854775807:
        raise ValueError("Invalid Windows clock frequency")
    if cancelled():
        raise InterruptedError("Cancelled before remaining reply")
    remaining(handshake_deadline)
    # Sample only after the exact Windows ready receipt was observed. Floor in
    # integer nanoseconds; neither serialization nor reply delay creates time.
    remaining_ms = (deadline - time.monotonic_ns()) // 1_000_000
    if not 0 < remaining_ms <= 230000:
        raise TimeoutError("Original clock expired before reply")
    reply = {"schema": "final-guard-clock-remaining-v1", "action": invocation["action"],
             "nonce": start["clockNonce"], "reservationSha256": hash_bytes(encode(start)),
             "invocationSha256": hash_bytes(encode(invocation)),
             "originalOuterLimitMilliseconds": 230000,
             "readySha256": hash_bytes(ready_bytes), "remainingMilliseconds": remaining_ms}
    # A compact ASCII line has exactly one LF, at the end. Windows waits for that
    # complete frame; it never parses an in-progress multi-line JSON prefix.
    reply_bytes = (json.dumps(reply, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    write_new(reply_path, reply_bytes)
    remaining(handshake_deadline)
    if cancelled():
        raise InterruptedError("Cancelled after remaining reply")
    return {"readySha256": hash_bytes(ready_bytes), "replySha256": hash_bytes(reply_bytes),
            "nonce": start["clockNonce"], "windowsReadyElapsedTicks": ticks,
            "windowsClockFrequency": frequency, "remainingMilliseconds": remaining_ms,
            "windowsDeadlineElapsedTicks": ticks + remaining_ms * frequency // 1000}


def start_proxy(command):
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    _retained_proxies.append(process)
    return process


def observe_proxy(process, deadline, cancelled):
    while True:
        if cancelled():
            raise InterruptedError("Controller observation cancelled")
        available = remaining(deadline)
        code = process.poll()
        if code is not None:
            if code != 0:
                raise RuntimeError("Original controller/proxy failed")
            return process
        time.sleep(min(0.05, available))


def resolve_recipe(number):
    def substitute(value):
        if isinstance(value, str):
            return value.replace("${GUARD_ACTION4}", number)
        if isinstance(value, list):
            return [substitute(item) for item in value]
        if isinstance(value, dict):
            return {key: substitute(item) for key, item in value.items()}
        return value
    return substitute(RECIPE)


def collect_normal(local, owned, start, invocation, original_proxy, clock, descriptor):
    if original_proxy.poll() != 0:
        raise ValueError("Original proxy zero exit is missing")
    receipt = decode(read_bytes(owned / "windows-result.json"))
    if receipt.get("schema") != "final-guard-windows-result-v1" or receipt.get("reservationSha256") != hash_bytes(encode(start)):
        raise ValueError("Original Windows completion binding changed")
    for key in ("normalCompletion", "compilerCompletionConfirmed", "captureCompleted", "bothStreamsEof"):
        if receipt.get(key) is not True:
            raise ValueError("Original Windows normal completion is incomplete")
    if receipt.get("compilerExitCode") != 0 or receipt.get("compilerTerminationRequested") is not False or receipt.get("safetyStop") is not False:
        raise ValueError("Failed or terminated compiler cannot establish normal success")
    if receipt.get("invocationSha256") != hash_bytes(encode(invocation)):
        raise ValueError("Original invocation mismatch")
    exact_bytes(owned / "clock-ready.json", clock["readySha256"], 2048)
    exact_bytes(owned / "clock-remaining.json", clock["replySha256"], 2048)
    if receipt.get("clockHandoff") != clock:
        raise ValueError("Original Windows clock binding changed")
    exact_bytes(owned / "authority.json", descriptor.envelope_sha256, 1024 * 1024)
    exact_bytes(owned / "final-guard/controller/WindowsFinalGuardPreflight.body.txt", PREFLIGHT_BODY_SHA256)
    for key in ("authoritySha256", "sourceReviewSha256", "preflightBodySha256", "preflightArgvSha256"):
        if receipt.get(key) != start[key] or invocation.get(key) != start[key]:
            raise ValueError("Original authority/preflight completion binding changed")
    if receipt.get("admissionSha256") != start["reviewSha256"] or receipt.get("authorityVerified") is not True:
        raise ValueError("Verified Windows projection completion is missing")
    # Fixed /nologo library compilation normally has empty output. Requiring both
    # streams empty is deliberately stricter than parsing localized diagnostics.
    for stream in ("stdout", "stderr"):
        data = exact_bytes(owned / (stream + ".bin"), receipt[stream + "Sha256"])
        if data or receipt.get(stream + "Bytes") != 0:
            raise ValueError("Unexpected compiler diagnostics")
    relative = Path("final-guard/WindowsFinalPublishGuard.dll")
    dll = read_bytes(owned / relative)
    if not dll or hash_bytes(dll) != receipt.get("dllSha256"):
        raise ValueError("Compiled artifact receipt mismatch")
    # This establishes observed output identity only; managed PE/IL/source binding
    # and independent artifact acceptance are later gates, not inferred here.
    build = {
        "schema": "final-guard-build-v1", "reservationSha256": hash_bytes(encode(start)),
        "windowsResultSha256": hash_bytes(read_bytes(owned / "windows-result.json")),
        "invocationSha256": hash_bytes(encode(invocation)), "sourceSha256": SOURCE_SHA256,
        "toolSha256": invocation["toolSha256"], "dllSha256": hash_bytes(dll),
        "dllBytes": len(dll), "dllPath": invocation["paths"]["compiledArtifactTemplate"],
        "artifactAccepted": False, "continuation_allowed": False, "clockHandoff": clock,
        "authoritySha256": descriptor.envelope_sha256,
        "sourceReviewSha256": descriptor.accepted["sourceAcceptanceSha256"],
        "admissionSha256": descriptor.accepted["executionAdmissionSha256"],
        "preflightBodySha256": PREFLIGHT_BODY_SHA256, "preflightArgvSha256": PREFLIGHT_ARGV_SHA256,
    }
    write_new(owned / "guard-build.json", encode(build))
    return {"normalCompletion": True, "quiescent": True, "artifactAccepted": False,
            "continuation_allowed": False, "guardBuildSha256": hash_bytes(encode(build)),
            "clockHandoff": clock, "authoritySha256": descriptor.envelope_sha256,
            "preflightBodySha256": PREFLIGHT_BODY_SHA256, "preflightArgvSha256": PREFLIGHT_ARGV_SHA256}


def prepare_guard_candidate():
    clock_started = time.monotonic_ns()
    deadline = clock_started + 230_000_000_000
    interrupted = False
    old_handlers = {}
    local = owned = original_proxy = None
    result = {"normalCompletion": False, "quiescent": False, "continuation_allowed": False}

    def mark_cancel(_number, _frame):
        nonlocal interrupted
        interrupted = True

    try:
        for value in (signal.SIGINT, signal.SIGTERM):
            old_handlers[value] = signal.signal(value, mark_cancel)
        descriptor = load_external_admission(deadline, lambda: interrupted)
        assert_owner_markers(descriptor, deadline, lambda: interrupted)
        with direct(LINUX / "action.lock").open("r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            totals, starts, count, manifest = refresh_histories_under_lock(descriptor, deadline, lambda: interrupted)
            remaining(deadline)
            if interrupted:
                raise InterruptedError("Cancelled before reservation")
            number, local, start = reserve_guard_under_lock(totals, starts, count, manifest, clock_started,
                                                                 descriptor, deadline, lambda: interrupted)
            try:
                # The one fixed command was derived and verified under the original clock.
                preflight_deadline = min(deadline, time.monotonic_ns() + 20_000_000_000)
                preflight_proxy = start_proxy(descriptor.preflight_command)
                observe_proxy(preflight_proxy, preflight_deadline, lambda: interrupted)
                remaining(deadline)
                owned = direct(PROJECTION / "actions" / number)
                owned.mkdir()
                for relative in ("home", "home/roaming", "home/local", "home/http", "home/plugins",
                                 "temp", "empty-program-files", "final-guard", "final-guard/source",
                                 "final-guard/controller"):
                    direct(owned / relative).mkdir()
                recipe = resolve_recipe(number)
                assert_descriptor_continuity(descriptor, deadline, lambda: interrupted)
                source = descriptor.component_bytes["guard"]
                controller = descriptor.component_bytes["controller"]
                write_new(owned / "authority.json", descriptor.envelope_bytes)
                write_new(owned / "final-guard/controller/WindowsFinalGuardPreflight.body.txt", descriptor.component_bytes["preflight"])
                exact_bytes(owned / "authority.json", descriptor.envelope_sha256, 1024 * 1024)
                exact_bytes(owned / "final-guard/controller/WindowsFinalGuardPreflight.body.txt", PREFLIGHT_BODY_SHA256)
                write_new(owned / "final-guard/source/WindowsValidationJob.cs", source)
                write_new(owned / "final-guard/controller/Invoke-WindowsFinalGuardPrepare.ps1", controller)
                exact_bytes(owned / "final-guard/source/WindowsValidationJob.cs", SOURCE_SHA256)
                # Never overwrite controller/WindowsValidationJob.cs or action 0001.
                invocation = {"schema": "final-guard-invocation-v1", "action": number,
                              "paths": recipe["paths"], "compiler": recipe["compilerInvocation"],
                              "toolSha256": recipe["tools"]["sha256"],
                              "reservationSha256": hash_bytes(encode(start)),
                              "authoritySha256": descriptor.envelope_sha256,
                              "sourceReviewSha256": descriptor.accepted["sourceAcceptanceSha256"],
                              "admissionSha256": descriptor.accepted["executionAdmissionSha256"],
                              "preflightBodySha256": PREFLIGHT_BODY_SHA256,
                              "preflightArgvSha256": PREFLIGHT_ARGV_SHA256,
                              "clockNonce": start["clockNonce"],
                              "originalOuterLimitMilliseconds": 230000,
                              "clockHandshakeLimitMilliseconds": 20000}
                write_new(owned / "started.json", encode(start))
                write_new(local / "windows-input.json", encode({"sha256": hash_bytes(encode(start))}))
                write_new(owned / "invocation.json", encode(invocation))
                command = [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                           recipe["paths"]["preparationControllerDirectoryTemplate"] + "\\Invoke-WindowsFinalGuardPrepare.ps1",
                           "-ActionName", number, "-ReservationSha256", hash_bytes(encode(start)),
                           "-InvocationSha256", hash_bytes(encode(invocation)),
                           "-AuthoritySha256", descriptor.envelope_sha256]
                handshake_deadline = min(deadline, time.monotonic_ns() + 20_000_000_000)
                original_proxy = start_proxy(command)
                clock = exchange_original_clock(owned, start, invocation, original_proxy,
                                                deadline, handshake_deadline, lambda: interrupted)
                observe_proxy(original_proxy, deadline, lambda: interrupted)
                remaining(deadline)
                result = collect_normal(local, owned, start, invocation, original_proxy, clock, descriptor)
                for platform in ("linux", "windows"):
                    for item in manifest["histories"][platform]:
                        verify_pinned_action(platform, item["number"], item)
                assert_descriptor_continuity(descriptor, deadline, lambda: interrupted)
                assert_owner_markers(descriptor, deadline, lambda: interrupted)
                remaining(deadline)
                if interrupted:
                    raise InterruptedError("Cancellation at original completion")
            except BaseException as error:
                result.update(normalCompletion=False, continuation_allowed=False,
                              artifactAccepted=False, failureType=type(error).__name__)
            finally:
                if not result["normalCompletion"]:
                    if owned is not None:
                        try:
                            write_new(owned / "cancel", b"")
                        except BaseException:
                            pass
                    # Passive emergency only. Never call the old stop controller
                    # or signal/kill/reopen a proxy or Windows PID.
                    # Cleanup shares the original clock; no deadline+10 restart.
                    end = min(deadline, time.monotonic_ns() + 10_000_000_000)
                    while original_proxy is not None and time.monotonic_ns() < end and original_proxy.poll() is None:
                        time.sleep(min(0.05, max(0.0, (end - time.monotonic_ns()) / 1_000_000_000)))
                result["utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                result["continuation_allowed"] = False
                write_new(local / "result.json", encode(result))
                if result["normalCompletion"]:
                    # Preserve the receipt if persistence returns late or cancelled;
                    # the same original invocation must fail before normal return.
                    check_time(deadline, lambda: interrupted)
    finally:
        for value, handler in old_handlers.items():
            signal.signal(value, handler)
    if result["normalCompletion"]:
        # Include shared-lock release and original signal-handler restoration.
        check_time(deadline, lambda: interrupted)
    return result


if __name__ == "__main__":
    raise RuntimeError("UNBOUND: no admitted command-line entry point")
