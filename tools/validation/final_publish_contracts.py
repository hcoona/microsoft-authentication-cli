"""Final-publication contracts for a separately accepted fixed literal.

The literal verifies immutable source before import and pins the completed
external authority envelope. A descriptor alone does not grant execution.
"""

DRAFT_ONLY = False
CORE_CSC_HISTORY_ONLY = False
COMPILER_NATIVE_INPUTS_HISTORY_ONLY = False
if CORE_CSC_HISTORY_ONLY and COMPILER_NATIVE_INPUTS_HISTORY_ONLY:
    raise RuntimeError('Observer history modes are mutually exclusive')
if DRAFT_ONLY and not (CORE_CSC_HISTORY_ONLY or COMPILER_NATIVE_INPUTS_HISTORY_ONLY):
    raise RuntimeError('DRAFT_ONLY: final publication contracts are unadmitted')

import base64
import contextlib
import datetime
import fcntl
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
import uuid

AUTHORITY = Path('/tmp/windows-final-publish0093-execution-authority.json')
EVIDENCE = Path('/tmp/windows-final-publish0093-authority-inputs')
PACKAGE = Path(__file__).absolute().parent.parent
REPOSITORY = Path('/home/shuaizhang/s/github.com/hcoona/microsoft-authentication-cli')
LINUX = Path('/var/tmp/azureauth-windows-slice-108')
HISTORY = LINUX / 'windows-actions'
PROJECTION = Path('/mnt/c/Temp/azureauth-windows-slice-108')
WINDOWS = 'C:\\Temp\\azureauth-windows-slice-108'
POWERSHELL = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
FORK = 'hcoona/microsoft-authentication-cli'
GITHUB_CLI_PATH = '/home/shuaizhang/.local/share/mise/installs/github-cli/2.88.0/gh_2.88.0_linux_amd64/bin/gh'
GITHUB_CLI_BYTES = 38613154
GITHUB_CLI_SHA256 = '8854d3cbf95e3a426df6e47e9471c7d2e4d33d2815813229b078283a55a6cb0a'
PROTOCOL = 'docs/research/experiments/windows-slice-validation.md'
PRODUCT = {'commit': '503360753accd0829801953823b1b57a4f852440',
           'tree': '8506cdd9781c8a331ea12ea8fe27a55292eec073'}
GUARD_SOURCE = 'd38846b080d5ee092fae9e21c9031712b56289093b50ca048d50589cca50ff4b'
RECIPE_SHA256 = 'bdaddd4765dfe6e9f5b48cc839097b96be411b9a3d84b581c1987e28efac06c8'
FINAL_FIRST_USE_SENTINEL = 'home/.dotnet/10.0.401.dotnetFirstUseSentinel'
GUARD_FIELDS = ('actionNumber', 'sourceSha256', 'dllSha256', 'guardBuildSha256',
                'preparationWindowsResultSha256', 'preparationWslResultSha256',
                'preparationReservationSha256', 'invocationSha256', 'compilerReceiptSha256',
                'artifactAcceptancePath', 'artifactAcceptanceSha256',
                'expectedAssemblyFullName', 'acceptedLoaderSourceSha256')
CALLER_PROVENANCE_LIMIT = 1048576
ORIGINAL_LOADER_SOURCE = 'ef16811f0f8cf481ee6a54b9b7f0552c14bbd6eeeca32bb391c255e52d35628e'
ORIGINAL_BINDING = Path('/tmp/windows-final-guard-0055-history-binding.json')
ORIGINAL_READER_REPOSITORY = Path('/tmp/azureauth-windows-guard-successor-fixture-source-108')
ORIGINAL_GUARD_EVIDENCE = Path('/tmp/windows-final-guard-0055-authority-inputs')
ORIGINAL_BINDING_REVIEW = ORIGINAL_GUARD_EVIDENCE / 'history-binding-review.json'
CALLER_AUTHORIZATION_JOINS = ('product', 'integration', 'protocol', 'components', 'recipe',
                              'sourceReview', 'guardAcceptance', 'acceptedGuard')
CALLER_AUTHORIZATION_FIELDS = ('schema', 'accepted', 'scope', *CALLER_AUTHORIZATION_JOINS,
                               'originalGuardEvidence', 'callerPolicy', 'noExecutionGrant')
CALLER_PROVENANCE_ROLES = ('binding', 'bindingReview', 'readerLauncher', 'readerLauncherAcceptance')
ORIGINAL_GUARD_AUTHORITY_FIELDS = ('branch', 'components', 'executionAdmission', 'failedGuardDisposition', 'fixtureDisposition', 'handoffAcceptance', 'handoffManifest', 'handoffProtocol', 'handoffSource', 'limits', 'preflight', 'protocol', 'publication', 'receiptPolicy', 'recipeSha256', 'repository', 'rootMarkers', 'schema', 'scope', 'source', 'sourceReview', 'target', 'toolSha256', 'wave')
ORIGINAL_GUARD_COMPONENTS = ('controller', 'dispatcher', 'finalPublishController', 'finalPublishDispatcher', 'guard', 'guardHistory', 'linuxHistoryReader', 'preflight', 'windowsHistoryController', 'windowsHistoryReader')

# Accepted successor source pins; no future K, B/R/L, or artifact hash is supplied.
ORIGINAL_SUCCESSOR_PROTOCOL = {'blob': '4925d95ad3a8a565c76ec9cb2c97fc59218dec6d',
 'commit': 'fc8408498dcc6b36729e658e41799de05d7f0190',
 'path': 'docs/research/experiments/windows-slice-validation.md',
 'sha256': '15b26e3e358867f28d88a67fc62dfb380cd406f37cbd86781670fa5b53e2371f',
 'tree': '7bf7bd51a0ed33929d010b7d938c21dd2a05a3d7'}
ORIGINAL_SUCCESSOR_VALIDATORS = {'guardHistory': {'repositoryPath': 'tools/validation/final_guard_history.py',
                  'gitBlob': 'f243211aeedeb5efab84ecf8a8cf272494ba160b',
                  'bytes': 56316,
                  'sha256': '96e30b1576b3e7524ddf05c7dc4229ca83c1530402d39594d0de172673668df3'},
 'linuxHistoryReader': {'repositoryPath': 'tools/validation/run_managed.py',
                        'gitBlob': 'e8b0b27fc81af3819ab9bb01640ad24f1998a72d',
                        'bytes': 47657,
                        'sha256': 'dd13f97e79fe84719c7540dced4a975ed22e43a85d6fbd57038264cf6056fca4'},
 'windowsHistoryReader': {'repositoryPath': 'tools/validation/run_windows.py',
                          'gitBlob': '9a3d35bbd228424553cff05ea5b68917b6b5f5e6',
                          'bytes': 140320,
                          'sha256': '1a81fc6f88b5f4e0918c84921ecea6756dd24d555a5c4dc004e7fa54acc62606'}}

# Exact accepted history data, not future execution or artifact bindings.
ORIGINAL_HISTORY_JOINS = {'failedGuardDisposition': {'bytes': 6200,
                            'path': '/tmp/windows-final-guard-0054-failed-history-disposition-v1.json',
                            'sha256': '6ce563b64be56f13281db3814e9ac19d4ff40bb0f316c451e95632cc98649ce9'},
 'fixtureDisposition': {'bytes': 919,
                        'path': '/tmp/windows-final-guard-0055-authority-inputs/fixture-disposition.json',
                        'sha256': '3299cb58d7283f5dd58b11f920f3fe37c602d2501b7b92a0dac1a6e6f485aea4'},
 'handoffAcceptance': {'bytes': 626,
                       'path': '/tmp/windows-final-guard-authority-inputs/post0053-handoff-acceptance.json',
                       'sha256': '7a864b8a5f8568ef444fb5a45185fc4b8da50f08aa0f72f5120186bf1fe3530c'},
 'handoffManifest': {'bytes': 172997,
                     'path': '/tmp/windows-final-guard-authority-inputs/post0053-handoff.json',
                     'sha256': 'e3668dc613dac94bdfeaad6dc7f64db4abf54297b5249d2b42055556a105f175'},
 'limits': {'accountEffects': False,
            'buildTestCharge': 0,
            'cleanupMillisecondsWithinOriginal': 10000,
            'combinedBuildTestCeiling': 120,
            'combinedPreparationCeiling': 16,
            'compilerMilliseconds': 30000,
            'externalCallMilliseconds': 30000,
            'fixtureBuildTestCharge': 1,
            'guardPreparations': 2,
            'handshakeMilliseconds': 20000,
            'installation': False,
            'linuxPreparationCeiling': 9,
            'outerMilliseconds': 230000,
            'preflightMilliseconds': 20000,
            'preparationCharge': 1,
            'publishCharge': 0,
            'reservedProcessScenarios': 0,
            'retry': False,
            'windowsBuildTestCeiling': 48,
            'windowsPreparationCeiling': 7}}
ORIGINAL_HISTORY_PREFIX = {'linux': {'compactSha256': '9266604b8159cfef32e91523a4d32789acd8591c89c145fb5372a62a8de0e89c',
           'entries': 45},
 'windows': {'compactSha256': '52fc1bcc1a412752659c7f1aadd049b8a94288c03eb7776b446402bf4d7cc063',
             'entries': 53}}
FAILED_GUARD_CONTENT = {'authority': {'bytes': 7161,
               'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/authority.json',
               'sha256': 'eab860fa6249ec583e33a637c2c9b0c12ae3302d3b1d2ae4bd3278fb729a55cc'},
 'controller': {'bytes': 43873,
                'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/final-guard/controller/Invoke-WindowsFinalGuardPrepare.ps1',
                'sha256': 'ea93b4eecfea6eed623a3149b648e93686db4f8bafa81561ff28ad0379e4ebae'},
 'invocation': {'bytes': 7001,
                'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/invocation.json',
                'sha256': '0a825b6d574b939e735e039ba4649510c4776f668b40c6ac70f610798982f936'},
 'windowsInput': {'bytes': 83,
                  'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054/windows-input.json',
                  'sha256': '77031c737e1dc79a1201be35503c10ca9a11b29fdf592e69062d59714c157193'},
 'windowsStarted': {'bytes': 1632,
                    'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/started.json',
                    'sha256': '3ed0846d150abd790c9a0793df686d04a3e924eaccaca68f96f802c67ae89a07'},
 'wslResult': {'bytes': 194,
               'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054/result.json',
               'sha256': 'feee51e22fab6207ddc7f9ec7c0a2db03b038a9a350cad4c1f050f7750c10d58'},
 'wslStarted': {'bytes': 1632,
                'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054/started.json',
                'sha256': '3ed0846d150abd790c9a0793df686d04a3e924eaccaca68f96f802c67ae89a07'}}
FAILED_GUARD_METADATA = {'compiler': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/compiler.json',
              'status': 'absent'},
 'compilerPending': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/compiler.json.pending',
                     'status': 'absent'},
 'dll': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/final-guard/WindowsFinalPublishGuard.dll',
         'status': 'absent'},
 'guardBuild': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/guard-build.json',
                'status': 'absent'},
 'hostSafetyStop': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/temp/owned-host-safety-stop.json',
                    'status': 'absent'},
 'processSafetyStop': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/temp/process-safety-stop.json',
                       'status': 'absent'},
 'ready': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/clock-ready.json',
           'status': 'absent'},
 'readyPending': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/clock-ready.json.pending',
                  'status': 'absent'},
 'reply': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/clock-remaining.json',
           'status': 'absent'},
 'stderr': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/stderr.bin',
            'status': 'absent'},
 'stdout': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/stdout.bin',
            'status': 'absent'},
 'windowsCancel': {'bytes': 0,
                   'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/cancel',
                   'status': 'present',
                   'type': 'file'},
 'windowsDirectory': {'bytes': 4096,
                      'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054',
                      'status': 'present',
                      'type': 'directory'},
 'windowsResult': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/windows-result.json',
                   'status': 'absent'},
 'windowsResultPending': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/windows-result.json.pending',
                          'status': 'absent'},
 'wslCancel': {'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054/cancel',
               'status': 'absent'},
 'wslDirectory': {'bytes': 4096,
                  'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054',
                  'status': 'present',
                  'type': 'directory'}}
FAILED_GUARD_CHARGE = {'buildTest': 0, 'preparation': 1, 'publish': 0, 'syntheticProcessScenarios': 0}
FAILED_GUARD_RESULT_FLAGS = {'artifactAccepted': False,
 'continuation_allowed': False,
 'failureType': 'RuntimeError',
 'normalCompletion': False,
 'quiescent': False}
FAILED_IDENTITY_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')

COMPONENTS = {
    'dispatcher': 'run_windows_final_publish.draft.py',
    'contracts': 'final_publish_contracts.py',
    'controller': 'Invoke-WindowsFinalPublish.draft.ps1',
    'bootstrap': 'Start-WindowsFinalPublish.draft.ps1',
    'nativeLauncher': 'WindowsScriptJobLauncher.cs',
}
INPUTS = ('sourceReview', 'handoff', 'handoffAcceptance', 'graph', 'graphAcceptance',
          'guardAcceptance', 'callerAuthorization', 'executionReview', 'publication')
LIMITS = {'preparation': 28, 'buildTest': 130, 'publish': 30, 'synthetic': 180,
          'outerMilliseconds': 2400000, 'actionMilliseconds': 1800000,
          'controllerMilliseconds': 1900000, 'prelaunchMilliseconds': 1810000,
          'nativeWorkMilliseconds': 2000000, 'nativeTotalMilliseconds': 2010000,
          'nativeSpawnReserveMilliseconds': 2030000, 'finalizationMilliseconds': 10000,
          'drainMilliseconds': 600000, 'observationToleranceMilliseconds': 0,
          'captureBytes': 8388608, 'activeProcesses': 32,
          'emergencyMillisecondsWithinOuter': 10000, 'retries': 0}
ROOT_MARKER = {'grant': 'a0f741b59e09f1eb95594dbfde7a6e634d962210',
               'issue': 108, 'protocol_family': PROTOCOL}


def fail(message):
    raise ValueError(message)


def keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        fail('Unknown or missing fields')


def integer(value, minimum=0, maximum=9223372036854775807):
    if type(value) is not int or not minimum <= value <= maximum:
        fail('Invalid bounded integer')
    return value


def string(value, pattern):
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        fail('Invalid fixed string')
    return value


def digest(value):
    return string(value, '[0-9a-f]{64}')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            fail('Duplicate JSON field')
        value[key] = item
    return value


def decode(data, canonical=False):
    value = json.loads(data.decode('utf-8-sig'), object_pairs_hook=pairs,
                       parse_constant=lambda _: fail('Nonfinite JSON'))
    if canonical and compact(value) != data:
        fail('Noncanonical JSON')
    return value


def budget(deadline, cancelled):
    if cancelled():
        raise InterruptedError('Final publication cancelled')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Original outer deadline expired')
    return remaining


def direct(path):
    path = Path(path)
    for item in (path, *path.parents):
        if item.is_symlink():
            fail('Linked input or output')
    return path


def read(path, deadline, cancelled, limit=8388608):
    budget(deadline, cancelled)
    path = direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            fail('Nonregular or oversized input')
        requested = limit + 1
        if CORE_CSC_HISTORY_ONLY or COMPILER_NATIVE_INPUTS_HISTORY_ONLY:
            requested = st.st_size + 1
            core_csc_charge_read(requested)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(requested)
        if CORE_CSC_HISTORY_ONLY or COMPILER_NATIVE_INPUTS_HISTORY_ONLY:
            after = os.fstat(fd)
            if (failed_identity(st) != failed_identity(after) or len(data) != st.st_size):
                fail('Observer history input changed during read')
        if len(data) > limit:
            fail('Input exceeded limit')
    finally:
        os.close(fd)
    budget(deadline, cancelled)
    return data


def bound(pin, path, deadline, cancelled, limit=8388608):
    keys(pin, ('bytes', 'sha256'))
    integer(pin['bytes'], 1, limit)
    digest(pin['sha256'])
    data = read(path, deadline, cancelled, limit)
    if len(data) != pin['bytes'] or sha(data) != pin['sha256']:
        fail('Exact immutable input changed')
    return data


def write_new(path, data, mode=0o600, *, deadline=None):
    def checkpoint():
        if deadline is not None:
            budget(deadline, lambda: False)
    checkpoint()
    path = direct(path)
    checkpoint()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        offset = 0
        while offset < len(data):
            checkpoint()
            count = os.write(fd, data[offset:offset + 65536])
            checkpoint()
            if count <= 0:
                raise OSError('Original output made no progress')
            offset += count
        checkpoint()
        os.fsync(fd)
        checkpoint()
    finally:
        os.close(fd)
    checkpoint()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        checkpoint()
        os.fsync(fd)
        checkpoint()
    finally:
        os.close(fd)
    checkpoint()


def relative(value):
    if (type(value) is not str or not value or '\\' in value or ':' in value or
            value.startswith('/') or any(x in ('', '.', '..') for x in value.split('/'))):
        fail('Invalid relative path')
    return value


def windows_path(value):
    if (type(value) is not str or not value.startswith('C:\\') or
            any(x in value for x in ('\0', '\r', '\n', '*', '?', '"', '|', '<', '>')) or
            ':' in value[2:] or any(x in ('.', '..') for x in value.split('\\'))):
        fail('Invalid exact Windows path')
    return value


def projection(value):
    value = windows_path(value)
    return Path('/mnt/c') / ntpath.normpath(value)[3:].replace('\\', '/')


def same_path(left, right):
    return ntpath.normcase(ntpath.normpath(left)) == ntpath.normcase(ntpath.normpath(right))


def git(args, deadline, cancelled):
    # Only immutable local Git queries are allowed here. Public review freshness
    # uses the separately bounded GET helper copied below from accepted source.
    return public_read(['/usr/bin/git', '--no-replace-objects', '-C', str(REPOSITORY), *args],
                       deadline, cancelled)


def verify_github_cli(deadline, cancelled):
    budget(deadline, cancelled)
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
                budget(deadline, cancelled)
                total += len(chunk)
                if total > GITHUB_CLI_BYTES:
                    raise ValueError('Fixed GitHub CLI exceeded its exact size')
                digest.update(chunk)
        if total != GITHUB_CLI_BYTES or digest.hexdigest() != GITHUB_CLI_SHA256:
            raise ValueError('Fixed GitHub CLI identity changed')
    finally:
        os.close(fd)
    budget(deadline, cancelled)


def public_read(argv, deadline, cancelled, output_limit=8388608):
    """Bounded Git/GET verification only; never an interop or subject process."""
    if COMPILER_NATIVE_INPUTS_HISTORY_ONLY or not DRAFT_ONLY:
        return compiler_verifier_read(argv, deadline, cancelled, output_limit)
    if argv[0] not in ('/usr/bin/git', GITHUB_CLI_PATH):
        fail('Not an immutable Git or public GET query')
    end = min(deadline, time.monotonic() + 30.0)
    budget(end, cancelled)
    if argv[0] == GITHUB_CLI_PATH:
        verify_github_cli(end, cancelled)
    budget(end, cancelled)
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('GIT_', 'GH_'))}
    environment.update(PATH='/usr/bin:/bin', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                       GIT_TERMINAL_PROMPT='0', GH_PROMPT_DISABLED='1', GH_PAGER='cat', GIT_PAGER='cat')
    if 'GH_TOKEN' in os.environ:
        environment['GH_TOKEN'] = os.environ['GH_TOKEN']
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, start_new_session=True)
    selector = selectors.DefaultSelector()
    captured = bytearray()
    total = 0
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            for key, _ in selector.select(min(0.025, budget(end, cancelled))):
                data = os.read(key.fileobj.fileno(), 8192)
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    total += len(data)
                    if total > output_limit:
                        fail('Public verification output exceeded its bound')
                    if key.fileobj is process.stdout:
                        captured.extend(data)
        budget(end, cancelled)
        if process.returncode != 0:
            fail('Immutable Git or public GET failed')
        return bytes(captured)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            # Only the locally created read-only verifier is stopped. This
            # function cannot launch a Windows controller, compiler or proxy.
            process.kill()
            left = max(0.0, end - time.monotonic())
            if left:
                try:
                    process.wait(timeout=left)
                except subprocess.TimeoutExpired:
                    pass


# This inactive compiler-only replacement is covered by the history source pin.
# Its one-use root also preserves failed starts before paired action reservation.
COMPILER_VERIFIER_ROOT = Path('/var/tmp/azureauth-compiler-verifiers-108-0062')
FINAL_VERIFIER_ROOT = Path('/var/tmp/azureauth-final-publish-verifiers-108-0093-v1')
FINAL_SOURCE_FILES = 34
# Four revision, six protocol/Wave blob, three ancestry, ten component,
# six review, two current-target, one inventory and two queries per source file.
FINAL_VERIFIER_MAXIMUM_CALLS = 32 + 2 * FINAL_SOURCE_FILES
_COMPILER_VERIFIER_CALLS = 0
_COMPILER_VERIFIER_FAILED = False
COMPILER_VERIFIER_TOOLS = {
    '/usr/bin/systemd-run': (97272, '03a68bafb0ebc0f5eff41cbdf3cbbdf126a3bb87e21140f9147bf78edce36d88'),
    '/usr/bin/env': (11352352, '48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0'),
    '/usr/bin/python3': (7477160, '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41'),
    '/usr/lib/systemd/systemd': (141776, '3c4b78ddb68e29e23da0465dd273f1ee82f5b9439ebfcec9798b395c05a2c1e3'),
}
COMPILER_VERIFIER_LEAF = r'''
import sys, time
deadline_ns = int(sys.argv[3])
if deadline_ns <= 0 or time.monotonic_ns() >= deadline_ns:
    raise SystemExit(125)
import json, os, signal
from pathlib import Path
path, unit = Path(sys.argv[1]), sys.argv[2]
groups = [line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
          if line.startswith('0::')]
if len(groups) != 1 or Path(groups[0]).name != unit:
    raise SystemExit(125)
fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
identity = {'pid': os.getpid(), 'startTicks': int(fields[19]),
            'cgroup': groups[0], 'unit': unit, 'observedMonotonicNs': time.monotonic_ns()}
raw = (json.dumps(identity, sort_keys=True, separators=(',', ':')) + '\n').encode()
pending = path.with_name(path.name + '.pending')
fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    if os.write(fd, raw) != len(raw):
        raise SystemExit(125)
    os.fsync(fd)
finally:
    os.close(fd)
os.link(pending, path)
pending.unlink()
fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
payload = bytearray()
while True:
    block = os.read(0, min(8192, 131073 - len(payload)))
    if not block:
        break
    payload.extend(block)
    if len(payload) > 131072:
        raise SystemExit(125)
value = json.loads(payload)
if (set(value) != {'argv', 'environment', 'deadlineNs'} or
        type(value['deadlineNs']) is not int or
        value['deadlineNs'] != deadline_ns or
        time.monotonic_ns() >= value['deadlineNs']):
    raise SystemExit(125)
fd = os.open('/dev/null', os.O_RDONLY)
os.dup2(fd, 0)
if fd != 0:
    os.close(fd)
for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ'):
    number = getattr(signal, name, None)
    if number is not None:
        signal.signal(number, signal.SIG_DFL)
if time.monotonic_ns() >= value['deadlineNs']:
    raise SystemExit(125)
os.execve(value['argv'][0], value['argv'], value['environment'])
'''


def compiler_verifier_group_empty(identity, unit):
    group = identity['cgroup']
    if (type(group) is not str or not group.startswith('/') or
            '..' in Path(group).parts or Path(group).name != unit or identity['unit'] != unit):
        fail('Verifier cgroup does not bind its unique unit')
    events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
    try:
        with events.open('rb') as stream:
            raw = stream.read(4097)
    except FileNotFoundError:
        return True
    if len(raw) > 4096:
        fail('Verifier cgroup status exceeded its bound')
    return dict(line.split() for line in raw.decode('ascii').splitlines()).get('populated') == '0'


def compiler_verifier_read(argv, deadline, cancelled, output_limit):
    """Source-fixed compiler or final supervision; failure disables the caller."""
    global _COMPILER_VERIFIER_CALLS, _COMPILER_VERIFIER_FAILED
    if DRAFT_ONLY and COMPILER_NATIVE_INPUTS_HISTORY_ONLY and not CORE_CSC_HISTORY_ONLY:
        root = COMPILER_VERIFIER_ROOT
        prefix = 'azureauth-compiler-0062-'
        maximum = 8
        start_record = {
            'schema': 'compiler-0062-verifiers-start-v1', 'maximumCalls': maximum,
            'priorCombinedBuildTest': 93, 'priorSynthetic': 52,
            'diagnosticBuildTestCharge': 1, 'diagnosticSyntheticCharge': 0}
        result_schema = 'compiler-verifier-result-v2'
    elif not DRAFT_ONLY and not CORE_CSC_HISTORY_ONLY and not COMPILER_NATIVE_INPUTS_HISTORY_ONLY:
        root = FINAL_VERIFIER_ROOT
        prefix = 'azureauth-final-publish-0093-'
        maximum = FINAL_VERIFIER_MAXIMUM_CALLS
        start_record = {
            'schema': 'final-publish-0093-verifiers-start-v1', 'maximumCalls': maximum,
            'priorCombinedBuildTest': 103, 'priorSynthetic': 147,
            'priorPreparation': 20, 'priorPublication': 2,
            'preparationCharge': 0, 'buildTestCharge': 0, 'publishCharge': 1,
            'syntheticCharge': 1, 'sameAttemptAsPairedReservation': True}
        result_schema = 'final-publish-verifier-result-v1'
    else:
        fail('Verifier mode is not admitted')
    began = time.monotonic()
    end = min(deadline, began + 30.0)
    if (_COMPILER_VERIFIER_FAILED or _COMPILER_VERIFIER_CALLS >= maximum or
            argv[0] not in ('/usr/bin/git', GITHUB_CLI_PATH) or
            type(output_limit) is not int or not 1 <= output_limit <= 8388608):
        fail('Unadmitted, repeated or failed compiler verifier')
    _COMPILER_VERIFIER_FAILED = True
    _COMPILER_VERIFIER_CALLS += 1
    number = _COMPILER_VERIFIER_CALLS
    budget(end, cancelled)
    if number == 1:
        root.mkdir(mode=0o700)
        fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        write_new(root / 'started.json', compact(dict(
            start_record, startedMonotonicNs=time.monotonic_ns())), deadline=(None if DRAFT_ONLY else end))
        for path, (size, expected) in COMPILER_VERIFIER_TOOLS.items():
            budget(end, cancelled)
            # Installed OS symlinks are permitted; exact resolved file bytes bind
            # the same trusted toolchain used by the accepted supervision batch.
            with open(path, 'rb') as stream:
                data = stream.read(size + 1)
            if len(data) != size or sha(data) != expected:
                fail('Installed verifier supervision tool changed')
    if argv[0] == GITHUB_CLI_PATH:
        verify_github_cli(end, cancelled)
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('GIT_', 'GH_'))}
    environment.update(PATH='/usr/bin:/bin', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                       GIT_TERMINAL_PROMPT='0', GH_PROMPT_DISABLED='1', GH_PAGER='cat', GIT_PAGER='cat')
    if 'GH_TOKEN' in os.environ:
        environment['GH_TOKEN'] = os.environ['GH_TOKEN']
    # Leave one preparation second plus job/start, stop and local observation
    # reserves. Recheck the complete remaining envelope immediately before spawn.
    runtime_ms = min(20000, int((budget(end, cancelled) - 9.0) * 1000))
    if runtime_ms < 1000:
        fail('Insufficient original verifier time for bounded completion')
    latest_exec = end - runtime_ms / 1000 - 4.0
    latest_exec_ns = int(latest_exec * 1_000_000_000)
    payload = compact({'argv': argv, 'environment': environment,
                       'deadlineNs': latest_exec_ns})
    if len(payload) > 131072 or len(COMPILER_VERIFIER_LEAF.encode()) > 8192:
        fail('Verifier input or bootstrap source exceeded its bound')
    directory = root / f'{number:02d}'
    directory.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    unit = f'{prefix}{uuid.uuid4().hex}-{number:02d}.service'
    identity_path = directory / 'identity.json'
    # Queue residence is unbounded. A late bootstrap checks the original
    # absolute deadline before identity effects or query-input consumption.
    command = [
        '/usr/bin/systemd-run', '--user', '--no-ask-password', '--quiet', '--wait', '--pipe',
        '--collect', '--expand-environment=no', '--job-mode=fail', '--unit=' + unit,
        '--service-type=exec', '--property=ExitType=cgroup', '--property=KillMode=control-group',
        '--property=SendSIGKILL=yes', '--property=Restart=no', '--property=JobRunningTimeoutSec=2s',
        '--property=TimeoutStartSec=2s', '--property=RuntimeMaxSec=' + str(runtime_ms) + 'ms',
        '--property=TimeoutStopSec=2s', '--working-directory=' + os.getcwd(), '--',
        '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C.UTF-8',
        '/usr/bin/python3', '-I', '-B', '-S', '-c', COMPILER_VERIFIER_LEAF,
        str(identity_path), unit, str(latest_exec_ns),
    ]
    runtime = '/run/user/' + str(os.getuid())
    client_environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8',
                          'XDG_RUNTIME_DIR': runtime,
                          'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus'}
    write_new(directory / 'started.json', compact({'unit': unit, 'call': number,
        'startedMonotonicNs': time.monotonic_ns(), 'deadlineMonotonicNs': int(end * 1_000_000_000),
        'runtimeMilliseconds': runtime_ms, 'jobRunningMilliseconds': 2000,
        'queueTimeoutConfigured': False,
        'startMilliseconds': 2000, 'stopMilliseconds': 2000}), deadline=(None if DRAFT_ONLY else end))
    process = None
    selector = selectors.DefaultSelector()
    identity = None
    captured = bytearray()
    stderr_prefix = bytearray()
    stderr_observed = 0
    total = sent = 0
    eof = set()
    failure = None
    group_empty = None
    completed = False
    try:
        # Keep the client in the admitted outer watchdog group. Only its service
        # runs separately; no Windows interop or subject is placed in that unit.
        if budget(end, cancelled) < runtime_ms / 1000 + 8.0:
            fail('Verifier preparation used its required lifetime reserve')
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=client_environment)
        for stream, event in ((process.stdin, selectors.EVENT_WRITE),
                              (process.stdout, selectors.EVENT_READ),
                              (process.stderr, selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event)
        for _ in range(1200):
            if time.monotonic() >= end - 0.25:
                failure = failure or 'Deadline'
                break
            if cancelled():
                failure = failure or 'Cancelled'
            if failure and process.stdin in [key.fileobj for key in selector.get_map().values()]:
                selector.unregister(process.stdin)
                process.stdin.close()
            for key, _event in selector.select(min(0.025, max(0, end - 0.25 - time.monotonic()))):
                stream = key.fileobj
                if stream is process.stdin:
                    try:
                        sent += os.write(stream.fileno(), payload[sent:sent + 8192])
                    except (BrokenPipeError, BlockingIOError):
                        failure = failure or 'InputHandoff'
                    if sent == len(payload) or failure:
                        selector.unregister(stream)
                        stream.close()
                else:
                    try:
                        chunk = os.read(stream.fileno(), min(8192, output_limit - total + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        eof.add('stdout' if stream is process.stdout else 'stderr')
                        selector.unregister(stream)
                    else:
                        total += len(chunk)
                        if stream is process.stderr:
                            stderr_observed += len(chunk)
                            stderr_prefix.extend(chunk[:max(0, 16384 - len(stderr_prefix))])
                        if total > output_limit:
                            failure = failure or 'OutputLimit'
                            for output in (process.stdout, process.stderr):
                                if output in [item.fileobj for item in selector.get_map().values()]:
                                    selector.unregister(output)
                                output.close()
                            break
                        if stream is process.stdout:
                            captured.extend(chunk)
            if identity is None and identity_path.exists():
                identity = decode(read(identity_path, end, lambda: False, 4096), canonical=True)
                keys(identity, ('pid', 'startTicks', 'cgroup', 'unit', 'observedMonotonicNs'))
                integer(identity['pid'], 1)
                integer(identity['startTicks'], 1)
                integer(identity['observedMonotonicNs'], 1, int(end * 1_000_000_000))
            if identity is not None and process.poll() is not None:
                group_empty = compiler_verifier_group_empty(identity, unit)
                if group_empty and (eof == {'stdout', 'stderr'} or failure):
                    completed = True
                    break
            if process.poll() is not None and eof == {'stdout', 'stderr'} and identity is None:
                failure = failure or 'IdentityUnavailable'
                break
            # A writable input can make select return immediately; count all
            # polls and keep the same absolute deadline instead of resetting it.
        if not completed or sent != len(payload) or process.returncode != 0:
            failure = failure or 'IncompleteVerifier'
    except BaseException as error:
        failure = failure or type(error).__name__
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=max(0.001, end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    failure = failure or 'ClientReapTimeout'
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        if time.monotonic() >= end:
            failure = failure or 'Deadline'
        # Keep startup evidence private in the existing receipt, without another
        # read, output allowance, or attempt. EOF alone does not imply completeness.
        write_new(directory / 'result.json', compact({
            'schema': result_schema, 'call': number, 'unit': unit,
            'clientExit': None if process is None else process.returncode,
            'stdoutEof': 'stdout' in eof, 'stderrEof': 'stderr' in eof,
            'stderrBytesObserved': stderr_observed, 'stderrBytesRetained': len(stderr_prefix),
            'stderrPrefixBase64': base64.b64encode(stderr_prefix).decode('ascii'),
            'stderrComplete': 'stderr' in eof and stderr_observed == len(stderr_prefix),
            'groupEmpty': group_empty, 'completed': completed, 'failure': failure,
            'elapsedMilliseconds': int((time.monotonic() - began) * 1000)}), deadline=(None if DRAFT_ONLY else end))
    budget(end, cancelled)
    if failure is not None:
        fail('Verifier failed; no subsequent helper or caller continuation')
    _COMPILER_VERIFIER_FAILED = False
    return bytes(captured)


def verify_public_review(pin, expected, deadline, cancelled):
    keys(pin, ('commentId', 'pullRequest', 'userId', 'userLogin', 'createdAt', 'updatedAt',
               'bodyBytes', 'bodySha256', 'apiBytes', 'apiSha256', 'publicUrl'))
    for key in ('commentId', 'pullRequest', 'userId'):
        integer(pin[key], 1)
    for key in ('bodySha256', 'apiSha256'):
        digest(pin[key])
    url = 'https://github.com/' + FORK + '/pull/' + str(pin['pullRequest']) + '#issuecomment-' + str(pin['commentId'])
    if pin['publicUrl'] != url or len(expected) != pin['bodyBytes'] or sha(expected) != pin['bodySha256']:
        fail('Public review body identity changed')
    raw = public_read([GITHUB_CLI_PATH, 'api', '--hostname', 'github.com', '--method', 'GET',
                       '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28',
                       'repos/' + FORK + '/issues/comments/' + str(pin['commentId'])], deadline, cancelled)
    if len(raw) != pin['apiBytes'] or sha(raw) != pin['apiSha256']:
        fail('Public review representation changed')
    value = decode(raw)
    if (value.get('id') != pin['commentId'] or value.get('html_url') != url or
            value.get('issue_url') != 'https://api.github.com/repos/' + FORK + '/issues/' + str(pin['pullRequest']) or
            value.get('user', {}).get('id') != pin['userId'] or value.get('user', {}).get('login') != pin['userLogin'] or
            value.get('created_at') != pin['createdAt'] or value.get('updated_at') != pin['updatedAt'] or
            type(value.get('body')) is not str or value['body'].encode('utf-8') != expected):
        fail('Public independent-review provenance changed')


def verify_revision(value, deadline, cancelled):
    keys(value, ('commit', 'tree'))
    for v in value.values():
        string(v, '[0-9a-f]{40}')
    if git(['rev-parse', '--verify', value['commit'] + '^{tree}'], deadline, cancelled) != (value['tree'] + '\n').encode():
        fail('Immutable source tree mismatch')


def verify_blob(owner, path, pin, deadline, cancelled):
    keys(pin, ('gitBlob', 'bytes', 'sha256'))
    string(pin['gitBlob'], '[0-9a-f]{40}')
    relative(path)
    entry = git(['ls-tree', owner['commit'], '--', path], deadline, cancelled)
    suffix = (' blob ' + pin['gitBlob'] + '\t' + path + '\n').encode()
    if entry not in (b'100644' + suffix, b'100755' + suffix):
        fail('Git path is missing, linked or unbound')
    data = git(['cat-file', 'blob', pin['gitBlob']], deadline, cancelled)
    if len(data) != pin['bytes'] or sha(data) != digest(pin['sha256']):
        fail('Git blob bytes changed')
    return data


def assert_target_current(envelope, deadline, cancelled):
    value = decode(public_read([GITHUB_CLI_PATH, 'api', '--hostname', 'github.com', '--method', 'GET',
                                'repos/' + FORK + '/git/ref/heads/main-v2'], deadline, cancelled))
    if (value.get('ref') != 'refs/heads/main-v2' or value.get('object', {}).get('type') != 'commit' or
            value.get('object', {}).get('sha') != envelope['target']['commit']):
        fail('Accepted target changed; refresh review without retry')


def resolve(value, substitutions):
    if type(value) is not str:
        fail('Nontext recipe entry')
    for key, text in substitutions.items():
        value = value.replace('${' + key + '}', text)
    if '${' in value or any(x in value for x in ('\0', '\r', '\n')):
        fail('Unknown substitution or native argument control character')
    return value


def verify_guard(value):
    keys(value, GUARD_FIELDS)
    string(value['actionNumber'], '(?!0000)[0-9]{4}')
    for key in GUARD_FIELDS:
        if key.endswith('Sha256'):
            digest(value[key])
    windows_path(value['artifactAcceptancePath'])
    string(value['expectedAssemblyFullName'], '[ -~]{1,512}')
    if value['sourceSha256'] != GUARD_SOURCE:
        fail('Guard source projection changed')


def provenance_descriptor(value, expected_path=None, maximum=CALLER_PROVENANCE_LIMIT, minimum=1):
    keys(value, ('path', 'bytes', 'sha256'))
    path = string(value['path'], '/[ -~]{1,4095}')
    if ('\\' in path or '//' in path or
            any(part in ('', '.', '..') for part in path[1:].split('/')) or
            (expected_path is not None and path != str(expected_path))):
        fail('Original provenance path changed or is not literal')
    integer(value['bytes'], minimum, maximum)
    digest(value['sha256'])
    return Path(path)


def original_reviewer(value):
    return string(value, '[A-Za-z0-9_./-]{1,160}')


def original_review_metadata(value):
    original_reviewer(value['reviewer'])
    timestamp = string(value['reviewedUtc'],
        r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|\+00:00)')
    datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))


def original_record(value, fixed, metadata=('reviewer', 'reviewedUtc')):
    keys(value, (*fixed, *metadata))
    # Exact JSON values distinguish booleans from integers without rewriting bytes.
    for name, expected in fixed.items():
        if compact(value[name]) != compact(expected):
            fail('Original accepted record join changed')
    original_review_metadata(value)


def load_caller_provenance(envelope, evidence, evidence_raw, deadline, cancelled):
    caller = evidence['callerAuthorization']
    keys(caller, CALLER_AUTHORIZATION_FIELDS)
    if (caller['schema'] != 'final-publish-caller-authorization-v1' or
            caller['accepted'] is not True or
            caller['scope'] != 'one-final-publish-use-of-original-accepted-guard' or
            caller['callerPolicy'] != 'fixed-final-only-callers-no-generic-helper-use' or
            caller['noExecutionGrant'] is not True):
        fail('Prospective caller authorization is absent or out of scope')
    for name in CALLER_AUTHORIZATION_JOINS:
        if compact(caller[name]) != compact(envelope[name]):
            fail('Prospective caller authorization names different inputs')
    verify_guard(caller['acceptedGuard'])
    origin = caller['originalGuardEvidence']
    keys(origin, CALLER_PROVENANCE_ROLES)
    for name in CALLER_PROVENANCE_ROLES:
        expected = ORIGINAL_BINDING if name == 'binding' else ORIGINAL_BINDING_REVIEW if name == 'bindingReview' else None
        provenance_descriptor(origin[name], expected)

    # K was read once by the bounded role loader. Seven original files follow.
    # The original reader and L are never imported, interpreted or executed here.
    continuity = [(EVIDENCE / 'callerAuthorization.json', envelope['callerAuthorization'],
                   evidence_raw['callerAuthorization'])]
    seen = {str(continuity[0][0])}

    def take(pin, expected_path=None, canonical=False, raw_only=False):
        path = provenance_descriptor(pin, expected_path)
        if len(continuity) >= 8 or str(path) in seen:
            fail('Duplicate or expanded caller provenance read set')
        seen.add(str(path))
        pair = {name: pin[name] for name in ('bytes', 'sha256')}
        raw = bound(pair, path, deadline, cancelled, CALLER_PROVENANCE_LIMIT)
        continuity.append((path, pair, raw))
        return raw if raw_only else decode(raw, canonical=canonical)

    binding = take(origin['binding'], ORIGINAL_BINDING, canonical=True)
    review = take(origin['bindingReview'], ORIGINAL_BINDING_REVIEW)
    # Accepted L semantics and reviewer independence are checked by K's reviewer
    # and the independently reviewed final literal launcher. Pin their raw bytes.
    take(origin['readerLauncher'], raw_only=True)
    take(origin['readerLauncherAcceptance'], raw_only=True)
    keys(binding, ('schema', 'scope', 'actionNumber', 'files', 'readerSources', 'recipe',
                   'completionAcceptance', 'artifactAcceptance', 'expectedAssemblyFullName',
                   'acceptedLoaderSourceSha256', 'artifactAcceptanceWindowsPath'))
    if (binding['schema'] != 'final-guard-history-binding-v2' or
            binding['scope'] != 'one-original-final-guard-preparation'):
        fail('Original B scope changed')
    number = string(binding['actionNumber'], '0055')
    local = str(HISTORY / number)
    projected = str(PROJECTION / 'actions' / number)
    native = WINDOWS + '\\actions\\' + number
    paths = {
        'wslStarted': local + '/started.json', 'wslResult': local + '/result.json',
        'windowsInput': local + '/windows-input.json', 'windowsStarted': projected + '/started.json',
        'invocation': projected + '/invocation.json', 'compiler': projected + '/compiler.json',
        'ready': projected + '/clock-ready.json', 'reply': projected + '/clock-remaining.json',
        'windowsResult': projected + '/windows-result.json', 'guardBuild': projected + '/guard-build.json',
        'authority': projected + '/authority.json', 'stdout': projected + '/stdout.bin',
        'stderr': projected + '/stderr.bin',
        'source': projected + '/final-guard/source/WindowsValidationJob.cs',
        'controller': projected + '/final-guard/controller/Invoke-WindowsFinalGuardPrepare.ps1',
        'preflight': projected + '/final-guard/controller/WindowsFinalGuardPreflight.body.txt',
        'dll': projected + '/final-guard/WindowsFinalPublishGuard.dll',
    }
    keys(binding['files'], paths)
    for role, path in paths.items():
        # These are descriptors, not extra reads of the historical file set.
        provenance_descriptor(binding['files'][role], path, 8388608, 0)
    readers = {'linuxHistoryReader': ORIGINAL_READER_REPOSITORY / 'tools/validation/run_managed.py',
               'windowsHistoryReader': ORIGINAL_READER_REPOSITORY / 'tools/validation/run_windows.py'}
    keys(binding['readerSources'], readers)
    for role, path in readers.items():
        provenance_descriptor(binding['readerSources'][role], path, 8388608, 0)
    provenance_descriptor(binding['recipe'], ORIGINAL_GUARD_EVIDENCE / 'guard-recipe.json', 8388608, 0)
    original_record(review, {
        'schema': 'final-guard-history-binding-review-v1', 'disposition': 'accepted',
        'scope': 'original-completion-and-managed-artifact-history-consumption',
        'binding': origin['binding'], 'readerSources': binding['readerSources'],
        'originalEvidenceUnchanged': True, 'independentCompletionAndArtifactReview': True,
        'noExecutionGrant': True}, ('author', 'reviewer', 'reviewedUtc'))
    original_reviewer(review['author'])
    if review['author'] == review['reviewer']:
        fail('Original B author cannot independently review B')
    completion = take(binding['completionAcceptance'], ORIGINAL_GUARD_EVIDENCE / 'original-completion-acceptance.json')
    artifact = take(binding['artifactAcceptance'], ORIGINAL_GUARD_EVIDENCE / 'managed-artifact-acceptance.json')
    artifact_bytes = continuity[-1][2]
    authority = take(binding['files']['authority'], projected + '/authority.json', canonical=True)
    if len(continuity) != 8:
        fail('Incomplete fixed caller provenance read set')
    keys(authority, ORIGINAL_GUARD_AUTHORITY_FIELDS)
    if authority['schema'] != 'final-guard-external-authority-v2':
        fail('Original preparation authority schema changed')
    keys(authority['components'], ORIGINAL_GUARD_COMPONENTS)
    if compact(authority['protocol']) != compact(ORIGINAL_SUCCESSOR_PROTOCOL):
        fail('Original successor protocol source changed')
    for role, source in ORIGINAL_SUCCESSOR_VALIDATORS.items():
        expected = {'commit': authority['protocol']['commit'],
                    'tree': authority['protocol']['tree'], **source}
        if compact(authority['components'][role]) != compact(expected):
            fail('Original successor reader or shared-module source changed')
    for role, expected in ORIGINAL_HISTORY_JOINS.items():
        if compact(authority[role]) != compact(expected):
            fail('Original M53, D54, fixture or successor limits changed')
        if role != 'limits':
            provenance_descriptor(authority[role], expected['path'])
    # These are E55 metadata joins, not additional original evidence reads.
    # K's independent review must bind L's actual module/disposition/fixture use.
    loader = authority['components']['finalPublishController']
    keys(loader, ('bytes', 'commit', 'gitBlob', 'repositoryPath', 'sha256', 'tree'))
    if (loader['repositoryPath'] != 'tools/validation/Invoke-WindowsFinalPublish.ps1' or
            loader['bytes'] != 16443 or loader['sha256'] != ORIGINAL_LOADER_SOURCE or
            binding['acceptedLoaderSourceSha256'] != loader['sha256']):
        fail('Original disabled-loader provenance changed')
    for role in ('linuxHistoryReader', 'windowsHistoryReader'):
        original = authority['components'][role]
        expected = {'path': str(readers[role]), 'bytes': original['bytes'], 'sha256': original['sha256']}
        if compact(binding['readerSources'][role]) != compact(expected):
            fail('Original reader source descriptors changed')
    original_record(completion, {
        'schema': 'final-guard-original-completion-acceptance-v1', 'disposition': 'accepted',
        'scope': 'one-original-compiler-controller-wsl-completion', 'actionNumber': number,
        'files': binding['files'], 'source': authority['source'], 'protocol': authority['protocol'],
        'originalProxyExitCode': 0, 'originalWindowsControllerExitCode': 0,
        'normalCompletion': True, 'quiescent': True, 'compilerTerminationRequested': False,
        'safetyStop': False, 'originalFlagsRemainFalse': True})
    files = binding['files']
    guard = {
        'actionNumber': number, 'sourceSha256': files['source']['sha256'],
        'dllSha256': files['dll']['sha256'], 'guardBuildSha256': files['guardBuild']['sha256'],
        'preparationWindowsResultSha256': files['windowsResult']['sha256'],
        'preparationWslResultSha256': files['wslResult']['sha256'],
        'preparationReservationSha256': files['wslStarted']['sha256'],
        'invocationSha256': files['invocation']['sha256'], 'compilerReceiptSha256': files['compiler']['sha256'],
        'artifactAcceptancePath': binding['artifactAcceptanceWindowsPath'],
        'artifactAcceptanceSha256': binding['artifactAcceptance']['sha256'],
        'expectedAssemblyFullName': binding['expectedAssemblyFullName'],
        'acceptedLoaderSourceSha256': binding['acceptedLoaderSourceSha256'],
    }
    verify_guard(guard)
    if (guard['artifactAcceptancePath'] != native + '\\final-guard\\artifact-acceptance.json' or
            compact(guard) != compact(envelope['acceptedGuard']) or
            compact(guard) != compact(caller['acceptedGuard'])):
        fail('Original thirteen-field guard projection changed')
    original_record(artifact, {
        'schema': 'final-guard-managed-artifact-acceptance-v1', 'disposition': 'accepted',
        'scope': 'exact-managed-final-guard-source-pe-il-and-final-loader-binding',
        'acceptedFinalGuard': {name: guard[name] for name in GUARD_FIELDS
                               if name not in ('artifactAcceptancePath', 'artifactAcceptanceSha256')},
        'artifact': files['dll'], 'completionAcceptance': binding['completionAcceptance'],
        'managedPeAndIlReviewed': True, 'sourceAndCompilerBindingReviewed': True,
        'noLoadOrSelfTestPerformed': True})
    if review['author'] in (completion['reviewer'], artifact['reviewer']):
        fail('Original B author cannot supply original independent acceptance')
    budget(deadline, cancelled)
    return {'files': tuple(continuity), 'continuityChecked': False,
            'artifactAcceptanceBytes': artifact_bytes,
            'successorHistory': {role: authority[role] for role in ORIGINAL_HISTORY_JOINS}}


def refresh_caller_provenance(admission, deadline, cancelled):
    provenance = admission['callerProvenance']
    if provenance['continuityChecked'] or len(provenance['files']) != 8:
        fail('Caller provenance continuity cannot be retried or expanded')
    # Latch before reading. An interrupted pass cannot be retried for more reads.
    provenance['continuityChecked'] = True
    for path, pin, original in provenance['files']:
        raw = bound(pin, path, deadline, cancelled, CALLER_PROVENANCE_LIMIT)
        if raw != original:
            fail('Original caller provenance changed before reservation')
    budget(deadline, cancelled)


def validate_graph(graph, recipe):
    keys(graph, ('schema', 'source', 'sourceRoot', 'packageRoot', 'protectedInputs',
                 'generatedResponses', 'preexistingResponses', 'generatedPaths',
                 'effectiveProperties', 'sourceInventory', 'absentInputs', 'toolResponseContract', 'toolResponses'))
    if graph['schema'] != 'final-publish-exact-graph-v2' or graph['source'] != PRODUCT:
        fail('Final graph source changed')
    root = windows_path(graph['sourceRoot'])
    if not ntpath.normcase(ntpath.normpath(root)).startswith(ntpath.normcase(WINDOWS + '\\sources\\')):
        fail('Source checkout is outside the dedicated source root')
    if graph['packageRoot'] != WINDOWS + '\\packages':
        fail('Package root changed')
    expected = {'Configuration': 'Release', 'RuntimeIdentifier': 'win-x64',
                'SelfContained': 'true', 'PublishAot': 'true', 'RuntimeFrameworkVersion': '10.0.12',
                'TreatWarningsAsErrors': 'true', 'IlcTreatWarningsAsErrors': 'true',
                'TrimmerSingleWarn': 'false', 'NativeDebugSymbols': 'true',
                'UseSharedCompilation': 'false', 'IlcUseEnvironmentalTools': 'true',
                'CppLinker': recipe['selectedToolPins']['link.exe']['path']}
    if graph['effectiveProperties'] != expected:
        fail('Effective build/symbol/warning policy differs from fixed recipe')
    values = graph['protectedInputs']
    if type(values) is not list or not 1 <= len(values) <= 20000:
        fail('Incomplete protected input map')
    seen = set()
    allowed_roots = (graph['sourceRoot'], graph['packageRoot'], 'C:\\Program Files\\dotnet',
                     'C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\VC\\Tools\\MSVC\\14.51.36231',
                     'C:\\Program Files (x86)\\Windows Kits\\10')
    allowed_system_tools = ('C:\\Windows\\System32\\cmd.exe',
                            'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                            'C:\\Windows\\System32\\chcp.com')
    for item in values:
        keys(item, ('path', 'bytes', 'sha256', 'role'))
        path = windows_path(item['path'])
        normalized = ntpath.normcase(ntpath.normpath(path))
        if not (any(normalized.startswith(ntpath.normcase(ntpath.normpath(root)) + '\\') for root in allowed_roots) or
                any(same_path(path, tool) for tool in allowed_system_tools)):
            fail('Protected input is outside the exact public source/package/tool roots')
        if normalized in seen:
            fail('Duplicate protected path')
        seen.add(normalized)
        integer(item['bytes'], 0, 536870912)
        digest(item['sha256'])
        if item['role'] not in ('source', 'lock', 'restore', 'sdk', 'task', 'package', 'native-tool', 'native-library'):
            fail('Unknown input role')
    for pin in recipe['selectedToolPins'].values():
        matches = [x for x in values if same_path(x['path'], pin['path'])]
        if len(matches) != 1 or matches[0]['bytes'] != pin['bytes'] or matches[0]['sha256'] != pin['sha256']:
            fail('Nominated native tool pin missing or changed')
    for executable in (recipe['invocation']['executable'], allowed_system_tools[1]):
        if len([x for x in values if same_path(x['path'], executable)]) != 1:
            fail('Original dotnet or PowerShell executable is not pinned')
    if type(graph['sourceInventory']) is not list or len(graph['sourceInventory']) != FINAL_SOURCE_FILES:
        fail('Missing exact immutable source inventory')
    for item in graph['sourceInventory']:
        keys(item, ('repositoryPath', 'gitBlob', 'bytes', 'sha256'))
        relative(item['repositoryPath'])
        string(item['gitBlob'], '[0-9a-f]{40}')
        digest(item['sha256'])
        integer(item['bytes'], 0, 8388608)
        actual_path = graph['sourceRoot'] + '\\' + item['repositoryPath'].replace('/', '\\')
        if not any(same_path(x['path'], actual_path) and x['sha256'] == item['sha256'] and
                   x['bytes'] == item['bytes'] for x in values):
            fail('Immutable product source is absent from protected inputs')
    if type(graph['absentInputs']) is not list or len(graph['absentInputs']) > 512:
        fail('Invalid exact absent-input map')
    for path in graph['absentInputs']:
        windows_path(path)
    if len(set(graph['absentInputs'])) != len(graph['absentInputs']):
        fail('Duplicate absent input')
    if type(graph['generatedPaths']) is not list or not 1 <= len(graph['generatedPaths']) <= 10000:
        fail('Missing finite generated output map')
    for path in graph['generatedPaths']:
        rendered = windows_path(resolve(path, {'ACTION_ROOT': WINDOWS + '\\actions\\9999',
                                              'SOURCE_ROOT': root, 'PACKAGE_ROOT': graph['packageRoot']}))
        normalized = ntpath.normcase(ntpath.normpath(rendered))
        if not any(normalized.startswith(ntpath.normcase(ntpath.normpath(parent)) + '\\')
                   for parent in (root, WINDOWS + '\\actions\\9999')):
            fail('Generated file is outside the dedicated final source/action roots')
    if len(set(graph['generatedPaths'])) != len(graph['generatedPaths']):
        fail('Duplicate generated output path')
    if graph['preexistingResponses'] != []:
        # The selected fixed publish has no caller-provided response files.
        # A future exact recipe needing one requires a source amendment, not a wildcard.
        fail('Preexisting response files are outside this recipe')
    responses = graph['generatedResponses']
    if type(responses) is not list or not 2 <= len(responses) <= 32:
        fail('Incomplete generated response map')
    identities = set()
    for item in responses:
        keys(item, ('id', 'pathTemplate', 'producer', 'consumer', 'lines', 'substitutions',
                    'encoding', 'newline', 'writeCount', 'consumeCount', 'retainedAfterConsume'))
        string(item['id'], '[a-z][a-z0-9-]{0,63}')
        if item['id'] in identities:
            fail('Duplicate response identity')
        identities.add(item['id'])
        if item['encoding'] not in ('utf-8', 'utf-8-bom') or item['newline'] != 'CRLF':
            fail('Unknown response serialization')
        if item['writeCount'] != 1 or item['consumeCount'] != 1 or item['retainedAfterConsume'] is not True:
            fail('Unobservable, rewritten or deleted response input')
        if item['pathTemplate'] not in graph['generatedPaths']:
            fail('Response path is not in the finite generated map')
        keys(item['producer'], ('path', 'sha256', 'target', 'writer', 'taskPath', 'taskSha256'))
        producer = item['producer']
        for pathkey, hashkey in (('path', 'sha256'), ('taskPath', 'taskSha256')):
            windows_path(producer[pathkey]); digest(producer[hashkey])
            if not any(same_path(x['path'], producer[pathkey]) and x['sha256'] == producer[hashkey] for x in values):
                fail('Response producer or task is not a protected input')
        if producer['writer'] != 'WriteLinesToFile':
            # Retained Csc and Exec inputs use the separate source-bound adapter.
            fail('Unreviewed response writer')
        string(producer['target'], '[A-Za-z_][A-Za-z0-9_]{0,127}')
        keys(item['consumer'], ('path', 'sha256', 'target', 'argumentTemplate', 'environment'))
        consumer = item['consumer']
        windows_path(consumer['path']); digest(consumer['sha256'])
        if not any(same_path(x['path'], consumer['path']) and x['sha256'] == consumer['sha256'] for x in values):
            fail('Response consumer is not a protected input')
        if consumer['argumentTemplate'] != '@"' + item['pathTemplate'] + '"':
            fail('Consumer does not reference the single exact response path')
        if type(consumer['environment']) is not dict or any(k.upper() in
                ('_MSPDBSRV_ENDPOINT_', '_MSPDBSRV_', 'LINK', '_LINK_', 'CL', '_CL_') for k in consumer['environment']):
            fail('Consumer mutates native endpoint or compiler overrides')
        if type(item['substitutions']) is not dict or len(item['substitutions']) > 128:
            fail('Unbounded response substitutions')
        for key, path in item['substitutions'].items():
            string(key, 'GENERATED_[A-Z0-9_]{1,64}')
            if path not in graph['generatedPaths']:
                fail('Generated substitution has no exact path')
        if type(item['lines']) is not list or not 1 <= len(item['lines']) <= 10000:
            fail('Missing exact ordered response template')
        slots = {'ACTION_ROOT': WINDOWS + '\\actions\\9999', 'SOURCE_ROOT': root,
                 'PACKAGE_ROOT': graph['packageRoot']}
        slots.update({k: resolve(v, slots) for k, v in item['substitutions'].items()})
        for line in item['lines']:
            rendered = resolve(line, slots)
            if not rendered or '@' in rendered or '*' in rendered or '?' in rendered:
                fail('Nested or wildcard response argument')
    if not {'ilc', 'link'}.issubset(identities):
        fail('Missing ILC or linker producer')
    ilc = next(x for x in responses if x['id'] == 'ilc')
    link = next(x for x in responses if x['id'] == 'link')
    target_hashes = ('9e0e1efb41bd7a848b633212d9c56f06cc97785dae0daae5b7bcab62b03849f2',
                     '22516102af0e4bdafa004795d3bbc30d617efe5bb7b809005d1ea3a00c436f6d')
    if (ilc['producer']['target'] != 'WriteIlcRspFileForCompilation' or ilc['consumer']['target'] != 'IlcCompile' or
            link['producer']['target'] != 'LinkNative' or link['consumer']['target'] != 'LinkNative' or
            any(x['producer']['sha256'] not in target_hashes for x in (ilc, link)) or
            link['consumer']['sha256'] != recipe['selectedToolPins']['link.exe']['sha256'] or
            '/DEBUG' not in link['lines'] or '/INCREMENTAL:NO' not in link['lines'] or
            '-g' not in ilc['lines'] or '--warnaserror' not in ilc['lines'] or '--singlewarn' in ilc['lines']):
        fail('Public .NET 10.0.12 producer/consumer/symbol contract changed')
    validate_tool_contract(graph, recipe)


# The following closed adapter covers only the reviewed Csc and Windows Exec
# producers. Its actual graph values are supplied only by external admission.
TOOL_SOURCES = {
    'msbuild': 'b44cdcec4c79c50c67560876707d57d4f635fa3b',
    'roslyn': 'f7797ed513e3035983346552ac2d9ca2281bc2ec',
    'sdk': '32593ca81f8aae7b0d41c1a7198529c3365106b8',
    'runtime': '4271d88e0aebf3d04f188f1334c2220d80555ef6',
}
TOOL_HOST_ROLES = ('sdkHost', 'sdkForwarder', 'msbuild', 'corelib', 'taskHost',
                   'logger', 'utilities', 'cscTask', 'execTask')
TEMP_DIRECTORY = r'MSBuildTemp[a-z0-5]{8}\.[a-z0-5]{3}'
TARGET_START = re.compile(
    r'^Target "([^"]+): \(TargetId:([1-9][0-9]*)\)" '
    r'(?:in file "([^"]+)" from project|in project) "([^"]+)" '
    r'\((?:entry point|target "[^"]+" depends on it)\):$')
TARGET_END = re.compile(
    r'^Done building target "([^"]+)" in project "([^"]+)"\.: \(TargetId:([1-9][0-9]*)\)$')
TASK_START = re.compile(r'^Task "([^"]+)" \(TaskId:([1-9][0-9]*)\)$')
TASK_END = re.compile(r'^Done executing task "([^"]+)"\. \(TaskId:([1-9][0-9]*)\)$')
TASK_MESSAGE = re.compile(r'^  (.*) \(TaskId:([1-9][0-9]*)\)$')
PRESERVATION = re.compile(r"^Preserving temporary file '([^']+)'$")


def tool_text(value, slots):
    value = resolve(value, slots)
    if (not value or len(value) > 1048576 or
            any(ord(c) < 32 or ord(c) == 127 for c in value)):
        fail('Unbounded or control-bearing tool text')
    value.encode('utf-8')  # Reject invalid Unicode rather than replacement.
    return value


def csc_tokens(text):
    """Pinned Roslyn splitter rules, restricted to single-line valid input.

    Preserve quotes/slashes, except the source's single enclosing quote pair.
    Hash comments, illegal characters, and unbalanced quoting are inadmissible.
    This function is not a shell parser.
    """
    result, i = [], 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i == len(text):
            break
        if text[i] == '#':
            fail('Response hash comment is outside the exact command contract')
        quotes, token = 0, []
        while i < len(text) and (not text[i].isspace() or quotes % 2):
            c = text[i]
            if c == '\\':
                start = i
                while i < len(text) and text[i] == '\\':
                    token.append(text[i]); i += 1
                if i < len(text) and text[i] == '"':
                    if (i - start) % 2 == 0:
                        quotes += 1
                    token.append('"'); i += 1
            elif c == '"':
                token.append(c); quotes += 1; i += 1
            else:
                if ord(c) < 32 or c == '|':
                    fail('Illegal response character')
                token.append(c); i += 1
        if quotes % 2:
            fail('Unbalanced response quoting')
        value = ''.join(token)
        if quotes == 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if value:
            if value.startswith('@'):
                fail('Nested Csc response token')
            result.append(value)
    return result


def tool_pin(pin, graph):
    keys(pin, ('path', 'sha256'))
    windows_path(pin['path']); digest(pin['sha256'])
    if len([x for x in graph['protectedInputs'] if
            x['path'] == pin['path'] and x['sha256'] == pin['sha256']]) != 1:
        fail('Tool source/runtime/task/consumer pin is not protected')


def tool_environment(graph, plan, recipe, slots):
    environment = {k: resolve(v, slots) for k, v in
                   recipe['invocation']['replacementEnvironmentTemplate'].items()}
    for stage, changes in enumerate((graph['toolResponseContract']['sdkEnvironmentOverrides'],
                                    plan['taskEnvironmentOverrides'])):
        if type(changes) is not list or len(changes) > 128:
            fail('Unbounded ordered environment overrides')
        seen = set()
        for item in changes:
            keys(item, ('name', 'value'))
            name = string(item['name'], '[A-Za-z_][A-Za-z0-9_()]{0,127}')
            if name.upper() in seen and not (stage == 1 and plan['kind'] == 'Csc' and name == 'DOTNET_ROOT'):
                fail('Duplicate descendant override outside the Csc clear/set pair')
            if name.upper() in (
                    '_MSPDBSRV_ENDPOINT_', '_MSPDBSRV_', 'LINK', '_LINK_', 'CL', '_CL_',
                    'TEMP', 'TMP', 'MSBUILDPRESERVETOOLTEMPFILES'):
                fail('Duplicate or forbidden descendant override')
            seen.add(name.upper())
            value = resolve(item['value'], slots)
            # Windows environment names compare ordinal-ignore-case.
            old = [k for k in environment if k.upper() == name.upper()]
            for k in old:
                del environment[k]
            environment[name] = value
        if stage == 1 and plan['kind'] == 'Csc':
            root_changes = [x for x in changes if x['name'].upper() == 'DOTNET_ROOT']
            expected_root = ntpath.dirname(graph['toolResponseContract']['hostBindings']['sdkHost']['path'])
            if root_changes != [{'name': 'DOTNET_ROOT', 'value': ''},
                                {'name': 'DOTNET_ROOT', 'value': expected_root}]:
                fail('Csc DOTNET_ROOT clear/set branch is not source-bound')
    declared = plan['childEnvironmentTemplate']
    if type(declared) is not dict or not 35 <= len(declared) <= 256:
        fail('Missing complete task child environment')
    if environment != {k: resolve(v, slots) for k, v in declared.items()}:
        fail('Task child environment does not follow admitted overrides')
    if len({k.upper() for k in environment}) != len(environment):
        fail('Case-alias child environment')
    for key, value in environment.items():
        string(key, '[A-Za-z_][A-Za-z0-9_()]{0,127}')
        if len(value) > 32767:
            fail('Unbounded child environment value')
    return environment


def tool_environment_hash(environment):
    return sha(('\0'.join(k + '=' + environment[k] for k in sorted(environment, key=str.upper))
                + '\0\0').encode('utf-16le'))


def render_tool_plan(graph, plan, recipe, slots):
    environment = tool_environment(graph, plan, recipe, slots)
    working = windows_path(resolve(plan['workingDirectoryTemplate'], slots))
    if working != ntpath.dirname(plan['projectPath']):
        fail('Task working directory differs from its source-bound project')
    if plan['kind'] == 'Csc':
        direct_text = tool_text(plan['directCommandTextTemplate'], slots)
        response_text = tool_text(plan['responseCommandTextTemplate'], slots)
        direct_tokens = csc_tokens(direct_text)
        tokens = csc_tokens(response_text)
        if direct_tokens.count('/noconfig') != 1:
            fail('Csc no-config command not established')
        expected_direct = '/noconfig' if plan['executionMode']['appHost'] else (
            'exec "' + plan['consumer']['path'] + '" /noconfig')
        if direct_text != expected_direct:
            fail('Csc direct command differs from the selected host/consumer')
        output = windows_path(resolve(plan['outputPathTemplate'], slots))
        outputs = [t[5:] for t in tokens if t.lower().startswith('/out:')]
        if len(outputs) != 1:
            fail('Csc output identity missing or duplicated')
        rendered_output = outputs[0]
        if rendered_output.startswith('"') and rendered_output.endswith('"'):
            rendered_output = rendered_output[1:-1]
        if not same_path(ntpath.join(working, rendered_output), output):
            fail('Csc response output differs from the planned artifact')
        command = plan['tool']['path'] + ' ' + direct_text + ' ' + response_text
        data = b'\xef\xbb\xbf' + response_text.encode('utf-8')
    else:
        command = tool_text(plan['commandTextTemplate'], slots)
        match = re.fullmatch(r'"([^"]+)" @"([^"]+)"', command)
        if not match or any(c in command for c in '%!^&|<>'):
            fail('Exec command is outside the two reviewed native invocations')
        consumer = match[1]
        # IlcCompile spells the native tool as ilc without .exe.
        if not ntpath.splitext(consumer)[1]:
            consumer += '.exe'
        response = next(x for x in graph['generatedResponses'] if x['id'] == plan['responseId'])
        if (not same_path(consumer, plan['consumer']['path']) or
                not same_path(ntpath.join(working, match[2]), resolve(response['pathTemplate'], slots))):
            fail('Exec command consumer/response path does not join its static response')
        encoding = plan['batchEncoding']
        lines = ['setlocal', 'set errorlevel=dummy', 'set errorlevel=']
        if 'mode' in encoding:
            if encoding != {'mode': 'ascii-default-detect', 'useUtf8Encoding': 'Detect',
                            'codePageTool': None} or not (command + working).isascii():
                fail('Exec ASCII/default-Detect input or encoding branch differs')
            codec = 'ascii'
        else:
            oem = encoding['oemCodePage']
            codec = 'utf-8' if oem == 65001 else 'cp' + str(oem)
            try:
                (command + working).encode(codec, errors='strict')
                representable = True
            except UnicodeEncodeError:
                representable = False
            specification = encoding['useUtf8Encoding'].upper()
            selected = 65001 if specification in ('ALWAYS', 'TRUE') or (
                specification in ('', 'DETECT') and not representable) else oem
            if encoding['codePage'] != selected:
                fail('Exec encoding selection differs from the pinned source')
            if selected != oem:
                lines.append('%SystemRoot%\\System32\\chcp.com ' + str(selected) + '>nul')
            codec = 'utf-8' if selected == 65001 else 'cp' + str(selected)
        lines.extend((command, 'exit %errorlevel%'))
        text = '\r\n'.join(lines) + '\r\n'
        data = text.encode(codec, errors='strict')
    if len(data) > 8388608:
        fail('Tool response exceeds the existing per-input bound')
    return command, data, tool_environment_hash(environment)


def validate_tool_contract(graph, recipe):
    contract = graph['toolResponseContract']
    keys(contract, ('schema', 'sources', 'hostBindings', 'console', 'sdkEnvironmentOverrides',
                    'directoryRoles', 'singleLoggingService', 'outOfProcessTaskHosts'))
    if (contract['schema'] != 'final-publish-tool-response-contract-v1' or
            contract['sources'] != TOOL_SOURCES or contract['singleLoggingService'] is not True or
            contract['outOfProcessTaskHosts'] is not False):
        fail('Unadmitted source/runtime/logging-service branch')
    if contract['console'] != {'stream': 'stdout', 'encoding': 'utf-8', 'locale': 'en-US',
            'verbosity': 'detailed', 'showEventId': True, 'forceNoAlign': True,
            'disableConsoleColor': True, 'terminalLogger': False}:
        fail('Unadmitted console source branch')
    keys(contract['hostBindings'], TOOL_HOST_ROLES)
    for pin in contract['hostBindings'].values():
        tool_pin(pin, graph)
    if contract['hostBindings']['sdkHost']['path'] != recipe['invocation']['executable']:
        fail('SDK host pin differs from the exact root invocation')
    plans = graph['toolResponses']
    if type(plans) is not list or not 3 <= len(plans) or len(plans) + len(graph['generatedResponses']) > 32:
        fail('Missing or excessive finite Csc/Exec response plans')
    roles = contract['directoryRoles']
    if type(roles) is not list or not 1 <= len(roles) <= len(plans):
        fail('Missing finite temporary-directory roles')
    for role in roles:
        string(role, '[a-z][a-z0-9-]{0,63}')
    if len(set(roles)) != len(roles) or len(graph['generatedPaths']) + len(roles) + len(plans) > 10000:
        fail('Duplicate roles or generated-input ceiling exceeded')
    identities = {x['id'] for x in graph['generatedResponses']}
    occurrences = set()
    used_roles, exec_responses = set(), []
    slots = {'ACTION_ROOT': WINDOWS + '\\actions\\9999', 'SOURCE_ROOT': graph['sourceRoot'],
             'PACKAGE_ROOT': graph['packageRoot'], 'ENDPOINT': '00000000000040008000000000000000'}
    common = ('id', 'kind', 'projectPath', 'targetName', 'taskOccurrence', 'producer',
              'tool', 'consumer', 'directoryRole', 'workingDirectoryTemplate',
              'taskEnvironmentOverrides', 'childEnvironmentTemplate', 'expectedOutcome')
    for plan in plans:
        kind = plan.get('kind')
        extra = ('directCommandTextTemplate', 'responseCommandTextTemplate', 'outputPathTemplate',
                 'executionMode') if kind == 'Csc' else ('commandTextTemplate', 'responseId', 'batchEncoding',
                                                       'echoOff', 'ignoreExitCode', 'workingDirectoryIsUnc')
        keys(plan, (*common, *extra))
        string(plan['id'], '[a-z][a-z0-9-]{0,63}')
        if plan['id'] in identities or kind not in ('Csc', 'Exec') or plan['expectedOutcome'] != 'executed-success':
            fail('Unknown, duplicate or skipped tool plan')
        identities.add(plan['id'])
        windows_path(plan['projectPath'])
        if not any(x['path'] == plan['projectPath'] for x in graph['protectedInputs']):
            fail('Tool project is unprotected')
        string(plan['targetName'], '[A-Za-z_][A-Za-z0-9_]{0,127}')
        integer(plan['taskOccurrence'], 1, 10000)
        identity = (plan['projectPath'], plan['targetName'], kind, plan['taskOccurrence'])
        if identity in occurrences:
            fail('Duplicate planned task occurrence')
        occurrences.add(identity)
        if plan['directoryRole'] not in roles:
            fail('Unknown temporary-directory role')
        used_roles.add(plan['directoryRole'])
        keys(plan['producer'], ('import', 'task'))
        for pin in (*plan['producer'].values(), plan['tool'], plan['consumer']):
            tool_pin(pin, graph)
        if plan['producer']['task'] != contract['hostBindings']['cscTask' if kind == 'Csc' else 'execTask']:
            fail('Task assembly differs from admitted source/host closure')
        if kind == 'Csc':
            mode = plan['executionMode']
            if type(mode.get('appHost')) is not bool or mode != {'builtinNetTask': True, 'frameworkBridge': False,
                    'hostCompiler': False, 'skipCompiler': False, 'useSharedCompilation': False,
                    'useCommandProcessor': False, 'responseFiles': [], 'appHost': mode['appHost']}:
                fail('Unknown Csc execution or nested response branch')
            directory = ntpath.dirname(plan['producer']['task']['path']) + '\\bincore'
            if plan['consumer']['path'] != directory + '\\csc.dll':
                fail('Built-in Csc consumer differs from task assembly location')
            if mode['appHost']:
                if plan['tool']['path'] != directory + '\\csc.exe':
                    fail('Built-in Csc apphost is not pinned')
            elif (plan['tool'] != contract['hostBindings']['sdkHost'] or
                  directory + '\\csc.exe' not in graph['absentInputs']):
                fail('Dotnet-exec Csc branch lacks its host or absent-apphost proof')
            if plan['outputPathTemplate'] not in graph['generatedPaths']:
                fail('Csc output is outside the finite generated graph')
        else:
            if plan['echoOff'] is not False or plan['ignoreExitCode'] is not False or plan['workingDirectoryIsUnc'] is not False:
                fail('Exec logging/status/UNC branch differs')
            if plan['tool']['path'] != 'C:\\Windows\\System32\\cmd.exe':
                fail('Exec command processor not pinned')
            if plan['responseId'] not in ('ilc', 'link'):
                fail('Unreviewed Exec companion role')
            response = next(x for x in graph['generatedResponses'] if x['id'] == plan['responseId'])
            if (plan['consumer']['path'] != response['consumer']['path'] or
                    plan['consumer']['sha256'] != response['consumer']['sha256'] or
                    plan['targetName'] != response['consumer']['target'] or
                    plan['producer']['import']['sha256'] != response['producer']['sha256']):
                fail('Exec role differs from the selected native response producer')
            exec_responses.append(plan['responseId'])
            encoding = plan['batchEncoding']
            if 'mode' in encoding:
                keys(encoding, ('mode', 'useUtf8Encoding', 'codePageTool'))
                if encoding != {'mode': 'ascii-default-detect', 'useUtf8Encoding': 'Detect',
                                'codePageTool': None}:
                    fail('Unreviewed Exec ASCII/default-Detect branch')
            else:
                keys(encoding, ('oemCodePage', 'codePage', 'useUtf8Encoding', 'codePageTool'))
                for name in ('oemCodePage', 'codePage'):
                    integer(encoding[name], 1, 65535)
                if encoding['useUtf8Encoding'] not in ('', 'Detect', 'Always', 'True', 'Never', 'System'):
                    fail('Unreviewed Exec encoding selection')
                if encoding['codePage'] != encoding['oemCodePage']:
                    tool_pin(encoding['codePageTool'], graph)
                    if encoding['codePageTool']['path'] != 'C:\\Windows\\System32\\chcp.com':
                        fail('Exec codepage tool differs from the source command')
                elif encoding['codePageTool'] is not None:
                    fail('Unexpected unused codepage tool')
        render_tool_plan(graph, plan, recipe, slots)
    if used_roles != set(roles) or sorted(exec_responses) != ['ilc', 'link']:
        fail('Unused directory role or incomplete/duplicate native Exec companion')


def tool_message_receipt(raw, offset):
    return {'offset': offset, 'bytes': len(raw), 'sha256': sha(raw)}


def join_tool_messages(graph, recipe, slots, stdout, stderr, checkpoint):
    # No cross-stream ordering is invented. The stderr exclusion rejects a
    # second logger route for these event families.
    for raw in stderr.splitlines():
        if re.search(rb'(?:TaskId:|TargetId:|Preserving temporary file)', raw):
            fail('Tool events arrived outside the admitted console stream')
    if not stdout.endswith(b'\r\n'):
        fail('Original ordinary console stream is incomplete')
    plans = graph['toolResponses']
    rendered = {}
    for plan in plans:
        checkpoint()
        rendered[plan['id']] = render_tool_plan(graph, plan, recipe, slots)
    target_stack, tasks, done, seen_targets = [], {}, {}, set()
    counts, dirs, seen_paths = {}, {}, set()
    previous_task, offset = 0, 0
    for raw in stdout.splitlines(keepends=True):
        checkpoint()
        if not raw.endswith(b'\r\n') or len(raw) > 2097152:
            fail('Unexpected console line framing or size')
        text = raw[:-2].decode('utf-8')
        receipt = tool_message_receipt(raw, offset)
        offset += len(raw)
        if '\r' in text or '\n' in text or '\0' in text or '\x1b' in text:
            fail('Uninterpretable console event')
        match = TARGET_START.fullmatch(text)
        if match:
            name, number, imported, project = match.groups()
            number = integer(int(number), 1, 2147483647)
            if number in seen_targets:
                fail('Reused target context')
            seen_targets.add(number)
            target_stack.append({'id': number, 'name': name, 'project': project,
                                 'import': imported or project, 'start': receipt})
            continue
        match = TARGET_END.fullmatch(text)
        if match:
            name, project, number = match.groups()
            if not target_stack:
                fail('Unmatched target finish')
            target = target_stack.pop()
            if (target['id'] != int(number) or target['name'] != name or
                    ntpath.basename(target['project']) != project or
                    any(state['target']['id'] == target['id'] for state in tasks.values())):
                fail('Ambiguous target/project nesting')
            continue
        match = TASK_START.fullmatch(text)
        if match:
            name, number = match.groups()
            number = integer(int(number), 1, 2147483647)
            if number <= previous_task or number in tasks or not target_stack:
                fail('Missing/reused/nonmonotonic same-service task context')
            previous_task = number
            target = target_stack[-1]
            identity = (target['project'], target['name'], name)
            counts[identity] = counts.get(identity, 0) + 1
            state = {'name': name, 'target': dict(target), 'start': receipt, 'plan': None,
                     'command': None, 'preservation': None, 'environment': []}
            if name in ('Csc', 'Exec'):
                matches = [p for p in plans if (p['projectPath'], p['targetName'], p['kind']) == identity
                           and p['taskOccurrence'] == counts[identity]]
                if len(matches) != 1 or matches[0]['producer']['import']['path'] != target['import']:
                    fail('Unexpected or ambiguous executed Csc/Exec graph occurrence')
                state['plan'] = matches[0]
            tasks[number] = state
            continue
        match = TASK_END.fullmatch(text)
        if match:
            name, number = match.groups(); number = int(number)
            state = tasks.pop(number, None)
            if (state is None or state['name'] != name or not target_stack or
                    state['target']['id'] != target_stack[-1]['id']):
                fail('Unmatched successful task finish')
            plan = state['plan']
            if plan is not None:
                expected_env = ['  ' + item['name'] + '=' + resolve(item['value'], slots)
                                for item in plan['taskEnvironmentOverrides']]
                if (state['command'] is None or state['preservation'] is None or
                        [x['text'] for x in state['environment']] != expected_env or
                        state['command']['offset'] >= state['preservation']['offset']):
                    fail('Incomplete or out-of-order tool/environment evidence')
                if plan['id'] in done:
                    fail('Duplicate tool completion')
                done[plan['id']] = {'id': plan['id'], 'kind': plan['kind'], 'taskId': number,
                    'projectPath': plan['projectPath'], 'targetName': plan['targetName'],
                    'taskOccurrence': plan['taskOccurrence'], 'targetId': state['target']['id'],
                    'targetStart': state['target']['start'], 'taskStart': state['start'],
                    'command': state['command'], 'preservation': state['preservation'],
                    'taskFinish': receipt, 'environmentMessages': [x['receipt'] for x in state['environment']],
                    'path': state['path'], 'directoryRole': plan['directoryRole']}
            continue
        match = TASK_MESSAGE.fullmatch(text)
        if match:
            message, number = match.groups(); number = int(number)
            state = tasks.get(number)
            if state is None:
                fail('Message outside its original task boundaries')
            plan = state['plan']
            preserving = PRESERVATION.fullmatch(message)
            if preserving and plan is None:
                fail('Undeclared retained ToolTask producer')
            if plan is not None:
                command, _, _ = rendered[plan['id']]
                if message == command:
                    if state['command'] is not None:
                        fail('Duplicate exact expanded command')
                    state['command'] = receipt
                elif preserving:
                    if state['preservation'] is not None:
                        fail('Multiple temporary files for one planned role')
                    path = windows_path(preserving[1])
                    parent, leaf = ntpath.split(path)
                    extension = r'\.rsp' if plan['kind'] == 'Csc' else r'\.exec\.cmd'
                    if (ntpath.dirname(parent) != slots['ACTION_ROOT'] + '\\temp' or
                            not re.fullmatch(TEMP_DIRECTORY, ntpath.basename(parent)) or
                            not re.fullmatch(r'tmp[0-9a-f]{32}' + extension, leaf) or path in seen_paths):
                        fail('Generated path does not satisfy its exact finite naming role')
                    role = plan['directoryRole']
                    if role in dirs and dirs[role] != parent or role not in dirs and parent in dirs.values():
                        fail('Temporary-directory roles alias or change')
                    dirs[role] = parent; seen_paths.add(path)
                    state['path'] = path; state['preservation'] = receipt
                elif re.fullmatch(r'  [A-Za-z_][A-Za-z0-9_()]*=.*', message):
                    if state['command'] is not None:
                        fail('Late task environment override message')
                    state['environment'].append({'text': message, 'receipt': receipt})
            continue
        # Event-shaped text cannot bypass the exact source grammar.
        if ('(TaskId:' in text or '(TargetId:' in text or 'Preserving temporary file' in text or
                text.startswith('Done executing task "') or text.startswith('Done building target "')):
            fail('Unknown, failed or ambiguous source event')
    if target_stack or tasks or len(done) != len(plans) or set(dirs) != set(graph['toolResponseContract']['directoryRoles']):
        fail('Incomplete original graph event closure')
    return [done[p['id']] for p in plans], dirs


def tool_inventory(graph, slots, expected_paths, expected_directories, checkpoint, before=False):
    root = direct(projection(slots['ACTION_ROOT'] + '\\temp'))
    count, paths, directories = 0, set(), set()
    temp_prefix = slots['ACTION_ROOT'] + '\\temp\\'
    static = set()
    for template in graph['generatedPaths']:
        path = resolve(template, slots)
        if path.startswith(temp_prefix):
            if ntpath.basename(path[len(temp_prefix):].split('\\')[0]).lower().startswith('msbuildtemp'):
                fail('Static generated path overlaps a dynamic temporary role')
            static.add(path)
            parent = ntpath.dirname(path)
            while parent.startswith(temp_prefix):
                static.add(parent)
                parent = ntpath.dirname(parent)
    pending = []
    with os.scandir(root) as items:
        for entry in items:
            checkpoint(); count += 1
            if count + len(graph['generatedPaths']) > 10000:
                fail('Temporary inventory exceeded generated-path bound')
            if not entry.name.lower().startswith('msbuildtemp'):
                pending.append((entry.path, temp_prefix + entry.name))
                continue
            if before or not re.fullmatch(TEMP_DIRECTORY, entry.name) or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                fail('Stale or inadmissible MSBuild temporary directory')
            parent = slots['ACTION_ROOT'] + '\\temp\\' + entry.name
            directories.add(parent)
            direct(entry.path)
            with os.scandir(entry.path) as members:
                for member in members:
                    checkpoint(); count += 1
                    if count + len(graph['generatedPaths']) > 10000:
                        fail('Temporary inventory exceeded generated-path bound')
                    if member.is_symlink() or not member.is_file(follow_symlinks=False):
                        fail('Nonregular or nested retained temporary input')
                    paths.add(parent + '\\' + member.name)
    while pending:
        checkpoint()
        local, path = pending.pop()
        if before or path not in static:
            fail('Undeclared or stale temporary input outside a tool role')
        direct(local)
        info = os.lstat(local)
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(local) as members:
                for member in members:
                    checkpoint(); count += 1
                    if count + len(graph['generatedPaths']) > 10000:
                        fail('Temporary inventory exceeded generated-path bound')
                    pending.append((member.path, path + '\\' + member.name))
        elif not stat.S_ISREG(info.st_mode):
            fail('Nonregular static temporary input')
    if not before and (paths != set(expected_paths) or directories != set(expected_directories)):
        fail('Unmatched or missing retained temporary member')


def tool_observations(graph, recipe, slots, stdout, stderr, reservation, graph_hash,
                      checkpoint, read_bytes):
    joined, directories = join_tool_messages(graph, recipe, slots, stdout, stderr, checkpoint)
    tool_inventory(graph, slots, [x['path'] for x in joined], directories.values(), checkpoint)
    observations = []
    for plan, observed in zip(graph['toolResponses'], joined):
        checkpoint()
        _, expected, environment_hash = render_tool_plan(graph, plan, recipe, slots)
        actual = read_bytes(projection(observed['path']))
        if actual != expected:
            fail('Original preserved tool input differs from exact producer bytes')
        observed.update(bytes=len(actual), sha256=sha(actual),
            producerImportSha256=plan['producer']['import']['sha256'],
            taskAssemblySha256=plan['producer']['task']['sha256'],
            consumerSha256=plan['consumer']['sha256'], toolSha256=plan['tool']['sha256'],
            childEnvironmentBlockSha256=environment_hash,
            stream='stdout', streamSha256=sha(stdout), reservationSha256=reservation,
            graphSha256=graph_hash, snapshot='response-inputs/' + plan['id'] + '.bin',
            snapshotSha256=sha(actual))
        observations.append(observed)
    return observations


def hash_protected(item, deadline, cancelled):
    budget(deadline, cancelled)
    path = direct(projection(item['path']))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size != item['bytes']:
            fail('Protected input size or type changed')
        hasher = hashlib.sha256()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            while chunk := stream.read(1048576):
                budget(deadline, cancelled)
                hasher.update(chunk)
        if hasher.hexdigest() != item['sha256']:
            fail('Protected input hash changed')
    finally:
        os.close(fd)
    budget(deadline, cancelled)


# Current publication consumes accepted checkpoints, never historical runtime leaves.
PUBLICATION_GUARD_FIELDS = ('actionNumber', 'sourceSha256', 'dllBytes', 'dllSha256',
                            'artifactAcceptanceSha256', 'expectedAssemblyFullName')
PUBLICATION_LAUNCHER_FIELDS = ('preparationAction', 'sourceSha256', 'exeBytes', 'exeSha256',
                              'artifactAcceptanceSha256', 'mode')
PUBLICATION_COUNTERS = ('preparation', 'buildTest', 'publication', 'synthetic')
PUBLICATION_BASE = {
    'path': '/tmp/windows-negatives0080-outcome-accounting-acceptance-budget-v1.json',
    'bytes': 9373,
    'sha256': 'ee9e2ca7b5635add3a231930acc8ef2c3d2851056d3f8689b239ce038c1de791',
}
PUBLICATION_GUARD_ACCEPTANCE = {
    'path': '/tmp/windows-named-guard0066-actual-managed-artifact-acceptance-lifetime-v1.json',
    'bytes': 22595,
    'sha256': '09240c6a14e37707be0ef772881c9fc8726d0b1b8bdf0d3de3b6850c2dcd809f',
}


def publication_descriptor_read(pin, deadline, cancelled):
    path = provenance_descriptor(pin, maximum=1048576)
    raw = bound({k: pin[k] for k in ('bytes', 'sha256')}, path, deadline, cancelled)
    return {'pin': pin, 'raw': raw, 'value': decode(raw)}


def verify_publication_artifacts(envelope, evidence, deadline, cancelled):
    guard = envelope['acceptedGuard']
    keys(guard, PUBLICATION_GUARD_FIELDS)
    expected = {
        'actionNumber': '0066',
        'sourceSha256': '45c0d829712bac66ece76676939310d04f59af9a83709f1b1e80b8bf1f4a8501',
        'dllBytes': 24576,
        'dllSha256': 'a18302e4658afc08b564be23c9b52995fba85c1a3345fba19662008efe30ae58',
        'artifactAcceptanceSha256': PUBLICATION_GUARD_ACCEPTANCE['sha256'],
        'expectedAssemblyFullName': 'WindowsFinalPublishGuard, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null',
    }
    if compact(guard) != compact(expected):
        fail('Original 0066 named guard projection changed')
    launcher = envelope['acceptedLauncher']
    keys(launcher, PUBLICATION_LAUNCHER_FIELDS)
    if (launcher['preparationAction'] != '0085' or launcher['mode'] != '--publication' or
            launcher['sourceSha256'] != envelope['components']['nativeLauncher']['sha256']):
        fail('Current publication launcher mode or compiled source changed')
    integer(launcher['exeBytes'], 1, 1048576)
    digest(launcher['exeSha256'])
    digest(launcher['artifactAcceptanceSha256'])
    budget(deadline, cancelled)


def load_publication_provenance(envelope, evidence, deadline, cancelled):
    caller = evidence['callerAuthorization']
    joins = (*CALLER_AUTHORIZATION_JOINS, 'acceptedLauncher')
    keys(caller, ('schema', 'accepted', 'scope', *joins, 'originalGuardEvidence',
                  'originalLauncherEvidence', 'callerPolicy', 'noExecutionGrant'))
    if (caller['schema'] != 'final-publish-caller-authorization-v2' or caller['accepted'] is not True or
            caller['scope'] != 'one-supervised-final-publication' or
            caller['callerPolicy'] != 'fixed-final-only-callers-no-generic-helper-use' or
            caller['noExecutionGrant'] is not True):
        fail('Current caller authorization is absent or out of scope')
    if any(compact(caller[key]) != compact(envelope[key]) for key in joins):
        fail('Current caller source, recipe or artifact join changed')
    for name in ('originalGuardEvidence', 'originalLauncherEvidence'):
        keys(caller[name], ('artifactAcceptance',))
    guard_pin = caller['originalGuardEvidence']['artifactAcceptance']
    if guard_pin != PUBLICATION_GUARD_ACCEPTANCE:
        fail('Current caller must retain the exact original 0066 acceptance')
    guard = publication_descriptor_read(guard_pin, deadline, cancelled)
    g = guard['value']
    if (g['schema'] != 'named-guard0066-actual-managed-artifact-acceptance-v1' or
            any(g['decision'].get(key) is not True for key in
                ('artifactAccepted', 'compiledSourceCorrespondenceAccepted', 'staticPeIlAccepted')) or
            g['references']['guardSource']['sha256'] != envelope['acceptedGuard']['sourceSha256'] or
            g['artifact']['bytes'] != envelope['acceptedGuard']['dllBytes'] or
            g['artifact']['sha256'] != envelope['acceptedGuard']['dllSha256']):
        fail('Original 0066 artifact acceptance does not establish this guard')
    launcher_pin = caller['originalLauncherEvidence']['artifactAcceptance']
    if launcher_pin['sha256'] != envelope['acceptedLauncher']['artifactAcceptanceSha256']:
        fail('Native artifact review changed')
    launcher = publication_descriptor_read(launcher_pin, deadline, cancelled)
    l = launcher['value']
    # This future actual-artifact review is produced only after the separately
    # admitted compilation and must cover the exact nonterminating mode.
    if (l.get('schema') != 'publication-launcher-managed-artifact-acceptance-v1' or
            l.get('accepted') is not True or l.get('preparationAction') != '0085' or
            l.get('sourceSha256') != envelope['acceptedLauncher']['sourceSha256'] or
            l.get('publicationMode') != '--publication' or
            l.get('noTerminationAfterResumeAttemptAccepted') is not True or
            l.get('artifact', {}).get('bytes') != envelope['acceptedLauncher']['exeBytes'] or
            l.get('artifact', {}).get('sha256') != envelope['acceptedLauncher']['exeSha256']):
        fail('Exact native publication artifact remains unaccepted')
    artifacts = {}
    for role, value in (('guardArtifact', g), ('launcherArtifact', l)):
        pin = {key: value['artifact'][key] for key in ('path', 'bytes', 'sha256')}
        path = provenance_descriptor(pin, maximum=1048576)
        raw = bound({key: pin[key] for key in ('bytes', 'sha256')}, path, deadline, cancelled)
        artifacts[role] = {'pin': pin, 'raw': raw}
    return {'guardAcceptance': guard, 'launcherAcceptance': launcher, **artifacts}


def refresh_publication_provenance(admission, deadline, cancelled):
    # Exactly four retained inputs, no recursive evidence traversal or old runtime reads.
    for role in ('guardAcceptance', 'launcherAcceptance', 'guardArtifact', 'launcherArtifact'):
        retained = admission['callerProvenance'][role]
        pin = retained['pin']
        raw = bound({key: pin[key] for key in ('bytes', 'sha256')},
                    Path(pin['path']), deadline, cancelled)
        if raw != retained['raw']:
            fail('Current publication provenance changed before reservation')


def refresh_publication_checkpoint(admission, deadline, cancelled, binding=None):
    manifest = admission['evidence']['handoff']
    keys(manifest, ('schema', 'baseAcceptance', 'baseCounters', 'stages', 'currentCounters',
                    'ceilings', 'knownEndpoints', 'nextAction', 'historyParents'))
    if (manifest['schema'] != 'final-publish-current-checkpoint-v1' or
            manifest['baseAcceptance'] != PUBLICATION_BASE or manifest['nextAction'] != '0093'):
        fail('Current publication checkpoint identity changed')
    expected_review = {'schema': 'final-publish-handoff-acceptance-v2', 'accepted': True,
                       'handoff': admission['envelope']['handoff'], 'originalDispositionsPreserved': True,
                       'noHistoryReplay': True, 'noExecutionGrant': True}
    if admission['evidence']['handoffAcceptance'] != expected_review:
        fail('Current checkpoint independent acceptance is absent')
    state = admission.setdefault('currentCheckpoint', {'passes': 0})
    if state['passes'] != (0 if binding is None else 1):
        fail('Current checkpoint repeated or reordered')
    state['passes'] += 1
    base = publication_descriptor_read(PUBLICATION_BASE, deadline, cancelled)['value']
    if (base['accounting']['order'] != list(PUBLICATION_COUNTERS) or
            base['accounting']['after'] != [19, 102, 2, 130] or
            base['accounting']['ceilings'] != [28, 130, 30, 180] or
            base.get('allOriginalCallsSpent') is not True):
        fail('Original 0080 accounting checkpoint changed')
    counters = dict(zip(PUBLICATION_COUNTERS, (19, 102, 2, 130), strict=True))
    ceilings = dict(zip(PUBLICATION_COUNTERS, (28, 130, 30, 180), strict=True))
    if manifest['baseCounters'] != counters or manifest['ceilings'] != ceilings:
        fail('Current counters or ceilings were reset')
    if type(manifest['stages']) is not list or len(manifest['stages']) != 2:
        fail('Publication requires exactly the new compilation and six-case acceptance')
    for stage, action, values in zip(manifest['stages'], ('0085', '0086'),
                                     ((1, 0, 0, 0), (0, 1, 0, 17)), strict=True):
        keys(stage, ('action', 'acceptance', 'charge', 'countersAfter'))
        charge = dict(zip(PUBLICATION_COUNTERS, values, strict=True))
        if stage['action'] != action or compact(stage['charge']) != compact(charge):
            fail('Future preparation or validation charge changed')
        receipt = publication_descriptor_read(stage['acceptance'], deadline, cancelled)['value']
        after = {key: counters[key] + charge[key] for key in PUBLICATION_COUNTERS}
        if (receipt.get('accounting') != {'action': action, 'before': counters, 'charge': charge, 'after': after} or
                receipt.get('accepted') is not True or stage['countersAfter'] != after):
            fail('Future stage lacks exact accepted accounting')
        counters = after
    if manifest['currentCounters'] != counters:
        fail('Current checkpoint arithmetic changed')
    prospective = dict(counters, publication=counters['publication'] + 1, synthetic=counters['synthetic'] + 1)
    if any(prospective[key] > ceilings[key] for key in PUBLICATION_COUNTERS) or ceilings['synthetic'] - prospective['synthetic'] < 12:
        fail('Publication exceeds ceilings or consumes protected CLI capacity')
    endpoints = manifest['knownEndpoints']
    if type(endpoints) is not list or len(endpoints) > 512 or endpoints != sorted(set(endpoints)):
        fail('Accepted endpoint projection is incomplete or duplicated')
    for endpoint in endpoints:
        string(endpoint, '[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}')
    parents = {'linuxActions': LINUX / 'actions', 'windowsActions': HISTORY,
               'windowsProjectionActions': PROJECTION / 'actions', 'windowsProjectionRoot': PROJECTION}
    keys(manifest['historyParents'], parents)
    for role, path in parents.items():
        expected = manifest['historyParents'][role]
        if type(expected) is not list or expected != sorted(set(expected)) or len(expected) > 128:
            fail('Invalid accepted parent membership')
        if binding is not None and role in ('windowsActions', 'windowsProjectionActions'):
            expected = sorted([*expected, manifest['nextAction']])
        if core_csc_names(path, 128, deadline, cancelled) != expected:
            fail('Parent membership changed; require a fresh accounting checkpoint')
    if binding is not None:
        for path in (binding['local'] / 'started.json', binding['owned'] / 'started.json'):
            if sha(read(path, deadline, cancelled, 16384)) != binding['reservationSha256']:
                fail('Original publication debit changed')
    return counters, manifest


def load_admission(deadline, cancelled, *, reviewed_authority):
    budget(deadline, cancelled)
    if DRAFT_ONLY:
        raise RuntimeError('UNBOUND: independent fixed launcher envelope')
    # bound rejects anything but the exact bytes/SHA256 descriptor before I/O.
    # The separately accepted literal supplies it without mutating module state.
    raw = bound(reviewed_authority, AUTHORITY, deadline, cancelled)
    envelope = decode(raw, canonical=True)
    keys(envelope, ('schema', 'repository', 'target', 'protocol', 'wave', 'product', 'integration',
                    'components', 'recipe', 'acceptedGuard', 'acceptedLauncher', 'rootMarkers', 'limits', *INPUTS))
    if (envelope['schema'] != 'final-publish-external-authority-v3' or envelope['repository'] != FORK or
            envelope['product'] != PRODUCT or envelope['limits'] != LIMITS):
        fail('Authority scope or selected product changed')
    for role in ('target', 'product', 'integration'):
        verify_revision(envelope[role], deadline, cancelled)
    keys(envelope['protocol'], ('commit', 'tree', 'gitBlob', 'bytes', 'sha256'))
    p = {k: envelope['protocol'][k] for k in ('commit', 'tree')}
    verify_revision(p, deadline, cancelled)
    protocol_pin = {k: envelope['protocol'][k] for k in ('gitBlob', 'bytes', 'sha256')}
    verify_blob(p, PROTOCOL, protocol_pin, deadline, cancelled)
    verify_blob(envelope['target'], PROTOCOL, protocol_pin, deadline, cancelled)
    verify_blob(envelope['target'], 'docs/delivery-wave.md', envelope['wave'], deadline, cancelled)
    for owner in (p, envelope['integration'], PRODUCT):
        git(['merge-base', '--is-ancestor', owner['commit'], envelope['target']['commit']], deadline, cancelled)
    keys(envelope['components'], COMPONENTS)
    component_bytes = {}
    for role, filename in COMPONENTS.items():
        pin = envelope['components'][role]
        data = verify_blob(envelope['integration'], 'tools/validation/' + filename.replace('.draft', ''), pin, deadline, cancelled)
        local = read(PACKAGE / 'candidate' / filename, deadline, cancelled)
        if data != local:
            fail('Materialized caller source differs from accepted immutable source')
        component_bytes[role] = data
    recipe_raw = bound(envelope['recipe'], PACKAGE / 'recipe.json', deadline, cancelled)
    if sha(recipe_raw) != RECIPE_SHA256:
        fail('The exact v4 invocation/environment/tool recipe changed')
    recipe = decode(recipe_raw, canonical=True)
    evidence_raw = {role: bound(envelope[role], EVIDENCE / (role + '.json'), deadline, cancelled,
                               CALLER_PROVENANCE_LIMIT if role == 'callerAuthorization' else 8388608)
                    for role in INPUTS}
    # Current wrappers use canonical JSON; original sealed evidence keeps its bytes.
    evidence = {role: decode(value, canonical=True)
                for role, value in evidence_raw.items()}
    common = {k: envelope[k] for k in ('product', 'integration', 'protocol', 'components', 'recipe')}
    if evidence['sourceReview'] != {'schema': 'final-publish-source-acceptance-v1', 'accepted': True,
                                    'scope': 'publication-only', **common}:
        fail('Source review does not cover this exact caller integration')
    validate_graph(evidence['graph'], recipe)
    if evidence['graphAcceptance'] != {'schema': 'final-publish-graph-acceptance-v1', 'accepted': True,
                                      'product': PRODUCT, 'graph': envelope['graph'], 'recipe': envelope['recipe'],
                                      'completeInputClosure': True, 'completeResponseClosure': True,
                                      'orderedProducerConsumerPlanAccepted': True}:
        fail('Independent complete graph/response acceptance missing')
    verify_publication_artifacts(envelope, evidence, deadline, cancelled)
    guard_review = evidence['guardAcceptance']
    if guard_review != {'schema': 'final-publish-guard-acceptance-v2', 'accepted': True,
                        'acceptedGuard': envelope['acceptedGuard'], 'original0066ProvenanceAccepted': True,
                        'managedGuardArtifactAccepted': True, 'finalNoKillModeAccepted': True}:
        fail('Independent actual guard acceptance missing')
    review_subject = {key: value for key, value in envelope.items() if key not in ('executionReview', 'publication', 'schema')}
    if evidence['executionReview'] != {'schema': 'final-publish-execution-acceptance-v1', 'accepted': True,
                                      'subject': review_subject, 'scope': 'one-final-publish-no-retry'}:
        fail('Independent current execution acceptance missing')
    publication = evidence['publication']
    review_roles = ('sourceReview', 'handoffAcceptance', 'graphAcceptance', 'guardAcceptance',
                    'callerAuthorization', 'executionReview')
    keys(publication, ('schema', *review_roles))
    if publication['schema'] != 'final-publish-publication-bindings-v2':
        fail('Publication binding schema changed')
    for role in review_roles:
        verify_public_review(publication[role], evidence_raw[role], deadline, cancelled)
    caller_provenance = load_publication_provenance(envelope, evidence, deadline, cancelled)
    keys(envelope['rootMarkers'], ('linuxOwnerSha256', 'windowsOwnerSha256'))
    for path, key in ((LINUX / 'owner.json', 'linuxOwnerSha256'), (PROJECTION / 'owner.json', 'windowsOwnerSha256')):
        data = read(path, deadline, cancelled, 4096)
        if sha(data) != digest(envelope['rootMarkers'][key]) or decode(data) != ROOT_MARKER:
            fail('Original root ownership changed')
    assert_target_current(envelope, deadline, cancelled)
    return {'envelope': envelope, 'authorityBytes': raw, 'components': component_bytes,
            'recipe': recipe, 'evidence': evidence, 'evidenceBytes': evidence_raw,
            'callerProvenance': caller_provenance,
            'failedHistory': {'passes': 0, 'reads': 0, 'requestedBytes': 0,
                              'metadataProbes': 0, 'remainingSeconds': 30.0,
                              'snapshot': None, 'failed': False}}


def names(path, deadline, cancelled):
    if CORE_CSC_HISTORY_ONLY or COMPILER_NATIVE_INPUTS_HISTORY_ONLY or not DRAFT_ONLY:
        values = core_csc_names(path, 100, deadline, cancelled)
    else:
        values = sorted(p.name for p in direct(path).iterdir())
    expected = [f'{i:04d}' for i in range(1, len(values) + 1)]
    if COMPILER_NATIVE_INPUTS_HISTORY_ONLY and Path(path) in (HISTORY, PROJECTION / 'actions'):
        # Retained 0060/0061 are parent membership only, outside the receipt handoff.
        # 0057 and failed 0058/0059 stay consumed, never fabricated disk entries.
        expected = [f'{i:04d}' for i in range(1, 57)] + ['0060', '0061']
        if len(values) == 59:
            expected.append('0062')
    elif not DRAFT_ONLY and Path(path) in (HISTORY, PROJECTION / 'actions'):
        expected = [f'{i:04d}' for i in range(1, 57)] + list(FINAL_RETAINED_SUCCESSORS)
        if len(values) == len(expected) + 1:
            expected.append(final_action_number())
    if values != expected:
        fail('Incomplete or noncontiguous original action history')
    return values


# Immutable final-caller binding to the unchanged accepted failed 0056 evidence.
CORE_CSC_FAILED_DISPOSITION = {
    "path": "/tmp/windows-core-csc-0056-failed-history-disposition-root-v1.json",
    "bytes": 3202,
    "sha256": "6a241958bfd4693de219393c5920277e18ead52f8d039cd265f412837d142525",
}
CORE_CSC_FAILED_DISPOSITION_BINDING = CORE_CSC_FAILED_DISPOSITION.copy()
CORE_CSC_FAILED_ORIGINALS = {
    "wsl-result": "/var/tmp/azureauth-windows-slice-108/windows-actions/0056/result.json",
    "wsl-started": "/var/tmp/azureauth-windows-slice-108/windows-actions/0056/started.json",
    "wsl-controller-attempt": "/var/tmp/azureauth-windows-slice-108/windows-actions/0056/controller-start-attempt.json",
    "windows-started": "/mnt/c/Temp/azureauth-windows-slice-108/actions/0056/started.json",
    "wsl-invocation": "/var/tmp/azureauth-windows-slice-108/windows-actions/0056/invocation.json",
    "windows-invocation": "/mnt/c/Temp/azureauth-windows-slice-108/actions/0056/invocation.json",
}


def verify_disposed_core_csc_observer(state=None, deadline=None, cancelled=None):
    """Read only the disposition and six fixed originals, never a complete tree.

    Each pass has seven content reads requesting at most 15,093 bytes. Final
    publication uses two passes sharing 30 seconds and checks current continuity;
    an ordinary history reader uses one pass. Historical absence stays historical.
    """
    if CORE_CSC_FAILED_DISPOSITION_BINDING != CORE_CSC_FAILED_DISPOSITION:
        raise ValueError("UNBOUND: exact failed 0056 disposition")
    state = {} if state is None else state
    if state.get("failed") or state.get("passes", 0) >= 2:
        raise ValueError("Failed 0056 history verification cannot repeat")
    began = time.monotonic()
    remaining = state.get("remainingSeconds", 30.0)
    end = began + remaining
    if deadline is not None:
        end = min(end, deadline)
    state["passes"] = state.get("passes", 0) + 1
    state["failed"] = True
    snapshot = {}

    def check():
        if cancelled is not None and cancelled():
            raise InterruptedError("Failed 0056 history verification cancelled")
        if time.monotonic() >= end:
            raise TimeoutError("Failed 0056 shared history deadline exhausted")

    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)

    def fixed_read(path, expected):
        path = Path(path)
        if not path.is_absolute() or len(path.parts) > 17:
            raise ValueError("Invalid fixed 0056 evidence path")
        for parent in reversed(path.parents):
            check()
            if not stat.S_ISDIR(os.stat(parent, follow_symlinks=False).st_mode):
                raise ValueError("Nonordinary 0056 evidence ancestor")
        check()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected["bytes"]:
                raise ValueError("Failed 0056 evidence type or size changed")
            check()
            if COMPILER_NATIVE_INPUTS_HISTORY_ONLY:
                core_csc_charge_read(expected["bytes"] + 1)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(expected["bytes"] + 1)
            check()
            after = os.fstat(fd)
            current = os.stat(path, follow_symlinks=False)
            if (identity(before) != identity(after) or identity(after) != identity(current) or
                    len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]):
                raise ValueError("Failed 0056 evidence identity or bytes changed")
            snapshot[str(path)] = identity(after)
            return raw
        finally:
            os.close(fd)

    try:
        disposition = json.loads(fixed_read(
            CORE_CSC_FAILED_DISPOSITION["path"], CORE_CSC_FAILED_DISPOSITION))
        # The complete descriptor hash pins all accepted historical and lifetime
        # evidence references. Only these six fixed originals are reread here.
        if (disposition["schema"] != "core-csc-observer-failed-history-disposition-v1" or
                disposition["actionNumber"] != "0056" or disposition["actionKind"] != "core-csc-observer" or
                set(disposition["originalCopies"]) != set(CORE_CSC_FAILED_ORIGINALS)):
            raise ValueError("Wrong exact failed 0056 disposition")
        raw = {role: fixed_read(path, disposition["originalCopies"][role])
               for role, path in CORE_CSC_FAILED_ORIGINALS.items()}
        if raw["wsl-started"] != raw["windows-started"] or raw["wsl-invocation"] != raw["windows-invocation"]:
            raise ValueError("Failed 0056 original pairs changed")
        started, result = json.loads(raw["wsl-started"]), json.loads(raw["wsl-result"])
        invocation, attempt = json.loads(raw["wsl-invocation"]), json.loads(raw["wsl-controller-attempt"])
        reservation_hash = hashlib.sha256(raw["wsl-started"]).hexdigest()
        if (started["number"] != "0056" or started["action"] != "core-csc-observer" or
                started["handoffSha256"] != disposition["baseHandoff"]["sha256"] or
                started["priorCounters"] != {"linux": [8, 37, 0, 0], "windows": [7, 48, 0, 48]} or
                [started[key] for key in ("preparationCharge", "buildTestCharge", "publishCharge",
                                         "reservedProcessScenarios")] != [0, 1, 0, 0] or
                any(value["reservationSha256"] != reservation_hash for value in (result, invocation, attempt)) or
                result["invocationSha256"] != hashlib.sha256(raw["wsl-invocation"]).hexdigest() or
                invocation["endpoint"] != started["endpoint"]):
            raise ValueError("Failed 0056 reservation or original charge changed")
        if (result["failureType"] != "RuntimeError" or result["outcome"] != "incomplete" or
                result["proxyExitCode"] is not None or result["launchAttempted"] is not True or
                result["safetyStop"] is not True or any(result[key] is not False for key in (
                    "normalCompletion", "quiescent", "originalWindowsCompletionJoined",
                    "graphAccepted", "artifactAccepted", "independentObservationAccepted", "continuation_allowed"))):
            raise ValueError("Failed 0056 original result flags changed")
        if state.get("snapshot") is not None and snapshot != state["snapshot"]:
            raise ValueError("Failed 0056 current continuity changed")
        check()
        state["snapshot"] = snapshot
        state["failed"] = False
        return started, result
    finally:
        state["remainingSeconds"] = remaining - (time.monotonic() - began)
        if state["remainingSeconds"] <= 0:
            state["failed"] = True
            raise TimeoutError("Failed 0056 shared verification time exhausted")
        try:
            check()
        except BaseException:
            state["failed"] = True
            raise


def classify(platform, start):
    action = start.get('action')
    if platform == 'linux':
        if action in ('fetch', 'restore'):
            return [1, 0, 0, 0]
        if action in ('build', 'test'):
            return [0, 1, 0, 0]
        fail('Unknown original Linux charge')
    if action in ('bootstrap', 'restore', 'final-guard-prepare'):
        return [1, 0, 0, 0]
    if action in ('build', 'test'):
        return [0, 1, 0, integer(start.get('reservedProcessScenarios', 0), 0, 60)]
    # A prior final publication, including a failed reservation, forbids retry.
    fail('Unknown or already consumed final Windows allocation')



def failed_identity(info):
    return tuple(getattr(info, key) for key in FAILED_IDENTITY_FIELDS)


def failed_parent(path, deadline, cancelled):
    # Only the source-defined fixed-role table calls this no-follow walk.
    parts = path.split('/')
    if (not path.startswith('/') or not 1 < len(parts) <= 17 or
            any(part in ('', '.', '..') for part in parts[1:])):
        fail('Noncanonical or overdeep failed-history role')
    budget(deadline, cancelled)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[1:-1]:
            budget(deadline, cancelled)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        budget(deadline, cancelled)
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def failed_metadata(state, deadline, cancelled):
    observed = {}
    for role, expected in FAILED_GUARD_METADATA.items():
        budget(deadline, cancelled)
        state['metadataProbes'] += 1
        if state['metadataProbes'] > 34:
            fail('Failed-history metadata allowance exhausted')
        parent = None
        try:
            parent, leaf = failed_parent(expected['path'], deadline, cancelled)
            info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            if expected['status'] != 'absent':
                fail('Required failed-history role disappeared')
            observed[role] = None
        else:
            if expected['status'] == 'absent':
                fail('Previously absent failed-history role appeared')
            if ((expected['type'] == 'directory' and not stat.S_ISDIR(info.st_mode)) or
                    (expected['type'] == 'file' and not stat.S_ISREG(info.st_mode)) or
                    (role == 'windowsCancel' and info.st_size != 0)):
                fail('Failed-history role kind or cancel marker changed')
            # Historical directory allocation size is not a current predicate.
            observed[role] = failed_identity(info)
        finally:
            if parent is not None:
                os.close(parent)
        budget(deadline, cancelled)
    return observed


def failed_content(state, deadline, cancelled):
    values, identities = {}, {}
    for role, pin in FAILED_GUARD_CONTENT.items():
        budget(deadline, cancelled)
        state['reads'] += 1
        state['requestedBytes'] += pin['bytes'] + 1
        if CORE_CSC_HISTORY_ONLY or COMPILER_NATIVE_INPUTS_HISTORY_ONLY:
            core_csc_charge_read(pin['bytes'] + 1)
        if state['reads'] > 14 or state['requestedBytes'] > 123166:
            fail('Failed-history content allowance exhausted')
        parent, leaf = failed_parent(pin['path'], deadline, cancelled)
        fd = None
        try:
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size != pin['bytes']:
                fail('Failed-history content kind or exact size changed')
            chunks, remaining = [], pin['bytes']
            while remaining:
                budget(deadline, cancelled)
                chunk = os.read(fd, min(remaining, 65536))
                if not chunk:
                    fail('Truncated failed-history content')
                chunks.append(chunk)
                remaining -= len(chunk)
            budget(deadline, cancelled)
            extra = os.read(fd, 1)
            after = os.fstat(fd)
            current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            raw = b''.join(chunks)
            if (extra or failed_identity(before) != failed_identity(after) or
                    failed_identity(after) != failed_identity(current) or
                    len(raw) != pin['bytes'] or sha(raw) != pin['sha256']):
                fail('Fresh failed-history content or identity changed')
            values[role], identities[role] = raw, failed_identity(after)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)
        budget(deadline, cancelled)
    return values, identities


def verify_failed_handoff(admission, deadline, cancelled, reserved):
    state = admission['failedHistory']
    expected_pass = 0 if reserved is None else 1
    if (state['failed'] or state['passes'] != expected_pass or
            (reserved is not None and reserved != (
                '0062' if COMPILER_NATIVE_INPUTS_HISTORY_ONLY else
                final_action_number() if not DRAFT_ONLY else '0057'))):
        fail('Failed-history checkpoint is missing, repeated or reordered')
    # Latch before I/O. An interrupted or rejected pass cannot obtain a retry.
    state['failed'] = True
    state['passes'] += 1
    began = time.monotonic()
    end = min(deadline, began + state['remainingSeconds'])
    try:
        budget(end, cancelled)
        if expected_pass == 0:
            metadata = failed_metadata(state, end, cancelled)
        raw, identities = failed_content(state, end, cancelled)
        if expected_pass == 1:
            metadata = failed_metadata(state, end, cancelled)
        snapshot = (metadata, identities, raw)
        if expected_pass == 0:
            state['snapshot'] = snapshot
        elif snapshot != state['snapshot']:
            fail('Failed-history continuity changed across the original final action')
        start, result = decode(raw['wslStarted']), decode(raw['wslResult'])
        if raw['wslStarted'] != raw['windowsStarted']:
            fail('Original failed-history start pair changed')
        if compact({key: result.get(key) for key in FAILED_GUARD_RESULT_FLAGS}) != compact(FAILED_GUARD_RESULT_FLAGS):
            fail('Original failed result flags changed')
        if decode(raw['windowsInput']) != {'sha256': FAILED_GUARD_CONTENT['wslStarted']['sha256']}:
            fail('Original failed Windows-input join changed')
        if (start.get('action') != 'final-guard-prepare' or
                compact(start.get('priorCounters')) != compact({'linux': [8, 37, 0, 0], 'windows': [5, 48, 0, 48]}) or
                start.get('handoffSha256') != ORIGINAL_HISTORY_JOINS['handoffManifest']['sha256']):
            fail('Original failed preparation identity or prior counters changed')
        for key, expected in (('preparationCharge', 1), ('buildTestCharge', 0),
                              ('publishCharge', 0), ('reservedProcessScenarios', 0)):
            if type(start.get(key)) is not int or start[key] != expected:
                fail('Original failed preparation charge changed')
        budget(end, cancelled)
        state['failed'] = False
        return {'kind': 'disposed-failed-0054', 'started': start,
                'charge': [FAILED_GUARD_CHARGE[key] for key in
                           ('preparation', 'buildTest', 'publish', 'syntheticProcessScenarios')]}
    finally:
        # Only active verification time is charged here; the same original outer
        # deadline covers the entire gap. Neither checkpoint receives 30 seconds.
        state['remainingSeconds'] -= time.monotonic() - began
        if state['remainingSeconds'] <= 0:
            state['failed'] = True
            raise TimeoutError('Shared failed-history verification time exhausted')
        budget(deadline, cancelled)


def refresh_history(admission, deadline, cancelled, reserved=None):
    envelope, evidence = admission['envelope'], admission['evidence']
    manifest = evidence['handoff']
    keys(manifest, ('schema', 'source', 'histories', 'recomputedCounters', 'knownEndpoints', 'guardAction'))
    if (manifest['schema'] != 'final-publish-after-guard-handoff-v2' or manifest['source'] != PRODUCT or
            manifest['guardAction'] != envelope['acceptedGuard']['actionNumber']):
        fail('After-guard immutable handoff identity changed')
    expected = {'schema': 'final-publish-handoff-acceptance-v1', 'accepted': True,
                'handoff': envelope['handoff'], 'originalDispositionsPreserved': True,
                'completePairedHistoryAccepted': True, 'guardAcceptance': envelope['guardAcceptance']}
    if evidence['handoffAcceptance'] != expected:
        fail('Independent immutable original-history handoff acceptance missing')
    keys(manifest['histories'], ('linux', 'windows'))
    keys(manifest['recomputedCounters'], ('linux', 'windows'))
    for platform, pin in ORIGINAL_HISTORY_PREFIX.items():
        entries = manifest['histories'][platform]
        expected_length = pin['entries'] + (3 if platform == 'windows' else 0)
        if (type(entries) is not list or len(entries) != expected_length or
                any(type(item) is not dict for item in entries) or
                sha(compact(entries[:pin['entries']])) != pin['compactSha256']):
            fail('Original accepted M53 prefix or exact successor suffix changed')
    failed_entry, successful_entry, observer_entry = manifest['histories']['windows'][-3:]
    keys(failed_entry, ('number', 'failedGuardDisposition'))
    if (failed_entry['number'] != '0054' or successful_entry.get('number') != '0055' or
            manifest['guardAction'] != '0055' or
            compact(failed_entry['failedGuardDisposition']) != compact(
                admission['callerProvenance']['successorHistory']['failedGuardDisposition'])):
        fail('Exact failed 0054 and successful 0055 handoff join changed')
    keys(observer_entry, ('number', 'failedObserverDisposition'))
    if (observer_entry['number'] != '0056' or
            observer_entry['failedObserverDisposition'] != CORE_CSC_FAILED_DISPOSITION):
        fail('Exact failed 0056 handoff disposition changed')
    totals = {'linux': [0, 0, 0, 0], 'windows': [0, 0, 0, 0]}
    starts = []
    endpoints = []
    for platform in ('linux', 'windows'):
        entries = manifest['histories'][platform]
        if type(entries) is not list or not 1 <= len(entries) <= 9998:
            fail('Missing or unbounded original history')
        base = LINUX / 'actions' if platform == 'linux' else HISTORY
        actual = names(base, deadline, cancelled)
        expected_numbers = [x.get('number') for x in entries]
        if platform == 'windows' and COMPILER_NATIVE_INPUTS_HISTORY_ONLY:
            # Retained parents only: never add 0060/0061 to receipt traversal.
            expected_numbers.extend(('0060', '0061'))
        elif platform == 'windows' and not DRAFT_ONLY:
            # Separate checks use 0062's reservation and the accepted 0063 copy.
            # Other successor children remain outside the historical receipt loop.
            expected_numbers.extend(FINAL_RETAINED_SUCCESSORS)
        if platform == 'windows' and reserved is not None:
            expected_numbers.append(reserved)
        if actual != expected_numbers:
            fail('New or missing action requires a fresh independent handoff')
        if platform == 'windows' and names(PROJECTION / 'actions', deadline, cancelled) != actual:
            fail('Original Windows/WSL reservation directories disagree')
        for item in entries:
            budget(deadline, cancelled)
            if platform == 'windows' and item['number'] == '0054':
                if compact(totals) != compact({'linux': [8, 37, 0, 0], 'windows': [5, 48, 0, 48]}):
                    fail('Original M53 charges changed before disposed 0054')
                failed = verify_failed_handoff(admission, deadline, cancelled, reserved)
                totals[platform] = [a + b for a, b in zip(totals[platform], failed['charge'])]
                starts.append(failed['started'])
                continue
            if platform == 'windows' and item['number'] == '0056':
                if totals != {'linux': [8, 37, 0, 0], 'windows': [7, 48, 0, 48]}:
                    fail('Original post-0055 charges changed before disposed 0056')
                start, _original_result = verify_disposed_core_csc_observer(
                    admission.setdefault('failedObserverHistory', {}), deadline, cancelled)
                totals[platform][1] += 1
                starts.append(start)
                endpoints.append(string(start['endpoint'], '[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}'))
                continue
            keys(item, ('number', 'localEntryNames', 'localFiles', 'windowsFiles', 'safetyMarkers'))
            local = base / item['number']
            if CORE_CSC_HISTORY_ONLY or COMPILER_NATIVE_INPUTS_HISTORY_ONLY or not DRAFT_ONLY:
                observed_names = core_csc_names(local, len(item['localEntryNames']), deadline, cancelled)
            else:
                observed_names = sorted(p.name for p in direct(local).iterdir())
            if observed_names != item['localEntryNames']:
                fail('Original receipt inventory changed')
            for field, directory in (('localFiles', local), ('windowsFiles', PROJECTION / 'actions' / item['number'])):
                if type(item[field]) is not dict or len(item[field]) > 20000:
                    fail('Invalid original evidence map')
                if platform == 'linux' and field == 'windowsFiles' and item[field]:
                    fail('Linux action contains Windows evidence')
                for path, expected_hash in item[field].items():
                    if sha(read(directory / relative(path), deadline, cancelled)) != digest(expected_hash):
                        fail('Original evidence bytes changed')
            if 'started.json' not in item['localFiles']:
                fail('Original durable charge absent')
            start = decode(read(local / 'started.json', deadline, cancelled))
            if platform == 'windows' and item['number'] == '0055':
                if (start.get('action') != 'final-guard-prepare' or
                        compact(start.get('priorCounters')) != compact(
                            {'linux': [8, 37, 0, 0], 'windows': [6, 48, 0, 48]})):
                    fail('Successful 0055 does not follow exact disposed 0054')
            charge = classify(platform, start)
            totals[platform] = [a + b for a, b in zip(totals[platform], charge)]
            if 'endpoint' in start:
                endpoint = string(start['endpoint'], '[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}')
                endpoints.append(endpoint)
            if platform == 'windows':
                starts.append(start)
                keys(item['safetyMarkers'], ('owned-host-safety-stop.json', 'process-safety-stop.json'))
                for marker, expected_hash in item['safetyMarkers'].items():
                    path = PROJECTION / 'actions' / item['number'] / 'temp' / marker
                    if expected_hash is None:
                        if path.exists() or path.is_symlink():
                            fail('Unadmitted process safety marker')
                    elif sha(read(path, deadline, cancelled)) != digest(expected_hash):
                        fail('Original safety disposition changed')
    if totals != manifest['recomputedCounters'] or sorted(endpoints) != manifest['knownEndpoints'] or len(endpoints) != len(set(endpoints)):
        fail('Original counters or endpoint history mismatch')
    if (sum(s['action'] == 'final-guard-prepare' for s in starts) != 2 or
            sum(s['action'] == 'core-csc-observer' for s in starts) != 1 or
            starts[-1]['action'] != 'core-csc-observer' or
            successful_entry['number'] != manifest['guardAction']):
        fail('Publication requires disposed 0054, original successful 0055 and disposed 0056')
    if sum(s['action'] == 'bootstrap' for s in starts) != 1 or sum(s['action'] == 'restore' for s in starts) != 4:
        fail('Original five bootstrap/restore actions changed')
    lp, lb, lpub, ls = totals['linux']
    wp, wb, wpub, ws = totals['windows']
    if (compact(totals) != compact({'linux': [8, 37, 0, 0], 'windows': [7, 49, 0, 48]}) or
            lp > 9 or wp != 7 or lp + wp > 16 or lb > 79 or wb > 49 or lb + wb + 1 > 120 or
            lpub != 0 or wpub != 0 or ls != 0 or ws != 48 or wpub + 1 > 12):
        fail('After-guard cumulative allocation differs from the accepted publication-only slot')
    if not DRAFT_ONLY:
        verify_final_successors(admission, totals, deadline, cancelled, reserved)
    # Exact original guard evidence is joined to the thirteen-field projection.
    guard = envelope['acceptedGuard']
    owned = PROJECTION / 'actions' / guard['actionNumber']
    local = HISTORY / guard['actionNumber']
    paths = {'started.json': 'preparationReservationSha256', 'invocation.json': 'invocationSha256',
             'compiler.json': 'compilerReceiptSha256', 'windows-result.json': 'preparationWindowsResultSha256',
             'guard-build.json': 'guardBuildSha256', 'final-guard/source/WindowsValidationJob.cs': 'sourceSha256',
             'final-guard/WindowsFinalPublishGuard.dll': 'dllSha256'}
    for path, field in paths.items():
        if sha(read(owned / path, deadline, cancelled)) != guard[field]:
            fail('Original guard artifact or completion binding changed')
    if sha(read(local / 'result.json', deadline, cancelled)) != guard['preparationWslResultSha256']:
        fail('Original guard WSL completion changed')
    if successful_entry['windowsFiles'].get('final-guard/artifact-acceptance.json') != guard['artifactAcceptanceSha256']:
        fail('Original artifact acceptance copy is absent from the admitted handoff')
    artifact_copy = read(projection(guard['artifactAcceptancePath']), deadline, cancelled, CALLER_PROVENANCE_LIMIT)
    if (sha(artifact_copy) != guard['artifactAcceptanceSha256'] or
            artifact_copy != admission['callerProvenance']['artifactAcceptanceBytes']):
        fail('Independent actual guard artifact acceptance changed')
    return totals, manifest


_CORE_CSC_STARTED = False
_CORE_CSC_READS = 0
_CORE_CSC_REQUESTED_BYTES = 0
_CORE_CSC_CLOCK = None
CORE_CSC_INPUTS = {
    'handoff': {'path': '/tmp/windows-final-publish-0055-completed-handoff-collector-v1.json',
                'bytes': 174955, 'sha256': '622c8835b7af93ddfcda4a0a5f8f17881eeff631e94b247e336d83c1b0e63710'},
    'handoffAcceptance': {'path': '/tmp/windows-final-publish-0055-handoff-acceptance-root-v1.json',
                          'bytes': 351, 'sha256': '101bdb6a6fb4c1cd8059887966bbc7f970c0a10a209fbc91c1bb044dbb033ad0'},
    'guardAcceptance': {'path': '/tmp/windows-final-publish-0055-guard-acceptance-candidate-wave-v1.json',
                        'bytes': 1346, 'sha256': '35eed91b45c1f49f5f2b7f2d5a90ea61ff82fa37cebf4150353227e77b66a018'},
    'artifactAcceptance': {'path': '/tmp/windows-final-guard-0055-authority-inputs/managed-artifact-acceptance.json',
                           'bytes': 1886, 'sha256': 'c118cc8b9ca6deb0685162177b9940c94a453ad3e87f39cdd2f88ffe6eacf55d'},
}

COMPILER_NATIVE_INPUTS_INPUTS = {
    'handoff': {'path': '/tmp/windows-final-publish-0056-disposed-handoff-root-v1.json',
                'bytes': 211842, 'sha256': 'fe13f88846f537825049dface75869cccad84f6df3bc2a748968a466c8443ba6'},
    'handoffAcceptance': {'path': '/tmp/windows-final-publish-0056-handoff-acceptance-candidate-wave-v1.json',
                          'bytes': 351, 'sha256': '8f06a719b4e2b586187fb9e5e2abc6763e2c35cb998ac7a6c976eefc4f87ed45'},
    'guardAcceptance': CORE_CSC_INPUTS['guardAcceptance'],
    'artifactAcceptance': CORE_CSC_INPUTS['artifactAcceptance'],
}

# These additions are independently accepted outside the historical paired
# ledger. Keep the original handoff bytes and its counters unchanged.
COMPILER_NATIVE_INPUTS_PRIOR_CAPACITY = {
    'recordedCombinedBuildTest': 87, 'recordedSynthetic': 48,
    'original0057UnavailableBuildTest': 1,
    'original0058FailedBuildTest': 1,
    'original0059FailedBuildTest': 1,
    'original0060FailedBuildTest': 1,
    'original0061FailedBuildTest': 1,
    'systemdBuildTest': 1, 'systemdSynthetic': 4,
    'systemdObservationCommit': 'a1492ce0f65f4ca0acaf04be6ffab72f445dfe20',
    'combinedBuildTest': 93, 'synthetic': 52,
    'additionalDiagnosticBuildTest': 1, 'additionalDiagnosticSynthetic': 0,
    'afterCombinedBuildTest': 94, 'afterSynthetic': 52,
}

# Fixed post-0056 dispositions supplement, rather than rewrite, the accepted
# paired handoff. Unavailable starts stay consumed without fabricated entries.
FINAL_CHARGED_SUCCESSORS = ('0057', '0058', '0059', '0060', '0061', '0062')
FINAL_FAILED_PUBLICATIONS = ('0063',)
FINAL_RETAINED_SUCCESSORS = ('0060', '0061', '0062', '0063')
FINAL_0062_RESERVATION = {
    'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0062/started.json',
    'sha256': '40012f4e1fd3bd1ba0d01431c7a600b7d89516b7f3e42dfeb8960c57f4b9779c',
}
FINAL_0063_RESERVATION_COPY = {
    'path': '/tmp/windows-final-publish0063-failure-observation-root-v1/wsl-started.json.bin',
    'bytes': 833,
    'sha256': 'bfacbbf1c4b103dc95bfbe9f5335a9eec13143178bbb348585322a01674b0a52',
}


def final_action_number():
    return f'{56 + len(FINAL_CHARGED_SUCCESSORS) + len(FINAL_FAILED_PUBLICATIONS) + 1:04d}'


def read_failed_final_reservation_copy(totals, previous_endpoints, deadline, cancelled):
    """Read only the sealed accepted copy, never original failed 0063 state."""
    pin = FINAL_0063_RESERVATION_COPY
    parent, leaf = failed_parent(pin['path'], deadline, cancelled)
    fd = None
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o400 or
                before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_size != pin['bytes']):
            fail('Accepted failed-publication copy shape changed')
        budget(deadline, cancelled)
        raw = os.read(fd, pin['bytes'] + 1)
        after = os.fstat(fd)
        current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        identities = [(failed_identity(info), info.st_uid, info.st_gid)
                      for info in (before, after, current)]
        if (len(raw) != pin['bytes'] or sha(raw) != pin['sha256'] or
                identities[0] != identities[1] or identities[1] != identities[2]):
            fail('Accepted failed-publication copy bytes or identity changed')
        start = decode(raw, canonical=True)
        if (start.get('schema') != 'final-publish-reservation-v1' or
                start.get('action') != 'final-publish' or start.get('number') != '0063' or
                start.get('source') != PRODUCT['commit'] or start.get('sourceTree') != PRODUCT['tree'] or
                start.get('protocol') != '12505bde79e9db09a19a6861f7a0693747741089' or
                start.get('authoritySha256') != '0dd69881dbce65ac3597d523101a08108553cd820ba8716dfd7878212bddfeb2' or
                start.get('handoffSha256') != COMPILER_NATIVE_INPUTS_INPUTS['handoff']['sha256'] or
                compact(start.get('priorCounters')) != compact(totals) or
                compact([start.get(k) for k in ('preparationCharge', 'buildTestCharge',
                    'publishCharge', 'reservedProcessScenarios')]) != compact([0, 0, 1, 0]) or
                start.get('originalOuterLimitMilliseconds') != 700000):
            fail('Accepted failed-publication reservation scope changed')
        endpoint = string(start.get('endpoint'), '[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}')
        if endpoint in previous_endpoints:
            fail('Accepted failed-publication endpoint collides with prior history')
        budget(deadline, cancelled)
        return (identities[1], raw), endpoint
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def verify_final_successors(admission, totals, deadline, cancelled, reserved):
    """Two checks of the diagnostic reservation and sealed failed-final copy."""
    state = admission.setdefault('finalSuccessors', {
        'passes': 0, 'remainingSeconds': 30.0, 'snapshot': None, 'failed': False})
    expected_pass = 0 if reserved is None else 1
    if (DRAFT_ONLY or CORE_CSC_HISTORY_ONLY or COMPILER_NATIVE_INPUTS_HISTORY_ONLY or
            state['failed'] or state['passes'] != expected_pass or
            (reserved is not None and reserved != final_action_number())):
        fail('Final successor checkpoint is missing, repeated or reordered')
    state['failed'] = True
    state['passes'] += 1
    began = time.monotonic()
    end = min(deadline, began + state['remainingSeconds'])
    parent = fd = None
    try:
        for role in ('handoff', 'handoffAcceptance'):
            pin = COMPILER_NATIVE_INPUTS_INPUTS[role]
            raw = admission['evidenceBytes'][role]
            if len(raw) != pin['bytes'] or sha(raw) != pin['sha256']:
                fail('Final publication must retain the exact post-0056 handoff')
        combined = sum(totals[p][1] for p in ('linux', 'windows')) + 1
        combined += len(FINAL_CHARGED_SUCCESSORS) + 1  # Accepted systemd batch.
        synthetic = sum(totals[p][3] for p in ('linux', 'windows')) + 4
        publication = sum(totals[p][2] for p in ('linux', 'windows')) + len(FINAL_FAILED_PUBLICATIONS)
        if (combined != 94 or synthetic != 52 or combined > LIMITS['buildTest'] or
                synthetic + 12 + 16 != LIMITS['synthetic'] or
                sum(totals[p][0] for p in ('linux', 'windows')) != 15 or
                sum(totals[p][2] for p in ('linux', 'windows')) != 0 or
                publication != 1 or publication + 1 > LIMITS['publish']):
            fail('Current final publication capacity changed')
        parent, leaf = failed_parent(FINAL_0062_RESERVATION['path'], end, cancelled)
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= 1048576:
            fail('Original 0062 reservation kind or size changed')
        budget(end, cancelled)
        # Exactly one size+1 request per pass: no buffered refill or retry.
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if (len(raw) != before.st_size or sha(raw) != FINAL_0062_RESERVATION['sha256'] or
                failed_identity(before) != failed_identity(after) or
                failed_identity(after) != failed_identity(current)):
            fail('Original 0062 reservation bytes or identity changed')
        snapshot = (failed_identity(after), raw)
        start = decode(raw, canonical=True)
        if (start.get('schema') != 'compiler-native-inputs-reservation-v1' or
                start.get('action') != 'compiler-native-inputs' or start.get('number') != '0062' or
                start.get('source') != PRODUCT['commit'] or start.get('sourceTree') != PRODUCT['tree'] or
                start.get('handoffSha256') != COMPILER_NATIVE_INPUTS_INPUTS['handoff']['sha256'] or
                compact(start.get('priorCounters')) != compact(totals) or
                compact(start.get('priorCapacity')) != compact(COMPILER_NATIVE_INPUTS_PRIOR_CAPACITY) or
                compact([start.get(k) for k in ('preparationCharge', 'buildTestCharge',
                    'publishCharge', 'reservedProcessScenarios')]) != compact([0, 1, 0, 0]) or
                start.get('originalOuterLimitMilliseconds') != 900000):
            fail('Original 0062 reservation scope or charge changed')
        first = integer(start.get('originalClockStartNanoseconds'), 1)
        last = integer(start.get('originalClockDeadlineNanoseconds'), 1)
        if last - first != 900000000000:
            fail('Original 0062 clock binding changed')
        endpoint = string(start.get('endpoint'), '[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}')
        if endpoint in admission['evidence']['handoff']['knownEndpoints']:
            fail('Original 0062 endpoint collides with accepted history')
        failed_snapshot, failed_endpoint = read_failed_final_reservation_copy(
            totals, [*admission['evidence']['handoff']['knownEndpoints'], endpoint], end, cancelled)
        snapshot = (snapshot, failed_snapshot)
        if expected_pass == 1 and snapshot != state['snapshot']:
            fail('Final predecessor reservation continuity changed')
        state['snapshot'], state['endpoints'] = snapshot, (endpoint, failed_endpoint)
        budget(end, cancelled)
        state['failed'] = False
    finally:
        try:
            if fd is not None:
                os.close(fd)
            if parent is not None:
                os.close(parent)
            state['remainingSeconds'] -= time.monotonic() - began
            if state['remainingSeconds'] <= 0:
                raise TimeoutError('Shared final successor verification time exhausted')
            budget(deadline, cancelled)
        except BaseException:
            state['failed'] = True
            raise


def _observer_history_inputs(compiler_native_inputs):
    """Select exactly one admitted history mode; this does not activate either."""
    if (type(compiler_native_inputs) is not bool or not DRAFT_ONLY or
            (compiler_native_inputs and
             (not COMPILER_NATIVE_INPUTS_HISTORY_ONLY or CORE_CSC_HISTORY_ONLY)) or
            (not compiler_native_inputs and
             (not CORE_CSC_HISTORY_ONLY or COMPILER_NATIVE_INPUTS_HISTORY_ONLY))):
        fail('Observer history mode is disabled or mismatched')
    return COMPILER_NATIVE_INPUTS_INPUTS if compiler_native_inputs else CORE_CSC_INPUTS


def core_csc_charge_read(requested):
    """One finite allowance across both original-history checkpoints."""
    global _CORE_CSC_READS, _CORE_CSC_REQUESTED_BYTES
    if (CORE_CSC_HISTORY_ONLY == COMPILER_NATIVE_INPUTS_HISTORY_ONLY or
            not DRAFT_ONLY or not _CORE_CSC_STARTED):
        fail('Unadmitted observer history use')
    _CORE_CSC_READS += 1
    _CORE_CSC_REQUESTED_BYTES += requested
    if _CORE_CSC_READS > 4096 or _CORE_CSC_REQUESTED_BYTES > 268435456:
        fail('Observer history read allowance exhausted')


def core_csc_names(path, maximum, deadline=None, cancelled=None):
    if deadline is None:
        deadline, cancelled = _CORE_CSC_CLOCK
    result = []
    # scandir yields entries incrementally; Path.iterdir may materialize a list.
    with os.scandir(direct(path)) as entries:
        while True:
            budget(deadline, cancelled)
            entry = next(entries, None)
            if entry is None:
                break
            result.append(entry.name)
            if len(result) > maximum:
                fail('Observer original history entry-count bound exceeded')
    return sorted(result)


def load_core_csc_history(authority, deadline, cancelled, *, compiler_native_inputs=False):
    # The independently admitted external literal binds the entire authority.
    # Loading only its history inputs cannot waive the final publication gates.
    inputs = _observer_history_inputs(compiler_native_inputs)
    if (authority.get('active') is not True or
            authority['historyAdapter']['sha256'] != globals().get('__accepted_source_sha256__')):
        fail('Observer-only captured source or literal authority missing')
    pin = authority['observerHistory']
    path = provenance_descriptor(pin)
    data = bound({k: pin[k] for k in ('bytes', 'sha256')}, path, deadline, cancelled, 1048576)
    config = decode(data, canonical=True)
    fields = ('schema', 'target', 'protocol', 'wave', 'product', 'rootMarkers')
    keys(config, (*fields, 'priorCapacity') if compiler_native_inputs else fields)
    if compiler_native_inputs and compact(config['priorCapacity']) != compact(COMPILER_NATIVE_INPUTS_PRIOR_CAPACITY):
        fail('Original unavailable/failed units or separately accepted systemd consumption changed')
    schema = ('compiler-native-inputs-history-inputs-v2' if compiler_native_inputs
              else 'core-csc-observer-history-inputs-v1')
    if config['schema'] != schema or config['product'] != PRODUCT:
        fail('Observer history scope changed')
    verify_revision(config['target'], deadline, cancelled)
    keys(config['protocol'], ('commit', 'tree', 'gitBlob', 'bytes', 'sha256'))
    if any(config['protocol'][k] != config['target'][k] for k in ('commit', 'tree')):
        fail('Observer requires the current accepted protocol revision')
    verify_blob(config['target'], PROTOCOL,
                {k: config['protocol'][k] for k in ('gitBlob', 'bytes', 'sha256')}, deadline, cancelled)
    verify_blob(config['target'], 'docs/delivery-wave.md', config['wave'], deadline, cancelled)
    evidence, raw = {}, {}
    for role, fixed in inputs.items():
        raw[role] = bound({k: fixed[k] for k in ('bytes', 'sha256')},
                          Path(fixed['path']), deadline, cancelled, 1048576)
        # The compiler handoff's exact accepted bytes use indented JSON.
        # Its hash and strict decoder bind the content without rewriting it.
        canonical = role != 'artifactAcceptance' and not (compiler_native_inputs and role == 'handoff')
        evidence[role] = decode(raw[role], canonical=canonical)
    guard_review = evidence['guardAcceptance']
    guard = guard_review['acceptedGuard']
    verify_guard(guard)
    if guard_review != {'schema': 'final-publish-guard-acceptance-v1', 'accepted': True,
                         'acceptedGuard': guard, 'originalPairedCompletionAccepted': True,
                         'managedGuardArtifactAccepted': True, 'finalNoKillModeAccepted': True}:
        fail('Original guard acceptance changed')
    envelope = dict(config, acceptedGuard=guard)
    for role in ('handoff', 'guardAcceptance'):
        envelope[role] = {k: inputs[role][k] for k in ('bytes', 'sha256')}
    keys(config['rootMarkers'], ('linuxOwnerSha256', 'windowsOwnerSha256'))
    for root, key in ((LINUX, 'linuxOwnerSha256'), (PROJECTION, 'windowsOwnerSha256')):
        marker = read(root / 'owner.json', deadline, cancelled, 4096)
        if sha(marker) != digest(config['rootMarkers'][key]) or decode(marker) != ROOT_MARKER:
            fail('Observer original root ownership changed')
    assert_target_current(envelope, deadline, cancelled)
    return {'envelope': envelope, 'evidence': evidence,
            'callerProvenance': {'successorHistory': ORIGINAL_HISTORY_JOINS,
                                 'artifactAcceptanceBytes': raw['artifactAcceptance']},
            'failedHistory': {'passes': 0, 'reads': 0, 'requestedBytes': 0,
                              'metadataProbes': 0, 'remainingSeconds': 30.0,
                              'snapshot': None, 'failed': False}}


class CoreCscLockLease:
    """The dispatcher owns this lease until its local finalization attempt ends."""
    def __init__(self, fd):
        self.fd = fd

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)


def _reserve_core_csc_observer(authority, original_start_ns, original_deadline_ns, cancelled,
                               *, compiler_native_inputs=False):
    global _CORE_CSC_STARTED, _CORE_CSC_CLOCK
    inputs = _observer_history_inputs(compiler_native_inputs)
    action_kind = 'compiler-native-inputs' if compiler_native_inputs else 'core-csc-observer'
    limit_ms = 900000 if compiler_native_inputs else 180000
    if _CORE_CSC_STARTED:
        fail('Observer reservation is disabled or already attempted')
    _CORE_CSC_STARTED = True
    integer(original_start_ns, 1)
    if original_deadline_ns != original_start_ns + limit_ms * 1_000_000:
        fail('Observer original clock changed')
    deadline = original_deadline_ns / 1_000_000_000
    _CORE_CSC_CLOCK = (deadline, cancelled)
    budget(deadline, cancelled)
    admission = load_core_csc_history(authority, deadline, cancelled,
                                      compiler_native_inputs=compiler_native_inputs)
    fd = os.open(direct(LINUX / 'action.lock'), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    lease = CoreCscLockLease(fd)
    local = owned = None
    started = None
    returned = False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            fail('Observer shared lock is not a regular file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        totals, manifest = refresh_history(admission, deadline, cancelled)
        prior_windows = [7, 49, 0, 48] if compiler_native_inputs else [7, 48, 0, 48]
        if totals != {'linux': [8, 37, 0, 0], 'windows': prior_windows}:
            fail('Observer prior allocation changed')
        # The paired historical ledger stays at 87 including its fixture once.
        # Originals 0057/0058/0059/0060/0061 and the systemd batch add one unit each;
        # this additional diagnostic adds a seventh. Historical charges stay fixed.
        linux_ceiling = 73 if compiler_native_inputs else 79
        windows_ceiling = 55 if compiler_native_inputs else 49
        unavailable = 5 if compiler_native_inputs else 0
        external_batch = 1 if compiler_native_inputs else 0
        combined = totals['linux'][1] + totals['windows'][1] + 1 + unavailable + external_batch + 1
        if (totals['linux'][1] > linux_ceiling or
                totals['windows'][1] + unavailable + 1 > windows_ceiling or combined > 120 or
                (compiler_native_inputs and combined != 94)):
            fail('Observer and existing fixture exceed combined allocation')
        number = f"{len(manifest['histories']['windows']) + unavailable + 1:04d}"
        if number != ('0062' if compiler_native_inputs else '0056'):
            fail('Original handoff changed; no observer reservation')
        local, owned = direct(HISTORY / number), direct(PROJECTION / 'actions' / number)
        if local.exists() or owned.exists():
            fail('Observer slot already exists; no retry or refund')
        endpoint = uuid.uuid4().hex
        if endpoint in manifest['knownEndpoints']:
            fail('Observer endpoint collision; no retry')
        nonce = os.urandom(32).hex()
        assert_target_current(admission['envelope'], deadline, cancelled)
        budget(deadline, cancelled)
        started = {'schema': action_kind + '-reservation-v1', 'action': action_kind,
                   'number': number, 'source': PRODUCT['commit'], 'sourceTree': PRODUCT['tree'],
                   'protocol': admission['envelope']['protocol']['commit'],
                   'waveBlob': admission['envelope']['wave']['gitBlob'],
                   'handoffSha256': inputs['handoff']['sha256'],
                   'priorCounters': totals, 'preparationCharge': 0, 'buildTestCharge': 1,
                   'publishCharge': 0, 'reservedProcessScenarios': 0,
                   'originalClockStartNanoseconds': original_start_ns,
                   'originalClockDeadlineNanoseconds': original_deadline_ns,
                   'originalOuterLimitMilliseconds': limit_ms, 'clockNonce': nonce,
                   'endpoint': endpoint, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        if compiler_native_inputs:
            started['priorCapacity'] = COMPILER_NATIVE_INPUTS_PRIOR_CAPACITY
        local.mkdir(mode=0o700)
        raw = compact(started)
        write_new(local / 'started.json', raw)
        # All failures after the durable start consume the sole dedicated unit.
        # A directory or partial start also blocks every subsequent history read.
        owned.mkdir()
        write_new(owned / 'started.json', raw)
        write_new(local / 'windows-input.json', compact({'sha256': sha(raw)}))
        budget(deadline, cancelled)
        returned = True
        return {'started': started, 'lockLease': lease, 'windowsActionPosix': str(owned),
                'wslActionPath': str(local), 'admission': admission, 'cancelled': cancelled,
                'originalValidated': False,
                'invocation': {'actionNumber': number, 'actionPath': WINDOWS + '\\actions\\' + number,
                               'packageRoot': WINDOWS + '\\packages', 'endpoint': endpoint,
                               'reservationSha256': sha(raw)}}
    except BaseException as error:
        if local is not None and local.exists():
            write_new(local / 'reservation-failure.json', compact({
                'schema': action_kind + '-reservation-failure-v1',
                'failureType': type(error).__name__, 'normalCompletion': False,
                'graphAccepted': False, 'artifactAccepted': False, 'continuation_allowed': False,
                'safetyStop': True, 'retainedLiveWorkOrUnknown': True}))
        raise
    finally:
        if not returned:
            lease.close()


def _validate_core_csc_observer_original(authority, reservation, invocation, clock,
                                        original_proxy_exit, original_deadline_ns,
                                        *, compiler_native_inputs=False):
    """Join the completed original proxy to a provisional Windows observation."""
    inputs = _observer_history_inputs(compiler_native_inputs)
    action_kind = 'compiler-native-inputs' if compiler_native_inputs else 'core-csc-observer'
    limit_ms = 900000 if compiler_native_inputs else 180000
    capture_limit = 8388608 if compiler_native_inputs else 4194304
    if (reservation['originalValidated'] or
            reservation['lockLease'].fd is None or type(original_proxy_exit) is not int or
            original_proxy_exit != 0):
        fail('Original observer proxy is incomplete or already consumed')
    reservation['originalValidated'] = True
    started = reservation['started']
    if (original_deadline_ns != started['originalClockDeadlineNanoseconds'] or
            original_deadline_ns != started['originalClockStartNanoseconds'] + limit_ms * 1_000_000 or
            started['originalOuterLimitMilliseconds'] != limit_ms or
            started['action'] != action_kind or
            started['number'] != ('0062' if compiler_native_inputs else '0056') or
            started['handoffSha256'] != inputs['handoff']['sha256'] or
            invocation['actionKind'] != action_kind or
            invocation['originalOuterLimitMilliseconds'] != limit_ms):
        fail('Observer validation reset the original deadline or changed history mode')
    if compiler_native_inputs and compact(started.get('priorCapacity')) != compact(COMPILER_NATIVE_INPUTS_PRIOR_CAPACITY):
        fail('Observer lost the original unavailable unit or external batch consumption')
    deadline, cancelled = original_deadline_ns / 1_000_000_000, reservation['cancelled']
    budget(deadline, cancelled)
    number = reservation['started']['number']
    local, owned = HISTORY / number, PROJECTION / 'actions' / number
    if ((owned / 'cancel').exists() or (owned / 'cancel').is_symlink() or
            invocation['reservationSha256'] != sha(compact(reservation['started']))):
        fail('Observer cancelled or original start changed')
    for root in (local, owned):
        if (read(root / 'started.json', deadline, cancelled, 1048576) != compact(reservation['started']) or
                read(root / 'invocation.json', deadline, cancelled, 1048576) != compact(invocation)):
            fail('Observer original start or invocation pair changed')
    ready_raw = read(owned / 'clock-ready.json', deadline, cancelled, 2048)
    reply_raw = read(owned / 'clock-remaining.json', deadline, cancelled, 2048)
    if sha(ready_raw) != clock['readySha256'] or sha(reply_raw) != clock['replySha256']:
        fail('Observer original clock frames changed')
    proof = decode(read(owned / 'windows-result.json', deadline, cancelled, 1048576))
    fixed = {'actionKind': action_kind, 'action': number,
             'reservationSha256': invocation['reservationSha256'],
             'invocationSha256': sha(compact(invocation)),
             'normalCompletion': True, 'quiescent': True, 'captureCompleted': True,
             'naturalJobCompletion': True, 'startAttempted': True, 'startReturned': True,
             'stopCalled': True, 'stopReturned': True, 'disposeAttempted': True, 'disposeCompleted': True,
             'disposeKillOnClose': True, 'disposeConfirmsQuiescence': False,
             'expectedDiagnosticSeen': True, 'safetyStop': False, 'jobTerminationRequested': False,
             'jobTerminationSucceeded': False,
             'graphAccepted': False, 'artifactAccepted': False, 'continuation_allowed': False,
             'independentObservationAccepted': False, 'captureTruncated': False,
             'outcome': 'expected-stop-candidate-awaiting-independent-acceptance'}
    for key, expected in fixed.items():
        if compact(proof.get(key)) != compact(expected):
            fail('Incomplete or mismatched original observer result')
    if (type(proof.get('subjectExitCode')) is not int or proof['subjectExitCode'] == 0 or
            any('Failure' in key or key == 'failureType' for key in proof)):
        fail('Observer subject did not complete the intended failure path')
    integer(proof.get('remainingMilliseconds'), 1, limit_ms)
    integer(proof.get('windowsElapsedMilliseconds'), 0, limit_ms - 1)
    integer(proof.get('jobActive'), 0, 0)
    integer(proof.get('stdoutBytes'), 0, capture_limit)
    integer(proof.get('stderrBytes'), 0, capture_limit - proof['stdoutBytes'])
    absence_count = integer(len(authority['physicalAbsences']), 1, 256)
    membership_count = integer(len(authority['physicalMembership']), 1, 32)
    integer(proof.get('absenceChecks'), 2, 2)
    integer(proof.get('absenceMetadataProbes'), 4 * absence_count, 9216)
    integer(proof.get('membershipChecks'), 2, 2)
    integer(proof.get('membershipMetadataProbes'), 4 * membership_count, 2176)
    integer(proof.get('membershipEntries'), 0, 1024)
    directory_count = integer(proof.get('lastDirectoryCount'), 2, 128)
    if compact(proof.get('lastFileSample', {}).get('directoryCount')) != compact(directory_count):
        fail('Observer final directory count differs from the completed sample')
    if compact(proof.get('clock')) != compact(clock):
        fail('Observer receipt clock differs from original caller clock')
    expected_drain = {'processedRejectionThresholdBytes': 65536, 'processedBytes': 0,
                      'observedOverflowBytes': 0, 'possibleUnobservedInFlightBytes': 0,
                      'possibleBytesAreObserved': False, 'issuedOverflowAllowanceBytes': 8192,
                      'maximumReadEnvelopeBytes': 73728, 'observedPlusPossibleBytes': 0,
                      'overflowRejected': False}
    # A successful natural completion already observed EOF on both streams
    # before Stop. No emergency drain or unobserved pending read is consistent
    # with this narrowly accepted original receipt.
    if compact(proof.get('emergencyDrainReadAccounting')) != compact(expected_drain):
        fail('Observer successful receipt has inconsistent emergency-read accounting')
    # Capture/binlog semantic interpretation has its own independent admission.
    # This join deliberately does not decode output or grant continuation.
    refresh_history(reservation['admission'], deadline, cancelled, reserved=number)
    assert_target_current(reservation['admission']['envelope'], deadline, cancelled)
    budget(deadline, cancelled)
    return proof


def reserve_core_csc_observer(authority, original_start_ns, original_deadline_ns, cancelled):
    return _reserve_core_csc_observer(authority, original_start_ns, original_deadline_ns, cancelled)


def reserve_compiler_native_inputs(authority, original_start_ns, original_deadline_ns, cancelled):
    return _reserve_core_csc_observer(authority, original_start_ns, original_deadline_ns, cancelled,
                                      compiler_native_inputs=True)


def validate_core_csc_observer_original(authority, reservation, invocation, clock,
                                         original_proxy_exit, original_deadline_ns):
    return _validate_core_csc_observer_original(authority, reservation, invocation, clock,
                                               original_proxy_exit, original_deadline_ns)


def validate_compiler_native_inputs_original(authority, reservation, invocation, clock,
                                              original_proxy_exit, original_deadline_ns):
    # The exact admitted dispatcher first retains and validates complete original
    # bootstrap transport, its candidate frame, and zero original proxy exit.
    # This shared join checks original receipts; it cannot grant Csc semantics.
    return _validate_core_csc_observer_original(authority, reservation, invocation, clock,
                                               original_proxy_exit, original_deadline_ns,
                                               compiler_native_inputs=True)


def final_startup_inputs(owned, deadline, cancelled):
    """Check the fixed inputs created only after the final durable reservation."""
    budget(deadline, cancelled)
    for path in (owned, owned / 'home', owned / 'home/.dotnet', owned / 'home/msbuild-user'):
        info = direct(path).lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            fail('Final startup directory shape or ownership changed')
    # Do not materialize a directory listing: one entry is enough to reject it.
    with os.scandir(owned / 'home/msbuild-user') as entries:
        if next(entries, None) is not None:
            fail('Final MSBuild user-extension directory is not empty')
    sentinel = direct(owned / FINAL_FIRST_USE_SENTINEL).lstat()
    if (not stat.S_ISREG(sentinel.st_mode) or sentinel.st_size != 0 or
            sentinel.st_uid != os.getuid()):
        fail('Final first-use sentinel shape, ownership or empty contents changed')
    budget(deadline, cancelled)


@contextlib.contextmanager
def admitted_reservation(deadline, began, cancelled, *, reviewed_authority):
    admission = load_admission(deadline, cancelled, reviewed_authority=reviewed_authority)
    lock_path = direct(LINUX / 'action.lock')
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            fail('Original shared lock is not a regular file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        totals, manifest = refresh_publication_checkpoint(admission, deadline, cancelled)
        graph = admission['evidence']['graph']
        source_paths = git(['ls-tree', '-r', '--name-only', PRODUCT['commit'], '--', 'src', 'global.json'],
                           deadline, cancelled).decode('ascii').splitlines()
        if sorted(x['repositoryPath'] for x in graph['sourceInventory']) != source_paths:
            fail('Product source inventory is incomplete or duplicated')
        for item in graph['sourceInventory']:
            pin = {k: item[k] for k in ('gitBlob', 'bytes', 'sha256')}
            data = verify_blob(PRODUCT, item['repositoryPath'], pin, deadline, cancelled)
            path = projection(graph['sourceRoot']) / item['repositoryPath']
            if read(path, deadline, cancelled) != data:
                fail('Materialized final product source changed')
        for item in graph['protectedInputs']:
            hash_protected(item, deadline, cancelled)
        for path in graph['absentInputs']:
            actual = direct(projection(path))
            if actual.exists():
                fail('Unexpected ambient source/import input')
        assert_target_current(admission['envelope'], deadline, cancelled)
        budget(deadline, cancelled)
        number = manifest['nextAction']
        local = direct(HISTORY / number)
        owned = direct(PROJECTION / 'actions' / number)
        if local.exists() or owned.exists():
            fail('Final publication reservation already exists')
        refresh_publication_provenance(admission, deadline, cancelled)
        # One UUIDv4 call, only here under the original shared lock. A collision
        # rejects this reservation; it does not generate a replacement nonce.
        endpoint = uuid.uuid4().hex
        string(endpoint, '[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}')
        if (endpoint == '0' * 32 or endpoint in manifest['knownEndpoints']):
            fail('Endpoint collision; no retry')
        envelope = admission['envelope']
        start = {'schema': 'final-publish-reservation-v2', 'action': 'final-publish', 'number': number,
                 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 'source': PRODUCT['commit'], 'sourceTree': PRODUCT['tree'],
                 'protocol': envelope['protocol']['commit'], 'waveBlob': envelope['wave']['gitBlob'],
                 'authoritySha256': sha(admission['authorityBytes']), 'handoffSha256': envelope['handoff']['sha256'],
                 'guardAcceptanceSha256': envelope['guardAcceptance']['sha256'], 'priorCounters': totals,
                 'preparationCharge': 0, 'buildTestCharge': 0, 'publishCharge': 1, 'reservedProcessScenarios': 1,
                 'endpoint': endpoint, 'originalOuterLimitMilliseconds': LIMITS['outerMilliseconds']}
        local.mkdir(mode=0o700)
        write_new(local / 'started.json', compact(start), deadline=deadline)
        # From this point any failure retains the original charge. Never remove,
        # rewrite or refund the start record; an incomplete pair blocks all work.
        binding = {'local': local, 'owned': owned, 'outerResultPath': local / 'result.json',
                   'cancelPath': owned / 'cancel', 'reservationSha256': sha(compact(start)),
                   'admission': admission, 'start': start, 'deadline': deadline, 'began': began}
        try:
            owned.mkdir()
            write_new(owned / 'started.json', compact(start), deadline=deadline)
            write_new(local / 'windows-input.json', compact({'sha256': sha(compact(start))}), deadline=deadline)
            for name in ('home', 'home/.dotnet', 'home/msbuild-user',
                         'home/roaming', 'home/local', 'home/http', 'home/plugins',
                         'temp', 'empty-program-files', 'controller', 'publish'):
                budget(deadline, cancelled)
                direct(owned / name).mkdir()
            write_new(owned / FINAL_FIRST_USE_SENTINEL, b'', deadline=deadline)
            slots = {'ACTION_ROOT': WINDOWS + '\\actions\\' + number,
                     'SOURCE_ROOT': graph['sourceRoot'], 'PACKAGE_ROOT': graph['packageRoot'], 'ENDPOINT': endpoint}
            recipe = admission['recipe']
            arguments = [resolve(x, slots) for x in recipe['invocation']['argumentVectorTemplate']]
            environment = {k: resolve(v, slots) for k, v in recipe['invocation']['replacementEnvironmentTemplate'].items()}
            if len(environment) != 35 or len({k.upper() for k in environment}) != 35:
                fail('Replacement environment shape changed')
            if any(k.upper() in recipe['invocation']['mustBeAbsentCaseInsensitive'] for k in environment):
                fail('Ambient native override is present')
            native = subprocess.list2cmdline(arguments)
            native_command = '"' + recipe['invocation']['executable'] + '" ' + native
            envblock = ('\0'.join(k + '=' + environment[k] for k in sorted(environment, key=str.upper)) + '\0\0').encode('utf-16le')
            invocation = {'schema': 'final-publish-invocation-v2', 'action': number,
                          'reservationSha256': binding['reservationSha256'], 'authoritySha256': sha(admission['authorityBytes']),
                          'actionPath': slots['ACTION_ROOT'], 'workingDirectory': graph['sourceRoot'],
                          'executable': recipe['invocation']['executable'], 'argumentVector': arguments,
                          'nativeArguments': native, 'nativeArgumentsSha256': sha(native.encode('utf-16le')),
                          'nativeCommandLine': native_command,
                          'nativeCommandLineSha256': sha(native_command.encode('utf-16le')),
                          'environment': environment, 'environmentBlockSha256': sha(envblock),
                          'endpoint': endpoint, 'acceptedGuard': envelope['acceptedGuard'],
                          'acceptedLauncher': envelope['acceptedLauncher'],
                          'graphSha256': envelope['graph']['sha256'], 'limits': LIMITS}
            for role in ('controller', 'bootstrap'):
                write_new(owned / 'controller' / COMPONENTS[role], admission['components'][role], deadline=deadline)
            write_new(owned / 'authority.json', admission['authorityBytes'], deadline=deadline)
            write_new(owned / 'caller-authorization.json', admission['evidenceBytes']['callerAuthorization'], deadline=deadline)
            write_new(owned / 'graph.json', admission['evidenceBytes']['graph'], deadline=deadline)
            write_new(owned / 'recipe.json', compact(recipe), deadline=deadline)
            write_new(owned / 'invocation.json', compact(invocation), deadline=deadline)
            binding.update(invocation=invocation, invocationSha256=sha(compact(invocation)), slots=slots)
            provenance = admission['callerProvenance']
            for role, leaf in (('guardArtifact', 'WindowsFinalPublishGuard.dll'),
                               ('launcherArtifact', 'WindowsScriptJobLauncher.exe'),
                               ('guardAcceptance', 'guard-artifact-acceptance.json'),
                               ('launcherAcceptance', 'launcher-artifact-acceptance.json')):
                write_new(owned / 'controller' / leaf, provenance[role]['raw'],
                          0o500 if role == 'launcherArtifact' else 0o400, deadline=deadline)
            launcher_path = owned / 'controller' / 'WindowsScriptJobLauncher.exe'
            launcher_info = direct(launcher_path).lstat()
            if not stat.S_ISREG(launcher_info.st_mode) or not launcher_info.st_mode & stat.S_IXUSR:
                fail('Copied native launcher is not executable; no repair is admitted')
            # Invocation bytes are sealed before constructing argv: no self-hash cycle.
            binding['exactControllerCommand'] = [str(launcher_path), '--publication',
                slots['ACTION_ROOT'], endpoint, sha(admission['authorityBytes']),
                envelope['components']['bootstrap']['sha256'], binding['reservationSha256'],
                binding['invocationSha256']]
            for template in graph['generatedPaths']:
                path = projection(resolve(template, slots))
                if path.exists() or path.is_symlink():
                    fail('Stale generated artifact or response input')
            tool_inventory(graph, slots, [], [], lambda: budget(deadline, cancelled), before=True)
            final_startup_inputs(owned, deadline, cancelled)
            budget(deadline, cancelled)
            yield binding
        except BaseException as error:
            budget(deadline, lambda: False)
            if not (local / 'result.json').exists():
                write_new(local / 'result.json', compact({'schema': 'final-publish-reservation-failure-v1',
                    'reservationSha256': binding['reservationSha256'], 'failureType': type(error).__name__,
                    'normalCompletion': False, 'safetyStop': True, 'artifactEligible': False,
                    'continuation_allowed': False, 'retainedLiveWorkOrUnknown': True}), deadline=deadline)
            raise
    finally:
        os.close(fd)


def exchange_clock(binding, process, deadline, cancelled):
    owned = binding['owned']
    end = min(deadline, time.monotonic() + 20.0)
    while not (owned / 'clock-ready.json').exists():
        budget(end, cancelled)
        if process.poll() is not None:
            fail('Original bootstrap exited before clock handoff')
        time.sleep(min(0.025, budget(end, cancelled)))
    raw = read(owned / 'clock-ready.json', end, cancelled, 4096)
    ready = decode(raw)
    keys(ready, ('schema', 'action', 'reservationSha256', 'invocationSha256', 'endpoint',
                 'windowsReadyCounter', 'windowsClockFrequency', 'controllerPid', 'controllerStartUtc'))
    fixed = {'schema': 'final-publish-clock-ready-v1', 'action': binding['start']['number'],
             'reservationSha256': binding['reservationSha256'], 'invocationSha256': binding['invocationSha256'],
             'endpoint': binding['start']['endpoint']}
    if any(ready[k] != value for k, value in fixed.items()):
        fail('Original Windows clock identity changed')
    integer(ready['windowsReadyCounter'], 1)
    integer(ready['windowsClockFrequency'], 1)
    integer(ready['controllerPid'], 1, 4294967295)
    string(ready['controllerStartUtc'], '[0-9T:.+Z-]{20,40}')
    # Preserve the original outer deadline while retaining the Windows clock cap.
    left = min(LIMITS['controllerMilliseconds'], int(budget(deadline, cancelled) * 1000))
    integer(left, 1, LIMITS['controllerMilliseconds'])
    reply = {'schema': 'final-publish-clock-remaining-v1', 'action': binding['start']['number'],
             'reservationSha256': binding['reservationSha256'], 'invocationSha256': binding['invocationSha256'],
             'endpoint': binding['start']['endpoint'], 'readySha256': sha(raw), 'remainingMilliseconds': left}
    write_new(owned / 'clock-remaining.json', compact(reply), deadline=deadline)
    budget(end, cancelled)
    binding['clock'] = {'ready': ready, 'readySha256': sha(raw), 'replySha256': sha(compact(reply)),
                        'deadlineCounter': ready['windowsReadyCounter'] + left * ready['windowsClockFrequency'] // 1000 - 1}


def publication_native_completion(binding, completion, deadline, cancelled):
    owned = binding['owned']
    raw = read(owned / 'launcher.jsonl', deadline, cancelled, 65536)
    if not raw.endswith(b'\n'):
        fail('Incomplete native publication journal')
    records = [decode(line) for line in raw.splitlines()]
    events = ('publication-bootstrap', 'publication-job-ready', 'publication-root-suspended',
              'publication-resume-attempt', 'publication-resumed', 'publication-audit',
              'publication-capture', 'publication-capture', 'publication-retention',
              'publication-operating-interval-end', 'publication-launcher-exit')
    if len(records) != len(events) or tuple(record.get('event') for record in records) != events:
        fail('Native publication did not complete its normal journal sequence')
    previous = -1
    for record in records:
        observed = integer(record['elapsedMilliseconds'], 0, LIMITS['nativeTotalMilliseconds'] - 1)
        if observed < previous:
            fail('Native journal restarted its original clock')
        previous = observed
    entry, job, root, attempt, resumed, audit, stdout, stderr, retention, closed, terminal = records
    job_name = 'Local\\azureauth-publication-108-' + binding['start']['number'] + '-' + binding['start']['endpoint']

    def require(record, expected):
        if any(key not in record or compact(record[key]) != compact(value) for key, value in expected.items()):
            fail('Native publication identity or lifetime predicate failed')

    require(entry, {'action': binding['start']['number'], 'jobName': job_name, 'fixtureCase': None,
                    'authoritySha256': sha(binding['admission']['authorityBytes']),
                    'bootstrapSha256': binding['admission']['envelope']['components']['bootstrap']['sha256'],
                    'reservationSha256': binding['reservationSha256'], 'invocationSha256': binding['invocationSha256'],
                    'workDeadlineMilliseconds': 2000000, 'totalDeadlineMilliseconds': 2010000})
    integer(entry['pid'], 1, 4294967295)
    integer(entry['session'], 0, 4294967295)
    string(entry['creationFileTime'], '[1-9][0-9]{0,18}')
    require(job, {'queryAccess': True, 'ownerOutsideJob': True, 'activeProcessLimit': 32,
                  'killOnClose': False, 'breakaway': False})
    require(root, {'pid': completion['bootstrapPid'], 'creationFileTime': completion['bootstrapCreationFileTime'],
                   'session': completion['bootstrapSession'], 'inJob': True})
    integer(root['pid'], 1, 4294967295)
    string(root['creationFileTime'], '[1-9][0-9]{0,18}')
    if root['session'] != entry['session'] or root['pid'] == entry['pid']:
        fail('Native/bootstrap incarnation or session join failed')
    require(attempt, {'resumeMayHaveRun': True})
    require(audit, {'atomic': False, 'limit': 32, 'complete': True, 'querySucceeded': True,
                    'assigned': 0, 'returned': 0, 'queryError': None, 'status': 'observed'})
    start = integer(audit['startedMilliseconds'], resumed['elapsedMilliseconds'], 2009999)
    end = integer(audit['endedMilliseconds'], start, 2009999)
    if end - start >= 5000:
        fail('Native same-held-Job audit exceeded five seconds')
    for name, record in (('stdout', stdout), ('stderr', stderr)):
        require(record, {'stream': name, 'initialized': True, 'readBytes': 0, 'confirmedFlushedBytes': 0,
                         'eof': True, 'overflowDetected': False, 'failureStage': None, 'failureType': None,
                         'failureHresult': None, 'failureNativeError': None, 'closeFailureType': None})
        if read(owned / ('launcher.' + name + '.bin'), deadline, cancelled, 16384) != b'':
            fail('Unexpected native-captured bootstrap output')
    require(retention, {'jobName': job_name, 'originalJobHandleHeld': True, 'rootCreated': True,
                        'resumeAttempted': True, 'resumed': True, 'neverResumedTerminationRequested': False,
                        'neverResumedTerminationSucceeded': False, 'neverResumedTerminationError': None,
                        'neverResumedRootExitConfirmed': False, 'rootExited': True, 'rootExitCode': 0,
                        'activeProcesses': 0, 'lifetimeFailureType': None, 'auditComplete': True,
                        'stdoutEof': True, 'stderrEof': True, 'retainedLiveWorkOrUnknown': False,
                        'failureLatched': False, 'evidenceIncomplete': False, 'completionObserved': True,
                        'failureAtFinalization': False, 'passiveEndedMilliseconds': None,
                        'terminationAfterResumeAttempt': False, 'nameRecoveryAfterCloseGuaranteed': False})
    integer(retention['totalProcesses'], 2)
    final_start = integer(retention['finalizationStartedMilliseconds'], 0, 1999999)
    final_end = integer(retention['finalDeadlineMilliseconds'], final_start + 1, 2010000)
    if final_end != min(2010000, final_start + 10000) or terminal['elapsedMilliseconds'] >= final_end:
        fail('Native finalization exceeded its original single window')
    require(closed, {'jobName': job_name, 'jobHandleClosed': True, 'retainedLiveWorkOrUnknown': False,
                     'nameRecoveryAfterCloseGuaranteed': False, 'finalDeadlineMilliseconds': final_end})
    require(terminal, {'readyForExit': True, 'retainedLiveWorkOrUnknown': False, 'capturedBytes': 0})
    write_new(binding['local'] / 'launcher.jsonl', raw, deadline=deadline)
    return {'outerJobName': job_name, 'outerJobActive': 0, 'outerJobTotal': retention['totalProcesses'],
            'outerJournalSha256': sha(raw)}


def original_completion(binding, proxy_exit, deadline, cancelled):
    if proxy_exit != 0:
        fail('Original WSL proxy did not exit zero')
    owned = binding['owned']
    exit_raw = read(owned / 'controller-exit.json', deadline, cancelled, 16384)
    completion = decode(exit_raw)
    expected_keys = ('schema', 'reservationSha256', 'invocationSha256', 'controllerPid', 'controllerStartUtc',
                     'bootstrapPid', 'bootstrapCreationFileTime', 'bootstrapSession',
                     'controllerExitObserved', 'controllerExitCode', 'controllerTerminationRequested',
                     'normalCompletion', 'safetyStop', 'windowsResultSha256', 'readySha256', 'replySha256',
                     'observedCounter', 'deadlineCounter', 'failureType')
    keys(completion, expected_keys)
    ready = binding['clock']['ready']
    fixed = {'schema': 'final-publish-controller-exit-v2', 'reservationSha256': binding['reservationSha256'],
             'invocationSha256': binding['invocationSha256'], 'controllerPid': ready['controllerPid'],
             'controllerStartUtc': ready['controllerStartUtc'], 'controllerExitObserved': True,
             'controllerExitCode': 0, 'controllerTerminationRequested': False,
             'normalCompletion': True, 'safetyStop': False, 'readySha256': binding['clock']['readySha256'],
             'replySha256': binding['clock']['replySha256'], 'deadlineCounter': binding['clock']['deadlineCounter'],
             'failureType': None}
    if any(type(completion[k]) is not type(v) or completion[k] != v for k, v in fixed.items()):
        fail('Actual original Windows controller completion is unestablished')
    if integer(completion['observedCounter'], 1) >= binding['clock']['deadlineCounter']:
        fail('Actual Windows controller exit was observed too late')
    native_proof = publication_native_completion(binding, completion, deadline, cancelled)
    raw = read(owned / 'windows-result.json', deadline, cancelled, 65536)
    if sha(raw) != digest(completion['windowsResultSha256']):
        fail('Original Windows result binding changed')
    result = decode(raw)
    required = {'schema': 'final-publish-windows-result-v1', 'reservationSha256': binding['reservationSha256'],
                'normalCompletion': True, 'safetyStop': False, 'quiescent': True, 'exitCode': 0,
                'captureCompleted': True, 'captureDisposition': 'complete', 'bothStreamsEof': True,
                'jobTerminationRequested': False, 'jobTerminationSucceeded': False,
                'rootTerminationRequested': False, 'rootTerminationSucceeded': False,
                'retainedLiveWorkOrUnknown': False, 'artifactEligible': False, 'continuation_allowed': False,
                'activeProcessesAtNormalExit': 0, 'lastJobActive': 0,
                'protectedInputsUnchanged': True, 'diagnosticsComplete': True,
                'generatedResponsesMatched': True, 'warningCount': 0, 'errorCount': 0}
    keys(result, (*required, 'neverResumedRootExitConfirmed', 'executionMayHaveBegun', 'stage',
                  'lastJobTotal', 'seconds', 'stdoutBytes', 'stderrBytes', 'stdoutSha256', 'stderrSha256',
                  'controllerSeconds', 'ended', 'postconditionsSha256', 'normalDrainStartedMilliseconds',
                  'normalDrainDeadlineMilliseconds', 'normalDrainObservedMilliseconds', 'innerAuditSha256'))
    for key, value in required.items():
        if type(result.get(key)) is not type(value) or result[key] != value:
            fail('Original final-publish success predicate failed')
    integer(result['lastJobTotal'], 1)
    subject = decode(read(owned / 'subject.json', deadline, cancelled, 4096))
    inner_name = 'Local\\azureauth-final-publish-108-' + binding['start']['number'] + '-' + binding['start']['endpoint']
    subject_expected = {'schema': 'final-publish-suspended-subject-v2', 'action': binding['start']['number'],
                        'session': completion['bootstrapSession'], 'jobName': inner_name,
                        'namedJobRightsVerified': True, 'reservationSha256': binding['reservationSha256'],
                        'invocationSha256': binding['invocationSha256'],
                        'authoritySha256': sha(binding['admission']['authorityBytes']),
                        'guardSourceSha256': binding['invocation']['acceptedGuard']['sourceSha256'],
                        'guardDllSha256': binding['invocation']['acceptedGuard']['dllSha256'], 'resumed': False}
    keys(subject, (*subject_expected, 'pid', 'creationFileTime'))
    if any(compact(subject[key]) != compact(value) for key, value in subject_expected.items()):
        fail('Suspended compiler identity or authority join changed')
    integer(subject['pid'], 1, 4294967295)
    string(subject['creationFileTime'], '[1-9][0-9]{0,18}')
    inner_raw = read(owned / 'inner-members.json', deadline, cancelled, 65536)
    if sha(inner_raw) != digest(result['innerAuditSha256']):
        fail('Original inner Job audit changed')
    inner = decode(inner_raw)
    for key, expected in {'complete': True, 'querySucceeded': True, 'atomic': False,
                          'jobName': inner_name, 'sessionId': completion['bootstrapSession'],
                          'assigned': 0, 'returned': 0, 'members': []}.items():
        if key not in inner or compact(inner[key]) != compact(expected):
            fail('Original same-held-inner-Job audit did not establish completion')

    if result['neverResumedRootExitConfirmed'] is not False or result['executionMayHaveBegun'] is not True or result['stage'] != 'normal-observed':
        fail('Original root lifecycle proof changed')
    drain_start = integer(result['normalDrainStartedMilliseconds'], 0, 1789999)
    drain_end = integer(result['normalDrainDeadlineMilliseconds'], drain_start + 1, 1790000)
    drain_observed = integer(result['normalDrainObservedMilliseconds'], drain_start, drain_end - 1)
    if drain_end != min(1790000, drain_start + LIMITS['drainMilliseconds']):
        fail('Original normal drain exceeded its fixed bound')
    if type(result['seconds']) not in (int, float) or not 0 <= result['seconds'] < 1800:
        fail('Action observation exceeded 1800 seconds')
    if type(result['controllerSeconds']) not in (int, float) or not 0 <= result['controllerSeconds'] < 1900:
        fail('Controller observation exceeded 1900 seconds')
    stdout = read(owned / 'stdout.bin', deadline, cancelled)
    stderr = read(owned / 'stderr.bin', deadline, cancelled)
    if len(stdout) + len(stderr) > 8388608:
        fail('Original combined output limit exceeded')
    for name, data in (('stdout', stdout), ('stderr', stderr)):
        if len(data) != result[name + 'Bytes'] or sha(data) != result[name + 'Sha256']:
            fail('Original capture identity changed')
    diagnostic_text = stdout.decode('utf-8') + '\n' + stderr.decode('utf-8')
    if '\0' in diagnostic_text or '\x1b' in diagnostic_text or re.search(
            r'(?:^|[\s:])(?:fatal\s+)?(?:warning|error)(?:\s+[A-Z][A-Z0-9]*\d+)?\s*:',
            diagnostic_text, re.IGNORECASE | re.MULTILINE):
        fail('Original diagnostics are incomplete, uninterpretable or nonzero')
    post_raw = read(owned / 'postconditions.json', deadline, cancelled, 8388608)
    if sha(post_raw) != digest(result['postconditionsSha256']):
        fail('Original postcondition receipt changed')
    post = decode(post_raw)
    keys(post, ('schema', 'reservationSha256', 'graphSha256', 'protectedInputsUnchanged', 'generatedResponses', 'toolResponses',
                'stdoutSha256', 'stderrSha256', 'warningCount', 'errorCount', 'bothStreamsEof', 'diagnosticsComplete'))
    fixed_post = {'schema': 'final-publish-postconditions-v2', 'reservationSha256': binding['reservationSha256'],
                  'graphSha256': binding['invocation']['graphSha256'], 'protectedInputsUnchanged': True,
                  'stdoutSha256': sha(stdout), 'stderrSha256': sha(stderr), 'warningCount': 0,
                  'errorCount': 0, 'bothStreamsEof': True, 'diagnosticsComplete': True}
    if any(type(post[k]) is not type(v) or post[k] != v for k, v in fixed_post.items()):
        fail('Original input/diagnostic proof failed')
    graph = binding['admission']['evidence']['graph']
    if type(post['generatedResponses']) is not list or len(post['generatedResponses']) != len(graph['generatedResponses']):
        fail('Incomplete original response observations')
    for response, observed in zip(graph['generatedResponses'], post['generatedResponses']):
        slots = dict(binding['slots'])
        slots.update({k: resolve(v, binding['slots']) for k, v in response['substitutions'].items()})
        expected_response = ('\r\n'.join(resolve(line, slots) for line in response['lines']) + '\r\n').encode('utf-8')
        if response['encoding'] == 'utf-8-bom':
            expected_response = b'\xef\xbb\xbf' + expected_response
        expected_observation = {'id': response['id'], 'path': resolve(response['pathTemplate'], slots),
                                'bytes': len(expected_response), 'sha256': sha(expected_response),
                                'producerSha256': response['producer']['sha256'],
                                'consumerSha256': response['consumer']['sha256']}
        if compact(observed) != compact(expected_observation):
            fail('Original response producer/template observation changed')
        if read(owned / 'response-inputs' / (response['id'] + '.rsp'), deadline, cancelled) != expected_response:
            fail('Retained original response bytes changed')
        if read(projection(expected_observation['path']), deadline, cancelled) != expected_response:
            fail('Generated response changed after original natural completion')
    expected_tools = tool_observations(graph, binding['admission']['recipe'], binding['slots'],
        stdout, stderr, binding['reservationSha256'], binding['invocation']['graphSha256'],
        lambda: budget(deadline, cancelled), lambda path: read(path, deadline, cancelled))
    if compact(post['toolResponses']) != compact(expected_tools):
        fail('Original Csc/Exec event, environment or response receipt changed')
    for observed in expected_tools:
        snapshot = read(owned / observed['snapshot'], deadline, cancelled)
        if len(snapshot) != observed['bytes'] or sha(snapshot) != observed['snapshotSha256']:
            fail('Original retained tool snapshot changed')
        if read(projection(observed['path']), deadline, cancelled) != snapshot:
            fail('Original tool input changed after natural completion')
    # No subject-output access happens before actual original completion above.
    final_startup_inputs(owned, deadline, cancelled)
    for item in binding['admission']['evidence']['graph']['protectedInputs']:
        hash_protected(item, deadline, cancelled)
    for path in graph['absentInputs']:
        if direct(projection(path)).exists():
            fail('Unexpected ambient source/import appeared')
    refresh_publication_checkpoint(binding['admission'], deadline, cancelled, binding)
    if (owned / 'cancel').exists():
        fail('Late cancellation preserves failure')
    for name in ('started.json', 'invocation.json', 'authority.json', 'caller-authorization.json',
                 'clock-ready.json', 'clock-remaining.json'):
        expected = {'started.json': binding['reservationSha256'], 'invocation.json': binding['invocationSha256'],
                    'authority.json': sha(binding['admission']['authorityBytes']),
                    'caller-authorization.json': sha(binding['admission']['evidenceBytes']['callerAuthorization']),
                    'clock-ready.json': binding['clock']['readySha256'],
                    'clock-remaining.json': binding['clock']['replySha256']}[name]
        limit = CALLER_PROVENANCE_LIMIT if name == 'caller-authorization.json' else 8388608
        if sha(read(owned / name, deadline, cancelled, limit)) != expected:
            fail('Original control evidence changed')
    write_new(binding['local'] / 'windows-result.json', raw, deadline=deadline)
    write_new(binding['local'] / 'controller-exit.json', exit_raw, deadline=deadline)
    return {**result, **native_proof}
