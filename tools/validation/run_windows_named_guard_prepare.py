"""Prospective compiler-only preparation 0066; no standalone execution entry.

Only a separately reviewed immutable launcher may load and call this module after
protocol/source admission. The launcher owns current-target verification through
its admitted finite systemd helper route; no caller Boolean grants authority.
"""

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
import types

NUMBER = '0066'
ACTION = 'named-final-guard-prepare'
LINUX = Path('/var/tmp/azureauth-windows-slice-108')
HISTORY = LINUX / 'windows-actions'
PROJECTION = Path('/mnt/c/Temp/azureauth-windows-slice-108')
POWERSHELL = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
PROTOCOL_PATH = 'docs/research/experiments/windows-slice-validation.md'
ROOT_MARKER = {'grant': 'a0f741b59e09f1eb95594dbfde7a6e634d962210',
               'issue': 108, 'protocol_family': PROTOCOL_PATH}
AUTHORITY_PATH = Path('/tmp/windows-named-guard0066-authority.json')
INPUT_ROOT = Path('/tmp/windows-named-guard0066-inputs')
COMPONENTS = {'dispatcher': 'run_windows_named_guard_prepare.py',
              'controller': 'Invoke-WindowsNamedGuardPrepare.ps1',
              'guard': 'WindowsFinalPublishGuard.cs',
              'history': 'named_guard_history.py'}
COUNTS = {'preparation': 16, 'buildTest': 94, 'publication': 2, 'synthetic': 52}
_retained_proxies = []
_invoked = False
_deadline = None
_cancelled = lambda: False
_reads = 0
_read_bytes = 0


def budget():
    if _deadline is None or _cancelled():
        raise InterruptedError('Preparation has no active original clock or was cancelled')
    remaining(_deadline)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def direct(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or len(path.parts) > 16:
        raise ValueError('Noncanonical preparation path')
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('Linked preparation path')
    return path


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def open_parent(path):
    path = direct(path)
    held = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            budget()
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=held)
            os.close(held)
            held = child
        return held
    except BaseException:
        os.close(held)
        raise


def read_bytes(path, limit=1048576):
    global _reads, _read_bytes
    budget()
    path = direct(path)
    parent = open_parent(path)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_nlink != 1 or not 0 <= before.st_size <= limit):
            raise ValueError('Preparation input type, owner or size')
        _reads += 1
        _read_bytes += before.st_size + 1
        if _reads > 96 or _read_bytes > 67108864:
            raise ValueError('Preparation input read ceiling')
        data = bytearray()
        while len(data) <= before.st_size:
            budget()
            chunk = os.read(fd, min(65536, before.st_size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(named):
            raise ValueError('Preparation input changed during read')
        if len(data) != before.st_size:
            raise ValueError('Preparation input length changed')
        fresh = open_parent(path)
        try:
            if (os.fstat(parent).st_dev, os.fstat(parent).st_ino) != (os.fstat(fresh).st_dev, os.fstat(fresh).st_ino):
                raise ValueError('Preparation input parent changed')
        finally:
            os.close(fresh)
        budget()
        return bytes(data)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def exact_bytes(path, expected, limit=1048576):
    if type(expected) is not str or re.fullmatch('[0-9a-f]{64}', expected) is None:
        raise ValueError('Unbound preparation input')
    raw = read_bytes(path, limit)
    if hash_bytes(raw) != expected:
        raise ValueError('Preparation input hash changed')
    return raw


def write_new(path, data):
    # Failure evidence may be persisted after cancellation, but creates no work.
    path = direct(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def cancel_created_action(path, held):
    """Write only through the retained, still-named directory we created."""
    actual = os.fstat(held)
    named = os.stat(direct(path), follow_symlinks=False)
    directory = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    if not stat.S_ISDIR(named.st_mode) or named.st_uid != os.getuid() or directory(named) != directory(actual):
        raise ValueError('Original created action directory is no longer named')
    fd = os.open('cancel', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=held)
    try:
        os.fsync(fd)
        os.fsync(held)
    finally:
        os.close(fd)


def keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError('Preparation authority shape changed')


def bound(binding, path):
    keys(binding, ('path', 'bytes', 'sha256'))
    if binding['path'] != str(path) or type(binding['bytes']) is not int or not 1 <= binding['bytes'] <= 1048576:
        raise ValueError('Preparation fixed input binding')
    raw = exact_bytes(path, binding['sha256'])
    if len(raw) != binding['bytes']:
        raise ValueError('Preparation fixed input length')
    return raw


def load_inputs(authority_sha256):
    raw = exact_bytes(AUTHORITY_PATH, authority_sha256)
    authority = decode(raw)
    keys(authority, ('schema', 'repository', 'branch', 'scope', 'source', 'protocol', 'wave',
                     'components', 'historyManifest', 'historyAcceptance', 'sourceReview',
                     'executionAdmission', 'rootMarkers', 'counts', 'nextAction'))
    if (encode(authority) != raw or authority['schema'] != 'named-guard-authority-v1' or
            authority['repository'] != 'hcoona/microsoft-authentication-cli' or authority['branch'] != 'main-v2' or
            authority['scope'] != 'one-compiler-only-preparation-after0065' or authority['nextAction'] != NUMBER or
            authority['counts'] != COUNTS or any(type(authority['counts'][k]) is not int for k in COUNTS)):
        raise ValueError('Preparation authority scope or framing')
    keys(authority['source'], ('commit', 'tree'))
    keys(authority['protocol'], ('commit', 'sha256'))
    keys(authority['wave'], ('sha256',))
    for value in authority['source'].values():
        if type(value) is not str or re.fullmatch('[0-9a-f]{40}', value) is None:
            raise ValueError('Preparation source revision')
    if authority['protocol']['commit'] != authority['source']['commit']:
        raise ValueError('Preparation protocol and source must merge together')
    for value in (authority['protocol']['sha256'], authority['wave']['sha256']):
        if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
            raise ValueError('Preparation authority digest')
    keys(authority['components'], COMPONENTS)
    components = {role: bound(authority['components'][role], INPUT_ROOT / name)
                  for role, name in COMPONENTS.items()}
    if Path(__file__) != INPUT_ROOT / COMPONENTS['dispatcher']:
        raise ValueError('Unadmitted dispatcher path')
    evidence = {role: bound(authority[role], INPUT_ROOT / (role + '.json'))
                for role in ('historyManifest', 'historyAcceptance', 'sourceReview', 'executionAdmission')}
    # Independent review supplies meaning; the exact immutable launcher binds
    # these evidence bytes and the entire authority. Runtime flags cannot do so.
    return raw, authority, components, evidence


def owner_markers(authority):
    keys(authority['rootMarkers'], ('linux', 'windows'))
    for role, root in (('linux', LINUX), ('windows', PROJECTION)):
        if decode(exact_bytes(root / 'owner.json', authority['rootMarkers'][role], 4096)) != ROOT_MARKER:
            raise ValueError('Existing experiment owner changed')


def check_copies(owned, authority, authority_sha256, start, invocation):
    exact_bytes(owned / 'authority.json', authority_sha256)
    exact_bytes(owned / 'started.json', hash_bytes(encode(start)), 16384)
    exact_bytes(owned / 'invocation.json', hash_bytes(encode(invocation)), 32768)
    exact_bytes(owned / 'final-guard/source/WindowsValidationJob.cs', authority['components']['guard']['sha256'])
    exact_bytes(owned / 'final-guard/controller/Invoke-WindowsNamedGuardPrepare.ps1', authority['components']['controller']['sha256'])


def collect_normal(owned, start, invocation, proxy, clock, authority, authority_sha256):
    if proxy.poll() != 0:
        raise ValueError('Original preparation proxy failed')
    raw = read_bytes(owned / 'windows-result.json', 65536)
    receipt = decode(raw)
    if (receipt.get('schema') != 'final-guard-windows-result-v1' or
            receipt.get('reservationSha256') != hash_bytes(encode(start)) or
            receipt.get('invocationSha256') != hash_bytes(encode(invocation)) or
            receipt.get('authoritySha256') != authority_sha256 or
            receipt.get('sourceReviewSha256') != authority['sourceReview']['sha256'] or
            receipt.get('admissionSha256') != authority['executionAdmission']['sha256'] or
            receipt.get('clockHandoff') != clock):
        raise ValueError('Preparation completion binding changed')
    for key in ('normalCompletion', 'compilerCompletionConfirmed', 'captureCompleted', 'bothStreamsEof', 'authorityVerified'):
        if receipt.get(key) is not True:
            raise ValueError('Preparation normal completion is incomplete')
    for key in ('compilerTerminationRequested', 'safetyStop', 'artifactAccepted', 'continuation_allowed'):
        if receipt.get(key) is not False:
            raise ValueError('Preparation result flag changed')
    if type(receipt.get('compilerExitCode')) is not int or receipt['compilerExitCode'] != 0:
        raise ValueError('Compiler exit failed')
    if type(receipt.get('outerMilliseconds')) is not int or not 0 <= receipt['outerMilliseconds'] < 230000:
        raise ValueError('Preparation Windows clock exceeded')
    exact_bytes(owned / 'clock-ready.json', clock['readySha256'], 2048)
    exact_bytes(owned / 'clock-remaining.json', clock['replySha256'], 2048)
    for stream in ('stdout', 'stderr'):
        if receipt.get(stream + 'Bytes') != 0 or exact_bytes(owned / (stream + '.bin'), receipt[stream + 'Sha256'], 0):
            raise ValueError('Unexpected compiler diagnostics')
    dll = exact_bytes(owned / 'final-guard/WindowsFinalPublishGuard.dll', receipt['dllSha256'], 8388608)
    if not dll or type(receipt.get('dllBytes')) is not int or len(dll) != receipt['dllBytes']:
        raise ValueError('Preparation DLL length changed')
    check_copies(owned, authority, authority_sha256, start, invocation)
    build = {'schema': 'named-guard-build-v1', 'action': NUMBER,
             'reservationSha256': hash_bytes(encode(start)), 'invocationSha256': hash_bytes(encode(invocation)),
             'windowsResultSha256': hash_bytes(raw), 'authoritySha256': authority_sha256,
             'sourceSha256': authority['components']['guard']['sha256'], 'dllSha256': hash_bytes(dll),
             'dllBytes': len(dll), 'toolSha256': invocation['toolSha256'], 'clockHandoff': clock,
             'artifactAccepted': False, 'continuation_allowed': False}
    budget()
    write_new(owned / 'guard-build.json', encode(build))
    return {'schema': 'named-guard-wsl-result-v1', 'normalCompletion': True, 'quiescent': True,
            'reservationSha256': hash_bytes(encode(start)), 'windowsResultSha256': hash_bytes(raw),
            'guardBuildSha256': hash_bytes(encode(build)), 'authoritySha256': authority_sha256,
            'artifactAccepted': False, 'continuation_allowed': False}


def prepare(authority_sha256, verify_current, original_started_ns, record_stage):
    """One call by the exact admitted launcher, under its original invocation.

    verify_current is the reviewed launcher's concrete supervised GET operation.
    Its source, helper bounds and literal call are admission inputs; substituting
    a lambda or relying on a return value alone supplies no review authority.
    """
    global _invoked, _deadline, _cancelled
    record_stage('dispatcher', 'entry')
    if _invoked:
        raise ValueError('Named guard preparation already invoked')
    _invoked = True
    if (type(original_started_ns) is not int or original_started_ns <= 0 or
            not 0 <= time.monotonic_ns() - original_started_ns < 230_000_000_000):
        raise ValueError('Missing or expired original launcher clock')
    started_ns = original_started_ns
    _deadline = started_ns + 230_000_000_000
    interrupted = False
    old_handlers = {}
    proxy = local = owned = None
    owned_fd = None
    controller_start_attempted = False
    lock_fd = None
    result = {'schema': 'named-guard-wsl-result-v1', 'normalCompletion': False,
              'quiescent': False, 'artifactAccepted': False, 'continuation_allowed': False}

    def cancel(_signum, _frame):
        nonlocal interrupted
        interrupted = True

    _cancelled = lambda: interrupted
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, cancel)
        record_stage('dispatcher', 'input-authority')
        raw, authority, components, evidence = load_inputs(authority_sha256)
        record_stage('dispatcher', 'owner-markers')
        owner_markers(authority)
        record_stage('dispatcher', 'history-load')
        history = types.ModuleType('admitted_named_guard_history')
        history.__file__ = str(INPUT_ROOT / COMPONENTS['history'])
        exec(compile(components['history'], history.__file__, 'exec'), history.__dict__)
        record_stage('dispatcher', 'action-lock')
        lock_path = direct(LINUX / 'action.lock')
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid() or
                lock_info.st_nlink != 1 or identity(lock_info) != identity(lock_path.stat())):
            raise ValueError('Existing shared action lock changed')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        budget()
        record_stage('freshness', 'supervision')
        current = verify_current(_deadline, _cancelled)
        budget()
        record_stage('freshness', 'target-match')
        if current != authority['source']['commit']:
            raise ValueError('Accepted main changed before preparation')
        record_stage('history-manifest', 'hash-and-size')
        comparison = history.ReservationComparison(evidence['historyManifest'],
                         authority['historyManifest']['sha256'], _deadline, _cancelled, record_stage)
        prior = comparison.compare()
        record_stage('dispatcher', 'capacity')
        if prior != COUNTS:
            raise ValueError('Named preparation capacity changed')
        record_stage('dispatcher', 'owner-lock-continuity')
        owner_markers(authority)
        if identity(lock_info) != identity(lock_path.stat()):
            raise ValueError('Shared action lock replaced')
        budget()
        record_stage('dispatcher', 'local-reservation')
        local = direct(HISTORY / NUMBER)
        local.mkdir(mode=0o700)
        try:
            start = {'action': ACTION, 'number': NUMBER,
                     'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     'protocol': authority['protocol']['commit'], 'source': authority['source']['commit'],
                     'sourceTree': authority['source']['tree'], 'priorCounters': prior,
                     'historyManifestSha256': authority['historyManifest']['sha256'],
                     'historyAcceptanceSha256': authority['historyAcceptance']['sha256'],
                     'authoritySha256': authority_sha256,
                     'reviewSha256': authority['executionAdmission']['sha256'],
                     'sourceReviewSha256': authority['sourceReview']['sha256'],
                     'sourceSha256': authority['components']['guard']['sha256'],
                     'dispatcherSha256': authority['components']['dispatcher']['sha256'],
                     'preparationControllerSha256': authority['components']['controller']['sha256'],
                     'preparationCharge': 1, 'buildTestCharge': 0, 'publishCharge': 0,
                     'reservedProcessScenarios': 0, 'clockNonce': secrets.token_hex(32),
                     'originalClockStartNanoseconds': started_ns,
                     'originalClockDeadlineNanoseconds': _deadline}
            write_new(local / 'started.json', encode(start))
            result['reservationSha256'] = hash_bytes(encode(start))
            budget()
            record_stage('dispatcher', 'windows-reservation')
            candidate_owned = direct(PROJECTION / 'actions' / NUMBER)
            candidate_owned.mkdir()
            owned = candidate_owned
            owned_fd = os.open(owned, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            write_new(owned / 'started.json', encode(start))
            comparison.compare(new_reservation_sha256=hash_bytes(encode(start)))
            record_stage('dispatcher', 'materialization')
            for relative in ('home', 'home/roaming', 'home/local', 'home/http', 'home/plugins',
                             'temp', 'empty-program-files', 'final-guard', 'final-guard/source', 'final-guard/controller'):
                budget()
                direct(owned / relative).mkdir()
            recipe = resolve_recipe(NUMBER)
            write_new(owned / 'authority.json', raw)
            write_new(owned / 'final-guard/source/WindowsValidationJob.cs', components['guard'])
            write_new(owned / 'final-guard/controller/Invoke-WindowsNamedGuardPrepare.ps1', components['controller'])
            invocation = {'schema': 'final-guard-invocation-v1', 'action': NUMBER,
                          'paths': recipe['paths'], 'compiler': recipe['compilerInvocation'],
                          'toolSha256': recipe['tools']['sha256'],
                          'reservationSha256': hash_bytes(encode(start)), 'authoritySha256': authority_sha256,
                          'sourceReviewSha256': authority['sourceReview']['sha256'],
                          'admissionSha256': authority['executionAdmission']['sha256'],
                          'clockNonce': start['clockNonce'], 'originalOuterLimitMilliseconds': 230000,
                          'clockHandshakeLimitMilliseconds': 20000}
            write_new(owned / 'invocation.json', encode(invocation))
            write_new(local / 'windows-input.json', encode({'sha256': hash_bytes(encode(start))}))
            record_stage('dispatcher', 'copy-validation')
            check_copies(owned, authority, authority_sha256, start, invocation)
            command = [POWERSHELL, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                       recipe['paths']['preparationControllerDirectoryTemplate'] + '\\Invoke-WindowsNamedGuardPrepare.ps1',
                       '-ActionName', NUMBER, '-ReservationSha256', hash_bytes(encode(start)),
                       '-InvocationSha256', hash_bytes(encode(invocation)), '-AuthoritySha256', authority_sha256]
            budget()
            # Keep the complete compiler, original-handle cleanup and receipt
            # reserve inside the original deadline before any controller starts.
            record_stage('dispatcher', 'launch-reserve')
            if remaining(_deadline) < 65:
                raise TimeoutError('Insufficient original preparation launch reserve')
            handshake_deadline = min(_deadline, time.monotonic_ns() + 20_000_000_000)
            record_stage('dispatcher', 'controller-start')
            controller_start_attempted = True
            proxy = start_proxy(command)
            record_stage('dispatcher', 'clock-handoff')
            clock = exchange_original_clock(owned, start, invocation, proxy, _deadline, handshake_deadline, _cancelled)
            record_stage('dispatcher', 'controller-completion')
            observe_proxy(proxy, _deadline, _cancelled)
            record_stage('dispatcher', 'result-validation')
            result = collect_normal(owned, start, invocation, proxy, clock, authority, authority_sha256)
            record_stage('dispatcher', 'final-input-continuity')
            owner_markers(authority)
            fresh_raw, _, fresh_components, fresh_evidence = load_inputs(authority_sha256)
            if fresh_raw != raw or fresh_components != components or fresh_evidence != evidence:
                raise ValueError('Preparation input continuity failed')
            budget()
        except BaseException as error:
            result.update(normalCompletion=False, artifactAccepted=False, continuation_allowed=False,
                          failureType=type(error).__name__)
        finally:
            if not result['normalCompletion']:
                if controller_start_attempted and owned_fd is not None:
                    try:
                        cancel_created_action(owned, owned_fd)
                        result['cancellationPersisted'] = True
                    except BaseException as error:
                        result['cancellationPersisted'] = False
                        result['cancellationFailureType'] = type(error).__name__
                end = min(_deadline, time.monotonic_ns() + 10_000_000_000)
                while proxy is not None and proxy.poll() is None and time.monotonic_ns() < end:
                    time.sleep(min(0.05, max(0, (end - time.monotonic_ns()) / 1_000_000_000)))
                # A returned proxy alone is not compiler or Windows quiescence.
                result['quiescent'] = False
            result['outerNanoseconds'] = time.monotonic_ns() - started_ns
            result['utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            write_new(local / 'result.json', encode(result))
            if result['normalCompletion']:
                budget()
    finally:
        if owned_fd is not None:
            os.close(owned_fd)
        if lock_fd is not None:
            os.close(lock_fd)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    if result['normalCompletion']:
        budget()
    return result

RECIPE = {'paths': {'compiledArtifactReceiptTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\guard-build.json', 'compiledArtifactTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\WindowsFinalPublishGuard.dll', 'compilerWorkingDirectoryTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source', 'copiedSourceTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs', 'guardActionFourDigits': None, 'onlyDynamicPathSubstitution': 'GUARD_ACTION4; fixed to admitted logical successor 0066, preserving absent physical slots 0057 through 0059 and 0065.', 'preparationControllerDirectoryTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\controller', 'sharedActionLock': '/var/tmp/azureauth-windows-slice-108/action.lock', 'windowsActionTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}', 'windowsRoot': 'C:\\Temp\\azureauth-windows-slice-108', 'wslActionTemplate': '/var/tmp/azureauth-windows-slice-108/windows-actions/${GUARD_ACTION4}', 'wslHistoryRoot': '/var/tmp/azureauth-windows-slice-108/windows-actions', 'wslWindowsProjectionTemplate': '/mnt/c/Temp/azureauth-windows-slice-108/actions/${GUARD_ACTION4}'}, 'compilerInvocation': {'analyzers': [], 'argumentVectorTemplate': ['/noconfig', '/nologo', '/target:library', '/out:C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\WindowsFinalPublishGuard.dll', '/reference:C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll', '/reference:C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll', 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs'], 'callerArgumentOrEnvironmentOverridesAllowed': False, 'clearInheritedEnvironment': True, 'compilerConfiguration': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe.config', 'customTasks': [], 'executable': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe', 'explicitReferences': ['C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll'], 'generators': [], 'implicitMscorlibReference': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.dll', 'nativeAotLinkerOrPdbServiceSelected': False, 'nativeArgumentsTemplate': '/noconfig /nologo /target:library /out:"C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\WindowsFinalPublishGuard.dll" /reference:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll" /reference:"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll" "C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs"', 'packageRestoreOrCopy': False, 'preservesOriginalBootstrapEnvironmentRecipe': True, 'productSymbolPolicyChanged': False, 'replacementEnvironmentEntryCount': 30, 'replacementEnvironmentTemplate': {'APPDATA': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\roaming', 'ComSpec': 'C:\\Windows\\System32\\cmd.exe', 'DOTNET_ADD_GLOBAL_TOOLS_TO_PATH': 'false', 'DOTNET_CLI_HOME': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1', 'DOTNET_CLI_UI_LANGUAGE': 'en-US', 'DOTNET_CLI_USE_MSBUILD_SERVER': '0', 'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE': 'true', 'DOTNET_GENERATE_ASPNET_CERTIFICATE': 'false', 'DOTNET_NOLOGO': '1', 'DOTNET_ROLL_FORWARD': 'Disable', 'DOTNET_ROOT': 'C:\\Program Files\\dotnet', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1', 'LOCALAPPDATA': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\local', 'MSBUILDDISABLENODEREUSE': '1', 'MSBuildEnableWorkloadResolver': 'false', 'NUGET_HTTP_CACHE_PATH': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\http', 'NUGET_PACKAGES': 'C:\\Temp\\azureauth-windows-slice-108\\packages', 'NUGET_PLUGINS_CACHE_PATH': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home\\plugins', 'OS': 'Windows_NT', 'PATH': 'C:\\Program Files\\dotnet;C:\\Windows\\System32', 'PROCESSOR_ARCHITECTURE': 'AMD64', 'PROGRAMFILES': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\empty-program-files', 'PROGRAMFILES(X86)': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\empty-program-files', 'SystemRoot': 'C:\\Windows', 'TEMP': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\temp', 'TESTINGPLATFORM_TELEMETRY_OPTOUT': '1', 'TMP': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\temp', 'USERPROFILE': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\home', 'WINDIR': 'C:\\Windows'}, 'resolvedArgumentStringBytesAndHash': None, 'resolvedEnvironmentBytesAndHash': None, 'responseFiles': [], 'sharedCompiler': False, 'sourceFiles': ['C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source\\WindowsValidationJob.cs'], 'workingDirectoryTemplate': 'C:\\Temp\\azureauth-windows-slice-108\\actions\\${GUARD_ACTION4}\\final-guard\\source'}, 'tools': {'installedToolReadPerformed': False, 'newToolInstallationOrRepairAllowed': False, 'sha256': {'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll': 'fd1097aed825d392a5dc8d19384381d4bb2a43498ea1c9d917f5d80c66600e1b', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll': '2b3c17c6208a0b4b6beb94e1a066f99ba06cdb2ea919479e99d47e8c6d96dc71', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe': '46809206887326d2d24db1eff1f3064de972c3451abe766b49111450a5e08e00', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe.config': '2d4610ade011e530d817dd3ba4fc787e5dc0c2297cc520c30a643b8fb13f9093', 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.dll': '5bffb20e1217bad314143d7e5c4c809bf9f522e8a0a063c8e7e9b25113de26eb', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe': '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e'}, 'source': 'Accepted immutable tools/validation/run_windows.py TOOLS entries'}}

def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()

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
