"""INACTIVE dedicated observer dispatcher; no experiment or candidate import admitted."""
EXECUTION_ADMITTED = False
HISTORY_ADAPTER_ADMITTED = False
if not EXECUTION_ADMITTED:
    raise RuntimeError("INACTIVE: observer execution is not admitted")

import datetime
import hashlib
import types
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

PROPOSAL_SHA256 = "7e6cd2cb681c701bc475f8b186cb12627b433921663917171a965b7bd57fa06c"
MANIFEST_SHA256 = "39fe2577d718a05efd4e71b40f522424f6c259f5ad3f43b3fd9b4b69d16c05cf"
MATERIALIZATION_SHA256 = "c37ab00e2bda8376786fabc5b81f9fcdcc02073b505466839da95b8c87e464e9"
SOURCE_INPUTS_SHA256 = "a03498832c8632794ff3c45e64c0009bee3c37983b857b0b4e73c3df43157127"
_input_read_bytes = 0
_input_read_files = 0
SOURCE_ROOT = r"C:\Temp\azureauth-windows-slice-108\observers\core-csc-5033607\source"
REQUIRED_REVIEWS = ("wave", "protocol", "callerReview", "runtimeReview", "loaderReview",
                    "physicalPreflightReview", "materializationReview", "helperEffectsReview",
                    "activeTargetReview", "historyReview", "executionReview")
_retained_proxies = []


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def decode(data):
    return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=pairs)


def direct(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("Relative selector")
    for part in (path, *path.parents):
        if stat.S_ISLNK(part.lstat().st_mode):
            raise ValueError("Symlink selector")
    return path


def charge_read(size):
    global _input_read_bytes, _input_read_files
    _input_read_bytes += size
    _input_read_files += 1
    if _input_read_bytes > 268435456 or _input_read_files > 256:
        raise ValueError("Input read allowance")


def small_file(path, limit):
    charge_read(limit + 1)
    path = direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Nonregular small input")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Small input bound")
    return data


def exact(descriptor, limit=16 * 1024 * 1024):
    if type(descriptor) is not dict or set(descriptor) != {"path", "bytes", "sha256"}:
        raise ValueError("Unbound descriptor")
    size = descriptor["bytes"]
    if type(size) is not int or not 0 <= size <= limit:
        raise ValueError("Input bound")
    charge_read(size + 1)
    path = direct(descriptor["path"])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        data = stream.read(size + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if not stat.S_ISREG(before.st_mode) or identity(before) != identity(after):
        raise ValueError("Input continuity")
    if len(data) != size or digest(data) != descriptor["sha256"]:
        raise ValueError("Input identity")
    return data


# Origin: reviewed dispatcher exclusive durable writes. No replacement/deletion.
def write_new(path, data):
    path = Path(path)
    direct(path.parent)
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def remaining(deadline):
    ticks = deadline - time.monotonic_ns()
    if ticks <= 0:
        raise TimeoutError("Original 180-second allowance expired")
    return ticks / 1_000_000_000


def quote_argument(value):
    if not isinstance(value, str) or any(c in value for c in ("\0", "\r", "\n")):
        raise ValueError("Argument control character")
    out, slashes = ['"'], 0
    for char in value:
        if char == "\\":
            slashes += 1
            continue
        out.append("\\" * (2 * slashes + 1 if char == '"' else slashes))
        out.append(char)
        slashes = 0
    out.extend(("\\" * (2 * slashes), '"'))
    return "".join(out)


def resolve(value, invocation):
    for token, key in (("${ACTION_ROOT}", "actionPath"), ("${PACKAGE_ROOT}", "packageRoot"),
                       ("${ENDPOINT}", "endpoint")):
        value = value.replace(token, invocation[key])
    if "${" in value:
        raise ValueError("Unresolved template")
    return value


def load_history_adapter(authority):
    if not HISTORY_ADAPTER_ADMITTED:
        raise RuntimeError("INACTIVE: existing history integration is not admitted")
    descriptor = authority["historyAdapter"]
    data = exact(descriptor)
    # Execute the captured and hash-verified source bytes. No loader reread or
    # bytecode cache selects different bytes between identity checks.
    module = types.ModuleType("accepted_observer_history_adapter")
    module.__file__ = descriptor["path"]
    module.__package__ = ""
    module.__dict__["__accepted_source_sha256__"] = digest(data)
    sys.modules[module.__name__] = module
    try:
        exec(compile(data, descriptor["path"], "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(module.__name__, None)
        raise
    for name in ("reserve_core_csc_observer", "validate_core_csc_observer_original"):
        if not callable(getattr(module, name, None)):
            raise ValueError("Missing accepted history entrypoint")
    return module


def stage_payloads(authority, plan, source_inputs, invocation, owned, deadline, cancelled):
    """One fixed 34+12-file stage plus separately accepted active observer bytes."""
    if source_inputs["count"] != 34 or source_inputs["bytes"] != 150146:
        raise ValueError("Source-input totals")
    mapping = {entry["gitPath"]: entry["payload"] for entry in source_inputs["sourceInputs"]}
    if len(mapping) != 34 or len(plan["sourcePayloads"]) != 34 or len(plan["restorePayloads"]) != 12:
        raise ValueError("Staging mapping")
    stage = owned / "observer-payloads"
    os.mkdir(stage, 0o700)
    count, total = 0, 0
    for entry in (*plan["sourcePayloads"], *plan["restorePayloads"]):
        remaining(deadline)
        if cancelled():
            raise InterruptedError("Cancelled during payload staging")
        descriptor = mapping[entry["gitPath"]] if "gitPath" in entry else entry["input"]
        if descriptor["bytes"] != entry["bytes"] or descriptor["sha256"] != entry["sha256"]:
            raise ValueError("Exact payload identity")
        expected = resolve(entry["stagedPayloadPathTemplate"], invocation)
        name = expected.rsplit("\\", 1)[-1]
        if expected != invocation["actionPath"] + "\\observer-payloads\\" + name or not name.endswith(".bin"):
            raise ValueError("Staging path")
        data = exact(descriptor)
        write_new(stage / name, data)
        count += 1
        total += len(data)
    if count != 46 or total != 383855:
        raise ValueError("Staged byte totals")
    remaining(deadline)
    if cancelled():
        raise InterruptedError("Cancelled before active-target staging")
    active = authority["wslActiveTarget"]
    windows_active = authority["activeTarget"]
    if (active["sha256"] != windows_active["sha256"] or active["bytes"] != windows_active["bytes"] or
            windows_active["path"] != "${ACTION_ROOT}\\observer-payloads\\observer.targets"):
        raise ValueError("Active observer target binding")
    if active["sha256"] == "14e7159b5a094cbeed12739a2a153f08b3fd6299e5864e2d4a2ede8301db5548":
        raise ValueError("Inactive observer target cannot be launched")
    write_new(stage / "observer.targets", exact(active, 65536))



def stage_authority_documents(authority, authority_bytes, invocation, owned, deadline, cancelled):
    """Stage only the fixed controller and its admitted offline input documents."""
    support = owned / "observer-support"
    os.mkdir(support, 0o700)
    native = invocation["actionPath"] + "\\observer-support\\"
    pairs_to_copy = [("Invoke-WindowsCoreCscObserver.ps1", authority["wslController"], authority["controller"]),
                     ("proposal.json", authority["wslProposal"], authority["proposal"]),
                     ("source-manifest.json", authority["wslSourceManifest"], authority["sourceManifest"]),
                     ("materialization.json", authority["wslMaterialization"], authority["materialization"])]
    pairs_to_copy += [(name + ".review", authority["wslReviews"][name], authority["reviews"][name])
                      for name in REQUIRED_REVIEWS]
    projections = authority["wslGuardProjections"]
    if type(projections) is not dict or set(projections) != {"wslResult", "completionAcceptance"}:
        raise ValueError("Guard evidence projection selection changed")
    for role, name, size in (("wslResult", "guard-wsl-result.json", 967),
                             ("completionAcceptance", "guard-completion-acceptance.json", 4068)):
        if type(projections[role]["bytes"]) is not int or projections[role]["bytes"] != size:
            raise ValueError("Guard evidence projection size changed")
        pairs_to_copy.append((name, projections[role], authority["guard"][role]))
    for name, source, destination in pairs_to_copy:
        remaining(deadline)
        if cancelled():
            raise InterruptedError("Cancelled while staging observer authority")
        if (destination["path"] != native + name or
                any(destination[k] != source[k] for k in ("bytes", "sha256"))):
            raise ValueError("Observer authority document mapping changed")
        write_new(support / name, exact(source))
    if authority["windowsAuthorityPath"] != native + "authority.json":
        raise ValueError("Windows authority selector changed")
    write_new(support / "authority.json", authority_bytes)
    expected_prefix = ["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                       "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                       native + "Invoke-WindowsCoreCscObserver.ps1"]
    if authority["windowsBootstrapPrefix"] != expected_prefix:
        raise ValueError("Observer Windows bootstrap prefix changed")
    remaining(deadline)
    if cancelled():
        raise InterruptedError("Cancelled after staging observer authority")


# Origin: 0055 exchange_original_clock. One ready-bound reply, never receive-time reset.
def exchange_original_clock(owned, start, invocation, invocation_sha, proxy, deadline, handshake_deadline, cancelled):
    if (deadline != start["originalClockDeadlineNanoseconds"] or
            deadline - start["originalClockStartNanoseconds"] != 180_000_000_000 or handshake_deadline > deadline):
        raise ValueError("Original clock identity")
    ready_path, reply_path = owned / "clock-ready.json", owned / "clock-remaining.json"
    while True:
        if cancelled():
            raise InterruptedError("Cancelled during handoff")
        remaining(handshake_deadline)
        if proxy.poll() is not None:
            raise RuntimeError("Controller exited before clock handoff")
        if ready_path.exists():
            ready_bytes = small_file(ready_path, 2048)
            ready = decode(ready_bytes)
            break
        time.sleep(min(0.025, remaining(handshake_deadline)))
    keys = {"schema", "action", "nonce", "reservationSha256", "invocationSha256",
            "originalOuterLimitMilliseconds", "windowsReadyElapsedTicks", "windowsClockFrequency"}
    if type(ready) is not dict or set(ready) != keys:
        raise ValueError("Ready shape")
    expected = {"schema": "final-guard-clock-ready-v1", "action": invocation["actionNumber"],
                "nonce": start["clockNonce"], "reservationSha256": invocation["reservationSha256"],
                "invocationSha256": invocation_sha, "originalOuterLimitMilliseconds": 180000}
    for key, value in expected.items():
        if type(ready[key]) is not type(value) or ready[key] != value:
            raise ValueError("Ready binding")
    ticks, frequency = ready["windowsReadyElapsedTicks"], ready["windowsClockFrequency"]
    if type(ticks) is not int or not 0 <= ticks <= 2**63 - 1 or type(frequency) is not int or not 0 < frequency <= 2**63 - 1:
        raise ValueError("Windows clock values")
    if cancelled():
        raise InterruptedError("Cancelled before reply")
    remaining(handshake_deadline)
    left = (deadline - time.monotonic_ns()) // 1_000_000
    if not 0 < left <= 180000:
        raise TimeoutError("No remaining allowance")
    reply = {"schema": "final-guard-clock-remaining-v1", "action": invocation["actionNumber"],
             "nonce": start["clockNonce"], "reservationSha256": invocation["reservationSha256"],
             "invocationSha256": invocation_sha, "originalOuterLimitMilliseconds": 180000,
             "readySha256": digest(ready_bytes), "remainingMilliseconds": left}
    reply_bytes = encode(reply)
    write_new(reply_path, reply_bytes)
    remaining(handshake_deadline)
    return {"readySha256": digest(ready_bytes), "replySha256": digest(reply_bytes),
            "windowsReadyElapsedTicks": ticks, "windowsClockFrequency": frequency,
            "remainingMilliseconds": left, "windowsDeadlineElapsedTicks": ticks + left * frequency // 1000}


def invoke_core_csc_observer_candidate(authority_path, admitted_authority_sha256):
    if (not EXECUTION_ADMITTED or type(admitted_authority_sha256) is not str or
            len(admitted_authority_sha256) != 64 or any(c not in "0123456789abcdef" for c in admitted_authority_sha256)):
        raise RuntimeError("INACTIVE or unbound authority")
    # This single clock includes authority checks, reservation, launch, handshake,
    # materialization, subject, cleanup, joining and bounded receipt finalization.
    began = time.monotonic_ns()
    deadline = began + 180_000_000_000
    path = direct(authority_path)
    descriptor = {"path": str(path), "bytes": path.stat().st_size, "sha256": admitted_authority_sha256}
    authority_bytes = exact(descriptor, 1024 * 1024)
    authority = decode(authority_bytes)
    for name in REQUIRED_REVIEWS:
        exact(authority["wslReviews"][name], 1024 * 1024)
    if authority["wslProposal"]["sha256"] != PROPOSAL_SHA256 or authority["wslSourceManifest"]["sha256"] != MANIFEST_SHA256:
        raise ValueError("Proposal binding")
    proposal = decode(exact(authority["wslProposal"]))
    manifest = decode(exact(authority["wslSourceManifest"]))
    if len(manifest["files"]) != 34 or manifest["sourceDiagnosticBytes"] != 150146:
        raise ValueError("Source manifest")
    exact(authority["dispatcher"])
    if Path(authority["dispatcher"]["path"]) != Path(__file__):
        raise ValueError("Dispatcher source binding")
    if (authority["wslMaterialization"]["sha256"] != MATERIALIZATION_SHA256 or
            authority["sourceInputs"]["sha256"] != SOURCE_INPUTS_SHA256):
        raise ValueError("Materialization/source-input identity")
    plan = decode(exact(authority["wslMaterialization"]))
    source_inputs = decode(exact(authority["sourceInputs"]))
    if (plan["sourceBytes"] != 150146 or plan["restoreBytes"] != 233709 or
            plan["sourceFileCount"] != 34 or plan["restoreFileCount"] != 12):
        raise ValueError("Materialization totals")
    history = load_history_adapter(authority)
    cancelled = False
    handlers = {}
    proxy = None
    reservation = None
    lock_lease = None
    finalization_failed = False
    result = {"actionKind": "core-csc-observer", "launchAttempted": False, "proxyExitCode": None,
              "normalCompletion": False, "quiescent": False, "graphAccepted": False,
              "artifactAccepted": False, "continuation_allowed": False, "safetyStop": True,
              "independentObservationAccepted": False, "originalWindowsCompletionJoined": False,
              "outcome": "incomplete"}

    def cancel(_signum, _frame):
        nonlocal cancelled
        cancelled = True

    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            handlers[number] = signal.signal(number, cancel)
        remaining(deadline)
        # Root supplies this narrow extension in the existing current reader.
        # It owns the shared lock, current counters, linked durable reservations,
        # unique endpoint and action number. Failure never refunds the unit.
        reservation = history.reserve_core_csc_observer(authority, began, deadline, lambda: cancelled)
        # Retain the lease through the WSL receipt attempt. Cancellation/timeout
        # does not wait for Windows finally or establish paired finalization.
        # If reserve raises before returning, that helper releases its own lease.
        lock_lease = reservation["lockLease"]
        if not callable(getattr(lock_lease, "close", None)):
            raise ValueError("Missing retained shared lock lease")
        start = reservation["started"]
        if start["originalClockStartNanoseconds"] != began or start["originalClockDeadlineNanoseconds"] != deadline:
            raise ValueError("Reservation reset original clock")
        invocation = dict(reservation["invocation"])
        if invocation["packageRoot"] != plan["packageRoot"]:
            raise ValueError("Package root")
        number = invocation["actionNumber"]
        if type(number) is not str or len(number) != 4 or not number.isascii() or not number.isdigit() or number == "0000":
            raise ValueError("Action number")
        if invocation["actionPath"] != "C:\\Temp\\azureauth-windows-slice-108\\actions\\" + number:
            raise ValueError("Windows action root")
        invocation.update(actionKind="core-csc-observer", originalOuterLimitMilliseconds=180000,
                          clockHandshakeLimitMilliseconds=20000, workingDirectory=SOURCE_ROOT,
                          executable=r"C:\Program Files\dotnet\dotnet.exe", clockNonce=start["clockNonce"],
                          authoritySha256=admitted_authority_sha256,
                          originalClockStartNanoseconds=start["originalClockStartNanoseconds"],
                          originalClockDeadlineNanoseconds=start["originalClockDeadlineNanoseconds"])
        invocation["environment"] = {key: resolve(value, invocation) for key, value in proposal["replacementEnvironmentTemplate"].items()}
        invocation["nativeArguments"] = " ".join(quote_argument(resolve(value, invocation)) for value in proposal["argumentVectorTemplate"])
        if len(invocation["environment"]) != 35:
            raise ValueError("Replacement environment size")
        raw_invocation = encode(invocation)
        invocation_sha = digest(raw_invocation)
        owned = direct(reservation["windowsActionPosix"])
        local = direct(reservation["wslActionPath"])
        if str(owned) != "/mnt/c/Temp/azureauth-windows-slice-108/actions/" + number:
            raise ValueError("Windows selector mapping")
        if str(local) != "/var/tmp/azureauth-windows-slice-108/windows-actions/" + number:
            raise ValueError("WSL selector mapping")
        windows_started = small_file(owned / "started.json", 1048576)
        wsl_started = small_file(local / "started.json", 1048576)
        if (windows_started != wsl_started or digest(windows_started) != invocation["reservationSha256"] or
                decode(windows_started) != start):
            raise ValueError("Original paired reservation bytes")
        write_new(owned / "invocation.json", raw_invocation)
        write_new(local / "invocation.json", raw_invocation)
        result.update(action=number, reservationSha256=invocation["reservationSha256"], invocationSha256=invocation_sha)
        stage_payloads(authority, plan, source_inputs, invocation, owned, deadline, lambda: cancelled)
        stage_authority_documents(authority, authority_bytes, invocation, owned, deadline, lambda: cancelled)
        # Command prefix and both authority/controller paths are exact admitted
        # data. No shell or interpolation is used to launch the Windows proxy.
        command = list(authority["windowsBootstrapPrefix"])
        command += ["-AuthorityPath", authority["windowsAuthorityPath"], "-AuthoritySha256", admitted_authority_sha256,
                    "-InvocationPath", invocation["actionPath"] + "\\invocation.json", "-InvocationSha256", invocation_sha]
        remaining(deadline)
        if cancelled:
            raise InterruptedError("Cancelled before launch")
        result["launchAttempted"] = True
        write_new(local / "controller-start-attempt.json", encode({"attempted": True, "reservationSha256": invocation["reservationSha256"]}))
        # Durable attempt persistence may return late; the debit is never refunded.
        remaining(deadline)
        if cancelled:
            raise InterruptedError("Cancelled after durable controller attempt")
        launch_started_ns = time.monotonic_ns()
        if launch_started_ns >= deadline:
            raise TimeoutError("Original deadline expired before controller launch")
        result["launchMonotonicNanoseconds"] = launch_started_ns
        result["handshakeDeadlineNanoseconds"] = min(deadline, launch_started_ns + 20_000_000_000)
        proxy = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        _retained_proxies.append(proxy)
        clock = exchange_original_clock(owned, start, invocation, invocation_sha, proxy, deadline,
                                        min(deadline, launch_started_ns + 20_000_000_000), lambda: cancelled)
        result["clock"] = clock
        while True:
            if cancelled:
                raise InterruptedError("Observer cancellation")
            remaining(deadline)
            code = proxy.poll()
            if code is not None:
                result["proxyExitCode"] = code
                if code != 0:
                    raise RuntimeError("Original Windows controller failed")
                break
            time.sleep(min(0.025, remaining(deadline)))
        # The root-owned extension validates originals and exact receipt flags;
        # output/binlog interpretation remains a separate independent acceptance.
        proof = history.validate_core_csc_observer_original(authority, reservation, invocation, clock, code, deadline)
        for key in ("normalCompletion", "quiescent", "captureCompleted", "naturalJobCompletion"):
            if proof.get(key) is not True:
                raise ValueError("Incomplete original Windows observation")
        if any(proof.get(key) is not False for key in ("graphAccepted", "artifactAccepted", "continuation_allowed",
                                                      "jobTerminationRequested", "independentObservationAccepted")):
            raise ValueError("Invalid original observer acceptance flags")
        if proof.get("outcome") != "expected-stop-candidate-awaiting-independent-acceptance":
            raise ValueError("Unexpected observer outcome")
        remaining(deadline)
        result.update(normalCompletion=True, quiescent=True, safetyStop=False, originalWindowsCompletionJoined=True,
                      outcome="expected-stop-candidate-awaiting-independent-acceptance")
    except BaseException as error:
        result["failureType"] = type(error).__name__
    finally:
        try:
            if reservation is not None:
                # Do not wait for Windows finally on timeout/cancellation. Its
                # completion can remain unknown after this WSL receipt attempt.
                # Retain incomplete originals; never synthesize a Windows result.
                if not result["normalCompletion"]:
                    try:
                        write_new(Path(reservation["windowsActionPosix"]) / "cancel", b"")
                    except FileExistsError:
                        pass
                    except BaseException as error:
                        result["cancelFailureType"] = type(error).__name__
                result["outerElapsedMilliseconds"] = (time.monotonic_ns() - began) // 1_000_000
                result["utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                write_new(Path(reservation["wslActionPath"]) / "result.json", encode(result))
        except BaseException as error:
            finalization_failed = True
            result["finalizationFailureType"] = type(error).__name__
        finally:
            try:
                if lock_lease is not None:
                    try:
                        # Local lease release is not Windows finalization or
                        # quiescence. Incomplete/uncollected original history
                        # must block all subsequent dependent work after close.
                        lock_lease.close()
                    except BaseException as error:
                        finalization_failed = True
                        result["lockReleaseFailureType"] = type(error).__name__
            finally:
                for number, previous in handlers.items():
                    try:
                        signal.signal(number, previous)
                    except BaseException as error:
                        finalization_failed = True
                        result["handlerRestoreFailureType"] = type(error).__name__
    # All finalization attempts precede the original success-deadline decision.
    # Persisted provisional receipts remain unchanged if this observation is late.
    if finalization_failed or cancelled or time.monotonic_ns() >= deadline:
        result["normalCompletion"] = False
        result["safetyStop"] = True
        result["outcome"] = "incomplete"
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise RuntimeError("An exact authority path and SHA from literal admission are required")
    outcome = invoke_core_csc_observer_candidate(sys.argv[1], sys.argv[2])
    raise SystemExit(0 if outcome["normalCompletion"] else 1)
