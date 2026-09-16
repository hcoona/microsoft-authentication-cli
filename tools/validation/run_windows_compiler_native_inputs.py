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

PROPOSAL_SHA256 = None
MANIFEST_SHA256 = None
MATERIALIZATION_SHA256 = None
SOURCE_INPUTS_SHA256 = None
SOURCE_BYTES = None
ACTIVE_TARGET_SHA256 = None
ACTIVE_TARGET_BYTES = None
BOOTSTRAP_CAPTURE_MAX_BYTES = 4096
BOOTSTRAP_MAX_PUMPS = 36004
BOOTSTRAP_STAGES = frozenset((
    "entry-gate", "bootstrap-initialization", "source-bindings", "authority-shape",
    "authority-read", "invocation-read", "source-admission", "clock-handoff",
    "materialization", "guard-load", "preflight", "subject-start",
    "subject-observation", "claim-validation", "subject-cleanup",
    "receipt-finalization", "lease-release", "controller-exit",
))
BOOTSTRAP_EXCEPTION_TYPES = frozenset((
    "ExecutionNotAdmitted", "IncompleteOriginalObservation", "OtherException",
    "System.Management.Automation.RuntimeException",
    "System.Management.Automation.MethodInvocationException",
    "System.Management.Automation.PropertyNotFoundException",
    "System.Management.Automation.ParameterBindingException",
    "System.Management.Automation.ItemNotFoundException",
    "System.Management.Automation.CommandNotFoundException",
    "System.Management.Automation.PSArgumentException",
    "System.Management.Automation.PSInvalidOperationException",
    "System.IO.IOException", "System.IO.FileNotFoundException",
    "System.IO.DirectoryNotFoundException", "System.IO.PathTooLongException",
    "System.IO.EndOfStreamException", "System.UnauthorizedAccessException",
    "System.InvalidOperationException", "System.ArgumentException",
    "System.ArgumentNullException", "System.ArgumentOutOfRangeException",
    "System.NotSupportedException", "System.TimeoutException",
    "System.Security.SecurityException", "System.OutOfMemoryException",
    "System.FormatException", "System.ObjectDisposedException",
    "System.InvalidCastException",
))
_input_read_bytes = 0
_input_read_files = 0
SOURCE_ROOT = r"C:\Temp\azureauth-windows-slice-108\observers\compiler-native-inputs-5033607-v1\source"
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
        raise TimeoutError("Original 900-second allowance expired")
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



def assert_new_source_bindings():
    for value in (PROPOSAL_SHA256, MANIFEST_SHA256, MATERIALIZATION_SHA256,
                  SOURCE_INPUTS_SHA256, ACTIVE_TARGET_SHA256):
        if (type(value) is not str or len(value) != 64 or
                any(c not in "0123456789abcdef" for c in value)):
            raise RuntimeError("New diagnostic source binding is not admitted")
    if (type(SOURCE_BYTES) is not int or SOURCE_BYTES <= 0 or
            type(ACTIVE_TARGET_BYTES) is not int or not 0 < ACTIVE_TARGET_BYTES <= 65536):
        raise RuntimeError("New diagnostic source sizes are not admitted")


def new_bootstrap_capture(proxy):
    # Allocate state before configuring either pipe, retaining a failed setup as
    # incomplete original transport instead of losing its in-memory record.
    return {"streams": (proxy.stdout, proxy.stderr), "data": (bytearray(), bytearray()),
            "eof": [False, False], "nonblocking": False, "pumps": 0,
            "readCalls": 0, "observedBytes": 0, "truncated": False,
            "overflowObservedBytes": 0, "readFailureType": None,
            "persistenceAttempted": False, "persisted": False, "metadata": None}


def configure_bootstrap_capture(capture):
    for stream in capture["streams"]:
        if stream is None:
            raise ValueError("Missing original bootstrap pipe")
        os.set_blocking(stream.fileno(), False)
    capture["nonblocking"] = True


def pump_bootstrap_capture(capture):
    # No thread, blocking read, retry process, or second Windows query. At most
    # 4096 retained bytes plus one overflow byte across both original pipes.
    if not capture["nonblocking"] or capture["truncated"] or capture["readFailureType"] is not None:
        raise ValueError("Bootstrap capture is not readable")
    capture["pumps"] += 1
    if capture["pumps"] > BOOTSTRAP_MAX_PUMPS:
        raise ValueError("Bootstrap pump bound")
    for index, stream in enumerate(capture["streams"]):
        if capture["eof"][index]:
            continue
        left = BOOTSTRAP_CAPTURE_MAX_BYTES - sum(map(len, capture["data"]))
        capture["readCalls"] += 1
        try:
            data = os.read(stream.fileno(), min(4096, left + 1))
        except BlockingIOError:
            continue
        except OSError as error:
            capture["readFailureType"] = type(error).__name__
            raise
        capture["observedBytes"] += len(data)
        if not data:
            capture["eof"][index] = True
            continue
        retained = min(left, len(data))
        capture["data"][index].extend(data[:retained])
        if retained != len(data):
            capture["truncated"] = True
            capture["overflowObservedBytes"] += len(data) - retained
            raise ValueError("Original bootstrap capture exceeded its finite bound")


def retain_bootstrap_capture(capture, local):
    # local is the already admitted reservation directory; never write a
    # controller-side receipt before its owned-path admission. No replacement.
    if capture["persistenceAttempted"]:
        if not capture["persisted"]:
            raise ValueError("Bootstrap persistence was incomplete; no retry")
        return capture["metadata"]
    capture["persistenceAttempted"] = True
    descriptors = []
    for name, data in zip(("bootstrap-stdout.bin", "bootstrap-stderr.bin"), capture["data"]):
        raw = bytes(data)
        write_new(local / name, raw)
        descriptors.append({"path": str(local / name), "bytes": len(raw), "sha256": digest(raw)})
    metadata = {
        "schema": "compiler-native-inputs-bootstrap-transport-v1",
        "stdout": descriptors[0], "stderr": descriptors[1],
        "complete": all(capture["eof"]) and not capture["truncated"] and capture["readFailureType"] is None,
        "eof": list(capture["eof"]), "truncated": capture["truncated"],
        "readFailureType": capture["readFailureType"],
        "retainedBytes": sum(map(len, capture["data"])),
        "retainedLimitBytes": BOOTSTRAP_CAPTURE_MAX_BYTES,
        "observedBytes": capture["observedBytes"],
        "overflowObservedBytes": capture["overflowObservedBytes"],
        "maximumReturnedBytes": BOOTSTRAP_CAPTURE_MAX_BYTES + 1,
        # Rejected entries can increment pumps; only the first admitted passes
        # may read. EAGAIN/EOF/short reads do not return the requested size.
        "pumps": capture["pumps"], "maximumReadBearingPumps": BOOTSTRAP_MAX_PUMPS,
        "maximumReadCalls": BOOTSTRAP_MAX_PUMPS * 2,
        "maximumRequestedBytes": BOOTSTRAP_MAX_PUMPS * 2 * 4096,
        "readCalls": capture["readCalls"],
    }
    raw_metadata = encode(metadata)
    if len(raw_metadata) > 4096:
        raise ValueError("Bootstrap transport metadata bound")
    write_new(local / "bootstrap-transport.json", raw_metadata)
    capture["metadata"] = metadata
    capture["persisted"] = True
    return metadata


def decode_bootstrap_frame(capture):
    # The original bytes remain private retained evidence. Never display raw
    # interpreter/error text or accept malformed transport as a sanitized frame.
    if (not capture["persisted"] or not capture["metadata"]["complete"] or
            capture["data"][1] or not 0 < len(capture["data"][0]) <= 1024):
        raise ValueError("Incomplete or unexpected original bootstrap transport")
    raw = bytes(capture["data"][0])
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or not raw.isascii():
        raise ValueError("Bootstrap frame encoding or count")
    frame = decode(raw)
    if type(frame) is not dict or set(frame) != {"schema", "stage", "outcome", "exceptionType"}:
        raise ValueError("Bootstrap frame schema")
    if frame["schema"] != "compiler-native-inputs-bootstrap-v1" or frame["stage"] not in BOOTSTRAP_STAGES:
        raise ValueError("Bootstrap frame stage")
    if frame["outcome"] == "candidate":
        if frame["stage"] != "controller-exit" or frame["exceptionType"] is not None:
            raise ValueError("Bootstrap candidate frame")
    elif frame["outcome"] == "failure":
        if frame["exceptionType"] not in BOOTSTRAP_EXCEPTION_TYPES:
            raise ValueError("Bootstrap exception type")
    else:
        raise ValueError("Bootstrap frame outcome")
    return frame


def load_history_adapter(authority):
    if not HISTORY_ADAPTER_ADMITTED:
        raise RuntimeError("INACTIVE: existing history integration is not admitted")
    descriptor = authority["historyAdapter"]
    data = exact(descriptor)
    # Execute the captured and hash-verified source bytes. No loader reread or
    # bytecode cache selects different bytes between identity checks.
    module = types.ModuleType("accepted_compiler_native_inputs_history_adapter")
    module.__file__ = descriptor["path"]
    module.__package__ = ""
    module.__dict__["__accepted_source_sha256__"] = digest(data)
    sys.modules[module.__name__] = module
    try:
        exec(compile(data, descriptor["path"], "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(module.__name__, None)
        raise
    for name in ("reserve_compiler_native_inputs", "validate_compiler_native_inputs_original"):
        if not callable(getattr(module, name, None)):
            raise ValueError("Missing accepted history entrypoint")
    return module


def stage_payloads(authority, plan, source_inputs, invocation, owned, deadline, cancelled):
    """One fixed 34+12-file stage plus separately accepted active observer bytes."""
    if source_inputs["count"] != 34 or source_inputs["bytes"] != SOURCE_BYTES:
        raise ValueError("Source-input totals")
    mapping = {entry["gitPath"]: entry["payload"] for entry in source_inputs["sourceInputs"]}
    if len(mapping) != 34 or len(plan["sourcePayloads"]) != 34 or len(plan["restorePayloads"]) != 12:
        raise ValueError("Staging mapping")
    stage = owned / "compiler-inputs-payloads"
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
        if expected != invocation["actionPath"] + "\\compiler-inputs-payloads\\" + name or not name.endswith(".bin"):
            raise ValueError("Staging path")
        data = exact(descriptor)
        write_new(stage / name, data)
        count += 1
        total += len(data)
    if count != 46 or total != SOURCE_BYTES + 233709:
        raise ValueError("Staged byte totals")
    remaining(deadline)
    if cancelled():
        raise InterruptedError("Cancelled before active-target staging")
    active = authority["wslActiveTarget"]
    windows_active = authority["activeTarget"]
    if (active["sha256"] != windows_active["sha256"] or active["bytes"] != windows_active["bytes"] or
            windows_active["path"] != "${ACTION_ROOT}\\compiler-inputs-payloads\\compiler-native-inputs.targets"):
        raise ValueError("Active observer target binding")
    if active["sha256"] != ACTIVE_TARGET_SHA256 or active["bytes"] != ACTIVE_TARGET_BYTES:
        raise ValueError("Unbound active compiler/native-inputs target")
    write_new(stage / "compiler-native-inputs.targets", exact(active, 65536))



def stage_authority_documents(authority, authority_bytes, invocation, owned, deadline, cancelled):
    """Stage only the fixed controller and its admitted offline input documents."""
    support = owned / "compiler-inputs-support"
    os.mkdir(support, 0o700)
    native = invocation["actionPath"] + "\\compiler-inputs-support\\"
    pairs_to_copy = [("Invoke-WindowsCompilerNativeInputs.ps1", authority["wslController"], authority["controller"]),
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
                       native + "Invoke-WindowsCompilerNativeInputs.ps1"]
    if authority["windowsBootstrapPrefix"] != expected_prefix:
        raise ValueError("Observer Windows bootstrap prefix changed")
    remaining(deadline)
    if cancelled():
        raise InterruptedError("Cancelled after staging observer authority")


# Origin: 0055 exchange_original_clock. One ready-bound reply, never receive-time reset.
def exchange_original_clock(owned, start, invocation, invocation_sha, proxy, bootstrap, deadline, handshake_deadline, cancelled):
    if (deadline != start["originalClockDeadlineNanoseconds"] or
            deadline - start["originalClockStartNanoseconds"] != 900_000_000_000 or handshake_deadline > deadline):
        raise ValueError("Original clock identity")
    ready_path, reply_path = owned / "clock-ready.json", owned / "clock-remaining.json"
    while True:
        if cancelled():
            raise InterruptedError("Cancelled during handoff")
        remaining(handshake_deadline)
        pump_bootstrap_capture(bootstrap)
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
                "invocationSha256": invocation_sha, "originalOuterLimitMilliseconds": 900000}
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
    if not 0 < left <= 900000:
        raise TimeoutError("No remaining allowance")
    reply = {"schema": "final-guard-clock-remaining-v1", "action": invocation["actionNumber"],
             "nonce": start["clockNonce"], "reservationSha256": invocation["reservationSha256"],
             "invocationSha256": invocation_sha, "originalOuterLimitMilliseconds": 900000,
             "readySha256": digest(ready_bytes), "remainingMilliseconds": left}
    reply_bytes = encode(reply)
    write_new(reply_path, reply_bytes)
    remaining(handshake_deadline)
    return {"readySha256": digest(ready_bytes), "replySha256": digest(reply_bytes),
            "windowsReadyElapsedTicks": ticks, "windowsClockFrequency": frequency,
            "remainingMilliseconds": left, "windowsDeadlineElapsedTicks": ticks + left * frequency // 1000}


def invoke_compiler_native_inputs_candidate(authority_path, admitted_authority_sha256):
    if (not EXECUTION_ADMITTED or type(admitted_authority_sha256) is not str or
            len(admitted_authority_sha256) != 64 or any(c not in "0123456789abcdef" for c in admitted_authority_sha256)):
        raise RuntimeError("INACTIVE or unbound authority")
    # This single clock includes authority checks, reservation, launch, handshake,
    # materialization, subject, cleanup, joining and bounded receipt finalization.
    began = time.monotonic_ns()
    deadline = began + 900_000_000_000
    assert_new_source_bindings()
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
    if len(manifest["files"]) != 34 or manifest["sourceDiagnosticBytes"] != SOURCE_BYTES:
        raise ValueError("Source manifest")
    exact(authority["dispatcher"])
    if Path(authority["dispatcher"]["path"]) != Path(__file__):
        raise ValueError("Dispatcher source binding")
    if (authority["wslMaterialization"]["sha256"] != MATERIALIZATION_SHA256 or
            authority["sourceInputs"]["sha256"] != SOURCE_INPUTS_SHA256):
        raise ValueError("Materialization/source-input identity")
    plan = decode(exact(authority["wslMaterialization"]))
    source_inputs = decode(exact(authority["sourceInputs"]))
    if (plan["sourceBytes"] != SOURCE_BYTES or plan["restoreBytes"] != 233709 or
            plan["sourceFileCount"] != 34 or plan["restoreFileCount"] != 12):
        raise ValueError("Materialization totals")
    history = load_history_adapter(authority)
    cancelled = False
    handlers = {}
    proxy = None
    bootstrap = None
    local = None
    reservation = None
    lock_lease = None
    finalization_failed = False
    result = {"actionKind": "compiler-native-inputs", "launchAttempted": False, "proxyExitCode": None,
              "normalCompletion": False, "quiescent": False, "graphAccepted": False,
              "artifactAccepted": False, "continuation_allowed": False, "safetyStop": True,
              "independentObservationAccepted": False, "originalWindowsCompletionJoined": False,
              "outcome": "incomplete", "bootstrapTransport": None,
              "bootstrapFrame": None, "bootstrapPersistenceAttempted": False}

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
        reservation = history.reserve_compiler_native_inputs(authority, began, deadline, lambda: cancelled)
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
        invocation.update(actionKind="compiler-native-inputs", originalOuterLimitMilliseconds=900000,
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
        proxy = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
        _retained_proxies.append(proxy)
        bootstrap = new_bootstrap_capture(proxy)
        configure_bootstrap_capture(bootstrap)
        clock = exchange_original_clock(owned, start, invocation, invocation_sha, proxy, bootstrap, deadline,
                                        min(deadline, launch_started_ns + 20_000_000_000), lambda: cancelled)
        result["clock"] = clock
        while True:
            if cancelled:
                raise InterruptedError("Observer cancellation")
            remaining(deadline)
            pump_bootstrap_capture(bootstrap)
            code = proxy.poll()
            if code is not None:
                result["proxyExitCode"] = code
                if all(bootstrap["eof"]):
                    result["bootstrapTransport"] = retain_bootstrap_capture(bootstrap, local)
                    result["bootstrapFrame"] = decode_bootstrap_frame(bootstrap)
                    if code != 0 or result["bootstrapFrame"]["outcome"] != "candidate":
                        raise RuntimeError("Original Windows controller failed")
                    break
            time.sleep(min(0.025, remaining(deadline)))
        # The root-owned extension validates originals and exact receipt flags;
        # output/binlog interpretation remains a separate independent acceptance.
        proof = history.validate_compiler_native_inputs_original(authority, reservation, invocation, clock, code, deadline)
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
        # The original proxy can fail before writing clock-ready. Retain that
        # very transport, including incomplete/invalid bytes, without a fresh
        # probe, raw-text display, deadline reset, or wait for Windows finally.
        if bootstrap is not None and local is not None:
            try:
                if (not bootstrap["persistenceAttempted"] and bootstrap["nonblocking"] and
                        not bootstrap["truncated"] and bootstrap["readFailureType"] is None and
                        proxy.poll() is not None):
                    result["proxyExitCode"] = proxy.returncode
                    for _ in range(4):
                        if all(bootstrap["eof"]) or time.monotonic_ns() >= deadline:
                            break
                        pump_bootstrap_capture(bootstrap)
            except BaseException as error:
                result["bootstrapDrainFailureType"] = type(error).__name__
            try:
                result["bootstrapTransport"] = retain_bootstrap_capture(bootstrap, local)
                if result["bootstrapFrame"] is None:
                    result["bootstrapFrame"] = decode_bootstrap_frame(bootstrap)
            except BaseException as error:
                result["bootstrapRetentionOrFrameFailureType"] = type(error).__name__
                result["normalCompletion"] = False
                result["safetyStop"] = True
                result["outcome"] = "incomplete"
            result["bootstrapPersistenceAttempted"] = bootstrap["persistenceAttempted"]
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
    outcome = invoke_compiler_native_inputs_candidate(sys.argv[1], sys.argv[2])
    raise SystemExit(0 if outcome["normalCompletion"] else 1)
