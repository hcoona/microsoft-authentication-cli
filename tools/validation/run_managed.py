"""Run one admitted, bounded Windows Slice managed-validation action on Linux.

The accepted protocol and independent source/provenance review authorize execution.
This helper records consumption and enforces the mechanical execution boundaries.
It is not a hostile-code sandbox or a replacement for contextual admission review.
"""

# PRIVATE SOURCE-ONLY PROPOSAL. No reader or subject execution is admitted.
DRAFT_ONLY = False
if DRAFT_ONLY:
    raise RuntimeError("DRAFT_ONLY: prospective final guard history integration")

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


REPOSITORY = Path(__file__).resolve().parents[2]
ROOT = Path("/var/tmp/azureauth-windows-slice-108")
PROTOCOL = "docs/research/experiments/windows-slice-validation.md"
RUNNERS = ("tools/validation/run_managed.py", "tools/validation/fetch_packages.py")
GRANT = "a0f741b59e09f1eb95594dbfde7a6e634d962210"
WAVE_BLOB = "956aebe0e19cce7dbd08dcaa7fe83a9ef9e01f7c"
PROJECT = "tests/Authentication.Scenarios/Authentication.Scenarios.csproj"
ASSEMBLY = "tests/Authentication.Scenarios/bin/Release/net10.0/Authentication.Scenarios.dll"
RESTORE_METADATA = tuple(
    f"{directory}/obj/{name}"
    for directory, project in (
        ("src/Authentication.Core", "Authentication.Core"),
        ("tests/Authentication.Scenarios", "Authentication.Scenarios"),
    )
    for name in ("project.assets.json", f"{project}.csproj.nuget.dgspec.json",
                 f"{project}.csproj.nuget.g.props", f"{project}.csproj.nuget.g.targets")
)
SOURCE_LINK_MAPS = (
    "src/Authentication.Core/obj/Release/net10.0/Authentication.Core.sourcelink.json",
    "tests/Authentication.Scenarios/obj/Release/net10.0/Authentication.Scenarios.sourcelink.json",
)
RESTORE_0035_SHA256 = "e8517bb57c776292e0298ba3f4c3a31661a13762b019c1d4aeade093f77f3cd6"
SDK_HASHES = {
    "dotnet": "01d89e0a0191052bfea616cd4ce624c8faf13b05bbddf7f64499c23e2a9d9269",
    "sdk/10.0.401/dotnet.dll": "bf8844d3d50869c1c05ff4aaf1908a81ca657106bed52be1388a8323690f5049",
    "sdk/10.0.401/MSBuild.dll": "c00b1a9d5e458b2775ee1ea353cd8735ee5e5bf137e7c8c7a468ffa6c90c4ab4",
    "shared/Microsoft.NETCore.App/10.0.12/System.Private.CoreLib.dll":
        "26304a2985357b9ee277f273667fcd9c892edae3ee6eba76f739033e95eb39b3",
}

# Exact reviewed disposition in the protocol's "Action 0022 Build Disposition".
# This does not change the failed receipt or admit another source or execution.
DISPOSED_BUILD_HASHES = {
    "started.json": "5db34bcbc6740c80b58553d56c7aa8779c11cb21ffc115f21568fc2abe88cf4f",
    "inputs.json": "f2f2b439225c90b130c8f662d54e813e604a7c55bbec3498aba02d900151b5a8",
    "result.json": "c02ba234adac677a63147c57fa0fca240846839953743d08c08e2576dd43bba7",
    "output.txt": "b91afcbc9cd5f0437906fdb6a314f34c9b0fe3a3e9cb9d2c6044ab6032958442",
}
# Exact stopped-result disposition; the original failed receipts remain unchanged.
DISPOSED_OWNED_PROCESS_RED = {
    "started.json": "9ad80c13d63adec92abc0557b01ff9006e860d714f36455917b17a904f06d416",
    "windows-input.json": "a926fad126c073e6a0fe3127dfccc34fa3e7f846f6d920778001a66272a17bc5",
    "result.json": "70a2f2e0d177ce230ac7765e95f8682200878a466b40b698fb9af034e0615572",
}

DISPOSED_WINDOWS_PREPARATION = {
    "started.json": "b5f6e94a9240778dd028610f5c0c76fe9fafcea2aa0f27bf84d19e9839839142",
    "result.json": "437df40a2c76f7e288de3fd5d36beff41f8b0318a85a55d0b2c24a3ab179d43e",
}
DISPOSED_WINDOWS_RESTORE = {
    "started.json": "98d325740fc4c3cf7e34132faadc2494396a069e8da3885eb72ade65c34fef4c",
    "windows-input.json": "e3075e32ca4d0a5dcc0221d6102ec6ced0db89ff0f3a092f8dcb184e76c2a899",
    "result.json": "891a2040d258df4af84deccadce7388092a430416df2f94bf0e7b93f4ec9527a",
}
DISPOSED_WINDOWS_TEST = {
    "started.json": "4fb0599b8aaacbcbb2099a2254426b3ac8a2ff16cfd5cacb90222c08b648a8c9",
    "windows-input.json": "3064a64bf43690bc5efc0c9022c6fe52da8d3a36880ec76efe5d691b1fdc1989",
    "result.json": "4ef1514ecd4e19cf02657a38ed73e5e920cb30cf38df9d54472ca89b3784f6ff",
}

# Exact accepted pre-subject attendance expiry; never a general failed-action bypass.
DISPOSED_WINDOWS_ATTENDANCE = {
    "result.json": "c15dd433a4d9a104d27e529909f7a8ec28e5b38d2bfa2dcad450e469a6b94338",
    "started.json": "f4d69974990731e5a32f35df7c71935982c7fc8f480ef58d90395567cfc75e29",
    "windows-input.json": "5b47542488f8d4ec2db81cecb3b0d8fa39e349d0c9e4cb9c71a69795b61547d1",
}

# Exact accepted UI-admission attendance expiry; the failed charge remains retained.
DISPOSED_UI_ATTENDANCE = {
    "result.json": "6c4596568982d0e44924d58d8386dee0b58f6d7f73a809047bd34860a46b1766",
    "started.json": "4785c692765970cd909c341470e3d8e750f448e45bc53ad3165a70e0cdaf46a7",
    "windows-input.json": "e07476d8b99467266698e3f212c2b687c3538b57eb8484d9812456713e1f618c",
}

# Exact second UI-admission expiry, including its completed wrapper migration.
DISPOSED_UI_ATTENDANCE_0034 = {
    "result.json": "2ba6cd4445dba723dcfd30dca57772c751ccf9d3fb775e5e0bfb688da2c21d83",
    "started.json": "74efac252f02bd01ca8ab75d4d6cc179d5f1fdfcfa4bcd7132f52712d03ec940",
    "windows-input.json": "e937ebb25470f0ec025af48a4e87d5683777423e9e283d5cc328880f9f98b46f",
}
ATTENDANCE_SECONDS = 14400
# Preserve the completed preceding action boundary in shared history recovery.
DEFAULT_HTTP_PRIOR_ACTION = 49


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def disposed_build_stop(action):
    return action.name == "0022" and all(
        (action / name).is_file() and digest(action / name) == expected
        for name, expected in DISPOSED_BUILD_HASHES.items()
    )


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def git(*arguments, cwd=REPOSITORY):
    # These are local Git operations only. Hooks cannot execute candidate commands.
    return subprocess.check_output(
        ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", *arguments],
        cwd=cwd, timeout=30, stderr=subprocess.DEVNULL,
    ).decode().strip()


def group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def execute(command, cwd, environment, ceiling):
    started = time.monotonic()
    cancelled = False

    def cancel(_number, _frame):
        nonlocal cancelled
        cancelled = True

    previous = {number: signal.signal(number, cancel) for number in (signal.SIGINT, signal.SIGTERM)}
    process = None
    output, reason, quiet = bytearray(), None, False
    try:
        process = subprocess.Popen(command, cwd=cwd, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                if cancelled or time.monotonic() - started >= ceiling:
                    reason = "cancelled" if cancelled else "timeout"
                    break
                for key, _mask in selector.select(0.1):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(output) + len(chunk) > 8 * 1024 * 1024:
                        reason = "output-limit"
                        break
                    else:
                        output.extend(chunk)
                if reason:
                    break
        process.poll()  # Reap an exited leader before checking its group.
        if group_exists(process.pid):
            reason = reason or "surviving-owned-process"
            for number in (signal.SIGTERM, signal.SIGKILL):
                if not group_exists(process.pid):
                    break
                os.killpg(process.pid, number)
                until = time.monotonic() + 5
                while time.monotonic() < until and group_exists(process.pid):
                    process.poll()
                    time.sleep(0.05)
        quiet = not group_exists(process.pid)
        return {"exit_code": process.poll(), "termination": reason,
                "quiescent": quiet, "elapsed_seconds": round(time.monotonic() - started, 3)}, bytes(output)
    finally:
        if process is not None and not quiet and group_exists(process.pid):
            # Preserve an incomplete receipt if unexpected controller failure prevents
            # the normal termination/evidence path. Never continue after that state.
            os.killpg(process.pid, signal.SIGKILL)
        if process is not None and process.stdout is not None:
            process.stdout.close()
        for number, handler in previous.items():
            signal.signal(number, handler)


def snapshot(checkout):
    paths = git("ls-files", cwd=checkout).splitlines()
    return {path: digest(checkout / path) for path in paths}


def restore_inputs(checkout, config):
    # Source admission also inspects imports outside these directories. This initial
    # protocol permits only the pinned SDK, reviewed package targets and these roots.
    paths = [checkout / "global.json", config]
    for root_name in ("src", "tests"):
        for current, directories, files in os.walk(checkout / root_name):
            directories[:] = [name for name in directories if name not in ("bin", "obj")]
            paths.extend(Path(current) / name for name in files if not name.endswith(".cs"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def artifact_hashes(checkout):
    return {str(path.relative_to(checkout)): digest(path)
            for name in ("src", "tests") for path in (checkout / name).rglob("*")
            if path.is_file() and ("bin" in path.parts or path.name == "project.assets.json"
                                   or str(path.relative_to(checkout)) in SOURCE_LINK_MAPS)}


def restore_metadata_hashes(checkout):
    return {name: digest(checkout / name) for name in RESTORE_METADATA}


def restore_metadata_projection(restore, prior_actions):
    latest = None
    for action in reversed(prior_actions):
        if json.loads((action / "started.json").read_text())["action"] == "restore":
            result = json.loads((action / "result.json").read_text())
            if result["status"] != "expected-result" or result["exit_code"] != 0 or \
                    not result["continuation_allowed"] or not result["quiescent"] or \
                    result["termination"] is not None:
                raise ValueError("Latest restore did not complete successfully")
            latest = action / "restore.json"
            break
    if latest is None or restore != json.loads(latest.read_text()):
        raise ValueError("Active restore differs from its latest successful receipt")
    historical = ROOT / "actions/0035/restore.json"
    if latest == historical and digest(historical) != RESTORE_0035_SHA256:
        raise ValueError("Historical restore receipt changed")
    paths = set(restore["assets"])
    if paths == set(RESTORE_METADATA):
        return restore["assets"]
    # Preserve the exact successful receipt; only its two explained build outputs
    # leave the restore prerequisite projection. No general obj-file exemption.
    if latest != historical or paths != set(RESTORE_METADATA) | set(SOURCE_LINK_MAPS):
        raise ValueError("Unrecognized restore metadata inventory")
    return {name: restore["assets"][name] for name in RESTORE_METADATA}


def verify_source_link_transition(checkout, restore):
    if set(restore["assets"]) == set(RESTORE_METADATA):
        return
    previous = json.loads((ROOT / "build.json").read_text())
    recorded = set(SOURCE_LINK_MAPS) & set(previous["artifacts"])
    if recorded and recorded != set(SOURCE_LINK_MAPS):
        raise ValueError("Incomplete previous SourceLink build evidence")
    expected = previous["artifacts"] if recorded else restore["assets"]
    if any(digest(checkout / name) != expected[name] for name in SOURCE_LINK_MAPS):
        raise ValueError("SourceLink inputs changed before the next build")


def verify_built_source_links(checkout, source):
    expected = {"documents": {str(checkout) + "/*":
                f"https://raw.githubusercontent.com/hcoona/microsoft-authentication-cli/{source}/*"}}
    if any(json.loads((checkout / name).read_text()) != expected for name in SOURCE_LINK_MAPS):
        raise ValueError("Built SourceLink maps differ from the admitted source")


def validate_windows_reservation_pair(started, peer, link, final, start_hash, final_hash, evidence):
    """Bind the initial WSL admission to its verified Windows execution copy."""
    if evidence.get("started.json") != start_hash or evidence.get("windows-result.json") != final_hash or \
            link != {"sha256": start_hash} or final.get("reservationSha256") != start_hash:
        raise ValueError("Missing or inconsistent Windows reservation link")
    extensions = {"fileSha256", "toolSha256"}
    if started.get("action") != "bootstrap":
        extensions.update(("helperPath", "helperSha256"))
    if not extensions <= peer.keys() or extensions & started.keys() or \
            {key: value for key, value in peer.items() if key not in extensions} != started:
        raise ValueError("WSL and Windows reservation copies disagree")


def verify_windows_reservation_pair(action, windows_action, result, started):
    paths = (windows_action / "started.json", windows_action / "windows-result.json", action / "windows-input.json")
    for path in paths:
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("Linked Windows reservation evidence")

    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate Windows reservation field")
            value[key] = item
        return value

    peer, final, link = (json.loads(path.read_text(), object_pairs_hook=unique) for path in paths)
    validate_windows_reservation_pair(started, peer, link, final,
                                     digest(paths[0]), digest(paths[1]), result["evidence"])
    if int(action.name) >= 22 and started.get("action") == "test" and \
            (started.get("testSuite") in ("ui-admission", "owned-process", "default-http-composition") or
             started.get("testSuite") == "owned-host" and started.get("expected") == "green"):
        evidence = result["evidence"]
        ready_path = windows_action / "attendance-ready.json"
        released_path = windows_action / "attendance-released.json"
        for path in (ready_path, released_path):
            if any(part.is_symlink() for part in (path, *path.parents)) or path.stat().st_size > 8192:
                raise ValueError("Invalid retained attendance receipt")
        ready = json.loads(ready_path.read_text(), object_pairs_hook=unique)
        released = json.loads(released_path.read_text(), object_pairs_hook=unique)
        ready_hash, released_hash = digest(ready_path), digest(released_path)
        marker_name = "attendance-release-" + ready_hash
        wait_seconds = 1800 if int(action.name) <= 34 else ATTENDANCE_SECONDS
        if set(ready) != {"action", "reservationSha256", "waitSeconds", "invocationSha256",
                          "controllerSha256", "preparedUtc"} or ready["action"] != action.name or \
                ready["reservationSha256"] != digest(paths[0]) or type(ready["waitSeconds"]) is not int or \
                ready["waitSeconds"] != wait_seconds or ready["invocationSha256"] != evidence.get("invocation.json") or \
                ready["controllerSha256"] != evidence.get("controller.json") or \
                evidence.get("attendance-ready.json") != ready_hash or \
                evidence.get("attendance-released.json") != released_hash or \
                final.get("attendanceReadySha256") != ready_hash or \
                final.get("attendanceReleasedSha256") != released_hash or \
                set(released) != {"readySha256", "releaseName", "waitMilliseconds"} or \
                released["readySha256"] != ready_hash or released["releaseName"] != marker_name or \
                type(released["waitMilliseconds"]) is not int or not 0 <= released["waitMilliseconds"] < wait_seconds * 1000 or \
                evidence.get(marker_name) != hashlib.sha256(b"").hexdigest() or "cancel" in evidence or \
                [name for name in evidence if name.startswith("attendance-release-")] != [marker_name]:
            raise ValueError("Retained attendance binding changed")


def final_guard_process_reservation(started):
    """The sole compiler-only preparation has no ordinary test selection."""
    if started.get("action") != "final-guard-prepare" or any(
            key in started for key in ("testSuite", "expected")):
        raise ValueError("Wrong final guard preparation category")
    for key, expected in (("preparationCharge", 1), ("buildTestCharge", 0),
                          ("publishCharge", 0), ("reservedProcessScenarios", 0)):
        if type(started.get(key)) is not int or started[key] != expected:
            raise ValueError("Incorrect final guard preparation charge")
    return 0


# Exact descriptors are supplied only by a separately independently reviewed
# launcher after materializing original evidence. No CLI/environment override,
# accepted Boolean, own-source hash substitution, or new persistent ledger exists.
FINAL_GUARD_REVIEWED_BINDING = None
FINAL_GUARD_BINDING_PATH = "/tmp/windows-final-guard-history-binding.json"
FINAL_GUARD_EVIDENCE_ROOT = "/tmp/windows-final-guard-authority-inputs"
FINAL_GUARD_BINDING_REVIEW_PATH = FINAL_GUARD_EVIDENCE_ROOT + "/history-binding-review.json"
FINAL_GUARD_RECIPE_SHA256 = "ed0fa260a638d3594a18dc51cbc87b588bdfa45f4fd90c7b9ce2fec501e65bcc"
FINAL_GUARD_SOURCE_SHA256 = "973d9a6ec33c0bfeafe182ec067a67d3b9eee76212b2be71296a24e598aa32e4"
FINAL_GUARD_PREFLIGHT_SHA256 = "11a93b9504b70e2caf1e7e6c2f333f1cda178e0adcf88d5998d3eca83450e8b9"
FINAL_GUARD_PREFLIGHT_ARGV_SHA256 = "47a11709b88178a0963d560b866a79d20d9e9310407c8e161365344870897bfb"
FINAL_GUARD_AUTHORITY_SPEC = {'branch': 'main-v2',
 'components': {'controller': {'bytes': '@size',
                               'commit': '@rev',
                               'gitBlob': '@rev',
                               'repositoryPath': 'tools/validation/Invoke-WindowsFinalGuardPrepare.ps1',
                               'sha256': '@hash',
                               'tree': '@rev'},
                'dispatcher': {'bytes': '@size',
                               'commit': '@rev',
                               'gitBlob': '@rev',
                               'repositoryPath': 'tools/validation/run_windows_final_guard_prepare.py',
                               'sha256': '@hash',
                               'tree': '@rev'},
                'finalPublishController': {'bytes': '@size',
                                           'commit': '@rev',
                                           'gitBlob': '@rev',
                                           'repositoryPath': 'tools/validation/Invoke-WindowsFinalPublish.ps1',
                                           'sha256': '@hash',
                                           'tree': '@rev'},
                'finalPublishDispatcher': {'bytes': '@size',
                                           'commit': '@rev',
                                           'gitBlob': '@rev',
                                           'repositoryPath': 'tools/validation/run_windows_final_publish.py',
                                           'sha256': '@hash',
                                           'tree': '@rev'},
                'guard': {'bytes': '@size',
                          'commit': '@rev',
                          'gitBlob': '@rev',
                          'repositoryPath': 'tools/validation/WindowsFinalPublishGuard.cs',
                          'sha256': '@hash',
                          'tree': '@rev'},
                'linuxHistoryReader': {'bytes': '@size',
                                       'commit': '@rev',
                                       'gitBlob': '@rev',
                                       'repositoryPath': 'tools/validation/run_managed.py',
                                       'sha256': '@hash',
                                       'tree': '@rev'},
                'preflight': {'bytes': '@size',
                              'commit': '@rev',
                              'gitBlob': '@rev',
                              'repositoryPath': 'tools/validation/WindowsFinalGuardPreflight.body.txt',
                              'sha256': '@hash',
                              'tree': '@rev'},
                'windowsHistoryController': {'bytes': '@size',
                                             'commit': '@rev',
                                             'gitBlob': '@rev',
                                             'repositoryPath': 'tools/validation/Invoke-WindowsValidation.ps1',
                                             'sha256': '@hash',
                                             'tree': '@rev'},
                'windowsHistoryReader': {'bytes': '@size',
                                         'commit': '@rev',
                                         'gitBlob': '@rev',
                                         'repositoryPath': 'tools/validation/run_windows.py',
                                         'sha256': '@hash',
                                         'tree': '@rev'}},
 'executionAdmission': {'bytes': '@size',
                        'path': '/tmp/windows-final-guard-authority-inputs/execution-admission.json',
                        'sha256': '@hash'},
 'handoffAcceptance': {'bytes': '@size',
                       'path': '/tmp/windows-final-guard-authority-inputs/post0053-handoff-acceptance.json',
                       'sha256': '@hash'},
 'handoffManifest': {'bytes': '@size',
                     'path': '/tmp/windows-final-guard-authority-inputs/post0053-handoff.json',
                     'sha256': '@hash'},
 'handoffProtocol': {'commit': '@rev', 'sha256': '@hash'},
 'handoffSource': {'commit': '@rev', 'tree': '@rev'},
 'limits': {'accountEffects': False,
            'buildTestCharge': 0,
            'cleanupMillisecondsWithinOriginal': 10000,
            'combinedBuildTestCeiling': 120,
            'combinedPreparationCeiling': 16,
            'compilerMilliseconds': 30000,
            'externalCallMilliseconds': 30000,
            'guardPreparations': 1,
            'handshakeMilliseconds': 20000,
            'installation': False,
            'linuxPreparationCeiling': 10,
            'outerMilliseconds': 230000,
            'preflightMilliseconds': 20000,
            'preparationCharge': 1,
            'publishCharge': 0,
            'reservedProcessScenarios': 0,
            'retry': False,
            'windowsBuildTestCeiling': 48,
            'windowsPreparationCeiling': 6},
 'preflight': {'argvSha256': '47a11709b88178a0963d560b866a79d20d9e9310407c8e161365344870897bfb',
               'bodySha256': '11a93b9504b70e2caf1e7e6c2f333f1cda178e0adcf88d5998d3eca83450e8b9'},
 'protocol': {'blob': '@rev',
              'commit': '@rev',
              'path': 'docs/research/experiments/windows-slice-validation.md',
              'sha256': '@hash',
              'tree': '@rev'},
 'publication': {'bytes': '@size',
                 'path': '/tmp/windows-final-guard-authority-inputs/publication.json',
                 'sha256': '@hash'},
 'receiptPolicy': {'bytes': '@size',
                   'path': '/tmp/windows-final-guard-authority-inputs/receipt-artifact-policy.json',
                   'sha256': '@hash'},
 'recipeSha256': 'ed0fa260a638d3594a18dc51cbc87b588bdfa45f4fd90c7b9ce2fec501e65bcc',
 'repository': 'hcoona/microsoft-authentication-cli',
 'rootMarkers': {'linuxOwnerSha256': '@hash',
                 'semanticMarker': {'grant': 'a0f741b59e09f1eb95594dbfde7a6e634d962210',
                                    'issue': 108,
                                    'protocol_family': 'docs/research/experiments/windows-slice-validation.md'},
                 'windowsOwnerSha256': '@hash'},
 'schema': 'final-guard-external-authority-v1',
 'scope': 'compiler-only-final-guard-prepare',
 'source': {'commit': '@rev', 'tree': '@rev'},
 'sourceReview': {'bytes': '@size',
                  'path': '/tmp/windows-final-guard-authority-inputs/source-review.json',
                  'sha256': '@hash'},
 'target': {'commit': '@rev', 'tree': '@rev'},
 'toolSha256': {'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll': 'fd1097aed825d392a5dc8d19384381d4bb2a43498ea1c9d917f5d80c66600e1b',
                'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.dll': '2b3c17c6208a0b4b6beb94e1a066f99ba06cdb2ea919479e99d47e8c6d96dc71',
                'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe': '46809206887326d2d24db1eff1f3064de972c3451abe766b49111450a5e08e00',
                'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe.config': '2d4610ade011e530d817dd3ba4fc787e5dc0c2297cc520c30a643b8fb13f9093',
                'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.dll': '5bffb20e1217bad314143d7e5c4c809bf9f522e8a0a063c8e7e9b25113de26eb',
                'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe': '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e'},
 'wave': {'blob': '@rev', 'path': 'docs/delivery-wave.md', 'sha256': '@hash'}}


def _guard_shape(value, spec):
    if type(spec) is dict:
        if type(value) is not dict or set(value) != set(spec):
            raise ValueError("Missing or unknown final guard fields")
        for key, child in spec.items():
            _guard_shape(value[key], child)
    elif type(spec) is list:
        if type(value) is not list or len(value) != len(spec):
            raise ValueError("Wrong final guard sequence")
        for item, child in zip(value, spec):
            _guard_shape(item, child)
    elif type(spec) is str and spec.startswith("@"):
        if spec in ("@size", "@bytes", "@positive", "@nonnegative"):
            low, high = (0, 8388608) if spec in ("@size", "@bytes") else (0, 9223372036854775807)
            if spec in ("@size", "@positive"):
                low = 1
            if type(value) is not int or not low <= value <= high:
                raise ValueError("Invalid final guard integer")
        else:
            patterns = {
                "@hash": r"[0-9a-f]{64}", "@rev": r"[0-9a-f]{40}",
                "@action": r"(?!0000)[0-9]{4}", "@reviewer": r"[A-Za-z0-9_./-]{1,160}",
                "@assembly": r"WindowsFinalPublishGuard, Version=(?:[0-9]{1,5}\.){3}[0-9]{1,5}, Culture=neutral, PublicKeyToken=null",
                "@timestamp": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|\+00:00)",
            }
            if type(value) is not str or spec not in patterns or re.fullmatch(patterns[spec], value) is None:
                raise ValueError("Invalid final guard string")
            if spec == "@timestamp":
                datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if spec == "@assembly" and any(int(part) > 65535 for part in value.split("Version=", 1)[1].split(",", 1)[0].split(".")):
                raise ValueError("Invalid managed assembly version")
    elif type(value) is not type(spec) or value != spec:
        raise ValueError("Fixed final guard value changed")


def _guard_json(data):
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate final guard JSON field")
            value[key] = item
        return value
    def finite(_value):
        raise ValueError("Nonfinite final guard JSON")
    return json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique, parse_constant=finite)


def _guard_encode(value, compact=False):
    options = {"sort_keys": True, "ensure_ascii": True, "allow_nan": False}
    options.update({"separators": (",", ":")} if compact else {"indent": 2})
    return (json.dumps(value, **options) + "\n").encode("ascii")


def _guard_file(path, descriptor, state, limit=1048576):
    """Bounded direct regular-file read; every ancestor is opened without links."""
    import stat
    _guard_shape(descriptor, {"path": str(path), "bytes": "@bytes", "sha256": "@hash"})
    if descriptor["bytes"] > limit or time.monotonic() >= state["deadline"]:
        raise ValueError("Final guard input or reader time bound exceeded")
    raw_path = str(path)
    parts = raw_path.split("/")
    if not raw_path.startswith("/") or any(item in ("", ".", "..") for item in parts[1:]):
        raise ValueError("Noncanonical final guard input path")
    state["reads"] += 1
    state["bytes"] += descriptor["bytes"]
    if state["reads"] > 128 or state["bytes"] > 67108864:
        raise ValueError("Final guard cumulative read bound exceeded")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    handle = None
    try:
        for part in parts[1:-1]:
            next_parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = next_parent
        handle = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(handle)
        if not stat.S_ISREG(before.st_mode) or before.st_size != descriptor["bytes"]:
            raise ValueError("Missing, nonregular or wrong-size final guard input")
        chunks, remaining = [], before.st_size
        while remaining:
            if time.monotonic() >= state["deadline"]:
                raise TimeoutError("Final guard receipt reader expired")
            chunk = os.read(handle, min(remaining, 65536))
            if not chunk:
                raise ValueError("Truncated final guard input")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(handle, 1):
            raise ValueError("Final guard input grew during read")
        after = os.fstat(handle)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("Final guard input changed during read")
        data = b"".join(chunks)
    finally:
        if handle is not None:
            os.close(handle)
        os.close(parent)
    if hashlib.sha256(data).hexdigest() != descriptor["sha256"] or time.monotonic() >= state["deadline"]:
        raise ValueError("Final guard input hash or time bound failed")
    state["continuity"].append((raw_path, dict(descriptor), limit))
    return data


def _guard_manifest_shape(manifest, authority):
    """Validate the accepted handoff data, without replacing historical validators."""
    if type(manifest) is not dict or set(manifest) != {
            "schema", "source", "protocol", "histories", "recomputedCounters", "defaultHttpGreenAccepted"}:
        raise ValueError("Invalid original handoff fields")
    _guard_shape({key: manifest[key] for key in ("schema", "source", "protocol", "defaultHttpGreenAccepted")}, {
        "schema": "final-guard-original-history-handoff-v1", "source": authority["handoffSource"],
        "protocol": authority["handoffProtocol"], "defaultHttpGreenAccepted": True})
    if type(manifest["histories"]) is not dict or set(manifest["histories"]) != {"linux", "windows"}:
        raise ValueError("Invalid original handoff platforms")
    _guard_shape(manifest["recomputedCounters"], {"linux": ["@nonnegative"] * 4, "windows": ["@nonnegative"] * 4})
    for platform, entries in manifest["histories"].items():
        if type(entries) is not list or not 1 <= len(entries) <= 9998:
            raise ValueError("Invalid original handoff length")
        for number, item in enumerate(entries, 1):
            if type(item) is not dict or set(item) != {"number", "localEntryNames", "localFiles", "windowsFiles", "safetyMarkers"}:
                raise ValueError("Invalid original handoff entry")
            _guard_shape(item["number"], f"{number:04d}")
            names = item["localEntryNames"]
            if type(names) is not list or len(names) > 10000 or any(type(name) is not str for name in names):
                raise ValueError("Invalid original local inventory")
            if names != sorted(set(names)):
                raise ValueError("Nonunique original local inventory")
            for name in names:
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,240}", name) or name in (".", ".."):
                    raise ValueError("Nonlocal original entry name")
            for key in ("localFiles", "windowsFiles"):
                files = item[key]
                if type(files) is not dict or len(files) > 10000:
                    raise ValueError("Invalid original file inventory")
                for name, digest in files.items():
                    if type(name) is not str or len(name) > 2048 or name.startswith("/") or "\\" in name or any(
                            part in ("", ".", "..") for part in name.split("/")):
                        raise ValueError("Nonlocal original inventory path")
                    _guard_shape(digest, "@hash")
            if "started.json" not in item["localFiles"]:
                raise ValueError("Missing original reservation binding")
            markers = item["safetyMarkers"]
            if type(markers) is not dict or set(markers) != {"owned-host-safety-stop.json", "process-safety-stop.json"}:
                raise ValueError("Missing original marker dispositions")
            for digest in markers.values():
                if digest is not None:
                    _guard_shape(digest, "@hash")


def verify_accepted_final_guard_preparation(action, windows_action, started, result):
    """Consume exact original completion and independent artifact acceptance only.

    Source/schema review precedes compilation. The later reviewed launcher pins
    an external binding and its independent review; no future artifact hash is
    inserted into these reader bytes. Ordinary direct use remains unbound.
    """
    final_guard_process_reservation(started)
    if DRAFT_ONLY or FINAL_GUARD_REVIEWED_BINDING is None:
        raise ValueError("UNBOUND: separately reviewed final guard evidence binding")
    state = {"deadline": time.monotonic() + 30.0, "reads": 0, "bytes": 0, "continuity": []}
    anchor = FINAL_GUARD_REVIEWED_BINDING
    descriptor = lambda path: {"path": str(path), "bytes": "@bytes", "sha256": "@hash"}
    _guard_shape(anchor, {"binding": descriptor(FINAL_GUARD_BINDING_PATH),
                          "review": descriptor(FINAL_GUARD_BINDING_REVIEW_PATH)})
    binding_bytes = _guard_file(FINAL_GUARD_BINDING_PATH, anchor["binding"], state)
    binding = _guard_json(binding_bytes)
    review = _guard_json(_guard_file(FINAL_GUARD_BINDING_REVIEW_PATH, anchor["review"], state))
    if type(binding) is not dict:
        raise ValueError("Invalid final guard external binding")
    number = binding.get("actionNumber")
    _guard_shape(number, "@action")
    local_root = "/var/tmp/azureauth-windows-slice-108/windows-actions/" + number
    windows_root = "/mnt/c/Temp/azureauth-windows-slice-108/actions/" + number
    native_root = "C:\\Temp\\azureauth-windows-slice-108\\actions\\" + number
    if str(action) != local_root or str(windows_action) != windows_root:
        raise ValueError("Guard history action path differs from exact binding")
    paths = {
        "wslStarted": local_root + "/started.json", "wslResult": local_root + "/result.json",
        "windowsInput": local_root + "/windows-input.json", "windowsStarted": windows_root + "/started.json",
        "invocation": windows_root + "/invocation.json", "compiler": windows_root + "/compiler.json",
        "ready": windows_root + "/clock-ready.json", "reply": windows_root + "/clock-remaining.json",
        "windowsResult": windows_root + "/windows-result.json", "guardBuild": windows_root + "/guard-build.json",
        "authority": windows_root + "/authority.json", "stdout": windows_root + "/stdout.bin",
        "stderr": windows_root + "/stderr.bin", "source": windows_root + "/final-guard/source/WindowsValidationJob.cs",
        "controller": windows_root + "/final-guard/controller/Invoke-WindowsFinalGuardPrepare.ps1",
        "preflight": windows_root + "/final-guard/controller/WindowsFinalGuardPreflight.body.txt",
        "dll": windows_root + "/final-guard/WindowsFinalPublishGuard.dll",
    }
    reader_paths = {"linuxHistoryReader": str(REPOSITORY / "tools/validation/run_managed.py"),
                    "windowsHistoryReader": str(REPOSITORY / "tools/validation/run_windows.py")}
    _guard_shape(binding, {
        "schema": "final-guard-history-binding-v1", "scope": "one-original-final-guard-preparation",
        "actionNumber": number, "files": {role: descriptor(path) for role, path in paths.items()},
        "readerSources": {role: descriptor(path) for role, path in reader_paths.items()},
        "recipe": descriptor(FINAL_GUARD_EVIDENCE_ROOT + "/guard-recipe.json"),
        "completionAcceptance": descriptor(FINAL_GUARD_EVIDENCE_ROOT + "/original-completion-acceptance.json"),
        "artifactAcceptance": descriptor(FINAL_GUARD_EVIDENCE_ROOT + "/managed-artifact-acceptance.json"),
        "expectedAssemblyFullName": "@assembly", "acceptedLoaderSourceSha256": "@hash",
        "artifactAcceptanceWindowsPath": native_root + "\\final-guard\\artifact-acceptance.json",
    })
    if _guard_encode(binding, compact=True) != binding_bytes:
        raise ValueError("Noncanonical external guard binding")
    _guard_shape(review, {
        "schema": "final-guard-history-binding-review-v1", "disposition": "accepted",
        "scope": "original-completion-and-managed-artifact-history-consumption",
        "binding": anchor["binding"], "readerSources": binding["readerSources"],
        "author": "@reviewer", "reviewer": "@reviewer", "reviewedUtc": "@timestamp",
        "originalEvidenceUnchanged": True, "independentCompletionAndArtifactReview": True,
        "noExecutionGrant": True,
    })
    if review["author"] == review["reviewer"]:
        raise ValueError("Guard binding author cannot independently review it")
    sha = {role: binding["files"][role]["sha256"] for role in paths}
    completion = _guard_json(_guard_file(binding["completionAcceptance"]["path"], binding["completionAcceptance"], state))
    _guard_shape(completion, {
        "schema": "final-guard-original-completion-acceptance-v1", "disposition": "accepted",
        "scope": "one-original-compiler-controller-wsl-completion", "actionNumber": number,
        "files": binding["files"], "source": {"commit": "@rev", "tree": "@rev"},
        "protocol": FINAL_GUARD_AUTHORITY_SPEC["protocol"],
        "originalProxyExitCode": 0, "originalWindowsControllerExitCode": 0,
        "normalCompletion": True, "quiescent": True, "compilerTerminationRequested": False,
        "safetyStop": False, "originalFlagsRemainFalse": True, "reviewer": "@reviewer", "reviewedUtc": "@timestamp",
    })
    final_guard = {
        "actionNumber": number, "sourceSha256": sha["source"], "dllSha256": sha["dll"],
        "guardBuildSha256": sha["guardBuild"], "preparationWindowsResultSha256": sha["windowsResult"],
        "preparationWslResultSha256": sha["wslResult"], "preparationReservationSha256": sha["wslStarted"],
        "invocationSha256": sha["invocation"], "compilerReceiptSha256": sha["compiler"],
        "expectedAssemblyFullName": binding["expectedAssemblyFullName"],
        "acceptedLoaderSourceSha256": binding["acceptedLoaderSourceSha256"],
    }
    artifact = _guard_json(_guard_file(binding["artifactAcceptance"]["path"], binding["artifactAcceptance"], state))
    _guard_shape(artifact, {
        "schema": "final-guard-managed-artifact-acceptance-v1", "disposition": "accepted",
        "scope": "exact-managed-final-guard-source-pe-il-and-final-loader-binding", "acceptedFinalGuard": final_guard,
        "artifact": binding["files"]["dll"], "completionAcceptance": binding["completionAcceptance"],
        "managedPeAndIlReviewed": True, "sourceAndCompilerBindingReviewed": True,
        "noLoadOrSelfTestPerformed": True, "reviewer": "@reviewer", "reviewedUtc": "@timestamp",
    })
    if review["author"] in (completion["reviewer"], artifact["reviewer"]):
        raise ValueError("Originating author cannot supply independent guard acceptance")
    # No action-root read precedes the exact binding, its independent review,
    # original normal-completion acceptance and managed-artifact acceptance.
    limits = {role: (8388608 if role == "dll" else 2048 if role in ("ready", "reply") else
                    0 if role in ("stdout", "stderr") else 1048576) for role in paths}
    raw = {role: _guard_file(path, binding["files"][role], state, limits[role]) for role, path in paths.items()}
    data = {role: _guard_json(raw[role]) for role in (
        "wslStarted", "wslResult", "windowsInput", "windowsStarted", "invocation", "compiler",
        "ready", "reply", "windowsResult", "guardBuild", "authority")}
    if raw["wslStarted"] != raw["windowsStarted"] or data["wslStarted"] != started or data["wslResult"] != result:
        raise ValueError("Original guard history objects or reservation pair changed")
    for role in ("wslStarted", "wslResult", "windowsInput", "windowsStarted", "invocation", "guardBuild"):
        if _guard_encode(data[role]) != raw[role]:
            raise ValueError("Noncanonical original Python guard receipt")
    authority = data["authority"]
    _guard_shape(authority, FINAL_GUARD_AUTHORITY_SPEC)
    _guard_shape(completion["source"], authority["source"])
    _guard_shape(completion["protocol"], authority["protocol"])
    if _guard_encode(authority, compact=True) != raw["authority"]:
        raise ValueError("Noncanonical original guard authority")
    if authority["recipeSha256"] != binding["recipe"]["sha256"] or binding["recipe"]["bytes"] != 6720:
        raise ValueError("Original compiler recipe binding changed")
    recipe_bytes = _guard_file(binding["recipe"]["path"], binding["recipe"], state)
    recipe = _guard_json(recipe_bytes.replace(b"${GUARD_ACTION4}", number.encode("ascii")))
    if recipe["paths"]["windowsActionTemplate"] != native_root:
        raise ValueError("Original compiler recipe action substitution changed")
    # These are original authority evidence copies, not a new acceptance ledger.
    evidence = {}
    for role in ("sourceReview", "handoffManifest", "handoffAcceptance", "executionAdmission", "receiptPolicy"):
        item = authority[role]
        evidence[role] = _guard_json(_guard_file(item["path"], item, state, 8388608 if role == "handoffManifest" else 1048576))
    _guard_shape(evidence["sourceReview"], {
        "schema": "final-guard-source-acceptance-v1", "accepted": True,
        "scope": "guard-preparation-source-activation-and-final-callers", "source": authority["source"],
        "components": authority["components"], "callerPolicy": "fixed-final-only-callers-no-generic-helper-use",
        "protocol": authority["protocol"], "recipeSha256": FINAL_GUARD_RECIPE_SHA256,
        "preflight": authority["preflight"], "toolSha256": authority["toolSha256"],
    })
    _guard_manifest_shape(evidence["handoffManifest"], authority)
    manifest = evidence["handoffManifest"]
    _guard_shape(evidence["handoffAcceptance"], {
        "schema": "final-guard-handoff-acceptance-v1", "accepted": True,
        "scope": "complete-original-post0053-history", "source": authority["handoffSource"],
        "protocol": authority["handoffProtocol"], "manifestBinding": authority["handoffManifest"],
        "completeHistoryAccepted": True, "dispositionsAccepted": True, "greenAccepted": True,
    })
    if int(number) != len(manifest["histories"]["windows"]) + 1:
        raise ValueError("Guard is not the next original handoff action")
    policy = {"schema": "final-guard-receipt-artifact-policy-v1", "scope": "final-guard-prepare",
              "originalCompletionRequired": True, "managedArtifactReviewRequired": True,
              "artifactAcceptedOnCollection": False, "continuationAllowedOnCollection": False}
    _guard_shape(evidence["receiptPolicy"], policy)
    admission = {key: authority[key] for key in (
        "repository", "branch", "scope", "target", "wave", "protocol", "source", "handoffSource",
        "handoffProtocol", "components", "sourceReview", "handoffManifest", "handoffAcceptance",
        "receiptPolicy", "rootMarkers", "recipeSha256", "toolSha256", "preflight", "limits")}
    admission.update(schema="final-guard-execution-admission-v1", accepted=True)
    _guard_shape(evidence["executionAdmission"], admission)
    for role, item in authority["components"].items():
        owner = authority["protocol"] if role in ("linuxHistoryReader", "windowsHistoryReader", "windowsHistoryController") else authority["source"]
        if item["commit"] != owner["commit"] or item["tree"] != owner["tree"]:
            raise ValueError("Original source/protocol role changed")
    for role, path in reader_paths.items():
        original = authority["components"][role]
        expected = {"path": path, "bytes": original["bytes"], "sha256": original["sha256"]}
        _guard_shape(binding["readerSources"][role], expected)
        _guard_file(path, expected, state)
    if str(Path(__file__).absolute()) not in reader_paths.values():
        raise ValueError("Guard reader is not the accepted materialized reader")
    for role in ("source", "controller", "preflight"):
        component = authority["components"]["guard" if role == "source" else role]
        if sha[role] != component["sha256"] or len(raw[role]) != component["bytes"]:
            raise ValueError("Original guard source component changed")
    if sha["source"] != FINAL_GUARD_SOURCE_SHA256 or sha["preflight"] != FINAL_GUARD_PREFLIGHT_SHA256:
        raise ValueError("Fixed guard or preflight source changed")
    if binding["acceptedLoaderSourceSha256"] != authority["components"]["finalPublishController"]["sha256"]:
        raise ValueError("Final loader differs from original accepted source")
    authority_fields = {
        "authoritySha256": sha["authority"], "sourceReviewSha256": authority["sourceReview"]["sha256"],
        "admissionSha256": authority["executionAdmission"]["sha256"],
        "preflightBodySha256": FINAL_GUARD_PREFLIGHT_SHA256, "preflightArgvSha256": FINAL_GUARD_PREFLIGHT_ARGV_SHA256,
    }
    _guard_shape(started, {
        "action": "final-guard-prepare", "utc": "@timestamp", "protocol": authority["protocol"]["commit"],
        "source": authority["source"]["commit"], "sourceTree": authority["source"]["tree"],
        "waveBlob": authority["wave"]["blob"], "reviewSha256": authority_fields["admissionSha256"],
        "handoffSha256": authority["handoffManifest"]["sha256"], "priorCounters": manifest["recomputedCounters"],
        "reservedProcessScenarios": 0, "preparationCharge": 1, "buildTestCharge": 0, "publishCharge": 0,
        "sourceSha256": sha["source"], "sourceBlob": authority["components"]["guard"]["gitBlob"],
        "preparationControllerSha256": sha["controller"], "dispatcherSha256": authority["components"]["dispatcher"]["sha256"],
        **{key: value for key, value in authority_fields.items() if key != "admissionSha256"},
        "clockNonce": "@hash", "originalClockStartNanoseconds": "@positive", "originalClockDeadlineNanoseconds": "@positive",
    })
    if started["originalClockDeadlineNanoseconds"] - started["originalClockStartNanoseconds"] != 230000000000:
        raise ValueError("Original outer clock changed")
    lp, lb, lpub, lproc = started["priorCounters"]["linux"]
    wp, wb, wpub, wproc = started["priorCounters"]["windows"]
    if not (lp <= 10 and lb <= 80 and lpub == lproc == 0 and wp == 5 and wb <= 48 and wpub == 0 and wproc == 48
            and lp + wp + 1 <= 16 and lb + wb <= 120):
        raise ValueError("Original guard capacity handoff changed")
    _guard_shape(data["windowsInput"], {"sha256": sha["wslStarted"]})
    invocation = data["invocation"]
    _guard_shape(invocation, {
        "schema": "final-guard-invocation-v1", "action": number, "paths": recipe["paths"],
        "compiler": recipe["compilerInvocation"], "toolSha256": recipe["tools"]["sha256"],
        "reservationSha256": sha["wslStarted"], **authority_fields, "clockNonce": started["clockNonce"],
        "originalOuterLimitMilliseconds": 230000, "clockHandshakeLimitMilliseconds": 20000,
    })
    _guard_shape(data["compiler"], {"pid": "@positive", "started": "@timestamp",
                                  "sourceSha256": sha["source"], "invocationSha256": sha["invocation"]})
    clock_identity = {"action": number, "nonce": started["clockNonce"], "reservationSha256": sha["wslStarted"],
                      "invocationSha256": sha["invocation"], "originalOuterLimitMilliseconds": 230000}
    ready, reply = data["ready"], data["reply"]
    _guard_shape(ready, {"schema": "final-guard-clock-ready-v1", **clock_identity,
                         "windowsReadyElapsedTicks": "@nonnegative", "windowsClockFrequency": "@positive"})
    _guard_shape(reply, {"schema": "final-guard-clock-remaining-v1", **clock_identity,
                         "readySha256": sha["ready"], "remainingMilliseconds": "@positive"})
    if _guard_encode(reply, compact=True) != raw["reply"] or reply["remainingMilliseconds"] > 230000:
        raise ValueError("Original one-frame clock reply changed")
    ticks, frequency = ready["windowsReadyElapsedTicks"], ready["windowsClockFrequency"]
    deadline_ticks = ticks + reply["remainingMilliseconds"] * frequency // 1000
    if deadline_ticks > 9223372036854775807 or ticks * 1000 >= 20000 * frequency:
        raise ValueError("Invalid original clock deadline or ready time")
    clock = {"readySha256": sha["ready"], "replySha256": sha["reply"], "nonce": started["clockNonce"],
             "windowsReadyElapsedTicks": ticks, "windowsClockFrequency": frequency,
             "remainingMilliseconds": reply["remainingMilliseconds"], "windowsDeadlineElapsedTicks": deadline_ticks}
    window_result = data["windowsResult"]
    _guard_shape(window_result, {
        "schema": "final-guard-windows-result-v1", "reservationSha256": sha["wslStarted"],
        "invocationSha256": sha["invocation"], "normalCompletion": True, "safetyStop": False,
        "compilerCompletionConfirmed": True, "compilerTerminationRequested": False, "compilerExitCode": 0,
        "captureCompleted": True, "bothStreamsEof": True, "artifactAccepted": False, "continuation_allowed": False,
        "stage": "compiler-normal-awaiting-outer-and-artifact-review", "authorityVerified": True, **authority_fields,
        "clockHandoff": clock, "dllSha256": sha["dll"], "dllBytes": len(raw["dll"]), "startAttempted": True,
        "stdoutBytes": 0, "stderrBytes": 0, "stdoutSha256": sha["stdout"], "stderrSha256": sha["stderr"],
        "captureDisposition": "complete", "outerMilliseconds": "@nonnegative", "ended": "@timestamp",
    })
    if not raw["dll"] or window_result["outerMilliseconds"] >= 230000 or (
            window_result["outerMilliseconds"] * frequency > deadline_ticks * 1000):
        raise ValueError("Guard artifact empty or original Windows completion late")
    _guard_shape(data["guardBuild"], {
        "schema": "final-guard-build-v1", "reservationSha256": sha["wslStarted"],
        "windowsResultSha256": sha["windowsResult"], "invocationSha256": sha["invocation"],
        "sourceSha256": sha["source"], "toolSha256": invocation["toolSha256"], "dllSha256": sha["dll"],
        "dllBytes": len(raw["dll"]), "dllPath": native_root + "\\final-guard\\WindowsFinalPublishGuard.dll",
        "artifactAccepted": False, "continuation_allowed": False, "clockHandoff": clock, **authority_fields,
    })
    _guard_shape(result, {
        "normalCompletion": True, "quiescent": True, "artifactAccepted": False, "continuation_allowed": False,
        "guardBuildSha256": sha["guardBuild"], "clockHandoff": clock, "authoritySha256": sha["authority"],
        "preflightBodySha256": FINAL_GUARD_PREFLIGHT_SHA256, "preflightArgvSha256": FINAL_GUARD_PREFLIGHT_ARGV_SHA256,
        "utc": "@timestamp",
    })
    # The final caller needs a Windows path to the same acceptance bytes. Its
    # eventual materialization and launch are separate admission, not this reader.
    # Do not manufacture that Windows copy or mutate any original false flag here.
    stop_markers = (local_root + "/cancel", windows_root + "/cancel",
                    windows_root + "/temp/owned-host-safety-stop.json", windows_root + "/temp/process-safety-stop.json")
    for marker in stop_markers:
        if any(path.is_symlink() for path in (Path(marker), *Path(marker).parents)) or os.path.lexists(marker):
            raise ValueError("Guard stop marker or linked marker path forbids history continuation")
    for path, item, limit in tuple(state["continuity"]):
        _guard_file(path, item, state, limit)
    for marker in stop_markers:
        if any(path.is_symlink() for path in (Path(marker), *Path(marker).parents)) or os.path.lexists(marker):
            raise ValueError("Guard stop marker changed during final continuity check")
    if time.monotonic() >= state["deadline"]:
        raise TimeoutError("Guard history verification expired at completion")
    # Success means only this one independently accepted historical preparation
    # can be counted. It does not authorize final tests, publish, W01 or a load.
    return {**final_guard, "artifactAcceptancePath": binding["artifactAcceptanceWindowsPath"],
            "artifactAcceptanceSha256": binding["artifactAcceptance"]["sha256"]}


def windows_process_reservation(number, started):
    """Preserve historical full batches and require explicit new finite selections."""
    action = started.get("action")
    if action == "final-guard-prepare":
        return final_guard_process_reservation(started)
    if action not in ("bootstrap", "restore", "build", "test"):
        raise ValueError("Unknown Windows action allocation")
    if number <= 14:
        if "testSuite" in started:
            raise ValueError("Historical Windows selection changed")
        required = 12 if number > 9 and action == "test" else 0
    else:
        if "testSuite" not in started:
            raise ValueError("Missing Windows selection")
        suite = started["testSuite"]
        if started.get("expected") not in ("red", "green") or (action != "test" and started["expected"] != "green"):
            raise ValueError("Unexpected Windows result expectation")
        if action == "test":
            if suite not in ("cli", "adapter", "owned-host", "local-provider", "host-admission", "ui-admission", "owned-process", "msal-composition", "msal-construction", "default-http-composition") or \
                    (suite == "owned-host" and number <= 18) or \
                    (suite == "local-provider" and number <= 24) or \
                    (suite == "host-admission" and number <= 28) or \
                    (suite == "ui-admission" and number <= 32) or \
                    (suite == "owned-process" and number <= 38) or \
                    (suite == "msal-composition" and number <= 42) or \
                    (suite == "msal-construction" and number <= 46) or \
                    (suite == "default-http-composition" and
                     (type(DEFAULT_HTTP_PRIOR_ACTION) is not int or number <= DEFAULT_HTTP_PRIOR_ACTION + 1)):
                raise ValueError("Unknown Windows test selection")
            required = (12 if suite == "cli" else 10 if suite == "owned-process" else
                        2 if suite == "default-http-composition" else 0)
        else:
            if suite is not None:
                raise ValueError("Non-test Windows selection")
            required = 0
    reserved = started.get("reservedProcessScenarios", 0 if number <= 9 else None)
    if type(reserved) is not int or reserved != required:
        raise ValueError("Unrecoverable Windows process reservation")
    return reserved


def windows_consumption():
    """Recover the sibling loop while holding the existing shared action lock."""
    history = ROOT / "windows-actions"
    if not history.exists():
        return 0, 0
    if history.is_symlink():
        raise ValueError("Linked Windows action history")
    preparation, build_test, number, process_scenarios, owned_processes = 0, 0, 0, 0, 0
    default_http_processes = 0
    default_http_phases = []
    guard_preparations = 0
    windows = Path("/mnt/c/Temp/azureauth-windows-slice-108/actions")
    for number, action in enumerate(sorted(history.iterdir()), 1):
        if action.is_symlink() or action.name != f"{number:04d}":
            raise ValueError("Noncontiguous Windows action history")
        receipt = json.loads((action / "result.json").read_text())
        started = json.loads((action / "started.json").read_text())
        if any((windows / action.name / "temp" / marker).exists()
               for marker in ("owned-host-safety-stop.json", "process-safety-stop.json")):
            raise ValueError("Owned fixture safety stop forbids both validation loops")
        if action.name == "0002":
            verify_disposed_windows_preparation(action, windows / action.name)
        elif action.name == "0003":
            if {path.name for path in action.iterdir()} != set(DISPOSED_WINDOWS_RESTORE) or any(
                (action / name).is_symlink() or digest(action / name) != expected
                for name, expected in DISPOSED_WINDOWS_RESTORE.items()
            ):
                raise ValueError("Disposed Windows restore receipt changed")
        elif action.name == "0006":
            verify_disposed_windows_test(action, windows / action.name)
        elif action.name == "0022":
            verify_disposed_windows_attendance(action, windows / action.name)
        elif action.name == "0033":
            verify_disposed_windows_attendance(
                action, windows / action.name, DISPOSED_UI_ATTENDANCE)
        elif action.name == "0034":
            verify_disposed_windows_attendance(
                action, windows / action.name, DISPOSED_UI_ATTENDANCE_0034)
        elif action.name == "0039":
            verify_disposed_owned_process_red(action, windows / action.name)
        elif started.get("action") == "final-guard-prepare":
            guard_preparations += 1
            if guard_preparations != 1:
                raise ValueError("A second final guard preparation is not allocated")
            verify_accepted_final_guard_preparation(action, windows / action.name, started, receipt)
        elif receipt.get("continuation_allowed") is not True or receipt.get("quiescent") is not True:
            raise ValueError("Unresolved Windows action stops both validation loops")
        if started.get("action") != "final-guard-prepare":
            for name, expected in receipt["evidence"].items():
                if digest(windows / action.name / name) != expected:
                    raise ValueError("Windows action evidence changed")
            if action.name not in ("0002", "0003", "0006", "0022", "0033", "0034"):
                verify_windows_reservation_pair(action, windows / action.name, receipt, started)
        reserved = windows_process_reservation(number, started)
        process_scenarios += reserved
        if started.get("testSuite") == "owned-process":
            owned_processes += reserved
        if started.get("testSuite") == "default-http-composition":
            default_http_processes += reserved
            default_http_phases.append(started["expected"])
        if started["action"] in ("bootstrap", "restore", "final-guard-prepare"):
            preparation += 1
        elif started["action"] in ("build", "test"):
            build_test += 1
        else:
            raise ValueError("Unknown Windows action allocation")
    if preparation > 6 or preparation - guard_preparations > 5 or \
            build_test > 48 or process_scenarios > 60 or \
            owned_processes > 20 or default_http_processes > 4 or \
            process_scenarios - owned_processes - default_http_processes > 36 or \
            default_http_phases not in ([], ["red"], ["red", "green"]):
        raise ValueError("Windows allocation exceeded")
    if number in (2, 3):
        raise ValueError("Windows restore must complete before Linux continuation")
    if number == 6:
        raise ValueError("Windows red test must complete before Linux continuation")
    if number == 22:
        raise ValueError("Windows owned-host test must complete before Linux continuation")
    if number in (33, 34):
        raise ValueError("Windows UI-admission red must complete before Linux continuation")
    if number == 39:
        raise ValueError("Windows corrected owned-process build must complete before Linux continuation")
    return preparation, build_test


def verify_disposed_owned_process_red(action, failed):
    """Recognize only the accepted failed 0039 evidence, never a replacement result."""
    for root in (action, failed):
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise ValueError("Linked disposed owned-process evidence")
    if action.name != "0039" or {path.name for path in action.iterdir()} != set(DISPOSED_OWNED_PROCESS_RED) or any(
        not (action / name).is_file() or (action / name).is_symlink() or digest(action / name) != expected
        for name, expected in DISPOSED_OWNED_PROCESS_RED.items()
    ):
        raise ValueError("Disposed owned-process receipts changed")
    evidence = json.loads((action / "result.json").read_text())["evidence"]
    paths = list(failed.rglob("*"))
    directories = sorted(str(path.relative_to(failed)) for path in paths if path.is_dir())
    directory_hash = hashlib.sha256(json.dumps(directories, separators=(",", ":")).encode()).hexdigest()
    if directory_hash != "0ee100b271ff3f109ea874d8f2a3fde3c20741f249898d22ca62c2b56519d2aa" or \
            {str(path.relative_to(failed)) for path in paths if path.is_file()} != set(evidence):
        raise ValueError("Disposed owned-process evidence boundary changed")
    for path in paths:
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("Invalid disposed owned-process evidence entry")
        if path.is_file() and digest(path) != evidence[str(path.relative_to(failed))]:
            raise ValueError("Disposed owned-process evidence changed")


def verify_disposed_windows_attendance(action, failed, receipts=DISPOSED_WINDOWS_ATTENDANCE):
    """Preserve an exactly disposed expired wait and its empty Job evidence."""
    for root in (action, failed):
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise ValueError("Linked disposed attendance evidence")
    if {path.name for path in action.iterdir()} != set(receipts) or any(
        (action / name).is_symlink() or not (action / name).is_file() or
        digest(action / name) != expected
        for name, expected in receipts.items()
    ):
        raise ValueError("Disposed attendance receipt changed")
    evidence = json.loads((action / "result.json").read_text())["evidence"]
    directories = {"home", "home/local", "home/roaming", "temp", "results", "empty-program-files"}
    paths = list(failed.rglob("*"))
    if {str(path.relative_to(failed)) for path in paths} != directories | set(evidence):
        raise ValueError("Disposed attendance boundary changed")
    for path in paths:
        name = str(path.relative_to(failed))
        if path.is_symlink() or (name in directories and not path.is_dir()):
            raise ValueError("Disposed attendance directory changed")
        if name not in directories and (not path.is_file() or digest(path) != evidence[name]):
            raise ValueError("Disposed attendance evidence changed")


def verify_disposed_windows_preparation(action, failed):
    """Keep the exact pre-subject Windows stop in the shared capacity history."""
    for root in (action, failed):
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise ValueError("Linked disposed Windows evidence")
    if {path.name for path in action.iterdir()} != set(DISPOSED_WINDOWS_PREPARATION):
        raise ValueError("Disposed Windows reservation changed")
    for name, expected in DISPOSED_WINDOWS_PREPARATION.items():
        path = action / name
        if path.is_symlink() or digest(path) != expected:
            raise ValueError("Disposed Windows receipt changed")
    paths = list(failed.rglob("*"))
    if {str(path.relative_to(failed)) for path in paths} != {
        "home", "home/local", "home/roaming", "temp", "results",
    } or any(path.is_symlink() or not path.is_dir() for path in paths):
        raise ValueError("Disposed Windows pre-subject boundary changed")


def verify_disposed_windows_test(action, failed):
    """Retain only the exact generated-name stop and its empty pre-subject boundary."""
    for root in (action, failed):
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise ValueError("Linked disposed Windows evidence")
    if {path.name for path in action.iterdir()} != set(DISPOSED_WINDOWS_TEST) or any(
        (action / name).is_symlink() or digest(action / name) != expected
        for name, expected in DISPOSED_WINDOWS_TEST.items()
    ):
        raise ValueError("Disposed Windows test receipt changed")
    directories = {"home", "home/local", "home/roaming", "temp", "results", "empty-program-files"}
    evidence = json.loads((action / "result.json").read_text())["evidence"]
    paths = list(failed.rglob("*"))
    if {str(path.relative_to(failed)) for path in paths} != directories | set(evidence):
        raise ValueError("Disposed Windows test boundary changed")
    for path in paths:
        name = str(path.relative_to(failed))
        if path.is_symlink():
            raise ValueError("Linked disposed Windows evidence")
        if name in directories:
            if not path.is_dir():
                raise ValueError("Disposed Windows test directory changed")
        elif not path.is_file() or digest(path) != evidence[name]:
            raise ValueError("Disposed Windows test evidence changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("fetch", "restore", "build", "test"))
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--review", required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--package", action="append", default=[])
    parser.add_argument("--expect", choices=("green", "red"), default="green")
    arguments = parser.parse_args()
    os.umask(0o077)
    if platform.system() != "Linux" or platform.machine() != "x86_64" or "microsoft" not in platform.release().lower():
        raise ValueError("This protocol requires the designated WSL2 Linux x64 host")
    for revision in (arguments.protocol, arguments.source, arguments.target):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("Use full immutable commits")
    if not re.fullmatch(r"https://github.com/hcoona/microsoft-authentication-cli/pull/[0-9]+#(?:issuecomment|pullrequestreview)-[0-9]+", arguments.review):
        raise ValueError("A governing independent admission review is required")
    if arguments.expect == "red" and arguments.action != "test":
        raise ValueError("Only an executed assertion failure can be an expected red result")
    if bool(arguments.package) != (arguments.action == "fetch") or len(arguments.package) > 40:
        raise ValueError("Only fetch accepts a bounded exact package list")
    if git("rev-parse", "origin/main-v2") != arguments.target:
        raise ValueError("Refresh and inspect accepted target before execution")
    git("merge-base", "--is-ancestor", arguments.protocol, arguments.target)
    git("merge-base", "--is-ancestor", GRANT, arguments.source)
    if git("rev-parse", f"{arguments.target}:docs/delivery-wave.md") != WAVE_BLOB:
        raise ValueError("The relied-on Wave changed; refresh protocol and gate evidence")
    for path in (PROTOCOL, *RUNNERS):
        if git("hash-object", str(REPOSITORY / path)) != git("rev-parse", f"{arguments.protocol}:{path}"):
            raise ValueError("Protocol/runner bytes differ from the accepted revision")
    sdk = arguments.sdk.resolve(strict=True)
    for path, expected in SDK_HASHES.items():
        if digest(sdk / path) != expected:
            raise ValueError("Installed SDK identity mismatch")

    marker = {"issue": 108, "grant": GRANT, "protocol_family": PROTOCOL}
    if not ROOT.exists() and not ROOT.is_symlink():
        ROOT.mkdir(mode=0o700)
        write_new(ROOT / "owner.json", marker)
        (ROOT / "actions").mkdir()
        (ROOT / "feed").mkdir()
        (ROOT / "packages").mkdir()
    status = ROOT.lstat()
    if ROOT.is_symlink() or status.st_uid != os.getuid() or status.st_mode & 0o777 != 0o700:
        raise ValueError("Unexpected experiment root ownership")
    if json.loads((ROOT / "owner.json").read_text()) != marker:
        raise ValueError("Unknown experiment history")
    # Lock plus exclusive starts provides sequential, crash-visible accounting.
    with (ROOT / "action.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        windows_preparation, windows_build_test = windows_consumption()
        previous = sorted((ROOT / "actions").iterdir())
        receipts = []
        for number, action in enumerate(previous, 1):
            if action.name != f"{number:04d}":
                raise ValueError("Noncontiguous action history")
            receipt = json.loads((action / "result.json").read_text())
            prior_start = json.loads((action / "started.json").read_text())
            if action.name == "0022":
                if not disposed_build_stop(action):
                    raise ValueError("Disposed build evidence changed or is missing")
                if number == len(previous) and (
                    arguments.action != "build" or arguments.source == prior_start["source"]
                ):
                    raise ValueError("Disposed build stop requires a newly admitted corrected-source build")
            elif not receipt["continuation_allowed"]:
                raise ValueError("Previous stop requires independently accepted disposition")
            receipts.append(prior_start)
        preparation = arguments.action in ("fetch", "restore")
        if sum(item["action"] in ("fetch", "restore") for item in receipts) + preparation > 10:
            raise ValueError("Initial preparation allocation exhausted")
        if sum(item["action"] in ("build", "test") for item in receipts) + (not preparation) > 80:
            raise ValueError("Initial build/test allocation exhausted")
        if sum(item["action"] in ("fetch", "restore") for item in receipts) + preparation + windows_preparation > 16 or \
                sum(item["action"] in ("build", "test") for item in receipts) + (not preparation) + windows_build_test > 120:
            raise ValueError("Combined Linux/Windows Wave capacity exhausted")
        if sum(item["reserved_download_bytes"] for item in receipts) + (128 * 1024 * 1024 if arguments.action == "fetch" else 0) > 1024**3:
            raise ValueError("Initial public download allocation exhausted")
        action = ROOT / "actions" / f"{len(previous) + 1:04d}"
        action.mkdir()
        started = {"action": arguments.action, "utc": utc(), "protocol": arguments.protocol,
                   "target": arguments.target, "source": arguments.source,
                   "source_tree": git("rev-parse", arguments.source + "^{tree}"),
                   "review": arguments.review, "expected": arguments.expect,
                   "packages": arguments.package,
                   "reserved_download_bytes": 128 * 1024 * 1024 if arguments.action == "fetch" else 0}
        write_new(action / "started.json", started)
        result = {"continuation_allowed": False, "utc": None, "status": "controller-failed"}
        try:
            checkout = ROOT / "subject"
            if not checkout.exists():
                git("worktree", "add", "--detach", str(checkout), arguments.source)
            else:
                git("diff", "--exit-code", "HEAD", cwd=checkout)
                # Retain generated lockfiles before a later source commit adopts them.
                for path in git("ls-files", "--others", "--exclude-standard", cwd=checkout).splitlines():
                    if Path(path).name != "packages.lock.json" or not path.startswith(("src/", "tests/")):
                        raise ValueError("Unreviewed file in execution checkout")
                    if path in git("ls-tree", "-r", "--name-only", arguments.source).splitlines():
                        if git("hash-object", str(checkout / path)) != git("rev-parse", f"{arguments.source}:{path}"):
                            raise ValueError("Candidate lock differs from the retained resolution")
                        saved = action / "retained-locks" / path
                        saved.parent.mkdir(parents=True, exist_ok=True)
                        (checkout / path).rename(saved)
                git("checkout", "--detach", arguments.source, cwd=checkout)
            before = snapshot(checkout)
            for name in ("home", "temp", "results", "downloads"):
                (action / name).mkdir()
            config = ROOT / "nuget.config"
            if not config.exists():
                config.write_text('<configuration><packageSources><clear/><add key="owned" value="'
                                  + str(ROOT / "feed") + '"/></packageSources>'
                                  '<packageSourceMapping><clear/><packageSource key="owned">'
                                  '<package pattern="*"/></packageSource></packageSourceMapping>'
                                  '</configuration>\n', encoding="utf-8")
            environment = {
                "PATH": f"{sdk}:/usr/bin:/bin", "HOME": str(action / "home"),
                "TMPDIR": str(action / "temp"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "DOTNET_ROOT": str(sdk), "DOTNET_CLI_HOME": str(action / "home"),
                "NUGET_PACKAGES": str(ROOT / "packages"),
                "NUGET_HTTP_CACHE_PATH": str(action / "home" / "http"),
                "NUGET_PLUGINS_CACHE_PATH": str(action / "home" / "plugins"),
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "TESTINGPLATFORM_TELEMETRY_OPTOUT": "1",
                "DOTNET_NUGET_SIGNATURE_VERIFICATION": "false",
                "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false",
                "DOTNET_ADD_GLOBAL_TOOLS_TO_PATH": "false", "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true",
                "DOTNET_CLI_USE_MSBUILD_SERVER": "0", "MSBUILDDISABLENODEREUSE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            dotnet = str(sdk / "dotnet")
            if arguments.action == "fetch":
                command = ["/usr/bin/python3", "-I", str(REPOSITORY / RUNNERS[1]),
                           str(action / "downloads"), *arguments.package]
            elif arguments.action == "restore":
                command = [dotnet, "restore", PROJECT, "--configfile", str(config),
                           "--packages", str(ROOT / "packages"), "--disable-parallel", "--verbosity", "minimal",
                           "-p:NuGetAudit=false", "-p:RestorePackagesWithLockFile=true",
                           "-p:UseSharedCompilation=false", "-m:1", "-nr:false"]
                if (checkout / "tests/Authentication.Scenarios/packages.lock.json").exists():
                    command.append("--locked-mode")
            else:
                restore = json.loads((ROOT / "restore.json").read_text())
                if restore["inputs"] != restore_inputs(checkout, config) or \
                        restore_metadata_projection(restore, previous) != restore_metadata_hashes(checkout):
                    raise ValueError("Restore inputs or generated assets changed")
                if arguments.action == "build":
                    verify_source_link_transition(checkout, restore)
                    command = [dotnet, "build", PROJECT, "-c", "Release", "--no-restore",
                               "--disable-build-servers", "-m:1", "-nr:false",
                               "-p:UseSharedCompilation=false", "--verbosity", "minimal"]
                else:
                    build = json.loads((ROOT / "build.json").read_text())
                    if build["source"] != arguments.source or build["artifacts"] != artifact_hashes(checkout):
                        raise ValueError("No unchanged successful build for this source")
                    command = [dotnet, ASSEMBLY, "--report-trx", "--results-directory", str(action / "results")]
            write_new(action / "inputs.json", {"command": command, "environment": environment,
                                               "source_hashes": before, "toolchain_hashes": SDK_HASHES})
            outcome, output = execute(command, checkout, environment, 180 if preparation else 120)
            (action / "output.txt").write_bytes(output)
            result.update(outcome)
            expected_exit = 2 if arguments.expect == "red" else 0
            passed = outcome["quiescent"] and outcome["termination"] is None and outcome["exit_code"] == expected_exit
            if snapshot(checkout) != before:
                raise ValueError("Tracked source changed during execution")
            if arguments.action == "test" and passed:
                files = list((action / "results").glob("*.trx"))
                if len(files) != 1:
                    raise ValueError("Missing or ambiguous TRX evidence")
                counters = ET.parse(files[0]).find(".//{*}Counters")
                if counters is None or int(counters.attrib["executed"]) == 0:
                    raise ValueError("No executed business tests")
                failed = int(counters.attrib["failed"])
                passed = (failed > 0) if arguments.expect == "red" else (failed == 0)
                result["tests"] = counters.attrib
            if arguments.action == "fetch" and passed:
                for package in (action / "downloads").glob("*.nupkg"):
                    target = ROOT / "feed" / package.name
                    if target.exists():
                        raise ValueError("A package identity was already fetched")
                    os.link(package, target)
            if arguments.action == "restore" and passed:
                restored = {"inputs": restore_inputs(checkout, config),
                            "assets": restore_metadata_hashes(checkout)}
                write_new(action / "restore.json", restored)
                (ROOT / "restore.json").write_text(json.dumps(restored), encoding="utf-8")
            if arguments.action == "build" and passed:
                verify_built_source_links(checkout, arguments.source)
                built = {"source": arguments.source, "artifacts": artifact_hashes(checkout)}
                write_new(action / "build.json", built)
                (ROOT / "build.json").write_text(json.dumps(built), encoding="utf-8")
            result.update(status="expected-result" if passed else "unexpected-result", continuation_allowed=passed)
        except Exception as error:
            result["error_type"] = type(error).__name__
        finally:
            result["utc"] = utc()
            write_new(action / "result.json", result)
        print(json.dumps({"action": action.name, **result}))
        return 0 if result["continuation_allowed"] else 1


if __name__ == "__main__":
    sys.exit(main())
