"""Import-safe, production-used exact 0054/0055 history validation.

Import performs no I/O. Production wrappers bind this module's actual source;
fixtures use the same predicates with a closed in-memory byte/metadata backend.
"""
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

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
FINAL_GUARD_BINDING_PATH = "/tmp/windows-final-guard-0055-history-binding.json"
FINAL_GUARD_EVIDENCE_ROOT = "/tmp/windows-final-guard-0055-authority-inputs"
FINAL_GUARD_BINDING_REVIEW_PATH = FINAL_GUARD_EVIDENCE_ROOT + "/history-binding-review.json"
FINAL_GUARD_RECIPE_SHA256 = "ed0fa260a638d3594a18dc51cbc87b588bdfa45f4fd90c7b9ce2fec501e65bcc"
FINAL_GUARD_SOURCE_SHA256 = "d38846b080d5ee092fae9e21c9031712b56289093b50ca048d50589cca50ff4b"
FINAL_GUARD_PREFLIGHT_SHA256 = "11a93b9504b70e2caf1e7e6c2f333f1cda178e0adcf88d5998d3eca83450e8b9"
FINAL_GUARD_PREFLIGHT_ARGV_SHA256 = "47a11709b88178a0963d560b866a79d20d9e9310407c8e161365344870897bfb"
ORIGINAL_AUTHORITY_SPEC = {'branch': 'main-v2',
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
                        'path': '/tmp/windows-final-guard-authority-inputs/execution-admission-v2.json',
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
                 'path': '/tmp/windows-final-guard-authority-inputs/publication-v2.json',
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
                  'path': '/tmp/windows-final-guard-authority-inputs/source-review-v2.json',
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


def verify_success(action, windows_action, started, result, anchor, reader_paths, state):
    """Consume exact original completion and independent artifact acceptance only.

    Source/schema review precedes compilation. The later reviewed launcher pins
    an external binding and its independent review; no future artifact hash is
    inserted into these reader bytes. Ordinary direct use remains unbound.
    """
    if anchor is None or state.get("failedValidated") is not True:
        raise ValueError("UNBOUND: successor context and successful evidence")
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
    _guard_shape(binding, {
        "schema": "final-guard-history-binding-v2", "scope": "one-original-final-guard-preparation",
        "actionNumber": "0055", "files": {role: descriptor(path) for role, path in paths.items()},
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
    if raw["wslStarted"] != raw["windowsStarted"] or (started is not None and data["wslStarted"] != started) or (result is not None and data["wslResult"] != result):
        raise ValueError("Original guard history objects or reservation pair changed")
    started, result = data["wslStarted"], data["wslResult"]
    final_guard_process_reservation(started)
    for role in ("wslStarted", "wslResult", "windowsInput", "windowsStarted", "invocation", "guardBuild"):
        if _guard_encode(data[role]) != raw[role]:
            raise ValueError("Noncanonical original Python guard receipt")
    authority = data["authority"]
    _guard_shape(authority, FINAL_GUARD_AUTHORITY_SPEC)
    if (authority["failedGuardDisposition"] != state["dispositionBinding"] or authority["fixtureDisposition"] != state["fixtureBinding"] or
            authority["handoffManifest"] != state["disposition"]["baseHandoff"] or
            authority["handoffAcceptance"] != state["disposition"]["baseHandoffAcceptance"]):
        raise ValueError("Successor disposition binding changed")
    module_source = state.get("moduleBinding")
    component = authority["components"]["guardHistory"]
    if module_source is None or component["bytes"] != module_source["bytes"] or component["sha256"] != module_source["sha256"]:
        raise ValueError("Actual guard-history module differs from successor authority")
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
        "schema": "final-guard-source-acceptance-v2", "accepted": True,
        "scope": "guard-preparation-source-activation-and-final-callers", "source": authority["source"],
        "components": authority["components"], "callerPolicy": "fixed-final-only-callers-no-generic-helper-use",
        "protocol": authority["protocol"], "recipeSha256": FINAL_GUARD_RECIPE_SHA256,
        "preflight": authority["preflight"], "toolSha256": authority["toolSha256"],
        "failedGuardDisposition": authority["failedGuardDisposition"],
        "fixtureDisposition": authority["fixtureDisposition"],
    })
    _guard_manifest_shape(evidence["handoffManifest"], authority)
    manifest = evidence["handoffManifest"]
    if manifest["recomputedCounters"] != {"linux": [8, 37, 0, 0], "windows": [5, 48, 0, 48]}:
        raise ValueError("Original M53 counters changed")
    _guard_shape(evidence["handoffAcceptance"], {
        "schema": "final-guard-handoff-acceptance-v1", "accepted": True,
        "scope": "complete-original-post0053-history", "source": authority["handoffSource"],
        "protocol": authority["handoffProtocol"], "manifestBinding": authority["handoffManifest"],
        "completeHistoryAccepted": True, "dispositionsAccepted": True, "greenAccepted": True,
    })
    if number != "0055" or len(manifest["histories"]["windows"]) != 53:
        raise ValueError("Guard is not the next original handoff action")
    policy = {"schema": "final-guard-receipt-artifact-policy-v1", "scope": "final-guard-prepare",
              "originalCompletionRequired": True, "managedArtifactReviewRequired": True,
              "artifactAcceptedOnCollection": False, "continuationAllowedOnCollection": False}
    _guard_shape(evidence["receiptPolicy"], policy)
    admission = {key: authority[key] for key in (
        "repository", "branch", "scope", "target", "wave", "protocol", "source", "handoffSource",
        "handoffProtocol", "components", "sourceReview", "handoffManifest", "handoffAcceptance",
        "receiptPolicy", "rootMarkers", "recipeSha256", "toolSha256", "preflight", "limits",
        "failedGuardDisposition", "fixtureDisposition")}
    admission.update(schema="final-guard-execution-admission-v2", accepted=True)
    _guard_shape(evidence["executionAdmission"], admission)
    for role, item in authority["components"].items():
        owner = authority["protocol"] if role in ("linuxHistoryReader", "windowsHistoryReader", "windowsHistoryController", "guardHistory") else authority["source"]
        if item["commit"] != owner["commit"] or item["tree"] != owner["tree"]:
            raise ValueError("Original source/protocol role changed")
    for role, path in reader_paths.items():
        original = authority["components"][role]
        expected = {"path": path, "bytes": original["bytes"], "sha256": original["sha256"]}
        _guard_shape(binding["readerSources"][role], expected)
        _guard_file(path, expected, state)
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
        "handoffSha256": authority["handoffManifest"]["sha256"], "priorCounters": SUCCESSOR_PRIOR,
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
    if not (started["priorCounters"] == SUCCESSOR_PRIOR and lp <= 9 and lb <= 80 and lpub == lproc == 0
            and wp == 6 and wb <= 48 and wpub == 0 and wproc == 48
            and lp + wp + 1 <= 16 and combined_build_test(lb, wb) <= 120):
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
        if state["io"].metadata(marker)["status"] != "absent":
            raise ValueError("Guard stop marker forbids successful history")
    state["successMarkers"] = stop_markers
    check(state)
    state["successStarted"], state["successResult"] = started, result
    # Success means only this one independently accepted historical preparation
    # can be counted. It does not authorize final tests, publish, W01 or a load.
    return {**final_guard, "artifactAcceptancePath": binding["artifactAcceptanceWindowsPath"],
            "artifactAcceptanceSha256": binding["artifactAcceptance"]["sha256"]}



# Successor-only admission; original v1 survives solely as failed0054 evidence.
D54_PATH = "/tmp/windows-final-guard-0054-failed-history-disposition-v1.json"
FIXTURE_ROOT = "/tmp/windows-final-guard-successor-fixture-0055-v1"
FIXTURE_DISPOSITION_PATH = FINAL_GUARD_EVIDENCE_ROOT + "/fixture-disposition.json"
SUCCESSOR_PRIOR = {"linux": [8, 37, 0, 0], "windows": [6, 48, 0, 48]}
FINAL_GUARD_AUTHORITY_SPEC = copy.deepcopy(ORIGINAL_AUTHORITY_SPEC)
FINAL_GUARD_AUTHORITY_SPEC["schema"] = "final-guard-external-authority-v2"
FINAL_GUARD_AUTHORITY_SPEC["limits"].update(guardPreparations=2, linuxPreparationCeiling=9,
    windowsPreparationCeiling=7, fixtureBuildTestCharge=1)
for _role in ("sourceReview", "executionAdmission", "publication"):
    FINAL_GUARD_AUTHORITY_SPEC[_role]["path"] = FINAL_GUARD_EVIDENCE_ROOT + "/" + ORIGINAL_AUTHORITY_SPEC[_role]["path"].rsplit("/", 1)[1]
FINAL_GUARD_AUTHORITY_SPEC["failedGuardDisposition"] = {"path": D54_PATH, "bytes": "@size", "sha256": "@hash"}
FINAL_GUARD_AUTHORITY_SPEC["fixtureDisposition"] = {"path": FIXTURE_DISPOSITION_PATH, "bytes": "@size", "sha256": "@hash"}
FINAL_GUARD_AUTHORITY_SPEC["components"]["guardHistory"] = {
    "commit": "@rev", "tree": "@rev", "repositoryPath": "tools/validation/final_guard_history.py",
    "gitBlob": "@rev", "bytes": "@size", "sha256": "@hash"}


def check(state):
    if time.monotonic() >= state["deadline"]:
        raise TimeoutError("Shared guard-validation deadline expired")
    if state["reads"] > 128 or state["bytes"] > 67108864:
        raise ValueError("Shared guard-validation read envelope exceeded")


def new_state(io=None, deadline=None):
    return {"deadline": min(time.monotonic() + 30.0, deadline) if deadline is not None else time.monotonic() + 30.0,
            "reads": 0, "bytes": 0, "continuity": {}, "io": io if io is not None else FileIO(),
            "failedValidated": False, "fixtureValidated": False, "finished": False}


def file_metadata(info):
    return {"status": "present", "type": "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "other",
            "device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size,
            "mode": stat.S_IMODE(info.st_mode), "mtime": info.st_mtime_ns, "ctime": info.st_ctime_ns}


class FileIO:
    """Real no-follow transport. Validation and accounting remain above this seam."""
    def parent(self, path):
        parts = str(path).split("/")
        if not str(path).startswith("/") or not 1 < len(parts) <= 17 or any(p in ("", ".", "..") for p in parts[1:]):
            raise ValueError("Noncanonical or overdeep fixed path")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, size, state):
        parent, leaf = self.parent(path)
        fd = None
        try:
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = file_metadata(os.fstat(fd))
            if before["type"] != "file" or before["bytes"] != size:
                raise ValueError("Nonregular or wrong-size input")
            parts = []
            remaining = size
            while remaining:
                check(state)
                part = os.read(fd, min(remaining, 65536))
                if not part:
                    raise ValueError("Truncated guard input")
                parts.append(part)
                remaining -= len(part)
            extra = os.read(fd, 1)
            after = file_metadata(os.fstat(fd))
            return b"".join(parts) + extra, before, after
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def metadata(self, path):
        try:
            parent, leaf = self.parent(path)
        except FileNotFoundError:
            return {"status": "absent"}
        try:
            try:
                return file_metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
            except FileNotFoundError:
                return {"status": "absent"}
        finally:
            os.close(parent)


def _guard_file(path, descriptor, state, limit=1048576, *, track=True):
    _guard_shape(descriptor, {"path": str(path), "bytes": "@bytes", "sha256": "@hash"})
    if descriptor["bytes"] > limit:
        raise ValueError("Guard input exceeds its fixed bound")
    check(state)
    state["reads"] += 1
    state["bytes"] += descriptor["bytes"] + 1
    check(state)
    raw, before, after = state["io"].read(str(path), descriptor["bytes"], state)
    if before != after or before.get("type") != "file" or len(raw) != descriptor["bytes"] or before.get("bytes") != len(raw):
        raise ValueError("Fresh guard input metadata/size changed")
    if hashlib.sha256(raw).hexdigest() != descriptor["sha256"]:
        raise ValueError("Guard input hash changed")
    if track:
        previous = state["continuity"].get(str(path))
        entry = (dict(descriptor), limit)
        if previous is not None and previous != entry:
            raise ValueError("Conflicting private descriptor")
        state["continuity"][str(path)] = entry
    check(state)
    return raw


def finish(state):
    if state["finished"]:
        raise ValueError("Guard transaction already finalized")
    for path, (item, limit) in tuple(state["continuity"].items()):
        _guard_file(path, item, state, limit, track=False)
    for path in state.get("successMarkers", ()):
        if state["io"].metadata(path)["status"] != "absent":
            raise ValueError("Successful guard stop marker changed")
    check(state)
    state["finished"] = True


def combined_build_test(linux, windows, prospective=0):
    if any(type(value) is not int or value < 0 for value in (linux, windows, prospective)):
        raise ValueError("Invalid build/test counter")
    total = linux + windows + 1 + prospective
    if total > 120:
        raise ValueError("Combined capacity including singleton fixture exceeded")
    return total

D54_SPEC = {'actionNumber': '0054', 'charge': {'buildTest': 0, 'preparation': 1, 'publish': 0, 'syntheticProcessScenarios': 0}, 'contentFiles': {'authority': {'bytes': 7161, 'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/authority.json', 'sha256': 'eab860fa6249ec583e33a637c2c9b0c12ae3302d3b1d2ae4bd3278fb729a55cc'}, 'controller': {'bytes': 43873, 'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/final-guard/controller/Invoke-WindowsFinalGuardPrepare.ps1', 'sha256': 'ea93b4eecfea6eed623a3149b648e93686db4f8bafa81561ff28ad0379e4ebae'}, 'invocation': {'bytes': 7001, 'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/invocation.json', 'sha256': '0a825b6d574b939e735e039ba4649510c4776f668b40c6ac70f610798982f936'}, 'windowsInput': {'bytes': 83, 'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054/windows-input.json', 'sha256': '77031c737e1dc79a1201be35503c10ca9a11b29fdf592e69062d59714c157193'}, 'windowsStarted': {'bytes': 1632, 'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/started.json', 'sha256': '3ed0846d150abd790c9a0793df686d04a3e924eaccaca68f96f802c67ae89a07'}, 'wslResult': {'bytes': 194, 'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054/result.json', 'sha256': 'feee51e22fab6207ddc7f9ec7c0a2db03b038a9a350cad4c1f050f7750c10d58'}, 'wslStarted': {'bytes': 1632, 'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054/started.json', 'sha256': '3ed0846d150abd790c9a0793df686d04a3e924eaccaca68f96f802c67ae89a07'}}, 'fixedMetadata': {'compiler': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/compiler.json', 'status': 'absent'}, 'compilerPending': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/compiler.json.pending', 'status': 'absent'}, 'dll': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/final-guard/WindowsFinalPublishGuard.dll', 'status': 'absent'}, 'guardBuild': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/guard-build.json', 'status': 'absent'}, 'hostSafetyStop': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/temp/owned-host-safety-stop.json', 'status': 'absent'}, 'processSafetyStop': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/temp/process-safety-stop.json', 'status': 'absent'}, 'ready': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/clock-ready.json', 'status': 'absent'}, 'readyPending': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/clock-ready.json.pending', 'status': 'absent'}, 'reply': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/clock-remaining.json', 'status': 'absent'}, 'stderr': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/stderr.bin', 'status': 'absent'}, 'stdout': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/stdout.bin', 'status': 'absent'}, 'windowsCancel': {'bytes': 0, 'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/cancel', 'status': 'present', 'type': 'file'}, 'windowsDirectory': {'bytes': 4096, 'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054', 'status': 'present', 'type': 'directory'}, 'windowsResult': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/windows-result.json', 'status': 'absent'}, 'windowsResultPending': {'path': '/mnt/c/Temp/azureauth-windows-slice-108/actions/0054/windows-result.json.pending', 'status': 'absent'}, 'wslCancel': {'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054/cancel', 'status': 'absent'}, 'wslDirectory': {'bytes': 4096, 'path': '/var/tmp/azureauth-windows-slice-108/windows-actions/0054', 'status': 'present', 'type': 'directory'}}, 'historicalInference': {'artifactAccepted': False, 'continuationAllowed': False, 'currentProcessOwnershipAccepted': False, 'currentQuiescenceAccepted': False, 'globalMetadataStabilityAccepted': False, 'normalCompletionAccepted': False, 'safeIntentionalRetentionAccepted': True}, 'originalResultFlags': {'artifactAccepted': False, 'continuation_allowed': False, 'failureType': 'RuntimeError', 'normalCompletion': False, 'quiescent': False}, 'schema': 'final-guard-failed-history-disposition-v1', 'scope': 'retain-and-count-original-0054-only', 'canonicalDisposition': {'commit': '0ee05baea76aa685c98d92267ee8a407ca2a9dae', 'tree': '8a93cfb8c9a2a249a81b8cdbd914ecff9b1fc758', 'path': 'docs/research/experiments/windows-slice-validation.md', 'blob': '03c54f0c1808278349233279dea182cf764760f3', 'sha256': '2c9325c81557a141e471b4bb62319171eb717fa1515fa5226753511262760840'}, 'originalAuthority': {'bytes': 7161, 'path': '/tmp/windows-final-guard-execution-authority.json', 'sha256': 'eab860fa6249ec583e33a637c2c9b0c12ae3302d3b1d2ae4bd3278fb729a55cc'}, 'baseHandoff': {'bytes': 172997, 'path': '/tmp/windows-final-guard-authority-inputs/post0053-handoff.json', 'sha256': 'e3668dc613dac94bdfeaad6dc7f64db4abf54297b5249d2b42055556a105f175'}, 'baseHandoffAcceptance': {'bytes': 626, 'path': '/tmp/windows-final-guard-authority-inputs/post0053-handoff-acceptance.json', 'sha256': '7a864b8a5f8568ef444fb5a45185fc4b8da50f08aa0f72f5120186bf1fe3530c'}, 'originalGuardCall': {'bytes': 1551, 'path': '/tmp/windows-final-guard-preparation-original-call-failure-v1.json', 'sha256': '2e2b3cd67bb32d4c19ba8eb8b45b91f00a04249925fd4b1db5abe52848af385b'}, 'originalGuardOutput': {'bytes': 169, 'path': '/tmp/windows-final-guard-preparation-original-output-v1.txt', 'sha256': '99263a024b0463175678aa46330b36f830f5501845ae28caa92730320b37222c'}, 'observation': {'inventory': {'bytes': 30694, 'path': '/tmp/windows-final-guard-failure-observation2-offline-v1/observation.json', 'sha256': '46b119069d4f3d18fb9c067a32f2f6d8e2605b49365d99b0a2a982cb8f992614'}, 'journal': {'bytes': 29775, 'path': '/tmp/windows-final-guard-failure-observation2-offline-v1/events.jsonl', 'sha256': 'f2efe2a56d230c0617a93c8e828f275547f3da3b5fcf408a303dfa60f2c7833b'}, 'originalCall': {'bytes': 1342, 'path': '/tmp/windows-final-guard-failure-observer2-original-call-v1.json', 'sha256': '26036800f0ab97ccd5be62ddb2d3dc8b372e42d6dc6affe2ecdbd8e397110215'}, 'originalOutput': {'bytes': 476, 'path': '/tmp/windows-final-guard-failure-observer2-original-output-v1.txt', 'sha256': 'a5243748164384386b96145a07a68faaff52bf9d021e546b42da3fbfa00407e3'}}, 'independentReview': {'bytes': 16278, 'path': '/tmp/windows-final-guard-failure-observer2-actual-evidence-independent-review-v1.json', 'sha256': 'bebc44af86761c114a5f337db5cd45a6b5e48c8643352d6056bc6da10a7eb850'}}


def load_context(disposition, fixture, state):
    if state.get("contextLoaded"):
        if (state["dispositionBinding"], state["fixtureBinding"]) != (disposition, fixture):
            raise ValueError("Conflicting successor context")
        return
    _guard_shape(disposition, {"path": D54_PATH, "bytes": "@size", "sha256": "@hash"})
    _guard_shape(fixture, {"path": FIXTURE_DISPOSITION_PATH, "bytes": "@size", "sha256": "@hash"})
    d = _guard_json(_guard_file(D54_PATH, disposition, state))
    _guard_shape(d, D54_SPEC)
    authority = d["originalAuthority"]
    _guard_shape(_guard_json(_guard_file(authority["path"], authority, state)), ORIGINAL_AUTHORITY_SPEC)
    item = d["independentReview"]
    review = _guard_json(_guard_file(item["path"], item, state))
    if review.get("acceptanceFlags", {}).get("historicalFailedAttemptSafeRetentionAccepted") is not True:
        raise ValueError("Original historical retention was not independently accepted")
    verify_fixture(fixture, state)
    state.update(contextLoaded=True, disposition=d, dispositionBinding=dict(disposition), fixtureBinding=dict(fixture))


def verify_fixture(binding, state):
    value = _guard_json(_guard_file(binding["path"], binding, state))
    desc = lambda path: {"path": path, "bytes": "@bytes", "sha256": "@hash"}
    expected = {
        "schema": "final-guard-successor-fixture-disposition-v1", "accepted": True,
        "scope": "one-charged-offline-successor-validator-fixture", "buildTestCharge": 1,
        "baselineProductCounters": {"linux": 37, "windows": 48},
        "original": {"start": desc(FIXTURE_ROOT + "/started.json"), "result": desc(FIXTURE_ROOT + "/result.json"),
                     "output": desc(FIXTURE_ROOT + "/output.jsonl")},
        "review": desc(FINAL_GUARD_EVIDENCE_ROOT + "/fixture-independent-review.json")}
    _guard_shape(value, expected)
    records = {role: _guard_file(item["path"], item, state, 65536) for role, item in value["original"].items()}
    start, result = _guard_json(records["start"]), _guard_json(records["result"])
    _guard_shape(start, {"schema": "final-guard-successor-fixture-start-v1", "fixtureOnly": True,
                        "buildTestCharge": 1, "baselineProductCounters": {"linux": 37, "windows": 48},
                        "admissionSha256": "@hash", "utc": "@timestamp"})
    _guard_shape(result, {"schema": "final-guard-successor-fixture-result-v1", "fixtureOnly": True,
                         "startSha256": hashlib.sha256(records["start"]).hexdigest(),
                         "outputSha256": hashlib.sha256(records["output"]).hexdigest(),
                         "buildTestCharge": 1, "passed": True, "normalCompletion": True,
                         "cases": "@positive", "validatorCalls": "@positive", "utc": "@timestamp"})
    if result["cases"] > 24 or result["validatorCalls"] > 72:
        raise ValueError("Fixture count envelope exceeded")
    item = value["review"]
    review = _guard_json(_guard_file(item["path"], item, state))
    _guard_shape(review, {"schema": "final-guard-successor-fixture-review-v1", "accepted": True,
                         "original": value["original"], "originalExitCode": 0, "fullyCollected": True,
                         "buildTestCharge": 1, "author": "@reviewer", "reviewer": "@reviewer",
                         "sourceAndRecipeBound": True, "noExecutionGrant": True})
    if review["author"] == review["reviewer"]:
        raise ValueError("Fixture author cannot independently accept it")
    state["fixtureValidated"] = True


def verify_failed(action, windows_action, started, result, state):
    if not state.get("contextLoaded") or state["failedValidated"]:
        raise ValueError("Missing context or duplicate failed0054")
    if str(action) != "/var/tmp/azureauth-windows-slice-108/windows-actions/0054" or str(windows_action) != "/mnt/c/Temp/azureauth-windows-slice-108/actions/0054":
        raise ValueError("Only exact original0054 may be disposed")
    d = state["disposition"]
    snapshots = []
    originals = []
    for _pass in range(2):
        check(state)
        observed = {}
        for role, expected in d["fixedMetadata"].items():
            check(state)
            actual = state["io"].metadata(expected["path"])
            if expected["status"] == "absent":
                if actual != {"status": "absent"}:
                    raise ValueError("Previously absent failed0054 path appeared")
            elif actual.get("status") != "present" or actual.get("type") != expected["type"]:
                raise ValueError("Failed0054 metadata role kind changed")
            elif role == "windowsCancel" and actual.get("bytes") != 0:
                raise ValueError("Failed0054 cancel marker changed")
            observed[role] = actual
        snapshots.append(observed)
        if _pass == 0:
            for _content_pass in range(2):
                originals.append({role: _guard_file(item["path"], item, state, 65536, track=False)
                                  for role, item in d["contentFiles"].items()})
    if snapshots[0] != snapshots[1] or originals[0] != originals[1]:
        raise ValueError("Fresh failed0054 evidence changed")
    raw = originals[0]
    original_start, original_result = _guard_json(raw["wslStarted"]), _guard_json(raw["wslResult"])
    if raw["wslStarted"] != raw["windowsStarted"] or (started is not None and original_start != started) or (result is not None and original_result != result):
        raise ValueError("Failed0054 receipt pair or caller objects changed")
    if any(original_result.get(key) != value for key, value in d["originalResultFlags"].items()):
        raise ValueError("Original failed flags changed")
    if _guard_json(raw["windowsInput"]) != {"sha256": d["contentFiles"]["wslStarted"]["sha256"]}:
        raise ValueError("Failed0054 Windows-input join changed")
    final_guard_process_reservation(original_start)
    if original_start["priorCounters"] != {"linux": [8, 37, 0, 0], "windows": [5, 48, 0, 48]}:
        raise ValueError("Original0054 prior counters changed")
    state["failedValidated"] = True
    state["failedStarted"], state["failedResult"] = original_start, original_result
    return {"kind": "disposed-failed-0054", "preparationCharge": 1, "artifactAccepted": False,
            "continuation_allowed": False}


def validate_history_action(consumer, action, windows_action, started, result, state,
                            success_anchor=None, reader_paths=None):
    if consumer not in ("linux-reader", "windows-reader", "dispatcher"):
        raise ValueError("Unknown guard-history consumer")
    if Path(action).name == "0054":
        return verify_failed(action, windows_action, started, result, state)
    if Path(action).name != "0055" or state.get("successValidated"):
        raise ValueError("Unallocated, reordered or duplicate guard preparation")
    value = verify_success(action, windows_action, started, result, success_anchor, reader_paths, state)
    state["successValidated"] = True
    return value


def successor_reservation(totals, starts, count, state):
    if not state.get("failedValidated") or not state.get("fixtureValidated") or count != 54 or totals != SUCCESSOR_PRIOR:
        raise ValueError("Exact disposed0054 and unchanged product prefix required")
    if [start["action"] for start in starts].count("final-guard-prepare") != 1:
        raise ValueError("Only original0054 may precede successor")
    if sum(start["action"] == "bootstrap" for start in starts) != 1 or sum(start["action"] == "restore" for start in starts) != 4:
        raise ValueError("Original bootstrap/restore composition changed")
    lp, lb, _, _ = totals["linux"]
    wp, wb, publish, processes = totals["windows"]
    combined_build_test(lb, wb)
    if lp > 9 or wp + 1 > 7 or lp + wp + 1 > 16 or wb != 48 or publish or processes != 48:
        raise ValueError("Successor allocation exceeded")
    return "0055"
