from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Sequence


AUDITED_SOURCE_REPOSITORY = "https://github.com/AzureAD/microsoft-authentication-cli"
AUDITED_SOURCE_COMMIT = "de20930c34b3b86c8a0ed7bbdeeca3f662dae918"
DOTNET_SDK_VERSION = "8.0.424"
DOTNET_SDK_ARCHIVE_URL = (
    "https://builds.dotnet.microsoft.com/dotnet/Sdk/8.0.424/"
    "dotnet-sdk-8.0.424-linux-x64.tar.gz"
)
DOTNET_SDK_ARCHIVE_SHA512 = (
    "6503fd9f464d5e3a4f43a881d2b74afc6a2c46ceda74d027f1565b7239f4b3ec"
    "884857c03c0dcd49eb52f384d5ae1fa5aaf135f0a6aabc5518103aceed643c74"
)
CAPTURE_LIMIT = 1024 * 1024
ASSET_SOURCE_LIMIT = 16 * 1024 * 1024
DISCOVERY_PASS_TIMEOUT = 0.25
MAX_DISCOVERED_PROCESSES = 2048
QUIESCENCE_FIXED_POINT_TIMEOUT = 2.0
CAPTURE_READER_GRACE_TIMEOUT = 0.5
CAPTURE_READER_SHUTDOWN_TIMEOUT = 2.0
SOURCE_MAX_ENTRIES = 32768
SOURCE_PER_FILE_LIMIT = 16 * 1024 * 1024
SOURCE_AGGREGATE_LIMIT = 256 * 1024 * 1024
SOURCE_ELAPSED_TIMEOUT = 30.0
GLOBAL_SAFETY_TERMINATIONS = frozenset(
    {"cancelled", "quiescence-unproved", "sensitive-output", "capture-failed"}
)
MODE_LOCAL_TERMINATIONS = frozenset({"timed-out", "output-limit-exceeded"})
LATE_CAPTURE_FAILURE_REASON = "recording-capture-unverifiable"
FAILURE_REASON_LIMIT = 1024
FAILURE_REASON_SEPARATOR = "; "
SOURCE_INTEGRITY_CHANGED_MARKER = "source-integrity-changed"
MISE_TOOL_NAME = "http:dotnet-sdk"
MISE_VERSION = "2026.8.10"
MISE_EXECUTABLE_SHA256 = (
    "1f5e8795d24073904ef20ba70c1250ad6389d8c5672226d152e0ed24909ba72f"
)
DIRECTORY_PACKAGES_PROPS_CONTENT = "<Project />\n"
TOOLCHAIN_ROOT = PurePosixPath(
    "/var/tmp/microsoft-authentication-cli/issue-1-toolchains/"
    "public-build-wsl2-linux-x64-dotnet-8-0-424-nuget-config-fix"
)
SELECTION_ROOT = PurePosixPath(
    "/var/tmp/microsoft-authentication-cli/issue-1-selections/"
    "public-build-wsl2-linux-x64-dotnet-8-0-424-nuget-config-fix"
)
DEPENDENCY_ASSET_DIRECTORY = PurePosixPath(
    "docs/research/experiments/assets"
)
SOURCE_FAITHFUL_PACKAGE_SOURCE = (
    "https://pkgs.dev.azure.com/office/_packaging/Office/nuget/v3/index.json"
)
PUBLIC_PACKAGE_SOURCE = "https://api.nuget.org/v3/index.json"
PCACACHE_TEST_FILTER = (
    "FullyQualifiedName!~Microsoft.Authentication.MSALWrapper.Test.PCACacheTest"
)
SENSITIVE_DETECTION_PATTERNS = (
    r"(?i)authorization\s*:\s*(?:bearer|basic)\s+\S+",
    (
        r"(?i)\b(?:password|passwd|token|secret|apikey|api_key|access_token|"
        r"refresh_token|client_secret)\s*[:=]\s*[^\s&]+"
    ),
    r"(?i)https?://[^/\s:@]+:[^/\s@]+@",
    (
        r"""(?i)["'](?:password|passwd|token|secret|apikey|api_key|access_token|"""
        r"""refresh_token|client_secret)["']\s*:\s*["'][^"']+"""
    ),
)

MISE_ENVIRONMENT_KEYS = (
    "HOME", "LANG", "LC_ALL", "MISE_CACHE_DIR", "MISE_CEILING_PATHS",
    "MISE_CONFIG_FILE", "MISE_DATA_DIR", "MISE_ENABLE_TOOLS",
    "MISE_GLOBAL_CONFIG_FILE", "MISE_LOCKED", "MISE_NO_ENV", "MISE_NO_HOOKS",
    "MISE_STATE_DIR", "MISE_SYSTEM_CONFIG_FILE", "MISE_TMP_DIR", "PATH",
    "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "XDG_STATE_HOME",
)
GIT_ENVIRONMENT_KEYS = (
    "GCM_INTERACTIVE", "GIT_ASKPASS", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_KEY_0", "GIT_CONFIG_KEY_1", "GIT_CONFIG_KEY_2",
    "GIT_CONFIG_KEY_3", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_VALUE_0", "GIT_CONFIG_VALUE_1", "GIT_CONFIG_VALUE_2",
    "GIT_CONFIG_VALUE_3", "GIT_SSH", "GIT_TERMINAL_PROMPT", "HOME", "LANG",
    "LC_ALL", "PATH", "SSH_ASKPASS", "TMPDIR", "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
)
DOTNET_ENVIRONMENT_KEYS = (
    "DOTNET_ADD_GLOBAL_TOOLS_TO_PATH", "DOTNET_CLI_HOME",
    "DOTNET_CLI_TELEMETRY_OPTOUT", "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE",
    "DOTNET_GENERATE_ASPNET_CERTIFICATE", "DOTNET_MULTILEVEL_LOOKUP",
    "DOTNET_NOLOGO", "DOTNET_ROOT", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE",
    "DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER",
    "DOTNET_WORKLOAD_UPDATE_NOTIFY_DISABLE", "HOME", "LANG", "LC_ALL",
    "MSBUILDDISABLENODEREUSE", "NUGET_CREDENTIALPROVIDERS_PATH",
    "NUGET_HTTP_CACHE_PATH", "NUGET_PACKAGES", "NUGET_PLUGINS_CACHE_PATH",
    "NUGET_SCRATCH", "PATH", "TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
)
REPLACEMENT_ENVIRONMENT_KEYS = tuple(
    sorted(set(MISE_ENVIRONMENT_KEYS) | set(GIT_ENVIRONMENT_KEYS) | set(DOTNET_ENVIRONMENT_KEYS))
)


@dataclass(frozen=True)
class PreparationSpec:
    identifier: str
    scope: str
    source_mode: str | None
    child: bool


PREPARATIONS = tuple(
    PreparationSpec(*item)
    for item in (
        ("prepare-toolchain-root", "global", None, False),
        ("prepare-selection-root", "global", None, False),
        ("prepare-selection-directories", "global", None, False),
        ("prepare-dotnet-sdk-selection", "global", None, False),
        ("prepare-toolchain-directories", "global", None, False),
        ("prepare-reviewed-mise-config", "global", None, False),
        ("mise-version", "global", None, True),
        ("mise-install-dotnet-sdk", "global", None, True),
        ("verify-dotnet-installation", "global", None, False),
        ("inspect-nuget-client-version", "global", None, False),
        ("git-source-faithful-init", "mode", "source-faithful", True),
        ("git-source-faithful-fetch", "mode", "source-faithful", True),
        ("git-source-faithful-checkout", "mode", "source-faithful", True),
        ("git-source-faithful-verify-head", "mode", "source-faithful", True),
        ("source-faithful-integrity-baseline", "mode", "source-faithful", False),
        (
            "generate-source-faithful-directory-packages-props",
            "mode",
            "source-faithful",
            False,
        ),
        ("verify-source-faithful-nuget-roots-empty", "mode", "source-faithful", False),
        ("dotnet-source-faithful-info", "mode", "source-faithful", True),
        (
            "dotnet-source-faithful-nuget-cache-locations",
            "mode",
            "source-faithful",
            True,
        ),
        ("git-public-only-init", "mode", "public-only", True),
        ("git-public-only-fetch", "mode", "public-only", True),
        ("git-public-only-checkout", "mode", "public-only", True),
        ("git-public-only-verify-head", "mode", "public-only", True),
        ("public-only-integrity-baseline", "mode", "public-only", False),
        ("generate-public-only-nuget-config", "mode", "public-only", False),
        (
            "generate-public-only-directory-packages-props",
            "mode",
            "public-only",
            False,
        ),
        ("verify-public-only-nuget-roots-empty", "mode", "public-only", False),
        ("dotnet-public-only-info", "mode", "public-only", True),
        ("dotnet-public-only-nuget-cache-locations", "mode", "public-only", True),
    )
)
PREPARATION_BY_ID = {item.identifier: item for item in PREPARATIONS}
CHECKOUT_BOUND_PREPARATION_IDS = frozenset(
    identifier
    for mode in ("source-faithful", "public-only")
    for identifier in (
        *(f"git-{mode}-{operation}" for operation in ("fetch", "checkout", "verify-head")),
        f"{mode}-integrity-baseline",
        f"dotnet-{mode}-info",
        f"dotnet-{mode}-nuget-cache-locations",
    )
)

COMMAND_IDS = (
    "source-faithful-restore",
    "source-faithful-build",
    "source-faithful-test",
    "source-faithful-package-adopat",
    "source-faithful-package-azureauth",
    "source-faithful-package-msalwrapper-benchmark",
    "source-faithful-package-msalwrapper",
    "source-faithful-package-testhelper",
    "public-only-restore",
    "public-only-build",
    "public-only-test",
    "public-only-package-adopat",
    "public-only-package-azureauth",
    "public-only-package-msalwrapper-benchmark",
    "public-only-package-msalwrapper",
    "public-only-package-testhelper",
)


def supervision_ceilings() -> dict[str, int | float]:
    return {
        "descendant_discovery_pass_seconds": DISCOVERY_PASS_TIMEOUT,
        "max_discovered_processes": MAX_DISCOVERED_PROCESSES,
        "fixed_point_seconds": QUIESCENCE_FIXED_POINT_TIMEOUT,
        "capture_reader_grace_seconds": CAPTURE_READER_GRACE_TIMEOUT,
        "capture_reader_shutdown_seconds": CAPTURE_READER_SHUTDOWN_TIMEOUT,
        "source_max_entries": SOURCE_MAX_ENTRIES,
        "source_per_file_bytes": SOURCE_PER_FILE_LIMIT,
        "source_aggregate_bytes": SOURCE_AGGREGATE_LIMIT,
        "source_elapsed_seconds": SOURCE_ELAPSED_TIMEOUT,
    }


def dependency_asset_path(
    bundle_id: str,
    source_mode: str,
    target_id: str,
) -> PurePosixPath:
    return DEPENDENCY_ASSET_DIRECTORY / (
        f"{bundle_id}-{source_mode}-{target_id}.project.assets.json"
    )


def is_late_capture_failure(attempt: dict[str, Any] | None) -> bool:
    return bool(
        attempt
        and all(
            isinstance(attempt.get(stream), dict)
            and attempt[stream].get("disposition") == "capture-unverifiable"
            for stream in ("stdout", "stderr")
        )
        and LATE_CAPTURE_FAILURE_REASON in str(attempt.get("failure_reason"))
    )


def is_late_capture_only_failure(outcome: dict[str, Any]) -> bool:
    attempts = outcome.get("attempts")
    attempt = attempts[0] if isinstance(attempts, list) and len(attempts) == 1 else None
    if (
        outcome.get("status") != "failed"
        or not is_late_capture_failure(attempt)
        or attempt.get("termination") != "completed"
        or attempt.get("exit_code") != 0
        or attempt.get("failure_reason") != LATE_CAPTURE_FAILURE_REASON
        or outcome.get("source_integrity_failure") is not None
        or outcome.get("unspawned_termination") is not None
    ):
        return False
    return (
        "failure_reason" not in outcome
        or outcome.get("failure_reason") == LATE_CAPTURE_FAILURE_REASON
    )


def has_failure_reason_marker(reason: object, marker: str) -> bool:
    return isinstance(reason, str) and marker in reason.split(
        FAILURE_REASON_SEPARATOR
    )


def append_failure_reason_marker(reason: str | None, marker: str) -> str:
    if has_failure_reason_marker(reason, marker):
        return reason
    if not reason:
        return marker
    suffix = f"{FAILURE_REASON_SEPARATOR}{marker}"
    return f"{reason[: FAILURE_REASON_LIMIT - len(suffix)]}{suffix}"


def command_argv(
    dotnet_host_path: str,
    mode: dict[str, Any],
    stage: str,
    target: str,
) -> list[str]:
    operation = {
        "restore": "restore",
        "build": "build",
        "test": "test",
        "package": "pack",
    }[stage]
    argv = [dotnet_host_path, operation, target]
    if stage == "restore":
        config = (
            f"{mode['checkout_root']}/nuget.config"
            if mode["id"] == "source-faithful"
            else mode["generated_nuget_config"]
        )
        argv.extend(
            [
                "--configfile",
                config,
                "--runtime",
                "linux-x64",
                "--packages",
                mode["nuget_packages_root"],
            ]
        )
    else:
        argv.extend(["--configuration", "Release", "--no-restore"])
        if stage == "test":
            argv.extend(["--filter", PCACACHE_TEST_FILTER])
        elif stage == "package":
            package = PurePosixPath(target).parent.name.casefold().replace(".", "-")
            argv.extend(["--output", f"{mode['package_output_root']}/{package}"])
    argv.extend(["--verbosity", "normal", "--nologo"])
    if stage != "package":
        argv.extend(
            [
                "-p:ImportDirectorySolutionProps=false",
                "-p:ImportDirectorySolutionTargets=false",
            ]
        )
    argv.extend(
        [
            "-noAutoResponse",
            "-p:ImportDirectoryBuildTargets=false",
            f"-p:DirectoryPackagesPropsPath={mode['generated_directory_packages_props']}",
            "-p:UseArtifactsOutput=true",
            f"-p:ArtifactsPath={PurePosixPath(mode['obj_root']).parent.as_posix()}",
        ]
    )
    return argv


def reduce_runtime(
    preparations: Sequence[dict[str, Any]],
    commands: Sequence[dict[str, Any]],
    command_plan: Sequence[dict[str, Any]],
    observations: Sequence[dict[str, Any]] = (),
    roots: Sequence[dict[str, Any]] = (),
    orchestration_stop: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reduce the fixed activation domain to blockers and one canonical cause."""
    mode_by_command = {
        command["id"]: command["source_mode"] for command in command_plan
    }
    mode_blockers: dict[str, str] = {}
    global_events: list[tuple[str, str, str]] = []
    late_capture_events: list[tuple[str, str, str]] = []
    ordinary_global_failure: str | None = None
    any_failure = False

    for outcome in preparations:
        if outcome["status"] != "failed":
            continue
        any_failure = True
        spec = PREPARATION_BY_ID[outcome["id"]]
        attempt = outcome["attempts"][0] if outcome["attempts"] else None
        if is_late_capture_failure(attempt):
            late_capture_events.append(
                (outcome["id"], "capture-failed", "preparation")
            )
            if is_late_capture_only_failure(outcome):
                continue
        termination = attempt["termination"] if attempt else "completed"
        if attempt is None and str(outcome.get("failure_reason", "")).startswith(
            ("capture-failed:", "spawn-failed:")
        ):
            termination = str(outcome["failure_reason"]).split(":", 1)[0]
        if termination in GLOBAL_SAFETY_TERMINATIONS or (
            spec.scope == "global" and termination != "completed"
        ):
            global_events.append((outcome["id"], termination, "preparation"))
        elif spec.scope == "global" and ordinary_global_failure is None:
            ordinary_global_failure = outcome["id"]
        elif spec.source_mode is not None:
            mode_blockers.setdefault(spec.source_mode, outcome["id"])
        if has_failure_reason_marker(
            outcome.get("failure_reason"),
            SOURCE_INTEGRITY_CHANGED_MARKER,
        ):
            global_events.append(
                (outcome["id"], SOURCE_INTEGRITY_CHANGED_MARKER, "preparation")
            )

    for outcome in commands:
        if outcome["status"] != "failed":
            continue
        any_failure = True
        attempt = outcome["attempts"][0] if outcome["attempts"] else None
        if is_late_capture_failure(attempt):
            late_capture_events.append(
                (outcome["command_id"], "capture-failed", "command")
            )
            if is_late_capture_only_failure(outcome):
                continue
        termination = (
            attempt["termination"]
            if attempt
            else outcome.get("unspawned_termination") or "completed"
        )
        if termination in GLOBAL_SAFETY_TERMINATIONS:
            global_events.append((outcome["command_id"], termination, "command"))
        elif termination in MODE_LOCAL_TERMINATIONS:
            mode = mode_by_command[outcome["command_id"]]
            mode_blockers.setdefault(mode, outcome["command_id"])
        if outcome.get("source_integrity_failure") is not None:
            global_events.append(
                (outcome["command_id"], "source-integrity-changed", "command")
            )

    if orchestration_stop is not None:
        global_events.append(
            (
                orchestration_stop["subject_id"],
                "cancelled",
                "orchestration",
            )
        )
    if (
        len(preparations) == len(PREPARATIONS)
        and len(commands) == len(command_plan)
    ):
        global_events.extend(late_capture_events)

    unproved = next(
        (item for item in observations if not item["proved"]),
        None,
    )
    if unproved is not None:
        return {
            "global_blocker": unproved["subject_id"],
            "mode_blockers": mode_blockers,
            "cause": "quiescence-unproved",
            "detail": {
                "subject_kind": unproved["subject_kind"],
                "subject_id": unproved["subject_id"],
            },
        }

    unverified_root = next(
        (
            root
            for root in roots
            if root["created"] and not root["identity_verified"]
        ),
        None,
    )
    if unverified_root is not None:
        return {
            "global_blocker": unverified_root["kind"],
            "mode_blockers": mode_blockers,
            "cause": "root-identity-unverified",
            "detail": {
                "subject_kind": "root",
                "subject_id": unverified_root["kind"],
            },
        }

    if global_events:
        subject_id, cause, subject_kind = global_events[0]
        detail = (
            orchestration_stop
            if subject_kind == "orchestration"
            else {"subject_kind": subject_kind, "subject_id": subject_id}
        )
        return {
            "global_blocker": subject_id,
            "mode_blockers": mode_blockers,
            "cause": cause,
            "detail": detail,
        }
    if ordinary_global_failure is not None:
        return {
            "global_blocker": ordinary_global_failure,
            "mode_blockers": mode_blockers,
            "cause": "preparation-failed",
            "detail": {
                "subject_kind": "preparation",
                "subject_id": ordinary_global_failure,
            },
        }
    return {
        "global_blocker": None,
        "mode_blockers": mode_blockers,
        "cause": (
            "completed-with-command-failures"
            if any_failure or mode_blockers
            else "completed"
        ),
        "detail": None,
    }
