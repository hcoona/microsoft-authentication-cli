from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import tomllib
import urllib.parse
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from extract_public_build_assets import (
    ExtractionError,
    condition_applies,
    extract_projection,
    parse_json_object_bytes,
)
from public_build_contract import (
    ASSET_SOURCE_LIMIT,
    AUDITED_SOURCE_COMMIT,
    AUDITED_SOURCE_REPOSITORY,
    CAPTURE_LIMIT,
    CHECKOUT_BOUND_PREPARATION_IDS,
    COMMAND_IDS,
    DOTNET_SDK_ARCHIVE_SHA512,
    DOTNET_SDK_ARCHIVE_URL,
    DOTNET_SDK_VERSION,
    GLOBAL_SAFETY_TERMINATIONS,
    LATE_CAPTURE_FAILURE_REASON,
    MISE_EXECUTABLE_SHA256,
    MISE_TOOL_NAME,
    MISE_VERSION,
    PCACACHE_TEST_FILTER,
    PREPARATIONS,
    PREPARATION_BY_ID,
    PUBLIC_PACKAGE_SOURCE,
    REPLACEMENT_ENVIRONMENT_KEYS,
    SELECTION_ROOT,
    SENSITIVE_DETECTION_PATTERNS,
    SOURCE_FAITHFUL_PACKAGE_SOURCE,
    SOURCE_INTEGRITY_CHANGED_MARKER,
    TOOLCHAIN_ROOT,
    command_argv,
    dependency_asset_path,
    is_late_capture_failure,
    is_late_capture_only_failure,
    has_failure_reason_marker,
    reduce_runtime,
    supervision_ceilings,
)


ROOT = Path(__file__).resolve().parents[1]
MISE_LOCK_BYTE_LIMIT = 64 * 1024
ROOT_RESOLVED = ROOT.resolve()
PUBLIC_BUILD_SOURCE_BASELINE_PATH = "docs/research/public-build-source-baseline.json"
PUBLIC_BUILD_LASSO_MANIFEST_PATH = "docs/research/public-build-lasso-reference-manifest.json"
PUBLIC_BUILD_SCHEMA_PATH = "schemas/research/public-build-experiment-bundle.schema.json"
COMPONENT_PATHS = {
    "runner": "tools/run_public_build_experiment.py",
    "contract": "tools/public_build_contract.py",
    "validator": "tools/public_build_validation.py",
    "extractor": "tools/extract_public_build_assets.py",
    "nuget_versions": "tools/nuget_versions.py",
    "schema": PUBLIC_BUILD_SCHEMA_PATH,
    "lockfile": "tools/public-build-mise.lock",
}
SENSITIVE_OUTPUT_DETECTION = tuple(
    re.compile(pattern) for pattern in SENSITIVE_DETECTION_PATTERNS
)


def _read_no_follow_bounded(
    root: Path,
    relative_path: PurePosixPath,
    limit: int,
) -> bytes:
    if (
        relative_path.is_absolute()
        or not relative_path.parts
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        raise ValueError("retained asset path is not canonical")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    descriptors = [os.open(root, directory_flags)]
    try:
        for component in relative_path.parts[:-1]:
            descriptors.append(
                os.open(component, directory_flags, dir_fd=descriptors[-1])
            )
        file_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        descriptor = os.open(
            relative_path.parts[-1],
            file_flags,
            dir_fd=descriptors[-1],
        )
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("retained asset is not a regular file")
        if metadata.st_size > limit:
            raise ValueError("retained asset exceeds its size limit")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            if total > limit:
                raise ValueError("retained asset exceeds its size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def load_strict_json(relative_path: str) -> dict[str, Any]:
    path = ROOT / relative_path
    try:
        return parse_json_object_bytes(path.read_bytes(), str(path))
    except OSError as error:
        raise ExtractionError(f"cannot read JSON from {path}: {error}") from error


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def source_manifest_payload(
    stage_applicability: dict[str, Any],
    targets: list[dict[str, Any]],
    package_targets: list[dict[str, Any]],
    declarations: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "stage_applicability": {
            stage: {
                "applicable": value["applicable"],
                "source_references": sorted(value["source_references"]),
            }
            for stage, value in sorted(stage_applicability.items())
        },
        "attempted_targets": sorted(
            (
                {
                    "id": target["id"],
                    "project_path": target["project_path"],
                    "target_framework": target["target_framework"],
                    "sdk": target["sdk"],
                    "project_references": sorted(target["project_references"]),
                    "source_references": sorted(target["source_references"]),
                }
                for target in targets
            ),
            key=lambda target: target["id"],
        ),
        "package_targets": sorted(
            (
                {
                    "target_id": package_target["target_id"],
                    "package_id": package_target["package_id"],
                    "source_references": sorted(
                        package_target["source_references"]
                    ),
                }
                for package_target in package_targets
            ),
            key=lambda package_target: package_target["target_id"],
        ),
        "source_declared_direct": sorted(
            (
                {
                    "declaration_id": declaration["declaration_id"],
                    "id": declaration["id"],
                    "kind": declaration["kind"],
                    "version_constraint": declaration["version_constraint"],
                    "path_property": declaration.get("path_property"),
                    "assembly_relative_path": declaration.get(
                        "assembly_relative_path"
                    ),
                    "declaration_location": declaration["declaration_location"],
                    "auxiliary_locations": sorted(
                        declaration["auxiliary_locations"]
                    ),
                    "targets": sorted(declaration["targets"]),
                    "condition": declaration["condition"],
                }
                for declaration in declarations
            ),
            key=lambda declaration: declaration["declaration_location"],
        ),
    }


def lasso_reference_manifest_payload(
    references: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        (
            {
                "id": reference["id"],
                "path": reference["path"],
                "line": reference["line"],
                "symbol": reference["symbol"],
                "kind": reference["kind"],
            }
            for reference in references
        ),
        key=lambda reference: reference["id"],
    )


def receipt_digest(bundle: dict[str, Any]) -> str:
    value = copy.deepcopy(bundle)
    try:
        receipt = value["runtime_evidence"]["receipt_binding"]
        digest = receipt["digest"]
    except (KeyError, TypeError) as error:
        raise ValueError("recorded bundle has no embedded receipt digest") from error
    if not isinstance(receipt, dict) or not isinstance(digest, str):
        raise ValueError("recorded bundle receipt digest has an invalid shape")
    del receipt["digest"]
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _json_type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, True)


def _schema_errors(
    value: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any],
    path: str = "$",
) -> list[str]:
    if "$ref" in schema:
        target: Any = root_schema
        for token in schema["$ref"].removeprefix("#/").split("/"):
            target = target[token.replace("~1", "/").replace("~0", "~")]
        return _schema_errors(value, target, root_schema, path)
    errors: list[str] = []
    expected_type = schema.get("type")
    types = expected_type if isinstance(expected_type, list) else [expected_type]
    if expected_type is not None and not any(
        _json_type_matches(value, item) for item in types
    ):
        return [f"{path}: expected type {expected_type}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: value differs from const")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is not in enum")
    if isinstance(value, dict):
        if len(value) < schema.get("minProperties", 0):
            errors.append(f"{path}: fewer than minProperties")
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required property {key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            errors.extend(
                f"{path}: unexpected property {key}"
                for key in value
                if key not in properties
            )
        for key, child in value.items():
            if key in properties:
                errors.extend(
                    _schema_errors(child, properties[key], root_schema, f"{path}.{key}")
                )
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than maxItems")
        if schema.get("uniqueItems") and len(
            {canonical_json_bytes(item) for item in value}
        ) != len(value):
            errors.append(f"{path}: array items are not unique")
        contains = schema.get("contains")
        if isinstance(contains, dict) and not any(
            not _schema_errors(item, contains, root_schema, path) for item in value
        ):
            errors.append(f"{path}: array has no item matching contains")
        if isinstance(schema.get("items"), dict):
            for index, child in enumerate(value):
                errors.extend(
                    _schema_errors(
                        child,
                        schema["items"],
                        root_schema,
                        f"{path}[{index}]",
                    )
                )
    elif isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than minLength")
        if len(value) > schema.get("maxLength", len(value)):
            errors.append(f"{path}: longer than maxLength")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: string does not match pattern")
        if schema.get("format") == "uri" and not urllib.parse.urlparse(value).scheme:
            errors.append(f"{path}: string is not an absolute URI")
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema.get("minimum", value):
            errors.append(f"{path}: value is below minimum")
        if value > schema.get("maximum", value):
            errors.append(f"{path}: value is above maximum")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            errors.append(f"{path}: value is not above exclusiveMinimum")
    for clause in schema.get("allOf", []):
        errors.extend(_schema_errors(value, clause, root_schema, path))
    if "oneOf" in schema and sum(
        not _schema_errors(value, clause, root_schema, path)
        for clause in schema["oneOf"]
    ) != 1:
        errors.append(f"{path}: value does not match exactly one oneOf branch")
    if "not" in schema and not _schema_errors(value, schema["not"], root_schema, path):
        errors.append(f"{path}: value matches prohibited not schema")
    if isinstance(schema.get("if"), dict):
        selected = "then" if not _schema_errors(
            value, schema["if"], root_schema, path
        ) else "else"
        if isinstance(schema.get(selected), dict):
            errors.extend(_schema_errors(value, schema[selected], root_schema, path))
    return errors


def validate_public_build_bundle_instance(
    bundle: Any,
    relative_path: str,
    *,
    baseline: dict[str, Any] | None = None,
    lasso_manifest: dict[str, Any] | None = None,
) -> list[str]:
    try:
        schema = load_strict_json(PUBLIC_BUILD_SCHEMA_PATH)
    except ExtractionError as error:
        return [str(error)]
    shape_errors = _schema_errors(bundle, schema, schema)
    if shape_errors:
        return [f"{relative_path}: {error}" for error in shape_errors]
    try:
        return validate_public_build_bundle_value(
            bundle,
            relative_path,
            baseline=baseline,
            lasso_manifest=lasso_manifest,
        )
    except (ExtractionError, KeyError, TypeError, ValueError) as error:
        return [f"{relative_path}: semantic validation failed: {error}"]


def normalized_absolute_path(
    value: str,
) -> tuple[str, PurePosixPath | PureWindowsPath] | None:
    if "\\" in value:
        return None
    windows = re.match(r"^[A-Za-z]:/", value) is not None
    if not windows and value.startswith("//"):
        return None
    raw_parts = value[3:].split("/") if windows else value.split("/")
    if any(part in {".", ".."} for part in raw_parts):
        return None
    path: PurePosixPath | PureWindowsPath = (
        PureWindowsPath(value) if windows else PurePosixPath(value)
    )
    if not path.is_absolute() or path.as_posix() != value:
        return None
    return ("windows" if windows else "posix"), path


def recorded_path_is_within(
    child: tuple[str, PurePosixPath | PureWindowsPath],
    parent: tuple[str, PurePosixPath | PureWindowsPath],
    allow_equal: bool = False,
) -> bool:
    if child[0] != parent[0]:
        return False
    child_parts = child[1].parts
    parent_parts = parent[1].parts
    if child[0] == "windows":
        child_parts = tuple(part.casefold() for part in child_parts)
        parent_parts = tuple(part.casefold() for part in parent_parts)
    return (
        len(child_parts) >= len(parent_parts)
        and (allow_equal or len(child_parts) > len(parent_parts))
        and child_parts[: len(parent_parts)] == parent_parts
    )


def recorded_paths_overlap(
    left: tuple[str, PurePosixPath | PureWindowsPath],
    right: tuple[str, PurePosixPath | PureWindowsPath],
) -> bool:
    return recorded_path_is_within(left, right, True) or recorded_path_is_within(
        right, left, True
    )


def _component_errors(
    bundle: dict[str, Any],
    relative_path: str,
) -> list[str]:
    errors: list[str] = []
    for name, expected_path in COMPONENT_PATHS.items():
        component = bundle["components"][name]
        if component["path"] != expected_path:
            errors.append(f"{relative_path}: component {name} uses an unexpected path")
            continue
        path = ROOT / expected_path
        if not path.is_file() or path.is_symlink():
            errors.append(f"{relative_path}: component {name} is not a live regular file")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != component["sha256"]:
            suffix = (
                "; after a recorded bundle exists, the first hash-bound component "
                "change must atomically choose a historical replay or record migration "
                "strategy with independent research review"
                if bundle["status"] == "recorded"
                else ""
            )
            errors.append(f"{relative_path}: live component drift for {name}{suffix}")
    return errors


def _mise_descriptor_errors(mise: dict[str, Any], relative_path: str) -> list[str]:
    try:
        descriptor = tomllib.loads(mise["config_content"])
    except (tomllib.TOMLDecodeError, TypeError) as error:
        return [f"{relative_path}: reviewed mise descriptor is invalid TOML: {error}"]
    tools = descriptor.get("tools")
    tool = tools.get(MISE_TOOL_NAME) if isinstance(tools, dict) else None
    platforms = tool.get("platforms") if isinstance(tool, dict) else None
    platform = (
        platforms.get("linux-x64") if isinstance(platforms, dict) else None
    )
    if (
        set(descriptor) != {"min_version", "tool_config", "tools"}
        or descriptor["min_version"] != MISE_VERSION
        or descriptor["tool_config"] != {"locked": True}
        or not isinstance(tools, dict)
        or set(tools) != {MISE_TOOL_NAME}
        or not isinstance(tool, dict)
        or set(tool) != {"version", "platforms"}
        or tool["version"] != DOTNET_SDK_VERSION
        or not isinstance(platforms, dict)
        or set(platforms) != {"linux-x64"}
        or platform
        != {
            "url": DOTNET_SDK_ARCHIVE_URL,
            "checksum": f"sha512:{DOTNET_SDK_ARCHIVE_SHA512}",
        }
    ):
        return [f"{relative_path}: reviewed mise descriptor violates locked SDK invariants"]
    return []


def _mise_lock_errors(
    bundle: dict[str, Any],
    relative_path: str,
    lock_bytes: bytes | None = None,
) -> list[str]:
    lock_path = ROOT / bundle["components"]["lockfile"]["path"]
    try:
        payload = lock_path.read_bytes() if lock_bytes is None else lock_bytes
        lock = tomllib.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        return [f"{relative_path}: experiment mise lock is unreadable: {error}"]
    tools = lock.get("tools")
    entries = tools.get(MISE_TOOL_NAME) if isinstance(tools, dict) else None
    expected = {
        "version": bundle["environment"]["dotnet_sdk"]["version"],
        "backend": MISE_TOOL_NAME,
        "platforms.linux-x64": {
            "checksum": (
                "sha512:"
                f"{bundle['environment']['dotnet_sdk']['archive_sha512']}"
            ),
            "url": bundle["environment"]["dotnet_sdk"]["archive_url"],
        },
    }
    if (
        set(lock) != {"tools"}
        or not isinstance(tools, dict)
        or set(tools) != {MISE_TOOL_NAME}
        or not isinstance(entries, list)
        or entries != [expected]
    ):
        return [
            f"{relative_path}: experiment mise lock is not the exact one-tool projection"
        ]
    return []


def load_validated_mise_lock_bytes(
    bundle: dict[str, Any],
    relative_path: str,
) -> bytes:
    component = bundle["components"]["lockfile"]
    path = ROOT / component["path"]
    flags = os.O_RDONLY
    for flag in ("O_CLOEXEC", "O_NOFOLLOW"):
        flags |= getattr(os, flag, 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ExtractionError(
            f"{relative_path}: experiment mise lock is unreadable: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ExtractionError(
                f"{relative_path}: experiment mise lock is not a regular file"
            )
        chunks: list[bytes] = []
        offset = 0
        while offset <= MISE_LOCK_BYTE_LIMIT:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MISE_LOCK_BYTE_LIMIT + 1 - offset),
            )
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        if offset > MISE_LOCK_BYTE_LIMIT:
            raise ExtractionError(
                f"{relative_path}: experiment mise lock exceeds its byte limit"
            )
        payload = b"".join(chunks)
    except OSError as error:
        raise ExtractionError(
            f"{relative_path}: experiment mise lock is unreadable: {error}"
        ) from error
    finally:
        os.close(descriptor)
    if hashlib.sha256(payload).hexdigest() != component["sha256"]:
        raise ExtractionError(
            f"{relative_path}: experiment mise lock differs from its reviewed hash"
        )
    errors = _mise_lock_errors(bundle, relative_path, payload)
    if errors:
        raise ExtractionError(errors[0])
    return payload


def _mode_errors(
    bundle: dict[str, Any],
    relative_path: str,
) -> list[str]:
    errors: list[str] = []
    modes = bundle["isolation"]["source_modes"]
    if [mode["id"] for mode in modes] != ["source-faithful", "public-only"]:
        return [f"{relative_path}: isolation must contain the two fixed source modes"]
    selection = PurePosixPath(bundle["isolation"]["selection_root"])
    expected_sources = {
        "source-faithful": ("audited-checkout", SOURCE_FAITHFUL_PACKAGE_SOURCE),
        "public-only": ("isolated-generated", PUBLIC_PACKAGE_SOURCE),
    }
    path_suffixes = {
        "checkout_root": "checkout",
        "home_root": "home",
        "nuget_packages_root": "nuget/packages",
        "nuget_http_cache_root": "nuget/http-cache",
        "nuget_plugins_cache_root": "nuget/plugins-cache",
        "nuget_scratch_root": "nuget/scratch",
        "temporary_root": "tmp",
        "obj_root": "artifacts/obj",
        "bin_root": "artifacts/bin",
        "package_output_root": "packages",
        "generated_directory_packages_props": "generated/Directory.Packages.props",
    }
    for mode in modes:
        mode_id = mode["id"]
        configuration, source = expected_sources[mode_id]
        root = selection / mode_id
        if (
            mode["configuration"] != configuration
            or mode["package_sources"] != [source]
        ):
            errors.append(f"{relative_path}: {mode_id} source authority differs")
        for key, suffix in path_suffixes.items():
            if mode[key] != (root / suffix).as_posix():
                errors.append(f"{relative_path}: {mode_id} {key} is outside its root")
        expected_config = (
            None
            if mode_id == "source-faithful"
            else (root / "generated/only-nuget.org.config").as_posix()
        )
        if mode["generated_nuget_config"] != expected_config:
            errors.append(f"{relative_path}: {mode_id} NuGet configuration differs")
    return errors


def _command_errors(
    bundle: dict[str, Any],
    baseline: dict[str, Any],
    relative_path: str,
) -> list[str]:
    errors: list[str] = []
    commands = bundle["protocol"]["commands"]
    if len({command["id"] for command in commands}) != len(commands):
        errors.append(f"{relative_path}: command IDs must be unique")
        return errors
    if [command["id"] for command in commands] != list(COMMAND_IDS):
        errors.append(
            f"{relative_path}: command IDs must equal the fixed ordered topology"
        )
    modes = {mode["id"]: mode for mode in bundle["isolation"]["source_modes"]}
    dotnet = bundle["environment"]["dotnet_sdk"]["host_path"]
    package_projects = {
        target["project_path"]
        for target in baseline["attempted_targets"]
        if target["id"] in {item["target_id"] for item in baseline["package_targets"]}
    }
    solution_target = baseline["source"]["build_entry_point"]
    commands_by_id = {command["id"]: command for command in commands}
    for mode_id, mode in modes.items():
        mode_commands = [item for item in commands if item["source_mode"] == mode_id]
        if len(mode_commands) != 8:
            errors.append(f"{relative_path}: {mode_id} must contain eight commands")
            continue
        restore_id = f"{mode_id}-restore"
        stages = [command["stage"] for command in mode_commands]
        if stages.count("restore") != 1 or stages.count("build") != 1 or stages.count(
            "test"
        ) != 1 or stages.count("package") != 5:
            errors.append(f"{relative_path}: {mode_id} stage coverage differs")
        if {
            command["target"] for command in mode_commands if command["stage"] == "package"
        } != package_projects:
            errors.append(f"{relative_path}: {mode_id} package targets differ from baseline")
        seen_ids: set[str] = set()
        for command in mode_commands:
            argv = command["argv"]
            if (
                command["cwd"] != mode["checkout_root"]
                or argv
                != command_argv(
                    dotnet,
                    mode,
                    command["stage"],
                    command["target"],
                )
                or command["max_attempts"] != 1
                or command["timeout_seconds"] > 900
            ):
                errors.append(f"{relative_path}: command {command['id']} violates execution invariants")
            if command["stage"] != "package":
                if command["id"] != f"{mode_id}-{command['stage']}":
                    errors.append(
                        f"{relative_path}: command {command['id']} contradicts its mode and stage"
                    )
                if command["target"] != solution_target:
                    errors.append(
                        f"{relative_path}: command {command['id']} does not use the audited entry point"
                    )
            if command["stage"] == "restore":
                if command["depends_on"] is not None:
                    errors.append(f"{relative_path}: restore {command['id']} is inconsistent")
            elif command["depends_on"] != restore_id:
                errors.append(f"{relative_path}: {command['id']} must depend on restore")
            if command["depends_on"] is not None:
                dependency = commands_by_id.get(command["depends_on"])
                if (
                    command["depends_on"] not in seen_ids
                    or dependency is None
                    or dependency["source_mode"] != mode_id
                    or dependency["stage"] != "restore"
                ):
                    errors.append(
                        f"{relative_path}: command {command['id']} dependency is not an earlier same-mode restore"
                    )
            if command["stage"] == "test":
                if command["test_filter"] != PCACACHE_TEST_FILTER:
                    errors.append(f"{relative_path}: test command lacks PCACache exclusion")
            elif command["test_filter"] is not None:
                errors.append(f"{relative_path}: non-test command has a test filter")
            if command["stage"] == "package":
                parent = Path(command["target"]).parent.name.casefold().replace(".", "-")
                if command["id"] != f"{mode_id}-package-{parent}":
                    errors.append(f"{relative_path}: package command ID contradicts its target")
            seen_ids.add(command["id"])
    if [command["source_mode"] for command in commands[:8]] != ["source-faithful"] * 8:
        errors.append(f"{relative_path}: source-faithful command block must be first")
    return errors


def validate_public_build_bundle_value(
    bundle: dict[str, Any],
    relative_path: str,
    baseline: dict[str, Any] | None = None,
    lasso_manifest: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    baseline = baseline or load_strict_json(PUBLIC_BUILD_SOURCE_BASELINE_PATH)
    lasso_manifest = lasso_manifest or load_strict_json(PUBLIC_BUILD_LASSO_MANIFEST_PATH)
    authorities = bundle["authorities"]
    source_payload_sha256 = canonical_sha256(
        source_manifest_payload(
            baseline["stage_applicability"],
            baseline["attempted_targets"],
            baseline["package_targets"],
            baseline["source_declared_direct"],
        )
    )
    lasso_payload_sha256 = canonical_sha256(
        lasso_reference_manifest_payload(lasso_manifest["references"])
    )
    if (
        authorities["source_baseline"]["payload_sha256"]
        != baseline["source_manifest_sha256"]
        or baseline["source_manifest_sha256"] != source_payload_sha256
    ):
        errors.append(f"{relative_path}: source authority hash differs from the fixed baseline")
    if (
        authorities["lasso_manifest"]["payload_sha256"]
        != lasso_manifest["lasso_reference_manifest_sha256"]
        or lasso_manifest["lasso_reference_manifest_sha256"]
        != lasso_payload_sha256
    ):
        errors.append(f"{relative_path}: Lasso authority hash differs from the fixed manifest")
    if baseline["source"] != lasso_manifest["source"] or any(
        baseline["source"].get(key) != value
        for key, value in {
            "repository": AUDITED_SOURCE_REPOSITORY,
            "commit": AUDITED_SOURCE_COMMIT,
        }.items()
    ):
        errors.append(f"{relative_path}: source authorities do not identify the audited commit")
    errors.extend(_component_errors(bundle, relative_path))

    environment = bundle["environment"]
    dotnet = environment["dotnet_sdk"]
    mise = environment["mise"]
    installation = (
        TOOLCHAIN_ROOT / "installs" / "http-dotnet-sdk" / DOTNET_SDK_VERSION
    )
    expected_dotnet_identity = {
        "version": DOTNET_SDK_VERSION,
        "archive_url": DOTNET_SDK_ARCHIVE_URL,
        "archive_sha512": DOTNET_SDK_ARCHIVE_SHA512,
        "manager_data_root": TOOLCHAIN_ROOT.as_posix(),
        "installation_root": installation.as_posix(),
        "host_path": (installation / "dotnet").as_posix(),
        "global_json_path": (SELECTION_ROOT / "global.json").as_posix(),
    }
    actual_dotnet_identity = {
        key: dotnet[key] for key in expected_dotnet_identity
    }
    try:
        global_json = parse_json_object_bytes(
            dotnet["global_json_content"].encode("utf-8"),
            f"{relative_path}: global.json",
        )
    except (ExtractionError, UnicodeError) as error:
        global_json = None
        errors.append(f"{relative_path}: reviewed global.json is invalid: {error}")
    if (
        environment["host_type"] != "native-linux"
        or environment["runtime_identifier"] != "linux-x64"
        or actual_dotnet_identity != expected_dotnet_identity
        or global_json
        != {
            "sdk": {
                "version": DOTNET_SDK_VERSION,
                "rollForward": "disable",
                "allowPrerelease": False,
            }
        }
    ):
        errors.append(f"{relative_path}: .NET identity or dedicated roots differ")
    if (
        mise["version"] != MISE_VERSION
        or mise["tool_name"] != MISE_TOOL_NAME
        or mise["executable_sha256"] != MISE_EXECUTABLE_SHA256
    ):
        errors.append(f"{relative_path}: mise identity or lock binding differs")
    errors.extend(_mise_descriptor_errors(mise, relative_path))
    errors.extend(_mise_lock_errors(bundle, relative_path))

    isolation = bundle["isolation"]
    if (
        isolation["toolchain_root"] != TOOLCHAIN_ROOT.as_posix()
        or isolation["selection_root"] != SELECTION_ROOT.as_posix()
        or isolation["replacement_environment"]["allowlist"]
        != list(REPLACEMENT_ENVIRONMENT_KEYS)
    ):
        errors.append(f"{relative_path}: fixed roots or replacement environment differ")
    left = normalized_absolute_path(isolation["toolchain_root"])
    right = normalized_absolute_path(isolation["selection_root"])
    if left is None or right is None or recorded_paths_overlap(left, right):
        errors.append(f"{relative_path}: selection and toolchain roots must be disjoint")
    errors.extend(_mode_errors(bundle, relative_path))
    errors.extend(_command_errors(bundle, baseline, relative_path))
    ceilings = supervision_ceilings()
    for name, value in bundle["protocol"]["supervision_bounds"].items():
        if name not in ceilings or value <= 0 or value > ceilings[name]:
            errors.append(f"{relative_path}: supervision bound {name} exceeds its ceiling")
    applicable_assemblies = [
        declaration["declaration_id"]
        for declaration in baseline["source_declared_direct"]
        if declaration["kind"] == "package-backed-assembly"
        and condition_applies(declaration["condition"], "linux-x64")
    ]
    if applicable_assemblies:
        errors.append(
            f"{relative_path}: applicable package-backed declarations "
            f"{applicable_assemblies} require an atomic runtime-contract expansion"
        )
    if bundle["status"] == "recorded":
        errors.extend(validate_public_build_runtime_evidence(bundle, relative_path, baseline))
    return errors


def _validate_output(
    output: dict[str, Any],
    subject_id: str,
    stream: str,
    expected_disposition: str,
    capture_root: PurePosixPath,
    seen_paths: set[PurePosixPath],
    relative_path: str,
) -> list[str]:
    errors: list[str] = []
    if expected_disposition == "suppressed-source-faithful":
        if output != {
            "disposition": "suppressed-source-faithful",
            "path": None,
            "sha256": None,
            "sanitized_bytes": 0,
            "excerpt": "",
            "truncated": False,
        }:
            errors.append(
                f"{relative_path}: {subject_id} {stream} suppressed output "
                "retains variable evidence"
            )
        return errors
    if output["disposition"] == "capture-unverifiable":
        if output != {
            "disposition": "capture-unverifiable",
            "path": None,
            "sha256": None,
            "sanitized_bytes": 0,
            "excerpt": "",
            "truncated": False,
        }:
            errors.append(
                f"{relative_path}: {subject_id} {stream} unverifiable output "
                "retains variable evidence"
            )
        return errors
    if output["disposition"] != "retained-sanitized":
        errors.append(
            f"{relative_path}: {subject_id} {stream} output disposition differs"
        )
        return errors
    if not isinstance(output["path"], str) or not isinstance(output["sha256"], str):
        errors.append(
            f"{relative_path}: {subject_id} {stream} retained output lacks identity"
        )
        return errors
    path = PurePosixPath(output["path"])
    if (
        not path.is_absolute()
        or not path.is_relative_to(capture_root)
        or path.parent != capture_root
        or not path.name.startswith(f"{subject_id}-{stream}-")
        or path.suffix != ".log"
    ):
        errors.append(f"{relative_path}: {subject_id} {stream} capture path is not bound")
    elif path in seen_paths:
        errors.append(f"{relative_path}: capture path {path} is referenced more than once")
    else:
        seen_paths.add(path)
    if output["sanitized_bytes"] > CAPTURE_LIMIT:
        errors.append(f"{relative_path}: {subject_id} {stream} exceeds the capture limit")
    if (
        output["sanitized_bytes"] < len(output["excerpt"].encode("utf-8"))
        and not output["truncated"]
    ):
        errors.append(f"{relative_path}: {subject_id} {stream} has an impossible byte count")
    if any(pattern.search(output["excerpt"]) for pattern in SENSITIVE_OUTPUT_DETECTION):
        errors.append(f"{relative_path}: {subject_id} {stream} retains sensitive output")
    return errors


def _attempt_errors(
    attempts: list[dict[str, Any]],
    status: str,
    subject_kind: str,
    subject_id: str,
    observations: dict[tuple[str, str], dict[str, Any]],
    capture_root: PurePosixPath,
    seen_paths: set[PurePosixPath],
    relative_path: str,
    *,
    expected_output_disposition: str = "retained-sanitized",
    semantic_failure: bool = False,
    unspawned: str | None = None,
    expects_child: bool = True,
    external_failure: bool = False,
) -> tuple[list[str], bool]:
    errors: list[str] = []
    typed_unspawned = (
        expects_child
        and status == "failed"
        and not attempts
        and unspawned in {"capture-failed", "spawn-failed"}
    )
    expected = (
        1
        if expects_child
        and status in {"passed", "failed"}
        and not typed_unspawned
        else 0
    )
    if len(attempts) != expected:
        errors.append(
            f"{relative_path}: {subject_id} status {status} requires {expected} attempt(s)"
        )
    if unspawned is not None and not expects_child:
        errors.append(
            f"{relative_path}: in-process {subject_id} uses a reserved "
            "unspawned termination"
        )
    elif bool(unspawned) != typed_unspawned:
        errors.append(f"{relative_path}: {subject_id} unspawned termination is inconsistent")
    for attempt in attempts:
        if status == "passed" and (
            attempt["termination"] != "completed" or attempt["exit_code"] != 0
        ):
            errors.append(f"{relative_path}: passed {subject_id} lacks a zero-exit attempt")
        if status == "failed" and (
            attempt["termination"] == "completed"
            and attempt["exit_code"] == 0
            and attempt["failure_reason"] is None
            and not external_failure
            and not semantic_failure
        ):
            errors.append(f"{relative_path}: failed {subject_id} has a successful attempt")
        if attempt["termination"] != "completed" and not attempt["failure_reason"]:
            errors.append(f"{relative_path}: {subject_id} termination lacks a reason")
        if SOURCE_INTEGRITY_CHANGED_MARKER in str(attempt["failure_reason"]):
            errors.append(
                f"{relative_path}: {subject_id} source integrity failure "
                "is stored in attempt evidence"
            )
        observation = observations.get((subject_kind, subject_id))
        if observation is None:
            errors.append(f"{relative_path}: {subject_id} lacks its quiescence observation")
        for stream in ("stdout", "stderr"):
            errors.extend(
                _validate_output(
                    attempt[stream],
                    subject_id,
                    stream,
                    expected_output_disposition,
                    capture_root,
                    seen_paths,
                    relative_path,
                )
            )
        if expected_output_disposition == "retained-sanitized":
            unverifiable = [
                attempt[stream]["disposition"] == "capture-unverifiable"
                for stream in ("stdout", "stderr")
            ]
            late_capture_failure = is_late_capture_failure(attempt)
            if any(unverifiable) and (
                not all(unverifiable)
                or (
                    attempt["termination"] not in GLOBAL_SAFETY_TERMINATIONS
                    and not late_capture_failure
                )
            ):
                errors.append(
                    f"{relative_path}: {subject_id} unverifiable capture "
                    "disposition is inconsistent"
                )
            if late_capture_failure and status != "failed":
                errors.append(
                    f"{relative_path}: {subject_id} late capture invalidation "
                    "does not fail its subject"
                )
        elif LATE_CAPTURE_FAILURE_REASON in str(attempt["failure_reason"]):
            errors.append(
                f"{relative_path}: {subject_id} suppressed output claims "
                "late retained-capture invalidation"
            )
    return errors, bool(attempts)


def _restore_metadata_errors(
    restore_metadata: dict[str, Any],
    mode: dict[str, Any],
    target_ref: str,
    relative_path: str,
) -> list[str]:
    expected_config = mode["generated_nuget_config"] or (
        f"{mode['checkout_root'].rstrip('/')}/nuget.config"
    )
    expected = {
        "packages_path": mode["nuget_packages_root"],
        "package_folders": [mode["nuget_packages_root"]],
        "config_file_paths": [expected_config],
        "sources": sorted(mode["package_sources"]),
    }
    if restore_metadata == expected:
        return []
    return [
        f"{relative_path}: target {target_ref} restore metadata "
        "differs from its isolated mode"
    ]


def _validate_dependency_evidence(
    bundle: dict[str, Any],
    baseline: dict[str, Any],
    outcomes: dict[str, dict[str, Any]],
    cache: dict[str, dict[str, Any]],
    asset_inspection_blocker: str | None,
    relative_path: str,
) -> tuple[list[str], set[str]]:
    errors: list[str] = []
    target_refs: set[str] = set()
    targets = {target["id"]: target for target in baseline["attempted_targets"]}
    declarations = {
        declaration["declaration_id"]: declaration
        for declaration in baseline["source_declared_direct"]
        if declaration["kind"] == "package"
    }
    modes = bundle["runtime_evidence"]["dependency_evidence"]["modes"]
    if [mode["source_mode"] for mode in modes] != ["source-faithful", "public-only"]:
        return [f"{relative_path}: dependency modes must cover the two source modes"], set()
    isolation = {mode["id"]: mode for mode in bundle["isolation"]["source_modes"]}
    for mode in modes:
        mode_id = mode["source_mode"]
        restore_id = f"{mode_id}-restore"
        actual_targets = {item["target_id"]: item for item in mode["targets"]}
        if len(actual_targets) != len(mode["targets"]) or set(actual_targets) != set(targets):
            errors.append(f"{relative_path}: {mode_id} dependency targets are incomplete")
            continue
        for target_id, item in actual_targets.items():
            target_ref = f"{mode_id}/{target_id}"
            target_refs.add(target_ref)
            applicable = {
                declaration_id
                for declaration_id, declaration in declarations.items()
                if target_id in declaration["targets"]
                and condition_applies(declaration["condition"], "linux-x64")
            }
            unresolved = {
                declaration["declaration_id"]: declaration
                for declaration in item["unresolved_declarations"]
            }
            if len(unresolved) != len(item["unresolved_declarations"]):
                errors.append(f"{relative_path}: {target_ref} repeats unresolved declarations")
            if asset_inspection_blocker is not None and (
                item["status"] != "invalid"
                or item["reason"] != asset_inspection_blocker
                or "asset" in item
            ):
                errors.append(
                    f"{relative_path}: {target_ref} does not preserve "
                    f"{asset_inspection_blocker}"
                )
            if item["status"] == "valid":
                if unresolved or item["reason"] is not None or "asset" not in item:
                    errors.append(f"{relative_path}: valid target {target_ref} is inconsistent")
                    continue
            else:
                if "asset" in item or not item["reason"] or set(unresolved) != applicable:
                    errors.append(f"{relative_path}: unresolved target {target_ref} is inconsistent")
                for declaration_id, unresolved_item in unresolved.items():
                    refs = unresolved_item["failure_evidence_refs"]
                    if target_ref not in refs or any(
                        ref not in {target_ref, restore_id} for ref in refs
                    ):
                        errors.append(
                            f"{relative_path}: unresolved {declaration_id} has invalid failure refs"
                        )
                    if outcomes[restore_id]["status"] == "passed" and restore_id in refs:
                        errors.append(f"{relative_path}: passed restore is failure evidence")
                continue
            asset = item["asset"]
            provenance = asset["provenance"]
            for field in ("retrieval_source_evidence", "access_evidence"):
                refs = provenance[field]
                if refs != [restore_id]:
                    errors.append(
                        f"{relative_path}: {target_ref} {field} must bind its restore"
                    )
            cache_ref = f"{mode_id}-initial-nuget-cache"
            if (
                provenance["initial_cache_evidence"] != [cache_ref]
                or cache_ref not in cache
            ):
                errors.append(
                    f"{relative_path}: {target_ref} lacks initial-cache provenance"
                )
            if asset_inspection_blocker is not None:
                errors.append(
                    f"{relative_path}: asset evidence exists after {asset_inspection_blocker}"
                )
                continue
            expected_path = dependency_asset_path(
                bundle["id"],
                mode_id,
                target_id,
            )
            if asset["path"] != expected_path.as_posix():
                errors.append(
                    f"{relative_path}: retained asset path for {target_ref} differs"
                )
                continue
            try:
                asset_bytes = _read_no_follow_bounded(
                    ROOT,
                    expected_path,
                    ASSET_SOURCE_LIMIT,
                )
            except (OSError, ValueError) as error:
                errors.append(
                    f"{relative_path}: retained asset {asset['path']} "
                    f"cannot be read safely: {error}"
                )
                continue
            if hashlib.sha256(asset_bytes).hexdigest() != asset["sha256"]:
                errors.append(f"{relative_path}: retained asset hash differs")
            if any(
                pattern.search(asset_bytes.decode("utf-8", errors="replace"))
                for pattern in SENSITIVE_OUTPUT_DETECTION
            ):
                errors.append(f"{relative_path}: retained asset contains sensitive output")
            try:
                replayed = extract_projection(
                    parse_json_object_bytes(asset_bytes, asset["path"]),
                    asset_bytes,
                    baseline,
                    target_id,
                    "linux-x64",
                    isolation[mode_id]["checkout_root"],
                )
            except ExtractionError as error:
                errors.append(f"{relative_path}: extractor replay failed: {error}")
            else:
                if replayed != asset["projection"]:
                    errors.append(f"{relative_path}: target {target_ref} does not exactly replay")
                errors.extend(
                    _restore_metadata_errors(
                        replayed["assets_projection"]["restore_metadata"],
                        isolation[mode_id],
                        target_ref,
                        relative_path,
                    )
                )
    return errors, target_refs


def validate_public_build_runtime_evidence(
    bundle: dict[str, Any],
    relative_path: str,
    baseline: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    runtime = bundle["runtime_evidence"]
    context = runtime["runtime_context"]
    mise_mode = int(context["mise_executable_mode"], 8)
    if (
        context["operating_system"] != "linux"
        or context["architecture"] != "x86_64"
        or context["reproduction_count"] != 1
        or context["mise_executable_owner_verified"] is not True
        or not mise_mode & stat.S_IXUSR
        or mise_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or context["mise_executable_sha256"]
        != bundle["environment"]["mise"]["executable_sha256"]
    ):
        errors.append(f"{relative_path}: runtime context contradicts the reviewed host")
    nuget = context["nuget_client_version_probe"]
    if nuget is not None and not nuget["path"].endswith(
        f"/sdk/{DOTNET_SDK_VERSION}/NuGet.CommandLine.XPlat.deps.json"
    ):
        errors.append(f"{relative_path}: NuGet version observation is outside the SDK")

    planned_commands = bundle["protocol"]["commands"]
    command_ids = [command["id"] for command in planned_commands]
    commands_by_id = {command["id"]: command for command in planned_commands}
    outcomes = runtime["command_outcomes"]
    outcomes_by_id = {item["command_id"]: item for item in outcomes}
    if len(outcomes_by_id) != len(outcomes) or list(outcomes_by_id) != command_ids:
        errors.append(f"{relative_path}: command outcomes must cover the reviewed order")

    observations = runtime["all_exit_quiescence"]["observations"]
    observations_by_subject = {
        (item["subject_kind"], item["subject_id"]): item
        for item in observations
    }
    for observation in observations:
        if observation["proved"] and (
            observation["final_live_descendants"] != 0
            or not observation["descendant_fixed_point"]
        ):
            errors.append(f"{relative_path}: proved quiescence lacks primitive proof")
    if runtime["all_exit_quiescence"]["identity_mechanisms"] != [
        "pidfd",
        "proc-starttime",
    ]:
        errors.append(
            f"{relative_path}: all-exit identity mechanisms differ"
        )

    capture_root = PurePosixPath(bundle["isolation"]["selection_root"]) / "captures"
    capture_paths: set[PurePosixPath] = set()
    spawned: set[tuple[str, str]] = set()
    for outcome in outcomes:
        attempt_errors, was_spawned = _attempt_errors(
            outcome["attempts"],
            outcome["status"],
            "command",
            outcome["command_id"],
            observations_by_subject,
            capture_root,
            capture_paths,
            relative_path,
            expected_output_disposition=(
                "suppressed-source-faithful"
                if commands_by_id[outcome["command_id"]]["source_mode"]
                == "source-faithful"
                else "retained-sanitized"
            ),
            unspawned=outcome["unspawned_termination"],
            external_failure=outcome["source_integrity_failure"] is not None,
        )
        errors.extend(attempt_errors)
        if was_spawned:
            spawned.add(("command", outcome["command_id"]))
        if outcome["status"] == "blocked":
            if not outcome["blocked_by"] or outcome["attempts"]:
                errors.append(f"{relative_path}: blocked command has invalid evidence")
        elif outcome["blocked_by"] is not None:
            errors.append(f"{relative_path}: nonblocked command carries blocker metadata")
        if (
            outcome["source_integrity_failure"] is not None
            and outcome["status"] != "failed"
        ):
            errors.append(
                f"{relative_path}: source integrity failure is attached to "
                f"nonfailed command {outcome['command_id']}"
            )

    preparations = runtime["preparation_outcomes"]
    if [item["id"] for item in preparations] != [
        item.identifier for item in PREPARATIONS
    ]:
        errors.append(
            f"{relative_path}: preparation outcomes must cover the fixed topology"
        )
    for preparation in preparations:
        spec = PREPARATION_BY_ID.get(preparation["id"])
        if spec is None:
            continue
        attempt_errors, was_spawned = _attempt_errors(
            preparation["attempts"],
            preparation["status"],
            "preparation",
            preparation["id"],
            observations_by_subject,
            capture_root,
            capture_paths,
            relative_path,
            semantic_failure=(
                preparation["status"] == "failed"
                and bool(preparation["failure_reason"])
            ),
            unspawned=(
                str(preparation["failure_reason"]).split(":", 1)[0]
                if not preparation["attempts"]
                and str(preparation["failure_reason"]).startswith(
                    ("capture-failed:", "spawn-failed:")
                )
                else None
            ),
            expects_child=spec.child,
        )
        errors.extend(attempt_errors)
        if was_spawned:
            spawned.add(("preparation", preparation["id"]))
        typed_unspawned = (
            spec.child
            and preparation["status"] == "failed"
            and not preparation["attempts"]
            and str(preparation["failure_reason"]).startswith(
                ("capture-failed:", "spawn-failed:")
            )
        )
        if (
            preparation["status"] != "blocked"
            and was_spawned != (spec.child and not typed_unspawned)
        ):
            errors.append(f"{relative_path}: preparation execution type differs")
        if (preparation["status"] == "passed") != (
            preparation["failure_reason"] is None
        ):
            errors.append(f"{relative_path}: preparation status and reason differ")
        reason = preparation["failure_reason"]
        contains_source_marker = SOURCE_INTEGRITY_CHANGED_MARKER in str(reason)
        has_source_marker = has_failure_reason_marker(
            reason,
            SOURCE_INTEGRITY_CHANGED_MARKER,
        )
        if contains_source_marker and not has_source_marker:
            errors.append(
                f"{relative_path}: preparation {preparation['id']} has a malformed "
                "source-integrity marker"
            )
        if has_source_marker and (
            preparation["id"] not in CHECKOUT_BOUND_PREPARATION_IDS
            or preparation["status"] != "failed"
            or (
                spec.child
                and len(preparation["attempts"]) != 1
                and not typed_unspawned
            )
            or (
                not spec.child
                and preparation["attempts"]
            )
        ):
            errors.append(
                f"{relative_path}: preparation {preparation['id']} has an invalid "
                "source-integrity overlay"
            )

    covered = set(observations_by_subject)
    if len(covered) != len(observations):
        errors.append(
            f"{relative_path}: quiescence subjects must be unique"
        )
    if covered != spawned:
        errors.append(f"{relative_path}: quiescence must cover every and only spawned subject")

    canonical_detail = runtime["canonical_termination"]["detail"]
    orchestration_stop = (
        canonical_detail
        if runtime["canonical_termination"]["cause"] == "cancelled"
        and isinstance(canonical_detail, dict)
        and canonical_detail.get("subject_kind") == "orchestration"
        else None
    )
    prep_prefix: list[dict[str, Any]] = []
    cancellation_reached = False
    for preparation in preparations:
        if (
            orchestration_stop is not None
            and orchestration_stop["subject_id"] == preparation["id"]
        ):
            cancellation_reached = True
        spec = PREPARATION_BY_ID[preparation["id"]]
        state = reduce_runtime(
            prep_prefix,
            [],
            planned_commands,
            orchestration_stop=orchestration_stop if cancellation_reached else None,
        )
        blocker = state["global_blocker"] or (
            state["mode_blockers"].get(spec.source_mode)
            if spec.source_mode is not None
            else None
        )
        if blocker is None and preparation["status"] == "blocked":
            errors.append(f"{relative_path}: preparation is blocked without a blocker")
        if blocker is not None and (
            preparation["status"] != "blocked"
            or preparation["failure_reason"] != f"blocked-by:{blocker}"
        ):
            errors.append(f"{relative_path}: preparation blocker propagation differs")
        prep_prefix.append(preparation)

    command_prefix: list[dict[str, Any]] = []
    command_plan_by_id = {item["id"]: item for item in planned_commands}
    for outcome in outcomes:
        if (
            orchestration_stop is not None
            and orchestration_stop["subject_id"] == outcome["command_id"]
        ):
            cancellation_reached = True
        plan = command_plan_by_id[outcome["command_id"]]
        state = reduce_runtime(
            preparations,
            command_prefix,
            planned_commands,
            orchestration_stop=orchestration_stop if cancellation_reached else None,
        )
        blocker = state["global_blocker"] or state["mode_blockers"].get(
            plan["source_mode"]
        )
        dependency = plan["depends_on"]
        if blocker is None and dependency is not None:
            prior = outcomes_by_id[dependency]
            if (
                prior["status"] != "passed"
                and not is_late_capture_only_failure(prior)
            ):
                blocker = dependency if prior["status"] == "failed" else prior["blocked_by"]
        if blocker is not None and (
            outcome["status"] != "blocked"
            or outcome["blocked_by"] != blocker
        ):
            errors.append(f"{relative_path}: command blocker propagation differs")
        if blocker is None and outcome["status"] == "blocked":
            errors.append(f"{relative_path}: command is blocked without a blocker")
        command_prefix.append(outcome)

    roots = runtime["ownership_conditioned_cleanup"]["roots"]
    if [root["kind"] for root in roots] != ["toolchain", "selection"]:
        errors.append(f"{relative_path}: root lifecycle must cover toolchain then selection")
    preparation_by_id = {item["id"]: item for item in preparations}
    for root, preparation_id in zip(
        roots, ("prepare-toolchain-root", "prepare-selection-root")
    ):
        status = preparation_by_id[preparation_id]["status"]
        if (
            (status == "passed" and not root["created"])
            or (status == "blocked" and root["created"])
            or (root["identity_verified"] and not root["created"])
        ):
            errors.append(f"{relative_path}: root lifecycle contradicts creation evidence")
    selection_root = next(
        (root for root in roots if root["kind"] == "selection"),
        None,
    )
    if (
        selection_root is not None
        and selection_root["created"]
        and not selection_root["identity_verified"]
        and any(
            attempt[stream]["disposition"] == "retained-sanitized"
            for outcome in [*preparations, *outcomes]
            for attempt in outcome["attempts"]
            for stream in ("stdout", "stderr")
        )
    ):
        errors.append(
            f"{relative_path}: unverified selection root retains sanitized "
            "capture references"
        )

    replay = reduce_runtime(
        preparations,
        outcomes,
        planned_commands,
        observations,
        roots,
        orchestration_stop,
    )
    if runtime["canonical_termination"] != {
        "cause": replay["cause"],
        "detail": replay["detail"],
    }:
        errors.append(f"{relative_path}: canonical termination differs from reducer replay")

    cache_items = runtime["cache_observations"]
    cache = {item["id"]: item for item in cache_items}
    if len(cache) != len(cache_items):
        errors.append(f"{relative_path}: cache observation IDs must be unique")
    modes = {mode["id"]: mode for mode in bundle["isolation"]["source_modes"]}
    expected_cache_ids: set[str] = set()
    for mode_id, mode in modes.items():
        cache_id = f"{mode_id}-initial-nuget-cache"
        observation = cache.get(cache_id)
        expected = (
            preparation_by_id[f"verify-{mode_id}-nuget-roots-empty"]["status"] == "passed"
            and preparation_by_id[
                f"dotnet-{mode_id}-nuget-cache-locations"
            ]["status"]
            == "passed"
        )
        if expected:
            expected_cache_ids.add(cache_id)
        if expected != (observation is not None):
            errors.append(f"{relative_path}: {mode_id} cache evidence is inconsistent")
        if observation is not None:
            if (
                observation["source_mode"] != mode_id
                or observation["preparation_refs"]
                != [
                    f"verify-{mode_id}-nuget-roots-empty",
                    f"dotnet-{mode_id}-nuget-cache-locations",
                ]
            ):
                errors.append(
                    f"{relative_path}: {mode_id} cache evidence binding differs"
                )
            if observation["effective_paths"] != {
                "http-cache": mode["nuget_http_cache_root"],
                "global-packages": mode["nuget_packages_root"],
                "temp": mode["nuget_scratch_root"],
                "plugins-cache": mode["nuget_plugins_cache_root"],
            }:
                errors.append(f"{relative_path}: {mode_id} cache paths differ")
    if set(cache) != expected_cache_ids:
        errors.append(
            f"{relative_path}: cache observations do not exactly match successful checks"
        )

    all_proved = all(item["proved"] for item in observations)
    selection = next((root for root in roots if root["kind"] == "selection"), None)
    global_preparation_failed = any(
        item["status"] == "failed"
        and PREPARATION_BY_ID[item["id"]].scope == "global"
        for item in preparations
    )
    blocker: str | None = None
    if not all_proved:
        blocker = "asset-inspection-blocked-by-unproved-quiescence"
    elif selection is None or not selection["created"] or not selection["identity_verified"]:
        blocker = "asset-inspection-blocked-by-root-identity-unverified"
    elif global_preparation_failed:
        blocker = "asset-inspection-blocked-by-preparation-failed"
    elif replay["cause"] not in {
        "completed",
        "completed-with-command-failures",
        "preparation-failed",
    }:
        blocker = f"asset-inspection-blocked-by-{replay['cause']}"
    dependency_errors, target_refs = _validate_dependency_evidence(
        bundle, baseline, outcomes_by_id, cache, blocker, relative_path
    )
    errors.extend(dependency_errors)

    valid_refs = (
        set(command_ids)
        | {item.identifier for item in PREPARATIONS}
        | set(cache)
        | target_refs
    )
    limitation_refs = {
        f"limitation-{index}" for index, _ in enumerate(bundle["limitations"], 1)
    }
    conclusions = runtime["bounded_conclusions"]
    for conclusion in conclusions["conclusions"]:
        if (
            not set(conclusion["evidence_refs"]).issubset(valid_refs)
            or not set(conclusion["limitation_refs"]).issubset(limitation_refs)
        ):
            errors.append(f"{relative_path}: conclusion refs are not reviewable")
    try:
        actual_receipt = receipt_digest(bundle)
    except ValueError as error:
        errors.append(f"{relative_path}: {error}")
    else:
        if runtime["receipt_binding"]["digest"] != actual_receipt:
            errors.append(f"{relative_path}: receipt digest does not match the bundle")
    return errors
