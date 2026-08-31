# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["PyYAML==6.0.3", "jsonschema==4.25.1", "markdown-it-py==4.2.0"]
# ///

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from extract_public_build_assets import (
    ExtractionError,
    extract_projection,
    parse_json_object_bytes,
)
from jsonschema import Draft202012Validator
from markdown_it import MarkdownIt
from markdown_it.token import Token
from nuget_versions import (
    nuget_constraint_is_valid,
    nuget_version_satisfies_constraint,
)
from public_build_contract import (
    DOTNET_SDK_ARCHIVE_SHA512,
    DOTNET_SDK_ARCHIVE_URL,
    DOTNET_SDK_VERSION,
    MISE_TOOL_NAME,
)
from public_build_validation import (
    canonical_sha256,
    lasso_reference_manifest_payload,
    source_manifest_payload,
    validate_public_build_bundle_instance,
    validate_public_build_bundle_value,
)
from run_public_build_experiment import run_bundle


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
MARKDOWN = MarkdownIt("commonmark", {"html": True})
REQUIREMENT_ID_PATTERN = re.compile(r"^V2-REQ-[0-9]{3}[A-Z]?$")
REQUIREMENT_PREFIX_PATTERN = re.compile(r"^V2-REQ-")
RETIRED_REQUIREMENT_PREFIX = "Retired - current authority: "
DECISION_PATTERN = re.compile(r"^([0-9]{4})-.*\.md$")
GLOB_MARKERS = frozenset("*?[")
ZERO_SHA = "0" * 40
ROOT_RECORD_PATHS = frozenset(
    {
        ".github/pull_request_template.md",
        "AGENTS.md",
        "CONTRIBUTING.md",
        "README.md",
        "SECURITY.md",
        "UPSTREAM.md",
    }
)
RECORD_ROOT_SUFFIXES = {
    "docs": (".md", ".yaml", ".yml", ".json", ".jsonl", ".csv"),
    "schemas": (".schema.json",),
    "contracts": (".schema.json",),
    "designs": (".md",),
}
BOOTSTRAP_SCHEMA_BINDINGS = (
    (
        "schemas/governance/record-families.schema.json",
        "docs/governance/record-families.yaml",
    ),
    (
        "schemas/governance/controls.schema.json",
        "docs/governance/controls.yaml",
    ),
)
HK_EXECUTION_PLANS = {
    "local-fast": ("run", "pre-commit"),
    "ci": ("check",),
}
PUBLIC_BUILD_SOURCE_BASELINE_PATH = (
    "docs/research/public-build-source-baseline.json"
)
PUBLIC_BUILD_LASSO_MANIFEST_PATH = (
    "docs/research/public-build-lasso-reference-manifest.json"
)
PUBLIC_BUILD_SCHEMA_PATH = (
    "schemas/research/public-build-experiment-bundle.schema.json"
)
PUBLIC_BUILD_EXTRACTOR_PATH = "tools/extract_public_build_assets.py"
PUBLIC_BUILD_NUGET_VERSIONS_PATH = "tools/nuget_versions.py"
PUBLIC_BUILD_RUNNER_PATH = "tools/run_public_build_experiment.py"
PUBLIC_BUILD_VALIDATION_PATH = "tools/public_build_validation.py"
PUBLIC_BUILD_RUNTIME_SCHEMA_ANCHORS = frozenset(
    {
        "all_exit_quiescence",
        "bounded_conclusions",
        "canonical_termination",
        "command_outcomes",
        "ownership_conditioned_cleanup",
        "receipt_binding",
    }
)


def load_yaml_path(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT).as_posix()} must contain a YAML object")
    return value


def load_yaml(relative_path: str) -> dict[str, Any]:
    return load_yaml_path(ROOT / relative_path)


def load_strict_json_path(path: Path) -> dict[str, Any]:
    try:
        return parse_json_object_bytes(path.read_bytes(), str(path))
    except OSError as error:
        raise ExtractionError(f"cannot read JSON from {path}: {error}") from error


def load_strict_json(relative_path: str) -> dict[str, Any]:
    return load_strict_json_path(ROOT / relative_path)


def duplicates(values: list[str]) -> list[str]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


def git_output(*arguments: str) -> str | None:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def token_plain_text(token: Token) -> str:
    if token.type in {"text", "code_inline", "image"}:
        return token.content
    if token.type in {"softbreak", "hardbreak"}:
        return " "
    return "".join(token_plain_text(child) for child in token.children or [])


def markdown_headings(text: str) -> list[str]:
    tokens = MARKDOWN.parse(text)
    headings: list[str] = []
    for index, token in enumerate(tokens):
        if (
            token.type == "heading_open"
            and index + 1 < len(tokens)
            and tokens[index + 1].type == "inline"
        ):
            headings.append(token_plain_text(tokens[index + 1]).strip())
    return headings


def walk_tokens(tokens: list[Token]) -> list[Token]:
    walked: list[Token] = []
    for token in tokens:
        walked.append(token)
        if token.children:
            walked.extend(walk_tokens(token.children))
    return walked


def requirement_headings(
    text: str,
) -> tuple[list[tuple[str, str | None]], list[str]]:
    requirements: list[tuple[str, str | None]] = []
    malformed: list[str] = []
    for heading_text in markdown_headings(text):
        if not REQUIREMENT_PREFIX_PATTERN.match(heading_text):
            continue
        identifier, separator, title = heading_text.partition(":")
        title = title.strip()
        if (
            not separator
            or REQUIREMENT_ID_PATTERN.fullmatch(identifier) is None
            or not title
        ):
            malformed.append(heading_text)
            continue
        if title.startswith("Retired"):
            if not title.startswith(RETIRED_REQUIREMENT_PREFIX):
                malformed.append(heading_text)
                continue
            authority = title.removeprefix(RETIRED_REQUIREMENT_PREFIX).strip()
            if not authority:
                malformed.append(heading_text)
                continue
            requirements.append((identifier, authority))
        else:
            requirements.append((identifier, None))
    return requirements, malformed


def markdown_link_destinations(text: str) -> list[str]:
    return [
        destination
        for token in walk_tokens(MARKDOWN.parse(text))
        if token.type == "link_open"
        and (destination := token.attrGet("href")) is not None
    ]


def resolve_accepted_base(errors: list[str]) -> str | None:
    explicit_base = os.environ.get("HK_BASE_REF")
    if explicit_base and explicit_base != ZERO_SHA:
        resolved_base = git_output(
            "rev-parse", "--verify", f"{explicit_base}^{{commit}}"
        )
        if resolved_base is None:
            errors.append(
                f"cannot resolve HK_BASE_REF for requirement-ID comparison: {explicit_base}"
            )
            return None
        return resolved_base

    for candidate in ("origin/main-v2", "main-v2"):
        resolved_base = git_output("rev-parse", "--verify", f"{candidate}^{{commit}}")
        if resolved_base is not None:
            return resolved_base

    errors.append(
        "cannot resolve the accepted target branch for requirement-ID comparison; "
        "fetch main-v2 or set HK_BASE_REF"
    )
    return None


def requirement_ids_at_commit(commit: str, errors: list[str]) -> set[str]:
    listing = git_output("ls-tree", "-r", "--name-only", commit, "--", "docs")
    if listing is None:
        errors.append(f"cannot list accepted documentation at {commit}")
        return set()

    requirement_ids: set[str] = set()
    for relative_path in listing.splitlines():
        if not relative_path.endswith(".md"):
            continue
        content = git_output("show", f"{commit}:{relative_path}")
        if content is None:
            errors.append(
                f"cannot read accepted requirement definitions from {relative_path}"
            )
            continue
        requirements, malformed = requirement_headings(content)
        requirement_ids.update(identifier for identifier, _authority in requirements)
        if malformed:
            errors.append(
                f"accepted record {relative_path} contains malformed requirement "
                f"headings: {', '.join(malformed)}"
            )
    return requirement_ids


def check_identifiers() -> list[str]:
    errors: list[str] = []
    requirement_occurrences: list[tuple[str, str, str | None]] = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        relative_path = path.relative_to(ROOT).as_posix()
        requirements, malformed = requirement_headings(path.read_text(encoding="utf-8"))
        for heading in malformed:
            errors.append(
                f"malformed requirement heading in {relative_path}: {heading}"
            )
        requirement_occurrences.extend(
            (identifier, relative_path, authority)
            for identifier, authority in requirements
        )

    requirement_ids = [
        identifier for identifier, _path, _authority in requirement_occurrences
    ]
    requirement_id_set = set(requirement_ids)
    for identifier in duplicates(requirement_ids):
        errors.append(f"duplicate requirement identifier: {identifier}")
    for identifier, relative_path, authority in requirement_occurrences:
        if not relative_path.startswith("docs/product/requirements/"):
            errors.append(
                f"requirement identifier {identifier} is defined outside the canonical "
                f"requirements family: {relative_path}"
            )
        if authority is None:
            continue
        if REQUIREMENT_ID_PATTERN.fullmatch(authority):
            if authority == identifier:
                errors.append(
                    f"retired requirement {identifier} cannot name itself as current "
                    "authority"
                )
            elif authority not in requirement_id_set:
                errors.append(
                    f"retired requirement {identifier} names unknown current authority "
                    f"{authority}"
                )
            continue
        path_text, separator, anchor = authority.partition("#")
        authority_path = resolve_repository_file(
            path_text,
            f"retired requirement {identifier} current authority",
            errors,
        )
        if authority_path is None:
            continue
        if authority_path.suffix.lower() != ".md":
            errors.append(
                f"retired requirement {identifier} current authority is not Markdown: "
                f"{authority}"
            )
        elif separator and anchor not in markdown_heading_slugs(authority_path):
            errors.append(
                f"retired requirement {identifier} current-authority anchor does not "
                f"exist or is not an ASCII GitHub heading anchor: {authority}"
            )

    accepted_base = resolve_accepted_base(errors)
    if accepted_base is not None:
        accepted_ids = requirement_ids_at_commit(accepted_base, errors)
        for identifier in sorted(accepted_ids - set(requirement_ids)):
            errors.append(f"established requirement identifier was removed: {identifier}")

    decision_numbers = [
        match.group(1)
        for path in sorted((ROOT / "docs/decisions").glob("*.md"))
        if (match := DECISION_PATTERN.fullmatch(path.name))
    ]
    for number in duplicates(decision_numbers):
        errors.append(f"duplicate decision number: {number}")

    registry_ids = {
        "record family": [
            item["id"]
            for item in load_yaml("docs/governance/record-families.yaml")["families"]
        ],
        "control": [
            item["id"]
            for item in load_yaml("docs/governance/controls.yaml")["controls"]
        ],
        "operational identity": [
            item["id"]
            for item in load_yaml("docs/governance/operational-identities.yaml")[
                "selected_v2"
            ]
        ],
        "recheck": [
            item["id"]
            for item in load_yaml("docs/research/rechecks.yaml")["rechecks"]
        ],
    }
    for label, values in registry_ids.items():
        for identifier in duplicates(values):
            errors.append(f"duplicate {label} identifier: {identifier}")
    return errors


def contains_glob(path: str) -> bool:
    return any(marker in path for marker in GLOB_MARKERS)


def matches(path: str, pattern: str) -> bool:
    if not contains_glob(pattern):
        return path == pattern
    return PurePosixPath(path).match(pattern)


def repository_path_error(value: str, allow_glob: bool = False) -> str | None:
    if "\\" in value:
        return "must use repository-relative POSIX separators"
    pure_path = PurePosixPath(value)
    if pure_path.is_absolute():
        return "must be repository-relative"
    if ".." in pure_path.parts:
        return "must not contain parent traversal"
    if not allow_glob and contains_glob(value):
        return "must identify one repository path"
    return None


def resolve_repository_file(
    value: str,
    label: str,
    errors: list[str],
) -> Path | None:
    if reason := repository_path_error(value):
        errors.append(f"{label} {reason}: {value}")
        return None
    lexical_path = ROOT / PurePosixPath(value)
    path = lexical_path.resolve()
    try:
        path.relative_to(ROOT_RESOLVED)
    except ValueError:
        errors.append(f"{label} resolves outside the repository: {value}")
        return None
    if not path.is_file():
        errors.append(f"{label} does not exist: {value}")
        return None
    if path != ROOT_RESOLVED / PurePosixPath(value):
        errors.append(f"{label} must not use a symbolic-link path: {value}")
        return None
    return path


def resolve_governed_record(
    candidate: Path,
    label: str,
    errors: list[str],
) -> Path | None:
    try:
        relative_path = candidate.relative_to(ROOT)
    except ValueError:
        errors.append(f"{label} is outside the repository: {candidate}")
        return None
    resolved = candidate.resolve()
    try:
        resolved.relative_to(ROOT_RESOLVED)
    except ValueError:
        errors.append(f"{label} resolves outside the repository: {relative_path}")
        return None
    if resolved != ROOT_RESOLVED / relative_path:
        errors.append(f"{label} must not use a symbolic-link path: {relative_path}")
        return None
    if not resolved.is_file():
        return None
    return resolved


def expand_family_paths(
    family: dict[str, Any],
    errors: list[str],
) -> set[Path]:
    pattern = family["path"]
    if reason := repository_path_error(pattern, allow_glob=True):
        errors.append(f"{family['id']} family path {reason}: {pattern}")
        return set()
    candidates = ROOT.glob(pattern) if contains_glob(pattern) else [ROOT / pattern]
    paths: set[Path] = set()
    for candidate in candidates:
        resolved = resolve_governed_record(
            candidate,
            f"{family['id']} family record",
            errors,
        )
        if resolved is not None:
            paths.add(resolved)
    return paths


def discover_governed_record_paths(errors: list[str]) -> set[Path]:
    candidates = {ROOT / relative_path for relative_path in ROOT_RECORD_PATHS}
    for root_name, suffixes in RECORD_ROOT_SUFFIXES.items():
        root = ROOT / root_name
        if not root.is_dir():
            continue
        candidates.update(
            path
            for path in root.rglob("*")
            if path.is_file() and any(path.name.endswith(suffix) for suffix in suffixes)
        )

    paths: set[Path] = set()
    for candidate in candidates:
        resolved = resolve_governed_record(candidate, "governed record", errors)
        if resolved is not None:
            paths.add(resolved)
    return paths


def github_ascii_slug(heading: str) -> str | None:
    if not heading.isascii():
        return None
    return "".join(
        character
        for character in heading.lower()
        if character.isalnum() or character in {" ", "-", "_"}
    ).replace(" ", "-")


def markdown_heading_slugs_from_text(text: str) -> set[str]:
    slugs: set[str] = set()
    occurrences: dict[str, int] = {}
    for heading in markdown_headings(text):
        base_slug = github_ascii_slug(heading)
        if base_slug is None:
            continue
        slug = base_slug
        count = occurrences.get(base_slug, 0)
        while slug in occurrences:
            count += 1
            slug = f"{base_slug}-{count}"
        occurrences[base_slug] = count
        occurrences[slug] = 0
        slugs.add(slug)
    return slugs


def markdown_heading_slugs(path: Path) -> set[str]:
    return markdown_heading_slugs_from_text(path.read_text(encoding="utf-8"))


def check_markdown_parser_contract() -> list[str]:
    errors: list[str] = []
    markdown = """\
<script>
## V2-REQ-998: Hidden
[Hidden](hidden.md)
</script>

<div>Rendered HTML block</div>

## V2-REQ-060: `Visible` *Heading*

`[Code](code.md)` \\[Escaped](escaped.md) [Real](real.md) [Reference][record]

[record]: reference.md
"""
    requirements, malformed = requirement_headings(markdown)
    if requirements != [("V2-REQ-060", None)] or malformed:
        errors.append("CommonMark requirement-heading parser contract failed")
    requirement_markdown = """\
## V2-REQ-061: Active requirement
## V2-REQ-062: Retired - current authority: V2-REQ-061
## V2-REQ-063:
## V2-REQ-064: Retired
"""
    requirements, malformed = requirement_headings(requirement_markdown)
    if requirements != [
        ("V2-REQ-061", None),
        ("V2-REQ-062", "V2-REQ-061"),
    ] or malformed != ["V2-REQ-063:", "V2-REQ-064: Retired"]:
        errors.append("requirement active-and-retired syntax contract failed")
    if set(markdown_link_destinations(markdown)) != {"real.md", "reference.md"}:
        errors.append("CommonMark documentation-link parser contract failed")

    slug_markdown = """\
## Use `dotnet` build
## A--B
## foo - bar
## foo
## foo-1
## foo
"""
    if markdown_heading_slugs_from_text(slug_markdown) != {
        "use-dotnet-build",
        "a--b",
        "foo---bar",
        "foo",
        "foo-1",
        "foo-2",
    }:
        errors.append("GitHub ASCII heading-anchor parser contract failed")
    return errors


def hk_steps_by_execution_point(errors: list[str]) -> dict[str, set[str]]:
    steps_by_execution_point: dict[str, set[str]] = {}
    for execution_point, arguments in HK_EXECUTION_PLANS.items():
        result = subprocess.run(
            ["hk", *arguments, "--all", "--plan", "--json"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            errors.append(
                f"cannot evaluate hk {execution_point} plan: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
            continue
        try:
            plan = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            errors.append(f"cannot parse hk {execution_point} plan JSON: {error}")
            continue
        expected_hook = "pre-commit" if execution_point == "local-fast" else "check"
        if plan.get("hook") != expected_hook:
            errors.append(
                f"hk {execution_point} plan reported unexpected hook: "
                f"{plan.get('hook')}"
            )
            continue
        plan_steps = plan.get("steps")
        if not isinstance(plan_steps, list):
            errors.append(f"hk {execution_point} plan does not contain a step list")
            continue
        steps_by_execution_point[execution_point] = {
            step["name"]
            for step in plan_steps
            if isinstance(step, dict)
            and isinstance(step.get("name"), str)
            and step.get("status") == "included"
        }
    return steps_by_execution_point


def check_public_build_activation_coupling(
    catalog: dict[str, Any],
    controls: list[dict[str, Any]],
    schema: dict[str, Any] | None = None,
    runner_path: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    family = next(
        (
            item
            for item in catalog["families"]
            if item["id"] == "public-build-experiment-bundles"
        ),
        None,
    )
    control = next(
        (
            item
            for item in controls
            if item["id"] == "public-build-evidence-consistency"
        ),
        None,
    )
    if family is None or control is None:
        return errors
    if family["state"] != control["state"]:
        errors.append(
            "public-build-experiment-bundles and "
            "public-build-evidence-consistency must activate in the same change"
        )
        return errors
    if family["state"] != "current":
        return errors
    expected_bundle_path = (
        "docs/research/experiments/"
        "public-build-linux-x64-dotnet-8-0-424-01.json"
    )
    if family["path"] != expected_bundle_path or family["format"] != "json":
        errors.append(
            "current public-build experiment singleton must use its exact JSON path"
        )
    bundle_paths = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "docs/research/experiments").glob("public-build-*.json")
        if path.is_file()
    )
    if bundle_paths != [expected_bundle_path]:
        errors.append(
            "current public-build experiment singleton must have cardinality one"
        )
    else:
        try:
            singleton = load_strict_json(expected_bundle_path)
        except ExtractionError as error:
            errors.append(str(error))
        else:
            expected_id = Path(expected_bundle_path).stem
            if singleton.get("id") != expected_id:
                errors.append(
                    "public-build singleton filename must equal its fixed bundle ID"
                )

    if schema is None:
        try:
            schema = load_strict_json(PUBLIC_BUILD_SCHEMA_PATH)
        except ExtractionError as error:
            errors.append(str(error))
            return errors
    marker = schema.get("x-public-build-contract")
    runtime_semantics = (
        marker.get("runtime_semantics") if isinstance(marker, dict) else None
    )
    runtime_property = (
        marker.get("runtime_property") if isinstance(marker, dict) else None
    )
    runtime_root_pointer = (
        marker.get("runtime_root") if isinstance(marker, dict) else None
    )
    if (
        not isinstance(marker, dict)
        or marker.get("mode") != "runtime"
        or marker.get("version") != 2
        or not isinstance(runtime_semantics, dict)
        or not isinstance(runtime_property, str)
        or not runtime_property
        or not isinstance(runtime_root_pointer, str)
    ):
        errors.append(
            "current public-build experiment bundles require a versioned runtime "
            "schema marker instead of the planned-only contract"
        )
    else:
        runtime_root = resolve_schema_pointer(schema, runtime_root_pointer)
        root_properties = schema.get("properties")
        runtime_property_schema = (
            root_properties.get(runtime_property)
            if isinstance(root_properties, dict)
            else None
        )
        runtime_property_ref = (
            runtime_property_schema.get("$ref")
            if isinstance(runtime_property_schema, dict)
            else None
        )
        missing_anchors = sorted(
            PUBLIC_BUILD_RUNTIME_SCHEMA_ANCHORS - set(runtime_semantics)
        )
        unexpected_anchors = sorted(
            set(runtime_semantics) - PUBLIC_BUILD_RUNTIME_SCHEMA_ANCHORS
        )
        duplicate_pointers = duplicates(
            [
                pointer
                for pointer in runtime_semantics.values()
                if isinstance(pointer, str)
            ]
        )
        invalid_anchors: list[str] = []
        unconstrained_anchors: list[str] = []
        runtime_required = (
            runtime_root.get("required") if isinstance(runtime_root, dict) else None
        )
        runtime_properties = (
            runtime_root.get("properties")
            if isinstance(runtime_root, dict)
            else None
        )
        for name, pointer in runtime_semantics.items():
            target = resolve_schema_pointer(schema, pointer)
            expected_prefix = f"{runtime_root_pointer}/properties/"
            property_name = (
                pointer.removeprefix(expected_prefix)
                if isinstance(pointer, str) and pointer.startswith(expected_prefix)
                else None
            )
            if (
                name not in PUBLIC_BUILD_RUNTIME_SCHEMA_ANCHORS
                or not isinstance(target, dict)
                or target.get("x-public-build-runtime-semantic") != name
                or not isinstance(property_name, str)
                or "/" in property_name
                or not isinstance(runtime_required, list)
                or property_name not in runtime_required
                or not isinstance(runtime_properties, dict)
                or runtime_properties.get(property_name) is not target
            ):
                invalid_anchors.append(name)
            elif not schema_rejects_empty_values(schema, target):
                unconstrained_anchors.append(name)
        runtime_required_by_discriminator = any(
            isinstance(clause, dict)
            and clause.get("if", {}).get("properties", {}).get("status", {}).get("const")
            == "planned"
            and runtime_property
            in clause.get("else", {}).get("required", [])
            for clause in schema.get("allOf", [])
        )
        runtime_root_valid = (
            isinstance(runtime_root, dict)
            and runtime_root.get("type") == "object"
            and runtime_required_by_discriminator
            and runtime_property_ref == runtime_root_pointer
        )
        if (
            not runtime_root_valid
            or missing_anchors
            or unexpected_anchors
            or duplicate_pointers
            or invalid_anchors
            or unconstrained_anchors
        ):
            errors.append(
                "current public-build runtime schema must bind every required runtime "
                "semantic to a distinct marked property with an enforcing schema "
                "assertion under a required runtime evidence root; "
                f"root_valid={runtime_root_valid}, missing={missing_anchors}, "
                f"unexpected={unexpected_anchors}, duplicate={duplicate_pointers}, "
                f"invalid={sorted(invalid_anchors)}, "
                f"unconstrained={sorted(unconstrained_anchors)}"
            )

    runner_path = runner_path or ROOT / PUBLIC_BUILD_RUNNER_PATH
    if not runner_path.is_file() or runner_path.is_symlink():
        errors.append(
            "current public-build experiment bundles require the repository-owned "
            f"runner at {PUBLIC_BUILD_RUNNER_PATH}"
        )
    elif not callable(run_bundle):
        errors.append(
            "current public-build experiment bundles require the fixed production "
            "run <planned-bundle> entry point"
        )

    try:
        mise_config = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))
        mise_lock = tomllib.loads((ROOT / "mise.lock").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        errors.append(f"cannot validate public-build mise configuration: {error}")
    else:
        sdk_config = mise_config.get("tools", {}).get(MISE_TOOL_NAME)
        sdk_lock_entries = mise_lock.get("tools", {}).get(MISE_TOOL_NAME)
        sdk_lock = (
            sdk_lock_entries[0]
            if isinstance(sdk_lock_entries, list) and len(sdk_lock_entries) == 1
            else None
        )
        expected_platform = {
            "url": DOTNET_SDK_ARCHIVE_URL,
            "checksum": f"sha512:{DOTNET_SDK_ARCHIVE_SHA512}",
        }
        if (
            MISE_TOOL_NAME
            not in mise_config.get("settings", {}).get("disable_tools", [])
            or not isinstance(sdk_config, dict)
            or sdk_config.get("version") != DOTNET_SDK_VERSION
            or sdk_config.get("platforms") != {"linux-x64": expected_platform}
            or "postinstall" in sdk_config
            or not isinstance(sdk_lock, dict)
            or sdk_lock.get("version") != DOTNET_SDK_VERSION
            or sdk_lock.get("backend") != MISE_TOOL_NAME
            or {
                key: value
                for key, value in sdk_lock.items()
                if key.startswith("platforms.")
            }
            != {"platforms.linux-x64": expected_platform}
        ):
            errors.append(
                "public-build SDK must remain a disabled-by-default, postinstall-free, "
                "Linux-x64-only locked HTTP tool"
            )

    implementation = control["implementation"]
    required_step = "public-build-runner-conformance"
    if (
        control["runner"] != "hk"
        or control["enforcement"] != "blocking"
        or implementation["kind"] != "hk-steps"
        or any(
            required_step not in implementation["steps"].get(execution_point, [])
            for execution_point in ("local-fast", "ci")
        )
        or not {"local-fast", "ci"}.issubset(control["execution_points"])
    ):
        errors.append(
            "current public-build evidence control must be blocking at local-fast "
            "and ci through the public-build-runner-conformance HK step"
        )
    return errors


def resolve_schema_pointer(schema: dict[str, Any], pointer: Any) -> Any | None:
    if not isinstance(pointer, str) or not pointer.startswith("#/"):
        return None
    value: Any = schema
    for raw_part in pointer[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def schema_rejects_empty_values(
    schema: dict[str, Any],
    node: dict[str, Any],
) -> bool:
    probe_schema = {
        "$schema": schema.get(
            "$schema",
            "https://json-schema.org/draft/2020-12/schema",
        ),
        "$defs": schema.get("$defs", {}),
        "allOf": [node],
    }
    validator = Draft202012Validator(probe_schema)
    return all(
        not validator.is_valid(value)
        for value in ({}, [], "", None)
    )


def check_control_references(catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    controls = load_yaml("docs/governance/controls.yaml")["controls"]
    errors.extend(check_public_build_activation_coupling(catalog, controls))
    current_families = [
        family for family in catalog["families"] if family["state"] == "current"
    ]
    hk_execution_steps = hk_steps_by_execution_point(errors)
    for control in controls:
        if control["state"] != "current":
            continue
        for reference in control["governing_rules"]:
            path_text, separator, anchor = reference.partition("#")
            path = resolve_repository_file(
                path_text,
                f"control {control['id']} governing rule",
                errors,
            )
            if path is None:
                continue
            relative_path = path.relative_to(ROOT_RESOLVED).as_posix()
            if path.suffix.lower() != ".md":
                errors.append(
                    f"control {control['id']} governing rule is not Markdown: {path_text}"
                )
                continue
            if not any(
                family["format"] == "markdown"
                and matches(relative_path, family["path"])
                for family in current_families
            ):
                errors.append(
                    f"control {control['id']} governing rule is not a current governed "
                    f"Markdown record: {path_text}"
                )
            if separator and anchor not in markdown_heading_slugs(path):
                errors.append(
                    f"control {control['id']} governing-rule anchor does not exist or "
                    f"is not an ASCII GitHub heading anchor: {reference}"
                )

        implementation = control["implementation"]
        if control["runner"] == "hk":
            if implementation["kind"] != "hk-steps":
                errors.append(f"control {control['id']} must identify its hk steps")
                continue
            declared_points = set(implementation["steps"])
            execution_points = set(control["execution_points"])
            if declared_points != execution_points:
                errors.append(
                    f"control {control['id']} hk step mappings must match its execution "
                    "points"
                )
            for execution_point, declared_steps in implementation["steps"].items():
                actual_steps = hk_execution_steps.get(execution_point)
                if actual_steps is None:
                    errors.append(
                        f"control {control['id']} uses unsupported hk execution point "
                        f"{execution_point}"
                    )
                    continue
                missing_steps = sorted(set(declared_steps) - actual_steps)
                if missing_steps:
                    errors.append(
                        f"control {control['id']} is not wired at {execution_point}: "
                        f"{', '.join(missing_steps)}"
                    )
        elif implementation["kind"] == "hk-steps":
            errors.append(f"non-hk control {control['id']} must not declare hk steps")
        elif implementation["kind"] == "repository-path":
            resolve_repository_file(
                implementation["value"],
                f"control {control['id']} implementation",
                errors,
            )
    return errors


def check_documentation_portal(
    current_family_paths: dict[str, set[Path]],
) -> list[str]:
    portal = ROOT / "docs/README.md"
    if not portal.is_file():
        return ["documentation portal does not exist: docs/README.md"]
    linked_records: set[str] = set()
    for target in markdown_link_destinations(portal.read_text(encoding="utf-8")):
        path_part = target.split("#", maxsplit=1)[0]
        if not path_part or "://" in path_part:
            continue
        resolved = (portal.parent / path_part).resolve()
        try:
            relative_path = resolved.relative_to(ROOT_RESOLVED)
        except ValueError:
            continue
        if resolved.is_file():
            linked_records.add(relative_path.as_posix())

    retained_records = {
        path.relative_to(ROOT_RESOLVED).as_posix()
        for paths in current_family_paths.values()
        for path in paths
        if path.is_file() and path != portal
    }
    return [
        f"documentation portal does not route to retained record: {relative_path}"
        for relative_path in sorted(retained_records - linked_records)
    ]


def check_catalog_paths() -> list[str]:
    errors = check_markdown_parser_contract()
    catalog = load_yaml("docs/governance/record-families.yaml")
    current = [family for family in catalog["families"] if family["state"] == "current"]
    current_family_paths: dict[str, set[Path]] = {}
    governed_paths = discover_governed_record_paths(errors)

    for family in catalog["families"]:
        pattern = family["path"]
        family_paths = expand_family_paths(family, errors)
        if family["state"] == "current":
            current_family_paths[family["id"]] = family_paths
            if family["carrier"] == "repository-file":
                if contains_glob(pattern):
                    errors.append(
                        f"{family['id']} uses a glob for a singleton path: {pattern}"
                    )
                elif not family_paths:
                    errors.append(f"{family['id']} path does not exist: {pattern}")
            elif not family_paths:
                errors.append(
                    f"{family['id']} path matches no current files: {pattern}"
                )
            for path in sorted(family_paths - governed_paths):
                errors.append(
                    f"current family {family['id']} path is outside governed record "
                    f"roots: {path.relative_to(ROOT_RESOLVED).as_posix()}"
                )
        elif family_paths:
            errors.append(
                f"{family['id']} has a record instance but remains scheduled; "
                "activate the family in the same change"
            )

        if schema := family.get("schema"):
            resolve_repository_file(
                schema,
                f"{family['id']} schema",
                errors,
            )

    for path in sorted(governed_paths):
        relative_path = path.relative_to(ROOT_RESOLVED).as_posix()
        matching_families = [
            family["id"] for family in current if matches(relative_path, family["path"])
        ]
        if not matching_families:
            errors.append(f"governed record has no current family: {relative_path}")
        elif len(matching_families) > 1:
            errors.append(
                f"governed record matches multiple current families: {relative_path} "
                f"({', '.join(matching_families)})"
            )

    errors.extend(check_documentation_portal(current_family_paths))
    errors.extend(check_control_references(catalog))
    return errors


def validate_public_build_source_baseline_value(
    baseline: dict[str, Any],
    relative_path: str,
) -> list[str]:
    errors: list[str] = []
    source_commit_prefix = f"{baseline['source']['commit']}:"
    source_references = [
        reference
        for stage in baseline["stage_applicability"].values()
        for reference in stage["source_references"]
    ]
    targets = baseline["attempted_targets"]
    source_references.extend(
        reference
        for target in targets
        for reference in target["source_references"]
    )
    target_ids = [target["id"] for target in targets]
    target_paths = [target["project_path"] for target in targets]
    for identifier in duplicates(target_ids):
        errors.append(f"{relative_path}: duplicate attempted target id: {identifier}")
    for project_path in duplicates(target_paths):
        errors.append(f"{relative_path}: duplicate attempted project path: {project_path}")
    target_id_set = set(target_ids)
    for target in targets:
        unknown_references = sorted(
            set(target["project_references"]) - target_id_set
        )
        if unknown_references:
            errors.append(
                f"{relative_path}: target {target['id']} references projects outside "
                f"the fixed solution baseline: {unknown_references}"
            )

    package_targets = baseline["package_targets"]
    source_references.extend(
        reference
        for package_target in package_targets
        for reference in package_target["source_references"]
    )
    package_target_ids = [
        package_target["target_id"] for package_target in package_targets
    ]
    for target_id in duplicates(package_target_ids):
        errors.append(f"{relative_path}: duplicate package target id: {target_id}")
    unknown_package_targets = sorted(set(package_target_ids) - target_id_set)
    if unknown_package_targets:
        errors.append(
            f"{relative_path}: package targets reference unknown attempted targets "
            f"{unknown_package_targets}"
        )
    package_ids = [
        package_target["package_id"].casefold()
        for package_target in package_targets
    ]
    for package_id in duplicates(package_ids):
        errors.append(f"{relative_path}: duplicate package identity: {package_id}")

    declarations = baseline["source_declared_direct"]
    source_references.extend(
        reference
        for declaration in declarations
        for reference in [
            declaration["declaration_location"],
            *declaration["auxiliary_locations"],
        ]
    )
    for reference in source_references:
        if not reference.startswith(source_commit_prefix):
            errors.append(
                f"{relative_path}: source reference does not use the canonical "
                f"source commit: {reference}"
            )
    declaration_ids = [
        declaration["declaration_id"] for declaration in declarations
    ]
    declaration_locations = [
        declaration["declaration_location"] for declaration in declarations
    ]
    for identifier in duplicates(declaration_ids):
        errors.append(f"{relative_path}: duplicate dependency declaration id: {identifier}")
    for location in duplicates(declaration_locations):
        errors.append(
            f"{relative_path}: duplicate dependency declaration location: {location}"
        )
    for declaration in declarations:
        unknown_targets = sorted(set(declaration["targets"]) - target_id_set)
        if unknown_targets:
            errors.append(
                f"{relative_path}: declaration {declaration['declaration_id']} "
                f"references unknown targets {unknown_targets}"
            )
        if declaration["kind"] == "package":
            unexpected_assembly_fields = sorted(
                field
                for field in ("path_property", "assembly_relative_path")
                if field in declaration
            )
            if unexpected_assembly_fields:
                errors.append(
                    f"{relative_path}: package declaration "
                    f"{declaration['declaration_id']} contains package-backed "
                    f"assembly fields {unexpected_assembly_fields}"
                )
        else:
            assembly_relative_path = PurePosixPath(
                declaration["assembly_relative_path"]
            )
            if (
                assembly_relative_path.is_absolute()
                or ".." in assembly_relative_path.parts
                or assembly_relative_path.as_posix()
                != declaration["assembly_relative_path"]
            ):
                errors.append(
                    f"{relative_path}: package-backed assembly declaration "
                    f"{declaration['declaration_id']} must use a normalized relative "
                    "assembly path"
                )

    actual_source_manifest_sha256 = canonical_sha256(
        source_manifest_payload(
            baseline["stage_applicability"],
            targets,
            package_targets,
            declarations,
        )
    )
    if baseline["source_manifest_sha256"] != actual_source_manifest_sha256:
        errors.append(
            f"{relative_path}: source manifest SHA-256 does not match its canonical "
            "stage applicability, targets, and declarations"
        )
    lasso_declarations = [
        declaration
        for declaration in declarations
        if declaration["kind"] == "package"
        and declaration["id"].casefold() == "microsoft.office.lasso"
    ]
    if len(lasso_declarations) != 1:
        errors.append(
            f"{relative_path}: source baseline must contain exactly one "
            "Microsoft.Office.Lasso package declaration"
        )
    return errors


def validate_public_build_source_baseline(path: Path) -> list[str]:
    try:
        baseline = load_strict_json_path(path)
    except ExtractionError as error:
        return [str(error)]
    return validate_public_build_source_baseline_value(
        baseline,
        path.relative_to(ROOT).as_posix(),
    )


def validate_public_build_lasso_manifest_value(
    manifest: dict[str, Any],
    relative_path: str,
    expected_source: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    if expected_source is not None and manifest["source"] != expected_source:
        errors.append(
            f"{relative_path}: Lasso manifest source differs from the canonical "
            "public-build source baseline"
        )
    references = manifest["references"]
    reference_ids = [reference["id"] for reference in references]
    for identifier in duplicates(reference_ids):
        errors.append(f"{relative_path}: duplicate Lasso reference id: {identifier}")
    expected_ids = [
        f"lasso-ref-{index:03d}" for index in range(1, len(references) + 1)
    ]
    if set(reference_ids) != set(expected_ids):
        errors.append(
            f"{relative_path}: Lasso reference IDs must form a contiguous set"
        )
    reference_locations = [
        (
            reference["path"],
            reference["line"],
            reference["kind"],
            reference["symbol"],
        )
        for reference in references
    ]
    for reference in duplicates(
        ["\0".join(map(str, location)) for location in reference_locations]
    ):
        errors.append(
            f"{relative_path}: duplicate Lasso source-reference tuple: "
            f"{reference.replace(chr(0), ':')}"
        )
    if reference_locations != sorted(reference_locations):
        errors.append(
            f"{relative_path}: Lasso references must be sorted by path, line, kind, "
            "and symbol"
        )
    actual_manifest_sha256 = canonical_sha256(
        lasso_reference_manifest_payload(references)
    )
    if manifest["lasso_reference_manifest_sha256"] != actual_manifest_sha256:
        errors.append(
            f"{relative_path}: Lasso manifest SHA-256 does not match its canonical "
            "source references"
        )
    return errors


def validate_public_build_lasso_manifest(path: Path) -> list[str]:
    try:
        baseline = load_strict_json(PUBLIC_BUILD_SOURCE_BASELINE_PATH)
        manifest = load_strict_json_path(path)
    except ExtractionError as error:
        return [str(error)]
    return validate_public_build_lasso_manifest_value(
        manifest,
        path.relative_to(ROOT).as_posix(),
        baseline["source"],
    )
def check_public_build_static_fixtures() -> list[str]:
    errors: list[str] = []
    try:
        schema = load_strict_json(PUBLIC_BUILD_SCHEMA_PATH)
        baseline = load_strict_json(PUBLIC_BUILD_SOURCE_BASELINE_PATH)
        lasso_manifest = load_strict_json(PUBLIC_BUILD_LASSO_MANIFEST_PATH)
        bundle = load_strict_json(
            "docs/research/experiments/"
            "public-build-linux-x64-dotnet-8-0-424-01.json"
        )
    except ExtractionError as error:
        return [str(error)]

    schema_errors = list(Draft202012Validator(schema).iter_errors(bundle))
    if schema_errors:
        errors.append(
            "public-build singleton failed schema validation: "
            f"{schema_errors[0].message}"
        )
    else:
        errors.extend(
            validate_public_build_bundle_value(
                bundle,
                "fixture:actual-singleton",
                baseline,
                lasso_manifest,
            )
        )

    invalid_json = {
        "duplicate-key": b'{"value":1,"value":2}',
        "nan": b'{"value":NaN}',
        "positive-infinity": b'{"value":Infinity}',
        "negative-infinity": b'{"value":-Infinity}',
    }
    for name, content in invalid_json.items():
        try:
            parse_json_object_bytes(content, f"fixture:{name}")
        except ExtractionError:
            pass
        else:
            errors.append(f"unsupported JSON input fixture {name} was not rejected")

    for fixture_name, target_id, runtime_identifier, checkout_root in (
        ("testhelper", "target-testhelper-net8-0", "linux-x64", "/fixture/checkout"),
        (
            "benchmark-windows",
            "target-msalwrapper-benchmark-net8-0",
            "win-x64",
            "C:/fixture/checkout",
        ),
    ):
        root = ROOT / "tools/fixtures/public-build"
        assets_path = root / f"{fixture_name}.project.assets.json"
        expected_path = root / f"{fixture_name}.expected-projection.json"
        try:
            assets_bytes = assets_path.read_bytes()
            actual = extract_projection(
                parse_json_object_bytes(assets_bytes, str(assets_path)),
                assets_bytes,
                baseline,
                target_id,
                runtime_identifier,
                checkout_root,
            )
            expected = parse_json_object_bytes(
                expected_path.read_bytes(), str(expected_path)
            )
        except (OSError, ExtractionError) as error:
            errors.append(f"public-build extractor fixture {fixture_name} failed: {error}")
        else:
            if actual != expected:
                errors.append(
                    f"public-build extractor fixture {fixture_name} did not exactly replay"
                )

    fixture_assets_path = ROOT / "tools/fixtures/public-build/testhelper.project.assets.json"
    orphan_assets = load_strict_json_path(fixture_assets_path)
    orphan_key = "Unrelated.Package/9.9.9"
    orphan_assets["targets"]["net8.0/linux-x64"][orphan_key] = {
        "type": "package"
    }
    orphan_assets["libraries"][orphan_key] = {"type": "package"}
    try:
        extract_projection(
            orphan_assets,
            json.dumps(orphan_assets).encode(),
            baseline,
            "target-testhelper-net8-0",
            "linux-x64",
            "/fixture/checkout",
        )
    except ExtractionError as error:
        if "unreachable" not in str(error):
            errors.append(f"public-build orphan fixture failed unclearly: {error}")
    else:
        errors.append("public-build extractor accepted an unreachable package node")

    for (resolved, constraint), expected in {
        ("1", "[1]"): True,
        ("2", "[1,3)"): True,
        ("8.0.0", "(8.0.0, )"): False,
        ("7.9.9", "8.0.0"): False,
    }.items():
        if nuget_version_satisfies_constraint(resolved, constraint) != expected:
            errors.append(
                f"bounded NuGet constraint fixture failed for {resolved} against {constraint}"
            )
    if nuget_constraint_is_valid("[1.0.0-alpha..1, )"):
        errors.append("bounded NuGet grammar accepted an invalid constraint")

    for component_name in ("validator", "schema", "lockfile"):
        drift = copy.deepcopy(bundle)
        drift["components"][component_name]["sha256"] = "0" * 64
        drift_errors = validate_public_build_bundle_value(
            drift,
            f"fixture:live-{component_name}-drift",
            baseline,
            lasso_manifest,
        )
        if not any("live component drift" in error for error in drift_errors):
            errors.append(
                f"public-build {component_name} drift fixture was not rejected"
            )

    applicable = copy.deepcopy(baseline)
    declaration = next(
        item
        for item in applicable["source_declared_direct"]
        if item["kind"] == "package-backed-assembly"
    )
    declaration["condition"] = "always"
    applicable_errors = validate_public_build_bundle_value(
        bundle, "fixture:applicable-assembly", applicable, lasso_manifest
    )
    if not any("atomic runtime-contract expansion" in error for error in applicable_errors):
        errors.append("applicable package-backed declaration fixture was not rejected")

    catalog = load_yaml("docs/governance/record-families.yaml")
    controls = load_yaml("docs/governance/controls.yaml")["controls"]
    mismatched = copy.deepcopy(catalog)
    next(
        family
        for family in mismatched["families"]
        if family["id"] == "public-build-experiment-bundles"
    )["state"] = "scheduled"
    if not check_public_build_activation_coupling(mismatched, controls):
        errors.append("public-build family/control mismatch was not rejected")
    errors.extend(check_public_build_activation_coupling(catalog, controls, schema=schema))
    return errors


def run_schema_validation(schema: str, instances: list[Path]) -> int:
    result = subprocess.run(
        [
            "check-jsonschema",
            "--schemafile",
            schema,
            *(path.relative_to(ROOT_RESOLVED).as_posix() for path in instances),
        ],
        cwd=ROOT,
        check=False,
    )
    return result.returncode


def run_metaschema_validation(instances: list[Path]) -> int:
    result = subprocess.run(
        [
            "check-jsonschema",
            "--check-metaschema",
            *(path.relative_to(ROOT_RESOLVED).as_posix() for path in instances),
        ],
        cwd=ROOT,
        check=False,
    )
    return result.returncode


def validate_structured_records() -> int:
    errors: list[str] = []
    for schema, instance in BOOTSTRAP_SCHEMA_BINDINGS:
        schema_path = ROOT / schema
        instance_path = ROOT / instance
        if not schema_path.is_file():
            errors.append(f"bootstrap schema does not exist: {schema}")
            continue
        if not instance_path.is_file():
            errors.append(f"bootstrap structured record does not exist: {instance}")
            continue
        if run_schema_validation(schema, [instance_path]) != 0:
            return 1

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    catalog = load_yaml("docs/governance/record-families.yaml")
    bootstrap_bindings = set(BOOTSTRAP_SCHEMA_BINDINGS)
    families = [
        family
        for family in catalog["families"]
        if (
            family.get("schema")
            and (family["schema"], family["path"]) not in bootstrap_bindings
        )
        or family["format"] == "json-schema"
    ]
    for family in families:
        instances = sorted(expand_family_paths(family, errors))
        if not instances:
            if family["state"] == "current":
                errors.append(
                    f"{family['id']} has no structured record at {family['path']}"
                )
            continue

        if family["format"] == "json-schema":
            if run_metaschema_validation(instances) != 0:
                return 1
        elif run_schema_validation(family["schema"], instances) != 0:
            return 1

        if family["id"] == "public-build-experiment-bundles":
            bundle_records = [
                (
                    instance.relative_to(ROOT).as_posix(),
                    load_strict_json_path(instance),
                )
                for instance in instances
            ]
            for label, bundle in bundle_records:
                errors.extend(
                    validate_public_build_bundle_instance(
                        bundle,
                        label,
                    )
                )
        elif family["id"] == "public-build-source-baseline":
            for instance in instances:
                errors.extend(validate_public_build_source_baseline(instance))
        elif family["id"] == "public-build-lasso-reference-manifest":
            for instance in instances:
                errors.extend(validate_public_build_lasso_manifest(instance))

        if family["state"] == "scheduled":
            errors.append(
                f"{family['id']} has a record instance but remains scheduled; "
                "activate the family in the same change"
            )

    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if errors:
        return 1

    fixture_errors = check_public_build_static_fixtures()
    for error in fixture_errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if fixture_errors else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("identifiers")
    subparsers.add_parser("schemas")
    subparsers.add_parser("catalog-paths")
    args = parser.parse_args()

    if args.command == "schemas":
        return validate_structured_records()

    errors = check_identifiers() if args.command == "identifiers" else check_catalog_paths()
    if not errors:
        return 0
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
