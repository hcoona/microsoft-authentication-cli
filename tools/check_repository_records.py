# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["PyYAML==6.0.3", "jsonschema==4.25.1", "markdown-it-py==4.2.0"]
# ///

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable

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
    PCACACHE_TEST_FILTER,
    PCACACHE_TEST_LIMITATION,
)


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
SOURCE_FAITHFUL_PACKAGE_SOURCE = (
    "https://pkgs.dev.azure.com/office/_packaging/Office/nuget/v3/index.json"
)
PUBLIC_PACKAGE_SOURCE = "https://api.nuget.org/v3/index.json"
EXTRACTOR_LIMITATION = (
    "Exact extractor replay proves that the recorded projection matches the retained "
    "project.assets.json bytes; it does not prove network access, cache emptiness, "
    "credential-provider absence, or causal attribution."
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
        or not isinstance(marker.get("version"), int)
        or marker["version"] < 1
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
        root_required = schema.get("required")
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
        runtime_root_valid = (
            isinstance(runtime_root, dict)
            and runtime_root.get("type") == "object"
            and isinstance(root_required, list)
            and runtime_property in root_required
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


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def normalized_absolute_path(
    value: str,
) -> tuple[str, PurePosixPath | PureWindowsPath] | None:
    if "\\" in value:
        return None
    is_windows = re.match(r"^[A-Za-z]:/", value) is not None
    if not is_windows and value.startswith("//"):
        return None
    raw_parts = value[3:].split("/") if is_windows else value.split("/")
    if any(part in {".", ".."} for part in raw_parts):
        return None
    if is_windows and any(part.endswith((" ", ".")) for part in raw_parts):
        return None
    path: PurePosixPath | PureWindowsPath
    if is_windows:
        path = PureWindowsPath(value)
        kind = "windows"
    else:
        path = PurePosixPath(value)
        kind = "posix"
    if not path.is_absolute() or path.as_posix() != value:
        return None
    return kind, path


def recorded_path_is_within(
    child: tuple[str, PurePosixPath | PureWindowsPath],
    parent: tuple[str, PurePosixPath | PureWindowsPath],
    allow_equal: bool = False,
) -> bool:
    child_kind, child_path = child
    parent_kind, parent_path = parent
    if child_kind != parent_kind:
        return False
    if child_kind == "windows":
        child_parts = tuple(part.casefold() for part in child_path.parts)
        parent_parts = tuple(part.casefold() for part in parent_path.parts)
    else:
        child_parts = child_path.parts
        parent_parts = parent_path.parts
    if len(child_parts) < len(parent_parts):
        return False
    if not allow_equal and len(child_parts) == len(parent_parts):
        return False
    return child_parts[: len(parent_parts)] == parent_parts


def recorded_paths_overlap(
    left: tuple[str, PurePosixPath | PureWindowsPath],
    right: tuple[str, PurePosixPath | PureWindowsPath],
) -> bool:
    return recorded_path_is_within(left, right, allow_equal=True) or (
        recorded_path_is_within(right, left, allow_equal=True)
    )


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


def planned_command_topology() -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for source_mode in ("source-faithful", "public-only"):
        restore_id = f"{source_mode}-restore"
        build_id = f"{source_mode}-build"
        commands.extend(
            [
                {
                    "id": restore_id,
                    "source_mode": source_mode,
                    "stage": "restore",
                    "target": "AzureAuth.sln",
                    "depends_on": None,
                    "max_attempts": 1,
                    "timeout_seconds": 900,
                    "test_filter": None,
                },
                {
                    "id": build_id,
                    "source_mode": source_mode,
                    "stage": "build",
                    "target": "AzureAuth.sln",
                    "depends_on": restore_id,
                    "max_attempts": 1,
                    "timeout_seconds": 900,
                    "test_filter": None,
                },
                {
                    "id": f"{source_mode}-test",
                    "source_mode": source_mode,
                    "stage": "test",
                    "target": "AzureAuth.sln",
                    "depends_on": restore_id,
                    "max_attempts": 1,
                    "timeout_seconds": 900,
                    "test_filter": PCACACHE_TEST_FILTER,
                },
                {
                    "id": f"{source_mode}-package-adopat",
                    "source_mode": source_mode,
                    "stage": "package",
                    "target": "src/AdoPat/AdoPat.csproj",
                    "depends_on": restore_id,
                    "max_attempts": 1,
                    "timeout_seconds": 900,
                    "test_filter": None,
                },
                {
                    "id": f"{source_mode}-package-azureauth",
                    "source_mode": source_mode,
                    "stage": "package",
                    "target": "src/AzureAuth/AzureAuth.csproj",
                    "depends_on": restore_id,
                    "max_attempts": 1,
                    "timeout_seconds": 900,
                    "test_filter": None,
                },
                {
                    "id": f"{source_mode}-package-msalwrapper-benchmark",
                    "source_mode": source_mode,
                    "stage": "package",
                    "target": (
                        "src/MSALWrapper.Benchmark/"
                        "MSALWrapper.Benchmark.csproj"
                    ),
                    "depends_on": restore_id,
                    "max_attempts": 1,
                    "timeout_seconds": 900,
                    "test_filter": None,
                },
                {
                    "id": f"{source_mode}-package-msalwrapper",
                    "source_mode": source_mode,
                    "stage": "package",
                    "target": "src/MSALWrapper/MSALWrapper.csproj",
                    "depends_on": restore_id,
                    "max_attempts": 1,
                    "timeout_seconds": 900,
                    "test_filter": None,
                },
                {
                    "id": f"{source_mode}-package-testhelper",
                    "source_mode": source_mode,
                    "stage": "package",
                    "target": "src/TestHelper/TestHelper.csproj",
                    "depends_on": restore_id,
                    "max_attempts": 1,
                    "timeout_seconds": 900,
                    "test_filter": None,
                },
            ]
        )
    return commands


def normalized_planned_command(command: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(command)
    normalized["timeout_seconds"] = 900
    return normalized


def validate_public_build_bundle_value(
    bundle: dict[str, Any],
    relative_path: str,
    baseline: dict[str, Any] | None = None,
    lasso_manifest: dict[str, Any] | None = None,
    require_runtime_runner: bool = False,
) -> list[str]:
    errors: list[str] = []
    baseline = baseline or load_strict_json(PUBLIC_BUILD_SOURCE_BASELINE_PATH)
    lasso_manifest = lasso_manifest or load_strict_json(
        PUBLIC_BUILD_LASSO_MANIFEST_PATH
    )

    authorities = bundle["authorities"]
    if (
        authorities["source_baseline"]["payload_sha256"]
        != baseline["source_manifest_sha256"]
    ):
        errors.append(
            f"{relative_path}: source authority hash differs from the fixed baseline"
        )
    if (
        authorities["lasso_manifest"]["payload_sha256"]
        != lasso_manifest["lasso_reference_manifest_sha256"]
    ):
        errors.append(
            f"{relative_path}: Lasso authority hash differs from the fixed manifest"
        )
    if baseline["source"] != lasso_manifest["source"]:
        errors.append(
            f"{relative_path}: fixed source and Lasso authorities identify "
            "different source"
        )

    source_modes = bundle["protocol"]["source_modes"]
    expected_modes = [
        {
            "id": "source-faithful",
            "configuration": "audited-checkout",
            "package_sources": [SOURCE_FAITHFUL_PACKAGE_SOURCE],
        },
        {
            "id": "public-only",
            "configuration": "isolated-generated",
            "package_sources": [PUBLIC_PACKAGE_SOURCE],
        },
    ]
    if source_modes != expected_modes:
        errors.append(
            f"{relative_path}: source modes must be the canonical source-faithful "
            "and public-only configurations"
        )

    commands = bundle["protocol"]["commands"]
    expected_commands = planned_command_topology()
    if len(commands) == len(expected_commands):
        normalized_commands = [
            normalized_planned_command(command) for command in commands
        ]
        if normalized_commands != expected_commands:
            errors.append(
                f"{relative_path}: command topology differs from the canonical "
                "two-mode restore/build/test/package plan"
            )
    else:
        errors.append(
            f"{relative_path}: command topology must contain exactly sixteen commands"
        )
    if any(
        not isinstance(command["timeout_seconds"], int)
        or command["timeout_seconds"] <= 0
        for command in commands
    ):
        errors.append(f"{relative_path}: every command must have a finite timeout")

    package_target_paths = {
        target["project_path"]
        for target in baseline["attempted_targets"]
        if target["id"]
        in {
            package_target["target_id"]
            for package_target in baseline["package_targets"]
        }
    }
    planned_package_paths = {
        command["target"]
        for command in commands
        if command["stage"] == "package"
    }
    if planned_package_paths != package_target_paths:
        errors.append(
            f"{relative_path}: package commands differ from the fixed package targets"
        )

    isolation = bundle["isolation"]
    environment = bundle["environment"]
    runtime_identifier = environment["runtime_identifier"]
    expected_path_kind = (
        "windows" if runtime_identifier.startswith("win-") else "posix"
    )
    path_values = {
        "selection root": isolation["selection_root"],
        "checkout root": isolation["checkout_root"],
        "mise data root": environment["dotnet_sdk"]["manager_data_root"],
        ".NET installation root": environment["dotnet_sdk"]["installation_root"],
        ".NET host path": environment["dotnet_sdk"]["host_path"],
    }
    normalized_paths: dict[
        str, tuple[str, PurePosixPath | PureWindowsPath]
    ] = {}
    for label, value in path_values.items():
        normalized = normalized_absolute_path(value)
        if normalized is None:
            errors.append(f"{relative_path}: {label} must be a canonical absolute path")
        else:
            normalized_paths[label] = normalized
            if normalized[0] != expected_path_kind:
                errors.append(
                    f"{relative_path}: {label} must use {expected_path_kind} paths "
                    f"for runtime {runtime_identifier}"
                )

    selection = normalized_paths.get("selection root")
    checkout = normalized_paths.get("checkout root")
    manager = normalized_paths.get("mise data root")
    installation = normalized_paths.get(".NET installation root")
    host = normalized_paths.get(".NET host path")
    if selection and checkout and not recorded_path_is_within(checkout, selection):
        errors.append(
            f"{relative_path}: checkout root must be inside the selection root"
        )
    if manager and installation and not recorded_path_is_within(
        installation, manager
    ):
        errors.append(
            f"{relative_path}: .NET installation root must be inside the mise data root"
        )
    if installation and host and not recorded_path_is_within(host, installation):
        errors.append(
            f"{relative_path}: .NET host path must be inside the installation root"
        )
    if selection and manager and recorded_paths_overlap(selection, manager):
        errors.append(
            f"{relative_path}: selection and toolchain roots must not overlap"
        )

    if PCACACHE_TEST_LIMITATION not in bundle["limitations"]:
        errors.append(
            f"{relative_path}: limitations must disclose the PCACache exclusion"
        )
    evidence_plan = bundle["evidence_plan"]
    extractor_components = evidence_plan["extractor"]
    expected_extractor_components = {
        "entry_point": PUBLIC_BUILD_EXTRACTOR_PATH,
        "nuget_versions": PUBLIC_BUILD_NUGET_VERSIONS_PATH,
    }
    for component_name, expected_path in expected_extractor_components.items():
        component = extractor_components[component_name]
        component_path = ROOT / component["path"]
        if component["path"] != expected_path:
            errors.append(
                f"{relative_path}: extractor component {component_name} uses an "
                "unexpected repository path"
            )
        elif not component_path.is_file() or component_path.is_symlink():
            errors.append(
                f"{relative_path}: extractor component {component_name} does not "
                "exist as a regular repository file"
            )
        elif (
            hashlib.sha256(component_path.read_bytes()).hexdigest()
            != component["sha256"]
        ):
            errors.append(
                f"{relative_path}: extractor component {component_name} hash "
                "differs from the reviewed file"
            )
    if require_runtime_runner:
        runner = environment["runner"]
        if runner["path"] != PUBLIC_BUILD_RUNNER_PATH:
            errors.append(
                f"{relative_path}: activated bundle must bind the canonical "
                f"repository runner {PUBLIC_BUILD_RUNNER_PATH}"
            )
            runner_path = ROOT / PUBLIC_BUILD_RUNNER_PATH
        else:
            runner_path = ROOT / runner["path"]
        if not runner_path.is_file() or runner_path.is_symlink():
            errors.append(
                f"{relative_path}: activated runner does not exist as a regular "
                "repository file"
            )
        elif hashlib.sha256(runner_path.read_bytes()).hexdigest() != runner["sha256"]:
            errors.append(
                f"{relative_path}: activated runner hash differs from the reviewed file"
            )
    return errors


def validate_public_build_bundle(path: Path) -> list[str]:
    try:
        bundle = load_yaml_path(path)
        return validate_public_build_bundle_value(
            bundle,
            path.relative_to(ROOT).as_posix(),
        )
    except (ExtractionError, ValueError) as error:
        return [str(error)]


def planned_bundle_fixture() -> dict[str, Any]:
    baseline = load_strict_json(PUBLIC_BUILD_SOURCE_BASELINE_PATH)
    lasso_manifest = load_strict_json(PUBLIC_BUILD_LASSO_MANIFEST_PATH)
    extractor_hash = hashlib.sha256(
        (ROOT / PUBLIC_BUILD_EXTRACTOR_PATH).read_bytes()
    ).hexdigest()
    nuget_versions_hash = hashlib.sha256(
        (ROOT / PUBLIC_BUILD_NUGET_VERSIONS_PATH).read_bytes()
    ).hexdigest()
    return {
        "schema_version": 1,
        "id": "public-build-fixture-linux",
        "status": "planned",
        "issue": {
            "number": 1,
            "url": (
                "https://github.com/hcoona/"
                "microsoft-authentication-cli/issues/1"
            ),
        },
        "authorities": {
            "source_baseline": {
                "path": PUBLIC_BUILD_SOURCE_BASELINE_PATH,
                "payload_sha256": baseline["source_manifest_sha256"],
            },
            "lasso_manifest": {
                "path": PUBLIC_BUILD_LASSO_MANIFEST_PATH,
                "payload_sha256": lasso_manifest[
                    "lasso_reference_manifest_sha256"
                ],
            },
        },
        "environment": {
            "host_type": "synthetic-linux",
            "runtime_identifier": "linux-x64",
            "dotnet_sdk": {
                "version": "8.0.100",
                "manager_data_root": "/fixture/toolchain",
                "installation_root": "/fixture/toolchain/installs/dotnet/8.0.100",
                "host_path": "/fixture/toolchain/installs/dotnet/8.0.100/dotnet",
                "host_sha256": "1" * 64,
            },
            "runner": {
                "path": "tools/run_public_build_experiment.py",
                "sha256": "2" * 64,
            },
        },
        "isolation": {
            "selection_root": "/fixture/run",
            "checkout_root": "/fixture/run/checkout",
            "replacement_environment": {
                "inherit_parent": False,
                "allowlist_defined_by_activation_contract": True,
            },
            "exclusive_no_follow_root_creation": True,
            "single_runner_invocation": True,
            "later_process_may_resume_or_cleanup": False,
        },
        "protocol": {
            "source_modes": [
                {
                    "id": "source-faithful",
                    "configuration": "audited-checkout",
                    "package_sources": [SOURCE_FAITHFUL_PACKAGE_SOURCE],
                },
                {
                    "id": "public-only",
                    "configuration": "isolated-generated",
                    "package_sources": [PUBLIC_PACKAGE_SOURCE],
                },
            ],
            "commands": planned_command_topology(),
        },
        "evidence_plan": {
            "retain_raw_project_assets": True,
            "strict_json_duplicate_rejection": True,
            "extractor": {
                "entry_point": {
                    "path": PUBLIC_BUILD_EXTRACTOR_PATH,
                    "sha256": extractor_hash,
                },
                "nuget_versions": {
                    "path": PUBLIC_BUILD_NUGET_VERSIONS_PATH,
                    "sha256": nuget_versions_hash,
                },
            },
            "exact_replay_required": True,
            "provenance_separate_from_projection": True,
            "cross_bindings": {
                "raw_asset_to_command_result": True,
                "projection_to_source_target": True,
                "package_nodes_to_provenance": True,
                "package_backed_assemblies_to_runtime_evidence": True,
                "limitations_to_conclusions": True,
            },
        },
        "limitations": [PCACACHE_TEST_LIMITATION],
        "policy_reference": (
            "docs/research/experiment-safety.md#phase-1-public-build-record"
        ),
    }


def validate_extractor_fixture_binding(
    actual: dict[str, Any],
    expected: dict[str, Any],
    source_mode: str,
    result_assets_sha256: str,
    provenance_node_ids: set[str],
    limitations: list[str],
    label: str,
) -> list[str]:
    errors: list[str] = []
    if actual != expected:
        errors.append(f"{label}: extractor replay differs from expected projection")
        return errors
    if result_assets_sha256 != actual["assets_file_sha256"]:
        errors.append(f"{label}: result does not bind the retained raw-assets hash")
    expected_source = (
        SOURCE_FAITHFUL_PACKAGE_SOURCE
        if source_mode == "source-faithful"
        else PUBLIC_PACKAGE_SOURCE
    )
    if actual["assets_projection"]["restore_metadata"]["sources"] != [expected_source]:
        errors.append(f"{label}: projection source differs from the source mode")
    package_node_ids = {
        node["node_id"]
        for node in actual["assets_projection"]["nodes"]
        if node["kind"] == "package"
    }
    if provenance_node_ids != package_node_ids:
        errors.append(f"{label}: package projection and provenance coverage differ")
    for required_limitation in (EXTRACTOR_LIMITATION, PCACACHE_TEST_LIMITATION):
        if required_limitation not in limitations:
            errors.append(f"{label}: required evidence limitation is missing")
    return errors


def replay_extractor_fixture(
    fixture_name: str,
    target_id: str,
    runtime_identifier: str,
    checkout_root: str,
) -> tuple[dict[str, Any], dict[str, Any], set[str]]:
    fixture_root = ROOT / "tools/fixtures/public-build"
    assets_path = fixture_root / f"{fixture_name}.project.assets.json"
    expected_path = fixture_root / f"{fixture_name}.expected-projection.json"
    assets_bytes = assets_path.read_bytes()
    assets = parse_json_object_bytes(assets_bytes, str(assets_path))
    expected = parse_json_object_bytes(expected_path.read_bytes(), str(expected_path))
    actual = extract_projection(
        assets,
        assets_bytes,
        load_strict_json(PUBLIC_BUILD_SOURCE_BASELINE_PATH),
        target_id,
        runtime_identifier,
        "net8.0",
        checkout_root,
    )
    package_nodes = {
        node["node_id"]
        for node in actual["assets_projection"]["nodes"]
        if node["kind"] == "package"
    }
    return actual, expected, package_nodes


def check_public_build_static_fixtures() -> list[str]:
    errors: list[str] = []
    try:
        schema = load_strict_json(PUBLIC_BUILD_SCHEMA_PATH)
        baseline = load_strict_json(PUBLIC_BUILD_SOURCE_BASELINE_PATH)
        lasso_manifest = load_strict_json(PUBLIC_BUILD_LASSO_MANIFEST_PATH)
    except ExtractionError as error:
        return [str(error)]

    validator = Draft202012Validator(schema)
    planned = planned_bundle_fixture()
    schema_errors = list(validator.iter_errors(planned))
    if schema_errors:
        errors.append(
            "public-build planned positive fixture failed schema validation: "
            f"{schema_errors[0].message}"
        )
    else:
        errors.extend(
            validate_public_build_bundle_value(
                planned,
                "fixture:planned",
                baseline,
                lasso_manifest,
            )
        )

    planned_negative_cases: list[
        tuple[str, Callable[[dict[str, Any]], None], str]
    ] = [
        (
            "source-binding",
            lambda value: value["authorities"]["source_baseline"].update(
                {"payload_sha256": "0" * 64}
            ),
            "source authority hash",
        ),
        (
            "command-topology",
            lambda value: value["protocol"]["commands"][1].update(
                {"depends_on": "public-only-restore"}
            ),
            "command topology differs",
        ),
        (
            "isolation",
            lambda value: value["environment"]["dotnet_sdk"].update(
                {"manager_data_root": "/fixture/run/toolchain"}
            ),
            "selection and toolchain roots must not overlap",
        ),
        (
            "runtime-path-flavor",
            lambda value: (
                value["isolation"].update(
                    {
                        "selection_root": "C:/fixture/run",
                        "checkout_root": "C:/fixture/run/checkout",
                    }
                ),
                value["environment"]["dotnet_sdk"].update(
                    {
                        "manager_data_root": "D:/fixture/toolchain",
                        "installation_root": "D:/fixture/toolchain/dotnet",
                        "host_path": "D:/fixture/toolchain/dotnet/dotnet.exe",
                    }
                ),
            ),
            "must use posix paths",
        ),
        (
            "posix-path-case",
            lambda value: value["isolation"].update(
                {"checkout_root": "/Fixture/run/checkout"}
            ),
            "checkout root must be inside",
        ),
    ]
    for name, mutate, expected_error in planned_negative_cases:
        negative = copy.deepcopy(planned)
        mutate(negative)
        if list(validator.iter_errors(negative)):
            errors.append(
                f"public-build planned semantic fixture {name} must remain schema-valid"
            )
            continue
        semantic_errors = validate_public_build_bundle_value(
            negative,
            f"fixture:{name}",
            baseline,
            lasso_manifest,
        )
        if not any(expected_error in error for error in semantic_errors):
            errors.append(
                f"public-build planned negative fixture {name} was not rejected"
            )

    stale_baseline = copy.deepcopy(baseline)
    stale_baseline["source_manifest_sha256"] = "0" * 64
    if not validate_public_build_source_baseline_value(
        stale_baseline,
        "fixture:source-hash",
    ):
        errors.append("public-build source hash negative fixture was not rejected")

    cross_source_manifest = copy.deepcopy(lasso_manifest)
    cross_source_manifest["source"]["commit"] = "0" * 40
    if not validate_public_build_lasso_manifest_value(
        cross_source_manifest,
        "fixture:lasso-source",
        baseline["source"],
    ):
        errors.append("public-build Lasso source negative fixture was not rejected")

    invalid_json_cases = {
        "duplicate-key": b'{"schema_version":1,"schema_version":2}',
        "nan": b'{"value":NaN}',
        "positive-infinity": b'{"value":Infinity}',
        "negative-infinity": b'{"value":-Infinity}',
        "positive-float-overflow": b'{"value":1e999}',
        "negative-float-overflow": b'{"value":-1e999}',
    }
    for name, content in invalid_json_cases.items():
        try:
            parse_json_object_bytes(content, f"fixture:{name}")
        except ExtractionError:
            pass
        else:
            errors.append(f"unsupported JSON input fixture {name} was not rejected")

    extractor_cases = (
        (
            "testhelper",
            "target-testhelper-net8-0",
            "linux-x64",
            "/fixture/checkout",
        ),
        (
            "benchmark-windows",
            "target-msalwrapper-benchmark-net8-0",
            "win-x64",
            "C:/fixture/checkout",
        ),
    )
    replayed: dict[
        str, tuple[dict[str, Any], dict[str, Any], set[str]]
    ] = {}
    for fixture_name, target_id, runtime_identifier, checkout_root in extractor_cases:
        try:
            actual, expected, package_nodes = replay_extractor_fixture(
                fixture_name,
                target_id,
                runtime_identifier,
                checkout_root,
            )
        except (OSError, ExtractionError) as error:
            errors.append(f"public-build extractor fixture {fixture_name} failed: {error}")
            continue
        replayed[fixture_name] = (actual, expected, package_nodes)
        errors.extend(
            validate_extractor_fixture_binding(
                actual,
                expected,
                "source-faithful",
                actual["assets_file_sha256"],
                package_nodes,
                [EXTRACTOR_LIMITATION, PCACACHE_TEST_LIMITATION],
                f"fixture:{fixture_name}",
            )
        )

    if "testhelper" in replayed:
        actual, expected, package_nodes = replayed["testhelper"]
        cross_binding_negatives = (
            (
                "result-hash",
                "0" * 64,
                package_nodes,
                [EXTRACTOR_LIMITATION, PCACACHE_TEST_LIMITATION],
                "result does not bind",
            ),
            (
                "provenance",
                actual["assets_file_sha256"],
                set(),
                [EXTRACTOR_LIMITATION, PCACACHE_TEST_LIMITATION],
                "projection and provenance coverage differ",
            ),
            (
                "limitation",
                actual["assets_file_sha256"],
                package_nodes,
                [PCACACHE_TEST_LIMITATION],
                "required evidence limitation is missing",
            ),
        )
        for name, result_hash, provenance, limitations, expected_error in (
            cross_binding_negatives
        ):
            binding_errors = validate_extractor_fixture_binding(
                actual,
                expected,
                "source-faithful",
                result_hash,
                provenance,
                limitations,
                f"fixture:{name}",
            )
            if not any(expected_error in error for error in binding_errors):
                errors.append(
                    f"public-build extractor negative fixture {name} was not rejected"
                )

    fixture_assets_path = (
        ROOT / "tools/fixtures/public-build/testhelper.project.assets.json"
    )
    orphan_assets = load_strict_json_path(fixture_assets_path)
    orphan_key = "Unrelated.Package/9.9.9"
    orphan_assets["targets"]["net8.0"][orphan_key] = {"type": "package"}
    orphan_assets["libraries"][orphan_key] = {"type": "package"}
    try:
        extract_projection(
            orphan_assets,
            json.dumps(orphan_assets).encode(),
            baseline,
            "target-testhelper-net8-0",
            "linux-x64",
            "net8.0",
            "/fixture/checkout",
        )
    except ExtractionError as error:
        if "unreachable" not in str(error):
            errors.append(
                "public-build orphan-node fixture failed for an unrelated reason: "
                f"{error}"
            )
    else:
        errors.append(
            "public-build extractor fixture accepted an unreachable package node"
        )

    version_cases = {
        ("1", "[1]"): True,
        ("2", "[1,3)"): True,
        ("8.0.0", "(8.0.0, )"): False,
        ("7.9.9", "8.0.0"): False,
    }
    for (resolved, constraint), expected in version_cases.items():
        if nuget_version_satisfies_constraint(resolved, constraint) != expected:
            errors.append(
                f"bounded NuGet constraint fixture failed for {resolved} "
                f"against {constraint}"
            )
    if nuget_constraint_is_valid("[1.0.0-alpha..1, )"):
        errors.append("bounded NuGet grammar accepted an invalid constraint")

    catalog = load_yaml("docs/governance/record-families.yaml")
    controls = load_yaml("docs/governance/controls.yaml")["controls"]
    mismatched_catalog = copy.deepcopy(catalog)
    next(
        family
        for family in mismatched_catalog["families"]
        if family["id"] == "public-build-experiment-bundles"
    )["state"] = "current"
    if not check_public_build_activation_coupling(mismatched_catalog, controls):
        errors.append(
            "public-build activation fixture did not reject a family/control mismatch"
        )
    current_catalog = copy.deepcopy(catalog)
    next(
        family
        for family in current_catalog["families"]
        if family["id"] == "public-build-experiment-bundles"
    )["state"] = "current"
    current_controls = copy.deepcopy(controls)
    current_control = next(
        control
        for control in current_controls
        if control["id"] == "public-build-evidence-consistency"
    )
    current_control["state"] = "current"
    current_control["implementation"]["steps"] = {
        "local-fast": [
            "structured-record-schema",
            "public-build-runner-conformance",
        ],
        "ci": [
            "structured-record-schema",
            "public-build-runner-conformance",
        ],
    }
    activation_errors = check_public_build_activation_coupling(
        current_catalog,
        current_controls,
    )
    if not any("planned-only contract" in error for error in activation_errors):
        errors.append(
            "public-build activation fixture accepted the planned-only schema"
        )
    unrelated_runtime_schema = copy.deepcopy(schema)
    unrelated_runtime_schema["x-public-build-contract"] = {
        "mode": "runtime",
        "version": 1,
        "runtime_property": "runtime_evidence",
        "runtime_root": "#/$defs/sha256",
        "runtime_semantics": {
            name: "#/$defs/sha256"
            for name in PUBLIC_BUILD_RUNTIME_SCHEMA_ANCHORS
        },
    }
    unrelated_runtime_schema["required"].append("runtime_evidence")
    unrelated_runtime_schema["properties"]["runtime_evidence"] = {
        "$ref": "#/$defs/sha256"
    }
    unrelated_activation_errors = check_public_build_activation_coupling(
        current_catalog,
        current_controls,
        schema=unrelated_runtime_schema,
        runner_path=ROOT / "tools/check_repository_records.py",
    )
    if not any(
        "distinct marked property" in error
        for error in unrelated_activation_errors
    ):
        errors.append(
            "public-build activation fixture accepted unrelated semantic aliases"
        )
    marker_only_runtime_schema = copy.deepcopy(schema)
    runtime_properties = {
        name: {
            "type": "object",
            "x-public-build-runtime-semantic": name,
        }
        for name in PUBLIC_BUILD_RUNTIME_SCHEMA_ANCHORS
    }
    marker_only_runtime_schema["$defs"]["runtimeEvidence"] = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(runtime_properties),
        "properties": runtime_properties,
    }
    marker_only_runtime_schema["required"].append("runtime_evidence")
    marker_only_runtime_schema["properties"]["runtime_evidence"] = {
        "$ref": "#/$defs/runtimeEvidence"
    }
    marker_only_runtime_schema["x-public-build-contract"] = {
        "mode": "runtime",
        "version": 1,
        "runtime_property": "runtime_evidence",
        "runtime_root": "#/$defs/runtimeEvidence",
        "runtime_semantics": {
            name: f"#/$defs/runtimeEvidence/properties/{name}"
            for name in PUBLIC_BUILD_RUNTIME_SCHEMA_ANCHORS
        },
    }
    marker_only_errors = check_public_build_activation_coupling(
        current_catalog,
        current_controls,
        schema=marker_only_runtime_schema,
        runner_path=ROOT / "tools/check_repository_records.py",
    )
    if not any("unconstrained=" in error for error in marker_only_errors):
        errors.append(
            "public-build activation fixture accepted marker-only runtime semantics"
        )
    constrained_runtime_schema = copy.deepcopy(marker_only_runtime_schema)
    for property_schema in constrained_runtime_schema["$defs"][
        "runtimeEvidence"
    ]["properties"].values():
        property_schema["additionalProperties"] = False
        property_schema["required"] = ["recorded"]
        property_schema["properties"] = {
            "recorded": {
                "const": True,
            }
        }
    constrained_errors = check_public_build_activation_coupling(
        current_catalog,
        current_controls,
        schema=constrained_runtime_schema,
        runner_path=ROOT / "tools/check_repository_records.py",
    )
    if constrained_errors:
        errors.append(
            "public-build activation positive fixture rejected constrained runtime "
            f"semantic anchors: {constrained_errors[0]}"
        )
    alternate_runner = copy.deepcopy(planned)
    alternate_runner_path = "tools/check_repository_records.py"
    alternate_runner["environment"]["runner"] = {
        "path": alternate_runner_path,
        "sha256": hashlib.sha256(
            (ROOT / alternate_runner_path).read_bytes()
        ).hexdigest(),
    }
    alternate_runner_errors = validate_public_build_bundle_value(
        alternate_runner,
        "fixture:alternate-runner",
        baseline,
        lasso_manifest,
        require_runtime_runner=True,
    )
    if not any("canonical repository runner" in error for error in alternate_runner_errors):
        errors.append(
            "public-build runtime fixture accepted a noncanonical runner path"
        )
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
                (instance.relative_to(ROOT).as_posix(), load_yaml_path(instance))
                for instance in instances
            ]
            for label, bundle in bundle_records:
                errors.extend(
                    validate_public_build_bundle_value(
                        bundle,
                        label,
                        require_runtime_runner=family["state"] == "current",
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
