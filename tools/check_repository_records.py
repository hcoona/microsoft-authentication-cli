# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["PyYAML==6.0.3", "markdown-it-py==4.2.0"]
# ///

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml
from markdown_it import MarkdownIt
from markdown_it.token import Token


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
MARKDOWN = MarkdownIt("commonmark", {"html": True})
REQUIREMENT_ID_PATTERN = re.compile(r"^V2-REQ-[0-9]{3}[A-Z]?$")
REQUIREMENT_PREFIX_PATTERN = re.compile(r"^V2-REQ-")
RETIRED_REQUIREMENT_PREFIX = "Retired - current authority: "
DECISION_PATTERN = re.compile(r"^([0-9]{4})-.*\.md$")
GLOB_MARKERS = frozenset("*?[")
ZERO_SHA = "0" * 40
EXACT_VERSION_PATTERN = re.compile(
    r"^[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
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
SOURCE_FAITHFUL_CONFIG_SHA256 = (
    "be2776f78f5af30efb8836a32c4467ca0dcd9220c17d778ed8332b33dd309a6b"
)
PUBLIC_CONFIG_SHA256 = (
    "f545a7e2ea14ac53cdfb91217cae67b8ff14275313f6298f9a3331d205b6c948"
)
SOURCE_MANIFEST_SHA256 = (
    "932e144f784d573e0113b129394a0c214d9b0a197f8498b056d2aeb35ebcc40f"
)
LASSO_REFERENCE_MANIFEST_SHA256 = (
    "361bcf3af38cba4e74416aef212a141bf9a926bda844402f20a1ab805e204db8"
)
SOURCE_FAITHFUL_PACKAGE_SOURCE = (
    "https://pkgs.dev.azure.com/office/_packaging/Office/nuget/v3/index.json"
)
PUBLIC_PACKAGE_SOURCE = "https://api.nuget.org/v3/index.json"


def load_yaml_path(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT).as_posix()} must contain a YAML object")
    return value


def load_yaml(relative_path: str) -> dict[str, Any]:
    return load_yaml_path(ROOT / relative_path)


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
            item["id"] for item in load_yaml("docs/governance/record-families.yaml")["families"]
        ],
        "control": [
            item["id"] for item in load_yaml("docs/governance/controls.yaml")["controls"]
        ],
        "operational identity": [
            item["id"]
            for item in load_yaml("docs/governance/operational-identities.yaml")["selected_v2"]
        ],
        "recheck": [item["id"] for item in load_yaml("docs/research/rechecks.yaml")["rechecks"]],
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


def check_control_references(catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    controls = load_yaml("docs/governance/controls.yaml")["controls"]
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


DOTNET_STAGE_ARGUMENT = {
    "restore": "restore",
    "build": "build",
    "test": "test",
    "package": "pack",
}


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def normalized_absolute_path(
    value: str,
) -> tuple[str, PurePosixPath | PureWindowsPath] | None:
    if "\\" in value:
        return None
    if re.match(r"^[A-Za-z]:/", value):
        path: PurePosixPath | PureWindowsPath = PureWindowsPath(value)
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
    child_parts = child_path.parts
    parent_parts = parent_path.parts
    if child_kind == "windows":
        child_parts = tuple(part.casefold() for part in child_parts)
        parent_parts = tuple(part.casefold() for part in parent_parts)
    if len(child_parts) < len(parent_parts):
        return False
    if not allow_equal and len(child_parts) == len(parent_parts):
        return False
    return child_parts[: len(parent_parts)] == parent_parts


def decoded_content_sha256(content_base64: str) -> str | None:
    try:
        content = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError):
        return None
    return hashlib.sha256(content).hexdigest()


def parse_nuget_version(
    value: str,
) -> tuple[tuple[int, int, int, int], tuple[str, ...] | None] | None:
    if EXACT_VERSION_PATTERN.fullmatch(value) is None:
        return None
    without_metadata = value.split("+", maxsplit=1)[0]
    core_text, separator, prerelease_text = without_metadata.partition("-")
    core = tuple(int(part) for part in core_text.split("."))
    padded_core = (*core, *(0 for _ in range(4 - len(core))))
    prerelease = (
        tuple(part.casefold() for part in re.split(r"[.-]", prerelease_text))
        if separator
        else None
    )
    return padded_core, prerelease


def compare_prerelease(
    left: tuple[str, ...] | None,
    right: tuple[str, ...] | None,
) -> int:
    if left is None:
        return 0 if right is None else 1
    if right is None:
        return -1
    for left_part, right_part in zip(left, right):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            return 1 if int(left_part) > int(right_part) else -1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return 1 if left_part > right_part else -1
    if len(left) == len(right):
        return 0
    return 1 if len(left) > len(right) else -1


def nuget_version_at_least(resolved: str, minimum: str) -> bool:
    resolved_version = parse_nuget_version(resolved)
    minimum_version = parse_nuget_version(minimum)
    if resolved_version is None or minimum_version is None:
        return False
    resolved_core, resolved_prerelease = resolved_version
    minimum_core, minimum_prerelease = minimum_version
    if resolved_core != minimum_core:
        return resolved_core > minimum_core
    return compare_prerelease(resolved_prerelease, minimum_prerelease) >= 0


def source_manifest_payload(
    targets: list[dict[str, Any]],
    declarations: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "attempted_targets": sorted(
            (
                {
                    "id": target["id"],
                    "project_path": target["project_path"],
                    "target_framework": target["target_framework"],
                    "sdk": target["sdk"],
                    "project_references": sorted(target["project_references"]),
                }
                for target in targets
            ),
            key=lambda target: target["id"],
        ),
        "package_declarations": sorted(
            (
                {
                    "id": declaration["id"],
                    "kind": declaration["kind"],
                    "version_constraint": declaration["version_constraint"],
                    "declaration_location": declaration["declaration_location"],
                    "targets": sorted(declaration["targets"]),
                    "condition": declaration["condition"],
                }
                for declaration in declarations
            ),
            key=lambda declaration: declaration["declaration_location"],
        ),
    }


def dependency_graph_payload(graph: dict[str, Any]) -> dict[str, Any]:
    return {
        "result_id": graph["result_id"],
        "target_id": graph["target_id"],
        "state": graph["state"],
        "nodes": sorted(graph["nodes"], key=lambda node: node["node_id"]),
        "edges": sorted(
            (
                {
                    **edge,
                    "declaration_ids": sorted(edge["declaration_ids"]),
                }
                for edge in graph["edges"]
            ),
            key=lambda edge: edge["edge_id"],
        ),
        "unresolved_edges": sorted(
            (
                {
                    **edge,
                    "declaration_ids": sorted(edge["declaration_ids"]),
                }
                for edge in graph["unresolved_edges"]
            ),
            key=lambda edge: edge["edge_id"],
        ),
    }


def validate_dotnet_invocation(
    command: dict[str, Any],
    environment: dict[str, Any],
    restore_configurations: dict[str, dict[str, Any]],
    relative_path: str,
) -> list[str]:
    errors: list[str] = []
    invocation = command["command"]
    if invocation["executable"] != "dotnet":
        errors.append(
            f"{relative_path}: protocol command {command['id']} must invoke dotnet "
            "directly without a shell wrapper"
        )

    arguments = invocation["arguments"]
    expected_stage_argument = DOTNET_STAGE_ARGUMENT[command["stage"]]
    if arguments[0].lower() != expected_stage_argument:
        errors.append(
            f"{relative_path}: protocol command {command['id']} must invoke "
            f"'dotnet {expected_stage_argument}'"
        )

    restore_configuration = restore_configurations.get(
        command["restore_configuration_id"]
    )
    if restore_configuration is None:
        errors.append(
            f"{relative_path}: protocol command {command['id']} references unknown "
            f"restore configuration {command['restore_configuration_id']}"
        )
    elif restore_configuration["source_mode"] != command["source_mode"]:
        errors.append(
            f"{relative_path}: protocol command {command['id']} references a restore "
            "configuration for a different source mode"
        )

    if command["stage"] == "restore" and restore_configuration is not None:
        expected_arguments = [
            expected_stage_argument,
            environment["build_entry_point"],
            "--configfile",
            restore_configuration["path"],
        ]
    else:
        expected_arguments = [
            expected_stage_argument,
            environment["build_entry_point"],
            "--configuration",
            environment["configuration"],
            "--no-restore",
        ]
    if arguments != expected_arguments:
        errors.append(
            f"{relative_path}: protocol command {command['id']} must use the canonical "
            f"argument list {expected_arguments}"
        )
    return errors


def validate_public_build_bundle_value(
    bundle: dict[str, Any], relative_path: str
) -> list[str]:
    errors: list[str] = []
    stages = ("restore", "build", "test", "package")
    source_modes = ("source-faithful", "public-only")
    expected_slots = {
        (source_mode, stage) for source_mode in source_modes for stage in stages
    }

    environment = bundle["environment"]
    checkout_path = normalized_absolute_path(environment["checkout_root"])
    if checkout_path is None:
        errors.append(
            f"{relative_path}: checkout_root must be a normalized absolute path"
        )

    isolation = bundle["isolation_profile"]
    isolation_paths: dict[str, tuple[str, PurePosixPath | PureWindowsPath]] = {}
    for field in (
        "home_root",
        "global_packages_root",
        "http_cache_root",
        "plugin_cache_root",
        "scratch_root",
    ):
        path = normalized_absolute_path(isolation[field])
        if path is None:
            errors.append(
                f"{relative_path}: isolation {field} must be a normalized absolute path"
            )
            continue
        isolation_paths[field] = path
        if checkout_path is not None and (
            recorded_path_is_within(path, checkout_path, allow_equal=True)
            or recorded_path_is_within(checkout_path, path, allow_equal=True)
        ):
            errors.append(
                f"{relative_path}: isolation {field} must not overlap the detached "
                "checkout root"
            )
    normalized_isolation_roots = [
        (kind, tuple(part.casefold() if kind == "windows" else part for part in path.parts))
        for kind, path in isolation_paths.values()
    ]
    if len(normalized_isolation_roots) != len(set(normalized_isolation_roots)):
        errors.append(f"{relative_path}: isolation roots must have distinct identities")

    protocol = bundle["protocol"]
    attempted_targets = protocol["attempted_targets"]
    target_ids = [target["id"] for target in attempted_targets]
    for identifier in duplicates(target_ids):
        errors.append(f"{relative_path}: duplicate attempted target id: {identifier}")
    targets_by_id = {target["id"]: target for target in attempted_targets}

    restore_configuration_records = protocol["restore_configurations"]
    restore_configuration_ids = [
        configuration["id"] for configuration in restore_configuration_records
    ]
    for identifier in duplicates(restore_configuration_ids):
        errors.append(
            f"{relative_path}: duplicate restore configuration id: {identifier}"
        )
    restore_configurations = {
        configuration["id"]: configuration
        for configuration in restore_configuration_records
    }
    restore_configurations_by_mode: dict[str, dict[str, Any]] = {}
    for configuration in restore_configuration_records:
        source_mode = configuration["source_mode"]
        if source_mode in restore_configurations_by_mode:
            errors.append(
                f"{relative_path}: duplicate restore configuration for {source_mode}"
            )
        else:
            restore_configurations_by_mode[source_mode] = configuration

        expected_origin = (
            "audited-upstream"
            if source_mode == "source-faithful"
            else "isolated-public"
        )
        if configuration["origin"] != expected_origin:
            errors.append(
                f"{relative_path}: {source_mode} restore configuration must use "
                f"origin {expected_origin}"
            )
        canonical_configuration_path = normalized_absolute_path(
            configuration["canonical_path"]
        )
        if canonical_configuration_path is None:
            errors.append(
                f"{relative_path}: {source_mode} canonical configuration path must be "
                "a normalized absolute path"
            )
        if source_mode == "source-faithful":
            if configuration["path"] != "nuget.config":
                errors.append(
                    f"{relative_path}: source-faithful restore configuration must be "
                    "the audited checkout's nuget.config"
                )
            if (
                configuration["sha256"] != SOURCE_FAITHFUL_CONFIG_SHA256
            ):
                errors.append(
                    f"{relative_path}: source-faithful restore configuration must use "
                    "the audited nuget.config SHA-256"
                )
            if configuration["content_base64"] is not None:
                errors.append(
                    f"{relative_path}: source-faithful configuration content is bound "
                    "by the audited source hash and must not be copied into the bundle"
                )
            if configuration["sources"] != [SOURCE_FAITHFUL_PACKAGE_SOURCE]:
                errors.append(
                    f"{relative_path}: source-faithful restore configuration must "
                    "record the audited Office package source"
                )
            if checkout_path is not None:
                expected_canonical_path = (
                    checkout_path[0],
                    checkout_path[1].joinpath("nuget.config"),
                )
                if canonical_configuration_path != expected_canonical_path:
                    errors.append(
                        f"{relative_path}: source-faithful canonical configuration path "
                        "must identify nuget.config under the detached checkout root"
                    )
        else:
            public_path = normalized_absolute_path(configuration["path"])
            scratch_path = isolation_paths.get("scratch_root")
            if public_path is None:
                errors.append(
                    f"{relative_path}: public-only restore configuration path must be "
                    "a normalized absolute path"
                )
            else:
                if public_path != canonical_configuration_path:
                    errors.append(
                        f"{relative_path}: public-only configuration path must equal its "
                        "verified canonical path"
                    )
                if scratch_path is None or not recorded_path_is_within(
                    public_path, scratch_path
                ):
                    errors.append(
                        f"{relative_path}: public-only restore configuration must be "
                        "inside the isolated scratch root"
                    )
                if checkout_path is not None and recorded_path_is_within(
                    public_path, checkout_path, allow_equal=True
                ):
                    errors.append(
                        f"{relative_path}: public-only restore configuration must be "
                        "outside the audited checkout"
                    )
            if configuration["sha256"] != PUBLIC_CONFIG_SHA256:
                errors.append(
                    f"{relative_path}: public-only restore configuration must use the "
                    "canonical Issue #1 content hash"
                )
            content_base64 = configuration["content_base64"]
            if (
                not isinstance(content_base64, str)
                or decoded_content_sha256(content_base64) != PUBLIC_CONFIG_SHA256
            ):
                errors.append(
                    f"{relative_path}: public-only restore configuration content must "
                    "decode to the canonical Issue #1 configuration"
                )
            if configuration["sources"] != [PUBLIC_PACKAGE_SOURCE]:
                errors.append(
                    f"{relative_path}: public-only restore configuration must contain "
                    "only the canonical NuGet.org v3 source"
                )

    if set(restore_configurations_by_mode) != set(source_modes):
        errors.append(
            f"{relative_path}: protocol must define exactly one restore configuration "
            "for each source mode"
        )

    commands = protocol["commands"]
    command_ids = [command["id"] for command in commands]
    for identifier in duplicates(command_ids):
        errors.append(f"{relative_path}: duplicate protocol command id: {identifier}")
    commands_by_id = {command["id"]: command for command in commands}
    commands_by_slot: dict[tuple[str, str], dict[str, Any]] = {}
    for command in commands:
        slot = (command["source_mode"], command["stage"])
        if slot in commands_by_slot:
            errors.append(
                f"{relative_path}: duplicate protocol slot: {slot[0]} {slot[1]}"
            )
        else:
            commands_by_slot[slot] = command

    missing_slots = sorted(expected_slots - set(commands_by_slot))
    extra_command_count = len(commands) - len(commands_by_slot)
    if missing_slots or extra_command_count:
        errors.append(
            f"{relative_path}: protocol must define exactly one command for every "
            "source-mode and stage combination"
        )

    for command in commands:
        errors.extend(
            validate_dotnet_invocation(
                command,
                bundle["environment"],
                restore_configurations,
                relative_path,
            )
        )
        restore = commands_by_slot.get((command["source_mode"], "restore"))
        expected_dependencies = [] if command["stage"] == "restore" else (
            [restore["id"]] if restore is not None else []
        )
        if command["depends_on"] != expected_dependencies:
            errors.append(
                f"{relative_path}: protocol command {command['id']} must declare exactly "
                f"the dependencies {expected_dependencies}"
            )

    results = bundle["command_results"]
    result_ids = [result["command_id"] for result in results]
    for identifier in duplicates(result_ids):
        errors.append(f"{relative_path}: duplicate command result id: {identifier}")
    result_id_set = set(result_ids)
    results_by_id = {result["command_id"]: result for result in results}
    results_by_slot: dict[tuple[str, str], dict[str, Any]] = {}
    for result in results:
        slot = (result["source_mode"], result["stage"])
        if slot in results_by_slot:
            errors.append(f"{relative_path}: duplicate result slot: {slot[0]} {slot[1]}")
        else:
            results_by_slot[slot] = result

    source_commit = bundle["source"]["commit"]
    environment_fingerprint = environment["fingerprint"]
    contaminated_execution = False
    for result in results:
        command_id = result["command_id"]
        command = commands_by_id.get(command_id)
        if command is None:
            errors.append(
                f"{relative_path}: result {command_id} has no matching protocol command"
            )
        else:
            for field in ("stage", "source_mode", "command"):
                if result[field] != command[field]:
                    errors.append(
                        f"{relative_path}: result {command_id} {field} does not match "
                        "the reviewed protocol"
                    )

        if result["source_commit"] != source_commit:
            errors.append(
                f"{relative_path}: result {command_id} uses a different source commit"
            )
        if result["environment_fingerprint"] != environment_fingerprint:
            errors.append(
                f"{relative_path}: result {command_id} uses a different environment fingerprint"
            )
        if result["isolation_profile_id"] != isolation["id"]:
            errors.append(
                f"{relative_path}: result {command_id} uses a different isolation profile"
            )

        status = result["status"]
        if result["stage"] != "restore":
            applicable = protocol["stage_applicability"][result["stage"]][
                "applicable"
            ]
            if applicable and status == "not-applicable":
                errors.append(
                    f"{relative_path}: applicable {result['stage']} stage cannot be "
                    "recorded as not-applicable"
                )
            elif not applicable and status != "not-applicable":
                errors.append(
                    f"{relative_path}: inapplicable {result['stage']} stage must be "
                    "recorded as not-applicable in both source modes"
                )

        if status in {"blocked", "not-applicable"}:
            if result["exit_code"] is not None or result["reproduction_count"] != 0:
                errors.append(
                    f"{relative_path}: unexecuted result {command_id} must use a null "
                    "exit code and zero reproductions"
                )
        elif result["reproduction_count"] < 1:
            errors.append(
                f"{relative_path}: executed result {command_id} must record at least "
                "one reproduction"
            )

        blocking_ids = result.get("blocked_by", [])
        if status != "blocked" and blocking_ids:
            errors.append(
                f"{relative_path}: non-blocked result {command_id} must not declare "
                "blocked_by"
            )

        if result["stage"] == "restore":
            if status in {"blocked", "not-applicable"}:
                errors.append(
                    f"{relative_path}: {result['source_mode']} restore must be executed"
                )
            integrity = result["execution_integrity"]
            if integrity["verification"] == "violated":
                contaminated_execution = True
            continue

        restore = results_by_slot.get((result["source_mode"], "restore"))
        if restore is None:
            errors.append(
                f"{relative_path}: {result['source_mode']} {result['stage']} result "
                "requires the corresponding restore result"
            )
            continue

        restore_id = restore["command_id"]
        if status == "blocked":
            if blocking_ids != [restore_id]:
                errors.append(
                    f"{relative_path}: blocked result {command_id} must name exactly "
                    f"the corresponding restore result {restore_id}"
                )
            if restore["status"] == "passed":
                errors.append(
                    f"{relative_path}: result {command_id} cannot be blocked by a "
                    "passing restore"
                )
        elif status in {"passed", "failed"} and restore["status"] != "passed":
            errors.append(
                f"{relative_path}: executed {result['source_mode']} "
                f"{result['stage']} requires a passed restore result"
            )

    inventory = bundle["dependency_inventory"]
    declarations = inventory["source_declared_direct"]
    declaration_ids = [dependency["declaration_id"] for dependency in declarations]
    for identifier in duplicates(declaration_ids):
        errors.append(f"{relative_path}: duplicate dependency declaration id: {identifier}")
    declaration_locations = [
        dependency["declaration_location"] for dependency in declarations
    ]
    for location in duplicates(declaration_locations):
        errors.append(
            f"{relative_path}: duplicate dependency declaration location: {location}"
        )
    declarations_by_id = {
        dependency["declaration_id"]: dependency for dependency in declarations
    }
    for declaration in declarations:
        expected_applicable = (
            declaration["condition"] != "not-windows"
            or environment["operating_system_family"] != "windows"
        )
        if declaration["applicable"] != expected_applicable:
            errors.append(
                f"{relative_path}: dependency declaration "
                f"{declaration['declaration_id']} applicability conflicts with the "
                "recorded operating-system family"
            )
        unknown_targets = sorted(set(declaration["targets"]) - set(targets_by_id))
        if unknown_targets:
            errors.append(
                f"{relative_path}: dependency declaration "
                f"{declaration['declaration_id']} references unknown targets "
                f"{unknown_targets}"
            )

    actual_source_manifest_sha256 = canonical_sha256(
        source_manifest_payload(attempted_targets, declarations)
    )
    if (
        inventory["source_manifest_sha256"] != SOURCE_MANIFEST_SHA256
        or actual_source_manifest_sha256 != SOURCE_MANIFEST_SHA256
    ):
        errors.append(
            f"{relative_path}: attempted targets and direct dependency declarations "
            "do not match the audited source manifest"
        )

    direct_coverage: dict[tuple[str, str], str] = {}
    graphs = inventory["restore_graphs"]
    graph_ids = [graph["id"] for graph in graphs]
    for identifier in duplicates(graph_ids):
        errors.append(f"{relative_path}: duplicate dependency graph id: {identifier}")
    graphs_by_slot: dict[tuple[str, str], dict[str, Any]] = {}
    public_graphs: list[dict[str, Any]] = []

    def record_direct_coverage(
        result_id: str,
        target_id: str,
        dependency_id: str,
        version_constraint: str,
        declaration_id: str,
        coverage: str,
        resolved_version: str | None = None,
    ) -> None:
        declaration = declarations_by_id.get(declaration_id)
        if declaration is None:
            errors.append(
                f"{relative_path}: dependency edge references unknown declaration "
                f"{declaration_id}"
            )
            return
        if not declaration["applicable"]:
            errors.append(
                f"{relative_path}: dependency edge references inapplicable declaration "
                f"{declaration_id}"
            )
        if declaration["targets"] != [target_id]:
            errors.append(
                f"{relative_path}: dependency edge declaration {declaration_id} does "
                f"not belong to target {target_id}"
            )
        if dependency_id.casefold() != declaration["id"].casefold():
            errors.append(
                f"{relative_path}: dependency edge identifier {dependency_id} does not "
                f"match declaration {declaration_id}"
            )
        if version_constraint != declaration["version_constraint"]:
            errors.append(
                f"{relative_path}: dependency edge does not preserve declaration "
                f"{declaration_id} version constraint"
            )
        if (
            resolved_version is not None
            and not nuget_version_at_least(
                resolved_version, declaration["version_constraint"]
            )
        ):
            errors.append(
                f"{relative_path}: resolved version {resolved_version} does not satisfy "
                f"declaration {declaration_id} minimum "
                f"{declaration['version_constraint']}"
            )
        key = (result_id, declaration_id)
        if key in direct_coverage:
            errors.append(
                f"{relative_path}: declaration {declaration_id} has multiple root "
                f"dependency edges for result {result_id}"
            )
        else:
            direct_coverage[key] = coverage

    for graph in graphs:
        result_id = graph["result_id"]
        target_id = graph["target_id"]
        slot = (result_id, target_id)
        if slot in graphs_by_slot:
            errors.append(
                f"{relative_path}: duplicate dependency graph for result {result_id} "
                f"and target {target_id}"
            )
        else:
            graphs_by_slot[slot] = graph

        result = results_by_id.get(result_id)
        if result is None:
            errors.append(
                f"{relative_path}: dependency graph {graph['id']} references unknown "
                f"result {result_id}"
            )
        elif result["stage"] != "restore":
            errors.append(
                f"{relative_path}: dependency graph {graph['id']} must reference a "
                "restore result"
            )
        elif result["status"] not in {"passed", "failed"}:
            errors.append(
                f"{relative_path}: dependency graph {graph['id']} references an "
                "unexecuted restore result"
            )
        elif result["source_mode"] == "public-only":
            public_graphs.append(graph)

        if target_id not in targets_by_id:
            errors.append(
                f"{relative_path}: dependency graph {graph['id']} references unknown "
                f"target {target_id}"
            )
        if (
            canonical_sha256(dependency_graph_payload(graph))
            != graph["normalized_graph_sha256"]
        ):
            errors.append(
                f"{relative_path}: dependency graph {graph['id']} normalized hash does "
                "not match its nodes and edges"
            )

        node_ids = [node["node_id"] for node in graph["nodes"]]
        for identifier in duplicates(node_ids):
            errors.append(
                f"{relative_path}: dependency graph {graph['id']} has duplicate node "
                f"{identifier}"
            )
        nodes_by_id = {node["node_id"]: node for node in graph["nodes"]}
        edge_ids = [
            edge["edge_id"]
            for edge in [*graph["edges"], *graph["unresolved_edges"]]
        ]
        for identifier in duplicates(edge_ids):
            errors.append(
                f"{relative_path}: dependency graph {graph['id']} has duplicate edge "
                f"{identifier}"
            )

        restore_configuration: dict[str, Any] | None = None
        if result is not None:
            command = commands_by_id.get(result_id)
            if command is not None:
                restore_configuration = restore_configurations.get(
                    command["restore_configuration_id"]
                )
        for node in graph["nodes"]:
            if (
                restore_configuration is not None
                and node["retrieval_source"] not in restore_configuration["sources"]
            ):
                errors.append(
                    f"{relative_path}: dependency graph {graph['id']} node "
                    f"{node['node_id']} uses a source outside the restore configuration"
                )
            if node["access"] != "anonymous" or node["initial_cache_state"] != "empty":
                contaminated_execution = True

        root_nodes: set[str] = set()
        adjacency: dict[str, set[str]] = {}
        for edge in graph["edges"]:
            from_node_id = edge["from_node_id"]
            to_node_id = edge["to_node_id"]
            node = nodes_by_id.get(to_node_id)
            if node is None:
                errors.append(
                    f"{relative_path}: dependency graph {graph['id']} edge "
                    f"{edge['edge_id']} references unknown target node {to_node_id}"
                )
            if from_node_id is None:
                root_nodes.add(to_node_id)
                if not edge["declaration_ids"]:
                    errors.append(
                        f"{relative_path}: root dependency edge {edge['edge_id']} must "
                        "reference a source declaration"
                    )
                for declaration_id in edge["declaration_ids"]:
                    record_direct_coverage(
                        result_id,
                        target_id,
                        node["id"] if node is not None else "",
                        edge["version_constraint"],
                        declaration_id,
                        "resolved",
                        node["version"] if node is not None else None,
                    )
            else:
                if from_node_id not in nodes_by_id:
                    errors.append(
                        f"{relative_path}: dependency graph {graph['id']} edge "
                        f"{edge['edge_id']} references unknown source node "
                        f"{from_node_id}"
                    )
                adjacency.setdefault(from_node_id, set()).add(to_node_id)
                if edge["declaration_ids"]:
                    errors.append(
                        f"{relative_path}: transitive dependency edge "
                        f"{edge['edge_id']} must not reference source declarations"
                    )

        unresolved_from_nodes: list[str] = []
        for edge in graph["unresolved_edges"]:
            from_node_id = edge["from_node_id"]
            if from_node_id is None:
                if not edge["declaration_ids"]:
                    errors.append(
                        f"{relative_path}: unresolved root edge {edge['edge_id']} must "
                        "reference a source declaration"
                    )
                for declaration_id in edge["declaration_ids"]:
                    record_direct_coverage(
                        result_id,
                        target_id,
                        edge["id"],
                        edge["version_constraint"],
                        declaration_id,
                        "unresolved",
                    )
            else:
                unresolved_from_nodes.append(from_node_id)
                if from_node_id not in nodes_by_id:
                    errors.append(
                        f"{relative_path}: dependency graph {graph['id']} unresolved "
                        f"edge {edge['edge_id']} references unknown source node "
                        f"{from_node_id}"
                    )
                if edge["declaration_ids"]:
                    errors.append(
                        f"{relative_path}: unresolved transitive edge "
                        f"{edge['edge_id']} must not reference source declarations"
                    )

        reachable = set(root_nodes)
        pending = list(root_nodes)
        while pending:
            source_node = pending.pop()
            for target_node in adjacency.get(source_node, set()):
                if target_node not in reachable:
                    reachable.add(target_node)
                    pending.append(target_node)
        unreachable_nodes = sorted(set(nodes_by_id) - reachable)
        if unreachable_nodes:
            errors.append(
                f"{relative_path}: dependency graph {graph['id']} contains unreachable "
                f"nodes {unreachable_nodes}"
            )
        unreachable_unresolved = sorted(
            node_id for node_id in unresolved_from_nodes if node_id not in reachable
        )
        if unreachable_unresolved:
            errors.append(
                f"{relative_path}: dependency graph {graph['id']} contains unresolved "
                f"edges from unreachable nodes {unreachable_unresolved}"
            )
        if result is not None and result["status"] == "passed":
            if graph["state"] != "complete" or graph["unresolved_edges"]:
                errors.append(
                    f"{relative_path}: passing restore result {result_id} requires a "
                    f"complete graph without unresolved edges for target {target_id}"
                )

    lasso_analysis = bundle.get("lasso_analysis")
    if lasso_analysis is not None:
        lasso_declaration = declarations_by_id.get(
            lasso_analysis["dependency_declaration_id"]
        )
        if (
            lasso_declaration is None
            or lasso_declaration["id"].casefold() != "microsoft.office.lasso"
        ):
            errors.append(
                f"{relative_path}: Lasso analysis must reference the audited "
                "Microsoft.Office.Lasso declaration"
            )
        mapping_ids = [
            mapping["id"] for mapping in lasso_analysis["responsibility_mappings"]
        ]
        for identifier in duplicates(mapping_ids):
            errors.append(
                f"{relative_path}: duplicate Lasso responsibility mapping id: "
                f"{identifier}"
            )
        source_references = [
            reference
            for mapping in lasso_analysis["responsibility_mappings"]
            for reference in mapping["source_references"]
        ]
        for reference in duplicates(source_references):
            errors.append(
                f"{relative_path}: Lasso source reference is mapped more than once: "
                f"{reference}"
            )
        if (
            lasso_analysis["source_reference_manifest_sha256"]
            != LASSO_REFERENCE_MANIFEST_SHA256
            or canonical_sha256(sorted(source_references))
            != LASSO_REFERENCE_MANIFEST_SHA256
        ):
            errors.append(
                f"{relative_path}: Lasso responsibility mappings do not cover the "
                "audited public source-reference manifest"
            )

    if contaminated_execution and bundle["status"] != "aborted":
        errors.append(
            f"{relative_path}: credential, provider, inherited-configuration, or "
            "populated-cache contamination requires an aborted bundle"
        )
    if bundle["status"] == "planned" and any(
        conclusion["kind"] == "runtime-observation"
        for conclusion in bundle["conclusions"]
    ):
        errors.append(
            f"{relative_path}: planned bundle cannot contain runtime observations"
        )
    if bundle["status"] != "completed":
        return errors

    if set(command_ids) != result_id_set or len(command_ids) != len(result_ids):
        errors.append(
            f"{relative_path}: completed bundle must have exactly one result for every "
            "reviewed protocol command"
        )

    restore_results = [
        result
        for (source_mode, stage), result in results_by_slot.items()
        if stage == "restore" and source_mode in source_modes
    ]
    expected_graph_slots = {
        (result["command_id"], target_id)
        for result in restore_results
        for target_id in target_ids
    }
    if set(graphs_by_slot) != expected_graph_slots:
        errors.append(
            f"{relative_path}: completed bundle must record one dependency graph for "
            "every restore result and attempted target"
        )

    for result in restore_results:
        for declaration_id, declaration in declarations_by_id.items():
            if not declaration["applicable"]:
                continue
            if (result["command_id"], declaration_id) not in direct_coverage:
                errors.append(
                    f"{relative_path}: declaration {declaration_id} lacks a resolved or "
                    f"unresolved root edge for restore result {result['command_id']}"
                )

    if lasso_analysis is None:
        errors.append(
            f"{relative_path}: completed bundle must include the bounded "
            "Microsoft.Office.Lasso analysis"
        )

    public_results = [
        result
        for (source_mode, _stage), result in results_by_slot.items()
        if source_mode == "public-only"
    ]
    completion = bundle["completion"]
    if completion["outcome"] == "publicly-reproducible":
        if len(public_results) != len(stages) or any(
            result["status"] not in {"passed", "not-applicable"}
            for result in public_results
        ):
            errors.append(
                f"{relative_path}: publicly-reproducible outcome conflicts with "
                "public-only command results"
            )
        if len(public_graphs) != len(target_ids) or any(
            graph["state"] != "complete" or graph["unresolved_edges"]
            for graph in public_graphs
        ):
            errors.append(
                f"{relative_path}: publicly-reproducible outcome requires a complete "
                "public-only graph without unresolved edges for every attempted target"
            )
        public_restore = results_by_slot.get(("public-only", "restore"))
        if public_restore is not None:
            for declaration_id, declaration in declarations_by_id.items():
                if not declaration["applicable"]:
                    continue
                if (
                    direct_coverage.get(
                        (public_restore["command_id"], declaration_id)
                    )
                    != "resolved"
                ):
                    errors.append(
                        f"{relative_path}: publicly-reproducible outcome lacks a "
                        f"resolved public root edge for declaration {declaration_id}"
                    )
        if any(
            node["access"] != "anonymous"
            or node["initial_cache_state"] != "empty"
            or node["retrieval_source"] != PUBLIC_PACKAGE_SOURCE
            for graph in public_graphs
            for node in graph["nodes"]
        ):
            errors.append(
                f"{relative_path}: publicly-reproducible outcome requires anonymous "
                "empty-cache NuGet.org provenance for every public graph node"
            )
    elif completion["outcome"] == "not-publicly-reproducible":
        has_failed_public_stage = any(
            result["status"] == "failed" for result in public_results
        )
        has_unresolved_public_edge = any(
            graph["unresolved_edges"] for graph in public_graphs
        )
        if not has_failed_public_stage and not has_unresolved_public_edge:
            errors.append(
                f"{relative_path}: not-publicly-reproducible outcome lacks a failed "
                "public-only stage or unresolved public-only dependency edge"
            )
    elif not bundle["limitations"]:
        errors.append(
            f"{relative_path}: inconclusive outcome must identify an evidence limitation"
        )

    return errors


def validate_public_build_bundle(path: Path) -> list[str]:
    return validate_public_build_bundle_value(
        load_yaml_path(path), path.relative_to(ROOT).as_posix()
    )


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
        else:
            if run_schema_validation(family["schema"], instances) != 0:
                return 1

        if family["id"] == "public-build-experiment-bundles":
            for instance in instances:
                errors.extend(validate_public_build_bundle(instance))

        if family["state"] == "scheduled":
            errors.append(
                f"{family['id']} has a record instance but remains scheduled; "
                "activate the family in the same change"
            )

    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if errors:
        return 1

    return 0


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
