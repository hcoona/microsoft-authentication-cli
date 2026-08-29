# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["PyYAML==6.0.3"]
# ///

from __future__ import annotations

import argparse
import html
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENT_ID_PATTERN = re.compile(r"^V2-REQ-[0-9]{3}[A-Z]?$")
REQUIREMENT_PREFIX_PATTERN = re.compile(r"^V2-REQ-")
ATX_HEADING_PATTERN = re.compile(r"^ {0,3}#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$")
SETEXT_HEADING_PATTERN = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
DECISION_PATTERN = re.compile(r"^([0-9]{4})-.*\.md$")
GLOB_MARKERS = frozenset("*?[")
ZERO_SHA = "0" * 40
EXACT_VERSION_PATTERN = re.compile(
    r"^[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
INLINE_LINK_PATTERN = re.compile(
    r"(?<!!)\[[^\]]+\]\(\s*(?:<([^>]+)>|([^)\s]+))(?:\s+['\"(][^)]*)?\)"
)
REFERENCE_LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]+\]\[([^\]]+)\]")
SHORT_REFERENCE_LINK_PATTERN = re.compile(r"(?<!!)\[([^\]]+)\](?![\[(])")
REFERENCE_DEFINITION_PATTERN = re.compile(
    r"^ {0,3}\[([^\]]+)\]:[ \t]*(?:<([^>]+)>|(\S+))"
)


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


def rendered_markdown_lines(text: str) -> list[str]:
    rendered: list[str] = []
    in_fence: tuple[str, int] | None = None
    in_comment = False
    in_html_block = False
    for raw_line in text.splitlines():
        line = raw_line
        if in_fence is not None:
            fence_character, fence_length = in_fence
            if re.match(
                rf"^ {{0,3}}{re.escape(fence_character)}{{{fence_length},}}[ \t]*$",
                line,
            ):
                in_fence = None
            continue

        fence_match = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if fence_match is not None:
            marker = fence_match.group(1)
            in_fence = (marker[0], len(marker))
            continue

        visible_parts: list[str] = []
        position = 0
        while position < len(line):
            if in_comment:
                comment_end = line.find("-->", position)
                if comment_end == -1:
                    position = len(line)
                    break
                in_comment = False
                position = comment_end + 3
                continue

            comment_start = line.find("<!--", position)
            if comment_start == -1:
                visible_parts.append(line[position:])
                break
            visible_parts.append(line[position:comment_start])
            in_comment = True
            position = comment_start + 4

        visible_line = "".join(visible_parts)
        stripped = visible_line.lstrip()
        if in_html_block:
            if stripped.startswith("</"):
                in_html_block = False
            continue
        if re.match(
            r"^ {0,3}<(address|article|aside|base|blockquote|body|caption|center|col|"
            r"colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|"
            r"footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|"
            r"li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|"
            r"search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|"
            r"ul)(?:[ \t]|>|/>)",
            visible_line,
            flags=re.IGNORECASE,
        ):
            in_html_block = not (stripped.endswith("/>") or stripped.startswith("<hr"))
            continue
        rendered.append(visible_line)
    return rendered


def strip_inline_code(text: str) -> str:
    return re.sub(r"`+[^`]*`+", "", text)


def requirement_headings(text: str) -> tuple[list[str], list[str]]:
    identifiers: list[str] = []
    malformed: list[str] = []
    lines = rendered_markdown_lines(text)
    for index, line in enumerate(lines):
        heading_text: str | None = None
        if (match := ATX_HEADING_PATTERN.fullmatch(line)) is not None:
            heading_text = match.group(1)
        elif (
            index + 1 < len(lines)
            and SETEXT_HEADING_PATTERN.fullmatch(lines[index + 1]) is not None
            and SETEXT_HEADING_PATTERN.fullmatch(lines[index]) is None
            and line.strip()
        ):
            heading_text = line.strip()
        if heading_text is None:
            continue
        heading_text = strip_inline_code(heading_text).strip()
        if not REQUIREMENT_PREFIX_PATTERN.match(heading_text):
            continue
        identifier, separator, _title = heading_text.partition(":")
        if separator and REQUIREMENT_ID_PATTERN.fullmatch(identifier):
            identifiers.append(identifier)
        else:
            malformed.append(heading_text)
    return identifiers, malformed


def markdown_link_destinations(text: str) -> list[str]:
    rendered_lines = rendered_markdown_lines(text)
    definitions: dict[str, str] = {}
    for line in rendered_lines:
        match = REFERENCE_DEFINITION_PATTERN.match(line)
        if match is not None:
            definitions[match.group(1).strip().casefold()] = (
                match.group(2) or match.group(3)
            )

    destinations: list[str] = []
    for line in rendered_lines:
        if REFERENCE_DEFINITION_PATTERN.match(line) is not None:
            continue
        for match in INLINE_LINK_PATTERN.finditer(line):
            destinations.append(match.group(1) or match.group(2))
        line_without_code = strip_inline_code(line)
        explicit_reference_spans: list[tuple[int, int]] = []
        for match in REFERENCE_LINK_PATTERN.finditer(line_without_code):
            explicit_reference_spans.append(match.span())
            reference = match.group(1).strip().casefold()
            if reference in definitions:
                destinations.append(definitions[reference])
        for match in SHORT_REFERENCE_LINK_PATTERN.finditer(line_without_code):
            if any(
                start <= match.start() < end
                for start, end in explicit_reference_spans
            ):
                continue
            reference = match.group(1).strip().casefold()
            if reference in definitions:
                destinations.append(definitions[reference])
    return destinations


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
        identifiers, malformed = requirement_headings(content)
        requirement_ids.update(identifiers)
        if malformed:
            errors.append(
                f"accepted record {relative_path} contains malformed requirement "
                f"headings: {', '.join(malformed)}"
            )
    return requirement_ids


def check_identifiers() -> list[str]:
    errors: list[str] = []

    requirement_occurrences: list[tuple[str, str]] = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        relative_path = path.relative_to(ROOT).as_posix()
        identifiers, malformed = requirement_headings(path.read_text(encoding="utf-8"))
        for heading in malformed:
            errors.append(
                f"malformed requirement heading in {relative_path}: {heading}"
            )
        requirement_occurrences.extend(
            (identifier, relative_path)
            for identifier in identifiers
        )
    requirement_ids = [identifier for identifier, _path in requirement_occurrences]
    for identifier in duplicates(requirement_ids):
        errors.append(f"duplicate requirement identifier: {identifier}")
    for identifier, relative_path in requirement_occurrences:
        if not relative_path.startswith("docs/product/requirements/"):
            errors.append(
                f"requirement identifier {identifier} is defined outside the canonical "
                f"requirements family: {relative_path}"
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


def github_heading_slug(heading: str) -> str:
    normalized = html.unescape(strip_inline_code(heading)).strip().lower()
    normalized = re.sub(r"<[^>]+>", "", normalized)
    normalized = re.sub(r"[^\w\s-]", "", normalized)
    normalized = re.sub(r"[\s-]+", "-", normalized)
    return normalized.strip("-")


def markdown_heading_slugs(path: Path) -> set[str]:
    slugs: set[str] = set()
    counts: Counter[str] = Counter()
    lines = rendered_markdown_lines(path.read_text(encoding="utf-8"))
    for index, line in enumerate(lines):
        heading_text: str | None = None
        if (match := ATX_HEADING_PATTERN.fullmatch(line)) is not None:
            heading_text = match.group(1)
        elif (
            index + 1 < len(lines)
            and SETEXT_HEADING_PATTERN.fullmatch(lines[index + 1]) is not None
            and SETEXT_HEADING_PATTERN.fullmatch(lines[index]) is None
            and line.strip()
        ):
            heading_text = line.strip()
        if heading_text is None:
            continue
        base_slug = github_heading_slug(heading_text)
        slug = base_slug if counts[base_slug] == 0 else f"{base_slug}-{counts[base_slug]}"
        counts[base_slug] += 1
        slugs.add(slug)
    return slugs


def check_control_references() -> list[str]:
    errors: list[str] = []
    controls = load_yaml("docs/governance/controls.yaml")["controls"]
    for control in controls:
        if control["state"] != "current":
            continue
        for reference in control["governing_rules"]:
            path_text, separator, anchor = reference.partition("#")
            path = ROOT / path_text
            if not path.is_file():
                errors.append(
                    f"control {control['id']} governing rule does not exist: {path_text}"
                )
                continue
            if separator:
                if path.suffix.lower() != ".md":
                    errors.append(
                        f"control {control['id']} governing-rule anchor targets a "
                        f"non-Markdown file: {reference}"
                    )
                elif anchor not in markdown_heading_slugs(path):
                    errors.append(
                        f"control {control['id']} governing-rule anchor does not exist: "
                        f"{reference}"
                    )

        implementation = control["implementation"]
        if implementation["kind"] == "repository-path":
            path = ROOT / implementation["value"]
            if not path.is_file():
                errors.append(
                    f"control {control['id']} implementation does not exist: "
                    f"{implementation['value']}"
                )
    return errors


def check_documentation_portal(catalog: dict[str, Any]) -> list[str]:
    portal = ROOT / "docs/README.md"
    linked_records: set[str] = set()
    for target in markdown_link_destinations(portal.read_text(encoding="utf-8")):
        path_part = target.split("#", maxsplit=1)[0]
        if not path_part or "://" in path_part:
            continue
        resolved = (portal.parent / path_part).resolve()
        try:
            relative_path = resolved.relative_to(ROOT)
        except ValueError:
            continue
        if resolved.is_file():
            linked_records.add(relative_path.as_posix())

    retained_records: set[str] = set()
    for family in catalog["families"]:
        if family["state"] != "current":
            continue
        pattern = family["path"]
        paths = ROOT.glob(pattern) if contains_glob(pattern) else [ROOT / pattern]
        retained_records.update(
            path.relative_to(ROOT).as_posix()
            for path in paths
            if path.is_file() and path != portal
        )
    return [
        f"documentation portal does not route to retained record: {relative_path}"
        for relative_path in sorted(retained_records - linked_records)
    ]


def check_catalog_paths() -> list[str]:
    errors: list[str] = []
    catalog = load_yaml("docs/governance/record-families.yaml")
    current = [family for family in catalog["families"] if family["state"] == "current"]
    current_family_paths: dict[str, set[Path]] = {}

    for family in current:
        pattern = family["path"]
        family_paths = {
            path
            for path in (
                ROOT.glob(pattern) if contains_glob(pattern) else [ROOT / pattern]
            )
            if path.is_file()
        }
        current_family_paths[family["id"]] = family_paths
        if family["carrier"] == "repository-file":
            if contains_glob(pattern):
                errors.append(f"{family['id']} uses a glob for a singleton path: {pattern}")
            elif not (ROOT / pattern).is_file():
                errors.append(f"{family['id']} path does not exist: {pattern}")
        elif not family_paths:
            errors.append(f"{family['id']} path matches no current files: {pattern}")

        schema = family.get("schema")
        if schema and not (ROOT / schema).is_file():
            errors.append(f"{family['id']} schema does not exist: {schema}")

    governed_paths = sorted(
        {
            path
            for paths in current_family_paths.values()
            for path in paths
        }
    )
    for path in governed_paths:
        relative_path = path.relative_to(ROOT).as_posix()
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

    errors.extend(check_documentation_portal(catalog))
    errors.extend(check_control_references())
    return errors


DOTNET_STAGE_ARGUMENT = {
    "restore": "restore",
    "build": "build",
    "test": "test",
    "package": "pack",
}


def exact_declared_version(version_constraint: str) -> str | None:
    if (
        version_constraint.startswith("[")
        and version_constraint.endswith("]")
        and "," not in version_constraint
    ):
        candidate = version_constraint[1:-1]
        if EXACT_VERSION_PATTERN.fullmatch(candidate):
            return candidate
    return None


def is_public_https_source(source: str) -> bool:
    return source == "https://api.nuget.org/v3/index.json"


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

    protocol = bundle["protocol"]
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
        if source_mode == "source-faithful":
            if configuration["path"] != "nuget.config":
                errors.append(
                    f"{relative_path}: source-faithful restore configuration must be "
                    "the audited checkout's nuget.config"
                )
            if (
                configuration["sha256"]
                != "be2776f78f5af30efb8836a32c4467ca0dcd9220c17d778ed8332b33dd309a6b"
            ):
                errors.append(
                    f"{relative_path}: source-faithful restore configuration must use "
                    "the audited nuget.config SHA-256"
                )
            if configuration["sources"] != [
                "https://pkgs.dev.azure.com/office/_packaging/Office/nuget/v3/index.json"
            ]:
                errors.append(
                    f"{relative_path}: source-faithful restore configuration must "
                    "record the audited Office package source"
                )
        else:
            for source in configuration["sources"]:
                if not is_public_https_source(source):
                    errors.append(
                        f"{relative_path}: public-only restore source must be an HTTPS "
                        f"URL without embedded credentials: {source}"
                    )

    if set(restore_configurations_by_mode) != set(source_modes):
        errors.append(
            f"{relative_path}: protocol must define exactly one restore configuration "
            "for each source mode"
        )
    else:
        source_faithful = restore_configurations_by_mode["source-faithful"]
        public_only = restore_configurations_by_mode["public-only"]
        if (
            public_only["path"] == source_faithful["path"]
            or public_only["sha256"] == source_faithful["sha256"]
            or public_only["sources"] == source_faithful["sources"]
        ):
            errors.append(
                f"{relative_path}: public-only restore configuration must differ from "
                "the audited source-faithful configuration"
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

    isolation_controls = bundle["isolation_controls"]
    isolation_ids = [control["id"] for control in isolation_controls]
    for identifier in duplicates(isolation_ids):
        errors.append(f"{relative_path}: duplicate isolation control id: {identifier}")
    isolation_id_set = set(isolation_ids)

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
    environment_fingerprint = bundle["environment"]["fingerprint"]
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
        for isolation_id in result["isolation_control_ids"]:
            if isolation_id not in isolation_id_set:
                errors.append(
                    f"{relative_path}: result {command_id} references unknown isolation "
                    f"control {isolation_id}"
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
    declaration_ids = [
        dependency["declaration_id"]
        for dependency in inventory["source_declared_direct"]
    ]
    for identifier in duplicates(declaration_ids):
        errors.append(f"{relative_path}: duplicate dependency declaration id: {identifier}")
    declarations_by_id = {
        dependency["declaration_id"]: dependency
        for dependency in inventory["source_declared_direct"]
    }
    covered_targets: dict[str, set[str]] = {
        declaration_id: set() for declaration_id in declarations_by_id
    }
    public_covered_targets: dict[str, set[str]] = {
        declaration_id: set() for declaration_id in declarations_by_id
    }

    public_resolved_observations: list[dict[str, Any]] = []
    public_unresolved_observations: list[dict[str, Any]] = []
    for collection in ("resolved", "unresolved"):
        for dependency in inventory[collection]:
            if (
                collection == "resolved"
                and not EXACT_VERSION_PATTERN.fullmatch(dependency["version"])
            ):
                errors.append(
                    f"{relative_path}: resolved dependency {dependency['id']} must "
                    "record an exact version"
                )
            dependency_has_public_observation = False
            dependency_targets: set[str] = set()
            public_dependency_targets: set[str] = set()
            for observation in dependency["observations"]:
                dependency_targets.update(observation["targets"])
                command_id = observation["result_id"]
                result = results_by_id.get(command_id)
                if result is None:
                    errors.append(
                        f"{relative_path}: {collection} dependency {dependency['id']} "
                        f"references unknown result {command_id}"
                    )
                    continue
                if result["stage"] != "restore":
                    errors.append(
                        f"{relative_path}: {collection} dependency {dependency['id']} "
                        f"must cite a restore result, not {command_id}"
                    )
                if result["status"] not in {"passed", "failed"}:
                    errors.append(
                        f"{relative_path}: {collection} dependency {dependency['id']} "
                        f"cites unexecuted result {command_id}"
                    )
                if collection == "unresolved" and result["status"] == "passed":
                    errors.append(
                        f"{relative_path}: unresolved dependency {dependency['id']} "
                        f"conflicts with passing restore result {command_id}"
                    )
                command = commands_by_id.get(command_id)
                if command is not None:
                    restore_configuration = restore_configurations.get(
                        command["restore_configuration_id"]
                    )
                    if (
                        restore_configuration is not None
                        and observation["retrieval_source"]
                        not in restore_configuration["sources"]
                    ):
                        errors.append(
                            f"{relative_path}: dependency {dependency['id']} cites "
                            f"retrieval source {observation['retrieval_source']} outside "
                            f"restore configuration {restore_configuration['id']}"
                        )
                if result["source_mode"] == "public-only":
                    dependency_has_public_observation = True
                    public_dependency_targets.update(observation["targets"])
                    target = (
                        public_resolved_observations
                        if collection == "resolved"
                        else public_unresolved_observations
                    )
                    target.append(observation)

            for declaration_id in dependency["declaration_ids"]:
                declaration = declarations_by_id.get(declaration_id)
                if declaration is None:
                    errors.append(
                        f"{relative_path}: {collection} dependency {dependency['id']} "
                        f"references unknown declaration {declaration_id}"
                    )
                    continue
                if dependency["id"].casefold() != declaration["id"].casefold():
                    errors.append(
                        f"{relative_path}: {collection} dependency {dependency['id']} "
                        f"does not match declaration {declaration_id} identifier "
                        f"{declaration['id']}"
                    )
                if dependency["kind"] != declaration["kind"]:
                    errors.append(
                        f"{relative_path}: {collection} dependency {dependency['id']} "
                        f"does not match declaration {declaration_id} kind "
                        f"{declaration['kind']}"
                    )
                if collection == "resolved":
                    exact_version = exact_declared_version(
                        declaration["version_constraint"]
                    )
                    if (
                        exact_version is not None
                        and dependency["version"] != exact_version
                    ):
                        errors.append(
                            f"{relative_path}: resolved dependency {dependency['id']} "
                            f"version {dependency['version']} does not match exact "
                            f"declaration {declaration_id} version {exact_version}"
                        )
                elif (
                    dependency["version_constraint"]
                    != declaration["version_constraint"]
                ):
                    errors.append(
                        f"{relative_path}: unresolved dependency {dependency['id']} "
                        f"does not preserve declaration {declaration_id} version "
                        "constraint"
                    )

                covered_targets[declaration_id].update(dependency_targets)
                if collection == "resolved" and dependency_has_public_observation:
                    public_covered_targets[declaration_id].update(
                        public_dependency_targets
                    )

    if bundle["status"] != "completed":
        return errors

    if set(command_ids) != result_id_set or len(command_ids) != len(result_ids):
        errors.append(
            f"{relative_path}: completed bundle must have exactly one result for every "
            "reviewed protocol command"
        )

    if not inventory["source_declared_direct"]:
        errors.append(
            f"{relative_path}: completed bundle must inventory source-declared dependencies"
        )
    for declaration_id, dependency in declarations_by_id.items():
        missing_targets = sorted(
            set(dependency["targets"]) - covered_targets[declaration_id]
        )
        if missing_targets:
            errors.append(
                f"{relative_path}: dependency declaration {declaration_id} lacks "
                f"resolved or unresolved coverage for targets {missing_targets}"
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
        if not public_resolved_observations:
            errors.append(
                f"{relative_path}: publicly-reproducible outcome requires public-only "
                "resolved dependency observations"
            )
        for observation in [
            *public_resolved_observations,
            *public_unresolved_observations,
        ]:
            if observation["access"] != "anonymous":
                errors.append(
                    f"{relative_path}: publicly-reproducible outcome requires anonymous "
                    "public-only dependency access"
                )
            if observation["cache_state"] != "empty":
                errors.append(
                    f"{relative_path}: publicly-reproducible outcome requires empty-cache "
                    "public-only dependency observations"
                )
        for declaration_id, dependency in declarations_by_id.items():
            missing_targets = sorted(
                set(dependency["targets"]) - public_covered_targets[declaration_id]
            )
            if missing_targets:
                errors.append(
                    f"{relative_path}: publicly-reproducible outcome lacks a public-only "
                    f"resolved observation for declaration {declaration_id} targets "
                    f"{missing_targets}"
                )
        if public_unresolved_observations:
            errors.append(
                f"{relative_path}: publicly-reproducible outcome conflicts with "
                "unresolved public-only dependency edges"
            )
    elif completion["outcome"] == "not-publicly-reproducible":
        has_failed_public_stage = any(
            result["status"] == "failed" for result in public_results
        )
        if not has_failed_public_stage and not public_unresolved_observations:
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


def validate_structured_records() -> int:
    catalog = load_yaml("docs/governance/record-families.yaml")
    families = [family for family in catalog["families"] if family.get("schema")]
    errors: list[str] = []

    for family in families:
        schema = family["schema"]
        instances = sorted(path for path in ROOT.glob(family["path"]) if path.is_file())
        if not instances:
            if family["state"] == "current":
                errors.append(
                    f"{family['id']} has no structured record at {family['path']}"
                )
            continue

        result = subprocess.run(
            [
                "check-jsonschema",
                "--schemafile",
                schema,
                *(path.relative_to(ROOT).as_posix() for path in instances),
            ],
            cwd=ROOT,
            check=False,
        )
        if result.returncode != 0:
            return result.returncode

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
