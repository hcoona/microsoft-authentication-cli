# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["PyYAML==6.0.3"]
# ///

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENT_PATTERN = re.compile(
    r"^#{1,6} (V2-REQ-[0-9]{3}[A-Z]?):", re.MULTILINE
)
DECISION_PATTERN = re.compile(r"^([0-9]{4})-.*\.md$")
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)\s]+)\)")
GLOB_MARKERS = frozenset("*?[")
ZERO_SHA = "0" * 40


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

    return git_output("rev-parse", "--verify", "HEAD^{commit}")


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
        requirement_ids.update(REQUIREMENT_PATTERN.findall(content))
    return requirement_ids


def check_identifiers() -> list[str]:
    errors: list[str] = []

    requirement_ids: list[str] = []
    for path in sorted((ROOT / "docs/product/requirements").glob("*.md")):
        requirement_ids.extend(REQUIREMENT_PATTERN.findall(path.read_text(encoding="utf-8")))
    for identifier in duplicates(requirement_ids):
        errors.append(f"duplicate requirement identifier: {identifier}")

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


def check_documentation_portal() -> list[str]:
    portal = ROOT / "docs/README.md"
    linked_records: set[str] = set()
    for target in MARKDOWN_LINK_PATTERN.findall(portal.read_text(encoding="utf-8")):
        path_part = target.split("#", maxsplit=1)[0]
        if not path_part or "://" in path_part:
            continue
        resolved = (portal.parent / path_part).resolve()
        try:
            relative_path = resolved.relative_to(ROOT)
        except ValueError:
            continue
        if relative_path.suffix == ".md":
            linked_records.add(relative_path.as_posix())

    retained_records = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "docs").rglob("*.md")
        if path != portal
    }
    return [
        f"documentation portal does not route to retained record: {relative_path}"
        for relative_path in sorted(retained_records - linked_records)
    ]


def check_catalog_paths() -> list[str]:
    errors: list[str] = []
    catalog = load_yaml("docs/governance/record-families.yaml")
    current = [family for family in catalog["families"] if family["state"] == "current"]

    for family in current:
        pattern = family["path"]
        if family["carrier"] == "repository-file":
            if contains_glob(pattern):
                errors.append(f"{family['id']} uses a glob for a singleton path: {pattern}")
            elif not (ROOT / pattern).is_file():
                errors.append(f"{family['id']} path does not exist: {pattern}")
        elif not any(path.is_file() for path in ROOT.glob(pattern)):
            errors.append(f"{family['id']} path matches no current files: {pattern}")

        schema = family.get("schema")
        if schema and not (ROOT / schema).is_file():
            errors.append(f"{family['id']} schema does not exist: {schema}")

    governed_paths = [
        *sorted(path for path in ROOT.glob("*.md") if path.is_file()),
        ROOT / ".github/pull_request_template.md",
        *sorted(path for path in (ROOT / "docs").rglob("*") if path.is_file()),
        *sorted(path for path in (ROOT / "schemas").rglob("*") if path.is_file()),
    ]
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

    errors.extend(check_documentation_portal())
    return errors


DOTNET_STAGE_ARGUMENT = {
    "restore": "restore",
    "build": "build",
    "test": "test",
    "package": "pack",
}


def validate_dotnet_invocation(
    command: dict[str, Any], relative_path: str
) -> list[str]:
    errors: list[str] = []
    invocation = command["command"]
    executable = invocation["executable"].replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    if executable.lower() not in {"dotnet", "dotnet.exe"}:
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

    if command["stage"] == "restore":
        if "--no-restore" in arguments:
            errors.append(
                f"{relative_path}: restore command {command['id']} must not include "
                "--no-restore"
            )
    elif "--no-restore" not in arguments:
        errors.append(
            f"{relative_path}: protocol command {command['id']} must include "
            "--no-restore as a direct dotnet argument"
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

    commands = bundle["protocol"]["commands"]
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
        errors.extend(validate_dotnet_invocation(command, relative_path))
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
    public_resolved_observations: list[dict[str, Any]] = []
    public_unresolved_observations: list[dict[str, Any]] = []
    resolved_without_public_observations: list[str] = []
    public_resolved_dependency_ids: set[str] = set()
    for collection in ("resolved", "unresolved"):
        for dependency in inventory[collection]:
            dependency_has_public_observation = False
            for observation in dependency["observations"]:
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
                if result["source_mode"] == "public-only":
                    dependency_has_public_observation = True
                    target = (
                        public_resolved_observations
                        if collection == "resolved"
                        else public_unresolved_observations
                    )
                    target.append(observation)
            if collection == "resolved" and not dependency_has_public_observation:
                resolved_without_public_observations.append(
                    f"{dependency['id']} {dependency['version']}"
                )
            elif collection == "resolved":
                public_resolved_dependency_ids.add(dependency["id"])

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
    observed_dependency_ids = {
        dependency["id"]
        for collection in ("resolved", "unresolved")
        for dependency in inventory[collection]
    }
    for dependency in inventory["source_declared_direct"]:
        if dependency["id"] not in observed_dependency_ids:
            errors.append(
                f"{relative_path}: source-declared dependency {dependency['id']} has no "
                "resolved or unresolved observation"
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
        for dependency in sorted(resolved_without_public_observations):
            errors.append(
                f"{relative_path}: publicly-reproducible outcome lacks a public-only "
                f"observation for resolved dependency {dependency}"
            )
        for dependency in inventory["source_declared_direct"]:
            if dependency["id"] not in public_resolved_dependency_ids:
                errors.append(
                    f"{relative_path}: publicly-reproducible outcome lacks a public-only "
                    f"resolved observation for direct dependency {dependency['id']}"
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
