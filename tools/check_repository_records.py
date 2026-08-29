# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["PyYAML==6.0.3"]
# ///

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENT_PATTERN = re.compile(r"^## (V2-REQ-[0-9]{3}[A-Z]?):", re.MULTILINE)
DECISION_PATTERN = re.compile(r"^([0-9]{4})-.*\.md$")
GLOB_MARKERS = frozenset("*?[")


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


def check_identifiers() -> list[str]:
    errors: list[str] = []

    requirement_ids: list[str] = []
    for path in sorted((ROOT / "docs/product/requirements").glob("*.md")):
        requirement_ids.extend(REQUIREMENT_PATTERN.findall(path.read_text(encoding="utf-8")))
    for identifier in duplicates(requirement_ids):
        errors.append(f"duplicate requirement identifier: {identifier}")

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

    return errors


def validate_public_build_bundle_value(
    bundle: dict[str, Any], relative_path: str
) -> list[str]:
    errors: list[str] = []

    commands = bundle["protocol"]["commands"]
    command_ids = [command["id"] for command in commands]
    for identifier in duplicates(command_ids):
        errors.append(f"{relative_path}: duplicate protocol command id: {identifier}")
    commands_by_id = {command["id"]: command for command in commands}

    isolation_controls = bundle["isolation_controls"]
    isolation_ids = [control["id"] for control in isolation_controls]
    for identifier in duplicates(isolation_ids):
        errors.append(f"{relative_path}: duplicate isolation control id: {identifier}")
    isolation_id_set = set(isolation_ids)

    for command in commands:
        for dependency in command["depends_on"]:
            if dependency == command["id"]:
                errors.append(
                    f"{relative_path}: protocol command {command['id']} depends on itself"
                )
            elif dependency not in commands_by_id:
                errors.append(
                    f"{relative_path}: protocol command {command['id']} depends on "
                    f"unknown command {dependency}"
                )

    results = bundle["command_results"]
    result_ids = [result["command_id"] for result in results]
    for identifier in duplicates(result_ids):
        errors.append(f"{relative_path}: duplicate command result id: {identifier}")
    result_id_set = set(result_ids)
    results_by_id = {result["command_id"]: result for result in results}

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
        for blocking_id in result.get("blocked_by", []):
            if blocking_id == command_id:
                errors.append(f"{relative_path}: result {command_id} blocks itself")
            elif blocking_id not in result_id_set:
                errors.append(
                    f"{relative_path}: result {command_id} is blocked by unknown result "
                    f"{blocking_id}"
                )

    inventory = bundle["dependency_inventory"]
    for collection in ("resolved", "unresolved"):
        for dependency in inventory[collection]:
            for command_id in dependency["observed_in"]:
                if command_id not in result_id_set:
                    errors.append(
                        f"{relative_path}: {collection} dependency {dependency['id']} "
                        f"references unknown result {command_id}"
                    )

    if bundle["status"] != "completed":
        return errors

    if set(command_ids) != result_id_set or len(command_ids) != len(result_ids):
        errors.append(
            f"{relative_path}: completed bundle must have exactly one result for every "
            "reviewed protocol command"
        )

    for source_mode in ("source-faithful", "public-only"):
        mode_results = {
            result["stage"]: result
            for result in results
            if result["source_mode"] == source_mode
        }
        restore = mode_results["restore"]
        if restore["status"] == "not-applicable":
            errors.append(
                f"{relative_path}: {source_mode} restore cannot be not-applicable"
            )

        for stage in ("build", "test", "package"):
            result = mode_results[stage]
            if restore["status"] != "passed":
                if result["status"] != "blocked":
                    errors.append(
                        f"{relative_path}: {source_mode} {stage} must be blocked when "
                        "its restore does not pass"
                    )
                elif restore["command_id"] not in result.get("blocked_by", []):
                    errors.append(
                        f"{relative_path}: {source_mode} {stage} must link its blocked "
                        "status to the restore result"
                    )
            elif result["status"] in {"passed", "failed"}:
                try:
                    command_arguments = shlex.split(result["command"])
                except ValueError:
                    errors.append(
                        f"{relative_path}: {source_mode} {stage} command cannot be parsed"
                    )
                else:
                    if "--no-restore" not in command_arguments:
                        errors.append(
                            f"{relative_path}: executed {source_mode} {stage} command "
                            "must include --no-restore"
                        )

    if not inventory["source_declared_direct"]:
        errors.append(
            f"{relative_path}: completed bundle must inventory source-declared dependencies"
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
    catalog_parser = subparsers.add_parser("catalog-paths")
    catalog_parser.add_argument("--advisory", action="store_true")
    args = parser.parse_args()

    if args.command == "schemas":
        return validate_structured_records()

    errors = check_identifiers() if args.command == "identifiers" else check_catalog_paths()
    if not errors:
        return 0

    prefix = "ADVISORY" if getattr(args, "advisory", False) else "ERROR"
    for error in errors:
        print(f"{prefix}: {error}", file=sys.stderr)
    return 0 if getattr(args, "advisory", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
