# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["PyYAML==6.0.3"]
# ///

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENT_PATTERN = re.compile(r"^## (V2-REQ-[0-9]{3}[A-Z]?):", re.MULTILINE)
DECISION_PATTERN = re.compile(r"^([0-9]{4})-.*\.md$")
GLOB_MARKERS = frozenset("*?[")


def load_yaml(relative_path: str) -> dict[str, Any]:
    path = ROOT / relative_path
    with path.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{relative_path} must contain a YAML object")
    return value


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


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("identifiers")
    catalog_parser = subparsers.add_parser("catalog-paths")
    catalog_parser.add_argument("--advisory", action="store_true")
    args = parser.parse_args()

    errors = check_identifiers() if args.command == "identifiers" else check_catalog_paths()
    if not errors:
        return 0

    prefix = "ADVISORY" if getattr(args, "advisory", False) else "ERROR"
    for error in errors:
        print(f"{prefix}: {error}", file=sys.stderr)
    return 0 if getattr(args, "advisory", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
