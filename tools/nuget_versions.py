from __future__ import annotations

import re


EXACT_VERSION_PATTERN = re.compile(
    r"^[0-9]+(?:\.[0-9]+){0,3}"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
MAX_EXACT_VERSION_LENGTH = 64
MAX_CONSTRAINT_LENGTH = 256
MAX_VERSION_COMPONENT = 2_147_483_647


def bounded_numeric_component(value: str) -> int | None:
    significant = value.lstrip("0") or "0"
    if len(significant) > 10:
        return None
    parsed = int(significant)
    return parsed if parsed <= MAX_VERSION_COMPONENT else None


def parse_nuget_version(
    value: str,
) -> tuple[tuple[int, int, int, int], tuple[str, ...] | None] | None:
    if (
        len(value) > MAX_EXACT_VERSION_LENGTH
        or EXACT_VERSION_PATTERN.fullmatch(value) is None
    ):
        return None
    without_metadata = value.split("+", maxsplit=1)[0]
    core_text, separator, prerelease_text = without_metadata.partition("-")
    core_parts = [bounded_numeric_component(part) for part in core_text.split(".")]
    if any(part is None for part in core_parts):
        return None
    core = tuple(part for part in core_parts if part is not None)
    padded_core = (*core, *(0 for _ in range(4 - len(core))))
    prerelease: tuple[str, ...] | None = None
    if separator:
        prerelease_parts = prerelease_text.split(".")
        for part in prerelease_parts:
            if part.isdigit():
                if len(part) > 1 and part.startswith("0"):
                    return None
                if bounded_numeric_component(part) is None:
                    return None
        prerelease = tuple(part.casefold() for part in prerelease_parts)
    return padded_core, prerelease


def nuget_version_is_valid(value: str) -> bool:
    return parse_nuget_version(value) is not None


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


def compare_nuget_versions(left: str, right: str) -> int | None:
    left_version = parse_nuget_version(left)
    right_version = parse_nuget_version(right)
    if left_version is None or right_version is None:
        return None
    left_core, left_prerelease = left_version
    right_core, right_prerelease = right_version
    if left_core != right_core:
        return 1 if left_core > right_core else -1
    return compare_prerelease(left_prerelease, right_prerelease)


def nuget_version_at_least(resolved: str, minimum: str) -> bool:
    comparison = compare_nuget_versions(resolved, minimum)
    return comparison is not None and comparison >= 0


def nuget_constraint_is_valid(constraint: str) -> bool:
    if len(constraint) > MAX_CONSTRAINT_LENGTH:
        return False
    constraint = constraint.strip()
    if nuget_version_is_valid(constraint):
        return True
    if (
        len(constraint) < 3
        or constraint[0] not in {"[", "("}
        or constraint[-1] not in {"]", ")"}
    ):
        return False
    body = constraint[1:-1]
    if "," not in body:
        return (
            constraint[0] == "["
            and constraint[-1] == "]"
            and nuget_version_is_valid(body.strip())
        )
    minimum, maximum = (part.strip() for part in body.split(",", maxsplit=1))
    if not minimum and not maximum:
        return False
    if minimum and not nuget_version_is_valid(minimum):
        return False
    if maximum and not nuget_version_is_valid(maximum):
        return False
    if minimum and maximum:
        comparison = compare_nuget_versions(minimum, maximum)
        if comparison is None or comparison > 0:
            return False
        if comparison == 0 and (
            constraint[0] == "(" or constraint[-1] == ")"
        ):
            return False
    return True


def nuget_version_satisfies_constraint(resolved: str, constraint: str) -> bool:
    constraint = constraint.strip()
    if not nuget_constraint_is_valid(constraint):
        return False
    if nuget_version_is_valid(constraint):
        return nuget_version_at_least(resolved, constraint)
    body = constraint[1:-1]
    if "," not in body:
        return (
            constraint[0] == "["
            and constraint[-1] == "]"
            and compare_nuget_versions(resolved, body.strip()) == 0
        )
    minimum, maximum = (part.strip() for part in body.split(",", maxsplit=1))
    if minimum:
        comparison = compare_nuget_versions(resolved, minimum)
        if comparison is None or comparison < 0 or (
            comparison == 0 and constraint[0] == "("
        ):
            return False
    if maximum:
        comparison = compare_nuget_versions(resolved, maximum)
        if comparison is None or comparison > 0 or (
            comparison == 0 and constraint[-1] == ")"
        ):
            return False
    return True
