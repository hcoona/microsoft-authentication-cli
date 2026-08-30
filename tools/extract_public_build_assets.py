# /// script
# requires-python = ">=3.13,<3.14"
# ///

from __future__ import annotations

import argparse
import hashlib
import json
import math
import posixpath
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from nuget_versions import nuget_version_satisfies_constraint


ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "docs/research/public-build-source-baseline.json"
RUNTIME_IDENTIFIER_PATTERN = re.compile(r"^(linux|win|osx)-(x64|arm64)$")


class ExtractionError(ValueError):
    pass


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ExtractionError(f"JSON object contains duplicate key {key!r}")
        value[key] = item
    return value


def reject_non_json_constant(value: str) -> None:
    raise ExtractionError(f"JSON contains non-standard numeric constant {value}")


def parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ExtractionError(
            f"JSON number is outside the supported finite range: {value}"
        )
    return parsed


def parse_json_object_bytes(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            content.decode("utf-8-sig"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_non_json_constant,
            parse_float=parse_finite_json_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExtractionError(f"cannot read JSON from {label}: {error}") from error
    if not isinstance(value, dict):
        raise ExtractionError(f"{label} must contain a JSON object")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        content = path.read_bytes()
    except OSError as error:
        raise ExtractionError(f"cannot read JSON from {path}: {error}") from error
    return parse_json_object_bytes(content, str(path))


def split_library_key(value: str) -> tuple[str, str]:
    package_id, separator, version = value.rpartition("/")
    if not separator or not package_id or not version:
        raise ExtractionError(f"invalid project.assets.json library key: {value}")
    return package_id, version


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    if not normalized:
        raise ExtractionError(f"cannot derive a stable identifier from {value!r}")
    return normalized


def dependency_constraint(value: Any, label: str) -> str:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict):
        target = value.get("target")
        version = value.get("version")
        if target not in {None, "Package", "Project"}:
            raise ExtractionError(f"{label} has an unsupported dependency target")
        if isinstance(version, str) and version:
            return version
    raise ExtractionError(f"{label} has no package version constraint")


def condition_applies(condition: str, runtime_identifier: str) -> bool:
    is_windows = runtime_identifier.startswith("win-")
    return {
        "always": True,
        "windows": is_windows,
        "not-windows": not is_windows,
    }[condition]


def direct_constraint_matches_source(actual: str, source: str) -> bool:
    if actual == source:
        return True
    minimum_range = re.fullmatch(r"\[\s*([^,\]]+)\s*,\s*\)", actual)
    return minimum_range is not None and minimum_range.group(1).strip() == source


def normalize_absolute_path(value: str, windows: bool) -> str:
    if windows:
        normalized = posixpath.normpath(value.replace("\\", "/"))
        if re.match(r"^[A-Za-z]:/", normalized) is None:
            raise ExtractionError(f"expected an absolute Windows path: {value}")
        return normalized.casefold()
    if "\\" in value:
        raise ExtractionError(f"expected a canonical POSIX path: {value}")
    normalized = posixpath.normpath(value)
    if not normalized.startswith("/"):
        raise ExtractionError(f"expected an absolute POSIX path: {value}")
    return normalized


def resolve_project_reference_path(current_project_path: str, value: str) -> str:
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        raise ExtractionError(
            f"project.assets.json project reference must be repository-relative: {value}"
        )
    resolved = posixpath.normpath(
        str(PurePosixPath(current_project_path).parent / PurePosixPath(normalized))
    )
    if resolved == ".." or resolved.startswith("../"):
        raise ExtractionError(
            f"project.assets.json project reference leaves the repository: {value}"
        )
    return resolved


def extract_projection(
    assets: dict[str, Any],
    assets_bytes: bytes,
    baseline: dict[str, Any],
    target_id: str,
    runtime_identifier: str,
    assets_target: str,
    checkout_root: str,
) -> dict[str, Any]:
    if RUNTIME_IDENTIFIER_PATTERN.fullmatch(runtime_identifier) is None:
        raise ExtractionError(f"unsupported runtime identifier: {runtime_identifier}")

    targets_by_id = {
        target["id"]: target for target in baseline["attempted_targets"]
    }
    target = targets_by_id.get(target_id)
    if target is None:
        raise ExtractionError(f"unknown source-baseline target: {target_id}")
    target_framework = target["target_framework"]
    expected_project_target_ids: set[str] = set()
    pending_project_target_ids = list(target["project_references"])
    while pending_project_target_ids:
        project_target_id = pending_project_target_ids.pop()
        if project_target_id in expected_project_target_ids:
            continue
        project_target = targets_by_id.get(project_target_id)
        if project_target is None:
            raise ExtractionError(
                f"source baseline references unknown project target {project_target_id}"
            )
        expected_project_target_ids.add(project_target_id)
        pending_project_target_ids.extend(project_target["project_references"])
    if assets_target != target_framework:
        raise ExtractionError(
            f"assets target {assets_target} does not match source-baseline target "
            f"framework {target_framework} selected by the canonical command"
        )

    project = assets.get("project")
    restore = project.get("restore") if isinstance(project, dict) else None
    project_path = restore.get("projectPath") if isinstance(restore, dict) else None
    if not isinstance(project_path, str) or not project_path:
        raise ExtractionError("project.assets.json has no restore projectPath")
    windows = runtime_identifier.startswith("win-")
    recorded_project_path = normalize_absolute_path(project_path, windows)
    expected_project_path = normalize_absolute_path(
        f"{checkout_root.rstrip('/')}/{target['project_path']}",
        windows,
    )
    if recorded_project_path != expected_project_path:
        raise ExtractionError(
            f"project.assets.json project path {project_path} does not match "
            f"source-baseline target {target['project_path']}"
        )
    packages_path = restore.get("packagesPath")
    if not isinstance(packages_path, str) or not packages_path:
        raise ExtractionError("project.assets.json has no restore packagesPath")
    normalized_packages_path = normalize_absolute_path(packages_path, windows)
    package_folders = assets.get("packageFolders")
    if not isinstance(package_folders, dict) or not package_folders:
        raise ExtractionError("project.assets.json has no packageFolders metadata")
    normalized_package_folders = sorted(
        normalize_absolute_path(path, windows) for path in package_folders
    )
    if len(normalized_package_folders) != len(set(normalized_package_folders)):
        raise ExtractionError(
            "project.assets.json has duplicate normalized packageFolders paths"
        )
    config_file_paths = restore.get("configFilePaths")
    if not isinstance(config_file_paths, list) or not config_file_paths:
        raise ExtractionError("project.assets.json has no restore configFilePaths")
    if not all(
        isinstance(path, str) and path for path in config_file_paths
    ):
        raise ExtractionError(
            "project.assets.json restore configFilePaths must contain paths"
        )
    normalized_config_file_paths = sorted(
        normalize_absolute_path(path, windows) for path in config_file_paths
    )
    if len(normalized_config_file_paths) != len(
        set(normalized_config_file_paths)
    ):
        raise ExtractionError(
            "project.assets.json has duplicate normalized configFilePaths"
        )
    sources = restore.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise ExtractionError("project.assets.json has no restore sources metadata")
    if not all(
        isinstance(source, str)
        and source
        and isinstance(details, dict)
        for source, details in sources.items()
    ):
        raise ExtractionError(
            "project.assets.json restore sources must map source identifiers to objects"
        )
    restore_metadata = {
        "packages_path": normalized_packages_path,
        "package_folders": normalized_package_folders,
        "config_file_paths": normalized_config_file_paths,
        "sources": sorted(sources),
    }
    restore_frameworks = restore.get("frameworks")
    if (
        not isinstance(restore_frameworks, dict)
        or set(restore_frameworks) != {target_framework}
    ):
        raise ExtractionError(
            "project.assets.json restore framework set differs from the source "
            f"baseline; observed="
            f"{sorted(restore_frameworks) if isinstance(restore_frameworks, dict) else None}, "
            f"expected={[target_framework]}"
        )
    restore_framework = (
        restore_frameworks.get(target_framework)
        if isinstance(restore_frameworks, dict)
        else None
    )
    project_references = (
        restore_framework.get("projectReferences")
        if isinstance(restore_framework, dict)
        else None
    )
    if not isinstance(project_references, dict):
        raise ExtractionError(
            "project.assets.json has no direct project-reference metadata for "
            f"{target_framework}"
        )
    baseline_target_ids_by_absolute_path = {
        normalize_absolute_path(
            f"{checkout_root.rstrip('/')}/{target_record['project_path']}",
            windows,
        ): target_record["id"]
        for target_record in baseline["attempted_targets"]
    }
    direct_project_target_ids: set[str] = set()
    for key, details in project_references.items():
        reference_path = details.get("projectPath") if isinstance(details, dict) else None
        if not isinstance(reference_path, str) or not reference_path:
            raise ExtractionError(
                f"direct project reference {key} has no projectPath"
            )
        normalized_key_path = normalize_absolute_path(key, windows)
        normalized_reference_path = normalize_absolute_path(reference_path, windows)
        if normalized_key_path != normalized_reference_path:
            raise ExtractionError(
                f"direct project-reference key {key} differs from projectPath "
                f"{reference_path}"
            )
        referenced_target_id = baseline_target_ids_by_absolute_path.get(
            normalized_reference_path
        )
        if referenced_target_id is None:
            raise ExtractionError(
                f"direct project reference is outside the source baseline: "
                f"{reference_path}"
            )
        if referenced_target_id in direct_project_target_ids:
            raise ExtractionError(
                f"duplicate direct project reference {referenced_target_id}"
            )
        direct_project_target_ids.add(referenced_target_id)
    if direct_project_target_ids != set(target["project_references"]):
        raise ExtractionError(
            "project.assets.json direct project-reference set differs from the "
            f"source baseline; observed={sorted(direct_project_target_ids)}, "
            f"expected={sorted(target['project_references'])}"
        )
    target_graphs = assets.get("targets")
    if (
        not isinstance(target_graphs, dict)
        or set(target_graphs) != {assets_target}
    ):
        raise ExtractionError(
            "project.assets.json target framework set differs from the source "
            f"baseline; observed="
            f"{sorted(target_graphs) if isinstance(target_graphs, dict) else None}, "
            f"expected={[assets_target]}"
        )
    if not isinstance(target_graphs.get(assets_target), dict):
        raise ExtractionError(
            f"project.assets.json has no target graph named {assets_target}"
        )
    target_graph = target_graphs[assets_target]

    libraries = assets.get("libraries")
    if not isinstance(libraries, dict):
        raise ExtractionError("project.assets.json has no libraries object")
    libraries_by_identity: dict[str, tuple[str, Any]] = {}
    for library_key, library in libraries.items():
        library_identity = library_key.casefold()
        if library_identity in libraries_by_identity:
            raise ExtractionError(
                f"project.assets.json contains duplicate library identity {library_key}"
            )
        libraries_by_identity[library_identity] = (library_key, library)

    nodes: list[dict[str, str]] = []
    nodes_by_package: dict[str, dict[str, str]] = {}
    nodes_by_dependency_id: dict[str, dict[str, str]] = {}
    nodes_by_library_key: dict[str, dict[str, str]] = {}
    project_target_ids: set[str] = set()
    baseline_target_ids_by_path = {
        target_record["project_path"]: target_record["id"]
        for target_record in baseline["attempted_targets"]
    }
    for library_key, details in target_graph.items():
        if not isinstance(details, dict):
            raise ExtractionError(
                f"project.assets.json target entry {library_key} is not an object"
            )
        library_record = libraries_by_identity.get(library_key.casefold())
        if library_record is None:
            raise ExtractionError(
                f"project.assets.json has no library metadata for {library_key}"
            )
        _, library = library_record
        if not isinstance(library, dict):
            raise ExtractionError(
                f"project.assets.json library metadata for {library_key} is not "
                "an object"
            )
        target_library_type = details.get("type")
        metadata_library_type = library.get("type")
        if target_library_type is not None and not isinstance(
            target_library_type, str
        ):
            raise ExtractionError(
                f"project.assets.json target type for {library_key} is not a string"
            )
        if metadata_library_type is not None and not isinstance(
            metadata_library_type, str
        ):
            raise ExtractionError(
                f"project.assets.json library type for {library_key} is not a string"
            )
        if (
            target_library_type is not None
            and metadata_library_type is not None
            and target_library_type != metadata_library_type
        ):
            raise ExtractionError(
                f"target and library types differ for {library_key}"
            )
        library_type = target_library_type or metadata_library_type
        if library_type not in {"package", "project"}:
            raise ExtractionError(
                f"project.assets.json has unsupported library type for {library_key}"
            )
        package_id, version = split_library_key(library_key)
        dependency_key = package_id.casefold()
        if dependency_key in nodes_by_dependency_id:
            raise ExtractionError(
                f"target {assets_target} has ambiguous dependency identity {package_id}"
            )
        if library_type == "package":
            node = {
                "node_id": f"node-{slug(package_id)}-{slug(version)}",
                "id": package_id,
                "kind": "package",
                "version": version,
                "baseline_target_id": None,
            }
            if dependency_key in nodes_by_package:
                raise ExtractionError(
                    f"target {assets_target} resolves multiple versions of {package_id}"
                )
            nodes_by_package[dependency_key] = node
        else:
            if not isinstance(library, dict):
                raise ExtractionError(
                    f"project.assets.json has no library metadata for {library_key}"
                )
            project_reference_values = [
                value
                for value in (
                    library.get("msbuildProject"),
                    library.get("path"),
                )
                if value is not None
            ]
            if any(
                not isinstance(value, str) or not value
                for value in project_reference_values
            ) or not project_reference_values:
                raise ExtractionError(
                    f"project library {library_key} has no MSBuild project path"
                )
            resolved_project_paths = {
                resolve_project_reference_path(
                    target["project_path"],
                    project_reference,
                )
                for project_reference in project_reference_values
            }
            if len(resolved_project_paths) != 1:
                raise ExtractionError(
                    f"project library {library_key} has contradictory project paths"
                )
            resolved_project_path = next(iter(resolved_project_paths))
            baseline_target_id = baseline_target_ids_by_path.get(resolved_project_path)
            if baseline_target_id is None:
                raise ExtractionError(
                    f"project library {library_key} maps outside the source baseline: "
                    f"{resolved_project_path}"
                )
            if baseline_target_id in project_target_ids:
                raise ExtractionError(
                    f"target {assets_target} contains duplicate project "
                    f"{baseline_target_id}"
                )
            project_target_ids.add(baseline_target_id)
            node = {
                "node_id": f"node-project-{slug(baseline_target_id)}",
                "id": package_id,
                "kind": "project",
                "version": version,
                "baseline_target_id": baseline_target_id,
            }
        nodes.append(node)
        nodes_by_dependency_id[dependency_key] = node
        nodes_by_library_key[library_key] = node

    if project_target_ids != expected_project_target_ids:
        raise ExtractionError(
            "project.assets.json project-node closure differs from the source baseline; "
            f"observed={sorted(project_target_ids)}, "
            f"expected={sorted(expected_project_target_ids)}"
        )

    node_ids = [node["node_id"] for node in nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ExtractionError("derived package node identifiers are not unique")

    frameworks = project.get("frameworks") if isinstance(project, dict) else None
    if (
        not isinstance(frameworks, dict)
        or set(frameworks) != {target["target_framework"]}
    ):
        raise ExtractionError(
            "project.assets.json project framework set differs from the source "
            f"baseline; observed="
            f"{sorted(frameworks) if isinstance(frameworks, dict) else None}, "
            f"expected={[target['target_framework']]}"
        )
    framework = (
        frameworks.get(target["target_framework"])
        if isinstance(frameworks, dict)
        else None
    )
    direct_dependencies = (
        framework.get("dependencies") if isinstance(framework, dict) else None
    )
    if not isinstance(direct_dependencies, dict):
        raise ExtractionError(
            "project.assets.json does not expose direct dependencies for "
            f"{target['target_framework']}"
        )
    direct_dependency_identities: set[str] = set()
    for dependency_id, value in direct_dependencies.items():
        dependency_identity = dependency_id.casefold()
        if dependency_identity in direct_dependency_identities:
            raise ExtractionError(
                "project.assets.json contains case-insensitive duplicate direct "
                f"dependency {dependency_id}"
            )
        direct_dependency_identities.add(dependency_identity)
        if isinstance(value, dict) and value.get("target") not in {
            None,
            "Package",
            "Project",
        }:
            raise ExtractionError(
                f"direct dependency {dependency_id} has unsupported target "
                f"{value.get('target')!r}"
            )

    def applicable_package_declarations(
        baseline_target_id: str,
    ) -> list[dict[str, Any]]:
        return [
            declaration
            for declaration in baseline["source_declared_direct"]
            if declaration["kind"] == "package"
            and declaration["targets"] == [baseline_target_id]
            and condition_applies(declaration["condition"], runtime_identifier)
        ]

    baseline_declarations = applicable_package_declarations(target_id)
    declarations_by_package = {
        declaration["id"].casefold(): declaration
        for declaration in baseline_declarations
    }
    if len(declarations_by_package) != len(baseline_declarations):
        raise ExtractionError(
            f"source baseline has ambiguous applicable package declarations for {target_id}"
        )

    direct_package_constraints: dict[str, str] = {}
    for package_id, value in direct_dependencies.items():
        if isinstance(value, dict) and value.get("target") not in {None, "Package"}:
            continue
        direct_package_constraints[package_id.casefold()] = dependency_constraint(
            value,
            f"direct dependency {package_id}",
        )
    if set(direct_package_constraints) != set(declarations_by_package):
        missing = sorted(set(declarations_by_package) - set(direct_package_constraints))
        unexpected = sorted(
            set(direct_package_constraints) - set(declarations_by_package)
        )
        raise ExtractionError(
            f"project.assets.json direct package set differs from the source baseline; "
            f"missing={missing}, unexpected={unexpected}"
        )
    for package_key, declaration in declarations_by_package.items():
        if not direct_constraint_matches_source(
            direct_package_constraints[package_key],
            declaration["version_constraint"],
        ):
            raise ExtractionError(
                f"project.assets.json direct constraint for {declaration['id']} "
                f"differs from source declaration {declaration['version_constraint']}"
            )

    direct_project_constraints: dict[str, tuple[dict[str, str], str]] = {}
    for project_id, value in direct_dependencies.items():
        if not isinstance(value, dict) or value.get("target") != "Project":
            continue
        node = nodes_by_dependency_id.get(project_id.casefold())
        if node is None or node["kind"] != "project":
            raise ExtractionError(
                f"direct project dependency {project_id} has no mapped project node"
            )
        baseline_target_id = node["baseline_target_id"]
        if baseline_target_id in direct_project_constraints:
            raise ExtractionError(
                f"duplicate direct project dependency {baseline_target_id}"
            )
        direct_project_constraints[baseline_target_id] = (
            node,
            dependency_constraint(
                value,
                f"direct project dependency {project_id}",
            ),
        )
    if set(direct_project_constraints) != direct_project_target_ids:
        raise ExtractionError(
            "project.assets.json direct project dependency set differs from its "
            "project-reference metadata"
        )
    for baseline_target_id, (
        node,
        constraint,
    ) in direct_project_constraints.items():
        if not nuget_version_satisfies_constraint(node["version"], constraint):
            raise ExtractionError(
                f"direct project dependency {baseline_target_id} constraint "
                f"{constraint} does not admit project version {node['version']}"
            )

    edges: list[dict[str, Any]] = []
    for package_key, declaration in declarations_by_package.items():
        node = nodes_by_package.get(package_key)
        if node is None:
            raise ExtractionError(
                f"project.assets.json does not resolve direct package "
                f"{declaration['id']}"
            )
        if not nuget_version_satisfies_constraint(
            node["version"],
            direct_package_constraints[package_key],
        ):
            raise ExtractionError(
                f"project.assets.json resolves direct package {declaration['id']} "
                f"at {node['version']}, outside constraint "
                f"{direct_package_constraints[package_key]}"
            )
        edges.append(
            {
                "edge_id": f"edge-root-{slug(declaration['declaration_id'])}",
                "from_node_id": None,
                "to_node_id": node["node_id"],
                "version_constraint": declaration["version_constraint"],
                "declaration_ids": [declaration["declaration_id"]],
            }
        )

    for library_key, node in nodes_by_library_key.items():
        details = target_graph[library_key]
        dependencies = details.get("dependencies", {})
        if not isinstance(dependencies, dict):
            raise ExtractionError(
                f"package {library_key} dependencies must be an object"
            )
        for package_id, value in dependencies.items():
            child = nodes_by_dependency_id.get(package_id.casefold())
            if child is None:
                raise ExtractionError(
                    f"package {library_key} references unresolved package {package_id}"
                )
            if isinstance(value, dict) and value.get("target") is not None:
                expected_target = (
                    "Project" if child["kind"] == "project" else "Package"
                )
                if value["target"] != expected_target:
                    raise ExtractionError(
                        f"dependency {library_key} -> {package_id} declares target "
                        f"{value['target']} but resolves a {child['kind']} node"
                    )
            constraint = dependency_constraint(
                value,
                f"dependency {library_key} -> {package_id}",
            )
            if not nuget_version_satisfies_constraint(
                child["version"],
                constraint,
            ):
                raise ExtractionError(
                    f"dependency {library_key} -> {package_id} constraint "
                    f"{constraint} does not admit resolved version {child['version']}"
                )
            edges.append(
                {
                    "edge_id": (
                        f"edge-{slug(node['node_id'])}-{slug(child['node_id'])}"
                    ),
                    "from_node_id": node["node_id"],
                    "to_node_id": child["node_id"],
                    "version_constraint": constraint,
                    "declaration_ids": [],
                }
            )

    for library_key, node in nodes_by_library_key.items():
        if node["kind"] != "project":
            continue
        details = target_graph[library_key]
        dependencies = details.get("dependencies", {})
        observed_package_constraints: dict[str, str] = {}
        for package_id, value in dependencies.items():
            child = nodes_by_dependency_id[package_id.casefold()]
            if child["kind"] != "package":
                continue
            observed_package_constraints[package_id.casefold()] = (
                dependency_constraint(
                    value,
                    f"project dependency {library_key} -> {package_id}",
                )
            )
        project_declarations = applicable_package_declarations(
            node["baseline_target_id"]
        )
        declarations_by_package = {
            declaration["id"].casefold(): declaration
            for declaration in project_declarations
        }
        if len(declarations_by_package) != len(project_declarations):
            raise ExtractionError(
                "source baseline has ambiguous applicable package declarations for "
                f"{node['baseline_target_id']}"
            )
        if set(observed_package_constraints) != set(declarations_by_package):
            missing = sorted(
                set(declarations_by_package) - set(observed_package_constraints)
            )
            unexpected = sorted(
                set(observed_package_constraints) - set(declarations_by_package)
            )
            raise ExtractionError(
                f"project node {node['baseline_target_id']} package edges differ "
                f"from the source baseline; missing={missing}, "
                f"unexpected={unexpected}"
            )
        for package_key, declaration in declarations_by_package.items():
            if not direct_constraint_matches_source(
                observed_package_constraints[package_key],
                declaration["version_constraint"],
            ):
                raise ExtractionError(
                    f"project node {node['baseline_target_id']} constraint for "
                    f"{declaration['id']} differs from source declaration "
                    f"{declaration['version_constraint']}"
                )

    nodes_by_id = {node["node_id"]: node for node in nodes}
    project_children_by_target: dict[str, set[str]] = {
        project_target_id: set()
        for project_target_id in expected_project_target_ids
    }
    for edge in edges:
        if edge["from_node_id"] is None:
            continue
        parent = nodes_by_id[edge["from_node_id"]]
        child = nodes_by_id[edge["to_node_id"]]
        if parent["kind"] == "package" and child["kind"] == "project":
            raise ExtractionError(
                f"package {parent['id']} cannot depend on project {child['id']}"
            )
        if parent["kind"] == "project" and child["kind"] == "project":
            project_children_by_target[parent["baseline_target_id"]].add(
                child["baseline_target_id"]
            )
    for project_target_id in expected_project_target_ids:
        expected_children = set(
            targets_by_id[project_target_id]["project_references"]
        )
        observed_children = project_children_by_target[project_target_id]
        if observed_children != expected_children:
            raise ExtractionError(
                f"project node {project_target_id} project-reference edges differ "
                f"from the source baseline; observed={sorted(observed_children)}, "
                f"expected={sorted(expected_children)}"
            )

    reachable_node_ids = {
        edge["to_node_id"] for edge in edges if edge["from_node_id"] is None
    }
    reachable_node_ids.update(
        node["node_id"] for node, _constraint in direct_project_constraints.values()
    )
    children_by_node: dict[str, set[str]] = {}
    for edge in edges:
        if edge["from_node_id"] is None:
            continue
        children_by_node.setdefault(edge["from_node_id"], set()).add(
            edge["to_node_id"]
        )
    pending = list(reachable_node_ids)
    while pending:
        parent_id = pending.pop()
        for child_id in children_by_node.get(parent_id, set()):
            if child_id in reachable_node_ids:
                continue
            reachable_node_ids.add(child_id)
            pending.append(child_id)
    unreachable_node_ids = sorted(set(nodes_by_id) - reachable_node_ids)
    if unreachable_node_ids:
        raise ExtractionError(
            "project.assets.json selected target contains unreachable dependency "
            f"nodes: {unreachable_node_ids}"
        )

    edge_ids = [edge["edge_id"] for edge in edges]
    if len(edge_ids) != len(set(edge_ids)):
        raise ExtractionError("derived dependency edge identifiers are not unique")

    projection = {
        "format_version": 1,
        "assets_target": assets_target,
        "restore_metadata": restore_metadata,
        "nodes": sorted(nodes, key=lambda node: node["node_id"]),
        "edges": sorted(edges, key=lambda edge: edge["edge_id"]),
    }
    return {
        "target_id": target_id,
        "assets_file_sha256": hashlib.sha256(assets_bytes).hexdigest(),
        "assets_projection": projection,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Extract the Issue #1 package topology projection from project.assets.json"
        )
    )
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--runtime-identifier", required=True)
    parser.add_argument("--assets-target", required=True)
    parser.add_argument("--checkout-root", required=True)
    args = parser.parse_args()

    try:
        assets_bytes = args.assets.read_bytes()
        assets = parse_json_object_bytes(assets_bytes, str(args.assets))
        projection = extract_projection(
            assets,
            assets_bytes,
            load_json(BASELINE_PATH),
            args.target_id,
            args.runtime_identifier,
            args.assets_target,
            args.checkout_root,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ExtractionError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(json.dumps(projection, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
