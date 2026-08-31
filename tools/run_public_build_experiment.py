#!/usr/bin/env python3
from __future__ import annotations

import argparse
import codecs
import copy
import ctypes
import errno
import hashlib
import json
import math
import os
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, NoReturn, Sequence

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
    DIRECTORY_PACKAGES_PROPS_CONTENT,
    DOTNET_ENVIRONMENT_KEYS,
    DOTNET_SDK_VERSION,
    DISCOVERY_PASS_TIMEOUT,
    FAILURE_REASON_SEPARATOR,
    GLOBAL_SAFETY_TERMINATIONS,
    GIT_ENVIRONMENT_KEYS,
    LATE_CAPTURE_FAILURE_REASON,
    MISE_ENVIRONMENT_KEYS,
    MISE_EXECUTABLE_SHA256,
    MISE_TOOL_NAME,
    MISE_VERSION,
    MAX_DISCOVERED_PROCESSES,
    REPLACEMENT_ENVIRONMENT_KEYS,
    SENSITIVE_DETECTION_PATTERNS,
    SOURCE_AGGREGATE_LIMIT,
    SOURCE_ELAPSED_TIMEOUT,
    SOURCE_MAX_ENTRIES,
    SOURCE_PER_FILE_LIMIT,
    SOURCE_INTEGRITY_CHANGED_MARKER,
    PREPARATION_BY_ID,
    append_failure_reason_marker,
    dependency_asset_path,
    has_failure_reason_marker,
    reduce_runtime,
    supervision_ceilings,
)
from public_build_validation import (
    PUBLIC_BUILD_LASSO_MANIFEST_PATH,
    PUBLIC_BUILD_SOURCE_BASELINE_PATH,
    canonical_json_bytes,
    load_validated_mise_lock_bytes,
    receipt_digest,
    validate_public_build_bundle_instance,
)


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_WRITE_ROOT = ROOT
ROOT_MARKER = ".public-build-root.json"
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
SYS_PIDFD_SEND_SIGNAL_X86_64 = 424
SYS_PIDFD_OPEN_X86_64 = 434
SYS_RENAMEAT2_X86_64 = 316
RENAME_EXCHANGE = 2
RENAME_NOREPLACE = 1
CAPTURE_CHUNK = 64 * 1024
EXCERPT_LIMIT = 16 * 1024
RETAINED_OUTPUT = "retained-sanitized"
SUPPRESSED_SOURCE_FAITHFUL_OUTPUT = "suppressed-source-faithful"
UNVERIFIABLE_OUTPUT = "capture-unverifiable"
STABLE_SCAN_COUNT = 3
STABLE_SCAN_DELAY = 0.02
ASSETS_DIRECTORY = ROOT / "docs/research/experiments/assets"
CANONICAL_BUNDLE_PATH = (
    ROOT
    / "docs/research/experiments/public-build-linux-x64-dotnet-8-0-424-01.json"
)
SENSITIVE_OUTPUT = (
    re.compile(r"(?i)(authorization\s*:\s*)(?:bearer|basic)\s+\S+"),
    re.compile(
        r"(?i)\b(password|passwd|token|secret|apikey|api_key|access_token|"
        r"refresh_token|client_secret)\s*[:=]([^\s&]+)"
    ),
    re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"),
)
SENSITIVE_OUTPUT_DETECTION = tuple(
    re.compile(pattern) for pattern in SENSITIVE_DETECTION_PATTERNS
)


class ValidationError(ValueError):
    pass


class CapabilityError(RuntimeError):
    pass


class RootCreationError(RuntimeError):
    def __init__(self, message: str, *, partial_identity: Any | None = None):
        super().__init__(message)
        self.partial_identity = partial_identity


class QuiescenceError(RuntimeError):
    pass


class CaptureError(RuntimeError):
    pass


class CaptureInitializationError(CaptureError):
    pass


class AssetPublicationError(RuntimeError):
    pass


class RecordingError(RuntimeError):
    def __init__(self, message: str, *, committed: bool = False):
        super().__init__(message)
        self.committed = committed


class RecordingRetry(RuntimeError):
    def __init__(
        self,
        reason: str,
        *,
        capture_groups: Sequence[RetainedCaptureGroup] = (),
    ):
        super().__init__(reason)
        self.reason = reason
        self.capture_groups = tuple(capture_groups)


@dataclass
class CanonicalBundleIdentity:
    canonical_path: Path
    descriptor: int
    parent_descriptor: int
    parent_device: int
    parent_inode: int
    basename: str
    device: int
    inode: int
    sha256: str


@dataclass
class CheckoutIdentity:
    canonical_path: Path
    descriptor: int
    device: int
    inode: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def _reject_constant(value: str) -> NoReturn:
    raise ValidationError(f"non-finite JSON number is not permitted: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _require_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationError("non-finite JSON number is not permitted")
    if isinstance(value, dict):
        for child in value.values():
            _require_finite(child)
    elif isinstance(value, list):
        for child in value:
            _require_finite(child)


def load_strict_json(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValidationError(f"cannot read strict JSON from {path}: {error}") from error
    return _load_strict_json_text(text, str(path))


def _load_strict_json_text(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as error:
        raise ValidationError(f"cannot read strict JSON from {label}: {error}") from error
    _require_finite(value)
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must contain a JSON object")
    return value


def _repository_relative_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(REPOSITORY_WRITE_ROOT)
    except ValueError as error:
        raise ValidationError(f"repository path is outside the pinned root: {path}") from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValidationError(f"repository path is not canonical: {path}")
    return relative


def _open_repository_parent(
    path: Path,
    *,
    create: bool = False,
    created_mode: int = 0o755,
) -> tuple[int, os.stat_result, str]:
    relative = _repository_relative_path(path)
    current = os.open(REPOSITORY_WRITE_ROOT, _directory_flags())
    try:
        for component in relative.parts[:-1]:
            created = False
            try:
                child = os.open(component, _directory_flags(), dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, created_mode, dir_fd=current)
                created = True
                os.fsync(current)
                child = os.open(component, _directory_flags(), dir_fd=current)
            if create and not created:
                os.fsync(current)
            os.close(current)
            current = child
        metadata = _verify_directory_fd(current, path.parent)
        return current, metadata, relative.name
    except BaseException:
        os.close(current)
        raise


def _open_canonical_bundle(path: Path) -> tuple[dict[str, Any], CanonicalBundleIdentity]:
    if Path(os.path.abspath(path)) != CANONICAL_BUNDLE_PATH:
        raise ValidationError(
            f"production run requires canonical bundle path {CANONICAL_BUNDLE_PATH}"
        )
    parent_descriptor, parent_metadata, basename = _open_repository_parent(path)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(basename, flags, dir_fd=parent_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("canonical bundle is not a regular file")
        chunks: list[bytes] = []
        offset = 0
        while chunk := os.pread(descriptor, CAPTURE_CHUNK, offset):
            chunks.append(chunk)
            offset += len(chunk)
        payload = b"".join(chunks)
        bundle = _load_strict_json_text(
            payload.decode("utf-8", errors="strict"),
            str(path),
        )
        identity = CanonicalBundleIdentity(
            canonical_path=Path(os.path.abspath(path)),
            descriptor=descriptor,
            parent_descriptor=parent_descriptor,
            parent_device=parent_metadata.st_dev,
            parent_inode=parent_metadata.st_ino,
            basename=basename,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        return bundle, identity
    except (OSError, UnicodeError, ValidationError):
        os.close(descriptor)
        os.close(parent_descriptor)
        raise


def _verify_canonical_parent_binding(identity: CanonicalBundleIdentity) -> None:
    parent = os.fstat(identity.parent_descriptor)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_dev != identity.parent_device
        or parent.st_ino != identity.parent_inode
    ):
        raise ValidationError("canonical bundle parent identity changed during execution")
    current_parent, current_metadata, basename = _open_repository_parent(
        identity.canonical_path
    )
    try:
        if (
            basename != identity.basename
            or current_metadata.st_dev != identity.parent_device
            or current_metadata.st_ino != identity.parent_inode
        ):
            raise ValidationError(
                "live canonical bundle parent binding changed during execution"
            )
    finally:
        os.close(current_parent)


def _verify_canonical_bundle_identity(identity: CanonicalBundleIdentity) -> None:
    _verify_canonical_parent_binding(identity)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    current = os.open(
        identity.basename,
        flags,
        dir_fd=identity.parent_descriptor,
    )
    try:
        metadata = os.fstat(current)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_dev != identity.device
            or metadata.st_ino != identity.inode
            or _descriptor_sha256(identity.descriptor) != identity.sha256
            or _descriptor_sha256(current) != identity.sha256
        ):
            raise ValidationError(
                "canonical planned bundle identity or content changed during execution"
            )
    finally:
        os.close(current)


def _path_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CAPTURE_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _descriptor_sha256(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while chunk := os.pread(descriptor, CAPTURE_CHUNK, offset):
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()




def validate_bundle(
    bundle: dict[str, Any],
    *,
    allow_recorded: bool = True,
) -> tuple[dict[str, Any], bytes]:
    if not isinstance(bundle, dict):
        raise ValidationError("bundle must be a JSON object")
    status = bundle.get("status")
    if status not in {"planned", "recorded"}:
        raise ValidationError("bundle status must be planned or recorded")
    if status == "recorded" and not allow_recorded:
        raise ValidationError("this operation requires a planned bundle")
    baseline = load_strict_json(ROOT / PUBLIC_BUILD_SOURCE_BASELINE_PATH)
    lasso_manifest = load_strict_json(ROOT / PUBLIC_BUILD_LASSO_MANIFEST_PATH)
    errors = validate_public_build_bundle_instance(
        bundle,
        f"{status} bundle",
        baseline=baseline,
        lasso_manifest=lasso_manifest,
    )
    if errors:
        raise ValidationError(errors[0])
    try:
        mise_lock_bytes = load_validated_mise_lock_bytes(
            bundle,
            f"{status} bundle",
        )
    except ExtractionError as error:
        raise ValidationError(str(error)) from error
    return baseline, mise_lock_bytes


def detect_wsl(
    kernel_release: str | None = None,
    interop_path: Path = Path("/proc/sys/fs/binfmt_misc/WSLInterop"),
) -> bool:
    release = kernel_release if kernel_release is not None else platform.release()
    if "microsoft" in release.casefold() or "wsl" in release.casefold():
        return True
    try:
        first_line = interop_path.read_text(encoding="utf-8").splitlines()[0]
    except FileNotFoundError:
        return False
    except (OSError, UnicodeError) as error:
        raise CapabilityError(f"cannot inspect WSL interop state: {error}") from error
    except IndexError:
        return False
    return first_line.strip().casefold() == "enabled"


def require_native_linux_x64(
    *,
    system: str | None = None,
    machine: str | None = None,
    kernel_release: str | None = None,
    interop_path: Path = Path("/proc/sys/fs/binfmt_misc/WSLInterop"),
) -> None:
    detected_system = system if system is not None else platform.system()
    detected_machine = machine if machine is not None else platform.machine()
    if detected_system != "Linux":
        raise CapabilityError("activation v1 supports only native Linux")
    if detected_machine not in {"x86_64", "AMD64"}:
        raise CapabilityError("activation v1 supports only Linux x64")
    if detect_wsl(kernel_release, interop_path):
        raise CapabilityError("activation v1 does not support WSL")


@dataclass(frozen=True)
class ExecutableIdentity:
    path: Path
    sha256: str
    owner: int
    mode: int
    descriptor: int


def verify_mise_executable(
    executable: Path,
    *,
    expected_sha256: str = MISE_EXECUTABLE_SHA256,
) -> ExecutableIdentity:
    descriptor: int | None = None
    try:
        resolved = executable.resolve(strict=True)
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(resolved, flags)
        metadata = os.fstat(descriptor)
    except (OSError, ValueError) as error:
        if descriptor is not None:
            os.close(descriptor)
        raise CapabilityError(f"cannot resolve mise executable: {error}") from error
    try:
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISREG(metadata.st_mode):
            raise CapabilityError("resolved mise executable is not a regular file")
        if metadata.st_uid != os.getuid():
            raise CapabilityError("resolved mise executable is not owned by the current user")
        if mode & 0o022:
            raise CapabilityError(
                "resolved mise executable is writable by its group or by other users"
            )
        if not mode & 0o100:
            raise CapabilityError("resolved mise executable is not owner-executable")
        actual_sha256 = _descriptor_sha256(descriptor)
        if actual_sha256 != expected_sha256:
            raise CapabilityError(
                "resolved mise executable hash differs from the reviewed digest"
            )
        return ExecutableIdentity(
            path=resolved,
            sha256=actual_sha256,
            owner=metadata.st_uid,
            mode=mode,
            descriptor=descriptor,
        )
    except (CapabilityError, OSError) as error:
        os.close(descriptor)
        if isinstance(error, CapabilityError):
            raise
        raise CapabilityError(f"cannot inspect mise executable: {error}") from error


def resolve_mise_executable(
    path_environment: str | None,
    expected_sha256: str = MISE_EXECUTABLE_SHA256,
) -> ExecutableIdentity:
    candidate = shutil.which("mise", path=path_environment)
    if candidate is None:
        raise CapabilityError("fixed runner requires an ambient mise executable")
    return verify_mise_executable(Path(candidate), expected_sha256=expected_sha256)


@dataclass(frozen=True)
class RootIdentity:
    path: Path
    device: int | None
    inode: int | None
    marker_device: int | None
    marker_inode: int | None
    marker_sha256: str | None
    initialized: bool


@dataclass
class CaptureIdentity:
    path: Path
    directory_descriptor: int
    directory_device: int
    directory_inode: int
    leaf_device: int
    leaf_inode: int
    leaf_size: int | None = None
    leaf_sha256: str | None = None

    def close(self) -> None:
        if self.directory_descriptor >= 0:
            os.close(self.directory_descriptor)
            self.directory_descriptor = -1


@dataclass
class RetainedCaptureGroup:
    subject_kind: str
    subject_id: str
    attempt: dict[str, Any]
    identities: tuple[CaptureIdentity, CaptureIdentity]
    invalidated: bool = False

    def close(self) -> None:
        for identity in self.identities:
            identity.close()


@dataclass(frozen=True)
class RestoreAssetSnapshot:
    present: bool
    sha256: str | None
    failure_reason: str | None


@dataclass
class PublishedAssetIdentity:
    path: Path
    directory_descriptor: int
    directory_device: int
    directory_inode: int
    filename: str
    device: int
    inode: int
    sha256: str

    def close(self) -> None:
        if self.directory_descriptor >= 0:
            os.close(self.directory_descriptor)
            self.directory_descriptor = -1


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _verify_directory_fd(
    descriptor: int,
    label: Path,
    *,
    owner: int | None = None,
    mode: int | None = None,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise RootCreationError(f"untrusted path component: {label}")
    if owner is not None and metadata.st_uid != owner:
        raise RootCreationError(f"unexpected owner for {label}")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise RootCreationError(f"unexpected mode for {label}")
    return metadata


def _open_child_directory(parent: int, name: str, label: Path) -> int:
    try:
        return os.open(name, _directory_flags(), dir_fd=parent)
    except OSError as error:
        raise RootCreationError(f"cannot safely open {label}: {error}") from error


def _open_repository_or_absolute_parent(
    path: Path,
) -> tuple[int, os.stat_result, str]:
    absolute = Path(os.path.abspath(path))
    try:
        return _open_repository_parent(absolute)
    except ValidationError:
        pass
    current = os.open("/", _directory_flags())
    current_path = Path("/")
    try:
        for component in absolute.parts[1:-1]:
            current_path /= component
            child = os.open(component, _directory_flags(), dir_fd=current)
            os.close(current)
            current = child
        return current, _verify_directory_fd(current, absolute.parent), absolute.name
    except BaseException:
        os.close(current)
        raise


def _is_under_var_tmp(path: Path) -> bool:
    try:
        path.relative_to("/var/tmp")
    except ValueError:
        return False
    return True


def _write_root_marker(leaf_descriptor: int, payload: bytes) -> os.stat_result:
    marker_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        marker_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        marker_flags |= os.O_NOFOLLOW
    marker_descriptor = os.open(
        ROOT_MARKER,
        marker_flags,
        0o600,
        dir_fd=leaf_descriptor,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(marker_descriptor, payload[offset:])
        os.fsync(marker_descriptor)
        return os.fstat(marker_descriptor)
    finally:
        os.close(marker_descriptor)


def create_exclusive_root(
    root: Path,
    trusted_base: Path,
    marker: dict[str, Any],
) -> RootIdentity:
    root = Path(os.path.abspath(root))
    trusted_base = Path(os.path.abspath(trusted_base))
    if root.parent != trusted_base:
        raise RootCreationError("experiment root must be a direct child of its trusted base")
    root_fd = os.open("/", _directory_flags())
    current_fd = root_fd
    opened: list[int] = []
    current_path = Path("/")
    production_base = _is_under_var_tmp(trusted_base)
    try:
        for component in trusted_base.parts[1:]:
            current_path /= component
            try:
                child_fd = os.open(component, _directory_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                if not production_base or not _is_under_var_tmp(current_path):
                    raise RootCreationError(
                        f"trusted base component does not exist: {current_path}"
                    )
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError as error:
                    raise RootCreationError(
                        f"cannot create trusted base component {current_path}: {error}"
                    ) from error
                child_fd = _open_child_directory(current_fd, component, current_path)
            except OSError as error:
                raise RootCreationError(
                    f"cannot safely open trusted base component {current_path}: {error}"
                ) from error
            opened.append(child_fd)
            current_fd = child_fd
            if current_path in {Path("/"), Path("/var"), Path("/var/tmp")}:
                metadata = _verify_directory_fd(current_fd, current_path)
                if current_path == Path("/var/tmp") and (
                    metadata.st_uid != 0
                    or stat.S_IMODE(metadata.st_mode) != 0o1777
                ):
                    raise RootCreationError("/var/tmp must be root-owned mode 1777")
            elif production_base:
                _verify_directory_fd(
                    current_fd,
                    current_path,
                    owner=os.getuid(),
                    mode=0o700,
                )
        _verify_directory_fd(
            current_fd,
            trusted_base,
            owner=os.getuid(),
            mode=0o700,
        )
        leaf = root.name
        try:
            os.mkdir(leaf, 0o700, dir_fd=current_fd)
        except FileExistsError as error:
            raise RootCreationError(f"experiment root already exists: {root}") from error
        except OSError as error:
            raise RootCreationError(f"cannot create experiment root {root}: {error}") from error
        partial = RootIdentity(
            path=root,
            device=None,
            inode=None,
            marker_device=None,
            marker_inode=None,
            marker_sha256=None,
            initialized=False,
        )
        try:
            root_metadata = os.stat(
                leaf,
                dir_fd=current_fd,
                follow_symlinks=False,
            )
            partial = RootIdentity(
                path=root,
                device=root_metadata.st_dev,
                inode=root_metadata.st_ino,
                marker_device=None,
                marker_inode=None,
                marker_sha256=None,
                initialized=False,
            )
            leaf_fd = _open_child_directory(current_fd, leaf, root)
            opened.append(leaf_fd)
            root_metadata = _verify_directory_fd(
                leaf_fd,
                root,
                owner=os.getuid(),
                mode=0o700,
            )
            payload = canonical_json_bytes(marker) + b"\n"
            marker_metadata = _write_root_marker(leaf_fd, payload)
            if (
                not stat.S_ISREG(marker_metadata.st_mode)
                or marker_metadata.st_uid != os.getuid()
                or stat.S_IMODE(marker_metadata.st_mode) != 0o600
            ):
                raise RootCreationError(f"untrusted root marker in {root}")
            marker_flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                marker_flags |= os.O_NOFOLLOW
            marker_descriptor = os.open(
                ROOT_MARKER,
                marker_flags,
                dir_fd=leaf_fd,
            )
            try:
                if _descriptor_sha256(marker_descriptor) != hashlib.sha256(payload).hexdigest():
                    raise RootCreationError(
                        f"root marker content differs after initialization in {root}"
                    )
            finally:
                os.close(marker_descriptor)
            os.fsync(leaf_fd)
            return RootIdentity(
                path=root,
                device=root_metadata.st_dev,
                inode=root_metadata.st_ino,
                marker_device=marker_metadata.st_dev,
                marker_inode=marker_metadata.st_ino,
                marker_sha256=hashlib.sha256(payload).hexdigest(),
                initialized=True,
            )
        except RootCreationError as error:
            if error.partial_identity is None:
                error.partial_identity = partial
            raise
        except OSError as error:
            raise RootCreationError(
                f"cannot initialize root marker in {root}: {error}",
                partial_identity=partial,
            ) from error
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)
        os.close(root_fd)


def _root_descriptor_matches_identity(
    identity: RootIdentity,
    leaf_descriptor: int,
) -> bool:
    if (
        not identity.initialized
        or identity.device is None
        or identity.inode is None
        or identity.marker_device is None
        or identity.marker_inode is None
        or identity.marker_sha256 is None
    ):
        return False
    try:
        root = os.fstat(leaf_descriptor)
        marker_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            marker_flags |= os.O_NOFOLLOW
        marker_descriptor = os.open(
            ROOT_MARKER,
            marker_flags,
            dir_fd=leaf_descriptor,
        )
        try:
            marker = os.fstat(marker_descriptor)
            marker_hash = _descriptor_sha256(marker_descriptor)
        finally:
            os.close(marker_descriptor)
    except OSError:
        return False
    return (
        stat.S_ISDIR(root.st_mode)
        and root.st_dev == identity.device
        and root.st_ino == identity.inode
        and root.st_uid == os.getuid()
        and stat.S_IMODE(root.st_mode) == 0o700
        and stat.S_ISREG(marker.st_mode)
        and marker.st_dev == identity.marker_device
        and marker.st_ino == identity.marker_inode
        and marker.st_uid == os.getuid()
        and stat.S_IMODE(marker.st_mode) == 0o600
        and marker_hash == identity.marker_sha256
    )


def _open_verified_root_identity(identity: RootIdentity) -> int | None:
    try:
        parent_descriptor, _, basename = _open_repository_or_absolute_parent(
            identity.path
        )
    except (OSError, RootCreationError, ValidationError):
        return None
    leaf_descriptor = -1
    try:
        leaf_descriptor = os.open(
            basename,
            _directory_flags(),
            dir_fd=parent_descriptor,
        )
        if not _root_descriptor_matches_identity(identity, leaf_descriptor):
            os.close(leaf_descriptor)
            return None
        return leaf_descriptor
    except OSError:
        if leaf_descriptor >= 0:
            os.close(leaf_descriptor)
        return None
    finally:
        os.close(parent_descriptor)


def verify_root_identity(identity: RootIdentity) -> bool:
    descriptor = _open_verified_root_identity(identity)
    if descriptor is None:
        return False
    os.close(descriptor)
    return True


def _retained_root_matches(
    identity: RootIdentity,
    retained_descriptor: int,
) -> bool:
    if not _root_descriptor_matches_identity(identity, retained_descriptor):
        return False
    current_descriptor = _open_verified_root_identity(identity)
    if current_descriptor is None:
        return False
    try:
        retained = os.fstat(retained_descriptor)
        current = os.fstat(current_descriptor)
        return (
            retained.st_dev == current.st_dev
            and retained.st_ino == current.st_ino
        )
    except OSError:
        return False
    finally:
        os.close(current_descriptor)


@dataclass
class ProcessIdentity:
    pid: int
    starttime: int
    pidfd: int

    def close(self) -> None:
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1


@dataclass(frozen=True)
class OutputEvidence:
    disposition: str
    path: str | None
    sha256: str | None
    sanitized_bytes: int
    excerpt: str
    truncated: bool

    def as_record(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition,
            "path": self.path,
            "sha256": self.sha256,
            "sanitized_bytes": self.sanitized_bytes,
            "excerpt": self.excerpt,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class SupervisedResult:
    spawned: bool
    exit_code: int | None
    termination: str
    quiescence_proved: bool
    discovered_processes: int
    reaped_processes: int
    final_live_descendants: int
    stdout: bytes
    stderr: bytes
    stdout_evidence: OutputEvidence
    stderr_evidence: OutputEvidence
    stdout_capture: Path | None
    stderr_capture: Path | None
    stdout_metadata: bytes | None
    failure_reason: str | None


def _proc_identity(pid: int) -> tuple[str, int, int] | None:
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as error:
        raise QuiescenceError(f"cannot inspect process identity {pid}: {error}") from error
    end = stat_text.rfind(")")
    if end < 0:
        raise QuiescenceError(f"malformed /proc identity for process {pid}")
    fields = stat_text[end + 2 :].split()
    if len(fields) < 20:
        raise QuiescenceError(f"incomplete /proc identity for process {pid}")
    try:
        return fields[0], int(fields[1]), int(fields[19])
    except ValueError as error:
        raise QuiescenceError(f"invalid /proc identity for process {pid}") from error


def _require_supervision_capabilities() -> None:
    if platform.system() != "Linux":
        raise CapabilityError("process-tree proof requires Linux")
    if not hasattr(os, "waitid") or not Path("/proc/self/task").is_dir():
        raise CapabilityError("process-tree proof requires procfs and waitid")
    descriptor = _pidfd_open(os.getpid())
    os.close(descriptor)


def _pidfd_open(pid: int) -> int:
    if hasattr(os, "pidfd_open"):
        return os.pidfd_open(pid, 0)
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.syscall(SYS_PIDFD_OPEN_X86_64, pid, 0)
    if descriptor < 0:
        error_number = ctypes.get_errno()
        raise CapabilityError(
            f"pidfd_open is unavailable: {os.strerror(error_number)}"
        )
    return int(descriptor)


def _pidfd_send_signal(pidfd: int, selected_signal: signal.Signals) -> None:
    if hasattr(signal, "pidfd_send_signal"):
        signal.pidfd_send_signal(pidfd, selected_signal)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        SYS_PIDFD_SEND_SIGNAL_X86_64,
        pidfd,
        int(selected_signal),
        0,
        0,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.ESRCH:
            raise ProcessLookupError(error_number, os.strerror(error_number))
        raise OSError(error_number, os.strerror(error_number))


def _bind_process_identity(pid: int, starttime: int) -> ProcessIdentity:
    try:
        pidfd = _pidfd_open(pid)
    except OSError as error:
        raise QuiescenceError(f"cannot bind pidfd identity for process {pid}: {error}") from error
    current = _proc_identity(pid)
    if current is None or current[2] != starttime:
        os.close(pidfd)
        raise QuiescenceError(f"process identity changed while binding pidfd for {pid}")
    return ProcessIdentity(pid, starttime, pidfd)


def _open_identity(pid: int, starttime: int) -> ProcessIdentity:
    return _bind_process_identity(pid, starttime)


def _identity_state(identity: ProcessIdentity) -> str | None:
    current = _proc_identity(identity.pid)
    if current is None or current[2] != identity.starttime:
        return None
    return current[0]


def _signal_identity(identity: ProcessIdentity, selected_signal: signal.Signals) -> None:
    if _identity_state(identity) is None:
        return
    try:
        _pidfd_send_signal(identity.pidfd, selected_signal)
    except ProcessLookupError:
        return
    except OSError as error:
        raise QuiescenceError(
            f"cannot signal process {identity.pid} through pidfd: {error}"
        ) from error


def child_subreaper_enabled() -> bool:
    state = ctypes.c_int()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(state), 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise CapabilityError(
            f"cannot read child subreaper state: {os.strerror(error_number)}"
        )
    return state.value == 1


def enable_child_subreaper() -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise CapabilityError(
            f"cannot enable child subreaper: {os.strerror(error_number)}"
        )
    if not child_subreaper_enabled():
        raise CapabilityError("child subreaper state did not remain enabled")
    return True


def _children_of(pid: int) -> list[int]:
    task_root = Path(f"/proc/{pid}/task")
    try:
        task_ids = [entry.name for entry in task_root.iterdir() if entry.name.isdigit()]
    except FileNotFoundError:
        return []
    except OSError as error:
        raise QuiescenceError(f"cannot enumerate tasks for process {pid}: {error}") from error
    children: set[int] = set()
    for task_id in task_ids:
        path = task_root / task_id / "children"
        try:
            text = path.read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError) as error:
            raise QuiescenceError(f"cannot enumerate children of process {pid}: {error}") from error
        for value in text.split():
            try:
                children.add(int(value))
            except ValueError as error:
                raise QuiescenceError(f"invalid child process identifier {value!r}") from error
    return sorted(children)


def _discover_descendants(
    tracked: dict[tuple[int, int], ProcessIdentity],
    baseline_children: set[tuple[int, int]],
    extra_parents: Sequence[int] = (),
    identity_opener: Any = None,
    *,
    pass_seconds: float = DISCOVERY_PASS_TIMEOUT,
    max_processes: int = MAX_DISCOVERED_PROCESSES,
) -> int:
    deadline = time.monotonic() + pass_seconds
    added = 0
    parents = {os.getpid()}
    parents.update(extra_parents)
    parents.update(
        identity.pid
        for identity in tracked.values()
        if _identity_state(identity) not in {None, "Z", "X"}
    )
    for parent in sorted(parents):
        if time.monotonic() >= deadline:
            raise QuiescenceError("descendant discovery pass exceeded its deadline")
        for pid in _children_of(parent):
            if time.monotonic() >= deadline:
                raise QuiescenceError("descendant discovery pass exceeded its deadline")
            current = _proc_identity(pid)
            if current is None:
                continue
            key = (pid, current[2])
            if key in baseline_children or key in tracked:
                continue
            if len(tracked) >= max_processes:
                raise QuiescenceError("descendant discovery exceeded its process bound")
            opener = identity_opener or _open_identity
            tracked[key] = opener(pid, current[2])
            added += 1
    return added


def _bounded_emergency_cleanup(
    process: subprocess.Popen[bytes],
    tracked: dict[tuple[int, int], ProcessIdentity],
    baseline_children: set[tuple[int, int]],
    bounds: dict[str, Any],
) -> tuple[int, str | None]:
    reaped = 0
    cleanup_error: str | None = None
    unbound_descendants: list[tuple[int, int]] = []
    deadline = time.monotonic() + bounds["fixed_point_seconds"]
    while time.monotonic() < deadline:
        try:
            _discover_descendants(
                tracked,
                baseline_children,
                (process.pid,),
                _bind_process_identity,
                pass_seconds=bounds["descendant_discovery_pass_seconds"],
                max_processes=bounds["max_discovered_processes"],
            )
        except (CapabilityError, QuiescenceError, OSError) as error:
            cleanup_error = _sanitize_failure_reason(error)
            queue = [process.pid]
            seen: set[int] = set()
            recovery_deadline = (
                time.monotonic() + bounds["descendant_discovery_pass_seconds"]
            )
            while queue and time.monotonic() < recovery_deadline:
                parent = queue.pop()
                try:
                    children = _children_of(parent)
                except QuiescenceError:
                    break
                for pid in children:
                    if pid in seen or len(seen) >= bounds["max_discovered_processes"]:
                        continue
                    seen.add(pid)
                    current = _proc_identity(pid)
                    if current is not None:
                        unbound_descendants.append((pid, current[2]))
                        queue.append(pid)
            break
        if process.poll() is not None:
            break
        time.sleep(STABLE_SCAN_DELAY)
    for identity in list(tracked.values()):
        try:
            _signal_identity(identity, signal.SIGKILL)
        except (QuiescenceError, OSError) as error:
            cleanup_error = cleanup_error or _sanitize_failure_reason(error)
    for pid, starttime in reversed(unbound_descendants):
        current = _proc_identity(pid)
        if current is None or current[2] != starttime:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            cleanup_error = cleanup_error or _sanitize_failure_reason(error)
    if process.poll() is None:
        try:
            process.kill()
        except OSError as error:
            cleanup_error = cleanup_error or _sanitize_failure_reason(error)
    try:
        process.wait(timeout=1)
    except (subprocess.TimeoutExpired, ChildProcessError, OSError) as error:
        cleanup_error = cleanup_error or _sanitize_failure_reason(error)
    end = time.monotonic() + bounds["fixed_point_seconds"]
    stable_empty = 0
    while time.monotonic() < end:
        try:
            added = _discover_descendants(
                tracked,
                baseline_children,
                identity_opener=_bind_process_identity,
                pass_seconds=bounds["descendant_discovery_pass_seconds"],
                max_processes=bounds["max_discovered_processes"],
            )
            reaped += _reap_available()
            live = _live_identities(tracked)
            for identity, _ in live:
                _signal_identity(identity, signal.SIGKILL)
            if added == 0 and not live:
                stable_empty += 1
            else:
                stable_empty = 0
            if stable_empty >= STABLE_SCAN_COUNT:
                break
        except (CapabilityError, QuiescenceError, OSError) as error:
            cleanup_error = cleanup_error or _sanitize_failure_reason(error)
            break
        time.sleep(STABLE_SCAN_DELAY)
    if stable_empty < STABLE_SCAN_COUNT:
        cleanup_error = cleanup_error or (
            "emergency cleanup deadline expired before consecutive empty scans"
        )
    return reaped, cleanup_error


def _live_identities(
    tracked: dict[tuple[int, int], ProcessIdentity],
) -> list[tuple[ProcessIdentity, str]]:
    live: list[tuple[ProcessIdentity, str]] = []
    for identity in tracked.values():
        state = _identity_state(identity)
        if state not in {None, "Z", "X"}:
            live.append((identity, state))
    return live


def _reap_available() -> int:
    reaped = 0
    while True:
        try:
            result = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG)
        except ChildProcessError:
            return reaped
        if result is None:
            return reaped
        reaped += 1


def _sanitize_text(text: str) -> str:
    sanitized = text.replace("\x00", "\\0")
    for pattern in SENSITIVE_OUTPUT:
        if pattern.pattern.startswith("(?i)(https"):
            sanitized = pattern.sub(r"\1[redacted]@", sanitized)
        else:
            sanitized = pattern.sub(r"\1[redacted]", sanitized)
    return sanitized


def _sanitize_failure_reason(error: BaseException) -> str:
    reason = _sanitize_text(f"{type(error).__name__}: {error}")
    reason = re.sub(
        r"(?i)(https?://)[^/\s:@]+:[^/\s@]+",
        r"\1[redacted]",
        reason,
    )
    return reason[:1024]


def _contains_sensitive_output(text: str) -> bool:
    return any(
        pattern.search(text) is not None for pattern in SENSITIVE_OUTPUT_DETECTION
    )


def _intended_output_evidence(
    identity: CaptureIdentity,
    result: dict[str, Any],
    *,
    forced_truncated: bool = False,
) -> OutputEvidence:
    initial = result.get("initial", b"")
    suffix = result.get("suffix", b"")
    total = result.get("sanitized_bytes", 0)
    truncated = total > EXCERPT_LIMIT or forced_truncated
    excerpt_bytes = (
        bytes(initial[: EXCERPT_LIMIT // 2])
        + b"\n...[bounded excerpt]...\n"
        + bytes(suffix)
        if truncated
        else bytes(initial)
    )
    return OutputEvidence(
        disposition=RETAINED_OUTPUT,
        path=identity.path.as_posix(),
        sha256=result.get("sha256", hashlib.sha256(b"").hexdigest()),
        sanitized_bytes=total,
        excerpt=excerpt_bytes.decode("utf-8", errors="replace"),
        truncated=truncated,
    )


def _verify_capture_evidence(
    identity: CaptureIdentity,
    result: dict[str, Any],
    *,
    forced_truncated: bool = False,
) -> OutputEvidence:
    current_directory, directory_metadata, basename = (
        _open_repository_or_absolute_parent(identity.path)
    )
    try:
        if (
            directory_metadata.st_dev != identity.directory_device
            or directory_metadata.st_ino != identity.directory_inode
        ):
            raise CaptureError("capture directory identity changed after creation")
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(basename, flags, dir_fd=current_directory)
        try:
            metadata = os.fstat(descriptor)
            digest = _descriptor_sha256(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_dev != identity.leaf_device
                or metadata.st_ino != identity.leaf_inode
                or metadata.st_size != result.get("sanitized_bytes", -1)
                or digest != result.get("sha256")
            ):
                raise CaptureError(
                    "retained capture identity or content differs from sanitizer output"
                )
            identity.leaf_size = metadata.st_size
            identity.leaf_sha256 = digest
        finally:
            os.close(descriptor)
    finally:
        os.close(current_directory)
    return _intended_output_evidence(
        identity,
        result,
        forced_truncated=forced_truncated,
    )


def _new_capture(
    capture_dir: Path,
    label: str,
    stream: str,
) -> tuple[CaptureIdentity, Any]:
    capture_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_descriptor, directory_metadata, _ = (
        _open_repository_or_absolute_parent(capture_dir / "leaf")
    )
    name = f"{label}-{stream}-{os.getpid()}-{time.monotonic_ns()}.log"
    path = capture_dir / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
    metadata: os.stat_result | None = None
    try:
        metadata = os.fstat(descriptor)
        identity = CaptureIdentity(
            path=path,
            directory_descriptor=directory_descriptor,
            directory_device=directory_metadata.st_dev,
            directory_inode=directory_metadata.st_ino,
            leaf_device=metadata.st_dev,
            leaf_inode=metadata.st_ino,
        )
        return identity, os.fdopen(descriptor, "wb", buffering=0)
    except (OSError, ValueError):
        os.close(descriptor)
        if metadata is not None:
            try:
                _quarantine_owned_leaf(
                    directory_descriptor,
                    name,
                    (metadata.st_dev, metadata.st_ino, None),
                    context="capture initialization cleanup",
                )
            except (OSError, RecordingError):
                pass
        os.close(directory_descriptor)
        raise


def _discard_capture_identity(identity: CaptureIdentity) -> None:
    try:
        _quarantine_owned_leaf(
            identity.directory_descriptor,
            identity.path.name,
            (identity.leaf_device, identity.leaf_inode, identity.leaf_sha256),
            context="capture setup cleanup",
        )
    except (OSError, RecordingError):
        pass
    identity.close()


def _record_output_violation(
    violation: dict[str, str],
    violation_lock: threading.Lock,
    cause: str,
    reason: str,
) -> None:
    with violation_lock:
        current = violation.get("cause")
        if current is None or (
            current == "output-limit-exceeded"
            and cause in {"sensitive-output", "capture-failed"}
        ):
            violation["cause"] = cause
            violation["reason"] = reason


def _stream_sanitized_capture(
    source_descriptor: int,
    destination: Any,
    *,
    metadata_limit: int,
    result: dict[str, Any],
    violation: dict[str, str],
    violation_lock: threading.Lock,
    stop_event: threading.Event,
) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    carry = ""
    captured = 0
    metadata = bytearray()
    digest = hashlib.sha256()
    initial = bytearray()
    suffix = bytearray()

    def set_violation(cause: str, reason: str) -> None:
        _record_output_violation(
            violation,
            violation_lock,
            cause,
            reason,
        )

    def persist(text: str) -> bool:
        nonlocal captured
        payload = text.replace("\x00", "\\0").encode("utf-8")
        remaining = CAPTURE_LIMIT - captured
        if len(payload) > remaining:
            if remaining:
                emitted = payload[:remaining]
                destination.write(emitted)
                digest.update(emitted)
                if len(initial) < EXCERPT_LIMIT:
                    initial.extend(emitted[: EXCERPT_LIMIT - len(initial)])
                suffix.extend(emitted)
                if len(suffix) > EXCERPT_LIMIT // 2:
                    del suffix[: len(suffix) - EXCERPT_LIMIT // 2]
                captured += remaining
            set_violation(
                "output-limit-exceeded",
                f"sanitized output exceeded the {CAPTURE_LIMIT}-byte capture limit",
            )
            return False
        destination.write(payload)
        digest.update(payload)
        if len(initial) < EXCERPT_LIMIT:
            initial.extend(payload[: EXCERPT_LIMIT - len(initial)])
        suffix.extend(payload)
        if len(suffix) > EXCERPT_LIMIT // 2:
            del suffix[: len(suffix) - EXCERPT_LIMIT // 2]
        captured += len(payload)
        return True

    try:
        os.set_blocking(source_descriptor, False)
        while not stop_event.is_set():
            try:
                raw = os.read(source_descriptor, CAPTURE_CHUNK)
            except BlockingIOError:
                stop_event.wait(0.01)
                continue
            if not raw:
                break
            if metadata_limit:
                if len(metadata) + len(raw) > metadata_limit:
                    set_violation(
                        "output-limit-exceeded",
                        f"metadata output exceeded the {metadata_limit}-byte limit",
                    )
                elif not violation:
                    metadata.extend(raw)
            text = decoder.decode(raw)
            combined = carry + text
            if _contains_sensitive_output(combined):
                set_violation(
                    "sensitive-output",
                    "sensitive output pattern detected before persistence",
                )
                carry = ""
                continue
            if len(combined) <= 4096:
                carry = combined
                continue
            ready, carry = combined[:-4096], combined[-4096:]
            persist(ready)
        final = carry + decoder.decode(b"", final=True)
        if final:
            if _contains_sensitive_output(final):
                set_violation(
                    "sensitive-output",
                    "sensitive output pattern detected before persistence",
                )
            elif not violation:
                persist(final)
        destination.flush()
        os.fsync(destination.fileno())
        result["metadata"] = bytes(metadata) if metadata_limit and not violation else None
        result["sha256"] = digest.hexdigest()
        result["sanitized_bytes"] = captured
        result["initial"] = bytes(initial)
        result["suffix"] = bytes(suffix)
    except (OSError, UnicodeError, ValueError) as error:
        set_violation("capture-failed", _sanitize_failure_reason(error))
        result["metadata"] = None
    finally:
        result.setdefault("sha256", digest.hexdigest())
        result.setdefault("sanitized_bytes", captured)
        result.setdefault("initial", bytes(initial))
        result.setdefault("suffix", bytes(suffix))
        try:
            os.close(source_descriptor)
        except OSError as error:
            set_violation("capture-failed", _sanitize_failure_reason(error))


def _stream_suppressed_output(
    source_descriptor: int,
    *,
    result: dict[str, Any],
    violation: dict[str, str],
    violation_lock: threading.Lock,
    stop_event: threading.Event,
) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    carry = ""
    observed = 0

    def set_violation(cause: str, reason: str) -> None:
        _record_output_violation(
            violation,
            violation_lock,
            cause,
            reason,
        )

    try:
        os.set_blocking(source_descriptor, False)
        while not stop_event.is_set():
            try:
                raw = os.read(source_descriptor, CAPTURE_CHUNK)
            except BlockingIOError:
                stop_event.wait(0.01)
                continue
            if not raw:
                break
            observed += len(raw)
            if observed > CAPTURE_LIMIT:
                set_violation(
                    "output-limit-exceeded",
                    f"suppressed output exceeded the {CAPTURE_LIMIT}-byte limit",
                )
            combined = carry + decoder.decode(raw)
            if _contains_sensitive_output(combined):
                set_violation(
                    "sensitive-output",
                    "sensitive output pattern detected before suppression",
                )
                carry = ""
            else:
                carry = combined[-4096:]
        final = carry + decoder.decode(b"", final=True)
        if final and _contains_sensitive_output(final):
            set_violation(
                "sensitive-output",
                "sensitive output pattern detected before suppression",
            )
    except (OSError, UnicodeError, ValueError) as error:
        set_violation("capture-failed", _sanitize_failure_reason(error))
    finally:
        result["metadata"] = None
        try:
            os.close(source_descriptor)
        except OSError as error:
            set_violation("capture-failed", _sanitize_failure_reason(error))


def _empty_output_evidence(disposition: str) -> OutputEvidence:
    if disposition in {
        SUPPRESSED_SOURCE_FAITHFUL_OUTPUT,
        UNVERIFIABLE_OUTPUT,
    }:
        return OutputEvidence(
            disposition=disposition,
            path=None,
            sha256=None,
            sanitized_bytes=0,
            excerpt="",
            truncated=False,
        )
    return OutputEvidence(
        disposition=RETAINED_OUTPUT,
        path="",
        sha256=hashlib.sha256(b"").hexdigest(),
        sanitized_bytes=0,
        excerpt="",
        truncated=False,
    )


def run_supervised(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    subreaper_enabled: bool,
    cancel_event: threading.Event | None = None,
    force_unproved: bool = False,
    capture_dir: Path | None = None,
    label: str = "child",
    stdout_metadata_limit: int = 0,
    output_disposition: str = RETAINED_OUTPUT,
    executable_fd: int | None = None,
    retained_fds: Sequence[int] = (),
    bounds: dict[str, Any] | None = None,
    retained_capture_identities: list[CaptureIdentity] | None = None,
) -> SupervisedResult:
    bounds = bounds or supervision_ceilings()
    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError("supervised executable must be an absolute path")
    if set(env) - set(REPLACEMENT_ENVIRONMENT_KEYS):
        raise ValueError("supervised environment contains keys outside the fixed allowlist")
    if output_disposition not in {
        RETAINED_OUTPUT,
        SUPPRESSED_SOURCE_FAITHFUL_OUTPUT,
    }:
        raise ValueError("unsupported supervised output disposition")
    if (
        output_disposition == SUPPRESSED_SOURCE_FAITHFUL_OUTPUT
        and stdout_metadata_limit
    ):
        raise ValueError("suppressed output cannot supply stdout metadata")
    _require_supervision_capabilities()
    if not subreaper_enabled or not child_subreaper_enabled():
        raise CapabilityError("supervised execution requires verified child subreaper state")
    baseline_children: set[tuple[int, int]] = set()
    for pid in _children_of(os.getpid()):
        current = _proc_identity(pid)
        if current is not None:
            baseline_children.add((pid, current[2]))
    selected_capture_dir = capture_dir or (cwd / ".supervisor-captures")
    stdout_identity: CaptureIdentity | None = None
    stderr_identity: CaptureIdentity | None = None
    stdout_stream: Any | None = None
    stderr_stream: Any | None = None
    try:
        if output_disposition == RETAINED_OUTPUT:
            stdout_identity, stdout_stream = _new_capture(
                selected_capture_dir, label, "stdout"
            )
            stderr_identity, stderr_stream = _new_capture(
                selected_capture_dir, label, "stderr"
            )
    except (OSError, ValueError) as error:
        for stream in (stdout_stream, stderr_stream):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        for identity in (stdout_identity, stderr_identity):
            if identity is not None:
                _discard_capture_identity(identity)
        empty_output = _empty_output_evidence(output_disposition)
        return SupervisedResult(
            spawned=False,
            exit_code=None,
            termination="capture-failed",
            quiescence_proved=True,
            discovered_processes=0,
            reaped_processes=0,
            final_live_descendants=0,
            stdout=b"",
            stderr=b"",
            stdout_evidence=empty_output,
            stderr_evidence=empty_output,
            stdout_capture=None,
            stderr_capture=None,
            stdout_metadata=None,
            failure_reason=f"capture-failed:{_sanitize_failure_reason(error)}",
        )
    process: subprocess.Popen[bytes] | None = None
    tracked: dict[tuple[int, int], ProcessIdentity] = {}
    termination = "completed"
    discovery_proved = True
    reaped = 0
    failure_reason: str | None = None
    violation: dict[str, str] = {}
    violation_lock = threading.Lock()
    stdout_result: dict[str, Any] = {}
    stderr_result: dict[str, Any] = {}
    stdout_thread: threading.Thread | None = None
    stderr_thread: threading.Thread | None = None
    stdout_thread_started = False
    stderr_thread_started = False
    stdout_descriptor: int | None = None
    stderr_descriptor: int | None = None
    capture_stop = threading.Event()
    executable = None
    pass_fds: tuple[int, ...] = tuple(dict.fromkeys(retained_fds))
    try:
        for retained_fd in pass_fds:
            os.fstat(retained_fd)
        if executable_fd is not None:
            os.fstat(executable_fd)
            executable = f"/proc/self/fd/{executable_fd}"
            pass_fds = tuple(dict.fromkeys((*pass_fds, executable_fd)))
        process = subprocess.Popen(
            list(argv),
            executable=executable,
            pass_fds=pass_fds,
            cwd=cwd,
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=False,
        )
    except (OSError, ValueError) as error:
        if stdout_stream is not None:
            stdout_stream.close()
        if stderr_stream is not None:
            stderr_stream.close()
        for identity in (stdout_identity, stderr_identity):
            if identity is not None:
                _discard_capture_identity(identity)
        empty_output = _empty_output_evidence(output_disposition)
        return SupervisedResult(
            spawned=False,
            exit_code=None,
            termination="spawn-failed",
            quiescence_proved=True,
            discovered_processes=0,
            reaped_processes=0,
            final_live_descendants=0,
            stdout=b"",
            stderr=b"",
            stdout_evidence=empty_output,
            stderr_evidence=empty_output,
            stdout_capture=None,
            stderr_capture=None,
            stdout_metadata=None,
            failure_reason=f"spawn-failed:{_sanitize_failure_reason(error)}",
        )
    try:
        root_state = _proc_identity(process.pid)
        if root_state is None:
            raise QuiescenceError("cannot establish root process identity")
        tracked[(process.pid, root_state[2])] = _open_identity(
            process.pid, root_state[2]
        )
        if process.stdout is None or process.stderr is None:
            raise CaptureError("cannot create supervised output pipes")
        stdout_descriptor = os.dup(process.stdout.fileno())
        stderr_descriptor = os.dup(process.stderr.fileno())
        process.stdout.close()
        process.stderr.close()
        if output_disposition == RETAINED_OUTPUT:
            stdout_thread = threading.Thread(
                target=_stream_sanitized_capture,
                args=(stdout_descriptor, stdout_stream),
                kwargs={
                    "metadata_limit": stdout_metadata_limit,
                    "result": stdout_result,
                    "violation": violation,
                    "violation_lock": violation_lock,
                    "stop_event": capture_stop,
                },
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=_stream_sanitized_capture,
                args=(stderr_descriptor, stderr_stream),
                kwargs={
                    "metadata_limit": 0,
                    "result": stderr_result,
                    "violation": violation,
                    "violation_lock": violation_lock,
                    "stop_event": capture_stop,
                },
                daemon=True,
            )
        else:
            stdout_thread = threading.Thread(
                target=_stream_suppressed_output,
                args=(stdout_descriptor,),
                kwargs={
                    "result": stdout_result,
                    "violation": violation,
                    "violation_lock": violation_lock,
                    "stop_event": capture_stop,
                },
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=_stream_suppressed_output,
                args=(stderr_descriptor,),
                kwargs={
                    "result": stderr_result,
                    "violation": violation,
                    "violation_lock": violation_lock,
                    "stop_event": capture_stop,
                },
                daemon=True,
            )
        try:
            stdout_thread.start()
        except RuntimeError as error:
            raise CaptureInitializationError(
                f"cannot start stdout capture reader: {error}"
            ) from error
        stdout_thread_started = True
        try:
            stderr_thread.start()
        except RuntimeError as error:
            raise CaptureInitializationError(
                f"cannot start stderr capture reader: {error}"
            ) from error
        stderr_thread_started = True
        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            try:
                if cancel_event is not None and cancel_event.is_set():
                    termination = "cancelled"
                    failure_reason = "cancellation-requested"
                    break
                _discover_descendants(
                    tracked,
                    baseline_children,
                    pass_seconds=bounds["descendant_discovery_pass_seconds"],
                    max_processes=bounds["max_discovered_processes"],
                )
                if violation:
                    termination = violation["cause"]
                    failure_reason = violation["reason"]
                    break
                if time.monotonic() >= deadline:
                    termination = "timed-out"
                    failure_reason = (
                        f"command exceeded its {timeout_seconds}-second deadline"
                    )
                    break
                time.sleep(0.01)
            except KeyboardInterrupt:
                termination = "cancelled"
                failure_reason = "keyboard-interrupt"
                break
        _discover_descendants(
            tracked,
            baseline_children,
            pass_seconds=bounds["descendant_discovery_pass_seconds"],
            max_processes=bounds["max_discovered_processes"],
        )
        stable = 0
        fixed_point_deadline = time.monotonic() + bounds["fixed_point_seconds"]
        while stable < STABLE_SCAN_COUNT:
            if cancel_event is not None and cancel_event.is_set():
                termination = "cancelled"
                failure_reason = failure_reason or "cancellation-requested"
            if time.monotonic() >= fixed_point_deadline:
                raise QuiescenceError(
                    "stopped descendant fixed point did not converge before its deadline"
                )
            added = _discover_descendants(
                tracked,
                baseline_children,
                pass_seconds=bounds["descendant_discovery_pass_seconds"],
                max_processes=bounds["max_discovered_processes"],
            )
            live = _live_identities(tracked)
            if any(state == "D" for _, state in live):
                raise QuiescenceError("a supervised process entered uninterruptible D state")
            for identity, state in live:
                if state not in {"T", "t"}:
                    _signal_identity(identity, signal.SIGSTOP)
            time.sleep(STABLE_SCAN_DELAY)
            added += _discover_descendants(
                tracked,
                baseline_children,
                pass_seconds=bounds["descendant_discovery_pass_seconds"],
                max_processes=bounds["max_discovered_processes"],
            )
            states = [state for _, state in _live_identities(tracked)]
            if any(state == "D" for state in states):
                raise QuiescenceError("a supervised process entered uninterruptible D state")
            if added == 0 and all(state in {"T", "t"} for state in states):
                stable += 1
            else:
                stable = 0
        for identity, _ in _live_identities(tracked):
            _signal_identity(identity, signal.SIGKILL)
        if process.poll() is None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired as error:
                raise QuiescenceError("root process did not exit after pidfd SIGKILL") from error
        stable_empty = 0
        end = time.monotonic() + 2.0
        while stable_empty < STABLE_SCAN_COUNT:
            _discover_descendants(
                tracked,
                baseline_children,
                pass_seconds=bounds["descendant_discovery_pass_seconds"],
                max_processes=bounds["max_discovered_processes"],
            )
            reaped += _reap_available()
            live = _live_identities(tracked)
            if any(state == "D" for _, state in live):
                raise QuiescenceError("a supervised process remained in D state")
            for identity, _ in live:
                _signal_identity(identity, signal.SIGKILL)
            if not live and _discover_descendants(
                tracked,
                baseline_children,
                pass_seconds=bounds["descendant_discovery_pass_seconds"],
                max_processes=bounds["max_discovered_processes"],
            ) == 0:
                stable_empty += 1
            else:
                stable_empty = 0
            if time.monotonic() >= end and stable_empty < STABLE_SCAN_COUNT:
                raise QuiescenceError("process-tree quiescence did not converge")
            time.sleep(STABLE_SCAN_DELAY)
    except KeyboardInterrupt as error:
        termination = "cancelled"
        failure_reason = "keyboard-interrupt"
        emergency_reaped, cleanup_error = _bounded_emergency_cleanup(
            process,
            tracked,
            baseline_children,
            bounds,
        )
        reaped += emergency_reaped
        if cleanup_error is not None:
            termination = "quiescence-unproved"
            discovery_proved = False
            failure_reason = cleanup_error
    except (
        CapabilityError,
        CaptureError,
        QuiescenceError,
        OSError,
    ) as error:
        termination = "quiescence-unproved"
        discovery_proved = False
        failure_reason = _sanitize_failure_reason(error)
        if process is not None:
            emergency_reaped, cleanup_error = _bounded_emergency_cleanup(
                process,
                tracked,
                baseline_children,
                bounds,
            )
            reaped += emergency_reaped
            if cleanup_error is not None and failure_reason is None:
                failure_reason = cleanup_error
    finally:
        if stdout_thread_started:
            stdout_thread.join(timeout=bounds["capture_reader_grace_seconds"])
        if stderr_thread_started:
            stderr_thread.join(timeout=bounds["capture_reader_grace_seconds"])
        if (
            stdout_thread_started
            and stdout_thread.is_alive()
            or stderr_thread_started
            and stderr_thread.is_alive()
        ):
            _record_output_violation(
                violation,
                violation_lock,
                "capture-failed",
                "capture readers required bounded forced shutdown",
            )
            capture_stop.set()
            for descriptor in (stdout_descriptor, stderr_descriptor):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            stdout_descriptor = None
            stderr_descriptor = None
            if stdout_thread_started:
                stdout_thread.join(timeout=bounds["capture_reader_shutdown_seconds"])
            if stderr_thread_started:
                stderr_thread.join(timeout=bounds["capture_reader_shutdown_seconds"])
        if stdout_thread_started and stdout_thread.is_alive():
            termination = "quiescence-unproved"
            discovery_proved = False
            failure_reason = "CaptureError: stdout capture thread did not terminate"
        if stderr_thread_started and stderr_thread.is_alive():
            termination = "quiescence-unproved"
            discovery_proved = False
            failure_reason = "CaptureError: stderr capture thread did not terminate"
        if not stdout_thread_started and stdout_descriptor is not None:
            os.close(stdout_descriptor)
        if not stderr_thread_started and stderr_descriptor is not None:
            os.close(stderr_descriptor)
        if process is not None:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
        if stdout_stream is not None:
            stdout_stream.close()
        if stderr_stream is not None:
            stderr_stream.close()
    if violation and (
        termination == "completed"
        or (
            violation["cause"] in {"sensitive-output", "capture-failed"}
            and termination != "quiescence-unproved"
        )
    ):
        termination = violation["cause"]
        failure_reason = violation["reason"]
    live_count = len(_live_identities(tracked))
    quiescence_proved = (
        discovery_proved and live_count == 0 and not force_unproved
    )
    if not quiescence_proved:
        termination = "quiescence-unproved"
    exit_code = process.returncode if process is not None else None
    for identity in tracked.values():
        identity.close()
    if output_disposition == RETAINED_OUTPUT:
        for capture_result in (stdout_result, stderr_result):
            capture_result.setdefault("sha256", hashlib.sha256(b"").hexdigest())
            capture_result.setdefault("sanitized_bytes", 0)
            capture_result.setdefault("initial", b"")
            capture_result.setdefault("suffix", b"")
        if stdout_identity is None or stderr_identity is None:
            raise AssertionError("spawned supervision lost its capture identities")
        captures_verified = False
        try:
            stdout_evidence = _verify_capture_evidence(
                stdout_identity,
                stdout_result,
                forced_truncated=termination == "output-limit-exceeded",
            )
            stderr_evidence = _verify_capture_evidence(
                stderr_identity,
                stderr_result,
                forced_truncated=termination == "output-limit-exceeded",
            )
            captures_verified = True
        except (CaptureError, OSError, RootCreationError, ValidationError) as error:
            stdout_evidence = _empty_output_evidence(UNVERIFIABLE_OUTPUT)
            stderr_evidence = _empty_output_evidence(UNVERIFIABLE_OUTPUT)
            if termination not in GLOBAL_SAFETY_TERMINATIONS:
                termination = "capture-failed"
                failure_reason = _sanitize_failure_reason(error)
        finally:
            if retained_capture_identities is None or not captures_verified:
                stdout_identity.close()
                stderr_identity.close()
        if retained_capture_identities is not None and captures_verified:
            retained_capture_identities.extend(
                (stdout_identity, stderr_identity)
            )
    else:
        if stdout_identity is not None or stderr_identity is not None:
            raise AssertionError("suppressed supervision created capture identities")
        stdout_evidence = _empty_output_evidence(output_disposition)
        stderr_evidence = _empty_output_evidence(output_disposition)
    return SupervisedResult(
        spawned=process is not None,
        exit_code=exit_code,
        termination=termination,
        quiescence_proved=quiescence_proved,
        discovered_processes=len(tracked),
        reaped_processes=reaped,
        final_live_descendants=live_count,
        stdout=stdout_evidence.excerpt.encode("utf-8"),
        stderr=stderr_evidence.excerpt.encode("utf-8"),
        stdout_evidence=stdout_evidence,
        stderr_evidence=stderr_evidence,
        stdout_capture=(
            stdout_identity.path
            if stdout_identity is not None
            and stdout_evidence.disposition != UNVERIFIABLE_OUTPUT
            else None
        ),
        stderr_capture=(
            stderr_identity.path
            if stderr_identity is not None
            and stderr_evidence.disposition != UNVERIFIABLE_OUTPUT
            else None
        ),
        stdout_metadata=stdout_result.get("metadata"),
        failure_reason=failure_reason,
    )


def _base_environment() -> dict[str, str]:
    return {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def mise_environment(toolchain_root: Path) -> dict[str, str]:
    home = toolchain_root / "home"
    config = home / ".config/mise/config.toml"
    env = {
        **_base_environment(),
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(toolchain_root / "tmp"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(toolchain_root / "cache"),
        "XDG_DATA_HOME": str(toolchain_root / "xdg-data"),
        "XDG_STATE_HOME": str(toolchain_root / "state"),
        "MISE_DATA_DIR": str(toolchain_root),
        "MISE_CACHE_DIR": str(toolchain_root / "cache/mise"),
        "MISE_STATE_DIR": str(toolchain_root / "state/mise"),
        "MISE_TMP_DIR": str(toolchain_root / "tmp/mise"),
        "MISE_CONFIG_FILE": str(config),
        "MISE_GLOBAL_CONFIG_FILE": str(config),
        "MISE_SYSTEM_CONFIG_FILE": str(toolchain_root / "config/no-system.toml"),
        "MISE_CEILING_PATHS": str(toolchain_root),
        "MISE_NO_ENV": "1",
        "MISE_NO_HOOKS": "1",
        "MISE_ENABLE_TOOLS": MISE_TOOL_NAME,
        "MISE_LOCKED": "1",
    }
    if set(env) != set(MISE_ENVIRONMENT_KEYS):
        raise AssertionError("mise environment differs from the reviewed key set")
    return env


def git_environment(mode: dict[str, Any], git_executable: Path) -> dict[str, str]:
    home = Path(mode["home_root"])
    env = {
        **_base_environment(),
        "HOME": str(home),
        "PATH": f"{git_executable.parent}:/usr/bin:/bin",
        "TMPDIR": mode["temporary_root"],
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_STATE_HOME": str(home / ".local/state"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_SSH": "/bin/false",
        "GCM_INTERACTIVE": "Never",
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "",
        "GIT_CONFIG_KEY_1": "core.askPass",
        "GIT_CONFIG_VALUE_1": "/bin/false",
        "GIT_CONFIG_KEY_2": "http.proxy",
        "GIT_CONFIG_VALUE_2": "",
        "GIT_CONFIG_KEY_3": "https.proxy",
        "GIT_CONFIG_VALUE_3": "",
    }
    if set(env) != set(GIT_ENVIRONMENT_KEYS):
        raise AssertionError("git environment differs from the reviewed key set")
    return env


def dotnet_environment(mode: dict[str, Any], dotnet_root: Path) -> dict[str, str]:
    home = Path(mode["home_root"])
    env = {
        **_base_environment(),
        "HOME": str(home),
        "PATH": f"{dotnet_root}:/usr/bin:/bin",
        "TMPDIR": mode["temporary_root"],
        "TMP": mode["temporary_root"],
        "TEMP": mode["temporary_root"],
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_STATE_HOME": str(home / ".local/state"),
        "DOTNET_ROOT": str(dotnet_root),
        "DOTNET_CLI_HOME": str(home / ".dotnet"),
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "DOTNET_ADD_GLOBAL_TOOLS_TO_PATH": "0",
        "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false",
        "DOTNET_WORKLOAD_UPDATE_NOTIFY_DISABLE": "1",
        "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "1",
        "DOTNET_MULTILEVEL_LOOKUP": "0",
        "DOTNET_NOLOGO": "1",
        "DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER": "1",
        "MSBUILDDISABLENODEREUSE": "1",
        "NUGET_PACKAGES": mode["nuget_packages_root"],
        "NUGET_HTTP_CACHE_PATH": mode["nuget_http_cache_root"],
        "NUGET_PLUGINS_CACHE_PATH": mode["nuget_plugins_cache_root"],
        "NUGET_SCRATCH": mode["nuget_scratch_root"],
        "NUGET_CREDENTIALPROVIDERS_PATH": "",
    }
    if set(env) != set(DOTNET_ENVIRONMENT_KEYS):
        raise AssertionError(".NET environment differs from the reviewed key set")
    return env


def _attempt_record(result: SupervisedResult) -> dict[str, Any]:
    return {
        "attempt": 1,
        "exit_code": result.exit_code,
        "termination": result.termination,
        "stdout": result.stdout_evidence.as_record(),
        "stderr": result.stderr_evidence.as_record(),
        "failure_reason": result.failure_reason,
    }


def _observation(
    result: SupervisedResult,
    subject_kind: str,
    subject_id: str,
) -> dict[str, Any]:
    return {
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "proved": result.quiescence_proved,
        "descendant_fixed_point": result.quiescence_proved,
        "final_live_descendants": result.final_live_descendants,
        "reaped_processes": result.reaped_processes,
    }


def _run_subject(
    subject_id: str,
    subject_kind: str,
    argv: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    capture_dir: Path,
    cancel_event: threading.Event | None,
    observations: list[dict[str, Any]],
    subreaper_enabled: bool,
    stdout_metadata_limit: int = 0,
    output_disposition: str = RETAINED_OUTPUT,
    executable_fd: int | None = None,
    retained_fds: Sequence[int] = (),
    bounds: dict[str, Any] | None = None,
    retained_capture_groups: list[RetainedCaptureGroup] | None = None,
) -> tuple[SupervisedResult, dict[str, Any] | None]:
    retained_identities: list[CaptureIdentity] | None = (
        [] if retained_capture_groups is not None else None
    )
    result = run_supervised(
        argv,
        cwd=cwd,
        env=env,
        timeout_seconds=timeout_seconds,
        subreaper_enabled=subreaper_enabled,
        cancel_event=cancel_event,
        capture_dir=capture_dir,
        label=subject_id,
        stdout_metadata_limit=stdout_metadata_limit,
        output_disposition=output_disposition,
        executable_fd=executable_fd,
        retained_fds=retained_fds,
        bounds=bounds,
        retained_capture_identities=retained_identities,
    )
    if not result.spawned:
        if retained_identities:
            for identity in retained_identities:
                identity.close()
        return result, None
    observation = _observation(result, subject_kind, subject_id)
    observations.append(observation)
    attempt = _attempt_record(result)
    if retained_identities:
        if len(retained_identities) != 2:
            for identity in retained_identities:
                identity.close()
            raise AssertionError("retained subject capture identity set is incomplete")
        retained_capture_groups.append(
            RetainedCaptureGroup(
                subject_kind=subject_kind,
                subject_id=subject_id,
                attempt=attempt,
                identities=(retained_identities[0], retained_identities[1]),
            )
        )
    return result, attempt


def _mkdirs(paths: Sequence[Path]) -> None:
    for path in paths:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)


def _write_exclusive(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(path, flags, mode)
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_mise_config(
    toolchain_root: Path,
    bundle: dict[str, Any],
    mise_lock_bytes: bytes,
) -> None:
    config = toolchain_root / "home/.config/mise/config.toml"
    lock = config.with_name("mise.lock")
    content = bundle["environment"]["mise"]["config_content"].encode("utf-8")
    lock_component = bundle["components"]["lockfile"]
    _write_exclusive(config, content)
    _write_exclusive(lock, mise_lock_bytes)
    if config.read_bytes() != content:
        raise ValidationError("generated mise config differs from its reviewed hash")
    if (
        hashlib.sha256(mise_lock_bytes).hexdigest() != lock_component["sha256"]
        or lock.read_bytes() != mise_lock_bytes
    ):
        raise ValidationError("generated mise lock differs from its reviewed hash")


def _write_public_nuget_config(path: Path) -> None:
    content = (
        b'<?xml version="1.0" encoding="utf-8"?>\n'
        b"<configuration>\n"
        b"  <packageSources>\n"
        b"    <clear />\n"
        b'    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" '
        b'protocolVersion="3" />\n'
        b"  </packageSources>\n"
        b"  <disabledPackageSources><clear /></disabledPackageSources>\n"
        b"  <packageSourceCredentials><clear /></packageSourceCredentials>\n"
        b"</configuration>\n"
    )
    _write_exclusive(path, content)


def _write_directory_packages_props(path: Path) -> None:
    content = DIRECTORY_PACKAGES_PROPS_CONTENT.encode("utf-8")
    _write_exclusive(path, content)
    if path.read_bytes() != content:
        raise ValidationError(
            "generated Directory.Packages.props differs from its reviewed content"
        )


def _verify_nuget_roots_empty(mode: dict[str, Any]) -> dict[str, str]:
    keys = (
        "nuget_http_cache_root",
        "nuget_packages_root",
        "nuget_scratch_root",
        "nuget_plugins_cache_root",
    )
    paths: dict[str, str] = {}
    for key in keys:
        path = Path(mode[key])
        if not path.is_dir() or path.is_symlink():
            raise ValidationError(f"{key} is not an isolated directory")
        if any(path.iterdir()):
            raise ValidationError(f"{key} was not initially empty")
        paths[key] = str(path)
    return paths


def _parse_nuget_cache_locations(
    payload: bytes,
    mode: dict[str, Any],
) -> dict[str, str]:
    expected = {
        "http-cache": mode["nuget_http_cache_root"],
        "global-packages": mode["nuget_packages_root"],
        "temp": mode["nuget_scratch_root"],
        "plugins-cache": mode["nuget_plugins_cache_root"],
    }
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ValidationError("NuGet cache locations are not UTF-8") from error
    observed: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"(?:info\s*:\s*)?([^:]+):\s*(\S.*)", line)
        if match is None:
            raise ValidationError("NuGet cache locations contain an invalid line")
        label, value = match.groups()
        if label not in expected or label in observed:
            raise ValidationError(
                "NuGet cache locations contain duplicate or unexpected labels"
            )
        if not value.startswith("/") or value.startswith("//"):
            raise ValidationError("NuGet cache locations must use absolute POSIX paths")
        observed[label] = value if value == "/" else value.rstrip("/")
    if set(observed) != set(expected):
        raise ValidationError("NuGet cache locations omit required labels")
    normalized_expected = {
        label: value if value == "/" else value.rstrip("/")
        for label, value in expected.items()
    }
    if observed != normalized_expected:
        raise ValidationError("NuGet cache locations differ from isolated mode roots")
    return expected


def _inspect_nuget_client_version(dotnet_root: Path) -> dict[str, Any]:
    deps_path = (
        dotnet_root
        / "sdk"
        / DOTNET_SDK_VERSION
        / "NuGet.CommandLine.XPlat.deps.json"
    )
    if (
        not deps_path.is_file()
        or deps_path.is_symlink()
        or not deps_path.resolve().is_relative_to(dotnet_root.resolve())
    ):
        raise ValidationError(
            "installed SDK NuGet.CommandLine.XPlat.deps.json is not a trusted file"
        )
    deps = load_strict_json(deps_path)
    libraries = deps.get("libraries")
    if not isinstance(libraries, dict):
        raise ValidationError("installed SDK NuGet deps file has no libraries object")
    prefix = "NuGet.CommandLine.XPlat/"
    matches = sorted(
        key for key in libraries
        if isinstance(key, str) and key.startswith(prefix)
    )
    if len(matches) != 1:
        raise ValidationError(
            "installed SDK NuGet deps file does not identify one exact client version"
        )
    version = matches[0][len(prefix) :]
    if re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z-]+)+", version) is None:
        raise ValidationError("installed SDK NuGet client version is not exact")
    return {
        "preparation_id": "inspect-nuget-client-version",
        "source": "NuGet.CommandLine.XPlat.deps.json",
        "path": str(deps_path),
        "sha256": _path_sha256(deps_path),
        "package": "NuGet.CommandLine.XPlat",
        "version": version,
    }


def _source_fingerprint(
    checkout_descriptor: int,
    *,
    max_entries: int = SOURCE_MAX_ENTRIES,
    per_file_limit: int = SOURCE_PER_FILE_LIMIT,
    aggregate_limit: int = SOURCE_AGGREGATE_LIMIT,
    elapsed_timeout: float = SOURCE_ELAPSED_TIMEOUT,
    clock: Any = time.monotonic,
) -> str:
    started = clock()
    entries = 0
    total_bytes = 0
    aggregate = hashlib.sha256()

    def account(relative: str, amount: int = 0) -> None:
        nonlocal entries, total_bytes
        if clock() - started > elapsed_timeout:
            raise ValidationError("source fingerprint exceeded its elapsed-time limit")
        entries += 1
        total_bytes += amount
        if entries > max_entries:
            raise ValidationError("source fingerprint exceeded its entry limit")
        if amount > per_file_limit:
            raise ValidationError(
                f"source fingerprint entry exceeded its byte limit: {relative}"
            )
        if total_bytes > aggregate_limit:
            raise ValidationError("source fingerprint exceeded its aggregate-byte limit")

    def add(relative: str, kind: str, mode: str, payload: bytes = b"") -> None:
        aggregate.update(relative.encode("utf-8", errors="strict"))
        aggregate.update(b"\0" + kind.encode() + b"\0" + mode.encode() + b"\0")
        aggregate.update(payload)
        aggregate.update(b"\0")

    def regular(
        parent: int,
        name: str,
        relative: str,
        metadata: os.stat_result,
        *,
        retain: bool = False,
    ) -> tuple[bytes, bytes | None]:
        if metadata.st_size > per_file_limit:
            account(relative, metadata.st_size)
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, dir_fd=parent)
        digest = hashlib.sha256()
        retained = bytearray() if retain else None
        size = 0
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            ):
                raise ValidationError(f"source identity changed: {relative}")
            while chunk := os.read(descriptor, CAPTURE_CHUNK):
                size += len(chunk)
                if size > per_file_limit:
                    account(relative, size)
                digest.update(chunk)
                if retained is not None:
                    retained.extend(chunk)
                if clock() - started > elapsed_timeout:
                    raise ValidationError(
                        "source fingerprint exceeded its elapsed-time limit"
                    )
            closed = os.fstat(descriptor)
            if (
                closed.st_size != opened.st_size
                or closed.st_mtime_ns != opened.st_mtime_ns
                or closed.st_ctime_ns != opened.st_ctime_ns
                or closed.st_mode != opened.st_mode
            ):
                raise ValidationError(f"source changed while fingerprinting: {relative}")
        finally:
            os.close(descriptor)
        account(relative, size)
        return digest.digest(), bytes(retained) if retained is not None else None

    root = os.dup(checkout_descriptor)
    if not stat.S_ISDIR(os.fstat(root).st_mode):
        os.close(root)
        raise ValidationError("retained checkout descriptor is not a directory")
    try:
        def walk(directory: int, prefix: str = "") -> None:
            before = os.fstat(directory)
            with os.scandir(directory) as scan:
                names: list[str] = []
                remaining_entries = max_entries - entries
                for entry in scan:
                    if clock() - started > elapsed_timeout:
                        raise ValidationError(
                            "source fingerprint exceeded its elapsed-time limit"
                        )
                    if not prefix and entry.name == ".git":
                        continue
                    if len(names) >= remaining_entries:
                        raise ValidationError(
                            "source fingerprint exceeded its entry limit"
                        )
                    names.append(entry.name)
                names.sort()
                if clock() - started > elapsed_timeout:
                    raise ValidationError(
                        "source fingerprint exceeded its elapsed-time limit"
                    )
            for name in names:
                relative = f"{prefix}/{name}" if prefix else name
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                mode = "755" if metadata.st_mode & 0o111 else "644"
                if stat.S_ISREG(metadata.st_mode):
                    content_digest, _ = regular(directory, name, relative, metadata)
                    add(relative, "file", mode, content_digest)
                elif stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(name, dir_fd=directory)
                    after = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (after.st_dev, after.st_ino, after.st_mtime_ns) != (
                        metadata.st_dev,
                        metadata.st_ino,
                        metadata.st_mtime_ns,
                    ):
                        raise ValidationError(f"source symlink changed: {relative}")
                    payload = target.encode("utf-8", errors="strict")
                    account(relative, len(payload))
                    add(relative, "symlink", "777", payload)
                elif stat.S_ISDIR(metadata.st_mode):
                    account(relative)
                    add(relative, "directory", mode)
                    child = os.open(name, _directory_flags(), dir_fd=directory)
                    try:
                        opened = os.fstat(child)
                        if (opened.st_dev, opened.st_ino) != (
                            metadata.st_dev,
                            metadata.st_ino,
                        ):
                            raise ValidationError(f"source directory changed: {relative}")
                        walk(child, relative)
                    finally:
                        os.close(child)
                else:
                    raise ValidationError(
                        f"source worktree has unsupported entry type: {relative}"
                    )
            after = os.fstat(directory)
            if (
                after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns
            ):
                raise ValidationError(
                    f"source directory changed while fingerprinting: {prefix or '.'}"
                )

        git = os.open(".git", _directory_flags(), dir_fd=root)
        try:
            git_before = os.fstat(git)
            for name in ("HEAD", "index"):
                relative = f".git/{name}"
                metadata = os.stat(name, dir_fd=git, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValidationError(f"{relative} is not a regular file")
                payload_digest, content = regular(
                    git,
                    name,
                    relative,
                    metadata,
                    retain=name == "HEAD",
                )
                if name == "HEAD":
                    if content != f"{AUDITED_SOURCE_COMMIT}\n".encode("ascii"):
                        raise ValidationError(".git/HEAD is not the audited detached commit")
                add(relative, "file", "755" if metadata.st_mode & 0o111 else "644", payload_digest)
            git_after = os.fstat(git)
            if (
                git_after.st_mtime_ns != git_before.st_mtime_ns
                or git_after.st_ctime_ns != git_before.st_ctime_ns
            ):
                raise ValidationError(".git changed while fingerprinting")
        finally:
            os.close(git)
        walk(root)
    finally:
        os.close(root)
    if clock() - started > elapsed_timeout:
        raise ValidationError("source fingerprint exceeded its elapsed-time limit")
    return aggregate.hexdigest()


def _open_checkout_identity(path: Path) -> CheckoutIdentity:
    canonical_path = Path(os.path.abspath(path))
    parent, _, basename = _open_repository_or_absolute_parent(canonical_path)
    try:
        descriptor = os.open(basename, _directory_flags(), dir_fd=parent)
    finally:
        os.close(parent)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ValidationError("checkout is not a directory")
    return CheckoutIdentity(
        canonical_path=canonical_path,
        descriptor=descriptor,
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def _verify_checkout_path_binding(identity: CheckoutIdentity) -> None:
    retained = os.fstat(identity.descriptor)
    if (
        not stat.S_ISDIR(retained.st_mode)
        or retained.st_dev != identity.device
        or retained.st_ino != identity.inode
    ):
        raise ValidationError("retained checkout identity changed during execution")
    parent, _, basename = _open_repository_or_absolute_parent(
        identity.canonical_path
    )
    try:
        current = os.open(basename, _directory_flags(), dir_fd=parent)
    finally:
        os.close(parent)
    try:
        metadata = os.fstat(current)
        if (
            metadata.st_dev != identity.device
            or metadata.st_ino != identity.inode
        ):
            raise ValidationError(
                "canonical checkout path no longer resolves to retained identity"
            )
    finally:
        os.close(current)


def _checkout_runtime_argument(
    argument: str,
    identity: CheckoutIdentity,
) -> str:
    canonical = str(identity.canonical_path)
    retained = f"/proc/self/fd/{identity.descriptor}"
    index = argument.find(canonical)
    if index < 0:
        return argument
    before = argument[:index]
    after = argument[index + len(canonical) :]
    if (before and before[-1] not in {"=", ":"}) or (
        after and not after.startswith("/")
    ):
        return argument
    return f"{before}{retained}{after}"


def _checkout_runtime_argv(
    argv: Sequence[str],
    identity: CheckoutIdentity,
) -> list[str]:
    canonical_config = str(identity.canonical_path / "nuget.config")
    return [
        (
            "nuget.config"
            if index > 0
            and argv[index - 1] == "--configfile"
            and argument == canonical_config
            else _checkout_runtime_argument(argument, identity)
        )
        for index, argument in enumerate(argv)
    ]


def _checkout_fingerprint(
    identity: CheckoutIdentity,
    **bounds: Any,
) -> str:
    fingerprint = _source_fingerprint(identity.descriptor, **bounds)
    _verify_checkout_path_binding(identity)
    return fingerprint


def _read_bounded_asset(
    source: Path,
    trusted_root: Path,
    trusted_root_descriptor: int,
) -> bytes:
    try:
        relative = source.relative_to(trusted_root)
    except ValueError as error:
        raise ValidationError(
            "project.assets.json is outside the verified selection root"
        ) from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValidationError("project.assets.json has a noncanonical relative path")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    descriptors: list[int] = [os.dup(trusted_root_descriptor)]
    try:
        if not stat.S_ISDIR(os.fstat(descriptors[0]).st_mode):
            raise ValidationError("verified selection root descriptor is not a directory")
        for component in relative.parts[:-1]:
            descriptors.append(
                os.open(component, directory_flags, dir_fd=descriptors[-1])
            )
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            relative.parts[-1],
            flags,
            dir_fd=descriptors[-1],
        )
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("project.assets.json is not a regular file")
        if metadata.st_size > ASSET_SOURCE_LIMIT:
            raise ValidationError(
                f"project.assets.json exceeds the {ASSET_SOURCE_LIMIT}-byte limit"
            )
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, CAPTURE_CHUNK):
            total += len(chunk)
            if total > ASSET_SOURCE_LIMIT:
                raise ValidationError(
                    f"project.assets.json exceeds the {ASSET_SOURCE_LIMIT}-byte limit"
                )
            chunks.append(chunk)
        payload = b"".join(chunks)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return payload


def _read_prevalidated_asset(
    source: Path,
    trusted_root: Path,
    trusted_root_descriptor: int,
) -> bytes:
    payload = _read_bounded_asset(
        source,
        trusted_root,
        trusted_root_descriptor,
    )
    if _contains_sensitive_output(payload.decode("utf-8", errors="replace")):
        raise ValidationError(
            "project.assets.json contains a credential or sensitive token pattern"
        )
    return payload


def _snapshot_restore_assets(
    bundle: dict[str, Any],
    baseline: dict[str, Any],
    mode: dict[str, Any],
    selection_identity: RootIdentity | None,
) -> dict[str, RestoreAssetSnapshot]:
    snapshots: dict[str, RestoreAssetSnapshot] = {}
    root_descriptor = (
        _open_verified_root_identity(selection_identity)
        if selection_identity is not None
        else None
    )
    if root_descriptor is None:
        reason = "restore-asset-snapshot-root-identity-unverified"
        return {
            target["id"]: RestoreAssetSnapshot(False, None, reason)
            for target in baseline["attempted_targets"]
        }
    try:
        for target in baseline["attempted_targets"]:
            target_id = target["id"]
            project_name = Path(target["project_path"]).stem
            source = Path(mode["obj_root"]) / project_name / "project.assets.json"
            try:
                payload = _read_bounded_asset(
                    source,
                    Path(bundle["isolation"]["selection_root"]),
                    root_descriptor,
                )
            except FileNotFoundError:
                snapshots[target_id] = RestoreAssetSnapshot(False, None, None)
            except (OSError, UnicodeError, ValidationError, ValueError) as error:
                snapshots[target_id] = RestoreAssetSnapshot(
                    False,
                    None,
                    "restore-asset-snapshot-unverifiable:"
                    + _sanitize_failure_reason(error),
                )
            else:
                snapshots[target_id] = RestoreAssetSnapshot(
                    True,
                    hashlib.sha256(payload).hexdigest(),
                    None,
                )
    finally:
        os.close(root_descriptor)
    return snapshots


def _retained_capture_matches(
    identity: CaptureIdentity,
    selection_identity: RootIdentity,
    selection_root_descriptor: int,
) -> bool:
    if (
        identity.directory_descriptor < 0
        or identity.leaf_size is None
        or identity.leaf_sha256 is None
        or not _retained_root_matches(
            selection_identity,
            selection_root_descriptor,
        )
    ):
        return False
    try:
        relative = identity.path.relative_to(selection_identity.path)
    except ValueError:
        return False
    if (
        len(relative.parts) != 2
        or relative.parts[0] != "captures"
        or relative.parts[1] != identity.path.name
    ):
        return False
    try:
        retained_parent = os.fstat(identity.directory_descriptor)
        current_parent, current_metadata, basename = (
            _open_repository_or_absolute_parent(identity.path)
        )
        try:
            if (
                basename != identity.path.name
                or not stat.S_ISDIR(retained_parent.st_mode)
                or retained_parent.st_dev != identity.directory_device
                or retained_parent.st_ino != identity.directory_inode
                or current_metadata.st_dev != identity.directory_device
                or current_metadata.st_ino != identity.directory_inode
            ):
                return False
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                basename,
                flags,
                dir_fd=identity.directory_descriptor,
            )
            try:
                metadata = os.fstat(descriptor)
                return (
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_dev == identity.leaf_device
                    and metadata.st_ino == identity.leaf_inode
                    and metadata.st_size == identity.leaf_size
                    and _descriptor_sha256(descriptor) == identity.leaf_sha256
                )
            finally:
                os.close(descriptor)
        finally:
            os.close(current_parent)
    except (OSError, RootCreationError, ValidationError):
        return False


def _write_exclusive_at(
    directory_descriptor: int,
    name: str,
    content: bytes,
    mode: int,
) -> os.stat_result:
    def cleanup_created(expected: os.stat_result | None) -> None:
        if expected is None:
            raise RecordingError(
                "exclusive recording candidate identity was not captured"
            )
        removed = _quarantine_owned_leaf(
            directory_descriptor,
            name,
            (expected.st_dev, expected.st_ino, None),
            context="exclusive recording candidate cleanup",
        )
        if not removed:
            raise RecordingError(
                "exclusive recording candidate identity changed before cleanup"
            )

    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
        dir_fd=directory_descriptor,
    )
    created: os.stat_result | None = None
    try:
        created = os.fstat(descriptor)
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("exclusive recording write made no progress")
            offset += written
        os.fsync(descriptor)
    except BaseException as error:
        cleanup_error: BaseException | None = None
        if created is None:
            try:
                created = os.fstat(descriptor)
            except OSError:
                pass
        try:
            cleanup_created(created)
        except BaseException as candidate_cleanup_error:
            cleanup_error = candidate_cleanup_error
        try:
            os.close(descriptor)
        except BaseException as close_error:
            cleanup_error = cleanup_error or close_error
        if cleanup_error is not None:
            raise RecordingError(
                f"exclusive recording candidate cleanup failed: {cleanup_error}"
            ) from error
        raise
    try:
        os.close(descriptor)
    except OSError as error:
        try:
            cleanup_created(created)
        except BaseException as cleanup_error:
            raise RecordingError(
                f"exclusive recording candidate cleanup failed: {cleanup_error}"
            ) from error
        raise
    if created is None:
        raise AssertionError("exclusive recording candidate identity was not captured")
    return created


def _published_asset_matches(identity: PublishedAssetIdentity) -> bool:
    try:
        retained_parent = os.fstat(identity.directory_descriptor)
        current_parent, current_metadata, basename = _open_repository_parent(
            identity.path
        )
        try:
            if (
                basename != identity.filename
                or retained_parent.st_dev != identity.directory_device
                or retained_parent.st_ino != identity.directory_inode
                or current_metadata.st_dev != identity.directory_device
                or current_metadata.st_ino != identity.directory_inode
            ):
                return False
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                identity.filename,
                flags,
                dir_fd=identity.directory_descriptor,
            )
            try:
                metadata = os.fstat(descriptor)
                return (
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_dev == identity.device
                    and metadata.st_ino == identity.inode
                    and _descriptor_sha256(descriptor) == identity.sha256
                )
            finally:
                os.close(descriptor)
        finally:
            os.close(current_parent)
    except (OSError, RootCreationError, ValidationError):
        return False


def _rollback_published_assets(
    published_assets: Sequence[PublishedAssetIdentity],
    *,
    identity_mismatch_is_error: bool = True,
) -> list[str]:
    errors: list[str] = []
    for identity in reversed(published_assets):
        try:
            removed = _quarantine_owned_leaf(
                identity.directory_descriptor,
                identity.filename,
                (identity.device, identity.inode, identity.sha256),
                context=f"published asset rollback for {identity.path}",
            )
            if not removed and identity_mismatch_is_error:
                errors.append(
                    f"published asset identity changed before rollback: {identity.path}"
                )
        except (OSError, RecordingError) as error:
            errors.append(_sanitize_failure_reason(error))
    return errors


def _atomic_publish_asset(
    payload: bytes,
    destination: Path,
    published_assets: list[PublishedAssetIdentity],
) -> PublishedAssetIdentity:
    directory_descriptor = -1
    directory_metadata: os.stat_result | None = None
    filename = destination.name
    temporary = f".{filename}.runner-{os.getpid()}-{time.monotonic_ns()}"
    descriptor: int | None = None
    registered: PublishedAssetIdentity | None = None
    temporary_identity: tuple[int, int, str | None] | None = None
    temporary_cleanup_attempted = False
    try:
        directory_descriptor, directory_metadata, filename = _open_repository_parent(
            destination,
            create=True,
        )
        temporary = f".{filename}.runner-{os.getpid()}-{time.monotonic_ns()}"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o644,
            dir_fd=directory_descriptor,
        )
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        temporary_metadata = os.fstat(descriptor)
        temporary_identity = (
            temporary_metadata.st_dev,
            temporary_metadata.st_ino,
            hashlib.sha256(payload).hexdigest(),
        )
        os.close(descriptor)
        descriptor = None
        os.link(
            temporary,
            filename,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        registered = PublishedAssetIdentity(
            path=destination,
            directory_descriptor=directory_descriptor,
            directory_device=directory_metadata.st_dev,
            directory_inode=directory_metadata.st_ino,
            filename=filename,
            device=temporary_metadata.st_dev,
            inode=temporary_metadata.st_ino,
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        published_assets.append(registered)
        directory_descriptor = -1
        if not _published_asset_matches(registered):
            raise AssetPublicationError(
                f"published asset identity differs from validated bytes: {destination}"
            )
        temporary_cleanup_attempted = True
        try:
            removed = _quarantine_owned_leaf(
                registered.directory_descriptor,
                temporary,
                temporary_identity,
                context=f"published asset staging cleanup for {destination}",
            )
            if not removed:
                raise RecordingError(
                    "published asset staging identity changed before cleanup"
                )
        except (OSError, RecordingError) as error:
            rollback_errors = _rollback_published_assets([registered])
            published_assets.remove(registered)
            registered.close()
            registered = None
            rollback_detail = (
                ""
                if not rollback_errors
                else "; published asset rollback is indeterminate: "
                + "; ".join(rollback_errors)
            )
            raise AssetPublicationError(
                f"published asset temporary cleanup failed: {error}{rollback_detail}"
            ) from error
        try:
            os.fsync(registered.directory_descriptor)
        except OSError as error:
            raise AssetPublicationError(
                f"published asset directory durability failed: {error}"
            ) from error
        return registered
    except FileExistsError:
        raise
    except AssetPublicationError as publication_error:
        if (
            registered is not None
            and temporary_identity is not None
            and not temporary_cleanup_attempted
        ):
            temporary_cleanup_attempted = True
            try:
                removed = _quarantine_owned_leaf(
                    registered.directory_descriptor,
                    temporary,
                    temporary_identity,
                    context=f"published asset staging cleanup for {destination}",
                )
                if not removed:
                    raise RecordingError(
                        "published asset staging identity changed before cleanup"
                    )
            except (OSError, RecordingError) as cleanup_error:
                raise AssetPublicationError(
                    "published asset failure left staging cleanup indeterminate: "
                    f"{cleanup_error}"
                ) from publication_error
        raise
    except OSError as error:
        if (
            registered is not None
            and temporary_identity is not None
            and not temporary_cleanup_attempted
        ):
            temporary_cleanup_attempted = True
            try:
                removed = _quarantine_owned_leaf(
                    registered.directory_descriptor,
                    temporary,
                    temporary_identity,
                    context=f"published asset staging cleanup for {destination}",
                )
                if not removed:
                    raise RecordingError(
                        "published asset staging identity changed before cleanup"
                    )
            except (OSError, RecordingError) as cleanup_error:
                raise AssetPublicationError(
                    "asset publication and staging cleanup are indeterminate: "
                    f"{cleanup_error}"
                ) from error
        raise AssetPublicationError(
            f"cannot publish retained asset {destination}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor >= 0:
            cleanup_error: BaseException | None = None
            if temporary_identity is not None and not temporary_cleanup_attempted:
                try:
                    removed = _quarantine_owned_leaf(
                        directory_descriptor,
                        temporary,
                        temporary_identity,
                        context=f"published asset staging cleanup for {destination}",
                    )
                    if not removed:
                        raise RecordingError(
                            "published asset staging identity changed before cleanup"
                        )
                except BaseException as error:
                    cleanup_error = error
            os.close(directory_descriptor)
            if cleanup_error is not None:
                raise AssetPublicationError(
                    f"published asset staging cleanup is indeterminate: {cleanup_error}"
                ) from cleanup_error


def _dependency_evidence(
    bundle: dict[str, Any],
    baseline: dict[str, Any],
    outcomes: list[dict[str, Any]],
    *,
    inspection_blocker: str | None,
    published_assets: list[PublishedAssetIdentity],
    selection_root_descriptor: int | None,
    restore_asset_snapshots: dict[str, dict[str, RestoreAssetSnapshot]],
) -> dict[str, Any]:
    outcomes_by_id = {item["command_id"]: item for item in outcomes}
    modes: list[dict[str, Any]] = []
    for mode in bundle["isolation"]["source_modes"]:
        mode_id = mode["id"]
        restore_id = f"{mode_id}-restore"
        restore = outcomes_by_id[restore_id]
        target_evidence: list[dict[str, Any]] = []
        for target in baseline["attempted_targets"]:
            target_id = target["id"]
            target_key = f"{mode_id}/{target_id}"
            project_name = Path(target["project_path"]).stem
            source = Path(mode["obj_root"]) / project_name / "project.assets.json"
            destination = (
                ASSETS_DIRECTORY
                / dependency_asset_path(
                    bundle["id"],
                    mode_id,
                    target_id,
                ).name
            )
            reason: str | None = None
            status = "valid"
            asset: dict[str, Any] | None = None
            snapshot = restore_asset_snapshots.get(mode_id, {}).get(target_id)
            if inspection_blocker is not None:
                status, reason = "invalid", inspection_blocker
            elif snapshot is None:
                status, reason = "invalid", "restore-asset-snapshot-unavailable"
            elif snapshot.failure_reason is not None:
                status, reason = "invalid", snapshot.failure_reason
            else:
                try:
                    if selection_root_descriptor is None:
                        raise ValidationError(
                            "verified selection root descriptor is unavailable"
                        )
                    asset_bytes = _read_prevalidated_asset(
                        source,
                        Path(bundle["isolation"]["selection_root"]),
                        selection_root_descriptor,
                    )
                    asset_sha256 = hashlib.sha256(asset_bytes).hexdigest()
                    if not snapshot.present:
                        raise ValidationError(
                            "project-assets-appeared-after-restore"
                        )
                    if asset_sha256 != snapshot.sha256:
                        raise ValidationError(
                            "project-assets-changed-after-restore"
                        )
                    projection = extract_projection(
                        parse_json_object_bytes(asset_bytes, source.as_posix()),
                        asset_bytes,
                        baseline,
                        target_id,
                        "linux-x64",
                        mode["checkout_root"],
                    )
                    _atomic_publish_asset(asset_bytes, destination, published_assets)
                    asset = {
                        "path": dependency_asset_path(
                            bundle["id"],
                            mode_id,
                            target_id,
                        ).as_posix(),
                        "sha256": asset_sha256,
                        "projection": projection,
                        "provenance": {
                            "retrieval_source_evidence": [restore_id],
                            "access_evidence": [restore_id],
                            "initial_cache_evidence": [
                                f"{mode_id}-initial-nuget-cache"
                            ],
                        },
                    }
                except FileNotFoundError:
                    if snapshot.present:
                        status = "invalid"
                        reason = "project-assets-changed-after-restore"
                    else:
                        status = "missing"
                        reason = "project-assets-missing"
                except (
                    ExtractionError,
                    FileExistsError,
                    OSError,
                    UnicodeError,
                    ValueError,
                ) as error:
                    status = "invalid"
                    reason = _sanitize_failure_reason(error)
            unresolved = []
            if status != "valid":
                declarations = [
                declaration
                for declaration in baseline["source_declared_direct"]
                if declaration["kind"] == "package"
                and condition_applies(declaration["condition"], "linux-x64")
                and target_id in declaration["targets"]
                ]
                unresolved = [
                    {
                        "declaration_id": declaration["declaration_id"],
                        "failure_evidence_refs": [
                            target_key,
                            *([restore_id] if restore["status"] == "failed" else []),
                        ],
                    }
                    for declaration in declarations
                ]
            item = {
                "target_id": target_id,
                "status": status,
                "reason": reason,
                "unresolved_declarations": unresolved,
            }
            if asset is not None:
                item["asset"] = asset
            target_evidence.append(item)
        modes.append(
            {"source_mode": mode_id, "targets": target_evidence}
        )
    return {"modes": modes}


def _renameat2(
    directory_descriptor: int,
    left: str,
    right: str,
    flags: int,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        SYS_RENAMEAT2_X86_64,
        directory_descriptor,
        os.fsencode(left),
        directory_descriptor,
        os.fsencode(right),
        flags,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _rename_exchange(directory_descriptor: int, left: str, right: str) -> None:
    _renameat2(directory_descriptor, left, right, RENAME_EXCHANGE)


def _rename_noreplace(directory_descriptor: int, left: str, right: str) -> None:
    _renameat2(directory_descriptor, left, right, RENAME_NOREPLACE)


def _open_recording_identity(path: Path) -> CanonicalBundleIdentity:
    parent_descriptor, parent_metadata, basename = _open_repository_parent(path)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(basename, flags, dir_fd=parent_descriptor)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        os.close(parent_descriptor)
        raise ValidationError("planned bundle is not a regular file")
    return CanonicalBundleIdentity(
        canonical_path=Path(os.path.abspath(path)),
        descriptor=descriptor,
        parent_descriptor=parent_descriptor,
        parent_device=parent_metadata.st_dev,
        parent_inode=parent_metadata.st_ino,
        basename=basename,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        sha256=_descriptor_sha256(descriptor),
    )


def _leaf_identity(
    directory_descriptor: int,
    name: str,
) -> tuple[int, int, str]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RecordingError(f"recording leaf is not a regular file: {name}")
        return metadata.st_dev, metadata.st_ino, _descriptor_sha256(descriptor)
    finally:
        os.close(descriptor)


def _quarantine_owned_leaf(
    directory_descriptor: int,
    name: str,
    expected: tuple[int, int, str | None],
    *,
    context: str,
    committed: bool = False,
) -> bool:
    quarantine = f".runner-quarantine-{secrets.token_hex(24)}"
    try:
        _rename_noreplace(directory_descriptor, name, quarantine)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RecordingError(
            f"{context}: atomic quarantine move failed: {error}",
            committed=committed,
        ) from error
    try:
        actual = _leaf_identity(directory_descriptor, quarantine)
    except BaseException as error:
        raise RecordingError(
            f"{context}: quarantined leaf inspection is indeterminate; "
            f"preserved as {quarantine}",
            committed=committed,
        ) from error
    matches = (
        actual[:2] == expected[:2]
        and (expected[2] is None or actual[2] == expected[2])
    )
    if not matches:
        try:
            _rename_noreplace(directory_descriptor, quarantine, name)
        except BaseException as error:
            raise RecordingError(
                f"{context}: unexpected leaf preserved as {quarantine}; "
                "restoration is indeterminate",
                committed=committed,
            ) from error
        try:
            os.fsync(directory_descriptor)
        except OSError as error:
            if committed:
                raise RecordingError(
                    f"{context}: unexpected leaf restoration durability is uncertain",
                    committed=True,
                ) from error
            raise RecordingError(
                f"{context}: unexpected leaf restoration durability is uncertain"
            ) from error
        return False
    try:
        os.unlink(quarantine, dir_fd=directory_descriptor)
    except OSError as error:
        raise RecordingError(
            f"{context}: verified invocation leaf cleanup is indeterminate; "
            f"preserved as {quarantine}",
            committed=committed,
        ) from error
    try:
        os.fsync(directory_descriptor)
    except OSError as error:
        if committed:
            raise RecordingError(
                f"{context}: verified cleanup durability is uncertain",
                committed=True,
            ) from error
        raise RecordingError(
            f"{context}: verified cleanup durability is uncertain"
        ) from error
    return True


def _atomic_replace_bundle(
    identity: CanonicalBundleIdentity,
    bundle: dict[str, Any],
    published_assets: Sequence[PublishedAssetIdentity],
    precommit_check: Callable[[], RecordingRetry | None] | None = None,
) -> None:
    payload = (
        json.dumps(bundle, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")
    temporary = (
        f".{identity.basename}.recorded-{os.getpid()}-{time.monotonic_ns()}"
    )
    candidate_identity: tuple[int, int, str] | None = None
    exchanged = False
    assets_rolled_back = False

    def rollback_assets(context: str) -> None:
        nonlocal assets_rolled_back
        if assets_rolled_back:
            return
        rollback_errors = _rollback_published_assets(
            published_assets,
            identity_mismatch_is_error=False,
        )
        assets_rolled_back = True
        if rollback_errors:
            raise RecordingError(
                f"{context}; invocation asset rollback is indeterminate: "
                + "; ".join(rollback_errors)
            )

    def restore_after_exchange(
        reason: str,
        error: BaseException | None = None,
        retry: RecordingRetry | None = None,
    ) -> None:
        nonlocal exchanged
        if candidate_identity is None:
            raise AssertionError("recording exchange lacks candidate identity")
        expected_plan = (identity.device, identity.inode, identity.sha256)
        try:
            current = _leaf_identity(
                identity.parent_descriptor,
                identity.basename,
            )
            displaced = _leaf_identity(
                identity.parent_descriptor,
                temporary,
            )
            if current != candidate_identity or displaced != expected_plan:
                raise RecordingError(
                    "recorded bundle exchange state changed before safe reversal",
                    committed=True,
                )
            _rename_exchange(
                identity.parent_descriptor,
                temporary,
                identity.basename,
            )
            _verify_canonical_bundle_identity(identity)
            returned_candidate = _leaf_identity(
                identity.parent_descriptor,
                temporary,
            )
            if returned_candidate != candidate_identity:
                raise RecordingError(
                    "canonical compare-and-swap reversal could not be verified",
                    committed=True,
                )
            os.fsync(identity.parent_descriptor)
            exchanged = False
        except BaseException as restore_error:
            if isinstance(restore_error, RecordingError) and restore_error.committed:
                raise
            raise RecordingError(
                "recorded bundle exchange could not be safely restored",
                committed=True,
            ) from restore_error
        if retry is not None:
            raise retry
        try:
            rollback_assets(reason)
        except RecordingError as rollback_error:
            raise rollback_error from error
        raise RecordingError(reason) from error

    try:
        candidate_metadata = _write_exclusive_at(
            identity.parent_descriptor,
            temporary,
            payload,
            0o600,
        )
        candidate_identity = (
            candidate_metadata.st_dev,
            candidate_metadata.st_ino,
            hashlib.sha256(payload).hexdigest(),
        )
        try:
            _verify_canonical_bundle_identity(identity)
            if not all(
                _published_asset_matches(asset)
                for asset in published_assets
            ):
                raise RecordingError(
                    "published asset identity changed before recorded bundle exchange"
                )
            if precommit_check is not None:
                retry = precommit_check()
                if retry is not None:
                    raise retry
        except RecordingRetry:
            raise
        except BaseException as error:
            try:
                rollback_assets("recorded bundle pre-exchange verification failed")
            except RecordingError as rollback_error:
                raise rollback_error from error
            if isinstance(error, RecordingError):
                raise
            raise RecordingError(
                f"recorded bundle pre-exchange verification failed: {error}"
            ) from error
        _rename_exchange(
            identity.parent_descriptor,
            temporary,
            identity.basename,
        )
        exchanged = True
        try:
            current = _leaf_identity(
                identity.parent_descriptor,
                identity.basename,
            )
            displaced = _leaf_identity(identity.parent_descriptor, temporary)
            _verify_canonical_parent_binding(identity)
            assets_match = all(
                _published_asset_matches(asset)
                for asset in published_assets
            )
            retry = precommit_check() if precommit_check is not None else None
        except BaseException as error:
            restore_after_exchange(
                "recorded bundle post-exchange verification failed",
                error,
            )
        expected = (identity.device, identity.inode, identity.sha256)
        if displaced != expected:
            raise RecordingError(
                "recorded bundle displaced plan identity changed after exchange; "
                "commit outcome is indeterminate",
                committed=True,
            )
        if current != candidate_identity or not assets_match:
            restore_after_exchange(
                "recorded bundle or published asset identity changed during "
                "atomic compare-and-swap"
            )
        if retry is not None:
            restore_after_exchange(
                f"recording commit deferred by {retry.reason}",
                retry=retry,
            )
        try:
            removed = _quarantine_owned_leaf(
                identity.parent_descriptor,
                temporary,
                (identity.device, identity.inode, identity.sha256),
                context="recorded bundle displaced-plan cleanup",
                committed=True,
            )
            if not removed:
                raise RecordingError(
                    "recorded bundle displaced plan changed before cleanup",
                    committed=True,
                )
        except (OSError, RecordingError) as error:
            if isinstance(error, RecordingError) and error.committed:
                raise
            raise RecordingError(
                f"recorded bundle committed but displaced plan cleanup failed: {error}",
                committed=True,
            ) from error
        try:
            os.fsync(identity.parent_descriptor)
        except OSError as error:
            raise RecordingError(
                f"recorded bundle committed but parent durability is uncertain: {error}",
                committed=True,
            ) from error
    except RecordingRetry:
        raise
    except RecordingError as error:
        if not error.committed and not exchanged and not assets_rolled_back:
            try:
                rollback_assets("recorded bundle replacement failed")
            except RecordingError as rollback_error:
                raise rollback_error from error
        raise
    except BaseException as error:
        if exchanged:
            raise RecordingError(
                f"recorded bundle exchange completed but outcome is indeterminate: {error}",
                committed=True,
            ) from error
        try:
            rollback_assets("recorded bundle replacement failed")
        except RecordingError as rollback_error:
            raise rollback_error from error
        if not isinstance(error, OSError):
            raise
        raise RecordingError(f"recorded bundle replacement failed: {error}") from error
    finally:
        if not exchanged and candidate_identity is not None:
            removed = _quarantine_owned_leaf(
                identity.parent_descriptor,
                temporary,
                candidate_identity,
                context="recorded bundle candidate cleanup",
            )
            if not removed:
                raise RecordingError(
                    "recorded bundle candidate changed before cleanup"
                )


def _blocked_outcomes(commands: list[dict[str, Any]], blocker: str) -> list[dict[str, Any]]:
    return [
        {
            "command_id": command["id"],
            "status": "blocked",
            "attempts": [],
            "unspawned_termination": None,
            "source_integrity_failure": None,
            "blocked_by": blocker,
        }
        for command in commands
    ]


def _execute_planned_bundle(
    bundle_path: Path,
    bundle: dict[str, Any],
    *,
    source_baseline: dict[str, Any],
    mise_lock_bytes: bytes,
    mise_identity: ExecutableIdentity,
    git_executable: Path,
    subreaper_enabled: bool,
    planned_identity: CanonicalBundleIdentity | None = None,
    cancel_event: threading.Event | None = None,
    checkout_identities: dict[str, CheckoutIdentity],
) -> dict[str, Any]:
    if not subreaper_enabled or not child_subreaper_enabled():
        raise CapabilityError(
            "planned execution requires the verified child subreaper state"
        )
    cancel_event = cancel_event or threading.Event()
    recording_identity = planned_identity or _open_recording_identity(bundle_path)
    owns_recording_identity = planned_identity is None
    toolchain_root = Path(bundle["isolation"]["toolchain_root"])
    selection_root = Path(bundle["isolation"]["selection_root"])
    toolchain_base = toolchain_root.parent
    selection_base = selection_root.parent
    commands = bundle["protocol"]["commands"]
    bounds = bundle["protocol"]["supervision_bounds"]
    observations: list[dict[str, Any]] = []
    preparations: list[dict[str, Any]] = []
    toolchain_identity: RootIdentity | None = None
    selection_identity: RootIdentity | None = None
    selection_root_descriptor: int | None = None
    orchestration_stop: dict[str, Any] | None = None
    published_assets: list[PublishedAssetIdentity] = []
    retained_capture_groups: list[RetainedCaptureGroup] = []
    restore_asset_snapshots: dict[
        str, dict[str, RestoreAssetSnapshot]
    ] = {}
    topology_by_id = PREPARATION_BY_ID

    def observe_cancellation(next_kind: str, next_id: str) -> None:
        nonlocal orchestration_stop
        if cancel_event.is_set() and orchestration_stop is None:
            orchestration_stop = {
                "subject_kind": "orchestration",
                "subject_id": next_id,
                "phase": f"before-{next_kind}",
            }

    def decision() -> dict[str, Any]:
        return reduce_runtime(
            preparations,
            [],
            commands,
            observations,
            orchestration_stop=orchestration_stop,
        )

    def blocked_by(spec: Any) -> str | None:
        state = decision()
        return state["global_blocker"] or (
            state["mode_blockers"].get(spec.source_mode)
            if spec.source_mode is not None
            else None
        )

    def preparation_record(
        identifier: str,
        *,
        status: str,
        attempts: list[dict[str, Any]],
        failure_reason: str | None,
    ) -> dict[str, Any]:
        spec = topology_by_id[identifier]
        return {
            "id": identifier,
            "status": status,
            "attempts": attempts,
            "failure_reason": failure_reason,
        }

    def in_process_preparation(identifier: str, operation: Any) -> Any | None:
        spec = topology_by_id[identifier]
        observe_cancellation("preparation", identifier)
        blocker = blocked_by(spec)
        if blocker is not None:
            preparations.append(
                preparation_record(
                    identifier,
                    status="blocked",
                    attempts=[],
                    failure_reason=f"blocked-by:{blocker}",
                )
            )
            return None
        try:
            result = operation()
        except (
            ExtractionError,
            OSError,
            RootCreationError,
            UnicodeError,
            ValidationError,
            ValueError,
        ) as error:
            reason = _sanitize_failure_reason(error)
            if identifier in CHECKOUT_BOUND_PREPARATION_IDS:
                reason = append_failure_reason_marker(
                    reason,
                    SOURCE_INTEGRITY_CHANGED_MARKER,
                )
            preparations.append(
                preparation_record(
                    identifier,
                    status="failed",
                    attempts=[],
                    failure_reason=reason,
                )
            )
            return None
        preparations.append(
            preparation_record(
                identifier,
                status="passed",
                attempts=[],
                failure_reason=None,
            )
        )
        return result

    def root_preparation(identifier: str, operation: Any) -> RootIdentity | None:
        spec = topology_by_id[identifier]
        observe_cancellation("preparation", identifier)
        blocker = blocked_by(spec)
        if blocker is not None:
            preparations.append(
                preparation_record(
                    identifier,
                    status="blocked",
                    attempts=[],
                    failure_reason=f"blocked-by:{blocker}",
                )
            )
            return None
        try:
            result = operation()
        except RootCreationError as error:
            preparations.append(
                preparation_record(
                    identifier,
                    status="failed",
                    attempts=[],
                    failure_reason=_sanitize_failure_reason(error),
                )
            )
            return (
                error.partial_identity
                if isinstance(error.partial_identity, RootIdentity)
                else None
            )
        preparations.append(
            preparation_record(
                identifier,
                status="passed",
                attempts=[],
                failure_reason=None,
            )
        )
        return result

    def child_preparation(
        identifier: str,
        argv: Sequence[str],
        cwd: Path,
        env: dict[str, str],
        timeout: float = 900,
        metadata_limit: int = 0,
        executable_fd: int | None = None,
        checkout_identity: CheckoutIdentity | None = None,
    ) -> SupervisedResult | None:
        spec = topology_by_id[identifier]
        observe_cancellation("preparation", identifier)
        blocker = blocked_by(spec)
        if blocker is not None:
            preparations.append(
                preparation_record(
                    identifier,
                    status="blocked",
                    attempts=[],
                    failure_reason=f"blocked-by:{blocker}",
                )
            )
            return None
        runtime_argv = list(argv)
        runtime_cwd = cwd
        retained_fds: tuple[int, ...] = ()
        checkout_binding_failure: str | None = None
        if checkout_identity is not None:
            try:
                _verify_checkout_path_binding(checkout_identity)
            except (OSError, ValidationError) as error:
                checkout_binding_failure = _sanitize_failure_reason(error)
            runtime_argv = _checkout_runtime_argv(argv, checkout_identity)
            runtime_cwd = Path(f"/proc/self/fd/{checkout_identity.descriptor}")
            retained_fds = (checkout_identity.descriptor,)
        result, attempt = _run_subject(
            identifier,
            "preparation",
            runtime_argv,
            cwd=runtime_cwd,
            env=env,
            timeout_seconds=timeout,
            capture_dir=selection_root / "captures",
            cancel_event=cancel_event,
            observations=observations,
            subreaper_enabled=subreaper_enabled,
            stdout_metadata_limit=metadata_limit,
            executable_fd=executable_fd,
            retained_fds=retained_fds,
            bounds=bounds,
            retained_capture_groups=retained_capture_groups,
        )
        passed = result.termination == "completed" and result.exit_code == 0
        preparations.append(
            preparation_record(
                identifier,
                status="passed" if passed else "failed",
                attempts=[] if attempt is None else [attempt],
                failure_reason=None if passed else (
                    result.failure_reason
                    or f"child-exit:{result.exit_code}"
                ),
            )
        )
        if checkout_identity is not None:
            try:
                _verify_checkout_path_binding(checkout_identity)
            except (OSError, ValidationError) as error:
                checkout_binding_failure = (
                    checkout_binding_failure or _sanitize_failure_reason(error)
                )
        if checkout_binding_failure is not None:
            preparation = preparations[-1]
            preparation["status"] = "failed"
            preparation["failure_reason"] = append_failure_reason_marker(
                preparation["failure_reason"],
                SOURCE_INTEGRITY_CHANGED_MARKER,
            )
        return result

    def invalidate_last_preparation(identifier: str, reason: str) -> None:
        if preparations[-1]["id"] != identifier:
            raise AssertionError("preparation validation order differs from the topology")
        preparation = preparations[-1]
        if has_failure_reason_marker(
            preparation["failure_reason"],
            SOURCE_INTEGRITY_CHANGED_MARKER,
        ):
            retained_reasons = FAILURE_REASON_SEPARATOR.join(
                part
                for part in preparation["failure_reason"].split(
                    FAILURE_REASON_SEPARATOR
                )
                if part != SOURCE_INTEGRITY_CHANGED_MARKER
            )
            semantic_reason = (
                reason
                if not retained_reasons
                else f"{retained_reasons}{FAILURE_REASON_SEPARATOR}{reason}"
            )
            preparation["status"] = "failed"
            preparation["failure_reason"] = append_failure_reason_marker(
                semantic_reason,
                SOURCE_INTEGRITY_CHANGED_MARKER,
            )
            return
        if preparation["status"] != "passed":
            return
        preparation["status"] = "failed"
        preparation["failure_reason"] = reason

    created_toolchain = root_preparation(
        "prepare-toolchain-root",
        lambda: create_exclusive_root(
                toolchain_root,
                toolchain_base,
                {"bundle": bundle["id"], "kind": "toolchain", "retention": "always"},
        ),
    )
    if isinstance(created_toolchain, RootIdentity):
        toolchain_identity = created_toolchain
    created_selection = root_preparation(
        "prepare-selection-root",
        lambda: create_exclusive_root(
                selection_root,
                selection_base,
                {"bundle": bundle["id"], "kind": "selection", "retention": "always"},
        ),
    )
    if isinstance(created_selection, RootIdentity):
        selection_identity = created_selection

    mode_by_id = {
        mode["id"]: mode for mode in bundle["isolation"]["source_modes"]
    }
    if selection_identity is not None:
        paths: list[Path] = [selection_root / "captures"]
        for mode in mode_by_id.values():
            paths.extend(
                [
                    Path(mode[key])
                    for key in (
                        "home_root",
                        "nuget_packages_root",
                        "nuget_http_cache_root",
                        "nuget_plugins_cache_root",
                        "nuget_scratch_root",
                        "temporary_root",
                        "obj_root",
                        "bin_root",
                        "package_output_root",
                    )
                ]
            )
            generated = mode["generated_nuget_config"]
            if generated is not None:
                paths.append(Path(generated).parent)
        in_process_preparation("prepare-selection-directories", lambda: _mkdirs(paths))
    else:
        in_process_preparation("prepare-selection-directories", lambda: None)
    in_process_preparation(
        "prepare-dotnet-sdk-selection",
        lambda: _write_exclusive(
            Path(bundle["environment"]["dotnet_sdk"]["global_json_path"]),
            bundle["environment"]["dotnet_sdk"]["global_json_content"].encode(
                "utf-8"
            ),
        ),
    )

    if toolchain_identity is not None:
        toolchain_paths = [
            toolchain_root / child
            for child in (
                "cache",
                "config",
                "home",
                "state",
                "tmp",
                "xdg-data",
                "config-work",
            )
        ]
        in_process_preparation(
            "prepare-toolchain-directories", lambda: _mkdirs(toolchain_paths)
        )
        in_process_preparation(
            "prepare-reviewed-mise-config",
            lambda: _write_mise_config(
                toolchain_root,
                bundle,
                mise_lock_bytes,
            ),
        )
    else:
        in_process_preparation("prepare-toolchain-directories", lambda: None)
        in_process_preparation("prepare-reviewed-mise-config", lambda: None)

    mise_executable = mise_identity.path
    mise_env = mise_environment(toolchain_root)
    mise_version_result = child_preparation(
        "mise-version",
        [str(mise_executable), "--version"],
        toolchain_root / "config-work",
        mise_env,
        60,
        4096,
        mise_identity.descriptor,
    )
    if (
        mise_version_result is not None
        and mise_version_result.termination == "completed"
        and (
            mise_version_result.stdout_metadata is None
            or not mise_version_result.stdout_metadata.decode(
                "utf-8",
                errors="replace",
            ).startswith(f"{MISE_VERSION} ")
        )
    ):
        invalidate_last_preparation(
            "mise-version",
            "mise-version-output-did-not-match-reviewed-version",
        )
    child_preparation(
        "mise-install-dotnet-sdk",
        [
            str(mise_executable),
            "--no-env",
            "--no-hooks",
            "--locked",
            "install",
            "--jobs=1",
            (
                f"{bundle['environment']['mise']['tool_name']}@"
                f"{bundle['environment']['dotnet_sdk']['version']}"
            ),
        ],
        toolchain_root / "config-work",
        mise_env,
        1800,
        executable_fd=mise_identity.descriptor,
    )
    dotnet = Path(bundle["environment"]["dotnet_sdk"]["host_path"])
    dotnet_root = Path(bundle["environment"]["dotnet_sdk"]["installation_root"])
    in_process_preparation(
        "verify-dotnet-installation",
        lambda: (
            None
            if dotnet.is_file()
            and os.access(dotnet, os.X_OK)
            and dotnet.resolve().is_relative_to(toolchain_root.resolve())
            else (_ for _ in ()).throw(ValidationError("mise did not create the fixed .NET host"))
        ),
    )
    nuget_client_probe = in_process_preparation(
        "inspect-nuget-client-version",
        lambda: _inspect_nuget_client_version(dotnet_root),
    )

    source_fingerprints: dict[str, str] = {}
    cache_observations: list[dict[str, Any]] = []
    for mode_id in ("source-faithful", "public-only"):
        mode = mode_by_id[mode_id]
        checkout = Path(mode["checkout_root"])
        git_env = git_environment(mode, git_executable)
        child_preparation(
            f"git-{mode_id}-init",
            [str(git_executable), "init", str(checkout)],
            selection_root,
            git_env,
            120,
        )
        if preparations[-1]["status"] == "passed":
            checkout_identity: CheckoutIdentity | None = None
            try:
                checkout_identity = _open_checkout_identity(checkout)
                _verify_checkout_path_binding(checkout_identity)
            except (OSError, ValidationError) as error:
                if checkout_identity is not None:
                    checkout_identity.close()
                invalidate_last_preparation(
                    f"git-{mode_id}-init",
                    _sanitize_failure_reason(error),
                )
            else:
                checkout_identities[mode_id] = checkout_identity
        checkout_identity = checkout_identities.get(mode_id)
        child_preparation(
            f"git-{mode_id}-fetch",
            [
                str(git_executable),
                "-C",
                str(checkout),
                "fetch",
                "--depth=1",
                "--no-tags",
                AUDITED_SOURCE_REPOSITORY,
                AUDITED_SOURCE_COMMIT,
            ],
            selection_root,
            git_env,
            900,
            checkout_identity=checkout_identity,
        )
        child_preparation(
            f"git-{mode_id}-checkout",
            [
                str(git_executable),
                "-C",
                str(checkout),
                "checkout",
                "--detach",
                AUDITED_SOURCE_COMMIT,
            ],
            selection_root,
            git_env,
            120,
            checkout_identity=checkout_identity,
        )
        rev_parse = child_preparation(
            f"git-{mode_id}-verify-head",
            [str(git_executable), "-C", str(checkout), "rev-parse", "HEAD"],
            selection_root,
            git_env,
            60,
            4096,
            checkout_identity=checkout_identity,
        )
        if rev_parse is not None and rev_parse.termination == "completed":
            try:
                head = (
                    rev_parse.stdout_metadata or b""
                ).decode("ascii", errors="strict").strip()
            except UnicodeError as error:
                head = ""
                invalidate_last_preparation(
                    f"git-{mode_id}-verify-head",
                    _sanitize_failure_reason(error),
                )
            if head != AUDITED_SOURCE_COMMIT:
                invalidate_last_preparation(
                    f"git-{mode_id}-verify-head",
                    "git-head-did-not-match-audited-commit",
                )
        fingerprint_id = f"{mode_id}-integrity-baseline"
        fingerprint = in_process_preparation(
            fingerprint_id,
            lambda checkout_identity=checkout_identity: (
                (_ for _ in ()).throw(
                    ValidationError("retained checkout descriptor is unavailable")
                )
                if checkout_identity is None
                else (
                    _checkout_fingerprint(
                        checkout_identity,
                        max_entries=bounds["source_max_entries"],
                        per_file_limit=bounds["source_per_file_bytes"],
                        aggregate_limit=bounds["source_aggregate_bytes"],
                        elapsed_timeout=bounds["source_elapsed_seconds"],
                    ),
                )[0]
            ),
        )
        if isinstance(fingerprint, str):
            source_fingerprints[mode_id] = fingerprint
        if mode_id == "public-only":
            public_config = mode["generated_nuget_config"]
            in_process_preparation(
                "generate-public-only-nuget-config",
                lambda: _write_public_nuget_config(Path(public_config)),
            )
        props_preparation = f"generate-{mode_id}-directory-packages-props"
        in_process_preparation(
            props_preparation,
            lambda mode=mode: _write_directory_packages_props(
                Path(mode["generated_directory_packages_props"])
            ),
        )
        empty_preparation = f"verify-{mode_id}-nuget-roots-empty"
        empty_paths = in_process_preparation(
            empty_preparation,
            lambda mode=mode: _verify_nuget_roots_empty(mode),
        )
        mode = mode_by_id[mode_id]
        dotnet_env = dotnet_environment(mode, dotnet_root)
        dotnet_info = child_preparation(
            f"dotnet-{mode_id}-info",
            [str(dotnet), "--info"],
            Path(mode["checkout_root"]),
            dotnet_env,
            120,
            CAPTURE_LIMIT,
            checkout_identity=checkout_identity,
        )
        if (
            dotnet_info is not None
            and dotnet_info.termination == "completed"
            and (
                dotnet_info.stdout_metadata is None
                or DOTNET_SDK_VERSION
                not in dotnet_info.stdout_metadata.decode(
                    "utf-8",
                    errors="replace",
                )
            )
        ):
            invalidate_last_preparation(
                f"dotnet-{mode_id}-info",
                "dotnet-info-did-not-report-reviewed-sdk",
            )
        cache_preparation = f"dotnet-{mode_id}-nuget-cache-locations"
        cache_locations = child_preparation(
            cache_preparation,
            [str(dotnet), "nuget", "locals", "all", "--list"],
            Path(mode["checkout_root"]),
            dotnet_env,
            120,
            64 * 1024,
            checkout_identity=checkout_identity,
        )
        if (
            cache_locations is not None
            and cache_locations.termination == "completed"
            and cache_locations.exit_code == 0
        ):
            try:
                effective_paths = _parse_nuget_cache_locations(
                    cache_locations.stdout_metadata or b"",
                    mode,
                )
            except ValidationError as error:
                invalidate_last_preparation(
                    cache_preparation,
                    _sanitize_failure_reason(error),
                )
            else:
                if isinstance(empty_paths, dict):
                    cache_observations.append(
                        {
                            "id": f"{mode_id}-initial-nuget-cache",
                            "source_mode": mode_id,
                            "kind": "nuget-cache-initial-state",
                            "preparation_refs": [
                                empty_preparation,
                                cache_preparation,
                            ],
                            "effective_paths": effective_paths,
                            "initial_empty": True,
                        }
                    )

    outcomes = _blocked_outcomes(commands, "not-executed")
    outcomes_by_id = {outcome["command_id"]: outcome for outcome in outcomes}
    for command in commands:
        command_id = command["id"]
        mode_id = command["source_mode"]
        dependency = command["depends_on"]
        observe_cancellation("command", command_id)
        state = reduce_runtime(
            preparations,
            outcomes,
            commands,
            observations,
            orchestration_stop=orchestration_stop,
        )
        blocker = state["global_blocker"] or state["mode_blockers"].get(mode_id)
        if blocker is not None:
            outcomes_by_id[command_id]["blocked_by"] = blocker
            continue
        if dependency is not None and outcomes_by_id[dependency]["status"] != "passed":
            outcomes_by_id[command_id].update(
                {
                    "blocked_by": dependency,
                }
            )
            continue
        mode = mode_by_id[mode_id]
        checkout_identity = checkout_identities.get(mode_id)
        if checkout_identity is None:
            raise AssertionError(
                "unblocked command lacks its retained checkout descriptor"
            )
        checkout_binding_failure: str | None = None
        try:
            _verify_checkout_path_binding(checkout_identity)
        except (OSError, ValidationError) as error:
            checkout_binding_failure = _sanitize_failure_reason(error)
        result, attempt = _run_subject(
            command_id,
            "command",
            _checkout_runtime_argv(command["argv"], checkout_identity),
            cwd=Path(f"/proc/self/fd/{checkout_identity.descriptor}"),
            env=dotnet_environment(mode, dotnet_root),
            timeout_seconds=command["timeout_seconds"],
            capture_dir=selection_root / "captures",
            cancel_event=cancel_event,
            observations=observations,
            subreaper_enabled=subreaper_enabled,
            output_disposition=(
                SUPPRESSED_SOURCE_FAITHFUL_OUTPUT
                if mode_id == "source-faithful"
                else RETAINED_OUTPUT
            ),
            retained_fds=(checkout_identity.descriptor,),
            bounds=bounds,
            retained_capture_groups=retained_capture_groups,
        )
        passed = result.termination == "completed" and result.exit_code == 0
        outcome = outcomes_by_id[command_id]
        outcome.update(
            {
                "status": "passed" if passed else "failed",
                "attempts": [] if attempt is None else [attempt],
                "unspawned_termination": (
                    result.termination
                    if attempt is None and not passed
                    else None
                ),
                "source_integrity_failure": None,
                "blocked_by": None,
            }
        )
        if command["stage"] == "restore" and result.quiescence_proved:
            restore_asset_snapshots[mode_id] = _snapshot_restore_assets(
                bundle,
                source_baseline,
                mode,
                selection_identity,
            )
        try:
            current_fingerprint = _checkout_fingerprint(
                checkout_identity,
                max_entries=bounds["source_max_entries"],
                per_file_limit=bounds["source_per_file_bytes"],
                aggregate_limit=bounds["source_aggregate_bytes"],
                elapsed_timeout=bounds["source_elapsed_seconds"],
            )
            source_unchanged = current_fingerprint == source_fingerprints[mode_id]
            fingerprint_reason = None
        except (KeyError, OSError, UnicodeError, ValidationError, ValueError) as error:
            source_unchanged = False
            fingerprint_reason = _sanitize_failure_reason(error)
        if checkout_binding_failure is not None:
            source_unchanged = False
            fingerprint_reason = checkout_binding_failure
        if not source_unchanged:
            outcome["status"] = "failed"
            outcome["source_integrity_failure"] = (
                fingerprint_reason or "fingerprint-mismatch"
            )

    observe_cancellation("recording", "recorded-bundle")
    all_proved = all(observation["proved"] for observation in observations)
    toolchain_verified = (
        toolchain_identity is not None and verify_root_identity(toolchain_identity)
    )
    if selection_identity is not None:
        selection_root_descriptor = _open_verified_root_identity(selection_identity)
    selection_verified = selection_root_descriptor is not None
    root_states = [
        {
            "kind": kind,
            "created": identity is not None,
            "identity_verified": verified,
        }
        for kind, identity, verified in (
            ("toolchain", toolchain_identity, toolchain_verified),
            ("selection", selection_identity, selection_verified),
        )
    ]
    selection_root_state = next(
        root for root in root_states if root["kind"] == "selection"
    )

    def capture_owner(group: RetainedCaptureGroup) -> dict[str, Any]:
        if group.subject_kind == "preparation":
            return next(
                item for item in preparations if item["id"] == group.subject_id
            )
        return outcomes_by_id[group.subject_id]

    def invalidate_capture_group(group: RetainedCaptureGroup) -> None:
        if group.invalidated:
            return
        previous_reason = group.attempt["failure_reason"]
        marker = LATE_CAPTURE_FAILURE_REASON
        reason = (
            marker
            if previous_reason is None
            else f"{str(previous_reason)[: 1024 - len(marker) - 2]}; {marker}"
        )
        empty = _empty_output_evidence(UNVERIFIABLE_OUTPUT).as_record()
        group.attempt["stdout"] = copy.deepcopy(empty)
        group.attempt["stderr"] = copy.deepcopy(empty)
        group.attempt["failure_reason"] = reason
        owner = capture_owner(group)
        already_failed = owner["status"] == "failed"
        owner["status"] = "failed"
        if group.subject_kind == "preparation":
            if not already_failed or owner["failure_reason"] is None:
                owner["failure_reason"] = reason
            cache_observations[:] = [
                observation
                for observation in cache_observations
                if group.subject_id not in observation["preparation_refs"]
            ]
        group.invalidated = True
        group.close()

    def active_capture_mismatches() -> list[RetainedCaptureGroup]:
        if (
            selection_identity is None
            or selection_root_descriptor is None
        ):
            return [
                group for group in retained_capture_groups if not group.invalidated
            ]
        return [
            group
            for group in retained_capture_groups
            if not group.invalidated
            and not all(
                _retained_capture_matches(
                    identity,
                    selection_identity,
                    selection_root_descriptor,
                )
                for identity in group.identities
            )
        ]

    if not selection_root_state["identity_verified"]:
        for group in retained_capture_groups:
            invalidate_capture_group(group)
    else:
        for group in active_capture_mismatches():
            invalidate_capture_group(group)

    state = reduce_runtime(
        preparations,
        outcomes,
        commands,
        observations,
        root_states,
        orchestration_stop,
    )
    dependency: dict[str, Any] | None = None
    commit_proven = False

    def asset_inspection_blocker() -> str | None:
        global_preparation_failed = any(
            PREPARATION_BY_ID[preparation["id"]].scope == "global"
            and preparation["status"] == "failed"
            for preparation in preparations
        )
        if not all_proved:
            return "asset-inspection-blocked-by-unproved-quiescence"
        if (
            selection_identity is None
            or not selection_root_state["identity_verified"]
        ):
            return "asset-inspection-blocked-by-root-identity-unverified"
        if global_preparation_failed:
            return "asset-inspection-blocked-by-preparation-failed"
        if state["cause"] not in {
            "completed",
            "completed-with-command-failures",
            "preparation-failed",
        }:
            return f"asset-inspection-blocked-by-{state['cause']}"
        return None

    def rollback_and_clear_assets(context: str) -> None:
        rollback_errors = _rollback_published_assets(
            published_assets,
            identity_mismatch_is_error=False,
        )
        for identity in published_assets:
            identity.close()
        published_assets.clear()
        if rollback_errors:
            raise ValidationError(
                f"{context}: " + "; ".join(rollback_errors)
            )

    def rebuild_dependency() -> None:
        nonlocal dependency
        dependency = _dependency_evidence(
            bundle,
            source_baseline,
            outcomes,
            inspection_blocker=asset_inspection_blocker(),
            published_assets=published_assets,
            selection_root_descriptor=selection_root_descriptor,
            restore_asset_snapshots=restore_asset_snapshots,
        )

    def recompute_state() -> None:
        nonlocal state
        state = reduce_runtime(
            preparations,
            outcomes,
            commands,
            observations,
            root_states,
            orchestration_stop,
        )

    def apply_late_cancellation() -> bool:
        nonlocal orchestration_stop
        if not cancel_event.is_set() or orchestration_stop is not None:
            return False
        orchestration_stop = {
            "subject_kind": "orchestration",
            "subject_id": "recorded-bundle",
            "phase": "before-recording-commit",
        }
        rollback_and_clear_assets("late cancellation asset rollback failed")
        recompute_state()
        rebuild_dependency()
        return True

    def apply_late_root_identity_failure(*, force: bool = False) -> bool:
        if not selection_root_state["identity_verified"]:
            pending = [
                group
                for group in retained_capture_groups
                if not group.invalidated
            ]
            if not pending:
                return False
        elif not force and (
            selection_identity is not None
            and selection_root_descriptor is not None
            and _retained_root_matches(
                selection_identity,
                selection_root_descriptor,
            )
        ):
            return False
        selection_root_state["identity_verified"] = False
        rollback_and_clear_assets(
            "late selection-root identity failure asset rollback failed"
        )
        for group in retained_capture_groups:
            invalidate_capture_group(group)
        recompute_state()
        rebuild_dependency()
        return True

    def apply_late_capture_failures(
        groups: Sequence[RetainedCaptureGroup] | None = None,
    ) -> bool:
        selected = list(groups) if groups is not None else active_capture_mismatches()
        selected = [group for group in selected if not group.invalidated]
        if not selected:
            return False
        rollback_and_clear_assets("late capture failure asset rollback failed")
        for group in selected:
            invalidate_capture_group(group)
        recompute_state()
        rebuild_dependency()
        return True

    try:
        rebuild_dependency()
        apply_late_cancellation()
        recorded = copy.deepcopy(bundle)
        recorded["status"] = "recorded"
        recorded["runtime_evidence"] = {
        "runtime_context": {
            "operating_system": "linux",
            "architecture": "x86_64",
            "kernel_release": platform.release(),
            "reproduction_count": 1,
            "mise_executable_sha256": mise_identity.sha256,
            "mise_executable_owner_verified": True,
            "mise_executable_mode": f"{mise_identity.mode:04o}",
            "nuget_client_version_probe": nuget_client_probe,
            "git_executable_sha256": _path_sha256(git_executable),
        },
        "preparation_outcomes": preparations,
        "cache_observations": cache_observations,
        "dependency_evidence": dependency,
        "command_outcomes": outcomes,
        "canonical_termination": {
            "cause": state["cause"],
            "detail": state["detail"],
        },
        "all_exit_quiescence": {
            "subreaper_enabled": subreaper_enabled,
            "identity_mechanisms": ["pidfd", "proc-starttime"],
            "observations": observations,
        },
        "ownership_conditioned_cleanup": {
            "roots": root_states,
        },
        "receipt_binding": {
            "algorithm": "sha256",
            "canonicalization": "canonical-json-v1",
            "scope": "recorded-bundle-excluding-receipt-digest",
            "digest": "",
        },
        "bounded_conclusions": {
            "conclusions": [
                {
                    "id": "conclusion-recorded-command-outcomes",
                    "epistemic_level": "runtime-observation",
                    "statement": (
                        "The runner recorded the bounded native-Linux-x64 command "
                        "outcomes with source-faithful output suppressed, other output "
                        "retained only when capture identity was verified, unverifiable "
                        "captures contributing no output evidence, and only asset evidence "
                        "admitted by the publication safety gates; "
                        "public causality and evidence sufficiency remain review judgments."
                    ),
                    "evidence_refs": [outcome["command_id"] for outcome in outcomes],
                    "limitation_refs": [
                        f"limitation-{index}"
                        for index in range(1, len(recorded["limitations"]) + 1)
                    ],
                }
            ],
        },
        }
        committed = False
        while not committed:
            if apply_late_root_identity_failure():
                continue
            if apply_late_capture_failures():
                continue
            if apply_late_cancellation():
                continue
            if dependency is None:
                raise AssertionError("recording dependency evidence is unavailable")
            recorded["runtime_evidence"]["dependency_evidence"] = dependency
            recorded["runtime_evidence"]["canonical_termination"] = {
                "cause": state["cause"],
                "detail": state["detail"],
            }
            recorded["runtime_evidence"]["receipt_binding"]["digest"] = ""
            recorded["runtime_evidence"]["receipt_binding"]["digest"] = (
                receipt_digest(recorded)
            )
            candidate_errors = validate_public_build_bundle_instance(
                recorded,
                str(bundle_path),
            )
            if candidate_errors:
                raise ValidationError(candidate_errors[0])
            retry: RecordingRetry | None = None
            with _cancellation_commit_boundary(
                cancel_event,
                cancellation_accounted=lambda: orchestration_stop is not None,
            ) as has_unrecorded_cancellation:
                def precommit_check() -> RecordingRetry | None:
                    if (
                        selection_root_state["identity_verified"]
                        and (
                            selection_identity is None
                            or selection_root_descriptor is None
                            or not _retained_root_matches(
                                selection_identity,
                                selection_root_descriptor,
                            )
                        )
                    ):
                        return RecordingRetry("root-identity-unverified")
                    if has_unrecorded_cancellation():
                        return RecordingRetry("cancelled")
                    mismatches = active_capture_mismatches()
                    if mismatches:
                        return RecordingRetry(
                            "capture-unverifiable",
                            capture_groups=mismatches,
                        )
                    return None

                retry = precommit_check()
                if retry is None:
                    try:
                        _atomic_replace_bundle(
                            recording_identity,
                            recorded,
                            published_assets,
                            precommit_check=precommit_check,
                        )
                    except RecordingRetry as error:
                        retry = error
                    else:
                        committed = True
                        commit_proven = True
            if retry is not None:
                if retry.reason == "root-identity-unverified":
                    apply_late_root_identity_failure(force=True)
                elif retry.reason == "cancelled":
                    apply_late_cancellation()
                elif retry.reason == "capture-unverifiable":
                    apply_late_capture_failures(retry.capture_groups)
                else:
                    raise AssertionError(
                        f"unknown recording retry reason: {retry.reason}"
                    )
        return recorded
    except RecordingError as error:
        if error.committed:
            commit_proven = True
        else:
            rollback_errors = _rollback_published_assets(
                published_assets,
                identity_mismatch_is_error=False,
            )
            if rollback_errors:
                raise RecordingError(
                    "recording failed and repository asset rollback was "
                    "indeterminate: "
                    + "; ".join(rollback_errors)
                ) from error
        raise
    except BaseException as error:
        rollback_errors = (
            []
            if commit_proven
            else _rollback_published_assets(
                published_assets,
                identity_mismatch_is_error=False,
            )
        )
        if rollback_errors:
            raise ValidationError(
                "pre-commit failure and repository asset rollback failed: "
                + "; ".join(rollback_errors)
            ) from error
        raise
    finally:
        for group in retained_capture_groups:
            group.close()
        for identity in published_assets:
            identity.close()
        if selection_root_descriptor is not None:
            os.close(selection_root_descriptor)
        if owns_recording_identity:
            os.close(recording_identity.descriptor)
            os.close(recording_identity.parent_descriptor)


def execute_planned_bundle(
    bundle_path: Path,
    bundle: dict[str, Any],
    *,
    source_baseline: dict[str, Any],
    mise_lock_bytes: bytes,
    mise_identity: ExecutableIdentity,
    git_executable: Path,
    subreaper_enabled: bool,
    planned_identity: CanonicalBundleIdentity | None = None,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    checkout_identities: dict[str, CheckoutIdentity] = {}
    try:
        return _execute_planned_bundle(
            bundle_path,
            bundle,
            source_baseline=source_baseline,
            mise_lock_bytes=mise_lock_bytes,
            mise_identity=mise_identity,
            git_executable=git_executable,
            subreaper_enabled=subreaper_enabled,
            planned_identity=planned_identity,
            cancel_event=cancel_event,
            checkout_identities=checkout_identities,
        )
    finally:
        for identity in checkout_identities.values():
            identity.close()


@contextmanager
def _invocation_cancellation() -> Iterator[threading.Event]:
    event = threading.Event()
    if threading.current_thread() is not threading.main_thread():
        yield event
        return
    cancellation_signals = (signal.SIGINT, signal.SIGTERM)
    previous = {
        selected_signal: signal.getsignal(selected_signal)
        for selected_signal in cancellation_signals
    }

    def request_cancellation(
        _signal_number: int,
        _frame: Any,
    ) -> None:
        event.set()

    for selected_signal in cancellation_signals:
        signal.signal(selected_signal, request_cancellation)
    try:
        yield event
    finally:
        for selected_signal, handler in previous.items():
            signal.signal(selected_signal, handler)


@contextmanager
def _cancellation_commit_boundary(
    event: threading.Event,
    *,
    cancellation_accounted: Callable[[], bool],
) -> Iterator[Callable[[], bool]]:
    cancellation_signals = {signal.SIGINT, signal.SIGTERM}

    def has_unrecorded_cancellation() -> bool:
        pending = (
            signal.sigpending()
            if threading.current_thread() is threading.main_thread()
            else set()
        )
        requested = event.is_set() or bool(pending & cancellation_signals)
        if requested:
            event.set()
        return requested and not cancellation_accounted()

    if threading.current_thread() is not threading.main_thread():
        yield has_unrecorded_cancellation
        return
    previous_mask = signal.pthread_sigmask(
        signal.SIG_BLOCK,
        cancellation_signals,
    )
    try:
        yield has_unrecorded_cancellation
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def run_bundle(path: Path) -> dict[str, Any]:
    with _invocation_cancellation() as cancel_event:
        bundle, planned_identity = _open_canonical_bundle(path)
        try:
            source_baseline, mise_lock_bytes = validate_bundle(
                bundle,
                allow_recorded=False,
            )
            require_native_linux_x64()
            _require_supervision_capabilities()
            subreaper_enabled = enable_child_subreaper()
            git = shutil.which("git", path="/usr/bin:/bin")
            if git is None:
                raise CapabilityError("fixed runner requires an absolute git executable")
            mise_identity = resolve_mise_executable(
                os.environ.get("PATH"),
                bundle["environment"]["mise"]["executable_sha256"],
            )
            try:
                return execute_planned_bundle(
                    path,
                    bundle,
                    source_baseline=source_baseline,
                    mise_lock_bytes=mise_lock_bytes,
                    mise_identity=mise_identity,
                    git_executable=Path(git).resolve(),
                    subreaper_enabled=subreaper_enabled,
                    planned_identity=planned_identity,
                    cancel_event=cancel_event,
                )
            finally:
                os.close(mise_identity.descriptor)
        finally:
            os.close(planned_identity.descriptor)
            os.close(planned_identity.parent_descriptor)


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate or run the fixed Issue #1 public-build experiment bundle."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("bundle", type=Path)
    run = subparsers.add_parser("run")
    run.add_argument("bundle", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_arguments()
    try:
        if args.command == "run":
            run_bundle(args.bundle)
            print(f"Recorded {args.bundle}")
        else:
            bundle = load_strict_json(args.bundle)
            validate_bundle(bundle)
            print(f"Validated {args.bundle}")
    except (
        ValidationError,
        CapabilityError,
        RootCreationError,
        RecordingError,
        OSError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
