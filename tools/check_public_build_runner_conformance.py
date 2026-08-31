#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any

from public_build_contract import (
    COMMAND_IDS,
    DOTNET_ENVIRONMENT_KEYS,
    GIT_ENVIRONMENT_KEYS,
    GLOBAL_SAFETY_TERMINATIONS,
    LATE_CAPTURE_FAILURE_REASON,
    MISE_ENVIRONMENT_KEYS,
    PREPARATIONS,
    SELECTION_ROOT,
    SOURCE_INTEGRITY_CHANGED_MARKER,
    TOOLCHAIN_ROOT,
    append_failure_reason_marker,
    reduce_runtime,
)
import run_public_build_experiment as runner
import public_build_validation as validation
from public_build_validation import validate_public_build_runtime_evidence
from run_public_build_experiment import (
    CAPTURE_LIMIT,
    CapabilityError,
    ROOT_MARKER,
    RootCreationError,
    ValidationError,
    _atomic_publish_asset,
    child_subreaper_enabled,
    create_exclusive_root,
    enable_child_subreaper,
    execute_planned_bundle,
    load_strict_json,
    receipt_digest,
    resolve_mise_executable,
    require_native_linux_x64,
    run_supervised,
    validate_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/fixtures/public-build/runner/helper.py"
PLANNED_BUNDLE = (
    ROOT
    / "docs/research/experiments/"
    "public-build-linux-x64-dotnet-8-0-424-01.json"
)
SOURCE_BASELINE = ROOT / "docs/research/public-build-source-baseline.json"
LASSO_MANIFEST = ROOT / "docs/research/public-build-lasso-reference-manifest.json"
WORK: Path
SUBREAPER_ENABLED = False


def command_topology() -> list[dict[str, Any]]:
    return load_strict_json(PLANNED_BUNDLE)["protocol"]["commands"]


def preparation_topology() -> list[dict[str, Any]]:
    return [
        {
            "id": item.identifier,
            "scope": item.scope,
            "source_mode": item.source_mode,
            "execution": "child" if item.child else "in-process",
        }
        for item in PREPARATIONS
    ]


def source_mode_plan() -> list[dict[str, Any]]:
    return load_strict_json(PLANNED_BUNDLE)["isolation"]["source_modes"]


def supervision_bounds() -> dict[str, Any]:
    return load_strict_json(PLANNED_BUNDLE)["protocol"]["supervision_bounds"]


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def supervised(
    *arguments: str,
    timeout: float = 2.0,
    env: dict[str, str] | None = None,
    cancel: threading.Event | None = None,
    force_unproved: bool = False,
):
    return run_supervised(
        [sys.executable, str(HELPER), *arguments],
        cwd=WORK,
        env=env or {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        timeout_seconds=timeout,
        subreaper_enabled=SUBREAPER_ENABLED,
        cancel_event=cancel,
        force_unproved=force_unproved,
        capture_dir=WORK / "captures",
        label=f"helper-{arguments[0]}",
    )


def test_literal_argv_environment_and_bounded_output() -> None:
    literal = "$(touch should-not-exist);*|'\""
    result = supervised("argv", literal)
    check(result.termination == "completed", "literal argv helper failed")
    check(json.loads(result.stdout) == [literal], "shell metacharacters were not literal")
    check(not (WORK / "should-not-exist").exists(), "shell metacharacters were executed")
    os.environ["PUBLIC_BUILD_POISON"] = "inherited"
    replacement = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "MISE_LOCKED": "present",
    }
    result = supervised("env", "PUBLIC_BUILD_POISON", "MISE_LOCKED", env=replacement)
    observed = json.loads(result.stdout)
    check(
        observed == {"MISE_LOCKED": "present", "PUBLIC_BUILD_POISON": None},
        "child inherited poison environment",
    )
    large = supervised("output", str(3 * 1024 * 1024))
    check(
        large.termination == "output-limit-exceeded",
        "large output did not fail closed with its typed termination",
    )
    check(large.stdout_evidence.truncated, "large stdout was not bounded")
    check(large.stderr_evidence.truncated, "large stderr was not bounded")
    check(
        large.stdout_capture.stat().st_size <= CAPTURE_LIMIT
        and large.stderr_capture.stat().st_size <= CAPTURE_LIMIT,
        "sanitized capture exceeded its hard byte limit",
    )
    sensitive = supervised("sensitive")
    check(
        sensitive.termination == "sensitive-output",
        "sensitive output did not fail closed with its typed termination",
    )
    captured = (
        sensitive.stdout_capture.read_text(encoding="utf-8")
        + sensitive.stderr_capture.read_text(encoding="utf-8")
    )
    check("do-not-persist" not in captured, "sensitive raw bytes were persisted")

    late_sensitive = WORK / "late-sensitive-output.bin"
    sensitive_key = b"\nclient_secret="
    late_sensitive.write_bytes(
        b"x" * (runner.CAPTURE_CHUNK * 16)
        + b"x" * (runner.CAPTURE_CHUNK - len(sensitive_key))
        + sensitive_key
        + b"late-secret\n"
    )
    retained_result: dict[str, Any] = {}
    retained_violation: dict[str, str] = {}
    retained_capture = WORK / "late-sensitive-capture.log"
    with retained_capture.open("wb", buffering=0) as destination:
        runner._stream_sanitized_capture(
            os.open(late_sensitive, os.O_RDONLY),
            destination,
            metadata_limit=0,
            result=retained_result,
            violation=retained_violation,
            violation_lock=threading.Lock(),
            stop_event=threading.Event(),
        )
    check(
        retained_violation.get("cause") == "sensitive-output"
        and retained_capture.stat().st_size == CAPTURE_LIMIT
        and b"late-secret" not in retained_capture.read_bytes(),
        "late sensitive retained output did not supersede bounded overflow",
    )

    suppressed_result: dict[str, Any] = {}
    suppressed_violation: dict[str, str] = {}
    runner._stream_suppressed_output(
        os.open(late_sensitive, os.O_RDONLY),
        result=suppressed_result,
        violation=suppressed_violation,
        violation_lock=threading.Lock(),
        stop_event=threading.Event(),
    )
    check(
        suppressed_violation.get("cause") == "sensitive-output",
        "late sensitive suppressed output did not supersede bounded overflow",
    )

    overflow_only = WORK / "overflow-before-capture-failure.bin"
    overflow_only.write_bytes(b"x" * (runner.CAPTURE_CHUNK * 17))
    capture_failure_result: dict[str, Any] = {}
    capture_failure_violation: dict[str, str] = {}
    underlying_capture = (WORK / "capture-failure-after-overflow.log").open(
        "wb",
        buffering=0,
    )

    class FailingFlush:
        def write(self, content: bytes) -> int:
            return underlying_capture.write(content)

        def flush(self) -> None:
            raise OSError("synthetic flush failure")

        def fileno(self) -> int:
            return underlying_capture.fileno()

    try:
        runner._stream_sanitized_capture(
            os.open(overflow_only, os.O_RDONLY),
            FailingFlush(),
            metadata_limit=0,
            result=capture_failure_result,
            violation=capture_failure_violation,
            violation_lock=threading.Lock(),
            stop_event=threading.Event(),
        )
    finally:
        underlying_capture.close()
    check(
        capture_failure_violation.get("cause") == "capture-failed",
        "capture failure did not supersede an earlier output overflow",
    )


def test_capture_identity_alteration_and_replacement() -> None:
    original_verify = runner._verify_capture_evidence
    expected = {
        "disposition": "capture-unverifiable",
        "path": None,
        "sha256": None,
        "sanitized_bytes": 0,
        "excerpt": "",
        "truncated": False,
    }

    def exercise(kind: str) -> None:
        changed = False

        def alter_before_verify(
            identity: Any,
            result: dict[str, Any],
            **keywords: Any,
        ) -> Any:
            nonlocal changed
            if not changed:
                changed = True
                if kind == "append":
                    with identity.path.open("ab") as stream:
                        stream.write(b"unsanitized-replacement-token")
                else:
                    replacement = identity.path.with_name(
                        f"{identity.path.name}.replacement"
                    )
                    replacement.write_bytes(b"unsanitized-replacement-token")
                    os.replace(replacement, identity.path)
            return original_verify(identity, result, **keywords)

        runner._verify_capture_evidence = alter_before_verify
        try:
            result = supervised("exit", "0")
        finally:
            runner._verify_capture_evidence = original_verify
        check(
            result.termination == "capture-failed"
            and result.stdout_evidence.as_record() == expected
            and result.stderr_evidence.as_record() == expected
            and result.stdout_capture is None
            and result.stderr_capture is None,
            f"capture {kind} was accepted or persisted as sanitizer evidence",
        )

    exercise("append")
    exercise("replacement")

    changed = False

    def alter_sensitive_before_verify(
        identity: Any,
        result: dict[str, Any],
        **keywords: Any,
    ) -> Any:
        nonlocal changed
        if not changed:
            changed = True
            with identity.path.open("ab") as stream:
                stream.write(b"unverifiable")
        return original_verify(identity, result, **keywords)

    runner._verify_capture_evidence = alter_sensitive_before_verify
    try:
        sensitive = supervised("sensitive")
    finally:
        runner._verify_capture_evidence = original_verify
    check(
        sensitive.termination == "sensitive-output"
        and sensitive.stdout_evidence.as_record() == expected
        and sensitive.stderr_evidence.as_record() == expected,
        "capture verification failure replaced the first global safety termination",
    )


def test_root_creation_guards_and_race() -> None:
    base = WORK / "trusted"
    base.mkdir(mode=0o700)
    existing = base / "existing"
    existing.mkdir(mode=0o700)
    for candidate in (existing,):
        try:
            create_exclusive_root(candidate, base, {"kind": "synthetic"})
        except RootCreationError:
            pass
        else:
            raise AssertionError("preexisting root was accepted")
    target = base / "target"
    target.mkdir(mode=0o700)
    symlink = base / "symlink"
    symlink.symlink_to(target, target_is_directory=True)
    try:
        create_exclusive_root(symlink, base, {"kind": "synthetic"})
    except RootCreationError:
        pass
    else:
        raise AssertionError("symlink leaf was accepted")
    ancestor_target = WORK / "ancestor-target"
    ancestor_target.mkdir(mode=0o700)
    ancestor_link = WORK / "ancestor-link"
    ancestor_link.symlink_to(ancestor_target, target_is_directory=True)
    try:
        create_exclusive_root(
            ancestor_link / "leaf",
            ancestor_link,
            {"kind": "synthetic"},
        )
    except RootCreationError:
        pass
    else:
        raise AssertionError("symlink trusted-base ancestor was accepted")
    created = create_exclusive_root(base / "created", base, {"kind": "synthetic"})
    check(created.path.joinpath(ROOT_MARKER).is_file(), "exclusive root marker is missing")

    race_root = base / "race"
    results: list[str] = []

    def contender() -> None:
        try:
            create_exclusive_root(race_root, base, {"kind": "race"})
        except RootCreationError:
            results.append("rejected")
        else:
            results.append("created")

    threads = [threading.Thread(target=contender) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    check(sorted(results) == ["created", "rejected"], "concurrent root creation was not exclusive")


def test_partial_root_marker_and_stale_selection_states() -> None:
    partial, _, _, _ = synthetic_case(
        "selection-post-mkdir-failure",
        fail_root_marker_kind="selection",
        use_real_candidate_validator=True,
    )
    partial_root = next(
        root
        for root in partial["runtime_evidence"]["ownership_conditioned_cleanup"][
            "roots"
        ]
        if root["kind"] == "selection"
    )
    check(
        partial_root
        == {
            "kind": "selection",
            "created": True,
            "identity_verified": False,
        }
        and partial["runtime_evidence"]["canonical_termination"]["cause"]
        == "root-identity-unverified",
        "post-mkdir failure did not preserve partial retained root state",
    )

    for fault in ("selection-stat", "selection-open"):
        partial, _, _, _ = synthetic_case(
            f"{fault}-failure",
            root_creation_fault=fault,
            use_real_candidate_validator=True,
        )
        runtime = partial["runtime_evidence"]
        roots = {
            root["kind"]: root
            for root in runtime["ownership_conditioned_cleanup"]["roots"]
        }
        preparation = {
            item["id"]: item
            for item in runtime["preparation_outcomes"]
        }
        check(
            roots["selection"]
            == {
                "kind": "selection",
                "created": True,
                "identity_verified": False,
            }
            and runtime["canonical_termination"]["cause"]
            == "root-identity-unverified"
            and preparation["prepare-selection-directories"]["status"] == "blocked"
            and preparation["prepare-toolchain-directories"]["status"] == "blocked",
            f"{fault} did not retain the physical root and block later work",
        )

    tampered, _, _, _ = synthetic_case(
        "selection-marker-tamper",
        tamper_selection_marker_before_identity_check=True,
        use_real_candidate_validator=True,
    )
    check(
        tampered["runtime_evidence"]["canonical_termination"]["cause"]
        == "root-identity-unverified",
        "marker payload tamper was not detected by root identity reverification",
    )

    stale, _, _, _ = synthetic_case(
        "stale-selection-root",
        precreate_selection_root=True,
        use_real_candidate_validator=True,
    )
    stale_root = next(
        root
        for root in stale["runtime_evidence"]["ownership_conditioned_cleanup"][
            "roots"
        ]
        if root["kind"] == "selection"
    )
    check(
        stale_root["created"] is False
        and stale_root["identity_verified"] is False
        and not any(
            "asset" in target
            for mode in stale["runtime_evidence"]["dependency_evidence"]["modes"]
            for target in mode["targets"]
        ),
        "pre-existing selection root was claimed or inspected",
    )


def test_one_attempt_and_lifecycle_table() -> None:
    counter = WORK / "attempt-count"
    result = supervised("count", str(counter), "7")
    check(
        result.termination == "completed" and result.exit_code == 7,
        "ordinary nonzero exit was not retained as a command outcome",
    )
    check(counter.read_text(encoding="ascii") == "1", "helper executed more than once")
    normal = supervised("exit", "0")
    check(normal.termination == "completed" and normal.quiescence_proved, "normal lifecycle failed")
    nonzero = supervised("exit", "9")
    check(
        nonzero.termination == "completed"
        and nonzero.exit_code == 9
        and nonzero.quiescence_proved,
        "nonzero lifecycle failed",
    )
    cancel = threading.Event()
    timer = threading.Thread(target=lambda: (time.sleep(0.08), cancel.set()))
    timer.start()
    cancelled = supervised("sleep", "5", cancel=cancel)
    timer.join()
    check(cancelled.termination == "cancelled" and cancelled.quiescence_proved, "cancel lifecycle failed")
    timed_out = supervised("sleep", "5", timeout=0.08)
    check(timed_out.termination == "timed-out" and timed_out.quiescence_proved, "timeout lifecycle failed")


def test_surviving_grandchild_and_retain_unproved() -> None:
    result = supervised("grandchild", "5")
    check(result.termination == "completed", "normal parent exit changed canonical result")
    check(result.discovered_processes >= 2, "surviving grandchild was not discovered")
    check(result.quiescence_proved, "surviving grandchild was not made quiescent")
    base = WORK / "retain-base"
    base.mkdir(mode=0o700)
    retained = base / "retained"
    create_exclusive_root(retained, base, {"kind": "synthetic-retain"})
    result = supervised("exit", "0", force_unproved=True)
    check(result.termination == "quiescence-unproved", "injected unproved result was not canonical")
    check(retained.is_dir(), "unproved lifecycle removed the retained root")


def test_bounded_discovery_and_capture_shutdown() -> None:
    started = time.monotonic()
    churn = supervised("fork-churn", "0.3", timeout=0.08)
    check(
        time.monotonic() - started < 5
        and churn.termination in {"timed-out", "quiescence-unproved"}
        and (
            churn.quiescence_proved
            or churn.termination == "quiescence-unproved"
        ),
        "high-churn descendant discovery was not bounded",
    )

    pid_file = WORK / "pipe-grandchild.pid"
    original_discovery = runner._discover_descendants

    def fail_discovery(*_arguments: Any, **_keywords: Any) -> int:
        time.sleep(0.15)
        raise runner.QuiescenceError("synthetic discovery failure")

    runner._discover_descendants = fail_discovery
    child_pid: int | None = None
    started = time.monotonic()
    try:
        result = supervised("pipe-grandchild", str(pid_file), timeout=2)
        if pid_file.exists():
            child_pid = int(pid_file.read_text(encoding="ascii"))
    finally:
        runner._discover_descendants = original_discovery
        if child_pid is not None:
            try:
                state = runner._proc_identity(child_pid)
                if state is not None:
                    identity = runner._open_identity(child_pid, state[2])
                    try:
                        runner._signal_identity(identity, runner.signal.SIGKILL)
                    finally:
                        identity.close()
            except (ProcessLookupError, runner.QuiescenceError):
                pass
            try:
                os.waitpid(child_pid, 0)
            except ChildProcessError:
                pass
    check(
        time.monotonic() - started < 5
        and result.termination == "quiescence-unproved",
        "capture readers kept the runner alive after quiescence failure",
    )


def test_emergency_cleanup_requires_stable_empty_scans() -> None:
    class FinishedProcess:
        pid = 424242

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float) -> int:
            return 0

        def kill(self) -> None:
            raise AssertionError("finished synthetic process was killed directly")

    original_discover = runner._discover_descendants
    original_live = runner._live_identities
    original_reap = runner._reap_available
    original_signal = runner._signal_identity
    original_sleep = runner.time.sleep
    post_kill_scans = 0
    descendant_live = False

    def discover(
        _tracked: Any,
        _baseline: Any,
        extra_parents: Any = (),
        identity_opener: Any = None,
        **_bounds: Any,
    ) -> int:
        nonlocal post_kill_scans, descendant_live
        if extra_parents:
            return 0
        post_kill_scans += 1
        if post_kill_scans == 2:
            descendant_live = True
            return 1
        return 0

    def live(_tracked: Any) -> list[tuple[Any, str]]:
        return [(object(), "R")] if descendant_live else []

    def signal_identity(_identity: Any, _signal: int) -> None:
        nonlocal descendant_live
        descendant_live = False

    runner._discover_descendants = discover
    runner._live_identities = live
    runner._reap_available = lambda: 0
    runner._signal_identity = signal_identity
    runner.time.sleep = lambda _delay: None
    try:
        _, cleanup_error = runner._bounded_emergency_cleanup(
            FinishedProcess(),
            {},
            set(),
            supervision_bounds(),
        )
    finally:
        runner._discover_descendants = original_discover
        runner._live_identities = original_live
        runner._reap_available = original_reap
        runner._signal_identity = original_signal
        runner.time.sleep = original_sleep
    check(
        cleanup_error is None and post_kill_scans >= 2 + runner.STABLE_SCAN_COUNT,
        "emergency cleanup accepted one empty scan before a reparented descendant appeared",
    )

    zero_bounds = supervision_bounds()
    zero_bounds["fixed_point_seconds"] = 0.0
    _, cleanup_error = runner._bounded_emergency_cleanup(
        FinishedProcess(),
        {},
        set(),
        zero_bounds,
    )
    check(
        cleanup_error is not None and "consecutive empty scans" in cleanup_error,
        "emergency cleanup deadline expiry did not preserve quiescence uncertainty",
    )


def test_source_fingerprint_bounds_races_and_no_follow() -> None:
    checkout = WORK / "fingerprint-checkout"
    (checkout / ".git").mkdir(mode=0o700, parents=True)
    (checkout / ".git/index").write_bytes(b"index")
    (checkout / ".git/HEAD").write_text(
        "de20930c34b3b86c8a0ed7bbdeeca3f662dae918\n",
        encoding="ascii",
    )
    (checkout / "a.txt").write_bytes(b"aaaa")
    (checkout / "b.txt").write_bytes(b"bbbb")
    outside = WORK / "fingerprint-outside"
    outside.write_bytes(b"outside-secret")
    (checkout / "link").symlink_to(outside)
    identity = runner._open_checkout_identity(checkout)
    try:
        fingerprint = runner._checkout_fingerprint(identity)
        outside.write_bytes(b"changed-outside-secret")
        check(
            runner._checkout_fingerprint(identity) == fingerprint,
            "source fingerprint followed a symbolic link outside the checkout",
        )
        (checkout / "untracked.txt").write_text("new\n", encoding="ascii")
        check(
            runner._checkout_fingerprint(identity) != fingerprint,
            "source fingerprint omitted an untracked worktree entry",
        )
        (checkout / "untracked.txt").unlink()
        (checkout / ".git/index").write_bytes(b"changed-index")
        check(
            runner._checkout_fingerprint(identity) != fingerprint,
            "source fingerprint omitted the Git index",
        )
        (checkout / ".git/index").write_bytes(b"index")
        cases = (
            ("entry", {"max_entries": 2}, "entry limit"),
            ("per-file", {"per_file_limit": 3}, "byte limit"),
            ("aggregate", {"aggregate_limit": 7}, "aggregate-byte limit"),
            (
                "elapsed",
                {
                    "elapsed_timeout": 0.5,
                    "clock": iter((0.0, 1.0, 1.0, 1.0, 1.0)).__next__,
                },
                "elapsed-time limit",
            ),
        )
        for name, keywords, expected in cases:
            try:
                runner._checkout_fingerprint(identity, **keywords)
            except ValidationError as error:
                check(expected in str(error), f"{name} fingerprint bound failed unclearly")
            else:
                raise AssertionError(f"{name} fingerprint bound was not enforced")
        original_scandir = runner.os.scandir
        yielded = 0

        class BoundedScan:
            def __enter__(self) -> "BoundedScan":
                return self

            def __exit__(self, *args: Any) -> None:
                return None

            def __iter__(self) -> "BoundedScan":
                return self

            def __next__(self) -> Any:
                nonlocal yielded
                yielded += 1
                if yielded > 4:
                    raise StopIteration
                return type("Entry", (), {"name": f"entry-{yielded}"})()

        runner.os.scandir = lambda _: BoundedScan()
        try:
            runner._checkout_fingerprint(identity, max_entries=2)
        except ValidationError as error:
            check("entry limit" in str(error), "lazy entry bound failed unclearly")
        else:
            raise AssertionError("source scanner exhausted entries before applying its limit")
        finally:
            runner.os.scandir = original_scandir
        check(yielded == 1, "source scanner consumed entries beyond its remaining budget")
        (checkout / ".git/HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
        try:
            runner._checkout_fingerprint(identity)
        except ValidationError as error:
            check("audited detached commit" in str(error), "HEAD failure was unclear")
        else:
            raise AssertionError("non-detached Git HEAD was accepted")
        (checkout / ".git/HEAD").write_text(
            "de20930c34b3b86c8a0ed7bbdeeca3f662dae918\n",
            encoding="ascii",
        )
        original_scandir = runner.os.scandir
        injected = False

        class RacingScan:
            def __init__(self, directory: int) -> None:
                self.scan = original_scandir(directory)

            def __enter__(self) -> Any:
                return self.scan.__enter__()

            def __exit__(self, *args: Any) -> Any:
                nonlocal injected
                result = self.scan.__exit__(*args)
                if not injected:
                    injected = True
                    (checkout / "raced.txt").write_text("late\n", encoding="ascii")
                return result

        runner.os.scandir = RacingScan
        try:
            runner._checkout_fingerprint(identity)
        except ValidationError as error:
            check("directory changed" in str(error), "source race failure was unclear")
        else:
            raise AssertionError("source directory race was accepted")
        finally:
            runner.os.scandir = original_scandir
    finally:
        identity.close()


def test_spawn_and_post_spawn_fault_cleanup() -> None:
    captures = WORK / "spawn-fault-captures"
    captures.mkdir(mode=0o700)
    original_popen = runner.subprocess.Popen

    runner.subprocess.Popen = lambda *args, **kwargs: (
        (_ for _ in ()).throw(OSError("synthetic Popen failure"))
    )
    try:
        result = runner.run_supervised(
            [sys.executable, str(HELPER), "sleep", "5"],
            cwd=WORK,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            timeout_seconds=1,
            subreaper_enabled=SUBREAPER_ENABLED,
            capture_dir=captures,
            label="popen-fault",
        )
    finally:
        runner.subprocess.Popen = original_popen
    check(
        not result.spawned
        and result.termination == "spawn-failed"
        and result.quiescence_proved
        and result.stdout_capture is None
        and result.stderr_capture is None
        and not list(captures.glob("popen-fault-*")),
        "Popen failure did not produce a clean typed unspawned result",
    )

    def exercise_post_spawn_fault(kind: str) -> None:
        processes: list[Any] = []

        def capture_popen(*args: Any, **kwargs: Any) -> Any:
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process

        original_open_identity = runner._open_identity
        original_dup = runner.os.dup
        original_thread_start = runner.threading.Thread.start
        runner.subprocess.Popen = capture_popen
        if kind == "pidfd":
            runner._open_identity = lambda *args, **kwargs: (
                (_ for _ in ()).throw(OSError("synthetic pidfd failure"))
            )
        elif kind == "dup":
            runner.os.dup = lambda descriptor: (
                (_ for _ in ()).throw(OSError("synthetic dup failure"))
            )
        else:
            runner.threading.Thread.start = lambda self: (
                (_ for _ in ()).throw(RuntimeError("synthetic thread start failure"))
            )
        try:
            result = runner.run_supervised(
                [sys.executable, str(HELPER), "sleep", "5"],
                cwd=WORK,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                timeout_seconds=1,
                subreaper_enabled=SUBREAPER_ENABLED,
                capture_dir=captures,
                label=f"{kind}-fault",
            )
        finally:
            runner.subprocess.Popen = original_popen
            runner._open_identity = original_open_identity
            runner.os.dup = original_dup
            runner.threading.Thread.start = original_thread_start
        check(
            result.spawned
            and result.termination == "quiescence-unproved"
            and all(process.poll() is not None for process in processes),
            f"{kind} post-spawn failure left a live or untyped child",
        )

    for kind in ("pidfd", "dup", "thread"):
        exercise_post_spawn_fault(kind)


def test_cancellation_initialization_fixed_point_and_between_subjects() -> None:
    pid_file = WORK / "cancel-initialization-grandchild.pid"
    original_dup = runner.os.dup
    interrupted = False

    def interrupt_dup(descriptor: int) -> int:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            time.sleep(0.25)
            raise KeyboardInterrupt()
        return original_dup(descriptor)

    runner.os.dup = interrupt_dup
    try:
        initialization = supervised(
            "instant-grandchild",
            str(pid_file),
            timeout=2,
        )
    finally:
        runner.os.dup = original_dup
    child_pid = int(pid_file.read_text(encoding="ascii"))
    check(
        initialization.termination == "cancelled"
        and initialization.quiescence_proved
        and initialization.discovered_processes >= 2
        and runner._proc_identity(child_pid) is None,
        "initialization interruption did not discover, kill, and reap descendants",
    )

    cancel = threading.Event()
    timer = threading.Thread(target=lambda: (time.sleep(0.08), cancel.set()))
    timer.start()
    original_signal = runner._signal_identity
    fixed_point_interrupted = False

    def interrupt_fixed_point(identity: Any, selected_signal: Any) -> None:
        nonlocal fixed_point_interrupted
        if selected_signal == runner.signal.SIGSTOP and not fixed_point_interrupted:
            fixed_point_interrupted = True
            raise KeyboardInterrupt()
        original_signal(identity, selected_signal)

    runner._signal_identity = interrupt_fixed_point
    try:
        fixed_point = supervised("sleep", "5", cancel=cancel)
    finally:
        runner._signal_identity = original_signal
        timer.join()
    check(
        fixed_point.termination == "cancelled"
        and fixed_point.quiescence_proved,
        "fixed-point interruption escaped bounded cancellation cleanup",
    )

    with runner._invocation_cancellation() as signal_event:
        os.kill(os.getpid(), runner.signal.SIGINT)
        check(signal_event.wait(1), "SIGINT did not become an invocation cancellation event")

    signal_pid_file = WORK / "sigterm-grandchild.pid"
    with runner._invocation_cancellation() as signal_event:
        signal_thread = threading.Thread(
            target=lambda: (
                time.sleep(0.08),
                os.kill(os.getpid(), runner.signal.SIGTERM),
            )
        )
        signal_thread.start()
        signalled = supervised(
            "instant-grandchild",
            str(signal_pid_file),
            timeout=2,
            cancel=signal_event,
        )
        signal_thread.join()
    signalled_pid = int(signal_pid_file.read_text(encoding="ascii"))
    check(
        signalled.termination == "cancelled"
        and signalled.quiescence_proved
        and runner._proc_identity(signalled_pid) is None,
        "SIGTERM did not enter bounded cancellation and descendant cleanup",
    )

    with runner._invocation_cancellation() as signal_event:
        previous_mask = runner.signal.pthread_sigmask(
            runner.signal.SIG_BLOCK,
            {runner.signal.SIGTERM},
        )
        try:
            os.kill(os.getpid(), runner.signal.SIGTERM)
            with runner._cancellation_commit_boundary(
                signal_event,
                cancellation_accounted=lambda: False,
            ) as has_unrecorded_cancellation:
                check(
                    has_unrecorded_cancellation(),
                    "pending SIGTERM was not observed before commit",
                )
        finally:
            runner.signal.pthread_sigmask(
                runner.signal.SIG_SETMASK,
                previous_mask,
            )

    with runner._invocation_cancellation() as signal_event:
        with runner._cancellation_commit_boundary(
            signal_event,
            cancellation_accounted=lambda: False,
        ) as has_unrecorded_cancellation:
            check(
                not has_unrecorded_cancellation(),
                "clean commit boundary reported cancellation",
            )
            os.kill(os.getpid(), runner.signal.SIGTERM)
            check(
                runner.signal.SIGTERM in runner.signal.sigpending(),
                "SIGTERM arriving after the commit cutoff was not deferred",
            )
            check(
                has_unrecorded_cancellation(),
                "SIGTERM arriving inside the masked boundary did not defer commit",
            )
        check(
            signal_event.wait(1),
            "deferred SIGTERM was not delivered after the commit boundary",
        )

    accounted = threading.Event()
    accounted.set()
    with runner._cancellation_commit_boundary(
        accounted,
        cancellation_accounted=lambda: True,
    ) as has_unrecorded_cancellation:
        check(
            not has_unrecorded_cancellation(),
            "accounted sticky cancellation continued to block commit",
        )

    between, _, _, _ = synthetic_case(
        "between-subject-cancellation",
        cancel_after_label="git-source-faithful-init",
        use_real_candidate_validator=True,
    )
    check(
        between["runtime_evidence"]["canonical_termination"]["cause"] == "cancelled"
        and all(
            outcome["status"] == "blocked" and not outcome["attempts"]
            for outcome in between["runtime_evidence"]["command_outcomes"]
        ),
        "between-subject cancellation escaped or allowed another command to spawn",
    )


def test_unsupported_host_before_root() -> None:
    base = WORK / "unsupported"
    base.mkdir(mode=0o700)
    root = base / "must-not-exist"
    try:
        require_native_linux_x64(system="Darwin", machine="x86_64")
        create_exclusive_root(root, base, {"kind": "must-not-create"})
    except CapabilityError:
        pass
    check(not root.exists(), "unsupported host created a root")
    interop = WORK / "WSLInterop"
    interop.write_text("enabled\n", encoding="ascii")
    for kernel, interop_path in (
        ("6.6.0", interop),
        ("5.15.0-microsoft-standard-WSL2", WORK / "missing-interop"),
    ):
        try:
            require_native_linux_x64(
                system="Linux",
                machine="x86_64",
                kernel_release=kernel,
                interop_path=interop_path,
            )
        except CapabilityError:
            pass
        else:
            raise AssertionError("WSL host was accepted")


def test_strict_json_and_receipt_tamper() -> None:
    duplicate = WORK / "duplicate.json"
    duplicate.write_text('{"status":"planned","status":"recorded"}', encoding="utf-8")
    try:
        load_strict_json(duplicate)
    except ValidationError:
        pass
    else:
        raise AssertionError("duplicate JSON key was accepted")
    nonfinite = WORK / "nonfinite.json"
    nonfinite.write_text('{"value":NaN}', encoding="utf-8")
    try:
        load_strict_json(nonfinite)
    except ValidationError:
        pass
    else:
        raise AssertionError("non-finite JSON was accepted")
    planned = load_strict_json(PLANNED_BUNDLE)
    malformed_cases = (
        ("unexpected nested property", lambda value: value["environment"]["dotnet_sdk"].__setitem__("unexpected", True)),
        ("wrong limitation type", lambda value: value["limitations"].__setitem__(0, 7)),
        ("too few limitations", lambda value: value["limitations"].clear()),
        (
            "unauthorized mise descriptor",
            lambda value: value["environment"]["mise"].__setitem__(
                "config_content",
                value["environment"]["mise"]["config_content"]
                + '\n[tools.python]\nversion = "3.13"\n',
            ),
        ),
    )
    for label, mutate in malformed_cases:
        malformed = copy.deepcopy(planned)
        mutate(malformed)
        try:
            validate_bundle(malformed)
        except ValidationError:
            pass
        else:
            raise AssertionError(f"{label} bypassed shared validation")
    baseline = load_strict_json(SOURCE_BASELINE)
    lasso_manifest = load_strict_json(LASSO_MANIFEST)
    mutated_baseline = copy.deepcopy(baseline)
    mutated_baseline["attempted_targets"][0]["source_references"][0] += "#changed"
    check(
        any(
            "source authority hash differs" in error
            for error in validation.validate_public_build_bundle_value(
                planned,
                "fixture:mutated-source-authority",
                baseline=mutated_baseline,
                lasso_manifest=lasso_manifest,
            )
        ),
        "mutated source authority payload retained its trusted hash",
    )
    mutated_lasso = copy.deepcopy(lasso_manifest)
    mutated_lasso["references"][0]["line"] += 1
    check(
        any(
            "Lasso authority hash differs" in error
            for error in validation.validate_public_build_bundle_value(
                planned,
                "fixture:mutated-lasso-authority",
                baseline=baseline,
                lasso_manifest=mutated_lasso,
            )
        ),
        "mutated Lasso authority payload retained its trusted hash",
    )


def test_planned_and_recorded_component_hash_lifecycle() -> None:
    planned = load_strict_json(PLANNED_BUNDLE)
    drifted = copy.deepcopy(planned)
    drifted["components"]["contract"]["sha256"] = "0" * 64
    planned_errors = validation.validate_public_build_bundle_value(
        drifted, "fixture:planned-live-drift"
    )
    recorded = copy.deepcopy(drifted)
    recorded["status"] = "recorded"
    recorded_errors = validation._component_errors(
        recorded, "fixture:recorded-live-drift"
    )
    check(
        any("live component drift" in error for error in planned_errors)
        and any("historical replay or record migration" in error for error in recorded_errors),
        "live component drift did not fail closed with the recorded migration trigger",
    )

    snapshot_root = WORK / "mise-lock-snapshot"
    lock_path = snapshot_root / planned["components"]["lockfile"]["path"]
    lock_path.parent.mkdir(mode=0o700, parents=True)
    reviewed_lock = (
        ROOT / planned["components"]["lockfile"]["path"]
    ).read_bytes()
    lock_path.write_bytes(reviewed_lock)
    original_validation_root = validation.ROOT
    validation.ROOT = snapshot_root
    try:
        retained_lock = validation.load_validated_mise_lock_bytes(
            planned,
            "fixture:mise-lock-snapshot",
        )
    finally:
        validation.ROOT = original_validation_root
    lock_path.write_bytes(b'[[tools.\"http:dotnet-sdk\"]]\nversion = \"changed\"\n')
    generated_root = snapshot_root / "generated-toolchain"
    runner._write_mise_config(generated_root, planned, retained_lock)
    generated_lock = generated_root / "home/.config/mise/mise.lock"
    check(
        retained_lock == reviewed_lock
        and generated_lock.read_bytes() == reviewed_lock
        and lock_path.read_bytes() != reviewed_lock,
        "generated mise lock followed a repository-path replacement",
    )


def test_exact_two_mode_command_topology() -> None:
    planned = load_strict_json(PLANNED_BUNDLE)
    commands = planned["protocol"]["commands"]
    check(len(commands) == 16, "command topology is not exactly sixteen commands")
    check(
        [command["id"] for command in commands] == list(COMMAND_IDS),
        "command topology differs from the shared exact order",
    )
    check(
        {mode: sum(command["source_mode"] == mode for command in commands)
         for mode in ("source-faithful", "public-only")}
        == {"source-faithful": 8, "public-only": 8},
        "command topology is not exactly two independent eight-command modes",
    )
    check(
        all(
            "--no-restore" in command["argv"]
            for command in commands
            if command["stage"] != "restore"
        ),
        "a downstream command can restore implicitly",
    )
    check(
        all("--no-build" not in command["argv"] for command in commands if command["stage"] == "test"),
        "test topology incorrectly suppresses build",
    )
    check(
        not any("$(" in argument for command in commands for argument in command["argv"]),
        "command topology contains an unevaluated MSBuild property expression",
    )
    for command in commands:
        argv = command["argv"]
        check("-noAutoResponse" in argv, "MSBuild auto response files remain enabled")
        check(
            "-p:ImportDirectoryBuildTargets=false" in argv,
            "MSBuild Directory.Build.targets imports remain enabled",
        )
        check(
            any(
                argument.startswith("-p:DirectoryPackagesPropsPath=")
                for argument in argv
            ),
            "MSBuild Directory.Packages.props isolation is not explicit",
        )
        check(
            not any("DirectoryBuildTargetsPath" in argument for argument in argv),
            "MSBuild Directory.Build.targets is redirected to a mutable path",
        )
        check(
            not any("ImportDirectoryBuildProps" in argument for argument in argv),
            "the audited checkout Directory.Build.props import was disabled",
        )
        if command["target"] == "AzureAuth.sln":
            check(
                "-p:ImportDirectorySolutionProps=false" in argv
                and "-p:ImportDirectorySolutionTargets=false" in argv,
                "solution-level ancestor imports remain enabled",
            )
    topology = preparation_topology()
    check(
        len(topology) == len({item["id"] for item in topology})
        == len(PREPARATIONS),
        "preparation topology is not complete and unique",
    )
    preparation_ids = [item["id"] for item in topology]
    install_index = preparation_ids.index("mise-install-dotnet-sdk")
    check(
        preparation_ids.index("prepare-dotnet-sdk-selection")
        < preparation_ids.index("dotnet-source-faithful-info")
        and preparation_ids.index("prepare-dotnet-sdk-selection")
        < preparation_ids.index("dotnet-public-only-info")
        and install_index < preparation_ids.index("verify-dotnet-installation")
        and install_index < preparation_ids.index("inspect-nuget-client-version")
        and all(
            install_index < index
            for index, item in enumerate(topology)
            if item["id"].startswith("dotnet-")
        ),
        "the first-run SDK installation is not ordered before SDK use",
    )
    check(
        supervision_bounds()
        == {
            "descendant_discovery_pass_seconds": 0.25,
            "max_discovered_processes": 2048,
            "fixed_point_seconds": 2.0,
            "capture_reader_grace_seconds": 0.5,
            "capture_reader_shutdown_seconds": 2.0,
            "source_max_entries": 32768,
            "source_per_file_bytes": 16777216,
            "source_aggregate_bytes": 268435456,
            "source_elapsed_seconds": 30.0,
        },
        "supervision bounds differ from the reviewed contract",
    )
    baseline = load_strict_json(
        ROOT / "docs/research/public-build-source-baseline.json"
    )
    command_cases: tuple[
        tuple[str, Any, str],
        ...,
    ] = (
        (
            "role-swap",
            lambda value: (
                value["protocol"]["commands"][0].__setitem__(
                    "id",
                    "source-faithful-build",
                ),
                value["protocol"]["commands"][1].__setitem__(
                    "id",
                    "source-faithful-restore",
                ),
            ),
            "contradicts its mode and stage",
        ),
        (
            "restore-after-dependent",
            lambda value: value["protocol"]["commands"].insert(
                1,
                value["protocol"]["commands"].pop(0),
            ),
            "dependency is not an earlier same-mode restore",
        ),
        (
            "build-test-order-swap",
            lambda value: value["protocol"]["commands"].__setitem__(
                slice(1, 3),
                list(reversed(value["protocol"]["commands"][1:3])),
            ),
            "fixed ordered topology",
        ),
        (
            "non-solution-entry-point",
            lambda value: (
                value["protocol"]["commands"][0].__setitem__(
                    "target",
                    "src/AzureAuth/AzureAuth.csproj",
                ),
                value["protocol"]["commands"][0]["argv"].__setitem__(
                    2,
                    "src/AzureAuth/AzureAuth.csproj",
                ),
            ),
            "does not use the audited entry point",
        ),
        (
            "argv-target-mismatch",
            lambda value: value["protocol"]["commands"][0]["argv"].__setitem__(
                2,
                "src/AzureAuth/AzureAuth.csproj",
            ),
            "violates execution invariants",
        ),
        (
            "unreviewed-source",
            lambda value: value["protocol"]["commands"][8]["argv"].extend(
                ["--source", "https://example.invalid/v3/index.json"]
            ),
            "violates execution invariants",
        ),
        (
            "duplicate-config",
            lambda value: value["protocol"]["commands"][8]["argv"].extend(
                ["--configfile", "/tmp/unreviewed.config"]
            ),
            "violates execution invariants",
        ),
        (
            "package-output-override",
            lambda value: value["protocol"]["commands"][11]["argv"].extend(
                ["--output", "/tmp/unreviewed-packages"]
            ),
            "violates execution invariants",
        ),
        (
            "artifacts-path-override",
            lambda value: value["protocol"]["commands"][9]["argv"].append(
                "-p:ArtifactsPath=/tmp/unreviewed-artifacts"
            ),
            "violates execution invariants",
        ),
        (
            "response-file",
            lambda value: value["protocol"]["commands"][9]["argv"].append(
                "@/tmp/unreviewed.rsp"
            ),
            "violates execution invariants",
        ),
        (
            "reordered-options",
            lambda value: value["protocol"]["commands"][9]["argv"].__setitem__(
                slice(3, 7),
                value["protocol"]["commands"][9]["argv"][5:7]
                + value["protocol"]["commands"][9]["argv"][3:5],
            ),
            "violates execution invariants",
        ),
    )
    for label, mutate, expected_error in command_cases:
        candidate = copy.deepcopy(planned)
        mutate(candidate)
        errors = validation._command_errors(candidate, baseline, label)
        check(
            any(expected_error in error for error in errors),
            f"{label} command mutation was accepted: {errors}",
        )


def test_documented_nuget_cache_location_output() -> None:
    mode = source_mode_plan()[0]
    expected = {
        "http-cache": mode["nuget_http_cache_root"],
        "global-packages": mode["nuget_packages_root"],
        "temp": mode["nuget_scratch_root"],
        "plugins-cache": mode["nuget_plugins_cache_root"],
    }
    payload = "\n".join(
        [
            f"info : http-cache: {expected['http-cache']}/",
            f"info : global-packages: {expected['global-packages']}//",
            f"info : temp: {expected['temp']}/",
            f"info : plugins-cache: {expected['plugins-cache']}/",
        ]
    ).encode()
    check(
        runner._parse_nuget_cache_locations(payload, mode) == expected,
        "documented Linux NuGet cache output did not return canonical expected roots",
    )
    for invalid in (
        payload.replace(
            expected["http-cache"].encode(),
            b"/genuinely/different",
        ),
        payload.replace(
            expected["temp"].encode(),
            b"relative/path",
        ),
    ):
        try:
            runner._parse_nuget_cache_locations(invalid, mode)
        except ValidationError:
            pass
        else:
            raise AssertionError("genuinely different NuGet cache location was accepted")


def test_restore_metadata_isolation_binding() -> None:
    projection = load_strict_json(
        ROOT
        / "tools/fixtures/public-build/testhelper.expected-projection.json"
    )["assets_projection"]
    mode = {
        "checkout_root": "/fixture/checkout",
        "nuget_packages_root": "/fixture/packages/source-faithful",
        "generated_nuget_config": None,
        "package_sources": [
            "https://pkgs.dev.azure.com/office/_packaging/Office/nuget/v3/index.json"
        ],
    }
    metadata = projection["restore_metadata"]
    check(
        not validation._restore_metadata_errors(
            metadata,
            mode,
            "source-faithful/target-testhelper-net8-0",
            "fixture",
        ),
        "matching restore metadata was rejected",
    )
    for field, value in {
        "packages_path": "/home/attacker/packages",
        "package_folders": ["/home/attacker/packages"],
        "config_file_paths": ["/home/attacker/NuGet.Config"],
        "sources": ["https://attacker.example/v3/index.json"],
    }.items():
        changed = copy.deepcopy(metadata)
        changed[field] = value
        check(
            any(
                "restore metadata differs from its isolated mode" in error
                for error in validation._restore_metadata_errors(
                    changed,
                    mode,
                    "source-faithful/target-testhelper-net8-0",
                    f"fixture-{field}",
                )
            ),
            f"ambient restore metadata field {field} was accepted",
        )
    procfd_metadata = copy.deepcopy(metadata)
    procfd_metadata["config_file_paths"] = [
        "/proc/self/fd/42/nuget.config"
    ]
    check(
        any(
            "restore metadata differs from its isolated mode" in error
            for error in validation._restore_metadata_errors(
                procfd_metadata,
                mode,
                "source-faithful/target-testhelper-net8-0",
                "fixture-procfd-config-path",
            )
        ),
        "descriptor-spelled restore config metadata was accepted as canonical",
    )
    recorded, logs, _, _ = synthetic_case(
        "source-faithful-relative-config-metadata",
        asset_modes=["source-faithful"],
        use_real_candidate_validator=True,
    )
    source_restore = next(
        item
        for item in logs
        if item["role"] == "dotnet"
        and item["runtime_argv"]
        and item["runtime_argv"][0] == "restore"
        and "--configfile" in item["runtime_argv"]
    )
    source_target = next(
        target
        for mode_evidence in recorded["runtime_evidence"][
            "dependency_evidence"
        ]["modes"]
        if mode_evidence["source_mode"] == "source-faithful"
        for target in mode_evidence["targets"]
        if target["target_id"] == "target-testhelper-net8-0"
    )
    check(
        source_restore["runtime_argv"][
            source_restore["runtime_argv"].index("--configfile") + 1
        ]
        == "nuget.config"
        and source_target["status"] == "valid"
        and recorded["status"] == "recorded",
        "relative source-faithful config did not produce replayable metadata",
    )


def rebase_value(value: Any, toolchain_root: Path, selection_root: Path) -> Any:
    if isinstance(value, str):
        return value.replace(str(TOOLCHAIN_ROOT), str(toolchain_root)).replace(
            str(SELECTION_ROOT), str(selection_root)
        )
    if isinstance(value, list):
        return [rebase_value(item, toolchain_root, selection_root) for item in value]
    if isinstance(value, dict):
        return {
            key: rebase_value(item, toolchain_root, selection_root)
            for key, item in value.items()
        }
    return value


def restore_fixed_paths_for_validation(
    value: Any,
    toolchain_root: Path,
    selection_root: Path,
) -> Any:
    if isinstance(value, str):
        return value.replace(str(toolchain_root), str(TOOLCHAIN_ROOT)).replace(
            str(selection_root),
            str(SELECTION_ROOT),
        )
    if isinstance(value, list):
        return [
            restore_fixed_paths_for_validation(
                item,
                toolchain_root,
                selection_root,
            )
            for item in value
        ]
    if isinstance(value, dict):
        normalized = {
            restore_fixed_paths_for_validation(
                key,
                toolchain_root,
                selection_root,
            ): restore_fixed_paths_for_validation(
                item,
                toolchain_root,
                selection_root,
            )
            for key, item in value.items()
        }
        if normalized.get("disposition") == "retained-sanitized":
            normalized["sanitized_bytes"] = max(
                normalized["sanitized_bytes"],
                len(normalized["excerpt"].encode("utf-8")),
            )
        return normalized
    return value


def normalized_recorded_errors(
    recorded: dict[str, Any],
    label: str,
) -> list[str]:
    normalized = restore_fixed_paths_for_validation(
        recorded,
        Path(recorded["isolation"]["toolchain_root"]),
        Path(recorded["isolation"]["selection_root"]),
    )
    normalized["runtime_evidence"]["runtime_context"][
        "mise_executable_sha256"
    ] = normalized["environment"]["mise"]["executable_sha256"]
    for component in normalized["components"].values():
        component["sha256"] = hashlib.sha256(
            (ROOT / component["path"]).read_bytes()
        ).hexdigest()
    normalized["runtime_evidence"]["receipt_binding"]["digest"] = receipt_digest(
        normalized
    )
    return validation.validate_public_build_bundle_instance(
        normalized,
        label,
    )


def synthetic_case(
    name: str,
    *,
    fail_restore_mode: str | None = None,
    fail_git_fetch_mode: str | None = None,
    fail_git_checkout_mode: str | None = None,
    fail_dotnet_info_mode: str | None = None,
    mismatch_dotnet_info_mode: str | None = None,
    invalid_cache_locations_mode: str | None = None,
    mismatch_git_head_mode: str | None = None,
    fail_integrity_baseline_mode: str | None = None,
    mismatch_mise_version: bool = False,
    occupy_public_config: bool = False,
    timeout_command: str | None = None,
    sensitive_command: str | None = None,
    overflow_command: str | None = None,
    overflow_sensitive_command: str | None = None,
    mutate_command: str | None = None,
    chmod_command: str | None = None,
    untracked_command: str | None = None,
    source_type_command: str | None = None,
    replace_checkout_during_command: str | None = None,
    replace_checkout_after_preparation: str | None = None,
    asset_modes: list[str] | None = None,
    sensitive_asset_modes: list[str] | None = None,
    symlink_asset_modes: list[str] | None = None,
    precreate_toolchain_root: bool = False,
    precreate_selection_root: bool = False,
    replace_mise_after_verification: bool = False,
    capture_failure_label: str | None = None,
    spawn_failure_label: str | None = None,
    force_unproved_label: str | None = None,
    replace_selection_root_before_identity_check: bool = False,
    candidate_validation_error: str | None = None,
    use_real_candidate_validator: bool = False,
    cancel_after_label: str | None = None,
    fail_root_marker_kind: str | None = None,
    root_creation_fault: str | None = None,
    tamper_selection_marker_before_identity_check: bool = False,
    replace_selection_root_before_asset_inspection: bool = False,
    replace_selection_root_after_asset_publication: bool = False,
    recording_fault: str | None = None,
    cancel_after_asset_publication: bool = False,
    capture_recording_fault: str | None = None,
    capture_recording_label: str | None = None,
    mutate_asset_after_restore_mode: str | None = None,
    fail_runtime_context_git_digest: bool = False,
    cancel_during_recording_exchange: bool = False,
    replace_selection_root_during_recording_exchange: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]], int, int]:
    case = WORK / name
    case.mkdir(mode=0o700)
    toolchain_base = case / "toolchains"
    selection_base = case / "selections"
    toolchain_base.mkdir(mode=0o700)
    selection_base.mkdir(mode=0o700)
    toolchain_root = toolchain_base / "bundle"
    selection_root = selection_base / "bundle"
    if precreate_toolchain_root:
        toolchain_root.mkdir(mode=0o700)
    if precreate_selection_root:
        selection_root.mkdir(mode=0o700)
    planned = rebase_value(
        load_strict_json(PLANNED_BUNDLE),
        toolchain_root,
        selection_root,
    )
    mise_lock_bytes = (
        ROOT / planned["components"]["lockfile"]["path"]
    ).read_bytes()
    checkout_entered_marker = case / "checkout-entered"
    checkout_release_marker = case / "checkout-release"
    command_ids = {
        json.dumps(command["argv"][1:]): command["id"]
        for command in planned["protocol"]["commands"]
    }
    control = {
        "command_ids": command_ids,
        "fail_restore_mode": fail_restore_mode,
        "fail_git_fetch_mode": fail_git_fetch_mode,
        "fail_git_checkout_mode": fail_git_checkout_mode,
        "fail_dotnet_info_mode": fail_dotnet_info_mode,
        "mismatch_dotnet_info_mode": mismatch_dotnet_info_mode,
        "invalid_cache_locations_mode": invalid_cache_locations_mode,
        "mismatch_git_head_mode": mismatch_git_head_mode,
        "mismatch_mise_version": mismatch_mise_version,
        "occupy_public_config": occupy_public_config,
        "sleep_command": timeout_command,
        "sensitive_command": sensitive_command,
        "overflow_command": overflow_command,
        "overflow_sensitive_command": overflow_sensitive_command,
        "mutate_command": mutate_command,
        "chmod_command": chmod_command,
        "untracked_command": untracked_command,
        "source_type_command": source_type_command,
        "replace_checkout_during_command": replace_checkout_during_command,
        "checkout_entered_marker": str(checkout_entered_marker),
        "checkout_release_marker": str(checkout_release_marker),
        "asset_modes": asset_modes or [],
        "sensitive_asset_modes": sensitive_asset_modes or [],
        "symlink_asset_modes": symlink_asset_modes or [],
        "asset_fixture": str(
            ROOT / "tools/fixtures/public-build/testhelper.project.assets.json"
        ),
    }
    (selection_base / "bundle.fake-control.json").write_text(
        json.dumps(control),
        encoding="utf-8",
    )
    bundle_path = case / "bundle.json"
    bundle_path.write_text(json.dumps(planned, indent=2) + "\n", encoding="utf-8")
    old_inode = bundle_path.stat().st_ino
    fake_bin = case / "bin"
    fake_bin.mkdir(mode=0o700)
    mise = fake_bin / "mise"
    git = fake_bin / "git"
    shutil.copyfile(HELPER, mise)
    shutil.copyfile(HELPER, git)
    mise.chmod(0o700)
    git.chmod(0o700)
    mise_identity = runner.verify_mise_executable(
        mise,
        expected_sha256=runner._path_sha256(mise),
    )
    if replace_mise_after_verification:
        replacement = fake_bin / "mise.replacement"
        replacement.write_text(
            "#!/usr/bin/env python3\nraise SystemExit(97)\n",
            encoding="ascii",
        )
        replacement.chmod(0o700)
        os.replace(replacement, mise)
    runner.ASSETS_DIRECTORY = case / "retained-assets"
    original_new_capture = runner._new_capture
    original_run_supervised = runner.run_supervised
    original_candidate_validator = runner.validate_public_build_bundle_instance
    original_verify_root_identity = runner.verify_root_identity
    original_open_verified_root_identity = runner._open_verified_root_identity
    original_write_root_marker = runner._write_root_marker
    original_open_child_directory = runner._open_child_directory
    original_os_stat = runner.os.stat
    original_atomic_replace_bundle = runner._atomic_replace_bundle
    original_leaf_identity = runner._leaf_identity
    original_dependency_evidence = runner._dependency_evidence
    original_atomic_publish_asset = runner._atomic_publish_asset
    original_path_sha256 = runner._path_sha256
    original_open_recording_identity = runner._open_recording_identity
    original_open_checkout_identity = runner._open_checkout_identity
    original_checkout_fingerprint = runner._checkout_fingerprint
    retained_selection_descriptors: list[int] = []
    created_capture_identities: list[Any] = []
    created_asset_identities: list[Any] = []
    recording_identities: list[Any] = []
    checkout_identities: list[Any] = []
    cancellation_event = threading.Event()
    if fail_root_marker_kind is not None:
        marker_calls = 0

        def fail_selected_root_marker(
            leaf_descriptor: int,
            payload: bytes,
        ) -> Any:
            nonlocal marker_calls
            marker_calls += 1
            selected = "toolchain" if marker_calls == 1 else "selection"
            if selected == fail_root_marker_kind:
                raise PermissionError("synthetic post-mkdir marker failure")
            return original_write_root_marker(leaf_descriptor, payload)

        runner._write_root_marker = fail_selected_root_marker
    if root_creation_fault is not None:
        faulted = False
        selection_parent = selection_base.stat()

        if root_creation_fault == "selection-stat":
            def fail_selection_stat(
                path: Any,
                *arguments: Any,
                **keywords: Any,
            ) -> Any:
                nonlocal faulted
                directory_descriptor = keywords.get("dir_fd")
                if (
                    not faulted
                    and path == selection_root.name
                    and directory_descriptor is not None
                ):
                    parent = os.fstat(directory_descriptor)
                    if (
                        parent.st_dev == selection_parent.st_dev
                        and parent.st_ino == selection_parent.st_ino
                    ):
                        faulted = True
                        raise OSError("synthetic immediate post-mkdir stat failure")
                return original_os_stat(path, *arguments, **keywords)

            runner.os.stat = fail_selection_stat
        elif root_creation_fault == "selection-open":
            def fail_selection_open(
                parent: int,
                name: str,
                label: Path,
            ) -> int:
                nonlocal faulted
                if not faulted and label == selection_root:
                    faulted = True
                    raise RootCreationError(
                        "synthetic immediate post-mkdir open failure"
                    )
                return original_open_child_directory(parent, name, label)

            runner._open_child_directory = fail_selection_open
        else:
            raise AssertionError(f"unknown root creation fault: {root_creation_fault}")
    def instrument_capture(
        capture_dir: Path,
        label: str,
        stream: str,
    ):
        if label == capture_failure_label and stream == "stdout":
            raise PermissionError("synthetic capture setup failure")
        identity, destination = original_new_capture(capture_dir, label, stream)
        created_capture_identities.append(identity)
        return identity, destination

    def instrument_asset(
        payload: bytes,
        destination: Path,
        published_assets: list[Any],
    ) -> Any:
        identity = original_atomic_publish_asset(
            payload,
            destination,
            published_assets,
        )
        created_asset_identities.append(identity)
        return identity

    def instrument_recording(path: Path) -> Any:
        identity = original_open_recording_identity(path)
        recording_identities.append(identity)
        return identity

    def instrument_checkout(path: Path) -> Any:
        identity = original_open_checkout_identity(path)
        checkout_identities.append(identity)
        return identity

    runner._new_capture = instrument_capture
    runner._atomic_publish_asset = instrument_asset
    runner._open_recording_identity = instrument_recording
    runner._open_checkout_identity = instrument_checkout
    if fail_integrity_baseline_mode is not None:
        integrity_baseline_failed = False

        def fail_selected_integrity_baseline(
            identity: Any,
            **keywords: Any,
        ) -> str:
            nonlocal integrity_baseline_failed
            if (
                not integrity_baseline_failed
                and identity.canonical_path.parent.name
                == fail_integrity_baseline_mode
            ):
                integrity_baseline_failed = True
                raise ValidationError("synthetic integrity baseline failure")
            return original_checkout_fingerprint(identity, **keywords)

        runner._checkout_fingerprint = fail_selected_integrity_baseline
    if fail_runtime_context_git_digest:
        def fail_git_digest(path: Path) -> str:
            if path == git:
                raise OSError("synthetic Git digest failure")
            return original_path_sha256(path)

        runner._path_sha256 = fail_git_digest
    if force_unproved_label is not None:
        def force_selected_unproved(
            argv: Any,
            **keywords: Any,
        ):
            if keywords.get("label") == force_unproved_label:
                keywords["force_unproved"] = True
            return original_run_supervised(argv, **keywords)

        runner.run_supervised = force_selected_unproved
    if timeout_command is not None:
        def shorten_selected_timeout(
            argv: Any,
            **keywords: Any,
        ):
            if keywords.get("label") == timeout_command:
                keywords["timeout_seconds"] = 0.08
            return original_run_supervised(argv, **keywords)

        runner.run_supervised = shorten_selected_timeout
    if spawn_failure_label is not None:
        def fail_selected_spawn(
            argv: Any,
            **keywords: Any,
        ):
            if keywords.get("label") != spawn_failure_label:
                return original_run_supervised(argv, **keywords)
            if mutate_command == spawn_failure_label:
                Path(keywords["cwd"]).joinpath("AzureAuth.sln").write_text(
                    "mutated before spawn failure\n",
                    encoding="utf-8",
                )
            original_popen = runner.subprocess.Popen
            runner.subprocess.Popen = lambda *args, **kwargs: (
                (_ for _ in ()).throw(OSError("synthetic Popen failure"))
            )
            try:
                return original_run_supervised(argv, **keywords)
            finally:
                runner.subprocess.Popen = original_popen

        runner.run_supervised = fail_selected_spawn
    if cancel_after_label is not None:
        def cancel_after_selected(
            argv: Any,
            **keywords: Any,
        ):
            result = original_run_supervised(argv, **keywords)
            if keywords.get("label") == cancel_after_label:
                cancellation_event.set()
            return result

        runner.run_supervised = cancel_after_selected
    if replace_checkout_during_command is not None:
        run_before_checkout_replacement = runner.run_supervised

        def replace_checkout_after_child_entry(
            argv: Any,
            **keywords: Any,
        ):
            if keywords.get("label") != replace_checkout_during_command:
                return run_before_checkout_replacement(argv, **keywords)
            command = next(
                item
                for item in planned["protocol"]["commands"]
                if item["id"] == replace_checkout_during_command
            )
            mode = next(
                item
                for item in planned["isolation"]["source_modes"]
                if item["id"] == command["source_mode"]
            )
            checkout = Path(mode["checkout_root"])
            displaced = checkout.with_name("checkout-retained-a")
            replacement = checkout.with_name("checkout-replacement-b")
            replacement_error: list[BaseException] = []

            def replace() -> None:
                try:
                    deadline = time.monotonic() + 10
                    while not checkout_entered_marker.exists():
                        if time.monotonic() > deadline:
                            raise AssertionError(
                                "checkout replacement child did not enter retained A"
                            )
                        time.sleep(0.01)
                    shutil.copytree(checkout, replacement, symlinks=True)
                    checkout.rename(displaced)
                    replacement.rename(checkout)
                    checkout_release_marker.write_text("continue", encoding="ascii")
                except BaseException as error:
                    replacement_error.append(error)
                    checkout_release_marker.write_text("abort", encoding="ascii")

            thread = threading.Thread(target=replace)
            thread.start()
            result = run_before_checkout_replacement(argv, **keywords)
            thread.join(timeout=12)
            check(not thread.is_alive(), "checkout replacement helper did not finish")
            if replacement_error:
                raise replacement_error[0]
            return result

        runner.run_supervised = replace_checkout_after_child_entry
    if replace_checkout_after_preparation is not None:
        run_before_preparation_replacement = runner.run_supervised

        def replace_checkout_after_preparation_child(
            argv: Any,
            **keywords: Any,
        ):
            result = run_before_preparation_replacement(argv, **keywords)
            if keywords.get("label") != replace_checkout_after_preparation:
                return result
            mode = next(
                item
                for item in planned["isolation"]["source_modes"]
                if replace_checkout_after_preparation.startswith(
                    f"git-{item['id']}-"
                )
            )
            checkout = Path(mode["checkout_root"])
            displaced = checkout.with_name("checkout-retained-preparation-a")
            replacement = checkout.with_name("checkout-replacement-preparation-b")
            shutil.copytree(checkout, replacement, symlinks=True)
            checkout.rename(displaced)
            replacement.rename(checkout)
            return result

        runner.run_supervised = replace_checkout_after_preparation_child
    replaced_before_identity = False
    tampered_before_identity = False

    def open_selection_identity(identity: Any) -> int | None:
        nonlocal replaced_before_identity, tampered_before_identity
        if (
            identity.path == selection_root
            and replace_selection_root_before_identity_check
            and not replaced_before_identity
        ):
            replaced_before_identity = True
            displaced = selection_root.with_name("bundle-displaced-before-identity")
            selection_root.rename(displaced)
            selection_root.mkdir(mode=0o700)
        if (
            identity.path == selection_root
            and tamper_selection_marker_before_identity_check
            and not tampered_before_identity
        ):
            tampered_before_identity = True
            identity.path.joinpath(ROOT_MARKER).write_text(
                "tampered\n",
                encoding="utf-8",
            )
        descriptor = original_open_verified_root_identity(identity)
        if identity.path == selection_root and descriptor is not None:
            retained_selection_descriptors.append(descriptor)
        return descriptor

    runner._open_verified_root_identity = open_selection_identity
    if recording_fault is not None:
        def faulted_atomic_replace(
            identity: Any,
            candidate: dict[str, Any],
            published_assets: list[Any],
            precommit_check: Any = None,
        ) -> None:
            def alter_asset(kind: str) -> None:
                target = published_assets[0].path
                if kind == "delete":
                    target.unlink()
                    return
                actor = target.with_name(f"{target.name}.actor")
                actor.write_bytes(b"actor-replacement")
                os.replace(actor, target)

            if recording_fault in {
                "pre-exchange-asset-delete",
                "pre-exchange-asset-replace",
            }:
                alter_asset(
                    "delete"
                    if recording_fault.endswith("delete")
                    else "replace"
                )
                original_atomic_replace_bundle(
                    identity,
                    candidate,
                    published_assets,
                    precommit_check=precommit_check,
                )
                return
            if recording_fault in {
                "post-exchange-asset-delete",
                "post-exchange-asset-replace",
                "post-exchange-asset-replace-indeterminate",
            }:
                original_exchange = runner._rename_exchange
                exchange_calls = 0

                def alter_after_exchange(
                    directory_descriptor: int,
                    left: str,
                    right: str,
                ) -> None:
                    nonlocal exchange_calls
                    exchange_calls += 1
                    if (
                        recording_fault
                        == "post-exchange-asset-replace-indeterminate"
                        and exchange_calls == 2
                    ):
                        raise OSError("synthetic reversal exchange failure")
                    original_exchange(directory_descriptor, left, right)
                    if exchange_calls == 1:
                        alter_asset(
                            "delete"
                            if recording_fault.endswith("delete")
                            else "replace"
                        )

                runner._rename_exchange = alter_after_exchange
                try:
                    original_atomic_replace_bundle(
                        identity,
                        candidate,
                        published_assets,
                        precommit_check=precommit_check,
                    )
                finally:
                    runner._rename_exchange = original_exchange
                return
            if recording_fault == "candidate-write":
                original_write = runner.os.write
                failed = False

                def fail_after_create(descriptor: int, content: bytes) -> int:
                    nonlocal failed
                    if not failed:
                        failed = True
                        raise OSError("synthetic candidate write failure")
                    return original_write(descriptor, content)

                runner.os.write = fail_after_create
                try:
                    original_atomic_replace_bundle(
                        identity,
                        candidate,
                        published_assets,
                        precommit_check=precommit_check,
                    )
                finally:
                    runner.os.write = original_write
                return
            if recording_fault == "exchange":
                original_exchange = runner._rename_exchange
                runner._rename_exchange = lambda *args, **kwargs: (
                    (_ for _ in ()).throw(OSError("synthetic exchange failure"))
                )
                try:
                    original_atomic_replace_bundle(
                        identity,
                        candidate,
                        published_assets,
                        precommit_check=precommit_check,
                    )
                finally:
                    runner._rename_exchange = original_exchange
                return
            if recording_fault == "concurrent-replacement":
                original_exchange = runner._rename_exchange
                replaced = False

                def replace_before_exchange(
                    directory_descriptor: int,
                    left: str,
                    right: str,
                ) -> None:
                    nonlocal replaced
                    if not replaced:
                        replaced = True
                        actor = f".{right}.concurrent"
                        runner._write_exclusive_at(
                            directory_descriptor,
                            actor,
                            b'{"actor":"replacement"}\n',
                            0o600,
                        )
                        os.rename(
                            actor,
                            right,
                            src_dir_fd=directory_descriptor,
                            dst_dir_fd=directory_descriptor,
                        )
                    original_exchange(directory_descriptor, left, right)

                runner._rename_exchange = replace_before_exchange
                try:
                    original_atomic_replace_bundle(
                        identity,
                        candidate,
                        published_assets,
                        precommit_check=precommit_check,
                    )
                finally:
                    runner._rename_exchange = original_exchange
                return
            if recording_fault == "post-exchange-displaced-replacement":
                original_exchange = runner._rename_exchange
                replaced = False

                def replace_displaced_before_first_inspection(
                    directory_descriptor: int,
                    left: str,
                    right: str,
                ) -> None:
                    nonlocal replaced
                    original_exchange(directory_descriptor, left, right)
                    if not replaced:
                        replaced = True
                        actor = f"{left}.actor"
                        runner._write_exclusive_at(
                            directory_descriptor,
                            actor,
                            b'{"actor":"replacement"}\n',
                            0o600,
                        )
                        os.rename(
                            actor,
                            left,
                            src_dir_fd=directory_descriptor,
                            dst_dir_fd=directory_descriptor,
                        )

                runner._rename_exchange = replace_displaced_before_first_inspection
                try:
                    original_atomic_replace_bundle(
                        identity,
                        candidate,
                        published_assets,
                        precommit_check=precommit_check,
                    )
                finally:
                    runner._rename_exchange = original_exchange
                return
            if recording_fault == "post-commit-fsync":
                original_fsync = runner.os.fsync

                def fail_parent_fsync(descriptor: int) -> None:
                    if descriptor == identity.parent_descriptor:
                        raise OSError("synthetic parent fsync failure")
                    original_fsync(descriptor)

                runner.os.fsync = fail_parent_fsync
                try:
                    original_atomic_replace_bundle(
                        identity,
                        candidate,
                        published_assets,
                        precommit_check=precommit_check,
                    )
                finally:
                    runner.os.fsync = original_fsync
                return
            if recording_fault == "post-exchange-displaced-read":
                def fail_displaced_read(
                    directory_descriptor: int,
                    name: str,
                ) -> tuple[int, int, str]:
                    if name.startswith(f".{identity.basename}.recorded-"):
                        raise OSError(
                            "synthetic displaced planned-bundle inspection failure"
                        )
                    return original_leaf_identity(directory_descriptor, name)

                runner._leaf_identity = fail_displaced_read
                try:
                    original_atomic_replace_bundle(
                        identity,
                        candidate,
                        published_assets,
                        precommit_check=precommit_check,
                    )
                finally:
                    runner._leaf_identity = original_leaf_identity
                return
            raise AssertionError(f"unknown recording fault: {recording_fault}")

        runner._atomic_replace_bundle = faulted_atomic_replace
    if (
        replace_selection_root_before_asset_inspection
        or replace_selection_root_after_asset_publication
        or cancel_after_asset_publication
        or mutate_asset_after_restore_mode is not None
    ):
        root_replaced = False

        def replace_selection_root(label: str) -> None:
            nonlocal root_replaced
            if root_replaced:
                return
            root_replaced = True
            displaced = selection_root.with_name(f"bundle-displaced-{label}")
            selection_root.rename(displaced)
            selection_root.mkdir(mode=0o700)

        def dependency_with_root_replacement(
            *arguments: Any,
            **keywords: Any,
        ) -> Any:
            if replace_selection_root_before_asset_inspection:
                replace_selection_root("before-assets")
            if mutate_asset_after_restore_mode is not None:
                mode = next(
                    item
                    for item in planned["isolation"]["source_modes"]
                    if item["id"] == mutate_asset_after_restore_mode
                )
                asset_path = (
                    Path(mode["obj_root"])
                    / "TestHelper/project.assets.json"
                )
                asset = json.loads(asset_path.read_text(encoding="utf-8"))
                asset["ignored_by_schema"] = {"changed": True}
                asset_path.write_text(json.dumps(asset), encoding="utf-8")
            evidence = original_dependency_evidence(*arguments, **keywords)
            if replace_selection_root_after_asset_publication:
                replace_selection_root("after-assets")
            if cancel_after_asset_publication:
                cancellation_event.set()
            return evidence

        runner._dependency_evidence = dependency_with_root_replacement
    original_rename_exchange = runner._rename_exchange
    exchange_injections = 0
    if (
        capture_recording_fault is not None
        or cancel_during_recording_exchange
        or replace_selection_root_during_recording_exchange
    ):
        def mutate_retained_capture(action: str) -> None:
            identity = next(
                item
                for item in created_capture_identities
                if item.directory_descriptor >= 0
                and item.leaf_sha256 is not None
                and (
                    capture_recording_label is None
                    or item.path.name.startswith(f"{capture_recording_label}-")
                )
            )
            if action == "delete":
                identity.path.unlink()
                return
            replacement = identity.path.with_name(
                f"{identity.path.name}.actor"
            )
            replacement.write_bytes(b"actor-capture-replacement")
            os.replace(replacement, identity.path)

        def inject_recording_window(
            directory_descriptor: int,
            left: str,
            right: str,
        ) -> None:
            nonlocal exchange_injections
            exchange_injections += 1
            if (
                exchange_injections == 1
                and capture_recording_fault is not None
                and capture_recording_fault.startswith("pre-exchange-")
            ):
                mutate_retained_capture(
                    capture_recording_fault.removeprefix("pre-exchange-")
                )
            original_rename_exchange(directory_descriptor, left, right)
            if exchange_injections == 1:
                if (
                    capture_recording_fault is not None
                    and capture_recording_fault.startswith("post-exchange-")
                ):
                    mutate_retained_capture(
                        capture_recording_fault.removeprefix("post-exchange-")
                    )
                if cancel_during_recording_exchange:
                    cancellation_event.set()
                if replace_selection_root_during_recording_exchange:
                    displaced = selection_root.with_name(
                        "bundle-displaced-during-exchange"
                    )
                    selection_root.rename(displaced)
                    selection_root.mkdir(mode=0o700)

        runner._rename_exchange = inject_recording_window
    execution_error: BaseException | None = None
    try:
        if use_real_candidate_validator:
            def validate_synthetic_candidate(
                candidate: dict[str, Any],
                relative_path: str,
                **keywords: Any,
            ) -> list[str]:
                normalized = restore_fixed_paths_for_validation(
                    candidate,
                    toolchain_root,
                    selection_root,
                )
                normalized["runtime_evidence"]["runtime_context"][
                    "mise_executable_sha256"
                ] = normalized["environment"]["mise"]["executable_sha256"]
                for component in normalized["components"].values():
                    component["sha256"] = hashlib.sha256(
                        (ROOT / component["path"]).read_bytes()
                    ).hexdigest()
                validation_assets = case / "validation-assets"
                for mode_evidence in normalized["runtime_evidence"][
                    "dependency_evidence"
                ]["modes"]:
                    for target in mode_evidence["targets"]:
                        asset = target.get("asset")
                        if asset is None:
                            continue
                        source = (
                            runner.ASSETS_DIRECTORY
                            / PurePosixPath(asset["path"]).name
                        )
                        normalized_asset = restore_fixed_paths_for_validation(
                            json.loads(source.read_text(encoding="utf-8")),
                            toolchain_root,
                            selection_root,
                        )
                        asset_bytes = json.dumps(normalized_asset).encode("utf-8")
                        validation_assets.mkdir(mode=0o700, exist_ok=True)
                        (validation_assets / source.name).write_bytes(asset_bytes)
                        asset_sha256 = hashlib.sha256(asset_bytes).hexdigest()
                        asset["sha256"] = asset_sha256
                        asset["projection"]["assets_file_sha256"] = asset_sha256
                normalized["runtime_evidence"]["receipt_binding"]["digest"] = (
                    receipt_digest(normalized)
                )
                original_asset_reader = validation._read_no_follow_bounded

                def read_synthetic_asset(
                    root: Path,
                    asset_path: PurePosixPath,
                    limit: int,
                ) -> bytes:
                    if asset_path.parent == PurePosixPath(
                        "docs/research/experiments/assets"
                    ):
                        return original_asset_reader(
                            validation_assets,
                            PurePosixPath(asset_path.name),
                            limit,
                        )
                    return original_asset_reader(root, asset_path, limit)

                validation._read_no_follow_bounded = read_synthetic_asset
                try:
                    return original_candidate_validator(
                        normalized,
                        relative_path,
                        **keywords,
                    )
                finally:
                    validation._read_no_follow_bounded = original_asset_reader

            runner.validate_public_build_bundle_instance = (
                validate_synthetic_candidate
            )
        else:
            runner.validate_public_build_bundle_instance = (
                lambda *args, **kwargs: (
                    [] if candidate_validation_error is None
                    else [candidate_validation_error]
                )
            )
        try:
            recorded = execute_planned_bundle(
                bundle_path,
                planned,
                source_baseline=load_strict_json(SOURCE_BASELINE),
                mise_lock_bytes=mise_lock_bytes,
                mise_identity=mise_identity,
                git_executable=git,
                subreaper_enabled=SUBREAPER_ENABLED,
                cancel_event=cancellation_event,
            )
        except (OSError, ValidationError, runner.RecordingError) as error:
            if (
                candidate_validation_error is None
                and recording_fault is None
                and not fail_runtime_context_git_digest
            ):
                raise
            execution_error = error
            recorded = load_strict_json(bundle_path)
    finally:
        runner._new_capture = original_new_capture
        runner.run_supervised = original_run_supervised
        runner.validate_public_build_bundle_instance = original_candidate_validator
        runner.verify_root_identity = original_verify_root_identity
        runner._open_verified_root_identity = original_open_verified_root_identity
        runner._write_root_marker = original_write_root_marker
        runner._open_child_directory = original_open_child_directory
        runner.os.stat = original_os_stat
        runner._atomic_replace_bundle = original_atomic_replace_bundle
        runner._leaf_identity = original_leaf_identity
        runner._dependency_evidence = original_dependency_evidence
        runner._atomic_publish_asset = original_atomic_publish_asset
        runner._path_sha256 = original_path_sha256
        runner._open_recording_identity = original_open_recording_identity
        runner._open_checkout_identity = original_open_checkout_identity
        runner._checkout_fingerprint = original_checkout_fingerprint
        runner._rename_exchange = original_rename_exchange
        os.close(mise_identity.descriptor)
    for descriptor in retained_selection_descriptors:
        try:
            os.fstat(descriptor)
        except OSError:
            pass
        else:
            raise AssertionError("selection-root identity descriptor leaked")
    for identity in created_capture_identities:
        if identity.directory_descriptor >= 0:
            raise AssertionError("capture identity descriptor leaked")
    for identity in created_asset_identities:
        if identity.directory_descriptor >= 0:
            raise AssertionError("published asset identity descriptor leaked")
    for identity in recording_identities:
        for descriptor in (identity.descriptor, identity.parent_descriptor):
            try:
                os.fstat(descriptor)
            except OSError:
                pass
            else:
                raise AssertionError("recording identity descriptor leaked")
    for identity in checkout_identities:
        if identity.descriptor >= 0:
            raise AssertionError("checkout identity descriptor leaked")
    new_inode = bundle_path.stat().st_ino
    if candidate_validation_error is not None:
        check(
            execution_error is not None
            and old_inode == new_inode
            and load_strict_json(bundle_path)["status"] == "planned"
            and not list((case / "retained-assets").glob("*.json")),
            "invalid recorded candidate replaced the plan or retained published assets",
        )
        return recorded, [], old_inode, new_inode
    if fail_runtime_context_git_digest:
        check(
            execution_error is not None
            and old_inode == new_inode
            and load_strict_json(bundle_path)["status"] == "planned"
            and not list((case / "retained-assets").glob("*.json")),
            "post-publication runtime-context failure committed or leaked an asset",
        )
        return recorded, [], old_inode, new_inode
    if recording_fault is not None:
        check(execution_error is not None, "recording fault did not surface")
        if recording_fault in {
            "concurrent-replacement",
            "post-commit-fsync",
            "post-exchange-displaced-replacement",
            "post-exchange-displaced-read",
            "post-exchange-asset-replace-indeterminate",
        }:
            check(
                isinstance(execution_error, runner.RecordingError)
                and execution_error.committed,
                "post-exchange recording fault was misclassified as pre-commit",
            )
        else:
            check(
                isinstance(execution_error, runner.RecordingError)
                and not execution_error.committed,
                "pre-commit recording fault was misclassified as committed",
            )
        return recorded, [], old_inode, new_inode
    logs: list[dict[str, Any]] = []
    for path in case.rglob("fake-*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            logs.append(json.loads(line))
    logs.sort(key=lambda item: item["time_ns"])
    check(
        all(
            item["proved"]
            for item in recorded["runtime_evidence"]["all_exit_quiescence"][
                "observations"
            ]
        )
        is (force_unproved_label is None),
        f"{name} recorded an unexpected aggregate quiescence state",
    )
    return recorded, logs, old_inode, new_inode


def test_production_orchestration_order_environment_and_atomic_recording() -> None:
    recorded, logs, old_inode, new_inode = synthetic_case("orchestration-success")
    synthetic_toolchain = recorded["isolation"]["toolchain_root"]
    synthetic_selection = recorded["isolation"]["selection_root"]
    runtime_context = recorded["runtime_evidence"]["runtime_context"]
    check(
        runtime_context["mise_executable_owner_verified"] is True
        and "mise_executable" not in runtime_context
        and "mise_executable_owner" not in runtime_context,
        "recorded runtime context retained ambient mise account identity",
    )
    check(
        "git_executable" not in runtime_context
        and isinstance(runtime_context["git_executable_sha256"], str),
        "recorded runtime context retained the ambient Git path",
    )
    check(
        Path(synthetic_selection, "global.json").read_text(encoding="utf-8")
        == recorded["environment"]["dotnet_sdk"]["global_json_content"],
        "controlled global.json was not created under the selection root",
    )

    cli_recorded = restore_fixed_paths_for_validation(
        recorded,
        Path(synthetic_toolchain),
        Path(synthetic_selection),
    )
    cli_recorded["id"] = "public-build-linux-x64-dotnet-8-0-424-01"
    cli_recorded["runtime_evidence"]["runtime_context"][
        "mise_executable_sha256"
    ] = cli_recorded["environment"]["mise"]["executable_sha256"]
    for component in cli_recorded["components"].values():
        component["sha256"] = hashlib.sha256(
            (ROOT / component["path"]).read_bytes()
        ).hexdigest()
    cli_recorded["runtime_evidence"]["receipt_binding"]["digest"] = receipt_digest(
        cli_recorded
    )
    validate_bundle(cli_recorded)
    baseline = load_strict_json(
        ROOT / "docs/research/public-build-source-baseline.json"
    )

    def runtime_errors(
        candidate: dict[str, Any],
        label: str,
    ) -> list[str]:
        candidate["runtime_evidence"]["receipt_binding"]["digest"] = receipt_digest(
            candidate
        )
        return validate_public_build_runtime_evidence(
            candidate,
            label,
            baseline,
        )

    unsafe_mise_identity = copy.deepcopy(cli_recorded)
    unsafe_mise_identity["runtime_evidence"]["runtime_context"].update(
        {
            "mise_executable_owner_verified": False,
            "mise_executable_mode": "0777",
        }
    )
    check(
        any(
            "runtime context contradicts" in error
            for error in runtime_errors(
                unsafe_mise_identity,
                "unsafe-mise-runtime-identity",
            )
        ),
        "unsafe or unverified mise runtime identity was accepted",
    )

    blocked = copy.deepcopy(cli_recorded)
    blocked_outcome = blocked["runtime_evidence"]["command_outcomes"][-1]
    blocked_subject = ("command", blocked_outcome["command_id"])
    blocked_outcome.update(
        {
            "status": "blocked",
            "attempts": [],
            "unspawned_termination": None,
            "source_integrity_failure": None,
            "blocked_by": "not-executed",
        }
    )
    blocked["runtime_evidence"]["all_exit_quiescence"]["observations"] = [
        observation
        for observation in blocked["runtime_evidence"]["all_exit_quiescence"][
            "observations"
        ]
        if (observation["subject_kind"], observation["subject_id"])
        != blocked_subject
    ]
    check(
        any(
            "command is blocked without a blocker" in error
            for error in runtime_errors(blocked, "blocked-without-cause")
        ),
        "unexplained blocked command was accepted",
    )
    stale_root_capture = copy.deepcopy(cli_recorded)
    next(
        root
        for root in stale_root_capture["runtime_evidence"][
            "ownership_conditioned_cleanup"
        ]["roots"]
        if root["kind"] == "selection"
    )["identity_verified"] = False
    check(
        any(
            "unverified selection root retains sanitized capture references"
            in error
            for error in runtime_errors(
                stale_root_capture,
                "stale-root-capture",
            )
        ),
        "unverified selection root retained sanitized capture references",
    )

    fixed_unverifiable = {
        "disposition": "capture-unverifiable",
        "path": None,
        "sha256": None,
        "sanitized_bytes": 0,
        "excerpt": "",
        "truncated": False,
    }
    retained = {
        "disposition": "retained-sanitized",
        "path": "/selection/captures/fixture-stderr-1.log",
        "sha256": hashlib.sha256(b"").hexdigest(),
        "sanitized_bytes": 0,
        "excerpt": "",
        "truncated": False,
    }
    observation = {
        ("command", "fixture"): {
            "subject_kind": "command",
            "subject_id": "fixture",
        }
    }

    def unverifiable_attempt_errors(
        termination: str,
        stdout: dict[str, Any],
        stderr: dict[str, Any],
        *,
        failure_reason: str | None = None,
    ) -> list[str]:
        errors, _ = validation._attempt_errors(
            [
                {
                    "attempt": 1,
                    "exit_code": 0,
                    "termination": termination,
                    "stdout": stdout,
                    "stderr": stderr,
                    "failure_reason": failure_reason or f"{termination}:fixture",
                }
            ],
            "failed",
            "command",
            "fixture",
            observation,
            Path("/selection/captures"),
            set(),
            "fixture:unverifiable-output",
        )
        return errors

    accepted_unverifiable = {
        "cancelled",
        "quiescence-unproved",
        "sensitive-output",
        "capture-failed",
    }
    check(
        accepted_unverifiable == set(GLOBAL_SAFETY_TERMINATIONS),
        "unverifiable-output acceptance drifted from global safety terminations",
    )
    for termination in sorted(accepted_unverifiable):
        check(
            not unverifiable_attempt_errors(
                termination,
                copy.deepcopy(fixed_unverifiable),
                copy.deepcopy(fixed_unverifiable),
            ),
            f"{termination} rejected fixed unverifiable output evidence",
        )
    for termination in ("completed", "timed-out", "output-limit-exceeded"):
        check(
            any(
                "disposition is inconsistent" in error
                for error in unverifiable_attempt_errors(
                    termination,
                    copy.deepcopy(fixed_unverifiable),
                    copy.deepcopy(fixed_unverifiable),
                )
            ),
            f"{termination} accepted fixed unverifiable output evidence",
        )
    check(
        not unverifiable_attempt_errors(
            "completed",
            copy.deepcopy(fixed_unverifiable),
            copy.deepcopy(fixed_unverifiable),
            failure_reason=LATE_CAPTURE_FAILURE_REASON,
        ),
        "precise late recording capture invalidation was rejected",
    )
    variable_unverifiable = copy.deepcopy(fixed_unverifiable)
    variable_unverifiable["excerpt"] = "stale output"
    check(
        any(
            "retains variable evidence" in error
            for error in unverifiable_attempt_errors(
                "capture-failed",
                variable_unverifiable,
                copy.deepcopy(fixed_unverifiable),
            )
        ),
        "variable unverifiable output evidence was accepted",
    )
    check(
        any(
            "disposition is inconsistent" in error
            for error in unverifiable_attempt_errors(
                "capture-failed",
                copy.deepcopy(fixed_unverifiable),
                retained,
            )
        ),
        "mixed verified and unverifiable stream evidence was accepted",
    )
    check(
        any(
            "disposition is inconsistent" in error
            for error in unverifiable_attempt_errors(
                "completed",
                copy.deepcopy(fixed_unverifiable),
                copy.deepcopy(fixed_unverifiable),
            )
        ),
        "completed attempt accepted unverifiable output evidence",
    )

    unsuppressed = copy.deepcopy(cli_recorded)
    source_attempt = next(
        outcome["attempts"][0]
        for outcome in unsuppressed["runtime_evidence"]["command_outcomes"]
        if outcome["command_id"] == "source-faithful-restore"
    )
    source_attempt["stdout"]["excerpt"] = "private diagnostic"
    source_attempt["stdout"]["sanitized_bytes"] = len("private diagnostic")
    check(
        any(
            "suppressed output retains variable evidence" in error
            for error in runtime_errors(
                unsuppressed,
                "source-faithful-output-retained",
            )
        ),
        "source-faithful command output was accepted as retained evidence",
    )

    duplicate_quiescence = copy.deepcopy(cli_recorded)
    duplicate = copy.deepcopy(
        duplicate_quiescence["runtime_evidence"]["all_exit_quiescence"][
            "observations"
        ][0]
    )
    duplicate_quiescence["runtime_evidence"]["all_exit_quiescence"][
        "observations"
    ].append(duplicate)
    check(
        any(
            "quiescence subjects must be unique" in error
            for error in runtime_errors(
                duplicate_quiescence,
                "duplicate-quiescence-subject",
            )
        ),
        "duplicate quiescence subject was accepted",
    )

    misbound_cache = copy.deepcopy(cli_recorded)
    misbound_cache["runtime_evidence"]["cache_observations"][0][
        "source_mode"
    ] = "public-only"
    check(
        any(
            "cache evidence binding differs" in error
            for error in runtime_errors(misbound_cache, "misbound-cache")
        ),
        "cache observation attributed to the wrong mode was accepted",
    )

    duplicate_cache = copy.deepcopy(cli_recorded)
    duplicate_cache["runtime_evidence"]["cache_observations"][1]["id"] = (
        duplicate_cache["runtime_evidence"]["cache_observations"][0]["id"]
    )
    duplicate_cache_errors = runtime_errors(
        duplicate_cache,
        "duplicate-cache-id",
    )
    check(
        any("cache observation IDs must be unique" in error for error in duplicate_cache_errors)
        and any(
            "cache observations do not exactly match successful checks" in error
            for error in duplicate_cache_errors
        ),
        "duplicate cache observation identity was accepted",
    )
    missing_preparation = copy.deepcopy(cli_recorded)
    missing_preparation["runtime_evidence"]["preparation_outcomes"].pop(6)
    missing_preparation["runtime_evidence"]["receipt_binding"]["digest"] = receipt_digest(
        missing_preparation
    )
    try:
        validate_bundle(missing_preparation)
    except ValidationError as error:
        check(
            "preparation" in str(error),
            "invalid preparation failed CLI validation for an unrelated reason",
        )
    else:
        raise AssertionError(
            "receipt-recomputed bundle with missing preparation passed CLI validation"
        )
    not_applicable = copy.deepcopy(cli_recorded)
    outcome = not_applicable["runtime_evidence"]["command_outcomes"][-1]
    observation_subject = ("command", outcome["command_id"])
    outcome.update(
        {
            "status": "not-applicable",
            "attempts": [],
            "unspawned_termination": None,
            "source_integrity_failure": None,
            "blocked_by": None,
        }
    )
    not_applicable["runtime_evidence"]["all_exit_quiescence"]["observations"] = [
        observation
        for observation in not_applicable["runtime_evidence"][
            "all_exit_quiescence"
        ]["observations"]
        if (observation["subject_kind"], observation["subject_id"])
        != observation_subject
    ]
    not_applicable["runtime_evidence"]["receipt_binding"]["digest"] = receipt_digest(
        not_applicable
    )
    try:
        validate_bundle(not_applicable)
    except ValidationError as error:
        check(
            ".status: value is not in enum" in str(error),
            "required not-applicable command failed for an unrelated reason",
        )
    else:
        raise AssertionError("required command was accepted as not-applicable")
    tampered = copy.deepcopy(cli_recorded)
    tampered["runtime_evidence"]["bounded_conclusions"]["conclusions"][0][
        "statement"
    ] = "tampered"
    try:
        validate_bundle(tampered)
    except ValidationError as error:
        check("receipt" in str(error), "tamper failed for an unrelated reason")
    else:
        raise AssertionError("receipt tamper was accepted")
    check(old_inode != new_inode, "recorded bundle did not atomically replace the planned inode")
    check(load_strict_json(WORK / "orchestration-success/bundle.json") == recorded, "atomic bundle output differs")
    command_logs = [
        item
        for item in logs
        if item["role"] == "dotnet"
        and item["argv"]
        and item["argv"][0] in {"restore", "build", "test", "pack"}
    ]
    expected = [command["argv"][1:] for command in recorded["protocol"]["commands"]]
    check([item["argv"] for item in command_logs] == expected, "sixteen commands ran out of exact order")
    check(
        all(
            item["runtime_argv"][1].startswith("/proc/self/fd/")
            for item in logs
            if item["role"] == "git"
            and item["runtime_argv"]
            and item["runtime_argv"][0] == "-C"
        ),
        "checkout Git operations were not descriptor-bound",
    )
    source_restore_log = next(
        item
        for item in command_logs
        if item["argv"][0] == "restore"
        and "source-faithful" in item["argv"][3]
    )
    check(
        source_restore_log["runtime_argv"][
            source_restore_log["runtime_argv"].index("--configfile") + 1
        ]
        == "nuget.config",
        "source-faithful configuration was not relative to descriptor-bound cwd",
    )
    expected_keys = {
        "mise": list(MISE_ENVIRONMENT_KEYS),
        "git": list(GIT_ENVIRONMENT_KEYS),
        "dotnet": list(DOTNET_ENVIRONMENT_KEYS),
    }
    for item in logs:
        check(
            item["env_keys"] == expected_keys[item["role"]],
            f"{item['role']} child environment differs from its exact allowlist",
        )
        forbidden = {
            key
            for key in item["env_keys"]
            if "PROXY" in key or key.startswith("WSL") or key == "PUBLIC_BUILD_POISON"
        }
        check(not forbidden, f"{item['role']} inherited forbidden environment keys")
        if item["role"] == "mise":
            check(
                item["path"] == "/usr/bin:/bin",
                "mise child PATH includes the ambient executable directory",
            )
    nuget_metadata_logs = [
        item["argv"]
        for item in logs
        if item["role"] == "dotnet"
        and item["argv"][:4] == ["nuget", "locals", "all", "--list"]
    ]
    check(
        len(nuget_metadata_logs) == 2
        and not any(
            item["role"] == "dotnet"
            and item["argv"] == ["nuget", "--version"]
            for item in logs
        ),
        "NuGet metadata did not use the documented cache-location command",
    )
    check(
        len(recorded["runtime_evidence"]["command_outcomes"]) == 16,
        "recorded bundle does not contain sixteen outcomes",
    )
    capture_root = Path(recorded["isolation"]["selection_root"]) / "captures"
    command_attempts = {
        outcome["command_id"]: outcome["attempts"][0]
        for outcome in recorded["runtime_evidence"]["command_outcomes"]
        if outcome["attempts"]
    }
    attempts = list(command_attempts.values()) + [
        attempt
        for preparation in recorded["runtime_evidence"]["preparation_outcomes"]
        for attempt in preparation["attempts"]
    ]
    check(
        all(
            Path(attempt[stream]["path"]).parent == capture_root
            for attempt in attempts
            for stream in ("stdout", "stderr")
            if attempt[stream]["disposition"] == "retained-sanitized"
        ),
        "attempt evidence does not bind retained selection-root capture paths",
    )
    check(
        all(
            command_attempts[command_id][stream]
            == {
                "disposition": "suppressed-source-faithful",
                "path": None,
                "sha256": None,
                "sanitized_bytes": 0,
                "excerpt": "",
                "truncated": False,
            }
            for command_id in command_attempts
            if command_id.startswith("source-faithful-")
            for stream in ("stdout", "stderr")
        ),
        "source-faithful output was not suppressed without variable evidence",
    )
    check(
        not any(
            path.name.startswith("source-faithful-")
            for path in capture_root.iterdir()
        ),
        "source-faithful command output was persisted under the capture root",
    )
    check(
        [
            item["id"]
            for item in recorded["runtime_evidence"]["preparation_outcomes"]
        ]
        == [item["id"] for item in preparation_topology()],
        "recorded preparation outcomes differ from the shared ordered topology",
    )
    check(
        all(
            not any("asset" in target for target in mode["targets"])
            for mode in recorded["runtime_evidence"]["dependency_evidence"]["modes"]
        ),
        "zero valid synthetic assets were not recorded as unavailable",
    )
    check(
        recorded["runtime_evidence"]["runtime_context"][
            "nuget_client_version_probe"
        ]
        == {
            "preparation_id": "inspect-nuget-client-version",
            "source": "NuGet.CommandLine.XPlat.deps.json",
            "path": (
                str(
                    WORK
                    / "orchestration-success/toolchains/bundle/"
                    "installs/http-dotnet-sdk/8.0.424/sdk/8.0.424/"
                    "NuGet.CommandLine.XPlat.deps.json"
                )
            ),
            "sha256": recorded["runtime_evidence"]["runtime_context"][
                "nuget_client_version_probe"
            ]["sha256"],
            "package": "NuGet.CommandLine.XPlat",
            "version": "6.11.1",
        },
        "exact NuGet client version probe was not recorded",
    )


def test_restore_failure_blocks_mode() -> None:
    recorded, _, _, _ = synthetic_case(
        "restore-failure",
        fail_restore_mode="source-faithful",
    )
    outcomes = {
        item["command_id"]: item
        for item in recorded["runtime_evidence"]["command_outcomes"]
    }
    check(outcomes["source-faithful-restore"]["status"] == "failed", "restore failure was lost")
    for command_id, outcome in outcomes.items():
        if command_id.startswith("source-faithful-") and command_id != "source-faithful-restore":
            check(
                outcome["status"] == "blocked"
                and outcome["blocked_by"] == "source-faithful-restore"
                and not outcome["attempts"],
                f"{command_id} was not blocked by its failed restore",
            )
    check(outcomes["public-only-restore"]["status"] == "passed", "independent mode did not continue")
    spawn_failed, _, _, _ = synthetic_case(
        "restore-spawn-failure",
        spawn_failure_label="source-faithful-restore",
    )
    spawn_outcomes = {
        item["command_id"]: item
        for item in spawn_failed["runtime_evidence"]["command_outcomes"]
    }
    check(
        spawn_outcomes["source-faithful-restore"]["status"] == "failed"
        and not spawn_outcomes["source-faithful-restore"]["attempts"]
        and spawn_outcomes["source-faithful-restore"]["unspawned_termination"]
        == "spawn-failed"
        and all(
            outcome["blocked_by"] == "source-faithful-restore"
            for command_id, outcome in spawn_outcomes.items()
            if command_id.startswith("source-faithful-")
            and command_id != "source-faithful-restore"
        )
        and spawn_outcomes["public-only-restore"]["status"] == "passed",
        "restore spawn failure was not typed or dependency-scoped",
    )

    preparation_failed, _, _, _ = synthetic_case(
        "preparation-failure",
        fail_git_fetch_mode="source-faithful",
    )
    check(
        preparation_failed["runtime_evidence"]["canonical_termination"]["cause"]
        == "completed-with-command-failures",
        "mode preparation failure was described as a global runner stop",
    )
    preparation_outcomes = {
        item["id"]: item
        for item in preparation_failed["runtime_evidence"]["preparation_outcomes"]
    }
    commands_by_id = {
        item["id"]: item
        for item in preparation_failed["protocol"]["commands"]
    }
    check(
        all(
            item["status"] == "blocked"
            and item["blocked_by"] == "git-source-faithful-fetch"
            and not item["attempts"]
            and (
                item["command_id"] == "source-faithful-restore"
                or commands_by_id[item["command_id"]]["depends_on"]
                == "source-faithful-restore"
            )
            for item in preparation_failed["runtime_evidence"]["command_outcomes"]
            if item["command_id"].startswith("source-faithful-")
        ),
        "mode preparation failure did not block its own commands",
    )
    check(
        all(
            item["status"] == "passed"
            for item in preparation_failed["runtime_evidence"]["command_outcomes"]
            if item["command_id"].startswith("public-only-")
        ),
        "mode preparation failure blocked the independent mode",
    )
    check(
        preparation_outcomes["git-public-only-checkout"]["status"] == "passed",
        "independent mode preparation did not continue",
    )

    capture_failed, _, _, _ = synthetic_case(
        "preparation-capture-setup-failure",
        capture_failure_label="git-source-faithful-init",
    )
    preparation_outcomes = {
        item["id"]: item
        for item in capture_failed["runtime_evidence"]["preparation_outcomes"]
    }
    failed_capture = preparation_outcomes["git-source-faithful-init"]
    check(
        capture_failed["runtime_evidence"]["canonical_termination"]["cause"]
        == "capture-failed"
        and not failed_capture["attempts"]
        and failed_capture["failure_reason"].startswith("capture-failed:"),
        "pre-Popen capture failure did not record a typed unspawned failure",
    )
    check(
        all(
            item["status"] == "blocked" and not item["attempts"]
            for item in capture_failed["runtime_evidence"]["command_outcomes"]
        ),
        "capture setup failure did not globally block commands",
    )


def test_mode_checkout_info_and_config_failures_are_isolated() -> None:
    cases = (
        (
            "checkout-preparation-failure",
            {"fail_git_checkout_mode": "source-faithful"},
            "source-faithful",
            "git-source-faithful-checkout",
        ),
        (
            "info-preparation-failure",
            {"fail_dotnet_info_mode": "source-faithful"},
            "source-faithful",
            "dotnet-source-faithful-info",
        ),
        (
            "config-preparation-failure",
            {"occupy_public_config": True},
            "public-only",
            "generate-public-only-nuget-config",
        ),
        (
            "cache-location-preparation-failure",
            {
                "invalid_cache_locations_mode": "source-faithful",
                "use_real_candidate_validator": True,
            },
            "source-faithful",
            "dotnet-source-faithful-nuget-cache-locations",
        ),
    )
    for name, arguments, blocked_mode, preparation_id in cases:
        recorded, _, _, _ = synthetic_case(name, **arguments)
        preparations = {
            item["id"]: item
            for item in recorded["runtime_evidence"]["preparation_outcomes"]
        }
        check(
            preparations[preparation_id]["status"] == "failed",
            f"{name} did not record its preparation failure",
        )
        for outcome in recorded["runtime_evidence"]["command_outcomes"]:
            if outcome["command_id"].startswith(f"{blocked_mode}-"):
                check(
                    outcome["status"] == "blocked" and not outcome["attempts"],
                    f"{name} did not block its mode",
                )
            else:
                check(
                    outcome["status"] == "passed",
                    f"{name} blocked the independent mode",
                )

    semantic_cases = (
        (
            "mise-version-output-mismatch",
            {"mismatch_mise_version": True},
            "mise-version",
        ),
        (
            "git-head-output-mismatch",
            {"mismatch_git_head_mode": "source-faithful"},
            "git-source-faithful-verify-head",
        ),
        (
            "dotnet-info-output-mismatch",
            {"mismatch_dotnet_info_mode": "source-faithful"},
            "dotnet-source-faithful-info",
        ),
    )
    for name, arguments, preparation_id in semantic_cases:
        recorded, _, _, _ = synthetic_case(
            name,
            use_real_candidate_validator=True,
            **arguments,
        )
        preparation = next(
            item
            for item in recorded["runtime_evidence"]["preparation_outcomes"]
            if item["id"] == preparation_id
        )
        attempt = preparation["attempts"][0]
        check(
            preparation["status"] == "failed"
            and preparation["failure_reason"]
            and attempt["termination"] == "completed"
            and attempt["exit_code"] == 0
            and attempt["failure_reason"] is None,
            f"{name} did not preserve its primitive success and semantic failure",
        )


def test_timeout_blocks_remaining() -> None:
    terminating = "source-faithful-build"
    recorded, _, _, _ = synthetic_case(
        "timeout",
        timeout_command=terminating,
    )
    outcomes = recorded["runtime_evidence"]["command_outcomes"]
    index = next(i for i, item in enumerate(outcomes) if item["command_id"] == terminating)
    check(outcomes[index]["attempts"][0]["termination"] == "timed-out", "timeout was not recorded")
    check(
        all(
            item["status"] == "blocked"
            and item["blocked_by"] == terminating
            and not item["attempts"]
            for item in outcomes[index + 1 :]
            if item["command_id"].startswith("source-faithful-")
        ),
        "commands after timeout in the same mode were not blocked",
    )
    check(
        all(
            item["status"] == "passed"
            for item in outcomes
            if item["command_id"].startswith("public-only-")
        ),
        "quiescence-proved timeout blocked the independent mode",
    )


def test_shared_stop_scope_and_precedence() -> None:
    mode_spawn, _, _, _ = synthetic_case(
        "mode-preparation-spawn-failure",
        spawn_failure_label="git-source-faithful-fetch",
        use_real_candidate_validator=True,
    )
    preparations = {
        item["id"]: item
        for item in mode_spawn["runtime_evidence"]["preparation_outcomes"]
    }
    check(
        mode_spawn["runtime_evidence"]["canonical_termination"]["cause"]
        == "completed-with-command-failures"
        and preparations["git-source-faithful-fetch"]["status"] == "failed"
        and all(
            outcome["status"] == "passed"
            for outcome in mode_spawn["runtime_evidence"]["command_outcomes"]
            if outcome["command_id"].startswith("public-only-")
        ),
        "mode-scoped preparation spawn failure became a global stop",
    )

    superseded, _, _, _ = synthetic_case(
        "later-global-supersedes-mode-timeout",
        timeout_command="source-faithful-build",
        sensitive_command="public-only-build",
        use_real_candidate_validator=True,
    )
    check(
        superseded["runtime_evidence"]["canonical_termination"]["cause"]
        == "sensitive-output",
        "later global safety stop did not supersede an earlier mode-local timeout",
    )


def test_sensitive_global_and_overflow_mode_local() -> None:
    terminating = "source-faithful-build"
    recorded, _, _, _ = synthetic_case(
        "command-sensitive-output",
        sensitive_command=terminating,
    )
    outcomes = recorded["runtime_evidence"]["command_outcomes"]
    attempt = next(
        item for item in outcomes if item["command_id"] == terminating
    )["attempts"][0]
    check(
        attempt["termination"] == "sensitive-output" and attempt["failure_reason"],
        "sensitive output did not retain its typed fail-closed termination",
    )
    terminating_index = [
        item["command_id"] for item in outcomes
    ].index(terminating)
    check(
        recorded["runtime_evidence"]["canonical_termination"]["cause"]
        == "sensitive-output"
        and all(
            item["status"] == "blocked"
            and item["blocked_by"] == terminating
            and not item["attempts"]
            for item in outcomes[terminating_index + 1 :]
        ),
        "sensitive output did not stop all remaining commands",
    )

    recorded, _, _, _ = synthetic_case(
        "command-output-overflow",
        overflow_command=terminating,
    )
    outcomes = recorded["runtime_evidence"]["command_outcomes"]
    check(
        all(
            item["status"] == "passed"
            for item in outcomes
            if item["command_id"].startswith("public-only-")
        ),
        "output overflow blocked the independent mode",
    )

    combined, _, _, _ = synthetic_case(
        "command-output-overflow-then-sensitive",
        overflow_sensitive_command=terminating,
    )
    combined_outcomes = combined["runtime_evidence"]["command_outcomes"]
    combined_attempt = next(
        item for item in combined_outcomes if item["command_id"] == terminating
    )["attempts"][0]
    check(
        combined_attempt["termination"] == "sensitive-output"
        and combined["runtime_evidence"]["canonical_termination"]["cause"]
        == "sensitive-output"
        and all(
            item["status"] == "blocked"
            for item in combined_outcomes[
                next(
                    index
                    for index, item in enumerate(combined_outcomes)
                    if item["command_id"] == terminating
                )
                + 1 :
            ]
        ),
        "late sensitive output did not supersede overflow and stop globally",
    )


def test_source_unchanged_guard() -> None:
    replacement, _, _, _ = synthetic_case(
        "checkout-a-to-b-replacement",
        replace_checkout_during_command="source-faithful-build",
        use_real_candidate_validator=True,
    )
    replacement_outcome = next(
        item
        for item in replacement["runtime_evidence"]["command_outcomes"]
        if item["command_id"] == "source-faithful-build"
    )
    case_root = WORK / "checkout-a-to-b-replacement/selections/bundle/source-faithful"
    check(
        replacement_outcome["status"] == "failed"
        and replacement_outcome["attempts"]
        and replacement_outcome["attempts"][0]["exit_code"] == 0
        and replacement_outcome["source_integrity_failure"] is not None
        and replacement["runtime_evidence"]["canonical_termination"]["cause"]
        == "source-integrity-changed"
        and (case_root / "checkout/AzureAuth.sln").read_text(encoding="utf-8")
        != "mutated retained checkout\n"
        and (case_root / "checkout-retained-a/AzureAuth.sln").read_text(
            encoding="utf-8"
        )
        == "mutated retained checkout\n",
        "A-to-B checkout replacement made a descriptor-bound command acceptable",
    )
    cases = (
        ("source-mutation", "mutate_command"),
        ("source-chmod", "chmod_command"),
        ("source-untracked", "untracked_command"),
        ("source-type", "source_type_command"),
    )
    for name, parameter in cases:
        terminating = "source-faithful-build"
        recorded, _, _, _ = synthetic_case(
            name,
            asset_modes=["source-faithful"],
            **{parameter: terminating},
        )
        outcomes = recorded["runtime_evidence"]["command_outcomes"]
        changed = next(item for item in outcomes if item["command_id"] == terminating)
        check(changed["status"] == "failed", f"{name} did not fail the command")
        check(
            changed["source_integrity_failure"] is not None,
            f"{name} did not retain a typed sanitized failure reason",
        )
        changed_index = [
            item["command_id"] for item in outcomes
        ].index(terminating)
        check(
            recorded["runtime_evidence"]["canonical_termination"]["cause"]
            == "source-integrity-changed"
            and all(
                item["status"] == "blocked"
                and item["blocked_by"] == terminating
                and not item["attempts"]
                for item in outcomes[changed_index + 1 :]
            ),
            f"{name} did not globally stop remaining commands",
        )
        dependency = recorded["runtime_evidence"]["dependency_evidence"]
        check(
            not any(
                "asset" in target
                for mode in dependency["modes"]
                for target in mode["targets"]
            )
            and all(
                target["status"] == "invalid"
                and target["reason"]
                == "asset-inspection-blocked-by-source-integrity-changed"
                for mode in dependency["modes"]
                for target in mode["targets"]
            ),
            f"{name} inspected or published assets after source mutation",
        )
    overlap, _, _, _ = synthetic_case(
        "source-mutation-after-timeout",
        timeout_command="source-faithful-build",
        mutate_command="source-faithful-build",
        use_real_candidate_validator=True,
    )
    overlap_outcome = next(
        item
        for item in overlap["runtime_evidence"]["command_outcomes"]
        if item["command_id"] == "source-faithful-build"
    )
    check(
        overlap_outcome["attempts"][0]["termination"] == "timed-out"
        and overlap_outcome["source_integrity_failure"] is not None
        and overlap["runtime_evidence"]["canonical_termination"]["cause"]
        == "source-integrity-changed",
        "mode-local timeout masked the later global source-integrity failure",
    )
    unspawned, _, _, _ = synthetic_case(
        "source-mutation-after-spawn-failure",
        spawn_failure_label="source-faithful-build",
        mutate_command="source-faithful-build",
        use_real_candidate_validator=True,
    )
    unspawned_outcome = next(
        item
        for item in unspawned["runtime_evidence"]["command_outcomes"]
        if item["command_id"] == "source-faithful-build"
    )
    check(
        not unspawned_outcome["attempts"]
        and unspawned_outcome["unspawned_termination"] == "spawn-failed"
        and unspawned_outcome["source_integrity_failure"] is not None
        and unspawned["runtime_evidence"]["canonical_termination"]["cause"]
        == "source-integrity-changed",
        "unspawned command failure masked the later global source-integrity failure",
    )


def test_preparation_checkout_binding_overlay() -> None:
    preparation_id = "git-source-faithful-fetch"
    bounded_reason = append_failure_reason_marker(
        "x" * 1024,
        SOURCE_INTEGRITY_CHANGED_MARKER,
    )
    check(
        len(bounded_reason) == 1024
        and bounded_reason.endswith(f"; {SOURCE_INTEGRITY_CHANGED_MARKER}"),
        "source-integrity failure overlay exceeded or lost the fixed reason bound",
    )
    failed, _, _, _ = synthetic_case(
        "preparation-checkout-replacement-failed-fetch",
        fail_git_fetch_mode="source-faithful",
        replace_checkout_after_preparation=preparation_id,
        use_real_candidate_validator=True,
    )
    failed_preparations = {
        item["id"]: item
        for item in failed["runtime_evidence"]["preparation_outcomes"]
    }
    failed_owner = failed_preparations[preparation_id]
    failed_attempt = failed_owner["attempts"][0]
    check(
        failed_owner["status"] == "failed"
        and failed_owner["failure_reason"]
        == append_failure_reason_marker(
            "child-exit:11",
            SOURCE_INTEGRITY_CHANGED_MARKER,
        )
        and failed_attempt["exit_code"] == 11
        and SOURCE_INTEGRITY_CHANGED_MARKER
        not in str(failed_attempt["failure_reason"])
        and failed["runtime_evidence"]["canonical_termination"]["cause"]
        == SOURCE_INTEGRITY_CHANGED_MARKER
        and all(
            item["status"] == "blocked" and not item["attempts"]
            for item in failed["runtime_evidence"]["preparation_outcomes"]
            if next(
                spec for spec in PREPARATIONS if spec.identifier == item["id"]
            ).source_mode
            == "public-only"
        )
        and all(
            item["status"] == "blocked" and not item["attempts"]
            for item in failed["runtime_evidence"]["command_outcomes"]
        ),
        "failed checkout-bound fetch lost exit 11, source integrity, or global stop",
    )

    for failure_kind, arguments, expected_prefix in (
        (
            "capture",
            {"capture_failure_label": preparation_id},
            "capture-failed:",
        ),
        (
            "spawn",
            {"spawn_failure_label": preparation_id},
            "spawn-failed:",
        ),
    ):
        unspawned, _, _, _ = synthetic_case(
            f"preparation-checkout-replacement-{failure_kind}-failure",
            replace_checkout_after_preparation=preparation_id,
            use_real_candidate_validator=True,
            **arguments,
        )
        owner = next(
            item
            for item in unspawned["runtime_evidence"]["preparation_outcomes"]
            if item["id"] == preparation_id
        )
        check(
            owner["status"] == "failed"
            and not owner["attempts"]
            and owner["failure_reason"].startswith(expected_prefix)
            and owner["failure_reason"].endswith(
                f"; {SOURCE_INTEGRITY_CHANGED_MARKER}"
            )
            and all(
                item["status"] == "blocked" and not item["attempts"]
                for item in unspawned["runtime_evidence"][
                    "preparation_outcomes"
                ]
                if next(
                    spec
                    for spec in PREPARATIONS
                    if spec.identifier == item["id"]
                ).source_mode
                == "public-only"
            )
            and all(
                item["status"] == "blocked" and not item["attempts"]
                for item in unspawned["runtime_evidence"]["command_outcomes"]
            )
            and not normalized_recorded_errors(
                unspawned,
                f"fixture:preparation-checkout-replacement-{failure_kind}-failure",
            ),
            f"{failure_kind} failure plus source-integrity overlay was invalid",
        )

    passed, _, _, _ = synthetic_case(
        "preparation-checkout-replacement-passed-fetch",
        replace_checkout_after_preparation=preparation_id,
        use_real_candidate_validator=True,
    )
    passed_owner = next(
        item
        for item in passed["runtime_evidence"]["preparation_outcomes"]
        if item["id"] == preparation_id
    )
    passed_attempt = passed_owner["attempts"][0]
    check(
        passed_owner["status"] == "failed"
        and passed_owner["failure_reason"] == SOURCE_INTEGRITY_CHANGED_MARKER
        and passed_attempt["termination"] == "completed"
        and passed_attempt["exit_code"] == 0
        and passed_attempt["failure_reason"] is None
        and passed["runtime_evidence"]["canonical_termination"]["cause"]
        == SOURCE_INTEGRITY_CHANGED_MARKER,
        "passed checkout-bound child did not retain primitive success and binding failure",
    )

    baseline_failure, _, _, _ = synthetic_case(
        "preparation-integrity-baseline-failure",
        fail_integrity_baseline_mode="source-faithful",
        use_real_candidate_validator=True,
    )
    baseline_owner = next(
        item
        for item in baseline_failure["runtime_evidence"]["preparation_outcomes"]
        if item["id"] == "source-faithful-integrity-baseline"
    )
    check(
        baseline_owner["status"] == "failed"
        and not baseline_owner["attempts"]
        and baseline_owner["failure_reason"].endswith(
            f"; {SOURCE_INTEGRITY_CHANGED_MARKER}"
        ),
        "in-process integrity baseline failure lacked source-integrity evidence",
    )
    for reserved_prefix in ("capture-failed:", "spawn-failed:"):
        invalid_reserved = copy.deepcopy(baseline_failure)
        invalid_runtime = invalid_reserved["runtime_evidence"]
        invalid_owner = next(
            item
            for item in invalid_runtime["preparation_outcomes"]
            if item["id"] == "source-faithful-integrity-baseline"
        )
        invalid_owner["failure_reason"] = (
            f"{reserved_prefix}fabricated; {SOURCE_INTEGRITY_CHANGED_MARKER}"
        )
        replay = reduce_runtime(
            invalid_runtime["preparation_outcomes"],
            invalid_runtime["command_outcomes"],
            invalid_reserved["protocol"]["commands"],
            invalid_runtime["all_exit_quiescence"]["observations"],
            invalid_runtime["ownership_conditioned_cleanup"]["roots"],
        )
        invalid_runtime["canonical_termination"] = {
            "cause": replay["cause"],
            "detail": replay["detail"],
        }
        if replay["cause"] == "capture-failed":
            for mode_evidence in invalid_runtime["dependency_evidence"][
                "modes"
            ]:
                for target in mode_evidence["targets"]:
                    if (
                        target.get("reason")
                        == "asset-inspection-blocked-by-source-integrity-changed"
                    ):
                        target["reason"] = (
                            "asset-inspection-blocked-by-capture-failed"
                        )
        reserved_errors = normalized_recorded_errors(
            invalid_reserved,
            f"fixture:in-process-{reserved_prefix[:-1]}",
        )
        check(
            len(reserved_errors) == 1
            and "uses a reserved unspawned termination"
            in reserved_errors[0],
            f"in-process {reserved_prefix} evidence was not rejected directly",
        )

    invalid_subject = copy.deepcopy(failed)
    mise_version = next(
        item
        for item in invalid_subject["runtime_evidence"]["preparation_outcomes"]
        if item["id"] == "mise-version"
    )
    mise_version["status"] = "failed"
    mise_version["failure_reason"] = SOURCE_INTEGRITY_CHANGED_MARKER
    check(
        any(
            "invalid source-integrity overlay" in error
            for error in normalized_recorded_errors(
                invalid_subject,
                "fixture:source-marker-non-checkout-preparation",
            )
        ),
        "source-integrity marker on a non-checkout preparation was accepted",
    )

    invalid_attempt = copy.deepcopy(failed)
    invalid_attempt_owner = next(
        item
        for item in invalid_attempt["runtime_evidence"]["preparation_outcomes"]
        if item["id"] == preparation_id
    )
    invalid_attempt_owner["attempts"][0]["failure_reason"] = (
        SOURCE_INTEGRITY_CHANGED_MARKER
    )
    check(
        any(
            "stored in attempt evidence" in error
            for error in normalized_recorded_errors(
                invalid_attempt,
                "fixture:source-marker-attempt-evidence",
            )
        ),
        "source-integrity marker in primitive attempt evidence was accepted",
    )

    unspawned = copy.deepcopy(failed)
    unspawned_owner = next(
        item
        for item in unspawned["runtime_evidence"]["preparation_outcomes"]
        if item["id"] == preparation_id
    )
    unspawned_owner["attempts"] = []
    check(
        any(
            "invalid source-integrity overlay" in error
            for error in normalized_recorded_errors(
                unspawned,
                "fixture:source-marker-unspawned-preparation",
            )
        ),
        "source-integrity marker without a spawned attempt was accepted",
    )

    nonfailed = copy.deepcopy(failed)
    nonfailed_owner = next(
        item
        for item in nonfailed["runtime_evidence"]["preparation_outcomes"]
        if item["id"] == preparation_id
    )
    nonfailed_owner["status"] = "passed"
    check(
        any(
            "invalid source-integrity overlay" in error
            for error in normalized_recorded_errors(
                nonfailed,
                "fixture:source-marker-passed-preparation",
            )
        ),
        "source-integrity marker on a passed preparation was accepted",
    )

    malformed = copy.deepcopy(failed)
    malformed_owner = next(
        item
        for item in malformed["runtime_evidence"]["preparation_outcomes"]
        if item["id"] == preparation_id
    )
    malformed_owner["failure_reason"] = (
        "child-exit:11;source-integrity-changed"
    )
    check(
        any(
            "malformed source-integrity marker" in error
            for error in normalized_recorded_errors(
                malformed,
                "fixture:source-marker-malformed",
            )
        ),
        "non-delimited source-integrity marker was accepted",
    )


def test_failed_restore_partial_assets_and_asset_destination_safety() -> None:
    recorded, _, _, _ = synthetic_case(
        "failed-restore-partial-assets",
        fail_restore_mode="source-faithful",
        asset_modes=["source-faithful"],
    )
    dependency = recorded["runtime_evidence"]["dependency_evidence"]
    mode_evidence = next(
        item
        for item in dependency["modes"]
        if item["source_mode"] == "source-faithful"
    )
    retained = [item["asset"] for item in mode_evidence["targets"] if "asset" in item]
    check(
        len(retained) == 1 and len(retained) < len(mode_evidence["targets"]),
        "failed restore with one valid asset was not classified as partial",
    )
    check(
        len(retained) == 1
        and retained[0]["provenance"]["retrieval_source_evidence"]
        == ["source-faithful-restore"],
        "retained asset was not bound to the failed restore outcome",
    )
    synthetic_toolchain = recorded["isolation"]["toolchain_root"]
    synthetic_selection = recorded["isolation"]["selection_root"]

    def restore_fixed_paths(value: Any) -> Any:
        if isinstance(value, str):
            return value.replace(
                synthetic_toolchain, str(TOOLCHAIN_ROOT)
            ).replace(synthetic_selection, str(SELECTION_ROOT))
        if isinstance(value, list):
            return [restore_fixed_paths(item) for item in value]
        if isinstance(value, dict):
            return {key: restore_fixed_paths(item) for key, item in value.items()}
        return value

    provenance_candidate = restore_fixed_paths(recorded)
    provenance_candidate["runtime_evidence"]["runtime_context"][
        "mise_executable_sha256"
    ] = provenance_candidate["environment"]["mise"]["executable_sha256"]
    for component in provenance_candidate["components"].values():
        component["sha256"] = hashlib.sha256(
            (ROOT / component["path"]).read_bytes()
        ).hexdigest()
    provenance_candidate["runtime_evidence"]["receipt_binding"]["digest"] = (
        receipt_digest(provenance_candidate)
    )
    baseline = load_strict_json(
        ROOT / "docs/research/public-build-source-baseline.json"
    )
    for label, field, value, expected_error in (
        ("empty", "initial_cache_evidence", [], "initial-cache provenance"),
        (
            "unknown",
            "retrieval_source_evidence",
            ["unknown-command"],
            "retrieval_source_evidence",
        ),
        (
            "wrong-kind",
            "initial_cache_evidence",
            ["source-faithful-restore"],
            "initial-cache provenance",
        ),
        (
            "cross-mode",
            "initial_cache_evidence",
            ["public-only-initial-nuget-cache"],
            "initial-cache provenance",
        ),
    ):
        invalid = copy.deepcopy(provenance_candidate)
        invalid_provenance = next(
            target["asset"]["provenance"]
            for mode in invalid["runtime_evidence"]["dependency_evidence"]["modes"]
            for target in mode["targets"]
            if "asset" in target
        )
        invalid_provenance[field] = value
        invalid["runtime_evidence"]["receipt_binding"]["digest"] = (
            receipt_digest(invalid)
        )
        errors = validate_public_build_runtime_evidence(
            invalid,
            label,
            baseline,
        )
        if not any(expected_error in error for error in errors):
            raise AssertionError(
                f"{label} provenance reference was accepted: {errors}"
            )
    public_restore = "public-only-restore"
    check(
        all(
            public_restore not in declaration["failure_evidence_refs"]
            for mode in dependency["modes"]
            if mode["source_mode"] == "public-only"
            for target in mode["targets"]
            for declaration in target["unresolved_declarations"]
        ),
        "a passed restore was used as failure evidence",
    )

    screened, _, _, _ = synthetic_case(
        "sensitive-asset-screening",
        asset_modes=["source-faithful"],
        sensitive_asset_modes=["source-faithful"],
    )
    screened_dependency = screened["runtime_evidence"]["dependency_evidence"]
    check(
        not any(
            "asset" in target
            for mode in screened_dependency["modes"]
            for target in mode["targets"]
        )
        and any(
            "sensitive token pattern" in target["reason"]
            for mode in screened_dependency["modes"]
            if mode["source_mode"] == "source-faithful"
            for target in mode["targets"]
            if target["status"] == "invalid"
        ),
        "sensitive project.assets.json bytes were published",
    )
    changed_after_restore, _, _, _ = synthetic_case(
        "asset-changed-after-restore",
        asset_modes=["public-only"],
        mutate_asset_after_restore_mode="public-only",
        use_real_candidate_validator=True,
    )
    changed_target = next(
        target
        for mode in changed_after_restore["runtime_evidence"][
            "dependency_evidence"
        ]["modes"]
        if mode["source_mode"] == "public-only"
        for target in mode["targets"]
        if target["target_id"] == "target-testhelper-net8-0"
    )
    check(
        changed_target["status"] == "invalid"
        and "project-assets-changed-after-restore" in changed_target["reason"]
        and "asset" not in changed_target
        and changed_target["unresolved_declarations"],
        "post-restore schema-accepted asset mutation was published or lost "
        "unresolved declarations",
    )
    symlinked, _, _, _ = synthetic_case(
        "symlinked-asset-component",
        asset_modes=["source-faithful"],
        symlink_asset_modes=["source-faithful"],
    )
    symlinked_dependency = symlinked["runtime_evidence"]["dependency_evidence"]
    check(
        not any(
            "asset" in target
            for mode in symlinked_dependency["modes"]
            for target in mode["targets"]
        )
        and any(
            target["status"] == "invalid"
            for mode in symlinked_dependency["modes"]
            if mode["source_mode"] == "source-faithful"
            for target in mode["targets"]
        ),
        "symlinked asset path component escaped the verified selection root",
    )

    safety_stopped, _, _, _ = synthetic_case(
        "asset-publication-safety-stop",
        asset_modes=["source-faithful", "public-only"],
        sensitive_command="source-faithful-build",
    )
    stopped_dependency = safety_stopped["runtime_evidence"]["dependency_evidence"]
    check(
        not any(
            "asset" in target
            for mode in stopped_dependency["modes"]
            for target in mode["targets"]
        )
        and all(
            target["status"] == "invalid"
            and target["reason"]
            == "asset-inspection-blocked-by-sensitive-output"
            for mode in stopped_dependency["modes"]
            for target in mode["targets"]
        ),
        "global sensitive stop did not prohibit all asset inspection",
    )
    misreported_blocker = copy.deepcopy(safety_stopped)
    misreported_blocker["runtime_evidence"]["dependency_evidence"]["modes"][0][
        "targets"
    ][0]["reason"] = "project-assets-missing"
    misreported_blocker["runtime_evidence"]["receipt_binding"]["digest"] = (
        receipt_digest(misreported_blocker)
    )
    blocker_errors = validate_public_build_runtime_evidence(
        misreported_blocker,
        "misreported-asset-blocker",
        load_strict_json(
            ROOT / "docs/research/public-build-source-baseline.json"
        ),
    )
    check(
        any("does not preserve asset-inspection-blocked-by-sensitive-output" in error
            for error in blocker_errors),
        "dependency target replaced the global asset-inspection blocker",
    )

    retained_reader = WORK / "retained-reader"
    retained_reader.mkdir(mode=0o700)
    retained_reader.joinpath("asset.json").write_bytes(b"abcd")
    check(
        validation._read_no_follow_bounded(
            retained_reader,
            Path("asset.json"),
            4,
        )
        == b"abcd",
        "bounded retained-asset reader changed valid bytes",
    )
    try:
        validation._read_no_follow_bounded(
            retained_reader,
            Path("asset.json"),
            3,
        )
    except ValueError as error:
        check("size limit" in str(error), "oversized retained asset failed unclearly")
    else:
        raise AssertionError("retained asset was read before enforcing its size limit")
    outside = WORK / "retained-reader-outside"
    outside.mkdir(mode=0o700)
    outside.joinpath("asset.json").write_bytes(b"safe")
    retained_reader.joinpath("linked").symlink_to(outside, target_is_directory=True)
    try:
        validation._read_no_follow_bounded(
            retained_reader,
            Path("linked/asset.json"),
            4,
        )
    except OSError:
        pass
    else:
        raise AssertionError("retained asset reader followed a parent symlink")

    escaped_asset = copy.deepcopy(provenance_candidate)
    escaped = next(
        target["asset"]
        for mode in escaped_asset["runtime_evidence"]["dependency_evidence"]["modes"]
        for target in mode["targets"]
        if "asset" in target
    )
    escaped["path"] = (
        "docs/research/experiments/assets/../../outside.project.assets.json"
    )
    escaped_asset["runtime_evidence"]["receipt_binding"]["digest"] = receipt_digest(
        escaped_asset
    )
    escaped_errors = validate_public_build_runtime_evidence(
        escaped_asset,
        "escaped-retained-asset",
        load_strict_json(
            ROOT / "docs/research/public-build-source-baseline.json"
        ),
    )
    check(
        any("retained asset path" in error for error in escaped_errors),
        "noncanonical retained asset destination was accepted",
    )

    unproved, _, _, _ = synthetic_case(
        "asset-publication-unproved-quiescence",
        asset_modes=["source-faithful", "public-only"],
        force_unproved_label="source-faithful-build",
    )
    unproved_dependency = unproved["runtime_evidence"]["dependency_evidence"]
    check(
        not any(
            "asset" in target
            for mode in unproved_dependency["modes"]
            for target in mode["targets"]
        )
        and all(
            target["status"] == "invalid"
            and target["reason"]
            == "asset-inspection-blocked-by-unproved-quiescence"
            for mode in unproved_dependency["modes"]
            for target in mode["targets"]
        ),
        "unproved child quiescence did not prohibit all asset inspection",
    )
    replaced_root, _, _, _ = synthetic_case(
        "replaced-selection-root",
        asset_modes=["source-faithful"],
        replace_selection_root_before_identity_check=True,
    )
    replaced_runtime = replaced_root["runtime_evidence"]
    check(
        replaced_runtime["canonical_termination"]["cause"]
        == "root-identity-unverified"
        and not any(
            "asset" in target
            for mode in replaced_runtime["dependency_evidence"]["modes"]
            for target in mode["targets"]
        )
        and all(
            target["reason"]
            == "asset-inspection-blocked-by-root-identity-unverified"
            for mode in replaced_runtime["dependency_evidence"]["modes"]
            for target in mode["targets"]
        ),
        "replaced selection root did not fail closed before asset access",
    )
    synthetic_case(
        "invalid-recorded-candidate",
        asset_modes=["source-faithful"],
        candidate_validation_error="synthetic invalid candidate",
    )

    asset_work = WORK / "asset-copy-regression"
    asset_work.mkdir(mode=0o700)
    destination = asset_work / "destination"
    destination.write_bytes(b"existing")
    published: list[Any] = []
    try:
        _atomic_publish_asset(b"new", destination, published)
    except FileExistsError:
        pass
    else:
        raise AssertionError("prevalidated asset overwrote an existing destination")
    check(
        destination.read_bytes() == b"existing"
        and not list(asset_work.glob(".destination.runner-*")),
        "prevalidated asset publication changed an existing destination or leaked temp",
    )
    for identity in published:
        identity.close()


def test_recording_phases_and_asset_identity_rollback() -> None:
    for timing in ("before-asset-inspection", "after-asset-publication"):
        recorded, _, _, _ = synthetic_case(
            f"selection-root-replaced-{timing}",
            asset_modes=["source-faithful"],
            replace_selection_root_before_asset_inspection=(
                timing == "before-asset-inspection"
            ),
            replace_selection_root_after_asset_publication=(
                timing == "after-asset-publication"
            ),
            use_real_candidate_validator=True,
        )
        dependency_targets = [
            target
            for mode in recorded["runtime_evidence"]["dependency_evidence"]["modes"]
            for target in mode["targets"]
        ]
        roots = {
            root["kind"]: root
            for root in recorded["runtime_evidence"][
                "ownership_conditioned_cleanup"
            ]["roots"]
        }
        check(
            recorded["runtime_evidence"]["canonical_termination"]["cause"]
            == "root-identity-unverified"
            and not roots["selection"]["identity_verified"]
            and not any(
                attempt[stream]["disposition"] == "retained-sanitized"
                for outcome in [
                    *recorded["runtime_evidence"]["preparation_outcomes"],
                    *recorded["runtime_evidence"]["command_outcomes"],
                ]
                for attempt in outcome["attempts"]
                for stream in ("stdout", "stderr")
            )
            and all(
                target["status"] == "invalid"
                and target["reason"]
                == "asset-inspection-blocked-by-root-identity-unverified"
                and "asset" not in target
                for target in dependency_targets
            )
            and not list(
                (
                    WORK
                    / f"selection-root-replaced-{timing}/retained-assets"
                ).glob("*.json")
            ),
            f"selection-root replacement {timing} retained assets or references",
        )

    exchanged_root, _, old_inode, new_inode = synthetic_case(
        "selection-root-replaced-during-exchange",
        asset_modes=["source-faithful"],
        replace_selection_root_during_recording_exchange=True,
    )
    exchanged_attempts = [
        attempt
        for outcome in [
            *exchanged_root["runtime_evidence"]["preparation_outcomes"],
            *exchanged_root["runtime_evidence"]["command_outcomes"],
        ]
        for attempt in outcome["attempts"]
    ]
    check(
        old_inode != new_inode
        and exchanged_root["runtime_evidence"]["canonical_termination"]["cause"]
        == "root-identity-unverified"
        and all(
            attempt[stream]["disposition"] != "retained-sanitized"
            for attempt in exchanged_attempts
            for stream in ("stdout", "stderr")
        )
        and not list(
            (
                WORK
                / "selection-root-replaced-during-exchange/retained-assets"
            ).glob("*.json")
        )
        and not normalized_recorded_errors(
            exchanged_root,
            "fixture:selection-root-replaced-during-exchange",
        ),
        "selection-root replacement during exchange committed stale captures or assets",
    )

    for timing in ("pre-exchange", "post-exchange"):
        for action in ("delete", "replace"):
            fault = f"{timing}-{action}"
            recorded, _, old_inode, new_inode = synthetic_case(
                f"capture-{fault}",
                asset_modes=["source-faithful"],
                capture_recording_fault=fault,
            )
            invalidated = [
                attempt
                for outcome in [
                    *recorded["runtime_evidence"]["preparation_outcomes"],
                    *recorded["runtime_evidence"]["command_outcomes"],
                ]
                for attempt in outcome["attempts"]
                if LATE_CAPTURE_FAILURE_REASON
                in str(attempt["failure_reason"])
            ]
            replacement_paths = list(
                (
                    WORK / f"capture-{fault}/selections/bundle/captures"
                ).glob("*")
            )
            check(
                old_inode != new_inode
                and recorded["runtime_evidence"]["canonical_termination"]["cause"]
                == "capture-failed"
                and len(invalidated) == 1
                and all(
                    invalidated[0][stream]
                    == {
                        "disposition": "capture-unverifiable",
                        "path": None,
                        "sha256": None,
                        "sanitized_bytes": 0,
                        "excerpt": "",
                        "truncated": False,
                    }
                    for stream in ("stdout", "stderr")
                )
                and not list(
                    (WORK / f"capture-{fault}/retained-assets").glob("*.json")
                )
                and (
                    action == "delete"
                    or any(
                        path.read_bytes() == b"actor-capture-replacement"
                        for path in replacement_paths
                        if path.is_file()
                    )
                )
                and not normalized_recorded_errors(
                    recorded,
                    f"fixture:capture-{fault}",
                ),
                f"{fault} capture race committed stale references, lost an actor "
                "replacement, or failed to roll back assets",
            )

    failed_restore, _, _, _ = synthetic_case(
        "failed-restore-late-capture",
        fail_restore_mode="public-only",
        capture_recording_fault="pre-exchange-replace",
        capture_recording_label="public-only-restore",
        use_real_candidate_validator=True,
    )
    failed_restore_outcomes = {
        outcome["command_id"]: outcome
        for outcome in failed_restore["runtime_evidence"]["command_outcomes"]
    }
    invalidated_restore = failed_restore_outcomes["public-only-restore"]
    check(
        failed_restore["status"] == "recorded"
        and invalidated_restore["status"] == "failed"
        and invalidated_restore["attempts"][0]["termination"] == "completed"
        and invalidated_restore["attempts"][0]["exit_code"] != 0
        and invalidated_restore["attempts"][0]["failure_reason"]
        == LATE_CAPTURE_FAILURE_REASON
        and all(
            invalidated_restore["attempts"][0][stream]["disposition"]
            == "capture-unverifiable"
            for stream in ("stdout", "stderr")
        )
        and all(
            outcome["status"] == "blocked"
            and outcome["blocked_by"] == "public-only-restore"
            for command_id, outcome in failed_restore_outcomes.items()
            if command_id.startswith("public-only-")
            and command_id != "public-only-restore"
        )
        and failed_restore["runtime_evidence"]["canonical_termination"]["cause"]
        == "capture-failed"
        and not normalized_recorded_errors(
            failed_restore,
            "fixture:failed-restore-late-capture",
        ),
        "late capture invalidation discarded a failed restore or its blockers",
    )

    semantic_failure, _, _, _ = synthetic_case(
        "semantic-preparation-late-capture",
        mismatch_mise_version=True,
        capture_recording_fault="pre-exchange-replace",
        capture_recording_label="mise-version",
        use_real_candidate_validator=True,
    )
    semantic_preparation = next(
        preparation
        for preparation in semantic_failure["runtime_evidence"][
            "preparation_outcomes"
        ]
        if preparation["id"] == "mise-version"
    )
    check(
        semantic_failure["status"] == "recorded"
        and semantic_preparation["status"] == "failed"
        and semantic_preparation["failure_reason"]
        == "mise-version-output-did-not-match-reviewed-version"
        and semantic_preparation["attempts"][0]["termination"] == "completed"
        and semantic_preparation["attempts"][0]["exit_code"] == 0
        and semantic_preparation["attempts"][0]["failure_reason"]
        == LATE_CAPTURE_FAILURE_REASON
        and all(
            preparation["status"] == "blocked"
            and preparation["failure_reason"] == "blocked-by:mise-version"
            for preparation in semantic_failure["runtime_evidence"][
                "preparation_outcomes"
            ]
            if PREPARATIONS.index(
                next(
                    spec
                    for spec in PREPARATIONS
                    if spec.identifier == preparation["id"]
                )
            )
            > PREPARATIONS.index(
                next(spec for spec in PREPARATIONS if spec.identifier == "mise-version")
            )
        )
        and semantic_failure["runtime_evidence"]["canonical_termination"]["cause"]
        == "capture-failed"
        and not normalized_recorded_errors(
            semantic_failure,
            "fixture:semantic-preparation-late-capture",
        ),
        "late capture invalidation discarded a semantic preparation failure",
    )

    for fault in ("candidate-write", "exchange"):
        current, _, old_inode, new_inode = synthetic_case(
            f"recording-{fault}",
            asset_modes=["source-faithful"],
            recording_fault=fault,
        )
        case = WORK / f"recording-{fault}"
        check(
            current["status"] == "planned"
            and old_inode == new_inode
            and not list(case.glob(".bundle.json.recorded-*"))
            and not list((case / "retained-assets").glob("*.json")),
            f"{fault} leaked state while preserving the planned bundle",
        )

    for timing in ("pre-exchange", "post-exchange"):
        for action in ("delete", "replace"):
            fault = f"{timing}-asset-{action}"
            current, _, old_inode, new_inode = synthetic_case(
                f"recording-{fault}",
                asset_modes=["source-faithful"],
                recording_fault=fault,
            )
            assets = list(
                (
                    WORK
                    / f"recording-{fault}/retained-assets"
                ).glob("*.json")
            )
            check(
                current["status"] == "planned"
                and old_inode == new_inode
                and (
                    not assets
                    if action == "delete"
                    else len(assets) == 1
                    and assets[0].read_bytes() == b"actor-replacement"
                ),
                f"{fault} committed the bundle, lost an actor replacement, "
                "or retained matching invocation assets",
            )

    indeterminate_asset, _, old_inode, new_inode = synthetic_case(
        "recording-post-exchange-asset-replace-indeterminate",
        asset_modes=["source-faithful"],
        recording_fault="post-exchange-asset-replace-indeterminate",
    )
    indeterminate_assets = list(
        (
            WORK
            / "recording-post-exchange-asset-replace-indeterminate/retained-assets"
        ).glob("*.json")
    )
    check(
        indeterminate_asset["status"] == "recorded"
        and old_inode != new_inode
        and any(
            asset.read_bytes() == b"actor-replacement"
            for asset in indeterminate_assets
        )
        and list(
            (
                WORK
                / "recording-post-exchange-asset-replace-indeterminate"
            ).glob(".bundle.json.recorded-*")
        ),
        "indeterminate post-exchange restoration claimed rollback or lost actor state",
    )

    for label, fault in (
        ("recording-concurrent-replacement", "concurrent-replacement"),
        (
            "recording-post-exchange-displaced-replacement",
            "post-exchange-displaced-replacement",
        ),
    ):
        ambiguous, _, old_inode, new_inode = synthetic_case(
            label,
            asset_modes=["source-faithful"],
            recording_fault=fault,
        )
        directory = WORK / label
        displaced = list(directory.glob(".bundle.json.recorded-*"))
        check(
            ambiguous["status"] == "recorded"
            and old_inode != new_inode
            and len(list((directory / "retained-assets").glob("*.json"))) == 1
            and any(
                path.read_bytes() == b'{"actor":"replacement"}\n'
                for path in displaced
            ),
            f"{fault} claimed reversal, lost actor bytes, or rolled back assets",
        )

    cancelled, _, _, _ = synthetic_case(
        "cancel-after-asset-publication",
        asset_modes=["source-faithful"],
        cancel_after_asset_publication=True,
        use_real_candidate_validator=True,
    )
    check(
        cancelled["runtime_evidence"]["canonical_termination"]["cause"]
        == "cancelled"
        and not list(
            (
                WORK
                / "cancel-after-asset-publication/retained-assets"
            ).glob("*.json")
        ),
        "late cancellation did not roll back published assets before commit",
    )

    for name, arguments, expected in (
        (
            "late-cancel-after-sensitive",
            {"sensitive_command": "source-faithful-build"},
            "sensitive-output",
        ),
        (
            "late-cancel-after-source-integrity",
            {"mutate_command": "source-faithful-build"},
            "source-integrity-changed",
        ),
        (
            "late-cancel-after-root-identity",
            {"replace_selection_root_after_asset_publication": True},
            "root-identity-unverified",
        ),
    ):
        overlapped, _, old_inode, new_inode = synthetic_case(
            name,
            asset_modes=["source-faithful"],
            cancel_after_asset_publication=True,
            use_real_candidate_validator=True,
            **arguments,
        )
        check(
            old_inode != new_inode
            and overlapped["runtime_evidence"]["canonical_termination"]["cause"]
            == expected,
            f"{name} spun or replaced the earlier canonical safety cause",
        )

    deferred, _, old_inode, new_inode = synthetic_case(
        "cancel-during-recording-exchange",
        asset_modes=["source-faithful"],
        cancel_during_recording_exchange=True,
    )
    check(
        old_inode != new_inode
        and deferred["runtime_evidence"]["canonical_termination"]["cause"]
        == "cancelled"
        and not list(
            (
                WORK
                / "cancel-during-recording-exchange/retained-assets"
            ).glob("*.json")
        )
        and not normalized_recorded_errors(
            deferred,
            "fixture:cancel-during-recording-exchange",
        ),
        "cancellation during the signal-masked exchange was committed before accounting",
    )

    synthetic_case(
        "runtime-context-git-digest-failure",
        asset_modes=["source-faithful"],
        fail_runtime_context_git_digest=True,
    )

    committed, _, old_inode, new_inode = synthetic_case(
        "recording-post-commit-fsync",
        asset_modes=["source-faithful"],
        recording_fault="post-commit-fsync",
    )
    check(
        committed["status"] == "recorded"
        and old_inode != new_inode
        and list(
            (WORK / "recording-post-commit-fsync/retained-assets").glob("*.json")
        ),
        "post-commit durability error rolled back referenced assets or the bundle",
    )

    indeterminate, _, old_inode, new_inode = synthetic_case(
        "recording-post-exchange-displaced-read",
        asset_modes=["source-faithful"],
        recording_fault="post-exchange-displaced-read",
    )
    check(
        indeterminate["status"] == "recorded"
        and old_inode != new_inode
        and list(
            (
                WORK
                / "recording-post-exchange-displaced-read/retained-assets"
            ).glob("*.json")
        ),
        "post-exchange displaced inspection fault rolled back the bundle or assets",
    )

    asset_root = WORK / "asset-identity"
    actual = asset_root / "actual"
    actual.mkdir(mode=0o700, parents=True)
    linked = asset_root / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    try:
        _atomic_publish_asset(b"payload", linked / "asset.json", [])
    except (OSError, ValidationError, runner.AssetPublicationError):
        pass
    else:
        raise AssertionError("asset destination ancestor symlink was followed")

    destination = actual / "owned.json"
    published: list[Any] = []
    identity = _atomic_publish_asset(b"owned", destination, published)
    replacement = actual / "replacement"
    replacement.write_bytes(b"other-actor")
    os.replace(replacement, destination)
    rollback_errors = runner._rollback_published_assets(published)
    check(
        rollback_errors
        and destination.read_bytes() == b"other-actor",
        "asset rollback unlinked a replacement owned by another actor",
    )
    identity.close()

    cleanup_destination = actual / "cleanup-fault.json"
    cleanup_registry: list[Any] = []
    original_noreplace = runner._rename_noreplace
    cleanup_failed = False

    def fail_temp_cleanup(
        directory_descriptor: int,
        left: str,
        right: str,
    ) -> None:
        nonlocal cleanup_failed
        if (
            not cleanup_failed
            and left.startswith(".cleanup-fault.json.runner-")
        ):
            cleanup_failed = True
            raise OSError("synthetic post-link cleanup failure")
        original_noreplace(directory_descriptor, left, right)

    runner._rename_noreplace = fail_temp_cleanup
    try:
        try:
            _atomic_publish_asset(
                b"owned",
                cleanup_destination,
                cleanup_registry,
            )
        except runner.AssetPublicationError:
            pass
        else:
            raise AssertionError("post-link cleanup fault was not surfaced")
    finally:
        runner._rename_noreplace = original_noreplace
    check(
        not cleanup_registry
        and not cleanup_destination.exists(),
        "post-link cleanup fault retained the published asset",
    )
    check(
        len(list(actual.glob(".cleanup-fault.json.runner-*"))) == 1,
        "indeterminate staging cleanup did not preserve the invocation object",
    )

    durability_destination = actual / "durability-fault.json"
    durability_registry: list[Any] = []
    original_fsync = runner.os.fsync
    durability_directory = actual.stat()

    def fail_asset_directory_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev == durability_directory.st_dev
            and metadata.st_ino == durability_directory.st_ino
        ):
            raise OSError("synthetic asset directory fsync failure")
        original_fsync(descriptor)

    runner.os.fsync = fail_asset_directory_fsync
    try:
        try:
            _atomic_publish_asset(
                b"owned",
                durability_destination,
                durability_registry,
            )
        except runner.AssetPublicationError:
            pass
        else:
            raise AssertionError("asset directory fsync fault was not surfaced")
    finally:
        runner.os.fsync = original_fsync
    check(
        not durability_registry and not durability_destination.exists(),
        "asset directory fsync failure did not trigger durable rollback",
    )

    rollback_destination = actual / "rollback-durability-fault.json"
    rollback_registry: list[Any] = []
    rollback_identity = _atomic_publish_asset(
        b"owned",
        rollback_destination,
        rollback_registry,
    )

    def fail_rollback_fsync(_descriptor: int) -> None:
        raise OSError("synthetic rollback directory fsync failure")

    runner.os.fsync = fail_rollback_fsync
    try:
        rollback_errors = runner._rollback_published_assets(rollback_registry)
    finally:
        runner.os.fsync = original_fsync
    check(
        rollback_errors and not rollback_destination.exists(),
        "rollback directory fsync uncertainty was not reported",
    )
    rollback_identity.close()

    creation_destination = asset_root / "new-assets" / "creation-fault.json"
    creation_registry: list[Any] = []
    creation_parent = asset_root.stat()

    def fail_creation_parent_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev == creation_parent.st_dev
            and metadata.st_ino == creation_parent.st_ino
        ):
            raise OSError("synthetic asset-directory creation fsync failure")
        original_fsync(descriptor)

    runner.os.fsync = fail_creation_parent_fsync
    try:
        try:
            _atomic_publish_asset(
                b"owned",
                creation_destination,
                creation_registry,
            )
        except runner.AssetPublicationError:
            pass
        else:
            raise AssertionError("asset-directory creation fsync fault was not surfaced")
    finally:
        runner.os.fsync = original_fsync
    check(
        not creation_registry and not creation_destination.exists(),
        "asset-directory creation durability fault published an asset",
    )


def test_quarantine_cleanup_linearization() -> None:
    work = WORK / "quarantine-linearization"
    work.mkdir(mode=0o700)

    def install_replacement_hook(prefix: str, payload: bytes):
        original = runner._rename_noreplace
        replaced = False

        def replace_before_move(
            directory_descriptor: int,
            left: str,
            right: str,
        ) -> None:
            nonlocal replaced
            if not replaced and left.startswith(prefix):
                replaced = True
                actor = f".actor-{time.monotonic_ns()}"
                descriptor = os.open(
                    actor,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                    0o600,
                    dir_fd=directory_descriptor,
                )
                try:
                    os.write(descriptor, payload)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.rename(
                    actor,
                    left,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                )
            original(directory_descriptor, left, right)

        runner._rename_noreplace = replace_before_move
        return original, lambda: replaced

    def actor_survives(directory: Path, payload: bytes) -> bool:
        return any(
            path.is_file() and path.read_bytes() == payload
            for path in directory.iterdir()
        )

    asset = work / "rollback-asset.json"
    published: list[Any] = []
    identity = _atomic_publish_asset(b"invocation", asset, published)
    check(runner._published_asset_matches(identity), "asset baseline did not match")
    original, replaced = install_replacement_hook(
        asset.name,
        b"actor-final-asset",
    )
    try:
        rollback_errors = runner._rollback_published_assets(published)
    finally:
        runner._rename_noreplace = original
        identity.close()
    check(
        replaced()
        and rollback_errors
        and actor_survives(work, b"actor-final-asset"),
        "asset replacement at the former rollback unlink window was deleted",
    )

    staging_asset = work / "staging-asset.json"
    staging_registry: list[Any] = []
    original, replaced = install_replacement_hook(
        ".staging-asset.json.runner-",
        b"actor-asset-staging",
    )
    try:
        try:
            _atomic_publish_asset(
                b"invocation",
                staging_asset,
                staging_registry,
            )
        except runner.AssetPublicationError:
            pass
        else:
            raise AssertionError("asset staging replacement was accepted")
    finally:
        runner._rename_noreplace = original
        for registered in staging_registry:
            registered.close()
    check(
        replaced()
        and not staging_asset.exists()
        and actor_survives(work, b"actor-asset-staging"),
        "asset staging cleanup deleted an actor replacement or retained publication",
    )

    def bundle_case(
        label: str,
        *,
        retry: bool = False,
        fail_exchange: bool = False,
        expected_committed: bool,
    ) -> None:
        directory = work / label
        directory.mkdir(mode=0o700)
        bundle = directory / "bundle.json"
        bundle.write_text('{"status":"planned"}\n', encoding="utf-8")
        identity = runner._open_recording_identity(bundle)
        original_noreplace, replaced = install_replacement_hook(
            ".bundle.json.recorded-",
            f"actor-{label}".encode(),
        )
        original_exchange = runner._rename_exchange
        if fail_exchange:
            runner._rename_exchange = lambda *args, **kwargs: (
                (_ for _ in ()).throw(OSError("synthetic exchange failure"))
            )
        checks = 0

        def retry_after_exchange() -> Any:
            nonlocal checks
            checks += 1
            return (
                runner.RecordingRetry("cancelled")
                if retry and checks > 1
                else None
            )

        try:
            try:
                runner._atomic_replace_bundle(
                    identity,
                    {"status": "recorded"},
                    [],
                    precommit_check=retry_after_exchange if retry else None,
                )
            except runner.RecordingError as error:
                check(
                    error.committed is expected_committed,
                    f"{label} cleanup replacement had incorrect commit classification",
                )
            else:
                raise AssertionError(f"{label} cleanup replacement was accepted")
        finally:
            runner._rename_noreplace = original_noreplace
            runner._rename_exchange = original_exchange
            os.close(identity.descriptor)
            os.close(identity.parent_descriptor)
        check(
            replaced()
            and actor_survives(directory, f"actor-{label}".encode())
            and (
                load_strict_json(bundle)["status"] == "recorded"
            ) is expected_committed,
            f"{label} cleanup replacement was lost or misclassified",
        )

    bundle_case("success-displaced", expected_committed=True)
    bundle_case("retry-reversal", retry=True, expected_committed=False)
    bundle_case("finally-candidate", fail_exchange=True, expected_committed=False)


def test_pre_root_mise_and_zero_child_lifecycle() -> None:
    fake_bin = WORK / "ambient-bin"
    fake_bin.mkdir(mode=0o700)
    fake = fake_bin / "mise"
    shutil.copyfile(HELPER, fake)
    fake.chmod(0o700)
    root_base = WORK / "pre-root-mise"
    root_base.mkdir(mode=0o700)
    root = root_base / "must-not-exist"
    try:
        resolve_mise_executable(str(fake_bin))
        create_exclusive_root(root, root_base, {"kind": "must-not-create"})
    except CapabilityError:
        pass
    else:
        raise AssertionError("unreviewed ambient mise executable was accepted")
    check(not root.exists(), "mise rejection occurred after root creation")

    recorded, _, _, _ = synthetic_case(
        "mise-descriptor-launch",
        replace_mise_after_verification=True,
    )
    preparation_status = {
        item["id"]: item["status"]
        for item in recorded["runtime_evidence"]["preparation_outcomes"]
    }
    check(
        preparation_status["mise-version"] == "passed"
        and preparation_status["mise-install-dotnet-sdk"] == "passed",
        "mise launch followed a replaced path instead of the reviewed descriptor",
    )
    recorded, _, _, _ = synthetic_case(
        "zero-child-global-preparation-failure",
        precreate_toolchain_root=True,
    )
    quiescence = recorded["runtime_evidence"]["all_exit_quiescence"]
    check(
        quiescence["subreaper_enabled"] is child_subreaper_enabled()
        and not quiescence["observations"]
        and all(item["proved"] for item in quiescence["observations"]),
        "zero-child lifecycle did not record the actual subreaper and proof state",
    )
    roots = {
        item["kind"]: item
        for item in recorded["runtime_evidence"]["ownership_conditioned_cleanup"]["roots"]
    }
    check(
        not roots["toolchain"]["created"] and not roots["selection"]["created"],
        "zero-child root lifecycle claimed uncreated roots",
    )


def test_run_bundle_composition_and_descriptor_lifecycle() -> None:
    planned = load_strict_json(PLANNED_BUNDLE)
    carrier = WORK / "composition-carrier"
    carrier.write_bytes(b"carrier")

    def exercise(*, fail_at: str | None = None) -> tuple[list[str], int | None]:
        calls: list[str] = []
        bundle_fd = os.open(carrier, os.O_RDONLY)
        parent_fd = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY)
        parent_metadata = os.fstat(parent_fd)
        mise_fd: int | None = None
        original = {
            name: getattr(runner, name)
            for name in (
                "_open_canonical_bundle",
                "validate_bundle",
                "require_native_linux_x64",
                "_require_supervision_capabilities",
                "enable_child_subreaper",
                "resolve_mise_executable",
                "execute_planned_bundle",
            )
        }
        original_which = runner.shutil.which
        identity = runner.CanonicalBundleIdentity(
            canonical_path=carrier,
            descriptor=bundle_fd,
            parent_descriptor=parent_fd,
            parent_device=parent_metadata.st_dev,
            parent_inode=parent_metadata.st_ino,
            basename=carrier.name,
            device=1,
            inode=1,
            sha256="0" * 64,
        )
        runner._open_canonical_bundle = lambda path: (
            calls.append("canonical") or (planned, identity)
        )
        def validate(*args: Any, **kwargs: Any) -> tuple[dict[str, Any], bytes]:
            calls.append("validate")
            return {}, b"reviewed-lock"

        runner.validate_bundle = validate

        def host() -> None:
            calls.append("host")
            if fail_at == "host":
                raise CapabilityError("synthetic host failure")

        runner.require_native_linux_x64 = host
        runner._require_supervision_capabilities = lambda: calls.append(
            "supervision"
        )
        runner.enable_child_subreaper = lambda: (
            calls.append("subreaper") or True
        )
        runner.shutil.which = lambda *args, **kwargs: (
            calls.append("git") or "/usr/bin/git"
        )

        def mise(_path: str | None, _expected_sha256: str) -> Any:
            nonlocal mise_fd
            calls.append("mise")
            if fail_at == "mise":
                raise CapabilityError("synthetic mise failure")
            mise_fd = os.open(carrier, os.O_RDONLY)
            return runner.ExecutableIdentity(
                path=carrier,
                sha256="0" * 64,
                owner=os.getuid(),
                mode=0o755,
                descriptor=mise_fd,
            )

        runner.resolve_mise_executable = mise

        def execute(*args: Any, **kwargs: Any) -> dict[str, Any]:
            calls.append("execute")
            check(
                kwargs["mise_lock_bytes"] == b"reviewed-lock",
                "run_bundle did not pass the validated lock snapshot to execution",
            )
            if fail_at == "execute":
                raise RuntimeError("synthetic execute failure")
            return {"status": "recorded"}

        runner.execute_planned_bundle = execute
        try:
            try:
                runner.run_bundle(PLANNED_BUNDLE)
            except (CapabilityError, RuntimeError):
                if fail_at is None:
                    raise
            else:
                check(fail_at is None, "composition failure was not propagated")
        finally:
            runner.shutil.which = original_which
            for name, value in original.items():
                setattr(runner, name, value)
        for descriptor in (bundle_fd, parent_fd, mise_fd):
            if descriptor is None:
                continue
            try:
                os.fstat(descriptor)
            except OSError:
                pass
            else:
                raise AssertionError("run_bundle leaked an identity descriptor")
        return calls, mise_fd

    success, _ = exercise()
    check(
        success
        == [
            "canonical",
            "validate",
            "host",
            "supervision",
            "subreaper",
            "git",
            "mise",
            "execute",
        ],
        "run_bundle composition order differs from the reviewed topology",
    )
    host_failure, _ = exercise(fail_at="host")
    check(
        "execute" not in host_failure and "mise" not in host_failure,
        "host failure reached mise or execute",
    )
    mise_failure, _ = exercise(fail_at="mise")
    check("execute" not in mise_failure, "mise failure reached execute")
    execute_failure, _ = exercise(fail_at="execute")
    check(
        execute_failure[-1] == "execute",
        "execute exception did not traverse the complete composition",
    )


def test_canonical_bundle_path_and_mid_run_identity() -> None:
    canonical = WORK / "canonical-bundle.json"
    canonical.write_bytes(PLANNED_BUNDLE.read_bytes())
    copy_path = WORK / "canonical-copy.json"
    copy_path.write_bytes(canonical.read_bytes())
    symlink_path = WORK / "canonical-symlink.json"
    symlink_path.symlink_to(canonical)
    original_path = runner.CANONICAL_BUNDLE_PATH
    runner.CANONICAL_BUNDLE_PATH = canonical
    try:
        try:
            runner._open_canonical_bundle(copy_path)
        except ValidationError:
            pass
        else:
            raise AssertionError("noncanonical bundle copy was accepted for production")
        try:
            runner._open_canonical_bundle(symlink_path)
        except ValidationError:
            pass
        else:
            raise AssertionError("bundle symlink was accepted for production")
        _, identity = runner._open_canonical_bundle(canonical)
        try:
            replacement = WORK / "canonical-replacement.json"
            replacement.write_bytes(canonical.read_bytes())
            os.replace(replacement, canonical)
            try:
                runner._verify_canonical_bundle_identity(identity)
            except ValidationError:
                pass
            else:
                raise AssertionError("mid-run canonical path replacement was accepted")
        finally:
            os.close(identity.descriptor)
            os.close(identity.parent_descriptor)
    finally:
        runner.CANONICAL_BUNDLE_PATH = original_path

    actual_parent = WORK / "canonical-actual-parent"
    actual_parent.mkdir(mode=0o700)
    actual_bundle = actual_parent / "bundle.json"
    actual_bundle.write_bytes(PLANNED_BUNDLE.read_bytes())
    linked_parent = WORK / "canonical-linked-parent"
    linked_parent.symlink_to(actual_parent, target_is_directory=True)
    linked_bundle = linked_parent / "bundle.json"
    runner.CANONICAL_BUNDLE_PATH = linked_bundle
    try:
        try:
            runner._open_canonical_bundle(linked_bundle)
        except (OSError, ValidationError):
            pass
        else:
            raise AssertionError("canonical bundle ancestor symlink was followed")
    finally:
        runner.CANONICAL_BUNDLE_PATH = original_path

    parent = WORK / "canonical-parent-rebinding"
    parent.mkdir(mode=0o700)
    bundle = parent / "bundle.json"
    bundle.write_bytes(PLANNED_BUNDLE.read_bytes())
    identity = runner._open_recording_identity(bundle)
    displaced_parent = WORK / "canonical-parent-rebinding-displaced"
    parent.rename(displaced_parent)
    parent.mkdir(mode=0o700)
    bundle.write_bytes(PLANNED_BUNDLE.read_bytes())
    try:
        try:
            runner._verify_canonical_bundle_identity(identity)
        except ValidationError:
            pass
        else:
            raise AssertionError("renamed and replaced canonical parent was accepted")
    finally:
        os.close(identity.descriptor)
        os.close(identity.parent_descriptor)

    exchange_parent = WORK / "canonical-parent-between-verify-exchange"
    exchange_parent.mkdir(mode=0o700)
    exchange_bundle = exchange_parent / "bundle.json"
    exchange_bundle.write_bytes(PLANNED_BUNDLE.read_bytes())
    identity = runner._open_recording_identity(exchange_bundle)
    moved_exchange_parent = WORK / "canonical-parent-after-verify"
    original_exchange = runner._rename_exchange
    replaced = False

    def replace_parent_before_exchange(
        directory_descriptor: int,
        left: str,
        right: str,
    ) -> None:
        nonlocal replaced
        if not replaced:
            replaced = True
            exchange_parent.rename(moved_exchange_parent)
            exchange_parent.mkdir(mode=0o700)
            exchange_bundle.write_text(
                '{"actor":"replacement"}\n',
                encoding="utf-8",
            )
        original_exchange(directory_descriptor, left, right)

    runner._rename_exchange = replace_parent_before_exchange
    try:
        try:
            runner._atomic_replace_bundle(identity, {"status": "recorded"}, [])
        except runner.RecordingError as error:
            check(
                error.committed,
                "parent replacement after verification was classified as pre-commit",
            )
        else:
            raise AssertionError("parent replacement before exchange was accepted")
    finally:
        runner._rename_exchange = original_exchange
        os.close(identity.descriptor)
        os.close(identity.parent_descriptor)
    check(
        load_strict_json(exchange_bundle) == {"actor": "replacement"},
        "recording through the retained parent clobbered the live replacement parent",
    )


def test_reducer_truth_table_and_dependency_aggregates() -> None:
    commands = command_topology()

    def preparation(
        identifier: str,
        termination: str = "completed",
        failure_reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "id": identifier,
            "status": "failed",
            "attempts": (
                [{"termination": termination, "failure_reason": termination}]
                if PREPARATIONS[
                    next(
                        index
                        for index, item in enumerate(PREPARATIONS)
                        if item.identifier == identifier
                    )
                ].child
                else []
            ),
            "failure_reason": failure_reason or termination,
        }

    def command(
        identifier: str,
        termination: str = "completed",
        reason: str | None = "failed",
        source_integrity_failure: str | None = None,
        *,
        spawned: bool = True,
    ) -> dict[str, Any]:
        return {
            "command_id": identifier,
            "status": "failed",
            "attempts": (
                [{"termination": termination, "failure_reason": reason}]
                if spawned
                else []
            ),
            "unspawned_termination": None if spawned else termination,
            "source_integrity_failure": source_integrity_failure,
        }

    cases = (
        ("completed", [], [], [], [], "completed"),
        (
            "command-failure",
            [],
            [command("source-faithful-build")],
            [],
            [],
            "completed-with-command-failures",
        ),
        (
            "mode-preparation",
            [preparation("source-faithful-integrity-baseline")],
            [],
            [],
            [],
            "completed-with-command-failures",
        ),
        (
            "global-preparation",
            [preparation("verify-dotnet-installation")],
            [],
            [],
            [],
            "preparation-failed",
        ),
        (
            "preparation-source-integrity-after-child-exit",
            [
                preparation(
                    "git-source-faithful-fetch",
                    failure_reason=append_failure_reason_marker(
                        "child-exit:11",
                        SOURCE_INTEGRITY_CHANGED_MARKER,
                    ),
                )
            ],
            [],
            [],
            [],
            SOURCE_INTEGRITY_CHANGED_MARKER,
        ),
        (
            "preparation-safety-precedes-source-integrity",
            [
                preparation(
                    "git-source-faithful-fetch",
                    "sensitive-output",
                    append_failure_reason_marker(
                        "sensitive-output",
                        SOURCE_INTEGRITY_CHANGED_MARKER,
                    ),
                )
            ],
            [],
            [],
            [],
            "sensitive-output",
        ),
        (
            "first-global-safety",
            [],
            [
                command("source-faithful-restore", "sensitive-output"),
                command("public-only-restore", "capture-failed"),
            ],
            [],
            [],
            "sensitive-output",
        ),
        (
            "late-root",
            [],
            [command("source-faithful-restore", "sensitive-output")],
            [],
            [{"kind": "selection", "created": True, "identity_verified": False}],
            "root-identity-unverified",
        ),
        (
            "unproved-quiescence",
            [],
            [command("source-faithful-restore", "sensitive-output")],
            [
                {
                    "subject_kind": "command",
                    "subject_id": "source-faithful-restore",
                    "proved": False,
                }
            ],
            [{"kind": "selection", "created": True, "identity_verified": False}],
            "quiescence-unproved",
        ),
        (
            "source-integrity",
            [],
            [
                command(
                    "source-faithful-build",
                    "completed",
                    None,
                    "fingerprint-mismatch",
                )
            ],
            [],
            [],
            "source-integrity-changed",
        ),
        (
            "source-integrity-after-timeout",
            [],
            [
                command(
                    "source-faithful-build",
                    "timed-out",
                    "timeout",
                    "fingerprint-mismatch",
                )
            ],
            [],
            [],
            "source-integrity-changed",
        ),
        (
            "source-integrity-after-spawn-failure",
            [],
            [
                command(
                    "source-faithful-build",
                    "spawn-failed",
                    "spawn failed",
                    "fingerprint-error",
                    spawned=False,
                )
            ],
            [],
            [],
            "source-integrity-changed",
        ),
        (
            "global-output-precedes-source-integrity",
            [],
            [
                command(
                    "source-faithful-build",
                    "sensitive-output",
                    "sensitive output",
                    "fingerprint-mismatch",
                )
            ],
            [],
            [],
            "sensitive-output",
        ),
    )
    for name, preparations, outcomes, observations, roots, expected in cases:
        actual = reduce_runtime(
            preparations,
            outcomes,
            commands,
            observations,
            roots,
        )["cause"]
        check(actual == expected, f"{name} reducer case produced {actual}")

    def late_attempt(
        termination: str = "completed",
        exit_code: int | None = 0,
        previous_reason: str | None = None,
    ) -> dict[str, Any]:
        marker = LATE_CAPTURE_FAILURE_REASON
        return {
            "termination": termination,
            "exit_code": exit_code,
            "failure_reason": (
                marker
                if previous_reason is None
                else f"{previous_reason}; {marker}"
            ),
            "stdout": {"disposition": "capture-unverifiable"},
            "stderr": {"disposition": "capture-unverifiable"},
        }

    def complete_preparations() -> list[dict[str, Any]]:
        return [
            {
                "id": spec.identifier,
                "status": "passed",
                "attempts": [],
                "failure_reason": None,
            }
            for spec in PREPARATIONS
        ]

    def complete_commands() -> list[dict[str, Any]]:
        return [
            {
                "command_id": item["id"],
                "status": "passed",
                "attempts": [],
                "unspawned_termination": None,
                "source_integrity_failure": None,
            }
            for item in commands
        ]

    preparations = complete_preparations()
    mise_index = next(
        index
        for index, spec in enumerate(PREPARATIONS)
        if spec.identifier == "mise-version"
    )
    preparations[mise_index] = {
        "id": "mise-version",
        "status": "failed",
        "attempts": [late_attempt()],
        "failure_reason": "mise-version-output-did-not-match-reviewed-version",
    }
    prefix_state = reduce_runtime(
        preparations[: mise_index + 1],
        [],
        commands,
    )
    final_state = reduce_runtime(
        preparations,
        complete_commands(),
        commands,
    )
    check(
        prefix_state["cause"] == "preparation-failed"
        and prefix_state["global_blocker"] == "mise-version"
        and final_state["cause"] == "capture-failed",
        "late capture discarded an ordinary global preparation failure",
    )

    preparations = complete_preparations()
    mode_index = next(
        index
        for index, spec in enumerate(PREPARATIONS)
        if spec.identifier == "git-public-only-init"
    )
    preparations[mode_index] = {
        "id": "git-public-only-init",
        "status": "failed",
        "attempts": [late_attempt("timed-out", None, "timeout")],
        "failure_reason": "timeout",
    }
    mode_state = reduce_runtime(
        preparations,
        complete_commands(),
        commands,
    )
    check(
        mode_state["cause"] == "capture-failed"
        and mode_state["mode_blockers"].get("public-only")
        == "git-public-only-init",
        "late capture discarded a mode-local preparation blocker",
    )

    for termination, source_failure, expected in (
        ("sensitive-output", None, "sensitive-output"),
        ("completed", "fingerprint-mismatch", "source-integrity-changed"),
    ):
        outcomes = complete_commands()
        command_index = next(
            index
            for index, item in enumerate(commands)
            if item["id"] == "public-only-build"
        )
        outcomes[command_index] = {
            "command_id": "public-only-build",
            "status": "failed",
            "attempts": [
                late_attempt(
                    termination,
                    0 if termination == "completed" else None,
                    None if termination == "completed" else termination,
                )
            ],
            "unspawned_termination": None,
            "source_integrity_failure": source_failure,
        }
        state = reduce_runtime(
            complete_preparations(),
            outcomes,
            commands,
        )
        check(
            state["cause"] == expected,
            f"late capture changed {expected} precedence",
        )

    outcomes = complete_commands()
    outcomes[0] = {
        "command_id": commands[0]["id"],
        "status": "failed",
        "attempts": [late_attempt()],
        "unspawned_termination": None,
        "source_integrity_failure": None,
    }
    cancelled = reduce_runtime(
        complete_preparations(),
        outcomes,
        commands,
        orchestration_stop={
            "subject_kind": "orchestration",
            "subject_id": "recorded-bundle",
            "phase": "before-recording-commit",
        },
    )
    check(
        cancelled["cause"] == "cancelled",
        "late capture changed cancellation precedence",
    )

def main() -> int:
    global SUBREAPER_ENABLED, WORK
    SUBREAPER_ENABLED = enable_child_subreaper()
    WORK = Path(tempfile.mkdtemp(prefix="public-build-conformance-"))
    original_write_root = runner.REPOSITORY_WRITE_ROOT
    runner.REPOSITORY_WRITE_ROOT = WORK
    try:
        tests = (
            test_literal_argv_environment_and_bounded_output,
            test_capture_identity_alteration_and_replacement,
            test_root_creation_guards_and_race,
            test_partial_root_marker_and_stale_selection_states,
            test_one_attempt_and_lifecycle_table,
            test_surviving_grandchild_and_retain_unproved,
            test_bounded_discovery_and_capture_shutdown,
            test_emergency_cleanup_requires_stable_empty_scans,
            test_source_fingerprint_bounds_races_and_no_follow,
            test_spawn_and_post_spawn_fault_cleanup,
            test_cancellation_initialization_fixed_point_and_between_subjects,
            test_unsupported_host_before_root,
            test_strict_json_and_receipt_tamper,
            test_planned_and_recorded_component_hash_lifecycle,
            test_exact_two_mode_command_topology,
            test_documented_nuget_cache_location_output,
            test_restore_metadata_isolation_binding,
            test_production_orchestration_order_environment_and_atomic_recording,
            test_restore_failure_blocks_mode,
            test_mode_checkout_info_and_config_failures_are_isolated,
            test_timeout_blocks_remaining,
            test_shared_stop_scope_and_precedence,
            test_sensitive_global_and_overflow_mode_local,
            test_source_unchanged_guard,
            test_preparation_checkout_binding_overlay,
            test_failed_restore_partial_assets_and_asset_destination_safety,
            test_recording_phases_and_asset_identity_rollback,
            test_quarantine_cleanup_linearization,
            test_pre_root_mise_and_zero_child_lifecycle,
            test_run_bundle_composition_and_descriptor_lifecycle,
            test_canonical_bundle_path_and_mid_run_identity,
            test_reducer_truth_table_and_dependency_aggregates,
        )
        for test in tests:
            test()
    finally:
        runner.REPOSITORY_WRITE_ROOT = original_write_root
        os.environ.pop("PUBLIC_BUILD_POISON", None)
        if WORK.exists() and not WORK.is_symlink():
            shutil.rmtree(WORK)
    print(f"Public-build runner conformance passed ({len(tests)} conceptual groups).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
