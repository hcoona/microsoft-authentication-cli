"""Private, nonexecuting final-publish outer-controller source candidate.

This file is not imported by run_windows.py. Its immutable source, Windows bootstrap,
admission/receipt checks, guard compilation and action capacity remain unbound.
"""

DRAFT_ONLY = True
if DRAFT_ONLY:
    raise RuntimeError("DRAFT_ONLY: final publish has no accepted execution binding")

import datetime
import json
import os
import signal
import subprocess
import time


# Retaining a Popen reference does not wait for, signal, or end the proxy. There is
# no context manager, atexit stop, subprocess.run, communicate or blocking wait.
_retained_proxies = []


def _assert_exact_admission(binding):
    """A future reviewed implementation must validate the fixed v4 recipe only.

    Required before Popen: accepted source/protocol/Wave identities; final graph,
    public payloads and protected inputs; the exact no-kill guard source/artifact
    and Windows bootstrap; current cumulative counters; a charged, durable linked
    Windows/WSL reservation with a fresh endpoint; exact command and owned paths;
    absence of prior result/cancel files; and a rule that missing/failed completion
    forbids continuation. This candidate does not create or reserve that capacity.
    """
    raise RuntimeError("UNBOUND: exact admission, preparation capacity and reservation")


def _assert_exact_original_completion(binding, original_proxy_exit):
    """Do not infer Windows completion from the WSL proxy return code.

    The future fixed validator must bind the original Windows result and controller
    zero exit to this reservation, original root zero exit, two complete original
    capture streams, all warning/input/timing predicates, natural zero Job counts
    at drain and final accounting, and zero termination requests. It must not read
    mutable subject outputs or enumerate the retained root while completion is
    unknown. Native image/symbol acceptance remains a separate later gate.
    """
    raise RuntimeError("UNBOUND: original Windows completion and exact receipt validator")


def _write_new_json(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    # A partial file remains failed evidence. Admission cannot treat mere presence
    # as completion; exact complete schema/content validation is still required.
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _request_retention_cancel(path):
    # The final Windows adapter interprets this only as stop-observing/retain.
    # This must never address the original controller's stop protocol.
    try:
        with path.open("xb") as stream:
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        return "already-present"
    return "created"


def invoke_final_publish_candidate(binding):
    if DRAFT_ONLY:
        raise RuntimeError("DRAFT_ONLY: no final-publish launch")
    _assert_exact_admission(binding)
    # Admission must already have durably charged this single action on both
    # hosts. An exception, killed collector or missing receipt never frees it.
    began = time.monotonic()
    controller_deadline = began + 700.0
    process = None
    interrupted = False
    old_handlers = {}
    result = {
        "normalCompletion": False,
        "safetyStop": True,
        "quiescent": False,
        "artifactEligible": False,
        "continuation_allowed": False,
        "retainedLiveWorkOrUnknown": True,
        "launchAttempted": False,
        "proxyExitCode": None,
        "proxyState": "not-created",
        "jobTerminationRequested": False,
        "proxyTerminationRequested": False,
        "reservationSha256": binding["reservationSha256"],
        "stage": "outer-admission-complete",
    }

    def mark_cancel(_number, _frame):
        nonlocal interrupted
        interrupted = True

    try:
        # Preserve the baseline's separate local session. A terminal signal is
        # handled here as a retention request, not forwarded to Windows work.
        for number in (signal.SIGINT, signal.SIGTERM):
            old_handlers[number] = signal.signal(number, mark_cancel)
        if interrupted or binding["cancelPath"].exists():
            raise InterruptedError("Cancellation before controller creation")
        if time.monotonic() >= controller_deadline:
            raise TimeoutError("Original outer controller deadline expired")
        result["launchAttempted"] = True
        result["proxyState"] = "creation-outcome-unknown"
        process = subprocess.Popen(
            binding["exactControllerCommand"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        result["proxyState"] = "observing"
        result["stage"] = "original-controller"
        while True:
            if interrupted or binding["cancelPath"].exists():
                raise InterruptedError("Final publish observation cancelled")
            now = time.monotonic()
            if now >= controller_deadline:
                raise TimeoutError("Original outer controller deadline expired")
            code = process.poll()
            if code is not None:
                result["proxyExitCode"] = code
                result["proxyState"] = "exited"
                if code != 0:
                    raise RuntimeError("Original controller/proxy failed")
                break
            time.sleep(min(0.05, max(0.0, controller_deadline - now)))

        # Even zero proxy exit cannot establish Windows quiescence or success.
        result["stage"] = "original-completion-validation"
        proof = _assert_exact_original_completion(binding, result["proxyExitCode"])
        if proof["quiescent"] is not True or proof["normalCompletion"] is not True:
            raise RuntimeError("Original Windows normal completion is unestablished")
        result["quiescent"] = True
        result["lastJobActive"] = proof["lastJobActive"]
        result["lastJobTotal"] = proof["lastJobTotal"]
        if interrupted or binding["cancelPath"].exists():
            raise InterruptedError("Cancellation at final outer observation")
        if time.monotonic() >= controller_deadline:
            raise TimeoutError("Original outer completion arrived after the deadline")
        result["normalCompletion"] = True
        result["safetyStop"] = False
        result["stage"] = "normal-observed-awaiting-artifact-acceptance"
    except BaseException as error:
        # A later proxy exit or zero count never resets this failure latch.
        result["normalCompletion"] = False
        result["safetyStop"] = True
        result["failureType"] = type(error).__name__
    finally:
        if not result["normalCompletion"]:
            # At most ten seconds of passive emergency observation. There is no
            # old windows_wait call, emergency PowerShell launch or process scan.
            emergency_end = min(controller_deadline + 10.0, time.monotonic() + 10.0)
            try:
                result["retentionCancelMarker"] = _request_retention_cancel(binding["cancelPath"])
            except BaseException as error:
                result["cancelMarkerFailureType"] = type(error).__name__
            if process is not None:
                while time.monotonic() < emergency_end:
                    try:
                        code = process.poll()
                        if code is not None:
                            result["proxyExitCode"] = code
                            result["proxyState"] = "exited-after-failure"
                            break
                        remaining = max(0.0, emergency_end - time.monotonic())
                        if remaining > 0.0:
                            time.sleep(min(0.05, remaining))
                    except BaseException as error:
                        result["emergencyObservationFailureType"] = type(error).__name__
                        break
                if result["proxyExitCode"] is None:
                    result["proxyState"] = "retained-live-or-unknown"
                    _retained_proxies.append(process)
        result["retainedLiveWorkOrUnknown"] = not result["quiescent"]
        # Independent artifact acceptance and any later action require their own
        # concrete admission. No result from this source authorizes continuation.
        result["artifactEligible"] = False
        result["continuation_allowed"] = False
        result["outerSeconds"] = round(time.monotonic() - began, 3)
        result["utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # Fixed controller-owned record only. No recursive evidence collection,
        # subject-artifact read or mutation of the durable reservation follows.
        try:
            _write_new_json(binding["outerResultPath"], result)
        finally:
            for number, handler in old_handlers.items():
                signal.signal(number, handler)
    return result


if __name__ == "__main__":
    raise RuntimeError("UNBOUND: no admitted CLI route or Windows bootstrap")
