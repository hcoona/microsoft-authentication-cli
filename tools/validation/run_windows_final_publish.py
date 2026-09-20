"""Final-publication collector; requires a separately accepted fixed literal."""

DRAFT_ONLY = False
if DRAFT_ONLY:
    raise RuntimeError('DRAFT_ONLY: final publish has no accepted execution binding')

import datetime
import signal
import subprocess
import time
from final_publish_contracts import admitted_reservation, budget, compact, exchange_clock, original_completion, write_new

_retained_proxies = []


def _assert_exact_admission(deadline, began, cancelled, *, reviewed_authority):
    return admitted_reservation(deadline, began, cancelled,
                                reviewed_authority=reviewed_authority)


def _assert_exact_original_completion(binding, original_proxy_exit, deadline, cancelled):
    return original_completion(binding, original_proxy_exit, deadline, cancelled)


def _write_new_json(path, value):
    write_new(path, compact(value))


def _request_retention_cancel(path):
    # This marker stops observation and retains possibly executed Windows work.
    # It never addresses the historical controller's termination protocol.
    try:
        write_new(path, b'')
    except FileExistsError:
        return 'already-present'
    return 'created'


def invoke_final_publish_candidate(*, reviewed_authority):
    if DRAFT_ONLY:
        raise RuntimeError('DRAFT_ONLY: no final-publish launch')
    began = time.monotonic()
    deadline = began + 700.0
    interrupted = False
    old_handlers = {}
    result = {'schema': 'final-publish-wsl-result-v1', 'normalCompletion': False,
              'safetyStop': True, 'quiescent': False, 'artifactEligible': False,
              'continuation_allowed': False, 'retainedLiveWorkOrUnknown': True,
              'launchAttempted': False, 'proxyExitCode': None, 'proxyState': 'not-created',
              'jobTerminationRequested': False, 'proxyTerminationRequested': False,
              'reservationSha256': None, 'stage': 'outer-admission'}

    def mark_cancel(_number, _frame):
        nonlocal interrupted
        interrupted = True

    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            old_handlers[number] = signal.signal(number, mark_cancel)
        # Admission, durable capacity, source checks, launch, collection and the
        # entire emergency path share this original 700-second absolute ceiling.
        # The original shared action lock stays held until final receipt writing.
        with _assert_exact_admission(deadline, began, lambda: interrupted,
                                     reviewed_authority=reviewed_authority) as binding:
            process = None
            result['reservationSha256'] = binding['reservationSha256']
            try:
                budget(deadline, lambda: interrupted)
                if binding['cancelPath'].exists():
                    raise InterruptedError('Cancellation before controller creation')
                result['launchAttempted'] = True
                result['proxyState'] = 'creation-outcome-unknown'
                process = subprocess.Popen(binding['exactControllerCommand'], stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           start_new_session=True)
                result['proxyState'] = 'observing'
                result['stage'] = 'original-controller'
                exchange_clock(binding, process, deadline, lambda: interrupted)
                while True:
                    left = budget(deadline, lambda: interrupted)
                    if binding['cancelPath'].exists():
                        raise InterruptedError('Final publication observation cancelled')
                    code = process.poll()
                    if code is not None:
                        result['proxyExitCode'] = code
                        result['proxyState'] = 'exited'
                        if code != 0:
                            raise RuntimeError('Original bootstrap/proxy failed')
                        break
                    time.sleep(min(0.05, left))
                result['stage'] = 'original-completion-validation'
                proof = _assert_exact_original_completion(binding, result['proxyExitCode'], deadline, lambda: interrupted)
                result['quiescent'] = proof['quiescent']
                result['lastJobActive'] = proof['lastJobActive']
                result['lastJobTotal'] = proof['lastJobTotal']
                budget(deadline, lambda: interrupted)
                if binding['cancelPath'].exists():
                    raise InterruptedError('Cancellation at final outer observation')
                result['normalCompletion'] = True
                result['safetyStop'] = False
                result['stage'] = 'normal-observed-awaiting-artifact-acceptance'
            except BaseException as error:
                result['normalCompletion'] = False
                result['safetyStop'] = True
                result['failureType'] = type(error).__name__
            finally:
                if not result['normalCompletion']:
                    emergency_end = min(deadline, time.monotonic() + 10.0)
                    try:
                        result['retentionCancelMarker'] = _request_retention_cancel(binding['cancelPath'])
                    except BaseException as error:
                        result['cancelMarkerFailureType'] = type(error).__name__
                    if process is not None:
                        while time.monotonic() < emergency_end:
                            try:
                                code = process.poll()
                                if code is not None:
                                    result['proxyExitCode'] = code
                                    result['proxyState'] = 'exited-after-failure'
                                    break
                                time.sleep(min(0.05, max(0.0, emergency_end - time.monotonic())))
                            except BaseException as error:
                                result['emergencyObservationFailureType'] = type(error).__name__
                                break
                        if result['proxyExitCode'] is None:
                            result['proxyState'] = 'retained-live-or-unknown'
                            _retained_proxies.append(process)
                result['retainedLiveWorkOrUnknown'] = not result['quiescent']
                result['artifactEligible'] = False
                result['continuation_allowed'] = False
                result['outerSeconds'] = round(time.monotonic() - began, 3)
                result['utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                _write_new_json(binding['outerResultPath'], result)
                if result['normalCompletion']:
                    # Durable write/fsync may return late. Preserve that original
                    # receipt, but fail this same invocation before it can return.
                    if binding['cancelPath'].exists():
                        raise InterruptedError('Cancellation during final receipt persistence')
                    budget(deadline, lambda: interrupted)
    finally:
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
    if result['normalCompletion']:
        # Includes original shared-lock release and signal-context finalization.
        # A completed-looking receipt cannot accept an unsuccessful invocation.
        if binding['cancelPath'].exists():
            raise InterruptedError('Cancellation during final outer context finalization')
        budget(deadline, lambda: interrupted)
    return result


if __name__ == '__main__':
    raise RuntimeError('UNBOUND: no independently admitted launcher entry point')
