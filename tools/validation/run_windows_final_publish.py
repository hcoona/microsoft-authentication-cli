"""Final-publication collector; requires a separately accepted fixed literal."""

DRAFT_ONLY = False
if DRAFT_ONLY:
    raise RuntimeError('DRAFT_ONLY: final publish has no accepted execution binding')

import datetime
import os
import selectors
import signal
import subprocess
import time
from final_publish_contracts import LIMITS, admitted_reservation, budget, compact, exchange_clock, original_completion, publication_failure_diagnostic, write_new

_retained_proxies = []


def _assert_exact_admission(deadline, began, cancelled, *, reviewed_authority, diagnostic):
    return admitted_reservation(deadline, began, cancelled,
                                reviewed_authority=reviewed_authority, diagnostic=diagnostic)


def _assert_exact_original_completion(binding, original_proxy_exit, deadline, cancelled):
    return original_completion(binding, original_proxy_exit, deadline, cancelled)


def _write_new_json(path, value, deadline):
    write_new(path, compact(value), deadline=deadline)


def _request_retention_cancel(path, deadline):
    # This marker stops observation and retains possibly executed Windows work.
    # It never addresses the historical controller's termination protocol.
    try:
        write_new(path, b'', deadline=deadline)
    except FileExistsError:
        return 'already-present'
    return 'created'


class _NativeTransport:
    """Bound original launcher transport without confusing it with compiler capture."""

    def __init__(self, process):
        self.selector = selectors.DefaultSelector()
        self.parts = {'stdout': bytearray(), 'stderr': bytearray()}
        self.eof = set()
        self.failed = False
        self.streams = (process.stdout, process.stderr)
        try:
            for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(stream.fileno(), False)
                self.selector.register(stream, selectors.EVENT_READ, name)
        except BaseException:
            self.close()
            raise

    def drain(self):
        if self.failed:
            return
        try:
            for key, _events in self.selector.select(0):
                remaining = 16384 - sum(map(len, self.parts.values()))
                chunk = os.read(key.fileobj.fileno(), min(4096, remaining + 1))
                if not chunk:
                    self.eof.add(key.data)
                    self.selector.unregister(key.fileobj)
                elif len(chunk) > remaining:
                    self.parts[key.data].extend(chunk[:remaining])
                    raise RuntimeError('Original native transport exceeded 16384 bytes')
                else:
                    self.parts[key.data].extend(chunk)
        except BlockingIOError:
            return
        except BaseException:
            self.failed = True
            raise

    def persist(self, binding, result, deadline):
        for name in ('stdout', 'stderr'):
            budget(deadline, lambda: False)
            raw = bytes(self.parts[name])
            write_new(binding['local'] / ('launcher-transport-' + name + '.bin'), raw, deadline=deadline)
            budget(deadline, lambda: False)
            result[name + 'TransportBytes'] = len(raw)
            result[name + 'TransportEof'] = name in self.eof
        result['transportFailed'] = self.failed

    def close(self):
        failure = None
        for owned in (self.selector, *self.streams):
            try:
                owned.close()
            except BaseException as error:
                failure = failure or error
        if failure is not None:
            raise failure


def invoke_final_publish_candidate(*, reviewed_authority, diagnostic):
    if DRAFT_ONLY:
        raise RuntimeError('DRAFT_ONLY: no final-publish launch')
    if type(diagnostic) is not dict or diagnostic:
        raise ValueError('A fresh empty diagnostic carrier is required')
    diagnostic.update(phase='outer-admission', launchAttempted=False,
                      failurePhase=None, failureCode=None)
    began = time.monotonic()
    deadline = began + LIMITS['outerMilliseconds'] / 1000
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
        # entire emergency path share this original 2400-second absolute ceiling.
        # The original shared action lock stays held until final receipt writing.
        with _assert_exact_admission(deadline, began, lambda: interrupted,
                                     reviewed_authority=reviewed_authority,
                                     diagnostic=diagnostic) as binding:
            process = None
            transport = None
            result['reservationSha256'] = binding['reservationSha256']
            try:
                diagnostic['phase'] = 'prelaunch-budget-check'
                budget(deadline, lambda: interrupted)
                if binding['cancelPath'].exists():
                    raise InterruptedError('Cancellation before controller creation')
                if budget(deadline, lambda: interrupted) * 1000 < LIMITS['nativeSpawnReserveMilliseconds']:
                    raise TimeoutError('Insufficient original time for native launcher and final collection')
                result['launchAttempted'] = True
                diagnostic['phase'] = 'native-launch-attempt'
                diagnostic['launchAttempted'] = True
                result['proxyState'] = 'creation-outcome-unknown'
                process = subprocess.Popen(binding['exactControllerCommand'], stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=True)
                diagnostic['phase'] = 'transport-initialization'
                transport = _NativeTransport(process)
                result['proxyState'] = 'observing'
                result['stage'] = 'original-controller'
                diagnostic['phase'] = 'clock-exchange'
                exchange_clock(binding, process, deadline, lambda: interrupted)
                diagnostic['phase'] = 'native-observation'
                while True:
                    left = budget(deadline, lambda: interrupted)
                    if binding['cancelPath'].exists():
                        raise InterruptedError('Final publication observation cancelled')
                    transport.drain()
                    code = process.poll()
                    if code is not None and transport.eof == {'stdout', 'stderr'}:
                        result['proxyExitCode'] = code
                        result['proxyState'] = 'exited'
                        if code != 0:
                            raise RuntimeError('Original bootstrap/proxy failed')
                        break
                    time.sleep(min(0.05, left))
                result['stage'] = 'original-completion-validation'
                diagnostic['phase'] = 'completion-validation'
                proof = _assert_exact_original_completion(binding, result['proxyExitCode'], deadline, lambda: interrupted)
                result['quiescent'] = proof['quiescent']
                result['lastJobActive'] = proof['lastJobActive']
                result['lastJobTotal'] = proof['lastJobTotal']
                for name in ('outerJobName', 'outerJobActive', 'outerJobTotal', 'outerJournalSha256'):
                    result[name] = proof[name]
                budget(deadline, lambda: interrupted)
                if binding['cancelPath'].exists():
                    raise InterruptedError('Cancellation at final outer observation')
                result['normalCompletion'] = True
                result['safetyStop'] = False
                result['stage'] = 'normal-observed-awaiting-artifact-acceptance'
            except BaseException as error:
                publication_failure_diagnostic(diagnostic, error)
                result['normalCompletion'] = False
                result['safetyStop'] = True
                result['failureType'] = type(error).__name__
            finally:
                diagnostic['phase'] = 'failure-retention'
                if not result['normalCompletion']:
                    emergency_end = min(deadline, time.monotonic() + 10.0)
                    try:
                        budget(emergency_end, lambda: False)
                        result['retentionCancelMarker'] = _request_retention_cancel(binding['cancelPath'], emergency_end)
                        budget(emergency_end, lambda: False)
                    except BaseException as error:
                        result['cancelMarkerFailureType'] = type(error).__name__
                    if process is not None:
                        while time.monotonic() < emergency_end:
                            try:
                                if transport is not None:
                                    transport.drain()
                                code = process.poll()
                                if code is not None and (transport is None or transport.eof == {'stdout', 'stderr'}):
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
                if transport is not None:
                    try:
                        diagnostic['phase'] = 'transport-persistence'
                        transport.persist(binding, result, deadline)
                    except BaseException as error:
                        publication_failure_diagnostic(diagnostic, error)
                        result['normalCompletion'] = False
                        result['safetyStop'] = True
                        result['transportPersistenceFailureType'] = type(error).__name__
                    finally:
                        diagnostic['phase'] = 'transport-close'
                        transport.close()
                result['retainedLiveWorkOrUnknown'] = not result['quiescent']
                result['artifactEligible'] = False
                result['continuation_allowed'] = False
                result['outerSeconds'] = round(time.monotonic() - began, 3)
                result['utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                diagnostic['phase'] = 'result-persistence'
                result['diagnostic'] = dict(diagnostic)
                budget(deadline, lambda: False)
                _write_new_json(binding['outerResultPath'], result, deadline)
                if result['normalCompletion']:
                    # Durable write/fsync may return late. Preserve that original
                    # receipt, but fail this same invocation before it can return.
                    if binding['cancelPath'].exists():
                        raise InterruptedError('Cancellation during final receipt persistence')
                    budget(deadline, lambda: interrupted)
                diagnostic['phase'] = 'context-finalization'
    except BaseException as error:
        publication_failure_diagnostic(diagnostic, error)
        raise
    finally:
        diagnostic['phase'] = 'signal-context-finalization'
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
    if result['normalCompletion']:
        diagnostic['phase'] = 'outer-finalization'
        # Includes original shared-lock release and signal-context finalization.
        # A completed-looking receipt cannot accept an unsuccessful invocation.
        if binding['cancelPath'].exists():
            raise InterruptedError('Cancellation during final outer context finalization')
        budget(deadline, lambda: interrupted)
    return result


if __name__ == '__main__':
    raise RuntimeError('UNBOUND: no independently admitted launcher entry point')
