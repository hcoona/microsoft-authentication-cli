"""Fixed same-process publisher checks for separately admitted clock action 0108.

This fixture evaluates only the five reviewed function spans. It never imports
the complete publication contracts or changes their entry guard.
"""

import ast
import errno
import hashlib
import os
from pathlib import Path
import time


FUNCTIONS = ('fail', 'budget', 'direct', 'write_new', 'publish_clock_reply')
CASES = ('partial-pending', 'pending-collision', 'final-collision', 'link-failure',
         'cancelled', 'expired', 'post-link-sync-failure')
PAYLOAD = b'{"fixedClockFixture":true}\n'
SENTINEL = b'fixed-clock-collision-sentinel\n'


def publisher_namespace(raw, pin):
    if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
        raise ValueError('Clock publisher source changed')
    raw.decode('ascii')
    if set(pin['spans']) != set(FUNCTIONS):
        raise ValueError('Unexpected publisher extraction set')
    nodes = []
    for name in FUNCTIONS:
        span = pin['spans'][name]
        if type(span['offset']) is not int or type(span['bytes']) is not int or \
                span['offset'] < 0 or span['bytes'] < 1 or span['offset'] + span['bytes'] > len(raw):
            raise ValueError('Publisher extraction offset bound')
        body = raw[span['offset']:span['offset'] + span['bytes']]
        if hashlib.sha256(body).hexdigest() != span['sha256']:
            raise ValueError('Publisher extraction hash changed')
        module = ast.parse(body.decode('ascii'))
        if len(module.body) != 1 or not isinstance(module.body[0], ast.FunctionDef) or module.body[0].name != name:
            raise ValueError('Publisher extraction is not one expected function')
        nodes.append(module.body[0])
    namespace = {'os': os, 'Path': Path, 'time': time}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<fixed-clock-publisher>', 'exec'), namespace)
    return namespace


class FixedFaultOs:
    """Per-case OS seam; no global monkey patch or change to candidate text."""

    def __init__(self, case, directory):
        self.case = case
        self.directory = directory
        self.link_calls = 0
        self.sync_calls = 0
        self.write_calls = 0
        self.partial_final_absent = False
        self.injected_error = None

    def __getattr__(self, name):
        return getattr(os, name)

    def write(self, fd, data):
        self.write_calls += 1
        if self.case == 'partial-pending' and self.write_calls == 1:
            count = os.write(fd, data[:len(data) // 2])
            self.partial_final_absent = not (self.directory / 'clock-remaining.json').exists()
            if not self.partial_final_absent or (self.directory / 'clock-remaining.json.pending').read_bytes() != data[:count]:
                raise AssertionError('Final reply exposed while pending writer was partial')
            return count
        return os.write(fd, data)

    def link(self, source, destination, *, follow_symlinks):
        self.link_calls += 1
        if self.link_calls != 1:
            raise AssertionError('Publisher retried link')
        if Path(source).read_bytes() != PAYLOAD:
            raise AssertionError('Pending reply incomplete at publication')
        if self.case == 'link-failure':
            self.injected_error = OSError(errno.EOPNOTSUPP, 'Fixed injected link failure')
            raise self.injected_error
        return os.link(source, destination, follow_symlinks=follow_symlinks)

    def fsync(self, fd):
        self.sync_calls += 1
        if self.case == 'post-link-sync-failure' and self.sync_calls == 3:
            self.injected_error = OSError(errno.EIO, 'Fixed injected publication sync failure')
            raise self.injected_error
        return os.fsync(fd)


def run_producer_cases(parent, namespace, original_deadline):
    results = []
    for case in CASES:
        if time.monotonic() >= original_deadline:
            raise TimeoutError('Original clock-fixture deadline expired')
        directory = parent / ('producer-' + case)
        directory.mkdir(mode=0o700)
        pending = directory / 'clock-remaining.json.pending'
        final = directory / 'clock-remaining.json'
        if case in ('pending-collision', 'final-collision'):
            namespace['write_new'](pending if case == 'pending-collision' else final,
                                   SENTINEL, deadline=original_deadline)
        seam = FixedFaultOs(case, directory)
        namespace['os'] = seam
        expected = {'pending-collision': FileExistsError, 'final-collision': FileExistsError,
                    'link-failure': OSError, 'cancelled': InterruptedError, 'expired': TimeoutError,
                    'post-link-sync-failure': OSError}.get(case)
        caught = None
        try:
            deadline = time.monotonic() - 1 if case == 'expired' else min(original_deadline, time.monotonic() + 10)
            namespace['publish_clock_reply'](directory, PAYLOAD, deadline, lambda: case == 'cancelled')
        except (OSError, ValueError, AssertionError) as error:
            caught = error
        finally:
            namespace['os'] = os
        if expected is None and caught is not None or expected is not None and not isinstance(caught, expected):
            raise AssertionError('Unexpected fixed producer outcome')
        if case in ('link-failure', 'post-link-sync-failure'):
            required_syncs = 2 if case == 'link-failure' else 3
            if seam.injected_error is None or caught is not seam.injected_error or \
                    seam.link_calls != 1 or seam.sync_calls != required_syncs:
                raise AssertionError('Intended publication fault was not the observed failure')
        if case in ('cancelled', 'expired'):
            if pending.exists() or final.exists() or seam.link_calls:
                raise AssertionError('Expired or cancelled publication wrote output')
        elif case == 'pending-collision':
            if pending.read_bytes() != SENTINEL or final.exists() or seam.link_calls:
                raise AssertionError('Pending collision changed existing bytes')
        elif case == 'final-collision':
            if final.read_bytes() != SENTINEL or pending.read_bytes() != PAYLOAD or seam.link_calls != 1:
                raise AssertionError('Final collision overwrote or retried')
        elif case == 'link-failure':
            if final.exists() or pending.read_bytes() != PAYLOAD or seam.link_calls != 1:
                raise AssertionError('Link failure retried or lost pending evidence')
        else:
            left, right = pending.stat(), final.stat()
            if pending.read_bytes() != PAYLOAD or final.read_bytes() != PAYLOAD or \
                    (left.st_dev, left.st_ino) != (right.st_dev, right.st_ino) or left.st_nlink != 2 or right.st_nlink != 2:
                raise AssertionError('Complete retained reply aliases disagree')
            if case == 'partial-pending' and not seam.partial_final_absent:
                raise AssertionError('Missing partial visibility observation')
        results.append({'case': case, 'passed': True, 'injected': True,
                        'exceptionType': None if caught is None else type(caught).__name__,
                        'linkCalls': seam.link_calls, 'syncCalls': seam.sync_calls,
                        'writeCalls': seam.write_calls, 'partialFinalAbsent': seam.partial_final_absent,
                        'injectionFired': seam.injected_error is not None,
                        'injectionMatched': seam.injected_error is not None and caught is seam.injected_error})
    return results
