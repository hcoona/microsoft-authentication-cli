"""One charged, independently admitted offline validation of real guard predicates."""

import base64
import contextlib
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
from types import MappingProxyType

OUTPUT = Path('/tmp/windows-final-guard-successor-fixture-0055-v1')
ADMISSION = Path('/tmp/windows-final-guard-0055-authority-inputs/fixture-admission.json')
LIMITS = {'milliseconds': 30000, 'cases': 24, 'validatorCalls': 72,
          'inputBytes': 8388608, 'outputBytes': 65536, 'invocations': 1}
CASES = {
    'failed-linux': None, 'failed-windows': None, 'failed-dispatcher': None,
    'success-linux': None, 'success-windows': None, 'success-dispatcher': None,
    'capacity119-plus-fixture': None,
    'capacity120-plus-fixture': 'Combined capacity including singleton fixture exceeded',
    'changed-content': 'Guard input hash changed',
    'changed-descriptor': 'Fixed final guard value changed',
    'unaccepted-disposition': 'Fixed final guard value changed',
    'false-flag': 'Failed0054 receipt pair or caller objects changed',
    'marker': 'Previously absent failed0054 path appeared',
    'linked-role': 'Failed0054 metadata role kind changed',
    'metadata-change': 'Fresh guard input metadata/size changed',
    'old-authority': 'Fixed final guard value changed',
    'wrong-action': 'Unallocated, reordered or duplicate guard preparation',
    'duplicate-guard': 'Missing context or duplicate failed0054',
    'third-guard': 'Unallocated, reordered or duplicate guard preparation',
    'intervening-history': 'Exact disposed0054 and unchanged product prefix required',
    'counter-mismatch': 'Exact disposed0054 and unchanged product prefix required',
    'missing-success-review': 'Unexpected fixture byte lookup',
    'invalid-success-completion': 'Fixed final guard value changed',
}


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate fixture field')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite fixture value')))


def bound(item, maximum):
    if type(item) is not dict or set(item) != {'path', 'bytes', 'sha256'} or type(item['bytes']) is not int or not 0 <= item['bytes'] <= maximum:
        raise ValueError('Invalid fixed fixture input descriptor')
    path = Path(item['path'])
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Linked or relative fixture input')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) != item['bytes'] or sha(raw) != item['sha256']:
        raise ValueError('Fixture input bytes changed')
    return raw


def write_new(name, raw, state):
    state['outputBytes'] += len(raw)
    if state['outputBytes'] > LIMITS['outputBytes']:
        raise ValueError('Fixture output ceiling exceeded')
    fd = os.open(OUTPUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:offset + 16384])
            if count <= 0:
                raise OSError('Fixture persistence made no progress')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(state['directoryFd'])


class MemoryIO:
    """Immutable exact lookup sequences, without any original filesystem fallback."""
    def __init__(self, case, state):
        self.files = {}
        for path, observations in case['files'].items():
            entries = []
            for item in observations:
                if set(item) != {'base64', 'before', 'after'}:
                    raise ValueError('Invalid fixture file observation')
                raw = base64.b64decode(item['base64'], validate=True)
                state['inputBytes'] += len(raw)
                if state['inputBytes'] > LIMITS['inputBytes']:
                    raise ValueError('Fixture synthetic input ceiling exceeded')
                entries.append((raw, MappingProxyType(dict(item['before'])), MappingProxyType(dict(item['after']))))
            self.files[path] = tuple(entries)
        self.files = MappingProxyType(self.files)
        self.observations = MappingProxyType({path: tuple(MappingProxyType(dict(item)) for item in items)
                                             for path, items in case['metadata'].items()})
        self.positions = {}
        self.log = []

    def next(self, operation, path, table):
        key = (operation, path)
        index = self.positions.get(key, 0)
        self.log.append([operation, path])
        if path not in table or index >= len(table[path]):
            raise ValueError('Unexpected fixture byte lookup' if operation == 'read' else 'Unexpected fixture metadata lookup')
        self.positions[key] = index + 1
        return table[path][index]

    def read(self, path, size, state):
        raw, before, after = self.next('read', path, self.files)
        return raw, dict(before), dict(after)

    def metadata(self, path):
        return dict(self.next('metadata', path, self.observations))


def main(admission_binding):
    if len(sys.argv) != 1 or not sys.flags.isolated or not sys.dont_write_bytecode or sys.flags.optimize:
        raise ValueError('One isolated, unoptimized, no-bytecode fixture invocation only')
    now = time.monotonic()
    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    if not 0 < remaining <= 30.0 or interval != 0:
        raise ValueError('Original launcher timer must remain active and nonrepeating')
    started = now + remaining - 30.0
    stopped = False
    def stop(_number, _frame):
        nonlocal stopped
        stopped = True
        raise TimeoutError('Original fixture clock or cancellation stopped the singleton')
    for number in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
        signal.signal(number, stop)
    admission_raw = bound(admission_binding, 65536)
    if admission_binding['path'] != str(ADMISSION):
        raise ValueError('Wrong fixture admission path')
    admission = decode(admission_raw)
    if set(admission) != {'schema', 'accepted', 'protocol', 'interpreter', 'harness', 'module', 'recipe',
                          'launcher', 'outputRoot', 'limits', 'buildTestCharge', 'baselineProductCounters'}:
        raise ValueError('Wrong closed fixture admission')
    if (admission['schema'] != 'final-guard-successor-fixture-admission-v1' or admission['accepted'] is not True or
            admission['outputRoot'] != str(OUTPUT) or admission['limits'] != LIMITS or admission['buildTestCharge'] != 1 or
            admission['baselineProductCounters'] != {'linux': 37, 'windows': 48} or
            Path(admission['harness']['path']) != Path(__file__).absolute()):
        raise ValueError('Fixture admission changed')
    if Path(admission['interpreter']['path']) != Path(sys.executable).resolve():
        raise ValueError('Wrong pinned fixture interpreter')
    bound(admission['interpreter'], 16777216)
    bound(admission['harness'], 1048576)
    if Path(admission['launcher']['path']) != Path(sys.argv[0]).absolute():
        raise ValueError('Wrong exact fixture launcher')
    bound(admission['launcher'], 1048576)
    module_raw = bound(admission['module'], 1048576)
    recipe_raw = bound(admission['recipe'], LIMITS['inputBytes'])
    recipe = decode(recipe_raw)
    if set(recipe) != {'schema', 'fixtureOnly', 'cases'} or recipe['schema'] != 'final-guard-successor-fixture-recipe-v1' or recipe['fixtureOnly'] is not True:
        raise ValueError('Wrong closed fixture recipe')
    cases = recipe['cases']
    if type(cases) is not list or [case['name'] for case in cases] != list(CASES) or len(cases) > LIMITS['cases']:
        raise ValueError('Exact named fixture cases required')
    # Creation is exclusive. Any durable start consumes charge1 even on failure.
    OUTPUT.mkdir(mode=0o700)
    parent_fd = os.open(OUTPUT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    state = {'directoryFd': os.open(OUTPUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
             'inputBytes': 0, 'outputBytes': 0, 'calls': 0}
    start = {'schema': 'final-guard-successor-fixture-start-v1', 'fixtureOnly': True,
             'buildTestCharge': 1, 'baselineProductCounters': {'linux': 37, 'windows': 48},
             'admissionSha256': sha(admission_raw), 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    start_raw = encode(start)
    write_new('started.json', start_raw, state)
    journal_fd = os.open(OUTPUT / 'output.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    os.fsync(journal_fd)
    os.fsync(state['directoryFd'])
    journal_parts = []
    def append_event(event):
        raw = encode(event)
        state['outputBytes'] += len(raw)
        if state['outputBytes'] > LIMITS['outputBytes']:
            raise ValueError('Fixture output ceiling exceeded')
        offset = 0
        while offset < len(raw):
            count = os.write(journal_fd, raw[offset:offset + 16384])
            if count <= 0:
                raise OSError('Fixture journal persistence failed')
            offset += count
        os.fsync(journal_fd)
        journal_parts.append(raw)
    importing = True
    allowed_writes = {str(OUTPUT / 'output.jsonl'), str(OUTPUT / 'result.json')}
    def audit(event, args):
        if event == 'open':
            path = args[0]
            if isinstance(path, int):
                return
            path = os.fsdecode(path)
            if path in allowed_writes:
                return
            if importing and path == admission['module']['path']:
                return
            raise PermissionError('Fixture original/unlisted filesystem access is forbidden')
        if event in ('os.listdir', 'os.scandir', 'os.system', 'os.fork', 'os.posix_spawn', 'subprocess.Popen') or event.startswith('socket.'):
            raise PermissionError('Fixture process/network/enumeration access is forbidden')
        if event == 'exec' and (not importing or args[0].co_filename != admission['module']['path']):
            raise PermissionError('Unlisted candidate execution is forbidden')
    sys.addaudithook(audit)
    events = []
    passed = False
    failure = None
    def call(function, *args, **kwargs):
        state['calls'] += 1
        if state['calls'] > LIMITS['validatorCalls'] or time.monotonic() - started >= 30.0:
            raise TimeoutError('Original fixture call/time ceiling exceeded')
        return function(*args, **kwargs)
    try:
        spec = importlib.util.spec_from_file_location('accepted_final_guard_history', admission['module']['path'])
        module = importlib.util.module_from_spec(spec)
        exec(compile(module_raw, admission['module']['path'], 'exec', dont_inherit=True), module.__dict__)
        importing = False
        if module.__file__ != admission['module']['path']:
            raise ValueError('Actual fixture module source path changed')
        # Candidate validators are silent. A print is an unexpected observation.
        class SilentCapture(io.StringIO):
            def write(self, value):
                if value:
                    raise ValueError('Unexpected candidate output')
                return 0
        capture = SilentCapture()
        for case in cases:
            name = case['name']
            expected_error = CASES[name]
            backend = MemoryIO(case, state)
            transaction = module.new_state(backend, deadline=started + 30.0)
            transaction['moduleBinding'] = dict(admission['module'])
            error = None
            projections = []
            with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
                try:
                    if name.startswith('capacity'):
                        product = 119 if name == 'capacity119-plus-fixture' else 120
                        projections.append(call(module.combined_build_test, product, 0))
                    else:
                        call(module.load_context, case['disposition'], case['fixture'], transaction)
                        for entry in case['entries']:
                            projections.append(call(module.validate_history_action, case['consumer'], entry['action'],
                                entry['windowsAction'], entry['started'], entry['result'], transaction,
                                case['successAnchor'], case['readerPaths']))
                        if name in ('intervening-history', 'counter-mismatch'):
                            call(module.successor_reservation, case['totals'], case['starts'], case['count'], transaction)
                        call(module.finish, transaction)
                except ValueError as problem:
                    error = str(problem)
            if capture.tell() or backend.log != case['expectedLookups']:
                raise ValueError('Unexpected fixture output or I/O sequence')
            if (expected_error is None and error is not None) or (expected_error is not None and error != expected_error):
                raise ValueError('Named fixture did not reach its exact expected contract boundary: ' + name)
            if name.startswith('failed-') and projections != [{'kind': 'disposed-failed-0054', 'preparationCharge': 1,
                                                             'artifactAccepted': False, 'continuation_allowed': False}]:
                raise ValueError('Failed history exposed an artifact or incorrect charge')
            if name.startswith('success-') and (len(projections) != 2 or projections[1].get('actionNumber') != '0055'):
                raise ValueError('Successful fixture lacks full0055 projection')
            event = {'case': name, 'passed': True, 'expectedError': error,
                     'lookups': len(backend.log), 'fixtureOnly': True}
            append_event(event)
            events.append(event)
        passed = True
    except BaseException as problem:
        importing = False
        if stopped:
            raise
        failure = {'failureType': type(problem).__name__, 'message': str(problem)[:1024]}
    if failure is not None:
        append_event(failure)
    os.fsync(journal_fd)
    os.close(journal_fd)
    output = b''.join(journal_parts)
    result = {'schema': 'final-guard-successor-fixture-result-v1', 'fixtureOnly': True,
              'startSha256': sha(start_raw), 'outputSha256': sha(output), 'buildTestCharge': 1,
              'passed': passed, 'normalCompletion': passed, 'cases': len(events),
              'validatorCalls': state['calls'], 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    write_new('result.json', encode(result), state)
    os.close(state['directoryFd'])
    result_raw = encode(result)
    state['outputBytes'] += len(result_raw)
    if state['outputBytes'] > LIMITS['outputBytes']:
        raise ValueError('Fixture stdout ceiling exceeded')
    print(result_raw.decode('ascii'), end='', flush=True)
    signal.setitimer(signal.ITIMER_REAL, 0)
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    raise RuntimeError('UNBOUND: use the independently pinned literal fixture launcher')
