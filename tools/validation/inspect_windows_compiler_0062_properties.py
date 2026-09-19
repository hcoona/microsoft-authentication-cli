"""Inactive, single-admission projection of one fixed retained JSON observation.

Source preparation only. Do not import or execute before exact admission.
This is not a binlog parser or a replacement stage-2 semantic selector.
"""

ACTIVE = False
if not ACTIVE:
    raise RuntimeError('Inactive: exact property-inspection admission is required')

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

INPUT_ROOT = Path('/tmp/windows-compiler-0062-success-evidence-stage2-root-v1')
INPUT_FILE = 'observations.json'
INPUT_BYTES = 10363238
INPUT_SHA = '8d575cde880fbb6b981898cdfbda4869f91cdb4a8a3283eb98413d05064104d6'
OUTPUT_ROOT = Path('/tmp/windows-compiler-0062-stage2-property-inspection-root-v1')
FAILURE_TRANSPORT = {
    'bytes': 5551,
    'sha256': '3c556b4bc33718b8c857eecb64a0ce0f0d8dc914803e1f8d690cc21e55e74e40',
}
PROPERTIES = ('TargetFramework', 'RuntimeIdentifier', 'Configuration')
CHUNK = 65536
LIMITS = {
    'requestedBytes': 67112960,
    'returnedBytes': 67108864,
    'inputReturnedBytes': 20971520,
    'inputPasses': 2,
    'outputBytes': 131072,
    'outputRequestedBytes': 131072,
    'ioCalls': 4096,
    'pathOperations': 1024,
    'readCalls': 4096,
    'writeCalls': 16,
    'closes': 16,
    'outputFiles': 4,
    'accountedRetainedBytes': 1073741824,
}
OUTPUT_LIMITS = {
    'started.json': 4096,
    'property-projection.json': 65536,
    'complete.json': 8192,
    'failure.json': 8192,
}
FALSE_CLAIMS = {
    'semanticAcceptance': False,
    'graphAccepted': False,
    'artifactAccepted': False,
    'continuation_allowed': False,
}


class Rejected(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__('Bounded property inspection rejected')


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


class Budget:
    def __init__(self, began):
        self.deadline = began + 300_000_000_000
        self.cancelled = False
        self.finalizing = False
        self.stage = 'admission'
        self.counts = dict.fromkeys(LIMITS, 0)
        # Fixed I/O, source, encoder and transient scratch allowance; JSON
        # character storage and token containers are charged before parsing.
        # This is a conservative accounting model, not a measured RSS claim.
        self.counts['accountedRetainedBytes'] = 100663296

    def check(self):
        require(time.monotonic_ns() < self.deadline, 'deadline')
        require(self.finalizing or not self.cancelled, 'cancelled')

    def reserve(self, **increments):
        self.check()
        for name, amount in increments.items():
            require(type(amount) is int and amount >= 0 and
                    self.counts[name] + amount <= LIMITS[name], 'limit-' + name)
        for name, amount in increments.items():
            self.counts[name] += amount

    def returned(self, size, is_input):
        # Charge every completed read before a post-read deadline rejection.
        self.counts['returnedBytes'] += size
        if is_input:
            self.counts['inputReturnedBytes'] += size
        require(self.counts['returnedBytes'] <= LIMITS['returnedBytes'],
                'limit-returnedBytes')
        require(self.counts['inputReturnedBytes'] <= LIMITS['inputReturnedBytes'],
                'limit-inputReturnedBytes')
        self.check()

    def written(self, size):
        self.counts['outputBytes'] += size
        require(self.counts['outputBytes'] <= LIMITS['outputBytes'],
                'limit-outputBytes')
        self.check()


def bounded_json(value, maximum, budget):
    pieces = []
    size = 0
    encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True,
                               separators=(',', ':'), allow_nan=False)
    for piece in encoder.iterencode(value):
        budget.check()
        raw = piece.encode('ascii')
        size += len(raw)
        require(size + 1 <= maximum, 'json-output-bound')
        pieces.append(raw)
    return b''.join(pieces) + b'\n'


def read_json(raw, maximum, budget):
    require(len(raw) <= maximum, 'json-input-bound')
    quoted = False
    escaped = False
    depth = 0
    tokens = 0
    string_bytes = 0
    collection_commas = []
    for index, byte in enumerate(raw):
        if index % 65536 == 0:
            budget.check()
        if quoted:
            string_bytes += 1
            require(string_bytes <= 8388608, 'json-string-bound')
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
            string_bytes = 0
            tokens += 1
        elif byte in (91, 123):
            depth += 1
            collection_commas.append(0)
            tokens += 1
            require(depth <= 32, 'json-nesting-bound')
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, 'json-unbalanced')
            collection_commas.pop()
        elif byte == 44:
            tokens += 1
            require(bool(collection_commas), 'json-comma-outside-container')
            collection_commas[-1] += 1
            require(collection_commas[-1] < 65536, 'json-collection-bound')
        require(tokens <= 2097152, 'json-token-bound')
    require(not quoted and depth == 0, 'json-unbalanced')
    budget.reserve(accountedRetainedBytes=4 * len(raw) + 384 * tokens)

    def pairs(rows):
        budget.check()
        result = {}
        for name, value in rows:
            require(name not in result, 'duplicate-json-key')
            result[name] = value
        return result

    def nonfinite(_text):
        raise Rejected('nonfinite-json')

    value = json.loads(raw.decode('ascii', errors='strict'),
                       object_pairs_hook=pairs, parse_constant=nonfinite)
    budget.check()
    return value


def hex_string(value, count=64):
    return (type(value) is str and len(value) == count and
            all(character in '0123456789abcdef' for character in value))


def descriptor(value, maximum):
    require(type(value) is dict and set(value) == {'bytes', 'sha256'} and
            type(value['bytes']) is int and 0 < value['bytes'] <= maximum and
            hex_string(value['sha256']), 'descriptor-shape')


def admission(budget):
    require(len(sys.argv) == 3, 'argument-count')
    expected, text = sys.argv[1:]
    require(hex_string(expected) and len(text) <= 16384, 'data-bound')
    raw = text.encode('ascii')
    require(sha(raw) == expected, 'data-sha')
    data = read_json(raw, 16384, budget)
    require(type(data) is dict and set(data) == {
        'schema', 'action', 'ordinal', 'oneInvocation', 'acceptedTarget',
        'inactiveSourceSha256', 'sourceSha256', 'runtimeReview',
        'stage2FailureAcceptance', 'stage2OriginalTransport', 'input', 'outputRoot',
    } and bounded_json(data, 16384, budget) == raw, 'data-shape')
    require(data['schema'] == 'compiler-0062-property-inspection-admission-v1' and
            data['action'] == '0062' and type(data['ordinal']) is int and
            data['ordinal'] == 1 and data['oneInvocation'] is True, 'data-identity')
    target = data['acceptedTarget']
    require(type(target) is dict and set(target) ==
            {'commit', 'tree', 'protocolSha256', 'waveSha256'}, 'target-shape')
    for name, size in (('commit', 40), ('tree', 40), ('protocolSha256', 64),
                       ('waveSha256', 64)):
        require(hex_string(target[name], size), 'target-pin')
    for name in ('inactiveSourceSha256', 'sourceSha256'):
        require(hex_string(data[name]), 'source-pin')
    for name in ('runtimeReview', 'stage2FailureAcceptance'):
        descriptor(data[name], 1048576)
    descriptor(data['stage2OriginalTransport'], 32768)
    descriptor(data['input'], 10485760)
    require(data['stage2OriginalTransport'] == FAILURE_TRANSPORT and
            data['input'] == {'bytes': INPUT_BYTES, 'sha256': INPUT_SHA} and
            data['outputRoot'] == str(OUTPUT_ROOT), 'fixed-evidence-binding')
    budget.check()
    return data, expected


class FixedIO:
    def __init__(self, budget):
        self.b = budget
        self.held = []
        self.directories = []
        self.source = None
        self.output = None
        self.output_parent = None
        self.outputs = []
        self.input_failed = False

    def op(self, function, *arguments, **keywords):
        self.b.reserve(ioCalls=1, pathOperations=1)
        result = function(*arguments, **keywords)
        self.b.check()
        return result

    def opened(self, name, flags, parent=None, mode=0o600):
        require(len(self.held) < 16, 'descriptor-count-bound')
        self.b.reserve(ioCalls=1, pathOperations=1)
        fd = os.open(name, flags, mode, dir_fd=parent)
        self.held.append(fd)
        self.b.check()
        return fd

    def held_id(self, fd):
        return identity(self.op(os.fstat, fd))

    def named_id(self, parent, leaf):
        return identity(self.op(os.stat, leaf, dir_fd=parent, follow_symlinks=False))

    def directory(self, path):
        require(path.is_absolute() and '..' not in path.parts, 'directory-path')
        fd = self.opened('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        before = self.held_id(fd)
        require(stat.S_ISDIR(before[2]), 'directory-type')
        self.directories.append([None, None, fd, before])
        for leaf in path.parts[1:]:
            before = self.named_id(fd, leaf)
            require(stat.S_ISDIR(before[2]), 'directory-type')
            new = self.opened(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, fd)
            require(self.held_id(new) == before, 'directory-open-identity')
            self.directories.append([fd, leaf, new, before])
            fd = new
        return self.directories[-1]

    def continuous(self, component):
        parent, leaf, fd, before = component
        require(self.held_id(fd) == before, 'directory-held-identity')
        if parent is not None:
            require(self.named_id(parent, leaf) == before, 'directory-named-identity')

    def own_mutation(self, component):
        parent, leaf, fd, before = component
        after = self.held_id(fd)
        require(after[:3] == before[:3], 'owned-directory-identity')
        if parent is not None:
            require(self.named_id(parent, leaf) == after, 'owned-directory-named')
        component[3] = after

    def prepare_output(self):
        self.output_parent = self.directory(OUTPUT_ROOT.parent)
        parent = self.output_parent[2]
        self.op(os.mkdir, OUTPUT_ROOT.name, mode=0o700, dir_fd=parent)
        self.own_mutation(self.output_parent)
        fd = self.opened(OUTPUT_ROOT.name,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, parent)
        before = self.held_id(fd)
        require(stat.S_ISDIR(before[2]) and stat.S_IMODE(before[2]) == 0o700 and
                self.named_id(parent, OUTPUT_ROOT.name) == before, 'output-directory')
        self.output = [parent, OUTPUT_ROOT.name, fd, before]
        self.op(os.fsync, parent)

    def read(self, fd, size, expected=None, is_input=False):
        require(not is_input or not self.input_failed, 'input-after-failure-forbidden')
        if is_input:
            self.b.reserve(inputPasses=1)
        pieces = []
        total = 0
        digest = hashlib.sha256()
        while total < size:
            count = min(CHUNK, size - total)
            self.b.reserve(ioCalls=1, readCalls=1, requestedBytes=count)
            raw = os.read(fd, count)
            self.b.returned(len(raw), is_input)
            require(len(raw) == count, 'short-read')
            if expected is None:
                pieces.append(raw)
            else:
                require(raw == expected[total:total + count], 'readback-mismatch')
            digest.update(raw)
            total += count
        self.b.reserve(ioCalls=1, readCalls=1, requestedBytes=1)
        extra = os.read(fd, 1)
        self.b.returned(len(extra), is_input)
        require(not extra, 'nonempty-eof')
        return (b''.join(pieces) if expected is None else None), digest.hexdigest()

    def input(self):
        component = self.directory(INPUT_ROOT)
        require(stat.S_IMODE(component[3][2]) == 0o700, 'input-directory-mode')
        parent = component[2]
        before = self.named_id(parent, INPUT_FILE)
        require(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o400 and
                before[3] == INPUT_BYTES, 'input-shape')
        fd = self.opened(INPUT_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, parent)
        self.source = (parent, INPUT_FILE, fd, before)
        require(self.held_id(fd) == before, 'input-open-identity')
        raw, digest = self.read(fd, INPUT_BYTES, is_input=True)
        require(digest == INPUT_SHA, 'input-sha')
        require(self.held_id(fd) == before and self.named_id(parent, INPUT_FILE) == before,
                'input-after-identity')
        return raw

    def input_continuity(self, raw):
        require(not self.input_failed and self.source is not None,
                'input-after-failure-forbidden')
        parent, leaf, fd, before = self.source
        require(self.held_id(fd) == before and self.named_id(parent, leaf) == before,
                'input-reread-before-identity')
        self.op(os.lseek, fd, 0, os.SEEK_SET)
        _, digest = self.read(fd, INPUT_BYTES, raw, is_input=True)
        require(digest == INPUT_SHA and self.held_id(fd) == before and
                self.named_id(parent, leaf) == before, 'input-reread-after-identity')
        for component in self.directories:
            self.continuous(component)

    def record(self, leaf, value):
        require(leaf in OUTPUT_LIMITS, 'output-selector')
        raw = bounded_json(value, OUTPUT_LIMITS[leaf], self.b)
        self.b.reserve(outputFiles=1)
        self.continuous(self.output)
        parent = self.output[2]
        fd = self.opened(leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, parent)
        self.own_mutation(self.output)
        initial = self.held_id(fd)
        require(stat.S_ISREG(initial[2]) and initial[3] == 0 and
                self.named_id(parent, leaf) == initial, 'output-open-identity')
        for offset in range(0, len(raw), CHUNK):
            chunk = raw[offset:offset + CHUNK]
            self.b.reserve(ioCalls=1, writeCalls=1, outputRequestedBytes=len(chunk))
            count = os.write(fd, chunk)
            self.b.written(count)
            require(count == len(chunk), 'short-write')
        self.op(os.fsync, fd)
        self.op(os.fchmod, fd, 0o400)
        self.op(os.fsync, fd)
        before = self.held_id(fd)
        require(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o400 and
                before[3] == len(raw) and self.named_id(parent, leaf) == before,
                'output-seal-identity')
        self.op(os.lseek, fd, 0, os.SEEK_SET)
        _, digest = self.read(fd, len(raw), raw)
        require(self.held_id(fd) == before and self.named_id(parent, leaf) == before,
                'output-readback-identity')
        self.op(os.fsync, parent)
        result = {'file': leaf, 'bytes': len(raw), 'sha256': digest}
        self.outputs.append((fd, before, result))
        return result

    def output_continuity(self):
        for fd, before, result in self.outputs:
            require(self.held_id(fd) == before and
                    self.named_id(self.output[2], result['file']) == before,
                    'output-final-identity')
        self.continuous(self.output)
        self.continuous(self.output_parent)

    def close(self, failure):
        for ordinal, fd in enumerate(reversed(self.held), 1):
            if time.monotonic_ns() >= self.b.deadline:
                failure('close', Rejected('deadline-before-close'))
                return
            try:
                self.b.reserve(ioCalls=1, closes=1)
            except BaseException as error:
                failure('close', error)
                return
            try:
                os.close(fd)
            except BaseException as error:
                failure('close-' + str(ordinal), error)
            if time.monotonic_ns() >= self.b.deadline:
                failure('close', Rejected('deadline-after-close'))
                return


def field(value, name, kind):
    require(type(value) is dict and name in value and type(value[name]) is kind,
            'projection-field-shape')
    return value[name]


def event_context(event):
    context = field(event, 'context', list)
    require(len(context) == 7 and all(type(value) is int and
            -(2**31) <= value < 2**31 for value in context), 'context-shape')
    return context


def event_ordinal(event):
    ordinal = field(event, 'ordinal', int)
    require(0 < ordinal <= 2000000, 'event-ordinal-bound')
    return ordinal


def project_key(event):
    context = event_context(event)
    return (context[0], context[1], context[4], context[5])


def task_key(event):
    context = event_context(event)
    return project_key(event) + (context[2], context[3])


def bounded_text(value, maximum=4096):
    require(type(value) is str and len(value) <= maximum, 'projected-text-bound')
    return value


def property_group(event, group, budget):
    rows = field(event, group, list)
    require(len(rows) <= 65536, 'property-group-bound')
    matches = {name: [] for name in PROPERTIES}
    lookup = {name.casefold(): name for name in PROPERTIES}
    for index, row in enumerate(rows):
        if index % 128 == 0:
            budget.check()
        require(type(row) is list and len(row) == 2 and type(row[0]) is str and
                (row[1] is None or type(row[1]) is str), 'property-pair-shape')
        name = lookup.get(row[0].casefold())
        if name is not None:
            require(len(matches[name]) < 8, 'matching-property-count-bound')
            key = bounded_text(row[0], 128)
            value = row[1]
            if value is not None:
                bounded_text(value)
            matches[name].append({'index': index, 'key': key,
                                  'type': 'null' if value is None else 'string',
                                  'value': value})
    return {'totalPairs': len(rows), 'properties': {
        name: {'count': len(matches[name]), 'matches': matches[name]}
        for name in PROPERTIES}}


def project_observations(value, budget):
    require(type(value) is dict and set(value) == {
        'schema', 'fileFormatVersion', 'minimumReaderVersion', 'explicitEof',
        'singleGzipMemberComplete', 'decompressedBytes', 'eofOffset', 'recordKinds',
        'opaqueKnownRecordKinds', 'events', 'semanticAcceptance', 'graphAccepted',
        'artifactAccepted', 'continuation_allowed',
    }, 'observations-shape')
    require(value['schema'] == 'compiler-0062-stage2-decoded-observations-v1',
            'observations-schema')
    for name, expected in (('fileFormatVersion', 26), ('minimumReaderVersion', 18)):
        require(type(value[name]) is int and value[name] == expected,
                'observations-version')
    for name in ('explicitEof', 'singleGzipMemberComplete'):
        require(value[name] is True, 'observations-structural-flag')
    for name in FALSE_CLAIMS:
        require(value[name] is False, 'observations-acceptance-flag')
    for name in ('decompressedBytes', 'eofOffset'):
        require(type(value[name]) is int and 0 < value[name] <= 536870912,
                'observations-offset-bound')
    counts = field(value, 'recordKinds', dict)
    opaque = field(value, 'opaqueKnownRecordKinds', dict)
    for mapping in (counts, opaque):
        require(len(mapping) <= 36 and all(
            type(key) is str and key in {str(i) for i in range(36)} and
            type(count) is int and 0 < count <= 2000000
            for key, count in mapping.items()), 'record-kind-count-shape')
    require(sum(counts.values()) <= 2000000 and counts.get('0') == 1 and
            opaque.get('15', 0) == counts.get('15', 0), 'record-kind-count-join')
    events = field(value, 'events', list)
    require(len(events) <= 65536, 'event-count-bound')
    projects = {}
    starts = {}
    finishes = {}
    all_project_starts = 0
    all_task_starts = 0
    last_ordinal = 0
    for event in events:
        budget.check()
        kind = field(event, 'kind', int)
        require(1 <= kind <= 35, 'event-kind')
        ordinal = event_ordinal(event)
        require(ordinal > last_ordinal, 'event-order')
        last_ordinal = ordinal
        if kind == 3:
            all_project_starts += 1
            key = project_key(event)
            require(key not in projects and len(projects) < 8192,
                    'project-context-duplicate-or-bound')
            projects[key] = event
        elif kind == 7:
            all_task_starts += 1
            if field(event, 'taskName', str) == 'Csc':
                key = task_key(event)
                require(key not in starts and len(starts) < 3, 'csc-start-count-or-duplicate')
                starts[key] = event
        elif kind == 8 and field(event, 'taskName', str) == 'Csc':
            key = task_key(event)
            require(key not in finishes and len(finishes) < 3,
                    'csc-finish-count-or-duplicate')
            finishes[key] = event
    require(all_project_starts == counts.get('3', 0) and
            all_task_starts == counts.get('7', 0), 'retained-lifecycle-count-join')
    require(len(starts) == len(finishes) == 3 and set(starts) == set(finishes),
            'three-csc-lifecycles-required')
    result = []
    for key, start in sorted(starts.items(), key=lambda pair: pair[1]['ordinal']):
        budget.check()
        finish = finishes[key]
        pkey = project_key(start)
        require(pkey in projects, 'csc-project-context-missing')
        project = projects[pkey]
        require(event_ordinal(project) < event_ordinal(start) < event_ordinal(finish),
                'project-csc-order')
        project_file = bounded_text(field(start, 'projectFile', str))
        task_file = bounded_text(field(start, 'taskFile', str))
        require(field(finish, 'projectFile', str) == project_file and
                field(project, 'projectFile', str) == project_file and
                field(finish, 'taskFile', str) == task_file, 'csc-project-file-join')
        succeeded = field(finish, 'succeeded', bool)
        result.append({
            'taskStart': {'ordinal': start['ordinal'], 'context': start['context'],
                          'taskName': 'Csc', 'projectFile': project_file,
                          'taskFile': task_file,
                          'taskAssemblyLocation': bounded_text(field(start, 'taskAssemblyLocation', str))},
            'taskFinish': {'ordinal': finish['ordinal'], 'context': finish['context'],
                           'taskName': 'Csc', 'projectFile': project_file,
                           'taskFile': task_file, 'succeeded': succeeded},
            'projectStart': {'ordinal': project['ordinal'], 'context': project['context'],
                             'projectFile': project_file,
                             'properties': property_group(project, 'properties', budget),
                             'globalProperties': property_group(project, 'globalProperties', budget)},
        })
    structural = {name: value[name] for name in (
        'schema', 'fileFormatVersion', 'minimumReaderVersion', 'explicitEof',
        'singleGzipMemberComplete', 'decompressedBytes', 'eofOffset',
        'semanticAcceptance', 'graphAccepted', 'artifactAccepted', 'continuation_allowed')}
    return {
        'schema': 'compiler-0062-project-property-projection-v1',
        'action': '0062', 'ordinal': 1, 'input': {'bytes': INPUT_BYTES, 'sha256': INPUT_SHA},
        'structuralObservation': structural,
        'recordKindCounts': {name: counts.get(name, 0) for name in ('3', '7', '15')},
        'opaqueEvaluationFinishedCount': opaque.get('15', 0),
        'cscContexts': result, 'diagnosticProjectionOnly': True,
        'propertiesMerged': False, 'missingPropertiesDefaulted': False,
        'evaluationPropertiesDecoded': False, 'binlogParsed': False,
        'stage2SemanticSelectionRetried': False, **FALSE_CLAIMS,
    }


def main():
    budget = Budget(time.monotonic_ns())
    io = FixedIO(budget)
    handlers = {}
    failures = []
    outputs = []
    data = None
    data_sha = None
    started = False

    def failed(stage, error):
        # Every caught diagnostic/finalization failure is retained in order.
        # Static control flow permits at most 16 closes plus 8 other failures.
        reason = error.reason if isinstance(error, Rejected) else 'runtime-' + type(error).__name__
        failures.append({'stage': stage, 'reason': reason})
        io.input_failed = True
        budget.finalizing = True

    def cancelled(_number, _frame):
        budget.cancelled = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            handlers[number] = signal.signal(number, cancelled)
        data, data_sha = admission(budget)
        budget.stage = 'output-create'
        io.prepare_output()
        outputs.append(io.record('started.json', {
            'schema': 'compiler-0062-property-inspection-start-v1',
            'action': '0062', 'ordinal': 1, 'admissionSha256': data_sha,
            'oneInvocation': True, 'normalCompletion': False,
            'originalToolExitRequired': True, **FALSE_CLAIMS}))
        started = True
        budget.stage = 'fixed-input'
        raw = io.input()
        budget.stage = 'json-parse'
        observed = read_json(raw, 10485760, budget)
        budget.stage = 'property-projection'
        projection = project_observations(observed, budget)
        projection['admissionSha256'] = data_sha
        projection['stage2FailureAcceptance'] = data['stage2FailureAcceptance']
        outputs.append(io.record('property-projection.json', projection))
        budget.stage = 'input-continuity'
        io.input_continuity(raw)
        budget.stage = 'output-continuity'
        io.output_continuity()
        budget.check()
    except BaseException as error:
        failed(budget.stage, error)

    # No input operation occurs after this point. No deadline is renewed.
    budget.finalizing = True
    if budget.cancelled and not any(row['reason'] == 'cancelled' for row in failures):
        failed('finalization', Rejected('cancelled'))
    if started:
        try:
            terminal = 'failure.json' if failures else 'complete.json'
            outputs.append(io.record(terminal, {
                'schema': 'compiler-0062-property-inspection-terminal-v1',
                'action': '0062', 'ordinal': 1, 'admissionSha256': data_sha,
                'normalCompletionCandidate': not failures,
                'originalToolExitRequired': True,
                'originalTransportRequiredForLaterFinalizationFailures': True,
                'failuresBeforeTerminal': failures[:], 'stage': budget.stage,
                'outputsBeforeTerminal': outputs[:],
                'countersBeforeTerminal': budget.counts.copy(), **FALSE_CLAIMS}))
        except BaseException as error:
            failed('terminal-persistence', error)
        try:
            io.output_continuity()
        except BaseException as error:
            failed('terminal-output-continuity', error)
    io.close(failed)
    for number, previous in handlers.items():
        if time.monotonic_ns() >= budget.deadline:
            failed('handler-restore', Rejected('deadline'))
            break
        try:
            signal.signal(number, previous)
        except BaseException as error:
            failed('handler-restore', error)
        if time.monotonic_ns() >= budget.deadline:
            failed('handler-restore', Rejected('deadline-after-restore'))
            break
    if budget.cancelled and not any(row['reason'] == 'cancelled' for row in failures):
        failed('transport', Rejected('cancelled'))
    if time.monotonic_ns() >= budget.deadline:
        # No stdout write is started after expiry. The missing original frame is
        # itself a rejection; an earlier terminal cannot establish completion.
        return 1
    try:
        frame = bounded_json({
            'schema': 'compiler-0062-property-inspection-transport-v1',
            'action': '0062', 'ordinal': 1, 'admissionSha256': data_sha,
            'normalCompletion': not failures, 'failures': failures,
            'stage': budget.stage, 'outputs': outputs,
            'countersBeforeTransport': budget.counts.copy(),
            'originalToolExitRequired': True, **FALSE_CLAIMS}, 8192, budget)
        budget.reserve(ioCalls=1, writeCalls=1, outputRequestedBytes=len(frame))
        count = os.write(1, frame)
        budget.written(count)
        require(count == len(frame), 'short-transport-write')
    except BaseException:
        # A failed sole transport write cannot be retried or amended.
        return 1
    return 0 if not failures and not budget.cancelled and time.monotonic_ns() < budget.deadline else 1


if __name__ == '__main__':
    raise SystemExit(main())
