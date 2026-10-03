"""Pure privacy projection checks; no collector main or Windows access."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest
import resource
import sys

SOURCE = Path(__file__).resolve().parents[1] / 'collect_selected_account_copy_results.py'
EXPECTED_SHA256 = 'd14127271cd1a47a7520102271b6f3b34183e2d6913d6d8752f8b47b685f77ed'
EXPECTED_SOURCE_BYTES = 20933
if SOURCE.is_symlink() or SOURCE.stat().st_size != EXPECTED_SOURCE_BYTES:
    raise ValueError('Unexpected test source shape')
with SOURCE.open('rb') as stream:
    raw = stream.read(EXPECTED_SOURCE_BYTES + 1)
if len(raw) != EXPECTED_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
    raise ValueError('Unexpected test source bytes')
FUNCTIONS = {'decode', 'exact_int', 'public_receipt', 'journal_record', 'interpret'}
CONSTANTS = {'EVENT_FIELDS', 'CAPTURE_FIELDS', 'BOOL_FIELDS', 'INT_FIELDS',
             'NULLABLE_FIELDS', 'EXCEPTION_TYPES', 'PHASES'}
tree = ast.parse(raw, filename=str(SOURCE))
selected = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in FUNCTIONS) or
    (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and
     n.targets[0].id in CONSTANTS)]
assert {n.name for n in selected if isinstance(n, ast.FunctionDef)} == FUNCTIONS
assert {n.targets[0].id for n in selected if isinstance(n, ast.Assign)} == CONSTANTS
NS = {'json': json, 're': re}
exec(compile(ast.Module(body=selected, type_ignores=[]), str(SOURCE), 'exec'), NS)


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        expected = [{'relative': 'toolchain\\public-' + str(i) + '.dll', 'bytes': 1,
                     'sha256': 'b' * 64, 'role': 'caller'} for i in range(200)]
        NS['ADMISSION'] = {'authoritySha256': 'a' * 64, 'expectedRows': copy.deepcopy(expected),
                           'nonce': '0' * 32}
        ident = dict(volume=1, attributes=32, links=1, index=(1 << 53) + 237,
                     created=134000000000000000, modified=134000000000000001,
                     changed=134000000000000002, length=1)
        counters = dict(opens=0, metadata=0, reads=0, writes=0, requestedReadBytes=0, writtenBytes=0)
        self.value = dict(schema='selected-account-public-materialization-v2', passed=True,
            authoritySha256='a' * 64,
            target='C:\\Temp\\azureauth-windows-slice-108\\confidential-native-account-v2',
            rows=[dict(row, identity=copy.deepcopy(ident), sourceIdentity=copy.deepcopy(ident)) for row in expected],
            failure='none', allHandlesClosed=True, noExperimentLive=False, productStarted=False, accountAccess=False,
            diagnostic=dict(copyOrdinal=0, completedCopies=200, wrapperPhase=4, nativePhase=405,
                heldOrdinal=400, errorKind=0, errorCode=0, **counters),
            counts=dict(counters, bootstrapReads=0, bootstrapRequestedReadBytes=0))

    def project(self, value):
        return NS['interpret']('materialization-result.json', (json.dumps(value) + '\n').encode())

    def reject(self, value):
        self.assertEqual(self.project(value), {'interpretation': 'invalid-public-shape'})

    def test_exact_large_integers(self):
        row = self.project(self.value)['receipt']['rows'][0]['identity']
        self.assertEqual(row['index'], (1 << 53) + 237)
        self.assertEqual(row['modified'], 134000000000000001)

    def test_unknown_fields(self):
        for place in ('receipt', 'row', 'identity', 'diagnostic'):
            with self.subTest(place=place):
                value = copy.deepcopy(self.value)
                target = {'receipt': value, 'row': value['rows'][0],
                    'identity': value['rows'][0]['identity'], 'diagnostic': value['diagnostic']}[place]
                target['unexpectedPrivateField'] = 'synthetic-private-marker'; self.reject(value)

    def test_unapproved_hash_path_role(self):
        for key, changed in [('sha256', 'c' * 64), ('relative', 'toolchain\\other.dll'), ('role', 'product')]:
            with self.subTest(key=key):
                value = copy.deepcopy(self.value); value['rows'][0][key] = changed; self.reject(value)

    def test_row_order(self):
        self.value['rows'][0], self.value['rows'][1] = self.value['rows'][1], self.value['rows'][0]
        self.reject(self.value)

    def test_boolean_is_not_numeric(self):
        for field in ('completedCopies', 'errorCode', 'requestedReadBytes'):
            with self.subTest(field=field):
                value = copy.deepcopy(self.value); value['diagnostic'][field] = True; self.reject(value)

    def test_identity_bounds_and_length(self):
        for key, changed in [('index', 1 << 64), ('changed', -1), ('links', 2), ('attributes', 0x400), ('length', 2)]:
            with self.subTest(key=key):
                value = copy.deepcopy(self.value); value['rows'][0]['identity'][key] = changed; self.reject(value)

    def test_provisional_success_shape(self):
        for key, changed in [('heldOrdinal', 399), ('nativePhase', 500), ('errorKind', 1)]:
            with self.subTest(key=key):
                value = copy.deepcopy(self.value); value['diagnostic'][key] = changed; self.reject(value)

    def test_signed_hresult(self):
        self.value.update(passed=False, failure='copy', rows=[]); self.value.pop('counts')
        self.value['diagnostic'].update(copyOrdinal=1, completedCopies=0, wrapperPhase=1,
            nativePhase=103, heldOrdinal=0, errorKind=3, errorCode=-2147024891)
        self.assertEqual(self.project(self.value)['receipt']['diagnostic']['errorCode'], -2147024891)

    def test_missing_context(self):
        self.value.update(passed=False, failure='native-source', rows=[], diagnostic=None); self.value.pop('counts')
        self.assertIsNone(self.project(self.value)['receipt']['diagnostic'])

    def test_duplicate_and_noninteger_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError): NS['decode'](raw)

    def test_capture_suppression(self):
        self.assertEqual(NS['interpret']('launcher.stdout.bin', b'synthetic-private-marker'),
                         {'interpretation': 'contents-suppressed', 'empty': False})

    def test_other_root(self):
        self.value['target'] = self.value['target'].replace('account-v2', 'account-v1'); self.reject(self.value)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
    resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(ProjectionTests).run(result)
    frame = (json.dumps({'schema': 'selected-account-copy-projection-check-v1',
        'testsRun': result.testsRun, 'failureCount': len(result.failures),
        'errorCount': len(result.errors), 'passed': result.wasSuccessful()},
        sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(frame) > 4096:
        sys.exit(1)
    sys.stdout.buffer.write(frame)
    sys.stdout.buffer.flush()
    sys.exit(0 if result.wasSuccessful() else 1)
