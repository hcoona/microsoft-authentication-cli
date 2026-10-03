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
EXPECTED_SHA256 = 'c5a5405430a7bc3b768bd77ea409a13cb8e24b50edc947cc333c8d4a038ce7e3'
EXPECTED_SOURCE_BYTES = 27565
if SOURCE.is_symlink() or SOURCE.stat().st_size != EXPECTED_SOURCE_BYTES:
    raise ValueError('Unexpected test source shape')
with SOURCE.open('rb') as stream:
    raw = stream.read(EXPECTED_SOURCE_BYTES + 1)
if len(raw) != EXPECTED_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
    raise ValueError('Unexpected test source bytes')
FUNCTIONS = {'decode', 'exact_int', 'output_sealing', 'public_receipt', 'public_single_copy_receipt', 'journal_record', 'interpret'}
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

    def test_identity_difference_mask(self):
        self.value.update(passed=False, failure='copy', rows=[])
        self.value['diagnostic'].update(copyOrdinal=12, completedCopies=11, wrapperPhase=1,
            nativePhase=270, heldOrdinal=0, errorKind=1, errorCode=270,
            identityMismatchMask=64, snapshotMismatchMask=0)
        projected = self.project(self.value)['receipt']
        self.assertEqual(projected, self.value)
        self.assertEqual(projected['diagnostic']['identityMismatchMask'], 64)
        self.value['diagnostic']['identityMismatchMask'] = 255
        self.assertEqual(self.project(self.value)['receipt']['diagnostic']['identityMismatchMask'], 255)

    def test_identity_difference_mask_type_and_range(self):
        for field, masks in (('identityMismatchMask', (True, -1, 256, 1.0, 'synthetic-private-marker')),
                             ('snapshotMismatchMask', (True, -1, 16, 1.0, 'synthetic-private-marker'))):
            for mask in masks:
                with self.subTest(field=field, mask=mask):
                    value = copy.deepcopy(self.value)
                    value['diagnostic'].update(identityMismatchMask=0, snapshotMismatchMask=0)
                    value['diagnostic'][field] = mask
                    self.reject(value)

    def test_identity_difference_mask_requires_matching_fault(self):
        for phase, kind in ((270, 3), (271, 1), (405, 0)):
            with self.subTest(phase=phase, kind=kind):
                value = copy.deepcopy(self.value)
                value.update(passed=False, failure='copy', rows=[])
                value['diagnostic'].update(nativePhase=phase, errorKind=kind,
                    errorCode=phase if kind == 1 else 0, identityMismatchMask=1, snapshotMismatchMask=0)
                self.reject(value)

    def test_zero_identity_difference_mask_does_not_claim_success(self):
        self.value['diagnostic'].update(identityMismatchMask=0, snapshotMismatchMask=0)
        self.assertEqual(self.project(self.value)['receipt'], self.value)
        self.value.update(passed=False, failure='copy', rows=[])
        self.value['diagnostic'].update(nativePhase=270, errorKind=1, errorCode=270)
        self.assertFalse(self.project(self.value)['receipt']['passed'])

    def test_snapshot_predicate_mask(self):
        self.value.update(passed=False, failure='copy', rows=[])
        self.value['diagnostic'].update(copyOrdinal=12, completedCopies=11, wrapperPhase=1,
            nativePhase=270, heldOrdinal=0, errorKind=1, errorCode=270, identityMismatchMask=0)
        for mask in (1, 2, 3, 4, 5, 6, 7, 8):
            with self.subTest(mask=mask):
                self.value['diagnostic']['snapshotMismatchMask'] = mask
                self.assertEqual(self.project(self.value)['receipt'], self.value)

    def test_snapshot_mask_requires_one_matching_first_fault(self):
        for phase, kind, identity_mask, snapshot_mask in ((270, 3, 0, 1), (271, 1, 0, 1),
                (405, 0, 0, 1), (270, 1, 64, 1), (270, 1, 0, 9)):
            with self.subTest(phase=phase, kind=kind, identity_mask=identity_mask, snapshot_mask=snapshot_mask):
                value = copy.deepcopy(self.value)
                value.update(passed=False, failure='copy', rows=[])
                value['diagnostic'].update(nativePhase=phase, errorKind=kind,
                    errorCode=phase if kind == 1 else 0,
                    identityMismatchMask=identity_mask, snapshotMismatchMask=snapshot_mask)
                self.reject(value)

    def test_partial_mask_pair_is_not_a_legacy_receipt(self):
        for field in ('identityMismatchMask', 'snapshotMismatchMask'):
            with self.subTest(field=field):
                value = copy.deepcopy(self.value)
                value['diagnostic'][field] = 0
                self.reject(value)

    def test_duplicate_and_noninteger_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError): NS['decode'](raw)

    def test_capture_suppression(self):
        self.assertEqual(NS['interpret']('launcher.stdout.bin', b'synthetic-private-marker'),
                         {'interpretation': 'contents-suppressed', 'empty': False})

    def test_other_root(self):
        self.value['target'] = self.value['target'].replace('account-v2', 'account-v1'); self.reject(self.value)


    def single_value(self):
        return dict(schema='selected-account-single-copy-diagnosis-v1', passed=True,
            authoritySha256='a' * 64, failure='none', copyCompleted=True,
            allHandlesClosed=True, noExperimentLive=False, productStarted=False, accountAccess=False,
            diagnostic=dict(wrapperPhase=3, nativePhase=405, heldOrdinal=2, errorKind=0, errorCode=0,
                identityMismatchMask=0, snapshotMismatchMask=0, opens=0, metadata=0, reads=0, writes=0,
                requestedReadBytes=0, writtenBytes=0))

    def test_single_copy_success_is_diagnosis_only(self):
        value = self.single_value(); projected = self.project(value)
        self.assertEqual(projected, dict(interpretation='validated-public-single-copy-diagnosis',
                                       receipt=value, diagnosisOnly=True))
        self.assertNotIn('rows', projected['receipt']); self.assertNotIn('target', projected['receipt'])

    def test_single_copy_first_fault_is_preserved(self):
        value = self.single_value(); value.update(passed=False, copyCompleted=False, failure='copy')
        value['diagnostic'].update(wrapperPhase=1, nativePhase=270, heldOrdinal=0,
            errorKind=1, errorCode=270, identityMismatchMask=64)
        self.assertEqual(self.project(value)['receipt'], value)
        value['diagnostic'].update(identityMismatchMask=0, snapshotMismatchMask=8)
        self.assertEqual(self.project(value)['receipt'], value)
        value.update(copyCompleted=False, failure='native-source', diagnostic=None)
        self.assertEqual(self.project(value)['receipt'], value)

    def test_single_copy_rejects_private_or_untyped_data(self):
        for location, field, changed in (('receipt', 'accountEmail', 'synthetic-private-marker'),
                ('receipt', 'copyCompleted', 1), ('receipt', 'accountAccess', True),
                ('receipt', 'failure', 'synthetic-private-marker'),
                ('diagnostic', 'unexpectedPrivateField', 'synthetic-private-marker'),
                ('diagnostic', 'requestedReadBytes', True),
                ('diagnostic', 'snapshotMismatchMask', 'synthetic-private-marker')):
            with self.subTest(location=location, field=field):
                value = self.single_value(); container = value if location == 'receipt' else value['diagnostic']
                container[field] = changed; self.reject(value)

    def test_single_copy_requires_complete_success_conjunction(self):
        for field, changed in (('copyCompleted', False), ('allHandlesClosed', False),
                               ('failure', 'copy'), ('diagnostic', None)):
            with self.subTest(field=field):
                value = self.single_value(); value[field] = changed; self.reject(value)
        for field, changed in (('heldOrdinal', 1), ('wrapperPhase', 2), ('nativePhase', 318),
                              ('errorKind', 3), ('identityMismatchMask', 64)):
            with self.subTest(field=field):
                value = self.single_value(); value['diagnostic'][field] = changed; self.reject(value)

    def test_single_copy_requires_exact_authority_and_mask_context(self):
        value = self.single_value(); value['authoritySha256'] = 'b' * 64; self.reject(value)
        for change in ({'snapshotMismatchMask': 16}, {'identityMismatchMask': 256},
                       {'snapshotMismatchMask': 9}, {'identityMismatchMask': 64, 'snapshotMismatchMask': 1}):
            with self.subTest(change=change):
                value = self.single_value(); value.update(passed=False, copyCompleted=False, failure='copy')
                value['diagnostic'].update(wrapperPhase=1, nativePhase=270, errorKind=1, errorCode=270)
                value['diagnostic'].update(change); self.reject(value)


    def sealing_value(self):
        value = self.single_value()
        value['schema'] = 'selected-account-single-copy-diagnosis-v2'
        value['diagnostic'].update(outputStage=3, firstReadChangeCount=1, sealedOutputs=1)
        return value

    def test_sealing_discloses_first_read_change_without_identity_values(self):
        value = self.sealing_value()
        projected = self.project(value)
        self.assertTrue(projected['diagnosisOnly'])
        self.assertEqual(projected['receipt'], value)
        self.assertEqual(set(projected['receipt']), set(self.single_value()))
        self.assertNotIn('identity', projected['receipt']['diagnostic'])

    def test_sealing_rejects_later_change_even_after_first_read_change(self):
        value = self.sealing_value()
        value.update(passed=False, copyCompleted=False, failure='copy')
        value['diagnostic'].update(wrapperPhase=1, nativePhase=280, outputStage=2,
            heldOrdinal=0, sealedOutputs=0, errorKind=1, errorCode=280, identityMismatchMask=64)
        self.assertEqual(self.project(value)['receipt'], value)
        value['passed'] = True; self.reject(value)

    def test_sealing_preserves_non_change_time_first_read_failure(self):
        value = self.sealing_value()
        value.update(passed=False, copyCompleted=False, failure='copy')
        value['diagnostic'].update(wrapperPhase=1, nativePhase=220, outputStage=1,
            heldOrdinal=0, sealedOutputs=0, firstReadChangeCount=0,
            errorKind=1, errorCode=220, identityMismatchMask=128)
        self.assertEqual(self.project(value)['receipt'], value)
        value['diagnostic']['identityMismatchMask'] = 64; self.reject(value)

    def test_sealing_requires_typed_complete_counter_set(self):
        for field in ('outputStage', 'firstReadChangeCount', 'sealedOutputs'):
            for change in ('missing', True, -1, 1.0, 'synthetic-private-marker'):
                with self.subTest(field=field, change=change):
                    value = self.sealing_value()
                    if change == 'missing': del value['diagnostic'][field]
                    else: value['diagnostic'][field] = change
                    self.reject(value)

    def test_sealing_rejects_impossible_phase_or_completion(self):
        for change in ({'outputStage': 2}, {'sealedOutputs': 0}, {'sealedOutputs': 2},
                       {'firstReadChangeCount': 2}, {'outputStage': 4}):
            with self.subTest(change=change):
                value = self.sealing_value(); value['diagnostic'].update(change); self.reject(value)
        value = self.sealing_value(); value.update(passed=False, copyCompleted=False, failure='copy')
        value['diagnostic'].update(nativePhase=280, errorKind=1, errorCode=280, identityMismatchMask=64)
        self.reject(value)

    def test_sealing_shape_cannot_reinterpret_legacy_receipt(self):
        value = self.sealing_value(); value['schema'] = 'selected-account-single-copy-diagnosis-v1'
        self.reject(value)
        value = self.single_value(); value['schema'] = 'selected-account-single-copy-diagnosis-v2'
        self.reject(value)

    def test_full_materialization_requires_all_outputs_sealed(self):
        value = copy.deepcopy(self.value); value['schema'] = 'selected-account-public-materialization-v3'
        value['diagnostic'].update(outputStage=3, firstReadChangeCount=200, sealedOutputs=200,
            identityMismatchMask=0, snapshotMismatchMask=0)
        self.assertEqual(self.project(value)['receipt'], value)
        for change in ({'sealedOutputs': 199}, {'outputStage': 2}, {'firstReadChangeCount': 201}):
            with self.subTest(change=change):
                changed = copy.deepcopy(value); changed['diagnostic'].update(change); self.reject(changed)

    def test_sealing_rejects_undeclared_initial_identity_or_timestamp(self):
        for field in ('outputInitialIdentity', 'outputFirstReadIdentity', 'changed', 'accessed'):
            with self.subTest(field=field):
                value = self.sealing_value(); value['diagnostic'][field] = 134000000000000001
                self.reject(value)


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
