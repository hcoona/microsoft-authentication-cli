"""In-memory invariant checks; never activate the caller or access Windows files."""

import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[1] / 'run_windows_managed_build.py'
DEFINITIONS = {'PredicateFailure', 'require', 'failure_identity', 'encode', 'identity', 'Budget'}
tree = ast.parse(SOURCE.read_text(), filename=str(SOURCE))
selected = ast.Module(body=[node for node in tree.body
                           if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and
                           node.name in DEFINITIONS], type_ignores=[])
assert {node.name for node in selected.body} == DEFINITIONS
NS = {'__file__': str(SOURCE), 'time': time, 'stat': stat, 'json': json, 'Path': Path,
      'direct': lambda path: path, 'digest': lambda raw: hashlib.sha256(raw).hexdigest()}
exec(compile(selected, str(SOURCE), 'exec'), NS)
Failure = NS['PredicateFailure']
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size',
          'st_mtime_ns', 'st_ctime_ns', 'st_nlink')


def info(values):
    return SimpleNamespace(**dict(zip(FIELDS, values, strict=True)))


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.payload = b'abc'
        self.closed = [1, 2, stat.S_IFREG | 0o600, 1000, 1000, 3, 100, 100, 1]
        self.initial = self.closed.copy()
        self.final = self.closed.copy()
        self.named = self.closed.copy()
        self.initial[7], self.final[7], self.named[7] = 110, 120, 130

    def execute(self, *, created=True, returned=None, expected=None, pin=None):
        actual = self.payload if returned is None else returned
        path = Mock()
        path.lstat.return_value = info(self.named)
        ops = SimpleNamespace(
            O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK,
            open=Mock(return_value=3), close=Mock(),
            fstat=Mock(side_effect=[info(self.initial), info(self.final)]),
            read=Mock(side_effect=[actual, b'']))
        now = time.monotonic_ns()
        budget = NS['Budget'](now, now + 60_000_000_000, now + 70_000_000_000)
        self.ops, self.path, self.budget = ops, path, budget
        with patch.dict(NS, {'os': ops, 'Path': lambda _: path}):
            if pin is not None:
                return budget.pin(pin, 1024)
            if created:
                return budget.read_created_copy(
                    path, 1024, self.closed, self.payload if expected is None else expected)
            return budget.read(path, 1024)

    def test_ctime_observations_and_final_named_baseline(self):
        baseline, observed = self.execute()
        self.assertEqual(baseline, self.named)
        self.assertEqual(observed['initialDescriptor'], self.initial)
        self.assertEqual(observed['finalDescriptor'], self.final)
        self.assertEqual(observed['namedPath'], self.named)
        self.assertTrue(observed['createdCopyReadback'])
        self.assertEqual((self.budget.reads, self.budget.requested), (1, 4))
        self.ops.close.assert_called_once_with(3)

    def test_every_non_ctime_field_remains_required_at_each_stage(self):
        for stage in ('initial', 'final', 'named'):
            for index in (0, 1, 2, 3, 4, 5, 6, 8):
                with self.subTest(stage=stage, field=FIELDS[index]):
                    self.setUp()
                    getattr(self, stage)[index] += 1
                    with self.assertRaises(Failure):
                        self.execute()

    def test_equal_length_different_payload_is_rejected(self):
        with self.assertRaisesRegex(Failure, 'Created copy differs from admitted payload'):
            self.execute(returned=b'abd')

    def test_empty_admitted_payload_is_valid(self):
        self.payload = b''
        for value in (self.closed, self.initial, self.final, self.named):
            value[5] = 0
        baseline, observed = self.execute()
        self.assertEqual(baseline, self.named)
        self.assertEqual(observed['returnedBytes'], 0)
        self.assertEqual((self.budget.reads, self.budget.requested), (1, 1))

    def test_length_failure_does_not_observe_later_metadata(self):
        for payload in (b'ab', b'abcd'):
            with self.subTest(payload=payload), self.assertRaises(Failure) as caught:
                self.execute(returned=payload)
            observation = caught.exception.read_observation
            self.assertIsNone(observation['finalDescriptor'])
            self.assertIsNone(observation['namedPath'])
            self.assertEqual(self.ops.fstat.call_count, 1)
            self.path.lstat.assert_not_called()

    def test_ordinary_read_keeps_full9_and_short_circuit(self):
        with self.assertRaises(Failure) as caught:
            self.execute(created=False)
        self.assertFalse(caught.exception.read_observation['createdCopyReadback'])
        self.assertIsNone(caught.exception.read_observation['namedPath'])
        self.path.lstat.assert_not_called()
        self.final = self.initial.copy()
        with self.assertRaises(Failure) as caught:
            self.execute(created=False)
        self.assertEqual(caught.exception.read_observation['namedPath'], self.named)

    def test_later_pin_does_not_rebaseline_ctime(self):
        baseline, _ = self.execute()
        self.initial = self.final = self.named = baseline.copy()
        self.initial[7] += 1
        pin = {'path': '/in-memory', 'bytes': 3,
               'sha256': hashlib.sha256(self.payload).hexdigest(), 'identity': baseline}
        with self.assertRaisesRegex(Failure, 'Admitted descriptor changed'):
            self.execute(created=False, pin=pin)

    def test_missing_payload_or_identity_cannot_use_created_rule(self):
        now = time.monotonic_ns()
        budget = NS['Budget'](now, now + 1_000_000_000, now + 2_000_000_000)
        for identity, payload in ((None, b'abc'), (self.closed, None)):
            with self.subTest(identity=identity, payload=payload), self.assertRaises(Failure):
                budget.read_created_copy(None, 1024, identity, payload)


class PinDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.payload = b'abc'
        self.identity = [1, 2, stat.S_IFREG | 0o600, 1000, 1000, 3, 100, 100, 1]
        self.pin = {'path': '/unretained-input-path', 'bytes': 3,
                    'sha256': hashlib.sha256(self.payload).hexdigest(),
                    'identity': self.identity.copy()}
        now = time.monotonic_ns()
        self.budget = NS['Budget'](now, now + 60_000_000_000, now + 70_000_000_000)
        self.budget.reads = 37
        self.budget.read = Mock(return_value=(self.payload, self.identity))

    def failure(self):
        with self.assertRaisesRegex(Failure, 'Admitted descriptor changed') as caught:
            self.budget.pin(self.pin, 1024)
        result = NS['failure_identity'](caught.exception)
        self.assertLessEqual(len(NS['encode'](result)), 2048)
        self.assertEqual(result['pinObservation']['readOrdinal'], 37)
        self.assertNotIn('readObservation', result)
        self.assertNotIn(self.pin['path'], NS['encode'](result).decode('ascii'))
        self.budget.read.assert_called_once_with(Path(self.pin['path']), 1024)
        return result['pinObservation']

    def test_length_mismatch_preserves_digest_short_circuit(self):
        self.pin['bytes'] = 2
        with patch.dict(NS, {'digest': Mock(side_effect=AssertionError('Must not hash'))}):
            observation = self.failure()
        self.assertEqual((observation['expectedBytes'], observation['returnedBytes']), (2, 3))
        self.assertFalse(observation['lengthMatches'])
        self.assertIsNone(observation['digestMatches'])
        self.assertIsNone(observation['identityMatches'])

    def test_digest_mismatch_retains_boolean_without_hash_or_payload(self):
        self.pin['sha256'] = '0' * 64
        observation = self.failure()
        self.assertTrue(observation['lengthMatches'])
        self.assertFalse(observation['digestMatches'])
        self.assertIsNone(observation['identityMatches'])
        encoded = NS['encode'](observation)
        self.assertNotIn(self.pin['sha256'].encode(), encoded)
        self.assertNotIn(self.payload, encoded)

    def test_identity_mismatch_retains_each_full9_operand(self):
        self.pin['identity'][7] -= 1
        observation = self.failure()
        self.assertTrue(observation['digestMatches'])
        self.assertFalse(observation['identityMatches'])
        self.assertEqual(observation['expectedIdentity'], self.pin['identity'])
        self.assertEqual(observation['observedIdentity'], self.identity)

    def test_malformed_or_unbounded_expected_values_are_not_retained(self):
        for value in ('private-descriptor-value', 1 << 128, True):
            with self.subTest(value_type=type(value).__name__):
                self.setUp()
                self.pin['bytes'] = value
                self.pin['identity'] = ['private-descriptor-value'] * 9
                observation = self.failure()
                self.assertIsNone(observation['expectedBytes'])
                self.assertIsNone(observation['expectedIdentity'])
                self.assertNotIn(b'private-descriptor-value', NS['encode'](observation))

    def test_success_and_original_read_failure_are_unchanged(self):
        self.assertEqual(self.budget.pin(self.pin, 1024), self.payload)
        self.budget.read.assert_called_once_with(Path(self.pin['path']), 1024)
        error = OSError('unretained-private-error')
        self.budget.read.side_effect = error
        with self.assertRaises(OSError) as caught:
            self.budget.pin(self.pin, 1024)
        self.assertIs(caught.exception, error)
        self.assertNotIn('pinObservation', NS['failure_identity'](error))


if __name__ == '__main__':
    unittest.main()
