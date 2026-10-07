"""Exercise exclusive public output readback with synthetic metadata and bytes."""
import ast
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest


source = Path(__file__).parent.parent / 'transfer_selected_account_public.py'
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    initial = os.fstat(fd)
    if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1 or not 0 < initial.st_size <= 32768:
        raise ValueError('Transfer source bound')
    raw = os.read(fd, initial.st_size)
    if len(raw) != initial.st_size or os.read(fd, 1):
        raise ValueError('Transfer source EOF')
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size',
              'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    expected = tuple(getattr(initial, field) for field in fields)
    if any(tuple(getattr(value, field) for field in fields) != expected
           for value in (os.fstat(fd), os.stat(source, follow_symlinks=False))):
        raise ValueError('Transfer source changed')
finally:
    os.close(fd)
tree = ast.parse(raw)
full9_node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'full9')
transfer = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Transfer')
methods = [n for n in transfer.body if isinstance(n, ast.FunctionDef) and n.name in ('write', 'stable')]
if len(methods) != 2:
    raise ValueError('Exact readback methods required')
namespace = dict(os=os, stat=stat, hashlib=__import__('hashlib'))
for node in tree.body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and \
            isinstance(node.targets[0], ast.Name) and node.targets[0].id in ('STAGE', 'LEAVES'):
        namespace[node.targets[0].id] = ast.literal_eval(node.value)
exec(compile(ast.Module(body=[full9_node] + methods, type_ignores=[]), str(source), 'exec'), namespace)


class Harness:
    write = namespace['write']
    stable = namespace['stable']

    def __init__(self, payload=b'public payload'):
        self.payload = payload
        self.returned = payload
        self.baseline = [1, 2, stat.S_IFREG | 0o600, 3, 4, len(payload), 5, 10, 1]
        created = list(self.baseline)
        created[5] = 0
        self.observations = [created] + [list(self.baseline) for _ in range(5)]
        self.registered = None
        self.created_content = {}
        self.closed = []
        self.directories = {namespace['STAGE']: (7, [])}

    def open(self, name, flags, parent):
        return 42 if flags & os.O_CREAT else 43

    def metadata(self, *args):
        values = self.observations.pop(0)
        return SimpleNamespace(**dict(zip(
            ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size',
             'st_mtime_ns', 'st_ctime_ns', 'st_nlink'), values)))

    def charge(self, *args):
        pass

    def native(self, operation, function, *args):
        # Never call the supplied OS function or access a real descriptor.
        return len(args[1]) if operation == 6 else None

    def close(self, fd):
        self.closed.append(fd)

    def same(self, expected, observed):
        if expected != observed:
            raise ValueError('Identity mismatch')

    def read(self, fd, length):
        if self.returned is None:
            raise ValueError('EOF rejected')
        return self.returned

    def held(self, parent, name, fd, identity):
        self.registered = list(identity)


class ReadbackTests(unittest.TestCase):
    def test_ctime_observations_survive_and_final_identity_is_used(self):
        h = Harness()
        for ordinal, value in enumerate((10, 11, 12, 13, 13), 1):
            h.observations[ordinal][7] = value
        result = h.write(7, 'authority.json', h.payload)
        observation = result['readbackObservation']
        self.assertEqual([v[7] for v in observation.values()], [10, 11, 12, 13, 13])
        self.assertEqual(result['full9'], observation['finalNamedFull9'])
        self.assertEqual(h.registered, result['full9'])
        self.assertEqual(h.closed, [42])

    def test_every_other_field_change_rejects_before_or_after_read(self):
        for snapshot in (2, 3, 4, 5):
            for field in (0, 1, 2, 3, 4, 5, 6, 8):
                with self.subTest(snapshot=snapshot, field=field):
                    h = Harness()
                    h.observations[snapshot][field] += 1
                    with self.assertRaises(ValueError):
                        h.write(7, 'authority.json', h.payload)

    def test_final_held_named_ctime_mismatch_rejects(self):
        h = Harness()
        h.observations[-1][7] += 1
        with self.assertRaises(ValueError):
            h.write(7, 'authority.json', h.payload)

    def test_content_length_and_eof_failures_reject(self):
        for returned in (b'public payloaD', b'public', None):
            with self.subTest(returned=returned):
                h = Harness()
                h.returned = returned
                with self.assertRaises(ValueError):
                    h.write(7, 'authority.json', h.payload)

    def test_unadmitted_leaf_and_parent_reject_before_creation(self):
        for parent, name in ((7, 'private.json'), (8, 'authority.json')):
            with self.subTest(parent=parent, name=name):
                h = Harness()
                with self.assertRaises(ValueError):
                    h.write(parent, name, h.payload)
                self.assertEqual(len(h.observations), 6)

    def test_ordinary_source_reader_remains_full9_strict(self):
        h = Harness()
        changed = list(h.baseline)
        changed[7] += 1
        h.observations = [changed, changed]
        with self.assertRaises(ValueError):
            h.stable(7, 'source.bin', 43, h.baseline)


if __name__ == '__main__':
    unittest.main(verbosity=2)
