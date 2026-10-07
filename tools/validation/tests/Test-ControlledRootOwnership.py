"""Source-only filesystem regressions; exact admission is required before execution."""
TEST_ADMITTED = False
FIXTURE_ROOT = None
if not TEST_ADMITTED or FIXTURE_ROOT is None:
    raise SystemExit('Inert root-ownership source tests.')

import ast
import hashlib
import io
import os
import stat
from types import SimpleNamespace
from pathlib import Path
import time

SOURCE = Path(__file__).resolve().parents[1] / 'controlled-callers/run_controlled_callers.py'
EXPECTED_SOURCE = (81101, '21f031cf0e92defc6a81174aba3cc22fb0be7f07573572475266f3df671174d0')


def full9(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_nlink)


def namespace():
    fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        assert stat.S_ISREG(first.st_mode) and first.st_nlink == 1
        raw = os.read(fd, 131073)
        assert not os.read(fd, 1)
        assert full9(os.fstat(fd)) == full9(first) == full9(SOURCE.lstat())
        assert (len(raw), hashlib.sha256(raw).hexdigest()) == EXPECTED_SOURCE
    finally:
        os.close(fd)
    tree = ast.parse(raw)
    # Load definitions and constants without activating the caller or its main entry.
    nodes = [node for node in tree.body
             if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))
             or (isinstance(node, ast.Assign)
                 and not any(isinstance(target, ast.Name) and target.id == 'ADMITTED'
                             for target in node.targets))]
    values = {'__file__': str(SOURCE), '__name__': 'ownership_regression_fixture'}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), values)
    return values


def fixture(name):
    case = Path(FIXTURE_ROOT) / name
    case.mkdir()
    linux, projection = case / 'linux', case / 'projection'
    linux.mkdir(); (linux / 'windows-actions').mkdir(); projection.mkdir()
    (linux / 'action.lock').write_bytes(b'')
    root = projection / 'named-fixtures-9001'; root.mkdir()
    values = namespace()
    values.update(LINUX=linux, PROJECTION=projection,
                  subprocess=SimpleNamespace(Popen=forbidden, run=forbidden))
    admission = {'action': '9001', 'suite': 'compile', 'nonce': '0' * 32, '_raw': b'{}'}
    began = time.monotonic_ns()
    budget = values['Budget'](began, began + 20_000_000_000, began + 25_000_000_000)
    return values, admission, began, budget, root, linux / 'windows-actions/9001'


def forbidden(*args, **kwargs):
    raise AssertionError('No materialization, process or Windows invocation is permitted.')


Path(FIXTURE_ROOT).mkdir(mode=0o700)
# Model a collision after a successful fresh-root preflight. Exclusive creation
# must still govern cancellation even when the earlier check could not see it.
v, a, began, budget, root, local = fixture('collision')
(root / 'sentinel').write_bytes(b'keep')
v['verify_admission'] = lambda *args: ([], b'', b'')
v['checkpoint'] = lambda *args: ([0, 0, 0, 0], [0, 1, 0, 7], [0, 1, 0, 7])
v['materialize_inputs'] = v['transport'] = forbidden
assert v['original'](a, began, began + 3_600_000_000_000, budget) == 1
assert sorted(path.name for path in root.iterdir()) == ['sentinel']
assert (root / 'sentinel').read_bytes() == b'keep'
result = v['decode']((local / 'original-failure.json').read_bytes())
assert result['cancelSkippedUnownedRoot'] is True and result['failureType'] == 'FileExistsError'

# A worker failing before its durable parent/root binding cannot cancel that root.
v, a, began, budget, root, local = fixture('unbound-worker')
local.mkdir()
v['open'] = lambda *args, **kwargs: io.BytesIO(b'0::/unbound-fixture\n')
v['transport'] = forbidden
assert v['worker'](a, began, began + 3_600_000_000_000,
                   began, began + 1_200_000_000_000, budget) == 1
assert not list(root.iterdir())
result = v['decode']((local / 'worker-result.json').read_bytes())
assert result['cancelSkippedUnownedRoot'] is True

# Preserve ordinary cancellation and failure retention for an acquired root.
v, a, began, budget, root, local = fixture('owned-cancel')
local.mkdir()
result = {'schema': 'ownership-regression-fixture-v1', 'stage': 'fixture',
          'failureType': 'FixtureFailure', 'caughtFailure': None}
assert v['retain_failure'](local, root, budget, result, 'original',
                           'original-failure.json', True) == 1
assert (root / 'cancel').read_bytes() == b''
assert (local / 'original-first-failure.json').is_file()
assert (local / 'original-failure.json').is_file()
assert 'cancelSkippedUnownedRoot' not in result
print('Three controlled root-ownership regressions passed.')
