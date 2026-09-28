# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = []
# ///
"""Check the two inert catalog consumers without importing or running either caller."""

import ast
import hashlib
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1] / "tools/validation/controlled-callers"


def check_bindings(catalog: bytes, python_source: str, powershell_source: str) -> list[str]:
    expected = (len(catalog), hashlib.sha256(catalog).hexdigest())
    errors = []
    assignments = [
        node.value
        for node in ast.parse(python_source).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "CATALOG" for target in node.targets)
    ]
    if len(assignments) != 1 or ast.literal_eval(assignments[0]) != expected:
        errors.append("Python CATALOG must contain the current catalog's exact length and SHA-256.")

    pattern = (
        r'^[ \t]*\$catalogBytes[ \t]*=[ \t]*Hold-Control[ \t]+'
        r'"\$root\\controller-input-catalog\.tsv"[ \t]+131072[ \t]+'
        r"'([0-9a-f]{64})'[ \t]*$"
    )
    pins = re.findall(pattern, powershell_source, re.MULTILINE)
    if pins != [expected[1]]:
        errors.append("PowerShell's sole catalog Hold-Control pin must match the current catalog SHA-256.")
    return errors


def main() -> int:
    try:
        errors = check_bindings(
            (ROOT / "control/controller-input-catalog.tsv").read_bytes(),
            (ROOT / "run_controlled_callers.py").read_text(),
            (ROOT / "Invoke-WindowsControlledCallers.ps1").read_text(),
        )
    except (OSError, SyntaxError, ValueError, TypeError) as error:
        print(f"Cannot check controlled caller catalog bindings: {error}", file=sys.stderr)
        return 1
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print("Controlled caller catalog bindings match both consumers.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
