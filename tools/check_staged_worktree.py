from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def changed_paths(*args: str) -> set[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-ext-diff", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return {
        os.fsdecode(path)
        for path in result.stdout.split(b"\0")
        if path
    }


def main() -> int:
    staged = changed_paths("--cached")
    unstaged = changed_paths()
    overlapping = sorted(staged & unstaged)
    if not overlapping:
        return 0

    print(
        "ERROR: staged files also have unstaged edits; checks would not see the "
        "exact commit snapshot:",
        file=sys.stderr,
    )
    for path in overlapping:
        print(f"  {path}", file=sys.stderr)
    print(
        "Stage the intended file content or set its unstaged edits aside, then retry.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
