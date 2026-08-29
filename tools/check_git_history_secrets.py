from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ZERO_SHA = "0" * 40


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def resolve_base() -> str | None:
    candidates = [
        os.environ.get("HK_BASE_REF"),
        "main-v2",
        "origin/main-v2",
        "HEAD^",
    ]
    head = git("rev-parse", "HEAD").stdout.strip()
    for candidate in candidates:
        if not candidate or candidate == ZERO_SHA:
            continue
        if git("rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}").returncode != 0:
            continue
        merge_base = git("merge-base", "HEAD", candidate)
        if merge_base.returncode == 0:
            value = merge_base.stdout.strip()
            if value and value != head:
                return value
        if candidate == "HEAD^":
            return git("rev-parse", "HEAD^").stdout.strip()
    return None


def main() -> int:
    base = resolve_base()
    if base is None:
        print("No prior commit range is available; the current-tree secret scan remains active.")
        return 0

    return subprocess.run(
        [
            "gitleaks",
            "git",
            "--redact",
            "--no-banner",
            f"--log-opts={base}..HEAD",
            str(ROOT),
        ],
        cwd=ROOT,
        check=False,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
