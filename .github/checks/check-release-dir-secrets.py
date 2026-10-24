#!/usr/bin/env python3
"""Guard: nothing under .github/release may reach for secrets or the signing environment.

Usage: check-release-dir-secrets.py [--root DIR]
       check-release-dir-secrets.py --self-test

.github/release is part of the published tree, and its scripts run in
unprivileged jobs as well as protected ones. A file there that references
`secrets.*` or the `release-signing` environment is either wired into the
wrong job or quietly widening what a release script can see. The only file
allowed to name them is the gate checker, which exists to police the workflow.
Adding another allowlist entry is a deliberate, reviewed change to this file.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELEASE_DIR = ".github/release"
ALLOWLIST = frozenset({"check-release-gates.py", "check-signing-workflow.py"})
PATTERN = re.compile(r"secrets\.|release-signing")


def problems(root: Path) -> list[str]:
    base = root / RELEASE_DIR
    if not base.is_dir():
        return [f"{RELEASE_DIR} not found under {root}"]
    out = []
    for path in sorted(p for p in base.rglob("*") if p.is_file()):
        rel = path.relative_to(base).as_posix()
        if rel in ALLOWLIST:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # binary file: nothing to scan
        for number, line in enumerate(text.splitlines(), 1):
            if PATTERN.search(line):
                out.append(f"{RELEASE_DIR}/{rel}:{number} references secrets or release-signing; not allowed here")
    return out


def self_test() -> int:
    assert problems(ROOT) == [], problems(ROOT)
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / RELEASE_DIR
        base.mkdir(parents=True)
        (base / "ok.sh").write_text("echo hello\n", encoding="utf-8")
        (base / "check-release-gates.py").write_text("release-signing secrets.X\n", encoding="utf-8")
        assert problems(Path(tmp)) == []
        for label, name, body in [
            ("secret", "new.sh", "x=${{ secrets.TOKEN }}\n"),
            ("environment", "new.yml", "environment: release-signing\n"),
            ("nested", "sub/new.py", "# secrets.FOO\n"),
        ]:
            target = base / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
            assert problems(Path(tmp)), f"not detected: {label}"
            target.unlink()
        assert problems(Path(tmp)) == []
        assert problems(Path(tmp) / "missing"), "missing directory accepted"
    print("ok")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    root = Path(argv[argv.index("--root") + 1]) if "--root" in argv else ROOT
    found = problems(root)
    for line in found:
        print(f"release dir guard failed: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
