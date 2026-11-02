#!/usr/bin/env python3
"""Require daemon integration tests to give each daemon a state directory of its own.

`DaemonState::new` resolves the process-wide `YADORILINK_CONFIG_DIR`, so every daemon an
integration-test process builds with it shares one state directory: its service-key pins,
space-management settings and per-device recovery areas. Tests that run as threads of one process
(all tests of a target) would then see each other's files, and consolidating test targets would
widen that sharing. Build a test daemon with `test_support::isolated_daemon_state`, or
`isolated_daemon_state_in` over the previous daemon's `config_dir()` when the test restarts one.

Run with no arguments to check the tree and `--self-test` to exercise the check.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "crates/yadorilink-daemon/tests"
SHARED = re.compile(r"\bDaemonState::new\s*\(")


def violations(path: str, text: str) -> list[str]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if SHARED.search(line.split("//", 1)[0]):
            found.append(
                f"{path}:{number}: builds a daemon over the process-wide state directory; use "
                "`yadorilink_daemon::test_support::isolated_daemon_state`"
            )
    return found


def check_tree() -> list[str]:
    errors: list[str] = []
    for path in sorted(TESTS.rglob("*.rs")):
        errors += violations(path.relative_to(ROOT).as_posix(), path.read_text(encoding="utf-8"))
    return errors


def self_test() -> None:
    assert len(violations("x.rs", "let s = DaemonState::new(id, a, b);\n")) == 1
    assert len(violations("x.rs", "let s = yadorilink_daemon::daemon_state::DaemonState::new (\n")) == 1
    assert not violations("x.rs", "// DaemonState::new(id, a, b)\n")
    assert not violations("x.rs", "let s = test_support::isolated_daemon_state(id, a, b);\n")
    assert not violations("x.rs", "let s = test_support::isolated_daemon_state_in(d, id, a, b);\n")


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        self_test()
        print("test state directory guard self-test passed")
        return 0
    errors = check_tree()
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
