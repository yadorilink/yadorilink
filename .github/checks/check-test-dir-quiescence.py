#!/usr/bin/env python3
"""Require daemon tests to wait for capture quiescence before a directory rename or removal.

On Windows a directory cannot be renamed or removed while any file below it is open, and the
daemon opens files transiently while it captures. A daemon integration test that renames or
removes a directory right after an index wait races those opens. The cure is
`support::quiescence::wait_quiescent` (directly, or through `wait_devices_quiescent`,
`remove_dir` or `rename_dir`), called earlier in the same function.

This guard scans the daemon tests that mutate synced directories (`GUARDED`, which a new such
test file must join) for `remove_dir_all(` and `fs::rename(` and
fails for each call whose enclosing function has no quiescence call before it. A call that is
safe for another reason (a file, or a directory no daemon watches) carries
`// quiescence-exempt: <reason>` on its line or the line above.

The same files, plus the Taguchi and row 14 matrices (`SWALLOW_GUARDED`), must not discard a
rename or removal result with `let _ =`: a failed rename hides exactly the defect the matrix
exists to find. Use `support::rename_unless_vanished` / `support::remove_file_unless_vanished`,
which tolerate only a file that is already gone.

Run with no arguments to check the tree and `--self-test` to exercise the check.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = "crates/yadorilink-daemon/tests"
GUARDED = (
    "directory_conflict_matrix.rs",
    "large_tree_gate.rs",
    "native_e2e_support/mod.rs",
    "rewind_execute.rs",
    "taguchi_collision_matrix_v3.rs",
)

SWALLOW_GUARDED = GUARDED + (
    "taguchi_collision_matrix.rs",
    "row14_strict_acceptance.rs",
)

SWALLOWED = re.compile(r"\blet\s+_\s*=\s*[\w:]*\b(?:rename|remove_file|remove_dir|remove_dir_all)\(")
MUTATION = re.compile(r"\bremove_dir_all\(|\bfs::rename\(")
QUIESCENCE = re.compile(r"\bwait_quiescent\(|\bwait_devices_quiescent\(")
FUNCTION = re.compile(r"^\s*(pub(\([a-z]+\))?\s+)?(async\s+)?fn\s")
EXEMPT = "quiescence-exempt:"


def check_text(rel: str, text: str) -> list[str]:
    errors: list[str] = []
    lines = text.splitlines()
    quiesced = False
    for number, line in enumerate(lines, 1):
        if FUNCTION.match(line):
            quiesced = False
        code = line.split("//", 1)[0]
        if QUIESCENCE.search(code):
            quiesced = True
        if not MUTATION.search(code):
            continue
        exempt = EXEMPT in line or (number > 1 and EXEMPT in lines[number - 2])
        if not quiesced and not exempt:
            errors.append(
                f"{rel}:{number}: directory rename/removal without a preceding "
                "`wait_quiescent` in the same function (or `// quiescence-exempt: <reason>`)"
            )
    return errors


def check_swallowed(rel: str, text: str) -> list[str]:
    return [
        f"{rel}:{number}: rename/removal result discarded with `let _ =` "
        "(use `support::rename_unless_vanished` / `support::remove_file_unless_vanished`)"
        for number, line in enumerate(text.splitlines(), 1)
        if SWALLOWED.search(line.split("//", 1)[0])
    ]


def check_tree(root: Path) -> list[str]:
    errors: list[str] = []
    for name in GUARDED:
        path = root / TESTS / name
        if not path.is_file():
            errors.append(f"{TESTS}/{name}: guarded file is missing; update GUARDED")
            continue
        errors += check_text(path.relative_to(root).as_posix(), path.read_text(encoding="utf-8"))
    for name in SWALLOW_GUARDED:
        path = root / TESTS / name
        if not path.is_file():
            if name not in GUARDED:
                errors.append(f"{TESTS}/{name}: guarded file is missing; update SWALLOW_GUARDED")
            continue
        errors += check_swallowed(
            path.relative_to(root).as_posix(), path.read_text(encoding="utf-8")
        )
    return errors


def self_test() -> None:
    bad = "async fn t() {\n    std::fs::remove_dir_all(p).unwrap();\n}\n"
    assert len(check_text("x.rs", bad)) == 1
    good = "async fn t() {\n    wait_quiescent(r, s, g).await;\n    std::fs::fs::rename(a, b);\n}\n"
    assert not check_text("x.rs", good.replace("fs::fs::", "fs::"))
    reset = (
        "async fn a() {\n    wait_quiescent(r, s, g).await;\n}\n"
        "async fn b() {\n    std::fs::rename(a, b).unwrap();\n}\n"
    )
    assert len(check_text("x.rs", reset)) == 1
    exempt = "fn f() {\n    // quiescence-exempt: a file\n    std::fs::rename(a, b);\n}\n"
    assert not check_text("x.rs", exempt)
    commented = "fn f() {\n    // std::fs::remove_dir_all(p)\n}\n"
    assert not check_text("x.rs", commented)
    swallowed = "fn f() {\n    let _ = std::fs::rename(a, b);\n    let _ = fs::remove_file(p);\n}\n"
    assert len(check_swallowed("x.rs", swallowed)) == 2
    assert not check_swallowed("x.rs", "fn f() {\n    // let _ = fs::rename(a, b);\n}\n")
    assert not check_swallowed("x.rs", "fn f() {\n    rename_unless_vanished(a, b);\n}\n")
    with tempfile.TemporaryDirectory() as tmp:
        tests = Path(tmp) / TESTS
        (tests / "native_e2e_support").mkdir(parents=True)
        for name in SWALLOW_GUARDED:
            (tests / name).write_text(bad if name == "rewind_execute.rs" else "", encoding="utf-8")
        found = check_tree(Path(tmp))
        assert len(found) == 1 and "rewind_execute.rs" in found[0], found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("test directory quiescence guard self-test passed")
        return 0
    errors = check_tree(ROOT)
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
