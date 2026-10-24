#!/usr/bin/env python3
"""Every file or directory flush goes through `yadorilink_fs_platform::flush`.

That module is the one place that issues `sync_all`, `sync_data`, `fsync` or
`F_FULLFSYNC` (and, on Windows, `FlushFileBuffers`), and it counts each call, so
the operation-count guards see every flush, including the directory syncs made
inside a durable move. A flush issued anywhere else is invisible to them: it can
be added or dropped without the baseline noticing.

Production code is what `check-materialization-semantic-boundary.py` scans. The
only reviewed exception is listed in `ALLOWLIST` with its reason. Run with no
arguments to check the tree, `--list` to print every flush call outside the
helper, `--self-test` to exercise the check on synthetic fixtures.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "materialization_semantic_boundary",
    Path(__file__).resolve().parent / "check-materialization-semantic-boundary.py",
)
_boundary = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_boundary)

NAMES = (
    "sync_all",
    "sync_data",
    "libc::fsync",
    "libc::fdatasync",
    "FlushFileBuffers",
)
# A call of the helper itself (`flush::sync_data(..)`) is the sanctioned form.
PATTERN = re.compile(r"(?<!flush::)" + _boundary.call_pattern(NAMES).pattern)
# `F_FULLFSYNC` is an argument of `fcntl`, not a call of its own.
FULLFSYNC = re.compile(r"(?<![A-Za-z0-9_])F_FULLFSYNC(?![A-Za-z0-9_])")
HELPER = "crates/yadorilink-fs-platform/src/flush.rs"

ALLOWLIST: dict[str, dict[str, int]] = {
    # Test-support fixtures that damage a segment file on purpose and persist the damage so the
    # next open sees it; they are compiled only for tests and are no product flush.
    "crates/yadorilink-local-storage/src/segment_store/testing.rs": {"sync_data": 4},
    # The Windows shell's flush of a dehydrate or revert through its own raw handle, before the
    # operation is reported done. It adds durability and is not a receive-path flush; the raw
    # handle is not a `std::fs::File` the helper could take.
    "crates/yadorilink-shell-ext-windows/src/provider_namespace.rs": {"FlushFileBuffers": 1},
}


def scan(root: Path) -> list[tuple[str, int, str, str]]:
    hits = [h for h in _boundary.scan(root, PATTERN) if h[0] != HELPER]
    for path in sorted(root.glob(_boundary.SOURCE_GLOB)):
        rel = str(path.relative_to(root))
        if rel == HELPER:
            continue
        for number, code in _boundary.production_lines(path, path.read_text(encoding="utf-8")):
            if FULLFSYNC.search(code):
                hits.append((rel, number, "<module>", "F_FULLFSYNC"))
    return hits


def evaluate(hits: list[tuple[str, int, str, str]], allowlist: dict[str, dict[str, int]]) -> list[str]:
    errors: list[str] = []
    found: Counter = Counter()
    where: dict[tuple[str, str], list[int]] = {}
    for rel, number, _, api in hits:
        found[(rel, api)] += 1
        where.setdefault((rel, api), []).append(number)
    expected = {(rel, api): n for rel, apis in allowlist.items() for api, n in apis.items()}
    for key in sorted(set(found) | set(expected)):
        rel, api = key
        if found[key] == expected.get(key, 0):
            continue
        lines = ", ".join(str(n) for n in where.get(key, [])) or "none"
        if key not in expected:
            errors.append(
                f"{rel}:{lines}: `{api}` bypasses the counted flush helper; "
                "use `yadorilink_fs_platform::flush` (sync_file, sync_directory, sync_data)"
            )
        else:
            errors.append(f"{rel}: `{api}` pinned at {expected[key]}, found {found[key]} (lines: {lines})")
    return errors


def self_test() -> None:
    hit = ("crates/demo/src/lib.rs", 3, "f", "sync_all")
    assert "bypasses" in evaluate([hit], {})[0]
    assert evaluate([hit], {"crates/demo/src/lib.rs": {"sync_all": 1}}) == []
    assert evaluate([], {"crates/demo/src/lib.rs": {"sync_all": 1}}) != []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "crates/demo/src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text(
            "fn f(x: &File) { x.sync_all(); x.sync_data(); flush::sync_data(x); libc::fcntl(fd, libc::F_FULLFSYNC); }\n"
            "#[cfg(test)]\nmod t { fn g(x: &File) { x.sync_all(); } }\n",
            encoding="utf-8",
        )
        helper = root / HELPER
        helper.parent.mkdir(parents=True)
        helper.write_text("fn h(x: &File) { x.sync_all(); }\n", encoding="utf-8")
        found = sorted((h[2], h[3]) for h in scan(root) if h[0] == "crates/demo/src/lib.rs")
        assert [api for _, api in found] == ["F_FULLFSYNC", "sync_all", "sync_data"], found
        assert all(h[0] != HELPER for h in scan(root)), "the helper itself is exempt"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("flush choke point guard self-test passed")
        return 0
    hits = scan(ROOT)
    if args.list:
        for rel, number, enclosing, api in hits:
            print(f"{rel}:{number}\t{enclosing}\t{api}")
        return 0
    errors = evaluate(hits, ALLOWLIST)
    if errors:
        print("every flush must go through the counted helper:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print("flush choke point guard: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
