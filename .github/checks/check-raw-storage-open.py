#!/usr/bin/env python3
"""Keep the unlocked storage openers behind a short, reviewed list of callers.

`SyncDatabase::open_process_locked` and `SegmentBlockStore::open_process_locked{,_with}` open the
replica database and the block store for a process that already holds the data area's exclusion
(the data-resource locks, or a writer lease). The block store's recovery truncates and removes
bytes a live writer may have staged, so opening it from a second process without that exclusion
destroys the first process's in-flight writes. The type system cannot say "the caller holds the
lock" across these crates, so the call sites are pinned instead: a library source file that names
either opener must be in `ALLOWED` with the exact number of mentions and the reason. A file with
a different count fails, in either direction, so a new caller (even in an allowed file) is a
reviewed change to this list. Comments and string literals are not mentions. Code reached through the foreign-language binding never names
them: a host gets the engine through `EmbeddedHost`, whose start takes the locks first.

Not scanned: integration tests, benches and examples (they own their directories), and test
modules (`tests.rs`, `*_tests.rs`, `tests/`). Code inside an inline `#[cfg(test)]` module of an
allowed file is counted like any other. A production module named like a test file is not
scanned; the file name is the convention this guard trusts.

    check-raw-storage-open.py [--self-test]
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

OPENER = re.compile(r"\bopen_process_locked(?:_with)?\b")

ALLOWED = {
    "crates/yadorilink-sqlite-runtime/src/database.rs": (1, "defines the database opener"),
    "crates/yadorilink-local-storage/src/segment_store/mod.rs": (4, "defines the store opener and the lease-checked `open_exclusive`"),
    "crates/yadorilink-local-storage/src/segment_store/index.rs": (1, "the store's own index, opened inside the store's open"),
    "crates/yadorilink-sync-sqlite/src/exclusive_open.rs": (5, "the lease-checked database open"),
    "crates/yadorilink-daemon/src/engine_startup.rs": (1, "`open_data` requires the engine's `DataResourceLocks`"),
    "crates/yadorilink-daemon/src/replica_coordinator.rs": (1, "opened only from `open_data`, under the same locks"),
    "crates/yadorilink-send/src/session.rs": (1, "Track Send's own block store under the config directory, opened by the engine that holds the data locks"),
    "crates/yadorilink-send/src/store.rs": (1, "Track Send's database, opened by the same engine"),
}


# Block comments, line comments and string literals, in the order they can appear in Rust source
# (a raw string or a nested block comment is out of scope: a miss there only adds a mention).
NOISE = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"', re.S)


def code_only(text: str) -> str:
    return NOISE.sub(" ", text)


def is_test_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name == "tests.rs" or name.endswith("_tests.rs") or "/tests/" in rel


def scan(root: Path) -> list[str]:
    problems: list[str] = []
    seen: set[str] = set()
    for path in sorted(root.glob("crates/*/src/**/*.rs")):
        rel = path.relative_to(root).as_posix()
        if is_test_file(rel):
            continue
        count = len(OPENER.findall(code_only(path.read_text(encoding="utf-8"))))
        if count == 0:
            continue
        seen.add(rel)
        if rel not in ALLOWED:
            problems.append(
                f"{rel}: names an unlocked storage opener; open through `open_exclusive` or "
                "the engine's locked path, or add the file to ALLOWED with the reason"
            )
        elif ALLOWED[rel][0] != count:
            problems.append(
                f"{rel}: names an unlocked opener {count} time(s), ALLOWED says "
                f"{ALLOWED[rel][0]}; review the change and update the list"
            )
    for rel in sorted(set(ALLOWED) - seen):
        problems.append(f"{rel}: in ALLOWED but no longer names an unlocked opener; remove it")
    return problems


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "crates/x/src"
        src.mkdir(parents=True)
        (src / "bad.rs").write_text("fn f() { Db::open_process_locked(p); }\n", encoding="utf-8")
        (src / "tests.rs").write_text("fn f() { Db::open_process_locked(p); }\n", encoding="utf-8")
        (src / "noise.rs").write_text('// open_process_locked\n/* open_process_locked */ let s = "open_process_locked";\n', encoding="utf-8")
        (src / "fine.rs").write_text("fn f() { Db::open_exclusive(p); }\n", encoding="utf-8")
        found = [p for p in scan(root) if p.startswith("crates/x/")]
        ok = len(found) == 1 and "bad.rs" in found[0]
        stale = [p for p in scan(root) if "in ALLOWED" in p]
        ok = ok and len(stale) == len(ALLOWED)
    print("self-test", "ok" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    problems = scan(ROOT)
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
