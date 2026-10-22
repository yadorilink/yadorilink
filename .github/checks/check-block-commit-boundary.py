#!/usr/bin/env python3
"""Keep block-store publication/removal primitives behind one capability seam.

`yadorilink-local-storage` removes and replaces filesystem objects (retired
block segments, recovery leftovers, materialization temp files) and issues
directory durability barriers. All of that goes through `fs_ops.rs`, so an
audit of "where does this crate unlink, rename, or flush a directory?" has
exactly one place to look. This guard pins that seam:

  * `fs_ops.rs` holds exactly one of each primitive (and no hard-link one); and
  * no other module in the crate calls a raw `fs::hard_link`, `fs::rename`,
    `fs::remove_file`, `fs::remove_dir` or `fs::remove_dir_all`.

The segment store's own ordering invariant (segment bytes are fsynced before
the index transaction that names them commits) is not a textual property; it
is proven by the crash matrix in
`crates/yadorilink-local-storage/tests/segment_store_crash.rs`.
"""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
SEAM = ROOT / "crates/yadorilink-local-storage/src/fs_ops.rs"
LOCAL_STORAGE_SRC = ROOT / "crates/yadorilink-local-storage/src"


def production_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    return text.split("\n#[cfg(test)]\nmod tests", 1)[0]


def is_test_file(path: Path) -> bool:
    return path.name == "tests.rs" or path.name.endswith("_tests.rs")


def locations(pattern: str, text: str) -> list[int]:
    compiled = re.compile(pattern)
    return [index for index, line in enumerate(text.splitlines(), 1) if compiled.search(line)]


def main() -> int:
    if not SEAM.is_file():
        print(
            f"block commit boundary: {SEAM.relative_to(ROOT)} is missing; "
            "retarget this guard to wherever the crate's filesystem seam now lives",
            file=sys.stderr,
        )
        return 1
    seam = production_text(SEAM)
    violations: list[str] = []

    expected_counts = {
        # Retired: publication is a replacing rename, so the seam holds no
        # hard-link primitive and must not grow one back.
        r"\bfs::hard_link\(": (0, "hard-link publication primitive (retired)"),
        r"\bfs::remove_file\(": (1, "physical removal primitive"),
        r"\bfs::rename\(": (1, "atomic replace primitive"),
        r"fs::File::open\(path\)\?\.sync_all\(": (1, "Unix directory durability sync"),
        # Windows documents no directory flush: namespace changes there are the
        # write-through moves of `yadorilink_fs_platform::durable_dir`, and
        # this seam holds neither a directory handle nor a flush.
        r"\bCreateFileW\(": (0, "Windows directory handle open (retired)"),
        r"\bFlushFileBuffers\(": (0, "Windows directory durability flush (retired)"),
    }
    for pattern, (expected, label) in expected_counts.items():
        found = locations(pattern, seam)
        if len(found) != expected:
            violations.append(
                f"{SEAM.relative_to(ROOT)}: expected {expected} {label}, "
                f"found {len(found)} at lines {found}"
            )

    # Every other module must go through `fs_ops` rather than acquire a
    # second raw publication/removal primitive.
    raw_mutation = re.compile(
        r"\b(?:std::)?fs::(?:hard_link|rename|remove_file|remove_dir|remove_dir_all)\("
    )
    for path in sorted(LOCAL_STORAGE_SRC.rglob("*.rs")):
        if path == SEAM or is_test_file(path):
            continue
        for line_number, line in enumerate(production_text(path).splitlines(), 1):
            if line.lstrip().startswith("//"):
                continue
            if raw_mutation.search(line):
                violations.append(
                    f"{path.relative_to(ROOT)}:{line_number}: raw filesystem "
                    "publication/removal outside fs_ops.rs"
                )

    if violations:
        print("block commit boundary violated", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("block commit boundary: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
