#!/usr/bin/env python3
"""Forbid masking a corrupt stored block/version list as a default.

A `blocks_json` or `version_json` column holds the block list / version vector
of an indexed file version. Parsing either with `unwrap_or_default()` (or the
`.ok()` / `unwrap_or_else(.. default)` variants) coerces a corrupt, unparseable
column into an *empty block list* or a *reset version vector* instead of
surfacing the fault. An empty block list reads downstream as "file has no
content", so this silently masks genuine index/DB corruption as a legitimately
empty file. Every such parse must fail closed (e.g. map the parse error to
`SyncError::CorruptState`) so on-disk corruption is observable, never coerced
away.

This guard fails if any production Rust source parses `blocks_json` or
`version_json` and then masks a parse failure with a default. Test modules are
excluded (they deliberately construct corrupt columns to prove the fail-closed
behavior).
"""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"

# `from_str( &?blocks_json/version_json )` followed, within the same statement
# (no intervening `;`), by a masking combinator. `[^;]*?` spans whitespace and
# newlines so a multi-line `.unwrap_or_default()` is still caught, but stops at
# the statement boundary so unrelated later code is never matched.
MASKING = re.compile(
    r"from_str\s*(?:::<[^(]*>)?\s*\(\s*&?\s*(?:blocks_json|version_json)\s*\)"
    r"[^;]*?\.\s*(?:unwrap_or_default|ok|unwrap_or_else)\b"
)


def production_text(path: Path) -> str:
    """Source with the trailing `#[cfg(test)] mod tests` block stripped."""
    text = path.read_text(encoding="utf-8")
    return text.split("\n#[cfg(test)]\nmod tests", 1)[0]


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan(text: str) -> list[int]:
    return [line_of(text, m.start()) for m in MASKING.finditer(text)]


def self_test() -> int:
    """Prove the guard catches the masking pattern and clears the fixed form."""
    bad = [
        "let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).unwrap_or_default();",
        "let counters = serde_json::from_str(version_json).unwrap_or_default();",
        "let b = serde_json::from_str(blocks_json).ok().unwrap_or_default();",
        "let b = serde_json::from_str(&blocks_json)\n    .unwrap_or_default();",
        # Turbofish form must not slip past the guard.
        "let b = serde_json::from_str::<Vec<BlockInfo>>(&blocks_json).unwrap_or_default();",
    ]
    good = [
        "let blocks = serde_json::from_str(&blocks_json).map_err(|e| "
        "SyncError::CorruptState(format!(\"corrupt: {e}\")))?;",
        # A different column that is legitimately defaultable is out of scope.
        "let pinned = serde_json::from_str(&pinned_json).unwrap_or_default();",
    ]
    ok = True
    for snippet in bad:
        if not scan(snippet):
            print(f"self-test FAIL: masking not detected: {snippet!r}", file=sys.stderr)
            ok = False
    for snippet in good:
        if scan(snippet):
            print(f"self-test FAIL: fail-closed form flagged: {snippet!r}", file=sys.stderr)
            ok = False
    if ok:
        print("stored-blocklist fail-closed guard self-test OK")
        return 0
    return 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    violations: list[str] = []
    for path in sorted(CRATES.rglob("*.rs")):
        text = production_text(path)
        for line_number in scan(text):
            violations.append(
                f"{path.relative_to(ROOT)}:{line_number}: corrupt stored block/version "
                f"list masked as a default; must fail closed (map to SyncError::CorruptState)"
            )

    if violations:
        print("stored block/version list must fail closed on corruption", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    print("stored-blocklist fail-closed guard OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
