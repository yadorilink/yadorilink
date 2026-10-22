#!/usr/bin/env python3
"""Keep index reads fail-closed, and off the panic path.

`file_index.rs` (`yadorilink-sync-sqlite`'s `FileIndexRepository`) is the
daemon's local file-row state. A single-row read there is
written as `conn.query_row(...)` and must map ONLY "no such row" to `None`,
propagating every other outcome (corruption, I/O, a locked/busy database, a
schema/column-type mismatch) as an error the caller can defer or abort on.

The correct idiom is `rusqlite::OptionalExtension::optional()?`, which returns
`None` solely for `QueryReturnedNoRows` and forwards all other errors. The
hazard is `query_row(...).ok()`: `.ok()` collapses EVERY error into `None`, so a
transient fault reads back as a wrong "absent/default" answer. The worst case is
`get_file` returning `None` on a transient error, which makes the local-change
path treat an existing file as brand-new and capture a spurious create over a
row that already exists, diverging from peers. Milder cases downgrade to a
dangerous default (`is_paused_for_group` -> `false` un-pauses a paused
group).

This guard therefore fails when production `file_index.rs` code:
  1. ends a `query_row(...)` / `optional(...)` statement with `.ok()` (the
     error-masking read), or
  2. reaches the panic path on the library boundary via `unwrap()`,
     `expect(...)`, `panic!`, `unreachable!`, `assert!`, `assert_eq!`,
     `assert_ne!`, `todo!`, or `unimplemented!` -- a locally-inconsistent
     state must return `SyncError::CorruptState`, not abort the whole daemon.

Test modules (`#[cfg(test)]`) are excluded: tests deliberately `.unwrap()` and
assert. A small pinned allowlist covers any production line that is legitimately
exempt; adding to it forces a reviewer to name the reason.

Run `--self-test` to prove the guard both catches a reintroduced `.ok()` /
boundary panic and clears the fixed forms.
"""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "crates/yadorilink-sync-sqlite/src/file_index.rs"

# A read statement that masks a real error as absent/default. A `query_row`
# (or `optional`) result must be consumed with `.optional()?`, which forwards
# every error but the missing-row case; chaining `.ok()`, `.unwrap_or(..)`,
# `.unwrap_or_default()`, or `.unwrap_or_else(..)` directly onto the read
# instead collapses corruption / I/O / a locked database into a wrong answer.
# `query_row`/`optional` may sit several lines above the masking combinator, so
# allow non-`;` filler (whitespace, the closure, the closing paren) between them
# but stop at the statement boundary so an unrelated later combinator is never
# attributed here (e.g. the legitimate `pinned.unwrap_or(0)` in a SEPARATE
# statement after `.optional()?;`).
OK_MASK = re.compile(
    r"\.\s*(?:query_row|optional)\s*\([^;]*?\)\s*\.\s*"
    r"(?:ok\s*\(\s*\)|unwrap_or\s*\(|unwrap_or_default\s*\(|unwrap_or_else\s*\()"
)

# Boundary panics: any of these on a production line in this library module.
PANIC_TOKENS = re.compile(
    r"\.\s*unwrap\s*\(\s*\)"
    r"|\.\s*expect\s*\("
    r"|\bpanic!\s*\("
    r"|\bunreachable!\s*\("
    r"|\bassert!\s*\("
    r"|\bassert_eq!\s*\("
    r"|\bassert_ne!\s*\("
    r"|\btodo!\s*\("
    r"|\bunimplemented!\s*\("
)

# Pinned allowlist of production lines that are legitimately exempt, keyed by a
# substring that must appear on the offending line. Keep this empty unless a
# reviewer has confirmed the site cannot propagate (e.g. an infallible trait
# method or a `Drop`); a fail-closed read is always preferable.
ALLOWLIST: list[str] = [
    # `encode_xattrs_column` returns `String`, not a `Result`: serializing a
    # `&[(String, Vec<u8>)]` to JSON cannot fail (string keys, byte arrays),
    # so there is no error a caller could be handed. The decode half,
    # `decode_xattrs_column`, is the fail-closed one and returns CorruptState.
    "xattr list is always representable as JSON",
]


def _strip_test_blocks(lines: list[str]) -> list[tuple[int, str]]:
    """Yield `(1-based line number, line)` for PRODUCTION lines only.

    Skips the body of any `#[cfg(test)]`-attributed item (a braced module or a
    single gated statement), matching check-mutation-boundary.py so a mid-file
    test hook cannot hide following production code.
    """
    out: list[tuple[int, str]] = []
    index = 0
    total = len(lines)
    while index < total:
        if lines[index].strip() == "#[cfg(test)]":
            index += 1
            while index < total and lines[index].strip().startswith("#["):
                index += 1
            depth = 0
            opened = False
            while index < total:
                code = lines[index].split("//", 1)[0]
                depth += code.count("{") - code.count("}")
                if "{" in code:
                    opened = True
                index += 1
                if opened:
                    if depth <= 0:
                        break
                elif code.rstrip().endswith(";"):
                    break
            continue
        out.append((index + 1, lines[index]))
        index += 1
    return out


def _allowlisted(line: str) -> bool:
    return any(snippet in line for snippet in ALLOWLIST)


def scan_text(text: str) -> list[tuple[int, str]]:
    """Return `(line, reason)` violations for one source string.

    `.ok()` masks can span lines, so they are matched against the full
    production-only text; boundary panics are matched per line.
    """
    lines = text.splitlines()
    prod = _strip_test_blocks(lines)
    prod_numbers = {n for n, _ in prod}
    prod_by_number = dict(prod)
    violations: list[tuple[int, str]] = []

    # Rebuild a production-only text (test lines blanked) so a multi-line
    # `query_row(...).ok()` still matches while test code stays invisible.
    blanked = [
        line if (i + 1) in prod_numbers else ""
        for i, line in enumerate(lines)
    ]
    prod_text = "\n".join(blanked)
    for m in OK_MASK.finditer(prod_text):
        lineno = prod_text.count("\n", 0, m.start()) + 1
        if _allowlisted(prod_by_number.get(lineno, "")):
            continue
        violations.append(
            (lineno, "index read masks its error as absent/default "
                     "(.ok()/.unwrap_or/.unwrap_or_default/.unwrap_or_else on a "
                     "query_row); use `.optional()?` so only a missing row is None")
        )

    for lineno, line in prod:
        code = line.split("//", 1)[0]
        if _allowlisted(line):
            continue
        if PANIC_TOKENS.search(code):
            violations.append(
                (lineno, "boundary panic in file_index.rs; return "
                         "SyncError::CorruptState instead of aborting the daemon")
            )

    return sorted(set(violations))


def self_test() -> int:
    bad_ok = [
        'let x: Option<i64> = conn.query_row("SELECT a FROM t", [], |r| r.get(0)).ok();',
        "let x = conn\n    .query_row(\n        \"SELECT a FROM t\",\n"
        "        params![g],\n        |r| r.get(0),\n    )\n    .ok();",
        "let x = conn.optional_stmt().query_row(sql, [], f).ok();",
        # Sibling masking combinators that collapse a real error to a default.
        "let n: i64 = conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0);",
        "let n = conn.query_row(sql, [], |r| r.get(0)).unwrap_or_default();",
        "let n = conn.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|_| 0);",
    ]
    bad_panic = [
        "        let conn = self.pool.get().unwrap();",
        '        let v = row.expect("must exist");',
        'assert_eq!(ops.len(), records.len(), "one op per record");',
        "        panic!(\"unreachable state\");",
        "        unreachable!();",
    ]
    good = [
        "let x: Option<i64> = conn.query_row(sql, [], |r| r.get(0)).optional()?;",
        "let x = conn\n    .query_row(sql, params![g], |r| r.get(0))\n    .optional()?;",
        "return Err(SyncError::CorruptState(format!(\"length mismatch: {n}\")));",
        # The fail-closed idiom: read into an Option via `.optional()?`, THEN
        # default the genuine no-row case in a SEPARATE statement. The default
        # here can never mask an error (the error already propagated via `?`).
        "let pinned: Option<i64> = conn.query_row(sql, [], |r| r.get(0)).optional()?;\n"
        "Ok(pinned.unwrap_or(0) != 0)",
        # `.ok()` that is not on a rusqlite read is out of scope.
        "let parsed = value.parse::<u64>().ok();",
    ]
    ok = True
    for snippet in bad_ok:
        if not any("masks its error" in reason for _, reason in scan_text(snippet)):
            print(f"self-test FAIL: masking read not detected:\n{snippet}", file=sys.stderr)
            ok = False
    for snippet in bad_panic:
        if not any("boundary panic" in reason for _, reason in scan_text(snippet)):
            print(f"self-test FAIL: boundary panic not detected: {snippet!r}", file=sys.stderr)
            ok = False
    for snippet in good:
        if scan_text(snippet):
            print(f"self-test FAIL: fail-closed form flagged:\n{snippet}", file=sys.stderr)
            ok = False
    if ok:
        print("index-read fail-closed guard self-test OK")
        return 0
    return 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    if not TARGET.exists():
        print(f"guard target not found: {TARGET}", file=sys.stderr)
        return 1

    text = TARGET.read_text(encoding="utf-8")
    violations = scan_text(text)
    rel = TARGET.relative_to(ROOT)
    if violations:
        print("index reads must fail closed and stay off the panic path", file=sys.stderr)
        for lineno, reason in violations:
            print(f"  {rel}:{lineno}: {reason}", file=sys.stderr)
        return 1

    print("index-read fail-closed guard OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
