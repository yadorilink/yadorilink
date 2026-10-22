#!/usr/bin/env python3
"""Ban silently collapsing a link-table read into "there are no links".

`list_links()` is fallible. Turning that error into an empty list with
`.unwrap_or_default()` does not mean "no links"; it means "I could not tell".
The two are not interchangeable, and the daemon acts on the difference:

  * The startup path uses the link list to run crash-recovery repair and to
    start each folder's watcher, which is what arms that group's startup gate.
    An empty list skips both, silently, for every folder.
  * The peer path resolves its sync roots from the same table, independently.
    It does not observe the startup path's failure.

So a swallowed enumeration error does not stop syncing -- it removes the
scan and the gate while leaving the writes. An inbound peer change then lands
in a folder that was never scanned this boot and overwrites local bytes that
were never indexed, with no conflict copy, because the local content never
became a change the DAG could see. Silent, and the user's own data.

The same shape is fine on a read-only diagnostic path, where "no links" merely
produces an unhelpful answer. What is never fine is doing it *silently*: this
guard requires the error to be surfaced, so the collapse is a visible decision
at the call site rather than a default that reads as routine.

ALLOWED (explicit, error surfaced):
    let links = state.sync_state.list_links().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "cannot read link table; ...");
        Vec::new()
    });

ALLOWED (fail-closed, preferred on any path that writes or gates):
    let links = sync_state.list_links()?;

BANNED:
    for link in sync_state.list_links().unwrap_or_default() { ... }
    let links = state.sync_state.list_links().unwrap_or(vec![]);
    let links = state.sync_state.list_links().ok().unwrap_or_default();

Run with --self-test to prove the guard still detects the shape it bans.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Production sources only; tests may model a failing table deliberately.
SCAN_DIRS = [
    ROOT / "crates/yadorilink-daemon/src",
    ROOT / "crates/yadorilink-cli/src",
    ROOT / "crates/yadorilink-client-core/src",
    ROOT / "crates/yadorilink-sync-sqlite/src",
]

# `list_links()` followed by any of the silent-collapse tails.
BANNED = re.compile(
    r"list_links\(\)\s*\.\s*(unwrap_or_default\(\)|unwrap_or\(|ok\(\)|unwrap_or_else\(\s*\|_)"
)


def offenders(text: str) -> list[tuple[int, str]]:
    hits = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        if BANNED.search(line):
            hits.append((lineno, stripped))
    return hits


def self_test() -> int:
    bad = [
        "    for link in sync_state.list_links().unwrap_or_default() {",
        "    let links = state.sync_state.list_links().unwrap_or(vec![]);",
        "    let links = state.sync_state.list_links().ok();",
        "    let links = state.sync_state.list_links().unwrap_or_else(|_| Vec::new());",
    ]
    good = [
        "    let links = sync_state.list_links()?;",
        "    let links = state.sync_state.list_links().unwrap_or_else(|e| {",
        "    // for link in sync_state.list_links().unwrap_or_default() {",
    ]
    failures = []
    for line in bad:
        if not offenders(line):
            failures.append(f"self-test: should have been flagged but was not: {line.strip()}")
    for line in good:
        if offenders(line):
            failures.append(f"self-test: should NOT have been flagged: {line.strip()}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("check-link-enumeration-fail-closed self-test: ok")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()

    findings = []
    scanned = 0
    for directory in SCAN_DIRS:
        if not directory.exists():
            print(f"guard scan dir not found: {directory}", file=sys.stderr)
            return 1
        for path in sorted(directory.rglob("*.rs")):
            scanned += 1
            for lineno, line in offenders(path.read_text(encoding="utf-8")):
                findings.append(f"{path.relative_to(ROOT)}:{lineno}: {line}")

    if findings:
        print(
            "A fallible link-table read is silently collapsing to 'no links'.\n"
            "'I could not read the links' is not 'there are no links' -- the startup\n"
            "path would skip repair, the watcher, and the startup gate for every\n"
            "folder, while the peer path keeps resolving roots and applying changes\n"
            "into folders that were never scanned.\n\n"
            "Use `list_links()?` to fail closed, or surface the error explicitly:\n"
            "    .unwrap_or_else(|e| { tracing::warn!(error = %e, \"...\"); Vec::new() })\n",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1

    print(f"check-link-enumeration-fail-closed: ok ({scanned} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
