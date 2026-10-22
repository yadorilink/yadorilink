#!/usr/bin/env python3
"""Keep the `links` table's one-live-link-per-group invariant enforceable.

A folder group may be linked to at most ONE folder on a device. The reason is
not tidiness. The file index is group-scoped and path-relative, but every disk
scan is root-scoped and authoritative. With two live roots on one group, each
root's scan walks its own folder, finds the OTHER root's indexed paths absent,
and tombstones them -- signed changes that ride the change-DAG to every device.
The user loses their own files, everywhere, silently, having done nothing but
link a folder twice.

This guard protects the two structural properties that keep that unreachable:

  1. `INSERT INTO links` appears exactly ONCE, inside `insert_link_row`. That
     function is the write chokepoint: it holds the check and the insert in one
     `BEGIN IMMEDIATE` transaction, so two concurrent `link` calls cannot both
     pass. A second insert site anywhere else is a bypass, and it would be a
     bypass that compiles, passes review, and loses data only in the field.

  2. `INSERT OR REPLACE INTO links` appears ZERO times. It is not a safer
     upsert here; it is three silent harms at once, each measured:
       * against a UNIQUE index it does not error, it DELETES the conflicting
         row -- silent link loss,
       * it resets `root_token` to NULL, re-arming root adoption and thereby
         disarming the unmounted-volume guard that stops whole-folder
         tombstoning,
       * it flips `orphaned` 1 -> 0, an un-orphan path nothing in the code
         intends and which resurrects a link whose authorization is gone.

  3. Both schema triggers are still present in `index.rs`. They are the layer
     that survives a writer which never reads the Rust chokepoint -- a raw
     `sqlite3` session, a second process, or a future third insert site.

Run with --self-test to prove the guard still detects the shapes it bans.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

LINK_REPOSITORY_RS = ROOT / "crates/yadorilink-sync-sqlite/src/link.rs"
SCHEMA_RS = ROOT / "crates/yadorilink-sqlite-runtime/src/schema.rs"

# Production sources only. Tests deliberately forge the state this outlaws (see
# `SyncState::force_second_live_link_for_test`) in order to pin what the read
# side does about a database that is ALREADY in it -- which is the case a user
# can already be in today, and the whole reason the read side is hardened.
SCAN_DIRS = [
    ROOT / "crates/yadorilink-daemon/src",
    ROOT / "crates/yadorilink-cli/src",
    ROOT / "crates/yadorilink-client-core/src",
    ROOT / "crates/yadorilink-sync-sqlite/src",
    ROOT / "crates/yadorilink-sqlite-runtime/src",
]

INSERT_OR_REPLACE = re.compile(r"INSERT\s+OR\s+REPLACE\s+INTO\s+links\b", re.IGNORECASE)
PLAIN_INSERT = re.compile(r"INSERT\s+INTO\s+links\b", re.IGNORECASE)

REQUIRED_TRIGGERS = [
    "links_one_live_root_per_group_insert",
    "links_one_live_root_per_group_unorphan",
]


FN_DECL = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")


def _code_lines(text: str):
    """Line numbers and text for PRODUCTION code only.

    Three things are deliberately not production and must not trip this guard:

      * Comment lines. This fix's own code explains at length why
        `INSERT OR REPLACE` is banned, and naming a thing is not doing it.
      * Everything from the file's `#[cfg(test)]` boundary onward. Rust unit
        tests live inline, and a test that pins the SCHEMA layer has to issue
        the exact statement production no longer may.
      * Any `*_for_test` helper. Forging the two-live-roots state is the only
        way to test what the read side does about a database ALREADY in it --
        which is the case a user can already be in, and the reason the read side
        is hardened at all.
    """
    lines = text.splitlines()
    stop = len(lines)
    for i, line in enumerate(lines):
        if line.strip().startswith("#[cfg(test)]"):
            stop = i
            break

    current_fn = ""
    for lineno, line in enumerate(lines[:stop], start=1):
        stripped = line.strip()
        match = FN_DECL.search(stripped)
        if match:
            current_fn = match.group(1)
        if stripped.startswith("//"):
            continue
        if current_fn.endswith("_for_test"):
            continue
        yield lineno, stripped


def or_replace_offenders(text: str) -> list[tuple[int, str]]:
    return [(n, l) for n, l in _code_lines(text) if INSERT_OR_REPLACE.search(l)]


def plain_insert_sites(text: str) -> list[tuple[int, str]]:
    return [
        (n, l)
        for n, l in _code_lines(text)
        if PLAIN_INSERT.search(l) and not INSERT_OR_REPLACE.search(l)
    ]


def self_test() -> int:
    failures = []

    bad_or_replace = [
        '    "INSERT OR REPLACE INTO links (local_path, group_id, paused) VALUES (?1, ?2, 0)",',
        '        tx.execute("insert or replace into links (local_path) VALUES (?1)", p)?;',
    ]
    for line in bad_or_replace:
        if not or_replace_offenders(line):
            failures.append(f"self-test: OR REPLACE should have been flagged: {line.strip()}")

    # A comment explaining the ban is not a violation of it.
    for line in ["    // `INSERT OR REPLACE INTO links` is deliberately NOT used."]:
        if or_replace_offenders(line):
            failures.append(f"self-test: a comment must not be flagged: {line.strip()}")

    bad_insert = ['    "INSERT INTO links (local_path, group_id, paused) VALUES (?1, ?2, 0)",']
    for line in bad_insert:
        if not plain_insert_sites(line):
            failures.append(f"self-test: plain INSERT should have been counted: {line.strip()}")

    # An INSERT into a different table must not be counted.
    for line in ['    "INSERT INTO pending_enrollments (operation_id) VALUES (?1)",']:
        if plain_insert_sites(line):
            failures.append(f"self-test: unrelated table must not be counted: {line.strip()}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("check-link-group-uniqueness self-test: ok")
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
            text = path.read_text(encoding="utf-8")
            for lineno, line in or_replace_offenders(text):
                findings.append(
                    f"{path.relative_to(ROOT)}:{lineno}: INSERT OR REPLACE INTO links: {line}"
                )

    if not LINK_REPOSITORY_RS.exists():
        print(f"guard target not found: {LINK_REPOSITORY_RS}", file=sys.stderr)
        return 1
    repository_text = LINK_REPOSITORY_RS.read_text(encoding="utf-8")

    inserts = plain_insert_sites(repository_text)
    if len(inserts) != 1:
        for lineno, line in inserts:
            findings.append(
                f"{LINK_REPOSITORY_RS.relative_to(ROOT)}:{lineno}: INSERT INTO links outside the "
                f"chokepoint: {line}"
            )
        if not inserts:
            findings.append(
                f"{LINK_REPOSITORY_RS.relative_to(ROOT)}: no `INSERT INTO links` found at all -- the "
                f"write chokepoint `insert_link_row` appears to be gone"
            )

    if not SCHEMA_RS.exists():
        print(f"guard target not found: {SCHEMA_RS}", file=sys.stderr)
        return 1
    schema_text = SCHEMA_RS.read_text(encoding="utf-8")
    for trigger in REQUIRED_TRIGGERS:
        if trigger not in schema_text:
            findings.append(
                f"{SCHEMA_RS.relative_to(ROOT)}: schema trigger `{trigger}` is missing -- the "
                f"database-level backstop is gone"
            )

    if findings:
        print(
            "The one-live-link-per-group invariant has lost an enforcement layer.\n\n"
            "A folder group linked at two folders makes each folder's scan tombstone\n"
            "the other's files -- signed changes that propagate to EVERY device. The\n"
            "user's own data, deleted everywhere, silently.\n\n"
            "All writes to `links` must go through `SyncState::insert_link_row`, which\n"
            "holds the check and the insert in one transaction. `INSERT OR REPLACE` is\n"
            "banned outright on this table: it deletes conflicting rows, NULLs\n"
            "`root_token`, and silently un-orphans.\n",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1

    print(f"check-link-group-uniqueness: ok ({scanned} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
