#!/usr/bin/env python3
"""Fail when a content-materialization write bypasses a crash-safe journal seam.

A file's blocks reach disk through exactly one low-level primitive,
`chunker::reconstruct_file`. Startup/periodic repair
(`materialization::repair_interrupted_materializations`) has to tell a
crash-mid-materialize (a `Hydrated` row whose file is missing but whose blocks
are present -> RECONSTRUCT) from an offline user-delete (same state ->
tombstone). That disambiguation only works if EVERY path that commits a
`Hydrated` content row with a still-pending disk write first records a durable
signal it can read back after a crash. Three such disciplines exist:

  * the materialization-intent journal (`MaterializationIntentGuard` in
    daemon `materialization_intent.rs`): write a durable intent BEFORE the bytes, clear it
    only AFTER the rename. Used by repair's own reconstruct and by the live peer
    materialize path.
  * the `Placeholder`/`Hydrating` -> `Hydrated` atomic flip: the row is only
    flipped to `Hydrated` AFTER the rename, so a crash leaves a non-`Hydrated`
    row that repair's pre-filter skips. Used by the hydrate paths.
  * the durable `restore_operations` journal: the intended version is recorded
    before the atomic replacement and reconciled against disk on restart. Used
    by the restore path.

This guard makes the class un-reintroducible in two ways:

1. The materialization-intent WRITE primitives
   (`begin_materialization_intent`, `clear_materialization_intent`) may be
   called only from the guard, startup repair, or an identically named method
   on a narrow materialization port adapter.
   A new path may not hand-roll intent bookkeeping — it must go through the
   guard. (The `has_materialization_intent` READ is unrestricted: repair, the
   live invariant `debug_assert`, and tests all consult it.)

2. Every production `reconstruct_file(` call site (or call of the daemon's
   off-runtime forwarder to it) must live in one of the sanctioned seam files
   above, and the total number of such call sites is pinned. A new content write anywhere — even an extra one inside an
   already-sanctioned file — trips the guard for review, forcing the author to
   confirm it is bracketed by one of the three disciplines.
"""

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = [
    ROOT / "crates/yadorilink-peer-session/src",
    ROOT / "crates/yadorilink-filesystem-sync/src",
    ROOT / "crates/yadorilink-daemon/src",
]

# The intent-journal WRITE primitives. A trailing `(` keeps the bare-name match
# from also catching `has_materialization_intent(` (a read, allowed anywhere).
INTENT_WRITE_TOKENS = (
    "begin_materialization_intent(",
    "clear_materialization_intent(",
)

# Files that own a complete crash-safe intent discipline rather than merely
# forwarding a narrow port method.
INTENT_WRITE_ALLOWED_FILES = {
    # The guard owns the durable begin/clear pairing.
    "crates/yadorilink-daemon/src/materialization_intent.rs",
    # Startup repair is itself a journal seam: it clears a recovered intent
    # only after reconstruction succeeds or the row is safely demoted.
    "crates/yadorilink-filesystem-sync/src/materialization_repair.rs",
}

# These composition-root modules implement the two materialization ports. A
# raw primitive is legal there only while implementing the identically named
# port method; this preserves the capability seam without exempting either
# file wholesale.
INTENT_PORT_ADAPTER_FILES = {
    "crates/yadorilink-daemon/src/replica_coordinator/materialization_execution.rs",
    "crates/yadorilink-daemon/src/replica_coordinator/materialization_state.rs",
}

# The single low-level content-to-disk writer.
RECONSTRUCT_TOKEN = "reconstruct_file("
# The publishing half of that writer when a caller assembles into a temp file
# first and renames it into place later. A caller that assembles, re-checks the
# path and then publishes writes content at the publish, so that call is the
# content-write site.
PERSIST_TOKEN = "persist_reconstructed_file("

# The daemon runs that writer off the async runtime through one thin
# forwarder. The forwarder's own inner `reconstruct_file(` is legal only inside
# the forwarder and is not a call site of its own; every call of the forwarder
# is a content-write site and is counted and file-restricted exactly like a
# direct `reconstruct_file(` call.
RECONSTRUCT_FORWARDER_FILE = "crates/yadorilink-daemon/src/local_convergence/types.rs"
RECONSTRUCT_FORWARDER = "reconstruct_file_off_runtime"
PERSIST_FORWARDER = "persist_reconstructed_file_off_runtime"
# The writer and the publish take a temp-file ledger through their `_in`
# variants, and production callers use those; the bare names above are only
# thin `NoTempLedger` wrappers. Both spellings are content-write sites, or the
# guard stops seeing the real call sites (it did, and counted 1 of 4).
RECONSTRUCT_IN_TOKEN = "reconstruct_file_in("
PERSIST_IN_TOKEN = "persist_reconstructed_file_in("
FORWARDER_OF = {
    RECONSTRUCT_TOKEN: RECONSTRUCT_FORWARDER,
    PERSIST_TOKEN: PERSIST_FORWARDER,
    PERSIST_IN_TOKEN: PERSIST_FORWARDER,
}
RECONSTRUCT_SITE_TOKENS = (
    RECONSTRUCT_TOKEN,
    PERSIST_TOKEN,
    RECONSTRUCT_IN_TOKEN,
    PERSIST_IN_TOKEN,
    RECONSTRUCT_FORWARDER + "(",
    PERSIST_FORWARDER + "(",
)

# The sanctioned content-write seam files (each upholds one of the three
# crash-safe disciplines described above). A content-write call anywhere else
# is a violation.
RECONSTRUCT_ALLOWED_FILES = {
    # Intent-journal seam (repair's own reconstruct).
    "crates/yadorilink-filesystem-sync/src/materialization_repair.rs",
    # Hydrating->Hydrated flip (daemon hydrate) + restore_operations journal
    # (restore).
    "crates/yadorilink-daemon/src/hydration.rs",
    # Intent-journal seam (live peer materialize), via the forwarder.
    "crates/yadorilink-daemon/src/local_convergence/materialize/eager.rs",
}

# Pinned total number of production content-write call sites across the
# sanctioned files. Bump this ONLY when adding a reviewed, provably crash-safe
# content-write site (and confirm it is bracketed by one of the three
# disciplines). Current sites:
#   materialization_repair.rs:    reconstruct_file_journaled                 (1)
#   hydration.rs:                 daemon hydrate publish + restore publish   (2)
#   materialize/eager.rs:         eager write publish (via the forwarder)    (1)
# Hydration, restore and the eager peer-update write assemble into a temp file,
# re-check the disk under the path lock and only then publish it with
# `persist_reconstructed_file`, so the publish is the content-write site.
EXPECTED_RECONSTRUCT_CALLS = 4

# Test code is recognised the same way the materialization-semantic guard
# recognises it, by loading that script's scanner instead of keeping another
# copy: an item under a test-only `cfg` is skipped wherever it sits, and a
# module FILE declared under such a `cfg` in its parent (file-per-module test
# files such as `foo/tests.rs`), or opening with `#![cfg(test)]`, is skipped
# whole. Test fixtures legitimately seed intents and call the writer directly.
_SEMANTIC_GUARD = ROOT / ".github" / "checks" / "check-materialization-semantic-boundary.py"


def _load_semantic_guard():
    spec = importlib.util.spec_from_file_location(
        "check_materialization_semantic_boundary", _SEMANTIC_GUARD
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


SEMANTIC = _load_semantic_guard()


def production_lines(path: Path) -> list[tuple[int, str]]:
    """`(1-based line number, code)` for every PRODUCTION line of one file."""
    return SEMANTIC.production_lines(path, path.read_text(encoding="utf-8"))


def in_matching_port_method(
    lines: list[tuple[int, str]], index: int, method: str
) -> bool:
    """Return whether a hit is inside the adapter's identically named method."""
    for _, candidate in reversed(lines[: index + 1]):
        stripped = candidate.strip()
        if stripped.startswith("fn "):
            return stripped.startswith(f"fn {method}(")
    return False


def enclosing_fn(lines: list[tuple[int, str]], index: int) -> str | None:
    """Name of the nearest `fn` declared at or above a hit, if any."""
    for _, candidate in reversed(lines[: index + 1]):
        match = SEMANTIC.FN_NAME.match(candidate)
        if match:
            return match.group(1)
    return None


def main() -> int:
    violations: list[str] = []
    reconstruct_hits = 0
    # Parents of a test module can live in any crate's source tree, so the
    # test-module set is computed over all of them.
    test_files = SEMANTIC.test_module_files(sorted(ROOT.glob(SEMANTIC.SOURCE_GLOB)))
    for source_root in SOURCE_ROOTS:
        for path in sorted(source_root.rglob("*.rs")):
            rel = str(path.relative_to(ROOT))
            if path.resolve() in test_files:
                continue
            lines = production_lines(path)
            for index, (lineno, line) in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue

                for token in INTENT_WRITE_TOKENS:
                    if token not in line:
                        continue
                    # Skip the primitive's own definition.
                    if ("fn " + token[:-1]) in line:
                        continue
                    method = token[:-1]
                    adapter_delegation = (
                        rel in INTENT_PORT_ADAPTER_FILES
                        and in_matching_port_method(lines, index, method)
                    )
                    if rel not in INTENT_WRITE_ALLOWED_FILES and not adapter_delegation:
                        violations.append(
                            f"{rel}:{lineno}: raw `{token[:-1]}` outside the "
                            f"MaterializationIntentGuard seam — route intent "
                            f"bookkeeping through the guard"
                        )

                for token in RECONSTRUCT_SITE_TOKENS:
                    if token not in line or ("fn " + token[:-1]) in line:
                        continue
                    if (
                        token in FORWARDER_OF
                        and rel == RECONSTRUCT_FORWARDER_FILE
                        and enclosing_fn(lines, index) == FORWARDER_OF[token]
                    ):
                        continue
                    if rel in RECONSTRUCT_ALLOWED_FILES:
                        reconstruct_hits += 1
                    else:
                        violations.append(
                            f"{rel}:{lineno}: `{token[:-1]}` writes content to disk "
                            f"outside a sanctioned crash-safe materialization seam"
                        )

    exit_code = 0
    if violations:
        print(
            "content materialization must go through a crash-safe journal seam "
            "(MaterializationIntentGuard, the Hydrating->Hydrated flip, or the "
            "restore_operations journal)",
            file=sys.stderr,
        )
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        exit_code = 1

    if reconstruct_hits != EXPECTED_RECONSTRUCT_CALLS:
        print(
            f"expected {EXPECTED_RECONSTRUCT_CALLS} production `reconstruct_file` call "
            f"site(s) in sanctioned seams, found {reconstruct_hits}. A new content-write "
            f"site must be confirmed crash-safe and this count bumped; a removed one must "
            f"lower it.",
            file=sys.stderr,
        )
        exit_code = 1

    if exit_code == 0:
        print(
            f"materialization journal: ok "
            f"({reconstruct_hits} sanctioned content-write sites)"
        )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
