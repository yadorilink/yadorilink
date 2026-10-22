#!/usr/bin/env python3
"""Fail when production code bypasses the change-emitting index-mutation seam.

Every LOCAL current-row mutation must append its signed change to the history
DAG in the same transaction — the job of the `*_emitting_change` family in
`index.rs`. This guard forbids the raw, non-emitting current-row writers
(`upsert_file`, `upsert_files_batch`, `set_exec_bit`, `set_record_kind`,
`mark_deleted_at`) from being called in production local-capture, peer-session,
or daemon code outside the SQLite repository and its narrow port adapters, so
a new DAG-silent local write cannot quietly reappear.

Allowed unconditionally:
  - the `*_emitting_change` family (an emitting local write), and
  - `upsert_file_with_origin` (applying a peer's already-signed change,
    correctly index-only / DAG-silent — the Projected seam).
Both are excluded by construction: the forbidden tokens require a `(`
immediately after the bare name, so `upsert_file_emitting_change(`,
`upsert_files_batch_emitting_change(`, and `upsert_file_with_origin(` never
match.

A small allowlist pins the handful of known-legit raw calls that remain:
index-only Projected metadata application in peer-session, and the two
sanctioned non-emitting local-capture paths (a group whose change
DAG has not been seeded yet, and the standalone no-emitter build). The total
allowed-hit count is pinned so a new raw call — even one that happens to share
an allowlisted snippet — trips the guard for review.
"""

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = [
    ROOT / "crates/yadorilink-local-capture/src",
    ROOT / "crates/yadorilink-peer-session/src",
    ROOT / "crates/yadorilink-daemon/src",
]

# The SQLite file-index module defines both raw primitives and the emitting
# wrappers; it is the repository boundary this check protects.
EXEMPT_FILES = {
    "crates/yadorilink-sync-sqlite/src/file_index.rs",
}

# Composition-root implementations of narrow capability ports. These files
# are not exempt: a raw writer is accepted only inside the identically named
# trait method, i.e. as the one direct repository delegation the port exists
# to provide.
PORT_ADAPTER_FILES = {
    "crates/yadorilink-daemon/src/replica_coordinator/local_mutation.rs",
    "crates/yadorilink-daemon/src/replica_coordinator/materialization_state.rs",
    "crates/yadorilink-daemon/src/replica_coordinator/peer_replica_state.rs",
}

# Test code is recognised the same way the materialization-semantic guard
# recognises it, by loading that script's scanner instead of keeping a second
# copy: an item under a `cfg` that holds only in test builds (`#[cfg(test)]`,
# `#[cfg(all(test, unix))]`, `#[cfg(any(test, feature = "test-support"))]`;
# only `test` and `feature = "test-support"` are recognized test gates, so a
# production gate such as `any(test, madsim)` is still scanned) is skipped
# wherever it sits in a file, and a module FILE declared under
# such a `cfg` in its parent (with `#[path]` and nested module directories
# followed), or opening with `#![cfg(test)]`, is skipped whole. A per-file
# scan alone cannot see the parent's attribute, which is why fixtures such as
# `test_support/peer_session_fixture.rs` used to be reported as production.
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

# The non-emitting current-row writers. Each needs a `(` right after the bare
# name so the emitting/Projected wrappers (`*_emitting_change(`,
# `upsert_file_with_origin(`) never match.
FORBIDDEN = (
    "upsert_file(",
    "upsert_files_batch(",
    "set_exec_bit(",
    "set_record_kind(",
    "mark_deleted_at(",
)

# Known-legit raw calls, keyed by repo-relative path -> list of substrings that
# must appear on the offending line for it to be permitted. Every entry is a
# non-emitting write that is provably NOT a DAG-silent local mutation:
#   * peer_session.rs: Projected — applying a peer's already-resolved change /
#     advertised metadata to the local index (index-only by design).
#   * local_change/{scan,event_ingest}.rs: a group with no change DAG yet (seeded by the chunked
#     initial import right after the scan) and the standalone no-emitter build,
#     neither of which has a DAG to diverge from.
ALLOWLIST = {
    "crates/yadorilink-peer-session/src/peer_session.rs": [
        # Projected: apply a peer's advertised metadata (index-only).
        # Both currently match nothing: the metadata application these named
        # moved into `apply_projected_row_atomic`, which writes the columns
        # inside the same transaction as the row. Kept because the seam they
        # permit is still the sanctioned one, so a future Projected write
        # landing here is a reviewed shape rather than a new exception.
        "state.set_record_kind(",
        "state.set_exec_bit(",
    ],
    "crates/yadorilink-daemon/src/replica_coordinator/local_mutation.rs": [
        # The standalone no-emitter build, inside capture's directory
        # operations (`commit_captured_directory`,
        # `commit_directory_removal`): an explicit directory's row, and the
        # point deletes of a vanished directory's observed entries.
        "self.file_index_repository().upsert_files_batch(",
        "self.file_index_repository().mark_deleted_at(",
    ],
    "crates/yadorilink-local-capture/src/local_change/scan.rs": [
        # No change DAG yet: the initial import seeds these rows into history
        # (the chunked scan batch).
        "self.state.upsert_files_batch(",
    ],
    "crates/yadorilink-local-capture/src/local_change/event_ingest.rs": [
        # No change DAG yet: the single-event path a build with no change
        # emitter takes.
        "self.state.upsert_files_batch(",
        # Standalone (no change emitter) delete path.
        "self.state.mark_deleted_at(",
        # Local-column bookkeeping applied right after the emitting write that
        # already carried the same exec bit / symlink kind in its FileVersion.
        # Both currently match nothing: the exec-bit one for the same reason
        # as the peer-session pair above, and the record-kind one since the
        # symlink kind moved into the single-row write that captures it.
        "self.state.set_exec_bit(",
        "self.state.set_record_kind(",
    ],
}

# Pinned total number of allowlisted raw calls across the tree. Bump this (and
# add the ALLOWLIST snippet) only for a reviewed, provably-non-silent site.
#
# The five, enumerated so the next person changing this number can check the
# same list rather than re-deriving it:
#   local_change/scan.rs               upsert_files_batch  x1  -- scan batch
#   local_change/event_ingest.rs       upsert_files_batch  x1  -- no-emitter event
#   local_change/event_ingest.rs       mark_deleted_at     x1  -- no-emitter delete
#   replica_coordinator/local_mutation.rs  upsert_files_batch  x1  -- no-emitter directory
#   replica_coordinator/local_mutation.rs  mark_deleted_at     x1  -- no-emitter observed-set delete
EXPECTED_ALLOWED = 5


def production_lines(path: Path) -> list[tuple[int, str]]:
    """`(1-based line number, code)` for every PRODUCTION line of one file.

    Whole-line comments and trailing `//` comments are dropped, and every
    item under a test-requiring `cfg` is skipped wherever it appears, so a
    mid-file test-only hook cannot hide a real seam bypass after it.
    """
    return SEMANTIC.production_lines(path, path.read_text(encoding="utf-8"))


def in_matching_port_method(
    lines: list[tuple[int, str]], index: int, method: str
) -> bool:
    """Recognize only a port method's delegation to its same-named writer."""
    for _, candidate in reversed(lines[: index + 1]):
        stripped = candidate.strip()
        if stripped.startswith("fn "):
            return stripped.startswith(f"fn {method}(")
    return False


def main() -> int:
    violations: list[str] = []
    allowed_hits = 0
    # Parents of a test module can live in any crate's source tree, so the
    # test-module set is computed over all of them.
    test_files = SEMANTIC.test_module_files(sorted(ROOT.glob(SEMANTIC.SOURCE_GLOB)))
    for source_root in SOURCE_ROOTS:
        for path in sorted(source_root.rglob("*.rs")):
            rel = str(path.relative_to(ROOT))
            if rel in EXEMPT_FILES or path.resolve() in test_files:
                continue
            allowed_snippets = ALLOWLIST.get(rel, [])
            lines = production_lines(path)
            for index, (lineno, line) in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue
                for token in FORBIDDEN:
                    if token not in line:
                        continue
                    if ("fn " + token[:-1]) in line:
                        continue
                    method = token[:-1]
                    adapter_delegation = (
                        rel in PORT_ADAPTER_FILES
                        and in_matching_port_method(lines, index, method)
                    )
                    if adapter_delegation:
                        continue
                    if any(snippet in line for snippet in allowed_snippets):
                        allowed_hits += 1
                    else:
                        violations.append(
                            f"{rel}:{lineno}: raw `{token[:-1]}` bypasses the "
                            f"change-emitting mutation seam"
                        )

    exit_code = 0
    if violations:
        print(
            "local current-row mutations must go through the *_emitting_change "
            "family (or upsert_file_with_origin for Projected peer changes)",
            file=sys.stderr,
        )
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        exit_code = 1
    if allowed_hits != EXPECTED_ALLOWED:
        print(
            f"allowlisted raw-mutation call count changed: expected "
            f"{EXPECTED_ALLOWED}, found {allowed_hits}. Review the new/removed "
            f"site and update EXPECTED_ALLOWED (and ALLOWLIST) in this script.",
            file=sys.stderr,
        )
        exit_code = 1
    if exit_code == 0:
        print("mutation boundary: ok")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
