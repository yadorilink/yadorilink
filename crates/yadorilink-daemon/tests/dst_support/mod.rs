//! Shared DST support: the no-silent-data-loss invariant checker,
//! expressed once here so every `tests/dst_*.rs` scenario asserts the
//! same invariant rather than each hand-rolling its own ad hoc check.
//!
//! The invariant (`sync-deterministic-testing` spec's "No-Silent-Data-
//! Loss Invariant Checker" requirement): a local write durably observed
//! by the watcher/debounce layer is never silently discarded, except
//! when superseded by a causally-later write or delete according to
//! that path's version vector.
//!
//! Gated on the simulation cfgs like every DST scenario file — a plain
//! `cargo test` sets neither, so it never builds this module.

#![cfg(turmoil)]
#![allow(dead_code)] // not every scenario exercises every method yet

// Failure-diagnostics modules layered on
// top of the triage/corpus machinery (bundle, first-divergence,
// signature memory, shrinker, coverage, lane-budget knob).
/// Same `DST_TRACE_PATH` selector: one exact sync path, a comma-separated
/// list, or `*`. Harness lines and product lines land in one stderr stream
/// and read as a single timeline. Deliberately an `eprintln` rather than
/// `RUST_LOG`, because logging overhead measurably suppresses the races
/// these scenarios exist to catch.
pub fn dst_trace_path(path: &str, msg: impl FnOnce() -> String) {
    static TRACED: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let traced = TRACED.get_or_init(|| std::env::var("DST_TRACE_PATH").ok());
    let selected = match traced.as_deref() {
        None => false,
        Some("*") => true,
        Some(spec) => spec.split(',').any(|candidate| candidate.trim() == path),
    };
    if selected {
        eprintln!("[DSTTRACE {path}] {}", msg());
    }
}

/// Two product-stack devices and the database state scenarios assert on.
// Every support module. None of them names a simulator: the Case IR, the
// oracle, the corpus, the generators, the fault injectors and their
// scheduler are the layer worth keeping, and swapping the execution
// substrate underneath must not touch a line of them. Their own `#[test]`
// runners get virtual time through `sim::block_on`.
pub mod boundary_device;
pub mod boundary_gate;
pub mod bundle;
pub mod case_ir;
pub mod clock;
pub mod clock_gate;
pub mod convergence_driver;
pub mod corpus;
pub mod coverage;
pub mod device_network;
pub mod diagnostics;
pub mod directory_model;
pub mod divergence;
pub mod explore;
pub mod fault;
pub mod fault_carrier;
pub mod fault_clock;
pub mod fault_disk;
pub mod fault_gate;
pub mod fault_schedule;
pub mod fault_sqlite;
pub mod fs_events;
pub mod fs_ops;
pub mod generator;
pub mod lane;
pub mod link;
pub mod namespace_oracle;
pub mod op_applier;
pub mod oracle;
pub mod random_sequences_gate;
pub mod reference_model;
pub mod risk_matrix_gate;
pub mod settle;
pub mod shrinker;
pub mod signature;
/// Where a scenario's simulated runtime is constructed. Compiles on both
/// substrates by design — it is the seam that hides which one is running.
pub mod sim;
pub mod sweep;
pub mod triage;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;

pub fn content_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone)]
enum ObservedKind {
    Write { content_hash: String },
    Delete,
}

#[derive(Debug, Clone)]
struct ObservedWrite {
    kind: ObservedKind,
    /// Monotonic order within this run: a later `seq` for the same path is
    /// trusted to supersede an earlier one, since within one device's own
    /// local write sequence there is no concurrent-edit ambiguity to
    /// resolve. Cross-device causality is not represented here at all — it
    /// lives in the signed change DAG, and `GlobalOracle` (oracle.rs) is the
    /// checker that consults it.
    seq: u64,
}

/// The "shadow oracle": every local write/delete a
/// scenario has durably delivered to the watcher/debounce boundary,
/// keyed by path, retaining only the causally-latest entry per path.
pub struct WriteOracle {
    observed: Mutex<HashMap<String, ObservedWrite>>,
    next_seq: Mutex<u64>,
}

impl WriteOracle {
    pub fn new() -> Self {
        Self { observed: Mutex::new(HashMap::new()), next_seq: Mutex::new(0) }
    }

    fn next_seq(&self) -> u64 {
        let mut seq = self.next_seq.lock().unwrap_or_else(|p| p.into_inner());
        *seq += 1;
        *seq
    }

    /// Records that `path` was durably written with `content`, prior to
    /// (or at) the moment the scenario delivers the corresponding
    /// synthetic watcher event.
    pub fn record_write(&self, path: &str, content: &[u8]) {
        let seq = self.next_seq();
        self.observed.lock().unwrap_or_else(|p| p.into_inner()).insert(
            path.to_string(),
            ObservedWrite {
                kind: ObservedKind::Write { content_hash: content_hash(content) },
                seq,
            },
        );
    }

    /// Records that `path` was durably deleted.
    pub fn record_delete(&self, path: &str) {
        let seq = self.next_seq();
        self.observed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(path.to_string(), ObservedWrite { kind: ObservedKind::Delete, seq });
    }
}

impl Default for WriteOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct InvariantViolation {
    pub path: String,
    pub detail: String,
}

impl std::fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.detail)
    }
}

/// Checks every path the oracle observed against `sync_state`'s current
/// index (and, for a live write, the real file still on disk under
/// `root`), returning one `InvariantViolation` per path that fails the
/// no-silent-data-loss invariant. An empty result means the invariant
/// held for everything this run observed.
///
/// Today's check (single-device scenarios, task group 3/4): a durably
/// observed write must be indexed, not deleted, with content matching
/// what was written — the oracle already collapses to only the
/// causally-latest write per path (`record_write`/`record_delete`
/// overwrite), so no additional "was this superseded by a later local
/// write" branch is needed here. A durably observed delete must be
/// indexed as deleted.
///
/// Not checked here: cross-device supersession and the "present as a
/// conflict-copy, not the live path" branch. Those are `GlobalOracle`'s job
/// (oracle.rs), which decides supersession from real DAG ancestry rather
/// than from anything this single-device shadow oracle records.
pub fn check_no_silent_data_loss(
    oracle: &WriteOracle,
    sync_state: &ReplicaCoordinator,
    group_id: &str,
    root: &Path,
) -> Vec<InvariantViolation> {
    let observed = oracle.observed.lock().unwrap_or_else(|p| p.into_inner());
    let mut violations = Vec::new();

    for (path, entry) in observed.iter() {
        let record = match sync_state.file_index_repository().get_file(group_id, path) {
            Ok(record) => record,
            Err(e) => {
                violations.push(InvariantViolation {
                    path: path.clone(),
                    detail: format!("index lookup failed: {e}"),
                });
                continue;
            }
        };

        match (&entry.kind, record) {
            (ObservedKind::Delete, None) => {
                violations.push(InvariantViolation {
                    path: path.clone(),
                    detail: "deleted but never indexed at all (no tombstone)".to_string(),
                });
            }
            (ObservedKind::Delete, Some(record)) if !record.deleted => {
                violations.push(InvariantViolation {
                    path: path.clone(),
                    detail: "deleted but the index still shows it as live".to_string(),
                });
            }
            (ObservedKind::Delete, Some(_)) => {} // correctly tombstoned

            (ObservedKind::Write { .. }, None) => {
                violations.push(InvariantViolation {
                    path: path.clone(),
                    detail: "written but never indexed".to_string(),
                });
            }
            (ObservedKind::Write { .. }, Some(record)) if record.deleted => {
                violations.push(InvariantViolation {
                    path: path.clone(),
                    detail: "written but the index shows it as deleted".to_string(),
                });
            }
            (ObservedKind::Write { content_hash: expected }, Some(_)) => {
                match std::fs::read(root.join(path)) {
                    Ok(on_disk) => {
                        let actual = content_hash(&on_disk);
                        if &actual != expected {
                            violations.push(InvariantViolation {
                                path: path.clone(),
                                detail: format!(
                                    "indexed, but on-disk content does not match what was \
                                     written (expected hash {expected}, found {actual})"
                                ),
                            });
                        }
                    }
                    Err(e) => {
                        violations.push(InvariantViolation {
                            path: path.clone(),
                            detail: format!("indexed as live, but not readable on disk: {e}"),
                        });
                    }
                }
            }
        }
    }

    violations
}

/// Formats a seed and its violations the way every scenario's panic
/// message should, so a DST failure is always reproducible the same way
/// (task spec's "Invariant violation fails the scenario" scenario:
/// report the seed, the offending path, and the loss point).
pub fn format_violations(seed: u64, violations: &[InvariantViolation]) -> String {
    let lines: Vec<String> = violations.iter().map(|v| format!("  - {v}")).collect();
    format!(
        "seed {seed}: {} no-silent-data-loss violation(s):\n{}",
        violations.len(),
        lines.join("\n")
    )
}

/// validates the checker itself catches each way a write can
/// be silently lost -- fabricating the index state directly (bypassing
/// the debounce pipeline entirely) so each case is isolated and
/// deterministic to set up, rather than relying on a real historical bug
/// reproducing under this specific harness (task group 5's job, once
/// peer reconciliation is wired into a DST scenario).
#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_domain::file::FileRecord;

    fn group_id() -> &'static str {
        "checker-test-group"
    }

    fn setup() -> (ReplicaCoordinator, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state.link_repository().add_link(&root.path().to_string_lossy(), group_id()).unwrap();
        (state, root)
    }

    fn record(path: &str, deleted: bool) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: Vec::new(),
            deleted,
        }
    }

    #[test]
    fn no_violation_when_write_is_indexed_and_on_disk_matches() {
        let (state, root) = setup();
        std::fs::write(root.path().join("a.txt"), b"hello").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                group_id(),
                &record("a.txt", false),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let oracle = WriteOracle::new();
        oracle.record_write("a.txt", b"hello");

        let violations = check_no_silent_data_loss(&oracle, &state, group_id(), root.path());
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn catches_a_write_that_was_never_indexed() {
        let (state, root) = setup();
        std::fs::write(root.path().join("a.txt"), b"hello").unwrap();
        // Deliberately never call state.upsert_file -- simulating the
        // self-echo-race class of bug (a genuine local write silently
        // never reaching the index).

        let oracle = WriteOracle::new();
        oracle.record_write("a.txt", b"hello");

        let violations = check_no_silent_data_loss(&oracle, &state, group_id(), root.path());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].path, "a.txt");
        assert!(violations[0].detail.contains("never indexed"), "{violations:?}");
    }

    #[test]
    fn catches_a_write_indexed_as_deleted() {
        let (state, root) = setup();
        std::fs::write(root.path().join("a.txt"), b"hello").unwrap();
        // Simulating the VV-fast-forward-deletion class of bug: the
        // write happened, but the index ended up recording a tombstone
        // for it instead.
        state
            .file_index_repository()
            .upsert_file(
                group_id(),
                &record("a.txt", true),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let oracle = WriteOracle::new();
        oracle.record_write("a.txt", b"hello");

        let violations = check_no_silent_data_loss(&oracle, &state, group_id(), root.path());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].detail.contains("deleted"), "{violations:?}");
    }

    #[test]
    fn catches_indexed_content_not_matching_what_was_written() {
        let (state, root) = setup();
        // On-disk content was silently overwritten with something other
        // than what this run's own write produced (e.g. a peer's write
        // clobbering it without going through conflict resolution).
        std::fs::write(root.path().join("a.txt"), b"someone else's content").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                group_id(),
                &record("a.txt", false),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let oracle = WriteOracle::new();
        oracle.record_write("a.txt", b"hello");

        let violations = check_no_silent_data_loss(&oracle, &state, group_id(), root.path());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].detail.contains("does not match"), "{violations:?}");
    }

    #[test]
    fn catches_a_delete_that_the_index_still_shows_as_live() {
        let (state, root) = setup();
        state
            .file_index_repository()
            .upsert_file(
                group_id(),
                &record("a.txt", false),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let oracle = WriteOracle::new();
        oracle.record_delete("a.txt");

        let violations = check_no_silent_data_loss(&oracle, &state, group_id(), root.path());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].detail.contains("still shows it as live"), "{violations:?}");
    }

    #[test]
    fn a_later_write_to_the_same_path_supersedes_an_earlier_one_in_the_oracle() {
        let (state, root) = setup();
        std::fs::write(root.path().join("a.txt"), b"second").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                group_id(),
                &record("a.txt", false),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let oracle = WriteOracle::new();
        oracle.record_write("a.txt", b"first");
        oracle.record_write("a.txt", b"second");

        let violations = check_no_silent_data_loss(&oracle, &state, group_id(), root.path());
        assert!(violations.is_empty(), "{violations:?}");
    }
}

/// How many seeds a scenario sweeps, from `DST_SEEDS` or `default`.
///
/// The per-PR lane sets `DST_SEEDS=1` and the scheduled sweeps do not set it
/// at all, so a scenario's full cost is its own default and the cheap lane's
/// cost is stated where the lane is defined rather than buried in a constant.
/// An unparseable value is the default rather than a panic: a mistyped
/// environment variable should not turn a scenario into an infrastructure
/// failure.
pub fn seeds(default: u64) -> std::ops::Range<u64> {
    0..std::env::var("DST_SEEDS").ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}
