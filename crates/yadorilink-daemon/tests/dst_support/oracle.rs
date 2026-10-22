//! The multi-device oracle
//! library — convergence, global no-loss, no-corruption, conflict-copy
//! accounting, and structural invariants — that a `Case`-IR-driven DST
//! scenario checks its final (or, where cheap, incremental) state against.
//!
//! Deliberately a *new*, separate mechanism from this module's sibling
//! `WriteOracle`/`check_no_silent_data_loss` (`dst_support/mod.rs`), not a
//! rewrite of it: that checker is single-device-scoped, already used and
//! tested by other `dst_*.rs` scenarios, and its own doc comment already
//! marks multi-device generalization as future work with `causal_evidence`
//! as the intended extension point. This module *is* that extension,
//! built from scratch against the real, multi-device shape rather than
//! retrofitted onto the single-device one, so existing callers are
//! unaffected. `content_hash` is re-used from the sibling module for
//! consistency (same hash for the same bytes everywhere in `dst_support`).
//!
//! Design-review notes this module encodes:
//! - **No-loss is causal-supersession-aware, not "every value survives."**
//!  A write legitimately, correctly disappears when a causally-*later*
//!  write or delete (by version vector) superseded it — requiring literal
//!  survival of every `content_id` would false-positive on every ordinary
//!  last-writer-wins overwrite. `GlobalOracle::record` takes the real
//!  `VersionVector` the write/delete carried at the moment it was durably
//!  applied; `check_no_loss` only requires survival of an entry that
//!  nothing else recorded for that path causally dominates.
//! - **`content_table` must be a complete source of truth.** Every op that
//!  produces disk content (`Write` *and* `Edit`) must register its bytes
//!  at issue time; the empty/placeholder/tombstone-materialization content
//!  an `OnDemand` policy or a delete can legitimately leave behind is
//!  deliberately out of this check's scope (Eager materialization only
//!  — every scenario using it runs Eager), so it never has to distinguish
//!  "legitimately no bytes" from "a third, corrupt value".
//! - **`Violation` is structured for triage/dedup**, not a bare
//!  string: `kind` + machine-readable `path`/`content_ids`/`devices`, with
//!  `detail` only for the human-readable remainder.
//! - **History legality (the oracle's 4th invariant) is intentionally not a
//!  separate general linearizability checker.** Its two components
//!  that actually matter for what these scenarios produce — "no write is
//!  lost without a causally-later write/delete explaining its absence"
//!  and "every genuine concurrent-edit pair keeps both copies" — are
//!  covered by `check_no_loss` and `check_conflict_copy_accounting`
//!  respectively. A more general legality oracle is grown from real
//!  triaged cases rather than written from scratch.

#![cfg(turmoil)]
#![allow(dead_code)] // not every check has a caller in every scenario that includes this module

use std::collections::{HashMap, HashSet};
use std::path::Path;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::native_plan::NativeRowIdentity;
use yadorilink_replica_domain::session_state::MaterializationState;

use super::case_ir::ContentTable;
use super::content_hash;
use super::dst_trace_path;
use super::namespace_oracle::{
    check_trees_converge, disk_tree, NamespaceViolation, NamespaceViolationKind,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViolationKind {
    Convergence,
    NoLoss,
    Corruption,
    ConflictCopyAccounting,
    StructuralIndexDiskMismatch,
    StructuralOrphanIndexRow,
    /// The mesh converged (every device agrees), but onto a value that is
    /// NOT the one the conflict rules say should win — a consistent-but-
    /// wrong winner. The five checks above are all structurally blind to
    /// this: convergence sees agreement, no-loss sees both racing writes
    /// surviving somewhere, no-corruption sees only bytes someone wrote.
    /// Only an independent reference model (`reference_model.rs`), which
    /// re-derives the expected winner from the input timeline, can catch it.
    ConvergedToWrongWinner,
    /// The index's materialization state for a row disagrees with what the
    /// file on disk actually shows -- a row marked `hydrated` whose backing
    /// file is empty (content not really materialized), or a `placeholder`
    /// whose file is already fully materialized. Guards the "avoid
    /// partial materialization being mistaken for a valid synced file"
    /// invariant; distinct from `StructuralIndexDiskMismatch` (which is
    /// pure existence) and `StructuralOrphanIndexRow` (which is a
    /// tombstone/disk disagreement).
    StructuralMaterializationMismatch,
    /// Two replicas assigned the same legacy causal identity
    /// `(group, path, version vector)` to different content identities. An
    /// equal version vector is treated as the same edit by reconciliation,
    /// so this divergence cannot heal without explicit detection.
    SameVersionIdentityMismatch,
    /// Promptness tracking: a per-round
    /// convergence check took
    /// longer than a realistic SLA to settle. Deliberately *not* a hard
    /// per-round failure -- production has no "N seconds or fail" gate,
    /// only eventual consistency -- but a genuine, measured cost (the
    /// self-echo re-index churn's ~30s hydration-timeout cycle, which is
    /// production behaviour) that must stay *visible* rather
    /// than being hidden by simply loosening the round-progression gate
    /// that tolerates it.
    SlowConvergence,
    /// An
    /// *informational* finding, never a hard failure -- the harness's
    /// self-healing lifecycle sweep (`repair_interrupted_materializations`
    /// / `remove_recorded_temp_files`, `dst_support::sweep::run_self_healing`)
    /// performed a repair the production daemon's periodic task would also
    /// have performed. Recorded so the signal about how often the repair
    /// path is exercised stays visible rather than silently
    /// swallowed; a sweep that *fails* to reach a consistent state still
    /// yields a hard structural/corruption violation from the terminal
    /// oracles that run after it.
    RepairedBySweep,
    /// A directory-shape finding from `namespace_oracle`: a kind mismatch,
    /// a directory left behind after its contents were deleted, data lost
    /// to a file-versus-directory conflict, and the rest of that module's
    /// checks every file-only oracle here cannot see.
    Namespace(NamespaceViolationKind),
}

impl From<NamespaceViolation> for Violation {
    fn from(v: NamespaceViolation) -> Self {
        Violation {
            kind: ViolationKind::Namespace(v.kind),
            path: (!v.path.is_empty()).then_some(v.path),
            content_ids: Vec::new(),
            devices: v.devices,
            detail: v.detail,
        }
    }
}

/// One oracle failure, structured so triage/dedup can group by
/// `(kind, path)` (or a coarser signature) without re-parsing prose.
#[derive(Debug, Clone)]
pub struct Violation {
    pub kind: ViolationKind,
    pub path: Option<String>,
    pub content_ids: Vec<u64>,
    pub devices: Vec<usize>,
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}]", self.kind)?;
        if let Some(path) = &self.path {
            write!(f, " path={path}")?;
        }
        if !self.devices.is_empty() {
            write!(f, " devices={:?}", self.devices)?;
        }
        if !self.content_ids.is_empty() {
            write!(f, " content_ids={:?}", self.content_ids)?;
        }
        write!(f, ": {}", self.detail)
    }
}

pub fn format_violations(seed: u64, violations: &[Violation]) -> String {
    let lines: Vec<String> = violations.iter().map(|v| format!("  - {v}")).collect();
    format!("seed {seed}: {} oracle violation(s):\n{}", violations.len(), lines.join("\n"))
}

/// One recorded write or delete, with the identity of the change that
/// authored it in the signed DAG — the causal evidence `check_no_loss`
/// compares entries against to decide whether an absent write was
/// legitimately superseded.
///
/// This is read back from the applying device right after the op is durably
/// applied; it is never fabricated. `None` means the harness could not
/// observe an authoring change for that op, in which case the entry is
/// treated as un-superseded (fail-loud: an unexplained disappearance is
/// reported rather than silently excused).
#[derive(Debug, Clone)]
struct HistoryEntry {
    device_idx: usize,
    /// `None` for a delete.
    content_id: Option<u64>,
    authoring: Option<NativeRowIdentity>,
}

/// Multi-device history + the checks run against it at the end of a run
/// (or, for the cheap ones, incrementally). One instance per `Case` run.
#[derive(Default)]
pub struct GlobalOracle {
    // path -> every write/delete recorded for it, in recording order.
    history: HashMap<String, Vec<HistoryEntry>>,
    // Promptness tracking: (path, elapsed) for every per-round
    // convergence check the harness ran, regardless of whether it stayed
    // within a realistic SLA -- see `check_convergence_promptness`.
    convergence_latencies: Vec<(String, std::time::Duration)>,
}

impl GlobalOracle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records how long one per-round convergence check took to settle,
    /// for `check_convergence_promptness` to later flag against an SLA.
    /// Called regardless of outcome (fast or slow) -- the promptness
    /// check itself decides what's notable, this is just the raw log.
    pub fn record_round_convergence_latency(&mut self, path: &str, elapsed: std::time::Duration) {
        self.convergence_latencies.push((path.to_string(), elapsed));
    }

    /// Promptness oracle: flags any
    /// per-round convergence that
    /// took longer than `sla` to settle, without itself gating round
    /// progression (that's `converge_path`'s own, deliberately generous,
    /// bound in the harness). Keeps a real, measured cost visible in the
    /// oracle's own findings rather than silently tolerated just because
    /// the round-progression gate is loose enough to not fail on it.
    /// Only ever called with a latency from a round that actually
    /// converged (a budget-exhausted round is a separate failure/skip
    /// path in each scenario, not a measured latency) -- so every finding
    /// here genuinely did settle, just slower than `sla`.
    ///
    /// Deliberately does not guess at *why* a given round was slow: this
    /// oracle is shared across scenario files with different fault-
    /// injection semantics (e.g. self-echo re-index churn is production
    /// behaviour in one scenario, but under a scenario
    /// that injects packet loss the more parsimonious explanation is a
    /// dropped `BlockRequest` driving a hydration-timeout/reconcile-retry
    /// cycle instead) -- asserting one specific mechanism here would be
    /// speculative for scenarios where it wasn't actually diagnosed.
    pub fn check_convergence_promptness(&self, sla: std::time::Duration) -> Vec<Violation> {
        self.convergence_latencies
            .iter()
            .filter(|(_, elapsed)| *elapsed > sla)
            .map(|(path, elapsed)| Violation {
                kind: ViolationKind::SlowConvergence,
                path: Some(path.clone()),
                content_ids: Vec::new(),
                devices: Vec::new(),
                detail: format!(
                    "convergence took {elapsed:?}, exceeding the {sla:?} promptness SLA, not \
                     itself a correctness bug (round progression still succeeded)"
                ),
            })
            .collect()
    }

    /// Records a durably-applied write, with the identity of the change that
    /// authored it (read the real authoring hash back off the applying
    /// device after applying the op — don't fabricate one).
    pub fn record_write(
        &mut self,
        path: &str,
        device_idx: usize,
        content_id: u64,
        authoring: Option<NativeRowIdentity>,
    ) {
        // The evidence itself is what the supersession test runs on, and a
        // wrong or repeated hash here manufactures a `[NoLoss]` out of a
        // perfectly converged run -- `supersedes` returns false when either
        // identity is `None` AND when the two are equal, so a stale read that
        // repeats the previous op's hash makes both ops mutually
        // unsupersedable and reports them as a *pair* of losses. Tracing the
        // recorded evidence is therefore the only way to tell a real loss
        // from a mis-recorded one; without it the trace shows correct
        // product behaviour and an inexplicable violation.
        dst_trace_path(path, || {
            format!(
                "oracle.record_write: device_idx={device_idx} content_id={content_id} evidence={}",
                authoring
                    .as_ref()
                    .map(|identity| hex::encode(&identity.provenance.0[..4]))
                    .unwrap_or_else(|| "NONE".to_string())
            )
        });
        self.history.entry(path.to_string()).or_default().push(HistoryEntry {
            device_idx,
            content_id: Some(content_id),
            authoring,
        });
    }

    /// Records a durably-applied delete (tombstone), with the identity of the
    /// change that authored it.
    pub fn record_delete(
        &mut self,
        path: &str,
        device_idx: usize,
        authoring: Option<NativeRowIdentity>,
    ) {
        self.history.entry(path.to_string()).or_default().push(HistoryEntry {
            device_idx,
            content_id: None,
            authoring,
        });
    }

    /// True when `later`'s head strictly supersedes `earlier`'s head: the
    /// later head's delta lists the earlier head's dot in the `removes` of an
    /// op at this path, directly or through a chain of removed heads' own
    /// deltas.
    ///
    /// The delta is asked of every device because a single replica may not yet
    /// retain the whole chain; one device answering yes is proof, since a
    /// delta's removal list is fixed by its signed bytes and cannot differ
    /// between replicas that both hold it.
    fn supersedes(
        devices: &[(&Path, &ReplicaCoordinator)],
        group_id: &str,
        path: &str,
        later: &HistoryEntry,
        earlier: &HistoryEntry,
    ) -> bool {
        let (Some(later_id), Some(earlier_id)) = (&later.authoring, &earlier.authoring) else {
            return false;
        };
        if later_id == earlier_id || later_id.dot == earlier_id.dot {
            return false;
        }
        devices.iter().any(|(_, state)| {
            Self::removes_transitively(state, group_id, path, later_id, earlier_id)
        })
    }

    /// Breadth-first walk from `later`'s dot through the heads each visited
    /// delta removes at the path (or at either head's source path), looking
    /// for `earlier`'s dot. Bounded: a replica missing a delta body simply
    /// ends that branch.
    fn removes_transitively(
        state: &ReplicaCoordinator,
        group_id: &str,
        path: &str,
        later: &NativeRowIdentity,
        earlier: &NativeRowIdentity,
    ) -> bool {
        use yadorilink_replica_domain::ids::FolderGroupId;
        use yadorilink_replica_domain::signed_delta::NativeDelta;
        use yadorilink_sync_sqlite::SyncSqliteError;

        const MAX_VISITED: usize = 256;
        let group = FolderGroupId(group_id.to_string());
        let mut visited = HashSet::new();
        let mut queue = std::collections::VecDeque::from([later.dot.clone()]);
        while let Some(dot) = queue.pop_front() {
            if !visited.insert(dot.clone()) || visited.len() > MAX_VISITED {
                continue;
            }
            let body = state
                .database()
                .read::<_, SyncSqliteError>(|conn| {
                    yadorilink_sync_sqlite::native_store::fetch_delta_body(
                        conn,
                        &group,
                        &dot.author,
                        dot.seq,
                    )
                })
                .ok()
                .flatten();
            let Some(delta) = body.and_then(|bytes| NativeDelta::from_wire_bytes(&bytes).ok())
            else {
                continue;
            };
            for op in &delta.ops {
                let op_path = op.path.as_str();
                if op_path != path
                    && op_path != later.source_path.as_str()
                    && op_path != earlier.source_path.as_str()
                {
                    continue;
                }
                for removal in &op.removes {
                    if removal.dot == earlier.dot {
                        return true;
                    }
                    queue.push_back(removal.dot.clone());
                }
            }
        }
        false
    }

    /// **No-loss (causal-supersession-aware).** A recorded entry needs to
    /// survive (as the live file, or as a `(conflicted copy...)` sibling)
    /// unless some *other* recorded entry for the same path has a version
    /// head that strictly supersedes it (the other entry's delta removes this
    /// entry's head, directly or transitively) — i.e. was genuinely superseded by a
    /// causally-later write or delete. Two genuinely concurrent entries
    /// (neither supersedes the other) both need to survive *unless* one is a
    /// delete that lost the conflict to the other's content ('s
    /// documented delete-vs-write outcome: the losing tombstone is
    /// dropped outright, never conflict-copied) — a losing delete is
    /// therefore never required to "survive" as a deletion once a
    /// concurrent write outright wins; only a losing *write* against a
    /// concurrent delete is required to survive as a conflict copy.
    pub fn check_no_loss(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &ReplicaCoordinator)],
        group_id: &str,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (path, entries) in &self.history {
            for (i, entry) in entries.iter().enumerate() {
                let superseded = entries.iter().enumerate().any(|(j, other)| {
                    if i == j {
                        return false;
                    }
                    Self::supersedes(devices, group_id, path, other, entry)
                });
                if superseded {
                    continue; // legitimately overwritten; no survival required
                }

                let Some(content_id) = entry.content_id else {
                    // A non-superseded delete: nothing further to check
                    // here (delete_survives-style checks belong to
                    // structural/no-corruption, since "survives" isn't
                    // meaningful for a tombstone the same way it is for
                    // content).
                    continue;
                };

                // A losing write against a concurrent delete is
                // still required to survive as a conflict copy --
                // only exempts the *delete* side, never the write side.
                // So every non-superseded write entry, concurrent or not,
                // must have its content_id's bytes present somewhere.
                let Some(expected_bytes) = content_table.get(content_id) else {
                    violations.push(Violation {
                        kind: ViolationKind::NoLoss,
                        path: Some(path.clone()),
                        content_ids: vec![content_id],
                        devices: vec![entry.device_idx],
                        detail: format!(
                            "content_id {content_id} recorded for a write with no corresponding \
                             content_table entry -- scenario bug, not a product violation"
                        ),
                    });
                    continue;
                };

                let survives = devices
                    .iter()
                    .any(|(root, _state)| write_survives_anywhere(root, path, expected_bytes));
                if !survives {
                    violations.push(Violation {
                        kind: ViolationKind::NoLoss,
                        path: Some(path.clone()),
                        content_ids: vec![content_id],
                        devices: vec![entry.device_idx],
                        detail: format!(
                            "device {}'s write (content_id {content_id}) was never causally \
                             superseded but its content is not present, live or as a conflict \
                             copy, on any device",
                            entry.device_idx
                        ),
                    });
                }
            }
        }

        violations
    }

    /// **Conflict-copy accounting.** For every path with two or more
    /// *mutually concurrent, non-superseded* write entries (a genuine
    /// race, not one that later got superseded by something else
    /// entirely), each such entry's content must appear exactly once
    /// across all devices combined (no duplicate conflict copies for the
    /// same divergent writer, no missing one).
    pub fn check_conflict_copy_accounting(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &ReplicaCoordinator)],
        group_id: &str,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (path, entries) in &self.history {
            let racing: Vec<&HistoryEntry> = entries
                .iter()
                .enumerate()
                .filter(|(i, entry)| {
                    entry.content_id.is_some()
                        && !entries.iter().enumerate().any(|(j, other)| {
                            *i != j && Self::supersedes(devices, group_id, path, other, entry)
                        })
                })
                .map(|(_, e)| e)
                .collect();
            if racing.len() < 2 {
                continue; // no genuine, still-live race on this path
            }

            for entry in &racing {
                let content_id = entry.content_id.expect("filtered to Some above");
                let Some(expected_bytes) = content_table.get(content_id) else { continue };
                // Review note: check *per device*, not
                // a cross-device sum -- a duplicate on one device and a
                // matching absence on another would otherwise cancel out
                // in a summed total (`devices.len` occurrences overall
                // looks "correct" even though one device has 2 copies and
                // another has 0). A per-device count > 1 is both sharper
                // and independent of whether the run has fully converged
                // yet.
                for (device_idx, (root, _)) in devices.iter().enumerate() {
                    let occurrences = count_matching_occurrences(root, path, expected_bytes);
                    if occurrences > 1 {
                        violations.push(Violation {
                            kind: ViolationKind::ConflictCopyAccounting,
                            path: Some(path.clone()),
                            content_ids: vec![content_id],
                            devices: vec![device_idx],
                            detail: format!(
                                "content_id {content_id} (from device {}'s write) appears \
                                 {occurrences} times on device {device_idx} alone -- implies a \
                                 duplicate conflict-copy name",
                                entry.device_idx
                            ),
                        });
                    }
                }
            }
        }

        violations
    }

    /// **No-corruption.** Every live file and every `(conflicted copy...)`
    /// sibling this oracle can find on any device must hash to a value
    /// present in `content_table` — a value nobody's recorded write
    /// produced is either a torn/partial write or genuinely mixed content.
    /// Exempts a row currently in `MaterializationState::Remote`: a
    /// placeholder is deliberately sparse/zero-filled content pre-sized to
    /// the record's length (see `repair_interrupted_materializations`'s
    /// eviction-placeholder handling in `materialization.rs`), so its bytes
    /// are never expected to match a recorded write — flagging one here
    /// would be flagging the on-demand-sync feature working as designed,
    /// not corruption.
    pub fn check_no_corruption(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &ReplicaCoordinator)],
        group_id: &str,
    ) -> Vec<Violation> {
        // Build the known-hash set once (O(1) per
        // lookup) rather than `ContentTable::contains_bytes`'s per-call
        // linear scan -- this runs once per file on every device.
        let known_hashes: HashSet<String> =
            content_table.iter().map(|(_, bytes)| content_hash(bytes)).collect();

        let mut violations = Vec::new();
        for (device_idx, (root, state)) in devices.iter().enumerate() {
            let Ok(entries) = std::fs::read_dir(root) else { continue };
            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else { continue };
                if !file_type.is_file() {
                    continue; // flat scope: root-level candidate paths only; see the `_recursive` checks
                }
                let file_name = entry.file_name();
                if file_name.to_string_lossy() == ROOT_IDENTITY_MARKER {
                    continue; // device-local identity marker, not a synced write
                }
                if matches!(
                    state
                        .materialization_state_repository()
                        .get_materialization_state(group_id, &file_name.to_string_lossy()),
                    Ok(Some(MaterializationState::Remote))
                ) {
                    continue;
                }
                let Ok(bytes) = std::fs::read(entry.path()) else { continue };
                let hash = content_hash(&bytes);
                if !known_hashes.contains(&hash) {
                    violations.push(Violation {
                        kind: ViolationKind::Corruption,
                        path: Some(entry.file_name().to_string_lossy().into_owned()),
                        content_ids: Vec::new(),
                        devices: vec![device_idx],
                        detail: format!(
                            "on-disk content (hash {hash}) matches no recorded write in this \
                             run's content table"
                        ),
                    });
                }
            }
        }
        violations
    }

    /// **Structural invariants.** Three index/disk consistency checks, run
    /// in a single pass over every `state = 'current'` row on every device:
    ///
    /// 1. `StructuralIndexDiskMismatch` — a live (non-deleted) row with no
    ///    file on disk at all (a row claiming "live" with nothing backing
    ///    it, a ghost-row bug). Existence only.
    /// 2. `StructuralOrphanIndexRow` — the structural *inverse*: the
    ///    current row is a tombstone (`deleted = true`) yet a real file
    ///    still lives at its path. The index says the path is gone, disk
    ///    disagrees — the tombstone never took effect (or a write
    ///    resurrected the file without re-versioning the row), the
    ///    "ghost file disagreeing with its own index row" class. A losing
    ///    write's conflict copy is named at a *different* path
    ///    (`... (conflicted copy ...)`), never the tombstoned path itself,
    ///    so a file at `record.path` here is never a legitimate
    ///    conflict-copy artifact. This is deliberately *not* the same as
    ///    "a real file with no index row" (an orphan *file*, not an orphan
    ///    *row*) — that reverse-lookup check needs a whole-tree walk
    ///    cross-referenced against the index and is not performed here.
    /// 3. `StructuralMaterializationMismatch` — for a live `RecordKind::
    ///    File` row, the index's `materialization_state` must agree with
    ///    the disk: a `hydrated` row must not be backed by an empty file
    ///    when the record is non-empty (content mislabeled materialized —
    ///    the "partial materialization mistaken for a valid synced file"
    ///    hazard), and a `placeholder` must not already be fully
    ///    materialized on disk. Pure existence is left to check 1;
    ///    directory/symlink rows carry no hydratable bytes (matching
    ///    `hydrate`/`materialize`'s own `RecordKind::File`-only guard) and
    ///    are skipped.
    ///
    /// Still deferred (real, valuable, but out of this pass's scope): a
    /// content-hash check against the record's `blocks`' `combined_block_
    /// hash` cross-referenced through the block store; the orphan-*file*
    /// (disk file with no index row) reverse lookup; and orphan *blocks*
    /// (block-store entries referenced by no live index row). All three
    /// need machinery beyond the index+disk pair this method has.
    pub fn check_structural(
        &self,
        group_id: &str,
        devices: &[(&Path, &ReplicaCoordinator)],
    ) -> Vec<Violation> {
        let mut violations = Vec::new();
        let mut identities_by_path: HashMap<
            String,
            Vec<(usize, NativeRowIdentity, yadorilink_replica_domain::ids::VersionHash)>,
        > = HashMap::new();
        for (device_idx, (root, state)) in devices.iter().enumerate() {
            let Ok(files) = state.file_index_repository().list_files(group_id) else { continue };
            for record in files {
                if let Ok(Some(current)) = state.sqlite().get_current_version_record(
                    &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_string()),
                    &record.path,
                ) {
                    let version_hash =
                        yadorilink_replica_domain::file::FileVersion::from_index_row(
                            current.blocks.clone(),
                            current.size,
                            current.mtime_unix_nanos,
                            current.record_kind,
                            current.unix_mode,
                            current.symlink_target.clone(),
                            current.xattrs.clone(),
                        )
                        .version_hash;
                    // The authoring-identity invariant is defined over LIVE
                    // content rows: one native head (dot + provenance) must
                    // project one content identity everywhere. A tombstone's authored
                    // "content" is the deletion itself; its row's residual
                    // content columns are whatever that device happened to
                    // hold when the delete landed (a never-hydrated scaffold
                    // on one device, full content on another) — legitimately
                    // device-local, so comparing them across devices is a
                    // false positive, not a divergence. A REAL
                    // deleted-vs-live divergence is still caught: the live
                    // side's row shows a different (content) head than the
                    // tombstone's, and the disk-level
                    // convergence oracle flags the file's presence anyway.
                    // (Scoped to this check only — the tombstone-orphan
                    // disk check below must still see deleted records.)
                    if let (false, Ok(Some(authoring_id))) = (
                        record.deleted,
                        state.file_index_repository().row_authoring(group_id, &record.path),
                    ) {
                        let identities = identities_by_path.entry(record.path.clone()).or_default();
                        if let Some((other_device, _, other_hash)) =
                            identities.iter().find(|(_, author, hash)| {
                                author == &authoring_id && hash != &version_hash
                            })
                        {
                            violations.push(Violation {
                                kind: ViolationKind::SameVersionIdentityMismatch,
                                path: Some(record.path.clone()),
                                content_ids: Vec::new(),
                                devices: vec![*other_device, device_idx],
                                detail: format!(
                                    "one native head identifies different content: device \
                                     {other_device}={}, device {device_idx}={} \
                                     (author={} row: size={} mtime={} blocks={} kind={:?} \
                                     exec={:?} deleted={})",
                                    hex::encode(other_hash.0),
                                    hex::encode(version_hash.0),
                                    hex::encode(&authoring_id.provenance.0[..8]),
                                    current.size,
                                    current.mtime_unix_nanos,
                                    current.blocks.len(),
                                    current.record_kind,
                                    current.unix_mode,
                                    record.deleted,
                                ),
                            });
                        }
                        identities.push((device_idx, authoring_id, version_hash));
                    }
                }
                let on_disk = root.join(&record.path);

                // (2) StructuralOrphanIndexRow: a tombstone row whose path
                // still has a live file. The tombstone is orphaned from the
                // filesystem it's supposed to describe.
                if record.deleted {
                    if on_disk.is_file() {
                        violations.push(Violation {
                            kind: ViolationKind::StructuralOrphanIndexRow,
                            path: Some(record.path.clone()),
                            content_ids: Vec::new(),
                            devices: vec![device_idx],
                            detail:
                                "index shows a deleted (tombstoned) row whose path still has a \
                                     live file on disk -- the tombstone never took effect"
                                    .to_string(),
                        });
                    }
                    continue;
                }

                // (1) StructuralIndexDiskMismatch: a live row with nothing
                // on disk. If there's no file there's also nothing to
                // compare materialization against, so stop here.
                if !on_disk.exists() {
                    violations.push(Violation {
                        kind: ViolationKind::StructuralIndexDiskMismatch,
                        path: Some(record.path.clone()),
                        content_ids: Vec::new(),
                        devices: vec![device_idx],
                        detail: "index shows a live, non-deleted row with no file on disk"
                            .to_string(),
                    });
                    continue;
                }

                // (3) StructuralMaterializationMismatch: only meaningful for
                // content-bearing file rows.
                let kind = state
                    .file_index_repository()
                    .get_record_kind(group_id, &record.path)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                if kind != RecordKind::File {
                    continue;
                }
                let Ok(Some(mat)) = state
                    .materialization_state_repository()
                    .get_materialization_state(group_id, &record.path)
                else {
                    continue;
                };
                let disk_len = std::fs::metadata(&on_disk).map(|m| m.len()).unwrap_or(0);
                match mat {
                    MaterializationState::Present => {
                        // A row claiming full materialization backed by an
                        // empty file for a non-empty record is a placeholder
                        // or torn write mislabeled `hydrated`. A genuinely
                        // 0-byte file has `record.size == 0` and is exempt.
                        if record.size > 0 && disk_len == 0 {
                            violations.push(Violation {
                                kind: ViolationKind::StructuralMaterializationMismatch,
                                path: Some(record.path.clone()),
                                content_ids: Vec::new(),
                                devices: vec![device_idx],
                                detail: format!(
                                    "row marked hydrated (index size {}) but its file on disk is \
                                     empty -- content is not actually materialized",
                                    record.size
                                ),
                            });
                        }
                    }
                    MaterializationState::Remote => {
                        // A full-size placeholder is normal: eviction (and
                        // the interrupted-materialize repair path) writes a
                        // sparse, zero-filled stub pre-sized to the record's
                        // length (`materialization.rs`'s "freshly written
                        // eviction placeholder" — the on-demand-sync design).
                        // What must never happen is a full-size placeholder
                        // holding real (non-zero) content: that is really
                        // hydrated while the index still calls it a
                        // placeholder.
                        let holds_real_content = record.size > 0
                            && disk_len == record.size
                            && std::fs::read(&on_disk)
                                .map(|bytes| bytes.iter().any(|&b| b != 0))
                                .unwrap_or(false);
                        if holds_real_content {
                            violations.push(Violation {
                                kind: ViolationKind::StructuralMaterializationMismatch,
                                path: Some(record.path.clone()),
                                content_ids: Vec::new(),
                                devices: vec![device_idx],
                                detail: format!(
                                    "row marked placeholder but its file on disk is fully \
                                     materialized ({disk_len} bytes) -- index materialization \
                                     state disagrees with disk"
                                ),
                            });
                        }
                    }
                    MaterializationState::Hydrating => {
                        // `Hydrating` is transient. Although the oracle runs
                        // at a quiescent convergence checkpoint (where a
                        // still-hydrating row is the stale-hydrating hazard
                        // `reset_stale_hydrating`
                        // repairs), this oracle fires shortly after
                        // `check_convergence` first passes, which can still
                        // overlap a final in-flight hydration on a device.
                        // Flagging it here would be a timing-dependent
                        // false positive, so this state is not checked.
                    }
                    MaterializationState::Evicting => {
                        // Like Hydrating, this is an in-flight state and may
                        // overlap the oracle's convergence checkpoint.
                    }
                }
            }
        }
        violations
    }

    /// **Convergence.** Every device in `devices` must agree on
    /// `name -> content-hash` for every live path any of them has (a
    /// `(conflicted copy...)` sibling is its own distinct name, so this
    /// naturally requires the same *set* of conflict copies too, not just
    /// the canonical path). Forward-compatible signature note: `devices`
    /// is the checked/expected-quiescent set — under fault injection only
    /// the online/healed set is a legitimate quiescence point, so callers
    /// may pass a subset rather than this function assuming "all".
    pub fn check_convergence(&self, devices: &[(&Path, &ReplicaCoordinator)]) -> Vec<Violation> {
        if devices.len() < 2 {
            return Vec::new();
        }
        let snapshots: Vec<HashMap<String, String>> =
            devices.iter().map(|(root, _)| flat_hash_snapshot(root)).collect();
        let reference = &snapshots[0];
        let mut violations = Vec::new();
        for (device_idx, snapshot) in snapshots.iter().enumerate().skip(1) {
            if snapshot != reference {
                violations.push(Violation {
                    kind: ViolationKind::Convergence,
                    path: None,
                    content_ids: Vec::new(),
                    devices: vec![0, device_idx],
                    detail: format!(
                        "device 0 and device {device_idx} disagree: device0={reference:?} \
                         device{device_idx}={snapshot:?}"
                    ),
                });
            }
        }
        violations
    }

    /// **Convergence (kind-aware).** Like `check_convergence_recursive`, but
    /// over `namespace_oracle::disk_tree`, which records directories and
    /// symlinks as entries: two devices that agree on every file but not on
    /// an empty directory, or hold a directory where the other holds a file,
    /// do not converge.
    pub fn check_convergence_namespace(
        &self,
        devices: &[(&Path, &ReplicaCoordinator)],
    ) -> Vec<Violation> {
        let trees: Vec<_> =
            devices.iter().enumerate().map(|(i, (root, _))| (i, disk_tree(root))).collect();
        check_trees_converge(&trees).into_iter().map(Violation::from).collect()
    }

    /// **Convergence (recursive).** For nested paths from directory ops:
    /// identical in every respect to
    /// `check_convergence` except it walks subdirectories too, via
    /// `recursive_hash_snapshot` instead of `flat_hash_snapshot` — a new
    /// sibling method, not a rewrite, so the retired two-device scenario's flat
    /// candidate-path scenario (and every other existing caller) keeps its
    /// exact current behavior unchanged. Any scenario that writes nested
    /// paths (`dir1/a.bin`) must call this variant instead: the flat one
    /// would only ever see top-level entries and silently ignore whole
    /// subtrees, false-passing a real divergence underneath a directory.
    pub fn check_convergence_recursive(
        &self,
        devices: &[(&Path, &ReplicaCoordinator)],
    ) -> Vec<Violation> {
        if devices.len() < 2 {
            return Vec::new();
        }
        let snapshots: Vec<HashMap<String, String>> =
            devices.iter().map(|(root, _)| recursive_hash_snapshot(root)).collect();
        let reference = &snapshots[0];
        let mut violations = Vec::new();
        for (device_idx, snapshot) in snapshots.iter().enumerate().skip(1) {
            if snapshot != reference {
                violations.push(Violation {
                    kind: ViolationKind::Convergence,
                    path: None,
                    content_ids: Vec::new(),
                    devices: vec![0, device_idx],
                    detail: format!(
                        "device 0 and device {device_idx} disagree: device0={reference:?} \
                         device{device_idx}={snapshot:?}"
                    ),
                });
            }
        }
        violations
    }

    /// **No-loss (recursive).** Same causal-supersession logic as
    /// `check_no_loss`, but proves survival via `write_survives_anywhere_
    /// recursive` (checks the conflict-copy sibling in `path`'s own parent
    /// directory, wherever nested that is) rather than `write_survives_
    /// anywhere`'s root-only conflict-copy scan. Needed once a path's
    /// directory can itself have been renamed/moved out from under it —
    /// see this module's doc comment on why the flat scan is a real gap
    /// for nested paths, not just an unused generality.
    pub fn check_no_loss_recursive(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &ReplicaCoordinator)],
        group_id: &str,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (path, entries) in &self.history {
            for (i, entry) in entries.iter().enumerate() {
                let superseded = entries.iter().enumerate().any(|(j, other)| {
                    if i == j {
                        return false;
                    }
                    Self::supersedes(devices, group_id, path, other, entry)
                });
                if superseded {
                    continue;
                }

                let Some(content_id) = entry.content_id else {
                    continue;
                };

                let Some(expected_bytes) = content_table.get(content_id) else {
                    violations.push(Violation {
                        kind: ViolationKind::NoLoss,
                        path: Some(path.clone()),
                        content_ids: vec![content_id],
                        devices: vec![entry.device_idx],
                        detail: format!(
                            "content_id {content_id} recorded for a write with no corresponding \
                             content_table entry -- scenario bug, not a product violation"
                        ),
                    });
                    continue;
                };

                let survives = devices.iter().any(|(root, _state)| {
                    write_survives_anywhere_recursive(root, path, expected_bytes)
                });
                if !survives {
                    violations.push(Violation {
                        kind: ViolationKind::NoLoss,
                        path: Some(path.clone()),
                        content_ids: vec![content_id],
                        devices: vec![entry.device_idx],
                        detail: format!(
                            "device {}'s write (content_id {content_id}) was never causally \
                             superseded but its content is not present, live or as a conflict \
                             copy, on any device (recursive search)",
                            entry.device_idx
                        ),
                    });
                }
            }
        }

        violations
    }

    /// **Conflict-copy accounting (recursive).** Same as `check_conflict_
    /// copy_accounting`, but counts occurrences via `count_matching_
    /// occurrences_recursive` so a duplicate conflict-copy nested under a
    /// directory is actually found instead of silently missed by a
    /// root-only scan.
    pub fn check_conflict_copy_accounting_recursive(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &ReplicaCoordinator)],
        group_id: &str,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (path, entries) in &self.history {
            let racing: Vec<&HistoryEntry> = entries
                .iter()
                .enumerate()
                .filter(|(i, entry)| {
                    entry.content_id.is_some()
                        && !entries.iter().enumerate().any(|(j, other)| {
                            *i != j && Self::supersedes(devices, group_id, path, other, entry)
                        })
                })
                .map(|(_, e)| e)
                .collect();
            if racing.len() < 2 {
                continue;
            }

            for entry in &racing {
                let content_id = entry.content_id.expect("filtered to Some above");
                let Some(expected_bytes) = content_table.get(content_id) else { continue };
                for (device_idx, (root, _)) in devices.iter().enumerate() {
                    let occurrences =
                        count_matching_occurrences_recursive(root, path, expected_bytes);
                    if occurrences > 1 {
                        violations.push(Violation {
                            kind: ViolationKind::ConflictCopyAccounting,
                            path: Some(path.clone()),
                            content_ids: vec![content_id],
                            devices: vec![device_idx],
                            detail: format!(
                                "content_id {content_id} (from device {}'s write) appears \
                                 {occurrences} times on device {device_idx} alone (recursive \
                                 search) -- implies a duplicate conflict-copy name",
                                entry.device_idx
                            ),
                        });
                    }
                }
            }
        }

        violations
    }

    /// **No-corruption (recursive).** Same as `check_no_corruption`, but
    /// walks subdirectories (`walk_recursive`) instead of a flat top-level
    /// `read_dir`, so a corrupt/torn value nested under a directory ops
    /// scenario's tree is actually found.
    pub fn check_no_corruption_recursive(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &ReplicaCoordinator)],
    ) -> Vec<Violation> {
        let known_hashes: HashSet<String> =
            content_table.iter().map(|(_, bytes)| content_hash(bytes)).collect();

        let mut violations = Vec::new();
        for (device_idx, (root, _state)) in devices.iter().enumerate() {
            let mut found = Vec::new();
            walk_recursive(root, root, &mut |rel_path, bytes| {
                if rel_path == ROOT_IDENTITY_MARKER {
                    return; // device-local identity marker, not a synced write
                }
                found.push((rel_path, content_hash(bytes)));
            });
            for (rel_path, hash) in found {
                if !known_hashes.contains(&hash) {
                    violations.push(Violation {
                        kind: ViolationKind::Corruption,
                        path: Some(rel_path),
                        content_ids: Vec::new(),
                        devices: vec![device_idx],
                        detail: format!(
                            "on-disk content (hash {hash}) matches no recorded write in this \
                             run's content table (recursive search)"
                        ),
                    });
                }
            }
        }
        violations
    }
}

/// The sync-root identity marker each device writes into its own root. It is
/// device-local by design -- every device mints its own token -- so it is the
/// one file under a sync root that legitimately differs between converged
/// devices. It is excluded from the index and never syncs, but these oracles
/// walk the real filesystem, so they must skip it themselves or every
/// comparison reports a convergence violation that is not one.
const ROOT_IDENTITY_MARKER: &str = ".yadorilink-root";

/// Flat, root-directory-only snapshot, like `write_survives_anywhere` and
/// `count_matching_occurrences`. A conflict-copy sibling for a nested path
/// (`dir/a.txt`) appears in `dir/`, not `root`, so scenarios with nested
/// paths must use the `_recursive` checks instead.
fn flat_hash_snapshot(root: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir(root) else { return out };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ROOT_IDENTITY_MARKER {
            continue;
        }
        if let Ok(bytes) = std::fs::read(entry.path()) {
            out.insert(name, content_hash(&bytes));
        }
    }
    out
}

/// True if `expected` bytes are present on `root`, either as the live
/// file at `path` or as a `(conflicted copy...)` sibling — generalizes
/// the retired two-device scenario's own `write_survives` to be called against
/// an arbitrary device root from shared oracle code.
fn write_survives_anywhere(root: &Path, path: &str, expected: &[u8]) -> bool {
    let live = root.join(path);
    if std::fs::read(&live).map(|c| c == expected).unwrap_or(false) {
        return true;
    }
    let stem =
        Path::new(path).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let Ok(entries) = std::fs::read_dir(root) else { return false };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&format!("{stem} ("))
            && name.contains("(conflicted copy")
            && std::fs::read(entry.path()).map(|c| c == expected).unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn count_matching_occurrences(root: &Path, path: &str, expected: &[u8]) -> usize {
    let mut count = 0;
    let live = root.join(path);
    if std::fs::read(&live).map(|c| c == expected).unwrap_or(false) {
        count += 1;
    }
    let stem =
        Path::new(path).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&format!("{stem} ("))
                && name.contains("(conflicted copy")
                && std::fs::read(entry.path()).map(|c| c == expected).unwrap_or(false)
            {
                count += 1;
            }
        }
    }
    count
}

/// Recursively walks `dir` (relative to
/// `root`, for building forward-slash-separated relative paths), invoking
/// `visit(relative_path, bytes)` for every regular file found. The
/// genuinely-recursive counterpart `flat_hash_snapshot`'s own doc comment
/// flags as missing before directory ops exist. Best-effort: an
/// unreadable directory/file is silently skipped (matches every other
/// disk-walk helper in this module — a transient race with a concurrent
/// writer is not itself an oracle failure).
fn walk_recursive(root: &Path, dir: &Path, visit: &mut dyn FnMut(String, &[u8])) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        if file_type.is_dir() {
            walk_recursive(root, &path, visit);
        } else if file_type.is_file() {
            let Ok(rel) = path.strip_prefix(root) else { continue };
            let Ok(bytes) = std::fs::read(&path) else { continue };
            visit(rel.to_string_lossy().replace('\\', "/"), &bytes);
        }
    }
}

/// Recursive counterpart to `flat_hash_snapshot` — descends into
/// subdirectories so a nested path's (or a nested conflict-copy sibling's)
/// entry is actually captured. See `flat_hash_snapshot`'s doc comment for
/// why the flat version is a real gap once directory ops introduce nested
/// paths.
fn recursive_hash_snapshot(root: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    walk_recursive(root, root, &mut |rel_path, bytes| {
        if rel_path == ROOT_IDENTITY_MARKER {
            return;
        }
        out.insert(rel_path, content_hash(bytes));
    });
    out
}

/// Recursive counterpart to `write_survives_anywhere` — a rename-invariant
/// survival search. The recorded `path` is only the write's *last known*
/// location: a whole-directory rename can remap it, while a conflict copy
/// materialized before the rename stays under the directory's old name (and
/// the two devices may even place it under different names). A conflict copy
/// therefore does NOT reliably preserve the recorded path's directory prefix,
/// so we cannot restrict the search to that one directory. Instead: the write
/// survives if the live file at `path` matches `expected`, OR if ANY file
/// anywhere under the device root carries the `(conflicted copy` marker and
/// has bytes equal to `expected`.
fn write_survives_anywhere_recursive(root: &Path, path: &str, expected: &[u8]) -> bool {
    let live = root.join(path);
    if std::fs::read(&live).map(|c| c == expected).unwrap_or(false) {
        return true;
    }
    let mut found = false;
    walk_recursive(root, root, &mut |rel_path, bytes| {
        if found {
            return;
        }
        let name = Path::new(&rel_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.contains("(conflicted copy") && bytes == expected {
            found = true;
        }
    });
    found
}

/// Recursive counterpart to `count_matching_occurrences` — same rename-
/// invariant, whole-tree conflict-copy search as
/// `write_survives_anywhere_recursive`, but counts every match (the live
/// file plus every `(conflicted copy` file anywhere under the device root
/// whose bytes equal `expected`) so accounting sees copies relocated by
/// directory renames.
fn count_matching_occurrences_recursive(root: &Path, path: &str, expected: &[u8]) -> usize {
    let mut count = 0;
    let live = root.join(path);
    if std::fs::read(&live).map(|c| c == expected).unwrap_or(false) {
        count += 1;
    }
    walk_recursive(root, root, &mut |rel_path, bytes| {
        let name = Path::new(&rel_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.contains("(conflicted copy") && bytes == expected {
            count += 1;
        }
    });
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_domain::file::FileRecord;

    fn group_id() -> &'static str {
        "oracle-test-group"
    }

    fn setup() -> (ReplicaCoordinator, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state.link_repository().add_link(&root.path().to_string_lossy(), group_id()).unwrap();
        // No emission-policy provider is registered on purpose. The hook
        // these tests used to install (a constant `ChangeAuth::PLACEHOLDER`)
        // became `LocalPolicyHeadProvider`, whose unset default is the same
        // all-zero placeholder head -- so installing one here would only
        // restate the default this oracle has always run against.
        (state, root)
    }

    /// Puts `path` in `state` explicitly, for a test whose subject is what
    /// the oracle makes of a given materialization state.
    ///
    /// These tests used to lean on `upsert_file` leaving a row `Present`,
    /// and said so in their comments. It does not: moving a path to a new
    /// version strips a carried-forward `Present` back to `Remote`
    /// (`file_index.rs`'s `strip_carried_forward_hydrated_in_tx`), because a
    /// new version is not materialized until something materializes it.
    /// That is the product's invariant and not a thing to work around, so
    /// each test now names the state it means. A default that has already
    /// flipped once is not a thing to depend on twice.
    fn mark(state: &ReplicaCoordinator, path: &str, materialization: MaterializationState) {
        state
            .materialization_state_repository()
            .set_materialization_state(
                group_id(),
                path,
                materialization,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }

    const DEVICE: &str = "oracle-test-device";

    /// The replica's author handle for [`DEVICE`].
    fn author_key(state: &ReplicaCoordinator) -> yadorilink_sync_sqlite::dag_store::LocalAuthorKey {
        yadorilink_daemon::test_support::local_seam::replica_author_key(
            state,
            DEVICE,
            ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]),
        )
        .unwrap()
    }

    /// Saves `path` as one local write through the production capture seam
    /// and returns the identity of the head the row then shows.
    ///
    /// The write's basis is the head the current row shows, exactly as
    /// capture reads it, so a second call's head supersedes the first --
    /// supersession in these tests is decided by the same removal relation
    /// production uses, never by a fabricated ordering.
    fn author_put(state: &ReplicaCoordinator, path: &str, mtime: i64) -> NativeRowIdentity {
        use yadorilink_replica_domain::file::RecordKind;
        use yadorilink_replica_domain::file::{FileMeta, FileVersion};

        let version = FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        let record = FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: mtime,
            blocks: vec![],
            deleted: false,
        };
        yadorilink_daemon::test_support::local_seam::commit_local_upsert(
            state,
            group_id(),
            &record,
            DEVICE,
            &version,
            None,
            &author_key(state),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
        authored_identity(state, path)
    }

    /// The identity of the head `path`'s current row shows, read back after a
    /// local commit (never fabricated).
    fn authored_identity(state: &ReplicaCoordinator, path: &str) -> NativeRowIdentity {
        state
            .file_index_repository()
            .row_authoring(group_id(), path)
            .unwrap()
            .expect("a local commit leaves the row showing its own head")
    }

    /// Deletes `path` as one local write over the head its row shows.
    fn author_delete(
        state: &ReplicaCoordinator,
        path: &str,
        observed_at: i64,
    ) -> NativeRowIdentity {
        yadorilink_daemon::test_support::local_seam::commit_local_delete(
            state,
            group_id(),
            path,
            DEVICE,
            observed_at,
            true,
            &author_key(state),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
        authored_tombstone_identity(state)
    }

    /// A delete lands no head, so the row has nothing to show: the identity
    /// of the delete is the author's newest delta (its dot, with that
    /// delta's hash as provenance), read back from the frontier.
    fn authored_tombstone_identity(state: &ReplicaCoordinator) -> NativeRowIdentity {
        use yadorilink_replica_domain::native_state::Dot;
        use yadorilink_sync_sqlite::SyncSqliteError;
        let group = yadorilink_replica_domain::ids::FolderGroupId(group_id().to_string());
        let (author, entry) = state
            .database()
            .read::<_, SyncSqliteError>(|conn| {
                let author = yadorilink_sync_sqlite::author_incarnation::current_author(conn)?;
                let entry = yadorilink_sync_sqlite::native_store::frontier_entry_get(
                    conn, &group, &author,
                )?;
                Ok((author, entry))
            })
            .unwrap();
        let entry = entry.expect("a local delete advances the author's frontier");
        NativeRowIdentity {
            source_path: yadorilink_replica_domain::ids::SyncPath(String::new()),
            dot: Dot { author, seq: entry.seq },
            provenance: entry.tip,
        }
    }

    #[test]
    fn no_loss_passes_when_the_only_write_survives() {
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"hello").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_write("a.txt", 0, 1, None);

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)], group_id());
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn no_loss_is_silent_about_a_legitimately_superseded_write() {
        // device-a wrote "first" then "second" (a DAG descendant) -- only
        // "second" needs to survive; "first" disappearing is correct LWW
        // behavior, not data loss.
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"second").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"first".to_vec());
        table.insert(2, b"second".to_vec());

        let first = author_put(&state_a, "a.txt", 1);
        let second = author_put(&state_a, "a.txt", 2);

        let mut oracle = GlobalOracle::new();
        oracle.record_write("a.txt", 0, 1, Some(first));
        oracle.record_write("a.txt", 0, 2, Some(second));

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)], group_id());
        assert!(violations.is_empty(), "the superseded write must not be flagged: {violations:?}");
    }

    #[test]
    fn no_loss_flags_a_write_that_truly_vanished() {
        let (state_a, root_a) = setup();
        // Nothing written to disk at all -- simulating a genuinely lost write.

        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_write("a.txt", 0, 1, None);

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)], group_id());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::NoLoss);
    }

    /// Regression distilled from `dst_directory_chaos` seed 45: no chaos, no network, no simulator --
    /// just the oracle fed the exact on-disk / history shape the full
    /// scenario produces. Before the fix, `check_no_loss_recursive` searched
    /// for a missing write's conflict copy ONLY in the recorded path's own
    /// parent directory (`write_survives_anywhere_recursive`), assuming a
    /// conflict copy always preserves the recorded path's directory prefix.
    /// That assumption is FALSE across a whole-directory rename: the oracle's
    /// recorded path is remapped to the directory's *new* name, but a
    /// conflict copy materialized *before* the rename stays under the *old*
    /// name (and the two devices can even place it under different names).
    /// The content is verifiably on disk, yet the oracle reported a false
    /// [NoLoss]. The fix makes the survival search rename-invariant
    /// (whole-tree), so this must now report NO violation.
    #[test]
    fn no_loss_false_positive_when_conflict_copy_is_in_a_renamed_directory() {
        let (state_a, root_a) = setup();
        // content_id 5's bytes survive on disk as a conflict copy, but in
        // `dir-r4/` (the directory's name when the conflict was resolved),
        // while the oracle's recorded path was remapped by a later rename
        // to `dir-r9/b.bin`. Same shape as the seed-45 dump:
        //  dir-r4/b (conflicted copy,..., device-b, 2f687000).bin
        std::fs::create_dir_all(root_a.path().join("dir-r4")).unwrap();
        std::fs::write(
            root_a
                .path()
                .join("dir-r4/b (conflicted copy, 1970-01-01-000054, device-b, 2f687000).bin"),
            b"seed 45 round 2 race-d-edit device-b",
        )
        .unwrap();

        let mut table = ContentTable::default();
        table.insert(5, b"seed 45 round 2 race-d-edit device-b".to_vec());

        let mut oracle = GlobalOracle::new();
        // Recorded against the post-rename path, never causally superseded.
        oracle.record_write("dir-r9/b.bin", 1, 5, None);

        let violations =
            oracle.check_no_loss_recursive(&table, &[(root_a.path(), &state_a)], group_id());
        // FIXED: content_id 5 is present on disk under dir-r4/ as a conflict
        // copy; the rename-invariant whole-tree search now counts it as
        // survival, so no [NoLoss] violation is reported.
        assert!(
            violations.is_empty(),
            "conflict copy in a renamed directory must count as survival: {violations:?}"
        );

        // Companion (guards accounting path): the relocated
        // conflict copy is now visible to the whole-tree occurrence count
        // even though it lives under `dir-r4/`, not the recorded `dir-r9/`.
        let expected = b"seed 45 round 2 race-d-edit device-b";
        assert_eq!(
            count_matching_occurrences_recursive(root_a.path(), "dir-r9/b.bin", expected),
            1,
            "the conflict copy relocated by the directory rename must be counted"
        );
    }

    #[test]
    fn no_loss_requires_both_sides_of_a_genuine_concurrent_race_to_survive() {
        let (state_a, root_a) = setup();
        // Both concurrent writes' content must be present -- one live,
        // one as a conflict copy.
        std::fs::write(root_a.path().join("a.txt"), b"from-a").unwrap();
        std::fs::write(root_a.path().join("a (conflicted copy, x).txt"), b"from-b").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"from-a".to_vec());
        table.insert(2, b"from-b".to_vec());

        let mut oracle = GlobalOracle::new();
        // Concurrent: neither dominates the other.
        oracle.record_write("a.txt", 0, 1, None);
        oracle.record_write("a.txt", 1, 2, None);

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)], group_id());
        assert!(violations.is_empty(), "{violations:?}");
    }

    // (delete-vs-write race) coverage, added per review:
    // `resolve_and_apply_conflict`'s documented outcome is
    // that a losing *delete* is dropped outright (never conflict-copied),
    // while a losing *write* against a concurrent delete still must
    // survive as a conflict copy -- these two tests each guard one
    // direction of that asymmetry, the highest-data-loss-risk path this
    // oracle exists to catch.

    #[test]
    fn no_loss_does_not_require_a_delete_to_survive_when_a_concurrent_write_wins() {
        // device-a deletes; device-b concurrently writes and wins the
        // conflict outright (documented, correct outcome: the
        // delete is dropped, no conflict copy for it). Only the write's
        // content needs to survive; the oracle must not demand the delete
        // "survive" as an absence check that no `check_no_loss` branch
        // performs in the first place.
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"write-wins").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"write-wins".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_delete("a.txt", 0, None); // concurrent, loses
        oracle.record_write("a.txt", 1, 1, None); // concurrent, wins

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)], group_id());
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn no_loss_flags_a_losing_write_against_a_concurrent_delete_that_never_survived() {
        // The asymmetric direction: a losing *write* against a concurrent
        // delete must still survive as a conflict copy (only
        // exempts the delete side). If neither the live path nor any
        // conflict copy holds the write's content, that's a genuine loss.
        let (state_a, root_a) = setup();
        // Only the delete's effect is visible on disk -- nothing at all
        // for the concurrent write's content.

        let mut table = ContentTable::default();
        table.insert(1, b"lost-write-content".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_delete("a.txt", 0, None); // concurrent, wins
        oracle.record_write("a.txt", 1, 1, None); // concurrent, loses -- must still survive

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)], group_id());
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].kind, ViolationKind::NoLoss);
        assert_eq!(violations[0].devices, vec![1]);
    }

    #[test]
    fn no_loss_is_silent_when_a_write_is_superseded_by_a_later_delete() {
        // Not a race: device-a's write is a DAG ancestor of the later
        // delete (not concurrent with it) -- a legitimate LWW
        // supersession by a delete, same as being superseded by a later
        // write. Must not be flagged.
        let (state_a, root_a) = setup();
        // Nothing on disk -- the later delete's tombstone correctly left
        // no file behind.

        let mut table = ContentTable::default();
        table.insert(1, b"superseded-by-delete".to_vec());

        let written = author_put(&state_a, "a.txt", 1);
        let deleted = author_delete(&state_a, "a.txt", 2);

        let mut oracle = GlobalOracle::new();
        oracle.record_write("a.txt", 0, 1, Some(written));
        oracle.record_delete("a.txt", 0, Some(deleted)); // causally later, dominates

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)], group_id());
        assert!(violations.is_empty(), "the superseded write must not be flagged: {violations:?}");
    }

    #[test]
    fn no_corruption_flags_a_value_nobody_wrote() {
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"corrupted-third-value").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());

        let oracle = GlobalOracle::new();
        let violations =
            oracle.check_no_corruption(&table, &[(root_a.path(), &state_a)], group_id());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Corruption);
    }

    #[test]
    fn no_corruption_passes_when_content_matches_the_table() {
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"hello").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());

        let oracle = GlobalOracle::new();
        let violations =
            oracle.check_no_corruption(&table, &[(root_a.path(), &state_a)], group_id());
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn convergence_passes_when_devices_agree() {
        let (state_a, root_a) = setup();
        let (state_b, root_b) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"same").unwrap();
        std::fs::write(root_b.path().join("a.txt"), b"same").unwrap();

        let oracle = GlobalOracle::new();
        let violations =
            oracle.check_convergence(&[(root_a.path(), &state_a), (root_b.path(), &state_b)]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn convergence_flags_disagreement() {
        let (state_a, root_a) = setup();
        let (state_b, root_b) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"one").unwrap();
        std::fs::write(root_b.path().join("a.txt"), b"different").unwrap();

        let oracle = GlobalOracle::new();
        let violations =
            oracle.check_convergence(&[(root_a.path(), &state_a), (root_b.path(), &state_b)]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Convergence);
    }

    /// The file-only recursive check calls a leftover empty directory
    /// converged; the kind-aware one does not, and names it.
    #[test]
    fn namespace_convergence_sees_the_empty_directory_the_file_check_misses() {
        let (state_a, root_a) = setup();
        let (state_b, root_b) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"same").unwrap();
        std::fs::write(root_b.path().join("a.txt"), b"same").unwrap();
        std::fs::create_dir_all(root_b.path().join("linux/arch")).unwrap();
        let devices = [(root_a.path(), &state_a), (root_b.path(), &state_b)];

        let oracle = GlobalOracle::new();
        assert!(oracle.check_convergence_recursive(&devices).is_empty());
        let violations = oracle.check_convergence_namespace(&devices);
        let paths: Vec<Option<&str>> = violations.iter().map(|v| v.path.as_deref()).collect();
        assert_eq!(paths, vec![Some("linux"), Some("linux/arch")]);
        assert!(violations
            .iter()
            .all(|v| v.kind == ViolationKind::Namespace(NamespaceViolationKind::TreeDivergence)));
        assert_eq!(
            super::super::bundle::violation_kind_label(violations[0].kind),
            "TreeDivergence"
        );
    }

    #[test]
    fn structural_flags_a_live_index_row_with_no_file_on_disk() {
        let (state_a, root_a) = setup();
        state_a
            .file_index_repository()
            .upsert_file(
                group_id(),
                &FileRecord {
                    path: "ghost.txt".to_string(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: Vec::new(),
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(group_id(), &[(root_a.path(), &state_a)]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::StructuralIndexDiskMismatch);
    }

    #[test]
    fn structural_flags_one_authoring_change_with_different_content() {
        let (state_a, root_a) = setup();
        let (state_b, root_b) = setup();
        for (state, root, byte) in
            [(&state_a, root_a.path(), b'a'), (&state_b, root_b.path(), b'b')]
        {
            let identity = NativeRowIdentity {
                source_path: yadorilink_replica_domain::ids::SyncPath("split.txt".to_string()),
                dot: yadorilink_replica_domain::native_state::Dot {
                    author: yadorilink_replica_domain::author::AuthorId {
                        device: yadorilink_replica_domain::ids::DeviceId("planted".to_string()),
                        incarnation: yadorilink_replica_domain::author::IncarnationId([1; 16]),
                    },
                    seq: yadorilink_replica_domain::ids::AuthorSeq(1),
                },
                provenance: yadorilink_replica_domain::ids::DeltaHash([7; 32]),
            };
            state
                .database()
                .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                    yadorilink_sync_sqlite::file_index::upsert_file_with_authoring_in_tx(
                        tx,
                        group_id(),
                        &FileRecord {
                            path: "split.txt".to_string(),
                            size: 1,
                            mtime_unix_nanos: 0,
                            blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                                hash: vec![byte; 32],
                                offset: 0,
                                size: 1,
                            }],
                            deleted: false,
                        },
                        DEVICE,
                        Some(&identity),
                    )
                })
                .unwrap();
            std::fs::write(root.join("split.txt"), [byte]).unwrap();
            // The subject here is the authoring-identity mismatch, so both
            // devices are genuinely materialized; leaving them `Remote`
            // would add a second, unrelated violation to the count below.
            mark(state, "split.txt", MaterializationState::Present);
        }

        let oracle = GlobalOracle::new();
        let violations = oracle
            .check_structural(group_id(), &[(root_a.path(), &state_a), (root_b.path(), &state_b)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].kind, ViolationKind::SameVersionIdentityMismatch);
        assert_eq!(violations[0].path.as_deref(), Some("split.txt"));
    }

    /// Builds a live (non-deleted) file record of a given size.
    fn live_record(path: &str, size: u64) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size,
            mtime_unix_nanos: 0,
            blocks: Vec::new(),
            deleted: false,
        }
    }

    // --- StructuralOrphanIndexRow: the tombstone/disk inverse of
    // StructuralIndexDiskMismatch (a deleted row whose file is still on
    // disk), added to wire up the previously-defined-but-unemitted variant.

    #[test]
    fn structural_orphan_flags_a_tombstone_whose_file_still_exists_on_disk() {
        let (state_a, root_a) = setup();
        // A current tombstone row: the index says "gone.txt" is deleted...
        state_a
            .file_index_repository()
            .upsert_file(
                group_id(),
                &FileRecord {
                    path: "gone.txt".to_string(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: Vec::new(),
                    deleted: true,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // ...but a real file still lives at that exact path.
        std::fs::write(root_a.path().join("gone.txt"), b"ghost").unwrap();

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(group_id(), &[(root_a.path(), &state_a)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].kind, ViolationKind::StructuralOrphanIndexRow);
        assert_eq!(violations[0].path.as_deref(), Some("gone.txt"));
    }

    #[test]
    fn structural_orphan_silent_when_tombstone_has_no_file_on_disk() {
        let (state_a, root_a) = setup();
        // A correctly-applied delete: tombstone row, and no file on disk.
        state_a
            .file_index_repository()
            .upsert_file(
                group_id(),
                &FileRecord {
                    path: "gone.txt".to_string(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: Vec::new(),
                    deleted: true,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(group_id(), &[(root_a.path(), &state_a)]);
        assert!(violations.is_empty(), "a clean tombstone must not be flagged: {violations:?}");
    }

    // --- StructuralMaterializationMismatch: index materialization state vs
    // what disk actually shows.

    #[test]
    fn structural_materialization_flags_hydrated_row_backed_by_empty_file() {
        let (state_a, root_a) = setup();
        // Row claims a 5-byte hydrated file...
        state_a
            .file_index_repository()
            .upsert_file(
                group_id(),
                &live_record("a.txt", 5),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        mark(&state_a, "a.txt", MaterializationState::Present);
        // ...but disk holds an empty file: content was never materialized.
        std::fs::write(root_a.path().join("a.txt"), b"").unwrap();

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(group_id(), &[(root_a.path(), &state_a)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].kind, ViolationKind::StructuralMaterializationMismatch);
    }

    #[test]
    fn structural_materialization_silent_for_hydrated_row_with_real_content() {
        let (state_a, root_a) = setup();
        state_a
            .file_index_repository()
            .upsert_file(
                group_id(),
                &live_record("a.txt", 5),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        std::fs::write(root_a.path().join("a.txt"), b"hello").unwrap();
        mark(&state_a, "a.txt", MaterializationState::Present);

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(group_id(), &[(root_a.path(), &state_a)]);
        assert!(
            violations.is_empty(),
            "a genuinely hydrated file must not be flagged: {violations:?}"
        );
    }

    #[test]
    fn structural_materialization_flags_placeholder_that_is_fully_materialized() {
        let (state_a, root_a) = setup();
        state_a
            .file_index_repository()
            .upsert_file(
                group_id(),
                &live_record("a.txt", 5),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state_a
            .materialization_state_repository()
            .set_materialization_state(
                group_id(),
                "a.txt",
                MaterializationState::Remote,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // A placeholder stub should not already hold its full content, but
        // disk has the whole 5 bytes: the index state disagrees with disk.
        std::fs::write(root_a.path().join("a.txt"), b"hello").unwrap();

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(group_id(), &[(root_a.path(), &state_a)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].kind, ViolationKind::StructuralMaterializationMismatch);
    }

    #[test]
    fn structural_materialization_silent_for_legitimate_placeholder_stub() {
        let (state_a, root_a) = setup();
        state_a
            .file_index_repository()
            .upsert_file(
                group_id(),
                &live_record("a.txt", 5),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state_a
            .materialization_state_repository()
            .set_materialization_state(
                group_id(),
                "a.txt",
                MaterializationState::Remote,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // A legitimate placeholder: an empty stub on disk, not yet hydrated.
        std::fs::write(root_a.path().join("a.txt"), b"").unwrap();

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(group_id(), &[(root_a.path(), &state_a)]);
        assert!(
            violations.is_empty(),
            "an empty placeholder stub must not be flagged: {violations:?}"
        );
    }
}
