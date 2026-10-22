//! Crash-recovery startup repair, crash-safe restore-journal reconciliation,
//! and offline-edit quarantine: `repair_interrupted_materializations`/
//! `_inner`, `reconstruct_file_journaled`, `reconcile_restore_operations`, and
//! `quarantine_dirty_disk_file`. This module depends only on
//! `MaterializationExecutionPort`, so nothing here ever names a concrete
//! state type. Every materialization-state change it makes goes through a
//! named owner operation on that port (the `open_repair_*` and
//! `settle_repair_*` pairs, `commit_recovered_materialized_state`,
//! `record_placeholder_identity`), never a raw state setter; the port has
//! none.
//!
//! `MaterializationIntentGuard` (the concrete struct this group's
//! `reconstruct_file_journaled` and the live peer materialize path both
//! bracket their writes with) lives in `yadorilink-daemon`'s
//! `materialization_intent` module -- the same reason
//! `open_materialization_intent_guard`
//! itself is a narrow delegate rather than a trait object constructor (see
//! `materialization_execution.rs`'s own doc comment). This module never names
//! that struct -- it only ever sees the guard through the
//! `Box<dyn OpenMaterializationIntent + Send + '_>` the port method returns.

use std::path::Path;

use yadorilink_local_storage::{
    apply_file_metadata, create_or_defer_placeholder, disk_bytes_match_indexed_blocks,
    disk_matches_expected_object, intent_target_hash, persist_reconstructed_file_in,
    reconstruct_file_to_temp_in, verify_write_target_within_root, BlockContentStore,
    DiskContentComparison, ExpectedObject,
};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;

use crate::materialization_execution::{
    GroupStructuralLedger, MaterializationExecutionError, MaterializationExecutionPort,
    MaterializationIntentKind, RepairRowSnapshot,
};
use yadorilink_replica_domain::session_state::RestoreCommitOutcome;

// --- Startup recovery ------------------------------------------------------

/// Result of one `repair_interrupted_materializations` pass — which paths
/// were found inconsistent, and how each was resolved.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MaterializationRepairReport {
    /// Content on disk was missing/mismatched but every block was still
    /// present in the local block store — self-healed with a fresh
    /// `reconstruct_file`, no peer round-trip needed.
    pub reconstructed: Vec<String>,
    /// On-disk bytes still matched the index exactly, but the path had no
    /// usable actual-state generation behind its `Present` claim — the
    /// proof was re-observed and republished. No bytes were touched. This
    /// is the only path that can heal that state: `hydrate` refuses it and
    /// `pin` cannot detect it.
    pub reproven: Vec<String>,
    /// Content on disk was missing/mismatched and at least one block was
    /// also missing locally — demoted from `Present` to `Remote` so
    /// normal on-demand hydration re-fetches it from a peer.
    pub demoted_to_placeholder: Vec<String>,
    /// Existing disk bytes differed from the indexed block identity while a
    /// materialization intent was open on the path, and the row could not
    /// explain them. Rather than overwrite them, they were moved to the paired
    /// conflict-copy path recorded here before the canonical path was
    /// repaired — `(original_path, quarantine_path)`. A divergent file with
    /// no intent is not listed: it is left in place and journaled as an
    /// ordinary local edit.
    pub quarantined_dirty: Vec<(String, String)>,
    /// A `Present` record whose on-disk file was missing *and* had no
    /// in-progress materialization intent journaled — i.e. the write had
    /// already completed and the file was then deleted (or renamed away)
    /// while the daemon was stopped. These are NOT reconstructed from the
    /// index (doing so would silently resurrect a user's offline deletion);
    /// each is classified as an offline deletion. When this pass was given a
    /// change emitter, the tombstone + `Delete` change was emitted here
    /// through the same seam the disk scan uses; otherwise the row is left
    /// untouched for the startup reconcile scan to tombstone.
    pub offline_deleted: Vec<String>,
    /// Paths this pass could not finish for a reason local to the path
    /// (an unreadable file, a failed write or rename). Each was left as
    /// the failure found it, for the next pass, and the pass went on to the
    /// next path instead of aborting. The startup caller treats a
    /// non-empty list like a failed pass.
    pub failed: Vec<String>,
    /// Held paths whose disk this pass brought into agreement with the row
    /// and released (see `crate::held_path_reconcile`). Anything under
    /// one of them the row could not account for is in `quarantined_dirty`.
    pub held_path_reconciled: Vec<String>,
    /// How many rows the per-path repair looked at (took a lock on and read
    /// back). A healthy live pass visits none: the settled rows are not
    /// examined one by one.
    pub rows_visited: usize,
}

/// Whether one `repair_interrupted_materializations`
/// pass runs at daemon startup, before any watcher/live-capture pipeline
/// exists for this link, or on the periodic live cadence, while ordinary
/// local edits can be racing it.
///
/// The distinction matters for exactly one thing: what a `Present`
/// record whose on-disk bytes have no in-progress materialization intent
/// means. At startup, before any watcher exists, this can only be an
/// offline user edit or deletion made while the daemon was stopped --
/// leaving a present-but-divergent file in place for the dirty journal /
/// startup scan to author as an ordinary local edit (and deferring a
/// missing one's tombstone to the startup reconcile scan) is the correct
/// disambiguation. Only a divergence under an open intent that the row
/// cannot explain is quarantined. On the live cadence, the SAME
/// observation can just as easily be a user edit **in progress right
/// now** -- sitting in the debounce accumulator, or captured but not yet
/// past its own per-path lock -- neither of which this repair pass's own
/// `try_lock` can see (a confirmed, reproduced race: this repair pass's
/// very next tick after a fresh restart grabbed a just-synced file's path
/// lock a live incoming peer edit had not yet reached, read the disk
/// bytes as "diverged," and quarantined them). Treating that the same
/// way the startup pass does -- quarantining the user's own in-flight
/// edit, or tombstoning a file mid-deletion -- would race and corrupt a
/// live edit instead of merely repairing a crash. `Live` mode instead
/// hands the path to the existing dirty-journal backstop
/// (`MaterializationExecutionPort::record_dirty_path`, already
/// redriven on its own periodic cadence -- see `local_change.rs`'s
/// "re-driving journaled local dirty paths" sweep) and leaves the
/// canonical file/row untouched, rather than acting on it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairMode {
    Startup,
    Live,
}

impl MaterializationRepairReport {
    /// Whether this pass found nothing to repair — the common case on a
    /// clean startup. Public so callers (`yadorilink-daemon::main`'s
    /// startup wiring) can decide whether to log anything at all without
    /// duplicating this check.
    pub fn is_empty(&self) -> bool {
        self.reconstructed.is_empty()
            && self.demoted_to_placeholder.is_empty()
            && self.quarantined_dirty.is_empty()
            && self.offline_deleted.is_empty()
            && self.failed.is_empty()
            && self.held_path_reconciled.is_empty()
    }
}

/// startup self-heal for a file whose local index already
/// recorded a `Present` materialization state (and the new version/block
/// list) *before* the crash, but whose on-disk content was never fully
/// (re)written — the exact window `PeerSyncSession::materialize`'s
/// eager-fetch branch leaves open: like every other materialization write
/// path in this crate, it commits the index row first and only then
/// performs the actual temp-write-then-rename (local-change self-echo
/// suppression, `local_change::process_event`, depends on the index
/// already reflecting the new state by the time the watcher sees the
/// resulting filesystem event — see `evict_file`'s doc comment for the
/// same discipline elsewhere in this crate — so that ordering is
/// deliberately not reversed here). A crash between those two steps
/// leaves the index correctly describing the new version while the
/// on-disk file is either stale (still the previous version's bytes) or
/// missing outright — indistinguishable from a genuinely synced file to
/// every other code path, which is exactly what the "avoid
/// partial materialization being mistaken for a valid synced file"
/// invariant forbids.
///
/// Runs once at daemon startup for every configured link, mirroring the
/// placement and rationale of the reset-stale-`Hydrating`-to-`Remote`
/// pass `yadorilink-daemon`'s `app.rs` also runs once at startup (via
/// `ReplicaCoordinator::materialization_state_repository`'s
/// `reset_stale_hydrating`) — the two together cover both
/// materialization states (`Hydrating`, handled there; `Present`, handled
/// here) that a crash can leave in a state inconsistent with reality.
///
/// This same check (a `Present` record whose on-disk state doesn't match)
/// can also arise during live operation, not just from a crash — this
/// function's caller in `yadorilink-daemon`'s
/// `adapters::runtime::link_runtime_controller` also invokes it on a
/// periodic background cadence for exactly this reason, as defense-in-depth
/// alongside the direct fixes to `try_apply_metadata_only_update` and the
/// debounce batch executor that address the actual root causes.
///
/// For every `Present`, non-deleted, ordinary-`File`-kind record in
/// `group_id` (symlinks/directories carry no block-based content to
/// verify or reconstruct, so are skipped entirely): if the on-disk file at
/// `root.join(path)` is missing, or its bytes do not match the indexed block
/// sequence, this is diagnosed as a disk/index divergence. Block hashes are
/// checked at their recorded boundaries, including when total size is equal,
/// because an edit made while the daemon was stopped has no dirty journal and
/// must not be mistaken for a clean or interrupted materialization.
///
/// If every one of the record's blocks is still present in the local
/// block store (the common case — the final write step failed or never
/// ran, but the fetched bytes it would have assembled from are already
/// durably stored, content-addressed, independent of that failed write),
/// the file is reconstructed again with no peer round-trip needed. Only
/// when a block is also missing locally is the record demoted to
/// `Remote`, so it is never left claiming hydrated content that
/// isn't actually there.
/// Returns `Err` — never an empty `Ok` report — when `root`'s identity cannot
/// be established (see [`yadorilink_root_authority::root_identity`]). That distinction is the whole
/// fail-closed lane: this pass is the crash-vs-offline-delete disambiguator, so
/// a caller that reads "nothing to repair" from an unverifiable root goes on to
/// scan it and tombstone everything. An `Err` instead lands the link in the
/// daemon's existing `repair_failed_local_paths` set, which already suppresses
/// that scan's delete emission.
pub fn repair_interrupted_materializations(
    state: &dyn MaterializationExecutionPort,
    store: &dyn BlockContentStore,
    root: &Path,
    group_id: &str,
    mode: RepairMode,
    permit: &RootCommitPermit,
) -> Result<MaterializationRepairReport, MaterializationExecutionError> {
    let root = state.open_root(root, group_id)?;
    repair_interrupted_materializations_inner(state, store, &root, group_id, mode, permit)
}

/// Takes a [`VerifiedRoot`] for the same reason
/// `local_change::reconcile_disk_with_ignore` does, and it is the same bug:
/// this pass independently grew its own root guard, and that guard
/// independently checked only that the path existed. An unmounted volume leaves
/// its mountpoint behind, so `fs::metadata` succeeded, every `Present` file
/// looked missing, and the classification below turned the folder into
/// offline-delete tombstones (and, before that, rewrote every file as a
/// placeholder). Requiring the proof in the signature is what stops a third
/// copy of the same mistake: the check now cannot be written incompletely here,
/// because it is not written here at all.
#[allow(
    clippy::too_many_lines,
    reason = "one sweep over every materialization-state row whose classification arms all \
              depend on the same per-pass state established up front (the `outstanding_intents` \
              snapshot, the diag counters feeding the closing summary warn, and the per-path \
              lock held across each decision); splitting an arm out would separate it from the \
              snapshot-versus-live-read reasoning documented inline and invite a fourth copy of \
              the incomplete-root-check bug this function's doc comment describes"
)]
fn repair_interrupted_materializations_inner(
    state: &dyn MaterializationExecutionPort,
    store: &dyn BlockContentStore,
    root: &VerifiedRoot,
    group_id: &str,
    mode: RepairMode,
    permit: &RootCommitPermit,
) -> Result<MaterializationRepairReport, MaterializationExecutionError> {
    let mut report = MaterializationRepairReport::default();
    let root = root.path();
    // Held paths first, before any row is looked at: until a held path's
    // disk is reconciled nothing else may write it, and its row describes
    // nothing that is on disk yet.
    let install = crate::held_path_reconcile::reconcile_held_paths(state, root, group_id, permit)?;
    report.held_path_reconciled = install.released;
    report.quarantined_dirty.extend(install.preserved);
    report.failed.extend(install.failed);
    // Per-sweep cost attribution (see the summary `warn!` at this
    // function's end): this pass runs on a live periodic cadence over
    // every materialization-state row in the group, so its per-row costs
    // are multiplied by the whole folder's size on every tick -- a shape
    // that is invisible from the outside because a healthy sweep reports
    // an EMPTY report and therefore logs nothing at all.
    // The exact set of paths that currently carry an intent, read ONCE for the
    // whole pass. Both "already fine, drop a moot intent" arms below (the file
    // arm and the symlink arm) used to issue an unconditional
    // `clear_materialization_intent` for every healthy path they visited --
    // one fsync-backed write transaction, each taking the process-wide writer
    // gate, for a DELETE that matches no row. The journal is empty in steady
    // state, so on a large folder that is the sweep's entire cost: measured at
    // 91k paths, 1.64M such no-op writes holding the writer gate for a
    // cumulative 2,223 seconds while the sweeps ran back-to-back (a single
    // pass outlasting its own 90s cadence).
    //
    // Skipping a clear for a path absent from this snapshot is safe in the
    // direction this module already relies on. An intent created after the
    // snapshot belongs to a materialize that is running RIGHT NOW and clears
    // its own intent on completion; if that materialize instead crashes, the
    // next pass's snapshot sees it. And a lingering intent is explicitly
    // fail-safe here already -- see this function's own opening comment on the
    // orphaned-intent edge, which deliberately leaves such intents in place.
    // Deferring a moot clear by one pass can therefore never lose data; it can
    // at worst defer one offline-delete classification by one cadence.
    //
    // This is emphatically NOT a per-write "read first, skip the write if it
    // looks unnecessary" pre-check: it is one read per pass, the write it
    // guards is a DELETE of a row this pass has positive evidence does not
    // exist, and the loop additionally holds the path's own lock (which every
    // materialize also holds while opening an intent) for the whole decision.
    let outstanding_intents = state.list_materialization_intent_paths(group_id)?;
    // Unlike `outstanding_intents` just above, the projection-obligation
    // signal below is deliberately NOT a whole-pass snapshot -- see
    // `MaterializationExecutionPort::has_unsettled_projection_obligation`'s
    // own doc comment for why a live, per-path read is used instead, and
    // for the full "not yet settled, not settled-but-wrong" scope of what
    // this signal covers (does not, for example, cover a hazard hold --
    // `HazardHeld` settlement deletes the obligation row; that route is
    // safe only because `hold_record` demotes `materialization_state`
    // directly itself).
    let sweep_started = std::time::Instant::now();
    let mut diag_rows_scanned = 0usize;
    let mut report_rows_visited = 0usize;
    let mut diag_hydrated = 0usize;
    let mut diag_lock_skipped = 0usize;
    let mut diag_disk_compared = 0usize;
    let mut diag_disk_matched = 0usize;
    let mut diag_intent_clears = 0usize;
    // Orphaned-intent edge (deliberately not swept here): a crash in the narrow
    // window between opening a materialization intent and committing this path's
    // index/materialization-state row leaves an intent with no corresponding
    // row. This loop is keyed on materialization-state rows, so it never visits
    // such an intent, and it is left in place. That is fail-SAFE: an orphaned
    // intent whose path has no index row cannot drive a spurious reconstruct
    // (the reconstruct arms below all require a present `Present` record), and
    // the disk-reconcile tombstone loop only iterates indexed rows, so the
    // orphan does not block any current deletion either. Its only effect is that
    // if the SAME path is later reused, the scan defers tombstoning it once (see
    // `local_change.rs`) — a deferred delete, never a wrong one. Proactively
    // clearing it is intentionally NOT done: this same function also runs on a
    // live periodic cadence, where an intent that merely looks orphaned may
    // belong to a materialize that just opened it and has not yet committed its
    // row; clearing that live intent would reopen exactly the crash-mid-write
    // data-loss window the journal exists to close. The safe recovery is instead
    // to leave it — a genuine reuse of the path re-opens (and later clears) its
    // own intent, overwriting the stale one.
    // One path's repair. A failure local to that path
    // (`MaterializationExecutionError::is_path_local`: its file could not be
    // read, written or renamed, it escaped the root) is recorded in
    // `report.failed` and the pass goes on to the next path; anything else
    // (a database or invariant failure, a lost root) aborts the pass, as
    // every failure used to.
    let mut failed = Vec::new();
    // A path still held after the reconciliation above is not this sweep's:
    // what stands there belongs to no row this device placed, the hold's
    // reconciliation is its one writer, and a `Present` row over such an
    // object would otherwise read as divergent bytes to quarantine.
    let held_paths: std::collections::HashSet<String> =
        state.list_held_paths(group_id)?.into_iter().map(|hold| hold.path).collect();
    let mut repair_one_path = |path: String,
                               snapshot_mstate: MaterializationState|
     -> Result<(), MaterializationExecutionError> {
        if held_paths.contains(&path) {
            return Ok(());
        }
        // Cheap pre-filter on the snapshot: skip rows that are obviously not
        // candidates without paying to take their lock. This snapshot can go
        // stale before the lock is acquired, so every check it informs is
        // re-read authoritatively under the lock below — it is only an
        // optimization to avoid locking every row in the group.
        diag_rows_scanned += 1;
        report_rows_visited += 1;
        if !is_repair_candidate_state(snapshot_mstate, &outstanding_intents, &path) {
            return Ok(());
        }
        diag_hydrated += 1;

        // Serialize this path's disk+index repair against the same per-path
        // lock the watcher/local-change pipeline, `hydrate_inner`, and the
        // eviction sweep hold while writing this file and its index row. Since
        // this pass now runs live on a periodic cadence (not only at startup
        // before any watcher exists), it would otherwise rename/rewrite the
        // file and flip its materialization state underneath a concurrent
        // writer, tearing the write or flipping the index row out from under
        // them. `try_lock` (never a blocking `lock`) so a path whose operation
        // is in progress is skipped and repaired on the next pass rather than
        // blocking the sweep — mirroring `evict_file`'s acquisition. Repair
        // touches no block-liveness gate (only `evict_file` does), so holding
        // just this one lock per iteration introduces no lock-ordering hazard
        // against physical block deletion and cannot deadlock.
        let path_lock = state.path_lock(group_id, &path);
        let Ok(_path_guard) = path_lock.try_lock() else {
            diag_lock_skipped += 1;
            return Ok(());
        };

        // Re-read the authoritative state under the lock, exactly as
        // `evict_file` re-checks after acquiring it. Between the snapshot above
        // and taking the lock, a concurrent eviction sweep (or a
        // local-change/hydrate) may have already transitioned this row and
        // rewritten the file. Acting on the stale snapshot would, for example,
        // mistake a freshly written eviction placeholder (a sparse zero file)
        // for a divergent user edit — quarantining it as a bogus conflict copy
        // and reversing the just-completed eviction. Only a row still in a
        // candidate state here is a genuine interrupted-materialization
        // candidate. One snapshot-shaped read replacing the three separate
        // CRUD re-checks this loop used to make individually under the
        // path lock. See `MaterializationExecutionPort::repair_row_snapshot`.
        let row = state.repair_row_snapshot(group_id, &path)?;
        let Some(row_state) = row.materialization_state else { return Ok(()) };
        if !is_repair_candidate_state(row_state, &outstanding_intents, &path) {
            return Ok(());
        }
        if row.record_kind.unwrap_or_default() == RecordKind::Symlink {
            // Not only `RecordKind::File`: a symlink row left `Present`
            // by a crash between the index commit and the physical
            // symlink write (see `materialize_symlink_at`'s matching
            // intent guard) must be examined by repair too, or "new
            // symlink row committed, crash, physical symlink never
            // created, restart" would never heal.
            let Some(record) = &row.file else { return Ok(()) };
            if record.deleted {
                return Ok(());
            }
            repair_one_interrupted_single_object(
                RecordKind::Symlink,
                state,
                root,
                group_id,
                &path,
                mode,
                permit,
                &outstanding_intents,
                &row,
                &mut report,
            )?;
            return Ok(());
        }
        if row.record_kind.unwrap_or_default() == RecordKind::Directory {
            let Some(record) = &row.file else { return Ok(()) };
            if record.deleted {
                return Ok(());
            }
            repair_one_interrupted_single_object(
                RecordKind::Directory,
                state,
                root,
                group_id,
                &path,
                mode,
                permit,
                &outstanding_intents,
                &row,
                &mut report,
            )?;
            return Ok(());
        }
        if row.record_kind.unwrap_or_default() != RecordKind::File {
            return Ok(());
        }
        let Some(record) = row.file else { return Ok(()) };
        if record.deleted || record.blocks.is_empty() {
            return Ok(());
        }

        // A settled row owes nothing, so the live sweep does not look at its
        // file: `Present`, a proof that names the current version, and no
        // intent open (every write in flight holds one). Hashing the file
        // would only be inferring a problem from bytes; a divergence with no
        // intent is an ordinary local edit, which capture owns. Startup still
        // compares: it is the one pass that must see an offline edit.
        if mode == RepairMode::Live
            && row_state == MaterializationState::Present
            && !outstanding_intents.contains(&path)
            && state.has_usable_materialized_generation(group_id, &path)?
        {
            return Ok(());
        }

        // A received file whose flush a batch barrier owes is the barrier's
        // while it runs; only a restart finds it unfinished.
        if mode == RepairMode::Live
            && outstanding_intents.contains(&path)
            && state.flush_pending_proof_identity(group_id, &path)?.is_some()
        {
            return Ok(());
        }

        let out_path = root.join(&path);
        diag_disk_compared += 1;
        let on_disk_size = std::fs::metadata(&out_path).ok().map(|m| m.len());
        let bytes_match_index = on_disk_size == Some(record.size)
            && disk_bytes_match_indexed_blocks(&out_path, &record.blocks)?;
        let intent_outstanding = outstanding_intents.contains(&path);
        let proof_stands = if bytes_match_index {
            diag_disk_matched += 1;
            // The healthy case writes NOTHING. This sweep runs on a
            // periodic cadence over every materialization-state row in the
            // replica, so a row that is already `Present` with a proof
            // naming its own version and no intent outstanding must cost
            // exactly the read that established that.
            let proof_stands = state.has_usable_materialized_generation(group_id, &path)?;
            if proof_stands && row_state == MaterializationState::Present && !intent_outstanding {
                return Ok(());
            }
            proof_stands
        } else {
            false
        };
        // The bytes are not the whole version: the version the proof below
        // names is a hash over the mode and the xattrs too, the same check
        // `hydrate_inner` makes before it heals a proof. A lane that crashed
        // after its bytes landed and before its mode or xattrs did leaves
        // right bytes under wrong metadata, and proving that publishes an
        // exact proof of metadata disk never got. Such a file is divergent:
        // it takes the arms below: with an intent open it is quarantined and the
        // whole version, metadata included, is reconstructed; with no intent
        // the path is left in place and journaled as a local edit (the
        // capture then authors the metadata change).
        //
        // The xattrs are compared with the strict reader, not the
        // best-effort `xattrs_already_match_disk`, which reads a failed
        // enumeration as "no attributes" and so could call a file whose
        // attributes it never read a match. An attribute set that cannot be
        // read is not a match: the path takes the divergent arms, as a
        // mismatch does.
        let disk_matches_index = bytes_match_index
            && yadorilink_local_storage::unix_mode_already_matches_disk(&out_path, row.unix_mode)?
            && matches!(
                yadorilink_local_storage::verify_replicated_xattrs_exact(&out_path, &row.xattrs),
                Ok(true)
            );
        if disk_matches_index {
            // The write completed and disk holds the version. What is
            // left is whatever the interrupted attempt did not finish: a
            // proof that no longer stands, a row still in the transient
            // state its opening transaction left, an intent still open.

            // Everything else is one guarded transaction. It used to be
            // three -- publish, then stamp, then clear -- and the path
            // lock does not span them: it serializes daemon-internal work,
            // while a supersession arrives from the native admission side. Between the
            // publish and the stamp the row could move from the version
            // whose bytes were just compared to a newer one, and the stamp
            // then claimed `Present` for content that had been superseded.
            //
            // The guard is re-evaluated inside the commit against the live
            // row, so a row that moved writes nothing at all -- intent
            // included, since that intent is the only durable record that
            // a write was ever in flight, and the next pass needs to find
            // the same repairable state rather than a path that now looks
            // like a genuine offline delete.
            let Some(version) = row.current_version else {
                tracing::warn!(
                    group_id,
                    path = %path,
                    "a repairable path whose bytes match the index has no current version row; \
                     leaving it for the next pass rather than proving it without a version"
                );
                return Ok(());
            };
            let identity =
                match yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path) {
                    Ok(identity) => identity,
                    Err(e) => {
                        tracing::warn!(
                            group_id,
                            path = %path,
                            error = %e,
                            "could not observe a path whose bytes match the index; its \
                             materialization stays unfinished for the next pass"
                        );
                        return Ok(());
                    }
                };
            // Matching bytes are not stable bytes: a write that was in flight
            // may have been renamed in without its flush (a received file waiting
            // for its batch), and a restart of the daemon alone leaves it in the
            // cache. The intent is the only record of that, so the file and its
            // directory reach stable storage before the intent goes.
            // Unix only: the deferral that makes this necessary exists only there.
            if cfg!(unix) && intent_outstanding {
                let flushed = yadorilink_local_storage::flush_received_files(
                    std::slice::from_ref(&out_path),
                    yadorilink_local_storage::ReceivedFlushMode::FullFsyncEach,
                    1,
                );
                if flushed.first() != Some(&yadorilink_local_storage::ReceivedFlushOutcome::Flushed)
                {
                    tracing::warn!(
                        group_id,
                        path = %path,
                        "could not flush a file whose write was in flight; its intent stays open"
                    );
                    return Ok(());
                }
            }
            let committed = state.commit_recovered_materialized_state(
                group_id,
                &path,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version,
                    identity: Box::new(Some(identity)),
                },
                yadorilink_peer_session::ports::ExpectedAuthoring {
                    state: row_state,
                    expected_version: Some(&version),
                },
                permit,
            )?;
            if committed {
                if !proof_stands {
                    report.reproven.push(path.clone());
                }
                if intent_outstanding {
                    diag_intent_clears += 1;
                }
                tracing::info!(
                    group_id,
                    path = %path,
                    "finished a materialization whose bytes were already correct on disk"
                );
            } else {
                tracing::info!(
                    group_id,
                    path = %path,
                    "the row this repair verified against was superseded before its commit; \
                     leaving it for the next pass"
                );
            }
            return Ok(());
        }

        // Bytes that are not the row's version but are, untouched, what this
        // device itself wrote and still holds a proof for: an older version
        // under a newer row (`Present` says only that an object exists). They
        // are no edit and no interrupted write -- quarantining them would
        // fabricate a conflict copy, and journalling them as a local change
        // would author the older version over the newer one. Bringing the
        // newer version in is the materialization lane's job, not this
        // sweep's. A path with an intent open is an interrupted write and
        // still takes the arms below.
        if on_disk_size.is_some()
            && !intent_outstanding
            && state.disk_is_untouched_proven_write(group_id, &path, &out_path)?
        {
            return Ok(());
        }

        // MISSING file, disambiguated by the durable materialization journal.
        // A missing file with no in-progress intent is not an interrupted
        // write: the write had already completed (its intent was cleared) and
        // the file was then deleted or renamed away while the daemon was
        // stopped. Reconstructing it from the index would silently resurrect
        // that offline deletion — and for a rename, restore the now-stale
        // source path. Classify it as an offline delete instead of healing it.
        // (A missing file WITH an intent is a genuine crash mid-write and falls
        // through to the reconstruct path below, as does any present-but-
        // divergent file.)
        //
        // Which intent it is decides that, not only whether one is open. A
        // tombstone delete opens its own intent before it removes the file,
        // and a crash between that removal and its settle leaves the row
        // live, the file gone and that intent open. The missing file is
        // where that delete was heading, not an interrupted write:
        // rebuilding it would resurrect the deleted file. Leave the path,
        // intent included, to the outstanding delete, which settles it.
        let intent_kind = state.materialization_intent_kind(group_id, &path)?;
        if on_disk_size.is_none() && intent_kind == Some(MaterializationIntentKind::Delete) {
            tracing::debug!(
                group_id,
                path = %path,
                "a Hydrated file is missing under an open delete intent; leaving it to that delete"
            );
            return Ok(());
        }
        let has_intent = intent_kind.is_some();
        // A missing file with an outstanding projection obligation is not
        // yet known to be an offline deletion either, same reasoning as the
        // intent check just above -- the Convergence Engine has not
        // finished deciding this path's fate. See `MaterializationExecution
        // Port::has_unsettled_projection_obligation`'s own doc comment for
        // why this is a SEPARATE, live, per-path signal from `has_intent`,
        // not a redundant one.
        let has_unsettled_obligation =
            state.has_unsettled_projection_obligation(group_id, &path)?;
        if on_disk_size.is_none() && !has_intent && has_unsettled_obligation {
            // Missing, no intent, but still-unsettled -- must NOT be
            // resolved either way here. Falling through to the reconstruct
            // arms below would silently RESURRECT a genuine offline
            // deletion that happens to race an unrelated pending
            // obligation on this same path (and once resurrected, nothing
            // else in this sweep will ever tombstone it again);
            // classifying it as offline-deleted here would be just as
            // wrong for a path the Convergence Engine has not finished
            // placing yet. Defer entirely -- the next pass re-evaluates
            // once the obligation settles one way or the other.
            return Ok(());
        }
        if on_disk_size.is_none() && !has_intent && mode == RepairMode::Live {
            // See `RepairMode::Live`'s own doc comment: on the live cadence
            // this "missing, no intent" observation may be a delete the
            // user is making RIGHT NOW, not yet captured -- hand it to the
            // dirty-journal backstop rather than deciding here whether it
            // is an offline deletion.
            state.record_dirty_path(group_id, &path, "removed", repair_now_unix_nanos(), permit)?;
            return Ok(());
        }
        if on_disk_size.is_none() && !has_intent {
            // Leave the row `Present` and the file missing exactly as they
            // are: the startup reconcile scan, which runs inside the group
            // startup barrier through the local-authoring seam and with its
            // own root-availability and per-subtree deletion guards,
            // tombstones the path. NOT reconstructing here is the whole fix;
            // the scan does the propagation.
            report.offline_deleted.push(path);
            return Ok(());
        }

        // An existing mismatched file is ambiguous: it may be a stale
        // interrupted write, or a user edit made while the daemon was stopped
        // (which has no dirty marker). With an intent open it is
        // quarantined before the canonical path is healed; with none it is
        // left in place (below). Full block-identity verification above also
        // catches same-size offline edits that the old size-only fast path
        // silently missed.
        //
        // Deliberately asymmetric with the missing-file arm above: nothing
        // from here down ever consults `has_unsettled_projection_
        // obligation` (an unsettled obligation earlier caused a MISSING
        // path to defer entirely, never resolving either way). That guard
        // exists specifically to stop a genuine offline DELETION from
        // being silently resurrected -- a risk that only exists when the
        // file is actually gone. Here it is not: something is physically
        // present, and quarantining it (below) before reconstructing
        // already preserves whatever it was, unconditionally, regardless
        // of what the obligation table says. There is no deletion to
        // protect against in this arm, so there is nothing for that guard
        // to add.
        //
        // On the live cadence, `!has_intent` here is the exact race
        // `RepairMode::Live`'s own doc comment describes: a present intent
        // still means a genuine interrupted materialization (safe to
        // quarantine+heal even live), but its absence no longer proves an
        // offline edit the way it does at startup -- it may be a live edit
        // not yet captured. Defer to the dirty-journal backstop instead of
        // touching the file at all.
        // At startup this is an offline edit: no intent means no interrupted
        // write explains the divergence. Leave the bytes in place and hand the
        // path to the dirty journal / initial scan, which author an ordinary
        // local Put (a concurrent peer change then takes normal conflict
        // semantics when the row is concurrent with it; when the row already
        // holds a peer version the edit was based on, it supersedes it). Repair
        // itself writes nothing to such a path, so nothing here can overwrite
        // the file. Between this pass and the initial scan's capture a peer's
        // version can still be applied; the executor's pre-write check
        // (`disk_holds_uncaptured_local_bytes`) protects changed content by
        // comparing bytes, but a metadata-only change (mode, xattrs) with
        // equal bytes is not covered. Only a path WITH an intent that disk
        // cannot explain is quarantined below.
        if on_disk_size.is_some() && !has_intent {
            state.record_dirty_path(
                group_id,
                &path,
                "created_or_modified",
                repair_now_unix_nanos(),
                permit,
            )?;
            return Ok(());
        }
        // Computed unconditionally, and reused below by the reconstruct
        // arm too, rather than declared twice: the quarantine-window
        // guard just below and `reconstruct_file_journaled`'s own guard
        // (opened separately, further down) target the same eventual
        // content, and `open_materialization_intent_guard`'s underlying
        // write is an `INSERT ... ON CONFLICT DO UPDATE` upsert keyed on
        // `(group_id, path)` -- opening it twice with the same hash for
        // the same row is idempotent, not a conflict.
        let target_hash = intent_target_hash(&record.blocks);
        // Opened BEFORE the quarantine rename below, not after -- matching
        // `MaterializationIntentGuard::open`'s own "before the bytes are
        // written" contract. Without this, a crash after
        // `quarantine_dirty_disk_file`'s rename succeeds (which makes the
        // canonical path go missing) but before `reconstruct_file_
        // journaled` gets a chance to open ITS OWN intent leaves the row
        // `Present`, the path missing, no intent, and -- this being a
        // purely local repair-sweep action, not driven by any native
        // admission or local emission -- no projection obligation either:
        // the next pass would misread repair's own in-progress recovery
        // as an offline deletion and tombstone a file repair itself just
        // moved aside. Intentionally left unconsumed (no `.clear()` call)
        // if this iteration never reaches reconstruction below (e.g. not
        // all blocks turn out to be present locally): both placeholder
        // arms clear whatever intent is on this row THEMSELVES once the
        // real placeholder write is confirmed (never on Windows, where
        // `create_or_defer_placeholder` defers that write to
        // `cfapi-host.exe` -- see their own `placeholder_deferred`
        // branches), and a plain drop without `.clear()` is inert (no
        // query) either way, matching this whole module's established
        // "an intent left dangling is fail-safe" discipline.
        //
        // The quarantine rename below is its own physical mutation, so the
        // same step also bumps the fence for it, after the intent. This
        // whole function has no native-frontier proof to publish under, so
        // every physical mutation below only ever invalidates via a bump,
        // never publishes. `path_lock` is held for this whole loop
        // iteration via `_path_guard` above.
        // A received file renamed in before its batch flush, then torn by a crash:
        // the object on disk is the very one this version's proof recorded and
        // nothing has touched it since (a write would have moved its identity),
        // so the bytes are the lost flush's, not an edit. Rebuilt in place from
        // the blocks, with nothing to quarantine. Any other divergence under an
        // open intent is quarantined as before.
        let rebuild_in_place = on_disk_size.is_some()
            && intent_kind == Some(MaterializationIntentKind::Materialize)
            && match state.flush_pending_proof_identity(group_id, &path)? {
                Some(Some(proof)) => {
                    yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path)
                        .is_ok_and(|observed| observed == proof)
                }
                _ => false,
            };
        if rebuild_in_place {
            tracing::warn!(
                group_id,
                path = %path,
                "a received file was torn before its batch flush reached stable storage; \
                 rebuilding it in place from the local blocks"
            );
        }
        let quarantine_intent_guard = if on_disk_size.is_some() {
            Some(state.open_repair_quarantine(group_id, &path, &target_hash, permit)?)
        } else {
            None
        };
        if on_disk_size.is_some() && !rebuild_in_place {
            match quarantine_dirty_disk_file(
                root,
                &path,
                &GroupStructuralLedger::new(state, group_id),
            ) {
                Ok(Some((quarantine_path, observed_at_unix_nanos))) => {
                    // The conflict copy is not merely a backup. Journal it as
                    // a newly-created local path before repairing the
                    // canonical file, so the daemon's startup dirty-journal
                    // re-drive promotes these bytes through the ordinary
                    // local-change/index/native state path even if the filesystem
                    // watcher was not running when repair moved the file.
                    state.record_dirty_path(
                        group_id,
                        &quarantine_path,
                        "created_or_modified",
                        observed_at_unix_nanos,
                        permit,
                    )?;
                    tracing::warn!(
                        group_id,
                        path = %path,
                        quarantine_path = %quarantine_path,
                        "local disk bytes diverged from the index during repair; quarantined \
                         its current bytes as a conflict copy before healing the canonical path"
                    );
                    report.quarantined_dirty.push((path.clone(), quarantine_path));
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        group_id,
                        path = %path,
                        error = %e,
                        "failed to quarantine divergent local file bytes; skipping repair of \
                         this path rather than overwriting a possible newer local edit"
                    );
                    return Ok(());
                }
            }
        }
        // Explicit, not just an implicit end-of-scope drop: `path` is
        // borrowed by this guard, and every remaining branch below (the
        // reconstruct arms and the placeholder arms) eventually moves
        // `path` into `report`. From this point on the row is protected
        // either by `reconstruct_file_journaled`'s own freshly-opened
        // guard (targeting the identical hash, an idempotent re-upsert of
        // the same row -- see this guard's own opening comment) or by a
        // placeholder arm's `clear_materialization_intent` call (or, when
        // the row was superseded first, by leaving the intent open), so
        // holding this one any longer buys nothing.
        drop(quarantine_intent_guard);

        let hashes: Vec<String> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        let present = store.present_blocks(&hashes)?;
        if !present.is_empty() && present.iter().all(|&p| p) {
            verify_write_target_within_root(
                &out_path,
                root,
                &GroupStructuralLedger::new(state, group_id),
            )?;
            // Every block is present locally, so the assembly needs no peer
            // round-trip. If the reconstruct nonetheless fails, the cause is
            // *transient* — a block-store read error during this pass (an EIO,
            // or a torn block failing checksum verification), or a failure of
            // the exec-bit `chmod` that completes the sequence — NOT a missing
            // block; the content is still durably present. Do not
            // `?`-propagate: that would abort the whole repair sweep for every
            // remaining path. Instead demote this one row to a retriable
            // `Remote` (the blocks stay in the store) and continue, so a
            // later reconcile re-drives the assembly from those same blocks on
            // a non-faulting read. Only a genuinely-missing block (the `else`
            // arm) is an unavoidable placeholder.
            // `target_hash` was already computed above, before the
            // quarantine step -- reused here, not recomputed. This is a
            // DIFFERENT physical write than the quarantine above (real
            // content, not a divergent-bytes relocation) -- its own bump.
            // Saved, not discarded: this arm really does mutate disk, so it
            // is an internal mutator and everything it publishes goes out
            // under exactly this epoch. It does NOT adopt its own write --
            // adoption would mint a second epoch that no concurrent mutator
            // could make it lose against, and would publish a proof with no
            // version.
            let repair_mutation_generation =
                state.dag_bump_mutation_fence(group_id, &path, "repair_reconstruct")?;
            match reconstruct_file_journaled(JournaledReconstruction {
                state,
                store,
                group_id,
                path: &path,
                out_path: &out_path,
                root,
                blocks: &record.blocks,
                mtime_unix_nanos: record.mtime_unix_nanos,
                unix_mode: row.unix_mode,
                xattrs: &row.xattrs,
                target_version_hash: &target_hash,
                permit,
            }) {
                Ok(()) => {
                    // Publish the proof this reconstruct owes, or, when it
                    // cannot be published, demote the row it was about.
                    if !state.settle_repair_reconstruct(
                        group_id,
                        &path,
                        &out_path,
                        row_state,
                        row.current_version,
                        repair_mutation_generation,
                        permit,
                    ) {
                        return Ok(());
                    }
                    report.reconstructed.push(path)
                }
                Err(e) => {
                    // Every fallback below writes under the root. A root that no longer
                    // verifies (its volume went away mid-assembly) stops the sweep here with
                    // the intent still open, rather than writing a placeholder onto the bare
                    // mountpoint.
                    state.verify_root(root, group_id)?;
                    // `reconstruct_file_journaled` leaves its intent open on
                    // every failure, including a failed `apply_unix_mode` or
                    // `apply_xattrs` after the bytes landed, so this arm is
                    // what decides the path's fate: it replaces the content
                    // with a placeholder and only then clears the intent,
                    // except when the placeholder write is deferred (below),
                    // where the intent must stay open.
                    tracing::warn!(
                        group_id,
                        path = %path,
                        error = %e,
                        "repair reconstruct failed with all blocks present; leaving retriable placeholder"
                    );
                    // The failure can come after the bytes were renamed into
                    // place (the mode or the replicated xattrs could not be
                    // applied). The path was emptied before this write (the
                    // divergent object, if any, was quarantined), so an object
                    // standing there now is this attempt's: it is no `Remote`
                    // row. The row keeps its state and the intent stays open,
                    // which is what keeps the path from reading as an offline
                    // delete and what makes the next pass retry the metadata.
                    if std::fs::symlink_metadata(&out_path).is_ok() {
                        tracing::warn!(
                            group_id,
                            path = %path,
                            "the rebuilt object stands but its metadata could not be applied; \
                             keeping the row and the intent for the next pass"
                        );
                        return Ok(());
                    }
                    if !state.open_repair_placeholder_demotion(
                        group_id,
                        &path,
                        row_state,
                        row.current_version.as_ref(),
                        permit,
                    )? {
                        log_superseded_placeholder_demotion(group_id, &path);
                        return Ok(());
                    }
                    verify_write_target_within_root(
                        &out_path,
                        root,
                        &GroupStructuralLedger::new(state, group_id),
                    )?;
                    // A different physical write than the failed
                    // reconstruct above (a placeholder instead of real
                    // content) -- its own bump.
                    state.dag_bump_mutation_fence(
                        group_id,
                        &path,
                        "repair_reconstruct_failed_placeholder",
                    )?;
                    let placeholder_outcome = create_or_defer_placeholder(&out_path);
                    let placeholder_deferred =
                        placeholder_outcome.is_deferred_to_a_separate_process();
                    state.record_placeholder_identity(
                        group_id,
                        &path,
                        placeholder_outcome,
                        permit,
                    )?;
                    if placeholder_deferred {
                        // Windows: `create_or_defer_placeholder` wrote
                        // nothing -- the real reparse-point placeholder is
                        // created later by `cfapi-host.exe`'s own poll.
                        // Clearing the intent here, before that happens,
                        // removes the only thing protecting this path from
                        // being misread as an offline deletion by a scan
                        // that runs before `cfapi-host.exe` catches up --
                        // the identical bug this whole repair function
                        // exists to close, just via a different write path
                        // than the ones already covered. Left open
                        // deliberately, not cleared automatically once
                        // confirmed: no mechanism in this codebase yet
                        // observes that confirmation from this process.
                        // `apply_unix_mode`/`apply_xattrs` skipped too --
                        // both are real syscalls against a path nothing
                        // has actually created yet in this case.
                    } else {
                        if placeholder_outcome.placed_an_object() {
                            // From the caller's row snapshot, for the same
                            // reason `reconstruct_file_journaled` takes them
                            // that way.
                            apply_file_metadata(&out_path, row.unix_mode, &row.xattrs)?;
                        }
                        // A `Remote` row is not an in-progress write; drop any
                        // intent (`reconstruct_file_journaled` never clears its
                        // own) so a later offline delete of this path is not
                        // misread as a crash to reconstruct.
                        state.clear_materialization_intent(group_id, &path, permit)?;
                    }
                    report.demoted_to_placeholder.push(path);
                }
            }
        } else {
            if !state.open_repair_placeholder_demotion(
                group_id,
                &path,
                row_state,
                row.current_version.as_ref(),
                permit,
            )? {
                log_superseded_placeholder_demotion(group_id, &path);
                return Ok(());
            }
            verify_write_target_within_root(
                &out_path,
                root,
                &GroupStructuralLedger::new(state, group_id),
            )?;
            // No blocks were even present locally -- this is its own,
            // independent physical write, its own bump.
            state.dag_bump_mutation_fence(group_id, &path, "repair_missing_blocks_placeholder")?;
            let placeholder_outcome = create_or_defer_placeholder(&out_path);
            let placeholder_deferred = placeholder_outcome.is_deferred_to_a_separate_process();
            state.record_placeholder_identity(group_id, &path, placeholder_outcome, permit)?;
            if placeholder_deferred {
                // See the reconstruct-failure arm above's matching branch:
                // Windows defers the real write to `cfapi-host.exe`, so
                // nothing is on disk yet -- the intent must stay open, and
                // `apply_unix_mode`/`apply_xattrs` are skipped too (real
                // syscalls against a path nothing has actually created).
            } else {
                if placeholder_outcome.placed_an_object() {
                    apply_file_metadata(&out_path, row.unix_mode, &row.xattrs)?;
                }
                // See the reconstruct-failure arm above: a `Remote` row carries
                // no in-progress intent.
                state.clear_materialization_intent(group_id, &path, permit)?;
            }
            report.demoted_to_placeholder.push(path);
        }
        Ok(())
    };
    let all_rows = state.list_materialization_states(group_id)?;
    let rows_listed = all_rows.len();
    // A live pass owes a settled row nothing (see the per-row check above), so
    // those are told apart for the whole folder in a few set-based reads instead
    // of being locked and read back one by one on every cadence. Startup still
    // examines every row: it is the one pass that must see an offline edit.
    let settled = if mode == RepairMode::Live {
        let present: Vec<&str> = all_rows
            .iter()
            .filter(|(path, row_state)| {
                **row_state == MaterializationState::Present && !outstanding_intents.contains(*path)
            })
            .map(|(path, _)| path.as_str())
            .collect();
        state.settled_file_paths(group_id, &present)?
    } else {
        std::collections::HashSet::new()
    };
    for (path, snapshot_mstate) in all_rows {
        if settled.contains(&path) {
            continue;
        }
        if let Err(error) = repair_one_path(path.clone(), snapshot_mstate) {
            if !error.is_path_local() {
                return Err(error);
            }
            // An owner transaction reports a lost root as an I/O error, the
            // same variant a path-local failure uses; re-check it before
            // going on to meet it again at every remaining path.
            permit.verify()?;
            tracing::warn!(
                group_id,
                path = %path,
                error = %error,
                "materialization repair could not finish this path; continuing with the next"
            );
            failed.push(path);
        }
    }
    report.failed = failed;
    report.rows_visited = report_rows_visited;
    // Permanent per-sweep cost summary (kept -- this pass runs on a live
    // ~90s periodic cadence per group, not per-event, so this is not the
    // noisy kind of diagnostic). `warn` deliberately, not `debug`: the
    // whole point is that a healthy sweep is otherwise invisible (an empty
    // report logs nothing on its own), and the question this answers is
    // how much a HEALTHY sweep costs.
    tracing::warn!(
        group_id,
        rows_listed = rows_listed,
        rows_scanned = diag_rows_scanned,
        hydrated = diag_hydrated,
        lock_skipped = diag_lock_skipped,
        disk_compared = diag_disk_compared,
        disk_matched = diag_disk_matched,
        intent_clears = diag_intent_clears,
        outstanding_intents = outstanding_intents.len(),
        elapsed_ms = sweep_started.elapsed().as_millis() as u64,
        "materialization repair sweep pass finished"
    );
    Ok(report)
}

/// Both placeholder demotion arms, when the row moved off the one this pass
/// read before the demotion could claim it: the row belongs to whoever
/// superseded it, so this pass writes nothing -- a placeholder sized and
/// stamped for the version it read would replace whatever the newer row's
/// own writer puts there. The intent stays open, as every other stale
/// repair attempt in this module leaves it.
fn log_superseded_placeholder_demotion(group_id: &str, path: &str) {
    tracing::info!(
        group_id,
        path = %path,
        "the row this repair would demote to a placeholder was superseded first; writing \
         nothing for it"
    );
}

/// Repairs one interrupted symlink materialization -- the symlink
/// counterpart of the block-based reconstruct arm above, much simpler
/// since a symlink has no partial/torn content: it either exists on disk
/// matching its recorded target, or it does not, with no "some blocks
/// present, some missing" middle state at all. Mirrors the file arm's
/// offline-delete-vs-interrupted-write disambiguation (`has_intent`) and
/// live-mode dirty-journal deferral.
///
/// Deliberately does NOT attempt the file arm's "quarantine a diverged
/// on-disk object as a conflict copy" repair: a symlink present on disk
/// but not matching the recorded target, with no repair intent, is left
/// untouched rather than silently overwritten -- a real, scoped
/// limitation, not an oversight.
// Each parameter is an independently-meaningful piece of repair context
// (state handle, path identity, emitter, mode, permit, snapshot, report
// sink); grouping them into a params struct here would not reduce the
// call site's own argument list and is out of scope for a lint cleanup.
//
// One function for both objects with no block content -- a symlink, and an
// explicit directory -- because what decides a missing or diverged object
// (an interrupted write, an interrupted delete, an unsettled obligation, or
// an offline deletion) is the same for both. They differ only in what
// "matches the row" means (the recorded target; a directory with the
// recorded mode) and in how the object is rebuilt. A directory is rebuilt
// only where nothing else stands: something other than a directory at its
// path may be a user's, and is never replaced.
#[allow(clippy::too_many_arguments)]
fn repair_one_interrupted_single_object(
    kind: RecordKind,
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    path: &str,
    mode: RepairMode,
    permit: &RootCommitPermit,
    // See the caller's own `outstanding_intents` comment: the whole-pass
    // snapshot of which paths actually carry an intent.
    outstanding_intents: &std::collections::HashSet<String>,
    // The caller's single-statement read of this row. Everything about
    // the row comes from here -- the target included, which used to be a
    // separate `get_symlink_target` and so could describe a different
    // incarnation than the version this function then proves.
    row: &RepairRowSnapshot,
    report: &mut MaterializationRepairReport,
) -> Result<(), MaterializationExecutionError> {
    let target = if kind == RecordKind::Symlink {
        let Some(target) = row.symlink_target.clone() else {
            // No target recorded at all -- matches `materialize_symlink_at`'s
            // own `PolicySkipped` outcome, which never attempts a write and
            // therefore never opens an intent either. Nothing to repair.
            return Ok(());
        };

        // The OTHER `PolicySkipped` case: a Windows peer that has not opted
        // into real symlink materialization. `target` above is genuinely
        // `Some` here (this device recorded it, it just declines to write
        // it), so unlike the branch above this does not early-out on its own
        // -- and without this check, it falls straight through to the
        // `on_disk_exists`/`has_intent` classification below, which cannot
        // tell "on-disk-missing because policy correctly declined to write
        // it" apart from "on-disk-missing because it was actually deleted".
        // That misclassification journals
        // the path dirty as "removed", and the always-running dirty-journal
        // redrive then emits a real, signed, GROUP-WIDE PROPAGATING tombstone
        // `Change` for a path this device never actually deleted -- turning a
        // benign, per-device policy choice into silent, unrecoverable data
        // loss for every OTHER peer in the group. Mirrors `materialize_
        // symlink_at`'s own `write_eligible` computation exactly, so the
        // write path and the repair path agree on what "policy declines to
        // write this" means. See that function's matching `materialization_
        // state` demotion for the other half of this fix (closes the window
        // for a fresh row; this closes it for a legacy row already stuck at
        // `Present` from before that fix shipped).
        #[cfg(unix)]
        let policy_permits_write = true;
        #[cfg(windows)]
        let policy_permits_write = state.windows_symlink_opt_in_for_group(group_id)?;
        #[cfg(not(any(unix, windows)))]
        let policy_permits_write = false;
        // Unconditional on `policy_permits_write` alone -- NOT combined with
        // `has_unsettled_obligation`. A combined version of this check
        // (`!policy_permits_write && has_unsettled_obligation`) was tried and
        // reverted: a LEGACY row that predates `materialize_symlink_at`'s own
        // demote-to-`Remote` fix has no obligation row at all --
        // `bootstrap_obligations_from_legacy_unapplied_changes` only backfills
        // rows behind an unapplied `changes` entry, and the repair-candidate
        // scan only ever selects `placeholder`/`hydrating` rows, never
        // `Present` ones -- so combining this check with `has_unsettled_
        // obligation` silently reopened the exact bug this function exists to
        // prevent, for every such legacy row: the check no longer fired, so
        // repair fell through to the offline-deletion classification below and
        // emitted the same real, signed, group-wide propagating tombstone the
        // unconditional check was written to prevent. Invisible on
        // non-Windows CI, since this whole branch is `#[cfg(windows)]`-gated.
        //
        // The accepted cost of staying unconditional instead: a symlink that
        // genuinely WAS written while opt-in was on, then legitimately deleted
        // offline AFTER opt-in was later turned off, has its repair-side
        // convergence suppressed too (current policy says nothing about
        // whether THIS row was ever actually materialized) -- bounded, not
        // unbounded: the startup full scan still reconciles it, so this is
        // lost redundancy, not lost data, and `reconcile_disk_with_ignore`
        // already applies the identical "any obligation row, including
        // `ignore_blocked`" suppression semantics elsewhere in this codebase,
        // so accepting this kind of over-suppression here isn't a new pattern.
        if !policy_permits_write {
            return Ok(());
        }
        Some(target)
    } else {
        None
    };

    let out_path = root.join(path);
    let lstat = std::fs::symlink_metadata(&out_path).ok();
    let on_disk_matches = match &target {
        Some(target) => {
            let on_disk_target = lstat
                .as_ref()
                .filter(|m| m.file_type().is_symlink())
                .and_then(|_| std::fs::read_link(&out_path).ok())
                .map(|t| yadorilink_fs_platform::fs_identity::target_to_bytes(&t));
            on_disk_target.as_deref() == Some(target.as_slice())
        }
        None => {
            lstat.as_ref().is_some_and(|m| m.is_dir())
                && yadorilink_local_storage::unix_mode_already_matches_disk(
                    &out_path,
                    row.unix_mode,
                )?
        }
    };
    if on_disk_matches {
        // The link on disk is exactly what the row says it should be, so
        // what is left is whatever the interrupted attempt did not
        // finish. This used to drop the intent and stop -- publishing no
        // proof at all, on a lane where no other pass publishes one
        // either. A symlink row could therefore sit `Present` with its
        // proof already dead (the live path bumps the fence before
        // writing) and no intent left to mark it, which nothing would
        // ever heal: the file arm's re-proving lane is `RecordKind::File`
        // only, and so is `hydrate`'s.
        //
        // Healthy rows still write nothing, same as the file arm.
        let proof_stands = state.has_usable_materialized_generation(group_id, path)?;
        let intent_outstanding = outstanding_intents.contains(path);
        let row_state = row.materialization_state;
        if proof_stands && row_state == Some(MaterializationState::Present) && !intent_outstanding {
            return Ok(());
        }
        let (Some(version), Some(state_now)) = (row.current_version, row_state) else {
            return Ok(());
        };
        let identity =
            yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path).ok();
        let committed = state.commit_recovered_materialized_state(
            group_id,
            path,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind,
                version,
                identity: Box::new(identity),
            },
            yadorilink_peer_session::ports::ExpectedAuthoring {
                state: state_now,
                expected_version: Some(&version),
            },
            permit,
        )?;
        if committed && !proof_stands {
            report.reproven.push(path.to_string());
        }
        return Ok(());
    }

    let intent_kind = state.materialization_intent_kind(group_id, path)?;
    let on_disk_exists = lstat.is_some();
    // An open delete intent is a tombstone delete interrupted around its
    // removal, not an interrupted write: see the regular-file arm. Never
    // rebuild the link, whether the path is missing or something a user
    // put there since; the delete settles it.
    if intent_kind == Some(MaterializationIntentKind::Delete) {
        tracing::debug!(
            group_id,
            path = %path,
            "a Hydrated symlink is under an open delete intent; leaving it to that delete"
        );
        return Ok(());
    }
    // Only a symlink is this arm's to replace: a regular file or directory
    // at the path may be a user's, and is never overwritten (as for the
    // directory arm below).
    if target.is_some() && lstat.as_ref().is_some_and(|m| !m.file_type().is_symlink()) {
        tracing::warn!(
            group_id,
            path,
            "a symlink's path holds something that is not a symlink; left untouched rather \
             than replaced"
        );
        return Ok(());
    }
    let has_intent = intent_kind.is_some();
    // A live, per-path read (see `MaterializationExecutionPort::has_
    // unsettled_projection_obligation`'s own doc comment) -- covers any
    // OTHER route that can leave a row `Present` with nothing on disk and
    // no intent, on every platform, not just the Windows policy-skip case
    // above -- a freshly-admitted row this pass runs before the first
    // materialize attempt, `restore_to_version`'s own symlink dispatch
    // mid-write, a bootstrap-scaffold row created by incoming metadata
    // before the paired content write lands, and any future such route,
    // PROVIDED it is still genuinely unsettled: this guard covers "not yet
    // settled", not "settled but left in the wrong state". It does NOT
    // cover a hazard hold: `HazardHeld` settlement deletes the obligation
    // row (`complete_obligation_if_non_exact_proof_current`), so this
    // guard goes inert for that class the moment the engine settles it.
    // The hazard-hold route is safe only because of the separate, direct
    // `materialization_state` demotion `hold_record` performs itself, not
    // because of this generic mechanism.
    let has_unsettled_obligation = state.has_unsettled_projection_obligation(group_id, path)?;
    if !on_disk_exists && !has_intent && has_unsettled_obligation {
        // Missing, no intent, but still-unsettled -- must NOT be resolved
        // either way here. Falling through to the reconstruct below would
        // silently RESURRECT a genuine offline deletion that happens to
        // race an unrelated pending obligation on this same path (and once
        // resurrected, nothing else in this sweep will ever tombstone it
        // again); classifying it as offline-deleted here would be just as
        // wrong for a path the Convergence Engine has not finished placing
        // yet. Defer entirely -- the next pass re-evaluates once the
        // obligation settles one way or the other.
        return Ok(());
    }
    if !on_disk_exists && !has_intent && mode == RepairMode::Live {
        // See `RepairMode::Live`'s own doc comment: this "missing, no
        // intent" observation may be a delete the user is making RIGHT
        // NOW, not yet captured.
        state.record_dirty_path(group_id, path, "removed", repair_now_unix_nanos(), permit)?;
        return Ok(());
    }
    if !on_disk_exists && !has_intent {
        // Missing, disambiguated by the durable materialization journal:
        // the write had already completed (its intent was cleared) and
        // the symlink was then deleted while the daemon was stopped.
        // Reconstructing it from the index would silently resurrect that
        // offline deletion.
        // Left for the startup reconcile scan to tombstone, as in the file
        // arm.
        report.offline_deleted.push(path.to_string());
        return Ok(());
    }
    if on_disk_exists && !has_intent && mode == RepairMode::Live {
        // Present but diverged, no intent, on the live cadence: may be a
        // local edit not yet captured. Defer to the dirty-journal
        // backstop rather than touching the symlink at all.
        state.record_dirty_path(
            group_id,
            path,
            "created_or_modified",
            repair_now_unix_nanos(),
            permit,
        )?;
        return Ok(());
    }
    if on_disk_exists && !has_intent {
        // Startup, present, diverged, no intent: an offline edit this
        // pass cannot safely resolve without the file arm's quarantine
        // machinery (not yet extended to symlinks). Left untouched rather
        // than silently overwriting a possible local change.
        tracing::warn!(
            group_id,
            path,
            "a diverged on-disk symlink with no repair intent was left untouched -- symlink \
             quarantine-on-diverge is not implemented"
        );
        return Ok(());
    }

    // Either missing with an intent (a genuine crash mid-write), or
    // present-but-wrong with an intent (a genuine interrupted overwrite)
    // -- both are safe to reconstruct from the durably recorded row.
    let (mutation_generation, intent_guard) = match &target {
        Some(target) => {
            let Some(opened) = rebuild_interrupted_symlink(
                state, root, group_id, path, &out_path, target, permit,
            )?
            else {
                return Ok(());
            };
            opened
        }
        None => {
            if lstat.as_ref().is_some_and(|m| !m.is_dir()) {
                tracing::warn!(
                    group_id,
                    path,
                    "an explicit directory's path holds something that is not a directory; \
                     left untouched rather than replaced"
                );
                return Ok(());
            }
            let canonical_root = std::fs::canonicalize(root)?;
            let opened = state.open_repair_object_rebuild(
                group_id,
                path,
                RecordKind::Directory,
                &yadorilink_local_storage::intent_target_hash(&[]),
                permit,
            )?;
            yadorilink_local_storage::create_explicit_directory(
                &out_path,
                &canonical_root,
                &GroupStructuralLedger::new(state, group_id),
            )?;
            yadorilink_local_storage::apply_unix_mode(&out_path, row.unix_mode)?;
            opened
        }
    };
    // The intent is cleared by the commit below, not before it: clearing
    // first leaves a window where the object exists, nothing records that a
    // write was in flight, and no proof has landed. Dropping the guard
    // unclear is inert -- the commit owns the clear.
    drop(intent_guard);
    let Some(version) = row.current_version else {
        tracing::warn!(
            group_id,
            path,
            ?kind,
            "rebuilt an object whose current version row is absent; leaving it unproven for \
             the next pass rather than publishing a proof that names no version"
        );
        return Ok(());
    };
    // The proof, with the identity now observable at the object, guarded
    // on the row this rebuild verified against.
    let published = state.settle_repair_object_rebuild(
        group_id,
        path,
        kind,
        &out_path,
        version,
        row.materialization_state,
        mutation_generation,
        permit,
    )?;
    if published {
        report.reconstructed.push(path.to_string());
    } else {
        tracing::info!(
            group_id,
            path,
            ?kind,
            "the row this rebuild verified against moved before its commit; the intent stays \
             open for the next pass"
        );
    }
    Ok(())
}

/// A journaled write's still-open materialization intent.
type OpenIntent<'a> =
    Box<dyn crate::materialization_execution::OpenMaterializationIntent + Send + 'a>;

/// The symlink half of [`repair_one_interrupted_single_object`]'s rebuild:
/// the write-policy check, then the journaled write of the recorded
/// target. `None` when policy declines the write.
fn rebuild_interrupted_symlink<'a>(
    state: &'a dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &'a str,
    path: &'a str,
    out_path: &Path,
    target: &[u8],
    permit: &'a RootCommitPermit<'a>,
) -> Result<Option<(i64, OpenIntent<'a>)>, MaterializationExecutionError> {
    #[cfg(unix)]
    let write_eligible = true;
    #[cfg(windows)]
    let write_eligible = state.windows_symlink_opt_in_for_group(group_id)?;
    #[cfg(not(any(unix, windows)))]
    let write_eligible = false;
    if !write_eligible {
        // Matches the live materialize path's own policy: a Windows link
        // that has not opted in never gets a real symlink written, so
        // repair must not write one on its behalf either.
        return Ok(None);
    }

    verify_write_target_within_root(out_path, root, &GroupStructuralLedger::new(state, group_id))?;
    // Retained, not discarded. This arm really does mutate disk, so it is
    // an internal mutator and everything it publishes goes out under
    // exactly the epoch its own write produced. Bumping and then
    // publishing nothing -- which is what this did -- actively destroys
    // whatever proof the path still had.
    //
    // The bump, then the intent naming the recorded target.
    let target_hash = yadorilink_local_storage::intent_target_hash_for_bytes(target);
    let opened = state.open_repair_object_rebuild(
        group_id,
        path,
        RecordKind::Symlink,
        &target_hash,
        permit,
    )?;
    #[cfg(unix)]
    yadorilink_local_storage::materialize_symlink_in(
        out_path,
        target,
        &crate::materialization_execution::GroupTempLedger::new(state, group_id),
    )?;
    #[cfg(windows)]
    yadorilink_local_storage::materialize_symlink_windows_in(
        out_path,
        target,
        &crate::materialization_execution::GroupTempLedger::new(state, group_id),
    )?;
    Ok(Some(opened))
}

/// Assembles `record`'s indexed blocks onto disk at `out_path` under a durable
/// materialization intent, so a crash *during this write itself* is recoverable
/// (the intent is still present on the next repair pass) rather than being
/// misread as an offline deletion of a `Present` file. Brackets the write with
/// `MaterializationExecutionPort::open_materialization_intent_guard`'s
/// returned guard — the same single seam the live peer materialize path uses
/// (through its own `yadorilink-peer-session::ports::OpenMaterializationIntent`
/// marker) — so the intent is durable before the temp-write-then-rename
/// begins. It is left open on every outcome: the caller's proof commit clears
/// it atomically with the proof and the `Present` stamp. This module never
/// names the concrete guard type (`yadorilink-daemon`'s
/// `MaterializationIntentGuard`) — only the opaque
/// `Box<dyn OpenMaterializationIntent + Send + '_>` the port method returns.
///
/// `Ok(())` means the *whole* physical sequence completed — bytes assembled
/// and the indexed mode and xattrs applied, the intent still open — not
/// merely that the content landed. Repair reports a path as `reconstructed` on
/// exactly that basis, so a file it lists is left the way the live peer
/// materialize path would have left it, permissions included, rather than
/// being a second, weaker materialization implementation.
struct JournaledReconstruction<'a> {
    state: &'a dyn MaterializationExecutionPort,
    store: &'a dyn BlockContentStore,
    group_id: &'a str,
    path: &'a str,
    out_path: &'a Path,
    /// The link root `out_path` lives under, re-verified right before the
    /// assembled file is renamed into it.
    root: &'a Path,
    blocks: &'a [yadorilink_replica_domain::file::BlockInfo],
    mtime_unix_nanos: i64,
    /// The mode and xattrs to stamp on the reconstructed file, from the
    /// caller's own single-statement row read -- the same incarnation
    /// `blocks`, `mtime_unix_nanos` and `target_version_hash` come from.
    unix_mode: Option<u32>,
    xattrs: &'a [(String, Vec<u8>)],
    target_version_hash: &'a [u8],
    permit: &'a RootCommitPermit<'a>,
}

// Test-only: makes the next reconstructs on this thread fail right after
// their bytes were renamed into place, as a failed mode or xattr apply does.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static FAIL_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms (or disarms) the failure described on `FAIL_AFTER_RENAME`.
#[cfg(any(test, feature = "test-support"))]
pub fn set_fail_after_rename_for_test(armed: bool) {
    FAIL_AFTER_RENAME.with(|cell| cell.set(armed));
}

fn reconstruct_file_journaled(
    request: JournaledReconstruction<'_>,
) -> Result<(), MaterializationExecutionError> {
    let guard = request.state.open_materialization_intent_guard(
        request.group_id,
        request.path,
        request.target_version_hash,
        request.permit,
    )?;
    // Never cleared here. Every `?` below returns with `guard` still live, and
    // the success path drops it uncleared too: the intent stays open through
    // the bytes, the mode and the xattrs, and is cleared only by the caller's
    // proof commit (`settle_repair_reconstruct`), in the same transaction that
    // publishes the proof and stamps `Present`. Clearing it any earlier
    // opens a window with neither an intent nor a proof, in which a crash or
    // a failed metadata write or commit leaves nothing recording that this
    // write was ever in flight.
    let ledger =
        crate::materialization_execution::GroupTempLedger::new(request.state, request.group_id);
    let tmp_path = reconstruct_file_to_temp_in(
        request.store,
        request.out_path,
        request.blocks,
        request.mtime_unix_nanos,
        &ledger,
    )?;
    // The assembly takes time proportional to the file, long enough for the
    // volume under the root to go away and leave a bare mountpoint. Prove the
    // root's identity again immediately before the rename, so nothing is
    // published onto the parent filesystem and no Present row follows.
    if let Err(error) = request.state.verify_root(request.root, request.group_id) {
        yadorilink_local_storage::discard_temp_file(&tmp_path, &ledger);
        return Err(error);
    }
    persist_reconstructed_file_in(&tmp_path, request.out_path, &ledger)?;
    #[cfg(any(test, feature = "test-support"))]
    if FAIL_AFTER_RENAME.with(std::cell::Cell::get) {
        return Err(MaterializationExecutionError::CorruptState(
            "injected failure after the rename".to_string(),
        ));
    }
    // `reconstruct_file` assembles into a fresh temp file, which gets default
    // permissions — so the assembled result does NOT carry the exec bit the
    // index recorded for this path, and a repaired POSIX executable would come
    // back as a plain file if this call were skipped. `local_change.rs`'s
    // content-only self-echo suppression now compares the on-disk exec bit
    // against the index too (alongside `reconstruct_file`'s own mtime
    // stamping), so a later local scan would eventually notice and
    // self-heal the divergence rather than leaving it silent. Still not a reason to
    // skip this call: repair's own contract (this function's doc comment
    // above) is that a path it reports `reconstructed` was left exactly as
    // the live peer materialize path would have left it, exec bit included,
    // not merely "eventually correct once some other pass notices."
    //
    // Both come from the caller's payload, not from a fresh read here.
    // `target_version_hash` -- the version the proof this arm publishes
    // names -- is a hash over the mode and the xattrs as well, so reading
    // them back off the row at this point would stamp one incarnation's
    // metadata onto bytes proven as another's.
    //
    // The attributes are strictly confirmed inside this write, before the
    // final mode. Unconfirmed attributes mean no exact proof: the caller
    // settles nothing and leaves the retriable placeholder, as for any other
    // failed reconstruct.
    let applied = yadorilink_local_storage::apply_file_metadata_verified(
        request.out_path,
        request.unix_mode,
        request.xattrs,
    )?;
    if let Err(refused) = yadorilink_local_storage::XattrEvidence::from(applied)
        .prove(request.out_path, request.xattrs)
    {
        return Err(MaterializationExecutionError::ReplicatedXattrsNotProven(format!(
            "{}: {refused:?}",
            request.path
        )));
    }
    drop(guard);
    Ok(())
}

/// Wall-clock now in unix nanoseconds, for stamping an offline-delete tombstone
/// this pass emits (mirrors the observed-time stamp the disk scan's delete path
/// uses). Monotonic-clock skew is irrelevant here — this is an observed-at
/// timestamp on a local tombstone, not an ordering primitive.
fn repair_now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestoreRecoveryReport {
    pub committed: Vec<String>,
    pub discarded_unstarted: Vec<String>,
    pub preserved_divergent: Vec<String>,
}

/// Which materialization states this sweep is allowed to act on.
///
/// `Present` is the original case: the index claims exact content, so a
/// disk that does not match it is a divergence only this pass can
/// diagnose.
///
/// `Hydrating` WITH an open materialization intent is the second, and it
/// is the same situation seen one step earlier. The projected-upserts
/// batch commits each row and opens its intent before publishing any of
/// the batch's temp files, so a crash in that window leaves exactly this
/// pair: a row naming the new version, a durable journal entry saying a
/// write for it was in flight, and on-disk bytes that are still the old
/// ones. The row makes no exact claim -- which is the point -- but it is
/// no less this pass's to repair, and nothing else can tell it apart from
/// an edit made while the daemon was down.
///
/// `Hydrating` WITHOUT an intent is an abandoned fetch, which the startup
/// `Hydrating` reset owns; acting on it here would race that.
fn is_repair_candidate_state(
    state: MaterializationState,
    outstanding_intents: &std::collections::HashSet<String>,
    path: &str,
) -> bool {
    match state {
        MaterializationState::Present => true,
        MaterializationState::Hydrating => outstanding_intents.contains(path),
        MaterializationState::Remote | MaterializationState::Evicting => false,
    }
}

/// What an exact verification has to compare for one indexed row, chosen
/// by that row's own declared kind rather than assumed to be a regular
/// file. A `Directory` needs no content at all: the paths inside it are
/// their own rows with their own proofs.
fn expected_object_for<'a>(
    kind: RecordKind,
    blocks: &'a [yadorilink_replica_domain::file::BlockInfo],
    symlink_target: Option<&'a [u8]>,
) -> ExpectedObject<'a> {
    match kind {
        RecordKind::File => ExpectedObject::File { blocks },
        RecordKind::Symlink => ExpectedObject::Symlink { target: symlink_target },
        RecordKind::Directory => ExpectedObject::Directory,
    }
}

/// Reconciles restore intents before generic startup materialization repair.
/// The disk content, not the journal state alone, is authoritative because a
/// process can die after the atomic rename but before persisting
/// `DiskCommitted`. Publishing and deleting the journal is one SQLite
/// transaction (see `commit_restore_operation`'s own doc comment for the
/// atomicity guarantee), so rerunning this function cannot append a second
/// version.
pub fn reconcile_restore_operations(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    permit: &RootCommitPermit,
) -> Result<RestoreRecoveryReport, MaterializationExecutionError> {
    let mut report = RestoreRecoveryReport::default();
    for operation in state.list_restore_operations(group_id)? {
        let out_path = root.join(&operation.path);
        verify_write_target_within_root(
            &out_path,
            root,
            &GroupStructuralLedger::new(state, group_id),
        )?;

        // Compared by the kind the journaled version itself declares. The
        // block comparison alone is a regular-file question: asked about a
        // symlink it follows the link and compares the TARGET's bytes
        // against the link's own empty block list, and asked about a
        // directory it fails the read outright. A restored symlink or
        // directory therefore never verified, however exactly right it
        // was, and recovery fell through to quarantine it.
        let journaled = expected_object_for(
            operation.meta.record_kind,
            &operation.record.blocks,
            operation.meta.symlink_target.as_deref(),
        );
        if disk_matches_expected_object(&out_path, journaled)? == DiskContentComparison::Matched {
            let already_committed = state
                .get_file(group_id, &operation.path)?
                .is_some_and(|current| current == operation.record);
            if already_committed {
                state.discard_restore_operation(&operation.operation_id)?;
            } else {
                // Reached only after the kind-aware verification above
                // confirmed the object's bytes. A regular file's version
                // also names its mode and replicated xattrs, and recovery
                // wrote none of them (an earlier process may have died
                // between the bytes and the metadata), so they are re-proved
                // from disk here; anything not proven publishes no exact
                // proof. The restore is still committed, as the live lane
                // does when it cannot confirm its attributes.
                let metadata_proven = operation.meta.record_kind != RecordKind::File
                    || (yadorilink_local_storage::unix_mode_already_matches_disk(
                        &out_path,
                        operation.meta.unix_mode,
                    )
                    .unwrap_or(false)
                        && yadorilink_local_storage::XattrEvidence::ReproveFromDisk
                            .prove(&out_path, &operation.meta.xattrs)
                            .is_ok());
                let identity = if metadata_proven {
                    yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path).ok()
                } else {
                    None
                };
                // `None`: recovery wrote nothing. It re-verified bytes an
                // earlier process left behind, so it has no epoch of its
                // own to publish under and adopts what it observed
                // instead -- see `commit_restore_operation`'s own doc for
                // why the two lanes differ.
                match state.commit_restore_operation(
                    &operation.operation_id,
                    identity.as_ref(),
                    None,
                    permit,
                )? {
                    RestoreCommitOutcome::Committed(_) => {}
                    RestoreCommitOutcome::Missing => continue,
                    // Unreachable for the adoption lane, which has no CAS
                    // to lose; handled rather than unwrapped so the two
                    // lanes cannot drift into a silent `unreachable!`.
                    RestoreCommitOutcome::FenceLost => continue,
                    RestoreCommitOutcome::Superseded => {
                        let observed_at_unix_nanos = std::fs::metadata(&out_path)
                            .and_then(|metadata| metadata.modified())
                            .ok()
                            .and_then(|modified| {
                                modified.duration_since(std::time::UNIX_EPOCH).ok()
                            })
                            .map(|duration| duration.as_nanos() as i64)
                            .unwrap_or(0);
                        state.preserve_divergent_restore(
                            &operation.operation_id,
                            group_id,
                            &operation.path,
                            "created_or_modified",
                            observed_at_unix_nanos,
                            permit,
                        )?;
                        report.preserved_divergent.push(operation.path);
                        continue;
                    }
                }
            }
            report.committed.push(operation.path);
            continue;
        }

        // The same kind-awareness on the other side of the question: "is
        // this the unstarted restore's base, untouched" is asked of
        // whatever kind the CURRENT row declares, which need not be the
        // journaled version's kind at all. Every field below comes from
        // one statement against one incarnation of the row -- the kind,
        // the blocks and the symlink target alike. The target used to be
        // a separate read, which made this comment's own claim false.
        let snapshot = state.repair_row_snapshot(group_id, &operation.path)?;
        let disk_still_matches_current = match snapshot.file.as_ref() {
            Some(record) if record.deleted => !out_path.exists(),
            Some(record) => {
                let expected = expected_object_for(
                    snapshot.record_kind.unwrap_or(RecordKind::File),
                    &record.blocks,
                    snapshot.symlink_target.as_deref(),
                );
                disk_matches_expected_object(&out_path, expected)? == DiskContentComparison::Matched
            }
            None => !out_path.exists(),
        };
        if disk_still_matches_current {
            state.discard_restore_operation(&operation.operation_id)?;
            report.discarded_unstarted.push(operation.path);
            continue;
        }

        // Neither side of the interrupted operation explains the bytes. They
        // may be an offline/local edit, so make the ordinary startup repair
        // quarantine and re-index them rather than overwriting them.
        let change_kind = if out_path.exists() { "created_or_modified" } else { "removed" };
        let observed_at_unix_nanos = std::fs::metadata(&out_path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos() as i64)
            .unwrap_or(0);
        state.preserve_divergent_restore(
            &operation.operation_id,
            group_id,
            &operation.path,
            change_kind,
            observed_at_unix_nanos,
            permit,
        )?;
        report.preserved_divergent.push(operation.path);
    }
    Ok(report)
}

/// Moves the current on-disk bytes of `rel_path` (under `root`) aside to a
/// conflict-copy sibling, returning the link-relative quarantine path — or
/// `None` if there is nothing on disk to move. Used by
/// `repair_interrupted_materializations` before it would otherwise overwrite a
/// path whose journaled local edit means the on-disk bytes may be a newer user
/// edit the watcher had not yet indexed. The quarantine name follows the same
/// `(conflicted copy, ...)` convention as conflict copies
/// (`yadorilink_replica_domain::conflict::conflict_copy_path`), so it reads naturally to the user
/// and the watcher re-syncs it as an ordinary new file. The move is the one
/// held-path recovery uses (`held_path_reconcile::move_aside`): the name's
/// disambiguator digests the bytes themselves, and the rename never replaces
/// an earlier copy already under the name chosen. A fixed `"local-recovered"`
/// device component names the origin without threading this device's id in.
/// The rename target is verified to stay within `root`, exactly like every
/// other write path in this module.
fn quarantine_dirty_disk_file(
    root: &Path,
    rel_path: &str,
    ledger: &dyn yadorilink_local_storage::StructuralDirectoryLedger,
) -> Result<Option<(String, i64)>, MaterializationExecutionError> {
    let src = root.join(rel_path);
    let meta = match std::fs::symlink_metadata(&src) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mtime_unix_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let quarantine_rel =
        crate::held_path_reconcile::move_aside(root, rel_path, &src, ledger, "local-recovered")?;
    Ok(Some((quarantine_rel, mtime_unix_nanos)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Quarantining moves bytes aside and creates no directory.
    struct NoLedger;
    impl yadorilink_local_storage::StructuralDirectoryLedger for NoLedger {
        fn record_intent(
            &self,
            rel_path: &str,
        ) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("quarantining created a directory: {rel_path}")
        }
        fn complete(
            &self,
            rel_path: &str,
            _identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
        ) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("quarantining created a directory: {rel_path}")
        }
        fn abandon(&self, rel_path: &str) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("quarantining created a directory: {rel_path}")
        }
        fn interrupted(
            &self,
            rel_path: &str,
        ) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("quarantining created a directory: {rel_path}")
        }
    }

    /// Two different unsaved edits quarantined from one path agree on size
    /// and modification time when a tool restores timestamps or the
    /// filesystem's clock is coarse. Named from those alone, the second
    /// copy took the first one's name and the rename replaced it.
    #[test]
    fn a_second_quarantine_does_not_replace_an_earlier_conflict_copy() {
        let root = tempfile::tempdir().unwrap();
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let mut quarantined = Vec::new();
        for content in [b"first edit!".as_slice(), b"other edit!".as_slice()] {
            let src = root.path().join("doc.txt");
            std::fs::write(&src, content).unwrap();
            std::fs::File::options().write(true).open(&src).unwrap().set_modified(mtime).unwrap();
            let (copy, _observed_at) =
                quarantine_dirty_disk_file(root.path(), "doc.txt", &NoLedger).unwrap().unwrap();
            quarantined.push(copy);
        }

        assert_ne!(quarantined[0], quarantined[1], "two different edits must get two names");
        assert_eq!(std::fs::read(root.path().join(&quarantined[0])).unwrap(), b"first edit!");
        assert_eq!(std::fs::read(root.path().join(&quarantined[1])).unwrap(), b"other edit!");
        assert!(!root.path().join("doc.txt").exists(), "the original was moved aside");
    }

    #[test]
    fn quarantining_an_absent_path_moves_nothing() {
        let root = tempfile::tempdir().unwrap();
        assert!(quarantine_dirty_disk_file(root.path(), "doc.txt", &NoLedger).unwrap().is_none());
    }
}
