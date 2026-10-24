//! Debounce flush processing and the batched authoritative commit
//! (`flush_pending_batch`) of mutations prepared during a flush.

use std::path::{Path, PathBuf};

use crate::error::LocalCaptureError;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::dirty_journal::dirty_kind_str;
use super::disk_observation::{
    disk_bytes_match_indexed_blocks_off_worker, error_means_absent, exact_leaf_exists_as_directory,
    prepare_match, try_exact_leaf_exists_as_file_or_symlink, PrepareMatch,
};
use super::event_ingest::EventOutcome;
use super::path_policy::relative_key;
use super::{FlushOutcome, LocalChangeOutcome, LocalChangeProcessor};

/// One path's authoritative mutation, prepared during a batched flush's
/// per-path pass (chunked, hashed, and decided against the state read at
/// that moment) but not yet committed, together with everything
/// `flush_pending_batch` needs to prove it is still current before
/// including it in the shared transaction: the disk identity and index row
/// this preparation was based on, so a change to either between
/// preparation and commit excludes this mutation from the batch rather
/// than authoring stale bytes or clobbering a concurrent peer update (see
/// `flush_pending_batch`'s own doc for the full argument -- this is the
/// SAME race-fingerprint scheme (`disk_race_fingerprint_or_stat`, stat-only where the volume has no change time) `peer_session::PeerSyncSession::
/// hydrate_inner` already relies on for the identical class of "is what I
/// prepared still current" question, applied here to local capture instead
/// of peer materialization).
pub(super) struct PendingBatchedCommit {
    pub(super) rel_path: String,
    pub(super) event_path: PathBuf,
    pub(super) observed_at_unix_nanos: i64,
    pub(super) disk_fingerprint_at_prepare: Option<(u64, Option<std::time::SystemTime>, i64, i64)>,
    pub(super) mutation: yadorilink_replica_domain::session_state::PreparedLocalMutation,
}

/// For a mutation whose fingerprint sample is stat-only: whether the file on disk still holds
/// exactly what the mutation records (a file's blocks, a symlink's target, a directory). Fail
/// closed: an unreadable path or any difference is "no", and the mutation is excluded and
/// re-driven. A delete has no bytes to check (its exact leaf is re-confirmed absent separately).
fn degraded_upsert_bytes_still_match(pending_commit: &PendingBatchedCommit) -> bool {
    use yadorilink_local_storage::{
        disk_matches_expected_object, DiskContentComparison, ExpectedObject,
    };
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_replica_domain::session_state::PreparedLocalMutation;
    let PreparedLocalMutation::Upsert { record, version, .. } = &pending_commit.mutation else {
        return true;
    };
    let path = &pending_commit.event_path;
    match version.meta.record_kind {
        // The bytes are read through `File::open`, which follows a symlink: the object must be a
        // regular file first.
        RecordKind::File => {
            std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
                && disk_bytes_match_indexed_blocks_off_worker(path, &record.blocks, record.size)
                    .unwrap_or(false)
        }
        RecordKind::Symlink => matches!(
            disk_matches_expected_object(
                path,
                ExpectedObject::Symlink { target: version.meta.symlink_target.as_deref() },
            ),
            Ok(DiskContentComparison::Matched)
        ),
        RecordKind::Directory => matches!(
            disk_matches_expected_object(path, ExpectedObject::Directory),
            Ok(DiskContentComparison::Matched)
        ),
    }
}

/// How many times a single path's chunk/index step is retried when it fails
/// with a *transient* block-store fault before the flush gives up on that
/// path. Bounded so a genuinely-stuck store can never spin forever; large
/// enough that a brief disk blip (or, under the deterministic simulator, a
/// fault decorator's "every Nth op" schedule) reliably clears on a later,
/// non-faulting attempt. Kept in line with the peer-materialize reconstruct
/// guard's own bound.
pub(super) const MAX_LOCAL_INDEX_RETRIES: u32 = 20;

/// How many processed paths' dirty-journal clears accumulate before
/// `process_flush_with_ignore` flushes them as one
/// `clear_dirty_paths_conditional_batch` transaction, instead of committing
/// (and fsyncing) each path's clear separately.
pub(super) const DIRTY_CLEAR_BATCH_SIZE: usize = 32;

/// How many prepared authoritative mutations (`PendingBatchedCommit`)
/// accumulate before `flush_pending_batch` commits them as one
/// `commit_local_mutations_batch` transaction, instead of committing (and
/// fsyncing) each path's mutation separately. Deliberately small relative
/// to `DIRTY_CLEAR_BATCH_SIZE`: every member's path lock is held for the
/// whole batch, so a large batch would hold many locks simultaneously for
/// longer than necessary.
pub(super) const AUTHORITATIVE_COMMIT_BATCH_SIZE: usize = 16;

/// Backoff between local-index retry attempts (see `MAX_LOCAL_INDEX_RETRIES`).
pub(super) const LOCAL_INDEX_RETRY_BACKOFF: std::time::Duration =
    std::time::Duration::from_millis(50);

/// Whether a `SyncSqliteError` from a path's chunk/index step is a
/// *transient* block-store fault that a bounded retry can clear, versus a
/// permanent error that must fail as before. Only the two transient
/// disk-fault shapes are retriable: a disk-full rejection (`DiskPressure`,
/// from the block store's own headroom preflight or an ENOSPC on write) and
/// a bare block-store I/O error (an EIO on the underlying `put`/`get`, which
/// the `From<StorageError>` impl wraps as `Storage(Io)` — never the
/// top-level `Io` variant, which is a filesystem call). Every other error —
/// a checksum mismatch (a torn/corrupt block), a missing block, an invalid
/// path, or a database/path-escape error — is permanent: retrying it just
/// wastes attempts, so it is classified non-retriable and fails immediately,
/// exactly as before this guard existed.
pub(super) fn is_retriable_block_store_error(e: &LocalCaptureError) -> bool {
    matches!(
        e,
        LocalCaptureError::SyncCore(SyncSqliteError::Storage(
            yadorilink_local_storage::StorageError::DiskPressure { .. }
                | yadorilink_local_storage::StorageError::Io(_)
                | yadorilink_local_storage::StorageError::SourceRead(_)
        ))
    )
}

impl LocalChangeProcessor {
    /// Turns one debounce-window flush (`debounce::DebounceFlush`) into
    /// indexed records — the executor half of 's accumulator/executor
    /// split. `DebounceFlush::Paths` is processed one path at a time via
    /// `process_event` (each individually indexed and self-echo-checked,
    /// exactly as a live single-event call would be); `DebounceFlush::RescanRequired`
    /// runs a full `scan_existing_files` reconciliation instead.
    ///
    /// Each path in a
    /// `DebounceFlush::Paths` batch is processed independently — one
    /// path's error (logged, not silently dropped) does not prevent the
    /// batch's other, unrelated paths from still being processed. A
    /// batch's paths come from a `HashMap` (no ordering guarantee), and
    /// the real filesystem watcher only ever fires once for a given real
    /// change: the previous behavior (`?` inside this loop, aborting the
    /// whole batch on the first error) could permanently lose an
    /// already-detected, unrelated event — including a local deletion
    /// that would otherwise have self-corrected a stale index row — to a
    /// transient failure (e.g. a exhausted-retry database-lock error
    /// under heavy concurrent load) on a completely different path
    /// earlier in iteration order.
    pub async fn process_flush(
        &self,
        group_id: &str,
        root: &Path,
        flush: DebounceFlush,
    ) -> Result<FlushOutcome, LocalCaptureError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        // `true`: this convenience entry point has no caller-supplied
        // fail-closed gate to respect, so it reproduces the historical
        // (pre-gating) behavior exactly -- every real production caller
        // goes through `process_flush_with_ignore` directly instead (see
        // `yadorilink-daemon`'s executor task), passing its own freshly-
        // computed gate.
        self.process_flush_with_ignore(group_id, root, flush, &ignore_set, true).await
    }

    /// `emit_tombstones` governs ONLY the `DebounceFlush::RescanRequired`
    /// case (`DebounceFlush::Paths` never emits a missing-file tombstone
    /// at all -- see `process_event`'s own per-path handling) -- see
    /// `scan_existing_files_with_ignore_gated_for_established_link`'s own
    /// doc comment for what this must be for a live caller (this link's
    /// startup-repair success ANDed with a FRESH read of the two-live-
    /// roots recovery flag, not a value frozen at link-start).
    #[allow(
        clippy::too_many_lines,
        clippy::excessive_nesting,
        reason = "the debounce-flush driver: both DebounceFlush variants \
                  plus, for the Paths variant, dirty-journal recording, the \
                  per-path retry loop with backoff over retriable \
                  block-store errors, policy-unavailable deferral, batched \
                  commit accumulation and bounded dirty-journal clearing. \
                  These layers share the mutable pending_clears / \
                  pending_batch accumulators and the per-path dirty_key, so \
                  the durability contract (a row is cleared only after its \
                  commit) is only checkable while they stay in one body"
    )]
    pub async fn process_flush_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        flush: DebounceFlush,
        ignore_set: &EffectiveIgnoreSet,
        emit_tombstones: bool,
    ) -> Result<FlushOutcome, LocalCaptureError> {
        match flush {
            DebounceFlush::Paths(paths) => {
                // Precompute each path's dirty-journal key once (`relative_key`
                // canonicalizes `root`, a syscall) and carry it alongside the
                // rest of the tuple through both the batch-journal step below
                // and the per-path processing loop that follows, instead of
                // recomputing it twice per path.
                let paths: Vec<(PathBuf, FsChangeKind, i64, Option<String>)> = paths
                    .into_iter()
                    .map(|(path, kind, observed_at)| {
                        let dirty_key = relative_key(root, &path);
                        (path, kind, observed_at, dirty_key)
                    })
                    .collect();

                // Journal the whole known batch durably in one transaction
                // *before* any path's block-store/index work runs — see
                // `record_dirty_paths_batch`'s own doc for why one commit for
                // the batch is equivalent to one commit per path here. The
                // debounce accumulator has already drained every path in this
                // flush, so if processing below crashes, restarts, or hits a
                // multi-second disk-full/EIO and the retry loop eventually
                // gives up, the in-memory knowledge that these paths changed
                // would otherwise be lost — a permanent split-brain. Rows
                // survive until the read/blockify/put/index+delta step commits
                // (cleared on the `Ok` arms below); a startup rescan and the
                // on-failure retry both re-drive whatever is still journaled.
                // If the batch call itself fails, fall back to the previous
                // per-path journal calls rather than invent new failure
                // semantics — either way a journal write failure is only
                // logged: losing the belt-and-suspenders row must not abort
                // processing the edits the normal way.
                let batch_entries: Vec<(String, String, i64)> = paths
                    .iter()
                    .filter_map(|(_, kind, observed_at, dirty_key)| {
                        dirty_key.as_ref().map(|key| {
                            (key.clone(), dirty_kind_str(*kind).to_string(), *observed_at)
                        })
                    })
                    .collect();
                if let Err(e) = self.state.record_dirty_paths_batch(
                    group_id,
                    &batch_entries,
                    &self.begin_journal_operation()?.permit(),
                ) {
                    tracing::warn!(
                        error = %e,
                        group_id,
                        path_count = batch_entries.len(),
                        "failed to batch-journal a debounced flush before processing; \
                         falling back to journaling each path individually"
                    );
                    for (path, kind, observed_at, dirty_key) in &paths {
                        if let Some(key) = dirty_key {
                            if let Err(e) = self.state.record_dirty_path(
                                group_id,
                                key,
                                dirty_kind_str(*kind),
                                *observed_at,
                                &self.begin_journal_operation()?.permit(),
                            ) {
                                tracing::warn!(
                                    error = %e,
                                    path = %path.display(),
                                    group_id,
                                    "failed to journal a dirty local path before processing; \
                                     proceeding with best-effort in-memory handling"
                                );
                            }
                        }
                    }
                }

                let mut records = Vec::new();
                // Successfully processed `(path, observed_at_unix_nanos)`
                // pairs, cleared from the dirty journal in bounded batches
                // (`DIRTY_CLEAR_BATCH_SIZE` at a time) rather than one
                // `write()`/fsync per path — see `clear_dirty_paths_conditional_batch`
                // for why each clear stays conditioned on its own
                // `observed_at_unix_nanos` rather than becoming an
                // unconditional `DELETE ... WHERE path IN (...)`.
                let mut pending_clears: Vec<(String, i64)> = Vec::new();
                let flush_pending_clears = |pending_clears: &mut Vec<(String, i64)>| {
                    if pending_clears.is_empty() {
                        return;
                    }
                    let result = self.begin_operation().and_then(|op| {
                        self.state
                            .clear_dirty_paths_conditional_batch(
                                group_id,
                                pending_clears,
                                &op.permit(),
                            )
                            .map_err(LocalCaptureError::from)
                    });
                    if let Err(e) = result {
                        tracing::warn!(
                            error = %e,
                            group_id,
                            path_count = pending_clears.len(),
                            "failed to clear a batch of processed dirty-path journal rows; \
                             a later rescan will re-verify and clear them"
                        );
                    }
                    pending_clears.clear();
                };
                // Prepared, not-yet-committed authoritative mutations for
                // the simple create/modify/delete case -- drained into one
                // shared `commit_local_mutations_batch` transaction every
                // `AUTHORITATIVE_COMMIT_BATCH_SIZE` paths (and once more
                // after this loop, for whatever remains) by
                // `flush_pending_batch`, instead of one commit per path.
                let mut pending_batch: Vec<PendingBatchedCommit> = Vec::new();
                let observed: Vec<(PathBuf, i64)> = paths
                    .iter()
                    .map(|(path, _, observed_at, _)| (path.clone(), *observed_at))
                    .collect();
                records.extend(
                    self.capture_recursive_operations_in_flush(
                        group_id, root, &observed, ignore_set,
                    )
                    .await,
                );
                for (path, kind, observed_at, dirty_key) in paths {
                    // A path's chunk/index step reads and writes content-
                    // addressed blocks through the block store. A *transient*
                    // block-store fault there — a disk-full
                    // (`SyncSqliteError::Storage(StorageError::DiskPressure)`)
                    // or an EIO (`SyncSqliteError::Storage(StorageError::Io)`)
                    // — must not
                    // silently drop this already-detected local edit: the
                    // debounce accumulator has already drained this path, and
                    // no live-repair sweep revisits a `Present` row whose
                    // on-disk bytes then silently drifted, so a dropped local
                    // write here is a permanent split-brain (two devices at
                    // the identical version vector with different on-disk
                    // bytes, which — equal VV being the sync identity — never
                    // reconcile). This mirrors the peer-materialize
                    // `reconstruct_file` guard (`PeerSyncSession::materialize`):
                    // the transient fault clears on a later, non-faulting
                    // attempt, so re-run this path's indexing a bounded number
                    // of times before giving up. Nothing is upserted on a
                    // failed attempt (chunking runs before any index write), so
                    // a retry is idempotent — it re-derives the same record and
                    // the same single version increment. A genuinely permanent
                    // error (anything not classified retriable) is not retried
                    // and fails exactly as before, so there is no
                    // unbounded/spin-forever risk.
                    let mut attempt = 0u32;
                    loop {
                        let result = self
                            .process_event_with_ignore_at(
                                group_id,
                                root,
                                &FsChangeEvent { path: path.clone(), kind },
                                ignore_set,
                                Some(observed_at),
                                Some(&mut pending_batch),
                            )
                            .await;
                        // The read/blockify/put/index+delta step for this path
                        // committed (or was a no-op), so its durable dirty-journal
                        // row is no longer needed — clear it. A crash in the
                        // narrow window between the index+delta commit and this
                        // delete just leaves the row for the next rescan, which
                        // re-reads the path, finds disk == index, and clears it
                        // as a `None` outcome: idempotent, never a lost edit.
                        let mut clear_dirty = || {
                            if let Some(key) = &dirty_key {
                                pending_clears.push((key.clone(), observed_at));
                                if pending_clears.len() >= DIRTY_CLEAR_BATCH_SIZE {
                                    flush_pending_clears(&mut pending_clears);
                                }
                            }
                        };
                        match result {
                            Ok(EventOutcome::Ready(LocalChangeOutcome::FileChanged(record))) => {
                                records.push(record);
                                clear_dirty();
                                break;
                            }
                            Ok(EventOutcome::Ready(LocalChangeOutcome::FilesChanged(orphaned))) => {
                                records.extend(orphaned);
                                clear_dirty();
                                break;
                            }
                            Ok(EventOutcome::Ready(LocalChangeOutcome::None)) => {
                                clear_dirty();
                                break;
                            }
                            Ok(EventOutcome::Ready(LocalChangeOutcome::RetryLater)) => {
                                // The file changed while it was read. Its
                                // dirty row stays (the capture already
                                // recorded why); the write that moved it
                                // queues the event that re-drives it.
                                tracing::info!(
                                    path = %path.display(),
                                    group_id,
                                    "a file changed while it was being captured; left \
                                     journaled dirty for a later flush"
                                );
                                break;
                            }
                            Ok(EventOutcome::Deferred) => {
                                // Prepared into `pending_batch`; this path's
                                // record/dirty-clear resolve once
                                // `flush_pending_batch` runs below (either
                                // right after this path, once the batch is
                                // full, or at the end of this flush).
                                break;
                            }
                            Err(LocalCaptureError::SyncCore(
                                SyncSqliteError::PolicyUnavailable,
                            )) => {
                                // The group's policy is stale, so the emit path
                                // withheld this edit's change rather than stamp
                                // it with a placeholder authorization context —
                                // a placeholder-auth change would become a local
                                // native head every valid-policy peer rejects,
                                // stranding this and every descendant change on
                                // an un-replicable branch. This is expected and
                                // transient, not a failure: leave the durable
                                // dirty-journal row in place (do NOT clear it)
                                // so the startup/backstop re-drive re-emits the
                                // path — with a real authorization stamp — once a
                                // valid policy snapshot restores the group.
                                // Nothing was written to the index or native state
                                // (the emit path returns before opening its write
                                // transaction), and the user's on-disk bytes are
                                // untouched; only the change emission is deferred.
                                let reason = SyncSqliteError::PolicyUnavailable.to_string();
                                if let Some(key) = &dirty_key {
                                    if let Err(je) = self.state.mark_dirty_path_attempt(
                                        group_id,
                                        key,
                                        &reason,
                                        &self.begin_operation()?.permit(),
                                    ) {
                                        tracing::warn!(
                                            error = %je,
                                            path = %key,
                                            group_id,
                                            "failed to record a dirty-path processing attempt"
                                        );
                                    }
                                }
                                tracing::info!(
                                    path = %path.display(),
                                    group_id,
                                    "withheld a local change because the group's policy is \
                                     stale; left the path journaled dirty to re-emit once a \
                                     valid policy snapshot is admitted"
                                );
                                break;
                            }
                            Err(e) => {
                                if is_retriable_block_store_error(&e)
                                    && attempt < MAX_LOCAL_INDEX_RETRIES
                                {
                                    attempt += 1;
                                    // Short backoff before re-reading/re-
                                    // writing the content-addressed blocks.
                                    // Under the deterministic simulator this
                                    // advances virtual time at no real cost;
                                    // in production it gives a transient disk
                                    // fault a moment to clear.
                                    tokio::time::sleep(LOCAL_INDEX_RETRY_BACKOFF).await;
                                    continue;
                                }
                                // Retries exhausted (or a permanent error).
                                // Leave the dirty-journal row in place — record
                                // the failure so the daemon's startup rescan
                                // (and any later flush touching the path)
                                // re-drives it rather than dropping the edit.
                                if let Some(key) = &dirty_key {
                                    if let Err(je) = self.state.mark_dirty_path_attempt(
                                        group_id,
                                        key,
                                        &e.to_string(),
                                        &self.begin_operation()?.permit(),
                                    ) {
                                        tracing::warn!(
                                            error = %je,
                                            path = %key,
                                            group_id,
                                            "failed to record a dirty-path processing attempt"
                                        );
                                    }
                                }
                                if Self::file_read_failure(&e).is_some() {
                                    // The user's own file could not be read: the unreadable-file
                                    // ledger (fed by the capture itself) already logs that once
                                    // per path/reason and carries the attention item, so every
                                    // re-drive pass stays quiet here.
                                    tracing::debug!(
                                        error = %e,
                                        path = %path.display(),
                                        group_id,
                                        attempts = attempt,
                                        "an unreadable path stays journaled dirty for re-drive"
                                    );
                                } else {
                                    tracing::warn!(
                                        error = %e,
                                        path = %path.display(),
                                        group_id,
                                        attempts = attempt,
                                        "failed to process one path in a debounced batch after \
                                         retries; left journaled dirty for re-drive on \
                                         rescan/restart"
                                    );
                                }
                                break;
                            }
                        }
                    }
                    if pending_batch.len() >= AUTHORITATIVE_COMMIT_BATCH_SIZE {
                        for (record, key, observed_at) in
                            self.flush_pending_batch(group_id, root, &mut pending_batch).await?
                        {
                            records.push(record);
                            pending_clears.push((key, observed_at));
                            if pending_clears.len() >= DIRTY_CLEAR_BATCH_SIZE {
                                flush_pending_clears(&mut pending_clears);
                            }
                        }
                    }
                }
                for (record, key, observed_at) in
                    self.flush_pending_batch(group_id, root, &mut pending_batch).await?
                {
                    records.push(record);
                    pending_clears.push((key, observed_at));
                }
                flush_pending_clears(&mut pending_clears);
                Ok(FlushOutcome { records })
            }
            DebounceFlush::RescanRequired => {
                let records = self.scan_existing_files_with_ignore_gated_for_established_link(
                    group_id,
                    root,
                    ignore_set,
                    emit_tombstones,
                    None,
                )?;
                Ok(FlushOutcome { records })
            }
        }
    }

    /// Streaming sibling of `process_flush_with_ignore`: for
    /// `DebounceFlush::Paths`, identical (each path is already processed
    /// and indexed individually, so there is no monolithic-batch delay to
    /// fix). For `DebounceFlush::RescanRequired`, `on_chunk_committed` is
    /// called once per durably-committed reconciliation chunk instead of
    /// withholding all of them until the whole scan returns -- see
    /// `scan_existing_files_with_ignore_streaming`'s own doc. The final
    /// `Ok(FlushOutcome)` is unchanged (still the whole scan's aggregate);
    /// a caller that streams per-chunk must not also re-announce this
    /// return value's `records` for `RescanRequired`, or every chunk would
    /// be announced twice.
    pub async fn process_flush_with_ignore_streaming(
        &self,
        group_id: &str,
        root: &Path,
        flush: DebounceFlush,
        ignore_set: &EffectiveIgnoreSet,
        emit_tombstones: bool,
        on_chunk_committed: &mut (dyn FnMut(&[FileRecord]) -> Result<(), LocalCaptureError> + Send),
    ) -> Result<FlushOutcome, LocalCaptureError> {
        match flush {
            DebounceFlush::Paths(_) => {
                self.process_flush_with_ignore(group_id, root, flush, ignore_set, emit_tombstones)
                    .await
            }
            DebounceFlush::RescanRequired => {
                let records = self.scan_existing_files_with_ignore_gated_for_established_link(
                    group_id,
                    root,
                    ignore_set,
                    emit_tombstones,
                    Some(on_chunk_committed),
                )?;
                Ok(FlushOutcome { records })
            }
        }
    }

    /// Commits a bounded batch of prepared authoritative mutations
    /// (`PendingBatchedCommit`, produced by `process_event_with_ignore_at`'s
    /// simple create/modify/delete case): acquires every member's per-path
    /// lock, revalidates each is still current, and commits only the
    /// still-valid subset in one `commit_local_mutations_batch` transaction
    /// — so a burst of local mutations shares one writer_gate hold instead
    /// of convoying on it (batched dirty-journal writes alone do not
    /// remove that contention).
    ///
    /// Correctness rests on three things, none of which
    /// `commit_local_mutations_batch` itself can enforce (it has no
    /// filesystem/tokio dependency):
    ///
    /// 1. **Locks are held for the whole call, never released early and
    ///    re-acquired.** Releasing a path's lock between preparing its
    ///    mutation and committing it would let a concurrent peer
    ///    materialization (or another local capture) write to that exact
    ///    path in the gap — reintroducing the stale-materialization race
    ///    class this project has repeatedly had to close elsewhere.
    ///    Acquired in lexicographic order of each path's lock key -- its
    ///    case/normalization fold, which is what the lock registry keys on
    ///    (not the batch's original order, and not the raw string) -- so
    ///    two concurrent holders of overlapping path sets never form a
    ///    lock-order cycle, and names that fold together are one lock taken
    ///    once. Directory capture takes several locks the same way; every
    ///    other holder in this daemon takes one path lock at a time.
    /// 2. **Revalidation immediately before commit, still under lock.**
    ///    Preparing a mutation (chunk/hash/decide) happens with no lock
    ///    held at all, so by the time this function acquires a path's
    ///    lock, disk or index state may have moved on. Re-checking both
    ///    (`prepare_match`, `get_file`) against what preparation
    ///    observed — the same scheme `peer_session::PeerSyncSession::
    ///    hydrate_inner` already relies on for the identical question —
    ///    catches a stale mutation before it authors bytes that are no
    ///    longer current; a mismatch excludes it from this batch entirely
    ///    rather than committing it anyway.
    /// 3. **One signed `Change` per mutation, in original order.** Passed
    ///    to `commit_local_mutations_batch` in the batch's original
    ///    (flush) order, not the lock-acquisition order, so the resulting
    ///    causal chain is identical to what committing each mutation
    ///    separately, in sequence, would have produced.
    ///
    /// Drains `pending` unconditionally. Returns `(record, rel_path,
    /// observed_at_unix_nanos)` for every mutation that actually committed
    /// — the caller pushes each into its own `records`/dirty-clear
    /// bookkeeping. A mutation dropped for staleness, or every mutation in
    /// this batch if the shared commit itself fails, is simply absent from
    /// the return value: its dirty-journal row is left untouched (this
    /// function never clears one), so the normal re-drive path picks it up
    /// again with fresh state — this mirrors the batched dirty-journal
    /// step's own "a failure here is only logged, never fatal to the rest
    /// of the flush" philosophy.
    pub(super) async fn flush_pending_batch(
        &self,
        group_id: &str,
        root: &Path,
        pending: &mut Vec<PendingBatchedCommit>,
    ) -> Result<Vec<(FileRecord, String, i64)>, LocalCaptureError> {
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let batch = std::mem::take(pending);
        let Some(emitter) = self.change_emitter.clone() else {
            // `process_event_with_ignore_at` only ever defers into a
            // batch when `self.change_emitter` is `Some` -- see its own
            // "simple case" gating. An empty emitter here would mean a
            // mutation was queued despite that gate, which is a logic
            // error in this module, not a runtime condition to recover
            // from.
            unreachable!("a batched mutation was prepared without a change_emitter configured");
        };

        // Acquire every member's path lock in lexicographic order of the
        // fold the lock registry keys on -- deadlock safety against any
        // other concurrent holder of a different subset of these same
        // locks (see this function's own doc comment, point 1). Ordering and
        // de-duplicating the raw strings is not enough: `Report.txt` and
        // `report.txt` are one lock, so a raw-string pass would take it
        // twice and wait on itself, and two holders could disagree on the
        // order of folded-equal names.
        let mut guards: Vec<tokio::sync::OwnedMutexGuard<()>> = Vec::with_capacity(batch.len());
        for rel_path in path_lock_order(batch.iter().map(|p| p.rel_path.as_str())) {
            let lock = self.state.path_lock(group_id, rel_path);
            guards.push(lock.lock_owned().await);
        }

        // Revalidate each, in the batch's original order — see this
        // function's own doc comment, point 2.
        let mut keep = Vec::with_capacity(batch.len());
        // Actual-state evidence for a KEPT item, or `None` for "commit the
        // Change/index exactly as before, publish no proof" -- computed
        // here, under this same revalidation pass, so a fresh
        // `FileIdentity` observation for an Upsert entry is taken at the
        // exact moment `current_disk` was already confirmed to still
        // match `disk_fingerprint_at_prepare`, not a separately-timed
        // stat that could itself race a change this loop's own disk read
        // already closed the window on. Meaningless (never read) for an
        // excluded item.
        let mut evidence_if_kept = Vec::with_capacity(batch.len());
        for pending_commit in &batch {
            // Whether the row still shows what the mutation was prepared
            // against is native's verdict (its witness, read before the
            // row), so a peer commit that happens to coincide with the old
            // version's size/mtime/blocks is still caught.
            let native_fresh = match pending_commit.mutation.native_witness() {
                Some(witness) => self.state.native_capture_is_fresh(group_id, witness)?,
                None => true,
            };
            let first_match = prepare_match(
                &pending_commit.event_path,
                &pending_commit.disk_fingerprint_at_prepare,
            );
            let mut still_current = first_match != PrepareMatch::Changed
                // Where the fingerprint is stat-only (the volume cannot answer the change
                // time/USN query) it cannot show a same-size rewrite with a restored mtime, so
                // the bytes are checked here, under the path lock. The second sample below
                // closes the read.
                && (first_match != PrepareMatch::Degraded
                    || degraded_upsert_bytes_still_match(pending_commit))
                && native_fresh
                && !match &pending_commit.mutation {
                    yadorilink_replica_domain::session_state::PreparedLocalMutation::Upsert {
                        record,
                        version,
                        ..
                    } => self.authors_pre_image_of_open_write(group_id, record, version)?,
                    yadorilink_replica_domain::session_state::PreparedLocalMutation::Delete {
                        ..
                    } => false,
                };
            use yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence as Evidence;
            let mut evidence = None;
            if still_current {
                match &pending_commit.mutation {
                    yadorilink_replica_domain::session_state::PreparedLocalMutation::Upsert {
                        ..
                    } => {
                        // The identity is observed INSIDE a bracket that the
                        // fingerprint re-check then closes: a write landing
                        // between the check above and this observation would
                        // otherwise be vouched for as the bytes the stale
                        // record describes.
                        let observed = FileIdentity::observe_path(&pending_commit.event_path).ok();
                        #[cfg(any(test, feature = "test-support"))]
                        super::record_builder::fire_post_identity_race_hook(
                            &pending_commit.event_path,
                        );
                        let closing = prepare_match(
                            &pending_commit.event_path,
                            &pending_commit.disk_fingerprint_at_prepare,
                        );
                        match (observed, closing) {
                            (Some(filesystem_identity), PrepareMatch::Strict)
                                if first_match == PrepareMatch::Strict =>
                            {
                                evidence = Some(Evidence::Present { filesystem_identity });
                            }
                            // Bytes verified above and both samples stat-only: commit, publish
                            // no proof (the identity cannot show a later same-size rewrite). The
                            // identity query is not needed for that, so its failure (a volume
                            // whose whole query errors) must not exclude the commit.
                            (_, PrepareMatch::Degraded)
                                if first_match == PrepareMatch::Degraded => {}
                            _ => still_current = false,
                        }
                    }
                    yadorilink_replica_domain::session_state::PreparedLocalMutation::Delete {
                        ..
                    } => {
                        // The prepared fingerprint may be that of a case- or
                        // normalization-folded sibling (the exact leaf was
                        // what was observed absent). `Absent` is published
                        // for the exact name, so it is re-confirmed here: an
                        // exact leaf that exists, or cannot be looked at,
                        // is not an absence.
                        match try_exact_leaf_exists_as_file_or_symlink(
                            root,
                            &pending_commit.rel_path,
                        ) {
                            Ok(false)
                                if !exact_leaf_exists_as_directory(
                                    root,
                                    &pending_commit.rel_path,
                                ) =>
                            {
                                evidence = Some(Evidence::Absent);
                            }
                            // The parent itself is gone: the leaf is too.
                            Err(error) if error_means_absent(&error) => {
                                evidence = Some(Evidence::Absent);
                            }
                            _ => still_current = false,
                        }
                    }
                }
            }
            if !still_current {
                tracing::info!(
                    path = %pending_commit.rel_path,
                    group_id,
                    "excluding a batched local mutation: disk or index state changed between \
                     preparation and commit; left journaled dirty for normal re-drive"
                );
            }
            keep.push(still_current);
            evidence_if_kept.push(evidence);
        }

        let mut resolved = Vec::with_capacity(batch.len());
        let mut valid_mutations = Vec::with_capacity(batch.len());
        let mut valid_evidence = Vec::with_capacity(batch.len());
        for ((pending_commit, ok), evidence) in batch.into_iter().zip(keep).zip(evidence_if_kept) {
            if ok {
                resolved.push((
                    pending_commit.mutation.record().clone(),
                    pending_commit.rel_path,
                    pending_commit.observed_at_unix_nanos,
                ));
                valid_mutations.push(pending_commit.mutation);
                valid_evidence.push(evidence);
            }
        }

        if !valid_mutations.is_empty() {
            let commit_result = self.state.commit_local_mutations_batch(
                group_id,
                &valid_mutations,
                &valid_evidence,
                &self.device_id,
                crate::ports::LocalChangeEmission {
                    author: &emitter,
                    permit: &self.begin_operation()?.permit(),
                },
            );
            if let Err(e) = commit_result {
                // An edit refused because this replica's own bucket at its
                // path is full of versions it was not shown can never be
                // authored there by retrying: hand it to the reconciliation
                // that preserves it as a conflict copy, so it neither stays
                // dirty (holding the capture barrier against every peer
                // change at the path) nor is lost.
                let unauthorable = unauthorable_upsert(&e).and_then(|path| {
                    valid_mutations.iter().zip(&resolved).find_map(|(mutation, (_, rel, _))| {
                        (is_upsert_at(mutation, path) && rel == path).then(|| rel.clone())
                    })
                });
                if let Some(rel_path) = unauthorable {
                    self.hold_unauthorable_edit(group_id, &rel_path)?;
                    // The reconciliation skips a locked path: wake it only
                    // once this batch's locks are released.
                    drop(guards);
                    self.state.wake_install_reconciliation();
                }
                tracing::warn!(
                    error = %e,
                    group_id,
                    batch_len = valid_mutations.len(),
                    "failed to commit a batched group of local mutations; left journaled dirty \
                     for re-drive"
                );
                return Ok(Vec::new());
            }
        }
        Ok(resolved)
        // `guards` drops here, releasing every path lock this batch held —
        // only after the shared commit above has returned.
    }
}

/// The paths in the order their locks are taken, each lock once.
///
/// The lock registry keys a path by its case/normalization fold, so the
/// order and the identity of a lock are both those of the fold: names that
/// fold together are one lock and appear once (the first of them), and two
/// holders ordering by the same key can never wait on each other in a
/// cycle. Ordering or de-duplicating the raw strings does neither.
pub(super) fn path_lock_order<S: AsRef<str>>(paths: impl IntoIterator<Item = S>) -> Vec<S> {
    let mut by_lock_key = std::collections::BTreeMap::new();
    for path in paths {
        by_lock_key
            .entry(yadorilink_fs_platform::canonical_fold::canonical_fold(path.as_ref()))
            .or_insert(path);
    }
    by_lock_key.into_values().collect()
}

/// The path of a local `Put` refused because the author's own bucket there
/// would hold more than `MAX_SELF_HEADS` heads: both of its own heads at the
/// path are versions this write was not shown, so no retry authors it.
pub(super) fn unauthorable_upsert(error: &SyncSqliteError) -> Option<&str> {
    match error {
        SyncSqliteError::AuthoringRefused {
            refusal:
                yadorilink_replica_domain::author::AuthoringRefusal::OwnBucketOverCap { path, .. },
        } => Some(path.as_str()),
        _ => None,
    }
}

/// Whether `mutation` saves content at exactly `path`.
fn is_upsert_at(
    mutation: &yadorilink_replica_domain::session_state::PreparedLocalMutation,
    path: &str,
) -> bool {
    matches!(
        mutation,
        yadorilink_replica_domain::session_state::PreparedLocalMutation::Upsert {
            op: yadorilink_replica_domain::local_op::Op::Put { path: put, .. },
            ..
        } if put.as_str() == path
    )
}

impl LocalChangeProcessor {
    /// Hands the edit on disk at `rel_path`, which this replica cannot
    /// author there ([`unauthorable_upsert`]), to the install
    /// reconciliation: the path is held with no prior placement, so the
    /// reconciliation preserves the edit as a conflict copy (captured as a
    /// new file) and places the path's current value, and capture authors
    /// nothing at the path meanwhile. The caller holds the path's lock and
    /// wakes the reconciliation once it has released it.
    pub(super) fn hold_unauthorable_edit(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<(), LocalCaptureError> {
        tracing::warn!(
            group_id,
            path = rel_path,
            "a local edit cannot be authored: this device's own heads at the path are two \
             versions it was not shown; preserving the edit as a conflict copy"
        );
        self.state.hold_unauthorable_local_edit(group_id, rel_path)?;
        Ok(())
    }
}
