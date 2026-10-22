//! The durable `local_dirty_paths` journal: re-driving journaled paths
//! and the on-disk encoding of their event kind.

use std::path::{Path, PathBuf};

use crate::error::LocalCaptureError;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::FsChangeKind;
use yadorilink_replica_domain::file::FileRecord;

use super::{FlushOutcome, LocalChangeProcessor};

/// Serialized `FsChangeKind` as stored (`"removed"` is an OBSERVED removal: the
/// journal only ever records what was observed, so a replay after a restart
/// is always an observed removal, never a semantic delete -- those are handled
/// synchronously and are not journaled) in the `local_dirty_paths` journal, so a
/// startup/backstop re-drive can reconstruct the exact `FsChangeEvent`.
pub(super) fn dirty_kind_str(kind: FsChangeKind) -> &'static str {
    match kind {
        FsChangeKind::CreatedOrModified => "created_or_modified",
        FsChangeKind::ObservedRemoval => "removed",
    }
}

/// Inverse of [`dirty_kind_str`]. Any unrecognized value maps to
/// `CreatedOrModified` — the safe default, since re-reading a path that turns
/// out to be absent still self-corrects to a deletion inside `process_event`.
pub(super) fn dirty_kind_from_str(s: &str) -> FsChangeKind {
    match s {
        "removed" => FsChangeKind::ObservedRemoval,
        _ => FsChangeKind::CreatedOrModified,
    }
}

/// Why a path whose content changed while it was being read stays dirty.
pub(super) const CHANGED_DURING_READ: &str =
    "content changed while it was being read; left for a later capture";

fn journal_uncaptured(
    state: &dyn crate::ports::LocalMutationStore,
    root_lease: &yadorilink_root_authority::root_commit::RootLease,
    group_id: &str,
    rel_path: &str,
    observed_at_unix_nanos: i64,
) -> Result<(), LocalCaptureError> {
    state.record_dirty_path(
        group_id,
        rel_path,
        dirty_kind_str(FsChangeKind::CreatedOrModified),
        observed_at_unix_nanos,
        &root_lease.begin_journal_operation()?.permit(),
    )?;
    state.mark_dirty_path_attempt(
        group_id,
        rel_path,
        CHANGED_DURING_READ,
        &root_lease.begin_journal_operation()?.permit(),
    )?;
    Ok(())
}

/// Edits handed over by an accumulator whose dirty-journal commit has not succeeded yet.
pub(super) struct RetainedHandoff {
    group_id: String,
    entries: Vec<(String, String, i64)>,
}

impl LocalChangeProcessor {
    /// The key a flush of `path` under `root` journals it dirty by, or
    /// `None` if the path cannot be journaled at all (outside `root`, or
    /// not representable as a wire path). A caller asking whether a flush
    /// left `path` uncaptured must ask about exactly this key.
    pub fn dirty_journal_key(root: &Path, path: &Path) -> Option<String> {
        super::path_policy::relative_key(root, path)
    }

    /// Journals edits an accumulator has handed to a requester, synchronously.
    ///
    /// Ownership invariant: an edit the accumulator has handed over is owned by exactly one of
    /// (a) a committed `local_dirty_paths` row, or (b) this processor's `retained_handoffs`. It
    /// is never owned by the in-flight reply alone, because a requester can be cancelled before
    /// it reads the reply. Ownership moves to (a) only when the commit succeeds. On failure the
    /// edits are moved to (b) and the error is returned, so the caller sees the failure rather
    /// than a log line; `retry_retained_handoffs` (run at the start of every
    /// `redrive_dirty_journal`, i.e. at startup and on the periodic backstop) commits them and
    /// keeps them until it does. Idempotent with the identical journaling `process_flush`
    /// repeats for the same batch. Admitted while the link is paused for a safe stop (see
    /// `begin_journal_operation`).
    ///
    /// Process restart: (b) is memory only and is deliberately not persisted. A journal that
    /// cannot take the row is the same store a persisted copy would need, so a second copy
    /// would depend on the failing thing. The guarantee is instead that nothing the retained
    /// batch described is only in memory: the edit is on disk, and the startup full scan
    /// (which runs before the startup re-drive) compares disk with the index by size, mtime
    /// and, when those match, by content, so it re-captures a lost new or modified file once
    /// and never tombstones one that is still present. Pinned by
    /// `a_retained_batch_lost_at_restart_is_refound_by_the_startup_scan` (file-backed index,
    /// every handle dropped and the file reopened).
    pub fn journal_handed_over_edits(
        &self,
        group_id: &str,
        root: &Path,
        paths: &[(PathBuf, FsChangeKind, i64)],
    ) -> Result<(), LocalCaptureError> {
        let entries: Vec<(String, String, i64)> = paths
            .iter()
            .filter_map(|(path, kind, observed_at)| {
                super::path_policy::relative_key(root, path)
                    .map(|key| (key, dirty_kind_str(*kind).to_string(), *observed_at))
            })
            .collect();
        if entries.is_empty() {
            return Ok(());
        }
        let handoff = RetainedHandoff { group_id: group_id.to_string(), entries };
        self.commit_handoff(&handoff).inspect_err(|_| self.retain_handoff(handoff))
    }

    /// Commits every retained handoff of `group_id`; those that still fail stay retained.
    /// Returns the first failure.
    pub fn retry_retained_handoffs(&self, group_id: &str) -> Result<(), LocalCaptureError> {
        let mine: Vec<RetainedHandoff> = {
            let mut retained =
                self.retained_handoffs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let (mine, others) = std::mem::take(&mut *retained)
                .into_iter()
                .partition(|handoff| handoff.group_id == group_id);
            *retained = others;
            mine
        };
        let mut first_error = None;
        for handoff in mine {
            if let Err(error) = self.commit_handoff(&handoff) {
                self.retain_handoff(handoff);
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// How many handed-over edits wait for a successful journal commit.
    pub fn retained_handoff_count(&self) -> usize {
        self.retained_handoffs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|handoff| handoff.entries.len())
            .sum()
    }

    fn commit_handoff(&self, handoff: &RetainedHandoff) -> Result<(), LocalCaptureError> {
        let op = self.begin_journal_operation()?;
        self.state.record_dirty_paths_batch(&handoff.group_id, &handoff.entries, &op.permit())?;
        Ok(())
    }

    fn retain_handoff(&self, handoff: RetainedHandoff) {
        self.retained_handoffs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(handoff);
    }

    /// Leaves `rel_path` journaled dirty after a pass that could not capture
    /// it (`LocalChangeOutcome::RetryLater`): the row re-drives the edit on
    /// the next flush or backstop, and holds a remote change for this path
    /// back until the edit is captured.
    pub(super) fn journal_uncaptured_local_edit(
        &self,
        group_id: &str,
        rel_path: &str,
        observed_at_unix_nanos: i64,
    ) -> Result<(), LocalCaptureError> {
        journal_uncaptured(
            self.state.as_ref(),
            &self.root_lease,
            group_id,
            rel_path,
            observed_at_unix_nanos,
        )
    }

    /// Whether `blocks`, read at `rel_path`, are a pre-image of a write
    /// still open over the path: an intent targets other content, and
    /// `blocks` are content this daemon's own writes may have left there --
    /// what the path was last proven to hold, or an earlier write the open
    /// intent replaced before it was proven. The open write moved the row
    /// and has not reached disk (it failed before its rename, or the daemon
    /// stopped), so authoring these bytes would put older content over the
    /// version being written; the write's own retry -- its intent stays
    /// open, its obligation unsettled -- owns the path until it lands. A
    /// real edit landing while such a write is open carries other bytes,
    /// and is captured. (A user restoring exactly one of those contents in
    /// that window is not told apart: the retry writes the newer version
    /// over it, and the restored content stays in history.)
    pub(super) fn is_pre_image_of_open_write(
        &self,
        group_id: &str,
        rel_path: &str,
        blocks: &[yadorilink_replica_domain::file::BlockInfo],
    ) -> Result<bool, LocalCaptureError> {
        let Some(intent_target) = self.state.materialization_intent_target(group_id, rel_path)?
        else {
            return Ok(false);
        };
        let disk_target = yadorilink_local_storage::intent_target_hash(blocks);
        if intent_target == disk_target {
            return Ok(false);
        }
        let pre_image =
            self.state.pre_image_content_targets(group_id, rel_path)?.contains(&disk_target);
        if pre_image {
            tracing::info!(
                group_id,
                path = %rel_path,
                "the bytes on disk are what an unfinished write is replacing; not a local edit"
            );
        }
        Ok(pre_image)
    }

    /// [`Self::is_pre_image_of_open_write`] for a prepared upsert, checked
    /// again under the path's lock right before it commits: a regular file
    /// whose prepared bytes are the pre-image of a write open over the path
    /// must not be authored. Anything else is not this check's business.
    pub(super) fn authors_pre_image_of_open_write(
        &self,
        group_id: &str,
        record: &FileRecord,
        version: &yadorilink_replica_domain::file::FileVersion,
    ) -> Result<bool, LocalCaptureError> {
        if version.meta.record_kind != yadorilink_replica_domain::file::RecordKind::File {
            return Ok(false);
        }
        self.is_pre_image_of_open_write(group_id, &record.path, &record.blocks)
    }

    /// Journals `rel_path` dirty once nothing holds its path lock, for a
    /// pass that read the path while another writer held that lock and so
    /// could neither author what it read nor journal it right away.
    ///
    /// Not right away, because the lock holder can be a write of a newer
    /// version that has already moved the row ahead of the disk: a path
    /// journaled dirty in that window reads to that write as a local edit
    /// landing over its target, and it abandons the newer version. Taken
    /// after the holder releases, the journal entry only asks for one more
    /// capture under the lock, which compares the disk with whatever row
    /// the holder left and authors exactly what differs.
    ///
    /// The waiter holds no other lock while it waits and takes this one by
    /// itself, so it cannot take part in a lock-order cycle; the lock is
    /// fair, so a path that is busy again and again is still journaled
    /// once its turn comes.
    pub(super) fn journal_uncaptured_once_unlocked(&self, group_id: &str, rel_path: &str) {
        let key = (group_id.to_owned(), rel_path.to_owned());
        let Some(waiter) = DeferredJournalWaiter::register(&self.deferred_journal_waiters, key)
        else {
            // A waiter for this path is already queued; it journals the
            // path when the lock frees, which is all this pass needs.
            return;
        };
        let lock = self.state.path_lock(group_id, rel_path);
        let state = self.state.clone();
        let root_lease = self.root_lease.clone();
        let group_id = group_id.to_owned();
        let rel_path = rel_path.to_owned();
        // Runs under the path lock and unregisters before returning, so
        // before the lock is released: a pass that finds the lock busy
        // after that registers a waiter of its own. A waiter dropped without
        // running (its task dropped at shutdown) unregisters too.
        let journal = move || {
            if let Err(error) = journal_uncaptured(
                state.as_ref(),
                &root_lease,
                &group_id,
                &rel_path,
                super::now_unix_nanos(),
            ) {
                tracing::warn!(
                    group_id,
                    path = %rel_path,
                    %error,
                    "could not journal a path a scan left uncaptured; the next scan reads it again"
                );
            }
            drop(waiter);
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    let _guard = lock.lock_owned().await;
                    journal();
                });
            }
            Err(_) => {
                std::thread::spawn(move || {
                    let _guard = lock.blocking_lock_owned();
                    journal();
                });
            }
        }
    }

    /// Re-drives every path still journaled dirty for `group_id` through the
    /// normal flush executor — the daemon's startup rescan and the durability
    /// backstop against a crash, a restart, or a disk fault that outlived the
    /// in-flight retry. Each `local_dirty_paths` row is turned back into the
    /// exact `FsChangeEvent` the debounce executor would have processed and run
    /// through `process_flush`, which re-reads the path, re-derives its record,
    /// commits the index + native state, and (on success) clears the row. A path
    /// whose on-disk content already matches the index resolves to `None` and
    /// is simply cleared — idempotent, never a spurious re-edit; one that still
    /// can't be processed stays journaled for the next attempt. Returns the
    /// produced records so the caller can announce them exactly as a live
    /// flush would.
    ///
    /// Nothing is re-driven while the group's policy is unavailable: every
    /// emitting write would refuse with `PolicyUnavailable`, so each path
    /// would only be re-read and journaled again, and the periodic backstop
    /// would repeat that for the whole journal on every tick (a directory
    /// tree captured before its policy arrives journals one row per
    /// directory). The rows stay in place and the first re-drive after the
    /// policy arrives captures them.
    pub async fn redrive_dirty_journal(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<FlushOutcome, LocalCaptureError> {
        // Handed-over edits whose journal commit failed come first: until they commit, the
        // journal does not yet hold everything this group owes a capture.
        self.retry_retained_handoffs(group_id)?;
        let dirty = self.state.list_dirty_paths(group_id)?;
        if dirty.is_empty() {
            return Ok(FlushOutcome::default());
        }
        if !self.state.local_emission_available(group_id) {
            tracing::debug!(
                group_id,
                count = dirty.len(),
                "group policy unavailable; leaving journaled local dirty paths for a later re-drive"
            );
            return Ok(FlushOutcome::default());
        }
        tracing::info!(
            group_id,
            count = dirty.len(),
            "re-driving journaled local dirty paths (startup/backstop rescan)"
        );
        // Reconstruct absolute event paths the same way the watcher produced
        // them — `process_event_with_ignore_at` re-relativizes against a
        // canonicalized `root`, so joining onto the canonical root here round-
        // trips to the stored relative key.
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let paths: Vec<(PathBuf, FsChangeKind, i64)> = dirty
            .into_iter()
            .map(|d| {
                (
                    canonical_root.join(&d.path),
                    dirty_kind_from_str(&d.change_kind),
                    d.observed_at_unix_nanos,
                )
            })
            .collect();
        self.process_flush(group_id, root, DebounceFlush::Paths(paths)).await
    }
}

type WaiterSet = std::sync::Arc<std::sync::Mutex<std::collections::HashSet<(String, String)>>>;

/// One queued deferred journal write, registered in its processor's waiter
/// set for as long as it exists.
struct DeferredJournalWaiter {
    waiters: WaiterSet,
    key: (String, String),
}

impl DeferredJournalWaiter {
    /// `None` when a waiter for `key` is already registered.
    fn register(waiters: &WaiterSet, key: (String, String)) -> Option<Self> {
        let inserted =
            waiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(key.clone());
        inserted.then(|| Self { waiters: waiters.clone(), key })
    }
}

impl Drop for DeferredJournalWaiter {
    fn drop(&mut self) {
        self.waiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&self.key);
    }
}

#[cfg(test)]
impl LocalChangeProcessor {
    /// How many deferred journal waiters exist right now: each holds a
    /// handle on the waiter set, so this counts the waiters themselves,
    /// not the paths they registered.
    pub(super) fn deferred_journal_waiter_count(&self) -> usize {
        std::sync::Arc::strong_count(&self.deferred_journal_waiters) - 1
    }
}
