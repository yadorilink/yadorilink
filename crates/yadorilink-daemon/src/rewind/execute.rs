//! The second half of a rewind execution: the prepared plan authored as
//! ordinary signed changes, one chunk per transaction.
//!
//! Each chunk is committed by
//! `yadorilink_sync_sqlite::RewindRunRepository::commit_chunk`, which checks
//! the chunk's paths against the plan inside its own transaction and
//! advances the journal row in that same transaction. This module only
//! sequences the chunks and supplies what that transaction cannot read
//! itself: a fresh writer verdict, the root operation, the author, and a
//! local check that the historical bytes are still held.
//!
//! No disk is written here. The ordinary projection materializes what each
//! chunk authored, as for any other local change; the run is a logical
//! change of the namespace.
//!
//! Any stop ends the run: a run that committed a chunk becomes
//! `needs_replan` (those changes stay as ordinary changes), one that
//! committed none ends `failed` with the kind that says why. Nothing is
//! skipped, retried or resumed.

use std::sync::Arc;

use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::{BlockHash, FolderGroupId};
use yadorilink_replica_domain::rewind::{
    RewindFailureKind, RewindPathAction, RewindPathEntry, RewindRunState,
};
use yadorilink_sync_sqlite::rewind_commit::{RewindChunkOutcome, RewindChunkStop};
use yadorilink_sync_sqlite::SyncSqliteError;

use super::prepare::{begin_rewind, PreparedRewind, RewindPrepareError};
use super::RewindExecuteRequest;
use crate::daemon_state::DaemonState;

/// Where a run can be stopped as a crash would stop it (no destructor runs,
/// so the journal row stays as it is), for tests of what a restart finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewindPoint {
    /// Before chunk `n` (0-based) is committed; for `n > 0`, between chunks.
    BeforeChunk(u64),
    /// Right after chunk `n` committed (its signed changes and the journal
    /// advance, one transaction), before the commit is announced: nothing
    /// has woken publication or the projection for it yet. After the last
    /// chunk the row is already `done`.
    AfterChunk(u64),
}

/// Called at each [`RewindPoint`]; `false` stops the run there as a crash.
pub type RewindHook = Arc<dyn Fn(RewindPoint) -> bool + Send + Sync>;

/// Begins an approved rewind and runs the rest of it in the background:
/// the content is gathered, then the chunks are committed. Returns the run
/// id once the run is recorded; its progress and outcome are read from the
/// journal ([`super::RewindQueries::status`]).
pub async fn start_rewind(
    state: Arc<DaemonState>,
    request: RewindExecuteRequest,
) -> Result<String, RewindPrepareError> {
    let begun = begin_rewind(state.clone(), request).await?;
    let run_id = begun.run_id().to_string();
    tokio::spawn(async move {
        match begun.prefetch().await {
            Ok(prepared) => {
                execute_rewind(state, prepared, None).await;
            }
            Err(error) => tracing::info!(%error, "folder rewind could not be prepared"),
        }
    });
    Ok(run_id)
}

/// Commits a prepared rewind chunk by chunk, and returns the state the run
/// ended in (`None` only when `hook` stopped it as a crash).
pub async fn execute_rewind(
    state: Arc<DaemonState>,
    prepared: PreparedRewind,
    hook: Option<RewindHook>,
) -> Option<RewindRunState> {
    // The retention pause is held until this function returns: through the
    // last chunk, whatever the outcome. Bound before the run guard so it
    // drops after it: the row is settled before the pause is released.
    let PreparedRewind { run, plan, chunks, retention } = prepared;
    let _retention = retention;
    let mut run = run;
    let runs = state.replica_coordinator.rewind_run_repository();
    let group_id = plan.group_id.clone();
    if chunks.is_empty() {
        run.armed = false;
        return match runs.finish_empty_run(&run.run_id) {
            Ok(()) => Some(RewindRunState::Done),
            Err(error) => {
                tracing::warn!(%error, run_id = %run.run_id, "could not record a finished rewind");
                None
            }
        };
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let index = index as u64;
        if let Some(hook) = &hook {
            if !hook(RewindPoint::BeforeChunk(index)) {
                std::mem::forget(run);
                return None;
            }
        }
        let kind = match commit_one_chunk(&state, &run.run_id, &group_id, index, chunk).await {
            Ok(ChunkResult::Committed { done }) => {
                if let Some(hook) = &hook {
                    if !hook(RewindPoint::AfterChunk(index)) {
                        std::mem::forget(run);
                        return None;
                    }
                }
                state.on_local_native_commit(&group_id).await;
                if done {
                    run.armed = false;
                    tracing::info!(run_id = %run.run_id, chunks = chunks.len(), "folder rewind done");
                    return Some(RewindRunState::Done);
                }
                continue;
            }
            Ok(ChunkResult::Stopped(kind)) => kind,
            Err(error) => {
                tracing::warn!(%error, run_id = %run.run_id, chunk = index, "folder rewind chunk failed");
                RewindFailureKind::Interrupted
            }
        };
        run.armed = false;
        tracing::info!(run_id = %run.run_id, chunk = index, ?kind, "folder rewind stopped");
        return match runs.stop_run(&run.run_id, kind) {
            Ok(ended) => Some(ended),
            Err(error) => {
                tracing::warn!(%error, run_id = %run.run_id, "could not record a stopped rewind");
                None
            }
        };
    }
    // Every chunk committed but the last did not report the run done: the
    // journal and the chunk list disagree. Settle it by the interruption
    // rule rather than claim it finished.
    tracing::warn!(run_id = %run.run_id, "folder rewind ended without its last chunk ending it");
    None
}

enum ChunkResult {
    Committed { done: bool },
    Stopped(RewindFailureKind),
}

/// Commits one chunk, holding for its duration the write-activity guard
/// (which also keeps block deletion out, so the bytes checked below stay
/// until the chunk's rows reference them) and a root operation (verified
/// inside the chunk's transaction).
async fn commit_one_chunk(
    state: &Arc<DaemonState>,
    run_id: &str,
    group_id: &str,
    index: u64,
    chunk: &[RewindPathEntry],
) -> Result<ChunkResult, SyncSqliteError> {
    let _write_activity = state.begin_write_activity();

    // The bytes were verified before the first chunk; this is the local-only
    // check that they are still here. Missing content is never fetched
    // under the root operation: the run stops instead.
    let blocks = chunk_blocks(state, group_id, chunk)?;
    if !state.blocks_verified_locally(blocks).await {
        tracing::warn!(run_id, chunk = index, "content a rewind chunk restores is no longer held");
        return Ok(ChunkResult::Stopped(RewindFailureKind::Transient));
    }

    let refused = Ok(ChunkResult::Stopped(RewindFailureKind::CommitRefused));
    let Ok(root_lease) = state.root_lease_for(group_id) else { return refused };
    let root_op = match root_lease.begin_operation() {
        Ok(op) => op,
        // Paused for a safe stop: the run can be continued once the pause lifts.
        Err(yadorilink_root_authority::RootAuthorityError::Quiescing(_)) => {
            return Ok(ChunkResult::Stopped(RewindFailureKind::Transient));
        }
        Err(_) => return refused,
    };
    let permit = root_op.permit();
    let Some(emitter) = state.local_author() else { return refused };
    let writer = crate::native_rebootstrap::is_writer(state, &FolderGroupId(group_id.to_string()));
    let outcome = crate::daemon_state::run_blocking_sweep_offloaded(|| {
        state
            .replica_coordinator
            .commit_rewind_chunk(run_id, group_id, index, chunk, &emitter, &permit, writer)
    });
    drop(root_op);
    match outcome {
        Ok(RewindChunkOutcome::Committed { done }) => Ok(ChunkResult::Committed { done }),
        Ok(RewindChunkOutcome::Stopped(stop)) => {
            tracing::info!(run_id, chunk = index, ?stop, "folder rewind chunk stopped");
            Ok(ChunkResult::Stopped(match stop {
                RewindChunkStop::FolderChanged { .. } => RewindFailureKind::FolderChanged,
                RewindChunkStop::Refused { .. } => RewindFailureKind::CommitRefused,
            }))
        }
        // Authoring refusals reached outside the chunk's transaction (the
        // author identity itself) stop the run like any other refusal.
        Err(
            SyncSqliteError::AuthoringRefused { .. }
            | SyncSqliteError::GroupFrozen { .. }
            | SyncSqliteError::PolicyUnavailable,
        ) => refused,
        Err(error) => Err(error),
    }
}

/// The blocks of the historical versions `chunk` restores.
fn chunk_blocks(
    state: &DaemonState,
    group_id: &str,
    chunk: &[RewindPathEntry],
) -> Result<Vec<VersionBlock>, SyncSqliteError> {
    let index = state.replica_coordinator.file_index_repository();
    let mut blocks = Vec::new();
    for entry in chunk {
        let seq = match entry.action {
            RewindPathAction::Create { version_seq, .. } => version_seq,
            RewindPathAction::Replace { to_version_seq, .. } => to_version_seq,
            _ => continue,
        };
        // A row that is gone is the chunk transaction's to report (the
        // folder changed); only the bytes are checked here.
        if let Some(version) = index.get_version(group_id, &entry.path, seq)? {
            if version.record_kind == yadorilink_replica_domain::file::RecordKind::File {
                blocks.extend(
                    version.blocks.into_iter().map(|block| VersionBlock {
                        hash: BlockHash(block.hash),
                        size: block.size,
                    }),
                );
            }
        }
    }
    Ok(blocks)
}

/// The control socket's handle onto [`start_rewind`].
pub struct RewindService {
    state: Arc<DaemonState>,
}

impl RewindService {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub(crate) async fn execute(
        &self,
        request: RewindExecuteRequest,
    ) -> Result<String, RewindPrepareError> {
        start_rewind(self.state.clone(), request).await
    }
}
