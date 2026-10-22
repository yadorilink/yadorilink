//! The first half of a rewind execution: everything that happens before
//! the first change, and that must all succeed before it.
//!
//! The invariant is: the approved plan is re-verified, all historical
//! content it needs is enumerated, fetched and verified locally, and only
//! when every byte is held does anything change. This module ends at that
//! point, with a [`PreparedRewind`] that holds the verified plan, its
//! journal row (`prefetched`) and the retention pause that keeps the plan's
//! historical rows in place. If preparation cannot complete, the rewind
//! never starts and nothing was changed: the run is recorded as failed with
//! one of two kinds, "content unavailable" or "transient".

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::rewind::{
    RewindFailureKind, RewindPathAction, RewindPathEntry, RewindPlan,
};
use yadorilink_sync_sqlite::rewind_commit::rewind_chunks;
use yadorilink_sync_sqlite::RewindRunStart;

use super::{verify_rewind_plan, RewindExecuteError, RewindExecuteRequest};
use crate::daemon_state::DaemonState;
use crate::hydration::rewind_prefetch;
use crate::replica_coordinator::{ReplicaCoordinator, RetentionPause};

/// Why a rewind could not be prepared. Nothing was changed in any case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewindPrepareError {
    /// Refused before anything was recorded: the plan could not be
    /// recomputed, is no longer the approved one, or has paths this device
    /// cannot answer for (see [`RewindExecuteError`]).
    Plan(RewindExecuteError),
    /// The group already has a rewind in progress. Nothing recorded.
    RunActive,
    /// This device may not change the group. Nothing recorded.
    NotAuthorized,
    /// The group is being re-established and accepts no changes now.
    /// Nothing recorded.
    GroupFrozen,
    /// Fetching the missing content would leave the block store's volume
    /// below its free-space headroom. Nothing recorded.
    InsufficientSpace { missing_bytes: u64 },
    /// A path the plan acts on has a change admitted here that the folder
    /// does not show yet: the plan id is unchanged, but the rewind would
    /// stop at that path. Nothing recorded.
    ///
    /// Only paths the plan acts on are checked. A peer's new path admitted
    /// but not yet in the folder is not in the plan at all; the rewind
    /// leaves it alone and it follows ordinary concurrent-edit semantics.
    FolderSettling { path: String },
    /// Recorded as failed, [`RewindFailureKind::ContentUnavailable`]:
    /// `files` of the plan's files hold content no device that could hold
    /// it has. "N files unavailable; rewind cannot start".
    ContentUnavailable { run_id: String, files: u64 },
    /// Recorded as failed, [`RewindFailureKind::Transient`]: the content
    /// could not all be gathered this time, `offline` naming the member
    /// devices that were not connected.
    Transient { run_id: String, offline: Vec<String> },
    /// Recorded as failed, [`RewindFailureKind::Transient`]: a local
    /// failure (storage, index) stopped preparation.
    Local { run_id: String, message: String },
}

impl std::fmt::Display for RewindPrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plan(error) => error.fmt(f),
            Self::RunActive => write!(f, "a rewind of this folder is already in progress"),
            Self::NotAuthorized => write!(f, "this device may not change this folder"),
            Self::GroupFrozen => write!(f, "this folder accepts no changes right now"),
            Self::InsufficientSpace { missing_bytes } => write!(
                f,
                "not enough free space to gather the {missing_bytes} bytes this rewind needs"
            ),
            Self::FolderSettling { .. } => {
                f.write_str(&RewindFailureKind::FolderChanged.message(0, &[]))
            }
            Self::ContentUnavailable { files, .. } => {
                f.write_str(&RewindFailureKind::ContentUnavailable.message(*files, &[]))
            }
            Self::Transient { offline, .. } => {
                f.write_str(&RewindFailureKind::Transient.message(0, offline))
            }
            Self::Local { message, .. } => write!(f, "rewind could not be prepared: {message}"),
        }
    }
}

impl std::error::Error for RewindPrepareError {}

/// A rewind whose every required byte is held and verified locally, and
/// which has changed nothing yet. Its journal row is `prefetched`.
///
/// Dropping it without finishing the run settles the row by the
/// interruption rule (nothing committed: failed, interrupted) and releases
/// the retention pause.
pub struct PreparedRewind {
    // Declared first so it drops first: the row is settled before the
    // pause (the in-memory "a run is active" marker) is released.
    pub(super) run: RunGuard,
    pub(super) plan: RewindPlan,
    /// The plan's actionable entries in commit order, one `Vec` per chunk
    /// (`rewind_chunks`); the journal row's `chunks_total` is its length.
    pub(super) chunks: Vec<Vec<RewindPathEntry>>,
    pub(super) retention: RetentionPause,
}

impl PreparedRewind {
    pub fn run_id(&self) -> &str {
        &self.run.run_id
    }

    /// The verified plan the run acts on: equal by id to the approved one,
    /// recomputed from the state it will change.
    pub fn plan(&self) -> &RewindPlan {
        &self.plan
    }
}

/// A rewind whose plan is verified and whose run is recorded (`planned`),
/// and whose content has not been gathered yet. [`Self::prefetch`] gathers
/// it. Dropping it settles the run as interrupted.
pub struct BegunRewind {
    state: Arc<DaemonState>,
    run: RunGuard,
    plan: RewindPlan,
    required: RequiredContent,
    retention: RetentionPause,
}

/// Settles its run on drop unless the run was ended explicitly: the same
/// rule startup applies, keyed by this run's id.
pub(super) struct RunGuard {
    pub(super) coordinator: Arc<ReplicaCoordinator>,
    pub(super) run_id: String,
    pub(super) armed: bool,
}

impl RunGuard {
    fn fail(mut self, kind: RewindFailureKind, unavailable_files: u64, offline: &[String]) {
        self.armed = false;
        if let Err(error) = self.coordinator.rewind_run_repository().mark_failed(
            &self.run_id,
            kind,
            unavailable_files,
            offline,
        ) {
            tracing::warn!(%error, run_id = %self.run_id, "could not record a failed rewind");
        }
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(error) = self.coordinator.rewind_run_repository().interrupt_run(&self.run_id) {
            tracing::warn!(%error, run_id = %self.run_id, "could not settle an interrupted rewind");
        }
    }
}

/// Prepares an approved rewind: [`begin_rewind`], then
/// [`BegunRewind::prefetch`].
pub async fn prepare_rewind(
    state: Arc<DaemonState>,
    request: RewindExecuteRequest,
) -> Result<PreparedRewind, RewindPrepareError> {
    begin_rewind(state, request).await?.prefetch().await
}

/// Begins an approved rewind: refuses early what cannot start, re-verifies
/// the plan, and records the run (`planned`). Quick: no content is fetched.
///
/// Order matters. The retention pause is taken before the plan is
/// re-verified, so an expiry cannot remove a row the verified plan relies
/// on afterwards (one that ran before is caught by the re-verify itself).
/// Nothing holds a path lock, a root operation or a write-activity guard,
/// because nothing here changes the folder.
pub async fn begin_rewind(
    state: Arc<DaemonState>,
    request: RewindExecuteRequest,
) -> Result<BegunRewind, RewindPrepareError> {
    let group_id = request.group_id.clone();
    let retention = state
        .replica_coordinator
        .pause_retention(&group_id)
        .ok_or(RewindPrepareError::RunActive)?;
    if !crate::native_rebootstrap::is_writer(&state, &FolderGroupId(group_id.clone())) {
        return Err(RewindPrepareError::NotAuthorized);
    }
    let frozen = state
        .replica_coordinator
        .held_path_repository()
        .group_frozen(&group_id)
        .map_err(|error| plan_error(error.to_string()))?;
    if frozen {
        return Err(RewindPrepareError::GroupFrozen);
    }
    let plan = verify_rewind_plan(state.clone(), request.clone())
        .await
        .map_err(RewindPrepareError::Plan)?;

    // The commit checks every path's live heads; one that already differs
    // (a change admitted here, not yet in the folder) would stop the run at
    // its chunk with the same plan id, so it is refused now, before any
    // content is gathered.
    let actionable: Vec<RewindPathEntry> = rewind_chunks(&plan).into_iter().flatten().collect();
    let settling = {
        let state = state.clone();
        let group_id = group_id.clone();
        crate::daemon_state::run_blocking_sweep_offloaded(move || {
            state
                .replica_coordinator
                .rewind_run_repository()
                .first_changed_path(&group_id, &actionable)
        })
        .map_err(|error| plan_error(error.to_string()))?
    };
    if let Some(path) = settling {
        return Err(RewindPrepareError::FolderSettling { path });
    }

    let required = {
        let state = state.clone();
        let plan = plan.clone();
        crate::daemon_state::run_blocking_sweep_offloaded(move || required_content(&state, &plan))?
    };
    let missing_bytes =
        rewind_prefetch::missing_bytes_estimate(&state, &group_id, &required.blocks)
            .map_err(|error| plan_error(error.to_string()))?;
    let free = state.block_store.free_space().map_err(|error| plan_error(error.to_string()))?;
    if free.is_some_and(|free| free.would_breach(missing_bytes)) {
        return Err(RewindPrepareError::InsufficientSpace { missing_bytes });
    }

    let run_id = uuid::Uuid::new_v4().to_string();
    let runs = state.replica_coordinator.rewind_run_repository();
    let begin = || {
        runs.begin_run(
            &run_id,
            &group_id,
            plan.target_unix_nanos,
            &request.plan_id,
            now_unix_nanos(),
        )
        .map_err(|error| plan_error(error.to_string()))
    };
    if let RewindRunStart::ActiveRunExists { run_id: orphan } = begin()? {
        // This process holds the group's retention pause, and every live run
        // holds it for as long as its row is unfinished, so an unfinished
        // row here belongs to no live run: one whose settling write failed.
        // Settle it by the interruption rule, then start.
        tracing::warn!(%orphan, "settling an unfinished rewind run no live run owns");
        runs.interrupt_run(&orphan).map_err(|error| plan_error(error.to_string()))?;
        if let RewindRunStart::ActiveRunExists { .. } = begin()? {
            return Err(RewindPrepareError::RunActive);
        }
    }
    let run = RunGuard { coordinator: state.replica_coordinator.clone(), run_id, armed: true };
    Ok(BegunRewind { state, run, plan, required, retention })
}

impl BegunRewind {
    pub fn run_id(&self) -> &str {
        &self.run.run_id
    }

    /// Makes all historical content the plan needs local and verified, and
    /// marks the run `prefetched`. If it cannot, the run is recorded as
    /// failed (content unavailable, or transient) and nothing was changed.
    pub async fn prefetch(self) -> Result<PreparedRewind, RewindPrepareError> {
        let BegunRewind { state, run, plan, required, retention } = self;
        let group_id = plan.group_id.clone();
        let verdict =
            match rewind_prefetch::prefetch_rewind_content(&state, &group_id, &required.blocks)
                .await
            {
                Ok(verdict) => verdict,
                Err(error) => {
                    let run_id = run.run_id.clone();
                    run.fail(RewindFailureKind::Transient, 0, &[]);
                    return Err(RewindPrepareError::Local { run_id, message: error.to_string() });
                }
            };
        if !verdict.unobtainable.is_empty() {
            let files = required.files_holding(&verdict.unobtainable);
            let run_id = run.run_id.clone();
            tracing::info!(%run_id, files, "rewind cannot start: historical content is unavailable");
            run.fail(RewindFailureKind::ContentUnavailable, files, &[]);
            return Err(RewindPrepareError::ContentUnavailable { run_id, files });
        }
        if !verdict.unresolved.is_empty() {
            let run_id = run.run_id.clone();
            tracing::info!(
                %run_id,
                blocks = verdict.unresolved.len(),
                offline = ?verdict.offline,
                "rewind could not be prepared: content not gathered this time"
            );
            run.fail(RewindFailureKind::Transient, 0, &verdict.offline);
            return Err(RewindPrepareError::Transient { run_id, offline: verdict.offline });
        }
        let chunks = rewind_chunks(&plan);
        if let Err(error) = state
            .replica_coordinator
            .rewind_run_repository()
            .mark_prefetched(&run.run_id, chunks.len() as u64)
        {
            let run_id = run.run_id.clone();
            run.fail(RewindFailureKind::Transient, 0, &[]);
            return Err(RewindPrepareError::Local { run_id, message: error.to_string() });
        }
        Ok(PreparedRewind { run, plan, chunks, retention })
    }
}

fn plan_error(message: String) -> RewindPrepareError {
    RewindPrepareError::Plan(RewindExecuteError::Plan(super::RewindError::Failed(message)))
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Every block the plan's restores need, once each, and which files need
/// which.
struct RequiredContent {
    blocks: Vec<BlockInfo>,
    /// Per `Create`/`Replace` entry, the hashes of its version's blocks.
    files: Vec<HashSet<Vec<u8>>>,
}

impl RequiredContent {
    fn files_holding(&self, hashes: &HashSet<Vec<u8>>) -> u64 {
        self.files.iter().filter(|file| !file.is_disjoint(hashes)).count() as u64
    }
}

/// Reads, for each entry that restores a version, that exact version's
/// row. Only `Create` and `Replace` need bytes. The row must still be the
/// one the plan names (same hash): the plan was verified moments ago under
/// the retention pause, so a mismatch means the folder changed since, and
/// is refused like any other changed plan.
fn required_content(
    state: &DaemonState,
    plan: &RewindPlan,
) -> Result<RequiredContent, RewindPrepareError> {
    let index = state.replica_coordinator.file_index_repository();
    let mut blocks: HashMap<Vec<u8>, BlockInfo> = HashMap::new();
    let mut files = Vec::new();
    for entry in &plan.entries {
        let (version_seq, version_hash) = match &entry.action {
            RewindPathAction::Create { version_seq, version_hash } => (*version_seq, version_hash),
            RewindPathAction::Replace { to_version_seq, to_version_hash } => {
                (*to_version_seq, to_version_hash)
            }
            RewindPathAction::Delete
            | RewindPathAction::Unchanged
            | RewindPathAction::Unavailable { .. } => continue,
        };
        let version = index
            .get_version(&plan.group_id, &entry.path, version_seq)
            .map_err(|error| plan_error(error.to_string()))?
            .filter(|version| version.version_hash == *version_hash)
            .ok_or_else(|| {
                plan_error(format!(
                    "{} no longer holds the version the rewind plan restores; preview again",
                    entry.path
                ))
            })?;
        let mut file = HashSet::new();
        for block in version.blocks {
            file.insert(block.hash.clone());
            blocks.entry(block.hash.clone()).or_insert(block);
        }
        files.push(file);
    }
    let mut blocks: Vec<BlockInfo> = blocks.into_values().collect();
    blocks.sort_by(|a, b| a.hash.cmp(&b.hash));
    Ok(RequiredContent { blocks, files })
}

#[cfg(test)]
mod tests;
