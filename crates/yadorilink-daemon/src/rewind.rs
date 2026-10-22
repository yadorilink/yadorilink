//! Folder Rewind's read-only preview entry point.
//!
//! This whole layer IS the dry run. It computes a [`RewindPlan`] and hands
//! it back; it emits no signed change, writes nothing to any filesystem,
//! creates no projection or materialization obligation, and changes nothing
//! about native admission. Structurally: it calls one read-only query and maps
//! its error. There is deliberately no `dry_run` flag to distinguish,
//! because there is no other mode.
//!
//! Shaped after `crate::gc`'s own `run_sweep` -> offloaded synchronous core
//! split, for the same reason that module gives: the underlying SQLite work
//! is a scan whose size grows with the group's path count, so it runs
//! through `block_in_place` when a multi-threaded runtime is current rather
//! than stalling the runtime's other work (the control socket, peer
//! sessions, ...) for its duration.

use std::sync::Arc;

use yadorilink_replica_domain::rewind::{
    RewindActionCounts, RewindPathAction, RewindPathEntry, RewindPlan, RewindPlanId,
    RewindRenameCandidate, RewindUnavailable,
};

use crate::daemon_state::DaemonState;

/// Byte budget for the per-path listing of one preview response.
///
/// A rewind plan is inherently unbounded -- one entry per path the device
/// has ever indexed for the group -- while a control-socket frame is capped
/// at `yadorilink_ipc_proto::framing::MAX_FRAME_LEN`. Dropping `unchanged`
/// entries (the usual majority) is the first line of defense, but it is not
/// a bound: a target older than the whole folder classifies every path as
/// `delete`, and `unavailable` entries carry a reason string on top of the
/// path. So the listing is also capped outright, at a fraction of the frame
/// limit that leaves generous room for the rest of the message and for the
/// per-entry estimate below being an estimate.
const ENTRY_LISTING_BUDGET_BYTES: usize = 512 * 1024;

/// Separate, much smaller budget for the advisory rename list, so a plan
/// with a great many content matches cannot crowd out the authoritative
/// per-path entries -- or push the whole message over the frame limit
/// between them.
const RENAME_LISTING_BUDGET_BYTES: usize = 64 * 1024;

/// Upper bound on one entry's protobuf-encoded size beyond its own strings:
/// five field tags, their length/varint payloads, and the entry's own
/// tag+length prefix. Deliberately generous -- the budget's job is to
/// guarantee the frame fits, so this must never underestimate.
const ENTRY_OVERHEAD_BYTES: usize = 64;

/// What a preview delivers over the wire: the whole plan's tallies, plus
/// as much of the per-path listing as fits.
///
/// The split matters. `counts` and the two totals are computed over EVERY
/// path, before any filtering or trimming, so the summary a person reads is
/// never made wrong by what did not fit. `entries` and `rename_candidates`
/// are best-effort detail, and `listing_truncated` says so out loud rather
/// than letting a partial list read as complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindPreview {
    pub group_id: String,
    pub target_unix_nanos: i64,
    /// The whole plan's identity ([`RewindPlan::plan_id`]), taken before
    /// trimming: every listing of one plan carries the same id.
    pub plan_id: RewindPlanId,
    pub counts: RewindActionCounts,
    pub total_entry_count: u64,
    pub total_rename_candidate_count: u64,
    pub entries: Vec<RewindPathEntry>,
    pub rename_candidates: Vec<RewindRenameCandidate>,
    pub listing_truncated: bool,
    /// The whole plan's unavailable paths by cause.
    pub unavailable: RewindUnavailable,
}

/// Trims a full [`RewindPlan`] to something one frame can carry.
///
/// `include_unchanged` controls only the filter, never the counts: an
/// omitted `unchanged` entry is still tallied. Both listings are then cut
/// at their byte budgets, oldest-first in the plan's own deterministic
/// order, so the same plan always trims to the same prefix.
pub(crate) fn trim_for_wire(plan: RewindPlan, include_unchanged: bool) -> RewindPreview {
    let plan_id = plan.plan_id();
    let counts = plan.action_counts();
    let unavailable = plan.unavailable();
    let total_entry_count = plan.entries.len() as u64;
    let total_rename_candidate_count = plan.rename_candidates.len() as u64;
    let mut listing_truncated = false;

    let mut rename_candidates = Vec::new();
    let mut spent = 0usize;
    for candidate in plan.rename_candidates {
        let cost = candidate.from_path.len() + candidate.to_path.len() + ENTRY_OVERHEAD_BYTES;
        if spent + cost > RENAME_LISTING_BUDGET_BYTES {
            listing_truncated = true;
            break;
        }
        spent += cost;
        rename_candidates.push(candidate);
    }

    let mut entries = Vec::new();
    let mut spent = 0usize;
    for entry in plan.entries {
        if !include_unchanged && entry.action == RewindPathAction::Unchanged {
            continue;
        }
        let reason_len = match &entry.action {
            RewindPathAction::Unavailable { reason } => reason.message().len(),
            _ => 0,
        };
        let cost = entry.path.len() + reason_len + ENTRY_OVERHEAD_BYTES;
        if spent + cost > ENTRY_LISTING_BUDGET_BYTES {
            listing_truncated = true;
            break;
        }
        spent += cost;
        entries.push(entry);
    }

    RewindPreview {
        group_id: plan.group_id,
        target_unix_nanos: plan.target_unix_nanos,
        plan_id,
        counts,
        total_entry_count,
        total_rename_candidate_count,
        entries,
        rename_candidates,
        listing_truncated,
        unavailable,
    }
}

/// Why a rewind preview could not be produced.
///
/// Module-local rather than a `DaemonError` variant, matching
/// `crate::gc::GcTriggerError`'s own convention for a feature module's
/// command surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewindError {
    /// No live link on this device references this group, so this device
    /// has no folder to rewind and no basis for an answer. Reported rather
    /// than returning an empty plan: an empty plan for a mistyped group id
    /// reads as "nothing would change", which is exactly the wrong thing to
    /// tell someone about to rewind a folder.
    UnknownGroup(String),
    Failed(String),
}

impl std::fmt::Display for RewindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RewindError::UnknownGroup(group_id) => {
                write!(f, "no linked folder on this device belongs to group {group_id}")
            }
            RewindError::Failed(detail) => write!(f, "rewind preview failed: {detail}"),
        }
    }
}

impl std::error::Error for RewindError {}

/// Computes the read-only rewind preview for `group_id` at
/// `at_unix_nanos` (nanoseconds since the Unix epoch, on THIS device's
/// clock).
///
/// See `yadorilink_sync_sqlite::rewind_plan::compute_rewind_plan` for the
/// plan's exact semantics -- in particular what
/// `RewindPathAction::Unavailable` means, and why a path this device has
/// never indexed is absent from the plan entirely rather than reported as
/// unchanged.
///
/// The full plan is always computed; `include_unchanged` and the byte
/// budgets in [`trim_for_wire`] decide only what is carried back. The plan
/// itself is never bounded, because the tallies have to be right.
pub async fn preview_rewind(
    state: Arc<DaemonState>,
    group_id: String,
    at_unix_nanos: i64,
    include_unchanged: bool,
) -> Result<RewindPreview, RewindError> {
    // Same offload helper, and the same reasoning, as `gc::run_sweep`'s --
    // see `daemon_state::run_blocking_sweep_offloaded`'s own doc comment.
    crate::daemon_state::run_blocking_sweep_offloaded(move || {
        preview_rewind_sync(&state, &group_id, at_unix_nanos)
            .map(|plan| trim_for_wire(plan, include_unchanged))
    })
}

fn preview_rewind_sync(
    state: &DaemonState,
    group_id: &str,
    at_unix_nanos: i64,
) -> Result<RewindPlan, RewindError> {
    let links = state
        .replica_coordinator
        .link_repository()
        .list_links()
        .map_err(|error| RewindError::Failed(error.to_string()))?;
    let Some(link) = links.iter().find(|link| !link.orphaned && link.group_id == group_id) else {
        return Err(RewindError::UnknownGroup(group_id.to_string()));
    };
    let sqlite = state.replica_coordinator.sqlite();
    let failed =
        |error: yadorilink_sync_sqlite::SyncSqliteError| RewindError::Failed(error.to_string());
    // Which of the erased, never re-indexed paths are still excluded from
    // sync: those stay outside the plan like every ignored path. Decided
    // before the plan's own read so the ignore check (which reads the
    // namespace for directory-only patterns) runs outside it. Without a
    // readable ignore set none is excluded, so each stays unavailable.
    let ignore_set = link.folder_path().and_then(|root| {
        yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet::load_for_link_root_checked(
            root,
        )
        .ok()
    });
    let still_excluded: std::collections::HashSet<String> = match &ignore_set {
        Some(set) => sqlite
            .rewind_erased_unindexed_paths(group_id, at_unix_nanos)
            .map_err(failed)?
            .into_iter()
            .filter(|path| {
                crate::local_convergence::path_is_ignored(
                    set,
                    &state.replica_coordinator,
                    group_id,
                    path,
                )
            })
            .collect(),
        None => std::collections::HashSet::new(),
    };
    sqlite
        .compute_rewind_plan(group_id, at_unix_nanos, &|path| still_excluded.contains(path))
        .map_err(failed)
}

/// What a person approves when they confirm a preview: the group, the exact
/// target the preview echoed (never a relative offset, which would resolve
/// against a different `now`), and the id of the plan they were shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindExecuteRequest {
    pub group_id: String,
    pub target_unix_nanos: i64,
    pub plan_id: RewindPlanId,
}

/// Why an approved plan may not be executed. Every variant is decided before
/// anything is changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewindExecuteError {
    /// The plan could not be recomputed at all (see [`RewindError`]).
    Plan(RewindError),
    /// The folder changed since the preview, so the plan recomputed from
    /// the current state is not the one that was approved. Carries the
    /// current plan's id and tallies so a caller can show what changed;
    /// it is never executed in place of the approved one.
    PlanStale { current_plan_id: RewindPlanId, current_counts: RewindActionCounts },
    /// The approved plan has paths this device cannot answer for at the
    /// target time, counted by cause. A rewind is all or nothing, so it
    /// cannot start.
    UnavailablePaths(RewindUnavailable),
}

impl std::fmt::Display for RewindExecuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RewindExecuteError::Plan(error) => error.fmt(f),
            RewindExecuteError::PlanStale { .. } => {
                f.write_str(yadorilink_replica_domain::rewind::PLAN_STALE_MESSAGE)
            }
            RewindExecuteError::UnavailablePaths(unavailable) => {
                f.write_str(&unavailable.message())
            }
        }
    }
}

impl std::error::Error for RewindExecuteError {}

/// The check every rewind execution starts with: recompute the full plan
/// from the current index and accept it only if it is exactly the plan that
/// was approved.
///
/// Returns that recomputed plan, which is the one an execution acts on --
/// equal by id to what the person saw, and read from the state it will
/// change. A different id is [`RewindExecuteError::PlanStale`]: the request
/// is refused and nothing is re-planned on the caller's behalf, because a
/// silently substituted plan is a change nobody approved. Reads only; it
/// changes nothing either way.
pub async fn verify_rewind_plan(
    state: Arc<DaemonState>,
    request: RewindExecuteRequest,
) -> Result<RewindPlan, RewindExecuteError> {
    crate::daemon_state::run_blocking_sweep_offloaded(move || {
        let current = preview_rewind_sync(&state, &request.group_id, request.target_unix_nanos)
            .map_err(RewindExecuteError::Plan)?;
        accept_approved_plan(current, &request.plan_id)
    })
}

fn accept_approved_plan(
    current: RewindPlan,
    approved: &RewindPlanId,
) -> Result<RewindPlan, RewindExecuteError> {
    let current_plan_id = current.plan_id();
    let current_counts = current.action_counts();
    if current_plan_id != *approved {
        return Err(RewindExecuteError::PlanStale { current_plan_id, current_counts });
    }
    if current_counts.unavailable > 0 {
        return Err(RewindExecuteError::UnavailablePaths(current.unavailable()));
    }
    Ok(current)
}

/// The control socket's read-only handle onto [`preview_rewind`]. Holds
/// `Arc<DaemonState>` directly rather than behind a port trait, matching
/// `crate::send_transfer::InboxQueries`'s own shape for a single-vertical-
/// slice read service (see `crate::queries`'s module doc comment).
pub(crate) struct RewindQueries {
    state: Arc<DaemonState>,
}

impl RewindQueries {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    /// The group's most recent rewind run, if any.
    pub(crate) fn status(
        &self,
        group_id: &str,
    ) -> Result<Option<yadorilink_replica_domain::rewind::RewindRun>, RewindError> {
        self.state
            .replica_coordinator
            .rewind_run_repository()
            .latest_run(group_id)
            .map_err(|error| RewindError::Failed(error.to_string()))
    }

    pub(crate) async fn preview(
        &self,
        group_id: &str,
        at_unix_nanos: i64,
        include_unchanged: bool,
    ) -> Result<RewindPreview, RewindError> {
        preview_rewind(self.state.clone(), group_id.to_string(), at_unix_nanos, include_unchanged)
            .await
    }
}

mod execute;
mod prepare;
pub use execute::{execute_rewind, start_rewind, RewindHook, RewindPoint, RewindService};
pub use prepare::{begin_rewind, prepare_rewind, BegunRewind, PreparedRewind, RewindPrepareError};

#[cfg(test)]
mod tests;
