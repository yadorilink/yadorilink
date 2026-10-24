//! The reconcile pass driven by NativeState's desired tree.
//!
//! This pass reads what a path must become from the native plan of its level: the
//! physical tree with the exact head behind every node.
//!
//! What a pass over a seed set does:
//!
//! 1. Plans the levels the seeds and their ancestors live on.
//! 2. Orders the work: at each depth the directories, then the entries;
//!    deletions last, deepest first. A path that gives up content another path
//!    still holds waits until that path has it (the displacement guard).
//! 3. Gives each node the shape the plan requires, and projects entries
//!    through [`Election::Native`], which re-plans under the path lock. A
//!    contested path, and everything below it, is left alone.
//! 4. Deletes a path only when the plan holds nothing for it *and* the row at
//!    it was produced under native authority (it names a native head).
//!    An empty native state never deletes.
//!
//! A pass declines (retry) rather than guess in a case it has no rule for
//! yet: a volume that folds names.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use futures_util::stream::{self, StreamExt};

use yadorilink_peer_session::peer_session::*;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::native_plan::{NativeLevelPlan, NativePlannedNode};
use yadorilink_replica_domain::session_state::LinkGate;

use super::namespace_steps::{parent_of, proper_ancestors, DirectoryVerdict};
use super::types::*;

/// One unit of work of a pass.
enum Work {
    Node(NativePlannedNode),
    /// A seed the plan holds nothing for.
    Absent,
}

/// Position in a pass: shallow first; directories, then entries; deletions
/// after everything, deep first.
fn rank(path: &str, work: &Work) -> (u8, usize, u8) {
    let depth = path.matches('/').count();
    match work {
        Work::Absent => (1, usize::MAX - depth, 0),
        Work::Node(
            NativePlannedNode::StructuralDirectory | NativePlannedNode::ExplicitDirectory { .. },
        ) => (0, depth, 0),
        Work::Node(NativePlannedNode::Entry { .. }) => (0, depth, 1),
    }
}

/// Whether a pass may settle a path at all.
enum Gate {
    Open,
    /// Excluded by this device's ignore set: settled without work.
    Ignored,
    /// Paused, in a frozen group, or below a directory that could not be
    /// shaped: left for a later attempt.
    Declined,
}

/// A file or symlink the plan puts at its own path.
fn is_plain_entry(node: &NativePlannedNode) -> bool {
    matches!(node, NativePlannedNode::Entry { .. })
}

/// The claim `path`'s write may close. A path whose conflict copy failed
/// earlier in this pass is not done, so its write gets no claim: its proof may
/// land, its obligation -- the copy's only one -- stays open and the next
/// attempt retries the copy. Every copy of `path` sits in its directory and is
/// ranked before own-name entries there, so it has already been tried by now.
fn claim_for<'a>(
    claims: Option<&'a super::obligation_claims::ObligationClaims>,
    path: &str,
    retry: &BTreeSet<String>,
) -> Option<super::obligation_claims::PathClaim<'a>> {
    claims.and_then(|claims| claims.for_path(path)).filter(|_| {
        !retry.iter().any(|p| yadorilink_replica_domain::conflict::is_conflict_copy_of(p, path))
    })
}

/// Own-name file entries that a pass settles together.
///
/// A pass settles its work one path at a time in rank order. For a run of
/// plain own-name file entries -- a file or symlink the plan puts at its own
/// path, in a group that is live, not paused, not ignored, and with every
/// ancestor shaped -- nothing one entry does is visible to another: each has
/// its own path lock, row, intent, fence and obligation, and its decisions
/// read only that path's state. What the serial order gave beyond that is kept
/// by construction:
///
/// * directories (ranked ahead at every depth), absent
///   paths (ranked last) and anything declined are barriers: the run gathered
///   so far finishes before the barrier item starts, and the next run starts
///   after it;
/// * two entries whose names could be the same file ([`RunIndependence`]) are
///   never in flight together; the later one starts only after the earlier one
///   finished, in rank order, as before;
/// * outcomes are merged into the pass in rank order once the run is done.
///
/// Each future still holds its own path lock for its whole write, and
/// does its own database calls and syncs in the order it always did. A failure
/// in one entry marks only that entry; the others run to completion.
struct RunEntry<'a> {
    path: &'a String,
    node: &'a NativePlannedNode,
    claim: Option<super::obligation_claims::PathClaim<'a>>,
    /// Share of the run's byte budget this entry takes while it is written.
    permits: u32,
}

/// Which names a run of own-name entries may not contain together.
///
/// Two names that fold to the same key (case and Unicode normalisation, over
/// the whole path so differently spelled directories count) can be one file on
/// a folding volume: the serial order lets the second see the first's row and
/// hold, which two simultaneous writers would both miss. A name and a conflict
/// copy of another name in the run are kept apart as well: the copy's retry
/// decides whether the original gets a claim.
#[derive(Default)]
struct RunIndependence {
    /// The folded name of every entry in the run.
    names: HashSet<String>,
    /// The folded name of every ancestor directory of an entry in the run.
    ancestors: HashSet<String>,
    paths: Vec<String>,
}

impl RunIndependence {
    fn conflicts_with_run(&self, path: &str) -> bool {
        use yadorilink_fs_platform::canonical_fold::canonical_fold;
        use yadorilink_replica_domain::conflict::is_conflict_copy_of;
        let own = canonical_fold(path);
        // An entry that folds onto the directory another entry lives in, or the
        // reverse, is the same kind of collision.
        self.names.contains(&own)
            || self.ancestors.contains(&own)
            || proper_ancestors(path).any(|ancestor| self.names.contains(&canonical_fold(ancestor)))
            || self
                .paths
                .iter()
                .any(|other| is_conflict_copy_of(other, path) || is_conflict_copy_of(path, other))
    }

    fn admit(&mut self, path: &str) {
        use yadorilink_fs_platform::canonical_fold::canonical_fold;
        self.names.insert(canonical_fold(path));
        self.ancestors.extend(proper_ancestors(path).map(canonical_fold));
        self.paths.push(path.to_owned());
    }

    fn clear(&mut self) {
        self.names.clear();
        self.ancestors.clear();
        self.paths.clear();
    }
}

/// Bytes of file data a run may have in flight at once, in KiB units: the
/// sum of the temp files being written. A file larger than this takes all of
/// it and so runs alone.
const RUN_BYTE_BUDGET_KIB: u32 = 256 * 1024;

fn byte_permits_for_size(size: u64) -> u32 {
    u32::try_from(size.div_ceil(1024)).unwrap_or(u32::MAX).clamp(1, RUN_BYTE_BUDGET_KIB)
}

/// Own-name entries settled concurrently per pass; `1` is the serial order.
pub(crate) const DEFAULT_RECEIVE_WRITE_CONCURRENCY: usize = 32;

/// Largest concurrency an override can select. Throughput plateaus well
/// before this (the receive window is itself capped at 64), and every lane
/// holds a path lock, a temp file and a share of the byte budget.
const MAX_RECEIVE_WRITE_CONCURRENCY: usize = 64;

const _: () = assert!(DEFAULT_RECEIVE_WRITE_CONCURRENCY <= MAX_RECEIVE_WRITE_CONCURRENCY);

/// Most items one collector batch (open, completion) carries.
///
/// Decoupled from the write concurrency: a full open batch makes two
/// root-identity filesystem checks per item inside ONE transaction while the
/// process-wide writer gate is held, so the hold is bounded by this cap times
/// the per-item checks (16 items: up to 32 observations), not by how many
/// files are in flight. A slow or network-mounted root would otherwise stall
/// scans, flushes and other writers, and lengthen `stop()`.
const DEFAULT_COLLECTOR_FLUSH_CAP: usize = 16;
const MIN_COLLECTOR_FLUSH_CAP: usize = 1;
const MAX_COLLECTOR_FLUSH_CAP: usize = 64;
pub(crate) fn parse_collector_flush_cap(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .map_or(DEFAULT_COLLECTOR_FLUSH_CAP, |n| {
            n.clamp(MIN_COLLECTOR_FLUSH_CAP, MAX_COLLECTOR_FLUSH_CAP)
        })
}

pub(crate) fn parse_receive_write_concurrency(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .map_or(DEFAULT_RECEIVE_WRITE_CONCURRENCY, |n| n.min(MAX_RECEIVE_WRITE_CONCURRENCY))
}

impl super::LocalConvergenceExecutor {
    /// The levels a pass over `seeds` has to read: each seed's, and its
    /// ancestors' (a head landing below a path can turn the path into a
    /// directory that displaces its own winner).
    fn native_levels_of(&self, seeds: &BTreeSet<String>) -> BTreeSet<String> {
        let mut levels = BTreeSet::new();
        for path in seeds {
            levels.insert(parent_of(path).to_owned());
            for ancestor in proper_ancestors(path) {
                levels.insert(parent_of(ancestor).to_owned());
            }
        }
        levels
    }

    /// Whether a rebootstrap freezes `group_id`: nothing is settled, written, removed
    /// or moved in it until the rebootstrap finishes.
    fn group_frozen(&self, group_id: &str) -> Result<bool, PeerSessionError> {
        self.state
            .held_path_repository()
            .group_frozen(group_id)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub(crate) async fn reconcile_group_paths_native(
        &self,
        group_id: &str,
        seed_paths: BTreeSet<String>,
        origin_device_id: &str,
        prefetched: &HashMap<String, BlockRequirement>,
        claims: Option<&super::obligation_claims::ObligationClaims>,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<ProjectionAttempt, PeerSessionError> {
        let call_started = std::time::Instant::now();
        if !seed_paths.is_empty() {
            yadorilink_fs_platform::join_timeline::mark_with_peer(
                &self.local_device_id,
                group_id,
                yadorilink_fs_platform::join_timeline::Milestone::ProjectionWorkCreated,
                origin_device_id,
            );
        }
        let plan_started = crate::receive_diag::clock();
        let LinkGate::Live { policy, .. } = self.state.link_gate_for_group(group_id)? else {
            return Ok(ProjectionAttempt { retry: seed_paths, ..Default::default() });
        };
        let mut paused = self
            .state
            .paused_item_repository()
            .list(group_id)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)?;
        paused.extend(
            self.state
                .held_path_repository()
                .held_paths(group_id)
                .map_err(crate::sync_error::SyncError::from)
                .map_err(PeerSessionError::from)?,
        );

        let mut settled: BTreeMap<String, SettlementEvidence> = BTreeMap::new();
        let mut retry: BTreeSet<String> = BTreeSet::new();

        // Plan every level once, for the names the pass is about: each seed, its
        // ancestors, and whatever stands for them. A level whose names cannot be planned (a
        // live head whose version this replica does not hold) fails closed: every seed that
        // needs it retries; nothing is taken as absent.
        let interesting: BTreeSet<&str> = seed_paths
            .iter()
            .map(String::as_str)
            .chain(seed_paths.iter().flat_map(|p| proper_ancestors(p)))
            .collect();
        let mut plans: BTreeMap<String, NativeLevelPlan> = BTreeMap::new();
        let mut unplannable: BTreeSet<String> = BTreeSet::new();
        for level in self.native_levels_of(&seed_paths) {
            let started = std::time::Instant::now();
            let on_level: BTreeSet<String> = interesting
                .iter()
                .filter(|name| parent_of(name) == level)
                .map(|name| (*name).to_owned())
                .collect();
            match self.state.native_plan_for_names(group_id, &level, &on_level) {
                Ok(plan) => {
                    plans.insert(level, plan);
                }
                Err(yadorilink_sync_sqlite::SyncSqliteError::NotFound(_)) => {
                    unplannable.insert(level);
                }
                Err(error) => return Err(crate::sync_error::SyncError::from(error).into()),
            }
            call_timer.add_dag_resolution(started.elapsed());
        }

        // A contested path is not planned: it and everything below it wait for
        // the loser's author to rename its head. Nothing is created, replaced
        // or removed at or below it.
        let contested: BTreeSet<String> = plans
            .values()
            .flat_map(|plan| plan.contested.iter().map(|path| path.as_str().to_owned()))
            .collect();

        // The work: every node of a planned level that a seed (or the
        // ancestor of one) is, and every seed the plan holds nothing for.
        let mut work: BTreeMap<String, Work> = BTreeMap::new();
        for plan in plans.values() {
            for (path, node) in &plan.nodes {
                if interesting.contains(path.as_str()) {
                    work.insert(path.as_str().to_owned(), Work::Node(node.clone()));
                }
            }
        }
        for path in &seed_paths {
            if work.contains_key(path) {
                continue;
            }
            if contested.contains(path) {
                retry.insert(path.clone());
                continue;
            }
            if unplannable.contains(parent_of(path)) {
                retry.insert(path.clone());
            } else {
                work.insert(path.clone(), Work::Absent);
            }
        }

        let mut order: Vec<&String> = work.keys().collect();
        order.sort_by_key(|path| (rank(path, &work[*path]), (*path).clone()));

        if let Some(started) = plan_started {
            call_timer.add_window_plan(started.elapsed());
        }
        let settle_started = crate::receive_diag::clock();
        let frozen = self.group_frozen(group_id)?;
        let mut unshaped: BTreeSet<String> = contested.clone();
        let mut pressure: Option<super::types::DiskPressureWait> = None;
        let limit = self.receive_write_concurrency();
        let mut run: Vec<RunEntry<'_>> = Vec::new();
        let mut independence = RunIndependence::default();
        for path in order {
            let item = &work[path];
            let gate = self.pass_gate(group_id, path, &paused, frozen, &unshaped);
            if let (Gate::Open, Work::Node(node)) = (&gate, item) {
                if is_plain_entry(node) {
                    if independence.conflicts_with_run(path) {
                        self.settle_plain_run(
                            group_id,
                            std::mem::take(&mut run),
                            &work,
                            policy,
                            prefetched,
                            limit,
                            call_timer,
                            (&mut settled, &mut retry, &mut unshaped, &mut pressure),
                        )
                        .await;
                        independence.clear();
                    }
                    // After the flush: the claim depends on what the entries before this
                    // one, a conflict copy of it above all, ended up as.
                    let claim = claim_for(claims, path, &retry);
                    independence.admit(path);
                    let permits =
                        byte_permits_for_size(self.planned_size(group_id, node, path, prefetched));
                    run.push(RunEntry { path, node, claim, permits });
                    continue;
                }
            }
            // Anything else is a barrier: the entries gathered so far finish first,
            // exactly as the serial order had them finish before this one began.
            self.settle_plain_run(
                group_id,
                std::mem::take(&mut run),
                &work,
                policy,
                prefetched,
                limit,
                call_timer,
                (&mut settled, &mut retry, &mut unshaped, &mut pressure),
            )
            .await;
            independence.clear();
            match gate {
                Gate::Ignored => {
                    settled.insert(path.clone(), SettlementEvidence::IgnoreExcluded);
                    continue;
                }
                Gate::Declined => {
                    retry.insert(path.clone());
                    continue;
                }
                Gate::Open => {}
            }
            let outcome = match item {
                Work::Absent => {
                    self.native_settle_absent(group_id, path, policy, origin_device_id).await
                }
                Work::Node(node) => {
                    let claim = claim_for(claims, path, &retry);
                    let skippable = claim.is_none() && !seed_paths.contains(path);
                    self.settle_or_skip_node(
                        group_id, path, node, policy, prefetched, claim, skippable,
                    )
                    .await
                }
            };
            self.record_native_outcome(
                group_id,
                path,
                item,
                outcome,
                (&mut settled, &mut retry, &mut unshaped, &mut pressure),
            );
        }
        self.settle_plain_run(
            group_id,
            std::mem::take(&mut run),
            &work,
            policy,
            prefetched,
            limit,
            call_timer,
            (&mut settled, &mut retry, &mut unshaped, &mut pressure),
        )
        .await;

        if let Some(started) = settle_started {
            call_timer.add_window_settle(started.elapsed());
        }
        self.remove_emptied_retained_ancestors(
            group_id,
            settled
                .iter()
                .filter(|(_, evidence)| matches!(evidence, SettlementEvidence::ExactAbsent { .. }))
                .map(|(path, _)| path),
        )
        .await;

        let touched: BTreeSet<&String> = work.keys().chain(seed_paths.iter()).collect();
        for path in touched {
            if !settled.contains_key(path) && !retry.contains(path) {
                tracing::error!(
                    group_id,
                    path = %path,
                    "the native pass examined a path but recorded neither settled nor retry for \
                     it; treating as retry, never as an accidental success"
                );
                retry.insert(path.clone());
            }
        }
        call_timer.finish(group_id, work.len(), settled.len(), retry.len(), call_started.elapsed());
        Ok(ProjectionAttempt { settled, retry, disk_pressure: pressure })
    }

    /// Bytes `path`'s write will put on disk: the version being materialised.
    pub(super) fn planned_size(
        &self,
        group_id: &str,
        node: &NativePlannedNode,
        path: &str,
        prefetched: &HashMap<String, BlockRequirement>,
    ) -> u64 {
        if let Some(requirement) = prefetched.get(path) {
            return requirement.record.size;
        }
        let NativePlannedNode::Entry { head, .. } = node else { return 0 };
        self.state
            .dag_get_file_version(group_id, &head.version())
            .ok()
            .flatten()
            .map_or(0, |version| version.size)
    }

    fn pass_gate(
        &self,
        group_id: &str,
        path: &str,
        paused: &[String],
        frozen: bool,
        unshaped: &BTreeSet<String>,
    ) -> Gate {
        if self.is_locally_ignored(group_id, path) {
            return Gate::Ignored;
        }
        // Nothing is settled in a group a rebootstrap freezes: settling would write,
        // remove or move an object while the rebootstrap holds the group still.
        if yadorilink_sync_sqlite::paused_items::path_is_covered(paused, path)
            || frozen
            || proper_ancestors(path).any(|ancestor| unshaped.contains(ancestor))
        {
            return Gate::Declined;
        }
        Gate::Open
    }

    /// How many own-name entries of a pass are settled at once. Read fresh per
    /// pass, so a measurement can A/B it with no rebuild; `1` is the serial
    /// order.
    fn receive_write_concurrency(&self) -> usize {
        #[cfg(any(test, feature = "test-support"))]
        {
            let pinned =
                self.receive_write_concurrency_override.load(std::sync::atomic::Ordering::Relaxed);
            if pinned > 0 {
                return pinned;
            }
        }
        self.state.tuning().receive_write_concurrency
    }

    /// How many items a collector batch may carry; see
    /// [`DEFAULT_COLLECTOR_FLUSH_CAP`].
    fn collector_flush_cap(&self) -> usize {
        #[cfg(any(test, feature = "test-support"))]
        {
            let pinned =
                self.collector_flush_cap_override.load(std::sync::atomic::Ordering::Relaxed);
            if pinned > 0 {
                return pinned;
            }
        }
        self.state.tuning().collector_flush_cap
    }

    /// Whether the files of a run hand their completion transaction to a
    /// shared queue (see [`super::completion_window`]) instead of each
    /// committing its own. Read fresh per pass, so a measurement can A/B it.
    fn batch_completion(&self) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        match self.batch_completion_override.load(std::sync::atomic::Ordering::Relaxed) {
            1 => return true,
            2 => return false,
            _ => {}
        }
        self.state.tuning().batch_completion
    }

    /// Whether the files of a run queue the open of their write in the same
    /// window. Read fresh per pass, so a measurement can A/B it.
    fn batch_open(&self) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        match self.batch_open_override.load(std::sync::atomic::Ordering::Relaxed) {
            1 => return true,
            2 => return false,
            _ => {}
        }
        self.state.tuning().batch_open
    }

    /// How a pass flushes the files it received, when it does not do so one by
    /// one: `YADORILINK_RECEIVE_DEFERRED_FSYNC` (on by default on macOS, `0`
    /// opts out; see `completion_window::parse_deferred_flush`). Read
    /// fresh per pass, so a measurement can A/B it.
    pub(crate) fn deferred_flush(
        &self,
        group_id: &str,
    ) -> Option<yadorilink_local_storage::ReceivedFlushMode> {
        #[cfg(any(test, feature = "test-support"))]
        let mode = match self.deferred_flush_override.load(std::sync::atomic::Ordering::Relaxed) {
            1 => Some(yadorilink_local_storage::ReceivedFlushMode::FullFsyncEach),
            2 => Some(yadorilink_local_storage::ReceivedFlushMode::FsyncThenOneFullFsync),
            3 => None,
            _ => self.state.tuning().deferred_flush,
        };
        #[cfg(not(any(test, feature = "test-support")))]
        let mode = self.state.tuning().deferred_flush;
        // Only a plain directory root: a provider root keeps the durability
        // contract of its own path, and a root whose declaration cannot be
        // read is not assumed plain.
        mode.filter(|_| {
            crate::provider_gate::require_filesystem_root(&self.state, group_id).is_ok()
        })
    }

    /// Hands the files a finished run left unflushed to one barrier, off the
    /// pass: the run does not wait for stable storage.
    fn start_flush_barrier(&self, window: &super::completion_window::CompletionWindow) {
        let Some(mode) = window.deferred_flush_mode() else { return };
        let pending = window.take_flush_pending();
        if pending.is_empty() {
            return;
        }
        let state = self.state.clone();
        let handle = tokio::task::spawn_blocking(move || {
            super::received_flush_barrier::run_flush_barrier(&state, pending, mode)
        });
        let mut barriers = self.flush_barriers.lock().unwrap_or_else(|p| p.into_inner());
        barriers.retain(|barrier| !barrier.is_finished());
        barriers.push(handle);
    }

    /// Waits for the barriers of the runs finished so far.
    #[cfg(all(test, unix))]
    pub(crate) async fn drain_flush_barriers(
        &self,
    ) -> Vec<super::received_flush_barrier::BarrierReport> {
        let handles = std::mem::take(&mut *self.flush_barriers.lock().unwrap());
        let mut reports = Vec::new();
        for handle in handles {
            reports.push(handle.await.expect("the barrier does not panic"));
        }
        reports
    }

    fn completion_max_latency(&self) -> std::time::Duration {
        #[cfg(any(test, feature = "test-support"))]
        {
            let pinned =
                self.completion_max_latency_override_ms.load(std::sync::atomic::Ordering::Relaxed);
            if pinned > 0 {
                return std::time::Duration::from_millis(pinned);
            }
        }
        super::completion_window::DEFAULT_MAX_LATENCY
    }

    /// Folds the outcome of settling `path` into the pass.
    fn record_native_outcome(
        &self,
        group_id: &str,
        path: &String,
        item: &Work,
        outcome: Result<MaterializeResult, PeerSessionError>,
        (settled, retry, unshaped, pressure): (
            &mut BTreeMap<String, SettlementEvidence>,
            &mut BTreeSet<String>,
            &mut BTreeSet<String>,
            &mut Option<super::types::DiskPressureWait>,
        ),
    ) {
        match outcome {
            Ok(MaterializeResult::Settled(evidence)) => {
                settled.insert(path.clone(), evidence);
            }
            Ok(MaterializeResult::RetryRequired) => {
                if matches!(item, Work::Node(node) if !matches!(node, NativePlannedNode::Entry { .. }))
                    && !self.directory_on_disk(group_id, path)
                {
                    unshaped.insert(path.clone());
                }
                retry.insert(path.clone());
            }
            Err(error) => {
                if let PeerSessionError::DiskPressure {
                    volume,
                    available_bytes,
                    headroom_bytes,
                    ..
                } = &error
                {
                    pressure.get_or_insert_with(|| super::types::DiskPressureWait {
                        volume: volume.clone(),
                        available_bytes: *available_bytes,
                        required_free_bytes: *headroom_bytes,
                    });
                }
                tracing::warn!(
                    group_id,
                    path = %path,
                    error = %error,
                    "failed to project a path from native state; leaving it for retry"
                );
                retry.insert(path.clone());
            }
        }
    }

    /// Settles a run of own-name entries (see [`RunEntry`]) with up to `limit`
    /// in flight, then folds their outcomes into the pass in rank order.
    #[allow(clippy::too_many_arguments)]
    async fn settle_plain_run(
        &self,
        group_id: &str,
        run: Vec<RunEntry<'_>>,
        work: &BTreeMap<String, Work>,
        policy: yadorilink_replica_domain::session_state::MaterializationPolicy,
        prefetched: &HashMap<String, BlockRequirement>,
        limit: usize,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
        ledger: (
            &mut BTreeMap<String, SettlementEvidence>,
            &mut BTreeSet<String>,
            &mut BTreeSet<String>,
            &mut Option<super::types::DiskPressureWait>,
        ),
    ) {
        if run.is_empty() {
            return;
        }
        let (settled, retry, unshaped, pressure) = ledger;
        let budget = tokio::sync::Semaphore::new(RUN_BYTE_BUDGET_KIB as usize);
        // One run, one window: the files of a run queue their completions here.
        let (completions, opens) = (self.batch_completion(), self.batch_open());
        let window = (completions || opens).then(|| {
            super::completion_window::CompletionWindow::with_deferred_flush(
                self.collector_flush_cap(),
                self.completion_max_latency(),
                completions,
                opens,
                self.state.async_commit(),
                self.deferred_flush(group_id),
            )
        });
        // Whatever ends the run, the files it left unflushed get their barrier: a
        // cancelled run schedules it from here when the normal path did not.
        let _barrier_on_drop = window
            .as_ref()
            .map(|window| FlushBarrierOnDrop { state: self.state.clone(), window: window.clone() });
        let trace = crate::receive_diag::run_trace_begin();
        let mut outcomes = crate::receive_diag::run_trace_scope(trace.clone(), async {
            // Built in a loop, not through a closure: a closure returning a borrowing
            // future makes the pass's future unprovably `Send`.
            let mut pending = Vec::with_capacity(run.len());
            for (index, entry) in run.iter().enumerate() {
                pending.push(self.settle_run_entry(
                    group_id,
                    index,
                    entry,
                    &budget,
                    window.as_ref(),
                    policy,
                    prefetched,
                ));
            }
            stream::iter(pending).buffer_unordered(limit.max(1)).collect::<Vec<_>>().await
        })
        .await;
        crate::receive_diag::run_trace_end(trace);
        if let Some(window) = &window {
            let (waits, flushes) = window.collector_times();
            call_timer.add_collectors(waits, flushes);
            self.start_flush_barrier(window);
        }
        outcomes.sort_by_key(|(index, _)| *index);
        for (index, outcome) in outcomes {
            let entry = &run[index];
            self.record_native_outcome(
                group_id,
                entry.path,
                &work[entry.path],
                outcome,
                (&mut *settled, &mut *retry, &mut *unshaped, &mut *pressure),
            );
        }
    }

    /// One entry of a run: waits for its share of the byte budget, then settles.
    #[allow(clippy::too_many_arguments)]
    async fn settle_run_entry(
        &self,
        group_id: &str,
        index: usize,
        entry: &RunEntry<'_>,
        budget: &tokio::sync::Semaphore,
        window: Option<&Arc<super::completion_window::CompletionWindow>>,
        policy: yadorilink_replica_domain::session_state::MaterializationPolicy,
        prefetched: &HashMap<String, BlockRequirement>,
    ) -> (usize, Result<MaterializeResult, PeerSessionError>) {
        let _bytes = budget.acquire_many(entry.permits).await;
        crate::receive_diag::mark(crate::receive_diag::Stage::Started);
        // A participant from here to the end of this future, however it ends:
        // the window does not wait for entries that are not running.
        let participant = window.map(|window| window.join());
        if let Some(window) = window {
            window.let_siblings_join().await;
        }
        let settle = self.native_settle_node(
            group_id,
            entry.path,
            entry.node,
            policy,
            prefetched,
            entry.claim,
        );
        let outcome = match (window, participant) {
            (Some(window), Some(participant)) => {
                super::completion_window::within(window.clone(), participant, settle).await
            }
            _ => settle.await,
        };
        crate::receive_diag::mark(crate::receive_diag::Stage::Closed);
        (index, outcome)
    }

    /// The zero-work pre-check under native authority: `path` is confirmed
    /// current only when native's plan makes it a plain entry and the recorded
    /// proof equals what native requires there. A removal, a directory, a
    /// contested path, or a path native cannot plan yet does the real work.
    pub(crate) fn native_zero_work_settlement(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        let plan = match self.state.native_plan_nodes(
            group_id,
            parent_of(path),
            &BTreeSet::from([path.to_owned()]),
        ) {
            Ok(plan) => plan,
            Err(yadorilink_sync_sqlite::SyncSqliteError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(crate::sync_error::SyncError::from(error).into()),
        };
        let own = SyncPath(path.to_owned());
        if !matches!(plan.nodes.get(&own), Some(NativePlannedNode::Entry { .. })) {
            return Ok(None);
        }
        Ok(self.state.dag_zero_work_settlement_if_already_current(group_id, path)?.map(
            |(exact_state, mutation_generation)| {
                SettlementEvidence::from_exact_actual_state(exact_state, mutation_generation)
            },
        ))
    }

    /// [`Self::native_settle_node`], except that an ancestor directory that is
    /// `skippable` (the pass is only passing through it) and already settled
    /// is not settled again.
    #[allow(clippy::too_many_arguments)]
    async fn settle_or_skip_node(
        &self,
        group_id: &str,
        path: &str,
        node: &NativePlannedNode,
        policy: yadorilink_replica_domain::session_state::MaterializationPolicy,
        prefetched: &HashMap<String, BlockRequirement>,
        claim: Option<super::obligation_claims::PathClaim<'_>>,
        skippable: bool,
    ) -> Result<MaterializeResult, PeerSessionError> {
        if skippable {
            if let Some(evidence) =
                self.already_settled_ancestor_directory(group_id, path, node).await?
            {
                return Ok(MaterializeResult::Settled(evidence));
            }
        }
        self.native_settle_node(group_id, path, node, policy, prefetched, claim).await
    }

    /// The settlement of an explicit directory that this pass is only passing
    /// through (an ancestor of a seed, not a seed), when settling it again
    /// could change nothing; `None` when it must be settled for real.
    ///
    /// Everything a directory settle writes is already so: the recorded proof
    /// is for the version the plan requires here now (re-read, descendants
    /// included), its fence is current (no write started since) and the live
    /// directory still has the recorded identity and mode; the row is that
    /// head's, not held, and `Present`; and the name is no hazard. Any change
    /// to the directory (a new head, a rename, a delete, a conflict, a write
    /// in flight, an edit on disk) fails one of these and the settle runs.
    ///
    /// The hazard await is not re-fenced: a write that lands in it leaves the
    /// evidence carrying the older fence, which the publication CAS refuses
    /// (a skip writes nothing, so nothing is lost); see
    /// `ancestor_directory_tests`.
    async fn already_settled_ancestor_directory(
        &self,
        group_id: &str,
        path: &str,
        node: &NativePlannedNode,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        let NativePlannedNode::ExplicitDirectory { head } = node else { return Ok(None) };
        if self.is_locally_ignored(group_id, path) {
            return Ok(None);
        }
        let Some((exact, mutation_generation, version)) =
            self.state.settled_explicit_directory(group_id, path, head)?
        else {
            return Ok(None);
        };
        let record = file_record_from_version(path, &version);
        if self.hazard_reason_for(group_id, &record).await?.is_some() {
            return Ok(None);
        }
        Ok(Some(SettlementEvidence::from_exact_actual_state(exact, mutation_generation)))
    }

    /// Whether `path` may give up the content its row shows, to show `planned`
    /// (`None` for a directory or nothing): a version that is live at another
    /// path as well is first on disk there, and on a platform that can make
    /// that durable.
    pub(crate) async fn displacement_allowed(
        &self,
        group_id: &str,
        path: &str,
        planned: Option<&yadorilink_replica_domain::ids::VersionHash>,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_sync_sqlite::displacement_guard::DisplacementGuard;
        let volume = self.volume_probes.folding(&self.sync_root(group_id)?).await.known();
        let verdict = self
            .state
            .displacement_guard(group_id, path, planned, &|other| {
                // A volume whose behaviour is unknown excludes nothing: the path waits.
                volume.is_some_and(|volume| volume_folds_together(volume, path, other))
            })
            .map_err(crate::sync_error::SyncError::from)?;
        Ok(match verdict {
            DisplacementGuard::Clear => true,
            DisplacementGuard::Wait => false,
            DisplacementGuard::Guarded(holders) => {
                // The rows are the index's belief; the disk must show it.
                for holder in &holders {
                    let on_disk = matches!(
                        self.zero_work_settlement_for_path(group_id, holder)?,
                        Some(SettlementEvidence::ExactObject { .. })
                    );
                    // The identity proof is inconclusive on a volume with a coarse birth-time
                    // clock and no inode generation (overlayfs, tmpfs), and waiting for it
                    // would wait forever. The question here is whether the content is kept
                    // under the other name, which its bytes answer directly.
                    if !on_disk && !self.holder_bytes_match_row(group_id, holder).await? {
                        return Ok(false);
                    }
                }
                let durable = match self.sync_root(group_id) {
                    Ok(root) => {
                        yadorilink_sync_sqlite::displacement_guard::destructive_step_durable(&root)
                    }
                    Err(_) => false,
                };
                if !durable {
                    tracing::warn!(
                        group_id,
                        path,
                        "the conflict is resolved, but this platform cannot yet make the file \
                         update durable; the local file is left as it is"
                    );
                }
                durable
            }
        })
    }

    /// Whether the object on disk at `holder` is, byte for byte, what the index row
    /// of `holder` describes (the file's blocks, or the symlink's target), and has been
    /// made durable. Anything that cannot be positively confirmed is `false`.
    async fn holder_bytes_match_row(
        &self,
        group_id: &str,
        holder: &str,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_local_storage::{
            disk_matches_expected_object, DiskContentComparison, ExpectedObject,
        };
        if self.is_locally_ignored(group_id, holder) {
            return Ok(false);
        }
        let Some(row) = self
            .state
            .file_index_repository()
            .canonical_current_row(group_id, holder)
            .map_err(crate::sync_error::SyncError::from)?
        else {
            return Ok(false);
        };
        if row.snapshot.deleted {
            return Ok(false);
        }
        let full = self.sync_root(group_id)?.join(holder);
        let snapshot = row.snapshot;
        let matched = tokio::task::spawn_blocking(move || {
            let expected = match snapshot.record_kind {
                yadorilink_replica_domain::file::RecordKind::File => {
                    ExpectedObject::File { blocks: &snapshot.blocks }
                }
                yadorilink_replica_domain::file::RecordKind::Symlink => {
                    ExpectedObject::Symlink { target: snapshot.symlink_target.as_deref() }
                }
                yadorilink_replica_domain::file::RecordKind::Directory => return false,
            };
            if !matches!(
                disk_matches_expected_object(&full, expected),
                Ok(DiskContentComparison::Matched)
            ) {
                return false;
            }
            // The caller is about to give up the only other copy: what was just read
            // must also survive a crash, in the file and in its directory entry.
            if snapshot.record_kind == yadorilink_replica_domain::file::RecordKind::File
                && !yadorilink_fs_platform::flush::open_for_flush(&full)
                    .and_then(|file| yadorilink_fs_platform::flush::sync_file(&file))
                    .is_ok()
            {
                return false;
            }
            yadorilink_local_storage::sync_parent_dir(&full).is_ok()
        })
        .await
        .unwrap_or(false);
        Ok(matched)
    }

    /// Gives `path` the shape `node` requires and projects it.
    #[allow(clippy::too_many_arguments)]
    async fn native_settle_node(
        &self,
        group_id: &str,
        path: &str,
        node: &NativePlannedNode,
        policy: yadorilink_replica_domain::session_state::MaterializationPolicy,
        prefetched: &HashMap<String, BlockRequirement>,
        claim: Option<super::obligation_claims::PathClaim<'_>>,
    ) -> Result<MaterializeResult, PeerSessionError> {
        let planned = match node {
            NativePlannedNode::Entry { head, .. } => Some(head.version()),
            _ => None,
        };
        if !self.displacement_allowed(group_id, path, planned.as_ref()).await? {
            return Ok(MaterializeResult::RetryRequired);
        }
        crate::receive_diag::mark(crate::receive_diag::Stage::Displaced);
        // A copy of content already on this device (a fork's copy of a hydrated
        // loser) is written, not left a placeholder: the guard at the original
        // path waits for it to stand on disk.
        let policy = match (&planned, policy) {
            (
                Some(version),
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
            ) if self
                .state
                .version_present_elsewhere(group_id, path, version)
                .map_err(crate::sync_error::SyncError::from)? =>
            {
                yadorilink_replica_domain::session_state::MaterializationPolicy::Eager
            }
            _ => policy,
        };
        match node {
            NativePlannedNode::StructuralDirectory => {
                self.settle_structural_container(group_id, path).await
            }
            NativePlannedNode::ExplicitDirectory { .. } => {
                if !self.displace_leaf_for_directory(group_id, path).await? {
                    return Ok(MaterializeResult::RetryRequired);
                }
                self.materialize_native_entry(
                    group_id,
                    path,
                    node,
                    policy,
                    prefetched.get(path),
                    claim,
                )
                .await
            }
            NativePlannedNode::Entry { .. } => {
                // A directory that holds this name under another spelling
                // cannot be displaced by an entry. A *leaf* that folds to
                // it is the name collision the materializer holds the
                // record for, so it is not declined here.
                if self.folded_directory_holds_name(group_id, path)? {
                    return Ok(MaterializeResult::RetryRequired);
                }
                match self.settle_directory_in_the_way(group_id, path).await? {
                    DirectoryVerdict::Clear => {}
                    DirectoryVerdict::Retry => return Ok(MaterializeResult::RetryRequired),
                    // The directory stays and the entry waits: the obstacle is
                    // this device's own, never a replicated name.
                    DirectoryVerdict::Kept => return Ok(MaterializeResult::RetryRequired),
                }
                crate::receive_diag::mark(crate::receive_diag::Stage::DirChecked);
                self.materialize_native_entry(
                    group_id,
                    path,
                    node,
                    policy,
                    prefetched.get(path),
                    claim,
                )
                .await
            }
        }
    }

    /// The plan holds nothing for `path`. It is removed only when the row at
    /// it was produced under native authority; a row of unknown
    /// authorship is never deleted on the strength of an empty native state.
    async fn native_settle_absent(
        &self,
        group_id: &str,
        path: &str,
        policy: yadorilink_replica_domain::session_state::MaterializationPolicy,
        origin_device_id: &str,
    ) -> Result<MaterializeResult, PeerSessionError> {
        if self.flush_local_changes_before_reconcile(group_id, path).await
            == PendingLocalFlushOutcome::RetryRequired
        {
            return Ok(MaterializeResult::RetryRequired);
        }
        let synthetic = FileRecord {
            path: path.to_owned(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: Vec::new(),
            deleted: true,
        };
        if let Some(reason) = self.hazard_reason_for(group_id, &synthetic).await? {
            // Which physical file a removal here would delete is ambiguous:
            // the row is marked held and nothing on disk is touched.
            if self.state.get_file(group_id, path)?.is_some_and(|row| !row.deleted) {
                self.state.rehold_if_reason_changed(group_id, path, &reason)?;
            }
            return Ok(MaterializeResult::RetryRequired);
        }
        let path_lock = self.state.path_lock(group_id, path);
        let _guard = crate::receive_diag::lock_path(&path_lock).await;
        // Re-plan under the lock: something may have landed since.
        let fresh = self
            .state
            .native_plan_node(group_id, path)
            .map_err(|error| PeerSessionError::from(crate::sync_error::SyncError::from(error)));
        match fresh {
            Ok(Some(_)) => return Ok(MaterializeResult::RetryRequired),
            Ok(_) => {}
            Err(_) => return Ok(MaterializeResult::RetryRequired),
        }
        let row = self.state.get_file(group_id, path)?;
        // The `version_seq = 0` scaffold of a metadata step whose head went away is not a live
        // row: it holds no content and no authorship, so there is nothing to remove for it.
        let still_live = row.as_ref().is_some_and(|r| !r.deleted)
            && self.state.has_real_current_row(group_id, path)?;
        if !still_live {
            if !self.observably_absent_on_disk(group_id, path)? {
                return Ok(MaterializeResult::RetryRequired);
            }
            if row.is_some_and(|r| !r.deleted) {
                // Only the scaffold row, dropped alone; anything on disk was refused above, left
                // for capture.
                let authority = self.root_lease_for(group_id)?;
                let authority_op = authority.begin_operation()?;
                self.state.retire_bootstrap_scaffold(group_id, path, &authority_op.permit())?;
            }
            let mutation_generation = self.state.dag_snapshot_mutation_fence(group_id, path)?;
            return Ok(MaterializeResult::Settled(SettlementEvidence::ExactAbsent {
                mutation_generation,
            }));
        }
        // Under the path lock: the content this removal drops lives on at
        // another path (a fork) and is on disk there, or the path waits.
        if !self.displacement_allowed(group_id, path, None).await? {
            return Ok(MaterializeResult::RetryRequired);
        }
        if self.state.row_authoring(group_id, path)?.is_none() {
            // Not known to be produced under native authority: revalidate
            // when native state speaks for the path, never guess.
            tracing::debug!(
                target: "convergence",
                group_id,
                path,
                "removal waits: the live row at the path has no verified native authoring"
            );
            return Ok(MaterializeResult::RetryRequired);
        }
        if self.removal_would_destroy_unrecorded_state(
            group_id,
            path,
            &self.local_file_path(group_id, path)?,
        )? {
            return Ok(MaterializeResult::RetryRequired);
        }
        let record = FileRecord {
            path: path.to_owned(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: Vec::new(),
            deleted: true,
        };
        let payload = MaterializationPayload::tombstone(record.clone());
        match self
            .materialize_local(group_id, &payload, policy, origin_device_id, None, None, None)
            .await?
        {
            LocalMaterializeOutcome::Concluded(result) => Ok(result),
            LocalMaterializeOutcome::NeedBlocks(_) => Ok(MaterializeResult::RetryRequired),
        }
    }
}

#[cfg(test)]
mod run_tests {
    use super::*;

    #[test]
    fn names_that_could_be_one_file_are_never_in_a_run_together() {
        let mut run = RunIndependence::default();
        run.admit("docs/Report.txt");
        run.admit("notes.txt");
        // Case, normalisation, and a differently spelled directory.
        assert!(run.conflicts_with_run("docs/report.txt"));
        assert!(run.conflicts_with_run("DOCS/Report.txt"));
        assert!(run.conflicts_with_run("Notes.TXT"));
        assert!(!RunIndependence::default().conflicts_with_run("x"));
        let mut composed = RunIndependence::default();
        composed.admit("caf\u{e9}.txt");
        assert!(composed.conflicts_with_run("cafe\u{301}.txt"));
        // An entry and the directory another entry lives in, either way round.
        let mut nested = RunIndependence::default();
        nested.admit("d/x.txt");
        assert!(nested.conflicts_with_run("D"));
        assert!(nested.conflicts_with_run("d"));
        let mut file = RunIndependence::default();
        file.admit("d");
        assert!(file.conflicts_with_run("D/x.txt"));
        // Unrelated names are independent.
        assert!(!run.conflicts_with_run("docs/other.txt"));
        assert!(!run.conflicts_with_run("a/notes.txt"));
        assert!(!nested.conflicts_with_run("d/y.txt"));
    }

    #[test]
    fn a_conflict_copy_and_its_original_are_never_in_a_run_together() {
        let copy = "a/report (conflicted copy, device-b).txt";
        assert!(yadorilink_replica_domain::conflict::is_conflict_copy_of(copy, "a/report.txt"));
        let mut run = RunIndependence::default();
        run.admit("a/report.txt");
        assert!(run.conflicts_with_run(copy));
        let mut run = RunIndependence::default();
        run.admit(copy);
        assert!(run.conflicts_with_run("a/report.txt"));
        run.clear();
        assert!(!run.conflicts_with_run("a/report.txt"));
    }

    #[test]
    fn a_file_larger_than_the_run_budget_takes_all_of_it() {
        assert_eq!(byte_permits_for_size(0), 1);
        assert_eq!(byte_permits_for_size(1024), 1);
        assert_eq!(byte_permits_for_size(1025), 2);
        assert_eq!(byte_permits_for_size(300 * 1024 * 1024), RUN_BYTE_BUDGET_KIB);
        assert_eq!(byte_permits_for_size(u64::MAX), RUN_BYTE_BUDGET_KIB);
    }

    #[test]
    fn the_write_concurrency_knob_defaults_to_concurrent_and_one_means_serial() {
        assert_eq!(parse_receive_write_concurrency(None), DEFAULT_RECEIVE_WRITE_CONCURRENCY);
        assert_eq!(parse_receive_write_concurrency(Some("1")), 1);
        assert_eq!(parse_receive_write_concurrency(Some("16")), 16);
        assert_eq!(parse_receive_write_concurrency(Some("0")), DEFAULT_RECEIVE_WRITE_CONCURRENCY);
        assert_eq!(parse_receive_write_concurrency(Some("x")), DEFAULT_RECEIVE_WRITE_CONCURRENCY);
    }

    #[test]
    fn the_collector_flush_cap_defaults_and_clamps() {
        assert_eq!(parse_collector_flush_cap(None), DEFAULT_COLLECTOR_FLUSH_CAP);
        assert_eq!(parse_collector_flush_cap(Some("0")), DEFAULT_COLLECTOR_FLUSH_CAP);
        assert_eq!(parse_collector_flush_cap(Some("x")), DEFAULT_COLLECTOR_FLUSH_CAP);
        assert_eq!(parse_collector_flush_cap(Some("1")), 1);
        assert_eq!(parse_collector_flush_cap(Some("8")), 8);
        assert_eq!(parse_collector_flush_cap(Some("100")), MAX_COLLECTOR_FLUSH_CAP);
    }

    #[test]
    fn the_write_concurrency_override_is_clamped() {
        assert_eq!(parse_receive_write_concurrency(Some("64")), MAX_RECEIVE_WRITE_CONCURRENCY);
        assert_eq!(parse_receive_write_concurrency(Some("128")), MAX_RECEIVE_WRITE_CONCURRENCY);
        assert_eq!(parse_receive_write_concurrency(Some("1000")), MAX_RECEIVE_WRITE_CONCURRENCY);
    }
}

/// Whether `volume` folds `other` and `path` onto one name, so that at most one of them can be
/// on disk.
pub(crate) fn volume_folds_together(
    volume: super::types::VolumeFolding,
    path: &str,
    other: &str,
) -> bool {
    use yadorilink_fs_platform::canonical_fold::{canonical_fold, case_fold, nfc};
    (volume.case_insensitive && case_fold(path) == case_fold(other))
        || (volume.normalization_insensitive && nfc(path) == nfc(other))
        || (volume.case_insensitive
            && volume.normalization_insensitive
            && canonical_fold(path) == canonical_fold(other))
}

#[cfg(test)]
mod volume_folding_tests {
    use super::volume_folds_together;
    use crate::local_convergence::types::VolumeFolding;

    const SENSITIVE: VolumeFolding =
        VolumeFolding { case_insensitive: false, normalization_insensitive: false };
    const CASE: VolumeFolding =
        VolumeFolding { case_insensitive: true, normalization_insensitive: false };

    #[test]
    fn a_case_sensitive_volume_folds_nothing_together() {
        assert!(!volume_folds_together(SENSITIVE, "Photo.jpg", "photo.jpg"));
    }

    #[test]
    fn a_case_insensitive_volume_folds_spellings_of_one_name_only() {
        assert!(volume_folds_together(CASE, "Photo.jpg", "photo.jpg"));
        assert!(!volume_folds_together(CASE, "Photo.jpg", "other.jpg"));
        assert!(!volume_folds_together(CASE, "a/Photo.jpg", "b/photo.jpg"));
    }
}

/// Starts the batch barrier of a window's unflushed files when the run that owns
/// the window ends without having started it (it was dropped mid-way).
struct FlushBarrierOnDrop {
    state: Arc<crate::replica_coordinator::ReplicaCoordinator>,
    window: Arc<super::completion_window::CompletionWindow>,
}

impl Drop for FlushBarrierOnDrop {
    fn drop(&mut self) {
        let Some(mode) = self.window.deferred_flush_mode() else { return };
        let pending = self.window.take_flush_pending();
        if pending.is_empty() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let state = self.state.clone();
        drop(runtime.spawn_blocking(move || {
            super::received_flush_barrier::run_flush_barrier(&state, pending, mode)
        }));
    }
}
