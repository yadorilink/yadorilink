//! Per-group startup-readiness barrier.
//!
//! A group whose filesystem watcher was just (re)started has NOT yet
//! finished reconciling its on-disk state against the index — the startup
//! disk scan reads an old whole-index snapshot and batch-commits records
//! derived from it *without* holding each path's `path_lock`. An incoming
//! peer change applied for the same path in that window (which DOES take
//! `path_lock`) would then be silently clobbered when the scan commits its
//! stale-snapshot record, turning what should be a concurrent conflict into
//! a last-writer overwrite. This gate lets peer-apply (and any other
//! post-startup mutator) wait until the group's startup reconciliation has
//! published its results before touching that group's paths. It is
//! per-group: a slow startup for one group never blocks peer apply for an
//! unrelated, already-ready group.
//!
//! The gate is a small generational 3-state machine rather than a plain
//! ready flag. Each startup attempt for a group gets a monotonic
//! [`StartupGeneration`]; the gate tracks the *latest* generation and its
//! phase (`Starting` / `Ready` / `Failed`). Two properties fall out of this:
//!   - A startup that does NOT complete (panic, task abort, error)
//!     transitions the gate to `Failed`, so peer apply fails *closed*
//!     (deferred) instead of being admitted over the half-built index — a
//!     startup crash can no longer silently open the gate and let peer
//!     changes overwrite un-indexed or un-redriven local state.
//!   - A completion is honored only when it carries the group's *current*
//!     generation, so a stale straggler (an aborted/unlinked old executor,
//!     or an earlier overlapping startup) can neither open nor fail a newer
//!     startup's barrier.
//!
//! This registry owns only the in-memory gate map and its notify-based
//! wait/wake logic. Deciding what an *absent* gate means for a given group
//! (no link on this device at all, vs. a live link whose startup never got
//! off the ground) requires reading the link table, which is SQL-backed and
//! stays on the caller (`SyncState::wait_group_ready`) rather than being
//! pulled into this in-memory-only registry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub use yadorilink_replica_domain::session_state::StartupFailed;

/// Per-`group_id` startup-readiness barriers (see `GroupStartupGate`).
/// Absent entry = never entered startup, treated as ready. A `std::sync`
/// map holding `Arc`s of the gate; the async wait happens on the cloned
/// `Arc`'s `Notify`, never while this registry lock is held.
pub struct StartupReadinessRegistry {
    gates: Mutex<HashMap<String, Arc<GroupStartupGate>>>,
}

struct GroupStartupGate {
    inner: std::sync::Mutex<GroupStartupState>,
    notify: tokio::sync::Notify,
}

struct GroupStartupState {
    /// Monotonic per-group startup generation. Each `begin_group_startup`
    /// bumps it, so a completion carrying an older generation is a stale
    /// straggler and is ignored.
    generation: u64,
    phase: GroupStartupPhase,
}

/// The phase of a group's most-recent startup generation.
enum GroupStartupPhase {
    /// Startup reconciliation for the current generation is in progress; peer
    /// apply parks.
    Starting,
    /// Startup reconciliation published its results; peer apply may proceed.
    Ready,
    /// Startup did not complete (panic, abort, or error). Peer apply is refused
    /// (fail-closed) rather than admitted over a half-built index, until a
    /// fresh `begin_group_startup` supersedes this generation and re-runs
    /// startup. The `String` is a human-readable reason for observability.
    Failed(String),
}

/// Identifies one startup attempt for a group. Returned by
/// [`StartupReadinessRegistry::begin_group_startup`] and presented back to
/// [`StartupReadinessRegistry::mark_group_ready`] /
/// [`StartupReadinessRegistry::mark_group_failed`], which ignore it unless
/// it is still the group's latest generation — so a stale completion from a
/// superseded (unlinked / aborted / relinked / overlapping) startup can
/// never open or fail a newer startup's barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupGeneration(u64);

impl Default for StartupReadinessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupReadinessRegistry {
    pub fn new() -> Self {
        Self { gates: Mutex::new(HashMap::new()) }
    }

    fn gate(&self, group_id: &str) -> Option<Arc<GroupStartupGate>> {
        self.gates.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(group_id).cloned()
    }

    /// Opens a fresh startup generation for `group_id`: bumps the group's
    /// monotonic generation and (re-)closes its gate to `Starting`, returning
    /// the new [`StartupGeneration`]. Call this *synchronously*, before spawning
    /// the group's startup/scan task and before any peer session that could
    /// apply a change for the group can run, so the closed gate is observed by
    /// every peer-apply path.
    ///
    /// Re-entry (a re-link, a watcher restart, or a startup retry) *supersedes*
    /// any prior generation — including a `Failed` one — with a new `Starting`
    /// generation. This is the recovery trigger: it clears a previous failure
    /// and re-runs startup, so a `Failed` gate never wedges peer apply forever.
    /// Any straggling completion from the superseded generation is thereafter a
    /// no-op (see `mark_group_ready` / `mark_group_failed`).
    pub fn begin_group_startup(&self, group_id: &str) -> StartupGeneration {
        let mut gates = self.gates.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match gates.get(group_id) {
            Some(gate) => {
                let mut state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
                state.generation += 1;
                state.phase = GroupStartupPhase::Starting;
                StartupGeneration(state.generation)
            }
            None => {
                gates.insert(
                    group_id.to_string(),
                    Arc::new(GroupStartupGate {
                        inner: std::sync::Mutex::new(GroupStartupState {
                            generation: 0,
                            phase: GroupStartupPhase::Starting,
                        }),
                        notify: tokio::sync::Notify::new(),
                    }),
                );
                StartupGeneration(0)
            }
        }
    }

    /// Opens `group_id`'s startup gate for `generation` and wakes every waiter.
    /// Called once the group's startup reconciliation (disk scan, initial
    /// import, dirty-journal redrive) has committed its results, so peer apply
    /// for the group may now proceed against an up-to-date index.
    ///
    /// A **no-op unless `generation` is still the group's latest**: a stale
    /// completion from a superseded startup (an aborted/unlinked old executor,
    /// or an earlier overlapping startup) must never open a newer generation's
    /// barrier. Also a no-op for a group that never entered startup.
    pub fn mark_group_ready(&self, group_id: &str, generation: StartupGeneration) {
        if let Some(gate) = self.gate(group_id) {
            let mut state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
            if state.generation != generation.0 {
                return;
            }
            state.phase = GroupStartupPhase::Ready;
            drop(state);
            gate.notify.notify_waiters();
        }
    }

    /// Records that `group_id`'s startup for `generation` did NOT complete
    /// (panic, task abort, or error): transitions the gate to `Failed` and
    /// wakes waiters, which then fail *closed* with [`StartupFailed`] rather
    /// than being admitted over the half-built index the failed startup left
    /// behind.
    ///
    /// Like `mark_group_ready`, a **no-op unless `generation` is still the
    /// group's latest** — so a stale abort's guard-drop cannot fail a newer
    /// generation. Recovery is a subsequent `begin_group_startup`, which
    /// supersedes the failure with a fresh `Starting` generation and re-runs
    /// startup. Local edits are unaffected: they live in the index and the
    /// dirty-path journal, independent of this gate, so a failure only *defers*
    /// peer apply, it never drops a local change.
    pub fn mark_group_failed(
        &self,
        group_id: &str,
        generation: StartupGeneration,
        reason: impl Into<String>,
    ) {
        if let Some(gate) = self.gate(group_id) {
            let mut state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
            if state.generation != generation.0 {
                return;
            }
            state.phase = GroupStartupPhase::Failed(reason.into());
            drop(state);
            gate.notify.notify_waiters();
        }
    }

    /// Whether `group_id`'s latest startup generation is still running, read
    /// without parking. `false` for a group that never entered startup (no
    /// gate, nothing in flight) and for one that has settled either way
    /// (`Ready` or `Failed`).
    ///
    /// Peer apply gates on `wait_group_ready` (polled once by
    /// `startup_admits_peer_apply`, so it defers rather than parks). This
    /// exists for
    /// periodic background repair passes, which have no useful notion of
    /// waiting: a repair that fires while startup is still building the index
    /// is not merely early, it races the one-shot work startup is in the
    /// middle of doing (see `DaemonState::backfill_missing_change_history`).
    pub fn group_startup_in_progress(&self, group_id: &str) -> bool {
        let Some(gate) = self.gate(group_id) else { return false };
        let state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
        matches!(state.phase, GroupStartupPhase::Starting)
    }

    /// Whether `group_id`'s latest startup generation has completed successfully, read without
    /// parking. `false` while it is running, after it failed, and for a group with no gate.
    pub fn group_startup_ready(&self, group_id: &str) -> bool {
        let Some(gate) = self.gate(group_id) else { return false };
        let state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
        matches!(state.phase, GroupStartupPhase::Ready)
    }

    /// Awaits `group_id`'s startup gate, if one is registered. Returns
    /// `None` when no gate exists for the group at all — the caller must
    /// then decide what an absent gate means (a group with no link on this
    /// device at all vs. a live link whose startup never got off the
    /// ground), which requires a SQL lookup this in-memory-only registry
    /// deliberately does not perform itself.
    ///
    /// Holds no lock while parked (the registry lock is released before
    /// awaiting), and must be called *before* acquiring any `path_lock`, so
    /// it can never deadlock against the startup writer.
    pub async fn wait_group_ready(&self, group_id: &str) -> Option<Result<(), StartupFailed>> {
        let gate = self.gate(group_id)?;
        loop {
            // Arm the notification *before* reading state so a mark that lands
            // between the read and the await is not lost (Notify's documented
            // lost-wakeup-free pattern).
            let notified = gate.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
                match &state.phase {
                    GroupStartupPhase::Ready => return Some(Ok(())),
                    GroupStartupPhase::Failed(reason) => {
                        return Some(Err(StartupFailed {
                            group_id: group_id.to_string(),
                            reason: reason.clone(),
                        }));
                    }
                    GroupStartupPhase::Starting => {}
                }
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests;
