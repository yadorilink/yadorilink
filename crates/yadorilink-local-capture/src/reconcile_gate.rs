//! Per-group single-flight for reconciliation passes.
//!
//! # The failure this exists to make impossible
//!
//! A reconciliation pass reads the group's whole index once
//! (`existing_by_path`), walks the folder deciding every path against that
//! snapshot, and only then commits. Nothing serialized two passes, and this
//! device has three independent things that start one: the link's startup
//! scan, the live `RescanRequired` rescan, and the 90-second periodic
//! disk-reconcile backstop.
//!
//! When two of them overlap, both snapshot the same index and both reach
//! the commit believing the same paths are unindexed:
//!
//! ```text
//! pass A: snapshot (index empty) ── walk ── author 10k Changes
//! pass B: snapshot (index empty) ──── walk ──── author the SAME 10k again
//! ```
//!
//! The second pass's `PreparedMutation`s are stale by the time they commit,
//! but nothing re-reads the index to notice, so every path gets a second
//! signed change carrying a byte-identical version. That is not a wasted
//! scan — it is permanent garbage in the history every peer must fetch,
//! verify and store. Observed on a real 10k import whose block phase ran
//! 113s, long enough for one backstop tick to land inside it: 20,000 `files`
//! rows over 10,000 paths, 20 changes where 10 were due, each path appearing
//! in two adjacent lamports.
//!
//! # What this does instead
//!
//! One pass per group at a time. A request arriving while a pass is running
//! does NOT wait and does NOT start a second pass — it marks a rerun, and
//! the running pass performs it itself when it finishes, taking a fresh
//! snapshot:
//!
//! ```text
//! pass running ── finishes ── rerun (fresh snapshot) ── done
//!      ↑              ↑
//! request ───────────┘  (coalesced, at most one rerun however many arrive)
//! ```
//!
//! So two passes never hold the same snapshot, and a request that arrives
//! mid-pass is still answered by a pass that started after it — which is
//! what the requester actually needs. The rerun is capped at one per
//! invocation: further requests arriving during the rerun re-arm the flag
//! for the next caller rather than extending this one indefinitely, and the
//! backstop's own timer guarantees there will be a next caller.
//!
//! # Mode is merged, never downgraded
//!
//! Coalescing an add-only backstop request into a full pass is free (full
//! strictly includes it). The reverse is not: running a coalesced full
//! request as an add-only rerun would silently drop the tombstone
//! reconciliation the requester asked for. [`PendingRerun`] therefore
//! merges toward the stronger mode, and merges `emit_tombstones` toward
//! `false` — that flag means "this boot's materialization repair succeeded,
//! so a missing file can be told apart from a crash", and when two
//! requesters disagree the fail-closed answer is the only safe one.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::local_change::ReconcileMode;

/// The reconcile a running pass owes once it finishes, merged across every
/// request that arrived while it was running.
#[derive(Clone, Copy, Debug)]
struct PendingRerun {
    /// Any coalesced request wanted a full reconcile.
    full: bool,
    /// Meaningful only when `full`. Starts `true` at the first full request
    /// and can only ever be pulled down to `false`.
    emit_tombstones: bool,
}

impl PendingRerun {
    fn merge(&mut self, mode: ReconcileMode) {
        match mode {
            ReconcileMode::Full { emit_tombstones } => {
                if self.full {
                    self.emit_tombstones &= emit_tombstones;
                } else {
                    self.full = true;
                    self.emit_tombstones = emit_tombstones;
                }
            }
            ReconcileMode::AddOnly => {}
        }
    }

    fn mode(self) -> ReconcileMode {
        if self.full {
            ReconcileMode::Full { emit_tombstones: self.emit_tombstones }
        } else {
            ReconcileMode::AddOnly
        }
    }
}

#[derive(Default)]
struct GroupGate {
    running: bool,
    pending: Option<PendingRerun>,
}

/// One per `LocalChangeProcessor`, which is one per link — the same
/// `Arc<LocalChangeProcessor>` the startup executor, the live flush loop and
/// the periodic backstop all hold, so all three contend on this one gate.
#[derive(Default)]
pub(crate) struct ReconcileGate {
    groups: Mutex<HashMap<String, GroupGate>>,
}

/// Held for exactly as long as a pass (and its coalesced rerun) is running.
/// Clearing `running` on `Drop` rather than at a return means an aborted
/// pass — a `?` on a disk error, a panic unwinding through the scan — frees
/// the gate instead of wedging the group's reconciles for the process's
/// lifetime.
pub(crate) struct ReconcilePass<'a> {
    gate: &'a ReconcileGate,
    group_id: String,
}

impl ReconcileGate {
    /// Claims the right to run a pass for `group_id`, or `None` when one is
    /// already running — in which case `mode` has been merged into the
    /// rerun that pass will perform.
    pub(crate) fn try_enter(
        &self,
        group_id: &str,
        mode: ReconcileMode,
    ) -> Option<ReconcilePass<'_>> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let gate = groups.entry(group_id.to_string()).or_default();
        if gate.running {
            let pending =
                gate.pending.get_or_insert(PendingRerun { full: false, emit_tombstones: true });
            pending.merge(mode);
            return None;
        }
        gate.running = true;
        Some(ReconcilePass { gate: self, group_id: group_id.to_string() })
    }

    /// Takes the coalesced rerun, if any request arrived during the pass.
    /// Clearing it here (rather than after the rerun) is what caps this
    /// invocation at one extra pass: a request landing during the rerun
    /// re-arms the flag for whoever calls next.
    pub(crate) fn take_rerun(&self, group_id: &str) -> Option<ReconcileMode> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        groups.get_mut(group_id)?.pending.take().map(PendingRerun::mode)
    }
}

impl Drop for ReconcilePass<'_> {
    fn drop(&mut self) {
        let mut groups = self.gate.groups.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(gate) = groups.get_mut(&self.group_id) {
            gate.running = false;
        }
    }
}

#[cfg(test)]
mod tests;
