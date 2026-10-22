//! Greedy delta-debug
//! shrinker over the Case IR.
//!
//! An investigation should start from a *minimal* case, because case size is a
//! token-cost multiplier for an agent. After a `LikelyProductBug` triage, the
//! harness shrinks the failing case by deterministic delta-debugging within a
//! bounded replay budget (default ~50), keeping the best-so-far case on budget
//! exhaustion (the design).
//!
//! The shrinker is generic over a caller-supplied reproduce-check
//! (`FnMut(&Case) -> ReproOutcome`): the scenario wiring passes a closure that
//! re-runs the candidate under the same seed/harness and reports whether the
//! same violation still fires. Reproduction under simulation is exact by
//! construction, so a candidate that reproduces *nondeterministically
//! differently* is a harness-fidelity bug — the shrinker aborts and reports it
//!  rather than silently continuing.
//!
//! Shrink order (the design): drop trailing rounds → drop whole devices → drop
//! ops (binary-chunk then singles) → shrink fault windows → shrink content
//! table.

#![allow(dead_code)]

use std::collections::BTreeSet;

use super::case_ir::{Case, ContentTable, Op};
use super::triage::TriageVerdict;

pub const DEFAULT_SHRINK_BUDGET: usize = 50;

/// Result of one reproduce-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReproOutcome {
    /// The candidate still triggers the same violation.
    Reproduced,
    /// The candidate no longer triggers it (this shrink step went too far).
    NotReproduced,
    /// The replay disagreed with itself / with the deterministic expectation —
    /// a harness-fidelity signal; the shrinker aborts.
    Nondeterministic,
}

#[derive(Debug, Clone)]
pub struct ShrinkConfig {
    pub budget: usize,
}

impl Default for ShrinkConfig {
    fn default() -> Self {
        Self { budget: DEFAULT_SHRINK_BUDGET }
    }
}

#[derive(Debug)]
pub struct ShrinkResult {
    /// The smallest still-reproducing case found (== original if nothing shrank).
    pub case_min: Case,
    pub replays_used: usize,
    /// True if the replay budget ran out before a fixpoint.
    pub budget_exhausted: bool,
    /// True if a candidate replay was nondeterministic; shrinking stopped and
    /// `case_min` holds the best case proven up to that point.
    pub nondeterministic_abort: bool,
}

/// Whether a verdict warrants shrinking (the design: artifacts don't merit the
/// shrink cost). The call site gates on this before invoking [`shrink`].
pub fn should_shrink(verdict: &TriageVerdict) -> bool {
    verdict.is_product_bug()
}

/// Greedily shrink `original`, keeping the smallest case that still reproduces.
pub fn shrink(
    original: Case,
    mut reproduce: impl FnMut(&Case) -> ReproOutcome,
    config: ShrinkConfig,
) -> ShrinkResult {
    let mut driver = Driver {
        best: original,
        reproduce: &mut reproduce,
        remaining: config.budget,
        used: 0,
        aborted: false,
    };

    // Each pass mutates `driver.best` in place, accepting a candidate only when
    // it still reproduces. Passes run until no pass makes progress (fixpoint) or
    // budget/abort stops us.
    loop {
        // Non-short-circuit `|`: every pass runs each round (a later pass can
        // make progress even when an earlier one didn't).
        let progressed = driver.drop_trailing_rounds()
            | driver.drop_whole_devices()
            | driver.drop_ops()
            | driver.shrink_fault_windows()
            | driver.shrink_content_table();
        // Stop on abort, budget exhaustion, or a fixpoint (no pass shrank).
        if driver.aborted || driver.remaining == 0 || !progressed {
            break;
        }
    }

    ShrinkResult {
        case_min: driver.best,
        replays_used: driver.used,
        budget_exhausted: driver.remaining == 0,
        nondeterministic_abort: driver.aborted,
    }
}

struct Driver<'a> {
    best: Case,
    reproduce: &'a mut dyn FnMut(&Case) -> ReproOutcome,
    remaining: usize,
    used: usize,
    aborted: bool,
}

impl Driver<'_> {
    /// Test `candidate`; on `Reproduced`, adopt it as the new best and return
    /// true. Returns false on non-reproduction, budget exhaustion, or abort.
    fn accept_if_reproduces(&mut self, candidate: Case) -> bool {
        if self.remaining == 0 || self.aborted {
            return false;
        }
        self.remaining -= 1;
        self.used += 1;
        match (self.reproduce)(&candidate) {
            ReproOutcome::Reproduced => {
                self.best = candidate;
                true
            }
            ReproOutcome::NotReproduced => false,
            ReproOutcome::Nondeterministic => {
                self.aborted = true;
                false
            }
        }
    }

    /// Drop the highest-`virtual_ts` "round" (all ops sharing the max ts across
    /// every device), repeatedly, while it still reproduces.
    fn drop_trailing_rounds(&mut self) -> bool {
        let mut progressed = false;
        while !self.aborted && self.remaining > 0 {
            let Some(max_ts) = max_virtual_ts(&self.best) else { break };
            let mut candidate = self.best.clone();
            for tl in &mut candidate.workload {
                tl.ops.retain(|(ts, _)| *ts != max_ts);
            }
            if total_ops(&candidate) == total_ops(&self.best) {
                break; // nothing at max_ts to drop
            }
            if self.accept_if_reproduces(candidate) {
                progressed = true;
            } else {
                break;
            }
        }
        progressed
    }

    /// Drop the highest-index device (its timeline + topology link), keeping
    /// device indices contiguous, while it still reproduces.
    fn drop_whole_devices(&mut self) -> bool {
        let mut progressed = false;
        while !self.aborted && self.remaining > 0 && self.best.topology.device_count > 1 {
            let last = self.best.topology.device_count - 1;
            let mut candidate = self.best.clone();
            candidate.workload.retain(|tl| tl.device_index != last);
            if candidate.topology.links.len() == self.best.topology.device_count {
                candidate.topology.links.pop();
            }
            candidate.topology.device_count -= 1;
            if self.accept_if_reproduces(candidate) {
                progressed = true;
            } else {
                break;
            }
        }
        progressed
    }

    /// Drop ops: first in binary chunks (halving), then single ops. A flat
    /// index over `(device, op-position)` gives a stable order to bisect.
    fn drop_ops(&mut self) -> bool {
        let mut progressed = false;
        let mut chunk = total_ops(&self.best);
        while chunk >= 1 {
            let mut start = 0;
            loop {
                let n = total_ops(&self.best);
                if start >= n || self.aborted || self.remaining == 0 {
                    break;
                }
                let end = (start + chunk).min(n);
                let candidate = drop_op_range(&self.best, start, end);
                if self.accept_if_reproduces(candidate) {
                    progressed = true;
                    // best shrank; retry the same start against the new best.
                } else {
                    start += chunk;
                }
            }
            if chunk == 1 {
                break;
            }
            chunk /= 2;
        }
        progressed
    }

    /// Shrink the fault schedule by dropping faults (binary-chunk then singles).
    /// Usually a no-op: most cases carry no fault windows.
    fn shrink_fault_windows(&mut self) -> bool {
        let mut progressed = false;
        let mut chunk = self.best.fault_schedule.len();
        while chunk >= 1 {
            let mut start = 0;
            loop {
                let n = self.best.fault_schedule.len();
                if start >= n || self.aborted || self.remaining == 0 {
                    break;
                }
                let end = (start + chunk).min(n);
                let mut candidate = self.best.clone();
                candidate.fault_schedule.drain(start..end);
                if self.accept_if_reproduces(candidate) {
                    progressed = true;
                } else {
                    start += chunk;
                }
            }
            if chunk == 1 {
                break;
            }
            chunk /= 2;
        }
        progressed
    }

    /// Rebuild the content table keeping only ids still referenced by an op.
    /// One candidate (no replay budget spent if it changes nothing).
    fn shrink_content_table(&mut self) -> bool {
        let referenced = referenced_content_ids(&self.best);
        let current: BTreeSet<u64> = self.best.content_table.iter().map(|(id, _)| *id).collect();
        if current == referenced {
            return false; // already minimal
        }
        let mut pruned = ContentTable::default();
        for (id, bytes) in self.best.content_table.iter() {
            if referenced.contains(id) {
                pruned.insert(*id, bytes.clone());
            }
        }
        let mut candidate = self.best.clone();
        candidate.content_table = pruned;
        self.accept_if_reproduces(candidate)
    }
}

fn total_ops(case: &Case) -> usize {
    case.workload.iter().map(|tl| tl.ops.len()).sum()
}

fn max_virtual_ts(case: &Case) -> Option<u64> {
    case.workload.iter().flat_map(|tl| tl.ops.iter().map(|(ts, _)| *ts)).max()
}

/// Remove the ops in the flat `[start, end)` index range (ordered by device,
/// then op position within the device).
fn drop_op_range(case: &Case, start: usize, end: usize) -> Case {
    let mut candidate = case.clone();
    let mut flat = 0;
    for tl in &mut candidate.workload {
        let mut kept = Vec::with_capacity(tl.ops.len());
        for op in tl.ops.drain(..) {
            let drop = flat >= start && flat < end;
            flat += 1;
            if !drop {
                kept.push(op);
            }
        }
        tl.ops = kept;
    }
    candidate
}

fn referenced_content_ids(case: &Case) -> BTreeSet<u64> {
    let mut ids = BTreeSet::new();
    for tl in &case.workload {
        for (_, op) in &tl.ops {
            match op {
                Op::Write { content_id, .. } | Op::Edit { content_id, .. } => {
                    ids.insert(*content_id);
                }
                _ => {}
            }
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::super::case_ir::{DeviceTimeline, FaultPlan, LinkTopology, Topology};
    use super::*;

    /// Build a case with `device_count` devices; device 0 gets `ops`, and the
    /// content table maps each referenced id plus some extras.
    fn seeded_case(device_count: usize, ops: Vec<(u64, Op)>) -> Case {
        let mut content_table = ContentTable::default();
        for id in 0..10u64 {
            content_table.insert(id, format!("content {id}").into_bytes());
        }
        Case {
            seed: 123,
            topology: Topology {
                device_count,
                links: (0..device_count)
                    .map(|_| LinkTopology { group_id: "g".into(), initial_online: true })
                    .collect(),
            },
            workload: (0..device_count)
                .map(|d| DeviceTimeline {
                    device_index: d,
                    ops: if d == 0 { ops.clone() } else { Vec::new() },
                })
                .collect(),
            fault_schedule: Vec::new(),
            content_table,
            fault_plan: FaultPlan::default(),
            history_steps: Vec::new(),
        }
    }

    /// The "injected violation": the case reproduces iff it still contains a
    /// Write to `poison.bin`. Everything else is noise the shrinker should peel.
    fn reproduces_iff_poison(case: &Case) -> ReproOutcome {
        let has_poison = case.workload.iter().any(|tl| {
            tl.ops
                .iter()
                .any(|(_, op)| matches!(op, Op::Write { path, .. } if path == "poison.bin"))
        });
        if has_poison {
            ReproOutcome::Reproduced
        } else {
            ReproOutcome::NotReproduced
        }
    }

    #[test]
    fn shrinks_to_the_minimal_reproducing_case() {
        // 20 noise ops surrounding one poison write across several rounds.
        let mut ops: Vec<(u64, Op)> = (0..10)
            .map(|i| (i, Op::Write { path: format!("noise-{i}.bin"), content_id: i % 10 }))
            .collect();
        ops.push((10, Op::Write { path: "poison.bin".into(), content_id: 1 }));
        ops.extend(
            (11..21).map(|i| (i, Op::Write { path: format!("noise-{i}.bin"), content_id: i % 10 })),
        );
        let original = seeded_case(3, ops);
        let original_ops = total_ops(&original);

        let result = shrink(original, reproduces_iff_poison, ShrinkConfig::default());

        assert!(!result.nondeterministic_abort);
        // Still reproduces.
        assert_eq!(reproduces_iff_poison(&result.case_min), ReproOutcome::Reproduced);
        // Substantially smaller: only the poison op should remain.
        assert!(
            total_ops(&result.case_min) < original_ops,
            "expected shrink, got {} of {original_ops} ops",
            total_ops(&result.case_min)
        );
        assert_eq!(total_ops(&result.case_min), 1, "should peel down to the single poison op");
        // Devices with no bearing on the violation are dropped.
        assert_eq!(result.case_min.topology.device_count, 1);
        // Content table pruned to referenced ids only (id 1, used by poison).
        let ids: Vec<u64> = result.case_min.content_table.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![1]);
    }

    #[test]
    fn aborts_and_reports_on_nondeterministic_replay() {
        let ops = vec![
            (0, Op::Write { path: "poison.bin".into(), content_id: 1 }),
            (1, Op::Write { path: "noise.bin".into(), content_id: 2 }),
        ];
        let original = seeded_case(1, ops);

        // A reproduce-check that flips to Nondeterministic on the first
        // candidate it sees (any shrink attempt).
        let mut seen = 0;
        let result = shrink(
            original,
            |_case| {
                seen += 1;
                ReproOutcome::Nondeterministic
            },
            ShrinkConfig::default(),
        );
        assert!(result.nondeterministic_abort);
        assert!(result.replays_used >= 1);
    }

    #[test]
    fn respects_the_replay_budget() {
        // A case that always reproduces and is large, with a tiny budget: the
        // shrinker must stop at the budget and report exhaustion, keeping the
        // best case proven so far.
        let ops: Vec<(u64, Op)> = (0..50)
            .map(|i| (i, Op::Write { path: "poison.bin".into(), content_id: i % 10 }))
            .collect();
        let original = seeded_case(4, ops);
        let result = shrink(
            original,
            |_case| ReproOutcome::Reproduced, // everything "reproduces"
            ShrinkConfig { budget: 5 },
        );
        assert!(result.budget_exhausted);
        assert!(result.replays_used <= 5);
    }
}
