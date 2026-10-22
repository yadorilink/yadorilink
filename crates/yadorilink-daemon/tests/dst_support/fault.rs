//! The intercepting network-fault decorator. Network faults were a manual
//! `outbound_partitioned: AtomicBool`
//! (`dst_intermittent_catchup_chaos.rs`) -- no
//! drop/delay/reorder/duplicate, which both under-tests the product and
//! forces artificial scenario shapes. `FaultingChannel` wraps the outbound
//! channel seam and applies a deterministic, seed-driven `FaultPlan`
//! (`case_ir::FaultPlan`) scheduled on the simulated clock: drop,
//! duplicate, delay (whence reorder), and partition/heal windows, all
//! reproducible from the serialized plan so a recorded corpus case replays
//! with identical network behavior. This module is the decorator's
//! *decision engine* -- pure, synchronous, and fully unit-testable without
//! a live session: given the next outbound message's simulated timestamp
//! it returns what should happen to it. The caller (a migrated scenario's
//! send path, or a soak run's fault injector) wraps its actual channel
//! `send` around `decide`. `#![cfg(turmoil)]`-gated like every DST scenario
//! file.

use super::case_ir::FaultPlan;
use super::fault_schedule::{FaultClass, ScheduledInjectors};

/// What should happen to one outbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultDecision {
    /// Deliver the message now, unmodified.
    Deliver,
    /// Deliver the message now, then deliver one identical duplicate.
    Duplicate,
    /// Deliver the message after `nanos` of simulated time. Heterogeneous
    /// delays are how reorder manifests: a delayed message lands after
    /// later, undelayed ones.
    Delay { nanos: i64 },
    /// Drop the message entirely (lost in transit, or partitioned).
    Drop,
}

/// Applies a `FaultPlan` to a stream of outbound messages deterministically.
/// One instance per decorated channel direction; `decide` is called once
/// per outbound message in send order.
pub struct FaultingChannel {
    plan: FaultPlan,
    /// 1-based count of messages presented to `decide` so far. The plan's
    /// "every Nth" rules key off this, so the same message ordinal always
    /// gets the same treatment -- the property that makes a replay exact.
    seq: u64,
    /// The scheduled injectors this channel reads its live plan from and
    /// credits at decision time. `None` for a fixed-plan channel, which
    /// credits nothing.
    seam: Option<ScheduledInjectors>,
}

impl FaultingChannel {
    /// A fixed-plan channel. It reports to no ledger, so a gated test that
    /// uses it earns no credit: use [`scheduled`](Self::scheduled).
    pub fn new(plan: FaultPlan) -> Self {
        Self { plan, seq: 0, seam: None }
    }

    /// A channel bound to the scheduler's live plan. Each `decide` reads the
    /// plan the schedule has open at that moment and credits the ledger entry
    /// whose window is open at that moment: the credit comes from here, the
    /// injection seam, never from the caller.
    pub fn scheduled(injectors: &ScheduledInjectors) -> Self {
        Self { plan: injectors.net_plan(), seq: 0, seam: Some(injectors.clone()) }
    }

    /// True if `now_nanos` falls in any half-open `[start, end)` partition
    /// window -- the reproducible replacement for `outbound_partitioned`.
    pub fn partitioned_at(&self, now_nanos: i64) -> bool {
        self.plan
            .partition_windows
            .iter()
            .any(|&(start, end)| now_nanos >= start && now_nanos < end)
    }

    /// Decides the fate of the next outbound message, presented at simulated
    /// time `now_nanos`, and advances the message counter. Precedence:
    /// partition (a cut link drops everything) > scheduled drop > duplicate
    /// > delay > deliver.
    pub fn decide(&mut self, now_nanos: i64) -> FaultDecision {
        if let Some(seam) = &self.seam {
            self.plan = seam.net_plan();
        }
        self.seq += 1;
        let (decision, class) = self.decide_classified(now_nanos);
        if let (Some(seam), Some(class)) = (&self.seam, class) {
            seam.credit(class);
        }
        decision
    }

    fn decide_classified(&self, now_nanos: i64) -> (FaultDecision, Option<FaultClass>) {
        let n = self.seq;
        if self.partitioned_at(now_nanos) {
            return (FaultDecision::Drop, Some(FaultClass::NetPartition));
        }
        if hits(self.plan.drop_every, n) {
            return (FaultDecision::Drop, Some(FaultClass::NetDrop));
        }
        if hits(self.plan.duplicate_every, n) {
            return (FaultDecision::Duplicate, Some(FaultClass::NetDuplicate));
        }
        if hits(self.plan.delay_every, n) {
            return (
                FaultDecision::Delay { nanos: self.plan.delay_nanos },
                Some(FaultClass::NetDelay),
            );
        }
        (FaultDecision::Deliver, None)
    }
}

fn hits(every: u32, n: u64) -> bool {
    every != 0 && n % every as u64 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drops_and_dups() -> FaultPlan {
        FaultPlan {
            partition_windows: Vec::new(),
            drop_every: 3,
            duplicate_every: 2,
            delay_every: 0,
            delay_nanos: 0,
        }
    }

    #[test]
    fn every_nth_rules_apply_by_message_ordinal() {
        let mut ch = FaultingChannel::new(drops_and_dups());
        // n=1: nothing -> Deliver; n=2: duplicate; n=3: drop (drop wins over
        // dup since 3%2!=0 anyway); n=4: duplicate; n=6: drop (and 6%2==0,
        // but drop has precedence).
        assert_eq!(ch.decide(0), FaultDecision::Deliver);
        assert_eq!(ch.decide(0), FaultDecision::Duplicate);
        assert_eq!(ch.decide(0), FaultDecision::Drop);
        assert_eq!(ch.decide(0), FaultDecision::Duplicate);
        assert_eq!(ch.decide(0), FaultDecision::Deliver); // n=5
        assert_eq!(ch.decide(0), FaultDecision::Drop); // n=6: drop precedence over dup
    }

    #[test]
    fn partition_window_drops_everything_inside_it_and_nothing_outside() {
        let plan = FaultPlan { partition_windows: vec![(1_000, 2_000)], ..FaultPlan::default() };
        let mut ch = FaultingChannel::new(plan);
        assert_eq!(ch.decide(999), FaultDecision::Deliver); // before the cut
        assert_eq!(ch.decide(1_000), FaultDecision::Drop); // window start (inclusive)
        assert_eq!(ch.decide(1_999), FaultDecision::Drop); // inside
        assert_eq!(ch.decide(2_000), FaultDecision::Deliver); // healed (end exclusive)
    }

    #[test]
    fn delay_carries_the_plans_delay_nanos() {
        let plan = FaultPlan { delay_every: 1, delay_nanos: 500, ..FaultPlan::default() };
        let mut ch = FaultingChannel::new(plan);
        assert_eq!(ch.decide(0), FaultDecision::Delay { nanos: 500 });
    }

    #[test]
    fn the_same_plan_replays_an_identical_decision_sequence() {
        let plan = FaultPlan {
            partition_windows: vec![(10, 20)],
            drop_every: 4,
            duplicate_every: 3,
            delay_every: 5,
            delay_nanos: 100,
        };
        let times = [0i64, 5, 15, 25, 30, 40, 45, 50];
        let run = |plan: FaultPlan| {
            let mut ch = FaultingChannel::new(plan);
            times.iter().map(|&t| ch.decide(t)).collect::<Vec<_>>()
        };
        assert_eq!(run(plan.clone()), run(plan), "the same FaultPlan must replay identically");
    }

    #[test]
    fn fault_plan_round_trips_through_json() {
        let plan = FaultPlan {
            partition_windows: vec![(1, 2), (5, 9)],
            drop_every: 7,
            duplicate_every: 0,
            delay_every: 2,
            delay_nanos: 250,
        };
        let json = serde_json::to_string(&plan).unwrap();
        let restored: FaultPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, restored);
    }
}
