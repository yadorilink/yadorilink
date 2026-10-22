//! First-divergence
//! localization as a **standalone reducer**.
//!
//! The incremental-oracle observer is meant to ride a triage-replay leg (one
//! automatic same-seed replay, no cost on passing runs). The localization
//! logic is factored out here as a pure reducer that a replay hook feeds one
//! boolean sample per event boundary: "does the terminal violation's predicate
//! hold *now*?". Keeping it standalone means it is fully unit-testable without
//! a running simulation; a replay leg only has to call `observe`.
//!
//! It records the earliest simulated time at which the predicate first holds
//! and never subsequently clears (design's `first_observable`) — deliberately
//! an *observation* point, not a root-cause claim.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// The recorded first-observable divergence point (the design). `oracle_kind` is
/// the label of the terminal `ViolationKind` being localized (stored as a
/// string because `ViolationKind` is not `Serialize`; see
/// `bundle::violation_kind_label`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstDivergence {
    /// Simulated time (nanoseconds) at the event boundary where the violated
    /// condition first became continuously observable.
    pub sim_time_nanos: u64,
    /// Index of that event in the run's full event timeline — the center the
    /// bundle's timeline slice is taken around.
    pub event_index: usize,
    /// Label of the terminal oracle kind whose predicate this localizes.
    pub oracle_kind: String,
}

/// Incremental observer for one terminal oracle predicate over a single replay.
///
/// Fed one sample per event boundary via [`observe`](Self::observe); at the end
/// of the run [`finish`](Self::finish) returns the start of the *final*
/// continuous holding streak — the earliest point from which the predicate held
/// and never cleared again. A predicate that is not holding at end of run
/// yields `None` (nothing durably diverged).
#[derive(Debug)]
pub struct DivergenceObserver {
    oracle_kind: String,
    /// Start (sim_time, event_index) of the current uninterrupted holding
    /// streak, or `None` if the predicate is not currently holding.
    streak_start: Option<(u64, usize)>,
}

impl DivergenceObserver {
    pub fn new(oracle_kind: impl Into<String>) -> Self {
        Self { oracle_kind: oracle_kind.into(), streak_start: None }
    }

    /// Record whether the predicate holds at this event boundary. `sim_time_nanos`
    /// must be non-decreasing across calls (event boundaries advance sim time).
    pub fn observe(&mut self, event_index: usize, sim_time_nanos: u64, holds: bool) {
        match (holds, self.streak_start.is_some()) {
            // Rising edge (or first sample that holds): a new streak begins here.
            (true, false) => self.streak_start = Some((sim_time_nanos, event_index)),
            // Falling edge: the streak is broken; any earlier holding is not the
            // *final* one, so discard it.
            (false, _) => self.streak_start = None,
            // Still holding: keep the streak's original start.
            (true, true) => {}
        }
    }

    /// The first-observable point, if the predicate was holding at end of run.
    pub fn finish(self) -> Option<FirstDivergence> {
        self.streak_start.map(|(sim_time_nanos, event_index)| FirstDivergence {
            sim_time_nanos,
            event_index,
            oracle_kind: self.oracle_kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drives an observer over `(holds)` samples at event indices 0.. with
    /// sim_time = index*10, returning the localized divergence.
    fn localize(samples: &[bool]) -> Option<FirstDivergence> {
        let mut obs = DivergenceObserver::new("Convergence");
        for (i, &holds) in samples.iter().enumerate() {
            obs.observe(i, (i as u64) * 10, holds);
        }
        obs.finish()
    }

    #[test]
    fn localizes_the_first_hold_that_never_clears() {
        // Holds from index 3 to the end.
        let d = localize(&[false, false, false, true, true, true]).unwrap();
        assert_eq!(d.event_index, 3);
        assert_eq!(d.sim_time_nanos, 30);
        assert_eq!(d.oracle_kind, "Convergence");
    }

    #[test]
    fn a_cleared_streak_does_not_count_only_the_final_one_does() {
        // Holds at 2, clears at 4, holds again from 6 to end: answer is 6.
        let d = localize(&[false, false, true, true, false, false, true, true]).unwrap();
        assert_eq!(d.event_index, 6);
        assert_eq!(d.sim_time_nanos, 60);
    }

    #[test]
    fn never_holding_yields_no_divergence() {
        assert!(localize(&[false, false, false]).is_none());
    }

    #[test]
    fn holding_from_the_very_first_boundary() {
        let d = localize(&[true, true, true]).unwrap();
        assert_eq!(d.event_index, 0);
        assert_eq!(d.sim_time_nanos, 0);
    }

    #[test]
    fn a_single_late_hold_at_the_end_is_the_divergence() {
        let d = localize(&[false, true, false, false, true]).unwrap();
        assert_eq!(d.event_index, 4);
    }
}
