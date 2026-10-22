//! The shared
//! convergence-settling primitive that replaces every fixed-duration
//! settle sleep and hand-tuned gate constant.
//!
//! Before this module, scenarios either slept a fixed `FINAL_SETTLE`
//! before the terminal oracle (firing "looks like a violation, is really
//! mid-flight" false failures) or hand-rolled their own poll loop with a
//! hand-widened gate constant (the canonical loops of the retired two-device and
//! network-fault scenarios, `while... FINAL_CONVERGENCE_TIMEOUT`
//! loops, plus the `ROUND_PROGRESSION_GATE` 5s->45s archaeology). `settle`
//! polls the convergence oracle on the *simulated* clock and returns the
//! instant it observes convergence; on budget exhaustion it records a
//! `SlowConvergence` finding and returns, never failing or skipping the
//! run (the "visibility-not-suppression" discipline: production
//! has no N-seconds-or-fail gate, so neither does the harness -- the
//! terminal oracles still run against whatever the actual state is).
//!
//! `#![cfg(turmoil)]`-gated like every DST scenario file.

use std::path::Path;
use std::time::Duration;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;

use super::oracle::{GlobalOracle, Violation, ViolationKind};

/// How often the settle loop re-checks convergence on the simulated clock.
/// 50ms of virtual time between polls matches the canonical loops'
/// `tokio::time::sleep(Duration::from_millis(50))` cadence.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The result of a settle: whether convergence was observed, how much
/// *simulated* time it took, and -- only when the budget was exhausted
/// without convergence -- the `SlowConvergence` finding that must stay
/// visible in the run's output.
pub struct SettleOutcome {
    pub converged: bool,
    pub elapsed: Duration,
    /// `Some` iff `budget` elapsed without `converged` ever holding. A
    /// `SlowConvergence` finding, never a hard failure: the caller surfaces
    /// it (it is deliberately not folded into the fatal-violation list) and
    /// still runs the terminal oracles, which hard-fail on their own if the
    /// final state is genuinely divergent rather than merely slow.
    pub slow_convergence: Option<Violation>,
}

/// The general settle primitive: polls `converged` on the simulated clock
/// until it returns true or `budget` of simulated time elapses. Scenarios
/// whose convergence predicate is neither the flat nor the recursive
/// whole-directory oracle (e.g. a per-path version-vector equality gate
/// like `converge_path`) use this directly with their own closure.
pub async fn settle_until(budget: Duration, mut converged: impl FnMut() -> bool) -> SettleOutcome {
    let start = tokio::time::Instant::now();
    let deadline = start + budget;
    let mut is_converged = converged();
    while !is_converged && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(POLL_INTERVAL).await;
        is_converged = converged();
    }
    let elapsed = tokio::time::Instant::now().saturating_duration_since(start);
    let slow_convergence = if is_converged { None } else { Some(slow_finding(budget, elapsed)) };
    SettleOutcome { converged: is_converged, elapsed, slow_convergence }
}

/// Settle on the flat convergence oracle (`check_convergence`) reporting no
/// disagreement -- the direct replacement for the retired two-device and
/// network-fault scenarios' terminal `FINAL_CONVERGENCE_TIMEOUT`
/// loop.
pub async fn settle(
    devices: &[(&Path, &ReplicaCoordinator)],
    oracle: &GlobalOracle,
    budget: Duration,
) -> SettleOutcome {
    settle_until(budget, || oracle.check_convergence(devices).is_empty()).await
}

/// Settle on the recursive convergence oracle (`check_convergence_
/// recursive`) -- for scenarios with nested paths (`dst_directory_chaos`),
/// where the flat variant would ignore whole subtrees.
pub async fn settle_recursive(
    devices: &[(&Path, &ReplicaCoordinator)],
    oracle: &GlobalOracle,
    budget: Duration,
) -> SettleOutcome {
    settle_until(budget, || oracle.check_convergence_recursive(devices).is_empty()).await
}

fn slow_finding(budget: Duration, elapsed: Duration) -> Violation {
    Violation {
        kind: ViolationKind::SlowConvergence,
        path: None,
        content_ids: Vec::new(),
        devices: Vec::new(),
        detail: format!(
            "did not converge within the {budget:?} settle budget ({elapsed:?} of simulated \
             time elapsed); recorded as SlowConvergence and proceeding to the terminal oracles \
             against the actual final state rather than failing or skipping"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These drive the async primitive directly and never touch the network,
    // so they need nothing from the substrate but its clock: a 60s budget
    // has to resolve instantly, and `settle_until`'s whole subject is how it
    // spends one. `sim::block_on` supplies that on either substrate.

    #[test]
    fn settle_returns_as_soon_as_the_predicate_holds() {
        super::super::sim::block_on(1, || async {
            let mut polls = 0u32;
            let outcome = settle_until(Duration::from_secs(60), || {
                polls += 1;
                polls >= 3 // converges on the third poll
            })
            .await;
            assert!(outcome.converged);
            assert!(outcome.slow_convergence.is_none());
            // Converged well within budget, so far less than the full 60s elapsed.
            assert!(outcome.elapsed < Duration::from_secs(60));
        });
    }

    #[test]
    fn budget_exhaustion_records_slow_convergence_and_is_not_fatal() {
        super::super::sim::block_on(2, || async {
            let outcome = settle_until(Duration::from_secs(1), || false).await;
            assert!(!outcome.converged);
            let finding = outcome.slow_convergence.expect("budget exhausted -> SlowConvergence");
            assert_eq!(finding.kind, ViolationKind::SlowConvergence);
            assert!(outcome.elapsed >= Duration::from_secs(1));
        });
    }
}
