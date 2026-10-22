//! The Convergence Engine stand-in every DST harness MUST run. A harness
//! without this driver silently stops materializing anything an admitted
//! change carries, so its scenarios report green/skip while exercising
//! nothing (a stalled startup canary, not a transport hang, is the symptom).
//! Centralized here so new harnesses import
//! one canonical driver instead of hand-rolling (or forgetting) it. One
//! driver per DEVICE, handed every session of that device, explicitly
//! round-robining them: an audit block-fetches only through the session it
//! ran on, and multiple per-session drivers racing one per-state wake with
//! the audit guard admitting a single winner would let a deterministic
//! scheduler pin a device's fetches to one peer forever (the daemon
//! rotates candidates with an explicit cursor for exactly this reason).
//! With a single session the round-robin degenerates to the old
//! per-session behavior.

use std::sync::{Arc, Weak};
use std::time::Duration;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_daemon::test_support::peer_session_fixture::TestPeerRuntime;

/// Fallback poll cadence when no materialization wake arrives — the same
/// value the migrated scenarios have always used.
pub const MATERIALIZATION_FALLBACK: Duration = Duration::from_millis(100);

/// Takes the session/executor *pair* rather than a bare session: the audit
/// moved off `PeerSyncSession` onto the local convergence executor, which
/// reaches back through the session only for blocks it cannot find on disk.
/// `TestPeerRuntime` is the daemon's own name for that pair, so a scenario
/// that builds its devices the way every other integration test does has
/// one to hand and never assembles a mismatched half.
pub fn spawn_convergence_driver(
    state: Arc<ReplicaCoordinator>,
    runtimes: Vec<Weak<TestPeerRuntime>>,
    group_ids: Vec<String>,
) {
    assert!(!runtimes.is_empty(), "a convergence driver needs at least one session");
    tokio::spawn(async move {
        let mut next = 0usize;
        loop {
            let Some(runtime) = runtimes[next % runtimes.len()].upgrade() else { return };
            next += 1;
            for group_id in &group_ids {
                let _ = runtime
                    .convergence
                    .clone()
                    .reconcile_local_materialization_audit(&runtime.driver(), group_id)
                    .await;
            }
            drop(runtime);
            tokio::select! {
                _ = state.materialization_wake().materialization_wake_notified() => {}
                _ = tokio::time::sleep(MATERIALIZATION_FALLBACK) => {}
            }
        }
    });
}
