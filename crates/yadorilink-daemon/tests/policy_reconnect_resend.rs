//! Proves an ordinary coordination-plane reconnect does not lock a group out
//! of both local emission and remote admission.
//!
//! The coordination plane's policy-send watermark is PER CONNECTION: a fresh
//! netmap subscription starts it empty, so the first frame on that connection
//! carries each shared group's signed policy chain from record 1 rather than
//! the incremental tail an already-established connection sends. The daemon's
//! own verified `GroupPolicyState`, by contrast, is persistent and
//! connection-independent -- it survives the reconnect untouched.
//!
//! `peer_orchestrator::record_group_policy_states` has to recognize that
//! combination. `change_policy::verify_group_policy_log_with_base` has zero
//! prefix tolerance (it requires the first record to be exactly
//! `base.current_seq + 1`), so verifying a from-record-1 resend against the
//! retained base reports a spurious sequence gap on a chain that has not
//! changed at all -- and a group whose policy snapshot "fails verification" is
//! marked stale, which resolves it to `Withhold`: no local edit can be
//! emitted for it and no peer Change can be admitted into it. Nothing on that
//! same connection re-verifies it afterwards, so the lockout persists.
//!
//! This test drives a real daemon against a real (fake-backed) WebSocket
//! netmap subscription, closes that socket from the server side exactly as a
//! coordination restart or idle timeout would, and asserts the group is still
//! `Verified` and NOT stale after the reconnect frame lands -- with no role or
//! policy change anywhere in the scenario, and in one round trip.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::change_policy::WriterRole;
use yadorilink_daemon::daemon_state::{DaemonState, GroupPolicyResolution};
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

fn new_test_daemon(device_id: &str) -> Arc<DaemonState> {
    let store_dir = tempfile::tempdir().unwrap();
    // Leaked deliberately: the block store must outlive the test; the process
    // tears the temp dir down on exit.
    let store = Arc::new(SegmentBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new(device_id.to_string(), sync_state, store)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_netmap_reconnects_full_policy_resend_keeps_the_group_verified() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_id = "device-policy-reconnect";
    let peer_id = "device-policy-reconnect-peer";
    let group_id = "group-policy-reconnect";

    let state = new_test_daemon(device_id);
    let root = tempfile::tempdir().unwrap();

    register_with_fake(&fake, &state, device_id, &[group_id]).await;
    // A second member so the netmap frame for this device is non-empty and
    // this group is genuinely "introduced" the way a real shared group is.
    // Its own daemon is never started -- this test is about one device's
    // policy verification across its own reconnect, not about peer sync.
    let peer_state = new_test_daemon(peer_id);
    register_with_fake(&fake, &peer_state, peer_id, &[group_id]).await;
    fake.grant_role(device_id, group_id, WriterRole::Editor);
    fake.grant_role(peer_id, group_id, WriterRole::Editor);

    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();

    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr: fake.addr(),
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id: device_id.to_string(),
    };
    let orchestrator_state = state.clone();
    tokio::spawn(async move {
        let _ = peer_orchestrator::run(config, orchestrator_state).await;
    });

    // The pre-condition: this device really has verified the whole chain on
    // its FIRST connection, so its cached base sits at the chain's head.
    wait_until(
        || {
            state
                .authority
                .group_policy_state(group_id)
                .map(|policy| policy.current_seq >= 2)
                .unwrap_or(false)
        },
        Duration::from_secs(30),
    )
    .await;
    assert!(
        !state.authority.is_group_policy_stale(group_id),
        "the group must not be stale before the reconnect -- otherwise this scenario proves nothing"
    );

    // Close the socket from the server side. Nothing about the group's policy
    // changes: the same two grant records, the same head, the same authority.
    let frames_before = fake.netmap_frames_built(device_id);
    assert!(
        wait_until_dropped(&fake, device_id).await,
        "the device must have a live netmap subscription to close"
    );

    // Wait for the reconnect to actually be served a frame, rather than
    // assuming enough wall-clock time has passed for one. This is the frame
    // that carries the group's chain from record 1 again while the daemon
    // still holds its verified base at seq 2.
    wait_until(|| fake.netmap_frames_built(device_id) > frames_before, Duration::from_secs(30))
        .await;

    // Let the daemon process that frame. A settle rather than a poll on
    // purpose: the failure mode is a durable state change (stale + policy
    // dropped) that never heals on this connection, so a poll for the GOOD
    // state would pass vacuously by observing it before the bad frame lands.
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        !state.authority.is_group_policy_stale(group_id),
        "an unchanged policy chain resent from record 1 on a reconnect must not mark the group \
         stale -- the coordination plane's policy-send watermark is per connection, so a full \
         resend is the NORMAL first frame after any reconnect, not evidence of a fork or a gap"
    );
    match state.resolve_group_policy(group_id) {
        GroupPolicyResolution::Verified(policy) => {
            assert!(
                policy.current_seq >= 2,
                "the verified chain must still be at its real head after the reconnect, got seq {}",
                policy.current_seq
            );
        }
        GroupPolicyResolution::Withhold => panic!(
            "the group must still resolve to a verified policy after an ordinary reconnect, got \
             Withhold -- both local emission and remote admission are now locked out for this \
             group, with nothing on this connection to undo it"
        ),
        GroupPolicyResolution::Bootstrap => panic!(
            "the group must still resolve to a verified policy after an ordinary reconnect, got \
             Bootstrap -- its verified state was dropped without even leaving the group marked \
             introduced"
        ),
    }

    // Keep the unstarted peer's state alive for the whole test so the fake's
    // membership view does not change underneath the reconnect.
    let _ = &peer_state;
}

/// Closes `device_id`'s netmap socket, retrying briefly: `run`'s subscription
/// is established asynchronously, so the very first attempt can land in the
/// window before the fake has registered the subscriber.
async fn wait_until_dropped(fake: &FakeCoordination, device_id: &str) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if fake.drop_subscription(device_id) {
            return true;
        }
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
