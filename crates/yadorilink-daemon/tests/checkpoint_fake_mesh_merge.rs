//! Regression coverage for mesh-authority splitting in the test harness:
//! pairing A-B,
//! then C-D, then B-C (bridging the two previously separate pairs) used to
//! leave D -- never named in the bridging call -- permanently pointed at
//! the now-abandoned second `FakeCoordination`, since `DaemonState::
//! coordination_client_config` is a `OnceLock` and cannot be migrated once
//! set. A Published Change crossing that island boundary verified against
//! the wrong authority key and was silently dropped -- indistinguishable,
//! from a test's own diagnostics, from "never received at all".
//!
//! There is no way to fix this after the fact (see `support::
//! checkpoint_fake_for`'s doc comment), so the real fix is `support::
//! TestPeerMesh`: one shared authority from construction, used for every
//! pairing in a test that connects more than two devices. This file checks
//! both halves: `TestPeerMesh` actually unifies a bridged mesh (positive),
//! and the old free-function path fails LOUD rather than silently
//! producing a split-brain authority if a test tries the unsafe shape
//! anyway (negative -- a regression guard against someone "fixing" the
//! assertion away instead of migrating to `TestPeerMesh`).

mod support;

use std::sync::Arc;

use support::TestAccount;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let device_id = support::register_device(account, name, [0u8; 32]).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(
        yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap(),
    );
    let state = DaemonState::new(device_id.clone(), sync_state, store);
    support::ensure_device_signing_key(&state);
    TestDevice { device_id, state, root: tempfile::tempdir().unwrap(), _store_dir: store_dir }
}

fn link(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_peer_mesh_unifies_every_historical_member_onto_one_authority() {
    let coordination_addr = support::start_coordination_server().await;
    let account = support::register_and_login(&coordination_addr, "test@example.com").await;
    let group_id = "shared".to_string();

    let a = setup_device(&account, "a").await;
    let b = setup_device(&account, "b").await;
    let c = setup_device(&account, "c").await;
    let d = setup_device(&account, "d").await;
    for device in [&a, &b, &c, &d] {
        link(device, &group_id);
    }

    let mesh = support::TestPeerMesh::new().await;
    // Two "separate" pairs, then a bridge -- all on the SAME mesh, so there
    // is only ever one authority to begin with.
    mesh.connect(&a.state, &a.device_id, &b.state, &b.device_id, std::slice::from_ref(&group_id))
        .await;
    mesh.connect(&c.state, &c.device_id, &d.state, &d.device_id, std::slice::from_ref(&group_id))
        .await;
    mesh.connect(&b.state, &b.device_id, &c.state, &c.device_id, std::slice::from_ref(&group_id))
        .await;

    let addr_a = a.state.coordination_client_config().unwrap().addr.clone();
    let addr_b = b.state.coordination_client_config().unwrap().addr.clone();
    let addr_c = c.state.coordination_client_config().unwrap().addr.clone();
    let addr_d = d.state.coordination_client_config().unwrap().addr.clone();
    assert_eq!(addr_a, addr_b, "A and B must share the mesh's one authority");
    assert_eq!(addr_b, addr_c, "B and C must share the mesh's one authority");
    assert_eq!(
        addr_c, addr_d,
        "D (paired only with C, never bridged directly to A/B) must still share the mesh's one \
         authority -- this is the exact case the old per-pair fake registry got wrong"
    );

    // Not just the client config pointer -- the actual bootstrap policy each
    // device holds for the shared group must verify under the SAME authority
    // key, since that is what admission actually checks.
    let policy_a =
        a.state.authority.group_policy_state(&group_id).expect("A must have a bootstrap policy");
    let policy_d =
        d.state.authority.group_policy_state(&group_id).expect("D must have a bootstrap policy");
    assert_eq!(
        policy_a.final_authority_key, policy_d.final_authority_key,
        "A's and D's bootstrap policy must be verified against the same authority key"
    );
}

/// Regression guard: a test that pairs more than two devices with
/// overlapping membership across calls (a genuine mesh, not just several
/// independent 2-device pairs) MUST use `TestPeerMesh`, never raw
/// `connect_two_daemons`/`checkpoint_fake_for` calls -- the latter cannot
/// safely bridge two already-committed islands (`DaemonState::
/// coordination_client_config` is a `OnceLock`), so `checkpoint_fake_for`
/// panics loudly rather than silently producing a split-brain authority.
/// If this test starts failing because the panic went away, that is a
/// regression: someone made the free-function path silently "succeed"
/// again without actually fixing the underlying OnceLock immutability,
/// which is exactly how this bug was introduced in the first place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[should_panic(expected = "DIFFERENT FakeCoordination instances")]
async fn bridging_two_pairs_via_raw_connect_two_daemons_fails_loud() {
    let coordination_addr = support::start_coordination_server().await;
    let account = support::register_and_login(&coordination_addr, "test@example.com").await;
    let group_id = "shared".to_string();

    let a = setup_device(&account, "a").await;
    let b = setup_device(&account, "b").await;
    let c = setup_device(&account, "c").await;
    let d = setup_device(&account, "d").await;
    for device in [&a, &b, &c, &d] {
        link(device, &group_id);
    }

    support::connect_two_daemons(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        std::slice::from_ref(&group_id),
    )
    .await;
    support::connect_two_daemons(
        &c.state,
        &c.device_id,
        &d.state,
        &d.device_id,
        std::slice::from_ref(&group_id),
    )
    .await;
    // Bridging call -- must panic rather than silently mis-wire B and C.
    support::connect_two_daemons(&b.state, &b.device_id, &c.state, &c.device_id, &[group_id]).await;
}
