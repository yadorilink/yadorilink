//! Canonical 3-node topology -- N (Full Replica,
//! relay-capable, "home NAS" role conceptually), M and W (On-Demand,
//! "Mac"/"Windows" roles conceptually). Reusable base for the multi-node
//! acceptance scenarios.
//!
//! Real production code at every layer this exercises: real
//! `DaemonState`, real `peer_orchestrator`-driven `PeerChannel`/
//! QUIC-shaped sessions over loopback UDP (same pattern as
//! `relay_chaos.rs`), real DAG mutation propagation via the real
//! filesystem watcher (`std::fs::write` on a linked local folder, not a
//! raw DB upsert -- `monkey_chaos.rs`'s established convention), real
//! `MaterializationPolicy::OnDemand` storage mode
//! (`storage_mode_orchestration.rs`'s API), real custody-confirmation
//! sweep (`DaemonState::refresh_custody_confirmation`, the same method
//! `DurabilityConfirmationJob` calls periodically in production), real
//! `group_durability_status` derivation.
//!
//! **Not** OS-native (CfAPI/File Provider) acceptance -- this proves the
//! application/daemon/transport/storage integration above the
//! platform-native boundary, not Explorer/Finder lifecycle behavior. See
//! `relay_chaos.rs`/`relay_session_e2e.rs` for the real-transport relay
//! coverage this reuses the relay-anchor role from.

mod support;

use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::stand_up_canonical_topology;
use support::wait_until_with_context;
use yadorilink_daemon::durability_service::GroupDurabilityStatus;

/// All three peers direct-connect;
/// M writes a file through the real filesystem watcher; N and W converge
/// on the exact same content; W then authors its own file, and N/M
/// converge on THAT (symmetric direction); N's
/// durability status is checked once a real custody-confirmation sweep
/// has run.
///
/// Both directions run in ONE test function (not two `#[tokio::test]`s
/// sharing one mesh-spawning helper) deliberately: `cargo test` runs
/// every `#[test]`/`#[tokio::test]` in a file's binary CONCURRENTLY by
/// default, and two independently-spawned 3-node meshes (6 real
/// `peer_orchestrator` reconnect-supervision loops, 6 UDP sockets, 6
/// SQLite pools) in the same process measurably starve each other's
/// handshake budget -- confirmed directly: splitting this into two
/// tests, even with orchestrator-task teardown on each, still flaked on
/// the mesh-connectivity wait under concurrent execution. One mesh per
/// process avoids the contention entirely rather than chasing a resource
/// budget that only gets more contended as node count scales up.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn happy_path_direct_convergence_and_hydration() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-happy-path-group";

    let (n, m, w, _handles) = stand_up_canonical_topology(&fake, group_id).await;

    // M authors real content through the real watcher/debounce/executor
    // path -- not a raw DB upsert, so the real common DAG/sync path is
    // exercised.
    let path = m.root.path().join("shared.txt");
    std::fs::write(&path, b"hello from M").unwrap();

    wait_until_with_context(
        || std::fs::read(n.root.path().join("shared.txt")).ok().as_deref() == Some(b"hello from M"),
        Duration::from_secs(30),
        || "N never converged on M's content".to_string(),
    )
    .await;

    // W is On-Demand: the file lands as a placeholder until something
    // above the platform-native boundary requests it -- in production, a
    // real OS callback (Windows FETCH_DATA / macOS "make available
    // offline"); here, the same `hydration::hydrate` entry point those
    // callbacks ultimately drive. Wait for it to land in the DAG first
    // (placeholder record present), then hydrate, then verify exact
    // bytes.
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "shared.txt" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(30),
        || "W never saw shared.txt's DAG record".to_string(),
    )
    .await;
    // The record can be listed while still the bootstrap scaffold, and the lane then
    // replaces it; a hydrate that sampled the scaffold fails closed and is retried.
    support::topology::hydrate_with_retries(&w.state, group_id, "shared.txt").await;
    assert_eq!(
        std::fs::read(w.root.path().join("shared.txt")).unwrap(),
        b"hello from M",
        "W's hydrated content must be the exact bytes M authored"
    );

    // Expected product behaviour, not a test bug: in THIS canonical topology N is
    // the group's ONLY full replica -- M and W are both On-Demand, so
    // neither is a durability holder. `classify()`'s `Protected` path
    // deliberately requires an OTHER confirmed full-replica peer, never
    // this device's own local completeness alone (see
    // `durability_service.rs`'s own doc comment). With no other full-replica peer configured, this is
    // structurally `AtRisk`: a single point of failure, correctly
    // reported as such -- "one full copy on an always-on device" is only
    // `Protected` once a SECOND full replica (or a fresh peer handoff
    // confirmation) exists. A real custody-confirmation sweep (the same
    // call `DurabilityConfirmationJob` makes periodically in production)
    // must positively confirm this, not just leave it at the
    // never-swept-yet default.
    n.state.refresh_custody_confirmation(group_id).await;
    assert_eq!(
        n.state.group_durability_status(group_id),
        GroupDurabilityStatus::AtRisk,
        "a lone complete-copy anchor with no other complete-copy peer must read AtRisk, \
         never Protected, from its own local completeness alone"
    );

    // Symmetric direction: W authors content;
    // N and M converge on it.
    let path = w.root.path().join("from-w.txt");
    std::fs::write(&path, b"hello from W").unwrap();

    wait_until_with_context(
        || std::fs::read(n.root.path().join("from-w.txt")).ok().as_deref() == Some(b"hello from W"),
        Duration::from_secs(30),
        || "N never converged on W's content".to_string(),
    )
    .await;
    wait_until_with_context(
        || {
            m.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "from-w.txt" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(30),
        || "M never saw from-w.txt's DAG record".to_string(),
    )
    .await;
    // The record can be listed while still the bootstrap scaffold, and the lane then
    // replaces it; a hydrate that sampled the scaffold fails closed and is retried.
    support::topology::hydrate_with_retries(&m.state, group_id, "from-w.txt").await;
    assert_eq!(
        std::fs::read(m.root.path().join("from-w.txt")).unwrap(),
        b"hello from W",
        "M's hydrated content must be the exact bytes W authored"
    );

    // Read-model truthfulness through the REAL wire boundary -- the exact
    // surface the CLI/desktop app actually read, not `DaemonState`
    // internals (`queries::link_status`'s canonical types are
    // deliberately `pub(crate)`; going through the real control socket,
    // same as `desktop_status_parity.rs`/`storage_mode_orchestration.rs`
    // already do, exercises `control_socket.rs`'s wire-conversion
    // functions too, so the CLI/desktop-facing semantic status model is
    // covered end to end).
    let w_link = support::control_socket_client::query_link_status(w.state.clone(), group_id).await;
    assert_eq!(
        w_link.local_storage_state(),
        yadorilink_ipc_proto::daemonctl::LocalStorageState::OnDemand,
        "W's wire-reported local storage state must truthfully be OnDemand"
    );
    assert_eq!(
        w_link.fetch_availability(),
        yadorilink_ipc_proto::daemonctl::FetchAvailability::AvailableNow,
        "W has both files fully hydrated locally now, so fetch_availability must read \
         AvailableNow through the real wire boundary"
    );
}
