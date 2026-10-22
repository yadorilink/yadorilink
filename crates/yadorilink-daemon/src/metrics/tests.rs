#![cfg(test)]

use std::sync::Arc;

use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

use super::*;
use crate::daemon_state::DaemonState;
use crate::peer_registry::{PeerReachability, UnreachableCategory};

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

#[tokio::test]
async fn renders_every_documented_metric_family() {
    let state = test_state();
    let metrics = DaemonMetrics::new(state);
    let rendered = metrics.render_openmetrics();

    assert!(rendered.contains("yadorilink_transfer_bytes_total"));
    assert!(rendered.contains("yadorilink_active_transfers"));
    assert!(rendered.contains("yadorilink_active_peers"));
    assert!(rendered.contains("yadorilink_sync_errors_total"));
    assert!(rendered.contains("yadorilink_block_fetch_seconds"));
}

#[tokio::test]
async fn reflects_live_state_active_peers_transfers_bytes_and_errors() {
    let state = test_state();
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "peer-a",
        PeerReachability::Connected(crate::route::RouteKind::Direct),
    );
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "peer-b",
        PeerReachability::Unreachable(UnreachableCategory::NoResponse),
    );
    let _guard = state.telemetry.begin_transfer("group-1", "big.bin", 100, 1);
    state.telemetry.record_transfer_block_done("group-1", "big.bin", 42, "peer-a");
    state.telemetry.record_recent_error("disk_pressure", "sweep");
    state.telemetry.record_recent_error("disk_pressure", "sweep");

    let metrics = DaemonMetrics::new(state);
    let rendered = metrics.render_openmetrics();

    assert!(rendered.contains("yadorilink_active_peers 1"));
    assert!(rendered.contains("yadorilink_active_transfers 1"));
    assert!(rendered.contains("yadorilink_transfer_bytes_total 42"));
    assert!(rendered.contains("yadorilink_sync_errors_total{category=\"disk_pressure\"} 2"));
}

/// No label or value may contain a device id, a path, a token, or a
/// peer address, even once real (test) activity has been recorded.
#[tokio::test]
async fn privacy_safe_metrics_never_contain_content_paths_keys_tokens_or_ips() {
    let state = test_state();
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "peer-secret-device-id",
        PeerReachability::Connected(crate::route::RouteKind::Direct),
    );
    let _guard =
        state.telemetry.begin_transfer("group-1", "/Users/alice/secret-plans.docx", 1000, 10);
    state.telemetry.record_transfer_block_done(
        "group-1",
        "/Users/alice/secret-plans.docx",
        500,
        "peer-secret-device-id",
    );
    state.telemetry.record_recent_error("disk_pressure", "hydration");

    let metrics = DaemonMetrics::new(state);
    let rendered = metrics.render_openmetrics();

    assert!(!rendered.contains("peer-secret-device-id"));
    assert!(!rendered.contains("secret-plans"));
    assert!(!rendered.contains("/Users/alice"));
    assert!(!rendered.contains("127.0.0.1"));
    assert!(!rendered.contains("token"));
    assert!(!rendered.contains("key"));
}
