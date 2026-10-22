//! Beta acceptance scenario for non-technical diagnosis of a failed peer
//! connection, exercised end-to-end over the real control socket (mirrors
//! `tests/control_socket.rs`/`tests/reporting_ipc.rs`'s own pattern).
#![cfg(unix)]

use std::sync::Arc;

use tokio::net::UnixStream;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ConnectivityDoctorRequest, DaemonControlRequest, DaemonControlResponse,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::SegmentBlockStore;

async fn start_daemon_with_state() -> (std::path::PathBuf, tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let state_db = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), state_db, store);
    let socket_path = dir.path().join("daemon.sock");

    let serve_path = socket_path.clone();
    let serve_state = state.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(
            &serve_path,
            std::sync::Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(
                serve_state,
            )),
        )
        .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket_path).await;
    (socket_path, dir, state)
}

async fn send(socket_path: &std::path::Path, payload: ReqPayload) -> DaemonControlResponse {
    let mut stream = UnixStream::connect(socket_path).await.unwrap();
    write_message(
        &mut stream,
        &DaemonControlRequest {
            payload: Some(payload),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    .unwrap();
    read_message(&mut stream).await.unwrap().unwrap()
}

/// Beta acceptance scenario: "a peer isn't connecting, what's wrong?" —
/// the connectivity doctor should give bounded, user-actionable categories
/// even when nothing else about the daemon has been configured yet,
/// rather than a blank screen or a raw error.
#[tokio::test]
async fn diagnosing_a_failed_peer_connection_via_the_doctor() {
    let (socket_path, _dir, _state) = start_daemon_with_state().await;

    let resp =
        send(&socket_path, ReqPayload::ConnectivityDoctor(ConnectivityDoctorRequest {})).await;
    let Some(RespPayload::ConnectivityDoctor(result)) = resp.payload else {
        panic!("wrong response variant: {:?}", resp.payload)
    };

    let names: Vec<&str> = result.categories.iter().map(|c| c.name.as_str()).collect();
    for expected in [
        "daemon",
        "listener",
        "coordination_plane",
        "authorization",
        "clock_config",
        "policy_disabled",
    ] {
        assert!(names.contains(&expected), "missing doctor category {expected}: {names:?}");
    }
    // Every category reports a bounded, known status — never blank.
    for category in &result.categories {
        assert!(
            matches!(category.status.as_str(), "ok" | "warn" | "error"),
            "unexpected status {} for {}",
            category.status,
            category.name
        );
        assert!(!category.detail.is_empty(), "{} has no user-actionable detail", category.name);
    }
    // This freshly-started daemon is, at minimum, actually running.
    let daemon_category = result.categories.iter().find(|c| c.name == "daemon").unwrap();
    assert_eq!(daemon_category.status, "ok");
}
