//! The space management setting and its dry run over a real control socket.
#![cfg(unix)]

use std::sync::Arc;

use tokio::net::UnixStream;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, GetSpaceManagementRequest,
    PreviewSpaceReclaimRequest, SetSpaceManagementRequest, SpaceManagementSettings,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::SegmentBlockStore;

static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn start_daemon() -> (std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    let socket_path = dir.path().join("daemon.sock");
    let serve_path = socket_path.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(
            &serve_path,
            Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(state)),
        )
        .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket_path).await;
    (socket_path, dir)
}

async fn send(socket: &std::path::Path, payload: ReqPayload) -> RespPayload {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    write_message(
        &mut stream,
        &DaemonControlRequest {
            payload: Some(payload),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    .unwrap();
    let response: DaemonControlResponse = read_message(&mut stream).await.unwrap().unwrap();
    response.payload.unwrap()
}

#[tokio::test]
async fn the_setting_defaults_to_off_and_is_stored() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket, _dir) = start_daemon().await;

    let RespPayload::GetSpaceManagement(first) =
        send(&socket, ReqPayload::GetSpaceManagement(GetSpaceManagementRequest {})).await
    else {
        panic!("not a settings answer")
    };
    assert_eq!(first.settings, Some(SpaceManagementSettings { enabled: false }));

    let RespPayload::SetSpaceManagement(set) = send(
        &socket,
        ReqPayload::SetSpaceManagement(SetSpaceManagementRequest {
            settings: Some(SpaceManagementSettings { enabled: true }),
        }),
    )
    .await
    else {
        panic!("not a settings answer")
    };
    assert_eq!(set.settings, Some(SpaceManagementSettings { enabled: true }));

    let RespPayload::GetSpaceManagement(again) =
        send(&socket, ReqPayload::GetSpaceManagement(GetSpaceManagementRequest {})).await
    else {
        panic!("not a settings answer")
    };
    assert_eq!(again.settings, Some(SpaceManagementSettings { enabled: true }));
}

#[tokio::test]
async fn a_daemon_without_provider_folders_does_not_pretend_to_preview() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket, _dir) = start_daemon().await;
    let answer =
        send(&socket, ReqPayload::PreviewSpaceReclaim(PreviewSpaceReclaimRequest {})).await;
    assert!(matches!(answer, RespPayload::Error(_)), "{answer:?}");
}
