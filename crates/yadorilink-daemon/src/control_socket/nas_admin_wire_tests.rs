//! `open_nas_admin` over a real control connection: the one request whose
//! connection is held after its response. A session that cannot open is
//! answered with one of the closed failure kinds and the connection ends;
//! a request from another protocol generation is refused like any other.

use std::sync::Arc;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::open_nas_admin_response::Outcome;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, NasAdminFailureKind, OpenNasAdminRequest,
    CONTROL_PROTOCOL_VERSION,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::SegmentBlockStore;

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

/// Sends `open_nas_admin` at `version` and returns the answer, and whether
/// the daemon then closed the connection.
async fn open(version: u32, device_id: &str) -> (DaemonControlResponse, bool) {
    let context = Arc::new(crate::control_context::ControlContext::from_state(test_state()));
    let (mut client, daemon_side) = tokio::io::duplex(4096);
    let serving = tokio::spawn(super::handle_connection(daemon_side, context));
    let request = DaemonControlRequest {
        payload: Some(ReqPayload::OpenNasAdmin(OpenNasAdminRequest {
            device_id: device_id.to_string(),
        })),
        protocol_version: version,
    };
    write_message(&mut client, &request).await.unwrap();
    let response = read_message::<DaemonControlResponse>(&mut client).await.unwrap().unwrap();
    let next = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read_message::<DaemonControlResponse>(&mut client),
    )
    .await
    .expect("the daemon is done with this connection");
    serving.await.unwrap().unwrap();
    (response, matches!(next, Ok(None)))
}

#[tokio::test]
async fn a_session_that_cannot_open_is_one_failure_kind_and_ends_the_connection() {
    // Not signed in: there is no account to find the device on.
    let (response, closed) = open(CONTROL_PROTOCOL_VERSION, "nas-1").await;
    assert_eq!(response.daemon_protocol_version, CONTROL_PROTOCOL_VERSION);
    match response.payload {
        Some(RespPayload::OpenNasAdmin(answer)) => assert_eq!(
            answer.outcome,
            Some(Outcome::Failure(NasAdminFailureKind::CouldNotOpen as i32))
        ),
        other => panic!("expected an open_nas_admin answer, got {other:?}"),
    }
    assert!(closed, "a session that did not open holds nothing open");

    // This device itself is never a device to manage.
    let (response, _) = open(CONTROL_PROTOCOL_VERSION, "device-a").await;
    assert!(matches!(
        response.payload,
        Some(RespPayload::OpenNasAdmin(answer))
            if answer.outcome == Some(Outcome::Failure(NasAdminFailureKind::CouldNotOpen as i32))
    ));
}

#[tokio::test]
async fn another_protocol_generation_is_refused_before_anything_opens() {
    let (response, closed) = open(CONTROL_PROTOCOL_VERSION - 1, "nas-1").await;
    assert!(matches!(response.payload, Some(RespPayload::Error(_))), "{response:?}");
    assert!(closed);
}
