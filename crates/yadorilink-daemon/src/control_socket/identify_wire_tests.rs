//! `identify` through the control dispatch: the documented fields, version enforcement like any
//! other request, and no change to the data area.

use std::path::PathBuf;
use std::sync::Arc;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, IdentifyRequest, OwnershipRecordStatus, CONTROL_PROTOCOL_VERSION,
};
use yadorilink_local_storage::ownership;
use yadorilink_local_storage::SegmentBlockStore;

use crate::daemon_state::DaemonState;
use crate::identity::{IdentityInputs, RuntimeIdentity};
use crate::replica_coordinator::ReplicaCoordinator;

fn context(
    exe: &str,
    source: &str,
    config: &std::path::Path,
) -> crate::control_context::ControlContext {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    crate::control_context::ControlContext::from_state(state).with_identity(Arc::new(
        RuntimeIdentity::from_inputs(IdentityInputs {
            exe: PathBuf::from(exe),
            install_source: source.into(),
            pid: 77,
            started_at_unix: 1_700_000_000,
            config_dir: Some(config.to_path_buf()),
        }),
    ))
}

async fn identify(
    context: &crate::control_context::ControlContext,
    version: u32,
) -> yadorilink_ipc_proto::daemonctl::DaemonControlResponse {
    super::handle_request(
        context,
        DaemonControlRequest {
            payload: Some(ReqPayload::Identify(IdentifyRequest {})),
            protocol_version: version,
        },
    )
    .await
}

#[tokio::test]
async fn identify_reports_an_app_bundle_daemon_and_its_data_area() {
    let config = tempfile::tempdir().unwrap();
    let context = context(
        "/Applications/YadoriLink.app/Contents/Library/LoginItems/D.app/Contents/MacOS/yadorilink-daemon",
        "app_bundle",
        config.path(),
    );
    let response = identify(&context, CONTROL_PROTOCOL_VERSION).await;
    assert_eq!(response.daemon_protocol_version, CONTROL_PROTOCOL_VERSION);
    let Some(RespPayload::Identify(report)) = response.payload else { panic!("not identify") };
    assert_eq!(report.install_source, "app_bundle");
    assert_eq!(report.owner, "gui");
    assert_eq!(report.install_root, "/Applications/YadoriLink.app");
    assert_eq!(report.pid, 77);
    assert_eq!(report.ownership_status, OwnershipRecordStatus::Missing as i32);
    assert!(!config.path().join(ownership::FILE_NAME).exists(), "identify is read-only");
}

#[tokio::test]
async fn identify_from_another_generation_is_refused_like_any_request() {
    let config = tempfile::tempdir().unwrap();
    let context = context("/usr/bin/yadorilink-daemon", "apt", config.path());
    let response = identify(&context, CONTROL_PROTOCOL_VERSION + 1).await;
    assert!(matches!(response.payload, Some(RespPayload::Error(_))));
}

/// A client that checks the daemon's release first sends `identify` and then its request on the
/// same connection, so the answer describes the daemon that serves the request.
#[tokio::test]
async fn identify_then_another_request_are_served_on_one_connection() {
    use yadorilink_ipc_proto::daemonctl::StatusRequest;
    use yadorilink_ipc_proto::framing::{read_message, write_message};

    let config = tempfile::tempdir().unwrap();
    let context = Arc::new(context("/usr/bin/yadorilink-daemon", "apt", config.path()));
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let served = tokio::spawn(super::handle_connection(server, context));
    for payload in [ReqPayload::Identify(IdentifyRequest {}), ReqPayload::Status(StatusRequest {})]
    {
        write_message(
            &mut client,
            &DaemonControlRequest {
                payload: Some(payload),
                protocol_version: CONTROL_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
    }
    let first = read_message::<yadorilink_ipc_proto::daemonctl::DaemonControlResponse>(&mut client)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(first.payload, Some(RespPayload::Identify(_))));
    let second =
        read_message::<yadorilink_ipc_proto::daemonctl::DaemonControlResponse>(&mut client)
            .await
            .unwrap()
            .unwrap();
    assert!(matches!(second.payload, Some(RespPayload::Status(_))), "{:?}", second.payload);
    served.await.unwrap().unwrap();
}
