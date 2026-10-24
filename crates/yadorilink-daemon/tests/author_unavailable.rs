//! A device whose author identity cannot be opened for a reason other than a
//! restored database (here: the installation witness cannot be recorded
//! outside the data set) hands out no author handle, and says so in `status`
//! instead of reporting a healthy daemon that silently syncs nothing.
#[cfg(unix)]
mod unix_tests {
    use std::path::Path;
    use std::sync::Arc;

    use tokio::net::UnixStream;
    use yadorilink_daemon::daemon_state::DaemonState;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        DaemonControlRequest, DaemonControlResponse, StatusRequest, StatusResponse,
    };
    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_local_storage::SegmentBlockStore;

    async fn status(socket: &Path) -> StatusResponse {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        write_message(
            &mut stream,
            &DaemonControlRequest {
                payload: Some(ReqPayload::Status(StatusRequest {})),
                protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let response = read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap();
        let Some(RespPayload::Status(status)) = response.payload else {
            panic!("expected a status response");
        };
        status
    }

    #[tokio::test]
    async fn an_author_identity_that_cannot_open_is_reported_not_healthy() {
        let root = tempfile::tempdir().unwrap();
        // The witness directory is a path below a regular file: it can never be created.
        let blocker = root.path().join("not-a-directory");
        std::fs::write(&blocker, b"x").unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let socket = root.path().join("daemon.sock");

        let store = Arc::new(SegmentBlockStore::new(data.join("blocks")).unwrap());
        let tuning = yadorilink_daemon::engine_tuning::EngineTuning {
            witness: yadorilink_daemon::install_witness::WitnessPlacement::At(
                blocker.join("witness"),
            ),
            ..Default::default()
        };
        let coordinator =
            Arc::new(ReplicaCoordinator::open_with(data.join("sync.sqlite3"), tuning).unwrap());
        let state = DaemonState::new("device-under-test".into(), coordinator, store);
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        assert!(state.local_author().is_none(), "no witness, no author");

        let serve_state = state.clone();
        let serve_socket = socket.clone();
        tokio::spawn(async move {
            let _ = yadorilink_daemon::control_socket::unix_transport::serve(
                &serve_socket,
                Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(
                    serve_state,
                )),
            )
            .await;
        });
        yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket).await;

        let status = status(&socket).await;
        assert!(
            status.attention_reasons.iter().any(|r| r == "author_unavailable"),
            "{:?}",
            status.attention_reasons
        );
    }
}
