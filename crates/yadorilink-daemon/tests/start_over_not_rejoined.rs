//! A folder that start over could not join again stays visible as needing action across a daemon
//! restart, keeps its files, and is cleared when the folder is linked to its group again.
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
        DaemonControlRequest, DaemonControlResponse, LinkRequest, ListLinksRequest,
        MarkLinkNotRejoinedRequest, StatusRequest, StatusResponse,
    };
    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_local_storage::SegmentBlockStore;

    struct Daemon {
        state: Arc<DaemonState>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Daemon {
        /// Stops the daemon for real, so every SQLite connection is closed before it is opened
        /// again (see `database_restored.rs`).
        async fn stop(self) {
            let Daemon { state, server } = self;
            server.abort();
            let _ = server.await;
            state.stop_background_tasks_for_tests();
            let weak = Arc::downgrade(&state);
            drop(state);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while weak.strong_count() > 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the daemon still holds its state: its database is still open"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }

    async fn daemon(data: &Path, socket: &Path) -> Daemon {
        let store = Arc::new(SegmentBlockStore::new(data.join("blocks")).unwrap());
        let coordinator = Arc::new(ReplicaCoordinator::open(data.join("sync.sqlite3")).unwrap());
        let state = DaemonState::new("device-under-test".into(), coordinator, store);
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
        let serve_state = state.clone();
        let serve_socket = socket.to_path_buf();
        let server = tokio::spawn(async move {
            let _ = yadorilink_daemon::control_socket::unix_transport::serve(
                &serve_socket,
                Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(
                    serve_state,
                )),
            )
            .await;
        });
        yadorilink_daemon::control_socket::unix_transport::wait_until_bound(socket).await;
        Daemon { state, server }
    }

    async fn send(socket: &Path, payload: ReqPayload) -> DaemonControlResponse {
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
        read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap()
    }

    async fn status(socket: &Path) -> StatusResponse {
        let Some(RespPayload::Status(status)) =
            send(socket, ReqPayload::Status(StatusRequest {})).await.payload
        else {
            panic!("expected a status response");
        };
        status
    }

    async fn link(socket: &Path, folder: &Path, group: &str) {
        let response = send(
            socket,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: group.into(),
                acknowledge_risks: true,
                ..Default::default()
            }),
        )
        .await;
        assert!(matches!(response.payload, Some(RespPayload::Link(_))), "{response:?}");
    }

    async fn mark(socket: &Path, folder: &Path) -> DaemonControlResponse {
        send(
            socket,
            ReqPayload::MarkLinkNotRejoined(MarkLinkNotRejoinedRequest {
                local_path: folder.to_string_lossy().to_string(),
            }),
        )
        .await
    }

    fn not_joined(status: &StatusResponse) -> Vec<String> {
        status
            .attention_reasons
            .iter()
            .filter(|reason| reason.starts_with("not_joined:"))
            .cloned()
            .collect()
    }

    /// Two folders, one cannot be joined again: after a restart it is still reported as needing
    /// action and the other is not; linking it to its group again clears it; the files of both
    /// were never touched.
    #[tokio::test]
    async fn a_folder_not_rejoined_stays_visible_across_a_restart_until_it_is_linked_again() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let socket = root.path().join("daemon.sock");
        let kept = root.path().join("kept");
        let other = root.path().join("other");
        for folder in [&kept, &other] {
            std::fs::create_dir_all(folder).unwrap();
            std::fs::write(folder.join("notes.txt"), format!("mine in {}", folder.display()))
                .unwrap();
        }

        // Linked as a daemon that was running before start over had them (rows only: a running
        // link runtime would keep the database open past `stop`).
        let first = daemon(&data, &socket).await;
        let links = first.state.replica_coordinator.link_repository();
        links.add_link(&kept.to_string_lossy(), "g-kept").unwrap();
        links.add_link(&other.to_string_lossy(), "g-other").unwrap();
        assert!(not_joined(&status(&socket).await).is_empty());

        // Start over could not join `kept`'s group again.
        let response = mark(&socket, &kept).await;
        assert!(
            matches!(response.payload, Some(RespPayload::MarkLinkNotRejoined(_))),
            "{response:?}"
        );
        let marked = status(&socket).await;
        assert_eq!(not_joined(&marked), ["not_joined:g-kept"]);
        assert_eq!(marked.overall_state, "degraded");

        // The app and the daemon restart.
        first.stop().await;
        let _ = std::fs::remove_file(&socket);
        let second = daemon(&data, &socket).await;
        let restarted = status(&socket).await;
        assert_eq!(
            not_joined(&restarted),
            ["not_joined:g-kept"],
            "the folder must still need action after a restart, and only that one"
        );
        let Some(RespPayload::ListLinks(list)) =
            send(&socket, ReqPayload::ListLinks(ListLinksRequest {})).await.payload
        else {
            panic!("expected a link list");
        };
        assert_eq!(list.links.len(), 2, "the link is kept, never dropped");

        // A new invite links the folder to its group again.
        link(&socket, &kept, "g-kept").await;
        assert!(not_joined(&status(&socket).await).is_empty(), "linking again clears it");

        for folder in [&kept, &other] {
            assert_eq!(
                std::fs::read_to_string(folder.join("notes.txt")).unwrap(),
                format!("mine in {}", folder.display()),
                "local files are never touched"
            );
        }
        // Left running: the re-link started its runtime, which holds the database open.
        drop(second);
    }

    /// A running link is stopped by the mark, so linking it again starts it afresh instead of
    /// being refused as already running.
    #[tokio::test]
    async fn a_running_link_is_stopped_by_the_mark_and_starts_again_when_linked() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let socket = root.path().join("daemon.sock");
        let folder = root.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("a.txt"), "a").unwrap();
        let _daemon = daemon(&data, &socket).await;

        link(&socket, &folder, "g-docs").await;
        assert!(matches!(
            mark(&socket, &folder).await.payload,
            Some(RespPayload::MarkLinkNotRejoined(_))
        ));
        assert_eq!(not_joined(&status(&socket).await), ["not_joined:g-docs"]);
        // Like an unlink, the stop of a link that scanned files can leave its root locked for a
        // moment; an invite is accepted long after that, so this waits it out.
        let mut attempt = 0;
        loop {
            let response = send(
                &socket,
                ReqPayload::Link(LinkRequest {
                    local_path: folder.to_string_lossy().to_string(),
                    group_id: "g-docs".into(),
                    acknowledge_risks: true,
                    ..Default::default()
                }),
            )
            .await;
            if matches!(response.payload, Some(RespPayload::Link(_))) {
                break;
            }
            attempt += 1;
            assert!(attempt < 50, "{response:?}");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(not_joined(&status(&socket).await).is_empty());
        assert_eq!(std::fs::read_to_string(folder.join("a.txt")).unwrap(), "a");
    }

    #[tokio::test]
    async fn marking_a_path_that_is_not_linked_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let socket = root.path().join("daemon.sock");
        let daemon = daemon(&data, &socket).await;
        let response = mark(&socket, &root.path().join("nowhere")).await;
        assert!(matches!(response.payload, Some(RespPayload::Error(_))), "{response:?}");
        daemon.stop().await;
    }
}
