//! A replica database restored from a backup onto the machine it came from
//! (the database file, its `.instance` sidecar and every other file of the
//! data set put back together) is refused: the daemon hands out no author
//! handle and reports `database_restored`. The installation witness kept
//! outside the data set is what disagrees with the restored copy.
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

    /// A running daemon: its state and the task serving the control socket.
    struct Daemon {
        state: Arc<DaemonState>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Daemon {
        /// Stops the daemon for real: ends the server task and the state's background tasks, then waits until nothing
        /// (no connection task, no coordinator) still holds the state, so every SQLite
        /// connection is closed before the caller touches the files. Dropping the
        /// state handle alone does not stop the daemon, because the server task owns
        /// a clone of it.
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

    /// Opens the daemon state over the data in `data`, wires the signing key
    /// (which opens the author identity), serves the control socket.
    async fn daemon(data: &Path, socket: &Path) -> Daemon {
        daemon_as(data, socket, "device-under-test", 7).await
    }

    /// One witness directory for the whole test process, kept outside every data set. Witness
    /// files are named by database path, so the tests do not share a witness.
    fn outside_witness() -> yadorilink_daemon::engine_tuning::EngineTuning {
        static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        let dir = DIR.get_or_init(|| tempfile::tempdir().unwrap());
        yadorilink_daemon::engine_tuning::EngineTuning {
            witness: yadorilink_daemon::install_witness::WitnessPlacement::At(
                dir.path().to_path_buf(),
            ),
            ..Default::default()
        }
    }

    /// [`daemon`] running as `device_id`, signing with the key made from `key_byte`.
    async fn daemon_as(data: &Path, socket: &Path, device_id: &str, key_byte: u8) -> Daemon {
        let store = Arc::new(SegmentBlockStore::new(data.join("blocks")).unwrap());
        let coordinator = Arc::new(
            ReplicaCoordinator::open_with(data.join("sync.sqlite3"), outside_witness()).unwrap(),
        );
        let state = DaemonState::new(device_id.into(), coordinator, store);
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[key_byte; 32]));
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

    /// Every file of the data set that belongs to the replica database.
    fn database_files(data: &Path) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(data)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.is_file()
                    && path.file_name().unwrap().to_string_lossy().starts_with("sync.sqlite3")
            })
            .collect()
    }

    fn copy_files(files: &[std::path::PathBuf], to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for file in files {
            std::fs::copy(file, to.join(file.file_name().unwrap())).unwrap();
        }
    }

    #[tokio::test]
    async fn an_older_copy_of_the_database_is_refused_and_reported() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let socket = root.path().join("daemon.sock");

        // First run, then a backup of the whole data set.
        let first = daemon(&data, &socket).await;
        let first_state = first.state.clone();
        assert!(first_state.local_author().is_some(), "a fresh install authors");
        let author = first_state.local_author().unwrap().author();
        drop(first_state);
        first.stop().await;
        let backup = root.path().join("backup");
        // The daemon is stopped (see `Daemon::stop`): nothing writes the files while they are copied.
        copy_files(&database_files(&data), &backup);

        // The install keeps running, and its database moves on.
        let second = daemon(&data, &socket).await;
        assert_eq!(
            second.state.local_author().unwrap().author(),
            author,
            "a restart keeps the author"
        );
        assert!(!status(&socket)
            .await
            .attention_reasons
            .iter()
            .any(|r| r.starts_with("database_")));
        second.stop().await;

        // Time Machine puts the older data set back, sidecar included.
        for file in database_files(&data) {
            std::fs::remove_file(file).unwrap();
        }
        copy_files(&database_files(&backup), &data);
        let _ = std::fs::remove_file(&socket);

        let restored = daemon(&data, &socket).await;
        assert!(restored.state.local_author().is_none(), "a restored database must not author");
        let status = status(&socket).await;
        assert!(
            status.attention_reasons.iter().any(|r| r == "database_restored:older_generation"),
            "{:?}",
            status.attention_reasons
        );
        assert_ne!(status.overall_state, "healthy");
    }

    /// The way out of the refusal: the same database, block store and files opened as a new device
    /// (what a start over registers). The restored state is no longer reported, the replica authors
    /// again, and the old device's author stays in the database as the prior incarnation instead of
    /// being written to again.
    #[tokio::test]
    async fn the_same_database_opened_as_a_new_device_authors_and_keeps_the_old_author() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let socket = root.path().join("daemon.sock");

        let first = daemon(&data, &socket).await;
        let old_author = first.state.local_author().unwrap().author();
        first.stop().await;
        let backup = root.path().join("backup");
        copy_files(&database_files(&data), &backup);
        daemon(&data, &socket).await.stop().await;
        for file in database_files(&data) {
            std::fs::remove_file(file).unwrap();
        }
        copy_files(&database_files(&backup), &data);
        let _ = std::fs::remove_file(&socket);

        let restored = daemon(&data, &socket).await;
        assert!(restored.state.local_author().is_none());
        restored.stop().await;
        let _ = std::fs::remove_file(&socket);

        let renewed = daemon_as(&data, &socket, "device-after-start-over", 9).await;
        let new_author =
            renewed.state.local_author().expect("a new device authors over the same database");
        assert_eq!(new_author.author().device.as_str(), "device-after-start-over");
        assert_ne!(new_author.author(), old_author);
        let status = status(&socket).await;
        assert!(
            !status.attention_reasons.iter().any(|r| r.starts_with("database_")),
            "{:?}",
            status.attention_reasons
        );
        drop(new_author);
        renewed.stop().await;
        // The prior incarnation is recorded, not erased.
        let conn = rusqlite::Connection::open(data.join("sync.sqlite3")).unwrap();
        let (device, previous): (String, Option<Vec<u8>>) = conn
            .query_row("SELECT device_id, previous FROM author_incarnation", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(device, "device-after-start-over");
        assert_eq!(previous.as_deref(), Some(old_author.incarnation.0.as_slice()));
    }
}
