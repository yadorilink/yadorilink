//! Exercises the shell-integration IPC protocol
//! end-to-end over a real Unix domain socket: status queries, the
//! daemon's proactive push, context actions, and the client's graceful
//! behavior when the daemon isn't running. Wrapped in `#[cfg(unix)]`
//! (Windows local IPC support) since it was already implicitly Unix-only
//! (`UnixStream`, `unix_transport::serve`) before that change — now made
//! explicit since `windows_pipe_tests` below adds a real Windows path
//! that would otherwise collide with these Unix-specific signatures.
#[cfg(unix)]
mod unix_socket_tests {

    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::UnixStream;
    use yadorilink_daemon::daemon_state::DaemonState;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
    use yadorilink_ipc_proto::shellipc::{
        ContextAction, ContextActionRequest, HydrateRequest, LocalState as ShellLocalState,
        LocalTransition as ShellLocalTransition, ShellIpcMessage, StatusQuery,
        SyncState as ShellSyncState,
    };
    use yadorilink_local_storage::SegmentBlockStore;
    use yadorilink_replica_domain::file::FileRecord;

    async fn start_daemon() -> (std::path::PathBuf, Arc<DaemonState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
        let sync_state =
            Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
        sync_state
            .link_repository()
            .add_link(dir.path().join("photos").to_string_lossy().as_ref(), "group-1")
            .unwrap();
        std::fs::create_dir_all(dir.path().join("photos")).unwrap();

        let state = DaemonState::new("device-a".into(), sync_state, store);
        let socket_path = dir.path().join("shell.sock");
        let serve_path = socket_path.clone();
        let serve_state =
            Arc::new(yadorilink_daemon::shell_context::ShellContext::from_state(state.clone()));
        tokio::spawn(async move {
            let _ =
                yadorilink_daemon::shell_ipc::unix_transport::serve(&serve_path, serve_state).await;
        });
        yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket_path).await;
        (socket_path, state, dir)
    }

    /// Stamps `path` as `Present`, which `upsert_file` alone does NOT do.
    ///
    /// `files.materialization_state` defaults to `'placeholder'` in the
    /// schema, and the only writer that stamps `Present` as part of
    /// indexing is the local-emission path
    /// (`stamp_hydrated_after_local_emission_in_tx`). A test that seeds a
    /// row with a bare `upsert_file` therefore gets a PLACEHOLDER, no
    /// matter how hydrated the file it describes looks -- so a test whose
    /// name says "an already hydrated file" was, before this helper, not
    /// testing that at all: the request under test short-circuited on the
    /// state check and never reached its own subject.
    ///
    /// `control_socket.rs` -- this file's sibling, exercising the same
    /// handlers over the control socket -- already hit exactly this and was
    /// fixed for it; these three cases were missed at the time.
    fn set_hydrated(state: &Arc<DaemonState>, path: &str) {
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                path,
                yadorilink_replica_domain::session_state::MaterializationState::Present,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }

    /// shell-integration spec: "Shell extension queries status via IPC".
    #[tokio::test]
    async fn status_query_reflects_indexed_file() {
        let (socket_path, state, dir) = start_daemon().await;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "vacation.jpg".into(),
                    size: 1,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let status = yadorilink_daemon::shell_ipc::client::query_status(
            &socket_path,
            &dir.path().join("photos/vacation.jpg").to_string_lossy(),
        )
        .await;
        assert_eq!(status, ShellSyncState::Synced);
    }

    /// / shell-integration spec: "Daemon not running" — the client
    /// must time out gracefully and report no overlay, never hang.
    #[tokio::test]
    async fn query_against_nonexistent_daemon_times_out_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent_socket = dir.path().join("no-such-daemon.sock");

        let status = tokio::time::timeout(
            Duration::from_secs(2),
            yadorilink_daemon::shell_ipc::client::query_status(&nonexistent_socket, "/some/path"),
        )
        .await
        .expect("query_status must not hang when the daemon isn't running");
        assert_eq!(status, ShellSyncState::Unspecified);
    }

    /// the daemon proactively pushes status updates to connected
    /// clients, not just answering queries.
    #[tokio::test]
    async fn daemon_pushes_status_update_to_connected_client() {
        let (socket_path, state, dir) = start_daemon().await;
        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        // The server task's `push_rx.subscribe` happens after `accept`
        // returns, slightly after the client's `connect` unblocks; a
        // broadcast channel drops sends with no subscribers yet, so give the
        // spawned connection handler a moment to reach its subscribe call.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Simulate a local change being indexed, as the daemon's own link-runtime tasks would do.
        let absolute_path = dir.path().join("photos/new.jpg").to_string_lossy().to_string();
        state.telemetry.push_status(yadorilink_ipc_proto::shellipc::StatusPush {
            path: absolute_path.clone(),
            state: ShellSyncState::Synced as i32,
            local_state: Some(ShellLocalState {
                local_object_present: true,
                current_content_present: true,
                transition: ShellLocalTransition::None as i32,
            }),
        });

        let msg = tokio::time::timeout(
            Duration::from_secs(2),
            read_message::<ShellIpcMessage>(&mut stream),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let Some(Payload::StatusPush(push)) = msg.payload else {
            panic!("expected a StatusPush message")
        };
        assert_eq!(push.path, absolute_path);
        assert_eq!(push.state, ShellSyncState::Synced as i32);
    }

    /// shell-integration spec: "Pause sync for a single item" via the context
    /// menu action, recorded durably against the linked folder's own
    /// relative path.
    #[tokio::test]
    async fn pause_item_context_action_is_recorded() {
        let (socket_path, state, dir) = start_daemon().await;
        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let path = dir.path().join("photos/vacation.jpg").to_string_lossy().to_string();

        write_message(
            &mut stream,
            &ShellIpcMessage {
                payload: Some(Payload::ContextActionRequest(ContextActionRequest {
                    path: path.clone(),
                    action: ContextAction::PauseItem as i32,
                })),
            },
        )
        .await
        .unwrap();

        let resp = read_message::<ShellIpcMessage>(&mut stream).await.unwrap().unwrap();
        let Some(Payload::ContextActionResponse(r)) = resp.payload else {
            panic!("expected a ContextActionResponse")
        };
        assert!(r.ok, "{}", r.error);
        assert_eq!(
            state.replica_coordinator.paused_item_repository().list("group-1").unwrap(),
            vec!["vacation.jpg".to_string()]
        );
    }

    async fn status_of(
        stream: &mut UnixStream,
        path: std::path::PathBuf,
    ) -> yadorilink_ipc_proto::shellipc::StatusResponse {
        let query = ShellIpcMessage {
            payload: Some(Payload::StatusQuery(StatusQuery {
                path: path.to_string_lossy().into_owned(),
            })),
        };
        write_message(stream, &query).await.unwrap();
        let resp = read_message::<ShellIpcMessage>(stream).await.unwrap().unwrap();
        let Some(Payload::StatusResponse(r)) = resp.payload else {
            panic!("expected a StatusResponse")
        };
        r
    }

    /// The status answer says whether the user paused exactly this item (Resume applies), or an
    /// item above it did (neither action applies: resuming the child would not resume anything).
    #[tokio::test]
    async fn status_response_tells_an_own_pause_from_an_inherited_one() {
        let (socket_path, state, dir) = start_daemon().await;
        state.replica_coordinator.paused_item_repository().pause("group-1", "vacation").unwrap();
        // The queried path's parent must exist so the tempdir's own symlinked
        // prefix (macOS `/var` -> `/private/var`) resolves like the link root's.
        std::fs::create_dir_all(dir.path().join("photos/vacation")).unwrap();
        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut answers = Vec::new();
        for rel in ["photos/vacation", "photos/vacation/a.jpg", "photos/other.jpg"] {
            let r = status_of(&mut stream, dir.path().join(rel)).await;
            answers.push((r.item_paused, r.paused_by_ancestor));
        }
        assert_eq!(answers, vec![(true, false), (false, true), (false, false)]);
    }

    /// A child paused under a paused parent: resuming the child would lift nothing, so the
    /// parent's pause is what the menu must report.
    #[tokio::test]
    async fn a_child_paused_under_a_paused_parent_is_still_governed_by_the_parent() {
        let (socket_path, state, dir) = start_daemon().await;
        let pauses = state.replica_coordinator.paused_item_repository();
        pauses.pause("group-1", "vacation").unwrap();
        pauses.pause("group-1", "vacation/a.jpg").unwrap();
        // The queried path's parent must exist so the tempdir's own symlinked
        // prefix (macOS `/var` -> `/private/var`) resolves like the link root's.
        std::fs::create_dir_all(dir.path().join("photos/vacation")).unwrap();
        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let child = status_of(&mut stream, dir.path().join("photos/vacation/a.jpg")).await;
        assert_eq!((child.item_paused, child.paused_by_ancestor), (true, true));
    }

    /// A paused link root: the root itself is paused, everything beneath it inherits.
    #[tokio::test]
    async fn a_paused_root_is_paused_and_its_children_inherit() {
        let (socket_path, state, dir) = start_daemon().await;
        state.replica_coordinator.paused_item_repository().pause("group-1", "").unwrap();
        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let root = status_of(&mut stream, dir.path().join("photos")).await;
        let child = status_of(&mut stream, dir.path().join("photos/a.jpg")).await;
        assert_eq!((root.item_paused, root.paused_by_ancestor), (true, false));
        assert_eq!((child.item_paused, child.paused_by_ancestor), (false, true));
    }

    /// Free Up Space is offered only where the daemon would accept the request: a file whose
    /// current bytes are here, under a root its own eviction gate accepts. In production a plain
    /// linked folder never is, so the menu must not promise it.
    #[tokio::test]
    async fn status_response_offers_free_up_space_only_where_the_daemon_would_accept_it() {
        let (socket_path, state, dir) = start_daemon().await;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "a.jpg".into(),
                    size: 1,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        set_hydrated(&state, "a.jpg");
        let on_disk = dir.path().join("photos/a.jpg");
        std::fs::write(&on_disk, b"x").unwrap();
        yadorilink_daemon::test_support::seed_prior_cycle_proof(
            &state.replica_coordinator,
            "group-1",
            "a.jpg",
            &on_disk,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        );
        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let file = dir.path().join("photos/a.jpg");
        let closed = status_of(&mut stream, file.clone()).await;
        assert!(closed.local_state.is_some_and(|s| s.current_content_present));
        assert!(!closed.free_up_space_offered, "the eviction gate refuses this root");

        state.set_test_on_demand_allowed(true);
        assert!(status_of(&mut stream, file).await.free_up_space_offered);
        let folder = status_of(&mut stream, dir.path().join("photos")).await;
        assert!(!folder.free_up_space_offered, "a folder is never offered");
        let outside = status_of(&mut stream, dir.path().join("elsewhere/a.jpg")).await;
        assert!(!outside.free_up_space_offered, "not under a linked folder");
    }

    /// The daemon states the badge and whether actions apply; a shell derives neither.
    #[tokio::test]
    async fn status_response_states_the_badge_and_whether_actions_apply() {
        use yadorilink_ipc_proto::shellipc::ShellBadge;
        let (socket_path, state, dir) = start_daemon().await;
        for name in ["here.jpg", "away.jpg"] {
            state
                .replica_coordinator
                .file_index_repository()
                .upsert_file(
                    "group-1",
                    &FileRecord {
                        path: name.into(),
                        size: 1,
                        mtime_unix_nanos: 0,
                        blocks: vec![],
                        deleted: false,
                    },
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
        }
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "away.jpg",
                yadorilink_replica_domain::session_state::MaterializationState::Remote,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let away = status_of(&mut stream, dir.path().join("photos/away.jpg")).await;
        assert_eq!(away.badge(), ShellBadge::OnlineOnly);
        assert!(away.actions_available);
        let folder = status_of(&mut stream, dir.path().join("photos")).await;
        assert_eq!(folder.badge(), ShellBadge::Synced);
        assert!(folder.actions_available, "a linked folder is tracked");
        let outside = status_of(&mut stream, dir.path().join("elsewhere/a.jpg")).await;
        assert_eq!(outside.badge(), ShellBadge::Unspecified);
        assert!(!outside.actions_available, "untracked: no mutation actions");
    }

    /// Evicting a hydrated file via the shell extension's
    /// context menu turns it back into a placeholder.
    #[tokio::test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "removing an evicted file needs the Linux write lease"
    )]
    async fn evict_item_context_action_turns_a_hydrated_file_into_a_placeholder() {
        let (socket_path, state, dir) = start_daemon().await;
        // This test is about the eviction gate's own success path, not the
        // on-demand pipeline's real-vs-fake state, so unconditionally
        // connect the fake here. See `DaemonState::
        // set_test_on_demand_allowed`'s own doc comment for why
        // a daemon integration test needs this instead of the production
        // probe (unconditionally `false`) or the free function's
        // thread-local a thread-local override (unreliable across this
        // multi-threaded runtime).
        state.set_test_on_demand_allowed(true);
        // `start_daemon` above only registers the link row in the
        // repository, never a real `LinkRuntimeController::start`/watcher,
        // so `hydration::evict`'s own `root_lease_for` lookup (which
        // resolves through the live runtime registry) has nothing to find.
        // See `install_test_root_commit_authority`'s own doc comment (same
        // pattern used by `multi_peer_hydration.rs` for the same reason).
        state.install_test_root_commit_authority("group-1");
        // `start_daemon` only registers the link row in the repository
        // directly, never adopting a real root identity token the way the
        // control-socket `Link` handler does -- without this, the
        // materialization write path's own `VerifiedRoot::verify` fails
        // with "the link has no previously-adopted root token" once it's
        // reached (which it now is, since the two gates above no longer
        // short-circuit first). See `multi_peer_hydration.rs`'s own
        // `seed_placeholder` for the identical pattern and its doc comment
        // on why this must happen before any index row exists for the
        // group.
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &dir.path().join("photos"),
            "group-1",
            state.replica_coordinator.as_ref(),
        )
        .unwrap();
        let content = vec![7u8; 500];
        std::fs::write(dir.path().join("photos/notes.txt"), &content).unwrap();
        // The block hash must be real, not a placeholder: `evict_file`
        // verifies on-disk bytes against indexed blocks before reclaiming
        // anything, so a hash that cannot possibly match this file's real
        // content makes eviction silently bail out as "changed" (`Ok`, but
        // nothing evicted) rather than actually evicting it -- see
        // `control_socket.rs`'s own `evict_via_control_socket_succeeds_for_
        // an_indexed_hydrated_file` for the identical pattern.
        let hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&content).to_vec()
        };
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "notes.txt".into(),
                    size: 500,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash,
                        offset: 0,
                        size: 500,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // `evict` refuses anything that is not currently hydrated, so
        // without this the handler answers `ok = false` and the test dies on
        // `assert!(r.ok)` (observed on the base at shell_ipc.rs:295) before
        // it ever reaches the placeholder assertion it exists for.
        set_hydrated(&state, "notes.txt");

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let path = dir.path().join("photos/notes.txt").to_string_lossy().to_string();
        write_message(
            &mut stream,
            &ShellIpcMessage {
                payload: Some(Payload::ContextActionRequest(ContextActionRequest {
                    path: path.clone(),
                    action: ContextAction::EvictItem as i32,
                })),
            },
        )
        .await
        .unwrap();

        let resp = read_message::<ShellIpcMessage>(&mut stream).await.unwrap().unwrap();
        let Some(Payload::ContextActionResponse(r)) = resp.payload else {
            panic!("expected a ContextActionResponse")
        };
        assert!(r.ok);
        assert_eq!(
            state
                .replica_coordinator
                .materialization_state_repository()
                .get_materialization_state("group-1", "notes.txt")
                .unwrap(),
            Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
        );
        assert!(
            std::fs::symlink_metadata(dir.path().join("photos/notes.txt")).is_err(),
            "an evicted file must no longer stand in the user tree"
        );
    }

    /// shell-integration spec: an unrelated path outside any linked folder
    /// shows no overlay (`Unspecified`), not an error.
    #[tokio::test]
    async fn status_query_for_unlinked_path_is_unspecified() {
        let (socket_path, _state, _dir) = start_daemon().await;
        let status = yadorilink_daemon::shell_ipc::client::query_status(
            &socket_path,
            "/somewhere/else/file.txt",
        )
        .await;
        assert_eq!(status, ShellSyncState::Unspecified);
    }

    /// on-demand-sync spec "Opening a placeholder triggers hydration" — the
    /// OS-callback-driven path: a `HydrateRequest` for a path
    /// with no reachable peer must fail with a clear, non-hanging error, not
    /// silently succeed or block the connection forever.
    #[tokio::test]
    async fn hydrate_request_for_unreachable_placeholder_returns_an_error() {
        let (socket_path, state, dir) = start_daemon().await;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "big.zip".into(),
                    size: 100,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xABu8; 32],
                        offset: 0,
                        size: 100,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "big.zip",
                yadorilink_replica_domain::session_state::MaterializationState::Remote,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let path = dir.path().join("photos/big.zip").to_string_lossy().to_string();
        write_message(
            &mut stream,
            &ShellIpcMessage { payload: Some(Payload::HydrateRequest(HydrateRequest { path })) },
        )
        .await
        .unwrap();

        let resp = tokio::time::timeout(
            Duration::from_secs(2),
            read_message::<ShellIpcMessage>(&mut stream),
        )
        .await
        .expect("hydrate request must not hang the connection with no peer connected")
        .unwrap()
        .unwrap();
        let Some(Payload::HydrateResponse(r)) = resp.payload else {
            panic!("expected a HydrateResponse")
        };
        assert!(!r.ok);
        assert!(!r.error.is_empty());
    }

    /// A status query reports the materialization state alongside sync state.
    #[tokio::test]
    async fn status_query_reports_materialization_state() {
        let (socket_path, state, dir) = start_daemon().await;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "vacation.jpg".into(),
                    size: 1,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // The assertion below expects `Hydrated`; the schema default is
        // `remote`, so without this the test asserts the default and never
        // exercises the status handler's state reporting at all. `Hydrated`
        // is reported only for content a usable proof names as the current
        // version's, so the object stands on disk under such a proof.
        let on_disk = dir.path().join("photos/vacation.jpg");
        std::fs::write(&on_disk, b"x").unwrap();
        yadorilink_daemon::test_support::seed_prior_cycle_proof(
            &state.replica_coordinator,
            "group-1",
            "vacation.jpg",
            &on_disk,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        );

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let path = dir.path().join("photos/vacation.jpg").to_string_lossy().to_string();
        write_message(
            &mut stream,
            &ShellIpcMessage { payload: Some(Payload::StatusQuery(StatusQuery { path })) },
        )
        .await
        .unwrap();
        let resp = read_message::<ShellIpcMessage>(&mut stream).await.unwrap().unwrap();
        let Some(Payload::StatusResponse(r)) = resp.payload else {
            panic!("expected a StatusResponse")
        };
        let local = r.local_state.expect("an indexed path has a local state");
        assert!(local.local_object_present && local.current_content_present);
    }
} // mod unix_socket_tests

/// The shell-integration IPC protocol
/// exercised above over a Unix socket, but over the Windows named-pipe
/// transport — status query, hydrate request, and the daemon's proactive
/// status push, since `windows_transport` (and now its matching client)
/// had never been run before this change.
#[cfg(windows)]
mod windows_pipe_tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::windows::named_pipe::ClientOptions;
    use yadorilink_daemon::daemon_state::DaemonState;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
    use yadorilink_ipc_proto::shellipc::{
        HydrateRequest, LocalState as ShellLocalState, LocalTransition as ShellLocalTransition,
        ShellIpcMessage, SyncState as ShellSyncState,
    };
    use yadorilink_local_storage::SegmentBlockStore;
    use yadorilink_replica_domain::file::FileRecord;

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_pipe_name() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\yadorilink-shell-test-{}-{n}", std::process::id())
    }

    async fn start_daemon() -> (String, Arc<DaemonState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
        let sync_state =
            Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
        sync_state
            .link_repository()
            .add_link(dir.path().join("photos").to_string_lossy().as_ref(), "group-1")
            .unwrap();
        std::fs::create_dir_all(dir.path().join("photos")).unwrap();

        let state = DaemonState::new("device-a".into(), sync_state, store);
        let pipe_name = unique_pipe_name();
        let serve_name = pipe_name.clone();
        let serve_state =
            Arc::new(yadorilink_daemon::shell_context::ShellContext::from_state(state.clone()));
        tokio::spawn(async move {
            let _ =
                yadorilink_daemon::shell_ipc::windows_transport::serve(&serve_name, serve_state)
                    .await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        (pipe_name, state, dir)
    }

    /// shell-integration spec: "Shell extension queries status via IPC",
    /// exercised through `shell_ipc::client::query_status`'s Windows branch
    /// rather than driving the pipe directly.
    #[tokio::test]
    async fn status_query_reflects_indexed_file_over_named_pipe() {
        let (pipe_name, state, dir) = start_daemon().await;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "vacation.jpg".into(),
                    size: 1,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let status = yadorilink_daemon::shell_ipc::client::query_status(
            &pipe_name,
            &dir.path().join("photos/vacation.jpg").to_string_lossy(),
        )
        .await;
        assert_eq!(status, ShellSyncState::Synced);
    }

    /// The client's fail-soft timeout behavior must also hold on Windows —
    /// no daemon listening on the pipe must not hang, just report
    /// `Unspecified`, matching the Unix client's contract exactly.
    #[tokio::test]
    async fn query_against_nonexistent_pipe_times_out_gracefully() {
        let status = tokio::time::timeout(
            Duration::from_secs(2),
            yadorilink_daemon::shell_ipc::client::query_status(
                r"\\.\pipe\yadorilink-shell-test-nonexistent",
                "/some/path",
            ),
        )
        .await
        .expect("query_status must not hang when the daemon isn't running");
        assert_eq!(status, ShellSyncState::Unspecified);
    }

    /// over the named-pipe transport: the daemon's proactive
    /// status push reaches a connected Windows client.
    #[tokio::test]
    async fn daemon_pushes_status_update_to_connected_client_over_named_pipe() {
        let (pipe_name, state, dir) = start_daemon().await;
        let mut stream = ClientOptions::new().open(&pipe_name).unwrap();
        // Same subscribe-after-accept race as the Unix test — give the
        // spawned connection handler a moment to reach its subscribe call.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let absolute_path = dir.path().join("photos/new.jpg").to_string_lossy().to_string();
        state.telemetry.push_status(yadorilink_ipc_proto::shellipc::StatusPush {
            path: absolute_path.clone(),
            state: ShellSyncState::Synced as i32,
            local_state: Some(ShellLocalState {
                local_object_present: true,
                current_content_present: true,
                transition: ShellLocalTransition::None as i32,
            }),
        });

        let msg = tokio::time::timeout(
            Duration::from_secs(2),
            read_message::<ShellIpcMessage>(&mut stream),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let Some(Payload::StatusPush(push)) = msg.payload else {
            panic!("expected a StatusPush message")
        };
        assert_eq!(push.path, absolute_path);
        assert_eq!(push.state, ShellSyncState::Synced as i32);
    }

    /// on-demand-sync's OS-callback-driven hydrate path, over the
    /// named-pipe transport: an unreachable placeholder must fail cleanly,
    /// not hang the connection.
    #[tokio::test]
    async fn hydrate_request_for_unreachable_placeholder_returns_an_error_over_named_pipe() {
        let (pipe_name, state, dir) = start_daemon().await;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "big.zip".into(),
                    size: 100,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: vec![0xABu8; 32],
                        offset: 0,
                        size: 100,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "big.zip",
                yadorilink_replica_domain::session_state::MaterializationState::Remote,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let mut stream = ClientOptions::new().open(&pipe_name).unwrap();
        let path = dir.path().join("photos/big.zip").to_string_lossy().to_string();
        write_message(
            &mut stream,
            &ShellIpcMessage { payload: Some(Payload::HydrateRequest(HydrateRequest { path })) },
        )
        .await
        .unwrap();

        let resp = tokio::time::timeout(
            Duration::from_secs(2),
            read_message::<ShellIpcMessage>(&mut stream),
        )
        .await
        .expect("hydrate request must not hang the connection with no peer connected")
        .unwrap()
        .unwrap();
        let Some(Payload::HydrateResponse(r)) = resp.payload else {
            panic!("expected a HydrateResponse")
        };
        assert!(!r.ok);
        assert!(!r.error.is_empty());
    }

    /// Regression test for the pipe-instance race
    /// `control_socket::windows_transport`'s doc comment describes: two
    /// clients connecting concurrently must both be served, not have one
    /// hit `ERROR_PIPE_BUSY` because the next instance wasn't created yet.
    #[tokio::test]
    async fn two_concurrent_clients_are_both_served() {
        let (pipe_name, state, dir) = start_daemon().await;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "vacation.jpg".into(),
                    size: 1,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let path_a = dir.path().join("photos/vacation.jpg").to_string_lossy().to_string();
        let path_b = "/somewhere/else/file.txt".to_string();
        let pipe_a = pipe_name.clone();
        let pipe_b = pipe_name.clone();
        let (status_a, status_b) = tokio::join!(
            yadorilink_daemon::shell_ipc::client::query_status(&pipe_a, &path_a),
            yadorilink_daemon::shell_ipc::client::query_status(&pipe_b, &path_b),
        );
        assert_eq!(status_a, ShellSyncState::Synced);
        assert_eq!(status_b, ShellSyncState::Unspecified);
    }
}
