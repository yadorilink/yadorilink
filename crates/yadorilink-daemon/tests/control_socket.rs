//! Exercises the CLI ↔ daemon control protocol
//! end-to-end over a real Unix domain socket, without needing a live
//! coordination plane — link/unlink/pause/resume/status/shutdown
//! only ever talk to the local daemon. Wrapped in `#[cfg(unix)]`
//! (Windows local IPC support) — see `shell_ipc.rs`'s test file for why.
#[cfg(unix)]
mod unix_socket_tests {

    use std::sync::Arc;

    use tokio::net::UnixStream;
    use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
    use yadorilink_daemon::daemon_state::DaemonState;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        ApplicationErrorCode, DaemonControlRequest, DaemonControlResponse, EvictRequest,
        FileAction, HydrateRequest, LinkRequest, LinkStatus, ListConflictsRequest,
        ListLinksRequest, ListTrashRequest, ListVersionsRequest, MaterializationStatusRequest,
        PauseRequest, PendingEnrollmentKind, RestoreTrashRequest, RestoreVersionRequest,
        ResumeRequest, StatusRequest, UnlinkRequest,
    };
    use yadorilink_ipc_proto::daemonctl::{
        PinItemRequest, RetentionPolicy, RetentionState, UnpinItemRequest,
    };
    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_local_storage::SegmentBlockStore;

    async fn start_daemon() -> (std::path::PathBuf, tempfile::TempDir) {
        let (socket_path, dir, _state) = start_daemon_with_state().await;
        (socket_path, dir)
    }

    /// Like `start_daemon`, but also returns the `DaemonState` handle for
    /// tests that need to index files directly (bypassing the watcher
    /// pipeline, which is covered by `local_change`/the daemon's own link-runtime tests).
    async fn start_daemon_with_state() -> (std::path::PathBuf, tempfile::TempDir, Arc<DaemonState>)
    {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
        let state_db = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
        let state = DaemonState::new("device-under-test".into(), state_db, store);
        // A registered (non-empty device_id) device with no change-signing
        // key is fail-closed (`ensure_initial_change_history`):
        // linking a folder refuses index-only sync rather than leave
        // emission silently off. Wire one before any test here links.
        state
            .set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);
        state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
        // Local edits now route through `replica_coordinator`, not
        // `sync_state` (7D-10.7) -- mirror the override there too, or
        // `DaemonState::new`'s real provider fires instead and withholds
        // for lack of a verified group policy.
        state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
        let socket_path = dir.path().join("daemon.sock");

        let serve_path = socket_path.clone();
        let serve_state = state.clone();
        tokio::spawn(async move {
            let _ = yadorilink_daemon::control_socket::unix_transport::serve(
                &serve_path,
                std::sync::Arc::new(
                    yadorilink_daemon::control_context::ControlContext::from_state(serve_state),
                ),
            )
            .await;
        });

        // Give the listener a moment to bind.
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
        read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap()
    }

    /// cli spec: "Link a folder via CLI" / "List linked folders".
    #[tokio::test]
    async fn link_then_list_shows_it() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("photos");
        std::fs::create_dir_all(&folder).unwrap();

        let resp = send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-1".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Link(_))));

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
        assert_eq!(list.links[0].group_id, "group-1");
        assert!(!list.links[0].paused);
    }

    /// The daemon refuses linking a folder that overlaps an already-linked
    /// folder at every confirmation level: nesting is an unsupported topology,
    /// not a risk `acknowledge_risks` can accept. The refusal is the daemon's
    /// alone, since it alone knows every existing link's path.
    #[tokio::test]
    async fn link_refuses_a_nested_link_even_with_acknowledge_risks() {
        let (socket_path, dir) = start_daemon().await;
        let parent = dir.path().join("parent");
        let child = parent.join("child");
        std::fs::create_dir_all(&child).unwrap();

        let resp = send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: parent.to_string_lossy().to_string(),
                group_id: "group-1".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Link(_))));

        // Linking `child` (nested inside the already-linked `parent`) is
        // refused with and without the acknowledgement.
        for acknowledge_risks in [false, true] {
            let resp = send(
                &socket_path,
                ReqPayload::Link(LinkRequest {
                    local_path: child.to_string_lossy().to_string(),
                    group_id: "group-2".into(),
                    on_demand: false,
                    acknowledge_risks,
                    pending_enrollment_operation_id: String::new(),
                    pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                    pending_enrollment_device_id: String::new(),
                }),
            )
            .await;
            let Some(RespPayload::CommandError(error)) = resp.payload else {
                panic!("expected the nested link to be refused, got {:?}", resp.payload)
            };
            assert_eq!(error.code(), ApplicationErrorCode::PathNotAllowed);
            assert!(
                error.message.contains("unsupported link topology"),
                "expected a clear message (acknowledge_risks={acknowledge_risks}), got {:?}",
                error.message
            );
        }

        // The refused link never got registered.
        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
    }

    /// With the on-demand pipeline not connected (the production answer), a
    /// request to link a folder on-demand is refused and leaves no link row
    /// behind: an unsupported root fails closed instead of falling back to
    /// some other placeholder mechanism.
    #[tokio::test]
    async fn link_on_demand_is_refused_while_the_pipeline_is_not_connected() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("remote-docs");
        std::fs::create_dir_all(&folder).unwrap();

        let resp = send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-1".into(),
                on_demand: true,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        let Some(RespPayload::Error(msg)) = resp.payload else {
            panic!("expected the on-demand link to be refused, got {:?}", resp.payload)
        };
        assert!(
            msg.contains("on-demand storage is not available for a regular folder"),
            "got {msg:?}"
        );

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert!(list.links.is_empty(), "a refused link must not be registered: {list:?}");
    }

    /// sync-engine spec: "Pause halts sync activity" / "Resume processes
    /// queued changes" — exercised at the control-protocol level.
    #[tokio::test]
    async fn pause_then_resume_round_trips_through_status() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-2".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let local_path = folder.to_string_lossy().to_string();
        let resp = send(
            &socket_path,
            ReqPayload::Pause(PauseRequest {
                local_path: local_path.clone(),
                ..Default::default()
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Pause(_))));

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert!(status.links[0].paused);

        let resp = send(
            &socket_path,
            ReqPayload::Resume(ResumeRequest { local_path, expected_group_id: String::new() }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Resume(_))));

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert!(!status.links[0].paused);
    }

    /// A timed pause reports its deadline in status, a longer pause replaces it, and
    /// pausing until resumed or resuming clears it.
    #[tokio::test]
    async fn timed_pause_reports_its_deadline_until_replaced_or_resumed() {
        use yadorilink_ipc_proto::daemonctl::PauseDuration;
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-t".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        let local_path = folder.to_string_lossy().to_string();
        let status = |socket_path: std::path::PathBuf| async move {
            let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
            let Some(RespPayload::Status(status)) = resp.payload else {
                panic!("wrong response variant")
            };
            (status.links[0].paused, status.links[0].paused_until_unix)
        };
        let pause = |duration: PauseDuration| {
            let socket_path = socket_path.clone();
            let local_path = local_path.clone();
            async move {
                let resp = send(
                    &socket_path,
                    ReqPayload::Pause(PauseRequest {
                        local_path,
                        duration: duration as i32,
                        expected_group_id: String::new(),
                    }),
                )
                .await;
                assert!(matches!(resp.payload, Some(RespPayload::Pause(_))));
            }
        };
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                as i64;

        pause(PauseDuration::ThirtyMinutes).await;
        let (paused, until) = status(socket_path.clone()).await;
        assert!(paused);
        assert!((now + 1790..=now + 1810).contains(&until), "30 minutes, got {until} at {now}");

        // One hour, not until tomorrow: midnight can be nearer than 30 minutes.
        pause(PauseDuration::OneHour).await;
        let (_, later) = status(socket_path.clone()).await;
        assert!((now + 3590..=now + 3610).contains(&later), "1 hour, got {later} at {now}");

        pause(PauseDuration::Unspecified).await;
        assert_eq!(status(socket_path.clone()).await, (true, 0));

        pause(PauseDuration::UntilTomorrow).await;
        let resp = send(
            &socket_path,
            ReqPayload::Resume(ResumeRequest {
                local_path: local_path.clone(),
                expected_group_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Resume(_))));
        assert_eq!(status(socket_path.clone()).await, (false, 0));
    }

    /// Cancel and retry answer with an error, not a hang or a fake success, for a transfer
    /// this device does not have.
    #[tokio::test]
    async fn cancel_and_retry_of_an_unknown_transfer_are_errors() {
        use yadorilink_ipc_proto::daemonctl::{CancelTransferRequest, RetryTransferRequest};
        let (socket_path, _dir) = start_daemon().await;
        for payload in [
            ReqPayload::CancelTransfer(CancelTransferRequest { transfer_id: "nope".into() }),
            ReqPayload::RetryTransfer(RetryTransferRequest {
                transfer_id: "nope".into(),
                ..Default::default()
            }),
        ] {
            let resp = send(&socket_path, payload).await;
            assert!(matches!(resp.payload, Some(RespPayload::Error(_))), "{:?}", resp.payload);
        }
    }

    /// cli spec: unlinking removes the folder from subsequent listings.
    #[tokio::test]
    async fn unlink_removes_the_link() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("videos");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-3".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        // An eager link makes this device a full replica of the group, but
        // the linked folder is empty -- nothing to hand off, so the
        // durability gate (`ensure_unlink_keeps_a_full_replica`) is
        // vacuously satisfied regardless of any other recorded peer.
        state.authority.set_peer_group_full_replica("device-b", "group-3", true);

        let resp = send(
            &socket_path,
            ReqPayload::Unlink(UnlinkRequest {
                local_path,
                force: false,
                expected_group_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Unlink(_))));

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert!(list.links.is_empty());
    }

    async fn link_at(socket_path: &std::path::Path, local_path: &str, group_id: &str) {
        let resp = send(
            socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.to_string(),
                group_id: group_id.into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        assert!(!matches!(resp.payload, Some(RespPayload::Error(_))), "{:?}", resp.payload);
    }

    async fn only_link(socket_path: &std::path::Path) -> Option<LinkStatus> {
        let resp = send(socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        list.links.into_iter().next()
    }

    fn is_group_mismatch(resp: &DaemonControlResponse) -> bool {
        matches!(&resp.payload, Some(RespPayload::CommandError(e))
            if e.code() == ApplicationErrorCode::GroupMismatch)
    }

    /// An unlink naming the wrong group is refused with a typed refusal and the
    /// link stays; the right group, and no group at all, unlink as before.
    #[tokio::test]
    async fn unlink_with_an_expected_group_checks_it() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("Docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        link_at(&socket_path, &local_path, "group-expect-a").await;
        state.authority.set_peer_group_full_replica("device-b", "group-expect-a", true);

        let unlink = |expected: &str| {
            ReqPayload::Unlink(UnlinkRequest {
                local_path: local_path.clone(),
                force: false,
                expected_group_id: expected.to_string(),
            })
        };
        let resp = send(&socket_path, unlink("group-expect-b")).await;
        assert!(is_group_mismatch(&resp), "{:?}", resp.payload);
        assert_eq!(only_link(&socket_path).await.unwrap().group_id, "group-expect-a");

        let resp = send(&socket_path, unlink("group-expect-a")).await;
        assert!(matches!(resp.payload, Some(RespPayload::Unlink(_))), "{:?}", resp.payload);
        assert!(only_link(&socket_path).await.is_none());

        // Absent: unchanged behaviour.
        link_at(&socket_path, &local_path, "group-expect-a").await;
        let resp = send(&socket_path, unlink("")).await;
        assert!(matches!(resp.payload, Some(RespPayload::Unlink(_))), "{:?}", resp.payload);
        assert!(only_link(&socket_path).await.is_none());
    }

    /// A folder unlinked and linked again to another group is not the folder the
    /// caller looked up: pause and resume refuse and change nothing.
    #[tokio::test]
    async fn pause_and_resume_with_an_expected_group_check_it() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("Docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        link_at(&socket_path, &local_path, "group-expect-a").await;

        let pause = |expected: &str| {
            ReqPayload::Pause(PauseRequest {
                local_path: local_path.clone(),
                expected_group_id: expected.to_string(),
                ..Default::default()
            })
        };
        let resume = |expected: &str| {
            ReqPayload::Resume(ResumeRequest {
                local_path: local_path.clone(),
                expected_group_id: expected.to_string(),
            })
        };

        let resp = send(&socket_path, pause("group-expect-b")).await;
        assert!(is_group_mismatch(&resp), "{:?}", resp.payload);
        assert!(!only_link(&socket_path).await.unwrap().paused);

        let resp = send(&socket_path, pause("group-expect-a")).await;
        assert!(matches!(resp.payload, Some(RespPayload::Pause(_))), "{:?}", resp.payload);
        assert!(only_link(&socket_path).await.unwrap().paused);

        let resp = send(&socket_path, resume("group-expect-b")).await;
        assert!(is_group_mismatch(&resp), "{:?}", resp.payload);
        assert!(only_link(&socket_path).await.unwrap().paused);

        let resp = send(&socket_path, resume("group-expect-a")).await;
        assert!(matches!(resp.payload, Some(RespPayload::Resume(_))), "{:?}", resp.payload);
        assert!(!only_link(&socket_path).await.unwrap().paused);

        // Absent: unchanged behaviour.
        let resp = send(&socket_path, pause("")).await;
        assert!(matches!(resp.payload, Some(RespPayload::Pause(_))), "{:?}", resp.payload);
        let resp = send(&socket_path, resume("")).await;
        assert!(matches!(resp.payload, Some(RespPayload::Resume(_))), "{:?}", resp.payload);

        // The replacement: same path, another group, after the caller's lookup.
        state.authority.set_peer_group_full_replica("device-b", "group-expect-a", true);
        send(
            &socket_path,
            ReqPayload::Unlink(UnlinkRequest {
                local_path: local_path.clone(),
                ..Default::default()
            }),
        )
        .await;
        link_at(&socket_path, &local_path, "group-expect-b").await;
        for stale in [pause("group-expect-a"), resume("group-expect-a")] {
            let resp = send(&socket_path, stale).await;
            assert!(is_group_mismatch(&resp), "{:?}", resp.payload);
        }
        let link = only_link(&socket_path).await.unwrap();
        assert_eq!(link.group_id, "group-expect-b");
        assert!(!link.paused);
        let resp = send(
            &socket_path,
            ReqPayload::Unlink(UnlinkRequest {
                local_path: local_path.clone(),
                expected_group_id: "group-expect-a".into(),
                ..Default::default()
            }),
        )
        .await;
        assert!(is_group_mismatch(&resp), "{:?}", resp.payload);
        assert_eq!(only_link(&socket_path).await.unwrap().group_id, "group-expect-b");
    }

    /// An unlink whose path matches no recorded link must fail loudly and
    /// leave the real link live, never report success.
    #[tokio::test]
    async fn unlink_of_a_path_matching_no_link_is_an_error_and_keeps_the_link() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("Docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-unlink-miss".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let respelled = format!("{local_path}/");
        let resp = send(
            &socket_path,
            ReqPayload::Unlink(UnlinkRequest {
                local_path: respelled,
                force: false,
                expected_group_id: String::new(),
            }),
        )
        .await;
        let Some(RespPayload::Error(message)) = resp.payload else {
            panic!("expected an error for an unmatched path, got {:?}", resp.payload)
        };
        assert!(message.contains("no folder is linked"), "{message}");

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
    }

    /// The daemon's working directory is unrelated to the user's, so a
    /// relative transfer path is refused rather than resolved against it.
    #[tokio::test]
    async fn transfer_requests_with_relative_paths_are_rejected() {
        let (socket_path, _dir) = start_daemon().await;

        let resp = send(
            &socket_path,
            ReqPayload::SendFile(yadorilink_ipc_proto::daemonctl::SendFileRequest {
                source_path: "notes.txt".into(),
                target_device: "laptop".into(),
            }),
        )
        .await;
        let Some(RespPayload::Error(message)) = resp.payload else {
            panic!("expected an error, got {:?}", resp.payload)
        };
        assert!(message.contains("absolute"), "{message}");

        let resp = send(
            &socket_path,
            ReqPayload::ReceiveTransfer(yadorilink_ipc_proto::daemonctl::ReceiveTransferRequest {
                transfer_id: "t".into(),
                destination_dir: "inbox".into(),
            }),
        )
        .await;
        let Some(RespPayload::Error(message)) = resp.payload else {
            panic!("expected an error, got {:?}", resp.payload)
        };
        assert!(message.contains("absolute"), "{message}");
    }

    /// THE C14 SEAM, end to end over the real socket.
    ///
    /// A folder group linked at more than one folder refuses to sync entirely.
    /// That refusal is otherwise only a log line -- loud in the code, silent
    /// where the user actually looks -- so status is what makes it visible, and
    /// the paths it names ARE the remedy, since unlinking is keyed by path.
    ///
    /// Drives `ListLinks` over the socket rather than calling the status builder
    /// directly: the producer of this flag was deletable (hardcode `false` ->
    /// "292 passed; 0 failed") precisely because nothing exercised the wiring.
    #[tokio::test]
    async fn status_reports_a_twice_linked_group_as_ambiguous_and_names_both_folders() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder_a = dir.path().join("aaa-photos");
        let folder_b = dir.path().join("bbb-photos");
        std::fs::create_dir_all(&folder_a).unwrap();
        std::fs::create_dir_all(&folder_b).unwrap();

        state
            .replica_coordinator
            .link_repository()
            .add_link(&folder_a.to_string_lossy(), "group-amb")
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .force_second_live_link_for_test(&folder_b.to_string_lossy(), "group-amb")
            .unwrap();

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant: {:?}", resp.payload)
        };

        for link in &list.links {
            assert!(
                link.ambiguous,
                "a folder group linked at two folders must report as not syncing; otherwise the \
                 refusal is invisible to the user and their folder silently stops syncing"
            );
            let mut named = link.ambiguous_local_paths.clone();
            named.sort();
            assert_eq!(
                named,
                vec![
                    folder_a.to_string_lossy().to_string(),
                    folder_b.to_string_lossy().to_string()
                ],
                "status must name every folder involved -- the paths are the remedy"
            );
        }
        assert_eq!(list.links.len(), 2, "both rows must stay visible for recovery");
    }

    /// A link whose coordination-side authorization is gone no longer syncs;
    /// status must not show it as healthy and up to date.
    #[tokio::test]
    async fn status_reports_an_orphaned_link_as_degraded() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("photos");
        std::fs::create_dir_all(&folder).unwrap();
        let path = folder.to_string_lossy().to_string();
        let links = state.replica_coordinator.link_repository();
        links.add_link(&path, "group-orphan").unwrap();
        links.mark_link_orphaned(&path).unwrap();

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
        assert!(list.links[0].degraded, "an orphaned link is not syncing");
        assert!(!list.links[0].degraded_reason.is_empty());
    }

    /// A healthy one-folder group must NOT be flagged. Without this, hardcoding
    /// `ambiguous: true` would pass the test above and every user would be told
    /// their folders are broken.
    #[tokio::test]
    async fn status_does_not_flag_a_normally_linked_group_as_ambiguous() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("photos");
        std::fs::create_dir_all(&folder).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link(&folder.to_string_lossy(), "group-ok")
            .unwrap();

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
        assert!(!list.links[0].ambiguous, "a group with one folder is not ambiguous");
        assert_eq!(list.links[0].ambiguous_local_paths.len(), 1);
    }

    /// THE UNLINK-RECOVERY SEAM, end to end over the real socket.
    ///
    /// Unlinking one of two roots is the documented recovery, and the handler
    /// must arm the survivor's additive-scan window as part of it: the departed
    /// root's rows stay in the group's index, and the survivor's next scan is
    /// root-scoped and authoritative, so without the flag the remedy deletes the
    /// files it was meant to save.
    ///
    /// Drives the real `Unlink` request: the `arm_additive_scan_for_survivor`
    /// call was deletable at "292 passed; 0 failed" because the only test that
    /// covered this behaviour set the flag by hand and never asked whether
    /// anything in production sets it.
    #[tokio::test]
    async fn unlinking_one_of_two_roots_arms_the_survivors_additive_scan() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder_a = dir.path().join("aaa-photos");
        let folder_b = dir.path().join("bbb-photos");
        std::fs::create_dir_all(&folder_a).unwrap();
        std::fs::create_dir_all(&folder_b).unwrap();

        state
            .replica_coordinator
            .link_repository()
            .add_link(&folder_a.to_string_lossy(), "group-amb")
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .force_second_live_link_for_test(&folder_b.to_string_lossy(), "group-amb")
            .unwrap();
        state.authority.set_peer_group_full_replica("device-b", "group-amb", true);

        // The window starts closed (the column defaults to 0) and nothing in
        // this test opens it, so a pass below means the unlink handler did. It
        // cannot be asserted here directly: while the group is still ambiguous,
        // reading the flag correctly hits the ambiguity gate. The
        // `an_ordinary_unlink_does_not_arm_any_additive_scan` case is what pins
        // that this is not simply armed unconditionally.
        let resp = send(
            &socket_path,
            ReqPayload::Unlink(UnlinkRequest {
                local_path: folder_b.to_string_lossy().to_string(),
                force: false,
                ..Default::default()
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Unlink(_))), "got {:?}", resp.payload);

        assert!(
            state
                .replica_coordinator
                .link_repository()
                .suppress_tombstones_for_group("group-amb")
                .unwrap(),
            "unlinking one of two roots must make the survivor's next scan additive -- otherwise \
             the recovery this error message instructs deletes every file that only existed in \
             the folder the user unlinked, on every device"
        );
    }

    /// An ordinary unlink -- one folder, one group -- must NOT arm the window.
    /// Arming it unconditionally would suppress the next scan's deletions on a
    /// perfectly healthy link, so a real user deletion made while the daemon was
    /// off would never propagate.
    #[tokio::test]
    async fn an_ordinary_unlink_does_not_arm_any_additive_scan() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder_a = dir.path().join("aaa-photos");
        let folder_b = dir.path().join("bbb-photos");
        std::fs::create_dir_all(&folder_a).unwrap();
        std::fs::create_dir_all(&folder_b).unwrap();

        // Two links, but on DIFFERENT groups: nothing ambiguous here.
        state
            .replica_coordinator
            .link_repository()
            .add_link(&folder_a.to_string_lossy(), "group-x")
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link(&folder_b.to_string_lossy(), "group-y")
            .unwrap();
        state.authority.set_peer_group_full_replica("device-b", "group-y", true);

        send(
            &socket_path,
            ReqPayload::Unlink(UnlinkRequest {
                local_path: folder_b.to_string_lossy().to_string(),
                force: false,
                ..Default::default()
            }),
        )
        .await;

        assert!(
            !state
                .replica_coordinator
                .link_repository()
                .suppress_tombstones_for_group("group-x")
                .unwrap(),
            "an unrelated group's link must keep propagating deletions normally"
        );
    }

    /// cli spec: "Status reports per-folder state" — including a live
    /// conflict count derived from the actual index, not just link metadata.
    #[tokio::test]
    async fn status_reports_conflict_count_from_index() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-4".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].conflict_count, 0);
    }

    /// Seeds a conflict copy the way a real one always arrives: with DAG
    /// history behind it.
    ///
    /// A bare `upsert_file` cannot be used for this. `Link` above starts the
    /// real link runtime, and with it the convergence engine's
    /// `retire_unjustified_ephemeral_conflict_copies` loop, which deletes
    /// any conflict copy the group's history does not account for -- exactly
    /// what an index row with no change behind it is. The row was being
    /// seeded and then correctly swept away before the request was served,
    /// so the test raced the retirement loop and lost.
    ///
    /// Returns nothing: callers assert through the control socket, which is
    /// the surface under test.
    fn seed_dag_backed_conflict_copy(
        state: &std::sync::Arc<DaemonState>,
        group_id: &str,
        path: &str,
        content: &[u8],
        mtime_unix_nanos: i64,
    ) {
        use yadorilink_replica_domain::file::{
            BlockInfo, FileMeta, FileRecord, FileVersion, RecordKind, VersionBlock,
        };

        // Real content, not an empty block list: a regular file's version is
        // required to have blocks iff it is non-empty, and its hash is
        // re-derived from its own encoding before it is stored. A version
        // claiming a size with nothing to back it is refused, which is the
        // right answer -- it does not describe anything.
        let hash_hex = state.block_store.put(content).unwrap();
        let hash = hex::decode(&hash_hex).unwrap();
        let size = content.len() as u64;

        let signing_key = state
            .device_signing_key()
            .expect("start_daemon_with_state installs one before anything links");
        let emitter = yadorilink_daemon::test_support::local_seam::replica_author_key(
            &state.replica_coordinator,
            &state.device_id,
            signing_key,
        )
        .unwrap();
        let version = FileVersion::new(
            vec![VersionBlock {
                hash: yadorilink_replica_domain::ids::BlockHash(hash.clone()),
                size: content.len() as u32,
            }],
            size,
            FileMeta {
                mtime_unix_nanos,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        let record = FileRecord {
            path: path.to_string(),
            size,
            mtime_unix_nanos,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };
        yadorilink_daemon::test_support::local_seam::commit_local_upsert(
            &state.replica_coordinator,
            group_id,
            &record,
            &state.device_id,
            &version,
            None,
            &emitter,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    }

    /// `yadorilink conflicts list` -- a live file whose path already
    /// carries the "(conflicted copy" marker `conflict_count` above counts
    /// by is individually listed, tagged with its link's `local_path`; a
    /// plain (non-conflicted) file in the same group is not.
    #[tokio::test]
    async fn list_conflicts_returns_conflicted_copy_files_tagged_by_link() {
        use yadorilink_replica_domain::file::FileRecord;

        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-conflicts".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-conflicts",
                &FileRecord {
                    path: "photo.jpg".into(),
                    size: 5,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        seed_dag_backed_conflict_copy(
            &state,
            "group-conflicts",
            "photo (conflicted copy, 2026-01-01-000000, device-b).jpg",
            b"7 bytes",
            42,
        );

        let resp = send(&socket_path, ReqPayload::ListConflicts(ListConflictsRequest {})).await;
        let Some(RespPayload::ListConflicts(list)) = resp.payload else {
            panic!("wrong response variant: {resp:?}")
        };
        assert_eq!(list.files.len(), 1);
        assert_eq!(list.files[0].local_path, local_path);
        assert_eq!(list.files[0].path, "photo (conflicted copy, 2026-01-01-000000, device-b).jpg");
        assert_eq!(list.files[0].size, 7);
        assert_eq!(list.files[0].mtime_unix_nanos, 42);
    }

    /// A conflict-copy file routinely gets deleted by the retirement sweep
    /// (`retire_unjustified_ephemeral_conflict_copies`) once it's no longer
    /// justified -- this is the ordinary case, not an edge case. Once
    /// deleted, it must disappear from BOTH `ListConflicts` and `status`'s
    /// per-link `conflict_count`, and the two must keep agreeing with each
    /// other throughout: both read the same underlying
    /// `list_live_conflict_copies` query, so there is no way for one to
    /// filter tombstones and the other not to.
    #[tokio::test]
    async fn a_deleted_conflict_copy_disappears_from_both_list_conflicts_and_conflict_count() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-retired-conflict".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let conflict_path = "note (conflicted copy, 2026-01-01-000000, device-b).txt";
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        seed_dag_backed_conflict_copy(&state, "group-retired-conflict", conflict_path, b"note", 0);

        // Still live: both surfaces agree it exists.
        let resp = send(&socket_path, ReqPayload::ListConflicts(ListConflictsRequest {})).await;
        let Some(RespPayload::ListConflicts(list)) = resp.payload else {
            panic!("wrong response variant: {resp:?}")
        };
        assert_eq!(list.files.len(), 1);
        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].conflict_count, 1);

        // The retirement sweep deletes it, same as it would once no unresolved
        // divergence justifies keeping the copy around.
        // Emitted, not a bare tombstone upsert. Once the group has DAG
        // history, a `deleted: true` row written straight through the index
        // has no native authoring identity with `version_seq > 0`, which the
        // `files_require_authoring_identity_on_insert` trigger aborts
        // outright -- the delete has to come from a change like any other.
        let signing_key = state
            .device_signing_key()
            .expect("start_daemon_with_state installs one before anything links");
        let emitter = yadorilink_daemon::test_support::local_seam::replica_author_key(
            &state.replica_coordinator,
            &state.device_id,
            signing_key,
        )
        .unwrap();
        yadorilink_daemon::test_support::local_seam::commit_local_delete(
            &state.replica_coordinator,
            "group-retired-conflict",
            conflict_path,
            &state.device_id,
            0,
            false,
            &emitter,
            &permit,
        )
        .unwrap();

        // Deleted: both surfaces agree it's gone -- neither still counts it.
        let resp = send(&socket_path, ReqPayload::ListConflicts(ListConflictsRequest {})).await;
        let Some(RespPayload::ListConflicts(list)) = resp.payload else {
            panic!("wrong response variant: {resp:?}")
        };
        assert_eq!(list.files.len(), 0, "a deleted conflict copy must not be listed");
        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(
            status.links[0].conflict_count, 0,
            "a deleted conflict copy must not be counted"
        );
    }

    /// A held file (a cross-platform name hazard, held rather than
    /// materialized or auto-renamed) is surfaced over the control socket
    /// with its count, path, reason, and hold timestamp, sourced from
    /// section 1's
    /// `held_reason`/`held_since_unix_nanos` columns via
    /// `SyncState::set_held`/`get_held_state`.
    #[tokio::test]
    async fn status_reports_held_file_count_and_reason() {
        use yadorilink_replica_domain::file::FileRecord;

        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-held".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let record = FileRecord {
            path: "a.txt".into(),
            size: 3,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        };
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-held",
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_held(
                "group-held",
                "a.txt",
                "case-fold collision with existing sibling 'A.txt'",
                123,
            )
            .unwrap();

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].held_file_count, 1);
        assert_eq!(status.links[0].held_files.len(), 1);
        assert_eq!(status.links[0].held_files[0].path, "a.txt");
        assert_eq!(
            status.links[0].held_files[0].reason,
            "case-fold collision with existing sibling 'A.txt'"
        );
        assert_eq!(status.links[0].held_files[0].held_since_unix_nanos, 123);
    }

    /// An unheld, non-symlink file never contributes to
    /// `held_file_count`/`held_files` — the field is
    /// absent (zero/empty), not merely unpopulated, when nothing in the
    /// link is actually held.
    #[tokio::test]
    async fn status_reports_no_held_files_when_none_are_held() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-not-held".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].held_file_count, 0);
        assert!(status.links[0].held_files.is_empty());
        assert_eq!(status.links[0].skipped_symlink_count, 0);
    }

    /// A symlink record with the Windows default-skip-with-visible-status
    /// policy in effect (`windows_symlink_opt_in` left at its default
    /// `false`) counts toward `skipped_symlink_count` when the daemon
    /// itself is running
    /// on Windows, the only platform where a symlink record is ever left
    /// unmaterialized by policy. **Not exercised on this development
    /// machine** (macOS/Linux only, matching section 3.2's own
    /// already-documented limitation) — this runs for real on this
    /// repository's `windows-latest` CI leg (see `.github/workflows/ci.yml`'s
    /// matrix), which is the first real verification of this `#[cfg(windows)]`
    /// path; reviewed carefully against `control_socket.rs`'s
    /// `is_skipped_windows_symlink` but not hand-run locally.
    #[cfg(windows)]
    #[tokio::test]
    async fn status_reports_skipped_windows_symlink_count() {
        use yadorilink_replica_domain::file::{FileRecord, RecordKind};

        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-symlink".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let record = FileRecord {
            path: "link-to-elsewhere".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        };
        state
            .replica_coordinator
            .upsert_file(
                "group-symlink",
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .set_record_kind(
                "group-symlink",
                "link-to-elsewhere",
                RecordKind::Symlink,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .set_symlink_target("group-symlink", "link-to-elsewhere", Some("target.txt"))
            .unwrap();
        // `windows_symlink_opt_in` is left at its default `false` — the
        // default-skip policy this test exercises.

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].skipped_symlink_count, 1);
    }

    /// Same setup as `status_reports_skipped_windows_symlink_count`, but a
    /// Per-link opt-in takes the symlink out of the
    /// default-skip policy — it no longer counts as skipped, since a real
    /// materialization attempt (success or failure) is made instead of a
    /// policy-driven skip. Windows-only for the same reason as its sibling
    /// test above.
    #[cfg(windows)]
    #[tokio::test]
    async fn status_does_not_count_an_opted_in_windows_symlink_as_skipped() {
        use yadorilink_replica_domain::file::{FileRecord, RecordKind};

        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-symlink-optin".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        state.replica_coordinator.set_windows_symlink_opt_in(&local_path, true).unwrap();

        let record = FileRecord {
            path: "link-to-elsewhere".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        };
        state
            .replica_coordinator
            .upsert_file(
                "group-symlink-optin",
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .set_record_kind(
                "group-symlink-optin",
                "link-to-elsewhere",
                RecordKind::Symlink,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .set_symlink_target("group-symlink-optin", "link-to-elsewhere", Some("target.txt"))
            .unwrap();

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].skipped_symlink_count, 0);
    }

    /// Cross-platform counterpart to `status_reports_skipped_windows_symlink_count`,
    /// runnable on this development machine: on a non-Windows daemon, a
    /// symlink record is never counted as policy-skipped, since only the
    /// Windows default-skip branch of `is_skipped_windows_symlink` ever
    /// returns `true` — a symlink materializes normally via
    /// `chunker::materialize_symlink` on every POSIX peer, regardless of
    /// `windows_symlink_opt_in`.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn status_reports_zero_skipped_symlinks_on_non_windows_even_for_a_symlink_record() {
        use yadorilink_replica_domain::file::{FileRecord, RecordKind};

        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-symlink-posix".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let record = FileRecord {
            path: "link-to-elsewhere".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        };
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-symlink-posix",
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .set_record_kind(
                "group-symlink-posix",
                "link-to-elsewhere",
                RecordKind::Symlink,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .set_symlink_target("group-symlink-posix", "link-to-elsewhere", Some(b"target.txt"))
            .unwrap();

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].skipped_symlink_count, 0);
    }

    /// manual eviction round-trips through the
    /// control socket: a hydrated file becomes a placeholder, its sync state
    /// (blocks) untouched.
    #[tokio::test]
    async fn evict_via_control_socket_turns_a_hydrated_file_into_a_placeholder() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-5".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        // No index entry exists for this path (the watcher pipeline that
        // would create one is exercised elsewhere, e.g. `local_change`'s and
        // the daemon's own link-runtime tests) — eviction over the control socket must
        // report a clear error rather than silently no-op'ing on an unknown path.
        let resp = send(
            &socket_path,
            ReqPayload::Evict(EvictRequest {
                absolute_path: folder.join("report.pdf").to_string_lossy().to_string(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Error(_))));
    }

    /// evicting a genuinely-indexed, hydrated
    /// file turns it into a correctly-sized placeholder, over the control
    /// socket end to end.
    #[tokio::test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "removing an evicted file needs the Linux write lease"
    )]
    async fn evict_via_control_socket_succeeds_for_an_indexed_hydrated_file() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        // This test is about the eviction gate's own success path, not the
        // on-demand pipeline's real-vs-fake state, so unconditionally
        // connect the fake here. See `DaemonState::
        // set_test_on_demand_allowed`'s own doc comment for why
        // a daemon integration test needs this instead of the production
        // probe (unconditionally `false`) or the free function's
        // thread-local a thread-local override (unreliable across this
        // multi-threaded runtime).
        state.set_test_on_demand_allowed(true);
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-7".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        // `Link` starts a real, live filesystem watcher for `folder`
        // (`LinkRuntimeController::start`, called from the daemon's own
        // Link handler) -- the write-then-index-directly setup below is
        // meant to bypass that watcher pipeline entirely (see
        // `start_daemon_with_state`'s own doc comment), but the watcher
        // itself does not know that: it can independently notice
        // `report.pdf` appearing on disk and start processing it
        // concurrently with this test's own direct `upsert_file` +
        // immediate `Evict`, racing for the same per-path lock
        // `evict_file`'s non-blocking `try_lock` refuses to wait for.
        // Confirmed as the actual cause of a real CI failure: the eviction
        // was rejected as `{path} is busy` -- the watcher held the lock.
        // Stopping the watch makes the bypass genuine instead of merely
        // likely on a fast host.
        LinkRuntimeController::new(state.clone()).stop(&local_path).await;
        // Stopping the watch above also tears down this link's runtime
        // registration, which is what `hydration::evict`'s own
        // `root_lease_for` lookup resolves through -- without this, eviction
        // fails closed with "no live root-commit authority" instead of
        // reaching the actual behavior under test. See
        // `install_test_root_commit_authority`'s own doc comment (same
        // pattern used by `multi_peer_hydration.rs` for the same reason).
        state.install_test_root_commit_authority("group-7");

        let content = vec![7u8; 1000];
        std::fs::write(folder.join("report.pdf"), &content).unwrap();
        // The block hash must be real, not a placeholder: `evict_file`
        // verifies on-disk bytes against indexed blocks before reclaiming
        // anything, so a hash that cannot possibly match this file's real
        // content makes eviction silently bail out as "changed" (`Ok`, but
        // nothing evicted) rather than actually evicting it.
        let hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&content).to_vec()
        };
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-7",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "report.pdf".into(),
                    size: 1000,
                    mtime_unix_nanos: 0,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash,
                        offset: 0,
                        size: 1000,
                    }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // `upsert_file` alone leaves `materialization_state` at the
        // schema's own default, `Remote` -- not `Present` -- since it
        // is the generic index-write primitive every kind of row (including
        // a not-yet-fetched on-demand placeholder) goes through. This test
        // is specifically about evicting an already-*hydrated* file (see
        // its own doc comment), so that has to be set explicitly here,
        // exactly like the real materialize path would have left it after
        // actually writing `report.pdf`'s bytes to disk. Without this,
        // `evict_file`'s own revalidation snapshot reads `materialization_
        // state != Some(Hydrated)` and silently, correctly, takes its
        // "leave the file materialized" bail-out path -- `dehydrated:
        // false`, `blocks_retained: true` -- which the control socket
        // still reports back as an ordinary `RespPayload::Evict` (a
        // legitimate no-op response, not an error), so eviction appeared
        // to "succeed" while never actually touching the file at all.
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(
                "group-7",
                "report.pdf",
                yadorilink_replica_domain::session_state::MaterializationState::Present,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // `busy` is transient by design: eviction never waits for a path lock,
        // so a background task that still holds it just after the watch stopped
        // gets a refusal that clears on its own. Retry for a bounded time.
        let evict_request = || {
            ReqPayload::Evict(EvictRequest {
                absolute_path: folder.join("report.pdf").to_string_lossy().to_string(),
            })
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut resp = send(&socket_path, evict_request()).await;
        while matches!(&resp.payload, Some(RespPayload::Error(e)) if e.contains("is busy"))
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            resp = send(&socket_path, evict_request()).await;
        }
        assert!(
            matches!(resp.payload, Some(RespPayload::Evict(_))),
            "indexed hydrated file should evict successfully, got {:?}",
            resp.payload
        );

        assert_eq!(
            state
                .replica_coordinator
                .materialization_state_repository()
                .get_materialization_state("group-7", "report.pdf")
                .unwrap(),
            Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
        );
        assert!(
            std::fs::symlink_metadata(folder.join("report.pdf")).is_err(),
            "an evicted file must no longer stand in the user tree"
        );
    }

    /// Evicting a folder over the control socket frees every hydrated file
    /// below it, and only those.
    #[tokio::test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "removing an evicted file needs the Linux write lease"
    )]
    async fn evict_via_control_socket_frees_every_hydrated_file_below_a_folder() {
        use yadorilink_replica_domain::session_state::MaterializationState;
        let (socket_path, dir, state) = start_daemon_with_state().await;
        state.set_test_on_demand_allowed(true);
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(folder.join("album")).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-8".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        // Same direct-index setup as the single-file test above, for the
        // same reasons: no watcher racing the per-path lock, and a live root
        // authority for the eviction to resolve.
        LinkRuntimeController::new(state.clone()).stop(&local_path).await;
        state.install_test_root_commit_authority("group-8");
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let index = state.replica_coordinator.file_index_repository();
        let materialization = state.replica_coordinator.materialization_state_repository();
        for (path, byte) in [("album/a.jpg", 1u8), ("album/b.jpg", 2u8), ("outside.txt", 3u8)] {
            let content = vec![byte; 500];
            std::fs::write(folder.join(path), &content).unwrap();
            let hash = {
                use sha2::{Digest, Sha256};
                Sha256::digest(&content).to_vec()
            };
            let record = yadorilink_replica_domain::file::FileRecord {
                path: path.into(),
                size: 500,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash,
                    offset: 0,
                    size: 500,
                }],
                deleted: false,
            };
            index.upsert_file("group-8", &record, &permit).unwrap();
            materialization
                .set_materialization_state("group-8", path, MaterializationState::Present, &permit)
                .unwrap();
        }

        let resp = send(
            &socket_path,
            ReqPayload::Evict(EvictRequest {
                absolute_path: folder.join("album").to_string_lossy().to_string(),
            }),
        )
        .await;
        let Some(RespPayload::Evict(evicted)) = resp.payload else {
            panic!("a folder of hydrated files should evict, got {:?}", resp.payload)
        };
        assert!(evicted.dehydrated);

        let state_of = |path: &str| materialization.get_materialization_state("group-8", path);
        assert_eq!(state_of("album/a.jpg").unwrap(), Some(MaterializationState::Remote));
        assert_eq!(state_of("album/b.jpg").unwrap(), Some(MaterializationState::Remote));
        assert_eq!(state_of("outside.txt").unwrap(), Some(MaterializationState::Present));
        assert_eq!(std::fs::read(folder.join("outside.txt")).unwrap(), vec![3u8; 500]);
    }

    /// A path the daemon has never indexed reports `known: false`
    /// over the control socket, never a guessed default state.
    #[tokio::test]
    async fn materialization_status_via_control_socket_reports_unknown_for_an_unindexed_path() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-status-1".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let resp = send(
            &socket_path,
            ReqPayload::MaterializationStatus(MaterializationStatusRequest {
                absolute_path: folder.join("never-seen.bin").to_string_lossy().to_string(),
            }),
        )
        .await;
        match resp.payload {
            Some(RespPayload::MaterializationStatus(status)) => {
                assert!(!status.known);
            }
            other => panic!("expected a MaterializationStatus response, got {other:?}"),
        }
    }

    /// An indexed file's real materialization state round-trips through the
    /// control socket exactly, end to end.
    #[tokio::test]
    async fn materialization_status_via_control_socket_reports_the_real_state() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-status-2".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        LinkRuntimeController::new(state.clone()).stop(&local_path).await;

        std::fs::write(folder.join("report.pdf"), vec![7u8; 10]).unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-status-2",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "report.pdf".into(),
                    size: 10,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // `current_content_present` is reported only for content a usable
        // proof names as the current version's; `Present` alone says an
        // object exists.
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(
                "group-status-2",
                "report.pdf",
                yadorilink_replica_domain::session_state::MaterializationState::Present,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let path = folder.join("report.pdf").to_string_lossy().to_string();
        let before = send(
            &socket_path,
            ReqPayload::MaterializationStatus(MaterializationStatusRequest {
                absolute_path: path.clone(),
            }),
        )
        .await;
        match before.payload {
            Some(RespPayload::MaterializationStatus(status)) => {
                let local = status.local_state.expect("an indexed path has a local state");
                assert!(local.local_object_present, "the object stands");
                assert!(!local.current_content_present, "no proof names the current version");
                // An ordinary folder downloads a placeholder through the daemon.
                assert_eq!(
                    status.available_actions,
                    vec![FileAction::Download as i32, FileAction::KeepOnDevice as i32]
                );
            }
            other => panic!("expected a MaterializationStatus response, got {other:?}"),
        }
        yadorilink_daemon::test_support::seed_prior_cycle_proof(
            &state.replica_coordinator,
            "group-status-2",
            "report.pdf",
            &folder.join("report.pdf"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        );

        let resp = send(
            &socket_path,
            ReqPayload::MaterializationStatus(MaterializationStatusRequest {
                absolute_path: folder.join("report.pdf").to_string_lossy().to_string(),
            }),
        )
        .await;
        match resp.payload {
            Some(RespPayload::MaterializationStatus(status)) => {
                assert!(status.known);
                let local = status.local_state.expect("an indexed path has a local state");
                assert!(local.local_object_present);
                assert!(local.current_content_present);
                // An ordinary folder can keep a file but never give its space back.
                assert_eq!(status.available_actions, vec![FileAction::KeepOnDevice as i32]);
            }
            other => panic!("expected a MaterializationStatus response, got {other:?}"),
        }
    }

    /// hydrate with no peer connected must return a clear error over the
    /// control socket, not hang the connection.
    #[tokio::test]
    async fn hydrate_without_a_connected_peer_returns_a_clear_error() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path,
                group_id: "group-6".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let nope_path = folder.join("nope.bin").to_string_lossy().to_string();

        let resp =
            send(&socket_path, ReqPayload::Hydrate(HydrateRequest { absolute_path: nope_path }))
                .await;
        assert!(matches!(resp.payload, Some(RespPayload::Error(_))));
    }
    /// `ListVersions`/`RestoreVersion` round-trip against a running
    /// daemon — an edit produces a superseded version, `versions` lists
    /// both (newest first, including current), and restoring the
    /// superseded version writes its content back to disk as a brand-new
    /// current version (never rewrites history).
    #[tokio::test]
    async fn list_versions_then_restore_version_round_trips_through_control_socket() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path,
                group_id: "group-versions".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let v1_hash = state.block_store.put(b"version one").unwrap();
        let v1_block = yadorilink_replica_domain::file::BlockInfo {
            hash: hex::decode(&v1_hash).unwrap(),
            offset: 0,
            size: 11,
        };
        // Mirrors what `LocalChangeProcessor` does for a real local edit
        // (`record_group_block_provenance`'s doc comment): without this, a
        // restore treats a block this test poked directly into the store as
        // never having been obtained through the group, and refuses it.
        state
            .replica_coordinator
            .record_block_provenance("group-versions", std::slice::from_ref(&v1_block.hash))
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(
                "group-versions",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "notes.txt".into(),
                    size: 11,
                    mtime_unix_nanos: 1,
                    blocks: vec![v1_block.clone()],
                    deleted: false,
                },
                "device-a",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let v2_hash = state.block_store.put(b"version two!").unwrap();
        let v2_block = yadorilink_replica_domain::file::BlockInfo {
            hash: hex::decode(&v2_hash).unwrap(),
            offset: 0,
            size: 12,
        };
        state
            .replica_coordinator
            .record_block_provenance("group-versions", std::slice::from_ref(&v2_block.hash))
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(
                "group-versions",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "notes.txt".into(),
                    size: 12,
                    mtime_unix_nanos: 2,
                    blocks: vec![v2_block],
                    deleted: false,
                },
                "device-a",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let absolute_path = folder.join("notes.txt").to_string_lossy().to_string();
        let resp = send(
            &socket_path,
            ReqPayload::ListVersions(ListVersionsRequest { absolute_path: absolute_path.clone() }),
        )
        .await;
        let Some(RespPayload::ListVersions(list)) = resp.payload else {
            panic!("wrong response variant: {resp:?}")
        };
        assert_eq!(list.versions.len(), 2, "both versions must be listed, including current");
        assert_eq!(list.versions[0].version_seq, 2, "newest first");
        assert_eq!(list.versions[0].state, "current");
        assert_eq!(list.versions[0].origin_device_id, "device-a");
        assert_eq!(list.versions[1].version_seq, 1);
        assert_eq!(list.versions[1].state, "superseded");

        let resp = send(
            &socket_path,
            ReqPayload::RestoreVersion(RestoreVersionRequest {
                absolute_path: absolute_path.clone(),
                version_seq: Some(1),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::RestoreVersion(_))), "{resp:?}");

        assert_eq!(std::fs::read(folder.join("notes.txt")).unwrap(), b"version one");
        let versions = state
            .replica_coordinator
            .sqlite()
            .dag_list_versions("group-versions", "notes.txt")
            .unwrap();
        assert_eq!(versions.len(), 3, "restore must add a new version, not rewrite history");
        assert_eq!(versions[0].version_seq, 3);
        assert_eq!(versions[0].blocks, vec![v1_block]);
    }

    /// `RestoreVersion` with no `version_seq` defaults to the most
    /// recent superseded version (spec "Restore without a version defaults
    /// to the most recent superseded version").
    #[tokio::test]
    async fn restore_version_without_a_version_seq_defaults_to_most_recent_superseded() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path,
                group_id: "group-default-restore".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let v1_hash = state.block_store.put(b"first").unwrap();
        let v1_block = yadorilink_replica_domain::file::BlockInfo {
            hash: hex::decode(&v1_hash).unwrap(),
            offset: 0,
            size: 5,
        };
        // See the identical comment in `list_versions_then_restore_version_
        // round_trips_through_control_socket` above.
        state
            .replica_coordinator
            .record_block_provenance("group-default-restore", std::slice::from_ref(&v1_block.hash))
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(
                "group-default-restore",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "todo.txt".into(),
                    size: 5,
                    mtime_unix_nanos: 1,
                    blocks: vec![v1_block.clone()],
                    deleted: false,
                },
                "device-a",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let v2_hash = hex::decode(state.block_store.put(b"second content").unwrap()).unwrap();
        state
            .replica_coordinator
            .record_block_provenance("group-default-restore", std::slice::from_ref(&v2_hash))
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(
                "group-default-restore",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "todo.txt".into(),
                    size: 14,
                    mtime_unix_nanos: 2,
                    blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                        hash: v2_hash,
                        offset: 0,
                        size: 14,
                    }],
                    deleted: false,
                },
                "device-a",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let absolute_path = folder.join("todo.txt").to_string_lossy().to_string();
        let resp = send(
            &socket_path,
            ReqPayload::RestoreVersion(RestoreVersionRequest {
                absolute_path: absolute_path.clone(),
                version_seq: None,
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::RestoreVersion(_))), "{resp:?}");
        assert_eq!(std::fs::read(folder.join("todo.txt")).unwrap(), b"first");

        // No superseded version at all -> clear error, not a silent no-op.
        let folder2 = dir.path().join("empty");
        std::fs::create_dir_all(&folder2).unwrap();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder2.to_string_lossy().to_string(),
                group_id: "group-no-superseded".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(
                "group-no-superseded",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "solo.txt".into(),
                    size: 0,
                    mtime_unix_nanos: 1,
                    blocks: vec![],
                    deleted: false,
                },
                "device-a",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let resp = send(
            &socket_path,
            ReqPayload::RestoreVersion(RestoreVersionRequest {
                absolute_path: folder2.join("solo.txt").to_string_lossy().to_string(),
                version_seq: None,
            }),
        )
        .await;
        let Some(RespPayload::Error(msg)) = resp.payload else { panic!("expected an error") };
        assert!(msg.contains("superseded"), "expected a clear message, got {msg:?}");
    }

    /// the missing-blocks restore failure path surfaces
    /// `SyncError::VersionContentUnavailable` specifically over IPC, not a
    /// generic error message — `RespPayload::Error` is just `e.to_string`,
    /// so this checks the text actually identifies unavailable version
    /// content (see that variant's `#[error(...)]` text in `error.rs`).
    #[tokio::test]
    async fn restore_version_with_missing_blocks_surfaces_a_distinguishable_error() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path,
                group_id: "group-missing-blocks".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        // A version referencing a block never actually written to this
        // device's block store (as if evicted, or never fetched).
        let phantom_block = yadorilink_replica_domain::file::BlockInfo {
            hash: {
                use sha2::{Digest, Sha256};
                Sha256::digest(b"never fetched").to_vec()
            },
            offset: 0,
            size: 13,
        };
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(
                "group-missing-blocks",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "phantom.bin".into(),
                    size: 13,
                    mtime_unix_nanos: 1,
                    blocks: vec![phantom_block],
                    deleted: false,
                },
                "device-a",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let resp = send(
            &socket_path,
            ReqPayload::RestoreVersion(RestoreVersionRequest {
                absolute_path: folder.join("phantom.bin").to_string_lossy().to_string(),
                version_seq: Some(1),
            }),
        )
        .await;
        let Some(RespPayload::Error(msg)) = resp.payload else {
            panic!("expected an error, got {resp:?}")
        };
        assert!(
            msg.contains("unavailable") && msg.to_lowercase().contains("version"),
            "expected a message identifying unavailable version content, got {msg:?}"
        );
        assert!(!folder.join("phantom.bin").exists(), "a failed restore must not create a file");
    }

    /// `ListTrash`/`RestoreTrash` round-trip — a deleted file
    /// shows up in `trash list`, and `trash restore` recovers it as a new
    /// live current version.
    #[tokio::test]
    async fn list_trash_then_restore_trash_round_trips_through_control_socket() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-trash".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let hash = state.block_store.put(b"soon deleted").unwrap();
        let block = yadorilink_replica_domain::file::BlockInfo {
            hash: hex::decode(&hash).unwrap(),
            offset: 0,
            size: 12,
        };
        // See the identical comment in `list_versions_then_restore_version_
        // round_trips_through_control_socket` above.
        state
            .replica_coordinator
            .record_block_provenance("group-trash", std::slice::from_ref(&block.hash))
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(
                "group-trash",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "gone.txt".into(),
                    size: 12,
                    mtime_unix_nanos: 1,
                    blocks: vec![block],
                    deleted: false,
                },
                "device-a",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .mark_deleted(
                "group-trash",
                "gone.txt",
                "device-a",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let resp = send(&socket_path, ReqPayload::ListTrash(ListTrashRequest {})).await;
        let Some(RespPayload::ListTrash(list)) = resp.payload else {
            panic!("wrong response variant: {resp:?}")
        };
        assert_eq!(list.files.len(), 1);
        assert_eq!(list.files[0].local_path, local_path);
        assert_eq!(list.files[0].path, "gone.txt");
        assert_eq!(list.files[0].last_known_size, 12);
        assert_eq!(list.files[0].origin_device_id, "device-a");

        let resp = send(
            &socket_path,
            ReqPayload::RestoreTrash(RestoreTrashRequest {
                absolute_path: folder.join("gone.txt").to_string_lossy().to_string(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::RestoreTrash(_))), "{resp:?}");

        assert_eq!(std::fs::read(folder.join("gone.txt")).unwrap(), b"soon deleted");
        let current = state
            .replica_coordinator
            .file_index_repository()
            .get_file("group-trash", "gone.txt")
            .unwrap()
            .unwrap();
        assert!(!current.deleted, "the file must be live again after a trash restore");
    }
    /// A retained original is listed over the control socket, counted in `status`, and a release
    /// for a group the device knows nothing of is an error, not an empty answer.
    #[tokio::test]
    async fn retained_originals_are_listed_and_a_release_for_an_unknown_group_is_refused() {
        use yadorilink_ipc_proto::daemonctl::{
            ListRetainedOriginalsRequest, ReleaseRetainedOriginalsRequest,
        };
        let (socket_path, _dir, state) = start_daemon_with_state().await;
        state
            .replica_coordinator
            .database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                tx.execute(
                    "INSERT INTO native_rebootstrap_quarantine \
                     (group_id, recovery_id, path, status, removal_claim) \
                     VALUES ('gone-group', 'rid', 'a.txt', 'retained', '0123456789abcdef')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();

        let resp =
            send(&socket_path, ReqPayload::ListRetainedOriginals(ListRetainedOriginalsRequest {}))
                .await;
        let Some(RespPayload::ListRetainedOriginals(list)) = resp.payload else {
            panic!("wrong response variant: {:?}", resp.payload)
        };
        assert_eq!(list.items.len(), 1);
        let item = &list.items[0];
        assert_eq!((item.group_id.as_str(), item.path.as_str()), ("gone-group", "a.txt"));
        assert!(item.group_removed && !item.reachable);

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else { panic!("wrong variant") };
        assert_eq!(status.preserved.unwrap().retained_originals, 1);

        let resp = send(
            &socket_path,
            ReqPayload::ReleaseRetainedOriginals(ReleaseRetainedOriginalsRequest {
                group_id: "no-such-group".into(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Error(_))), "{:?}", resp.payload);
    }

    /// The release the storage window asks for, over the real control socket, against a linked
    /// folder: an original kept under its claim with its recorded fingerprint is removed where
    /// the platform proves no writer can hold it (Linux), and reported as still retained where
    /// it cannot; the answer names the outcome the window turns into its message.
    #[tokio::test]
    async fn a_kept_original_is_released_over_the_socket_where_the_platform_can_prove_it() {
        use yadorilink_fs_platform::reserved_namespace::{artefact_component_name, ArtefactKind};
        use yadorilink_ipc_proto::daemonctl::ReleaseRetainedOriginalsRequest;
        use yadorilink_sync_sqlite::native_rebootstrap_install::observe_regular_file;
        use yadorilink_sync_sqlite::native_rebootstrap_retained::kept_fingerprint;
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("kept-folder");
        std::fs::create_dir_all(&folder).unwrap();
        link_folder(&socket_path, &folder, "group-kept").await;
        let claim = "0123456789abcdef";
        let kept = folder.join(artefact_component_name(ArtefactKind::Preimage, claim).unwrap());
        std::fs::write(&kept, b"the old bytes").unwrap();
        let fingerprint =
            kept_fingerprint(&observe_regular_file(std::fs::File::open(&kept).unwrap()).unwrap())
                .unwrap();
        state
            .replica_coordinator
            .database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                tx.execute(
                    "INSERT INTO native_rebootstrap_quarantine \
                     (group_id, recovery_id, path, status, removal_claim) \
                     VALUES ('group-kept', 'rid', 'old.txt', 'retained', ?1)",
                    [claim],
                )?;
                tx.execute(
                    "INSERT INTO native_rebootstrap_retained_digest \
                     (group_id, recovery_id, path, fingerprint) \
                     VALUES ('group-kept', 'rid', 'old.txt', ?1)",
                    [fingerprint.as_slice()],
                )?;
                Ok(())
            })
            .unwrap();

        // The group's startup continuation holds its machine claim for a moment; the daemon
        // answers "try again" until it is done.
        let mut resp;
        let mut tries = 0;
        loop {
            resp = send(
                &socket_path,
                ReqPayload::ReleaseRetainedOriginals(ReleaseRetainedOriginalsRequest {
                    group_id: "group-kept".into(),
                }),
            )
            .await;
            tries += 1;
            if !matches!(&resp.payload, Some(RespPayload::Error(e)) if e.contains("try again"))
                || tries > 100
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        let Some(RespPayload::ReleaseRetainedOriginals(done)) = resp.payload else {
            panic!("wrong response variant: {:?}", resp.payload)
        };
        let proved = cfg!(any(target_os = "linux", windows));
        let outcomes: Vec<_> =
            done.releases.iter().map(|r| (r.path.as_str(), r.outcome.as_str())).collect();
        if proved {
            // The folder's own startup continuation may already have released it, which
            // leaves nothing for this request to report.
            assert!(outcomes == [("old.txt", "removed")] || outcomes.is_empty(), "{outcomes:?}");
        } else {
            assert_eq!(outcomes, [("old.txt", "still_retained")]);
        }
        let expected = if proved { "removed" } else { "still_retained" };
        assert_eq!(kept.exists(), expected == "still_retained");
        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else { panic!("wrong variant") };
        assert_eq!(status.preserved.unwrap().retained_originals, u32::from(kept.exists()));
    }

    async fn link_folder(socket_path: &std::path::Path, folder: &std::path::Path, group: &str) {
        let resp = send(
            socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: group.into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Link(_))), "{resp:?}");
    }

    async fn retention_of(socket_path: &std::path::Path, path: &std::path::Path) -> RetentionState {
        let resp = send(
            socket_path,
            ReqPayload::MaterializationStatus(MaterializationStatusRequest {
                absolute_path: path.to_string_lossy().to_string(),
            }),
        )
        .await;
        let Some(RespPayload::MaterializationStatus(status)) = resp.payload else {
            panic!("expected a MaterializationStatus response, got {resp:?}")
        };
        status.retention.expect("a path under a linked folder reports its retention")
    }

    fn pinned(explicit: bool) -> RetentionState {
        RetentionState { policy: RetentionPolicy::Pinned as i32, explicit }
    }

    fn reclaimable() -> RetentionState {
        RetentionState { policy: RetentionPolicy::Reclaimable as i32, explicit: false }
    }

    /// The retention policy is a standing choice, reported apart from the
    /// materialization state, and a folder's pin is inherited beneath it.
    #[tokio::test]
    async fn pin_and_unpin_over_the_control_socket_set_the_policy_and_inherit_by_folder() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(folder.join("album")).unwrap();
        link_folder(&socket_path, &folder, "group-pin").await;
        let album = folder.join("album");
        let photo = album.join("one.jpg");

        assert_eq!(retention_of(&socket_path, &photo).await, reclaimable());

        // The path is not indexed, so there is nothing to download; the pin stands regardless.
        let resp = send(
            &socket_path,
            ReqPayload::PinItem(PinItemRequest {
                absolute_path: album.to_string_lossy().to_string(),
            }),
        )
        .await;
        let Some(RespPayload::PinItem(pin)) = resp.payload else { panic!("{resp:?}") };
        assert_eq!(pin.retention, Some(pinned(true)));
        assert_eq!(retention_of(&socket_path, &album).await, pinned(true));
        assert_eq!(retention_of(&socket_path, &photo).await, pinned(false), "inherited");

        // No per-child override: the child stays pinned and the answer says so.
        let resp = send(
            &socket_path,
            ReqPayload::UnpinItem(UnpinItemRequest {
                absolute_path: photo.to_string_lossy().to_string(),
            }),
        )
        .await;
        let Some(RespPayload::UnpinItem(unpin)) = resp.payload else { panic!("{resp:?}") };
        assert_eq!(unpin.retention, Some(pinned(false)));

        let resp = send(
            &socket_path,
            ReqPayload::UnpinItem(UnpinItemRequest {
                absolute_path: album.to_string_lossy().to_string(),
            }),
        )
        .await;
        let Some(RespPayload::UnpinItem(unpin)) = resp.payload else { panic!("{resp:?}") };
        assert_eq!(unpin.retention, Some(reclaimable()));
        assert_eq!(retention_of(&socket_path, &photo).await, reclaimable());
    }

    /// A path outside every linked folder has no policy to set.
    #[tokio::test]
    async fn pinning_a_path_outside_every_linked_folder_is_an_error() {
        let (socket_path, dir) = start_daemon().await;
        let resp = send(
            &socket_path,
            ReqPayload::PinItem(PinItemRequest {
                absolute_path: dir.path().join("elsewhere.txt").to_string_lossy().to_string(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Error(_))), "{resp:?}");
    }
} // mod unix_socket_tests

/// the same control protocol exercised
/// above over a Unix socket, but over the Windows named-pipe transport —
/// only compiled/run on Windows, where `unix_transport` isn't available at
/// all. Uses a per-test unique pipe name: named pipes live in
/// the `\\.\pipe\` namespace, not the filesystem, so `tempfile::tempdir`
/// isolation doesn't apply the way it does for the Unix-socket tests above.
#[cfg(windows)]
mod windows_pipe_tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use tokio::net::windows::named_pipe::ClientOptions;
    use yadorilink_daemon::daemon_state::DaemonState;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        DaemonControlRequest, DaemonControlResponse, LinkRequest, ListLinksRequest, PauseRequest,
        PendingEnrollmentKind, ResumeRequest, StatusRequest,
    };
    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_local_storage::SegmentBlockStore;

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_pipe_name() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\yadorilink-test-{}-{n}", std::process::id())
    }

    async fn start_daemon() -> (String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
        let state_db = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
        let state = DaemonState::new("device-under-test".into(), state_db, store);
        // See the identical comment in the Unix `start_daemon_with_state` above.
        state
            .set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);
        state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
        // Local edits now route through `replica_coordinator`, not
        // `sync_state` (7D-10.7) -- mirror the override there too, or
        // `DaemonState::new`'s real provider fires instead and withholds
        // for lack of a verified group policy.
        state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
        let pipe_name = unique_pipe_name();

        let serve_name = pipe_name.clone();
        tokio::spawn(async move {
            let _ = yadorilink_daemon::control_socket::windows_transport::serve(
                &serve_name,
                std::sync::Arc::new(
                    yadorilink_daemon::control_context::ControlContext::from_state(state),
                ),
            )
            .await;
        });

        // Give the listener a moment to create the first pipe instance.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        (pipe_name, dir)
    }

    async fn send(pipe_name: &str, payload: ReqPayload) -> DaemonControlResponse {
        let mut stream = ClientOptions::new().open(pipe_name).unwrap();
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

    #[tokio::test]
    async fn link_then_list_shows_it_over_named_pipe() {
        let (pipe_name, dir) = start_daemon().await;
        let folder = dir.path().join("photos");
        std::fs::create_dir_all(&folder).unwrap();

        let resp = send(
            &pipe_name,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-1".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Link(_))));

        let resp = send(&pipe_name, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
        assert_eq!(list.links[0].group_id, "group-1");
    }

    /// Confirms the daemon really is serving multiple connections
    /// concurrently over the named pipe (the pre-create-next-instance
    /// pattern), not just one client ever.
    #[tokio::test]
    async fn pause_then_resume_round_trips_over_named_pipe() {
        let (pipe_name, dir) = start_daemon().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        send(
            &pipe_name,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-2".into(),
                on_demand: false,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let local_path = folder.to_string_lossy().to_string();
        let resp = send(
            &pipe_name,
            ReqPayload::Pause(PauseRequest {
                local_path: local_path.clone(),
                ..Default::default()
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Pause(_))));

        let resp = send(&pipe_name, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert!(status.links[0].paused);

        let resp = send(
            &pipe_name,
            ReqPayload::Resume(ResumeRequest { local_path, expected_group_id: String::new() }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Resume(_))));
    }

    /// A second, concurrent client connecting while the first is mid-flight
    /// must not be refused — the daemon's next-instance-pre-created pattern
    ///  exists specifically so this works.
    #[tokio::test]
    async fn two_concurrent_clients_are_both_served() {
        let (pipe_name, dir) = start_daemon().await;
        let folder_a = dir.path().join("a");
        let folder_b = dir.path().join("b");
        std::fs::create_dir_all(&folder_a).unwrap();
        std::fs::create_dir_all(&folder_b).unwrap();

        let pipe_a = pipe_name.clone();
        let pipe_b = pipe_name.clone();
        let (resp_a, resp_b) = tokio::join!(
            send(
                &pipe_a,
                ReqPayload::Link(LinkRequest {
                    local_path: folder_a.to_string_lossy().to_string(),
                    group_id: "group-a".into(),
                    on_demand: false,
                    acknowledge_risks: true,
                    pending_enrollment_operation_id: String::new(),
                    pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                    pending_enrollment_device_id: String::new(),
                }),
            ),
            send(
                &pipe_b,
                ReqPayload::Link(LinkRequest {
                    local_path: folder_b.to_string_lossy().to_string(),
                    group_id: "group-b".into(),
                    on_demand: false,
                    acknowledge_risks: true,
                    pending_enrollment_operation_id: String::new(),
                    pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                    pending_enrollment_device_id: String::new(),
                }),
            ),
        );
        assert!(matches!(resp_a.payload, Some(RespPayload::Link(_))));
        assert!(matches!(resp_b.payload, Some(RespPayload::Link(_))));
    }
}
