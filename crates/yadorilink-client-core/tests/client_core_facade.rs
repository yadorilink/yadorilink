//! The product facade against a stand-in daemon on a real socket, and
//! against no daemon at all.
#![cfg(unix)]

use std::time::Duration;

use yadorilink_client_core::dto::{CoreConfig, DaemonLaunch, FolderMode, StatusUpdate};
use yadorilink_client_core::error::{DaemonUnavailableReason, DesktopError};
use yadorilink_client_core::ClientCore;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ApplicationCommandError, ApplicationErrorCode, DaemonControlRequest, DaemonControlResponse,
    IdentifyResponse, LinkStatus, ListLinksResponse, StatusResponse, CONTROL_PROTOCOL_VERSION,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};

/// The tests share `YADORILINK_CONTROL_SOCKET`, a process-global variable.
static SOCKET_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn core() -> std::sync::Arc<ClientCore> {
    ClientCore::new(CoreConfig { daemon_launch: DaemonLaunch::SpawnBinary { path: None } })
}

/// Serves every request with `respond` until the test ends.
fn serve(
    socket: &std::path::Path,
    respond: impl Fn(DaemonControlRequest) -> RespPayload + Send + Sync + 'static,
) {
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let respond = std::sync::Arc::new(respond);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let respond = respond.clone();
            tokio::spawn(async move {
                // A state-changing request is preceded by the client's release check on the
                // same connection, so serve requests until the client closes it.
                while let Ok(Some(request)) =
                    read_message::<DaemonControlRequest>(&mut stream).await
                {
                    let payload = if matches!(request.payload, Some(ReqPayload::Identify(_))) {
                        RespPayload::Identify(IdentifyResponse {
                            engine_api_version: yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION,
                            ..Default::default()
                        })
                    } else {
                        respond(request)
                    };
                    let response = DaemonControlResponse {
                        daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
                        payload: Some(payload),
                    };
                    if write_message(&mut stream, &response).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

fn linked_docs() -> LinkStatus {
    LinkStatus { local_path: "/f/Docs".into(), group_id: "g1".into(), ..Default::default() }
}

#[tokio::test]
async fn status_snapshot_maps_unreachable_daemon_to_daemon_unavailable() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("nobody-home.sock"));

    let error = core().status_snapshot().await.unwrap_err();
    assert!(
        matches!(
            error,
            DesktopError::DaemonUnavailable { reason: DaemonUnavailableReason::NotRunning, .. }
        ),
        "{error:?}"
    );

    let watch = core().watch_status(Duration::from_millis(20));
    let update = tokio::time::timeout(Duration::from_secs(5), watch.next()).await.unwrap();
    assert!(
        matches!(update, Some(StatusUpdate::Unavailable { ref error }) if error.is_daemon_unavailable()),
        "{update:?}"
    );
    watch.cancel();

    let account = core().account_status().await;
    assert_eq!(account.has_linked_folders, None, "unknown while the daemon is down");
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

#[tokio::test]
async fn status_and_folder_detail_read_the_daemons_status() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    serve(&socket, |_| {
        RespPayload::Status(StatusResponse {
            links: vec![linked_docs()],
            overall_state: "healthy".into(),
            ..Default::default()
        })
    });
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

    let snapshot = core().status_snapshot().await.unwrap();
    assert_eq!(snapshot.folders.len(), 1);
    assert_eq!(snapshot.folders[0].name, "Docs");

    let detail = core().folder_detail("/f/Docs".into()).await.unwrap();
    assert_eq!(detail.summary.group_id, "g1");
    let missing = core().folder_detail("/f/Other".into()).await.unwrap_err();
    assert!(
        matches!(missing, DesktopError::InvalidInput { field: Some(ref f), .. } if f == "local_path"),
        "{missing:?}"
    );
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

#[tokio::test]
async fn a_storage_mode_change_for_a_group_not_linked_here_is_about_the_group_id() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    serve(&socket, |_| RespPayload::ListLinks(ListLinksResponse { links: vec![linked_docs()] }));
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

    let error =
        core().set_storage_mode("g-elsewhere".into(), FolderMode::OnDemand).await.unwrap_err();
    assert!(
        matches!(error, DesktopError::InvalidInput { field: Some(ref f), .. } if f == "group_id"),
        "{error:?}"
    );
    let unchanged = core().set_storage_mode("g1".into(), FolderMode::KeepAll).await.unwrap();
    assert!(!unchanged.changed);
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

#[tokio::test]
async fn an_unforced_unlink_refused_for_durability_offers_the_override() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    serve(&socket, |_| {
        RespPayload::CommandError(ApplicationCommandError {
            code: ApplicationErrorCode::NotProtected as i32,
            message: "refusing to unlink /f/Docs: no other complete copy is confirmed ready to \
                      durably hold every file in this group yet. Re-run with --force to unlink \
                      anyway."
                .into(),
            group_ids: vec!["g1".into()],
            operation_id: String::new(),
        })
    });
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

    let error = core().unlink_folder("/f/Docs".into(), false, None).await.unwrap_err();
    assert!(matches!(error, DesktopError::DurabilityBlocked { can_force: true, .. }), "{error:?}");
    let forced = core().unlink_folder("/f/Docs".into(), true, None).await.unwrap_err();
    assert!(
        matches!(forced, DesktopError::DurabilityBlocked { can_force: false, .. }),
        "{forced:?}"
    );
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

#[tokio::test]
async fn starting_a_daemon_that_cannot_be_launched_is_daemon_unavailable() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("nobody-home.sock"));
    let core = ClientCore::new(CoreConfig {
        daemon_launch: DaemonLaunch::SpawnBinary {
            path: Some(dir.path().join("no-such-daemon").to_string_lossy().into_owned()),
        },
    });
    let error = core.start_daemon().await.unwrap_err();
    match error {
        DesktopError::DaemonUnavailable {
            reason: DaemonUnavailableReason::NotRunning,
            message,
        } => {
            assert!(message.contains("no-such-daemon"), "{message}");
        }
        other => panic!("expected daemon unavailable, got {other:?}"),
    }
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

/// A daemon that is running but wedged accepts the connection and never
/// answers. Starting it must say so promptly: launching another copy cannot
/// help, and waiting on every poll's reply deadline in turn kept the app's
/// "starting" state up for minutes before a misleading "did not become
/// reachable".
#[tokio::test(start_paused = true)]
async fn starting_a_daemon_that_never_answers_reports_it_unresponsive_promptly() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);
    // A launch that "succeeds" without bringing anything up, as
    // `launchctl kickstart` does for a job that is already running.
    let core = ClientCore::new(CoreConfig {
        daemon_launch: DaemonLaunch::SpawnBinary { path: Some("/usr/bin/true".into()) },
    });

    let started = tokio::time::Instant::now();
    let error = core.start_daemon().await.unwrap_err();
    let waited = started.elapsed();
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");

    assert!(waited <= Duration::from_secs(30), "start waited {waited:?} on a silent daemon");
    match error {
        DesktopError::DaemonUnavailable {
            reason: DaemonUnavailableReason::Unresponsive, ..
        } => {}
        other => panic!("expected an unresponsive daemon, got {other:?}"),
    }
}

#[tokio::test]
async fn unlink_sends_the_link_key_verbatim() {
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::UnlinkResponse;

    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();
    serve(&socket, move |request| {
        if let Some(ReqPayload::Unlink(r)) = request.payload {
            record.lock().unwrap().push((r.local_path, r.force));
        }
        RespPayload::Unlink(UnlinkResponse::default())
    });
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

    // A provider-backed folder's key is not a filesystem path.
    core().unlink_folder("provider://root-1".into(), false, None).await.unwrap();
    assert_eq!(*seen.lock().unwrap(), [("provider://root-1".to_owned(), false)]);
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

#[tokio::test]
async fn readopt_sends_the_folder_and_reports_a_refusal() {
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::ReadoptVolumeResponse;

    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let folder = std::fs::canonicalize(dir.path()).unwrap().join("Docs");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();
    let refuse = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let refusing = refuse.clone();
    serve(&socket, move |request| {
        if let Some(ReqPayload::ReadoptVolume(r)) = request.payload {
            record.lock().unwrap().push(r.local_path);
        }
        if refusing.load(std::sync::atomic::Ordering::SeqCst) {
            RespPayload::Error("the disk has no identity this system can check".into())
        } else {
            RespPayload::ReadoptVolume(ReadoptVolumeResponse {})
        }
    });
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

    core().readopt_folder(folder.to_string_lossy().into_owned()).await.unwrap();
    refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    let error = core().readopt_folder(folder.to_string_lossy().into_owned()).await.unwrap_err();
    assert!(error.to_string().contains("no identity"), "{error}");
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert_eq!(seen.lock().unwrap()[0], folder.to_string_lossy());
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

/// "Acknowledge and finish" through the facade: only an explicit call records the
/// acknowledgement, it is idempotent, and with no replacement waiting it reports `false` and
/// creates nothing.
#[tokio::test]
async fn acknowledging_possible_loss_is_explicit_and_changes_nothing_without_a_replacement() {
    use yadorilink_local_storage::replacement_unconfirmed as record;
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    let core = core();

    assert!(!core.acknowledge_possible_loss().await.unwrap());
    assert!(!record::pending(dir.path()), "nothing may be created when no replacement waits");

    record::write(
        dir.path(),
        &record::Record {
            old_device_id: "old".into(),
            new_device_id: "new".into(),
            unconfirmed_group_ids: vec!["g1".into()],
            acknowledged_possible_loss: false,
        },
    )
    .unwrap();
    assert!(record::acknowledgement_required(dir.path()), "waiting until the person acts");

    assert!(core.acknowledge_possible_loss().await.unwrap());
    assert!(!record::acknowledgement_required(dir.path()));
    assert!(core.acknowledge_possible_loss().await.unwrap(), "acknowledging twice is harmless");
    let kept = record::read(dir.path()).unwrap().unwrap();
    assert_eq!(kept.unconfirmed_group_ids, ["g1"], "the record is otherwise untouched");
    std::env::remove_var("YADORILINK_CONFIG_DIR");
}
