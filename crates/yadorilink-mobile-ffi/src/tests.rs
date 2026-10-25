//! The exported surface, driven the way the foreign side drives it: blocking calls from a
//! plain thread, and the async channel calls polled with no Tokio runtime in sight.
//! Deterministic: nothing waits on the clock except bounds that a hang would trip.

use std::future::Future;
use std::sync::Mutex;
use std::task::{Context, Poll, Wake, Waker};

use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{ListProviderFoldersRequest, ShellIpcMessage};

use super::*;

/// Drives a future on the calling thread, the way Swift's executor drives an exported future.
fn block_on<F: Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    assert!(tokio::runtime::Handle::try_current().is_err(), "must run outside any runtime");
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        assert!(std::time::Instant::now() < deadline, "future did not finish within 30s");
        std::thread::park_timeout(Duration::from_millis(20));
    }
}

/// The engine allows one instance per process at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

struct Area {
    _guard: std::sync::MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
    config: EngineConfig,
}

fn area() -> Area {
    let guard = ONE_AT_A_TIME.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("data")).unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    let config = EngineConfig {
        config_dir: path("state"),
        block_store_root: path("blocks"),
        sync_db_path: path("data/sync.sqlite3"),
        provider_temp_root: None,
        credential_keyring_scope: None,
        auth_server_addr: None,
        coordination_addr: None,
        host_name: None,
        witness_dir: Some(path("witness")),
        machine_id: Some("mobile-ffi-test-id".to_owned()),
    };
    Area { _guard: guard, _dir: dir, config }
}

fn list_request() -> Vec<u8> {
    ShellIpcMessage {
        payload: Some(Payload::ListProviderFoldersRequest(ListProviderFoldersRequest::default())),
    }
    .encode_to_vec()
}

fn fresh() -> Arc<CancelHandle> {
    CancelHandle::new()
}

#[test]
fn the_lifecycle_runs_through_the_exported_calls() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    assert_eq!(host.state(), HostState::Stopped);
    host.start().unwrap();
    assert_eq!(host.state(), HostState::Running);
    host.suspend().unwrap();
    assert_eq!(host.state(), HostState::Suspended);
    host.resume().unwrap();
    assert_eq!(host.state(), HostState::Running);
    host.stop().unwrap();
    assert_eq!(host.state(), HostState::Stopped);
    host.stop().unwrap();
}

#[test]
fn a_call_in_the_wrong_state_is_a_typed_refusal() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    assert!(matches!(
        host.suspend(),
        Err(HostFailure::WrongState { state: HostState::Stopped, .. })
    ));
    assert!(matches!(host.open_provider_channel(), Err(HostFailure::WrongState { .. })));
    host.start().unwrap();
    let Err(HostFailure::WrongState { operation, state }) = host.start() else {
        panic!("a second start must be refused")
    };
    assert_eq!((operation.as_str(), state), ("start", HostState::Running));
    assert!(matches!(
        host.list_folders(&fresh(), None),
        Ok(folders) if folders.is_empty()
    ));
    host.stop().unwrap();
    assert!(matches!(host.list_folders(&fresh(), None), Err(CallFailure::NotRunning { .. })));
}

#[test]
fn a_second_engine_over_the_same_database_is_a_typed_start_failure() {
    let area = area();
    let first = MobileHost::new(area.config.clone());
    first.start().unwrap();
    let second = MobileHost::new(area.config.clone());
    let refused = second.start().expect_err("the data area is taken");
    assert!(matches!(refused, HostFailure::AlreadyRunning { .. }), "{refused:?}");
    assert_eq!(second.state(), HostState::Stopped);
    first.stop().unwrap();
}

/// For a test that only holds in the embedded shape: true when this build is desktop-shaped
/// (a `--workspace` build unifies the daemon's `process-model` feature on) and the test should
/// return. CI's dedicated embedded-shape run sets `YADORILINK_EXPECT_EMBEDDED_SHAPE`, and there
/// a desktop-shaped build is a failure, not a skip.
fn desktop_shaped_skip() -> bool {
    if !ordinary_folder_links_supported() {
        return false;
    }
    assert!(
        std::env::var_os("YADORILINK_EXPECT_EMBEDDED_SHAPE").is_none(),
        "this run was to pin the embedded shape, but the daemon's process model is on"
    );
    true
}

#[test]
fn linking_an_ordinary_folder_is_refused_as_no_change_source() {
    if desktop_shaped_skip() {
        return;
    }
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let folder = tempfile::tempdir().unwrap();
    let request = LinkFolderRequest {
        local_path: folder.path().display().to_string(),
        group_id: "g".into(),
        on_demand: false,
        acknowledge_risks: true,
    };
    let refused = host.link_folder(request, &fresh(), Some(30_000)).expect_err("refused");
    assert!(matches!(refused, CallFailure::NoChangeSource { .. }), "{refused:?}");
    assert!(host.list_folders(&fresh(), None).unwrap().is_empty(), "nothing was persisted");
    host.stop().unwrap();
}

#[test]
fn restoring_without_an_earlier_version_never_claims_a_restore() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let request =
        RestoreVersionRequest { group_id: "g".into(), path: "a.txt".into(), version_seq: None };
    let result = host.restore_version(request, &fresh(), Some(30_000));
    assert!(matches!(result, Ok(false) | Err(CallFailure::Failed { .. })), "{result:?}");
    host.stop().unwrap();
}

#[test]
fn a_cancel_handle_serves_one_call() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();

    let cancelled = fresh();
    cancelled.cancel();
    assert!(matches!(
        host.list_folders(&cancelled, None),
        Err(CallFailure::Cancelled { still_running: false })
    ));
    assert!(matches!(host.list_folders(&cancelled, None), Err(CallFailure::HandleUsed)));

    let used = fresh();
    host.list_folders(&used, None).unwrap();
    assert!(matches!(host.list_folders(&used, None), Err(CallFailure::HandleUsed)));

    assert!(matches!(
        host.list_folders(&fresh(), Some(0)),
        Err(CallFailure::DeadlineExceeded { still_running: false })
    ));
    host.stop().unwrap();
}

#[test]
fn the_provider_channel_carries_encoded_messages() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let channel = host.open_provider_channel().unwrap();

    block_on(channel.send(list_request())).unwrap();
    let answer = block_on(channel.recv()).expect("the engine answers");
    let answer = ShellIpcMessage::decode(answer.as_slice()).unwrap();
    assert!(matches!(
        answer.payload,
        Some(Payload::ListProviderFoldersResponse(response)) if response.snapshot_available
    ));

    // Bytes that are not a message are refused before anything is sent.
    let refused = block_on(channel.send(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff])).unwrap_err();
    assert!(matches!(refused, ChannelFailure::InvalidMessage { .. }), "{refused:?}");

    host.stop().unwrap();
    assert!(block_on(channel.recv()).is_none(), "a stopped engine closes the channel");
}

#[test]
fn closing_the_channel_ends_a_waiting_recv_and_later_calls() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let channel = host.open_provider_channel().unwrap();

    let waiting = {
        let channel = channel.clone();
        std::thread::spawn(move || block_on(channel.recv()))
    };
    // Wake the waiting call by closing, whether or not it has started waiting yet.
    channel.close();
    assert!(waiting.join().unwrap().is_none());
    channel.close();
    assert!(matches!(block_on(channel.send(list_request())), Err(ChannelFailure::Closed)));
    assert!(block_on(channel.recv()).is_none());

    // The host is unaffected, and a new channel works.
    let again = host.open_provider_channel().unwrap();
    block_on(again.send(list_request())).unwrap();
    assert!(block_on(again.recv()).is_some());
    host.stop().unwrap();
}

/// Every outcome of the host's commands and every error kind has a mobile form: a refusal of
/// each family arrives as its own typed `CallFailure`, not as text.
#[test]
fn refusals_of_every_family_arrive_typed() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let folder = tempfile::tempdir().unwrap();

    // An ordinary folder in a share command: no change source (only where the build has none;
    // a `--workspace` build is desktop-shaped, see the test above).
    if !desktop_shaped_skip() {
        let create = CreateShareRequest {
            group_name: "Photos".into(),
            folder: ShareFolder::Ordinary {
                local_path: folder.path().display().to_string(),
                create_if_missing: false,
            },
            on_demand: false,
            acknowledge_risks: true,
        };
        let refused = host.create_share(create, &fresh(), Some(30_000)).expect_err("refused");
        assert!(matches!(refused, CallFailure::NoChangeSource { .. }), "{refused:?}");
    }

    // A link the engine does not have, with a group expectation: the typed mismatch is only for
    // a link that exists, so an unknown link is the plain failure.
    let pause = PauseLinkRequest {
        link_key: "/not/linked".into(),
        duration: PauseFor::OneHour,
        expected_group_id: None,
    };
    assert!(matches!(
        host.pause_link(pause, &fresh(), Some(30_000)),
        Err(CallFailure::Failed { .. })
    ));

    // A preserved item that does not exist.
    let item = PreservedRef { group_id: "g".into(), item_id: "nope".into() };
    assert!(matches!(
        host.discard_preserved(item, &fresh(), Some(30_000)),
        Err(CallFailure::PreservedRefused { reason: PreservedRefusal::NotFound, .. })
    ));

    // An account command with no account.
    let refused = host.sign_out(&fresh(), Some(30_000)).expect_err("not signed in");
    assert!(
        matches!(&refused, CallFailure::Account { error } if error.kind == AccountErrorKind::NotSignedIn),
        "{refused:?}"
    );
    host.stop().unwrap();
}

#[test]
fn status_space_management_and_the_account_read_through_the_exported_calls() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();

    let status = host.status(&fresh(), Some(30_000)).unwrap();
    assert!(status.folders.is_empty());
    assert_eq!(status.account.sign_in, SignInState::SignedOut);
    assert_eq!(status.account.has_linked_folders, Some(false));
    assert!(!host.doctor(&fresh(), Some(30_000)).unwrap().is_empty());
    assert!(host.preserved_items(&fresh(), Some(30_000)).unwrap().is_empty());

    assert!(!host.space_management(&fresh(), Some(30_000)).unwrap());
    assert!(host.set_space_management(true, &fresh(), Some(30_000)).unwrap());
    assert!(host.space_management(&fresh(), Some(30_000)).unwrap());

    let account = host.account_status(&fresh(), Some(30_000)).unwrap();
    assert!(!account.device_registered);
    host.stop().unwrap();
}

/// A sign-in starts, ends when cancelled, and its id is invalid after the engine restarts.
#[test]
fn a_sign_in_starts_and_cancels_and_its_id_dies_with_the_engine() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let id = host.begin_sign_in(false, Some(60_000), &fresh(), Some(30_000)).unwrap();
    host.cancel_sign_in(id, &fresh(), Some(30_000)).unwrap();
    host.cancel_sign_in(id, &fresh(), Some(30_000)).unwrap();
    // The sign-in ends as cancelled, or as failed when the coordination service was refused
    // before the cancel; it never ends as signed in. Steps the flow emitted before the cancel
    // (`Enrolling`) come first, so follow the numbering to the last one.
    let mut after = 0;
    let mut last = None;
    for _ in 0..16 {
        let step = host.poll_sign_in(id, after, &fresh(), Some(30_000)).unwrap();
        assert!(!matches!(step.event, SignInEvent::SignedIn { .. }), "{:?}", step.event);
        if matches!(step.event, SignInEvent::Cancelled | SignInEvent::Failed { .. }) {
            last = Some(step.event);
            break;
        }
        assert!(step.seq > after, "the numbering did not advance: {:?}", step.event);
        after = step.seq;
    }
    let last = last.expect("no terminal step within 16 steps");
    assert!(matches!(last, SignInEvent::Cancelled | SignInEvent::Failed { .. }));

    // Without the id (a begin whose answer was lost): the engine's current sign-in.
    // (The flow may already have failed on the unreachable service, then it is finished.)
    let current = host.cancel_current_sign_in(&fresh(), Some(30_000)).unwrap();
    assert!(
        matches!(current, SignInCancellation::Stopped { id: got } | SignInCancellation::AlreadyFinished { id: got } if got == id),
        "{current:?}"
    );

    host.suspend().unwrap();
    host.resume().unwrap();
    assert_eq!(
        host.cancel_current_sign_in(&fresh(), Some(30_000)).unwrap(),
        SignInCancellation::NothingToCancel,
        "a restarted engine holds no sign-in"
    );
    let stale = host.poll_sign_in(id, 0, &fresh(), Some(30_000)).expect_err("a restarted engine");
    assert!(
        matches!(&stale, CallFailure::Account { error } if error.kind == AccountErrorKind::InvalidInput),
        "{stale:?}"
    );
    host.stop().unwrap();
}

#[test]
fn the_credential_settings_come_from_the_config_not_the_environment() {
    let area = area();
    let file: yadorilink_embedded_host::EngineConfig = area.config.clone().into();
    assert!(matches!(file.credentials.backend, host::CredentialBackend::File(_)));
    assert_eq!(file.credentials.key_mirror, host::KeyMirror::Disabled);

    let scoped = EngineConfig {
        credential_keyring_scope: Some("engine-a".into()),
        auth_server_addr: Some("http://127.0.0.1:1".into()),
        coordination_addr: Some("http://127.0.0.1:2".into()),
        host_name: Some("Test Phone".into()),
        ..area.config.clone()
    };
    let scoped: yadorilink_embedded_host::EngineConfig = scoped.into();
    assert_eq!(
        scoped.credentials.backend,
        host::CredentialBackend::Keyring { scope: Some("engine-a".into()) }
    );
    assert_eq!(scoped.credentials.auth_server_addr.as_deref(), Some("http://127.0.0.1:1"));
    assert_eq!(scoped.credentials.coordination_addr.as_deref(), Some("http://127.0.0.1:2"));
    assert_eq!(scoped.credentials.host_name.as_deref(), Some("Test Phone"));
}

#[test]
fn a_scope_that_is_not_canonical_is_refused_when_the_engine_starts() {
    let area = area();
    let config =
        EngineConfig { credential_keyring_scope: Some("Engine-A".into()), ..area.config.clone() };
    let host = MobileHost::new(config);
    assert!(host.start().is_err(), "an uppercase scope must not start an engine");
}

#[test]
fn the_hosts_witness_directory_is_the_engines_and_none_is_refused_at_start() {
    let area = area();
    let named: yadorilink_embedded_host::EngineConfig = area.config.clone().into();
    assert_eq!(
        named.tuning.witness,
        yadorilink_embedded_host::WitnessPlacement::Persistent(
            area.config.witness_dir.clone().unwrap().into()
        )
    );

    let without = EngineConfig { witness_dir: None, ..area.config.clone() };
    let unset: yadorilink_embedded_host::EngineConfig = without.clone().into();
    assert_eq!(unset.tuning.witness, yadorilink_embedded_host::WitnessPlacement::Unset);
    let host = MobileHost::new(without);
    assert!(host.start().is_err(), "an engine with no witness directory must not start");

    // An empty string names nothing: it is none, not the working directory.
    let empty = EngineConfig { witness_dir: Some(String::new()), ..area.config.clone() };
    let converted: yadorilink_embedded_host::EngineConfig = empty.clone().into();
    assert_eq!(converted.tuning.witness, yadorilink_embedded_host::WitnessPlacement::Unset);
    assert!(matches!(MobileHost::new(empty).start(), Err(HostFailure::StartFailed { .. })));
}

/// A relative directory, or one inside the state directory, is refused at start as a typed
/// `StartFailed` that names the witness directory.
#[test]
fn an_unusable_witness_directory_is_a_typed_start_failure() {
    let area = area();
    let state = std::path::PathBuf::from(&area.config.config_dir);
    for dir in ["relative-witness".to_owned(), state.join("witness").display().to_string()] {
        let config = EngineConfig { witness_dir: Some(dir.clone()), ..area.config.clone() };
        match MobileHost::new(config).start() {
            Err(HostFailure::StartFailed { message }) => {
                assert!(message.contains("witness directory"), "{dir}: {message}");
            }
            other => panic!("{dir}: expected StartFailed, got {other:?}"),
        }
    }
    assert!(!std::path::Path::new("relative-witness").exists());
}

/// A step-up of a signed-out engine is refused at its begin, as the step-up's own typed error
/// and never as an ordinary sign-in.
#[test]
fn a_step_up_needs_a_sign_in() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let refused = host.begin_sign_in(true, None, &fresh(), Some(30_000)).expect_err("signed out");
    assert!(
        matches!(&refused, CallFailure::Account { error } if error.kind == AccountErrorKind::NotSignedIn),
        "{refused:?}"
    );
    host.stop().unwrap();
}

#[test]
fn the_reauthentication_refusal_has_its_own_kind() {
    let reauth = host::DesktopError::PermissionDenied {
        message: "confirm again".into(),
        reason: host::PermissionDeniedReason::ReauthenticationRequired,
    };
    assert_eq!(AccountError::from(reauth).kind, AccountErrorKind::ReauthenticationRequired);
    let other = host::DesktopError::PermissionDenied {
        message: "no".into(),
        reason: host::PermissionDeniedReason::Forbidden,
    };
    assert_eq!(AccountError::from(other).kind, AccountErrorKind::PermissionDenied);
}

#[test]
fn the_terms_consent_refusal_has_its_own_kind() {
    let consent = host::DesktopError::PermissionDenied {
        message: "accept the Terms".into(),
        reason: host::PermissionDeniedReason::TermsConsentRequired,
    };
    assert_eq!(AccountError::from(consent).kind, AccountErrorKind::TermsConsentRequired);
}

#[test]
fn the_invite_parser_is_the_engines() {
    assert_eq!(
        parse_invite_input("  YadoriLink://Invite/ab-12_Z/ ".into()).as_deref(),
        Ok("ab-12_Z")
    );
    assert_eq!(parse_invite_input("ab-12_Z".into()).as_deref(), Ok("ab-12_Z"));
    assert_eq!(parse_invite_input("  ".into()), Err(InviteError::Empty));
    assert_eq!(parse_invite_input("a".repeat(200)), Err(InviteError::TooLong));
    assert_eq!(parse_invite_input("not an invite!".into()), Err(InviteError::Malformed));

    // The vectors the iOS app's copy of the parser used to carry.
    for good in ["yadorilink://invite/K7QX-M2PA", "abc123", "yadorilink://invite/abc/"] {
        assert!(parse_invite_input(good.into()).is_ok(), "{good}");
    }
    assert!(parse_invite_input("a".repeat(64)).is_ok());
    for bad in [
        "yadorilink://invite/",
        "yadorilink://invite/a/b",
        "yadorilink://invite/a?x=1",
        "https://example.com/x",
        "a b",
        "\u{e9}",
    ] {
        assert!(parse_invite_input(bad.into()).is_err(), "{bad}");
    }
    assert!(parse_invite_input("a".repeat(65)).is_err());
    assert!(parse_invite_input("x".repeat(100_000)).is_err());
}

struct Capture(Mutex<Vec<(LogLevel, String, String)>>);

impl LogSink for Capture {
    fn log(&self, level: LogLevel, target: String, message: String) {
        self.0.lock().unwrap().push((level, target, message));
    }
}

/// The sink receives events at its level and above, and a process takes one sink.
#[test]
fn the_log_sink_receives_the_engines_events_once_per_process() {
    let capture = Arc::new(Capture(Mutex::new(Vec::new())));
    install_log_sink(capture.clone(), LogLevel::Warn).unwrap();
    tracing::info!("below the level");
    tracing::warn!(key = 7, "a warning");
    // Other tests' engines may log warnings in this process too: look for ours.
    let seen = capture.0.lock().unwrap().clone();
    assert!(
        seen.iter().all(|(level, _, _)| matches!(level, LogLevel::Warn | LogLevel::Error)),
        "{seen:?}"
    );
    assert!(!seen.iter().any(|(_, _, message)| message.contains("below the level")), "{seen:?}");
    let ours = seen.iter().find(|(_, _, message)| message.contains("a warning")).expect("ours");
    assert_eq!(ours.0, LogLevel::Warn);
    assert!(ours.2.contains("key=7"), "{ours:?}");
    assert!(matches!(
        install_log_sink(capture, LogLevel::Info),
        Err(LogSinkFailure::AlreadyInstalled)
    ));
}

#[test]
fn the_sign_in_origins_split_the_approval_page_from_the_authorization_server() {
    let area = area();
    let config = EngineConfig {
        auth_server_addr: Some("https://auth.example.test".into()),
        ..area.config.clone()
    };
    let host = MobileHost::new(config);
    host.start().unwrap();
    let hosts = host.sign_in_origins(&fresh(), Some(30_000)).unwrap();
    assert_eq!(hosts.authorization.as_deref(), Some("https://auth.example.test"));
    // The coordination origin is the process's, never the authorization server's.
    assert_ne!(hosts.approve_device.as_deref(), Some("https://auth.example.test"));
    host.stop().unwrap();
}

/// The refusal that says to restart the engine first has its own kind, and every other refusal
/// stays a plain `Refused`.
#[test]
fn the_restart_required_refusal_has_its_own_account_error_kind() {
    use crate::app::{AccountError, AccountErrorKind};
    let refused = |reason| {
        AccountError::from(yadorilink_embedded_host::DesktopError::Refused {
            message: "m".into(),
            reason,
        })
        .kind
    };
    assert_eq!(
        refused(yadorilink_embedded_host::RefusalReason::StartOverRestartRequired),
        AccountErrorKind::StartOverRestartRequired
    );
    assert_eq!(
        refused(yadorilink_embedded_host::RefusalReason::DatabaseNotRestored),
        AccountErrorKind::Refused
    );
}
