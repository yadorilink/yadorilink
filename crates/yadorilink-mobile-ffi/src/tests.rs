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
        provider_temp_root: Some(path("provider-temp")),
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
    assert!(
        matches!(host.start(), Err(HostFailure::WitnessPlacementRequired)),
        "an engine with no witness directory must not start"
    );

    // An empty string names nothing: it is none, not the working directory.
    let empty = EngineConfig { witness_dir: Some(String::new()), ..area.config.clone() };
    let converted: yadorilink_embedded_host::EngineConfig = empty.clone().into();
    assert_eq!(converted.tuning.witness, yadorilink_embedded_host::WitnessPlacement::Unset);
    assert!(matches!(MobileHost::new(empty).start(), Err(HostFailure::WitnessPlacementRequired)));
}

/// A relative directory, or one inside the state directory, is refused at start as a typed
/// `WitnessDirUnusable` that names the witness directory.
#[test]
fn an_unusable_witness_directory_is_a_typed_start_failure() {
    let area = area();
    let state = std::path::PathBuf::from(&area.config.config_dir);
    for dir in ["relative-witness".to_owned(), state.join("witness").display().to_string()] {
        let config = EngineConfig { witness_dir: Some(dir.clone()), ..area.config.clone() };
        match MobileHost::new(config).start() {
            Err(error @ HostFailure::WitnessDirUnusable { .. }) => {
                assert!(error.to_string().contains("witness directory"), "{dir}: {error}");
            }
            other => panic!("{dir}: expected WitnessDirUnusable, got {other:?}"),
        }
    }
    assert!(!std::path::Path::new("relative-witness").exists());
}

/// Listing the joinable folder groups needs an account: a signed-out engine says so, typed.
#[test]
fn listing_joinable_groups_needs_a_sign_in() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let refused = host.list_joinable_groups(&fresh(), Some(30_000)).expect_err("signed out");
    assert!(
        matches!(&refused, CallFailure::Account { error } if error.kind == AccountErrorKind::NotSignedIn),
        "{refused:?}"
    );
    host.stop().unwrap();
}

/// The joinable group record carries the facade's summary unchanged.
#[test]
fn a_joinable_group_is_the_facades_summary() {
    let group: JoinableGroup = yadorilink_embedded_host::dto::GroupSummary {
        group_id: "g1".into(),
        name: "Photos".into(),
    }
    .into();
    assert_eq!(group, JoinableGroup { group_id: "g1".into(), name: "Photos".into() });
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

/// The keychain adapter of the instance nonce keeps one item per scope and reads absence as none.
#[test]
fn the_keychain_instance_nonce_round_trips_per_scope() {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use yadorilink_embedded_host::InstanceNonceKeychain;
    use yadorilink_os_keychain::{Attr, Backend, Keychain, Status};

    #[derive(Debug, Clone, Default)]
    struct Memory(Arc<Mutex<HashMap<String, Vec<u8>>>>);
    fn account(attrs: &[Attr]) -> String {
        attrs
            .iter()
            .find_map(|a| if let Attr::Account(v) = a { Some(v.clone()) } else { None })
            .unwrap()
    }
    fn data(attrs: &[Attr]) -> Vec<u8> {
        attrs
            .iter()
            .find_map(|a| if let Attr::ValueData(v) = a { Some(v.clone()) } else { None })
            .unwrap()
    }
    impl Backend for Memory {
        fn add(&self, attributes: &[Attr]) -> Result<(), Status> {
            self.0.lock().unwrap().insert(account(attributes), data(attributes));
            Ok(())
        }
        fn update(&self, query: &[Attr], changes: &[Attr]) -> Result<(), Status> {
            match self.0.lock().unwrap().get_mut(&account(query)) {
                Some(slot) => {
                    *slot = data(changes);
                    Ok(())
                }
                None => Err(Status::NotFound),
            }
        }
        fn copy_data(&self, query: &[Attr]) -> Result<Vec<u8>, Status> {
            self.0.lock().unwrap().get(&account(query)).cloned().ok_or(Status::NotFound)
        }
        fn delete(&self, _: &[Attr]) -> Result<(), Status> {
            Ok(())
        }
    }

    let memory = Memory::default();
    let a = crate::KeychainInstanceNonce::new(Keychain::new(memory.clone()), "a");
    let b = crate::KeychainInstanceNonce::new(Keychain::new(memory), "b");
    assert_eq!(a.read().unwrap(), None);
    a.write(&[7; 16]).unwrap();
    assert_eq!(a.read().unwrap(), Some([7; 16]));
    assert_eq!(b.read().unwrap(), None);
}

/// The Activity list is local: a signed-out engine with no folders answers an empty page.
#[test]
fn listing_activity_works_signed_out_and_is_empty_without_folders() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let page = host.list_activity(50, None, None, &fresh(), Some(30_000)).expect("local read");
    assert_eq!(page, ActivityPage { events: vec![], next_cursor: None });
    host.stop().unwrap();
}

/// A call on an engine that is not running is a typed failure, and a cancelled one is aborted.
#[test]
fn listing_activity_honours_cancel() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let cancel = fresh();
    cancel.cancel();
    assert!(host.list_activity(50, None, None, &cancel, None).is_err());
    host.stop().unwrap();
}

/// The activity records carry the facade's page and filter unchanged.
#[test]
fn activity_records_map_the_facades_dtos() {
    use yadorilink_embedded_host::dto;
    let filter: dto::ActivityFilter = ActivityFilter {
        kinds: vec![ActivityKind::Conflict, ActivityKind::Restored],
        origin: ActivityOrigin::OtherDevices,
    }
    .into();
    assert_eq!(
        filter,
        dto::ActivityFilter {
            kinds: vec![dto::ActivityKind::Conflict, dto::ActivityKind::Restored],
            origin: dto::ActivityOrigin::OtherDevices,
        }
    );
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(5);
    let page: ActivityPage = dto::ActivityPage {
        events: vec![dto::ActivityEvent {
            cursor: 9,
            local_path: "/r".into(),
            path: "a.txt".into(),
            kind: dto::ActivityKind::Updated,
            origin_device_id: Some("d1".into()),
            origin_device_name: Some("Mac".into()),
            is_this_device: false,
            at: Some(at),
        }],
        next_cursor: Some(9),
    }
    .into();
    assert_eq!(
        page,
        ActivityPage {
            events: vec![ActivityEvent {
                cursor: 9,
                local_path: "/r".into(),
                path: "a.txt".into(),
                kind: ActivityKind::Updated,
                origin_device_id: Some("d1".into()),
                origin_device_name: Some("Mac".into()),
                is_this_device: false,
                at: Some(at),
            }],
            next_cursor: Some(9),
        }
    );
}

/// Send on a signed-out engine: the writes name that nobody is signed in (typed), the lists read
/// as empty or say the Send service is not up, and nothing is left running.
#[test]
fn send_calls_on_a_signed_out_engine_are_typed() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let signed_out = |result: Result<(), CallFailure>| match result.expect_err("signed out") {
        CallFailure::Refused { code, .. } => {
            assert_eq!(code, RefusalCode::LocalIdentityUnavailable)
        }
        other => panic!("{other:?}"),
    };
    signed_out(
        host.create_send_link(SendLinkTtl::OneHour, vec![], &fresh(), Some(30_000)).map(drop),
    );
    signed_out(host.preview_send_link("A-B".into(), &fresh(), Some(30_000)).map(drop));
    signed_out(host.redeem_send_link("A-B".into(), None, &fresh(), Some(30_000)).map(drop));
    signed_out(host.cancel_send_link("l".into(), &fresh(), Some(30_000)));
    signed_out(host.send_link_status("l".into(), &fresh(), Some(30_000)).map(drop));
    assert!(host.list_send_links(&fresh(), Some(30_000)).expect("an empty list").is_empty());
    // No Send service without a registered, signed-in device.
    assert!(matches!(host.list_inbox(&fresh(), Some(30_000)), Err(CallFailure::Failed { .. })));
    host.stop().unwrap();
}

/// A cancelled read of the Send lists is aborted like any read.
#[test]
fn listing_send_links_honours_cancel() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let cancel = fresh();
    cancel.cancel();
    assert!(matches!(
        host.list_send_links(&cancel, None),
        Err(CallFailure::Cancelled { still_running: false })
    ));
    host.stop().unwrap();
}

/// The wire states and failures map onto the exported ones without loss.
#[test]
fn send_link_states_and_failures_mirror_the_products() {
    use yadorilink_embedded_host::dto as d;
    let states = [
        (d::SendLinkState::Waiting, SendLinkState::Waiting),
        (d::SendLinkState::Redeemed, SendLinkState::Redeemed),
        (d::SendLinkState::Transferring, SendLinkState::Transferring),
        (d::SendLinkState::Done, SendLinkState::Done),
        (d::SendLinkState::Cancelled, SendLinkState::Cancelled),
        (d::SendLinkState::Expired, SendLinkState::Expired),
        (d::SendLinkState::Interrupted, SendLinkState::Interrupted),
    ];
    for (product, exported) in states {
        assert_eq!(SendLinkState::from(product), exported);
    }
    assert_eq!(
        TransferFailure::from(d::TransferFailure::Interrupted),
        TransferFailure::Interrupted
    );
    assert_eq!(
        RefusalCode::from(yadorilink_ipc_proto::daemonctl::ApplicationErrorCode::SendLinksDisabled),
        RefusalCode::SendLinksDisabled
    );
}

#[test]
fn an_incoming_transfer_carries_the_link_redeemed_receive_fields() {
    use yadorilink_ipc_proto::daemonctl::InboxTransfer;
    let entry = InboxTransfer {
        transfer_id: "t".into(),
        status: "in_progress".into(),
        total_size: 10,
        link_id: "link-1".into(),
        received_bytes: 4,
        destination_dir: "/recv/link-1".into(),
        ..Default::default()
    };
    let record = crate::send::IncomingTransfer::from(
        yadorilink_embedded_host::dto::incoming_transfer(&entry),
    );
    assert_eq!(record.link_id.as_deref(), Some("link-1"));
    assert_eq!(record.received_bytes, 4);
    assert_eq!(record.destination_dir.as_deref(), Some("/recv/link-1"));
    let plain =
        crate::send::IncomingTransfer::from(yadorilink_embedded_host::dto::incoming_transfer(
            &InboxTransfer { transfer_id: "u".into(), ..Default::default() },
        ));
    assert_eq!((plain.link_id, plain.received_bytes, plain.destination_dir), (None, 0, None));
}

// ---- writes ----------------------------------------------------------------------------------

fn running(area: &Area) -> Arc<MobileHost> {
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    host
}

#[test]
fn a_file_is_staged_by_move_and_by_clone_and_a_stage_can_be_discarded() {
    let area = area();
    let host = running(&area);
    let work = tempfile::tempdir_in(area._dir.path()).unwrap();
    let bytes = vec![3u8; 2 << 20];
    let path = work.path().join("movie.mov");
    std::fs::write(&path, &bytes).unwrap();

    let moved = host
        .stage_upload(
            StageSource::Path { path: path.display().to_string() },
            StageMode::Move,
            &fresh(),
            Some(60_000),
        )
        .unwrap();
    let StageResult::Staged { upload } = moved else { panic!("not staged: {moved:?}") };
    assert_eq!(upload.how, StagedHow::Moved, "the file was renamed, not copied");
    assert_eq!((upload.size, upload.sha256.len()), (bytes.len() as u64, 32));
    assert!(!path.exists());
    let staged = area._dir.path().join("provider-temp/ingest").join(&upload.ingest_name);
    assert_eq!(std::fs::read(&staged).unwrap(), bytes);

    // A source that is not there is a typed refusal, not a failed call.
    let missing = host
        .stage_upload(
            StageSource::Path { path: path.display().to_string() },
            StageMode::Clone,
            &fresh(),
            Some(60_000),
        )
        .unwrap();
    assert!(
        matches!(missing, StageResult::Refused { code: WriteRefusal::IngestUnstable, .. }),
        "{missing:?}"
    );

    host.discard_staged_upload(upload.ingest_name.clone(), &fresh(), Some(60_000)).unwrap();
    assert!(!staged.exists());
    // Idempotent, and only names the engine issued are accepted.
    host.discard_staged_upload(upload.ingest_name, &fresh(), Some(60_000)).unwrap();
    assert!(host.discard_staged_upload("../elsewhere".to_owned(), &fresh(), Some(60_000)).is_err());
    host.stop().unwrap();
}

#[test]
fn a_change_for_an_unknown_root_is_a_typed_refusal_and_delivery_names_what_it_does_not_know() {
    let area = area();
    let host = running(&area);
    let change = WriteChange {
        request_id: vec![1],
        session_id: vec![7; 16],
        operation_seq: 1,
        root_id: vec![9; 16],
        kind: WriteKind::Create,
        item_id: Vec::new(),
        parent_item_id: None,
        name: Some("a.txt".into()),
        entry_kind: WriteEntryKind::File,
        base_version: Vec::new(),
        content: None,
        mtime_unix_nanos: None,
        exec: None,
        recursive: false,
        base_generation: None,
        parent_generation: None,
        observed_revision: None,
        restore_from: None,
    };
    let result = host.apply_change(change, &fresh(), Some(60_000)).unwrap();
    assert!(
        matches!(result, WriteResult::Refused { code: WriteRefusal::NotReady, .. }),
        "{result:?}"
    );

    let report = host
        .version_delivery(
            vec![DeliveryItem {
                root_id: vec![9; 16],
                item_id: vec![8; 16],
                content_version: vec![0; 40],
            }],
            &fresh(),
            Some(60_000),
        )
        .unwrap();
    assert_eq!(report.items.len(), 1);
    assert_eq!(report.items[0].state, DeliveryState::NotFound);
    assert_eq!(report.undelivered_count, 0, "an unknown item is not counted as only on this phone");

    let too_many = (0..257)
        .map(|n| DeliveryItem {
            root_id: vec![9; 16],
            item_id: vec![n as u8; 16],
            content_version: vec![0; 40],
        })
        .collect();
    assert!(host.version_delivery(too_many, &fresh(), Some(60_000)).is_err());
    host.stop().unwrap();
}

#[test]
fn the_wire_answers_map_to_the_typed_results() {
    use yadorilink_ipc_proto::shellipc as wire;
    let item = wire::ProviderAppliedItem {
        item_id: vec![1; 16],
        parent_item_id: Vec::new(),
        name: "a.txt".into(),
        entry_kind: wire::EntryKind::File as i32,
        content_version: vec![2; 40],
        metadata_version: vec![3; 40],
        size: 5,
        mtime_unix_nanos: 6,
        exec: true,
        current: true,
        namespace_revision: 7,
        parent_generation: 8,
    };
    let applied = WriteResult::from(wire::ProviderApplyChangeResponse {
        ok: true,
        outcome: wire::ProviderApplyOutcome::Concurrent as i32,
        item: Some(item),
        replayed: true,
        ..Default::default()
    });
    let WriteResult::Applied { outcome, item, replayed } = applied else { panic!() };
    assert_eq!((outcome, replayed), (WriteOutcome::Concurrent, true));
    assert_eq!(item.unwrap().content_version, vec![2; 40]);

    let refused = WriteResult::from(wire::ProviderApplyChangeResponse {
        ok: false,
        failure: wire::ProviderApplyFailure::KeepLocal as i32,
        error: "keep".into(),
        suggested_name: "a (phone).txt".into(),
        ..Default::default()
    });
    assert_eq!(
        refused,
        WriteResult::Refused {
            code: WriteRefusal::KeepLocal,
            message: "keep".into(),
            suggested_name: Some("a (phone).txt".into()),
        }
    );
    // Every wire failure has a refusal the app can show.
    for failure in [
        wire::ProviderApplyFailure::NotAuthorized,
        wire::ProviderApplyFailure::StaleView,
        wire::ProviderApplyFailure::NameCollision,
        wire::ProviderApplyFailure::LowDisk,
        wire::ProviderApplyFailure::OperationMismatch,
    ] {
        let result = WriteResult::from(wire::ProviderApplyChangeResponse {
            failure: failure as i32,
            ..Default::default()
        });
        assert!(matches!(result, WriteResult::Refused { .. }));
    }
    let request = wire::ProviderApplyChangeRequest::from(WriteChange {
        request_id: vec![1],
        session_id: vec![2; 16],
        operation_seq: 3,
        root_id: vec![4; 16],
        kind: WriteKind::Modify,
        item_id: vec![5; 16],
        parent_item_id: Some(Vec::new()),
        name: Some("b".into()),
        entry_kind: WriteEntryKind::Directory,
        base_version: vec![6; 40],
        content: Some(WriteContent { ingest_name: "up-1".into(), size: 9, sha256: vec![7; 32] }),
        mtime_unix_nanos: Some(10),
        exec: Some(true),
        recursive: true,
        base_generation: Some(11),
        parent_generation: Some(12),
        observed_revision: Some(13),
        restore_from: Some(crate::writes::RestoreSource {
            path: "a/b.txt".into(),
            version_hash: vec![9; 32],
        }),
    });
    assert_eq!(request.kind, wire::ProviderChangeKind::Modify as i32);
    assert_eq!(request.entry_kind, wire::EntryKind::Directory as i32);
    assert_eq!(request.parent_item_id, Some(Vec::new()), "an empty parent is the root");
    assert_eq!(request.content.unwrap().ingest_name, "up-1");
    assert_eq!(request.metadata.unwrap().exec, Some(true));
    assert_eq!(
        (request.base_generation, request.parent_generation, request.observed_revision),
        (Some(11), Some(12), Some(13))
    );
    let restore = request.restore_from.unwrap();
    assert_eq!((restore.path.as_str(), restore.version_hash), ("a/b.txt", vec![9; 32]));
}

/// The destination picker's device record: a full copy is `full_replica`, only an owner or
/// editor `can_write`, and an unrecognized storage mode never reads as a full replica.
#[test]
fn a_group_device_says_whether_it_keeps_a_full_replica() {
    let member = |storage, role| yadorilink_embedded_host::dto::MemberSummary {
        device_id: "d1".into(),
        device_name: "Mac".into(),
        role,
        relationship: yadorilink_embedded_host::dto::MemberRelationship::YourOtherDevice,
        storage,
        online: true,
        last_seen: Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(42)),
    };
    let full: GroupDevice = member(
        yadorilink_embedded_host::dto::MemberStorage::FullCopy,
        yadorilink_embedded_host::dto::ShareRole::Editor,
    )
    .into();
    assert!(full.full_replica && full.can_write && full.online && !full.is_this_device);
    assert_eq!(full.last_seen_unix, Some(42));
    let phone: GroupDevice = member(
        yadorilink_embedded_host::dto::MemberStorage::OnDemand,
        yadorilink_embedded_host::dto::ShareRole::Viewer,
    )
    .into();
    assert!(!phone.full_replica && !phone.can_write);
}

/// The device list needs an account, like the joinable list.
#[test]
fn listing_group_devices_needs_a_sign_in() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let refused =
        host.list_group_devices("g1".into(), &fresh(), Some(30_000)).expect_err("signed out");
    assert!(
        matches!(&refused, CallFailure::Account { error } if error.kind == AccountErrorKind::NotSignedIn),
        "{refused:?}"
    );
    host.stop().unwrap();
}

/// A phone cannot create an On-Demand share: its only member would keep no full copy.
#[test]
fn creating_an_on_demand_share_is_refused_typed() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let create = CreateShareRequest {
        group_name: "Photos".into(),
        folder: ShareFolder::Provider { display_name: "Photos".into(), request_token: "t".into() },
        on_demand: true,
        acknowledge_risks: false,
    };
    let refused = host.create_share(create, &fresh(), Some(30_000)).expect_err("refused");
    assert!(matches!(refused, CallFailure::NoFullReplica { .. }), "{refused:?}");
    host.stop().unwrap();
}

/// A refused pairing code has its own account error kind, so an app can say "make a new code".
#[test]
fn a_refused_pairing_code_has_its_own_account_error_kind() {
    use crate::app::{AccountError, AccountErrorKind};
    let error = AccountError::from(yadorilink_embedded_host::DesktopError::Refused {
        message: "m".into(),
        reason: yadorilink_embedded_host::RefusalReason::PairingCodeInvalid,
    });
    assert_eq!(error.kind, AccountErrorKind::PairingCodeInvalid);
}

/// Each of the seven hand-over refusals has its own account error kind; other refusals stay
/// `Refused`.
#[test]
fn every_primary_transfer_refusal_has_its_own_account_error_kind() {
    use crate::app::{AccountError, AccountErrorKind as K};
    use yadorilink_embedded_host::RefusalReason as R;
    let kind = |reason| {
        AccountError::from(yadorilink_embedded_host::DesktopError::Refused {
            message: "m".into(),
            reason,
        })
        .kind
    };
    let all = [
        (R::PrimaryTransferNotPrimary, K::PrimaryTransferNotPrimary),
        (R::PrimaryTransferTargetNotMember, K::PrimaryTransferTargetNotMember),
        (R::PrimaryTransferTargetSameAccount, K::PrimaryTransferTargetSameAccount),
        (R::PrimaryTransferOfferExpired, K::PrimaryTransferOfferExpired),
        (R::PrimaryTransferGroupNotActive, K::PrimaryTransferGroupNotActive),
        (R::PrimaryTransferConflict, K::PrimaryTransferConflict),
        (R::PrimaryTransferNotFound, K::PrimaryTransferNotFound),
    ];
    for (reason, expected) in all {
        assert_eq!(kind(reason), expected);
    }
    assert_eq!(kind(R::StartOverRestartRequired), K::StartOverRestartRequired);
}

/// The offer record keeps every field and reads times as Unix seconds.
#[test]
fn a_primary_transfer_converts_with_its_status_and_times() {
    use crate::app::{PrimaryTransfer, PrimaryTransferDirection, PrimaryTransferStatus};
    use yadorilink_embedded_host::dto as d;
    let at = |s| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s);
    let summary = |status| d::PrimaryTransferSummary {
        transfer_id: "t".into(),
        group_id: "g".into(),
        group_name: "Photos".into(),
        direction: d::PrimaryTransferDirection::Incoming,
        status,
        to_device_id: "dev".into(),
        created_at: at(10),
        expires_at: at(20),
    };
    let pending: PrimaryTransfer = summary(d::PrimaryTransferStatus::Pending).into();
    assert_eq!(pending.direction, PrimaryTransferDirection::Incoming);
    assert_eq!(pending.status, PrimaryTransferStatus::Pending);
    assert_eq!((pending.created_at_unix, pending.expires_at_unix), (10, 20));
    let other: PrimaryTransfer =
        summary(d::PrimaryTransferStatus::Other { raw: "x".into() }).into();
    assert_eq!(other.status, PrimaryTransferStatus::Other { raw: "x".into() });
}

/// All five hand-over calls need a sign-in.
#[test]
fn the_primary_transfer_calls_need_a_sign_in() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let signed_out = |r: Result<(), CallFailure>| {
        let refused = r.expect_err("signed out");
        assert!(
            matches!(&refused, CallFailure::Account { error } if error.kind == AccountErrorKind::NotSignedIn),
            "{refused:?}"
        );
    };
    let c = || fresh();
    signed_out(host.list_primary_transfers(&c(), Some(30_000)).map(drop));
    signed_out(host.offer_primary_transfer("g".into(), "d".into(), &c(), Some(30_000)).map(drop));
    signed_out(host.cancel_primary_transfer("g".into(), "t".into(), &c(), Some(30_000)).map(drop));
    signed_out(host.decline_primary_transfer("g".into(), "t".into(), &c(), Some(30_000)).map(drop));
    signed_out(host.accept_primary_transfer("g".into(), "t".into(), &c(), Some(30_000)).map(drop));
    host.stop().unwrap();
}

/// A restore that no device can supply has its own refusal, so the app can say "connect the
/// device that has the file".
#[test]
fn an_unavailable_version_is_a_typed_write_refusal() {
    use yadorilink_ipc_proto::shellipc as wire;
    let result = WriteResult::from(wire::ProviderApplyChangeResponse {
        ok: false,
        failure: wire::ProviderApplyFailure::VersionUnavailable as i32,
        error: "gone".into(),
        ..Default::default()
    });
    assert!(
        matches!(result, WriteResult::Refused { code: WriteRefusal::VersionUnavailable, .. }),
        "{result:?}"
    );
}

/// The history listings keep every field, add the device names that were readable and leave the
/// rest `None`.
#[test]
fn the_history_listings_convert_with_device_names() {
    use crate::writes::{
        DeletedParent, HistoryEntryKind, HistoryVersionState as State, ItemHistory,
    };
    use yadorilink_embedded_host as h;
    let names = std::collections::HashMap::from([("mac".to_owned(), "Mac".to_owned())]);
    let version = |seq, state, origin: Option<&str>| h::ItemVersion {
        version_seq: seq,
        version_hash: vec![seq as u8; 32],
        size: 10,
        mtime_unix_nanos: 5,
        state,
        origin_device_id: origin.map(str::to_owned),
        kind: h::HistoryEntryKind::File,
        restorable: state != h::HistoryVersionState::Current,
    };
    let history: ItemHistory = crate::writes::item_history_for_tests(h::HistoryOutcome {
        listing: h::ItemHistory {
            path: "a/b.txt".into(),
            live: true,
            versions: vec![
                version(2, h::HistoryVersionState::Current, Some("phone")),
                version(1, h::HistoryVersionState::Superseded, Some("mac")),
            ],
        },
        device_names: names.clone(),
    });
    assert_eq!(history.path, "a/b.txt");
    assert_eq!(history.versions[0].state, State::Current);
    assert!(!history.versions[0].restorable && history.versions[1].restorable);
    assert_eq!(history.versions[0].origin_device_name, None, "an unreadable name is None");
    assert_eq!(history.versions[1].origin_device_name.as_deref(), Some("Mac"));
    assert_eq!(history.versions[1].version_hash, vec![1; 32]);

    let deleted = crate::writes::deleted_items_for_tests(h::HistoryOutcome {
        listing: h::DeletedItems {
            truncated: true,
            items: vec![h::DeletedItem {
                path: "d/x.bin".into(),
                name: "x.bin".into(),
                parent: h::DeletedParent::Item(vec![7; 16]),
                version_seq: 3,
                version_hash: vec![3; 32],
                size: 99,
                deleted_at_unix_nanos: 123,
                origin_device_id: Some("mac".into()),
                kind: h::HistoryEntryKind::File,
                restorable: true,
                operation: Some("mac:ab".into()),
            }],
        },
        device_names: names,
    });
    assert!(deleted.truncated);
    let item = &deleted.items[0];
    assert_eq!(item.parent, DeletedParent::Item { item_id: vec![7; 16] });
    assert_eq!((item.kind, item.size), (HistoryEntryKind::File, 99));
    assert_eq!(item.origin_device_name.as_deref(), Some("Mac"));
    assert_eq!(item.operation.as_deref(), Some("mac:ab"));
}

/// Both listings need a running engine and a known root.
#[test]
fn the_history_listings_refuse_an_unknown_root() {
    let area = area();
    let host = MobileHost::new(area.config.clone());
    host.start().unwrap();
    let refused = host.list_deleted(vec![1; 16], &fresh(), Some(30_000)).expect_err("no such root");
    assert!(matches!(refused, CallFailure::Failed { .. }), "{refused:?}");
    let refused = host
        .list_versions(vec![1; 16], vec![2; 16], &fresh(), Some(30_000))
        .expect_err("no such root");
    assert!(matches!(refused, CallFailure::Failed { .. }), "{refused:?}");
    host.stop().unwrap();
}
