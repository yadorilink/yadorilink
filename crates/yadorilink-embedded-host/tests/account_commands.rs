//! The account commands: a sign-in the host polls and cancels (scripted, so every step is
//! released by the test, not by a server or the clock), and the commands that need an account
//! answering "not signed in" from the engine's own state directory.

#![allow(
    clippy::result_large_err,
    reason = "the sign-in precheck's signature is the client layer's, which returns its own error type"
)]

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use yadorilink_client_core::dto::{LoginOptions, SignInState};
use yadorilink_client_core::session::LoginSession;
use yadorilink_client_core::DesktopError;
use yadorilink_embedded_host::{
    AccountCommand, BeginSignIn, CallError, CallOptions, CancelHandle, Command, CommandOutput,
    EmbeddedHost, LoginEvent, PollSignIn, SignInCancellation, SignInId, SignInStep,
};

mod support;
use support::{area, serialized};

fn within(secs: u64) -> CallOptions {
    CallOptions { deadline: Some(Duration::from_secs(secs)), cancel: CancelHandle::new() }
}

/// Released by the test: the user approving the device, and the sign-in finishing.
#[derive(Clone, Default)]
struct Script {
    approve: Arc<Notify>,
    finish: Arc<Notify>,
}

/// A sign-in that reports `Enrolling`, waits to be approved, shows its code, waits to finish.
fn scripted_sign_in(
    script: Script,
) -> impl Fn(std::path::PathBuf, LoginOptions, bool) -> Arc<LoginSession> + Send + Sync + 'static {
    move |dir, options, _reauthenticate| {
        let script = script.clone();
        Arc::new(LoginSession::with_flow(
            options,
            Box::new(|| Ok(())),
            Box::new(move |sink| {
                Box::pin(async move {
                    sink.send(LoginEvent::Enrolling);
                    script.approve.notified().await;
                    sink.send(LoginEvent::ShowDeviceCode {
                        verification_uri: "https://example.invalid/device".into(),
                        user_code: "ABCD-EFGH".into(),
                    });
                    script.finish.notified().await;
                    let settings = yadorilink_client_core::coordination::credential_store::CredentialSettings::new(
                        yadorilink_embedded_host::CredentialBackend::File(
                            dir.join("credentials.json"),
                        ),
                        yadorilink_embedded_host::KeyMirror::Disabled,
                    );
                    Ok(yadorilink_client_core::account_status_in(&dir, &settings, None))
                })
            }),
        ))
    }
}

fn host_with(script: &Script) -> (EmbeddedHost, support::Area) {
    let area = area();
    let host = EmbeddedHost::new(area.config.clone())
        .with_sign_in_for_test(scripted_sign_in(script.clone()));
    host.start().unwrap();
    (host, area)
}

fn account(host: &EmbeddedHost, command: AccountCommand) -> Result<CommandOutput, CallError> {
    host.execute(Command::Account(command), &within(30))
}

fn begin(host: &EmbeddedHost) -> SignInId {
    let CommandOutput::SignInBegun(id) =
        account(host, AccountCommand::BeginSignIn(BeginSignIn::default())).unwrap()
    else {
        panic!("a sign-in id")
    };
    id
}

fn poll(host: &EmbeddedHost, id: SignInId, after: u64) -> Result<SignInStep, CallError> {
    match account(host, AccountCommand::PollSignIn(PollSignIn { id, after }))? {
        CommandOutput::SignInStep(step) => Ok(step),
        other => panic!("a sign-in step, got {other:?}"),
    }
}

/// The call failed with the product's `InvalidInput`.
fn assert_invalid_input<T: std::fmt::Debug>(result: Result<T, CallError>, expected: &str) {
    match result {
        Err(CallError::Account(error)) if matches!(*error, DesktopError::InvalidInput { .. }) => {}
        other => panic!("expected {expected}: {other:?}"),
    }
}

fn not_signed_in(result: Result<CommandOutput, CallError>) {
    match result {
        Err(CallError::Account(error)) if matches!(*error, DesktopError::NotSignedIn { .. }) => {}
        other => panic!("expected NotSignedIn: {other:?}"),
    }
}

#[test]
fn a_sign_in_is_polled_step_by_step_and_a_timed_out_poll_loses_no_step() {
    let _serial = serialized();
    let script = Script::default();
    let (host, _area) = host_with(&script);
    let id = begin(&host);

    let first = poll(&host, id, 0).unwrap();
    assert_eq!((first.seq, &first.event), (1, &LoginEvent::Enrolling));
    // The answer was lost: asking again for the step after 0 gives the same step.
    assert_eq!(poll(&host, id, 0).unwrap(), first);

    // Nothing happens within the deadline: the poll ends, and the sign-in goes on.
    let short =
        CallOptions { deadline: Some(Duration::from_millis(200)), cancel: CancelHandle::new() };
    assert_eq!(
        host.execute(
            Command::Account(AccountCommand::PollSignIn(PollSignIn { id, after: 1 })),
            &short
        ),
        Err(CallError::DeadlineExceeded { still_running: false })
    );
    script.approve.notify_one();
    let second = poll(&host, id, 1).unwrap();
    assert_eq!(second.seq, 2);
    assert!(
        matches!(second.event, LoginEvent::ShowDeviceCode { ref user_code, .. } if user_code == "ABCD-EFGH")
    );

    script.finish.notify_one();
    let last = poll(&host, id, 2).unwrap();
    assert_eq!(last.seq, 3);
    let LoginEvent::SignedIn { account } = last.event else { panic!("signed in") };
    assert_eq!(account.sign_in, SignInState::SignedOut, "the script wrote no credential");

    // The sign-in has ended: nothing follows the last step.
    assert_invalid_input(poll(&host, id, 3), "the sign-in to have ended");
    host.stop().unwrap();
}

#[test]
fn cancelling_a_sign_in_ends_it_as_cancelled_and_is_repeatable() {
    let _serial = serialized();
    let script = Script::default();
    let (host, _area) = host_with(&script);
    let id = begin(&host);
    assert_eq!(poll(&host, id, 0).unwrap().event, LoginEvent::Enrolling);

    assert_eq!(account(&host, AccountCommand::CancelSignIn(id)).unwrap(), CommandOutput::Done);
    assert_eq!(poll(&host, id, 1).unwrap().event, LoginEvent::Cancelled);
    assert_eq!(account(&host, AccountCommand::CancelSignIn(id)).unwrap(), CommandOutput::Done);
    host.stop().unwrap();
}

#[test]
fn beginning_a_sign_in_ends_the_one_before_and_a_restart_forgets_it() {
    let _serial = serialized();
    let script = Script::default();
    let (host, _area) = host_with(&script);
    let first = begin(&host);
    let second = begin(&host);
    assert_ne!(first, second);
    assert_invalid_input(poll(&host, first, 0), "the first sign-in to have ended");
    assert_eq!(poll(&host, second, 0).unwrap().event, LoginEvent::Enrolling);

    host.suspend().unwrap();
    host.resume().unwrap();
    assert_invalid_input(poll(&host, second, 1), "a restarted engine to forget the sign-in");
    // A new sign-in after the restart never reuses an id from before it: the stale id can
    // neither read the new sign-in's steps nor cancel it.
    let third = begin(&host);
    assert!(third != first && third != second);
    assert_invalid_input(poll(&host, second, 0), "the old id to stay invalid");
    assert_eq!(account(&host, AccountCommand::CancelSignIn(second)).unwrap(), CommandOutput::Done);
    assert_eq!(poll(&host, third, 0).unwrap().event, LoginEvent::Enrolling, "not cancelled");
    host.stop().unwrap();
}

#[test]
fn a_sign_in_the_precheck_refuses_is_a_typed_error_of_the_begin() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone()).with_sign_in_for_test(|_, options, _| {
        Arc::new(LoginSession::with_flow(
            options,
            Box::new(|| Err(DesktopError::invalid_input("already enrolled", "session"))),
            Box::new(|_| Box::pin(async { unreachable!("a refused sign-in does not start") })),
        ))
    });
    host.start().unwrap();
    assert_invalid_input(
        account(&host, AccountCommand::BeginSignIn(BeginSignIn::default())),
        "the precheck's refusal",
    );
    host.stop().unwrap();
}

#[test]
fn the_commands_that_need_an_account_say_not_signed_in() {
    let _serial = serialized();
    let (host, _area) = host_with(&Script::default());
    for command in [
        AccountCommand::SignOut,
        AccountCommand::RegisterDevice { name: "phone".into() },
        AccountCommand::DeletionImpact,
        AccountCommand::ListJoinableGroups,
        AccountCommand::DeletionStatus,
        AccountCommand::RequestDeletion { acknowledge_impact: false },
        AccountCommand::ConfirmDeletion { confirmation_token: "token".into() },
        AccountCommand::CancelDeletion,
        AccountCommand::CompleteDeletion,
    ] {
        not_signed_in(account(&host, command));
    }
    host.stop().unwrap();
}

/// The account state is read from the engine's own directory: a device registered in one engine's
/// directory is not another's.
#[test]
fn the_account_status_is_the_engines_own() {
    let _serial = serialized();
    let (host, area) = host_with(&Script::default());
    let (other, _other_area) = host_with(&Script::default());
    let status = |host: &EmbeddedHost| {
        let CommandOutput::Account(status) = account(host, AccountCommand::Status).unwrap() else {
            panic!("an account status")
        };
        status
    };
    assert!(!status(&host).device_registered);

    // Written after the engine started: an engine refuses to start on a registration whose key
    // is missing.
    yadorilink_client_core::coordination::device_config::save_in(
        &area.config.config_dir,
        &yadorilink_client_core::coordination::device_config::DeviceConfig {
            device_id: "device-1".into(),
            coordination_addr: "http://127.0.0.1:1".into(),
            signing_public_key: String::new(),
            config_version: yadorilink_client_core::coordination::device_config::CONFIG_VERSION,
        },
    )
    .unwrap();
    let mine = status(&host);
    assert!(mine.device_registered);
    assert_eq!(mine.this_device_id.as_deref(), Some("device-1"));
    assert_eq!(mine.has_linked_folders, Some(false));
    assert!(!status(&other).device_registered);
    other.stop().unwrap();
    host.stop().unwrap();
}

#[test]
fn a_step_up_asks_the_step_up_flow_and_needs_a_sign_in() {
    let _serial = serialized();
    // The flag reaches the session factory.
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let area = area();
    let recorder = seen.clone();
    let host = EmbeddedHost::new(area.config.clone()).with_sign_in_for_test(
        move |_dir, options, reauthenticate| {
            recorder.lock().unwrap().push(reauthenticate);
            Arc::new(LoginSession::with_flow(
                options,
                Box::new(|| Ok(())),
                Box::new(|_| Box::pin(std::future::pending())),
            ))
        },
    );
    host.start().unwrap();
    let step_up = BeginSignIn { reauthenticate: true, ..BeginSignIn::default() };
    account(&host, AccountCommand::BeginSignIn(step_up)).unwrap();
    account(&host, AccountCommand::BeginSignIn(BeginSignIn::default())).unwrap();
    assert_eq!(*seen.lock().unwrap(), [true, false]);
    host.stop().unwrap();

    // The product's step-up needs a credential: signed out, the begin itself says so.
    let area = self::area();
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    let step_up = BeginSignIn { reauthenticate: true, ..BeginSignIn::default() };
    not_signed_in(account(&host, AccountCommand::BeginSignIn(step_up)));
}

fn cancel_current(host: &EmbeddedHost) -> SignInCancellation {
    match account(host, AccountCommand::CancelCurrentSignIn).unwrap() {
        CommandOutput::SignInCancellation(cancellation) => cancellation,
        other => panic!("a cancellation, got {other:?}"),
    }
}

#[test]
fn cancelling_the_current_sign_in_needs_no_id_and_is_safe_when_there_is_none() {
    let _serial = serialized();
    let script = Script::default();
    let (host, _area) = host_with(&script);
    assert_eq!(cancel_current(&host), SignInCancellation::NothingToCancel);

    // The host never learned the id (its begin timed out): it cancels what the engine holds.
    let id = begin(&host);
    assert_eq!(poll(&host, id, 0).unwrap().event, LoginEvent::Enrolling);
    assert_eq!(cancel_current(&host), SignInCancellation::Stopped(id));
    assert_eq!(poll(&host, id, 1).unwrap().event, LoginEvent::Cancelled);
    assert_eq!(cancel_current(&host), SignInCancellation::Stopped(id), "repeatable");

    // The flow was stopped: letting it go on completes nothing (the script writes no store;
    // the stopped flow is gone, so its poll ends).
    script.approve.notify_one();
    script.finish.notify_one();
    assert_invalid_input(poll(&host, id, 2), "the cancelled sign-in to have ended");
    host.stop().unwrap();
}

#[test]
fn cancelling_a_sign_in_that_already_finished_says_so() {
    let _serial = serialized();
    let script = Script::default();
    let (host, _area) = host_with(&script);
    let id = begin(&host);
    script.approve.notify_one();
    script.finish.notify_one();
    // Wait for the terminal step: the flow has returned.
    let mut after = 0;
    loop {
        let step = poll(&host, id, after).unwrap();
        after = step.seq;
        if matches!(step.event, LoginEvent::SignedIn { .. }) {
            break;
        }
    }
    assert_eq!(cancel_current(&host), SignInCancellation::AlreadyFinished(id));
    host.stop().unwrap();
}

/// A sign-in whose single poll "writes the credential" slowly: it says it is inside the poll,
/// holds the thread for 300 ms and sets `written`, as the product's flow writes inside one poll.
fn slow_writing_sign_in(
    entered: std::sync::mpsc::Sender<()>,
    written: Arc<std::sync::atomic::AtomicBool>,
) -> LoginSession {
    use std::sync::atomic::Ordering;
    LoginSession::with_flow(
        LoginOptions {
            flow: yadorilink_client_core::dto::LoginFlow::DeviceCode,
            overall_timeout: None,
        },
        Box::new(|| Ok(())),
        Box::new(move |_sink| {
            Box::pin(async move {
                let _ = entered.send(());
                std::thread::sleep(Duration::from_millis(300));
                written.store(true, Ordering::SeqCst);
                Ok(yadorilink_client_core::dto::AccountStatus {
                    sign_in: SignInState::SignedOut,
                    client_id: None,
                    this_device_id: None,
                    device_registered: false,
                    default_device_name: String::new(),
                    has_linked_folders: None,
                    start_over_pending: false,
                })
            })
        }),
    )
}

/// A write racing a cancel, for the ordinary sign-in and the step-up: the cancel does not
/// return before the write that was in flight has finished, and says the flow had finished.
#[test]
fn a_cancel_returns_only_after_a_racing_credential_write_has_finished() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let _serial = serialized();
    for reauthenticate in [false, true] {
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let written = Arc::new(AtomicBool::new(false));
        let session =
            std::sync::Mutex::new(Some(slow_writing_sign_in(entered_tx, written.clone())));
        let area = area();
        let host = EmbeddedHost::new(area.config.clone()).with_sign_in_for_test(move |_, _, _| {
            Arc::new(session.lock().unwrap().take().expect("one sign-in"))
        });
        host.start().unwrap();
        let step_up = BeginSignIn { reauthenticate, ..BeginSignIn::default() };
        let CommandOutput::SignInBegun(id) =
            account(&host, AccountCommand::BeginSignIn(step_up)).unwrap()
        else {
            panic!("a sign-in id")
        };
        entered.recv_timeout(Duration::from_secs(10)).expect("the flow reached its write");

        for cancel in [AccountCommand::CancelCurrentSignIn, AccountCommand::CancelSignIn(id)] {
            // (The second command repeats against the finished flow.)
            let is_current = matches!(cancel, AccountCommand::CancelCurrentSignIn);
            let output = account(&host, cancel).unwrap();
            assert!(
                written.load(Ordering::SeqCst),
                "the cancel returned while the credential write was still running"
            );
            if is_current {
                assert_eq!(
                    output,
                    CommandOutput::SignInCancellation(SignInCancellation::AlreadyFinished(id))
                );
            }
        }
        host.stop().unwrap();
    }
}

/// Beginning a sign-in stops the one before first: the new sign-in's precheck reads the state the
/// old flow left, after its in-flight write.
#[test]
fn beginning_a_sign_in_stops_the_previous_flow_before_the_new_one_checks() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let _serial = serialized();
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let written = Arc::new(AtomicBool::new(false));
    let first = std::sync::Mutex::new(Some(slow_writing_sign_in(entered_tx, written.clone())));
    let seen_by_precheck = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let (written_for_check, seen) = (written.clone(), seen_by_precheck.clone());
    let area = area();
    let host =
        EmbeddedHost::new(area.config.clone()).with_sign_in_for_test(move |_, options, _| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Arc::new(first.lock().unwrap().take().unwrap());
            }
            let (written, seen) = (written_for_check.clone(), seen.clone());
            Arc::new(LoginSession::with_flow(
                options,
                Box::new(move || {
                    seen.store(written.load(Ordering::SeqCst), Ordering::SeqCst);
                    Ok(())
                }),
                Box::new(|_| Box::pin(std::future::pending())),
            ))
        });
    host.start().unwrap();
    begin(&host);
    entered.recv_timeout(Duration::from_secs(10)).expect("the flow reached its write");
    begin(&host);
    assert!(
        seen_by_precheck.load(Ordering::SeqCst),
        "the new sign-in checked the store while the previous flow could still write"
    );
    host.stop().unwrap();
}
