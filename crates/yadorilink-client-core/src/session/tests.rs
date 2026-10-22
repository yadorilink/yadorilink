use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::SystemTime;

use tokio::sync::oneshot;
use tokio::time::timeout;

use super::*;
use crate::dto::{BrowserPurpose, LoginFlow, SignInState};
use crate::error::{NetworkErrorKind, PermissionDeniedReason};

fn options(timeout: Option<Duration>) -> LoginOptions {
    LoginOptions { flow: LoginFlow::Loopback, overall_timeout: timeout }
}

fn no_precheck() -> LoginPrecheckFn {
    Box::new(|| Ok(()))
}

fn account() -> AccountStatus {
    AccountStatus {
        sign_in: SignInState::SignedIn,
        client_id: Some("client-1".into()),
        this_device_id: None,
        device_registered: false,
        default_device_name: "Mac".into(),
        has_linked_folders: None,
        start_over_pending: false,
    }
}

fn loopback_steps() -> Vec<LoginEvent> {
    vec![
        LoginEvent::Enrolling,
        LoginEvent::OpenBrowser {
            url: "https://example.test/approve".into(),
            purpose: BrowserPurpose::ApproveDevice,
        },
        LoginEvent::WaitingForApproval { expires_in: Duration::from_secs(600) },
        LoginEvent::OpenBrowser {
            url: "https://example.test/authorize".into(),
            purpose: BrowserPurpose::SignIn,
        },
        LoginEvent::WaitingForAuthorization,
    ]
}

/// A flow that reports `steps`, then waits for `gate`, then "writes the
/// credential" (sets `written`) and signs in.
fn gated_flow(
    steps: Vec<LoginEvent>,
    gate: oneshot::Receiver<()>,
    written: Arc<AtomicBool>,
) -> LoginFlowFn {
    Box::new(move |sink| {
        Box::pin(async move {
            for step in steps {
                sink.send(step);
            }
            let _ = gate.await;
            written.store(true, Ordering::SeqCst);
            Ok(account())
        })
    })
}

async fn next(session: &LoginSession) -> Option<LoginEvent> {
    timeout(Duration::from_secs(5), session.next_event()).await.expect("an event within 5s")
}

#[tokio::test]
async fn login_events_follow_documented_order() {
    let (open, gate) = oneshot::channel();
    let written = Arc::new(AtomicBool::new(false));
    let session = LoginSession::with_flow(
        options(None),
        no_precheck(),
        gated_flow(loopback_steps(), gate, written),
    );
    session.begin().unwrap();
    for expected in loopback_steps() {
        assert_eq!(next(&session).await, Some(expected));
    }
    open.send(()).unwrap();
    assert_eq!(next(&session).await, Some(LoginEvent::SignedIn { account: account() }));
    assert_eq!(next(&session).await, None, "nothing after the terminal event");
    assert_eq!(next(&session).await, None);
}

#[tokio::test]
async fn login_cancel_writes_nothing_to_credential_store() {
    let (open, gate) = oneshot::channel();
    let written = Arc::new(AtomicBool::new(false));
    let session = LoginSession::with_flow(
        options(None),
        no_precheck(),
        gated_flow(loopback_steps(), gate, written.clone()),
    );
    session.begin().unwrap();
    assert_eq!(next(&session).await, Some(LoginEvent::Enrolling));
    session.cancel();
    session.cancel();
    // The steps already queued are dropped: the next event is the cancel.
    assert_eq!(next(&session).await, Some(LoginEvent::Cancelled));
    assert_eq!(next(&session).await, None);
    // Even if the browser comes back now, the stopped flow writes nothing.
    let _ = open.send(());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!written.load(Ordering::SeqCst), "a cancelled sign-in must not store a credential");
}

#[tokio::test]
async fn a_terminal_event_queued_before_cancel_is_still_delivered() {
    let (open, gate) = oneshot::channel();
    let session = LoginSession::with_flow(
        options(None),
        no_precheck(),
        gated_flow(vec![], gate, Arc::new(AtomicBool::new(false))),
    );
    session.begin().unwrap();
    open.send(()).unwrap();
    // Let the flow finish and queue its SignedIn.
    tokio::time::sleep(Duration::from_millis(50)).await;
    session.cancel();
    assert_eq!(next(&session).await, Some(LoginEvent::SignedIn { account: account() }));
    assert_eq!(next(&session).await, None);
}

#[tokio::test]
async fn a_failed_flow_ends_with_its_error() {
    let error = DesktopError::PermissionDenied {
        message: "refused".into(),
        reason: PermissionDeniedReason::SessionRejected,
    };
    let failure = error.clone();
    let session = LoginSession::with_flow(
        options(None),
        no_precheck(),
        Box::new(move |sink| {
            Box::pin(async move {
                sink.send(LoginEvent::Enrolling);
                Err(failure)
            })
        }),
    );
    session.begin().unwrap();
    assert_eq!(next(&session).await, Some(LoginEvent::Enrolling));
    assert_eq!(next(&session).await, Some(LoginEvent::Failed { error }));
    assert_eq!(next(&session).await, None);
}

#[tokio::test]
async fn an_overall_timeout_ends_the_flow_as_a_network_failure() {
    let (_open, gate) = oneshot::channel();
    let written = Arc::new(AtomicBool::new(false));
    let session = LoginSession::with_flow(
        options(Some(Duration::from_millis(50))),
        no_precheck(),
        gated_flow(vec![LoginEvent::Enrolling], gate, written.clone()),
    );
    session.begin().unwrap();
    assert_eq!(next(&session).await, Some(LoginEvent::Enrolling));
    match next(&session).await {
        Some(LoginEvent::Failed {
            error: DesktopError::Network { kind: NetworkErrorKind::Unreachable, message },
        }) => assert_eq!(message, "timed out waiting for browser sign-in"),
        other => panic!("expected a timeout failure, got {other:?}"),
    }
    assert!(!written.load(Ordering::SeqCst));
}

#[tokio::test]
async fn begin_runs_once_and_reports_the_precheck_refusal() {
    let refused = DesktopError::PermissionDenied {
        message: "already enrolled".into(),
        reason: PermissionDeniedReason::SessionRejected,
    };
    let refusal = refused.clone();
    let flow_ran = Arc::new(AtomicBool::new(false));
    let ran = flow_ran.clone();
    let session = LoginSession::with_flow(
        options(None),
        Box::new(move || Err(refusal.clone())),
        Box::new(move |_| {
            ran.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(account()) })
        }),
    );
    assert_eq!(session.begin(), Err(refused));
    assert!(matches!(session.begin(), Err(DesktopError::InvalidInput { .. })));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!flow_ran.load(Ordering::SeqCst));

    let (_open, gate) = oneshot::channel();
    let session = LoginSession::with_flow(
        options(None),
        no_precheck(),
        gated_flow(vec![], gate, Arc::new(AtomicBool::new(false))),
    );
    session.begin().unwrap();
    assert!(matches!(session.begin(), Err(DesktopError::InvalidInput { .. })));
    session.cancel();
}

#[tokio::test]
async fn cancelling_before_begin_ends_the_session() {
    let (_open, gate) = oneshot::channel();
    let session = LoginSession::with_flow(
        options(None),
        no_precheck(),
        gated_flow(vec![], gate, Arc::new(AtomicBool::new(false))),
    );
    session.cancel();
    assert_eq!(next(&session).await, Some(LoginEvent::Cancelled));
    assert!(matches!(session.begin(), Err(DesktopError::InvalidInput { .. })));
    assert_eq!(next(&session).await, None);
}

#[test]
fn begin_without_a_runtime_is_an_internal_error_not_a_panic() {
    let (_open, gate) = oneshot::channel();
    let session = LoginSession::with_flow(
        options(None),
        no_precheck(),
        gated_flow(vec![], gate, Arc::new(AtomicBool::new(false))),
    );
    assert!(matches!(session.begin(), Err(DesktopError::Internal { .. })));
}

// ---- status watch -------------------------------------------------------------

fn unavailable(message: &str) -> StatusUpdate {
    StatusUpdate::Unavailable {
        error: DesktopError::Internal { message: message.into(), category: "test".into() },
    }
}

/// A poll that reports whatever `current` holds, counting polls.
fn scripted_poll(current: Arc<Mutex<StatusUpdate>>, polls: Arc<AtomicUsize>) -> StatusPollFn {
    Arc::new(move || {
        let current = current.clone();
        let polls = polls.clone();
        Box::pin(async move {
            polls.fetch_add(1, Ordering::SeqCst);
            current.lock().unwrap().clone()
        })
    })
}

async fn next_update(watch: &StatusWatch) -> Option<StatusUpdate> {
    timeout(Duration::from_secs(5), watch.next()).await.expect("an update within 5s")
}

async fn nothing_within(watch: &StatusWatch, wait: Duration) -> bool {
    timeout(wait, watch.next()).await.is_err()
}

#[tokio::test]
async fn status_watch_is_latest_wins_and_dedups() {
    let current = Arc::new(Mutex::new(unavailable("a")));
    let polls = Arc::new(AtomicUsize::new(0));
    let watch = StatusWatch::start(
        scripted_poll(current.clone(), polls.clone()),
        Duration::from_millis(10),
    );

    assert_eq!(next_update(&watch).await, Some(unavailable("a")));
    // Polling goes on, but an unchanged result is not delivered again.
    assert!(nothing_within(&watch, Duration::from_millis(100)).await);
    assert!(polls.load(Ordering::SeqCst) > 2, "the loop keeps polling");

    // Two changes while nobody is reading: only the latest is delivered.
    *current.lock().unwrap() = unavailable("b");
    tokio::time::sleep(Duration::from_millis(60)).await;
    *current.lock().unwrap() = unavailable("c");
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(next_update(&watch).await, Some(unavailable("c")));
    assert!(nothing_within(&watch, Duration::from_millis(60)).await);

    // A forced poll is delivered even when nothing changed.
    watch.refresh();
    assert_eq!(next_update(&watch).await, Some(unavailable("c")));

    watch.cancel();
    watch.cancel();
    assert_eq!(next_update(&watch).await, None);
    let after_cancel = polls.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(polls.load(Ordering::SeqCst), after_cancel, "a cancelled watch stops polling");
}

#[tokio::test]
async fn refresh_polls_now_rather_than_at_the_next_tick() {
    let current = Arc::new(Mutex::new(unavailable("a")));
    let polls = Arc::new(AtomicUsize::new(0));
    let watch = StatusWatch::start(scripted_poll(current.clone(), polls), Duration::from_secs(60));
    assert_eq!(next_update(&watch).await, Some(unavailable("a")));
    *current.lock().unwrap() = unavailable("b");
    watch.refresh();
    assert_eq!(next_update(&watch).await, Some(unavailable("b")));
}

#[tokio::test]
async fn the_capture_time_alone_is_not_a_change() {
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = polls.clone();
    let poll: StatusPollFn = Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let response = yadorilink_ipc_proto::daemonctl::StatusResponse::default();
            StatusUpdate::Snapshot {
                snapshot: crate::dto::status_snapshot(
                    &response,
                    crate::dto::AccountStatus {
                        sign_in: crate::dto::SignInState::SignedOut,
                        client_id: None,
                        this_device_id: None,
                        device_registered: false,
                        default_device_name: String::new(),
                        has_linked_folders: None,
                        start_over_pending: false,
                    },
                    SystemTime::now(),
                ),
            }
        })
    });
    let watch = StatusWatch::start(poll, Duration::from_millis(10));
    assert!(matches!(next_update(&watch).await, Some(StatusUpdate::Snapshot { .. })));
    assert!(nothing_within(&watch, Duration::from_millis(100)).await);
    assert!(polls.load(Ordering::SeqCst) > 2);
}

#[tokio::test]
async fn dropping_the_watch_stops_the_loop() {
    let current = Arc::new(Mutex::new(unavailable("a")));
    let polls = Arc::new(AtomicUsize::new(0));
    let watch =
        StatusWatch::start(scripted_poll(current, polls.clone()), Duration::from_millis(10));
    assert!(next_update(&watch).await.is_some());
    drop(watch);
    tokio::time::sleep(Duration::from_millis(30)).await;
    let after_drop = polls.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(polls.load(Ordering::SeqCst), after_drop);
}
