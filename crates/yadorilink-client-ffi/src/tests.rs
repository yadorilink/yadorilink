use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use yadorilink_client_core::dto::{
    BrowserPurpose, CoreConfig, DaemonLaunch, LoginFlow, LoginOptions, StatusUpdate,
};
use yadorilink_client_core::error::{DaemonUnavailableReason, DesktopError};

use super::*;

/// Drives a future on the calling thread with no Tokio runtime anywhere in
/// sight, the way Swift's executor drives an exported future.
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
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        assert!(std::time::Instant::now() < deadline, "future did not finish within 10s");
        std::thread::park_timeout(Duration::from_millis(50));
    }
}

/// No test in this module may reach the OS keychain: it blocks on a permission dialog and leaks
/// items. Both switches are constant, so setting them once for the whole test process is safe.
fn hermetic_keychain() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var("YADORILINK_DISABLE_OS_KEYRING", "1");
        std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    });
}

/// The tests share `YADORILINK_CONTROL_SOCKET`, a process-global variable.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn without_daemon<T>(body: impl FnOnce() -> T) -> T {
    hermetic_keychain();
    let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("nobody-home.sock"));
    let result = body();
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
    result
}

fn client() -> Arc<ClientCore> {
    hermetic_keychain();
    ClientCore::new(CoreConfig { daemon_launch: DaemonLaunch::SpawnBinary { path: None } })
}

#[test]
fn a_call_polled_by_a_foreign_executor_runs_on_the_client_runtime() {
    let thread = block_on(bridge(async {
        // Timers need the Tokio reactor: this only finishes on the runtime.
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(std::thread::current().name().map(str::to_owned))
    }));
    assert_eq!(thread.unwrap().as_deref(), Some("yadorilink-client"));
}

#[test]
fn the_facade_reports_an_absent_daemon_across_the_bridge() {
    let error = without_daemon(|| block_on(client().status_snapshot())).unwrap_err();
    assert!(
        matches!(
            error,
            DesktopError::DaemonUnavailable { reason: DaemonUnavailableReason::NotRunning, .. }
        ),
        "{error:?}"
    );
    let account = without_daemon(|| block_on(client().account_status()));
    assert_eq!(account.has_linked_folders, None);
    // Only the real answer names this device; the bridge-failure fallback
    // leaves the name empty, and would otherwise pass the check above.
    assert!(!account.default_device_name.is_empty(), "account_status fell back: {account:?}");
}

#[test]
fn errors_keep_their_case_and_field_across_the_bridge() {
    let error =
        block_on(client().run_preflight("/no/such/place/for/yadorilink".into())).unwrap_err();
    assert!(
        matches!(error, DesktopError::InvalidInput { field: Some(ref f), .. } if f == "local_path"),
        "{error:?}"
    );
}

#[test]
fn a_panicking_task_is_an_internal_error_not_a_crash() {
    let result: Result<(), DesktopError> = block_on(bridge(async {
        panic!("simulated failure inside the client layer");
    }));
    match result {
        Err(DesktopError::Internal { category, .. }) => assert_eq!(category, "panic"),
        other => panic!("expected an internal error, got {other:?}"),
    }
    // The runtime survives the panic.
    assert_eq!(block_on(bridge(async { Ok(7) })).unwrap(), 7);
}

#[test]
fn a_panicking_synchronous_body_returns_its_fallback() {
    let value = guarded(|| "fallback", || panic!("simulated"));
    assert_eq!(value, "fallback");
}

/// A sign-in whose flow reports two events, then waits for the returned
/// sender before it writes `written`: the stand-in for storing a credential.
fn scripted_session(
    written: Arc<AtomicBool>,
) -> (Arc<LoginSession>, tokio::sync::oneshot::Sender<()>) {
    let (release_write, gate) = tokio::sync::oneshot::channel::<()>();
    let inner = core::session::LoginSession::with_flow(
        LoginOptions { flow: LoginFlow::Loopback, overall_timeout: None },
        Box::new(|| Ok(())),
        Box::new(move |sink| {
            Box::pin(async move {
                sink.send(LoginEvent::Enrolling);
                sink.send(LoginEvent::OpenBrowser {
                    url: "https://example.test/approve".into(),
                    purpose: BrowserPurpose::ApproveDevice,
                });
                if gate.await.is_err() {
                    return Err(DesktopError::Internal {
                        message: "the write gate was dropped".into(),
                        category: "x".into(),
                    });
                }
                written.store(true, Ordering::SeqCst);
                Err(DesktopError::Internal { message: "unreachable".into(), category: "x".into() })
            })
        }),
    );
    (LoginSession::wrap(Arc::new(inner)), release_write)
}

#[test]
fn a_sign_in_begun_outside_any_runtime_runs_and_cancels_through_its_channel() {
    let written = Arc::new(AtomicBool::new(false));
    let (session, release_write) = scripted_session(written.clone());
    session.begin().unwrap();
    assert_eq!(block_on(session.next_event()), Some(LoginEvent::Enrolling));

    let other = session.clone();
    std::thread::spawn(move || other.cancel()).join().unwrap();
    assert_eq!(block_on(session.next_event()), Some(LoginEvent::Cancelled));
    assert_eq!(block_on(session.next_event()), None);
    assert!(matches!(session.begin(), Err(DesktopError::InvalidInput { .. })));
    // Let the flow go on to its write. A cancelled flow was dropped, so
    // nothing is left to receive this and nothing is written.
    let _ = release_write.send(());
    std::thread::sleep(Duration::from_millis(50));
    assert!(!written.load(Ordering::SeqCst), "a cancelled sign-in wrote its credential");
}

#[test]
fn a_status_watch_started_outside_any_runtime_polls_and_stops_on_cancel() {
    let watch = without_daemon(|| {
        let watch = client().watch_status(Duration::from_millis(20));
        let first = block_on(watch.next());
        assert!(
            matches!(first, Some(StatusUpdate::Unavailable { ref error }) if error.is_daemon_unavailable()),
            "{first:?}"
        );
        watch
    });
    watch.refresh();
    watch.cancel();
    watch.cancel();
    assert_eq!(block_on(watch.next()), None);
}
