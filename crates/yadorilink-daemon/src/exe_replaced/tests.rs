#![cfg(test)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use super::*;
use crate::application::ports::{BoxFuture, SafeStopBusy};

fn write(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
}

/// A bundle layout with an executable and an Info.plist.
fn bundle(root: &Path) -> (PathBuf, PathBuf) {
    let contents = root.join("YadoriLink.app").join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    let exe = contents.join("MacOS").join("daemon");
    write(&exe, "binary-v1");
    write(&contents.join("Info.plist"), "<string>1.0</string>");
    (exe, contents.join("Info.plist"))
}

fn present(target: &Target) -> Identity {
    match target.observe() {
        Observation::Present(id) => id,
        other => panic!("expected present, got {other:?}"),
    }
}

#[test]
fn an_untouched_installation_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (exe, _) = bundle(dir.path());
    let target = Target::new(exe);
    let mut detector = Detector::new(present(&target));
    for _ in 0..5 {
        assert!(!detector.observe(target.observe()));
    }
}

#[cfg(unix)]
#[test]
fn rename_over_is_replaced_after_two_consistent_looks() {
    let dir = tempfile::tempdir().unwrap();
    let (exe, _) = bundle(dir.path());
    let target = Target::new(exe.clone());
    let mut detector = Detector::new(present(&target));
    let new = exe.with_file_name("daemon.new");
    write(&new, "binary-v2-longer");
    std::fs::rename(&new, &exe).unwrap();
    assert!(!detector.observe(target.observe()), "one look is not enough");
    assert!(detector.observe(target.observe()));
}

#[cfg(unix)]
#[test]
fn delete_and_recreate_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (exe, _) = bundle(dir.path());
    let target = Target::new(exe.clone());
    let mut detector = Detector::new(present(&target));
    // Hold the old inode so the new file cannot reuse its number.
    let _old = std::fs::File::open(&exe).unwrap();
    std::fs::remove_file(&exe).unwrap();
    write(&exe, "binary-v1");
    assert!(!detector.observe(target.observe()));
    assert!(detector.observe(target.observe()));
}

#[test]
fn an_in_place_version_bump_of_the_plist_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (exe, plist) = bundle(dir.path());
    let target = Target::new(exe);
    let mut detector = Detector::new(present(&target));
    // Same length, so only the content tells the versions apart.
    write(&plist, "<string>2.0</string>");
    assert!(!detector.observe(target.observe()));
    assert!(detector.observe(target.observe()));
}

#[test]
fn a_brief_gap_then_the_same_file_is_not_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (exe, _) = bundle(dir.path());
    let target = Target::new(exe.clone());
    let mut detector = Detector::new(present(&target));
    let aside = exe.with_file_name("daemon.aside");
    std::fs::rename(&exe, &aside).unwrap();
    assert_eq!(target.observe(), Observation::Missing);
    assert!(!detector.observe(target.observe()));
    std::fs::rename(&aside, &exe).unwrap();
    for _ in 0..3 {
        assert!(!detector.observe(target.observe()));
    }
}

#[test]
fn a_gap_between_two_changed_looks_restarts_the_count() {
    let id = |n: u64| Identity {
        exe: FileId {
            #[cfg(unix)]
            dev: 1,
            #[cfg(unix)]
            ino: n,
            len: n,
            mtime: None,
        },
        bundle_info: None,
    };
    let mut detector = Detector::new(id(1));
    assert!(!detector.observe(Observation::Present(id(2))));
    assert!(!detector.observe(Observation::Missing));
    assert!(!detector.observe(Observation::Present(id(2))));
    assert!(!detector.observe(Observation::Unverifiable));
    assert!(!detector.observe(Observation::Present(id(2))));
    assert!(detector.observe(Observation::Present(id(2))));
}

#[test]
fn a_failed_look_is_not_a_change() {
    let mut detector = {
        let dir = tempfile::tempdir().unwrap();
        let (exe, _) = bundle(dir.path());
        Detector::new(present(&Target::new(exe)))
    };
    for _ in 0..4 {
        assert!(!detector.observe(Observation::Unverifiable));
    }
    let denied = std::io::Error::from(ErrorKind::PermissionDenied);
    assert_eq!(classify(&denied), Observation::Unverifiable);
    assert_eq!(classify(&std::io::Error::from(ErrorKind::NotFound)), Observation::Missing);
}

struct FakeLifecycle {
    requests: AtomicU32,
    answers: Mutex<Vec<SafeStopOutcome>>,
    /// How long a request takes to answer (the real one waits for writes to drain).
    delay: Duration,
    /// Plain (non-restart) requests: the watch must never make one.
    plain_requests: AtomicU32,
    /// Sent `true` when a request begins: another shutdown source firing meanwhile.
    other_shutdown: Option<tokio::sync::watch::Sender<bool>>,
}

impl FakeLifecycle {
    fn new(answers: Vec<SafeStopOutcome>) -> Arc<Self> {
        Arc::new(Self {
            requests: AtomicU32::new(0),
            plain_requests: AtomicU32::new(0),
            answers: Mutex::new(answers),
            delay: Duration::ZERO,
            other_shutdown: None,
        })
    }

    fn slow(
        answers: Vec<SafeStopOutcome>,
        delay: Duration,
        other_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            requests: AtomicU32::new(0),
            plain_requests: AtomicU32::new(0),
            answers: Mutex::new(answers),
            delay,
            other_shutdown,
        })
    }
}

impl DaemonLifecyclePort for FakeLifecycle {
    fn request_shutdown(&self) {}

    fn request_safe_stop(&self, _deadline: Duration) -> BoxFuture<'_, SafeStopOutcome> {
        self.plain_requests.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { SafeStopOutcome::Stopping { already_in_progress: true } })
    }

    fn request_safe_stop_to_restart(&self, _deadline: Duration) -> BoxFuture<'_, SafeStopOutcome> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let mut answers = self.answers.lock().unwrap();
        let answer = if answers.len() > 1 { answers.remove(0) } else { answers[0].clone() };
        if let Some(tx) = &self.other_shutdown {
            tx.send_replace(true);
        }
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            answer
        })
    }
}

fn stopping() -> SafeStopOutcome {
    SafeStopOutcome::Stopping { already_in_progress: false }
}

fn busy() -> SafeStopOutcome {
    SafeStopOutcome::Busy {
        reason: SafeStopBusy::WritesInProgress,
        detail: "x".into(),
        retry_after: Duration::from_secs(5),
    }
}

const CONFIG: ReplacedConfig = ReplacedConfig {
    interval: Duration::from_secs(10),
    stop_deadline: Duration::from_secs(30),
    busy_backoff_cap: Duration::from_secs(100),
};

fn id(n: u64) -> Identity {
    Identity {
        exe: FileId {
            #[cfg(unix)]
            dev: 1,
            #[cfg(unix)]
            ino: n,
            len: n,
            mtime: None,
        },
        bundle_info: None,
    }
}

fn no_shutdown() -> (tokio::sync::watch::Sender<bool>, tokio::sync::watch::Receiver<bool>) {
    tokio::sync::watch::channel(false)
}

fn already_stopping() -> SafeStopOutcome {
    SafeStopOutcome::Stopping { already_in_progress: true }
}

#[tokio::test(start_paused = true)]
async fn a_swap_during_startup_is_a_change_from_the_baseline_taken_before_it() {
    // The baseline (id 1) was recorded before the daemon started; by the first look the
    // executable is already the new one (id 2), and stays so.
    let lifecycle = FakeLifecycle::new(vec![stopping()]);
    let (_tx, rx) = no_shutdown();
    let start = tokio::time::Instant::now();
    watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(2))).await;
    assert_eq!(start.elapsed(), Duration::from_secs(20), "detected at the second look");
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.plain_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn an_unchanged_executable_asks_for_nothing() {
    let lifecycle = FakeLifecycle::new(vec![stopping()]);
    let (_tx, rx) = no_shutdown();
    let watched = watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(1)));
    assert!(tokio::time::timeout(Duration::from_secs(3600), watched).await.is_err());
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 0);
    assert_eq!(lifecycle.plain_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_busy_daemon_keeps_running_and_is_asked_again_later() {
    let lifecycle = FakeLifecycle::new(vec![busy(), busy(), stopping()]);
    let (_tx, rx) = no_shutdown();
    let start = tokio::time::Instant::now();
    watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(2))).await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 3);
    assert_eq!(lifecycle.plain_requests.load(Ordering::SeqCst), 0);
    // Two detecting looks, then waits of 20 s and 40 s between the requests.
    assert_eq!(start.elapsed(), Duration::from_secs(20 + 20 + 40));
}

#[tokio::test(start_paused = true)]
async fn a_retry_after_busy_looks_again_and_gives_up_when_the_change_is_gone() {
    // Looks 1 and 2 find the swap; the first request is busy; at the retry the executable was
    // put back (look 3) or deleted (look 3) and is never asked about again.
    for gone in [Observation::Present(id(1)), Observation::Missing, Observation::Unverifiable] {
        let lifecycle = FakeLifecycle::new(vec![busy(), stopping()]);
        let (_tx, rx) = no_shutdown();
        let looks = AtomicU32::new(0);
        let watched = watch_with(CONFIG, lifecycle.clone(), id(1), rx, || {
            if looks.fetch_add(1, Ordering::SeqCst) < 2 {
                Observation::Present(id(2))
            } else {
                gone.clone()
            }
        });
        assert!(tokio::time::timeout(Duration::from_secs(3600), watched).await.is_err());
        assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 1, "{gone:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_stop_requested_before_the_watch_subscribed_ends_it() {
    let (tx, _first) = no_shutdown();
    tx.send_replace(true);
    // Subscribing marks the current value as seen: only the current value tells.
    let rx = tx.subscribe();
    let lifecycle = FakeLifecycle::new(vec![stopping()]);
    watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(2))).await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn busy_alone_never_asks_for_an_exit_even_mid_request() {
    // A slow request (it waits for writes to drain) that ends busy; the watch is dropped while
    // the request is outstanding and between retries.
    let lifecycle = FakeLifecycle::slow(vec![busy()], Duration::from_secs(25), None);
    let (_tx, rx) = no_shutdown();
    let watched = watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(2)));
    // 20 s: first request outstanding.
    assert!(tokio::time::timeout(Duration::from_secs(30), watched).await.is_err());
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.plain_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn busy_forever_keeps_asking_and_never_exits() {
    let lifecycle = FakeLifecycle::new(vec![busy()]);
    let (_tx, rx) = no_shutdown();
    let watched = watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(2)));
    assert!(tokio::time::timeout(Duration::from_secs(1000), watched).await.is_err());
    assert!(lifecycle.requests.load(Ordering::SeqCst) > 2);
}

#[tokio::test(start_paused = true)]
async fn another_shutdown_during_our_outstanding_request_is_not_a_restart() {
    // `daemon stop` / SIGTERM lands while our request waits; the real safe-stop path then
    // answers that a stop is already in progress.
    let (tx, rx) = no_shutdown();
    let lifecycle =
        FakeLifecycle::slow(vec![already_stopping()], Duration::from_secs(10), Some(tx));
    watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(2))).await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.plain_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn another_shutdown_while_we_wait_ends_the_watch_without_a_restart() {
    let (tx, rx) = no_shutdown();
    let lifecycle = FakeLifecycle::new(vec![stopping()]);
    let watched = watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(2)));
    tokio::pin!(watched);
    assert!(tokio::time::timeout(Duration::from_secs(5), &mut watched).await.is_err());
    tx.send_replace(true);
    watched.await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 0);
    assert_eq!(lifecycle.plain_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_stop_somebody_else_committed_is_not_a_restart() {
    let lifecycle = FakeLifecycle::new(vec![already_stopping()]);
    let (_tx, rx) = no_shutdown();
    watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(2))).await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.plain_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_watch_after_a_stop_somebody_else_committed_keeps_waiting_for_nothing() {
    // The watch returns on `already_in_progress` (their stop), not before it asked: it asked
    // exactly once, and a daemon that is not stopping gets no further requests.
    let lifecycle = FakeLifecycle::new(vec![already_stopping()]);
    let (_tx, rx) = no_shutdown();
    let watched = watch_with(CONFIG, lifecycle.clone(), id(1), rx, || Observation::Present(id(2)));
    tokio::pin!(watched);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), &mut watched).await.is_err(),
        "the watch has not decided anything before its second look"
    );
    watched.await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 1);
}

#[test]
fn a_bundle_whose_version_record_vanished_is_not_replaced() {
    let with_plist = |digest: Option<u64>| {
        let mut i = id(1);
        i.bundle_info = digest;
        i
    };
    let mut detector = Detector::new(with_plist(Some(7)));
    for _ in 0..4 {
        assert!(!detector.observe(Observation::Present(with_plist(None))), "plist deleted only");
    }
    // The executable replaced while the record is gone is still a replacement.
    let mut swapped = Detector::new(with_plist(Some(7)));
    let mut new_exe = id(2);
    new_exe.bundle_info = None;
    assert!(!swapped.observe(Observation::Present(new_exe.clone())));
    assert!(swapped.observe(Observation::Present(new_exe)));
    // A changed record still counts after two looks.
    assert!(!detector.observe(Observation::Present(with_plist(Some(8)))));
    assert!(detector.observe(Observation::Present(with_plist(Some(8)))));
    // A bundle that never had one is judged by the executable alone.
    let mut plain = Detector::new(with_plist(None));
    assert!(!plain.observe(Observation::Present(id(2))));
    assert!(plain.observe(Observation::Present(id(2))));
}

#[test]
fn the_restart_status_is_not_an_existing_exit_code() {
    assert_eq!(RESTART_EXIT_CODE, 75);
    assert_ne!(RESTART_EXIT_CODE, crate::identity::REFUSAL_EXIT_CODE);
    assert!(![0, 1, 2].contains(&RESTART_EXIT_CODE));
}

#[test]
fn without_arming_nothing_is_watched() {
    // No test arms the process-wide state, so the run loop's hook does nothing.
    assert!(!supervised());
}

#[cfg(windows)]
#[test]
fn arming_is_inert_on_windows() {
    arm();
    assert!(!supervised());
}
