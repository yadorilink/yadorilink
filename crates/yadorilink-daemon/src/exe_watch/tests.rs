#![cfg(test)]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::application::ports::{BoxFuture, SafeStopBusy};

struct FakeLifecycle {
    requests: AtomicU32,
    /// Answers in order; the last one repeats.
    answers: Mutex<Vec<SafeStopOutcome>>,
}

impl FakeLifecycle {
    fn new(answers: Vec<SafeStopOutcome>) -> Arc<Self> {
        Arc::new(Self { requests: AtomicU32::new(0), answers: Mutex::new(answers) })
    }
}

impl DaemonLifecyclePort for FakeLifecycle {
    fn request_shutdown(&self) {}

    fn request_safe_stop(&self, _deadline: Duration) -> BoxFuture<'_, SafeStopOutcome> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let mut answers = self.answers.lock().unwrap();
        let answer = if answers.len() > 1 { answers.remove(0) } else { answers[0].clone() };
        Box::pin(async move { answer })
    }
}

fn present(yes: bool) -> PathProbe {
    if yes {
        PathProbe::Present
    } else {
        PathProbe::Missing
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

const CONFIG: ExeWatchConfig = ExeWatchConfig {
    interval: Duration::from_secs(10),
    misses_needed: 3,
    stop_deadline: Duration::from_secs(30),
    busy_backoff_cap: Duration::from_secs(100),
};

#[tokio::test(start_paused = true)]
async fn a_path_that_stays_is_never_a_reason_to_stop() {
    let lifecycle = FakeLifecycle::new(vec![stopping()]);
    let task =
        tokio::spawn(watch_with("/app".into(), CONFIG, lifecycle.clone(), |_| PathProbe::Present));
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert!(!task.is_finished());
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn an_atomic_replace_that_leaves_the_path_missing_for_an_instant_does_not_stop() {
    // Missing at exactly one look in every four, for hours: each gap is shorter than the
    // required run of consecutive misses.
    let looks = AtomicU32::new(0);
    let lifecycle = FakeLifecycle::new(vec![stopping()]);
    let task = tokio::spawn(watch_with("/app".into(), CONFIG, lifecycle.clone(), move |_| {
        present(!looks.fetch_add(1, Ordering::SeqCst).is_multiple_of(4))
    }));
    tokio::time::sleep(Duration::from_secs(10_000)).await;
    assert!(!task.is_finished());
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn a_path_that_stays_missing_stops_the_daemon_once_through_safe_stop() {
    let gone = Arc::new(AtomicBool::new(false));
    let lifecycle = FakeLifecycle::new(vec![stopping()]);
    let seen = gone.clone();
    let task = tokio::spawn(watch_with("/app".into(), CONFIG, lifecycle.clone(), move |_| {
        present(!seen.load(Ordering::SeqCst))
    }));
    tokio::time::sleep(Duration::from_secs(25)).await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 0);
    gone.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 0, "two misses are not enough");
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 1);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_busy_answer_is_asked_again_at_the_next_look_and_never_forced() {
    let lifecycle = FakeLifecycle::new(vec![busy(), busy(), stopping()]);
    let task =
        tokio::spawn(watch_with("/app".into(), CONFIG, lifecycle.clone(), |_| PathProbe::Missing));
    tokio::time::sleep(Duration::from_secs(500)).await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 3);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_path_that_returns_after_a_miss_resets_the_count() {
    let looks = AtomicU32::new(0);
    let lifecycle = FakeLifecycle::new(vec![stopping()]);
    // Look 1,2 missing, 3 present, 4,5 missing, 6 present, ...: never three in a row.
    let task = tokio::spawn(watch_with("/app".into(), CONFIG, lifecycle.clone(), move |_| {
        present(looks.fetch_add(1, Ordering::SeqCst) % 3 == 2)
    }));
    tokio::time::sleep(Duration::from_secs(5_000)).await;
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 0);
    task.abort();
}

#[test]
fn the_real_probe_sees_a_file_replaced_in_place_as_present() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("yadorilink-daemon");
    std::fs::write(&exe, b"old").unwrap();
    assert!(probe_on_disk(&exe) == PathProbe::Present);
    let staged = dir.path().join("new");
    std::fs::write(&staged, b"new").unwrap();
    std::fs::rename(&staged, &exe).unwrap();
    assert_eq!(probe_on_disk(&exe), PathProbe::Present);
    std::fs::remove_file(&exe).unwrap();
    assert_eq!(probe_on_disk(&exe), PathProbe::Missing);
}

#[tokio::test]
async fn a_deleted_installation_stops_a_real_daemon_through_safe_stop() {
    use yadorilink_local_storage::SegmentBlockStore;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let coordinator = Arc::new(
        crate::replica_coordinator::ReplicaCoordinator::open(dir.path().join("db")).unwrap(),
    );
    let state = crate::daemon_state::DaemonState::new("device-a".into(), coordinator, store);
    let lifecycle: Arc<dyn DaemonLifecyclePort> = Arc::new(
        crate::adapters::runtime::runtime_control::DaemonLifecycleAdapter::new(state.clone()),
    );

    // The "installation": a bundle directory replaced atomically, then deleted.
    let bundle = dir.path().join("YadoriLink.app");
    std::fs::create_dir_all(bundle.join("Contents")).unwrap();
    let config = ExeWatchConfig {
        interval: Duration::from_millis(20),
        misses_needed: 3,
        stop_deadline: Duration::from_secs(5),
        busy_backoff_cap: Duration::from_secs(1),
    };
    let watcher = tokio::spawn(watch(bundle.clone(), config, lifecycle));

    // Replace in place: new bundle moved over the old one's name via a rename of the old aside.
    let aside = dir.path().join("old.app");
    std::fs::rename(&bundle, &aside).unwrap();
    std::fs::create_dir_all(bundle.join("Contents")).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!*state.shutdown_tx.borrow(), "a replaced bundle is not a vanished one");
    assert!(!watcher.is_finished());

    std::fs::remove_dir_all(&bundle).unwrap();
    tokio::time::timeout(Duration::from_secs(10), watcher).await.unwrap().unwrap();
    assert!(*state.shutdown_tx.borrow(), "the same safe stop began the shutdown");
}

struct Recording(Arc<FakeLifecycle>, Arc<Mutex<Vec<Duration>>>, tokio::time::Instant);

impl DaemonLifecyclePort for Recording {
    fn request_shutdown(&self) {}
    fn request_safe_stop(&self, d: Duration) -> BoxFuture<'_, SafeStopOutcome> {
        self.1.lock().unwrap().push(self.2.elapsed());
        self.0.request_safe_stop(d)
    }
}

#[tokio::test(start_paused = true)]
async fn repeated_busy_answers_back_off_to_the_cap() {
    let lifecycle = FakeLifecycle::new(vec![busy()]);
    let start = tokio::time::Instant::now();
    let times = Arc::new(Mutex::new(Vec::new()));
    let port = Arc::new(Recording(lifecycle, times.clone(), start));
    let task = tokio::spawn(watch_with("/app".into(), CONFIG, port, |_| PathProbe::Missing));
    tokio::time::sleep(Duration::from_secs(600)).await;
    task.abort();
    let times = times.lock().unwrap().clone();
    let gaps: Vec<u64> = times.windows(2).map(|w| (w[1] - w[0]).as_secs()).collect();
    // Interval 10 s: gaps double (20, 40, 80) and then stay at the 100 s cap.
    assert_eq!(&gaps[..4], &[20, 40, 80, 100], "{gaps:?}");
    assert!(gaps[3..].iter().all(|g| *g == 100), "{gaps:?}");
}

#[tokio::test(start_paused = true)]
async fn a_path_that_returns_after_busy_answers_resets_the_backoff() {
    let lifecycle = FakeLifecycle::new(vec![busy()]);
    let start = tokio::time::Instant::now();
    let times = Arc::new(Mutex::new(Vec::new()));
    let port = Arc::new(Recording(lifecycle, times.clone(), start));
    // Looks 1-4 find it missing, look 5 finds it back, then it is missing again for good.
    let looks = AtomicU32::new(0);
    let task = tokio::spawn(watch_with("/app".into(), CONFIG, port, move |_| {
        present(looks.fetch_add(1, Ordering::SeqCst) == 4)
    }));
    tokio::time::sleep(Duration::from_secs(150)).await;
    task.abort();
    let times: Vec<u64> = times.lock().unwrap().iter().map(|t| t.as_secs()).collect();
    // Interval 10 s. Looks at 10, 20, 30 -> request at 30 (busy, wait 20); look at 50 ->
    // request (busy, wait 40); the look at 90 finds the path and resets the wait to 10 s.
    // Missing again at 100, 110, 120 -> request at 120 (busy, wait 20) -> request at 140.
    // Without the reset the wait would still be 40 s: requests at 210 and later.
    assert_eq!(&times[..4], &[30, 50, 120, 140], "{times:?}");
}

/// Runs the watcher over a scripted sequence of looks (the last repeats) for `secs` virtual
/// seconds and returns the number of safe-stop requests.
async fn requests_after(script: Vec<PathProbe>, secs: u64) -> u32 {
    let lifecycle = FakeLifecycle::new(vec![stopping()]);
    let looks = AtomicU32::new(0);
    let task = tokio::spawn(watch_with("/app".into(), CONFIG, lifecycle.clone(), move |_| {
        let i = looks.fetch_add(1, Ordering::SeqCst) as usize;
        script[i.min(script.len() - 1)]
    }));
    tokio::time::sleep(Duration::from_secs(secs)).await;
    task.abort();
    lifecycle.requests.load(Ordering::SeqCst)
}

use PathProbe::{Missing as M, Present as P, Unverifiable as U};

#[tokio::test(start_paused = true)]
async fn an_unverifiable_look_between_present_looks_is_not_a_deletion() {
    assert_eq!(requests_after(vec![P, U, P], 3_600).await, 0);
}

#[tokio::test(start_paused = true)]
async fn an_installation_that_stays_unverifiable_is_never_stopped() {
    assert_eq!(requests_after(vec![P, U], 3_600).await, 0);
}

#[tokio::test(start_paused = true)]
async fn an_unverifiable_look_breaks_a_run_of_misses() {
    // Missing, missing, unverifiable, missing, missing, ...: absence was never observed three
    // times in a row.
    assert_eq!(requests_after(vec![M, M, U, M, M, U, M, M, U, P], 3_600).await, 0);
}

#[tokio::test(start_paused = true)]
async fn a_miss_run_after_an_unverifiable_look_still_stops() {
    // Unverifiable does not disable the watcher: three real misses afterwards stop it.
    assert_eq!(requests_after(vec![P, U, M], 100).await, 1);
}

#[tokio::test(start_paused = true)]
async fn the_bundle_reappearing_after_busy_answers_makes_no_further_request() {
    let lifecycle = FakeLifecycle::new(vec![busy()]);
    let looks = AtomicU32::new(0);
    // Looks 1-3 missing (request at 30, busy), 4th look at 50 is Present for good.
    let task = tokio::spawn(watch_with("/app".into(), CONFIG, lifecycle.clone(), move |_| {
        present(looks.fetch_add(1, Ordering::SeqCst) >= 3)
    }));
    tokio::time::sleep(Duration::from_secs(3_600)).await;
    assert!(!task.is_finished());
    assert_eq!(lifecycle.requests.load(Ordering::SeqCst), 1);
    task.abort();
}

#[cfg(unix)]
#[test]
fn the_real_probe_calls_an_unreadable_path_unverifiable_not_missing() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let exe = locked.join("yadorilink-daemon");
    std::fs::write(&exe, b"x").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let probed = probe_on_disk(&exe);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Root ignores directory modes; there the look succeeds and the case does not arise.
    assert!(matches!(probed, PathProbe::Unverifiable | PathProbe::Present), "{probed:?}");
    if probed != PathProbe::Present {
        assert_eq!(probed, PathProbe::Unverifiable);
    }
}

#[test]
fn the_real_probe_calls_a_path_below_a_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    assert_eq!(probe_on_disk(&file.join("below")), PathProbe::Missing);
    assert_eq!(probe_on_disk(&dir.path().join("absent")), PathProbe::Missing);
}
