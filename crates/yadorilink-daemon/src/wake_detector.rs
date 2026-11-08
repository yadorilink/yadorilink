//! Notices that the machine slept, and says the network may have changed.
//!
//! Waking from sleep (or a Wi-Fi roam) often leaves every local address as it was, so the
//! substrate's address watch reports nothing, while the connections made before it sit on
//! paths that no longer carry traffic and that QUIC does not give up on for minutes. The one
//! thing a sleep always leaves is a hole in the wall clock: a timer that should have fired
//! every [`TICK`] fires much later, and the time that passed is far more than the tick.
//! Monotonic clocks may or may not count suspended time depending on the platform, so the
//! hole is read off the wall clock. A forward clock step looks the same and is treated the
//! same; recycling connections is cheap and the keepers redial at once.
//!
//! This is the only place the tick and the threshold live. What a resume does is not decided
//! here: it is reported to the substrate as the network having come back, which is the event
//! every recovery path already reacts to.

use std::time::{Duration, SystemTime};

/// How often the detector looks at the wall clock. Slow on purpose: an idle daemon's wakeups
/// are budgeted, and a resume is acted on within one tick of it.
pub(crate) const TICK: Duration = Duration::from_secs(5);

/// How much longer than [`TICK`] the wall clock may have advanced between two ticks before it
/// counts as a sleep. Generous, so a busy runtime that ran a tick late is never read as one.
pub(crate) const RESUME_GAP: Duration = Duration::from_secs(10);

/// The wall clock, replaceable in tests.
pub(crate) trait WallClock: Send + 'static {
    fn now(&self) -> SystemTime;
}

/// The system clock.
pub(crate) struct SystemClock;

impl WallClock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Whether `elapsed` of wall-clock time since the last tick means the machine was asleep.
fn is_resume(elapsed: Duration) -> bool {
    elapsed > TICK + RESUME_GAP
}

/// Calls `on_resume` each time a tick finds the wall clock further ahead than a tick explains.
/// Runs until its task is dropped.
pub(crate) async fn run(clock: impl WallClock, on_resume: impl Fn()) {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last = clock.now();
    loop {
        ticker.tick().await;
        let now = clock.now();
        // A clock that went backwards is not a sleep.
        let elapsed = now.duration_since(last).unwrap_or_default();
        last = now;
        if is_resume(elapsed) {
            tracing::info!(
                slept_secs = elapsed.as_secs(),
                "the machine resumed; the network may have changed"
            );
            on_resume();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use super::*;

    /// A wall clock that follows tokio's paused time plus a settable extra offset: what a sleep
    /// does (the wall clock moves, the runtime's timers do not).
    #[derive(Clone)]
    struct FakeClock {
        start: SystemTime,
        origin: tokio::time::Instant,
        slept_secs: Arc<AtomicU64>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                start: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
                origin: tokio::time::Instant::now(),
                slept_secs: Arc::default(),
            }
        }

        fn sleep_for(&self, secs: u64) {
            self.slept_secs.fetch_add(secs, Ordering::SeqCst);
        }
    }

    impl WallClock for FakeClock {
        fn now(&self) -> SystemTime {
            self.start
                + self.origin.elapsed()
                + Duration::from_secs(self.slept_secs.load(Ordering::SeqCst))
        }
    }

    /// Starts the detector and lets it take its first reading before the test moves the clock.
    async fn counting(clock: FakeClock) -> (Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
        let resumes = Arc::new(AtomicU64::new(0));
        let counter = resumes.clone();
        let task = tokio::spawn(run(clock, move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        tokio::task::yield_now().await;
        (resumes, task)
    }

    #[tokio::test(start_paused = true)]
    async fn an_undisturbed_clock_reports_nothing() {
        let (resumes, task) = counting(FakeClock::new()).await;
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert_eq!(resumes.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_sleep_is_reported_once_at_the_next_tick() {
        let clock = FakeClock::new();
        let (resumes, task) = counting(clock.clone()).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(resumes.load(Ordering::SeqCst), 0);

        clock.sleep_for(3 * 3600);
        tokio::time::sleep(TICK + Duration::from_secs(1)).await;
        assert_eq!(resumes.load(Ordering::SeqCst), 1, "reported within a tick of waking");

        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(resumes.load(Ordering::SeqCst), 1, "and only once");
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_gap_inside_the_tolerance_is_not_a_sleep() {
        let clock = FakeClock::new();
        let (resumes, task) = counting(clock.clone()).await;
        clock.sleep_for(RESUME_GAP.as_secs());
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(resumes.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_sleep_is_reported_again() {
        let clock = FakeClock::new();
        let (resumes, task) = counting(clock.clone()).await;
        for expected in 1..=2 {
            clock.sleep_for(600);
            tokio::time::sleep(TICK * 3).await;
            assert_eq!(resumes.load(Ordering::SeqCst), expected);
        }
        task.abort();
    }
}
