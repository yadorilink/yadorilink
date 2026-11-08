//! `DriftDetectorJob` -- the slow safety net under the filesystem watcher: every few hours (and once
//! after the machine wakes) each running link's folder is compared with its index by size and
//! modification time, and what differs is sent through the route a live watcher event takes. It
//! finds a missed modify, delete or re-create of an already-indexed file; the 90-second add-only
//! backstop already finds new files. See `LinkRuntimeController::run_drift_detector_sweep` and
//! `yadorilink_local_capture::LocalChangeProcessor::detect_drift`.
//!
//! Scheduling is a plain value type ([`DriftSchedule`], [`WakeDetector`]) over injected times, so it
//! is tested without sleeping.
//!
//! A volume that returns needs no trigger of its own: a link whose disk went away is stopped, and
//! starting it again runs the full startup scan.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;

/// How often the job looks at whether anything is due.
pub(crate) const TICK: Duration = Duration::from_secs(60);
/// The time between two checks of one link (each link's own interval is spread by up to 20%).
pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// How long after the daemon starts a link is first checked: the startup scan has just covered it.
pub(crate) const FIRST_DELAY: Duration = Duration::from_secs(10 * 60);
/// A wall clock that moved this much more than the monotonic clock means the machine slept.
const WAKE_GAP: Duration = Duration::from_secs(120);

/// The interval a setting (`YADORILINK_DRIFT_RESCAN_INTERVAL_SECS`; `0` switches the check off)
/// selects, or the default.
pub(crate) fn interval_from(raw: Option<&str>) -> Option<Duration> {
    match raw.map(|raw| raw.trim().parse::<u64>()) {
        Some(Ok(0)) => None,
        Some(Ok(secs)) => Some(Duration::from_secs(secs)),
        Some(Err(_)) | None => Some(DEFAULT_INTERVAL),
    }
}

/// When each link is next due.
pub(crate) struct DriftSchedule {
    interval: Duration,
    first_delay: Duration,
    started: Instant,
    last_run: HashMap<String, Instant>,
    /// When the machine last woke: a link last checked before then is due.
    woke_at: Option<Instant>,
}

impl DriftSchedule {
    pub(crate) fn new(interval: Duration, first_delay: Duration, started: Instant) -> Self {
        Self { interval, first_delay, started, last_run: HashMap::new(), woke_at: None }
    }

    /// The interval of one link: the base interval spread by a fixed factor between 0.8 and 1.2
    /// derived from its name, so links do not all come due at once.
    fn interval_of(&self, key: &str) -> Duration {
        self.interval.mul_f64(0.8 + 0.4 * f64::from(self.spread_of(key) % 1000) / 999.0)
    }

    fn spread_of(&self, key: &str) -> u32 {
        key.bytes().fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)))
    }

    pub(crate) fn due(&self, key: &str, now: Instant) -> bool {
        match self.last_run.get(key) {
            None => {
                // Spread by up to 10 minutes so links do not all start at once.
                let stagger = Duration::from_secs(u64::from(self.spread_of(key) % 600));
                self.woke_at.is_some()
                    || now.duration_since(self.started) >= self.first_delay + stagger
            }
            Some(last) => {
                self.woke_at.is_some_and(|woke| *last < woke)
                    || now.duration_since(*last) >= self.interval_of(key)
            }
        }
    }

    /// Records that `key` was checked at `now`.
    pub(crate) fn ran(&mut self, key: &str, now: Instant) {
        self.last_run.insert(key.to_owned(), now);
    }

    /// The machine woke at `now`: every link not checked since is due, one tick after another
    /// (each check records itself, so a link is served once per wake and never starves the rest).
    pub(crate) fn woke(&mut self, now: Instant) {
        self.woke_at = Some(now);
    }
}

/// Notices that the machine slept: the wall clock keeps going while the monotonic one does not.
pub(crate) struct WakeDetector {
    last_wall: SystemTime,
    last_mono: Instant,
}

impl WakeDetector {
    pub(crate) fn new(wall: SystemTime, mono: Instant) -> Self {
        Self { last_wall: wall, last_mono: mono }
    }

    pub(crate) fn observe(&mut self, wall: SystemTime, mono: Instant) -> bool {
        let wall_elapsed = wall.duration_since(self.last_wall).unwrap_or_default();
        let mono_elapsed = mono.duration_since(self.last_mono);
        self.last_wall = wall;
        self.last_mono = mono;
        wall_elapsed > mono_elapsed + WAKE_GAP
    }
}

pub(crate) struct DriftDetectorJob {
    controller: Arc<LinkRuntimeController>,
    schedule: Arc<Mutex<DriftSchedule>>,
    wake: Mutex<WakeDetector>,
}

impl DriftDetectorJob {
    /// `None` when `interval` is `None` (the check is switched off).
    pub(crate) fn new(
        controller: Arc<LinkRuntimeController>,
        interval: Option<Duration>,
    ) -> Option<Self> {
        let interval = interval?;
        let now = Instant::now();
        Some(Self {
            controller,
            schedule: Arc::new(Mutex::new(DriftSchedule::new(interval, FIRST_DELAY, now))),
            wake: Mutex::new(WakeDetector::new(SystemTime::now(), now)),
        })
    }

    pub(crate) async fn run_once(&self) {
        let woke = self
            .wake
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe(SystemTime::now(), Instant::now());
        if woke {
            tracing::info!("the machine woke from sleep: every folder gets a drift check");
            self.schedule.lock().unwrap_or_else(|p| p.into_inner()).woke(Instant::now());
        }
        // The passes run on their own tasks, beyond this tick.
        drop(self.controller.run_drift_detector_sweep(&self.schedule).await);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_is_first_checked_after_the_startup_delay_and_then_every_interval() {
        let t0 = Instant::now();
        let mut schedule = DriftSchedule::new(Duration::from_secs(3600), FIRST_DELAY, t0);
        assert!(!schedule.due("/a", t0 + Duration::from_secs(60)));
        assert!(!schedule.due("/a", t0 + FIRST_DELAY - Duration::from_secs(1)));
        assert!(schedule.due("/a", t0 + FIRST_DELAY + Duration::from_secs(600)));
        schedule.ran("/a", t0 + FIRST_DELAY);
        // Within 0.8 x the interval of the run: not due; after 1.2 x: due.
        assert!(!schedule.due("/a", t0 + FIRST_DELAY + Duration::from_secs(2800)));
        assert!(schedule.due("/a", t0 + FIRST_DELAY + Duration::from_secs(4400)));
    }

    #[test]
    fn links_are_spread_and_never_outside_twenty_percent() {
        let schedule = DriftSchedule::new(Duration::from_secs(1000), FIRST_DELAY, Instant::now());
        let mut distinct = std::collections::HashSet::new();
        for i in 0..50 {
            let interval = schedule.interval_of(&format!("/folder-{i}"));
            assert!(interval >= Duration::from_secs(800) && interval <= Duration::from_secs(1200));
            distinct.insert(interval);
        }
        assert!(distinct.len() > 10, "links come due at different times");
    }

    #[test]
    fn a_wake_makes_every_link_due_once_and_never_starves_the_ones_after_the_first() {
        let t0 = Instant::now();
        let mut schedule = DriftSchedule::new(Duration::from_secs(3600), FIRST_DELAY, t0);
        schedule.ran("/a", t0 + Duration::from_secs(5));
        assert!(!schedule.due("/a", t0 + Duration::from_secs(60)));
        schedule.woke(t0 + Duration::from_secs(50));
        assert!(schedule.due("/a", t0 + Duration::from_secs(60)));
        assert!(schedule.due("/never-run", t0 + Duration::from_secs(60)));
        // /a is served; it does not come due again for the same wake, so a limited number of
        // passes per tick reaches the links behind it.
        schedule.ran("/a", t0 + Duration::from_secs(61));
        assert!(!schedule.due("/a", t0 + Duration::from_secs(120)));
        assert!(schedule.due("/never-run", t0 + Duration::from_secs(120)));
        schedule.ran("/never-run", t0 + Duration::from_secs(121));
        assert!(!schedule.due("/never-run", t0 + Duration::from_secs(180)));
        // A later wake demands another round.
        schedule.woke(t0 + Duration::from_secs(200));
        assert!(schedule.due("/a", t0 + Duration::from_secs(201)));
    }

    #[test]
    fn a_wall_clock_that_ran_ahead_of_the_monotonic_one_is_a_wake() {
        let wall0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mono0 = Instant::now();
        let mut detector = WakeDetector::new(wall0, mono0);
        // A normal minute.
        assert!(!detector.observe(wall0 + Duration::from_secs(60), mono0 + Duration::from_secs(60)));
        // The machine slept for an hour: the wall clock moved, the monotonic one did not.
        assert!(detector
            .observe(wall0 + Duration::from_secs(60 + 3600), mono0 + Duration::from_secs(120)));
        // The clock being set back is not a wake.
        assert!(!detector.observe(wall0, mono0 + Duration::from_secs(180)));
    }

    #[test]
    fn the_setting_can_switch_the_check_off_or_set_its_interval() {
        assert_eq!(interval_from(None), Some(DEFAULT_INTERVAL));
        assert_eq!(interval_from(Some("0")), None);
        assert_eq!(interval_from(Some(" 900 ")), Some(Duration::from_secs(900)));
        assert_eq!(interval_from(Some("soon")), Some(DEFAULT_INTERVAL));
    }
}
