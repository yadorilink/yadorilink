//! Rate limit for repeating WARN events (e.g. swarm_discovery's
//! "error sending mDNS: No route to host" once per send attempt).
//!
//! The first occurrence of each distinct warning (target + all fields) is
//! logged; repeats within [`WARN_REPEAT_INTERVAL`] are dropped and counted,
//! and the next one past the interval is logged after a one-line
//! "suppressed N" summary. Non-WARN events pass untouched.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Filter};

pub const WARN_REPEAT_INTERVAL: Duration = Duration::from_secs(60);
const SUMMARY_TARGET: &str = "yadorilink_daemon::log_throttle";
const MAX_TRACKED: usize = 1024;

#[derive(Default)]
pub struct WarnThrottle {
    seen: Mutex<HashMap<String, (Instant, u64)>>,
}

struct KeyVisitor(String);

impl Visit for KeyVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={:?};", field.name(), value);
    }
}

impl WarnThrottle {
    /// `Some(suppressed)` when this event should be logged (`suppressed` repeats were
    /// dropped since the last one); `None` when it should be dropped.
    fn admit(&self, key: String, now: Instant) -> Option<u64> {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if seen.len() >= MAX_TRACKED && !seen.contains_key(&key) {
            seen.retain(|_, (last, _)| now.duration_since(*last) < WARN_REPEAT_INTERVAL);
        }
        match seen.get_mut(&key) {
            None => {
                seen.insert(key, (now, 0));
                Some(0)
            }
            Some((last, suppressed)) if now.duration_since(*last) >= WARN_REPEAT_INTERVAL => {
                let n = *suppressed;
                *last = now;
                *suppressed = 0;
                Some(n)
            }
            Some((_, suppressed)) => {
                *suppressed += 1;
                None
            }
        }
    }
}

impl<S: Subscriber> Filter<S> for WarnThrottle {
    fn enabled(&self, _: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        true
    }

    fn event_enabled(&self, event: &Event<'_>, _: &Context<'_, S>) -> bool {
        let meta = event.metadata();
        if *meta.level() != Level::WARN || meta.target() == SUMMARY_TARGET {
            return true;
        }
        let mut key = KeyVisitor(meta.target().to_string());
        key.0.push(';');
        event.record(&mut key);
        match self.admit(key.0, Instant::now()) {
            None => false,
            Some(0) => true,
            Some(n) => {
                // The lock is released; this re-enters the filter for a different target.
                tracing::warn!(
                    target: "yadorilink_daemon::log_throttle",
                    suppressed = n,
                    "the next warning from {} repeated {n} more time(s) since it was last logged",
                    meta.target()
                );
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_logged_repeats_suppressed_then_summarised_after_interval() {
        let t = WarnThrottle::default();
        let t0 = Instant::now();
        assert_eq!(t.admit("a".into(), t0), Some(0));
        for _ in 0..100 {
            assert_eq!(t.admit("a".into(), t0 + Duration::from_secs(1)), None);
        }
        assert_eq!(t.admit("b".into(), t0), Some(0));
        assert_eq!(t.admit("a".into(), t0 + WARN_REPEAT_INTERVAL), Some(100));
        assert_eq!(t.admit("a".into(), t0 + WARN_REPEAT_INTERVAL), None);
    }
}
