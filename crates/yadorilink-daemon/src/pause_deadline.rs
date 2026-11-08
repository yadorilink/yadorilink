//! How long a folder pause lasts. A pause has at most one optional resume
//! deadline: a fixed length, the next local midnight, or none (until the
//! user resumes). There is no schedule beyond that.
//!
//! The deadline is persisted with the pause itself (`LinkRepository::
//! pause_until`) as a wall-clock Unix timestamp, because it has to survive
//! a restart and a monotonic clock does not. The consequences are defined
//! here rather than left to chance:
//!
//! - A deadline at or before the current time resumes the link on the next
//!   tick, and on startup (the first tick runs at once). A pause that ended
//!   while the daemon was down therefore ends as soon as it is back.
//! - A clock that jumps forward ends the pause early, by the size of the
//!   jump.
//! - A clock that jumps backward cannot keep a link paused for long: no
//!   deadline this module hands out is further than [`MAX_TIMED_PAUSE_SECS`]
//!   away, so a stored deadline beyond that horizon is treated as already
//!   over. A smaller backward jump delays the resume by at most that much.

use chrono::{DateTime, Duration, TimeZone};

/// Longer than any deadline [`PauseDuration::resume_at`] produces (the longest
/// pause is 24 hours; an hour of slack).
pub(crate) const MAX_TIMED_PAUSE_SECS: i64 = 25 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PauseDuration {
    /// No deadline: paused until the user resumes.
    UntilResumed,
    TwoHours,
    EightHours,
    TwentyFourHours,
}

impl PauseDuration {
    /// The Unix time the pause ends, or `None` for [`Self::UntilResumed`].
    pub(crate) fn resume_at<Tz: TimeZone>(self, now: DateTime<Tz>) -> Option<i64> {
        let ends = match self {
            Self::UntilResumed => return None,
            Self::TwoHours => now + Duration::hours(2),
            Self::EightHours => now + Duration::hours(8),
            Self::TwentyFourHours => now + Duration::hours(24),
        };
        Some(ends.timestamp())
    }
}

/// The newest deadline that can still be genuine at `now_unix`.
pub(crate) fn latest_plausible_deadline(now_unix: i64) -> i64 {
    now_unix.saturating_add(MAX_TIMED_PAUSE_SECS)
}

#[cfg(test)]
mod tests;
