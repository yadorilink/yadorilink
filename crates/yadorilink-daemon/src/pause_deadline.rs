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

/// Longer than any deadline [`PauseDuration::resume_at`] produces (the next
/// local midnight is at most a day and an hour away across a clock change).
pub(crate) const MAX_TIMED_PAUSE_SECS: i64 = 26 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PauseDuration {
    /// No deadline: paused until the user resumes.
    UntilResumed,
    ThirtyMinutes,
    OneHour,
    /// Until the next local midnight.
    UntilTomorrow,
}

impl PauseDuration {
    /// The Unix time the pause ends, or `None` for [`Self::UntilResumed`].
    /// `now` carries the zone whose midnight "tomorrow" means.
    pub(crate) fn resume_at<Tz: TimeZone>(self, now: DateTime<Tz>) -> Option<i64> {
        let ends = match self {
            Self::UntilResumed => return None,
            Self::ThirtyMinutes => now + Duration::minutes(30),
            Self::OneHour => now + Duration::hours(1),
            Self::UntilTomorrow => next_midnight(&now),
        };
        Some(ends.timestamp())
    }
}

fn next_midnight<Tz: TimeZone>(now: &DateTime<Tz>) -> DateTime<Tz> {
    let midnight = now
        .date_naive()
        .succ_opt()
        .and_then(|day| day.and_hms_opt(0, 0, 0))
        .and_then(|local| now.timezone().from_local_datetime(&local).earliest());
    // A date past the calendar's end or a midnight skipped by a clock
    // change: a day from now is close enough and never earlier.
    midnight.unwrap_or_else(|| now.clone() + Duration::hours(24))
}

/// The newest deadline that can still be genuine at `now_unix`.
pub(crate) fn latest_plausible_deadline(now_unix: i64) -> i64 {
    now_unix.saturating_add(MAX_TIMED_PAUSE_SECS)
}

#[cfg(test)]
mod tests;
