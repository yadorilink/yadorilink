#![cfg(test)]

use super::*;
use chrono::{FixedOffset, TimeZone};

fn at(hour: u32, minute: u32) -> DateTime<FixedOffset> {
    FixedOffset::east_opt(9 * 3600)
        .unwrap()
        .with_ymd_and_hms(2026, 10, 15, hour, minute, 0)
        .unwrap()
}

#[test]
fn fixed_lengths_count_from_now_and_until_resumed_has_no_deadline() {
    let now = at(10, 15);
    assert_eq!(PauseDuration::ThirtyMinutes.resume_at(now), Some(now.timestamp() + 30 * 60));
    assert_eq!(PauseDuration::OneHour.resume_at(now), Some(now.timestamp() + 3600));
    assert_eq!(PauseDuration::UntilResumed.resume_at(now), None);
}

#[test]
fn until_tomorrow_is_the_next_local_midnight() {
    let midnight = at(0, 0) + Duration::days(1);
    for now in [at(0, 0), at(10, 15), at(23, 59)] {
        assert_eq!(
            PauseDuration::UntilTomorrow.resume_at(now),
            Some(midnight.timestamp()),
            "{now}"
        );
    }
    // Local, not UTC: 23:30 in UTC+9 is 14:30 UTC, and midnight is 30 minutes away.
    assert_eq!(
        PauseDuration::UntilTomorrow.resume_at(at(23, 30)),
        Some(at(23, 30).timestamp() + 30 * 60)
    );
}

#[test]
fn every_produced_deadline_is_inside_the_plausible_horizon() {
    let now = at(0, 0);
    for duration in
        [PauseDuration::ThirtyMinutes, PauseDuration::OneHour, PauseDuration::UntilTomorrow]
    {
        let deadline = duration.resume_at(now).unwrap();
        assert!(deadline > now.timestamp());
        assert!(deadline <= latest_plausible_deadline(now.timestamp()));
    }
}

/// Just before midnight "until tomorrow" is the shortest option, so no caller or test may
/// assume it is the longest.
#[test]
fn until_tomorrow_can_be_sooner_than_a_fixed_length() {
    let now = at(23, 45);
    assert!(
        PauseDuration::UntilTomorrow.resume_at(now).unwrap()
            < PauseDuration::ThirtyMinutes.resume_at(now).unwrap()
    );
}
