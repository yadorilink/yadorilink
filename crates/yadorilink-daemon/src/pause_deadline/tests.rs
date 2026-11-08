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
    assert_eq!(PauseDuration::TwoHours.resume_at(now), Some(now.timestamp() + 2 * 3600));
    assert_eq!(PauseDuration::EightHours.resume_at(now), Some(now.timestamp() + 8 * 3600));
    assert_eq!(PauseDuration::TwentyFourHours.resume_at(now), Some(now.timestamp() + 24 * 3600));
    assert_eq!(PauseDuration::UntilResumed.resume_at(now), None);
}

#[test]
fn every_produced_deadline_is_inside_the_plausible_horizon() {
    let now = at(0, 0);
    for duration in
        [PauseDuration::TwoHours, PauseDuration::EightHours, PauseDuration::TwentyFourHours]
    {
        let deadline = duration.resume_at(now).unwrap();
        assert!(deadline > now.timestamp());
        assert!(deadline <= latest_plausible_deadline(now.timestamp()));
    }
}
