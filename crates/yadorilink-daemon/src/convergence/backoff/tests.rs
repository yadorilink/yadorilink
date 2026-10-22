#![cfg(test)]

use super::*;

fn assert_within_jitter(actual: Duration, base_secs: f64) {
    let min = base_secs * (1.0 - BACKOFF_JITTER_FRACTION);
    let max = base_secs * (1.0 + BACKOFF_JITTER_FRACTION);
    let actual_secs = actual.as_secs_f64();
    assert!(
        actual_secs >= min && actual_secs <= max,
        "expected {actual_secs}s within [{min}, {max}]"
    );
}

#[test]
fn schedule_matches_design_doc_shape() {
    assert_within_jitter(next_backoff(0), 1.0);
    assert_within_jitter(next_backoff(1), 1.0);
    assert_within_jitter(next_backoff(2), 2.0);
    assert_within_jitter(next_backoff(3), 4.0);
    assert_within_jitter(next_backoff(4), 8.0);
    assert_within_jitter(next_backoff(5), 16.0);
    assert_within_jitter(next_backoff(6), 30.0);
}

#[test]
fn schedule_caps_at_30s_for_large_attempt_counts() {
    assert_within_jitter(next_backoff(7), 30.0);
    assert_within_jitter(next_backoff(1000), 30.0);
}

#[test]
fn jitter_never_produces_a_negative_or_zero_duration() {
    for attempt in 0..10 {
        for _ in 0..50 {
            assert!(next_backoff(attempt) > Duration::ZERO);
        }
    }
}
