#![cfg(test)]

use super::*;

/// The ring buffer is bounded — recording past `MAX_RECENT_ERRORS`
/// drops the oldest, not the newest.
#[test]
fn ring_buffer_is_bounded_and_drops_oldest_first() {
    let log = RecentErrorLog::new();
    for i in 0..(MAX_RECENT_ERRORS + 10) {
        log.record("disk_pressure", format!("sweep-{i}"));
    }
    let recent = log.recent();
    assert_eq!(recent.len(), MAX_RECENT_ERRORS);
    // Newest first.
    assert_eq!(recent[0].coarse_context, format!("sweep-{}", MAX_RECENT_ERRORS + 9));
}

/// The recent-error buffer is redacted — every field is a stable
/// category, a timestamp, or whatever fixed context string the
/// caller passed; this test exists as a structural guard (an
/// exhaustive match with named bindings) so a future field addition
/// can't quietly smuggle in a raw path/key/token/IP without updating
/// this note.
#[test]
fn record_shape_never_carries_more_than_category_timestamp_and_context() {
    let record = RecentErrorRecord {
        category: "disk_pressure",
        timestamp_unix: 0,
        coarse_context: "hydration".to_string(),
    };
    let RecentErrorRecord { category: _, timestamp_unix: _, coarse_context: _ } = record;
}

/// Per-category counts are monotonic even once the bounded ring
/// buffer starts evicting old entries.
#[test]
fn category_counts_stay_monotonic_across_ring_buffer_eviction() {
    let log = RecentErrorLog::new();
    for i in 0..(MAX_RECENT_ERRORS + 5) {
        log.record("peer_unreachable", format!("attempt-{i}"));
    }
    let counts = log.category_counts();
    let (_, count) = counts.iter().find(|(c, _)| *c == "peer_unreachable").unwrap();
    assert_eq!(*count, (MAX_RECENT_ERRORS + 5) as u64);
    // The bounded ring buffer itself did evict older entries.
    assert_eq!(log.recent().len(), MAX_RECENT_ERRORS);
}

#[test]
fn different_categories_are_counted_independently() {
    let log = RecentErrorLog::new();
    log.record("disk_pressure", "sweep");
    log.record("disk_pressure", "sweep");
    log.record("peer_unreachable", "hydration");

    let counts: HashMap<_, _> = log.category_counts().into_iter().collect();
    assert_eq!(counts.get("disk_pressure"), Some(&2));
    assert_eq!(counts.get("peer_unreachable"), Some(&1));
}
