#![cfg(test)]

use super::*;

fn entry(id: &str, size_bytes: usize) -> QueuedReportMetadata {
    QueuedReportMetadata {
        report_id: id.to_string(),
        report_type: ReportType::Usage,
        queued_at: "2026-01-01T00:00:00Z".into(),
        size_bytes,
        submit_attempts: 0,
    }
}

#[test]
fn evicts_entries_older_than_max_age() {
    let policy = RetentionPolicy { max_age_seconds: 100, ..Default::default() };
    let queue = vec![entry("old", 10), entry("fresh", 10)];
    let ages = |id: &str| if id == "old" { 500 } else { 5 };
    let evicted = policy.entries_to_evict(&queue, 1000, |e| 1000 - ages(&e.report_id));
    assert_eq!(evicted, vec!["old".to_string()]);
}

#[test]
fn evicts_entries_over_the_max_entry_byte_cap() {
    let policy = RetentionPolicy { max_entry_bytes: 1000, ..Default::default() };
    let queue = vec![entry("huge", 5000), entry("normal", 100)];
    let evicted = policy.entries_to_evict(&queue, 0, |_| 0);
    assert_eq!(evicted, vec!["huge".to_string()]);
}

#[test]
fn evicts_oldest_excess_entries_once_over_max_count() {
    let policy =
        RetentionPolicy { max_entries: 2, max_age_seconds: u64::MAX, ..Default::default() };
    let queue = vec![entry("a", 10), entry("b", 10), entry("c", 10)];
    // "a" queued first (oldest), "c" queued last (newest).
    let queued_order = |id: &str| match id {
        "a" => 0,
        "b" => 1,
        "c" => 2,
        _ => unreachable!(),
    };
    let evicted = policy.entries_to_evict(&queue, 0, |e| queued_order(&e.report_id));
    assert_eq!(evicted, vec!["a".to_string()]);
}

#[test]
fn empty_queue_evicts_nothing() {
    let policy = RetentionPolicy::default();
    assert!(policy.entries_to_evict(&[], 0, |_| 0).is_empty());
}
