#![cfg(test)]

use super::*;

#[test]
fn increments_persist_across_a_new_instance() {
    let dir = tempfile::tempdir().unwrap();
    let counters = ReportingCounters::open(dir.path());
    counters.increment_command_category("link");
    counters.increment_command_category("link");
    counters.increment_command_category("status");

    let reopened = ReportingCounters::open(dir.path());
    let payload = reopened.to_usage_payload();
    assert_eq!(payload.command_category_counts.get("link"), Some(&2));
    assert_eq!(payload.command_category_counts.get("status"), Some(&1));
}

#[test]
fn buckets_transfer_sizes_and_latency_coarsely() {
    let dir = tempfile::tempdir().unwrap();
    let counters = ReportingCounters::open(dir.path());
    counters.record_transfer_bytes(500);
    counters.record_transfer_bytes(5 * 1024 * 1024);
    counters.record_latency_millis(50);
    counters.record_latency_millis(5000);

    let payload = counters.to_usage_payload();
    assert_eq!(payload.transfer_size_bucket_counts.get("<1MB"), Some(&1));
    assert_eq!(payload.transfer_size_bucket_counts.get("1-10MB"), Some(&1));
    assert_eq!(payload.latency_bucket_counts.get("<100ms"), Some(&1));
    assert_eq!(payload.latency_bucket_counts.get("2-10s"), Some(&1));
}

#[test]
fn uptime_bucket_starts_below_one_hour() {
    let dir = tempfile::tempdir().unwrap();
    let counters = ReportingCounters::open(dir.path());
    assert_eq!(counters.current_uptime_bucket(), "<1h");
}

#[test]
fn reset_clears_every_counter() {
    let dir = tempfile::tempdir().unwrap();
    let counters = ReportingCounters::open(dir.path());
    counters.increment_command_category("link");
    counters.record_error_category("sync_conflict");
    counters.reset();

    let payload = counters.to_usage_payload();
    assert!(payload.command_category_counts.is_empty());
    assert!(payload.error_category_counts.is_empty());
}

#[test]
fn linked_folder_snapshot_replaces_rather_than_accumulates() {
    let dir = tempfile::tempdir().unwrap();
    let counters = ReportingCounters::open(dir.path());
    counters.record_linked_folder_counts(3, BTreeMap::from([("eager".to_string(), 2)]));
    counters.record_linked_folder_counts(1, BTreeMap::from([("on-demand".to_string(), 1)]));

    let payload = counters.to_usage_payload();
    assert_eq!(payload.linked_folder_count, 1);
    assert_eq!(payload.linked_folder_policy_counts.get("on-demand"), Some(&1));
    assert_eq!(payload.linked_folder_policy_counts.get("eager"), None);
}
