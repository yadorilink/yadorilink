#![cfg(test)]

use super::*;
use yadorilink_reporting::schema::{
    OsFamily, ReportPayload, ReportType, UsagePayload, SCHEMA_VERSION,
};

fn sample_envelope() -> ReportEnvelope {
    ReportEnvelope {
        schema_version: SCHEMA_VERSION,
        report_type: ReportType::Usage,
        generated_at: "2026-01-01T00:00:00Z".into(),
        yadorilink_version: "0.1.0".into(),
        os_family: OsFamily::Linux,
        os_version_bucket: "24.04".into(),
        arch: "x86_64".into(),
        install_channel: None,
        anonymous_reporter_id: None,
        payload: ReportPayload::Usage(UsagePayload::default()),
    }
}

/// queue deletion (via the public `QueueStore` facade, not
/// just `EntryStore` directly).
#[test]
fn enqueue_list_delete_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let queue = QueueStore::new(dir.path());
    let meta = queue.enqueue(sample_envelope()).unwrap();
    assert_eq!(queue.list().unwrap().len(), 1);
    assert!(queue.delete(&meta.report_id).unwrap());
    assert!(queue.list().unwrap().is_empty());
}

#[test]
fn queue_lives_outside_any_configured_directory_other_than_reporting() {
    let dir = tempfile::tempdir().unwrap();
    let queue = QueueStore::new(dir.path());
    queue.enqueue(sample_envelope()).unwrap();
    assert!(dir.path().join("queue").is_dir());
    // Nothing here ever touches a "linked" or "sync" subpath.
    assert!(!dir.path().join("linked").exists());
}

#[test]
fn flush_clears_the_whole_queue() {
    let dir = tempfile::tempdir().unwrap();
    let queue = QueueStore::new(dir.path());
    queue.enqueue(sample_envelope()).unwrap();
    queue.enqueue(sample_envelope()).unwrap();
    assert_eq!(queue.flush().unwrap(), 2);
    assert!(queue.list().unwrap().is_empty());
}
