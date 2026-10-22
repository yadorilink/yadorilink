#![cfg(test)]

use super::*;
use crate::schema::{OsFamily, ReportPayload, ReportType, UsagePayload, SCHEMA_VERSION};

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

#[test]
fn insert_then_list_then_show_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let store = EntryStore::new(dir.path(), RetentionPolicy::default());
    let meta = store.insert(sample_envelope()).unwrap();

    let listed = store.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].report_id, meta.report_id);

    let shown = store.show(&meta.report_id).unwrap().unwrap();
    assert_eq!(shown, sample_envelope());
}

#[test]
fn show_of_unknown_id_returns_none_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = EntryStore::new(dir.path(), RetentionPolicy::default());
    assert_eq!(store.show("does-not-exist").unwrap(), None);
}

/// `id` reaches `show`/`delete` directly from unvalidated IPC/CLI
/// input -- a path-traversal or absolute-path id must not let either
/// operation reach a file outside the store directory. Reproduces the
/// exact shape a real attacker string would take (`../../../../tmp/
/// victim`), against a real file placed outside `dir` on disk, so a
/// regression that reopens the escape would actually delete/read that
/// file rather than merely fail an assertion on `id`'s shape.
#[test]
fn an_id_that_would_escape_the_store_directory_is_rejected_not_traversed() {
    let root = tempfile::tempdir().unwrap();
    let store_dir = root.path().join("queue");
    std::fs::create_dir_all(&store_dir).unwrap();
    let store = EntryStore::new(&store_dir, RetentionPolicy::default());

    let victim = root.path().join("victim.json");
    std::fs::write(&victim, "not a report, must survive").unwrap();

    for malicious_id in
        ["../victim", "../../victim", "some/../../victim", "/etc/passwd", ".", "..", "sub/dir"]
    {
        assert_eq!(
            store.show(malicious_id).unwrap(),
            None,
            "show({malicious_id:?}) must not read anything, real or synthetic"
        );
        assert!(
            !store.delete(malicious_id).unwrap(),
            "delete({malicious_id:?}) must report nothing removed"
        );
    }

    assert!(victim.exists(), "an id outside the store must never reach a real file on disk");
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "not a report, must survive",
        "the file outside the store must be untouched"
    );
}

/// queue deletion.
#[test]
fn delete_removes_the_entry_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store = EntryStore::new(dir.path(), RetentionPolicy::default());
    let meta = store.insert(sample_envelope()).unwrap();

    assert!(store.delete(&meta.report_id).unwrap());
    assert!(store.show(&meta.report_id).unwrap().is_none());
    // Deleting again is a no-op, not an error.
    assert!(!store.delete(&meta.report_id).unwrap());
}

#[test]
fn flush_removes_every_entry() {
    let dir = tempfile::tempdir().unwrap();
    let store = EntryStore::new(dir.path(), RetentionPolicy::default());
    store.insert(sample_envelope()).unwrap();
    store.insert(sample_envelope()).unwrap();
    assert_eq!(store.list().unwrap().len(), 2);

    let removed = store.flush().unwrap();
    assert_eq!(removed, 2);
    assert!(store.list().unwrap().is_empty());
}

/// retention cap deletion — count cap, exercised through
/// the real `EntryStore`/filesystem rather than only the pure
/// `RetentionPolicy` unit tests in `yadorilink-reporting`.
#[test]
fn apply_retention_evicts_down_to_max_entries() {
    let dir = tempfile::tempdir().unwrap();
    let policy =
        RetentionPolicy { max_entries: 2, max_age_seconds: u64::MAX, ..Default::default() };
    let store = EntryStore::new(dir.path(), policy);
    for _ in 0..5 {
        store.insert(sample_envelope()).unwrap();
        // Ensure distinct mtimes so eviction order is deterministic
        // even on filesystems with coarse mtime resolution.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // insert already applies retention after every call, so the
    // store should already be down to the cap.
    assert_eq!(store.list().unwrap().len(), 2);
}

#[test]
fn apply_retention_evicts_oversized_entries() {
    let dir = tempfile::tempdir().unwrap();
    let policy = RetentionPolicy { max_entry_bytes: 10, ..Default::default() };
    let store = EntryStore::new(dir.path(), policy);
    let meta = store.insert(sample_envelope()).unwrap();
    // The freshly-inserted entry's real size is far larger than 10
    // bytes, so `insert`'s own post-insert retention sweep should
    // have already evicted it.
    assert!(store.show(&meta.report_id).unwrap().is_none());
}
