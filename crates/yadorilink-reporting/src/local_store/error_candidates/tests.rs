#![cfg(test)]

use super::*;
use crate::builder::{build_error_envelope, ErrorPayloadBuilder, ReportEnvironment};
use crate::schema::OsFamily;

fn sample_error_envelope() -> ReportEnvelope {
    let env = ReportEnvironment {
        generated_at: "2026-01-01T00:00:00Z".into(),
        yadorilink_version: "0.1.0".into(),
        os_family: OsFamily::Macos,
        os_version_bucket: "15.x".into(),
        arch: "aarch64".into(),
        install_channel: None,
        anonymous_reporter_id: None,
    };
    let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core");
    build_error_envelope(env, builder).0
}

#[test]
fn create_list_show_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = ErrorCandidateStore::new(dir.path());
    let meta = store.create_candidate(sample_error_envelope()).unwrap();
    assert_eq!(store.list().unwrap().len(), 1);
    assert_eq!(store.show(&meta.report_id).unwrap().unwrap(), sample_error_envelope());
    assert_eq!(store.most_recent().unwrap().unwrap().report_id, meta.report_id);
}

/// retention cap deletion for error candidates specifically
/// (distinct defaults from the queue).
#[test]
fn default_policy_caps_at_twenty_entries() {
    let policy = default_retention_policy();
    assert_eq!(policy.max_entries, 20);
    assert_eq!(policy.max_age_seconds, 14 * 24 * 60 * 60);
}

#[test]
fn delete_removes_a_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let store = ErrorCandidateStore::new(dir.path());
    let meta = store.create_candidate(sample_error_envelope()).unwrap();
    assert!(store.delete(&meta.report_id).unwrap());
    assert!(store.show(&meta.report_id).unwrap().is_none());
}

#[test]
fn candidates_and_queue_are_kept_in_separate_directories() {
    let dir = tempfile::tempdir().unwrap();
    let store = ErrorCandidateStore::new(dir.path());
    store.create_candidate(sample_error_envelope()).unwrap();
    assert!(dir.path().join("error-candidates").is_dir());
    assert!(!dir.path().join("queue").exists());
}

/// the redaction summary captured at creation time survives
/// a round trip through the sidecar file.
#[test]
fn create_candidate_with_summary_round_trips_the_summary() {
    let dir = tempfile::tempdir().unwrap();
    let store = ErrorCandidateStore::new(dir.path());
    let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core")
        .log_lines(vec!["reading /Users/alice/secret failed".to_string()]);
    let env = ReportEnvironment {
        generated_at: "2026-01-01T00:00:00Z".into(),
        yadorilink_version: "0.1.0".into(),
        os_family: OsFamily::Linux,
        os_version_bucket: "24.04".into(),
        arch: "x86_64".into(),
        install_channel: None,
        anonymous_reporter_id: None,
    };
    let (envelope, summary) = build_error_envelope(env, builder);
    assert!(!summary.is_empty());

    let meta = store.create_candidate_with_summary(envelope.clone(), &summary).unwrap();
    let (shown_envelope, shown_summary) =
        store.show_with_summary(&meta.report_id).unwrap().unwrap();
    assert_eq!(shown_envelope, envelope);
    assert_eq!(shown_summary.categories.len(), summary.categories.len());
}

/// A plain `create_candidate` (no summary given) shows an empty
/// summary, not an error.
#[test]
fn show_with_summary_of_a_plain_candidate_returns_an_empty_summary() {
    let dir = tempfile::tempdir().unwrap();
    let store = ErrorCandidateStore::new(dir.path());
    let meta = store.create_candidate(sample_error_envelope()).unwrap();
    let (_envelope, summary) = store.show_with_summary(&meta.report_id).unwrap().unwrap();
    assert!(summary.is_empty());
}

#[test]
fn delete_also_removes_the_summary_sidecar_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = ErrorCandidateStore::new(dir.path());
    let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core")
        .log_lines(vec!["reading /Users/alice/secret failed".to_string()]);
    let env = ReportEnvironment {
        generated_at: "2026-01-01T00:00:00Z".into(),
        yadorilink_version: "0.1.0".into(),
        os_family: OsFamily::Linux,
        os_version_bucket: "24.04".into(),
        arch: "x86_64".into(),
        install_channel: None,
        anonymous_reporter_id: None,
    };
    let (envelope, summary) = build_error_envelope(env, builder);
    let meta = store.create_candidate_with_summary(envelope, &summary).unwrap();
    assert!(store.summary_path(&meta.report_id).exists());
    store.delete(&meta.report_id).unwrap();
    assert!(!store.summary_path(&meta.report_id).exists());
}
