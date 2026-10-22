#![cfg(test)]

use super::*;

#[test]
fn record_severe_error_persists_a_candidate_and_redacts_log_lines() {
    let dir = tempfile::tempdir().unwrap();
    let storage = ReportingStorage::open(dir.path());
    let id = record_severe_error(
        &storage,
        "daemon_startup",
        "sync-state",
        vec!["failed to open /Users/alice/sync-state.sqlite3".to_string()],
    );
    assert!(id.is_some());
    let candidates = storage.error_candidates().list().unwrap();
    assert_eq!(candidates.len(), 1);
    let envelope = storage.error_candidates().show(&candidates[0].report_id).unwrap().unwrap();
    let json = envelope.to_json();
    assert!(!json.contains("alice"));
}

/// -3.4 "the hook in isolation": `record_panic` -- the exact
/// function the installed panic hook calls -- must yield a single bounded,
/// redacted, unsent candidate. The message, location, and backtrace all
/// carry a home path; none of it may reach disk.
#[test]
fn record_panic_yields_a_bounded_redacted_unsent_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let storage = ReportingStorage::open(dir.path());

    let id = record_panic(
        &storage,
        "index corrupt reading /Users/alice/Sync/notes.md",
        Some("crates/yadorilink-daemon/src/foo.rs:42"),
        "0: frame at /Users/alice/secret\n1: more frames",
    );
    assert!(id.is_some());

    // Bounded: exactly one candidate under the error-candidate store's caps.
    let candidates = storage.error_candidates().list().unwrap();
    assert_eq!(candidates.len(), 1);
    // Unsent: nothing was queued for submission -- a candidate is not a
    // submission, and no network path is reachable from record_panic.
    assert!(storage.queue().list().unwrap().is_empty());

    let envelope = storage.error_candidates().show(&candidates[0].report_id).unwrap().unwrap();
    let json = envelope.to_json();
    // Redacted: the home path (and the user file name inside it) is gone,
    // and the redaction pass did run (a redaction marker is present).
    assert!(!json.contains("alice"));
    assert!(!json.contains("notes.md"));
    assert!(json.contains("[REDACTED"));
    // Categorized as a panic, which the intake triages as a crash.
    assert!(json.contains("\"panic\""));
}

/// end-to-end: the *installed* hook captures a real
/// unhandled panic. Serialized against any other test touching the global
/// panic hook, and the prior hook is restored afterwards so the rest of
/// the suite is unaffected.
#[test]
fn installed_panic_hook_captures_a_real_panic() {
    use std::sync::{Arc, Mutex};
    static HOOK_LOCK: Mutex<()> = Mutex::new(());
    let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(ReportingStorage::open(dir.path()));

    // Save the pre-existing hook, install ours, trigger a contained panic,
    // then restore -- so this test never leaks a hook into the suite.
    let previous = std::panic::take_hook();
    install_panic_hook(Arc::clone(&storage));
    let result = std::panic::catch_unwind(|| {
        panic!("induced panic at /Users/alice/secret");
    });
    std::panic::set_hook(previous);
    assert!(result.is_err());

    // The panic produced a bounded, redacted candidate.
    let candidates = storage.error_candidates().list().unwrap();
    assert!(!candidates.is_empty());
    let envelope = storage.error_candidates().show(&candidates[0].report_id).unwrap().unwrap();
    assert!(!envelope.to_json().contains("alice"));
}
