#![cfg(test)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

use super::*;
use crate::daemon_state::DaemonState;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

fn test_bundle_service(state: &Arc<DaemonState>) -> Arc<DiagnosticsBundleQueryService> {
    crate::adapters::build_query_services(state.clone()).diagnostics_bundle.clone()
}

/// Diagnostics-specific redaction: a link whose local path carries a
/// real home-directory fragment must never appear verbatim in the
/// daemon-assembled bundle -- proves the daemon-side assembly
/// actually calls into `yadorilink_reporting`'s redaction helpers,
/// not just that the CLI-only fallback does (already covered by
/// `yadorilink-reporting::diagnostics`'s own tests).
#[tokio::test]
async fn daemon_bundle_redacts_a_real_linked_folder_path() {
    let state = test_state();
    state
        .replica_coordinator
        .link_repository()
        .add_link("/Users/alice/Documents/secret-project", "11111111-2222-3333-4444-555555555555")
        .unwrap();

    let resp = build_bundle(&test_bundle_service(&state)).await;

    assert_eq!(resp.collection_mode, "daemon");
    assert!(!resp.bundle_json.contains("/Users/alice"));
    assert!(!resp.bundle_json.contains("alice"));
    assert!(!resp.bundle_json.contains("secret-project"));
    assert!(!resp.bundle_json.contains("11111111-2222-3333-4444-555555555555"));
    // Required diagnostics bundle schema keys are present.
    let parsed: serde_json::Value = serde_json::from_str(&resp.bundle_json).unwrap();
    for key in [
        "schema_version",
        "generated_at",
        "yadorilink_version",
        "platform",
        "daemon",
        "links",
        "recent_errors",
        "updates",
        "resources",
        "environment",
        "redaction",
    ] {
        assert!(parsed.get(key).is_some(), "missing bundle key {key}");
    }
    // A stable, non-raw pseudonym stands in for the real identifiers.
    assert!(resp.bundle_json.contains("link:001"));
}

/// The bundle's link paths are opaque tokens, never redacted-but-partial
/// real paths: a folder name that survives pattern redaction (spaces, an
/// unusual root) must not reach a support engineer.
#[tokio::test]
async fn daemon_bundle_replaces_link_paths_with_opaque_tokens() {
    let state = test_state();
    state
        .replica_coordinator
        .link_repository()
        .add_link("/Volumes/Work Drive/Acme Merger/Tax Returns", "group-a")
        .unwrap();

    let resp = build_bundle(&test_bundle_service(&state)).await;

    for leaked in ["Volumes", "Work", "Acme", "Merger", "Tax", "Returns"] {
        assert!(!resp.bundle_json.contains(leaked), "{leaked} leaked into the bundle");
    }
    let parsed: serde_json::Value = serde_json::from_str(&resp.bundle_json).unwrap();
    assert_eq!(parsed["links"][0]["path"], "path:001");
}

/// Bundle generation is bounded -- even if the underlying
/// sub-collection work is stuck (simulated here with a `thread::sleep`
/// well longer than the timeout, standing in for e.g. an unexpectedly
/// huge link/file walk), `run_bounded` still returns within its
/// timeout, not after the stuck work eventually finishes.
///
/// Deliberately uses a bounded (2s), not unbounded/hours-long,
/// `thread::sleep` for the injected stuck-collection stand-in: a
/// `spawn_blocking` OS thread can't be cancelled once started, and
/// tokio's own runtime teardown (which every `#[tokio::test]` performs
/// when the test function returns) waits for outstanding blocking
/// tasks to actually finish before the process can proceed -- an
/// earlier version of this test used `Duration::from_secs(3600)` here
/// and, while `run_bounded`'s *return* was still correctly bounded by
/// `short_timeout`, the test binary itself then hung for up to an hour
/// at teardown waiting for that detached thread, which defeats the
/// entire point of this check. 2s is still far longer than
/// `short_timeout` (proving the bound), while keeping this test's
/// total wall-clock cost small.
#[tokio::test]
async fn bundle_generation_is_bounded_even_if_a_sub_collection_hangs() {
    let state = test_state();
    let bundle_service = test_bundle_service(&state);
    let short_timeout = Duration::from_millis(150);

    let started = Instant::now();
    let resp = run_bounded(short_timeout, move || {
        // Stands in for a sub-collection that doesn't return in time
        // (e.g. a huge log/file scan) -- well longer than
        // `short_timeout`, so this proves the *caller* doesn't wait
        // for it, not merely that the closure itself is slow.
        std::thread::sleep(Duration::from_secs(2));
        assemble_bundle_json(&bundle_service, 0)
    })
    .await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(800),
        "build_bundle must return promptly once its timeout elapses, not wait for the \
         stuck sub-collection to finish (which sleeps for 2s); took {elapsed:?}"
    );
    assert_eq!(resp.collection_mode, "daemon-partial");
    let parsed: serde_json::Value = serde_json::from_str(&resp.bundle_json).unwrap();
    assert!(parsed.get("schema_version").is_some(), "fallback bundle must still be schema-valid");
}

/// The mirror case: well within budget, generation completes normally
/// and reports `"daemon"`, not `"daemon-partial"`.
#[tokio::test]
async fn bundle_generation_reports_full_daemon_mode_when_not_bounded() {
    let state = test_state();
    let resp = build_bundle(&test_bundle_service(&state)).await;
    assert_eq!(resp.collection_mode, "daemon");
}
