//! The conformance
//! test that pins `dst_support::fs_events::decompose` against the *real*
//! notify-backed watcher, so a change to `watcher.rs`'s event
//! classification that no longer matches the harness's decomposition is
//! caught here -- before any DST seed sweep false-fails weeks later from
//! the drift.
//!
//! This is a plain, per-platform test on purpose: it exercises the actual
//! OS watcher (FSEvents / inotify / ReadDirectoryChangesW) on a real
//! tempdir, which no simulator models. It compiles the *exact*
//! `fs_events.rs` source the simulation scenarios use, via `#[path]`, so
//! the two share one source of truth. It runs in CI's ordinary `cargo test`
//! legs, per platform.

use std::path::Path;
use std::time::Duration;

use yadorilink_filesystem_sync::watcher::{watch_folder, FsChangeKind};

#[path = "dst_support/fs_events.rs"]
mod fs_events;

use fs_events::{decompose, FsOp, WatchEvent};

/// Drains every event the watcher delivers within a short quiescent window
/// (returns once no new event has arrived for `quiet` or `overall`
/// elapses), collecting the classified `(relative-path, kind)` pairs.
/// Relative paths are forward-slash, stripped of the canonicalized root
/// prefix, so they line up with `decompose`'s output.
async fn drain_relative(
    events: &mut tokio::sync::mpsc::Receiver<yadorilink_filesystem_sync::watcher::FsChangeEvent>,
    root: &Path,
    quiet: Duration,
    overall: Duration,
) -> Vec<(String, FsChangeKind)> {
    // `FsChangeKind` is not `Hash`, so a `Vec` (deduplicated) stands in for
    // a set here.
    let mut observed: Vec<(String, FsChangeKind)> = Vec::new();
    let deadline = tokio::time::Instant::now() + overall;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(quiet.min(remaining), events.recv()).await {
            Ok(Some(ev)) => {
                if let Ok(rel) = ev.path.strip_prefix(root) {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    let pair = (rel, ev.kind);
                    if !pair.0.is_empty() && !observed.contains(&pair) {
                        observed.push(pair);
                    }
                }
            }
            // Channel closed, or `quiet` elapsed with no new event: settled.
            Ok(None) | Err(_) => break,
        }
    }
    observed
}

fn expected_pairs(op: &FsOp) -> Vec<(String, FsChangeKind)> {
    decompose(op).into_iter().map(|WatchEvent { path, kind }| (path, kind)).collect()
}

/// Every classified pair `decompose` predicts for `op` must actually be
/// delivered by the real watcher. We assert a subset (not exact equality)
/// deliberately: a real backend can legitimately deliver *extra* events the
/// harness need not model -- most commonly a `CreatedOrModified` for the
/// parent directory itself when a child changes (see `watcher.rs`'s own
/// `recv_until` note) -- but it must never *fail* to deliver, in the
/// classified language, what `decompose` claims it does. A drift where the
/// classification itself changed (e.g. a rename source stops mapping to
/// `Removed`) makes the expected pair absent and fails here.
fn assert_decompose_is_delivered(op: &FsOp, observed: &[(String, FsChangeKind)], label: &str) {
    for pair in expected_pairs(op) {
        assert!(
            observed.contains(&pair),
            "{label}: decompose predicts {pair:?} but the real watcher delivered {observed:?}"
        );
    }
}

#[tokio::test]
async fn create_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let mut watcher = watch_folder(&root).unwrap();

    let op = FsOp::Create { path: "created.txt".into() };
    std::fs::write(root.join("created.txt"), b"hello").unwrap();

    let observed = drain_relative(
        &mut watcher.events,
        &root,
        Duration::from_millis(800),
        Duration::from_secs(8),
    )
    .await;
    assert_decompose_is_delivered(&op, &observed, "create");
}

#[tokio::test]
async fn delete_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(root.join("victim.txt"), b"hello").unwrap();
    let mut watcher = watch_folder(&root).unwrap();
    // Let the initial-scan / create noise settle before the op under test.
    let _ = drain_relative(
        &mut watcher.events,
        &root,
        Duration::from_millis(500),
        Duration::from_secs(3),
    )
    .await;

    let op = FsOp::Delete { path: "victim.txt".into() };
    std::fs::remove_file(root.join("victim.txt")).unwrap();

    let observed = drain_relative(
        &mut watcher.events,
        &root,
        Duration::from_millis(800),
        Duration::from_secs(8),
    )
    .await;
    assert_decompose_is_delivered(&op, &observed, "delete");
}

/// A rename's *source*-side classification is genuinely backend-specific
/// and is the one part of `decompose`'s output that is NOT platform-
/// normalized:
///
/// - inotify (Linux) reports the rename as `RenameMode::Both`, so
///  `watcher.rs` classifies the source `Removed` and the destination
///  `CreatedOrModified` -- exactly what `decompose` models, because that
///  is the decomposition the DST scenarios deliberately *inject*.
/// - FSEvents (macOS) cannot say which side is which, so notify surfaces it
///  as create/modify events and `watcher.rs`'s `RenameMode::Any`/`Other`
///  fallback (its own doc comment on this) classifies *both* paths
///  `CreatedOrModified`.
///
/// So the conformance test pins only the invariant that holds on every
/// backend -- the destination becomes a live `CreatedOrModified`, and the
/// source path is observed at all -- rather than the source's kind, which
/// is why the scenarios inject a chosen decomposition instead of depending
/// on the live backend. `decompose` itself stays the inotify/`RenameMode::
/// Both` model the scenarios use; a drift where `watcher.rs` stopped
/// emitting the destination create still fails here.
#[tokio::test]
async fn rename_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(root.join("before.txt"), b"hello").unwrap();
    let mut watcher = watch_folder(&root).unwrap();
    let _ = drain_relative(
        &mut watcher.events,
        &root,
        Duration::from_millis(500),
        Duration::from_secs(3),
    )
    .await;

    std::fs::rename(root.join("before.txt"), root.join("after.txt")).unwrap();

    let observed = drain_relative(
        &mut watcher.events,
        &root,
        Duration::from_millis(1000),
        Duration::from_secs(8),
    )
    .await;

    assert!(
        observed.contains(&("after.txt".to_string(), FsChangeKind::CreatedOrModified)),
        "rename: destination must be a live CreatedOrModified on every backend, got {observed:?}"
    );
    assert!(
        observed.iter().any(|(path, _)| path == "before.txt"),
        "rename: the source path must be observed (as Removed on inotify, or CreatedOrModified \
         under the FSEvents Any/Other fallback), got {observed:?}"
    );
}
