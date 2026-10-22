#![cfg(test)]
//! A path whose current version changes wakes the custody-hold reconciler: a
//! lease this device holds for the version that was replaced backs nothing
//! any more, and waiting for the periodic recheck would keep the responder's
//! blocks pinned for minutes.

use super::delete_projection_tests::{reconcile, Remote};
use super::growing_file_projection_tests::Harness;
use crate::test_support::remote_admission_fixture::{delete, put};
use futures_util::FutureExt;
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::ids::{DeltaHash, VersionHash};

/// Whether a wake is pending, consuming it.
fn woken(h: &Harness) -> bool {
    h.state.custody_hold_wake().notified().now_or_never().is_some()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_newer_version_arriving_wakes_the_reconciler() {
    let h = Harness::new(true);
    std::fs::write(h.path("notes.txt"), b"the version this device holds").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let old = DeltaHash(h.own_head("notes.txt").change_hash);
    std::fs::write(h.path("scratch.bin"), b"the newer version a peer authored").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer = VersionHash(h.own_head("scratch.bin").content.unwrap().version_hash);
    let mut remote = Remote::new();
    remote.admit(&h, vec![put("notes.txt", newer, vec![old])]).await;
    let _ = woken(&h);
    assert!(!woken(&h), "sanity: nothing is pending before the pass");

    reconcile(&h, &["notes.txt"]).await;

    assert!(woken(&h), "applying the newer version woke the reconciler");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_arriving_wakes_the_reconciler() {
    let h = Harness::new(true);
    std::fs::write(h.path("notes.txt"), b"the version the remover saw").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let seen = DeltaHash(h.own_head("notes.txt").change_hash);
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;
    let _ = woken(&h);

    reconcile(&h, &["notes.txt"]).await;

    assert!(woken(&h), "applying the removal woke the reconciler");
}
