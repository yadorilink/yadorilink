#![cfg(test)]
//! A contested path keeps what the disk has until the loser's author has moved
//! its head to its copy path; the winner then replaces the loser's bytes at the
//! original path only once those bytes stand, whole, at the copy path. The
//! displacement guard is what the reconcile lanes consult before any step that
//! drops content, and a platform that cannot make a directory entry durable
//! resolves the conflict but leaves the local file update waiting.

use super::growing_file_projection_tests::{Harness, GROUP};
use super::*;
use crate::test_support::remote_admission_fixture::{admit_remote, put};
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::native_fork::copy_path;

fn driver(h: &Harness) -> Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver> {
    h.session.clone() as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>
}

async fn pass(h: &Harness) {
    h.convergence
        .reconcile_paths_directly(&driver(h), GROUP, h.head_paths())
        .await
        .unwrap()
        .expect("sanity: the pass must actually run");
}

/// This device's own `x` (content `mine`) against a peer's concurrent put of
/// other content that wins the name; returns the harness, this device's version
/// and the peer's. Content is tried until the peer's version wins, because the
/// order of concurrent heads is the version hash.
async fn local_x_loses_to_a_peer(label: &str) -> (Harness, VersionHash, VersionHash) {
    for attempt in 0..64u32 {
        let h = Harness::new(false);
        let mine = format!("{label}: this device's x");
        std::fs::write(h.path("x"), &mine).unwrap();
        assert!(matches!(h.capture("x").await, LocalChangeOutcome::FileChanged(_)));
        let mine_version = VersionHash(h.own_head("x").content.unwrap().version_hash);
        let theirs = format!("{label}: the peer's x, attempt {attempt}");
        std::fs::write(h.path("scratch"), &theirs).unwrap();
        assert!(matches!(h.capture("scratch").await, LocalChangeOutcome::FileChanged(_)));
        let theirs_version = VersionHash(h.own_head("scratch").content.unwrap().version_hash);
        if theirs_version.0 <= mine_version.0 {
            continue;
        }
        let stored = h.state.dag_get_file_version(GROUP, &theirs_version).unwrap().expect("stored");
        admit_remote(
            &h.state,
            GROUP,
            "device-remote",
            vec![put("x", theirs_version, Vec::new())],
            &[stored],
        );
        return (h, mine_version, theirs_version);
    }
    panic!("no content that wins the name was found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contested_path_keeps_the_disk_until_it_is_forked() {
    let (h, _mine, _theirs) = local_x_loses_to_a_peer("pending").await;

    for _ in 0..3 {
        pass(&h).await;
    }

    assert_eq!(
        std::fs::read(h.path("x")).unwrap(),
        b"pending: this device's x",
        "a pending path is a semantic state: the disk keeps what it has"
    );
    assert_eq!(h.state.file_index_repository().contested_path_count(GROUP).unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_winner_replaces_the_loser_only_after_the_loser_stands_at_its_copy() {
    // No identity-proof gate: on a volume whose identity proof is inconclusive (overlayfs,
    // tmpfs: no inode generation, coarse birth time) the copy's bytes still answer the guard.
    let (h, mine, _theirs) = local_x_loses_to_a_peer("guard").await;
    h.fork_own_contests();

    for _ in 0..4 {
        pass(&h).await;
    }

    let copy = copy_path("x", &mine);
    assert_eq!(std::fs::read(h.path(&copy)).unwrap(), b"guard: this device's x");
    assert_eq!(h.state.file_index_repository().contested_path_count(GROUP).unwrap(), 0);
    // The replacement itself needs durable namespace changes.
    if crate::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the original",
    ) {
        assert_ne!(std::fs::read(h.path("x")).unwrap(), b"guard: this device's x");
    }
}

/// A platform that cannot make a directory entry durable (Windows, until its
/// validation lands) resolves the conflict and writes the copy, but does not
/// replace or remove the file that still holds the loser's only other copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_directory_durability_the_conflict_is_resolved_but_the_file_waits() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (h, mine, _theirs) = local_x_loses_to_a_peer("windows").await;
    let root = h.convergence.sync_root(GROUP).unwrap();
    yadorilink_sync_sqlite::displacement_guard::set_force_no_directory_durability(&root, true);
    h.fork_own_contests();

    for _ in 0..4 {
        pass(&h).await;
    }

    let copy = copy_path("x", &mine);
    assert_eq!(std::fs::read(h.path(&copy)).unwrap(), b"windows: this device's x", "the copy");
    assert_eq!(
        std::fs::read(h.path("x")).unwrap(),
        b"windows: this device's x",
        "the file that holds the loser is not replaced while the update cannot be durable"
    );
    assert_eq!(h.state.file_index_repository().contested_path_count(GROUP).unwrap(), 0);

    // Lifting the forced refusal only helps where the platform can make the
    // update durable at all.
    if !crate::test_support::windows_durability_gate_allows_tests(
        "the waiting update once the refusal lifts",
    ) {
        return;
    }
    yadorilink_sync_sqlite::displacement_guard::set_force_no_directory_durability(&root, false);
    for _ in 0..4 {
        pass(&h).await;
    }
    assert_ne!(std::fs::read(h.path("x")).unwrap(), b"windows: this device's x");
}

/// The guard's question is whether the displaced content stands under the other name, and
/// the other name's bytes decide it: other bytes there keep the original path waiting, and
/// the loser's own bytes (even rewritten, so no identity proof can vouch for the file) let it go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_original_waits_while_the_copy_holds_other_bytes() {
    if !crate::test_support::windows_durability_gate_allows_tests("the guard's clearance") {
        return;
    }
    let (h, mine, theirs) = local_x_loses_to_a_peer("bytes").await;
    let root = h.convergence.sync_root(GROUP).unwrap();
    yadorilink_sync_sqlite::displacement_guard::set_force_no_directory_durability(&root, true);
    h.fork_own_contests();
    for _ in 0..4 {
        pass(&h).await;
    }
    let copy = copy_path("x", &mine);
    assert_eq!(std::fs::read(h.path(&copy)).unwrap(), b"bytes: this device's x", "the copy");
    yadorilink_sync_sqlite::displacement_guard::set_force_no_directory_durability(&root, false);

    std::fs::write(h.path(&copy), b"something else entirely").unwrap();
    assert!(
        !h.convergence.displacement_allowed(GROUP, "x", Some(&theirs)).await.unwrap(),
        "other bytes at the copy do not preserve the loser"
    );

    std::fs::write(h.path(&copy), b"bytes: this device's x").unwrap();
    assert!(
        h.convergence.displacement_allowed(GROUP, "x", Some(&theirs)).await.unwrap(),
        "the loser's bytes at the copy preserve it, whatever the identity proof says"
    );
}

/// An on-demand folder with the loser hydrated at `x`: the loser's fork is a copy
/// of bytes already here, so it is written (not left a placeholder), and the
/// loser's bytes stand at the copy path (the guard let the original wait for it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_an_on_demand_folder_a_hydrated_loser_is_copied_and_not_left_a_placeholder() {
    let (h, mine, _theirs) = local_x_loses_to_a_peer("ondemand").await;
    h.state
        .link_repository()
        .set_materialization_policy(
            &h.convergence.sync_root(GROUP).unwrap().to_string_lossy(),
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();
    h.fork_own_contests();

    for _ in 0..6 {
        pass(&h).await;
    }

    let copy = copy_path("x", &mine);
    assert_eq!(std::fs::read(h.path(&copy)).unwrap(), b"ondemand: this device's x");
    // What the on-demand lane then does at `x` (a placeholder for the winner) is
    // its own business; the loser's bytes stand at the copy path whatever it does.
}

/// Ten guards that each find another path holding the displaced version must all finish: the
/// question whether that path can coexist is answered on the guard's own connection, so a
/// guard never holds one pooled connection while waiting for a second.
#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn concurrent_displacement_guards_do_not_exhaust_the_connection_pool() {
    let h = Harness::new(false);
    let when = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    for name in ["a", "b"] {
        std::fs::write(h.path(name), b"same bytes").unwrap();
        std::fs::File::options()
            .write(true)
            .open(h.path(name))
            .unwrap()
            .set_modified(when)
            .unwrap();
        assert!(matches!(h.capture(name).await, LocalChangeOutcome::FileChanged(_)));
    }
    let a = VersionHash(h.own_head("a").content.unwrap().version_hash);
    let b = VersionHash(h.own_head("b").content.unwrap().version_hash);
    assert_eq!(a, b, "sanity: the two paths hold one version");
    let state = Arc::new(h.state.clone());
    assert!(
        matches!(
            state.displacement_guard(GROUP, "a", None, &|_| false).unwrap(),
            yadorilink_sync_sqlite::displacement_guard::DisplacementGuard::Guarded(_)
        ),
        "sanity: `a` is displacing a version that lives on at `b`"
    );
    let started = std::time::Instant::now();
    let guards: Vec<_> = (0..10)
        .map(|_| {
            let state = state.clone();
            tokio::task::spawn_blocking(move || {
                // The volume folds `b` onto `a`.
                state.displacement_guard(GROUP, "a", None, &|other| other == "b").unwrap()
            })
        })
        .collect();
    for guard in guards {
        guard.await.unwrap();
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(10), "guards stalled on the pool");
}
