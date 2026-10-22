#![cfg(test)]
//! What native's plan says has to be fetched; these tests pin the
//! requirements prefetch acts on.

use super::growing_file_projection_tests::{Harness, GROUP};
use std::collections::BTreeSet;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;

fn put(path: &str, version: VersionHash) -> Op {
    Op::Put { path: SyncPath(path.into()), version }
}

fn store(h: &Harness, versions: &[&FileVersion]) {
    h.state
        .database()
        .write(|conn| {
            for version in versions {
                yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
            }
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
}

/// A peer's put that is concurrent with whatever the path holds.
fn concurrent_put(h: &Harness, device: &str, path: &str, version: &FileVersion) {
    store(h, &[version]);
    crate::test_support::remote_admission_fixture::admit_remote_ops(
        &h.state,
        GROUP,
        device,
        &[put(path, version.version_hash)],
        crate::test_support::remote_admission_fixture::Basis::Nothing,
    );
}

fn wanted(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|p| p.to_string()).collect()
}

fn missing_version(size: u32, seed: u8) -> FileVersion {
    crate::test_support::sync_stack_fixture::file_version(size, seed)
}

/// A contested path plans nothing: neither version is wanted until the loser's
/// author has moved its head to its copy path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contested_path_wants_nothing_until_it_is_forked() {
    let h = Harness::new(true);
    let (a, b) = (missing_version(10, 1), missing_version(11, 2));
    concurrent_put(&h, "device-r1", "x", &a);
    concurrent_put(&h, "device-r2", "x", &b);
    let paths = wanted(&["x"]);

    let native = h.convergence.content_missing_locally_from_native(GROUP, &paths).unwrap();

    assert!(native.is_empty(), "{native:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_this_device_already_holds_is_not_wanted() {
    let h = Harness::new(true);
    std::fs::write(h.path("scratch"), b"already here").unwrap();
    h.capture("scratch").await;
    let held = VersionHash(h.own_head("scratch").content.unwrap().version_hash);
    let held = h.state.dag_get_file_version(GROUP, &held).unwrap().unwrap();
    concurrent_put(&h, "device-r1", "y", &held);

    let native = h.convergence.content_missing_locally_from_native(GROUP, &wanted(&["y"])).unwrap();
    assert!(native.is_empty(), "{native:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_requested_sources_are_planned_even_when_a_level_holds_more() {
    let h = Harness::new(true);
    let (a, b) = (missing_version(10, 3), missing_version(11, 4));
    concurrent_put(&h, "device-r1", "p", &a);
    concurrent_put(&h, "device-r1", "q", &b);

    let native = h.convergence.content_missing_locally_from_native(GROUP, &wanted(&["p"])).unwrap();
    assert_eq!(native.len(), 1);
    assert_eq!(native[0].path, "p");
}

/// A file where a directory is required is contested: the file is not wanted
/// at its name. Its child's content is: it is needed whichever way the contest
/// resolves, though the child is not written until it does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_where_a_directory_is_required_is_not_wanted_at_its_name() {
    let h = Harness::new(true);
    let (file, child) = (missing_version(10, 5), missing_version(12, 6));
    concurrent_put(&h, "device-r1", "a", &file);
    concurrent_put(&h, "device-r1", "a/x", &child);

    let native =
        h.convergence.content_missing_locally_from_native(GROUP, &wanted(&["a", "a/x"])).unwrap();
    assert!(native.iter().all(|r| r.path == "a/x"), "{native:?}");
}

/// A version native has not stored makes its path contested: nothing is wanted
/// and the path is not planned as an absence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unresolvable_version_wants_nothing_and_plans_no_absence() {
    let h = Harness::new(true);
    let unknown = missing_version(10, 7);
    // Native shows a head whose version this device has never stored.
    crate::test_support::remote_admission_fixture::admit_remote(
        &h.state,
        GROUP,
        "device-r1",
        vec![crate::test_support::remote_admission_fixture::put(
            "z",
            unknown.version_hash,
            Vec::new(),
        )],
        &[],
    );

    assert!(h
        .convergence
        .content_missing_locally_from_native(GROUP, &wanted(&["z"]))
        .unwrap()
        .is_empty());
}
