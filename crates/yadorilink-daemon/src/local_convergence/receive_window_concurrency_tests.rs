#![cfg(test)]
//! The plain own-name file entries of one reconcile pass are written
//! concurrently, and everything the serial order guaranteed still holds:
//! colliding names and directories stay ordered, one entry's failure leaves
//! the others whole, a local edit racing any of the paths in flight is never
//! overwritten or authored over a newer version, and the end state equals
//! the serial pass's.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_local_capture::ports::LocalMutationStore as _;
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_peer_session::convergence_driver::{BlockFetch, ConvergenceDriver, FetchedBlock};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::{BlockInfo, FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::{OverlapProbe, ProbeSeam};
use crate::test_support::remote_admission_fixture::{admit_remote_ops, Basis};

const PEER: &str = "device-peer";

/// A peer that holds nothing: every block it is asked for is missing.
struct EmptyPeer;

impl ConvergenceDriver for EmptyPeer {
    fn peer_device_id(&self) -> &str {
        PEER
    }

    fn fetch_block<'a>(
        &'a self,
        _group_id: &'a str,
        _file_path: &'a str,
        _block: &'a BlockInfo,
        _timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<FetchedBlock, PeerSessionError>> + Send + 'a>> {
        Box::pin(async {
            Ok(FetchedBlock { outcome: BlockFetch::Missing, wire_wait: Duration::ZERO })
        })
    }
}

pub(super) fn pin_concurrency(h: &Harness, limit: usize) {
    h.convergence.receive_write_concurrency_override.store(limit, Ordering::Relaxed);
}

pub(super) fn arm(h: &Harness, probe: &Arc<OverlapProbe>) {
    *h.convergence.overlap_probe.lock().unwrap() = Some(probe.clone());
}

/// The version of `content`, captured from a scratch file this device holds,
/// so its blocks are local and the group's own.
pub(super) async fn source(h: &Harness, tag: &str, content: &[u8]) -> VersionHash {
    let scratch = format!("zz-source-{tag}");
    std::fs::write(h.path(&scratch), content).unwrap();
    assert!(matches!(h.capture(&scratch).await, LocalChangeOutcome::FileChanged(_)));
    VersionHash(h.own_head(&scratch).content.unwrap().version_hash)
}

pub(super) fn put(path: &str, version: VersionHash) -> Op {
    Op::Put { path: SyncPath(path.into()), version }
}

pub(super) fn publish(h: &Harness, ops: &[Op]) {
    admit_remote_ops(&h.state, GROUP, PEER, ops, Basis::CurrentHeads);
}

pub(super) fn driver() -> Arc<dyn ConvergenceDriver> {
    Arc::new(EmptyPeer)
}

pub(super) async fn reconcile(h: &Harness, paths: &[String]) -> super::ProjectionAttempt {
    h.convergence
        .reconcile_paths_directly(&driver(), GROUP, paths.iter().cloned().collect())
        .await
        .unwrap()
        .expect("the attempt runs")
}

pub(super) fn names(prefix: &str, count: usize) -> Vec<String> {
    (0..count).map(|i| format!("{prefix}{i:02}.txt")).collect()
}

pub(super) async fn publish_new_files(h: &Harness, files: &[String]) -> BTreeMap<String, Vec<u8>> {
    let mut contents = BTreeMap::new();
    let mut ops = Vec::new();
    for (i, name) in files.iter().enumerate() {
        let content = format!("content of {name}").into_bytes();
        let version = source(h, &i.to_string(), &content).await;
        ops.push(put(name, version));
        contents.insert(name.clone(), content);
    }
    publish(h, &ops);
    contents
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_files_of_a_pass_are_written_at_the_same_time() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    let files = names("f", 8);
    let contents = publish_new_files(&h, &files).await;
    // Held between the temp file's sync and the rename until three writes are
    // there together, each with its path lock held: a serial pass never gets
    // there and times out.
    let probe = OverlapProbe::new(ProbeSeam::BeforeRename, 3, 5_000);
    arm(&h, &probe);

    let attempt = reconcile(&h, &files).await;

    assert!(probe.max_in_flight() >= 3, "writes did not overlap: {:?}", probe.events());
    assert!(probe.max_in_flight() <= 8);
    for name in &files {
        assert!(attempt.is_settled(name), "{name} did not settle: {:?}", attempt.retry);
        assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_limit_of_one_writes_one_file_at_a_time() {
    let h = Harness::new(false);
    pin_concurrency(&h, 1);
    let files = names("s", 3);
    publish_new_files(&h, &files).await;
    let probe = OverlapProbe::new(ProbeSeam::BeforeRename, 2, 150);
    arm(&h, &probe);

    let attempt = reconcile(&h, &files).await;

    assert_eq!(probe.max_in_flight(), 1, "{:?}", probe.events());
    assert!(files.iter().all(|name| attempt.is_settled(name)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_more_files_are_in_flight_than_the_limit() {
    let h = Harness::new(false);
    pin_concurrency(&h, 3);
    let files = names("l", 12);
    publish_new_files(&h, &files).await;
    let probe = OverlapProbe::new(ProbeSeam::BeforeRename, 3, 5_000);
    arm(&h, &probe);

    let attempt = reconcile(&h, &files).await;

    assert_eq!(probe.max_in_flight(), 3, "{:?}", probe.events());
    assert!(files.iter().all(|name| attempt.is_settled(name)));
}

/// Names that fold to one key are never written at the same time, and the
/// later one starts only after the earlier one finished, as in the serial
/// order. The independent names around them are not delayed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn names_that_fold_together_are_written_one_after_the_other() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    let files: Vec<String> =
        ["Foo.txt", "bar.txt", "baz.txt", "foo.txt", "qux.txt"].map(String::from).to_vec();
    publish_new_files(&h, &files).await;
    let probe = OverlapProbe::new(ProbeSeam::BeforeRename, 1, 20_000);
    probe.hold_until_released();
    arm(&h, &probe);

    let task = {
        let (convergence, files) = (h.convergence.clone(), files.clone());
        tokio::spawn(async move {
            convergence
                .reconcile_paths_directly(&driver(), GROUP, files.into_iter().collect())
                .await
        })
    };
    let waited = std::time::Instant::now();
    while probe.in_flight() < 3 {
        assert!(waited.elapsed() < Duration::from_secs(20), "{:?}", probe.events());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Everything that may run has arrived by now.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let first_run = probe.events();
    assert_eq!(
        probe.in_flight(),
        3,
        "the first run is Foo.txt, bar.txt and baz.txt: {first_run:?}"
    );
    assert!(
        !first_run.iter().any(|(path, _)| path == "foo.txt"),
        "foo.txt started while Foo.txt was in flight: {first_run:?}"
    );
    probe.release();
    let attempt = task.await.unwrap().unwrap().expect("the attempt runs");

    let events = probe.events();
    if let Some(later) = events.iter().position(|(path, entered)| path == "foo.txt" && *entered) {
        let earlier = events
            .iter()
            .position(|(path, entered)| path == "Foo.txt" && !*entered)
            .expect("Foo.txt left the seam");
        assert!(earlier < later, "foo.txt started before Foo.txt finished: {events:?}");
    }
    assert!(attempt.is_settled("Foo.txt") && attempt.is_settled("bar.txt"));
    assert!(attempt.is_settled("qux.txt"));
}

/// Directories are barriers: a file below a directory is written after the
/// directory is shaped, and an entry at one depth never starts before the
/// directories of its depth are done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_below_new_directories_are_written_after_their_directories() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    let files: Vec<String> =
        ["top0.txt", "top1.txt", "a/x.txt", "a/y.txt", "a/b/z.txt", "a/b/w.txt", "c/d/e/deep.txt"]
            .map(String::from)
            .to_vec();
    let contents = publish_new_files(&h, &files).await;
    let probe = OverlapProbe::new(ProbeSeam::BeforeRename, 2, 3_000);
    arm(&h, &probe);

    let attempt = reconcile(&h, &files).await;

    for name in &files {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
        assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
    }
    assert!(probe.max_in_flight() >= 2, "{:?}", probe.events());
}

/// One entry that cannot be written (its blocks are nowhere) is retried; the
/// others are written, and the state left is the serial pass's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_files_failure_leaves_the_other_files_written_as_in_the_serial_pass() {
    async fn run(limit: usize) -> (BTreeSet<String>, BTreeSet<String>, BTreeMap<String, String>) {
        let h = Harness::new(false);
        pin_concurrency(&h, limit);
        let mut files = names("ok", 6);
        publish_new_files(&h, &files).await;
        // A version whose blocks this device does not hold, and the peer has none.
        let missing = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![9; 32]), size: 10 }],
            10,
            FileMeta {
                mtime_unix_nanos: 1,
                unix_mode: Some(0o644),
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        h.state
            .database()
            .write(|conn| {
                yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, &missing)?;
                Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
            })
            .unwrap();
        publish(&h, &[put("bad.txt", missing.version_hash)]);
        files.push("bad.txt".into());
        let probe =
            OverlapProbe::new(ProbeSeam::BeforeRename, 2, if limit > 1 { 3_000 } else { 100 });
        arm(&h, &probe);
        let attempt = reconcile(&h, &files).await;
        if limit > 1 {
            assert!(probe.max_in_flight() >= 2, "{:?}", probe.events());
        }
        let settled = attempt.settled.keys().cloned().collect();
        (settled, attempt.retry.clone(), snapshot(&h, &files))
    }

    let serial = run(1).await;
    let concurrent = run(8).await;

    assert_eq!(serial.1, BTreeSet::from(["bad.txt".to_string()]), "{serial:?}");
    assert_eq!(serial.0.len(), 6);
    assert_eq!(concurrent, serial);
    assert!(
        concurrent.2["bad.txt"].contains("state=Some(Remote)"),
        "{:?}",
        concurrent.2["bad.txt"]
    );
}

/// What a name looks like once a pass is over: disk, row, state, intent, heads.
pub(super) fn snapshot(h: &Harness, files: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for name in files {
        let disk = match std::fs::read(h.path(name)) {
            Ok(bytes) => format!("disk=present:{}", String::from_utf8_lossy(&bytes)),
            Err(_) => "disk=absent".to_string(),
        };
        let row = h.state.get_file(GROUP, name).unwrap().map_or("row=none".to_string(), |row| {
            format!("row=deleted:{},size:{},blocks:{}", row.deleted, row.size, row.blocks.len())
        });
        let state = h.state.get_materialization_state(GROUP, name).unwrap();
        let intent = h.state.materialization_intent_target(GROUP, name).unwrap().is_some();
        let heads: Vec<String> =
            h.native_heads(name).iter().map(|head| head.dot.author.device.0.clone()).collect();
        out.insert(
            name.clone(),
            format!("{disk} {row} state={state:?} intent={intent} heads={heads:?}"),
        );
    }
    out
}

pub(super) fn on_disk_tree(h: &Harness) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if rel.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                walk(root, &path, out);
            } else {
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(&h.path(""), &h.path(""), &mut out);
    out
}

/// A seeded workload: new files in nested directories, names that differ only
/// in case, then in a second pass changes, deletes and renames.
async fn run_workload(
    limit: usize,
) -> (BTreeMap<String, String>, BTreeMap<String, Vec<u8>>, usize) {
    let (state, disk, max, _) = run_workload_with(limit, 0).await;
    (state, disk, max)
}

/// `batch_completion`: `0` the configured default, `1` batched, `2` per file.
/// Also returns the item count of every batched close transaction.
pub(super) async fn run_workload_with(
    limit: usize,
    batch_completion: u8,
) -> (BTreeMap<String, String>, BTreeMap<String, Vec<u8>>, usize, Vec<usize>) {
    run_workload_full(limit, batch_completion, 0, 0).await
}

/// [`run_workload_with`] with the open batching and the commit offload pinned
/// (`0` the configured default, `1` on, `2` off for each).
pub(super) async fn run_workload_full(
    limit: usize,
    batch_completion: u8,
    batch_open: u8,
    async_commit: u8,
) -> (BTreeMap<String, String>, BTreeMap<String, Vec<u8>>, usize, Vec<usize>) {
    let h = Harness::new(false);
    pin_concurrency(&h, limit);
    h.convergence.batch_open_override.store(batch_open, Ordering::Relaxed);
    h.state.test_observers.async_commit_override.store(async_commit, Ordering::Relaxed);
    h.convergence.batch_completion_override.store(batch_completion, Ordering::Relaxed);
    let probe = OverlapProbe::new(ProbeSeam::BeforeRename, 2, if limit > 1 { 300 } else { 50 });
    arm(&h, &probe);
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let dirs = ["", "a/", "a/b/", "c/", "c/d/e/", "A/"];
    let mut files: Vec<String> = Vec::new();
    for i in 0..40 {
        let dir = dirs[(next() % dirs.len() as u64) as usize];
        files.push(format!("{dir}f{i:02}.txt"));
    }
    files.extend(["Dup.txt", "dup.txt", "a/Case.txt", "a/case.txt"].map(String::from));
    files.sort();
    files.dedup();

    let mut ops = Vec::new();
    for (i, name) in files.iter().enumerate() {
        let filler = "x".repeat((next() % 3000) as usize);
        let content = format!("{name} v1 {i} {filler}").into_bytes();
        let version = source(&h, &format!("1-{i}"), &content).await;
        ops.push(put(name, version));
    }
    // One version whose blocks this device does not hold and the peer has none: its
    // write fails and it stays a retriable placeholder, in every configuration.
    let missing = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(vec![9; 32]), size: 10 }],
        10,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    h.state
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, &missing)?;
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
    ops.push(put("bad.txt", missing.version_hash));
    files.push("bad.txt".into());
    publish(&h, &ops);
    let first = reconcile(&h, &files).await;
    assert!(files.iter().all(|f| first.is_settled(f) || first.retry.contains(f)));

    // Second pass: change a quarter, delete a quarter, rename a few.
    let mut touched: Vec<String> = Vec::new();
    let mut ops = Vec::new();
    for (i, name) in files.iter().enumerate() {
        match next() % 8 {
            0 | 1 => {
                let content = format!("{name} v2 {i}").into_bytes();
                let version = source(&h, &format!("2-{i}"), &content).await;
                ops.push(put(name, version));
                touched.push(name.clone());
            }
            2 | 3 => {
                ops.push(Op::Delete { path: SyncPath(name.clone()) });
                touched.push(name.clone());
            }
            4 => {
                let to = format!("moved/{i}/{}", name.rsplit('/').next().unwrap());
                let content = format!("{name} moved {i}").into_bytes();
                let version = source(&h, &format!("3-{i}"), &content).await;
                ops.push(Op::Move {
                    from: SyncPath(name.clone()),
                    to: SyncPath(to.clone()),
                    version,
                });
                touched.push(name.clone());
                touched.push(to);
            }
            _ => {}
        }
    }
    publish(&h, &ops);
    let second = reconcile(&h, &touched).await;
    assert!(touched.iter().all(|f| second.is_settled(f) || second.retry.contains(f)));

    let mut all: Vec<String> = files.clone();
    all.extend(touched.iter().cloned());
    all.sort();
    all.dedup();
    let mut state = snapshot(&h, &all);
    state.insert(
        "attempts".into(),
        format!(
            "{:?} {:?}",
            first.settled.keys().collect::<Vec<_>>(),
            second.settled.keys().collect::<Vec<_>>()
        ),
    );
    state.insert("retries".into(), format!("{:?} {:?}", first.retry, second.retry));
    let sizes = h.state.test_observers.close_batch_sizes.lock().unwrap().clone();
    (state, on_disk_tree(&h), probe.max_in_flight(), sizes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_pass_ends_in_the_state_of_the_serial_pass() {
    let (serial_state, serial_disk, serial_max) = run_workload(1).await;
    let (concurrent_state, concurrent_disk, concurrent_max) = run_workload(8).await;

    assert_eq!(serial_max, 1);
    assert!(concurrent_max >= 2, "the workload never overlapped two writes");
    assert_eq!(concurrent_disk, serial_disk);
    assert_eq!(concurrent_state, serial_state);
}

/// The commits of the open and of the completion collector run on the blocking pool
/// or inline: the same end state, on the seeded workload (failures, name
/// collisions, moves, deletes).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offloaded_commit_pass_ends_in_the_state_of_an_inline_pass() {
    let (inline_state, inline_disk, _, _) = run_workload_full(8, 1, 0, 2).await;
    let (offloaded_state, offloaded_disk, offloaded_max, closes) =
        run_workload_full(8, 1, 0, 1).await;

    assert!(offloaded_max >= 2, "the workload never overlapped two writes");
    assert_eq!(offloaded_disk, inline_disk);
    assert_eq!(offloaded_state, inline_state);
    assert!(closes.iter().sum::<usize>() > 0);
}

/// Eight paths with writes in flight, each renamed into place and not yet
/// committed, while a scan and a capture run: none of them may author the
/// bytes this device itself just wrote over the newer version a peer
/// published. The path locks, held by every writer for its whole write, are
/// what keeps them out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scan_during_eight_writes_in_flight_authors_nothing_over_the_newer_versions() {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 8);
    let files = names("g", 8);
    let mut ops = Vec::new();
    let mut newer = BTreeMap::new();
    for (i, name) in files.iter().enumerate() {
        // This device's own version first, then the peer's newer one over it.
        std::fs::write(h.path(name), format!("own version {i}")).unwrap();
        assert!(matches!(h.capture(name).await, LocalChangeOutcome::FileChanged(_)));
        let content = format!("peer's newer version {i}").into_bytes();
        let version = source(&h, &format!("n{i}"), &content).await;
        ops.push(put(name, version));
        newer.insert(name.clone(), (content, version));
    }
    publish(&h, &ops);
    let probe = OverlapProbe::new(ProbeSeam::BeforeCommit, 1, 30_000);
    probe.hold_until_released();
    arm(&h, &probe);

    let task = {
        let (convergence, files) = (h.convergence.clone(), files.clone());
        tokio::spawn(async move {
            convergence
                .reconcile_paths_directly(&driver(), GROUP, files.into_iter().collect())
                .await
        })
    };
    let waited = std::time::Instant::now();
    while probe.in_flight() < 8 {
        assert!(waited.elapsed() < Duration::from_secs(30), "{:?}", probe.events());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Every file now holds the peer's bytes on disk with nothing committed.
    for name in &files {
        assert_eq!(std::fs::read(h.path(name)).unwrap(), newer[name].0);
    }
    let scanned = h.scan();
    assert!(
        !scanned.iter().any(|record| files.contains(&record.path)),
        "a scan authored a path whose write was in flight: {scanned:?}"
    );
    probe.release();
    let attempt = task.await.unwrap().unwrap().expect("the attempt runs");

    assert!(files.iter().all(|name| attempt.is_settled(name)), "{:?}", attempt.retry);
    for name in &files {
        assert!(matches!(h.capture(name).await, LocalChangeOutcome::None), "{name}");
    }
    h.redrive().await;
    for name in &files {
        let heads = h.native_heads(name);
        assert_eq!(heads.len(), 1, "{name}: no local head beside the newer version");
        assert_eq!(heads[0].dot.author.device.0, PEER);
        assert_eq!(heads[0].payload.version.0, newer[name].1 .0);
        assert_eq!(std::fs::read(h.path(name)).unwrap(), newer[name].0);
    }
}

fn large_content(tag: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i + tag * 31) % 251) as u8).collect()
}

/// A file's planned size is its version's, whether or not its blocks had to
/// be fetched: a locally available large file is charged against the run's
/// byte budget like any other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_locally_available_file_is_charged_its_planned_size() {
    let h = Harness::new(false);
    let content = large_content(1, 300_000);
    let version = source(&h, "big", &content).await;
    publish(&h, &[put("big.bin", version)]);
    let node = h
        .state
        .native_plan_level(GROUP, "")
        .unwrap()
        .nodes
        .get(&SyncPath("big.bin".into()))
        .cloned()
        .expect("the plan places big.bin");

    let size = h.convergence.planned_size(GROUP, &node, "big.bin", &Default::default());

    assert_eq!(size, 300_000);
}

fn temp_files(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".yadorilink-tmp."))
        .collect()
}

/// Files that each fit the free space but not together are not all written
/// at once: the ones that do not fit are refused up front, none runs out of
/// space mid-write, and they complete as space comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_that_fit_one_by_one_but_not_together_are_not_written_together() {
    const MIB: u64 = 1024 * 1024;
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    let files = names("h", 8);
    let mut ops = Vec::new();
    for (i, name) in files.iter().enumerate() {
        let version = source(&h, &i.to_string(), &large_content(i, (4 * MIB) as usize)).await;
        ops.push(put(name, version));
    }
    publish(&h, &ops);
    h.convergence.set_headroom_enforced_for_tests(true);
    // A fixed free space, whatever earlier writes used: room for two of the
    // four-MiB files above the headroom and not for three. Only the reservation
    // across writes can make the pass write two at a time.
    *h.convergence.fake_available_bytes.lock().unwrap() = Some(10 * MIB);
    h.convergence.set_headroom_override_bytes_for_tests(Some(0));
    *h.convergence.volume_key_override.lock().unwrap() = Some("files-that-fit-volume".into());
    let probe = OverlapProbe::new(ProbeSeam::BeforeRename, 2, 3_000);
    arm(&h, &probe);

    let mut pending: Vec<String> = files.clone();
    let mut passes = 0;
    while !pending.is_empty() {
        passes += 1;
        assert!(passes <= 8, "the files never completed: {pending:?}");
        let attempt = reconcile(&h, &pending).await;
        assert!(temp_files(&h.path("")).is_empty(), "a temp file was left behind");
        pending.retain(|name| !attempt.is_settled(name));
        if passes == 1 {
            assert_eq!(pending.len(), 6, "only two fit: {:?}", attempt.retry);
        }
    }

    assert_eq!(probe.max_in_flight(), 2, "{:?}", probe.events());
    for (i, name) in files.iter().enumerate() {
        assert_eq!(std::fs::read(h.path(name)).unwrap(), large_content(i, (4 * MIB) as usize));
    }
    assert_eq!(
        super::reconcile::reserved_on("files-that-fit-volume"),
        0,
        "every reservation is released"
    );
}

/// A store whose reads wait until the test lets them go.
struct GatedStore {
    /// Panics instead of reading, once let go.
    panics: bool,
    entered: std::sync::atomic::AtomicUsize,
    open: (std::sync::Mutex<bool>, std::sync::Condvar),
}

impl yadorilink_peer_session::ports::BlockContentStore for GatedStore {
    fn put(
        &self,
        _data: &[u8],
    ) -> Result<yadorilink_local_storage::ContentHash, yadorilink_local_storage::StorageError> {
        unimplemented!()
    }

    fn put_prepared(
        &self,
        _prepared: &yadorilink_local_storage::LocallyHashedBlock,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        unimplemented!()
    }

    fn put_prepared_batch(
        &self,
        _prepared: &[yadorilink_local_storage::LocallyHashedBlock],
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        unimplemented!()
    }

    fn get(&self, _hash: &str) -> Result<Vec<u8>, yadorilink_local_storage::StorageError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let (lock, cv) = &self.open;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = cv.wait(open).unwrap();
        }
        if self.panics {
            panic!("injected block read failure");
        }
        Ok(vec![7u8; 1024])
    }

    fn present_blocks(
        &self,
        hashes: &[yadorilink_local_storage::ContentHash],
    ) -> Result<Vec<bool>, yadorilink_local_storage::StorageError> {
        Ok(vec![true; hashes.len()])
    }
}

/// Dropping the run while eight assemblies are running (a link stopping)
/// leaves no temp file behind once their blocking tasks finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_a_run_mid_assembly_leaves_no_temp_files() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(GatedStore {
        panics: false,
        entered: Default::default(),
        open: (std::sync::Mutex::new(false), std::sync::Condvar::new()),
    });
    let mut running = Vec::new();
    for i in 0..8u8 {
        let (store, out) = (store.clone(), dir.path().join(format!("f{i}")));
        running.push(tokio::spawn(async move {
            let block = BlockInfo { hash: vec![i; 32], offset: 0, size: 1024 };
            super::types::reconstruct_file_to_temp_off_runtime(
                store,
                &out,
                &[block],
                1,
                None,
                no_ledger(),
            )
            .await
        }));
    }
    let waited = std::time::Instant::now();
    while store.entered.load(Ordering::SeqCst) < 8 {
        assert!(waited.elapsed() < Duration::from_secs(10), "assemblies did not start");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(temp_files(dir.path()).len(), 8, "sanity: eight temps are being written");
    for task in &running {
        task.abort();
    }
    for task in running {
        let _ = task.await;
    }
    *store.open.0.lock().unwrap() = true;
    store.open.1.notify_all();

    let waited = std::time::Instant::now();
    while !temp_files(dir.path()).is_empty() {
        assert!(
            waited.elapsed() < Duration::from_secs(10),
            "temps stranded: {:?}",
            temp_files(dir.path())
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn gated(panics: bool) -> Arc<GatedStore> {
    Arc::new(GatedStore {
        panics,
        entered: Default::default(),
        open: (std::sync::Mutex::new(false), std::sync::Condvar::new()),
    })
}

fn let_go(store: &GatedStore) {
    *store.open.0.lock().unwrap() = true;
    store.open.1.notify_all();
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let waited = std::time::Instant::now();
    while !done() {
        assert!(waited.elapsed() < Duration::from_secs(30), "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The space an assembly reserved stays reserved while its blocking task is
/// still writing, even when the future awaiting it is dropped, and is freed
/// once the task and its temp cleanup are done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_assembly_keeps_its_space_reserved_until_it_finishes() {
    use super::reconcile::{reserved_on, HeadroomReservation};
    let dir = tempfile::tempdir().unwrap();
    let store = gated(false);
    // A failing assertion must not leave the blocking task parked forever.
    struct LetGoOnDrop(Arc<GatedStore>);
    impl Drop for LetGoOnDrop {
        fn drop(&mut self) {
            let_go(&self.0);
        }
    }
    let _release = LetGoOnDrop(store.clone());
    let reservation = Arc::new(HeadroomReservation::for_tests("abandoned-volume", 5));
    let task = {
        let (store, out, held) = (store.clone(), dir.path().join("f"), reservation.clone());
        tokio::spawn(async move {
            let block = BlockInfo { hash: vec![1; 32], offset: 0, size: 1024 };
            super::types::reconstruct_file_to_temp_off_runtime(
                store,
                &out,
                &[block],
                1,
                Some(held),
                no_ledger(),
            )
            .await
        })
    };
    until("the assembly did not start", || store.entered.load(Ordering::SeqCst) == 1).await;
    task.abort();
    let _ = task.await;
    drop(reservation);

    assert_eq!(reserved_on("abandoned-volume"), 5, "released while the assembly still writes");
    let_go(&store);
    until("the space was never released", || reserved_on("abandoned-volume") == 0).await;
    until("a temp was stranded", || temp_files(dir.path()).is_empty()).await;
}

/// A block read that panics after the temp file exists leaves no temp file
/// and releases the reserved space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panicking_assembly_leaves_no_temp_and_frees_its_space() {
    use super::reconcile::{reserved_on, HeadroomReservation};
    let dir = tempfile::tempdir().unwrap();
    let store = gated(true);
    let_go(&store);
    let held = Arc::new(HeadroomReservation::for_tests("panicking-volume", 7));
    let block = BlockInfo { hash: vec![2; 32], offset: 0, size: 1024 };

    let result = super::types::reconstruct_file_to_temp_off_runtime(
        store,
        &dir.path().join("f"),
        &[block],
        1,
        Some(held.clone()),
        no_ledger(),
    )
    .await;
    drop(held);

    assert!(result.is_err());
    assert!(temp_files(dir.path()).is_empty(), "{:?}", temp_files(dir.path()));
    assert_eq!(reserved_on("panicking-volume"), 0);
}

/// Links on one volume share one account of reserved space, however many
/// executors write to them; another volume's account is separate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_of_two_executors_on_one_volume_cannot_jointly_exceed_its_free_space() {
    use super::reconcile::{reserved_on, HeadroomReservation};
    const MIB: u64 = 1024 * 1024;
    let (first, second) = (Harness::new(false), Harness::new(false));
    for h in [&first, &second] {
        h.convergence.set_headroom_enforced_for_tests(true);
        *h.convergence.fake_available_bytes.lock().unwrap() = Some(10 * MIB);
        h.convergence.set_headroom_override_bytes_for_tests(Some(0));
        *h.convergence.volume_key_override.lock().unwrap() = Some("two-executors-volume".into());
    }
    let target = first.path("a");
    let a = first.convergence.preflight_disk_headroom(GROUP, &target, 4 * MIB).unwrap();
    let b = first.convergence.preflight_disk_headroom(GROUP, &target, 4 * MIB).unwrap();

    let refused = second.convergence.preflight_disk_headroom(GROUP, &second.path("b"), 4 * MIB);
    assert!(refused.is_err(), "the second executor was admitted against space already claimed");
    drop(a);
    let admitted = second.convergence.preflight_disk_headroom(GROUP, &second.path("b"), 4 * MIB);
    assert!(admitted.is_ok(), "space came back but the second executor is still refused");
    drop((b, admitted));

    // Another volume's reservations do not count here.
    let elsewhere = HeadroomReservation::for_tests("some-other-volume", 100 * MIB);
    let unaffected = first.convergence.preflight_disk_headroom(GROUP, &target, 4 * MIB);
    assert!(unaffected.is_ok());
    *second.convergence.volume_key_override.lock().unwrap() = Some("some-other-volume".into());
    assert!(second.convergence.preflight_disk_headroom(GROUP, &target, 4 * MIB).is_err());
    assert_eq!(reserved_on("some-other-volume"), 100 * MIB);
    drop(elsewhere);
}

/// The same cancellation rule for hydration's write, through the executor's
/// real hydration path: its caller going away mid-write does not release the
/// space the write is still using.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_hydration_keeps_its_space_reserved_until_its_write_finishes() {
    use super::reconcile::reserved_on;
    const VOLUME: &str = "hydration-through-executor-volume";
    let h = Harness::new(false);
    std::fs::write(h.path("hp.bin"), vec![5u8; 2000]).unwrap();
    assert!(matches!(h.capture("hp.bin").await, LocalChangeOutcome::FileChanged(_)));
    h.state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "hp.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Remote,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    std::fs::remove_file(h.path("hp.bin")).unwrap();

    // The same replica, with a store whose reads wait for the test.
    let store = gated(false);
    struct LetGoOnDrop(Arc<GatedStore>);
    impl Drop for LetGoOnDrop {
        fn drop(&mut self) {
            let_go(&self.0);
        }
    }
    let _release = LetGoOnDrop(store.clone());
    let ports = crate::test_support::peer_session_fixture::ExecutorPorts::permissive();
    let executor = super::LocalConvergenceExecutor::new(
        h.state.clone(),
        "device-local".to_string(),
        ports.root_commit_authority_provider.clone(),
        ports.pending_local_change_flush.clone(),
        std::collections::HashMap::from([(GROUP.to_string(), h.path(""))]),
        store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
        ports.block_write_activity_provider.clone(),
        super::HeadroomPolicy::disabled(),
    );
    executor.set_headroom_enforced_for_tests(true);
    *executor.fake_available_bytes.lock().unwrap() = Some(100 * 1024 * 1024);
    executor.set_headroom_override_bytes_for_tests(Some(0));
    *executor.volume_key_override.lock().unwrap() = Some(VOLUME.into());

    // The assembly every hydration and eager write shares (`reconstruct_file_to_temp_off_runtime`),
    // run directly with the reservation the lanes take before it.
    let canonical = h
        .state
        .file_index_repository()
        .canonical_current_row(GROUP, "hp.bin")
        .unwrap()
        .expect("the captured file's row");
    let blocks = canonical.snapshot.blocks.clone();
    let headroom =
        Arc::new(executor.preflight_disk_headroom(GROUP, &h.path("hp.bin"), 2000).unwrap());
    let task = {
        let (store, target, mtime) = (
            store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            h.path("hp.bin"),
            canonical.snapshot.mtime_unix_nanos,
        );
        tokio::spawn(async move {
            super::types::reconstruct_file_to_temp_off_runtime(
                store,
                &target,
                &blocks,
                mtime,
                Some(headroom),
                no_ledger(),
            )
            .await
        })
    };
    until("the hydration write did not start", || store.entered.load(Ordering::SeqCst) >= 1).await;
    task.abort();
    let _ = task.await;

    assert_eq!(reserved_on(VOLUME), 2000, "released while the write still runs");
    let_go(&store);
    until("the space was never released", || reserved_on(VOLUME) == 0).await;
}

/// A free-space query that hangs on one volume holds up that volume's
/// preflights only. B proves it by reaching its own free-space query while
/// A's is still blocked; the waits are watchdogs, not the measure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hung_free_space_query_on_one_volume_does_not_block_another() {
    const MIB: u64 = 1024 * 1024;
    let (a, b) = (Harness::new(false), Harness::new(false));
    for (h, key) in [(&a, "hung-volume"), (&b, "other-volume")] {
        h.convergence.set_headroom_enforced_for_tests(true);
        *h.convergence.fake_available_bytes.lock().unwrap() = Some(100 * MIB);
        h.convergence.set_headroom_override_bytes_for_tests(Some(0));
        *h.convergence.volume_key_override.lock().unwrap() = Some(key.into());
    }
    let flag = || Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (a_entered, a_release, b_entered) = (flag(), flag(), flag());
    let (entered, release) = (a_entered.clone(), a_release.clone());
    *a.convergence.free_space_probe.lock().unwrap() = Some(Arc::new(move || {
        entered.store(true, Ordering::SeqCst);
        let watchdog = std::time::Instant::now();
        while !release.load(Ordering::SeqCst) && watchdog.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }));
    let entered = b_entered.clone();
    *b.convergence.free_space_probe.lock().unwrap() =
        Some(Arc::new(move || entered.store(true, Ordering::SeqCst)));
    let hung = {
        let (convergence, target) = (a.convergence.clone(), a.path("x"));
        std::thread::spawn(move || {
            convergence.preflight_disk_headroom(GROUP, &target, MIB).map(|_| ()).is_ok()
        })
    };
    until("A's query did not start", || a_entered.load(Ordering::SeqCst)).await;

    let (convergence, target) = (b.convergence.clone(), b.path("y"));
    let other = std::thread::spawn(move || {
        convergence.preflight_disk_headroom(GROUP, &target, MIB).map(|_| ()).is_ok()
    });
    until("B never reached its query while A was blocked", || b_entered.load(Ordering::SeqCst))
        .await;
    assert!(!a_release.load(Ordering::SeqCst), "A was still blocked when B got there");
    a_release.store(true, Ordering::SeqCst);

    assert!(other.join().unwrap());
    assert!(hung.join().unwrap());
}

fn no_ledger() -> Arc<dyn yadorilink_local_storage::TempFileLedger> {
    Arc::new(yadorilink_local_storage::NoTempLedger)
}
