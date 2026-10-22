//! Folder Rewind execution end to end, on real daemons with real watchers:
//! the plan is authored as ordinary signed changes, the ordinary projection
//! writes the folder (historical content AND historical mtime), and a peer
//! converges through ordinary sync.
//!
//! Also what a rewind must never do: re-capture its own restored files as
//! new edits (whatever the filesystem's mtime precision), win over a
//! concurrent edit, author a chunk twice across a crash, or start without
//! every byte it restores held locally.

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{
    advertise_substrate_endpoints, fully_connected, link_eager, new_node, spawn_orchestrator,
    TopologyHandles, TopologyNode,
};
use support::{open_file_backed_replica_coordinator, register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::change_policy::{GroupPolicyState, WriterRole};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::rewind::{
    execute_rewind, prepare_rewind, preview_rewind, RewindExecuteRequest, RewindHook, RewindPoint,
};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::rewind::{RewindFailureKind, RewindRunState};

const GROUP: &str = "rewind-execute-group";

struct Device {
    id: String,
    state: Arc<DaemonState>,
    root: PathBuf,
    _owned: Owned,
}

/// What keeps a device's directories (and, for a topology node, its
/// reference-cycle release) alive for the test.
enum Owned {
    Alone { _root: tempfile::TempDir, _store: tempfile::TempDir, _index: tempfile::TempDir },
    Node(#[allow(dead_code)] Box<TopologyNode>),
}

impl Device {
    /// A device on its own, a writer of the group, watching its folder.
    fn alone(id: &str) -> Self {
        init_tracing();
        support::ensure_isolated_config_dir();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let (coordinator, index_dir) = open_file_backed_replica_coordinator();
        let state = DaemonState::new(id.to_string(), Arc::new(coordinator), store);
        support::ensure_device_signing_key(&state);
        state.authority.install_test_group_policy(
            GROUP,
            GroupPolicyState::with_members_for_tests(&[(id, WriterRole::Editor)]),
        );
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
        LinkRuntimeController::new(state.clone()).start(local_path, GROUP.to_string()).unwrap();
        Device {
            id: id.to_string(),
            state,
            root: root.path().to_path_buf(),
            _owned: Owned::Alone { _root: root, _store: store_dir, _index: index_dir },
        }
    }

    fn node(node: TopologyNode) -> Self {
        Device {
            id: node.device_id.clone(),
            state: node.state.clone(),
            root: node.root.path().to_path_buf(),
            _owned: Owned::Node(Box::new(node)),
        }
    }

    fn local_path(&self) -> String {
        self.root.to_string_lossy().to_string()
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn write(&self, rel: &str, content: &str) {
        let path = self.path(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// Every regular file under the root: content and mtime (nanoseconds).
    fn tree(&self) -> BTreeMap<String, (String, i64)> {
        let mut out = BTreeMap::new();
        walk(&self.root, &self.root, &mut out);
        out
    }

    /// Every path's current row: (seq, deleted). A new user edit shows as a
    /// new seq.
    fn current_rows(&self) -> BTreeMap<String, (i64, bool)> {
        let database = self.state.replica_coordinator.database();
        let conn = database.pool_for_test().get().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT path, version_seq, deleted FROM files \
                 WHERE group_id = ?1 AND state = 'current' ORDER BY path",
            )
            .unwrap();
        let rows = stmt
            .query_map([GROUP], |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?))))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        rows
    }

    /// The signed changes this device has authored.
    fn own_deltas(&self) -> i64 {
        let database = self.state.replica_coordinator.database();
        let conn = database.pool_for_test().get().unwrap();
        conn.query_row(
            "SELECT count(*) FROM native_delta_log WHERE group_id = ?1 AND author = ?2",
            [GROUP, self.id.as_str()],
            |r| r.get(0),
        )
        .unwrap()
    }

    async fn wait_indexed(&self, rel: &str, live: bool) {
        wait_until_with_context(
            || self.current_rows().get(rel).is_some_and(|(_, deleted)| *deleted != live),
            Duration::from_secs(30),
            || {
                format!(
                    "{} never indexed {rel} (live: {live}): {:?}; versions {:?}; disk {:?}",
                    self.id,
                    self.current_rows(),
                    self.state.replica_coordinator.sqlite().dag_list_versions(GROUP, rel),
                    support::real_entry_names(&self.root)
                )
            },
        )
        .await;
    }

    async fn wait_tree(&self, expected: &BTreeMap<String, String>, what: &str) {
        wait_until_with_context(
            || contents(&self.tree()) == *expected,
            Duration::from_secs(60),
            || format!("{}: {what}: {:?}", self.id, contents(&self.tree())),
        )
        .await;
    }

    /// Previews at `target` until the folder has settled into a plan with
    /// `actionable` paths, and returns the request that approves it.
    async fn approve(&self, target: i64, actionable: u64) -> RewindExecuteRequest {
        self.approve_when(target, |n| n == actionable).await.0
    }

    /// Previews at `target` until the plan's actionable count satisfies
    /// `settled`; returns the request that approves it and that count.
    async fn approve_when(
        &self,
        target: i64,
        settled: impl Fn(u64) -> bool,
    ) -> (RewindExecuteRequest, u64) {
        let mut last = None;
        for _ in 0..3600 {
            let preview =
                preview_rewind(self.state.clone(), GROUP.into(), target, false).await.unwrap();
            let counts = preview.counts;
            let actionable = counts.create + counts.delete + counts.replace;
            if settled(actionable) && counts.unavailable == 0 {
                let request = RewindExecuteRequest {
                    group_id: GROUP.into(),
                    target_unix_nanos: target,
                    plan_id: preview.plan_id,
                };
                return (request, actionable);
            }
            last = Some(counts);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{}: the plan never settled: {last:?}", self.id);
    }

    /// Prepares and executes `request` to its end.
    async fn rewind(&self, request: RewindExecuteRequest) -> RewindRunState {
        let prepared = prepare_rewind(self.state.clone(), request).await.unwrap();
        execute_rewind(self.state.clone(), prepared, None).await.expect("the run ends")
    }

    fn latest_run(&self) -> yadorilink_replica_domain::rewind::RewindRun {
        self.state.replica_coordinator.rewind_run_repository().latest_run(GROUP).unwrap().unwrap()
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (String, i64)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if yadorilink_fs_platform::reserved_namespace::is_reserved_component(&entry.file_name())
            || name == yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME
            || name == yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME
            || name.contains(".yadorilink-tmp.")
        {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if meta.is_dir() {
            walk(root, &path, out);
        } else if meta.is_file() {
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            let mtime =
                meta.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                    as i64;
            out.insert(rel, (std::fs::read_to_string(&path).unwrap_or_default(), mtime));
        }
    }
}

fn contents(tree: &BTreeMap<String, (String, i64)>) -> BTreeMap<String, String> {
    tree.iter().map(|(path, (content, _))| (path.clone(), content.clone())).collect()
}

fn expected(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(path, content)| (path.to_string(), content.to_string())).collect()
}

/// A target strictly between what was admitted before and what comes after.
async fn target_now() -> i64 {
    tokio::time::sleep(Duration::from_millis(20)).await;
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        as i64;
    tokio::time::sleep(Duration::from_millis(20)).await;
    at
}

/// The state a rewind brings back: three files, one in a directory.
async fn original(device: &Device) -> BTreeMap<String, String> {
    device.write("report.txt", "report as it was");
    device.write("notes.txt", "notes as they were");
    device.write("sub/data.txt", "data as it was");
    for rel in ["report.txt", "notes.txt", "sub/data.txt"] {
        device.wait_indexed(rel, true).await;
    }
    expected(&[
        ("report.txt", "report as it was"),
        ("notes.txt", "notes as they were"),
        ("sub/data.txt", "data as it was"),
    ])
}

/// A mass edit after the target: one file overwritten, one deleted, one
/// renamed, one created in a new directory. Waits until all of it is
/// captured.
async fn mass_edit(device: &Device) {
    device.write("report.txt", "ENCRYPTED");
    std::fs::remove_file(device.path("notes.txt")).unwrap();
    std::fs::rename(device.path("sub/data.txt"), device.path("sub/data.txt.locked")).unwrap();
    device.write("ransom/README.txt", "pay up");
    device.wait_indexed("notes.txt", false).await;
    device.wait_indexed("sub/data.txt", false).await;
    device.wait_indexed("sub/data.txt.locked", true).await;
    device.wait_indexed("ransom/README.txt", true).await;
    wait_until_with_context(
        || device.current_rows().get("report.txt").is_some_and(|(seq, _)| *seq >= 2),
        Duration::from_secs(30),
        || format!("the overwrite was never captured: {:?}", device.current_rows()),
    )
    .await;
}

/// The whole folder comes back on the device that rewinds -- content and
/// historical mtime, through the ordinary projection -- and a connected
/// peer converges on it through ordinary sync. A finished rewind is a
/// fixed point: previewing it again finds nothing to do.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rewind_restores_the_folder_and_a_peer_converges_through_ordinary_sync() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let (a, b) = (new_node("rewind-a-nas"), new_node("rewind-b-laptop"));
    for node in [&a, &b] {
        register_with_fake(&fake, &node.state, &node.device_id, &[GROUP]).await;
        fake.grant_role(&node.device_id, GROUP, WriterRole::Editor);
        link_eager(node, GROUP);
    }
    let mut handles = TopologyHandles::new();
    handles.insert(a.device_id.clone(), spawn_orchestrator(fake.addr(), &a));
    handles.insert(b.device_id.clone(), spawn_orchestrator(fake.addr(), &b));
    advertise_substrate_endpoints(&[&a, &b]).await;
    wait_until_with_context(
        || fully_connected(&a.state, &b.device_id) && fully_connected(&b.state, &a.device_id),
        Duration::from_secs(60),
        || "the two devices never connected".to_string(),
    )
    .await;
    let (a, b) = (Device::node(a), Device::node(b));

    let before = original(&a).await;
    b.wait_tree(&before, "never received the original files").await;
    let original_mtimes = a.tree();
    let target = target_now().await;
    mass_edit(&a).await;
    b.wait_tree(
        &expected(&[
            ("report.txt", "ENCRYPTED"),
            ("sub/data.txt.locked", "data as it was"),
            ("ransom/README.txt", "pay up"),
        ]),
        "never received the mass edit",
    )
    .await;

    // report replaced, notes and data created, data.txt.locked, README and
    // possibly the new directory removed.
    let preview = preview_rewind(a.state.clone(), GROUP.into(), target, false).await.unwrap();
    assert_eq!((preview.counts.replace, preview.counts.create), (1, 2), "{:?}", preview.counts);
    assert!(preview.counts.delete >= 2, "{:?}", preview.counts);
    let request = RewindExecuteRequest {
        group_id: GROUP.into(),
        target_unix_nanos: target,
        plan_id: preview.plan_id,
    };

    assert_eq!(a.rewind(request).await, RewindRunState::Done);
    let run = a.latest_run();
    assert_eq!((run.restored, run.chunks_done, run.chunks_total), (3, 1, 1));
    assert!(run.message().starts_with("Rewind finished: 3 files restored"), "{}", run.message());

    a.wait_tree(&before, "the rewind never materialized").await;
    // The historical mtime came back with the content (not the time of the
    // rewind), as far as this filesystem stores it.
    for (path, (_, mtime)) in a.tree() {
        assert_eq!(mtime, original_mtimes[&path].1, "{path} has the historical mtime");
    }
    b.wait_tree(&before, "the peer never converged on the rewind").await;

    // A fixed point: nothing left to do once projection settled.
    a.approve(target, 0).await;
    handles.shutdown();
}

/// The files a rewind restores carry their historical mtime, and the next
/// capture must not take them for edits a person made -- neither the
/// watcher's look at what the projection wrote, nor a full rescan after a
/// restart, and not when the filesystem keeps a coarser mtime than the
/// version recorded (whole seconds as on HFS+ or exFAT, 100 ns as on NTFS).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restored_files_are_not_captured_again_as_new_edits() {
    let a = Device::alone("device-a");
    let before = original(&a).await;
    let target = target_now().await;
    mass_edit(&a).await;
    let (request, _) = a.approve_when(target, |n| n >= 5).await;
    let deltas_before = a.own_deltas();
    assert_eq!(a.rewind(request).await, RewindRunState::Done);
    let rewind_deltas = a.own_deltas() - deltas_before;
    a.wait_tree(&before, "the rewind never materialized").await;
    a.approve(target, 0).await;

    // Settled: what the projection wrote is not captured again.
    let rows = a.current_rows();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(a.current_rows(), rows, "the projection's own writes were captured as edits");
    assert_eq!(a.own_deltas() - deltas_before, rewind_deltas, "no change beyond the rewind's");

    // A restart's full rescan, after the filesystem coarsened the mtimes.
    let controller = LinkRuntimeController::new(a.state.clone());
    controller.stop(&a.local_path()).await;
    let coarsen = |rel: &str, step: u128| {
        let path = a.path(rel);
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let nanos = mtime.duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let coarse = std::time::UNIX_EPOCH + Duration::from_nanos((nanos / step * step) as u64);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(coarse)).unwrap();
    };
    coarsen("report.txt", 1_000_000_000);
    coarsen("notes.txt", 100);
    controller.start(a.local_path(), GROUP.to_string()).unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(a.current_rows(), rows, "a coarser mtime made a restored file look edited");
    assert_eq!(a.own_deltas() - deltas_before, rewind_deltas, "no change beyond the rewind's");
    assert_eq!(contents(&a.tree()), before);
}

/// An edit made after the rewind was prepared, to a path it restores: the
/// chunk commits nothing, the run ends having changed nothing (executing
/// again needs a new preview), and the edit is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_edit_stops_the_rewind_and_is_kept() {
    let a = Device::alone("device-a");
    original(&a).await;
    let target = target_now().await;
    mass_edit(&a).await;
    let (request, _) = a.approve_when(target, |n| n >= 5).await;
    let prepared = prepare_rewind(a.state.clone(), request).await.unwrap();

    a.write("report.txt", "edited while the rewind was prepared");
    wait_until_with_context(
        || a.current_rows().get("report.txt").is_some_and(|(seq, _)| *seq >= 3),
        Duration::from_secs(30),
        || format!("the edit was never captured: {:?}", a.current_rows()),
    )
    .await;
    let deltas_before = a.own_deltas();

    let ended = execute_rewind(a.state.clone(), prepared, None).await;

    assert_eq!(ended, Some(RewindRunState::Failed));
    let run = a.latest_run();
    assert_eq!(run.failure_kind, Some(RewindFailureKind::FolderChanged));
    assert_eq!(run.message(), "The folder changed; wait for sync to settle, then preview again.");
    assert_eq!(a.own_deltas(), deltas_before, "zero mutations");
    assert!(!a.state.replica_coordinator.retention_paused(GROUP));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        std::fs::read_to_string(a.path("report.txt")).unwrap(),
        "edited while the rewind was prepared",
        "the rewind never wins over a concurrent edit"
    );
}

/// The number of files that makes a plan two chunks.
const TWO_CHUNKS: usize = 1024 + 6;

/// Creates `TWO_CHUNKS` files, then deletes them all after the target: a
/// rewind restores them in two chunks.
async fn mass_deleted(a: &Device) -> i64 {
    for i in 0..TWO_CHUNKS {
        a.write(&format!("many/f{i:05}.txt"), &format!("file {i}"));
    }
    wait_until_with_context(
        || a.current_rows().keys().filter(|path| path.starts_with("many/")).count() == TWO_CHUNKS,
        Duration::from_secs(120),
        || format!("only {} files indexed", a.current_rows().len()),
    )
    .await;
    let target = target_now().await;
    std::fs::remove_dir_all(a.path("many")).unwrap();
    let live_files = || -> Vec<String> {
        a.current_rows()
            .into_iter()
            .filter(|(path, (_, deleted))| path.starts_with("many/") && !deleted)
            .map(|(path, _)| path)
            .collect()
    };
    wait_until_with_context(
        || live_files().is_empty(),
        Duration::from_secs(120),
        || format!("still live after the mass delete: {:?}", live_files()),
    )
    .await;
    target
}

/// A crash between two chunks: the first chunk's changes stay as ordinary
/// changes, the run needs a new preview (it is never resumed), nothing is
/// authored twice, and a fresh preview from the current state finishes the
/// job.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_between_chunks_needs_a_new_preview_and_authors_nothing_twice() {
    let a = Device::alone("device-a");
    let target = mass_deleted(&a).await;
    let (request, total) = a.approve_when(target, |n| n >= TWO_CHUNKS as u64).await;
    let prepared = prepare_rewind(a.state.clone(), request).await.unwrap();
    assert_eq!(a.latest_run().chunks_total, 2);

    let crash: RewindHook = Arc::new(|point| point != RewindPoint::BeforeChunk(1));
    assert_eq!(execute_rewind(a.state.clone(), prepared, Some(crash)).await, None);
    let mid = a.latest_run();
    assert_eq!((mid.state, mid.chunks_done), (RewindRunState::Committing, 1));
    let deltas_after_first = a.own_deltas();

    // The restart's settle, from the row alone.
    let runs = a.state.replica_coordinator.rewind_run_repository();
    assert_eq!(runs.interrupt_unfinished_runs().unwrap(), 1);
    let settled = a.latest_run();
    assert_eq!(settled.state, RewindRunState::NeedsReplan);
    assert_eq!(
        settled.message(),
        "Rewind was interrupted. Review the current state and preview again."
    );
    assert_eq!(a.own_deltas(), deltas_after_first, "settling authors nothing");

    // What the first chunk restored is now the current state; the rest is
    // what a new preview finds.
    let rest = a.approve(target, total - 1024).await;
    assert_eq!(a.rewind(rest).await, RewindRunState::Done);
    wait_until_with_context(
        || a.tree().len() == TWO_CHUNKS,
        Duration::from_secs(120),
        || format!("{} of {TWO_CHUNKS} files back", a.tree().len()),
    )
    .await;
    a.approve(target, 0).await;
}

/// An edit between two chunks, to a path the second chunk restores: the
/// second chunk commits nothing, the run needs a new preview (the first
/// chunk's changes stay), and the edit is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_edit_between_chunks_stops_the_run_as_needing_a_new_preview() {
    let a = Arc::new(Device::alone("device-a"));
    let target = mass_deleted(&a).await;
    let (request, _) = a.approve_when(target, |n| n >= TWO_CHUNKS as u64).await;
    let prepared = prepare_rewind(a.state.clone(), request).await.unwrap();

    // The last path in restore order is in the second chunk.
    let edited = format!("many/f{:05}.txt", TWO_CHUNKS - 1);
    let device = a.clone();
    let path = edited.clone();
    let edit_between: RewindHook = Arc::new(move |point| {
        if point == RewindPoint::BeforeChunk(1) {
            device.write(&path, "a person wrote this meanwhile");
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while !device.current_rows().get(&path).is_some_and(|(_, deleted)| !deleted) {
                assert!(std::time::Instant::now() < deadline, "the edit was never captured");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        true
    });
    // The hook blocks while the watcher captures the edit; it runs on the
    // test's own thread, not a runtime worker.
    let ended = execute_rewind(a.state.clone(), prepared, Some(edit_between)).await;

    assert_eq!(ended, Some(RewindRunState::NeedsReplan));
    let run = a.latest_run();
    assert_eq!(run.chunks_done, 1);
    assert_eq!(run.failure_kind, None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        std::fs::read_to_string(a.path(&edited)).unwrap(),
        "a person wrote this meanwhile",
        "the rewind never wins over a concurrent edit"
    );
}

/// Block GC between preparation and the first chunk: the historical rows
/// the plan restores keep their blocks live, so nothing the rewind needs is
/// swept and it completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn block_gc_between_preparation_and_commit_keeps_what_the_rewind_restores() {
    let a = Device::alone("device-a");
    let before = original(&a).await;
    let target = target_now().await;
    mass_edit(&a).await;
    let (request, _) = a.approve_when(target, |n| n >= 5).await;
    let prepared = prepare_rewind(a.state.clone(), request).await.unwrap();

    // The product's live set, swept with the fresh-block grace window
    // already past, so only liveness protects anything.
    let live = a
        .state
        .replica_coordinator
        .materialization_state_repository()
        .live_block_hashes_including_native_heads()
        .unwrap();
    let future = std::time::SystemTime::now() + Duration::from_secs(3600);
    a.state.block_store.sweep(&live, future, false).unwrap();

    assert_eq!(execute_rewind(a.state.clone(), prepared, None).await, Some(RewindRunState::Done));
    a.wait_tree(&before, "the rewind never materialized").await;
}

/// A block the rewind restores disappears after it was verified (local
/// corruption, an external deletion): the chunk is not committed and the
/// content is not fetched under the commit -- the run ends having changed
/// nothing, retryable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_block_missing_at_commit_fails_closed_with_nothing_changed() {
    let a = Device::alone("device-a");
    original(&a).await;
    let target = target_now().await;
    mass_edit(&a).await;
    let (request, _) = a.approve_when(target, |n| n >= 5).await;
    let prepared = prepare_rewind(a.state.clone(), request).await.unwrap();

    let index = a.state.replica_coordinator.file_index_repository();
    let seq = a
        .state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(GROUP, "notes.txt")
        .unwrap()
        .into_iter()
        .filter(|v| !v.deleted)
        .map(|v| v.version_seq)
        .max()
        .unwrap();
    let version = index.get_version(GROUP, "notes.txt", seq).unwrap().unwrap();
    for block in &version.blocks {
        a.state.block_store.delete(&hex::encode(&block.hash)).unwrap();
    }
    let rows = a.current_rows();
    let deltas_before = a.own_deltas();

    let ended = execute_rewind(a.state.clone(), prepared, None).await;

    assert_eq!(ended, Some(RewindRunState::Failed));
    assert_eq!(a.latest_run().failure_kind, Some(RewindFailureKind::Transient));
    assert_eq!(a.own_deltas(), deltas_before, "zero mutations");
    assert_eq!(a.current_rows(), rows);
}
