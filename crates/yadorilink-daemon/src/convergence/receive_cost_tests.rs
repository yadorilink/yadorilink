#![cfg(test)]

//! MEASUREMENT GUARD, not a semantic test: how many SQLite write
//! transactions receiving one file costs on a running link, driven by the
//! real obligation engine. Every outer write transaction is one WAL commit,
//! so this is the per-path durability cost the receive path pays before any
//! file byte is counted.
//!
//! The assertion is an upper bound with room to spare, so a later change
//! that folds more of these commits together keeps passing; the exact count
//! is printed for whoever is measuring. Whether a received file is correct
//! is the business of the semantic tests, never of this one.
//!
//! Content-carrying versions have their blocks put into the local store and
//! recorded as this group's (`record_block_provenance`), as a completed
//! fetch leaves them. A block that is only physically present does not count
//! as the group's, so without that record the eager lane asks the fixture's
//! peer for it, and that peer never answers: the attempt then waits out the
//! bulk fetch timeout instead of projecting.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use yadorilink_filesystem_sync::watcher::{
    FolderWatchSource, FsChangeEvent, RealFolderWatchSource, SimulatedFolderWatchSource,
};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::BlockHash;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

pub(super) const GROUP: &str = "receive-cost-group";

/// The outer write transactions one received path costs, exactly: the metadata
/// apply, the pre-write commit that opens the content write, the durable record
/// of the temp file the write will create (so a crash cannot orphan it), and
/// one commit that publishes the proof, stamps `Present`, clears the intent and
/// completes the obligation. Receiving a file took 13 before its pre-write
/// steps were folded into one transaction (taking 4 away) and its plans
/// stopped opening write transactions that record nothing (4 more), and the
/// proof, its second publication and the completion were folded into one
/// commit; the temp-file record is the fourth. The guard runs against a quiet
/// watcher so the count is this exact number and fails if any change adds to
/// it; do not raise it to absorb a timing-dependent extra, find that extra.
///
/// The number lives in `.github/checks/perf-baseline.json`, where changing it needs a
/// recorded reason (see `.github/checks/check-perf-baseline.py`).
pub(super) fn max_write_transactions_per_path() -> u64 {
    perf_baseline()["write_transactions_per_received_path_max"].as_u64().expect("baseline entry")
}

/// The operation-count baseline shared with the storage-level durability guard.
pub(super) fn perf_baseline() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../../.github/checks/perf-baseline.json"))
        .expect("perf-baseline.json parses")
}

pub(super) struct Fixture {
    pub(super) state: Arc<DaemonState>,
    pub(super) root: std::path::PathBuf,
    _root_dir: crate::test_support::sync_stack_fixture::ReleasingDir,
    _database_dir: Option<tempfile::TempDir>,
    /// The executor the peer session projects through: the seam tests
    /// set free space and headroom on.
    pub(super) executor: Arc<crate::local_convergence::LocalConvergenceExecutor>,
    /// Keeps a quiet fixture's simulated event channel open.
    _quiet_events: Option<tokio::sync::mpsc::Sender<FsChangeEvent>>,
}

/// `on_disk`: the replica database is a file (WAL, `synchronous = FULL`,
/// as in the daemon) instead of in memory, so its commits really sync.
pub(super) async fn fixture(on_disk: bool) -> Fixture {
    fixture_watching(on_disk, Arc::new(RealFolderWatchSource), None).await
}

/// [`fixture`] whose folder watcher is simulated and never sees an event: the
/// OS's echo of the daemon's own writes (a dirty-path record, written when the
/// debounced event lands, which on a slow disk is inside the window being
/// counted) is the watcher's cost, not the receive's, and would make the count
/// depend on timing.
pub(super) async fn quiet_fixture(on_disk: bool) -> Fixture {
    let (source, events) = SimulatedFolderWatchSource::new(16);
    fixture_watching(on_disk, Arc::new(source), Some(events)).await
}

async fn fixture_watching(
    on_disk: bool,
    source: Arc<dyn FolderWatchSource>,
    quiet_events: Option<tokio::sync::mpsc::Sender<FsChangeEvent>>,
) -> Fixture {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();
    let local_path = root.to_string_lossy().into_owned();
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let database_dir = on_disk.then(|| tempfile::tempdir().unwrap());
    let replica_coordinator = Arc::new(match &database_dir {
        Some(dir) => ReplicaCoordinator::open(dir.path().join("replica.db")).unwrap(),
        None => ReplicaCoordinator::open_in_memory().unwrap(),
    });
    // No maintenance coordinator: projection runs only when the test drives
    // it, so nothing else writes while a path is being counted.
    let state = DaemonState::build("device-local".into(), replica_coordinator, store);
    state.set_device_signing_key(SigningKey::from_bytes(&[7u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_group_id| Ok([0u8; 32])));
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    LinkRuntimeController::new(state.clone())
        .start_with_source(local_path, GROUP.to_string(), source)
        .expect("the watch must start");
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.replica_coordinator.wait_group_ready(GROUP),
    )
    .await
    .expect("the initial scan must finish")
    .expect("the initial scan must succeed");
    let executor = register_peer_session(&state).await;
    let _root_dir = crate::test_support::sync_stack_fixture::ReleasingDir::new(root_dir, &state);
    Fixture {
        state,
        root,
        _root_dir,
        _database_dir: database_dir,
        executor,
        _quiet_events: quiet_events,
    }
}

/// A session to a peer that never answers: projection has a driver, and
/// every block a path needs must already be this group's.
async fn register_peer_session(
    state: &Arc<DaemonState>,
) -> Arc<crate::local_convergence::LocalConvergenceExecutor> {
    let deps = crate::peer_orchestrator::peer_sync_session_deps(state);
    let (transports, _peer_transports) =
        crate::test_support::session_transports_pair("device-local", "device-peer").await;
    let peer_store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store.clone(),
    );
    let session = PeerSyncSession::over_substrate(
        "device-local".to_string(),
        "device-peer".to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        peer_store,
        vec![GROUP.to_string()],
        transports,
        deps,
    );
    let executor = state.local_convergence();
    state.peers.register_session("device-peer".to_string(), session, executor.clone());
    executor
}

impl Fixture {
    /// The replica database file, for a fixture built `on_disk`.
    pub(super) fn database_path(&self) -> Option<std::path::PathBuf> {
        self._database_dir.as_ref().map(|dir| dir.path().join("replica.db"))
    }

    /// Stores `content` as this group's blocks and returns the version a
    /// peer would name for it.
    pub(super) fn content_version(&self, content: &[u8], mtime: i64) -> FileVersion {
        self.content_version_with_mode(content, mtime, None)
    }

    /// [`Self::content_version`] naming a Unix mode, so that the file a pass
    /// writes for it is exactly the version and a watcher looking at it has
    /// nothing to author.
    pub(super) fn content_version_with_mode(
        &self,
        content: &[u8],
        mtime: i64,
        unix_mode: Option<u32>,
    ) -> FileVersion {
        let block_size = yadorilink_local_storage::chunker::DEFAULT_BLOCK_SIZE;
        let mut blocks = Vec::new();
        for chunk in content.chunks(block_size) {
            let hash = hex::decode(self.state.block_store.put(chunk).unwrap()).unwrap();
            self.state
                .replica_coordinator
                .record_block_provenance(GROUP, std::slice::from_ref(&hash))
                .unwrap();
            blocks.push(VersionBlock { hash: BlockHash(hash), size: chunk.len() as u32 });
        }
        FileVersion::new(
            blocks,
            content.len() as u64,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    }

    pub(super) fn admit(&self, name: &str, version: &FileVersion) {
        crate::test_support::remote_admission_fixture::admit_remote(
            &self.state.replica_coordinator,
            GROUP,
            "device-peer",
            vec![crate::test_support::remote_admission_fixture::put(
                name,
                version.version_hash,
                vec![],
            )],
            std::slice::from_ref(version),
        );
    }

    pub(super) fn read(&self, name: &str) -> Option<Vec<u8>> {
        std::fs::read(self.root.join(name)).ok()
    }

    /// Admits `name` and drives the engine until its bytes are on disk.
    /// Returns the write transactions the projection took: storing the
    /// blocks and admitting the delta are the delivery's, not counted.
    async fn receive(
        &self,
        engine: &crate::convergence::engine::ConvergenceEngine,
        name: &str,
        content: &[u8],
        mtime: i64,
    ) -> u64 {
        let version = self.content_version(content, mtime);
        self.admit(name, &version);
        let db = self.state.replica_coordinator.database();
        let before = db.write_transaction_count();
        mark(&format!("begin {name}"));
        for _ in 0..50 {
            tokio::time::timeout(
                std::time::Duration::from_secs(20),
                crate::convergence::engine::drive_obligations_once_for_test(engine, 128, 256),
            )
            .await
            .expect("one engine pass must not stall");
            if self.read(name).as_deref() == Some(content) {
                mark(&format!("end {name}"));
                return db.write_transaction_count() - before;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("{name} was not projected");
    }
}

pub(super) fn content_of(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add((i % 251) as u8)).collect()
}

/// Write transactions per received path for an empty file, a one-block file
/// and a multi-block file, one path at a time after a warm-up path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn measurement_guard_write_transactions_per_received_path() {
    let f = quiet_fixture(false).await;
    let engine = crate::convergence::engine::ConvergenceEngine::new(f.state.clone());
    // One-time per-group work is not what is being counted.
    f.receive(&engine, "warm.txt", b"warm-up", 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    const PATHS: u64 = 4;
    let block = yadorilink_local_storage::chunker::DEFAULT_BLOCK_SIZE;
    let shapes: [(&str, usize); 3] =
        [("empty", 0), ("one-block", 4096), ("multi-block", 2 * block + 1000)];
    let mut mtime = 10;
    let mut measured = Vec::new();
    for (shape, len) in shapes {
        let mut spent = 0;
        for i in 0..PATHS {
            mtime += 1;
            let content = content_of(len, (i as u8).wrapping_add(len as u8));
            spent += f.receive(&engine, &format!("{shape}-{i}.bin"), &content, mtime).await;
        }
        let per_path = spent as f64 / PATHS as f64;
        eprintln!("MEASURE receive {shape}: {per_path} write transactions per path");
        measured.push((shape, per_path));
    }
    for (shape, per_path) in measured {
        assert!(
            per_path <= max_write_transactions_per_path() as f64,
            "receiving one {shape} file took {per_path} write transactions, more than the \
             {} this guard allows",
            max_write_transactions_per_path()
        );
    }
}

/// Appends `line` to the file `$FSYNC_LOG` names, when it is set: an
/// fsync-logging shim loaded into the test process writes one line per sync
/// call there, and these marks bracket each projection being measured.
fn mark(line: &str) {
    use std::io::Write as _;
    if let Some(log) = std::env::var_os("FSYNC_LOG") {
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(log).unwrap();
        writeln!(file, "MARK {line}").unwrap();
    }
}

/// The same receives against an on-disk replica database, timed: files per
/// second, and (under the shim) the sync calls each received path costs.
/// Only an observation on whatever machine runs it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement; run explicitly"]
async fn measurement_on_disk_receive_cost() {
    let f = fixture(true).await;
    let engine = crate::convergence::engine::ConvergenceEngine::new(f.state.clone());
    f.receive(&engine, "warm.txt", b"warm-up", 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    const PATHS: u64 = 40;
    let block = yadorilink_local_storage::chunker::DEFAULT_BLOCK_SIZE;
    let shapes: [(&str, usize); 3] =
        [("empty", 0), ("one-block", 4096), ("multi-block", 2 * block + 1000)];
    let mut mtime = 10;
    for (shape, len) in shapes {
        let mut spent = 0;
        let mut busy = std::time::Duration::ZERO;
        for i in 0..PATHS {
            mtime += 1;
            let content = content_of(len, (i as u8).wrapping_add(len as u8));
            let started = std::time::Instant::now();
            spent += f.receive(&engine, &format!("{shape}-{i}.bin"), &content, mtime).await;
            busy += started.elapsed();
        }
        eprintln!(
            "MEASURE on-disk {shape}: {} write transactions per path, {:.1} files/s",
            spent as f64 / PATHS as f64,
            PATHS as f64 / busy.as_secs_f64()
        );
    }
}

/// Admits `count` one-block files at once and drives the real obligation
/// engine, in its default windows, until every one is on disk. Returns the
/// write transactions the projections took, by call site, and in total.
///
/// Process-wide gate counters are reset first, so this is only meaningful
/// when nothing else in the process writes: run it alone.
async fn receive_window_by_site(count: usize, reset: bool) -> (Vec<(String, u64)>, u64, u64) {
    let f = fixture(false).await;
    let engine = crate::convergence::engine::ConvergenceEngine::new(f.state.clone());
    f.receive(&engine, "warm.txt", b"warm-up", 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let mut contents = Vec::new();
    for i in 0..count {
        let name = format!("w{i:04}.bin");
        let content = content_of(3000 + i % 7, (i % 251) as u8);
        let version = f.content_version(&content, 10 + i as i64);
        f.admit(&name, &version);
        contents.push((name, content));
    }
    if reset {
        yadorilink_sqlite_runtime::writer_gate_stats::reset();
    }
    let database = f.state.replica_coordinator.database();
    let before = database.write_transaction_count();
    for _ in 0..(count * 2 + 50) {
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            crate::convergence::engine::drive_obligations_once_for_test(&engine, 128, 256),
        )
        .await
        .expect("one engine pass must not stall");
        if contents.iter().all(|(name, content)| f.read(name).as_deref() == Some(content)) {
            break;
        }
    }
    for (name, content) in &contents {
        assert_eq!(f.read(name).as_deref(), Some(content.as_slice()), "{name} was not projected");
    }
    let total = database.write_transaction_count() - before;
    let sites = yadorilink_sqlite_runtime::writer_gate_stats::hold_site_stats()
        .into_iter()
        .map(|(site, calls, _)| (site, calls))
        .collect();
    let gate_total = yadorilink_sqlite_runtime::writer_gate_stats::stats().0;
    (sites, total, gate_total)
}

/// A burst of received files, projected by the real engine in its default
/// windows with the files of a window written concurrently, all arrive and
/// cost the same bounded number of write transactions each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_of_received_files_arrives_whole_through_the_engine() {
    const COUNT: usize = 24;
    let (_sites, total, _) = receive_window_by_site(COUNT, false).await;
    assert!(
        total <= max_write_transactions_per_path() * COUNT as u64,
        "{total} write transactions for {COUNT} files"
    );
}

/// Every write transaction a window of received files takes is attributed to
/// a call site, and the sites add up to the total.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement; process-wide counters, run alone"]
async fn measurement_every_write_transaction_of_a_received_window_has_a_site() {
    let count: usize =
        std::env::var("RECEIVE_FILES").ok().and_then(|n| n.parse().ok()).unwrap_or(500);
    let (sites, total, gate_total) = receive_window_by_site(count, true).await;
    let attributed: u64 = sites.iter().map(|(_, calls)| calls).sum();
    for (site, calls) in &sites {
        eprintln!(
            "MEASURE site {site}: {:.2} write transactions per file",
            *calls as f64 / count as f64
        );
    }
    eprintln!(
        "MEASURE total {:.2} per file; attributed {:.2}; gate total {:.2}",
        total as f64 / count as f64,
        attributed as f64 / count as f64,
        gate_total as f64 / count as f64
    );
    assert_eq!(attributed, total, "some write transactions have no site");
    assert_eq!(gate_total, total);
}
