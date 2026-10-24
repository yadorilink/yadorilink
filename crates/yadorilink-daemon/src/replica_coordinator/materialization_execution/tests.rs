#![cfg(test)]

use super::*;
use std::path::Path;
use yadorilink_filesystem_sync::block_liveness::BlockLivenessGate;
use yadorilink_filesystem_sync::materialization_eviction::{evict_file, MaterializationContext};
use yadorilink_filesystem_sync::materialization_repair::{
    repair_interrupted_materializations, RepairMode,
};
use yadorilink_local_storage::{BlockStore as _, SegmentBlockStore};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, MaterializationState};
use yadorilink_replica_engine::custody::{CustodyStamp, FullReplicaCustody};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;

/// A custody oracle that never confirms anything. With `REMOTE_CUSTODY_LEASES_SUPPORTED` on,
/// `verify_reclaim_custody` consults it (on Windows the platform gate answers `None` first), so a
/// test using this stub shows that an unconfirmed custody never authorizes a block purge.
struct NeverConfirms;

impl FullReplicaCustody for NeverConfirms {
    fn confirm_exact_version(
        &self,
        _: &str,
        _: &str,
        _: &VersionHash,
        _: &[yadorilink_replica_domain::file::VersionBlock],
    ) -> Option<CustodyStamp> {
        None
    }

    fn confirmation_still_valid(
        &self,
        _: &str,
        _: &str,
        _: &VersionHash,
        _: &CustodyStamp,
    ) -> bool {
        false
    }
}

/// A custody oracle that panics if it is ever consulted: proves an
/// eviction never asks for custody, not merely that it ignored the answer.
#[cfg(not(windows))]
struct PanicsIfConsulted;

#[cfg(not(windows))]
impl FullReplicaCustody for PanicsIfConsulted {
    fn confirm_exact_version(
        &self,
        _: &str,
        _: &str,
        _: &VersionHash,
        _: &[yadorilink_replica_domain::file::VersionBlock],
    ) -> Option<CustodyStamp> {
        panic!("custody must not be consulted for this eviction");
    }

    fn confirmation_still_valid(
        &self,
        _: &str,
        _: &str,
        _: &VersionHash,
        _: &CustodyStamp,
    ) -> bool {
        panic!("custody must not be consulted for this eviction");
    }
}

/// On an on-demand (non-full-replica) device, an evicted file's
/// content-addressed blocks are NEVER purged from the local block
/// store unless the custody oracle confirms: `NeverConfirms` is consulted and refuses, so
/// `verify_reclaim_custody` yields nothing and no block is purged. This pins the fail-closed
/// invariant (nothing is purged without a durable custody lease).
///
/// `#[cfg(not(windows))]`: this is the only test in this module that
/// drives a `Present` row all the way through `evict_file` to a
/// successful placeholder write, so it is the only one that actually
/// reaches `materialization_eviction::evict_to_placeholder`'s Windows
/// arm (every other eviction test here either rejects earlier --
/// diverged-on-disk -- or, like the cross-group tests below,
/// leaves its row at the schema-v25 `Remote` default, which bails
/// out of `evict_file` before `evict_to_placeholder` is ever called).
/// On Windows that arm does not locally write a placeholder at all --
/// by design (see `evict_to_placeholder`'s own doc comment) it asks
/// the real `cfapi-host.exe` process to confirm native dehydration over
/// a named pipe (`placeholder_dehydrate_windows::
/// dehydrate_via_cfapi_host_blocking`), and there is no test-support
/// seam to fake that confirmation the way `create_or_defer_
/// placeholder`'s `set_test_force_deferred_placeholder_for_path` fakes
/// the Windows-deferred *creation* path elsewhere in this module. A
/// plain `cargo test` binary never starts that host process, so on a
/// real Windows runner this call fails fast with a pipe-connect error
/// (`EvictionOutcomeAmbiguous`) regardless of whether the row has a
/// recorded placeholder identity -- recording one (as a real Windows
/// CfAPI-hydrated row always would) only changes which error `evict_
/// file` returns, not whether this test can succeed without that
/// external process. This is a test-infrastructure gap, not a
/// production bug: the fail-closed behavior itself is exactly what a
/// real Windows host is supposed to do. Scoping the test out mirrors
/// this same module's `repair_recreates_a_symlink_after_a_simulated_
/// crash_before_the_write`, `#[cfg(unix)]`-scoped for the same reason
/// (a real write this platform cannot exercise without OS-specific
/// support this test harness does not provide).
#[cfg(not(windows))]
#[test]
fn evict_on_an_on_demand_device_frees_the_file_but_never_purges_its_blocks_without_confirmed_custody(
) {
    let _exclusion =
        yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root.path());
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"content nobody else has confirmed custody of";
    let record = store_and_record(&store, "a.bin", content);
    let hash = hex::encode(&record.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-a", &record, &permit);
    std::fs::write(root.path().join("a.bin"), content).unwrap();

    let outcome = evict_file(
        MaterializationContext {
            state: &state,
            liveness_gate: &BlockLivenessGate::default(),
            store: &store,
            root: root.path(),
            permit: &permit,
        },
        "group-a",
        "a.bin",
        false, // on-demand device, not a complete copy
        &NeverConfirms,
    )
    .unwrap();

    assert!(outcome.dehydrated, "the working-tree copy is still freed");
    assert!(outcome.blocks_retained, "unconfirmed custody must never authorize a block purge");
    assert!(store.exists(&hash).unwrap(), "the block must survive on disk, unconfirmed");
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state("group-a", "a.bin")
            .unwrap(),
        Some(MaterializationState::Remote)
    );
    // The working-tree object itself must actually be gone -- not merely
    // have its index row updated: a `Remote` row has no local object, and no
    // stand-in is written in its place.
    assert!(
        std::fs::symlink_metadata(root.path().join("a.bin")).is_err(),
        "the evicted object must no longer stand in the user tree"
    );
}

/// Eviction removes the sync root's bytes (Windows: dehydrates the placeholder), so a sync root
/// whose volume is not known durable is left exactly as it was: nothing dehydrated, no block
/// reclaimed, the row still `Present`.
#[test]
fn evict_on_a_sync_root_volume_that_is_not_known_durable_touches_nothing() {
    let _exclusion =
        yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root.path());
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"content on a volume that is not known durable";
    let record = store_and_record(&store, "a.bin", content);
    let hash = hex::encode(&record.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-a", &record, &permit);
    std::fs::write(root.path().join("a.bin"), content).unwrap();
    let sync_root = root.path().to_path_buf();
    let _verdict =
        yadorilink_filesystem_sync::materialization_eviction::set_volume_verdict_for_test(
            move |dir| dir != Some(sync_root.as_path()),
        );

    let outcome = evict_file(
        MaterializationContext {
            state: &state,
            liveness_gate: &BlockLivenessGate::default(),
            store: &store,
            root: root.path(),
            permit: &permit,
        },
        "group-a",
        "a.bin",
        false,
        &NeverConfirms,
    )
    .unwrap();

    assert!(!outcome.dehydrated, "no bytes may be removed without a positive verdict");
    assert!(outcome.blocks_retained);
    assert!(store.exists(&hash).unwrap());
    assert_eq!(std::fs::read(root.path().join("a.bin")).unwrap(), content);
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state("group-a", "a.bin")
            .unwrap(),
        Some(MaterializationState::Present)
    );
}

/// Confirms every version, and while doing so (under the path lock, like the real custody
/// request) starts a block-reference writer that holds its write while it waits for that lock:
/// what a local-change flush does when it races an eviction.
#[cfg(not(windows))]
struct ConfirmsWithAWriterWaitingOnThePathLock {
    gate: std::sync::Arc<BlockLivenessGate>,
    lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    writer: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[cfg(not(windows))]
impl FullReplicaCustody for ConfirmsWithAWriterWaitingOnThePathLock {
    fn confirm_exact_version(
        &self,
        _: &str,
        _: &str,
        _: &VersionHash,
        _: &[yadorilink_replica_domain::file::VersionBlock],
    ) -> Option<CustodyStamp> {
        let (holding, held) = std::sync::mpsc::channel();
        let (gate, lock) = (self.gate.clone(), self.lock.clone());
        let writer = std::thread::spawn(move || {
            let _write = gate.begin_reference_write();
            holding.send(()).unwrap();
            drop(lock.blocking_lock());
        });
        held.recv().unwrap();
        *self.writer.lock().unwrap() = Some(writer);
        Some(CustodyStamp::new("full-peer".into(), 1))
    }

    fn confirmation_still_valid(
        &self,
        _: &str,
        _: &str,
        _: &VersionHash,
        _: &CustodyStamp,
    ) -> bool {
        true
    }
}

/// A writer that holds its block-reference write while it waits for the path lock must not
/// deadlock with the eviction that holds the lock and wants the writers gone: the eviction lets
/// the lock go, the writer finishes, and the blocks are then reclaimed.
#[cfg(not(windows))]
#[test]
fn an_eviction_does_not_deadlock_with_a_writer_waiting_for_the_path_lock() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root.path());
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"content an eviction must not deadlock over";
    let record = store_and_record(&store, "a.bin", content);
    let hash = hex::encode(&record.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-a", &record, &permit);
    std::fs::write(root.path().join("a.bin"), content).unwrap();
    let gate = std::sync::Arc::new(BlockLivenessGate::default());
    let custody = ConfirmsWithAWriterWaitingOnThePathLock {
        gate: gate.clone(),
        lock: state.path_lock_registry().path_lock("group-a", "a.bin"),
        writer: std::sync::Mutex::new(None),
    };

    let (done, finished) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let _exclusion =
                yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test();
            let outcome = evict_file(
                MaterializationContext {
                    state: &state,
                    liveness_gate: &gate,
                    store: &store,
                    root: root.path(),
                    permit: &permit,
                },
                "group-a",
                "a.bin",
                false,
                &custody,
            )
            .unwrap();
            done.send(outcome).unwrap();
        });
        let outcome = finished
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the eviction deadlocked with a writer waiting for the path lock");
        assert!(outcome.dehydrated);
        assert_eq!(outcome.blocks_reclaimed, 1);
    });
    custody.writer.lock().unwrap().take().unwrap().join().unwrap();
    assert!(!store.exists(&hash).unwrap());
}

/// A full replica is the group's durable holder: evicting a file there frees
/// the working-tree copy but never reclaims a block, and never even asks
/// whether another replica holds the version (`PanicsIfConsulted`).
/// `#[cfg(not(windows))]` for the same reason as the on-demand test above:
/// it drives a successful placeholder write.
#[cfg(not(windows))]
#[test]
fn evict_on_a_full_replica_keeps_every_block_without_consulting_custody() {
    let _exclusion =
        yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root.path());
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"the durable holder's copy of this version";
    let record = store_and_record(&store, "a.bin", content);
    let hash = hex::encode(&record.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-a", &record, &permit);
    std::fs::write(root.path().join("a.bin"), content).unwrap();

    let outcome = evict_file(
        MaterializationContext {
            state: &state,
            liveness_gate: &BlockLivenessGate::default(),
            store: &store,
            root: root.path(),
            permit: &permit,
        },
        "group-a",
        "a.bin",
        true, // complete copy
        &PanicsIfConsulted,
    )
    .unwrap();

    assert!(outcome.dehydrated, "the working-tree copy is freed");
    assert!(outcome.blocks_retained, "a complete copy never reclaims a block");
    assert_eq!((outcome.blocks_reclaimed, outcome.bytes_reclaimed), (0, 0));
    assert!(store.exists(&hash).unwrap(), "the block must stay in the block store");
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state("group-a", "a.bin")
            .unwrap(),
        Some(MaterializationState::Remote)
    );
}

/// Hydrated `a.bin` on a linked root, plus a probe recording, each time
/// eviction asks for custody, whether the path lock is held and what the row
/// says. Custody must be asked for under the lock the custody reconciler
/// needs, before the row leaves `Present`.
/// (path lock held, the row's state) when custody was asked for.
#[cfg(not(windows))]
type CustodyAsk = (bool, Option<MaterializationState>);

#[cfg(not(windows))]
struct CustodyProbeFixture {
    state: std::rc::Rc<ReplicaCoordinator>,
    root: tempfile::TempDir,
    store: SegmentBlockStore,
    _store_dir: tempfile::TempDir,
    seen: std::rc::Rc<std::cell::RefCell<Vec<CustodyAsk>>>,
    _probe: yadorilink_filesystem_sync::materialization_eviction::CustodyProbeGuardForTest,
}

#[cfg(not(windows))]
impl CustodyProbeFixture {
    fn new() -> Self {
        let state = std::rc::Rc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-a", root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let content = b"content whose custody is confirmed under the lock";
        let record = store_and_record(&store, "a.bin", content);
        upsert_hydrated_file(&state, "group-a", &record, &RootCommitPermit::for_tests());
        std::fs::write(root.path().join("a.bin"), content).unwrap();
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let probe =
            yadorilink_filesystem_sync::materialization_eviction::set_custody_probe_for_test({
                let state = state.clone();
                let seen = seen.clone();
                move || {
                    let locked = state.path_lock("group-a", "a.bin").try_lock().is_err();
                    let row = state
                        .materialization_state_repository()
                        .get_materialization_state("group-a", "a.bin")
                        .unwrap();
                    seen.borrow_mut().push((locked, row));
                }
            });
        Self { state, root, store, _store_dir: store_dir, seen, _probe: probe }
    }

    fn evict(&self, is_full_replica: bool, custody: &dyn FullReplicaCustody) {
        evict_file(
            MaterializationContext {
                state: &*self.state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &self.store,
                root: self.root.path(),
                permit: &RootCommitPermit::for_tests(),
            },
            "group-a",
            "a.bin",
            is_full_replica,
            custody,
        )
        .unwrap();
    }
}

#[cfg(not(windows))]
#[test]
fn custody_is_asked_for_under_the_path_lock_before_the_row_leaves_present() {
    let fixture = CustodyProbeFixture::new();
    fixture.evict(false, &NeverConfirms);
    assert_eq!(*fixture.seen.borrow(), vec![(true, Some(MaterializationState::Present))]);
}

/// A path that fails revalidation never reaches the custody confirmation, so
/// no hold is committed for an eviction that cannot proceed.
#[cfg(not(windows))]
#[test]
fn a_dirty_path_never_asks_for_custody() {
    let fixture = CustodyProbeFixture::new();
    let permit = RootCommitPermit::for_tests();
    fixture
        .state
        .dirty_path_repository()
        .record_dirty_path("group-a", "a.bin", "created_or_modified", 1, &permit)
        .unwrap();
    fixture.evict(false, &NeverConfirms);
    assert!(fixture.seen.borrow().is_empty());
}

#[cfg(not(windows))]
#[test]
fn a_full_replica_never_asks_for_custody() {
    let fixture = CustodyProbeFixture::new();
    fixture.evict(true, &PanicsIfConsulted);
    assert!(fixture.seen.borrow().is_empty());
}

/// Content that already diverged from the indexed version
/// BEFORE `evict_file` is even called (an unsynced local edit landed
/// sometime after the last index write, or any other source of
/// pre-existing on-disk drift) must abort the eviction at its first
/// `disk_bytes_match_indexed_blocks` check, before any placeholder is
/// written -- never silently discard those bytes. This specifically exercises the FIRST divergence
/// check (`materialization_eviction.rs`'s pre-lock read); it does NOT
/// exercise the SECOND recheck performed after the path lock is
/// acquired (the one that specifically closes a race occurring DURING
/// this call itself) -- that revalidation has no direct test today.
#[test]
fn evict_aborts_when_disk_content_diverges_from_the_indexed_version() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root.path());
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let indexed_content = b"the version the index still believes is current";
    let record = store_and_record(&store, "a.bin", indexed_content);
    let hash = hex::encode(&record.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-a", &record, &permit);
    // A local edit landed on disk that the index does not know about
    // yet, before this call even begins.
    std::fs::write(root.path().join("a.bin"), b"a locally edited, unindexed replacement").unwrap();

    let outcome = evict_file(
        MaterializationContext {
            state: &state,
            liveness_gate: &BlockLivenessGate::default(),
            store: &store,
            root: root.path(),
            permit: &permit,
        },
        "group-a",
        "a.bin",
        false,
        &AlwaysConfirmed,
    )
    .unwrap();

    assert!(!outcome.dehydrated, "eviction must abort, not silently discard the local edit");
    assert!(outcome.blocks_retained);
    assert!(
        store.exists(&hash).unwrap(),
        "the aborted eviction must not touch the block store either"
    );
    assert_eq!(
        std::fs::read(root.path().join("a.bin")).unwrap(),
        b"a locally edited, unindexed replacement",
        "the unindexed local edit's bytes must survive untouched"
    );
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state("group-a", "a.bin")
            .unwrap(),
        Some(MaterializationState::Present),
        "the row must be left exactly as it was, not stuck mid-transition"
    );
}

/// Proves the impl above lets a real `Arc<ReplicaCoordinator>`
/// unsize-coerce to `Arc<dyn MaterializationExecutionPort>`, and that
/// calls through the coerced handle still dispatch correctly -- same
/// shape as `materialization_state::tests::
/// arc_replica_coordinator_coerces_to_port_trait` for the wider port
/// this one narrows.
#[test]
fn arc_replica_coordinator_coerces_to_execution_port_trait() {
    let coordinator: Arc<ReplicaCoordinator> =
        Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let port: Arc<dyn MaterializationExecutionPort> = coordinator;

    let _lock = port.path_lock("group-a", "path/a.txt");
    assert_eq!(port.get_file("group-a", "path/a.txt").unwrap(), None);
}

fn adopt_root(state: &ReplicaCoordinator, group_id: &str, root: &Path) {
    state.link_repository().add_link(&root.to_string_lossy(), group_id).unwrap();
    VerifiedRoot::open(root, group_id, state).unwrap();
}

/// Test-only convenience: `upsert_file` alone no longer leaves a fresh
/// row `Present` (schema v25 defaults `materialization_state` to
/// `Remote` instead -- see `SCHEMA_VERSION`'s own doc comment).
/// Every test in this module that upserts a record to simulate an
/// already-fully-materialized row (the overwhelming majority here --
/// this module is about repair/eviction over already-hydrated content)
/// must say so explicitly now, the same way production local-emission
/// callers do, rather than relying on a column default a genuinely
/// unhydrated row must NOT get.
fn upsert_hydrated_file(
    state: &ReplicaCoordinator,
    group_id: &str,
    record: &FileRecord,
    permit: &RootCommitPermit,
) {
    state.file_index_repository().upsert_file(group_id, record, permit).unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(group_id, &record.path, MaterializationState::Present, permit)
        .unwrap();
}

fn store_and_record(store: &SegmentBlockStore, path: &str, content: &[u8]) -> FileRecord {
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    FileRecord {
        path: path.to_owned(),
        size: content.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
        deleted: false,
    }
}

struct AlwaysConfirmed;

impl FullReplicaCustody for AlwaysConfirmed {
    fn confirm_exact_version(
        &self,
        _: &str,
        _: &str,
        _: &VersionHash,
        _: &[yadorilink_replica_domain::file::VersionBlock],
    ) -> Option<CustodyStamp> {
        Some(CustodyStamp::new("test-peer".to_owned(), 0))
    }

    fn confirmation_still_valid(
        &self,
        _: &str,
        _: &str,
        _: &VersionHash,
        _: &CustodyStamp,
    ) -> bool {
        true
    }
}

/// Confirms custody for exactly one path; every other path is uncustodied.
struct ConfirmsOnly(&'static str);

impl FullReplicaCustody for ConfirmsOnly {
    fn confirm_exact_version(
        &self,
        _: &str,
        path: &str,
        _: &VersionHash,
        _: &[yadorilink_replica_domain::file::VersionBlock],
    ) -> Option<CustodyStamp> {
        (path == self.0).then(|| CustodyStamp::new("test-peer".to_owned(), 0))
    }

    fn confirmation_still_valid(
        &self,
        _: &str,
        path: &str,
        _: &VersionHash,
        _: &CustodyStamp,
    ) -> bool {
        path == self.0
    }
}

fn assert_cross_group_reference_retains_shared_block(
    other_state: MaterializationState,
    custody: &dyn FullReplicaCustody,
) {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root.path());
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"same content shared across folder groups";
    let record_a = store_and_record(&store, "group-a.bin", content);
    let mut record_b = record_a.clone();
    record_b.path = "group-b.bin".to_owned();
    let hash = hex::encode(&record_a.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    state.file_index_repository().upsert_file("group-a", &record_a, &permit).unwrap();
    state.file_index_repository().upsert_file("group-b", &record_b, &permit).unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state("group-b", "group-b.bin", other_state, &permit)
        .unwrap();
    std::fs::write(root.path().join("group-a.bin"), content).unwrap();

    evict_file(
        MaterializationContext {
            state: &state,
            liveness_gate: &BlockLivenessGate::default(),
            store: &store,
            root: root.path(),
            permit: &permit,
        },
        "group-a",
        "group-a.bin",
        false,
        custody,
    )
    .unwrap();

    assert!(store.exists(&hash).unwrap(), "another group still references the shared block");
}

#[test]
fn eviction_must_not_delete_block_used_by_hydrated_file_in_another_group() {
    assert_cross_group_reference_retains_shared_block(
        MaterializationState::Present,
        &AlwaysConfirmed,
    );
}

#[test]
fn eviction_must_not_delete_block_retained_for_uncustodied_placeholder_in_another_group() {
    assert_cross_group_reference_retains_shared_block(
        MaterializationState::Remote,
        &ConfirmsOnly("group-a.bin"),
    );
}

/// Two identical files; evicting the first keeps the shared blocks (the second is
/// hydrated), and evicting the second -- the last hydrated referrer -- must free them, because the
/// first is a placeholder whose own custody is confirmed too.
#[cfg(not(windows))]
fn evict_two_identical_files(
    second_custody: &dyn FullReplicaCustody,
) -> (SegmentBlockStore, String, ReplicaCoordinator, tempfile::TempDir, tempfile::TempDir) {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root.path());
    state
        .link_repository()
        .set_materialization_policy(
            &root.path().to_string_lossy(),
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"identical content of shared-c and shared-d";
    let record_c = store_and_record(&store, "c.bin", content);
    let mut record_d = record_c.clone();
    record_d.path = "d.bin".to_owned();
    let hash = hex::encode(&record_c.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-a", &record_c, &permit);
    upsert_hydrated_file(&state, "group-a", &record_d, &permit);
    std::fs::write(root.path().join("c.bin"), content).unwrap();
    std::fs::write(root.path().join("d.bin"), content).unwrap();
    let evict = |path: &str, custody: &dyn FullReplicaCustody| {
        evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            "group-a",
            path,
            false,
            custody,
        )
        .unwrap()
    };
    evict("c.bin", &AlwaysConfirmed);
    assert!(store.exists(&hash).unwrap(), "d.bin is still hydrated and needs the blocks");
    evict("d.bin", second_custody);
    (store, hash, state, root, store_dir)
}

#[cfg(not(windows))]
#[test]
fn evicting_the_last_identical_referrer_frees_the_shared_blocks() {
    let _exclusion =
        yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test();
    let (store, hash, ..) = evict_two_identical_files(&AlwaysConfirmed);
    assert!(
        !store.exists(&hash).unwrap(),
        "both identical files are placeholders with confirmed custody: nothing roots the blocks"
    );
}

#[cfg(not(windows))]
#[test]
fn a_shared_block_stays_while_the_other_placeholder_has_no_confirmed_custody() {
    let _exclusion =
        yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test();
    let (store, hash, ..) = evict_two_identical_files(&ConfirmsOnly("d.bin"));
    assert!(
        store.exists(&hash).unwrap(),
        "c.bin's custody is not confirmed, so its placeholder may hold the only local copy"
    );
}

#[test]
fn concurrent_evictions_across_groups_must_preserve_shared_block() {
    use std::sync::Barrier;

    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-a", root_a.path());
    adopt_root(&state, "group-b", root_b.path());
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let content = b"concurrently evicted cross-group content";
    let record_a = store_and_record(&store, "a.bin", content);
    let mut record_b = record_a.clone();
    record_b.path = "b.bin".to_owned();
    let hash = hex::encode(&record_a.blocks[0].hash);
    let permit = RootCommitPermit::for_tests();
    state.file_index_repository().upsert_file("group-a", &record_a, &permit).unwrap();
    state.file_index_repository().upsert_file("group-b", &record_b, &permit).unwrap();
    std::fs::write(root_a.path().join("a.bin"), content).unwrap();
    std::fs::write(root_b.path().join("b.bin"), content).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let gate = Arc::new(BlockLivenessGate::default());
    let handles: Vec<_> = [
        ("group-a", "a.bin", root_a.path().to_owned()),
        ("group-b", "b.bin", root_b.path().to_owned()),
    ]
    .into_iter()
    .map(|(group_id, path, root)| {
        let state = state.clone();
        let store = store.clone();
        let barrier = barrier.clone();
        let gate = gate.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let permit = RootCommitPermit::for_tests();
            evict_file(
                MaterializationContext {
                    state: state.as_ref(),
                    liveness_gate: gate.as_ref(),
                    store: store.as_ref(),
                    root: &root,
                    permit: &permit,
                },
                group_id,
                path,
                false,
                &AlwaysConfirmed,
            )
            .unwrap();
        })
    })
    .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    assert!(store.exists(&hash).unwrap(), "concurrent cross-group eviction deleted shared block");
}

fn record_with_blocks(path: &str, content: &[u8], hash: Vec<u8>) -> FileRecord {
    FileRecord {
        path: path.to_owned(),
        size: content.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
        deleted: false,
    }
}

/// The live repair sweep runs over EVERY materialization-state row in the
/// group on its own periodic cadence, and its "already fine" arm used to
/// issue an unconditional `clear_materialization_intent` for each such row
/// -- one fsync-backed write transaction, each taking the process-wide
/// writer gate, for a DELETE matching no row, since the intent journal is
/// empty in steady state. The sweep now reads the outstanding set once per
/// pass and writes only for a path actually in it.
///
/// The cost reduction itself is not asserted here: the only instrument
/// that can see "did this take the writer gate at all" is `writer_gate_stats`'s
/// process-global counter, and a global counter cannot be read soundly
/// from a parallel test runner -- another test writing to its own database
/// inflates it (confirmed: this assertion passed alone and failed in the
/// full suite). It is evidenced by measurement instead, at the scale where
/// it matters: a 20,050-row pass went from 35,491ms to 4,195ms with
/// `intent_clears=0`. What IS asserted deterministically is the primitive
/// the fix rests on -- that the set really is the outstanding set -- plus
/// the correctness half in the test below.
#[test]
fn the_outstanding_intent_set_is_exactly_the_paths_that_have_one() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let permit = RootCommitPermit::for_tests();
    let intents = state.materialization_intent_repository();

    assert!(
        intents.list_materialization_intent_paths("group-1").unwrap().is_empty(),
        "a group that has never materialized anything has no outstanding intents"
    );

    intents.begin_materialization_intent("group-1", "a.txt", &[0; 32], &permit).unwrap();
    intents.begin_materialization_intent("group-1", "b.txt", &[1; 32], &permit).unwrap();
    // A different group's intent must never leak into this group's set.
    intents.begin_materialization_intent("group-2", "c.txt", &[2; 32], &permit).unwrap();

    let outstanding = intents.list_materialization_intent_paths("group-1").unwrap();
    assert_eq!(
        outstanding,
        ["a.txt".to_string(), "b.txt".to_string()].into_iter().collect(),
        "exactly this group's open intents, and nothing else"
    );

    intents.clear_materialization_intent("group-1", "a.txt", &permit).unwrap();
    assert_eq!(
        intents.list_materialization_intent_paths("group-1").unwrap(),
        ["b.txt".to_string()].into_iter().collect(),
        "a cleared intent leaves the set"
    );
}

/// Teeth for the assertion above: the sweep must still clear an intent that
/// genuinely exists. A crash between a completed rename and its own intent
/// clear leaves exactly this state, and leaving it would later make an
/// ordinary offline deletion of the same path read as a crash mid-write.
#[test]
fn a_sweep_still_clears_a_real_dangling_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();

    let content = b"already written before the crash".to_vec();
    let hash = hex::decode(store.put(&content).unwrap()).unwrap();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("doc.txt", &content, hash),
        &permit,
    );
    // The rename completed; only the intent's own clear did not.
    std::fs::write(root.path().join("doc.txt"), &content).unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();
    assert!(state
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "doc.txt")
        .unwrap());

    repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Live,
        &permit,
    )
    .unwrap();

    assert!(
        !state
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "doc.txt")
            .unwrap(),
        "a real dangling intent over a completed write must still be dropped"
    );
}

/// A live pass over a folder in which nothing changed looks at no row: the rows
/// whose proof names their current version are settled in one set-based read, not
/// locked and read back one by one every cadence. A row that is not settled is
/// still visited, and healed.
#[test]
fn a_live_repair_pass_over_settled_rows_visits_none_of_them() {
    const GROUP: &str = "group-settled-rows";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    const FILES: usize = 40;
    for i in 0..FILES {
        let name = format!("file-{i}.txt");
        let content = format!("content {i}");
        let record = store_and_record(&store, &name, content.as_bytes());
        upsert_hydrated_file(&state, GROUP, &record, &permit);
        std::fs::write(root.path().join(&name), content).unwrap();
    }
    let pass = |mode| {
        repair_interrupted_materializations(&state, &store, root.path(), GROUP, mode, &permit)
            .unwrap()
    };

    // Startup proves every row once.
    let startup = pass(RepairMode::Startup);
    assert_eq!(startup.reproven.len(), FILES);

    let live = pass(RepairMode::Live);
    assert_eq!(live.rows_visited, 0, "a live pass over unchanged rows visited some of them");
    assert!(live.is_empty());

    // One row loses its proof (a new local write is in flight): only it is visited.
    let content = b"edited while the pass was idle";
    let record = store_and_record(&store, "file-7.txt", content);
    upsert_hydrated_file(&state, GROUP, &record, &permit);
    std::fs::write(root.path().join("file-7.txt"), content).unwrap();
    let live = pass(RepairMode::Live);
    assert_eq!(live.rows_visited, 1, "{live:?}");
    assert_eq!(live.reproven, vec!["file-7.txt".to_string()]);
}

#[test]
fn repair_reconstructs_locally_after_a_simulated_crash_before_rename() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"hello from before the crash";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();
    assert_eq!(report.reconstructed, vec!["doc.txt"]);
    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), content);
}

/// A repair reconstruct keeps its intent until the proof commit clears it.
/// The intent is the only durable record that the write is in flight, so a
/// failure (or a crash) after the bytes and metadata land but before the
/// proof is committed must leave it open for the next pass to decide.
#[test]
fn a_repair_reconstruct_whose_proof_commit_fails_keeps_its_intent_open() {
    const GROUP: &str = "group-reconstruct-proof-commit-fails";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt, but never proven";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, GROUP, &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP, "doc.txt", &[0; 32], &permit)
        .unwrap();
    crate::replica_coordinator::materialization_owner::set_test_fail_repair_reconstruct_proof_commit(
        GROUP, "doc.txt", true,
    );

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), content);
    assert!(report.reconstructed.is_empty(), "nothing was proven, so nothing is reconstructed");
    assert!(
        !MaterializationExecutionPort::has_usable_materialized_generation(&state, GROUP, "doc.txt")
            .unwrap(),
        "the failed commit published no proof"
    );
    assert!(
        state
            .materialization_intent_repository()
            .has_materialization_intent(GROUP, "doc.txt")
            .unwrap(),
        "the intent must survive until the proof commit that clears it"
    );
}

/// The kept intent has to be one some lane still decides. A proof commit
/// that fails without a crash left the row `Remote`, which is never a
/// repair candidate, so the intent stayed open with full bytes on disk and
/// no pass ever visited it again -- and every scan kept deferring an
/// offline delete of that path. The failed settle now leaves the row in
/// the in-flight state, so the next pass (live, here) finds `Hydrating`
/// with an open intent over matching bytes and proves it.
#[test]
fn a_repair_reconstruct_whose_proof_commit_failed_is_proven_by_the_next_pass() {
    const GROUP: &str = "group-reconstruct-proof-commit-fails-then-heals";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt, proven one pass later";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, GROUP, &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP, "doc.txt", &[0; 32], &permit)
        .unwrap();
    crate::replica_coordinator::materialization_owner::set_test_fail_repair_reconstruct_proof_commit(
        GROUP, "doc.txt", true,
    );
    repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();
    crate::replica_coordinator::materialization_owner::set_test_fail_repair_reconstruct_proof_commit(
        GROUP, "doc.txt", false,
    );
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrating),
        "an unproven reconstruct that keeps its intent must stay a repair candidate"
    );

    repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Live,
        &permit,
    )
    .unwrap();

    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), content);
    assert!(
        MaterializationExecutionPort::has_usable_materialized_generation(&state, GROUP, "doc.txt")
            .unwrap(),
        "the next pass proves the bytes the failed settle left behind"
    );
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Present)
    );
    assert!(
        !state
            .materialization_intent_repository()
            .has_materialization_intent(GROUP, "doc.txt")
            .unwrap(),
        "the proving commit clears the intent the failed settle kept"
    );
}

/// The success counterpart: the proof commit is what clears the intent, in
/// the same transaction that publishes the proof and stamps `Present`.
#[test]
fn a_repair_reconstruct_clears_its_intent_with_the_proof_it_commits() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt and proven";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["doc.txt"]);
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Present)
    );
    assert!(!state
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "doc.txt")
        .unwrap());
}

/// The exact crash cut-point repair must cover: a symlink row is committed durably, then the daemon
/// crashes before the physical symlink is ever written -- previously,
/// repair's own `RecordKind::File`-only filter meant this row was
/// simply never examined, leaving the symlink permanently missing
/// across restarts (and, before `materialize_symlink_at`'s matching
/// fix, no durable intent even existed to disambiguate this from an
/// offline deletion in the first place). Confirmed genuinely RED by
/// temporarily reverting the loop's symlink branch back to the bare
/// `RecordKind::File`-only filter: the row was skipped and the
/// symlink was never created.
#[cfg(unix)]
#[test]
fn repair_recreates_a_symlink_after_a_simulated_crash_before_the_write() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, "group-1", &record, &permit);
    state
        .file_index_repository()
        .set_record_kind("group-1", "link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target("group-1", "link.txt", Some(b"target.txt"))
        .unwrap();
    // Simulate the crash: a durable intent was opened (exactly what
    // `materialize_symlink_at` now does before its own row commit),
    // but the physical symlink write never happened.
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "link.txt", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["link.txt"]);
    let out_path = root.path().join("link.txt");
    assert!(
        std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
        "must be a real symlink on disk after repair"
    );
    assert_eq!(std::fs::read_link(&out_path).unwrap(), std::path::Path::new("target.txt"));
    assert!(
        MaterializationExecutionPort::materialization_intent_kind(&state, "group-1", "link.txt")
            .unwrap()
            .is_none(),
        "the intent must be cleared once repair completes the write"
    );
}

/// An explicit directory whose materialization was interrupted
/// between its row commit and its `mkdir` (the intent is still open, the
/// directory is not on disk) is recreated by repair, with its mode, and
/// proven.
#[cfg(unix)]
#[test]
fn repair_recreates_missing_explicit_directory() {
    use std::os::unix::fs::PermissionsExt as _;
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "nested/docs".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, "group-1", &record, &permit);
    state
        .file_index_repository()
        .set_record_kind("group-1", "nested/docs", RecordKind::Directory, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_unix_mode("group-1", "nested/docs", Some(0o750), &permit)
        .unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "nested/docs", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["nested/docs"]);
    let metadata = std::fs::symlink_metadata(root.path().join("nested/docs")).unwrap();
    assert!(metadata.is_dir(), "repair must recreate a real directory");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o750);
    assert!(
        MaterializationExecutionPort::materialization_intent_kind(&state, "group-1", "nested/docs")
            .unwrap()
            .is_none(),
        "the intent must be cleared once repair completes the directory"
    );
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state,
        "group-1",
        "nested/docs"
    )
    .unwrap());
    // The parent repair had to create is structural, like any other.
    assert!(matches!(
        state.sqlite().dag_structural_directory_origin("group-1", "nested").unwrap(),
        yadorilink_sync_sqlite::structural_origin::StructuralDirectoryOrigin::Recorded(_)
    ));
}

/// A healthy explicit directory costs repair nothing, and a directory
/// whose materialization completed on disk but whose proof did not land
/// is proven, not recreated.
#[test]
fn repair_proves_an_explicit_directory_already_on_disk() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "docs".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, "group-1", &record, &permit);
    state
        .file_index_repository()
        .set_record_kind("group-1", "docs", RecordKind::Directory, &permit)
        .unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "docs", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reproven, vec!["docs"]);
    assert!(report.reconstructed.is_empty());
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "docs"
    )
    .unwrap());
}

/// The offline-deletion counterpart of the crash-recovery test above:
/// a symlink row says `Present` with a recorded target, but there is
/// no on-disk symlink and no open intent -- the write had already
/// completed (intent cleared) and the symlink was deleted while the
/// daemon was stopped. Repair must classify this as an offline
/// deletion, never resurrect it.
#[test]
fn repair_does_not_resurrect_an_offline_deleted_symlink() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    // `repair_one_interrupted_symlink`'s Windows arm gates its ENTIRE
    // body -- including this test's own offline-delete classification
    // -- on the link's `windows_symlink_opt_in` policy flag, which a
    // fresh `add_link` (inside `adopt_root` above) defaults to `false`
    // (see `windows_symlink_opt_in_for_group`'s own `unwrap_or(0)`).
    // Without opting in here, `policy_permits_write` is `false` on
    // Windows and the function returns `Ok(())` before ever reaching
    // the on-disk/intent checks this test means to exercise, so
    // `report.offline_deleted` stays empty regardless of what is (or
    // is not) on disk. Mirrors the same opt-in every other symlink-
    // materialization test that must actually reach that logic on
    // Windows already performs (see e.g. `yadorilink-daemon::
    // hydration`'s own `set_windows_symlink_opt_in(..., true)` calls).
    #[cfg(windows)]
    state
        .link_repository()
        .set_windows_symlink_opt_in(&root.path().to_string_lossy(), true)
        .unwrap();
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "gone-link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, "group-1", &record, &permit);
    state
        .file_index_repository()
        .set_record_kind("group-1", "gone-link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target("group-1", "gone-link.txt", Some(b"target.txt"))
        .unwrap();
    // No intent opened, and nothing on disk -- the write completed
    // and was later deleted offline; never simulate a crash here.

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.offline_deleted, vec!["gone-link.txt"]);
    assert_eq!(report.reconstructed, Vec::<String>::new());
    assert!(!root.path().join("gone-link.txt").exists());
}

/// A crash inside a single-path tombstone delete, after its
/// `remove_file` and before its settle: the row is still live and
/// `Present`, the file is gone, and the delete's own intent is open. That
/// intent is a delete, not an interrupted write, so the missing file is the
/// state it was heading to. Repair must not rebuild the file from blocks;
/// it leaves the path and the intent to the outstanding delete. Run for
/// both modes, since the missing-file arms differ between them.
fn crash_a_tombstone_delete_after_its_removal(
    state: &ReplicaCoordinator,
    group_id: &str,
    root: &Path,
    record: &FileRecord,
    permit: &RootCommitPermit,
) {
    let out_path = root.join(&record.path);
    let (delete_intent_guard, _mutation_generation) =
        state.open_tombstone_delete(group_id, &record.path, permit).unwrap();
    std::fs::remove_file(&out_path).unwrap();
    // The crash: the settle never runs, so the intent is dropped uncleared.
    drop(delete_intent_guard);
}

#[test]
fn repair_does_not_reconstruct_a_file_its_interrupted_tombstone_delete_removed() {
    for (group_id, mode) in
        [("group-tomb-startup", RepairMode::Startup), ("group-tomb-live", RepairMode::Live)]
    {
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, group_id, root.path());
        let permit = RootCommitPermit::for_tests();
        let content = b"deleted by a peer's tombstone";
        let record = store_and_record(&store, "doc.txt", content);
        upsert_hydrated_file(&state, group_id, &record, &permit);
        std::fs::write(root.path().join("doc.txt"), content).unwrap();
        crash_a_tombstone_delete_after_its_removal(&state, group_id, root.path(), &record, &permit);

        let report = repair_interrupted_materializations(
            &state,
            &store,
            root.path(),
            group_id,
            mode,
            &permit,
        )
        .unwrap();

        assert!(
            !root.path().join("doc.txt").exists(),
            "{mode:?}: repair recreated a file its tombstone delete had already removed"
        );
        assert_eq!(report.reconstructed, Vec::<String>::new(), "{mode:?}");
        assert_eq!(report.offline_deleted, Vec::<String>::new(), "{mode:?}");
        assert!(
            state
                .materialization_intent_repository()
                .has_materialization_intent(group_id, "doc.txt")
                .unwrap(),
            "{mode:?}: the delete's intent is the outstanding delete's to settle"
        );
    }
}

/// The owner tells a delete's intent from a write's by the target it
/// opened it with, and that must hold for an empty file too: the ordinary
/// target of an empty file is the hash of an empty block list, which the
/// delete's target must never equal.
#[test]
fn the_owner_classifies_a_tombstone_intent_as_a_delete_and_an_empty_files_write_as_a_write() {
    const GROUP: &str = "group-intent-kind";
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    assert_eq!(state.materialization_intent_kind(GROUP, "gone.txt").unwrap(), None);

    let (delete_intent_guard, _) = state.open_tombstone_delete(GROUP, "gone.txt", &permit).unwrap();
    drop(delete_intent_guard);
    assert_eq!(
        state.materialization_intent_kind(GROUP, "gone.txt").unwrap(),
        Some(MaterializationIntentKind::Delete)
    );

    state
        .materialization_intent_repository()
        .begin_materialization_intent(
            GROUP,
            "empty.txt",
            &yadorilink_local_storage::intent_target_hash(&[]),
            &permit,
        )
        .unwrap();
    assert_eq!(
        state.materialization_intent_kind(GROUP, "empty.txt").unwrap(),
        Some(MaterializationIntentKind::Materialize)
    );
}

/// The symlink lane's counterpart of the tombstone crash: the removed
/// link must not be rebuilt either.
#[cfg(unix)]
#[test]
fn repair_does_not_recreate_a_symlink_its_interrupted_tombstone_delete_removed() {
    const GROUP: &str = "group-tomb-link";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, GROUP, &record, &permit);
    state
        .file_index_repository()
        .set_record_kind(GROUP, "link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target(GROUP, "link.txt", Some(b"target.txt"))
        .unwrap();
    std::os::unix::fs::symlink("target.txt", root.path().join("link.txt")).unwrap();
    crash_a_tombstone_delete_after_its_removal(&state, GROUP, root.path(), &record, &permit);

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert!(
        std::fs::symlink_metadata(root.path().join("link.txt")).is_err(),
        "repair recreated a symlink its tombstone delete had already removed"
    );
    assert_eq!(report.reconstructed, Vec::<String>::new());
}

/// A user's regular file created at a tombstoned symlink's path while the
/// daemon was stopped (after the delete's intent opened, before its unlink)
/// must survive startup repair; the deleted link is not resurrected over it.
#[cfg(unix)]
#[test]
fn repair_leaves_a_user_file_at_a_symlink_path_under_an_open_delete_intent() {
    const GROUP: &str = "group-tomb-link-user-file";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, GROUP, &record, &permit);
    state
        .file_index_repository()
        .set_record_kind(GROUP, "link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target(GROUP, "link.txt", Some(b"target.txt"))
        .unwrap();
    let (guard, _) = state.open_tombstone_delete(GROUP, "link.txt", &permit).unwrap();
    drop(guard);
    std::fs::write(root.path().join("link.txt"), b"user data").unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(std::fs::read(root.path().join("link.txt")).unwrap(), b"user data");
    assert_eq!(report.reconstructed, Vec::<String>::new());
}

/// A regular file at a symlink row's path under a write intent is likewise
/// not the arm's to replace.
#[cfg(unix)]
#[test]
fn repair_leaves_a_user_file_at_a_symlink_path_under_a_write_intent() {
    const GROUP: &str = "group-write-link-user-file";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, GROUP, &record, &permit);
    state
        .file_index_repository()
        .set_record_kind(GROUP, "link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target(GROUP, "link.txt", Some(b"target.txt"))
        .unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP, "link.txt", &[0; 32], &permit)
        .unwrap();
    std::fs::write(root.path().join("link.txt"), b"user data").unwrap();

    repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(std::fs::read(root.path().join("link.txt")).unwrap(), b"user data");
}

/// An interrupted overwrite of an actual symlink (stale target, write
/// intent open) is still completed.
#[cfg(unix)]
#[test]
fn repair_still_completes_an_interrupted_symlink_overwrite() {
    const GROUP: &str = "group-write-link-overwrite";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, GROUP, &record, &permit);
    state
        .file_index_repository()
        .set_record_kind(GROUP, "link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target(GROUP, "link.txt", Some(b"target.txt"))
        .unwrap();
    std::os::unix::fs::symlink("stale.txt", root.path().join("link.txt")).unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP, "link.txt", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["link.txt"]);
    assert_eq!(
        std::fs::read_link(root.path().join("link.txt")).unwrap(),
        std::path::Path::new("target.txt")
    );
}

/// The generic defense-in-depth fix: a `Present` row that is missing
/// on disk, has no open intent, but still has an OUTSTANDING projection
/// obligation must not be classified as an offline deletion either --
/// the Convergence Engine has not finished deciding this path's fate
/// yet (this is the shape of a freshly-admitted row a repair sweep
/// happens to run before the first materialize attempt, a hazard-hold
/// route that never demoted `materialization_state` itself, or any
/// future route with the same gap -- covered generically instead of
/// patched per route). Same setup as
/// `repair_does_not_resurrect_an_offline_deleted_symlink` immediately
/// above, with one addition: a projection-obligation row for the path.
#[test]
fn repair_does_not_classify_as_offline_deleted_while_a_projection_obligation_is_still_unsettled() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "not-yet-placed-link.txt".to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    state.file_index_repository().upsert_file("group-1", &record, &permit).unwrap();
    state
        .file_index_repository()
        .set_record_kind("group-1", "not-yet-placed-link.txt", RecordKind::Symlink, &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target("group-1", "not-yet-placed-link.txt", Some(b"target.txt"))
        .unwrap();
    // No intent opened, nothing on disk -- same as the offline-deleted
    // test above, EXCEPT this path still has an outstanding projection
    // obligation, simulating "admitted but never yet materialized"
    // rather than "materialized, then offline-deleted".
    state
        .sqlite()
        .dag_bump_projection_obligations_for_touched_paths(
            "group-1",
            &["not-yet-placed-link.txt"],
            1,
        )
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(
        report.offline_deleted,
        Vec::<String>::new(),
        "a path with an unsettled projection obligation must never be classified as an \
         offline deletion, even at startup"
    );
    // Not just "no tombstone" -- also "not silently resurrected". A
    // still-unsettled path must be deferred entirely, not reconstructed
    // either: falling through to reconstruction here would recreate a
    // symlink that might describe a genuine, still-fresh offline
    // deletion racing this unrelated obligation. `report.reconstructed`
    // being empty proves repair took neither side of that decision.
    assert_eq!(report.reconstructed, Vec::<String>::new());
    // `Path::exists()` follows symlinks and reports `false` for a
    // dangling one (this test's `record` names a `symlink_target` that
    // is never actually created on disk) -- it would read as "doesn't
    // exist" whether or not repair wrote a symlink here, so it cannot
    // tell "left alone" apart from "reconstructed". `symlink_metadata`
    // does not follow the link, so it distinguishes them correctly.
    assert!(
        std::fs::symlink_metadata(root.path().join("not-yet-placed-link.txt")).is_err(),
        "repair must not have written anything at all for a still-unsettled path"
    );
}

/// `RepairMode::Live`'s whole reason to exist: a `Present` record
/// whose on-disk bytes are present but diverge from the index, with
/// NO open materialization intent, must NOT be treated the same way
/// `RepairMode::Startup` does (quarantine + heal from the index) --
/// it may be a live user edit still sitting in the debounce
/// accumulator, not an offline edit. Live mode must leave the file
/// completely untouched and instead hand it to the dirty-journal
/// backstop, which is what actually captures a real live edit.
#[test]
fn live_repair_does_not_quarantine_a_present_divergent_file_with_no_open_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let indexed_content = b"the synced, indexed content";
    let hash = hex::decode(store.put(indexed_content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("doc.txt", indexed_content, hash),
        &permit,
    );
    // No materialization intent opened -- and the on-disk bytes differ
    // from what's indexed, simulating a live user edit that has not
    // yet been captured (no crash, the "daemon" here never stopped).
    let live_edit_content = b"a live user edit still in flight";
    std::fs::write(root.path().join("doc.txt"), live_edit_content).unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Live,
        &permit,
    )
    .unwrap();

    assert!(
        report.quarantined_dirty.is_empty(),
        "live mode must never quarantine a possibly-in-flight local edit: {:?}",
        report.quarantined_dirty
    );
    assert!(report.reconstructed.is_empty());
    assert_eq!(
        std::fs::read(root.path().join("doc.txt")).unwrap(),
        live_edit_content,
        "the canonical file must be left completely untouched by live repair"
    );
    let dirty = state.dirty_path_repository().list_dirty_paths("group-1").unwrap();
    assert!(
        dirty.iter().any(|d| d.path == "doc.txt"),
        "the live edit must be handed to the dirty-journal backstop instead: {dirty:?}"
    );
}

/// Startup decision table for a `Present` file row (an offline edit stays a plain local edit). With no
/// materialization intent, nothing interrupted a write, so whatever disk holds
/// is the user's: missing is an offline delete, matching bytes are clean, and
/// different bytes stay in place for the dirty journal / initial scan to author
/// as an ordinary local edit (never a conflicted copy at repair time). With an
/// intent, disk bytes that the row can explain are crash recovery, and bytes it
/// cannot explain keep the conservative quarantine.
#[test]
fn startup_repair_decision_table_for_a_present_file() {
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Disk {
        Missing,
        Indexed,
        Other,
    }
    // (name, disk, intent open)
    let cases = [
        ("no intent, missing", Disk::Missing, false),
        ("no intent, bytes == indexed", Disk::Indexed, false),
        ("no intent, bytes != indexed", Disk::Other, false),
        ("intent, missing", Disk::Missing, true),
        ("intent, bytes == indexed", Disk::Indexed, true),
        ("intent, bytes != indexed", Disk::Other, true),
    ];
    for (name, disk, intent) in cases {
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let indexed: &[u8] = b"the synced, indexed content";
        let other: &[u8] = b"an edit made while the daemon was stopped";
        let hash = hex::decode(store.put(indexed).unwrap()).unwrap();
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-1", root.path());
        let permit = RootCommitPermit::for_tests();
        upsert_hydrated_file(
            &state,
            "group-1",
            &record_with_blocks("doc.txt", indexed, hash),
            &permit,
        );
        match disk {
            Disk::Missing => {}
            Disk::Indexed => std::fs::write(root.path().join("doc.txt"), indexed).unwrap(),
            Disk::Other => std::fs::write(root.path().join("doc.txt"), other).unwrap(),
        }
        if intent {
            state
                .materialization_intent_repository()
                .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
                .unwrap();
        }

        let report = repair_interrupted_materializations(
            &state,
            &store,
            root.path(),
            "group-1",
            RepairMode::Startup,
            &permit,
        )
        .unwrap();

        let on_disk = std::fs::read(root.path().join("doc.txt")).ok();
        let dirty = state.dirty_path_repository().list_dirty_paths("group-1").unwrap();
        let dirty_doc = dirty.iter().any(|d| d.path == "doc.txt");
        match (disk, intent) {
            (Disk::Missing, false) => {
                assert_eq!(report.offline_deleted, vec!["doc.txt".to_owned()], "{name}");
                assert!(on_disk.is_none(), "{name}: an offline delete is not resurrected");
                assert!(report.quarantined_dirty.is_empty(), "{name}");
            }
            (Disk::Indexed, false) => {
                assert!(report.quarantined_dirty.is_empty(), "{name}");
                assert!(!dirty_doc, "{name}: clean file is not dirty");
                assert_eq!(on_disk.as_deref(), Some(indexed), "{name}");
            }
            (Disk::Other, false) => {
                assert!(
                    report.quarantined_dirty.is_empty(),
                    "{name}: {:?}",
                    report.quarantined_dirty
                );
                assert!(report.reconstructed.is_empty(), "{name}");
                assert_eq!(on_disk.as_deref(), Some(other), "{name}: edit stays at the path");
                assert!(dirty_doc, "{name}: edit is handed to the dirty journal: {dirty:?}");
                let conflicted = std::fs::read_dir(root.path())
                    .unwrap()
                    .filter(|e| {
                        e.as_ref().unwrap().file_name().to_string_lossy().contains("conflicted")
                    })
                    .count();
                assert_eq!(conflicted, 0, "{name}: no conflicted copy is created");
            }
            (Disk::Missing, true) | (Disk::Indexed, true) => {
                assert!(report.quarantined_dirty.is_empty(), "{name}");
                assert_eq!(on_disk.as_deref(), Some(indexed), "{name}: crash recovery");
            }
            (Disk::Other, true) => {
                assert_eq!(report.quarantined_dirty.len(), 1, "{name}");
                assert_eq!(on_disk.as_deref(), Some(indexed), "{name}: canonical healed");
                assert_eq!(
                    std::fs::read(root.path().join(&report.quarantined_dirty[0].1)).unwrap(),
                    other,
                    "{name}: unexplained bytes are preserved in the quarantine copy"
                );
            }
        }
    }
}

/// The index row holds a peer's version while the local file differs from it
/// (an offline edit). With no intent, startup repair does not pick a winner or
/// move bytes: the edit stays at the path and goes to the dirty journal, and
/// the peer's blocks stay in the store. What authoring then does is decided by
/// the native witness, not here (an edit based on the row's version
/// supersedes it; a peer head the edit did not observe is a conflict, see
/// `an_offline_edit_racing_a_peer_edit_keeps_both_versions_as_a_normal_conflict`).
#[test]
fn startup_repair_leaves_an_offline_edit_in_place_when_the_row_already_holds_a_peer_version() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let peer: &[u8] = b"the peer's concurrent version";
    let local: &[u8] = b"my offline edit";
    let peer_hash = hex::decode(store.put(peer).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("doc.txt", peer, peer_hash.clone()),
        &permit,
    );
    std::fs::write(root.path().join("doc.txt"), local).unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert!(report.quarantined_dirty.is_empty() && report.reconstructed.is_empty());
    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), local);
    assert!(store.present_blocks(&[hex::encode(&peer_hash)]).unwrap()[0], "peer bytes kept");
    let dirty = state.dirty_path_repository().list_dirty_paths("group-1").unwrap();
    assert!(dirty.iter().any(|d| d.path == "doc.txt"), "{dirty:?}");
}

/// Seeds a `Present` row holding `indexed`, with `doc.txt` on disk as `disk`.
fn seed_present(
    state: &ReplicaCoordinator,
    store: &SegmentBlockStore,
    root: &Path,
    indexed: &[u8],
    disk: Option<&[u8]>,
) {
    let hash = hex::decode(store.put(indexed).unwrap()).unwrap();
    adopt_root(state, "group-1", root);
    upsert_hydrated_file(
        state,
        "group-1",
        &record_with_blocks("doc.txt", indexed, hash),
        &RootCommitPermit::for_tests(),
    );
    if let Some(disk) = disk {
        std::fs::write(root.join("doc.txt"), disk).unwrap();
    }
}

fn startup_repair(
    state: &ReplicaCoordinator,
    store: &SegmentBlockStore,
    root: &Path,
) -> yadorilink_filesystem_sync::materialization_repair::MaterializationRepairReport {
    repair_interrupted_materializations(
        state,
        store,
        root,
        "group-1",
        RepairMode::Startup,
        &RootCommitPermit::for_tests(),
    )
    .unwrap()
}

fn is_dirty(state: &ReplicaCoordinator) -> bool {
    state
        .dirty_path_repository()
        .list_dirty_paths("group-1")
        .unwrap()
        .iter()
        .any(|d| d.path == "doc.txt")
}

/// A `Hydrating` row with an intent is an interrupted write: bytes the row
/// cannot explain are quarantined and the version rebuilt, like `Present`.
#[test]
fn startup_repair_recovers_a_hydrating_row_with_an_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    let permit = RootCommitPermit::for_tests();
    let indexed: &[u8] = b"the row's content";
    seed_present(&state, &store, root.path(), indexed, Some(b"stale partial bytes"));
    state
        .materialization_state_repository()
        .set_materialization_state("group-1", "doc.txt", MaterializationState::Hydrating, &permit)
        .unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();

    let report = startup_repair(&state, &store, root.path());

    assert_eq!(report.quarantined_dirty.len(), 1, "{report:?}");
    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), indexed);
}

/// A present, divergent file under an unsettled projection obligation but no
/// intent is still an ordinary offline edit: the obligation only defers a
/// MISSING path, since a present file has no deletion to protect.
#[test]
fn startup_repair_journals_a_present_divergent_file_despite_an_unsettled_obligation() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    let edit: &[u8] = b"an offline edit";
    seed_present(&state, &store, root.path(), b"the row's content", Some(edit));
    state
        .sqlite()
        .dag_bump_projection_obligations_for_touched_paths("group-1", &["doc.txt"], 0)
        .unwrap();
    assert!(state.has_unsettled_projection_obligation("group-1", "doc.txt").unwrap());

    let report = startup_repair(&state, &store, root.path());

    assert!(report.quarantined_dirty.is_empty() && report.reconstructed.is_empty());
    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), edit);
    assert!(is_dirty(&state));
}

/// `RepairMode::Live`'s missing-file counterpart: a `Present` record
/// whose file is missing, with no open intent, must not be classified
/// as an offline deletion the way `Startup` mode does -- it may be a
/// live delete in progress. Hand it to the dirty-journal backstop
/// instead of touching the index/emitting a tombstone directly.
#[test]
fn live_repair_records_a_dirty_removal_instead_of_classifying_an_offline_delete() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"content that is about to look deleted";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    // No intent, and the file simply never existed under `root` here --
    // standing in for "missing right now," the same disk state a live
    // in-progress delete produces.

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Live,
        &permit,
    )
    .unwrap();

    assert!(
        report.offline_deleted.is_empty(),
        "live mode must not classify a missing file as an offline deletion: {:?}",
        report.offline_deleted
    );
    let dirty = state.dirty_path_repository().list_dirty_paths("group-1").unwrap();
    assert!(
        dirty.iter().any(|d| d.path == "doc.txt" && d.change_kind == "removed"),
        "the missing file must be handed to the dirty-journal backstop as a removal: {dirty:?}"
    );
}

#[test]
fn repair_demotes_to_placeholder_when_blocks_are_also_missing_locally() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("missing.bin", b"not present", vec![0xcd; 32]),
        &permit,
    );
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "missing.bin", &[0; 32], &permit)
        .unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();
    assert_eq!(report.demoted_to_placeholder, vec!["missing.bin"]);
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state("group-1", "missing.bin")
            .unwrap(),
        Some(MaterializationState::Remote)
    );
}

/// Which block-store call supersedes the row in [`SupersedingStore`]:
/// `present_blocks` for the missing-blocks demotion arm, `get` (which then
/// fails, so the reconstruct fails) for the reconstruct-failed arm.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SupersedeOn {
    PresentBlocks,
    GetThenFail,
}

/// A block store that supersedes the repair's row to a new version in the
/// middle of the repair's iteration -- after the lane took its row snapshot
/// under the path lock, before it demotes the row to a placeholder. It does
/// what a lock-free supersession does to a live current row: a new version,
/// left `Remote`.
struct SupersedingStore<'a> {
    inner: &'a SegmentBlockStore,
    state: &'a ReplicaCoordinator,
    group_id: &'a str,
    on: SupersedeOn,
    v2: std::sync::Mutex<Option<FileRecord>>,
}

impl SupersedingStore<'_> {
    fn supersede_once(&self) {
        let Some(v2) = self.v2.lock().unwrap().take() else { return };
        let permit = RootCommitPermit::for_tests();
        self.state.file_index_repository().upsert_file(self.group_id, &v2, &permit).unwrap();
        self.state
            .materialization_state_repository()
            .set_materialization_state(
                self.group_id,
                &v2.path,
                MaterializationState::Remote,
                &permit,
            )
            .unwrap();
    }
}

impl yadorilink_local_storage::BlockContentStore for SupersedingStore<'_> {
    fn put(
        &self,
        data: &[u8],
    ) -> Result<yadorilink_local_storage::ContentHash, yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::put(self.inner, data)
    }

    fn put_prepared(
        &self,
        prepared: &yadorilink_local_storage::LocallyHashedBlock,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::put_prepared(self.inner, prepared)
    }

    fn put_prepared_batch(
        &self,
        prepared: &[yadorilink_local_storage::LocallyHashedBlock],
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::put_prepared_batch(self.inner, prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, yadorilink_local_storage::StorageError> {
        if self.on == SupersedeOn::GetThenFail {
            self.supersede_once();
            return Err(yadorilink_local_storage::StorageError::Io(std::io::Error::other(
                "test-injected block read failure",
            )));
        }
        yadorilink_local_storage::BlockStore::get(self.inner, hash)
    }

    fn present_blocks(
        &self,
        hashes: &[yadorilink_local_storage::ContentHash],
    ) -> Result<Vec<bool>, yadorilink_local_storage::StorageError> {
        let present = yadorilink_local_storage::BlockStore::present_blocks(self.inner, hashes)?;
        if self.on == SupersedeOn::PresentBlocks {
            self.supersede_once();
        }
        Ok(present)
    }
}

/// A repair pass whose row is superseded to V2 after its snapshot
/// must not demote or placeholder the path for V1. Runs both placeholder
/// arms: blocks missing, and reconstruct failed with every block present.
fn assert_a_superseded_repair_writes_no_v1_placeholder(on: SupersedeOn) {
    const GROUP: &str = "group-superseded-repair-demotion";
    let store_dir = tempfile::tempdir().unwrap();
    let inner = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    let v1_content = b"version one, eleven";
    let v1 = match on {
        // Absent from the store: the missing-blocks arm.
        SupersedeOn::PresentBlocks => record_with_blocks("doc.bin", v1_content, vec![0xcd; 32]),
        // Present, so the lane reconstructs, and the read fails.
        SupersedeOn::GetThenFail => store_and_record(&inner, "doc.bin", v1_content),
    };
    upsert_hydrated_file(&state, GROUP, &v1, &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP, "doc.bin", &[0; 32], &permit)
        .unwrap();
    let v2_content = b"version two is a good deal longer than version one";
    let v2 = record_with_blocks("doc.bin", v2_content, vec![0xef; 32]);
    let store = SupersedingStore {
        inner: &inner,
        state: &state,
        group_id: GROUP,
        on,
        v2: std::sync::Mutex::new(Some(v2.clone())),
    };

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert!(store.v2.lock().unwrap().is_none(), "the supersession must have run mid-pass");
    let on_disk = std::fs::metadata(root.path().join("doc.bin")).ok().map(|m| m.len());
    assert_eq!(
        on_disk, None,
        "a repair about V1 wrote a placeholder (V1 is {} bytes, V2 {}) over the V2 row",
        v1.size, v2.size
    );
    assert!(report.demoted_to_placeholder.is_empty(), "{:?}", report.demoted_to_placeholder);
    assert_eq!(
        MaterializationExecutionPort::get_recorded_placeholder_identity(&state, GROUP, "doc.bin")
            .unwrap(),
        None,
        "no placeholder identity may be recorded for the V2 row from a V1 write"
    );
    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.bin")
            .unwrap(),
        Some(MaterializationState::Remote),
        "the V2 row keeps the state its own writer gave it"
    );
    assert!(
        state
            .materialization_intent_repository()
            .has_materialization_intent(GROUP, "doc.bin")
            .unwrap(),
        "a stale attempt writes nothing, the intent included"
    );
}

#[test]
fn a_repair_whose_row_was_superseded_writes_no_placeholder_when_blocks_are_missing() {
    assert_a_superseded_repair_writes_no_v1_placeholder(SupersedeOn::PresentBlocks);
}

#[test]
fn a_repair_whose_row_was_superseded_writes_no_placeholder_when_the_reconstruct_fails() {
    assert_a_superseded_repair_writes_no_v1_placeholder(SupersedeOn::GetThenFail);
}

/// The tenth route in the "current, non-deleted row with nothing on
/// disk under its own name and no protecting intent/obligation/hold"
/// bug family, at this repair sweep's own missing-blocks placeholder-
/// demotion arm: `create_or_defer_placeholder` writes nothing on
/// Windows (real creation deferred to `cfapi-host.exe`'s own poll),
/// but this arm used to clear the row's protecting intent
/// unconditionally, exactly as if a real placeholder write had
/// happened. This sweep runs on a live ~90s periodic cadence, so the
/// window is not a rare crash race. Uses `create_or_defer_
/// placeholder`'s own test-only failure-injection seam (real Windows
/// behavior is not exercisable on this host) to force the deferred
/// outcome regardless of platform.
#[test]
fn repair_leaves_the_intent_open_when_the_windows_placeholder_write_is_deferred() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(
        &state,
        "group-1",
        &record_with_blocks("missing-deferred.bin", b"not present either", vec![0xce; 32]),
        &permit,
    );
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "missing-deferred.bin", &[0; 32], &permit)
        .unwrap();

    // `repair_interrupted_materializations` canonicalizes `root` itself
    // (via `MaterializationExecutionPort::open_root` ->
    // `VerifiedRoot::open`, which calls `root.canonicalize()`) before
    // ever joining a path onto it -- see that type's own doc comment
    // ("Callers relativize walked entries against this, so it must be
    // the same resolution the caller's own scan performs internally").
    // The failure-injection seam below matches on exact `PathBuf`
    // equality, not on-disk identity, so this test must arm the SAME
    // canonicalized path repair will actually build internally, not
    // the raw `tempdir()` path -- on a host where the temp directory
    // itself sits behind a symlink (e.g. macOS's `/var` ->
    // `/private/var`, under which `TMPDIR` lives), those two differ:
    // arming the raw path would silently never match, and the real
    // (non-deferred) `write_placeholder` would run instead, leaving an
    // actual placeholder file this test's own sanity assertion below
    // expects to be absent.
    let canonical_root = root.path().canonicalize().unwrap();
    let out_path = canonical_root.join("missing-deferred.bin");
    yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
        &out_path, true,
    );
    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    );
    yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
        &out_path, false,
    );
    let report = report.unwrap();

    assert_eq!(report.demoted_to_placeholder, vec!["missing-deferred.bin"]);
    assert!(
        !root.path().join("missing-deferred.bin").exists(),
        "sanity: the deferred placeholder write must genuinely be absent"
    );
    assert!(
        state
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "missing-deferred.bin")
            .unwrap(),
        "a materialization intent must protect this path while its real placeholder \
         creation is deferred to cfapi-host.exe -- clearing it here removes the only \
         thing telling the tombstone loop this is not a genuine offline deletion"
    );
}

/// Leaves `rel_path` as a materialization in flight: its intent open and its row
/// in the transient in-flight state, with nothing yet published to disk. This
/// is the window a crash can land in, which repair has to resolve.
fn open_optimistic_row(
    state: &ReplicaCoordinator,
    group_id: &str,
    rel_path: &str,
    record: &FileRecord,
    unix_mode: Option<u32>,
) {
    let metadata = LocalFileMetaColumns {
        record_kind: RecordKind::File,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode,
        xattrs: Vec::new(),
    };
    let target = yadorilink_local_storage::intent_target_hash(&record.blocks);
    state
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            yadorilink_sync_sqlite::MaterializationIntentRepository::begin_materialization_intent_in_tx(
                tx, group_id, rel_path, &target, 0,
            )?;
            yadorilink_sync_sqlite::file_index::upsert_file_in_tx(tx, group_id, record, "device-b")?;
            yadorilink_sync_sqlite::MaterializationStateRepository::set_materialization_state_in_tx(
                tx,
                group_id,
                rel_path,
                yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
            )?;
            yadorilink_sync_sqlite::file_index::apply_local_meta_columns_in_tx(
                tx, group_id, rel_path, &metadata,
            )?;
            yadorilink_sync_sqlite::MaterializationStateRepository::clear_held_in_tx(
                tx, group_id, rel_path,
            )?;
            Ok(())
        })
        .unwrap();
}

/// A bounded batch commits the row+intent for every upsert in one
/// transaction, before ANY of their temp files publish to their final
/// path. A crash in exactly that window -- after this commits, but
/// before `try_commit_ordinary_batch`'s own per-path `persist_
/// reconstructed_file` call ever runs for this candidate -- must look
/// identical to an unbatched `materialize()`'s own crash-after-intent-
/// open window to the existing repair pass: reconstructed from the
/// still-locally-present blocks, not silently classified as an offline
/// deletion.
#[test]
fn a_crash_after_the_batch_commits_a_rows_intent_but_before_its_disk_publish_is_repaired_from_local_blocks(
) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"batched upsert content, never published before the simulated crash";
    let record = store_and_record(&store, "batched.txt", content);
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();

    open_optimistic_row(&state, "group-1", "batched.txt", &record, None);
    assert!(
        !root.path().join("batched.txt").exists(),
        "sanity: this test's whole point is that the disk publish never happened"
    );
    assert!(state
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "batched.txt")
        .unwrap());

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["batched.txt".to_string()]);
    assert!(report.offline_deleted.is_empty(), "must not be misread as an offline deletion");
    assert_eq!(std::fs::read(root.path().join("batched.txt")).unwrap(), content);
}

/// The ordinary batch's other crash window: `try_commit_ordinary_batch` has already
/// published this candidate's temp file to its final path, but crashes
/// before its own `finalize_projected_mutations_batch` call -- so the
/// row stays `Present` with a dangling open intent and no recorded
/// fingerprint. The published bytes already match the index, so repair
/// must recognize this as already-complete and just drop the stale
/// intent (matching an unbatched `materialize()`'s identical crash-
/// after-rename-before-intent-clear window) -- never quarantine or
/// otherwise disturb the correct, already-durable file.
///
/// The eager content write has the same window: its bytes are durable
/// and its one commit -- proof, stamp, intent clear and the claimed
/// obligation's completion -- never ran. The path's obligation is open
/// across the crash, and repair leaves it open: closing it is a claim's
/// business, never repair's. The next claim then closes it against the
/// proof repair restored, with no physical work, and a second repair finds
/// nothing to do.
#[test]
fn a_crash_after_the_batchs_disk_publish_but_before_finalize_only_clears_the_stale_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"batched upsert content, published to disk before the simulated crash";
    let record = store_and_record(&store, "batched2.txt", content);
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();

    open_optimistic_row(&state, "group-1", "batched2.txt", &record, None);
    state
        .sqlite()
        .dag_bump_projection_obligations_for_touched_paths("group-1", &["batched2.txt"], 0)
        .unwrap();
    let claimed = state
        .sqlite()
        .dag_lookup_projection_obligation("group-1", "batched2.txt")
        .unwrap()
        .expect("an armed obligation");
    // Stands in for `try_commit_ordinary_batch`'s own `persist_
    // reconstructed_file` publish, which this test does not need to
    // exercise again (already covered by `yadorilink-local-storage`'s
    // own tests) -- only the resulting on-disk state matters here.
    std::fs::write(root.path().join("batched2.txt"), content).unwrap();
    assert!(state
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "batched2.txt")
        .unwrap());

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert!(report.reconstructed.is_empty());
    assert!(report.quarantined_dirty.is_empty());
    assert!(report.offline_deleted.is_empty());
    assert!(
        !state
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "batched2.txt")
            .unwrap(),
        "repair must clear the stale intent once it confirms the published bytes already \
         match the index"
    );
    assert_eq!(std::fs::read(root.path().join("batched2.txt")).unwrap(), content);
    assert_eq!(
        state.sqlite().dag_lookup_projection_obligation("group-1", "batched2.txt").unwrap(),
        Some(claimed.clone()),
        "repair must leave the obligation exactly as the crash left it"
    );

    let version = state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::read_canonical_current_row(conn, "group-1", "batched2.txt")
        })
        .unwrap()
        .expect("the row")
        .version_hash();
    assert!(
        state
            .complete_zero_work_obligation(
                "group-1",
                "batched2.txt",
                claimed.invalidation_generation,
                claimed.obligation_incarnation,
                &yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version,
                    identity: Box::new(None),
                },
            )
            .unwrap(),
        "the next claim closes the obligation against the proof repair restored"
    );

    let again = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();
    assert!(again.reconstructed.is_empty() && again.quarantined_dirty.is_empty());
    assert!(again.offline_deleted.is_empty(), "a second repair finds nothing to do");
    assert_eq!(std::fs::read(root.path().join("batched2.txt")).unwrap(), content);
}

/// The version a row names is a hash over the mode and the xattrs as
/// well as the bytes, so bytes that match are not yet the version. A
/// lane that crashes after its bytes land and before its mode is applied
/// leaves the row's intent open over the right bytes
/// with the old mode. Repair's disk-matches arm used to prove the version
/// on the bytes alone, publishing an exact proof of a mode disk never got.
#[cfg(unix)]
#[test]
fn repair_does_not_prove_a_version_whose_mode_disk_never_got() {
    use std::os::unix::fs::PermissionsExt;
    const GROUP: &str = "group-repair-mode-mismatch";
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"#!/bin/sh\necho the version says this is executable\n";
    let record = store_and_record(&store, "run.sh", content);
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    open_optimistic_row(&state, GROUP, "run.sh", &record, Some(0o755));
    // The crash: the bytes landed, the exec bit never did.
    let out_path = root.path().join("run.sh");
    std::fs::write(&out_path, content).unwrap();
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    let disk_mode = std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
    let proven =
        MaterializationExecutionPort::has_usable_materialized_generation(&state, GROUP, "run.sh")
            .unwrap();
    assert!(
        !(proven && disk_mode != 0o755),
        "repair proved a version whose mode is 0o755 over a file whose mode is {disk_mode:o}"
    );
    assert_eq!(std::fs::read(&out_path).unwrap(), content);
    assert_eq!(disk_mode, 0o755, "repair finishes the write by applying the version's mode");
    assert!(proven, "and then proves what it wrote");
}

/// Sets up a file row already transitioned to `Remote` -- matching
/// every real caller, which always pairs `record_placeholder_generation`
/// with that same transition (never calls it on a `Present` row).
fn setup_placeholder_file(
    group_id: &str,
    path: &str,
) -> (ReplicaCoordinator, RootCommitPermit<'static>) {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let permit = RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(group_id, &record_with_blocks(path, b"x", vec![0xab; 32]), &permit)
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(group_id, path, MaterializationState::Remote, &permit)
        .unwrap();
    (state, permit)
}

fn recorded(
    identity: yadorilink_local_storage::PlaceholderDiskIdentity,
) -> yadorilink_sync_sqlite::RecordedPlaceholderGeneration {
    yadorilink_sync_sqlite::RecordedPlaceholderGeneration {
        identity,
        provider_kind: "internal-inode".to_owned(),
    }
}

/// A recorded placeholder identity survives an in-process
/// "restart" (a fresh read through the repository, not merely an
/// in-memory cache). `provider_kind` round-trips too, not merely the
/// `(dev, ino)` pair.
#[test]
fn recorded_placeholder_generation_is_readable_after_being_recorded() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
    let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 7, ino: 42 };

    state
        .materialization_state_repository()
        .record_placeholder_generation("group-1", "doc.txt", identity, "internal-inode", &permit)
        .unwrap();

    assert_eq!(
        state
            .materialization_state_repository()
            .get_placeholder_generation("group-1", "doc.txt")
            .unwrap(),
        Some(recorded(identity))
    );
}

/// `record_placeholder_generation_if_absent` must do its
/// check-then-write atomically in one `database.write` closure -- pins
/// the race a two-call form would have (`get_placeholder_generation` then a separate
/// `record_placeholder_generation`): a second "concurrent" mint for
/// the same path with a DIFFERENT candidate identity must lose, not
/// silently overwrite the first winner.
#[test]
fn record_placeholder_generation_if_absent_keeps_the_first_winner() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
    let first = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 1 };
    let second = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 2 };

    let winner_a = state
        .materialization_state_repository()
        .record_placeholder_generation_if_absent(
            "group-1",
            "doc.txt",
            first,
            "windows-cfapi-generation",
            &permit,
        )
        .unwrap();
    let winner_b = state
        .materialization_state_repository()
        .record_placeholder_generation_if_absent(
            "group-1",
            "doc.txt",
            second,
            "windows-cfapi-generation",
            &permit,
        )
        .unwrap();

    assert_eq!(winner_a, first);
    assert_eq!(winner_b, first, "the second caller must see the first caller's winning value");
    assert_eq!(
        state
            .materialization_state_repository()
            .get_placeholder_generation("group-1", "doc.txt")
            .unwrap()
            .unwrap()
            .identity,
        first,
        "the persisted row must still hold the first-minted identity, never the second"
    );
}

/// A row already carrying a DIFFERENT provider's identity (e.g. the
/// Unix `(dev, ino)` scheme) is treated as "nothing recorded for THIS
/// provider yet" and overwritten -- matches
/// `record_placeholder_generation`'s own unconditional behavior for
/// that case, which this method must not silently change.
#[test]
fn record_placeholder_generation_if_absent_overwrites_a_different_providers_identity() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
    let unix_identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 7, ino: 42 };
    state
        .materialization_state_repository()
        .record_placeholder_generation(
            "group-1",
            "doc.txt",
            unix_identity,
            "internal-inode",
            &permit,
        )
        .unwrap();

    let windows_identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 99 };
    let winner = state
        .materialization_state_repository()
        .record_placeholder_generation_if_absent(
            "group-1",
            "doc.txt",
            windows_identity,
            "windows-cfapi-generation",
            &permit,
        )
        .unwrap();

    assert_eq!(winner, windows_identity);
}

/// A path with no recorded identity -- never placeholdered, or cleared
/// -- must read back `None`, not a synthetic zero identity: callers
/// treat `None` as fail-closed "unknown", which a real `dev:0, ino:0`
/// row would defeat.
#[test]
fn unrecorded_placeholder_generation_reads_back_as_none() {
    let (state, _permit) = setup_placeholder_file("group-1", "doc.txt");

    assert_eq!(
        state
            .materialization_state_repository()
            .get_placeholder_generation("group-1", "doc.txt")
            .unwrap(),
        None
    );
}

/// A row that has since left
/// `Remote` (hydrated, say) must never expose its old identity
/// through this getter, even though nothing explicitly cleared it --
/// gated on the row's own current `materialization_state`, not merely
/// on the recorded columns being non-NULL.
#[test]
fn placeholder_generation_is_hidden_once_the_row_leaves_placeholder_state() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
    let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 1, ino: 1 };
    let repo = state.materialization_state_repository();
    repo.record_placeholder_generation("group-1", "doc.txt", identity, "internal-inode", &permit)
        .unwrap();

    repo.set_materialization_state("group-1", "doc.txt", MaterializationState::Present, &permit)
        .unwrap();

    assert_eq!(repo.get_placeholder_generation("group-1", "doc.txt").unwrap(), None);
}

/// The opposite property from the test above, on the OTHER
/// accessor -- `get_recorded_placeholder_identity` must keep exposing
/// a row's identity after it leaves `Remote` for `Present`,
/// since Windows eviction reads a `Present` file's still-recorded
/// generation as the expected identity for its native dehydrate call.
/// If this ever regressed to also gating on `materialization_state =
/// 'placeholder'` (e.g. by accidentally sharing `get_placeholder_
/// generation`'s query), `evict_to_placeholder`'s Windows arm would
/// treat every genuinely-placeholdered `Present` file as having "no
/// recorded identity" and refuse to evict it at all.
#[test]
fn recorded_placeholder_identity_survives_the_hydrated_transition() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
    let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 7 };
    let repo = state.materialization_state_repository();
    repo.record_placeholder_generation(
        "group-1",
        "doc.txt",
        identity,
        "windows-cfapi-generation",
        &permit,
    )
    .unwrap();

    repo.set_materialization_state("group-1", "doc.txt", MaterializationState::Present, &permit)
        .unwrap();

    // The dirty-detection accessor hides it (previous test) ...
    assert_eq!(repo.get_placeholder_generation("group-1", "doc.txt").unwrap(), None);
    // ... but the eviction accessor still sees it.
    assert_eq!(
        repo.get_recorded_placeholder_identity("group-1", "doc.txt").unwrap(),
        Some(yadorilink_sync_sqlite::RecordedPlaceholderGeneration {
            identity,
            provider_kind: "windows-cfapi-generation".to_owned(),
        })
    );
    assert_eq!(
        state.get_recorded_placeholder_identity("group-1", "doc.txt").unwrap(),
        Some((identity, "windows-cfapi-generation".to_owned()))
    );
}

/// A newer placeholder write's identity must fully replace an older
/// one -- `record_placeholder_generation` called twice for the same
/// path leaves only the SECOND identity readable, never a stale first
/// one a caller could wrongly trust. This is the exact "stale
/// generation must not be trusted" invariant.
#[test]
fn recording_a_new_generation_replaces_the_old_one() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
    let stale = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 1, ino: 1 };
    let fresh = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 1, ino: 2 };
    let repo = state.materialization_state_repository();
    repo.record_placeholder_generation("group-1", "doc.txt", stale, "internal-inode", &permit)
        .unwrap();

    repo.record_placeholder_generation("group-1", "doc.txt", fresh, "internal-inode", &permit)
        .unwrap();

    assert_eq!(
        repo.get_placeholder_generation("group-1", "doc.txt").unwrap(),
        Some(recorded(fresh))
    );
}

/// `clear_placeholder_generation` must actually erase the recorded
/// identity, not merely become unreachable -- a stale identity left in
/// place after a hydrate (say) could later be wrongly matched against a
/// brand-new placeholder that happens to reuse the same inode number.
#[test]
fn clearing_a_placeholder_generation_removes_it() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");
    let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 1, ino: 1 };
    let repo = state.materialization_state_repository();
    repo.record_placeholder_generation("group-1", "doc.txt", identity, "internal-inode", &permit)
        .unwrap();

    repo.clear_placeholder_generation("group-1", "doc.txt", &permit).unwrap();

    assert_eq!(repo.get_placeholder_generation("group-1", "doc.txt").unwrap(), None);
}

/// Clearing a path that was never recorded is a no-op, not an error --
/// mirrors `clear_held`'s own precedent so callers never need to check
/// "was this ever a placeholder" first.
#[test]
fn clearing_an_unrecorded_placeholder_generation_is_not_an_error() {
    let (state, permit) = setup_placeholder_file("group-1", "doc.txt");

    state
        .materialization_state_repository()
        .clear_placeholder_generation("group-1", "doc.txt", &permit)
        .unwrap();
}

/// `list_placeholder_generations` is the bulk-load path
/// `LocalChangeProcessor::scan_existing_files` will use -- it must
/// include every recorded identity for the group and exclude paths
/// with none, in one call.
#[test]
fn list_placeholder_generations_includes_only_recorded_paths() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let permit = RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file("group-1", &record_with_blocks("has-one.bin", b"x", vec![0xab; 32]), &permit)
        .unwrap();
    state
        .file_index_repository()
        .upsert_file("group-1", &record_with_blocks("has-none.bin", b"y", vec![0xcd; 32]), &permit)
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state("group-1", "has-one.bin", MaterializationState::Remote, &permit)
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state("group-1", "has-none.bin", MaterializationState::Remote, &permit)
        .unwrap();
    let identity = yadorilink_local_storage::PlaceholderDiskIdentity { dev: 9, ino: 99 };
    state
        .materialization_state_repository()
        .record_placeholder_generation(
            "group-1",
            "has-one.bin",
            identity,
            "internal-inode",
            &permit,
        )
        .unwrap();

    let all =
        state.materialization_state_repository().list_placeholder_generations("group-1").unwrap();

    assert_eq!(all.get("has-one.bin"), Some(&recorded(identity)));
    assert!(!all.contains_key("has-none.bin"));
}

/// `RepairRowSnapshot` is named for a property it has to actually
/// have.
///
/// It used to take the version, authoring and state from one canonical
/// statement and then go back to the database twice more for the kind
/// and the record -- three read transactions with no isolation
/// spanning them. The struct could carry the version and authoring of
/// one incarnation of the row beside the blocks and kind of another,
/// and repair would then check a guard built from the first against
/// bytes chosen by the second.
///
/// The path lock does not close that: native admission does not take it,
/// so a supersession can land while a live repair pass is between reads.
mod repair_row_snapshot {
    use super::*;

    const GROUP: &str = "g";
    const PATH: &str = "notes.txt";

    fn record(size: u64, hash: u8) -> FileRecord {
        FileRecord {
            path: PATH.into(),
            size,
            mtime_unix_nanos: 0,
            blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                hash: vec![hash; 32],
                offset: 0,
                size: size as u32,
            }],
            deleted: false,
        }
    }

    /// Every field describes the same row, including the two that used
    /// to be fetched separately.
    #[test]
    fn every_field_comes_from_the_same_incarnation_of_the_row() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let permit = RootCommitPermit::for_tests();
        coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &record(4, 1), "device-a", &permit)
            .unwrap();
        coordinator
            .file_index_repository()
            .set_symlink_target(GROUP, PATH, Some(b"../elsewhere"))
            .unwrap();
        coordinator
            .file_index_repository()
            .set_record_kind(GROUP, PATH, RecordKind::Symlink, &permit)
            .unwrap();

        let snapshot = <ReplicaCoordinator as MaterializationExecutionPort>::repair_row_snapshot(
            &coordinator,
            GROUP,
            PATH,
        )
        .unwrap();

        assert_eq!(snapshot.record_kind, Some(RecordKind::Symlink));
        assert_eq!(
            snapshot.symlink_target.as_deref(),
            Some(&b"../elsewhere"[..]),
            "the target must come from the snapshot, not a fourth read at the point of use"
        );
        let file = snapshot.file.expect("a current row");
        assert_eq!(file.size, 4);
        assert!(snapshot.current_version.is_some());
    }

    /// The version a guard is built from and the blocks a verification
    /// runs against must move together. A read taken after a
    /// supersession must never yield the old version beside the new
    /// blocks.
    #[test]
    fn a_supersession_moves_every_field_together() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let permit = RootCommitPermit::for_tests();
        coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &record(4, 1), "device-a", &permit)
            .unwrap();
        let before = <ReplicaCoordinator as MaterializationExecutionPort>::repair_row_snapshot(
            &coordinator,
            GROUP,
            PATH,
        )
        .unwrap();

        coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &record(7, 9), "device-a", &permit)
            .unwrap();
        let after = <ReplicaCoordinator as MaterializationExecutionPort>::repair_row_snapshot(
            &coordinator,
            GROUP,
            PATH,
        )
        .unwrap();

        assert_ne!(before.current_version, after.current_version, "the version must move");
        assert_ne!(
            before.file.as_ref().unwrap().blocks,
            after.file.as_ref().unwrap().blocks,
            "and so must the blocks -- a snapshot holding one of each is the defect"
        );
        assert_eq!(after.file.as_ref().unwrap().size, 7);
    }

    /// A path with no current row answers empty rather than a
    /// half-built struct whose `file` came from a row its
    /// `current_version` did not.
    #[test]
    fn a_missing_row_yields_nothing_rather_than_a_partial_snapshot() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let snapshot = <ReplicaCoordinator as MaterializationExecutionPort>::repair_row_snapshot(
            &coordinator,
            GROUP,
            "never-seen",
        )
        .unwrap();
        assert!(snapshot.file.is_none());
        assert!(snapshot.current_version.is_none());
        assert!(snapshot.record_kind.is_none());
        assert!(snapshot.symlink_target.is_none());
        assert!(snapshot.materialization_state.is_none());
    }
}

/// Eviction and repair-sweep failures that are local to one path. A read-only
/// parent directory makes the placeholder write fail before its rename,
/// after the eviction has already marked the row `Evicting` and bumped the
/// path's fence; an unreadable file makes the repair sweep's byte compare
/// fail. Each test probes first that the permission actually denies this
/// process (a root user is not denied) and returns early when it does not.
#[cfg(unix)]
mod path_local_failure_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use yadorilink_filesystem_sync::materialization_execution::AbandonedEviction;

    const GROUP: &str = "group-path-local-failure";

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Makes `dir` read-only; `false` (and the mode restored) when this
    /// process can still create a file in it.
    fn make_dir_unwritable(dir: &Path) -> bool {
        set_mode(dir, 0o555);
        let probe = dir.join(".write-probe");
        if std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            set_mode(dir, 0o755);
            return false;
        }
        true
    }

    fn hydrated_on_disk(
        state: &ReplicaCoordinator,
        store: &SegmentBlockStore,
        root: &Path,
        path: &str,
        content: &[u8],
        permit: &RootCommitPermit,
    ) {
        let record = store_and_record(store, path, content);
        upsert_hydrated_file(state, GROUP, &record, permit);
        let out_path = root.join(path);
        std::fs::create_dir_all(out_path.parent().unwrap()).unwrap();
        std::fs::write(out_path, content).unwrap();
    }

    fn row_state(state: &ReplicaCoordinator, path: &str) -> Option<MaterializationState> {
        state.materialization_state_repository().get_materialization_state(GROUP, path).unwrap()
    }

    /// A failure after the fence bump must not leave the row `Evicting`
    /// until the next daemon start: nothing but the startup reset moves a
    /// row out of it, so the file stays reported as in flight, is no longer
    /// an eviction candidate and is not a repair candidate. The write never
    /// landed and the bytes still verify, so the row goes back to
    /// `Present` with a proof published under the bumped fence.
    #[test]
    fn an_eviction_whose_placeholder_write_fails_goes_back_to_hydrated_with_a_proof() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        let content = b"bytes an eviction failed to replace";
        hydrated_on_disk(&state, &store, root.path(), "dir/a.bin", content, &permit);
        let dir = root.path().join("dir");
        if !make_dir_unwritable(&dir) {
            return;
        }

        let result = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            GROUP,
            "dir/a.bin",
            false,
            &NeverConfirms,
        );
        set_mode(&dir, 0o755);

        assert!(result.is_err(), "the placeholder write failed, got {result:?}");
        assert_eq!(std::fs::read(root.path().join("dir/a.bin")).unwrap(), content);
        assert_eq!(
            row_state(&state, "dir/a.bin"),
            Some(MaterializationState::Present),
            "a failed eviction must not leave its row Evicting"
        );
        assert!(
            MaterializationExecutionPort::has_usable_materialized_generation(
                &state,
                GROUP,
                "dir/a.bin"
            )
            .unwrap(),
            "the verified bytes are proven again under the fence the attempt bumped"
        );
    }

    /// The repair sweep, the same way: an unreadable file stops only its
    /// own repair, and the pass still re-proves the next path.
    #[test]
    fn a_repair_sweep_continues_past_one_paths_unreadable_file() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "a.bin", b"unreadable to this user", &permit);
        hydrated_on_disk(&state, &store, root.path(), "b.bin", b"readable, needs a proof", &permit);
        let unreadable = root.path().join("a.bin");
        set_mode(&unreadable, 0o000);
        if std::fs::read(&unreadable).is_ok() {
            set_mode(&unreadable, 0o644);
            return;
        }

        let result = repair_interrupted_materializations(
            &state,
            &store,
            root.path(),
            GROUP,
            RepairMode::Startup,
            &permit,
        );
        set_mode(&unreadable, 0o644);

        let report = result.expect("one path's read failure must not fail the sweep");
        assert_eq!(report.reproven, vec!["b.bin".to_owned()]);
        assert_eq!(report.failed, vec!["a.bin".to_owned()], "and the failed path is reported");
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Present));
    }

    /// A failed eviction's own failure is logged only when it, too, belongs
    /// to the path. When closing the row fails for a reason the whole
    /// transaction shares (a database failure), the eviction returns that
    /// error rather than the path-local one it was already carrying.
    #[test]
    fn a_failed_evictions_transaction_wide_abandon_failure_is_what_it_returns() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "dir/a.bin", b"cannot be replaced", &permit);
        let dir = root.path().join("dir");
        if !make_dir_unwritable(&dir) {
            return;
        }
        state
            .test_observers
            .abandon_eviction_fails
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let result = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            GROUP,
            "dir/a.bin",
            false,
            &NeverConfirms,
        );
        set_mode(&dir, 0o755);

        assert!(
            matches!(result, Err(MaterializationExecutionError::CorruptState(_))),
            "the abandon's transaction-wide failure is what the eviction returns: {result:?}"
        );
    }

    /// Group-wide failures are told apart at their source, not by the
    /// error's variant: every eviction re-verifies the root before it
    /// touches anything, so a root that lost its identity (unmounted,
    /// replaced) fails as a root-authority error, not as a path-local I/O
    /// error, and changes nothing.
    #[test]
    fn an_eviction_under_a_lost_root_fails_as_a_root_authority_error() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "a.bin", b"on a root that is gone", &permit);
        std::fs::remove_file(
            root.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();

        let result = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &permit,
            },
            GROUP,
            "a.bin",
            false,
            &NeverConfirms,
        );

        assert!(
            matches!(result, Err(MaterializationExecutionError::RootAuthority(_))),
            "a lost root must fail as a root-authority error: {result:?}"
        );
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Present));
    }

    /// A held root lease whose root this process no longer owns: the lock
    /// sidecar was replaced, so every permit from it fails to verify, and
    /// fails as an I/O error, the variant a path-local failure also uses.
    fn lost_root_operation(
        locked: &Path,
    ) -> yadorilink_root_authority::root_commit::LinkOperation<'static> {
        let lock =
            yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(locked).unwrap();
        let lease: &'static _ = Box::leak(Box::new(
            yadorilink_root_authority::root_commit::RootLease::new(lock, GROUP.to_string(), 0),
        ));
        let operation = lease.begin_operation().unwrap();
        let lock_path =
            locked.join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::File::create(&lock_path).unwrap();
        assert!(
            operation.permit().verify().is_err(),
            "fixture check: the root must really look lost, or this test proves nothing"
        );
        operation
    }

    /// A root lost while an eviction runs fails the eviction at its first
    /// owner transaction, and changes nothing.
    #[test]
    fn an_eviction_whose_root_is_lost_mid_operation_fails_and_changes_nothing() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let setup_permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "a.bin", b"first", &setup_permit);
        let locked = tempfile::tempdir().unwrap();
        let operation = lost_root_operation(locked.path());

        let result = evict_file(
            MaterializationContext {
                state: &state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &store,
                root: root.path(),
                permit: &operation.permit(),
            },
            GROUP,
            "a.bin",
            false,
            &NeverConfirms,
        );

        assert!(result.is_err(), "a root lost mid-operation must fail the eviction: {result:?}");
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Present));
    }

    /// The repair sweep stops at a root lost mid-sweep.
    #[test]
    fn a_repair_sweep_stops_when_its_root_is_lost_mid_sweep() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let setup_permit = RootCommitPermit::for_tests();
        hydrated_on_disk(&state, &store, root.path(), "a.bin", b"needs a proof", &setup_permit);
        hydrated_on_disk(&state, &store, root.path(), "b.bin", b"so does this", &setup_permit);
        let locked = tempfile::tempdir().unwrap();
        let operation = lost_root_operation(locked.path());

        let result = repair_interrupted_materializations(
            &state,
            &store,
            root.path(),
            GROUP,
            RepairMode::Startup,
            &operation.permit(),
        );

        assert!(
            matches!(result, Err(MaterializationExecutionError::RootAuthority(_))),
            "a root lost mid-sweep must abort the sweep: {result:?}"
        );
    }

    /// A row the eviction lane left `Evicting` over `content` on disk, and
    /// the version it names.
    fn evicting_row(
        state: &ReplicaCoordinator,
        root: &Path,
        path: &str,
        content: &[u8],
    ) -> VersionHash {
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let permit = RootCommitPermit::for_tests();
        hydrated_on_disk(state, &store, root, path, content, &permit);
        state
            .materialization_state_repository()
            .set_materialization_state(GROUP, path, MaterializationState::Evicting, &permit)
            .unwrap();
        state
            .file_index_repository()
            .canonical_current_row(GROUP, path)
            .unwrap()
            .unwrap()
            .version_hash()
    }

    fn has_proof(state: &ReplicaCoordinator, path: &str) -> bool {
        MaterializationExecutionPort::has_usable_materialized_generation(state, GROUP, path)
            .unwrap()
    }

    fn abandon(
        state: &ReplicaCoordinator,
        path: &str,
        version: &VersionHash,
        abandoned: AbandonedEviction,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError> {
        MaterializationExecutionPort::abandon_eviction(
            state, GROUP, path, version, abandoned, permit,
        )
    }

    #[test]
    fn an_abandoned_eviction_whose_file_no_longer_verifies_goes_back_to_hydrated_unproven() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let version = evicting_row(&state, root.path(), "a.bin", b"edited during the attempt");

        let permit = RootCommitPermit::for_tests();
        assert!(abandon(&state, "a.bin", &version, AbandonedEviction::NotWritten, &permit).unwrap());
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Present));
        assert!(!has_proof(&state, "a.bin"), "bytes that did not verify earn no proof");
    }

    #[test]
    fn an_abandoned_eviction_whose_placeholder_may_exist_resolves_to_placeholder() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let version = evicting_row(&state, root.path(), "a.bin", b"dehydrated, or maybe not");

        let permit = RootCommitPermit::for_tests();
        assert!(abandon(
            &state,
            "a.bin",
            &version,
            AbandonedEviction::PlaceholderMayExist,
            &permit
        )
        .unwrap());
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Remote));
    }

    /// The row moved to another version while it was `Evicting`: whatever
    /// the file holds, it is not that version, so no claim of `Present`
    /// and no proof, even for bytes that verified against the old one.
    #[test]
    fn an_abandoned_eviction_of_a_row_now_naming_another_version_resolves_to_placeholder() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        evicting_row(&state, root.path(), "a.bin", b"the version the eviction revalidated");
        let identity = yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(
            &root.path().join("a.bin"),
        )
        .unwrap();
        let other_version = VersionHash([7u8; 32]);

        let permit = RootCommitPermit::for_tests();
        assert!(abandon(
            &state,
            "a.bin",
            &other_version,
            AbandonedEviction::Intact { identity },
            &permit
        )
        .unwrap());
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Remote));
        assert!(!has_proof(&state, "a.bin"));
    }

    #[test]
    fn abandoning_a_row_that_already_left_evicting_writes_nothing() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let version = evicting_row(&state, root.path(), "a.bin", b"settled by someone else");
        let permit = RootCommitPermit::for_tests();
        state
            .materialization_state_repository()
            .set_materialization_state(GROUP, "a.bin", MaterializationState::Remote, &permit)
            .unwrap();

        assert!(
            !abandon(&state, "a.bin", &version, AbandonedEviction::NotWritten, &permit).unwrap()
        );
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Remote));
    }

    /// Root swap: the permit is verified inside the abandon's transaction,
    /// so under a lost root it publishes no proof and moves nothing; the
    /// row stays `Evicting` for the startup reset rather than committing a
    /// claim about a root this device no longer owns.
    #[test]
    fn an_abandoned_eviction_under_a_lost_root_writes_nothing() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, GROUP, root.path());
        let version = evicting_row(&state, root.path(), "a.bin", b"bytes under a swapped root");
        let identity = yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(
            &root.path().join("a.bin"),
        )
        .unwrap();
        let locked = tempfile::tempdir().unwrap();
        let lock = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(locked.path())
            .unwrap();
        let lease =
            yadorilink_root_authority::root_commit::RootLease::new(lock, GROUP.to_string(), 0);
        let operation = lease.begin_operation().unwrap();
        let lock_path =
            locked.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::File::create(&lock_path).unwrap();
        assert!(
            operation.permit().verify().is_err(),
            "fixture check: the root must really look lost, or this test proves nothing"
        );

        let outcome = abandon(
            &state,
            "a.bin",
            &version,
            AbandonedEviction::Intact { identity },
            &operation.permit(),
        );

        assert!(outcome.is_err(), "an abandon under a lost root must fail");
        assert_eq!(row_state(&state, "a.bin"), Some(MaterializationState::Evicting));
        assert!(!has_proof(&state, "a.bin"), "nothing may be published under a lost root");
    }
}

/// Runs a startup repair over one Hydrated row with an open intent, carrying
/// `mode` and `xattrs`, and reports what it reconstructed.
#[cfg(target_os = "linux")]
fn repair_one_with_metadata(
    mode: u32,
    xattrs: &[(String, Vec<u8>)],
) -> (ReplicaCoordinator, tempfile::TempDir, Vec<String>) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt with replicated metadata";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    state.file_index_repository().set_unix_mode("group-1", "doc.txt", Some(mode), &permit).unwrap();
    state.file_index_repository().set_xattrs("group-1", "doc.txt", xattrs, &permit).unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();
    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();
    (state, root, report.reconstructed)
}

/// Repair's reconstruct must not publish an exact proof when the replicated
/// attributes it set cannot be confirmed (a name the kernel rejects makes the
/// set fail silently), even though its bytes and mode landed.
#[cfg(target_os = "linux")]
#[test]
fn a_repair_reconstruct_publishes_no_proof_when_its_xattrs_cannot_be_confirmed() {
    let unsettable = vec![(format!("user.{}", "a".repeat(300)), b"v".to_vec())];

    let (state, _root, reconstructed) = repair_one_with_metadata(0o644, &unsettable);

    assert!(reconstructed.is_empty(), "an unproven reconstruct must not be reported as done");
    assert!(!MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
}

/// The positive half: valid attributes with a final owner-unreadable mode
/// reach the proof, on the check taken before the mode was applied.
#[cfg(target_os = "linux")]
#[test]
fn a_repair_reconstruct_to_an_owner_unreadable_mode_reaches_a_proof_with_its_xattr() {
    use std::os::unix::fs::PermissionsExt;
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];

    let (state, root, reconstructed) = repair_one_with_metadata(0o200, &xattrs);

    assert_eq!(reconstructed, vec!["doc.txt"]);
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
    let out_path = root.path().join("doc.txt");
    assert_eq!(std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777, 0o200);
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        yadorilink_local_storage::read_replicated_xattrs(&std::fs::File::open(&out_path).unwrap()),
        xattrs
    );
}

/// Journals a restore of `doc.txt` whose version carries `mode` and
/// `xattrs`, leaves only its bytes on disk (as a process that died after
/// the rename and before applying the metadata would), then lets `prepare`
/// adjust the file and runs startup restore recovery.
#[cfg(target_os = "linux")]
fn recover_restore_with_metadata(
    mode: u32,
    xattrs: &[(String, Vec<u8>)],
    prepare: impl FnOnce(&Path),
) -> ReplicaCoordinator {
    let content = b"restored bytes left behind by a crash";
    let hash = <sha2::Sha256 as sha2::Digest>::digest(content).to_vec();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    state
        .restore_operation_repository()
        .record_restore_operation(&yadorilink_replica_domain::session_state::RestoreOperation {
            operation_id: "op-1".to_string(),
            group_id: "group-1".to_string(),
            path: "doc.txt".to_string(),
            target_version_seq: 1,
            expected_current_version_seq: None,
            state: yadorilink_replica_domain::session_state::RestoreOperationState::DiskCommitted,
            record: record_with_blocks("doc.txt", content, hash),
            origin_device_id: "device-a".to_string(),
            meta: LocalFileMetaColumns {
                record_kind: RecordKind::File,
                symlink_target: None,
                symlink_out_of_root: false,
                unix_mode: Some(mode),
                xattrs: xattrs.to_vec(),
            },
        })
        .unwrap();
    let out_path = root.path().join("doc.txt");
    std::fs::write(&out_path, content).unwrap();
    prepare(&out_path);

    yadorilink_filesystem_sync::materialization_repair::reconcile_restore_operations(
        &state,
        root.path(),
        "group-1",
        &permit,
    )
    .unwrap();
    state
}

/// Recovery re-verified only the bytes, then published an exact proof for a
/// version whose mode and xattrs were never applied. It must re-prove them
/// from disk and publish nothing when they do not match.
#[cfg(target_os = "linux")]
#[test]
fn restore_recovery_publishes_no_proof_for_metadata_it_cannot_prove() {
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];

    let state = recover_restore_with_metadata(0o640, &xattrs, |_| {});

    assert!(!MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
}

/// The positive half: when the bytes, the mode and the xattrs on disk are
/// all the journaled version's, recovery publishes its proof.
#[cfg(target_os = "linux")]
#[test]
fn restore_recovery_proves_a_file_whose_metadata_matches() {
    use std::os::unix::fs::PermissionsExt;
    let xattrs = vec![("user.test".to_string(), b"value".to_vec())];

    let state = recover_restore_with_metadata(0o640, &xattrs, |out_path| {
        yadorilink_local_storage::apply_xattrs(out_path, &xattrs).unwrap();
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    });

    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        &state, "group-1", "doc.txt"
    )
    .unwrap());
}

/// Eviction's removal races a user. The hook acts after eviction's last check
/// of the object and before it detaches it.
#[cfg(not(windows))]
mod eviction_race_tests {
    use super::*;
    use yadorilink_filesystem_sync::materialization_eviction::set_pre_removal_hook_for_test;

    struct Setup {
        state: ReplicaCoordinator,
        root: tempfile::TempDir,
        store: SegmentBlockStore,
        _store_dir: tempfile::TempDir,
        permit: RootCommitPermit<'static>,
        _assumed: Option<
            yadorilink_filesystem_sync::materialization_eviction::AssumedExclusionGuardForTest,
        >,
    }

    /// Eviction as on a platform that grants the write exclusion.
    fn setup(content: &[u8]) -> Setup {
        let mut s = setup_real(content);
        s._assumed = Some(
            yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test(),
        );
        s
    }

    /// Eviction on this host's real exclusion: a Linux write lease, none on macOS.
    fn setup_real(content: &[u8]) -> Setup {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "group-a", root.path());
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let record = store_and_record(&store, "a.bin", content);
        let permit = RootCommitPermit::for_tests();
        upsert_hydrated_file(&state, "group-a", &record, &permit);
        std::fs::write(root.path().join("a.bin"), content).unwrap();
        Setup { state, root, store, _store_dir: store_dir, permit, _assumed: None }
    }

    fn evict(s: &Setup) -> yadorilink_filesystem_sync::materialization_eviction::EvictionOutcome {
        evict_file(
            MaterializationContext {
                state: &s.state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &s.store,
                root: s.root.path(),
                permit: &s.permit,
            },
            "group-a",
            "a.bin",
            true,
            &PanicsIfConsulted,
        )
        .unwrap()
    }

    fn state_of(s: &Setup) -> Option<MaterializationState> {
        s.state
            .materialization_state_repository()
            .get_materialization_state("group-a", "a.bin")
            .unwrap()
    }

    fn entries(s: &Setup) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(s.root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    /// The user deletes the file after eviction's last check. That is not an
    /// eviction's own removal: the row must come back `Present` and the
    /// delete must stay evidence (journaled for capture), not be swallowed as
    /// an echo.
    #[test]
    fn a_user_delete_that_beats_the_removal_is_not_settled_as_an_eviction() {
        let s = setup(b"content the user deletes mid-eviction");
        let _hook = set_pre_removal_hook_for_test(|path| std::fs::remove_file(path).unwrap());

        let outcome = evict(&s);

        assert!(!outcome.dehydrated, "a competing delete is not this eviction's removal");
        assert_eq!(state_of(&s), Some(MaterializationState::Present));
        assert!(
            s.state.dirty_path_repository().is_path_dirty("group-a", "a.bin").unwrap(),
            "the user's delete must stay journaled as a removal"
        );
    }

    /// An editor saves (atomic replace, new bytes) after eviction's last
    /// check. Eviction must not destroy the save: it is back at its path, the
    /// row is not `Remote`, and nothing is left under a quarantine name.
    #[test]
    fn a_save_that_lands_before_the_removal_is_preserved() {
        let s = setup(b"content the editor is about to replace");
        let saved: &[u8] = b"the editor's save, never captured";
        let _hook = set_pre_removal_hook_for_test(move |path| {
            let tmp = path.with_file_name("a.bin.saving");
            std::fs::write(&tmp, saved).unwrap();
            std::fs::rename(&tmp, path).unwrap();
        });

        let outcome = evict(&s);

        assert!(!outcome.dehydrated);
        assert_eq!(std::fs::read(s.root.path().join("a.bin")).unwrap(), saved);
        assert_eq!(state_of(&s), Some(MaterializationState::Present));
        assert_eq!(entries(&s), vec!["a.bin".to_string()]);
    }

    /// Putting a detached object back links it to its path and then drops the
    /// quarantine name. The link must be durable before the name that is the
    /// only other reference to the object is unlinked, or a power loss can
    /// keep the unlink and lose the link, and with it the object.
    #[test]
    fn a_restore_makes_the_link_durable_before_it_unlinks_the_quarantine_name_and_the_unlink_after()
    {
        let s = setup(b"content the editor is about to replace");
        let _ = yadorilink_filesystem_sync::materialization_eviction::take_restore_trace_for_test();
        let _hook = set_pre_removal_hook_for_test(move |path| {
            let tmp = path.with_file_name("a.bin.saving");
            std::fs::write(&tmp, b"a save").unwrap();
            std::fs::rename(&tmp, path).unwrap();
        });

        evict(&s);

        assert_eq!(
            yadorilink_filesystem_sync::materialization_eviction::take_restore_trace_for_test(),
            vec!["detached", "synced", "linked", "synced", "unlinked", "synced"]
        );
    }

    /// Eviction's own detach: rename -> directory sync -> verify -> unlink ->
    /// directory sync. Each barrier is what makes the step before it durable
    /// before the next step can be the only thing left of the object.
    #[test]
    fn eviction_orders_its_detach_barriers_around_the_verification_and_the_unlink() {
        let s = setup(b"content to evict, in order");
        let _ = yadorilink_filesystem_sync::materialization_eviction::take_restore_trace_for_test();

        assert!(evict(&s).dehydrated);

        assert_eq!(
            yadorilink_filesystem_sync::materialization_eviction::take_restore_trace_for_test(),
            vec!["detached", "synced", "verified", "unlinked", "synced"]
        );
    }

    /// Something already stands at the quarantine name (a leftover, or a user
    /// file with that name). Eviction must not replace it: it is recovered
    /// first, as a conflict copy because the path is occupied, and the
    /// eviction then proceeds.
    #[test]
    fn an_object_at_the_quarantine_name_is_never_overwritten() {
        let s = setup(b"content to evict");
        let out = s.root.path().join("a.bin");
        let q = yadorilink_filesystem_sync::materialization_eviction::eviction_quarantine_path(
            &out, "a.bin",
        )
        .unwrap();
        std::fs::write(&q, b"a leftover that must survive").unwrap();
        let _ = yadorilink_filesystem_sync::materialization_eviction::take_restore_trace_for_test();

        let outcome = evict(&s);
        // The conflict copy is durable (`synced`) before the eviction goes on.
        assert_eq!(
            yadorilink_filesystem_sync::materialization_eviction::take_restore_trace_for_test(),
            vec!["synced", "detached", "synced", "verified", "unlinked", "synced"]
        );

        assert!(outcome.dehydrated);
        let kept = std::fs::read_dir(s.root.path())
            .unwrap()
            .filter_map(|e| std::fs::read(e.unwrap().path()).ok())
            .any(|bytes| bytes == b"a leftover that must survive");
        assert!(kept, "the object at the quarantine name was destroyed");
    }

    /// A symlink planted at the quarantine name (dangling, or leading outside
    /// the root) is only ever moved, never followed or replaced: eviction
    /// proceeds and the symlink survives as a conflict copy.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_quarantine_name_is_kept_and_never_followed() {
        let s = setup(b"content to evict");
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("victim");
        std::fs::write(&target, b"outside the root").unwrap();
        let out = s.root.path().join("a.bin");
        let q = yadorilink_filesystem_sync::materialization_eviction::eviction_quarantine_path(
            &out, "a.bin",
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, &q).unwrap();

        let outcome = evict(&s);

        assert!(outcome.dehydrated);
        assert_eq!(std::fs::read(&target).unwrap(), b"outside the root");
        let kept = std::fs::read_dir(s.root.path()).unwrap().any(|e| {
            let path = e.unwrap().path();
            std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink()
                && std::fs::read_link(&path).unwrap() == target
        });
        assert!(kept, "the planted symlink was destroyed or followed");
    }

    /// A directory planted at the quarantine name, with content, is kept
    /// whole as a conflict copy and the eviction still completes.
    #[test]
    fn a_directory_at_the_quarantine_name_is_kept_with_its_content() {
        let s = setup(b"content to evict");
        let out = s.root.path().join("a.bin");
        let q = yadorilink_filesystem_sync::materialization_eviction::eviction_quarantine_path(
            &out, "a.bin",
        )
        .unwrap();
        std::fs::create_dir(&q).unwrap();
        std::fs::write(q.join("inner"), b"planted inner file").unwrap();

        let outcome = evict(&s);

        assert!(outcome.dehydrated);
        let kept = std::fs::read_dir(s.root.path()).unwrap().any(|e| {
            let path = e.unwrap().path();
            path.is_dir()
                && std::fs::read(path.join("inner")).ok().as_deref() == Some(b"planted inner file")
        });
        assert!(kept, "the planted directory or its content was destroyed");
    }

    /// Where no atomic no-replace move exists the eviction is NOT performed:
    /// there is no check-then-rename or link-then-unlink fallback, since either
    /// can destroy an object it never looked at. The row stays `Present` over
    /// the untouched file.
    #[test]
    fn without_an_atomic_no_replace_move_the_eviction_fails_closed() {
        let s = setup(b"content that must stay put");
        yadorilink_local_storage::materialize_write::set_test_no_atomic_rename(true);
        let result = evict_file(
            MaterializationContext {
                state: &s.state,
                liveness_gate: &BlockLivenessGate::default(),
                store: &s.store,
                root: s.root.path(),
                permit: &s.permit,
            },
            "group-a",
            "a.bin",
            true,
            &PanicsIfConsulted,
        );
        yadorilink_local_storage::materialize_write::set_test_no_atomic_rename(false);

        assert!(result.is_err(), "the eviction must not be performed: {result:?}");
        assert_eq!(
            std::fs::read(s.root.path().join("a.bin")).unwrap(),
            b"content that must stay put"
        );
        assert_eq!(state_of(&s), Some(MaterializationState::Present));
    }

    /// Nothing settles `Remote` until the unlink is durable. A directory sync
    /// that fails after the unlink (the barrier numbered 2; the first is the
    /// detach's, before it) returns the error and leaves the row `Evicting`,
    /// so startup re-decides.
    #[test]
    fn a_failed_sync_after_the_unlink_leaves_the_row_evicting() {
        // The only barrier after the unlink is the final one.
        let failing = 2;
        {
            let s = setup(b"content whose unlink cannot be made durable");
            yadorilink_filesystem_sync::materialization_eviction::fail_directory_barrier_for_test(
                Some(failing),
            );
            let result = evict_file(
                MaterializationContext {
                    state: &s.state,
                    liveness_gate: &BlockLivenessGate::default(),
                    store: &s.store,
                    root: s.root.path(),
                    permit: &s.permit,
                },
                "group-a",
                "a.bin",
                true,
                &PanicsIfConsulted,
            );
            yadorilink_filesystem_sync::materialization_eviction::fail_directory_barrier_for_test(
                None,
            );

            assert!(result.is_err(), "barrier {failing}: the error must be returned");
            assert_eq!(state_of(&s), Some(MaterializationState::Evicting), "barrier {failing}");
        }
    }

    /// A program opened the file for writing before eviction detached it and writes after the
    /// object was verified. The unlink would make those bytes unreachable, so it must not happen:
    /// without a proof that no writer exists the object goes back to its path, the row stays
    /// `Present`, and nothing is reported as freed.
    #[test]
    fn bytes_written_through_a_pre_opened_handle_after_verification_are_never_lost() {
        use std::io::{Seek, Write};
        let s = setup_real(b"content a program has open for writing");
        let out = s.root.path().join("a.bin");
        let writer = std::fs::OpenOptions::new().write(true).open(&out).unwrap();
        let writer = std::rc::Rc::new(std::cell::RefCell::new(writer));
        let late = writer.clone();
        let _hook =
            yadorilink_filesystem_sync::materialization_eviction::set_pre_unlink_hook_for_test(
                move |_| {
                    let mut w = late.borrow_mut();
                    w.rewind().unwrap();
                    w.write_all(b"WRITTEN AFTER VERIFY, MUST SURVIVE").unwrap();
                    w.sync_all().unwrap();
                },
            );

        let outcome = evict(&s);

        assert!(!outcome.dehydrated, "an eviction over a possible writer must not report success");
        assert_eq!(state_of(&s), Some(MaterializationState::Present));
        let kept = std::fs::read(&out).unwrap();
        assert!(kept.starts_with(b"WRITTEN AFTER VERIFY"), "the late write was lost: {kept:?}");
        assert_eq!(
            entries(&s),
            vec!["a.bin".to_string()],
            "nothing may be left under a quarantine name"
        );
        // The handle still reaches the object that is at the path.
        writer.borrow_mut().write_all(b"+more").unwrap();
        assert!(std::fs::read(&out).unwrap().ends_with(b"+more"));
    }

    /// With the exclusion guaranteed nothing can be writing, and the file is removed as before.
    #[test]
    fn a_guaranteed_exclusion_lets_the_eviction_unlink() {
        let s = setup(b"content nobody has open");
        assert!(evict(&s).dehydrated);
        assert!(!s.root.path().join("a.bin").exists());
        assert_eq!(state_of(&s), Some(MaterializationState::Remote));
    }

    /// Without any program holding the file open, Linux grants the write lease and the file is
    /// removed; macOS has no such primitive and never claims the exclusion, so the file stays.
    #[test]
    fn an_unheld_file_is_removed_only_where_the_os_proves_it() {
        let s = setup_real(b"content nobody has open");
        let outcome = evict(&s);
        let present = s.root.path().join("a.bin").exists();
        if cfg!(target_os = "linux") {
            assert!(outcome.dehydrated && !present);
            assert_eq!(state_of(&s), Some(MaterializationState::Remote));
        } else {
            assert!(!outcome.dehydrated && present);
            assert_eq!(state_of(&s), Some(MaterializationState::Present));
        }
    }

    /// A crash between the verification and the unlink leaves the object under its quarantine
    /// name. A writer that is still alive writes to it there; startup recovery gives it back to
    /// its path with those bytes.
    #[test]
    fn a_crash_before_the_unlink_keeps_a_late_write_and_recovery_restores_it() {
        use std::io::{Seek, Write};
        let s = setup(b"content a program has open for writing");
        let out = s.root.path().join("a.bin");
        let mut writer = std::fs::OpenOptions::new().write(true).open(&out).unwrap();
        let _hook =
            yadorilink_filesystem_sync::materialization_eviction::set_pre_unlink_hook_for_test(
                |_| panic!("injected crash between verification and unlink"),
            );
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| evict(&s)));
        assert!(crashed.is_err());
        assert!(!out.exists(), "the crash leaves the object detached");

        writer.rewind().unwrap();
        writer.write_all(b"WRITTEN AFTER THE CRASH").unwrap();
        yadorilink_filesystem_sync::materialization_eviction::recover_eviction_quarantine(
            &s.state,
            s.root.path(),
            "group-a",
            "a.bin",
        )
        .unwrap();

        assert!(std::fs::read(&out).unwrap().starts_with(b"WRITTEN AFTER THE CRASH"));
        assert_eq!(entries(&s), vec!["a.bin".to_string()]);
    }

    /// A crash after eviction detached the object and before it removed it
    /// leaves the object under its quarantine name. Startup recovery puts it
    /// back (or, if the path is taken, keeps it as a recoverable copy).
    #[test]
    fn a_quarantine_leftover_is_recovered_at_startup() {
        let s = setup(b"content a crash stranded in quarantine");
        let out = s.root.path().join("a.bin");
        let q = yadorilink_filesystem_sync::materialization_eviction::eviction_quarantine_path(
            &out, "a.bin",
        )
        .unwrap();
        std::fs::rename(&out, &q).unwrap();

        yadorilink_filesystem_sync::materialization_eviction::recover_eviction_quarantine(
            &s.state,
            s.root.path(),
            "group-a",
            "a.bin",
        )
        .unwrap();

        assert_eq!(
            std::fs::read(&out).unwrap(),
            b"content a crash stranded in quarantine",
            "the stranded object must be restored to its path"
        );
        assert!(!q.exists());
    }
}

/// An unmarked root is adopted automatically only on disk evidence. A `Remote`
/// row's absence is expected, but it cannot vouch that this directory is the
/// link's folder: an index of nothing but `Remote` rows over an empty
/// mountpoint (an unmounted volume) must not be adopted without an explicit
/// readoption.
#[test]
fn an_unmarked_empty_root_is_not_adopted_for_an_index_of_only_remote_rows() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    state.link_repository().add_link(&root.path().to_string_lossy(), "group-a").unwrap();
    let permit = RootCommitPermit::for_tests();
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let record = store_and_record(&store, "a.bin", b"remote only");
    state.file_index_repository().upsert_file("group-a", &record, &permit).unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state("group-a", "a.bin", MaterializationState::Remote, &permit)
        .unwrap();

    assert!(
        VerifiedRoot::open(root.path(), "group-a", &state).is_err(),
        "an empty unmarked root was adopted on no disk evidence at all"
    );
}

/// A reconstruct that fails AFTER its bytes were renamed into place (the mode
/// or the replicated xattrs could not be applied) leaves an object standing.
/// The repair must not call that `Remote` and clear its intent: the object is
/// there, the metadata is owed, and the intent is what keeps the path from
/// reading as an offline delete and what makes the next pass retry.
#[cfg(unix)]
#[test]
fn a_repair_reconstruct_that_fails_after_its_rename_keeps_the_object_and_the_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt, then its metadata could not be applied";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();

    yadorilink_filesystem_sync::materialization_repair::set_fail_after_rename_for_test(true);
    let _ = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    )
    .unwrap();
    yadorilink_filesystem_sync::materialization_repair::set_fail_after_rename_for_test(false);

    assert!(
        std::fs::symlink_metadata(root.path().join("doc.txt")).is_ok(),
        "setup: the bytes must have been renamed into place before the metadata failed"
    );
    assert_ne!(
        state
            .materialization_state_repository()
            .get_materialization_state("group-1", "doc.txt")
            .unwrap(),
        Some(MaterializationState::Remote),
        "an object stands at the path: the row cannot be Remote"
    );
    assert!(
        state
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "doc.txt")
            .unwrap(),
        "the intent must stay open so the next pass retries the metadata"
    );
}

/// A block store whose first read takes the root's marker away: the volume
/// under the link root disappears while a repair is assembling a file.
#[cfg(unix)]
struct UnmountingStore<'a> {
    inner: &'a SegmentBlockStore,
    marker: std::path::PathBuf,
}

#[cfg(unix)]
impl yadorilink_local_storage::BlockContentStore for UnmountingStore<'_> {
    fn put(
        &self,
        data: &[u8],
    ) -> Result<yadorilink_local_storage::ContentHash, yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::put(self.inner, data)
    }

    fn put_prepared(
        &self,
        prepared: &yadorilink_local_storage::LocallyHashedBlock,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::put_prepared(self.inner, prepared)
    }

    fn put_prepared_batch(
        &self,
        prepared: &[yadorilink_local_storage::LocallyHashedBlock],
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::put_prepared_batch(self.inner, prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, yadorilink_local_storage::StorageError> {
        let _ = std::fs::remove_file(&self.marker);
        yadorilink_local_storage::BlockStore::get(self.inner, hash)
    }

    fn present_blocks(
        &self,
        hashes: &[yadorilink_local_storage::ContentHash],
    ) -> Result<Vec<bool>, yadorilink_local_storage::StorageError> {
        yadorilink_local_storage::BlockStore::present_blocks(self.inner, hashes)
    }
}

/// A repair whose root leaves its volume while the file is being assembled
/// renames nothing into the bare mountpoint and leaves no Present row.
#[cfg(unix)]
#[test]
fn a_repair_reconstruct_does_not_publish_onto_a_root_that_left_its_volume() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let content = b"rebuilt onto a volume that vanished";
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    let permit = RootCommitPermit::for_tests();
    upsert_hydrated_file(&state, "group-1", &record_with_blocks("doc.txt", content, hash), &permit);
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &[0; 32], &permit)
        .unwrap();
    let unmounting = UnmountingStore {
        inner: &store,
        marker: root.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
    };

    let outcome = repair_interrupted_materializations(
        &state,
        &unmounting,
        root.path(),
        "group-1",
        RepairMode::Startup,
        &permit,
    );

    assert!(
        std::fs::symlink_metadata(root.path().join("doc.txt")).is_err(),
        "the file was renamed onto the bare mountpoint"
    );
    assert!(outcome.is_err(), "the sweep must stop on a root that no longer verifies");
    assert!(
        state
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "doc.txt")
            .unwrap(),
        "the intent must stay open: no placeholder was written and nothing settled the path"
    );
}

/// Proves `doc.txt` the way an interrupted write is finished (intent open,
/// file missing, startup repair rebuilds it), leaving a `Present` row with a
/// usable proof and no intent.
fn settle_proven_present(state: &ReplicaCoordinator, store: &SegmentBlockStore, root: &Path) {
    let content = b"the synced, indexed content";
    seed_present(state, store, root, content, None);
    state
        .materialization_intent_repository()
        .begin_materialization_intent(
            "group-1",
            "doc.txt",
            &[0; 32],
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    let report = startup_repair(state, store, root);
    assert_eq!(report.reconstructed, vec!["doc.txt"]);
    assert!(MaterializationExecutionPort::has_usable_materialized_generation(
        state, "group-1", "doc.txt"
    )
    .unwrap());
}

/// A settled row (`Present`, usable proof, no intent) owes the live sweep
/// nothing, so it does not read the file: a divergence there is left to
/// capture, and the sweep neither journals nor touches it.
#[test]
fn live_repair_does_not_read_a_settled_present_file() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    settle_proven_present(&state, &store, root.path());
    let edit: &[u8] = b"an edit the watcher has not delivered";
    std::fs::write(root.path().join("doc.txt"), edit).unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Live,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert!(report.is_empty(), "{report:?}");
    assert!(!is_dirty(&state), "a settled row is not compared, so nothing is journaled");
    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), edit);
}

/// The startup pass is unchanged: the same settled row with different bytes
/// is an offline edit and is journaled for the initial scan.
#[test]
fn startup_repair_still_compares_a_settled_present_file() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    settle_proven_present(&state, &store, root.path());
    let edit: &[u8] = b"an edit made while the daemon was stopped";
    std::fs::write(root.path().join("doc.txt"), edit).unwrap();

    startup_repair(&state, &store, root.path());

    assert!(is_dirty(&state), "an offline edit is found at startup");
    assert_eq!(std::fs::read(root.path().join("doc.txt")).unwrap(), edit);
}

/// A row with an intent open is unfinished work and is still examined live,
/// proof or not.
#[test]
fn live_repair_still_examines_a_present_file_with_an_open_intent() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    settle_proven_present(&state, &store, root.path());
    state
        .materialization_intent_repository()
        .begin_materialization_intent(
            "group-1",
            "doc.txt",
            &[0; 32],
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    std::fs::remove_file(root.path().join("doc.txt")).unwrap();

    let report = repair_interrupted_materializations(
        &state,
        &store,
        root.path(),
        "group-1",
        RepairMode::Live,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert_eq!(report.reconstructed, vec!["doc.txt"]);
}

// Crash matrix of a temp file's life. A write records the temp file, creates
// it, fills and syncs it, renames it over the target and releases the record.
// Link start removes what the records name and nothing else.
mod temp_file_crash_matrix {
    use super::*;
    use yadorilink_local_storage::{
        persist_reconstructed_file_in, reconstruct_file_to_temp_in, TempFileLedger,
    };

    const G: &str = "group-tmp";

    /// A ledger that records but whose release never happens: the process died
    /// before it.
    struct DiesBeforeRelease<'a>(&'a dyn TempFileLedger);
    impl TempFileLedger for DiesBeforeRelease<'_> {
        fn record(&self, tmp: &Path) -> Result<(), yadorilink_local_storage::StorageError> {
            self.0.record(tmp)
        }
        fn release(&self, _tmp: &Path) {}
        fn strand(&self, dir: &Path) -> Result<(), yadorilink_local_storage::StorageError> {
            self.0.strand(dir)
        }
    }

    struct Fixture {
        state: ReplicaCoordinator,
        store: SegmentBlockStore,
        _store_dir: tempfile::TempDir,
        root: tempfile::TempDir,
        blocks: Vec<BlockInfo>,
    }

    fn fixture() -> Fixture {
        let store_dir = tempfile::tempdir().unwrap();
        let store = SegmentBlockStore::new(store_dir.path()).unwrap();
        let data = b"temp file crash matrix content";
        let hash = hex::decode(store.put(data).unwrap()).unwrap();
        Fixture {
            state: ReplicaCoordinator::open_in_memory().unwrap(),
            store,
            _store_dir: store_dir,
            root: tempfile::tempdir().unwrap(),
            blocks: vec![BlockInfo { hash, offset: 0, size: data.len() as u32 }],
        }
    }

    impl Fixture {
        fn recorded(&self) -> Vec<String> {
            self.state.temp_ledger(G).list().unwrap()
        }
        fn recover(&self) -> Vec<std::path::PathBuf> {
            self.state.remove_recorded_temp_files(G, self.root.path()).unwrap()
        }
        fn names(&self) -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(self.root.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }
    }

    /// Case 1: Crash after the name is recorded, before the file is created.
    #[test]
    fn crash_after_record_before_create() {
        let f = fixture();
        let tmp = f.root.path().join("a.yadorilink-tmp.1.1");
        f.state.temp_ledger(G).record(&tmp).unwrap();
        assert_eq!(f.recorded().len(), 1);
        assert!(f.recover().is_empty(), "nothing was created, nothing to remove");
        assert!(f.recorded().is_empty());
    }

    /// Names recorded together by concurrent writers (one grouped commit) and
    /// never created: recovery drops exactly those records, deletes nothing,
    /// and leaves another group's record and an unrecorded lookalike alone.
    #[test]
    fn crash_after_a_grouped_record_before_any_create() {
        let f = fixture();
        let other_group = "other-group";
        let theirs = f.root.path().join("theirs.yadorilink-tmp.1.1");
        f.state.temp_ledger(other_group).record(&theirs).unwrap();
        let lookalike = f.root.path().join("mine.yadorilink-tmp.1.2");
        std::fs::write(&lookalike, b"not recorded by anyone").unwrap();
        let ledger = f.state.temp_ledger(G);
        let names: Vec<_> =
            (0..6).map(|n| f.root.path().join(format!("w{n}.yadorilink-tmp.1.{n}"))).collect();
        std::thread::scope(|scope| {
            for name in &names {
                let ledger = &ledger;
                scope.spawn(move || ledger.record(name).unwrap());
            }
        });
        assert_eq!(f.recorded().len(), 6);

        assert!(f.recover().is_empty(), "nothing was created, nothing to remove");

        assert!(f.recorded().is_empty());
        assert_eq!(f.state.temp_ledger(other_group).list().unwrap().len(), 1, "not ours");
        assert_eq!(std::fs::read(&lookalike).unwrap(), b"not recorded by anyone");
    }

    /// Of names recorded together, the one whose file a crash left is removed,
    /// the one never created only loses its record, and a user's file beside
    /// them is untouched.
    #[test]
    fn recovery_after_a_grouped_record_touches_only_the_recorded_names() {
        let f = fixture();
        let ledger = f.state.temp_ledger(G);
        let created = f.root.path().join("a.yadorilink-tmp.9.1");
        let never_created = f.root.path().join("b.yadorilink-tmp.9.2");
        std::thread::scope(|scope| {
            for name in [&created, &never_created] {
                let ledger = &ledger;
                scope.spawn(move || ledger.record(name).unwrap());
            }
        });
        std::fs::write(&created, b"partial").unwrap();
        let users = f.root.path().join("users-file.txt");
        std::fs::write(&users, b"mine").unwrap();

        assert_eq!(f.recover(), vec![created]);

        assert_eq!(std::fs::read(&users).unwrap(), b"mine");
        assert!(f.recorded().is_empty());
    }

    /// Case 2: Crash while the file is being filled (it exists, partly written).
    #[test]
    fn crash_mid_assembly() {
        let f = fixture();
        let tmp = f.root.path().join("a.yadorilink-tmp.1.2");
        f.state.temp_ledger(G).record(&tmp).unwrap();
        std::fs::write(&tmp, b"partial").unwrap();
        assert_eq!(f.recover(), vec![tmp.clone()]);
        assert!(f.names().is_empty() && f.recorded().is_empty());
    }

    /// Case 3: Crash after the temp file is complete and synced, before the rename.
    #[test]
    fn crash_after_assembly_before_rename() {
        let f = fixture();
        let out = f.root.path().join("a.bin");
        let ledger = f.state.temp_ledger(G);
        let tmp = reconstruct_file_to_temp_in(&f.store, &out, &f.blocks, 0, &ledger).unwrap();
        assert!(tmp.exists() && f.recorded().len() == 1);
        assert_eq!(f.recover(), vec![tmp]);
        assert!(!out.exists(), "nothing was published");
        assert!(f.names().is_empty() && f.recorded().is_empty());
    }

    /// Case 4: Crash after the rename, before the record is released: the published
    /// file is untouched and only the stale record goes.
    #[test]
    fn crash_after_rename_before_release() {
        let f = fixture();
        let out = f.root.path().join("a.bin");
        let ledger = f.state.temp_ledger(G);
        let dying = DiesBeforeRelease(&ledger);
        let tmp = reconstruct_file_to_temp_in(&f.store, &out, &f.blocks, 0, &dying).unwrap();
        persist_reconstructed_file_in(&tmp, &out, &dying).unwrap();
        assert_eq!(f.recorded().len(), 1, "the release never ran");
        assert!(f.recover().is_empty(), "the temp file is gone: nothing to remove");
        assert_eq!(f.names(), vec!["a.bin".to_string()]);
        assert_eq!(std::fs::read(&out).unwrap(), b"temp file crash matrix content");
        assert!(f.recorded().is_empty());
    }

    /// Case 5: No crash: a write that finishes leaves no record, and recovery has
    /// nothing to do.
    #[test]
    fn a_finished_write_leaves_nothing_recorded() {
        let f = fixture();
        let out = f.root.path().join("a.bin");
        let ledger = f.state.temp_ledger(G);
        let tmp = reconstruct_file_to_temp_in(&f.store, &out, &f.blocks, 0, &ledger).unwrap();
        persist_reconstructed_file_in(&tmp, &out, &ledger).unwrap();
        assert!(f.recorded().is_empty());
        assert!(f.recover().is_empty());
        assert_eq!(f.names(), vec!["a.bin".to_string()]);
    }

    /// Case 6: A symlink's temp link, created and never renamed.
    #[cfg(unix)]
    #[test]
    fn crash_with_a_temp_symlink() {
        let f = fixture();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("target"), b"must survive").unwrap();
        let tmp = f.root.path().join("l.yadorilink-tmp.1.6");
        f.state.temp_ledger(G).record(&tmp).unwrap();
        std::os::unix::fs::symlink(outside.path().join("target"), &tmp).unwrap();
        assert_eq!(f.recover(), vec![tmp]);
        assert_eq!(std::fs::read(outside.path().join("target")).unwrap(), b"must survive");
        assert!(f.names().is_empty());
    }

    /// The window the single per-path intent could not cover: a second write
    /// of the same path replaces the intent while the first write's temp file
    /// is still on disk. Both temp files are named by their own records.
    #[test]
    fn a_second_write_does_not_orphan_the_first_writes_temp_file() {
        let f = fixture();
        let out = f.root.path().join("a.bin");
        let permit = RootCommitPermit::for_tests();
        let ledger = f.state.temp_ledger(G);
        let intents = f.state.materialization_intent_repository();
        intents.begin_materialization_intent(G, "a.bin", &[1; 32], &permit).unwrap();
        let first = reconstruct_file_to_temp_in(&f.store, &out, &f.blocks, 0, &ledger).unwrap();
        intents.begin_materialization_intent(G, "a.bin", &[2; 32], &permit).unwrap();
        let second = reconstruct_file_to_temp_in(&f.store, &out, &f.blocks, 0, &ledger).unwrap();
        let mut removed = f.recover();
        removed.sort();
        let mut expected = vec![first, second];
        expected.sort();
        assert_eq!(removed, expected);
        assert!(f.names().is_empty());
    }

    /// A directory component swapped for a symlink while stopped must not aim
    /// the removal outside the root.
    #[cfg(unix)]
    #[test]
    fn recovery_does_not_follow_a_symlinked_ancestor() {
        let f = fixture();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("x.yadorilink-tmp.1.3");
        std::fs::write(&victim, b"outside the root").unwrap();
        std::os::unix::fs::symlink(outside.path(), f.root.path().join("sub")).unwrap();
        let recorded = f.root.path().join("sub/x.yadorilink-tmp.1.3");
        f.state.temp_ledger(G).record(&recorded).unwrap();

        assert!(f.recover().is_empty());

        assert_eq!(std::fs::read(&victim).unwrap(), b"outside the root");
    }

    /// Recovery never decides from a name: an unrecorded file that looks
    /// exactly like a temp file is a user's, and a recorded path that lies
    /// outside the root is left alone. A recorded directory is removed only
    /// when it is empty, by one non-recursive `rmdir`; with anything inside it
    /// stays, and so does its record.
    #[test]
    fn recovery_removes_only_what_a_record_names() {
        let f = fixture();
        let lookalike = f.root.path().join("notes.yadorilink-tmp.12345.7");
        std::fs::write(&lookalike, b"mine").unwrap();
        let unrecorded_dir = f.root.path().join("e.yadorilink-tmp.1.8");
        std::fs::create_dir(&unrecorded_dir).unwrap();
        let empty = f.root.path().join("d.yadorilink-tmp.1.8");
        std::fs::create_dir(&empty).unwrap();
        let full = f.root.path().join("full.yadorilink-tmp.1.8");
        std::fs::create_dir(&full).unwrap();
        std::fs::write(full.join("child"), b"data").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let elsewhere = outside.path().join("x.yadorilink-tmp.1.9");
        std::fs::write(&elsewhere, b"not under the root").unwrap();
        let ledger = f.state.temp_ledger(G);
        ledger.record(&empty).unwrap();
        ledger.record(&full).unwrap();
        ledger.record(&elsewhere).unwrap();

        assert_eq!(f.recover(), vec![empty.clone()]);
        assert_eq!(std::fs::read(&lookalike).unwrap(), b"mine");
        assert!(unrecorded_dir.is_dir(), "an unrecorded directory is never touched");
        assert!(!empty.exists());
        assert_eq!(std::fs::read(full.join("child")).unwrap(), b"data");
        assert!(elsewhere.exists());
        assert_eq!(f.recorded(), vec![full.display().to_string()], "only the full one is kept");
    }

    /// A crash between a Stage directory and its publication leaves a recorded
    /// empty directory beside the target and nothing at the target; recovery
    /// removes exactly that.
    #[test]
    fn crash_between_a_stage_directory_and_its_publication() {
        use yadorilink_fs_platform::durable_dir::{arm_failpoint, disarm_failpoint, NsFailpoint};
        let f = fixture();
        let target = f.root.path().join("d");
        let canonical = std::fs::canonicalize(f.root.path()).unwrap();
        let ledger =
            yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger::new(
                &f.state, G,
            );
        arm_failpoint(NsFailpoint::AfterStage);
        let result = yadorilink_local_storage::create_explicit_directory(
            &canonical.join("d"),
            &canonical,
            &ledger,
        );
        disarm_failpoint();
        assert!(result.is_err());
        assert!(!target.exists());
        assert_eq!(f.names().len(), 1, "the Stage directory is beside the target");
        assert_eq!(f.recorded().len(), 1, "and a record names it");

        // The record names the stage under the canonical root the directory
        // was created with, so recovery is handed that same root (the temp
        // dir is itself behind a symlink on macOS).
        assert_eq!(f.state.remove_recorded_temp_files(G, &canonical).unwrap().len(), 1);

        assert!(f.names().is_empty() && f.recorded().is_empty());
    }
}

mod structural_intents_without_an_age_sweep {
    use super::*;

    fn pending(state: &ReplicaCoordinator) -> Vec<(String, String)> {
        state
            .sqlite()
            .dag_list_unresolved_structural_intents(None)
            .unwrap()
            .into_iter()
            .map(|i| (i.group_id, i.path))
            .collect()
    }

    /// An intent a dead process left stays until the group's link starts: no
    /// clock decides, however old or young it is. Link start resolves only its
    /// own group's, and records the directory found as of lost provenance.
    #[test]
    fn link_start_resolves_its_own_groups_intents_and_nothing_else() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        adopt_root(&state, "ga", root_a.path());
        adopt_root(&state, "gb", root_b.path());
        std::fs::create_dir(root_a.path().join("d")).unwrap();
        std::fs::create_dir(root_b.path().join("d")).unwrap();
        state.record_structural_directory_intent("ga", "d").unwrap();
        state.record_structural_directory_intent("gb", "d").unwrap();

        let resolved = state.resolve_structural_intents_at_link_start("ga").unwrap();

        assert_eq!(resolved, vec![("ga".to_string(), "d".to_string())]);
        assert_eq!(pending(&state), vec![("gb".to_string(), "d".to_string())]);
    }

    /// A writer leaving with its intent unsettled resolves just that intent.
    #[test]
    fn an_interrupted_writer_resolves_only_its_own_intent() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        adopt_root(&state, "ga", root.path());
        std::fs::create_dir(root.path().join("d")).unwrap();
        state.record_structural_directory_intent("ga", "d").unwrap();
        state.record_structural_directory_intent("ga", "e").unwrap();

        state.resolve_interrupted_structural_intent("ga", "d").unwrap();

        assert_eq!(pending(&state), vec![("ga".to_string(), "e".to_string())]);
    }
}
