#![cfg(test)]

//! The block-store half of a provider eviction: a fake custody source and a fake host drive the
//! real coordinator, hold table, block store and deletion guard.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, ProviderKind};
use yadorilink_replica_engine::custody::CustodyStamp;
use yadorilink_sync_sqlite::provider::ItemId;

use super::*;
use crate::provider_evict::EvictHost;
use crate::provider_evidence::ProviderMembership;
use crate::provider_publication::EvictOutcome as HostAnswer;
use crate::replica_coordinator::ReplicaCoordinator;

pub(crate) const GROUP: &str = "group-1";
const LOCAL_PATH: &str = "/provider/photos";

/// The ordered record of what the fakes were asked, shared so a test can see the interleaving.
pub(crate) type Log = Arc<Mutex<Vec<String>>>;

pub(crate) struct FakeCustody {
    state: Arc<DaemonState>,
    pub(crate) log: Log,
    pub(crate) grant: AtomicBool,
    /// Tests only: grant the first lease asked for and refuse every later one.
    pub(crate) grant_only_first: AtomicBool,
    pub(crate) valid: AtomicBool,
    pub(crate) acquires: AtomicUsize,
    /// Whether the item's path lock was held while the lease was being asked for.
    pub(crate) lock_held_during_acquire: AtomicBool,
    /// Whether the item's path lock was held when the lease was checked for the deletion.
    pub(crate) lock_held_during_validation: AtomicBool,
    /// Runs while the acquire is in flight (the item can move on meanwhile).
    pub(crate) during_acquire: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Custody for FakeCustody {
    fn acquire<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        _version_hash: VersionHash,
        _blocks: &'a [VersionBlock],
    ) -> BoxFuture<'a, Option<CustodyStamp>> {
        Box::pin(async move {
            let ordinal = self.acquires.fetch_add(1, Ordering::SeqCst);
            if self.grant_only_first.load(Ordering::SeqCst) && ordinal > 0 {
                return None;
            }
            self.log.lock().unwrap().push("acquire".into());
            let lock = self.state.replica_coordinator.path_lock(group_id, path);
            self.lock_held_during_acquire.store(lock.try_lock().is_err(), Ordering::SeqCst);
            if let Some(hook) = self.during_acquire.lock().unwrap().take() {
                hook();
            }
            self.grant.load(Ordering::SeqCst).then(|| CustodyStamp::new("full-peer".into(), 1))
        })
    }

    fn still_valid(
        &self,
        group_id: &str,
        path: &str,
        _version_hash: &VersionHash,
        _stamp: &CustodyStamp,
    ) -> bool {
        let lock = self.state.replica_coordinator.path_lock(group_id, path);
        self.lock_held_during_validation.store(lock.try_lock().is_err(), Ordering::SeqCst);
        self.valid.load(Ordering::SeqCst)
    }
}

pub(crate) struct FakeHost {
    state: Arc<DaemonState>,
    pub(crate) log: Log,
    /// Whether the item's path lock was held while the host was being asked.
    pub(crate) lock_held_during_evict: AtomicBool,
    pub(crate) connected: AtomicBool,
    pub(crate) answers: Mutex<VecDeque<HostAnswer>>,
    pub(crate) targets: Mutex<Vec<[u8; 32]>>,
}

impl EvictHost for FakeHost {
    fn connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    fn evict_shown_version<'a>(
        &'a self,
        _root_id: &'a str,
        _item: ItemId,
        target: [u8; 32],
    ) -> BoxFuture<'a, HostAnswer> {
        Box::pin(async move {
            self.log.lock().unwrap().push("host_evict".into());
            let held = self
                .state
                .replica_coordinator
                .provider_repository()
                .path_for_item(_root_id, &_item)
                .ok()
                .flatten()
                .is_some_and(|(path, _)| {
                    self.state.replica_coordinator.path_lock(GROUP, &path).try_lock().is_err()
                });
            self.lock_held_during_evict.store(held, Ordering::SeqCst);
            self.targets.lock().unwrap().push(target);
            self.answers.lock().unwrap().pop_front().unwrap_or(HostAnswer::Evicted)
        })
    }
}

pub(crate) struct Fx {
    pub(crate) state: Arc<DaemonState>,
    pub(crate) root: String,
    pub(crate) custody: Arc<FakeCustody>,
    pub(crate) host: Arc<FakeHost>,
    pub(crate) log: Log,
    pub(crate) membership: Arc<ProviderMembership>,
    /// The block store's directory, for tests that damage a stored payload.
    pub(crate) store_root: std::path::PathBuf,
    epoch: AtomicUsize,
}

pub(crate) fn data_of(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|n| (n as u8).wrapping_mul(31).wrapping_add(tag)).collect()
}

impl Fx {
    /// An on-demand provider root with a ready domain, a fake host and a fake custody source.
    pub(crate) fn new() -> Self {
        let store_root = tempfile::tempdir().unwrap().keep();
        let store = Arc::new(
            SegmentBlockStore::new(store_root.clone()).unwrap().with_volume_verdict(|_| true),
        );
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        state.replica_coordinator.link_repository().add_link(LOCAL_PATH, GROUP).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(LOCAL_PATH, MaterializationPolicy::OnDemand)
            .unwrap();
        let repo = state.replica_coordinator.provider_repository();
        let root = repo.declare_root(GROUP, ProviderKind::MacFileProvider, "Photos").unwrap();
        repo.set_domain_registered(&root, true).unwrap();
        repo.record_extension_handshake(&root, 1).unwrap();
        let log: Log = Arc::default();
        let custody = Arc::new(FakeCustody {
            state: state.clone(),
            log: log.clone(),
            grant: AtomicBool::new(true),
            grant_only_first: AtomicBool::new(false),
            valid: AtomicBool::new(true),
            acquires: AtomicUsize::new(0),
            lock_held_during_acquire: AtomicBool::new(false),
            lock_held_during_validation: AtomicBool::new(false),
            during_acquire: Mutex::new(None),
        });
        let host = Arc::new(FakeHost {
            state: state.clone(),
            log: log.clone(),
            lock_held_during_evict: AtomicBool::new(false),
            connected: AtomicBool::new(true),
            answers: Mutex::default(),
            targets: Mutex::default(),
        });
        Self {
            state,
            root,
            custody,
            host,
            log,
            membership: Arc::default(),
            store_root,
            epoch: AtomicUsize::new(1),
        }
    }

    /// The reclaim machinery with the lease flag taken as on.
    pub(crate) fn reclaim(&self) -> Arc<ProviderReclaim> {
        Arc::new(
            ProviderReclaim::with_custody(self.state.clone(), self.custody.clone())
                .with_leases_enabled_for_test(),
        )
    }

    /// The reclaim machinery exactly as production builds it from these parts (flag as shipped).
    pub(crate) fn shipped_reclaim(&self) -> Arc<ProviderReclaim> {
        Arc::new(ProviderReclaim::with_custody(self.state.clone(), self.custody.clone()))
    }

    pub(crate) fn set_policy(&self, policy: MaterializationPolicy) {
        self.state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(LOCAL_PATH, policy)
            .unwrap();
    }

    /// Commits a version of `path` made of one block per entry of `blocks`, all present in the
    /// store, with the row in the state a provider row always has: `Remote`.
    pub(crate) fn commit(&self, path: &str, seq: i64, blocks: &[&[u8]]) -> Vec<String> {
        let mut hashes = Vec::new();
        let mut json = Vec::new();
        let mut offset = 0usize;
        for data in blocks {
            let hash = self.state.block_store.put(data).unwrap();
            let bytes = hex::decode(&hash).unwrap();
            self.state
                .replica_coordinator
                .record_block_provenance(GROUP, std::slice::from_ref(&bytes))
                .unwrap();
            json.push(format!(
                r#"{{"hash":{:?},"offset":{},"size":{}}}"#,
                bytes,
                offset,
                data.len()
            ));
            offset += data.len();
            hashes.push(hash);
        }
        let blocks_json = format!("[{}]", json.join(","));
        self.state
            .replica_coordinator
            .database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                tx.execute(
                    "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![GROUP, path],
                )?;
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state, materialization_state) \
                     VALUES (?1, ?2, ?3, 1, ?5, 0, ?4, 'current', 'remote')",
                    rusqlite::params![GROUP, path, offset as i64, seq, blocks_json],
                )?;
                let row = yadorilink_sync_sqlite::read_canonical_current_row(tx, GROUP, path)?
                    .expect("the row just written");
                let version = yadorilink_replica_domain::session_state::CurrentVersionRecord::from(
                    row.snapshot,
                )
                .to_file_version();
                yadorilink_sync_sqlite::dag_store::put_file_version(tx, GROUP, &version)?;
                Ok(())
            })
            .unwrap();
        hashes
    }

    /// A new current version of `path` with the same blocks and a different mtime: a
    /// metadata-only change.
    pub(crate) fn touch(&self, path: &str, seq: i64, mtime: i64) {
        self.state
            .replica_coordinator
            .database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                tx.execute(
                    "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![GROUP, path],
                )?;
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state, materialization_state) \
                     SELECT group_id, path, size, ?4, blocks_json, 0, ?3, 'current', 'remote' \
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'superseded' \
                     ORDER BY version_seq DESC LIMIT 1",
                    rusqlite::params![GROUP, path, seq, mtime],
                )?;
                let row = yadorilink_sync_sqlite::read_canonical_current_row(tx, GROUP, path)?
                    .expect("the row just written");
                let version = yadorilink_replica_domain::session_state::CurrentVersionRecord::from(
                    row.snapshot,
                )
                .to_file_version();
                yadorilink_sync_sqlite::dag_store::put_file_version(tx, GROUP, &version)?;
                Ok(())
            })
            .unwrap();
    }

    /// A published item of `path`, whose OS copy the host holds.
    pub(crate) fn item(&self, path: &str) -> ItemId {
        let repo = self.state.replica_coordinator.provider_repository();
        let item = repo.mint_item(&self.root, path).unwrap();
        let hash = repo.current_version_hash(&self.root, &item).unwrap().unwrap();
        repo.publish_first(&self.root, &item, hash).unwrap();
        item
    }

    /// A published item whose OS copy the daemon has evidence for.
    pub(crate) fn held_item(&self, path: &str) -> ItemId {
        let item = self.item(path);
        self.os_holds(item);
        item
    }

    /// The host lists `item` as materialized although the daemon never handed it over.
    pub(crate) fn listed_without_handoff(&self, item: ItemId) {
        let repo = self.state.replica_coordinator.provider_repository();
        let report = yadorilink_ipc_proto::shellipc::ProviderMaterializedReport {
            root_id: hex::decode(&self.root).unwrap(),
            reporter_epoch: self.epoch.fetch_add(1, Ordering::SeqCst) as u64,
            report_seq: 1,
            full: true,
            observed_after_seq: 0,
            upserts: vec![yadorilink_ipc_proto::shellipc::ProviderMaterializedItem {
                item_id: item.to_vec(),
            }],
            removed: Vec::new(),
            more: false,
        };
        let latest = repo.latest_evidence_seq(&self.root).unwrap().unwrap();
        assert!(!self.membership.apply(&report, latest).needs_full);
    }

    /// The daemon's evidence that the OS holds `item` at its current version: a verified handoff
    /// and a host report, taken after it, that lists the item.
    pub(crate) fn os_holds(&self, item: ItemId) {
        self.os_lists_after(item, false);
    }

    /// The evidence that the OS was served only windows of `item`'s current version and lists it
    /// afterwards (a large file read through the OS partial-content API).
    pub(crate) fn os_holds_windows(&self, item: ItemId) {
        self.os_lists_after(item, true);
    }

    fn os_lists_after(&self, item: ItemId, windows_only: bool) {
        let repo = self.state.replica_coordinator.provider_repository();
        let version = repo.current_version_hash(&self.root, &item).unwrap().unwrap();
        let seq = if windows_only {
            repo.record_window_serve(&self.root, &item, version).unwrap().unwrap()
        } else {
            repo.record_handoff(&self.root, &item, version).unwrap().unwrap()
        };
        let report = yadorilink_ipc_proto::shellipc::ProviderMaterializedReport {
            root_id: hex::decode(&self.root).unwrap(),
            reporter_epoch: self.epoch.fetch_add(1, Ordering::SeqCst) as u64,
            report_seq: 1,
            full: true,
            observed_after_seq: seq,
            upserts: vec![yadorilink_ipc_proto::shellipc::ProviderMaterializedItem {
                item_id: item.to_vec(),
            }],
            removed: Vec::new(),
            more: false,
        };
        let ack =
            self.membership.apply(&report, repo.latest_evidence_seq(&self.root).unwrap().unwrap());
        assert!(!ack.needs_full, "the host report was refused");
    }

    pub(crate) fn cached(&self, hash: &str) -> bool {
        self.state.block_store.exists(hash).unwrap()
    }

    pub(crate) fn current_version(&self, path: &str) -> VersionHash {
        self.state
            .replica_coordinator
            .sqlite()
            .dag_get_current_version_record(GROUP, path)
            .unwrap()
            .unwrap()
            .to_file_version()
            .version_hash
    }
}

pub(crate) async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// Items that left the OS's materialized set are reclaimed one by one, and an item that is gone
/// or was queued twice is not a problem.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_queue_frees_the_blocks_of_items_the_os_dropped() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    let kept = fx.commit("b.bin", 1, &[&data_of(2, 4096)]);
    let a = fx.item("a.bin");
    let b = fx.item("b.bin");
    fx.os_holds(a);
    let queue = Arc::new(ReclaimQueue::new(fx.state.clone(), fx.reclaim()));

    // `b` was never handed over, `[9; 16]` is no item.
    let now = fx
        .state
        .replica_coordinator
        .provider_repository()
        .latest_evidence_seq(&fx.root)
        .unwrap()
        .unwrap();
    queue.schedule(&fx.root, vec![(a, now), (a, now), (b, now), ([9u8; 16], now)]);

    eventually("the dropped item's blocks are freed", || !fx.cached(&blocks[0])).await;
    assert!(fx.cached(&kept[0]), "an item the daemon never handed over was reclaimed");
    assert_eq!(
        fx.custody.acquires.load(Ordering::SeqCst),
        1,
        "a duplicate asked for a second lease"
    );
}

/// The queue runs the reclaim as production builds it: with the shipped flag on it frees the
/// departed copy's blocks, except where the platform does not offer durable namespace changes
/// (Windows until its gate is validated), where it asks for no lease and keeps every block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_queue_with_the_shipped_reclaim_frees_blocks_only_where_the_platform_is_durable() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    let a = fx.held_item("a.bin");
    let queue = Arc::new(ReclaimQueue::new(fx.state.clone(), fx.shipped_reclaim()));

    queue.schedule(&fx.root, vec![(a, u64::MAX)]);
    if yadorilink_fs_platform::durable_dir::platform_offers_durable_namespace() {
        eventually("the departed copy's blocks are freed", || !fx.cached(&blocks[0])).await;
    } else {
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fx.custody.acquires.load(Ordering::SeqCst), 0);
        assert!(fx.cached(&blocks[0]));
    }
}

/// Reclaim deletes the block store's bytes, so only the volume that holds them decides: with the
/// global gate open, a block-store volume that is not known durable keeps every block, however the
/// sync root's volume is judged.
async fn prepare_with_block_store_verdict(
    block_store_durable: Option<bool>,
    other_volumes_durable: bool,
) -> (Result<Prepared, Retained>, Fx, Vec<String>) {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    // The segment files, not the store root, are what a reclaim deletes.
    let store_root = fx.store_root.join("segments");
    let reclaim = ProviderReclaim::with_custody(fx.state.clone(), fx.custody.clone())
        .with_volume_verdict_for_test(move |dir| match (dir, block_store_durable) {
            (Some(d), Some(verdict)) if d == store_root => verdict,
            (Some(_), _) => other_volumes_durable,
            (None, _) => false,
        });
    let prepared = reclaim.prepare(GROUP, "a.bin", None).await;
    (prepared, fx, blocks)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsupported_or_unknown_block_store_volume_keeps_the_blocks_even_beside_a_supported_sync_root(
) {
    // The block store's volume is refused while every other volume (the sync root) is Supported.
    let (prepared, fx, blocks) = prepare_with_block_store_verdict(Some(false), true).await;
    assert_eq!(prepared.err(), Some(Retained::CustodyUnsupported));
    assert_eq!(fx.custody.acquires.load(Ordering::SeqCst), 0);
    assert!(fx.cached(&blocks[0]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_supported_block_store_volume_allows_the_reclaim_whatever_the_sync_root_says() {
    // The sync root's volume is not what is deleted from: only the block store's counts.
    let (prepared, fx, _) = prepare_with_block_store_verdict(Some(true), false).await;
    assert!(prepared.is_ok());
    assert_eq!(fx.custody.acquires.load(Ordering::SeqCst), 1);
}

/// A departure is bound to the copy that left: a handoff made after the departed listing began
/// is a copy that has not left, however the item looks by the time the queue runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_departure_older_than_the_handoff_reclaims_nothing() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    let a = fx.held_item("a.bin");
    let repo = fx.state.replica_coordinator.provider_repository();
    let handoff = repo.handoff(&fx.root, &a).unwrap().unwrap();
    let queue = Arc::new(ReclaimQueue::new(fx.state.clone(), fx.reclaim()));

    // The listing that departed began before the handoff was recorded.
    queue.schedule(&fx.root, vec![(a, handoff.evidence_seq - 1)]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fx.custody.acquires.load(Ordering::SeqCst), 0);
    assert!(fx.cached(&blocks[0]));

    // The listing that departed began at the handoff: that copy left.
    queue.schedule(&fx.root, vec![(a, handoff.evidence_seq)]);
    eventually("the departed copy's blocks are freed", || !fx.cached(&blocks[0])).await;
}

/// A departure queued for one version does not reclaim a newer one that was handed over before
/// the queue ran.
#[tokio::test(flavor = "current_thread")]
async fn a_queued_departure_does_not_reclaim_a_newer_version() {
    let fx = Fx::new();
    let old = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    let a = fx.held_item("a.bin");
    let queue = Arc::new(ReclaimQueue::new(fx.state.clone(), fx.reclaim()));
    let stamp = fx
        .state
        .replica_coordinator
        .provider_repository()
        .latest_evidence_seq(&fx.root)
        .unwrap()
        .unwrap();

    // The worker is spawned but cannot run before the next await.
    queue.schedule(&fx.root, vec![(a, stamp)]);
    let newer = fx.commit("a.bin", 2, &[&data_of(2, 4096)]);
    fx.os_holds(a);
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(fx.custody.acquires.load(Ordering::SeqCst), 0);
    assert!(fx.cached(&old[0]) && fx.cached(&newer[0]));
}

/// A pin recorded after the lease was taken keeps the cached blocks: the final deletion reads
/// the pin again under the deletion guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_recorded_after_the_lease_keeps_the_blocks() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    let reclaim = fx.reclaim();
    let prepared = reclaim.prepare(GROUP, "a.bin", None).await.expect("a lease was granted");

    fx.state.replica_coordinator.pinned_item_repository().pin(GROUP, "a.bin").unwrap();
    let freed = reclaim.reclaim(prepared).await.unwrap();

    assert_eq!(freed.blocks, 0);
    assert!(fx.cached(&blocks[0]), "a pinned item's block was freed");
}

/// Identical content under two paths. Every provider row is a placeholder, so each one's
/// retained blocks used to root the other's and neither reclaim ever freed anything. With the
/// other copy leased too, the shared blocks go; without that lease they stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_content_under_two_paths_is_freed_when_both_are_leased() {
    let fx = Fx::new();
    let data = data_of(7, 4096);
    let blocks = fx.commit("c.bin", 1, &[&data]);
    fx.commit("d.bin", 1, &[&data]);
    let reclaim = fx.reclaim();

    let prepared = reclaim.prepare(GROUP, "c.bin", None).await.unwrap();
    assert_eq!(
        fx.custody.acquires.load(Ordering::SeqCst),
        2,
        "the identical sibling is leased too"
    );
    let freed = reclaim.reclaim(prepared).await.unwrap();
    assert_eq!(freed.blocks, 1);
    assert!(!fx.cached(&blocks[0]), "no copy of the content is left to root the block");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_content_stays_while_the_other_copy_cannot_be_leased() {
    let fx = Fx::new();
    let data = data_of(8, 4096);
    let blocks = fx.commit("c.bin", 1, &[&data]);
    fx.commit("d.bin", 1, &[&data]);
    let reclaim = fx.reclaim();
    // The first lease (c.bin) is granted, the sibling's is refused.
    fx.custody.grant_only_first.store(true, Ordering::SeqCst);

    let prepared = reclaim.prepare(GROUP, "c.bin", None).await.unwrap();
    let freed = reclaim.reclaim(prepared).await.unwrap();
    assert_eq!(freed.blocks, 0);
    assert!(fx.cached(&blocks[0]), "d.bin's own custody is unconfirmed: it may hold the only copy");
}
