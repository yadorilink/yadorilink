//! A provider fetch of a large file cancelled in the middle of its transfer must leave the device
//! able to free another file and to fetch a small one: nothing the cancelled fetch held (a path
//! lock, a block-writer registration, a staging file, a download slot) outlives it.
//!
//! ```text
//!   A (Eager, full replica)           B (OnDemand provider root)
//!   big.bin, small-0, small-1  ---->  placeholders
//!                              <-----  small-0 materialized, held by the OS
//!                              <-----  big.bin fetch starts; its first stored block is held
//!   (the fetch is cancelled while that block is being stored)
//!                                      evict small-0   -> blocks freed
//!                                      fetch small-1   -> bytes arrive
//!                                      fetch big.bin   -> bytes arrive
//! ```

mod support;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};

use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::test_support::provider_evict_harness::{
    materialize_temp, HostReply, ProviderEvictHarness, RangedOutcome,
};
use yadorilink_local_storage::{
    BlockStore, ContentHash, GcReport, LocallyHashedBlock, SegmentBlockStore, StorageError,
};
use yadorilink_replica_domain::session_state::MaterializationPolicy;

const GROUP: &str = "cancel-free-group";
const MIB: usize = 1024 * 1024;

/// A real block store whose next write can be held: the write blocks until released, so a fetch
/// can be cancelled at an exact point of its transfer.
struct HoldingStore {
    inner: Arc<SegmentBlockStore>,
    armed: AtomicBool,
    /// Holds the next read instead of the next write.
    on_read: AtomicBool,
    held: Mutex<HoldState>,
    changed: Condvar,
}

#[derive(Default)]
struct HoldState {
    reached: bool,
    released: bool,
}

impl HoldingStore {
    fn arm(&self, on_read: bool) {
        *self.held.lock().unwrap() = HoldState::default();
        self.on_read.store(on_read, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }

    fn reached(&self) -> bool {
        self.held.lock().unwrap().reached
    }

    fn release(&self) {
        self.held.lock().unwrap().released = true;
        self.changed.notify_all();
    }

    fn on_write(&self) {
        if !self.on_read.load(Ordering::SeqCst) {
            self.hold();
        }
    }

    fn on_read(&self) {
        if self.on_read.load(Ordering::SeqCst) {
            self.hold();
        }
    }

    fn hold(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            let mut held = self.held.lock().unwrap();
            held.reached = true;
            while !held.released {
                held = self.changed.wait(held).unwrap();
            }
        }
    }
}

impl BlockStore for HoldingStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.on_write();
        self.inner.put(data)
    }

    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        self.on_write();
        self.inner.put_prepared(prepared)
    }

    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        self.on_write();
        self.inner.put_prepared_batch(prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.on_read();
        self.inner.get(hash)
    }

    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.on_read();
        self.inner.get_unchecked(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        self.inner.delete(hash)
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        self.inner.exists(hash)
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.inner.list_by_prefix(prefix)
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        self.inner.present_blocks(hashes)
    }

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.inner.sweep(live, grace_cutoff, dry_run)
    }
}

struct Device {
    id: &'static str,
    state: Arc<DaemonState>,
    controller: LinkRuntimeController,
    root: tempfile::TempDir,
    store: Arc<HoldingStore>,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

impl Device {
    fn new(id: &'static str, policy: MaterializationPolicy) -> Device {
        support::ensure_isolated_config_dir();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(HoldingStore {
            inner: Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap()),
            armed: AtomicBool::new(false),
            on_read: AtomicBool::new(false),
            held: Mutex::default(),
            changed: Condvar::new(),
        });
        let index_dir = tempfile::tempdir().unwrap();
        let coordinator = yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open(
            index_dir.path().join("index.db"),
        )
        .unwrap();
        let state = DaemonState::new(id.to_string(), Arc::new(coordinator), store.clone());
        state.set_test_on_demand_allowed(true);
        support::ensure_device_signing_key(&state);
        let device = Device {
            id,
            controller: LinkRuntimeController::new(state.clone()),
            state,
            root: tempfile::tempdir().unwrap(),
            store,
            _store_dir: store_dir,
            _index_dir: index_dir,
        };
        let repo = device.state.replica_coordinator.link_repository();
        repo.add_link(&device.local_path(), GROUP).unwrap();
        repo.set_materialization_policy(&device.local_path(), policy).unwrap();
        device
    }

    fn local_path(&self) -> String {
        self.root.path().to_string_lossy().to_string()
    }

    fn start(&self) {
        self.controller.start(self.local_path(), GROUP.to_string()).unwrap();
    }

    fn indexed_size(&self, path: &str) -> Option<u64> {
        let index = self.state.replica_coordinator.file_index_repository();
        if !index.has_real_current_row(GROUP, path).ok()? {
            return None;
        }
        index.get_file(GROUP, path).ok().flatten().map(|record| record.size)
    }

    fn held_blocks(&self, path: &str) -> usize {
        let record = self
            .state
            .replica_coordinator
            .file_index_repository()
            .get_file(GROUP, path)
            .unwrap()
            .unwrap();
        record.blocks.iter().filter(|b| self.store.get(&hex::encode(&b.hash)).is_ok()).count()
    }
}

/// Bytes that do not repeat, so every block of the file is distinct.
fn content(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

async fn staged(
    state: &Arc<DaemonState>,
    path: &str,
    dir: &std::path::Path,
    name: &str,
) -> Vec<u8> {
    let outcome =
        materialize_temp(state, GROUP, path, &dir.join(name), None, None).await.expect("fetch");
    match outcome {
        RangedOutcome::Assembled { file, .. } => std::fs::read(file).unwrap(),
        other => panic!("not assembled: {other:?}"),
    }
}

/// Where the large fetch is cancelled.
#[derive(Clone, Copy)]
enum CancelAt {
    /// While one of its fetched blocks is being stored.
    BlockStore,
    /// While the verified blocks are being read into the staging file.
    Assembly,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(windows, ignore = "block reclaim is retain-only on Windows")]
async fn a_fetch_cancelled_mid_transfer_does_not_block_freeing_or_fetching_other_files() {
    cancel_then_free(CancelAt::BlockStore).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(windows, ignore = "block reclaim is retain-only on Windows")]
async fn a_fetch_cancelled_while_assembling_does_not_block_freeing_or_fetching_other_files() {
    cancel_then_free(CancelAt::Assembly).await;
}

async fn cancel_then_free(at: CancelAt) {
    let a = Device::new("device-a", MaterializationPolicy::Eager);
    let b = Device::new("device-b", MaterializationPolicy::OnDemand);
    a.start();
    b.start();
    let (_handles, _link) = support::connect_two_daemons_with_link(
        &a.state,
        a.id,
        &b.state,
        b.id,
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;
    b.state.authority.set_peer_group_full_replica(a.id, GROUP, true);
    b.state.install_p2p_custody_confirmer();

    let big = content(1, 48 * MIB);
    let small = [content(2, 70_000), content(3, 71_000)];
    let staging = tempfile::tempdir_in(a.root.path().parent().unwrap()).unwrap();
    for (name, bytes) in [("big.bin", &big), ("small-0.bin", &small[0]), ("small-1.bin", &small[1])]
    {
        std::fs::write(staging.path().join(name), bytes).unwrap();
        std::fs::rename(staging.path().join(name), a.root.path().join(name)).unwrap();
    }
    support::wait_until_with_context(
        || {
            b.indexed_size("big.bin") == Some(big.len() as u64)
                && b.indexed_size("small-0.bin") == Some(small[0].len() as u64)
                && b.indexed_size("small-1.bin") == Some(small[1].len() as u64)
        },
        Duration::from_secs(120),
        || "device B never adopted the files".into(),
    )
    .await;

    // A provider root has no watched directory.
    b.controller.stop(&b.local_path()).await;
    let host = ProviderEvictHarness::declare(&b.state, GROUP);
    let items = [host.item("small-0.bin"), host.item("small-1.bin"), host.item("big.bin")];
    let out = tempfile::tempdir().unwrap();

    // small-0 is on this device and held by the OS, so it can be freed later.
    assert_eq!(staged(&b.state, "small-0.bin", out.path(), "s0").await, small[0]);
    host.host_holds(items[0]);

    // The large fetch is cancelled while one of its blocks is being stored.
    b.store.arm(matches!(at, CancelAt::Assembly));
    let cancelled = {
        let (state, path) = (b.state.clone(), out.path().join("big-cancelled"));
        tokio::spawn(async move {
            let _ = materialize_temp(&state, GROUP, "big.bin", &path, None, None).await;
        })
    };
    support::wait_until_with_context(
        || b.store.reached(),
        Duration::from_secs(60),
        || "the large fetch never reached the cancel point".into(),
    )
    .await;
    cancelled.abort();
    let _ = cancelled.await;
    b.store.release();

    // Freeing the other file frees its blocks.
    host.reply_next(HostReply::Evicted);
    let mut result = host.evict(GROUP, "small-0.bin").await.unwrap();
    for _ in 0..50 {
        if result.retained != "busy" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        host.reply_next(HostReply::Evicted);
        result = host.evict(GROUP, "small-0.bin").await.unwrap();
    }
    assert_eq!(result.retained, "", "freeing stalled after the cancel: {result:?}");
    assert!(result.blocks_reclaimed >= 1, "{result:?}");
    assert_eq!(b.held_blocks("small-0.bin"), 0);

    // Another small file is fetched, and so is the large one the cancel interrupted.
    let second = tokio::time::timeout(
        Duration::from_secs(60),
        staged(&b.state, "small-1.bin", out.path(), "s1"),
    )
    .await
    .expect("the small fetch stalled after the cancel");
    assert_eq!(second, small[1]);
    let whole = tokio::time::timeout(
        Duration::from_secs(120),
        staged(&b.state, "big.bin", out.path(), "big"),
    )
    .await
    .expect("the large fetch stalled after the cancel");
    assert!(whole == big, "the large file's bytes differ");
}
