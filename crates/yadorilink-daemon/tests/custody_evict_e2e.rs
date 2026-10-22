//! End to end through the daemon, over a real paired session: an on-demand
//! device hydrates a file, takes a durable custody lease at a full replica,
//! evicts it locally (the cached blocks are reclaimed from its block store),
//! garbage collects, and reopens the file (fetched back from the full
//! replica, verified byte for byte).
//!
//! ```text
//!   A (Eager, full replica, responder)      B (OnDemand, requester)
//!   writes the file               --adopt-->  placeholder (Remote)
//!                                 <-fetch--   hydrate (Present)
//!   durable lease row             <-acquire-  evict: hold granted, blocks reclaimed
//!   GC keeps the blocks                       GC; blocks stay gone
//!                                 <-fetch--   reopen: content verified
//! ```
//!
//! Content is generated, written and verified as a stream (never held whole
//! in memory), so the same code covers 4 KiB, 1 MiB and 1 GiB. The 1 GiB case
//! is `#[ignore]`d (about a minute and a half of I/O in a debug build, ~4 GiB of
//! disk); run it with
//! `cargo test -p yadorilink-daemon --test custody_evict_e2e -- --ignored`
//! (`CUSTODY_E2E_BYTES` shrinks it).
//!
//! Faults, each fail closed:
//! - peer unreachable: no lease, no hold granted, every block retained, the
//!   file still opens from them;
//! - responder restart: the lease survives it, GC on the restarted responder
//!   keeps the blocks, the reopen succeeds;
//! - requester restart: the granted hold and the evicted state survive it,
//!   the reconciler does not release the lease, the reopen succeeds.
//!
//! Already covered, not repeated here (`custody_lease.rs`): the lease is a GC
//! live root on its own (`confirmation_is_a_committed_lease_that_keeps_the_
//! blocks_live`), crash ordering of the hold rows (`a_requested_row_is_
//! released_and_removed_after_a_restart`, `a_remote_or_evicting_row_at_the_
//! held_version_keeps_its_lease`), an unreachable peer keeping its hold row
//! (`an_unreachable_peer_keeps_the_row`); and `custody_version_present.rs`
//! (no confirmation from a corrupt, wiped or retained-only peer).

mod support;

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_daemon::test_support::provider_evict_harness::{
    materialize_temp, HostReply, ProviderEvictHarness, RangedOutcome,
};
use yadorilink_filesystem_sync::materialization_eviction::EvictionOutcome;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};
use yadorilink_sync_sqlite::remote_custody_hold::HoldState;

const GROUP: &str = "custody-e2e-group";
const PATH: &str = "payload.bin";
const SEED: u64 = 0x5eed_c0de;
const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Byte `offset..offset+buf.len()` of the generated stream: independent of how
/// the caller slices it, so writer and verifier need no shared state.
fn fill(offset: u64, buf: &mut [u8]) {
    let mut at = offset;
    let mut out = 0;
    while out < buf.len() {
        let mut word = (at / 8).wrapping_add(SEED).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        word ^= word >> 31;
        let bytes = word.to_le_bytes();
        let skip = (at % 8) as usize;
        let take = (8 - skip).min(buf.len() - out);
        buf[out..out + take].copy_from_slice(&bytes[skip..skip + take]);
        out += take;
        at += take as u64;
    }
}

fn write_stream(path: &std::path::Path, size: u64) {
    let mut file = std::fs::File::create(path).unwrap();
    let mut buf = vec![0u8; MIB as usize];
    let mut offset = 0;
    while offset < size {
        let n = (size - offset).min(MIB) as usize;
        fill(offset, &mut buf[..n]);
        file.write_all(&buf[..n]).unwrap();
        offset += n as u64;
    }
    file.sync_all().unwrap();
}

fn verify_stream(path: &std::path::Path, size: u64) {
    let mut file = std::fs::File::open(path).unwrap();
    assert_eq!(file.metadata().unwrap().len(), size, "wrong length");
    let mut have = vec![0u8; MIB as usize];
    let mut want = vec![0u8; MIB as usize];
    let mut offset = 0;
    while offset < size {
        let n = (size - offset).min(MIB) as usize;
        file.read_exact(&mut have[..n]).unwrap();
        fill(offset, &mut want[..n]);
        assert!(have[..n] == want[..n], "content differs in the 1 MiB at offset {offset}");
        offset += n as u64;
    }
}

struct Dev {
    id: &'static str,
    state: Arc<DaemonState>,
    controller: LinkRuntimeController,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    index_dir: tempfile::TempDir,
    store: Arc<SegmentBlockStore>,
    /// States of earlier runs. Kept alive so the harness's per-state registries (keyed by
    /// address) never see a new state at a dead one's address.
    retired: Vec<Arc<DaemonState>>,
}

impl Dev {
    fn local_path(&self) -> String {
        self.root.path().to_string_lossy().to_string()
    }

    fn open_state(
        id: &str,
        index_dir: &std::path::Path,
        store: &Arc<SegmentBlockStore>,
    ) -> Arc<DaemonState> {
        let coordinator = yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open(
            index_dir.join("index.db"),
        )
        .unwrap();
        let state = DaemonState::new(id.to_string(), Arc::new(coordinator), store.clone());
        state.set_test_on_demand_allowed(true);
        state
    }

    /// A fresh device with its link registered (not yet watching).
    fn new(id: &'static str, policy: MaterializationPolicy) -> Dev {
        support::ensure_isolated_config_dir();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let index_dir = tempfile::tempdir().unwrap();
        let state = Self::open_state(id, index_dir.path(), &store);
        support::ensure_device_signing_key(&state);
        let dev = Dev {
            id,
            controller: LinkRuntimeController::new(state.clone()),
            state,
            root: tempfile::tempdir().unwrap(),
            _store_dir: store_dir,
            index_dir,
            store,
            retired: Vec::new(),
        };
        let repo = dev.state.replica_coordinator.link_repository();
        repo.add_link(&dev.local_path(), GROUP).unwrap();
        repo.set_materialization_policy(&dev.local_path(), policy).unwrap();
        dev
    }

    fn start(&self) {
        self.controller.start(self.local_path(), GROUP.to_string()).unwrap();
    }

    /// The process dies and comes back on the same files: a new `DaemonState` over the same
    /// index and block store, the same identity key, the watch started again.
    async fn restart(&mut self) {
        let key = self.state.device_signing_key().expect("a signing key");
        self.controller.stop(&self.local_path()).await;
        let next = Self::open_state(self.id, self.index_dir.path(), &self.store);
        self.retired.push(std::mem::replace(&mut self.state, next));
        self.state.set_device_signing_key(key);
        self.controller = LinkRuntimeController::new(self.state.clone());
        self.start();
    }

    fn record(&self) -> Option<FileRecord> {
        let index = self.state.replica_coordinator.file_index_repository();
        if !index.has_real_current_row(GROUP, PATH).ok()? {
            return None;
        }
        index.get_file(GROUP, PATH).ok().flatten()
    }

    fn materialization(&self) -> Option<MaterializationState> {
        self.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .ok()
            .flatten()
    }

    fn held_blocks(&self, record: &FileRecord) -> usize {
        record.blocks.iter().filter(|b| self.store.get(&hex::encode(&b.hash)).is_ok()).count()
    }

    fn leases(&self) -> usize {
        self.state
            .replica_coordinator
            .remote_custody_lease_repository()
            .list_active()
            .unwrap()
            .len()
    }

    fn hold_states(&self) -> Vec<HoldState> {
        self.state
            .replica_coordinator
            .remote_custody_hold_repository()
            .list()
            .unwrap()
            .into_iter()
            .map(|hold| hold.state)
            .collect()
    }
}

struct Pairing {
    handles: [tokio::task::JoinHandle<()>; 2],
    _link: Arc<support::PairingLink>,
}

async fn pair(a: &Dev, b: &Dev) -> Pairing {
    let (handles, link) = support::connect_two_daemons_with_link(
        &a.state,
        a.id,
        &b.state,
        b.id,
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;
    // No coordination plane here: say who the full replica is, and install the production
    // custody confirmer on the requester.
    b.state.authority.set_peer_group_full_replica(a.id, GROUP, true);
    b.state.install_p2p_custody_confirmer();
    Pairing { handles, _link: link }
}

async fn sever(a: &Dev, b: &Dev, pairing: Pairing) {
    support::sever_reconciliation(&a.state, &b.state).await;
    for handle in &pairing.handles {
        handle.abort();
    }
    drop(pairing);
    // A peer that went away is no longer a session either side can ask.
    a.state.peers.remove(b.id);
    b.state.peers.remove(a.id);
    tokio::time::sleep(Duration::from_millis(300)).await;
}

/// Both devices up, paired, and the file written on A and adopted by B as a placeholder.
async fn world(size: u64) -> (Dev, Dev, Pairing, FileRecord) {
    let a = Dev::new("device-a", MaterializationPolicy::Eager);
    let b = Dev::new("device-b", MaterializationPolicy::OnDemand);
    a.start();
    b.start();
    let pairing = pair(&a, &b).await;

    // Written beside the root and renamed in, so the watcher sees the whole file at once.
    let staging = tempfile::tempdir_in(a.root.path().parent().unwrap()).unwrap();
    let staged = staging.path().join(PATH);
    write_stream(&staged, size);
    std::fs::rename(&staged, a.root.path().join(PATH)).unwrap();

    let patience = Duration::from_secs(60 + size / MIB);
    support::wait_until_with_context(
        || b.record().is_some_and(|r| r.size == size) && b.materialization().is_some(),
        patience,
        || "device B never adopted the file".into(),
    )
    .await;
    let record = b.record().unwrap();
    assert_eq!(b.materialization(), Some(MaterializationState::Remote), "adopted as a placeholder");
    assert_eq!(b.held_blocks(&record), 0, "adoption fetched bytes");
    support::wait_until_with_context(
        || a.record().is_some_and(|r| r.size == size),
        patience,
        || "device A never indexed its file".into(),
    )
    .await;
    (a, b, pairing, record)
}

/// Opens the file (a hydration) and checks its bytes. A hydration can be refused for a moment
/// right after a pairing or a restart, while the peer's published state is still arriving, so it
/// is tried a few times; the last failure is the test's.
async fn open_on(b: &Dev, size: u64) {
    let mut attempts = 0;
    loop {
        attempts += 1;
        match hydration::hydrate(&b.state, GROUP, PATH).await {
            Ok(()) => break,
            Err(_) if attempts < 10 => tokio::time::sleep(Duration::from_secs(1)).await,
            Err(error) => panic!("hydrate failed {attempts} times: {error:?}"),
        }
    }
    assert_eq!(b.materialization(), Some(MaterializationState::Present));
    verify_stream(&b.root.path().join(PATH), size);
}

/// `hydration::evict`, retried while a live session still holds the path for a moment.
async fn evict(b: &Dev) -> EvictionOutcome {
    use yadorilink_daemon::sync_error::SyncError;
    // Eviction unlinks the working-tree copy only where the OS proves no writer can exist (the
    // Linux write lease). Elsewhere (macOS) it keeps the file by design, so stand in for the
    // exclusion there; Linux runs the real lease.
    for _ in 0..200 {
        let result = {
            // Armed per call, on the thread that runs it (the flag is thread-local).
            #[cfg(not(target_os = "linux"))]
            let _exclusion =
                yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test();
            hydration::evict(&b.state, GROUP, PATH)
        };
        match result {
            Err(SyncError::EvictionRejected(_)) => {
                tokio::time::sleep(Duration::from_millis(100)).await
            }
            other => return other.expect("evict"),
        }
    }
    panic!("the eviction stayed rejected");
}

async fn gc(dev: &Dev) {
    for _ in 0..100 {
        match yadorilink_daemon::gc::run_sweep(dev.state.clone(), false).await {
            Ok(_) => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    panic!("GC never ran on {}", dev.id);
}

/// Runs the hold reconciler until it reports nothing left to settle. A pass answers `true` when
/// some hold could not be settled yet (its path busy, the peer unreachable) and a later pass
/// should retry; right after a reopen the path is briefly busy with the daemon's own follow-up
/// work, so one pass may skip it. The loop is bounded, and ends with every hold settled.
async fn settle_holds(dev: &Dev) {
    for _ in 0..200 {
        if !dev.state.release_obsolete_custody_holds().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the hold reconciler never finished on {}", dev.id);
}

/// Evicts with a lease and checks what that must leave behind.
async fn evict_with_custody(a: &Dev, b: &Dev, record: &FileRecord) {
    let outcome = evict(b).await;
    assert!(outcome.dehydrated, "the working-tree copy was not freed");
    assert!(!outcome.blocks_retained, "a leased eviction kept its blocks");
    assert!(outcome.blocks_reclaimed >= 1 && outcome.bytes_reclaimed > 0);
    assert_eq!(b.materialization(), Some(MaterializationState::Remote));
    assert_eq!(b.held_blocks(record), 0, "a block of the evicted version stayed on B");
    assert!(std::fs::symlink_metadata(b.root.path().join(PATH)).is_err());
    assert_eq!(a.leases(), 1, "the responder holds the lease");
    assert_eq!(b.hold_states(), [HoldState::Granted]);
    assert_eq!(a.held_blocks(record), record.blocks.len(), "the complete copy lost a block");
}

/// The whole path for one size.
async fn hydrate_acquire_evict_gc_reopen(size: u64) {
    let (a, b, _pairing, record) = world(size).await;
    eprintln!("stage: adopted ({} blocks)", record.blocks.len());
    open_on(&b, size).await;
    eprintln!("stage: hydrated");
    evict_with_custody(&a, &b, &record).await;
    eprintln!("stage: evicted");

    gc(&b).await;
    gc(&a).await;
    assert_eq!(b.held_blocks(&record), 0, "GC brought a block back");
    assert_eq!(a.held_blocks(&record), record.blocks.len(), "GC on the complete copy ate a block");
    assert_eq!(a.leases(), 1, "GC dropped the lease");

    // Reopen: the bytes come back from the full replica and match the original stream.
    open_on(&b, size).await;
    assert_eq!(b.held_blocks(&record), record.blocks.len());
    // The file is Present again, so the lease is no longer depended on.
    settle_holds(&b).await;
    assert_eq!(a.leases(), 0);
    assert!(b.hold_states().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "block reclaim is retain-only on Windows while its directory durability gate is closed, and this harness has no cfapi-host for eviction"
)]
async fn custody_round_trip_4_kib() {
    hydrate_acquire_evict_gc_reopen(4 * KIB).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "block reclaim is retain-only on Windows while its directory durability gate is closed, and this harness has no cfapi-host for eviction"
)]
async fn custody_round_trip_1_mib() {
    hydrate_acquire_evict_gc_reopen(MIB).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "block reclaim is retain-only on Windows while its directory durability gate is closed, and this harness has no cfapi-host for eviction"
)]
#[cfg_attr(
    not(windows),
    ignore = "1 GiB of generated content through two daemons; minutes of I/O and ~4 GiB of disk"
)]
async fn custody_round_trip_1_gib() {
    // `CUSTODY_E2E_BYTES` shrinks the run for a quick look at the scaling.
    let size = std::env::var("CUSTODY_E2E_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(GIB);
    hydrate_acquire_evict_gc_reopen(size).await;
}

/// The only peer that could take custody cannot be reached: no lease is taken, no hold is
/// granted, no block is reclaimed, and the file still opens from the blocks that were kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "block reclaim is retain-only on Windows while its directory durability gate is closed, and this harness has no cfapi-host for eviction"
)]
async fn an_unreachable_peer_evicts_and_reclaims_nothing() {
    let size = 64 * KIB;
    let (a, b, pairing, record) = world(size).await;
    open_on(&b, size).await;
    sever(&a, &b, pairing).await;

    // An attempt that left the file alone (the path was busy for a moment) is tried again, so
    // that what is asserted below is an eviction that really ran without custody.
    let mut outcome = evict(&b).await;
    for _ in 0..50 {
        if outcome.dehydrated {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        outcome = evict(&b).await;
    }

    // The working-tree copy goes (every block it needs is still here); nothing is reclaimed on
    // unconfirmed custody.
    assert!(outcome.dehydrated, "the eviction never ran");
    assert_eq!(b.materialization(), Some(MaterializationState::Remote));
    assert!(std::fs::symlink_metadata(b.root.path().join(PATH)).is_err());
    assert!(outcome.blocks_retained, "blocks were reclaimed without a confirmed lease");
    assert_eq!(outcome.blocks_reclaimed, 0);
    assert_eq!(b.held_blocks(&record), record.blocks.len());
    assert_eq!(a.leases(), 0);
    assert!(!b.hold_states().contains(&HoldState::Granted));

    gc(&b).await;
    assert_eq!(b.held_blocks(&record), record.blocks.len(), "GC removed a block that has no lease");
    // Readable offline, from the retained blocks.
    open_on(&b, size).await;
}

/// The responder restarts after granting: the lease is durable, GC on the restarted responder
/// keeps the blocks, and the requester reopens the file from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "block reclaim is retain-only on Windows while its directory durability gate is closed, and this harness has no cfapi-host for eviction"
)]
async fn a_responder_restart_keeps_the_lease_and_the_file_reopens() {
    let size = 64 * KIB;
    let (mut a, b, pairing, record) = world(size).await;
    open_on(&b, size).await;
    evict_with_custody(&a, &b, &record).await;

    sever(&a, &b, pairing).await;
    a.restart().await;
    assert_eq!(a.leases(), 1, "the lease did not survive the restart");
    // The responder's own file rows also root these blocks, and GC's grace window protects fresh
    // ones, so this is a smoke check. That a lease alone is a GC live root is proven in
    // `custody_lease.rs` (`confirmation_is_a_committed_lease_that_keeps_the_blocks_live`); here
    // the row's durability across the restart is what is asserted.
    gc(&a).await;
    assert_eq!(a.held_blocks(&record), record.blocks.len(), "GC after the restart ate a block");

    let _pairing = pair(&a, &b).await;
    open_on(&b, size).await;
    assert_eq!(a.leases(), 1, "the lease is released only once the hold reconciler runs");
    settle_holds(&b).await;
    assert_eq!(a.leases(), 0);
}

/// The requester restarts after evicting: its granted hold and the evicted state survive, the
/// reconciler keeps the lease while the file is evicted, and the reopen works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "block reclaim is retain-only on Windows while its directory durability gate is closed, and this harness has no cfapi-host for eviction"
)]
async fn a_requester_restart_keeps_the_hold_and_the_file_reopens() {
    let size = 64 * KIB;
    let (a, mut b, pairing, record) = world(size).await;
    open_on(&b, size).await;
    evict_with_custody(&a, &b, &record).await;

    sever(&a, &b, pairing).await;
    b.restart().await;
    assert_eq!(b.materialization(), Some(MaterializationState::Remote));
    assert_eq!(b.hold_states(), [HoldState::Granted], "the hold did not survive the restart");
    assert_eq!(b.held_blocks(&record), 0);

    let _pairing = pair(&a, &b).await;
    settle_holds(&b).await;
    assert_eq!(a.leases(), 1, "the reconciler released a lease the evicted file depends on");

    open_on(&b, size).await;
    settle_holds(&b).await;
    assert_eq!(a.leases(), 0);
}

/// The production provider route (`ProviderEvictor` over the real `ProviderReclaim` and its async
/// peer custody, the hold reconciler, the provider hydration into a staging file) against a real
/// responder over a real paired session. The File Provider host is the only fake: it answers the
/// OS-side eviction. Unlike the tests above, which drive the linked-root `hydration::evict`
/// protocol path, this is the path the custody flag enables in a shipped build.
async fn provider_round_trip(reply: HostReply) {
    let size = 300 * KIB;
    let (a, b, _pairing, record) = world(size).await;
    // A provider root has no watched directory: the daemon writes nothing user-visible there.
    b.controller.stop(&b.local_path()).await;
    let host = ProviderEvictHarness::declare(&b.state, GROUP);
    let item = host.item(PATH);
    let staging = tempfile::tempdir().unwrap();

    // The item is materialized: the daemon assembled the bytes for the OS, the host reports it
    // holds them, and the blocks are in the daemon's store. A block no item names must survive.
    let assembled = host.materialize(GROUP, PATH, &staging.path().join("first")).await.unwrap();
    verify_stream(&assembled, size);
    host.host_holds(item);
    assert_eq!(b.held_blocks(&record), record.blocks.len());
    let unrelated = b.store.put(b"a cached block no evicted item names").unwrap();

    // The eviction takes a real lease at the responder before the OS copy goes.
    host.reply_next(reply);
    let mut result = host.evict(GROUP, PATH).await.unwrap();
    for _ in 0..50 {
        if result.retained != "busy" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        host.reply_next(reply);
        result = host.evict(GROUP, PATH).await.unwrap();
    }
    assert_eq!(result.retained, "", "blocks stayed: {result:?}");
    assert_eq!(result.dehydrated, reply == HostReply::Evicted);
    assert_eq!(result.blocks_reclaimed, record.blocks.len() as u64);
    assert!(host.host_was_asked() >= 1);
    assert_eq!(b.held_blocks(&record), 0, "a block of the evicted item stayed");
    assert!(b.store.exists(&unrelated).unwrap(), "a block no evicted item names was removed");
    assert_eq!(a.leases(), 1, "the responder holds a durable lease");
    assert_eq!(b.hold_states(), [HoldState::Granted]);
    assert_eq!(a.held_blocks(&record), record.blocks.len());

    // While the item depends on the lease, the reconciler keeps it and GC on the responder
    // leaves its blocks.
    settle_holds(&b).await;
    gc(&a).await;
    assert_eq!(a.leases(), 1);
    assert_eq!(a.held_blocks(&record), record.blocks.len());

    // The next open fetches the exact bytes back; with them local again the lease is released.
    let reopened = host.materialize(GROUP, PATH, &staging.path().join("second")).await.unwrap();
    verify_stream(&reopened, size);
    assert_eq!(b.held_blocks(&record), record.blocks.len());
    settle_holds(&b).await;
    assert_eq!(a.leases(), 0, "the lease outlived the need for it");
    assert!(b.hold_states().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "block reclaim is retain-only on Windows while its directory durability gate is closed"
)]
async fn the_provider_route_leases_evicts_reclaims_and_reopens() {
    provider_round_trip(HostReply::Evicted).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "block reclaim is retain-only on Windows while its directory durability gate is closed"
)]
async fn the_provider_route_reclaims_for_an_item_the_os_already_dropped() {
    provider_round_trip(HostReply::NotMaterialized).await;
}

/// Automatic space management under disk pressure gives a downloaded file back through the same
/// provider route as a person's "free up space": a real lease at the responder before the OS copy
/// goes, the blocks reclaimed, and the next open fetches the exact bytes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "block reclaim is retain-only on Windows while its directory durability gate is closed"
)]
async fn automatic_space_management_reclaims_through_the_provider_route_and_the_file_reopens() {
    let size = 300 * KIB;
    let (a, b, _pairing, record) = world(size).await;
    b.controller.stop(&b.local_path()).await;
    let host = ProviderEvictHarness::declare(&b.state, GROUP);
    let item = host.item(PATH);
    let staging = tempfile::tempdir().unwrap();
    let assembled = host.materialize(GROUP, PATH, &staging.path().join("first")).await.unwrap();
    verify_stream(&assembled, size);
    host.host_holds(item);
    assert_eq!(b.held_blocks(&record), record.blocks.len());

    // Right after the download the item can still be held by the hydration for a moment: the
    // scan then leaves it out (an empty pass) or its turn finds it busy.
    let mut pass = host.auto_reclaim_pass().await;
    for _ in 0..50 {
        if !pass.is_empty() && !pass.iter().any(|done| done.reason == "busy") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        pass = host.auto_reclaim_pass().await;
    }
    assert_eq!(pass.len(), 1, "{pass:?}");
    assert_eq!(pass[0].path, PATH);
    assert!(pass[0].reclaimed, "{pass:?}");
    assert_eq!(pass[0].blocks, record.blocks.len() as u64, "{pass:?}");
    assert!(host.host_was_asked() >= 1);
    assert_eq!(b.held_blocks(&record), 0, "a block of the reclaimed item stayed");
    assert_eq!(a.leases(), 1, "the responder holds a durable lease");

    let reopened = host.materialize(GROUP, PATH, &staging.path().join("second")).await.unwrap();
    verify_stream(&reopened, size);
    settle_holds(&b).await;
    assert_eq!(a.leases(), 0, "the lease outlived the need for it");
}

// ---- Ranged materialization: a window of an exact version, fetched block-wise ----------------

/// The version hash of B's current row for the file.
fn current_version(b: &Dev) -> [u8; 32] {
    b.state
        .replica_coordinator
        .file_index_repository()
        .canonical_current_row(GROUP, PATH)
        .unwrap()
        .expect("a current row")
        .version_hash()
        .0
}

/// The indexes of `record`'s blocks that overlap `[offset, offset + len)`.
fn covering(record: &FileRecord, offset: u64, len: u64) -> Vec<usize> {
    record
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| b.offset < offset + len && b.offset + b.size as u64 > offset)
        .map(|(n, _)| n)
        .collect()
}

fn held_set(b: &Dev, record: &FileRecord) -> Vec<usize> {
    record
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, blk)| b.store.get(&hex::encode(&blk.hash)).is_ok())
        .map(|(n, _)| n)
        .collect()
}

/// One ranged request on B for `version`. A request can be refused for a moment right after a
/// pairing, while the peer's published state is still arriving, so a failure is retried a few
/// times; `RangeNotSatisfiable` and `VersionOutOfDate` are answers, never retried.
async fn ranged_on(
    b: &Dev,
    version: [u8; 32],
    offset: u64,
    len: u64,
    staging: &std::path::Path,
    tries: usize,
) -> Result<RangedOutcome, String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut attempt = 0;
    loop {
        attempt += 1;
        let staged = staging
            .join(format!("window-{}", NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
        match materialize_temp(&b.state, GROUP, PATH, &staged, Some(version), Some((offset, len)))
            .await
        {
            Ok(outcome) => return Ok(outcome),
            Err(_) if attempt < tries => tokio::time::sleep(Duration::from_millis(500)).await,
            Err(error) => return Err(format!("{error:?}")),
        }
    }
}

/// The served window must hold exactly the generated stream's bytes at that offset.
fn verify_window(file: &std::path::Path, offset: u64, len: u64) {
    let have = std::fs::read(file).unwrap();
    let mut want = vec![0u8; len as usize];
    fill(offset, &mut want);
    assert!(have == want, "the window at {offset}+{len} differs");
}

/// Nothing a ranged request does may make the file present, or leave anything in its place.
fn assert_not_present(b: &Dev) {
    assert_eq!(b.materialization(), Some(MaterializationState::Remote), "a window made it present");
    assert!(std::fs::symlink_metadata(b.root.path().join(PATH)).is_err(), "a file appeared");
}

const RANGED_SIZE: u64 = 4 * MIB;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_inside_one_block_fetches_that_block_only() {
    let (_a, b, _pairing, record) = world(RANGED_SIZE).await;
    assert!(record.blocks.len() >= 8, "the file must span many blocks: {}", record.blocks.len());
    let staging = tempfile::tempdir().unwrap();
    let mid = &record.blocks[record.blocks.len() / 2];
    let (offset, len) = (mid.offset + 10, (mid.size as u64 / 2).max(1));
    let expected = covering(&record, offset, len);
    assert_eq!(expected.len(), 1, "the window was meant to sit in one block");

    let RangedOutcome::Assembled { file, served, size } =
        ranged_on(&b, current_version(&b), offset, len, staging.path(), 10).await.unwrap()
    else {
        panic!("not assembled")
    };
    assert_eq!((served, size), (Some((offset, len)), RANGED_SIZE));
    verify_window(&file, offset, len);
    assert_eq!(held_set(&b, &record), expected, "more than the covering block was fetched");
    assert_not_present(&b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_across_two_blocks_fetches_both_and_only_both() {
    let (_a, b, _pairing, record) = world(RANGED_SIZE).await;
    let staging = tempfile::tempdir().unwrap();
    let k = record.blocks.len() / 2;
    let boundary = record.blocks[k].offset;
    let (offset, len) = (boundary - 7, 20);
    assert_eq!(covering(&record, offset, len), [k - 1, k]);

    let RangedOutcome::Assembled { file, served, .. } =
        ranged_on(&b, current_version(&b), offset, len, staging.path(), 10).await.unwrap()
    else {
        panic!("not assembled")
    };
    assert_eq!(served, Some((offset, len)));
    verify_window(&file, offset, len);
    assert_eq!(held_set(&b, &record), [k - 1, k]);
    assert_not_present(&b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ranges_at_the_end_empty_and_past_it() {
    let (_a, b, _pairing, record) = world(RANGED_SIZE).await;
    let staging = tempfile::tempdir().unwrap();
    let version = current_version(&b);
    let last = record.blocks.len() - 1;

    // Reaching past the end is cut at the end: the last block alone is fetched.
    let tail = record.blocks[last].offset + 5;
    let RangedOutcome::Assembled { file, served, .. } =
        ranged_on(&b, version, tail, 1 << 30, staging.path(), 10).await.unwrap()
    else {
        panic!("not assembled")
    };
    assert_eq!(served, Some((tail, RANGED_SIZE - tail)));
    verify_window(&file, tail, RANGED_SIZE - tail);
    assert_eq!(held_set(&b, &record), [last]);

    // A window of no bytes, inside the file and exactly at its end, needs no block and no peer.
    for offset in [0, RANGED_SIZE / 3, RANGED_SIZE] {
        let RangedOutcome::Assembled { file, served, .. } =
            ranged_on(&b, version, offset, 0, staging.path(), 1).await.unwrap()
        else {
            panic!("not assembled")
        };
        assert_eq!(served, Some((offset, 0)));
        assert_eq!(std::fs::metadata(&file).unwrap().len(), 0);
    }
    // An offset past the end cannot be satisfied.
    assert!(matches!(
        ranged_on(&b, version, RANGED_SIZE + 1, 1, staging.path(), 1).await.unwrap(),
        RangedOutcome::RangeNotSatisfiable
    ));
    assert_eq!(held_set(&b, &record), [last], "an empty or refused window fetched a block");
    assert_not_present(&b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_the_peer_cannot_supply_intact_fails_the_range_and_stores_nothing() {
    let (a, b, _pairing, record) = world(RANGED_SIZE).await;
    let staging = tempfile::tempdir().unwrap();
    let k = record.blocks.len() / 2;
    let block = &record.blocks[k];
    support::corrupt_stored_block(a._store_dir.path(), &hex::encode(&block.hash));

    let result = ranged_on(&b, current_version(&b), block.offset + 1, 8, staging.path(), 2).await;
    assert!(
        !matches!(result, Ok(RangedOutcome::Assembled { .. })),
        "bytes were returned for a corrupt block: {result:?}"
    );
    assert!(held_set(&b, &record).is_empty(), "an unverified block was stored");
    assert!(std::fs::read_dir(staging.path()).unwrap().next().is_none(), "bytes were left behind");
    assert_not_present(&b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_went_away_fails_the_range_closed() {
    let (a, b, pairing, record) = world(RANGED_SIZE).await;
    let version = current_version(&b);
    sever(&a, &b, pairing).await;
    let staging = tempfile::tempdir().unwrap();
    let result = ranged_on(&b, version, 100, 8, staging.path(), 1).await;
    assert!(!matches!(result, Ok(RangedOutcome::Assembled { .. })), "{result:?}");
    assert!(held_set(&b, &record).is_empty());
    assert!(std::fs::read_dir(staging.path()).unwrap().next().is_none());
    assert_not_present(&b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_of_a_version_that_is_no_longer_current_is_refused() {
    let (a, b, _pairing, record) = world(RANGED_SIZE).await;
    let old = current_version(&b);

    // The peer moves on to a longer file; B adopts the new version.
    let newer = RANGED_SIZE + 64 * KIB;
    let staged = a.root.path().parent().unwrap().join("newer.bin");
    write_stream(&staged, newer);
    std::fs::rename(&staged, a.root.path().join(PATH)).unwrap();
    support::wait_until_with_context(
        || b.record().is_some_and(|r| r.size == newer),
        Duration::from_secs(60),
        || "device B never adopted the newer version".into(),
    )
    .await;

    let staging = tempfile::tempdir().unwrap();
    assert!(matches!(
        ranged_on(&b, old, 10, 8, staging.path(), 1).await.unwrap(),
        RangedOutcome::VersionOutOfDate
    ));
    assert!(held_set(&b, &record).is_empty(), "a block of the stale version was fetched");
    assert_not_present(&b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_open_after_a_range_fetches_only_the_missing_blocks() {
    let (a, b, _pairing, record) = world(RANGED_SIZE).await;
    let staging = tempfile::tempdir().unwrap();
    let k = record.blocks.len() / 2;
    let (offset, len) = (record.blocks[k].offset + 3, 5);
    ranged_on(&b, current_version(&b), offset, len, staging.path(), 10).await.unwrap();
    assert_eq!(held_set(&b, &record), [k]);
    assert_not_present(&b);

    // The responder can no longer supply the block B already holds: a full open that went back to
    // the peer for it would fail, so success means the held block was used as it was.
    support::corrupt_stored_block(a._store_dir.path(), &hex::encode(&record.blocks[k].hash));

    open_on(&b, RANGED_SIZE).await;
    assert_eq!(b.materialization(), Some(MaterializationState::Present));
    assert_eq!(b.held_blocks(&record), record.blocks.len());
    verify_stream(&b.root.path().join(PATH), RANGED_SIZE);
}

/// A 4 KiB open of a 1 GiB file: the window the Windows host asks for is one aligned 4 KiB range
/// of the exact version, and only the blocks covering it are fetched, never the whole file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_4_kib_open_of_a_1_gib_file_fetches_only_the_covering_blocks() {
    let (_a, b, _pairing, record) = world(GIB).await;
    assert_eq!(record.size, GIB);
    let staging = tempfile::tempdir().unwrap();
    let (offset, len) = (GIB / 2, 4 * KIB);
    let expected = covering(&record, offset, len);
    assert!(!expected.is_empty() && expected.len() <= 2, "{expected:?}");

    let RangedOutcome::Assembled { file, served, size } =
        ranged_on(&b, current_version(&b), offset, len, staging.path(), 10).await.unwrap()
    else {
        panic!("not assembled")
    };
    assert_eq!((served, size), (Some((offset, len)), GIB));
    verify_window(&file, offset, len);
    let held = held_set(&b, &record);
    assert_eq!(held, expected, "more than the covering blocks were fetched");
    let held_bytes: u64 = held.iter().map(|n| record.blocks[*n].size as u64).sum();
    assert!(held_bytes < GIB / 64, "{held_bytes} bytes of a {GIB}-byte file were fetched");
    assert_not_present(&b);
}
