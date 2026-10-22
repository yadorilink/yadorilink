//! Acceptance coverage for the convergence engine's source-side
//! shared block-serving scheduler, byte fairness, explicit congestion signals,
//! and separation of content backpressure from control/metadata traffic.
//!
//! These tests intentionally exercise observable behavior through real
//! `PeerSyncSession`s rather than naming a particular `BlockServeEngine` API.
//! The implementation may choose its internal queue/coalescer types freely.
//!
//! A serving path without that scheduler fails these tests:
//! - identical requests arriving through different peer sessions each perform
//!   their own source-store read;
//! - enough stalled `BlockRequest` handlers consume the ordinary-message
//!   permits and delay a control query on the same session;
//! - one peer/group can place a large FIFO backlog ahead of later work from a
//!   different peer or group;
//! - the wire schema has no explicit serve-credit or Busy/Redirect contract.

mod support;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tokio::task::JoinSet;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::{
    BlockStore, ContentHash, GcReport, SegmentBlockStore, StorageError,
};
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, VersionHash};

const GROUP_A: &str = "stage2-group-a";
const GROUP_B: &str = "stage2-group-b";

#[derive(Clone, Copy)]
enum ReadMode {
    Delay(Duration),
    Gate,
}

#[derive(Default)]
struct ReadState {
    calls_by_hash: HashMap<String, usize>,
    entered: Vec<String>,
    permits: usize,
    immediate_hashes: HashSet<String>,
}

/// A real `SegmentBlockStore` with deterministic observation/control around `get`.
///
/// `Delay` widens the overlap window so identical cross-session requests must
/// coalesce. `Gate` records every source read and blocks it until the test
/// releases a permit, making queue order and control-lane starvation directly
/// observable without relying on machine speed.
struct InstrumentedBlockStore {
    inner: Arc<SegmentBlockStore>,
    mode: ReadMode,
    state: Mutex<ReadState>,
    changed: Condvar,
}

impl InstrumentedBlockStore {
    fn new(inner: Arc<SegmentBlockStore>, mode: ReadMode) -> Self {
        Self { inner, mode, state: Mutex::new(ReadState::default()), changed: Condvar::new() }
    }

    fn calls_for(&self, hash_hex: &str) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .calls_by_hash
            .get(hash_hex)
            .copied()
            .unwrap_or(0)
    }

    fn allow_immediate(&self, hash_hex: &str) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .immediate_hashes
            .insert(hash_hex.to_string());
    }

    fn release(&self, count: usize) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.permits = state.permits.saturating_add(count);
        self.changed.notify_all();
    }

    /// Let every gated read through, for good.
    ///
    /// The gate is deliberately untimed -- that is what makes queue order
    /// observable without depending on machine speed -- but an untimed wait
    /// that outlives the test body turns a failing assertion into a hung
    /// binary rather than a failed test. A gated read parks a blocking-pool
    /// thread, the panic unwinds past the test's own `release`, and the
    /// `#[tokio::test]` runtime's drop then waits for those threads forever.
    /// Measured: after the assertion at `late_small_requests...` fired, the
    /// process sat at 28 threads and zero CPU until it was killed.
    ///
    /// [`GateOpenOnUnwind`] calls this from `Drop`, so it runs on the panic
    /// path as well as the ordinary one.
    fn open_permanently(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.permits = usize::MAX;
        self.changed.notify_all();
    }

    fn wait_for_entered_at_least(&self, count: usize, timeout: Duration) -> usize {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        while state.entered.len() < count {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|p| p.into_inner());
            state = next;
        }
        state.entered.len()
    }

    /// Starts the gate over: reads that already entered are forgotten and every later read
    /// waits for a permit again.
    fn close_gate_and_forget_entered(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.permits = 0;
        state.entered.clear();
        self.changed.notify_all();
    }

    fn entered_count(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).entered.len()
    }

    fn entered_position(&self, hash_hex: &str) -> Option<usize> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entered
            .iter()
            .position(|h| h == hash_hex)
    }
}

/// Opens a gated store's gate when the test body ends, however it ends.
///
/// See [`InstrumentedBlockStore::open_permanently`].
struct GateOpenOnUnwind(Arc<InstrumentedBlockStore>);

impl Drop for GateOpenOnUnwind {
    fn drop(&mut self) {
        self.0.open_permanently();
    }
}

impl BlockStore for InstrumentedBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.inner.put(data)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let immediate = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            *state.calls_by_hash.entry(hash.to_string()).or_insert(0) += 1;
            state.entered.push(hash.to_string());
            let immediate = state.immediate_hashes.contains(hash);
            self.changed.notify_all();

            if matches!(self.mode, ReadMode::Gate) && !immediate {
                while state.permits == 0 {
                    state = self.changed.wait(state).unwrap_or_else(|p| p.into_inner());
                }
                state.permits -= 1;
            }
            immediate
        };

        if !immediate {
            if let ReadMode::Delay(delay) = self.mode {
                std::thread::sleep(delay);
            }
        }
        self.inner.get(hash)
    }

    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
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
    device_id: String,
    state: Arc<DaemonState>,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
    _roots: Vec<tempfile::TempDir>,
}

fn new_plain_device(device_id: &str, groups: &[&str]) -> Device {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    new_device(device_id, groups, store, store_dir)
}

fn new_instrumented_device(
    device_id: &str,
    groups: &[&str],
    mode: ReadMode,
) -> (Device, Arc<InstrumentedBlockStore>) {
    let store_dir = tempfile::tempdir().unwrap();
    let inner = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let instrumented = Arc::new(InstrumentedBlockStore::new(inner, mode));
    let store: Arc<dyn BlockStore + Send + Sync> = instrumented.clone();
    (new_device(device_id, groups, store, store_dir), instrumented)
}

fn new_device(
    device_id: &str,
    groups: &[&str],
    store: Arc<dyn BlockStore + Send + Sync>,
    store_dir: tempfile::TempDir,
) -> Device {
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.to_string(), Arc::new(sync_state), store);
    support::ensure_device_signing_key(&state);
    let mut roots = Vec::new();
    for group in groups {
        let root = tempfile::tempdir().unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link(&root.path().to_string_lossy(), group)
            .unwrap();
        support::mark_group_started(&state, group);
        roots.push(root);
    }
    Device {
        device_id: device_id.to_string(),
        state,
        _store_dir: store_dir,
        _index_dir: index_dir,
        _roots: roots,
    }
}

#[derive(Clone)]
struct SeededBlock {
    path: String,
    hash: Vec<u8>,
    hash_hex: String,
    data: Vec<u8>,
    version_hash: VersionHash,
    version_blocks: Vec<VersionBlock>,
}

fn seeded_data(seed: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i.wrapping_mul(131) + seed.wrapping_mul(17) + i / 7) % 251) as u8).collect()
}

/// Seeds `path` in `group` via a real signed local Change (not a raw
/// `store.put` + `upsert_file`), and publishes it. Block-serving
/// authorization now requires a real Published Change behind a served
/// path -- `published_file_at_path`/
/// `published_group_file_version_references_block` both join against
/// `change_authorization`, which a raw `upsert_file` (no authoring change
/// at all) can never satisfy. Every caller of this function pairs the
/// returned device via `connect()` afterward, which flushes this device's
/// PRE-EXISTING Pending content for the shared group as part of `support::
/// connect_two_daemons`'s own setup -- so the Change authored here
/// deterministically becomes Published before any peer ever gets a chance
/// to request it.
fn seed_block(device: &Device, group: &str, path: &str, data: Vec<u8>) -> SeededBlock {
    let hash_hex = device.state.block_store.put(&data).unwrap();
    let hash = hex::decode(&hash_hex).unwrap();

    let version_blocks =
        vec![VersionBlock { hash: BlockHash(hash.clone()), size: data.len() as u32 }];
    let version = FileVersion::new(
        version_blocks.clone(),
        data.len() as u64,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let record = FileRecord {
        path: path.to_string(),
        size: data.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: hash.clone(), offset: 0, size: data.len() as u32 }],
        deleted: false,
    };
    let signing_key = device.state.device_signing_key().expect(
        "new_device calls ensure_device_signing_key, so every seed_block caller already has one",
    );
    let emitter = yadorilink_daemon::test_support::local_seam::replica_author_key(
        &device.state.replica_coordinator,
        &device.device_id,
        signing_key,
    )
    .unwrap();
    yadorilink_daemon::test_support::local_seam::commit_local_upsert(
        &device.state.replica_coordinator,
        group,
        &record,
        &device.device_id,
        &version,
        None,
        &emitter,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
    // `record_group_block_provenance`'s doc comment: without this, the
    // block-serving path refuses this block as never having been obtained
    // through the group. `upsert_file_emitting_change` records the
    // authorization link but not provenance -- see `DagProducer::
    // commit_create`'s identical two-step sequence in the peer-session
    // test suite.
    device
        .state
        .replica_coordinator
        .record_block_provenance(group, std::slice::from_ref(&hash))
        .unwrap();

    SeededBlock {
        path: path.to_string(),
        hash,
        hash_hex,
        data,
        version_hash: version.version_hash,
        version_blocks,
    }
}

async fn connect(source: &Device, requester: &Device, groups: &[&str]) {
    let groups = groups.iter().map(|g| (*g).to_string()).collect::<Vec<_>>();
    support::connect_two_daemons(
        &source.state,
        &source.device_id,
        &requester.state,
        &requester.device_id,
        &groups,
    )
    .await;
}

fn session_to(device: &Device, peer_id: &str) -> Arc<PeerSyncSession> {
    device
        .state
        .peers
        .session(peer_id)
        .unwrap_or_else(|| panic!("no session from {} to {peer_id}", device.device_id))
}

fn spawn_fetches(
    session: Arc<PeerSyncSession>,
    group: &str,
    blocks: &[SeededBlock],
) -> JoinSet<()> {
    let mut tasks = JoinSet::new();
    for block in blocks.iter().cloned() {
        let session = session.clone();
        let group = group.to_string();
        tasks.spawn(async move {
            let received = session
                .fetch_block(&group, &block.path, &block.hash)
                .await
                .expect("block request must not fail")
                .expect("source must return the block");
            assert_eq!(&received[..], block.data.as_slice());
        });
    }
    tasks
}

async fn drain(tasks: &mut JoinSet<()>, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        while let Some(result) = tasks.join_next().await {
            result.expect("fetch task panicked");
        }
    })
    .await
    .expect("fetch tasks did not finish after the source gate opened");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn identical_block_requested_by_many_peers_is_read_once_and_fanned_out() {
    support::ensure_isolated_config_dir();
    let (source, store) =
        new_instrumented_device("source", &[GROUP_A], ReadMode::Delay(Duration::from_millis(300)));

    let requesters =
        (0..6).map(|i| new_plain_device(&format!("requester-{i}"), &[GROUP_A])).collect::<Vec<_>>();
    // `connect()` (via `support::connect_two_daemons`) installs the
    // bootstrap policy `seed_block`'s `upsert_file_emitting_change` needs
    // in order to authorize local emission at all -- it must run first,
    // not after seeding, unlike this test's original ordering.
    for requester in &requesters {
        connect(&source, requester, &[GROUP_A]).await;
    }
    let block = seed_block(&source, GROUP_A, "shared.bin", seeded_data(1, 128 * 1024));
    source.state.flush_pending_checkpoint_for_group_for_test(GROUP_A).await;

    let barrier = Arc::new(tokio::sync::Barrier::new(requesters.len() + 1));
    let mut tasks = JoinSet::new();
    for requester in &requesters {
        let session = session_to(requester, &source.device_id);
        let barrier = barrier.clone();
        let block = block.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            let received = session
                .fetch_block(GROUP_A, &block.path, &block.hash)
                .await
                .expect("request must succeed")
                .expect("source must return the block");
            assert_eq!(&received[..], block.data.as_slice());
        });
    }
    barrier.wait().await;
    drain(&mut tasks, Duration::from_secs(15)).await;

    assert_eq!(
        store.calls_for(&block.hash_hex),
        1,
        "six requesters for one (group, hash) must share one source read/hash/compress operation"
    );
}

/// Regression for a confirmed cross-group response-correlation bug: two
/// folder groups sharing one peer connection can legitimately reference
/// the IDENTICAL content hash (e.g. the same file copied into both), and
/// the source can legitimately answer them DIFFERENTLY -- GROUP_A has
/// recorded provenance for this hash and gets `Found`, GROUP_B's index
/// references the same hash/path but this device never recorded GROUP_B
/// provenance for it, so it must be refused. Correlating replies by
/// `block_hash` alone (the pre-fix behavior) cannot tell these two
/// concurrent requests apart: whichever reply lands first on the wire
/// resolves BOTH waiters, so GROUP_B's request could silently receive
/// GROUP_A's `Found` bytes -- bypassing GROUP_B's own provenance check
/// entirely. `request_id`-scoped correlation on the negotiated path must
/// keep these two outcomes fully independent regardless of arrival order.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_requests_for_the_same_hash_across_groups_never_cross_wire_their_outcomes() {
    support::ensure_isolated_config_dir();
    let (source, _store) = new_instrumented_device(
        "source",
        &[GROUP_A, GROUP_B],
        ReadMode::Delay(Duration::from_millis(50)),
    );
    let requester = new_plain_device("requester", &[GROUP_A, GROUP_B]);
    // `connect()` installs the bootstrap policy `seed_block` needs to
    // authorize local emission at all -- must run before any seeding.
    connect(&source, &requester, &[GROUP_A, GROUP_B]).await;

    // GROUP_A: real provenance recorded -- must be served.
    let block = seed_block(&source, GROUP_A, "shared.bin", seeded_data(1, 4096));

    // GROUP_B: the index references the IDENTICAL hash at a different
    // path, but this device never recorded GROUP_B provenance for it --
    // must be refused, no matter what GROUP_A's concurrent request gets.
    let group_b_path = "not-provenanced.bin";
    source
        .state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP_B,
            &FileRecord {
                path: group_b_path.to_string(),
                size: block.data.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo {
                    hash: block.hash.clone(),
                    offset: 0,
                    size: block.data.len() as u32,
                }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    source.state.flush_pending_checkpoint_for_group_for_test(GROUP_A).await;
    let session = session_to(&requester, &source.device_id);

    let (group_a_result, group_b_result) = tokio::join!(
        session.fetch_block(GROUP_A, &block.path, &block.hash),
        session.fetch_block(GROUP_B, group_b_path, &block.hash),
    );

    let group_a_bytes = group_a_result
        .expect("request must not fail")
        .expect("GROUP_A has real recorded provenance and must be served");
    assert_eq!(&group_a_bytes[..], block.data.as_slice());

    let group_b_bytes = group_b_result.expect("request must not fail");
    assert!(
        group_b_bytes.is_none(),
        "GROUP_B has no recorded provenance for this hash and must be refused, even though a \
         concurrent GROUP_A request for the IDENTICAL hash was legitimately served -- hash-only \
         correlation would leak GROUP_A's Found bytes to this GROUP_B waiter instead"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn stalled_content_requests_do_not_delay_control_messages_on_the_same_session() {
    support::ensure_isolated_config_dir();
    let (source, store) = new_instrumented_device("source", &[GROUP_A], ReadMode::Gate);
    let requester = new_plain_device("requester", &[GROUP_A]);
    // `connect()` installs the bootstrap policy `seed_block` needs to
    // authorize local emission at all -- must run before any seeding.
    connect(&source, &requester, &[GROUP_A]).await;

    let noisy = (0..72)
        .map(|i| {
            seed_block(
                &source,
                GROUP_A,
                &format!("bulk-{i:03}.bin"),
                seeded_data(100 + i, 16 * 1024),
            )
        })
        .collect::<Vec<_>>();
    let control = seed_block(&source, GROUP_A, "control-proof.bin", seeded_data(999, 1024));
    // The control query itself verifies this block. Keep that one read outside
    // the artificial content gate; only the ordinary BlockRequest flood stalls.
    store.allow_immediate(&control.hash_hex);
    source.state.flush_pending_checkpoint_for_group_for_test(GROUP_A).await;

    requester.state.authority.set_peer_group_full_replica(&source.device_id, GROUP_A, true);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let session = session_to(&requester, &source.device_id);
    let mut noisy_tasks = spawn_fetches(session, GROUP_A, &noisy);
    let entered = store.wait_for_entered_at_least(64, Duration::from_secs(2));
    assert!(entered > 0, "the test never created source-side content pressure");

    let started = Instant::now();
    let confirmed = tokio::time::timeout(
        Duration::from_millis(750),
        requester.state.confirm_version_present_via_peer(
            GROUP_A,
            &control.path,
            control.version_hash,
            &control.version_blocks,
        ),
    )
    .await
    .expect(
        "VersionPresent control traffic was delayed behind stalled content handlers; \
         content flow control must use a separate logical lane",
    );
    assert!(confirmed, "the source held the exact control-proof version");
    assert!(
        started.elapsed() < Duration::from_millis(750),
        "control reply exceeded the stage-2 latency budget"
    );

    store.release(1_000);
    drain(&mut noisy_tasks, Duration::from_secs(15)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn late_small_requests_from_another_peer_and_group_cut_ahead_of_a_large_backlog() {
    support::ensure_isolated_config_dir();
    let (source, store) = new_instrumented_device("source", &[GROUP_A, GROUP_B], ReadMode::Gate);
    // Whatever happens below, no gated read is still parked when this test
    // returns -- see `open_permanently`.
    let _gate = GateOpenOnUnwind(store.clone());
    let peer_a = new_plain_device("peer-a", &[GROUP_A, GROUP_B]);
    let peer_b = new_plain_device("peer-b", &[GROUP_A]);
    // `connect()` installs the bootstrap policy `seed_block` needs to
    // authorize local emission at all -- must run before any seeding.
    connect(&source, &peer_a, &[GROUP_A, GROUP_B]).await;
    connect(&source, &peer_b, &[GROUP_A]).await;

    let large_backlog = (0..96)
        .map(|i| {
            seed_block(
                &source,
                GROUP_A,
                &format!("large-{i:03}.bin"),
                seeded_data(2_000 + i, 64 * 1024),
            )
        })
        .collect::<Vec<_>>();
    let other_group =
        seed_block(&source, GROUP_B, "small-other-group.bin", seeded_data(9_001, 1024));
    let other_peer = seed_block(&source, GROUP_A, "small-other-peer.bin", seeded_data(9_002, 1024));
    source.state.flush_pending_checkpoint_for_group_for_test(GROUP_A).await;
    source.state.flush_pending_checkpoint_for_group_for_test(GROUP_B).await;

    // The peers are ordinary daemons: once they are linked and the files are seeded they fetch
    // the seeded blocks themselves, and those fetches would fill each peer's request window
    // (and the source's dispatch slots) in a timing the test does not control, so that a
    // "late" request waits in the requester behind them rather than being ordered by the
    // source. Let that traffic finish first, with the gate open, then close the gate: from
    // there on the only requests are the ones this test makes.
    store.release(usize::MAX / 2);
    let synced = |device: &Device| {
        large_backlog
            .iter()
            .all(|block| device.state.block_store.exists(&block.hash_hex).unwrap_or(false))
    };
    support::wait_until_with_context(
        || synced(&peer_a) && synced(&peer_b),
        Duration::from_secs(60),
        || "the peers never finished fetching the seeded files themselves".to_owned(),
    )
    .await;
    // Their last requests are answered by now; wait for the source to see no more.
    let mut last = (store.entered_count(), Instant::now());
    while last.1.elapsed() < Duration::from_secs(1) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = store.entered_count();
        if now != last.0 {
            last = (now, Instant::now());
        }
    }
    store.close_gate_and_forget_entered();

    let session_a = session_to(&peer_a, &source.device_id);
    let session_b = session_to(&peer_b, &source.device_id);
    let mut tasks = spawn_fetches(session_a.clone(), GROUP_A, &large_backlog);

    // Let the old per-session FIFO establish a meaningful backlog. A stage-2
    // scheduler may intentionally start far fewer reads; either way there is
    // outstanding pressure before the two small requests arrive.
    let entered = store.wait_for_entered_at_least(16, Duration::from_secs(2));
    assert!(entered > 0, "the large backlog never reached the source");

    for (session, group, block) in
        [(session_a, GROUP_B, other_group.clone()), (session_b, GROUP_A, other_peer.clone())]
    {
        tasks.spawn(async move {
            let received = session
                .fetch_block(group, &block.path, &block.hash)
                .await
                .expect("small request must not fail")
                .expect("source must return the small block");
            assert_eq!(&received[..], block.data.as_slice());
        });
    }

    // A byte-fair source queue must choose both newly-active classes promptly,
    // rather than draining dozens of already-enqueued large reads first.
    for _ in 0..16 {
        if store.entered_position(&other_group.hash_hex).is_some()
            && store.entered_position(&other_peer.hash_hex).is_some()
        {
            break;
        }
        store.release(1);
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    let group_position = store.entered_position(&other_group.hash_hex);
    let peer_position = store.entered_position(&other_peer.hash_hex);
    assert!(
        group_position.is_some_and(|position| position < 32),
        "a small request from another group was starved behind the large backlog: \
         position={group_position:?}"
    );
    assert!(
        peer_position.is_some_and(|position| position < 32),
        "a small request from another peer was starved behind the large backlog: \
         position={peer_position:?}"
    );

    store.release(10_000);
    drain(&mut tasks, Duration::from_secs(20)).await;
}

/// A `.proto` read as a structure rather than as a string.
///
/// The previous version of the schema test called `contains()` on the raw
/// source text, which cannot tell a live field from the record of a deleted
/// one. `reserved "redirect";` contains `redirect`, so asserting that
/// `redirect` was still part of the wire passed against the very line that
/// documents its removal. Three of the four "required" serve-credit fields
/// were in the same position: `available_worker_slots` and
/// `estimated_queue_delay_ms` are reserved, not present, and the test was
/// green on both.
///
/// The parser below is deliberately small -- it understands only the subset
/// this repository's `.proto` files use -- but it distinguishes the three
/// things a substring search cannot: which message a name belongs to,
/// whether it is a declaration or a reservation, and what its number and
/// `oneof` membership are.
mod proto_model {
    use std::collections::{HashMap, HashSet};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Field {
        pub name: String,
        pub ty: String,
        pub number: u32,
        /// The `oneof` this field is declared inside, if any.
        pub oneof: Option<String>,
    }

    #[derive(Debug, Default, Clone)]
    pub struct Message {
        pub fields: Vec<Field>,
        pub reserved_names: HashSet<String>,
        pub reserved_numbers: HashSet<u32>,
    }

    impl Message {
        pub fn field(&self, name: &str) -> Option<&Field> {
            self.fields.iter().find(|f| f.name == name)
        }

        /// Field names declared inside `oneof`, in declaration order.
        pub fn oneof_fields(&self, oneof: &str) -> Vec<&Field> {
            self.fields.iter().filter(|f| f.oneof.as_deref() == Some(oneof)).collect()
        }
    }

    /// Everything after `//` on a line is a comment, and a comment naming a
    /// removed field is exactly what a substring search mistakes for the
    /// field itself.
    fn strip_comments(src: &str) -> String {
        // Line comments only. A `/* */` block would be left in place, and a
        // field declaration inside one would be read as a declaration -- or,
        // worse, a `//` inside a block comment would truncate a real line and
        // make a field vanish, which turns every `field(x).is_none()` check
        // into a pass for the wrong reason. No schema in this repository uses
        // block comments; this refuses to keep parsing if one appears.
        assert!(
            !src.contains("/*"),
            "this parser handles only `//` comments; a block comment appeared and would be \
             misread -- teach it `/* */` before relying on the result"
        );
        src.lines()
            .map(|line| match line.find("//") {
                Some(at) => &line[..at],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn parse_reserved(body: &str, message: &mut Message) {
        for item in body.split(',') {
            let item = item.trim();
            if let Some(quoted) = item.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
                message.reserved_names.insert(quoted.to_string());
            } else if let Ok(number) = item.parse::<u32>() {
                message.reserved_numbers.insert(number);
            } else if let Some((lo, hi)) = item.split_once(" to ") {
                // `reserved 3 to 7;`
                if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u32>(), hi.trim().parse::<u32>()) {
                    for n in lo..=hi {
                        message.reserved_numbers.insert(n);
                    }
                }
            }
        }
    }

    /// Parses `Type name = N;`, tolerating the `repeated`/`optional` label.
    fn parse_field(statement: &str, oneof: Option<&str>) -> Option<Field> {
        let (decl, number) = statement.rsplit_once('=')?;
        let number = number.trim().parse::<u32>().ok()?;
        let mut words: Vec<&str> = decl.split_whitespace().collect();
        let name = words.pop()?;
        // Drop the cardinality label so `repeated bytes x` reports `bytes`.
        while matches!(words.first().copied(), Some("repeated" | "optional" | "required")) {
            words.remove(0);
        }
        let ty = words.pop()?;
        if !words.is_empty() {
            return None;
        }
        Some(Field {
            name: name.to_string(),
            ty: ty.to_string(),
            number,
            oneof: oneof.map(str::to_string),
        })
    }

    /// Messages by name. Nested messages are not used by these schemas and
    /// are not handled; a `oneof` block is, since that is what carries the
    /// block-response outcomes.
    ///
    /// Statements are accumulated until their terminating `;` rather than
    /// read a line at a time: a `reserved` list wraps across lines in this
    /// schema, and treating each line as a statement drops everything after
    /// the first.
    pub fn parse(src: &str) -> HashMap<String, Message> {
        let src = strip_comments(src);
        let mut out: HashMap<String, Message> = HashMap::new();
        let mut current: Option<(String, Message)> = None;
        let mut oneof: Option<String> = None;
        let mut pending = String::new();

        for raw in src.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if current.is_none() {
                if let Some(rest) = line.strip_prefix("message ") {
                    if let Some(name) = rest.split_whitespace().next() {
                        current = Some((name.to_string(), Message::default()));
                    }
                }
                continue;
            }
            if pending.is_empty() {
                if let Some(rest) = line.strip_prefix("oneof ") {
                    oneof = rest.split_whitespace().next().map(str::to_string);
                    continue;
                }
                if line == "}" {
                    if oneof.take().is_some() {
                        continue;
                    }
                    let (name, message) = current.take().expect("inside a message");
                    out.insert(name, message);
                    continue;
                }
            }
            if !pending.is_empty() {
                pending.push(' ');
            }
            pending.push_str(line);
            let Some(statement) = pending.strip_suffix(';').map(str::to_string) else {
                continue;
            };
            pending.clear();
            let (_, message) = current.as_mut().expect("inside a message");
            let statement = statement.trim();
            if let Some(body) = statement.strip_prefix("reserved ") {
                parse_reserved(body, message);
            } else if let Some(field) = parse_field(statement, oneof.as_deref()) {
                message.fields.push(field);
            }
        }
        out
    }
}

/// The wire contract for block serving, asserted against the parsed schema.
///
/// Every check names one message, so a field moving between messages is a
/// failure rather than something a whole-file search would still find.
#[test]
fn wire_schema_pins_block_stream_headers_and_explicit_congestion_outcomes() {
    let schema = include_str!("../../yadorilink-ipc-proto/proto/sync.proto");
    let messages = proto_model::parse(schema);

    // Serve credit is not negotiated on the wire: each device enforces its
    // own serving budget locally, and the session-start message that used to
    // advertise one is gone together with the control-stream envelope that
    // carried it.
    assert!(!messages.contains_key("ClusterConfig"), "no session-start negotiation message");
    assert!(!messages.contains_key("SyncMessage"), "no control-stream envelope");

    // One block request is one bidirectional stream, so the request and
    // response headers are their own messages, and neither carries a
    // correlation id.
    let request = messages.get("BlockRequestHeader").expect("BlockRequestHeader must exist");
    assert!(
        request.field("request_id").is_none(),
        "a block request header must carry no correlation id -- the stream is the correlation"
    );
    assert_eq!(
        request.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
        ["folder_group_id", "file_path", "block_hash"],
        "a block request names exactly the block it wants and nothing else"
    );

    // The response's admission-control outcomes are a closed set: a
    // same-generation peer sets exactly one, and an absent outcome is
    // malformed rather than a forward-compatible unknown.
    let response = messages.get("BlockResponseHeader").expect("BlockResponseHeader must exist");
    assert_eq!(
        response
            .oneof_fields("outcome")
            .iter()
            .map(|f| (f.name.as_str(), f.ty.as_str(), f.number))
            .collect::<Vec<_>>(),
        [
            ("found", "BlockFound", 1),
            ("dont_have", "bool", 2),
            ("busy", "BlockBusy", 3),
            ("rejected", "BlockRejected", 5),
        ],
        "the outcome set is closed; adding a case is a wire generation change"
    );
    // The removed redirect case. This is the assertion the substring version
    // got backwards: it asserted `redirect` was PRESENT, and passed because
    // `reserved \"redirect\";` contains the word.
    assert!(
        response.field("redirect").is_none(),
        "the redirect outcome was removed and must not come back without a new generation"
    );
    assert!(
        response.reserved_names.contains("redirect") && response.reserved_numbers.contains(&4),
        "the removed redirect case must stay reserved by both name and number"
    );

    // Congestion is carried in its own message with its own fields, so a
    // busy answer is distinguishable from "does not have it".
    let busy = messages.get("BlockBusy").expect("BlockBusy must exist");
    assert_eq!(busy.field("retry_after_ms").map(|f| f.number), Some(1));
    assert_eq!(busy.field("queue_depth").map(|f| f.number), Some(2));
    let rejected = messages.get("BlockRejected").expect("BlockRejected must exist");
    assert_eq!(rejected.field("reason").map(|f| f.ty.as_str()), Some("string"));

    // Inline chunking is gone: a block is one body on one stream.
    let found = messages.get("BlockFound").expect("BlockFound must exist");
    for gone in ["chunk_offset", "total_size"] {
        assert!(
            found.field(gone).is_none(),
            "inline block-reply chunking is gone; {gone:?} must not reappear"
        );
    }
    assert_eq!(
        found.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
        ["size", "hash", "compression"],
        "a found block carries its length, its identity and its encoding"
    );
}

/// The parser has to make the distinction the old test could not, so that
/// distinction is itself tested rather than assumed.
#[test]
fn the_schema_parser_tells_a_declared_field_from_a_reserved_or_commented_one() {
    let messages = proto_model::parse(
        r#"
        // A comment naming ghost = 9 must not create a field.
        message Sample {
          reserved 4;
          reserved "redirect";
          // A reserved list that wraps, which a line-at-a-time reader
          // truncates after the first line.
          reserved "wrapped_one", "wrapped_two",
                   "wrapped_three";
          uint32 live = 1;
          oneof outcome {
            bool picked = 2;
          }
        }
        "#,
    );
    let sample = messages.get("Sample").expect("the sample message parses");

    // The exact failure that made the previous test green on a removed field.
    assert!(sample.field("redirect").is_none(), "a reserved name is not a field");
    assert!(sample.reserved_names.contains("redirect"));
    assert!(sample.reserved_numbers.contains(&4));

    for wrapped in ["wrapped_one", "wrapped_two", "wrapped_three"] {
        assert!(
            sample.reserved_names.contains(wrapped),
            "a wrapped reserved list must be read to its end, not to its first line"
        );
    }

    // The exact failure a comment would have caused.
    assert!(sample.field("ghost").is_none(), "a name in a comment is not a field");

    assert_eq!(sample.field("live").map(|f| (f.ty.as_str(), f.number)), Some(("uint32", 1)));
    assert_eq!(
        sample.oneof_fields("outcome").iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
        ["picked"],
        "oneof membership is recorded, so a field cannot drift out of its oneof unnoticed"
    );
    assert!(
        sample.field("live").expect("live is a field").oneof.is_none(),
        "a top-level field must not be reported as part of the oneof"
    );
}
