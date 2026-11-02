#![cfg(test)]
//! The prefetch stage overlaps the paths of one attempt: these tests pin
//! that it does, that it stays inside its allowance of concurrent requests,
//! and that overlapping changes nothing about what ends up held.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use yadorilink_peer_session::convergence_driver::{BlockFetch, ConvergenceDriver, FetchedBlock};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::{BlockInfo, FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, SyncPath};
use yadorilink_replica_domain::local_op::Op;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::hydrate::{PathPrefetch, PrefetchShape};
use crate::local_convergence::call_timer::ReconcileCallTimer;
use crate::test_support::remote_admission_fixture::{admit_remote_ops, Basis};

const PEER: &str = "device-r1";

/// A peer whose answers are scripted per block hash, and which measures how
/// many requests it is serving at once.
#[derive(Default)]
struct FakePeer {
    served: HashMap<Vec<u8>, Bytes>,
    /// Answered with a verified refusal.
    refused: HashSet<Vec<u8>>,
    /// Answered with a transport error.
    failing: HashSet<Vec<u8>>,
    /// Answered with a transport error when asked under this path.
    failing_at: HashSet<(String, Vec<u8>)>,
    /// Paths the peer's own state no longer references this block at: a
    /// request naming one is answered as not found, the way the serving
    /// side authorises every request against the path it names.
    unreferenced_at: HashSet<(String, Vec<u8>)>,
    /// A per-block latency overriding `latency`.
    slow: HashMap<Vec<u8>, Duration>,
    /// Answered as found, with bytes that do not hash to the key.
    corrupt: HashSet<Vec<u8>>,
    latency: Duration,
    /// Never answers: every request stays in flight until it is dropped.
    stall: bool,
    /// Holds every request until this many are in flight at once (a hang backstop
    /// aside), so overlap is observed by count, not by timing.
    hold_until: usize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    requests: Mutex<Vec<Vec<u8>>>,
    on_first_request: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

struct Flight<'a>(&'a FakePeer);

impl<'a> Flight<'a> {
    fn enter(peer: &'a FakePeer) -> Self {
        let now = peer.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        peer.max_in_flight.fetch_max(now, Ordering::SeqCst);
        Self(peer)
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl FakePeer {
    fn serving(contents: &[&Content]) -> Self {
        Self {
            served: contents
                .iter()
                .flat_map(|c| c.blocks.iter().map(|(h, d)| (h.clone(), d.clone())))
                .collect(),
            ..Default::default()
        }
    }

    fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    fn requests_for(&self, hash: &[u8]) -> usize {
        self.requests.lock().unwrap().iter().filter(|h| h.as_slice() == hash).count()
    }
}

impl ConvergenceDriver for FakePeer {
    fn peer_device_id(&self) -> &str {
        PEER
    }

    fn fetch_block<'a>(
        &'a self,
        _group_id: &'a str,
        file_path: &'a str,
        block: &'a BlockInfo,
        _timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<FetchedBlock, PeerSessionError>> + Send + 'a>> {
        Box::pin(async move {
            let _flight = Flight::enter(self);
            self.requests.lock().unwrap().push(block.hash.clone());
            let hook = self.on_first_request.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
            if self.stall {
                std::future::pending::<()>().await;
            }
            let backstop = tokio::time::Instant::now();
            while self.max_in_flight.load(Ordering::SeqCst) < self.hold_until {
                assert!(backstop.elapsed() < Duration::from_secs(60), "requests never overlapped");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            tokio::time::sleep(self.slow.get(&block.hash).copied().unwrap_or(self.latency)).await;
            let at = (file_path.to_string(), block.hash.clone());
            let outcome = if self.failing.contains(&block.hash) || self.failing_at.contains(&at) {
                return Err(PeerSessionError::from(std::io::Error::other("scripted failure")));
            } else if self.unreferenced_at.contains(&at) {
                BlockFetch::Missing
            } else if self.refused.contains(&block.hash) {
                BlockFetch::VerifiedRefusal { reason: "scripted refusal".into() }
            } else if self.corrupt.contains(&block.hash) {
                // What a session does with an answer whose bytes are not the block asked for:
                // it never reaches the executor as a block, it is a block that did not arrive.
                BlockFetch::Missing
            } else {
                match self.served.get(&block.hash) {
                    Some(data) => BlockFetch::Fetched(
                        yadorilink_local_storage::VerifiedBlock::check(
                            data,
                            &block.hash,
                            block.size,
                        )
                        .expect("the scripted bytes are the block"),
                    ),
                    None => BlockFetch::Missing,
                }
            };
            Ok(FetchedBlock { outcome, wire_wait: self.latency })
        })
    }
}

/// A file version whose blocks are real content, so the receive side's own
/// hash check accepts what the fake peer serves.
struct Content {
    version: FileVersion,
    blocks: Vec<(Vec<u8>, Bytes)>,
}

impl Content {
    fn of(chunks: &[&[u8]]) -> Self {
        let blocks: Vec<(Vec<u8>, Bytes)> = chunks
            .iter()
            .map(|chunk| {
                let hashed =
                    yadorilink_local_storage::LocallyHashedBlock::from_bytes(chunk.to_vec());
                (hex::decode(hashed.hash().as_bytes()).unwrap(), Bytes::copy_from_slice(chunk))
            })
            .collect();
        let size: u64 = blocks.iter().map(|(_, d)| d.len() as u64).sum();
        let version = FileVersion::new(
            blocks
                .iter()
                .map(|(h, d)| VersionBlock { hash: BlockHash(h.clone()), size: d.len() as u32 })
                .collect(),
            size,
            FileMeta {
                mtime_unix_nanos: 1,
                exec: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        Self { version, blocks }
    }

    fn one(text: &str) -> Self {
        Self::of(&[text.as_bytes()])
    }

    fn hash(&self, index: usize) -> Vec<u8> {
        self.blocks[index].0.clone()
    }
}

/// A harness that commits every fetched block to the store, as the receive does when single-pass
/// is off: the tests above this point are about fetching and holding blocks in the store.
fn store_harness() -> Harness {
    let h = Harness::new(false);
    h.convergence.single_pass_override.store(2, Ordering::Relaxed);
    h
}

fn store_version(h: &Harness, version: &FileVersion) {
    h.state
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
}

fn put(path: &str, version: &FileVersion) -> Op {
    Op::Put { path: SyncPath(path.into()), version: version.version_hash }
}

/// A peer's put of `content` at `path`, which this device has not fetched.
fn published(h: &Harness, path: &str, content: &Content) {
    store_version(h, &content.version);
    admit_remote_ops(&h.state, GROUP, PEER, &[put(path, &content.version)], Basis::Nothing);
}

async fn prefetch(
    h: &Harness,
    peer: &Arc<FakePeer>,
    paths: &[&str],
    shape: PrefetchShape,
) -> BTreeMap<String, PathPrefetch> {
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let paths: BTreeSet<String> = paths.iter().map(|p| p.to_string()).collect();
    let (_requirements, outcomes, _hold) = h
        .convergence
        .obtain_missing_content_with(&driver, GROUP, &paths, &ReconcileCallTimer::new(), shape)
        .await
        .unwrap();
    outcomes
}

fn overlapped(fetches_in_flight: usize) -> PrefetchShape {
    PrefetchShape::Overlapped { fetches_in_flight }
}

/// Whether this device holds `hash` AND can prove this group obtained it --
/// the only sense in which a fetched block counts.
fn held(h: &Harness, hash: &[u8]) -> bool {
    let stored = h.convergence.store.present_blocks(&[hex::encode(hash)]).unwrap()[0];
    let provenanced =
        h.state.group_has_block_provenance_batch(GROUP, &[hash.to_vec()]).unwrap().contains(hash);
    stored && provenanced
}

fn stored(h: &Harness, hash: &[u8]) -> bool {
    h.convergence.store.present_blocks(&[hex::encode(hash)]).unwrap()[0]
}

fn refusals(h: &Harness) -> BTreeSet<(String, String)> {
    h.state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let mut stmt =
                conn.prepare("SELECT path, version_hash FROM block_fetch_refusals ORDER BY path")?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<BTreeSet<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
}

/// `count` paths of one distinct block each, published by the peer.
fn one_block_paths(h: &Harness, count: usize) -> (Vec<String>, Vec<Content>) {
    let names: Vec<String> = (0..count).map(|i| format!("f{i:02}")).collect();
    let contents: Vec<Content> =
        names.iter().map(|n| Content::one(&format!("body of {n}"))).collect();
    for (name, content) in names.iter().zip(&contents) {
        published(h, name, content);
    }
    (names, contents)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_block_paths_have_more_than_one_fetch_in_flight() {
    let h = store_harness();
    let (names, contents) = one_block_paths(&h, 16);
    let mut peer = FakePeer::serving(&contents.iter().collect::<Vec<_>>());
    peer.latency = Duration::from_millis(20);
    let peer = Arc::new(peer);

    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let outcomes = prefetch(&h, &peer, &names, overlapped(32)).await;

    assert!(outcomes.values().all(|o| *o == PathPrefetch::Obtained), "{outcomes:?}");
    assert!(
        peer.max_in_flight() > 1,
        "one-block paths were fetched one at a time (max in flight {})",
        peer.max_in_flight()
    );
    assert!(contents.iter().all(|c| held(&h, &c.hash(0))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_attempt_never_has_more_fetches_in_flight_than_its_allowance() {
    let h = store_harness();
    // Paths of several blocks as well as one: the allowance is for the
    // whole attempt, not per path.
    let (mut names, mut contents) = one_block_paths(&h, 12);
    for i in 0..4 {
        let name = format!("m{i}");
        let chunks: Vec<Vec<u8>> =
            (0..6).map(|j| format!("{name} part {j}").into_bytes()).collect();
        let content = Content::of(&chunks.iter().map(Vec::as_slice).collect::<Vec<_>>());
        published(&h, &name, &content);
        names.push(name);
        contents.push(content);
    }
    let mut peer = FakePeer::serving(&contents.iter().collect::<Vec<_>>());
    peer.latency = Duration::from_millis(10);
    let peer = Arc::new(peer);

    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let outcomes = prefetch(&h, &peer, &names, overlapped(4)).await;

    assert!(outcomes.values().all(|o| *o == PathPrefetch::Obtained), "{outcomes:?}");
    let max = peer.max_in_flight();
    assert!((2..=4).contains(&max), "max in flight {max}, allowance 4");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_two_paths_need_is_asked_for_once() {
    let h = store_harness();
    let a = Content::of(&[b"shared block", b"only in a"]);
    let b = Content::of(&[b"shared block", b"only in b"]);
    let c = Content::of(&[b"shared block"]);
    published(&h, "a", &a);
    published(&h, "b", &b);
    published(&h, "c", &c);
    let mut peer = FakePeer::serving(&[&a, &b, &c]);
    peer.latency = Duration::from_millis(20);
    let peer = Arc::new(peer);

    let outcomes = prefetch(&h, &peer, &["a", "b", "c"], overlapped(8)).await;

    assert!(outcomes.values().all(|o| *o == PathPrefetch::Obtained), "{outcomes:?}");
    let shared = a.hash(0);
    assert_eq!(peer.requests_for(&shared), 1, "the shared block was asked for more than once");
    assert!(held(&h, &shared) && held(&h, &a.hash(1)) && held(&h, &b.hash(1)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_paths_failed_fetch_leaves_the_other_paths_whole() {
    let h = store_harness();
    let (names, contents) = one_block_paths(&h, 6);
    let mut peer = FakePeer::serving(&contents.iter().collect::<Vec<_>>());
    peer.latency = Duration::from_millis(5);
    peer.failing.insert(contents[1].hash(0));
    peer.served.remove(&contents[3].hash(0));
    peer.refused.insert(contents[4].hash(0));
    let peer = Arc::new(peer);

    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let outcomes = prefetch(&h, &peer, &names, overlapped(8)).await;

    let expected: BTreeMap<String, PathPrefetch> = [
        ("f00", PathPrefetch::Obtained),
        ("f01", PathPrefetch::Failed),
        ("f02", PathPrefetch::Obtained),
        ("f03", PathPrefetch::Incomplete),
        ("f04", PathPrefetch::Incomplete),
        ("f05", PathPrefetch::Obtained),
    ]
    .into_iter()
    .map(|(p, o)| (p.to_string(), o))
    .collect();
    assert_eq!(outcomes, expected);
    for i in [0, 2, 5] {
        assert!(held(&h, &contents[i].hash(0)), "f0{i} was not obtained");
    }
    for i in [1, 3, 4] {
        assert!(!stored(&h, &contents[i].hash(0)));
    }
    assert_eq!(
        refusals(&h),
        BTreeSet::from([("f04".to_string(), contents[4].version.version_hash.to_hex())])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bytes_that_do_not_hash_to_their_key_are_never_held() {
    let h = store_harness();
    let (names, contents) = one_block_paths(&h, 3);
    let mut peer = FakePeer::serving(&contents.iter().collect::<Vec<_>>());
    peer.corrupt.insert(contents[1].hash(0));
    let peer = Arc::new(peer);

    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    prefetch(&h, &peer, &names, overlapped(8)).await;

    assert!(!stored(&h, &contents[1].hash(0)));
    assert!(
        !h.state
            .group_has_block_provenance_batch(GROUP, &[contents[1].hash(0)])
            .unwrap()
            .contains(&contents[1].hash(0)),
        "provenance recorded for bytes that were never stored"
    );
    assert!(held(&h, &contents[0].hash(0)) && held(&h, &contents[2].hash(0)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_whose_plan_went_stale_before_its_turn_is_not_fetched() {
    let h = store_harness();
    let a = Content::one("a's body");
    let b = Content::one("b's first body");
    let b_newer = Content::one("b's newer body");
    published(&h, "a", &a);
    published(&h, "b", &b);
    store_version(&h, &b_newer.version);
    let mut peer = FakePeer::serving(&[&a, &b, &b_newer]);
    // While the attempt is busy with `a`, the peer's newer put of `b`
    // supersedes the version `b` was planned for.
    let state = h.state.clone();
    let newer = b_newer.version.clone();
    peer.on_first_request = Mutex::new(Some(Box::new(move || {
        admit_remote_ops(&state, GROUP, PEER, &[put("b", &newer)], Basis::CurrentHeads);
    })));
    let peer = Arc::new(peer);

    // An allowance of one: `b`'s turn comes only after `a`'s fetch.
    let outcomes = prefetch(&h, &peer, &["a", "b"], overlapped(1)).await;

    assert_eq!(outcomes.get("a"), Some(&PathPrefetch::Obtained), "{outcomes:?}");
    assert_eq!(outcomes.get("b"), Some(&PathPrefetch::Stale), "{outcomes:?}");
    assert_eq!(peer.requests_for(&b.hash(0)), 0, "fetched content for a superseded version");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_the_attempt_cancels_every_fetch_in_flight() {
    let h = Arc::new(store_harness());
    let (names, contents) = one_block_paths(&h, 8);
    let mut peer = FakePeer::serving(&contents.iter().collect::<Vec<_>>());
    peer.stall = true;
    let peer = Arc::new(peer);

    let attempt = {
        let (h, peer) = (h.clone(), peer.clone());
        tokio::spawn(async move {
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            prefetch(&h, &peer, &names, overlapped(4)).await
        })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while peer.in_flight.load(Ordering::SeqCst) == 0 {
        assert!(tokio::time::Instant::now() < deadline, "no fetch ever started");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    attempt.abort();
    assert!(attempt.await.unwrap_err().is_cancelled());

    assert_eq!(peer.in_flight.load(Ordering::SeqCst), 0, "a fetch outlived its attempt");
    let asked = peer.requests.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(peer.requests.lock().unwrap().len(), asked, "fetching went on after the drop");
}

/// The overlapped stage against the serial one it replaces, over the same
/// peer: the same paths end the same way, and the same blocks end up held,
/// stored and refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_paths_ends_in_the_same_state_as_fetching_them_one_by_one() {
    struct Run {
        outcomes: BTreeMap<String, PathPrefetch>,
        held: Vec<bool>,
        stored: Vec<bool>,
        refusals: BTreeSet<(String, String)>,
    }
    async fn run(shape: PrefetchShape) -> Run {
        let h = store_harness();
        let mut contents = Vec::new();
        let mut names = Vec::new();
        for i in 0..10 {
            let name = format!("p{i}");
            let content = match i % 4 {
                0 => Content::one(&format!("{name} alone")),
                1 => Content::of(&[b"common", format!("{name} tail").as_bytes()]),
                2 => Content::of(&[
                    format!("{name} 1").as_bytes(),
                    format!("{name} 2").as_bytes(),
                    format!("{name} 3").as_bytes(),
                ]),
                _ => Content::of(&[b"common", b"also common"]),
            };
            published(&h, &name, &content);
            names.push(name);
            contents.push(content);
        }
        let mut peer = FakePeer::serving(&contents.iter().collect::<Vec<_>>());
        peer.latency = Duration::from_millis(3);
        // The peer no longer references a block two later paths share at
        // the first path that asks for it; the others are still served it.
        peer.unreferenced_at.insert(("p3".to_string(), contents[3].hash(1)));
        // Each path's unobtainable block is its last, so how far a path
        // gets before giving up cannot depend on timing.
        peer.served.remove(&contents[2].hash(2));
        peer.refused.insert(contents[4].hash(0));
        peer.failing.insert(contents[6].hash(2));
        peer.corrupt.insert(contents[8].hash(0));
        let peer = Arc::new(peer);
        let paths: Vec<&str> = names.iter().map(String::as_str).collect();
        let outcomes = prefetch(&h, &peer, &paths, shape).await;
        let hashes: Vec<Vec<u8>> =
            contents.iter().flat_map(|c| c.blocks.iter().map(|(h, _)| h.clone())).collect();
        Run {
            outcomes,
            held: hashes.iter().map(|x| held(&h, x)).collect(),
            stored: hashes.iter().map(|x| stored(&h, x)).collect(),
            refusals: refusals(&h),
        }
    }

    let serial = run(PrefetchShape::Serial).await;
    let overlapped = run(overlapped(4)).await;

    assert_eq!(overlapped.outcomes, serial.outcomes);
    assert_eq!(overlapped.held, serial.held);
    assert_eq!(overlapped.stored, serial.stored);
    assert_eq!(overlapped.refusals, serial.refusals);
    assert!(serial.held.iter().any(|h| *h) && serial.held.iter().any(|h| !*h));
}

/// With a fixed per-request latency, overlapping the paths keeps several
/// requests in flight at once where one-by-one keeps exactly one. Counted
/// requests, not elapsed time: a slow host stretches both runs alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_paths_divides_the_wait_by_the_allowance() {
    const PATHS: usize = 24;
    const ALLOWANCE: usize = 8;
    async fn peak(shape: PrefetchShape, hold_until: usize) -> usize {
        let h = store_harness();
        let (names, contents) = one_block_paths(&h, PATHS);
        let mut peer = FakePeer::serving(&contents.iter().collect::<Vec<_>>());
        peer.latency = Duration::from_millis(20);
        peer.hold_until = hold_until;
        let peer = Arc::new(peer);
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let outcomes = prefetch(&h, &peer, &names, shape).await;
        assert!(outcomes.values().all(|o| *o == PathPrefetch::Obtained), "{outcomes:?}");
        peer.max_in_flight()
    }

    assert_eq!(peak(PrefetchShape::Serial, 0).await, 1, "one-by-one asks one at a time");
    let overlapped = peak(overlapped(ALLOWANCE), 2).await;
    assert!(
        (2..=ALLOWANCE).contains(&overlapped),
        "overlapped paths kept {overlapped} requests in flight (allowance {ALLOWANCE})"
    );
}

/// A, then B, both need H. The peer serves H for B's path but no longer
/// references it at A's: B must still end up with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_block_not_found_for_one_path_is_still_asked_for_under_the_other() {
    let h = store_harness();
    let a = Content::of(&[b"shared block"]);
    let b = Content::of(&[b"shared block", b"only in b"]);
    published(&h, "a", &a);
    published(&h, "b", &b);
    let mut peer = FakePeer::serving(&[&a, &b]);
    peer.latency = Duration::from_millis(20);
    peer.unreferenced_at.insert(("a".to_string(), a.hash(0)));
    let peer = Arc::new(peer);

    let outcomes = prefetch(&h, &peer, &["a", "b"], overlapped(8)).await;

    assert_eq!(outcomes.get("a"), Some(&PathPrefetch::Incomplete), "{outcomes:?}");
    assert_eq!(outcomes.get("b"), Some(&PathPrefetch::Obtained), "{outcomes:?}");
    assert!(held(&h, &a.hash(0)) && held(&h, &b.hash(1)));
}

/// A transport error answering one path's request is that path's failure
/// alone: a path that joined the request asks again on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_requests_error_fails_only_the_path_that_asked() {
    let h = store_harness();
    let a = Content::of(&[b"shared block"]);
    let b = Content::of(&[b"shared block", b"only in b"]);
    published(&h, "a", &a);
    published(&h, "b", &b);
    let mut peer = FakePeer::serving(&[&a, &b]);
    peer.latency = Duration::from_millis(20);
    peer.failing_at.insert(("a".to_string(), a.hash(0)));
    let peer = Arc::new(peer);

    let outcomes = prefetch(&h, &peer, &["a", "b"], overlapped(8)).await;

    assert_eq!(outcomes.get("a"), Some(&PathPrefetch::Failed), "{outcomes:?}");
    assert_eq!(outcomes.get("b"), Some(&PathPrefetch::Obtained), "{outcomes:?}");
    assert!(held(&h, &a.hash(0)));
}

/// A path that already gave up keeps the outcome it gave up with, whatever
/// a request it would have shared later turns out to be.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_that_gave_up_is_not_relabelled_by_a_later_shared_answer() {
    let h = store_harness();
    let a = Content::of(&[b"shared block"]);
    let b = Content::of(&[b"absent block", b"shared block"]);
    published(&h, "a", &a);
    published(&h, "b", &b);
    let mut peer = FakePeer::serving(&[&a, &b]);
    peer.latency = Duration::from_millis(5);
    // A's request for the shared block is still on the wire when B learns
    // its first block is absent and reaches the shared one.
    peer.slow.insert(a.hash(0), Duration::from_millis(200));
    peer.served.remove(&b.hash(0));
    peer.failing.insert(a.hash(0));
    let peer = Arc::new(peer);

    let outcomes = prefetch(&h, &peer, &["a", "b"], overlapped(2)).await;

    assert_eq!(outcomes.get("a"), Some(&PathPrefetch::Failed), "{outcomes:?}");
    assert_eq!(outcomes.get("b"), Some(&PathPrefetch::Incomplete), "{outcomes:?}");
}

/// Callers of the path fingerprint on a volume that cannot answer the change time or USN
/// (Windows only; simulated through the thread-local seam, so these run on a current-thread
/// runtime; the fingerprint reads under test are made on the test thread, while the blocking
/// byte hash of the target is not and does not need the seam). A caller that used the strict
/// fingerprint would get a sample that equals no other, so an untouched file would look changed
/// and every materialize over an existing file would be declined for retry, forever. Elsewhere the
/// seam changes nothing and these only pin the same invariant on the stat fingerprint.
mod degraded_fingerprint_callers {
    use super::*;
    use crate::local_convergence::types::{LocalMaterializeOutcome, MaterializationPayload};
    use yadorilink_fs_platform::fs_identity::{
        change_time_unreadable_for_test, disk_race_fingerprint_or_stat,
    };
    use yadorilink_replica_domain::session_state::MaterializationPolicy;

    /// A local file at `name` that is captured (indexed, clean), and a peer's put of `newer` that
    /// supersedes it and whose blocks this device does not hold.
    async fn local_file_superseded_by_missing_content(
        h: &Harness,
        name: &str,
        newer: &Content,
    ) -> std::path::PathBuf {
        std::fs::write(h.path(name), b"the local v1 bytes").unwrap();
        h.capture(name).await;
        store_version(h, &newer.version);
        admit_remote_ops(&h.state, GROUP, PEER, &[put(name, &newer.version)], Basis::CurrentHeads);
        h.path(name)
    }

    /// The seam is in effect on this thread (Windows): the observed sample is stat-only.
    fn assert_degraded(path: &std::path::Path) {
        #[cfg(windows)]
        assert!(
            yadorilink_fs_platform::fs_identity::disk_race_fingerprint_or_stat_observed(path)
                .expect("the file exists")
                .1,
            "fixture: the change time must read as unavailable"
        );
        #[cfg(not(windows))]
        let _ = path;
    }

    /// reconcile.rs `block_requirement_for_version`: the sample the prefetch stage hands out is the
    /// one a later bracket can equal.
    #[tokio::test(flavor = "current_thread")]
    async fn the_requirement_the_prefetch_plan_hands_out_carries_a_comparable_sample() {
        let _unreadable = change_time_unreadable_for_test();
        let h = store_harness();
        let newer = Content::one("the peer's v2 bytes");
        let path = local_file_superseded_by_missing_content(&h, "w", &newer).await;
        assert_degraded(&path);

        let wanted: BTreeSet<String> = BTreeSet::from(["w".to_owned()]);
        let required = h.convergence.content_missing_locally_from_native(GROUP, &wanted).unwrap();

        assert_eq!(required.len(), 1, "{required:?}");
        let sample = disk_race_fingerprint_or_stat(&path);
        assert!(sample.is_some());
        assert_eq!(required[0].observed_disk, sample, "an untouched file must compare equal");
    }

    /// eager.rs pre-fetch bracket (`observe_target`): the requirement the materialize itself
    /// raises carries a comparable sample.
    #[tokio::test(flavor = "current_thread")]
    async fn the_requirement_the_materialize_raises_carries_a_comparable_sample() {
        let _unreadable = change_time_unreadable_for_test();
        let h = store_harness();
        let newer = Content::one("the peer's v2 bytes");
        let path = local_file_superseded_by_missing_content(&h, "w", &newer).await;
        assert_degraded(&path);
        let payload = MaterializationPayload::from_version("w", newer.version.clone());

        let outcome = h
            .convergence
            .materialize_local(
                GROUP,
                &payload,
                MaterializationPolicy::Eager,
                PEER,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let LocalMaterializeOutcome::NeedBlocks(required) = outcome else {
            panic!("the content is not held here: {outcome:?}");
        };
        let sample = disk_race_fingerprint_or_stat(&path);
        assert!(sample.is_some());
        assert_eq!(required.observed_disk, sample, "an untouched file must compare equal");
    }

    /// The whole path, through the real callers: prefetch, the pre-fetch sample, the fetch, and the
    /// post-fetch bracket (eager.rs `revalidate_target`). The file nobody touched is replaced.
    #[tokio::test(flavor = "current_thread")]
    async fn an_untouched_file_is_replaced_by_the_fetched_content() {
        let _unreadable = change_time_unreadable_for_test();
        let h = store_harness();
        let newer = Content::one("the peer's v2 bytes");
        let path = local_file_superseded_by_missing_content(&h, "w", &newer).await;
        assert_degraded(&path);
        let peer = Arc::new(FakePeer::serving(&[&newer]));
        let driver: Arc<dyn ConvergenceDriver> = peer.clone();

        let _ = h
            .convergence
            .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["w".to_owned()]))
            .await;

        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"the peer's v2 bytes",
            "the pass was declined as if the file had changed"
        );
    }
}

// -- single-pass receive: the blocks of small files stay in memory for the pass --------------------

#[cfg(unix)]
fn single_pass(h: &Harness, on: bool) {
    h.convergence.single_pass_override.store(if on { 1 } else { 2 }, Ordering::Relaxed);
}

/// The block store underneath the executor's view, without the pass's in-memory blocks.
#[cfg(unix)]
fn committed(h: &Harness, hash: &[u8]) -> bool {
    use yadorilink_local_storage::BlockContentStore;
    BlockContentStore::present_blocks(h.store.as_ref(), &[hex::encode(hash)]).unwrap()[0]
}

#[cfg(unix)]
fn provenanced(h: &Harness, hash: &[u8]) -> bool {
    h.state.group_has_block_provenance_batch(GROUP, &[hash.to_vec()]).unwrap().contains(hash)
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_pass_keeps_a_small_files_blocks_in_memory_and_commits_nothing_for_them() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let (names, contents) = one_block_paths(&h, 6);
    let peer = Arc::new(FakePeer::serving(&contents.iter().collect::<Vec<_>>()));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let paths: BTreeSet<String> = names.iter().cloned().collect();

    let (_requirements, outcomes, hold) = h
        .convergence
        .obtain_missing_content_with(
            &driver,
            GROUP,
            &paths,
            &ReconcileCallTimer::new(),
            overlapped(8),
        )
        .await
        .unwrap();

    assert!(outcomes.values().all(|o| *o == PathPrefetch::Obtained), "{outcomes:?}");
    for content in &contents {
        let hash = content.hash(0);
        // The executor reads the pass's blocks as held...
        assert!(
            h.convergence.store.present_blocks(&[hex::encode(&hash)]).unwrap()[0],
            "the pass's block must be readable through the executor's store"
        );
        assert!(h.convergence.window_blocks.held_for(GROUP, &hex::encode(&hash)));
        // ...but nothing was committed for it, and nothing attests to it.
        assert!(!committed(&h, &hash), "a small file's block must not reach the block store");
        assert!(!provenanced(&h, &hash), "no provenance without a durable write");
        assert_eq!(
            h.convergence.store.get(&hex::encode(&hash)).unwrap(),
            content.blocks[0].1.to_vec(),
            "the bytes read back are the verified ones"
        );
    }
    assert!(hold._window.is_some());

    // Letting go of the pass releases every block.
    drop(hold);
    for content in &contents {
        assert!(!h.convergence.window_blocks.contains(&hex::encode(content.hash(0))));
        assert!(!h.convergence.store.present_blocks(&[hex::encode(content.hash(0))]).unwrap()[0]);
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_single_pass_the_blocks_are_committed_with_provenance_as_before() {
    let h = Harness::new(false);
    single_pass(&h, false);
    let (names, contents) = one_block_paths(&h, 4);
    let peer = Arc::new(FakePeer::serving(&contents.iter().collect::<Vec<_>>()));
    let names: Vec<&str> = names.iter().map(String::as_str).collect();

    let outcomes = prefetch(&h, &peer, &names, overlapped(8)).await;

    assert!(outcomes.values().all(|o| *o == PathPrefetch::Obtained), "{outcomes:?}");
    for content in &contents {
        let hash = content.hash(0);
        assert!(committed(&h, &hash) && provenanced(&h, &hash));
        assert!(!h.convergence.window_blocks.contains(&hex::encode(&hash)));
    }
}

/// Above the in-memory size a file is written into its own temp as it arrives, not committed to the
/// store; the prefetch leaves it as a ready temp for the settle, and a pass that ends without the
/// settle taking it removes it. Without the flag the same file goes to the store with provenance.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_above_the_in_memory_size_becomes_a_ready_temp_with_single_pass_and_a_store_copy_without(
) {
    use crate::local_convergence::window_blocks::WINDOW_BLOCKS_FILE_MAX_BYTES;
    let big = vec![7u8; WINDOW_BLOCKS_FILE_MAX_BYTES as usize + 1];
    for on in [true, false] {
        let h = Harness::new(false);
        single_pass(&h, on);
        let content = Content::of(&[&big]);
        published(&h, "big", &content);
        let peer = Arc::new(FakePeer::serving(&[&content]));
        let driver: Arc<dyn ConvergenceDriver> = peer.clone();
        let paths: BTreeSet<String> = BTreeSet::from(["big".to_owned()]);

        let (_requirements, outcomes, holds) = h
            .convergence
            .obtain_missing_content_with(
                &driver,
                GROUP,
                &paths,
                &ReconcileCallTimer::new(),
                overlapped(4),
            )
            .await
            .unwrap();

        assert_eq!(outcomes["big"], PathPrefetch::Obtained);
        let hash = content.hash(0);
        let version = content.version.version_hash.to_hex();
        if on {
            assert!(!committed(&h, &hash) && !provenanced(&h, &hash), "no store copy");
            assert!(h.convergence.filled_temps.holds(GROUP, "big", &version), "a ready temp");
            assert_eq!(leftover_temps(&h, "big").len(), 1);
            // The pass ends without a settle: the temp is removed.
            drop(holds);
            for _ in 0..100 {
                if leftover_temps(&h, "big").is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(leftover_temps(&h, "big").is_empty(), "an untaken ready temp is removed");
            assert!(!h.convergence.filled_temps.holds(GROUP, "big", &version));
        } else {
            assert!(committed(&h, &hash) && provenanced(&h, &hash), "a store copy as before");
            assert!(!h.convergence.filled_temps.holds(GROUP, "big", &version));
            assert!(leftover_temps(&h, "big").is_empty());
        }
    }
}

// -- single-pass receive of a large file: written into its own temp while it arrives ------------

/// Block bodies of `size` bytes whose first byte tells them apart.
#[cfg(unix)]
fn large_blocks(sizes: &[usize]) -> Vec<Vec<u8>> {
    sizes.iter().enumerate().map(|(i, size)| vec![i as u8 + 1; *size]).collect()
}

#[cfg(unix)]
fn leftover_temps(h: &Harness, file: &str) -> Vec<String> {
    let dir = h.path(file).parent().unwrap().to_path_buf();
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".yadorilink-tmp."))
        .collect()
}

/// A file above the in-memory size: its blocks are written at their offsets into the file's own temp
/// as they arrive, the temp is flushed, read back and renamed in; nothing reaches the block store, no
/// provenance is recorded, no temp is left, and the transfer entry is gone once the file is placed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_pass_writes_a_large_file_while_it_arrives_without_a_store_copy() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let tracker = crate::transfer_progress::TransferProgressTracker::new();
    h.convergence.attach_transfer_progress(tracker.clone());
    let bodies = large_blocks(&[2 << 20, 2 << 20, 2 << 20]);
    let content = Content::of(&bodies.iter().map(Vec::as_slice).collect::<Vec<_>>());
    published(&h, "big", &content);
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();

    h.convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["big".to_owned()]))
        .await
        .unwrap();

    assert_eq!(std::fs::read(h.path("big")).unwrap(), bodies.concat(), "the file holds the bytes");
    for index in 0..3 {
        let hash = content.hash(index);
        assert!(!committed(&h, &hash), "block {index}: no store copy");
        assert!(!provenanced(&h, &hash), "block {index}: no provenance row");
    }
    assert!(leftover_temps(&h, "big").is_empty(), "no temp is left beside the file");
    assert!(!h.convergence.filled_temps.holds(GROUP, "big", "x"));
    assert!(
        tracker.snapshot().is_empty(),
        "the transfer entry is withdrawn once the file is placed"
    );
}

/// A fetch that fails part way places no file and puts nothing in the store; what was written into
/// the file's temp is kept for the retry of the same version.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_file_whose_fetch_fails_is_not_placed_and_keeps_its_temp_for_the_retry() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let bodies = large_blocks(&[2 << 20, 2 << 20, 2 << 20]);
    let content = Content::of(&bodies.iter().map(Vec::as_slice).collect::<Vec<_>>());
    published(&h, "big", &content);
    let mut peer = FakePeer::serving(&[&content]);
    peer.failing.insert(content.hash(2));
    let peer = Arc::new(peer);
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();

    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["big".to_owned()]))
        .await;

    assert!(!h.path("big").exists(), "a file that did not arrive is not placed");
    assert_eq!(leftover_temps(&h, "big").len(), 1, "the temp is kept for the retry");
    assert_eq!(h.convergence.partial_temps.len(), 1);
    for index in 0..3 {
        assert!(!committed(&h, &content.hash(index)), "block {index}: nothing in the store");
    }
}

/// The first attempt of a three-block file fails at its last block; returns the harness, the bodies
/// and the content, with the kept temp in place.
#[cfg(unix)]
async fn a_three_block_file_with_a_kept_temp() -> (Harness, Vec<Vec<u8>>, Content) {
    let h = Harness::new(false);
    single_pass(&h, true);
    let bodies = large_blocks(&[2 << 20, 2 << 20, 2 << 20]);
    let content = Content::of(&bodies.iter().map(Vec::as_slice).collect::<Vec<_>>());
    published(&h, "big", &content);
    let mut peer = FakePeer::serving(&[&content]);
    peer.failing.insert(content.hash(2));
    let driver: Arc<dyn ConvergenceDriver> = Arc::new(peer);
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["big".to_owned()]))
        .await;
    assert_eq!(h.convergence.partial_temps.len(), 1, "sanity: the first attempt kept its temp");
    (h, bodies, content)
}

#[cfg(unix)]
async fn retry_big(h: &Harness, peer: &Arc<FakePeer>) {
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    h.convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["big".to_owned()]))
        .await
        .unwrap();
    h.convergence.drain_flush_barriers().await;
}

/// The retry asks the peer only for the blocks the kept temp lacks, and places the file.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_asks_only_for_the_blocks_the_kept_temp_lacks() {
    let (h, bodies, content) = a_three_block_file_with_a_kept_temp().await;
    let peer = Arc::new(FakePeer::serving(&[&content]));

    retry_big(&h, &peer).await;

    assert_eq!(peer.requests_for(&content.hash(0)), 0, "block 0 was in the kept temp");
    assert_eq!(peer.requests_for(&content.hash(1)), 0, "block 1 was in the kept temp");
    assert_eq!(peer.requests_for(&content.hash(2)), 1, "block 2 was fetched");
    assert_eq!(std::fs::read(h.path("big")).unwrap(), bodies.concat());
    assert!(leftover_temps(&h, "big").is_empty());
    assert_eq!(h.convergence.partial_temps.len(), 0);
}

/// Nothing in a kept temp is trusted: a block damaged in it meanwhile is read back, found not to
/// hash, and fetched again.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_damaged_in_the_kept_temp_is_fetched_again() {
    use std::io::{Seek, SeekFrom, Write};
    let (h, bodies, content) = a_three_block_file_with_a_kept_temp().await;
    let temp = h.path(&leftover_temps(&h, "big")[0]);
    let mut file = std::fs::OpenOptions::new().write(true).open(temp).unwrap();
    file.seek(SeekFrom::Start(1000)).unwrap();
    file.write_all(&[0xEE; 64]).unwrap();
    let peer = Arc::new(FakePeer::serving(&[&content]));

    retry_big(&h, &peer).await;

    assert_eq!(peer.requests_for(&content.hash(0)), 1, "the damaged block was fetched again");
    assert_eq!(peer.requests_for(&content.hash(1)), 0, "the intact block was not");
    assert_eq!(std::fs::read(h.path("big")).unwrap(), bodies.concat());
}

/// A kept temp that was removed meanwhile is not used: the retry starts a fresh one and fetches
/// every block.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_temp_that_was_removed_is_replaced_by_a_fresh_one() {
    let (h, bodies, content) = a_three_block_file_with_a_kept_temp().await;
    let temp = h.path(&leftover_temps(&h, "big")[0]);
    std::fs::remove_file(temp).unwrap();
    let peer = Arc::new(FakePeer::serving(&[&content]));

    retry_big(&h, &peer).await;

    for index in 0..3 {
        assert_eq!(peer.requests_for(&content.hash(index)), 1, "block {index} was fetched");
    }
    assert_eq!(std::fs::read(h.path("big")).unwrap(), bodies.concat());
    assert!(leftover_temps(&h, "big").is_empty());
}

/// A kept temp whose name was taken by another file is neither resumed nor removed: the retry makes
/// a fresh temp, and the other file is left alone.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_temp_replaced_by_another_file_is_neither_used_nor_removed() {
    let (h, bodies, content) = a_three_block_file_with_a_kept_temp().await;
    let temp = h.path(&leftover_temps(&h, "big")[0]);
    let other = h.path("someone-elses-file");
    std::fs::write(&other, vec![0x5Au8; 6 << 20]).unwrap();
    std::fs::rename(&other, &temp).unwrap();
    let peer = Arc::new(FakePeer::serving(&[&content]));

    retry_big(&h, &peer).await;

    for index in 0..3 {
        assert_eq!(peer.requests_for(&content.hash(index)), 1, "block {index} was fetched");
    }
    assert_eq!(std::fs::read(h.path("big")).unwrap(), bodies.concat());
    assert_eq!(std::fs::read(&temp).unwrap(), vec![0x5Au8; 6 << 20], "their file is untouched");
}

/// A newer version of the path drops the temp kept for the older one.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newer_version_drops_the_temp_kept_for_the_older_one() {
    let (h, _bodies, _content) = a_three_block_file_with_a_kept_temp().await;
    let newer_bodies = large_blocks(&[3 << 20, 2 << 20]);
    let newer = Content::of(&newer_bodies.iter().map(Vec::as_slice).collect::<Vec<_>>());
    store_version(&h, &newer.version);
    admit_remote_ops(&h.state, GROUP, PEER, &[put("big", &newer.version)], Basis::CurrentHeads);
    let peer = Arc::new(FakePeer::serving(&[&newer]));

    retry_big(&h, &peer).await;

    assert_eq!(std::fs::read(h.path("big")).unwrap(), newer_bodies.concat());
    assert_eq!(h.convergence.partial_temps.len(), 0);
    assert!(leftover_temps(&h, "big").is_empty(), "the older version's temp is gone");
}

/// A block the block store already holds (an older receive) is not asked of the peer: it is read
/// from the store, checked, and written into the file like the others.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_file_takes_a_block_the_store_already_holds_from_the_store() {
    use yadorilink_local_storage::BlockContentStore;
    let h = Harness::new(false);
    single_pass(&h, true);
    let bodies = large_blocks(&[2 << 20, 2 << 20, 2 << 20]);
    let content = Content::of(&bodies.iter().map(Vec::as_slice).collect::<Vec<_>>());
    published(&h, "big", &content);
    BlockContentStore::put(h.store.as_ref(), &bodies[1]).unwrap();
    h.state.record_block_provenance(GROUP, &[content.hash(1)]).unwrap();
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();

    h.convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["big".to_owned()]))
        .await
        .unwrap();

    assert_eq!(std::fs::read(h.path("big")).unwrap(), bodies.concat());
    assert_eq!(peer.requests_for(&content.hash(1)), 0, "the held block is not asked of the peer");
    assert_eq!(peer.requests_for(&content.hash(0)), 1);
    assert!(leftover_temps(&h, "big").is_empty());
}

/// While a large file fills, its data is flushed in steps (so that the end of the file has little
/// left to flush), and every step is finished before the file is completed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_file_is_flushed_in_steps_while_it_fills() {
    use crate::local_convergence::large_file_sink::LargeFileSink;
    let h = Harness::new(false);
    let bodies = large_blocks(&[1 << 20, 1 << 20, 1 << 20, 1 << 20]);
    let content = Content::of(&bodies.iter().map(Vec::as_slice).collect::<Vec<_>>());
    let record = yadorilink_replica_domain::file::FileRecord {
        path: "stepped".into(),
        size: 4 << 20,
        mtime_unix_nanos: 1,
        blocks: content
            .version
            .blocks
            .iter()
            .scan(0u64, |offset, block| {
                let at = *offset;
                *offset += u64::from(block.size);
                Some(yadorilink_replica_domain::file::BlockInfo {
                    hash: block.hash.0.clone(),
                    offset: at,
                    size: block.size,
                })
            })
            .collect(),
        deleted: false,
    };
    let ledger: Arc<dyn yadorilink_local_storage::TempFileLedger> =
        Arc::new(h.state.temp_ledger(GROUP));
    let staged =
        yadorilink_local_storage::StagedFile::create(&h.path("stepped"), 4 << 20, ledger).unwrap();
    let probe = {
        // The sink owns the staged file; keep a way to count its flushes.
        let mut sink = LargeFileSink::with_checkpoint(
            staged,
            Arc::new(crate::local_convergence::reconcile::HeadroomReservation::for_tests(
                "stepped-test",
                0,
            )),
            2 << 20,
        );
        for (index, body) in bodies.iter().enumerate() {
            let verified = yadorilink_local_storage::VerifiedBlock::check(
                body,
                &content.hash(index),
                body.len() as u32,
            )
            .unwrap();
            sink.write_block(&record, &verified).await.unwrap();
        }
        let before_final = sink.staged.data_flushes();
        sink.finalize(h.convergence.store.clone(), &record).await.unwrap();
        (before_final, sink.staged.tmp_path().to_path_buf(), sink)
    };
    let (before_final, tmp, sink) = probe;
    assert!(before_final >= 1, "the file was flushed while it filled ({before_final})");
    assert_eq!(std::fs::read(&tmp).unwrap(), bodies.concat());
    drop(sink);
    assert!(!tmp.exists(), "a staged file nobody kept is removed");
}

// -- single-pass receive: a pinned or leased path still reaches the block store -------------------

/// A pinned small file's blocks are committed to the store with the group's provenance, like a
/// receive without single-pass; its unpinned neighbour's stay in memory.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_pass_commits_a_pinned_small_files_blocks_to_the_store() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let (names, contents) = one_block_paths(&h, 2);
    h.state.pinned_item_repository().pin(GROUP, &names[0]).unwrap();
    let peer = Arc::new(FakePeer::serving(&contents.iter().collect::<Vec<_>>()));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();

    h.convergence
        .reconcile_paths_directly(&driver, GROUP, names.iter().cloned().collect())
        .await
        .unwrap();

    let (pinned, plain) = (contents[0].hash(0), contents[1].hash(0));
    assert!(committed(&h, &pinned) && provenanced(&h, &pinned), "the pinned file is in the store");
    assert!(!committed(&h, &plain), "an unpinned small file still stays out of the store");
    assert_eq!(std::fs::read(h.path(&names[0])).unwrap(), contents[0].blocks[0].1.to_vec());
}

/// A pinned large file does not go into its own file alone: its blocks are fetched into the store
/// and the file is reconstructed from it, while an unpinned one is still written as it arrives.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_pass_commits_a_pinned_large_files_blocks_to_the_store() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let bodies = large_blocks(&[2 << 20, 2 << 20, 2 << 20]);
    let pinned = Content::of(&bodies.iter().map(Vec::as_slice).collect::<Vec<_>>());
    let other_bodies: Vec<Vec<u8>> =
        bodies.iter().map(|b| b.iter().map(|x| x ^ 0x55).collect()).collect();
    let plain = Content::of(&other_bodies.iter().map(Vec::as_slice).collect::<Vec<_>>());
    published(&h, "big-pinned", &pinned);
    published(&h, "big-plain", &plain);
    h.state.pinned_item_repository().pin(GROUP, "big-pinned").unwrap();
    let peer = Arc::new(FakePeer::serving(&[&pinned, &plain]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();

    h.convergence
        .reconcile_paths_directly(
            &driver,
            GROUP,
            BTreeSet::from(["big-pinned".to_owned(), "big-plain".to_owned()]),
        )
        .await
        .unwrap();

    assert_eq!(std::fs::read(h.path("big-pinned")).unwrap(), bodies.concat());
    assert_eq!(std::fs::read(h.path("big-plain")).unwrap(), other_bodies.concat());
    for index in 0..3 {
        let hash = pinned.hash(index);
        assert!(committed(&h, &hash) && provenanced(&h, &hash), "pinned block {index}");
        assert!(!committed(&h, &plain.hash(index)), "unpinned block {index} stays out");
    }
    assert!(leftover_temps(&h, "big-pinned").is_empty());
}

/// A block a pinned path shares with an unpinned file of the same pass, which the pass kept in
/// memory only, still reaches the store for the pinned path: it is not skipped as "already fetched".
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_shared_with_an_unpinned_file_still_reaches_the_store_for_a_pinned_one() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let content = Content::one("the same body in two files");
    // The unpinned one sorts first, so it is fetched (and kept in memory) before the pinned one.
    published(&h, "a-plain", &content);
    published(&h, "b-pinned", &content);
    h.state.pinned_item_repository().pin(GROUP, "b-pinned").unwrap();
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();

    h.convergence
        .reconcile_paths_directly(
            &driver,
            GROUP,
            BTreeSet::from(["a-plain".to_owned(), "b-pinned".to_owned()]),
        )
        .await
        .unwrap();

    let hash = content.hash(0);
    assert!(committed(&h, &hash), "the pinned path's block is in the store");
    assert!(provenanced(&h, &hash), "and this group has provenance for it");
    assert_eq!(std::fs::read(h.path("b-pinned")).unwrap(), content.blocks[0].1.to_vec());
    assert_eq!(std::fs::read(h.path("a-plain")).unwrap(), content.blocks[0].1.to_vec());
}

/// A group asked to store (a custody lease request is in flight) commits every path's blocks.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_pass_commits_everything_while_the_group_is_asked_to_store() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let (names, contents) = one_block_paths(&h, 3);
    let peer = Arc::new(FakePeer::serving(&contents.iter().collect::<Vec<_>>()));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let hold = h.state.store_mode_requests().hold(GROUP, std::time::Duration::from_secs(60));

    h.convergence
        .reconcile_paths_directly(&driver, GROUP, names.iter().cloned().collect())
        .await
        .unwrap();
    drop(hold);

    for content in &contents {
        let hash = content.hash(0);
        assert!(committed(&h, &hash) && provenanced(&h, &hash));
    }
}

/// The same shared block with one fetch in flight at a time, so the unpinned file's block is already
/// in the pass (kept in memory) when the pinned path's turn comes: the pass-wide "already fetched"
/// shortcut must not skip it for the pinned path.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_already_fetched_shortcut_does_not_skip_a_block_a_pinned_path_needs_in_the_store() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let content = Content::one("a body fetched for the unpinned file first");
    published(&h, "a-plain", &content);
    published(&h, "b-pinned", &content);
    h.state.pinned_item_repository().pin(GROUP, "b-pinned").unwrap();
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let paths = BTreeSet::from(["a-plain".to_owned(), "b-pinned".to_owned()]);

    let (_requirements, outcomes, _hold) = h
        .convergence
        .obtain_missing_content_with(
            &driver,
            GROUP,
            &paths,
            &ReconcileCallTimer::new(),
            overlapped(1),
        )
        .await
        .unwrap();

    assert!(outcomes.values().all(|o| *o == PathPrefetch::Obtained), "{outcomes:?}");
    assert!(committed(&h, &content.hash(0)), "the pinned path's block reached the store");
}

/// The pinned path's own store commit fails while an unpinned neighbour holds the shared block in
/// memory. The settle must not build the pinned file from that memory-only block: the version the
/// pin promises would be left with the file alone. The unpinned file, which needs no store copy, is
/// placed as usual.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_path_whose_store_commit_failed_is_not_settled_from_a_neighbours_memory_block() {
    use yadorilink_local_storage::BlockStore;
    let h = Harness::new(false);
    single_pass(&h, true);
    let content = Content::one("a body both files need");
    published(&h, "a-plain", &content);
    published(&h, "b-pinned", &content);
    h.state.pinned_item_repository().pin(GROUP, "b-pinned").unwrap();
    // The store refuses every write from here: the pinned path's commit fails.
    h.store.set_headroom_enforced(true);
    h.store.set_headroom_override_bytes(Some(u64::MAX / 2));
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();

    let _ = h
        .convergence
        .reconcile_paths_directly(
            &driver,
            GROUP,
            BTreeSet::from(["a-plain".to_owned(), "b-pinned".to_owned()]),
        )
        .await;

    assert!(!committed(&h, &content.hash(0)), "fixture: nothing reached the store");
    assert!(!h.path("b-pinned").exists(), "the pinned file is not built from a memory-only block");
    assert_eq!(
        std::fs::read(h.path("a-plain")).unwrap(),
        content.blocks[0].1.to_vec(),
        "the unpinned file needs no store copy"
    );
}

/// The same failure when the shared block has provenance from an earlier life (it was stored, then
/// reclaimed): the store answers "present" for it only because the neighbour holds it in memory, so
/// the provenance row must not stand in for a store copy.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_old_provenance_row_does_not_stand_in_for_a_store_copy_of_a_pinned_path() {
    use yadorilink_local_storage::BlockStore;
    let h = Harness::new(false);
    single_pass(&h, true);
    let content = Content::one("a body stored once and reclaimed");
    published(&h, "a-plain", &content);
    published(&h, "b-pinned", &content);
    h.state.pinned_item_repository().pin(GROUP, "b-pinned").unwrap();
    h.state.record_block_provenance(GROUP, &[content.hash(0)]).unwrap();
    h.store.set_headroom_enforced(true);
    h.store.set_headroom_override_bytes(Some(u64::MAX / 2));
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();

    let _ = h
        .convergence
        .reconcile_paths_directly(
            &driver,
            GROUP,
            BTreeSet::from(["a-plain".to_owned(), "b-pinned".to_owned()]),
        )
        .await;

    assert!(!committed(&h, &content.hash(0)), "fixture: the block is not in the store");
    assert!(!h.path("b-pinned").exists(), "the pinned file is not built from a memory copy");
    assert_eq!(std::fs::read(h.path("a-plain")).unwrap(), content.blocks[0].1.to_vec());
}

/// A large file received while nothing keeps it ends as a ready temp, which stands for its blocks.
/// If the path is pinned before the settle, the temp no longer does: the version the pin promises
/// has to be in the store, so the settle asks for the blocks instead of placing the temp.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ready_temp_does_not_stand_for_a_path_pinned_before_the_settle() {
    use crate::local_convergence::window_blocks::WINDOW_BLOCKS_FILE_MAX_BYTES;
    let h = Harness::new(false);
    single_pass(&h, true);
    let big = vec![9u8; WINDOW_BLOCKS_FILE_MAX_BYTES as usize + 1];
    let content = Content::of(&[&big]);
    published(&h, "big", &content);
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let paths = BTreeSet::from(["big".to_owned()]);
    let (requirements, _outcomes, _holds) = h
        .convergence
        .obtain_missing_content_with(
            &driver,
            GROUP,
            &paths,
            &ReconcileCallTimer::new(),
            overlapped(4),
        )
        .await
        .unwrap();
    let version = content.version.version_hash.to_hex();
    assert!(h.convergence.filled_temps.holds(GROUP, "big", &version), "fixture: a ready temp");
    let record = requirements["big"].record.clone();

    assert!(
        !h.convergence.content_missing_for_settle(GROUP, &record, &version).unwrap(),
        "an unpinned path is satisfied by its ready temp"
    );

    h.state.pinned_item_repository().pin(GROUP, "big").unwrap();

    assert!(
        h.convergence.content_missing_for_settle(GROUP, &record, &version).unwrap(),
        "a pinned path is not: its version has to be in the store"
    );
}

/// Another group's pass holds a block in memory, and this group has an old provenance row for it
/// (stored once, then reclaimed). The executor's store answers "present" for it, but the only copy
/// is another group's memory: a path that must be in the store is not satisfied by it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_groups_memory_block_does_not_satisfy_a_pinned_path() {
    use crate::local_convergence::window_blocks::WindowBlocksHold;
    let h = Harness::new(false);
    single_pass(&h, true);
    let content = Content::one("a block only another group's pass holds");
    let record = yadorilink_replica_domain::file::FileRecord {
        path: "pinned.bin".to_owned(),
        size: content.blocks[0].1.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![yadorilink_replica_domain::file::BlockInfo {
            hash: content.hash(0),
            offset: 0,
            size: content.blocks[0].1.len() as u32,
        }],
        deleted: false,
    };
    h.state.record_block_provenance(GROUP, &[content.hash(0)]).unwrap();
    let mut other =
        WindowBlocksHold::new(Arc::clone(&h.convergence.window_blocks), "another-group");
    assert!(other.try_hold(&hex::encode(content.hash(0)), &content.blocks[0].1));
    assert!(
        !h.convergence.blocks_missing_locally(GROUP, &record).unwrap(),
        "an unpinned path is satisfied by what the executor's store answers"
    );

    h.state.pinned_item_repository().pin(GROUP, "pinned.bin").unwrap();

    assert!(
        h.convergence.blocks_missing_locally(GROUP, &record).unwrap(),
        "a pinned path needs the store itself"
    );
    drop(other);
}

/// The same situation at admission: what a pinned path still has to fetch is decided against the
/// store itself, so the block is fetched and committed instead of being skipped on the strength of a
/// memory copy and an old provenance row.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_asks_the_store_itself_for_a_pinned_path() {
    use crate::local_convergence::window_blocks::WindowBlocksHold;
    let h = Harness::new(false);
    single_pass(&h, true);
    let content = Content::one("a block another pass holds in memory");
    published(&h, "pinned.bin", &content);
    h.state.pinned_item_repository().pin(GROUP, "pinned.bin").unwrap();
    h.state.record_block_provenance(GROUP, &[content.hash(0)]).unwrap();
    let mut other =
        WindowBlocksHold::new(Arc::clone(&h.convergence.window_blocks), "another-group");
    assert!(other.try_hold(&hex::encode(content.hash(0)), &content.blocks[0].1));
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();

    let (_requirements, outcomes, _hold) = h
        .convergence
        .obtain_missing_content_with(
            &driver,
            GROUP,
            &BTreeSet::from(["pinned.bin".to_owned()]),
            &ReconcileCallTimer::new(),
            overlapped(4),
        )
        .await
        .unwrap();

    assert_eq!(outcomes["pinned.bin"], PathPrefetch::Obtained);
    assert_eq!(peer.requests_for(&content.hash(0)), 1, "the block was asked of the peer");
    assert!(committed(&h, &content.hash(0)), "and committed to the store");
    drop(other);
}

/// A path pinned between the settle's look and the moment it takes the ready temp does not use the
/// temp: the temp is discarded and the write ends so that the next pass fetches into the store.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ready_temp_is_not_taken_for_a_path_pinned_meanwhile() {
    use crate::local_convergence::window_blocks::WINDOW_BLOCKS_FILE_MAX_BYTES;
    let h = Harness::new(false);
    single_pass(&h, true);
    let big = vec![5u8; WINDOW_BLOCKS_FILE_MAX_BYTES as usize + 1];
    let content = Content::of(&[&big]);
    published(&h, "big", &content);
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let (_requirements, _outcomes, _holds) = h
        .convergence
        .obtain_missing_content_with(
            &driver,
            GROUP,
            &BTreeSet::from(["big".to_owned()]),
            &ReconcileCallTimer::new(),
            overlapped(4),
        )
        .await
        .unwrap();
    let version = content.version.version_hash.to_hex();
    assert!(h.convergence.filled_temps.holds(GROUP, "big", &version), "fixture: a ready temp");

    // Unpinned, the temp is handed over (and put back for the next half of the test).
    let temp = h.convergence.take_ready_temp(GROUP, "big", &version).unwrap();
    assert!(temp.is_some(), "an unpinned path takes its ready temp");
    drop(temp);

    // A fresh ready temp, then the pin lands before the take.
    let (_requirements, _outcomes, _holds2) = h
        .convergence
        .obtain_missing_content_with(
            &driver,
            GROUP,
            &BTreeSet::from(["big".to_owned()]),
            &ReconcileCallTimer::new(),
            overlapped(4),
        )
        .await
        .unwrap();
    assert!(
        h.convergence.filled_temps.holds(GROUP, "big", &version),
        "fixture: a ready temp again"
    );
    h.state.pinned_item_repository().pin(GROUP, "big").unwrap();

    assert!(h.convergence.take_ready_temp(GROUP, "big", &version).is_err());
    assert!(!h.convergence.filled_temps.holds(GROUP, "big", &version), "the temp is gone");
}

// -- barrier 1: the temp of a received file is durable before it is renamed over its target ------

#[cfg(unix)]
fn deferred(h: &Harness) {
    h.convergence
        .deferred_flush_override
        .store(super::receive_deferred_flush_tests::FULL_FLUSH_EACH, Ordering::Relaxed);
}

#[cfg(unix)]
fn temp_flushes(h: &Harness) -> usize {
    yadorilink_local_storage::completed_flushes_under(&h.path(""))
        .iter()
        .filter(|path| {
            path.file_name().is_some_and(|n| n.to_string_lossy().starts_with(".yadorilink-tmp."))
        })
        .count()
}

#[cfg(unix)]
fn directory_flushes(h: &Harness) -> usize {
    let root = h.path("");
    yadorilink_local_storage::completed_flushes_under(&root)
        .iter()
        .filter(|path| **path == root)
        .count()
}

/// Reconciles `names` and stops every file at the seam before its rename, as a power cut there
/// would; returns the held task's abort handle so the process "dies" there.
#[cfg(unix)]
async fn stopped_before_the_rename(
    h: &Harness,
    peer: &Arc<FakePeer>,
    names: &[String],
) -> tokio::task::JoinHandle<()> {
    let probe = crate::local_convergence::OverlapProbe::new(
        crate::local_convergence::ProbeSeam::BeforeRename,
        names.len(),
        30_000,
    );
    probe.hold_until_released();
    *h.convergence.overlap_probe.lock().unwrap() = Some(probe.clone());
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let task = {
        let (convergence, paths) =
            (h.convergence.clone(), names.iter().cloned().collect::<BTreeSet<_>>());
        tokio::spawn(async move {
            let _ = convergence.reconcile_paths_directly(&driver, GROUP, paths).await;
        })
    };
    let waited = std::time::Instant::now();
    while probe.in_flight() < names.len() {
        assert!(waited.elapsed() < Duration::from_secs(30), "{:?}", probe.events());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    *h.convergence.overlap_probe.lock().unwrap() = None;
    task
}

/// Barrier 1: by the time a file stands at the seam right before its rename, the temp's data and the
/// directory entry of the temp are flushed, the directory once for the whole batch, and the target
/// is still untouched.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_temp_is_flushed_with_its_directory_before_it_is_renamed() {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    h.convergence.receive_write_concurrency_override.store(8, Ordering::Relaxed);
    let (names, contents) = one_block_paths(&h, 6);
    let peer = Arc::new(FakePeer::serving(&contents.iter().collect::<Vec<_>>()));

    let task = stopped_before_the_rename(&h, &peer, &names).await;

    assert_eq!(temp_flushes(&h), names.len(), "every temp's data was flushed");
    let dirs = directory_flushes(&h);
    assert!(dirs >= 1, "the temps' directory was flushed");
    assert!(
        dirs < names.len(),
        "the directory is flushed per batch, not per file: {dirs} {:?}",
        yadorilink_local_storage::completed_flushes_under(&h.path(""))
    );
    for name in &names {
        assert!(!h.path(name).exists(), "{name}: the target is not touched before the flush");
    }
    task.abort();
    let _ = task.await;
}

/// The same for a large file filled while it arrived: its data was flushed when it was filled and is
/// not flushed again, but its temp name is made durable before the rename.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_temp_of_a_large_file_gets_its_directory_flushed_before_the_rename() {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let bodies = large_blocks(&[2 << 20, 2 << 20, 2 << 20]);
    let content = Content::of(&bodies.iter().map(Vec::as_slice).collect::<Vec<_>>());
    published(&h, "big", &content);
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let before = directory_flushes(&h);

    let task = stopped_before_the_rename(&h, &peer, &["big".to_owned()]).await;

    assert!(directory_flushes(&h) > before, "the temp's directory entry is flushed");
    assert!(!h.path("big").exists());
    task.abort();
    let _ = task.await;
}

/// A temp that cannot be flushed is not renamed: a file that replaces a received one leaves the
/// target with its previous bytes, a new file is not placed, no temp is left and nothing is
/// reported synced. Both are fetched and placed by the next pass: the untouched previous bytes
/// under the open intent are the write's pre-image, not a local edit that would stall it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_barrier_one_renames_nothing_and_the_next_pass_places_both_files() {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let driver_of = |peer: &Arc<FakePeer>| -> Arc<dyn ConvergenceDriver> { peer.clone() };
    let (replaced, fresh) = ("f00".to_owned(), "f01".to_owned());
    let paths: BTreeSet<String> = [replaced.clone(), fresh.clone()].into();
    let closed = |name: &str| super::receive_deferred_flush_tests::closed(&h, name);

    // A previous version of one path, received and closed.
    let v1 = Content::one("v1 of the replaced file");
    published(&h, &replaced, &v1);
    let peer = Arc::new(FakePeer::serving(&[&v1]));
    h.convergence
        .reconcile_paths_directly(&driver_of(&peer), GROUP, BTreeSet::from([replaced.clone()]))
        .await
        .unwrap();
    h.convergence.drain_flush_barriers().await;
    assert!(closed(&replaced));

    // Its replacement and a new file; only the temp flushes of this root fail.
    let v2 = Content::one("v2 of the replaced file");
    let new = Content::one("a new file");
    store_version(&h, &v2.version);
    admit_remote_ops(&h.state, GROUP, PEER, &[put(&replaced, &v2.version)], Basis::CurrentHeads);
    published(&h, &fresh, &new);
    let peer = Arc::new(FakePeer::serving(&[&v2, &new]));
    {
        let needle =
            format!("{}/.yadorilink-tmp.", h.path("").to_string_lossy().trim_end_matches('/'));
        let _fail = yadorilink_local_storage::fail_received_flushes_of(&needle);
        let _ =
            h.convergence.reconcile_paths_directly(&driver_of(&peer), GROUP, paths.clone()).await;
        h.convergence.drain_flush_barriers().await;
        assert_eq!(
            std::fs::read(h.path(&replaced)).unwrap(),
            v1.blocks[0].1.to_vec(),
            "the target keeps what it held"
        );
        assert!(!h.path(&fresh).exists(), "a new file is not placed");
        assert!(leftover_temps(&h, &fresh).is_empty(), "the failed temps are removed");
        assert!(!closed(&replaced) && !closed(&fresh), "nothing is reported synced");
        let authored: BTreeSet<String> = h.scan().into_iter().map(|r| r.path).collect();
        assert!(authored.is_empty(), "the untouched old bytes are not authored: {authored:?}");
    }

    let attempt = h
        .convergence
        .reconcile_paths_directly(&driver_of(&peer), GROUP, paths.clone())
        .await
        .unwrap()
        .expect("the attempt runs");
    h.convergence.drain_flush_barriers().await;
    assert!(attempt.is_settled(&fresh), "the new file is not stuck: {attempt:?}");
    assert!(attempt.is_settled(&replaced), "the replaced file is not stuck: {attempt:?}");
    assert_eq!(std::fs::read(h.path(&fresh)).unwrap(), new.blocks[0].1.to_vec());
    assert_eq!(std::fs::read(h.path(&replaced)).unwrap(), v2.blocks[0].1.to_vec());
    assert!(closed(&fresh) && closed(&replaced));
}

/// The process stops after barrier 1 and before the rename (a power cut there): the temp the
/// barrier made durable is still beside the target and holds the whole file, the target was never
/// touched, and after a restart's repair the next pass fetches and places the new file.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_a_cut_between_barrier_one_and_the_rename_keeps_the_temp_and_the_file_is_fetched_again(
) {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let (names, contents) = one_block_paths(&h, 2);
    let peer = Arc::new(FakePeer::serving(&contents.iter().collect::<Vec<_>>()));

    let task = stopped_before_the_rename(&h, &peer, &names).await;
    let temps = leftover_temps(&h, &names[0]);
    assert_eq!(temps.len(), names.len(), "each file's durable temp is beside its target");
    let held: BTreeSet<Vec<u8>> = temps.iter().map(|t| std::fs::read(h.path(t)).unwrap()).collect();
    let wanted: BTreeSet<Vec<u8>> = contents.iter().map(|c| c.blocks[0].1.to_vec()).collect();
    assert_eq!(held, wanted, "the temps hold the complete received bytes");
    for name in &names {
        assert!(!h.path(name).exists(), "{name}: the target was never touched");
    }
    task.abort();
    let _ = task.await;

    // The restart: repair, then the pass the obligation re-drives.
    super::receive_deferred_flush_tests::startup(&h);
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let attempt = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, names.iter().cloned().collect())
        .await
        .unwrap()
        .expect("the attempt runs");
    h.convergence.drain_flush_barriers().await;
    for (name, content) in names.iter().zip(&contents) {
        assert!(attempt.is_settled(name), "{name}: {attempt:?}");
        assert_eq!(std::fs::read(h.path(name)).unwrap(), content.blocks[0].1.to_vec());
        assert!(super::receive_deferred_flush_tests::closed(&h, name));
    }
}

/// The temp that barrier 1 flushed is the object that is renamed: a temp swapped for another file
/// (same bytes, never flushed) after the barrier is refused before the rename, never renamed over
/// the target unflushed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_temp_swapped_after_barrier_one_is_refused_before_the_rename() {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let (names, contents) = one_block_paths(&h, 1);
    let peer = Arc::new(FakePeer::serving(&[&contents[0]]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let dir = h.path("");
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() = Some(Box::new(move |_| {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            if entry.file_name().to_string_lossy().starts_with(".yadorilink-tmp.") {
                let bytes = std::fs::read(entry.path()).unwrap();
                let other = dir.join("swap-in");
                std::fs::write(&other, bytes).unwrap();
                std::fs::rename(&other, entry.path()).unwrap();
            }
        }
    }));

    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, names.iter().cloned().collect())
        .await;
    let reports = h.convergence.drain_flush_barriers().await;

    // The swapped object was refused before the rename; the retry wrote and flushed a fresh temp.
    assert_eq!(reports.iter().map(|r| r.failed).sum::<usize>(), 0, "{reports:?}");
    assert_eq!(std::fs::read(h.path(&names[0])).unwrap(), contents[0].blocks[0].1.to_vec());
    assert!(super::receive_deferred_flush_tests::closed(&h, &names[0]));
}

/// A file written in place after barrier 1 flushed it moves the stamp that barrier 2 compares, so
/// barrier 2 flushes the file again under its final name.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_temp_written_in_place_after_barrier_one_is_flushed_again_by_barrier_two() {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let (names, contents) = one_block_paths(&h, 1);
    let peer = Arc::new(FakePeer::serving(&[&contents[0]]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let dir = h.path("");
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() = Some(Box::new(move |_| {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            if entry.file_name().to_string_lossy().starts_with(".yadorilink-tmp.") {
                // The same bytes, written in place: the length is unchanged and the time moves.
                std::thread::sleep(Duration::from_millis(20));
                let bytes = std::fs::read(entry.path()).unwrap();
                std::fs::write(entry.path(), bytes).unwrap();
            }
        }
    }));

    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, names.iter().cloned().collect())
        .await;
    h.convergence.drain_flush_barriers().await;

    let flushed = yadorilink_local_storage::completed_flushes_under(&h.path(""));
    assert!(flushed.contains(&h.path(&names[0])), "the file is flushed under its final name");
}

/// A receive dropped while it waits for barrier 1 leaves its temp where it is: another receive may
/// be running the barrier over that very temp and recording its witness, so a removal here could
/// leave a witness for a temp that is gone, which reads as "renamed". The temp left behind says
/// "not renamed"; the startup sweep removes it once the intent is gone. Whatever a witness names
/// is still there.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receive_dropped_while_it_waits_for_barrier_one_never_leaves_a_witness_for_a_missing_temp(
) {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let (names, contents) = one_block_paths(&h, 1);
    let peer = Arc::new(FakePeer::serving(&[&contents[0]]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    // Cancel the receive while its temp is queued: the batch is held back by a flush that blocks.
    let hold = super::received_flush_barrier::test_hold::hold_temp_flushes_under(
        h.path("").to_string_lossy().trim_end_matches('/'),
    );
    let task = {
        let (convergence, paths) =
            (h.convergence.clone(), names.iter().cloned().collect::<BTreeSet<_>>());
        tokio::spawn(async move {
            let _ = convergence.reconcile_paths_directly(&driver, GROUP, paths).await;
        })
    };
    while hold.entered() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Dropping the cancelled receive waits for the held batch, so it is released from elsewhere.
    let releaser = std::thread::spawn({
        let hold = hold;
        move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(hold);
        }
    });
    task.abort();
    let _ = task.await;
    releaser.join().unwrap();
    let witness = h
        .state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(yadorilink_sync_sqlite::write_removal_facts(conn, GROUP, &names[0])?
                .and_then(|facts| facts.temp_witness))
        })
        .unwrap();
    if let Some(witness) = witness {
        assert!(h.path(&witness).exists(), "a witness names a temp that is gone: {witness}");
    }
    // The temp the drop left behind is an ordinary stray once the intent is gone.
    let _ = leftover_temps(&h, &names[0]);
}

/// A received file `f00` replaced by a version whose barrier 1 failed: returns the harness's peer
/// serving the new version.
#[cfg(unix)]
async fn replaced_with_a_failed_barrier_one(
    h: &Harness,
    v1: &Content,
    v2: &Content,
) -> Arc<FakePeer> {
    let name = "f00".to_owned();
    let paths = BTreeSet::from([name.clone()]);
    published(h, &name, v1);
    let peer: Arc<FakePeer> = Arc::new(FakePeer::serving(&[v1]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    h.convergence.reconcile_paths_directly(&driver, GROUP, paths.clone()).await.unwrap();
    h.convergence.drain_flush_barriers().await;
    store_version(h, &v2.version);
    admit_remote_ops(&h.state, GROUP, PEER, &[put(&name, &v2.version)], Basis::CurrentHeads);
    let peer: Arc<FakePeer> = Arc::new(FakePeer::serving(&[v2]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let needle = format!("{}/.yadorilink-tmp.", h.path("").to_string_lossy().trim_end_matches('/'));
    let _fail = yadorilink_local_storage::fail_received_flushes_of(&needle);
    let _ = h.convergence.reconcile_paths_directly(&driver, GROUP, paths).await;
    peer
}

/// A user's edit made AFTER repair stood the write down is not overwritten by the retry: the row is
/// in flight over the file, and the file is neither the previous version nor the new one.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_edit_after_the_stand_down_is_not_overwritten_by_the_retry() {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let (v1, v2) = (Content::one("v1"), Content::one("v2"));
    let peer = replaced_with_a_failed_barrier_one(&h, &v1, &v2).await;
    let report = super::receive_deferred_flush_tests::startup(&h);
    assert_eq!(report.stood_down, vec!["f00".to_string()], "{report:?}");
    std::fs::write(h.path("f00"), b"the user's words after the stand-down").unwrap();

    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["f00".to_owned()]))
        .await;

    assert_eq!(
        std::fs::read(h.path("f00")).unwrap(),
        b"the user's words after the stand-down",
        "the retry did not rename the new version over the user's bytes"
    );
}

/// A user's edit of the previous version, made before the restart, is still preserved: only the
/// untouched object the device itself wrote is the write's pre-image.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_edit_over_the_previous_version_is_kept_by_the_repair_after_a_failed_barrier_one() {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let (v1, v2) = (Content::one("v1"), Content::one("v2"));
    let _peer = replaced_with_a_failed_barrier_one(&h, &v1, &v2).await;
    std::fs::write(h.path("f00"), b"the user's own words").unwrap();

    let report = super::receive_deferred_flush_tests::startup(&h);

    assert!(report.stood_down.is_empty(), "{report:?}");
    let kept = std::fs::read_dir(h.path(""))
        .unwrap()
        .flatten()
        .filter_map(|e| std::fs::read(e.path()).ok())
        .any(|bytes| bytes == b"the user's own words");
    assert!(kept, "the user's bytes are preserved: {report:?}");
}

/// A file that replaces a received one, whose barrier 1 failed and whose process then restarted,
/// is not turned into a "local-recovered" conflict copy of the old version by startup repair, and
/// the next pass places the new version. Repair finds the open intent over the untouched previous
/// version with no copy of the new bytes to rebuild from, and stands the write down instead of
/// quarantining the old bytes.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_whose_barrier_one_failed_survives_a_restart_without_a_conflict_copy() {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let driver_of = |peer: &Arc<FakePeer>| -> Arc<dyn ConvergenceDriver> { peer.clone() };
    let name = "f00".to_owned();
    let paths = BTreeSet::from([name.clone()]);
    let v1 = Content::one("v1");
    published(&h, &name, &v1);
    let peer = Arc::new(FakePeer::serving(&[&v1]));
    h.convergence.reconcile_paths_directly(&driver_of(&peer), GROUP, paths.clone()).await.unwrap();
    h.convergence.drain_flush_barriers().await;
    let v2 = Content::one("v2");
    store_version(&h, &v2.version);
    admit_remote_ops(&h.state, GROUP, PEER, &[put(&name, &v2.version)], Basis::CurrentHeads);
    let peer = Arc::new(FakePeer::serving(&[&v2]));
    {
        let needle =
            format!("{}/.yadorilink-tmp.", h.path("").to_string_lossy().trim_end_matches('/'));
        let _fail = yadorilink_local_storage::fail_received_flushes_of(&needle);
        let _ =
            h.convergence.reconcile_paths_directly(&driver_of(&peer), GROUP, paths.clone()).await;
    }

    super::receive_deferred_flush_tests::startup(&h);

    let authored: BTreeSet<String> = h.scan().into_iter().map(|r| r.path).collect();
    assert!(authored.is_empty(), "no conflict copy of the old version: {authored:?}");
    h.convergence.reconcile_paths_directly(&driver_of(&peer), GROUP, paths).await.unwrap();
    h.convergence.drain_flush_barriers().await;
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), v2.blocks[0].1.to_vec());
}

/// The same cut for a file that replaces a received one: the previous version stays at the name,
/// repair stands the write down instead of quarantining it, and the next pass places the new
/// version with no conflict copy.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_a_cut_between_barrier_one_and_the_rename_of_a_replacement_keeps_the_old_version() {
    let h = Harness::new(false);
    single_pass(&h, true);
    deferred(&h);
    let name = "f00".to_owned();
    let (v1, v2) = (Content::one("v1 content"), Content::one("v2 content"));
    published(&h, &name, &v1);
    let first: Arc<FakePeer> = Arc::new(FakePeer::serving(&[&v1]));
    let driver: Arc<dyn ConvergenceDriver> = first.clone();
    h.convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from([name.clone()]))
        .await
        .unwrap();
    h.convergence.drain_flush_barriers().await;
    store_version(&h, &v2.version);
    admit_remote_ops(&h.state, GROUP, PEER, &[put(&name, &v2.version)], Basis::CurrentHeads);
    let peer = Arc::new(FakePeer::serving(&[&v2]));

    let task = stopped_before_the_rename(&h, &peer, std::slice::from_ref(&name)).await;
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), v1.blocks[0].1.to_vec());
    task.abort();
    let _ = task.await;

    let report = super::receive_deferred_flush_tests::startup(&h);
    assert!(report.quarantined_dirty.is_empty(), "{report:?}");
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), v1.blocks[0].1.to_vec());
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    h.convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from([name.clone()]))
        .await
        .unwrap();
    h.convergence.drain_flush_barriers().await;
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), v2.blocks[0].1.to_vec());
    assert!(super::receive_deferred_flush_tests::closed(&h, &name));
    let authored: BTreeSet<String> = h.scan().into_iter().map(|r| r.path).collect();
    assert!(authored.is_empty(), "no conflict copy: {authored:?}");
}

/// A path settled from a single-pass receive holds its content only as its file: the store has
/// none of its blocks. A later pass over the same path (a reconnect, an unrelated wake) finds the
/// disk already at the version and must not fetch the content again.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settled_file_only_path_is_not_fetched_again_by_a_later_pass() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let content = Content::one("a body received straight into its file");
    published(&h, "settled", &content);
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let paths = BTreeSet::from(["settled".to_owned()]);

    let _ = h.convergence.reconcile_paths_directly(&driver, GROUP, paths.clone()).await;
    assert_eq!(std::fs::read(h.path("settled")).unwrap(), content.blocks[0].1.to_vec());
    assert!(!committed(&h, &content.hash(0)), "fixture: the content is only the file");
    let first = peer.requests_for(&content.hash(0));
    assert_eq!(first, 1, "fixture: one fetch settled it");

    let wanted = h.convergence.content_missing_locally_from_native(GROUP, &paths).unwrap();
    let _ = h.convergence.reconcile_paths_directly(&driver, GROUP, paths).await;

    assert!(wanted.is_empty(), "the plan wants content the disk already holds: {wanted:?}");
    assert_eq!(peer.requests_for(&content.hash(0)), first, "the settled path was fetched again");

    // A path that has to be in the store still gets its content there.
    h.state.pinned_item_repository().pin(GROUP, "settled").unwrap();
    let wanted = h.convergence.content_missing_locally_from_native(GROUP, &paths_again()).unwrap();
    assert_eq!(wanted.len(), 1, "a pinned path is fetched into the store");
}

#[cfg(unix)]
fn paths_again() -> BTreeSet<String> {
    BTreeSet::from(["settled".to_owned()])
}

/// Skipping the fetch of a settled file-only path must not hide a later local change: an edit of
/// the file is captured as a new version, and its deletion is captured as a removal.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_edit_or_delete_of_a_settled_file_only_path_is_still_captured() {
    let h = Harness::new(false);
    single_pass(&h, true);
    let content = Content::one("a body received straight into its file");
    published(&h, "settled", &content);
    let peer = Arc::new(FakePeer::serving(&[&content]));
    let driver: Arc<dyn ConvergenceDriver> = peer.clone();
    let paths = paths_again();
    let _ = h.convergence.reconcile_paths_directly(&driver, GROUP, paths.clone()).await;
    assert!(!committed(&h, &content.hash(0)), "fixture: the content is only the file");
    let received = content.version.version_hash;

    std::fs::write(h.path("settled"), b"edited by the user afterwards").unwrap();
    // Even before capture has journaled or fenced the edit, a changed file is not skipped.
    assert_eq!(
        h.convergence.content_missing_locally_from_native(GROUP, &paths).unwrap().len(),
        1,
        "a changed file is wanted again, not trusted on the standing proof"
    );
    h.capture("settled").await;
    let edited = h.own_head("settled").content.unwrap().version_hash;
    assert_ne!(edited, received.0, "the edit became the path's head");
    // The proof of the received version is void, so the plan wants nothing it could hide it with.
    let _ = h.convergence.reconcile_paths_directly(&driver, GROUP, paths).await;
    assert_eq!(
        std::fs::read(h.path("settled")).unwrap(),
        b"edited by the user afterwards",
        "the edit is not overwritten"
    );

    std::fs::remove_file(h.path("settled")).unwrap();
    h.observe_removal("settled").await;
    let row = h.state.file_index_repository().canonical_current_row(GROUP, "settled").unwrap();
    assert!(row.is_none_or(|row| row.snapshot.deleted), "the deletion was captured");
}
