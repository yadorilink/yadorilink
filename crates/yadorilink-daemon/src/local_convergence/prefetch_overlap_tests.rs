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
                BlockFetch::Fetched { hash: block.hash.clone(), data: Bytes::from_static(b"no") }
            } else {
                match self.served.get(&block.hash) {
                    Some(data) => {
                        BlockFetch::Fetched { hash: block.hash.clone(), data: data.clone() }
                    }
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
                unix_mode: Some(0o644),
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
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
    let (_requirements, outcomes) = h
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
    let h = Harness::new(false);
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
    let h = Harness::new(false);
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
    let h = Harness::new(false);
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
    let h = Harness::new(false);
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
    let h = Harness::new(false);
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
    let h = Harness::new(false);
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
    let h = Arc::new(Harness::new(false));
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
        let h = Harness::new(false);
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
        let h = Harness::new(false);
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
    let h = Harness::new(false);
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
    let h = Harness::new(false);
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
    let h = Harness::new(false);
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
        let h = Harness::new(false);
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
        let h = Harness::new(false);
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
        let h = Harness::new(false);
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
