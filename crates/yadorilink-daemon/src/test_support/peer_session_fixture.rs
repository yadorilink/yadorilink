//! The `ReplicaCoordinator`-backed peer-session integration fixture.
//!
//! It lived in `yadorilink-peer-session`'s own `tests/peer_session.rs` until
//! the tests whose subject is materialization, hydration and convergence moved
//! to this crate. The fixture could not follow them by being copied -- two
//! copies of a 200-line mini-replica drift, and a fix lands on one side only --
//! and it could not stay behind either, because `Device` is a
//! `ReplicaCoordinator`, a link row, a `VerifiedRoot`, a startup gate, native state
//! and a self-signing checkpoint author: this crate's subject, not
//! peer-session's.
//!
//! So it lives here, and peer-session's remaining integration tests reach it
//! through the dev-dependency on this crate they already had. That back-edge
//! is a test-harness bridge and not the end state: once the tests that stayed
//! behind no longer need a daemon-built session, the edge and this module's
//! peer-session half can both go.
#![allow(dead_code)] // each side of the split uses a different subset

// Reusable plain-build native-delta test support (signed-delta producer).
pub mod dag_wire_support;

use ed25519_dalek::SigningKey;
use prost::Message as _;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

use crate::replica_coordinator::ReplicaCoordinator;
use dag_wire_support::DagProducer;
use proto::block_response_header::Outcome as BlockOutcome;
use yadorilink_ipc_proto::sync as proto;
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::{
    BlockWriteActivityProvider, PeerSyncSession, PeerSyncSessionDeps, PendingLocalChangeFlush,
    PendingLocalFlushOutcome, RootCommitAuthorityProvider,
};
use yadorilink_peer_session::ports::BlockStreamTransport;
use yadorilink_peer_session::rate_limiter::RateLimiters;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;
use yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES;

/// The payload a test's bare `FileRecord` stands for: an ordinary
/// regular file with no separately-carried metadata.
///
/// Production never builds one this way -- it carries the version from
/// whatever produced the bytes (a resolved native version, the wire metadata
/// that arrived with the record). These fixtures have only the record, so
/// this derives the version that record itself names.
///
/// Note the `RecordKind::File`: it is a real claim now, not a filler.
/// Materialization picks its lane from the payload's kind rather than
/// from the index row, so a fixture whose path is a symlink must use
/// [`symlink_payload_for`] instead -- seeding `set_record_kind` on the
/// row no longer routes anything.
///
/// A `deleted` record is a tombstone payload, as production builds it
/// (`MaterializationPayload::tombstone`). Deriving it through a version
/// instead would drop `deleted` -- a version names content, not an
/// absence -- and route the "tombstone" down the content lanes.
pub fn payload_for(
    record: &yadorilink_replica_domain::file::FileRecord,
) -> crate::local_convergence::types::MaterializationPayload {
    if record.deleted {
        return crate::local_convergence::types::MaterializationPayload::tombstone(record.clone());
    }
    payload_with_meta(record, yadorilink_replica_domain::file::RecordKind::File, None)
}

/// The payload for a path being materialized as a symlink.
///
/// `target` is the link target the write will use -- `None` is the "no
/// target" trigger for `SymlinkMaterializeOutcome::PolicySkipped`. Both
/// the lane choice and the target now come from here rather than from
/// `set_record_kind`/`set_symlink_target` on the row, because the row can
/// move between the dispatch, the write and the proof while the payload
/// cannot.
pub fn symlink_payload_for(
    record: &yadorilink_replica_domain::file::FileRecord,
    target: Option<&[u8]>,
) -> crate::local_convergence::types::MaterializationPayload {
    payload_with_meta(record, yadorilink_replica_domain::file::RecordKind::Symlink, target)
}

pub fn payload_with_meta(
    record: &yadorilink_replica_domain::file::FileRecord,
    record_kind: yadorilink_replica_domain::file::RecordKind,
    symlink_target: Option<&[u8]>,
) -> crate::local_convergence::types::MaterializationPayload {
    crate::local_convergence::types::MaterializationPayload::from_version(
        &record.path,
        yadorilink_replica_domain::file::FileVersion::from_index_row(
            record.blocks.clone(),
            record.size,
            record.mtime_unix_nanos,
            record_kind,
            None,
            symlink_target.map(|t| t.to_vec()),
            Vec::new(),
        ),
    )
}

pub const GROUP: &str = "shared-photos";

// Peers connect directly (the relay was removed). This still binds a
// throwaway listener so it hands back a real, unused address and the
// existing call sites keep their shape; `connect_pair` ignores it and wires
// a direct loopback pair instead.
pub async fn bind_unused_addr() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

pub fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// `len` bytes that compression cannot shrink, derived deterministically
/// from `seed`.
///
/// Chained SHA-256 output has no structure for zstd to exploit, so every
/// compressed form of it is larger than the original -- which is what makes
/// it the right content for any test whose subject is the size of a block
/// *on the wire*. A responder always tries to compress, so a block of
/// repeated bytes would cross the wire two orders of magnitude smaller than
/// its stored size, and a test that reasoned about the stored size would be
/// reasoning about a number that never appears anywhere.
///
/// Deterministic rather than random on purpose: a failing run has to be
/// reproducible, which a real RNG would not make it.
pub fn incompressible_bytes(seed: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut block = sha256_bytes(seed.as_bytes());
    while out.len() < len {
        out.extend_from_slice(&block);
        block = sha256_bytes(&block);
    }
    out.truncate(len);
    out
}

pub struct Device {
    pub device_id: String,
    pub root: tempfile::TempDir,
    pub store: Arc<SegmentBlockStore>,
    pub state: Arc<ReplicaCoordinator>,
    // This device's Ed25519 change-signing key. Local edits go through
    // native authoring (`processor()` wires this as the `LocalAuthorKey`), and the
    // peer pins the matching verifying key so it admits the signed deltas.
    pub signing_key: SigningKey,
    // Next `checkpoint_seq` [`Device::publish_pending`] self-signs with --
    // see that method's own doc comment.
    pub next_checkpoint_seq: std::sync::atomic::AtomicU64,
    /// This device's substrate endpoint.
    ///
    /// Real, because a session's transports are required and a session that
    /// exists with transports that can never carry anything is the state this
    /// cutover removed from production. A test whose subject never fetches a
    /// block simply never opens a lane on it — unused and unusable are
    /// different things.
    pub node: Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    /// Where this device's peers can be reached.
    ///
    /// One book per test, not one per process: device ids here are fixed
    /// names ("device-a"), and this binary runs its tests concurrently, so a
    /// shared book would let one test's `device-a` redirect another test's.
    /// A device joins an existing book with [`Device::peer`], which is what
    /// makes a pairing explicit rather than ambient.
    pub book: yadorilink_lane_ports::testing::TestAddressBook,
}

pub struct BlockingActivityProvider {
    pub attempted: std::sync::mpsc::SyncSender<()>,
    pub release: Arc<(Mutex<bool>, Condvar)>,
}

impl BlockWriteActivityProvider for BlockingActivityProvider {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_> {
        self.attempted.send(()).unwrap();
        let (released, wake) = &*self.release;
        let mut released = released.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
        Box::new(())
    }
}

impl Device {
    /// A device in a world of its own.
    pub async fn new(device_id: &str) -> Self {
        Self::in_world(device_id, yadorilink_lane_ports::testing::TestAddressBook::new()).await
    }

    /// A device that can reach, and be reached by, `self`.
    pub async fn peer(&self, device_id: &str) -> Self {
        Self::in_world(device_id, self.book.clone()).await
    }

    /// A substrate endpoint standing in for `device_id`, with no session and
    /// no replica behind it.
    ///
    /// For a test whose subject is what a *requester* does with a
    /// deliberately wrong answer: the test plays the peer itself, taking the
    /// inbound lane and writing the response. Real transport, real framing,
    /// the test's bytes — which is a different thing from a session that
    /// cannot carry anything at all.
    pub async fn fake_peer(
        &self,
        device_id: &str,
    ) -> Arc<yadorilink_lane_ports::testing::TestPeerNode> {
        yadorilink_lane_ports::testing::TestPeerNode::start(device_id, self.book.clone()).await
    }

    pub async fn in_world(
        device_id: &str,
        book: yadorilink_lane_ports::testing::TestAddressBook,
    ) -> Self {
        let node =
            yadorilink_lane_ports::testing::TestPeerNode::start(device_id, book.clone()).await;
        Self::in_world_with_node(device_id, book, node)
    }

    /// [`in_world`], for a caller that has already started this device's
    /// substrate endpoint.
    ///
    /// A deterministic simulation has to: its endpoint must be bound inside
    /// the simulated host, on the simulated carrier, with an identity fixed
    /// before that host started. What it must not do is re-derive the rest
    /// of this setup by hand -- the link row, the root's identity marker and
    /// the startup gate are each load-bearing in ways that fail silently
    /// (see the comments below), and a second copy of them would drift from
    /// this one.
    ///
    /// [`in_world`]: Self::in_world
    pub fn in_world_with_node(
        device_id: &str,
        book: yadorilink_lane_ports::testing::TestAddressBook,
        node: Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    ) -> Self {
        // Deterministic per-id key so the peer can pin the verifying key and a
        // failing run is reproducible.
        let seed: [u8; 32] = sha256_bytes(device_id.as_bytes()).try_into().unwrap();
        let root = tempfile::tempdir().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // Link `GROUP` at this device's root, the same way linking the folder
        // would. A session's sync roots are *derived from* the link table in
        // production (`sync_roots_for_groups` reads `list_links`), and the
        // peer-apply path re-reads that table for every write it makes — so a
        // device holding a root with no matching link row is a state the daemon
        // cannot produce, and one the apply path deliberately refuses to write
        // for. Registering it here keeps the fixture's invariant the same as
        // production's; the tests that care about pause/unlink/policy still
        // drive those explicitly on top.
        state
            .link_repository()
            .add_link(&root.path().canonicalize().unwrap().to_string_lossy(), GROUP)
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        // A linked group also owes a completed startup reconciliation before
        // the peer-apply path will admit anything for it: `wait_group_ready`
        // defers a batch for a live link whose startup never registered a gate,
        // on the grounds that the index may be half-built. The daemon's link
        // manager runs that startup for real; these tests have no link manager,
        // so stand in for it and declare the group's startup finished. Without
        // this, a linked fixture device would defer every incoming batch —
        // which is also why an *unlinked* fixture device was admitted here
        // before: no link means no startup is owed.
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        Device {
            device_id: device_id.to_string(),
            root,
            store: Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap()),
            state,
            node,
            book,
            signing_key: SigningKey::from_bytes(&seed),
            next_checkpoint_seq: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// A `LocalAuthorKey` signing as this device. Recreated on demand — its
    /// authoring state lives in the group's native state in
    /// `ReplicaCoordinator`, not in the emitter, so a fresh instance authors
    /// from the current heads.
    pub fn emitter(&self) -> Arc<LocalAuthorKey> {
        Arc::new(LocalAuthorKey::for_tests(self.device_id.clone(), self.signing_key.clone()))
    }

    pub fn processor(&self) -> LocalChangeProcessor {
        LocalChangeProcessor::new(
            self.state.clone(),
            self.store.clone(),
            self.device_id.clone(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(self.emitter())
    }

    /// A signed-change producer over this device's state/store, for scenarios
    /// that need to inject a specific record as a genuine native commit rather than
    /// via a real on-disk edit (`commit_create` stores the block and emits a
    /// signed Create, the same primitive the local-change producer drives).
    pub fn producer(&self) -> DagProducer {
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> = self.store.clone();
        DagProducer::new(self.state.clone(), store, &self.device_id, self.signing_key.clone())
    }

    /// Canonicalized root path. `LocalChangeProcessor::process_event`
    /// canonicalizes its `root` argument internally (real OS watchers
    /// report fully-resolved paths — see its doc comment), so tests that
    /// hand-construct `FsChangeEvent`s must build paths consistently from
    /// an already-canonical root, exactly as a real watcher's paths would be.
    pub fn root_path(&self) -> std::path::PathBuf {
        self.root.path().canonicalize().unwrap()
    }

    pub fn sync_roots(&self) -> HashMap<String, std::path::PathBuf> {
        HashMap::from([(GROUP.to_string(), self.root_path())])
    }

    /// Publishes every change this device's own native head reaches from
    /// `heads` -- the whole "everything committed since the last publish"
    /// span for [`GROUP`] -- by self-signing one covering checkpoint and
    /// attaching it to this device's own store, mirroring the daemon's real
    /// `flush_pending_checkpoint` minus the coordination-plane round trip.
    /// A local edit (`processor().process_event`/`producer().commit_create`)
    /// is Pending (no authorization evidence) until published; only a
    /// Published change is eligible for `send_change_batch` to pick up over
    /// the real reconcile/heads-announce wire path. Call this after authoring,
    /// before a test waits on the change reaching its peer.
    ///
    /// Walks back from the current heads rather than tracking a `pending`
    /// buffer like `DagProducer::publish_pending` does, since `processor()`
    /// builds a FRESH `LocalChangeProcessor` per call (no persistent
    /// producer instance to track authored hashes on) -- so this instead
    /// re-derives "what's Pending" from native state directly: everything
    /// reachable from the current heads that has no evidence yet.
    pub fn publish_pending(&self) {
        dag_wire_support::publish_pending_native_deltas(
            &self.state,
            &self.signing_key,
            &self.device_id,
        );
    }
}

/// Links `local_path` to [`GROUP`] and takes the group's startup gate through
/// to Ready — the state every live link is in on a real daemon, and therefore
/// the only one a test that expects peer records to apply should set up.
///
/// A daemon never leaves a live link without a gate: `app::run` arms one for
/// every non-orphaned link at boot before any fallible watcher setup, and the
/// `AddLink` control path arms one via `start_link_watch` in the same call that
/// commits the row. Peer apply for a live link with no gate therefore defers —
/// on every path — so a link set
/// up with a bare `add_link` would silently defer every incoming record for the
/// whole test budget instead of exercising what the test means to check.
pub fn link_with_completed_startup(state: &ReplicaCoordinator, local_path: &str) {
    state.link_repository().add_link(local_path, GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        std::path::Path::new(local_path),
        GROUP,
        state,
    )
    .unwrap();
    let generation = state.startup_readiness().begin_group_startup(GROUP);
    state.startup_readiness().mark_group_ready(GROUP, generation);
}

// ---------------------------------------------------------------------
// Standing in for a peer on the block-transfer path.
//
// One block request is one bidirectional stream: the requester opens it,
// writes a length-prefixed `BlockRequestHeader` and finishes its own
// direction; the responder writes a length-prefixed `BlockResponseHeader`
// and then exactly the number of raw body bytes that header declared,
// followed by FIN. Nothing correlates a request to its answer except the
// stream they share, and nothing is chunked.
//
// The helpers below are that exchange, from either side, so a test that
// stands in for a peer says *what it wants to answer* rather than
// re-deriving the framing. Everything that a real responder can say is
// expressible through them; so is everything a hostile one can, which is
// the point -- the tampering the security tests do must be visible as a
// deliberate choice at the call site, not buried in hand-rolled framing
// that could accidentally drift from the wire.
// ---------------------------------------------------------------------

/// One answer to one block request, in the shape a responder puts it on the
/// wire.
///
/// [`BlockAnswer::Found`] builds a self-consistent header from the request
/// it is answering: the declared `size` is the body's real length and the
/// `hash` is the requested one, echoed back. [`BlockAnswer::FoundExactly`]
/// leaves all four fields to the caller, for the tests whose whole subject
/// is a responder whose header and body disagree -- with each other, with
/// the request, or with any legal block size.
#[derive(Clone, Debug)]
pub enum BlockAnswer {
    Found { body: Vec<u8>, compression: i32 },
    FoundExactly { size: u64, hash: Vec<u8>, compression: i32, body: Vec<u8> },
    DontHave,
    Busy { retry_after_ms: u32, queue_depth: u32 },
    Rejected { reason: String },
}

impl BlockAnswer {
    /// The ordinary `Found`: these exact bytes, uncompressed. What a
    /// responder that simply holds the block sends, and what all but a
    /// handful of tests want.
    pub fn found(body: impl Into<Vec<u8>>) -> Self {
        BlockAnswer::Found { body: body.into(), compression: proto::Compression::None as i32 }
    }

    /// The response header and the body bytes that follow it. The body is
    /// empty for every outcome but `Found`, which is what makes each of
    /// them end the stream the same way.
    pub fn into_wire(
        self,
        request: &proto::BlockRequestHeader,
    ) -> (proto::BlockResponseHeader, Vec<u8>) {
        let outcome = match self {
            BlockAnswer::Found { body, compression } => {
                let found = proto::BlockFound {
                    size: body.len() as u64,
                    hash: request.block_hash.clone(),
                    compression,
                };
                return (
                    proto::BlockResponseHeader { outcome: Some(BlockOutcome::Found(found)) },
                    body,
                );
            }
            BlockAnswer::FoundExactly { size, hash, compression, body } => {
                let found = proto::BlockFound { size, hash, compression };
                return (
                    proto::BlockResponseHeader { outcome: Some(BlockOutcome::Found(found)) },
                    body,
                );
            }
            BlockAnswer::DontHave => BlockOutcome::DontHave(true),
            BlockAnswer::Busy { retry_after_ms, queue_depth } => {
                BlockOutcome::Busy(proto::BlockBusy { retry_after_ms, queue_depth })
            }
            BlockAnswer::Rejected { reason } => {
                BlockOutcome::Rejected(proto::BlockRejected { reason })
            }
        };
        (proto::BlockResponseHeader { outcome: Some(outcome) }, Vec::new())
    }
}

/// Writes `answer` onto `stream`: the response header, then the body bytes
/// it declared, then the FIN that ends this side of the exchange.
pub async fn answer_block_request(
    stream: &mut dyn yadorilink_peer_session::ports::PeerBlockStream,
    request: &proto::BlockRequestHeader,
    answer: BlockAnswer,
) {
    let (header, body) = answer.into_wire(request);
    stream.send_message(&header.encode_to_vec()).await.expect("the response header must go out");
    stream.send_body(&body).await.expect("the response body must go out");
}

/// Plays the peer for the next `count` block requests that arrive on
/// `node`'s block lane, answering each with whatever `answer` returns.
///
/// For a test whose subject is what a *requester* does with a deliberately
/// wrong answer. Same real
/// transport the session under test uses; only the bytes are the test's.
pub async fn serve_block_requests_on_lane(
    node: &Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    count: usize,
    mut answer: impl FnMut(usize, &proto::BlockRequestHeader) -> BlockAnswer,
) -> Vec<proto::BlockRequestHeader> {
    let mut served = Vec::with_capacity(count);
    for index in 0..count {
        let (_group, stream) =
            node.accept_unclaimed_lane().await.expect("the endpoint closed before a block request");
        let mut stream = yadorilink_lane_ports::LaneBlockStream::new(stream);
        let header = yadorilink_peer_session::ports::PeerBlockStream::recv_message(
            &mut stream,
            MAX_BLOCK_STREAM_HEADER_BYTES,
        )
        .await
        .expect("the block stream ended before its request header");
        let request = proto::BlockRequestHeader::decode(header.as_slice())
            .expect("a block request header must decode");
        let reply = answer(index, &request);
        answer_block_request(&mut stream, &request, reply).await;
        served.push(request);
    }
    served
}

/// Opens a block stream to `target_device_id`'s session over `requester`'s
/// own substrate block lane, and sends one request header on it, without
/// waiting for the answer.
///
/// A block request reaches a session no other way (see
/// `PeerSyncSession::serve_block_stream`'s own doc comment), so a test
/// playing the requester
/// needs its own substrate identity to dial in with -- `Device::fake_peer`
/// gives it exactly that, real transport and real framing, the same way a
/// real peer would reach the session under test.
///
/// For a test that needs a request to be genuinely *in flight* while it
/// does something else -- revoking the responder's authorization, holding
/// its dispatch slot, or issuing a second concurrent request whose outcome
/// depends on the first still being unfinished. Read the answer with
/// [`read_block_response`] when the test is ready for it.
pub async fn begin_block_request_in_group(
    requester: &Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    target_device_id: &str,
    group_id: &str,
    file_path: &str,
    hash: &[u8],
) -> Box<dyn yadorilink_peer_session::ports::PeerBlockStream> {
    let mut stream = requester
        .transports_for(target_device_id)
        .open(group_id)
        .await
        .expect("a block stream must open");
    let header = proto::BlockRequestHeader {
        folder_group_id: group_id.to_string(),
        file_path: file_path.to_string(),
        block_hash: hash.to_vec(),
    };
    stream.send_message(&header.encode_to_vec()).await.expect("the request header must go out");
    // Nothing else is ever sent on this direction; saying so is what lets
    // the responder stop reading rather than infer it.
    stream.finish_send();
    stream
}

/// [`begin_block_request_in_group`] for the group these tests share.
pub async fn begin_block_request(
    requester: &Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    target_device_id: &str,
    file_path: &str,
    hash: &[u8],
) -> Box<dyn yadorilink_peer_session::ports::PeerBlockStream> {
    begin_block_request_in_group(requester, target_device_id, GROUP, file_path, hash).await
}

/// Reads one whole block response off `stream`: its header, then exactly
/// the body bytes that header declared.
///
/// The body comes back raw -- before any decompression -- because the tests
/// that inspect a response's wire form need exactly that, and the ones that
/// do not simply ignore it. A non-`Found` outcome has no body at all, which
/// reads as an empty `Vec`.
pub async fn read_block_response(
    stream: &mut Box<dyn yadorilink_peer_session::ports::PeerBlockStream>,
) -> (proto::BlockResponseHeader, Vec<u8>) {
    let header = stream
        .recv_message(MAX_BLOCK_STREAM_HEADER_BYTES)
        .await
        .expect("the block stream ended before its response header");
    let response = proto::BlockResponseHeader::decode(header.as_slice())
        .expect("a block response header must decode");
    let size = match &response.outcome {
        Some(BlockOutcome::Found(found)) => found.size as usize,
        _ => 0,
    };
    let body = stream.recv_body(size).await.expect("the block stream ended before its body");
    (response, body)
}

/// One whole block request/response exchange against `target_device_id`'s
/// session, dialled from `requester`'s own substrate node: request out,
/// answer and body back.
pub async fn request_block_in_group(
    requester: &Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    target_device_id: &str,
    group_id: &str,
    file_path: &str,
    hash: &[u8],
) -> (proto::BlockResponseHeader, Vec<u8>) {
    let mut stream =
        begin_block_request_in_group(requester, target_device_id, group_id, file_path, hash).await;
    read_block_response(&mut stream).await
}

/// [`request_block_in_group`] for the group these tests share.
pub async fn request_block(
    requester: &Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    target_device_id: &str,
    file_path: &str,
    hash: &[u8],
) -> (proto::BlockResponseHeader, Vec<u8>) {
    request_block_in_group(requester, target_device_id, GROUP, file_path, hash).await
}

/// The `Found` outcome of `response`, or a panic naming what arrived
/// instead -- the assertion nearly every served-content test opens with.
pub fn expect_found(response: &proto::BlockResponseHeader) -> &proto::BlockFound {
    match &response.outcome {
        Some(BlockOutcome::Found(found)) => found,
        other => panic!("expected a Found block response, got {other:?}"),
    }
}

pub fn spawn_session(device: &Device, peer_device_id: &str) -> Arc<TestPeerRuntime> {
    spawn_session_with_groups(device, peer_device_id, vec![GROUP.to_string()])
}

/// `yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()` wires the deny-by-default provider
/// (mirroring the daemon-facing `PeerSyncSessionDeps::denied()`),
/// which makes every real-mutation call (`materialize`, `hydrate_file_with_
/// timeout`, ...) fail fast with "no live root-commit authority" -- correct
/// for a caller that never established a link, wrong for a test standing in
/// for the daemon's real per-link `RootLease` (installed by
/// `yadorilink-daemon`'s `DaemonState` once `start_link_watch` acquires the
/// link's `SyncRootLock`). The crate-internal equivalent
/// (`AlwaysValidRootCommitAuthorityProvider` in `peer_session.rs`) is not
/// part of the crate's public surface, so this integration test binary
/// needs its own -- mirrors `tests/dag_wire_support/mod.rs`'s identically
/// named/shaped provider, duplicated rather than shared because the two are
/// separate integration test binaries.
pub struct AlwaysValidRootCommitAuthorityProvider {
    pub lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
}

impl AlwaysValidRootCommitAuthorityProvider {
    pub fn shared() -> Arc<dyn RootCommitAuthorityProvider> {
        Arc::new(Self {
            lease: Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        })
    }
}

impl RootCommitAuthorityProvider for AlwaysValidRootCommitAuthorityProvider {
    fn root_lease_for(
        &self,
        _group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        Some(self.lease.clone())
    }
}

/// The three ports the convergence executor takes beside its session.
pub struct ExecutorPorts {
    pub root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
    pub pending_local_change_flush: Arc<dyn PendingLocalChangeFlush>,
    pub block_write_activity_provider: Arc<dyn BlockWriteActivityProvider>,
}

impl ExecutorPorts {
    /// No live root-commit authority (every real mutation fails closed), no
    /// pending local change to flush, no write-activity guard.
    pub fn denied() -> Self {
        Self {
            root_commit_authority_provider: Arc::new(DeniedRootCommitAuthority),
            pending_local_change_flush: Arc::new(SettledPendingLocalChangeFlush),
            block_write_activity_provider: Arc::new(NoWriteActivity),
        }
    }

    /// [`Self::denied`], with a root-commit authority that always grants a
    /// lease so a real mutation path can run.
    pub fn permissive() -> Self {
        Self {
            root_commit_authority_provider: AlwaysValidRootCommitAuthorityProvider::shared(),
            ..Self::denied()
        }
    }
}

struct DeniedRootCommitAuthority;

impl RootCommitAuthorityProvider for DeniedRootCommitAuthority {
    fn root_lease_for(
        &self,
        _group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        None
    }
}

struct SettledPendingLocalChangeFlush;

impl PendingLocalChangeFlush for SettledPendingLocalChangeFlush {
    fn flush_pending_local_change<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = PendingLocalFlushOutcome> + Send + 'a>>
    {
        Box::pin(async { PendingLocalFlushOutcome::Settled })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = PendingLocalFlushOutcome> + Send + 'a>>
    {
        Box::pin(async { PendingLocalFlushOutcome::Settled })
    }
}

struct NoWriteActivity;

impl BlockWriteActivityProvider for NoWriteActivity {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }
}

pub fn spawn_session_with_groups(
    device: &Device,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
) -> Arc<TestPeerRuntime> {
    spawn_session_configured(device, peer_device_id, shared_group_ids)
}

/// Fallback poll interval for `spawn_test_convergence_driver` when the wake
/// notification is missed (mirrors the production engine's own event+fallback
/// `tokio::select!` shape in `convergence/engine.rs`).
pub const TEST_CONVERGENCE_FALLBACK: Duration = Duration::from_millis(100);

/// The production daemon's `ConvergenceEngine` is the only thing that
/// turns an admitted native delta into on-disk content:
/// peer-session delivery only admits the delta and arms a
/// projection obligation. This harness's sessions have no daemon and
/// thus no engine, so any test that asserts on disk content (not just native
/// admission) needs this driver running, or it will hang until its own
/// timeout regardless of how correct the sync logic is. Deliberately polls
/// `reconcile_paths_directly` for whatever native state currently shows as
/// admitted-but-unapplied, rather than re-deriving the engine's own
/// claim/obligation logic — this harness only needs *some* driver of
/// materialization, not a second implementation of the real scheduler.
/// `reconcile_local_materialization_audit` alone is NOT enough for this:
/// ordinary projection now runs exclusively through
/// `projection_obligations` + the daemon's Convergence Engine, neither of
/// which this session-only harness has, so the periodic audit's remaining
/// responsibilities (conflict-copy retirement, repair candidates) alone
/// would never materialize a fresh admission here.
#[allow(
    clippy::excessive_nesting,
    reason = "test-harness stand-in for the daemon's ConvergenceEngine: the spawned task's \
              loop, per-group sweep, unapplied-change/op path collection and the \
              Hydrating-path exclusion all live in one closure that owns the session's Weak \
              upgrade and must drop it before awaiting the wake. Splitting a level out would \
              move that upgrade/drop lifetime out of sight of the select! it guards."
)]
pub fn spawn_test_convergence_driver(
    session: &Arc<TestPeerRuntime>,
    state: Arc<ReplicaCoordinator>,
    group_ids: Vec<String>,
) {
    let weak_session = Arc::downgrade(session);

    tokio::spawn(async move {
        loop {
            let Some(session) = weak_session.upgrade() else {
                return;
            };

            for group_id in &group_ids {
                if let Ok(touched) =
                    state.database().read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                        conn.prepare("SELECT DISTINCT path FROM native_heads WHERE group_id = ?1")?
                            .query_map([group_id], |row| row.get::<_, String>(0))?
                            .collect::<Result<std::collections::BTreeSet<_>, _>>()
                            .map_err(Into::into)
                    })
                {
                    let mut paths = touched;
                    // Excludes any path a real, in-flight fetch is
                    // currently hydrating: a handful of tests manually
                    // orchestrate a precise race window against ONE
                    // path's materialization state while a real
                    // `hydrate_file` call is in progress (e.g.
                    // `hydrate_file_detects_a_superseding_authoring_
                    // change_mid_fetch`/`..._a_concurrent_disk_edit_mid_
                    // fetch`), and this driver's own unconditional sweep
                    // landing on the SAME path mid-fetch raced those
                    // tests into real, reproducible failures -- this
                    // driver has no business touching a path something
                    // else is already actively fetching.
                    paths.retain(|path| {
                        !matches!(
                            state
                                .materialization_state_repository()
                                .get_materialization_state(group_id, path),
                            Ok(Some(
                                yadorilink_replica_domain::session_state::MaterializationState::Hydrating
                            ))
                        )
                    });
                    if !paths.is_empty() {
                        let _ = session
                            .convergence
                            .reconcile_paths_directly(&session.driver(), group_id, paths)
                            .await;
                    }
                }
                if let Err(error) = session
                    .convergence
                    .clone()
                    .reconcile_local_materialization_audit(&session.driver(), group_id)
                    .await
                {
                    tracing::debug!(
                        %error,
                        %group_id,
                        "test convergence driver deferred materialization"
                    );
                }
            }

            // Drop the strong ref before waiting so the session can still be
            // torn down while this loop sleeps between passes.
            drop(session);

            tokio::select! {
                _ = state.materialization_wake().materialization_wake_notified() => {}
                _ = tokio::time::sleep(TEST_CONVERGENCE_FALLBACK) => {}
            }
        }
    });
}

/// One-shot sibling of [`spawn_test_convergence_driver`] for the many call
/// sites in this file that drive materialization inline (no background
/// loop) rather than via that spawned driver -- same reasoning, same fix:
/// `reconcile_local_materialization_audit` alone no longer performs
/// ordinary reprojection, so a caller expecting a fresh admission to
/// materialize after ONE call must
/// also drive `reconcile_paths_directly` for whatever native state shows as
/// admitted-but-unapplied first. Propagates the audit call's own error
/// (matching every existing call site's `.unwrap()`); the reconcile step
/// is best-effort, exactly like `spawn_test_convergence_driver`'s.
pub async fn drive_materialization_for_test(
    session: &Arc<TestPeerRuntime>,
    state: &Arc<ReplicaCoordinator>,
    group_id: &str,
) -> Result<bool, yadorilink_peer_session::PeerSessionError> {
    let _ = state;
    session
        .convergence
        .clone()
        .reconcile_local_materialization_audit(&session.driver(), group_id)
        .await
}

/// Sibling of [`drive_materialization_for_test`] for the handful of modules
/// that construct their session via `peer_session::PeerSyncSession`
/// directly (bypassing the public facade re-export this file's top-level
/// `use` brings in) rather than through one of this file's own
/// `spawn_session*` helpers -- a genuinely different Rust type from the
/// facade's `PeerSyncSession`, not just a differently-spelled import of the
/// same one, so it needs its own overload.
pub async fn drive_materialization_for_test_impl(
    session: &Arc<TestPeerRuntime>,
    state: &Arc<ReplicaCoordinator>,
    group_id: &str,
) -> Result<bool, yadorilink_peer_session::PeerSessionError> {
    let _ = state;
    session
        .convergence
        .clone()
        .reconcile_local_materialization_audit(&session.driver(), group_id)
        .await
}

/// Shared spawn seam.
pub fn spawn_session_configured(
    device: &Device,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
) -> Arc<TestPeerRuntime> {
    spawn_session_configured_ex(
        device,
        peer_device_id,
        shared_group_ids,
        true,
        Some(AlwaysValidRootCommitAuthorityProvider::shared()),
    )
}

/// Like `spawn_session_configured`, but skips installing the test-only
/// convergence driver: a hand-written fake responder in a test that answers
/// exactly one block request (to model a specific corrupt/mismatched/bomb
/// answer and assert on the resulting error) can otherwise have that single
/// answer consumed by the driver's own legitimate background repair fetch
/// for the same placeholder, racing the test's own explicit
/// `hydrate_file_with_timeout` call for it. Use this for any test whose
/// subject is hydration's own request/response handling (timeout, corrupt or
/// mismatched bytes, a header bound to the wrong block) rather than
/// end-to-end disk convergence.
pub fn spawn_session_without_convergence_driver(
    device: &Device,
    peer_device_id: &str,
) -> Arc<TestPeerRuntime> {
    spawn_session_configured_ex(device, peer_device_id, vec![GROUP.to_string()], false, None)
}

/// Like `spawn_session_without_convergence_driver`, but wires a permissive
/// `AlwaysValidRootCommitAuthorityProvider` instead of `yadorilink_peer_session::peer_session::PeerSyncSessionDeps::
/// standalone()`'s deny-by-default one, so `hydrate_file_with_timeout` (and
/// any other real mutation path) can actually attempt its fetch instead of
/// failing closed before ever sending a block request -- for a test whose
/// fake responder depends on that request actually arriving.
pub fn spawn_session_without_convergence_driver_with_root_authority(
    device: &Device,
    peer_device_id: &str,
) -> Arc<TestPeerRuntime> {
    spawn_session_configured_ex(
        device,
        peer_device_id,
        vec![GROUP.to_string()],
        false,
        Some(AlwaysValidRootCommitAuthorityProvider::shared()),
    )
}

pub fn spawn_session_with_block_serve_engine(
    device: &Device,
    peer_device_id: &str,
    block_serve_engine: Arc<yadorilink_peer_session::block_serve::BlockServeEngine>,
) -> Arc<TestPeerRuntime> {
    let peer_transports = device.node.transports_for(peer_device_id);
    let transports = yadorilink_peer_session::ports::SessionTransports {
        blocks: peer_transports.clone(),
        service: peer_transports.clone(),
    };
    let deps = PeerSyncSessionDeps {
        block_serve_engine: Some(block_serve_engine),
        ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
    };
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &device.state,
        device.store.clone(),
    );
    let session = PeerSyncSession::over_substrate(
        device.device_id.clone(),
        peer_device_id.to_owned(),
        device.state.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        device.store.clone(),
        vec![GROUP.to_owned()],
        transports,
        deps,
    );
    device.node.serve_with(peer_device_id, session.clone());
    let runtime = runtime_for(device, session.clone(), &ExecutorPorts::permissive());
    spawn_test_convergence_driver(&runtime, device.state.clone(), vec![GROUP.to_owned()]);
    runtime
}

/// Like [`spawn_session`], but with this session's [`RateLimiters`] wired
/// at construction.
///
/// Wired at construction and not with `set_rate_limiters` afterwards,
/// because `set_rate_limiters` is one of the dependency setters that
/// `assert_not_started` guards: it panics with "PeerSyncSession
/// dependencies are immutable after run() starts" the moment `run()` has
/// begun. `spawn_session` spawns `run()` before it returns, so calling
/// the setter on its result is a race against the scheduler that a busy
/// machine loses -- observed, as exactly that panic. `PeerSyncSessionDeps`
/// carries the field, so there is no reason to race it.
pub fn spawn_session_with_rate_limiters(
    device: &Device,
    peer_device_id: &str,
    rate_limiters: Arc<RateLimiters>,
) -> Arc<TestPeerRuntime> {
    let peer_transports = device.node.transports_for(peer_device_id);
    let transports = yadorilink_peer_session::ports::SessionTransports {
        blocks: peer_transports.clone(),
        service: peer_transports.clone(),
    };
    let deps = PeerSyncSessionDeps {
        rate_limiters,
        ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
    };
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &device.state,
        device.store.clone(),
    );
    let session = PeerSyncSession::over_substrate(
        device.device_id.clone(),
        peer_device_id.to_owned(),
        device.state.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        device.store.clone(),
        vec![GROUP.to_owned()],
        transports,
        deps,
    );
    device.node.serve_with(peer_device_id, session.clone());
    session.set_block_serve_engine(yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        1_000,
    ));
    let runtime = runtime_for(device, session.clone(), &ExecutorPorts::permissive());
    spawn_test_convergence_driver(&runtime, device.state.clone(), vec![GROUP.to_owned()]);
    runtime
}

/// Shared spawn seam. `change_authenticator` defaults to
/// `DerivedKeyAuthenticator` at every call site above except
/// `spawn_session_with_authenticator`, which lets a test wire in a
/// different one at construction (this field is no longer settable after
/// the fact -- see `PeerSyncSessionDeps`'s doc comment in
/// `yadorilink_peer_session::peer_session`).
#[allow(clippy::too_many_arguments)]
pub fn spawn_session_configured_ex(
    device: &Device,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
    install_convergence_driver: bool,
    root_commit_authority_provider: Option<Arc<dyn RootCommitAuthorityProvider>>,
) -> Arc<TestPeerRuntime> {
    let convergence_groups = shared_group_ids.clone();
    let convergence_state = device.state.clone();

    let deps = PeerSyncSessionDeps::standalone();
    let mut ports = ExecutorPorts::denied();
    if let Some(provider) = root_commit_authority_provider {
        ports.root_commit_authority_provider = provider;
    }

    // The transports, from this device's own substrate endpoint — the same
    // adapters production uses, over a real iroh connection this fixture
    // dials on demand. Required at construction now (`SessionTransports`,
    // see its own doc comment) rather than attached after: a fixture that
    // could produce a session without them would be a fixture that no
    // longer checks the invariant the daemon is being held to.
    let peer_transports = device.node.transports_for(peer_device_id);
    let transports = yadorilink_peer_session::ports::SessionTransports {
        blocks: peer_transports.clone(),
        service: peer_transports.clone(),
    };

    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &device.state,
        device.store.clone(),
    );
    let session = PeerSyncSession::over_substrate(
        device.device_id.clone(),
        peer_device_id.to_string(),
        device.state.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        device.store.clone(),
        shared_group_ids,
        transports,
        deps,
    );
    // Block serving is no longer optional: every real (`DaemonState`-backed)
    // session always has an engine installed (see
    // `PeerSyncSession::set_block_serve_engine`'s own doc comment), so this
    // harness's own sessions get one too rather than falling into
    // `handle_block_request`'s defensive "no engine installed" fail-closed
    // path on any test that happens to exercise a block request. Generous,
    // effectively unlimited budgets -- these tests aren't about credit
    // exhaustion unless they say so.
    session.set_block_serve_engine(yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        1_000,
    ));
    // The peer is served from here too, so a block or service stream it opens
    // reaches the session that owns it. `serve_with` is a no-op until the
    // peer has published an address, which is why the pairing helpers build
    // both devices before either session.
    device.node.serve_with(peer_device_id, session.clone());

    let runtime = runtime_for(device, session.clone(), &ports);
    if install_convergence_driver {
        spawn_test_convergence_driver(&runtime, convergence_state, convergence_groups);
    }
    runtime
}

/// Puts `record` into `device`'s index as an unhydrated placeholder — the
/// state a device is in once it has adopted a peer's delta but before it has
/// any of the content.
///
/// The tests below are about the block lane: what crosses it, how fast, and
/// whether the bytes survive the round trip. How the *delta* reached this
/// device is a separate mechanism with its own coverage.
pub fn adopt_as_placeholder(device: &Device, record: &yadorilink_replica_domain::file::FileRecord) {
    device
        .state
        .file_index_repository()
        .upsert_file(GROUP, record, &RootCommitPermit::for_tests())
        .unwrap();
    device
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            &record.path,
            MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
}

pub fn expect_file_changed(
    outcome: LocalChangeOutcome,
) -> yadorilink_replica_domain::file::FileRecord {
    match outcome {
        LocalChangeOutcome::FileChanged(record) => record,
        other => panic!("expected FileChanged, got {other:?}"),
    }
}

/// Polls `cond` until it holds, panicking with the *call site* and the
/// budget once `timeout` elapses.
///
/// The location is the point. This helper is awaited from well over a
/// hundred places in this file, and the old bare "condition never became
/// true within timeout" panic named none of them -- a failing run gave a
/// reader a test name and nothing else, so telling a genuine convergence
/// regression apart from an unrelated wait in the same test meant
/// re-deriving the call graph by hand every time. `#[track_caller]` on a
/// plain function returning a future records the caller correctly;
/// putting it on an `async fn` would record wherever the future happened
/// to be polled instead.
#[track_caller]
pub fn wait_until<F: Fn() -> bool>(
    cond: F,
    timeout: Duration,
) -> impl std::future::Future<Output = ()> {
    let caller = std::panic::Location::caller();
    async move {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if cond() {
                return;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("condition never became true within {timeout:?}, awaited at {caller}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// How long a convergence wait tolerates *no* forward progress before it
/// declares a stall.
///
/// Sized against the slowest per-item step this suite actually observes,
/// not against a whole test's runtime. These tests are required to run
/// with `TMPDIR` on real, non-tmpfs storage (tmpfs timestamp granularity
/// is too coarse for the mtime-sensitive tests elsewhere in the
/// workspace), so every file materialization pays real `fsync`s: three
/// or four of them, for the block store's put, `reconstruct_file`'s own,
/// and the parent directory. On a rotational disk shared with concurrent
/// build and test I/O, one `fsync` measures 100-960ms (median ~450ms)
/// against ~0.02ms on tmpfs -- four orders of magnitude, which no single
/// flat deadline can span. The worst gap between two consecutive files
/// landing, measured across a 150-file sync on such a disk, was ~5.6s.
/// 30s is more than five times that, so a genuinely wedged convergence
/// is still reported promptly while a merely slow disk never trips it.
pub const NO_PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Sets `device` up the way a peer that has adopted a file but not its
/// content is set up: an index row for `path` referencing one block whose
/// hash is `content`'s, a `Remote` materialization state, and a
/// placeholder on disk -- with nothing at all in the block store. A
/// `hydrate_file_with_timeout` call against it turns into exactly one block
/// request for the returned hash.
///
/// Factored out because the three "the responder answered, and the answer
/// must not be believed" tests below need the identical fixture and differ
/// only in what the responder says.
pub fn seed_placeholder_awaiting_hydration(device: &Device, path: &str, content: &[u8]) -> Vec<u8> {
    let hash = sha256_bytes(content);
    device
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: path.into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: hash.clone(),
                    offset: 0,
                    size: content.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            path,
            MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    hash
}

// --- Characterization tests for `handle_block_request` /
// `handle_block_request_with_credit` invariant ordering. These pin the
// exact examination-permit-drop and dispatch/credit-guard drop ORDERING,
// so a future mechanical
// extraction/refactor that reorders any of them fails a fast, deterministic
// test instead of only ever showing up as an intermittent cross-peer
// fairness/DoS regression under load.

/// Shared setup for the four `examination_permit_is_released_before_reply_*`
/// tests below: stores `data` in `device`'s block store, records the
/// group's provenance for its hash, and upserts a one-block `FileRecord` at
/// `path` referencing it -- the same pattern several tests above already
/// inline individually, factored out here since these tests need it for
/// more than one distinct hash each.
pub fn seed_referenced_block(device: &Device, path: &str, data: &[u8]) -> Vec<u8> {
    // `commit_create` + `publish_pending` (not a raw `store.put` +
    // `upsert_file`): block-serving authorization now requires a real
    // PUBLISHED delta backing the served path -- `commit_create` also calls `record_group_block_
    // provenance` itself, matching what this helper used to do explicitly.
    let record = device.producer().commit_create(GROUP, path, data, 0);
    device.publish_pending();
    record.blocks[0].hash.clone()
}

/// Like `seed_referenced_block`, but deliberately withholds
/// `record_group_block_provenance` -- the block is referenced by a live
/// `FileRecord` (so `block_request_is_referenced` passes) but has no
/// verified group provenance (so `group_has_block_provenance` fails),
/// isolating that specific rejection path from the "not referenced at all"
/// one `seed_referenced_block`'s absence would otherwise also trigger.
pub fn seed_referenced_block_without_provenance(
    device: &Device,
    path: &str,
    data: &[u8],
) -> Vec<u8> {
    // Same PUBLISHED-delta authoring as `seed_referenced_block`, but then
    // strips the provenance row `commit_create` records as a side effect --
    // this helper's whole point is isolating "referenced by a real
    // published delta, but never obtained through this group" from "not
    // referenced at all," so the delta itself must still be genuinely
    // published, only its provenance withheld.
    let record = device.producer().commit_create(GROUP, path, data, 0);
    device.publish_pending();
    let hash = record.blocks[0].hash.clone();
    device
        .state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM group_block_provenance WHERE group_id = ?1 AND block_hash = ?2",
                rusqlite::params![GROUP, hash],
            )?;
            Ok(())
        })
        .unwrap();
    hash
}

/// Bounds a hand-written fake responder task so a future regression (e.g.
/// the request it's waiting for never arriving) fails fast with a
/// descriptive panic instead of hanging the test indefinitely. Aborts the
/// task on timeout so it doesn't linger past the failing assertion.
pub async fn await_responder(responder: tokio::task::JoinHandle<()>) {
    let abort_handle = responder.abort_handle();
    match tokio::time::timeout(Duration::from_secs(5), responder).await {
        Ok(join_result) => join_result.expect("fake responder task panicked"),
        Err(_) => {
            abort_handle.abort();
            panic!("fake responder did not finish within 5s");
        }
    }
}

/// Builds a `BlockServeEngine` with generous dispatch/credit budgets (not
/// what the tests using this helper exercise) but a device-wide
/// examination-admission pool drained down to exactly one free slot --
/// every other slot consumed directly via the engine's own public
/// `try_begin_examination` and held in the returned `Vec` for the whole
/// test. With one slot deliberately left free, a live session backed by
/// this engine can push exactly one block request through examination at a
/// time; a second request sent immediately afterward can only also get
/// examined (rather than denied at the recv loop's own `try_begin_
/// examination` gate -- a `Busy` reply with no handler ever spawned for it)
/// if the first request's `examination_permits` was already dropped. This
/// is the least-invasive way to make `examination_admission`'s internal
/// semaphore state observable from a test without a backdoor into
/// `BlockServeEngine` itself -- its live permit count is deliberately not
/// part of its public API (see `ExaminationPermit`'s own doc comment: "the
/// field is intentionally write-only from this crate's perspective").
pub fn engine_with_one_free_examination_slot() -> (
    Arc<yadorilink_peer_session::block_serve::BlockServeEngine>,
    Vec<yadorilink_peer_session::block_serve::ExaminationPermit>,
) {
    let engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        4,
    );
    let mut held = Vec::new();
    while let Ok(permit) = engine.try_begin_examination() {
        held.push(permit);
    }
    assert!(!held.is_empty(), "sanity: examination capacity must be positive");
    held.pop();
    (engine, held)
}

/// A session and the executor that does its local work -- the fixture's
/// counterpart to production's [`crate::peer_registry::PeerRuntime`].
///
/// Before the executor moved into this crate, `PeerSyncSession` built one
/// for itself and exposed `hydrate_file`, `reconcile_paths_directly` and
/// `reconcile_local_materialization_audit` as thin wrappers that took the
/// path lock and called through. Those wrappers could not follow the
/// executor here: peer-session no longer knows the type. So this holds the
/// pair and re-offers exactly those wrappers, with the same lock
/// acquisition and the same argument order, which is what lets the moved
/// tests keep their call sites unchanged -- the point of this migration is
/// to move test ownership without touching a single assertion.
///
/// `Deref`s to the session, so every method that genuinely still belongs to
/// the session resolves without a wrapper here.
pub struct TestPeerRuntime {
    pub session: Arc<PeerSyncSession>,
    pub convergence: Arc<crate::local_convergence::LocalConvergenceExecutor>,
    /// The same coordinator both halves were built from, held because the
    /// per-path lock the hydration wrappers must take lives on it and the
    /// session's own handle is private.
    pub state: Arc<ReplicaCoordinator>,
    /// The store as the daemon's own state holds it; present when the runtime was built from a
    /// device, which is what lets [`TestPeerRuntime::hydrate_file`] run the PRODUCTION hydration.
    block_store: Option<Arc<dyn yadorilink_local_storage::BlockStore + Send + Sync>>,
    daemon: std::sync::OnceLock<Arc<crate::daemon_state::DaemonState>>,
}

/// What a hydration of one path concluded, as these tests observe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationOutcome {
    /// Content is fully written to disk under this path's name.
    Hydrated,
    /// Every block was fetched, but a filename hazard withheld the physical write.
    Held { reason: String },
}

impl TestPeerRuntime {
    /// A daemon state over the SAME coordinator and store, with this runtime's session registered as
    /// the peer: the production hydration (`hydration::hydrate`) runs against it, so the tests that
    /// used the executor's own second hydration body now exercise the one production implementation.
    fn daemon_state(&self) -> &Arc<crate::daemon_state::DaemonState> {
        self.daemon.get_or_init(|| {
            let store = self
                .block_store
                .clone()
                .expect("hydrate_file needs a runtime built from a device (it carries the store)");
            let state = crate::daemon_state::DaemonState::new(
                self.convergence.local_device_id.clone(),
                self.state.clone(),
                store,
            );
            state.peers.register_session(
                self.driver().peer_device_id().to_string(),
                self.session.clone(),
                self.convergence.clone(),
            );
            state
        })
    }

    /// Obtains and writes one path's content through the convergence executor's PRODUCTION lane
    /// (`materialize`, the Eager path the receive engine drives): the bulk fetch family, whose
    /// block-fetch behaviour (what is re-asked, what is not) differs on purpose from the
    /// interactive one `hydrate_file` runs. `RetryRequired` (content not obtained) is an error.
    pub async fn materialize_via_convergence(
        &self,
        group_id: &str,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<(), yadorilink_peer_session::PeerSessionError> {
        use crate::local_convergence::types::{MaterializationPayload, MaterializeResult};
        use yadorilink_peer_session::PeerSessionError;
        let current = self
            .state
            .current_row_snapshot(group_id, path)?
            .ok_or_else(|| PeerSessionError::NotFound(format!("file {group_id}/{path}")))?;
        let payload = MaterializationPayload::from_current_row(path, current.to_file_version());
        let driver = self.driver();
        let outcome = tokio::time::timeout(
            timeout,
            self.convergence.materialize(
                &driver,
                group_id,
                &payload,
                yadorilink_replica_domain::session_state::MaterializationPolicy::Eager,
                driver.peer_device_id(),
                None,
            ),
        )
        .await;
        match outcome {
            Ok(Ok(MaterializeResult::Settled(_))) => Ok(()),
            Ok(Ok(MaterializeResult::RetryRequired)) | Err(_) => {
                Err(PeerSessionError::HydrationFailed(path.to_string()))
            }
            Ok(Err(error)) => Err(error),
        }
    }

    /// Hydrates one path through the production in-place hydration, with its default ceiling.
    pub async fn hydrate_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<HydrationOutcome, yadorilink_peer_session::PeerSessionError> {
        self.hydrate_file_with_timeout(
            group_id,
            path,
            yadorilink_peer_session::peer_session::DEFAULT_HYDRATION_TIMEOUT,
        )
        .await
    }

    /// [`Self::hydrate_file`] with an absolute ceiling.
    pub async fn hydrate_file_with_timeout(
        &self,
        group_id: &str,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<HydrationOutcome, yadorilink_peer_session::PeerSessionError> {
        use yadorilink_peer_session::PeerSessionError;
        let state = self.daemon_state().clone();
        // No link runtime runs in these fixtures: the same always-valid authority the executor's
        // own ports use stands in for the link's root lease.
        state.install_test_root_commit_authority(group_id);
        match crate::hydration::hydrate_with_timeout(&state, group_id, path, timeout).await {
            Ok(()) => {
                // A path held for a filename hazard is not hydrated, whatever the fetch did.
                match self.state.get_held_state(group_id, path) {
                    Ok(Some(reason)) => Ok(HydrationOutcome::Held { reason: reason.reason }),
                    _ => Ok(HydrationOutcome::Hydrated),
                }
            }
            Err(crate::sync_error::SyncError::NotFound(what)) => {
                Err(PeerSessionError::NotFound(what))
            }
            Err(other) => {
                let _ = other;
                Err(PeerSessionError::HydrationFailed(path.to_string()))
            }
        }
    }
}

impl TestPeerRuntime {
    /// The session as the callback the executor reaches back through for a
    /// block it cannot find on disk.
    pub fn driver(
        &self,
    ) -> Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver> {
        self.session.clone()
    }
}

/// The executor half of a [`TestPeerRuntime`], built from `ports`.
fn runtime_for(
    device: &Device,
    session: Arc<PeerSyncSession>,
    ports: &ExecutorPorts,
) -> Arc<TestPeerRuntime> {
    runtime_build(
        session,
        &device.device_id,
        device.state.clone(),
        device.store.clone(),
        device.sync_roots(),
        ports,
        Some(device.store.clone()),
    )
}

/// A [`TestPeerRuntime`] for a session built by hand, rather than through one
/// of the `spawn_session*` helpers above, whose executor takes
/// [`ExecutorPorts::permissive`]. Use [`runtime_from_parts`] to supply other
/// ports.
pub fn permissive_runtime(
    session: Arc<PeerSyncSession>,
    local_device_id: &str,
    state: Arc<ReplicaCoordinator>,
    store: Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
    sync_roots: HashMap<String, std::path::PathBuf>,
) -> Arc<TestPeerRuntime> {
    runtime_build(
        session,
        local_device_id,
        state,
        store,
        sync_roots,
        &ExecutorPorts::permissive(),
        None,
    )
}

/// [`permissive_runtime`] for a concrete store, which also lets [`TestPeerRuntime::hydrate_file`]
/// run the production hydration over the same store.
pub fn permissive_runtime_with_store<S>(
    session: Arc<PeerSyncSession>,
    local_device_id: &str,
    state: Arc<ReplicaCoordinator>,
    store: Arc<S>,
    sync_roots: HashMap<String, std::path::PathBuf>,
) -> Arc<TestPeerRuntime>
where
    S: yadorilink_peer_session::ports::BlockContentStore
        + yadorilink_local_storage::BlockStore
        + 'static,
{
    runtime_from_parts(
        session,
        local_device_id,
        state,
        store,
        sync_roots,
        &ExecutorPorts::permissive(),
    )
}

/// [`permissive_runtime`], for a caller that has its own `ports`.
pub fn runtime_from_parts<S>(
    session: Arc<PeerSyncSession>,
    local_device_id: &str,
    state: Arc<ReplicaCoordinator>,
    store: Arc<S>,
    sync_roots: HashMap<String, std::path::PathBuf>,
    ports: &ExecutorPorts,
) -> Arc<TestPeerRuntime>
where
    S: yadorilink_peer_session::ports::BlockContentStore
        + yadorilink_local_storage::BlockStore
        + 'static,
{
    runtime_build(session, local_device_id, state, store.clone(), sync_roots, ports, Some(store))
}

fn runtime_build(
    session: Arc<PeerSyncSession>,
    local_device_id: &str,
    state: Arc<ReplicaCoordinator>,
    store: Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
    sync_roots: HashMap<String, std::path::PathBuf>,
    ports: &ExecutorPorts,
    block_store: Option<Arc<dyn yadorilink_local_storage::BlockStore + Send + Sync>>,
) -> Arc<TestPeerRuntime> {
    Arc::new(TestPeerRuntime {
        convergence: crate::local_convergence::LocalConvergenceExecutor::new(
            state.clone(),
            local_device_id.to_string(),
            ports.root_commit_authority_provider.clone(),
            ports.pending_local_change_flush.clone(),
            sync_roots,
            store,
            ports.block_write_activity_provider.clone(),
            crate::local_convergence::HeadroomPolicy::disabled(),
        ),
        session,
        state,
        block_store,
        daemon: std::sync::OnceLock::new(),
    })
}
