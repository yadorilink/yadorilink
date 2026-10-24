//! Orchestrates Track Send's four operations (`send`, `inbox`, `receive`,
//! and serving an inbound connection) over this device's iroh endpoint --
//! the same device identity, NAT traversal and relays the sync protocol
//! uses, reached only through Track Send's own ALPN
//! (`SubstrateNode::connect_track_send` and the inbound connections the
//! node's Track Send handler admits), never through any sync-protocol
//! session, lane or port.
//!
//! Device addressing is a caller-supplied [`DeviceDirectory`] rather than
//! anything this crate resolves itself -- see that trait's own doc comment
//! for why (this crate must not depend on `yadorilink-daemon`, which is
//! where the real netmap-derived directory lives).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_ipc_proto::send::{
    chunk_stream_message, send_envelope, ChunkHeader, ChunkPullRejected, ChunkPullRequest,
    ChunkStreamMessage, SendEnvelope, SendFileEntry, SendManifest, SendManifestAck, TransferDone,
};
use yadorilink_local_storage::{
    hash_block_bytes, reconstruct_file, BlockContentStore, SegmentBlockStore,
};
use yadorilink_sync_substrate::{
    PeerAddress, PeerId, SubstrateNode, TrackSendConnection, TrackSendReader, TrackSendWriter,
};

use crate::error::{Result, SendError, PULL_REASON_CANCELED, PULL_REASON_NOT_ACCEPTED};
use crate::manifest::{build_outbound_manifest, chunk_byte_size};
use crate::store::{InboundStatus, OutboundStatus, OutboundTransfer, SendStore};
use crate::wire::{read_message, write_message};

/// One same-account device this daemon already knows about, as resolved
/// by a caller-supplied [`DeviceDirectory`] -- the device id, its Ed25519
/// device key (which IS its iroh endpoint id, so the dial accepts an answer
/// from that key only), and where its iroh endpoint was last reported to
/// answer: direct socket addresses and relay URLs. The addresses are hints;
/// iroh adds whatever its own lookup knows.
#[derive(Debug, Clone)]
pub struct ResolvedDevice {
    pub device_id: String,
    pub signing_key: [u8; 32],
    pub direct_addresses: Vec<std::net::SocketAddr>,
    pub relay_urls: Vec<String>,
}

impl ResolvedDevice {
    fn address(&self) -> PeerAddress {
        PeerAddress::new(PeerId::from_bytes(self.signing_key))
            .with_direct(self.direct_addresses.iter().copied())
            .with_relays(self.relay_urls.iter().cloned())
    }
}

/// This daemon's already-known, same-account device list -- reused for
/// labeling an inbound connection's already-authenticated peer
/// (`device_id_for_key`) and for a receiver's own pull-phase dial back to a
/// sender it has already accepted an offer from (`receive_transfer`), never
/// re-derived. See the crate's own module doc comment for why this is a
/// port rather than a direct dependency on `yadorilink-daemon`.
///
/// Deliberately NOT consulted by [`SendService::offer_send`] to decide
/// whether a grant is needed for a given target: `resolve` succeeding only
/// ever means this device has ordinary netmap/sync connectivity to the
/// target, never that sending to it is authorized. See `request_grant`'s
/// own doc comment for why every offer requires a grant regardless of what
/// `resolve` says.
///
/// Cross-account send is out of scope for v1 by construction, not merely
/// unimplemented: the production implementation
/// (`yadorilink-daemon::send_transfer::DaemonDeviceDirectory`) obtains a
/// grant only through the coordination plane's `POST /send/authorization`
/// route, which resolves both the sender and receiver device id against the
/// SAME caller-account bearer token (`isDeviceOwnedByUser`, twice, against
/// one `userId`) -- so there is no `device_query` naming a device outside
/// the caller's own account this route can ever satisfy, independent of
/// whatever `resolve`'s own (separately account-scoped, and
/// cross-account-inclusive) netmap state happens to say. Sending to a
/// device on a different account needs a cross-account permission model
/// that does not exist yet; this trait is deliberately left as the seam a
/// future cross-account-aware `DeviceDirectory` implementation would plug
/// into, once that model does.
///
/// Every Track Send offer -- same-account or not, netmap-visible or not --
/// is gated by exactly ONE primitive: a short-lived, sender+receiver-bound
/// Track Send rendezvous grant (`POST /send/authorization`,
/// `crates/yadorilink-daemon`'s `send_transfer` module), obtained by
/// `request_grant` and enforced on the receiving side by
/// [`SendService::handle_offer`]'s own unconditional `consume_grant` call.
/// Deliberately NOT an extension of ordinary netmap visibility -- see that
/// module's own doc comment for the full design -- and deliberately never
/// skipped merely because `resolve` also happens to know the target: an
/// ordinary netmap/sync relationship establishes connectivity and
/// addressing, never Send authorization.
///
/// The resolved device, plus the grant material [`SendService::offer_send`]
/// must present alongside the manifest offer this grant authorizes -- see
/// `send.proto`'s own `SendEnvelope.grant_id`/`grant_nonce` doc comment for
/// exactly where and how these travel on the wire.
#[derive(Debug, Clone)]
pub struct GrantedDevice {
    pub device: ResolvedDevice,
    pub grant_id: String,
    pub grant_nonce: String,
    /// Unix seconds. The grant, and the Track Send admission it gives
    /// `device`'s key on this device, end then; see the daemon's
    /// `send_transfer` module for who reads it.
    pub expires_at_unix: i64,
}

#[async_trait::async_trait]
pub trait DeviceDirectory: Send + Sync {
    /// Resolves a CLI-supplied device query -- today, an exact device id,
    /// matching the identifier every other device-scoped daemon command
    /// (`remove_device`, `revoke_device`, ...) already takes -- against
    /// this daemon's own device list. Used for a receiver's pull-phase
    /// dial-back to an already-accepted sender (`receive_transfer`) and by
    /// other daemon-side device-query callers -- deliberately NOT consulted
    /// by `offer_send` itself, which always goes through `request_grant`
    /// instead; see this trait's own doc comment.
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice>;

    /// The device id this daemon has pinned for `signing_key`, if any.
    /// Used only to LABEL an inbound offer's already-authenticated sender
    /// for display (`inbox`) -- authorization itself never depends on
    /// this succeeding: the Track Send ALPN's own admission already refused
    /// any key this device has no grant or accepted offer for before a
    /// connection could reach here at all. A production implementation extends this beyond
    /// ordinary netmap-pinned peers to ALSO recognize a key this device
    /// currently has an outstanding, not-yet-consumed Track Send grant
    /// for (see `GrantedDevice`'s own doc comment) -- `handle_offer` relies
    /// on this to name the sender it is about to ask `consume_grant` to
    /// validate.
    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String>;

    /// Called by [`SendService::offer_send`] for EVERY outbound offer,
    /// unconditionally -- requests a Track Send rendezvous grant naming this
    /// exact device pair from the coordination plane, and resolves
    /// `receiver_device_query` to the actual target device as a side effect
    /// of that same request (the grant response carries the receiver's
    /// connect material). This has fully replaced what `resolve` used to be
    /// consulted for inside `offer_send`: `resolve` still exists for other
    /// callers, but no ordinary netmap relationship exempts a target from
    /// needing a grant here. `None` (the default) means this directory has
    /// no grant capability at all -- `offer_send` then fails loudly instead
    /// of falling back to sending ungranted, so every test/fake directory
    /// that models only an ordinary netmap and does not override this
    /// cannot send at all, which is deliberate.
    async fn request_grant(&self, _receiver_device_query: &str) -> Option<GrantedDevice> {
        None
    }

    /// Called by `handle_offer` for EVERY inbound offer, unconditionally --
    /// an offer whose envelope carries an empty `grant_id` is passed
    /// through to this call with empty strings rather than skipped, so an
    /// implementation MUST fail closed for that input exactly like it does
    /// for any other unknown, invalid, or already-consumed grant id (the
    /// default implementation below already does, by always returning
    /// `Err`). There is no "no grant presented" case that bypasses this
    /// call: a connection admitted on the Track Send ALPN never counts as
    /// authorization for an offer on its own. Validates the grant against the coordination plane
    /// and, on success, marks it consumed there before the offer is durably
    /// recorded. `peer_key` is the handshake-authenticated key (the iroh
    /// endpoint id) of the connection that presented this grant.
    ///
    /// An implementation MUST derive the sender identity it reports to the
    /// coordination plane from `peer_key` alone -- via its own
    /// independently-obtained record of which grant belongs to which key
    /// (the same record `device_id_for_key` consults) -- and never from
    /// any claim inside the offer envelope or manifest itself. That is the
    /// entire defense against sender substitution: an attacker can
    /// present any `grant_id` it likes, but can only complete the
    /// handshake as the key it actually holds the private half of.
    ///
    /// `Err` (the default: grants unsupported) refuses the offer before it
    /// is stored -- same fail-closed shape as `resolve` returning `None`.
    async fn consume_grant(
        &self,
        _grant_id: &str,
        _grant_nonce: &str,
        _peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        Err("this directory does not support Track Send grants".to_string())
    }
}

/// One inbox entry -- a decoded, display-ready view over a stored
/// [`crate::store::InboundTransfer`].
#[derive(Debug, Clone)]
pub struct InboxEntry {
    pub transfer_id: String,
    pub sender_device_id: String,
    pub files: Vec<(String, u64)>,
    pub total_size: u64,
    pub offered_at_unix_nanos: i64,
    pub status: &'static str,
    /// A closed code from [`crate::error::failure`] for a transfer that stopped with a reason.
    pub failure: Option<String>,
}

/// One outbound transfer for the sent list -- a decoded, display-ready view over a stored
/// [`crate::store::OutboundTransfer`].
#[derive(Debug, Clone)]
pub struct SentEntry {
    pub transfer_id: String,
    pub target_device_id: String,
    pub files: Vec<(String, u64)>,
    pub total_size: u64,
    pub created_at_unix_nanos: i64,
    /// "offered" (not answered yet), "accepted" (the receiver may pull it), "completed",
    /// "declined" or "canceled".
    pub status: &'static str,
    /// A closed code from [`failure`] when it stopped with a reason worth showing.
    pub failure: Option<String>,
    /// Whether `retry_sent_transfer` is offered for it.
    pub can_retry: bool,
}

/// Which side of a transfer this device is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Sent,
    Received,
}

#[derive(Debug, Clone)]
pub struct SendOfferOutcome {
    pub transfer_id: String,
    pub files_offered: Vec<String>,
    pub total_size: u64,
}

#[derive(Debug, Clone)]
pub struct ReceiveOutcome {
    pub destination_dir: PathBuf,
    pub files_received: Vec<String>,
    pub bytes_received: u64,
}

/// How long one Track Send dial is given. iroh tries every address it has
/// for the peer (direct and relayed) within this one attempt.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on how long a rejection path (`handle_offer`'s grant-check
/// failure, `reject_pull`'s every reason) waits for `send.stopped()` --
/// best-effort confirmation that a peer actually received the rejection
/// message before this device closes the connection out from under it --
/// see `handle_offer`'s own call site comment for why `stopped()` alone is
/// not otherwise bounded. Not correctness-critical: a peer that never
/// unblocks `stopped()` just makes this device wait out the timeout before
/// closing anyway, exactly as if the flush had never been attempted.
const REJECT_ACK_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one chunk write may make no progress before the serve gives up on the receiver. A
/// receiver that stops reading blocks the write through flow control; without a bound the serve
/// (and so a cancel, which is only read between chunks) would last as long as the connection.
const SERVE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Application-level close codes for Track Send connections -- this
/// protocol's own namespace, separate from the sync protocol's, so a peer
/// never has to guess which protocol's table an error came from.
mod close_code {
    pub const DONE: u32 = 0;
    pub const REJECTED: u32 = 1;
    pub const PROTOCOL_ERROR: u32 = 2;
}

/// How many finished (completed, failed or canceled) transfers each list shows; every transfer
/// still going is always listed.
pub const FINISHED_HISTORY_LIMIT: usize = 20;

/// How many finished transfers of each direction are kept at all; older ones are deleted when a
/// transfer finishes. Bounds the history, never what was received or sent.
pub const FINISHED_RETAINED_LIMIT: usize = 100;

/// A block newer than this is never reaped, whatever the transfers on record say: an offer writes
/// its blocks before its transfer is recorded, and a put refreshes the age of a block it finds,
/// so the grace covers that gap (and a sweep racing it).
pub const BLOCK_REAP_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// Removes a receive from the running set however it ends.
struct ActiveReceive<'a> {
    running: &'a std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Notify>>>,
    transfer_id: String,
}

impl Drop for ActiveReceive<'_> {
    fn drop(&mut self) {
        self.running.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.transfer_id);
    }
}

pub struct SendService {
    node: SubstrateNode,
    /// Receives running in this process, by transfer id, each with the
    /// signal that cancels exactly that one.
    running_receives: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Notify>>>,
    /// Counts every cancel of a sent transfer, whether or not it changed anything. A retry notes it
    /// before waiting for its new authorization and gives up if it moved, so a cancel that lands
    /// during the wait is never undone by the retry. A cancel of an unrelated transfer also
    /// stops a pending retry, which asks to be run again: rare, and the safe way round.
    outbound_cancels: std::sync::atomic::AtomicU64,
    /// Held, briefly and never across an await, by a cancel (its count and its write) and by a
    /// retry's final check and reopening, so the two cannot interleave.
    outbound_lifecycle: std::sync::Mutex<()>,
    store: SendStore,
    block_store: SegmentBlockStore,
    directory: Arc<dyn DeviceDirectory>,
    default_inbox_dir: PathBuf,
    /// A deterministic mid-transfer "crash" seam for real crash-recovery
    /// tests -- see [`Self::test_abort_after_n_chunks`]. Always `None` in
    /// production: nothing outside a `test`/`test-support` build can set
    /// it.
    #[cfg(any(test, feature = "test-support"))]
    chunk_abort: std::sync::Mutex<Option<ChunkAbortHook>>,
    /// Test-only: parks a pull being served just before its first chunk; see
    /// [`Self::test_park_next_serve`].
    #[cfg(any(test, feature = "test-support"))]
    serve_gate: std::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    /// How long one chunk write may stall; see [`SERVE_WRITE_TIMEOUT`].
    serve_write_timeout: std::sync::Mutex<Duration>,
    /// Test-only: makes the next chunk write never progress, as a receiver that stopped reading.
    #[cfg(any(test, feature = "test-support"))]
    stall_next_serve_write: std::sync::atomic::AtomicBool,
}

#[cfg(any(test, feature = "test-support"))]
struct ChunkAbortHook {
    remaining: u32,
    notify: Arc<tokio::sync::Notify>,
    /// Never notified by anything -- once `remaining` reaches zero, the
    /// pull loop awaits this and parks there unconditionally, so the exact
    /// instant a caller's `notify.notified()` wakes up, the pulling task is
    /// GUARANTEED to already be parked with no further chunk read able to
    /// start, whatever the runtime's own scheduling latency turns out to
    /// be. This is what makes `test_abort_after_n_chunks` an exact
    /// rendezvous rather than a best-effort race against real network I/O.
    pause: Arc<tokio::sync::Notify>,
}

impl SendService {
    pub fn new(
        node: SubstrateNode,
        store_db_path: impl AsRef<Path>,
        block_store_root: impl AsRef<Path>,
        directory: Arc<dyn DeviceDirectory>,
        default_inbox_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        std::fs::create_dir_all(block_store_root.as_ref())?;
        let default_inbox_dir = default_inbox_dir.into();
        std::fs::create_dir_all(&default_inbox_dir)?;
        let store = SendStore::open(store_db_path)?;
        // A receive only runs inside the process that started it, so any
        // row still marked in progress was cut off by the previous exit.
        store.interrupt_in_progress_inbound()?;
        // Whatever an earlier run left beyond the bound goes now.
        store.prune_finished(FINISHED_RETAINED_LIMIT, "")?;
        let service = Self {
            node,
            running_receives: std::sync::Mutex::default(),
            outbound_cancels: std::sync::atomic::AtomicU64::new(0),
            outbound_lifecycle: std::sync::Mutex::new(()),
            store,
            block_store: SegmentBlockStore::open_process_locked(block_store_root.as_ref())?,
            directory,
            default_inbox_dir,
            #[cfg(any(test, feature = "test-support"))]
            chunk_abort: std::sync::Mutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            serve_gate: std::sync::Mutex::new(None),
            serve_write_timeout: std::sync::Mutex::new(SERVE_WRITE_TIMEOUT),
            #[cfg(any(test, feature = "test-support"))]
            stall_next_serve_write: std::sync::atomic::AtomicBool::new(false),
        };
        // Blocks an earlier run left behind (finished transfers, abandoned offers).
        service.note(service.reap_blocks(BLOCK_REAP_GRACE));
        Ok(service)
    }

    /// Test-only: arranges for the returned [`tokio::sync::Notify`] to fire
    /// the instant this service has durably confirmed `n` chunks across a
    /// `receive_transfer` call (any file, in pull order) -- letting a real
    /// crash-recovery test abort the task actually driving `receive_transfer`
    /// at an EXACT, deterministic point (some chunks durably on disk, the
    /// rest not) instead of racing a fixed sleep against real network I/O.
    /// The task's own drop/abort is the "crash": nothing here fakes
    /// durability or skips the real write/verify path chunks before `n`
    /// already went through.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_abort_after_n_chunks(&self, n: u32) -> Arc<tokio::sync::Notify> {
        let notify = Arc::new(tokio::sync::Notify::new());
        *self.chunk_abort.lock().unwrap_or_else(|p| p.into_inner()) = Some(ChunkAbortHook {
            remaining: n,
            notify: notify.clone(),
            pause: Arc::new(tokio::sync::Notify::new()),
        });
        notify
    }

    /// Test-only: the next pull this service serves parks just before its first chunk. Returns
    /// `(reached, proceed)`: `reached` fires once the pull is parked, and `proceed` lets it go on.
    /// Gives a test an exact point between "the pull was admitted" and "the first chunk is
    /// written" to cancel at, instead of racing real network I/O.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_park_next_serve(&self) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let gate = (Arc::new(tokio::sync::Notify::new()), Arc::new(tokio::sync::Notify::new()));
        *self.serve_gate.lock().unwrap_or_else(|p| p.into_inner()) = Some(gate.clone());
        gate
    }

    /// Test-only: shortens how long a chunk write may stall before the serve gives up.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_set_serve_write_timeout(&self, timeout: Duration) {
        *self.serve_write_timeout.lock().unwrap_or_else(|p| p.into_inner()) = timeout;
    }

    /// Test-only: the next chunk this service writes to a pull never makes progress, as when the
    /// receiver has stopped reading.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_stall_next_serve_write(&self) {
        self.stall_next_serve_write.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Returns the pause handle to await (outside the lock -- holding a
    /// `std::sync::Mutex` guard across an `.await` is a bug even for a
    /// short one) exactly when `n` chunks have now been confirmed;
    /// otherwise `None`, meaning the caller should proceed immediately.
    #[cfg(any(test, feature = "test-support"))]
    fn note_chunk_confirmed(&self) -> Option<Arc<tokio::sync::Notify>> {
        let mut guard = self.chunk_abort.lock().unwrap_or_else(|p| p.into_inner());
        let hook = guard.as_mut()?;
        hook.remaining = hook.remaining.saturating_sub(1);
        if hook.remaining == 0 {
            hook.notify.notify_one();
            let pause = hook.pause.clone();
            // One-shot: clear the hook the instant it fires, so it can
            // never fire a second time. Without this, `remaining` stays
            // saturated at 0 (`saturating_sub`), and the very next chunk
            // this device EVER confirms -- whether later in this same
            // pull after some other caller happens to notify `pause`, or
            // in a wholly separate, LATER `receive_transfer` call (exactly
            // the crash-recovery retry `test_abort_after_n_chunks` exists
            // to let a test drive) -- would see `remaining == 0` again and
            // park forever on a `pause` nothing is ever going to notify a
            // second time. A real bug this exact shape caused: the retry
            // half of a crash-recovery test hung indefinitely on its
            // second chunk once the first `test_abort_after_n_chunks`
            // rendezvous had already fired once.
            *guard = None;
            Some(pause)
        } else {
            None
        }
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn note_chunk_confirmed(&self) -> Option<Arc<tokio::sync::Notify>> {
        None
    }

    // ---- sender side ---------------------------------------------------

    /// `yadorilink send <source_path> <target_device>`. Idempotent: a
    /// second call with the exact same (canonicalized source path, target
    /// device) re-drives the SAME transfer id and manifest -- built and
    /// durably recorded once -- rather than re-chunking the source or
    /// minting a new offer.
    pub async fn offer_send(
        &self,
        source_path: &Path,
        target_device_query: &str,
    ) -> Result<SendOfferOutcome> {
        // A Track Send grant is mandatory for EVERY offer, unconditionally
        // -- `resolve()` is deliberately never consulted here. This device
        // already having an ordinary netmap/sync relationship with the
        // target (same-account, or cross-account -- `computeNetmap` also
        // includes cross-account invite-accepted devices as netmap peers) is
        // not an exemption from needing its own short-lived grant: it would
        // let a stock client send with zero Send-specific authorization,
        // which is exactly the hole `handle_offer`'s matching unconditional
        // check on the receiving side exists to close. See `GrantedDevice`'s
        // own doc comment for the full design.
        let granted = self
            .directory
            .request_grant(target_device_query)
            .await
            .ok_or_else(|| SendError::NoKnownDeviceKey(target_device_query.to_string()))?;
        // The receiver dials this device back to pull chunks once it
        // accepts the offer. Admitting that dial is the Track Send
        // admission's job: `request_grant` has already recorded the grant
        // for the receiver's key, and an accepted offer keeps admitting it
        // after the grant expires (see `expects_pull_from`).
        let target = granted.device;
        let grant_id = granted.grant_id;
        let grant_nonce = granted.grant_nonce;
        let canonical_source = std::fs::canonicalize(source_path)?;
        let canonical_source_str = canonical_source.to_string_lossy().into_owned();

        let existing = self
            .store
            .find_outbound_by_source_and_target(&canonical_source_str, &target.device_id)?;
        let outbound = match existing {
            Some(row) => row,
            None => {
                let transfer_id = uuid::Uuid::new_v4().to_string();
                let (manifest, _total_size) =
                    build_outbound_manifest(&self.block_store, &canonical_source, &transfer_id)?;
                let created_at_unix_nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as i64;
                self.store.insert_outbound_offered(
                    &transfer_id,
                    &target.device_id,
                    &target.signing_key,
                    &canonical_source_str,
                    &manifest,
                    created_at_unix_nanos,
                )?;
                self.store.get_outbound(&transfer_id)?.expect("just inserted")
            }
        };

        self.drive_offer(&outbound, &target, grant_id, grant_nonce).await
    }

    /// Offers `outbound` to `target` under the grant and records the answer. A transfer that
    /// stops here keeps a closed reason for the sent list; one the receiver declines is over.
    async fn drive_offer(
        &self,
        outbound: &OutboundTransfer,
        target: &ResolvedDevice,
        grant_id: String,
        grant_nonce: String,
    ) -> Result<SendOfferOutcome> {
        let result = self.offer_once(outbound, target, grant_id, grant_nonce).await;
        match &result {
            Ok(_) => self.note(self.store.clear_failure(&outbound.transfer_id)),
            Err(error) => {
                self.note(self.store.record_failure(&outbound.transfer_id, error.failure_code()))
            }
        }
        result
    }

    /// [`SendStore::prune_finished`], then reaps the blocks that leaves unreferenced.
    fn prune_and_reap(&self, spare: &str) -> Result<()> {
        self.store.prune_finished(FINISHED_RETAINED_LIMIT, spare)?;
        self.reap_blocks(BLOCK_REAP_GRACE)
    }

    /// Deletes the blocks no transfer on record can still need (see
    /// [`SendStore::live_chunk_hashes`]) and that are older than `grace`. The block store is
    /// Track Send's own, so nothing else references what it holds. Content that is shared
    /// between transfers stays as long as any of them needs it.
    pub(crate) fn reap_blocks(&self, grace: Duration) -> Result<()> {
        let live = self.store.live_chunk_hashes()?;
        let cutoff =
            std::time::SystemTime::now().checked_sub(grace).unwrap_or(std::time::UNIX_EPOCH);
        let report =
            yadorilink_local_storage::BlockStore::sweep(&self.block_store, &live, cutoff, false)?;
        if report.blocks_deleted > 0 {
            tracing::debug!(
                blocks = report.blocks_deleted,
                bytes = report.bytes_reclaimed,
                "Track Send: reaped blocks no transfer needs"
            );
        }
        Ok(())
    }

    /// Logs a bookkeeping write that failed; the transfer's own outcome is what the caller sees.
    fn note(&self, written: Result<()>) {
        if let Err(error) = written {
            tracing::warn!(%error, "Track Send: could not record a transfer's state");
        }
    }

    async fn offer_once(
        &self,
        outbound: &OutboundTransfer,
        target: &ResolvedDevice,
        grant_id: String,
        grant_nonce: String,
    ) -> Result<SendOfferOutcome> {
        let connection = dial_send(&self.node, target).await?;
        let (mut send, mut recv) = connection.open_stream().await?;
        write_message(
            &mut send,
            &SendEnvelope {
                payload: Some(send_envelope::Payload::Manifest(outbound.manifest.clone())),
                grant_id,
                grant_nonce,
            },
        )
        .await?;
        send.finish().ok();
        let ack: SendManifestAck = read_message(&mut recv).await?;
        if !ack.accepted {
            // Terminal, not left in `Offered`: `handle_pull` requires
            // `Acked` before serving any chunk, so a receiver that just
            // declined this offer must not be able to dial back and pull
            // the content anyway -- see `handle_pull`'s own status check.
            self.store.mark_outbound_rejected(&outbound.transfer_id)?;
            self.note(self.prune_and_reap(&outbound.transfer_id));
            connection.close(close_code::DONE, b"offer complete");
            return Err(SendError::OfferRejected(ack.reason));
        }
        // Durably recorded BEFORE this connection is closed, deliberately --
        // a receiver that just answered `accepted: true` is free to dial
        // this device straight back for the pull, and `handle_pull`'s
        // `OutboundStatus::Acked` check has to see this write land as early
        // as this side can possibly make it, not after whatever local work
        // `connection.close` itself does first. Closing before this write
        // used to leave a narrow window where an immediate pull could reach
        // `handle_pull` before this row actually flipped to `Acked` --
        // proven to fail closed (a spurious rejection the receiver simply
        // retries), never a security hole, but narrowing it costs nothing
        // here since neither statement depends on the other's result.
        self.store.mark_outbound_acked(&outbound.transfer_id)?;
        connection.close(close_code::DONE, b"offer complete");
        // Offered again while already accepted is the same offer, still going. Only a cancel that
        // landed while the offer was in flight makes it not so.
        if self.store.outbound_status(&outbound.transfer_id)? == Some(OutboundStatus::Canceled) {
            return Err(SendError::TransferCanceled(outbound.transfer_id.clone()));
        }

        Ok(SendOfferOutcome {
            transfer_id: outbound.transfer_id.clone(),
            files_offered: outbound
                .manifest
                .files
                .iter()
                .map(|f| f.relative_path.clone())
                .collect(),
            total_size: outbound.manifest.total_size,
        })
    }

    /// Which side of `transfer_id` this device is, when it knows the transfer.
    pub fn transfer_direction(&self, transfer_id: &str) -> Result<Option<TransferDirection>> {
        if self.store.get_inbound(transfer_id)?.is_some() {
            return Ok(Some(TransferDirection::Received));
        }
        Ok(self.store.get_outbound(transfer_id)?.map(|_| TransferDirection::Sent))
    }

    /// Every transfer this device sent that is still going, plus the most recent finished ones,
    /// oldest first.
    pub fn list_sent(&self) -> Result<Vec<SentEntry>> {
        let rows = self.store.list_outbound_recent(FINISHED_HISTORY_LIMIT)?;
        rows.into_iter()
            .map(|row| {
                let status = match row.status {
                    OutboundStatus::Offered => "offered",
                    OutboundStatus::Acked => "accepted",
                    OutboundStatus::Completed => "completed",
                    OutboundStatus::Rejected => "declined",
                    OutboundStatus::Canceled => "canceled",
                };
                let can_retry = matches!(
                    row.status,
                    OutboundStatus::Offered | OutboundStatus::Rejected | OutboundStatus::Canceled
                );
                Ok(SentEntry {
                    failure: self.store.failure(&row.transfer_id)?,
                    transfer_id: row.transfer_id,
                    target_device_id: row.target_device_id,
                    files: row
                        .manifest
                        .files
                        .iter()
                        .map(|f| (f.relative_path.clone(), f.size))
                        .collect(),
                    total_size: row.manifest.total_size,
                    created_at_unix_nanos: row.created_at_unix_nanos,
                    status,
                    can_retry,
                })
            })
            .collect()
    }

    /// Stops a transfer this device sent. Idempotent: one already canceled, declined or
    /// completed is left as it is (a completed one is never undone). The receiver's pull stops at
    /// once and any later pull is refused; the receiver's copy of what it already got is not
    /// touched.
    fn cancel_outbound(&self, transfer_id: &str) -> Result<()> {
        let _lifecycle = self.outbound_lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        self.outbound_cancels.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.store.cancel_outbound(transfer_id)? {
            self.note(self.prune_and_reap(transfer_id));
        }
        Ok(())
    }

    /// Offers a canceled, declined or never-answered transfer again. Nothing is reused that could
    /// have gone stale: the offered file or folder must still be exactly what was offered, the
    /// coordination plane must grant a new authorization for the same device, and the device must
    /// still have the same key. Any failed check leaves the transfer as it was.
    pub async fn retry_sent_transfer(&self, transfer_id: &str) -> Result<SendOfferOutcome> {
        // Before anything is read or hashed: a cancel at any later point is newer than this retry.
        let cancels_seen = self.outbound_cancels.load(std::sync::atomic::Ordering::SeqCst);
        let outbound = self
            .store
            .get_outbound(transfer_id)?
            .ok_or_else(|| SendError::NotSent(transfer_id.to_string()))?;
        if !matches!(
            outbound.status,
            OutboundStatus::Offered | OutboundStatus::Rejected | OutboundStatus::Canceled
        ) {
            return Err(SendError::NotRetryable {
                transfer_id: transfer_id.to_string(),
                status: outbound.status.as_str(),
            });
        }
        match build_outbound_manifest(
            &crate::manifest::HashOnlyStore,
            Path::new(&outbound.source_path),
            transfer_id,
        ) {
            Ok((rebuilt, _)) if same_files(&rebuilt, &outbound.manifest) => {}
            Ok(_) | Err(SendError::EmptyManifest(_)) => {
                return Err(SendError::SourceChanged(transfer_id.to_string()));
            }
            Err(SendError::Io(error))
            | Err(SendError::Storage(yadorilink_local_storage::StorageError::SourceRead(error)))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Err(SendError::SourceChanged(transfer_id.to_string()));
            }
            Err(error) => return Err(error),
        }
        let granted =
            self.directory.request_grant(&outbound.target_device_id).await.ok_or_else(|| {
                SendError::NeedsNewAuthorization(outbound.target_device_id.clone())
            })?;
        if granted.device.signing_key != outbound.target_signing_key {
            return Err(SendError::TargetChanged(
                outbound.target_device_id.clone(),
                transfer_id.to_string(),
            ));
        }
        {
            // Checked and written with no cancel in between.
            let _lifecycle = self.outbound_lifecycle.lock().unwrap_or_else(|p| p.into_inner());
            if self.outbound_cancels.load(std::sync::atomic::Ordering::SeqCst) != cancels_seen
                || !self.store.reopen_outbound(transfer_id, &outbound.status)?
            {
                // Settled by something else (a cancel, say) since the retry began: that is
                // newer than this retry and stands.
                return Err(SendError::NotRetryable {
                    transfer_id: transfer_id.to_string(),
                    status: "changed",
                });
            }
        }
        let reopened = self
            .store
            .get_outbound(transfer_id)?
            .ok_or_else(|| SendError::UnknownTransfer(transfer_id.to_string()))?;
        self.drive_offer(&reopened, &granted.device, granted.grant_id, granted.grant_nonce).await
    }

    // ---- receiver side --------------------------------------------------

    pub fn list_inbox(&self) -> Result<Vec<InboxEntry>> {
        let rows = self.store.list_inbound_recent(FINISHED_HISTORY_LIMIT)?;
        rows.into_iter()
            .map(|row| {
                Ok(InboxEntry {
                    failure: self.store.failure(&row.transfer_id)?,
                    transfer_id: row.transfer_id,
                    sender_device_id: row.sender_device_id,
                    files: row
                        .manifest
                        .files
                        .iter()
                        .map(|f| (f.relative_path.clone(), f.size))
                        .collect(),
                    total_size: row.manifest.total_size,
                    offered_at_unix_nanos: row.offered_at_unix_nanos,
                    status: row.status.as_str(),
                })
            })
            .collect()
    }

    /// `yadorilink receive <transfer_id> [--to <dir>]` -- the explicit
    /// accept step. Resumable: every file's missing chunks are recomputed
    /// from this device's own local block store on every call
    /// (`BlockContentStore::present_blocks`), so re-running this after a
    /// crash or a network interruption only re-pulls what never landed
    /// durably, never bytes already confirmed.
    pub async fn receive_transfer(
        &self,
        transfer_id: &str,
        destination_dir: Option<&Path>,
    ) -> Result<ReceiveOutcome> {
        let cancel = Arc::new(tokio::sync::Notify::new());
        {
            let mut running = self.running_receives.lock().unwrap_or_else(|p| p.into_inner());
            if running.contains_key(transfer_id) {
                return Err(SendError::AlreadyReceiving(transfer_id.to_string()));
            }
            running.insert(transfer_id.to_string(), cancel.clone());
        }
        let _active =
            ActiveReceive { running: &self.running_receives, transfer_id: transfer_id.to_string() };

        let result = tokio::select! {
            result = self.receive_inner(transfer_id, destination_dir) => result,
            () = cancel.notified() => Err(SendError::TransferCanceled(transfer_id.to_string())),
        };
        if let Err(error) = &result {
            // Only a row still in progress becomes failed: a canceled one
            // stays canceled.
            match self.store.fail_inbound(transfer_id) {
                Ok(true) => {
                    self.note(self.store.record_failure(transfer_id, error.failure_code()));
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%error, transfer_id, "Track Send: could not record a failed receive");
                }
            }
        }
        result
    }

    async fn receive_inner(
        &self,
        transfer_id: &str,
        destination_dir: Option<&Path>,
    ) -> Result<ReceiveOutcome> {
        let inbound = self
            .store
            .get_inbound(transfer_id)?
            .ok_or_else(|| SendError::UnknownTransfer(transfer_id.to_string()))?;
        if inbound.status == InboundStatus::Canceled {
            return Err(SendError::TransferCanceled(transfer_id.to_string()));
        }

        let requested_dir = match destination_dir {
            Some(dir) => dir.to_string_lossy().into_owned(),
            None => self.default_inbox_dir.join(transfer_id).to_string_lossy().into_owned(),
        };
        let destination_dir = self.store.claim_inbound_destination(transfer_id, &requested_dir)?;
        if self.store.resume_inbound(transfer_id)? {
            self.store.clear_failure(transfer_id)?;
        }
        let destination_dir = PathBuf::from(destination_dir);
        std::fs::create_dir_all(&destination_dir)?;

        let sender = self
            .directory
            .resolve(&inbound.sender_device_id)
            .ok_or_else(|| SendError::NoKnownAddress(inbound.sender_device_id.clone()))?;

        let mut files_received = Vec::new();
        let mut bytes_received: u64 = 0;
        for (file_index, entry) in inbound.manifest.files.iter().enumerate() {
            let first_missing = first_missing_chunk(&self.block_store, &entry.chunk_hashes)?;
            if let Some(start_chunk_index) = first_missing {
                self.pull_file(&sender, transfer_id, file_index as u32, entry, start_chunk_index)
                    .await?;
            }
            let out_path = safe_join(&destination_dir, &entry.relative_path)?;
            let blocks = entry
                .chunk_hashes
                .iter()
                .enumerate()
                .map(|(idx, hash)| {
                    Ok(yadorilink_replica_domain::file::BlockInfo {
                        hash: hash.clone(),
                        offset: idx as u64 * entry.chunk_size as u64,
                        size: chunk_byte_size(entry, idx)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let mtime_unix_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64;
            // The inbox is not a sync root: its directories are plain ones.
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            reconstruct_file(&self.block_store, &out_path, &blocks, mtime_unix_nanos)?;
            files_received.push(entry.relative_path.clone());
            bytes_received += entry.size;
        }

        self.store.mark_inbound_completed(transfer_id)?;
        self.note(self.store.clear_failure(transfer_id));
        self.note(self.prune_and_reap(transfer_id));
        self.tell_sender_done(sender, transfer_id);
        Ok(ReceiveOutcome { destination_dir, files_received, bytes_received })
    }

    /// Tells the sender, in the background and best effort, that every file arrived, so its sent
    /// list can show the transfer as completed. Nothing waits on it and a failure only means the
    /// sender keeps showing the transfer as accepted.
    fn tell_sender_done(&self, sender: ResolvedDevice, transfer_id: &str) {
        let node = self.node.clone();
        let transfer_id = transfer_id.to_string();
        tokio::spawn(async move {
            if let Err(error) = send_done(&node, &sender, &transfer_id).await {
                tracing::debug!(%error, transfer_id, "Track Send: could not tell the sender the transfer finished");
            }
        });
    }

    /// Stops the running receive of `transfer_id`, if any, and marks the
    /// transfer canceled; for a transfer this device sent, stops serving it
    /// (see `cancel_outbound`). Idempotent: an already canceled or completed
    /// transfer is left as it is. Only this transfer is affected. Blocks
    /// already pulled stay in the block store for a retry.
    pub fn cancel_transfer(&self, transfer_id: &str) -> Result<()> {
        if self.store.get_inbound(transfer_id)?.is_none() {
            // Not received here: stops a transfer this device sent, or is the usual error.
            self.store
                .get_outbound(transfer_id)?
                .ok_or_else(|| SendError::UnknownTransfer(transfer_id.to_string()))?;
            return self.cancel_outbound(transfer_id);
        }
        if self.store.cancel_inbound(transfer_id)? {
            self.note(self.prune_and_reap(transfer_id));
        }
        if let Some(cancel) =
            self.running_receives.lock().unwrap_or_else(|p| p.into_inner()).get(transfer_id)
        {
            cancel.notify_one();
        }
        Ok(())
    }

    /// Resumes a failed or canceled inbound transfer. Before anything is
    /// changed it re-checks that the sender is still a known device, that the
    /// recorded manifest is still consistent and stays inside the
    /// destination, and that the destination is still usable. Any failed
    /// check leaves the transfer exactly as it was.
    pub async fn retry_transfer(&self, transfer_id: &str) -> Result<ReceiveOutcome> {
        let inbound = self
            .store
            .get_inbound(transfer_id)?
            .ok_or_else(|| SendError::UnknownTransfer(transfer_id.to_string()))?;
        if !matches!(inbound.status, InboundStatus::Failed | InboundStatus::Canceled) {
            return Err(SendError::NotRetryable {
                transfer_id: transfer_id.to_string(),
                status: inbound.status.as_str(),
            });
        }
        self.directory
            .resolve(&inbound.sender_device_id)
            .ok_or_else(|| SendError::NoKnownAddress(inbound.sender_device_id.clone()))?;
        crate::manifest::validate_offered_manifest(&inbound.manifest)
            .map_err(SendError::Protocol)?;
        if let Some(destination) = inbound.destination_dir.as_deref() {
            let path = Path::new(destination);
            if !path.is_absolute() {
                return Err(SendError::BadDestination(
                    destination.to_string(),
                    "it is not an absolute path".to_string(),
                ));
            }
            if path.exists() && !path.is_dir() {
                return Err(SendError::BadDestination(
                    destination.to_string(),
                    "it is not a directory".to_string(),
                ));
            }
            for entry in &inbound.manifest.files {
                safe_join(path, &entry.relative_path)?;
            }
        }
        self.store.uncancel_inbound(transfer_id)?;
        self.receive_transfer(transfer_id, None).await
    }

    async fn pull_file(
        &self,
        sender: &ResolvedDevice,
        transfer_id: &str,
        file_index: u32,
        entry: &SendFileEntry,
        start_chunk_index: u32,
    ) -> Result<()> {
        let connection = dial_send(&self.node, sender).await?;
        let (mut send, mut recv) = connection.open_stream().await?;
        write_message(
            &mut send,
            &SendEnvelope {
                payload: Some(send_envelope::Payload::Pull(ChunkPullRequest {
                    transfer_id: transfer_id.to_string(),
                    file_index,
                    start_chunk_index,
                })),
                // Never a grant on a pull -- see send.proto's own
                // `SendEnvelope.grant_id` doc comment for why: this
                // device's authorization to be dialed back was already
                // established when it presented (and this daemon
                // consumed) a grant for the ORIGINAL offer, if one was
                // needed at all.
                grant_id: String::new(),
                grant_nonce: String::new(),
            },
        )
        .await?;
        send.finish().ok();

        // An accepted sender is trusted for CONTENT (it already passed the
        // grant/ack gate this connection was authorized through), never for
        // how much it sends, in what order, or how large it claims each
        // chunk is -- this device's own copy of the manifest, already on
        // disk before this dial, is the only thing every chunk is checked
        // against below.
        //
        // `next_chunk_index` is both the resume cursor and the loop's own
        // hard upper bound: the `while` condition stops issuing reads the
        // instant `entry.chunk_hashes.len()` chunks have been received, no
        // matter what the peer's own `last_chunk` flag claims (or never
        // claims) after that -- otherwise an already-accepted sender could
        // keep this loop running indefinitely, streaming unbounded chunks
        // into this device's block store.
        let total_chunks = entry.chunk_hashes.len() as u32;
        let mut next_chunk_index = start_chunk_index;
        while next_chunk_index < total_chunks {
            let message: ChunkStreamMessage = read_message(&mut recv).await?;
            match message.payload {
                Some(chunk_stream_message::Payload::Rejected(ChunkPullRejected { reason })) => {
                    connection.close(close_code::REJECTED, b"pull rejected");
                    return Err(SendError::PullRejected(reason));
                }
                Some(chunk_stream_message::Payload::Header(ChunkHeader {
                    chunk_index,
                    size,
                    last_chunk,
                })) => {
                    if chunk_index != next_chunk_index {
                        connection.close(close_code::PROTOCOL_ERROR, b"unexpected chunk index");
                        return Err(SendError::Protocol(format!(
                            "file {file_index}: expected chunk index {next_chunk_index}, peer sent {chunk_index}"
                        )));
                    }
                    // Checked, and the pull aborted, BEFORE `read_body`
                    // allocates anything: the header's `size` is a
                    // peer-controlled `u32` (up to 4 GiB), so this
                    // comparison against this device's own manifest is what
                    // actually bounds the allocation below, not whatever
                    // the peer claims.
                    let expected_size = chunk_byte_size(entry, chunk_index as usize)?;
                    if size != expected_size {
                        connection.close(close_code::PROTOCOL_ERROR, b"unexpected chunk size");
                        return Err(SendError::Protocol(format!(
                            "file {file_index} chunk {chunk_index}: expected {expected_size} bytes, peer declared {size}"
                        )));
                    }
                    let body = read_body(&mut recv, size as usize).await?;
                    // Verified against this device's own manifest hash
                    // BEFORE ever reaching the block store. Content-
                    // addressing alone would keep a mismatched chunk from
                    // corrupting the reconstructed file (it just would not
                    // be the block `reconstruct_file` looks up), but
                    // rejecting it here catches a bad or truncated chunk
                    // immediately and aborts the transfer with a clear
                    // error, instead of silently writing garbage the rest
                    // of this transfer will never reference.
                    let actual_hash = hash_block_bytes(&body);
                    let expected_hash = hex::encode(&entry.chunk_hashes[chunk_index as usize]);
                    if actual_hash != expected_hash {
                        connection.close(
                            close_code::PROTOCOL_ERROR,
                            b"chunk failed integrity verification",
                        );
                        return Err(SendError::ChunkHashMismatch { file_index, chunk_index });
                    }
                    // Content-addressed: this write itself IS the durable
                    // resume checkpoint (see `store.rs`'s own module doc
                    // comment) -- `SegmentBlockStore::put`'s single-item commit
                    // path fsyncs before returning, every time.
                    self.block_store.put(&body)?;
                    if let Some(pause) = self.note_chunk_confirmed() {
                        // Parks here forever (see `ChunkAbortHook::pause`'s
                        // own doc comment) -- a real crash-recovery test
                        // aborts the task while it is parked, guaranteeing
                        // no further chunk is ever read past this point.
                        pause.notified().await;
                    }
                    next_chunk_index += 1;
                    if last_chunk {
                        break;
                    }
                }
                None => return Err(SendError::Protocol("empty chunk stream message".to_string())),
            }
        }
        connection.close(close_code::DONE, b"pull complete");
        Ok(())
    }

    // ---- inbound connection handling ------------------------------------

    /// Whether this device has an accepted offer outstanding for the
    /// device holding `peer_key`: it is the receiver, and it may come back
    /// to pull after the grant's short lifetime. Membership in any folder
    /// group is never a reason.
    ///
    /// An accepted offer never expires, so this says nothing about whether
    /// the device is still authorized at all. The caller's admission policy
    /// must also require the device's current authority; this alone must
    /// never admit a connection.
    pub fn expects_pull_from(&self, peer_key: &[u8; 32]) -> bool {
        self.store.has_acked_outbound_for(peer_key).unwrap_or_else(|error| {
            tracing::warn!(%error, "Track Send: could not read outbound offers; refusing");
            false
        })
    }

    /// Serves every inbound Track Send connection in `inbound` for the life
    /// of this service. Each connection is handled on its own spawned task
    /// so one slow or stalled peer cannot hold up another's offer or pull.
    pub async fn run_inbound_dispatcher(
        self: Arc<Self>,
        mut inbound: tokio::sync::mpsc::Receiver<TrackSendConnection>,
    ) {
        while let Some(connection) = inbound.recv().await {
            let service = self.clone();
            tokio::spawn(async move {
                service.serve_connection(connection).await;
            });
        }
    }

    async fn serve_connection(&self, connection: TrackSendConnection) {
        let peer_key = *connection.peer().as_bytes();
        loop {
            let (send, recv) = match connection.accept_stream().await {
                Ok(pair) => pair,
                Err(_) => return, // connection closed by the peer -- normal end of session.
            };
            if let Err(error) = self.serve_stream(&connection, send, recv, peer_key).await {
                tracing::warn!(%error, "Track Send: inbound stream ended in error");
                return;
            }
        }
    }

    async fn serve_stream(
        &self,
        connection: &TrackSendConnection,
        mut send: TrackSendWriter,
        mut recv: TrackSendReader,
        peer_key: [u8; 32],
    ) -> Result<()> {
        let envelope: SendEnvelope = read_message(&mut recv).await?;
        let grant =
            (!envelope.grant_id.is_empty()).then_some((envelope.grant_id, envelope.grant_nonce));
        match envelope.payload {
            Some(send_envelope::Payload::Manifest(manifest)) => {
                self.handle_offer(&mut send, peer_key, manifest, grant).await
            }
            Some(send_envelope::Payload::Pull(pull)) => {
                self.handle_pull(connection, &mut send, peer_key, pull).await
            }
            Some(send_envelope::Payload::Done(done)) => {
                self.handle_done(&mut send, peer_key, done).await
            }
            None => {
                connection.close(close_code::PROTOCOL_ERROR, b"empty envelope");
                Err(SendError::Protocol("empty envelope".to_string()))
            }
        }
    }

    async fn handle_offer(
        &self,
        send: &mut TrackSendWriter,
        peer_key: [u8; 32],
        manifest: SendManifest,
        grant: Option<(String, String)>,
    ) -> Result<()> {
        // A grant must validate and be atomically consumed BEFORE anything
        // about this offer is durably recorded -- an offer this device
        // never actually earned authorization for must leave no trace, not
        // even a rejected-but-stored inbox entry.
        //
        // This check is UNCONDITIONAL: a connection admitted on the Track
        // Send ALPN only proves this device currently expects this key (a
        // live grant, or an accepted offer it may pull) -- it says nothing
        // about whether THIS offer was ever actually granted.
        // An envelope with an empty `grant_id` is passed straight into
        // `consume_grant` as an empty string rather than skipped, so it is
        // rejected exactly the same way an unknown/invalid/already-consumed
        // grant id is -- there is no separate "trust it because this peer
        // also happens to be an ordinary netmap peer" path, same-account or
        // cross-account (`computeNetmap` includes cross-account
        // invite-accepted devices as netmap peers too). Ordinary
        // netmap/sync authorization must never be sufficient on its own to
        // receive a Send.
        let (grant_id, grant_nonce) = grant.unwrap_or_default();
        let verdict = match self.directory.consume_grant(&grant_id, &grant_nonce, &peer_key).await {
            // An authorized sender's manifest is still the sender's claim: it
            // sizes the allocations of the pull, so it must be consistent
            // before it is recorded.
            Ok(()) => crate::manifest::validate_offered_manifest(&manifest),
            Err(reason) => Err(reason),
        };
        if let Err(reason) = verdict {
            write_message(send, &SendManifestAck { accepted: false, reason: reason.clone() })
                .await?;
            send.finish().ok();
            // Wait for the peer to have actually received this rejection
            // before returning `Err` -- the caller (`serve_connection`)
            // drops its connection handle as soon as this call returns an
            // error, and the last handle closing ends the connection.
            // `finish()` only QUEUES the ack; without this wait, the close
            // can race ahead of it, so the peer sees a bare connection loss
            // instead of the rejection reason it was just sent. Bounded:
            // a peer that keeps the connection alive while never reading
            // would otherwise hold this forever, and flushing is
            // best-effort, not correctness-critical -- the rejection error
            // below is returned either way.
            send.flushed(REJECT_ACK_FLUSH_TIMEOUT).await;
            return Err(SendError::OfferRejected(reason));
        }
        let sender_device_id =
            self.directory.device_id_for_key(&peer_key).unwrap_or_else(|| hex::encode(peer_key));
        let offered_at_unix_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;
        // Durably recorded BEFORE the ack -- see `SendStore::
        // insert_inbound_if_new`'s own doc comment.
        self.store.insert_inbound_if_new(
            &manifest.transfer_id,
            &sender_device_id,
            &manifest,
            offered_at_unix_nanos,
        )?;
        write_message(send, &SendManifestAck { accepted: true, reason: String::new() }).await?;
        send.finish().ok();
        Ok(())
    }

    /// The receiver says it wrote every file: the transfer is completed, if it was offered to this
    /// exact device and is still offered or accepted. Anything else is answered not accepted and changes
    /// nothing; a canceled transfer is not undone.
    async fn handle_done(
        &self,
        send: &mut TrackSendWriter,
        peer_key: [u8; 32],
        done: TransferDone,
    ) -> Result<()> {
        let completed = match self.store.get_outbound(&done.transfer_id)? {
            Some(outbound) if outbound.target_signing_key == peer_key => match outbound.status {
                OutboundStatus::Completed => true,
                // Offered too: the receiver can finish and say so before this device has
                // recorded the acceptance it is still reading.
                OutboundStatus::Offered | OutboundStatus::Acked => {
                    let moved = self.store.mark_outbound_completed(&done.transfer_id)?;
                    if moved {
                        self.note(self.prune_and_reap(&done.transfer_id));
                    }
                    moved
                }
                _ => false,
            },
            _ => false,
        };
        write_message(send, &SendManifestAck { accepted: completed, reason: String::new() })
            .await?;
        send.finish().ok();
        Ok(())
    }

    async fn handle_pull(
        &self,
        connection: &TrackSendConnection,
        send: &mut TrackSendWriter,
        peer_key: [u8; 32],
        pull: ChunkPullRequest,
    ) -> Result<()> {
        // Serving a chunk pull requires BOTH that this is the exact device
        // the offer named AND that this device's own record shows that
        // device actually accepted it (`OutboundStatus::Acked`) -- the peer
        // key check alone is not enough: a receiver that dialed back,
        // received the manifest, and then answered
        // `SendManifestAck{accepted:false}` is still the device the offer
        // was addressed to, but must not be able to pull the content it
        // just declined. `offer_send` moves a declined offer to
        // `OutboundStatus::Rejected` (never leaves it in `Offered`) for
        // exactly this check; an offer still in `Offered` -- the ack has
        // not landed yet, or never will -- is refused the same way, since
        // this device has no record it was ever accepted.
        let outbound = self.store.get_outbound(&pull.transfer_id)?;
        let outbound = match outbound {
            Some(outbound) if outbound.target_signing_key != peer_key => {
                return self
                    .reject_pull(connection, send, "not the device this was offered to")
                    .await;
            }
            Some(outbound) if outbound.status == OutboundStatus::Canceled => {
                return self.reject_pull(connection, send, PULL_REASON_CANCELED).await;
            }
            // A completed transfer keeps serving: a receiver that could not finish writing
            // pulls again.
            Some(outbound)
                if !matches!(
                    outbound.status,
                    OutboundStatus::Acked | OutboundStatus::Completed
                ) =>
            {
                return self.reject_pull(connection, send, PULL_REASON_NOT_ACCEPTED).await;
            }
            Some(outbound) => outbound,
            None => return self.reject_pull(connection, send, "unknown transfer id").await,
        };
        let Some(entry) = outbound.manifest.files.get(pull.file_index as usize) else {
            return self.reject_pull(connection, send, "file index out of range").await;
        };
        let num_chunks = entry.chunk_hashes.len() as u32;
        if pull.start_chunk_index >= num_chunks {
            return self.reject_pull(connection, send, "start chunk index out of range").await;
        }
        let served =
            self.serve_chunks(send, &pull.transfer_id, entry, pull.start_chunk_index).await;
        self.note_serve_outcome(&pull.transfer_id, &served);
        if !served? {
            // Stopped between two chunks, so the rejection is a whole message of its own.
            return self.reject_pull(connection, send, PULL_REASON_CANCELED).await;
        }
        send.finish().ok();
        Ok(())
    }

    /// Streams the chunks of `entry` from `start_chunk_index` to the end. Whether the sender
    /// canceled the transfer is read before every chunk, so a cancel stops the pull at a message
    /// boundary (false) and never inside a header or a body.
    async fn serve_chunks(
        &self,
        send: &mut TrackSendWriter,
        transfer_id: &str,
        entry: &SendFileEntry,
        start_chunk_index: u32,
    ) -> Result<bool> {
        let num_chunks = entry.chunk_hashes.len() as u32;
        #[cfg(any(test, feature = "test-support"))]
        {
            let gate = self.serve_gate.lock().unwrap_or_else(|p| p.into_inner()).take();
            if let Some((reached, proceed)) = gate {
                reached.notify_one();
                proceed.notified().await;
            }
        }
        for chunk_index in start_chunk_index..num_chunks {
            // Anything but an accepted (or completed) transfer stops the pull: a canceled one, or
            // one that is gone.
            if !matches!(
                self.store.outbound_status(transfer_id)?,
                Some(OutboundStatus::Acked | OutboundStatus::Completed)
            ) {
                return Ok(false);
            }
            let hash = &entry.chunk_hashes[chunk_index as usize];
            let hash_hex = hex::encode(hash);
            let body = {
                let _reads = yadorilink_local_storage::io_diag::attribute_reads(
                    yadorilink_local_storage::io_diag::ReadReason::SendServe,
                );
                self.block_store.get(&hash_hex)?
            };
            let last_chunk = chunk_index + 1 == num_chunks;
            let header = ChunkStreamMessage {
                payload: Some(chunk_stream_message::Payload::Header(ChunkHeader {
                    chunk_index,
                    size: body.len() as u32,
                    last_chunk,
                })),
            };
            #[cfg(any(test, feature = "test-support"))]
            let stall =
                self.stall_next_serve_write.swap(false, std::sync::atomic::Ordering::SeqCst);
            #[cfg(not(any(test, feature = "test-support")))]
            let stall = false;
            let timeout = *self.serve_write_timeout.lock().unwrap_or_else(|p| p.into_inner());
            write_chunk_bounded(send, &header, &body, timeout, stall).await?;
        }
        Ok(true)
    }

    /// Records how a pull ended for a transfer still accepted: the reason it stopped, or nothing
    /// once a whole file was served (an earlier note, such as a stall, no longer holds). A
    /// canceled or finished transfer keeps what it has; the store decides that atomically.
    fn note_serve_outcome(&self, transfer_id: &str, served: &Result<bool>) {
        let reason = match served {
            Ok(true) => None,
            Ok(false) => return,
            Err(error) => Some(error.failure_code()),
        };
        self.note(self.store.note_serve_outcome(transfer_id, reason));
    }

    async fn reject_pull(
        &self,
        connection: &TrackSendConnection,
        send: &mut TrackSendWriter,
        reason: &str,
    ) -> Result<()> {
        write_message(
            send,
            &ChunkStreamMessage {
                payload: Some(chunk_stream_message::Payload::Rejected(ChunkPullRejected {
                    reason: reason.to_string(),
                })),
            },
        )
        .await?;
        send.finish().ok();
        // Same hazard `handle_offer`'s rejection path guards against (see
        // that call site's own comment): `finish()` only QUEUES this
        // message for the connection's background driver, so closing the
        // connection immediately below can race ahead of the driver ever
        // actually transmitting it -- the peer would see a bare connection
        // loss instead of the rejection reason it was just sent. Wait
        // (bounded; best-effort, not correctness-critical) for the peer to
        // have received it first.
        send.flushed(REJECT_ACK_FLUSH_TIMEOUT).await;
        connection.close(close_code::REJECTED, reason.as_bytes());
        Ok(())
    }
}

/// Writes one chunk (header, then body) and gives up with [`SendError::ReceiverStalled`] when a
/// write makes no progress for `timeout`. The bound is on inactivity, not on the whole chunk: it
/// restarts whenever the receiver accepts any bytes, so a slow receiver that keeps reading is never
/// cut off. `stall` (tests only) stands in for a receiver that has stopped reading.
async fn write_chunk_bounded<W: tokio::io::AsyncWrite + Unpin>(
    send: &mut W,
    header: &ChunkStreamMessage,
    body: &[u8],
    timeout: Duration,
    stall: bool,
) -> Result<()> {
    if stall {
        return within(timeout, std::future::pending()).await;
    }
    within(timeout, write_message(send, header)).await?;
    let mut rest = body;
    while !rest.is_empty() {
        // One `write` call, so the bound restarts whenever any bytes were accepted.
        let written =
            within(timeout, async { Ok(tokio::io::AsyncWriteExt::write(send, rest).await?) })
                .await?;
        rest = &rest[written..];
    }
    Ok(())
}

/// `write`, or [`SendError::ReceiverStalled`] when it makes no progress for `timeout`.
async fn within<T>(
    timeout: Duration,
    write: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(timeout, write).await {
        Ok(result) => result,
        Err(_) => Err(SendError::ReceiverStalled),
    }
}

/// Tells `sender` that `transfer_id` arrived whole and waits for its answer, so the message is not
/// lost to the connection closing first.
async fn send_done(node: &SubstrateNode, sender: &ResolvedDevice, transfer_id: &str) -> Result<()> {
    let connection = dial_send(node, sender).await?;
    let (mut send, mut recv) = connection.open_stream().await?;
    write_message(
        &mut send,
        &SendEnvelope {
            payload: Some(send_envelope::Payload::Done(TransferDone {
                transfer_id: transfer_id.to_string(),
            })),
            grant_id: String::new(),
            grant_nonce: String::new(),
        },
    )
    .await?;
    send.finish().ok();
    let _answer: SendManifestAck = read_message(&mut recv).await?;
    connection.close(close_code::DONE, b"done noted");
    Ok(())
}

/// Whether two manifests offer the same files with the same content.
fn same_files(a: &SendManifest, b: &SendManifest) -> bool {
    a.files.len() == b.files.len()
        && a.files.iter().zip(&b.files).all(|(x, y)| {
            x.relative_path == y.relative_path
                && x.size == y.size
                && x.chunk_size == y.chunk_size
                && x.chunk_hashes == y.chunk_hashes
        })
}

/// The first chunk index in `chunk_hashes` not yet durably present in
/// `store`, or `None` if every chunk is already there (nothing to pull --
/// including the zero-chunk case, an empty file).
fn first_missing_chunk(store: &SegmentBlockStore, chunk_hashes: &[Vec<u8>]) -> Result<Option<u32>> {
    if chunk_hashes.is_empty() {
        return Ok(None);
    }
    let hex_hashes: Vec<String> = chunk_hashes.iter().map(hex::encode).collect();
    let present = store.present_blocks(&hex_hashes)?;
    Ok(present.iter().position(|&p| !p).map(|idx| idx as u32))
}

/// Joins `relative` onto `root`, refusing anything that would land outside
/// `root` -- a defense-in-depth check against a manifest carrying a
/// path-traversal `relative_path` (`../../etc/passwd`), independent of and
/// in addition to the sender being an authenticated, authorized device.
fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut out = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => {
                return Err(SendError::Protocol(format!(
                    "manifest path escapes the destination directory: {relative}"
                )))
            }
        }
    }
    Ok(out)
}

async fn read_body(recv: &mut TrackSendReader, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    // A broken or closed connection, not a fault of this device's own disk: reported as such.
    tokio::io::AsyncReadExt::read_exact(recv, &mut buf)
        .await
        .map_err(yadorilink_transport::TransportError::Io)?;
    Ok(buf)
}

/// Dials `device` on the Track Send ALPN, giving up after [`DIAL_TIMEOUT`].
/// The handshake accepts an answer from `device.signing_key` only.
async fn dial_send(node: &SubstrateNode, device: &ResolvedDevice) -> Result<TrackSendConnection> {
    match tokio::time::timeout(DIAL_TIMEOUT, node.connect_track_send(&device.address())).await {
        Ok(connection) => Ok(connection?),
        Err(_) => Err(SendError::DialTimedOut(device.device_id.clone())),
    }
}

/// Regression tests proving that a Send offer requires a validated,
/// single-use grant on BOTH sides, regardless of what ordinary netmap/sync
/// state also happens to be true. `handle_offer`'s unconditional
/// `consume_grant` call is exercised directly, over a real iroh Track Send
/// connection, bypassing `offer_send` entirely so each test controls
/// precisely what an adversarial or merely non-compliant sender presents
/// (including presenting nothing at all). `offer_send`'s own unconditional
/// `request_grant` call has two separate tests, deliberately not just one:
/// the positive control at the bottom of this module proves a compliant
/// sender still succeeds when a real grant is obtainable with NO ordinary
/// netmap relationship at all, and
/// `offer_send_refuses_a_netmap_resolvable_target_when_no_grant_can_be_obtained`
/// proves the actual guard this crate depends on -- a target `resolve` can
/// reach through ordinary netmap connectivity, but for which no grant is
/// obtainable, must be refused before ever dialing, not sent to ungranted.
/// The positive-control test alone cannot exercise that guard, because its
/// own `resolve` always returns `None`; both tests are needed together.
#[cfg(test)]
mod tests;
