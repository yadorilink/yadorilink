//! `PeerSyncSession`'s injected capabilities: the responders and runtime
//! knobs the daemon (or a test) hands a session at construction through
//! `PeerSyncSessionDeps`, and their deny-by-default stand-ins. Also home to
//! the local-capture and root-authority ports the daemon's convergence
//! executor consumes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use yadorilink_replica_domain::ids::VersionHash;

use crate::rate_limiter::RateLimiters;

/// Lets the convergence executor ask whether the path it's about to
/// reconcile against a peer's update has a local change still sitting, undispatched,
/// in that link's debounce accumulator (`debounce::run_debouncer`'s
/// `FlushPathRequest` handling) — and if so, force it to flush and be
/// captured into the index *before* the executor compares or
/// materializes the path, so a peer's write
/// or tombstone for the same path can never race ahead of it. A
/// manually-written `Pin<Box<dyn Future>>`-returning method, not an `async
/// fn`, since this needs to be *dyn*-callable through `Arc<dyn
/// PendingLocalChangeFlush>` — native `async fn` in traits isn't
/// object-safe without this same boilerplate, and this crate has no
/// `async_trait` dependency to hide it behind. Outcome of a targeted
/// local-flush round trip
/// (`PendingLocalChangeFlush::flush_pending_local_change` /
/// `flush_case_fold_sibling`), through this link's debounce-accumulator
/// channel. That channel is small and shared by every concurrent peer
/// message handler reconciling a path against this link — under a
/// duplicate-delivery storm it can back up, so the round trip is bounded
/// rather than awaited unconditionally. `Settled` means the local side is
/// safely accounted for (flushed, or genuinely nothing pending) and the
/// peer change may proceed to native admission. `RetryRequired` means this
/// round trip could not complete its bound (the enqueue or the reply timed
/// out) — the local pending edit's state relative to the incoming peer
/// change is unknown, so admitting the peer change now would risk silently
/// clobbering it; the caller must defer this change instead (it will be
/// re-requested by anti-entropy).
///
/// `RetryRequired` also covers a local edit the flush could not capture (a
/// file that changed while it was read, a capture that failed): a caller
/// about to write to the path must not proceed on it.
#[must_use = "a caller about to write to the path must not proceed on RetryRequired"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingLocalFlushOutcome {
    Settled,
    RetryRequired,
}

impl PendingLocalFlushOutcome {
    /// Both guards settled only if each did.
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Settled, Self::Settled) => Self::Settled,
            _ => Self::RetryRequired,
        }
    }
}

pub trait PendingLocalChangeFlush: Send + Sync {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>>;

    /// Like `flush_pending_local_change`, but for the *other* case-variant
    /// path that would collide with `rel_path` on a case-insensitive
    /// filesystem, rather than `rel_path` itself — see
    /// `PeerSyncSession::flush_case_fold_sibling_before_reconcile`'s doc
    /// comment for why this exists as a separate call.
    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>>;

    /// Captures whatever `rel_path` holds on disk right now, its absence
    /// included: like `flush_pending_local_change`, and in addition, when
    /// nothing answers to the path, the deletion of a path the index still
    /// holds live -- without waiting for a watcher event that may not have
    /// been processed yet. For a caller that has established the disk moved
    /// on from a change this device captured and must capture the newer
    /// state rather than project the older one.
    ///
    /// The default captures what `flush_pending_local_change` does, which
    /// leaves a deletion to the watcher.
    fn capture_local_path_state<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        self.flush_pending_local_change(group_id, rel_path)
    }
}

/// Mirrors `PendingLocalChangeFlush`'s injection shape exactly (see that
/// trait's own doc comment for why this crate needs the daemon to inject
/// per-group lookups like this rather than depending on `yadorilink-daemon`
/// directly), for a different seam: every `SyncState` mutation the
/// convergence executor makes (index/native state/materialization-state
/// writes) requires a `root_commit::RootCommitPermit`, minted from a
/// `LinkOperation` admitted against the per-link `root_commit::RootLease`
/// this provides for `group_id`. `None` means this device has no live,
/// established link for that group right now -- the caller must treat that
/// exactly like any other "this link isn't available" failure, never
/// synthesize a permissive fallback lease.
pub trait RootCommitAuthorityProvider: Send + Sync {
    fn root_lease_for(
        &self,
        group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>>;
}

/// Deny-by-default implementations of this session's two handoff
/// capability traits, used by [`PeerSyncSessionDeps::standalone`].
struct DeniedHandoffLeaseResponder;

impl HandoffLeaseResponder for DeniedHandoffLeaseResponder {
    fn request_handoff_lease<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn release_handoff_lease<'a>(
        &'a self,
        _group_id: &'a str,
        _lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
    }
}

struct DeniedHandoffTicketResponder;

impl HandoffTicketResponder for DeniedHandoffTicketResponder {
    fn request_handoff_ticket<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn release_handoff_ticket<'a>(
        &'a self,
        _group_id: &'a str,
        _target_device_id: &'a str,
        _lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

struct DeniedCustodyRehomeResponder;

impl CustodyRehomeResponder for DeniedCustodyRehomeResponder {
    fn rehome<'a>(
        &'a self,
        _from_peer: &'a str,
        _group_id: &'a str,
        _file_path: &'a str,
        _version_hash: VersionHash,
        _attempt_token: [u8; 16],
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
    }
}

/// Everything a session is given that is not its peer, its transport or
/// its storage: the two handoff responders it answers service RPCs
/// through, and the runtime knobs the daemon sets from shared global state.
///
/// A call site that overrides one of them starts from [`Self::standalone`]
/// and uses struct-update syntax instead of repeating all of them.
pub struct PeerSyncSessionDeps {
    pub rate_limiters: Arc<RateLimiters>,
    /// `None` means no serve budget was installed, which
    /// `handle_block_request` treats as fail-closed -- see
    /// `block_serve_engine`'s field doc.
    pub block_serve_engine: Option<Arc<crate::block_serve::BlockServeEngine>>,
    pub handoff_lease_responder: Arc<dyn HandoffLeaseResponder>,
    pub handoff_ticket_responder: Arc<dyn HandoffTicketResponder>,
    pub custody_rehome_responder: Arc<dyn CustodyRehomeResponder>,
}

impl Clone for PeerSyncSessionDeps {
    fn clone(&self) -> Self {
        Self {
            rate_limiters: self.rate_limiters.clone(),
            block_serve_engine: self.block_serve_engine.clone(),
            handoff_lease_responder: self.handoff_lease_responder.clone(),
            handoff_ticket_responder: self.handoff_ticket_responder.clone(),
            custody_rehome_responder: self.custody_rehome_responder.clone(),
        }
    }
}

impl PeerSyncSessionDeps {
    /// Deny-by-default responders and unlimited / default values for the
    /// knobs.
    ///
    /// Capabilities that need daemon or coordination-plane state deny
    /// requests. Nothing is represented by absence.
    pub fn standalone() -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        Self {
            rate_limiters: Arc::new(RateLimiters::unlimited()),
            block_serve_engine: Some(crate::block_serve::BlockServeEngine::new(
                64 * GIB,
                16 * GIB,
                32 * GIB,
                64,
            )),
            handoff_lease_responder: Arc::new(DeniedHandoffLeaseResponder),
            handoff_ticket_responder: Arc::new(DeniedHandoffTicketResponder),
            custody_rehome_responder: Arc::new(DeniedCustodyRehomeResponder),
        }
    }

    /// [`Self::standalone`] with no block-serve budget installed, which
    /// makes `handle_block_request` fail closed. The shape a caller
    /// constructing a session directly against this module -- with no
    /// device-wide serve engine to share -- gets.
    pub fn denied() -> Self {
        Self { block_serve_engine: None, ..Self::standalone() }
    }
}

/// A target device's answer to its own `HandoffLeaseResponder`, carrying
/// exactly what the service-RPC lane's `HandoffLease` response needs: the
/// coordination-plane-issued lease id, the digest of the durability-root set
/// the target actually verified and pinned against that lease, and its
/// expiry. Kept as a plain struct here (rather than depending on a wire
/// type directly) so `HandoffLeaseResponder` implementors don't need to
/// reason about wire framing, mirroring how `request_version_present`'s own
/// `bool` return keeps its callers wire-free.
#[derive(Debug, Clone)]
pub struct PeerHandoffLeaseGrant {
    pub lease_id: String,
    /// This device's own durability-roots digest: the 32-byte SHA-256 over
    /// the sorted `(path, change::VersionHash)` set of every durability root
    /// it retains — the same digest a source-side readiness check computes.
    pub root_digest: [u8; 32],
    pub expires_at_unix: i64,
    /// The lease's lifetime as a duration, for a caller that must outlast it
    /// without comparing its own clock to the coordination plane's.
    pub ttl_seconds: i64,
}

/// Returns `None` when this device could not obtain a live lease this
/// round (its own readiness check failed, it has no coordination-plane
/// config, the coordination-plane request itself failed, or the atomic
/// local pin aborted) — the responder answers the peer `granted = false`
/// in every one of those cases, exactly as if the request had never been
/// understood at all, never distinguishing the reason over the wire.
pub trait HandoffLeaseResponder: Send + Sync {
    fn request_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>>;

    /// Ends the lease. `true` only when it is ended for good (a later attempt
    /// to use it fails); the answer is what the asker's own close of the group
    /// waits for.
    fn release_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
        lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// Caller-injected guard factory that lets a session serialize creation of
/// new block references with daemon-level physical deletion.
pub trait BlockWriteActivityProvider: Send + Sync {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_>;
}

/// A device's answer to its own `HandoffTicketResponder`, carrying exactly
/// what the service-RPC lane's `HandoffTicket` response needs. Unlike
/// `PeerHandoffLeaseGrant`, there is no `root_digest` here: the requester
/// (the operating device removing/revoking this one) has no root set of its
/// own to compare against -- it trusts `granted` as this device's own
/// authenticated attestation of ITS OWN roots. `lease_id`/`target_device_id`
/// are both `None` when the device's root set was empty (vacuously ready --
/// nothing to hand off), and both `Some` otherwise: `target_device_id` is
/// the confirming peer (C) the lease was obtained from, which the operating
/// device must present alongside `lease_id` to the coordination plane's
/// lease-guarded role-loss commit -- a lease id alone does not identify
/// which `(group, target)` pair to atomically re-verify it against.
#[derive(Debug, Clone)]
pub struct PeerHandoffTicketGrant {
    pub lease_id: Option<String>,
    pub target_device_id: Option<String>,
    pub expires_at_unix: i64,
}

/// Lets a `PeerSyncSession` answer an incoming `HandoffTicketRequest` by
/// bridging to the daemon's own removed-device-ticket machinery
/// (`DaemonState::obtain_own_handoff_ticket`), the same caller-injected
/// trait-object shape as `HandoffLeaseResponder` above and for the same
/// reason. Returns `None` when this device could not obtain a live lease
/// for its own root set this round (no confirming peer holds its whole
/// root set, its own coordination-plane request failed, etc.) -- the
/// responder answers the peer `granted = false` in every one of those
/// cases, exactly as `HandoffLeaseResponder` already does.
pub trait HandoffTicketResponder: Send + Sync {
    fn request_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>>;

    fn release_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Lets a session answer a full replica that is about to stop being one and
/// asks this device, the requester of a custody lease it holds, to move that
/// custody elsewhere (`ServiceRequest::CustodyRehome`). The implementation
/// owns the decision: it knows which holds this device recorded and what the
/// path still depends on, and `from_peer` is the authenticated peer the
/// request arrived from, never a name the request supplies.
///
/// `true` only when this device no longer depends on `from_peer`'s lease
/// and that lease is released; every refusal and failure is `false`.
pub trait CustodyRehomeResponder: Send + Sync {
    fn rehome<'a>(
        &'a self,
        from_peer: &'a str,
        group_id: &'a str,
        file_path: &'a str,
        version_hash: VersionHash,
        attempt_token: [u8; 16],
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}
