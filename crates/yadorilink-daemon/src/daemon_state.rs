//! Shared, in-process state for the running daemon: the durable sync
//! index/block store (survives restarts), plus purely in-memory
//! bookkeeping the control socket (section 7.6/7.7) reports on — live peer
//! connectivity and per-link watcher tasks, neither of which makes sense
//! to persist.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::broadcast;
use yadorilink_filesystem_sync::block_liveness::{
    BlockLivenessGate, BlockPhysicalDeletionGuard, BlockReferenceWriteGuard,
};
use yadorilink_local_storage::BlockStore;
use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::local_op::PolicyUnavailable;
use yadorilink_replica_engine::custody::{CustodyStamp, FullReplicaCustody};

#[cfg(test)]
use crate::background_custody::BackgroundCustodyEvidence;
use crate::background_custody::BackgroundCustodyOutcome;
#[cfg(test)]
use crate::durability_service::CustodyConfirmer;
use crate::durability_service::{DurabilityEvidence, GroupDurabilityStatus};
use crate::handoff_proof::StrongHandoffProof;
use yadorilink_peer_session::peer_session::{
    BlockWriteActivityProvider, HandoffLeaseResponder, HandoffTicketResponder,
    PeerHandoffLeaseGrant, PeerHandoffTicketGrant, PeerSyncSession,
};
use yadorilink_peer_session::rate_limiter::RateLimiters;
use yadorilink_replica_domain::session_state::{
    DurabilityRoot, DurabilityRoots, MembershipCommitMode, MembershipDurabilityScope,
    MembershipOperationAction, MembershipOperationState, RoleLossAction, RoleLossOperationParams,
    RoleLossOperationState, RootSetSummary,
};
use yadorilink_sync_sqlite::handoff_lease::HandoffLeaseState;

use crate::change_policy::GroupPolicyState;
use crate::governance_config::GovernanceConfigStore;
use crate::reporting::ReportingStorage;
use crate::supervise;

mod offline_authorization;
pub(crate) use offline_authorization::is_within_offline_horizon;
pub use offline_authorization::{AuthorizationProvenance, OFFLINE_AUTHORIZATION_HORIZON_SECS};
mod peer_authority;
pub use peer_authority::PeerAuthorityState;

/// How often the retention-expiry sweep
/// runs — see its spawn site in `DaemonState::new` for why this is a much
/// longer interval than the other periodic sweeps in this file.
pub(crate) const RETENTION_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
const MATERIALIZATION_REPAIR_SWEEP_INTERVAL: Duration = Duration::from_secs(90);

/// Test-only hook overriding the value every subsequently-constructed
/// `DaemonState`'s materialization-repair scheduler starts with, closing a
/// race `set_materialization_repair_sweep_interval` alone cannot: that
/// setter only takes effect on the scheduler's *next* sleep, so a caller
/// racing against `DaemonState::new` (which has already spawned the
/// scheduler by the time it returns) cannot guarantee its override lands
/// before that task's first read — especially on a multi-threaded runtime,
/// where the newly-spawned task can start executing on a different worker
/// thread immediately, with no `.await` needed to hand it control. A test
/// that needs to prove convergence with NO help from this periodic sweep
/// needs the FIRST sleep, not just subsequent ones, to already
/// reflect the override. Set this before constructing any `DaemonState`
/// whose scheduler should start with it.
static MATERIALIZATION_REPAIR_SWEEP_INTERVAL_OVERRIDE_FOR_TESTS: std::sync::OnceLock<
    Mutex<Option<Duration>>,
> = std::sync::OnceLock::new();

pub fn set_default_materialization_repair_sweep_interval_for_tests(interval: Duration) {
    *MATERIALIZATION_REPAIR_SWEEP_INTERVAL_OVERRIDE_FOR_TESTS
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Some(interval);
}

fn default_materialization_repair_sweep_interval() -> Duration {
    MATERIALIZATION_REPAIR_SWEEP_INTERVAL_OVERRIDE_FOR_TESTS
        .get()
        .and_then(|m| *m.lock().unwrap_or_else(|p| p.into_inner()))
        .unwrap_or(MATERIALIZATION_REPAIR_SWEEP_INTERVAL)
}

pub use crate::durability_service::set_default_custody_confirmation_sweep_interval_for_tests;

/// How often the role-loss-operation reconciliation sweep
/// (`ReplicaRoleService::reconcile_role_loss`, scheduled by `RecoveryJob`)
/// retries any journal row left
/// mid-flight by a crash or a compensation attempt that couldn't reach the
/// coordination plane. Matches `MATERIALIZATION_REPAIR_SWEEP_INTERVAL`'s
/// cadence rather than the much longer retention-expiry one: a role-loss
/// split state is a user-visible correctness gap the same way a broken
/// materialization is, not a slow-moving housekeeping concern.
pub(crate) const ROLE_LOSS_RECONCILIATION_SWEEP_INTERVAL: Duration = Duration::from_secs(90);
/// Overall bound on `confirm_version_present_via_peer`'s concurrent fan-out
/// across every candidate peer. Each individual `request_version_present`
/// already enforces its own ~10s per-request timeout (`peer_session.rs`), and
/// every candidate is now queried concurrently rather than one after another,
/// so the realistic wall-clock cost of a full sweep is already that single
/// ~10s window regardless of how many peers are queried — not the old
/// N-peers-times-10s worst case. This wraps the whole fan-out in one slightly
/// longer timeout anyway, as a defense-in-depth backstop, rather than relying
/// solely on each query's own internal bound.
pub(crate) const VERSION_PRESENT_QUERY_OVERALL_TIMEOUT: Duration = Duration::from_secs(12);

/// This crate's own build version, parsed as semver — the "current
/// running version" `update::manifest::LocalContext` compares manifest
/// entries against. `CARGO_PKG_VERSION` is always the exact
/// `workspace.package.version` string (`Cargo.toml`), which is already
/// strict semver in this workspace, so a parse failure here would mean a
/// broken build, not a runtime condition to handle gracefully — falling
/// back to `0.0.0` (never matches any real applicable-update comparison
/// as "newer", so this fails closed to "never auto-update" rather than
/// panicking the whole daemon over a version-string typo).
fn current_crate_version() -> semver::Version {
    semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .unwrap_or_else(|_| semver::Version::new(0, 0, 0))
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl FullReplicaCustody for DaemonState {
    fn confirm_exact_version(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        self.full_replica_custody_confirmation(group_id, path, version_hash, blocks)
    }

    fn confirmation_still_valid(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        stamp: &CustodyStamp,
    ) -> bool {
        self.custody_confirmation_still_valid(group_id, path, version_hash, stamp)
    }
}

/// The outcome of [`DaemonState::resolve_group_policy`] — the single
/// group-policy/authorization resolution point that both local emission and
/// inbound admission consume. Collapsing "not introduced", "not loaded yet",
/// "own-verification-stale", and "coordinator-flagged invalid" into one value
/// keeps the fail-closed decision in exactly one place.
pub enum GroupPolicyResolution {
    /// A verified policy snapshot is loaded; authorize against it.
    Verified(GroupPolicyState),
    /// Fail closed: the group's policy is stale (own verification failure or
    /// coordinator-flagged invalid), or it is already introduced but its
    /// verified policy has not loaded yet this run. No local emission, no
    /// admission — the same withholding the stale-policy case already gets.
    Withhold,
    /// The genuine pre-policy bootstrap window: the group has never been
    /// introduced and no snapshot has ever existed, so the placeholder stamp
    /// is still the legitimately accepted authorization on both sides.
    Bootstrap,
}

/// Whether a folder group can be used locally right now — the answer to
/// [`DaemonState::group_readiness`].
///
/// Deliberately distinguishes "not ready yet, and this resolves itself"
/// from "not ready, and something is wrong". `GroupPolicyResolution`
/// collapses both into `Withhold` because for a fail-closed authorization
/// decision they are the same answer; for a caller deciding whether to wait
/// or to report a problem they are not, and collapsing them is why a
/// freshly created group was indistinguishable from a broken one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupReadiness {
    /// No link row for this group on this device. Nothing will change on its
    /// own; the group has to be created or joined first.
    NotJoined,
    /// Linked, and waiting for its verified policy to arrive. Transient and
    /// self-resolving: a newly created or joined group sits here until the
    /// coordination plane's netmap carrying its policy lands.
    AwaitingPolicy,
    /// A policy was loaded and has since been distrusted — own verification
    /// failure, or coordinator-flagged invalid. Unlike `AwaitingPolicy` this
    /// is not expected to clear by simply waiting.
    PolicyStale,
    /// Linked, policy verified (or legitimately in the pre-policy bootstrap
    /// window), and this device may author into the group.
    Ready,
}

impl GroupReadiness {
    pub fn is_ready(self) -> bool {
        matches!(self, GroupReadiness::Ready)
    }
}

/// One Track Send grant-derived peer -- see `DaemonState::send_grant_peers`'s
/// own field doc comment. `grant_id`/`nonce` let a caller cross-check an
/// inbound offer's OWN claimed grant against what this device was actually
/// told (by its own `request_grant` response, or the coordination plane's
/// push) to expect from `signing_key`, before ever spending a coordination-
/// plane round trip on an obviously-wrong one -- defense in depth, not the
/// load-bearing check: the Worker's own atomic `consumeSendAuthorization`
/// guard is what actually decides, and `device_id` here (never anything an
/// offer's payload claims) is what makes that call's `senderDeviceId`
/// trustworthy in the first place.
#[derive(Debug, Clone)]
pub struct SendGrantPeer {
    pub device_id: String,
    pub signing_key: [u8; 32],
    /// Where the device's iroh endpoint answers, from the grant material.
    pub reachability: crate::coordination_client::SubstrateReachability,
    pub grant_id: String,
    pub nonce: String,
    pub expires_at_unix: i64,
}

/// One link's claim on its disk-reconcile backstop pass; see
/// [`DaemonState::begin_backstop_pass`].
pub(crate) struct BackstopPass {
    state: Arc<DaemonState>,
    local_path: String,
}

impl Drop for BackstopPass {
    fn drop(&mut self) {
        self.state
            .backstop_in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.local_path);
    }
}

/// See `DaemonState::provider_content_probe`.
pub(crate) type ProviderContentProbe = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

pub struct DaemonState {
    pub device_id: String,
    /// Links whose disk-reconcile backstop pass is still running, by local
    /// path. A later sweep leaves such a link alone instead of stacking a
    /// second whole-folder pass on the first.
    backstop_in_flight: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Invite acceptances waiting on this account's decision, per folder group, as the latest
    /// netmap reported them. Display only: replaced whole by each netmap, empty until the first,
    /// and never read for authorization.
    pending_approvals: std::sync::RwLock<std::collections::HashMap<String, u32>>,
    /// Wakes the custody-hold reconciler task (`crate::custody_holds`).
    pub(crate) custody_hold_wake: Arc<tokio::sync::Notify>,
    /// The daemon's single owner of replica state: every production read
    /// and provider registration goes through this field (there is no
    /// separate `SyncState` handle on `DaemonState`).
    pub replica_coordinator: Arc<crate::replica_coordinator::ReplicaCoordinator>,
    pub block_store: Arc<dyn BlockStore + Send + Sync>,
    /// Coalesces concurrent `FETCH_DATA`-driven `hydration::hydrate`
    /// calls for the same path onto one real attempt -- see
    /// `hydration_single_flight`'s own module doc for why this is
    /// layered outside, not a replacement for, `hydrate_inner`'s
    /// per-path lock. Per daemon-instance state, matching
    /// `ReplicaCoordinator::path_lock_registry`'s own reasoning (never a
    /// process-wide `static`, which a test's many in-process daemon
    /// instances would wrongly share).
    pub hydrate_single_flight: crate::hydration_single_flight::HydrateSingleFlight,
    /// Opens waiting on the user's behalf that are not yet `Hydrating` rows (queued for an
    /// assembly slot); part of `LinkStatus.requested_content_count`.
    pub requested_opens: Arc<crate::requested_opens::RequestedOpens>,
    /// Shared, device-wide block-serve credit/coalescing engine
    /// -- one instance for the whole daemon, handed to every
    /// `PeerSyncSession` this device constructs via
    /// `PeerSyncSession::set_block_serve_engine` (`peer_orchestrator.rs`),
    /// exactly like `block_store` above. See
    /// `yadorilink_peer_session::block_serve`'s own doc comment for why the
    /// engine type itself lives in that crate rather than this one.
    pub block_serve_engine: Arc<yadorilink_peer_session::block_serve::BlockServeEngine>,
    /// Live peer sessions and per-peer connectivity, updated as
    /// `PeerChannel`s connect/upgrade -- see
    /// `crate::peer_registry::PeerRegistry`'s own doc comment. Reached only
    /// through its own methods; the maps themselves are private.
    pub peers: Arc<crate::peer_registry::PeerRegistry>,
    /// This device's iroh connectivity: its published relay URLs and
    /// substrate endpoint, each peer's plane-reported substrate reachability,
    /// and the only way to bind an iroh endpoint -- see
    /// `PeerConnectivityRuntime`'s own doc comment.
    pub peer_connectivity: Arc<crate::peer_connectivity_runtime::PeerConnectivityRuntime>,
    /// Track Send's own service, published by `crate::send_transfer::run`
    /// once the reconciliation stack's iroh endpoint exists (Track Send is
    /// served on that endpoint's own ALPN). `None` until then; `crate::send_transfer::SendTransferService`/
    /// `InboxQueries` report a clear "not ready yet" error for that
    /// window rather than blocking a control-socket request on it.
    pub send_service: tokio::sync::OnceCell<Arc<yadorilink_send::SendService>>,
    /// Track Send grant-derived peers this device currently knows about
    /// through the coordination plane's short-lived, sender+receiver-bound
    /// rendezvous grant primitive -- never through ordinary netmap
    /// membership (see `crate::send_transfer`'s own module doc comment for
    /// the full design). Populated two ways: this device's own
    /// `request_send_authorization` response names the RECEIVER it may now
    /// reach, and a `"send_authorization"` push on the netmap WebSocket
    /// subscription names a SENDER it should now expect. A plain `Vec`
    /// rather than a `HashMap`, because the cardinality is tiny (minutes-
    /// scale TTL, one entry per outstanding grant) and it needs to be
    /// looked up by EITHER signing key or device id depending on the
    /// caller -- see `record_send_grant_peer`/`send_grant_peer_by_key`/
    /// `send_grant_peer_by_device_id`.
    pub send_grant_peers: Mutex<Vec<SendGrantPeer>>,
    /// Which peers are authorized for what: netmap-derived signing keys,
    /// writer and full-replica status, the membership generation that
    /// versions them, the pinned coordination service key, and per-group
    /// policy state -- see `PeerAuthorityState`'s own
    /// doc comment. Reached only through its own methods.
    pub authority: Arc<PeerAuthorityState>,
    /// This device's Ed25519 change-history signing key, wired once at startup
    /// when the device is registered. `None` (the default) leaves signed
    /// change-history emission off — see `set_device_signing_key`.
    pub device_signing_key: Mutex<Option<ed25519_dalek::SigningKey>>,
    /// When this replica folds a group's history: `DaemonConfig.fold`, set
    /// by the daemon's composition root; read when the reconciliation stack
    /// starts its fold scheduler.
    /// Overridable copy of `MATERIALIZATION_REPAIR_SWEEP_INTERVAL` — same
    /// mutable-after-construction shape as `PeerSyncSession::
    /// maintenance_reconcile_interval` (`StdMutex`, opt-in override via
    /// `set_materialization_repair_sweep_interval`), for the identical
    /// reason: every existing call site keeps compiling and behaving
    /// identically at the 90s default, and a test that needs the backstop
    /// to fire faster than production's cadence can opt in without a
    /// constructor parameter.
    materialization_repair_sweep_interval: Mutex<Duration>,
    /// local_path -> that link's single runtime record: its
    /// folder-watcher tasks (the debounce accumulator and the executor
    /// that consumes its flushes, plus the periodic repair and
    /// dirty-journal tasks), its targeted-flush handle, and its sync-root
    /// single-instance OS lock. All three used to be three independently-
    /// updated maps (`link_tasks`, `link_flush_handles`, `link_root_locks`)
    /// keyed the same way but published and torn down at different points
    /// in `start_link_watch_inner`/`stop_link_watch` — which is exactly
    /// what let a peer session's targeted flush
    /// (`LinkFlushHandle::flush_pending_local_change` and friends) and the
    /// disk-reconcile backstop sweep (`run_disk_reconcile_backstop_sweep`),
    /// both of which take their own `Arc<LinkFlushHandle>` clone
    /// independent of any map, keep committing index/native state writes after
    /// `stop_link_watch` had already removed the entry and dropped the
    /// root lock. `LinkRuntime` closes that gap with `LinkFlushHandle`'s
    /// own operation fence (`LinkOpFence`): `stop_link_watch` aborts and
    /// awaits every task exactly as before, then additionally waits for
    /// that fence to drain (every in-flight targeted flush or backstop
    /// call to actually finish, and every new one to be refused) before
    /// dropping `root_lock`. See `LinkRuntime`'s own doc.
    ///
    /// A `LinkSlot::Starting` placeholder is reserved via `links` as the
    /// very first step of `start_link_watch_inner` (via
    /// `LinkSlotStartingGuard` -- see its own doc for the start-vs-stop
    /// zombie-runtime race this closes), replaced by `LinkSlot::Ready` once
    /// every fallible step has succeeded, and removed as a single entry by
    /// `stop_link_watch`. See `crate::link_registry::LinkRegistry`'s own
    /// doc comment for its exact coordination; fields are private, reached
    /// only through its own methods.
    pub links: Arc<crate::link_registry::LinkRegistry>,
    /// Test-only override consulted by `root_lease_for` before its normal
    /// `link_runtimes` lookup -- lets a unit test that only calls
    /// `sync_state.add_link(...)` (never a real `start_link_watch`, which
    /// spins up a watcher, debounce/executor/repair tasks, and an OS-level
    /// root lock the test has no interest in) still exercise a production
    /// mutation path that requires a live `RootCommitPermit`
    /// (`hydration::hydrate_inner`, `hydration::evict`, ...). Not reachable
    /// outside test builds -- see this field's own `cfg` -- so it is not a
    /// production bypass, the same seam `root_commit::RootLease::
    /// for_tests()` is for tests that hold a `SyncState` handle directly
    /// rather than a `DaemonState`.
    #[cfg(any(test, feature = "test-support"))]
    pub test_root_commit_authorities:
        Mutex<HashMap<String, Arc<yadorilink_root_authority::root_commit::RootLease>>>,
    /// Test-only override of the per-root on-demand decision (`provider_gate`: a plain root never
    /// allows it; only a ready provider root with the provider-roots switch on does) -- `None` (the default)
    /// leaves the real decision in force. Per daemon, not thread-local, because a multi-threaded Tokio
    /// integration test's async task is not guaranteed to run on the OS thread the test set it from.
    /// Not reachable outside test builds -- see this field's own `cfg`.
    #[cfg(any(test, feature = "test-support"))]
    pub test_on_demand_allowed: Mutex<Option<bool>>,
    /// Every supervised background task this state started (the convergence
    /// engine, the repair sweeps, ...), kept so a harness that replaces the
    /// state with a new one over the same database can stop the old ones.
    /// Production restarts by exiting the process, so it never needs this;
    /// without it a replaced state's engine keeps claiming the shared
    /// database's obligations and every task keeps running against folders
    /// the harness has already deleted.
    #[cfg(any(test, feature = "test-support"))]
    pub background_tasks: Mutex<Vec<tokio::task::AbortHandle>>,
    /// Test-only stand-in for the coordination plane the fold loop asks for
    /// seal authorizations (`fold_scheduler::spawn`): consulted in place of
    /// a `ProductionCheckpointSource` built from
    /// [`Self::coordination_client_config`], for a harness with no
    /// coordination plane to reach. The authorizations it returns are
    /// verified exactly as a production one is. Not reachable outside test
    /// builds -- see this field's own `cfg`.
    #[cfg(any(test, feature = "test-support"))]
    pub test_seal_checkpoint_source:
        Mutex<Option<Arc<dyn crate::checkpoint_source::CheckpointSource>>>,
    /// This device's observability-facing runtime state -- see
    /// `crate::runtime_telemetry::RuntimeTelemetry`'s own doc comment.
    pub telemetry: Arc<crate::runtime_telemetry::RuntimeTelemetry>,
    /// Graceful-shutdown support: incremented for the duration of
    /// every `on_local_native_commit` fan-out so
    /// `main.rs`'s shutdown path can wait for in-flight broadcasts to
    /// drain (bounded by a timeout) before tearing the process down,
    /// instead of possibly cutting one off mid-send.
    in_flight_broadcasts: AtomicI64,
    /// The control socket's `Shutdown` handler used to call
    /// `std::process::exit(0)` directly, a second shutdown path entirely
    /// separate from SIGTERM/SIGINT handling — neither aborted watcher
    /// tasks, checkpointed anything, or drained broadcasts. Sending `true`
    /// here instead routes it through the exact same graceful-shutdown
    /// code in `main.rs` that the signal handlers use; `main.rs` holds the
    /// matching `Receiver` (via `subscribe`) in its top-level `select!`.
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Serializes safe-stop requests; `true` once one has brought the daemon to a safe point
    /// and begun its exit. See `adapters::runtime::safe_stop`.
    pub(crate) safe_stop_committed: tokio::sync::Mutex<bool>,
    /// Local consent/counters/error-candidate/
    /// queue storage, the type that IPC dispatch and
    /// severe-error hooks operate on. Opening this never writes anything
    /// to disk by itself (see `reporting::mod`'s doc comment), so adding
    /// this field is safe for every existing `DaemonState::new` call site,
    /// test or production.
    pub reporting: Arc<ReportingStorage>,
    /// On-disk persistence for the
    /// global rate limits / headroom override (`governance_config`'s doc
    /// comment). Opening this never writes anything to disk by itself,
    /// mirroring `reporting`'s "safe for every existing call site" property.
    pub governance_config: Arc<GovernanceConfigStore>,
    /// The single, shared upload/
    /// download token-bucket pair every `PeerSyncSession` this daemon
    /// constructs is wired to (`peer_orchestrator::spawn_peer_session`,
    /// via `PeerSyncSession::set_rate_limiters`) — this is what makes
    /// "concurrent per-peer fetches share one global ceiling"
    /// true: they all draw from these exact two `Arc<TokenBucket>`
    /// instances, not independent per-session copies. Initialized from
    /// `governance_config` at construction; `GovernanceCommandPort::
    /// set_limits` (`adapters::runtime::governance`) re-reads config and
    /// updates these same buckets' rates in place (live reload) rather
    /// than replacing the `Arc`, so every already-connected session picks
    /// up a change on its very next token consumption.
    pub rate_limiters: Arc<RateLimiters>,
    /// Mirrors `enable_disk_headroom_enforcement`'s effect for the block
    /// store, but for `PeerSyncSession`s constructed *after* it's set:
    /// `peer_orchestrator::spawn_peer_session` reads this when wiring a
    /// newly-connected session's `set_headroom_enforced`. `false` by
    /// default (every test in this crate that drives real peer sessions —
    /// `multi_peer_hydration`, `e2e_three_devices`, etc. — goes through the
    /// exact same `spawn_peer_session`, so this needs the same "off unless
    /// `main.rs` opts in" default the block store gets).
    disk_headroom_enforcement_enabled: std::sync::atomic::AtomicBool,
    /// Test-only headroom reserve for the link preflight's free-space reading, so a test does not
    /// depend on how full the host's disk is. Production passes no override.
    #[cfg(any(test, feature = "test-support"))]
    link_preflight_headroom_override: Mutex<Option<u64>>,
    /// This device's durability confirmation/latch state -- see
    /// `crate::durability_service::DurabilityService`'s own doc comment.
    /// `durability.group_durability_latch`: group_id -> latched
    /// `Unknown` override, set by
    /// [`Self::latch_group_durability_unknown`] whenever a force override
    /// bypasses this daemon's own durability handoff gate for that group.
    /// A group with NO entry here is not thereby "Protected" — its status is
    /// still derived live (see [`Self::group_durability_status`]); presence
    /// here only ever pins a group to `Unknown` until a later
    /// whole-group handoff re-check clears it. The set is loaded from and
    /// written through `SyncState` so force history survives restart.
    durability: Arc<crate::durability_service::DurabilityService>,
    /// operation_id -> consecutive `TransientFailure` count from
    /// `EnrollmentRecoveryService::reconcile_once`'s activate retries, so a
    /// coordination-plane outage (or any other unconfirmable activate) that
    /// outlasts `enrollment_recovery_service::TRANSIENT_ESCALATION_THRESHOLD` sweeps
    /// is escalated -- a loud, stable log line, not just the ordinary
    /// per-sweep debug/info trace -- instead of retrying invisibly forever.
    /// The retry itself is never abandoned and the local link/marker are
    /// never rolled back on a mere attempt count (only a `Deleted` outcome
    /// does that): this is a visibility bound, not a correctness one.
    /// In-memory only, like `degraded_links` above: it resets on restart,
    /// which is fine -- a fresh process re-earns its own escalation budget
    /// rather than inheriting a stale one, and the coordination plane's own
    /// TTL sweep is the ultimate backstop regardless of how long this has
    /// been climbing.
    pending_enrollment_transient_attempts: Mutex<HashMap<String, u32>>,
    /// Check/download/verify/install
    /// orchestration, persisted update policy, and the pinned trust root
    /// for manifest signature verification.
    pub update_manager: Arc<crate::update::manager::UpdateManager>,
    /// Incremented for the duration of
    /// every sync-critical write this daemon performs — the initial
    /// folder scan and every debounced flush's chunk/index/broadcast pass
    /// (the daemon's own `LinkRuntimeController::start`), and on-demand-sync's
    /// hydrate/evict/restore materialization writes (`hydration.rs`).
    /// Mirrors `in_flight_broadcasts` and `BroadcastGuard`'s exact
    /// counter-plus-RAII-guard shape, so a write path that returns early
    /// or panics still gets counted back out. `is_write_safe_point`
    /// (below) is exactly "this counter is zero" — install is deferred
    /// whenever it isn't, per the "Safe Update Windows" decision.
    active_write_ops: AtomicI64,
    /// When this `DaemonState`
    /// (i.e. this daemon process) was constructed — feeds the diagnostics
    /// bundle's coarse `daemon.uptime_bucket` field via `uptime` below.
    /// In-memory only, like `task_liveness`/`degraded_links` above:
    /// naturally resets on every restart, which is exactly "time since
    /// this daemon started."
    started_at: std::time::Instant,
    /// Unix seconds of the most recent
    /// local-change/peer-reconciliation/hydration activity — the idle
    /// scheduler (`gc::maybe_run_idle_sweep`) waits for this to be at
    /// least `gc::GC_IDLE_THRESHOLD` in the past before attempting a
    /// sweep. Updated by `begin_write_activity` (covers the local-change
    /// flush executor and hydration's hydrate/evict/restore paths — every
    /// existing call site of that guard) and by native
    /// replication (covers peer reconciliation: a delta batch admitted from
    /// a peer, or a recovery bundle joined). Initialized to "now" at
    /// construction, so a freshly-started daemon waits out a full idle
    /// period before its very first sweep rather than immediately racing
    /// startup's own link-resume/repair work.
    last_activity_unix: AtomicI64,
    /// GC scheduling coordination and
    /// last-run bookkeeping — see `gc_state::GcState`'s doc comment.
    pub gc: Arc<crate::gc_state::GcState>,
    /// This device's coordination-plane address + access token, set once at
    /// startup (`app.rs`, alongside the other production-only coordination
    /// wiring: NAT traversal, pending-enrollment
    /// reconcile) whenever a registered device and a stored access token are
    /// both available. `None` in most unit tests and on a device that has never registered/logged in — every
    /// caller (currently only the handoff-lease request path,
    /// [`Self::request_handoff_lease`]) treats that as "coordination plane
    /// unavailable" and fails closed (no lease requested), the same
    /// unreachable-coordination-plane handling every other
    /// `coordination_client` call already has. A `OnceLock` rather than a
    /// `Mutex`/`RwLock`: this is set exactly once, early in startup, and never
    /// changes for the rest of the process's life (an access-token refresh
    /// from a later re-login is a pre-existing gap every other
    /// `coordination_client` caller in this daemon already has — see
    /// `pending_enrollment`'s module doc for the same accepted limitation).
    coordination_client_config: std::sync::OnceLock<CoordinationClientConfig>,
    /// Whether a provider root's content is complete on the OS, answered from the provider side's
    /// own evidence (see `provider_status::eager_status_complete`). Installed once by the shell
    /// side when it starts; absent until then and in tests, which reads as "not complete".
    provider_content_probe: std::sync::OnceLock<ProviderContentProbe>,
    /// Serializes [`Self::flush_pending_checkpoint_for_group`] across its
    /// two production triggers (`on_local_native_commit`, on every local
    /// mutation, and `peer_orchestrator.rs`'s reconnect hook, on every WS
    /// connect) -- without this, both can race to read the SAME pending
    /// batch before either attaches evidence, each requesting its own
    /// checkpoint from the coordination plane, and the second `attach_
    /// authorization_evidence` call then fails closed (`SyncSqliteError::
    /// CorruptState`, "already has a DIFFERENT payload") since the two
    /// checkpoints differ -- confirmed by a real flaky failure, not a
    /// hypothetical. One mutex for the whole device (not per-group): a
    /// flush is an infrequent, already-network-bound operation, so
    /// serializing it globally costs nothing worth avoiding the lock
    /// bookkeeping for.
    pub(crate) flush_lock: tokio::sync::Mutex<()>,
    /// The live native replication connections to peers.
    pub(crate) native_replication: Arc<crate::native_replication_runtime::NativeReplicationHub>,
    /// The peer session driver, once it is running: it holds the transport
    /// stack and keeps the per-peer sessions that serve blocks and service
    /// RPCs. Absent until the transport stack is up.
    peer_session_driver: Mutex<Option<Arc<crate::sync_adapter::PeerSessionDriver>>>,
    /// Test-only escape hatch from the unconditional, real-time periodic
    /// `daemon-state-membership-recovery-sweep` and `daemon-state-replacement-confirm`
    /// (which lists `/devices/supersessions` at startup) spawned by [`Self::new`] --
    /// see [`Self::disable_membership_recovery_sweep_for_test`]'s own doc
    /// comment for why a recovery-diagnosis crash-qualification test needs
    /// this. Always `false` (sweep enabled, unchanged from today) unless a
    /// test explicitly opts out; compiled out of non-test builds entirely.
    #[cfg(test)]
    pub(crate) membership_recovery_sweep_disabled_for_test: std::sync::atomic::AtomicBool,
}

/// This device's coordination-plane address + credential — see
/// [`DaemonState::coordination_client_config`]'s doc comment.
///
/// `auth` is a credential, not a token. It used to be the `access_token:
/// String` this daemon read once at startup, which was authenticated for as
/// long as that token lived -- five minutes on the Authorization Server's
/// plane. A `CoordinationAuth` holds the shared credential manager instead, so
/// every subsystem that reaches the coordination plane through this config
/// refreshes through the same cache and the same cross-process rotation lock
/// rather than presenting a token that died while the daemon was idle.
#[derive(Debug, Clone)]
pub struct CoordinationClientConfig {
    pub addr: String,
    pub auth: yadorilink_fapi_client::CoordinationAuth,
}

/// RAII guard for `DaemonState::in_flight_broadcasts` — decrements on
/// drop so a broadcast that returns early (or panics) still gets counted
/// out, the same "can't forget to release" property a `MutexGuard` gives you.
struct BroadcastGuard<'a> {
    counter: &'a AtomicI64,
}

impl Drop for BroadcastGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// RAII guard for
/// `DaemonState::active_write_ops`, mirroring `BroadcastGuard` exactly.
pub struct WriteActivityGuard<'a> {
    counter: &'a AtomicI64,
    _liveness: BlockReferenceWriteGuard<'a>,
}

impl Drop for WriteActivityGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BlockWriteActivityProvider for DaemonState {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(self.begin_write_activity())
    }
}

/// Backs [`DaemonState::link_runtime_dependencies`]'s narrow bundle: the
/// three operations the per-link runtime module tree (`link_runtime.rs`
/// and `link_runtime/operations/*.rs`) needs but cannot perform itself
/// without reaching into daemon-wide coordination state that dependency
/// bundle deliberately does not carry -- see
/// `link_runtime::dependencies::LinkRuntimeHostPort`'s own doc for why
/// each of these three specifically can't just be a plain field there.
impl crate::link_runtime::dependencies::LinkRuntimeHostPort for DaemonState {
    fn note_capture_settled(&self, _group_id: &str) {
        // `local_dirty_paths: present -> absent` is a veto clearing for
        // admission (a staged Change touching a dirty path is
        // `CaptureBarrierOpen` and stays staged), and a flush that settles a
        // barrier while authoring nothing never reaches
        // `note_local_commit_for_group`. Admission is driven by the peer
        // session driver's own wakes, so nothing is owed here.
    }

    fn on_local_native_commit<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        // Resolves to the inherent method below (Rust prefers an inherent
        // method over a trait method of the same name on the same
        // receiver type), not a recursive call into this trait method --
        // the same resolution `HandoffLeaseResponder for DaemonState`
        // already relies on just above.
        Box::pin(self.on_local_native_commit(group_id))
    }

    fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(self.begin_write_activity())
    }

    fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        self.device_signing_key()
    }
}

impl DaemonState {
    /// Replaces the per-group count of requests waiting on this account's approval.
    pub(crate) fn set_pending_approvals(&self, counts: impl IntoIterator<Item = (String, u32)>) {
        *self.pending_approvals.write().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            counts.into_iter().filter(|(_, count)| *count > 0).collect();
    }

    /// How many requests wait on this account's approval to join `group_id`.
    pub(crate) fn pending_approvals(&self, group_id: &str) -> u32 {
        self.pending_approvals
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_id)
            .copied()
            .unwrap_or(0)
    }

    /// Narrows this daemon-wide state down to exactly what the per-link
    /// runtime module tree needs -- see
    /// `link_runtime::dependencies::LinkRuntimeDependencies`'s own doc.
    /// Called at the top of every `LinkRuntimeController` entry point that
    /// touches that module tree (`start_inner`, the disk-
    /// reconcile backstop sweep, ...), each of which threads the returned
    /// bundle down instead of `self` from that point on.
    pub(crate) fn link_runtime_dependencies(
        self: &Arc<Self>,
    ) -> Arc<crate::link_runtime::dependencies::LinkRuntimeDependencies> {
        Arc::new(crate::link_runtime::dependencies::LinkRuntimeDependencies {
            replica_coordinator: self.replica_coordinator.clone(),
            block_store: self.block_store.clone(),
            telemetry: self.telemetry.clone(),
            device_id: self.device_id.clone(),
            host: self.clone() as Arc<dyn crate::link_runtime::dependencies::LinkRuntimeHostPort>,
        })
    }

    /// Shared by both `PendingLocalChangeFlush` methods below: resolves
    /// `group_id` to its live `LinkRuntime`, if this device is actively
    /// linked (and watching) that group at all.
    fn link_runtime_for(&self, group_id: &str) -> Option<Arc<crate::link_runtime::LinkRuntime>> {
        let local_path = match self.replica_coordinator.link_repository().list_links() {
            Ok(links) => links
                .into_iter()
                .find(|l| l.group_id == group_id)
                .and_then(|l| l.folder_path().map(str::to_string)),
            Err(e) => {
                tracing::warn!(error = %e, group_id, "failed to look up this group's local link");
                None
            }
        };
        let local_path = local_path?;
        // `Starting` or absent: nothing to flush against yet either way.
        self.links.runtime(&local_path)
    }
}

impl yadorilink_peer_session::peer_session::PendingLocalChangeFlush for DaemonState {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = yadorilink_peer_session::peer_session::PendingLocalFlushOutcome>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match self.link_runtime_for(group_id) {
                // `Starting` or absent: nothing to flush against yet either way.
                Some(runtime) => runtime.flush_pending_local_change(group_id, rel_path).await,
                None => yadorilink_peer_session::peer_session::PendingLocalFlushOutcome::Settled,
            }
        })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = yadorilink_peer_session::peer_session::PendingLocalFlushOutcome>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match self.link_runtime_for(group_id) {
                Some(runtime) => runtime.flush_case_fold_sibling(group_id, rel_path).await,
                None => yadorilink_peer_session::peer_session::PendingLocalFlushOutcome::Settled,
            }
        })
    }

    fn capture_local_path_state<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = yadorilink_peer_session::peer_session::PendingLocalFlushOutcome>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match self.link_runtime_for(group_id) {
                Some(runtime) => runtime.capture_local_path_state(group_id, rel_path).await,
                // No link: nothing can be captured, so nothing may be
                // written over either.
                None => {
                    yadorilink_peer_session::peer_session::PendingLocalFlushOutcome::RetryRequired
                }
            }
        })
    }
}

/// The decision logic behind [`DaemonState::obtain_handoff_lease_from_peer`]:
/// whether a target's `HandoffLeaseGrant` actually covers this device's own
/// current durability-root set. Split out as a pure function -- no session,
/// no network, no coordination client -- so this one comparison (the entire
/// safety property `obtain_handoff_lease_from_peer` exists to enforce) is
/// directly unit-testable without a live peer. `None` on a mismatch means
/// the target is not actually caught up to `my_digest`'s exact set -- the
/// caller must decline this round, never relinquish its role on the
/// strength of a lease that doesn't cover what it currently holds.
fn handoff_lease_grant_matches_digest(
    grant: &PeerHandoffLeaseGrant,
    my_digest: [u8; 32],
) -> Option<String> {
    if grant.root_digest != my_digest {
        return None;
    }
    Some(grant.lease_id.clone())
}

/// Runs a blocking housekeeping sweep off the async worker pool when a
/// multi-thread runtime is available, otherwise inline on the current thread.
///
/// Shared by every call site in this crate that wraps a *plain synchronous*
/// function this way, with the same function serving both the offloaded and
/// inline paths (only how it's invoked differs, never what it does): the
/// retention-expiry sweep (`run_retention_expiry_sweep`), the GC sweep
/// (`gc::run_sweep_with_grace_cutoff`), and the disk-reconcile backstop
/// sweep (`LinkRuntimeController::run_disk_reconcile_backstop_sweep`, which
/// routes each link's `reconcile_added_files_from_disk` call through here —
/// that call is synchronous and walks the whole link folder, chunking and
/// hashing every file the index has never seen). All of these are blocking
/// work — they park on the `BlockLivenessGate` condvar and/or do synchronous
/// SQLite/block-store I/O — invoked from async tasks (periodic drivers, the
/// startup path, or directly from an async caller), so calling them directly
/// would block a tokio worker thread and, under load, starve the pool.
/// `block_in_place` hands the blocking work off so the worker can keep
/// servicing other tasks.
///
/// Generic over the closure's return type so callers that need a result back
/// (e.g. `gc::run_sweep_with_grace_cutoff`'s `Result<GcReport, GcTriggerError>`,
/// or the disk-reconcile backstop's per-link `Vec<FileRecord>`) can use this
/// too, not just the ones that only run for side effects — `block_in_place`
/// already returns its closure's value.
///
/// Not used by `custody.rs`'s peer-confirmation bridge, which has the same
/// guard shape but different fallback semantics: it has no synchronous
/// implementation to fall back to (it bridges to an async peer query), so its
/// non-multi-thread branch can't just call the same closure inline — see the
/// comment there.
///
/// When there is no multi-thread worker to offload onto (a current-thread
/// runtime, or called outside any runtime — e.g. tests), the plain synchronous
/// path is correct and cannot starve a worker pool.
pub(crate) fn run_blocking_sweep_offloaded<R>(sweep: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(sweep)
        }
        _ => sweep(),
    }
}

impl DaemonState {
    /// Whether `group_id`'s root may run OnDemand -- the single place every call
    /// site in this crate (`ReplicaRoleService::set_storage_mode` via
    /// `OnDemandCapabilityPort`, `hydration::evict`) reads, so
    /// `set_test_on_demand_allowed`'s override reaches all of them
    /// uniformly. A PER-ROOT decision (`provider_gate`): only a ready provider
    /// root may. The global placeholder capability is consulted for its test
    /// override only and is `false` in every real build.
    pub(crate) fn root_allows_on_demand(&self, group_id: &str) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(connected) =
            *self.test_on_demand_allowed.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            return connected;
        }
        crate::provider_gate::root_allows_on_demand(&self.replica_coordinator, group_id)
    }

    /// Convenience wrapper around [`Self::build`] for every caller that
    /// wants the old all-in-one behavior: construct `self`, then start
    /// `MaintenanceCoordinator` on it immediately. Production
    /// (`app::run`) uses `build` directly instead, so it controls exactly
    /// when maintenance starts relative to the rest of composition-root
    /// wiring; this wrapper exists so the very large number of existing
    /// test call sites (which only ever wanted a fully-functional
    /// `DaemonState`, never cared about controlling that ordering
    /// themselves) don't all need to change.
    pub fn new(
        device_id: String,
        replica_coordinator: Arc<crate::replica_coordinator::ReplicaCoordinator>,
        block_store: Arc<dyn BlockStore + Send + Sync>,
    ) -> Arc<Self> {
        let state = Self::build(device_id, replica_coordinator, block_store);
        #[cfg(any(test, feature = "test-support"))]
        {
            let ((), tasks) = crate::supervise::collect_spawned_tasks(|| {
                crate::maintenance_coordinator::start(&state, None);
            });
            *state.background_tasks.lock().unwrap_or_else(|p| p.into_inner()) = tasks;
        }
        #[cfg(not(any(test, feature = "test-support")))]
        crate::maintenance_coordinator::start(&state, None);
        state
    }

    /// Construction only -- builds `self` and wires its internal
    /// closures (local-change-auth/repair-election providers), but starts
    /// no background task and performs no other side effect beyond that
    /// wiring. The caller owns starting `MaintenanceCoordinator` on
    /// the returned state (see [`Self::new`] for the common case, or
    /// `app::run` for production's own explicit sequencing).
    #[allow(
        clippy::too_many_lines,
        reason = "one `DaemonState` struct-literal construction plus the closure \
                  providers (local-change-auth, repair election, orphan-promotion \
                  freshness) that must be installed on the already-built `Arc<Self>` \
                  because they capture it. The length is the field list and its \
                  per-field tuning rationale; splitting it would either duplicate the \
                  literal across helpers or hand out a partially-wired state before \
                  its providers are set."
    )]
    pub(crate) fn build(
        device_id: String,
        replica_coordinator: Arc<crate::replica_coordinator::ReplicaCoordinator>,
        block_store: Arc<dyn BlockStore + Send + Sync>,
    ) -> Arc<Self> {
        let (status_push_tx, _) = broadcast::channel(256);
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let local_device_id = device_id.clone();
        let governance_config = GovernanceConfigStore::new(crate::device_config::config_dir());
        // Apply whatever's on disk
        // (or the safe unlimited/no-override default if nothing's ever
        // been written) right away, so a freshly-started daemon's very
        // first session/block write already reflects a previous `limits
        // set`/headroom override rather than starting unlimited/unenforced
        // for a beat.
        let initial_governance = governance_config.load_or_default();
        let rate_limiters = Arc::new(RateLimiters::new(
            initial_governance.upload_limit_bytes_per_sec,
            initial_governance.download_limit_bytes_per_sec,
        ));
        // Rate limiting is always safe to wire in unconditionally (`0` =
        // unlimited = zero overhead), so every `DaemonState`,
        // test or production, gets the real configured/default rates.
        // Disk-headroom *enforcement* is deliberately NOT turned on here —
        // see `enable_disk_headroom_enforcement`'s doc comment for why
        // that's a separate, production-only opt-in `main.rs` calls
        // explicitly, mirroring `SegmentBlockStore`/`PeerSyncSession`'s own
        // "off by default" behavior at every other layer of this change.
        block_store.set_headroom_override_bytes(initial_governance.headroom_override_bytes);
        let (persisted_durability_latches, durability_latch_load_failed) = match replica_coordinator
            .role_loss_operation_repository()
            .list_durability_unknown_latches()
        {
            Ok(groups) => (groups, false),
            Err(error) => {
                tracing::error!(%error, "failed to load durability-unknown latches; failing status closed");
                (Vec::new(), true)
            }
        };
        let unknown_scope_membership_marker = replica_coordinator
            .membership_operation_repository()
            .has_open_unknown_durability_scope_operation()
            .unwrap_or(true);
        // Built before the struct literal moves `replica_coordinator`: the
        // authority restores this device's last-known-good peer
        // authorization from that same database, so an offline restart can
        // go on talking to peers a netmap already authorized. See
        // `offline_authorization`'s module doc for why that snapshot is a
        // cache of an already-made decision and never an authority.
        let offline_authorization =
            offline_authorization::OfflineAuthorizationCache::new(replica_coordinator.clone());
        let state = Arc::new(Self {
            device_id,
            backstop_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            pending_approvals: std::sync::RwLock::default(),
            custody_hold_wake: replica_coordinator.custody_hold_wake(),
            replica_coordinator,
            block_store,
            hydrate_single_flight: crate::hydration_single_flight::HydrateSingleFlight::new(),
            requested_opens: Arc::default(),
            // 512 MiB global / 128 MiB per-peer / 256 MiB per-group,
            // sized against `MAX_BLOCK_SIZE` (16 MiB, `chunker.rs`) --
            // each of a request's credit is reserved pessimistically at
            // that pre-read worst case (see `handle_block_request_with_
            // credit`'s doc comment), so these bound roughly how many
            // full-size blocks this device serves concurrently overall/to
            // one peer/for one group, not raw request count. 16 is
            // `BlockServeEngine::new`'s own tuned value -- it is now BOTH
            // what this device advertises AND the real concurrent-dispatch
            // cap (previously two independently-set, silently-diverging
            // numbers: this passed 64 while the dispatch queue itself was
            // separately hardcoded to 16, so a peer favoring this device
            // based on its advertised worker-slot count was reading a
            // number this device could never actually back up). See that
            // constructor's own doc comment for the throughput/fairness
            // measurements 16 was tuned against before changing it.
            block_serve_engine: yadorilink_peer_session::block_serve::BlockServeEngine::new(
                512 * 1024 * 1024,
                128 * 1024 * 1024,
                256 * 1024 * 1024,
                16,
            ),
            peers: Arc::new(crate::peer_registry::PeerRegistry::new()),
            peer_connectivity: Arc::new(
                crate::peer_connectivity_runtime::PeerConnectivityRuntime::new(local_device_id),
            ),
            send_service: tokio::sync::OnceCell::new(),
            send_grant_peers: Mutex::new(Vec::new()),
            authority: Arc::new(PeerAuthorityState::restored_from(offline_authorization)),
            device_signing_key: Mutex::new(None),
            materialization_repair_sweep_interval: Mutex::new(
                default_materialization_repair_sweep_interval(),
            ),
            links: Arc::new(crate::link_registry::LinkRegistry::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_root_commit_authorities: Mutex::new(HashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_on_demand_allowed: Mutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            background_tasks: Mutex::new(Vec::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_seal_checkpoint_source: Mutex::new(None),
            telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_push_tx)),
            in_flight_broadcasts: AtomicI64::new(0),
            shutdown_tx,
            safe_stop_committed: tokio::sync::Mutex::new(false),
            reporting: Arc::new(ReportingStorage::open_default()),
            governance_config: Arc::new(governance_config),
            rate_limiters,
            disk_headroom_enforcement_enabled: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            link_preflight_headroom_override: Mutex::new(None),
            durability: Arc::new(crate::durability_service::DurabilityService::new(
                persisted_durability_latches
                    .into_iter()
                    .map(|group_id| (group_id, GroupDurabilityStatus::Unknown))
                    .collect(),
                durability_latch_load_failed,
                unknown_scope_membership_marker,
            )),
            pending_enrollment_transient_attempts: Mutex::new(HashMap::new()),
            update_manager: Arc::new(crate::update::manager::UpdateManager::new(
                crate::device_config::config_dir(),
                current_crate_version(),
            )),
            active_write_ops: AtomicI64::new(0),
            started_at: std::time::Instant::now(),
            last_activity_unix: AtomicI64::new(now_unix()),
            gc: Arc::new(crate::gc_state::GcState::new()),
            coordination_client_config: std::sync::OnceLock::new(),
            provider_content_probe: std::sync::OnceLock::new(),
            flush_lock: tokio::sync::Mutex::new(()),
            native_replication: Arc::new(
                crate::native_replication_runtime::NativeReplicationHub::default(),
            ),
            peer_session_driver: Mutex::new(None),
            #[cfg(test)]
            membership_recovery_sweep_disabled_for_test: std::sync::atomic::AtomicBool::new(false),
        });
        {
            let weak_state = Arc::downgrade(&state);
            let local_policy_head_provider: Arc<
                crate::replica_coordinator::LocalPolicyHeadProvider,
            > = Arc::new(move |group_id| {
                let Some(state) = weak_state.upgrade() else {
                    // The daemon is being torn down. Report the policy as
                    // unavailable rather than emitting during shutdown.
                    return Err(PolicyUnavailable);
                };
                // Under `AuthorizationCheckpoint` admission, writer authorization happens
                // only at checkpoint issuance -- local emission (offline
                // authoring) is always available to any device regardless
                // of writer role. This resolves only the policy_head to
                // stamp the local repair-election consistency check
                // against; it is not itself an authorization decision.
                match state.resolve_group_policy(group_id) {
                    GroupPolicyResolution::Verified(policy) => Ok(policy.policy_head),
                    GroupPolicyResolution::Bootstrap => Ok([0u8; 32]),
                    GroupPolicyResolution::Withhold => Err(PolicyUnavailable),
                }
            });
            // `build_change_processor` constructs `LocalChangeProcessor`
            // from `replica_coordinator` (it implements
            // `LocalMutationStore`), so real local edits resolve their
            // policy-head stamp through `ReplicaCoordinator::
            // local_policy_head` exclusively; this is the provider's only
            // production registration.
            state.replica_coordinator.set_local_policy_head_provider(local_policy_head_provider);
        }
        state
    }

    /// This device's durability state owner -- for a caller that needs only
    /// the custody-confirmation cache or the sweep interval, not the
    /// orchestration `DaemonState` layers over them.
    pub(crate) fn durability(&self) -> &Arc<crate::durability_service::DurabilityService> {
        &self.durability
    }

    /// Records the substrate reachability the coordination plane reports for
    /// `device_id`, then projects it.
    ///
    /// `None` means this peer's substrate has not published an address yet,
    /// which is NOT the claim that it is reachable nowhere -- erasing on its
    /// account would make a peer undialable that is about to be dialable.
    /// `Some`, including `Some` with both lists empty, IS authoritative.
    pub fn record_peer_substrate_reachability(
        &self,
        device_id: &str,
        reachability: Option<crate::coordination_client::SubstrateReachability>,
    ) {
        // "Not published yet" leaves what is known alone -- but the
        // projection below still has to run, and unconditionally: it
        // reflects current state, so a peer whose signing key or
        // peer session driver only arrived after its address must
        // reach the directory without waiting for another push.
        if let Some(reachability) = reachability {
            self.peer_connectivity.record_peer_substrate_reachability(device_id, reachability);
        }
        self.project_substrate_reachability(device_id);
    }

    /// Projects current coordination state for `device_id` into the address
    /// directory: pinned signing key -> PeerId, plus whatever reachability is
    /// on record.
    ///
    /// The directory is a PROJECTION of current state, never a cache of the
    /// events that produced it. That is why this is one helper with three
    /// callers rather than three code paths: whichever of the driver, the
    /// signing key and the reachability arrives last, the projection ends in
    /// the same place without waiting for another netmap push. An earlier
    /// version wrote through only when a driver already existed, and in
    /// production the driver never does at that moment -- so nothing was ever
    /// written, and because a push is a snapshot the next identical one
    /// changed nothing and wrote nothing again.
    ///
    /// Precedence is explicit rather than implied by call order: the substrate
    /// field wins whenever the plane has supplied one, and the legacy relay
    /// list is consulted only for a peer it has not.
    pub(crate) fn project_substrate_reachability(&self, device_id: &str) {
        let Some(driver) = self.peer_session_driver() else {
            return;
        };
        self.peer_connectivity.project_peer_address(device_id, driver.stack().endpoint());
    }

    /// Publishes this device's Track Send service once
    /// `crate::send_transfer::run` has built it. A no-op if one is already
    /// published: one Track Send service per process.
    pub fn set_send_service(&self, service: Arc<yadorilink_send::SendService>) {
        let _ = self.send_service.set(service);
    }

    /// This device's Track Send service, if `crate::send_transfer::run`
    /// has built and published one yet.
    pub fn send_service(&self) -> Option<Arc<yadorilink_send::SendService>> {
        self.send_service.get().cloned()
    }

    /// Marks `local_path` Degraded
    /// (disk-pressure), scheduling its next re-check via
    /// `BackoffConfig::DEGRADED_LINK_RECHECK` — a link already degraded has
    /// its backoff attempt count bumped (spacing repeated pressure further
    /// apart, "not a tight retry loop") rather than reset, and
    /// keeps its original `since_unix` onset time.
    pub fn mark_link_degraded(&self, local_path: &str, reason: String) {
        self.links.mark_degraded(local_path, reason, now_unix(), |backoff_attempt| {
            supervise::BackoffConfig::DEGRADED_LINK_RECHECK.next(backoff_attempt).as_secs() as i64
        });
    }

    /// Terminal OwnershipLost for `local_path`; true on the first transition only.
    pub fn mark_link_ownership_lost(&self, local_path: &str) -> bool {
        self.links.mark_ownership_lost(local_path, now_unix())
    }

    /// Clears `local_path`'s Degraded state, if any — a no-op if it wasn't
    /// degraded.
    pub fn clear_link_degraded(&self, local_path: &str) {
        self.links.clear_degraded(local_path);
    }

    /// Clears `local_path`'s Degraded state if its volume is no longer Critical. An
    /// undeterminable volume stays degraded. True when it cleared.
    pub(crate) fn clear_link_degraded_if_space_recovered(&self, local_path: &str) -> bool {
        if !self.links.is_degraded(local_path) {
            return false;
        }
        let headroom_override = self.governance_config.load_or_default().headroom_override_bytes;
        match yadorilink_local_storage::free_space::classify_volume(
            std::path::Path::new(local_path),
            headroom_override,
        ) {
            Ok(space)
                if space.classify()
                    != yadorilink_local_storage::free_space::FreeSpaceState::Critical =>
            {
                self.clear_link_degraded(local_path);
                true
            }
            _ => false,
        }
    }

    pub fn is_link_degraded(&self, local_path: &str) -> bool {
        self.links.is_degraded(local_path)
    }

    pub fn degraded_link_info(
        &self,
        local_path: &str,
    ) -> Option<crate::link_registry::DegradedLinkInfo> {
        self.links.degraded_info(local_path)
    }

    /// Pins `group_id` to [`GroupDurabilityStatus::Unknown`],
    /// overriding whatever it would otherwise derive to. The one call site
    /// today is `control_socket::ensure_unlink_keeps_a_full_replica`'s
    /// `--force` bypass: once this device's own durability handoff gate has
    /// been overridden for a group, the group's remaining local replica
    /// must not be able to report `Protected` again until a real re-check
    /// says so, even if, moment to moment, its files happen to look fully
    /// materialized. Idempotent — latching an already-latched group is a
    /// no-op.
    pub fn latch_group_durability_unknown(
        &self,
        group_id: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        self.replica_coordinator
            .role_loss_operation_repository()
            .latch_group_durability_unknown(group_id)?;
        self.durability.latch_unknown(group_id);
        Ok(())
    }

    /// Clears a previously-latched `Unknown` override for
    /// `group_id`, if any — meant to be called once a positive
    /// whole-group handoff re-confirmation is observed for it (today:
    /// [`Self::full_replica_handoff_ready`]'s own success path calls this
    /// directly, so any caller of
    /// [`Self::another_full_replica_is_ready`]/
    /// [`Self::another_full_replica_is_ready_excluding`] that confirms
    /// coverage again clears the latch as a side effect). A no-op if the
    /// group was never latched, or is not currently latched.
    pub fn clear_group_durability_latch(
        &self,
        group_id: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        self.replica_coordinator
            .role_loss_operation_repository()
            .clear_group_durability_unknown(group_id)?;
        self.durability.clear_unknown(group_id);
        Ok(())
    }

    /// Records one more consecutive `TransientFailure` activate outcome for
    /// `operation_id` and returns the new running count -- see
    /// `pending_enrollment_transient_attempts`'s doc comment. Never resets
    /// itself; the caller clears it explicitly once the marker resolves
    /// ([`Self::clear_pending_enrollment_transient_attempts`]).
    pub fn note_pending_enrollment_transient_attempt(&self, operation_id: &str) -> u32 {
        let mut attempts =
            self.pending_enrollment_transient_attempts.lock().unwrap_or_else(|p| p.into_inner());
        let count = attempts.entry(operation_id.to_string()).or_insert(0);
        *count += 1;
        *count
    }

    /// Drops `operation_id`'s transient-attempt counter, once its marker has
    /// resolved (activated, confirmed deleted, or its link is gone and it
    /// was canceled) and there is nothing left to escalate. A no-op if it
    /// was never tracked.
    pub fn clear_pending_enrollment_transient_attempts(&self, operation_id: &str) {
        self.pending_enrollment_transient_attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(operation_id);
    }

    /// Whether this daemon currently has any daemon-wide or group-scoped
    /// reason to distrust its own evidence for `group_id` -- the exact
    /// same fact set `group_durability_status` folds into its own
    /// fail-closed `Unknown` branch, exposed separately so
    /// OTHER derivations that must fail closed the same way (e.g.
    /// `FetchAvailability`) can reuse it instead of re-deriving an
    /// equivalent-but-possibly-drifting copy of the same precedence.
    pub(crate) fn daemon_wide_evidence_uncertain(&self, group_id: &str) -> bool {
        self.durability.latch_load_failed()
            || self.durability.scope_unknown()
            || self
                .replica_coordinator
                .membership_operation_repository()
                .has_recovery_blocked_membership_operation()
                .unwrap_or(true)
            || self.authority.is_group_policy_stale(group_id)
            // The per-group post-`--force` latch (`durability.is_latched_unknown`)
            // is folded into `group_durability_status`'s own `Unknown`
            // branch via `DurabilityService::classify` (not visible in this
            // free function's own fact list, since that method fills it in
            // internally) -- it belongs here too: a `--force` override that
            // bypassed the handoff gate means this daemon explicitly cannot
            // currently vouch for the group, which is exactly the condition
            // this method exists to detect. Omitting it was a real bug: a group
            // could show `durability
            // unknown` while `fetch_availability` still read `AvailableNow`.
            || self.durability.is_latched_unknown(group_id)
    }

    /// This group's current local durability status: the latched override
    /// above if one is set, otherwise a value derived live from
    /// `DurabilityService`'s custody confirmation cache (a real, periodically-refreshed
    /// peer-confirmed whole-group check -- see `DurabilityConfirmationJob`)
    /// plus this device's own sync state. `Protected` requires a fresh cache
    /// entry; this device's own materialization completeness alone never
    /// produces it (only `Protecting`, for a full-replica device still
    /// catching up locally) -- see `crate::durability_service`'s own
    /// module documentation. This method itself never performs a live peer
    /// round-trip (too costly to run on every `status` call); it only ever
    /// reads what the background sweep already cached.
    pub fn group_durability_status(&self, group_id: &str) -> GroupDurabilityStatus {
        // The three account-wide/group-scoped "cannot currently confirm"
        // facts (latch-table load failure, an unresolved unknown-scope
        // removal, a recovery-blocked membership operation) are gathered
        // here since they live on `DaemonState`'s own atomics/`SyncState`,
        // not inside `DurabilityService` -- see
        // `crate::durability_service::classify`'s own doc for why this
        // exact precedence (each one short-circuits before the optimistic
        // materialization check ever runs) is the actual fail-safe
        // property, not an implementation detail. `latched_unknown` is
        // left `false` here -- `DurabilityService::classify` fills it in
        // from its own latch table, which this method never touches
        // directly.
        //
        // `Protected` evidence comes ONLY from a fresh `custody_confirmation_
        // cache` entry -- a real peer-confirmed whole-group check
        // (`full_replica_handoff_ready`, run periodically by
        // `DurabilityConfirmationJob`, which ALSO covers the vacuous
        // "group has no durability roots at all" case using the real
        // root-enumeration it already performs -- NOT this device's own
        // locally-visible file count, which only reflects currently-live
        // files and would miss retained/trash-restorable durability roots
        // an empty-looking group might still have). This device's OWN
        // materialization completeness (`is_local_full_replica` +
        // `materialization`) is deliberately kept out of the `Protected`
        // path entirely -- it only ever feeds `Protecting`, for the case
        // where this device itself is a full replica still catching up to
        // head. `Protected` is never derived from local materialization
        // alone without consulting any peer.
        let (facts, _) = self.gather_durability_facts(group_id);
        tracing::debug!(
            local_device_id = %self.device_id,
            %group_id,
            ?facts,
            "group_durability_status computed"
        );
        self.durability.classify(group_id, facts)
    }

    /// The facts [`Self::group_durability_status`] classifies, plus the raw
    /// materialization counts they were reduced from (for
    /// [`Self::dump_durability_diagnostics`]). `latched_unknown` is left
    /// `false`: `DurabilityService::classify` fills it in from its own latch
    /// table.
    fn gather_durability_facts(
        &self,
        group_id: &str,
    ) -> (
        crate::durability_service::DurabilityFacts,
        Result<
            yadorilink_sync_sqlite::MaterializationCounts,
            yadorilink_sync_sqlite::SyncSqliteError,
        >,
    ) {
        let counts = self
            .replica_coordinator
            .materialization_state_repository()
            .materialization_counts(group_id);
        let materialization = match &counts {
            Ok(counts)
                if counts.placeholder == 0 && counts.hydrating == 0 && counts.evicting == 0 =>
            {
                Ok(crate::durability_service::MaterializationHealth::FullyLocal)
            }
            Ok(_) => Ok(crate::durability_service::MaterializationHealth::Partial),
            Err(_) => Err(()),
        };
        let facts = crate::durability_service::DurabilityFacts {
            latch_load_failed: self.durability.latch_load_failed(),
            scope_unknown: self.durability.scope_unknown(),
            recovery_blocked: self
                .replica_coordinator
                .membership_operation_repository()
                .has_recovery_blocked_membership_operation()
                .unwrap_or(true),
            latched_unknown: false,
            group_policy_stale: self.authority.is_group_policy_stale(group_id),
            materialization,
            is_local_full_replica: self.is_local_full_replica(group_id),
            any_other_full_replica_peer_configured: self
                .authority
                .any_other_full_replica_peer_configured(group_id),
            peer_confirmed_custody: self.has_fresh_custody_confirmation(group_id),
            ever_confirmation_swept: self.durability.has_ever_been_custody_swept(group_id),
            known_unobtainable_required_content: self
                .has_known_unobtainable_required_content(group_id),
        };
        (facts, counts)
    }

    /// re-checks free space for every Degraded link whose backoff
    /// window has elapsed, clearing it ("cleared once a
    /// subsequent headroom check for that link's volume succeeds") once
    /// the volume is no longer `Critical`, or rescheduling it (bumped
    /// backoff) if it's still under pressure. A link whose local folder no
    /// longer exists (unlinked while degraded) or whose free space can't
    /// currently be determined is left degraded rather than guessed clear.
    pub(crate) fn recheck_degraded_links(&self) {
        let now = now_unix();
        let due = self.links.degraded_due_snapshot(now);
        if due.is_empty() {
            return;
        }
        let headroom_override = self.governance_config.load_or_default().headroom_override_bytes;
        for (local_path, reason) in due {
            let space = yadorilink_local_storage::free_space::classify_volume(
                std::path::Path::new(&local_path),
                headroom_override,
            );
            match space {
                Ok(space)
                    if space.classify()
                        != yadorilink_local_storage::free_space::FreeSpaceState::Critical =>
                {
                    tracing::info!(local_path = %local_path, "disk-pressure re-check succeeded; clearing Degraded state");
                    self.clear_link_degraded(&local_path);
                }
                _ => {
                    // Still under pressure (or undeterminable) — reschedule
                    // with a bumped backoff rather than leaving a stale
                    // `next_recheck_unix` in the past (which would make
                    // this a hot loop at the 2s poll interval).
                    self.mark_link_degraded(&local_path, reason);
                }
            }
        }
    }

    /// Re-reads the persisted
    /// governance config and applies it to the *same* shared
    /// Turns on the block store's
    /// disk-headroom preflight (`SegmentBlockStore::headroom_enforced`'s "off by
    /// default" flag) for this daemon's actual production block store.
    /// Deliberately **not** called from `DaemonState::new` itself — `new`
    /// is the one constructor every test in this crate (and
    /// `yadorilink-cli`'s daemon-backed tests) goes through too, and
    /// unconditionally enforcing the real default headroom formula against
    /// whatever this *host machine's* actual free space happens to be
    /// would make every test that writes a real block newly
    /// environment-dependent — confirmed a real, not hypothetical, risk
    /// elsewhere in this change (this dev machine is genuinely 96% full).
    /// `main.rs` calls this exactly once, right after constructing the real
    /// `DaemonState` for the `yadorilink-daemon` binary itself.
    pub fn enable_disk_headroom_enforcement(&self) {
        self.block_store.set_headroom_enforced(true);
        self.disk_headroom_enforcement_enabled.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// The headroom reserve the link preflight measures free space against: the default
    /// `max(1 GiB, 5%)` unless a test pinned it.
    pub(crate) fn link_preflight_headroom_override(&self) -> Option<u64> {
        #[cfg(any(test, feature = "test-support"))]
        {
            *self.link_preflight_headroom_override.lock().unwrap_or_else(|p| p.into_inner())
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            None
        }
    }

    /// Pins the link preflight's headroom reserve (`Some(0)`: free space is never low).
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_link_preflight_headroom_override_for_tests(&self, headroom_bytes: Option<u64>) {
        *self.link_preflight_headroom_override.lock().unwrap_or_else(|p| p.into_inner()) =
            headroom_bytes;
    }

    /// Whether `enable_disk_headroom_enforcement` has been called —
    /// consulted by `peer_orchestrator::spawn_peer_session` when wiring a
    /// newly-connected session's own headroom preflight.
    pub fn disk_headroom_enforcement_enabled(&self) -> bool {
        self.disk_headroom_enforcement_enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records this device's Ed25519 change-history signing key. The real
    /// daemon binary calls this once at startup when the device is
    /// registered. A registered (non-empty `device_id`) `DaemonState` built
    /// without one is a fail-closed condition, not a legitimate no-emitter
    /// path -- local edits would be indexed but never recorded as
    /// native deltas, which is silent data loss from the group's perspective.
    /// Only a genuinely unregistered device (empty `device_id`) tolerates
    /// this being unset.
    pub fn set_device_signing_key(&self, signing_key: ed25519_dalek::SigningKey) {
        *self.device_signing_key.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(signing_key.clone());
        // Opens this replica's author identity now, before anything authors:
        // the incarnation check against the `<db>.instance` sidecar rotates a
        // restored, cloned or migrated replica here, and the sidecar is
        // written before any handle is handed out. A failure leaves no
        // handle, and every authoring path asks again (`local_author`) and
        // fails closed while it keeps failing.
        if !self.device_id.is_empty() {
            if let Err(error) =
                self.replica_coordinator.open_local_author(&self.device_id, signing_key)
            {
                tracing::error!(%error, "opening the replica's author identity failed");
            }
        }
    }

    /// The author handle this device signs local changes with: this
    /// replica's current author incarnation (`ReplicaCoordinator::
    /// open_local_author`). `None` for a device with no signing key, or
    /// while the author identity cannot be opened.
    pub fn local_author(&self) -> Option<Arc<yadorilink_sync_sqlite::dag_store::LocalAuthorKey>> {
        let signing_key = self.device_signing_key()?;
        match self.replica_coordinator.open_local_author(&self.device_id, signing_key) {
            Ok(author) => Some(author),
            Err(error) => {
                tracing::error!(%error, "opening the replica's author identity failed");
                None
            }
        }
    }

    /// This device's change-history signing key, if one has been wired.
    /// Consulted by the daemon's own `LinkRuntimeController`-owned module tree when deciding whether to emit signed
    /// changes for a folder.
    pub fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        self.device_signing_key.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Mirrors a peer's pinned Ed25519 change-history signing key from the
    /// netmap so the change authenticator can verify that device's changes.
    pub fn record_peer_signing_key(&self, device_id: &str, key: [u8; 32]) {
        self.authority.record_peer_signing_key(device_id, key);
        // The key IS the endpoint id, so it is a prerequisite of the
        // projection rather than an input to it. Reachability recorded before
        // the key arrived projected nothing; this is what closes that ordering
        // without waiting for another netmap push.
        self.project_substrate_reachability(device_id);
    }

    /// Removes every already-expired entry from `send_grant_peers` -- called
    /// at the start of every read/write against it, matching
    /// `handle_lan_announcement`'s own "TTL-pruned on every call" convention
    /// rather than a separate sweep task. Cheap at this scale: one entry per
    /// currently outstanding grant, minutes-scale TTL.
    fn prune_expired_send_grant_peers(guard: &mut Vec<SendGrantPeer>) {
        let now = now_unix();
        guard.retain(|p| p.expires_at_unix > now);
    }

    /// Records (or, for the same signing key, replaces) a Track Send
    /// grant-derived peer -- see `send_grant_peers`'s own field doc comment
    /// for the two call sites this serves and why this is never a way to
    /// reach ordinary netmap-authorized peer state.
    pub fn record_send_grant_peer(&self, peer: SendGrantPeer) {
        let mut guard = self.send_grant_peers.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune_expired_send_grant_peers(&mut guard);
        guard.retain(|p| p.signing_key != peer.signing_key);
        guard.push(peer);
    }

    /// The grant-derived peer currently on record for `signing_key`, if its
    /// grant has not yet expired. `device_id_for_key`'s and `consume_grant`'s
    /// own sender-identity derivation both rest on this: a Track Send
    /// connection's handshake-authenticated key (its iroh endpoint id) is
    /// looked up here, never trusted from anything the connection itself
    /// claims.
    pub fn send_grant_peer_by_key(&self, signing_key: &[u8; 32]) -> Option<SendGrantPeer> {
        let mut guard = self.send_grant_peers.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune_expired_send_grant_peers(&mut guard);
        guard.iter().find(|p| &p.signing_key == signing_key).cloned()
    }

    /// The grant-derived peer currently on record for `device_id`, if its
    /// grant has not yet expired -- `DaemonDeviceDirectory::resolve`'s
    /// fallback for a `receive_transfer` pull-dial against a sender this
    /// device has no ordinary netmap relationship with.
    pub fn send_grant_peer_by_device_id(&self, device_id: &str) -> Option<SendGrantPeer> {
        let mut guard = self.send_grant_peers.lock().unwrap_or_else(|p| p.into_inner());
        Self::prune_expired_send_grant_peers(&mut guard);
        guard.iter().find(|p| p.device_id == device_id).cloned()
    }

    /// Applies one peer's netmap entry as an authoritative snapshot. Every
    /// peer-scoped authorization set is replaced, not incrementally patched,
    /// so demotion/revocation cannot leave a stale writer or full-replica bit
    /// behind merely because the transport session was already connected.
    pub fn replace_peer_netmap_metadata(
        &self,
        device_id: &str,
        signing_key: Option<[u8; 32]>,
        authorized_groups: &HashSet<String>,
        full_replica_groups: &HashSet<String>,
    ) {
        self.apply_peer_netmap_metadata(
            device_id,
            signing_key,
            authorized_groups,
            full_replica_groups,
            offline_authorization::SnapshotMirror::Now,
        );
    }

    /// The identity-seeding first half of one netmap peer entry: the peer's
    /// key is recorded and every group authorization is withheld until this
    /// same pass's validation settles what it may serve.
    ///
    /// Separate from [`replace_peer_netmap_metadata`](Self::replace_peer_netmap_metadata)
    /// only in that it does not mirror the intermediate onto disk -- the
    /// call that settles the peer's groups, a few lines later in the same
    /// pass, writes the authorization the netmap really left behind. See
    /// `SnapshotMirror` for why that is the faithful thing to persist.
    pub(crate) fn seed_netmap_peer_identity(&self, device_id: &str, signing_key: Option<[u8; 32]>) {
        self.apply_peer_netmap_metadata(
            device_id,
            signing_key,
            &HashSet::new(),
            &HashSet::new(),
            offline_authorization::SnapshotMirror::AfterThisNetmapPassSettles,
        );
    }

    fn apply_peer_netmap_metadata(
        &self,
        device_id: &str,
        signing_key: Option<[u8; 32]>,
        authorized_groups: &HashSet<String>,
        full_replica_groups: &HashSet<String>,
        mirror: offline_authorization::SnapshotMirror,
    ) {
        let _ = self.authority.replace_peer_netmap_metadata(
            device_id,
            signing_key,
            authorized_groups,
            full_replica_groups,
            mirror,
        );

        // The netmap installs signing keys HERE, not through
        // `record_peer_signing_key` -- so this is where a first-time peer's
        // endpoint id becomes known. Reachability recorded moments earlier in
        // the same pass found no key and projected nothing; without this it
        // would wait for a netmap that reported something DIFFERENT, because a
        // repeat of the same one is no change at all.
        self.project_substrate_reachability(device_id);
    }

    pub fn clear_peer_netmap_metadata(&self, device_id: &str) {
        self.replace_peer_netmap_metadata(device_id, None, &HashSet::new(), &HashSet::new());
    }

    /// Deletes this device's last-known-good peer authorization, in memory
    /// and on disk.
    ///
    /// For the events after which there is no authorization left to
    /// remember: this machine has been signed out, or is not a registered
    /// device. The snapshot exists so an offline restart can continue an
    /// authorization the coordination plane granted; once the account
    /// relationship that granted it is gone, continuing it is exactly what
    /// must not happen, so the record goes rather than sitting on disk for
    /// a later restart to act on.
    pub fn forget_offline_peer_authorization(&self) {
        self.authority.forget_offline_authorization();
    }

    /// Deletes the persisted authorization of every device `present` does
    /// not name. `present` must be the device set of a full authoritative
    /// netmap snapshot -- see
    /// `PeerAuthorityState::forget_offline_authorizations_absent_from`.
    pub(crate) fn forget_offline_peer_authorizations_absent_from(&self, present: &HashSet<String>) {
        self.authority.forget_offline_authorizations_absent_from(present);
    }

    /// Records (or clears) whether `device_id` may write `group_id`, derived
    /// from the netmap's per-group share roles.
    pub fn set_peer_group_writer(&self, device_id: &str, group_id: &str, is_writer: bool) {
        let _ = self.authority.set_peer_group_writer(device_id, group_id, is_writer);
    }

    /// Installs the peer session driver -- see the `peer_session_driver`
    /// field.
    ///
    /// No backfill against `self.peers`: a `PeerSyncSession` requires real
    /// `SessionTransports` at construction now (see that type's own doc
    /// comment), so nothing already registered could have been constructed
    /// without a stack that already existed -- there is no "session exists,
    /// transports attach later" state left for this to reconcile.
    pub fn install_peer_session_driver(&self, driver: Arc<crate::sync_adapter::PeerSessionDriver>) {
        *self.peer_session_driver.lock().unwrap_or_else(|p| p.into_inner()) = Some(driver.clone());

        // Every peer address recorded before this driver existed.
        //
        // The netmap is normally applied first: a daemon subscribes and gets a
        // push long before the reconciliation stack is built. Those pushes
        // reach the recorder, find no driver, and skip the
        // directory write -- and because a push is a snapshot, the NEXT
        // identical push is `changed == false` and skips it again. The
        // directory would then never learn where any peer answers, for the
        // life of the process, and every reconciliation dial would fail with
        // no address to use.
        //
        // Replaying what is already recorded is the whole fix, and it belongs
        // here rather than in the recorder: this is the moment the consumer
        // starts existing.
        for device_id in self.peer_connectivity.peers_with_recorded_reachability() {
            self.project_substrate_reachability(&device_id);
        }
    }

    /// Removes the peer session driver, stopping this device's half of
    /// every peer session and dropping the substrate endpoint with it.
    ///
    /// For a test that needs a genuine partition. Forgetting a peer's
    /// addresses is not enough on its own: iroh keeps its own address book
    /// for a node it has already talked to, so a device that has ever
    /// reconciled with a peer can still reach it after our own record of
    /// where it lives is cleared.
    #[cfg(any(test, feature = "test-support"))]
    pub fn take_peer_session_driver(&self) -> Option<Arc<crate::sync_adapter::PeerSessionDriver>> {
        self.peer_session_driver.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// Drops everything this state holds that holds this state back, so the
    /// last `Arc` a test drops actually frees it.
    ///
    /// A registered `PeerSyncSession` reaches back to its `DaemonState`
    /// through its deps, and an installed peer session driver through its
    /// stack; either keeps the state -- and with it both databases and their
    /// pool worker threads -- alive for the rest of the process. The daemon
    /// builds one state per process, so that is only ever a test's problem,
    /// but it is one: a test binary that builds hundreds of states ran out
    /// of threads. For a fixture's teardown, after the test has finished
    /// with the state.
    #[cfg(any(test, feature = "test-support"))]
    pub fn release_reference_cycles_for_tests(&self) {
        drop(self.take_peer_session_driver());
        for (device_id, _) in self.peers.all_sessions() {
            self.peers.remove(&device_id);
        }
    }

    /// Stops every background task this state started (see
    /// [`Self::background_tasks`]).
    #[cfg(any(test, feature = "test-support"))]
    pub fn stop_background_tasks_for_tests(&self) {
        for task in self.background_tasks.lock().unwrap_or_else(|p| p.into_inner()).drain(..) {
            task.abort();
        }
    }

    /// The peer session driver, once installed.
    pub fn peer_session_driver(&self) -> Option<Arc<crate::sync_adapter::PeerSessionDriver>> {
        self.peer_session_driver.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Registers a live session for `peer_device_id`.
    ///
    /// No attach step: `session` already carries real `SessionTransports`
    /// (a required constructor parameter -- see that type's own doc
    /// comment), resolved by its caller from [`session_transports_for`]
    /// before construction. There is no longer a "session exists, transports
    /// attach later" window this needs to close, so registration is just
    /// registration.
    pub fn register_peer_session(
        self: &Arc<Self>,
        peer_device_id: &str,
        session: Arc<yadorilink_peer_session::peer_session::PeerSyncSession>,
        sync_roots: std::collections::HashMap<String, std::path::PathBuf>,
    ) {
        let local = self.local_convergence_with_roots(sync_roots);
        self.peers.register_session(peer_device_id.to_string(), session, local);
    }

    /// Registers `session` for `peer_device_id` unless one is already
    /// registered, returning whether it was. A session somebody else
    /// registered is left standing.
    pub(crate) fn register_peer_session_if_absent(
        self: &Arc<Self>,
        peer_device_id: &str,
        session: Arc<yadorilink_peer_session::peer_session::PeerSyncSession>,
        sync_roots: std::collections::HashMap<String, std::path::PathBuf>,
    ) -> bool {
        let local = self.local_convergence_with_roots(sync_roots);
        self.peers.register_session_if_absent(peer_device_id, session, local)
    }

    /// The substrate transports a new session for `peer_device_id` would
    /// need, or `None` if this device has no reconciliation stack yet.
    ///
    /// Callers that cannot get `Some` here must not construct a session at
    /// all -- `SessionTransports` is required at construction, so there is
    /// no degraded-but-representable session to fall back to. A peer that
    /// connects before this device's own stack exists (a real window: the
    /// stack starts asynchronously, retried by `spawn_reconciliation_
    /// startup` until it succeeds) simply gets no session yet; the normal
    /// reconnect path tries again, and by then the stack is almost always
    /// up.
    pub fn session_transports_for(
        &self,
        peer_device_id: &str,
    ) -> Option<yadorilink_peer_session::ports::SessionTransports> {
        Some(self.peer_session_driver()?.stack().transports_for(peer_device_id))
    }

    /// Whether THIS device syncs `group_id` as a full replica (its link's
    /// storage mode is eager/"store everything"). A missing link or any lookup
    /// error is treated as "not a full replica" — the guard/custody callers
    /// only ever need the positive, and an absent link cannot be a replica.
    pub fn is_local_full_replica(&self, group_id: &str) -> bool {
        matches!(
            self.replica_coordinator.link_repository().materialization_policy_for_group(group_id),
            Ok(Some(yadorilink_replica_domain::session_state::MaterializationPolicy::Eager))
        )
    }

    /// Installs the custody confirmer used by the on-demand reclamation gate.
    /// Production wires a peer-to-peer confirmer (below); tests inject a
    /// deterministic one so custody behavior can be exercised without a live
    /// peer.
    #[cfg(test)]
    pub fn set_custody_confirmer(&self, confirmer: Arc<dyn CustodyConfirmer>) {
        self.durability.install_custody_confirmer(confirmer);
    }

    /// Wires the peer-to-peer custody confirmer: a confirmation is the
    /// responder's durable custody lease, acquired over the peer session.
    /// Physical cache reclamation is enabled
    /// ([`yadorilink_replica_engine::custody::REMOTE_CUSTODY_LEASES_SUPPORTED`])
    /// on platforms that offer durable namespace changes: the requester
    /// records its eviction intent and releases the lease when it no longer
    /// needs it, and a responder losing its full-replica role hands its leases
    /// off or refuses.
    pub fn install_p2p_custody_confirmer(self: &Arc<Self>) {
        self.durability.install_custody_confirmer(Arc::new(
            crate::adapters::runtime::custody::P2pCustodyConfirmer::new(self),
        ));
    }

    /// Fail-closed custody gate for on-demand cache reclamation: whether a full
    /// replica can be confirmed to *durably hold* `path`'s current version, so
    /// this on-demand device may delete its cached copy. Being *configured* as a
    /// full replica is not enough — an offline, behind, or block-missing replica
    /// must not confirm. Delegates to the installed [`CustodyConfirmer`]; with
    /// none installed (or none can confirm), it returns `false` and the blocks
    /// are retained.
    fn full_replica_custody_confirmation(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        self.durability.confirm_version(group_id, path, version_hash, blocks)
    }

    pub fn full_replica_custody_confirmed(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> bool {
        self.full_replica_custody_confirmation(group_id, path, version_hash, blocks).is_some()
    }

    fn custody_confirmation_still_valid(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        stamp: &CustodyStamp,
    ) -> bool {
        self.durability.confirmation_still_valid(group_id, path, version_hash, stamp)
    }

    /// Whether `peer_id` may be counted as a holder of `group_id`'s data for custody, handoff and
    /// durability: a netmap-authorized full-replica writer that speaks this build's versions.
    ///
    /// A peer of another version is reachable but its answers (or silence) mean nothing about
    /// what it holds, so it is excluded, not asked. That is a pause: the operation waits or is
    /// refused, nothing is deleted, and the peer counts again once the versions match.
    pub(crate) fn peer_may_hold_custody(&self, peer_id: &str, group_id: &str) -> bool {
        self.authority.peer_group_is_full_replica(peer_id, group_id)
            && self.authority.peer_is_writer(peer_id, group_id)
            && self.peers.peer_is_version_compatible(&self.peer_connectivity, peer_id)
    }

    /// Asks every currently-connected, currently-authorized full-replica peer
    /// whether it durably holds the exact version identified by
    /// `version_hash` (with `blocks` restating its ordered block list) — the
    /// exact version the caller (eviction) pinned and is about to reclaim —
    /// in parallel, and returns true as soon as any of them confirms. The
    /// version identity and block list are supplied by the caller, not
    /// re-read from the index here, so the answer is bound to the version
    /// being evicted rather than whatever the current record happens to be
    /// after a concurrent edit. Re-checks authorization against the current
    /// netmap-derived state (full-replica member and authorized writer) both
    /// before querying a peer and again before trusting its reply, and
    /// requires the netmap-authorization generation unchanged across the
    /// round-trip — so a peer revoked or demoted at any point during the
    /// (bounded) wait never confirms. Peer-to-peer only; never involves the
    /// coordination plane.
    ///
    /// Deliberately stays a per-file, exact-version check and is NOT routed
    /// through [`Self::full_replica_handoff_ready`]'s whole-group durability
    /// ROOT set (`SyncState::enumerate_group_durability_roots`): eviction
    /// custody only ever needs proof for the one version being reclaimed,
    /// never the group's whole retained history. GC unification — a future
    /// block-store sweep computing its live set from roots ∪
    /// hydration-in-progress (`MaterializationState::Hydrating`) ∪
    /// dirty/in-flight (`SyncState::list_dirty_paths`) ∪ a grace window — is
    /// out of scope here.
    ///
    /// A peer of another protocol version connects (the transport has one fixed ALPN) and is
    /// refused at the lane hello, so [`Self::peer_may_hold_custody`] leaves it out before asking:
    /// its silence is not an answer. Querying every candidate
    /// concurrently, instead of one after another,
    /// turns the old O(peers × per-request timeout) worst case into a single
    /// per-request timeout window regardless of peer count — see
    /// `VERSION_PRESENT_QUERY_OVERALL_TIMEOUT`'s doc comment.
    pub async fn confirm_version_present_via_peer(
        &self,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
    ) -> bool {
        self.confirm_version_present_witness_via_peer(group_id, path, version_hash, blocks)
            .await
            .is_some()
    }

    pub(crate) async fn confirm_version_present_witness_via_peer(
        &self,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        let candidates: Vec<(String, Arc<PeerSyncSession>)> = self
            .peers
            .all_sessions()
            .into_iter()
            .filter(|(peer_id, _session)| self.peer_may_hold_custody(peer_id, group_id))
            .collect();
        if candidates.is_empty() {
            return None;
        }

        // Capture the authorization generation before the fan-out so a reply
        // can be rejected if the netmap changed while it was in flight.
        let epoch_before = self.authority.membership_generation();
        let mut queries: FuturesUnordered<_> = candidates
            .into_iter()
            .map(|(peer_id, session)| async move {
                // Eviction custody: `for_handoff = false` requires the peer
                // to match its CURRENT record for this path, never a merely
                // retained version whose blocks retention could later
                // reclaim (which would leave this device, having already
                // dropped its own cached copy, with no durable holder).
                let confirmed = session
                    .request_version_present(group_id, path, version_hash, blocks, false)
                    .await;
                (peer_id, confirmed)
            })
            .collect();

        let confirmed_by_any = tokio::time::timeout(VERSION_PRESENT_QUERY_OVERALL_TIMEOUT, async {
            while let Some((peer_id, confirmed)) = queries.next().await {
                // Re-verify AFTER the reply: the peer must still be an
                // authorized full-replica writer AND the netmap-authorization
                // view must not have changed at all during the wait, so a
                // revoke/demote — or any membership churn — mid-round-trip
                // fails closed rather than trusting a now-stale ACK.
                if confirmed
                    && self.authority.membership_generation() == epoch_before
                    && self.peer_may_hold_custody(&peer_id, group_id)
                {
                    return Some(CustodyStamp::new(peer_id, epoch_before));
                }
            }
            None
        })
        .await;
        // A timed-out fan-out (the defense-in-depth backstop above, not the
        // expected case) is treated the same as "no peer confirmed" — fail
        // closed, matching every other unconfirmed outcome here.
        confirmed_by_any.unwrap_or(None)
    }

    /// Ends the lease `peer_id` holds for this device on exactly this version.
    /// `true` once the peer acknowledged; `false` when it is not connected or
    /// did not answer, in which case the lease stays and the release is
    /// retried.
    pub async fn release_custody_lease_via_peer(
        &self,
        peer_id: &str,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        attempt_token: [u8; 16],
    ) -> bool {
        let Some((_, session)) =
            self.peers.all_sessions().into_iter().find(|(id, _)| id == peer_id)
        else {
            return false;
        };
        session.request_custody_release(group_id, path, version_hash, attempt_token).await
    }

    /// Whether some OTHER full replica of `group_id` can be confirmed, right
    /// now, to durably hold the current version of EVERY file in the group —
    /// the gate an eager device must pass before it may give up its own
    /// full-replica status and demote to on-demand (see
    /// `control_socket`'s storage-mode-change handler). Without central
    /// storage a full replica is the only durable copy of a group's files, so
    /// this is fail-closed throughout: an unreadable file list, no single
    /// peer that holds the whole group, or any non-`File` record it cannot
    /// even classify all report "not ready" rather than risk a handoff that
    /// turns out to have nowhere durable to land. A group with no current
    /// files at all is vacuously ready — there is nothing to hand off.
    ///
    /// Readiness is decided PER PEER, not per file: it is not enough that
    /// every file is held by *some* peer (peer B could hold file1 and peer C
    /// hold file2 with neither holding both, which would still leave the
    /// group with zero complete durable copies). A handoff is ready only when
    /// at least one *single* connected, authorized full-replica writer peer
    /// is confirmed to hold every file — a genuine complete replica to hand
    /// off to. See [`Self::peer_holds_entire_group`].
    ///
    /// Only `RecordKind::File` records need confirming (directories and
    /// symlinks carry no blocks); a deleted record needs no durable holder
    /// either.
    ///
    /// Also backs the unlink durability gate
    /// (`control_socket::ensure_unlink_keeps_a_full_replica`): a device
    /// giving up its OWN eager status only ever needs to confirm some other
    /// peer is ready, which is exactly what this checks. Revoke/device-removal
    /// use the sibling [`Self::another_full_replica_is_ready_excluding`]
    /// instead, since there the device losing access is not the caller.
    pub async fn another_full_replica_is_ready(&self, group_id: &str) -> bool {
        self.full_replica_handoff_ready(group_id, None).await.is_some()
    }

    /// Like [`Self::another_full_replica_is_ready`], but a specific
    /// `excluded_device_id` is never counted as the confirming replica, even
    /// if it is currently connected and recorded as an eager full replica.
    /// Used by the revoke/device-removal readiness pre-check: the device
    /// about to lose access must not be allowed to count as its own handoff
    /// target — the whole point of the check is confirming some OTHER
    /// full replica is ready before that device is removed.
    pub async fn another_full_replica_is_ready_excluding(
        &self,
        group_id: &str,
        excluded_device_id: &str,
    ) -> bool {
        self.full_replica_handoff_ready(group_id, Some(excluded_device_id)).await.is_some()
    }

    /// Like [`Self::another_full_replica_is_ready`], but on success also
    /// returns the exact durability-root-set digest the confirmation was
    /// made against (`None` on a not-ready answer, same as the plain bool
    /// form). A caller about to COMMIT a daemon-driven role loss (unlink,
    /// demote) must capture this digest here and then re-fetch
    /// [`Self::local_durability_roots_digest`] immediately before the local
    /// commit, refusing (or requiring `--force`) if the two differ — see
    /// `control_socket::ensure_unlink_keeps_a_full_replica`/
    /// `set_storage_mode`. A changed digest means this device's own root set
    /// moved (a local edit landed) after the peer confirmed coverage of the
    /// OLD set, so that confirmation no longer proves anything about the new
    /// one — closing the TOCTOU window between check and commit.
    ///
    /// Only the non-excluding form is offered: the CLI-orchestrated
    /// revoke/device-remove commit happens on the coordination Worker, which
    /// this daemon cannot wrap in a re-check immediately before that commit —
    /// see `durability_force.rs`'s own doc comment for why that TOCTOU window
    /// is left as a documented, bounded gap instead.
    pub async fn full_replica_handoff_ready_digest(&self, group_id: &str) -> Option<[u8; 32]> {
        self.full_replica_handoff_ready(group_id, None).await.map(|proof| proof.root_digest())
    }

    /// This device's own current durability-root-set digest for `group_id`,
    /// read fresh from the local index only — no peer round trip. See
    /// [`Self::full_replica_handoff_ready_digest`]'s doc comment for the
    /// re-confirm pattern this backs. `None` (fail closed) if the local
    /// enumeration itself errors.
    pub fn local_durability_roots_digest(&self, group_id: &str) -> Option<[u8; 32]> {
        self.durability_roots_for_group(group_id).map(|roots| roots.digest)
    }

    /// Records this device's coordination-plane address + access token —
    /// called once, early in `app.rs`'s startup path, whenever both are
    /// available. A no-op if already set (matches `OnceLock::set`'s own
    /// semantics; every production call site only ever calls this once
    /// anyway).
    pub fn set_coordination_client_config(
        &self,
        addr: String,
        auth: yadorilink_fapi_client::CoordinationAuth,
    ) {
        let _ = self.coordination_client_config.set(CoordinationClientConfig { addr, auth });
    }

    /// Installs the provider-content probe. A no-op if already set.
    pub(crate) fn set_provider_content_probe(&self, probe: ProviderContentProbe) {
        let _ = self.provider_content_probe.set(probe);
    }

    /// `Ok(())` only when the provider root's wanted content is complete on the OS; the error says
    /// what is missing. Fail closed: no probe installed is an error.
    pub(crate) fn provider_content_complete(&self, root_id: &str) -> Result<(), String> {
        match self.provider_content_probe.get() {
            Some(probe) => probe(root_id),
            None => Err("File Provider support has not started".to_owned()),
        }
    }

    /// Overrides how often the daemon-level materialization-repair sweep
    /// (`spawn_materialization_repair_task`) re-drives any change still
    /// unapplied — see `materialization_repair_sweep_interval`'s doc
    /// comment. A test whose scenario can leave a change legitimately
    /// stalled for multiple production-cadence (90s) intervals with no
    /// other retry trigger in flight (no new local writes, no incoming
    /// traffic) can opt into a much shorter one instead of either widening
    /// its own timeout budget to absorb 90s gaps or accepting a wall-clock
    /// tax production doesn't need. The job reads the interval fresh before
    /// each sleep, so a change takes effect from the next sleep; a sleep
    /// already in progress still runs to its old length.
    pub fn set_materialization_repair_sweep_interval(&self, interval: Duration) {
        *self.materialization_repair_sweep_interval.lock().unwrap_or_else(|p| p.into_inner()) =
            interval;
    }

    /// `pub(crate)`: read by `maintenance::materialization_repair::
    /// MaterializationRepairJob`, which owns this scheduler's sleep-loop
    /// (moved out of this file's own former
    /// `spawn_materialization_repair_scheduler`).
    pub(crate) fn materialization_repair_sweep_interval(&self) -> Duration {
        *self.materialization_repair_sweep_interval.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Test seam: publishes a sweep round's outcome for `group_id` the way
    /// `background_custody::run_cycle` does -- see
    /// `DurabilityService::publish_background_custody` for the epoch and
    /// freshness rules. `membership_generation` is the generation captured
    /// BEFORE the round trip and is what the record is stamped with; the
    /// current generation read here only decides whether a still-fresh
    /// positive survives a negative.
    #[cfg(test)]
    pub(crate) fn publish_background_custody(
        &self,
        group_id: &str,
        outcome: BackgroundCustodyEvidence,
        membership_generation: u64,
        epoch_before: u64,
    ) -> bool {
        let current_membership_generation = self.authority.membership_generation();
        self.durability.publish_background_custody(
            group_id,
            outcome,
            membership_generation,
            epoch_before,
            current_membership_generation,
        )
    }

    /// The device whose answer to the background custody check currently backs
    /// `group_id`'s `Protected` status; `None` when the confirmation is not fresh or
    /// vacuous (nothing to corroborate).
    pub(crate) fn group_custody_confirmed_peer(&self, group_id: &str) -> Option<String> {
        if !self.has_fresh_custody_confirmation(group_id) {
            return None;
        }
        self.durability
            .fresh_corroboration(group_id, self.authority.membership_generation())
            .and_then(|(peer, _)| peer)
    }

    /// Whether `group_id` has a whole-group peer-confirmed custody record
    /// in cache that is BOTH still within `CUSTODY_CONFIRMATION_STALENESS_
    /// BOUND` of its confirmation time (monotonic clock, immune to a wall-
    /// clock adjustment) AND was recorded
    /// under the CURRENT `membership_generation` (any peer netmap change
    /// since invalidates it outright, regardless of age), AND still matches this group's CURRENT
    /// durability-root digest (a cheap local DB read/hash, not a network
    /// round-trip -- see `durability_roots_for_group`'s own doc comment).
    ///
    /// That last check is what stops a confirmed group's content changing
    /// -- e.g. a new file synced in as a placeholder -- from riding a
    /// stale confirmation as `Protected` for up to the full staleness
    /// bound: a content/root-set change never bumps the netmap-
    /// authorization `membership_generation` counter, so the generation
    /// check alone cannot catch it (this cache's sibling consumer,
    /// `fetch_available_via_confirmed_peer`, already re-derived and
    /// compared the current digest for exactly this reason; this method
    /// had not, so a group could report `Protected` while
    /// `fetch_availability` correctly, and misleadingly, showed
    /// `UnavailableNow` for content no peer had actually confirmed).
    /// Digest equality also directly proves the vacuous (no-peer,
    /// empty) case is still vacuous, since an empty set has a fixed digest
    /// distinct from any non-empty one -- so this subsumes the separate "is
    /// the group still empty" check an earlier version of this method took
    /// as its own parameter. Fail closed (`false`) if the current
    /// enumeration itself errors.
    ///
    /// The digest compared is the CURRENT-state one, because that is what a
    /// background cycle publishes and the only one that converges between
    /// honest replicas -- see `RootSetSummary`'s own doc comment. A change
    /// to retained history alone therefore no longer invalidates a
    /// corroboration, which is correct: the corroboration never claimed
    /// anything about retained history in the first place.
    fn has_fresh_custody_confirmation(&self, group_id: &str) -> bool {
        let Some((_, confirmed_digest)) =
            self.durability.fresh_corroboration(group_id, self.authority.membership_generation())
        else {
            return false;
        };
        // The CURRENT-state digest, matching what a cycle publishes. Not
        // the whole-root-set one: those are different sets the moment a
        // group retains a single superseded version, and comparing one
        // against the other would make this answer `false` forever.
        self.local_root_set_summary(group_id)
            .is_some_and(|now| now.current_digest == confirmed_digest)
    }

    /// This device's own root-set summary for `group_id`, memoised against
    /// the group's root-set generation -- see
    /// `DurabilityService::local_root_set_summary` for the memo's validity
    /// and fail-closed rules.
    ///
    /// `pub` rather than `pub(crate)` so an integration test can state the
    /// condition it is constructing -- that two devices agree about current
    /// content and disagree about retained history is the premise of the
    /// test that pins those two as different questions, and a test that
    /// merely assumed it would stop testing anything the day the premise
    /// stopped holding.
    pub fn local_root_set_summary(&self, group_id: &str) -> Option<RootSetSummary> {
        self.durability
            .local_root_set_summary(self.replica_coordinator.file_index_repository(), group_id)
    }

    /// What kind of evidence `group_id`'s durability status is currently
    /// standing on.
    ///
    /// A payload-verified answer outranks an index-corroborated one, and
    /// both are subject to the same staleness bound and the same
    /// re-derivation of the digest they were made against -- an old proof of
    /// a root set this device has moved past is not evidence about the one
    /// it holds now.
    pub fn group_durability_evidence(&self, group_id: &str) -> DurabilityEvidence {
        if let Some(digest) = self.durability.fresh_strong_proof_digest(group_id) {
            if self.local_durability_roots_digest(group_id) == Some(digest) {
                return DurabilityEvidence::VerifiedPayload;
            }
        }
        if self.has_fresh_custody_confirmation(group_id) {
            return DurabilityEvidence::CorroboratedIndex;
        }
        DurabilityEvidence::None
    }

    /// Whether `group_id`'s durability is `Unknown` only because no custody
    /// check has run for it yet. See [`crate::durability_service::first_check_pending`].
    pub fn group_durability_check_pending(&self, group_id: &str) -> bool {
        let (mut facts, _) = self.gather_durability_facts(group_id);
        facts.latched_unknown = self.durability.is_latched_unknown(group_id);
        crate::durability_service::first_check_pending(&facts)
    }

    /// How many peers a background cycle would currently ask about
    /// `group_id`.
    ///
    /// Exists so a scale test can state its own premise. The assertion that
    /// matters there is "two candidate peers still cost zero per-root
    /// queries", and a test that never checked there were two would pass
    /// just as happily against one.
    pub fn custody_candidate_peer_count_for_tests(&self, group_id: &str) -> usize {
        crate::background_custody::custody_candidate_peers(
            &self.peers,
            &self.peer_connectivity,
            &self.authority,
            group_id,
        )
        .len()
    }

    /// Runs one background custody cycle for `group_id`, synchronously from
    /// the caller's perspective, and publishes what it found.
    ///
    /// The cycle itself lives in [`crate::background_custody::run_cycle`],
    /// not here, and that is not filing. The one property this whole design
    /// rests on is that the background path cannot reach the action-time
    /// proof, and the architecture manifest enforces it by forbidding that
    /// module from naming any strong-proof entry point — which requires the
    /// cycle to be in a file such a rule can point at. This method is the
    /// public name tests and the maintenance job call; it deliberately does
    /// nothing but delegate.
    pub async fn refresh_custody_confirmation(&self, group_id: &str) -> BackgroundCustodyOutcome {
        let components = crate::background_custody::CustodyCycleComponents {
            durability: &self.durability,
            authority: &self.authority,
            peers: &self.peers,
            peer_connectivity: &self.peer_connectivity,
            file_index: self.replica_coordinator.file_index_repository(),
        };
        crate::background_custody::run_cycle(&components, group_id).await
    }

    /// Event-driven trigger for [`Self::refresh_custody_confirmation`]: a peer
    /// just became usable, so confirm custody now instead of waiting for the
    /// periodic sweep (which stays as the lost-wake backstop). Never blocks;
    /// at most one refresh is pending per group, so a burst of sessions
    /// coalesces. Returns how many refresh tasks this call scheduled.
    /// Must be called inside a Tokio runtime.
    pub(crate) fn request_custody_refresh(self: &Arc<Self>, groups: &[String]) -> usize {
        let mut scheduled = 0;
        for group in groups {
            if !self.durability.mark_custody_refresh_pending(group) {
                continue;
            }
            scheduled += 1;
            let state = self.clone();
            let group = group.clone();
            tokio::spawn(async move {
                state.durability.clear_custody_refresh_pending(&group);
                let _ = state.refresh_custody_confirmation(&group).await;
            });
        }
        scheduled
    }

    /// Positively confirms
    /// (never merely infers from connectivity) that at least one of this
    /// group's currently-required (repair-candidate) paths has no
    /// obtainable/durable holder among current membership -- see
    /// `DurabilityFacts::known_unobtainable_required_content`'s own doc
    /// comment for the full definition and the four facts this proves
    /// before returning `true`. Only meaningful for a local full replica:
    /// an OnDemand device's own `Remote` rows are its ordinary
    /// steady state, not a durability signal.
    fn has_known_unobtainable_required_content(&self, group_id: &str) -> bool {
        if !self.is_local_full_replica(group_id) {
            return false;
        }
        let Ok(paths) = self
            .replica_coordinator
            .materialization_state_repository()
            .list_materialization_repair_candidates(group_id)
        else {
            return false;
        };
        if paths.is_empty() {
            return false;
        }
        let current_writers = self.authority.current_group_writers(group_id);
        for path in &paths {
            // Facts 1+2 (still native-justified, missing locally) are
            // implied by `path` being a repair candidate at all --
            // `list_materialization_repair_candidates`'s own WHERE
            // clause already requires `state = 'current'`, `deleted = 0`,
            // and `placeholder`/`hydrating`.
            // ONE read for the origin and the version alike. Refusal
            // evidence is keyed by the exact version it is about, and
            // `ensure_blocks_present_core` records it under the version
            // its payload named. A lookup key stitched together out of
            // six separate reads can name a version no incarnation of
            // the row ever had, and would then match nothing this or any
            // other device ever recorded -- silently answering "no
            // refusals" for a path that has them, which is the fail-open
            // direction for "this content is unobtainable".
            let Ok(Some(row)) = self
                .replica_coordinator
                .file_index_repository()
                .canonical_current_row(group_id, path)
            else {
                continue;
            };
            let Some(origin_device_id) = row.origin_device_id.clone() else {
                continue;
            };
            let current_version_hash = row.version_hash().to_hex();
            let Ok(refusers) = self
                .replica_coordinator
                .materialization_state_repository()
                .refusing_peers_for_path(group_id, path, &current_version_hash)
            else {
                continue;
            };
            // Fact 3: the presumed sole holder (this path's origin) has
            // left authoritative membership, OR has itself explicitly
            // refused this exact version. Without that second clause,
            // this check would exempt the origin from Fact 4 purely on
            // still-current-writer membership, with no way for it to ever
            // become "accounted for" -- a path could sit in `Protecting`
            // forever once the origin device itself was the (sole)
            // recorded refuser. That's reachable in real production, not
            // just in a harness: `apply_locked_record`'s `incoming_origin`
            // falls back to attributing origin to the RELAYING peer
            // whenever that peer's own `get_origin_device_id` lookup for
            // the path came back empty -- so a relayed conflict copy can
            // end up with `origin_device_id` pointing at a peer that never
            // actually held the content, while the true original author
            // has already left the group and is invisible to this check
            // entirely. Still a current writer AND has never refused =>
            // still a plausible holder => never AtRisk from this path
            // alone. Still a current writer but HAS refused => no longer
            // exempt; falls through to Fact 4 below, where it's already
            // correctly counted via `refusers.contains`.
            if current_writers.contains(&origin_device_id) && !refusers.contains(&origin_device_id)
            {
                continue;
            }
            // Fact 4: every OTHER current writer has EXPLICITLY,
            // definitively refused this EXACT version of this path (never
            // inferred from an untried/offline writer's silence, and
            // never conflated with a refusal recorded against some OTHER
            // version this path once had -- see `block_fetch_refusals`'s
            // own schema doc comment for why refusal evidence is bound to
            // `version_hash`, not just `path`). The origin device is not
            // exempted here: if it's still present, it
            // only reached this point because it explicitly refused too
            // (the check above), so `refusers.contains` already accounts
            // for it correctly without a separate carve-out.
            let unaccounted_for =
                current_writers.iter().any(|id| id != &self.device_id && !refusers.contains(id));
            if !unaccounted_for {
                return true;
            }
        }
        false
    }

    /// Whether this group has REAL content-confirmed peer
    /// custody evidence (the same fresh, staleness/generation-bound
    /// `DurabilityService`'s custody confirmation cache entry that backs durability's
    /// `Protected`) whose confirming peer is ALSO currently reachable.
    /// `fetch_availability`'s only source of peer-served `AvailableNow`
    /// evidence for content not already hydrated locally.
    ///
    /// Deliberately NOT the netmap's content-blind "declared full-replica
    /// writer" fact alone (an earlier version of this method checked
    /// exactly that plus reachability, which is insufficient: a peer can be reachable and declared
    /// a full replica while genuinely still catching up itself, or its
    /// declaration can simply be stale/wrong -- neither proves it holds
    /// THIS group's current content). Requiring a fresh confirmation
    /// closes that gap: `DurabilityService`'s custody confirmation cache is only ever populated
    /// by a real peer round-trip in which that peer reported an `Eager`
    /// policy, a current-state digest equal to this device's own, and every
    /// one of its own current rows materialized. That last part is what
    /// keeps this from being the very approximation it replaced: a peer
    /// that has projected the changes and fetched none of the content has
    /// an identical digest and reports itself unmaterialized.
    ///
    /// It is nonetheless weaker than it was, and the difference is worth
    /// stating rather than discovering. The cache used to be populated by
    /// the whole-group handoff proof, whose per-root check also required
    /// the peer to hold verified BLOCK PROVENANCE for the group -- the
    /// serving authorization it will later demand of itself before actually
    /// answering a block request. Nothing in the background summary
    /// establishes that, so a peer holding the content without provenance
    /// for this group would be reported here as able to serve it and would
    /// then refuse the fetch. That state is narrow -- provenance is
    /// recorded when verified bytes are obtained through the group, which
    /// is also how the content got there -- but it is not impossible, and
    /// this axis is the one place the background/action-time split is
    /// visible to a user rather than only to a gate.
    ///
    /// The confirming peer's CURRENT reachability is checked in addition
    /// to the confirmation's own freshness/generation bounds: the
    /// confirmation proves the peer held the content as of its own
    /// staleness window, but says nothing about whether that peer is
    /// reachable RIGHT NOW -- a peer that has since gone offline cannot
    /// actually serve a fetch, even if its last confirmation is still
    /// technically fresh.
    ///
    /// The current-digest re-derivation below has the identical role as
    /// `has_fresh_custody_confirmation`'s own -- see that method's doc
    /// comment.
    pub(crate) fn fetch_available_via_confirmed_peer(&self, group_id: &str) -> bool {
        let Some((peer_device_id, confirmed_digest)) =
            self.durability.fresh_corroboration(group_id, self.authority.membership_generation())
        else {
            return false;
        };
        // Re-derive the group's CURRENT durability-root digest (a cheap
        // local DB read/hash, not a network round-trip -- see
        // `durability_roots_for_group`'s own doc comment) and require it
        // to still match what the cached confirmation actually proved.
        // Without this, a fresh confirmation stays trusted across an
        // intervening content change (e.g. a new file synced in as a
        // placeholder) that its `membership_generation` binding alone
        // never catches, since content/root-set changes never bump the
        // netmap-authorization generation counter -- otherwise a real
        // HIGH-severity false-`AvailableNow` gap. Fail closed (`None`) if the current enumeration
        // itself errors.
        let Some(current_roots) = self.local_root_set_summary(group_id) else {
            return false;
        };
        if current_roots.current_digest != confirmed_digest {
            return false;
        }
        match peer_device_id {
            None => current_roots.current_count == 0,
            Some(device_id) => {
                self.peer_connectivity.reachability(&device_id).is_some_and(|r| r.is_connected())
            }
        }
    }

    /// This device's coordination-plane address + access token, if recorded
    /// — see [`Self::set_coordination_client_config`]'s doc comment for when
    /// it is (and, notably, isn't: most of this crate's own unit tests never
    /// call the setter) set.
    pub fn coordination_client_config(&self) -> Option<&CoordinationClientConfig> {
        self.coordination_client_config.get()
    }

    /// Where the fold loop asks for seal authorizations and a flush for publication
    /// evidence: the coordination
    /// plane this daemon is configured for, or `None` before it has one.
    /// A test build may stand a fake in for it
    /// ([`Self::test_seal_checkpoint_source`]).
    pub fn seal_checkpoint_source(
        &self,
    ) -> Option<Arc<dyn crate::checkpoint_source::CheckpointSource>> {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(source) =
            self.test_seal_checkpoint_source.lock().unwrap_or_else(|p| p.into_inner()).clone()
        {
            return Some(source);
        }
        self.coordination_client_config().map(|config| {
            Arc::new(crate::checkpoint_source::ProductionCheckpointSource::new(
                config.addr.clone(),
                config.auth.clone(),
            )) as Arc<dyn crate::checkpoint_source::CheckpointSource>
        })
    }

    /// Stops the real-time periodic `daemon-state-membership-recovery-sweep`
    /// (role-loss + membership reconciliation, unconditional and
    /// real-time -- see that sweep's own doc comment) from acting on THIS
    /// `DaemonState`'s journal rows. A recovery-diagnosis crash-
    /// qualification test builds a real `DaemonState` (through the same
    /// `new()` production callers use) specifically to plant a membership/
    /// role-loss journal row and read it back through the real
    /// `recovery show` path -- the SAME background sweep this daemon would
    /// also run in production would otherwise race that read (some sweep
    /// branches mutate or delete a matching row unconditionally, with no
    /// age gate, regardless of whether a coordination-plane config is even
    /// set), corrupting the very state under test. Must be called
    /// synchronously, before this task's first `.await` after construction
    /// -- the spawned sweep task cannot run even one line of its own code
    /// until the caller yields, so calling this immediately after `new()`
    /// is race-free by construction, not by timing luck.
    #[cfg(test)]
    pub fn disable_membership_recovery_sweep_for_test(&self) {
        self.membership_recovery_sweep_disabled_for_test
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// `local_path` is the link this operation concerns (both demote and
    /// unlink always name one). FAIL-CLOSED: the Prepared row is the
    /// durability mechanism this whole saga rests on, so its write is NOT
    /// best-effort. If it fails (a genuine local storage error), this
    /// returns `Err` and the caller (`control_socket`'s demote/unlink
    /// paths) MUST abort BEFORE calling `commit_handoff_role_loss` —
    /// committing the role loss on the Worker without a durable recovery
    /// record would reopen the exact split-state hole (Worker on-demand /
    /// local eager, with nothing to drive a retry) the journal exists to
    /// close. Aborting here is always safe: nothing has been committed on
    /// either side yet, so a failed Prepared write leaves no split, only a
    /// plain "couldn't start the operation, retry" error.
    pub fn open_role_loss_operation(
        &self,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
        action: RoleLossAction,
        local_path: &str,
    ) -> Result<String, String> {
        let operation_id = uuid::Uuid::new_v4().to_string();
        self.replica_coordinator
            .role_loss_operation_repository()
            .insert_role_loss_operation(
                &operation_id,
                group_id,
                RoleLossOperationParams {
                    source_device_id: &self.device_id,
                    target_device_id,
                    lease_id,
                    action,
                    local_path: Some(local_path),
                    now_unix: now_unix(),
                },
            )
            .map(|()| operation_id)
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    group_id,
                    target_device_id,
                    "refusing to commit a handoff role loss: could not persist its durable \
                     rollback journal row (fail-closed; nothing has been committed yet)"
                );
                format!(
                    "could not record the durable rollback journal for this operation ({e}); \
                     nothing was committed, so it is safe to retry"
                )
            })
    }

    /// Advances a role-loss-operation journal row to `WorkerCommitted` —
    /// called immediately after the coordination service role-loss commit
    /// succeeds, so a crash from this point on is reconciled by the
    /// startup + periodic sweep (`ReplicaRoleService::reconcile_role_loss`)
    /// instead of left as a split state.
    pub fn mark_role_loss_worker_committed(&self, operation_id: &str, membership_generation: i64) {
        if let Err(e) = self
            .replica_coordinator
            .role_loss_operation_repository()
            .mark_role_loss_worker_committed(operation_id, membership_generation, now_unix())
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a role-loss operation journal row to WorkerCommitted"
            );
        }
    }

    /// Deletes a role-loss-operation journal row whose coordination service
    /// commit never happened (the Worker call itself failed or was refused)
    /// — nothing was committed on either side, so the row never protected
    /// anything real.
    pub fn discard_role_loss_operation(&self, operation_id: &str) {
        if let Err(e) = self
            .replica_coordinator
            .role_loss_operation_repository()
            .delete_role_loss_operation(operation_id)
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to delete an abandoned role-loss operation journal row"
            );
        }
    }

    /// Closes out a role-loss-operation journal row on the normal success
    /// path: the coordination service commit AND the matching local
    /// policy/link change both landed. Advances to `LocalCommitted` then
    /// deletes the row — the same outcome as before this journal existed,
    /// just with a journal row written and cleaned up around it.
    pub fn settle_role_loss_operation_success(&self, operation_id: &str) {
        let now = now_unix();
        if let Err(e) = self
            .replica_coordinator
            .role_loss_operation_repository()
            .advance_role_loss_operation(operation_id, RoleLossOperationState::LocalCommitted, now)
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a role-loss operation journal row to LocalCommitted"
            );
        }
        if let Err(e) = self
            .replica_coordinator
            .role_loss_operation_repository()
            .delete_role_loss_operation(operation_id)
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to delete a LocalCommitted role-loss operation journal row; it will be \
                 cleaned up by the next reconciliation sweep"
            );
        }
    }

    /// Called instead of releasing tickets / falling through to a plain
    /// revoke-remove, so an outcome that MAY already have committed on the
    /// coordination plane is never silently treated as "never happened".
    /// Never overwrites an existing row under `operation_id` -- returns
    /// `Ok(false)` on conflict so the caller can retry under a fresh id
    /// (see `replica_membership_service.rs`'s
    /// `open_membership_operation`), rather than silently clobbering
    /// whatever that row already recorded.
    #[allow(clippy::too_many_arguments)]
    pub fn try_persist_membership_operation(
        &self,
        operation_id: &str,
        action: MembershipOperationAction,
        commit_mode: MembershipCommitMode,
        removed_device_id: &str,
        group_ids: &[String],
        target_device_ids: &[String],
        lease_ids: &[Option<String>],
        state: MembershipOperationState,
        durability_scope: MembershipDurabilityScope,
        latch_group_ids: &[String],
        last_error: Option<&str>,
    ) -> Result<bool, String> {
        let inserted = self
            .replica_coordinator
            .membership_operation_repository()
            .try_insert_membership_operation(
                operation_id,
                action,
                commit_mode,
                removed_device_id,
                group_ids,
                target_device_ids,
                lease_ids,
                state,
                durability_scope,
                latch_group_ids,
                last_error,
                now_unix(),
            )
            .map_err(|e| e.to_string())?;
        if inserted && durability_scope == MembershipDurabilityScope::Unknown {
            self.durability.set_scope_unknown(true);
        }
        Ok(inserted)
    }

    /// Advances an existing `Prepared` membership-operation row to
    /// `Ambiguous` — the row is KEPT (not deleted), unlike
    /// [`Self::settle_membership_operation`]: an ambiguous commit's real
    /// outcome is still unknown, so its journal row must survive for
    /// `reconcile_ambiguous_membership_operations` to resolve later.
    pub fn mark_membership_operation_ambiguous(&self, operation_id: &str, detail: &str) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .mark_membership_operation_state(
                operation_id,
                MembershipOperationState::Ambiguous,
                Some(detail),
                now_unix(),
            )
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a membership operation journal row to Ambiguous"
            );
        }
    }

    /// Marks a membership-operation journal row's outcome as settled
    /// (`Completed`/`DefinitelyRejected`) by deleting it directly --
    /// best-effort, matching [`Self::settle_role_loss_operation_success`].
    /// Deletes in ONE step rather than updating to `final_state` and then
    /// deleting: a row is never re-read after reaching a terminal state
    /// (`scan_open_membership_operations` excludes both terminal states),
    /// so an update that succeeds but is followed by a failed delete would
    /// leave an orphaned row invisible to every future sweep -- there is no
    /// "cleaned up by the next reconciliation sweep" for a row a terminal
    /// state itself hides from that sweep's own query.
    pub fn settle_membership_operation(
        &self,
        operation_id: &str,
        _final_state: MembershipOperationState,
    ) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .delete_membership_operation(operation_id)
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to delete a settled membership operation; its non-terminal journal row \
                 remains available for idempotent recovery"
            );
        }
        self.refresh_unknown_scope_membership_marker();
    }

    /// Deletes a membership-operation journal row whose scope became known
    /// (an unknown-scope marker converted to per-group latches) — matching
    /// [`Self::discard_role_loss_operation`].
    pub fn discard_membership_operation(&self, operation_id: &str) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .delete_membership_operation(operation_id)
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to delete a resolved membership operation journal row"
            );
        }
        self.refresh_unknown_scope_membership_marker();
    }

    /// Advances a membership-operation row to `RecoveryBlocked` -- automatic
    /// recovery refused (an operation_id conflict, a local/remote request
    /// identity mismatch, or a malformed journal row). The row is KEPT (not
    /// deleted): unlike a confirmed terminal outcome, there is nothing safe
    /// to conclude here, so it stays for operator attention and is excluded
    /// from periodic resend/settlement.
    pub fn mark_membership_operation_recovery_blocked(&self, operation_id: &str, detail: &str) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .mark_membership_operation_state(
                operation_id,
                MembershipOperationState::RecoveryBlocked,
                Some(detail),
                now_unix(),
            )
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a membership operation journal row to RecoveryBlocked"
            );
        }
    }

    /// Advances a membership-operation row to `LocalSettlementPending` --
    /// the remote mutation is confirmed committed, but a required local
    /// follow-up (e.g. a post-commit durability latch) failed and must be
    /// retried. The row is KEPT so the next reconciliation sweep retries the
    /// local step; it must never be silently discarded until that step also
    /// succeeds.
    pub fn mark_membership_operation_local_settlement_pending(
        &self,
        operation_id: &str,
        detail: &str,
    ) {
        if let Err(e) = self
            .replica_coordinator
            .membership_operation_repository()
            .mark_membership_operation_state(
                operation_id,
                MembershipOperationState::LocalSettlementPending,
                Some(detail),
                now_unix(),
            )
        {
            tracing::warn!(
                error = %e,
                operation_id,
                "failed to advance a membership operation journal row to LocalSettlementPending"
            );
        }
    }

    /// Re-derives `DurabilityService`'s unknown-scope marker from the journal —
    /// called after any delete/settle that might have resolved the last
    /// outstanding `Unknown`-durability-scope row, so `group_durability_status`
    /// stops forcing `Unknown` account-wide once every such row is
    /// resolved.
    fn refresh_unknown_scope_membership_marker(&self) {
        let still_present = self
            .replica_coordinator
            .membership_operation_repository()
            .has_open_unknown_durability_scope_operation()
            .unwrap_or(true);
        self.durability.set_scope_unknown(still_present);
    }

    /// Requests a full-replica-handoff lease for `group_id` — the daemon-side
    /// half of `RequestHandoffLeaseRequest`. Runs this device's own local
    /// readiness check first (reusing [`Self::full_replica_handoff_ready_
    /// digest`] exactly as-is: called TARGET-side here, it asks "does some
    /// other connected full-replica peer confirm holding everything I hold" —
    /// the same predicate `CheckFullReplicaHandoffReadyRequest` asks
    /// SOURCE-side, just invoked for the opposite purpose. Once sync has
    /// converged the two devices' durability-root sets, this device's own
    /// root set IS the group's current root set, so "a peer confirms holding
    /// everything I hold" and "I hold everything the group currently has" are
    /// the same fact from either side).
    ///
    /// On a positive local check, calls the coordination service to actually issue
    /// the lease (giving a real `lease_id`), then — ONLY THEN — atomically
    /// re-enumerates this device's exact `(path, version_seq)` root rows AND
    /// records the local pin for them in one transaction
    /// (`sync_state.handoff_lease_repository().record_handoff_lease_atomic`),
    /// so no retention sweep can evict a row between enumerating it and
    /// pinning it (the gap a separate `record_handoff_lease` call alone
    /// leaves — see its sibling's own doc comment). Ordering the Worker call
    /// first is what makes this
    /// atomic pin possible without a local schema change: the real
    /// Worker-issued `lease_id` is already in hand, so the single atomic
    /// write only ever inserts/updates one row keyed on it, never
    /// provisions a placeholder first.
    ///
    /// The atomic pin also returns the digest of exactly the set it pinned.
    /// If that digest no longer matches the readiness digest captured in
    /// step one — the root set moved between the readiness attestation and
    /// the atomic pin landing (e.g. a retention sweep evicted a root, or a
    /// new local version landed) — this aborts: it ATTEMPTS to release both
    /// the just-written local pin
    /// (`sync_state.handoff_lease_repository().set_handoff_lease_state`,
    /// `Released`) and the just-granted Worker lease
    /// (`coordination_client::release_handoff_lease`), then returns `None`,
    /// exactly as if no lease had been obtained at all. Both releases are
    /// best-effort (each swallows its own error): if either fails, the
    /// local time-based pin expiry (`expires_at_unix`, the check
    /// `SyncState::leased_version_keys_for_group` actually enforces) and the
    /// Worker's own TTL sweep are the backstop, so nothing lingers past its
    /// expiry regardless — the same abandoned-lease model the design already
    /// relies on. This is a safe decline, not a data-loss risk: the caller
    /// (`control_socket`) treats `None` as "no lease this round" and the
    /// existing local digest-recapture-then-recheck gate
    /// (`SyncState::recheck_digest_then_remove_link`/`recheck_digest_then_
    /// set_materialization_policy`) is what actually protects the role-loss
    /// commit either way. The same best-effort Worker release is also
    /// attempted if the atomic local pin itself errors after a successful
    /// Worker POST, so no post-POST failure path leaves a granted Worker
    /// lease with no active cleanup attempt.
    ///
    /// Neither digest nor any pinned `(path, version_seq)` row is ever sent
    /// to the coordination service: the lease request/release calls carry only
    /// `(group_id, target_device_id[, lease_id])`
    /// (`coordination_client::request_handoff_lease`/`release_handoff_
    /// lease`'s own doc comments) — the Worker adjudicates
    /// membership/eligibility only, never version content.
    ///
    /// Returns `None` if the local check fails, this device has no
    /// coordination-plane config recorded ([`Self::coordination_client_
    /// config`]), the coordination-plane request itself fails, the atomic
    /// local pin errors, or the digest-mismatch abort above fires — every
    /// case is treated identically by the caller (`control_socket`): no
    /// lease was requested or recorded.
    ///
    /// On success, also returns the digest of exactly the root set this
    /// grant pins (`pinned_digest`, equal to `attested_digest` by
    /// construction at this point) — used by [`HandoffLeaseResponder for
    /// DaemonState`] to answer an incoming peer-to-peer `HandoffLeaseRequest`
    /// with this device's own `root_digest`, exchanged directly with the
    /// requesting peer and never sent to the coordination service.
    pub async fn request_handoff_lease(
        &self,
        group_id: &str,
    ) -> Option<(crate::coordination_client::HandoffLeaseGrant, [u8; 32])> {
        let attested_digest = self.full_replica_handoff_ready_digest(group_id).await?;
        let config = self.coordination_client_config.get()?;
        let grant = crate::coordination_client::request_handoff_lease(
            &config.addr,
            &config.auth,
            group_id,
            &self.device_id,
        )
        .await?;
        // A best-effort Worker-side release of the lease just granted, for
        // every post-POST abort path below. Best-effort: a failure here just
        // means the Worker's own TTL sweep reclaims the lease instead (the
        // accepted abandoned-lease backstop), so it is logged-and-swallowed
        // inside `release_handoff_lease` rather than surfaced.
        let release_worker_lease = move |lease_id: String| async move {
            crate::coordination_client::release_handoff_lease(
                &config.addr,
                &config.auth,
                group_id,
                &self.device_id,
                &lease_id,
            )
            .await;
        };

        // Trust-boundary check on the Worker-supplied TTL duration. A
        // non-positive `ttl_seconds` (which the current Worker never emits,
        // but a buggy or hostile coordination response could) would yield a
        // local pin deadline at or before now, so the pin would lapse
        // immediately and reopen the retention/GC race the lease exists to
        // close. Treat it as a failed lease: release the just-granted Worker
        // lease best-effort and return `None`, exactly like every other
        // "no usable lease this round" path here — the mandatory-lease
        // caller then fails closed, which is safe. `record_handoff_lease_
        // atomic` also rejects this structurally as defense in depth, but
        // catching it here avoids ever writing (and then having to release)
        // a doomed local pin.
        if grant.ttl_seconds <= 0 {
            tracing::warn!(
                group_id,
                lease_id = %grant.lease_id,
                ttl_seconds = grant.ttl_seconds,
                "handoff lease request aborted: coordination response carried a non-positive TTL; \
                 releasing Worker lease and declining this round"
            );
            release_worker_lease(grant.lease_id).await;
            return None;
        }

        // `grant.ttl_seconds` (a duration), never `grant.expires_at_unix` (the
        // Worker's own absolute expiry, stamped against the Worker's clock):
        // the local pin deadline `record_handoff_lease_atomic` derives from
        // this must come from THIS device's own clock (`now_unix()` below)
        // plus the TTL, so it can never be thrown off by skew between this
        // device's clock and the Worker's -- see that function's own doc
        // comment for the full rationale.
        let (pinned_digest, _pinned_versions) = match self
            .replica_coordinator
            .handoff_lease_repository()
            .record_handoff_lease_atomic(group_id, &grant.lease_id, now_unix(), grant.ttl_seconds)
        {
            Ok(pinned) => pinned,
            Err(e) => {
                // The atomic local pin errored after the Worker already
                // granted the lease -- attempt to release the Worker lease so
                // it does not sit granted with no local pin until its TTL
                // (symmetric with the digest-mismatch abort below).
                tracing::debug!(error = %e, group_id, lease_id = %grant.lease_id,
                    "handoff lease request aborted: atomic local pin failed; releasing Worker lease");
                release_worker_lease(grant.lease_id).await;
                return None;
            }
        };
        if pinned_digest != attested_digest {
            // The root set moved between the readiness attestation and the
            // atomic pin landing -- decline rather than hand out a lease that
            // no longer pins what was verified. Attempt to release both
            // halves; each release is best-effort, with the local time-based
            // pin expiry and the Worker TTL sweep as the backstop if either
            // fails.
            if let Err(e) = self
                .replica_coordinator
                .handoff_lease_repository()
                .set_handoff_lease_state(&grant.lease_id, HandoffLeaseState::Released)
            {
                tracing::debug!(error = %e, group_id, lease_id = %grant.lease_id,
                    "handoff lease digest-mismatch abort: could not release local pin");
            }
            tracing::info!(
                group_id,
                lease_id = %grant.lease_id,
                "handoff lease request aborted: durability-root set changed between readiness \
                 attestation and atomic pin; declining this round"
            );
            release_worker_lease(grant.lease_id).await;
            return None;
        }
        Some((grant, pinned_digest))
    }

    /// Ends a lease this target granted: coordination plane first, local pin
    /// second.
    ///
    /// The order is the fail-safe one. The local pin is dropped only after the
    /// plane reports its lease ended (`released` / `gone`); a lease the plane
    /// leaves alone (held by a running removal) keeps its pin, so retention
    /// never under-retains while the plane's lease is still authoritative. A
    /// crash between the two steps over-retains until retry or TTL: safe. No
    /// rollback of the pin is ever needed.
    ///
    /// `true` only when both are ended, which is what lets the caller
    /// acknowledge the requesting peer (the holder of a removal ticket then
    /// treats that ticket as unusable). A lease this device has no record of
    /// is not one it can say is ended, and no configured coordination service
    /// is not an acknowledgement.
    pub async fn release_owned_handoff_lease(&self, group_id: &str, lease_id: &str) -> bool {
        let repository = self.replica_coordinator.handoff_lease_repository();
        match repository.list_handoff_leases_for_group(group_id) {
            Ok(leases) if leases.iter().any(|lease| lease.lease_id == lease_id) => {}
            Ok(_) => {
                tracing::debug!(group_id, lease_id, "no local record of the handoff lease");
                return false;
            }
            Err(e) => {
                tracing::debug!(error = %e, group_id, lease_id, "could not read local handoff lease");
                return false;
            }
        }
        let Some(config) = self.coordination_client_config.get() else {
            return false;
        };
        if !crate::coordination_client::release_handoff_lease(
            &config.addr,
            &config.auth,
            group_id,
            &self.device_id,
            lease_id,
        )
        .await
        {
            return false;
        }
        match repository.set_handoff_lease_state(lease_id, HandoffLeaseState::Released) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                tracing::debug!(error = %e, group_id, lease_id, "could not release local handoff lease pin");
                false
            }
        }
    }

    /// Source-side counterpart to [`Self::request_handoff_lease`]: asks a
    /// specific, already-confirmed target peer to run that same target-side
    /// flow on ITS device, over the peer-to-peer `HandoffLeaseRequest`/
    /// `HandoffLeaseGrant` exchange (`peer_session.rs`), and returns the
    /// resulting lease id only if the target's own attested `root_digest`
    /// matches `my_digest` — compared here, daemon-local, never sent to or
    /// asked of the coordination service.
    ///
    /// `target_peer_device_id` must name a peer this device currently has a
    /// live session with (normally the exact peer
    /// [`Self::full_replica_handoff_proof`] just confirmed);
    /// no session for that id returns `None` immediately.
    ///
    /// Returns `None` — fail closed, never partially trusted — on every one
    /// of: no live session for that peer, the peer not granting (`granted =
    /// false` or an empty lease id, including a peer running a build that
    /// predates this message, which simply times out the same way), or a
    /// digest mismatch. A mismatch specifically means the target is not
    /// actually caught up to this device's exact current root set — the
    /// caller must NOT relinquish its own role on that basis, only decline
    /// this round.
    pub async fn obtain_handoff_lease_from_peer(
        &self,
        group_id: &str,
        target_peer_device_id: &str,
        my_digest: [u8; 32],
    ) -> Option<String> {
        self.obtain_handoff_lease_grant_from_peer(group_id, target_peer_device_id, my_digest)
            .await
            .map(|(lease_id, _ttl_seconds)| lease_id)
    }

    /// [`Self::obtain_handoff_lease_from_peer`] that also returns how long the
    /// lease lives (seconds, a duration: never compared with a clock).
    pub async fn obtain_handoff_lease_grant_from_peer(
        &self,
        group_id: &str,
        target_peer_device_id: &str,
        my_digest: [u8; 32],
    ) -> Option<(String, i64)> {
        let session = self.peers.session(target_peer_device_id)?;
        let grant = session.request_handoff_lease_from_peer(group_id).await?;
        let lease_id = handoff_lease_grant_matches_digest(&grant, my_digest);
        let ttl_seconds = grant.ttl_seconds;
        if lease_id.is_none() {
            tracing::info!(
                group_id,
                target_device_id = %target_peer_device_id,
                "handoff lease request declined: target's attested durability-root digest \
                 does not match this device's own current digest; not relinquishing local role \
                 this round"
            );
            if let Err(e) = session.release_handoff_lease_to_peer(group_id, &grant.lease_id).await {
                tracing::debug!(
                    error = %e,
                    group_id,
                    lease_id = %grant.lease_id,
                    target_device_id = %target_peer_device_id,
                    "could not send digest-mismatched handoff lease release; TTL remains the backstop"
                );
            }
        }
        lease_id.map(|lease_id| (lease_id, ttl_seconds))
    }

    /// The removed-device-ticket RESPONDER half of `HandoffTicketRequest`,
    /// run on THIS device's own `DaemonState` -- i.e. called on a device (B)
    /// that a DIFFERENT operating device (X) is in the process of removing/
    /// revoking, asking B to attest and hand off ITS OWN roots before it
    /// leaves. This is exactly the Stage-B SOURCE-side flow
    /// ([`Self::full_replica_handoff_proof`] +
    /// [`Self::obtain_handoff_lease_from_peer`]), reused verbatim: a removed
    /// device attesting its own roots to obtain a lease from some other
    /// confirmed peer IS the source-side handoff flow, just triggered by a
    /// different caller (X, over the new `HandoffTicketRequest` wire
    /// message, rather than this device's own unlink/demote code path).
    ///
    /// Returns `None` -- which the wire responder
    /// (`HandoffTicketResponder for DaemonState` below) turns into `granted
    /// = false` -- when: this device's own root set for `group_id` is
    /// non-empty and no connected peer confirms holding all of it (the
    /// digest mismatch/no-confirming-peer case is exactly what closes the
    /// durability gap: X could not have attested this on B's behalf, and B itself
    /// could not either this round), or the confirmed peer's own coordi-
    /// nation-plane round trip fails (see [`Self::obtain_handoff_lease_
    /// from_peer`]'s doc comment for the full list of sub-cases, all
    /// collapsed to `None` there already).
    ///
    /// An EMPTY root set is vacuously ready (see [`Self::full_replica_
    /// handoff_ready`]'s own doc comment) and needs no lease -- this
    /// returns `Some` with `lease_id: None`/`target_device_id: None` in that
    /// case, which the wire responder reports as `granted = true` with an
    /// empty `lease_id`/`target_device_id`. X cannot bind such a ticket to a
    /// lease-guarded commit (there is no target to name), so it is not
    /// usable as a removal ticket by X's atomic wiring even though it is a
    /// perfectly valid "nothing to hand off" answer.
    ///
    /// `target_device_id` is the SAME confirming peer
    /// [`Self::full_replica_handoff_proof`] already learned
    /// and [`Self::obtain_handoff_lease_from_peer`] requested the lease
    /// from -- this is what closes the previously-disclosed gap where the
    /// ticket carried a lease id but no target to atomically re-verify it
    /// against at removal time.
    ///
    /// `expires_at_unix` is always `0` here: propagating the confirming
    /// peer's real expiry would require changing [`Self::obtain_handoff_
    /// lease_from_peer`]'s public signature (used unmodified by Stage B),
    /// and the ticket's `expires_at_unix` is documented (see
    /// `HandoffTicketGrant`'s proto doc comment) as carried only for X to
    /// record/log, never re-verified -- X's actual decision now rests on
    /// presenting `(lease_id, target_device_id)` to a lease-guarded commit,
    /// not on the `granted` bool alone.
    pub async fn obtain_own_handoff_ticket(
        &self,
        group_id: &str,
    ) -> Option<PeerHandoffTicketGrant> {
        // A ticket says this device may be removed without losing data. The
        // custody leases it holds for other devices are data only it has, so
        // they move first. The group stays closed to new leases while the
        // ticket is worked out, and for a while after it is granted, since the
        // removal is committed by another device at a later moment; any
        // refusal reopens it.
        let closed = match self.hand_off_custody_leases(group_id).await {
            Ok(closed) => closed,
            Err(reason) => {
                tracing::warn!(group_id, %reason, "refusing a removal ticket: custody leases could not be handed off");
                return None;
            }
        };
        let proof = self.full_replica_handoff_proof(group_id).await?;
        let digest = proof.root_digest();
        let (lease_id, target_device_id) = match proof.into_peer_device_id() {
            // Nothing to hand off: the ticket carries no lease, cannot be bound
            // to a lease-guarded commit, and the responder discards it. It
            // closes nothing.
            None => {
                return Some(PeerHandoffTicketGrant {
                    lease_id: None,
                    target_device_id: None,
                    expires_at_unix: 0,
                })
            }
            Some(peer_id) => {
                let (lease_id, ttl_seconds) =
                    self.obtain_handoff_lease_grant_from_peer(group_id, &peer_id, digest).await?;
                // The removal is committed inside that lease; the group stays
                // closed to new custody leases for as long as it can live,
                // counted from now (the grant has only just arrived).
                if let Err(reason) = closed.hold_for_ticket(
                    crate::custody_handoff::ticket_close_for(ttl_seconds),
                    &lease_id,
                ) {
                    // No ticket leaves this device without a close that outlives
                    // a restart; the lease just obtained from the target is given back.
                    tracing::warn!(group_id, %reason, "refusing a removal ticket: its close could not be recorded");
                    if let Some(session) = self.peers.session(&peer_id) {
                        // Best effort; the lease's own lifetime is the backstop.
                        let _ = session.release_handoff_lease_to_peer(group_id, &lease_id).await;
                    }
                    return None;
                }
                (Some(lease_id), Some(peer_id))
            }
        };
        Some(PeerHandoffTicketGrant { lease_id, target_device_id, expires_at_unix: 0 })
    }

    /// The removed-device-ticket REQUESTER half: run on the OPERATING
    /// device's (X's) own `DaemonState` to ask a DIFFERENT device (`device_
    /// id`, the one being removed/revoked) to attest and hand off its own
    /// roots for `group_id`, over the peer-to-peer `HandoffTicketRequest`/
    /// `HandoffTicketGrant` exchange (`peer_session.rs`). Backs
    /// `durability_force.rs`'s cross-device gate: a `Some` result for every
    /// at-risk group lets the removal proceed WITHOUT `--force`.
    ///
    /// Returns `None` -- collapsed identically, matching this crate's other
    /// fail-closed daemon-side checks -- for every one of: no live session
    /// for `device_id` on this daemon (the device is offline/unreachable
    /// from X's point of view), the request timing out, or the device's own
    /// attestation declining (its root set isn't fully confirmed by any
    /// peer it can reach). X never needs to (and structurally cannot: this
    /// method never reads or compares X's own root index) distinguish these
    /// -- the design's whole point is that X cannot attest a different
    /// device's roots, so this always routes the decision through the
    /// removed device itself, never through X's local view.
    pub async fn obtain_handoff_ticket_from_device(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Option<PeerHandoffTicketGrant> {
        let session = self.peers.session(device_id)?;
        session.request_handoff_ticket_from_peer(group_id).await
    }

    /// Asks the removed device that created a ticket to route its release to
    /// the target peer that owns the corresponding lease and local pin.
    pub async fn release_handoff_ticket_from_device(
        &self,
        group_id: &str,
        device_id: &str,
        target_device_id: &str,
        lease_id: &str,
    ) -> Result<(), String> {
        let session = self.peers.session(device_id);
        if let Some(session) = session {
            if let Err(e) =
                session.release_handoff_ticket_to_peer(group_id, target_device_id, lease_id).await
            {
                tracing::debug!(
                    error = %e,
                    group_id,
                    device_id,
                    target_device_id,
                    lease_id,
                    "could not send removed-device ticket release; TTL remains the backstop"
                );
                return Err(e.to_string());
            }
            return Ok(());
        }
        Err(format!("no active session for removed device {device_id}"))
    }

    /// Takes a fresh [`StrongHandoffProof`] for `group_id`, or `None` if one
    /// cannot be established right now.
    ///
    /// This is the only way to obtain that value, and every destructive
    /// action that may cost this device its own durable copy takes one here,
    /// immediately, rather than consulting anything remembered. Cached
    /// background evidence (`crate::background_custody`) is a different type
    /// for exactly this reason: it cannot be turned into one of these, and it
    /// is not admissible where one is required.
    ///
    /// The proof names the peer that confirmed coverage — `None` inside it
    /// for a vacuously-ready empty root set, where there is no "the
    /// confirming peer" because nothing needed confirming. Call sites that
    /// must name a concrete handoff TARGET for the coordination service's
    /// role-loss commit endpoint
    /// (`crate::coordination_client::commit_handoff_role_loss`) read it from
    /// there. Only the non-excluding form is offered, matching
    /// `full_replica_handoff_ready_digest`'s own doc comment on why.
    pub async fn full_replica_handoff_proof(&self, group_id: &str) -> Option<StrongHandoffProof> {
        self.full_replica_handoff_ready(group_id, None).await
    }

    /// Shared implementation behind
    /// [`Self::another_full_replica_is_ready`],
    /// [`Self::another_full_replica_is_ready_excluding`],
    /// [`Self::full_replica_handoff_ready_digest`], and
    /// [`Self::full_replica_handoff_proof`]; see their doc comments for the
    /// semantics `excluded_device_id` (`None` for the non-excluding forms)
    /// adds.
    ///
    /// This is the one function in the daemon that establishes every clause
    /// of [`StrongHandoffProof`]'s contract, and therefore the one place
    /// allowed to construct one — pinned by the architecture manifest, not
    /// merely by this comment.
    async fn full_replica_handoff_ready(
        &self,
        group_id: &str,
        excluded_device_id: Option<&str>,
    ) -> Option<StrongHandoffProof> {
        // Enumerate every durability root (current + retained superseded +
        // trash-restorable; see `SyncState::enumerate_group_durability_roots`)
        // once, up front, so each candidate peer is checked against the same
        // set. Fail closed if the enumeration itself errors.
        let roots = self.durability_roots_for_group(group_id)?;
        // Nothing to hand off — vacuously ready. Deliberately does NOT clear a
        // post-force `Unknown` latch: an empty root set is not a
        // positive coverage confirmation (an all-deleted, retention-expired
        // group looks the same as one that genuinely never had files), so
        // clearing here could hide exactly the uncertainty the latch was set
        // to preserve. Only a real peer-confirmed whole-group hold below
        // clears it.
        if roots.roots.is_empty() {
            return Some(StrongHandoffProof::new(
                roots.digest,
                None,
                self.authority.membership_generation(),
            ));
        }
        for (peer_id, session) in self.peers.all_sessions() {
            if excluded_device_id == Some(peer_id.as_str()) {
                continue;
            }
            if !self.peer_may_hold_custody(&peer_id, group_id) {
                continue;
            }
            let generation = self.authority.membership_generation();
            if self.peer_holds_entire_group(&peer_id, &session, group_id, &roots.roots).await {
                // A whole-group handoff target is confirmed again: any
                // post-force `Unknown` latch for this group no
                // longer reflects reality, so clear it back toward
                // whatever the group's live sync state now derives to.
                //
                // This is the ONLY place that clears that latch. The latch
                // records that a `--force` override bypassed this gate, and
                // only the gate itself re-earning its answer may retire it.
                // The background custody monitor deliberately does not, and
                // is held to that by the architecture manifest: its evidence
                // is an index comparison, which is not the kind of fact the
                // latch was set to wait for.
                if let Err(error) = self.clear_group_durability_latch(group_id) {
                    tracing::warn!(%error, group_id, "failed to clear persistent durability latch");
                }
                self.durability.note_strong_proof(group_id, roots.digest);
                return Some(StrongHandoffProof::new(roots.digest, Some(peer_id), generation));
            }
        }
        None
    }

    /// This group's durability-root set — current + retained superseded +
    /// trash-restorable versions (`SyncState::enumerate_group_durability_
    /// roots`), plus its digest. `None` (fail closed) if the underlying
    /// enumeration errors.
    pub(crate) fn durability_roots_for_group(&self, group_id: &str) -> Option<DurabilityRoots> {
        self.replica_coordinator
            .file_index_repository()
            .enumerate_group_durability_roots(group_id)
            .ok()
    }

    /// Whether one specific peer — `peer_id`, reached over its own `session`
    /// — durably holds EVERY root in `roots` (the group's whole durability
    /// root set: current + retained superseded + trash-restorable versions,
    /// as `(path, change::VersionHash)` pairs). This is the per-peer counterpart to
    /// [`Self::confirm_version_present_via_peer`]'s per-file/any-peer query:
    /// it pins one peer and requires that same peer to confirm the whole
    /// set, so a complete durable replica is proven, not a fragmentary one
    /// assembled across several incomplete peers.
    ///
    /// Fail-closed and authorization-guarded exactly like
    /// `confirm_version_present_via_peer`: for each root it captures the
    /// netmap-authorization generation before the round-trip and, after the
    /// reply, requires the generation unchanged AND the peer still an
    /// authorized full-replica writer — so a revoke/demote (or any
    /// membership churn) arriving mid-check fails the whole thing closed.
    /// Short-circuits on the first root this peer cannot confirm.
    ///
    /// Every root's `version_hash` is sent alongside its block hashes/sizes
    /// (see the loop below), and every connected peer's responder enforces
    /// it: answering a `for_handoff = true` query on block-hash agreement
    /// alone -- the false-positive (two distinct versions sharing an
    /// identical block list, e.g. an mtime-only edit) this whole check
    /// exists to close -- is behavior no peer of this protocol generation
    /// has, and a peer of another generation cannot complete the TLS
    /// handshake. This used to require an advertised capability bit, and
    /// skipped any peer that had not set it.
    async fn peer_holds_entire_group(
        &self,
        peer_id: &str,
        session: &Arc<PeerSyncSession>,
        group_id: &str,
        roots: &[DurabilityRoot],
    ) -> bool {
        for root in roots {
            let epoch_before = self.authority.membership_generation();
            // Whole-group handoff: `for_handoff = true` lets the peer confirm a
            // root against any version it still retains (current OR retained
            // history), since a handoff must cover every durability root, not
            // just current heads.
            if !session
                .request_version_present(
                    group_id,
                    &root.path,
                    root.version_hash,
                    &root.blocks,
                    true,
                )
                .await
            {
                return false;
            }
            // Re-verify AFTER the reply: the peer must still be an authorized
            // full-replica writer, and the netmap-authorization view must not
            // have changed at all during the wait. Anything else fails closed
            // rather than trusting a now-stale ACK.
            if self.authority.membership_generation() != epoch_before
                || !self.peer_may_hold_custody(peer_id, group_id)
            {
                return false;
            }
        }
        true
    }

    /// Marks `group_id`'s policy state untrusted because its latest snapshot
    /// failed verification. Change admission for the group fails closed until
    /// [`clear_group_policy_stale`](PeerAuthorityState::clear_group_policy_stale) resets it.
    /// Records the failure time; the caller logs the reason.
    pub fn mark_group_policy_stale(&self, group_id: &str) {
        self.authority.mark_group_policy_stale(group_id);
        for (_, session) in self.peers.all_sessions() {
            session.revoke_group(group_id);
        }
    }

    /// Applies one verified policy snapshot: `verified` becomes the whole
    /// trusted set (its groups' stale markers cleared) and every `stale`
    /// group is marked stale, all in one critical section so no reader sees
    /// a mix of the old and new snapshot. Each group marked stale is then
    /// revoked from every live session, after the switch is visible and the
    /// lock released, exactly as [`mark_group_policy_stale`](Self::mark_group_policy_stale) does.
    pub(crate) fn apply_policy_snapshot(
        &self,
        verified: HashMap<String, GroupPolicyState>,
        stale: Vec<String>,
    ) {
        for group_id in self.authority.apply_policy_snapshot(verified, stale) {
            for (_, session) in self.peers.all_sessions() {
                session.revoke_group(&group_id);
            }
        }
    }

    /// The single group-policy/authorization resolution point that every
    /// staleness source funnels through, so both local emission
    /// (`DaemonState::new`'s local-change auth provider) and inbound admission
    /// (`NetmapChangeAuthenticator::accepts_change_auth`) fail closed on the
    /// same conditions instead of each re-deriving the `None`/stale handling
    /// ad hoc:
    ///
    /// - own-verification-stale or coordinator-flagged invalid (both recorded
    ///   via [`mark_group_policy_stale`](Self::mark_group_policy_stale)) →
    ///   [`Withhold`](GroupPolicyResolution::Withhold);
    /// - a verified snapshot is loaded →
    ///   [`Verified`](GroupPolicyResolution::Verified);
    /// - no verified snapshot, not stale, but the group is already introduced
    ///   (linked or a known writer exists) → the policy simply has not loaded
    ///   yet this run → [`Withhold`](GroupPolicyResolution::Withhold);
    /// - otherwise the genuine pre-policy bootstrap window (never introduced,
    ///   no snapshot has ever existed) → [`Bootstrap`](GroupPolicyResolution::Bootstrap),
    ///   where the placeholder stamp is still legitimate on both sides.
    pub fn resolve_group_policy(&self, group_id: &str) -> GroupPolicyResolution {
        self.authority.resolve_group_policy(group_id, || self.group_is_linked(group_id))
    }

    /// Whether `group_id` is ready to be used locally, and if not, why not.
    ///
    /// "Ready" is the conjunction the name implies: the group is linked on
    /// this device, a verified policy is loaded for it, and this device may
    /// author into it. Before this existed there was no way to ask that
    /// question — only ways to find out by failing, which is exactly what
    /// callers did. A local edit made against a group whose policy had not
    /// arrived yet failed to commit with `PolicyUnavailable` and was
    /// journaled for re-drive; nothing distinguished "not ready yet, this
    /// will resolve on its own" from "something is wrong", so both a user
    /// watching a folder and a test waiting to measure something had to
    /// write a file and see whether it converged.
    ///
    /// Authorization is not a separate check here, deliberately. Under
    /// `AuthorizationCheckpoint` admission, local emission is available to
    /// any device that holds the group regardless of writer role (writer
    /// authorization happens at checkpoint issuance), so "this device may
    /// author into it" is exactly `resolve_group_policy` not resolving to
    /// `Withhold` — the same primitive `local_policy_head_provider` gates
    /// on. Deriving it a second way here would let the two drift, and the
    /// failure that drift produces looks like a policy bug rather than a
    /// duplicated-predicate bug.
    pub fn group_readiness(&self, group_id: &str) -> GroupReadiness {
        if !self.group_is_linked(group_id) {
            return GroupReadiness::NotJoined;
        }
        if self.authority.is_group_policy_stale(group_id) {
            return GroupReadiness::PolicyStale;
        }
        match self.resolve_group_policy(group_id) {
            GroupPolicyResolution::Verified(_) | GroupPolicyResolution::Bootstrap => {
                GroupReadiness::Ready
            }
            // Linked, not stale, and still withheld: the group has been
            // introduced (a peer names it, or it is linked) but no verified
            // policy has arrived for it yet. This is the transient state a
            // freshly created or joined group sits in, and the one that used
            // to be indistinguishable from a failure.
            GroupPolicyResolution::Withhold => GroupReadiness::AwaitingPolicy,
        }
    }

    /// Whether `group_id` has a local link row. Also the link half of
    /// `PeerAuthorityState::group_is_introduced` (passed in by
    /// `resolve_group_policy`), which deliberately also answers true for a
    /// group this device merely knows a peer writes to — a different
    /// question, and the wrong one for readiness.
    fn group_is_linked(&self, group_id: &str) -> bool {
        self.replica_coordinator
            .link_repository()
            .list_links()
            .map(|links| links.iter().any(|link| link.group_id == group_id))
            // A link table this daemon cannot read is not evidence that the
            // group is ready; fail closed, same as every other readiness
            // input here.
            .unwrap_or(false)
    }

    /// Whether this device may currently serve `group_id` to *anyone*.
    ///
    /// This is the local half of the disclosure question, and it is about this
    /// device rather than about any peer: a group whose policy has gone stale
    /// (own verification failure, or coordinator-flagged invalid) or has not
    /// loaded yet this run is one this device can no longer vouch for, so it
    /// is withheld from every peer regardless of how well authorized that peer
    /// is. Disclosure is the conjunction:
    ///
    /// ```text
    ///   MayDisclose(peer, group)
    ///       = group_is_servable(group)          // this device may serve it
    ///       AND peer_is_writer(peer, group)     // that peer may be told
    /// ```
    ///
    /// Both the legacy announcement path
    /// (`NetmapChangeAuthenticator::effective_servable_groups`) and the
    /// reconciliation path (`sync_adapter::DaemonPeerDirectory`) call this one
    /// primitive rather than each re-deriving the condition. That is not only
    /// tidiness: while both paths run, any difference between them would show
    /// up in an equivalence measurement as a transport difference when it was
    /// really a policy difference.
    pub fn group_is_servable(&self, group_id: &str) -> bool {
        !matches!(self.resolve_group_policy(group_id), GroupPolicyResolution::Withhold)
    }

    /// Graceful shutdown: blocks until no `on_local_native_commit`
    /// call is in flight, or `timeout` elapses,
    /// whichever comes first — best-effort draining rather than a hard
    /// guarantee (a peer session's send can itself hang on a dead
    /// connection; `yadorilink-transport`'s I/O timeouts, out of this
    /// crate's scope, bound that).
    pub async fn wait_for_broadcasts_to_drain(&self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = self.in_flight_broadcasts.load(Ordering::SeqCst);
            if remaining <= 0 {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(remaining, "timed out waiting for in-flight broadcasts to drain; proceeding with shutdown anyway");
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn begin_broadcast(&self) -> BroadcastGuard<'_> {
        self.in_flight_broadcasts.fetch_add(1, Ordering::SeqCst);
        BroadcastGuard { counter: &self.in_flight_broadcasts }
    }

    /// Call around any sync-critical
    /// write (folder scan/flush processing in the daemon's own `LinkRuntimeController`,
    /// materialization writes in `hydration.rs`) so
    /// `is_write_safe_point` reports `false` for its duration. Public (not
    /// just crate-visible) since both call sites are in sibling modules
    /// of this same crate but need the exact same guard type
    /// `on_local_native_commit`'s own private `begin_broadcast` uses internally.
    pub fn begin_write_activity(&self) -> WriteActivityGuard<'_> {
        let liveness = self.block_liveness_gate().begin_reference_write();
        self.active_write_ops.fetch_add(1, Ordering::SeqCst);
        // Every existing call site of this
        // guard (the local-change flush executor started via the daemon's own `LinkRuntimeController`,
        // hydration's hydrate/evict/restore paths in `hydration.rs`) is
        // exactly the "local-change/hydration activity" the GC idle
        // scheduler needs to know about.
        self.record_activity();
        WriteActivityGuard { counter: &self.active_write_ops, _liveness: liveness }
    }

    pub(crate) fn begin_block_deletion(&self) -> BlockPhysicalDeletionGuard<'_> {
        self.block_liveness_gate().begin_physical_deletion()
    }

    pub(crate) fn try_begin_block_deletion(&self) -> Option<BlockPhysicalDeletionGuard<'_>> {
        self.block_liveness_gate().try_begin_physical_deletion()
    }

    /// Whether every block of a version is in this device's block store with bytes that read back
    /// and hash to their name. This is the proof that the version is recoverable from the device
    /// alone, and the only evidence on which a destructive step (dropping the OS copy, releasing a
    /// remote custody lease) may rely on the local store; index presence (`exists`) is not.
    ///
    /// It is the same strong read the custody acquire runs (`BlockStore::get` re-hashes the
    /// payload), under the same block-reference guard, so no deletion pass can take a block while
    /// it is read. Any read, decode, hash or length failure answers `false`. The reads run on the
    /// blocking pool; the cost is one full read of the version's bytes.
    pub(crate) async fn blocks_verified_locally(&self, blocks: Vec<VersionBlock>) -> bool {
        let store = self.block_store.clone();
        let coordinator = self.replica_coordinator.clone();
        let verified = tokio::task::spawn_blocking(move || {
            let _no_block_deletion =
                coordinator.block_liveness_gate().begin_reference_write_barging();
            let _reads = yadorilink_local_storage::io_diag::attribute_reads(
                yadorilink_local_storage::io_diag::ReadReason::CustodyEvidence,
            );
            blocks.iter().all(|block| {
                store
                    .get(&hex::encode(&block.hash.0))
                    .is_ok_and(|bytes| bytes.len() as u64 == u64::from(block.size))
            })
        })
        .await;
        verified.unwrap_or(false)
    }

    pub(crate) fn block_liveness_gate(&self) -> &BlockLivenessGate {
        self.replica_coordinator.block_liveness_gate()
    }

    /// Marks "now" as the most recent
    /// local-change/peer-reconciliation/hydration activity — see
    /// `last_activity_unix`'s doc comment for its two call sites.
    pub fn record_activity(&self) {
        self.last_activity_unix.store(now_unix(), Ordering::SeqCst);
    }

    /// How long it's been since the most
    /// recent recorded activity — the GC idle scheduler's own condition is
    /// exactly `idle_duration >= gc::GC_IDLE_THRESHOLD`.
    pub fn idle_duration(&self) -> Duration {
        let last = self.last_activity_unix.load(Ordering::SeqCst);
        Duration::from_secs(now_unix().saturating_sub(last).max(0) as u64)
    }

    /// Test-only escape hatch: production code only ever calls
    /// `record_activity` (always "now"); tests simulating having been
    /// idle for a while need to set an arbitrary past timestamp directly,
    /// without literally waiting out `gc::GC_IDLE_THRESHOLD`.
    #[cfg(test)]
    pub(crate) fn set_last_activity_unix_for_test(&self, unix: i64) {
        self.last_activity_unix.store(unix, Ordering::SeqCst);
    }

    /// Per the "Safe Update Timing" decision: `true` exactly when no
    /// sync-critical write is currently in progress — the sole condition
    /// `update_ipc::install`/the periodic install-safe-point check
    ///  uses to decide whether to proceed or defer.
    pub fn is_write_safe_point(&self) -> bool {
        self.active_write_ops.load(Ordering::SeqCst) <= 0
    }

    /// Wall-clock time elapsed
    /// since this `DaemonState` was constructed — i.e. since this daemon
    /// process started. Used only to bucket `daemon.uptime_bucket` in the
    /// diagnostics bundle (`diagnostics_ipc::uptime_bucket`); never
    /// exposed as an exact duration anywhere reportable, matching this
    /// codebase's existing "coarse bucket, not an exact value"
    /// convention for anything that ends up in a report/bundle (see
    /// `UsagePayload.daemon_uptime_bucket`'s doc comment).
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Health surface: records whether essential task `name` is
    /// currently running, from the outside (`main.rs` owns the essential
    /// `JoinSet`/supervision itself; this is just where the result
    /// is published for `control_socket`'s health handler to read).
    pub fn set_task_alive(&self, name: &str, alive: bool) {
        self.telemetry.set_task_alive(name, alive);
    }

    /// Follow-up for a local commit to `group_id` that is already durable in
    /// native state: publishes the group's pending native checkpoint, then
    /// tells the peer session driver and the retirement/hazard machinery
    /// the group has something new ([`Self::note_local_commit_for_group`]).
    /// The caller decides whether there is anything to follow up on; this
    /// carries no record payload.
    pub async fn on_local_native_commit(&self, group_id: &str) {
        // The ONLY Pending -> Published path is the checkpoint flush, and
        // `peer_orchestrator.rs`'s reconnect hook fires it once per WS
        // connect, so any local mutation committed AFTER that one-shot flush
        // already ran (an ordinary live edit made while already connected,
        // or content recovered by `backfill_missing_change_history` after
        // the flush already found nothing pending) would otherwise never get
        // checkpointed until the NEXT reconnect (exercised end to end by
        // `chaos_coordination_unreachable.rs`'s initial-sync probe and
        // `viewer_editor_authorization_end_to_end.rs`'s Editor scenario).
        // Every local-mutation path funnels through this one chokepoint
        // (`capture_local_change.rs`, `link_runtime_controller.rs`,
        // `hydration.rs`, and this type's own backfill-repair arm), so
        // hooking the flush here closes the gap for every path at once
        // without inventing a second publication mechanism. Awaited inline
        // (not spawned): this method has no `Arc<Self>` receiver to hand a
        // `'static` spawned task, and every caller is already deep in an
        // async background task, not a latency-sensitive synchronous path.
        //
        // Deliberately BEFORE the wake, not after: the wake lets the
        // peer session driver start pushing, and a peer can only be sent
        // a delta that is already Published.
        self.fork_contested_heads(group_id);
        self.flush_pending_native_checkpoint_for_group(group_id).await;
        self.note_local_commit_for_group(group_id).await;
    }
    /// Test-only entry point for [`Self::flush_pending_checkpoint_for_
    /// group`] -- `connect_two_daemons`-paired integration tests (`yadorilink
    /// -daemon/tests/support/mod.rs`) wire a real in-process coordination
    /// plane but never run a real `peer_orchestrator::run` netmap loop, so
    /// there is no reconnect trigger to flush content that became `Pending`
    /// BEFORE the two devices were ever paired. Same method, just reachable
    /// from outside this crate.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn flush_pending_checkpoint_for_group_for_test(&self, group_id: &str) {
        self.flush_pending_native_checkpoint_for_group(group_id).await
    }

    /// [`Self::flush_pending_checkpoint_for_group`] for this device's native
    /// deltas: publishes the pending batch, then pushes what became
    /// sendable to every attached peer. The flush is serialized per device
    /// (the coordination plane numbers a device's checkpoints); the
    /// push, which waits on peers, happens after the lock is released.
    pub(crate) async fn flush_pending_native_checkpoint_for_group(&self, group_id: &str) {
        let published = {
            let _guard = self.flush_lock.lock().await;
            self.flush_pending_native_checkpoint_for_group_inner(group_id).await
        };
        if let Some(hashes) = published {
            let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_string());
            self.native_replication.push_published(&group, &hashes).await;
        }
    }

    /// Test-only: dials `device` for native replication the way a session
    /// keeper does, for harnesses that pair devices without one.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn dial_native_replication_for_test(self: &Arc<Self>, device: &str) {
        let Some(driver) = self.peer_session_driver() else { return };
        crate::native_replication_runtime::dial_if_dialer(self, driver.stack().endpoint(), device)
            .await;
    }

    /// Test-only: ends every native replication connection, as a partition
    /// does.
    #[cfg(any(test, feature = "test-support"))]
    pub fn sever_native_replication_for_test(&self) {
        self.native_replication.detach_all();
    }

    /// Test-only: stops every rebootstrap of this device at the points `hook` refuses, as a
    /// crash would; `None` removes the hook.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_rebootstrap_hook_for_test(&self, hook: Option<crate::native_rebootstrap::Hook>) {
        self.native_replication.set_rebootstrap_hook_for_test(hook);
    }

    /// What `device` has said it no longer holds the history for, per group, as the
    /// native replication rounds with it recorded: for status and diagnostics.
    pub fn native_history_truncated_by(
        &self,
        device: &str,
    ) -> std::collections::BTreeMap<
        yadorilink_replica_domain::ids::FolderGroupId,
        yadorilink_replica_domain::history_truncation::RetainedSummary,
    > {
        self.native_replication.history_truncated_by(device)
    }

    /// Whether a native replication connection to `device` is attached.
    #[cfg(any(test, feature = "test-support"))]
    pub fn native_replication_attached_for_test(&self, device: &str) -> bool {
        self.native_replication.is_attached(device)
    }

    /// Test-only entry point for [`Self::flush_pending_native_checkpoint_for_group`].
    #[cfg(any(test, feature = "test-support"))]
    pub async fn flush_pending_native_checkpoint_for_group_for_test(&self, group_id: &str) {
        self.flush_pending_native_checkpoint_for_group(group_id).await
    }

    /// The deltas the flush just published, if it published any.
    async fn flush_pending_native_checkpoint_for_group_inner(
        &self,
        group_id: &str,
    ) -> Option<Vec<yadorilink_replica_domain::native_state::DeltaHash>> {
        let source = self.seal_checkpoint_source()?;
        let signing_key = self.device_signing_key()?;
        let policy = self.authority.group_policy_state(group_id)?;
        let resolve_authority_key = |key_id: &[u8; 32], policy_head: &[u8; 32]| {
            policy.resolve_authority_key(key_id, policy_head)
        };
        let shutdown = self.shutdown_tx.subscribe();
        match crate::native_checkpoint_flush::flush_pending_native_checkpoint_until(
            &self.replica_coordinator.database(),
            source.as_ref(),
            group_id,
            &self.device_id,
            &signing_key.verifying_key(),
            &resolve_authority_key,
            &|| *shutdown.borrow(),
        )
        .await
        {
            Ok(flushed) => match flushed.outcome {
                crate::checkpoint_source::FlushOutcome::Flushed { batch_size, checkpoint_seq } => {
                    tracing::info!(
                        group_id,
                        batch_size,
                        checkpoint_seq,
                        "native checkpoint flush: published pending batch"
                    );
                    Some(flushed.published)
                }
                _ => None,
            },
            Err(e) => {
                tracing::warn!(group_id, error = %e, "native checkpoint flush failed");
                None
            }
        }
    }

    /// The one place a locally-durable commit turns into "the
    /// `PeerSessionDriver` knows this group changed" -- factored out of
    /// `on_local_native_commit` so a caller that already knows independently
    /// there is something new can raise the same wake without first
    /// publishing a checkpoint (content that is durable in native state but
    /// not yet materialized locally must not suppress the wake and leave
    /// propagation dependent on the driver's own periodic sweep).
    ///
    /// There is no per-peer announce here any more (RBSR/reconciliation
    /// finds the difference by comparing durable sets over its own
    /// connection, not by a device telling its peers "I have new heads");
    /// this method's whole job is (1) telling `PeerSessionDriver` this
    /// group has a new local change to reconcile, and (2) the per-session
    /// bookkeeping every commit has always needed regardless of any peer --
    /// this device's own recorded frontier, and the retirement/hazard wakes.
    pub(crate) async fn note_local_commit_for_group(&self, group_id: &str) {
        // The one place a locally published commit is turned into everything
        // that has to happen next. Every local-mutation route already reaches
        // here -- including the retroactive-repair carrier, which calls this
        // directly rather than through `on_local_native_commit` -- so a route added
        // later cannot forget to raise the event, because it has to publish.
        //
        // Getting this wrong once is what put it here: an earlier version of
        // the cutover raised the reconciliation event in `on_local_native_commit`
        // instead. Every ordinary edit worked, and the repair carrier -- the
        // one caller that does not go through `on_local_native_commit` -- silently
        // raised nothing at all.

        // The bookkeeping a commit has always raised: this device's own
        // recorded frontier, and the retirement/hazard wakes. Nothing here
        // speaks to a peer -- and nothing here is per-peer either. The
        // frontier recorded is THIS device's, keyed by group; both wakes are
        // group-scoped. It nonetheless used to run inside every session that
        // shared the group, so one identical device-local write and two
        // identical `mark_dirty` calls were repeated once per connected peer.
        // Done once here instead.
        //
        // Still gated on at least one session sharing the group, exactly as
        // the per-session loop was. Whether a commit should raise these with
        // no peer connected is a real question -- the retirement backstop
        // reaches the same work eventually either way -- and not one a move
        // gets to decide.
        let _in_flight = self.begin_broadcast(); // let shutdown wait for this to finish
        if !self.peers.all_sessions().iter().any(|(_, session)| session.shares_group(group_id)) {
            return;
        }
        self.replica_coordinator.hazard_recheck_wake().mark_dirty(group_id);
    }

    /// Claims `local_path`'s disk-reconcile backstop pass; `None` when one is
    /// already running. The claim is released when the returned guard drops.
    pub(crate) fn begin_backstop_pass(self: &Arc<Self>, local_path: &str) -> Option<BackstopPass> {
        let claimed = self
            .backstop_in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(local_path.to_string());
        claimed.then(|| BackstopPass { state: self.clone(), local_path: local_path.to_string() })
    }

    pub fn local_convergence(
        self: &Arc<Self>,
    ) -> Arc<crate::local_convergence::LocalConvergenceExecutor> {
        self.local_convergence_with_roots(std::collections::HashMap::new())
    }

    /// The executor a session gets: same construction, with the sync roots
    /// that session was given. One per session, which is exactly what each
    /// session used to build for itself.
    pub fn local_convergence_with_roots(
        self: &Arc<Self>,
        sync_roots: std::collections::HashMap<String, std::path::PathBuf>,
    ) -> Arc<crate::local_convergence::LocalConvergenceExecutor> {
        crate::local_convergence::LocalConvergenceExecutor::new(
            self.replica_coordinator.clone(),
            self.device_id.clone(),
            self.clone(),
            self.clone(),
            sync_roots,
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                self.block_store.clone(),
            )),
            self.clone(),
            crate::local_convergence::HeadroomPolicy {
                enforced: self.disk_headroom_enforcement_enabled(),
                // Read per construction, not cached, for the same reason
                // `recheck_degraded_links` re-reads it per pass: an operator
                // can change the reserve while the daemon runs, and an
                // executor is built per call.
                override_bytes: self.governance_config.load_or_default().headroom_override_bytes,
            },
        )
    }
}

/// Bridges an incoming peer-to-peer `HandoffLeaseRequest` (`peer_session.rs`)
/// to this device's own target-side lease machinery
/// ([`DaemonState::request_handoff_lease`]) — installed onto every
/// constructed session via `PeerSyncSession::set_handoff_lease_responder`
/// (`peer_orchestrator.rs`), the same "daemon injects real behavior into a
/// session" shape `PendingLocalChangeFlush for DaemonState` uses
/// (the daemon's own `LinkRuntimeController`). `self.request_handoff_lease(group_id)` below resolves
/// to the inherent method of the same name (Rust always prefers an inherent
/// method over a trait method of the same name on the same receiver type),
/// not a recursive call into this trait method.
impl HandoffLeaseResponder for DaemonState {
    fn request_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>> {
        Box::pin(async move {
            let (grant, root_digest) = self.request_handoff_lease(group_id).await?;
            Some(PeerHandoffLeaseGrant {
                lease_id: grant.lease_id,
                root_digest,
                expires_at_unix: grant.expires_at_unix,
                ttl_seconds: grant.ttl_seconds,
            })
        })
    }

    fn release_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
        lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { self.release_owned_handoff_lease(group_id, lease_id).await })
    }
}

/// Bridges an incoming peer-to-peer `HandoffTicketRequest` (`peer_session.
/// rs`) -- sent by a DIFFERENT device (X) that is removing/revoking THIS
/// device -- to this device's own removed-device-ticket machinery
/// ([`DaemonState::obtain_own_handoff_ticket`]) -- installed onto every
/// constructed session via `PeerSyncSession::set_handoff_ticket_responder`
/// (`peer_orchestrator.rs`), the same shape `HandoffLeaseResponder for
/// DaemonState` above uses. `self.obtain_own_handoff_ticket(group_id)` below
/// resolves to the inherent method of the same name, not a recursive call
/// into this trait method.
impl HandoffTicketResponder for DaemonState {
    fn request_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>> {
        Box::pin(async move { self.obtain_own_handoff_ticket(group_id).await })
    }

    fn release_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.end_ticket_close_when_released(group_id, lease_id, || async move {
                match self.peers.session(target_device_id) {
                    Some(session) => {
                        match session.release_handoff_lease_to_peer(group_id, lease_id).await {
                            Ok(()) => true,
                            Err(error) => {
                                tracing::debug!(%error, group_id, target_device_id, lease_id, "removed-device ticket release was not acknowledged");
                                false
                            }
                        }
                    }
                    None => false,
                }
            })
            .await;
        })
    }
}

impl DaemonState {
    /// The removal a ticket was for is done or abandoned, which this device
    /// learns from the device that holds the ticket. Its close on new custody
    /// leases ends only once the lease target has acknowledged the release (the
    /// ticket can then no longer be used). Until then the close stays, durably,
    /// and the release can be repeated; the close also ends on its own when
    /// the ticket's lifetime has run out. Scoped to (group, lease): another
    /// ticket's close is untouched.
    pub(crate) async fn end_ticket_close_when_released<F, Fut>(
        &self,
        group_id: &str,
        lease_id: &str,
        release_at_target: F,
    ) where
        F: FnOnce() -> Fut,
        Fut: Future<Output = bool>,
    {
        if release_at_target().await {
            self.replica_coordinator.custody_closing().release_ticket(group_id, lease_id);
        } else {
            tracing::warn!(
                group_id,
                lease_id,
                "the ticket's handoff lease release was not acknowledged; keeping the group closed"
            );
        }
    }
}

#[cfg(test)]
mod offline_authorization_tests;
#[cfg(test)]
mod tests;
