//! In-process fake of the Cloudflare-Worker coordination plane, for the full-
//! stack E2E tests that drive the real [`peer_orchestrator`]. It is a test
//! fixture, not a second coordination implementation: it implements only the
//! four endpoints the daemon touches at runtime, and only enough of each to
//! make peer discovery, per-group write authorization, and revocation happen.
//!
//!   - `GET /netmap/subscribe?deviceId=` (WebSocket): pushes `{type:"netmap"}`
//!     frames — the sole seam that makes the orchestrator spawn and tear down
//!     peer sessions.
//!   - `POST /devices/:id/endpoint`: answered `204`
//!     (best-effort on the daemon).
//!
//! Revocation is expressed exactly as the real plane expresses it: recompute
//! the netmap without the revoked peer or group and push it; the orchestrator
//! diffs against its previous snapshot and drops the session (or the group
//! edge). There is no explicit "removed" field on the wire — a peer simply
//! stops appearing.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use futures_util::SinkExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

#[derive(Clone)]
struct DeviceInfo {
    signing_public_key_b64: String,
    /// Every address this device advertises, in the order the netmap
    /// presents them. A real coordination plane publishes each address a
    /// device might be reachable at -- its LAN interfaces, its reflexive
    /// address, a port-mapped one -- because it cannot know which of them a
    /// given peer can actually use. A list rather than one address
    /// specifically so a test can express the shape that matters: a peer
    /// whose FIRST advertised endpoint does not work.
    endpoints: Vec<String>,
    groups: HashSet<String>,
    full_replica_groups: HashSet<String>,
}

#[derive(Default)]
struct Inner {
    devices: HashMap<String, DeviceInfo>,
    snapshot_generation: u64,
    /// device_id -> sender forwarding a netmap JSON text frame to that device's
    /// live WebSocket connection.
    subscribers: HashMap<String, mpsc::UnboundedSender<String>>,
    /// Opt-in signed policy distribution for tests that exercise local writes
    /// after the coordination connection disappears. Other fake users keep the
    /// legacy policy-free frame so their revocation semantics stay unchanged.
    policy_service_key: Option<SigningKey>,
    /// Whether a device's own endpoint report is applied to its advertised
    /// endpoints, or accepted and dropped.
    ///
    /// Off by default, because most tests configure reachability themselves
    /// and a daemon's real report arriving underneath would silently replace
    /// what the test set up. The relay-publication gate turns it on precisely
    /// because the publication is what it is testing.
    apply_endpoint_reports: bool,
    /// Substrate reachability this plane has stored per device, exactly as the
    /// real one would: an omitted field leaves it, an explicit one replaces it.
    substrate_reachability: HashMap<String, (Vec<String>, Vec<String>)>,
    /// How many endpoint reports to refuse before accepting again, and how many
    /// have arrived in total. A test proving a refused report is retried needs
    /// both -- the count alone cannot tell a retry from a first attempt.
    endpoint_reports_to_fail: u32,
    endpoint_reports_seen: u32,
    /// `(viewer_device_id, target_device_id) -> endpoints`, overriding what
    /// `target_device_id`'s own `DeviceInfo::endpoints` would otherwise
    /// publish, but ONLY in the netmap frame `viewer_device_id` itself
    /// receives -- see `FakeCoordination::set_peer_view_endpoints`'s own
    /// doc comment for why this exists (asymmetric reachability, not a
    /// device-global property). Deliberately separate storage from
    /// `DeviceInfo`, not a field on it: a real coordination plane has
    /// exactly one advertised-endpoints list per device, and conflating an
    /// asymmetric test override with that would make `update_endpoints`
    /// (which mutates `DeviceInfo` and models a device's own candidate
    /// republish) silently clobber or be clobbered by this. Survives
    /// `register_device` re-registering `target_device_id` with a fresh
    /// real endpoint -- restart tests specifically need a viewer's view of
    /// a peer to stay overridden across that peer's own reconnect.
    endpoint_view_overrides: HashMap<(String, String), Vec<String>>,
    /// Track Send rendezvous grants -- see `serve_send_authorization_issue`'s
    /// own doc comment. grant_id -> record.
    send_authorizations: HashMap<String, FakeSendAuthorization>,
    /// Per-group, append-only signed policy chain this fake has issued via
    /// `grant_role`, in the exact `PolicyRecord` shape
    /// `yadorilink_daemon::change_policy::verify_group_policy_log` accepts --
    /// built with that same crate's own `change_policy::policy_signing::
    /// grant_record` helper, so a record built here is byte-identical
    /// (preimage, hash chain, signature) to what the coordination service's real
    /// `recordGrantWithRole` (`src/policy/service.ts`) would produce, not a
    /// hand-rolled approximation of the wire format. A group with no entry
    /// here has never had `grant_role` called for it -- `signed_policy_logs`
    /// then falls back to the historical all-zero, no-records frame every
    /// non-role-aware test already depends on.
    group_policy_chains: HashMap<String, Vec<yadorilink_daemon::change_policy::PolicyRecord>>,
    /// Per-subscriber, per-group "already sent up to this seq" watermark --
    /// mirrors the coordination service's own per-WebSocket `policyWatermarks`
    /// (`durable-objects/netmap-device.ts`): a group's policy chain is never
    /// resent in full to a subscriber that has already seen a prefix of it,
    /// only the tail beyond what it was last sent, because the daemon's own
    /// `verify_group_policy_log_with_base` only accepts a record tail that
    /// starts exactly at its last verified seq + 1, not a redundant full
    /// resend. Reset (removed) whenever a device (re)subscribes, exactly
    /// like a fresh production WebSocket starts with a fresh (empty)
    /// watermark map for that connection.
    policy_send_watermarks: HashMap<String, HashMap<String, u64>>,
    /// How many netmap frames this fake has BUILT for each device, over the
    /// fake's whole lifetime (never reset by a resubscribe, unlike
    /// `policy_send_watermarks`). A test that needs to know a device has
    /// actually been served a frame on a NEW connection -- rather than
    /// merely that enough wall-clock time has passed for one -- samples this
    /// before closing the socket and waits for it to advance.
    netmap_frames_built: HashMap<String, u64>,
    /// `(device_id, group_id) -> requests waiting on that device's account`, reported in the
    /// device's own netmap as `pendingApprovals` (absent while none).
    pending_approvals: HashMap<(String, String), u32>,
    /// `device_id -> its account's deletion state`, reported in the device's own netmap as
    /// `self.accountDeletionState` (the field is absent while unset, like an older plane).
    account_deletion: HashMap<String, String>,
    /// Per `(group_id, device_id)` issuance counter for
    /// `serve_authorization_checkpoint` -- `AuthorizationCheckpoint::
    /// checkpoint_seq` must strictly increase per issuing device, matching
    /// the coordination service's own per-device issuance counter.
    checkpoint_seqs: HashMap<(String, String), u64>,
    /// Canned responses for the three handoff routes, keyed by
    /// `(route, group_id)`.
    ///
    /// Absence is meaningful and is the default: a group with no configured
    /// response for a route falls through to the same blanket `204` this
    /// fake answered before these routes were parsed at all, so every test
    /// that does not opt in sees byte-identical behaviour to before. Only a
    /// test that calls one of the `set_handoff_*_response` methods changes
    /// what it gets.
    handoff_responses: HashMap<(HandoffRoute, String), (u16, String)>,
    /// Runs synchronously while `/handoff/lease` is being served, before the
    /// response is written.
    ///
    /// This is the narrowest available hook into the real TOCTOU window that
    /// `DaemonState::request_handoff_lease` guards: it computes its
    /// `attested_digest` BEFORE this HTTP round trip and re-derives
    /// `pinned_digest` AFTER it returns, declining the lease if they differ.
    /// A test proving that guard fires needs to make a real state change
    /// land strictly between those two points, which means during this call.
    handoff_lease_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Every handoff request served, in arrival order -- the counting and
    /// payload-inspection surface tests need, since a canned responder alone
    /// cannot prove a route was actually exercised rather than bypassed.
    handoff_requests: Vec<HandoffRequest>,
}

/// The three coordination-plane handoff routes this fake answers.
///
/// Deliberately only these three. Everything else about the handoff state
/// machine -- lease lifetime, digest verification, membership generation,
/// who may commit -- stays in production code and is exercised there; this
/// fake is a test double for the plane's HTTP surface, not a second
/// implementation of its rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum HandoffRoute {
    /// `POST /shares/groups/{groupId}/handoff/lease`
    Lease,
    /// `POST /shares/groups/{groupId}/handoff/commit`
    Commit,
    /// `POST /shares/groups/{groupId}/handoff/lease/{leaseId}/release`
    Release,
}

/// One handoff request this fake served.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HandoffRequest {
    pub route: HandoffRoute,
    pub group_id: String,
    /// Only `Release` carries one.
    pub lease_id: Option<String>,
    /// The raw request body, so a test can assert on what was actually sent
    /// rather than only that something was.
    pub body: String,
}

/// One in-flight (or already-consumed) Track Send grant this fake has
/// issued. Mirrors the coordination service's `send_authorizations` table just
/// enough for real daemon-side E2E coverage: identity binding and atomic
/// single-use consumption. Deliberately does not model account scoping
/// (this fake has no account concept for anything else either -- every
/// registered device is implicitly "the same account") or a real TTL sweep
/// -- those properties are exhaustively covered by the coordination service's
/// own `test/send-authorization.test.ts` against the real Worker; this
/// fake's job is only to exercise the DAEMON side end to end.
#[derive(Clone)]
struct FakeSendAuthorization {
    nonce: String,
    sender_device_id: String,
    receiver_device_id: String,
    consumed: bool,
}

/// A handle to the running fake. Cloneable; every clone shares one server.
#[derive(Clone)]
pub struct FakeCoordination {
    inner: Arc<Mutex<Inner>>,
    addr: String,
    accept_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl FakeCoordination {
    /// Binds a loopback listener and starts serving. The returned address is an
    /// `http://127.0.0.1:PORT` base URL suitable for `OrchestratorConfig::
    /// coordination_addr` (the daemon rewrites it to `ws://` for the netmap
    /// subscription and dials the POST endpoints over http).
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let inner = Arc::new(Mutex::new(Inner::default()));
        let accept_inner = inner.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let conn_inner = accept_inner.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, conn_inner).await;
                });
            }
        });
        FakeCoordination { inner, addr, accept_task: Arc::new(Mutex::new(Some(accept_task))) }
    }

    pub fn addr(&self) -> String {
        self.addr.clone()
    }

    pub fn enable_signed_policy(&self) {
        self.inner.lock().unwrap().policy_service_key = Some(SigningKey::from_bytes(&[42u8; 32]));
    }

    /// The service signing key `enable_signed_policy` installed, for a
    /// test that needs to sign something itself with the same key this
    /// fake uses.
    pub fn policy_signing_key(&self) -> Option<SigningKey> {
        self.inner.lock().unwrap().policy_service_key.clone()
    }

    /// Closes `device_id`'s live netmap WebSocket from the server side,
    /// exactly as a coordination-plane restart, a load-balancer idle
    /// timeout, or a Durable Object eviction would. Dropping the forwarding
    /// sender ends `serve_netmap_subscription`'s own `rx.recv()`, which
    /// closes the socket; the daemon's `peer_orchestrator::run` backoff loop
    /// then redials and re-subscribes on its own.
    ///
    /// Deliberately does NOT clear `policy_send_watermarks` here -- the
    /// re-subscribe path does that, which is the whole point: the daemon's
    /// first frame after reconnecting carries each group's policy chain from
    /// record 1 again while the daemon still holds its persistent verified
    /// base. Returns whether a subscription was actually live to close.
    pub fn drop_subscription(&self, device_id: &str) -> bool {
        self.inner.lock().unwrap().subscribers.remove(device_id).is_some()
    }

    /// How many netmap frames this fake has built for `device_id` so far --
    /// see `Inner::netmap_frames_built`.
    pub fn netmap_frames_built(&self, device_id: &str) -> u64 {
        self.inner.lock().unwrap().netmap_frames_built.get(device_id).copied().unwrap_or(0)
    }

    /// The signed policy log this fake distributes for `group_id` now: its
    /// grant chain up to the latest record (an empty log before the first).
    pub fn group_policy_log(
        &self,
        group_id: &str,
    ) -> yadorilink_daemon::change_policy::GroupPolicyLog {
        let inner = self.inner.lock().unwrap();
        let chain = inner.group_policy_chains.get(group_id).cloned().unwrap_or_default();
        let (current_seq, current_epoch, policy_head) = match chain.last() {
            Some(head) => (head.seq, head.epoch, head.record_hash.clone()),
            None => (0, 0, vec![0u8; 32]),
        };
        yadorilink_daemon::change_policy::GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq,
            current_epoch,
            policy_head,
            records: chain,
        }
    }

    /// Grants `device_id` a specific writer role for `group_id` by appending
    /// a real, signed `ACTION_GRANT_WITH_ROLE` record to that group's policy
    /// chain and pushing a fresh netmap update -- the fake-coordination
    /// counterpart to a real `share grant --role viewer|editor` request
    /// landing on the coordination service's `recordGrantWithRole`
    /// (the coordination service). Built with
    /// `yadorilink_daemon::change_policy::policy_signing::grant_record`, the
    /// SAME helper this crate's own unit tests
    /// (`daemon_state.rs`'s `local_change_auth_provider_withholds_a_viewers_
    /// local_edit_but_allows_an_editor`, `change_auth.rs`'s
    /// `accepts_change_auth_rejects_a_viewer_and_accepts_the_same_device_
    /// as_an_editor`) use to construct a role-carrying Grant -- the record
    /// this produces is therefore byte-identical in shape (preimage, hash
    /// chain, signature) to what a real coordination plane would sign, not
    /// an approximation of `GroupPolicyLogWire`/`WsPolicyRecord`'s wire
    /// contract.
    ///
    /// `device_id` must already be registered (`register_device`) -- the
    /// Grant binds the SHA-256 fingerprint of its currently-registered
    /// signing key, exactly as a real Grant binds a device's registered
    /// key. `enable_signed_policy` must have been called first; panics
    /// otherwise, since there is no service signing key to issue a record
    /// with. Multiple calls for the same group append further records to
    /// that group's chain (seq keeps increasing), so a device's role can be
    /// changed (e.g. Viewer then later Editor) the same way a real grant
    /// chain evolves.
    pub fn grant_role(
        &self,
        device_id: &str,
        group_id: &str,
        role: yadorilink_daemon::change_policy::WriterRole,
    ) {
        use yadorilink_daemon::change_policy::policy_signing::grant_record;
        {
            let mut inner = self.inner.lock().unwrap();
            let signing_key = inner
                .policy_service_key
                .clone()
                .expect("grant_role requires enable_signed_policy() to be called first");
            let device = inner
                .devices
                .get(device_id)
                .unwrap_or_else(|| panic!("grant_role: device {device_id} is not registered"))
                .clone();
            let b64 = base64::engine::general_purpose::STANDARD;
            let signing_public_key: [u8; 32] = b64
                .decode(&device.signing_public_key_b64)
                .expect("registered signing key is valid base64")
                .try_into()
                .expect("registered signing key is 32 bytes");
            let fingerprint: [u8; 32] = Sha256::digest(signing_public_key).into();

            let chain = inner.group_policy_chains.entry(group_id.to_string()).or_default();
            let prev: [u8; 32] = chain
                .last()
                .map(|record| {
                    record.record_hash.as_slice().try_into().expect("record_hash is 32 bytes")
                })
                .unwrap_or([0u8; 32]);
            let seq = chain.last().map(|record| record.seq + 1).unwrap_or(1);
            let record =
                grant_record(&signing_key, group_id, seq, prev, device_id, fingerprint, role);
            chain.push(record);
        }
        self.push();
    }

    /// Changes `device_id`'s role for `group_id` the same way
    /// the coordination service's live role-change endpoint (`changeDeviceRole`,
    /// `src/shares/service.ts`) does for a DOWNGRADE: a plain `Revoke`
    /// record (bumping the group's `auth_epoch`, exactly like an ordinary
    /// revoke) immediately followed by a `GrantWithRole` record at
    /// `new_role`, at the SAME newly-bumped epoch -- and then a fresh
    /// netmap push, so every subscriber (including `device_id` itself)
    /// re-derives write authorization from the updated chain on its very
    /// next check.
    ///
    /// Unlike a real downgrade, this always appends the chained pair
    /// regardless of whether `new_role` genuinely outranks the device's
    /// current role -- callers that need to distinguish upgrade-vs-downgrade
    /// behavior should call `grant_role` directly for a plain upgrade (no
    /// epoch bump); this helper exists specifically to drive the
    /// epoch-bumping downgrade path end to end. `device_id` must already be
    /// registered and already have a prior `grant_role` call for
    /// `group_id` (there must be a chain to revoke from); panics otherwise.
    pub fn downgrade_role(
        &self,
        device_id: &str,
        group_id: &str,
        new_role: yadorilink_daemon::change_policy::WriterRole,
    ) {
        use yadorilink_daemon::change_policy::policy_signing::{
            grant_record_at_epoch, revoke_record_at_epoch,
        };
        {
            let mut inner = self.inner.lock().unwrap();
            let signing_key = inner
                .policy_service_key
                .clone()
                .expect("downgrade_role requires enable_signed_policy() to be called first");
            let device = inner
                .devices
                .get(device_id)
                .unwrap_or_else(|| panic!("downgrade_role: device {device_id} is not registered"))
                .clone();
            let b64 = base64::engine::general_purpose::STANDARD;
            let signing_public_key: [u8; 32] = b64
                .decode(&device.signing_public_key_b64)
                .expect("registered signing key is valid base64")
                .try_into()
                .expect("registered signing key is 32 bytes");
            let fingerprint: [u8; 32] = Sha256::digest(signing_public_key).into();

            let chain = inner.group_policy_chains.get_mut(group_id).unwrap_or_else(|| {
                panic!("downgrade_role: group {group_id} has no policy chain yet")
            });
            let head = chain.last().expect("downgrade_role: group's policy chain is empty");
            let head_hash: [u8; 32] =
                head.record_hash.as_slice().try_into().expect("record_hash is 32 bytes");
            let new_epoch = head.epoch + 1;
            let revoke_seq = head.seq + 1;
            let revoke = revoke_record_at_epoch(
                &signing_key,
                group_id,
                revoke_seq,
                head_hash,
                new_epoch,
                device_id,
            );
            let revoke_hash: [u8; 32] =
                revoke.record_hash.as_slice().try_into().expect("record_hash is 32 bytes");
            let regrant = grant_record_at_epoch(
                &signing_key,
                group_id,
                revoke_seq + 1,
                revoke_hash,
                new_epoch,
                device_id,
                fingerprint,
                new_role,
            );
            chain.push(revoke);
            chain.push(regrant);
        }
        self.push();
    }

    /// Takes the coordination plane down completely, as a chaos test needs:
    /// aborts the accept loop (freeing the listener, so the bound port stops
    /// answering and any daemon reconnect attempt fails) and drops every live
    /// subscription (closing the daemons' netmap WebSockets). Peer-to-peer
    /// sync, which runs over the direct transport, is unaffected — which is
    /// the whole point of the `Published Data Plane Survives Coordination
    /// Outage` tests: coordination-plane reachability gates NEW checkpoint
    /// issuance, never already-Published data-plane transfer.
    ///
    /// Deliberately does NOT clear `devices`/`group_policy_chains`/
    /// `checkpoint_seqs`: a real coordination plane's registration and
    /// policy database is durable storage, not in-memory connection state --
    /// an outage does not forget who is registered or what a group's policy
    /// chain says, only the live connections themselves drop. Only
    /// `subscribers` (the live netmap WebSocket handles) and
    /// `endpoint_view_overrides` (a connection-scoped test override) are
    /// connection-scoped and so are cleared here; see [`Self::restart`] for
    /// resuming service on the same address once a test's outage window ends.
    pub fn shutdown(&self) {
        if let Some(task) = self.accept_task.lock().unwrap().take() {
            task.abort();
        }
        let mut inner = self.inner.lock().unwrap();
        inner.subscribers.clear();
        inner.endpoint_view_overrides.clear();
    }

    /// Resumes serving on the SAME address [`Self::shutdown`] took down --
    /// the recovery half of a coordination-plane outage chaos test. Every
    /// device/policy-chain/checkpoint-sequence record registered before the
    /// outage is still present (see [`Self::shutdown`]'s own doc comment),
    /// so a daemon's own reconnect logic picks the netmap subscription back
    /// up without needing to re-register anything.
    pub fn restart(&self) {
        let addr: std::net::SocketAddr = self
            .addr
            .trim_start_matches("http://")
            .parse()
            .expect("FakeCoordination::addr is always a parseable loopback socket address");
        let inner = self.inner.clone();
        let accept_task_handle = self.accept_task.clone();
        let restart_task = tokio::spawn(async move {
            // A handful of short retries: `shutdown()`'s aborted accept task
            // drops its `TcpListener` (closing the fd) essentially
            // immediately, but the abort itself is async-cancelled, not
            // synchronously joined, so there is a brief window where the
            // kernel has not yet released the port.
            let mut bind_attempts = 0;
            let listener = loop {
                match TcpListener::bind(addr).await {
                    Ok(listener) => break listener,
                    Err(_) if bind_attempts < 20 => {
                        bind_attempts += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Err(e) => panic!(
                        "the port FakeCoordination::shutdown just freed is still not bindable \
                         after {bind_attempts} retries: {e}"
                    ),
                }
            };
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let conn_inner = inner.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, conn_inner).await;
                });
            }
        });
        *accept_task_handle.lock().unwrap() = Some(restart_task);
    }

    /// Records a device's identity and initial group membership, then pushes a
    /// fresh netmap to everyone. A device has one key: its Ed25519 signing
    /// key. The orchestrator pins it from the netmap and verifies every
    /// incoming change against it.
    pub fn register_device(
        &self,
        device_id: &str,
        signing_public_key: [u8; 32],
        endpoint: String,
        groups: &[&str],
    ) {
        let b64 = base64::engine::general_purpose::STANDARD;
        let info = DeviceInfo {
            signing_public_key_b64: b64.encode(signing_public_key),
            endpoints: vec![endpoint],
            groups: groups.iter().map(|g| g.to_string()).collect(),
            full_replica_groups: HashSet::new(),
        };
        self.inner.lock().unwrap().devices.insert(device_id.to_string(), info);
        self.push();
    }

    /// Configures what `POST /shares/groups/{group_id}/handoff/lease`
    /// answers for this group.
    ///
    /// Until a test calls this, that route falls through to the blanket
    /// `204` — an empty body where the daemon expects JSON, which it
    /// correctly reports as "coordination unavailable". That is the real
    /// behaviour a demotion sees against an unconfigured plane, and it is
    /// what these routes did before this fake parsed them; opting in is
    /// what changes it.
    #[allow(dead_code)]
    pub fn set_handoff_lease_response(&self, group_id: &str, status: u16, body: serde_json::Value) {
        self.set_handoff_response(HandoffRoute::Lease, group_id, status, body);
    }

    /// Configures what `POST /shares/groups/{group_id}/handoff/commit`
    /// answers. See [`set_handoff_lease_response`](Self::set_handoff_lease_response).
    #[allow(dead_code)]
    pub fn set_handoff_commit_response(
        &self,
        group_id: &str,
        status: u16,
        body: serde_json::Value,
    ) {
        self.set_handoff_response(HandoffRoute::Commit, group_id, status, body);
    }

    /// Configures what
    /// `POST /shares/groups/{group_id}/handoff/lease/{leaseId}/release`
    /// answers, for any lease id.
    #[allow(dead_code)]
    pub fn set_handoff_release_response(
        &self,
        group_id: &str,
        status: u16,
        body: serde_json::Value,
    ) {
        self.set_handoff_response(HandoffRoute::Release, group_id, status, body);
    }

    fn set_handoff_response(
        &self,
        route: HandoffRoute,
        group_id: &str,
        status: u16,
        body: serde_json::Value,
    ) {
        self.inner
            .lock()
            .unwrap()
            .handoff_responses
            .insert((route, group_id.to_string()), (status, body.to_string()));
    }

    /// Installs a closure that runs synchronously while a `/handoff/lease`
    /// request is being served, before its response is written.
    ///
    /// The window this opens is real, not synthetic:
    /// `DaemonState::request_handoff_lease` computes its `attested_digest`
    /// before this HTTP round trip and re-derives `pinned_digest` after it,
    /// declining the lease when they differ. A closure here lands strictly
    /// between the two, so a test can make a genuine state change (a real
    /// file write) at the one instant that exercises that guard, with no
    /// production code modified.
    #[allow(dead_code)]
    pub fn on_handoff_lease(&self, hook: impl Fn() + Send + Sync + 'static) {
        self.inner.lock().unwrap().handoff_lease_hook = Some(Arc::new(hook));
    }

    /// How many requests this fake has served for `route`.
    ///
    /// Proves a route was genuinely exercised rather than bypassed — a
    /// canned response alone cannot distinguish "the daemon asked and got
    /// this" from "the daemon never asked".
    #[allow(dead_code)]
    pub fn handoff_request_count(&self, route: HandoffRoute) -> usize {
        self.inner.lock().unwrap().handoff_requests.iter().filter(|r| r.route == route).count()
    }

    /// Every handoff request served so far, in arrival order, for a test
    /// that needs to assert on the bodies rather than only the counts.
    #[allow(dead_code)]
    pub fn handoff_requests(&self) -> Vec<HandoffRequest> {
        self.inner.lock().unwrap().handoff_requests.clone()
    }

    /// Marks (or clears) a device as a full replica ("store everything") of a
    /// group — mirrored onto peers' `fullReplicaGroupIds`.
    pub fn set_full_replica(&self, device_id: &str, group_id: &str, is_full_replica: bool) {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(dev) = inner.devices.get_mut(device_id) {
                if is_full_replica {
                    dev.full_replica_groups.insert(group_id.to_string());
                } else {
                    dev.full_replica_groups.remove(group_id);
                }
            }
        }
        self.push();
    }

    /// Reports `count` requests waiting on `device_id`'s account to join `group_id` (0 clears),
    /// as the real plane does for the owner's devices.
    pub fn set_pending_approvals(&self, device_id: &str, group_id: &str, count: u32) {
        {
            let mut inner = self.inner.lock().unwrap();
            let key = (device_id.to_string(), group_id.to_string());
            if count == 0 {
                inner.pending_approvals.remove(&key);
            } else {
                inner.pending_approvals.insert(key, count);
            }
        }
        self.push();
    }

    /// Reports `state` (`pending` / `urgent` / `none`) as `device_id`'s own account deletion
    /// state; `None` stops sending the `self` field at all.
    pub fn set_account_deletion_state(&self, device_id: &str, state: Option<&str>) {
        {
            let mut inner = self.inner.lock().unwrap();
            match state {
                Some(state) => inner.account_deletion.insert(device_id.to_string(), state.into()),
                None => inner.account_deletion.remove(device_id),
            };
        }
        self.push();
    }

    /// Republishes `device_id`'s advertised endpoint -- mirroring
    /// what a real coordination plane would push over the netmap
    /// subscription if a device's network conditions changed (e.g. a new
    /// reflexive address). This is a device-GLOBAL candidate republish,
    /// the same information every peer's netmap subscription receives --
    /// it does not, and cannot, tear down a live QUIC connection any peer
    /// already has to `device_id`. Production's own orchestrator only
    /// consults candidates when it has no live session (initial dial,
    /// post-failure reconnect): an established connection is left alone
    /// by a bare candidate update, precisely so that address churn during
    /// a live session does not itself cause disruption. A test that needs
    /// to force a genuinely dead path for one specific peer pair, or to
    /// force a currently-live direct connection down, needs
    /// `set_peer_view_endpoints` and/or an explicit live-connection
    /// teardown seam respectively -- see that method's own doc comment.
    #[allow(dead_code)]
    /// Apply each device's own endpoint report to its advertised endpoints,
    /// instead of accepting and dropping it.
    ///
    /// Turns this fixture into the full publication loop: a daemon learns its
    /// reachability, reports it here, and its peers receive exactly that in
    /// their netmap. Off by default — see `Inner::apply_endpoint_reports`.
    #[allow(dead_code)]
    /// Refuse the next `n` endpoint reports with 503.
    #[allow(dead_code)]
    pub fn fail_next_endpoint_reports(&self, n: u32) {
        self.inner.lock().unwrap().endpoint_reports_to_fail = n;
    }

    /// How many endpoint reports have arrived, refused ones included.
    #[allow(dead_code)]
    pub fn endpoint_report_count(&self) -> u32 {
        self.inner.lock().unwrap().endpoint_reports_seen
    }

    /// The substrate reachability this plane currently stores for `device_id`,
    /// or `None` if it has never been told.
    #[allow(dead_code)]
    pub fn substrate_reachability_of(&self, device_id: &str) -> Option<(Vec<String>, Vec<String>)> {
        self.inner.lock().unwrap().substrate_reachability.get(device_id).cloned()
    }

    pub fn apply_endpoint_reports(&self) {
        self.inner.lock().unwrap().apply_endpoint_reports = true;
    }

    /// The endpoints this plane currently advertises for `device_id`.
    #[allow(dead_code)]
    pub fn advertised_endpoints(&self, device_id: &str) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .devices
            .get(device_id)
            .map(|device| device.endpoints.clone())
            .unwrap_or_default()
    }

    pub fn update_endpoint(&self, device_id: &str, endpoint: String) {
        self.update_endpoints(device_id, vec![endpoint]);
    }

    /// Republishes `device_id`'s advertised endpoints as a whole ordered
    /// list, so a test can express a peer that advertises several addresses
    /// of which only some work -- in particular one whose FIRST advertised
    /// address does not. Device-global, like `update_endpoint`'s own doc
    /// comment explains -- every subscriber sees the same list, subject to
    /// `set_peer_view_endpoints`'s per-viewer override below.
    #[allow(dead_code)]
    pub fn update_endpoints(&self, device_id: &str, endpoints: Vec<String>) {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(dev) = inner.devices.get_mut(device_id) {
                dev.endpoints = endpoints;
            }
        }
        self.push();
    }

    /// Overrides the endpoints `viewer_device_id`'s OWN netmap reports for
    /// `target_device_id`, independent of what every other subscriber
    /// sees. A real coordination plane cannot generally do this (it
    /// publishes one endpoint list per device to everyone), but this test
    /// fixture needs it anyway: a test scenario wants `M` and `W` to be
    /// mutually unreachable while both stay reachable from `N`, and
    /// `update_endpoints`'s device-global republish cannot express that
    /// asymmetry at all -- setting `W`'s endpoint dead would make `N` lose
    /// its own real direct path to `W` too.
    ///
    /// Overriding here has no effect on group membership or full-replica
    /// status -- purely which address(es) `viewer_device_id`'s netmap
    /// names for `target_device_id`. Survives `target_device_id`
    /// re-registering via `register_device` (a restart pushing a fresh
    /// real endpoint does not implicitly clear a viewer's override of it).
    #[allow(dead_code)]
    pub fn set_peer_view_endpoints(
        &self,
        viewer_device_id: &str,
        target_device_id: &str,
        endpoints: Vec<String>,
    ) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner
                .endpoint_view_overrides
                .insert((viewer_device_id.to_string(), target_device_id.to_string()), endpoints);
        }
        self.push();
    }

    /// Removes a `set_peer_view_endpoints` override, reverting
    /// `viewer_device_id`'s view of `target_device_id` to that device's
    /// own globally-advertised endpoints.
    #[allow(dead_code)]
    pub fn clear_peer_view_endpoints(&self, viewer_device_id: &str, target_device_id: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner
                .endpoint_view_overrides
                .remove(&(viewer_device_id.to_string(), target_device_id.to_string()));
        }
        self.push();
    }

    /// Revokes a device's access to one group and pushes the new netmap — the
    /// device drops out of that group's membership, so peers sharing only that
    /// group see it disappear and tear the session (or group edge) down.
    pub fn revoke(&self, device_id: &str, group_id: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(dev) = inner.devices.get_mut(device_id) {
                dev.groups.remove(group_id);
                dev.full_replica_groups.remove(group_id);
            }
        }
        self.push();
    }

    /// Removes a device entirely (device removal) and pushes the new netmap;
    /// peers see it vanish and tear the session down.
    pub fn remove_device(&self, device_id: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.devices.remove(device_id);
            inner
                .endpoint_view_overrides
                .retain(|(viewer, target), _| viewer != device_id && target != device_id);
        }
        self.push();
    }

    /// Recomputes and sends each subscribed device its current netmap: the
    /// other devices that share at least one group with it.
    fn push(&self) {
        let mut inner = self.inner.lock().unwrap();
        let subscribers: Vec<_> = inner
            .subscribers
            .iter()
            .map(|(device_id, tx)| (device_id.clone(), tx.clone()))
            .collect();
        for (subscriber_id, tx) in subscribers {
            let frame = netmap_frame_for(&mut inner, &subscriber_id);
            let _ = tx.send(frame);
        }
    }
}

/// The `{type:"netmap"}` JSON frame for `subscriber_id`: every other device
/// sharing at least one of the subscriber's groups, each with the shared-group
/// subset (membership = bidirectional write authority) and full-replica subset.
fn netmap_frame_for(inner: &mut Inner, subscriber_id: &str) -> String {
    *inner.netmap_frames_built.entry(subscriber_id.to_string()).or_default() += 1;
    let self_groups =
        inner.devices.get(subscriber_id).map(|d| d.groups.clone()).unwrap_or_default();

    let mut peers = Vec::new();
    for (device_id, dev) in &inner.devices {
        if device_id == subscriber_id {
            continue;
        }
        let shared: Vec<String> = dev.groups.intersection(&self_groups).cloned().collect();
        if shared.is_empty() {
            continue;
        }
        let full_replica: Vec<String> =
            dev.full_replica_groups.intersection(&self_groups).cloned().collect();
        // Per-viewer override wins over the device's own global endpoint
        // list -- see `set_peer_view_endpoints`'s own doc comment.
        let visible_endpoints = inner
            .endpoint_view_overrides
            .get(&(subscriber_id.to_string(), device_id.to_string()))
            .unwrap_or(&dev.endpoints);
        peers.push(serde_json::json!({
            "deviceId": device_id,
            "signingPublicKeyBase64": dev.signing_public_key_b64,
            "endpoints": visible_endpoints
                .iter()
                .map(|address| serde_json::json!({ "address": address }))
                .collect::<Vec<_>>(),
            "sharedGroupIds": shared,
            "fullReplicaGroupIds": full_replica,
        }));
    }
    inner.snapshot_generation += 1;
    let mut frame = serde_json::json!({
        "type": "netmap",
        "snapshotGeneration": inner.snapshot_generation.to_string(),
        "peers": peers
    });
    let pending: Vec<serde_json::Value> = inner
        .pending_approvals
        .iter()
        .filter(|((device_id, _), _)| device_id == subscriber_id)
        .map(|((_, group_id), count)| serde_json::json!({ "groupId": group_id, "count": count }))
        .collect();
    if let Some(state) = inner.account_deletion.get(subscriber_id) {
        frame["self"] = serde_json::json!({ "accountDeletionState": state });
    }
    if !pending.is_empty() {
        frame["pendingApprovals"] = serde_json::Value::Array(pending);
    }
    if let Some(service_key) = &inner.policy_service_key {
        frame["serviceSigningPublicKeyBase64"] = serde_json::Value::String(
            base64::engine::general_purpose::STANDARD
                .encode(service_key.verifying_key().to_bytes()),
        );
        frame["groupPolicyLogs"] = signed_policy_logs(inner, subscriber_id, &self_groups);
        // Required on every push, like the two fields above: the daemon
        // rejects a netmap without it as malformed. This fake never isolates
        // a group, so the list is always empty.
        frame["policyInvalidGroupIds"] = serde_json::json!([]);
    }
    frame.to_string()
}

const WIRE_ACTION_GRANT_WITH_ROLE: u32 = 3;

/// Renders one signed `PolicyRecord` (built by `grant_role` via
/// `policy_signing::grant_record`) into the exact camelCase/base64 wire
/// shape `peer_orchestrator.rs`'s `WsPolicyRecord` deserializes -- the
/// mirror image of that struct's own field-by-field decoding, so a record
/// built here and one built by a real coordination plane are
/// indistinguishable on the wire.
fn policy_record_to_wire_json(
    record: &yadorilink_daemon::change_policy::PolicyRecord,
) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut json = serde_json::json!({
        "groupId": record.group_id,
        "seq": record.seq,
        "prevRecordHashBase64": b64.encode(&record.prev_record_hash),
        "recordHashBase64": b64.encode(&record.record_hash),
        "epoch": record.epoch,
        "actionType": record.action_type,
        "deviceId": record.device_id,
        "signingKeyFingerprintBase64": b64.encode(&record.signing_key_fingerprint),
        "newAuthorityKeyBase64": b64.encode(&record.new_authority_key),
        "signerKeyIdBase64": b64.encode(&record.signer_key_id),
        "signatureBase64": b64.encode(&record.signature),
    });
    // Omitted entirely (not merely absent-as-null) for anything but a
    // grant-with-role record -- matches the daemon-side `#[serde(default)]`
    // `Option<u32>` field, which defaults to absent the same way.
    if record.action_type == WIRE_ACTION_GRANT_WITH_ROLE {
        json["role"] = serde_json::Value::from(record.role);
    }
    json
}

/// Builds the `groupPolicyLogs` array for one subscriber's netmap frame:
/// every group it belongs to, each with the group's CURRENT head coordinates
/// (`currentSeq`/`currentEpoch`/`policyHeadBase64`, always the group's real
/// current state, matching the coordination service's own `toWirePolicyLog`) but
/// only the record TAIL this specific subscriber has not already been sent
/// (`policy_send_watermarks`, matching that same Worker's per-connection
/// `policyWatermarks` filtering in `pushNetmapSerializedSafely`). A group
/// `grant_role` has never touched keeps the historical all-zero, no-records
/// shape every pre-existing (non-role-aware) test in this suite depends on.
fn signed_policy_logs(
    inner: &mut Inner,
    subscriber_id: &str,
    groups: &HashSet<String>,
) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut group_ids: Vec<_> = groups.iter().cloned().collect();
    group_ids.sort();
    let logs: Vec<_> = group_ids
        .into_iter()
        .map(|group_id| {
            let chain = inner.group_policy_chains.get(&group_id).cloned().unwrap_or_default();
            let Some(head) = chain.last() else {
                return serde_json::json!({
                    "groupId": group_id,
                    "currentSeq": 0,
                    "currentEpoch": 0,
                    "policyHeadBase64": b64.encode([0u8; 32]),
                    "records": [],
                });
            };
            let current_seq = head.seq;
            let current_epoch = head.epoch;
            let policy_head_b64 = b64.encode(&head.record_hash);
            let watermarks =
                inner.policy_send_watermarks.entry(subscriber_id.to_string()).or_default();
            let since = watermarks.get(&group_id).copied().unwrap_or(0);
            let records: Vec<_> = chain
                .iter()
                .filter(|record| record.seq > since)
                .map(policy_record_to_wire_json)
                .collect();
            watermarks.insert(group_id.clone(), current_seq);
            serde_json::json!({
                "groupId": group_id,
                "currentSeq": current_seq,
                "currentEpoch": current_epoch,
                "policyHeadBase64": policy_head_b64,
                "records": records,
            })
        })
        .collect();
    serde_json::Value::Array(logs)
}

async fn handle_connection(mut stream: TcpStream, inner: Arc<Mutex<Inner>>) -> std::io::Result<()> {
    let (head, leftover) = read_http_head(&mut stream).await?;
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let is_ws_upgrade = head.to_ascii_lowercase().contains("upgrade: websocket");
    if method == "GET" && target.starts_with("/netmap/subscribe") && is_ws_upgrade {
        serve_netmap_subscription(stream, &head, &target, inner).await
    } else if method == "POST" {
        if target.split('?').next() == Some("/send/authorization") {
            serve_send_authorization_issue(stream, &head, leftover, inner).await
        } else if let Some(grant_id) = parse_send_authorization_consume_target(&target) {
            serve_send_authorization_consume(stream, &head, leftover, grant_id, inner).await
        } else if let Some(group_id) = parse_authorization_checkpoint_target(&target) {
            serve_authorization_checkpoint(stream, &head, leftover, group_id, inner).await
        } else if let Some((route, group_id, lease_id)) = parse_handoff_target(&target) {
            serve_handoff(stream, &head, leftover, route, group_id, lease_id, inner).await
        } else if let Some(device_id) = parse_endpoint_report_target(&target) {
            serve_endpoint_report(stream, &head, leftover, device_id, inner).await
        } else {
            // Every other route the daemon calls is best-effort: a 204 is
            // all it needs. Drain any request body first so the socket
            // closes cleanly.
            drain_body(&mut stream, &head, leftover).await?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n").await?;
            stream.flush().await
        }
    } else {
        drain_body(&mut stream, &head, leftover).await?;
        stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n").await?;
        stream.flush().await
    }
}

/// Matches `/devices/{deviceId}/endpoint` and extracts `deviceId`.
fn parse_endpoint_report_target(target: &str) -> Option<String> {
    let path = target.split('?').next().unwrap_or(target);
    let device_id = path.strip_prefix("/devices/")?.strip_suffix("/endpoint")?;
    (!device_id.is_empty() && !device_id.contains('/')).then(|| device_id.to_string())
}

/// Applies a device's endpoint report, the way the real coordination plane
/// does: the reported addresses become that device's advertised endpoints,
/// and its peers are pushed a fresh netmap.
///
/// This used to be swallowed with a bare 204, which made every test's peer
/// reachability something the *test* had configured rather than something a
/// daemon had published. That is exactly the half of the loop a relay URL has
/// to survive — a daemon learns its own relay from the substrate, publishes it
/// here, and a peer can only dial it if what comes back out of the netmap is
/// what went in.
///
/// Stored verbatim and forwarded unchanged, like the real plane: nothing here
/// parses an address, because classifying one is the receiving daemon's job.
async fn serve_endpoint_report(
    mut stream: TcpStream,
    head: &str,
    leftover: Vec<u8>,
    device_id: String,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let body = read_body(&mut stream, head, leftover).await?;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Candidate {
        address: String,
        #[serde(default)]
        priority: i32,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        #[serde(default)]
        candidates: Vec<Candidate>,
        /// Absent leaves the stored snapshot alone; present -- including
        /// present and empty -- replaces it.
        #[serde(default)]
        substrate_reachability: Option<WireSubstrate>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WireSubstrate {
        #[serde(default)]
        direct: Vec<String>,
        #[serde(default)]
        relays: Vec<String>,
    }

    // Decided under the lock, acted on outside it: a guard alive across an
    // await makes this whole future non-Send.
    let refuse = {
        let mut guard = inner.lock().unwrap();
        guard.endpoint_reports_seen += 1;
        let refuse = guard.endpoint_reports_to_fail > 0;
        if refuse {
            guard.endpoint_reports_to_fail -= 1;
        }
        refuse
    };
    if refuse {
        // A real refusal, so only the daemon's own retry can make the next one
        // happen.
        stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n").await?;
        return Ok(());
    }

    let changed = match serde_json::from_slice::<Req>(&body) {
        Ok(req) => {
            let mut guard = inner.lock().unwrap();
            if let Some(substrate) = req.substrate_reachability {
                guard
                    .substrate_reachability
                    .insert(device_id.clone(), (substrate.direct, substrate.relays));
            }
            // Accepted and dropped unless a test opted in. See
            // `Inner::apply_endpoint_reports`.
            if !guard.apply_endpoint_reports {
                false
            } else {
                match guard.devices.get_mut(&device_id) {
                    Some(device) => {
                        let mut candidates = req.candidates;
                        // Best first, matching what the real plane's
                        // `ORDER BY priority ASC` yields for a netmap read.
                        candidates.sort_by_key(|c| std::cmp::Reverse(c.priority));
                        let endpoints: Vec<String> =
                            candidates.into_iter().map(|c| c.address).collect();
                        let moved = device.endpoints != endpoints;
                        device.endpoints = endpoints;
                        moved
                    }
                    // A report for a device this fixture never registered is
                    // accepted and dropped, exactly as the 204 before it did.
                    None => false,
                }
            }
        }
        Err(_) => false,
    };

    if changed {
        // Same push the fixture's own mutators do: a device's reachability
        // moving is a netmap change for every peer of it.
        let mut guard = inner.lock().unwrap();
        let subscribers: Vec<_> = guard
            .subscribers
            .iter()
            .map(|(device_id, tx)| (device_id.clone(), tx.clone()))
            .collect();
        for (subscriber_id, tx) in subscribers {
            let frame = netmap_frame_for(&mut guard, &subscriber_id);
            let _ = tx.send(frame);
        }
    }

    stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n").await?;
    stream.flush().await
}

/// Matches `/send/authorization/{grantId}/consume` and extracts `grantId`.
fn parse_send_authorization_consume_target(target: &str) -> Option<String> {
    let path = target.split('?').next().unwrap_or(target);
    let grant_id = path.strip_prefix("/send/authorization/")?.strip_suffix("/consume")?;
    (!grant_id.is_empty() && !grant_id.contains('/')).then(|| grant_id.to_string())
}

/// Matches `/shares/groups/{groupId}/authorization-checkpoint` and extracts
/// `groupId`.
fn parse_authorization_checkpoint_target(target: &str) -> Option<String> {
    let path = target.split('?').next().unwrap_or(target);
    let group_id =
        path.strip_prefix("/shares/groups/")?.strip_suffix("/authorization-checkpoint")?;
    (!group_id.is_empty() && !group_id.contains('/')).then(|| group_id.to_string())
}

/// Matches the three handoff routes and extracts what identifies them.
///
/// Release is tested FIRST because `/handoff/lease` is a strict prefix of
/// `/handoff/lease/{leaseId}/release`: checking lease first would swallow
/// every release call and answer it as a lease request.
fn parse_handoff_target(target: &str) -> Option<(HandoffRoute, String, Option<String>)> {
    let path = target.split('?').next().unwrap_or(target);
    let rest = path.strip_prefix("/shares/groups/")?;
    let (group_id, tail) = rest.split_once('/')?;
    if group_id.is_empty() {
        return None;
    }
    let group_id = group_id.to_string();
    if let Some(lease_id) =
        tail.strip_prefix("handoff/lease/").and_then(|t| t.strip_suffix("/release"))
    {
        if lease_id.is_empty() || lease_id.contains('/') {
            return None;
        }
        return Some((HandoffRoute::Release, group_id, Some(lease_id.to_string())));
    }
    match tail {
        "handoff/lease" => Some((HandoffRoute::Lease, group_id, None)),
        "handoff/commit" => Some((HandoffRoute::Commit, group_id, None)),
        _ => None,
    }
}

/// Serves the three handoff routes from a test's canned configuration.
///
/// Deliberately not a handoff state machine: it records the request, runs
/// the lease hook if one is installed, and answers with whatever the test
/// configured. With nothing configured it falls through to the same blanket
/// `204` this fake gave before it parsed these routes at all, so a test that
/// never opts in cannot tell the difference.
///
/// The hook runs with the lock released, because a hook is test code that
/// may well call back into this fake.
async fn serve_handoff(
    mut stream: TcpStream,
    head: &str,
    leftover: Vec<u8>,
    route: HandoffRoute,
    group_id: String,
    lease_id: Option<String>,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let body = read_body(&mut stream, head, leftover).await?;
    let body = String::from_utf8_lossy(&body).into_owned();

    let (configured, hook) = {
        let mut guard = inner.lock().unwrap();
        guard.handoff_requests.push(HandoffRequest {
            route,
            group_id: group_id.clone(),
            lease_id,
            body,
        });
        let configured = guard.handoff_responses.get(&(route, group_id)).cloned();
        let hook = matches!(route, HandoffRoute::Lease)
            .then(|| guard.handoff_lease_hook.clone())
            .flatten();
        (configured, hook)
    };

    if let Some(hook) = hook {
        hook();
    }

    match configured {
        Some((status, body)) => {
            let reason = match status {
                200 => "OK",
                204 => "No Content",
                403 => "Forbidden",
                409 => "Conflict",
                _ => "Unknown",
            };
            respond_json(&mut stream, status, reason, &body).await
        }
        None => {
            stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n").await?;
            stream.flush().await
        }
    }
}

/// Serves `POST /shares/groups/:groupId/authorization-checkpoint` for real
/// -- `yadorilink_daemon::coordination_client::request_authorization_
/// checkpoint`'s server side, the coordination service's `routes/shares.ts`
/// (phase 2e) mirrored just enough to exercise `checkpoint_source::
/// flush_pending_checkpoint` end to end against real daemon code, not an
/// in-process bypass. Reuses `verify_group_policy_log` (the SAME verifier
/// the daemon itself runs on the received netmap frame) against this fake's
/// own `group_policy_chains` to decide current writer status and the
/// `policy_epoch`/`policy_seq`/`policy_head` triple the issued checkpoint
/// pins -- so a checkpoint this fake issues is byte-identical in shape to
/// one a real coordination plane would issue for the same chain state, not
/// an approximation. 403s (no writer role) mirror the real 403 the daemon's
/// own `coordination_client::request_authorization_checkpoint` already
/// treats as an expected refusal, not an error.
async fn serve_authorization_checkpoint(
    mut stream: TcpStream,
    head: &str,
    leftover: Vec<u8>,
    group_id: String,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let body = read_body(&mut stream, head, leftover).await?;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        device_id: String,
        merkle_root_base64: String,
        leaf_count: u64,
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let Ok(req) = serde_json::from_slice::<Req>(&body) else {
        return respond_json(&mut stream, 400, "Bad Request", r#"{"error":"invalid body"}"#).await;
    };
    let Some(merkle_root) =
        b64.decode(&req.merkle_root_base64).ok().and_then(|v| <[u8; 32]>::try_from(v).ok())
    else {
        return respond_json(&mut stream, 400, "Bad Request", r#"{"error":"invalid merkle root"}"#)
            .await;
    };

    let (policy_service_key, chain, device) = {
        let inner = inner.lock().unwrap();
        (
            inner.policy_service_key.clone(),
            inner.group_policy_chains.get(&group_id).cloned().unwrap_or_default(),
            inner.devices.get(&req.device_id).cloned(),
        )
    };
    let Some(policy_service_key) = policy_service_key else {
        return respond_json(
            &mut stream,
            403,
            "Forbidden",
            r#"{"error":"no policy service key -- call enable_signed_policy() first"}"#,
        )
        .await;
    };
    let Some(device) = device else {
        return respond_json(&mut stream, 404, "Not Found", r#"{"error":"unknown device"}"#).await;
    };

    use yadorilink_daemon::change_policy::{verify_group_policy_log, GroupPolicyLog};
    let (current_seq, current_epoch, policy_head) = match chain.last() {
        Some(head_record) => (head_record.seq, head_record.epoch, head_record.record_hash.clone()),
        None => (0, 0, vec![0u8; 32]),
    };
    let log = GroupPolicyLog {
        group_id: group_id.clone(),
        current_seq,
        current_epoch,
        policy_head: policy_head.clone(),
        records: chain,
    };
    let policy = verify_group_policy_log(&policy_service_key.verifying_key().to_bytes(), &log)
        .expect(
            "this fake's own group_policy_chains must always verify against its own signing key",
        );

    // The genuine pre-policy bootstrap window: a group `grant_role` has
    // never touched has no chain to check a writer role against at all --
    // see `GroupPolicyState::resolve_group_policy`'s own doc comment ("the
    // placeholder stamp is still the legitimately accepted authorization on
    // both sides"). Any registered device may obtain a checkpoint here; the
    // exemption ends the instant the group's chain gets its first record.
    let bootstrap = current_seq == 0 && current_epoch == 0 && policy.current_writers().is_empty();
    if !bootstrap
        && !policy.current_writers().iter().any(|writer| writer.device_id == req.device_id)
    {
        return respond_json(
            &mut stream,
            403,
            "Forbidden",
            r#"{"error":"not currently a writer"}"#,
        )
        .await;
    }

    let signing_public_key: [u8; 32] = b64
        .decode(&device.signing_public_key_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .expect("registered device signing key is valid base64/32 bytes");
    let signing_key_fingerprint: [u8; 32] = Sha256::digest(signing_public_key).into();
    let signer_key_id: [u8; 32] =
        Sha256::digest(policy_service_key.verifying_key().to_bytes()).into();
    let policy_head_array: [u8; 32] =
        policy_head.try_into().expect("policy_head is always 32 bytes");

    let checkpoint_seq = {
        let mut inner = inner.lock().unwrap();
        let counter =
            inner.checkpoint_seqs.entry((group_id.clone(), req.device_id.clone())).or_insert(0);
        *counter += 1;
        *counter
    };

    let checkpoint = yadorilink_replica_domain::authorization_checkpoint::AuthorizationCheckpoint {
        group_id: group_id.clone(),
        device_id: req.device_id.clone(),
        signing_key_fingerprint,
        merkle_root,
        leaf_count: req.leaf_count,
        checkpoint_seq,
        signer_key_id,
        policy_epoch: current_epoch,
        policy_seq: current_seq,
        policy_head: policy_head_array,
        issued_at_unix: unix_now() as u64,
    };
    let signature = yadorilink_replica_domain::authorization_checkpoint::sign_checkpoint(
        &checkpoint,
        &policy_service_key,
    );

    let response_body = serde_json::json!({
        "groupId": checkpoint.group_id,
        "deviceId": checkpoint.device_id,
        "signingKeyFingerprintBase64": b64.encode(checkpoint.signing_key_fingerprint),
        "merkleRootBase64": b64.encode(checkpoint.merkle_root),
        "leafCount": checkpoint.leaf_count,
        "checkpointSeq": checkpoint.checkpoint_seq,
        "signerKeyIdBase64": b64.encode(checkpoint.signer_key_id),
        "policyEpoch": checkpoint.policy_epoch,
        "policySeq": checkpoint.policy_seq,
        "policyHeadBase64": b64.encode(checkpoint.policy_head),
        "issuedAtUnix": checkpoint.issued_at_unix,
        "signatureBase64": b64.encode(signature),
    });
    respond_json(&mut stream, 200, "OK", &response_body.to_string()).await
}

/// Serves `POST /send/authorization` for real -- Track Send's rendezvous
/// grant, the coordination service's `routes/send.ts` mirrored just enough to
/// exercise `coordination_client::request_send_authorization` and the
/// `send_authorization` netmap-subscription push end to end against real
/// daemon code, not an in-process bypass. See `FakeSendAuthorization`'s own
/// doc comment for what this deliberately does not model.
async fn serve_send_authorization_issue(
    mut stream: TcpStream,
    head: &str,
    leftover: Vec<u8>,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let body = read_body(&mut stream, head, leftover).await?;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        sender_device_id: String,
        receiver_device_id: String,
    }
    let Ok(req) = serde_json::from_slice::<Req>(&body) else {
        return respond_json(&mut stream, 400, "Bad Request", r#"{"error":"invalid body"}"#).await;
    };
    if req.sender_device_id == req.receiver_device_id {
        return respond_json(
            &mut stream,
            400,
            "Bad Request",
            r#"{"error":"sender and receiver must differ"}"#,
        )
        .await;
    }

    let (sender, receiver, receiver_substrate) = {
        let inner = inner.lock().unwrap();
        (
            inner.devices.get(&req.sender_device_id).cloned(),
            inner.devices.get(&req.receiver_device_id).cloned(),
            substrate_json(&inner, &req.receiver_device_id),
        )
    };
    let (Some(_sender), Some(receiver)) = (sender.clone(), receiver) else {
        return respond_json(&mut stream, 404, "Not Found", r#"{"error":"unknown device"}"#).await;
    };

    let grant_id = uuid_like("grant");
    let nonce = uuid_like("nonce");
    let now = unix_now();
    let expires_at = now + 300;
    {
        let mut inner = inner.lock().unwrap();
        inner.send_authorizations.insert(
            grant_id.clone(),
            FakeSendAuthorization {
                nonce: nonce.clone(),
                sender_device_id: req.sender_device_id.clone(),
                receiver_device_id: req.receiver_device_id.clone(),
                consumed: false,
            },
        );
    }

    // Delivered synchronously, before this responds -- matching
    // the coordination service's own "push happens inside the request handler"
    // convention (see `routes/send.ts`'s own comment).
    push_send_authorization(
        &inner,
        &req.receiver_device_id,
        &grant_id,
        &nonce,
        &req.sender_device_id,
        expires_at,
    );

    let body = serde_json::json!({
        "grantId": grant_id,
        "nonce": nonce,
        "expiresAt": expires_at,
        "receiver": {
            "deviceId": req.receiver_device_id,
            "signingPublicKeyBase64": receiver.signing_public_key_b64,
            "substrateReachability": receiver_substrate,
        },
    })
    .to_string();
    respond_json(&mut stream, 200, "OK", &body).await
}

/// Serves `POST /send/authorization/:grantId/consume` for real -- the
/// atomic single-use guard `handle_offer`/`DaemonDeviceDirectory::
/// consume_grant` calls before ever recording an inbound offer. Same
/// identity-binding shape as the real Worker's `consumeSendAuthorization`:
/// grant id, nonce, sender, and receiver must all match a still-unconsumed
/// record, checked and flipped to consumed under the SAME lock acquisition
/// (no separate read-then-write), so two concurrent attempts for the same
/// grant can never both succeed.
async fn serve_send_authorization_consume(
    mut stream: TcpStream,
    head: &str,
    leftover: Vec<u8>,
    grant_id: String,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let body = read_body(&mut stream, head, leftover).await?;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        nonce: String,
        sender_device_id: String,
        receiver_device_id: String,
    }
    let Ok(req) = serde_json::from_slice::<Req>(&body) else {
        return respond_json(&mut stream, 400, "Bad Request", r#"{"error":"invalid body"}"#).await;
    };

    let sender = {
        let mut inner = inner.lock().unwrap();
        let consumable = inner.send_authorizations.get(&grant_id).is_some_and(|g| {
            !g.consumed
                && g.nonce == req.nonce
                && g.sender_device_id == req.sender_device_id
                && g.receiver_device_id == req.receiver_device_id
        }) && inner.devices.contains_key(&req.sender_device_id)
            && inner.devices.contains_key(&req.receiver_device_id);
        if consumable {
            inner.send_authorizations.get_mut(&grant_id).unwrap().consumed = true;
            let substrate = substrate_json(&inner, &req.sender_device_id);
            inner.devices.get(&req.sender_device_id).cloned().map(|device| (device, substrate))
        } else {
            None
        }
    };
    let Some((sender, sender_substrate)) = sender else {
        return respond_json(
            &mut stream,
            403,
            "Forbidden",
            r#"{"error":"send authorization is invalid, expired, or already used"}"#,
        )
        .await;
    };

    let body = serde_json::json!({
        "sender": {
            "deviceId": req.sender_device_id,
            "signingPublicKeyBase64": sender.signing_public_key_b64,
            "substrateReachability": sender_substrate,
        },
    })
    .to_string();
    respond_json(&mut stream, 200, "OK", &body).await
}

/// Pushes a `{type:"send_authorization",...}` frame to `receiver_device_id`'s
/// live subscription, if it has one -- a no-op wake otherwise, matching
/// the coordination service's own "content-blind, never stored" delivery
/// contract for this push.
fn push_send_authorization(
    inner: &Arc<Mutex<Inner>>,
    receiver_device_id: &str,
    grant_id: &str,
    nonce: &str,
    sender_device_id: &str,
    expires_at: i64,
) {
    let inner = inner.lock().unwrap();
    let Some(tx) = inner.subscribers.get(receiver_device_id) else { return };
    let Some(sender) = inner.devices.get(sender_device_id) else { return };
    let frame = serde_json::json!({
        "type": "send_authorization",
        "grantId": grant_id,
        "nonce": nonce,
        "from": sender_device_id,
        "senderSigningPublicKeyBase64": sender.signing_public_key_b64,
        "senderSubstrateReachability": substrate_json(&inner, sender_device_id),
        "expiresAt": expires_at,
    })
    .to_string();
    let _ = tx.send(frame);
}

/// A device's stored iroh substrate reachability as the Worker's send
/// material carries it (`{direct, relays}`), or `null` when the device has
/// not published one.
fn substrate_json(inner: &Inner, device_id: &str) -> serde_json::Value {
    match inner.substrate_reachability.get(device_id) {
        Some((direct, relays)) => serde_json::json!({ "direct": direct, "relays": relays }),
        None => serde_json::Value::Null,
    }
}

/// A short, sufficiently-unique id for this fake's own grant/nonce values --
/// not a real UUID library dependency, just enough entropy (a monotonic
/// process-wide counter) that two concurrently-issued grants in the same
/// test never collide. `label` distinguishes a grant id from a nonce in
/// test failure output.
fn uuid_like(label: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{label}-{n}-{}", unix_now())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn respond_json(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// Like `drain_body`, but returns the collected bytes instead of discarding
/// them -- several routes this fake answers need the request body itself.
async fn read_body(
    stream: &mut TcpStream,
    head: &str,
    already_read: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().to_string())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = already_read;
    let mut chunk = [0u8; 1024];
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length.min(body.len()));
    Ok(body)
}

/// Reads bytes until the end of the HTTP request head (`\r\n\r\n`). Returns the
/// head as a string plus any bytes read past it (the start of a POST body).
async fn read_http_head(stream: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            let leftover = buf[pos + 4..].to_vec();
            return Ok((head, leftover));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            let head = String::from_utf8_lossy(&buf).into_owned();
            return Ok((head, Vec::new()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn drain_body(
    stream: &mut TcpStream,
    head: &str,
    already_read: Vec<u8>,
) -> std::io::Result<()> {
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().to_string())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut remaining = content_length.saturating_sub(already_read.len());
    let mut chunk = [0u8; 1024];
    while remaining > 0 {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        remaining = remaining.saturating_sub(n);
    }
    Ok(())
}

async fn serve_netmap_subscription(
    mut stream: TcpStream,
    head: &str,
    target: &str,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let device_id = target
        .split_once("deviceId=")
        .map(|(_, rest)| rest.split('&').next().unwrap_or("").to_string())
        .unwrap_or_default();
    let key = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("sec-websocket-key").then(|| value.trim().to_string())
        })
        .unwrap_or_default();
    let accept = derive_accept_key(key.as_bytes());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    let mut ws = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    // Register and immediately send this device its current netmap.
    let initial = {
        let mut guard = inner.lock().unwrap();
        guard.subscribers.insert(device_id.clone(), tx);
        // A brand-new subscription starts with a fresh (empty) per-group
        // policy watermark -- mirrors a real coordination plane's per-
        // WebSocket `policyWatermarks` map starting empty for a new socket
        // (`durable-objects/netmap-device.ts`'s `WeakMap<WebSocket, ...>`),
        // so this device's very first frame on a (re)connect always carries
        // each shared group's policy chain from the beginning.
        //
        // Note what this does NOT mean: it is emphatically not "the device
        // has no retained base state for this group". The plane's watermark
        // is per CONNECTION; the daemon's cached `GroupPolicyState` is
        // persistent and connection-independent, and survives every
        // reconnect. So on an ordinary reconnect the daemon receives a
        // from-record-1 resend while still holding a fully-verified base at
        // some higher seq -- the exact combination `peer_orchestrator::
        // record_group_policy_states` has to recognize as a resend rather
        // than feed to `verify_group_policy_log_with_base` (which has zero
        // prefix tolerance) as if it were an incremental tail. An earlier
        // version of this comment asserted the opposite premise, which is
        // why no test in this suite caught that; `policy_reconnect_resend.rs`
        // now covers it directly.
        guard.policy_send_watermarks.remove(&device_id);
        netmap_frame_for(&mut guard, &device_id)
    };
    if ws.send(Message::Text(initial.into())).await.is_err() {
        inner.lock().unwrap().subscribers.remove(&device_id);
        return Ok(());
    }

    // Forward every pushed frame; also drain inbound (pings/close) so the
    // connection stays healthy. Ends when either side closes.
    use futures_util::StreamExt;
    loop {
        tokio::select! {
            frame = rx.recv() => match frame {
                Some(text) => {
                    if ws.send(Message::Text(text.into())).await.is_err() { break; }
                }
                None => break,
            },
            inbound = ws.next() => match inbound {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
        }
    }
    inner.lock().unwrap().subscribers.remove(&device_id);
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
