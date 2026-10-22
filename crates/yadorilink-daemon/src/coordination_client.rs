//! Unary coordination-plane calls the daemon makes outside the netmap
//! subscription: this device's substrate address report, and the
//! activate/cancel calls
//! `EnrollmentRecoveryService::reconcile_once` issues for a create/join left
//! over from a previous run. Each speaks the coordination plane over its
//! HTTP+JSON API, the same host the netmap WebSocket subscription connects to.
//!
//! Every call is best-effort: a failure is logged at debug and swallowed, so
//! a transient coordination-plane outage never takes down the caller's task.
//! The activate calls below return an
//! [`ActivateOutcome`] (rather than swallowing the result entirely) so
//! `EnrollmentRecoveryService::reconcile_once` knows whether it is safe to drop its
//! local marker, must mark the link orphaned, or should leave the marker for
//! the next sweep to retry. The cancel calls stay a bare success/failure
//! bool: `reconcile` treats a cancel as best-effort regardless of why it
//! failed (the coordination plane's own TTL sweep is the eventual backstop
//! either way), so there is no extra outcome for it to branch on.
//!
//! # Every call here takes a credential, not a token
//!
//! These functions used to take `access_token: &str` and call `bearer_auth`.
//! They now take a [`CoordinationAuth`], and the difference is not cosmetic:
//! the Coordination API is a DPoP resource server, so an authenticated request
//! needs a live access token **and** a proof signed by that token's key and
//! bound to this exact method and URL. A `&str` cannot produce the second, and
//! a token captured at daemon startup cannot produce the first either -- it
//! lives five minutes.
//!
//! The whole of that is behind [`SendAuthorized::send_authorized`], which is
//! the only place in this module that touches an `Authorization` header. It
//! reads the method and URL **off the built request** rather than from its
//! caller, so a proof can never be minted for a different call than the one
//! that is sent -- a DPoP proof whose `htm`/`htu` name the wrong endpoint is
//! refused by the server with a 401 that reads exactly like an expired token,
//! and the two are worth being structurally unable to confuse.

use yadorilink_fapi_client::CoordinationAuth;

/// Why an authenticated coordination call did not produce a response.
///
/// The arms are genuinely different facts and are kept apart rather than
/// flattened into a string. `Transport` and `CredentialServiceUnavailable`
/// are the planes being unreachable, which is transient and is what every
/// retry in this daemon exists for. `Unauthenticated` is this device being
/// unable to produce a credential at all -- the refresh was refused, the
/// registration was revoked, the credential store is unreadable -- which no
/// amount of retrying the *request* fixes.
#[derive(Debug)]
pub enum CoordinationCallError {
    /// This device could not mint a credential for the call. It was never sent.
    Unauthenticated(String),
    /// Minting the credential needed the authorization server (a refresh or
    /// its discovery), and it answered with a server error (5xx). Nothing
    /// was refused: the call was never sent, and the same credential may
    /// work once the server is back.
    CredentialServiceUnavailable(String),
    /// The call (or the refresh it needed) was sent and the transport failed.
    Transport(reqwest::Error),
}

impl From<yadorilink_fapi_client::Error> for CoordinationCallError {
    /// A transport failure or a 5xx from the authorization server is an
    /// outage; every other failure to mint a credential (a 4xx refusal such
    /// as `invalid_grant` included) is this device's credential not working.
    fn from(error: yadorilink_fapi_client::Error) -> Self {
        match error {
            yadorilink_fapi_client::Error::Http(transport) => {
                CoordinationCallError::Transport(transport)
            }
            other if other.status().is_some_and(|status| status >= 500) => {
                CoordinationCallError::CredentialServiceUnavailable(other.to_string())
            }
            other => CoordinationCallError::Unauthenticated(other.to_string()),
        }
    }
}

impl std::fmt::Display for CoordinationCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoordinationCallError::Unauthenticated(detail)
            | CoordinationCallError::CredentialServiceUnavailable(detail) => write!(f, "{detail}"),
            CoordinationCallError::Transport(error) => write!(f, "{error}"),
        }
    }
}

impl CoordinationCallError {
    /// The diagnosis category for this failure.
    ///
    /// A credential this device could not mint is `Unauthorized`, the same
    /// category a 401 from the plane produces -- because it is the same
    /// situation seen one step earlier, and an operator reading a diagnosis
    /// needs "this device's credential is the problem", not "the network".
    fn category(&self) -> RemoteEvidenceErrorCategory {
        match self {
            CoordinationCallError::Unauthenticated(_) => RemoteEvidenceErrorCategory::Unauthorized,
            CoordinationCallError::CredentialServiceUnavailable(_) => {
                RemoteEvidenceErrorCategory::ServerError
            }
            CoordinationCallError::Transport(error) => categorize_transport_error(error),
        }
    }
}

/// Send a request authenticated as this device.
///
/// Replaces `.bearer_auth(token).send()`. The credential is minted from the
/// built request's own method and URL, which is why this is a send rather than
/// a builder step: a DPoP proof does not exist until the request it binds to
/// does.
pub(crate) trait SendAuthorized {
    async fn send_authorized(
        self,
        auth: &CoordinationAuth,
    ) -> Result<reqwest::Response, CoordinationCallError>;
}

impl SendAuthorized for reqwest::RequestBuilder {
    async fn send_authorized(
        self,
        auth: &CoordinationAuth,
    ) -> Result<reqwest::Response, CoordinationCallError> {
        // `CoordinationAuth::execute` is now the one place in this crate --
        // and the one place in the fapi-client crate's public API -- that
        // reads `htm`/`htu` off a built request and sends it. This used to be
        // reimplemented here with its own `build_split`, its own header
        // insertion and its own error mapping; that copy is deleted rather
        // than kept in sync with the canonical one.
        auth.execute(self).await.map_err(CoordinationCallError::from)
    }
}

/// Where this device's reconciliation substrate can be reached, as ONE
/// snapshot.
///
/// Deliberately not the netmap's legacy `endpoints` list. That list is the
/// peer-session transport's dial targets; the substrate is a separate iroh
/// endpoint on a separate socket with a different ALPN, and a dial landing on
/// the wrong one completes at the QUIC layer and is then refused for an
/// unknown ALPN -- a hard failure rather than a path worth retrying. Measured
/// every way round, one list cannot serve both.
///
/// Carries no identity. The remote endpoint id IS the peer's already-pinned
/// device signing key, so a key in here would be a second, unpinned claim that
/// could disagree with the pinned one.
///
/// Both halves travel together because they describe one address generation.
/// Published separately they could describe two, and a peer would dial a
/// direct address from one generation with a relay from another.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubstrateReachability {
    pub direct: Vec<std::net::SocketAddr>,
    pub relays: Vec<String>,
}

/// A Track Send rendezvous grant from `POST /send/authorization` --
/// the coordination service's `routes/send.ts`, backed by the `send_authorizations`
/// table (see that migration's own doc comment for what this primitive is
/// and, deliberately, is not: never an extension of folder-group/ACL
/// membership). Names the exact sender+receiver pair it authorizes and
/// carries ONLY the receiver's own Track Send connect material -- its
/// signing key (= iroh endpoint id) and where its iroh endpoint answers --
/// never any other same-account device's key or address.
#[derive(Debug, Clone)]
pub struct SendAuthorizationGrant {
    pub grant_id: String,
    /// Presented alongside `grant_id` at consume time, never alone -- see
    /// `consume_send_authorization`'s own doc comment for why a leaked or
    /// logged grant id must not be independently consumable.
    pub nonce: String,
    pub expires_at_unix: i64,
    pub receiver_device_id: String,
    pub receiver_signing_key: [u8; 32],
    /// Empty when the receiver's iroh endpoint has not published an
    /// address yet; the dial then relies on what the endpoint's own lookup
    /// knows.
    pub receiver_reachability: SubstrateReachability,
}

/// Where a device's iroh endpoint answers, in the wire shape the
/// coordination plane uses for it (`{direct, relays}`). Unparseable direct
/// addresses are dropped.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireSubstrateReachability {
    #[serde(default)]
    direct: Vec<String>,
    #[serde(default)]
    relays: Vec<String>,
}

impl From<WireSubstrateReachability> for SubstrateReachability {
    fn from(wire: WireSubstrateReachability) -> Self {
        Self {
            direct: wire.direct.iter().filter_map(|a| a.parse().ok()).collect(),
            relays: wire.relays,
        }
    }
}

/// The result of an `activate_create`/`activate_join` call, distinguished by
/// what the coordination plane's response actually communicates --
/// `EnrollmentRecoveryService::reconcile_once` branches on this instead of a bare bool
/// since "already active" and "permanently gone" call for different local
/// follow-up (see its own doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivateOutcome {
    /// The Pending row was flipped to Active by this call.
    Success,
    /// The row was already Active -- activate is idempotent by
    /// `operation_id`, so a retried call (e.g. this device's own earlier
    /// call already succeeded before a crash) lands here rather than
    /// erroring.
    AlreadyActive,
    /// Cross-account invite acceptance only: the coordination plane
    /// accepted this device's half, but the invite was minted requiring the
    /// group owner's approval, so the membership is parked awaiting their
    /// decision and grants nothing yet.
    ///
    /// A 2xx like `Success`, and deliberately NOT folded into it: the
    /// security property does not depend on the caller believing this (with
    /// no policy-log grant the device authorizes nothing whatever it
    /// concludes), but the HONESTY of what the caller then tells the user
    /// does. Folding it into `Success` is what made the CLI report "Joined
    /// folder group ..." for a folder that will never sync until someone
    /// else acts.
    AwaitingApproval,
    /// The coordination-side row this operation id names is permanently
    /// gone (never prepared, or already cancelled/swept) -- a 404 from the
    /// coordination plane. There is nothing left to activate.
    Deleted,
    /// Anything that isn't a clear terminal answer: a network error, a
    /// timeout, or a non-404 rejection. Worth retrying; not a verdict about
    /// the row itself.
    TransientFailure,
}

/// The classified result of a coordination-plane enrollment PREPARE call
/// (create or join) -- distinct from a plain success/failure `Result` so a
/// caller can tell "definitely never committed" (safe to discard the local
/// journal row) apart from "may have committed, response merely lost" (must
/// never discard, must resend under the same operation_id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentPrepareOutcome {
    Prepared {
        group_id: String,
    },
    /// 4xx (other than 409). The remote prepare was NOT committed.
    DefinitelyRejected(String),
    /// The coordination plane named why the invite cannot be redeemed (its
    /// `code` field). The remote prepare was NOT committed.
    InviteRefused {
        reason: crate::application::model::InviteRefusal,
        detail: String,
    },
    /// 409 -- this operation_id already names a differently-shaped request.
    Conflict(String),
    /// Transport failure, 5xx, or an unparseable 2xx create response.
    Ambiguous(String),
}

/// The classified result of a coordination-plane enrollment CANCEL call --
/// mirrors [`EnrollmentPrepareOutcome`]. Unlike prepare, the Worker's own
/// cancel routes treat "already gone"/"already active" as an ordinary 2xx
/// no-op (see the coordination service's own idempotent-cancel contract), so a
/// 404 here is NOT a routine "already cancelled" -- it means this
/// operation_id's identity itself doesn't match what the Worker expects,
/// same as a 409.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentCancelOutcome {
    /// 2xx -- includes an already-deleted/already-swept/already-active
    /// no-op.
    Confirmed,
    /// 409 or 404 -- a request-identity mismatch, not a routine absence.
    Conflict(String),
    /// Transport failure or 5xx.
    Ambiguous(String),
}

#[derive(Debug, Clone, Copy)]
pub struct RoleLossCommitRequest<'a> {
    pub group_id: &'a str,
    pub source_device_id: &'a str,
    pub target_device_id: &'a str,
    pub lease_id: Option<&'a str>,
    pub action: &'a str,
    pub operation_id: &'a str,
}

/// Why `GET /devices` gave no listing, in the two kinds the NAS management
/// authorizer must tell apart.
///
/// `Unreachable` is the plane not answering: a transport failure, a timeout,
/// a 5xx, or a body cut off in transit. `Refused` is the plane (or this
/// device's own credential) answering "no" or answering something that is
/// not a listing this build can trust: a 401/403 or any other non-5xx
/// error status, a credential this device cannot mint, or a body that does
/// not parse -- one without `signedOut` included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceListingError {
    Unreachable(String),
    Refused(String),
}

impl From<CoordinationCallError> for DeviceListingError {
    fn from(error: CoordinationCallError) -> Self {
        match error {
            CoordinationCallError::Transport(error) => {
                DeviceListingError::Unreachable(error.to_string())
            }
            CoordinationCallError::CredentialServiceUnavailable(detail) => {
                DeviceListingError::Unreachable(detail)
            }
            CoordinationCallError::Unauthenticated(detail) => DeviceListingError::Refused(detail),
        }
    }
}

impl std::fmt::Display for DeviceListingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceListingError::Unreachable(detail) => write!(f, "unreachable: {detail}"),
            DeviceListingError::Refused(detail) => write!(f, "refused: {detail}"),
        }
    }
}

pub use imp::{
    activate_create, activate_invite_accept, activate_join, cancel_create,
    cancel_create_classified, cancel_invite_accept_classified, cancel_join, cancel_join_classified,
    commit_handoff_role_loss, compensate_handoff_role_loss, consume_send_authorization,
    fetch_edge_state, find_account_device, find_handoff_lease, list_account_device_keys,
    prepare_create, prepare_invite_accept, prepare_join, query_enrollment_operation,
    query_membership_operation, query_membership_operation_categorized, query_role_loss_operation,
    release_handoff_lease, report_endpoint, request_authorization_checkpoint,
    request_handoff_lease, request_send_authorization, resolve_edge, set_storage_mode,
};
// `MintedInvite` is `pub(crate)` (defined in `application::model`, a
// crate-internal module) -- unlike every other re-export above, whose
// return types are genuinely part of this module's own public surface, so
// `mint_invite` can only ever be re-exported at `pub(crate)`, not widened
// to `pub` alongside its siblings.
pub(crate) use imp::mint_invite;

/// Why a remote-evidence lookup could not be answered -- see
/// `RemoteEvidence`'s own doc comment for the
/// contract this backs: NONE of these categories may ever be treated as
/// "the operation doesn't exist" (only a genuine HTTP 404 means that).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteEvidenceErrorCategory {
    /// The request never reached the coordination plane at all (DNS,
    /// connection refused, TLS failure, ...).
    Network,
    /// The request timed out waiting for a response.
    Timeout,
    /// The coordination plane responded, but with a server-side failure
    /// (5xx) or an unexpected non-success status this lookup has no more
    /// specific category for.
    ServerError,
    /// The coordination plane rejected the request's credentials (401/403)
    /// -- distinct from every other category because it likely means this
    /// device's own access token needs refreshing, not that the operation
    /// itself is unreachable.
    Unauthorized,
    /// A 2xx response whose body could not be parsed as the expected
    /// shape.
    MalformedResponse,
    /// The coordination plane responded successfully but the response
    /// shape names something this build does not recognize (e.g. a
    /// `status`/`kind` string added by a newer Worker deploy) -- distinct
    /// from `MalformedResponse` (which means the JSON itself didn't even
    /// parse) so a caller can tell "the plane is ahead of this build" apart
    /// from "the plane sent garbage".
    Unsupported,
    /// The operation is recorded and approved but not finished (a device
    /// removal whose credentials may already be stopped): neither committed
    /// nor rejected. The outcome is unresolved; retry with the SAME operation
    /// id to complete it.
    Pending,
}

/// A remote-evidence lookup's failure: the category above, plus a
/// human-readable detail for logs. Never constructed for a 404 -- that is
/// `RemoteEvidence::RecordNotFound`, not an
/// error.
#[derive(Debug, Clone)]
pub struct RemoteQueryError {
    pub category: RemoteEvidenceErrorCategory,
    pub message: String,
}

impl std::fmt::Display for RemoteQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn categorize_transport_error(error: &reqwest::Error) -> RemoteEvidenceErrorCategory {
    if error.is_timeout() {
        RemoteEvidenceErrorCategory::Timeout
    } else {
        RemoteEvidenceErrorCategory::Network
    }
}

/// Bounded so a recovery-evidence lookup can genuinely produce
/// [`RemoteEvidenceErrorCategory::Timeout`] rather than hang indefinitely
/// (this file's other calls use a plain, timeout-less `reqwest::Client::new()`
/// -- fine for a best-effort background call, wrong for an operator-facing
/// diagnosis command that must return in bounded time either way).
pub const EVIDENCE_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub fn evidence_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(EVIDENCE_LOOKUP_TIMEOUT)
        .build()
        .expect("building the recovery-evidence HTTP client")
}

fn categorize_error_status(status: reqwest::StatusCode) -> RemoteEvidenceErrorCategory {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        RemoteEvidenceErrorCategory::Unauthorized
    } else {
        // Every other non-success, non-404 status -- including a genuine
        // 5xx, but also any other unexpected code this lookup has no more
        // specific category for. Never `RecordNotFound`: only a literal
        // 404 means that.
        RemoteEvidenceErrorCategory::ServerError
    }
}

/// A successfully-issued full-replica-handoff lease grant — the target-side
/// half of the round trip described on `HandoffLease` (`yadorilink_sync_
/// core::index`) and on the `RequestHandoffLeaseRequest` proto message.
///
/// `expires_at_unix` is the coordination Worker's OWN absolute expiry,
/// stamped against the Worker's clock purely for the Worker's own
/// bookkeeping and TTL sweep -- callers must never store or compare it
/// against a LOCAL clock reading on this device (that cross-clock comparison
/// is exactly the bug `ttl_seconds` exists to avoid: under clock skew it
/// could read a still-live lease as already expired, or vice versa). Any
/// caller that needs to pin something locally (this device's own retention
/// sweep) must derive its own deadline from `ttl_seconds` plus this device's
/// own `now_unix()` -- see `SyncState::record_handoff_lease_atomic`.
#[derive(Debug, Clone)]
pub struct HandoffLeaseGrant {
    pub lease_id: String,
    pub expires_at_unix: i64,
    /// The lease's TTL DURATION, as configured on the coordination Worker --
    /// clock-independent, unlike `expires_at_unix`. This is what a caller
    /// combines with its OWN clock reading to compute a local pin deadline.
    pub ttl_seconds: i64,
}

/// The result of a successful role-loss commit — this is entirely the
/// coordination-plane's own view: it carries no root-digest/content field,
/// since the Worker only ever adjudicates membership/eligibility, never file
/// paths, block hashes, or version content (see `commit_handoff_role_loss`'s
/// doc comment). The `HandoffResult` proto message adds `root_digest` on top
/// of this shape at the call site, populated entirely from the caller's own
/// already-known local digest — never sent to or read back from the Worker.
/// Kept as a plain struct here (rather than constructing the proto type
/// directly) so this module stays free of any dependency on
/// `yadorilink-ipc-proto`, matching every other function in this file.
pub(crate) use crate::application::model::membership::{
    HandoffCommitResult, MembershipOperationLookup, MembershipOperationRecord,
    MembershipRemoteRequest, MembershipRemoteRequestGroup, MembershipRemoteResult,
    MembershipRemoteStatus, RoleLossCommitOutcome, RoleLossCompensationOutcome,
};
pub(crate) use crate::application::model::MintedInvite;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentRemoteStatus {
    Preparing,
    Prepared,
    Active,
    Cancelled,
}

/// The exact canonical request the coordination plane fingerprinted
/// `operation_id` against, mirroring `MembershipRemoteRequest`'s own
/// identity-comparison role. `Create`'s `storage_mode` is not actually a
/// wire field (a CREATE's creator edge is always `"eager"` by construction
/// -- see `prepareCreateFolderGroupRow`'s own doc comment on the Worker
/// side) -- it is filled in as that fixed constant here so both variants
/// present the same shape for identity comparison against a local
/// enrollment journal row, which always has a `storage_mode` regardless of
/// `kind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentRemoteRequest {
    Create { group_name: String, device_id: String, storage_mode: String },
    Join { group_id: String, device_id: String, storage_mode: String },
}

/// An enrollment operation record read back from the coordination plane,
/// scoped by this device's own account (the Worker's
/// `/devices/enrollment-operations/:operationId` route is itself
/// `userId`-scoped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentOperationRecord {
    pub status: EnrollmentRemoteStatus,
    pub request_fingerprint: String,
    pub request: EnrollmentRemoteRequest,
    /// The `groupId` from the ledger row's own `result` payload, when
    /// present (set once `prepared`/`active`). `None` while still
    /// `preparing`, or if the Worker response omitted it.
    pub result_group_id: Option<String>,
}

/// A role-loss-commit receipt read back from the coordination plane's
/// `role_loss_operation_receipts` table -- its mere
/// existence IS the evidence: a receipt means the underlying acl mutation
/// committed, full stop, there is no separate `status` field the way
/// enrollment/membership have one. See
/// the coordination service's `commitRoleLossGuarded` for
/// why this receipt is reliable (a `changes()`-chained, replay-idempotent
/// UPSERT) rather than a best-effort side record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleLossOperationRecord {
    pub group_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub lease_id: Option<String>,
    /// `"demote"` or `"revoke"` -- the Worker's own wire action string (see
    /// `commitHandoffRoleLoss`'s own doc comment for why the daemon's own
    /// `Unlink` role-loss action is sent to the Worker as `"demote"` too).
    pub action: String,
    /// Never `None` once decode succeeds -- `query_role_loss_operation`
    /// itself rejects a NULL generation as `Unsupported` before this type is
    /// ever constructed (generation 8's column is `NOT NULL`), so this field
    /// is non-optional rather than a redundant always-`Some` wrapper.
    pub membership_generation: i64,
    pub committed_at_unix: i64,
}

mod imp {
    use base64::Engine;
    use serde::{Deserialize, Serialize};

    use super::{
        categorize_error_status, evidence_http_client, ActivateOutcome, CoordinationAuth,
        CoordinationCallError, DeviceListingError, EnrollmentOperationRecord,
        EnrollmentRemoteRequest, EnrollmentRemoteStatus, HandoffCommitResult, HandoffLeaseGrant,
        MembershipOperationLookup, MembershipOperationRecord, MembershipRemoteRequest,
        MembershipRemoteRequestGroup, MembershipRemoteResult, MembershipRemoteStatus,
        RemoteEvidenceErrorCategory, RemoteQueryError, RoleLossCommitOutcome,
        RoleLossCommitRequest, RoleLossCompensationOutcome, RoleLossOperationRecord,
        SendAuthorizationGrant, SendAuthorized, SubstrateReachability,
    };

    /// `skip_serializing_if` predicate for an optional boolean request
    /// field whose `false` means exactly what omitting it means.
    fn is_false(value: &bool) -> bool {
        !*value
    }

    /// The machine-readable `code` of a coordination error body, when it has one.
    fn coord_error_code(body_text: &str) -> Option<String> {
        let value: serde_json::Value = serde_json::from_str(body_text).ok()?;
        value.get("code")?.as_str().map(str::to_string)
    }

    /// Extracts the coordination plane's own `{"error": "..."}` message
    /// from a rejected response body, when the body actually has that
    /// shape. Used by `prepare_invite_accept` to give its `DefinitelyRejected`
    /// detail a clean, directly user-facing message (e.g. "invite is
    /// invalid or already used") instead of a raw `HTTP 400:
    /// {"error":"..."}` dump -- that raw form is what every enrollment
    /// error detail in this file falls back to, and still does here too
    /// (see the caller) whenever the body does not parse as this exact
    /// shape.
    fn coord_error_message(body_text: &str) -> Option<String> {
        let value: serde_json::Value = serde_json::from_str(body_text).ok()?;
        value.get("error")?.as_str().map(str::to_string)
    }

    /// Posts `body` and reports success/failure back to the caller instead of
    /// only logging it -- `EnrollmentRecoveryService::reconcile_once` needs to
    /// know whether it may drop its local marker.
    /// Bounded for the same reason [`EVIDENCE_LOOKUP_TIMEOUT`] exists, and now
    /// for a sharper one: the endpoint report is retried until it lands, and a
    /// retry loop whose attempt never returns is not a retry loop. A refused
    /// connection or a 500 reaches the backoff; a TCP connection that is
    /// accepted and then answered by nobody would park `send()` forever, and
    /// this device's reachability would never be republished.
    const ENDPOINT_REPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    async fn post_no_content_ok<B: Serialize>(
        url: String,
        auth: &CoordinationAuth,
        body: &B,
        what: &str,
    ) -> bool {
        let result = reqwest::Client::new().post(&url).json(body).send_authorized(auth).await;
        match result {
            Ok(resp) if resp.status().is_success() => true,
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), what, "coordination call rejected");
                false
            }
            Err(e) => {
                tracing::debug!(error = %e, what, "coordination call failed");
                false
            }
        }
    }

    /// The response body an activate call's 2xx response carries: which
    /// non-error outcome (`ActivateCreateResult`/`ActivateJoinResult`/
    /// `ActivateInviteAcceptResult` on the coordination service side) it
    /// landed on. A response that fails to parse (an older
    /// the coordination service build that still replies with an empty 204, or
    /// any other unexpected body) is treated as a plain `Success` -- the
    /// status code alone already confirms the row is active, and "already
    /// active" vs. "freshly activated" makes no difference to any caller of
    /// `activate_create`/`activate_join`.
    #[derive(Deserialize)]
    struct ActivateResultBody {
        result: String,
    }

    /// The coordination plane's own result strings, matched POSITIVELY --
    /// an unrecognized future outcome falls through to plain `Success`
    /// (the status code already confirmed the mutation landed), never into
    /// one of the specific branches.
    const ACTIVATE_RESULT_ALREADY_ACTIVE: &str = "already_active";
    const ACTIVATE_RESULT_AWAITING_APPROVAL: &str = "awaiting_approval";
    const ACTIVATE_RESULT_ALREADY_AWAITING_APPROVAL: &str = "already_awaiting_approval";

    /// Shared by `activate_create`/`activate_join`/`activate_invite_accept`:
    /// every one of those coordination service routes is 404 on a
    /// permanently-gone row and otherwise 2xx with a `{"result": ...}` body
    /// -- see the coordination service's activate
    /// handlers.
    async fn post_activate<B: Serialize>(
        url: String,
        auth: &CoordinationAuth,
        body: &B,
        what: &str,
    ) -> ActivateOutcome {
        let result = reqwest::Client::new().post(&url).json(body).send_authorized(auth).await;
        match result {
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                tracing::debug!(what, "coordination call: operation not found (row gone)");
                ActivateOutcome::Deleted
            }
            Ok(resp) if resp.status().is_success() => match resp.json::<ActivateResultBody>().await
            {
                Ok(body) if body.result == ACTIVATE_RESULT_ALREADY_ACTIVE => {
                    ActivateOutcome::AlreadyActive
                }
                // Both awaiting-approval outcomes are the same answer to
                // the only question a caller of this has: is this device a
                // member yet? (No.) Which call parked it -- this one, or an
                // earlier attempt -- changes nothing about what happens
                // next or what the user is told.
                Ok(body)
                    if body.result == ACTIVATE_RESULT_AWAITING_APPROVAL
                        || body.result == ACTIVATE_RESULT_ALREADY_AWAITING_APPROVAL =>
                {
                    ActivateOutcome::AwaitingApproval
                }
                _ => ActivateOutcome::Success,
            },
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), what, "coordination call rejected");
                ActivateOutcome::TransientFailure
            }
            Err(e) => {
                tracing::debug!(error = %e, what, "coordination call failed");
                ActivateOutcome::TransientFailure
            }
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationIdBody<'a> {
        operation_id: &'a str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct JoinOperationBody<'a> {
        operation_id: &'a str,
        device_id: &'a str,
    }

    /// Confirms a previously-prepared CREATE enrollment (the coordination service's
    /// `POST /shares/groups/:groupId/activate`), turning a Pending group +
    /// its creator's Pending eager membership into the real thing. Called
    /// both by the CLI's own create flow (immediately, via its own HTTP
    /// client) and by `EnrollmentRecoveryService::reconcile_once` on daemon startup, for
    /// a marker left over from a killed CLI process.
    pub async fn activate_create(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        operation_id: &str,
    ) -> ActivateOutcome {
        post_activate(
            format!("{addr}/shares/groups/{group_id}/activate"),
            auth,
            &OperationIdBody { operation_id },
            "create activate",
        )
        .await
    }

    /// The compensating call for a CREATE enrollment that will never be
    /// activated (`POST /shares/groups/:groupId/cancel`) -- a no-op on the
    /// server if the group was already activated or is already gone.
    pub async fn cancel_create(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        operation_id: &str,
    ) -> bool {
        post_no_content_ok(
            format!("{addr}/shares/groups/{group_id}/cancel"),
            auth,
            &OperationIdBody { operation_id },
            "create cancel",
        )
        .await
    }

    /// Confirms a previously-prepared JOIN enrollment (`POST
    /// /shares/groups/:groupId/join/activate`), turning a Pending membership
    /// into the real thing.
    pub async fn activate_join(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> ActivateOutcome {
        post_activate(
            format!("{addr}/shares/groups/{group_id}/join/activate"),
            auth,
            &JoinOperationBody { operation_id, device_id },
            "join activate",
        )
        .await
    }

    /// The compensating call for a JOIN enrollment that will never be
    /// activated (`POST /shares/groups/:groupId/join/cancel`) -- deletes
    /// only the membership, never the group; a no-op on the server if it
    /// was already activated or is already gone.
    pub async fn cancel_join(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> bool {
        post_no_content_ok(
            format!("{addr}/shares/groups/{group_id}/join/cancel"),
            auth,
            &JoinOperationBody { operation_id, device_id },
            "join cancel",
        )
        .await
    }

    /// Sends the create-prepare request and classifies the response -- see
    /// [`super::EnrollmentPrepareOutcome`].
    pub async fn prepare_create(
        addr: &str,
        auth: &CoordinationAuth,
        operation_id: &str,
        name: &str,
        device_id: &str,
        storage_mode: &str,
    ) -> super::EnrollmentPrepareOutcome {
        use super::EnrollmentPrepareOutcome;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            operation_id: &'a str,
            name: &'a str,
            creating_device_id: &'a str,
            storage_mode: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            group_id: String,
        }

        let response = match reqwest::Client::new()
            .post(format!("{addr}/shares/groups/prepare"))
            .json(&Body { operation_id, name, creating_device_id: device_id, storage_mode })
            .send_authorized(auth)
            .await
        {
            Ok(response) => response,
            Err(error) => return EnrollmentPrepareOutcome::Ambiguous(error.to_string()),
        };
        let status = response.status();
        if status == reqwest::StatusCode::CONFLICT {
            return EnrollmentPrepareOutcome::Conflict(response.text().await.unwrap_or_default());
        }
        if status.is_client_error() {
            return EnrollmentPrepareOutcome::DefinitelyRejected(format!(
                "create prepare returned HTTP {status}: {}",
                response.text().await.unwrap_or_default()
            ));
        }
        if !status.is_success() {
            return EnrollmentPrepareOutcome::Ambiguous(format!(
                "create prepare returned HTTP {status}: {}",
                response.text().await.unwrap_or_default()
            ));
        }
        match response.json::<Response>().await {
            Ok(body) if !body.group_id.is_empty() => {
                EnrollmentPrepareOutcome::Prepared { group_id: body.group_id }
            }
            Ok(_) => EnrollmentPrepareOutcome::Ambiguous(
                "create prepare returned an empty group_id".to_string(),
            ),
            Err(error) => EnrollmentPrepareOutcome::Ambiguous(format!(
                "create prepare may have committed but its response was unparseable: {error}"
            )),
        }
    }

    /// Sends the join-prepare request and classifies the response. Unlike
    /// create, the group id is already known (it names the group being
    /// joined), so a bare 2xx is enough to confirm `Prepared`.
    pub async fn prepare_join(
        addr: &str,
        auth: &CoordinationAuth,
        operation_id: &str,
        group_id: &str,
        device_id: &str,
        storage_mode: &str,
    ) -> super::EnrollmentPrepareOutcome {
        use super::EnrollmentPrepareOutcome;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            operation_id: &'a str,
            device_id: &'a str,
            storage_mode: &'a str,
        }

        let response = match reqwest::Client::new()
            .post(format!("{addr}/shares/groups/{group_id}/join/prepare"))
            .json(&Body { operation_id, device_id, storage_mode })
            .send_authorized(auth)
            .await
        {
            Ok(response) => response,
            Err(error) => return EnrollmentPrepareOutcome::Ambiguous(error.to_string()),
        };
        let status = response.status();
        if status.is_success() {
            return EnrollmentPrepareOutcome::Prepared { group_id: group_id.to_string() };
        }
        let detail = format!(
            "join prepare returned HTTP {status}: {}",
            response.text().await.unwrap_or_default()
        );
        if status == reqwest::StatusCode::CONFLICT {
            EnrollmentPrepareOutcome::Conflict(detail)
        } else if status.is_client_error() {
            EnrollmentPrepareOutcome::DefinitelyRejected(detail)
        } else {
            EnrollmentPrepareOutcome::Ambiguous(detail)
        }
    }

    async fn classify_cancel_response(
        response: Result<reqwest::Response, CoordinationCallError>,
    ) -> super::EnrollmentCancelOutcome {
        use super::EnrollmentCancelOutcome;

        let response = match response {
            Ok(response) => response,
            Err(error) => return EnrollmentCancelOutcome::Ambiguous(error.to_string()),
        };
        let status = response.status();
        if status.is_success() {
            return EnrollmentCancelOutcome::Confirmed;
        }
        let detail =
            format!("cancel returned HTTP {status}: {}", response.text().await.unwrap_or_default());
        // A 404 here is NOT a routine "already gone" -- the Worker's own
        // cancel routes already fold that into an ordinary 2xx no-op, so a
        // 404 or 409 means this operation_id's identity itself doesn't
        // match.
        if status == reqwest::StatusCode::CONFLICT || status == reqwest::StatusCode::NOT_FOUND {
            EnrollmentCancelOutcome::Conflict(detail)
        } else {
            EnrollmentCancelOutcome::Ambiguous(detail)
        }
    }

    /// Sends the create-cancel request and classifies the response -- see
    /// [`super::EnrollmentCancelOutcome`]. Distinct from the plain bool
    /// [`cancel_create`] above: `EnrollmentService`'s own compensation
    /// sequence needs to tell a confirmed identity mismatch apart from a
    /// merely-ambiguous transport failure, which a bare bool cannot.
    pub async fn cancel_create_classified(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        operation_id: &str,
    ) -> super::EnrollmentCancelOutcome {
        classify_cancel_response(
            reqwest::Client::new()
                .post(format!("{addr}/shares/groups/{group_id}/cancel"))
                .json(&OperationIdBody { operation_id })
                .send_authorized(auth)
                .await,
        )
        .await
    }

    /// Sends the join-cancel request and classifies the response -- see
    /// [`cancel_create_classified`]'s own doc comment.
    pub async fn cancel_join_classified(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> super::EnrollmentCancelOutcome {
        classify_cancel_response(
            reqwest::Client::new()
                .post(format!("{addr}/shares/groups/{group_id}/join/cancel"))
                .json(&JoinOperationBody { operation_id, device_id })
                .send_authorized(auth)
                .await,
        )
        .await
    }

    /// Sends the cross-account invite-accept prepare request and classifies
    /// the response -- see [`prepare_create`]'s own doc comment for why:
    /// unlike join, the group id is not known ahead of time (only the
    /// invite code names it), so a successful response's `groupId` is what
    /// the caller learns the group actually is.
    pub async fn prepare_invite_accept(
        addr: &str,
        auth: &CoordinationAuth,
        operation_id: &str,
        code: &str,
        device_id: &str,
        storage_mode: &str,
    ) -> super::EnrollmentPrepareOutcome {
        use super::EnrollmentPrepareOutcome;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            operation_id: &'a str,
            code: &'a str,
            device_id: &'a str,
            storage_mode: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            group_id: String,
        }

        let response = match reqwest::Client::new()
            .post(format!("{addr}/shares/invites/accept/prepare"))
            .json(&Body { operation_id, code, device_id, storage_mode })
            .send_authorized(auth)
            .await
        {
            Ok(response) => response,
            Err(error) => return EnrollmentPrepareOutcome::Ambiguous(error.to_string()),
        };
        let status = response.status();
        if status == reqwest::StatusCode::CONFLICT {
            return EnrollmentPrepareOutcome::Conflict(response.text().await.unwrap_or_default());
        }
        if status.is_client_error() {
            let body_text = response.text().await.unwrap_or_default();
            // Prefer the coordination plane's own clean `error` message
            // (e.g. "invite is invalid or already used") over a raw
            // HTTP-status-plus-JSON-body dump -- this is the detail an
            // expired/already-used/cancelled invite surfaces all the way
            // up to `yadorilink share accept`'s own error output, so it
            // should read as a sentence, not a debug trace.
            let detail = coord_error_message(&body_text).unwrap_or_else(|| {
                format!("invite accept prepare returned HTTP {status}: {body_text}")
            });
            return match coord_error_code(&body_text).as_deref() {
                Some("invite_expired") => EnrollmentPrepareOutcome::InviteRefused {
                    reason: crate::application::model::InviteRefusal::Expired,
                    detail,
                },
                Some("invite_already_used") => EnrollmentPrepareOutcome::InviteRefused {
                    reason: crate::application::model::InviteRefusal::AlreadyUsed,
                    detail,
                },
                _ => EnrollmentPrepareOutcome::DefinitelyRejected(detail),
            };
        }
        if !status.is_success() {
            return EnrollmentPrepareOutcome::Ambiguous(format!(
                "invite accept prepare returned HTTP {status}: {}",
                response.text().await.unwrap_or_default()
            ));
        }
        match response.json::<Response>().await {
            Ok(body) if !body.group_id.is_empty() => {
                EnrollmentPrepareOutcome::Prepared { group_id: body.group_id }
            }
            Ok(_) => EnrollmentPrepareOutcome::Ambiguous(
                "invite accept prepare returned an empty group_id".to_string(),
            ),
            Err(error) => EnrollmentPrepareOutcome::Ambiguous(format!(
                "invite accept prepare may have committed but its response was unparseable: \
                 {error}"
            )),
        }
    }

    /// Confirms a previously-prepared cross-account invite acceptance
    /// (`POST /shares/groups/:groupId/invites/accept/activate`), turning a
    /// Pending membership into the real thing. No code in the body -- the
    /// coordination plane re-derives the invite (and its role) from what
    /// this (deviceId, operationId) pair already redeemed at prepare time.
    pub async fn activate_invite_accept(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> ActivateOutcome {
        post_activate(
            format!("{addr}/shares/groups/{group_id}/invites/accept/activate"),
            auth,
            &JoinOperationBody { operation_id, device_id },
            "invite accept activate",
        )
        .await
    }

    /// The compensating call for an invite acceptance that will never be
    /// activated (`POST /shares/groups/:groupId/invites/accept/cancel`) --
    /// deletes only the still-Pending membership; does NOT return the
    /// invite itself to unused (see the coordination plane's own doc
    /// comment on that route).
    pub async fn cancel_invite_accept_classified(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> super::EnrollmentCancelOutcome {
        classify_cancel_response(
            reqwest::Client::new()
                .post(format!("{addr}/shares/groups/{group_id}/invites/accept/cancel"))
                .json(&JoinOperationBody { operation_id, device_id })
                .send_authorized(auth)
                .await,
        )
        .await
    }

    /// Mints a one-use, expiring, device-scoped cross-account invite for
    /// `group_id` (`POST /shares/groups/:groupId/invites`). Owner-only on
    /// the coordination plane's side; `Err` carries the rejection detail
    /// verbatim (e.g. "not the owner", "invalid role") -- there is no
    /// crash-safety story to classify here (a single stateless request, no
    /// local state to reconcile), so a plain `Result` is enough, unlike the
    /// enrollment prepare/activate/cancel calls above.
    pub(crate) async fn mint_invite(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        minting_device_id: &str,
        role: Option<&str>,
        ttl_secs: Option<u64>,
        requires_approval: bool,
    ) -> Result<super::MintedInvite, String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            minting_device_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            role: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            ttl_secs: Option<u64>,
            /// Omitted entirely when false, the way `role`/`ttl_secs` are
            /// when unset: the coordination plane treats an absent key and
            /// an explicit `false` identically, so skipping keeps a mint
            /// that wants no approval step byte-identical on the wire to
            /// one from a build that predates this option.
            #[serde(skip_serializing_if = "is_false")]
            requires_approval: bool,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            code: String,
            invite_id: String,
            group_id: String,
            role: String,
            expires_at_unix: i64,
            /// Whether the invite is approval-gated. Required: the mint
            /// route always reports it, and reading an absent value as
            /// `false` would tell the daemon an approval-gated invite needs
            /// no approval.
            requires_approval: bool,
        }

        let response = reqwest::Client::new()
            .post(format!("{addr}/shares/groups/{group_id}/invites"))
            .json(&Body { minting_device_id, role, ttl_secs, requires_approval })
            .send_authorized(auth)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "invite mint returned HTTP {status}: {}",
                response.text().await.unwrap_or_default()
            ));
        }
        let body = response
            .json::<Response>()
            .await
            .map_err(|e| format!("invite mint response was unparseable: {e}"))?;
        Ok(super::MintedInvite {
            code: body.code,
            invite_id: body.invite_id,
            group_id: body.group_id,
            role: body.role,
            expires_at_unix: body.expires_at_unix,
            requires_approval: body.requires_approval,
        })
    }

    /// Returns whether the plane accepted the report.
    ///
    /// Observable, not fire-and-forget, because this is now the ONLY way a
    /// peer learns where this device's substrate answers. A POST lost to a
    /// coordination blip used to be lost for good: the reporter waited for the
    /// next address change, and an address that never changes again produces
    /// none.
    pub async fn report_endpoint(
        addr: &str,
        auth: &CoordinationAuth,
        device_id: String,
        substrate: &super::SubstrateReachability,
    ) -> bool {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body {
            substrate_reachability: WireSubstrateReachability,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct WireSubstrateReachability {
            direct: Vec<String>,
            relays: Vec<String>,
        }
        let body = Body {
            substrate_reachability: WireSubstrateReachability {
                direct: substrate.direct.iter().map(ToString::to_string).collect(),
                relays: substrate.relays.clone(),
            },
        };
        let url = format!("{addr}/devices/{device_id}/endpoint");
        let client = match reqwest::Client::builder().timeout(ENDPOINT_REPORT_TIMEOUT).build() {
            Ok(client) => client,
            Err(error) => {
                tracing::debug!(%error, "could not build the endpoint-report client");
                return false;
            }
        };
        match client.post(&url).json(&body).send_authorized(auth).await {
            Ok(resp) if resp.status().is_success() => true,
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), "endpoint report rejected");
                false
            }
            Err(error) => {
                tracing::debug!(%error, "endpoint report failed");
                false
            }
        }
    }

    /// Looks up whether `target_device_id` currently holds a live handoff
    /// lease for `group_id` (`GET /shares/groups/:groupId/handoff/lease?
    /// targetDeviceId=...`) -- the SOURCE side of the round trip
    /// `request_handoff_lease` starts on the TARGET side. Called by a
    /// source-side role-loss commit path just before
    /// `commit_handoff_role_loss`, so a target that already requested a
    /// lease (because it independently verified readiness) has that lease
    /// actually presented and confirmed as part of the commit, instead of
    /// the commit always going through with `lease_id: None` and the lease
    /// being left to expire on its own. `None` on any failure (unreachable
    /// coordination plane, rejected request, unparseable response, or no
    /// live lease found) -- the caller treats this exactly like "no lease
    /// to present": `commit_handoff_role_loss` still succeeds on the
    /// Active+eager guard alone (a lease is retention-protection insurance
    /// for the target, not a hard prerequisite for the role-loss
    /// authorization itself).
    pub async fn find_handoff_lease(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        target_device_id: &str,
    ) -> Option<String> {
        #[derive(Deserialize)]
        struct LeaseInfo {
            #[serde(rename = "leaseId")]
            lease_id: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            lease: Option<LeaseInfo>,
        }
        let url = match url::Url::parse(&format!("{addr}/shares/groups/{group_id}/handoff/lease")) {
            Ok(mut u) => {
                u.query_pairs_mut().append_pair("targetDeviceId", target_device_id);
                u
            }
            Err(e) => {
                tracing::debug!(error = %e, "handoff lease lookup: could not build request URL");
                return None;
            }
        };
        let result = reqwest::Client::new().get(url).send_authorized(auth).await;
        match result {
            Ok(resp) if resp.status().is_success() => match resp.json::<Resp>().await {
                Ok(r) => r.lease.map(|l| l.lease_id),
                Err(e) => {
                    tracing::debug!(error = %e, "handoff lease lookup: unparseable response");
                    None
                }
            },
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), "handoff lease lookup rejected");
                None
            }
            Err(e) => {
                tracing::debug!(error = %e, "handoff lease lookup failed");
                None
            }
        }
    }

    /// Requests a full-replica-handoff lease from the coordination service
    /// (`POST /shares/groups/:groupId/handoff/lease`), called by the handoff
    /// TARGET immediately after its own local readiness check confirms it
    /// holds every root of the group. Carries no digest or other
    /// content-derived value -- the request is purely `(group_id,
    /// target_device_id)`; the Worker's whole contribution to a handoff is
    /// confirming device/group membership and eligibility, never anything
    /// about the actual files or versions involved. `None` on any failure
    /// (unreachable coordination plane, rejected request, or an unparseable
    /// response) -- the caller (`daemon_state`'s handoff-lease request path)
    /// treats this exactly like an unconfirmed local readiness check: no
    /// lease was requested or recorded, and the caller's own TTL/retry story
    /// (retry the whole check-then-request sequence later) is unaffected.
    pub async fn request_handoff_lease(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        target_device_id: &str,
    ) -> Option<HandoffLeaseGrant> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            target_device_id: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            lease_id: String,
            expires_at: i64,
            ttl_seconds: i64,
        }
        let url = format!("{addr}/shares/groups/{group_id}/handoff/lease");
        let body = Body { target_device_id };
        let result = reqwest::Client::new().post(&url).json(&body).send_authorized(auth).await;
        match result {
            Ok(resp) if resp.status().is_success() => match resp.json::<Resp>().await {
                Ok(r) => Some(HandoffLeaseGrant {
                    lease_id: r.lease_id,
                    expires_at_unix: r.expires_at,
                    ttl_seconds: r.ttl_seconds,
                }),
                Err(e) => {
                    tracing::debug!(error = %e, "handoff lease request: unparseable response");
                    None
                }
            },
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), "handoff lease request rejected");
                None
            }
            Err(e) => {
                tracing::debug!(error = %e, "handoff lease request failed");
                None
            }
        }
    }

    /// The JSON body of an authorization-checkpoint request. Ordinary
    /// publication requests carry no `purpose`, so they are unchanged; a
    /// seal names it explicitly.
    fn checkpoint_request_body(
        device_id: &str,
        request_id: &str,
        merkle_root: [u8; 32],
        leaf_count: u64,
        purpose: crate::checkpoint_source::CheckpointPurpose,
    ) -> serde_json::Value {
        let mut body = serde_json::json!({
            "deviceId": device_id,
            "requestId": request_id,
            "merkleRootBase64": base64::engine::general_purpose::STANDARD.encode(merkle_root),
            "leafCount": leaf_count,
        });
        if purpose == crate::checkpoint_source::CheckpointPurpose::Seal {
            body["purpose"] = serde_json::Value::from("seal");
        }
        body
    }

    /// Requests (or, for an already-decided `request_id`,
    /// replays) a signed `AuthorizationCheckpoint` for `device_id`'s
    /// pending batch, via the coordination service's
    /// `POST /shares/groups/:groupId/authorization-checkpoint`
    /// (`src/routes/shares.ts`). `request_id` MUST be
    /// deterministic in the caller for a given `(group_id, device_id,
    /// merkle_root, leaf_count)` — see
    /// `checkpoint_source::pending_batch_request_id` — so a retry after a
    /// lost response reuses the SAME decided record rather than being
    /// judged (and potentially refused) as a brand new request against
    /// possibly-changed writer status.
    ///
    /// Best-effort like every other call in this module: `None` on any
    /// failure, including a legitimate 403 ("not currently a writer" —
    /// expected and not logged above debug) and a 409 (idempotency
    /// conflict — should never happen for a caller deriving `request_id`
    /// correctly, logged at `warn` since it indicates a caller bug rather
    /// than an expected outcome).
    #[allow(clippy::too_many_arguments)]
    pub async fn request_authorization_checkpoint(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        device_id: &str,
        request_id: &str,
        merkle_root: [u8; 32],
        leaf_count: u64,
        purpose: crate::checkpoint_source::CheckpointPurpose,
    ) -> Option<(
        yadorilink_replica_domain::authorization_checkpoint::AuthorizationCheckpoint,
        [u8; 64],
    )> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            group_id: String,
            device_id: String,
            signing_key_fingerprint_base64: String,
            merkle_root_base64: String,
            leaf_count: u64,
            checkpoint_seq: u64,
            signer_key_id_base64: String,
            policy_epoch: u64,
            policy_seq: u64,
            policy_head_base64: String,
            issued_at_unix: u64,
            signature_base64: Option<String>,
        }
        fn decode32(b64: &str) -> Option<[u8; 32]> {
            let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            bytes.try_into().ok()
        }
        let url = format!("{addr}/shares/groups/{group_id}/authorization-checkpoint");
        let body = checkpoint_request_body(device_id, request_id, merkle_root, leaf_count, purpose);
        let result = reqwest::Client::new().post(&url).json(&body).send_authorized(auth).await;
        match result {
            Ok(resp) if resp.status().is_success() => match resp.json::<Resp>().await {
                Ok(r) => {
                    let Some(signature_base64) = r.signature_base64 else {
                        tracing::debug!(
                            "authorization checkpoint request: response carried no signature yet"
                        );
                        return None;
                    };
                    let Some(signature_bytes) = base64::engine::general_purpose::STANDARD
                        .decode(&signature_base64)
                        .ok()
                        .and_then(|b| <[u8; 64]>::try_from(b).ok())
                    else {
                        tracing::debug!("authorization checkpoint request: unparseable signature");
                        return None;
                    };
                    let (
                        Some(signing_key_fingerprint),
                        Some(merkle_root),
                        Some(signer_key_id),
                        Some(policy_head),
                    ) = (
                        decode32(&r.signing_key_fingerprint_base64),
                        decode32(&r.merkle_root_base64),
                        decode32(&r.signer_key_id_base64),
                        decode32(&r.policy_head_base64),
                    )
                    else {
                        tracing::debug!(
                            "authorization checkpoint request: unparseable 32-byte field"
                        );
                        return None;
                    };
                    Some((
                        yadorilink_replica_domain::authorization_checkpoint::AuthorizationCheckpoint {
                            group_id: r.group_id,
                            device_id: r.device_id,
                            signing_key_fingerprint,
                            merkle_root,
                            leaf_count: r.leaf_count,
                            checkpoint_seq: r.checkpoint_seq,
                            signer_key_id,
                            policy_epoch: r.policy_epoch,
                            policy_seq: r.policy_seq,
                            policy_head,
                            issued_at_unix: r.issued_at_unix,
                        },
                        signature_bytes,
                    ))
                }
                Err(e) => {
                    tracing::debug!(error = %e, "authorization checkpoint request: unparseable response");
                    None
                }
            },
            Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                tracing::debug!(
                    device_id,
                    group_id,
                    "authorization checkpoint request: not currently a writer"
                );
                None
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::CONFLICT => {
                tracing::warn!(
                    request_id,
                    "authorization checkpoint request: idempotency conflict -- request_id was \
                     reused for a different payload, which should never happen for a correctly \
                     derived request_id"
                );
                None
            }
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), "authorization checkpoint request rejected");
                None
            }
            Err(e) => {
                tracing::debug!(error = %e, "authorization checkpoint request failed");
                None
            }
        }
    }

    /// Explicitly releases a still-provisional handoff lease this device (as
    /// the target) decided not to use after all
    /// (`POST /shares/groups/:groupId/handoff/lease/:leaseId/release`) —
    /// called when the atomic local verify+pin
    /// (`SyncState::record_handoff_lease_atomic`) finds the durability-root
    /// set has moved since the readiness digest this lease was requested
    /// against was captured, so the lease is abandoned rather than kept
    /// around under a set it no longer matches. Carries no digest or other
    /// content-derived value, matching every other call in this module — just
    /// the opaque `lease_id` plus `(group_id, target_device_id)`. Best-effort
    /// like `find_handoff_lease`/`request_handoff_lease`: a failure here just
    /// means the lease is instead cleaned up later by the coordination service's
    /// own TTL sweep, so it is logged at debug and swallowed rather than
    /// surfaced to the caller.
    ///
    /// `true` only when the service reports the lease ended (`released`, or
    /// `gone` for no such lease). A success answer without that state, or one
    /// saying the lease is left alone (`reserved-not-released`,
    /// `confirmed-not-released`), is `false`.
    pub async fn release_handoff_lease(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
    ) -> bool {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            target_device_id: &'a str,
        }
        let url = format!("{addr}/shares/groups/{group_id}/handoff/lease/{lease_id}/release");
        let body = Body { target_device_id };
        let result = reqwest::Client::new().post(&url).json(&body).send_authorized(auth).await;
        #[derive(serde::Deserialize)]
        struct Answer {
            state: String,
        }
        match result {
            Ok(resp) if resp.status().is_success() => match resp.json::<Answer>().await {
                Ok(answer) if matches!(answer.state.as_str(), "released" | "gone") => true,
                Ok(answer) => {
                    tracing::debug!(state = %answer.state, "handoff lease left in place");
                    false
                }
                Err(e) => {
                    tracing::debug!(error = %e, "handoff lease release answer unreadable");
                    false
                }
            },
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), "handoff lease release rejected");
                false
            }
            Err(e) => {
                tracing::debug!(error = %e, "handoff lease release failed");
                false
            }
        }
    }

    /// Commits a source device's full-replica-handoff role loss
    /// (`POST /shares/groups/:groupId/handoff/commit`) — the coordination service
    /// atomically confirms `target_device_id` is currently an Active, eager
    /// full replica before committing `action` (`"demote"`: this device's own
    /// ACL edge narrows to on-demand; `"revoke"`: some other device's edge is
    /// removed entirely) and, if `lease_id` is set, confirms that lease (an
    /// opaque token scoped to `(group_id, target_device_id)`) in the same
    /// write. Carries no digest or other content-derived value, matching
    /// `request_handoff_lease` — the coordination plane's role here is
    /// entirely membership/eligibility adjudication; the "is this still the
    /// version I verified" question stays peer-attested and local (this
    /// device's own pre-existing digest-recapture-then-recheck gate, e.g.
    /// `SyncState::recheck_digest_then_remove_link`), never something the
    /// Worker checks. Unlike every other call in this module, this one
    /// surfaces its failure to the caller instead of swallowing it: the CLI
    /// call sites (`commands::share`, `commands::durability_force`) must not
    /// proceed to commit the LOCAL side of a role loss (removing a link,
    /// flipping local materialization policy) when the coordination-plane
    /// commit itself was refused or unreachable.
    pub async fn commit_handoff_role_loss(
        addr: &str,
        auth: &CoordinationAuth,
        request: RoleLossCommitRequest<'_>,
    ) -> RoleLossCommitOutcome {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            source_device_id: &'a str,
            target_device_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            lease_id: Option<&'a str>,
            action: &'a str,
            operation_id: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            target_device_id: String,
            membership_generation: i64,
            lease_id: Option<String>,
        }
        let url = format!("{addr}/shares/groups/{}/handoff/commit", request.group_id);
        let body = Body {
            source_device_id: request.source_device_id,
            target_device_id: request.target_device_id,
            lease_id: request.lease_id,
            action: request.action,
            operation_id: request.operation_id,
        };
        let resp = match reqwest::Client::new().post(&url).json(&body).send_authorized(auth).await {
            Ok(resp) => resp,
            Err(e) => {
                return RoleLossCommitOutcome::Ambiguous(format!(
                    "could not confirm the coordination-plane commit: {e}"
                ));
            }
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let detail =
                format!("coordination plane refused the handoff commit ({status}): {text}");
            return if status == reqwest::StatusCode::CONFLICT {
                RoleLossCommitOutcome::Conflict(detail)
            } else if status.is_client_error() {
                RoleLossCommitOutcome::DefinitelyRejected(detail)
            } else {
                RoleLossCommitOutcome::Ambiguous(detail)
            };
        }
        let parsed: Resp = match resp.json().await {
            Ok(parsed) => parsed,
            Err(e) => {
                return RoleLossCommitOutcome::Ambiguous(format!(
                    "handoff commit succeeded but its response was unparseable: {e}"
                ));
            }
        };
        RoleLossCommitOutcome::Committed(HandoffCommitResult {
            target_device_id: parsed.target_device_id,
            membership_generation: parsed.membership_generation,
            lease_id: parsed.lease_id,
        })
    }

    /// Resolves a share edge id to its `(group_id, device_id)` by listing
    /// the account's own share edges, the same `/shares` route the CLI used
    /// to call directly. Kept here so `revoke_edge` is fully daemon-owned:
    /// the CLI never sees the edge listing or issues a raw HTTP delete
    /// against the coordination plane for it (see
    /// `ReplicaMembershipService::revoke_edge`'s doc comment).
    pub async fn resolve_edge(
        addr: &str,
        auth: &CoordinationAuth,
        edge_id: &str,
    ) -> Result<Option<(String, String)>, String> {
        Ok(list_share_edges(addr, auth)
            .await?
            .into_iter()
            .find(|edge| edge.edge_id == edge_id)
            .map(|edge| (edge.group_id, edge.device_id)))
    }

    /// One row of the `GET /shares` listing, as far as this daemon reads it.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EdgeInfo {
        edge_id: String,
        group_id: String,
        device_id: String,
        /// The edge's membership state (`"active"`, `"pending"`, or
        /// `"pending_approval"`). Required: `acl.state` is NOT NULL and the
        /// listing reports it for every row, so an absent value is a
        /// malformed response rather than an edge whose state is unknown.
        state: String,
    }

    async fn list_share_edges(
        addr: &str,
        auth: &CoordinationAuth,
    ) -> Result<Vec<EdgeInfo>, String> {
        #[derive(Deserialize)]
        struct Resp {
            edges: Vec<EdgeInfo>,
        }
        let resp = reqwest::Client::new()
            .get(format!("{addr}/shares"))
            .send_authorized(auth)
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("listing shares returned HTTP {}", resp.status()));
        }
        let parsed: Resp = resp.json().await.map_err(|e| e.to_string())?;
        Ok(parsed.edges)
    }

    /// The signing keys of every active device on this device's own account
    /// that is not signed out -- `GET /devices`, scoped by the caller's
    /// credential, so a device on another account (a folder-sharing peer
    /// included) is never listed. A removed device is not listed either. A
    /// signed-out device is listed with `signedOut: true` and left out here.
    /// A key that does not decode is left out rather than failing the
    /// listing: it can only fail to admit.
    pub async fn list_account_device_keys(
        addr: &str,
        auth: &CoordinationAuth,
    ) -> Result<Vec<[u8; 32]>, DeviceListingError> {
        Ok(list_account_devices(addr, auth)
            .await?
            .into_iter()
            .filter(|device| !device.signed_out)
            .filter_map(|device| decode_signing_key(&device.signing_public_key_base64))
            .collect())
    }

    /// One device on this device's own account, from the same `GET
    /// /devices` listing: its signing key (its endpoint id) and where its
    /// endpoint last said it answers. `Ok(None)` when the account lists no
    /// such device, or lists it with a key that does not decode. The
    /// reachability is empty when the device has published none (or the
    /// coordination plane does not report it); a dial then relies on what
    /// the endpoint's own lookup knows.
    pub async fn find_account_device(
        addr: &str,
        auth: &CoordinationAuth,
        device_id: &str,
    ) -> Result<Option<([u8; 32], SubstrateReachability)>, String> {
        Ok(list_account_devices(addr, auth).await.map_err(|e| e.to_string())?.into_iter().find_map(
            |device| {
                if device.device_id != device_id {
                    return None;
                }
                let key = decode_signing_key(&device.signing_public_key_base64)?;
                Some((key, device.substrate_reachability.map(Into::into).unwrap_or_default()))
            },
        ))
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AccountDevice {
        #[serde(default)]
        device_id: String,
        signing_public_key_base64: String,
        /// Required, with no default: a plane that does not say whether a
        /// device is signed out gives no listing at all, so management never
        /// trusts an older plane on this point.
        signed_out: bool,
        #[serde(default)]
        substrate_reachability: Option<super::WireSubstrateReachability>,
    }

    async fn list_account_devices(
        addr: &str,
        auth: &CoordinationAuth,
    ) -> Result<Vec<AccountDevice>, DeviceListingError> {
        #[derive(Deserialize)]
        struct Resp {
            devices: Vec<AccountDevice>,
        }
        let resp = reqwest::Client::new()
            .get(format!("{addr}/devices"))
            .send_authorized(auth)
            .await
            .map_err(DeviceListingError::from)?;
        let status = resp.status();
        if status.is_server_error() {
            return Err(DeviceListingError::Unreachable(format!(
                "listing devices returned HTTP {status}"
            )));
        }
        if !status.is_success() {
            return Err(DeviceListingError::Refused(format!(
                "listing devices returned HTTP {status}"
            )));
        }
        let body =
            resp.bytes().await.map_err(|e| DeviceListingError::Unreachable(e.to_string()))?;
        let parsed: Resp = serde_json::from_slice(&body)
            .map_err(|e| DeviceListingError::Refused(format!("unusable device listing: {e}")))?;
        Ok(parsed.devices)
    }

    /// The coordination plane's membership `state` for one (group, device)
    /// edge, read from the same `/shares` listing `resolve_edge` uses.
    /// `Ok(None)` means the account's listing carries no such edge at all,
    /// or carries one whose state this coordination plane does not report
    /// -- both of which callers must treat as "unknown", never as "not
    /// active".
    pub async fn fetch_edge_state(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        device_id: &str,
    ) -> Result<Option<String>, String> {
        Ok(list_share_edges(addr, auth)
            .await?
            .into_iter()
            .find(|edge| edge.group_id == group_id && edge.device_id == device_id)
            .map(|edge| edge.state))
    }

    /// Confirms whether a daemon-driven membership mutation actually landed,
    /// by `operation_id` -- see `MembershipOperationLookup`'s doc comment.
    /// Scoped by this device's own account, never by device ownership, so it
    /// keeps answering correctly after the removed device's own row is gone
    /// (unlike `resolve_edge`/eager-groups above). `Ok(NotFound)` means a
    /// genuine HTTP 404 -- no durable operation record was returned for
    /// this operation id at lookup time. It does NOT prove that the
    /// request was definitely rejected, that no historical mutation
    /// occurred, or that treating this operation as resolved is safe --
    /// see `RemoteEvidence`'s own doc comment
    /// for the same contract stated once, generally. Distinct from `Err`,
    /// which means the query itself couldn't be answered (network error,
    /// 5xx) and the caller must treat the operation's outcome as still
    /// unknown, not as rejected.
    pub async fn query_membership_operation(
        addr: &str,
        auth: &CoordinationAuth,
        operation_id: &str,
    ) -> Result<MembershipOperationLookup, String> {
        query_membership_operation_categorized(&evidence_http_client(), addr, auth, operation_id)
            .await
            .map_err(|e| e.message)
    }

    /// Same lookup as [`query_membership_operation`], sharing its entire
    /// request-building/parsing implementation, but with the failure
    /// categorized -- see [`RemoteEvidenceErrorCategory`]'s own doc
    /// comment. Used by the recovery-evidence module's
    /// `RecoveryEvidenceSource` implementation, which must distinguish a
    /// timeout/network/server error (still `Unavailable`, might resolve on
    /// retry) from a 404 (`RecordNotFound`, a real answer) -- a
    /// distinction the plain `String` error above deliberately does not
    /// expose to its own (pre-existing) callers, which never needed it.
    /// Takes `client` explicitly (rather than building one internally, the
    /// way every other function in this file does) so a test can inject a
    /// short-timeout client and exercise a genuine, real `Timeout`
    /// classification end to end, through `WorkerEvidenceSource` itself,
    /// instead of only unit-testing `categorize_transport_error` in
    /// isolation against a raw `reqwest::Error`.
    pub async fn query_membership_operation_categorized(
        client: &reqwest::Client,
        addr: &str,
        auth: &CoordinationAuth,
        operation_id: &str,
    ) -> Result<MembershipOperationLookup, RemoteQueryError> {
        // Decoded as a plain `String` below, not a serde enum -- see
        // `query_enrollment_operation`'s identical reasoning for why an
        // unrecognized-but-well-formed status must be `Unsupported`, not
        // `MalformedResponse`.
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct ResultBody {
            #[serde(default)]
            affected_group_ids: Option<Vec<String>>,
            target_device_id: Option<String>,
            membership_generation: Option<i64>,
            lease_id: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RequestGroupBody {
            group_id: String,
            target_device_id: Option<String>,
            lease_id: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RequestBody {
            // Present on the wire (the Worker's own fingerprint input
            // includes it) but unused here: this lookup is already scoped
            // to the caller's own account server-side, so there's nothing
            // left to compare it against locally.
            #[allow(dead_code)]
            user_id: String,
            action: String,
            removed_device_id: String,
            mode: String,
            groups: Vec<RequestGroupBody>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            operation_id: String,
            status: String,
            action: String,
            removed_device_id: String,
            request_fingerprint: String,
            request: RequestBody,
            result: Option<ResultBody>,
            rejection_code: Option<String>,
            rejection_detail: Option<String>,
        }
        let resp = client
            .get(format!("{addr}/devices/membership-operations/{operation_id}"))
            .send_authorized(auth)
            .await
            .map_err(|e| RemoteQueryError { category: e.category(), message: e.to_string() })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(MembershipOperationLookup::NotFound);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(RemoteQueryError {
                category: categorize_error_status(status),
                message: format!("membership operation lookup returned HTTP {status}"),
            });
        }
        let parsed: Resp = resp.json().await.map_err(|e| RemoteQueryError {
            category: RemoteEvidenceErrorCategory::MalformedResponse,
            message: e.to_string(),
        })?;
        // Same endpoint-contract check as `query_enrollment_operation`'s own
        // -- see that function's identical comment.
        if parsed.operation_id != operation_id {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "operation id mismatch: requested {operation_id}, received {}",
                    parsed.operation_id
                ),
            });
        }
        let status = match parsed.status.as_str() {
            "committed" => MembershipRemoteStatus::Committed,
            "definitely-rejected" => MembershipRemoteStatus::DefinitelyRejected,
            // An approved removal that has not finished: neither outcome is
            // known, and the same operation id completes it.
            "removal-pending" => {
                return Err(RemoteQueryError {
                    category: RemoteEvidenceErrorCategory::Pending,
                    message: format!(
                        "membership operation {operation_id} is still pending; retry it with the same operation id"
                    ),
                });
            }
            other => {
                return Err(RemoteQueryError {
                    category: RemoteEvidenceErrorCategory::Unsupported,
                    message: format!("unsupported membership operation status: {other}"),
                });
            }
        };
        // The Worker's own `MembershipOperationAction`/`MembershipOperationMode`
        // wire types (the coordination service) are each a
        // closed two-value set -- an unrecognized value here means a newer
        // Worker deploy this build predates, `Unsupported`, not a shape
        // violation. Checked on both the top-level `action` and the nested
        // `request.action` since they are independently-decoded fields.
        for candidate in [parsed.action.as_str(), parsed.request.action.as_str()] {
            if candidate != "revoke" && candidate != "remove-device" {
                return Err(RemoteQueryError {
                    category: RemoteEvidenceErrorCategory::Unsupported,
                    message: format!("unsupported membership operation action: {candidate}"),
                });
            }
        }
        if parsed.request.mode != "guarded" && parsed.request.mode != "plain" {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::Unsupported,
                message: format!("unsupported membership operation mode: {}", parsed.request.mode),
            });
        }
        // Two independently-decoded fields naming the same request
        // (top-level vs. `request.*`) disagreeing is not an unrecognized
        // value -- it is the response contradicting itself, which is
        // `MalformedResponse`, not `Unsupported`.
        if parsed.action != parsed.request.action {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "membership operation action mismatch: top-level {}, request {}",
                    parsed.action, parsed.request.action
                ),
            });
        }
        if parsed.removed_device_id != parsed.request.removed_device_id {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "membership operation removed device mismatch: top-level {}, request {}",
                    parsed.removed_device_id, parsed.request.removed_device_id
                ),
            });
        }
        let result = parsed.result.map(|r| MembershipRemoteResult {
            affected_group_ids: r.affected_group_ids,
            target_device_id: r.target_device_id,
            membership_generation: r.membership_generation,
            lease_id: r.lease_id,
        });
        let request = MembershipRemoteRequest {
            action: parsed.request.action,
            removed_device_id: parsed.request.removed_device_id,
            mode: parsed.request.mode,
            groups: parsed
                .request
                .groups
                .into_iter()
                .map(|group| MembershipRemoteRequestGroup {
                    group_id: group.group_id,
                    target_device_id: group.target_device_id,
                    lease_id: group.lease_id,
                })
                .collect(),
        };
        Ok(MembershipOperationLookup::Found(Box::new(MembershipOperationRecord {
            status,
            action: parsed.action,
            removed_device_id: parsed.removed_device_id,
            request_fingerprint: parsed.request_fingerprint,
            request,
            result,
            rejection_code: parsed.rejection_code,
            rejection_detail: parsed.rejection_detail,
        })))
    }

    /// Reads the coordination plane's own `enrollment_operations` ledger
    /// row by `operation_id`, scoped to this device's own account (the
    /// Worker route itself is `userId`-scoped). `Ok(None)` means a genuine
    /// HTTP 404 -- no durable operation record was returned for this
    /// operation id at lookup time. It does NOT prove that the request was
    /// definitely rejected, that no historical mutation occurred, or that
    /// treating this operation as resolved is safe -- see
    /// `RemoteEvidence`'s own doc comment for
    /// the same contract stated once, generally. Distinct from `Err`, which
    /// means the query itself could not be answered -- see
    /// [`RemoteEvidenceErrorCategory`]'s own doc comment for why these must
    /// never be conflated.
    pub async fn query_enrollment_operation(
        client: &reqwest::Client,
        addr: &str,
        auth: &CoordinationAuth,
        operation_id: &str,
    ) -> Result<Option<EnrollmentOperationRecord>, RemoteQueryError> {
        // `kind`/`status` are decoded as plain `String`, not a serde enum:
        // a serde enum fails the ENTIRE response parse on an unrecognized
        // variant, which this lookup would then report as
        // `MalformedResponse` -- indistinguishable from genuinely broken
        // JSON. Matched explicitly below instead, so an unrecognized-but
        // well-formed value (a newer Worker deploy adding a status this
        // build predates) is reported as `Unsupported`.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RequestBody {
            // Present on the wire (the fingerprint input includes it) but
            // unused here: this lookup is already scoped to the caller's
            // own account server-side.
            #[allow(dead_code)]
            user_id: String,
            #[serde(default)]
            group_name: Option<String>,
            #[serde(default)]
            group_id: Option<String>,
            device_id: String,
            #[serde(default)]
            storage_mode: Option<String>,
        }
        #[derive(Deserialize, Default)]
        struct ResultBody {
            #[serde(rename = "groupId")]
            group_id: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            operation_id: String,
            kind: String,
            status: String,
            request_fingerprint: String,
            request: RequestBody,
            result: Option<ResultBody>,
        }
        let resp = client
            .get(format!("{addr}/devices/enrollment-operations/{operation_id}"))
            .send_authorized(auth)
            .await
            .map_err(|e| RemoteQueryError { category: e.category(), message: e.to_string() })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(RemoteQueryError {
                category: categorize_error_status(status),
                message: format!("enrollment operation lookup returned HTTP {status}"),
            });
        }
        let parsed: Resp = resp.json().await.map_err(|e| RemoteQueryError {
            category: RemoteEvidenceErrorCategory::MalformedResponse,
            message: e.to_string(),
        })?;
        // The endpoint's own contract is to answer for exactly the
        // requested operation_id -- a mismatch means the Worker response
        // itself broke that contract (not a local-vs-remote identity
        // question the diagnosis engine handles), so this is
        // `MalformedResponse`, not `Conflict` (which does not even exist
        // at this layer).
        if parsed.operation_id != operation_id {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "operation id mismatch: requested {operation_id}, received {}",
                    parsed.operation_id
                ),
            });
        }
        let status = match parsed.status.as_str() {
            "preparing" => EnrollmentRemoteStatus::Preparing,
            "prepared" => EnrollmentRemoteStatus::Prepared,
            "active" => EnrollmentRemoteStatus::Active,
            "cancelled" => EnrollmentRemoteStatus::Cancelled,
            other => {
                return Err(RemoteQueryError {
                    category: RemoteEvidenceErrorCategory::Unsupported,
                    message: format!("unsupported enrollment status: {other}"),
                });
            }
        };
        // `storage_mode` is a real wire field for `join`; for `create` it
        // is always `"eager"` by construction (see
        // `EnrollmentRemoteRequest`'s own doc comment) -- an absent field
        // there is expected, not a shape violation. A `join` response
        // missing it, or either kind missing its own required id field, IS
        // a shape this build doesn't recognize.
        let request = match parsed.kind.as_str() {
            "create" => {
                let Some(group_name) = parsed.request.group_name else {
                    return Err(RemoteQueryError {
                        category: RemoteEvidenceErrorCategory::Unsupported,
                        message: "create enrollment response missing groupName".to_string(),
                    });
                };
                EnrollmentRemoteRequest::Create {
                    group_name,
                    device_id: parsed.request.device_id,
                    storage_mode: "eager".to_string(),
                }
            }
            "join" => {
                let (Some(group_id), Some(storage_mode)) =
                    (parsed.request.group_id, parsed.request.storage_mode)
                else {
                    return Err(RemoteQueryError {
                        category: RemoteEvidenceErrorCategory::Unsupported,
                        message: "join enrollment response missing groupId/storageMode".to_string(),
                    });
                };
                if storage_mode != "eager" && storage_mode != "on-demand" {
                    return Err(RemoteQueryError {
                        category: RemoteEvidenceErrorCategory::Unsupported,
                        message: format!("unsupported join storage mode: {storage_mode}"),
                    });
                }
                EnrollmentRemoteRequest::Join {
                    group_id,
                    device_id: parsed.request.device_id,
                    storage_mode,
                }
            }
            other => {
                return Err(RemoteQueryError {
                    category: RemoteEvidenceErrorCategory::Unsupported,
                    message: format!("unsupported enrollment kind: {other}"),
                });
            }
        };
        Ok(Some(EnrollmentOperationRecord {
            status,
            request_fingerprint: parsed.request_fingerprint,
            request,
            result_group_id: parsed.result.and_then(|r| r.group_id),
        }))
    }

    /// Reads the coordination plane's `role_loss_operation_receipts` row by
    /// `operation_id` -- the receipt's mere existence IS the
    /// evidence that a role-loss commit landed; there is no separate
    /// status field the way enrollment/membership have one. `Ok(None)`
    /// means a genuine HTTP 404 -- no durable receipt was returned for this
    /// operation id at lookup time. It does NOT prove that the request was
    /// definitely rejected, that no historical mutation occurred (a commit
    /// made before generation 7, when this table did not exist, leaves no
    /// receipt either), or that treating this operation as resolved is
    /// safe -- see `RemoteEvidence`'s own doc
    /// comment for the same contract stated once, generally.
    pub async fn query_role_loss_operation(
        client: &reqwest::Client,
        addr: &str,
        auth: &CoordinationAuth,
        operation_id: &str,
    ) -> Result<Option<RoleLossOperationRecord>, RemoteQueryError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            operation_id: String,
            group_id: String,
            source_device_id: String,
            target_device_id: String,
            lease_id: Option<String>,
            action: String,
            membership_generation: Option<i64>,
            committed_at: i64,
        }
        let resp = client
            .get(format!("{addr}/devices/role-loss-operations/{operation_id}"))
            .send_authorized(auth)
            .await
            .map_err(|e| RemoteQueryError { category: e.category(), message: e.to_string() })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(RemoteQueryError {
                category: categorize_error_status(status),
                message: format!("role-loss operation lookup returned HTTP {status}"),
            });
        }
        let parsed: Resp = resp.json().await.map_err(|e| RemoteQueryError {
            category: RemoteEvidenceErrorCategory::MalformedResponse,
            message: e.to_string(),
        })?;
        // Same endpoint-contract check as `query_enrollment_operation`'s own
        // -- see that function's identical comment.
        if parsed.operation_id != operation_id {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "operation id mismatch: requested {operation_id}, received {}",
                    parsed.operation_id
                ),
            });
        }
        // `action` is well-formed JSON but has a closed, known set of legal
        // values on the Worker side (`"demote"`/`"revoke"` -- see
        // `commitHandoffRoleLoss`'s own doc comment) -- anything else is
        // `Unsupported`, not a shape violation.
        if parsed.action != "demote" && parsed.action != "revoke" {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::Unsupported,
                message: format!("unsupported role-loss action: {}", parsed.action),
            });
        }
        // Generation 8's `role_loss_operation_receipts.membership_generation`
        // column is `NOT NULL` (see that table's own migration comment) --
        // a receipt with no generation at all is a shape this build does
        // not recognize, not a legitimately absent value; treating it as
        // generation 0 (an earlier version of this code did) would silently
        // fabricate a successful outcome from a malformed row.
        let Some(membership_generation) = parsed.membership_generation else {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::Unsupported,
                message: "role-loss receipt missing membershipGeneration".to_string(),
            });
        };
        Ok(Some(RoleLossOperationRecord {
            group_id: parsed.group_id,
            source_device_id: parsed.source_device_id,
            target_device_id: parsed.target_device_id,
            lease_id: parsed.lease_id,
            action: parsed.action,
            membership_generation,
            committed_at_unix: parsed.committed_at,
        }))
    }

    pub async fn compensate_handoff_role_loss(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        source_device_id: &str,
        target_device_id: &str,
        lease_id: &str,
        expected_membership_generation: Option<i64>,
    ) -> Result<RoleLossCompensationOutcome, String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            source_device_id: &'a str,
            target_device_id: &'a str,
            lease_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            expected_membership_generation: Option<i64>,
        }
        #[derive(Deserialize)]
        struct Resp {
            status: String,
        }
        let response = reqwest::Client::new()
            .post(format!("{addr}/shares/groups/{group_id}/handoff/compensate"))
            .json(&Body {
                source_device_id,
                target_device_id,
                lease_id,
                expected_membership_generation,
            })
            .send_authorized(auth)
            .await
            .map_err(|e| format!("could not confirm role-loss compensation: {e}"))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(format!(
                "coordination plane rejected role-loss compensation ({status}): {text}"
            ));
        }
        match response.json::<Resp>().await.map_err(|e| e.to_string())?.status.as_str() {
            "restored" => Ok(RoleLossCompensationOutcome::Restored),
            "superseded" => Ok(RoleLossCompensationOutcome::Superseded),
            other => Err(format!("unknown role-loss compensation status: {other}")),
        }
    }

    /// Reports this device's storage mode for a folder group
    /// (`POST /shares/groups/:groupId/storage-mode`) -- the coordination service's
    /// single writer of `storage_mode` for a PROMOTION (on-demand -> eager).
    /// A DEMOTION instead writes `storage_mode` through
    /// `commit_handoff_role_loss`'s role-loss commit, which additionally
    /// confirms the handoff target and any presented lease atomically with
    /// the write; a promotion has no such hazard (gaining a durable copy is
    /// always safe), so this is a plain, unconditional write. Carries only
    /// the group id, this device's id, and the mode literal -- content-blind,
    /// like every other call in this module. Unlike most calls here, this one
    /// surfaces its failure to the caller instead of swallowing it: the
    /// daemon's `control_socket::set_storage_mode` must not proceed to flip
    /// local policy to eager when this write did not land, since that would
    /// leave this device locally eager while the coordination plane (and any
    /// peer reading its pushed netmap) still believes it is on-demand.
    pub async fn set_storage_mode(
        addr: &str,
        auth: &CoordinationAuth,
        group_id: &str,
        device_id: &str,
        storage_mode: &str,
    ) -> Result<(), String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            device_id: &'a str,
            storage_mode: &'a str,
        }
        let url = format!("{addr}/shares/groups/{group_id}/storage-mode");
        let body = Body { device_id, storage_mode };
        let resp = reqwest::Client::new()
            .post(&url)
            .json(&body)
            .send_authorized(auth)
            .await
            .map_err(|e| format!("could not reach the coordination plane: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "coordination plane refused the storage-mode change ({status}): {text}"
            ));
        }
        Ok(())
    }

    /// Decodes a base64 Ed25519 public key into the fixed-size form every
    /// signing-key field in this daemon uses. `None` for anything that
    /// isn't valid base64 or doesn't decode to exactly 32 bytes -- the
    /// coordination plane's own signing-key column is exactly 32 bytes or
    /// absent (see `sendConnectMaterialFor`'s own `null` case), so a
    /// present-but-wrong-length value here means a build mismatch between
    /// this daemon and the coordination plane, not a real key to try to use
    /// anyway.
    fn decode_signing_key(base64_key: &str) -> Option<[u8; 32]> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(base64_key).ok()?;
        bytes.try_into().ok()
    }

    /// Requests a Track Send rendezvous grant naming `receiver_device_id` as
    /// the exact (and only) device this call authorizes `sender_device_id`
    /// to reach -- `POST /send/authorization`. Unlike most calls in this
    /// module, this surfaces its failure to the caller: `SendTransferService`
    /// needs to tell a user-initiated `yadorilink send` apart a real
    /// rejection (receiver removed, not on this account, budget exceeded)
    /// from a transient outage, and a silently-swallowed `None` cannot do
    /// that.
    pub async fn request_send_authorization(
        addr: &str,
        auth: &CoordinationAuth,
        sender_device_id: &str,
        receiver_device_id: &str,
    ) -> Result<SendAuthorizationGrant, String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            sender_device_id: &'a str,
            receiver_device_id: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ReceiverBody {
            device_id: String,
            signing_public_key_base64: String,
            #[serde(default)]
            substrate_reachability: Option<super::WireSubstrateReachability>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            grant_id: String,
            nonce: String,
            expires_at: i64,
            receiver: ReceiverBody,
        }
        let url = format!("{addr}/send/authorization");
        let body = Body { sender_device_id, receiver_device_id };
        let resp = reqwest::Client::new()
            .post(&url)
            .json(&body)
            .send_authorized(auth)
            .await
            .map_err(|e| format!("could not reach the coordination plane: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "coordination plane refused the send-authorization request ({status}): {text}"
            ));
        }
        let parsed: Resp = resp
            .json()
            .await
            .map_err(|e| format!("unparseable send-authorization response: {e}"))?;
        let receiver_signing_key = decode_signing_key(&parsed.receiver.signing_public_key_base64)
            .ok_or_else(|| {
            "send-authorization response carried an unparseable receiver signing key".to_string()
        })?;
        Ok(SendAuthorizationGrant {
            grant_id: parsed.grant_id,
            nonce: parsed.nonce,
            expires_at_unix: parsed.expires_at,
            receiver_device_id: parsed.receiver.device_id,
            receiver_signing_key,
            receiver_reachability: parsed
                .receiver
                .substrate_reachability
                .map(Into::into)
                .unwrap_or_default(),
        })
    }

    /// Atomically consumes a grant -- `POST /send/authorization/:grantId/consume`
    /// -- naming the exact sender identity this device's own Track Send
    /// handshake just authenticated (never a value merely claimed in the application-
    /// layer offer that presented `grant_id`/`nonce`; see
    /// `yadorilink-send`'s `handle_offer`, which is what calls this). Only
    /// the first consume of a grant succeeds -- see
    /// `consumeSendAuthorization`'s own doc comment on the
    /// Worker side for why a SECOND call with the exact same arguments
    /// (a replay, or an honest retry after this device never saw the first
    /// response) reliably fails rather than reliably succeeding twice: only
    /// the first to actually commit gets a receiver's `Ok`, and a caller
    /// that legitimately needs to retry a transient failure does so by
    /// requesting a fresh grant, not by re-presenting a consumed one.
    pub async fn consume_send_authorization(
        addr: &str,
        auth: &CoordinationAuth,
        grant_id: &str,
        nonce: &str,
        sender_device_id: &str,
        receiver_device_id: &str,
    ) -> Result<(), String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            nonce: &'a str,
            sender_device_id: &'a str,
            receiver_device_id: &'a str,
        }
        let url = format!("{addr}/send/authorization/{grant_id}/consume");
        let body = Body { nonce, sender_device_id, receiver_device_id };
        let resp = reqwest::Client::new()
            .post(&url)
            .json(&body)
            .send_authorized(auth)
            .await
            .map_err(|e| format!("could not reach the coordination plane: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "send authorization is invalid, expired, or already used ({status}): {text}"
            ));
        }
        // The response also names the sender; this device already knows who
        // it is from the authenticated connection, so the body is not read.
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::{
            activate_invite_accept, checkpoint_request_body, coord_error_message, fetch_edge_state,
            find_account_device, list_account_device_keys, prepare_create, prepare_invite_accept,
            request_authorization_checkpoint, resolve_edge, SubstrateReachability,
        };
        use crate::checkpoint_source::CheckpointPurpose;
        use crate::coordination_client::{ActivateOutcome, EnrollmentPrepareOutcome};
        use crate::coordination_client::{CoordinationCallError, DeviceListingError};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// The credential every call in this module now takes, wrapping the
        /// pre-cutover opaque token these mock servers expect to see as
        /// `Authorization: Bearer`. On the new plane the equivalent is built
        /// from an enrolled client registration and there is no constructor
        /// that takes a string at all.
        fn test_auth() -> yadorilink_fapi_client::CoordinationAuth {
            yadorilink_fapi_client::test_support::offline_auth()
        }

        #[tokio::test]
        async fn account_device_keys_come_from_the_device_listing_and_bad_keys_are_left_out() {
            use base64::Engine as _;
            let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/devices"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "devices": [
                        { "deviceId": "a", "deviceName": "Mac", "signingPublicKeyBase64": key, "signedOut": false },
                        { "deviceId": "b", "deviceName": "Odd", "signingPublicKeyBase64": "AAAA", "signedOut": false },
                    ]
                })))
                .mount(&server)
                .await;
            let keys = list_account_device_keys(&server.uri(), &test_auth()).await.unwrap();
            assert_eq!(keys, vec![[7u8; 32]]);
        }

        /// The device to manage is looked up on this device's own account
        /// listing: its key and where it answers. A device the account does
        /// not list is not found, whatever else knows of it.
        #[tokio::test]
        async fn an_account_device_is_found_with_its_key_and_reachability() {
            use base64::Engine as _;
            let key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/devices"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "devices": [
                        { "deviceId": "mac", "deviceName": "Mac", "signingPublicKeyBase64": key, "signedOut": false },
                        {
                            "deviceId": "nas", "deviceName": "NAS", "signingPublicKeyBase64": key,
                            "signedOut": false,
                            "substrateReachability": {
                                "direct": ["192.0.2.7:4433", "not an address"],
                                "relays": ["https://relay.example/"]
                            }
                        },
                    ]
                })))
                .mount(&server)
                .await;
            let (found, reachability) =
                find_account_device(&server.uri(), &test_auth(), "nas").await.unwrap().unwrap();
            assert_eq!(found, [9u8; 32]);
            assert_eq!(reachability.direct, vec!["192.0.2.7:4433".parse().unwrap()]);
            assert_eq!(reachability.relays, vec!["https://relay.example/".to_string()]);
            let (_, none_published) =
                find_account_device(&server.uri(), &test_auth(), "mac").await.unwrap().unwrap();
            assert_eq!(none_published, SubstrateReachability::default());
            assert!(find_account_device(&server.uri(), &test_auth(), "elsewhere")
                .await
                .unwrap()
                .is_none());
        }

        /// A listing answered with `status`: what `list_account_device_keys` makes of it.
        async fn listing_answered(
            response: ResponseTemplate,
        ) -> Result<Vec<[u8; 32]>, DeviceListingError> {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/devices"))
                .respond_with(response)
                .mount(&server)
                .await;
            list_account_device_keys(&server.uri(), &test_auth()).await
        }

        /// The credential being refused is an answer, not an outage: it must
        /// never be mistaken for "the plane is unreachable", which management
        /// rides out on its last listing.
        #[tokio::test]
        async fn a_refused_device_listing_is_refused_not_unreachable() {
            for status in [401, 403, 404] {
                assert!(
                    matches!(
                        listing_answered(ResponseTemplate::new(status)).await,
                        Err(DeviceListingError::Refused(_))
                    ),
                    "HTTP {status}"
                );
            }
        }

        #[tokio::test]
        async fn a_server_error_or_no_answer_is_unreachable() {
            for status in [500, 502, 503] {
                assert!(
                    matches!(
                        listing_answered(ResponseTemplate::new(status)).await,
                        Err(DeviceListingError::Unreachable(_))
                    ),
                    "HTTP {status}"
                );
            }
            // Nothing listens there (wiremock pools its servers, so a dropped
            // one would still answer).
            let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", gone.local_addr().unwrap());
            drop(gone);
            assert!(matches!(
                list_account_device_keys(&addr, &test_auth()).await,
                Err(DeviceListingError::Unreachable(_))
            ));
        }

        /// Minting the credential can fail too. The authorization server
        /// being down (5xx) is an outage, like the coordination plane being
        /// down; it refusing the refresh (4xx) is this device's credential not
        /// working, as is anything else that stops a credential being minted.
        #[test]
        fn a_credential_refresh_is_unreachable_only_when_the_server_fails() {
            use yadorilink_fapi_client::Error;
            let answered = |status: u16| {
                DeviceListingError::from(CoordinationCallError::from(Error::Response {
                    step: "refresh",
                    status,
                    body: String::new(),
                    parsed: None,
                }))
            };
            for status in [500, 502, 503] {
                assert!(matches!(answered(status), DeviceListingError::Unreachable(_)), "{status}");
            }
            for status in [400, 401, 403, 429] {
                assert!(matches!(answered(status), DeviceListingError::Refused(_)), "{status}");
            }
            assert!(matches!(
                DeviceListingError::from(CoordinationCallError::from(Error::NotEnrolled)),
                DeviceListingError::Refused(_)
            ));
        }

        /// A signed-out device stays listed (the CLI still shows it) but is
        /// never one whose key admits.
        #[tokio::test]
        async fn a_signed_out_device_is_left_out_of_the_keys() {
            use base64::Engine as _;
            let engine = base64::engine::general_purpose::STANDARD;
            let keys = listing_answered(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "devices": [
                        { "deviceId": "in", "deviceName": "Mac", "signingPublicKeyBase64": engine.encode([1u8; 32]), "signedOut": false },
                        { "deviceId": "out", "deviceName": "Laptop", "signingPublicKeyBase64": engine.encode([2u8; 32]), "signedOut": true },
                    ]
                }),
            ))
            .await
            .unwrap();
            assert_eq!(keys, vec![[1u8; 32]]);
        }

        /// A plane that does not say whether a device is signed out (an
        /// older worker) gives no listing at all: every key is refused, not
        /// just the device the field is missing on.
        #[tokio::test]
        async fn a_listing_without_signed_out_is_refused_whole() {
            use base64::Engine as _;
            let engine = base64::engine::general_purpose::STANDARD;
            let answered = listing_answered(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({
                    "devices": [
                        { "deviceId": "in", "deviceName": "Mac", "signingPublicKeyBase64": engine.encode([1u8; 32]), "signedOut": false },
                        { "deviceId": "old", "deviceName": "NAS", "signingPublicKeyBase64": engine.encode([3u8; 32]) },
                    ]
                }),
            ))
            .await;
            assert!(matches!(answered, Err(DeviceListingError::Refused(_))), "{answered:?}");
        }

        #[test]
        fn a_seal_checkpoint_request_names_its_purpose_and_a_publication_one_does_not() {
            let seal = checkpoint_request_body("dev", "req", [7; 32], 1, CheckpointPurpose::Seal);
            assert_eq!(seal["purpose"], "seal");
            let publication =
                checkpoint_request_body("dev", "req", [7; 32], 3, CheckpointPurpose::Publication);
            assert!(publication.get("purpose").is_none(), "publication requests are unchanged");
            assert_eq!(publication["leafCount"], 3);
        }

        #[tokio::test]
        async fn the_checkpoint_request_posts_the_seal_purpose_to_the_issuance_route() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/shares/groups/g1/authorization-checkpoint"))
                .respond_with(ResponseTemplate::new(403))
                .mount(&server)
                .await;
            let seal = request_authorization_checkpoint(
                &server.uri(),
                &test_auth(),
                "g1",
                "dev",
                "req",
                [1; 32],
                1,
                CheckpointPurpose::Seal,
            )
            .await;
            assert!(seal.is_none());
            let requests = server.received_requests().await.expect("recorded requests");
            assert_eq!(requests.len(), 1);
            let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
            assert_eq!(body["purpose"], "seal");
        }

        #[test]
        fn coord_error_message_extracts_the_coordination_planes_error_field() {
            let body = r#"{"error":"invite is invalid or already used"}"#;
            assert_eq!(
                coord_error_message(body).as_deref(),
                Some("invite is invalid or already used"),
            );
        }

        #[test]
        fn coord_error_message_returns_none_for_a_body_with_no_error_field() {
            assert_eq!(coord_error_message(r#"{"other":"x"}"#), None);
        }

        #[test]
        fn coord_error_message_returns_none_for_unparseable_bodies() {
            assert_eq!(coord_error_message(""), None);
            assert_eq!(coord_error_message("not json"), None);
            assert_eq!(coord_error_message(r#"{"error":123}"#), None);
        }

        /// The coordination plane's `code` tells an expired invite from a used one;
        /// no code (an older worker) stays a plain rejection.
        #[tokio::test]
        async fn prepare_invite_accept_reads_the_refusal_code() {
            use crate::application::model::InviteRefusal;
            let cases = [
                (
                    serde_json::json!({"error": "invite is invalid or already used", "code": "invite_expired"}),
                    EnrollmentPrepareOutcome::InviteRefused {
                        reason: InviteRefusal::Expired,
                        detail: "invite is invalid or already used".to_string(),
                    },
                ),
                (
                    serde_json::json!({"error": "invite is invalid or already used", "code": "invite_already_used"}),
                    EnrollmentPrepareOutcome::InviteRefused {
                        reason: InviteRefusal::AlreadyUsed,
                        detail: "invite is invalid or already used".to_string(),
                    },
                ),
                (
                    serde_json::json!({"error": "invite is invalid or already used"}),
                    EnrollmentPrepareOutcome::DefinitelyRejected(
                        "invite is invalid or already used".to_string(),
                    ),
                ),
            ];
            for (body, expected) in cases {
                let server = MockServer::start().await;
                Mock::given(method("POST"))
                    .and(path("/shares/invites/accept/prepare"))
                    .respond_with(ResponseTemplate::new(400).set_body_json(body))
                    .mount(&server)
                    .await;
                let outcome = prepare_invite_accept(
                    &server.uri(),
                    &test_auth(),
                    "op-1",
                    "invite-code-1",
                    "device-b",
                    "on-demand",
                )
                .await;
                assert_eq!(outcome, expected);
            }
        }

        /// Regression test: `POST /shares/groups/prepare`'s real success
        /// body is `{"groupId": ..., "state": ...}` (the coordination service's
        /// `prepareCreateFolderGroup`/`PendingEnrollmentResult`) --
        /// `prepare_create`'s inner `Response` struct was missing
        /// `#[serde(rename_all = "camelCase")]`, so it failed to parse a
        /// real 2xx response at all. That parse failure was silently
        /// swallowed into `EnrollmentPrepareOutcome::Ambiguous` (the worst
        /// outcome class -- "may have committed, response merely lost"),
        /// even though the create had genuinely succeeded, driving every
        /// `share create` against a real deployed worker into the
        /// reconciliation path instead of completing normally. This proves
        /// the full round trip -- request sent, realistic response parsed --
        /// lands on `Prepared`, not `Ambiguous`.
        #[tokio::test]
        async fn prepare_create_a_realistic_camelcase_response_is_prepared_not_ambiguous() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/shares/groups/prepare"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({ "groupId": "group-1", "state": "pending" }),
                    ),
                )
                .mount(&server)
                .await;

            let outcome =
                prepare_create(&server.uri(), &test_auth(), "op-1", "photos", "device-a", "eager")
                    .await;
            assert_eq!(
                outcome,
                EnrollmentPrepareOutcome::Prepared { group_id: "group-1".to_string() }
            );
        }

        /// Same bug, same fix, on the cross-account invite-accept path:
        /// `POST /shares/invites/accept/prepare` returns the identical
        /// `{"groupId": ..., "state": ...}` shape (`prepareInviteAccept`'s
        /// own return type). Before this fix, EVERY `share accept` against
        /// a real worker landed on `Ambiguous` even on a genuine success --
        /// and because the invite is atomically consumed server-side before
        /// this response is even built, the invite was already burned while
        /// the daemon reported "don't know if this committed", never
        /// completing the local link.
        #[tokio::test]
        async fn prepare_invite_accept_a_realistic_camelcase_response_is_prepared_not_ambiguous() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/shares/invites/accept/prepare"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({ "groupId": "group-2", "state": "active" }),
                    ),
                )
                .mount(&server)
                .await;

            let outcome = prepare_invite_accept(
                &server.uri(),
                &test_auth(),
                "op-2",
                "invite-code-1",
                "device-b",
                "on-demand",
            )
            .await;
            assert_eq!(
                outcome,
                EnrollmentPrepareOutcome::Prepared { group_id: "group-2".to_string() }
            );
        }

        /// Regression test, same bug class: `GET /shares`' real response
        /// carries camelCase edge keys (`listShares`'s `ShareEdgeInfo`) --
        /// `resolve_edge`'s inner `EdgeInfo` struct was missing
        /// `#[serde(rename_all = "camelCase")]`, so it silently resolved
        /// every edge id to `None` against a real worker (every field but
        /// none matched, so `serde_json` filled in nothing and the id
        /// comparison in `.find(...)` never matched), which is what backs
        /// `share revoke <edge-id>`.
        #[tokio::test]
        async fn resolve_edge_deserializes_the_coordination_planes_camelcase_shares_shape() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/shares"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "edges": [{
                        "edgeId": "edge-1",
                        "groupId": "group-1",
                        "groupName": "photos",
                        "deviceId": "device-1",
                        "state": "active",
                    }]
                })))
                .mount(&server)
                .await;

            let resolved = resolve_edge(&server.uri(), &test_auth(), "edge-1").await.unwrap();
            assert_eq!(resolved, Some(("group-1".to_string(), "device-1".to_string())));
        }

        /// Same fixture, a different edge id: must resolve to `None` rather
        /// than panicking or misreporting a different edge as a match.
        #[tokio::test]
        async fn resolve_edge_returns_none_for_an_edge_id_not_in_the_account_edge_list() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/shares"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "edges": [{
                        "edgeId": "edge-1",
                        "groupId": "group-1",
                        "groupName": "photos",
                        "deviceId": "device-1",
                        "state": "active",
                    }]
                })))
                .mount(&server)
                .await;

            let resolved =
                resolve_edge(&server.uri(), &test_auth(), "edge-does-not-exist").await.unwrap();
            assert_eq!(resolved, None);
        }

        /// The state a targeted revoke reads before deciding whether it
        /// needs a ticket-bound full-replica handoff at all -- see
        /// `ReplicaMembershipService::target_edge_is_provably_not_active`.
        /// Same camelCase listing, matched on the (group, device) pair
        /// rather than the edge id.
        #[tokio::test]
        async fn fetch_edge_state_reads_the_pairs_state_from_the_shares_listing() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/shares"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "edges": [
                        {
                            "edgeId": "edge-1",
                            "groupId": "group-1",
                            "groupName": "photos",
                            "deviceId": "device-1",
                            "state": "active",
                        },
                        {
                            "edgeId": "edge-2",
                            "groupId": "group-1",
                            "groupName": "photos",
                            "deviceId": "device-2",
                            "state": "pending_approval",
                        },
                    ]
                })))
                .mount(&server)
                .await;

            let uri = server.uri();
            assert_eq!(
                fetch_edge_state(&uri, &test_auth(), "group-1", "device-2").await.unwrap(),
                Some("pending_approval".to_string())
            );
            assert_eq!(
                fetch_edge_state(&uri, &test_auth(), "group-1", "device-1").await.unwrap(),
                Some("active".to_string())
            );
            // An edge the listing does not carry is "unknown", never "not
            // active" -- the caller must keep failing closed on it.
            assert_eq!(
                fetch_edge_state(&uri, &test_auth(), "group-1", "device-9").await.unwrap(),
                None
            );
        }

        /// A listing row with no `state` is a malformed response, not an
        /// edge whose state is unknown.
        ///
        /// This asserts the opposite of what it used to. Tolerating the
        /// absence was an affordance for a coordination plane that
        /// predated edge-state reporting; `acl.state` is NOT NULL and the
        /// listing reports it on every row, so the only things an absent
        /// value can now mean are a truncated or corrupted response. The
        /// distinction matters because "unknown" is a load-bearing answer
        /// here -- callers fail closed on it -- so silently manufacturing
        /// one from a broken response would hand a targeted revoke a
        /// fail-closed verdict that looks like it was actually reported.
        /// Failing the listing instead is the honest outcome.
        #[tokio::test]
        async fn a_shares_listing_row_without_a_state_is_rejected_as_malformed() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/shares"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "edges": [{
                        "edgeId": "edge-1",
                        "groupId": "group-1",
                        "groupName": "photos",
                        "deviceId": "device-1",
                    }]
                })))
                .mount(&server)
                .await;

            assert!(
                fetch_edge_state(&server.uri(), &test_auth(), "group-1", "device-1").await.is_err(),
                "an absent state must fail the listing rather than read back as the `None` that \
                 means 'this edge was not listed at all'"
            );
        }

        /// The activate outcome that must NOT be folded into a plain
        /// success: the coordination plane accepted this device's half of a
        /// cross-account acceptance, but the invite required the group
        /// owner's approval, so no membership exists yet. Both spellings
        /// (fresh, and a retry that finds it already parked) are the same
        /// answer to the only question the caller has.
        #[tokio::test]
        async fn activate_invite_accept_distinguishes_awaiting_approval_from_success() {
            for result in ["awaiting_approval", "already_awaiting_approval"] {
                let server = MockServer::start().await;
                Mock::given(method("POST"))
                    .and(path("/shares/groups/group-1/invites/accept/activate"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(serde_json::json!({ "result": result })),
                    )
                    .mount(&server)
                    .await;

                let outcome =
                    activate_invite_accept(&server.uri(), &test_auth(), "group-1", "op-1", "dev-1")
                        .await;
                assert_eq!(outcome, ActivateOutcome::AwaitingApproval, "for result {result:?}");
            }
        }

        /// ... while the ordinary outcomes on the same route are unchanged,
        /// including an unrecognized future one, which stays a plain
        /// success (the status code already confirmed the mutation landed).
        #[tokio::test]
        async fn activate_invite_accept_keeps_its_other_outcomes() {
            for (result, expected) in [
                ("activated", ActivateOutcome::Success),
                ("already_active", ActivateOutcome::AlreadyActive),
                ("some_future_outcome", ActivateOutcome::Success),
            ] {
                let server = MockServer::start().await;
                Mock::given(method("POST"))
                    .and(path("/shares/groups/group-1/invites/accept/activate"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(serde_json::json!({ "result": result })),
                    )
                    .mount(&server)
                    .await;

                let outcome =
                    activate_invite_accept(&server.uri(), &test_auth(), "group-1", "op-1", "dev-1")
                        .await;
                assert_eq!(outcome, expected, "for result {result:?}");
            }
        }
    }
}
