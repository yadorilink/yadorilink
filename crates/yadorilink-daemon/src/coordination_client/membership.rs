//! The membership calls of the coordination client: invites, share edges, account devices and
//! the membership-operation queries.

use super::imp::*;
use super::*;
use serde::{Deserialize, Serialize};

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
) -> Result<super::MintedInvite, crate::application::model::MintInviteError> {
    use crate::application::model::MintInviteError;
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
        .map_err(|e| MintInviteError::Rejected(e.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        let detail = format!("invite mint returned HTTP {status}: {text}");
        return Err(if is_terms_consent_refusal(status, &text) {
            MintInviteError::TermsConsentRequired(detail)
        } else {
            MintInviteError::Rejected(detail)
        });
    }
    let body = response.json::<Response>().await.map_err(|e| {
        MintInviteError::Rejected(format!("invite mint response was unparseable: {e}"))
    })?;
    Ok(super::MintedInvite {
        code: body.code,
        invite_id: body.invite_id,
        group_id: body.group_id,
        role: body.role,
        expires_at_unix: body.expires_at_unix,
        requires_approval: body.requires_approval,
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
pub struct EdgeInfo {
    pub edge_id: String,
    pub group_id: String,
    pub device_id: String,
    /// The edge's membership state (`"active"`, `"pending"`, or
    /// `"pending_approval"`). Required: `acl.state` is NOT NULL and the
    /// listing reports it for every row, so an absent value is a
    /// malformed response rather than an edge whose state is unknown.
    pub state: String,
}

pub async fn list_share_edges(
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
pub(crate) struct AccountDevice {
    #[serde(default)]
    pub(crate) device_id: String,
    pub(crate) signing_public_key_base64: String,
    /// Required, with no default: a plane that does not say whether a
    /// device is signed out gives no listing at all, so management never
    /// trusts an older plane on this point.
    pub(crate) signed_out: bool,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    pub(crate) substrate_reachability: Option<super::WireSubstrateReachability>,
}

/// The account's devices that are not signed out, with their names and
/// whether the coordination plane last saw them online.
pub async fn list_account_device_names(
    addr: &str,
    auth: &CoordinationAuth,
) -> Result<Vec<(String, String, bool)>, String> {
    Ok(list_account_devices(addr, auth)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|device| !device.signed_out)
        .map(|device| (device.device_id, device.device_name, device.online))
        .collect())
}

pub(crate) async fn list_account_devices(
    addr: &str,
    auth: &CoordinationAuth,
) -> Result<Vec<AccountDevice>, DeviceListingError> {
    // Bounded like the other operator-facing lookups: a coordination plane that
    // accepts the connection and never answers must not hang the caller (the
    // web page's device card, NAS management admission).
    list_account_devices_with(&evidence_http_client(), addr, auth).await
}

pub(super) async fn list_account_devices_with(
    client: &reqwest::Client,
    addr: &str,
    auth: &CoordinationAuth,
) -> Result<Vec<AccountDevice>, DeviceListingError> {
    #[derive(Deserialize)]
    struct Resp {
        devices: Vec<AccountDevice>,
    }
    let resp = client
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
        return Err(DeviceListingError::Refused(format!("listing devices returned HTTP {status}")));
    }
    let body = resp.bytes().await.map_err(|e| DeviceListingError::Unreachable(e.to_string()))?;
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
