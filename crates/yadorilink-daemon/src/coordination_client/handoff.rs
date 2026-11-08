//! The `handoff` calls of the coordination client.

use super::imp::*;
use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

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
    let Ok(client) = reqwest::Client::builder()
        .timeout(crate::native_checkpoint_flush::CHECKPOINT_REQUEST_TIMEOUT)
        .build()
    else {
        return None;
    };
    let result = client.post(&url).json(&body).send_authorized(auth).await;
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
/// Best-effort like every other call in this module: an `Err` on any failure, told apart by
/// [`CheckpointRefusal`](crate::checkpoint_source::CheckpointRefusal): no answer or a server error
/// is `Unreachable` (retried, the service may come back; so is a 429, and a decided-but-not-yet-signed
/// answer); a 403 whose `error` code is `not_writer` or `not_device_owner` is
/// `NotAuthorized` (a viewer, a revoked device, or a device the account does not own; expected,
/// not logged above debug; the message text is never read); anything else that is not a checkpoint (the
/// Terms, a refused credential, a missing route, a bad body, a 409) is `Rejected`: the service
/// answered and waiting does not by itself help. A 409 (idempotency conflict) should never happen
/// for a caller deriving `request_id` correctly and is logged at `warn` since it indicates a
/// caller bug rather than an expected outcome.
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
) -> Result<
    (yadorilink_replica_domain::authorization_checkpoint::AuthorizationCheckpoint, [u8; 64]),
    crate::checkpoint_source::CheckpointRefusal,
> {
    use crate::checkpoint_source::CheckpointRefusal;
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
                    // The decision is recorded and the signing is a pure function of it, redone on
                    // the next request with the same id: a moment's wait, not a refusal.
                    return Err(CheckpointRefusal::Unreachable);
                };
                let Some(signature_bytes) = base64::engine::general_purpose::STANDARD
                    .decode(&signature_base64)
                    .ok()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok())
                else {
                    tracing::debug!("authorization checkpoint request: unparseable signature");
                    return Err(CheckpointRefusal::Rejected);
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
                    tracing::debug!("authorization checkpoint request: unparseable 32-byte field");
                    return Err(CheckpointRefusal::Rejected);
                };
                Ok((
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
                Err(CheckpointRefusal::Rejected)
            }
        },
        Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
            // The route answers a 403 with `{ "error": <code>, "message": <prose> }` and the
            // refusal is told apart by the code alone, never by the message: `not_writer` (a
            // viewer, or revoked) and `not_device_owner` (the device is not this account's) are
            // about this device's right to publish; the Terms gate's `terms_consent_required` and
            // any 403 without a known code (a gateway, an older service) are not.
            let code = resp
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|body| body.get("error").and_then(|e| e.as_str()).map(str::to_owned));
            match code.as_deref() {
                Some("not_writer" | "not_device_owner") => {
                    tracing::debug!(
                        device_id,
                        group_id,
                        code = code.as_deref().unwrap_or_default(),
                        "authorization checkpoint request: publishing is not allowed for this device"
                    );
                    Err(CheckpointRefusal::NotAuthorized)
                }
                _ => {
                    tracing::debug!(
                        device_id,
                        group_id,
                        code = code.as_deref().unwrap_or("none"),
                        "authorization checkpoint request: forbidden, not about this device's role"
                    );
                    Err(CheckpointRefusal::Rejected)
                }
            }
        }
        Ok(resp) if resp.status() == reqwest::StatusCode::CONFLICT => {
            tracing::warn!(
                request_id,
                "authorization checkpoint request: idempotency conflict -- request_id was \
                 reused for a different payload, which should never happen for a correctly \
                 derived request_id"
            );
            Err(CheckpointRefusal::Rejected)
        }
        Ok(resp)
            if resp.status().is_server_error()
                || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
        {
            // A server error, or the service shedding load (429: the account's request budget):
            // the service is there and says "later".
            tracing::debug!(status = %resp.status(), "authorization checkpoint request: try later");
            Err(CheckpointRefusal::Unreachable)
        }
        Ok(resp) => {
            // A credential that is refused (401), a route that is not there (404), a bad request:
            // the service answered, and waiting does not make it say yes.
            tracing::debug!(status = %resp.status(), "authorization checkpoint request rejected");
            Err(CheckpointRefusal::Rejected)
        }
        Err(e) => {
            tracing::debug!(error = %e, "authorization checkpoint request failed");
            Err(CheckpointRefusal::Unreachable)
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
        let detail = format!("coordination plane refused the handoff commit ({status}): {text}");
        return if status == reqwest::StatusCode::CONFLICT {
            RoleLossCommitOutcome::Conflict(detail)
        } else if is_terms_consent_refusal(status, &text) {
            RoleLossCommitOutcome::TermsConsentRequired(detail)
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
