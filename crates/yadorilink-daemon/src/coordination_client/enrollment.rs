//! The `enrollment` calls of the coordination client.

use super::imp::*;
use super::*;
use serde::{Deserialize, Serialize};

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
        let body_text = response.text().await.unwrap_or_default();
        let detail = format!("create prepare returned HTTP {status}: {body_text}");
        return if is_terms_consent_refusal(status, &body_text) {
            EnrollmentPrepareOutcome::TermsConsentRequired(detail)
        } else {
            EnrollmentPrepareOutcome::DefinitelyRejected(detail)
        };
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
    let body_text = response.text().await.unwrap_or_default();
    let detail = format!("join prepare returned HTTP {status}: {body_text}");
    if status == reqwest::StatusCode::CONFLICT {
        EnrollmentPrepareOutcome::Conflict(detail)
    } else if is_terms_consent_refusal(status, &body_text) {
        EnrollmentPrepareOutcome::TermsConsentRequired(detail)
    } else if status.is_client_error() {
        EnrollmentPrepareOutcome::DefinitelyRejected(detail)
    } else {
        EnrollmentPrepareOutcome::Ambiguous(detail)
    }
}

pub(crate) async fn classify_cancel_response(
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
        if is_terms_consent_refusal(status, &body_text) {
            return EnrollmentPrepareOutcome::TermsConsentRequired(detail);
        }
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

/// Shared by `activate_create`/`activate_join`/`activate_invite_accept`:
/// every one of those coordination service routes is 404 on a
/// permanently-gone row and otherwise 2xx with a `{"result": ...}` body
/// -- see the coordination service's activate
/// handlers.
pub(crate) async fn post_activate<B: Serialize>(
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
        Ok(resp) if resp.status().is_success() => match resp.json::<ActivateResultBody>().await {
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
