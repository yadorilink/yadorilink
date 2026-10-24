//! Self-service account management: the account-deletion lifecycle and the
//! account data export, over the coordination plane's `/account/*` routes.
//!
//! Both operate only on server-side coordination records; neither ever
//! touches the folders synced on the user's machines (see
//! `wording::LOCAL_FIRST_NOTICE`).

use serde::{Deserialize, Serialize};

use std::future::Future;

use crate::coordination::http_client::CoordinationAccess;

use crate::coordination::http_client::{get_json, post_json, post_json_with_failure, require_auth};
use crate::error::CoreError;

#[derive(Debug, Clone, Deserialize)]
pub struct DeletionRequested {
    /// Shown once; confirming the deletion requires it.
    #[serde(rename = "confirmationToken")]
    pub confirmation_token: String,
}

/// Mirrors the coordination plane's `DeletionStatus` JSON. `state` is one of
/// `active` | `requested` | `grace`; the grace fields are present only in the
/// `grace` state.
#[derive(Debug, Clone, Deserialize)]
pub struct DeletionStatus {
    pub state: String,
    #[serde(rename = "graceExpiresAtUnix")]
    pub grace_expires_at_unix: Option<i64>,
    #[serde(rename = "remainingSecs")]
    pub remaining_secs: Option<i64>,
}

#[derive(Serialize)]
struct ConfirmRequest<'a> {
    #[serde(rename = "confirmationToken")]
    confirmation_token: &'a str,
}

/// A group the deletion would affect, as the coordination plane reports it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ImpactGroup {
    #[serde(rename = "groupId")]
    pub group_id: String,
    pub name: String,
    /// Devices of other accounts that belong to a group this account owns; absent for a
    /// foreign group at risk.
    #[serde(rename = "guestDevices", default)]
    pub guest_devices: Option<u32>,
}

/// What finalizing the deletion would do to other people's data custody.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeletionImpact {
    /// Groups owned by someone else where this account's devices are the only full replicas.
    #[serde(rename = "foreignGroupsAtRisk")]
    pub foreign_groups_at_risk: Vec<ImpactGroup>,
    /// Groups this account owns that other accounts' devices belong to.
    #[serde(rename = "ownedGroupsWithGuests")]
    pub owned_groups_with_guests: Vec<ImpactGroup>,
}

impl DeletionImpact {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.foreign_groups_at_risk.is_empty() && self.owned_groups_with_guests.is_empty()
    }

    /// Every affected group id, each once, in report order.
    #[must_use]
    pub fn group_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        for group in self.foreign_groups_at_risk.iter().chain(&self.owned_groups_with_guests) {
            if !ids.contains(&group.group_id) {
                ids.push(group.group_id.clone());
            }
        }
        ids
    }
}

#[derive(Serialize)]
struct RequestBody {
    #[serde(rename = "acknowledgeImpact")]
    acknowledge_impact: bool,
}

/// The data-loss text shown before an acknowledged deletion.
pub const IMPACT_REFUSAL: &str = "deleting this account would remove other people's access, or the last full copy of a shared folder group they rely on; review the affected groups and acknowledge to proceed";

/// What deleting the account would do to other people's access and data custody. Read-only.
pub async fn deletion_impact() -> Result<DeletionImpact, CoreError> {
    deletion_impact_with(&require_auth().await?).await
}

/// [`deletion_impact`] over an authenticated session.
pub async fn deletion_impact_with(auth: &CoordinationAccess) -> Result<DeletionImpact, CoreError> {
    get_json("/account/deletion/impact", auth).await
}

/// The gate: an impact that is not empty is refused unless the person acknowledged it.
fn gate(impact: &DeletionImpact, acknowledged: bool) -> Result<(), CoreError> {
    if impact.is_empty() || acknowledged {
        return Ok(());
    }
    Err(CoreError::DurabilityBlocked {
        message: IMPACT_REFUSAL.to_owned(),
        group_ids: impact.group_ids(),
    })
}

/// Requests account deletion. Nothing is deleted yet.
///
/// Deleting an account takes its devices out of every shared folder group at
/// once, so a group that depends on them (or that other accounts belong to) is
/// reported first and the request is refused with
/// [`CoreError::DurabilityBlocked`] until `acknowledge_impact` is set: the
/// explicit override. The coordination plane applies the same rule and records
/// an acknowledged override durably, so this check is a courtesy, not the gate.
///
/// The coordination plane also requires a sign-in made in the last five
/// minutes. When there is none this fails with
/// [`CoreError::ReauthenticationRequired`]; [`request_deletion_with_step_up`] is
/// the form that signs in again and retries.
pub async fn request_deletion(acknowledge_impact: bool) -> Result<DeletionRequested, CoreError> {
    request_deletion_with(&require_auth().await?, acknowledge_impact).await
}

/// [`request_deletion`] over an authenticated session.
pub async fn request_deletion_with(
    auth: &CoordinationAccess,
    acknowledge_impact: bool,
) -> Result<DeletionRequested, CoreError> {
    let impact: DeletionImpact = get_json("/account/deletion/impact", auth).await?;
    gate(&impact, acknowledge_impact)?;
    post_request(auth, acknowledge_impact).await
}

/// The request itself, with the typed stale-sign-in refusal told apart.
async fn post_request(
    auth: &CoordinationAccess,
    acknowledge_impact: bool,
) -> Result<DeletionRequested, CoreError> {
    match post_json_with_failure(
        "/account/deletion/request",
        &RequestBody { acknowledge_impact },
        auth,
    )
    .await?
    {
        Ok(requested) => Ok(requested),
        Err(failure)
            if failure.status == 403
                && failure.code.as_deref() == Some(REAUTHENTICATION_REQUIRED) =>
        {
            Err(CoreError::ReauthenticationRequired)
        }
        Err(failure) => Err(failure.into_core_error()),
    }
}

/// The `code` the coordination plane answers a stale sign-in with.
const REAUTHENTICATION_REQUIRED: &str = "reauthentication_required";

/// [`request_deletion`], and when it needs a fresh sign-in, `step_up` runs
/// (the person signs in again as this installation) and the request is made
/// once more. A second refusal is returned as it is: there is no loop.
///
/// `step_up` never touches the device key or the registration; see
/// [`crate::ops::auth::reauthenticate`].
pub async fn request_deletion_with_step_up<F, Fut>(
    acknowledge_impact: bool,
    step_up: F,
) -> Result<DeletionRequested, CoreError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), CoreError>>,
{
    retry_after_step_up(|| request_deletion(acknowledge_impact), step_up).await
}

async fn retry_after_step_up<T, A, AF, S, SF>(mut attempt: A, step_up: S) -> Result<T, CoreError>
where
    A: FnMut() -> AF,
    AF: Future<Output = Result<T, CoreError>>,
    S: FnOnce() -> SF,
    SF: Future<Output = Result<(), CoreError>>,
{
    match attempt().await {
        Err(CoreError::ReauthenticationRequired) => {
            step_up().await?;
            attempt().await
        }
        other => other,
    }
}

/// Confirms a requested deletion with its one-time token, starting the grace
/// period.
pub async fn confirm_deletion(confirmation_token: String) -> Result<DeletionStatus, CoreError> {
    confirm_deletion_with(&require_auth().await?, &confirmation_token).await
}

/// [`confirm_deletion`] over an authenticated session.
pub async fn confirm_deletion_with(
    auth: &CoordinationAccess,
    confirmation_token: &str,
) -> Result<DeletionStatus, CoreError> {
    post_json("/account/deletion/confirm", &ConfirmRequest { confirmation_token }, auth).await
}

/// Cancels a requested or confirmed deletion before the grace period ends.
pub async fn cancel_deletion() -> Result<DeletionStatus, CoreError> {
    cancel_deletion_with(&require_auth().await?).await
}

/// [`cancel_deletion`] over an authenticated session.
pub async fn cancel_deletion_with(auth: &CoordinationAccess) -> Result<DeletionStatus, CoreError> {
    post_json("/account/deletion/cancel", &(), auth).await
}

pub async fn deletion_status() -> Result<DeletionStatus, CoreError> {
    deletion_status_with(&require_auth().await?).await
}

/// [`deletion_status`] over an authenticated session.
pub async fn deletion_status_with(auth: &CoordinationAccess) -> Result<DeletionStatus, CoreError> {
    get_json("/account/deletion/status", auth).await
}

/// The raw versioned export document. The server builds it from an allowlist
/// and it is content-blind by construction: it never holds file contents,
/// names or paths.
pub async fn export_account() -> Result<serde_json::Value, CoreError> {
    let auth = require_auth().await?;
    get_json("/account/export", &auth).await
}

/// The export document pretty-printed as JSON.
pub async fn export_account_json() -> Result<String, CoreError> {
    let document = export_account().await?;
    Ok(serde_json::to_string_pretty(&document)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(id: &str) -> ImpactGroup {
        ImpactGroup { group_id: id.into(), name: id.into(), guest_devices: None }
    }

    fn impact(foreign: &[&str], owned: &[&str]) -> DeletionImpact {
        DeletionImpact {
            foreign_groups_at_risk: foreign.iter().map(|g| group(g)).collect(),
            owned_groups_with_guests: owned.iter().map(|g| group(g)).collect(),
        }
    }

    #[test]
    fn an_empty_impact_needs_no_acknowledgement() {
        assert!(gate(&impact(&[], &[]), false).is_ok());
    }

    #[test]
    fn an_impact_is_refused_without_acknowledgement_and_names_each_group_once() {
        let blocked = gate(&impact(&["a", "b"], &["b", "c"]), false).unwrap_err();
        match blocked {
            CoreError::DurabilityBlocked { group_ids, .. } => {
                assert_eq!(group_ids, vec!["a", "b", "c"]);
            }
            other => panic!("expected DurabilityBlocked, got {other:?}"),
        }
    }

    #[test]
    fn an_acknowledged_impact_proceeds() {
        assert!(gate(&impact(&["a"], &["b"]), true).is_ok());
    }

    #[test]
    fn the_impact_document_decodes() {
        let doc = serde_json::json!({
            "foreignGroupsAtRisk": [{"groupId": "g1", "name": "Docs"}],
            "ownedGroupsWithGuests": [{"groupId": "g2", "name": "Mine", "guestDevices": 2}],
        });
        let decoded: DeletionImpact = serde_json::from_value(doc).unwrap();
        assert_eq!(decoded.foreign_groups_at_risk[0].guest_devices, None);
        assert_eq!(decoded.owned_groups_with_guests[0].guest_devices, Some(2));
    }

    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// An offline credential for the coordination service `server` stands in for.
    fn access(server: &MockServer) -> crate::coordination::http_client::CoordinationAccess {
        crate::coordination::http_client::CoordinationAccess::new(
            yadorilink_fapi_client::test_support::offline_auth(),
            server.uri(),
        )
    }

    async fn impact_of(server: &MockServer, foreign: &[&str]) {
        let groups: Vec<_> =
            foreign.iter().map(|g| serde_json::json!({"groupId": g, "name": g})).collect();
        Mock::given(method("GET"))
            .and(path("/account/deletion/impact"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "foreignGroupsAtRisk": groups,
                "ownedGroupsWithGuests": [],
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_deletion_with_an_impact_is_refused_before_the_request_is_sent() {
        let server = MockServer::start().await;
        impact_of(&server, &["g1"]).await;
        let auth = access(&server);
        let refused = request_deletion_with(&auth, false).await.unwrap_err();
        assert!(
            matches!(refused, CoreError::DurabilityBlocked { ref group_ids, .. } if group_ids == &["g1"])
        );
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|r| r.url.path() != "/account/deletion/request"));
    }

    #[tokio::test]
    async fn an_acknowledged_deletion_is_requested_with_the_acknowledgement_and_returns_its_token()
    {
        let server = MockServer::start().await;
        impact_of(&server, &["g1"]).await;
        Mock::given(method("POST"))
            .and(path("/account/deletion/request"))
            .and(body_json(serde_json::json!({"acknowledgeImpact": true})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"confirmationToken": "t-1"})),
            )
            .mount(&server)
            .await;
        let auth = access(&server);
        let requested = request_deletion_with(&auth, true).await.unwrap();
        assert_eq!(requested.confirmation_token, "t-1");
    }

    #[tokio::test]
    async fn confirm_cancel_and_status_speak_the_deletion_routes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/account/deletion/confirm"))
            .and(body_json(serde_json::json!({"confirmationToken": "t-1"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "grace", "graceExpiresAtUnix": 100, "remainingSecs": 50,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/account/deletion/cancel"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"state": "active"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/account/deletion/status"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"state": "active"})),
            )
            .mount(&server)
            .await;
        let auth = access(&server);
        let confirmed = confirm_deletion_with(&auth, "t-1").await.unwrap();
        assert_eq!((confirmed.state.as_str(), confirmed.remaining_secs), ("grace", Some(50)));
        assert_eq!(cancel_deletion_with(&auth).await.unwrap().state, "active");
        assert_eq!(deletion_status_with(&auth).await.unwrap().state, "active");
    }
}

#[cfg(test)]
mod reauthentication_tests;
