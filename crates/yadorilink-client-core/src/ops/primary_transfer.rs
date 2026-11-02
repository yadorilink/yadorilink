//! Handing a folder's primary ownership to another person.
//!
//! The primary owner of a folder group is an ACCOUNT. The hand-over is two steps because the
//! folder moves onto the target's quota and the target inherits the right to delete it: the
//! primary OFFERS to a device that is an active member of another account, and the target
//! account ACCEPTS (any of its devices may), DECLINES, or the primary CANCELS. An offer lasts
//! seven days and a folder has at most one pending offer. After an accept the old primary keeps a
//! delegated Owner seat; every member learns the new owner through the normal membership refresh.
//!
//! Account-level HTTP calls (`/shares/groups/:id/primary-transfer/*`, `/shares/primary-transfers`),
//! authenticated like every other share mutation. The engine only relays: authority is decided by
//! the service, and a refusal is typed by its `reason` ([`PrimaryTransferRefusal`]), never by text.
//! The call needs the service; nothing is queued offline.
//!
//! Every mutation carries a client-made `operationId`. It is kept on disk (the pending-request
//! store the provider-folder creations use) BEFORE the request is sent and forgotten only on a
//! definitive answer, so a retry after a lost reply, even after a restart, replays the original
//! outcome instead of making a second one. A different request gets its own id.

use std::path::Path;

use serde::Deserialize;

use super::provider_pending::PendingStore;
use crate::coordination::http_client::{
    get_json, post_json_with_failure, require_auth, ApiFailure, CoordinationAccess,
};
use crate::error::{CoreError, LimitKind, PrimaryTransferRefusal};

/// Which side of an offer the caller is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    /// The caller's account offered its folder.
    Outgoing,
    /// The caller's account is offered a folder.
    Incoming,
    /// A direction a newer service added.
    #[serde(other)]
    Unrecognized,
}

/// One pending offer, as the service lists it. It carries no account id, email or name of the
/// other side; `to_device_id` is the device the primary named.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrimaryTransfer {
    pub transfer_id: String,
    pub group_id: String,
    pub group_name: String,
    pub direction: TransferDirection,
    /// The service's status word (`pending` while it is listed).
    pub status: String,
    pub to_device_id: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
}

/// What accepting an offer produced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrimaryTransferAccepted {
    pub transfer_id: String,
    pub group_id: String,
    /// The folder's membership generation after the hand-over.
    pub membership_generation: u64,
}

#[derive(Deserialize)]
struct TransferEnvelope {
    transfer: PrimaryTransfer,
}

#[derive(Deserialize)]
struct TransferList {
    transfers: Vec<PrimaryTransfer>,
}

fn offer_body(operation_id: &str, target_device_id: &str) -> serde_json::Value {
    serde_json::json!({ "operationId": operation_id, "targetDeviceId": target_device_id })
}

fn settle_body(operation_id: &str, transfer_id: &str) -> serde_json::Value {
    serde_json::json!({ "transferId": transfer_id, "operationId": operation_id })
}

fn route(group_id: &str, step: &str) -> String {
    format!("/shares/groups/{group_id}/primary-transfer/{step}")
}

/// The typed refusal a failed answer carries, or the generic classification.
fn failure_to_error(failure: ApiFailure) -> CoreError {
    let body = failure.body();
    let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    if error == "primary_transfer_refused" {
        let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        return match PrimaryTransferRefusal::from_reason(reason) {
            Some(refusal) => CoreError::PrimaryTransferRefused(refusal),
            None => CoreError::Other(format!("primary_transfer_refused: {reason}")),
        };
    }
    if failure.status == 404 {
        return CoreError::PrimaryTransferRefused(PrimaryTransferRefusal::NotFound);
    }
    if failure.status == 409 && error == "operation_conflict" {
        return CoreError::PrimaryTransferRefused(PrimaryTransferRefusal::Conflict);
    }
    failure.into_core_error()
}

/// Whether the answer settles the request for good: it was done, or refused in a way a retry of
/// the same request cannot change. Anything else (no connection, a stalled or 5xx answer, a
/// session problem) may have reached the service, so the id stays for the retry.
fn is_definitive(result: &Result<(), &CoreError>) -> bool {
    match result {
        Ok(()) => true,
        Err(
            CoreError::PrimaryTransferRefused(_)
            | CoreError::Forbidden(_)
            | CoreError::LimitExceeded { kind: LimitKind::Quota, .. },
        ) => true,
        Err(_) => false,
    }
}

/// Sends one mutation under its durable operation id.
async fn mutate<Resp: serde::de::DeserializeOwned>(
    state_dir: &Path,
    signature: String,
    auth: &CoordinationAccess,
    path: &str,
    body: impl FnOnce(&str) -> serde_json::Value,
) -> Result<Resp, CoreError> {
    let store = PendingStore::at(state_dir.join("provider-pending.json"));
    let operation_id = store.token_for(&signature).map_err(|e| {
        CoreError::Other(format!("could not record the request before sending it: {e}"))
    })?;
    let request = body(&operation_id);
    let result = match post_json_with_failure::<serde_json::Value, Resp>(path, &request, auth).await
    {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(failure)) => Err(failure_to_error(failure)),
        Err(error) => Err(error),
    };
    if is_definitive(&result.as_ref().map(|_| ())) {
        store.clear(&signature);
    }
    result
}

fn signature(kind: &str, group_id: &str, subject: &str) -> String {
    format!("primary-transfer\u{1f}{kind}\u{1f}{group_id}\u{1f}{subject}")
}

/// Offers `group_id`'s primary ownership to the account that owns `target_device_id`, an active
/// member device of the folder. The caller must be the folder's primary owner.
pub async fn offer_in(
    auth: &CoordinationAccess,
    state_dir: &Path,
    group_id: &str,
    target_device_id: &str,
) -> Result<PrimaryTransfer, CoreError> {
    let envelope: TransferEnvelope = mutate(
        state_dir,
        signature("offer", group_id, target_device_id),
        auth,
        &route(group_id, "offer"),
        |operation_id| offer_body(operation_id, target_device_id),
    )
    .await?;
    Ok(envelope.transfer)
}

/// Withdraws a pending offer the caller's account made.
pub async fn cancel_in(
    auth: &CoordinationAccess,
    state_dir: &Path,
    group_id: &str,
    transfer_id: &str,
) -> Result<PrimaryTransfer, CoreError> {
    settle(auth, state_dir, "cancel", group_id, transfer_id).await
}

/// Turns down an offer made to the caller's account.
pub async fn decline_in(
    auth: &CoordinationAccess,
    state_dir: &Path,
    group_id: &str,
    transfer_id: &str,
) -> Result<PrimaryTransfer, CoreError> {
    settle(auth, state_dir, "decline", group_id, transfer_id).await
}

async fn settle(
    auth: &CoordinationAccess,
    state_dir: &Path,
    step: &str,
    group_id: &str,
    transfer_id: &str,
) -> Result<PrimaryTransfer, CoreError> {
    let envelope: TransferEnvelope = mutate(
        state_dir,
        signature(step, group_id, transfer_id),
        auth,
        &route(group_id, step),
        |operation_id| settle_body(operation_id, transfer_id),
    )
    .await?;
    Ok(envelope.transfer)
}

/// Accepts an offer made to the caller's account (any device of it may): the folder moves onto
/// this account, which becomes its primary owner.
pub async fn accept_in(
    auth: &CoordinationAccess,
    state_dir: &Path,
    group_id: &str,
    transfer_id: &str,
) -> Result<PrimaryTransferAccepted, CoreError> {
    mutate(
        state_dir,
        signature("accept", group_id, transfer_id),
        auth,
        &route(group_id, "accept"),
        |operation_id| settle_body(operation_id, transfer_id),
    )
    .await
}

/// The pending, unexpired offers this account made or received.
pub async fn list_with(auth: &CoordinationAccess) -> Result<Vec<PrimaryTransfer>, CoreError> {
    let list: TransferList = get_json("/shares/primary-transfers", auth).await?;
    Ok(list.transfers)
}

fn process_state_dir() -> Result<std::path::PathBuf, CoreError> {
    Ok(crate::coordination::device_config::config_dir()?)
}

/// [`offer_in`] for this process's own account and state directory.
pub async fn offer(group_id: &str, target_device_id: &str) -> Result<PrimaryTransfer, CoreError> {
    let auth = require_auth().await?;
    offer_in(&auth, &process_state_dir()?, group_id, target_device_id).await
}

/// [`cancel_in`] for this process's own account and state directory.
pub async fn cancel(group_id: &str, transfer_id: &str) -> Result<PrimaryTransfer, CoreError> {
    let auth = require_auth().await?;
    cancel_in(&auth, &process_state_dir()?, group_id, transfer_id).await
}

/// [`decline_in`] for this process's own account and state directory.
pub async fn decline(group_id: &str, transfer_id: &str) -> Result<PrimaryTransfer, CoreError> {
    let auth = require_auth().await?;
    decline_in(&auth, &process_state_dir()?, group_id, transfer_id).await
}

/// [`accept_in`] for this process's own account and state directory.
pub async fn accept(
    group_id: &str,
    transfer_id: &str,
) -> Result<PrimaryTransferAccepted, CoreError> {
    let auth = require_auth().await?;
    accept_in(&auth, &process_state_dir()?, group_id, transfer_id).await
}

/// Which settling call a selection is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettleStep {
    /// The target account takes the folder over.
    Accept,
    /// The target account turns the offer down.
    Decline,
    /// The primary withdraws its offer.
    Cancel,
}

impl SettleStep {
    fn word(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Decline => "decline",
            Self::Cancel => "cancel",
        }
    }

    /// The side of an offer this step is taken from.
    #[must_use]
    pub fn direction(self) -> TransferDirection {
        match self {
            Self::Accept | Self::Decline => TransferDirection::Incoming,
            Self::Cancel => TransferDirection::Outgoing,
        }
    }
}

/// The offer a loosely named selector stands for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedOffer {
    pub group_id: String,
    pub transfer_id: String,
    /// The folder's name; the selector as typed when the offer is no longer listed.
    pub group_name: String,
}

/// The offer `selector` (an offer id, a folder id or a folder name) names for `step`.
///
/// The offers the service still lists come first. A settling call whose reply was lost may have
/// been done by the service, which then no longer lists the offer; the call's operation id is
/// still on disk, and repeating the call replays its outcome. So an offer that is not listed
/// is also looked for among those unsettled calls, and selected from there, instead of being
/// reported as not found before the call can be repeated.
///
/// # Errors
/// [`PrimaryTransferRefusal::NotFound`] when nothing matches; [`CoreError::Other`] when several
/// offers do (the person names one by its offer id).
pub async fn select_offer_in(
    auth: &CoordinationAccess,
    state_dir: &Path,
    step: SettleStep,
    selector: &str,
) -> Result<SelectedOffer, CoreError> {
    let listed = list_with(auth).await?;
    let found = find_offer(&listed, selector, step.direction());
    let mut candidates: Vec<SelectedOffer> = found
        .into_iter()
        .map(|t| SelectedOffer {
            group_id: t.group_id.clone(),
            transfer_id: t.transfer_id.clone(),
            group_name: t.group_name.clone(),
        })
        .collect();
    if candidates.is_empty() {
        candidates = unsettled_calls(auth, state_dir, step, selector).await?;
    }
    match candidates.as_slice() {
        [] => Err(CoreError::PrimaryTransferRefused(PrimaryTransferRefusal::NotFound)),
        [one] => Ok(one.clone()),
        _ => Err(CoreError::Other(format!(
            "more than one pending offer matches {selector:?}; name one by its offer id \
             (`yadorilink share transfer list`)"
        ))),
    }
}

/// The calls of `step` that were sent and never answered for good, whose folder or offer
/// `selector` names (a folder name is looked up only if the ids do not match).
async fn unsettled_calls(
    auth: &CoordinationAccess,
    state_dir: &Path,
    step: SettleStep,
    selector: &str,
) -> Result<Vec<SelectedOffer>, CoreError> {
    let store = PendingStore::at(state_dir.join("provider-pending.json"));
    let signatures = store
        .signatures()
        .map_err(|e| CoreError::Other(format!("could not read the unanswered requests: {e}")))?;
    let prefix = signature(step.word(), "", "");
    let prefix = prefix.trim_end_matches('\u{1f}');
    let mut calls: Vec<(String, String)> = signatures
        .iter()
        .filter_map(|s| s.strip_prefix(prefix)?.strip_prefix('\u{1f}'))
        .filter_map(|rest| rest.split_once('\u{1f}'))
        .map(|(group, transfer)| (group.to_owned(), transfer.to_owned()))
        .collect();
    if calls.is_empty() {
        return Ok(Vec::new());
    }
    let by_id = |(group, transfer): &(String, String)| group == selector || transfer == selector;
    if !calls.iter().any(by_id) {
        // Only now is the name worth a lookup; a name that resolves nowhere matches nothing.
        let Ok(named) = super::shares::resolve_group_id(auth, selector).await else {
            return Ok(Vec::new());
        };
        calls.retain(|(group, _)| *group == named);
    } else {
        calls.retain(by_id);
    }
    Ok(calls
        .into_iter()
        .map(|(group_id, transfer_id)| SelectedOffer {
            group_id,
            transfer_id,
            group_name: selector.to_owned(),
        })
        .collect())
}

/// This process's own account and state directory, for the `*_in` calls.
pub async fn process_context() -> Result<(CoordinationAccess, std::path::PathBuf), CoreError> {
    Ok((require_auth().await?, process_state_dir()?))
}

/// [`list_with`] for this process's own account.
pub async fn list() -> Result<Vec<PrimaryTransfer>, CoreError> {
    let auth = require_auth().await?;
    list_with(&auth).await
}

/// The offers in `transfers` that match `selector`: a transfer id, or a folder name / id (an
/// offer's folder). Used by front ends that let a person name an offer loosely.
#[must_use]
pub fn find_offer<'a>(
    transfers: &'a [PrimaryTransfer],
    selector: &str,
    direction: TransferDirection,
) -> Vec<&'a PrimaryTransfer> {
    transfers
        .iter()
        .filter(|t| t.direction == direction)
        .filter(|t| t.transfer_id == selector || t.group_id == selector || t.group_name == selector)
        .collect()
}

#[cfg(test)]
mod tests;
