//! Self-service account management: the account-deletion lifecycle and the
//! account data export, over the coordination plane's `/account/*` routes.
//!
//! Both operate only on server-side coordination records; neither ever
//! touches the folders synced on the user's machines (see
//! `wording::LOCAL_FIRST_NOTICE`).

use serde::{Deserialize, Serialize};

use crate::coordination::http_client::{get_json, post_json, require_auth};
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

// Deliberately no durability handoff gate here, unlike removing a device:
// account deletion destroys every folder group this account owns, so there
// is no other replica to hand off to -- and it already goes through its own
// grace period plus an explicit confirmation token before anything is
// destroyed.

/// Requests account deletion. Nothing is deleted yet.
pub async fn request_deletion() -> Result<DeletionRequested, CoreError> {
    let auth = require_auth().await?;
    post_json("/account/deletion/request", &(), &auth).await
}

/// Confirms a requested deletion with its one-time token, starting the grace
/// period.
pub async fn confirm_deletion(confirmation_token: String) -> Result<DeletionStatus, CoreError> {
    let auth = require_auth().await?;
    post_json(
        "/account/deletion/confirm",
        &ConfirmRequest { confirmation_token: &confirmation_token },
        &auth,
    )
    .await
}

/// Cancels a requested or confirmed deletion before the grace period ends.
pub async fn cancel_deletion() -> Result<DeletionStatus, CoreError> {
    let auth = require_auth().await?;
    post_json("/account/deletion/cancel", &(), &auth).await
}

pub async fn deletion_status() -> Result<DeletionStatus, CoreError> {
    let auth = require_auth().await?;
    get_json("/account/deletion/status", &auth).await
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
