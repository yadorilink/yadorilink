//! Telling the coordination service that this device replaces another one (`POST
//! /devices/supersede`), the request a start over sends after the new device registered.
//!
//! The service marks the old device superseded and revokes it only against a proof made by the
//! NEW device's signing key over `yadorilink-device-supersede-v1\n<account>\n<old>\n<new>`. The
//! proof is made here with the key at hand and nothing about the key leaves the process; the
//! request is idempotent, so the same call may be sent again after an interruption.
//!
//! The new device may still be registered to an installation that was signed out before this
//! sign-in (a refused request asks for a fresh sign-in, which is a new installation): the service
//! then binds the device to the current installation as part of the same request, after the same
//! checks, so nothing here re-registers.
//!
//! The account id is the `sub` of the id token the sign-in received. It is kept beside the
//! credential (`account_id` in the state directory) at sign-in, because nothing else on the client
//! knows it. A wrong value only makes the proof fail at the service.

use std::path::Path;

use crate::coordination::http_client::CoordinationAccess;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::coordination::device_config;
use crate::coordination::http_client::{post_json_with_failure, require_auth, ApiFailure};
use crate::error::CoreError;

const ACCOUNT_ID_FILE: &str = "account_id";
const PROOF_DOMAIN: &str = "yadorilink-device-supersede-v1";
const REAUTHENTICATION_REQUIRED: &str = "reauthentication_required";
const INSTALLATION_NOT_SIGNED_OUT: &str = "installation_not_signed_out";

/// What the service answered to a supersede request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersedeResponse {
    pub old_device_id: String,
    pub new_device_id: String,
    pub superseded_at_unix: u64,
    /// `healthy` or `replacement-unconfirmed`; anything else is treated as unconfirmed.
    pub protection: String,
    #[serde(default)]
    pub unconfirmed_group_ids: Vec<String>,
}

impl SupersedeResponse {
    /// Protection may be shown as healthy only when the service said so.
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        self.protection == "healthy"
    }
}

/// Why a supersede request did not succeed.
#[derive(Debug)]
pub enum SupersedeError {
    /// The sign-in is older than the service accepts for replacing a device (or none was
    /// recorded): sign in again, then run the start over again.
    ReauthenticationRequired,
    /// The new device is registered to another installation that is still signed in. The service
    /// moves a device to the current installation only after the installation that registered it
    /// was signed out: sign that one out, sign in again, then run the start over again.
    InstallationNotSignedOut,
    /// The old device was already replaced by a different device.
    AlreadyReplaced,
    /// Anything else, including a service that could not be reached: the request may be sent again.
    Failed(CoreError),
}

impl From<CoreError> for SupersedeError {
    fn from(error: CoreError) -> Self {
        Self::Failed(error)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SupersedeRequest<'a> {
    old_device_id: &'a str,
    new_device_id: &'a str,
    new_device_proof_base64: String,
}

/// The exact bytes the new device signs.
#[must_use]
pub fn proof_message(account_id: &str, old_device_id: &str, new_device_id: &str) -> Vec<u8> {
    format!("{PROOF_DOMAIN}\n{account_id}\n{old_device_id}\n{new_device_id}").into_bytes()
}

/// The `sub` claim of an id token, read without verifying it (the token came over the sign-in's
/// own TLS connection to the service and only names the account in a proof the service checks).
#[must_use]
pub fn subject_of_id_token(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("sub")?.as_str().filter(|sub| !sub.is_empty()).map(str::to_owned)
}

/// Keeps the account id of the sign-in that just finished (or forgets the previous one when this
/// sign-in did not name an account). Best effort: a missing record is reported later, when it is
/// needed, as a request to sign in again.
pub(crate) fn record_account_id(dir: &Path, id_token: Option<&str>) {
    let path = dir.join(ACCOUNT_ID_FILE);
    match id_token.and_then(subject_of_id_token) {
        Some(account_id) => {
            let _ = std::fs::write(&path, account_id);
        }
        None => {
            let _ = yadorilink_fs_platform::durable_dir::remove_file_durably(&path);
        }
    }
}

/// Whether a sign-in's id token names a different account than the one recorded for this
/// installation. Only a recorded account and a named one can differ: with either missing there is
/// nothing to compare, and the caller goes on.
pub(crate) fn is_other_account(dir: &Path, id_token: Option<&str>) -> bool {
    match (recorded_account_id(dir), id_token.and_then(subject_of_id_token)) {
        (Some(recorded), Some(signed_in)) => recorded != signed_in,
        _ => false,
    }
}

fn recorded_account_id(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join(ACCOUNT_ID_FILE)).ok()?;
    let id = text.trim();
    (!id.is_empty()).then(|| id.to_owned())
}

/// Sends the supersede claim for `old_device_id`, proven by the signing key in the state
/// directory (the key of `new_device_id`).
///
/// # Errors
/// [`SupersedeError`]; nothing is changed locally.
pub async fn supersede_device(
    old_device_id: &str,
    new_device_id: &str,
) -> Result<SupersedeResponse, SupersedeError> {
    let dir = device_config::config_dir().map_err(CoreError::from)?;
    let Some(account_id) = recorded_account_id(&dir) else {
        return Err(SupersedeError::ReauthenticationRequired);
    };
    let key = yadorilink_transport::DeviceSigningKeyPair::load_existing(
        dir.join("signing_key"),
        crate::coordination::credential_store::key_mirror(),
    )
    .map_err(|e| CoreError::Other(e.to_string()))?;
    let auth = require_auth().await?;
    send(&auth, &key, &account_id, old_device_id, new_device_id).await
}

/// [`supersede_device`] over the state directory `dir` and the credential `settings` of a host
/// that names them (the embedded engine), instead of the process environment's.
///
/// # Errors
/// [`SupersedeError`]; nothing is changed locally.
pub async fn supersede_device_in(
    dir: &Path,
    settings: &crate::coordination::credential_store::CredentialSettings,
    old_device_id: &str,
    new_device_id: &str,
) -> Result<SupersedeResponse, SupersedeError> {
    let Some(account_id) = recorded_account_id(dir) else {
        return Err(SupersedeError::ReauthenticationRequired);
    };
    let key = yadorilink_transport::DeviceSigningKeyPair::load_existing(
        dir.join("signing_key"),
        settings.key_mirror,
    )
    .map_err(|e| CoreError::Other(e.to_string()))?;
    let auth = crate::coordination::http_client::require_auth_in(dir, settings).await?;
    send(&auth, &key, &account_id, old_device_id, new_device_id).await
}

async fn send(
    auth: &CoordinationAccess,
    key: &yadorilink_transport::DeviceSigningKeyPair,
    account_id: &str,
    old_device_id: &str,
    new_device_id: &str,
) -> Result<SupersedeResponse, SupersedeError> {
    let proof = key.sign_detached(&proof_message(account_id, old_device_id, new_device_id));
    let request = SupersedeRequest {
        old_device_id,
        new_device_id,
        new_device_proof_base64: base64::engine::general_purpose::STANDARD.encode(proof),
    };
    match post_json_with_failure("/devices/supersede", &request, auth).await? {
        Ok(response) => Ok(response),
        Err(failure) => Err(classify(failure)),
    }
}

fn classify(failure: ApiFailure) -> SupersedeError {
    if failure.status == 403 && failure.code.as_deref() == Some(REAUTHENTICATION_REQUIRED) {
        SupersedeError::ReauthenticationRequired
    } else if failure.status == 403 && failure.code.as_deref() == Some(INSTALLATION_NOT_SIGNED_OUT)
    {
        SupersedeError::InstallationNotSignedOut
    } else if failure.status == 409 {
        SupersedeError::AlreadyReplaced
    } else if failure.status == 404 {
        // Either the retired device is not on this account, or this service does not offer the
        // route yet (a client newer than the service fails closed rather than skipping the claim).
        SupersedeError::Failed(CoreError::Other(
            "the coordination service does not know the retired device on this account, or does \
             not support replacing devices yet; nothing was changed, try again after the service \
             is updated"
                .to_owned(),
        ))
    } else {
        SupersedeError::Failed(failure.into_core_error())
    }
}

#[cfg(test)]
mod tests;
