//! This crate's binding to the one credential store.
//!
//! There used to be two implementations of the same contract -- this crate's
//! `token_store.rs` and `yadorilink-daemon`'s -- each opening its own
//! `keyring::Entry` under its own idea of the key names, with the CLI writing
//! an access token and the daemon reading it. They have been replaced by
//! [`yadorilink_fapi_client::store`], which holds what is actually durable
//! (the `client_id`, the client private key and the refresh token), refuses a
//! store it cannot fully understand, and takes a cross-process lock before
//! rotating anything.
//!
//! What is left here is the binding, and it is one function: where this
//! process's config directory is. The daemon's equivalent module is the same
//! function over its own `config_dir`, which is deliberately the only thing
//! the two have left in common.
//!
//! # There is one credential shape, and no second place to look
//!
//! This module used to expose `legacy_access_token`, `legacy_refresh_token`
//! and `save_legacy_session` for the pre-cutover coordination plane -- an
//! access token and a refresh token minted by `/auth/google/*` and validated
//! against the `sessions` table. They are gone, with that plane. An
//! installation holds [`Credentials`] or it holds nothing, and "nothing" means
//! not enrolled rather than "try the older store".

use crate::error::CoreError;
use yadorilink_fapi_client::store::{CredentialStore, Credentials};
use yadorilink_fapi_client::DEFAULT_LOCK_TIMEOUT;

/// Open the credential store this process should use.
///
/// Built per call rather than cached: `YADORILINK_CONFIG_DIR` and
/// `YADORILINK_CREDENTIAL_STORE` are read at open time, so a test (or a user
/// running one command against a different profile) gets the directory it
/// asked for rather than the one the first call happened to see.
pub fn open() -> Result<CredentialStore, CoreError> {
    let dir = crate::coordination::device_config::config_dir()?;
    // The credential file backend may be pointed elsewhere; that place is checked too.
    yadorilink_fs_platform::state_dir::process_override(
        yadorilink_fs_platform::state_dir::PathOverride::CredentialFile,
    )?;
    Ok(CredentialStore::configure_from_env(&dir)?)
}

/// This installation's OAuth credentials, if it has enrolled.
pub fn installation() -> Result<Option<Credentials>, CoreError> {
    Ok(open()?.load()?)
}

/// Forget every credential this machine holds for YadoriLink.
///
/// A failure is returned rather than logged. A logout that could not remove a
/// credential has not logged anyone out, and the previous implementation's
/// `tracing::warn!` meant a user on a machine they were about to hand over
/// would see "Logged out." and a live session.
pub async fn clear() -> Result<(), CoreError> {
    let store = open()?;
    let lock = store.lock(DEFAULT_LOCK_TIMEOUT).await?;
    Ok(store.clear(&lock)?)
}

/// Remove everything this machine keeps in its credential store, locally only
/// (see [`CredentialStore::purge_local`]). Succeeds when nothing is stored.
pub async fn purge_local() -> Result<(), CoreError> {
    let store = open()?;
    let lock = store.lock(DEFAULT_LOCK_TIMEOUT).await?;
    Ok(store.purge_local(&lock)?)
}
