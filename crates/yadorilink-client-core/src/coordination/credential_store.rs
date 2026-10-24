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

/// How one installation stores and reaches its credentials. The CLI builds it from the process
/// environment ([`CredentialSettings::from_env`]); an embedding host gives its own, so a host
/// never depends on the environment.
#[derive(Debug, Clone)]
pub struct CredentialSettings {
    /// Which store holds the credential.
    pub backend: yadorilink_fapi_client::store::Backend,
    /// Whether the device key is mirrored into the OS keyring.
    pub key_mirror: yadorilink_transport::KeyMirror,
    /// The Authorization Server to use instead of the stored credential's issuer.
    pub auth_server_addr: Option<String>,
    /// The coordination service the account commands talk to (sign-in, device registration,
    /// sign-out, account deletion). `None` is the build's own address, else loopback; see
    /// [`CredentialSettings::coordination_addr`].
    pub coordination_addr: Option<String>,
    /// How this machine names itself on the approval page of a sign-in. `None` is a generic
    /// label.
    pub host_name: Option<String>,
}

impl CredentialSettings {
    /// Settings for an embedding host: the given store and key mirror, with every address
    /// the build's default.
    #[must_use]
    pub fn new(
        backend: yadorilink_fapi_client::store::Backend,
        key_mirror: yadorilink_transport::KeyMirror,
    ) -> Self {
        Self {
            backend,
            key_mirror,
            auth_server_addr: None,
            coordination_addr: None,
            host_name: None,
        }
    }

    /// The environment's selection for the state directory `dir`:
    /// `YADORILINK_CREDENTIAL_STORE`, `YADORILINK_CREDENTIAL_FILE`,
    /// `YADORILINK_DISABLE_OS_KEYRING`, `YADORILINK_AUTH_SERVER_ADDR`,
    /// `YADORILINK_COORDINATION_ADDR` and the machine's host name. This is the one place the
    /// client layer reads them; everything below is handed the result.
    pub fn from_env(dir: &std::path::Path) -> Result<Self, CoreError> {
        Ok(Self {
            backend: yadorilink_fapi_client::store::Backend::from_env(dir)?,
            key_mirror: yadorilink_transport::KeyMirror::from_env(),
            auth_server_addr: std::env::var(crate::coordination::http_client::AUTH_SERVER_ADDR_VAR)
                .ok(),
            coordination_addr: std::env::var(
                crate::coordination::http_client::COORDINATION_ADDR_VAR,
            )
            .ok(),
            host_name: std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")).ok(),
        })
    }

    /// The coordination endpoint: the setting if it names one, else the build-time default, else
    /// loopback. The single resolver for the request base URL and for the endpoint recorded in
    /// `device.json` at registration.
    #[must_use]
    pub fn coordination_addr(&self) -> String {
        crate::coordination::http_client::resolve_coordination_addr(
            self.coordination_addr.as_deref(),
            crate::coordination::http_client::COMPILED_COORDINATION_ADDR,
        )
    }
}

/// Whether this process mirrors the device key into the OS keyring: the CLI's mapping of
/// `YADORILINK_DISABLE_OS_KEYRING`, read where the command starts.
#[must_use]
pub fn key_mirror() -> yadorilink_transport::KeyMirror {
    yadorilink_transport::KeyMirror::from_env()
}

/// Open the credential store this process should use.
///
/// Built per call rather than cached: `YADORILINK_CONFIG_DIR` and
/// `YADORILINK_CREDENTIAL_STORE` are read at open time, so a test (or a user
/// running one command against a different profile) gets the directory it
/// asked for rather than the one the first call happened to see.
pub fn open() -> Result<CredentialStore, CoreError> {
    let dir = process_dir()?;
    open_in(&dir, &CredentialSettings::from_env(&dir)?)
}

/// The state directory this process was configured with, once it is known that the credential
/// store it selects may be used: the directory is allowed, and so is a credential file the
/// environment names elsewhere.
pub fn process_dir() -> Result<std::path::PathBuf, CoreError> {
    let dir = crate::coordination::device_config::config_dir()?;
    // The credential file backend may be pointed elsewhere; that place is checked too.
    yadorilink_fs_platform::state_dir::process_override(
        yadorilink_fs_platform::state_dir::PathOverride::CredentialFile,
    )?;
    Ok(dir)
}

/// The credential store of the state directory `dir`, for a host that names its directory
/// instead of leaving it to the environment.
pub fn open_in(
    dir: &std::path::Path,
    settings: &CredentialSettings,
) -> Result<CredentialStore, CoreError> {
    Ok(CredentialStore::with_backend(settings.backend.clone(), dir))
}

/// This installation's OAuth credentials, if it has enrolled.
pub fn installation() -> Result<Option<Credentials>, CoreError> {
    Ok(open()?.load()?)
}

/// [`installation`] for the state directory `dir`.
pub fn installation_in(
    dir: &std::path::Path,
    settings: &CredentialSettings,
) -> Result<Option<Credentials>, CoreError> {
    Ok(open_in(dir, settings)?.load()?)
}

/// Forget every credential this machine holds for YadoriLink.
///
/// A failure is returned rather than logged. A logout that could not remove a
/// credential has not logged anyone out, and the previous implementation's
/// `tracing::warn!` meant a user on a machine they were about to hand over
/// would see "Logged out." and a live session.
pub async fn clear() -> Result<(), CoreError> {
    clear_store(open()?).await
}

/// [`clear`] for the state directory `dir`.
pub async fn clear_in(
    dir: &std::path::Path,
    settings: &CredentialSettings,
) -> Result<(), CoreError> {
    clear_store(open_in(dir, settings)?).await
}

async fn clear_store(store: CredentialStore) -> Result<(), CoreError> {
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
