//! This crate's binding to the one credential store.
//!
//! This module used to be an eleven-line copy of `yadorilink-cli`'s
//! `token_store.rs` that read the access token the CLI had written. Two
//! implementations of one contract is one too many, and the contract itself
//! was wrong: an access token lives five minutes
//! (the coordination service), so a daemon that reads
//! one at startup is authenticated until its first coffee break.
//!
//! The store is now [`yadorilink_fapi_client::store`] and the thing that keeps
//! a daemon authenticated is [`yadorilink_fapi_client::CredentialManager`],
//! which holds the access token in memory and refreshes it before it dies.
//! What is left here is the binding: which directory this process's
//! credentials live in.
//!
//! # The daemon holds a credential, not a token
//!
//! `app.rs` used to read one access token here at startup and hand copies of
//! it to the coordination client, the netmap subscriber and the NAT prober.
//! That is gone. [`coordination_auth`] returns a
//! [`yadorilink_fapi_client::CoordinationAuth`] built over one shared
//! [`yadorilink_fapi_client::CredentialManager`], and every subsystem holds a
//! clone of it -- an `Arc`, so all of them refresh through the same in-memory
//! cache and the same cross-process rotation lock rather than each rotating
//! the stored refresh token on its own. A refresh-token replay is not a
//! harmless 400: it fires the server's reuse defence and takes the whole grant
//! family down.

use std::path::PathBuf;
use std::sync::Arc;

use yadorilink_fapi_client::store::{CredentialStore, Credentials, StoreError};
use yadorilink_fapi_client::{CoordinationAuth, CredentialManager, Metadata};

/// Where this installation's Authorization Server lives; see the CLI's
/// constant of the same name. Defaults to the issuer in the stored credential.
pub const AUTH_SERVER_ADDR_VAR: &str = "YADORILINK_AUTH_SERVER_ADDR";

/// Open the credential store this process should use.
pub fn open() -> Result<CredentialStore, StoreError> {
    CredentialStore::configure_from_env(&crate::device_config::config_dir())
}

/// This installation's OAuth credentials, if it has enrolled.
pub fn installation() -> Result<Option<Credentials>, StoreError> {
    open()?.load()
}

/// The credential this daemon authenticates every coordination call with, or
/// `None` if this installation has not enrolled.
///
/// `None` means exactly one thing: NOT ENROLLED. There is no second store to
/// consult and no older credential shape to fall back to -- an installation
/// either holds a `client_id`, a client key and a refresh token, or it holds
/// nothing. A daemon in the second state runs and syncs nothing remotely,
/// which is a supported state; what it never does is reach the coordination
/// plane by some other means.
///
/// A store that cannot be READ is an error rather than a `None`, because the
/// two mean opposite things and only one of them is a user who has not signed
/// in. Starting anyway would be the fall-back-to-anonymity this store exists to
/// refuse.
///
/// One credential manager, built once here and shared by every subsystem,
/// which refreshes the five-minute access token on its own and mints a DPoP
/// proof per request.
///
/// Building the manager reaches the network once, for discovery. That is
/// deliberate and it happens at startup rather than at first use: a daemon
/// whose stored credential belongs to a different deployment, or whose
/// registration has been revoked, should say so while someone is still looking
/// at it.
///
/// # A network that is simply down is not a misconfiguration
///
/// That startup fetch used to be the only way to a manager, which made an
/// unreachable Authorization Server fatal: the `?` here left `app::run` and
/// the process exited. A daemon on a machine whose internet is out would
/// therefore not start at all -- including on the local network, where its
/// already-authorized peers were sitting reachable the whole time. So the
/// document this device last fetched is kept
/// ([`remember_discovery_document`]) and used when, and only when, the fetch
/// fails at the transport (`reqwest`) layer: nothing was reached, so nothing
/// was learned that could contradict it.
///
/// Every OTHER failure is still fatal, which is what keeps the check above
/// meaningful: a server that answers with an error status, a document that
/// no longer meets the profile, and an issuer that disagrees with the stored
/// credential are all cases where the server WAS reached and said something,
/// and none of them is a network outage to ride out.
pub async fn coordination_auth() -> anyhow::Result<Option<CoordinationAuth>> {
    let store = open()?;

    let Some(credentials) = store.load()? else { return Ok(None) };
    let manager = manager_for(store, &credentials).await?;
    let reload: yadorilink_fapi_client::Reload = Arc::new(|running_client_id| {
        Box::pin(async move { reload_manager(&running_client_id).await })
    });
    Ok(Some(CoordinationAuth::reloading(manager, reload)?))
}

/// The manager over the installation the store holds now, when that is not
/// `running_client_id`: what a running daemon follows after the CLI signed
/// out and in again. `None` when the store is empty (signed out: keep what is
/// running until a sign-in) or still holds the running installation.
async fn reload_manager(
    running_client_id: &str,
) -> Result<Option<Arc<CredentialManager>>, yadorilink_fapi_client::Error> {
    let store = open().map_err(yadorilink_fapi_client::Error::Store)?;
    let Some(credentials) = store.load().map_err(yadorilink_fapi_client::Error::Store)? else {
        return Ok(None);
    };
    if credentials.client_id() == running_client_id {
        return Ok(None);
    }
    let manager = manager_for(store, &credentials)
        .await
        .map_err(|error| yadorilink_fapi_client::Error::Reload(format!("{error:#}")))?;
    tracing::info!("the credential store holds a new sign-in; the daemon now uses it");
    Ok(Some(manager))
}

async fn manager_for(
    store: CredentialStore,
    credentials: &Credentials,
) -> anyhow::Result<Arc<CredentialManager>> {
    let base =
        std::env::var(AUTH_SERVER_ADDR_VAR).unwrap_or_else(|_| credentials.issuer().to_owned());
    let store = Arc::new(store);
    let manager = match CredentialManager::from_credentials(
        reqwest::Client::new(),
        &base,
        store.clone(),
        credentials,
    )
    .await
    {
        Ok(manager) => {
            remember_discovery_document(&base, manager.client().metadata());
            manager
        }
        Err(yadorilink_fapi_client::Error::Http(error)) => {
            let Some(metadata) = remembered_discovery_document(&base) else {
                return Err(anyhow::Error::new(error).context(
                    "could not reach the Authorization Server and this device has no \
                     discovery document from an earlier run to start from",
                ));
            };
            tracing::warn!(
                %error,
                issuer = %credentials.issuer(),
                "the Authorization Server is unreachable; starting from the discovery \
                 document this device fetched on an earlier run. No coordination call can \
                 succeed until it answers again -- this daemon starts so that work needing \
                 no server (local folders, and peers on this network the plane already \
                 authorized) is not blocked by an outage."
            );
            CredentialManager::from_credentials_and_metadata(
                reqwest::Client::new(),
                &base,
                store,
                credentials,
                metadata,
            )?
        }
        Err(error) => return Err(error.into()),
    };
    let manager = manager
        // `EssentialTasks::shutdown` (`supervise.rs`) aborts every other
        // essential task the instant one of them fails, and a refresh can be
        // running inline inside one of them when that happens. Detaching the
        // post-refresh persist into its own `tokio::spawn` -- holding no
        // `AbortHandle` that shutdown could reach -- is what stops that abort
        // from cancelling a write the server has already made necessary. See
        // `yadorilink_fapi_client::Detach`.
        .with_detach(Arc::new(|work| {
            tokio::spawn(async move { work() });
        }));
    Ok(Arc::new(manager))
}

/// Where the last discovery document this device fetched is kept.
///
/// Beside the device config rather than in the credential store: it holds
/// nothing secret -- it is a public document any client may GET -- and it is
/// not a credential, so it has no business in a file whose whole contract is
/// that it holds one.
fn discovery_document_path() -> PathBuf {
    crate::device_config::config_dir().join("coordination_discovery.json")
}

/// One socket's remembered discovery document.
///
/// The socket is stored with it because a document is only meaningful for
/// the socket it was fetched from: a machine pointed at a different
/// Authorization Server (a `YADORILINK_AUTH_SERVER_ADDR` override, a local
/// development deployment) must not start from the previous one's endpoints.
#[derive(serde::Serialize, serde::Deserialize)]
struct RememberedDiscoveryDocument {
    base_url: String,
    metadata: Metadata,
}

/// Keeps the document a successful discovery returned, so a later start
/// taken while the server is unreachable has one.
///
/// Best-effort: failing to write it costs a future offline start its head
/// start, and is never a reason to fail a startup that has just succeeded.
fn remember_discovery_document(base_url: &str, metadata: &Metadata) {
    let remembered =
        RememberedDiscoveryDocument { base_url: base_url.to_owned(), metadata: metadata.clone() };
    let path = discovery_document_path();
    let write = serde_json::to_vec_pretty(&remembered)
        .map_err(std::io::Error::other)
        .and_then(|bytes| std::fs::write(&path, bytes));
    if let Err(error) = write {
        tracing::warn!(
            %error,
            path = %path.display(),
            "could not keep the Authorization Server's discovery document; a later start \
             taken while that server is unreachable will have to refuse instead"
        );
    }
}

/// The document last fetched from `base_url`, if this device has one.
///
/// Returns `None` for anything unexpected -- absent, unreadable, unparsable,
/// or remembered for a different socket -- because every one of them means
/// the same thing to the caller: there is nothing here to start from, so the
/// unreachable server stays fatal.
fn remembered_discovery_document(base_url: &str) -> Option<Metadata> {
    let path = discovery_document_path();
    let bytes = std::fs::read(&path).ok()?;
    let remembered: RememberedDiscoveryDocument = serde_json::from_slice(&bytes).ok()?;
    if remembered.base_url != base_url {
        tracing::warn!(
            remembered = %remembered.base_url,
            requested = %base_url,
            "the remembered discovery document belongs to a different Authorization Server \
             socket; ignoring it"
        );
        return None;
    }
    Some(remembered.metadata)
}

#[cfg(test)]
mod tests;
