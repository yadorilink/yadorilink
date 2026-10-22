//! Signing this installation in and out.
//!
//! # The three flows, and why they are three
//!
//! ```text
//!   ENROLMENT  (this machine has no identity)   -> a client_id
//!   LOGIN      (this machine has a client_id)   -> a refresh token
//!   REFRESH    (this machine has both)          -> an access token
//! ```
//!
//! [`login`] runs the first two in order. They are genuinely different
//! operations: enrolment happens BEFORE any OAuth client exists, so the
//! request that opens it cannot be authenticated and what it yields is a
//! REGISTRATION; login is made by an authenticated `client_id` and what it
//! yields is a TOKEN. The identity leg happens in a BROWSER, on the server's
//! side of the wire, and no identity-provider artefact of any kind reaches
//! this process.
//!
//! # Why the loopback listener is bound first
//!
//! The redirect URI is registered during enrolment and is then fixed for the
//! life of the registration, so the port has to be known before the
//! registration is made. Binding port 0 first and registering the port the
//! kernel handed back is the only order in which the two agree.
//!
//! # Progress is reported, never printed
//!
//! Every step a person has to act on (open this page, enter this code) is
//! reported to the caller as a [`LoginEvent`], in order; the caller decides
//! how to show it. `wording::login_event_lines` is the terminal rendering.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_fapi_client::{
    complete_enrolment, open_enrolment, AuthorizationRequest, CredentialManager, DevicePoll,
    EnrolmentRequest, Es256Key, FapiClient, Pkce,
};

use crate::coordination::credential_store;
use crate::error::CoreError;

mod loopback;

/// The scope a login asks for. `offline_access` is what makes the response
/// carry a refresh token; without one this machine would hold a credential
/// that dies in five minutes.
const LOGIN_SCOPE: &str = "openid offline_access";

/// How long to wait for the browser to come back to the loopback listener.
/// Long enough for a human to sign in to an identity provider that asks for a
/// second factor; short enough that a login nobody is watching does not hold
/// a port open indefinitely.
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Which page a [`LoginEvent::OpenBrowser`] is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserPurpose {
    /// Approving this computer's enrolment into the account.
    ApproveDevice,
    /// Signing in as the newly registered client.
    SignIn,
}

/// One step of a sign-in, reported in order.
///
/// Loopback flow: `Enrolling`, `OpenBrowser{ApproveDevice}`,
/// `WaitingForApproval`, `OpenBrowser{SignIn}`, `WaitingForAuthorization`,
/// `SignedIn`. Device-code flow: `Enrolling`, `OpenBrowser{ApproveDevice}`,
/// `WaitingForApproval`, `ShowDeviceCode`, `SignedIn`. A failure ends the
/// flow with an error instead of `SignedIn`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginEvent {
    /// The loopback listener is bound and the enrolment request is in flight.
    Enrolling,
    /// A page the person has to open in a browser.
    OpenBrowser { url: String, purpose: BrowserPurpose },
    /// Waiting for the enrolment to be approved; the approval link is valid
    /// for `expires_in`.
    WaitingForApproval { expires_in: Duration },
    /// Waiting for the browser to come back to the loopback redirect.
    WaitingForAuthorization,
    /// Device-code flow only: the verification page, the URI with the code
    /// already in it when the server sent one, and the code itself.
    ShowDeviceCode {
        verification_uri: String,
        verification_uri_complete: Option<String>,
        user_code: String,
    },
    /// Signed in; the credential store now holds this installation's
    /// credential.
    SignedIn { client_id: String },
}

/// Enrols this installation and signs it in, reporting each step to `sink`.
///
/// Nothing is written to the credential store until both halves have
/// succeeded: a store holding a `client_id` with no refresh token is the
/// half-configured state the store itself refuses to hold.
///
/// `device`: use the RFC 8628 device-authorization grant for the sign-in leg
/// instead of the loopback-redirect authorization-code flow. Every
/// registration still needs a loopback `redirect_uris` entry, so a loopback
/// listener is still bound during enrolment, but it is never dialed on this
/// path and is dropped immediately after.
pub async fn login(device: bool, mut sink: impl FnMut(LoginEvent)) -> Result<(), CoreError> {
    let store = Arc::new(credential_store::open()?);
    if store.load()?.is_some() {
        return Err(already_enrolled());
    }

    let base_url = crate::coordination::http_client::coordination_addr();
    let http = crate::coordination::http_client::client()?;

    // 1. The port this machine will receive its redirect on, decided by the
    //    kernel and then registered, in that order.
    let listener = loopback::Listener::bind().await?;
    let redirect_uri = listener.redirect_uri().to_owned();
    let redirect_uris = vec![redirect_uri.clone()];
    sink(LoginEvent::Enrolling);

    // 2. Enrolment. The key is generated here and only its public half is sent.
    let client_key = Es256Key::generate();
    let pending = open_enrolment(
        &http,
        &base_url,
        &client_key,
        &EnrolmentRequest { redirect_uris: &redirect_uris, client_name: Some(&client_name()) },
    )
    .await?;

    sink(LoginEvent::OpenBrowser {
        url: pending.approval_uri.clone(),
        purpose: BrowserPurpose::ApproveDevice,
    });
    sink(LoginEvent::WaitingForApproval { expires_in: pending.expires_in });

    let registration =
        complete_enrolment(&http, &pending, &client_key, |wait| tokio::time::sleep(wait)).await?;

    // 3. Login, as the client that was just registered. Discovery runs here
    //    and not earlier because the profile check is per client.
    // Serialised before the key is handed to the client, which takes it by
    // value: `Es256Key` is deliberately not `Clone`.
    let client_key_jwk = client_key.to_jwk_json();
    let client = FapiClient::discover(
        http,
        &base_url,
        registration.client_id.clone(),
        client_key,
        Es256Key::generate(),
    )
    .await?;

    let tokens = if device {
        // The loopback listener registered above is never contacted on this
        // path; drop it now instead of holding the port for no reason.
        drop(listener);

        let authorization = client.request_device_authorization(LOGIN_SCOPE).await?;
        sink(LoginEvent::ShowDeviceCode {
            verification_uri: authorization.verification_uri.clone(),
            verification_uri_complete: authorization.verification_uri_complete.clone(),
            user_code: authorization.user_code.clone(),
        });
        loop {
            match client.poll_device_authorization(&authorization.device_code).await? {
                DevicePoll::Granted(tokens) => break *tokens,
                DevicePoll::Pending => {
                    tokio::time::sleep(authorization.poll_interval()).await;
                }
                DevicePoll::SlowDown => {
                    tokio::time::sleep(authorization.poll_interval() + Duration::from_secs(5))
                        .await;
                }
            }
        }
    } else {
        let pkce = Pkce::generate();
        let state = loopback::random_state();
        let pushed = client
            .push_authorization_request(&AuthorizationRequest {
                redirect_uri: &redirect_uri,
                scope: LOGIN_SCOPE,
                state: &state,
                // Without this the token response arrives with a 200 and
                // simply no refresh token, which is a login that has already
                // expired.
                prompt: Some("consent"),
                pkce: &pkce,
            })
            .await?;

        let authorize = client.authorization_endpoint_url(&pushed.request_uri)?;
        sink(LoginEvent::OpenBrowser {
            url: authorize.to_string(),
            purpose: BrowserPurpose::SignIn,
        });
        sink(LoginEvent::WaitingForAuthorization);

        let code =
            listener.wait_for_code(&state, &client.metadata().issuer, LOOPBACK_TIMEOUT).await?;
        client.exchange_authorization_code(&code, &redirect_uri, &pkce).await?
    };

    // 4. One write, with everything in it. `establish` takes the client that
    //    was just used, so the login that just happened and the session that
    //    follows it cannot disagree about the issuer, and the stored
    //    `client_id` cannot name a registration other than the one holding
    //    the tokens.
    let manager = CredentialManager::establish(client, client_key_jwk, &tokens, store).await?;
    // The proof that this device replaces another needs the account id, which only this sign-in
    // received. A directory that cannot be resolved here would already have failed above.
    if let Ok(dir) = crate::coordination::device_config::config_dir() {
        crate::ops::device_supersede::record_account_id(&dir, tokens.id_token());
    }

    sink(LoginEvent::SignedIn { client_id: manager.client_id().to_owned() });
    Ok(())
}

/// Refuses when this installation already holds a credential, the same
/// refusal [`login`] starts with, so a front end can refuse before starting a
/// sign-in at all.
pub fn ensure_not_enrolled() -> Result<(), CoreError> {
    if credential_store::installation()?.is_some() {
        return Err(already_enrolled());
    }
    Ok(())
}

fn already_enrolled() -> CoreError {
    CoreError::AuthFailed(
        "this installation is already enrolled. `yadorilink logout` first if you mean to enrol \
         it again -- re-enrolling mints a NEW identity rather than repairing the old one, and the \
         old one stays live until it is revoked."
            .to_owned(),
    )
}

/// A label for the approval page. Never an identifier -- the server sanitises
/// it and does not trust it as one.
fn client_name() -> String {
    let host = hostname();
    format!("YadoriLink on {host}")
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "this computer".to_owned())
}

/// The server's answer to a sign-out: the tombstone it wrote.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignOutResponse {
    client_id: String,
    first_revocation: bool,
    grants_revoked: u32,
}

/// How a sign-out that removed the local credential established that this
/// installation's remote authority is gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignOutKind {
    /// The server revoked this installation just now.
    Revoked { grants_revoked: u32 },
    /// The server reports it had already been revoked.
    AlreadyRevoked,
    /// The server refused the session, and the Authorization Server then
    /// independently confirmed the registration is revoked.
    ConfirmedRevokedAfterRejection,
}

/// Signs out: revoke this installation's authority, confirm it, and only then
/// destroy the local credential.
///
/// # Why the order is not negotiable
///
/// A user who signs out believes their remote authority is gone. The refresh
/// token in the local store is **not sender-constrained**, so anything that
/// copied it before a local delete could keep minting access tokens. Deleting
/// the only copy this process knows about is not revocation.
///
/// So the server is asked first, and only a confirmed revocation earns the
/// local clear:
///
/// ```text
///   revoked, confirmed         -> clear the store, Revoked
///   already revoked            -> clear the store, AlreadyRevoked
///   401, and independently
///     confirmed revoked        -> clear the store, ConfirmedRevokedAfterRejection
///   401, but independently
///     confirmed still alive    -> KEEP the store; AuthFailed
///   could not confirm either
///     way                      -> KEEP the store; AuthFailed
/// ```
///
/// A user who genuinely wants the local half alone has
/// [`forget_local_credentials`], a different operation under a different name.
///
/// # Why a 401 is not, by itself, evidence of anything
///
/// Every 401 this plane can produce maps to [`CoreError::AuthFailed`] -- a
/// DPoP mismatch, a malformed proof, a middleware bug, and a token that is 401
/// because this very revocation already landed. Only one of those means the
/// credential is safe to delete, so a 401 triggers
/// `CoordinationAuth::confirm_registration_status`, which forces a refresh and
/// asks the Authorization Server directly. `invalid_grant` on its own does NOT
/// mean the client is revoked, so it keeps the credential.
pub async fn sign_out() -> Result<SignOutKind, CoreError> {
    if credential_store::installation()?.is_none() {
        return Err(CoreError::NotLoggedIn);
    }

    let auth = crate::coordination::http_client::require_auth().await?;
    let client_id = auth.client_id().to_owned();

    let answer = crate::coordination::http_client::post_json::<_, SignOutResponse>(
        "/devices/sign-out",
        &serde_json::json!({}),
        &auth,
    )
    .await;

    let attempt = match answer {
        Ok(tombstone) => SignOutAttempt::Tombstone(tombstone),
        Err(CoreError::AuthFailed(detail)) => {
            SignOutAttempt::Denied401 { detail, confirmed: confirm_after_401(&auth).await }
        }
        Err(other) => SignOutAttempt::Failed(other),
    };

    match sign_out_verdict(attempt, &client_id) {
        SignOutVerdict::Clear(kind) => {
            credential_store::clear().await?;
            Ok(kind)
        }
        SignOutVerdict::KeepCredential(error) => Err(error),
    }
}

/// What a 401 from `/devices/sign-out` turned out to mean, established by
/// forcing a refresh rather than inferred from the 401 itself.
#[derive(Debug)]
enum Confirmed {
    Revoked,
    Alive,
    Unknown(String),
}

async fn confirm_after_401(auth: &yadorilink_fapi_client::CoordinationAuth) -> Confirmed {
    use yadorilink_fapi_client::RegistrationStatus;
    match auth.confirm_registration_status().await {
        RegistrationStatus::Revoked => Confirmed::Revoked,
        RegistrationStatus::Alive => Confirmed::Alive,
        RegistrationStatus::Unknown(error) => Confirmed::Unknown(error.to_string()),
    }
}

/// One attempt at `/devices/sign-out`, resolved to the point where
/// [`sign_out_verdict`] can decide the local store's fate without any further
/// network call.
#[derive(Debug)]
enum SignOutAttempt {
    Tombstone(SignOutResponse),
    Denied401 { detail: String, confirmed: Confirmed },
    Failed(CoreError),
}

/// What a sign-out attempt entitles the client to do with its local store.
///
/// A pure function, because this decision -- and not the HTTP call -- is the
/// part that can be wrong in a way nobody notices: "the revocation failed and
/// the credential was deleted anyway" looks exactly like success.
#[derive(Debug)]
enum SignOutVerdict {
    Clear(SignOutKind),
    KeepCredential(CoreError),
}

fn sign_out_verdict(attempt: SignOutAttempt, our_client_id: &str) -> SignOutVerdict {
    match attempt {
        SignOutAttempt::Tombstone(tombstone) if tombstone.client_id != our_client_id => {
            // The server reported revoking something other than this
            // installation. Clearing would destroy the credential that could
            // ask again.
            SignOutVerdict::KeepCredential(CoreError::AuthFailed(format!(
                "the server reported revoking {} rather than this installation ({our_client_id}); \
                 nothing was signed out and your credentials are unchanged",
                tombstone.client_id
            )))
        }
        SignOutAttempt::Tombstone(tombstone) if tombstone.first_revocation => {
            SignOutVerdict::Clear(SignOutKind::Revoked { grants_revoked: tombstone.grants_revoked })
        }
        SignOutAttempt::Tombstone(_) => SignOutVerdict::Clear(SignOutKind::AlreadyRevoked),
        SignOutAttempt::Denied401 { confirmed: Confirmed::Revoked, .. } => {
            SignOutVerdict::Clear(SignOutKind::ConfirmedRevokedAfterRejection)
        }
        SignOutAttempt::Denied401 { detail, confirmed: Confirmed::Alive } => {
            SignOutVerdict::KeepCredential(CoreError::AuthFailed(format!(
                "sign-out was refused ({detail}), but this installation's registration is \
                 confirmed still active on the server -- this looks like a server-side bug \
                 rather than a revocation. Your credentials were NOT removed; try again."
            )))
        }
        SignOutAttempt::Denied401 { detail, confirmed: Confirmed::Unknown(why) } => {
            SignOutVerdict::KeepCredential(CoreError::AuthFailed(format!(
                "sign-out was refused ({detail}), and whether the registration is actually \
                 revoked could not be confirmed ({why}). Your credentials were NOT removed, \
                 because deleting them on an unconfirmed 401 is exactly the failure this check \
                 exists to prevent. Try again when you are online, or remove this device from \
                 another one."
            )))
        }
        SignOutAttempt::Failed(other) => {
            SignOutVerdict::KeepCredential(CoreError::AuthFailed(format!(
                "could not revoke this computer's access ({other}). Your credentials were NOT \
             removed, because deleting them would leave this computer signed in on the server \
             with no way to sign it out from here. Try again when you are online, or remove this \
             device from another one."
            )))
        }
    }
}

/// Destroys this machine's stored credential WITHOUT revoking anything.
///
/// After this the installation is still authorized on the server and a copy
/// of the refresh token still works, which is why it is not what signing out
/// does.
pub async fn forget_local_credentials() -> Result<(), CoreError> {
    if credential_store::installation()?.is_none() {
        return Err(CoreError::NotLoggedIn);
    }
    credential_store::clear().await?;
    Ok(())
}

/// Remove everything this machine keeps in its credential store, without
/// revoking anything on the server: the local purge the uninstaller runs for
/// `--purge-data`. Unlike [`forget_local_credentials`] it is not an error to
/// have nothing stored, and on macOS it also removes the device-key mirrors in
/// the credential keychain group.
pub async fn purge_local_credentials() -> Result<(), CoreError> {
    credential_store::purge_local().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
