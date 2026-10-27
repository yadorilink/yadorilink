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
    complete_enrolment, open_enrolment, AuthorizationRequest, CredentialManager, EnrolmentRequest,
    Es256Key, FapiClient, Pkce,
};

use crate::coordination::credential_store;
use crate::error::{CoreError, Hint};

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
pub async fn login(device: bool, sink: impl FnMut(LoginEvent)) -> Result<(), CoreError> {
    let dir = credential_store::process_dir()?;
    login_in(&dir, &credential_store::CredentialSettings::from_env(&dir)?, device, sink).await
}

/// [`login`] for the state directory `dir`: the credential store and the device-supersede record
/// are that directory's, whatever the environment says.
pub async fn login_in(
    dir: &std::path::Path,
    settings: &credential_store::CredentialSettings,
    device: bool,
    mut sink: impl FnMut(LoginEvent),
) -> Result<(), CoreError> {
    let store = Arc::new(credential_store::open_in(dir, settings)?);
    if store.load()?.is_some() {
        // An installation whose session the server refuses to refresh (`invalid_grant`: after a
        // change of the Terms every grant of an account without current consent is refused)
        // signs in again as itself, which keeps its identity, device and folders. Anything else,
        // including a refresh that cannot be tried now, keeps the refusal below.
        if refresh_is_refused_in(dir, settings).await? {
            return reauthenticate_in(dir, settings, device, sink).await;
        }
        return Err(already_enrolled());
    }

    let base_url = settings.coordination_addr();
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
        &EnrolmentRequest {
            redirect_uris: &redirect_uris,
            client_name: Some(&client_name(settings.host_name.as_deref())),
        },
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
    // The explicit Authorization Server (the setting every later credential load honors) when
    // there is one; enrolment above stays on the coordination endpoint.
    let discovery_url = settings.auth_server_addr.as_deref().unwrap_or(&base_url);
    let client = FapiClient::discover(
        http,
        discovery_url,
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
        client.complete_device_authorization(&authorization).await?
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
    // received.
    crate::ops::device_supersede::record_account_id(dir, tokens.id_token());

    sink(LoginEvent::SignedIn { client_id: manager.client_id().to_owned() });
    Ok(())
}

/// Confirms the person's account again as THIS installation, for an action that
/// needs an interactive confirmation made in the last few minutes (starting an
/// account deletion).
///
/// This is a login by the client the credential store already holds: the same
/// `client_id`, the same client key, no enrolment. Nothing registers a device,
/// replaces one, or touches the client key; the server shows the identity
/// provider's account chooser and records the completion time. That proves a
/// recent interactive account confirmation, not a fresh credential check.
///
/// OAuth endpoints are discovered where the stored credential's issuer says
/// the Authorization Server is, exactly as every other authenticated call.
///
/// The loopback redirect uses a fresh port: the registration is native, and a
/// loopback redirect matches on everything but the port. `device`: the
/// device-authorization grant instead, as [`login`].
///
/// The tokens the step-up is issued replace the stored refresh token, so the
/// store keeps one live grant.
pub async fn reauthenticate(device: bool, sink: impl FnMut(LoginEvent)) -> Result<(), CoreError> {
    let dir = credential_store::process_dir()?;
    reauthenticate_in(&dir, &credential_store::CredentialSettings::from_env(&dir)?, device, sink)
        .await
}

/// [`reauthenticate`] for the state directory `dir`: the credential store and the Authorization
/// Server are the host's settings, whatever the environment says.
pub async fn reauthenticate_in(
    dir: &std::path::Path,
    settings: &credential_store::CredentialSettings,
    device: bool,
    mut sink: impl FnMut(LoginEvent),
) -> Result<(), CoreError> {
    // Discovery runs against the Authorization Server (the stored issuer, or the
    // address override), never the coordination API.
    let manager = crate::coordination::http_client::credential_manager_in(dir, settings).await?;
    let client = manager.client();

    let tokens = if device {
        let authorization = client.request_fresh_device_authorization(LOGIN_SCOPE).await?;
        sink(LoginEvent::ShowDeviceCode {
            verification_uri: authorization.verification_uri.clone(),
            verification_uri_complete: authorization.verification_uri_complete.clone(),
            user_code: authorization.user_code.clone(),
        });
        client.complete_device_authorization(&authorization).await?
    } else {
        let listener = loopback::Listener::bind().await?;
        let redirect_uri = listener.redirect_uri().to_owned();
        let pkce = Pkce::generate();
        let state = loopback::random_state();
        let pushed = client
            .push_authorization_request(&AuthorizationRequest {
                redirect_uri: &redirect_uri,
                scope: LOGIN_SCOPE,
                state: &state,
                // `consent` makes our Authorization Server run an interaction
                // even when the browser holds a session for this client, and
                // keeps the refresh token that `offline_access` needs. The
                // identity provider's account chooser is the server's doing.
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

    // A step-up proves the person is still the account this installation belongs to: another
    // account's tokens must not replace its session.
    if crate::ops::device_supersede::is_other_account(dir, tokens.id_token()) {
        return Err(CoreError::AccountMismatch);
    }
    manager.adopt(&tokens).await?;
    // Keeps the record of installations that predate it, or whose record was lost; a sign-in
    // that names no account leaves it as it is.
    if tokens.id_token().and_then(crate::ops::device_supersede::subject_of_id_token).is_some() {
        crate::ops::device_supersede::record_account_id(dir, tokens.id_token());
    }
    sink(LoginEvent::SignedIn { client_id: manager.client_id().to_owned() });
    Ok(())
}

/// The origins (scheme, host and port, lowercase, e.g. `https://auth.example.test:8443`) a front
/// end may open a sign-in page on, per purpose. A link is trusted only when its origin equals
/// the one of its purpose, never on an origin Core did not name: `None` means that purpose has
/// no origin Core can tell, so no link of it is trusted.
///
/// The two differ whenever the settings name an Authorization Server apart from the
/// coordination service, because the device approval is the coordination service's (enrolment
/// is dialed there) while every OAuth page is the Authorization Server's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSignInOrigins {
    /// `BrowserPurpose::ApproveDevice`: the coordination service's approval page.
    pub approve_device: Option<String>,
    /// `BrowserPurpose::SignIn` and the `ShowDeviceCode` verification page: the Authorization
    /// Server the settings name, else the issuer of the stored credential, else the coordination
    /// service the sign-in discovers it from.
    pub authorization: Option<String>,
}

/// The [`TrustedSignInOrigins`] of this installation.
///
/// # Errors
/// The credential store could not be read (only consulted when the settings name no
/// Authorization Server): an unreadable store is not an empty one, and the coordination
/// fallback must not be trusted for a page the stored issuer would have served.
pub fn trusted_sign_in_origins_in(
    dir: &std::path::Path,
    settings: &credential_store::CredentialSettings,
) -> Result<TrustedSignInOrigins, CoreError> {
    trusted_sign_in_origins_for(dir, settings, &settings.coordination_addr())
}

/// [`trusted_sign_in_origins_in`] against an explicit coordination address.
fn trusted_sign_in_origins_for(
    dir: &std::path::Path,
    settings: &credential_store::CredentialSettings,
    coordination: &str,
) -> Result<TrustedSignInOrigins, CoreError> {
    let authorization = match &settings.auth_server_addr {
        Some(address) => address.clone(),
        None => credential_store::installation_in(dir, settings)?
            .map_or_else(|| coordination.to_owned(), |credentials| credentials.issuer().to_owned()),
    };
    Ok(TrustedSignInOrigins {
        approve_device: origin_of(coordination),
        authorization: origin_of(&authorization),
    })
}

fn origin_of(address: &str) -> Option<String> {
    let url = url::Url::parse(address).ok()?;
    url.host_str()?;
    Some(url.origin().ascii_serialization())
}

/// Refuses when this installation already holds a credential, the same
/// refusal [`login`] starts with, so a front end can refuse before starting a
/// sign-in at all.
pub fn ensure_not_enrolled() -> Result<(), CoreError> {
    let dir = credential_store::process_dir()?;
    ensure_not_enrolled_in(&dir, &credential_store::CredentialSettings::from_env(&dir)?)
}

/// [`ensure_not_enrolled`] for the state directory `dir`.
pub fn ensure_not_enrolled_in(
    dir: &std::path::Path,
    settings: &credential_store::CredentialSettings,
) -> Result<(), CoreError> {
    if credential_store::installation_in(dir, settings)?.is_some() {
        return Err(already_enrolled());
    }
    Ok(())
}

/// Whether the Authorization Server refuses to refresh the stored session with `invalid_grant`,
/// asked once. A refresh that works, or a revoked registration, is "no". A server that cannot be
/// reached is an error, not "no": answering "already enrolled" there would send a person whose
/// installation merely needs a sign-in toward signing out.
async fn refresh_is_refused_in(
    dir: &std::path::Path,
    settings: &credential_store::CredentialSettings,
) -> Result<bool, CoreError> {
    let manager = crate::coordination::http_client::credential_manager_in(dir, settings).await?;
    match manager.force_refresh().await {
        Err(e) if e.is_invalid_grant() => Ok(true),
        Err(e @ yadorilink_fapi_client::Error::Http(_)) => Err(e.into()),
        // Rate limited or failing: the server could not answer, which is not "no".
        Err(yadorilink_fapi_client::Error::Response { status: 429 | 500..=599, .. }) => {
            Err(CoreError::CoordinationPlaneUnreachable(
                "the authorization server did not answer".to_owned(),
            ))
        }
        _ => Ok(false),
    }
}

fn already_enrolled() -> CoreError {
    CoreError::AuthFailed(
        "this installation is already enrolled. Re-enrolling mints a NEW identity rather than \
         repairing the old one, and the old one stays live until it is revoked. The sign-in \
         belongs to this computer user, not to one data directory: it can be removed from this \
         computer when the data directory was removed without signing out (that does not revoke \
         it on the server)"
            .to_owned(),
    )
    .hinted(Hint::AlreadyEnrolled)
}

/// A label for the approval page. Never an identifier -- the server sanitises
/// it and does not trust it as one.
fn client_name(host_name: Option<&str>) -> String {
    let host = host_name.unwrap_or("this computer");
    format!("YadoriLink on {host}")
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

/// What a completed sign-out did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignOutReport {
    pub kind: SignOutKind,
    /// Set when the device key's copy in the OS credential store could not be removed. The
    /// sign-out itself is complete; this says what is left behind and how to finish.
    pub key_cleanup_warning: Option<String>,
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
pub async fn sign_out() -> Result<SignOutReport, CoreError> {
    let dir = credential_store::process_dir()?;
    sign_out_in(&dir, &credential_store::CredentialSettings::from_env(&dir)?).await
}

/// [`sign_out`] for the state directory `dir`.
pub async fn sign_out_in(
    dir: &std::path::Path,
    settings: &credential_store::CredentialSettings,
) -> Result<SignOutReport, CoreError> {
    if credential_store::installation_in(dir, settings)?.is_none() {
        return Err(CoreError::NotLoggedIn);
    }

    let auth = crate::coordination::http_client::require_auth_in(dir, settings).await?;
    let client_id = auth.client_id().to_owned();

    let answer = crate::coordination::http_client::post_json::<_, SignOutResponse>(
        "/devices/sign-out",
        &serde_json::json!({}),
        &auth,
    )
    .await;

    let attempt = match answer {
        Ok(tombstone) => SignOutAttempt::Tombstone(tombstone),
        Err(error) => match denied_401_detail(error) {
            Ok(detail) => {
                SignOutAttempt::Denied401 { detail, confirmed: confirm_after_401(&auth).await }
            }
            Err(other) => SignOutAttempt::Failed(other),
        },
    };

    match sign_out_verdict(attempt, &client_id) {
        SignOutVerdict::Clear(kind) => {
            credential_store::clear_in(dir, settings).await?;
            // The server has revoked this installation and the credential is gone: that is the
            // signed-out state. Removing the device key's OS keyring copy comes last and cannot
            // undo it; a failure is reported, never turned into a half-signed-out error.
            let key_cleanup_warning = delete_device_key_mirrors_for(dir, settings.key_mirror);
            Ok(SignOutReport { kind, key_cleanup_warning })
        }
        SignOutVerdict::KeepCredential(error) => Err(error),
    }
}

/// Every 401 the coordination plane can answer, typed or not, is a denial whose meaning must be
/// confirmed; any other error is a failure of the attempt itself.
fn denied_401_detail(error: CoreError) -> Result<String, CoreError> {
    match error.into_unhinted() {
        CoreError::AuthFailed(detail) => Ok(detail),
        // A refresh refused with `invalid_grant` is as undecided as any other refused session:
        // confirm it rather than treat it as a failed attempt.
        refused @ CoreError::SignInRequired => Ok(refused.to_string()),
        CoreError::DeviceSuperseded => Ok(CoreError::DeviceSuperseded.to_string()),
        other => Err(other),
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

/// What probing the account after a finalized deletion found.
#[derive(Debug)]
enum DeletionProbe {
    /// The account still answers: the deletion has not been finalized (or is in its grace
    /// period).
    StillExists,
    Denied401 {
        detail: String,
        confirmed: Confirmed,
        /// The server's answer to "was this installation revoked because its account was
        /// deleted", asked only once the registration is confirmed revoked. `None` when it could
        /// not be asked.
        account_deleted: Option<bool>,
    },
    Failed(CoreError),
}

/// Whether the local credential may be removed because the account is gone. The evidence has to
/// be about the account, not just the installation: a refusal whose registration is confirmed
/// revoked is also what a sign-out from another device looks like, so it needs the server to
/// say this installation was revoked by the account's deletion. An account that still answers,
/// an unconfirmed refusal, a revoked registration with a live account and a failed probe all
/// keep the credential.
fn deletion_completion_verdict(probe: DeletionProbe) -> Result<(), CoreError> {
    match probe {
        DeletionProbe::Denied401 {
            confirmed: Confirmed::Revoked,
            account_deleted: Some(true),
            ..
        } => Ok(()),
        DeletionProbe::Denied401 {
            confirmed: Confirmed::Revoked,
            account_deleted: Some(false),
            ..
        } => Err(CoreError::InvalidInput(
            "this installation was signed out, but the account has not been deleted; nothing was \
             removed from this computer"
                .into(),
        )),
        DeletionProbe::Denied401 {
            confirmed: Confirmed::Revoked,
            account_deleted: None,
            detail,
        } => Err(CoreError::AuthFailed(format!(
            "the account was refused ({detail}) and whether it is deleted could not be \
                 confirmed. Your credentials were NOT removed; try again when you are online."
        ))),
        DeletionProbe::StillExists => Err(CoreError::InvalidInput(
            "the account has not been deleted yet; nothing was removed from this computer".into(),
        )),
        DeletionProbe::Denied401 { detail, confirmed: Confirmed::Alive, .. } => {
            Err(CoreError::AuthFailed(format!(
                "the account was refused ({detail}) but this installation is confirmed still \
                 active on the server, so the account is not deleted. Your credentials were NOT \
                 removed."
            )))
        }
        DeletionProbe::Denied401 { detail, confirmed: Confirmed::Unknown(why), .. } => {
            Err(CoreError::AuthFailed(format!(
                "the account was refused ({detail}) and whether it is deleted could not be \
                 confirmed ({why}). Your credentials were NOT removed; try again when you are \
                 online."
            )))
        }
        DeletionProbe::Failed(other) => Err(CoreError::AuthFailed(format!(
            "could not check whether the account is deleted ({other}). Your credentials were NOT \
             removed; try again when you are online."
        ))),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountDeletedAnswer {
    account_deleted: bool,
}

/// After the server has finalized this account's deletion, removes this computer's local
/// credential and device key the same way a confirmed sign-out does. The synced folders and the
/// local replica data are never touched.
///
/// Fails closed: the credential is only removed when the account's refusal is independently
/// confirmed as a revoked registration, so calling this while the account still exists (the
/// grace period, a cancelled deletion) changes nothing.
pub async fn complete_account_deletion() -> Result<SignOutReport, CoreError> {
    let dir = credential_store::process_dir()?;
    complete_account_deletion_in(&dir, &credential_store::CredentialSettings::from_env(&dir)?).await
}

/// [`complete_account_deletion`] for the state directory `dir`.
pub async fn complete_account_deletion_in(
    dir: &std::path::Path,
    settings: &credential_store::CredentialSettings,
) -> Result<SignOutReport, CoreError> {
    if credential_store::installation_in(dir, settings)?.is_none() {
        return Err(CoreError::NotLoggedIn);
    }
    let auth = crate::coordination::http_client::require_auth_in(dir, settings).await?;
    let answer = crate::coordination::http_client::get_json::<crate::ops::account::DeletionStatus>(
        "/account/deletion/status",
        &auth,
    )
    .await;
    let probe = match answer {
        Ok(_) => DeletionProbe::StillExists,
        Err(error) => match denied_401_detail(error) {
            Ok(detail) => {
                let confirmed = confirm_after_401(&auth).await;
                let account_deleted = if matches!(confirmed, Confirmed::Revoked) {
                    crate::coordination::http_client::get_json_unauthenticated::<AccountDeletedAnswer>(
                        auth.addr(),
                        &format!("/installation-status/{}/account-deleted", auth.client_id()),
                    )
                    .await
                    .ok()
                    .map(|answer| answer.account_deleted)
                } else {
                    None
                };
                DeletionProbe::Denied401 { detail, confirmed, account_deleted }
            }
            Err(other) => DeletionProbe::Failed(other),
        },
    };
    deletion_completion_verdict(probe)?;
    credential_store::clear_in(dir, settings).await?;
    Ok(SignOutReport {
        kind: SignOutKind::ConfirmedRevokedAfterRejection,
        key_cleanup_warning: delete_device_key_mirrors_for(dir, settings.key_mirror),
    })
}

/// Destroys this machine's stored credential WITHOUT revoking anything, and removes the device
/// key's OS keyring copy. The returned text, when present, says that copy could not be removed.
///
/// After this the installation is still authorized on the server and a copy
/// of the refresh token still works, which is why it is not what signing out
/// does.
pub async fn forget_local_credentials() -> Result<Option<String>, CoreError> {
    if credential_store::installation()?.is_none() {
        return Err(CoreError::NotLoggedIn);
    }
    credential_store::clear().await?;
    Ok(delete_device_key_mirrors())
}

/// Remove everything this machine keeps in its credential store, without
/// revoking anything on the server: the local purge the uninstaller runs for
/// `--purge-data`. Unlike [`forget_local_credentials`] it is not an error to
/// have nothing stored. It also removes the device-key mirrors (on every
/// platform; macOS additionally sweeps the whole credential keychain group).
/// The returned text, when present, says a device key copy could not be removed.
pub async fn purge_local_credentials() -> Result<Option<String>, CoreError> {
    credential_store::purge_local().await?;
    Ok(delete_device_key_mirrors())
}

/// The local purge for a caller that already holds the store's lock (the uninstaller, which
/// removes the data directory right after): the configured backend, then the device key's
/// keyring copies named by the key files under `config_dir`. The copies are found through those
/// files, so this runs before they are deleted. The returned text says a copy could not be
/// removed.
pub fn purge_local_credentials_locked(
    store: &yadorilink_fapi_client::store::CredentialStore,
    lock: &yadorilink_fapi_client::store::CredentialLock,
    config_dir: &std::path::Path,
) -> Result<Option<String>, CoreError> {
    purge_local_credentials_locked_with(store, lock, config_dir, &|path| {
        yadorilink_transport::DeviceSigningKeyPair::delete_keyring_entry(
            path,
            crate::coordination::credential_store::key_mirror(),
        )
    })
}

/// [`purge_local_credentials_locked`] with the keyring deletion supplied (tests use a fake).
pub fn purge_local_credentials_locked_with(
    store: &yadorilink_fapi_client::store::CredentialStore,
    lock: &yadorilink_fapi_client::store::CredentialLock,
    config_dir: &std::path::Path,
    delete: &DeleteKeyMirror,
) -> Result<Option<String>, CoreError> {
    store.purge_local(lock)?;
    Ok(delete_device_key_mirrors_in(config_dir, delete))
}

/// Removes the OS keyring copies of this machine's device key and of every retired one, leaving
/// the key files. `None` when every copy is gone (or never existed).
fn delete_device_key_mirrors_for(
    dir: &std::path::Path,
    mirror: yadorilink_transport::KeyMirror,
) -> Option<String> {
    delete_device_key_mirrors_in(dir, &|path| {
        yadorilink_transport::DeviceSigningKeyPair::delete_keyring_entry(path, mirror)
    })
}

/// [`delete_device_key_mirrors_for`] this process's configured state directory.
fn delete_device_key_mirrors() -> Option<String> {
    match crate::coordination::device_config::config_dir() {
        Ok(dir) => delete_device_key_mirrors_for(&dir, credential_store::key_mirror()),
        Err(error) => Some(format!(
            "the device key's copy in the OS credential store was not removed, because the \
             configuration directory could not be found ({error})"
        )),
    }
}

use yadorilink_transport::KeyringDelete;

pub type DeleteKeyMirror<'a> =
    dyn Fn(&std::path::Path) -> Result<KeyringDelete, yadorilink_transport::TransportError> + 'a;

fn delete_device_key_mirrors_in(dir: &std::path::Path, delete: &DeleteKeyMirror) -> Option<String> {
    let mut paths = vec![dir.join("signing_key")];
    let mut failures = Vec::new();
    let retired_dir = dir.join(crate::ops::start_over::RETIRED_DIR);
    match std::fs::read_dir(&retired_dir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => paths.push(entry.path().join("signing_key")),
                    Err(error) => failures.push(format!("{}: {error}", retired_dir.display())),
                }
            }
        }
        // No retired identity was ever kept.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => failures.push(format!("{}: {error}", retired_dir.display())),
    }
    failures.extend(paths.iter().filter_map(|path| delete(path).err().map(|e| e.to_string())));
    if failures.is_empty() {
        return None;
    }
    Some(format!(
        "the device key's copy in the OS credential store could not be removed and may still \
         be there: {}",
        failures.join("; ")
    ))
}

#[cfg(test)]
mod tests;
