//! HTTP+WebSocket client for the Cloudflare-hosted coordination plane —
//! the sole path every front end takes to the coordination service. Talks to the
//! service's plain JSON routes; every coordination command goes through
//! the request helpers in this module.
//!
//! # An authenticated request cannot be built without a credential
//!
//! Every helper here used to take `access_token: Option<&str>` and call
//! `bearer_auth`. Three things were wrong with that and only one of them was
//! the `Option`:
//!
//! * `None` was reachable from any call site, so "authenticated route" and
//!   "unauthenticated route" were the same function and the difference was one
//!   argument nobody had to justify;
//! * a `&str` is not a credential on the plane this product is cutting over to.
//!   The Coordination API is a DPoP resource server: it wants
//!   `Authorization: DPoP <token>` **and** a proof signed by the key that token
//!   was issued against, minted fresh for this method and this URL;
//! * an access token lives five minutes, so a token that was valid when a
//!   caller obtained it is not necessarily valid when the request is sent.
//!
//! So every helper here takes [`CoordinationAuth`] by reference and not by
//! `Option`. There is exactly one way to produce a `CoordinationAuth` -- from a
//! `yadorilink_fapi_client::CredentialManager`, which needs an enrolled client
//! key and refresh token in the credential store -- and no way at all to
//! produce one from an access token. `require_auth` is the only thing in this
//! crate that builds one.
//!
//! That claim now has no exception. `CoordinationAuth` used to be an enum with
//! a `LegacySession(String)` arm, which was the one constructor that took a
//! bare token; it has been deleted along with the Worker's
//! `authorizeLegacySession`. There is no constructor anywhere in this
//! workspace that turns a string into a credential.
//!
//! # There is no unauthenticated request helper
//!
//! There were two, `post_json_unauthenticated` and
//! `post_json_no_content_unauthenticated`, carried over from the sign-in legs
//! of the deleted `sessions` plane: `POST /auth/google`, the device-login
//! broker, and a logout that presented a refresh token as its whole
//! credential. Every one of those routes is gone, and the helpers had no
//! caller left.
//!
//! They are deleted rather than kept for a future need, because a generic
//! "POST anything to any coordination path with no credential" primitive is
//! most of a second credential plane already built: it is the one shape that
//! lets a new route be added without anyone having to answer what authenticates
//! it. The rule this module exists to hold is that a caller cannot reach the
//! Coordination API except through a credential, and an unauthenticated POST
//! that takes the path as an argument is precisely the hole in it.
//!
//! Enrolment genuinely does need HTTP before an OAuth client exists -- that is
//! what enrolment is for -- and it does not come back here for it. It lives in
//! `yadorilink_fapi_client::{open_enrolment, poll_enrolment,
//! complete_enrolment}`: three functions named for the one transaction they
//! run, each posting to its own `BOOTSTRAP_*_PATH` constant rather than to a
//! path a caller chooses.

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;
use yadorilink_fapi_client::{CoordinationAuth, CredentialManager};

use crate::error::{CoreError, LimitKind};

/// Serializes test-only mutation of `YADORILINK_COORDINATION_ADDR`, the
/// process-global env var [`coordination_addr`] reads -- shared by
/// every test in this crate that points the coordination HTTP client at a
/// local mock server, so two such tests can never race on the same global
/// env var when `cargo test` runs them concurrently in one process. A
/// `tokio::sync::Mutex`, not `std::sync::Mutex`: some of these tests hold
/// the guard across a multi-request `.await` span, and a
/// `std::sync::MutexGuard` held across an await point is exactly what
/// `clippy::await_holding_lock` flags as a real hazard (a blocked std mutex
/// can starve the async runtime); the tokio version is designed to be held
/// this way.
#[cfg(test)]
pub(crate) static COORDINATION_ADDR_ENV_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

/// Loopback endpoint used when neither the environment nor the build supplies
/// one (development and local builds).
const LOOPBACK_COORDINATION_ADDR: &str = "http://127.0.0.1:8787";

/// Endpoint baked in at build time. Release builds set
/// `YADORILINK_DEFAULT_COORDINATION_ADDR` while compiling; other builds leave
/// it unset and fall back to loopback.
const COMPILED_COORDINATION_ADDR: Option<&str> =
    option_env!("YADORILINK_DEFAULT_COORDINATION_ADDR");

/// The coordination endpoint: the `YADORILINK_COORDINATION_ADDR` environment
/// variable if set, else the build-time default, else loopback. This is the
/// single resolver for the request base URL and for the endpoint recorded in
/// `device.json` at registration.
pub fn coordination_addr() -> String {
    resolve_coordination_addr(
        std::env::var("YADORILINK_COORDINATION_ADDR").ok().as_deref(),
        COMPILED_COORDINATION_ADDR,
    )
}

fn resolve_coordination_addr(env: Option<&str>, compiled: Option<&str>) -> String {
    [env, compiled]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|v| !v.is_empty())
        .unwrap_or(LOOPBACK_COORDINATION_ADDR)
        .to_string()
}

/// Where this installation's Authorization Server lives.
///
/// Defaults to the issuer recorded in the credential store, which is the right
/// answer for every deployment: the issuer is the AS's own identity and it
/// emits issuer-absolute URLs. The override exists for a local `wrangler dev`,
/// where the issuer is the deployed hostname and the socket is loopback —
/// exactly the split `FapiClient::to_local` was built for.
pub const AUTH_SERVER_ADDR_VAR: &str = "YADORILINK_AUTH_SERVER_ADDR";

/// The credential for an authenticated coordination call, or
/// [`CoreError::NotLoggedIn`] if this installation has not enrolled.
///
/// This is the single place a `CoordinationAuth` is built in this crate, and
/// it has one branch, not two. An enrolled installation has a `client_id`, a
/// client key and a refresh token in the credential store; a
/// [`CredentialManager`] is built over them, which means one discovery round
/// trip and, if the cached token is spent, one refresh. Every request
/// thereafter gets a live token and a fresh DPoP proof from it.
///
/// An empty store is [`CoreError::NotLoggedIn`] and nothing else. It is not a
/// signal to look somewhere older: the legacy `sessions`-table credential this
/// used to fall back to no longer exists in the store, in this crate, or in
/// the Worker.
///
/// A credential store that cannot be read is [`CoreError::CredentialStore`],
/// not "not logged in". The two send the user to opposite places: one to
/// `yadorilink login`, which would succeed and leave the damaged store behind;
/// the other to the store itself.
///
/// Built per call rather than cached in a process-global: a CLI process runs
/// one command, and a cached manager would hold the refresh lock's peer view
/// of the store across a command that deliberately rewrites it (`logout`).
pub async fn require_auth() -> Result<CoordinationAuth, CoreError> {
    bounded(build_auth()).await
}

async fn build_auth() -> Result<CoordinationAuth, CoreError> {
    let store = crate::coordination::credential_store::open()?;
    let credentials = store.load()?.ok_or(CoreError::NotLoggedIn)?;
    let base =
        std::env::var(AUTH_SERVER_ADDR_VAR).unwrap_or_else(|_| credentials.issuer().to_owned());
    let manager =
        CredentialManager::from_credentials(client()?, &base, Arc::new(store), &credentials)
            .await?;
    Ok(CoordinationAuth::new(Arc::new(manager))?)
}

/// Whether this machine holds any credential at all.
///
/// Deliberately synchronous and deliberately *not* a weaker `require_auth`: it
/// answers "should the UI offer sign-in or sign-out?", which the desktop app's
/// tray asks every two seconds, and building a credential manager (a discovery
/// round trip, possibly a refresh) to answer a menu-rendering question would
/// put a network call on a 2 s timer. A store this process cannot read reads as
/// not signed in here, because the remedy the menu can offer is the same
/// either way; every path that actually *uses* a credential reports the store's
/// error instead.
#[must_use]
pub fn is_signed_in() -> bool {
    let Ok(store) = crate::coordination::credential_store::open() else { return false };
    matches!(store.load(), Ok(Some(_)))
}

/// Coordination-address validation: a remote address must use `https://`;
/// only a loopback host may use plain `http://` (local `wrangler dev`).
/// Uses the `url` crate to parse the address rather than hand-rolled string
/// splitting -- an earlier hand-rolled version of this function split on
/// `:` to find the host, which silently mangled IPv6 literal addresses
/// like `http://[::1]:8787` (the same bug class this crate's own
/// `google_login.rs`/`peer_orchestrator.rs` avoided by switching to `url`
/// too).
fn validate_addr(addr: &str) -> Result<(), CoreError> {
    let url = url::Url::parse(addr).map_err(|e| {
        CoreError::CoordinationPlaneUnreachable(format!("invalid coordination address: {e}"))
    })?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(&url) => Ok(()),
        "http" => Err(CoreError::CoordinationPlaneUnreachable(
            "remote coordination addresses must use https://".to_string(),
        )),
        _ => Err(CoreError::CoordinationPlaneUnreachable(
            "coordination address must use http:// or https://".to_string(),
        )),
    }
}

/// Matches on `url`'s typed `Host` enum rather than `host_str` -- for an
/// IPv6 literal, `host_str` returns the bracketed authority form
/// (`"[::1]"`), which `std::net::IpAddr::from_str` cannot parse; a first
/// attempt at this fix used `host_str` this way and shipped with exactly
/// that bug (caught by `validate_addr_handles_an_ipv6_loopback_literal`
/// below). `Host::Ipv6` carries an already-parsed `Ipv6Addr` directly, so
/// there is no string/bracket handling left to get wrong.
fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// How long connecting to the coordination plane may take.
const CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// How long one coordination request may take, answer included. Every
/// request here moves a small JSON body, so a longer wait is a stalled
/// connection, which the app could not otherwise abandon.
const REQUEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);

/// How long one operation may take end to end: building the credential
/// (discovery, a refresh) or sending an authenticated request (which may
/// refresh once). Each step has its own [`REQUEST_BUDGET`], so without this a
/// stalled service could be waited on once per step.
const OPERATION_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// Runs one coordination step under [`OPERATION_BUDGET`]; running out is the
/// same "cannot reach the service" the UI already shows for a refused connection.
async fn bounded<T>(
    step: impl std::future::Future<Output = Result<T, CoreError>>,
) -> Result<T, CoreError> {
    tokio::time::timeout(OPERATION_BUDGET, step).await.unwrap_or_else(|_| {
        Err(CoreError::CoordinationPlaneUnreachable(
            "the coordination service did not answer in time".into(),
        ))
    })
}

/// The HTTP client for every coordination request this crate makes, sign-in
/// included, with [`CONNECT_BUDGET`] and [`REQUEST_BUDGET`].
pub(crate) fn client() -> Result<reqwest::Client, CoreError> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_BUDGET)
        .timeout(REQUEST_BUDGET)
        .build()
        .map_err(|e| CoreError::CoordinationPlaneUnreachable(e.to_string()))
}

async fn handle_response<Resp: DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<Resp, CoreError> {
    let status = resp.status();
    if status.is_success() {
        return resp.json::<Resp>().await.map_err(|e| {
            // A body that stalls or is cut off is the service not answering,
            // not a malformed answer.
            if e.is_timeout() || e.is_body() {
                CoreError::CoordinationPlaneUnreachable(e.to_string())
            } else {
                CoreError::Other(e.to_string())
            }
        });
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(body) => body,
        // The status line arrived but the body never finished: the service
        // is not answering, whatever the status said.
        Err(e) if e.is_timeout() || e.is_body() => {
            return Err(CoreError::CoordinationPlaneUnreachable(e.to_string()));
        }
        Err(_) => serde_json::Value::default(),
    };
    Err(error_from_body(status.as_u16(), &body))
}

/// Maps a failed coordination response body to a `CoreError`. Split out from
/// `handle_response` so the classification is unit-testable without
/// constructing a `reqwest::Response`.
///
/// The typed `quota_exceeded` and
/// `rate_limited` bodies (shared by the CLI and, via this same client, the
/// desktop app) are rendered as specific, actionable messages rather than the
/// opaque code, and classified as `LimitExceeded` (user-actionable) rather than
/// as a coordination-plane outage.
fn error_from_body(status: u16, body: &serde_json::Value) -> CoreError {
    let code = body.get("error").and_then(|v| v.as_str()).unwrap_or("");

    if code == "quota_exceeded" {
        let resource = body.get("resource").and_then(|v| v.as_str()).unwrap_or("resource");
        let limit = body.get("limit").and_then(|v| v.as_u64());
        let current = body.get("current").and_then(|v| v.as_u64());
        let human = match resource {
            "devices" => "registered devices",
            "folder_groups" => "folder groups",
            "share_edges" => "shared devices",
            "netmap_entries" => "network map entries",
            other => other,
        };
        let counts = match (current, limit) {
            (Some(c), Some(l)) => format!(" ({c} of {l})"),
            (_, Some(l)) => format!(" (limit {l})"),
            _ => String::new(),
        };
        let advice = "remove some before adding more, or ask an operator to raise the limit";
        return CoreError::LimitExceeded {
            message: format!("you've reached the {human} limit{counts}; {advice}"),
            kind: LimitKind::Quota,
        };
    }

    if code == "rate_limited" {
        let retry = body.get("retryAfterSeconds").and_then(|v| v.as_u64());
        let msg = match retry {
            Some(secs) => format!("too many requests; retry in about {secs}s"),
            None => "too many requests; slow down and retry shortly".to_string(),
        };
        return CoreError::LimitExceeded { message: msg, kind: LimitKind::RateLimited };
    }

    let message = if code.is_empty() { "request failed".to_string() } else { code.to_string() };
    match status {
        401 => CoreError::AuthFailed(message),
        403 => CoreError::Forbidden(message),
        429 | 503 => CoreError::CoordinationPlaneUnreachable(message),
        _ => CoreError::Other(message),
    }
}

/// Builds the request URL for `path` after checking the configured coordination
/// address is one this client will talk to at all.
fn endpoint(path: &str) -> Result<String, CoreError> {
    let addr = coordination_addr();
    validate_addr(&addr)?;
    Ok(format!("{addr}{path}"))
}

pub async fn post_json<Req: Serialize, Resp: DeserializeOwned>(
    path: &str,
    body: &Req,
    auth: &CoordinationAuth,
) -> Result<Resp, CoreError> {
    let url = endpoint(path)?;
    bounded(async {
        let resp = auth.execute(client()?.post(&url).json(body)).await?;
        handle_response(resp).await
    })
    .await
}

/// A failed coordination answer that carries its status and body, for a caller that has to tell
/// one typed refusal from another (the generic mapping of [`error_from_body`] folds them).
#[derive(Debug)]
pub struct ApiFailure {
    pub status: u16,
    /// The body's machine-readable `code`, when it has one.
    pub code: Option<String>,
    body: serde_json::Value,
}

impl ApiFailure {
    pub(crate) fn from_parts(status: u16, body: serde_json::Value) -> Self {
        let code = body.get("code").and_then(|v| v.as_str()).map(str::to_owned);
        Self { status, code, body }
    }

    /// The generic classification, for every failure the caller does not handle itself.
    #[must_use]
    pub fn into_core_error(self) -> CoreError {
        error_from_body(self.status, &self.body)
    }
}

/// Like `post_json`, but an HTTP failure status comes back as an [`ApiFailure`] instead of being
/// folded into a [`CoreError`]. The outer error is a request that did not complete (no credential,
/// no connection, a stalled answer).
pub async fn post_json_with_failure<Req: Serialize, Resp: DeserializeOwned>(
    path: &str,
    body: &Req,
    auth: &CoordinationAuth,
) -> Result<Result<Resp, ApiFailure>, CoreError> {
    let url = endpoint(path)?;
    bounded(async {
        let resp = auth.execute(client()?.post(&url).json(body)).await?;
        let status = resp.status();
        if status.is_success() {
            return handle_response(resp).await.map(Ok);
        }
        let body: serde_json::Value = match resp.json().await {
            Ok(body) => body,
            Err(e) if e.is_timeout() || e.is_body() => {
                return Err(CoreError::CoordinationPlaneUnreachable(e.to_string()));
            }
            Err(_) => serde_json::Value::default(),
        };
        Ok(Err(ApiFailure::from_parts(status.as_u16(), body)))
    })
    .await
}

/// Like `post_json`, but for endpoints that return `204 No Content` on success (logout, revoke, etc.).
pub async fn post_json_no_content<Req: Serialize>(
    path: &str,
    body: &Req,
    auth: &CoordinationAuth,
) -> Result<(), CoreError> {
    let url = endpoint(path)?;
    bounded(async {
        let resp = auth.execute(client()?.post(&url).json(body)).await?;
        if resp.status().is_success() {
            return Ok(());
        }
        handle_response::<serde_json::Value>(resp).await.map(|_| ())
    })
    .await
}

pub async fn get_json<Resp: DeserializeOwned>(
    path: &str,
    auth: &CoordinationAuth,
) -> Result<Resp, CoreError> {
    let url = endpoint(path)?;
    bounded(async {
        let resp = auth.execute(client()?.get(&url)).await?;
        handle_response(resp).await
    })
    .await
}

/// Issues a `DELETE` with no request body for endpoints that return
/// `204 No Content` on success (e.g. terminal single-group delete).
pub async fn delete_no_content(path: &str, auth: &CoordinationAuth) -> Result<(), CoreError> {
    let url = endpoint(path)?;
    bounded(async {
        let resp = auth.execute(client()?.delete(&url)).await?;
        if resp.status().is_success() {
            return Ok(());
        }
        handle_response::<serde_json::Value>(resp).await.map(|_| ())
    })
    .await
}

#[cfg(test)]
mod tests;
