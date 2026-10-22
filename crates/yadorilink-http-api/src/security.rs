//! Request-level security gates. Three independent layers, all mandatory:
//!
//! 1. [`require_known_host`] -- applied to *every* route (including the
//!    static Web UI): the `Host` header must exactly name one of this
//!    adapter's own bound loopback addresses. This is the primary defense
//!    against DNS rebinding. An attacker's page at `http://evil.example`
//!    can make `evil.example`'s DNS record resolve to `127.0.0.1`, but it
//!    cannot make the browser send a `Host` header naming anything other
//!    than `evil.example` -- `Host` is set by the browser from the request
//!    URL and is on the Fetch standard's forbidden-header list, so
//!    client-side JS cannot override it. A rebound request's `Host` header
//!    therefore never matches this allowlist, regardless of which IP it
//!    actually connects to.
//! 2. [`require_allowed_origin`] -- applied to every route: when a request
//!    carries an `Origin` header (every browser `fetch`/`XHR` sends one,
//!    same-origin or not; plain navigations and non-browser clients such as
//!    `curl` typically do not) it must exactly match this adapter's own
//!    origin or an explicitly configured dev-server origin. Requests
//!    without an `Origin` header fall through to bearer-token
//!    authentication instead.
//! 3. [`require_bearer_token`] -- applied only to `/api/*`: every request
//!    must carry `Authorization: Bearer <token>` matching this run's
//!    freshly generated token (`token.rs`). The token is never accepted
//!    from a cookie or query string -- see the crate root doc comment for
//!    why a cookie specifically would reopen a CSRF hole despite the Origin
//!    check above (a cookie is auto-attached by the browser to *any*
//!    request to this origin, cross-origin page or not; a header is not).
//!
//! Streams the daemon authorized as another device on the same account
//! (`Access::Peer`, see `peer.rs`) skip layer 3, accept any loopback `Host`
//! port in layer 1, and in layer 2 need `Origin` to be exactly their own
//! `http://<Host>`, present on every state-changing request.
//!
//! [`add_security_headers`] is a fourth, response-side layer (not a gate):
//! every response, including one an earlier layer already rejected, gets
//! `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` -- this
//! adapter's responses (status/link/token data, and the shell page that
//! reads a bearer token out of `localStorage`) are never something a shared
//! cache or a MIME-sniffing browser should treat as reusable or
//! reinterpretable.

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::{Access, AppState};

/// The body of a refused `Host`. The usual cause is an `ssh -L` tunnel whose
/// local port differs from the dashboard's own port (the browser then sends
/// that other port in `Host`), so the refusal says how to open it instead.
/// The allowlist itself stays exact.
pub const HOST_REFUSED: &str = "Host header not recognized by this adapter. Open the dashboard \
                                at http://127.0.0.1:<port>/ with its own port; an ssh -L tunnel \
                                must use the same port on both sides.";

pub async fn require_known_host(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let known = match state.access {
        Access::LocalTcp => state.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)),
        // The managing device's own loopback listener, on a port of its
        // choosing; still only a loopback name (see `peer.rs`).
        Access::Peer => crate::peer::is_loopback_host(host),
    };
    if !known {
        tracing::warn!(host, "rejected request: Host header not in this adapter's allowlist");
        return Err(ApiError::Forbidden(HOST_REFUSED));
    }
    Ok(next.run(req).await)
}

pub async fn require_allowed_origin(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if state.access == Access::Peer {
        return require_peer_origin(req, next).await;
    }
    if let Some(origin_header) = req.headers().get(header::ORIGIN) {
        // A real browser-issued `Origin` header is always ASCII (it's
        // built from a URI's scheme/host/port); a value that fails to
        // parse as one is never going to equal-match this adapter's own
        // allowlist entries either, so treat it as a rejection -- not as
        // "no Origin header was sent" -- fail closed rather than falling
        // through to bearer-token auth alone.
        let Ok(origin) = origin_header.to_str() else {
            tracing::warn!("rejected request: Origin header is not valid ASCII/UTF-8");
            return Err(ApiError::Forbidden("Origin not allowed by this adapter"));
        };
        if !state.allowed_origins.iter().any(|o| o == origin) {
            tracing::warn!(origin, "rejected request: Origin not in this adapter's allowlist");
            return Err(ApiError::Forbidden("Origin not allowed by this adapter"));
        }
    }
    Ok(next.run(req).await)
}

/// The peer path's Origin rule (see `peer.rs`). With no token behind it,
/// this is what stops another page in the managing device's browser: an
/// `Origin` must be exactly this request's own `http://<Host>`, and a
/// request that can change state must carry one. Browsers send `Origin` on
/// every such request, so only a forged or cross-site one is refused.
async fn require_peer_origin(req: Request, next: Next) -> Result<Response, ApiError> {
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    match req.headers().get(header::ORIGIN) {
        Some(origin) => {
            let Ok(origin) = origin.to_str() else {
                return Err(ApiError::Forbidden("Origin not allowed by this adapter"));
            };
            let own = origin
                .strip_prefix("http://")
                .is_some_and(|rest| !host.is_empty() && rest.eq_ignore_ascii_case(host));
            if !own {
                tracing::warn!(origin, "rejected request: Origin is not this page's own");
                return Err(ApiError::Forbidden("Origin not allowed by this adapter"));
            }
        }
        None if !req.method().is_safe() => {
            tracing::warn!("rejected request: a state-changing request without Origin");
            return Err(ApiError::Forbidden("Origin not allowed by this adapter"));
        }
        None => {}
    }
    Ok(next.run(req).await)
}

pub async fn require_bearer_token(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // A stream the daemon already authorized as a same-account device.
    if state.access == Access::Peer {
        return Ok(next.run(req).await);
    }
    // RFC 7235 says the auth-scheme token ("Bearer") is compared
    // case-insensitively; `str::strip_prefix` alone is not, so this splits
    // the scheme off explicitly instead.
    let presented =
        req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then_some(rest)
        });
    let ok = match presented {
        Some(presented) => constant_time_eq(presented.as_bytes(), state.token.as_bytes()),
        None => false,
    };
    if !ok {
        return Err(ApiError::Unauthorized);
    }
    Ok(next.run(req).await)
}

/// Response-side, not a gate: always runs, on every response including one
/// an earlier layer already rejected -- see this module's own doc comment.
pub async fn add_security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Not built for speed -- built so a mismatching guess doesn't run in
/// visibly-varying time depending on where the first differing byte falls.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests;
