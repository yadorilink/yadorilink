//! HTTP-facing error type. Every handler in this crate returns
//! `Result<T, ApiError>`; this module is the one place that decides which
//! HTTP status code a given failure gets, so that decision is made
//! consistently rather than ad hoc per handler.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug)]
pub enum ApiError {
    /// No (or an incorrect) bearer token on a request that requires one.
    Unauthorized,
    /// The `Host`/`Origin` header didn't pass this adapter's own DNS-rebinding
    /// / cross-origin defenses -- see `security.rs`.
    Forbidden(&'static str),
    /// A required request parameter (e.g. `?path=`) is missing or malformed.
    BadRequest(String),
    /// The control socket could not be reached at all (daemon not running,
    /// or this adapter's own configured socket path is wrong).
    DaemonUnavailable,
    /// The daemon accepted the request and framing but reported a
    /// `DaemonControlResponse.error` (a free-text string; the daemon's own
    /// wire protocol has no structured error code for these -- see
    /// `control_client`'s module doc comment). Surfaced as a client error
    /// (400) rather than a server error (502): every request this adapter
    /// forwards that can produce this is a caller-suppled-path lookup
    /// (`versions`, `materialization`, `pause`, `evict`, ...), so an
    /// unresolvable path is the overwhelmingly common cause.
    DaemonRejected(String),
    /// Anything else: a framing/protocol-version mismatch between this
    /// adapter and the daemon it's talking to, or an internal bug.
    Internal(String),
    /// `/api/events` is already at `AppState::sse_slots`' concurrency cap.
    /// Rejected outright rather than queued -- see that field's own doc
    /// comment.
    TooManyStreams,
    /// A long request (see `ControlClient::send_long`) was still running when
    /// this adapter stopped waiting. The daemon carries on with it, so the
    /// caller must look at the current state before asking again.
    StillRunning,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl ApiError {
    fn status_and_message(&self) -> (StatusCode, String) {
        match self {
            ApiError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "missing or invalid bearer token".to_string())
            }
            ApiError::Forbidden(reason) => (StatusCode::FORBIDDEN, reason.to_string()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::DaemonUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "could not reach the yadorilink daemon control socket".to_string(),
            ),
            ApiError::DaemonRejected(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            ApiError::TooManyStreams => (
                StatusCode::SERVICE_UNAVAILABLE,
                "too many concurrent /api/events streams; try again shortly".to_string(),
            ),
            ApiError::StillRunning => (
                StatusCode::GATEWAY_TIMEOUT,
                "the daemon is still working on this request; check the current state before \
                 trying again"
                    .to_string(),
            ),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.status_and_message().1)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = self.status_and_message();
        (status, axum::Json(ErrorBody { error: message })).into_response()
    }
}
