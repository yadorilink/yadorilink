//! Optional HTTPS submission client.
//!
//! This module is deliberately narrow and self-contained: it takes a
//! `&ReportEnvelope` and a plain `Option<&str>` endpoint URL and returns
//! a `SubmissionReceipt` or a `SubmissionError` — nothing more. It has
//! no access to (and therefore cannot leak) any yadorilink account
//! token, device identity, or sync/auth state, since callers never hand
//! it any of that; it is structurally impossible for it to attach an
//! `Authorization` header or similar credential.
//!
//! Design constraints enforced here:
//! - HTTPS-only, with the same loopback exception used by
//!   `yadorilink-cli`'s coordination-address validation
//!   (`crates/yadorilink-cli/src/grpc.rs::is_loopback_host`), so a
//!   `127.0.0.1`/`localhost` endpoint can be exercised in tests without
//!   standing up TLS.
//! - A hard client-side timeout, enforced twice: once via reqwest's own
//!   per-request timeout, and again via an outer `tokio::time::timeout`
//!   guard, so a hang anywhere in the connect/TLS/response path cannot
//!   block a caller (e.g. a CLI command) past the configured duration.
//! - A payload-size/shape check that reuses `ReportEnvelope::validate`
//!   (and therefore `MAX_REPORT_BYTES`) rather than reinventing a limit.
//! - A simple client-side rate limiter: a minimum interval between
//!   submission attempts, enforced *before* any network call is made.
//! - `SubmissionError::is_retryable` so a caller can distinguish
//!   transient failures (timeout, network error, 5xx) worth retrying
//!   from permanent ones (no endpoint configured, invalid endpoint,
//!   invalid payload, 4xx) that won't succeed on retry. This module
//!   never retries internally — retry/backoff policy belongs to the
//!   caller, so a single `submit` call can never loop indefinitely.
//! - "No endpoint configured" is representable at the type level
//!   (`endpoint: Option<&str>` -> `SubmissionError::NoEndpointConfigured`)
//!   rather than requiring a placeholder URL, so preview/export-only
//!   builds and configs remain first-class.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::queue::SubmissionReceipt;
use crate::schema::{ReportEnvelope, ValidationError};

/// Tunable knobs for the submission client. Defaults are conservative:
/// a CLI/daemon caller should never feel a hung reporting endpoint, and
/// reporting is not a bulk-submission workload, so a modest minimum
/// interval between attempts is enough to keep a misbehaving caller (or
/// retry loop) from hammering the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmissionConfig {
    /// Hard timeout for the whole request (connect + send + receive).
    /// 10 seconds: long enough to tolerate normal internet latency and
    /// TLS handshake overhead, short enough that a CLI command invoking
    /// `--submit` never feels "stuck" waiting on a maintainer endpoint.
    pub timeout: Duration,
    /// Minimum wall-clock gap this client enforces between the start of
    /// one submission attempt and the next, regardless of outcome.
    pub min_submit_interval: Duration,
}

impl Default for SubmissionConfig {
    fn default() -> Self {
        SubmissionConfig {
            timeout: Duration::from_secs(10),
            min_submit_interval: Duration::from_secs(1),
        }
    }
}

/// Permanent vs. retryable is exposed via [`SubmissionError::is_retryable`]
/// rather than via separate error types, so callers can match on the
/// specific failure while still asking the one question that matters
/// for retry/backoff policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubmissionError {
    /// `endpoint` was `None` — a first-class, non-error-ish state:
    /// callers should treat this as "reporting export/preview still
    /// works, submission just isn't configured," not as a network
    /// failure.
    #[error("no reporting endpoint is configured")]
    NoEndpointConfigured,
    /// The endpoint string was not a valid URL, or was `http://` to a
    /// non-loopback host (see module docs re: the loopback exception).
    #[error("invalid reporting endpoint: {0}")]
    InvalidEndpoint(String),
    /// The envelope failed `ReportEnvelope::validate` — wrong schema
    /// version, missing required field, or over `MAX_REPORT_BYTES`.
    /// Retrying the identical envelope will never succeed.
    #[error("report failed validation before submission: {0}")]
    InvalidPayload(#[from] ValidationError),
    /// This client's own `min_submit_interval` hasn't elapsed yet. No
    /// network call was attempted. `retry_after` is how much longer the
    /// caller should wait before trying again.
    #[error("submission rate limit: retry after {retry_after:?}")]
    RateLimited { retry_after: Duration },
    /// The request did not complete within `SubmissionConfig::timeout`.
    #[error("reporting endpoint timed out after {0:?}")]
    Timeout(Duration),
    /// A connection-level failure (DNS, TCP, TLS) below the HTTP layer.
    #[error("network error while submitting report: {0}")]
    Network(String),
    /// The endpoint responded with a non-2xx status. 5xx is treated as
    /// retryable (server-side/transient); 4xx is treated as permanent
    /// (the request itself was rejected and won't succeed unchanged).
    #[error("reporting endpoint returned HTTP {status}")]
    HttpStatus { status: u16, body_snippet: String },
    /// The endpoint returned 2xx but a body this client could not parse
    /// into a receipt. The endpoint contract is narrow (validate +
    /// return an opaque receipt id), so a malformed 2xx body indicates a
    /// protocol mismatch, not a transient condition.
    #[error("reporting endpoint returned an unparseable response: {0}")]
    InvalidResponse(String),
}

impl SubmissionError {
    /// Whether a caller might reasonably retry this exact submission
    /// later (subject to its own backoff policy — this module never
    /// retries on its own). The caller decides whether to retry.
    pub fn is_retryable(&self) -> bool {
        match self {
            SubmissionError::NoEndpointConfigured => false,
            SubmissionError::InvalidEndpoint(_) => false,
            SubmissionError::InvalidPayload(_) => false,
            SubmissionError::RateLimited { .. } => true,
            SubmissionError::Timeout(_) => true,
            SubmissionError::Network(_) => true,
            SubmissionError::HttpStatus { status, .. } => *status >= 500,
            SubmissionError::InvalidResponse(_) => false,
        }
    }
}

/// The narrow response contract here: "return an opaque receipt ID."
/// `submitted_at` is endpoint-stamped (not generated here)
/// so this module — like the rest of this crate — never needs its own
/// clock source; see `lib.rs`/`schema.rs` module docs for why that
/// property matters for testability.
#[derive(Debug, Deserialize)]
struct SubmitResponseBody {
    receipt_id: String,
    submitted_at: String,
}

/// An HTTPS-only client for submitting report envelopes to a configured
/// maintainer (or fork) endpoint. Holds only an HTTP client, config, and
/// the rate limiter's last-attempt timestamp — no sync/auth/device state
/// is reachable from here by construction.
pub struct SubmissionClient {
    http: reqwest::Client,
    config: SubmissionConfig,
    last_attempt: Mutex<Option<Instant>>,
}

impl SubmissionClient {
    pub fn new(config: SubmissionConfig) -> Result<Self, SubmissionError> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| SubmissionError::Network(e.to_string()))?;
        Ok(SubmissionClient { http, config, last_attempt: Mutex::new(None) })
    }

    pub fn with_default_config() -> Result<Self, SubmissionError> {
        SubmissionClient::new(SubmissionConfig::default())
    }

    /// Submits `envelope` to `endpoint` and returns the endpoint's
    /// receipt, tagged with the caller-supplied `report_id` (this
    /// module never generates report IDs itself — that's the local
    /// queue's job, see `queue.rs`).
    ///
    /// `endpoint: None` short-circuits to
    /// `SubmissionError::NoEndpointConfigured` before anything else runs
    /// (no validation, no rate-limit consumption, no network call) —
    /// this is what makes "no endpoint configured" free for callers that
    /// only want preview/export behavior.
    pub async fn submit(
        &self,
        report_id: &str,
        envelope: &ReportEnvelope,
        endpoint: Option<&str>,
    ) -> Result<SubmissionReceipt, SubmissionError> {
        let Some(endpoint) = endpoint else {
            return Err(SubmissionError::NoEndpointConfigured);
        };
        let url = validate_endpoint(endpoint)?;
        envelope.validate()?;
        self.reserve_rate_limit_slot()?;

        let body = envelope.to_json();
        let request = self
            .http
            .post(url)
            .timeout(self.config.timeout)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send();

        let response = tokio::time::timeout(self.config.timeout, request)
            .await
            .map_err(|_elapsed| SubmissionError::Timeout(self.config.timeout))?
            .map_err(|e| {
                if e.is_timeout() {
                    SubmissionError::Timeout(self.config.timeout)
                } else {
                    SubmissionError::Network(e.to_string())
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let body_snippet = response.text().await.unwrap_or_default();
            let body_snippet: String = body_snippet.chars().take(200).collect();
            return Err(SubmissionError::HttpStatus { status: status.as_u16(), body_snippet });
        }

        let parsed: SubmitResponseBody =
            response.json().await.map_err(|e| SubmissionError::InvalidResponse(e.to_string()))?;

        Ok(SubmissionReceipt {
            report_id: report_id.to_string(),
            receipt_id: parsed.receipt_id,
            submitted_at: parsed.submitted_at,
        })
    }

    /// Enforces `min_submit_interval` *before* any network call is made.
    /// Records the attempt timestamp on success so the next call
    /// (regardless of that attempt's eventual outcome) is measured from
    /// when this one started.
    fn reserve_rate_limit_slot(&self) -> Result<(), SubmissionError> {
        let mut last = self.last_attempt.lock().expect("submission rate-limit lock poisoned");
        let now = Instant::now();
        if let Some(previous) = *last {
            let elapsed = now.duration_since(previous);
            if elapsed < self.config.min_submit_interval {
                return Err(SubmissionError::RateLimited {
                    retry_after: self.config.min_submit_interval - elapsed,
                });
            }
        }
        *last = Some(now);
        Ok(())
    }
}

/// HTTPS-only, with the same loopback exception `yadorilink-cli` uses
/// for its coordination address (see module docs). Kept as a free
/// function (rather than sharing code with `yadorilink-cli::grpc`)
/// since the two crates must not depend on each other, but the policy
/// is intentionally identical in spirit.
fn validate_endpoint(raw: &str) -> Result<reqwest::Url, SubmissionError> {
    let url =
        reqwest::Url::parse(raw).map_err(|e| SubmissionError::InvalidEndpoint(e.to_string()))?;
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback_host(url.host_str()) => Ok(url),
        "http" => Err(SubmissionError::InvalidEndpoint(
            "reporting endpoint must use https:// (http:// is only allowed to a loopback host, \
             for local testing)"
                .to_string(),
        )),
        other => {
            Err(SubmissionError::InvalidEndpoint(format!("unsupported endpoint scheme `{other}`")))
        }
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else { return false };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

#[cfg(test)]
mod tests;
