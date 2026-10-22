//! Daemon-side handlers for the diagnostics IPC surface added to
//! `daemon_control.proto`. Kept in its own module, mirroring
//! `reporting_ipc.rs`/`update_ipc.rs`'s precedent, rather than inlined
//! into `control_socket.rs`'s match arms.
//!
//! This module is now IPC encode/package only: bundle *assembly* lives in
//! `crate::queries::diagnostics_bundle::DiagnosticsBundleQueryService`
//! (composing narrow ports, none of which know about protobuf or JSON);
//! this module's own job is turning that plain snapshot into the exact
//! JSON shape the diagnostics bundle schema expects, then redacting and
//! wrapping it into the wire response. Redaction is never reimplemented
//! here: every assembled bundle, including the bounded-timeout fallback,
//! is passed through `yadorilink_reporting::redact_diagnostics_value`
//! (the same daemon-independent helper `yadorilink-cli`'s CLI-only
//! fallback bundle already uses) before it ever leaves this module.
//!
//! Bounded generation time and failure handling: bundle assembly runs on
//! a `spawn_blocking` worker thread (mirroring `hydration.rs`'s "move
//! synchronous I/O off the tokio worker" precedent for `BlockStore::put`),
//! wrapped in `tokio::time::timeout` (`hydration::hydrate_with_timeout`'s
//! own established pattern) so a slow or stuck sub-collection (e.g. an
//! unexpectedly large number of files/links to walk) can never hang the
//! control-socket connection -- the caller always gets a response within
//! `DIAGNOSTICS_BUNDLE_TIMEOUT`, either the real bundle or a minimal,
//! still schema-valid `"daemon-partial"` fallback.

use std::time::Duration;

use serde_json::json;
use yadorilink_ipc_proto::daemonctl::{DiagnosticsBundleResponse, RedactionCategoryCount};

use crate::queries::diagnostics_bundle::{
    DiagnosticsBundleQueryService, DiagnosticsBundleSnapshot,
};

/// The overall time budget for one bundle-assembly call.
/// Chosen to match `PER_BLOCK_FETCH_TIMEOUT` (`hydration.rs`) -- long
/// enough for a large number of links/files to be walked even on a
/// loaded daemon, short enough that a CLI `diagnose preview`/`export`
/// never appears to hang. Every sub-collection this module performs is
/// local (in-memory state or local disk stat calls, never network I/O),
/// so 5 seconds is generous, not tight.
const DIAGNOSTICS_BUNDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// `yadorilink diagnose preview`/`export` (daemon-backed path): both
/// request the exact same assembled-and-redacted bundle -- see this
/// module's doc comment and `daemon_control.proto`'s
/// `DiagnosticsBundleResponse` doc comment for why preview/export share
/// one response shape.
pub(crate) async fn build_bundle(
    bundle_query: &std::sync::Arc<DiagnosticsBundleQueryService>,
) -> DiagnosticsBundleResponse {
    let bundle_query = bundle_query.clone();
    let generated_at_unix = crate::reporting::time::now_unix_seconds() as i64;
    run_bounded(DIAGNOSTICS_BUNDLE_TIMEOUT, move || {
        assemble_bundle_json(&bundle_query, generated_at_unix)
    })
    .await
}

/// The actual bound: runs `work` on a `spawn_blocking` thread and gives
/// it `timeout` to finish. A `work` closure that never returns (the
/// "stuck sub-collection" case) leaves its thread running in the
/// background -- synchronous code can't be forcibly preempted -- but the
/// control socket itself always gets an answer by `timeout`, which is
/// the actual guarantee here ("cannot hang indefinitely").
async fn run_bounded(
    timeout: Duration,
    work: impl FnOnce() -> serde_json::Value + Send + 'static,
) -> DiagnosticsBundleResponse {
    // Runs `work` on a `spawn_blocking` thread bounded by `timeout`.
    let outcome = tokio::time::timeout(timeout, tokio::task::spawn_blocking(work)).await;
    let (bundle, collection_mode) = match outcome {
        Ok(Ok(bundle)) => (bundle, "daemon"),
        Ok(Err(join_err)) => {
            tracing::warn!(error = %join_err, "diagnostics bundle assembly task panicked");
            (timeout_fallback_bundle(), "daemon-partial")
        }
        Err(_elapsed) => {
            tracing::warn!(
                timeout_secs = timeout.as_secs(),
                "diagnostics bundle generation exceeded its time budget; returning a partial bundle"
            );
            (timeout_fallback_bundle(), "daemon-partial")
        }
    };
    finish_response(bundle, collection_mode)
}

/// Redacts the assembled bundle and packages it into the wire response --
/// shared by the happy path and the bounded-timeout fallback, since both
/// must go through the exact same redaction pass (idempotent, so
/// redacting the already-minimal fallback is harmless).
fn finish_response(bundle: serde_json::Value, collection_mode: &str) -> DiagnosticsBundleResponse {
    let (redacted, summary) = yadorilink_reporting::redact_diagnostics_value(&bundle);
    let redaction_summary = summary
        .categories
        .iter()
        .map(|(category, count)| RedactionCategoryCount {
            category: format!("{category:?}"),
            count: *count as u32,
        })
        .collect();
    DiagnosticsBundleResponse {
        bundle_json: serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| "{}".to_string()),
        redaction_summary,
        collection_mode: collection_mode.to_string(),
    }
}

/// The real, happy-path bundle -- synchronous by construction (every
/// port `DiagnosticsBundleQueryService` composes is itself synchronous),
/// run inside `run_bounded`'s `spawn_blocking` worker. Shape matches the
/// diagnostics bundle schema; this function's only job is turning the
/// plain `DiagnosticsBundleSnapshot` into that exact JSON shape -- no
/// state reads of its own.
fn assemble_bundle_json(
    bundle_query: &DiagnosticsBundleQueryService,
    generated_at_unix: i64,
) -> serde_json::Value {
    encode_bundle_json(bundle_query.build(generated_at_unix))
}

/// `DiagnosticsBundleSnapshot` -> the diagnostics bundle JSON schema.
fn encode_bundle_json(snapshot: DiagnosticsBundleSnapshot) -> serde_json::Value {
    let bundle_links: Vec<serde_json::Value> = snapshot
        .runtime
        .links
        .iter()
        .enumerate()
        .map(|(i, link)| {
            json!({
                // Sequential, per-bundle pseudonyms -- not a hash of the
                // real group_id/local_path -- deliberately, to give
                // "stable pseudonymous IDs... over category-level
                // context" so a support engineer can tell "link 1" apart
                // from "link 2" across the *same* bundle's
                // `links`/`recent_errors` sections without ever seeing the
                // real identifier.
                "link_id": format!("link:{:03}", i + 1),
                "group_id": format!("group:{:03}", i + 1),
                "state": link.state_label,
                // The folder path is user data (names of clients, matters,
                // people); pattern redaction cannot promise to remove all of
                // it, so only a token that distinguishes the links is kept.
                "path": format!("path:{:03}", i + 1),
            })
        })
        .collect();

    let task_health: Vec<serde_json::Value> = snapshot
        .health
        .tasks
        .iter()
        .map(|t| json!({ "name": t.name, "state": if t.alive { "running" } else { "stopped" } }))
        .collect();

    let recent_errors: Vec<serde_json::Value> = snapshot
        .logs
        .recent_errors
        .iter()
        .map(|e| json!({ "category": e.category, "timestamp": e.timestamp, "context": e.context }))
        .collect();

    json!({
        "schema_version": 1,
        "generated_at": crate::reporting::time::unix_seconds_to_rfc3339(
            snapshot.generated_at_unix.max(0) as u64
        ),
        "yadorilink_version": env!("CARGO_PKG_VERSION"),
        "platform": {
            "os_family": std::env::consts::OS,
            "os_version_bucket": "unknown",
            "arch": std::env::consts::ARCH,
        },
        "daemon": {
            "reachable": true,
            "uptime_bucket": uptime_bucket(snapshot.runtime.uptime),
            "task_health": task_health,
        },
        "links": bundle_links,
        "recent_errors": recent_errors,
        "updates": {
            "state": snapshot.update.state,
            "channel": snapshot.update.channel,
            "available_version": snapshot.update.available_version,
            "mandatory": snapshot.update.mandatory,
            "holdback_reason": snapshot.update.holdback_reason,
        },
        "resources": {
            "disk_state": snapshot.runtime.disk_state,
            "limits": snapshot.runtime.limits_state,
        },
        "environment": {
            "install_channel": snapshot.configuration.install_channel,
        },
        "redaction": {
            "version": 1,
            "pseudonymized_fields": ["link_id", "group_id", "path"],
        },
    })
}

/// The fallback shape: a minimal bundle that still satisfies diagnostics
/// bundle required top-level keys, used whenever `run_bounded` can't
/// produce the real one in time (or the assembly task panicked). Its one
/// `recent_errors` entry is synthesized here, not read from the
/// error-candidate store, precisely so the user/support engineer can see
/// that generation was incomplete rather than silently getting an
/// empty-looking-but-actually-fine bundle.
fn timeout_fallback_bundle() -> serde_json::Value {
    let now = crate::reporting::time::now_rfc3339();
    json!({
        "schema_version": 1,
        "generated_at": now,
        "yadorilink_version": env!("CARGO_PKG_VERSION"),
        "platform": {
            "os_family": std::env::consts::OS,
            "os_version_bucket": "unknown",
            "arch": std::env::consts::ARCH,
        },
        "daemon": {
            "reachable": true,
            "uptime_bucket": "unknown",
            "task_health": [],
        },
        "links": [],
        "recent_errors": [
            {
                "category": "diagnostics_generation_incomplete",
                "timestamp": now,
                "context": "one or more diagnostics sub-collections did not complete within the bundle generation time budget",
            }
        ],
        "updates": { "state": "unknown" },
        "resources": { "disk_state": "unknown", "limits": "unknown" },
        "environment": { "install_channel": "unknown" },
        "redaction": { "version": 1, "pseudonymized_fields": [] },
    })
}

/// Coarse "how long has this daemon been running" bucket, reusing the
/// exact bucket labels `UsagePayload.daemon_uptime_bucket`'s doc comment
/// already establishes for this same concept elsewhere in this codebase
/// (`yadorilink-reporting::schema::UsagePayload`), rather than inventing a
/// second, differently-labeled bucket set for what is conceptually the
/// same measurement.
fn uptime_bucket(uptime: Duration) -> &'static str {
    match uptime.as_secs() {
        0..=3599 => "<1h",
        3600..=86_399 => "1h-1d",
        86_400..=604_799 => "1d-7d",
        _ => ">7d",
    }
}

#[cfg(test)]
mod tests;
