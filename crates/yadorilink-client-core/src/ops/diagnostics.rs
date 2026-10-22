//! Diagnostics bundles.
//!
//! Prefers the daemon-assembled bundle whenever the daemon is reachable: it
//! has daemon-owned status, config and recent-error state a client process
//! never reads directly. Falls back to a limited, client-only bundle only
//! when the daemon is not reachable at all; any other daemon-side failure (a
//! malformed response, a daemon error) is propagated rather than masked by
//! the fallback, so a real daemon-side bug never just looks like "daemon
//! unavailable".

use serde_json::{json, Value};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{DiagnosticsExportRequest, DiagnosticsPreviewRequest};
use yadorilink_reporting::redact_diagnostics_value;

use crate::coordination::device_config;
use crate::daemon::control;
use crate::error::CoreError;

/// Which request variant to send. Both hit the same daemon-side assembly;
/// only the caller's disposition of the result differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleRequest {
    Preview,
    Export,
}

/// A diagnostics bundle, already redacted.
#[derive(Clone, Debug, PartialEq)]
pub struct DiagnosticsBundle {
    pub bundle: Value,
    /// How many redaction-category matches the bundle's redaction reported.
    pub redaction_count: usize,
    /// Where the bundle came from: `daemon`, `daemon-partial` (generation hit
    /// its bounded time budget) or `cli-only-fallback` (the daemon was not
    /// reachable).
    pub collection_mode: String,
}

/// Fetches a diagnostics bundle, falling back to the limited client-only
/// bundle when the daemon is not running.
pub async fn collect_bundle(request: BundleRequest) -> Result<DiagnosticsBundle, CoreError> {
    let payload = match request {
        BundleRequest::Preview => ReqPayload::DiagnosticsPreview(DiagnosticsPreviewRequest {}),
        BundleRequest::Export => ReqPayload::DiagnosticsExport(DiagnosticsExportRequest {}),
    };
    match control::send(payload).await {
        Ok(resp) => {
            let bundle = match resp.payload {
                Some(RespPayload::DiagnosticsPreview(b))
                | Some(RespPayload::DiagnosticsExport(b)) => b,
                _ => return Err(CoreError::Other("unexpected daemon response".into())),
            };
            let mut value: Value = serde_json::from_str(&bundle.bundle_json)?;
            // Record which assembly path produced this bundle inside the
            // bundle itself, so a bundle shared later still says so.
            if let Some(daemon_obj) = value.get_mut("daemon").and_then(Value::as_object_mut) {
                daemon_obj.insert("collection_mode".to_string(), json!(bundle.collection_mode));
            }
            let count = bundle.redaction_summary.iter().map(|c| c.count as usize).sum();
            Ok(DiagnosticsBundle {
                bundle: value,
                redaction_count: count,
                collection_mode: bundle.collection_mode,
            })
        }
        Err(CoreError::DaemonNotRunning) => {
            let (bundle, count) = limited_bundle();
            Ok(DiagnosticsBundle {
                bundle,
                redaction_count: count,
                collection_mode: "cli-only-fallback".to_string(),
            })
        }
        Err(e) => Err(e),
    }
}

/// The daemon-assembled export bundle exactly as the daemon produced it, with
/// no fallback: fails when the daemon is not running.
pub async fn export_bundle_json() -> Result<String, CoreError> {
    let resp = control::send(ReqPayload::DiagnosticsExport(DiagnosticsExportRequest {})).await?;
    match resp.payload {
        Some(RespPayload::DiagnosticsExport(bundle)) => Ok(bundle.bundle_json),
        _ => Err(CoreError::Other(
            "daemon returned an unexpected response to a diagnostics export request".into(),
        )),
    }
}

/// The desktop app's font-resolution record, which it writes under the
/// config directory, so a machine rendering boxes is distinguishable from one
/// that resolved a font fine.
fn desktop_font_status() -> Value {
    let Ok(dir) = device_config::config_dir() else {
        return json!({ "state": "state-directory-unusable" });
    };
    let path = dir.join("desktop-font-status.json");
    match std::fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(value) => value,
            Err(e) => json!({ "state": "unreadable", "error": e.to_string() }),
        },
        Err(_) => json!({ "state": "no-window-has-run" }),
    }
}

/// The bundle a client can assemble without the daemon: schema, build and
/// platform metadata only, redacted by the same redaction the daemon uses.
fn limited_bundle() -> (Value, usize) {
    let bundle = json!({
        "schema_version": 1,
        "generated_at": "unknown",
        "yadorilink_version": env!("CARGO_PKG_VERSION"),
        "platform": {
            "os_family": std::env::consts::OS,
            "os_version_bucket": "unknown",
            "arch": std::env::consts::ARCH
        },
        "daemon": {
            "reachable": false,
            "collection_mode": "cli-only-fallback"
        },
        "links": [],
        "recent_errors": [],
        "updates": {
            "state": "unknown"
        },
        "resources": {
            "disk_state": "unknown",
            "limits": "unknown"
        },
        "environment": {
            "install_channel": "unknown"
        },
        "desktop_ui": {
            "font": desktop_font_status()
        },
        "redaction": {
            "version": 1,
            "pseudonymized_fields": []
        }
    });

    let (redacted, summary) = redact_diagnostics_value(&bundle);
    let count = summary.categories.iter().map(|(_, count)| *count).sum();
    (redacted, count)
}

#[cfg(test)]
mod tests;
