//! `yadorilink report...`: usage/error report preview and export, error
//! submission, and consent controls.
//!
//! ## Daemon-backed vs. CLI-only
//!
//! Every command here first checks whether the daemon control socket is
//! reachable (`daemon_available`) and prefers routing through it — the
//! daemon owns the live usage counters and is the only thing this crate
//! ever calls `SubmissionClient`/makes a network reporting call through
//! (enforcing a single consent-check path). When the
//! daemon is unreachable:
//! - `usage`: falls back to a genuinely limited report (this process's
//!   own version/OS/arch only, no command/sync counters — those are
//!   daemon-owned runtime state this crate deliberately does not read
//!   directly, even though `counters.json` happens to be a plain file,
//!   because a stale on-disk snapshot masquerading as "current usage"
//!   would be misleading).
//! - `error --last`/`--id`: reads directly from the *shared*
//!   `<config_dir>/reporting/error-candidates/` store via
//!   `yadorilink_reporting::local_store::error_candidates::ErrorCandidateStore`
//!   — this is deliberately **not** treated as daemon-only. See the
//!   module doc comment on `handle_reportable_error` below for why: a
//!   candidate is a finished, self-contained document (unlike the
//!   continuously-mutating counters), and this crate's own error-reporting hook
//!   writes into the exact same store, so "read the shared store
//!   directly" is what makes daemon-created and CLI-created candidates
//!   both show up under `--last` regardless of whether the daemon
//!   happens to be running right now.
//! - `consent *`: same reasoning as error candidates — consent state is
//!   plain local config, not daemon-owned runtime state, so every consent
//!   command works directly against `ConsentStore` when the daemon isn't
//!   reachable, keeping it easy for forks/offline users to disable or
//!   inspect.
//! - `error --submit`: **does** require the daemon and fails with a clear,
//!   reporting-specific error (`CliError::ReportingDaemonRequired`) when
//!   it's unavailable — submission is the one network path this crate keeps
//!   exclusively behind the daemon.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::ConsentAction;
use yadorilink_ipc_proto::daemonctl::{
    DeleteQueueItemRequest, FlushQueueRequest, GenerateLastErrorReportRequest,
    GenerateUsageReportRequest, ListQueueItemsRequest, QueueItem, ReportingConsentState,
    ReportingStatusRequest, ShowQueueItemRequest, StatusRequest, SubmitReportRequest,
    UpdateConsentRequest,
};
use yadorilink_reporting::builder::{build_usage_envelope, UsagePayloadBuilder};
use yadorilink_reporting::consent::ConsentState;
use yadorilink_reporting::local_store::environment;
use yadorilink_reporting::local_store::{
    consent_store::ConsentStore, error_candidates::ErrorCandidateStore,
};

use crate::control_client;
use crate::error::CliError;

fn reporting_dir() -> Result<PathBuf, CliError> {
    Ok(crate::device_config::config_dir()?.join("reporting"))
}

fn local_consent_store() -> Result<ConsentStore, CliError> {
    Ok(ConsentStore::new(reporting_dir()?))
}

fn local_error_candidates() -> Result<ErrorCandidateStore, CliError> {
    Ok(ErrorCandidateStore::new(reporting_dir()?))
}

async fn daemon_available() -> bool {
    control_client::send(ReqPayload::Status(StatusRequest {})).await.is_ok()
}

fn print_consent(consent: &ReportingConsentState) {
    println!("Usage submission:        {}", on_off(consent.usage_submission_enabled));
    println!("Automatic error submission: {}", on_off(consent.error_submission_enabled));
    println!("Prompt after failures:    {}", on_off(consent.prompt_to_report_enabled));
    println!("Automatic queue retry:    {}", on_off(consent.queue_retry_enabled));
    println!(
        "Anonymous reporter id:    {}",
        consent.anonymous_reporter_id.as_deref().unwrap_or("(none — not opted in yet)")
    );
    println!(
        "Reporting endpoint:       {}",
        consent.endpoint_override.as_deref().unwrap_or("(none configured)")
    );
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

fn local_consent_to_proto(consent: &ConsentState) -> ReportingConsentState {
    ReportingConsentState {
        usage_submission_enabled: consent.usage_submission_enabled,
        error_submission_enabled: consent.error_submission_enabled,
        prompt_to_report_enabled: consent.prompt_to_report_enabled,
        queue_retry_enabled: consent.queue_retry_enabled,
        anonymous_reporter_id: consent.anonymous_reporter_id.clone(),
        endpoint_override: consent.endpoint_override.clone(),
    }
}

fn write_export(path: &Path, report_json: &str) -> Result<(), CliError> {
    std::fs::write(path, report_json)?;
    println!("Wrote report to {}", path.display());
    Ok(())
}

fn print_redaction_summary(redaction_summary: &[(String, u32)]) {
    if redaction_summary.is_empty() {
        return;
    }
    println!();
    println!("Redacted before this preview (categories, occurrence counts):");
    for (category, count) in redaction_summary {
        println!("  {category}: {count}");
    }
}

/// Interactive submit confirmation, factored so the prompt-reading itself is unit
/// testable without a real terminal — `confirm` (used by real commands)
/// always reads real stdin; tests call `confirm_with_reader` directly
/// with an in-memory reader.
pub fn confirm_with_reader(prompt: &str, assume_yes: bool, reader: &mut impl BufRead) -> bool {
    if assume_yes {
        return true;
    }
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn confirm(prompt: &str, assume_yes: bool) -> bool {
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    confirm_with_reader(prompt, assume_yes, &mut lock)
}

fn generate_limited_usage_report_json() -> String {
    // A refused state directory has no consent on record: the report carries the defaults.
    let consent = local_consent_store().map(|store| store.load_or_default()).unwrap_or_default();
    let env = environment::current(&consent);
    // Deliberately empty/default: no command/sync/error counters — see
    // module doc comment on why this crate doesn't read `counters.json`
    // directly as a substitute.
    let payload = UsagePayloadBuilder::new().build();
    build_usage_envelope(env, payload).to_json()
}

// -- `yadorilink report usage` -------------------------------------------

pub async fn usage(preview: bool, export: Option<PathBuf>) -> Result<(), CliError> {
    // Usage summaries are preview/export only — they are never submitted
    // over the network — so the preview is shown whenever nothing was
    // written to a file.
    let show_preview = preview || export.is_none();
    let available = daemon_available().await;

    let report_json = if available {
        let resp =
            control_client::send(ReqPayload::GenerateUsageReport(GenerateUsageReportRequest {}))
                .await?;
        let Some(RespPayload::GenerateUsageReport(r)) = resp.payload else {
            return Err(CliError::Other("unexpected daemon response".into()));
        };
        r.report_json
    } else {
        generate_limited_usage_report_json()
    };

    if show_preview {
        println!("{report_json}");
    }
    if let Some(path) = &export {
        write_export(path, &report_json)?;
    }
    Ok(())
}

// -- `yadorilink report error` -------------------------------------------

pub async fn error(
    id: Option<String>,
    preview: bool,
    export: Option<PathBuf>,
    submit: bool,
    yes: bool,
) -> Result<(), CliError> {
    let show_preview = preview || (!submit && export.is_none());
    let available = daemon_available().await;

    let (report_json, redaction_summary) = if available {
        let resp = control_client::send(ReqPayload::GenerateLastErrorReport(
            GenerateLastErrorReportRequest { report_id: id.clone() },
        ))
        .await?;
        let Some(RespPayload::GenerateLastErrorReport(r)) = resp.payload else {
            return Err(CliError::Other("unexpected daemon response".into()));
        };
        let summary =
            r.redaction_summary.into_iter().map(|c| (c.category, c.count)).collect::<Vec<_>>();
        (r.report_json, summary)
    } else {
        // See module doc comment: error candidates are shared, not
        // daemon-only, storage.
        let store = local_error_candidates()?;
        let candidate_id = match &id {
            Some(id) => id.clone(),
            None => {
                store
                    .most_recent()
                    .map_err(|e| CliError::Other(e.to_string()))?
                    .ok_or_else(|| {
                        CliError::Other(
                            "no error candidate is available yet — nothing has been captured \
                         locally, and the daemon is not running to check its own candidates"
                                .to_string(),
                        )
                    })?
                    .report_id
            }
        };
        let (envelope, summary) = store
            .show_with_summary(&candidate_id)
            .map_err(|e| CliError::Other(e.to_string()))?
            .ok_or_else(|| {
                CliError::Other(format!("no error candidate found with id `{candidate_id}`"))
            })?;
        let summary_pairs = summary
            .categories
            .iter()
            .map(|(category, count)| (format!("{category:?}"), *count as u32))
            .collect::<Vec<_>>();
        (envelope.to_json(), summary_pairs)
    };

    if show_preview {
        println!("{report_json}");
        print_redaction_summary(&redaction_summary);
    }
    if let Some(path) = &export {
        write_export(path, &report_json)?;
    }
    if submit {
        submit_report_json(report_json, "error", yes).await?;
    }
    Ok(())
}

async fn submit_report_json(report_json: String, kind: &str, yes: bool) -> Result<(), CliError> {
    if !daemon_available().await {
        return Err(CliError::ReportingDaemonRequired(
            "submitting a report requires the yadorilink daemon (network submission is only \
             ever performed by the daemon) — run `yadorilink daemon start`, or use --export to \
             save the report to a file instead"
                .to_string(),
        ));
    }
    if !confirm(&format!("Submit this {kind} report to the configured reporting endpoint?"), yes) {
        println!("Not submitted.");
        return Ok(());
    }
    let resp =
        control_client::send(ReqPayload::SubmitReport(SubmitReportRequest { report_json })).await?;
    let Some(RespPayload::SubmitReport(r)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if r.queued_for_retry {
        println!("Submission failed but the report was queued locally for automatic retry.");
    } else {
        println!("Submitted. Receipt: {} (at {})", r.receipt_id, r.submitted_at);
    }
    Ok(())
}

// -- `yadorilink report consent...` -------------------------------------

pub async fn consent_status() -> Result<(), CliError> {
    if daemon_available().await {
        let resp =
            control_client::send(ReqPayload::ReportingStatus(ReportingStatusRequest {})).await?;
        let Some(RespPayload::ReportingStatus(r)) = resp.payload else {
            return Err(CliError::Other("unexpected daemon response".into()));
        };
        if let Some(consent) = &r.consent {
            print_consent(consent);
        }
        println!("Queued unsent reports:    {}", r.queue_count);
        println!("Local error candidates:   {}", r.error_candidate_count);
    } else {
        println!("(daemon not running — showing local consent state only)");
        let consent = local_consent_store()?.load_or_default();
        print_consent(&local_consent_to_proto(&consent));
        let candidate_count = local_error_candidates()?.list().map(|v| v.len()).unwrap_or(0);
        println!("Queued unsent reports:    unavailable (daemon not running)");
        println!("Local error candidates:   {candidate_count}");
    }
    Ok(())
}

async fn update_consent(
    action: ConsentAction,
    bool_value: Option<bool>,
    string_value: Option<String>,
) -> Result<(), CliError> {
    if daemon_available().await {
        let resp = control_client::send(ReqPayload::UpdateConsent(UpdateConsentRequest {
            action: action as i32,
            bool_value,
            string_value,
        }))
        .await?;
        let Some(RespPayload::UpdateConsent(r)) = resp.payload else {
            return Err(CliError::Other("unexpected daemon response".into()));
        };
        if let Some(consent) = &r.consent {
            print_consent(consent);
        }
        return Ok(());
    }

    // Daemon unreachable: consent is plain local config (module doc
    // comment) — every action below has a direct `ConsentStore` method.
    let store = local_consent_store()?;
    let consent = match action {
        ConsentAction::EnableUsage => store.opt_in_usage(),
        ConsentAction::EnableError => store.opt_in_error_reporting(),
        ConsentAction::EnableCrashReporting => store.opt_in_crash_reporting(),
        ConsentAction::DisableAll => store.disable_all_submission(),
        ConsentAction::SetPrompt => store.set_prompt_to_report_enabled(bool_value.unwrap_or(false)),
        _ => return Err(CliError::Other("unsupported consent action".to_string())),
    }
    .map_err(|e| CliError::Other(e.to_string()))?;
    print_consent(&local_consent_to_proto(&consent));
    Ok(())
}

pub async fn consent_enable() -> Result<(), CliError> {
    // Opting in to crash reporting turns on both automatic error
    // submission and background queue retry, so a captured crash is
    // submitted (or queued and retried) without any further action.
    update_consent(ConsentAction::EnableCrashReporting, None, None).await
}

pub async fn consent_disable() -> Result<(), CliError> {
    update_consent(ConsentAction::DisableAll, None, None).await
}

pub async fn consent_prompts(enabled: bool) -> Result<(), CliError> {
    update_consent(ConsentAction::SetPrompt, Some(enabled), None).await
}

// -- `yadorilink report queue...` ----------------------------------------
//
// The submit-retry queue is daemon-owned runtime state (the same store
// `report consent status`'s `Queued unsent reports` count already reads,
// via `context.queries.reporting` on the daemon side) -- every command
// here requires the daemon, the same way `error --submit` does, rather
// than falling back to a local reconstruction the way `usage`/`error
// --last` do for their own CLI-only-safe data.

async fn require_daemon(action: &str) -> Result<(), CliError> {
    if daemon_available().await {
        return Ok(());
    }
    Err(CliError::ReportingDaemonRequired(format!(
        "{action} requires the yadorilink daemon (the submit-retry queue is daemon-owned \
         runtime state) — run `yadorilink daemon start`"
    )))
}

fn queue_item_line(item: &QueueItem) -> String {
    format!(
        "{}  type={}  queued_at={}  size={}  attempts={}",
        item.report_id, item.report_type, item.queued_at, item.size_bytes, item.submit_attempts
    )
}

pub async fn queue_list() -> Result<(), CliError> {
    require_daemon("listing the queue").await?;
    let resp = control_client::send(ReqPayload::ListQueueItems(ListQueueItemsRequest {})).await?;
    let Some(RespPayload::ListQueueItems(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if list.items.is_empty() {
        println!("Queue is empty.");
        return Ok(());
    }
    for item in &list.items {
        println!("{}", queue_item_line(item));
    }
    Ok(())
}

pub async fn queue_show(report_id: String) -> Result<(), CliError> {
    require_daemon("showing a queue item").await?;
    let resp =
        control_client::send(ReqPayload::ShowQueueItem(ShowQueueItemRequest { report_id })).await?;
    let Some(RespPayload::ShowQueueItem(r)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("{}", r.report_json);
    Ok(())
}

pub async fn queue_delete(report_id: String) -> Result<(), CliError> {
    require_daemon("deleting a queue item").await?;
    let resp = control_client::send(ReqPayload::DeleteQueueItem(DeleteQueueItemRequest {
        report_id: report_id.clone(),
    }))
    .await?;
    let Some(RespPayload::DeleteQueueItem(r)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if r.deleted {
        println!("Deleted queue item {report_id}");
    } else {
        println!("No queue item found with id {report_id}");
    }
    Ok(())
}

pub async fn queue_flush() -> Result<(), CliError> {
    require_daemon("flushing the queue").await?;
    let resp = control_client::send(ReqPayload::FlushQueue(FlushQueueRequest {})).await?;
    let Some(RespPayload::FlushQueue(r)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("Removed {} queued item(s)", r.removed_count);
    Ok(())
}

// -- reportable-error hook -----------------------------------------------

/// Called from `main.rs`'s top-level error path for any command failure
/// worth surfacing to reporting (`CliError::is_reportable`). Two jobs,
/// both best-effort and both entirely local (no network call is
/// reachable from this function, ensuring no data is sent automatically):
/// 1. Persists a local error candidate directly into the *shared*
///    `error-candidates` store (see module doc comment) — capturing
///    CLI-command failures alongside daemon-side severe errors: both write into the
///    exact same on-disk store via the exact same `ErrorCandidateStore`
///    API, just from two different processes/call sites. No IPC message
///    was added for this because a local file write needs no daemon
///    round trip either way, and it means `report error --last` finds
///    whichever kind of candidate (daemon- or CLI-originated) is newest,
///    without the CLI needing to know or care which process created it.
/// 2. Prints a one-line hint suggesting `yadorilink report error --last
///  --preview`.
///
/// Both are skipped entirely if `prompt_to_report_enabled` is off
/// (which can be disabled via `report consent prompts false`).
/// Never panics, never changes the process's exit code (the caller reads
/// that from the original `CliError` untouched), never blocks on
/// anything beyond a local file write.
pub async fn handle_reportable_error(err: &CliError) {
    let (Ok(consent_store), Ok(store)) = (local_consent_store(), local_error_candidates()) else {
        return;
    };
    let consent = consent_store.load_or_default();
    if !consent.prompt_to_report_enabled {
        return;
    }

    let category = err.report_category();
    let builder = yadorilink_reporting::builder::ErrorPayloadBuilder::new(category, "cli")
        .log_lines(vec![err.to_string()]);
    let env = environment::current(&consent);
    let (envelope, summary) = yadorilink_reporting::builder::build_error_envelope(env, builder);
    let _ = store.create_candidate_with_summary(envelope, &summary);

    eprintln!(
        "hint: run `yadorilink report error --last --preview` to see what would be reported \
         (nothing is sent automatically)"
    );
}

#[cfg(test)]
mod tests;
