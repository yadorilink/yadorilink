//! `yadorilink recovery list`/`show`. `show` is a stable
//! diagnosis: local journal state, exactly one remote lookup against the
//! coordination plane, and a pure recommendation -- see
//! `yadorilink_daemon::recovery_diagnosis`'s own doc comment for the full
//! before/lookup/after/compare sequence this is built from. Both
//! subcommands are strictly read-only: neither ever retries a remote call
//! or mutates a journal row.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    show_recovery_operation_response, InvalidRecoveryOperation, ListRecoveryOperationsRequest,
    RecoveryDiagnosis, RecoveryEvidenceQualification, RecoveryLocalEvidenceChanged,
    RecoveryObservationQualification, RecoveryOperation, RecoveryOperationNotFound,
    RecoveryRemoteIdentityQualification, RecoveryRemoteState, RecoverySnapshotAfterLookup,
    RecoverySnapshotRevision, ShowRecoveryOperationRequest,
};

use crate::control_client;
use crate::error::CliError;

#[derive(serde::Serialize)]
struct RecoveryOperationJson<'a> {
    operation_id: &'a str,
    domain: &'a str,
    action: &'a str,
    state: &'a str,
    severity: &'a str,
    group_ids: &'a [String],
    device_id: Option<&'a str>,
    local_path: Option<&'a str>,
    attempts: u64,
    last_error: Option<&'a str>,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl<'a> From<&'a RecoveryOperation> for RecoveryOperationJson<'a> {
    fn from(op: &'a RecoveryOperation) -> Self {
        RecoveryOperationJson {
            operation_id: &op.operation_id,
            domain: &op.domain,
            action: &op.action,
            state: &op.state,
            severity: &op.severity,
            group_ids: &op.group_ids,
            device_id: op.device_id.as_deref(),
            local_path: op.local_path.as_deref(),
            attempts: op.attempts,
            last_error: op.last_error.as_deref(),
            created_at_unix: op.created_at_unix,
            updated_at_unix: op.updated_at_unix,
        }
    }
}

#[derive(serde::Serialize)]
struct InvalidRecoveryOperationJson<'a> {
    operation_id: Option<&'a str>,
    domain: &'a str,
    raw_state: Option<&'a str>,
    detail: &'a str,
}

impl<'a> From<&'a InvalidRecoveryOperation> for InvalidRecoveryOperationJson<'a> {
    fn from(op: &'a InvalidRecoveryOperation) -> Self {
        InvalidRecoveryOperationJson {
            operation_id: op.operation_id.as_deref(),
            domain: &op.domain,
            raw_state: op.raw_state.as_deref(),
            detail: &op.detail,
        }
    }
}

fn age_secs(created_at_unix: i64) -> i64 {
    (unix_now() - created_at_unix).max(0)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn format_age(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

pub async fn list(json: bool) -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::ListRecoveryOperations(ListRecoveryOperationsRequest {}))
            .await?;
    let Some(RespPayload::ListRecoveryOperations(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };

    if json {
        #[derive(serde::Serialize)]
        struct Output<'a> {
            operations: Vec<RecoveryOperationJson<'a>>,
            invalid: Vec<InvalidRecoveryOperationJson<'a>>,
        }
        let output = Output {
            operations: list.operations.iter().map(Into::into).collect(),
            invalid: list.invalid.iter().map(Into::into).collect(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|e| CliError::Other(format!("failed to encode JSON: {e}")))?
        );
        return Ok(());
    }

    if list.operations.is_empty() && list.invalid.is_empty() {
        println!("No recovery operations.");
        return Ok(());
    }

    if !list.operations.is_empty() {
        println!("{:<12}{:<22}{:<8}{:<10}OPERATION", "DOMAIN", "STATE", "AGE", "ATTEMPTS");
        for op in &list.operations {
            println!(
                "{:<12}{:<22}{:<8}{:<10}{}",
                op.domain,
                op.state,
                format_age(age_secs(op.created_at_unix)),
                op.attempts,
                op.operation_id,
            );
        }
    }
    if !list.invalid.is_empty() {
        println!();
        println!("Malformed rows (require operator attention):");
        for op in &list.invalid {
            println!(
                "  {:<12}{:<22}{}",
                op.domain,
                op.operation_id.as_deref().unwrap_or("<unreadable id>"),
                op.detail,
            );
        }
    }
    Ok(())
}

// ============================== JSON shapes ==============================

/// Every field two identity-bearing values were compared on. Mirrors
/// `yadorilink_daemon::recovery_diagnosis::model::ObservationQualification`'s
/// own wire slugs.
#[derive(serde::Serialize)]
struct ObservationQualificationJson<'a> {
    status: &'a str,
    mismatch_fields: &'a [String],
    detail: Option<&'a str>,
}

impl<'a> From<&'a RecoveryObservationQualification> for ObservationQualificationJson<'a> {
    fn from(q: &'a RecoveryObservationQualification) -> Self {
        ObservationQualificationJson {
            status: &q.status,
            mismatch_fields: &q.mismatch_fields,
            detail: q.detail.as_deref(),
        }
    }
}

#[derive(serde::Serialize)]
struct RemoteIdentityQualificationJson<'a> {
    status: &'a str,
    mismatch_fields: &'a [String],
    not_comparable_reasons: &'a [String],
    not_evaluated_reason: Option<&'a str>,
}

impl<'a> From<&'a RecoveryRemoteIdentityQualification> for RemoteIdentityQualificationJson<'a> {
    fn from(q: &'a RecoveryRemoteIdentityQualification) -> Self {
        RemoteIdentityQualificationJson {
            status: &q.status,
            mismatch_fields: &q.mismatch_fields,
            not_comparable_reasons: &q.not_comparable_reasons,
            not_evaluated_reason: q.not_evaluated_reason.as_deref(),
        }
    }
}

#[derive(serde::Serialize)]
struct EvidenceQualificationJson<'a> {
    link: Option<ObservationQualificationJson<'a>>,
    pending_marker: Option<ObservationQualificationJson<'a>>,
    remote_identity: RemoteIdentityQualificationJson<'a>,
}

impl<'a> From<&'a RecoveryEvidenceQualification> for EvidenceQualificationJson<'a> {
    fn from(q: &'a RecoveryEvidenceQualification) -> Self {
        EvidenceQualificationJson {
            link: q.link.as_ref().map(Into::into),
            pending_marker: q.pending_marker.as_ref().map(Into::into),
            remote_identity: q
                .remote_identity
                .as_ref()
                .map(Into::into)
                .expect("remote_identity is always set on a diagnosed qualification"),
        }
    }
}

#[derive(serde::Serialize)]
struct RemoteStateJson<'a> {
    status: &'a str,
    unavailable_category: Option<&'a str>,
}

impl<'a> From<&'a RecoveryRemoteState> for RemoteStateJson<'a> {
    fn from(r: &'a RecoveryRemoteState) -> Self {
        RemoteStateJson {
            status: &r.status,
            unavailable_category: r.unavailable_category.as_deref(),
        }
    }
}

#[derive(serde::Serialize)]
struct SnapshotRevisionJson<'a> {
    state: &'a str,
    updated_at_unix: i64,
    diagnostic_fingerprint: u64,
}

impl<'a> From<&'a RecoverySnapshotRevision> for SnapshotRevisionJson<'a> {
    fn from(r: &'a RecoverySnapshotRevision) -> Self {
        SnapshotRevisionJson {
            state: &r.state,
            updated_at_unix: r.updated_at_unix,
            diagnostic_fingerprint: r.diagnostic_fingerprint,
        }
    }
}

#[derive(serde::Serialize)]
struct SnapshotAfterLookupJson<'a> {
    outcome: &'a str,
    revision: Option<SnapshotRevisionJson<'a>>,
    raw_state: Option<&'a str>,
    detail: Option<&'a str>,
}

impl<'a> From<&'a RecoverySnapshotAfterLookup> for SnapshotAfterLookupJson<'a> {
    fn from(a: &'a RecoverySnapshotAfterLookup) -> Self {
        SnapshotAfterLookupJson {
            outcome: &a.outcome,
            revision: a.revision.as_ref().map(Into::into),
            raw_state: a.raw_state.as_deref(),
            detail: a.detail.as_deref(),
        }
    }
}

/// The top-level `--json` shape for `recovery show`. `outcome` is always
/// present -- every variant here is a typed, successfully-retrieved
/// response, never collapsed into a bare top-level error string.
#[derive(serde::Serialize)]
#[serde(tag = "outcome")]
enum ShowOutputJson<'a> {
    #[serde(rename = "diagnosed")]
    Diagnosed {
        operation: Box<RecoveryOperationJson<'a>>,
        remote: RemoteStateJson<'a>,
        recommendation: &'a str,
        reason_codes: &'a [String],
        automatic_recovery_safe: bool,
        qualification: EvidenceQualificationJson<'a>,
        local_revision: SnapshotRevisionJson<'a>,
    },
    #[serde(rename = "invalid_operation")]
    InvalidOperation {
        operation_id: Option<&'a str>,
        domain: &'a str,
        raw_state: Option<&'a str>,
        detail: &'a str,
    },
    #[serde(rename = "operation_not_found")]
    OperationNotFound { domain: &'a str, operation_id: &'a str },
    #[serde(rename = "local_evidence_changed")]
    LocalEvidenceChanged {
        domain: &'a str,
        operation_id: &'a str,
        before: SnapshotRevisionJson<'a>,
        after: SnapshotAfterLookupJson<'a>,
    },
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), CliError> {
    println!(
        "{}",
        serde_json::to_string_pretty(value)
            .map_err(|e| CliError::Other(format!("failed to encode JSON: {e}")))?
    );
    Ok(())
}

fn print_field(label: &str, value: impl std::fmt::Display) {
    println!("{label:<28}{value}");
}

fn render_diagnosed(diagnosis: &RecoveryDiagnosis) {
    let op = diagnosis.operation.as_ref().expect("operation is always set on a Diagnosed outcome");
    let remote = diagnosis.remote.as_ref().expect("remote is always set on a Diagnosed outcome");
    let qualification = diagnosis
        .qualification
        .as_ref()
        .expect("qualification is always set on a Diagnosed outcome");

    print_field("operation_id:", &op.operation_id);
    print_field("domain:", &op.domain);
    print_field("action:", &op.action);
    print_field("local_state:", &op.state);
    print_field("remote_state:", &remote.status);
    if let Some(category) = &remote.unavailable_category {
        print_field("remote_unavailable_category:", category);
    }
    print_field("recommendation:", &diagnosis.recommendation);
    print_field(
        "automatic_recovery_safe:",
        if diagnosis.automatic_recovery_safe { "yes" } else { "no" },
    );
    print_field(
        "reason_codes:",
        if diagnosis.reason_codes.is_empty() {
            "-".to_string()
        } else {
            diagnosis.reason_codes.join(", ")
        },
    );
    print_field("group_ids:", op.group_ids.join(", "));
    if let Some(device_id) = &op.device_id {
        print_field("device_id:", device_id);
    }
    if let Some(local_path) = &op.local_path {
        print_field("local_path:", local_path);
    }
    print_field("attempts:", op.attempts);
    if let Some(last_error) = &op.last_error {
        print_field("last_error:", last_error);
    }
    if let Some(link) = &qualification.link {
        print_field("link_identity:", &link.status);
    }
    if let Some(marker) = &qualification.pending_marker {
        print_field("marker_identity:", &marker.status);
    }
    if let Some(remote_identity) = &qualification.remote_identity {
        print_field("remote_identity:", &remote_identity.status);
    }
}

pub async fn show(domain: &str, operation_id: String, json: bool) -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::ShowRecoveryOperation(ShowRecoveryOperationRequest {
            domain: domain.to_string(),
            operation_id,
        }))
        .await?;
    let Some(RespPayload::ShowRecoveryOperation(show)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };

    match show.result {
        Some(show_recovery_operation_response::Result::Diagnosed(diagnosis)) => {
            if json {
                let op = diagnosis
                    .operation
                    .as_ref()
                    .expect("operation is always set on a Diagnosed outcome");
                let remote =
                    diagnosis.remote.as_ref().expect("remote is always set on a Diagnosed outcome");
                let qualification = diagnosis
                    .qualification
                    .as_ref()
                    .expect("qualification is always set on a Diagnosed outcome");
                let local_revision = diagnosis
                    .local_revision
                    .as_ref()
                    .expect("local_revision is always set on a Diagnosed outcome");
                return print_json(&ShowOutputJson::Diagnosed {
                    operation: Box::new(op.into()),
                    remote: remote.into(),
                    recommendation: &diagnosis.recommendation,
                    reason_codes: &diagnosis.reason_codes,
                    automatic_recovery_safe: diagnosis.automatic_recovery_safe,
                    qualification: qualification.into(),
                    local_revision: local_revision.into(),
                });
            }
            render_diagnosed(&diagnosis);
            Ok(())
        }
        Some(show_recovery_operation_response::Result::Invalid(op)) => {
            if json {
                return print_json(&ShowOutputJson::InvalidOperation {
                    operation_id: op.operation_id.as_deref(),
                    domain: &op.domain,
                    raw_state: op.raw_state.as_deref(),
                    detail: &op.detail,
                });
            }
            println!("operation_id: {}", op.operation_id.as_deref().unwrap_or("<unreadable id>"));
            println!("domain:       {}", op.domain);
            if let Some(raw_state) = &op.raw_state {
                println!("raw_state:    {raw_state}");
            }
            println!("detail:       {}", op.detail);
            println!("this row is malformed and requires operator attention");
            Ok(())
        }
        Some(show_recovery_operation_response::Result::NotFound(RecoveryOperationNotFound {
            key,
        })) => {
            let key = key.expect("key is always set on a NotFound outcome");
            if json {
                return print_json(&ShowOutputJson::OperationNotFound {
                    domain: &key.domain,
                    operation_id: &key.operation_id,
                });
            }
            println!(
                "No recovery operation found for {} operation id {}.",
                key.domain, key.operation_id
            );
            Ok(())
        }
        Some(show_recovery_operation_response::Result::LocalEvidenceChanged(
            RecoveryLocalEvidenceChanged { key, before, after },
        )) => {
            let key = key.expect("key is always set on a LocalEvidenceChanged outcome");
            let before = before.expect("before is always set on a LocalEvidenceChanged outcome");
            let after = after.expect("after is always set on a LocalEvidenceChanged outcome");
            if json {
                return print_json(&ShowOutputJson::LocalEvidenceChanged {
                    domain: &key.domain,
                    operation_id: &key.operation_id,
                    before: (&before).into(),
                    after: (&after).into(),
                });
            }
            println!(
                "Local recovery evidence changed while remote evidence was being read.\n\
                 Run the command again."
            );
            Ok(())
        }
        None => Err(CliError::Other("unexpected daemon response".into())),
    }
}

#[cfg(test)]
mod tests;
