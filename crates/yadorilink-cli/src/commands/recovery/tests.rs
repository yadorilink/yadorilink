#![cfg(test)]

use super::*;

/// Pins the exact `recovery list --json` field set/order/naming for a
/// valid recovery operation -- a `serde` field rename or reorder here is
/// a breaking change for any script/tool parsing this output, and this
/// repository has not shipped a public release yet, so nothing else
/// would catch a silent drift.
#[test]
fn recovery_operation_json_snapshot() {
    let op = RecoveryOperation {
        operation_id: "op-1".to_string(),
        domain: "enrollment".to_string(),
        action: "create".to_string(),
        state: "activation_pending".to_string(),
        severity: "pending".to_string(),
        group_ids: vec!["group-1".to_string()],
        device_id: Some("device-a".to_string()),
        local_path: Some("/home/alice/Photos".to_string()),
        attempts: 2,
        last_error: None,
        created_at_unix: 1_700_000_000,
        updated_at_unix: 1_700_000_100,
    };
    let json: RecoveryOperationJson = (&op).into();
    let rendered = serde_json::to_string_pretty(&json).unwrap();
    assert_eq!(
        rendered,
        r#"{
  "operation_id": "op-1",
  "domain": "enrollment",
  "action": "create",
  "state": "activation_pending",
  "severity": "pending",
  "group_ids": [
    "group-1"
  ],
  "device_id": "device-a",
  "local_path": "/home/alice/Photos",
  "attempts": 2,
  "last_error": null,
  "created_at_unix": 1700000000,
  "updated_at_unix": 1700000100
}"#
    );
}

/// Pins the exact `recovery list --json` field set for an invalid
/// (malformed) row -- `operation_id: null` in particular, since that is
/// the whole point of this row shape (a row whose id itself could not be
/// decoded).
#[test]
fn invalid_recovery_operation_json_snapshot() {
    let op = InvalidRecoveryOperation {
        operation_id: None,
        domain: "membership".to_string(),
        raw_state: Some("from-the-future".to_string()),
        detail: "unknown membership operation state: from-the-future".to_string(),
    };
    let json: InvalidRecoveryOperationJson = (&op).into();
    let rendered = serde_json::to_string_pretty(&json).unwrap();
    assert_eq!(
        rendered,
        r#"{
  "operation_id": null,
  "domain": "membership",
  "raw_state": "from-the-future",
  "detail": "unknown membership operation state: from-the-future"
}"#
    );
}

fn diagnosed_operation() -> RecoveryOperation {
    RecoveryOperation {
        operation_id: "op-1".to_string(),
        domain: "enrollment".to_string(),
        action: "create".to_string(),
        state: "activation_pending".to_string(),
        severity: "pending".to_string(),
        group_ids: vec!["group-1".to_string()],
        device_id: Some("device-a".to_string()),
        local_path: Some("/home/alice/Photos".to_string()),
        attempts: 0,
        last_error: None,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn diagnosed() -> RecoveryDiagnosis {
    RecoveryDiagnosis {
        operation: Some(diagnosed_operation()),
        remote: Some(RecoveryRemoteState {
            status: "prepared".to_string(),
            unavailable_category: None,
        }),
        recommendation: "retry_remote_activation".to_string(),
        reason_codes: vec![],
        automatic_recovery_safe: true,
        qualification: Some(RecoveryEvidenceQualification {
            link: Some(RecoveryObservationQualification {
                status: "exact".to_string(),
                mismatch_fields: vec![],
                detail: None,
            }),
            pending_marker: Some(RecoveryObservationQualification {
                status: "exact".to_string(),
                mismatch_fields: vec![],
                detail: None,
            }),
            remote_identity: Some(RecoveryRemoteIdentityQualification {
                status: "exact".to_string(),
                mismatch_fields: vec![],
                not_comparable_reasons: vec![],
                not_evaluated_reason: None,
            }),
        }),
        local_revision: Some(RecoverySnapshotRevision {
            state: "activation_pending".to_string(),
            updated_at_unix: 1,
            diagnostic_fingerprint: 42,
        }),
    }
}

/// `--json` for a `Diagnosed` outcome always carries a top-level
/// `outcome: "diagnosed"` field -- never collapsed into a bare error
/// string, matching every other outcome kind's own tagged shape.
#[test]
fn diagnosed_json_snapshot() {
    let d = diagnosed();
    let op = d.operation.as_ref().unwrap();
    let remote = d.remote.as_ref().unwrap();
    let qualification = d.qualification.as_ref().unwrap();
    let local_revision = d.local_revision.as_ref().unwrap();
    let output = ShowOutputJson::Diagnosed {
        operation: Box::new(op.into()),
        remote: remote.into(),
        recommendation: &d.recommendation,
        reason_codes: &d.reason_codes,
        automatic_recovery_safe: d.automatic_recovery_safe,
        qualification: qualification.into(),
        local_revision: local_revision.into(),
    };
    let rendered = serde_json::to_string_pretty(&output).unwrap();
    assert!(rendered.starts_with("{\n  \"outcome\": \"diagnosed\","), "{rendered}");
    assert!(rendered.contains("\"recommendation\": \"retry_remote_activation\""));
    assert!(rendered.contains("\"automatic_recovery_safe\": true"));
}

#[test]
fn invalid_operation_json_snapshot() {
    let output = ShowOutputJson::InvalidOperation {
        operation_id: Some("op-1"),
        domain: "membership",
        raw_state: Some("from-the-future"),
        detail: "unknown membership operation state: from-the-future",
    };
    let rendered = serde_json::to_string_pretty(&output).unwrap();
    assert!(rendered.starts_with("{\n  \"outcome\": \"invalid_operation\","), "{rendered}");
}

#[test]
fn operation_not_found_json_snapshot() {
    let output = ShowOutputJson::OperationNotFound { domain: "enrollment", operation_id: "op-1" };
    let rendered = serde_json::to_string_pretty(&output).unwrap();
    assert_eq!(
        rendered,
        r#"{
  "outcome": "operation_not_found",
  "domain": "enrollment",
  "operation_id": "op-1"
}"#
    );
}

#[test]
fn local_evidence_changed_json_snapshot() {
    let output = ShowOutputJson::LocalEvidenceChanged {
        domain: "enrollment",
        operation_id: "op-1",
        before: SnapshotRevisionJson {
            state: "activation_pending",
            updated_at_unix: 1,
            diagnostic_fingerprint: 42,
        },
        after: SnapshotAfterLookupJson {
            outcome: "operation_not_found",
            revision: None,
            raw_state: Some("active"),
            detail: None,
        },
    };
    let rendered = serde_json::to_string_pretty(&output).unwrap();
    assert!(rendered.starts_with("{\n  \"outcome\": \"local_evidence_changed\","), "{rendered}");
    assert!(rendered.contains("\"outcome\": \"operation_not_found\""));
}
