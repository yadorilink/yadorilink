#![cfg(test)]

use super::*;

fn sample_usage_envelope() -> ReportEnvelope {
    ReportEnvelope {
        schema_version: SCHEMA_VERSION,
        report_type: ReportType::Usage,
        generated_at: "2026-01-01T00:00:00Z".into(),
        yadorilink_version: "0.1.0".into(),
        os_family: OsFamily::Macos,
        os_version_bucket: "15.x".into(),
        arch: "aarch64".into(),
        install_channel: Some("pkg".into()),
        anonymous_reporter_id: Some("11111111-2222-3333-4444-555555555555".into()),
        payload: ReportPayload::Usage(UsagePayload {
            linked_folder_count: 2,
            daemon_uptime_bucket: "1d-7d".into(),
            peer_count_bucket: "1-2".into(),
            ..Default::default()
        }),
    }
}

#[test]
fn schema_round_trips_through_json_unchanged() {
    let envelope = sample_usage_envelope();
    let json = envelope.to_json();
    let parsed = ReportEnvelope::from_json(&json).unwrap();
    assert_eq!(envelope, parsed);
}

#[test]
fn two_envelopes_built_from_the_same_logical_data_serialize_identically_regardless_of_transport() {
    // "Transport-independent payload equality": the same
    // envelope, built twice, must produce byte-identical JSON — no
    // transport-specific field (e.g. an HTTP header, a CLI flag)
    // leaks into the payload itself.
    let a = sample_usage_envelope();
    let b = sample_usage_envelope();
    assert_eq!(a.to_json(), b.to_json());
}

#[test]
fn validate_rejects_wrong_schema_version() {
    let mut envelope = sample_usage_envelope();
    envelope.schema_version = SCHEMA_VERSION + 1;
    assert!(matches!(envelope.validate(), Err(ValidationError::UnsupportedSchemaVersion { .. })));
}

#[test]
fn validate_rejects_payload_type_mismatch() {
    let mut envelope = sample_usage_envelope();
    envelope.report_type = ReportType::Error;
    assert!(matches!(envelope.validate(), Err(ValidationError::PayloadTypeMismatch)));
}

#[test]
fn validate_rejects_empty_required_fields() {
    let mut envelope = sample_usage_envelope();
    envelope.yadorilink_version = String::new();
    assert!(matches!(envelope.validate(), Err(ValidationError::MissingField { .. })));
}

#[test]
fn validate_rejects_oversized_reports() {
    let mut envelope = sample_usage_envelope();
    if let ReportPayload::Usage(usage) = &mut envelope.payload {
        for i in 0..10_000 {
            usage.command_category_counts.insert(format!("category-{i}"), i);
        }
    }
    assert!(matches!(envelope.validate(), Err(ValidationError::TooLarge { .. })));
}

#[test]
fn error_payload_missing_category_is_rejected() {
    let mut envelope = sample_usage_envelope();
    envelope.report_type = ReportType::Error;
    envelope.payload = ReportPayload::Error(ErrorPayload::default());
    assert!(matches!(envelope.validate(), Err(ValidationError::MissingField { .. })));
}

#[test]
fn serialized_usage_report_never_contains_field_names_associated_with_internal_identity() {
    // Structural proof of the allowlist principle: the
    // JSON text can never contain these substrings, because
    // UsagePayload/ErrorPayload simply have no field that could hold
    // them — this isn't a redaction check (see redact.rs for that),
    // it's a schema-shape check.
    let envelope = sample_usage_envelope();
    let json = envelope.to_json();
    for forbidden in [
        "file_name",
        "file_path",
        "account_id",
        "device_id",
        "group_id",
        "peer_id",
        "auth_token",
        "wireguard_key",
    ] {
        assert!(!json.contains(forbidden), "unexpected field `{forbidden}` in report JSON");
    }
}
