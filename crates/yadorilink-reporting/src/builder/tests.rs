#![cfg(test)]

use super::*;

fn env() -> ReportEnvironment {
    ReportEnvironment {
        generated_at: "2026-01-01T00:00:00Z".into(),
        yadorilink_version: "0.1.0".into(),
        os_family: OsFamily::Linux,
        os_version_bucket: "24.04".into(),
        arch: "x86_64".into(),
        install_channel: None,
        anonymous_reporter_id: None,
    }
}

fn doc_fixture_env() -> ReportEnvironment {
    ReportEnvironment {
        generated_at: "2026-01-01T00:00:00Z".into(),
        yadorilink_version: "0.1.0".into(),
        os_family: OsFamily::Linux,
        os_version_bucket: "24.04".into(),
        arch: "x86_64".into(),
        install_channel: Some("source".into()),
        anonymous_reporter_id: Some("anon-doc-fixture-0001".into()),
    }
}

fn assert_public_doc_fixture_json_is_private(json: &str) {
    let forbidden = [
        "alice",
        "taxes.pdf",
        "/Users",
        "/home",
        "C:\\Users",
        "11111111-2222-3333-4444-555555555555",
        "203.0.113.42",
        "eyJhbGciOiJIUzI1NiJ9",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "hunter2",
        "alice@example.com",
        "file_path",
        "account_id",
        "device_id",
        "group_id",
        "peer_id",
        "auth_token",
        "wireguard_key",
    ];
    for needle in forbidden {
        assert!(!json.contains(needle), "doc fixture leaked sensitive substring: {needle}");
    }
}

fn expected_doc_usage_report_fixture() -> ReportEnvelope {
    let payload = UsagePayloadBuilder::new()
        .enabled_feature_flags(vec!["on-demand-sync".to_string()])
        .linked_folder_count(3)
        .linked_folder_policy_count("eager", 1)
        .linked_folder_policy_count("on-demand", 2)
        .command_category_count("link", 2)
        .command_category_count("status", 8)
        .daemon_uptime_bucket("1d-7d")
        .sync_state_count("synced", 12)
        .sync_state_count("conflicted", 1)
        .error_category_count("daemon_startup", 1)
        .transfer_size_bucket_count("1MiB-64MiB", 4)
        .latency_bucket_count("100ms-1s", 9)
        .peer_count_bucket("1-2")
        .build();
    build_usage_envelope(doc_fixture_env(), payload)
}

fn expected_doc_error_report_fixture() -> ReportEnvelope {
    let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core")
        .log_lines(vec![
            "failed to scan /private/tmp/taxes.pdf for report fixture".to_string(),
            concat!(
                "peer 11111111-2222-3333-4444-555555555555 at 203.0.113.42 ",
                "returned auth Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop"
            )
            .to_string(),
            "relay https://user:hunter2@relay.example.com reported owner alice@example.com"
                .to_string(),
        ])
        .backtrace(concat!(
            "panicked at /Users/alice with key ",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        ));
    let (envelope, summary) = build_error_envelope(doc_fixture_env(), builder);
    assert!(!summary.is_empty());
    envelope
}

#[test]
fn usage_builder_produces_a_valid_envelope() {
    let payload = UsagePayloadBuilder::new()
        .linked_folder_count(3)
        .linked_folder_policy_count("eager", 2)
        .linked_folder_policy_count("on-demand", 1)
        .peer_count_bucket("1-2")
        .daemon_uptime_bucket("1d-7d")
        .build();
    let envelope = build_usage_envelope(env(), payload);
    envelope.validate().unwrap();
}

#[test]
fn error_builder_redacts_log_lines_and_backtrace_before_returning() {
    let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core")
        .log_lines(vec!["reading /Users/alice/secret failed".to_string()])
        .backtrace("panicked at /Users/alice/project/src/main.rs:42".to_string());
    let (envelope, summary) = build_error_envelope(env(), builder);
    envelope.validate().unwrap();
    let json = envelope.to_json();
    assert!(!json.contains("alice"));
    assert!(!summary.is_empty());
}

#[test]
fn error_builder_with_no_free_text_produces_an_empty_redaction_summary() {
    let builder = ErrorPayloadBuilder::new("daemon_startup", "control_socket");
    let (envelope, summary) = build_error_envelope(env(), builder);
    envelope.validate().unwrap();
    assert!(summary.is_empty());
}

#[test]
fn usage_report_fixture_contains_no_private_fields() {
    let expected = expected_doc_usage_report_fixture();
    expected.validate().unwrap();
    let fixture_json = expected.to_json();
    assert_public_doc_fixture_json_is_private(&fixture_json);
}

#[test]
fn error_report_fixture_contains_no_private_fields() {
    let expected = expected_doc_error_report_fixture();
    expected.validate().unwrap();
    let fixture_json = expected.to_json();
    assert!(fixture_json.contains("[REDACTED_HOME]"));
    assert!(fixture_json.contains("[REDACTED_TOKEN]"));
    assert_public_doc_fixture_json_is_private(&fixture_json);
}
