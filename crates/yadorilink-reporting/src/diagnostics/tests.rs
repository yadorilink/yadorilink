#![cfg(test)]

use serde_json::json;

use super::*;
use crate::redact::RedactionCategory;

#[test]
fn redacts_sensitive_diagnostics_text() {
    let text = "failed reading /Users/alice/Project/secret.txt with Bearer abcdefgh12345678 from 192.168.1.10";

    let (redacted, summary) = redact_diagnostics_text(text);

    assert!(!redacted.contains("/Users/alice"));
    assert!(!redacted.contains("secret.txt"));
    assert!(!redacted.contains("abcdefgh12345678"));
    assert!(!redacted.contains("192.168.1.10"));
    assert!(diagnostics_summary_count(&summary, RedactionCategory::HomeDirectory) >= 1);
    assert!(diagnostics_summary_count(&summary, RedactionCategory::BearerToken) >= 1);
    assert!(diagnostics_summary_count(&summary, RedactionCategory::IpAddress) >= 1);
}

#[test]
fn redacts_nested_diagnostics_json_values() {
    let bundle = json!({
        "link": {
            "path": "/Users/alice/Documents/Private",
            "device_id": "11111111-2222-3333-4444-555555555555",
            "peer": "10.0.0.4:7444"
        },
        "logs": [
            "token Bearer abcdefgh12345678",
            "key AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        ]
    });

    let (redacted, summary) = redact_diagnostics_value(&bundle);
    let rendered = serde_json::to_string(&redacted).unwrap();

    assert!(!rendered.contains("/Users/alice"));
    assert!(!rendered.contains("Private"));
    assert!(!rendered.contains("11111111-2222-3333-4444-555555555555"));
    assert!(!rendered.contains("10.0.0.4"));
    assert!(!rendered.contains("abcdefgh12345678"));
    assert!(!rendered.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="));
    assert!(diagnostics_summary_count(&summary, RedactionCategory::HomeDirectory) >= 1);
    assert!(diagnostics_summary_count(&summary, RedactionCategory::UuidLikeId) >= 1);
    assert!(diagnostics_summary_count(&summary, RedactionCategory::WireguardKey) >= 1);
}
