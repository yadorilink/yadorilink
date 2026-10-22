#![cfg(test)]

use std::time::Duration;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::builder::{build_usage_envelope, ReportEnvironment};
use crate::schema::UsagePayload;

fn sample_env() -> ReportEnvironment {
    ReportEnvironment {
        generated_at: "2026-01-01T00:00:00Z".into(),
        yadorilink_version: "0.1.0".into(),
        os_family: crate::schema::OsFamily::Linux,
        os_version_bucket: "24.04".into(),
        arch: "x86_64".into(),
        install_channel: None,
        anonymous_reporter_id: None,
    }
}

fn sample_envelope() -> ReportEnvelope {
    build_usage_envelope(
        sample_env(),
        UsagePayload {
            linked_folder_count: 1,
            daemon_uptime_bucket: "1h-1d".into(),
            peer_count_bucket: "1-2".into(),
            ..Default::default()
        },
    )
}

fn fast_client(min_submit_interval: Duration) -> SubmissionClient {
    SubmissionClient::new(SubmissionConfig { timeout: Duration::from_secs(5), min_submit_interval })
        .unwrap()
}

#[tokio::test]
async fn valid_report_to_reachable_endpoint_returns_the_mocks_receipt() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reports"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "receipt_id": "receipt-abc123",
            "submitted_at": "2026-01-01T00:00:05Z",
        })))
        .mount(&server)
        .await;

    let client = fast_client(Duration::from_millis(0));
    let endpoint = format!("{}/reports", server.uri());
    let receipt = client
        .submit("report-1", &sample_envelope(), Some(&endpoint))
        .await
        .expect("submission should succeed against a reachable mock endpoint");

    assert_eq!(receipt.report_id, "report-1");
    assert_eq!(receipt.receipt_id, "receipt-abc123");
    assert_eq!(receipt.submitted_at, "2026-01-01T00:00:05Z");
}

#[tokio::test]
async fn no_endpoint_configured_fails_without_any_network_call() {
    let server = MockServer::start().await;
    // No `Mock::given(...)` mounted — if a request were sent it
    // would 404, but we assert below that none was sent at all.

    let client = fast_client(Duration::from_millis(0));
    let err = client
        .submit("report-1", &sample_envelope(), None)
        .await
        .expect_err("None endpoint must fail as NoEndpointConfigured");

    assert_eq!(err, SubmissionError::NoEndpointConfigured);
    assert!(!err.is_retryable());
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no request should reach the endpoint when none is configured"
    );
}

#[tokio::test]
async fn a_hanging_endpoint_does_not_block_past_the_configured_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reports"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"receipt_id": "late", "submitted_at": "x"}))
                // Far longer than the client's configured timeout below.
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;

    let client = SubmissionClient::new(SubmissionConfig {
        timeout: Duration::from_millis(150),
        min_submit_interval: Duration::from_millis(0),
    })
    .unwrap();
    let endpoint = format!("{}/reports", server.uri());

    let started = Instant::now();
    let err = client
        .submit("report-1", &sample_envelope(), Some(&endpoint))
        .await
        .expect_err("a hanging endpoint must time out, not hang the caller");
    let elapsed = started.elapsed();

    assert!(matches!(err, SubmissionError::Timeout(_)));
    assert!(err.is_retryable());
    assert!(
        elapsed < Duration::from_secs(2),
        "submit() took {elapsed:?}, expected it to return near the 150ms timeout, \
         well under the mock's 5s delay"
    );
}

#[tokio::test]
async fn outgoing_request_carries_no_authorization_header_or_auth_token_shaped_value() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reports"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "receipt_id": "receipt-1",
            "submitted_at": "2026-01-01T00:00:05Z",
        })))
        .mount(&server)
        .await;

    let client = fast_client(Duration::from_millis(0));
    let endpoint = format!("{}/reports", server.uri());
    client
        .submit("report-1", &sample_envelope(), Some(&endpoint))
        .await
        .expect("submission should succeed");

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];

    assert!(
        request.headers.get("authorization").is_none(),
        "submission request must never carry an Authorization header"
    );

    // A locally-constructed, auth-token-shaped value this client was
    // never given access to in the first place (its function
    // signature only accepts a ReportEnvelope + endpoint string) —
    // asserting its absence documents that no such value can leak
    // into the wire request, now or after a future refactor.
    let fake_device_auth_token = "yadorilink-device-secret-do-not-leak-4f9c2e";
    let body_text = String::from_utf8_lossy(&request.body);
    assert!(!body_text.contains(fake_device_auth_token));
    for (name, value) in request.headers.iter() {
        assert_ne!(name.as_str().to_ascii_lowercase(), "authorization");
        if let Ok(value_str) = value.to_str() {
            assert!(!value_str.contains(fake_device_auth_token));
        }
    }
}

#[tokio::test]
async fn rate_limiter_blocks_a_second_immediate_attempt_without_a_network_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reports"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "receipt_id": "receipt-1",
            "submitted_at": "2026-01-01T00:00:05Z",
        })))
        .mount(&server)
        .await;

    let client = fast_client(Duration::from_secs(60));
    let endpoint = format!("{}/reports", server.uri());

    client
        .submit("report-1", &sample_envelope(), Some(&endpoint))
        .await
        .expect("first submission should succeed");

    let err = client
        .submit("report-2", &sample_envelope(), Some(&endpoint))
        .await
        .expect_err("second immediate submission should be rate limited");
    assert!(matches!(err, SubmissionError::RateLimited { .. }));
    assert!(err.is_retryable());

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the rate-limited attempt must not reach the network"
    );
}

#[tokio::test]
async fn a_permanent_http_4xx_is_not_marked_retryable_but_a_5xx_is() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reports"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;

    let client = fast_client(Duration::from_millis(0));
    let endpoint = format!("{}/reports", server.uri());
    let err = client.submit("report-1", &sample_envelope(), Some(&endpoint)).await.unwrap_err();
    assert!(matches!(err, SubmissionError::HttpStatus { status: 400, .. }));
    assert!(!err.is_retryable());
}

#[test]
fn plain_http_to_a_non_loopback_host_is_rejected() {
    let err = validate_endpoint("http://reports.example.com/submit").unwrap_err();
    assert!(matches!(err, SubmissionError::InvalidEndpoint(_)));
}

#[test]
fn plain_http_to_loopback_is_accepted_for_local_testing() {
    assert!(validate_endpoint("http://127.0.0.1:8080/submit").is_ok());
    assert!(validate_endpoint("http://localhost:8080/submit").is_ok());
}

#[test]
fn https_to_any_host_is_accepted() {
    assert!(validate_endpoint("https://reports.example.com/submit").is_ok());
}

#[test]
fn an_oversized_envelope_is_rejected_before_any_network_attempt_would_be_made() {
    let mut envelope = sample_envelope();
    if let crate::schema::ReportPayload::Usage(usage) = &mut envelope.payload {
        for i in 0..10_000 {
            usage.command_category_counts.insert(format!("category-{i}"), i);
        }
    }
    let err = envelope.validate().unwrap_err();
    assert!(matches!(err, ValidationError::TooLarge { .. }));
    // And the same failure surfaces through SubmissionError as a
    // permanent (non-retryable) error via `?`/`From`.
    let submission_err: SubmissionError = err.into();
    assert!(!submission_err.is_retryable());
}
