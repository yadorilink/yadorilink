#![cfg(test)]

use super::*;

#[test]
fn validate_addr_accepts_https_and_loopback_http_only() {
    assert!(validate_addr("https://coordination.example").is_ok());
    assert!(validate_addr("http://127.0.0.1:8787").is_ok());
    assert!(validate_addr("http://coordination.example").is_err());
    assert!(validate_addr("ftp://127.0.0.1").is_err());
}

/// Regression test: an earlier version of this function hand-rolled
/// the host extraction by splitting on `:`, which silently mangled an
/// IPv6 loopback literal (`[::1]`) since the address itself contains
/// colons. Parsing with the `url` crate handles this correctly.
#[test]
fn validate_addr_handles_an_ipv6_loopback_literal() {
    assert!(validate_addr("http://[::1]:8787").is_ok());
    assert!(validate_addr("http://[2001:db8::1]:8787").is_err());
}

#[test]
fn quota_exceeded_renders_a_specific_actionable_limit_error() {
    let body = serde_json::json!({
        "error": "quota_exceeded",
        "resource": "devices",
        "limit": 20,
        "current": 20
    });
    let err = error_from_body(429, &body);
    match err {
        CoreError::LimitExceeded { message: msg, kind: LimitKind::Quota } => {
            assert!(msg.contains("registered devices"), "got: {msg}");
            assert!(msg.contains("20 of 20"), "got: {msg}");
        }
        other => panic!("expected LimitExceeded, got {other:?}"),
    }
}

#[test]
fn rate_limited_renders_a_retry_hint() {
    let body = serde_json::json!({
        "error": "rate_limited",
        "scope": "source",
        "retryAfterSeconds": 30
    });
    match error_from_body(429, &body) {
        CoreError::LimitExceeded { message: msg, kind: LimitKind::RateLimited } => {
            assert!(msg.contains("30s"), "got: {msg}")
        }
        other => panic!("expected LimitExceeded, got {other:?}"),
    }
}

/// The cutover requirement, asserted rather than described: an empty
/// credential store is `NotLoggedIn` and the call never reaches a network.
/// Before the cutover this same state fell through to
/// `load_legacy_session`, so the assertion that matters is the *absence*
/// of a second lookup -- there is no other store to consult, and
/// `require_auth` has one branch to be wrong about.
#[tokio::test]
async fn an_empty_credential_store_is_not_enrolled_rather_than_a_second_lookup() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", dir.path().join("credentials.json"));
    // Pointed at a port nothing listens on: if `require_auth` ever tried
    // to reach the Authorization Server for an unenrolled installation,
    // this would surface as a transport error instead of `NotLoggedIn`.
    std::env::set_var(AUTH_SERVER_ADDR_VAR, "http://127.0.0.1:1");

    let result = require_auth().await;
    let signed_in = is_signed_in();

    std::env::remove_var(AUTH_SERVER_ADDR_VAR);
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");

    assert!(matches!(result, Err(CoreError::NotLoggedIn)), "expected NotLoggedIn, got {result:?}");
    assert!(!signed_in, "an installation with no credential reported itself signed in");
}

/// A store written by a build that still had the legacy plane is refused
/// as a store error, not read as "not logged in" and not migrated. The two
/// send the user to opposite places.
#[tokio::test]
async fn a_pre_cutover_store_is_a_store_error_rather_than_a_silent_sign_out() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("credentials.json");
    std::fs::write(
        &path,
        r#"{"format":1,"legacy_session":{"access_token":"at","refresh_token":"rt"}}"#,
    )
    .expect("write a pre-cutover document");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only");
    }

    let _guard = COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", &path);
    let result = require_auth().await;
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");

    assert!(
        matches!(result, Err(CoreError::CredentialStore(_))),
        "expected a credential-store error, got {result:?}"
    );
}

#[test]
fn plain_401_and_untyped_bodies_keep_their_prior_classification() {
    let auth = error_from_body(401, &serde_json::json!({ "error": "invalid credentials" }));
    assert!(matches!(auth, CoreError::AuthFailed(_)));
    let other = error_from_body(500, &serde_json::json!({ "error": "internal error" }));
    assert!(matches!(other, CoreError::Other(_)));
}

/// A 403 is classified as its own category, and its text is the bare error
/// code exactly as the untyped classification rendered it.
#[test]
fn a_403_is_forbidden_with_the_error_code_as_its_message() {
    let forbidden = error_from_body(403, &serde_json::json!({ "error": "not_group_owner" }));
    assert!(matches!(&forbidden, CoreError::Forbidden(m) if m == "not_group_owner"));
    assert_eq!(forbidden.to_string(), "not_group_owner");
}

/// A coordination request whose connection stalls (a server or middlebox
/// that holds it open without answering) must fail on its own. The app
/// cannot abandon an awaited call, so a request with no deadline would keep
/// its spinner up for the life of the process.
#[tokio::test(start_paused = true)]
async fn a_request_the_server_never_answers_gives_up() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        client().unwrap().get(format!("http://{addr}/v1/anything")).send(),
    )
    .await
    .expect("a request to a silent server must give up on its own");
    assert!(answer.unwrap_err().is_timeout());
}

#[test]
fn coordination_addr_env_override_wins_over_compiled_default() {
    assert_eq!(
        resolve_coordination_addr(Some("http://override:1"), Some("https://compiled.example")),
        "http://override:1"
    );
}

#[test]
fn coordination_addr_uses_compiled_default_without_env() {
    assert_eq!(
        resolve_coordination_addr(None, Some("https://compiled.example")),
        "https://compiled.example"
    );
    assert_eq!(
        resolve_coordination_addr(Some("  "), Some("https://compiled.example")),
        "https://compiled.example"
    );
}

#[test]
fn coordination_addr_falls_back_to_loopback() {
    assert_eq!(resolve_coordination_addr(None, None), "http://127.0.0.1:8787");
}

/// A step that never finishes (a service that accepts and never answers, at
/// any of discovery, refresh or the request itself) ends within the operation
/// budget as the "service unreachable" error the UI shows with Retry.
#[tokio::test(start_paused = true)]
async fn an_operation_that_never_finishes_is_unreachable_within_the_budget() {
    let started = tokio::time::Instant::now();
    let err = bounded(std::future::pending::<Result<(), CoreError>>()).await.unwrap_err();
    assert!(matches!(err, CoreError::CoordinationPlaneUnreachable(_)), "{err:?}");
    assert!(started.elapsed() <= std::time::Duration::from_secs(30));
    assert!(matches!(
        crate::error::DesktopError::from(err),
        crate::error::DesktopError::Network {
            kind: crate::error::NetworkErrorKind::Unreachable,
            ..
        }
    ));
}

/// A silent server fails the request itself well inside the budget.
#[tokio::test(start_paused = true)]
async fn a_silent_server_times_out_within_thirty_seconds() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    let started = tokio::time::Instant::now();
    let err = client().unwrap().get(format!("http://{addr}/x")).send().await.unwrap_err();
    assert!(err.is_timeout());
    assert!(started.elapsed() <= std::time::Duration::from_secs(30));
}

/// A closed port is refused at once, as the same unreachable error.
#[tokio::test]
async fn a_closed_port_is_refused_promptly() {
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let started = std::time::Instant::now();
    let err = client().unwrap().get(format!("http://{addr}/x")).send().await.unwrap_err();
    assert!(err.is_connect());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// A server that sends headers and then stalls the body is also
/// "unreachable", not an internal error.
#[tokio::test]
async fn a_stalled_success_body_is_unreachable() {
    stalled_body_is_unreachable("200 OK").await;
}

#[tokio::test]
async fn a_stalled_401_body_is_unreachable() {
    stalled_body_is_unreachable("401 Unauthorized").await;
}

#[tokio::test]
async fn a_stalled_500_body_is_unreachable() {
    stalled_body_is_unreachable("500 Internal Server Error").await;
}

async fn stalled_body_is_unreachable(status: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{{"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut s, _)) = listener.accept().await {
            // Read the request head before answering: newer hyper rejects a response that
            // arrives before its request was read as an unexpected message.
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let _ = s.write_all(head.as_bytes()).await;
            held.push(s);
        }
    });
    // The connection and the head are real socket I/O, so they run on the real clock: a paused
    // clock auto-advances whenever the runtime waits on a socket, which under load fires the
    // request timeout before the head arrives. Only the stall itself runs on paused time.
    let resp = client().unwrap().get(format!("http://{addr}/x")).send().await.unwrap();
    tokio::time::pause();
    let err = handle_response::<serde_json::Value>(resp).await.unwrap_err();
    assert!(matches!(err, CoreError::CoordinationPlaneUnreachable(_)), "{err:?}");
}
