//! How a `CoordinationAuth` treats the Terms-consent gate of the Coordination
//! service, against a local HTTP server that answers with the exact shapes the
//! service produces: `403 {"error":"terms_consent_required","terms_version":..}`
//! on an API call and `400 {"error":"invalid_grant"}` on a refresh.

use std::sync::Arc;
use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_fapi_client::store::{Backend, CredentialStore, Credentials};
use yadorilink_fapi_client::{CoordinationAuth, CoordinationBlock, CredentialManager, Es256Key};

fn metadata(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/auth"),
        "token_endpoint": format!("{issuer}/token"),
        "pushed_authorization_request_endpoint": format!("{issuer}/request"),
        "userinfo_endpoint": format!("{issuer}/me"),
        "registration_endpoint": format!("{issuer}/reg"),
        "require_pushed_authorization_requests": true,
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    })
}

struct Fixture {
    server: MockServer,
    auth: CoordinationAuth,
    store: Arc<CredentialStore>,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata(&server.uri())))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Arc::new(CredentialStore::with_backend(
        Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    ));
    let lock = store.lock(Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &Credentials::new(
                server.uri(),
                "ylk-test-installation".to_owned(),
                Es256Key::generate().to_jwk_json(),
                "rt-1".to_owned(),
            ),
        )
        .expect("seed the store");
    drop(lock);
    let manager = CredentialManager::restore(reqwest::Client::new(), &server.uri(), store.clone())
        .await
        .expect("restore from the store");
    let auth = CoordinationAuth::new(Arc::new(manager)).expect("a valid issuer");
    Fixture { server, auth, store, _dir: dir }
}

async fn token_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("recording on")
        .iter()
        .filter(|r| r.url.path() == "/token")
        .count()
}

/// A refresh answered `invalid_grant` is reported as sign-in required, keeps the
/// stored credential, and is not presented to the server again for every call.
#[tokio::test]
async fn refused_refresh_is_remembered_and_not_repeated_and_keeps_the_credential() {
    let f = fixture().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(serde_json::json!({"error": "invalid_grant"})),
        )
        .mount(&f.server)
        .await;
    assert_eq!(f.auth.block(), None);

    for _ in 0..5 {
        let err =
            f.auth.authorize("GET", &format!("{}/devices", f.server.uri())).await.unwrap_err();
        assert!(err.is_invalid_grant(), "the refusal is replayed as the same error: {err}");
    }

    assert_eq!(f.auth.block(), Some(CoordinationBlock::SignInRequired));
    assert_eq!(token_requests(&f.server).await, 1, "one refused refresh, not one per call");
    let kept = f.store.load().expect("readable").expect("the credential is kept");
    assert_eq!(kept.refresh_token(), "rt-1");
}

/// A forced refresh (Sign Out's probe) is never answered from the memory.
#[tokio::test]
async fn a_forced_refresh_still_asks_the_server() {
    let f = fixture().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(serde_json::json!({"error": "invalid_grant"})),
        )
        .mount(&f.server)
        .await;
    let _ = f.auth.authorize("GET", &format!("{}/devices", f.server.uri())).await;
    let _ = f.auth.confirm_registration_status().await;
    assert_eq!(token_requests(&f.server).await, 2);
}

/// `observe_status` is how the netmap upgrade reports the same refusal; a later
/// passing status clears it.
#[test]
fn a_consent_refusal_names_the_version_and_only_a_success_clears_it() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let f = rt.block_on(fixture());
    let body =
        br#"{"error":"terms_consent_required","terms_version":"placeholder-v0","message":"m"}"#;
    f.auth.observe_status(403, body);
    assert_eq!(
        f.auth.block(),
        Some(CoordinationBlock::TermsConsentRequired {
            terms_version: Some("placeholder-v0".into())
        })
    );
    // Answers that prove nothing about the gate leave what is known as it is.
    for (status, other) in [
        (403, &br#"{"error":"forbidden"}"#[..]),
        (403, &b""[..]),
        (401, &b""[..]),
        (404, &b""[..]),
        (429, &b""[..]),
    ] {
        f.auth.observe_status(status, other);
        assert!(f.auth.block().is_some(), "{status} must not clear the block");
    }
    f.auth.observe_status(200, b"");
    assert_eq!(f.auth.block(), None);
}

/// Through `execute`: the 403 is recognised AND handed to the caller whole.
#[tokio::test]
async fn execute_recognises_the_consent_refusal_and_returns_the_body_intact() {
    let f = fixture().await;
    // A cached token so no refresh is needed: seed through a token endpoint that succeeds once.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-1", "token_type": "DPoP", "expires_in": 300,
            "refresh_token": "rt-2", "scope": "openid offline_access"
        })))
        .mount(&f.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/devices"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "terms_consent_required", "terms_version": "placeholder-v0", "message": "m"
        })))
        .mount(&f.server)
        .await;
    let request = reqwest::Client::new().get(format!("{}/devices", f.server.uri()));
    let response = f.auth.execute(request).await.expect("sent");
    assert_eq!(response.status(), 403);
    let body: serde_json::Value = response.json().await.expect("the body is still readable");
    assert_eq!(body["terms_version"], "placeholder-v0");
    assert_eq!(
        f.auth.block(),
        Some(CoordinationBlock::TermsConsentRequired {
            terms_version: Some("placeholder-v0".into())
        })
    );
    // The credential is untouched by a consent refusal.
    assert!(f.store.load().expect("readable").is_some());
}

/// Callers queued behind a refresh that the server refuses do not each send their own.
#[tokio::test]
async fn concurrent_callers_share_one_refused_refresh() {
    let f = fixture().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_delay(Duration::from_millis(150))
                .set_body_json(serde_json::json!({"error": "invalid_grant"})),
        )
        .mount(&f.server)
        .await;
    let url = format!("{}/devices", f.server.uri());
    let calls: Vec<_> = (0..8)
        .map(|_| {
            let (auth, url) = (f.auth.clone(), url.clone());
            tokio::spawn(async move { auth.authorize("GET", &url).await })
        })
        .collect();
    for call in calls {
        assert!(call.await.unwrap().unwrap_err().is_invalid_grant());
    }
    assert_eq!(token_requests(&f.server).await, 1);
}

/// A refresh that works again proves the consent gate was passed.
#[tokio::test]
async fn a_successful_refresh_clears_a_remembered_consent_block() {
    let f = fixture().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-1", "token_type": "DPoP", "expires_in": 300,
            "refresh_token": "rt-2", "scope": "openid offline_access"
        })))
        .mount(&f.server)
        .await;
    f.auth.observe_status(403, br#"{"error":"terms_consent_required"}"#);
    assert!(f.auth.block().is_some());
    f.auth.authorize("GET", &format!("{}/devices", f.server.uri())).await.expect("refreshed");
    assert_eq!(f.auth.block(), None);
}

/// A token served from the cache is no evidence that the consent gate is passed.
#[tokio::test]
async fn a_cache_hit_authorize_does_not_clear_the_consent_block() {
    let f = fixture().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-1", "token_type": "DPoP", "expires_in": 300,
            "refresh_token": "rt-2", "scope": "openid offline_access"
        })))
        .mount(&f.server)
        .await;
    let url = format!("{}/devices", f.server.uri());
    f.auth.authorize("GET", &url).await.expect("one real refresh");
    f.auth.observe_status(403, br#"{"error":"terms_consent_required","terms_version":"v"}"#);
    for _ in 0..3 {
        f.auth.authorize("GET", &url).await.expect("served from the cache");
    }
    assert_eq!(token_requests(&f.server).await, 1, "the later calls were cache hits");
    assert!(f.auth.block().is_some(), "a cache hit must not lift the block");
}
