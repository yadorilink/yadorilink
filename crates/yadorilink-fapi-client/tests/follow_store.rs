//! A running process follows a credential store that was replaced under it
//! (sign out, then sign in again) without restarting.
//!
//! The manager is fixed to one installation. These tests drive the
//! `CoordinationAuth` built with `reloading` through the two ways the change
//! shows up: the server refusing the cached token of the old installation, and
//! the old installation's refresh finding the store holds another one.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};
use yadorilink_fapi_client::store::{Backend, CredentialStore, Credentials};
use yadorilink_fapi_client::{CoordinationAuth, CredentialManager, Error, Es256Key, Reload};

async fn serve_discovery(server: &MockServer) {
    let issuer = server.uri();
    let document = serde_json::json!({
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
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document))
        .mount(server)
        .await;
}

/// The token endpoint issues `at-<suffix of the presented refresh token>`, so
/// which installation a request belongs to is readable from its access token.
async fn serve_tokens(server: &MockServer, expires_in: u64) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |request: &Request| {
            let body = String::from_utf8_lossy(&request.body).into_owned();
            let presented = body
                .split('&')
                .find_map(|pair| pair.strip_prefix("refresh_token="))
                .unwrap_or("rt-unknown")
                .to_owned();
            let suffix = presented.trim_start_matches("rt-");
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": format!("at-{suffix}"),
                "token_type": "DPoP",
                "expires_in": expires_in,
                "refresh_token": format!("rt-{suffix}-rotated"),
                "scope": "openid offline_access",
            }))
        })
        .mount(server)
        .await;
}

/// `/ping` accepts only the new installation's token.
async fn serve_ping(server: &MockServer, calls: Arc<AtomicUsize>) {
    Mock::given(method("GET"))
        .and(path("/ping"))
        .respond_with(move |request: &Request| {
            calls.fetch_add(1, Ordering::SeqCst);
            let authorization = request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            if authorization.starts_with("DPoP at-new") {
                ResponseTemplate::new(200).set_body_string(authorization)
            } else {
                ResponseTemplate::new(401)
            }
        })
        .mount(server)
        .await;
}

async fn install(store: &CredentialStore, issuer: &str, client_id: &str, refresh_token: &str) {
    let lock = store.lock(Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &Credentials::new(
                issuer.to_owned(),
                client_id.to_owned(),
                Es256Key::generate().to_jwk_json(),
                refresh_token.to_owned(),
            ),
        )
        .expect("save");
}

async fn sign_out(store: &CredentialStore) {
    let lock = store.lock(Duration::from_secs(5)).await.expect("lock");
    store.clear(&lock).expect("clear");
}

fn reloader(base: String, store: Arc<CredentialStore>) -> Reload {
    Arc::new(move |running: String| {
        let base = base.clone();
        let store = store.clone();
        Box::pin(async move {
            match store.load()? {
                Some(stored) if stored.client_id() != running => Ok(Some(Arc::new(
                    CredentialManager::restore(reqwest::Client::new(), &base, store.clone())
                        .await?,
                ))),
                _ => Ok(None),
            }
        })
    })
}

struct Fixture {
    server: MockServer,
    store: Arc<CredentialStore>,
    auth: CoordinationAuth,
    _dir: tempfile::TempDir,
}

async fn running_daemon(expires_in: u64) -> Fixture {
    let server = MockServer::start().await;
    serve_discovery(&server).await;
    serve_tokens(&server, expires_in).await;
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Arc::new(CredentialStore::with_backend(
        Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    ));
    install(&store, &server.uri(), "client-old", "rt-old").await;
    let manager = CredentialManager::restore(reqwest::Client::new(), &server.uri(), store.clone())
        .await
        .expect("restore");
    let auth =
        CoordinationAuth::reloading(Arc::new(manager), reloader(server.uri(), store.clone()))
            .expect("auth");
    Fixture { server, store, auth, _dir: dir }
}

#[tokio::test]
async fn logout_then_login_is_followed_on_the_next_call_even_with_a_cached_old_token() {
    let fixture = running_daemon(300).await;
    let calls = Arc::new(AtomicUsize::new(0));
    serve_ping(&fixture.server, calls.clone()).await;
    let url = format!("{}/ping", fixture.server.uri());
    let http = reqwest::Client::new();

    // The old installation's token is cached and refused by the server.
    let first = fixture.auth.execute(http.get(&url)).await.expect("send");
    assert_eq!(first.status(), 401);
    assert_eq!(fixture.auth.client_id(), "client-old");

    sign_out(&fixture.store).await;
    install(&fixture.store, &fixture.server.uri(), "client-new", "rt-new").await;

    let second = fixture.auth.execute(http.get(&url)).await.expect("send");
    assert_eq!(second.status(), 200, "the call after sign-in must use the new installation");
    assert_eq!(fixture.auth.client_id(), "client-new");
}

#[tokio::test]
async fn logout_then_login_is_followed_when_the_old_token_needs_refreshing() {
    // Inside the refresh skew: every call refreshes, so the refresh is what
    // discovers that the store holds another installation.
    let fixture = running_daemon(10).await;
    sign_out(&fixture.store).await;
    install(&fixture.store, &fixture.server.uri(), "client-new", "rt-new").await;

    let headers = fixture.auth.authorize("GET", &format!("{}/x", fixture.server.uri())).await;
    let headers = headers.expect("authorizes as the new installation");
    assert_eq!(headers.authorization(), "DPoP at-new");
    assert_eq!(fixture.auth.client_id(), "client-new");
}

#[tokio::test]
async fn a_signed_out_store_is_not_followed_and_the_failure_stays_visible() {
    let fixture = running_daemon(10).await;
    sign_out(&fixture.store).await;

    let result = fixture.auth.authorize("GET", &format!("{}/x", fixture.server.uri())).await;
    assert!(matches!(result, Err(Error::NotEnrolled)), "got {result:?}");
    assert_eq!(fixture.auth.client_id(), "client-old");
}

#[tokio::test]
async fn concurrent_calls_all_follow_one_replaced_sign_in() {
    let fixture = running_daemon(300).await;
    let calls = Arc::new(AtomicUsize::new(0));
    serve_ping(&fixture.server, calls).await;
    let url = format!("{}/ping", fixture.server.uri());
    let http = reqwest::Client::new();
    assert_eq!(fixture.auth.execute(http.get(&url)).await.expect("send").status(), 401);

    sign_out(&fixture.store).await;
    install(&fixture.store, &fixture.server.uri(), "client-new", "rt-new").await;

    let get = || fixture.auth.execute(http.get(&url));
    let (a, b, c, d) = tokio::join!(get(), get(), get(), get());
    for response in [a, b, c, d] {
        assert_eq!(response.expect("send").status(), 200);
    }
}
