//! A process that keeps making authenticated Coordination calls across the
//! five-minute access-token lifetime, in real wall-clock time.
//!
//! # Why this test costs five and a half minutes and is worth it
//!
//! the coordination service sets
//! `accessToken: 300` seconds. Every other test in this workspace proves
//! things about the token cache's *arithmetic* -- that a token inside the skew
//! is not served, that a missing `expires_in` is treated as short. None of
//! them proves the product property, which is that a long-running daemon is
//! still authenticated after lunch. That property is the difference between a
//! demonstration and a daemon, and the only way to establish it is to cross
//! the boundary.
//!
//! So this test does not fake the clock, does not shorten the lifetime, and
//! does not assert on `expires_in`. It issues tokens with the deployment's own
//! 300-second lifetime, stands up a resource server that *enforces* that
//! lifetime against its own monotonic clock, and then makes an authenticated
//! request every twenty seconds for five minutes and twenty seconds. A run
//! that captured a token at startup -- which is exactly what the daemon's old
//! `OrchestratorConfig { access_token: String }` did -- starts failing at
//! t+300s and cannot recover.
//!
//! # What the resource server refuses, and why that matters
//!
//! The mock below is not a rubber stamp. It records the instant each access
//! token was issued and answers `401 invalid_token` to any request presenting
//! one older than 300 seconds, exactly as an expired opaque token would be
//! refused by `resource.ts`. Without that, the test would pass against a
//! client that never refreshed at all, which is the bug it exists to catch.
//!
//! # Which failure this would show
//!
//! * A token held as a value: every call from t+300s on is a 401 and the test
//!   fails on the first one.
//! * A refresh that never fires: same, one interval later.
//! * A refresh that fires but is not adopted: the assertion that the token in
//!   flight changed at least once fails even if the calls somehow succeed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use yadorilink_fapi_client::store::{Backend, CredentialStore, Credentials};
use yadorilink_fapi_client::{CoordinationAuth, Es256Key, FapiClient};

/// The deployment's own value. Not shortened for the test -- shortening it
/// would prove the client can refresh a token that the product does not issue.
const ACCESS_TOKEN_LIFETIME: Duration = Duration::from_secs(300);

/// Long enough that the run is unambiguously past the boundary rather than
/// sitting on it.
const RUN_FOR: Duration = Duration::from_secs(320);

/// One authenticated request per interval. Sixteen requests over the run, of
/// which at least four land after the startup token has died.
const CALL_EVERY: Duration = Duration::from_secs(20);

/// The Authorization Server and the Resource Server, sharing one token table,
/// because in production they share one deployment and the resource server
/// validates what the authorization server issued.
#[derive(Default)]
struct Plane {
    /// access token -> the instant it was issued.
    issued: HashMap<String, Instant>,
    /// The refresh token that is currently live. Rotated on every refresh.
    refresh_token: String,
    /// How many refreshes the client has performed.
    refreshes: u32,
}

impl Plane {
    fn issue(&mut self) -> (String, String) {
        self.refreshes += 1;
        let access = format!("at-{}", self.refreshes);
        let refresh = format!("rt-{}", self.refreshes);
        self.issued.insert(access.clone(), Instant::now());
        self.refresh_token = refresh.clone();
        (access, refresh)
    }

    fn is_live(&self, access_token: &str) -> bool {
        self.issued.get(access_token).is_some_and(|issued| issued.elapsed() < ACCESS_TOKEN_LIFETIME)
    }
}

/// `POST /token`, `grant_type=refresh_token`. Rotates, and refuses a refresh
/// token that is not the live one.
struct TokenEndpoint(Arc<Mutex<Plane>>);

impl Respond for TokenEndpoint {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = String::from_utf8_lossy(&request.body).into_owned();
        let presented = form_value(&body, "refresh_token").unwrap_or_default();

        let mut plane = self.0.lock().expect("the plane mutex");
        if presented != plane.refresh_token {
            return ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": "invalid_grant" }));
        }
        let (access, refresh) = plane.issue();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": access,
            "token_type": "DPoP",
            "expires_in": ACCESS_TOKEN_LIFETIME.as_secs(),
            "refresh_token": refresh,
        }))
    }
}

/// A Coordination API route that actually checks the credential's lifetime.
struct ProtectedRoute(Arc<Mutex<Plane>>);

impl Respond for ProtectedRoute {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let Some(authorization) = request.headers.get("authorization") else {
            return ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({ "error": "invalid_token" }));
        };
        let authorization = authorization.to_str().unwrap_or_default();
        let Some(token) = authorization.strip_prefix("DPoP ") else {
            // A `Bearer`-shaped credential is refused, whatever it carries --
            // the same refusal `resource.ts` makes.
            return ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({ "error": "invalid_token" }));
        };
        if request.headers.get("dpop").is_none() {
            return ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({ "error": "invalid_dpop_proof" }));
        }
        if !self.0.lock().expect("the plane mutex").is_live(token) {
            return ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({ "error": "invalid_token" }));
        }
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "devices": [], "presented": token }))
    }
}

fn form_value(body: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(body.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// Real wall-clock, deliberately: this is the one property in the credential
/// manager that a virtual clock cannot establish, because the thing being
/// checked is whether the client's own notion of expiry agrees with a server's.
#[tokio::test(flavor = "multi_thread")]
async fn a_process_stays_authenticated_across_the_five_minute_access_token_lifetime() {
    let plane = Arc::new(Mutex::new(Plane::default()));
    // The starting grant: one live refresh token, no access token yet, so the
    // client's very first call has to go and get one.
    plane.lock().expect("the plane mutex").refresh_token = "rt-0".to_owned();

    let server = MockServer::start().await;
    let issuer = server.uri();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        // The deployed server's profile, not a three-member minimum. Discovery
        // requires the whole profile -- PAR required, PKCE S256,
        // `private_key_jwt`, ES256 for assertions and for DPoP, the
        // authorization-code and refresh-token grants -- and a mock that
        // advertised less would exercise a client this product cannot build.
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "pushed_authorization_request_endpoint": format!("{issuer}/request"),
            "require_pushed_authorization_requests": true,
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(TokenEndpoint(plane.clone()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/devices"))
        .respond_with(ProtectedRoute(plane.clone()))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let store = CredentialStore::with_backend(
        Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    );
    let client_key = Es256Key::generate();
    let lock = store.lock(Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &Credentials::new(
                issuer.clone(),
                "ylk-boundary".to_owned(),
                client_key.to_jwk_json(),
                "rt-0".to_owned(),
            ),
        )
        .expect("seed the store");
    drop(lock);

    let client = FapiClient::discover(
        reqwest::Client::new(),
        &issuer,
        "ylk-boundary",
        client_key,
        Es256Key::generate(),
    )
    .await
    .expect("discovery");
    let manager =
        Arc::new(yadorilink_fapi_client::test_support::manager_over(client, Arc::new(store)));
    let auth = CoordinationAuth::new(manager).expect("the mock issuer is a URL");

    let http = reqwest::Client::new();
    let url = format!("{issuer}/devices");
    let started = Instant::now();
    let mut tokens_seen = Vec::new();
    let mut calls_after_the_boundary = 0_u32;

    while started.elapsed() < RUN_FOR {
        let elapsed = started.elapsed();
        let response = auth
            .execute(http.get(&url))
            .await
            .unwrap_or_else(|e| panic!("could not authenticate at t+{elapsed:?}: {e}"));
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap_or_default();

        assert_eq!(
            status, 200,
            "an authenticated call failed at t+{elapsed:?} with {body}; a daemon that captured \
             its token at startup fails here and never recovers"
        );

        let presented =
            body["presented"].as_str().expect("the route echoes the token it accepted").to_owned();
        if tokens_seen.last() != Some(&presented) {
            tokens_seen.push(presented);
        }
        if elapsed > ACCESS_TOKEN_LIFETIME {
            calls_after_the_boundary += 1;
        }

        println!(
            "t+{:>3}s  200  token={}  refreshes={}",
            elapsed.as_secs(),
            tokens_seen.last().expect("at least one token"),
            plane.lock().expect("the plane mutex").refreshes
        );

        tokio::time::sleep(CALL_EVERY).await;
    }

    assert!(
        started.elapsed() > ACCESS_TOKEN_LIFETIME,
        "the run did not reach the boundary it exists to cross"
    );
    assert!(
        calls_after_the_boundary >= 1,
        "no authenticated call landed after the startup token's lifetime had elapsed"
    );
    assert!(
        tokens_seen.len() >= 2,
        "the same access token was presented for the whole run ({tokens_seen:?}); the calls \
         succeeded without the token ever being refreshed, which means the resource server is \
         not enforcing the lifetime and this test proves nothing"
    );

    let plane = plane.lock().expect("the plane mutex");
    assert!(
        plane.refreshes >= 2,
        "the client refreshed {} time(s); one is the initial token, so a second is what crossing \
         the boundary requires",
        plane.refreshes
    );
    println!(
        "crossed the boundary: {} distinct access tokens over {}s, {} token-endpoint round trips",
        tokens_seen.len(),
        started.elapsed().as_secs(),
        plane.refreshes
    );
}
