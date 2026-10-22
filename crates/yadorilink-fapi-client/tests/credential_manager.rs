//! The credential manager and the enrolment endpoints, against a local HTTP
//! server.
//!
//! # Why these are not gated on a live Authorization Server
//!
//! `tests/vertical_flow.rs` and `tests/negatives.rs` need the real server
//! because what they assert is the server's behaviour. What is asserted here
//! is the *client's*: that the cache refreshes before a five-minute token
//! dies rather than after, that a rotated refresh token is persisted before it
//! is relied on, that two processes cannot spend the same refresh token, and
//! that a device-grant poll widens its interval the way RFC 8628 section 3.5
//! requires. None of that is observable from a successful live run -- a live
//! run passes whether or not the cache ever refreshed -- and two of them
//! cannot be produced against a live server at all without waiting five
//! minutes or revoking a real grant.
//!
//! A deployment's discovery document need not advertise
//! `device_authorization_endpoint` or `registration_endpoint`, so these are
//! exercised against a mock server.

use std::sync::Arc;
use std::time::Duration;

use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};
use yadorilink_fapi_client::store::{Backend, CredentialStore, Credentials};
use yadorilink_fapi_client::{CredentialManager, Error, Es256Key, FapiClient};

/// The metadata a deployment with every feature on advertises. Written out
/// rather than fetched so a test can turn one member off and see what the
/// client does about it.
fn metadata(issuer: &str, device_flow: bool) -> serde_json::Value {
    let mut grant_types = vec!["authorization_code", "refresh_token"];
    if device_flow {
        grant_types.push(yadorilink_fapi_client::DEVICE_CODE_GRANT);
    }
    let mut document = serde_json::json!({
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
        "grant_types_supported": grant_types,
    });
    if device_flow {
        document["device_authorization_endpoint"] =
            serde_json::Value::String(format!("{issuer}/device/auth"));
    }
    document
}

async fn serve_discovery(server: &MockServer, device_flow: bool) {
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata(&issuer, device_flow)))
        .mount(server)
        .await;
}

fn token_body(access_token: &str, refresh_token: &str, expires_in: u64) -> serde_json::Value {
    serde_json::json!({
        "access_token": access_token,
        "token_type": "DPoP",
        "expires_in": expires_in,
        "refresh_token": refresh_token,
        "scope": "openid offline_access",
    })
}

struct Enrolled {
    _dir: tempfile::TempDir,
    store: Arc<CredentialStore>,
}

async fn enrol(issuer: &str, refresh_token: &str) -> Enrolled {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = CredentialStore::with_backend(
        Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    );
    let lock = store.lock(Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &Credentials::new(
                issuer.to_owned(),
                "ylk-test-installation".to_owned(),
                Es256Key::generate().to_jwk_json(),
                refresh_token.to_owned(),
            ),
        )
        .expect("save");
    drop(lock);
    Enrolled { _dir: dir, store: Arc::new(store) }
}

async fn manager(server: &MockServer, enrolled: &Enrolled) -> CredentialManager {
    CredentialManager::restore(reqwest::Client::new(), &server.uri(), enrolled.store.clone())
        .await
        .expect("restore from the store")
}

/// The header a DPoP proof travelled in, decoded back to its embedded key's
/// thumbprint -- which is the sender constraint the server would record.
fn proof_jkt(request: &Request) -> String {
    use base64::Engine as _;
    let proof = request
        .headers
        .get("dpop")
        .expect("every token request carries a proof")
        .to_str()
        .expect("ASCII");
    let header = proof.split('.').next().expect("compact JWS");
    let decoded =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header).expect("base64url");
    let header: serde_json::Value = serde_json::from_slice(&decoded).expect("JSON");
    let jwk: yadorilink_fapi_client::PublicJwk =
        serde_json::from_value(header["jwk"].clone()).expect("four-member EC JWK");
    jwk.thumbprint()
}

// --- the access-token cache --------------------------------------------------

#[tokio::test]
async fn a_live_access_token_is_served_from_memory_rather_than_refreshed_again() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_body("at-1", "rt-2", 300)))
        .expect(1)
        .mount(&server)
        .await;

    let enrolled = enrol(&server.uri(), "rt-1").await;
    let manager = manager(&server, &enrolled).await;

    assert_eq!(manager.access_token().await.expect("first"), "at-1");
    for _ in 0..20 {
        assert_eq!(manager.access_token().await.expect("cached"), "at-1");
    }
    // `expect(1)` above is the assertion: twenty-one calls, one token request.
}

/// The whole reason this type exists. A five-minute token used by a
/// long-running daemon has to be replaced *before* it dies, and the proof that
/// it is is that a token near its end is not served.
#[tokio::test]
async fn a_token_close_to_expiry_is_replaced_before_it_dies() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    let issued = std::sync::atomic::AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |_: &Request| {
            let n = issued.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // The first token has ten seconds left the moment it arrives,
            // which is inside any sane skew; the second is a full lifetime.
            let lifetime = if n == 0 { 10 } else { 300 };
            ResponseTemplate::new(200).set_body_json(token_body(
                &format!("at-{n}"),
                &format!("rt-{n}"),
                lifetime,
            ))
        })
        .mount(&server)
        .await;

    let enrolled = enrol(&server.uri(), "rt-start").await;
    let manager = manager(&server, &enrolled).await;

    assert_eq!(manager.access_token().await.expect("first"), "at-0");
    assert_eq!(
        manager.access_token().await.expect("second"),
        "at-1",
        "a token inside the refresh skew must not be handed out"
    );
    assert_eq!(manager.access_token().await.expect("third"), "at-1", "and then it is cached");
}

/// Rotation is only safe if it is durable. A manager that refreshed and kept
/// the new token in memory would present a dead one after any restart -- and
/// presenting a dead refresh token is not a harmless 400, it fires the reuse
/// defence and takes the grant down.
#[tokio::test]
async fn a_rotated_refresh_token_is_persisted_before_the_access_token_is_returned() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=rt-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_body("at-1", "rt-2", 300)))
        .mount(&server)
        .await;

    let enrolled = enrol(&server.uri(), "rt-1").await;
    let manager = manager(&server, &enrolled).await;
    manager.access_token().await.expect("refresh");

    assert_eq!(
        enrolled.store.load().expect("load").expect("enrolled").refresh_token(),
        "rt-2",
        "the rotated token must be on disk, not only in memory"
    );
}

/// The daemon's reason for `Detach` to exist at all: its essential-task
/// supervisor (`yadorilink-daemon::supervise::EssentialTasks::shutdown`)
/// aborts every other essential task the instant one of them fails, and a
/// refresh can be running inline inside one of them when that happens.
///
/// This proves the property a real `tokio::spawn`-backed `Detach` (exactly
/// what the daemon installs) has to have: once the server has answered and
/// rotated the token, aborting the task that asked for the refresh must not
/// stop the write. A rendezvous rather than a sleep, for the same reason
/// `tests/cross_process_rotation.rs` uses one -- the property under test is an
/// exact interleaving (abort lands *after* the closure has started, *before*
/// it finishes), and a sleep-based approximation would only assert "usually".
#[tokio::test]
async fn aborting_the_caller_after_the_server_rotates_does_not_stop_the_persist_it_started() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=rt-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_body("at-1", "rt-2", 300)))
        .mount(&server)
        .await;

    let enrolled = enrol(&server.uri(), "rt-1").await;

    let started = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());
    let finished = Arc::new(tokio::sync::Notify::new());
    let (started_in_task, proceed_in_task, finished_in_task) =
        (started.clone(), proceed.clone(), finished.clone());
    let detach: yadorilink_fapi_client::Detach = Arc::new(move |work| {
        let (started, proceed, finished) =
            (started_in_task.clone(), proceed_in_task.clone(), finished_in_task.clone());
        // The real `Detach` the daemon installs, plus a gate around the
        // closure so the test controls exactly when it runs relative to the
        // abort below.
        tokio::spawn(async move {
            started.notify_one();
            proceed.notified().await;
            work();
            finished.notify_one();
        });
    });
    let manager = Arc::new(manager(&server, &enrolled).await.with_detach(detach));

    let refreshing = manager.clone();
    let handle = tokio::spawn(async move { refreshing.access_token().await });

    // The server has answered by the time this returns: `refresh_now` cannot
    // reach `self.detach` without the network round trip -- and therefore the
    // rotation -- already having completed.
    started.notified().await;

    handle.abort();
    let outcome = handle.await;
    assert!(outcome.unwrap_err().is_cancelled(), "the caller was not actually aborted");

    // Only now does the detached write run -- proving it survived an abort
    // that landed while it was still pending, not merely one that landed
    // before it was spawned.
    proceed.notify_one();
    finished.notified().await;

    assert_eq!(
        enrolled.store.load().expect("load").expect("enrolled").refresh_token(),
        "rt-2",
        "the server already killed rt-1; losing rt-2 as well because the caller was aborted \
         would strand this installation with no live refresh token at all"
    );
}

/// The reason the store is re-read inside the lock rather than cached. If
/// another process rotated while this one was idle, the value in memory is
/// dead and presenting it revokes the family.
#[tokio::test]
async fn a_refresh_presents_the_stored_token_rather_than_the_one_it_started_with() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=rt-rotated-by-the-other-process"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_body("at-1", "rt-3", 300)))
        .mount(&server)
        .await;

    let enrolled = enrol(&server.uri(), "rt-1").await;
    let manager = manager(&server, &enrolled).await;

    // What the other process did between this manager being built and its
    // first refresh.
    let lock = enrolled.store.lock(Duration::from_secs(5)).await.expect("lock");
    enrolled
        .store
        .rotate_refresh_token(&lock, "ylk-test-installation", "rt-rotated-by-the-other-process")
        .expect("rotate");
    drop(lock);

    assert_eq!(manager.access_token().await.expect("refresh"), "at-1");
}

/// A refresh token carries no DPoP binding (measured), which is
/// what lets the DPoP key be per-process. Asserted rather than relied on: this
/// pins that the client really does present a key the grant has never seen,
/// so the day the server starts binding refresh tokens this fails here rather
/// than in a daemon that silently cannot restart.
#[tokio::test]
async fn refreshing_happens_under_a_dpop_key_the_grant_has_never_seen() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let recorder = seen.clone();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |request: &Request| {
            let mut seen = recorder.lock().expect("lock");
            seen.push(proof_jkt(request));
            // A new refresh token on every call, because that is what the
            // server does and what the client now requires: answering with the
            // token that was just presented is refused as a failure to rotate.
            let issued = seen.len() + 1;
            ResponseTemplate::new(200).set_body_json(token_body(
                &format!("at-{issued}"),
                &format!("rt-{issued}"),
                300,
            ))
        })
        .mount(&server)
        .await;

    let enrolled = enrol(&server.uri(), "rt-1").await;

    // Two processes, one after the other, over one stored credential: the
    // shape of a daemon restart.
    let first = manager(&server, &enrolled).await;
    first.access_token().await.expect("first process");
    let second = manager(&server, &enrolled).await;
    second.force_refresh().await.expect("second process");

    let keys = seen.lock().expect("lock").clone();
    assert_eq!(keys.len(), 2);
    assert_ne!(
        keys[0], keys[1],
        "each process must prove a fresh DPoP key; a persisted one is a credential at rest for \
         no benefit"
    );
    assert_eq!(keys[1], second.client().dpop_jkt());
}

/// The store never grows a DPoP key. If it did, the key would be a persisted
/// credential whose loss is not a revocation and whose theft is not detectable
/// -- all cost, no defence.
#[tokio::test]
async fn no_dpop_key_and_no_access_token_ever_reach_the_store() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_body(
            "at-secret-value",
            "rt-2",
            300,
        )))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("credentials.json");
    let store = Arc::new(CredentialStore::with_backend(Backend::File(path.clone()), dir.path()));
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
        .expect("save");
    drop(lock);

    let manager = CredentialManager::restore(reqwest::Client::new(), &server.uri(), store)
        .await
        .expect("restore");
    manager.access_token().await.expect("refresh");

    let document = std::fs::read_to_string(&path).expect("read the store back");
    assert!(!document.contains("at-secret-value"), "the access token was persisted");
    assert!(!document.contains(&manager.client().dpop_jkt()), "the DPoP key was persisted");
}

/// Two processes, one credential. The lock is what stops them spending the
/// same refresh token, which the server answers by revoking the whole family.
#[tokio::test]
async fn a_second_process_cannot_refresh_while_the_first_holds_the_rotation_lock() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_a = CredentialStore::with_backend(
        Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    );
    let store_b = CredentialStore::with_backend(
        Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    );

    let held = store_a.lock(Duration::from_secs(5)).await.expect("first acquire");
    let err = store_b
        .lock(Duration::from_millis(200))
        .await
        .expect_err("the second must refuse rather than refresh alongside the first");
    assert!(matches!(err, yadorilink_fapi_client::StoreError::LockTimeout { .. }), "got {err}");

    drop(held);
    store_b.lock(Duration::from_millis(500)).await.expect("released");
}

/// Being unable to take the lock is a refusal, not a shrug. Refreshing anyway
/// is precisely the case that destroys the grant.
#[tokio::test]
async fn a_refresh_that_cannot_take_the_lock_fails_rather_than_proceeding_without_it() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_body("at-1", "rt-2", 300)))
        .expect(0)
        .mount(&server)
        .await;

    let enrolled = enrol(&server.uri(), "rt-1").await;
    let manager = manager(&server, &enrolled).await.with_lock_timeout(Duration::from_millis(100));

    let _held = enrolled.store.lock(Duration::from_secs(5)).await.expect("the other process");
    let err = manager.access_token().await.expect_err("the lock is held elsewhere");
    assert!(matches!(err, Error::Store(_)), "got {err}");
}

#[tokio::test]
async fn a_store_holding_nothing_is_reported_as_not_enrolled_rather_than_as_a_failure_later() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Arc::new(CredentialStore::with_backend(
        Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    ));

    let err = CredentialManager::restore(reqwest::Client::new(), &server.uri(), store)
        .await
        .expect_err("nothing is enrolled");
    assert!(matches!(err, Error::NotEnrolled), "got {err}");
}

/// A credential store copied between deployments authenticates against
/// nothing. The failure has to name both issuers, or it reads as a broken key.
#[tokio::test]
async fn a_credential_from_a_different_deployment_is_refused_by_name() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    let enrolled = enrol("https://some-other-deployment.test", "rt-1").await;

    let err =
        CredentialManager::restore(reqwest::Client::new(), &server.uri(), enrolled.store.clone())
            .await
            .expect_err("a credential for another issuer");
    let rendered = err.to_string();
    assert!(rendered.contains("some-other-deployment.test"), "got {rendered}");
    assert!(rendered.contains(&server.uri()), "got {rendered}");
}

// --- the RFC 8628 device grant ----------------------------------------------

#[tokio::test]
async fn a_device_grant_polls_past_pending_and_slow_down_to_a_token() {
    let server = MockServer::start().await;
    serve_discovery(&server, true).await;
    Mock::given(method("POST"))
        .and(path("/device/auth"))
        .and(body_string_contains("client_assertion_type"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "dc-1",
            "user_code": "BCDF-GHJK-LMNP",
            "verification_uri": format!("{}/device", server.uri()),
            "verification_uri_complete": format!("{}/device?user_code=BCDF-GHJK-LMNP", server.uri()),
            "expires_in": 600,
            "interval": 1,
        })))
        .mount(&server)
        .await;

    let polls = std::sync::atomic::AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |_: &Request| {
            match polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                0 => ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "authorization_pending"})),
                1 => ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "slow_down"})),
                _ => ResponseTemplate::new(200).set_body_json(token_body(
                    "at-device",
                    "rt-device",
                    300,
                )),
            }
        })
        .mount(&server)
        .await;

    let client = FapiClient::discover(
        reqwest::Client::new(),
        &server.uri(),
        "ylk-test-installation",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .await
    .expect("discover");

    assert!(client.metadata().supports_device_grant());
    let authorization =
        client.request_device_authorization("openid offline_access").await.expect("device auth");
    let printed = authorization.instructions();
    assert!(printed.contains("BCDF-GHJK-LMNP"));
    assert!(
        printed.contains(&format!("{}/device?user_code=BCDF-GHJK-LMNP", server.uri())),
        "the completed verification URI the server sent must be the printed link: {printed}"
    );

    let tokens = client.complete_device_authorization(&authorization).await.expect("granted");
    assert_eq!(tokens.access_token(), "at-device");
    assert_eq!(tokens.refresh_token(), "rt-device");
}

/// `access_denied` and `expired_token` are terminal. Treating them as pending
/// would poll a dead code until its ten minutes ran out and then report the
/// wrong reason.
#[tokio::test]
async fn a_denied_device_authorization_stops_rather_than_polling_on() {
    let server = MockServer::start().await;
    serve_discovery(&server, true).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(serde_json::json!({"error": "access_denied"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = FapiClient::discover(
        reqwest::Client::new(),
        &server.uri(),
        "ylk-test-installation",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .await
    .expect("discover");

    let err = client.poll_device_authorization("dc-1").await.expect_err("denied");
    assert_eq!(err.oauth_error(), Some("access_denied"));
}

#[tokio::test]
async fn a_deployment_without_the_device_grant_says_so_rather_than_guessing_the_path() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    let client = FapiClient::discover(
        reqwest::Client::new(),
        &server.uri(),
        "ylk-test-installation",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .await
    .expect("discover");

    assert!(!client.metadata().supports_device_grant());
    let err = client
        .request_device_authorization("openid offline_access")
        .await
        .expect_err("no device endpoint");
    assert!(matches!(err, Error::MissingMetadata("device_authorization_endpoint")), "got {err}");
}

#[tokio::test]
async fn a_device_poll_is_refused_when_it_carries_no_proof_of_possession() {
    let server = MockServer::start().await;
    serve_discovery(&server, true).await;
    let seen = Arc::new(std::sync::Mutex::new(Option::<String>::None));
    let recorder = seen.clone();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |request: &Request| {
            *recorder.lock().expect("lock") = Some(proof_jkt(request));
            ResponseTemplate::new(200).set_body_json(token_body("at-device", "rt-device", 300))
        })
        .mount(&server)
        .await;

    let dpop_key = Es256Key::generate();
    let expected = dpop_key.jkt();
    let client = FapiClient::discover(
        reqwest::Client::new(),
        &server.uri(),
        "ylk-test-installation",
        Es256Key::generate(),
        dpop_key,
    )
    .await
    .expect("discover");

    client.poll_device_authorization("dc-1").await.expect("granted");
    assert_eq!(
        seen.lock().expect("lock").clone(),
        Some(expected),
        "the registration sets dpop_bound_access_tokens, so a poll with no proof is refused by \
         the server; the client must always send one"
    );
}

// --- discovery ---------------------------------------------------------------

/// Without this check at discovery, every capability mismatch would surface
/// as an opaque 400 several requests later.
#[tokio::test]
async fn a_server_this_client_cannot_use_is_refused_at_discovery() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let mut document = metadata(&issuer, false);
    document["token_endpoint_auth_methods_supported"] = serde_json::json!(["client_secret_basic"]);
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document))
        .mount(&server)
        .await;

    let err = FapiClient::discover(
        reqwest::Client::new(),
        &server.uri(),
        "ylk-test-installation",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .await
    .expect_err("this client cannot authenticate against that server");
    assert!(matches!(err, Error::UnsupportedServer(_)), "got {err}");
    assert!(err.to_string().contains("private_key_jwt"), "got {err}");
}

// --- a crash between the server's rotation and the durable write ------------

/// The server rotates the token and the process dies before its write lands, so
/// the disk still holds the token the server just retired. Nothing the dying
/// process does can prevent that; what the restarted one does must be
/// ordinary: present what the disk holds. The server accepts a re-presented
/// token for a short window while its successor has gone unused, so the
/// restarted client needs no recovery code of its own -- and, because every
/// process uses a fresh DPoP key, the contract cannot depend on the key that
/// obtained the token.
#[tokio::test]
async fn a_restart_after_a_lost_rotation_response_recovers_by_presenting_what_the_disk_holds() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    let presentations = std::sync::atomic::AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=rt-1"))
        .respond_with(move |_: &Request| {
            // First presentation rotates to rt-2; a re-presentation inside the
            // server's recovery window replaces the unconfirmed rt-2.
            let n = presentations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let successor = if n == 0 { "rt-2" } else { "rt-2-recovered" };
            ResponseTemplate::new(200).set_body_json(token_body("at", successor, 300))
        })
        .mount(&server)
        .await;

    let enrolled = enrol(&server.uri(), "rt-1").await;

    // The first process: the server answers, and the process dies before the
    // write. A `Detach` that never runs the closure is that death -- the
    // closure is dropped, the manager's own contract violation panics the
    // task, and the disk is untouched.
    let doomed: yadorilink_fapi_client::Detach = Arc::new(drop);
    let first = Arc::new(manager(&server, &enrolled).await.with_detach(doomed));
    let died = tokio::spawn(async move { first.access_token().await }).await;
    assert!(died.is_err(), "the first process did not die before persisting");
    assert_eq!(
        enrolled.store.load().expect("load").expect("enrolled").refresh_token(),
        "rt-1",
        "the write never happened, so the disk holds the retired token"
    );

    // The restart: a fresh manager, hence a fresh DPoP key, doing the ordinary
    // thing.
    let restarted = manager(&server, &enrolled).await;
    assert_eq!(restarted.access_token().await.expect("recovery refresh"), "at");
    assert_eq!(
        enrolled.store.load().expect("load").expect("enrolled").refresh_token(),
        "rt-2-recovered",
        "a recovery response is persisted exactly like a normal rotation"
    );

    let requests = server.received_requests().await.expect("recorded");
    let proofs: Vec<String> =
        requests.iter().filter(|r| r.url.path() == "/token").map(proof_jkt).collect();
    assert_eq!(proofs.len(), 2);
    assert_ne!(proofs[0], proofs[1], "each process proves its own DPoP key");
}

/// There is no retry loop to storm with: a failed refresh is one request, the
/// store is untouched, and the caller's next attempt presents the same token --
/// which the server's recovery window makes safe to re-present.
#[tokio::test]
async fn a_failed_refresh_is_one_request_and_leaves_the_stored_token_to_be_presented_again() {
    let server = MockServer::start().await;
    serve_discovery(&server, false).await;
    let attempts = std::sync::atomic::AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=rt-1"))
        .respond_with(move |_: &Request| {
            if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_json(token_body("at-1", "rt-2", 300))
            }
        })
        .mount(&server)
        .await;

    let enrolled = enrol(&server.uri(), "rt-1").await;
    let manager = manager(&server, &enrolled).await;

    assert!(manager.access_token().await.is_err());
    let after_failure = server.received_requests().await.expect("recorded");
    assert_eq!(
        after_failure.iter().filter(|r| r.url.path() == "/token").count(),
        1,
        "one failed refresh must be one request"
    );
    assert_eq!(enrolled.store.load().expect("load").expect("enrolled").refresh_token(), "rt-1");

    assert_eq!(manager.access_token().await.expect("second attempt"), "at-1");
    assert_eq!(enrolled.store.load().expect("load").expect("enrolled").refresh_token(), "rt-2");
}
