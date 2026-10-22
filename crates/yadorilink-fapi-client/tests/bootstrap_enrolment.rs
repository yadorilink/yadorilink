//! The client half of the fresh-install bootstrap transaction.
//!
//! What is asserted here is what this PROCESS does with the server's answers:
//! that it sends only the public key, that it never sends the handle anywhere
//! but the poll, that it treats `authorization_pending` as "keep waiting" and
//! anything else as a failure, that it stops on the server's own deadline, and
//! that it refuses a registration carrying an upstream credential.
//!
//! What is NOT asserted here is the server's half -- the single consume, the
//! indistinguishable poll, the key that was captured at `start`. Those are
//! properties of the Worker and are asserted against the real Worker in
//! the coordination service; a mock server here
//! could only re-state this crate's guess about them. The two halves meet on a
//! real wire in the CLI's coordination wire-contract test.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};
use yadorilink_fapi_client::{
    complete_enrolment, open_enrolment, poll_enrolment, EnrolmentPoll, EnrolmentRequest, Error,
    Es256Key, PendingEnrolment,
};

const CLIENT_ID: &str = "ylk-AAAAAAAAAAAAAAAAAAAAAA";

fn loopback() -> Vec<String> {
    vec!["http://127.0.0.1:41234/callback".to_owned()]
}

fn request<'a>(uris: &'a [String]) -> EnrolmentRequest<'a> {
    EnrolmentRequest { redirect_uris: uris, client_name: Some("laptop") }
}

fn started(handle: &str) -> serde_json::Value {
    serde_json::json!({
        "bootstrap_handle": handle,
        "approval_uri": "https://as.test/bootstrap/approve?code=a-different-secret",
        "expires_in": 600,
        "poll_interval_seconds": 5,
    })
}

/// `open_enrolment` now reads the issuer off this deployment's own discovery
/// document before it does anything else, so every test that opens a
/// transaction against a mock server has to serve one. Defaults the issuer to
/// the mock server's own address, which is what every test that is not
/// specifically about the issuer/socket split wants.
async fn mount_discovery(server: &MockServer) {
    mount_discovery_as(server, &server.uri()).await;
}

/// Same as [`mount_discovery`], but with an issuer that is NOT the socket --
/// for the one test that exercises the split a loopback deployment relies on.
async fn mount_discovery_as(server: &MockServer, issuer: &str) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "issuer": issuer })),
        )
        .mount(server)
        .await;
}

/// A sleep that records what it was asked to wait for and returns at once, so
/// the polling loop's own deadline is assertable without spending it.
fn recording_sleep(
    log: Arc<Mutex<Vec<Duration>>>,
) -> impl FnMut(Duration) -> std::future::Ready<()> {
    move |waited| {
        log.lock().expect("lock").push(waited);
        std::future::ready(())
    }
}

async fn open_against(server: &MockServer, key: &Es256Key) -> PendingEnrolment {
    let uris = loopback();
    open_enrolment(&reqwest::Client::new(), &server.uri(), key, &request(&uris))
        .await
        .expect("the transaction opens")
}

// --- opening a transaction ---------------------------------------------------

#[tokio::test]
async fn opening_a_transaction_sends_the_public_key_and_no_credential_at_all() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let seen = Arc::new(Mutex::new(serde_json::Value::Null));
    let headers = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorder = seen.clone();
    let header_recorder = headers.clone();
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(move |request: &Request| {
            *recorder.lock().expect("lock") = request.body_json().expect("JSON body");
            *header_recorder.lock().expect("lock") =
                request.headers.keys().map(|name| name.as_str().to_ascii_lowercase()).collect();
            ResponseTemplate::new(201).set_body_json(started("f".repeat(64).as_str()))
        })
        .mount(&server)
        .await;

    let key = Es256Key::generate();
    let pending = open_against(&server, &key).await;

    assert_eq!(pending.expires_in, Duration::from_secs(600));
    assert_eq!(pending.poll_interval, Duration::from_secs(5));
    assert_eq!(pending.approval_uri, "https://as.test/bootstrap/approve?code=a-different-secret");

    let body = seen.lock().expect("lock").clone();
    assert_eq!(body["jwks"]["keys"][0]["kty"], "EC");
    assert_eq!(body["jwks"]["keys"][0]["crv"], "P-256");
    assert!(body["jwks"]["keys"][0].get("d").is_none(), "the private half was sent");
    assert_eq!(body["redirect_uris"][0], "http://127.0.0.1:41234/callback");
    // The body carries a key and a redirect. Nothing else: there is no identity
    // proof member any more, and a request that offered one would be asking the
    // server to accept an upstream token from a caller.
    let members: Vec<&String> =
        body.as_object().expect("object").keys().filter(|k| !body[*k].is_null()).collect();
    assert_eq!(members.len(), 3, "unexpected members in the start body: {body}");

    // And no credential rides on the request either. This is the one endpoint
    // in the whole system that an installation with nothing reaches, so an
    // `authorization` header here would mean it is not that endpoint.
    let sent = headers.lock().expect("lock").clone();
    assert!(!sent.iter().any(|name| name == "authorization"), "sent {sent:?}");
}

/// The server's refusal names which piece of metadata it rejected, and that is
/// the only useful thing in the body. It has to survive to the caller, and it
/// has to arrive at `start` -- before a human has been sent anywhere.
#[tokio::test]
async fn a_key_set_the_server_refuses_fails_at_the_start_rather_than_after_a_human_is_involved() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_redirect_uri",
            "error_description": "redirect_uris may only be loopback URIs",
        })))
        .mount(&server)
        .await;

    let uris = vec!["https://example.test/callback".to_owned()];
    let err = open_enrolment(
        &reqwest::Client::new(),
        &server.uri(),
        &Es256Key::generate(),
        &request(&uris),
    )
    .await
    .expect_err("a non-loopback redirect is refused");
    assert_eq!(err.oauth_error(), Some("invalid_redirect_uri"));
    assert_eq!(err.status(), Some(400));
}

/// A transaction with no life left is a loop that will only ever print "still
/// waiting". Saying so at the start is the difference between a clear failure
/// and ten minutes of nothing.
#[tokio::test]
async fn a_transaction_that_is_already_dead_is_refused_rather_than_polled() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let mut body = started(&"f".repeat(64));
    body["expires_in"] = serde_json::json!(0);
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(ResponseTemplate::new(201).set_body_json(body))
        .mount(&server)
        .await;

    let uris = loopback();
    let err = open_enrolment(
        &reqwest::Client::new(),
        &server.uri(),
        &Es256Key::generate(),
        &request(&uris),
    )
    .await
    .expect_err("a dead transaction must not be returned as an open one");
    assert!(matches!(err, Error::Registration(_)), "got {err}");
}

// --- collecting the registration --------------------------------------------

#[tokio::test]
async fn the_handle_is_presented_only_to_the_poll_and_never_appears_anywhere_else() {
    let handle = "d".repeat(64);
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let start_bodies = Arc::new(Mutex::new(String::new()));
    let recorder = start_bodies.clone();
    let handle_for_start = handle.clone();
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(move |request: &Request| {
            *recorder.lock().expect("lock") = String::from_utf8_lossy(&request.body).into_owned();
            ResponseTemplate::new(201).set_body_json(started(&handle_for_start))
        })
        .mount(&server)
        .await;

    let polled = Arc::new(Mutex::new(serde_json::Value::Null));
    let poll_recorder = polled.clone();
    Mock::given(method("POST"))
        .and(path("/bootstrap/poll"))
        .respond_with(move |request: &Request| {
            *poll_recorder.lock().expect("lock") = request.body_json().expect("JSON body");
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "client_id": CLIENT_ID }))
        })
        .mount(&server)
        .await;

    let key = Es256Key::generate();
    let pending = open_against(&server, &key).await;

    // The handle came back from `start`; it was not in what was sent there.
    assert!(!start_bodies.lock().expect("lock").contains(&handle));
    // It is not reachable as a field, and it is not in the Debug rendering, so
    // the only way it leaves this process is the poll below.
    assert!(!format!("{pending:?}").contains(&handle), "{pending:?}");

    let registration = match poll_enrolment(&reqwest::Client::new(), &pending, &key).await {
        Ok(EnrolmentPoll::Registered(registration)) => registration,
        other => panic!("expected a registration, got {other:?}"),
    };
    assert_eq!(registration.client_id, CLIENT_ID);
    assert_eq!(polled.lock().expect("lock")["bootstrap_handle"], serde_json::json!(handle));
}

/// Every poll carries a fresh, key-bound proof alongside the handle -- not
/// merely the handle by itself. What the SERVER does with it (refuse a
/// mismatched key, refuse a stolen handle with no key at all) is asserted in
/// the coordination service, per this file's own
/// header; what this client controls is that the proof is sent at all, that
/// it names the pending key, and that two polls do not resend the same one.
#[tokio::test]
async fn every_poll_carries_a_fresh_proof_signed_by_the_pending_key() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(ResponseTemplate::new(201).set_body_json(started(&"9".repeat(64))))
        .mount(&server)
        .await;

    let bodies = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let recorder = bodies.clone();
    Mock::given(method("POST"))
        .and(path("/bootstrap/poll"))
        .respond_with(move |request: &Request| {
            recorder.lock().expect("lock").push(request.body_json().expect("JSON body"));
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": "authorization_pending" }))
        })
        .mount(&server)
        .await;

    let key = Es256Key::generate();
    let pending = open_against(&server, &key).await;

    poll_enrolment(&reqwest::Client::new(), &pending, &key).await.expect("poll");
    poll_enrolment(&reqwest::Client::new(), &pending, &key).await.expect("poll");

    let seen = bodies.lock().expect("lock").clone();
    assert_eq!(seen.len(), 2);
    let proofs: Vec<&str> =
        seen.iter().map(|b| b["proof"].as_str().expect("a proof string")).collect();
    assert_ne!(proofs[0], proofs[1], "each poll must mint a fresh proof rather than resend one");

    for proof in proofs {
        let segments: Vec<&str> = proof.split('.').collect();
        assert_eq!(segments.len(), 3, "a compact JWS is three segments: {proof}");
        use base64::Engine as _;
        let decode = |segment: &str| -> serde_json::Value {
            serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(segment)
                    .expect("base64url"),
            )
            .expect("JSON")
        };
        let header = decode(segments[0]);
        assert_eq!(header["typ"], "bootstrap-poll+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(
            header["jwk"]["x"],
            key.public_jwk().x,
            "the proof must be signed by the key this transaction was opened with"
        );

        // Bound to one operation at one deployment, exactly as a DPoP proof
        // is: a proof minted for this poll verifies at no other endpoint.
        let claims = decode(segments[1]);
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], format!("{}/bootstrap/poll", server.uri()));
    }
}

/// The socket a poll is actually sent to and the issuer its proof's `htu` is
/// signed against are two different things, exactly as they are for a real
/// DPoP proof: a loopback development deployment dials a local socket while
/// the issuer stays the deployed hostname. If the proof signed the SOCKET
/// instead, a captured handle-and-proof pair relayed to a different endpoint
/// that merely resolves the same way would still verify there; binding to the
/// issuer is what makes the proof mean nothing anywhere but the deployment
/// that captured this transaction's key.
#[tokio::test]
async fn the_proof_binds_htu_to_the_discovered_issuer_rather_than_the_socket_dialed() {
    let server = MockServer::start().await;
    let issuer = "https://deployed.example";
    mount_discovery_as(&server, issuer).await;
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(ResponseTemplate::new(201).set_body_json(started(&"7".repeat(64))))
        .mount(&server)
        .await;

    let polled = Arc::new(Mutex::new(serde_json::Value::Null));
    let recorder = polled.clone();
    Mock::given(method("POST"))
        .and(path("/bootstrap/poll"))
        .respond_with(move |request: &Request| {
            *recorder.lock().expect("lock") = request.body_json().expect("JSON body");
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": "authorization_pending" }))
        })
        .mount(&server)
        .await;

    let key = Es256Key::generate();
    let pending = open_against(&server, &key).await;
    poll_enrolment(&reqwest::Client::new(), &pending, &key).await.expect("poll");

    let proof = polled.lock().expect("lock")["proof"].as_str().expect("a proof string").to_owned();
    use base64::Engine as _;
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(proof.split('.').nth(1).expect("a JWS payload"))
            .expect("base64url"),
    )
    .expect("JSON claims");
    assert_eq!(claims["htu"], format!("{issuer}/bootstrap/poll"));
    assert_ne!(
        claims["htu"].as_str().expect("a string"),
        format!("{}/bootstrap/poll", server.uri()),
        "the proof must not have signed the socket it happened to dial"
    );
}

/// `authorization_pending` is the server's one answer for unknown, pending,
/// expired and already-redeemed. A client that treated it as a failure would
/// give up the moment it started; one that treated any 400 as pending would
/// loop through a real refusal until the deadline.
#[tokio::test]
async fn only_authorization_pending_means_keep_waiting() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(ResponseTemplate::new(201).set_body_json(started(&"a".repeat(64))))
        .mount(&server)
        .await;

    let attempt = Arc::new(AtomicUsize::new(0));
    let counter = attempt.clone();
    Mock::given(method("POST"))
        .and(path("/bootstrap/poll"))
        .respond_with(move |_: &Request| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "authorization_pending",
                "error_description": "this bootstrap transaction has not been approved",
            })),
            _ => ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "something else entirely",
            })),
        })
        .mount(&server)
        .await;

    let key = Es256Key::generate();
    let pending = open_against(&server, &key).await;

    assert!(matches!(
        poll_enrolment(&reqwest::Client::new(), &pending, &key).await,
        Ok(EnrolmentPoll::Pending)
    ));

    let err = poll_enrolment(&reqwest::Client::new(), &pending, &key)
        .await
        .expect_err("a refusal that is not `authorization_pending` is a failure");
    assert_eq!(err.oauth_error(), Some("invalid_request"));
}

#[tokio::test]
async fn the_loop_waits_at_the_advertised_interval_and_stops_at_the_advertised_deadline() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    let mut body = started(&"b".repeat(64));
    body["expires_in"] = serde_json::json!(30);
    body["poll_interval_seconds"] = serde_json::json!(10);
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(ResponseTemplate::new(201).set_body_json(body))
        .mount(&server)
        .await;

    let polls = Arc::new(AtomicUsize::new(0));
    let counter = polls.clone();
    Mock::given(method("POST"))
        .and(path("/bootstrap/poll"))
        .respond_with(move |_: &Request| {
            counter.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": "authorization_pending" }))
        })
        .mount(&server)
        .await;

    let key = Es256Key::generate();
    let pending = open_against(&server, &key).await;

    let waits = Arc::new(Mutex::new(Vec::new()));
    let err =
        complete_enrolment(&reqwest::Client::new(), &pending, &key, recording_sleep(waits.clone()))
            .await
            .expect_err("an enrolment nobody approves has to end");

    // 30 seconds of life at 10-second intervals: three attempts, two waits.
    assert_eq!(polls.load(Ordering::SeqCst), 3);
    assert_eq!(*waits.lock().expect("lock"), vec![Duration::from_secs(10); 2]);
    assert!(
        matches!(&err, Error::Registration(message) if message.contains("30 seconds")),
        "the failure must name the deadline it hit: {err}"
    );
}

#[tokio::test]
async fn an_approval_that_arrives_mid_loop_ends_it_with_the_registration() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(ResponseTemplate::new(201).set_body_json(started(&"c".repeat(64))))
        .mount(&server)
        .await;

    let attempt = Arc::new(AtomicUsize::new(0));
    let counter = attempt.clone();
    Mock::given(method("POST"))
        .and(path("/bootstrap/poll"))
        .respond_with(move |_: &Request| {
            if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({ "error": "authorization_pending" }))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "client_id": CLIENT_ID,
                    "token_endpoint_auth_method": "private_key_jwt",
                    "dpop_bound_access_tokens": true,
                }))
            }
        })
        .mount(&server)
        .await;

    let key = Es256Key::generate();
    let pending = open_against(&server, &key).await;

    let waits = Arc::new(Mutex::new(Vec::new()));
    let registration =
        complete_enrolment(&reqwest::Client::new(), &pending, &key, recording_sleep(waits.clone()))
            .await
            .expect("the approval completes the enrolment");

    assert_eq!(registration.client_id, CLIENT_ID);
    assert_eq!(registration.metadata["token_endpoint_auth_method"], "private_key_jwt");
    // It stopped the moment it had an answer rather than running to the
    // deadline, and it did not poll again afterwards.
    assert_eq!(attempt.load(Ordering::SeqCst), 3);
    assert_eq!(waits.lock().expect("lock").len(), 2);
}

// --- what a registration may not contain ------------------------------------

/// The architecture says this client has no secret, and the server asserts it
/// twice. A third assertion here makes the claim true of what this process
/// actually holds -- and a secret that arrived is refused rather than stored,
/// because storing it is what would make it real.
#[tokio::test]
async fn a_registration_that_comes_back_with_a_secret_is_refused_rather_than_stored() {
    let err = collected(serde_json::json!({
        "client_id": CLIENT_ID,
        "client_secret": "this must never be accepted",
    }))
    .await
    .expect_err("a secret must be refused");
    assert!(matches!(err, Error::Registration(_)), "got {err}");
}

/// The whole reason the identity leg moved into a browser on the server's side
/// is that no upstream artefact reaches this process. If one ever does, the
/// enrolment is refused here rather than written to the credential store, where
/// it would then be a thing this machine holds.
#[tokio::test]
async fn a_registration_carrying_an_upstream_credential_is_refused() {
    for forbidden in ["id_token", "access_token", "refresh_token"] {
        let err = collected(serde_json::json!({
            "client_id": CLIENT_ID,
            forbidden: "an upstream artefact that must not be here",
        }))
        .await
        .unwrap_err();
        assert!(
            matches!(&err, Error::Registration(message) if message.contains(forbidden)),
            "{forbidden}: got {err}"
        );
    }
}

/// A 200 with no `client_id` is not an enrolment, however well-formed the JSON
/// is. Reported as a missing member rather than as an empty `client_id` that
/// would be written to the store and fail at the next request.
#[tokio::test]
async fn a_registration_with_no_client_id_is_refused() {
    let err = collected(serde_json::json!({ "token_endpoint_auth_method": "private_key_jwt" }))
        .await
        .expect_err("a registration with no client_id is not one");
    assert!(matches!(err, Error::MissingMetadata("client_id")), "got {err}");
}

/// Runs one poll that answers 200 with `body`, and reports what this client did
/// with it.
async fn collected(body: serde_json::Value) -> Result<(), Error> {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    Mock::given(method("POST"))
        .and(path("/bootstrap/start"))
        .respond_with(ResponseTemplate::new(201).set_body_json(started(&"e".repeat(64))))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/bootstrap/poll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let key = Es256Key::generate();
    let pending = open_against(&server, &key).await;
    poll_enrolment(&reqwest::Client::new(), &pending, &key).await.map(|_| ())
}
