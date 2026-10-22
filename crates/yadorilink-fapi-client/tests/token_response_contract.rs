//! What this client accepts as a token response, and what it refuses.
//!
//! # The property
//!
//! A 200 from the token endpoint is not the same thing as a usable credential.
//! This client talks to one Authorization Server whose token responses have a
//! known shape, so every field this file requires is a field the real server
//! already sends. Accepting less does not buy interoperability with anything
//! that exists; it buys a broken session that reports success.
//!
//! Three requirements, each of which was a tolerance before this file:
//!
//! * **`token_type` must be `DPoP`.** It was carried as an unread `String`. A
//!   server answering `Bearer` is a server that did not sender-constrain the
//!   token, and this client would have gone on presenting it with an
//!   `Authorization: DPoP` header and a proof -- succeeding only because the
//!   resource server happened to be stricter than the client.
//! * **`expires_in` must be present and non-zero.** It was `Option<u64>`, and
//!   `None` meant "assume sixty seconds". That assumption is a guess about the
//!   lifetime of a credential, made by the party that does not get to decide
//!   it.
//! * **every refresh response must carry a *rotated* refresh token.** This was
//!   the expensive one. A refresh response with no new refresh token logged a
//!   warning, left the already-spent token in the store, and returned the
//!   access token anyway -- so a session that was already dead reported success
//!   and bought five more minutes before failing somewhere else entirely. A
//!   response that returns the *same* refresh token is the same defect wearing
//!   a different shape: this server rotates, and a repeated token means the one
//!   in the store is spent.
//!
//! # Where the refusal has to happen
//!
//! At the client, on the response, before the value exists. A validated
//! `TokenResponse` is the only way to hold one, its fields are private, and
//! there is no constructor outside this crate -- so "a token response that was
//! never checked" is not a value a caller can be handed and not a value a
//! caller can build.

mod as_profile;

use std::sync::Arc;

use as_profile::accepted_server;
use serde_json::{json, Value};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_fapi_client::store::{Backend, CredentialStore, Credentials};
use yadorilink_fapi_client::{Error, Es256Key, FapiClient};

/// The token response the deployed server actually sends.
fn good_token_response() -> Value {
    json!({
        "access_token": "at-1",
        "token_type": "DPoP",
        "expires_in": 300,
        "refresh_token": "rt-1",
        "scope": "openid offline_access",
    })
}

/// Answer `POST /token` with `edit(good_token_response())`.
async fn serve_token(server: &MockServer, edit: impl FnOnce(&mut Value)) {
    let mut body = good_token_response();
    edit(&mut body);
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// Refresh `rt-0` against a server answering with a doctored token response.
async fn refresh_with(edit: impl FnOnce(&mut Value)) -> Result<(), Error> {
    let (server, client) = accepted_server().await;
    serve_token(&server, edit).await;
    client.refresh("rt-0").await.map(|_| ())
}

/// The failure must name the member that was wrong, so a future server change
/// is readable from the error rather than from a debugger.
fn refusal_names(error: &Error, member: &str) {
    let rendered = error.to_string();
    assert!(rendered.contains(member), "the refusal does not name `{member}`: {rendered}");
}

// --- token_type ---------------------------------------------------------------

#[tokio::test]
async fn a_bearer_token_response_is_refused() {
    let error = refresh_with(|body| body["token_type"] = json!("Bearer"))
        .await
        .expect_err("a Bearer token is not a sender-constrained credential");
    refusal_names(&error, "token_type");
}

#[tokio::test]
async fn a_token_response_with_no_token_type_is_refused() {
    let error = refresh_with(|body| {
        body.as_object_mut().expect("an object").remove("token_type");
    })
    .await
    .expect_err("an absent token_type is not evidence of DPoP");
    refusal_names(&error, "token_type");
}

/// RFC 6749 makes `token_type` case-insensitive and the server sends `DPoP`;
/// refusing `dpop` would be strictness that catches nothing and breaks on a
/// library upgrade.
#[tokio::test]
async fn the_token_type_is_compared_without_regard_to_case() {
    let (server, client) = accepted_server().await;
    serve_token(&server, |body| body["token_type"] = json!("dpop")).await;
    client.refresh("rt-0").await.expect("`dpop` is `DPoP`");
}

// --- expires_in ---------------------------------------------------------------

#[tokio::test]
async fn a_token_response_with_no_lifetime_is_refused_rather_than_assumed() {
    let error = refresh_with(|body| {
        body.as_object_mut().expect("an object").remove("expires_in");
    })
    .await
    .expect_err("a missing lifetime must not be replaced with a guess");
    refusal_names(&error, "expires_in");
}

/// Zero is not a lifetime; it is a token that is already dead, and the refresh
/// skew would turn it into an unbounded refresh loop.
#[tokio::test]
async fn a_token_response_with_a_zero_lifetime_is_refused() {
    let error = refresh_with(|body| body["expires_in"] = json!(0))
        .await
        .expect_err("a zero lifetime is not a usable credential");
    refusal_names(&error, "expires_in");
}

// --- rotation -----------------------------------------------------------------

/// The headline. Before this, the client logged a warning and returned the
/// access token, so the caller saw success while the stored refresh token was
/// spent.
#[tokio::test]
async fn a_refresh_response_with_no_new_refresh_token_is_refused() {
    let error = refresh_with(|body| {
        body.as_object_mut().expect("an object").remove("refresh_token");
    })
    .await
    .expect_err("a refresh that does not rotate has spent the stored token for nothing");
    refusal_names(&error, "refresh_token");
}

/// The same defect wearing a different shape. This server rotates on every
/// refresh, so a repeat of the token just presented means it is spent.
#[tokio::test]
async fn a_refresh_response_that_returns_the_token_just_spent_is_refused() {
    let error = refresh_with(|body| body["refresh_token"] = json!("rt-0"))
        .await
        .expect_err("the token that was just presented is not a rotation");
    refusal_names(&error, "refresh_token");
}

/// The positive, so the refusals above cannot be satisfied by refusing
/// everything.
#[tokio::test]
async fn a_rotated_refresh_response_is_accepted() {
    let (server, client) = accepted_server().await;
    serve_token(&server, |_| {}).await;
    let tokens = client.refresh("rt-0").await.expect("a well-formed refresh response");
    assert_eq!(tokens.access_token(), "at-1");
    assert_eq!(tokens.refresh_token(), "rt-1");
    assert_eq!(tokens.expires_in(), std::time::Duration::from_secs(300));
}

// --- the same contract on the credential manager -------------------------------

/// The manager is the only thing in the product that refreshes, so the
/// requirement has to hold there rather than only on the primitive. The store
/// must still hold the token that was presented: the refresh failed, so
/// overwriting it with something the server did not send would lose the only
/// credential this installation has.
#[tokio::test]
async fn the_manager_fails_a_refresh_that_does_not_rotate_rather_than_reporting_success() {
    let (server, client) = accepted_server().await;
    serve_token(&server, |body| {
        body.as_object_mut().expect("an object").remove("refresh_token");
    })
    .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let store = Arc::new(CredentialStore::with_backend(
        Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    ));
    let lock = store.lock(std::time::Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &Credentials::new(
                server.uri(),
                "ylk-profile-test".to_owned(),
                Es256Key::generate().to_jwk_json(),
                "rt-0".to_owned(),
            ),
        )
        .expect("seed the store");
    drop(lock);

    let manager = yadorilink_fapi_client::test_support::manager_over(client, store.clone());
    let error = manager
        .access_token()
        .await
        .expect_err("a refresh that did not rotate must not be reported as an access token");
    refusal_names(&error, "refresh_token");

    assert_eq!(
        store.load().expect("load").expect("enrolled").refresh_token(),
        "rt-0",
        "a failed refresh must not disturb the stored credential"
    );
}

/// The authorization-code leg is held to the same requirement: this client only
/// ever asks for `offline_access`, and a code exchange that yields no refresh
/// token produces an installation that is authenticated for five minutes and
/// cannot enrol.
#[tokio::test]
async fn a_code_exchange_that_yields_no_refresh_token_is_refused() {
    let (server, client) = accepted_server().await;
    serve_token(&server, |body| {
        body.as_object_mut().expect("an object").remove("refresh_token");
    })
    .await;

    let pkce = yadorilink_fapi_client::Pkce::generate();
    let error = client
        .exchange_authorization_code("code-1", "http://127.0.0.1:41234/callback", &pkce)
        .await
        .expect_err("a grant with no refresh token cannot become an enrolled installation");
    refusal_names(&error, "refresh_token");
}

/// And the device grant, which is the other way an installation enrols.
#[tokio::test]
async fn a_device_grant_that_yields_no_refresh_token_is_refused() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    as_profile::serve(&server, as_profile::with_device_grant(&issuer)).await;
    let client = as_profile::connect(&server).await.expect("a device-grant deployment");

    serve_token(&server, |body| {
        body.as_object_mut().expect("an object").remove("refresh_token");
    })
    .await;

    let error = client
        .poll_device_authorization("dc-1")
        .await
        .expect_err("a device grant with no refresh token cannot enrol an installation");
    refusal_names(&error, "refresh_token");
}

/// A 200 that is not even a token response must not be mistaken for one -- the
/// same path, one step earlier.
#[tokio::test]
async fn a_token_response_with_no_access_token_is_refused() {
    let error = refresh_with(|body| {
        body.as_object_mut().expect("an object").remove("access_token");
    })
    .await
    .expect_err("a response with no access token is not a credential");
    refusal_names(&error, "access_token");
}

/// Rotation is asserted against the token this process presented, not against
/// whatever the store happens to hold, so a concurrent rotation by another
/// process cannot be read as a failure to rotate.
#[tokio::test]
async fn rotation_is_measured_against_the_token_that_was_presented() {
    let (server, client) = accepted_server().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=rt-7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at-8",
            "token_type": "DPoP",
            "expires_in": 300,
            // Different from `rt-7`, the same as some *other* process's spent
            // token. Nothing here may consult the store to decide that.
            "refresh_token": "rt-0",
        })))
        .mount(&server)
        .await;

    let tokens = client.refresh("rt-7").await.expect("rt-0 is a rotation away from rt-7");
    assert_eq!(tokens.refresh_token(), "rt-0");
}

/// `FapiClient` is the only door to a token response, and it is reached only
/// through a discovery document this client vetted. Pinned here so the two
/// halves of the contract stay one contract.
#[tokio::test]
async fn a_token_response_can_only_be_obtained_through_a_vetted_server() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let mut document = as_profile::deployed_profile(&issuer);
    document["dpop_signing_alg_values_supported"] = json!(["EdDSA"]);
    as_profile::serve(&server, document).await;
    serve_token(&server, |_| {}).await;

    let error = FapiClient::discover(
        reqwest::Client::new(),
        &server.uri(),
        "ylk-profile-test",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .await
    .expect_err("a server that cannot verify this client's proofs is refused before any token");
    assert!(matches!(error, Error::UnsupportedServer(_)), "got {error}");
}
