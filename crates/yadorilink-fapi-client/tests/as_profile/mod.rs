//! The deployed Authorization Server's discovery document, as a fixture.
//!
//! Shared by `tests/server_profile.rs` (which downgrades one member at a time)
//! and `tests/token_response_contract.rs` (which needs a server that discovery
//! accepts, so the only thing under test is the token response).
//!
//! Captured from the coordination service under its own provider test harness --
//! its Authorization Server answering `/.well-known/openid-configuration` with
//! `AS_ISSUER` set -- rather than invented here. A fixture more generous than
//! the real document would let these tests pass while the product fails.

#![allow(dead_code)]

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_fapi_client::{Error, Es256Key, FapiClient, DEVICE_CODE_GRANT};

/// Every member the deployed document carries, including the ones this client
/// does not read -- their presence is part of what was measured.
pub fn deployed_profile(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/auth"),
        "token_endpoint": format!("{issuer}/token"),
        "pushed_authorization_request_endpoint": format!("{issuer}/request"),
        "registration_endpoint": format!("{issuer}/reg"),
        "userinfo_endpoint": format!("{issuer}/me"),
        "end_session_endpoint": format!("{issuer}/session/end"),
        "jwks_uri": format!("{issuer}/jwks"),
        "require_pushed_authorization_requests": true,
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["form_post", "fragment", "query"],
        "scopes_supported": ["openid", "offline_access"],
        "subject_types_supported": ["public"],
        "claims_supported": ["sub", "sid", "auth_time", "iss"],
        "authorization_response_iss_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "claims_parameter_supported": false,
    })
}

/// The same document with the device grant switched on, which is what a
/// deployment carrying `AS_DEVICE_SECRET` advertises.
pub fn with_device_grant(issuer: &str) -> Value {
    let mut document = deployed_profile(issuer);
    document["device_authorization_endpoint"] = json!(format!("{issuer}/device/auth"));
    document["grant_types_supported"] =
        json!(["authorization_code", "refresh_token", DEVICE_CODE_GRANT]);
    document
}

/// Answer the well-known path with `document`.
pub async fn serve(server: &MockServer, document: Value) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document))
        .mount(server)
        .await;
}

/// Run discovery against `server`.
pub async fn connect(server: &MockServer) -> Result<FapiClient, Error> {
    FapiClient::discover(
        reqwest::Client::new(),
        &server.uri(),
        "ylk-profile-test",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .await
}

/// Stand up a server serving the unmodified deployed profile, and a client
/// over it.
pub async fn accepted_server() -> (MockServer, FapiClient) {
    let server = MockServer::start().await;
    let issuer = server.uri();
    serve(&server, deployed_profile(&issuer)).await;
    let client = connect(&server).await.expect("the deployed profile is accepted");
    (server, client)
}

/// The discovery members a refusal named, in order.
///
/// Every unmet requirement is written as `member: why`, so the member name is
/// a stable identifier a test can pin without depending on the prose.
pub fn unmet(error: &Error) -> Vec<String> {
    let Error::UnsupportedServer(problems) = error else {
        panic!("expected the profile check to refuse, got {error}");
    };
    problems
        .iter()
        .map(|problem| {
            problem
                .split_once(':')
                .unwrap_or_else(|| panic!("`{problem}` does not start with a member name"))
                .0
                .to_owned()
        })
        .collect()
}
