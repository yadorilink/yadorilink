//! `CoordinationAuth::confirm_registration_status`, against a local HTTP
//! server.
//!
//! The one property under test is the classification of a refused refresh:
//! `invalid_client` means this installation's client registration is gone
//! (the only kill boundary this architecture has), and `invalid_grant` does
//! NOT mean that -- it is also what a dead refresh token or a reuse-defence
//! grant revocation produces while the client registration is still live.
//! Sign Out's whole reason for calling this method is to avoid clearing a
//! local credential on a guess, so the two outcomes must not be conflated.

use std::sync::Arc;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_fapi_client::store::{Backend, CredentialStore, Credentials};
use yadorilink_fapi_client::{CoordinationAuth, CredentialManager, Es256Key, RegistrationStatus};

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

/// An enrolled installation, one refresh away from finding out what
/// [`confirm_registration_status`] reports about a token endpoint that
/// answers `error`.
async fn auth_after_token_endpoint_answers(error: &str) -> RegistrationStatus {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata(&server.uri())))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": error,
            "error_description": "the mock token endpoint always answers this way",
        })))
        .mount(&server)
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
                "ylk-test-installation".to_owned(),
                Es256Key::generate().to_jwk_json(),
                "rt-1".to_owned(),
            ),
        )
        .expect("seed the store");
    drop(lock);

    let manager = CredentialManager::restore(reqwest::Client::new(), &server.uri(), store)
        .await
        .expect("restore from the store");
    let auth = CoordinationAuth::new(Arc::new(manager)).expect("a valid issuer");
    auth.confirm_registration_status().await
}

/// The one status that earns a local credential clear on an unconfirmed 401:
/// the server refusing `private_key_jwt` client authentication itself.
#[tokio::test]
async fn invalid_client_is_reported_as_revoked() {
    assert!(
        matches!(
            auth_after_token_endpoint_answers("invalid_client").await,
            RegistrationStatus::Revoked
        ),
        "invalid_client must confirm the registration is gone"
    );
}

/// THE PROPERTY THIS FILE EXISTS FOR. `invalid_grant` is what a dead refresh
/// token, or the reuse defence revoking one grant, ALSO produces -- neither
/// of which means the client registration itself is gone. Reporting it as
/// `Revoked` would let a Sign Out clear a local credential whose
/// registration is still live on the server, orphaning it.
#[tokio::test]
async fn invalid_grant_is_not_reported_as_revoked() {
    let status = auth_after_token_endpoint_answers("invalid_grant").await;
    assert!(
        !matches!(status, RegistrationStatus::Revoked),
        "invalid_grant alone must not confirm a client revocation, got {status:?}"
    );
    assert!(matches!(status, RegistrationStatus::Unknown(_)), "got {status:?}");
}

/// A refusal this method has no special handling for settles nothing either,
/// for the same reason `invalid_grant` does not.
#[tokio::test]
async fn an_unrelated_refusal_is_reported_as_unknown() {
    let status = auth_after_token_endpoint_answers("invalid_request").await;
    assert!(matches!(status, RegistrationStatus::Unknown(_)), "got {status:?}");
}
