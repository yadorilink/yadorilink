//! The one Authorization Server profile this client will talk to, capability
//! by capability.
//!
//! # Why this is a requirement list and not a tolerance list
//!
//! This client is not a generic OAuth client. It talks to exactly one
//! Authorization Server -- the one in the coordination service -- and that
//! server's discovery document is not an unknown quantity: it is a fixed
//! profile produced by a configuration this repository owns
//! (`src/auth/provider/config.ts`). Interoperating with some *other* server is
//! not a requirement, so every tolerance is pure downside: it is a place where
//! a server that quietly stopped advertising a capability still looks like a
//! successful discovery, and the failure arrives several requests later as an
//! opaque 400 -- or does not arrive at all, because the capability that went
//! missing was a defence rather than a feature.
//!
//! The two shapes that tolerance took before this file existed:
//!
//! * an **empty** capability list meant "unknown, probably fine". A server
//!   advertising no `code_challenge_methods_supported` at all was accepted by
//!   a client that only implements S256, and a server advertising no
//!   `dpop_signing_alg_values_supported` was accepted by a client whose access
//!   tokens have no other sender constraint.
//! * `require_pushed_authorization_requests`, `pushed_authorization_request_endpoint`
//!   and `grant_types_supported` were parsed but never *required*. A
//!   deployment that stopped requiring PAR -- the single control that keeps an
//!   authorization request out of a browser-visible URL -- discovered
//!   successfully.
//!
//! # One test per capability, on purpose
//!
//! Each test below takes the full profile, changes exactly one member, and
//! asserts that discovery refuses **and names that member and only that
//! member**. Asserting the whole unmet list rather than "contains" is what
//! makes these tests double as a proof that the other checks still pass: a
//! change that accidentally starts rejecting a well-formed document fails here
//! too.
//!
//! The names pinned are the discovery document's own member names, so a future
//! server that quietly stops advertising one is caught by that name.

mod as_profile;

use as_profile::{connect, deployed_profile, serve, unmet, with_device_grant};
use serde_json::{json, Value};
use wiremock::MockServer;
use yadorilink_fapi_client::{Error, Es256Key, FapiClient};

/// Serve `edit(document)` at the well-known path and run discovery against it.
async fn discover(edit: impl FnOnce(&mut Value)) -> Result<FapiClient, Error> {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let mut document = deployed_profile(&issuer);
    edit(&mut document);
    serve(&server, document).await;
    connect(&server).await
}

/// One downgraded member, one named refusal.
async fn refused_for(member: &str, edit: impl FnOnce(&mut Value)) {
    let error = discover(edit)
        .await
        .err()
        .unwrap_or_else(|| panic!("discovery accepted a server that does not satisfy `{member}`"));
    assert_eq!(unmet(&error), vec![member.to_owned()], "got {error}");
}

fn drop_member(document: &mut Value, member: &str) {
    document.as_object_mut().expect("the document is an object").remove(member);
}

// --- the profile, capability by capability -----------------------------------

#[tokio::test]
async fn the_deployed_profile_is_accepted_as_it_stands() {
    let client = discover(|_| {}).await.expect("the deployed discovery document");
    assert!(!client.metadata().supports_device_grant(), "no device endpoint is advertised");
}

#[tokio::test]
async fn a_server_with_no_par_endpoint_is_refused() {
    refused_for("pushed_authorization_request_endpoint", |document| {
        drop_member(document, "pushed_authorization_request_endpoint");
    })
    .await;
}

/// PAR that is *offered* but not *required* is the same authorization request
/// in a browser-visible URL for anyone who asks for it that way.
#[tokio::test]
async fn a_server_that_does_not_require_par_is_refused() {
    refused_for("require_pushed_authorization_requests", |document| {
        document["require_pushed_authorization_requests"] = json!(false);
    })
    .await;
}

/// Absent is not "unknown but probably fine": it is a server this client has
/// no evidence will accept an S256 challenge.
#[tokio::test]
async fn a_server_that_advertises_no_pkce_method_is_refused() {
    refused_for("code_challenge_methods_supported", |document| {
        drop_member(document, "code_challenge_methods_supported");
    })
    .await;
}

#[tokio::test]
async fn a_server_that_advertises_plain_pkce_instead_of_s256_is_refused() {
    refused_for("code_challenge_methods_supported", |document| {
        document["code_challenge_methods_supported"] = json!(["plain"]);
    })
    .await;
}

#[tokio::test]
async fn a_server_that_advertises_no_client_authentication_method_is_refused() {
    refused_for("token_endpoint_auth_methods_supported", |document| {
        drop_member(document, "token_endpoint_auth_methods_supported");
    })
    .await;
}

#[tokio::test]
async fn a_server_that_wants_a_client_secret_instead_of_private_key_jwt_is_refused() {
    refused_for("token_endpoint_auth_methods_supported", |document| {
        document["token_endpoint_auth_methods_supported"] = json!(["client_secret_basic"]);
    })
    .await;
}

#[tokio::test]
async fn a_server_that_advertises_no_assertion_signing_algorithm_is_refused() {
    refused_for("token_endpoint_auth_signing_alg_values_supported", |document| {
        drop_member(document, "token_endpoint_auth_signing_alg_values_supported");
    })
    .await;
}

#[tokio::test]
async fn a_server_that_does_not_take_es256_client_assertions_is_refused() {
    refused_for("token_endpoint_auth_signing_alg_values_supported", |document| {
        document["token_endpoint_auth_signing_alg_values_supported"] = json!(["RS256"]);
    })
    .await;
}

#[tokio::test]
async fn a_server_that_advertises_no_dpop_algorithm_is_refused() {
    refused_for("dpop_signing_alg_values_supported", |document| {
        drop_member(document, "dpop_signing_alg_values_supported");
    })
    .await;
}

/// DPoP is the access token's only sender constraint. A server that cannot
/// verify this client's proofs issues tokens that are bearer tokens in
/// practice.
#[tokio::test]
async fn a_server_that_does_not_verify_es256_dpop_proofs_is_refused() {
    refused_for("dpop_signing_alg_values_supported", |document| {
        document["dpop_signing_alg_values_supported"] = json!(["EdDSA"]);
    })
    .await;
}

/// The exactness this client's profile requires, not merely a superset: a
/// resource server that ALSO verifies Ed25519 or EdDSA DPoP proofs alongside
/// ES256 is a wider attack surface than the one this client's document was
/// checked against, even though ES256 itself is still present. `oidc-provider`
/// 9.12.0 defaults `dPoPSigningAlgValues` to exactly this wider set, which is
/// the shape this test would have missed under "contains" rather than
/// "exactly".
#[tokio::test]
async fn a_server_that_advertises_a_wider_dpop_algorithm_set_than_es256_alone_is_refused() {
    refused_for("dpop_signing_alg_values_supported", |document| {
        document["dpop_signing_alg_values_supported"] = json!(["ES256", "Ed25519", "EdDSA"]);
    })
    .await;
}

/// Same exactness, for the client-assertion signing algorithm: a token
/// endpoint that also accepts `RS256` client assertions alongside `ES256`
/// accepts an assertion this client never produces, from a key this client
/// never registered.
#[tokio::test]
async fn a_server_that_accepts_a_wider_client_assertion_algorithm_set_than_es256_alone_is_refused()
{
    refused_for("token_endpoint_auth_signing_alg_values_supported", |document| {
        document["token_endpoint_auth_signing_alg_values_supported"] = json!(["ES256", "RS256"]);
    })
    .await;
}

/// Same exactness, for client authentication: a token endpoint that also
/// accepts `client_secret_basic` alongside `private_key_jwt` is a server this
/// client's key-only architecture was not checked against, whether or not
/// this particular client would ever be issued a secret.
#[tokio::test]
async fn a_server_that_accepts_a_wider_client_auth_method_set_than_private_key_jwt_alone_is_refused(
) {
    refused_for("token_endpoint_auth_methods_supported", |document| {
        document["token_endpoint_auth_methods_supported"] =
            json!(["private_key_jwt", "client_secret_basic"]);
    })
    .await;
}

/// Dropping the member fails two requirements rather than one, and the refusal
/// names both: `authorization_code` and `refresh_token` are separate needs that
/// happen to be advertised in the same list, and a client told only about the
/// first would fix its server and come back to discover the second.
#[tokio::test]
async fn a_server_that_advertises_no_grant_types_is_refused() {
    let error = discover(|document| drop_member(document, "grant_types_supported"))
        .await
        .expect_err("discovery accepted a server advertising no grant types at all");
    assert_eq!(
        unmet(&error),
        vec!["grant_types_supported".to_owned(), "grant_types_supported".to_owned()],
        "got {error}"
    );
    let rendered = error.to_string();
    assert!(rendered.contains("`authorization_code`"), "got {rendered}");
    assert!(rendered.contains("`refresh_token`"), "got {rendered}");
}

#[tokio::test]
async fn a_server_without_the_authorization_code_grant_is_refused() {
    refused_for("grant_types_supported", |document| {
        document["grant_types_supported"] = json!(["refresh_token"]);
    })
    .await;
}

/// Without `refresh_token` every session this client establishes is five
/// minutes long, and the daemon it exists for cannot run.
#[tokio::test]
async fn a_server_without_the_refresh_token_grant_is_refused() {
    refused_for("grant_types_supported", |document| {
        document["grant_types_supported"] = json!(["authorization_code"]);
    })
    .await;
}

// --- the device grant: advertised on both halves, or on neither --------------

/// `device_code` is the one capability that is optional rather than required,
/// because the deployment turns it on with `AS_DEVICE_SECRET` and a deployment
/// without one is a correct deployment. What is required is coherence.
#[tokio::test]
async fn a_deployment_with_the_device_grant_on_is_accepted_and_says_so() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    serve(&server, with_device_grant(&issuer)).await;
    let client = connect(&server).await.expect("a deployment with the device grant on");
    assert!(client.metadata().supports_device_grant());
}

/// An endpoint the token endpoint would refuse to honour. Advertising the door
/// without the grant is how a headless enrolment gets all the way to polling
/// before it fails.
#[tokio::test]
async fn a_device_authorization_endpoint_without_the_device_code_grant_is_refused() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let mut document = with_device_grant(&issuer);
    document["grant_types_supported"] = json!(["authorization_code", "refresh_token"]);
    serve(&server, document).await;
    let error = connect(&server)
        .await
        .expect_err("a device endpoint with no device grant is not a coherent profile");
    assert_eq!(unmet(&error), vec!["device_authorization_endpoint".to_owned()], "got {error}");
}

#[tokio::test]
async fn a_device_code_grant_with_no_device_authorization_endpoint_is_refused() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let mut document = with_device_grant(&issuer);
    drop_member(&mut document, "device_authorization_endpoint");
    serve(&server, document).await;
    let error = connect(&server)
        .await
        .expect_err("a device grant with no endpoint to start it at is not a coherent profile");
    assert_eq!(unmet(&error), vec!["device_authorization_endpoint".to_owned()], "got {error}");
}

// --- the profile cannot be sidestepped ---------------------------------------

/// The stronger property: not merely that `discover` refuses, but that there is
/// no lower-level way to end up holding a client over a profile `discover`
/// would have refused.
///
/// `from_metadata` exists so a completed login can hand its client over without
/// fetching the document a second time. It must not also be the seam that lets
/// a caller assemble a client over a document nobody checked -- `Metadata`'s
/// fields are public, so without this the profile gate is advisory.
#[tokio::test]
async fn a_client_cannot_be_assembled_over_a_profile_discovery_would_have_refused() {
    let mut document = deployed_profile("https://as.test");
    document["require_pushed_authorization_requests"] = json!(false);
    let metadata: yadorilink_fapi_client::Metadata =
        serde_json::from_value(document).expect("a parseable document");

    let error = FapiClient::from_metadata(
        reqwest::Client::new(),
        url::Url::parse("https://as.test").expect("a base URL"),
        metadata,
        "ylk-profile-test",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .expect_err("from_metadata must apply the same profile check discovery does");
    assert_eq!(unmet(&error), vec!["require_pushed_authorization_requests".to_owned()]);
}
