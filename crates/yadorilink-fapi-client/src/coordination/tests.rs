#![cfg(test)]

use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;

fn issuer() -> Url {
    Url::parse("https://as.example").expect("a valid issuer")
}

/// The whole point of `htu_for`: the socket the client dialed does not
/// appear in the signed proof. A client talking to a loopback `wrangler
/// dev` still signs the deployment's issuer-absolute URL, because that is
/// the URL the server rebuilds and compares against.
#[test]
fn htu_is_the_issuer_origin_with_the_requests_path() {
    assert_eq!(
        htu_for(&issuer(), "http://127.0.0.1:8787/devices/register").expect("a URL"),
        "https://as.example/devices/register"
    );
}

/// RFC 9449 §4.2 excludes query and fragment from `htu`, and
/// `resource.ts::normalizeHtu` strips them before comparing. Signing them
/// would make every request with a query string fail `htu` verification.
#[test]
fn htu_drops_the_query_and_the_fragment() {
    assert_eq!(
        htu_for(&issuer(), "https://as.example/shares?group=g1#frag").expect("a URL"),
        "https://as.example/shares"
    );
}

/// Every authenticated request carries the DPoP scheme and a proof. The
/// `Bearer` arm this type used to have is gone, so there is no longer a
/// credential in this workspace that produces a proof-free request.
#[tokio::test]
async fn an_authorized_request_is_always_dpop_and_always_carries_a_proof() {
    let auth = crate::test_support::offline_auth();
    let headers = auth
        .authorize("GET", "https://c.example/devices")
        .await
        .expect("a seeded token needs no network");
    assert!(headers.authorization().starts_with("DPoP "), "scheme was {}", headers.authorization());
    assert!(!headers.dpop().is_empty(), "a request went out with no proof");
}

/// A credential must not render itself. `Debug` on the wrapper and on the
/// minted headers are both reachable from a `tracing` field by accident,
/// which is how a token reaches a log file.
#[tokio::test]
async fn debug_renders_no_credential() {
    let auth = crate::test_support::offline_auth();
    let rendered = format!("{auth:?}");
    assert!(
        !rendered.contains(crate::test_support::OFFLINE_ACCESS_TOKEN),
        "the token reached Debug: {rendered}"
    );

    let headers = auth
        .authorize("GET", "https://c.example/x")
        .await
        .expect("a seeded token needs no network");
    let rendered = format!("{headers:?}");
    assert!(
        !rendered.contains(crate::test_support::OFFLINE_ACCESS_TOKEN),
        "the token reached Debug: {rendered}"
    );
    assert!(rendered.contains("DPoP"), "the scheme is the useful half: {rendered}");
}

/// The proof has to bind to the request, or it is a bearer token with extra
/// steps. This checks the three claims the resource server compares against
/// values it derives itself: `htm`, `htu` and `ath`.
#[test]
fn a_dpop_proof_binds_the_method_the_issuer_derived_url_and_the_token() {
    use sha2::Digest as _;

    let key = crate::key::Es256Key::generate();
    let proof = crate::dpop::dpop_proof(
        &key,
        "POST",
        &htu_for(&issuer(), "http://127.0.0.1:8787/devices/register").expect("a URL"),
        Some("opaque-access-token"),
    )
    .expect("signing a proof");

    let claims: serde_json::Value = serde_json::from_slice(
        &B64.decode(proof.split('.').nth(1).expect("a JWS payload")).expect("base64url"),
    )
    .expect("JSON claims");

    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], "https://as.example/devices/register");
    assert_eq!(claims["ath"], crate::jws::b64url(sha2::Sha256::digest(b"opaque-access-token")));
}
