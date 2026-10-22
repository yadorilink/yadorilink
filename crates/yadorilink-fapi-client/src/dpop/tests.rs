#![cfg(test)]

use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;

fn decode(segment: &str) -> serde_json::Value {
    serde_json::from_slice(&B64.decode(segment).expect("base64url")).expect("JSON")
}

#[test]
fn a_proof_carries_the_public_key_and_the_dpop_type() {
    let key = Es256Key::generate();
    let proof = dpop_proof(&key, "POST", "https://as.test/token", None).expect("sign");
    let header = decode(proof.split('.').next().unwrap());

    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["jwk"]["kty"], "EC");
    assert_eq!(header["jwk"]["crv"], "P-256");
    assert!(header["jwk"].get("d").is_none(), "the private scalar must never appear in a proof");

    let claims = decode(proof.split('.').nth(1).unwrap());
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], "https://as.test/token");
    assert!(claims.get("ath").is_none(), "no token was presented, so there is nothing to bind to");
}

/// `ath` is `base64url(SHA-256(access_token))` over the token's ASCII.
#[test]
fn ath_is_the_digest_of_the_token_that_is_being_presented() {
    let key = Es256Key::generate();
    let proof = dpop_proof(&key, "GET", "https://as.test/me", Some("opaque-token")).expect("sign");
    let claims = decode(proof.split('.').nth(1).unwrap());
    assert_eq!(claims["ath"], b64url(Sha256::digest(b"opaque-token")));
}

#[test]
fn the_header_jwk_thumbprint_is_the_keys_jkt() {
    let key = Es256Key::generate();
    let proof = dpop_proof(&key, "GET", "https://as.test/me", None).expect("sign");
    let header = decode(proof.split('.').next().unwrap());
    let embedded: crate::key::PublicJwk =
        serde_json::from_value(header["jwk"].clone()).expect("four-member EC JWK");
    assert_eq!(
        embedded.thumbprint(),
        key.jkt(),
        "the server derives the sender constraint from this embedded key"
    );
}

#[test]
fn every_proof_carries_a_fresh_jti() {
    let key = Es256Key::generate();
    let a = dpop_proof(&key, "GET", "https://as.test/me", None).expect("sign");
    let b = dpop_proof(&key, "GET", "https://as.test/me", None).expect("sign");
    assert_ne!(
        decode(a.split('.').nth(1).unwrap())["jti"],
        decode(b.split('.').nth(1).unwrap())["jti"]
    );
}
