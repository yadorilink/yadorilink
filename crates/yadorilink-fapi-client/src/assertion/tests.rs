#![cfg(test)]

use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;

fn decode(segment: &str) -> serde_json::Value {
    serde_json::from_slice(&B64.decode(segment).expect("base64url")).expect("JSON")
}

#[test]
fn the_assertion_names_the_client_as_both_issuer_and_subject() {
    let key = Es256Key::generate().with_kid("client-1");
    let jwt = client_assertion(&key, "yadorilink-cli", "https://example.test")
        .expect("signing cannot fail");
    let parts: Vec<&str> = jwt.split('.').collect();

    let header = decode(parts[0]);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], "client-1");
    assert!(header.get("typ").is_none(), "no typ is registered for this assertion");

    let claims = decode(parts[1]);
    assert_eq!(claims["iss"], "yadorilink-cli");
    assert_eq!(claims["sub"], "yadorilink-cli");
    assert_eq!(claims["aud"], "https://example.test");
    assert!(claims["exp"].as_u64().unwrap() > claims["iat"].as_u64().unwrap());
}

#[test]
fn every_assertion_carries_a_fresh_jti() {
    let key = Es256Key::generate();
    let first = client_assertion(&key, "c", "https://a.test").expect("sign");
    let second = client_assertion(&key, "c", "https://a.test").expect("sign");
    let a = decode(first.split('.').nth(1).unwrap());
    let b = decode(second.split('.').nth(1).unwrap());
    assert_ne!(a["jti"], b["jti"], "jti is replay-detected; reusing one fails the second request");
}

#[test]
fn a_key_without_a_kid_omits_the_header_member_rather_than_sending_null() {
    let key = Es256Key::generate();
    let jwt = client_assertion(&key, "c", "https://a.test").expect("sign");
    let header = decode(jwt.split('.').next().unwrap());
    assert!(header.get("kid").is_none());
}
