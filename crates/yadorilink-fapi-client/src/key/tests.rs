#![cfg(test)]

use super::*;

/// The exact bytes RFC 7638 hashes. If this ever changes shape -- an added
/// member, a reordered field, whitespace -- the thumbprint stops matching
/// the server's `cnf_jkt` and every DPoP-bound request fails with a 401
/// that names nothing.
#[test]
fn the_thumbprint_input_is_the_canonical_four_member_jwk() {
    let jwk = PublicJwk {
        crv: "P-256".to_owned(),
        kty: "EC".to_owned(),
        x: "XXX".to_owned(),
        y: "YYY".to_owned(),
    };
    assert_eq!(
        serde_json::to_string(&jwk).expect("all fields are strings"),
        r#"{"crv":"P-256","kty":"EC","x":"XXX","y":"YYY"}"#
    );
}

/// RFC 7638 section 3.1's own worked example is for an RSA key, so the
/// P-256 vector here is RFC 7517 appendix A.1's EC key, whose thumbprint is
/// reproducible with any conforming implementation.
#[test]
fn the_thumbprint_matches_an_independent_implementation() {
    let jwk = PublicJwk {
        crv: "P-256".to_owned(),
        kty: "EC".to_owned(),
        x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".to_owned(),
        y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM".to_owned(),
    };
    // Independently produced by `jose.calculateJwkThumbprint` over the
    // same four members; see this crate's report for the transcript.
    assert_eq!(jwk.thumbprint(), "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s");
}

#[test]
fn a_jwks_public_half_is_recomputed_from_d_rather_than_trusted() {
    let key = Es256Key::generate();
    let real = key.public_jwk();
    let document = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "d": B64.encode(key.signing.to_bytes()),
        // A public half that does not belong to `d` at all.
        "x": "AAAA",
        "y": "BBBB",
        "kid": "client-1",
    })
    .to_string();

    let loaded = Es256Key::from_jwk_json(&document).expect("valid d");
    assert_eq!(loaded.public_jwk(), real, "x/y come from d, not from the file");
    assert_eq!(loaded.kid(), Some("client-1"));
}

/// The client key is generated once and then lives in the credential
/// store for the life of the enrolment, so export and import have to be
/// exact inverses -- a round trip that lost the key would surface as an
/// `invalid_client` naming nothing, on the next process start.
#[test]
fn a_client_key_survives_a_round_trip_through_its_jwk_document() {
    let key = Es256Key::generate().with_kid("installation");
    let restored = Es256Key::from_jwk_json(&key.to_jwk_json()).expect("its own export");
    assert_eq!(restored.public_jwk(), key.public_jwk());
    assert_eq!(restored.jkt(), key.jkt());
    assert_eq!(restored.kid(), Some("installation"));
}

/// `Debug` is what ends up in a log line or an `anyhow` chain. It must not
/// carry the scalar that `to_jwk_json` deliberately does.
#[test]
fn debug_never_renders_the_private_scalar_that_the_jwk_export_does() {
    let key = Es256Key::generate();
    let exported = key.to_jwk_json();
    let scalar = serde_json::from_str::<serde_json::Value>(&exported).expect("JSON")["d"]
        .as_str()
        .expect("the export carries d")
        .to_owned();

    assert!(!format!("{key:?}").contains(&scalar), "the private scalar reached Debug output");
}

#[test]
fn a_non_p256_jwk_is_refused_rather_than_coerced() {
    let document = r#"{"kty":"OKP","crv":"Ed25519","d":"AAAA","x":"BBBB"}"#;
    let err = Es256Key::from_jwk_json(document).expect_err("Ed25519 is not an ES256 key");
    assert!(
        format!("{err}").contains("EC P-256"),
        "the error should name the expectation, got: {err}"
    );
}
