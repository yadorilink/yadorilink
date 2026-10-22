#![cfg(test)]

use super::*;

#[test]
fn the_start_body_sends_the_public_half_and_never_the_private_one() {
    let key = Es256Key::generate();
    let uris = vec!["http://127.0.0.1:41234/callback".to_owned()];
    let body = serde_json::json!({
        "jwks": { "keys": [key.public_jwk()] },
        "redirect_uris": uris,
        "client_name": Some("laptop"),
    })
    .to_string();

    let scalar = serde_json::from_str::<serde_json::Value>(&key.to_jwk_json()).expect("JSON")["d"]
        .as_str()
        .expect("d")
        .to_owned();
    assert!(!body.contains(&scalar), "the private scalar reached the enrolment request");
    assert!(body.contains(key.public_jwk().x.as_str()));
}

/// The handle is the value the registration is collected with. A `Debug`
/// that printed it would put it in every log line that logs the struct,
/// which is the way this kind of secret actually escapes.
#[test]
fn the_handle_is_not_in_the_debug_output() {
    let pending = PendingEnrolment {
        handle: "a-secret-nobody-should-see".to_owned(),
        approval_uri: "https://as.test/bootstrap/approve?code=other".to_owned(),
        expires_in: Duration::from_secs(600),
        poll_interval: Duration::from_secs(5),
        transport_base: Url::parse("https://as.test").expect("a valid base URL"),
        canonical_issuer: "https://as.test".to_owned(),
    };
    let rendered = format!("{pending:?}");
    assert!(!rendered.contains("a-secret-nobody-should-see"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(rendered.contains("bootstrap/approve"), "{rendered}");
}

#[test]
fn a_registration_carrying_an_upstream_credential_is_refused() {
    for forbidden in ["id_token", "access_token", "refresh_token"] {
        let body = serde_json::json!({
            "client_id": "ylk-AAAAAAAAAAAAAAAAAAAAAA",
            forbidden: "an upstream artefact that must not be here",
        })
        .to_string();
        let err = registration_from(&body).expect_err("{forbidden} must be refused");
        assert!(
            matches!(&err, Error::Registration(message) if message.contains(forbidden)),
            "got {err}"
        );
    }
}
