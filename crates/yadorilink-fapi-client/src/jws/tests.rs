#![cfg(test)]

use super::*;

#[test]
fn a_compact_jws_has_three_base64url_segments_and_a_64_byte_signature() {
    let key = SigningKey::from_slice(&[7u8; 32]).expect("fixed non-zero scalar is a valid key");
    let jws = sign_compact(
        &key,
        &serde_json::json!({ "alg": "ES256" }),
        &serde_json::json!({ "iss": "client" }),
    )
    .expect("signing a fixed key and fixed claims cannot fail");

    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact serialization is three segments");
    assert!(
        !jws.contains('=') && !jws.contains('+') && !jws.contains('/'),
        "JOSE uses unpadded base64url, got {jws}"
    );

    let signature = B64.decode(parts[2]).expect("segment is base64url");
    assert_eq!(
        signature.len(),
        64,
        "ES256 signs as raw r||s, never DER -- a DER signature here would \
         be accepted by nothing"
    );

    let header: serde_json::Value =
        serde_json::from_slice(&B64.decode(parts[0]).expect("segment is base64url"))
            .expect("header is JSON");
    assert_eq!(header["alg"], "ES256");
}
