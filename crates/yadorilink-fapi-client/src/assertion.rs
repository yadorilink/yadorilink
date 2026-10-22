//! `private_key_jwt` client authentication (RFC 7523 section 2.2, OpenID
//! Connect Core section 9).

use crate::error::Result;
use crate::jws::{jti, now_secs};
use crate::key::Es256Key;

/// The `client_assertion_type` every request carries alongside the assertion.
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How long an assertion is valid. Short on purpose: the assertion is a
/// single-use credential for one request, and its `jti` is replay-detected
/// server-side anyway.
const LIFETIME_SECS: u64 = 120;

/// Mint one `private_key_jwt` client assertion.
///
/// `audience` must be the **issuer**, not the endpoint being called and not the
/// socket being dialed. The server accepts an audience of the issuer, the token
/// endpoint, or the endpoint URL, and the issuer is the only one of the three
/// that is the same for every request -- so using it removes a whole class of
/// "works at `/token`, fails at `/request`" bug. Take it from the discovery
/// document's `issuer`, never from the URL the client connected to.
///
/// This must be called once per request: a cached assertion is rejected the
/// second time it is presented, because `jti` is replay-detected.
pub fn client_assertion(key: &Es256Key, client_id: &str, audience: &str) -> Result<String> {
    let now = now_secs();
    let mut header = serde_json::json!({ "alg": "ES256" });
    // The header `alg` must equal the client record's registered
    // `token_endpoint_auth_signing_alg` by exact string compare. This server
    // registers `ES256`, which has exactly one spelling -- unlike Ed25519,
    // which oidc-provider treats as two distinct, non-interchangeable names
    // (`Ed25519` and `EdDSA`) and whose every mismatch surfaces as the same
    // opaque `401 invalid_client`.
    if let Some(kid) = key.kid() {
        header["kid"] = serde_json::Value::String(kid.to_owned());
    }

    key.sign_compact(
        &header,
        &serde_json::json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "jti": jti(),
            "iat": now,
            "exp": now + LIFETIME_SECS,
        }),
    )
}

#[cfg(test)]
mod tests;
