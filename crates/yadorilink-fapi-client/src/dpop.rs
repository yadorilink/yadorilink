//! DPoP proofs (RFC 9449).

use sha2::{Digest as _, Sha256};

use crate::error::Result;
use crate::jws::{b64url, jti, now_secs};
use crate::key::Es256Key;

/// Mint one DPoP proof.
///
/// `htu` is the **issuer-derived** endpoint URL, never the socket the client
/// actually connected to. The Authorization Server compares the proof's `htu`
/// against the URL it builds from its own configured issuer, and it drops the
/// incoming `Host` header entirely, so a client talking to `127.0.0.1:8787`
/// must still send `https://<issuer>/token`. Deriving `htu` from the request
/// URL produces an `invalid_dpop_proof` that reads like a signature problem.
/// Take it from the discovery document's endpoint fields.
///
/// `access_token` is required whenever a token is being presented -- the `ath`
/// claim binds this proof to that specific token. It is absent for the
/// unauthenticated legs (PAR, and the token endpoint itself).
///
/// One proof per request: `jti` is replay-detected server-side, and `iat` is
/// only accepted inside a 300-second window.
pub fn dpop_proof(
    key: &Es256Key,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
) -> Result<String> {
    let mut claims = serde_json::json!({
        "htm": htm,
        "htu": htu,
        "iat": now_secs(),
        "jti": jti(),
    });
    if let Some(token) = access_token {
        claims["ath"] = serde_json::Value::String(b64url(Sha256::digest(token.as_bytes())));
    }

    // The public key travels in the header, so the server can check the proof
    // without having seen the key before -- and its RFC 7638 thumbprint is what
    // it compares against the token's recorded sender constraint. Only the four
    // required members go in; the private half never leaves this process.
    key.sign_compact(
        &serde_json::json!({
            "alg": "ES256",
            "typ": "dpop+jwt",
            "jwk": key.public_jwk(),
        }),
        &claims,
    )
}

#[cfg(test)]
mod tests;
