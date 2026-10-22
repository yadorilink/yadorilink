//! JWS compact serialization, ES256 only.
//!
//! This is the entire hand-written JOSE surface of this crate, and it is
//! deliberately small: two base64url segments and a signature. There is no
//! parsing path, no `alg` negotiation and no verification path here -- which is
//! where the JOSE vulnerability classes live. The client never verifies a JWS:
//! the access tokens this Authorization Server issues are opaque, and the
//! `id_token` is not consumed.
//!
//! The cryptography itself is NOT hand-rolled. The P-256 ECDSA signature comes
//! from `p256`/`ecdsa`, the digest from `sha2`, and the encoding from `base64`.
//!
//! Why no JOSE crate: the only candidate already able to emit the DPoP header
//! shape (`jsonwebtoken` 11 with its `rust_crypto` feature) bundles `rsa` as a
//! non-optional part of that feature, and `rsa` carries RUSTSEC-2023-0071 with
//! `patched = []`. `cargo deny check advisories` is blocking in this
//! workspace's CI, so that crate cannot be added at all. Its `aws_lc_rs`
//! alternative pulls a license (`MIT-0`) that is not on this workspace's
//! allow-list. Both would still need `p256` for key generation and for the
//! JWK's affine coordinates, so neither removes a dependency -- they only add.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

/// base64url without padding -- the only encoding JOSE uses.
#[must_use]
pub fn b64url(bytes: impl AsRef<[u8]>) -> String {
    B64.encode(bytes)
}

/// Sign `header` and `claims` as an ES256 JWS in compact serialization.
///
/// The signature is the raw `r || s` pair, 64 bytes, which is exactly what
/// RFC 7518 specifies for ES256 -- `Signature::to_bytes()` already returns that
/// form, so there is no DER unwrapping step. `p256` signs through RFC 6979, so
/// the nonce is derived deterministically from the key and the message rather
/// than drawn from the RNG at call time.
pub(crate) fn sign_compact(
    key: &SigningKey,
    header: &serde_json::Value,
    claims: &serde_json::Value,
) -> crate::Result<String> {
    let signing_input =
        format!("{}.{}", b64url(serde_json::to_vec(header)?), b64url(serde_json::to_vec(claims)?));
    let signature: Signature = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64url(signature.to_bytes())))
}

/// Seconds since the Unix epoch, for `iat` / `exp`.
///
/// The server checks a DPoP proof's `iat` against a 300-second window, so a
/// client whose clock is badly wrong fails with `invalid_dpop_proof` rather
/// than anything that names the clock.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A fresh `jti`.
///
/// Both the client assertion and the DPoP proof are replay-detected
/// server-side, so this must be called once per request. Reusing either across
/// a retry is rejected the second time.
pub(crate) fn jti() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests;
