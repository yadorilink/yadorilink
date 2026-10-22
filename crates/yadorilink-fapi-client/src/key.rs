//! The two ES256 keys a FAPI 2.0 client holds, and their public JWK form.
//!
//! A client holds *two* independent keys, and they are never the same key:
//!
//! * the **client key** -- a long-lived registered credential whose public half
//!   sits in the Authorization Server's client record, used to sign
//!   `private_key_jwt` client assertions;
//! * the **DPoP key** -- per-session proof-of-possession material, whose public
//!   half travels inside every proof's protected header.
//!
//! Neither is the device identity key. The device identity is an
//! `ed25519_dalek::SigningKey`; these are `p256::ecdsa::SigningKey`, so the
//! compiler rejects any confusion between them.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate as _;
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};
use crate::jws;

/// An EC public JWK, restricted to the four members RFC 7638 calls required
/// for `kty: "EC"`.
///
/// The field order here is load-bearing and is not an accident: `crv`, `kty`,
/// `x`, `y` is lexicographic order, and `serde_json` serializes struct fields
/// in declaration order with no whitespace. Serializing this struct therefore
/// *is* the RFC 7638 canonical form, which is why the thumbprint is computed
/// straight off it. A `serde_json::Value` map would not carry that guarantee.
///
/// `alg`, `use` and `kid` are deliberately absent: RFC 7638 excludes them, so
/// the thumbprint is independent of how the algorithm happens to be spelled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicJwk {
    pub crv: String,
    pub kty: String,
    pub x: String,
    pub y: String,
}

impl PublicJwk {
    /// The RFC 7638 JWK thumbprint, base64url-unpadded. This is the `jkt` the
    /// Authorization Server records as the access token's sender constraint.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        // Every field of `PublicJwk` is a `String`, so this cannot fail; an
        // empty digest produced in place of a real error would be a `jkt` this
        // client silently signed against no key at all.
        let canonical =
            serde_json::to_vec(self).expect("PublicJwk holds only Strings, which always serialize");
        jws::b64url(Sha256::digest(&canonical))
    }
}

/// An ES256 keypair plus the optional `kid` the server's client record names.
pub struct Es256Key {
    signing: SigningKey,
    kid: Option<String>,
}

impl std::fmt::Debug for Es256Key {
    /// Never renders the private scalar.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Es256Key")
            .field("kid", &self.kid)
            .field("jkt", &self.public_jwk().thumbprint())
            .finish_non_exhaustive()
    }
}

impl Es256Key {
    /// A fresh keypair. Used for the DPoP key, which has no registered
    /// counterpart and exists only for the lifetime of a session.
    #[must_use]
    pub fn generate() -> Self {
        Self { signing: SigningKey::generate(), kid: None }
    }

    /// Load a private ES256 key from a JWK document.
    ///
    /// Accepts the shape `jose`'s `exportJWK` emits -- `{"kty":"EC",
    /// "crv":"P-256","d":...,"x":...,"y":...}` -- because that is the format
    /// the Authorization Server's own tooling writes the client key in, and
    /// the client's assertions must verify against the public half of exactly
    /// that key.
    ///
    /// Only `d` is read; `x`/`y` are recomputed from it rather than trusted, so
    /// a JWK whose public half does not match its private half cannot silently
    /// produce assertions that verify against the wrong record.
    pub fn from_jwk_json(document: &str) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct PrivateJwk {
            kty: String,
            crv: String,
            d: String,
            kid: Option<String>,
        }

        let jwk: PrivateJwk = serde_json::from_str(document)?;
        if jwk.kty != "EC" || jwk.crv != "P-256" {
            return Err(Error::Key(format!(
                "expected an EC P-256 key, got kty={} crv={}",
                jwk.kty, jwk.crv
            )));
        }
        let scalar =
            B64.decode(&jwk.d).map_err(|e| Error::Key(format!("`d` is not base64url: {e}")))?;
        let signing = SigningKey::from_slice(&scalar)
            .map_err(|e| Error::Key(format!("`d` is not a valid P-256 scalar: {e}")))?;

        Ok(Self { signing, kid: jwk.kid })
    }

    /// Export the private key as a JWK document.
    ///
    /// The inverse of [`Es256Key::from_jwk_json`], and the form the credential
    /// store persists: a generated client key has to be written somewhere, and
    /// JWK is the format the Authorization Server's own tooling emits, so
    /// there is exactly one representation and one parser in the tree.
    ///
    /// This is the only method that renders the private scalar. It is named
    /// for what it does rather than being reachable through `Display` or
    /// `Serialize`, so a key cannot leak into a log line by being formatted:
    /// `Debug` renders only the `kid` and the thumbprint.
    #[must_use]
    pub fn to_jwk_json(&self) -> String {
        let public = self.public_jwk();
        let mut document = serde_json::json!({
            "kty": public.kty,
            "crv": public.crv,
            "d": jws::b64url(self.signing.to_bytes()),
            "x": public.x,
            "y": public.y,
        });
        if let Some(kid) = &self.kid {
            document["kid"] = serde_json::Value::String(kid.clone());
        }
        // A map of strings always serializes; an empty document written in
        // place of a real error here would be the private key silently failing
        // to reach the credential store it is about to be persisted into.
        serde_json::to_string(&document).expect("a JSON object of Strings always serializes")
    }

    /// Attach or replace the `kid` placed in the assertion's protected header.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The public half, as the four-member EC JWK.
    ///
    /// Built from the *uncompressed* SEC1 point: 65 bytes, a `0x04` tag
    /// followed by the two 32-byte affine coordinates. The tag byte is not part
    /// of the JWK.
    #[must_use]
    pub fn public_jwk(&self) -> PublicJwk {
        let point = self.signing.verifying_key().to_sec1_point(false);
        let bytes = point.as_ref();
        debug_assert_eq!(bytes.len(), 65, "uncompressed P-256 SEC1 point");
        PublicJwk {
            crv: "P-256".to_owned(),
            kty: "EC".to_owned(),
            x: jws::b64url(&bytes[1..33]),
            y: jws::b64url(&bytes[33..65]),
        }
    }

    /// The RFC 7638 thumbprint of the public half.
    #[must_use]
    pub fn jkt(&self) -> String {
        self.public_jwk().thumbprint()
    }

    pub(crate) fn sign_compact(
        &self,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> Result<String> {
        jws::sign_compact(&self.signing, header, claims)
    }
}

#[cfg(test)]
mod tests;
