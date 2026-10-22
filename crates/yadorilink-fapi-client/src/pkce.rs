//! PKCE, S256 only (RFC 7636).
//!
//! `plain` is not implemented. FAPI 2.0 requires S256, and this Authorization
//! Server advertises `code_challenge_methods_supported: ["S256"]` and nothing
//! else, so a `plain` code path would only be a way to get it wrong.

use sha2::{Digest as _, Sha256};

use crate::jws::b64url;

/// A PKCE verifier and its S256 challenge, generated together so the two can
/// never drift apart.
#[derive(Clone)]
pub struct Pkce {
    verifier: String,
    challenge: String,
}

impl std::fmt::Debug for Pkce {
    /// Renders the challenge and not the verifier. The challenge is sent in
    /// the clear at PAR and identifies nothing on its own; the verifier is
    /// presented exactly once, at the token endpoint, and is the whole reason
    /// PKCE exists -- a `Debug` that rendered it would put a single-use
    /// authorization secret into whatever log line happened to format this
    /// value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkce").field("challenge", &self.challenge).finish_non_exhaustive()
    }
}

impl Pkce {
    /// A fresh pair.
    ///
    /// 48 random bytes, base64url-encoded to 64 ASCII characters. RFC 7636
    /// allows 43-128 characters and requires at least 256 bits of entropy;
    /// this is 384 bits.
    #[must_use]
    pub fn generate() -> Self {
        let mut entropy = [0u8; 48];
        getrandom::fill(&mut entropy).expect("the OS random source is available");
        Self::from_verifier(b64url(entropy))
    }

    /// Build the pair from an existing verifier. Exposed so a test can pin a
    /// known verifier/challenge vector; production code should use
    /// [`Pkce::generate`].
    #[must_use]
    pub fn from_verifier(verifier: String) -> Self {
        // The challenge hashes the ASCII of the verifier, not the bytes it was
        // encoded from. Hashing the pre-encoding entropy is a classic way to
        // produce a challenge that no server will ever match.
        let challenge = b64url(Sha256::digest(verifier.as_bytes()));
        Self { verifier, challenge }
    }

    /// Sent at the token endpoint.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Sent in the pushed authorization request.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

#[cfg(test)]
mod tests;
