//! Device pairing codes: how a signed-in account hands a NEW installation its
//! own sign-in without a browser on that installation.
//!
//! The account's web page shows a ten-minute, single-use code
//! (`XXXX-XXXX-XXXX`) and a QR code of a link that carries it. The new
//! installation sends the code with `POST /bootstrap/start`; it stands in for
//! the browser approval of the ordinary enrolment, and everything after it
//! (the key-bound poll, the OAuth login) is the same code path.
//!
//! The code is a bearer secret for ten minutes: whoever redeems it enrols a
//! device on the account. So it is a type of its own that cannot be printed by
//! accident ([`fmt::Debug`] is redacted, there is no `Display`), and the
//! normalisation here is deliberately exactly the server's: anything that is
//! not twelve letters of the code alphabet is refused before a request is
//! made, which also keeps a mistyped code from spending the server's abuse
//! budget.

use std::fmt;

use url::Url;

/// The code alphabet: twenty consonants, so a code cannot spell a word.
const ALPHABET: &str = "BCDFGHJKLMNPQRSTVWXZ";
const CODE_LENGTH: usize = 12;
/// The longest input worth looking at (a scanned link included).
const MAX_INPUT_LENGTH: usize = 2048;

/// A pairing code that is well formed. Not proof that the server knows it.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingCode(String);

/// The input cannot be a pairing code. Carries nothing of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("that is not a pairing code: it is twelve letters, shown as XXXX-XXXX-XXXX")]
pub struct MalformedPairingCode;

impl PairingCode {
    /// A code as a person typed it: upper or lower case, with or without the
    /// hyphens, surrounding or inner spaces.
    ///
    /// # Errors
    /// [`MalformedPairingCode`] unless it is twelve letters of the alphabet.
    pub fn parse(input: &str) -> Result<Self, MalformedPairingCode> {
        if input.is_empty() || input.len() > 64 {
            return Err(MalformedPairingCode);
        }
        let compact: String =
            input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>();
        let compact = compact.to_ascii_uppercase();
        if compact.len() != CODE_LENGTH || !compact.chars().all(|c| ALPHABET.contains(c)) {
            return Err(MalformedPairingCode);
        }
        Ok(Self(compact))
    }

    /// What a QR scan or a pasted link yields: the page link the web page
    /// shows (`.../account/devices/pair?code=XXXX-XXXX-XXXX`), or the bare
    /// code. The link's host is not used for anything: the code is only ever
    /// sent to the coordination service this installation is configured for.
    ///
    /// # Errors
    /// [`MalformedPairingCode`] when no well-formed code is found.
    pub fn from_scanned(input: &str) -> Result<Self, MalformedPairingCode> {
        let trimmed = input.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_INPUT_LENGTH {
            return Err(MalformedPairingCode);
        }
        if trimmed.contains("://") {
            let url = Url::parse(trimmed).map_err(|_| MalformedPairingCode)?;
            let code = url
                .query_pairs()
                .find(|(key, _)| key == "code")
                .map(|(_, value)| value.into_owned())
                .ok_or(MalformedPairingCode)?;
            return Self::parse(&code);
        }
        Self::parse(trimmed)
    }

    /// `XXXX-XXXX-XXXX`, for showing the code back to its owner (never for a
    /// log).
    #[must_use]
    pub fn formatted(&self) -> String {
        format!("{}-{}-{}", &self.0[..4], &self.0[4..8], &self.0[8..])
    }

    /// The request body's form: twelve letters, no hyphens.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(<redacted>)")
    }
}

#[cfg(test)]
mod tests;
