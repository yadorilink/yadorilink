//! The code of a cross-account Send link, and the sealed file list it unlocks.
//!
//! A code is minted on the sender's device and has two halves: an 8-character lookup id the
//! coordination service indexes the link by, and a 26-character secret (130 random bits) that never
//! leaves the two people's devices. From the secret both ends derive, with HKDF-SHA256, a token
//! (what a receiver presents to preview or redeem; the service stores only its hash) and a
//! 256-bit AES-GCM key that seals the file list. The service therefore holds the lookup id, a hash
//! of the token and a ciphertext, and can neither read the names and sizes nor reconstruct the
//! secret. The key is used for exactly one encryption, so the random 96-bit nonce cannot repeat
//! under it; the link id is bound as associated data so a ciphertext cannot be replayed under
//! another link.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const LOOKUP_LEN: usize = 8;
const SECRET_LEN: usize = 26;
const HKDF_SALT: &[u8] = b"yadorilink-send-link-v2";
const AAD_PREFIX: &str = "yadorilink-send-preview-v2:";
const TOKEN_HASH_PREFIX: &str = "yadorilink-send-link-v2:";
const NONCE_LEN: usize = 12;
/// The list is padded with JSON whitespace to a multiple of this, so a ciphertext's length shows
/// the list's size only to the nearest kilobyte.
const PAD_TO: usize = 1024;

/// A parsed or freshly minted code. Its `Debug` output names nothing of it.
#[derive(Clone, PartialEq, Eq)]
pub struct SendLinkCode {
    lookup_id: String,
    secret: String,
}

impl std::fmt::Debug for SendLinkCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SendLinkCode(..)")
    }
}

fn random_chars(len: usize) -> String {
    (0..len).map(|_| char::from(ALPHABET[usize::from(rand::random::<u8>() % 32)])).collect()
}

impl SendLinkCode {
    /// A fresh code from the operating system's randomness.
    pub fn mint() -> Self {
        Self { lookup_id: random_chars(LOOKUP_LEN), secret: random_chars(SECRET_LEN) }
    }

    /// Parses what a person typed or pasted: case, dashes and whitespace are presentation only.
    /// `None` for anything that is not exactly a code.
    pub fn parse(raw: &str) -> Option<Self> {
        let normalized: String = raw
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if normalized.len() != LOOKUP_LEN + SECRET_LEN
            || !normalized.bytes().all(|b| ALPHABET.contains(&b))
        {
            return None;
        }
        let (lookup_id, secret) = normalized.split_at(LOOKUP_LEN);
        Some(Self { lookup_id: lookup_id.to_owned(), secret: secret.to_owned() })
    }

    /// The code as shown to people: groups of four separated by dashes.
    pub fn display(&self) -> String {
        let all = format!("{}{}", self.lookup_id, self.secret);
        all.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// What the service indexes the link by.
    pub fn lookup_id(&self) -> &str {
        &self.lookup_id
    }

    fn derive(&self, purpose: &str) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), self.secret.as_bytes());
        let mut out = [0u8; 32];
        let info = format!("{}:{purpose}", self.lookup_id);
        // 32 bytes is far below HKDF's output limit, so this cannot fail.
        hkdf.expand(info.as_bytes(), &mut out).expect("hkdf output length is valid");
        out
    }

    /// What a receiver presents to preview or redeem: lowercase hex of the derived token.
    pub fn token_hex(&self) -> String {
        hex(&self.derive("token"))
    }

    /// What the sender submits at creation instead of the token itself.
    pub fn token_hash_hex(&self) -> String {
        hex(&Sha256::digest(format!("{TOKEN_HASH_PREFIX}{}", self.token_hex()).as_bytes()))
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.derive("preview-key")))
    }

    /// Seals the file list for `link_id`: unpadded base64url of `nonce || ciphertext || tag`.
    pub fn seal_preview(&self, link_id: &str, files: &[(String, u64)]) -> Result<String, String> {
        let mut plaintext = serde_json::to_vec(
            &files
                .iter()
                .map(|(name, size)| serde_json::json!({ "name": name, "size": size }))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| format!("could not encode the file list: {e}"))?;
        plaintext.resize(plaintext.len().div_ceil(PAD_TO) * PAD_TO, b' ');
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let aad = format!("{AAD_PREFIX}{link_id}");
        let sealed = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload { msg: &plaintext, aad: aad.as_bytes() },
            )
            .map_err(|_| "could not seal the file list".to_string())?;
        let mut blob = nonce_bytes.to_vec();
        blob.extend_from_slice(&sealed);
        Ok(URL_SAFE_NO_PAD.encode(blob))
    }

    /// The file list sealed for `link_id`, or `None` when the blob is not one this code sealed for
    /// that link (wrong code, wrong link, altered or malformed).
    pub fn open_preview(&self, link_id: &str, blob: &str) -> Option<Vec<(String, u64)>> {
        let raw = URL_SAFE_NO_PAD.decode(blob).ok()?;
        if raw.len() < NONCE_LEN + 16 {
            return None;
        }
        let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
        let aad = format!("{AAD_PREFIX}{link_id}");
        let plaintext = self
            .cipher()
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: aad.as_bytes() })
            .ok()?;
        parse_entries(&plaintext)
    }
}

/// The file list inside a sealed preview. The sender holds the key, so its contents are the
/// sender's claim and are parsed as untrusted.
fn parse_entries(plaintext: &[u8]) -> Option<Vec<(String, u64)>> {
    #[derive(serde::Deserialize)]
    struct Entry {
        name: String,
        size: u64,
    }
    let entries: Vec<Entry> = serde_json::from_slice(plaintext).ok()?;
    Some(entries.into_iter().map(|e| (e.name, e.size)).collect())
}

/// The untrusted-input entry points, for the fuzz targets only.
#[cfg(fuzzing)]
pub fn fuzz_entry(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some(code) = SendLinkCode::parse(text) {
            let _ = code.display();
            let _ = code.token_hash_hex();
            let _ = code.open_preview("link", text);
        }
    }
    let _ = parse_entries(data);
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<(String, u64)> {
        vec![("report.pdf".to_string(), 1234), ("photos/a.jpg".to_string(), 99)]
    }

    #[test]
    fn a_minted_code_round_trips_through_its_display_form() {
        let code = SendLinkCode::mint();
        let shown = code.display();
        assert_eq!(shown.len(), 34 + 8);
        assert_eq!(SendLinkCode::parse(&shown), Some(code.clone()));
        assert_eq!(SendLinkCode::parse(&shown.to_lowercase().replace('-', " ")), Some(code));
    }

    #[test]
    fn anything_that_is_not_exactly_a_code_is_refused() {
        let shown = SendLinkCode::mint().display();
        assert!(SendLinkCode::parse("").is_none());
        assert!(SendLinkCode::parse(&shown[..shown.len() - 1]).is_none());
        assert!(SendLinkCode::parse(&format!("{shown}A")).is_none());
        assert!(SendLinkCode::parse(&shown.replacen(&shown[..1], "1", 1)).is_none());
    }

    #[test]
    fn the_token_and_its_hash_depend_on_the_whole_code_and_differ_from_it() {
        let a = SendLinkCode::mint();
        let b = SendLinkCode::mint();
        assert_ne!(a.token_hex(), b.token_hex());
        assert_ne!(a.token_hex(), a.token_hash_hex());
        assert_eq!(a.token_hex().len(), 64);
        assert_eq!(a.token_hash_hex().len(), 64);
        let secret = &a.display().replace('-', "")[LOOKUP_LEN..];
        assert!(!a.token_hex().to_uppercase().contains(secret));
    }

    #[test]
    fn a_sealed_list_opens_with_the_same_code_and_link() {
        let code = SendLinkCode::mint();
        let blob = code.seal_preview("link-1", &files()).unwrap();
        assert_eq!(code.open_preview("link-1", &blob), Some(files()));
    }

    #[test]
    fn the_blob_holds_no_plaintext_name() {
        let code = SendLinkCode::mint();
        let blob = code.seal_preview("link-1", &files()).unwrap();
        let raw = URL_SAFE_NO_PAD.decode(&blob).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains("report"));
        assert!(!blob.contains("report"));
    }

    #[test]
    fn a_wrong_code_wrong_link_or_altered_blob_does_not_open() {
        let code = SendLinkCode::mint();
        let blob = code.seal_preview("link-1", &files()).unwrap();
        assert!(SendLinkCode::mint().open_preview("link-1", &blob).is_none());
        // Same secret, different lookup id: a different key.
        let other_lookup =
            SendLinkCode { lookup_id: "AAAAAAAA".into(), secret: code.secret.clone() };
        assert!(other_lookup.open_preview("link-1", &blob).is_none());
        assert!(code.open_preview("link-2", &blob).is_none());
        let mut raw = URL_SAFE_NO_PAD.decode(&blob).unwrap();
        for index in [0, NONCE_LEN, raw.len() - 1] {
            raw[index] ^= 1;
            assert!(code.open_preview("link-1", &URL_SAFE_NO_PAD.encode(&raw)).is_none());
            raw[index] ^= 1;
        }
        assert!(code
            .open_preview("link-1", &URL_SAFE_NO_PAD.encode(&raw[..raw.len() - 1]))
            .is_none());
        assert!(code.open_preview("link-1", "").is_none());
        assert!(code.open_preview("link-1", "not base64!").is_none());
    }

    #[test]
    fn the_blob_length_shows_the_list_size_only_to_the_kilobyte() {
        let code = SendLinkCode::mint();
        let one = code.seal_preview("link-1", &files()[..1]).unwrap();
        let two = code.seal_preview("link-1", &files()).unwrap();
        assert_eq!(one.len(), two.len());
        let raw = URL_SAFE_NO_PAD.decode(&one).unwrap();
        assert_eq!(raw.len(), NONCE_LEN + PAD_TO + 16);
    }

    #[test]
    fn derivation_matches_fixed_vectors() {
        // Computed independently (HKDF-SHA256 per RFC 5869 in another implementation).
        let code = SendLinkCode::parse("ABCDEFGH-ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        assert_eq!(
            code.token_hex(),
            "3bb2b41894959a2d5eff8d80bbb083654969129cdce5024916f7610b2c482703"
        );
        assert_eq!(
            hex(&code.derive("preview-key")),
            "63ab4bea9f9e5a63275757ff27e7b895b4e65506c7a96b6a2a09aeae43c9ebf7"
        );
        assert_eq!(
            code.token_hash_hex(),
            "9d3e0229dbaf0a032efb83a9c9600a4fea5b1205e781e22dcbf8dccfa519fa39"
        );
    }

    #[test]
    fn two_seals_of_the_same_list_differ() {
        let code = SendLinkCode::mint();
        assert_ne!(
            code.seal_preview("link-1", &files()).unwrap(),
            code.seal_preview("link-1", &files()).unwrap()
        );
    }

    #[test]
    fn debug_output_never_shows_the_code() {
        let code = SendLinkCode::mint();
        let debug = format!("{code:?} {:?}", Some(&code));
        assert!(!debug.contains(code.lookup_id()));
        assert!(!debug.contains(&code.secret));
    }
}
