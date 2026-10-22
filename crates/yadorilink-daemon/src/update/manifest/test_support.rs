#![cfg(test)]

//! Test-only helpers for signing a manifest with a throwaway keypair
//! instead of `TRUSTED_KEYS`'s real (dev-placeholder) key — used by
//! this module's own tests and by `policy`/`manager` tests elsewhere
//! in this crate that need a realistic signed-envelope fixture.
use super::*;
use ed25519_dalek::{Signer, SigningKey};

pub const TEST_KEY_ID: &str = "test-key-1";

pub fn test_signing_key() -> SigningKey {
    // Fixed, obviously-not-secret seed: deterministic test fixtures,
    // never used outside `#[cfg(test)]`.
    SigningKey::from_bytes(&[7u8; 32])
}

pub fn test_trusted_keys() -> Vec<(String, [u8; 32])> {
    vec![(TEST_KEY_ID.to_string(), test_signing_key().verifying_key().to_bytes())]
}

pub fn sign_manifest(manifest: &UpdateManifest) -> SignedManifestEnvelope {
    let manifest_json = serde_json::to_string(manifest).unwrap();
    let signing_key = test_signing_key();
    let signature = signing_key.sign(manifest_json.as_bytes());
    use base64::Engine;
    SignedManifestEnvelope {
        key_id: TEST_KEY_ID.to_string(),
        manifest_json,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        trust_chain: Vec::new(),
    }
}

/// Turns `test_trusted_keys()`'s `(String, [u8; 32])` pairs into real
/// `TrustedKey`s a verifier can use. `TrustedKey.public_key_hex` is
/// `&'static str`; leaking the hex string is fine for a
/// `#[cfg(test)]`-only helper that runs a bounded number of times per
/// test binary.
pub fn trusted_keys_hex(keys: &[(String, [u8; 32])]) -> Vec<TrustedKey> {
    keys.iter()
        .map(|(id, pk)| TrustedKey {
            key_id: Box::leak(id.clone().into_boxed_str()),
            public_key_hex: Box::leak(hex::encode(pk).into_boxed_str()),
        })
        .collect()
}

/// Deterministic, obviously-not-secret key `n` for rotation tests.
pub fn numbered_key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

pub fn public_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// A genesis key set holding the given `(key_id, key)` pairs.
pub fn genesis_of(keys: &[(&str, &SigningKey)]) -> Vec<TrustedKey> {
    keys.iter()
        .map(|(id, key)| TrustedKey {
            key_id: Box::leak(id.to_string().into_boxed_str()),
            public_key_hex: Box::leak(public_hex(key).into_boxed_str()),
        })
        .collect()
}

pub fn sign_record(
    key: &SigningKey,
    key_id: &str,
    serial: u64,
    add: &[(&str, &SigningKey)],
    revoke: &[&str],
) -> super::super::trust::SignedTrustRecord {
    use super::super::trust::{self, KeyEntry, SignedTrustRecord, TrustRecord};
    let record = TrustRecord {
        schema_version: trust::TRUST_RECORD_SCHEMA_VERSION,
        serial,
        add: add
            .iter()
            .map(|(id, k)| KeyEntry { key_id: id.to_string(), public_key_hex: public_hex(k) })
            .collect(),
        revoke: revoke.iter().map(|s| s.to_string()).collect(),
    };
    let record_json = serde_json::to_string(&record).unwrap();
    let signature = key.sign(&trust::signing_bytes(&record_json));
    use base64::Engine;
    SignedTrustRecord {
        key_id: key_id.to_string(),
        record_json,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    }
}

pub fn sign_manifest_as(
    key: &SigningKey,
    key_id: &str,
    manifest: &UpdateManifest,
    trust_chain: Vec<super::super::trust::SignedTrustRecord>,
) -> SignedManifestEnvelope {
    let manifest_json = serde_json::to_string(manifest).unwrap();
    let signature = key.sign(manifest_json.as_bytes());
    use base64::Engine;
    SignedManifestEnvelope {
        key_id: key_id.to_string(),
        manifest_json,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        trust_chain,
    }
}
