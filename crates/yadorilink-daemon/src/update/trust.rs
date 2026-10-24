//! The update trust set: which manifest-signing keys a client accepts, and
//! how that set changes without shipping a new binary.
//!
//! A build compiles in a *genesis* key set (`manifest::TRUSTED_KEYS`). From
//! there the set only changes through an append-only chain of signed
//! [`SignedTrustRecord`]s:
//!
//! * record `n` must be signed by a key that is trusted *at that point in the
//!   chain* (genesis keys, plus earlier additions, minus earlier revocations),
//!   so every key is chained back to the compiled-in root;
//! * serials are strictly sequential, so a record cannot be skipped, reordered
//!   or replayed;
//! * a record adds keys and/or revokes key ids. A revoked key never verifies
//!   again, and neither does the same public key under a new id;
//! * a record cannot revoke its own signer, and the set can never become empty.
//!
//! Planned rotation: a record signed by the current key adds the next key;
//! manifests are signed by either key during the overlap; a later record
//! signed by the next key revokes the old one. Emergency revocation is the
//! same record signed by any still-trusted key.
//!
//! The chain rides on the manifest envelope (`trust_chain`), so no new
//! endpoint is needed. Each record is individually signed, so the unsigned
//! envelope wrapper carries no trust. The client persists the longest chain it
//! has verified ([`TrustStore`]) and replays it from the compiled-in root at
//! every check, so a stripped or replayed chain can never un-revoke a key and
//! a tampered persisted chain fails closed.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::manifest::{is_placeholder_public_key, TrustedKey};

pub const TRUST_RECORD_SCHEMA_VERSION: u32 = 1;
/// Upper bound on chain length. Rotations are rare; a bound keeps a hostile
/// host from making clients replay or store an unbounded chain.
pub const MAX_CHAIN_LEN: usize = 64;
/// Domain separation: a trust-record signature is made over this prefix plus
/// the record bytes, so a signature over a manifest body can never be replayed
/// as a trust record (or the reverse).
pub const TRUST_RECORD_DOMAIN: &[u8] = b"yadorilink-trust-record-v1\n";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    #[error("trust record is malformed: {0}")]
    Malformed(String),
    #[error("trust record schema version {0} is not supported")]
    UnsupportedSchemaVersion(u32),
    #[error("trust record signed by key '{0}', which is not trusted at that point")]
    SignerNotTrusted(String),
    #[error("trust record signed by revoked key '{0}'")]
    SignerRevoked(String),
    #[error("trust record signature is invalid")]
    SignatureInvalid,
    #[error("trust record serial {found} is out of sequence (expected {expected})")]
    BadSerial { expected: u64, found: u64 },
    #[error("trust record adds invalid key '{0}'")]
    InvalidKey(String),
    #[error("trust record adds key '{0}', which is or was already in the trust set")]
    DuplicateKey(String),
    #[error("trust record revokes '{0}', which is not an active key")]
    RevokeUnknown(String),
    #[error("trust record revokes its own signer '{0}'")]
    SelfRevoke(String),
    #[error("trust record changes nothing")]
    Empty,
    #[error("trust record would leave no active key")]
    NoActiveKeys,
    #[error("trust chain is longer than {MAX_CHAIN_LEN} records")]
    ChainTooLong,
    #[error("offered trust chain conflicts with the persisted chain at serial {0}")]
    Conflict(u64),
    #[error("trust chain storage failed: {0}")]
    Storage(String),
}

/// A trust record as published: the exact signed bytes plus the signature,
/// mirroring `SignedManifestEnvelope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTrustRecord {
    pub key_id: String,
    pub record_json: String,
    /// Standard base64 of the raw 64-byte Ed25519 signature over
    /// [`TRUST_RECORD_DOMAIN`] followed by `record_json`.
    pub signature_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    pub key_id: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRecord {
    pub schema_version: u32,
    pub serial: u64,
    #[serde(default)]
    pub add: Vec<KeyEntry>,
    #[serde(default)]
    pub revoke: Vec<String>,
}

/// The bytes a trust-record signature covers.
pub fn signing_bytes(record_json: &str) -> Vec<u8> {
    let mut bytes = TRUST_RECORD_DOMAIN.to_vec();
    bytes.extend_from_slice(record_json.as_bytes());
    bytes
}

/// The keys currently trusted and the keys permanently revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustState {
    pub serial: u64,
    active: Vec<KeyEntry>,
    revoked: Vec<KeyEntry>,
}

fn normalize_hex(hex: &str) -> String {
    hex.trim().to_ascii_lowercase()
}

pub(crate) fn decode_verifying_key(public_key_hex: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(public_key_hex.trim()).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

impl TrustState {
    /// The state a build starts from: only its compiled-in keys.
    pub fn genesis(keys: &[TrustedKey]) -> Self {
        TrustState {
            serial: 0,
            active: keys
                .iter()
                .map(|k| KeyEntry {
                    key_id: k.key_id.to_string(),
                    public_key_hex: normalize_hex(k.public_key_hex),
                })
                .collect(),
            revoked: Vec::new(),
        }
    }

    /// Replays `chain` over the genesis keys, failing on the first record that
    /// does not verify.
    pub fn replay(keys: &[TrustedKey], chain: &[SignedTrustRecord]) -> Result<Self, TrustError> {
        if chain.len() > MAX_CHAIN_LEN {
            return Err(TrustError::ChainTooLong);
        }
        let mut state = Self::genesis(keys);
        for record in chain {
            state.apply(record)?;
        }
        Ok(state)
    }

    pub fn active_public_key(&self, key_id: &str) -> Option<&str> {
        self.active.iter().find(|k| k.key_id == key_id).map(|k| k.public_key_hex.as_str())
    }

    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked.iter().any(|k| k.key_id == key_id)
    }

    pub fn active_key_ids(&self) -> Vec<&str> {
        self.active.iter().map(|k| k.key_id.as_str()).collect()
    }

    /// Verifies and applies one record. On error the state is unchanged.
    pub fn apply(&mut self, signed: &SignedTrustRecord) -> Result<(), TrustError> {
        if self.serial as usize >= MAX_CHAIN_LEN {
            return Err(TrustError::ChainTooLong);
        }
        let signer_hex = match self.active_public_key(&signed.key_id) {
            Some(hex) => hex.to_string(),
            None if self.is_revoked(&signed.key_id) => {
                return Err(TrustError::SignerRevoked(signed.key_id.clone()));
            }
            None => return Err(TrustError::SignerNotTrusted(signed.key_id.clone())),
        };
        let signer_key = decode_verifying_key(&signer_hex)
            .ok_or_else(|| TrustError::SignerNotTrusted(signed.key_id.clone()))?;
        use base64::Engine;
        let signature: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(&signed.signature_base64)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(TrustError::SignatureInvalid)?;
        signer_key
            .verify(&signing_bytes(&signed.record_json), &Signature::from_bytes(&signature))
            .map_err(|_| TrustError::SignatureInvalid)?;

        let record: TrustRecord = serde_json::from_str(&signed.record_json)
            .map_err(|e| TrustError::Malformed(e.to_string()))?;
        if record.schema_version != TRUST_RECORD_SCHEMA_VERSION {
            return Err(TrustError::UnsupportedSchemaVersion(record.schema_version));
        }
        let expected = self.serial + 1;
        if record.serial != expected {
            return Err(TrustError::BadSerial { expected, found: record.serial });
        }
        if record.add.is_empty() && record.revoke.is_empty() {
            return Err(TrustError::Empty);
        }
        if record.revoke.contains(&signed.key_id) {
            return Err(TrustError::SelfRevoke(signed.key_id.clone()));
        }

        let mut next = self.clone();
        for key in &record.add {
            let public_key_hex = normalize_hex(&key.public_key_hex);
            if key.key_id.trim().is_empty()
                || key.key_id != key.key_id.trim()
                || decode_verifying_key(&public_key_hex).is_none()
                || is_placeholder_public_key(&public_key_hex)
            {
                return Err(TrustError::InvalidKey(key.key_id.clone()));
            }
            let seen = next.active.iter().chain(next.revoked.iter());
            if seen
                .into_iter()
                .any(|k| k.key_id == key.key_id || k.public_key_hex == public_key_hex)
            {
                return Err(TrustError::DuplicateKey(key.key_id.clone()));
            }
            next.active.push(KeyEntry { key_id: key.key_id.clone(), public_key_hex });
        }
        for id in &record.revoke {
            let at = next
                .active
                .iter()
                .position(|k| k.key_id == *id)
                .ok_or_else(|| TrustError::RevokeUnknown(id.clone()))?;
            let key = next.active.remove(at);
            next.revoked.push(key);
        }
        if next.active.is_empty() {
            return Err(TrustError::NoActiveKeys);
        }
        next.serial = expected;
        *self = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaveStep {
    TempWritten,
    TempSynced,
    Published,
}

/// Persists the longest verified trust chain next to the update policy.
pub struct TrustStore {
    path: PathBuf,
    /// Held across the whole load, verify and save in `sync`: the manager is
    /// shared by the periodic check and manual checks, and an unserialized
    /// shorter extension could overwrite a longer chain and un-revoke a key.
    sync_lock: std::sync::Mutex<()>,
}

impl TrustStore {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        TrustStore {
            path: config_dir.as_ref().join("update_trust_chain.json"),
            sync_lock: std::sync::Mutex::new(()),
        }
    }

    fn load_chain(&self) -> Result<Vec<SignedTrustRecord>, TrustError> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|e| TrustError::Storage(format!("persisted chain is unreadable: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(TrustError::Storage(e.to_string())),
        }
    }

    /// Persists `chain` so that a crash at any step leaves either the previous
    /// complete chain or the new complete chain, never a torn or missing one:
    /// the directory is created durably, the chain is written to a sibling
    /// temporary file and fsynced, then published over the target by a durable
    /// move (rename plus a sync of the parent directory). An error means the
    /// chain is NOT known to be persisted, and `sync` then refuses the check
    /// instead of acting on a revocation that a restart could forget.
    fn save_chain(&self, chain: &[SignedTrustRecord]) -> Result<(), TrustError> {
        self.save_chain_with(chain, &mut |_| Ok(())).map_err(|e| TrustError::Storage(e.to_string()))
    }

    fn save_chain_with(
        &self,
        chain: &[SignedTrustRecord],
        after: &mut dyn FnMut(SaveStep) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        use std::io::Write;

        use yadorilink_fs_platform::durable_dir::{
            create_dir_all_durably, publish_durably, Replace,
        };

        if let Some(parent) = self.path.parent() {
            create_dir_all_durably(parent)?;
        }
        let json = serde_json::to_string_pretty(chain).map_err(std::io::Error::other)?;
        let tmp = self.temp_path();
        // The temporary has one fixed name and is truncated here, so a torn
        // leftover from a crash or failed save is never read (load only reads
        // the chain file) and is overwritten by the next save.
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(json.as_bytes())?;
        after(SaveStep::TempWritten)?;
        yadorilink_fs_platform::flush::sync_file(&file)?;
        drop(file);
        after(SaveStep::TempSynced)?;
        publish_durably(&tmp, &self.path, Replace::Yes)?;
        after(SaveStep::Published)
    }

    fn temp_path(&self) -> PathBuf {
        self.path.with_file_name(".update_trust_chain.json.tmp")
    }

    /// The effective trust state for one check: the persisted chain replayed
    /// over `genesis`, extended by whatever longer verified chain the server
    /// `offered`. A shorter or empty offer changes nothing (so a stripped or
    /// replayed chain cannot un-revoke a key); an offer that disagrees with
    /// the persisted chain, or an extension that does not verify, is an error.
    /// A persisted chain that no longer verifies is also an error: the client
    /// refuses every manifest rather than fall back to a larger trust set.
    pub fn sync(
        &self,
        genesis: &[TrustedKey],
        offered: &[SignedTrustRecord],
    ) -> Result<TrustState, TrustError> {
        // A poisoned lock only means another sync panicked; the file on disk
        // is replaced atomically, so continuing is safe.
        let _serialized = self.sync_lock.lock().unwrap_or_else(|e| e.into_inner());
        let persisted = self.load_chain()?;
        let mut state = TrustState::replay(genesis, &persisted)?;
        for (i, (kept, new)) in persisted.iter().zip(offered).enumerate() {
            if kept != new {
                return Err(TrustError::Conflict(i as u64 + 1));
            }
        }
        if offered.len() > persisted.len() {
            if offered.len() > MAX_CHAIN_LEN {
                return Err(TrustError::ChainTooLong);
            }
            for record in &offered[persisted.len()..] {
                state.apply(record)?;
            }
            // Fail closed: `state` is a local, so a failed save leaves nothing
            // advanced, and the error refuses the check rather than accepting
            // a manifest under a revocation that is not on disk.
            self.save_chain(offered)?;
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests;
