//! The durable rebootstrap target and its local verification.
//!
//! A target bundle is verified against the live policy once, when it is
//! obtained. What that verification was answered from is recorded with the
//! bundle ([`PolicyAnswers`]), together with a verification record that says the
//! target may be used for the destructive install. After a restart the target is
//! verified again from the stored bytes and the stored answers alone: no peer,
//! no authority and no live policy are consulted, so a target that was accepted
//! is not rejected because nobody can be reached or because the policy has moved
//! on since. The live policy decides only which local changes may still be
//! authored.

use std::cell::RefCell;

use serde_json::{Map, Value};

use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::native_checkpoint_seal::{NativeSealPolicy, SealPolicyPoint};

use crate::native_bootstrap::{verify_native_bootstrap, NativeBootstrap, VerifiedNativeBootstrap};
use crate::native_bootstrap_codec::{decode_recovery_bundle, encode_recovery_bundle};
use crate::native_rebootstrap_recovery::{parse_hex32, sha256};

/// Why a target could not be stored or could not be verified from what is stored.
#[derive(Debug, PartialEq, Eq)]
pub enum TargetError {
    /// The bundle cannot be stored in the recovery format.
    NotStorable(String),
    /// The stored target does not verify from the stored material.
    NotVerifiable(String),
    /// The record does not permit the install, or does not match the stored files.
    NotPermitted(String),
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStorable(d) => write!(f, "target not storable: {d}"),
            Self::NotVerifiable(d) => write!(f, "target not verifiable: {d}"),
            Self::NotPermitted(d) => write!(f, "target install not permitted: {d}"),
        }
    }
}

impl std::error::Error for TargetError {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Answer {
    AuthorityKey { key_id: [u8; 32], head: [u8; 32], key: Option<[u8; 32]> },
    Writer { device: String, fingerprint: [u8; 32], point: PointKey, answer: bool },
}

type PointKey = (u64, u64, [u8; 32]);

fn point_key(point: &SealPolicyPoint) -> PointKey {
    (point.epoch, point.seq, point.head)
}

/// The answers a verification got from the policy it ran against: the public
/// authority key each lookup resolved to, and whether the writer held at each
/// policy point. Replayed, it is a policy that knows
/// exactly what was asked then and nothing else.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyAnswers {
    answers: Vec<Answer>,
}

impl PolicyAnswers {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut sorted = self.answers.clone();
        sorted.sort();
        sorted.dedup();
        let entries: Vec<Value> = sorted.iter().map(answer_value).collect();
        let mut map = Map::new();
        map.insert("format_version".into(), Value::from(1u64));
        map.insert("answers".into(), Value::Array(entries));
        let mut out = Vec::new();
        crate::native_rebootstrap_recovery::canonical_json_into(&Value::Object(map), &mut out);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TargetError> {
        let bad = |d: &str| TargetError::NotVerifiable(format!("verification material: {d}"));
        let value: Value = serde_json::from_slice(bytes).map_err(|e| bad(&e.to_string()))?;
        let list =
            value.get("answers").and_then(Value::as_array).ok_or_else(|| bad("no answers"))?;
        let answers = list
            .iter()
            .map(|entry| parse_answer(entry).ok_or_else(|| bad("an answer is malformed")))
            .collect::<Result<_, _>>()?;
        Ok(Self { answers })
    }
}

fn hex_of(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

fn point_value(point: &PointKey) -> Value {
    let mut map = Map::new();
    map.insert("epoch".into(), Value::from(point.0));
    map.insert("seq".into(), Value::from(point.1));
    map.insert("head".into(), hex_of(&point.2));
    Value::Object(map)
}

fn answer_value(answer: &Answer) -> Value {
    let mut map = Map::new();
    match answer {
        Answer::AuthorityKey { key_id, head, key } => {
            map.insert("kind".into(), Value::String("authority_key".into()));
            map.insert("key_id".into(), hex_of(key_id));
            map.insert("head".into(), hex_of(head));
            map.insert("key".into(), key.as_ref().map_or(Value::Null, |k| hex_of(k)));
        }
        Answer::Writer { device, fingerprint, point, answer } => {
            map.insert("kind".into(), Value::String("writer".into()));
            map.insert("device".into(), Value::String(device.clone()));
            map.insert("fingerprint".into(), hex_of(fingerprint));
            map.insert("point".into(), point_value(point));
            map.insert("answer".into(), Value::Bool(*answer));
        }
    }
    Value::Object(map)
}

fn hex32_field(map: &Value, key: &str) -> Option<[u8; 32]> {
    parse_hex32(map.get(key)?.as_str()?).ok()
}

fn parse_point(value: &Value) -> Option<PointKey> {
    let point = value.get("point")?;
    Some((point.get("epoch")?.as_u64()?, point.get("seq")?.as_u64()?, hex32_field(point, "head")?))
}

fn parse_answer(entry: &Value) -> Option<Answer> {
    match entry.get("kind")?.as_str()? {
        "authority_key" => Some(Answer::AuthorityKey {
            key_id: hex32_field(entry, "key_id")?,
            head: hex32_field(entry, "head")?,
            key: match entry.get("key")? {
                Value::Null => None,
                other => Some(parse_hex32(other.as_str()?).ok()?),
            },
        }),
        "writer" => Some(Answer::Writer {
            device: entry.get("device")?.as_str()?.to_owned(),
            fingerprint: hex32_field(entry, "fingerprint")?,
            point: parse_point(entry)?,
            answer: entry.get("answer")?.as_bool()?,
        }),
        _ => None,
    }
}

impl NativeSealPolicy for PolicyAnswers {
    fn resolve_authority_key(
        &self,
        signer_key_id: &[u8; 32],
        policy_head: &[u8; 32],
    ) -> Option<ed25519_dalek::VerifyingKey> {
        self.answers.iter().find_map(|answer| match answer {
            Answer::AuthorityKey { key_id, head, key: Some(key) }
                if key_id == signer_key_id && head == policy_head =>
            {
                ed25519_dalek::VerifyingKey::from_bytes(key).ok()
            }
            _ => None,
        })
    }

    fn writer_at_policy_point(
        &self,
        device: &str,
        signing_key_fingerprint: &[u8; 32],
        point: &SealPolicyPoint,
    ) -> bool {
        self.answers.iter().any(|answer| {
            matches!(answer, Answer::Writer { device: d, fingerprint, point: p, answer: true }
                if d == device && fingerprint == signing_key_fingerprint && *p == point_key(point))
        })
    }
}

/// A policy that passes every question to `inner` and remembers the answers.
pub struct RecordingPolicy<'a> {
    inner: &'a dyn NativeSealPolicy,
    log: RefCell<Vec<Answer>>,
}

impl<'a> RecordingPolicy<'a> {
    pub fn new(inner: &'a dyn NativeSealPolicy) -> Self {
        Self { inner, log: RefCell::new(Vec::new()) }
    }

    pub fn into_answers(self) -> PolicyAnswers {
        PolicyAnswers { answers: self.log.into_inner() }
    }
}

impl NativeSealPolicy for RecordingPolicy<'_> {
    fn resolve_authority_key(
        &self,
        signer_key_id: &[u8; 32],
        policy_head: &[u8; 32],
    ) -> Option<ed25519_dalek::VerifyingKey> {
        let key = self.inner.resolve_authority_key(signer_key_id, policy_head);
        self.log.borrow_mut().push(Answer::AuthorityKey {
            key_id: *signer_key_id,
            head: *policy_head,
            key: key.as_ref().map(|k| k.to_bytes()),
        });
        key
    }

    fn writer_at_policy_point(
        &self,
        device: &str,
        signing_key_fingerprint: &[u8; 32],
        point: &SealPolicyPoint,
    ) -> bool {
        let answer = self.inner.writer_at_policy_point(device, signing_key_fingerprint, point);
        self.log.borrow_mut().push(Answer::Writer {
            device: device.to_owned(),
            fingerprint: *signing_key_fingerprint,
            point: point_key(point),
            answer,
        });
        answer
    }
}

/// What is stored for a target before the root is first modified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTarget {
    pub bundle: Vec<u8>,
    pub bundle_sha256: [u8; 32],
    pub material: Vec<u8>,
    pub record: Vec<u8>,
    pub checkpoint_hash: [u8; 32],
}

/// The local verification record: the target may be used for the destructive
/// install.
struct Record {
    checkpoint_hash: [u8; 32],
    policy_seq: u64,
    policy_head: [u8; 32],
    material_sha256: [u8; 32],
    bundle_sha256: [u8; 32],
    install_permitted: bool,
}

impl Record {
    fn to_bytes(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert("format_version".into(), Value::from(1u64));
        map.insert("checkpoint_hash".into(), hex_of(&self.checkpoint_hash));
        map.insert("policy_seq".into(), Value::from(self.policy_seq));
        map.insert("policy_head".into(), hex_of(&self.policy_head));
        map.insert("material_sha256".into(), hex_of(&self.material_sha256));
        map.insert("bundle_sha256".into(), hex_of(&self.bundle_sha256));
        map.insert("install_permitted".into(), Value::Bool(self.install_permitted));
        let mut out = Vec::new();
        crate::native_rebootstrap_recovery::canonical_json_into(&Value::Object(map), &mut out);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        Some(Self {
            checkpoint_hash: hex32_field(&value, "checkpoint_hash")?,
            policy_seq: value.get("policy_seq")?.as_u64()?,
            policy_head: hex32_field(&value, "policy_head")?,
            material_sha256: hex32_field(&value, "material_sha256")?,
            bundle_sha256: hex32_field(&value, "bundle_sha256")?,
            install_permitted: value.get("install_permitted")?.as_bool()?,
        })
    }
}

/// Verifies `bundle` against `policy`, remembering what the policy answered, and
/// returns what must be stored with the target: the exact bundle bytes, the
/// answers and a record that permits the install. The record exists only because
/// the stored bytes verified again from the stored answers alone.
pub fn verify_and_prepare_target(
    bundle: NativeBootstrap,
    group: &FolderGroupId,
    policy: &dyn NativeSealPolicy,
) -> Result<(VerifiedNativeBootstrap, StoredTarget), crate::error::SyncSqliteError> {
    let bytes = encode_recovery_bundle(&bundle).map_err(|e| {
        crate::error::SyncSqliteError::InvalidInput(format!("target not storable: {e:?}"))
    })?;
    let recording = RecordingPolicy::new(policy);
    let verified = verify_native_bootstrap(bundle, group, &recording)?;
    let answers = recording.into_answers();
    let SealPolicyPoint { seq: policy_seq, head: policy_head, .. } = verified.seal_policy_point();
    let material = answers.to_bytes();
    let bundle_sha256 = sha256(&bytes);
    let record = Record {
        checkpoint_hash: verified.checkpoint_hash(),
        policy_seq,
        policy_head,
        material_sha256: sha256(&material),
        bundle_sha256,
        install_permitted: true,
    }
    .to_bytes();
    let stored = StoredTarget {
        bundle: bytes,
        bundle_sha256,
        material,
        record,
        checkpoint_hash: verified.checkpoint_hash(),
    };
    // The record is only as good as the restart's verification: run it now.
    verify_stored_target(group, &stored).map_err(|e| {
        crate::error::SyncSqliteError::InvalidInput(format!(
            "the stored target would not verify: {e}"
        ))
    })?;
    Ok((verified, stored))
}

/// Verifies a stored target from what is stored alone.
pub fn verify_stored_target(
    group: &FolderGroupId,
    stored: &StoredTarget,
) -> Result<VerifiedNativeBootstrap, TargetError> {
    let record = Record::from_bytes(&stored.record)
        .ok_or_else(|| TargetError::NotPermitted("the verification record is unreadable".into()))?;
    if !record.install_permitted {
        return Err(TargetError::NotPermitted("the record does not permit the install".into()));
    }
    if sha256(&stored.bundle) != record.bundle_sha256
        || record.bundle_sha256 != stored.bundle_sha256
    {
        return Err(TargetError::NotPermitted("the bundle is not the one verified".into()));
    }
    if sha256(&stored.material) != record.material_sha256 {
        return Err(TargetError::NotPermitted(
            "the verification material is not the one recorded".into(),
        ));
    }
    let answers = PolicyAnswers::from_bytes(&stored.material)?;
    let bundle = decode_recovery_bundle(&stored.bundle)
        .map_err(|e| TargetError::NotVerifiable(format!("the bundle does not decode: {e:?}")))?;
    let verified = verify_native_bootstrap(bundle, group, &answers)
        .map_err(|e| TargetError::NotVerifiable(e.to_string()))?;
    if verified.checkpoint_hash() != record.checkpoint_hash {
        return Err(TargetError::NotPermitted("the checkpoint is not the one recorded".into()));
    }
    Ok(verified)
}

/// The checkpoint hash a stored target's record names.
pub fn recorded_checkpoint_hash(record: &[u8]) -> Option<[u8; 32]> {
    Record::from_bytes(record).map(|r| r.checkpoint_hash)
}

/// The policy sequence and head the record was verified against.
pub fn recorded_policy_point(record: &[u8]) -> Option<(u64, [u8; 32])> {
    Record::from_bytes(record).map(|r| (r.policy_seq, r.policy_head))
}
