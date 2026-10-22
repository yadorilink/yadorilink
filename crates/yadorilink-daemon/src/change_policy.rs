//! Client-side verifier for the signed group policy log carried in netmap
//! updates. This mirrors the coordination plane's canonical record encoding
//! using plain data types owned here, so verification has no dependency on
//! the coordination plane's transport or wire format.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use yadorilink_replica_engine::authorized_writer::AuthorizedWriter;
use yadorilink_sync_sqlite::policy_watermark::PolicyWatermark;

/// A group's signed policy log as delivered by the coordination plane in a
/// netmap update. Plain data the netmap client fills from the coordination
/// plane's response; verified below against the pinned service key.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GroupPolicyLog {
    pub group_id: String,
    pub current_seq: u64,
    pub current_epoch: u64,
    /// 32-byte hash of the latest record (zero if none).
    pub policy_head: Vec<u8>,
    pub records: Vec<PolicyRecord>,
}

/// One signed entry in a group's policy log. Field layout matches the
/// coordination plane's canonical record so the signing-bytes computation
/// below reproduces exactly what the signer hashed.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PolicyRecord {
    pub group_id: String,
    pub seq: u64,
    /// 32 bytes; zero for the genesis record.
    pub prev_record_hash: Vec<u8>,
    /// 32 bytes; SHA-256(signing_bytes || signature).
    pub record_hash: Vec<u8>,
    /// `auth_epoch` after this record applies.
    pub epoch: u64,
    /// 0 Grant | 1 Revoke | 2 RotateAuthority | 3 Grant-with-role. See
    /// `ACTION_GRANT_WITH_ROLE`'s own doc comment for why this is a
    /// DISTINCT action type from plain Grant, not a role field bolted onto
    /// it.
    pub action_type: u32,
    /// Grant/Revoke.
    pub device_id: String,
    /// Grant only; 32 bytes (zero if the device has no signing key).
    pub signing_key_fingerprint: Vec<u8>,
    /// Grant only; 0=Viewer, 1=Editor, 2=Owner. See [`WriterRole`].
    pub role: u32,
    /// RotateAuthority only; 32 bytes.
    pub new_authority_key: Vec<u8>,
    /// 32-byte fingerprint of the signing authority key.
    pub signer_key_id: Vec<u8>,
    /// 64-byte Ed25519 over the signing bytes.
    pub signature: Vec<u8>,
}

const POLICY_DOMAIN_TAG: &[u8; 8] = b"ylpolic1";
const ACTION_REVOKE: u32 = 1;
const ACTION_ROTATE_AUTHORITY: u32 = 2;
/// A Grant record; its signing preimage ends with an explicit role byte.
/// Byte-for-byte contract with the coordination service
/// canonicalSigningBytes`.
///
/// Type 0 was the role-less Grant and is retired -- do not reuse the
/// discriminant. A role byte was once appended to type 0's preimage in place,
/// which silently broke the signature of every Grant already written: a shape
/// change must take a new action type, never extend an existing one.
pub(crate) const ACTION_GRANT_WITH_ROLE: u32 = 3;
const HASH_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const ZERO_HASH: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// A device's permission tier under one group's Grant. Read access (group
/// membership, block-serving, sync eligibility) is unaffected by this value
/// — that stays gated purely on group authorization, as it already was.
/// This value ONLY narrows which authorized devices [`GroupPolicyState`]
/// treats as WRITERS: `current_writers`/`writers_at` admit `Editor`/`Owner`
/// grants and exclude `Viewer` grants — checkpoint issuance (the sole write
/// authorization gate under `AuthorizationCheckpoint` admission)
/// refuses a Viewer, so a Viewer's
/// Change can never carry the evidence any peer requires to admit it.
/// `Owner` carries no
/// extra cryptographic weight over `Editor` in THIS verifier today (nothing
/// here yet distinguishes "may also manage grants" from "may write") — that
/// distinction belongs to whichever service issues Grant/Revoke/
/// RotateAuthority records (the coordination plane's policy service, the
/// sole holder of a group's authority key), not to this read-only verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WriterRole {
    Viewer,
    Editor,
    Owner,
}

impl WriterRole {
    /// Whether this role is treated as a writer by the `current_writers`/
    /// `writers_at` writer-set accessors.
    fn is_writer(self) -> bool {
        matches!(self, WriterRole::Editor | WriterRole::Owner)
    }

    pub fn to_wire(self) -> u32 {
        match self {
            WriterRole::Viewer => 0,
            WriterRole::Editor => 1,
            WriterRole::Owner => 2,
        }
    }

    pub fn from_wire(value: u32) -> Result<Self, String> {
        match value {
            0 => Ok(WriterRole::Viewer),
            1 => Ok(WriterRole::Editor),
            2 => Ok(WriterRole::Owner),
            other => Err(format!("policy record has invalid writer role {other}")),
        }
    }
}

/// One device this group's signed policy currently grants ANY access to --
/// Viewer, Editor, or Owner alike. Unlike [`AuthorizedWriter`] (which
/// [`GroupPolicyState::current_writers`]/`writers_at` narrow to Editor/Owner
/// only), this includes Viewer-role members: a Viewer is a real group member
/// even though its changes are never admitted as writes. `role` carries no
/// admission authority of its own here -- checkpoint issuance remains the
/// sole write-authorization check; this type exists purely to report
/// membership and role.
///
/// This type and [`GroupPolicyState::current_members`] have no production
/// consumer in this daemon today, and that is deliberate rather than an
/// oversight: the user-facing "people with access" listing is served by the
/// coordination plane, which folds the same policy log itself. What this
/// fold provides is a second, independent implementation to check that one
/// against -- see
/// `current_members_matches_the_ts_fold_currentroles_parity_fixture`, which
/// pins the two against one identical grant/revoke fixture. A listing that
/// disagreed with the verifier that actually admits or rejects a device's
/// changes would misreport exactly the state an operator relies on, so the
/// parity reference is the point; it is not dead code awaiting a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub device_id: String,
    pub role: WriterRole,
    pub signing_key_fingerprint: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicyAction {
    Grant { device_id: String, signing_key_fingerprint: [u8; HASH_LEN], role: WriterRole },
    Revoke { device_id: String },
    RotateAuthority { new_authority_key: [u8; HASH_LEN] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedPolicyRecord {
    seq: u64,
    prev_record_hash: [u8; HASH_LEN],
    record_hash: [u8; HASH_LEN],
    epoch: u64,
    signer_key_id: [u8; HASH_LEN],
    action: PolicyAction,
    signature: [u8; SIGNATURE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPolicyState {
    pub current_seq: u64,
    pub current_epoch: u64,
    pub policy_head: [u8; HASH_LEN],
    pub final_authority_key: [u8; HASH_LEN],
    /// How many `RotateAuthority` records the verified chain contains — a
    /// monotonic generation counter for the group's signing authority.
    /// Persisted alongside the rollback watermark so an older chain that
    /// predates a rotation can be recognized and rejected after a restart.
    pub authority_generation: u64,
    records: BTreeMap<u64, VerifiedPolicyRecord>,
    /// Every historical policy point this state has ever verified,
    /// mapped to the RAW authority key that was valid to verify the
    /// record AT that point — `record_hash(N) -> the authority_key value
    /// verify_group_policy_log_with_base's loop held BEFORE processing
    /// record N` (i.e. the key that actually signed record N, before any
    /// `RotateAuthority` effect record N itself might carry takes hold
    /// for N+1 onward), plus one entry for `ZERO_HASH -> service_public_key`
    /// covering the empty-chain bootstrap point. `final_authority_key`
    /// alone only ever answers "what is the CURRENT key" — this answers
    /// "what key was valid AT policy point P," which
    /// `resolve_authority_key` (used by
    /// `authorization_checkpoint::verify_change_admission`'s caller) needs:
    /// a checkpoint pins a specific historical `policy_head`, and the key
    /// that must have signed it is whichever key was in effect at THAT
    /// point, not whatever the chain's tip currently is.
    authority_key_history: BTreeMap<[u8; HASH_LEN], [u8; HASH_LEN]>,
}

/// The outcome of checking a freshly verified policy snapshot against the
/// persisted rollback watermark for its group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatermarkVerdict {
    /// The snapshot is at least as new as the watermark and continuous with
    /// it; adopt it and advance the persisted watermark to these coordinates.
    Accept(PolicyWatermark),
    /// The snapshot is a rollback, a fork, or an unrelated chain relative to
    /// the watermark; reject it (fail closed) and do not lower the watermark.
    Reject(String),
}

/// Why [`GroupPolicyState::writers_at`] refused to answer for a given seq.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterSnapshotError {
    /// `requested` is beyond `current`, this state's own verified position —
    /// the caller asked for a writer set at a policy point this device
    /// cannot yet vouch for.
    FutureSequence { requested: u64, current: u64 },
    /// `requested` falls within the verified range but has no record at
    /// that exact seq, which the chain's own gap-free construction should
    /// make impossible.
    MissingSequence { requested: u64 },
}

impl std::fmt::Display for WriterSnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriterSnapshotError::FutureSequence { requested, current } => write!(
                f,
                "writer snapshot requested at seq {requested}, beyond this state's verified seq {current}"
            ),
            WriterSnapshotError::MissingSequence { requested } => write!(
                f,
                "writer snapshot requested at seq {requested} has no verified record at that seq"
            ),
        }
    }
}

impl std::error::Error for WriterSnapshotError {}

impl GroupPolicyState {
    /// The full set of currently-authorized writers, replaying every
    /// Grant/Revoke in the verified chain up to `self.current_seq`. Cannot
    /// fail: `self.current_seq` is this state's own verified position, never
    /// a future or missing one. See [`Self::writers_at`] for reconstructing
    /// a specific historical seq's set instead.
    pub fn current_writers(&self) -> Vec<AuthorizedWriter> {
        self.writers_up_to(self.current_seq)
    }

    /// The authorized writer set as of a specific `auth_seq`. Sorted by
    /// `device_id` so any two devices that replay the same verified chain up
    /// to the same seq compute the identical `Vec`.
    ///
    /// Fails closed rather than silently substituting a different set:
    /// `auth_seq` beyond `self.current_seq` asks for a policy point this
    /// device cannot yet vouch for (this is NOT "the current set", even
    /// though replaying up to it would produce one), and `auth_seq` within
    /// `[1, current_seq]` with no verified record at that exact seq
    /// indicates the chain itself is broken (impossible for a chain that
    /// passed `verify_group_policy_log`'s gap-free sequencing check, but
    /// this does not re-trust that invariant here).
    pub fn writers_at(&self, auth_seq: u64) -> Result<Vec<AuthorizedWriter>, WriterSnapshotError> {
        if auth_seq > self.current_seq {
            return Err(WriterSnapshotError::FutureSequence {
                requested: auth_seq,
                current: self.current_seq,
            });
        }
        if auth_seq >= 1 && !self.records.contains_key(&auth_seq) {
            return Err(WriterSnapshotError::MissingSequence { requested: auth_seq });
        }
        Ok(self.writers_up_to(auth_seq))
    }

    fn writers_up_to(&self, auth_seq: u64) -> Vec<AuthorizedWriter> {
        let mut grants: BTreeMap<&str, ([u8; HASH_LEN], WriterRole)> = BTreeMap::new();
        for record in self.records.range(..=auth_seq).map(|(_, record)| record) {
            match &record.action {
                PolicyAction::Grant { device_id, signing_key_fingerprint, role, .. } => {
                    grants.insert(device_id.as_str(), (*signing_key_fingerprint, *role));
                }
                PolicyAction::Revoke { device_id } => {
                    grants.remove(device_id.as_str());
                }
                PolicyAction::RotateAuthority { .. } => {}
            }
        }
        // Viewer-role grants are group members but not writers -- excluded
        // here so this "writer set" accessor never hands a Viewer to
        // callers (repair-election candidate ranking, etc.) that assume
        // everything returned may legitimately author changes.
        grants
            .into_iter()
            .filter(|(_, (_, role))| role.is_writer())
            .map(|(device_id, (signing_key_fingerprint, _))| AuthorizedWriter {
                device_id: device_id.to_string(),
                signing_key_fingerprint,
            })
            .collect()
    }

    /// The full group membership as of `self.current_seq` -- Viewer, Editor,
    /// and Owner grants alike; unlike [`Self::current_writers`], a
    /// Viewer-role grant is included here, not excluded. Serves as the
    /// parity reference the coordination plane's own membership fold is
    /// checked against rather than as a caller in this daemon -- see
    /// [`GroupMember`]'s own doc comment. This is a strict superset of
    /// [`Self::writers_up_to`]'s own fold -- the identical grants map, the
    /// identical Grant/Revoke replay, just without that method's
    /// `is_writer()` filter -- so it inherits that fold's correctness
    /// rather than re-deriving it. Sorted by `device_id` (the `BTreeMap`'s
    /// own iteration order) for the same determinism reason `writers_at`'s
    /// own doc comment gives: any two devices that replay the same verified
    /// chain up to the same seq compute the identical `Vec`.
    pub fn current_members(&self) -> Vec<GroupMember> {
        self.members_up_to(self.current_seq)
    }

    /// The full group membership, with roles, as of `auth_seq`; refused on the
    /// same terms as [`Self::writers_at`].
    pub fn members_at(&self, auth_seq: u64) -> Result<Vec<GroupMember>, WriterSnapshotError> {
        if auth_seq > self.current_seq {
            return Err(WriterSnapshotError::FutureSequence {
                requested: auth_seq,
                current: self.current_seq,
            });
        }
        if auth_seq >= 1 && !self.records.contains_key(&auth_seq) {
            return Err(WriterSnapshotError::MissingSequence { requested: auth_seq });
        }
        Ok(self.members_up_to(auth_seq))
    }

    fn members_up_to(&self, auth_seq: u64) -> Vec<GroupMember> {
        let mut grants: BTreeMap<&str, ([u8; HASH_LEN], WriterRole)> = BTreeMap::new();
        for record in self.records.range(..=auth_seq).map(|(_, record)| record) {
            match &record.action {
                PolicyAction::Grant { device_id, signing_key_fingerprint, role, .. } => {
                    grants.insert(device_id.as_str(), (*signing_key_fingerprint, *role));
                }
                PolicyAction::Revoke { device_id } => {
                    grants.remove(device_id.as_str());
                }
                PolicyAction::RotateAuthority { .. } => {}
            }
        }
        grants
            .into_iter()
            .map(|(device_id, (signing_key_fingerprint, role))| GroupMember {
                device_id: device_id.to_string(),
                role,
                signing_key_fingerprint,
            })
            .collect()
    }

    /// SHA-256 of the group's current authority public key. Pins WHICH trust
    /// root produced this state, so the watermark can catch a fork that swaps
    /// the authority key without advancing the generation counter, and an audit
    /// can name the exact key that was trusted. `final_authority_key` is the
    /// authority Ed25519 public key (32 bytes) in effect at the verified head,
    /// after applying every `RotateAuthority` in the chain.
    pub fn authority_key_fingerprint(&self) -> [u8; HASH_LEN] {
        Sha256::digest(self.final_authority_key).into()
    }

    /// The `resolve_authority_key` callback
    /// `authorization_checkpoint::verify_change_admission` (and
    /// the native checkpoint flush, which locally
    /// re-verifies a checkpoint the coordination plane just issued) needs:
    /// given a checkpoint's claimed `signer_key_id` and the specific
    /// historical `policy_head` it was issued against, returns the raw
    /// authority key that was ACTUALLY valid at that point, but only if
    /// its fingerprint matches `signer_key_id` — never a bare "trust
    /// whatever key is named," the same discipline `verify_change_admission`'s
    /// own doc comment requires of every caller.
    ///
    /// Deliberately keyed on `policy_head`, not "the current key": a
    /// checkpoint pins a SPECIFIC past policy point, and the key that
    /// must have produced its signature is whichever key was in effect
    /// THEN, which may be an already-rotated-out key by the time this is
    /// called — `final_authority_key`/`authority_key_fingerprint` alone
    /// can only ever answer "what is the key right now," which is why
    /// this resolves through `authority_key_history` instead of that
    /// field.
    pub fn resolve_authority_key(
        &self,
        signer_key_id: &[u8; HASH_LEN],
        policy_head: &[u8; HASH_LEN],
    ) -> Option<VerifyingKey> {
        // The empty-chain point names the key the group started with. Once the
        // authority has rotated, that key is retired: nothing a checkpoint
        // pins at the empty chain can be vouched for any more, so a leaked
        // retired key cannot sign one naming any device it likes.
        if *policy_head == ZERO_HASH && self.authority_generation > 0 {
            return None;
        }
        let raw_key = self.authority_key_history.get(policy_head)?;
        let fingerprint: [u8; HASH_LEN] = Sha256::digest(raw_key).into();
        if &fingerprint != signer_key_id {
            return None;
        }
        VerifyingKey::from_bytes(raw_key).ok()
    }

    /// Whether a checkpoint pinned at policy point (`seq`, `head`) may vouch
    /// for `device_id` signing under `signing_key_fingerprint`: the verified
    /// chain must hold exactly `head` at `seq`, and the device must have been
    /// a writer under that key at `seq`. A delta published before a later
    /// revoke stays admissible, because the device was a writer at the point
    /// the checkpoint pins. The empty-chain point (`seq == 0`) carries no
    /// grants, so it is valid only for its own head and only while the
    /// authority has not rotated.
    pub fn writer_at_policy_point(
        &self,
        device_id: &str,
        signing_key_fingerprint: &[u8; HASH_LEN],
        seq: u64,
        head: &[u8; HASH_LEN],
    ) -> bool {
        if seq == 0 {
            return *head == ZERO_HASH && self.authority_generation == 0;
        }
        if self.record_head_at(seq) != Some(*head) {
            return false;
        }
        self.members_at(seq).is_ok_and(|members| {
            members.iter().any(|member| {
                member.device_id == device_id
                    && member.signing_key_fingerprint == *signing_key_fingerprint
                    && member.role.is_writer()
            })
        })
    }

    /// This state's rollback watermark coordinates: the highest verified
    /// sequence, its head hash, the authority generation at that head, and the
    /// fingerprint of the authority key that signed up to it. Every one of
    /// them is produced by the verification that just ran; the fingerprint is
    /// a plain `[u8; 32]`, never absent.
    pub fn to_watermark(&self) -> PolicyWatermark {
        PolicyWatermark {
            highest_verified_seq: self.current_seq,
            highest_verified_head: self.policy_head,
            authority_key_generation: self.authority_generation,
            authority_key_fingerprint: self.authority_key_fingerprint(),
        }
    }

    /// The verified `record_hash` at `seq`, if the verified chain covers it.
    /// A snapshot verified with `base = None` (as after a daemon restart, when
    /// the coordination plane resends the full chain) carries every record
    /// from seq 1, so this resolves any `seq` up to `current_seq`.
    pub(crate) fn record_head_at(&self, seq: u64) -> Option<[u8; HASH_LEN]> {
        self.records.get(&seq).map(|record| record.record_hash)
    }

    /// Decides whether adopting this verified snapshot is permitted given the
    /// group's persisted rollback watermark (`None` when the group has never
    /// been recorded). The signed hash-chain + signature check that produced
    /// `self` proves the chain is internally valid, but a *past* valid chain
    /// is equally signature-valid, so a peer or the coordination plane could
    /// replay an old chain after a restart to hide a later revoke. The
    /// watermark closes that: it is the highest chain this device has ever
    /// verified, and it never moves backward.
    ///
    /// - A lower `current_seq`, or a lower authority generation, is a
    ///   rollback — reject.
    /// - The SAME authority generation but a DIFFERENT authority-key
    ///   fingerprint is a fork at the trust root — reject. Two chains at the
    ///   same rotation count must share the same authority key; a differing key
    ///   means the snapshot descends from a different root than the one this
    ///   device verified. The head-hash chaining below remains the primary
    ///   cryptographic binding; this fingerprint check is an additional guard
    ///   that also catches a same-generation swap directly.
    /// - The same `current_seq` with a different head is a fork — reject;
    ///   an identical resend is accepted and keeps the watermark.
    /// - A higher `current_seq` must *extend* the watermark: the new chain's
    ///   record at the watermark's sequence must hash to the watermark's head
    ///   (the hash chain then guarantees identical history up to that point).
    ///   An unrelated or forked longer chain is rejected.
    ///
    /// A generation INCREASE legitimately changes the authority key: each
    /// `RotateAuthority` was already signature-verified against the key it
    /// replaces while producing `self`, and (for a longer chain) the
    /// extend-the-head check below proves the rotation happened on top of the
    /// verified history — so a higher generation is accepted and its new
    /// fingerprint recorded, exactly as before, without newly rejecting a
    /// legitimate rotation. The fingerprint is only compared for EQUALITY, and
    /// only at an equal generation.
    ///
    /// Every stored watermark carries a fingerprint: the column is `NOT
    /// NULL` and the only writer is a completed verification. There is no
    /// "unknown fingerprint" case to treat leniently, so an equal generation
    /// with a differing fingerprint is always a fork.
    pub fn watermark_verdict(&self, stored: Option<&PolicyWatermark>) -> WatermarkVerdict {
        let Some(stored) = stored else {
            // First time this group is seen locally — nothing to roll back to.
            return WatermarkVerdict::Accept(self.to_watermark());
        };
        if self.current_seq < stored.highest_verified_seq {
            return WatermarkVerdict::Reject(format!(
                "policy rollback: snapshot seq {} is below verified watermark {}",
                self.current_seq, stored.highest_verified_seq
            ));
        }
        if self.authority_generation < stored.authority_key_generation {
            return WatermarkVerdict::Reject(format!(
                "policy authority rollback: snapshot generation {} is below verified {}",
                self.authority_generation, stored.authority_key_generation
            ));
        }
        // Same authority generation must mean the same authority key.
        if self.authority_generation == stored.authority_key_generation
            && stored.authority_key_fingerprint != self.authority_key_fingerprint()
        {
            return WatermarkVerdict::Reject(format!(
                "policy fork: snapshot at authority generation {} presents a different \
                 authority key than the verified watermark",
                self.authority_generation
            ));
        }
        if self.current_seq == stored.highest_verified_seq {
            if self.policy_head != stored.highest_verified_head {
                return WatermarkVerdict::Reject(format!(
                    "policy fork: snapshot at seq {} has a different head than the verified \
                     watermark",
                    self.current_seq
                ));
            }
            // Identical to what we already trust — keep the watermark's
            // coordinates. Return `self`'s watermark rather than the stored one
            // so a legacy row with no fingerprint gets it backfilled here (seq,
            // head, and generation are all equal in this branch, so the only
            // field that can differ is a previously-absent fingerprint).
            return WatermarkVerdict::Accept(self.to_watermark());
        }
        // Strictly higher: the new chain must contain the watermark's head at
        // the watermark's sequence, proving it continues that exact history.
        match self.record_head_at(stored.highest_verified_seq) {
            Some(head) if head == stored.highest_verified_head => {
                WatermarkVerdict::Accept(self.to_watermark())
            }
            _ => WatermarkVerdict::Reject(format!(
                "policy fork: snapshot seq {} does not extend verified head at seq {}",
                self.current_seq, stored.highest_verified_seq
            )),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl GroupPolicyState {
    /// The placeholder-authority state: an empty verified chain
    /// (`records.is_empty() && current_seq == 0 && current_epoch == 0 &&
    /// policy_head == ZERO_HASH`). For a test/benchmark that needs
    /// `DaemonState::resolve_group_policy` to resolve to `Verified` (not
    /// `Withhold`) for a group it never ran a real signed policy log
    /// through -- without it, a real `DaemonState`'s one-shot, cached
    /// retirement-session construction (`DaemonState::local_retirement_
    /// session`) permanently revokes the group from every peer session the
    /// first time it reaches this group, not on some ongoing basis; see
    /// `PeerAuthorityState::install_test_group_policy_bootstrap`'s own doc comment
    /// for the full mechanism. That method is what a caller outside this
    /// module actually reaches this through (this struct's `records` field
    /// is private to this module, so nothing else can construct a
    /// `GroupPolicyState` literal at all).
    /// A verified-looking policy whose membership is exactly `members`, in
    /// the order given, for tests that need a group's member list (the
    /// records are not signed; nothing here re-verifies them).
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_members_for_tests(members: &[(&str, WriterRole)]) -> Self {
        let mut state = Self::placeholder_for_tests();
        for (index, (device_id, role)) in members.iter().enumerate() {
            let seq = index as u64 + 1;
            state.records.insert(
                seq,
                VerifiedPolicyRecord {
                    seq,
                    prev_record_hash: ZERO_HASH,
                    record_hash: ZERO_HASH,
                    epoch: 0,
                    signer_key_id: ZERO_HASH,
                    action: PolicyAction::Grant {
                        device_id: (*device_id).to_string(),
                        signing_key_fingerprint: ZERO_HASH,
                        role: *role,
                    },
                    signature: [0u8; SIGNATURE_LEN],
                },
            );
        }
        state.current_seq = members.len() as u64;
        state
    }

    pub fn placeholder_for_tests() -> Self {
        Self {
            current_seq: 0,
            current_epoch: 0,
            policy_head: ZERO_HASH,
            final_authority_key: ZERO_HASH,
            authority_generation: 0,
            records: BTreeMap::new(),
            authority_key_history: BTreeMap::new(),
        }
    }
}

pub fn verify_group_policy_log(
    service_public_key: &[u8],
    log: &GroupPolicyLog,
) -> Result<GroupPolicyState, String> {
    verify_group_policy_log_with_base(service_public_key, None, log)
}

pub fn verify_group_policy_log_with_base(
    service_public_key: &[u8],
    base: Option<&GroupPolicyState>,
    log: &GroupPolicyLog,
) -> Result<GroupPolicyState, String> {
    let mut authority_key = fixed::<HASH_LEN>(service_public_key, "service public key")?;
    let current_head = fixed::<HASH_LEN>(&log.policy_head, "policy head")?;
    let mut expected_prev = ZERO_HASH;
    let mut expected_seq = 1u64;
    let mut authority_generation = base.map(|b| b.authority_generation).unwrap_or(0);
    let mut records = BTreeMap::new();
    let mut authority_key_history: BTreeMap<[u8; HASH_LEN], [u8; HASH_LEN]> =
        base.map(|b| b.authority_key_history.clone()).unwrap_or_default();
    if let Some(base) = base {
        authority_key = base.final_authority_key;
        expected_prev = base.policy_head;
        expected_seq = base.current_seq.saturating_add(1);
        records = base.records.clone();
        if log.records.is_empty() {
            if log.current_seq == base.current_seq
                && log.current_epoch == base.current_epoch
                && current_head == base.policy_head
            {
                return Ok(base.clone());
            }
            return Err("policy snapshot has no records beyond the retained prefix".into());
        }
    }
    // The empty-chain bootstrap point always resolves to the pinned
    // service key, regardless of whether this call resumes from a base
    // (a base's own history already carries this entry forward via the
    // `unwrap_or_default()` above, so `or_insert` here is a genuine no-op
    // when resuming and the only thing that matters on a fresh chain).
    authority_key_history.entry(ZERO_HASH).or_insert(authority_key);

    let mut ordered = log.records.clone();
    ordered.sort_by_key(|record| record.seq);

    for record in &ordered {
        if record.group_id != log.group_id {
            return Err(format!(
                "policy record group {} does not match log group {}",
                record.group_id, log.group_id
            ));
        }
        if record.seq != expected_seq {
            return Err(format!("policy sequence gap at {}", record.seq));
        }
        let key_before = authority_key;
        let verified = verify_record(record, &authority_key, expected_prev)?;
        expected_prev = verified.record_hash;
        // `key_before` is the key that actually verified THIS record's
        // signature -- i.e. the key valid as of this record's own
        // `record_hash` becoming the chain head, before whatever effect
        // this same record carries (a RotateAuthority) takes hold for
        // the NEXT record onward.
        authority_key_history.insert(verified.record_hash, key_before);
        if let PolicyAction::RotateAuthority { new_authority_key } = &verified.action {
            authority_key = *new_authority_key;
            authority_generation += 1;
        }
        records.insert(verified.seq, verified);
        expected_seq += 1;
    }

    let derived_head =
        records.last_key_value().map(|(_, record)| record.record_hash).unwrap_or(ZERO_HASH);
    let derived_seq = records.last_key_value().map(|(seq, _)| *seq).unwrap_or(0);
    let derived_epoch = records.last_key_value().map(|(_, record)| record.epoch).unwrap_or(0);
    if log.current_seq != derived_seq {
        return Err(format!(
            "policy current_seq {} does not match derived {}",
            log.current_seq, derived_seq
        ));
    }
    if log.current_epoch != derived_epoch {
        return Err(format!(
            "policy current_epoch {} does not match derived {}",
            log.current_epoch, derived_epoch
        ));
    }
    if current_head != derived_head {
        return Err("policy head does not match the verified chain".into());
    }

    Ok(GroupPolicyState {
        current_seq: derived_seq,
        current_epoch: derived_epoch,
        policy_head: derived_head,
        final_authority_key: authority_key,
        authority_generation,
        records,
        authority_key_history,
    })
}

fn verify_record(
    record: &PolicyRecord,
    authority_key: &[u8; HASH_LEN],
    expected_prev: [u8; HASH_LEN],
) -> Result<VerifiedPolicyRecord, String> {
    let prev_record_hash = fixed::<HASH_LEN>(&record.prev_record_hash, "prev_record_hash")?;
    if prev_record_hash != expected_prev {
        return Err(format!("policy record {} has a broken prev hash", record.seq));
    }
    let record_hash = fixed::<HASH_LEN>(&record.record_hash, "record_hash")?;
    let signer_key_id = fixed::<HASH_LEN>(&record.signer_key_id, "signer_key_id")?;
    let expected_signer_key_id: [u8; HASH_LEN] = Sha256::digest(authority_key).into();
    if signer_key_id != expected_signer_key_id {
        return Err(format!("policy record {} signer key id mismatch", record.seq));
    }
    let signature = fixed::<SIGNATURE_LEN>(&record.signature, "signature")?;
    let action = parse_action(record)?;
    let verified = VerifiedPolicyRecord {
        seq: record.seq,
        prev_record_hash,
        record_hash,
        epoch: record.epoch,
        signer_key_id,
        action,
        signature,
    };
    let signing_bytes = signing_bytes(&record.group_id, &verified);
    let verifying_key = VerifyingKey::from_bytes(authority_key)
        .map_err(|_| "invalid policy service public key".to_string())?;
    let sig = Signature::from_bytes(&verified.signature);
    verifying_key
        .verify_strict(&signing_bytes, &sig)
        .map_err(|_| format!("policy record {} signature verification failed", record.seq))?;
    let mut hasher = Sha256::new();
    hasher.update(&signing_bytes);
    hasher.update(verified.signature);
    let computed_hash: [u8; HASH_LEN] = hasher.finalize().into();
    if computed_hash != verified.record_hash {
        return Err(format!("policy record {} hash mismatch", record.seq));
    }
    Ok(verified)
}

fn parse_action(record: &PolicyRecord) -> Result<PolicyAction, String> {
    match record.action_type {
        ACTION_GRANT_WITH_ROLE => {
            let signing_key_fingerprint =
                fixed::<HASH_LEN>(&record.signing_key_fingerprint, "signing_key_fingerprint")?;
            let role = WriterRole::from_wire(record.role)?;
            Ok(PolicyAction::Grant {
                device_id: record.device_id.clone(),
                signing_key_fingerprint,
                role,
            })
        }
        ACTION_REVOKE => Ok(PolicyAction::Revoke { device_id: record.device_id.clone() }),
        ACTION_ROTATE_AUTHORITY => {
            let new_authority_key =
                fixed::<HASH_LEN>(&record.new_authority_key, "new_authority_key")?;
            Ok(PolicyAction::RotateAuthority { new_authority_key })
        }
        _ => Err(format!("policy record {} has invalid action type", record.seq)),
    }
}

fn signing_bytes(group_id: &str, record: &VerifiedPolicyRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(POLICY_DOMAIN_TAG);
    put_str(&mut buf, group_id);
    put_u64(&mut buf, record.seq);
    buf.extend_from_slice(&record.prev_record_hash);
    put_u64(&mut buf, record.epoch);
    buf.extend_from_slice(&record.signer_key_id);
    match &record.action {
        PolicyAction::Grant { device_id, signing_key_fingerprint, role } => {
            buf.push(ACTION_GRANT_WITH_ROLE as u8);
            put_str(&mut buf, device_id);
            buf.extend_from_slice(signing_key_fingerprint);
            // Signed so a role cannot be tampered with in transit or storage
            // without invalidating the record's signature: an in-transit
            // downgrade (Owner->Viewer) or upgrade (Viewer->Editor) is as
            // detectable as tampering with the device_id would be.
            buf.push(role.to_wire() as u8);
        }
        PolicyAction::Revoke { device_id } => {
            buf.push(ACTION_REVOKE as u8);
            put_str(&mut buf, device_id);
        }
        PolicyAction::RotateAuthority { new_authority_key } => {
            buf.push(ACTION_ROTATE_AUTHORITY as u8);
            buf.extend_from_slice(new_authority_key);
        }
    }
    buf
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn fixed<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| format!("{field} is not {N} bytes"))
}

/// The *signing* half of the group policy log: turns a group's Grant/Revoke/
/// RotateAuthority actions into the signed, hash-chained [`PolicyRecord`]s
/// that [`verify_group_policy_log`] accepts.
///
/// In production this half lives in the coordination plane's policy service,
/// which is the only holder of a group's authority private key; a daemon only
/// ever verifies. It is compiled here for this module's own tests and for
/// another crate's `feature = "test-support"` dev-dependency on this one
/// (`cfg(test)` alone is never active for such a caller) -- never in a
/// production build.
///
/// A test harness with no coordination plane still has to bring its daemon
/// to a verified policy the way a shipped one gets there -- through
/// `verify_group_policy_log_with_base` and the rollback watermark. Handing
/// the harness a way to *sign* a real log keeps every authorization check on
/// the daemon side intact; the alternative (installing a `GroupPolicyState`
/// into `DaemonState` directly) would test a daemon that no user ever runs.
///
/// The `test-support` path exists for this crate's OWN full-stack
/// integration tests (`tests/support/fake_coordination.rs`): a fake
/// coordination plane that wants to serve a genuinely role-carrying,
/// correctly-signed policy log over the real netmap wire format needs to
/// sign one exactly the way a real coordination plane would, rather than
/// hand-rolling an approximation of the preimage/hash-chain shape.
#[cfg(any(test, feature = "test-support"))]
pub mod policy_signing {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    use super::{
        GroupPolicyLog, PolicyAction, PolicyRecord, VerifiedPolicyRecord, WriterRole,
        ACTION_GRANT_WITH_ROLE, ACTION_REVOKE, ACTION_ROTATE_AUTHORITY, HASH_LEN, SIGNATURE_LEN,
        ZERO_HASH,
    };

    /// A group policy log whose chain is nothing but writer Grants, one per
    /// entry of `writers` in the order given (so seq 1 grants `writers[0]`),
    /// signed by `authority` and ready to be handed to the daemon exactly as a
    /// netmap update's `group_policy_logs` entry would be. Every grant is
    /// `WriterRole::Editor` -- callers that need a specific role (e.g. a
    /// Viewer or Owner) should build records with [`grant_record`] directly.
    ///
    /// Each writer is named by its device id and its Ed25519 change-history
    /// *public* key; the Grant binds the SHA-256 fingerprint of that key, which
    /// is what admission later compares against the key that actually verified
    /// an incoming change. Callers therefore cannot accidentally bind a
    /// fingerprint that admits nothing.
    pub fn signed_writer_grant_log(
        authority: &SigningKey,
        group_id: &str,
        writers: &[(&str, [u8; 32])],
    ) -> GroupPolicyLog {
        let mut records: Vec<PolicyRecord> = Vec::with_capacity(writers.len());
        let mut prev = ZERO_HASH;
        for (index, (device_id, signing_public_key)) in writers.iter().enumerate() {
            let fingerprint: [u8; HASH_LEN] = Sha256::digest(signing_public_key).into();
            let record = grant_record(
                authority,
                group_id,
                index as u64 + 1,
                prev,
                device_id,
                fingerprint,
                WriterRole::Editor,
            );
            prev = record.record_hash.as_slice().try_into().expect("record_hash is 32 bytes");
            records.push(record);
        }
        GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: records.len() as u64,
            // Grants alone never advance the authorization epoch; only a
            // Revoke does, and this chain has none.
            current_epoch: 0,
            policy_head: prev.to_vec(),
            records,
        }
    }

    /// Epoch-0 shorthand for [`grant_record_at_epoch`]: correct only when
    /// this Grant is appended before the group's first-ever Revoke (a Grant
    /// never changes the epoch itself, so its own signed epoch is whatever
    /// is already in effect). Every existing caller of this function
    /// appends grants before any revoke, so this has always been that
    /// value; a caller building a chain where a Grant follows a Revoke
    /// (e.g. a live role downgrade's own re-grant at the new, lower role)
    /// must use [`grant_record_at_epoch`] instead and pass the real current
    /// epoch explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_record(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        device_id: &str,
        signing_key_fingerprint: [u8; HASH_LEN],
        role: WriterRole,
    ) -> PolicyRecord {
        grant_record_at_epoch(key, group_id, seq, prev, 0, device_id, signing_key_fingerprint, role)
    }

    /// Same as [`grant_record`], but for a Grant appended when the group's
    /// current epoch is already non-zero -- `epoch` is the record's own
    /// signed epoch field, i.e. whatever epoch is already in effect (a
    /// Grant never changes it). Needed to build a chain where a Grant
    /// follows a Revoke at the same or a later point, such as the
    /// coordination plane's own live-role-downgrade sequence (a Revoke that
    /// bumps the epoch, immediately followed by a Grant at the new, lower
    /// role and the SAME bumped epoch).
    #[allow(clippy::too_many_arguments)]
    pub fn grant_record_at_epoch(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        epoch: u64,
        device_id: &str,
        signing_key_fingerprint: [u8; HASH_LEN],
        role: WriterRole,
    ) -> PolicyRecord {
        signed_record(
            key,
            group_id,
            seq,
            prev,
            epoch,
            PolicyAction::Grant { device_id: device_id.to_string(), signing_key_fingerprint, role },
        )
    }

    /// Epoch-1 shorthand for [`revoke_record_at_epoch`]: correct only for a
    /// group's first-ever revoke (from epoch 0). Every existing internal
    /// caller of this function is exactly that case; a caller building a
    /// chain with more than one revoke, or a revoke that follows an earlier
    /// one, must use [`revoke_record_at_epoch`] instead and pass the real
    /// resulting epoch explicitly.
    //
    // `#[allow(dead_code)]`: under the `test-support`-only compilation this
    // module is also reachable from (see this module's own doc comment),
    // `cfg(test)` is false, so this crate's own `#[cfg(test)] mod tests` --
    // this shorthand's only caller -- is absent from that build; a
    // consuming crate's integration tests reach `revoke_record_at_epoch`
    // directly instead.
    #[allow(dead_code)]
    pub(super) fn revoke_record(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        device_id: &str,
    ) -> PolicyRecord {
        revoke_record_at_epoch(key, group_id, seq, prev, 1, device_id)
    }

    /// Same as [`revoke_record`], but `epoch` is the record's own signed
    /// epoch field explicitly -- the epoch value AFTER this revoke applies
    /// (always `previous_epoch + 1`, since a Revoke always bumps it). Used
    /// by `fake_coordination.rs`'s live-role-downgrade helper, which must
    /// compute this from whatever the group's chain-so-far actually is
    /// rather than assume it is always the group's first revoke.
    pub fn revoke_record_at_epoch(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        epoch: u64,
        device_id: &str,
    ) -> PolicyRecord {
        signed_record(
            key,
            group_id,
            seq,
            prev,
            epoch,
            PolicyAction::Revoke { device_id: device_id.to_string() },
        )
    }

    // See `revoke_record`'s own `#[allow(dead_code)]` comment just above.
    #[allow(dead_code)]
    pub(crate) fn rotate_record(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        new_authority_key: [u8; HASH_LEN],
    ) -> PolicyRecord {
        signed_record(
            key,
            group_id,
            seq,
            prev,
            0,
            PolicyAction::RotateAuthority { new_authority_key },
        )
    }

    /// Signs one record over exactly the bytes [`super::signing_bytes`]
    /// produces -- the same function the verifier hashes -- so a record built
    /// here and a record built by the coordination plane are byte-identical
    /// for the same action.
    pub(super) fn signed_record(
        key: &SigningKey,
        group_id: &str,
        seq: u64,
        prev: [u8; HASH_LEN],
        epoch: u64,
        action: PolicyAction,
    ) -> PolicyRecord {
        let public = key.verifying_key().to_bytes();
        let signer_key_id: [u8; HASH_LEN] = Sha256::digest(public).into();
        let mut verified = VerifiedPolicyRecord {
            seq,
            prev_record_hash: prev,
            record_hash: ZERO_HASH,
            epoch,
            signer_key_id,
            action,
            signature: [0u8; SIGNATURE_LEN],
        };
        let bytes = super::signing_bytes(group_id, &verified);
        verified.signature = key.sign(&bytes).to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.update(verified.signature);
        verified.record_hash = hasher.finalize().into();

        let mut record = PolicyRecord {
            group_id: group_id.to_string(),
            seq,
            prev_record_hash: prev.to_vec(),
            record_hash: verified.record_hash.to_vec(),
            epoch,
            action_type: ACTION_GRANT_WITH_ROLE,
            device_id: String::new(),
            signing_key_fingerprint: Vec::new(),
            role: 0,
            new_authority_key: Vec::new(),
            signer_key_id: signer_key_id.to_vec(),
            signature: verified.signature.to_vec(),
        };
        match verified.action {
            PolicyAction::Grant { device_id, signing_key_fingerprint, role } => {
                record.action_type = ACTION_GRANT_WITH_ROLE;
                record.device_id = device_id;
                record.signing_key_fingerprint = signing_key_fingerprint.to_vec();
                record.role = role.to_wire();
            }
            PolicyAction::Revoke { device_id } => {
                record.action_type = ACTION_REVOKE;
                record.device_id = device_id;
            }
            PolicyAction::RotateAuthority { new_authority_key } => {
                record.action_type = ACTION_ROTATE_AUTHORITY;
                record.new_authority_key = new_authority_key.to_vec();
            }
        }
        record
    }
}

#[cfg(test)]
mod tests;
