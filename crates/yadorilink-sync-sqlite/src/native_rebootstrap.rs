//! Rebootstrap, up to and including the preserved durability barrier.
//!
//! A replica whose history is behind what its peers retain cannot catch up by
//! deltas. It installs a verified checkpoint of a peer, the target, but the
//! target does not contain every change this replica made: an own delta the
//! target's frontier does not cover would be lost. This module decides which
//! target to take, saves what the target would lose, and makes both durable
//! before anything is destroyed. It changes neither the sync root nor the native
//! state; installing the target is a later stage that starts from the
//! [`Preserved`] barrier reached here.
//!
//! What is saved is the whole uncovered own delta sequence, of every incarnation
//! of this device and whether or not a delta was ever published: the exact signed
//! bytes, the file version each put names, and the order in which they must be
//! replayed. It goes to a recovery area ([`crate::native_rebootstrap_recovery`])
//! from which it can be recovered with no database and no sync root, together
//! with the exact target bundle and what is needed to verify that bundle again
//! with no peer and no authority ([`crate::native_rebootstrap_target`]).
//!
//! The journal tables here are progress bookkeeping only. Before the barrier the
//! old state is wholly authoritative: a crash discards the half-written area.
//! After it, the manifest is the recovery basis.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::history_truncation::{HistoryTruncations, VerifiedCandidate};
use yadorilink_replica_domain::ids::{
    AuthorSeq, BlockHash, DeviceId, FolderGroupId, SyncPath, VersionHash,
};
use yadorilink_replica_domain::native_checkpoint_seal::NativeSealPolicy;
use yadorilink_replica_domain::native_frontier::{NativeAuthorFrontier, NativeAuthorFrontierEntry};
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::signed_delta::NativeDelta;

use crate::error::SyncSqliteError;
use crate::native_bootstrap::{NativeBootstrap, VerifiedNativeBootstrap};
use crate::native_history_floor::frontier_covers;
use crate::native_rebootstrap_recovery::{
    new_recovery_id, sha256, AreaError, Manifest, ManifestDelta, ManifestItem, ManifestRemoteOnly,
    ManifestRemoval, ManifestUnit, ManifestVersion, RecoveryArea,
};
use crate::native_rebootstrap_target::{
    verify_and_prepare_target, verify_stored_target, StoredTarget, TargetError,
};
use crate::native_store::Admission;

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- One rebootstrap per group: where it is and what it is for. Progress
        -- bookkeeping only; the recovery area is the source of truth.
        CREATE TABLE IF NOT EXISTS native_rebootstrap_journal (
            group_id               TEXT PRIMARY KEY,
            recovery_id            TEXT NOT NULL,
            state                  TEXT NOT NULL,
            blocked_reason         TEXT,
            blocked_detail         TEXT,
            target_checkpoint_hash BLOB NOT NULL,
            target_bundle_sha256   BLOB,
            manifest_sha256        BLOB,
            -- The area of the rebootstrap this one replaced, kept until this
            -- one's barrier holds so that it is swept and never leaks.
            superseded_recovery_id TEXT,
            -- Set while a call holds this group's rebootstrap; cleared when it
            -- returns and by the restart (a process that died holding it).
            in_progress            INTEGER NOT NULL DEFAULT 0,
            items_total            INTEGER NOT NULL DEFAULT 0,
            items_copied           INTEGER NOT NULL DEFAULT 0,
            -- The highest sequence of this device's own authors that the final capture pass
            -- has committed under its capability; written in the transaction of the delta it
            -- names, never apart from it.
            capture_high_seq       INTEGER,
            -- Hash of the group's author frontier and closure rows as they stood when the
            -- plan was made, under the freeze. The install compares it again before it
            -- clears anything: a mismatch means something wrote past the freeze.
            frozen_frontier_hash   BLOB,
            started_at             INTEGER NOT NULL,
            updated_at             INTEGER NOT NULL
        ) WITHOUT ROWID;

        -- The replay of the uncovered own deltas: one row per step of the manifest, in
        -- manifest order. `outcome` is NULL until the step is decided and is written in the
        -- transaction that authors its delta, so the rows are the replay's cursor and, with
        -- `new_seq` and `new_delta_hash`, its head map: the new delta that carries the put of
        -- an old one. `authored` has both, `moot` (nothing left to say) and `unreplayed`
        -- (the unit could not be authored) have neither.
        CREATE TABLE IF NOT EXISTS native_rebootstrap_delta (
            group_id        TEXT NOT NULL,
            ordinal         INTEGER NOT NULL,
            old_delta_hash  BLOB NOT NULL,
            outcome         TEXT,
            new_seq         INTEGER,
            new_delta_hash  BLOB,
            PRIMARY KEY (group_id, ordinal)
        ) WITHOUT ROWID;

        -- One row per file of the recovery area that is not a fixed name.
        CREATE TABLE IF NOT EXISTS native_rebootstrap_recovery_item (
            group_id      TEXT NOT NULL,
            item_key      TEXT NOT NULL,
            kind          TEXT NOT NULL,
            size          INTEGER NOT NULL,
            content_hash  BLOB NOT NULL,
            status        TEXT NOT NULL,
            PRIMARY KEY (group_id, item_key)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

// --- choosing the target ------------------------------------------------------------------

/// A verified checkpoint a replica could rebootstrap to, as far as choosing
/// among them goes.
#[derive(Clone, Debug)]
pub struct TargetCandidate {
    pub checkpoint_id: [u8; 32],
    pub frontier: NativeAuthorFrontier,
}

/// The highest seq of an own incarnation that `entry` covers. A row at the
/// entry's seq whose hash is not the entry's tip means this incarnation forked
/// from the target's: nothing of it is covered. A seq with no row is covered on
/// the frontier's word (rows below the own history floor are not kept).
fn covered_limit(
    entry: Option<&NativeAuthorFrontierEntry>,
    hash_at: impl Fn(u64) -> Option<DeltaHash>,
) -> u64 {
    let Some(entry) = entry else { return 0 };
    match hash_at(entry.seq.get()) {
        Some(hash) if hash != entry.tip => 0,
        _ => entry.seq.get(),
    }
}

/// Whether `newer` provably descends from `older`: it covers it, is not covered by it, and
/// wherever it is further along for one of this replica's own incarnations, both positions
/// lie on the local chain (the only chain of that incarnation this replica can check). A
/// higher own position that is beyond the local chain, or off it, may be an equivocated
/// branch sealed independently, so nothing orders the two. Other authors' chains are not
/// held; their frontier order is taken as it stands.
fn provably_descends(
    newer: &TargetCandidate,
    older: &TargetCandidate,
    own: &BTreeMap<AuthorId, Vec<DeltaHash>>,
) -> bool {
    if !frontier_covers(&newer.frontier, &older.frontier)
        || frontier_covers(&older.frontier, &newer.frontier)
    {
        return false;
    }
    older.frontier.iter().all(|(author, old)| {
        let Some(chain) = own.get(author) else { return true };
        let Some(new) = newer.frontier.get(author) else { return false };
        if new.seq == old.seq {
            return true;
        }
        let on_chain = |entry: &NativeAuthorFrontierEntry| {
            entry.seq.get() >= 1 && chain.get(entry.seq.get() as usize - 1) == Some(&entry.tip)
        };
        on_chain(new) && on_chain(old)
    })
}

/// Chooses the checkpoint to rebootstrap to among verified candidates. Every one
/// is a valid target; the rule only makes the choice a function of the set:
/// among the candidates preservation accepts, drop one that another provably
/// descends from, of the rest take the one that covers the most of this replica's
/// own chain (the least to re-assert), then the greatest checkpoint id. Neither
/// adoption time nor arrival order is an input. `own` is the replica's own chain
/// per incarnation: the delta hashes in seq order from seq 1. `blocked` holds the
/// reason preservation refuses a candidate, for those it refuses; when it refuses
/// all of them the reason is that of the candidate the rule would otherwise have
/// chosen.
pub fn choose_rebootstrap_target(
    candidates: &[TargetCandidate],
    own: &BTreeMap<AuthorId, Vec<DeltaHash>>,
    blocked: &BTreeMap<[u8; 32], BlockedReason>,
) -> Result<Option<[u8; 32]>, BlockedReason> {
    let covered = |candidate: &TargetCandidate| -> usize {
        own.iter()
            .map(|(author, chain)| {
                let limit = covered_limit(candidate.frontier.get(author), |seq| {
                    chain.get(seq as usize - 1).copied()
                });
                (limit as usize).min(chain.len())
            })
            .sum()
    };
    let best = |pool: Vec<&TargetCandidate>| -> Option<[u8; 32]> {
        pool.iter()
            .filter(|c| !pool.iter().any(|o| provably_descends(o, c, own)))
            .max_by_key(|c| (covered(c), c.checkpoint_id))
            .map(|c| c.checkpoint_id)
    };
    let usable: Vec<&TargetCandidate> =
        candidates.iter().filter(|c| !blocked.contains_key(&c.checkpoint_id)).collect();
    if let Some(chosen) = best(usable) {
        return Ok(Some(chosen));
    }
    match best(candidates.iter().collect()) {
        None => Ok(None),
        Some(id) => Err(blocked.get(&id).cloned().expect("every candidate is blocked")),
    }
}

// --- why a rebootstrap does not proceed -------------------------------------------------

/// Why preserving failed. Nothing destructive has happened for any of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreservationFailure {
    /// A copy did not read back as written.
    CopyVerification {
        item: String,
    },
    InsufficientSpace {
        needed: u64,
        available: u64,
    },
    Io {
        detail: String,
    },
    /// The location cannot hold the area.
    RecoveryAreaUnavailable {
        detail: String,
    },
    /// The pass that folds the folder into the index did not complete.
    CapturePartial {
        detail: String,
    },
    /// The bytes of a version a put names are not held.
    ContentUnavailable {
        version: VersionHash,
    },
    /// A put names a version this replica has no record of.
    VersionUnknown {
        version: VersionHash,
    },
    /// The target does not verify from what is stored with it.
    TargetNotVerifiable {
        detail: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockedReason {
    /// An own delta the target does not cover has no exact body: the target is
    /// not installable. Absence of a head is never read as a delete.
    LocalIntentUnavailable {
        delta: DeltaHash,
    },
    PreservationFailed(PreservationFailure),
    /// The recovery area does not agree with its manifest.
    ManifestInconsistent {
        detail: String,
    },
    /// The candidate can no longer be used and the root is still unmodified.
    CandidateExpired,
    /// This platform has no verified way to make a directory-entry change
    /// durable, which the preserved barrier relies on: nothing is started.
    DurabilityUnsupported,
    /// A head the target lacks is not a durable recovery item. The destructive
    /// step does not run for it.
    RemoteOnlyUnpreserved {
        item: String,
    },
}

impl BlockedReason {
    fn encode(&self) -> (String, String) {
        use PreservationFailure as F;
        match self {
            Self::LocalIntentUnavailable { delta } => {
                ("local_intent_unavailable".into(), hex::encode(delta.0))
            }
            Self::ManifestInconsistent { detail } => {
                ("manifest_inconsistent".into(), detail.clone())
            }
            Self::CandidateExpired => ("candidate_expired".into(), String::new()),
            Self::DurabilityUnsupported => ("durability_unsupported".into(), String::new()),
            Self::RemoteOnlyUnpreserved { item } => {
                ("remote_only_unpreserved".into(), item.clone())
            }
            Self::PreservationFailed(failure) => match failure {
                F::CopyVerification { item } => ("copy_verification".into(), item.clone()),
                F::InsufficientSpace { needed, available } => {
                    ("insufficient_space".into(), format!("{needed} {available}"))
                }
                F::Io { detail } => ("io".into(), detail.clone()),
                F::RecoveryAreaUnavailable { detail } => {
                    ("recovery_area_unavailable".into(), detail.clone())
                }
                F::CapturePartial { detail } => ("capture_partial".into(), detail.clone()),
                F::ContentUnavailable { version } => {
                    ("content_unavailable".into(), hex::encode(version.0))
                }
                F::VersionUnknown { version } => ("version_unknown".into(), hex::encode(version.0)),
                F::TargetNotVerifiable { detail } => {
                    ("target_not_verifiable".into(), detail.clone())
                }
            },
        }
    }

    fn decode(code: &str, detail: &str) -> Option<Self> {
        use PreservationFailure as F;
        let hash = || -> Option<[u8; 32]> {
            let mut out = [0u8; 32];
            hex::decode_to_slice(detail, &mut out).ok()?;
            Some(out)
        };
        let failed = |f| Some(Self::PreservationFailed(f));
        match code {
            "local_intent_unavailable" => {
                Some(Self::LocalIntentUnavailable { delta: DeltaHash(hash()?) })
            }
            "manifest_inconsistent" => Some(Self::ManifestInconsistent { detail: detail.into() }),
            "candidate_expired" => Some(Self::CandidateExpired),
            "durability_unsupported" => Some(Self::DurabilityUnsupported),
            "remote_only_unpreserved" => Some(Self::RemoteOnlyUnpreserved { item: detail.into() }),
            "copy_verification" => failed(F::CopyVerification { item: detail.into() }),
            "insufficient_space" => {
                let (needed, available) = detail.split_once(' ')?;
                failed(F::InsufficientSpace {
                    needed: needed.parse().ok()?,
                    available: available.parse().ok()?,
                })
            }
            "io" => failed(F::Io { detail: detail.into() }),
            "recovery_area_unavailable" => {
                failed(F::RecoveryAreaUnavailable { detail: detail.into() })
            }
            "capture_partial" => failed(F::CapturePartial { detail: detail.into() }),
            "content_unavailable" => {
                failed(F::ContentUnavailable { version: VersionHash(hash()?) })
            }
            "version_unknown" => failed(F::VersionUnknown { version: VersionHash(hash()?) }),
            "target_not_verifiable" => failed(F::TargetNotVerifiable { detail: detail.into() }),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebootstrapState {
    Planning,
    /// The group is frozen except for the one final capture pass: remote admission and
    /// materialization are refused, and local authoring is refused to everyone but the holder
    /// of this rebootstrap's [`CaptureAuthority`].
    Capturing,
    Preserving,
    /// The durability barrier holds: the target and every protected intent are
    /// durable and read back.
    Preserved,
    /// The originals of the changes that will not be re-authored are being moved
    /// out of the root. From here the root has been (or is about to be) modified,
    /// so the target is fixed.
    Quarantining,
    /// The target is installed: the native state is the target's, this device
    /// authors as a new incarnation and the old one is fenced. Remote admission is open
    /// again and the bounded catch-up drains what the peers can give now; materialization
    /// and local authoring stay frozen.
    CatchingUp,
    /// The catch-up is over. Own intent is replayed unit by unit as deltas of the new
    /// incarnation, through the freeze, until [`finish_rebootstrap`] ends it. Remote
    /// admission stays open.
    Replaying,
    Blocked(BlockedReason),
}

impl RebootstrapState {
    /// The sync root has been (or is about to be) modified: the recorded target is the only
    /// target, and a block is recorded beside the stage rather than replacing it.
    pub fn root_modified(&self) -> bool {
        matches!(self, Self::Quarantining | Self::CatchingUp | Self::Replaying)
    }

    /// The target is installed.
    pub fn is_installed(&self) -> bool {
        matches!(self, Self::CatchingUp | Self::Replaying)
    }
}

/// What `share status` and the diagnostics report of a group's rebootstrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebootstrapStatus {
    pub state: RebootstrapState,
    pub recovery_id: String,
    pub target_checkpoint_hash: [u8; 32],
    pub items_total: u64,
    pub items_copied: u64,
    pub started_at: i64,
    pub updated_at: i64,
    /// The digest of the manifest the barrier recorded, once it holds.
    pub manifest_sha256: Option<[u8; 32]>,
    /// The digest of the target bundle the area was given, once it is durable.
    pub target_bundle_sha256: Option<[u8; 32]>,
    /// The highest sequence the final capture pass has committed, once it has committed one.
    pub capture_high_seq: Option<u64>,
    /// Why the machine cannot go on, when it is blocked at a stage the root has
    /// already been modified in: the stage itself is not replaced by the block.
    pub blocked: Option<BlockedReason>,
}

fn array32(bytes: Vec<u8>) -> Result<[u8; 32], SyncSqliteError> {
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| SyncSqliteError::CorruptState("a rebootstrap hash is not 32 bytes".into()))
}

/// The group's rebootstrap, if one exists.
pub fn rebootstrap_status(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<Option<RebootstrapStatus>, SyncSqliteError> {
    type Row = (
        String,
        String,
        Option<String>,
        Option<String>,
        Vec<u8>,
        i64,
        i64,
        i64,
        i64,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
    );
    let row: Option<Row> = conn
        .query_row(
            "SELECT recovery_id, state, blocked_reason, blocked_detail, target_checkpoint_hash, \
             items_total, items_copied, started_at, updated_at, manifest_sha256, \
             target_bundle_sha256, capture_high_seq \
             FROM native_rebootstrap_journal WHERE group_id = ?1",
            [group.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        recovery_id,
        state,
        code,
        detail,
        target,
        total,
        copied,
        started,
        updated,
        manifest_sha256,
        bundle_sha256,
        capture_high_seq,
    )) = row
    else {
        return Ok(None);
    };
    let corrupt =
        |what: &str| SyncSqliteError::CorruptState(format!("rebootstrap journal: {what}"));
    let overlay = match (state.as_str(), code.as_deref()) {
        ("blocked", _) | (_, None) => None,
        (_, Some(code)) => Some(
            BlockedReason::decode(code, detail.as_deref().unwrap_or_default())
                .ok_or_else(|| corrupt("unknown blocked reason"))?,
        ),
    };
    let state = match state.as_str() {
        "planning" => RebootstrapState::Planning,
        "capturing" => RebootstrapState::Capturing,
        "preserving" => RebootstrapState::Preserving,
        "preserved" => RebootstrapState::Preserved,
        "quarantining" => RebootstrapState::Quarantining,
        "catching_up" => RebootstrapState::CatchingUp,
        "replaying" => RebootstrapState::Replaying,
        "blocked" => RebootstrapState::Blocked(
            BlockedReason::decode(
                code.as_deref().unwrap_or_default(),
                detail.as_deref().unwrap_or_default(),
            )
            .ok_or_else(|| corrupt("unknown blocked reason"))?,
        ),
        _ => return Err(corrupt("unknown state")),
    };
    Ok(Some(RebootstrapStatus {
        state,
        recovery_id,
        target_checkpoint_hash: array32(target)?,
        items_total: total as u64,
        items_copied: copied as u64,
        started_at: started,
        updated_at: updated,
        manifest_sha256: manifest_sha256.map(array32).transpose()?,
        target_bundle_sha256: bundle_sha256.map(array32).transpose()?,
        capture_high_seq: capture_high_seq.map(|seq| seq as u64),
        blocked: overlay,
    }))
}

// --- the freeze ---------------------------------------------------------------------------

/// The right to author this device's own changes through a rebootstrap's freeze, for the one
/// final capture pass that folds what is on disk into the index before the plan is made.
///
/// Only the rebootstrap driver can make one (the constructor is private to this module), and
/// only after reading its own journal row in [`RebootstrapState::Capturing`] under the
/// recovery id it is issued for. It is neither `Clone` nor `Copy`, is not stored in any
/// global or thread-local, and is handed down the call chain as an explicit argument until the
/// store's install gate reads it ([`crate::local_author::LocalAuthor::capture`]).
///
/// The capability proves nothing by itself: the gate re-reads the journal in the authoring
/// transaction and honours it only while that row is still `Capturing` for the same recovery
/// id, and only for a delta of this device. Once the journal leaves `Capturing` every copy of
/// it, however it was kept, is refused.
///
/// Nothing outside this module can build one: its fields are private and no constructor is
/// public.
///
/// ```compile_fail
/// use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
/// use yadorilink_sync_sqlite::native_rebootstrap::CaptureAuthority;
///
/// let _forged = CaptureAuthority {
///     group: FolderGroupId("g".into()),
///     device: DeviceId("d".into()),
///     recovery_id: "r".into(),
/// };
/// ```
///
/// ```compile_fail
/// let _ = yadorilink_sync_sqlite::native_rebootstrap::CaptureAuthority::issue;
/// ```
#[derive(Debug)]
pub struct CaptureAuthority {
    group: FolderGroupId,
    device: DeviceId,
    recovery_id: String,
}

impl CaptureAuthority {
    /// Issues the capability for the journal row of `group`, which must be in `Capturing`
    /// under `recovery_id`.
    fn issue(
        conn: &Connection,
        group: &FolderGroupId,
        device: &DeviceId,
        recovery_id: &str,
    ) -> Result<Self, SyncSqliteError> {
        match journal_gate_row(conn, group)? {
            Some(row) if row.state == "capturing" && row.recovery_id == recovery_id => Ok(Self {
                group: group.clone(),
                device: device.clone(),
                recovery_id: recovery_id.to_owned(),
            }),
            _ => Err(SyncSqliteError::CorruptState(
                "a capture authority is issued only for a journal in Capturing".into(),
            )),
        }
    }

    /// A capability for `recovery_id` without the journal check, so a test can present one the
    /// gate must refuse (another recovery id, or a journal that has moved on), or one a host's
    /// capture seam must carry through.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(group: &FolderGroupId, device: &DeviceId, recovery_id: &str) -> Self {
        Self { group: group.clone(), device: device.clone(), recovery_id: recovery_id.to_owned() }
    }

    pub fn recovery_id(&self) -> &str {
        &self.recovery_id
    }
}

/// The capability of the checkpoint install's own deltas to pass the freeze it runs under.
/// Like [`CaptureAuthority`] it carries the group and the recovery id it was issued for and
/// cannot be built outside this module; the gate honours it only while the journal is
/// `Quarantining` or `Replaying` for that recovery id, and never in `Capturing` or
/// `CatchingUp`.
#[derive(Debug)]
pub struct InstallAuthority {
    group: FolderGroupId,
    recovery_id: String,
}

impl InstallAuthority {
    /// Issues the capability for the journal row of `group`, which must be `Quarantining` or
    /// `Replaying` under `recovery_id`.
    pub(crate) fn issue(
        conn: &Connection,
        group: &FolderGroupId,
        recovery_id: &str,
    ) -> Result<Self, SyncSqliteError> {
        match journal_gate_row(conn, group)? {
            Some(row)
                if matches!(row.state.as_str(), "quarantining" | "replaying")
                    && row.recovery_id == recovery_id =>
            {
                Ok(Self { group: group.clone(), recovery_id: recovery_id.to_owned() })
            }
            _ => Err(SyncSqliteError::CorruptState(
                "an install authority is issued only for a journal in Quarantining or Replaying"
                    .into(),
            )),
        }
    }

    /// Whether this is the capability of rebootstrap `recovery_id` of `group`.
    pub(crate) fn is_for(&self, group: &FolderGroupId, recovery_id: &str) -> bool {
        self.group == *group && self.recovery_id == recovery_id
    }

    /// A capability for `recovery_id` without the journal check, so a test can present one the
    /// gate must refuse.
    #[cfg(test)]
    pub(crate) fn for_test(group: &FolderGroupId, recovery_id: &str) -> Self {
        Self { group: group.clone(), recovery_id: recovery_id.to_owned() }
    }
}

/// Writes a journal row in `state` (a journal state's stored name) for `group`, as the
/// machine would have left it, so a test can present the gate with any stage.
#[cfg(any(test, feature = "test-support"))]
pub fn set_journal_for_test(
    conn: &Connection,
    group: &FolderGroupId,
    state: &str,
    recovery_id: &str,
) {
    conn.execute("DELETE FROM native_rebootstrap_journal WHERE group_id = ?1", [group.as_str()])
        .unwrap();
    conn.execute(
        "INSERT INTO native_rebootstrap_journal \
         (group_id, recovery_id, state, target_checkpoint_hash, started_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, 0, 0)",
        (group.as_str(), recovery_id, state, [0u8; 32].as_slice()),
    )
    .unwrap();
}

/// The final capture pass of a rebootstrap: folds the current disk into the index as ordinary
/// local deltas, authoring them through `authority`. The group is frozen for everyone else
/// while it runs. `Partial` (unreadable entries, paused items) means the index may not know all
/// of the user's edits, and blocks the plan.
///
/// The capability is shared, not cloned: the pass may hand the `Arc` to the workers that author
/// for it, and must drop every handle before it returns. The gate honours it only while the
/// journal is `Capturing` under its recovery id, so a handle kept longer authors nothing.
pub trait FinalCapture {
    fn capture(&self, authority: &Arc<CaptureAuthority>) -> CaptureBarrier;
}

/// What the install gate learned about the group's freeze for one delta.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FreezeVerdict {
    /// No rebootstrap freezes the group (or its journal has not reached `Capturing`, or it is
    /// blocked or discarded): the delta is admitted as usual.
    Open,
    /// The group is frozen against this delta. Nothing may be written for it.
    Frozen,
    /// The delta is the final capture's: admitted, and the install must record the capture
    /// under `recovery_id` in its own transaction ([`record_capture`]).
    Capture { recovery_id: String },
}

struct GateRow {
    recovery_id: String,
    state: String,
    capture_high_seq: Option<i64>,
}

fn journal_gate_row(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<Option<GateRow>, SyncSqliteError> {
    Ok(conn
        .prepare_cached(
            "SELECT recovery_id, state, capture_high_seq \
             FROM native_rebootstrap_journal WHERE group_id = ?1",
        )?
        .query_row([group.as_str()], |row| {
            Ok(GateRow {
                recovery_id: row.get(0)?,
                state: row.get(1)?,
                capture_high_seq: row.get(2)?,
            })
        })
        .optional()?)
}

/// The one freeze check, read by the store's install funnel for every delta it installs.
///
/// Derived from the journal state alone (no stored flag), so it holds across a restart:
///
/// * no journal, `planning`, `blocked`: open;
/// * `capturing`: frozen, except for a LOCAL delta (its author is a device the authority was
///   issued to) presented with the capture authority of this very rebootstrap, once, in
///   sequence;
/// * `preserving`, `preserved`: frozen for everyone;
/// * `quarantining`: frozen, except for the install's own deltas, presented with the install
///   authority of this very rebootstrap;
/// * `catching_up`: remote admission is open (the bounded catch-up needs it); local authoring
///   and the install authority are refused;
/// * `replaying`: remote admission is open, local authoring is refused, and the replay's own
///   deltas pass with the install authority of this very rebootstrap.
///
/// An authority is honoured in its own state only: a capture authority never passes after
/// `Capturing`, an install authority never passes in `Capturing` or `CatchingUp`, and neither
/// passes for another recovery id.
pub(crate) fn check_freeze(
    conn: &Connection,
    group: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
    admission: Admission<'_>,
) -> Result<FreezeVerdict, SyncSqliteError> {
    let Some(row) = journal_gate_row(conn, group)? else { return Ok(FreezeVerdict::Open) };
    match row.state.as_str() {
        "planning" | "blocked" => Ok(FreezeVerdict::Open),
        "capturing" => {
            let continues = row.capture_high_seq.is_none_or(|high| (seq.get() as i64) > high);
            match admission {
                Admission::RebootstrapCapture(authority)
                    if authority.group == *group
                        && authority.recovery_id == row.recovery_id
                        && authority.device == author.device
                        && continues =>
                {
                    Ok(FreezeVerdict::Capture { recovery_id: row.recovery_id })
                }
                _ => Ok(FreezeVerdict::Frozen),
            }
        }
        "preserving" | "preserved" => Ok(FreezeVerdict::Frozen),
        "quarantining" | "replaying" => match admission {
            Admission::RebootstrapInstall(authority)
                if authority.group == *group && authority.recovery_id == row.recovery_id =>
            {
                Ok(FreezeVerdict::Open)
            }
            Admission::Remote if row.state == "replaying" => Ok(FreezeVerdict::Open),
            _ => Ok(FreezeVerdict::Frozen),
        },
        "catching_up" => match admission {
            Admission::Remote => Ok(FreezeVerdict::Open),
            _ => Ok(FreezeVerdict::Frozen),
        },
        other => Err(SyncSqliteError::CorruptState(format!(
            "rebootstrap journal: unknown state {other:?}"
        ))),
    }
}

/// Records that the capture pass committed a delta of sequence `seq`, in the transaction that
/// installs that delta: the delta and its consumption of the capability exist together or not
/// at all.
pub(crate) fn record_capture(
    conn: &Connection,
    group: &FolderGroupId,
    recovery_id: &str,
    seq: AuthorSeq,
) -> Result<(), SyncSqliteError> {
    let changed = conn
        .prepare_cached(
            "UPDATE native_rebootstrap_journal SET capture_high_seq = ?3 \
             WHERE group_id = ?1 AND recovery_id = ?2 AND state = 'capturing'",
        )?
        .execute((group.as_str(), recovery_id, seq.get() as i64))?;
    if changed != 1 {
        return Err(SyncSqliteError::CorruptState(
            "the capture pass committed a delta for a journal that is no longer capturing".into(),
        ));
    }
    Ok(())
}

/// Journal states in which the group is frozen: from `Capturing` until the rebootstrap is
/// finished. A blocked journal that has not reached `Quarantining` is open (the old state is
/// still authoritative).
const FROZEN_STATES: &str =
    "('capturing', 'preserving', 'preserved', 'quarantining', 'catching_up', 'replaying')";

/// Whether a rebootstrap freezes `group_id`. Derived from the journal alone, so it holds across
/// a restart and ends only when the journal is finished or discarded.
pub fn group_frozen(conn: &Connection, group_id: &str) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .prepare_cached(&format!(
            "SELECT 1 FROM native_rebootstrap_journal WHERE group_id = ?1 \
             AND state IN {FROZEN_STATES}"
        ))?
        .query_row([group_id], |_| Ok(()))
        .optional()?
        .is_some())
}

/// Whether this device's own deltas of `group_id` are withheld from peers: the group is frozen
/// and the target is not installed yet. The incarnation that authors them is about to be closed
/// at the target's position and what it authored past that is replayed as the new incarnation's,
/// so a peer that took one of them now would hold it under a closed author next to its replay.
/// From the install on there is no old delta to serve and the replay's own are published.
pub fn own_deltas_withheld(conn: &Connection, group_id: &str) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .prepare_cached(
            "SELECT 1 FROM native_rebootstrap_journal WHERE group_id = ?1 \
             AND state IN ('capturing', 'preserving', 'preserved', 'quarantining')",
        )?
        .query_row([group_id], |_| Ok(()))
        .optional()?
        .is_some())
}

/// Whether any group is frozen: the question every enforcement point asks first, so an idle
/// replica pays one probe of a table that is empty.
pub fn any_group_frozen(conn: &Connection) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .prepare_cached(&format!(
            "SELECT 1 FROM native_rebootstrap_journal WHERE state IN {FROZEN_STATES} LIMIT 1"
        ))?
        .query_row([], |_| Ok(()))
        .optional()?
        .is_some())
}

/// A boolean SQL expression, true when the group named by `{group}` is frozen: the scheduler's
/// filter, so that a frozen group's rows do not take claim slots.
#[cfg(test)]
pub(crate) fn frozen_group_sql(group: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM native_rebootstrap_journal j WHERE j.group_id = {group} \
         AND j.state IN {FROZEN_STATES})"
    )
}

/// Refuses to write, delete, rename or replace anything in a frozen group. Called inside the
/// path's lock before a lane's first mutating step, and never bypassed.
pub(crate) fn refuse_materialization_if_frozen(
    conn: &Connection,
    group_id: &str,
) -> Result<(), SyncSqliteError> {
    if group_frozen(conn, group_id)? {
        return Err(SyncSqliteError::GroupFrozen { group_id: group_id.to_owned() });
    }
    Ok(())
}

/// The hash of the set the `Preserved` barrier protects: the author frontier and the closure
/// rows (the verified closures, this replica's own included) a delta admitted past the freeze
/// would change, in canonical order, bound to the digest of the manifest that names what was
/// preserved and to the high-water mark of the final capture pass.
///
/// A disk edit made after the capture pass is deliberately not part of it: it is not authored
/// (the group is frozen), stays on disk, and is captured by the scan after the freeze ends.
pub(crate) fn frozen_frontier_hash(
    conn: &Connection,
    group: &FolderGroupId,
    manifest_sha256: &[u8; 32],
    capture_high_seq: Option<i64>,
) -> Result<[u8; 32], SyncSqliteError> {
    let mut bytes = Vec::new();
    bytes.extend(manifest_sha256);
    bytes.extend(capture_high_seq.unwrap_or(-1).to_be_bytes());
    let mut push_rows = |sql: &str, tag: u8| -> Result<(), SyncSqliteError> {
        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query([group.as_str()])?;
        while let Some(row) = rows.next()? {
            bytes.push(tag);
            let author: String = row.get(0)?;
            let incarnation: Vec<u8> = row.get(1)?;
            let cutoff: Option<i64> = row.get(2)?;
            let tip: Option<Vec<u8>> = row.get(3)?;
            bytes.extend((author.len() as u64).to_be_bytes());
            bytes.extend(author.as_bytes());
            bytes.extend((incarnation.len() as u64).to_be_bytes());
            bytes.extend(&incarnation);
            bytes.extend(cutoff.map_or([0u8; 9], |n| {
                let mut out = [1u8; 9];
                out[1..].copy_from_slice(&n.to_be_bytes());
                out
            }));
            bytes.extend(tip.unwrap_or_default());
        }
        Ok(())
    };
    push_rows(
        "SELECT author, incarnation, seq, tip FROM native_author_frontier WHERE group_id = ?1 \
         ORDER BY author, incarnation",
        1,
    )?;
    push_rows(
        "SELECT author, incarnation, cutoff_seq, cutoff_tip FROM native_closed_authors \
         WHERE group_id = ?1 ORDER BY author, incarnation",
        2,
    )?;
    push_rows(
        "SELECT author, incarnation, cutoff_seq, cutoff_tip FROM native_author_closure \
         WHERE group_id = ?1 ORDER BY author, incarnation, closure_hash",
        3,
    )?;
    Ok(sha256(&bytes))
}

/// Whether the protected set is still what the `Preserved` barrier recorded. `manifest_sha256`
/// is the digest of the manifest as it is read from the recovery area now. A journal that has
/// not recorded a hash (before `Preserved`) is never unchanged.
pub(crate) fn frozen_frontier_unchanged(
    conn: &Connection,
    group: &FolderGroupId,
    manifest_sha256: &[u8; 32],
) -> Result<bool, SyncSqliteError> {
    let row: Option<(Option<Vec<u8>>, Option<i64>)> = conn
        .query_row(
            "SELECT frozen_frontier_hash, capture_high_seq FROM native_rebootstrap_journal \
             WHERE group_id = ?1",
            [group.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((Some(recorded), capture_high_seq)) = row else { return Ok(false) };
    let now = frozen_frontier_hash(conn, group, manifest_sha256, capture_high_seq)?;
    Ok(recorded == now.as_slice())
}

/// Ends the freeze of a rebootstrap whose own intent has been replayed: the journal and
/// everything that belongs to it go, and the group admits, authors and materializes again. The
/// caller rescans the root afterwards; edits made during the freeze were never authored and are
/// still on disk. Refused (`false`) unless the journal is `Replaying` under `recovery_id` and
/// every replay step has an outcome. The frontier the replica had before the freeze is not a
/// condition: the machine ends when the tail is drained and the replay is done.
/// Returns whether a finished rebootstrap was found.
pub fn finish_rebootstrap(
    conn: &Connection,
    group: &FolderGroupId,
    recovery_id: &str,
) -> Result<bool, SyncSqliteError> {
    match rebootstrap_status(conn, group)? {
        Some(status)
            if status.state == RebootstrapState::Replaying
                && status.recovery_id == recovery_id
                && crate::native_rebootstrap_replay::outstanding_steps(conn, group)? == 0 =>
        {
            delete_rows(conn, group)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) fn set_state(
    conn: &Connection,
    group: &FolderGroupId,
    state: &str,
    now: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "UPDATE native_rebootstrap_journal SET state = ?2, updated_at = ?3 WHERE group_id = ?1",
        (group.as_str(), state, now),
    )?;
    Ok(())
}

fn set_blocked(
    conn: &Connection,
    group: &FolderGroupId,
    reason: &BlockedReason,
    now: i64,
) -> Result<(), SyncSqliteError> {
    let (code, detail) = reason.encode();
    // Once the paths are held the root is being modified: a block is recorded
    // beside the stage and the stage stays, because going back to an earlier one
    // would plan again over a root that is no longer what the plan read.
    conn.execute(
        "UPDATE native_rebootstrap_journal \
         SET state = CASE WHEN state IN ('quarantining', 'catching_up', 'replaying') THEN state \
                          ELSE 'blocked' END, \
             blocked_reason = ?2, blocked_detail = ?3, updated_at = ?4 \
         WHERE group_id = ?1",
        (group.as_str(), code, detail, now),
    )?;
    Ok(())
}

/// Forgets a block recorded beside a stage the machine has since been found able
/// to continue from.
fn clear_block(conn: &Connection, group: &FolderGroupId) -> Result<(), SyncSqliteError> {
    conn.execute(
        "UPDATE native_rebootstrap_journal SET blocked_reason = NULL, blocked_detail = NULL \
         WHERE group_id = ?1 AND state IN ('quarantining', 'catching_up', 'replaying')",
        [group.as_str()],
    )?;
    Ok(())
}

/// Deletes the journal of `group` with everything that belongs to it, the quarantine
/// rows included. Only a rebootstrap the root has not been
/// modified for may be deleted.
fn delete_journal(conn: &Connection, group: &FolderGroupId) -> Result<(), SyncSqliteError> {
    if let Some(status) = rebootstrap_status(conn, group)? {
        if matches!(
            status.state,
            RebootstrapState::Quarantining
                | RebootstrapState::CatchingUp
                | RebootstrapState::Replaying
        ) {
            return Err(SyncSqliteError::CorruptState(
                "a rebootstrap whose root has been modified is never deleted".into(),
            ));
        }
    }
    delete_rows(conn, group)
}

/// Removes every row of the group's rebootstrap in one atomic step: the journal is never gone
/// while rows that belong to it remain, nor the other way round. A savepoint, so it nests inside
/// a caller's transaction or step.
fn delete_rows(conn: &Connection, group: &FolderGroupId) -> Result<(), SyncSqliteError> {
    atomically(conn, || {
        for table in [
            "native_rebootstrap_journal",
            "native_rebootstrap_delta",
            "native_rebootstrap_recovery_item",
            "native_rebootstrap_quarantine",
        ] {
            // A retained original is owned by its quarantine row for good: the object stays
            // under its claimed name, and the row is the only record of where.
            let keep = if table == "native_rebootstrap_quarantine" {
                " AND status != 'retained'"
            } else {
                ""
            };
            conn.execute(
                &format!("DELETE FROM {table} WHERE group_id = ?1{keep}"),
                [group.as_str()],
            )?;
        }
        Ok(())
    })
}

// --- the preserve ledger ------------------------------------------------------------------

/// What a rebootstrap would do with a change this replica made, judged at
/// planning time from its authority then. It decides which originals would be
/// copied aside and which re-asserted; it never licenses authoring later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reassertability {
    Reassertable,
    /// This device is not a Writer now.
    NotWriter,
    /// Policy withholds the path.
    PolicyWithheld,
}

pub trait ReassertAuthority {
    fn classify(&self, path: &SyncPath) -> Reassertability;
}

/// The bytes of one file version held locally, to be read once and never held whole: `size` and
/// `sha256` were established over the whole content before any of it is handed out, and every
/// consumer checks the stream against them as it copies, so a read that ends short, runs long,
/// fails, or yields other bytes publishes nothing.
pub struct HeldContent<'a> {
    pub size: u64,
    pub sha256: [u8; 32],
    pub reader: Box<dyn std::io::Read + Send + 'a>,
}

impl HeldContent<'static> {
    /// Content that is already in memory (its size and digest are computed here).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            size: bytes.len() as u64,
            sha256: sha256(&bytes),
            reader: Box::new(std::io::Cursor::new(bytes)),
        }
    }
}

/// The bytes of a file version held locally.
pub trait RecoveryContentSource {
    /// The bytes of `version`, every block verified against the version's blocks, or `None` if
    /// they are not wholly held. Asked only for versions of kind file.
    fn open_version(&self, version: &FileVersion) -> Result<Option<HeldContent<'_>>, String>;

    /// The blocks of `version` that are held locally, whether or not the rest are. Asked only
    /// for versions of kind file whose bytes are not wholly held.
    fn held_blocks(&self, version: &FileVersion) -> Result<Vec<BlockHash>, String>;
}

/// An own delta the target does not cover, with its exact signed bytes.
#[derive(Clone, Debug)]
pub struct OwnDelta {
    pub hash: DeltaHash,
    pub wire: Vec<u8>,
    pub delta: NativeDelta,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayUnit {
    /// In replay order.
    pub deltas: Vec<DeltaHash>,
    pub reassertable: Reassertability,
}

/// Everything the target would lose, and the order to replay it in.
#[derive(Clone, Debug)]
pub struct PreservePlan {
    pub target_checkpoint_hash: [u8; 32],
    /// Every own incarnation that has an uncovered delta.
    pub old_authors: Vec<AuthorId>,
    /// The uncovered deltas in replay order (a topological order of the replay
    /// graph; the old chain order within an incarnation).
    pub order: Vec<OwnDelta>,
    /// The unit each delta of `order` belongs to.
    pub unit_of: Vec<usize>,
    pub units: Vec<ReplayUnit>,
    /// The file version each put of the sequence names.
    pub versions: BTreeMap<VersionHash, FileVersion>,
}

#[derive(Debug)]
pub enum PlanError {
    Blocked(BlockedReason),
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for PlanError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

/// Every own delta in the log, per incarnation of `own_device`, by seq.
fn own_log(
    conn: &Connection,
    group: &FolderGroupId,
    own_device: &DeviceId,
) -> Result<BTreeMap<AuthorId, Vec<(u64, DeltaHash)>>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT incarnation, seq, delta_hash FROM native_delta_log \
         WHERE group_id = ?1 AND author = ?2 ORDER BY incarnation, seq",
    )?;
    let rows = stmt.query_map((group.as_str(), own_device.as_str()), |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?))
    })?;
    let mut out: BTreeMap<AuthorId, Vec<(u64, DeltaHash)>> = BTreeMap::new();
    for row in rows {
        let (incarnation, seq, hash) = row?;
        let incarnation = <[u8; 16]>::try_from(incarnation.as_slice())
            .map_err(|_| SyncSqliteError::CorruptState("an incarnation is not 16 bytes".into()))?;
        let author = AuthorId {
            device: own_device.clone(),
            incarnation: yadorilink_replica_domain::author::IncarnationId(incarnation),
        };
        out.entry(author).or_default().push((seq as u64, DeltaHash(array32(hash)?)));
    }
    Ok(out)
}

/// The own deltas, ANY incarnation, authorized or not, whose dot the target's
/// frontier does not cover, with their exact bodies. A body that is missing, or
/// is not the delta the log names, makes the target not installable.
///
/// The log of each incarnation must be what the replica authored: the rows above
/// what the target covers are contiguous and end at the position the replica's
/// own frontier records, and where the target's position names a row the log
/// does not keep it lies at or below the replica's own history floor. Anything
/// else is a chain the replica cannot vouch for, and the target is not
/// installable: a silent gap would be read as nothing to preserve.
pub fn uncovered_own_deltas(
    conn: &Connection,
    group: &FolderGroupId,
    own_device: &DeviceId,
    target: &NativeAuthorFrontier,
) -> Result<Vec<OwnDelta>, PlanError> {
    let local = crate::native_store::load_frontier(conn, group)?;
    let mut out = Vec::new();
    // Every incarnation of this device the replica has a position for, closed ones
    // included, as well as every one the log has rows for: a log collected whole
    // leaves an incarnation with no rows, and what it authored above the target is
    // still to be preserved.
    let mut logs = own_log(conn, group, own_device)?;
    for author in local.keys().filter(|author| &author.device == own_device) {
        logs.entry(author.clone()).or_default();
    }
    for (author, chain) in logs {
        let blocked =
            |delta: DeltaHash| PlanError::Blocked(BlockedReason::LocalIntentUnavailable { delta });
        let tail = chain
            .last()
            .map(|(_, hash)| *hash)
            .or_else(|| local.get(&author).map(|entry| entry.tip))
            .unwrap_or(DeltaHash([0; 32]));
        let floor = crate::native_history_floor::floor_entry(conn, group, &author)?;
        let limit = match target.get(&author) {
            None => 0,
            Some(entry) => match chain.iter().find(|(seq, _)| *seq == entry.seq.get()) {
                // This incarnation forked from the target's: nothing is covered.
                Some((_, hash)) if *hash != entry.tip => 0,
                Some(_) => entry.seq.get(),
                // The log keeps no row there. The position is vouched for only by a
                // record of the replica's own at that exact seq (its floor, or its
                // own frontier) and only when the tips agree; a different tip is
                // another branch, and a seq below the floor has no evidence of
                // ancestry. Neither is covered by its seq alone.
                None => {
                    let vouched = |own: Option<&NativeAuthorFrontierEntry>| {
                        own.filter(|own| own.seq == entry.seq).map(|own| own.tip == entry.tip)
                    };
                    match vouched(floor.as_ref()).or_else(|| vouched(local.get(&author))) {
                        Some(true) => entry.seq.get(),
                        Some(false) => 0,
                        None if floor.as_ref().is_some_and(|f| entry.seq < f.seq) => 0,
                        None => return Err(blocked(tail)),
                    }
                }
            },
        };
        let counter = local.get(&author).map(|entry| entry.seq.get()).unwrap_or(0);
        let counter_tip = local.get(&author).map(|entry| entry.tip).unwrap_or(tail);
        let above: Vec<(u64, DeltaHash)> =
            chain.into_iter().filter(|(seq, _)| *seq > limit).collect();
        let expected: Vec<u64> = (limit + 1..=counter.max(limit)).collect();
        if above.iter().map(|(seq, _)| *seq).collect::<Vec<_>>() != expected {
            // The first row that is out of place, or the recorded tip if the tail
            // is what is missing.
            let culprit = above
                .iter()
                .zip(expected.iter().map(Some).chain(std::iter::repeat(None)))
                .find(|((seq, _), want)| Some(seq) != *want)
                .map(|((_, hash), _)| *hash)
                .unwrap_or(counter_tip);
            return Err(blocked(culprit));
        }
        for (seq, logged) in above {
            let unavailable = || blocked(logged);
            let wire = crate::native_store::fetch_delta_body(conn, group, &author, AuthorSeq(seq))?
                .ok_or_else(unavailable)?;
            let delta = NativeDelta::from_wire_bytes(&wire).map_err(|_| unavailable())?;
            if delta.delta_hash() != logged || delta.author != author || delta.seq.get() != seq {
                return Err(unavailable());
            }
            out.push(OwnDelta { hash: logged, wire, delta });
        }
    }
    Ok(out)
}

struct ReplayGraph {
    order: Vec<usize>,
    component: Vec<usize>,
}

fn find(parent: &mut [usize], mut node: usize) -> usize {
    while parent[node] != node {
        parent[node] = parent[parent[node]];
        node = parent[node];
    }
    node
}

/// The replay graph over `nodes` (sorted by author, then seq): chain edges
/// (same incarnation, `n -> n+1`) and removal edges (the delta that created an
/// own head, `-> ` the delta that removes it). The replay order is a topological
/// order of both; the units are the connected components over the removal edges
/// alone, joined across the parts of one recursive operation. A removal names the
/// hash of the delta that created the head, so the graph cannot hold a cycle.
fn replay_graph(nodes: &[OwnDelta]) -> Result<ReplayGraph, String> {
    let count = nodes.len();
    let by_hash: BTreeMap<DeltaHash, usize> =
        nodes.iter().enumerate().map(|(index, n)| (n.hash, index)).collect();
    let mut edges: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut parent: Vec<usize> = (0..count).collect();
    for index in 1..count {
        if nodes[index - 1].delta.author == nodes[index].delta.author {
            edges.insert((index - 1, index));
        }
    }
    for (index, node) in nodes.iter().enumerate() {
        for removal in node.delta.ops.iter().flat_map(|op| &op.removes) {
            if let Some(&creator) = by_hash.get(&removal.provenance).filter(|c| **c != index) {
                edges.insert((creator, index));
                let (a, b) = (find(&mut parent, creator), find(&mut parent, index));
                parent[a] = b;
            }
        }
    }
    let mut operations: BTreeMap<[u8; 16], usize> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        let Some(part) = node.delta.recursive_part else { continue };
        match operations.get(&part.operation_id.0) {
            Some(&first) => {
                let (a, b) = (find(&mut parent, first), find(&mut parent, index));
                parent[a] = b;
            }
            None => {
                operations.insert(part.operation_id.0, index);
            }
        }
    }
    let mut indegree = vec![0usize; count];
    for (_, to) in &edges {
        indegree[*to] += 1;
    }
    let mut ready: BTreeSet<usize> = (0..count).filter(|i| indegree[*i] == 0).collect();
    let mut order = Vec::with_capacity(count);
    while let Some(next) = ready.pop_first() {
        order.push(next);
        for (_, to) in edges.range((next, 0)..(next + 1, 0)) {
            indegree[*to] -= 1;
            if indegree[*to] == 0 {
                ready.insert(*to);
            }
        }
    }
    if order.len() != count {
        return Err("the replay graph has a cycle".into());
    }
    let mut component_ids: BTreeMap<usize, usize> = BTreeMap::new();
    let mut component = vec![0usize; count];
    for &node in &order {
        let root = find(&mut parent, node);
        let next = component_ids.len();
        component[node] = *component_ids.entry(root).or_insert(next);
    }
    Ok(ReplayGraph { order, component })
}

fn classify_unit(deltas: &[&OwnDelta], authority: &dyn ReassertAuthority) -> Reassertability {
    deltas
        .iter()
        .flat_map(|d| d.delta.ops.iter())
        .map(|op| authority.classify(&op.path))
        .find(|c| *c != Reassertability::Reassertable)
        .unwrap_or(Reassertability::Reassertable)
}

/// Computes what a rebootstrap to `target` would lose and how to replay it. Pure
/// reads: nothing is written.
pub fn plan_preservation(
    conn: &Connection,
    group: &FolderGroupId,
    own_device: &DeviceId,
    target: &NativeAuthorFrontier,
    target_checkpoint_hash: [u8; 32],
    authority: &dyn ReassertAuthority,
) -> Result<PreservePlan, PlanError> {
    let mut nodes = uncovered_own_deltas(conn, group, own_device, target)?;
    nodes.sort_by(|a, b| {
        (&a.delta.author, a.delta.seq.get()).cmp(&(&b.delta.author, b.delta.seq.get()))
    });
    let graph = replay_graph(&nodes)
        .map_err(|detail| PlanError::Blocked(BlockedReason::ManifestInconsistent { detail }))?;
    let mut unit_of = Vec::with_capacity(nodes.len());
    let mut units: Vec<Vec<usize>> = Vec::new();
    for &node in &graph.order {
        let unit = graph.component[node];
        if unit == units.len() {
            units.push(Vec::new());
        }
        units[unit].push(node);
        unit_of.push(unit);
    }
    let units = units
        .into_iter()
        .map(|members| {
            let refs: Vec<&OwnDelta> = members.iter().map(|i| &nodes[*i]).collect();
            ReplayUnit {
                deltas: refs.iter().map(|d| d.hash).collect(),
                reassertable: classify_unit(&refs, authority),
            }
        })
        .collect();
    let mut versions = BTreeMap::new();
    for &node in &graph.order {
        for put in nodes[node].delta.ops.iter().filter_map(|op| op.put.as_ref()) {
            if versions.contains_key(&put.version) {
                continue;
            }
            let version = crate::dag_store::get_file_version(conn, group.as_str(), &put.version)?
                .ok_or(PlanError::Blocked(BlockedReason::PreservationFailed(
                PreservationFailure::VersionUnknown { version: put.version },
            )))?;
            versions.insert(put.version, version);
        }
    }
    let mut old_authors: Vec<AuthorId> = nodes.iter().map(|n| n.delta.author.clone()).collect();
    old_authors.dedup();
    let mut ordered = Vec::with_capacity(nodes.len());
    let mut slots: Vec<Option<OwnDelta>> = nodes.into_iter().map(Some).collect();
    for &node in &graph.order {
        ordered.push(slots[node].take().expect("each node is ordered once"));
    }
    Ok(PreservePlan {
        target_checkpoint_hash,
        old_authors,
        order: ordered,
        unit_of,
        units,
        versions,
    })
}

// --- the machine --------------------------------------------------------------------------

/// A point at which a test may stop the process, to see what survives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failpoint {
    /// The journal says `Capturing` and the capability is issued; the pass has not run.
    BeforeCapture,
    /// The final capture pass has run and its deltas are durable; the journal still says
    /// `Capturing`.
    AfterCapture,
    /// The target, its digest, its material and its record are durable.
    AfterTargetDurable,
    /// The recovery item with this index (versions, then deltas) is durable.
    AfterRecoveryItem(usize),
    /// The files of the remote-only item with this index are durable; its row is not.
    AfterRemoteOnlyFiles(usize),
    /// The row of the remote-only item with this index is durable.
    AfterRemoteOnlyRow(usize),
    /// Every item is durable; the manifest is not written yet.
    BeforeManifest,
    /// The manifest is durable and read back; the journal still says `Preserving`.
    AfterManifest,
    /// The journal says `Preserved`.
    AtPreserved,
}

/// The process died at a failpoint.
#[derive(Debug, PartialEq, Eq)]
pub struct Crash;

/// Whether the folder was folded into the index by one complete pass over the
/// disk once the group was gated. A partial pass, unreadable entries or paused
/// items mean the old state may not know all of the user's edits.
#[derive(Clone, Debug)]
pub enum CaptureBarrier {
    Completed,
    Partial { detail: String },
}

pub struct PreserveContext<'a> {
    /// Under the daemon's state directory, outside every synced root.
    pub recovery_root: &'a Path,
    /// Where recovery items live: under the daemon's state directory, outside every synced
    /// root and apart from `recovery_root`, which is swept when a rebootstrap ends.
    pub items_root: PathBuf,
    pub sync_roots: &'a [PathBuf],
    /// Free bytes on the volume of the recovery root, when known.
    pub available_bytes: Option<u64>,
    pub capture: CaptureBarrier,
    /// The final capture pass, run once with the journal in `Capturing`.
    pub final_capture: &'a dyn FinalCapture,
    pub content: &'a dyn RecoveryContentSource,
    pub authority: &'a dyn ReassertAuthority,
    pub now_unix: i64,
}

/// What the replica has learned about its peers' history, for the entry rule.
pub struct LeaveIncremental<'a> {
    pub truncations: &'a HistoryTruncations,
    pub connected: &'a [&'a str],
}

pub struct BeginRequest<'a> {
    pub group: &'a FolderGroupId,
    pub own_device: &'a DeviceId,
    pub bundle: NativeBootstrap,
    /// The live policy the bundle is verified against, once.
    pub policy: &'a dyn NativeSealPolicy,
    pub gate: LeaveIncremental<'a>,
}

/// The durability barrier holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preserved {
    pub recovery_id: String,
    pub dir: PathBuf,
    pub manifest_sha256: [u8; 32],
    pub checkpoint_hash: [u8; 32],
}

#[derive(Debug)]
pub enum BeginError {
    /// The bundle did not verify: no journal was started.
    CandidateRefused(String),
    /// Not every connected peer has truncated the group: no journal was started.
    NotLeavingIncremental,
    /// The candidate is covered by the target already preserved (or loses the
    /// choice rule to it): nothing was started and the preserved target stands.
    NotBetterThanCurrent,
    /// The install has begun: the target of recovery id `.0` cannot be replaced.
    TargetFixed(String),
    /// Another call holds this group's rebootstrap.
    Busy,
    Blocked(BlockedReason),
    Crashed,
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for BeginError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

impl From<PlanError> for BeginError {
    fn from(error: PlanError) -> Self {
        match error {
            PlanError::Blocked(reason) => Self::Blocked(reason),
            PlanError::Store(error) => Self::Store(error),
        }
    }
}

pub(crate) fn area_failure(error: AreaError) -> BlockedReason {
    BlockedReason::PreservationFailed(match error {
        AreaError::Unavailable(detail) => PreservationFailure::RecoveryAreaUnavailable { detail },
        AreaError::Io(error) => PreservationFailure::Io { detail: error.to_string() },
        AreaError::Inconsistent(item) => PreservationFailure::CopyVerification { item },
    })
}

fn blocked(
    conn: &Connection,
    group: &FolderGroupId,
    reason: BlockedReason,
    now: i64,
) -> BeginError {
    match set_blocked(conn, group, &reason, now) {
        Ok(()) => BeginError::Blocked(reason),
        Err(error) => BeginError::Store(error),
    }
}

/// Removes a rebootstrap that has not reached the barrier (or was superseded):
/// its area, the area it replaced if that is still there, and its journal.
/// Idempotent.
fn discard(
    conn: &Connection,
    recovery_root: &Path,
    group: &FolderGroupId,
    recovery_id: &str,
) -> Result<(), SyncSqliteError> {
    if let Some(status) = rebootstrap_status(conn, group)? {
        if matches!(
            status.state,
            RebootstrapState::Quarantining
                | RebootstrapState::CatchingUp
                | RebootstrapState::Replaying
        ) {
            // The originals of the quarantined changes are in this area and nowhere
            // else.
            return Err(SyncSqliteError::CorruptState(
                "a rebootstrap whose root has been modified is never discarded".into(),
            ));
        }
    }
    let remove = |id: &str| {
        RecoveryArea::remove(recovery_root, group, id)
            .map_err(|e| SyncSqliteError::CorruptState(e.to_string()))
    };
    if let Some(older) = superseded_area(conn, group)? {
        remove(&older)?;
    }
    remove(recovery_id)?;
    delete_journal(conn, group)
}

fn superseded_area(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<Option<String>, SyncSqliteError> {
    Ok(conn
        .query_row(
            "SELECT superseded_recovery_id FROM native_rebootstrap_journal WHERE group_id = ?1",
            [group.as_str()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

/// Removes the area a barrier that now holds replaced, then forgets it.
fn sweep_superseded(
    conn: &Connection,
    recovery_root: &Path,
    group: &FolderGroupId,
) -> Result<(), SyncSqliteError> {
    if let Some(older) = superseded_area(conn, group)? {
        RecoveryArea::remove(recovery_root, group, &older)
            .map_err(|e| SyncSqliteError::CorruptState(e.to_string()))?;
        conn.execute(
            "UPDATE native_rebootstrap_journal SET superseded_recovery_id = NULL \
             WHERE group_id = ?1",
            [group.as_str()],
        )?;
    }
    Ok(())
}

pub(crate) enum BusyOrStore {
    Busy,
    Store(SyncSqliteError),
}

impl From<rusqlite::Error> for BusyOrStore {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

impl From<SyncSqliteError> for BusyOrStore {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

/// A call's claim on the group's rebootstrap, released when it is dropped.
pub(crate) struct GroupGuard<'a> {
    conn: &'a Connection,
    group: String,
}

impl Drop for GroupGuard<'_> {
    fn drop(&mut self) {
        let _ = self.conn.execute(
            "UPDATE native_rebootstrap_journal SET in_progress = 0 WHERE group_id = ?1",
            [&self.group],
        );
    }
}

/// Takes the group's rebootstrap for one call, in a write transaction that
/// reads and sets the claim together, so two callers (threads, connections,
/// processes) cannot both pass. `Busy` if another holds it.
pub(crate) fn acquire<'a>(
    conn: &'a Connection,
    group: &FolderGroupId,
) -> Result<GroupGuard<'a>, BusyOrStore> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let claimed = tx.execute(
        "UPDATE native_rebootstrap_journal SET in_progress = 1 \
         WHERE group_id = ?1 AND in_progress = 0",
        [group.as_str()],
    )?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM native_rebootstrap_journal WHERE group_id = ?1)",
        [group.as_str()],
        |row| row.get(0),
    )?;
    tx.commit()?;
    if exists && claimed == 0 {
        return Err(BusyOrStore::Busy);
    }
    Ok(GroupGuard { conn, group: group.as_str().to_owned() })
}

/// Runs `body` as one atomic step of the journal.
fn atomically<T>(
    conn: &Connection,
    body: impl FnOnce() -> Result<T, SyncSqliteError>,
) -> Result<T, SyncSqliteError> {
    conn.execute_batch("SAVEPOINT rebootstrap_step")?;
    match body() {
        Ok(value) => {
            conn.execute_batch("RELEASE rebootstrap_step")?;
            Ok(value)
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK TO rebootstrap_step; RELEASE rebootstrap_step");
            Err(error)
        }
    }
}

/// Whether `candidate` should replace the preserved target `current`: it must
/// not be covered by it. Of two incomparable targets the choice rule decides, so
/// that two peers that disagree cannot make the replica start over for each of
/// them in turn.
fn candidate_replaces(
    conn: &Connection,
    group: &FolderGroupId,
    own_device: &DeviceId,
    current: &TargetCandidate,
    candidate: &TargetCandidate,
) -> Result<bool, SyncSqliteError> {
    if frontier_covers(&current.frontier, &candidate.frontier) {
        return Ok(false);
    }
    let mut own: BTreeMap<AuthorId, Vec<DeltaHash>> = BTreeMap::new();
    for (author, rows) in own_log(conn, group, own_device)? {
        let top = rows.last().map(|(seq, _)| *seq).unwrap_or(0) as usize;
        let mut chain = vec![DeltaHash([0; 32]); top];
        for (seq, hash) in rows {
            chain[seq as usize - 1] = hash;
        }
        own.insert(author, chain);
    }
    let mut blocked = BTreeMap::new();
    for target in [current, candidate] {
        match uncovered_own_deltas(conn, group, own_device, &target.frontier) {
            Ok(_) => {}
            Err(PlanError::Blocked(reason)) => {
                blocked.insert(target.checkpoint_id, reason);
            }
            Err(PlanError::Store(error)) => return Err(error),
        }
    }
    Ok(choose_rebootstrap_target(&[current.clone(), candidate.clone()], &own, &blocked)
        .is_ok_and(|chosen| chosen == Some(candidate.checkpoint_id)))
}

/// Re-checks that the area of a journal that is not `Preserved` any more because it
/// was blocked is still a complete, valid area, and if so makes it `Preserved`
/// again: a block never discards an area that holds the user's data.
fn unblock_if_area_holds(
    conn: &Connection,
    recovery_root: &Path,
    group: &FolderGroupId,
    now: i64,
) -> Result<bool, SyncSqliteError> {
    let Some(status) = rebootstrap_status(conn, group)? else { return Ok(false) };
    if !matches!(status.state, RebootstrapState::Blocked(_)) {
        return Ok(false);
    }
    let complete = RecoveryArea::open_existing(recovery_root, group, &status.recovery_id)
        .is_ok_and(|area| area.has_manifest());
    if !complete {
        return Ok(false);
    }
    // Judged as the barrier would judge it, from a journal that says so.
    conn.execute(
        "UPDATE native_rebootstrap_journal SET state = 'preserved', updated_at = ?2 \
         WHERE group_id = ?1 AND manifest_sha256 IS NOT NULL",
        (group.as_str(), now),
    )?;
    match resume_preserved(conn, recovery_root, group) {
        Ok(preserved) => {
            // A blocked journal does not freeze the group: if anything was admitted or
            // authored meanwhile, the barrier no longer protects what is there, and only an
            // explicit discard resolves it.
            if frozen_frontier_unchanged(conn, group, &preserved.manifest_sha256)? {
                return Ok(true);
            }
            let reason = BlockedReason::ManifestInconsistent {
                detail: "the group changed while the rebootstrap was blocked".into(),
            };
            set_blocked(conn, group, &reason, now)?;
            Ok(false)
        }
        Err(reason) => {
            set_blocked(conn, group, &reason, now)?;
            Ok(false)
        }
    }
}

/// Gives up a blocked rebootstrap on purpose: its area and journal go. The
/// explicit resolution for an area that cannot be made good again.
pub fn discard_blocked_rebootstrap(
    conn: &Connection,
    recovery_root: &Path,
    group: &FolderGroupId,
) -> Result<bool, SyncSqliteError> {
    match rebootstrap_status(conn, group)? {
        Some(status) if matches!(status.state, RebootstrapState::Blocked(_)) => {
            let _busy = match acquire(conn, group) {
                Ok(guard) => guard,
                Err(BusyOrStore::Busy) => return Ok(false),
                Err(BusyOrStore::Store(error)) => return Err(error),
            };
            discard(conn, recovery_root, group, &status.recovery_id)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Starts a rebootstrap to `request.bundle` and takes it to the barrier.
///
/// A journal is started only for a bundle that verified and only when every
/// connected peer has truncated the group (an empty peer set never starts one).
/// A second call for the same target after the barrier resumes it; for another
/// target it starts over with a new recovery id, as the root is still
/// unmodified.
pub fn begin_rebootstrap(
    conn: &Connection,
    request: BeginRequest<'_>,
    ctx: &PreserveContext<'_>,
    hook: &mut dyn FnMut(Failpoint) -> Result<(), Crash>,
) -> Result<Preserved, BeginError> {
    let group = request.group;
    // Before anything is read, written or journaled: the barrier below cannot be
    // honoured on a platform that cannot flush a directory entry.
    if !crate::native_rebootstrap_recovery::directory_durability_available(ctx.recovery_root) {
        return Err(BeginError::Blocked(BlockedReason::DurabilityUnsupported));
    }
    let (verified, stored) = verify_and_prepare_target(request.bundle, group, request.policy)
        .map_err(|e| BeginError::CandidateRefused(e.to_string()))?;
    let candidate = VerifiedCandidate { checkpoint_id: verified.checkpoint_hash() };
    // Either every connected peer has truncated the group, or a verified closure has put this
    // replica above a cutoff (or a closure fork stands): incremental catch-up cannot work, and
    // no peer needs to have said so.
    let closure_forced = !crate::native_closure::needs_rebootstrap(conn, group)?.is_empty();
    if !closure_forced
        && !request.gate.truncations.should_leave_incremental(
            group,
            request.gate.connected,
            Some(&candidate),
        )
    {
        return Err(BeginError::NotLeavingIncremental);
    }
    let mut superseded = None;
    let _busy = match acquire(conn, group) {
        Ok(guard) => guard,
        Err(BusyOrStore::Busy) => return Err(BeginError::Busy),
        Err(BusyOrStore::Store(error)) => return Err(BeginError::Store(error)),
    };
    if let Some(old) = rebootstrap_status(conn, group)? {
        let mut old = old;
        if matches!(old.state, RebootstrapState::Blocked(_)) {
            // A block never discards an area that holds the user's data: it is
            // checked again and, if it holds, resumed. Only an area that never
            // got a manifest is swept.
            if unblock_if_area_holds(conn, ctx.recovery_root, group, ctx.now_unix)? {
                old = rebootstrap_status(conn, group)?.expect("the journal was just read");
            } else if RecoveryArea::open_existing(ctx.recovery_root, group, &old.recovery_id)
                .is_ok_and(|area| area.has_manifest())
            {
                // The reason may just have been replaced by the check above.
                let now = rebootstrap_status(conn, group)?.map(|s| s.state);
                let Some(RebootstrapState::Blocked(reason)) = now else {
                    return Err(BeginError::Store(SyncSqliteError::CorruptState(
                        "a blocked rebootstrap changed under its own check".into(),
                    )));
                };
                return Err(BeginError::Blocked(reason));
            }
        }
        if matches!(
            old.state,
            RebootstrapState::Quarantining
                | RebootstrapState::CatchingUp
                | RebootstrapState::Replaying
        ) {
            // The root has been modified (or is about to be): the recorded target
            // is the only target, whatever a peer offers now.
            return Err(BeginError::TargetFixed(old.recovery_id));
        }
        if old.state == RebootstrapState::Preserved {
            if old.target_checkpoint_hash == verified.checkpoint_hash() {
                if let CaptureBarrier::Partial { detail } = &ctx.capture {
                    return Err(BeginError::Blocked(BlockedReason::PreservationFailed(
                        PreservationFailure::CapturePartial { detail: detail.clone() },
                    )));
                }
                let resumed = resume_preserved(conn, ctx.recovery_root, group)
                    .map_err(BeginError::Blocked)?;
                // The group is frozen at the barrier, so the protected set is what was
                // recorded. If it is not, something wrote past the freeze: the barrier is
                // blocked, and only an explicit discard plans again.
                if !frozen_frontier_unchanged(conn, group, &resumed.manifest_sha256)? {
                    return Err(blocked(
                        conn,
                        group,
                        BlockedReason::ManifestInconsistent {
                            detail: "the group changed after the barrier".into(),
                        },
                        ctx.now_unix,
                    ));
                }
                sweep_superseded(conn, ctx.recovery_root, group)?;
                return Ok(resumed);
            } else if let Some(current) = current_candidate(ctx.recovery_root, group, &old) {
                let new = TargetCandidate {
                    checkpoint_id: verified.checkpoint_hash(),
                    frontier: verified.frontier().clone(),
                };
                if !candidate_replaces(conn, group, request.own_device, &current, &new)? {
                    return Err(BeginError::NotBetterThanCurrent);
                }
            }
            superseded = Some(old.recovery_id.clone());
        } else {
            discard(conn, ctx.recovery_root, group, &old.recovery_id)?;
        }
    }
    start_journal_and_preserve(
        conn,
        request.own_device,
        group,
        &verified,
        &stored,
        ctx,
        superseded,
        hook,
    )
}

/// Starts a journal for `verified` (replacing the one it supersedes, whose area
/// is swept once the new barrier holds) and takes it to the barrier.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_journal_and_preserve(
    conn: &Connection,
    own_device: &DeviceId,
    group: &FolderGroupId,
    verified: &VerifiedNativeBootstrap,
    stored: &StoredTarget,
    ctx: &PreserveContext<'_>,
    superseded: Option<String>,
    hook: &mut dyn FnMut(Failpoint) -> Result<(), Crash>,
) -> Result<Preserved, BeginError> {
    if let Some(old) = rebootstrap_status(conn, group)? {
        if matches!(
            old.state,
            RebootstrapState::Quarantining
                | RebootstrapState::CatchingUp
                | RebootstrapState::Replaying
        ) {
            return Err(BeginError::TargetFixed(old.recovery_id));
        }
    }
    let recovery_id = new_recovery_id();
    atomically(conn, || {
        // The replaced journal row goes only as the new one is written, and the
        // new one remembers the area to sweep.
        delete_journal(conn, group)?;
        conn.execute(
            "INSERT INTO native_rebootstrap_journal \
             (group_id, recovery_id, state, target_checkpoint_hash, superseded_recovery_id, \
              started_at, updated_at) \
             VALUES (?1, ?2, 'planning', ?3, ?4, ?5, ?5)",
            (
                group.as_str(),
                &recovery_id,
                verified.checkpoint_hash().as_slice(),
                &superseded,
                ctx.now_unix,
            ),
        )?;
        Ok(())
    })?;
    capture_pass(conn, own_device, group, ctx, &recovery_id, hook)?;
    let outcome = preserve(conn, own_device, group, verified, stored, ctx, &recovery_id, hook)?;
    sweep_superseded(conn, ctx.recovery_root, group)?;
    Ok(outcome)
}

/// Freezes the group and runs the one final capture pass: the journal moves to `Capturing`
/// (remote admission and materialization are refused, local authoring is refused to everyone
/// but the pass), the pass folds the disk into the index under its capability, and the plan
/// that follows sees what it authored. Leaving `Capturing` is what ends the capability.
fn capture_pass(
    conn: &Connection,
    own_device: &DeviceId,
    group: &FolderGroupId,
    ctx: &PreserveContext<'_>,
    recovery_id: &str,
    hook: &mut dyn FnMut(Failpoint) -> Result<(), Crash>,
) -> Result<(), BeginError> {
    set_state(conn, group, "capturing", ctx.now_unix)?;
    let authority = Arc::new(CaptureAuthority::issue(conn, group, own_device, recovery_id)?);
    hook(Failpoint::BeforeCapture).map_err(|_| BeginError::Crashed)?;
    let barrier = ctx.final_capture.capture(&authority);
    drop(authority);
    hook(Failpoint::AfterCapture).map_err(|_| BeginError::Crashed)?;
    match barrier {
        CaptureBarrier::Completed => Ok(()),
        CaptureBarrier::Partial { detail } => Err(blocked(
            conn,
            group,
            BlockedReason::PreservationFailed(PreservationFailure::CapturePartial { detail }),
            ctx.now_unix,
        )),
    }
}

/// The preserved target of `status` as a candidate, read from its area; `None` if
/// the area cannot be read (then anything replaces it).
fn current_candidate(
    recovery_root: &Path,
    group: &FolderGroupId,
    status: &RebootstrapStatus,
) -> Option<TargetCandidate> {
    let area = RecoveryArea::open_existing(recovery_root, group, &status.recovery_id).ok()?;
    let verified = verify_target_in_area(&area, group).ok()?;
    Some(TargetCandidate {
        checkpoint_id: verified.checkpoint_hash(),
        frontier: verified.frontier().clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn preserve(
    conn: &Connection,
    own_device: &DeviceId,
    group: &FolderGroupId,
    verified: &VerifiedNativeBootstrap,
    stored: &StoredTarget,
    ctx: &PreserveContext<'_>,
    recovery_id: &str,
    hook: &mut dyn FnMut(Failpoint) -> Result<(), Crash>,
) -> Result<Preserved, BeginError> {
    let block = |reason| blocked(conn, group, reason, ctx.now_unix);
    if let CaptureBarrier::Partial { detail } = &ctx.capture {
        return Err(block(BlockedReason::PreservationFailed(
            PreservationFailure::CapturePartial { detail: detail.clone() },
        )));
    }
    let plan = plan_preservation(
        conn,
        group,
        own_device,
        verified.frontier(),
        verified.checkpoint_hash(),
        ctx.authority,
    )
    .map_err(|e| match e {
        PlanError::Blocked(reason) => block(reason),
        PlanError::Store(error) => BeginError::Store(error),
    })?;
    check_space(&plan, stored, ctx).map_err(block)?;
    let area = RecoveryArea::create(ctx.recovery_root, group, recovery_id, ctx.sync_roots)
        .map_err(|e| block(area_failure(e)))?;
    set_state(conn, group, "preserving", ctx.now_unix)?;
    write_target(conn, group, &area, stored, ctx.now_unix).map_err(block)?;
    hook(Failpoint::AfterTargetDurable).map_err(|_| BeginError::Crashed)?;
    let versions = copy_items(conn, group, &area, &plan, ctx, hook)?;
    let remote_only = save_remote_only(conn, group, verified, &plan, ctx, recovery_id, hook)?;
    hook(Failpoint::BeforeManifest).map_err(|_| BeginError::Crashed)?;
    // The barrier is crossed only over a set that is wholly durable: re-read, not remembered.
    crate::native_recovery_items::verify_items(conn, &ctx.items_root, group, &remote_only)
        .map_err(block)?;
    let manifest =
        build_manifest(group, recovery_id, &plan, versions, remote_only, stored, ctx.now_unix);
    let manifest_sha256 = area.write_manifest(&manifest).map_err(|e| block(area_failure(e)))?;
    let intent = area.read_intent().map_err(|e| block(area_failure(e)))?;
    if intent.manifest != manifest {
        return Err(block(BlockedReason::ManifestInconsistent {
            detail: "the manifest read back is not the one written".into(),
        }));
    }
    // Every file and directory of the area was published by a durable move, the
    // manifest last, so the names that lead to them are on disk already.
    hook(Failpoint::AfterManifest).map_err(|_| BeginError::Crashed)?;
    set_preserved(conn, group, &manifest_sha256, ctx.now_unix)?;
    hook(Failpoint::AtPreserved).map_err(|_| BeginError::Crashed)?;
    Ok(Preserved {
        recovery_id: recovery_id.to_owned(),
        dir: area.dir().to_path_buf(),
        manifest_sha256,
        checkpoint_hash: verified.checkpoint_hash(),
    })
}

fn hex_hashes<'a>(hashes: impl Iterator<Item = &'a BlockHash>) -> Vec<String> {
    hashes.map(|hash| hex::encode(&hash.0)).collect()
}

/// Saves every head the target lacks as a recovery item, in the item store: files durable,
/// then the row. An item whose files and row are already as they would be written stays as it
/// is (a retry after a crash); a file with no row is rewritten. Returns what the manifest
/// states.
fn save_remote_only(
    conn: &Connection,
    group: &FolderGroupId,
    verified: &VerifiedNativeBootstrap,
    plan: &PreservePlan,
    ctx: &PreserveContext<'_>,
    recovery_id: &str,
    hook: &mut dyn FnMut(Failpoint) -> Result<(), Crash>,
) -> Result<Vec<ManifestRemoteOnly>, BeginError> {
    use crate::native_recovery_items as items;
    let block = |reason| blocked(conn, group, reason, ctx.now_unix);
    let replayed: BTreeSet<DeltaHash> = plan.order.iter().map(|d| d.hash).collect();
    let heads = items::plan_remote_only(conn, group, verified, &replayed)?;
    if heads.is_empty() {
        return Ok(Vec::new());
    }
    items::open_store(&ctx.items_root, group, ctx.sync_roots)
        .map_err(|e| block(area_failure(e)))?;
    items::sweep_unregistered(conn, &ctx.items_root, group)?;
    let failed = |f| block(BlockedReason::PreservationFailed(f));
    let mut entries = Vec::with_capacity(heads.len());
    for (index, head) in heads.iter().enumerate() {
        let item_id = head.item_id(group);
        let record = crate::dag_store::get_file_version(conn, group.as_str(), &head.version)?;
        let mut body = match record {
            None => items::ItemBody {
                content: items::ItemContent::RecordUnavailable,
                record: None,
                held: None,
                retained_blocks: Vec::new(),
            },
            Some(record) if record.meta.record_kind != RecordKind::File => items::ItemBody {
                content: items::ItemContent::Complete,
                record: Some(record),
                held: None,
                retained_blocks: Vec::new(),
            },
            Some(record) => {
                let held = ctx
                    .content
                    .open_version(&record)
                    .map_err(|detail| failed(PreservationFailure::Io { detail }))?;
                match held {
                    Some(held) => items::ItemBody {
                        content: items::ItemContent::Complete,
                        retained_blocks: hex_hashes(record.blocks.iter().map(|b| &b.hash)),
                        record: Some(record),
                        held: Some(held),
                    },
                    None => {
                        let held = ctx
                            .content
                            .held_blocks(&record)
                            .map_err(|detail| failed(PreservationFailure::Io { detail }))?;
                        items::ItemBody {
                            content: items::ItemContent::Unavailable,
                            retained_blocks: hex_hashes(held.iter()),
                            record: Some(record),
                            held: None,
                        }
                    }
                }
            }
        };
        let entry = items::save_item(
            conn,
            &ctx.items_root,
            group,
            head,
            &item_id,
            &mut body,
            recovery_id,
            ctx.now_unix,
            &mut || hook(Failpoint::AfterRemoteOnlyFiles(index)),
        )
        .map_err(|e| match e {
            items::SaveError::Area(e) => block(area_failure(e)),
            items::SaveError::Crashed => BeginError::Crashed,
            items::SaveError::Store(e) => e.into(),
        })?;
        hook(Failpoint::AfterRemoteOnlyRow(index)).map_err(|_| BeginError::Crashed)?;
        entries.push(entry);
    }
    Ok(entries)
}

fn set_preserved(
    conn: &Connection,
    group: &FolderGroupId,
    manifest_sha256: &[u8; 32],
    now: i64,
) -> Result<(), SyncSqliteError> {
    let capture_high_seq: Option<i64> = conn.query_row(
        "SELECT capture_high_seq FROM native_rebootstrap_journal WHERE group_id = ?1",
        [group.as_str()],
        |row| row.get(0),
    )?;
    let frontier_hash = frozen_frontier_hash(conn, group, manifest_sha256, capture_high_seq)?;
    conn.execute(
        "UPDATE native_rebootstrap_journal \
         SET state = 'preserved', manifest_sha256 = ?2, frozen_frontier_hash = ?4, \
             updated_at = ?3 WHERE group_id = ?1",
        (group.as_str(), manifest_sha256.as_slice(), now, frontier_hash.as_slice()),
    )?;
    Ok(())
}

/// The bytes the area will hold: the bundle, the replay deltas, each version, a
/// little for the manifest.
fn check_space(
    plan: &PreservePlan,
    stored: &StoredTarget,
    ctx: &PreserveContext<'_>,
) -> Result<(), BlockedReason> {
    let needed: u64 = stored.bundle.len() as u64
        + stored.material.len() as u64
        + plan.order.iter().map(|d| d.wire.len() as u64).sum::<u64>()
        + plan.versions.values().map(|v| v.size).sum::<u64>()
        + 4096 * (1 + plan.order.len() as u64);
    match ctx.available_bytes {
        Some(available) if available < needed => {
            Err(BlockedReason::PreservationFailed(PreservationFailure::InsufficientSpace {
                needed,
                available,
            }))
        }
        _ => Ok(()),
    }
}

/// Writes the target first: the exact bundle and its digest, then what verifies
/// it again locally, then the record that permits the install; each read back.
fn write_target(
    conn: &Connection,
    group: &FolderGroupId,
    area: &RecoveryArea,
    stored: &StoredTarget,
    now: i64,
) -> Result<(), BlockedReason> {
    let io = |e| area_failure(e);
    let digest = area.write_target_bundle(&stored.bundle).map_err(io)?;
    area.write_material(&stored.material).map_err(io)?;
    area.write_verification_record(&stored.record).map_err(io)?;
    let back = StoredTarget {
        bundle: area.read_target_bundle().map_err(io)?,
        bundle_sha256: area.read_target_digest().map_err(io)?,
        material: area.read_material().map_err(io)?,
        record: area.read_verification_record().map_err(io)?,
        checkpoint_hash: stored.checkpoint_hash,
    };
    if back != *stored || digest != stored.bundle_sha256 {
        return Err(BlockedReason::PreservationFailed(PreservationFailure::CopyVerification {
            item: "target.bundle".into(),
        }));
    }
    verify_stored_target(group, &back).map_err(|e| {
        BlockedReason::PreservationFailed(PreservationFailure::TargetNotVerifiable {
            detail: e.to_string(),
        })
    })?;
    conn.execute(
        "UPDATE native_rebootstrap_journal SET target_bundle_sha256 = ?2, updated_at = ?3 \
         WHERE group_id = ?1",
        (group.as_str(), digest.as_slice(), now),
    )
    .map_err(|e| {
        BlockedReason::PreservationFailed(PreservationFailure::Io { detail: e.to_string() })
    })?;
    Ok(())
}

fn record_item(
    conn: &Connection,
    group: &FolderGroupId,
    key: &str,
    kind: &str,
    size: u64,
    hash: &[u8; 32],
    status: &str,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT INTO native_rebootstrap_recovery_item \
         (group_id, item_key, kind, size, content_hash, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(group_id, item_key) DO UPDATE SET status = excluded.status",
        (group.as_str(), key, kind, size as i64, hash.as_slice(), status),
    )?;
    Ok(())
}

/// Copies every version, then every delta, into the area; each is written,
/// fsynced, read back and only then marked copied. Returns what each version's
/// copy turned out to be.
fn copy_items(
    conn: &Connection,
    group: &FolderGroupId,
    area: &RecoveryArea,
    plan: &PreservePlan,
    ctx: &PreserveContext<'_>,
    hook: &mut dyn FnMut(Failpoint) -> Result<(), Crash>,
) -> Result<Vec<ManifestVersion>, BeginError> {
    let block = |reason| blocked(conn, group, reason, ctx.now_unix);
    let total = plan.versions.values().filter(|v| v.meta.record_kind == RecordKind::File).count()
        + plan.order.len();
    conn.execute(
        "UPDATE native_rebootstrap_journal SET items_total = ?2 WHERE group_id = ?1",
        (group.as_str(), total as i64),
    )
    .map_err(SyncSqliteError::from)?;
    for (ordinal, delta) in plan.order.iter().enumerate() {
        conn.execute(
            "INSERT INTO native_rebootstrap_delta (group_id, ordinal, old_delta_hash) \
             VALUES (?1, ?2, ?3)",
            (group.as_str(), ordinal as i64, delta.hash.0.as_slice()),
        )
        .map_err(SyncSqliteError::from)?;
    }
    let mut copies = Vec::new();
    let mut done = 0usize;
    for version in plan.versions.values() {
        let entry = copy_version(conn, group, area, version, ctx).map_err(block)?;
        if entry.has_bytes {
            done += 1;
            mark_copied(conn, group, done, ctx.now_unix)?;
            hook(Failpoint::AfterRecoveryItem(done - 1)).map_err(|_| BeginError::Crashed)?;
        }
        copies.push(entry);
    }
    for delta in &plan.order {
        let key = format!("deltas/{}.bin", hex::encode(delta.hash.0));
        let digest = sha256(&delta.wire);
        record_item(conn, group, &key, "delta", delta.wire.len() as u64, &digest, "pending")?;
        area.write_delta(&delta.hash, &delta.wire).map_err(|e| block(area_failure(e)))?;
        if area.read_delta(&delta.hash).map_err(|e| block(area_failure(e)))? != delta.wire {
            return Err(block(BlockedReason::PreservationFailed(
                PreservationFailure::CopyVerification { item: key },
            )));
        }
        record_item(conn, group, &key, "delta", delta.wire.len() as u64, &digest, "copied")?;
        done += 1;
        mark_copied(conn, group, done, ctx.now_unix)?;
        hook(Failpoint::AfterRecoveryItem(done - 1)).map_err(|_| BeginError::Crashed)?;
    }
    Ok(copies)
}

fn mark_copied(
    conn: &Connection,
    group: &FolderGroupId,
    copied: usize,
    now: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "UPDATE native_rebootstrap_journal SET items_copied = ?2, updated_at = ?3 \
         WHERE group_id = ?1",
        (group.as_str(), copied as i64, now),
    )?;
    Ok(())
}

fn record_kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::File => "file",
        RecordKind::Directory => "directory",
        RecordKind::Symlink => "symlink",
    }
}

fn copy_version(
    conn: &Connection,
    group: &FolderGroupId,
    area: &RecoveryArea,
    version: &FileVersion,
    ctx: &PreserveContext<'_>,
) -> Result<ManifestVersion, BlockedReason> {
    let mut entry = ManifestVersion {
        version: version.version_hash,
        record_kind: record_kind_name(version.meta.record_kind).into(),
        has_bytes: false,
        size: 0,
        sha256: sha256(&[]),
        mtime_unix_nanos: version.meta.mtime_unix_nanos,
        unix_mode: version.meta.unix_mode,
        symlink_target: version.meta.symlink_target.clone(),
    };
    let failed = |f| BlockedReason::PreservationFailed(f);
    // The whole record, read back and re-hashed, so the version can be replayed
    // from the area without the index.
    area.write_record(version).map_err(area_failure)?;
    if area.read_record(&version.version_hash).map_err(area_failure)? != *version {
        return Err(failed(PreservationFailure::CopyVerification {
            item: format!("versions/{}.record", hex::encode(version.version_hash.0)),
        }));
    }
    if version.meta.record_kind != RecordKind::File {
        return Ok(entry);
    }
    let mut held = ctx
        .content
        .open_version(version)
        .map_err(|detail| failed(PreservationFailure::Io { detail }))?
        .ok_or_else(|| {
            failed(PreservationFailure::ContentUnavailable { version: version.version_hash })
        })?;
    let key = format!("versions/{}", hex::encode(version.version_hash.0));
    let (size, digest) = (held.size, held.sha256);
    let pending = |status| {
        record_item(conn, group, &key, "version", size, &digest, status)
            .map_err(|e| failed(PreservationFailure::Io { detail: e.to_string() }))
    };
    pending("pending")?;
    // Streamed into the area under the digest the source established: a read that fails or
    // yields other bytes publishes nothing.
    area.write_version_from(&version.version_hash, &mut held.reader, size, &digest)
        .map_err(area_failure)?;
    drop(held);
    // Hashed back through a fixed buffer: the copy is never held whole.
    if !area.version_matches(&version.version_hash, &digest, size).map_err(area_failure)? {
        return Err(failed(PreservationFailure::CopyVerification { item: key }));
    }
    pending("copied")?;
    entry.has_bytes = true;
    entry.size = size;
    entry.sha256 = digest;
    Ok(entry)
}

fn build_manifest(
    group: &FolderGroupId,
    recovery_id: &str,
    plan: &PreservePlan,
    versions: Vec<ManifestVersion>,
    remote_only: Vec<ManifestRemoteOnly>,
    stored: &StoredTarget,
    now: i64,
) -> Manifest {
    let reason = |c: &Reassertability| match c {
        Reassertability::Reassertable => None,
        Reassertability::NotWriter => Some("not_writer".to_owned()),
        Reassertability::PolicyWithheld => Some("path_withheld".to_owned()),
    };
    let mut items = Vec::new();
    for (index, delta) in plan.order.iter().enumerate() {
        let unit = plan.unit_of[index];
        for (op_index, op) in delta.delta.ops.iter().enumerate() {
            items.push(ManifestItem {
                delta: delta.hash,
                op_index,
                path: op.path.as_str().to_owned(),
                put_version: op.put.as_ref().map(|p| p.version),
                removes: op
                    .removes
                    .iter()
                    .map(|r| ManifestRemoval {
                        author: r.dot.author.clone(),
                        seq: r.dot.seq.get(),
                        header: r.provenance,
                    })
                    .collect(),
                reassertable: plan.units[unit].reassertable == Reassertability::Reassertable,
                unit,
            });
        }
    }
    Manifest {
        group_id: group.as_str().to_owned(),
        recovery_id: recovery_id.to_owned(),
        created_at: now,
        target_checkpoint_hash: plan.target_checkpoint_hash,
        target_bundle_sha256: stored.bundle_sha256,
        target_bundle_size: stored.bundle.len() as u64,
        verification_record_sha256: sha256(&stored.record),
        material_sha256: sha256(&stored.material),
        old_authors: plan.old_authors.clone(),
        delta_order: plan.order.iter().map(|d| d.hash).collect(),
        deltas: plan
            .order
            .iter()
            .enumerate()
            .map(|(index, d)| ManifestDelta {
                hash: d.hash,
                author: d.delta.author.clone(),
                seq: d.delta.seq.get(),
                wire_size: d.wire.len() as u64,
                wire_sha256: sha256(&d.wire),
                unit: plan.unit_of[index],
                recursive: d.delta.recursive_part.map(|part| {
                    crate::native_rebootstrap_recovery::ManifestRecursive {
                        operation_id: part.operation_id.0,
                        part_index: part.part_index,
                        part_count: part.part_count,
                    }
                }),
            })
            .collect(),
        units: plan
            .units
            .iter()
            .map(|u| ManifestUnit {
                deltas: u.deltas.clone(),
                reassertable: u.reassertable == Reassertability::Reassertable,
                reason: reason(&u.reassertable),
            })
            .collect(),
        versions,
        items,
        remote_only,
    }
}

// --- restart --------------------------------------------------------------------------------

/// What a restart found.
#[derive(Debug, PartialEq, Eq)]
pub enum RestartOutcome {
    /// No rebootstrap.
    Idle,
    /// A rebootstrap that had not reached the barrier was discarded: the old
    /// state is authoritative and the group may start over.
    Abandoned { recovery_id: String },
    /// The barrier held: resume from the manifest.
    Preserved(Preserved),
    /// The root may be partly quarantined: resume the install from the stored
    /// target.
    Quarantining(Preserved),
    /// The target is installed and the bounded catch-up has not finished: run it again with
    /// a fresh bound.
    CatchingUp(Preserved),
    /// The catch-up is over: the replay of own intent continues from its cursor.
    Replaying(Preserved),
    /// Blocked, as it was; the cause is in the status.
    Blocked(BlockedReason),
}

/// Reads the area of the group's preserved rebootstrap and verifies it: the
/// manifest against itself and the files, and the stored target locally.
pub fn resume_preserved(
    conn: &Connection,
    recovery_root: &Path,
    group: &FolderGroupId,
) -> Result<Preserved, BlockedReason> {
    let status = rebootstrap_status(conn, group)
        .map_err(|e| BlockedReason::ManifestInconsistent { detail: e.to_string() })?
        .filter(|s| {
            matches!(s.state, RebootstrapState::Preserved | RebootstrapState::Quarantining)
                || s.state.is_installed()
        })
        .ok_or_else(|| BlockedReason::ManifestInconsistent {
            detail: "no preserved rebootstrap".into(),
        })?;
    let inconsistent = |detail: String| BlockedReason::ManifestInconsistent { detail };
    let area = RecoveryArea::open_existing(recovery_root, group, &status.recovery_id)
        .map_err(|e| inconsistent(e.to_string()))?;
    let intent = area.read_intent().map_err(|e| inconsistent(e.to_string()))?;
    if intent.manifest.recovery_id != status.recovery_id
        || intent.manifest.target_checkpoint_hash != status.target_checkpoint_hash
        || intent.manifest.group_id != group.as_str()
    {
        return Err(inconsistent("the manifest is not this rebootstrap's".into()));
    }
    // The area must be the one the barrier recorded, not merely one that agrees
    // with itself: a directory swapped in by anything else is self-consistent too.
    let manifest_sha256 =
        sha256(&area.read_manifest_bytes().map_err(|e| inconsistent(e.to_string()))?);
    if status.manifest_sha256 != Some(manifest_sha256) {
        return Err(inconsistent("the manifest is not the one the barrier recorded".into()));
    }
    let bundle_sha256 =
        sha256(&area.read_target_bundle().map_err(|e| inconsistent(e.to_string()))?);
    if status.target_bundle_sha256 != Some(bundle_sha256) {
        return Err(inconsistent("the target bundle is not the one the journal recorded".into()));
    }
    let verified = verify_target_in_area(&area, group).map_err(|e| {
        BlockedReason::PreservationFailed(PreservationFailure::TargetNotVerifiable {
            detail: e.to_string(),
        })
    })?;
    // The manifest's checkpoint was just compared with the journal's.
    if verified.checkpoint_hash() != intent.manifest.target_checkpoint_hash {
        return Err(inconsistent(
            "the stored target is not the checkpoint the manifest names".into(),
        ));
    }
    Ok(Preserved {
        recovery_id: status.recovery_id,
        dir: area.dir().to_path_buf(),
        manifest_sha256,
        checkpoint_hash: verified.checkpoint_hash(),
    })
}

/// Verifies the target stored in `area` from what is stored in it alone: no
/// peer, no authority and no live policy.
pub fn verify_target_in_area(
    area: &RecoveryArea,
    group: &FolderGroupId,
) -> Result<VerifiedNativeBootstrap, TargetError> {
    let unreadable = |e: AreaError| TargetError::NotVerifiable(e.to_string());
    let stored = StoredTarget {
        bundle: area.read_target_bundle().map_err(unreadable)?,
        bundle_sha256: area.read_target_digest().map_err(unreadable)?,
        material: area.read_material().map_err(unreadable)?,
        record: area.read_verification_record().map_err(unreadable)?,
        checkpoint_hash: [0; 32],
    };
    verify_stored_target(group, &stored)
}

/// What to do about the group's rebootstrap after a restart. Before the barrier
/// the old state is authoritative and the half-written area is discarded; after
/// it the manifest is the recovery basis. Also removes any area that was left
/// incomplete and belongs to no journal.
pub fn recover_after_restart(
    conn: &Connection,
    recovery_root: &Path,
    group: &FolderGroupId,
) -> Result<RestartOutcome, SyncSqliteError> {
    conn.execute(
        "UPDATE native_rebootstrap_journal SET in_progress = 0 WHERE group_id = ?1",
        [group.as_str()],
    )?;
    let status = rebootstrap_status(conn, group)?;
    let outcome = match &status {
        None => RestartOutcome::Idle,
        Some(s) => match &s.state {
            RebootstrapState::Planning
            | RebootstrapState::Capturing
            | RebootstrapState::Preserving => {
                discard(conn, recovery_root, group, &s.recovery_id)?;
                RestartOutcome::Abandoned { recovery_id: s.recovery_id.clone() }
            }
            RebootstrapState::Blocked(reason) => RestartOutcome::Blocked(reason.clone()),
            RebootstrapState::Preserved
            | RebootstrapState::Quarantining
            | RebootstrapState::CatchingUp
            | RebootstrapState::Replaying => match resume_preserved(conn, recovery_root, group) {
                Ok(preserved) => {
                    clear_block(conn, group)?;
                    // A crash between the barrier and the sweep of the area it
                    // replaced leaves that area behind.
                    sweep_superseded(conn, recovery_root, group)?;
                    match s.state {
                        RebootstrapState::Quarantining => RestartOutcome::Quarantining(preserved),
                        RebootstrapState::CatchingUp => RestartOutcome::CatchingUp(preserved),
                        RebootstrapState::Replaying => RestartOutcome::Replaying(preserved),
                        _ => RestartOutcome::Preserved(preserved),
                    }
                }
                Err(reason) => {
                    set_blocked(conn, group, &reason, s.updated_at)?;
                    RestartOutcome::Blocked(reason)
                }
            },
        },
    };
    // An area without a manifest never reached the barrier, whatever the journal
    // says: no complete area is touched.
    for id in RecoveryArea::incomplete_ids(recovery_root, group)
        .map_err(|e| SyncSqliteError::CorruptState(e.to_string()))?
    {
        RecoveryArea::remove(recovery_root, group, &id)
            .map_err(|e| SyncSqliteError::CorruptState(e.to_string()))?;
    }
    Ok(outcome)
}

/// The candidate can no longer be used and nothing has been installed: the
/// rebootstrap is blocked, and its half-written area is left for the restart
/// sweep. Refused once the barrier holds: a durable target does not expire.
pub fn expire_candidate(
    conn: &Connection,
    group: &FolderGroupId,
    now: i64,
) -> Result<bool, SyncSqliteError> {
    let Some(status) = rebootstrap_status(conn, group)? else { return Ok(false) };
    match status.state {
        RebootstrapState::Planning | RebootstrapState::Capturing | RebootstrapState::Preserving => {
            set_blocked(conn, group, &BlockedReason::CandidateExpired, now)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}
