//! The one destructive transition of a group's native state.
//!
//! [`install_checkpoint`] clears the group's native state and installs a verified
//! checkpoint bundle in its place. Nothing else in the crate replaces or clears a
//! group's state: a device that joins a group for the first time and a device that
//! rebootstraps both call it, the first on state that is empty (the clear has
//! nothing to delete), the second behind the preserved barrier.
//!
//! The install never merges. A checkpoint is not joined into state that is there:
//! anything the replica holds that the target does not cover has been set aside by
//! the rebootstrap barrier before this runs, so there is nothing to reconcile and
//! nothing the install could silently drop.
//!
//! In order, all in the caller's transaction:
//!
//! 1. the kind is checked: a fresh install needs empty state; a rebootstrap needs
//!    the marker of its own recovery id, a journal in `Quarantining`, and the
//!    barrier exactly as it was recorded (the frozen frontier and the recovery
//!    items), read again here, immediately before the clear;
//! 2. the target is checked against the closures this replica already holds;
//! 3. the group's native state is cleared;
//! 4. the target is installed, with the closures it carries stored bound to its
//!    checkpoint;
//! 5. the projection is armed for every path whose heads changed;
//! 6. a rebootstrap rotates this device to a new incarnation and closes the old
//!    ones.
//!
//! An `Err` leaves the transaction to be dropped: nothing is committed by this
//! function, and nothing is recorded by a refusal.

use std::collections::BTreeSet;

use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationMintReason};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId};
use yadorilink_replica_domain::native_frontier::{
    beyond_closed_cutoff, AuthorState, NativeAuthorFrontierEntry,
};

use crate::error::SyncSqliteError;
use crate::native_bootstrap::VerifiedNativeBootstrap;
use crate::native_rebootstrap::{
    frozen_frontier_unchanged, rebootstrap_status, BlockedReason, Crash, InstallAuthority,
    RebootstrapState,
};
use crate::native_rebootstrap_install::InstallStep;
use crate::native_rebootstrap_recovery::Manifest;
use crate::native_recovery_items::verify_items;

/// Tables with a `group_id` column the install clears for the group: the
/// replicated native state, what is derived from it, and the evidence that
/// belongs to it.
pub const CLEARED_BY_INSTALL: &[&str] = &[
    "author_own_ahead",
    "native_author_context",
    "native_author_frontier",
    "native_authoring_witness",
    "native_authorization_checkpoints",
    "native_checkpoint_frontier",
    "native_checkpoint_seal_evidence",
    "native_checkpoints",
    "native_closed_authors",
    "native_delta_bodies",
    "native_delta_holds",
    "native_delta_log",
    "native_heads",
    "native_history_floor",
    "native_local_capture",
    "native_recursive_operation_parts",
    "native_removal_operation",
];

/// Tables with a `group_id` column the install keeps: the rebootstrap's own
/// bookkeeping, the verified closures (protocol evidence the target's bundle
/// is checked against and that keeps gating admission), and everything that
/// describes the sync root rather than the native state.
pub const PRESERVED_BY_INSTALL: &[&str] = &[
    // The verified closures, and the rebootstrap's own bookkeeping.
    "native_author_closure",
    "native_rebootstrap_delta",
    "native_rebootstrap_journal",
    "native_rebootstrap_quarantine",
    "native_rebootstrap_retained_digest",
    "native_rebootstrap_recovery_item",
    // Recovery items: only an explicit discard deletes them.
    "native_recovery_item",
    // Custody leases this device holds for other devices: a promise to a
    // requester that only its explicit release ends.
    "remote_custody_lease",
    // Attempts a requester released, kept so a late acquire commits nothing.
    "remote_custody_release_tombstone",
    // The close a granted removal ticket holds on new custody leases: a promise
    // to the device that holds the ticket, ended only by its release.
    "custody_ticket_close",
    // Custody this device asked other devices to hold for it: the record the
    // release of those leases is driven from.
    "remote_custody_hold",
    // The contested paths: re-judged for every path whose heads the install
    // changes ([`crate::native_desired_state::arm_projection_for_state_change`]).
    "native_contest_candidate",
    // The units of own intent a replay did not author: the area that holds them stays.
    "native_unreplayed_unit",
    // A cache token that moves by trigger when the tables it covers change.
    "native_state_generation",
    // What describes the sync root and this device's use of the group.
    "block_fetch_refusals",
    "duplicate_recovery_paths",
    "durability_unknown_latches",
    "enrollment_operations",
    "file_root_set_generation",
    "file_version_blocks",
    "file_versions",
    "files",
    "group_block_provenance",
    "group_local_history_floor",
    "group_policy_watermark",
    "handoff_leases",
    "held_paths",
    "links",
    "local_dirty_paths",
    "materialization_intents",
    "materialization_replaced_targets",
    "materialization_tmp_files",
    "offline_group_policy_log",
    "offline_peer_authorization_group",
    "path_actual_mutation_fences",
    "path_local_history_erased",
    "path_materialized_generations",
    "paused_items",
    "pinned_items",
    "provider_dirs",
    "provider_dirty_paths",
    "provider_items",
    "provider_roots",
    // The durable intent to remove an OS domain: an install never changes it.
    "provider_removals",
    "pending_enrollments",
    "projection_obligations",
    "restore_operations",
    "retained_directories",
    // A rewind's progress journal: what it authored are ordinary changes,
    // and the row only says how far the run got.
    "rewind_runs",
    "role_loss_operations",
    "stranded_directories",
    "structural_directory_origins",
    "structural_provenance_lost",
];

/// What the install runs under.
pub enum InstallKind<'a> {
    /// A group this replica holds no native state of.
    Fresh,
    /// The rebootstrap whose journal is `Quarantining` for the authority's recovery id.
    Rebootstrap(RebootstrapBarrier<'a>),
}

/// What a rebootstrap install proves and uses.
pub struct RebootstrapBarrier<'a> {
    /// The marker of the one rebootstrap this install belongs to.
    pub authority: &'a InstallAuthority,
    /// The manifest the barrier recorded.
    pub manifest: &'a Manifest,
    pub manifest_sha256: &'a [u8; 32],
    /// Where the recovery items live.
    pub items_root: &'a std::path::Path,
    /// The signing key of this device when it may close its own old incarnations.
    /// Without it (no write authority) the install signs no closure.
    pub closure_key: Option<&'a ed25519_dalek::SigningKey>,
}

/// What an install changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InstalledCheckpoint {
    /// Paths whose live heads differ after the install.
    pub changed_paths: Vec<String>,
    /// The incarnation this device authors as from now on, when the install rotated it.
    pub new_author: Option<AuthorId>,
}

/// Why a checkpoint was not installed. Nothing of it is written.
#[derive(Debug)]
pub enum CheckpointError {
    /// A fresh install into state that is there.
    NotEmpty,
    /// The marker does not belong to the rebootstrap the journal is at, or the journal
    /// is not at the stage the install runs from.
    NotInstallable(String),
    /// What the barrier protected is not what it recorded: something wrote past the
    /// freeze. Found before anything was cleared.
    FrontierChanged,
    /// What the clear would destroy is not saved.
    Blocked(BlockedReason),
    /// A verified closure this replica holds closes `author` at a cutoff below the
    /// target's frontier of it.
    RetiredAuthorLifted {
        author: AuthorId,
        cutoff: Option<u64>,
        target: u64,
    },
    /// Two valid closures of `author`, or a closure and the target's position of it,
    /// cut the chain at sequence `seq` with different tips.
    ClosureFork {
        author: AuthorId,
        seq: u64,
    },
    /// A closure the target carries is not bound to its checkpoint as a replacement.
    ClosureNotBound {
        author: AuthorId,
    },
    Crashed,
    Store(SyncSqliteError),
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEmpty => write!(f, "this replica already holds native state of the group"),
            Self::NotInstallable(why) => write!(f, "the checkpoint cannot be installed: {why}"),
            Self::FrontierChanged => write!(f, "the group changed after the barrier"),
            Self::Blocked(reason) => write!(f, "the barrier no longer holds: {reason:?}"),
            Self::RetiredAuthorLifted { author, cutoff, target } => write!(
                f,
                "a verified closure closes {author:?} at {cutoff:?}, but the target holds it at \
                 seq {target}"
            ),
            Self::ClosureFork { author, seq } => {
                write!(f, "the closures of {author:?} disagree about the tip at seq {seq}")
            }
            Self::ClosureNotBound { author } => {
                write!(f, "the closure of {author:?} is not bound to the checkpoint it came in")
            }
            Self::Crashed => write!(f, "crashed"),
            Self::Store(error) => write!(f, "{error}"),
        }
    }
}

impl From<SyncSqliteError> for CheckpointError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

impl From<rusqlite::Error> for CheckpointError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

/// Replaces `group`'s native state by `verified`'s, in the caller's transaction.
/// `step` is told how far the install got, and a crash it returns stops the install
/// there.
pub fn install_checkpoint(
    tx: &Connection,
    group: &FolderGroupId,
    verified: VerifiedNativeBootstrap,
    kind: InstallKind<'_>,
    step: &mut dyn FnMut(InstallStep) -> Result<(), Crash>,
) -> Result<InstalledCheckpoint, CheckpointError> {
    let barrier = match &kind {
        InstallKind::Fresh => {
            require_empty(tx, group)?;
            None
        }
        InstallKind::Rebootstrap(barrier) => {
            check_barrier(tx, group, barrier)?;
            Some(barrier)
        }
    };
    refuse_what_known_closures_contradict(tx, group, &verified)?;

    // What vouches for this device's key is cleared with the native state and comes
    // back only if the target carries it: the closure of the old incarnation needs it.
    let own_authorization = match barrier.and_then(|b| b.closure_key) {
        Some(key) => crate::native_publication::latest_authorization_for_device(
            tx,
            group.as_str(),
            crate::author_incarnation::current_author(tx)?.device.as_str(),
            &key.verifying_key().to_bytes(),
        )?,
        None => None,
    };
    let old_state = crate::native_store::load_state(tx, group)?;

    clear_native_state(tx, group)?;
    let mut done = |s| step(s).map_err(|_| CheckpointError::Crashed);
    done(InstallStep::NativeStateCleared)?;

    write_target(tx, group, verified)?;
    done(InstallStep::TargetInstalled)?;

    // The clear dropped every derived fact of the group (placements, stable names, kept
    // copies), so every path of the target is armed as if it were new, and so is every
    // path only the old state had.
    let installed_state = crate::native_store::load_state(tx, group)?;
    let nothing = yadorilink_replica_domain::native_state::NativeState::new();
    crate::native_desired_state::arm_projection_for_state_change(
        tx,
        group.as_str(),
        &nothing,
        &installed_state,
    )?;
    crate::native_desired_state::arm_projection_for_state_change(
        tx,
        group.as_str(),
        &old_state,
        &nothing,
    )?;
    done(InstallStep::ProjectionArmed)?;
    // A provider root's namespace now exists (its rows are the projector's to write): the
    // verification of the initial build may run.
    tx.execute("UPDATE provider_roots SET install_done = 1 WHERE group_id = ?1", [group.as_str()])?;

    let new_author = match barrier {
        Some(barrier) => Some(rotate_and_close(tx, group, barrier, own_authorization)?),
        None => None,
    };
    if barrier.is_some() {
        done(InstallStep::Rotated)?;
    }

    let changed_paths = old_state
        .heads
        .keys()
        .chain(installed_state.heads.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| old_state.heads.get(*path) != installed_state.heads.get(*path))
        .map(|path| path.as_str().to_owned())
        .collect();
    Ok(InstalledCheckpoint { changed_paths, new_author })
}

// --- the kind --------------------------------------------------------------------------------------

/// A fresh install needs a group without native state: no live head, no context and no
/// frontier entry.
fn require_empty(conn: &Connection, group: &FolderGroupId) -> Result<(), CheckpointError> {
    let state = crate::native_store::load_state(conn, group)?;
    let frontier = crate::native_store::load_frontier(conn, group)?;
    if state.heads.is_empty() && state.context.is_empty() && frontier.is_empty() {
        Ok(())
    } else {
        Err(CheckpointError::NotEmpty)
    }
}

/// The rebootstrap install runs from `Quarantining`, for the recovery id of its own
/// marker, over the barrier exactly as it was recorded: re-read now, immediately
/// before the clear, not remembered from the transition into the quarantine.
fn check_barrier(
    tx: &Connection,
    group: &FolderGroupId,
    barrier: &RebootstrapBarrier<'_>,
) -> Result<(), CheckpointError> {
    let status = rebootstrap_status(tx, group)?
        .ok_or_else(|| CheckpointError::NotInstallable("no rebootstrap".into()))?;
    if status.state != RebootstrapState::Quarantining {
        return Err(CheckpointError::NotInstallable(format!("it is {:?}", status.state)));
    }
    if !barrier.authority.is_for(group, &status.recovery_id)
        || barrier.manifest.recovery_id != status.recovery_id
    {
        return Err(CheckpointError::NotInstallable(
            "the install marker is for another rebootstrap".into(),
        ));
    }
    // The group has been frozen since the final capture. If something was written past
    // the freeze anyway, clearing the old state would delete it with no copy of it
    // anywhere.
    if !frozen_frontier_unchanged(tx, group, barrier.manifest_sha256)? {
        return Err(CheckpointError::FrontierChanged);
    }
    // What the clear would destroy must be saved: the items are re-read here.
    verify_items(tx, barrier.items_root, group, &barrier.manifest.remote_only)
        .map_err(CheckpointError::Blocked)
}

/// The target must not contradict a closure this replica holds, nor one the target
/// itself carries: an author this replica refuses above a cutoff is not lifted above
/// it by the frontier the install writes, and two closures that cut the chain
/// differently are never resolved by picking one.
fn refuse_what_known_closures_contradict(
    tx: &Connection,
    group: &FolderGroupId,
    verified: &VerifiedNativeBootstrap,
) -> Result<(), CheckpointError> {
    let carried_closures = &verified.payload().closures;
    let mut authors: BTreeSet<AuthorId> =
        crate::native_closure::closure_authors(tx, group)?.into_iter().collect();
    authors.extend(carried_closures.iter().map(|closure| closure.closure.author.clone()));
    for author in authors {
        let carried = carried_closures
            .iter()
            .filter(|closure| closure.closure.author == author)
            .map(|closure| closure.closure.cutoff);
        let Some(effective) =
            crate::native_closure::effective_from_rows_with(tx, group, &author, carried)?
        else {
            continue;
        };
        if effective.fork {
            return Err(CheckpointError::ClosureFork {
                author,
                seq: effective.seq.map_or(0, AuthorSeq::get),
            });
        }
        let Some(theirs) = verified.frontier().get(&author) else { continue };
        if beyond_closed_cutoff(effective.seq, theirs.seq) {
            return Err(CheckpointError::RetiredAuthorLifted {
                author,
                cutoff: effective.seq.map(AuthorSeq::get),
                target: theirs.seq.get(),
            });
        }
        if effective.seq == Some(theirs.seq) && effective.tip != Some(theirs.tip) {
            return Err(CheckpointError::ClosureFork { author, seq: theirs.seq.get() });
        }
    }
    Ok(())
}

// --- the clear ---------------------------------------------------------------------------------------

/// Deletes the native state of `group`, in the order its references allow. The only
/// place in the crate that does.
pub(crate) fn clear_native_state(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<(), SyncSqliteError> {
    let g = group.as_str();
    // Evidence is keyed by delta hash and refers to the group's checkpoints.
    conn.execute(
        "DELETE FROM native_delta_authorization WHERE checkpoint_hash IN \
         (SELECT checkpoint_hash FROM native_authorization_checkpoints WHERE group_id = ?1)",
        [g],
    )?;
    conn.execute(
        "DELETE FROM native_delta_pending_evidence WHERE checkpoint_hash IN \
         (SELECT checkpoint_hash FROM native_authorization_checkpoints WHERE group_id = ?1)",
        [g],
    )?;
    conn.execute(
        "DELETE FROM native_delta_pending_evidence WHERE delta_hash IN \
         (SELECT delta_hash FROM native_delta_log WHERE group_id = ?1)",
        [g],
    )?;
    conn.execute(
        "DELETE FROM native_delta_authorization WHERE delta_hash IN \
         (SELECT delta_hash FROM native_delta_log WHERE group_id = ?1)",
        [g],
    )?;
    conn.execute("DELETE FROM native_authorization_checkpoints WHERE group_id = ?1", [g])?;
    for table in CLEARED_BY_INSTALL {
        if *table == "native_authorization_checkpoints" {
            continue;
        }
        conn.execute(&format!("DELETE FROM {table} WHERE group_id = ?1"), [g])?;
    }
    Ok(())
}

// --- the install ---------------------------------------------------------------------------------------

fn corrupt(detail: impl Into<String>) -> SyncSqliteError {
    SyncSqliteError::CorruptState(detail.into())
}

/// Writes the target into the cleared group.
///
/// Rows are not installed: they are this device's own projection. Projection facts
/// (kept copies and stable names) are recorded as carried.
fn write_target(
    tx: &Connection,
    group: &FolderGroupId,
    verified: VerifiedNativeBootstrap,
) -> Result<(), CheckpointError> {
    let (state, frontier, payload, sealer_public_key, seal) = verified.into_parts();
    let states = payload
        .author_states()
        .map_err(|detail| SyncSqliteError::InvalidInput(detail.to_owned()))?;
    state
        .check_invariants()
        .map_err(|error| SyncSqliteError::InvalidInput(format!("install refused: {error}")))?;

    // A target that holds more of this replica's own author than the (now empty) state
    // does means another copy wrote under the same identity: the report makes the next
    // authoring rotate.
    if let Some(own) = crate::author_incarnation::incarnation_record(tx)?.map(|r| r.author) {
        if let Some(entry) = frontier.get(&own) {
            crate::native_admission::note_if_own_author_ahead(
                tx,
                group.as_str(),
                &own,
                None,
                entry.seq,
            )?;
        }
    }

    crate::native_checkpoint_frontier::adopt_verified_checkpoint(
        tx,
        group,
        &payload.checkpoint,
        &seal,
        &sealer_public_key,
        &crate::native_checkpoint_frontier::CheckpointCoverage { states: states.clone() },
    )?;

    // The deltas the sealed heads rest on, with their evidence, so this replica can
    // serve and re-seal what it installed.
    for delta in &payload.deltas {
        let decoded = yadorilink_replica_domain::signed_delta::NativeDelta::from_wire_bytes(
            &delta.delta_wire,
        )
        .map_err(|error| corrupt(format!("{error:?}")))?;
        if crate::native_publication::evidence_for(tx, &decoded.delta_hash())?.is_none() {
            let checkpoint =
                yadorilink_replica_domain::authorization_checkpoint::decode_checkpoint(
                    &delta.checkpoint_encoded,
                )
                .map_err(|error| corrupt(format!("{error:?}")))?;
            crate::native_publication::attach_authorization_evidence_on_conn(
                tx,
                &delta.checkpoint_hash,
                group.as_str(),
                checkpoint.device_id.as_str(),
                checkpoint.checkpoint_seq,
                &delta.checkpoint_encoded,
                delta.checkpoint_signature.as_slice(),
                &delta.author_signing_public_key,
                &[(decoded.delta_hash(), delta.merkle_proof_encoded.clone())],
            )?;
        }
        crate::native_store::record_delta_body_for_witness(
            tx,
            group,
            &decoded.author,
            decoded.seq,
            decoded.delta_hash(),
            &delta.delta_wire,
        )?;
        crate::native_recursive_operation::record_delta(tx, group.as_str(), &decoded)?;
    }
    for encoded in &payload.file_versions {
        let version = FileVersion::from_canonical_encoding(encoded)
            .map_err(|error| corrupt(format!("{error}")))?;
        crate::dag_store::put_file_version(tx, group.as_str(), &version)?;
    }

    crate::native_store::install_state(tx, group, &state)?;
    // A closed author's frontier entry is the one the closure stores, exactly, so that
    // the entry and the stored closure stay equal and a later seal reproduces them.
    let mut installed_frontier = frontier.clone();
    for (author, state) in &states {
        if let AuthorState::Closed { frontier: Some(entry) } = state {
            if let Some(slot) = installed_frontier.get_mut(author) {
                *slot = *entry;
            }
        }
    }
    crate::native_store::install_frontier(tx, group, &installed_frontier)?;

    // The closures that prove the checkpoint's closed states are stored with the
    // target, in this transaction and bound to its checkpoint; only then are the states
    // installed.
    let checkpoint_hash = payload.checkpoint.checkpoint_hash().0;
    for closure in &payload.closures {
        crate::native_closure::store_verified_bundle_closure(tx, closure, checkpoint_hash)?;
        if !crate::native_closure::is_bound_as_replacement(tx, closure)? {
            return Err(CheckpointError::ClosureNotBound {
                author: closure.closure.author.clone(),
            });
        }
    }
    for (author, state) in &states {
        if let AuthorState::Closed { frontier } = state {
            crate::native_closure::install_closed_state(tx, group, author, frontier.as_ref())?;
        }
    }
    crate::native_closure::close_states_where_reached(tx, group)?;
    // This replica holds no bodies below the frontier it installed: the checkpoint is
    // where its history begins.
    crate::native_history_floor::adopt_history_floor(tx, group, &checkpoint_hash)?;
    Ok(())
}

// --- the rotation --------------------------------------------------------------------------------------

/// Rotates this device to a new incarnation, after the target is in, so that the
/// closure of an old incarnation has its position in the target as its cutoff. Every
/// own old incarnation whose changes were set aside is closed: a peer that still
/// relays its deltas would otherwise duplicate what is re-authored. The device signs
/// each closure itself; a replica without the authority to sign closes nothing, and an
/// incarnation of another device is not this device's to close.
fn rotate_and_close(
    tx: &Connection,
    group: &FolderGroupId,
    barrier: &RebootstrapBarrier<'_>,
    own_authorization: Option<Vec<u8>>,
) -> Result<AuthorId, CheckpointError> {
    let old_current = crate::author_incarnation::current_author(tx)?;
    let record =
        crate::author_incarnation::rotate_incarnation(tx, IncarnationMintReason::Rebootstrap)?;
    if let Some(key) = barrier.closure_key {
        let closing = std::iter::once(&old_current)
            .chain(barrier.manifest.old_authors.iter().filter(|old| **old != old_current));
        for old in closing.filter(|old| old.device == old_current.device) {
            let cutoff: Option<NativeAuthorFrontierEntry> =
                crate::native_store::frontier_entry_get(tx, group, old)?;
            let closure = yadorilink_replica_domain::author_closure::AuthorClosure {
                group_id: group.clone(),
                author: old.clone(),
                cutoff,
            }
            .sign(key, own_authorization.clone().unwrap_or_default());
            crate::native_closure::record_rotation_closure(tx, &closure)?;
        }
    }
    Ok(record.author)
}
