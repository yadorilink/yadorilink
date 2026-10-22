//! Closing an author-incarnation: the verified, self-signed closures and what
//! they gate.
//!
//! An incarnation that was rotated away from is closed at a cutoff: deltas of it
//! at or below the cutoff are still admitted (a replica that is behind needs
//! them, and an exact re-delivery is a duplicate), deltas above it never are.
//! `None` closes the incarnation before its first delta.
//!
//! There is one record of a closure, [`native_author_closure`]: the closure the
//! closed device signed, with its signature, key and authorization, so every row
//! is a self-contained proof that verifies again on its own. The row is
//!
//! * the evidence that a closure exists and verified,
//! * the admission cutoff, the moment it is stored, whether or not the replica
//!   can install it as the author's state (see [`effective_closed_cutoff`]),
//! * the material a [`ClosureOutcome::Fork`] is detected from,
//! * the input [`needs_rebootstrap`] derives from, and
//! * the backing of an installed `Closed` author state: an author is `Closed`
//!   only while a verified closure with exactly its cutoff is held.
//!
//! Rows are outside every root, digest and projection, and a rebootstrap install
//! never clears them. A closure leaves the device only inside a bundle whose
//! replacement checkpoint carries the semantics the old incarnation had not yet
//! published: a row holds the hash of that checkpoint in
//! `replacement_checkpoint_hash`, and [`closures_for_export`] reads only rows
//! that have one. A closure received inside a bundle is stored in the
//! transaction that accepts the bundle, never before.
//!
//! The installed state lives in `native_closed_authors`, which a checkpoint
//! commits through the author-state root.

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::author_closure::{join_cutoffs, ClosureJoin, SignedAuthorClosure};
use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId};
use yadorilink_replica_domain::native_checkpoint_seal::{NativeSealPolicy, SealPolicyPoint};
use yadorilink_replica_domain::native_frontier::{beyond_closed_cutoff, NativeAuthorFrontierEntry};
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::signed_delta::NativeDelta;

use crate::error::SyncSqliteError;

/// Creates the tables of this module on `conn`, and those it reads when a
/// closure drops held deltas (the hold queue and its parked evidence).
pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    crate::native_admission::init_admission_tables(conn)?;
    crate::native_publication::init_native_publication_tables(conn)?;
    conn.execute_batch(
        r#"
        -- One row per verified closure. `cutoff_seq` NULL: closed before the
        -- first delta. A device that signed several closures keeps all of them:
        -- the lower sequence dominates, and two rows at one sequence with
        -- different tips are the evidence of a fork. `replacement_checkpoint_hash`
        -- is NULL until the sealed checkpoint that replaces everything the old
        -- incarnation had not published exists; only a device's own rotation
        -- row is ever NULL, and no outward path reads a NULL row.
        CREATE TABLE IF NOT EXISTS native_author_closure (
            group_id             TEXT    NOT NULL,
            author               TEXT    NOT NULL,
            incarnation          BLOB    NOT NULL,
            cutoff_seq           INTEGER CHECK (cutoff_seq IS NULL OR cutoff_seq >= 1),
            cutoff_tip           BLOB,
            closure_hash         BLOB    NOT NULL,
            closure              BLOB    NOT NULL,
            signature            BLOB    NOT NULL,
            author_public_key    BLOB    NOT NULL,
            authorization        BLOB    NOT NULL,
            source               TEXT    NOT NULL CHECK (source IN ('rotation', 'bundle')),
            verified_at_unixtime INTEGER NOT NULL,
            replacement_checkpoint_hash BLOB,
            PRIMARY KEY (group_id, author, incarnation, closure_hash),
            CHECK ((cutoff_seq IS NULL) = (cutoff_tip IS NULL)),
            CHECK (replacement_checkpoint_hash IS NULL OR length(replacement_checkpoint_hash) = 32)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

fn now_unixtime() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn corrupt(detail: impl Into<String>) -> SyncSqliteError {
    SyncSqliteError::CorruptState(detail.into())
}

fn refused(detail: impl Into<String>) -> SyncSqliteError {
    SyncSqliteError::ClosureRefused(detail.into())
}

/// A closure's stored cutoff columns: sequence and tip, both null together.
type RawCutoff = (Option<i64>, Option<Vec<u8>>);

fn cutoff_entry(
    seq: Option<i64>,
    tip: Option<Vec<u8>>,
) -> Result<Option<NativeAuthorFrontierEntry>, SyncSqliteError> {
    match (seq, tip) {
        (Some(seq), Some(tip)) => Ok(Some(NativeAuthorFrontierEntry {
            seq: AuthorSeq(seq as u64),
            tip: DeltaHash(crate::native_store::as_array32(&tip)?),
        })),
        _ => Ok(None),
    }
}

// --- the installed state -----------------------------------------------------------

/// The cutoff entry `author`'s installed `Closed` state stores: `None` when the
/// author is not closed, `Some(None)` when it is closed before its first delta.
pub(crate) fn closed_cutoff_entry(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<Option<Option<NativeAuthorFrontierEntry>>, SyncSqliteError> {
    let row: Option<RawCutoff> = conn
        .prepare_cached(
            "SELECT cutoff_seq, cutoff_tip FROM native_closed_authors \
             WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3",
        )?
        .query_row(
            (group_id.as_str(), author.device.as_str(), author.incarnation.0.as_slice()),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(seq, tip)| cutoff_entry(seq, tip)).transpose()
}

/// Every installed `Closed` state of the group: the author and the cutoff entry
/// it is closed at (`None`: before its first delta), in author order.
pub fn load_closed_authors(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Vec<(AuthorId, Option<NativeAuthorFrontierEntry>)>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT author, incarnation, cutoff_seq, cutoff_tip \
         FROM native_closed_authors WHERE group_id = ?1",
    )?;
    let mut rows = stmt.query([group_id.as_str()])?;
    let mut closed = Vec::new();
    while let Some(row) = rows.next()? {
        let author = crate::native_store::read_author(row.get(0)?, row.get(1)?)?;
        closed.push((author, cutoff_entry(row.get(2)?, row.get(3)?)?));
    }
    // Canonical order, whatever order the rows come back in.
    closed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(closed)
}

/// Records `author` as `Closed` at `cutoff`. Refused unless a verified closure
/// with exactly that cutoff is held and may leave the device: an author appears
/// closed in no state without a closure its own device signed.
pub(crate) fn install_closed_state(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    cutoff: Option<&NativeAuthorFrontierEntry>,
) -> Result<(), SyncSqliteError> {
    let backed: bool = conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM native_author_closure \
             WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 \
               AND cutoff_seq IS ?4 AND cutoff_tip IS ?5 \
               AND replacement_checkpoint_hash IS NOT NULL)",
        )?
        .query_row(
            (
                group_id.as_str(),
                author.device.as_str(),
                author.incarnation.0.as_slice(),
                cutoff.map(|entry| entry.seq.get() as i64),
                cutoff.map(|entry| entry.tip.0.to_vec()),
            ),
            |row| row.get(0),
        )?;
    if !backed {
        return Err(corrupt(format!(
            "{author:?} cannot be closed at {cutoff:?}: no verified closure with that cutoff"
        )));
    }
    conn.execute(
        "INSERT INTO native_closed_authors \
         (group_id, author, incarnation, closed_at_unixtime, cutoff_seq, cutoff_tip) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT (group_id, author, incarnation) DO UPDATE SET \
           cutoff_seq = excluded.cutoff_seq, cutoff_tip = excluded.cutoff_tip",
        (
            group_id.as_str(),
            author.device.as_str(),
            author.incarnation.0.as_slice(),
            now_unixtime(),
            cutoff.map(|entry| entry.seq.get() as i64),
            cutoff.map(|entry| entry.tip.0.to_vec()),
        ),
    )?;
    // A Closed author can never act: its losing heads are now forkable by any
    // writer, which the fork pass has not yet had cause to consider.
    crate::native_contest_candidates::reset_attempts(conn, group_id.as_str())?;
    Ok(())
}

// --- the cutoff -----------------------------------------------------------------------

/// The strictest cutoff an author is closed at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EffectiveCutoff {
    /// The last admissible sequence; `None` closes the author before its first delta.
    pub seq: Option<AuthorSeq>,
    /// The tip the cutoff names; `None` exactly when `seq` is.
    pub tip: Option<DeltaHash>,
    /// Two valid closures cut the chain at `seq` with different tips. Deltas
    /// above `seq` are refused all the same: a cut exists whichever tip is right.
    pub fork: bool,
}

/// What the cutoff says about one delta.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ClosedVerdict {
    Open,
    /// Above the cutoff: never admissible, never held.
    Beyond {
        cutoff: Option<AuthorSeq>,
    },
    /// At the cutoff sequence but not the delta the closure names.
    Fork {
        seq: AuthorSeq,
    },
}

impl EffectiveCutoff {
    pub(crate) fn verdict(&self, seq: AuthorSeq, hash: &DeltaHash) -> ClosedVerdict {
        if beyond_closed_cutoff(self.seq, seq) {
            ClosedVerdict::Beyond { cutoff: self.seq }
        } else if !self.fork && self.seq == Some(seq) && self.tip.is_some_and(|tip| tip != *hash) {
            ClosedVerdict::Fork { seq }
        } else {
            ClosedVerdict::Open
        }
    }
}

/// The strictest of `cutoffs` (lowest sequence, `None` lowest), and whether two
/// of them fork at that sequence. Independent of the order of `cutoffs`.
pub(crate) fn strictest(
    cutoffs: impl IntoIterator<Item = Option<NativeAuthorFrontierEntry>>,
) -> Option<EffectiveCutoff> {
    let mut best: Option<(Option<NativeAuthorFrontierEntry>, bool)> = None;
    for cutoff in cutoffs {
        best = Some(match best {
            None => (cutoff, false),
            Some((held, fork)) => match join_cutoffs(cutoff.as_ref(), held.as_ref()) {
                ClosureJoin::Lower => (cutoff, false),
                ClosureJoin::Higher | ClosureJoin::Identical => (held, fork),
                ClosureJoin::Fork => (held, true),
            },
        });
    }
    best.map(|(cutoff, fork)| EffectiveCutoff {
        seq: cutoff.map(|entry| entry.seq),
        tip: cutoff.map(|entry| entry.tip),
        fork,
    })
}

fn closure_cutoffs(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<Vec<Option<NativeAuthorFrontierEntry>>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT cutoff_seq, cutoff_tip FROM native_author_closure \
         WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3",
    )?;
    let mut rows =
        stmt.query((group_id.as_str(), author.device.as_str(), author.incarnation.0.as_slice()))?;
    let mut cutoffs = Vec::new();
    while let Some(row) = rows.next()? {
        cutoffs.push(cutoff_entry(row.get(0)?, row.get(1)?)?);
    }
    Ok(cutoffs)
}

/// The cutoff `author` is closed at in `group_id`, if it is closed at all: the
/// strictest of the installed `Closed` state and every verified closure. This is
/// the one function admission reads, at exactly two places: the admission gate
/// and the store-level install.
pub fn effective_closed_cutoff(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<Option<EffectiveCutoff>, SyncSqliteError> {
    let mut cutoffs = closure_cutoffs(conn, group_id, author)?;
    cutoffs.extend(closed_cutoff_entry(conn, group_id, author)?);
    Ok(strictest(cutoffs))
}

/// `Some(cutoff)` when sequence `seq` of `author` lies beyond the cutoff the
/// author is closed at, `None` when it may proceed to the ordinary gates.
pub(crate) fn beyond_cutoff(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
) -> Result<Option<Option<AuthorSeq>>, SyncSqliteError> {
    Ok(effective_closed_cutoff(conn, group_id, author)?
        .filter(|cutoff| beyond_closed_cutoff(cutoff.seq, seq))
        .map(|cutoff| cutoff.seq))
}

/// The strictest cutoff of `author` over the verified closure rows this replica holds and
/// `extra` closures it is about to take. The installed `Closed` state is left out: it is
/// backed by a row, and an install that is about to replace it must not be judged by it.
pub(crate) fn effective_from_rows_with(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    extra: impl IntoIterator<Item = Option<NativeAuthorFrontierEntry>>,
) -> Result<Option<EffectiveCutoff>, SyncSqliteError> {
    let mut cutoffs = closure_cutoffs(conn, group_id, author)?;
    cutoffs.extend(extra);
    Ok(strictest(cutoffs))
}

/// Every author of `group_id` that has a closure row.
pub(crate) fn closure_authors(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Vec<AuthorId>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT author, incarnation FROM native_author_closure WHERE group_id = ?1",
    )?;
    let mut rows = stmt.query([group_id.as_str()])?;
    let mut authors = Vec::new();
    while let Some(row) = rows.next()? {
        authors.push(crate::native_store::read_author(row.get(0)?, row.get(1)?)?);
    }
    authors.sort();
    Ok(authors)
}

// --- storing a closure ------------------------------------------------------------------

/// What storing a closure did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClosureOutcome {
    /// A new row. The author is closed on the spot if the replica stands exactly
    /// at the cutoff; if it is below, it stays open and keeps syncing up to it.
    Stored,
    /// This very closure was held already.
    AlreadyHeld,
    /// Another closure of the author cuts the chain at the same sequence with a
    /// different tip. Both rows are kept as the evidence; neither is installed.
    Fork,
}

/// Stores a closure of a bundle that was verified as a whole
/// ([`crate::native_bootstrap::verify_native_bootstrap`]), in the transaction
/// that installs that bundle.
pub(crate) fn store_verified_bundle_closure(
    conn: &Connection,
    closure: &SignedAuthorClosure,
    checkpoint_hash: [u8; 32],
) -> Result<ClosureOutcome, SyncSqliteError> {
    insert_row(conn, closure, "bundle", Some(checkpoint_hash))
}

/// Verifies `closure` for `group_id` under `policy` and stores it as received
/// inside the bundle whose sealed checkpoint has hash `checkpoint_hash`. The one
/// way a closure of another device enters; to be called in the transaction that
/// accepts that bundle. There is no entry for a closure on its own.
pub fn store_bundle_closure(
    conn: &Connection,
    group_id: &FolderGroupId,
    closure: &SignedAuthorClosure,
    checkpoint_hash: [u8; 32],
    policy: &dyn NativeSealPolicy,
) -> Result<ClosureOutcome, SyncSqliteError> {
    verify_closure(group_id, closure, policy)?;
    insert_row(conn, closure, "bundle", Some(checkpoint_hash))
}

/// The checks every closure passes before anything is stored: it is for this
/// group, signed by the closed author's own device under a key the authority vouched
/// for, and that device was a writer at the policy point the vouching names.
pub(crate) fn verify_closure(
    group_id: &FolderGroupId,
    closure: &SignedAuthorClosure,
    policy: &dyn NativeSealPolicy,
) -> Result<(), SyncSqliteError> {
    let checkpoint = closure
        .verify(group_id.as_str(), |key_id, head| policy.resolve_authority_key(key_id, head))
        .map_err(|error| refused(error.to_string()))?;
    let point = SealPolicyPoint {
        epoch: checkpoint.policy_epoch,
        seq: checkpoint.policy_seq,
        head: checkpoint.policy_head,
    };
    if !policy.writer_at_policy_point(
        &checkpoint.device_id,
        &checkpoint.signing_key_fingerprint,
        &point,
    ) {
        return Err(refused(
            "the closing device was not a writer at the policy point its authorization names",
        ));
    }
    Ok(())
}

/// Stores the closure this device signed for an incarnation it rotated away
/// from. It gates admission of the old incarnation at once, and no outward path
/// reads it until [`mark_replacement_checkpoint`].
pub fn record_rotation_closure(
    conn: &Connection,
    closure: &SignedAuthorClosure,
) -> Result<ClosureOutcome, SyncSqliteError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(&closure.author_public_key)
        .map_err(|_| refused("the closure key is malformed"))?;
    ed25519_dalek::Verifier::verify(
        &key,
        &closure.closure.signed_content(),
        &ed25519_dalek::Signature::from_bytes(&closure.signature),
    )
    .map_err(|_| refused("the closure signature does not verify"))?;
    insert_row(conn, closure, "rotation", None)
}

/// The single insert of a verified closure: joins it with what is held (lower
/// sequence wins, an equal sequence with another tip is a fork), drops the
/// deltas it makes unservable and closes the author if the replica stands at the
/// cutoff.
fn insert_row(
    conn: &Connection,
    closure: &SignedAuthorClosure,
    source: &str,
    replacement: Option<[u8; 32]>,
) -> Result<ClosureOutcome, SyncSqliteError> {
    let group_id = &closure.closure.group_id;
    let author = &closure.closure.author;
    let cutoff = closure.closure.cutoff;
    let hash = closure.closure_hash();
    let key = (
        group_id.as_str(),
        author.device.as_str(),
        author.incarnation.0.as_slice(),
        hash.as_slice(),
    );

    let held: Option<Option<Vec<u8>>> = conn
        .prepare_cached(
            "SELECT replacement_checkpoint_hash FROM native_author_closure \
             WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND closure_hash = ?4",
        )?
        .query_row(key, |row| row.get(0))
        .optional()?;
    if let Some(held_replacement) = held {
        if let (None, Some(replacement)) = (held_replacement, replacement) {
            conn.execute(
                "UPDATE native_author_closure SET replacement_checkpoint_hash = ?5 \
                 WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND closure_hash = ?4",
                (key.0, key.1, key.2, key.3, replacement.as_slice()),
            )?;
            close_state_if_reached(conn, group_id, author)?;
        }
        return Ok(ClosureOutcome::AlreadyHeld);
    }

    let forks = match cutoff {
        None => false,
        Some(entry) => conn
            .prepare_cached(
                "SELECT EXISTS (SELECT 1 FROM native_author_closure \
                 WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 \
                   AND cutoff_seq = ?4 AND cutoff_tip != ?5)",
            )?
            .query_row(
                (key.0, key.1, key.2, entry.seq.get() as i64, entry.tip.0.as_slice()),
                |row| row.get(0),
            )?,
    };
    conn.execute(
        "INSERT INTO native_author_closure \
         (group_id, author, incarnation, cutoff_seq, cutoff_tip, closure_hash, closure, \
          signature, author_public_key, authorization, source, verified_at_unixtime, \
          replacement_checkpoint_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        rusqlite::params![
            key.0,
            key.1,
            key.2,
            cutoff.map(|entry| entry.seq.get() as i64),
            cutoff.map(|entry| entry.tip.0.to_vec()),
            hash.as_slice(),
            closure.closure.signed_content(),
            closure.signature.as_slice(),
            closure.author_public_key.as_slice(),
            closure.authorization,
            source,
            now_unixtime(),
            replacement.as_ref().map(|hash| hash.as_slice()),
        ],
    )?;
    if let Some(effective) = effective_closed_cutoff(conn, group_id, author)? {
        sweep_held_beyond(conn, group_id, author, effective.seq)?;
    }
    close_state_if_reached(conn, group_id, author)?;
    Ok(if forks { ClosureOutcome::Fork } else { ClosureOutcome::Stored })
}

/// Closes `author` as an installed state when the replica stands exactly where
/// its strictest verified closure cuts: no frontier entry for a cutoff before
/// the first delta, the cutoff's sequence and tip otherwise. A closure that
/// cannot leave the device yet, a fork, and a replica below or above the cutoff
/// leave the state as it is.
pub(crate) fn close_state_if_reached(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<(), SyncSqliteError> {
    let Some(effective) = effective_closed_cutoff(conn, group_id, author)? else { return Ok(()) };
    if effective.fork {
        return Ok(());
    }
    let cutoff =
        effective.seq.zip(effective.tip).map(|(seq, tip)| NativeAuthorFrontierEntry { seq, tip });
    let local = crate::native_store::frontier_entry_get(conn, group_id, author)?;
    if local != cutoff {
        return Ok(());
    }
    if closed_cutoff_entry(conn, group_id, author)? == Some(cutoff) {
        return Ok(());
    }
    let exportable: bool = conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM native_author_closure \
             WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 \
               AND cutoff_seq IS ?4 AND cutoff_tip IS ?5 \
               AND replacement_checkpoint_hash IS NOT NULL)",
        )?
        .query_row(
            (
                group_id.as_str(),
                author.device.as_str(),
                author.incarnation.0.as_slice(),
                cutoff.map(|entry| entry.seq.get() as i64),
                cutoff.map(|entry| entry.tip.0.to_vec()),
            ),
            |row| row.get(0),
        )?;
    if exportable {
        install_closed_state(conn, group_id, author, cutoff.as_ref())?;
    }
    Ok(())
}

/// Closes, as an installed state, every author whose strictest verified closure cuts exactly
/// where the replica now stands. A closure outlives the clear of a rebootstrap, so after a
/// checkpoint is installed the author it closes may stand at its cutoff without having
/// reached it through a delta or a closure arrival.
pub(crate) fn close_states_where_reached(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<(), SyncSqliteError> {
    for author in closure_authors(conn, group_id)? {
        close_state_if_reached(conn, group_id, &author)?;
    }
    Ok(())
}

/// Whether the stored row of `closure` names the checkpoint that replaces what its
/// incarnation had not published, which is what lets it leave the device inside that
/// checkpoint's bundle.
pub(crate) fn is_bound_as_replacement(
    conn: &Connection,
    closure: &SignedAuthorClosure,
) -> Result<bool, SyncSqliteError> {
    let author = &closure.closure.author;
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM native_author_closure \
             WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND closure_hash = ?4 \
               AND replacement_checkpoint_hash IS NOT NULL)",
        )?
        .query_row(
            (
                closure.closure.group_id.as_str(),
                author.device.as_str(),
                author.incarnation.0.as_slice(),
                closure.closure_hash().as_slice(),
            ),
            |row| row.get(0),
        )?)
}

/// Records that the sealed checkpoint `checkpoint_hash` replaces everything the
/// incarnation `author` had not published, which makes its own closure
/// exportable, with that checkpoint's bundle. A closure that carries no
/// authorization can never be verified by anyone else and stays unexported.
///
/// Refused while a rebootstrap of the group is still running: the replacement checkpoint is the
/// one that holds the replayed own intent, so it cannot exist before the replay is over, and no
/// closure leaves the device before it.
pub fn mark_replacement_checkpoint(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    checkpoint_hash: [u8; 32],
) -> Result<(), SyncSqliteError> {
    if crate::native_rebootstrap::group_frozen(conn, group_id.as_str())? {
        return Err(SyncSqliteError::GroupFrozen { group_id: group_id.as_str().to_owned() });
    }
    conn.execute(
        "UPDATE native_author_closure SET replacement_checkpoint_hash = ?4 \
         WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 \
           AND replacement_checkpoint_hash IS NULL AND length(authorization) > 0",
        (
            group_id.as_str(),
            author.device.as_str(),
            author.incarnation.0.as_slice(),
            checkpoint_hash.as_slice(),
        ),
    )?;
    close_state_if_reached(conn, group_id, author)
}

// --- reading the evidence ----------------------------------------------------------------

fn load_closures(
    conn: &Connection,
    group_id: &FolderGroupId,
    exportable_only: bool,
) -> Result<Vec<SignedAuthorClosure>, SyncSqliteError> {
    let sql = if exportable_only {
        "SELECT closure, author_public_key, signature, authorization FROM native_author_closure \
         WHERE group_id = ?1 AND replacement_checkpoint_hash IS NOT NULL \
           AND length(authorization) > 0 \
         ORDER BY author, incarnation, closure_hash"
    } else {
        "SELECT closure, author_public_key, signature, authorization FROM native_author_closure \
         WHERE group_id = ?1 ORDER BY author, incarnation, closure_hash"
    };
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([group_id.as_str()])?;
    let mut closures = Vec::new();
    while let Some(row) = rows.next()? {
        let content: Vec<u8> = row.get(0)?;
        let key: Vec<u8> = row.get(1)?;
        let signature: Vec<u8> = row.get(2)?;
        let authorization: Vec<u8> = row.get(3)?;
        closures.push(
            SignedAuthorClosure::from_parts(
                &content,
                crate::native_store::as_array32(&key)?,
                signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| corrupt("a stored closure signature is not 64 bytes"))?,
                &authorization,
            )
            .map_err(|error| corrupt(format!("a stored closure does not decode: {error}")))?,
        );
    }
    Ok(closures)
}

/// Every closure row of `group_id`, rotation rows included.
pub fn all_closures(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Vec<SignedAuthorClosure>, SyncSqliteError> {
    load_closures(conn, group_id, false)
}

/// The closures that may leave this device: those whose replacement checkpoint
/// exists and that can be verified by others. The only reader an outward path
/// (a bundle, a checkpoint carrier) may use.
pub fn closures_for_export(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Vec<SignedAuthorClosure>, SyncSqliteError> {
    load_closures(conn, group_id, true)
}

/// The incarnations this device rotated away from whose closure no replacement checkpoint covers
/// yet: the closures that gate admission locally and may not leave the device. Whoever seals a
/// replacement checkpoint with every own unit replayed marks each of them with
/// [`mark_replacement_checkpoint`].
pub fn unexported_rotation_authors(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Vec<AuthorId>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT author, incarnation FROM native_author_closure \
         WHERE group_id = ?1 AND source = 'rotation' \
           AND replacement_checkpoint_hash IS NULL AND length(authorization) > 0 \
         ORDER BY author, incarnation",
    )?;
    let rows = stmt.query_map([group_id.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (device, incarnation) = row?;
        let incarnation = <[u8; 16]>::try_from(incarnation.as_slice())
            .map_err(|_| corrupt("a stored closure incarnation is not 16 bytes"))?;
        out.push(AuthorId {
            device: yadorilink_replica_domain::ids::DeviceId(device),
            incarnation: yadorilink_replica_domain::author::IncarnationId(incarnation),
        });
    }
    Ok(out)
}

/// A group that cannot continue incrementally because of a verified closure.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NeedsRebootstrap {
    pub author: AuthorId,
    /// The strictest cutoff (`None`: before the first delta).
    pub cutoff_seq: Option<AuthorSeq>,
    /// The installed frontier of the author, if it has one.
    pub local_seq: Option<AuthorSeq>,
    /// The cutoff is in doubt: two valid closures (or a closure and the
    /// frontier) disagree about the tip at one sequence.
    pub fork: bool,
}

/// The authors a verified closure puts the group out of step with: the installed
/// frontier is above the cutoff, or a fork stands. Derived from the closure rows
/// and the frontier on every call and never stored, so a restart gives the same
/// answer and nothing but a compatible install ends it.
pub fn needs_rebootstrap(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Vec<NeedsRebootstrap>, SyncSqliteError> {
    let mut needs = Vec::new();
    for author in closure_authors(conn, group_id)? {
        let Some(effective) = effective_closed_cutoff(conn, group_id, &author)? else { continue };
        let local = crate::native_store::frontier_entry_get(conn, group_id, &author)?;
        let above = local.is_some_and(|entry| beyond_closed_cutoff(effective.seq, entry.seq));
        let frontier_forks = local.is_some_and(|entry| {
            effective.seq == Some(entry.seq) && effective.tip.is_some_and(|tip| tip != entry.tip)
        });
        if effective.fork || frontier_forks || above {
            needs.push(NeedsRebootstrap {
                author,
                cutoff_seq: effective.seq,
                local_seq: local.map(|entry| entry.seq),
                fork: effective.fork || frontier_forks,
            });
        }
    }
    Ok(needs)
}

// --- held deltas a closure makes unservable -------------------------------------------------

static UNSERVABLE_HOLDS_DROPPED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// How many held deltas were dropped because nothing could ever release them
/// (they wait on, or follow, a delta of a closed incarnation above its
/// cutoff), since start.
pub fn unservable_holds_dropped() -> u64 {
    UNSERVABLE_HOLDS_DROPPED.load(std::sync::atomic::Ordering::Relaxed)
}

/// The first sequence a closure at `cutoff` refuses.
fn first_closed_seq(cutoff: Option<AuthorSeq>) -> AuthorSeq {
    cutoff.map_or(AuthorSeq::FIRST, |cutoff| AuthorSeq(cutoff.get() + 1))
}

/// Drops the held deltas of `author` beyond `cutoff`: a closed incarnation
/// never admits them, so a hold would wait for nothing. Whatever waited on
/// them goes too (see [`drop_unservable_holds`]).
pub(crate) fn sweep_held_beyond(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    cutoff: Option<AuthorSeq>,
) -> Result<usize, SyncSqliteError> {
    drop_unservable_holds(conn, group_id, author, first_closed_seq(cutoff))
}

/// Drops every held delta that can never be released because `author` will
/// never admit sequence `from` or anything above it: the author's own holds at
/// or above `from`, and the holds of any author that wait on such a dot (a
/// removal or kept head the context gate is holding for). A dropped delta is
/// itself a delta its author will not have admitted, so what waited on it is
/// dropped in turn. Their parked publication evidence goes with them. The
/// result depends only on the closure and the held set, not on the order
/// anything arrived in. Returns how many holds were dropped.
pub(crate) fn drop_unservable_holds(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    from: AuthorSeq,
) -> Result<usize, SyncSqliteError> {
    let mut dead: std::collections::BTreeMap<AuthorId, AuthorSeq> =
        std::collections::BTreeMap::from([(author.clone(), from)]);
    let mut queue = vec![(author.clone(), from)];
    let mut dropped = 0;
    while let Some((who, from)) = queue.pop() {
        let mut stmt = conn.prepare(
            "SELECT author, incarnation, seq, wire_bytes FROM native_delta_holds \
             WHERE group_id = ?1 AND ( \
                 (author = ?2 AND incarnation = ?3 AND seq >= ?4) \
              OR (waiting_on_author = ?2 AND waiting_on_incarnation = ?3 \
                  AND waiting_on_seq >= ?4))",
        )?;
        let mut rows = stmt.query((
            group_id.as_str(),
            who.device.as_str(),
            who.incarnation.0.as_slice(),
            from.get() as i64,
        ))?;
        let mut doomed = Vec::new();
        while let Some(row) = rows.next()? {
            doomed.push((
                crate::native_store::read_author(row.get(0)?, row.get(1)?)?,
                AuthorSeq(row.get::<_, i64>(2)? as u64),
                row.get::<_, Vec<u8>>(3)?,
            ));
        }
        drop(rows);
        drop(stmt);
        for (held_author, seq, wire) in doomed {
            let delta = NativeDelta::from_wire_bytes(&wire)
                .map_err(|error| corrupt(format!("held delta failed to decode: {error}")))?;
            crate::native_publication::take_pending_evidence(conn, &delta.delta_hash())?;
            conn.execute(
                "DELETE FROM native_delta_holds \
                 WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND seq = ?4",
                (
                    group_id.as_str(),
                    held_author.device.as_str(),
                    held_author.incarnation.0.as_slice(),
                    seq.get() as i64,
                ),
            )?;
            dropped += 1;
            if dead.get(&held_author).is_none_or(|first| seq < *first) {
                dead.insert(held_author.clone(), seq);
                queue.push((held_author, seq));
            }
        }
    }
    if dropped > 0 {
        UNSERVABLE_HOLDS_DROPPED.fetch_add(dropped as u64, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(dropped)
}

/// Closes `author` at its current frontier entry (no entry: before its first
/// delta) with a closure whose signature and authorization nobody could verify:
/// for tests of state that only need an author to be closed.
#[cfg(test)]
pub(crate) fn close_author_unverified(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<(), SyncSqliteError> {
    use yadorilink_replica_domain::author_closure::AuthorClosure;
    let cutoff = crate::native_store::frontier_entry_get(conn, group_id, author)?;
    let closure = AuthorClosure { group_id: group_id.clone(), author: author.clone(), cutoff }
        .sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]), vec![0; 64]);
    insert_row(conn, &closure, "bundle", Some([1; 32]))?;
    Ok(())
}
