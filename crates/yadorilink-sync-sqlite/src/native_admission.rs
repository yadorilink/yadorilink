//! Remote admission of one `NativeDelta` -- the context-gated
//! algorithm: [`admit_native_delta`] runs
//! every write its verdict causes in the caller's own transaction (pass
//! `&tx`, exactly as every other function in this crate documents), and a
//! held delta's signed bytes are the only thing persisted for it — nothing
//! reaches `native_author_context`/`native_heads`/`native_author_frontier`
//! until it is actually admitted.
//!
//! Two gates run before a delta's ops ever touch [`NativeState`]:
//!
//! 1. **Chain continuity** ([`native_frontier::classify_chain_advance`]):
//!    is this delta exactly its own author's next seq?
//! 2. **Op-level context gate** (this module): does every dot a removal
//!    names belong to an author this replica has observed at least that
//!    far? A dot it has observed but no longer holds live (superseded by
//!    a different provenance, or already removed) is *not* what this gate
//!    holds on — that is [`NativeState::receive_verified`]'s best-effort
//!    no-op case, applied only once both gates pass.
//!
//! Either gate can hold the delta; holding persists its wire bytes,
//! keyed by the one dot it is missing, and releases (recursively retries)
//! every held delta waiting on a dot the moment that dot is actually
//! admitted. Held deltas are persisted rows (`native_delta_holds`), a
//! hold queue built for native's chain-and-context admission shape.

use ed25519_dalek::VerifyingKey;
use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::authorization_checkpoint::MerkleProof;
use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId};
use yadorilink_replica_domain::native_frontier::{self, ChainGate, UnloggedHistory};
use yadorilink_replica_domain::native_state::{DeltaHash, Dot};
use yadorilink_replica_domain::proof_carrying_delta::{
    verify_proof_carrying_delta, DeltaProofVerificationError, ProofCarryingDelta,
};
use yadorilink_replica_domain::signed_delta::NativeDelta;

use crate::error::SyncSqliteError;
use crate::native_publication;
use crate::native_store;

/// Creates the admission tables on `conn`.
pub fn init_admission_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- native_delta_log itself is created by native_store::init_native_tables
        -- now -- its writer, record_delta_log, lives there too; see that
        -- function's own doc for why.

        -- One row per held delta, keyed by its own dot; `wire_bytes` is
        -- `NativeDelta::to_wire_bytes()`'s encoding, kept only so the hold
        -- can be retried later. Nothing else of a held delta is written
        -- anywhere.
        CREATE TABLE IF NOT EXISTS native_delta_holds (
            group_id                TEXT NOT NULL,
            author                   TEXT NOT NULL,
            incarnation              BLOB NOT NULL,
            seq                      INTEGER NOT NULL,
            wire_bytes               BLOB NOT NULL,
            waiting_on_author        TEXT NOT NULL,
            waiting_on_incarnation   BLOB NOT NULL,
            waiting_on_seq           INTEGER NOT NULL,
            received_at_unixtime     INTEGER NOT NULL,
            PRIMARY KEY (group_id, author, incarnation, seq)
        );
        CREATE INDEX IF NOT EXISTS native_delta_holds_waiting_on
            ON native_delta_holds (group_id, waiting_on_author, waiting_on_incarnation, waiting_on_seq);
        "#,
    )?;
    Ok(())
}

/// Two deltas signed by one author at one seq — the receiver already knew
/// a different one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Equivocation {
    pub author: AuthorId,
    pub seq: AuthorSeq,
    pub known: DeltaHash,
    pub found: DeltaHash,
}

/// What [`admit_native_delta`] did with one remote delta.
#[derive(Debug, PartialEq, Eq)]
pub enum NativeAdmission {
    /// Applied, together with every delta its admission released (in the
    /// order each was admitted; this delta's own dot is not repeated
    /// here).
    Admitted {
        dot: Dot,
        released: Vec<Dot>,
    },
    /// Its exact hash is already this author's recorded history at that
    /// seq: no-op, nothing written.
    Duplicate,
    /// Held; not yet applied anywhere.
    Held {
        waiting_on: Dot,
    },
    Equivocation(Equivocation),
    /// The delta's own signature does not verify.
    BadSignature,
    /// No key is on file for the delta's claimed author.
    UnknownAuthor,
    /// Structurally invalid regardless of sender honesty (see
    /// `NativeState::receive_verified`'s malformed checks).
    Malformed(String),
    /// A redelivered delta at a seq this replica has already moved past,
    /// but which it holds no log entry for because it joined from a
    /// checkpoint whose frontier already covers it.
    /// This replica cannot tell an ordinary duplicate redelivery
    /// apart from a genuine equivocation attempt at this depth -- state is
    /// unaffected either way (this gate never lets the delta advance
    /// anything regardless of which one it was), but the distinction
    /// itself is honestly reported as lost rather than guessed at.
    PriorHistoryTruncated {
        at_seq: AuthorSeq,
    },
    /// [`admit_published_native_delta`] only: the delta's own
    /// proof-carrying bundle (its authorization checkpoint and Merkle
    /// proof) does not verify -- see
    /// `proof_carrying_delta::verify_proof_carrying_delta`'s own error
    /// variants for exactly which check failed. Nothing is written for
    /// this delta anywhere; a receiver never gates admission on FIXING an
    /// unauthorized delta, only on refusing it.
    Unauthorized(DeltaProofVerificationError),
    /// A path this delta names (an op's own path) is one no replica may ever store — the same permanent,
    /// signed-bytes-only predicate
    /// (`yadorilink_fs_platform::reserved_namespace::
    /// wire_path_admission_refusal`). Final, not a hold: re-delivering the
    /// identical delta can never produce another verdict, so there is
    /// nothing to wait for. Checked before any chain/context gate runs.
    InvalidPath(yadorilink_replica_domain::admission::PathRefusal),
    /// This delta individually passes chain continuity and the op-level
    /// context gate, but applying it to this replica's own current
    /// `NativeState` would leave a resulting state that violates its own
    /// invariants (e.g. more than `MAX_SELF_HEADS` live heads of one
    /// author at a path, reachable across several individually-legitimate
    /// deltas that never remove what an earlier one of theirs put).
    /// Refused, nothing written -- see
    /// `native_store::InstallOutcome::WouldViolateInvariant`'s own
    /// doc.
    WouldViolateInvariant(yadorilink_replica_domain::native_state::InvariantViolation),
    /// The delta's author-incarnation is closed -- retired for an incarnation
    /// rotation, or fenced by this replica until that retirement arrives -- and
    /// the delta's sequence is above the cutoff (`None`: the incarnation was
    /// closed before its first delta, so every sequence is). Final, never a
    /// hold: nothing is written, and the delta can never become admissible, so a
    /// delayed delta of a rotated-away incarnation cannot re-enter. Sequences at
    /// or below the cutoff keep their ordinary verdicts.
    AuthorClosed {
        author: AuthorId,
        cutoff: Option<AuthorSeq>,
    },
    /// The delta is at exactly the sequence a verified closure of its author cuts
    /// the chain at, but is not the delta the closure names (or two valid
    /// closures of the author disagree about that sequence): the author signed
    /// two different histories. Final, nothing is written.
    ClosureFork {
        author: AuthorId,
        seq: AuthorSeq,
    },
    /// The delta names a dot (a removal or a kept head) of an author-incarnation
    /// that is closed above that dot's sequence: the dependency can never be
    /// admitted, so the delta can never be. Final, never a hold: nothing is
    /// written, on every replica that holds the closure and whatever the order
    /// of arrival.
    UnservableDependency {
        dependency: Dot,
    },
    /// A rebootstrap has frozen the group: nothing is admitted until it has finished or been
    /// discarded. Not a verdict on the delta and not a fault of the sender (no equivocation,
    /// no penalty): nothing is written, no hold is recorded, and the same delta is admitted by
    /// the delivery that follows the freeze.
    GroupFrozen,
}

/// Admits one remote `NativeDelta`, running every write its verdict
/// causes on `conn` (pass `&tx` for the caller's own transaction; see the
/// module doc). `key_for` resolves an author's current verifying key —
/// called for `delta` itself and again for every held delta this call
/// releases, since a release may retry a delta from a different author
/// entirely.
///
/// This is the entry point for a delta with NO other source of its
/// author's key (the lower plain-admission layer, exercised directly by tests and any
/// future caller that has no proof-carrying bundle to hand) -- a delta
/// admitted via [`admit_published_native_delta`] instead uses that
/// function's already-verified, checkpoint-carried key for itself (never
/// this live lookup), precisely so a legitimately published-then-revoked
/// author's late delta is not refused for a reason publish-time
/// authorization was designed to make irrelevant. See
/// [`admit_native_delta_with_key`].
pub fn admit_native_delta(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
    key_for: &dyn Fn(&AuthorId) -> Option<VerifyingKey>,
) -> Result<NativeAdmission, SyncSqliteError> {
    let Some(key) = key_for(&delta.author) else {
        return Ok(NativeAdmission::UnknownAuthor);
    };
    admit_native_delta_with_key(conn, group_id, delta, &key, key_for)
}

/// [`admit_native_delta`]'s body, taking `delta`'s own verifying key
/// directly rather than resolving it live -- the caller already knows it
/// (either from a live lookup, as [`admit_native_delta`] does, or from a
/// delta's own proof-carrying bundle, as
/// [`admit_published_native_delta`] does). `key_for` is still used, exactly
/// as before, to resolve OTHER authors' keys for whatever this admission's
/// release cascade retries -- see [`release_waiters`] for why that lookup
/// itself first prefers a held delta's own stored evidence over `key_for`.
fn admit_native_delta_with_key(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
    key: &VerifyingKey,
    key_for: &dyn Fn(&AuthorId) -> Option<VerifyingKey>,
) -> Result<NativeAdmission, SyncSqliteError> {
    let local_seq =
        native_store::frontier_entry_get(conn, group_id, &delta.author)?.map(|entry| entry.seq);
    match apply_or_hold(conn, group_id, delta, key)? {
        Step::Admitted(dot) => {
            note_if_own_author_ahead(conn, group_id.as_str(), &delta.author, local_seq, delta.seq)?;
            let released = release_waiters(conn, group_id, &dot, key_for)?;
            Ok(NativeAdmission::Admitted { dot, released })
        }
        Step::Held { waiting_on } => {
            note_if_own_author_ahead(conn, group_id.as_str(), &delta.author, local_seq, delta.seq)?;
            Ok(NativeAdmission::Held { waiting_on })
        }
        Step::Duplicate => Ok(NativeAdmission::Duplicate),
        Step::Equivocation(e) => {
            // Someone else signed this replica's own author at a sequence it
            // already used: report it as ahead by at least one.
            let reported = AuthorSeq(delta.seq.0.max(local_seq.map_or(0, |seq| seq.0) + 1));
            note_if_own_author_ahead(conn, group_id.as_str(), &delta.author, local_seq, reported)?;
            Ok(NativeAdmission::Equivocation(e))
        }
        Step::BadSignature => Ok(NativeAdmission::BadSignature),
        Step::Malformed(m) => Ok(NativeAdmission::Malformed(m)),
        Step::PriorHistoryTruncated { at_seq } => {
            Ok(NativeAdmission::PriorHistoryTruncated { at_seq })
        }
        Step::InvalidPath(refusal) => Ok(NativeAdmission::InvalidPath(refusal)),
        Step::WouldViolateInvariant(violation) => {
            Ok(NativeAdmission::WouldViolateInvariant(violation))
        }
        Step::AuthorClosed { cutoff } => {
            Ok(NativeAdmission::AuthorClosed { author: delta.author.clone(), cutoff })
        }
        Step::ClosureFork { seq } => {
            Ok(NativeAdmission::ClosureFork { author: delta.author.clone(), seq })
        }
        Step::GroupFrozen => Ok(NativeAdmission::GroupFrozen),
        Step::UnservableDependency { dependency } => {
            Ok(NativeAdmission::UnservableDependency { dependency })
        }
    }
}

/// Records that a peer presented `author` at `reported`, above this replica's
/// own position `local`, when `author` is this replica's current author: another
/// copy wrote under the same identity (a restored backup), so authoring in the
/// group must rotate the incarnation before it signs another delta. Anything
/// about another author, or before an incarnation exists, is not this replica's
/// concern.
pub(crate) fn note_if_own_author_ahead(
    conn: &Connection,
    group_id: &str,
    author: &AuthorId,
    local: Option<AuthorSeq>,
    reported: AuthorSeq,
) -> Result<bool, SyncSqliteError> {
    let Some(record) = crate::author_incarnation::incarnation_record(conn)? else {
        return Ok(false);
    };
    if record.author != *author {
        return Ok(false);
    }
    crate::author_incarnation::note_own_author_ahead(
        conn,
        group_id,
        &crate::author_incarnation::OwnAuthorAhead {
            author: author.clone(),
            local: local.unwrap_or(AuthorSeq(0)),
            reported,
        },
    )
}

/// Admits one REMOTELY received `NativeDelta`, requiring it to carry
/// its own publish-time authorization evidence (an `AuthorizationCheckpoint`
/// covering it plus its [`MerkleProof`]), verified through
/// `proof_carrying_delta::verify_proof_carrying_delta`.
///
/// Verification runs FIRST, unconditionally, before [`admit_native_delta`]'s
/// chain/context gates ever see the delta. A delta that fails verification is refused
/// outright ([`NativeAdmission::Unauthorized`]): nothing is written for it
/// anywhere, and no signature/chain/context gate below ever runs on it.
///
/// A delta that verifies but cannot be installed YET (its chain/context
/// gates hold it, exactly as [`admit_native_delta`] already does for the
/// unauthenticated case) still has its now-verified evidence persisted
/// (`native_publication::record_pending_evidence`) so that WHENEVER this
/// replica eventually installs it -- on this call directly, or via a later
/// call's release cascade -- the evidence is attached in the SAME
/// transaction as the install, never left to be reconstructed from
/// scratch.
///
/// `key_for` is exactly [`admit_native_delta`]'s own parameter (resolves an
/// author's current verifying key, for `delta` itself and for every held
/// delta a release retries); `resolve_authority_key` is
/// `verify_change_admission`'s own parameter (resolves the checkpoint's
/// signer key against the caller's verified policy chain -- see that
/// function's doc for why a bare caller-supplied key is never accepted).
///
/// Owns its own atomicity: opens a transaction on `conn`, runs
/// [`admit_published_native_delta_on_conn`], and commits -- so a caller
/// with no transaction of its own (e.g. `yadorilink-daemon`'s
/// native connection handler, receiving bytes straight off a real
/// peer connection) gets full all-or-nothing atomicity across checkpoint
/// storage, pending evidence, the delta's own install (state, frontier,
/// log, body), and its evidence promotion, with no partial-write window if
/// the process crashes or an error occurs partway through. A caller that
/// is already inside its own transaction should call
/// [`admit_published_native_delta_on_conn`] directly instead (SQLite
/// rejects a nested `BEGIN`) -- exactly the `_on_conn` convention this
/// crate already uses for `native_publication::attach_authorization_evidence`.
#[allow(clippy::too_many_arguments)]
pub fn admit_published_native_delta(
    conn: &Connection,
    group_id: &FolderGroupId,
    encoded_delta: &[u8],
    checkpoint_hash: &[u8; 32],
    checkpoint_encoded: &[u8],
    checkpoint_signature: &[u8; 64],
    author_signing_public_key: &[u8; 32],
    proof: &MerkleProof,
    key_for: &dyn Fn(&AuthorId) -> Option<VerifyingKey>,
    resolve_authority_key: impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey>,
) -> Result<NativeAdmission, SyncSqliteError> {
    let tx = conn.unchecked_transaction()?;
    let outcome = admit_published_native_delta_on_conn(
        &tx,
        group_id,
        encoded_delta,
        checkpoint_hash,
        checkpoint_encoded,
        checkpoint_signature,
        author_signing_public_key,
        proof,
        key_for,
        resolve_authority_key,
    )?;
    tx.commit()?;
    Ok(outcome)
}

/// [`admit_published_native_delta`]'s body without its own transaction, for
/// a caller already inside one.
#[allow(clippy::too_many_arguments)]
pub fn admit_published_native_delta_on_conn(
    conn: &Connection,
    group_id: &FolderGroupId,
    encoded_delta: &[u8],
    checkpoint_hash: &[u8; 32],
    checkpoint_encoded: &[u8],
    checkpoint_signature: &[u8; 64],
    author_signing_public_key: &[u8; 32],
    proof: &MerkleProof,
    key_for: &dyn Fn(&AuthorId) -> Option<VerifyingKey>,
    resolve_authority_key: impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey>,
) -> Result<NativeAdmission, SyncSqliteError> {
    let input = ProofCarryingDelta {
        encoded_delta,
        checkpoint_hash,
        checkpoint_encoded,
        checkpoint_signature,
        author_signing_public_key,
        proof,
    };
    let verified =
        match verify_proof_carrying_delta(&input, group_id.as_str(), resolve_authority_key) {
            Ok(verified) => verified,
            Err(error) => return Ok(NativeAdmission::Unauthorized(error)),
        };

    native_publication::store_checkpoint(
        conn,
        checkpoint_hash,
        group_id.as_str(),
        &verified.checkpoint.device_id,
        verified.checkpoint.checkpoint_seq,
        checkpoint_encoded,
        checkpoint_signature,
        author_signing_public_key,
    )?;
    let proof_encoded =
        yadorilink_replica_domain::authorization_checkpoint::encode_merkle_proof(proof);
    native_publication::record_pending_evidence(
        conn,
        &verified.delta_hash,
        checkpoint_hash,
        &proof_encoded,
    )?;

    // Use the key `verify_proof_carrying_delta` already proved this delta's
    // signature verifies under -- never a live `key_for` lookup for this
    // delta itself. `key_for` is passed through only for whatever this
    // admission's release cascade retries; each of those held deltas
    // resolves its OWN key the same way (see `release_waiters`).
    let carried_key = VerifyingKey::from_bytes(author_signing_public_key).map_err(|_| {
        SyncSqliteError::InvalidInput(
            "carried author signing key is not a valid Ed25519 key".into(),
        )
    })?;
    let outcome =
        admit_native_delta_with_key(conn, group_id, &verified.delta, &carried_key, key_for)?;
    let newly_installed: Vec<Dot> = match &outcome {
        NativeAdmission::Admitted { dot, released } => {
            std::iter::once(dot.clone()).chain(released.iter().cloned()).collect()
        }
        _ => Vec::new(),
    };
    attach_pending_evidence(conn, group_id, &newly_installed)?;
    // A delta already installed earlier (e.g. via the plain admission path with
    // no proof at hand yet, or an earlier admit_published_native_delta call
    // whose evidence didn't attach) can have its own proof arrive LATER --
    // that must still attach evidence for it, not leave it permanently
    // unpublished. `Step::Duplicate` is only ever returned when the logged
    // hash already equals this delta's own hash (see NeedsHistoryLookup's
    // handling in apply_or_hold: a mismatch there is Equivocation, not
    // Duplicate) -- re-confirmed here defensively rather than assumed, so a
    // future regression that broke that invariant would fail closed
    // (refusing to attach) instead of silently misattributing evidence to
    // the wrong delta.
    if matches!(outcome, NativeAdmission::Duplicate) {
        let dot = Dot { author: verified.delta.author.clone(), seq: verified.delta.seq };
        if let Some(hash) = native_store::delta_log_hash(conn, group_id, &dot.author, dot.seq)? {
            if hash != verified.delta_hash {
                return Err(SyncSqliteError::CorruptState(format!(
                    "logged hash for {:?} at {:?} does not match the delta this proof verified -- \
                     Step::Duplicate should be unreachable for a mismatched hash",
                    dot.author, dot.seq
                )));
            }
            if let Some((evidence_checkpoint_hash, evidence_proof)) =
                native_publication::take_pending_evidence(conn, &hash)?
            {
                native_publication::attach_delta_evidence(
                    conn,
                    &hash,
                    &evidence_checkpoint_hash,
                    &evidence_proof,
                )?;
            }
        }
    }
    Ok(outcome)
}

/// Attaches the publication evidence a verified delta carried while it waited
/// to every one of `dots` that is installed now.
fn attach_pending_evidence(
    conn: &Connection,
    group_id: &FolderGroupId,
    dots: &[Dot],
) -> Result<(), SyncSqliteError> {
    for dot in dots {
        let Some(hash) = native_store::delta_log_hash(conn, group_id, &dot.author, dot.seq)? else {
            continue;
        };
        if let Some((evidence_checkpoint_hash, evidence_proof)) =
            native_publication::take_pending_evidence(conn, &hash)?
        {
            native_publication::attach_delta_evidence(
                conn,
                &hash,
                &evidence_checkpoint_hash,
                &evidence_proof,
            )?;
        }
    }
    Ok(())
}

/// One admission attempt's outcome, before the release cascade runs.
enum Step {
    Admitted(Dot),
    Held { waiting_on: Dot },
    Duplicate,
    Equivocation(Equivocation),
    BadSignature,
    Malformed(String),
    PriorHistoryTruncated { at_seq: AuthorSeq },
    InvalidPath(yadorilink_replica_domain::admission::PathRefusal),
    WouldViolateInvariant(yadorilink_replica_domain::native_state::InvariantViolation),
    AuthorClosed { cutoff: Option<AuthorSeq> },
    ClosureFork { seq: AuthorSeq },
    UnservableDependency { dependency: Dot },
    GroupFrozen,
}

/// The first path `delta` names that no replica may store, by the same
/// signed-bytes-only predicate -- every op's own path.
fn path_refusal(delta: &NativeDelta) -> Option<yadorilink_replica_domain::admission::PathRefusal> {
    use yadorilink_fs_platform::reserved_namespace::{
        wire_path_admission_refusal, WirePathRefusal,
    };
    use yadorilink_replica_domain::admission::PathRefusal;
    delta.ops.iter().find_map(|op| match wire_path_admission_refusal(op.path.as_str())? {
        WirePathRefusal::ReservedNamespace => {
            Some(PathRefusal::ReservedNamespaceCollision { path: op.path.as_str().to_owned() })
        }
        WirePathRefusal::NonPortable => {
            Some(PathRefusal::NonPortablePath { path: op.path.as_str().to_owned() })
        }
    })
}

fn apply_or_hold(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
    key: &VerifyingKey,
) -> Result<Step, SyncSqliteError> {
    if delta.verify_signature(key).is_err() {
        return Ok(Step::BadSignature);
    }
    // A path no replica may ever store is refused before any chain/context
    // gate does other work: no basis, chain state or dependency could ever
    // make it admissible.
    // Final, never a hold -- see `NativeAdmission::InvalidPath`'s own doc.
    if let Some(refusal) = path_refusal(delta) {
        return Ok(Step::InvalidPath(refusal));
    }

    // A closed incarnation takes nothing above its cutoff: refused before the
    // chain gate can classify the delta as continuing the chain or hold it for
    // a predecessor. At the cutoff sequence only the delta the closure names
    // passes.
    if let Some(cutoff) =
        crate::native_closure::effective_closed_cutoff(conn, group_id, &delta.author)?
    {
        match cutoff.verdict(delta.seq, &delta.delta_hash()) {
            crate::native_closure::ClosedVerdict::Open => {}
            crate::native_closure::ClosedVerdict::Beyond { cutoff } => {
                return Ok(Step::AuthorClosed { cutoff });
            }
            crate::native_closure::ClosedVerdict::Fork { seq } => {
                return Ok(Step::ClosureFork { seq });
            }
        }
    }

    let current = native_store::frontier_entry_get(conn, group_id, &delta.author)?;
    match native_frontier::classify_chain_advance(current.as_ref(), delta.prev, delta.seq) {
        ChainGate::Continues => {}
        ChainGate::Equivocation { at_seq, expected_prev, found_prev } => {
            return Ok(Step::Equivocation(Equivocation {
                author: delta.author.clone(),
                seq: at_seq,
                known: expected_prev.unwrap_or_default(),
                found: found_prev.unwrap_or_default(),
            }));
        }
        ChainGate::NeedsPredecessor { missing_through } => {
            // `classify_chain_advance` only reaches this case with
            // `missing_through` at least one past the author's legitimate
            // next seq (>= FIRST + 1), so subtracting one should never
            // underflow -- but that lower bound is enforced far from here,
            // in `signed_delta.rs`'s wire decode, not by anything in this
            // function's own control flow. Checked rather than trusted, so
            // a future decode-time regression fails closed here too instead
            // of panicking on an unsigned underflow.
            let Some(predecessor_seq) = missing_through.get().checked_sub(1) else {
                return Ok(Step::Malformed(format!(
                    "{:?} claims a first-delta seq of zero, which is not a legitimate sequence",
                    delta.author
                )));
            };
            let waiting_on = Dot { author: delta.author.clone(), seq: AuthorSeq(predecessor_seq) };
            return match hold(conn, group_id, delta, &waiting_on)? {
                HoldOutcome::Held => Ok(Step::Held { waiting_on }),
                HoldOutcome::Equivocation(e) => Ok(Step::Equivocation(e)),
            };
        }
        ChainGate::NeedsHistoryLookup { at_seq } => {
            return match logged_hash(conn, group_id, &delta.author, at_seq)? {
                Some(known) if known == delta.delta_hash() => Ok(Step::Duplicate),
                Some(known) => Ok(Step::Equivocation(Equivocation {
                    author: delta.author.clone(),
                    seq: at_seq,
                    known,
                    found: delta.delta_hash(),
                })),
                // Absent legitimately means one of two things: the log and
                // the frontier have drifted apart (a bug elsewhere), or the
                // entry is at or below this replica's history floor, which a
                // join sets at the checkpoint it joined from. The author's
                // floor entry tells them apart exactly.
                None => {
                    let floor =
                        crate::native_history_floor::floor_entry(conn, group_id, &delta.author)?;
                    Ok(
                        match native_frontier::classify_unlogged_history(
                            floor.as_ref(),
                            at_seq,
                            delta.delta_hash(),
                        ) {
                            UnloggedHistory::Duplicate => Step::Duplicate,
                            UnloggedHistory::Equivocation { known } => {
                                Step::Equivocation(Equivocation {
                                    author: delta.author.clone(),
                                    seq: at_seq,
                                    known,
                                    found: delta.delta_hash(),
                                })
                            }
                            UnloggedHistory::PriorHistoryTruncated => {
                                Step::PriorHistoryTruncated { at_seq }
                            }
                            UnloggedHistory::Drift => Step::Malformed(format!(
                                "no logged delta for {:?} at seq {at_seq:?}, but the frontier is past it",
                                delta.author
                            )),
                        },
                    )
                }
            };
        }
        ChainGate::SeqExhausted => {
            return Ok(Step::Malformed(format!(
                "{:?} has exhausted its sequence space",
                delta.author
            )));
        }
    }

    // Op-level context gate: every named removal and every named kept head
    // must belong to an author this replica has observed at least that far. A
    // dot it has observed but that is no longer live is not this gate's
    // concern: for a removal that is `receive_verified`'s best-effort no-op
    // case below.
    for op in &delta.ops {
        for dot in op.removes.iter().map(|removal| &removal.dot) {
            let observed = native_store::author_context_seq(conn, group_id, &dot.author)?;
            if observed.is_none_or(|seq| seq < dot.seq) {
                // A dot above the cutoff of a closed incarnation is never
                // admitted, so nothing could ever release this delta.
                if crate::native_closure::beyond_cutoff(conn, group_id, &dot.author, dot.seq)?
                    .is_some()
                {
                    return Ok(Step::UnservableDependency { dependency: dot.clone() });
                }
                return match hold(conn, group_id, delta, dot)? {
                    HoldOutcome::Held => Ok(Step::Held { waiting_on: dot.clone() }),
                    HoldOutcome::Equivocation(e) => Ok(Step::Equivocation(e)),
                };
            }
        }
    }

    // The parts of one recursive operation must agree on how many there are.
    if let Some(recorded) =
        crate::native_recursive_operation::conflicting_part_count(conn, group_id.as_str(), delta)?
    {
        return Ok(Step::Malformed(format!(
            "{:?} claims a recursive operation of {} parts, but an earlier part of it says \
             {recorded}",
            delta.author,
            delta.recursive_part.map_or(0, |part| part.part_count)
        )));
    }

    // `install_verified_delta_inner` (native_store.rs) is the one choke
    // point that records this into `native_delta_log` now -- see that
    // function's own doc, and `native_publication`'s module doc for why
    // this single choke point matters for local-authoring's publication
    // tracking too. Called directly (not through the `install_verified_
    // delta` wrapper) so a `WouldViolateInvariant` verdict becomes a
    // proper `Step`, not a hard error.
    match native_store::install_verified_delta_inner(conn, group_id, delta, key)? {
        native_store::InstallOutcome::Installed(dot) => {
            clear_hold(conn, group_id, &delta.author, delta.seq)?;
            crate::native_desired_state::arm_projection_for_delta(
                conn,
                group_id.as_str(),
                delta,
                false,
            )?;
            Ok(Step::Admitted(dot))
        }
        native_store::InstallOutcome::AuthorClosed { cutoff } => Ok(Step::AuthorClosed { cutoff }),
        native_store::InstallOutcome::ClosureFork { seq } => Ok(Step::ClosureFork { seq }),
        native_store::InstallOutcome::GroupFrozen => Ok(Step::GroupFrozen),
        native_store::InstallOutcome::WouldViolateInvariant(violation) => {
            Ok(Step::WouldViolateInvariant(violation))
        }
    }
}

/// Retries every held delta waiting on `dot`, now admitted, and whatever
/// they release in turn.
fn release_waiters(
    conn: &Connection,
    group_id: &FolderGroupId,
    dot: &Dot,
    key_for: &dyn Fn(&AuthorId) -> Option<VerifyingKey>,
) -> Result<Vec<Dot>, SyncSqliteError> {
    let mut released = Vec::new();
    let mut queue = waiters_of(conn, group_id, dot)?;
    while let Some(held) = queue.pop() {
        // A cascade below may have dropped this hold since it was queued.
        if !hold_exists(conn, group_id, &held)? {
            continue;
        }
        let Some(key) = held_delta_key(conn, &held, key_for)? else { continue };
        match apply_or_hold(conn, group_id, &held, &key)? {
            Step::Admitted(new_dot) => {
                released.push(new_dot.clone());
                queue.extend(waiters_of(conn, group_id, &new_dot)?);
            }
            // Still blocked (possibly on something else now); `apply_or_hold`
            // has already re-pointed its hold row at the new blocker.
            Step::Held { .. } => {}
            // Its incarnation was closed while it waited, or it names a dot of
            // one: it can never be admitted, so the hold goes, and with it
            // whatever waited on it.
            Step::AuthorClosed { .. }
            | Step::ClosureFork { .. }
            | Step::UnservableDependency { .. } => {
                crate::native_closure::drop_unservable_holds(
                    conn,
                    group_id,
                    &held.author,
                    held.seq,
                )?;
            }
            // No longer admissible at all: its hold row is left in place
            // rather than silently discarded, so a later manual audit of
            // `native_delta_holds` can see it never resolved. Retrying it
            // again on a future release is safe (idempotent: `apply_or_hold`
            // re-derives the same verdict from scratch).
            Step::Duplicate
            | Step::Equivocation(_)
            | Step::BadSignature
            | Step::Malformed(_)
            | Step::PriorHistoryTruncated { .. }
            | Step::InvalidPath(_)
            | Step::WouldViolateInvariant(_)
            // Frozen while it waited: its hold stays and it is retried when the freeze ends.
            | Step::GroupFrozen => {}
        }
    }
    Ok(released)
}

/// A held delta's own verifying key: its publish-time evidence's carried key if it
/// arrived via `admit_published_native_delta` and has one still pending
/// (never a live lookup for a delta this replica already independently
/// verified — the same reason `admit_published_native_delta` itself never
/// uses `key_for` for the delta it just verified), else `key_for`'s live
/// lookup for a delta that came in through the plain admission layer with no
/// evidence of its own. A malformed stored key is treated as "no historical
/// key" (falls through to `key_for`) rather than failing the whole release
/// cascade over one held delta's corrupted row.
fn held_delta_key(
    conn: &Connection,
    held: &NativeDelta,
    key_for: &dyn Fn(&AuthorId) -> Option<VerifyingKey>,
) -> Result<Option<VerifyingKey>, SyncSqliteError> {
    if let Some((checkpoint_hash, _proof)) =
        native_publication::peek_pending_evidence(conn, &held.delta_hash())?
    {
        if let Some((_encoded, _signature, author_key)) =
            native_publication::checkpoint_envelope(conn, &checkpoint_hash)?
        {
            if let Ok(key) = VerifyingKey::from_bytes(&author_key) {
                return Ok(Some(key));
            }
        }
    }
    Ok(key_for(&held.author))
}

fn hold_exists(
    conn: &Connection,
    group_id: &FolderGroupId,
    held: &NativeDelta,
) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .prepare_cached(
            "SELECT 1 FROM native_delta_holds \
             WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND seq = ?4",
        )?
        .exists((
            group_id.as_str(),
            held.author.device.as_str(),
            held.author.incarnation.0.as_slice(),
            held.seq.get() as i64,
        ))?)
}

fn waiters_of(
    conn: &Connection,
    group_id: &FolderGroupId,
    dot: &Dot,
) -> Result<Vec<NativeDelta>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT wire_bytes FROM native_delta_holds \
         WHERE group_id = ?1 AND waiting_on_author = ?2 AND waiting_on_incarnation = ?3 AND waiting_on_seq = ?4",
    )?;
    let mut rows = stmt.query((
        group_id.as_str(),
        dot.author.device.as_str(),
        dot.author.incarnation.0.as_slice(),
        dot.seq.get() as i64,
    ))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let wire_bytes: Vec<u8> = row.get(0)?;
        let delta = NativeDelta::from_wire_bytes(&wire_bytes).map_err(|err| {
            SyncSqliteError::CorruptState(format!("held delta failed to decode: {err}"))
        })?;
        out.push(delta);
    }
    Ok(out)
}

/// What attempting to hold a delta found: a fresh hold row was written (or
/// an identical redelivery of an already-held delta had its row re-pointed
/// at the current blocker — both are "proceed as held"), or a DIFFERENT delta already
/// held at this exact `(author, incarnation, seq)` proves the author
/// equivocated. On [`HoldOutcome::Equivocation`] the existing row is left
/// completely alone: the first delta's own wire bytes are the
/// equivocation's evidence and must never be overwritten by whichever one
/// arrived second.
/// Most held deltas one author may have in a group, and most a group may
/// have in all. A held delta waits for a predecessor that may never arrive,
/// and an authorized writer can sign any number of far-future deltas, so the
/// table is bounded: past a cap the oldest hold is dropped (the peer sends it
/// again if it is still needed, and a delta that was already admitted never
/// depended on it).
const MAX_HELD_PER_AUTHOR: i64 = 1024;
const MAX_HELD_PER_GROUP: i64 = 8192;

static HELD_DELTAS_EVICTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many held deltas were dropped to stay within the caps, since start.
pub fn held_deltas_evicted() -> u64 {
    HELD_DELTAS_EVICTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Drops the oldest holds of `group_id` (restricted to `author`'s when given)
/// until fewer than `cap` remain, making room for one more.
fn evict_oldest_holds(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: Option<&AuthorId>,
    cap: i64,
) -> Result<(), SyncSqliteError> {
    let (author_device, author_incarnation) = match author {
        Some(author) => (Some(author.device.as_str()), Some(author.incarnation.0.as_slice())),
        None => (None, None),
    };
    let held: i64 = conn.query_row(
        "SELECT COUNT(*) FROM native_delta_holds WHERE group_id = ?1 \
         AND (?2 IS NULL OR (author = ?2 AND incarnation = ?3))",
        rusqlite::params![group_id.as_str(), author_device, author_incarnation],
        |row| row.get(0),
    )?;
    let excess = held - (cap - 1);
    if excess <= 0 {
        return Ok(());
    }
    let dropped = conn.execute(
        "DELETE FROM native_delta_holds WHERE rowid IN ( \
             SELECT rowid FROM native_delta_holds WHERE group_id = ?1 \
             AND (?2 IS NULL OR (author = ?2 AND incarnation = ?3)) \
             ORDER BY received_at_unixtime, rowid LIMIT ?4)",
        rusqlite::params![group_id.as_str(), author_device, author_incarnation, excess],
    )?;
    HELD_DELTAS_EVICTED.fetch_add(dropped as u64, std::sync::atomic::Ordering::Relaxed);
    tracing::warn!(group = %group_id.as_str(), dropped, "held native deltas over the cap were dropped");
    Ok(())
}

enum HoldOutcome {
    Held,
    Equivocation(Equivocation),
}

fn hold(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
    waiting_on: &Dot,
) -> Result<HoldOutcome, SyncSqliteError> {
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT wire_bytes FROM native_delta_holds WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND seq = ?4",
            (group_id.as_str(), delta.author.device.as_str(), delta.author.incarnation.0.as_slice(), delta.seq.get() as i64),
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing_bytes) = existing {
        let existing_delta = NativeDelta::from_wire_bytes(&existing_bytes).map_err(|error| {
            SyncSqliteError::CorruptState(format!("held delta does not decode: {error}"))
        })?;
        let existing_hash = existing_delta.delta_hash();
        let new_hash = delta.delta_hash();
        if existing_hash == new_hash {
            // Identical delta, so the same row -- but what it waits on can
            // differ between attempts: a retry after its first blocker
            // landed may find a different dependency still missing, and
            // `waiters_of` only finds a hold by its stored blocker. Re-point
            // the row so the new blocker's arrival releases it.
            conn.execute(
                "UPDATE native_delta_holds \
                 SET waiting_on_author = ?5, waiting_on_incarnation = ?6, waiting_on_seq = ?7 \
                 WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND seq = ?4",
                (
                    group_id.as_str(),
                    delta.author.device.as_str(),
                    delta.author.incarnation.0.as_slice(),
                    delta.seq.get() as i64,
                    waiting_on.author.device.as_str(),
                    waiting_on.author.incarnation.0.as_slice(),
                    waiting_on.seq.get() as i64,
                ),
            )?;
            return Ok(HoldOutcome::Held);
        }
        // A DIFFERENT signed delta at the exact same (author, seq) this
        // replica has already seen held -- the author equivocated. The
        // existing row is the first delta's own evidence; it must survive
        // this call untouched, not be overwritten by the second one.
        return Ok(HoldOutcome::Equivocation(Equivocation {
            author: delta.author.clone(),
            seq: delta.seq,
            known: existing_hash,
            found: new_hash,
        }));
    }

    evict_oldest_holds(conn, group_id, Some(&delta.author), MAX_HELD_PER_AUTHOR)?;
    evict_oldest_holds(conn, group_id, None, MAX_HELD_PER_GROUP)?;
    conn.execute(
        "INSERT INTO native_delta_holds \
         (group_id, author, incarnation, seq, wire_bytes, waiting_on_author, waiting_on_incarnation, waiting_on_seq, received_at_unixtime) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, unixepoch())",
        (
            group_id.as_str(),
            delta.author.device.as_str(),
            delta.author.incarnation.0.as_slice(),
            delta.seq.get() as i64,
            delta.to_wire_bytes(),
            waiting_on.author.device.as_str(),
            waiting_on.author.incarnation.0.as_slice(),
            waiting_on.seq.get() as i64,
        ),
    )?;
    Ok(HoldOutcome::Held)
}

fn clear_hold(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "DELETE FROM native_delta_holds WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND seq = ?4",
        (group_id.as_str(), author.device.as_str(), author.incarnation.0.as_slice(), seq.get() as i64),
    )?;
    Ok(())
}

fn logged_hash(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
) -> Result<Option<DeltaHash>, SyncSqliteError> {
    native_store::delta_log_hash(conn, group_id, author, seq)
}

#[cfg(test)]
mod tests {
    mod floor;

    use ed25519_dalek::SigningKey;
    use rusqlite::Connection;
    use yadorilink_replica_domain::author::IncarnationId;
    use yadorilink_replica_domain::ids::{DeviceId, SyncPath, VersionHash};
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, HeadRef};

    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&c).unwrap();
        native_store::init_native_tables(&c).unwrap();
        init_admission_tables(&c).unwrap();
        native_publication::init_native_publication_tables(&c).unwrap();
        c
    }

    fn group() -> FolderGroupId {
        FolderGroupId("g1".into())
    }

    fn author(name: &str) -> AuthorId {
        AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([1u8; 16]) }
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn keys(pairs: Vec<(AuthorId, SigningKey)>) -> impl Fn(&AuthorId) -> Option<VerifyingKey> {
        move |a: &AuthorId| {
            pairs.iter().find(|(author, _)| author == a).map(|(_, k)| k.verifying_key())
        }
    }

    fn delta(
        author: &AuthorId,
        seq: u64,
        prev: Option<DeltaHash>,
        path: &str,
        version: u8,
        removes: Vec<HeadRef>,
        key: &SigningKey,
    ) -> NativeDelta {
        let mut d = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: author.clone(),
            seq: AuthorSeq(seq),
            prev,
            ops: vec![DeltaOp {
                path: SyncPath(path.into()),
                removes,
                put: Some(DeltaPut { version: VersionHash([version; 32]) }),
            }],
            signature: [0u8; 64],
        };
        d.sign(key);
        d
    }

    fn held_count(c: &Connection, who: Option<&AuthorId>) -> i64 {
        match who {
            Some(who) => c.query_row(
                "SELECT COUNT(*) FROM native_delta_holds WHERE author = ?1",
                [who.device.as_str()],
                |r| r.get(0),
            ),
            None => c.query_row("SELECT COUNT(*) FROM native_delta_holds", [], |r| r.get(0)),
        }
        .unwrap()
    }

    /// An authorized writer can sign any number of deltas ahead of its chain;
    /// each is held waiting for a predecessor that never arrives. The table
    /// must not grow without bound: past the per-author cap the oldest holds
    /// go, the newest stay.
    #[test]
    fn one_author_cannot_grow_the_held_table_past_its_cap() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let lookup = keys(vec![(a.clone(), key_a.clone())]);
        let before = held_deltas_evicted();
        let total = MAX_HELD_PER_AUTHOR as u64 + 30;
        for seq in 2..2 + total {
            let d = delta(&a, seq, None, "x", 1, vec![], &key_a);
            let outcome = admit_native_delta(&c, &group(), &d, &lookup).unwrap();
            assert!(matches!(outcome, NativeAdmission::Held { .. }), "{outcome:?}");
        }
        assert_eq!(held_count(&c, Some(&a)), MAX_HELD_PER_AUTHOR);
        assert!(held_deltas_evicted() >= before + 30, "evictions are counted");
        let newest: i64 = c
            .query_row("SELECT MAX(seq) FROM native_delta_holds WHERE author = 'a'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(newest as u64, 1 + total, "the newest hold is kept, the oldest dropped");
    }

    /// Many authors together are bounded too.
    #[test]
    fn a_group_cannot_hold_more_deltas_than_its_cap_across_authors() {
        let c = conn();
        let authors: Vec<(AuthorId, SigningKey)> =
            (0..10u8).map(|n| (author(&format!("w{n}")), key(n + 1))).collect();
        let lookup = keys(authors.clone());
        let per_author = (MAX_HELD_PER_GROUP / 10 + 50).min(MAX_HELD_PER_AUTHOR);
        for (who, signing) in &authors {
            for seq in 2..2 + per_author as u64 {
                let d = delta(who, seq, None, "x", 1, vec![], signing);
                admit_native_delta(&c, &group(), &d, &lookup).unwrap();
            }
        }
        assert!(held_count(&c, None) <= MAX_HELD_PER_GROUP);
        assert!(10 * per_author > MAX_HELD_PER_GROUP, "the test must exceed the group cap");
    }

    #[test]
    fn a_first_delta_admits_directly() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
        let outcome =
            admit_native_delta(&c, &group(), &d, &keys(vec![(a.clone(), key_a)])).unwrap();
        assert!(
            matches!(outcome, NativeAdmission::Admitted { released, .. } if released.is_empty())
        );
    }

    /// This replica's own author on `c`, with its incarnation minted.
    fn own_author(c: &Connection) -> AuthorId {
        crate::author_incarnation::ensure_incarnation(
            c,
            &crate::author_incarnation::IncarnationEnvironment {
                device_id: DeviceId("own".into()),
                sidecar: None,
                machine_fingerprint: b"machine".to_vec(),
            },
        )
        .unwrap()
        .author
    }

    fn ahead_report(c: &Connection) -> Option<crate::author_incarnation::OwnAuthorAhead> {
        crate::author_incarnation::own_author_ahead(c, "g1").unwrap()
    }

    /// A peer presents a delta of this replica's own author that it has not
    /// signed: another copy wrote under the same identity. The delta is
    /// admitted (it is real history), and the report makes the next authoring
    /// rotate before it signs anything.
    #[test]
    fn a_peers_delta_of_this_replicas_own_author_ahead_of_it_is_reported() {
        let c = conn();
        let own = own_author(&c);
        let key_own = key(7);
        let d1 = delta(&own, 1, None, "x", 1, vec![], &key_own);
        let lookup = keys(vec![(own.clone(), key_own)]);

        let admitted = admit_native_delta(&c, &group(), &d1, &lookup).unwrap();

        assert!(matches!(admitted, NativeAdmission::Admitted { .. }), "{admitted:?}");
        let report = ahead_report(&c).expect("the own-author-ahead report is recorded");
        assert_eq!(report.author, own);
        assert_eq!(report.reported, AuthorSeq(1));
        assert_eq!(report.local, AuthorSeq(0));
    }

    /// A delta of the own author that is out of order (its predecessor is
    /// missing) is held, and reported just the same.
    #[test]
    fn a_held_future_delta_of_this_replicas_own_author_is_reported() {
        let c = conn();
        let own = own_author(&c);
        let key_own = key(7);
        let d1 = delta(&own, 1, None, "x", 1, vec![], &key_own);
        let d3 = delta(&own, 3, Some(DeltaHash([9; 32])), "z", 3, vec![], &key_own);
        let lookup = keys(vec![(own.clone(), key_own)]);
        // The first delta is this replica's own, recorded as it authored it.
        native_store::install_verified_delta(&c, &group(), &d1, &key(7).verifying_key()).unwrap();
        assert!(ahead_report(&c).is_none(), "nothing is ahead after its own delta");

        let held = admit_native_delta(&c, &group(), &d3, &lookup).unwrap();

        assert!(matches!(held, NativeAdmission::Held { .. }), "{held:?}");
        assert_eq!(ahead_report(&c).expect("reported").reported, AuthorSeq(3));
    }

    /// A different delta at a sequence this replica already used is another
    /// copy's write under the same identity: reported as ahead by one.
    #[test]
    fn an_equivocation_of_this_replicas_own_author_is_reported() {
        let c = conn();
        let own = own_author(&c);
        let key_own = key(7);
        let mine = delta(&own, 1, None, "x", 1, vec![], &key_own);
        let theirs = delta(&own, 1, None, "y", 2, vec![], &key_own);
        let lookup = keys(vec![(own.clone(), key_own)]);
        // This replica's own delta is already recorded as history.
        native_store::install_verified_delta(&c, &group(), &mine, &key(7).verifying_key()).unwrap();

        let verdict = admit_native_delta(&c, &group(), &theirs, &lookup).unwrap();

        assert!(matches!(verdict, NativeAdmission::Equivocation(_)), "{verdict:?}");
        assert_eq!(ahead_report(&c).expect("reported").reported, AuthorSeq(2));
    }

    /// Another author's deltas, and a redelivery of this replica's own, are
    /// not an own-author-ahead report.
    #[test]
    fn other_authors_and_own_redeliveries_are_not_reported() {
        let c = conn();
        let own = own_author(&c);
        let key_own = key(7);
        let other = author("other");
        let key_other = key(8);
        let lookup = keys(vec![(own.clone(), key_own.clone()), (other.clone(), key_other.clone())]);
        let mine = delta(&own, 1, None, "x", 1, vec![], &key_own);
        native_store::install_verified_delta(&c, &group(), &mine, &key_own.verifying_key())
            .unwrap();

        admit_native_delta(
            &c,
            &group(),
            &delta(&other, 1, None, "o", 1, vec![], &key_other),
            &lookup,
        )
        .unwrap();
        let again = admit_native_delta(&c, &group(), &mine, &lookup).unwrap();

        assert_eq!(again, NativeAdmission::Duplicate);
        assert!(ahead_report(&c).is_none());
    }

    /// A held delta is promoted through the same install funnel as a fresh one, so a rebootstrap's
    /// freeze keeps it where it is, held, until the freeze ends.
    #[test]
    fn held_delta_promotion_is_refused_while_the_group_is_frozen() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let d1 = delta(&a, 1, None, "x", 1, vec![], &key_a);
        let d2 = delta(&a, 2, Some(d1.delta_hash()), "y", 2, vec![], &key_a);
        let lookup = keys(vec![(a.clone(), key_a.clone())]);
        assert!(matches!(
            admit_native_delta(&c, &group(), &d2, &lookup).unwrap(),
            NativeAdmission::Held { .. }
        ));
        // The predecessor lands below the admission layer, so the cascade has not run.
        native_store::install_verified_delta(&c, &group(), &d1, &key_a.verifying_key()).unwrap();
        let predecessor = Dot { author: a.clone(), seq: AuthorSeq(1) };

        crate::native_rebootstrap::set_journal_for_test(&c, &group(), "preserved", "r");
        let released = release_waiters(&c, &group(), &predecessor, &lookup).unwrap();

        assert!(released.is_empty(), "promoted through a freeze: {released:?}");
        assert!(hold_exists(&c, &group(), &d2).unwrap(), "the hold was dropped");
        assert_eq!(
            native_store::frontier_entry_get(&c, &group(), &a).unwrap().map(|e| e.seq),
            Some(AuthorSeq(1))
        );

        c.execute("DELETE FROM native_rebootstrap_journal", []).unwrap();
        let released = release_waiters(&c, &group(), &predecessor, &lookup).unwrap();
        assert_eq!(released, vec![Dot { author: a, seq: AuthorSeq(2) }]);
    }

    #[test]
    fn a_delta_ahead_of_its_own_chain_is_held_and_released_once_its_predecessor_lands() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let d1 = delta(&a, 1, None, "x", 1, vec![], &key_a);
        let d1_hash = d1.delta_hash();
        let d2 = delta(&a, 2, Some(d1_hash), "y", 2, vec![], &key_a);

        let lookup = keys(vec![(a.clone(), key_a)]);
        let held = admit_native_delta(&c, &group(), &d2, &lookup).unwrap();
        assert_eq!(
            held,
            NativeAdmission::Held { waiting_on: Dot { author: a.clone(), seq: AuthorSeq(1) } }
        );

        let admitted = admit_native_delta(&c, &group(), &d1, &lookup).unwrap();
        let NativeAdmission::Admitted { dot, released } = admitted else {
            panic!("expected Admitted, got {admitted:?}")
        };
        assert_eq!(dot, Dot { author: a.clone(), seq: AuthorSeq(1) });
        assert_eq!(released, vec![Dot { author: a.clone(), seq: AuthorSeq(2) }]);

        let state = native_store::load_state(&c, &group()).unwrap();
        assert!(
            state.heads.contains_key(&SyncPath("y".into())),
            "the released delta must actually be applied"
        );
    }

    #[test]
    fn a_different_delta_at_the_same_held_dot_is_an_equivocation_not_a_silent_overwrite() {
        // Two genuinely different signed deltas from `a`, both at seq=2,
        // both held (their common predecessor at seq=1 never arrives in
        // this test): X arrives first and is held, then Y (a different
        // delta at the exact same author/seq) arrives -- the author
        // equivocated. Y must not silently replace X's held evidence.
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let some_prev = DeltaHash([9u8; 32]);
        let x = delta(&a, 2, Some(some_prev), "x", 1, vec![], &key_a);
        let y = delta(&a, 2, Some(some_prev), "y", 2, vec![], &key_a);
        assert_ne!(x.delta_hash(), y.delta_hash(), "x and y must be genuinely different deltas");

        let lookup = keys(vec![(a.clone(), key_a)]);
        let held_x = admit_native_delta(&c, &group(), &x, &lookup).unwrap();
        assert!(matches!(held_x, NativeAdmission::Held { .. }));

        let outcome = admit_native_delta(&c, &group(), &y, &lookup).unwrap();
        let NativeAdmission::Equivocation(e) = outcome else {
            panic!("expected Equivocation, got {outcome:?}")
        };
        assert_eq!(e.author, a);
        assert_eq!(e.seq, AuthorSeq(2));
        assert_eq!(
            e.known,
            x.delta_hash(),
            "the FIRST held delta's hash must be preserved as evidence"
        );
        assert_eq!(e.found, y.delta_hash());

        // The held row must still hold X's own bytes, not Y's.
        let held_bytes: Vec<u8> = c
            .query_row(
                "SELECT wire_bytes FROM native_delta_holds WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND seq = ?4",
                (group().as_str(), a.device.as_str(), a.incarnation.0.as_slice(), 2i64),
                |row| row.get(0),
            )
            .unwrap();
        let held_delta = NativeDelta::from_wire_bytes(&held_bytes).unwrap();
        assert_eq!(
            held_delta.delta_hash(),
            x.delta_hash(),
            "held row must still be X, never overwritten by Y"
        );
    }

    #[test]
    fn redelivering_the_exact_same_held_delta_is_idempotent_not_an_equivocation() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let some_prev = DeltaHash([9u8; 32]);
        let x = delta(&a, 2, Some(some_prev), "x", 1, vec![], &key_a);

        let lookup = keys(vec![(a.clone(), key_a)]);
        let first = admit_native_delta(&c, &group(), &x, &lookup).unwrap();
        assert!(matches!(first, NativeAdmission::Held { .. }));

        // The identical delta, redelivered -- must remain Held, never
        // Equivocation.
        let second = admit_native_delta(&c, &group(), &x, &lookup).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn a_delta_naming_a_reserved_namespace_path_is_refused_outright_not_held() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        // The wire-path predicate
        // (`yadorilink_fs_platform::reserved_namespace::
        // wire_path_admission_refusal`), exercised here through native's
        // own admission path rather than a re-implementation of it.
        let d = delta(&a, 1, None, ".yadorilink-root.lock", 1, vec![], &key_a);
        let outcome =
            admit_native_delta(&c, &group(), &d, &keys(vec![(a.clone(), key_a)])).unwrap();
        assert!(
            matches!(outcome, NativeAdmission::InvalidPath(_)),
            "expected InvalidPath, got {outcome:?}"
        );
        // Final, not a hold: nothing was written waiting for anything.
        let state = native_store::load_state(&c, &group()).unwrap();
        assert!(state.heads.is_empty());
    }

    #[test]
    fn a_delta_naming_an_ordinary_path_is_unaffected_by_the_path_check() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let d = delta(&a, 1, None, "docs/notes.txt", 1, vec![], &key_a);
        let outcome =
            admit_native_delta(&c, &group(), &d, &keys(vec![(a.clone(), key_a)])).unwrap();
        assert!(matches!(outcome, NativeAdmission::Admitted { .. }));
    }

    #[test]
    fn three_puts_at_one_path_with_no_removals_is_refused_at_the_third_not_a_persistent_broken_state(
    ) {
        // Regression: seq1 Put, seq2 Put (no removal of seq1's head),
        // seq3 Put (no removal of seq1/seq2's heads) -- each individually
        // signed, individually chain-continuous, and individually passes
        // the op-level context gate (there is nothing to observe: no
        // removal is named at all). Together they would leave 3 live
        // heads of one author at one path, exceeding MAX_SELF_HEADS (2).
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let lookup = keys(vec![(a.clone(), key_a.clone())]);

        let d1 = delta(&a, 1, None, "x", 1, vec![], &key_a);
        let d1_hash = d1.delta_hash();
        let admitted1 = admit_native_delta(&c, &group(), &d1, &lookup).unwrap();
        assert!(matches!(admitted1, NativeAdmission::Admitted { .. }));

        let d2 = delta(&a, 2, Some(d1_hash), "x", 2, vec![], &key_a);
        let d2_hash = d2.delta_hash();
        let admitted2 = admit_native_delta(&c, &group(), &d2, &lookup).unwrap();
        assert!(matches!(admitted2, NativeAdmission::Admitted { .. }));

        let state_before_d3 = native_store::load_state(&c, &group()).unwrap();

        let d3 = delta(&a, 3, Some(d2_hash), "x", 3, vec![], &key_a);
        let outcome = admit_native_delta(&c, &group(), &d3, &lookup).unwrap();
        assert!(
            matches!(outcome, NativeAdmission::WouldViolateInvariant(_)),
            "expected WouldViolateInvariant, got {outcome:?}"
        );

        // Refused, not merely held: nothing was written for it, and the
        // persisted state is byte-for-byte what it was before the attempt
        // -- not a broken 3-head state a later namespace-v2 write would
        // then fail against.
        let state_after_d3 = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state_before_d3, state_after_d3, "a refused delta must leave state untouched");
        let path_heads = &state_after_d3.heads[&SyncPath("x".into())];
        assert_eq!(path_heads.len(), 2, "still exactly 2 heads, never 3");
    }

    #[test]
    fn a_delta_naming_an_unobserved_foreign_dot_is_held_and_released_once_that_author_lands() {
        let c = conn();
        let a = author("a");
        let b = author("b");
        let key_a = key(1);
        let key_b = key(2);
        let lookup = keys(vec![(a.clone(), key_a.clone()), (b.clone(), key_b.clone())]);

        let b_dot = Dot { author: b.clone(), seq: AuthorSeq(1) };
        // `a`'s delta removes a dot from `b` that this replica has not
        // observed yet at all (not merely superseded).
        let d_a = delta(
            &a,
            1,
            None,
            "x",
            2,
            vec![HeadRef { dot: b_dot.clone(), provenance: DeltaHash([0; 32]) }],
            &key_a,
        );
        let held = admit_native_delta(&c, &group(), &d_a, &lookup).unwrap();
        assert_eq!(held, NativeAdmission::Held { waiting_on: b_dot.clone() });

        let d_b = delta(&b, 1, None, "x", 9, vec![], &key_b);
        let admitted = admit_native_delta(&c, &group(), &d_b, &lookup).unwrap();
        let NativeAdmission::Admitted { released, .. } = admitted else {
            panic!("expected Admitted, got {admitted:?}")
        };
        assert_eq!(
            released,
            vec![Dot { author: a.clone(), seq: AuthorSeq(1) }],
            "a's delta must be released once b's dot is observed"
        );
    }

    #[test]
    fn a_held_delta_whose_blocker_changes_on_retry_is_released_by_the_new_blocker() {
        let c = conn();
        let a = author("a");
        let b = author("b");
        let key_a = key(1);
        let key_b = key(2);
        let lookup = keys(vec![(a.clone(), key_a.clone()), (b.clone(), key_b.clone())]);

        let a_dot = Dot { author: a.clone(), seq: AuthorSeq(1) };
        let d_a = delta(&a, 1, None, "x", 2, vec![], &key_a);
        let d_b1 = delta(&b, 1, None, "y", 3, vec![], &key_b);
        // b@2 removes a@1, and also needs its own predecessor b@1.
        let d_b2 = delta(
            &b,
            2,
            Some(d_b1.delta_hash()),
            "x",
            4,
            vec![HeadRef { dot: a_dot.clone(), provenance: d_a.delta_hash() }],
            &key_b,
        );

        let b1_dot = Dot { author: b.clone(), seq: AuthorSeq(1) };
        let held = admit_native_delta(&c, &group(), &d_b2, &lookup).unwrap();
        assert_eq!(held, NativeAdmission::Held { waiting_on: b1_dot });

        // b@1 lands; b@2 is retried and is now blocked on a@1 instead.
        let admitted = admit_native_delta(&c, &group(), &d_b1, &lookup).unwrap();
        assert!(
            matches!(&admitted, NativeAdmission::Admitted { released, .. } if released.is_empty()),
            "b@2 must still be held on a@1, got {admitted:?}"
        );

        // a@1 lands: the held b@2 must now be released.
        let admitted = admit_native_delta(&c, &group(), &d_a, &lookup).unwrap();
        let NativeAdmission::Admitted { released, .. } = admitted else {
            panic!("expected Admitted, got {admitted:?}")
        };
        assert_eq!(released, vec![Dot { author: b.clone(), seq: AuthorSeq(2) }]);
    }

    #[test]
    fn a_byte_identical_redelivery_of_an_already_admitted_delta_is_a_duplicate() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let lookup = keys(vec![(a.clone(), key_a.clone())]);
        let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
        admit_native_delta(&c, &group(), &d, &lookup).unwrap();
        assert_eq!(
            admit_native_delta(&c, &group(), &d, &lookup).unwrap(),
            NativeAdmission::Duplicate
        );
    }

    #[test]
    fn a_different_delta_at_an_already_admitted_seq_is_equivocation() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let lookup = keys(vec![(a.clone(), key_a.clone())]);
        let d1 = delta(&a, 1, None, "x", 1, vec![], &key_a);
        admit_native_delta(&c, &group(), &d1, &lookup).unwrap();
        let forked = delta(&a, 1, None, "x", 99, vec![], &key_a);
        assert!(matches!(
            admit_native_delta(&c, &group(), &forked, &lookup).unwrap(),
            NativeAdmission::Equivocation(_)
        ));
    }

    #[test]
    fn two_different_deltas_both_claiming_the_legitimate_next_seq_is_equivocation() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let lookup = keys(vec![(a.clone(), key_a.clone())]);
        let d1 = delta(&a, 1, None, "x", 1, vec![], &key_a);
        let d1_hash = d1.delta_hash();
        admit_native_delta(&c, &group(), &d1, &lookup).unwrap();

        let legitimate_next = delta(&a, 2, Some(d1_hash), "y", 2, vec![], &key_a);
        admit_native_delta(&c, &group(), &legitimate_next, &lookup).unwrap();

        // A second, different delta also claiming seq 2 -- but citing the
        // right prev, so it is not a WrongNextSeq case, it is exactly the
        // ChainBreak-at-legitimate-position shape... except prev is
        // correct here, so seq 2 is no longer the legitimate next position
        // (3 is); this actually falls into NeedsHistoryLookup, and its
        // hash differs from the one logged at seq 2.
        let forked_at_2 = delta(&a, 2, Some(d1_hash), "z", 3, vec![], &key_a);
        assert!(matches!(
            admit_native_delta(&c, &group(), &forked_at_2, &lookup).unwrap(),
            NativeAdmission::Equivocation(_)
        ));
    }

    #[test]
    fn an_unknown_author_is_refused_without_touching_state() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
        let outcome = admit_native_delta(&c, &group(), &d, &keys(vec![])).unwrap();
        assert_eq!(outcome, NativeAdmission::UnknownAuthor);
        assert!(native_store::load_state(&c, &group()).unwrap().heads.is_empty());
    }

    #[test]
    fn a_bad_signature_is_refused() {
        let c = conn();
        let a = author("a");
        let mut d = delta(&a, 1, None, "x", 1, vec![], &key(1));
        d.signature = [0xAB; 64];
        let outcome =
            admit_native_delta(&c, &group(), &d, &keys(vec![(a.clone(), key(1))])).unwrap();
        assert_eq!(outcome, NativeAdmission::BadSignature);
    }

    /// A replica joined from a checkpoint holds no log below its frontier: a
    /// redelivery there is reported as unverifiable. Without a checkpoint the
    /// same missing entry is drift, and a seq the replica did log is still a
    /// plain duplicate.
    #[test]
    fn a_redelivery_below_a_joined_checkpoints_history_is_reported_as_unverifiable() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let lookup = keys(vec![(a.clone(), key_a.clone())]);

        let d1 = delta(&a, 1, None, "x", 1, vec![], &key_a);
        let d2 = delta(&a, 2, Some(d1.delta_hash()), "x", 2, vec![], &key_a);
        admit_native_delta(&c, &group(), &d1, &lookup).unwrap();
        admit_native_delta(&c, &group(), &d2, &lookup).unwrap();
        c.execute("DELETE FROM native_delta_log WHERE seq = 1", []).unwrap();

        let drifted = admit_native_delta(&c, &group(), &d1, &lookup).unwrap();
        assert!(matches!(drifted, NativeAdmission::Malformed(_)), "{drifted:?}");

        // The replica's history begins at the checkpoint it adopted as its floor.
        let floor =
            crate::native_checkpoint_frontier::adopt_current_state_for_test(&c, &group()).unwrap();
        crate::native_history_floor::adopt_history_floor(&c, &group(), &floor).unwrap();

        let redelivered = admit_native_delta(&c, &group(), &d1, &lookup).unwrap();
        assert_eq!(redelivered, NativeAdmission::PriorHistoryTruncated { at_seq: AuthorSeq(1) });
        let logged = admit_native_delta(&c, &group(), &d2, &lookup).unwrap();
        assert_eq!(logged, NativeAdmission::Duplicate);
    }

    /// A replica that already held part of an author's history and then joined
    /// a bundle has holes in its log below the frontier, not only a missing
    /// prefix: a redelivery in a hole is just as unverifiable as one below the
    /// first logged delta.
    #[test]
    fn a_redelivery_in_a_hole_left_by_a_join_is_reported_as_unverifiable() {
        let c = conn();
        let a = author("a");
        let key_a = key(1);
        let lookup = keys(vec![(a.clone(), key_a.clone())]);

        let d1 = delta(&a, 1, None, "x", 1, vec![], &key_a);
        let d2 = delta(&a, 2, Some(d1.delta_hash()), "x", 2, vec![], &key_a);
        let d3 = delta(&a, 3, Some(d2.delta_hash()), "y", 3, vec![], &key_a);
        for d in [&d1, &d2, &d3] {
            let admitted = admit_native_delta(&c, &group(), d, &lookup).unwrap();
            assert!(matches!(admitted, NativeAdmission::Admitted { .. }), "{admitted:?}");
        }
        c.execute("DELETE FROM native_delta_log WHERE seq = 2", []).unwrap();

        // The replica's history begins at the checkpoint it adopted as its floor.
        let floor =
            crate::native_checkpoint_frontier::adopt_current_state_for_test(&c, &group()).unwrap();
        crate::native_history_floor::adopt_history_floor(&c, &group(), &floor).unwrap();

        let redelivered = admit_native_delta(&c, &group(), &d2, &lookup).unwrap();
        assert_eq!(redelivered, NativeAdmission::PriorHistoryTruncated { at_seq: AuthorSeq(2) });
    }

    mod published {
        //! `admit_published_native_delta` -- the fixed invariants are:
        //! authorized at
        //! publish/certify time, not edit time; a delta legitimately
        //! published before a revoke stays valid even arriving late; a
        //! delta published after a revoke is refused; the verdict never
        //! depends on delivery order; a held delta's evidence survives to
        //! its eventual release.
        use super::*;
        use yadorilink_replica_domain::authorization_checkpoint::{
            build_merkle_proof, canonical_signing_bytes,
            checkpoint_hash as compute_checkpoint_hash, fingerprint_signing_key, merkle_root,
            sign_checkpoint, AuthorizationCheckpoint,
        };

        const GROUP_STR: &str = "g1";

        fn authority_key() -> SigningKey {
            SigningKey::from_bytes(&[42u8; 32])
        }

        /// One delta's full authorization bundle, as an honest sender (or
        /// the local checkpoint-flush path, once built) would produce it.
        struct Bundle {
            encoded_delta: Vec<u8>,
            checkpoint_hash: [u8; 32],
            checkpoint_encoded: Vec<u8>,
            checkpoint_signature: [u8; 64],
            author_public_key: [u8; 32],
            proof: MerkleProof,
        }

        fn bundle_for(
            delta: &NativeDelta,
            author_signing_key: &SigningKey,
            device_id: &str,
        ) -> Bundle {
            let leaves = vec![delta.delta_hash().0];
            let checkpoint = AuthorizationCheckpoint {
                group_id: GROUP_STR.to_string(),
                device_id: device_id.to_string(),
                signing_key_fingerprint: fingerprint_signing_key(
                    &author_signing_key.verifying_key(),
                ),
                merkle_root: merkle_root(&leaves),
                leaf_count: 1,
                checkpoint_seq: 1,
                signer_key_id: fingerprint_signing_key(&authority_key().verifying_key()),
                policy_epoch: 0,
                policy_seq: 1,
                policy_head: [0u8; 32],
                issued_at_unix: 1,
            };
            let signature = sign_checkpoint(&checkpoint, &authority_key());
            let checkpoint_encoded = canonical_signing_bytes(&checkpoint);
            Bundle {
                encoded_delta: delta.to_wire_bytes(),
                checkpoint_hash: compute_checkpoint_hash(&checkpoint_encoded, &signature),
                checkpoint_encoded,
                checkpoint_signature: signature,
                author_public_key: author_signing_key.verifying_key().to_bytes(),
                proof: build_merkle_proof(&leaves, 0),
            }
        }

        fn resolve_authority(
            recognize: bool,
        ) -> impl Fn(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey> {
            move |key_id, _head| {
                let authority = authority_key().verifying_key();
                (recognize && *key_id == fingerprint_signing_key(&authority)).then_some(authority)
            }
        }

        fn admit(
            c: &Connection,
            bundle: &Bundle,
            key_for: &dyn Fn(&AuthorId) -> Option<VerifyingKey>,
            recognize_authority: bool,
        ) -> NativeAdmission {
            admit_published_native_delta(
                c,
                &group(),
                &bundle.encoded_delta,
                &bundle.checkpoint_hash,
                &bundle.checkpoint_encoded,
                &bundle.checkpoint_signature,
                &bundle.author_public_key,
                &bundle.proof,
                key_for,
                resolve_authority(recognize_authority),
            )
            .unwrap()
        }

        #[test]
        fn a_delta_published_before_a_revoke_admits_and_is_recorded_as_published() {
            let c = conn();
            let a = author("a");
            let key_a = key(1);
            let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let d_hash = d.delta_hash();
            let bundle = bundle_for(&d, &key_a, "a");
            let lookup = keys(vec![(a.clone(), key_a)]);

            let outcome = admit(&c, &bundle, &lookup, true);
            assert!(matches!(outcome, NativeAdmission::Admitted { .. }));
            assert!(native_publication::is_published(&c, &d_hash).unwrap());
        }

        /// The fixed invariant: a delta published while its author was a
        /// legitimate writer stays valid however late it arrives, even
        /// after that author is later revoked. `verify_change_admission`
        /// never asks "is this author CURRENTLY a writer" -- only whether
        /// the checkpoint's signature verifies under a key the receiver's
        /// policy chain recognizes as having been valid at `policy_head`.
        /// There is no clock anywhere in this check (see
        /// `AuthorizationCheckpoint::issued_at_unix`'s own doc: deliberately
        /// not part of what admission checks), so a late arrival changes
        /// nothing.
        #[test]
        fn a_delta_published_before_a_revoke_is_still_valid_no_matter_how_late_it_arrives() {
            let c = conn();
            let a = author("a");
            let key_a = key(1);
            let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let bundle = bundle_for(&d, &key_a, "a");
            let lookup = keys(vec![(a.clone(), key_a)]);

            let outcome = admit(&c, &bundle, &lookup, true);
            assert!(matches!(outcome, NativeAdmission::Admitted { .. }));
        }

        /// A delta whose checkpoint was signed by a key the receiver's OWN
        /// verified policy chain no longer recognizes -- e.g. the authority
        /// key was rotated/the device's checkpoint-issuing capability was
        /// revoked before this checkpoint could have been legitimately
        /// issued -- is refused outright, and nothing is written for it.
        #[test]
        fn a_delta_whose_checkpoint_signer_the_policy_chain_no_longer_recognizes_is_refused() {
            let c = conn();
            let a = author("a");
            let key_a = key(1);
            let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let d_hash = d.delta_hash();
            let bundle = bundle_for(&d, &key_a, "a");
            let lookup = keys(vec![(a.clone(), key_a)]);

            let outcome = admit(&c, &bundle, &lookup, false);
            assert!(matches!(outcome, NativeAdmission::Unauthorized(_)));
            assert!(!native_publication::is_published(&c, &d_hash).unwrap());
            assert!(
                native_store::load_state(&c, &group()).unwrap().heads.is_empty(),
                "an unauthorized delta must never be installed, chain/context gates never even run"
            );
        }

        /// No parameter carries who delivered the delta or when -- admitting
        /// the identical bundle via two separate calls (modeling two
        /// different receive paths, or a re-delivery) gives the identical
        /// verdict.
        #[test]
        fn the_verdict_does_not_depend_on_delivery_order() {
            let c1 = conn();
            let c2 = conn();
            let a = author("a");
            let key_a = key(1);
            let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let bundle = bundle_for(&d, &key_a, "a");
            let lookup = keys(vec![(a.clone(), key_a)]);

            let first = admit(&c1, &bundle, &lookup, true);
            let second = admit(&c2, &bundle, &lookup, true);
            assert_eq!(first, second);
        }

        /// A delta that verifies but is held on its own chain gate still has
        /// its evidence attached the moment it is later released -- the
        /// evidence is never re-derived or dropped across the hold.
        #[test]
        fn a_held_deltas_evidence_survives_to_its_eventual_release() {
            let c = conn();
            let a = author("a");
            let key_a = key(1);
            let d1 = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let d1_hash = d1.delta_hash();
            let d2 = delta(&a, 2, Some(d1_hash), "y", 2, vec![], &key_a);
            let d2_hash = d2.delta_hash();
            let lookup = keys(vec![(a.clone(), key_a.clone())]);

            // d2 arrives first, verified but held on its own chain gate.
            let bundle2 = bundle_for(&d2, &key_a, "a");
            let held = admit(&c, &bundle2, &lookup, true);
            assert!(matches!(held, NativeAdmission::Held { .. }));
            assert!(!native_publication::is_published(&c, &d2_hash).unwrap());

            // d1 lands (via the same published path); its own admission
            // releases d2, which must now ALSO be published, from the
            // evidence it already carried across the hold.
            let bundle1 = bundle_for(&d1, &key_a, "a");
            let admitted = admit(&c, &bundle1, &lookup, true);
            assert!(matches!(admitted, NativeAdmission::Admitted { .. }));
            assert!(native_publication::is_published(&c, &d1_hash).unwrap());
            assert!(
                native_publication::is_published(&c, &d2_hash).unwrap(),
                "the released delta's evidence must have carried across its hold"
            );
        }

        /// A delta already installed via the plain (non-proof-carrying)
        /// path, whose legitimate publication proof only arrives later,
        /// must still end up published -- not stuck at `is_published =
        /// false` forever because `Step::Duplicate` used to skip evidence
        /// attachment entirely.
        #[test]
        fn a_late_arriving_proof_for_an_already_installed_delta_is_still_attached() {
            let c = conn();
            let a = author("a");
            let key_a = key(1);
            let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let d_hash = d.delta_hash();
            let lookup = keys(vec![(a.clone(), key_a.clone())]);

            // Installed with no proof at hand yet.
            let plain = admit_native_delta(&c, &group(), &d, &lookup).unwrap();
            assert!(matches!(plain, NativeAdmission::Admitted { .. }));
            assert!(!native_publication::is_published(&c, &d_hash).unwrap());

            // The same delta's valid proof arrives later.
            let bundle = bundle_for(&d, &key_a, "a");
            let outcome = admit(&c, &bundle, &lookup, true);
            assert!(matches!(outcome, NativeAdmission::Duplicate));
            assert!(
                native_publication::is_published(&c, &d_hash).unwrap(),
                "a late-arriving proof for an already-installed delta must still attach evidence"
            );
        }

        /// The actual regression this fixes: `a_delta_published_before_a_
        /// revoke_is_still_valid_no_matter_how_late_it_arrives` (above)
        /// never removed the author from `key_for`'s own lookup table, so
        /// it could not have caught the bug it claims to guard against.
        /// Here `key_for` is `|_| None` -- exactly what a live key table
        /// looks like once an author is fully revoked and forgotten -- and
        /// admission must still succeed, using the checkpoint-carried key
        /// `verify_proof_carrying_delta` already proved correct.
        #[test]
        fn a_delta_published_before_a_revoke_admits_even_once_the_author_is_gone_from_the_live_key_table(
        ) {
            let c = conn();
            let a = author("a");
            let key_a = key(1);
            let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let d_hash = d.delta_hash();
            let bundle = bundle_for(&d, &key_a, "a");
            let no_live_keys: &dyn Fn(&AuthorId) -> Option<VerifyingKey> = &|_| None;

            let outcome = admit(&c, &bundle, no_live_keys, true);
            assert!(
                matches!(outcome, NativeAdmission::Admitted { .. }),
                "a checkpoint-verified delta must not be refused for a revoked/forgotten live key: {outcome:?}"
            );
            assert!(native_publication::is_published(&c, &d_hash).unwrap());
        }

        /// The same regression, on the held-then-released path: `d2`
        /// arrives (and is verified, then held on its own chain gate)
        /// WHILE the author is still live, but by the time `d1` lands and
        /// releases it, the author has been fully revoked from the live
        /// key table. Release must still succeed, from `d2`'s own stored
        /// pending evidence -- not from a live lookup that no longer knows
        /// this author at all.
        #[test]
        fn a_held_deltas_release_does_not_depend_on_the_live_key_table_either() {
            let c = conn();
            let a = author("a");
            let key_a = key(1);
            let d1 = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let d1_hash = d1.delta_hash();
            let d2 = delta(&a, 2, Some(d1_hash), "y", 2, vec![], &key_a);
            let d2_hash = d2.delta_hash();

            // d2 arrives first and is held -- the live table still knows
            // `a` at this point, mirroring a real receive that happens
            // before any revoke.
            let live_lookup = keys(vec![(a.clone(), key_a.clone())]);
            let bundle2 = bundle_for(&d2, &key_a, "a");
            let held = admit(&c, &bundle2, &live_lookup, true);
            assert!(matches!(held, NativeAdmission::Held { .. }));

            // By the time d1 arrives and releases d2, `a` is gone from the
            // live key table entirely.
            let no_live_keys: &dyn Fn(&AuthorId) -> Option<VerifyingKey> = &|_| None;
            let bundle1 = bundle_for(&d1, &key_a, "a");
            let admitted = admit(&c, &bundle1, no_live_keys, true);
            let NativeAdmission::Admitted { released, .. } = admitted else {
                panic!("expected d1 to admit directly, got {admitted:?}")
            };
            assert_eq!(
                released,
                vec![Dot { author: a.clone(), seq: AuthorSeq(2) }],
                "d2 must still be released"
            );
            assert!(native_publication::is_published(&c, &d2_hash).unwrap());
        }

        /// The plain, unauthenticated [`admit_native_delta`] path (used by
        /// local authoring) is untouched by any of this: a delta
        /// admitted through it stays installed but unpublished until
        /// something separately attaches evidence for it.
        #[test]
        fn the_plain_admission_path_is_unaffected_and_leaves_deltas_unpublished() {
            let c = conn();
            let a = author("a");
            let key_a = key(1);
            let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let d_hash = d.delta_hash();
            let outcome =
                admit_native_delta(&c, &group(), &d, &keys(vec![(a.clone(), key_a)])).unwrap();
            assert!(matches!(outcome, NativeAdmission::Admitted { .. }));
            assert!(!native_publication::is_published(&c, &d_hash).unwrap());
        }

        /// `admit_published_native_delta` on a bare, non-transactional
        /// `Connection` (exactly how `yadorilink-daemon`'s
        /// replication session calls it, receiving bytes off a real peer
        /// connection) must be all-or-nothing. Fails the
        /// LAST write in the sequence (evidence promotion into
        /// `native_delta_authorization`) -- the point furthest from the
        /// start, so a bug here is the one most likely to leave every
        /// EARLIER write (state, frontier, delta log, delta body)
        /// committed while only publication is lost. Mirrors
        /// `native_checkpoint_authorization`'s own crash-injection idiom
        /// (`a_crash_partway_through_the_snapshot_insert_loop_leaves_
        /// nothing_partial`, itself mirroring `dcf_crash.rs`'s
        /// scalar-function-plus-trigger failpoint).
        #[test]
        fn a_crash_at_the_last_step_leaves_nothing_partial_not_even_the_earlier_writes() {
            use rusqlite::functions::FunctionFlags;

            let c = conn();
            let a = author("a");
            let key_a = key(1);
            let d = delta(&a, 1, None, "x", 1, vec![], &key_a);
            let bundle = bundle_for(&d, &key_a, "a");
            let lookup = keys(vec![(a.clone(), key_a)]);

            c.create_scalar_function("failpoint_hit", 0, FunctionFlags::SQLITE_UTF8, |_| Ok(true))
                .unwrap();
            c.execute_batch(
                "CREATE TEMP TRIGGER evidence_failpoint BEFORE INSERT ON main.native_delta_authorization \
                 BEGIN SELECT RAISE(ABORT, 'injected crash') WHERE failpoint_hit(); END;",
            )
            .unwrap();

            let err = admit_published_native_delta(
                &c,
                &group(),
                &bundle.encoded_delta,
                &bundle.checkpoint_hash,
                &bundle.checkpoint_encoded,
                &bundle.checkpoint_signature,
                &bundle.author_public_key,
                &bundle.proof,
                &lookup,
                resolve_authority(true),
            )
            .unwrap_err();
            assert!(err.to_string().contains("injected crash"), "{err}");

            // Nothing survives: not the state, not the frontier, not the
            // log, not the body, not the checkpoint, not the pending
            // evidence -- the whole sequence rolled back together.
            assert!(native_store::load_state(&c, &group()).unwrap().heads.is_empty());
            assert!(native_store::frontier_entry_get(&c, &group(), &a).unwrap().is_none());
            assert_eq!(native_store::delta_log_hash(&c, &group(), &a, AuthorSeq(1)).unwrap(), None);
            assert_eq!(
                native_store::fetch_delta_body(&c, &group(), &a, AuthorSeq(1)).unwrap(),
                None
            );
            assert!(!native_publication::is_published(&c, &d.delta_hash()).unwrap());

            // Disarm and confirm a retry succeeds cleanly -- crash
            // recovery, not permanent corruption.
            c.execute_batch("DROP TRIGGER evidence_failpoint;").unwrap();
            let retried = admit(&c, &bundle, &lookup, true);
            assert!(matches!(retried, NativeAdmission::Admitted { .. }));
            assert!(native_publication::is_published(&c, &d.delta_hash()).unwrap());
        }
    }
}
