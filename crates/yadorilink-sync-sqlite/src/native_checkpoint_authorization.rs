//! Storage-layer half of `NativeCheckpoint` sealing, over the SAME shared
//! authority layer as delta publication
//! (`authorization_checkpoint`/`native_checkpoint_seal`), keyed by a
//! checkpoint's own `checkpoint_hash` rather than a `DeltaHash`.
//!
//! Two schemas, two lifecycles, never conflated (see
//! `native_publication.rs`'s own doc for the same point about the delta
//! case):
//!
//! * `native_checkpoint::NativeCheckpoint`/`native_store::seal_checkpoint`
//!   -- a GROUP-level Merkle namespace/frontier-root snapshot, signed by
//!   the sealer's OWN key. Answers "what did this group's content and
//!   author-frontier look like at this point."
//! * `native_checkpoint_seal::NativeCheckpointSealEvidence` (this module's
//!   input) -- a PER-SEAL writer-legitimacy proof, issued by the same
//!   coordination-plane authority that issues the per-delta evidence.
//!   Answers "was this device a writer when it sealed this
//!   specific checkpoint."
//!
//! [`install_authorized_checkpoint`] is the ONE gate a `NativeCheckpoint`
//! must pass to be recognized as a checkpoint this replica retains and can
//! offer for recovery: it verifies the seal-authorization
//! evidence (`native_checkpoint_seal::verify_native_checkpoint_seal_authorization`),
//! verifies the checkpoint's own sealer signature
//! (`NativeCheckpoint::verify_signature`, against the SAME public key the
//! evidence names), and only then adopts it together with the frontier it
//! covers.

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
use yadorilink_replica_domain::native_checkpoint::NativeCheckpoint;
use yadorilink_replica_domain::native_checkpoint_seal::{
    verify_native_checkpoint_seal_authorization, NativeCheckpointSealEvidence, NativeSealPolicy,
};

use crate::error::SyncSqliteError;

/// Creates this module's tables on `conn`.
pub fn init_native_checkpoint_authorization_tables(
    conn: &Connection,
) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- The seal-authorization evidence a checkpoint was actually
        -- installed with, kept for the SAME durable lifetime as the
        -- checkpoint body itself (`native_checkpoints`, in `native_store`)
        -- so this replica can still show another peer, after its own restart,
        -- that the checkpoint was legitimately sealed --
        -- this evidence, plus the checkpoint body, is the ONLY remaining
        -- proof the checkpoint was ever legitimately sealed.
        -- `evidence_sealer`/`evidence_bytes` are
        -- exactly `NativeCheckpointSealEvidence`'s two fields; this
        -- replica already verified them once at install time
        -- (`verify_native_checkpoint_seal_authorization`) and does not
        -- re-verify on every read -- a receiving PEER re-verifies
        -- independently, which is the whole point of carrying raw evidence
        -- rather than a boolean "this replica said it checked."
        CREATE TABLE IF NOT EXISTS native_checkpoint_seal_evidence (
            group_id       TEXT NOT NULL,
            checkpoint_hash BLOB NOT NULL,
            evidence_sealer TEXT NOT NULL,
            evidence_bytes  BLOB NOT NULL,
            PRIMARY KEY (group_id, checkpoint_hash)
        );
        "#,
    )?;
    Ok(())
}

/// Verifies `evidence` authorizes `sealer_public_key` to have sealed
/// `checkpoint` for `group_id`, verifies `checkpoint`'s own signature
/// against that same key, and only on both successes adopts it
/// ([`crate::native_checkpoint_frontier::adopt_verified_checkpoint`]), together
/// with its evidence and the frontier it covers in one atomic step.
pub fn install_authorized_checkpoint(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint: &NativeCheckpoint,
    evidence: &NativeCheckpointSealEvidence,
    policy: &dyn NativeSealPolicy,
    coverage: &crate::native_checkpoint_frontier::CheckpointCoverage,
) -> Result<(), SyncSqliteError> {
    let verified = verify_native_checkpoint_seal_authorization(
        group_id.as_str(),
        checkpoint,
        evidence,
        policy,
    )
    .map_err(|refusal| {
        SyncSqliteError::InvalidInput(format!("native checkpoint seal not authorized: {refusal:?}"))
    })?;
    let sealer_key =
        ed25519_dalek::VerifyingKey::from_bytes(&verified.sealer_public_key).map_err(|_| {
            SyncSqliteError::InvalidInput("malformed sealer public key in evidence".into())
        })?;

    crate::native_checkpoint_frontier::adopt_verified_checkpoint(
        conn,
        group_id,
        checkpoint,
        evidence,
        &sealer_key,
        coverage,
    )
}

/// Persists `evidence` exactly as verified, keyed by the checkpoint it
/// authorized -- see this module's own table doc for why it shares the
/// checkpoint body's durable lifetime.
pub(crate) fn store_seal_evidence(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint_hash: &[u8; 32],
    evidence: &NativeCheckpointSealEvidence,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT OR IGNORE INTO native_checkpoint_seal_evidence \
         (group_id, checkpoint_hash, evidence_sealer, evidence_bytes) VALUES (?1, ?2, ?3, ?4)",
        (
            group_id.as_str(),
            &checkpoint_hash[..],
            evidence.sealer.as_str(),
            evidence.evidence.as_slice(),
        ),
    )?;
    Ok(())
}

/// The seal-authorization evidence a checkpoint was installed with, if
/// this replica still has it, to hand to a peer alongside the checkpoint
/// body itself.
pub fn fetch_checkpoint_seal_evidence(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint_hash: &[u8; 32],
) -> Result<Option<NativeCheckpointSealEvidence>, SyncSqliteError> {
    conn.query_row(
        "SELECT evidence_sealer, evidence_bytes FROM native_checkpoint_seal_evidence \
         WHERE group_id = ?1 AND checkpoint_hash = ?2",
        (group_id.as_str(), &checkpoint_hash[..]),
        |row| {
            let sealer: String = row.get(0)?;
            let evidence: Vec<u8> = row.get(1)?;
            Ok(NativeCheckpointSealEvidence { sealer: DeviceId(sealer), evidence })
        },
    )
    .optional()
    .map_err(SyncSqliteError::from)
}

#[cfg(test)]
mod tests;
