//! Publication of this device's own native deltas. A native delta is
//! sendable to a peer only with authorization evidence, so the deltas
//! `author_op` installed locally stay unsent until this attaches it.
//!
//! The same [`CheckpointSource`] issues the checkpoint; a native leaf is the
//! delta's [`DeltaHash`], and every leaf is independently verified before
//! any evidence is attached.

use ed25519_dalek::VerifyingKey;
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proofs, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof,
    merkle_root, verify_change_inclusion, verify_checkpoint_authorization,
};
use yadorilink_replica_domain::ids::{DeltaHash, FolderGroupId};
use yadorilink_sync_sqlite::native_publication;

use crate::checkpoint_source::{
    pending_batch_request_id, AuthorityKeyResolver, CheckpointPurpose, CheckpointSource,
    FlushError, FlushOutcome,
};

/// The most deltas one checkpoint covers: the coordination plane refuses to
/// sign a checkpoint claiming more leaves. A longer backlog is published in
/// order, the rest by the next flush.
const MAX_BATCH_LEAVES: usize = 1 << 20;

/// Leaves verified between two looks at the stop signal. Verification is
/// CPU-bound inside an async task, so this bounds how long a shutdown waits on
/// it (and how long the runtime goes without a scheduling point).
const VERIFY_CHUNK_LEAVES: usize = 4096;

/// Cuts `pending` (in publication order) to at most `max` entries.
fn cap_batch<T>(pending: &mut Vec<T>, max: usize) {
    pending.truncate(max);
}

/// What a native flush did, and which deltas it just made sendable.
#[derive(Debug)]
pub struct NativeFlush {
    pub outcome: FlushOutcome,
    pub published: Vec<DeltaHash>,
}

/// [`flush_pending_native_checkpoint_until`] with no stop signal.
pub async fn flush_pending_native_checkpoint(
    db: &yadorilink_sqlite_runtime::SyncDatabase,
    source: &dyn CheckpointSource,
    group_id: &str,
    device_id: &str,
    own_signing_public_key: &VerifyingKey,
    resolve_authority_key: &AuthorityKeyResolver<'_>,
) -> Result<NativeFlush, FlushError> {
    flush_pending_native_checkpoint_until(
        db,
        source,
        group_id,
        device_id,
        own_signing_public_key,
        resolve_authority_key,
        &|| false,
    )
    .await
}

/// Collects `device_id`'s pending native deltas in `group_id` (every
/// incarnation), obtains one signed checkpoint for the batch, verifies it
/// against every delta, and only then attaches evidence for all of them.
/// Idempotent and retry-safe: the request id is derived from the pending set.
///
/// `should_stop` is polled between chunks of the CPU-bound verification; once
/// it returns true the flush returns [`FlushOutcome::Interrupted`] without
/// attaching anything, and the next flush redoes the same batch.
pub async fn flush_pending_native_checkpoint_until(
    db: &yadorilink_sqlite_runtime::SyncDatabase,
    source: &dyn CheckpointSource,
    group_id: &str,
    device_id: &str,
    own_signing_public_key: &VerifyingKey,
    resolve_authority_key: &AuthorityKeyResolver<'_>,
    should_stop: &(dyn Fn() -> bool + Sync),
) -> Result<NativeFlush, FlushError> {
    let group = FolderGroupId(group_id.to_owned());
    let mut pending: Vec<_> = db.read(|conn| {
        native_publication::pending_native_deltas_for_device(conn, &group, device_id)
    })?;
    cap_batch(&mut pending, MAX_BATCH_LEAVES);
    if pending.is_empty() {
        return Ok(NativeFlush { outcome: FlushOutcome::NothingPending, published: Vec::new() });
    }

    let leaves: Vec<[u8; 32]> =
        pending.iter().map(|(_, _, hash): &(_, _, DeltaHash)| hash.0).collect();
    let request_id = pending_batch_request_id(
        group_id,
        device_id,
        &leaves.iter().map(|leaf| DeltaHash(*leaf)).collect::<Vec<_>>(),
    );
    let root = merkle_root(&leaves);

    let Some((checkpoint, signature)) = source
        .request_authorization_checkpoint(
            group_id,
            device_id,
            &request_id,
            root,
            leaves.len() as u64,
            CheckpointPurpose::Publication,
        )
        .await
    else {
        return Ok(NativeFlush { outcome: FlushOutcome::Refused, published: Vec::new() });
    };

    // The checkpoint-level checks (signature, group, device, key) do not
    // depend on the leaf, so they run once; each leaf then needs only its own
    // Merkle path checked.
    verify_checkpoint_authorization(
        group_id,
        device_id,
        own_signing_public_key,
        &checkpoint,
        &signature,
        |key_id, policy_head| resolve_authority_key(key_id, policy_head),
    )
    .map_err(|error| FlushError::CheckpointDidNotVerify { change_index: 0, error })?;
    let proofs = build_merkle_proofs(&leaves);
    for (chunk_index, chunk) in leaves.chunks(VERIFY_CHUNK_LEAVES).enumerate() {
        if should_stop() {
            return Ok(NativeFlush { outcome: FlushOutcome::Interrupted, published: Vec::new() });
        }
        let first = chunk_index * VERIFY_CHUNK_LEAVES;
        for (offset, leaf) in chunk.iter().enumerate() {
            let index = first + offset;
            verify_change_inclusion(*leaf, &proofs[index], &checkpoint).map_err(|error| {
                FlushError::CheckpointDidNotVerify { change_index: index, error }
            })?;
        }
        tokio::task::yield_now().await;
    }
    if should_stop() {
        return Ok(NativeFlush { outcome: FlushOutcome::Interrupted, published: Vec::new() });
    }

    let checkpoint_encoded = canonical_signing_bytes(&checkpoint);
    let hash = checkpoint_hash(&checkpoint_encoded, &signature);
    let entries: Vec<(DeltaHash, Vec<u8>)> = pending
        .iter()
        .zip(proofs.iter())
        .map(|((_, _, delta_hash), proof)| (*delta_hash, encode_merkle_proof(proof)))
        .collect();
    let key_bytes = own_signing_public_key.to_bytes();
    db.write(|conn| {
        native_publication::attach_authorization_evidence(
            conn,
            &hash,
            group_id,
            device_id,
            checkpoint.checkpoint_seq,
            &checkpoint_encoded,
            &signature,
            &key_bytes,
            &entries,
        )
    })?;

    Ok(NativeFlush {
        outcome: FlushOutcome::Flushed {
            batch_size: pending.len(),
            checkpoint_seq: checkpoint.checkpoint_seq,
        },
        published: entries.into_iter().map(|(hash, _)| hash).collect(),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cap_tests {
    use super::*;

    #[test]
    fn a_backlog_beyond_the_cap_is_cut_in_order() {
        let mut pending: Vec<u32> = (0..10).collect();
        cap_batch(&mut pending, 4);
        assert_eq!(pending, vec![0, 1, 2, 3]);
        cap_batch(&mut pending, 100);
        assert_eq!(pending.len(), 4, "a shorter backlog is untouched");
    }
}
