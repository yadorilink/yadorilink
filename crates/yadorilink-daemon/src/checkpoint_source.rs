//! The daemon-side half
//! of checkpoint issuance — collecting a group's pending (uncheckpointed)
//! native deltas into a batch, requesting a signed `AuthorizationCheckpoint`
//! for it, and attaching the result locally so `published_view`'s
//! functions start reporting those deltas as published.
//!
//! A trait so tests can supply a fake without any network dependency, and
//! a thin production implementation wrapping
//! `coordination_client::request_authorization_checkpoint`.
//!
//! Wired into the daemon's reconnect event loop by
//! `peer_orchestrator/ws_netmap.rs::spawn_flush_pending_checkpoints` and
//! surfaced by `connection_trace.rs`'s `checkpoint_pending` doctor
//! category. This is the ONLY local-publication path —
//! there is no second way for a locally authored Change to become
//! `Published`.

use std::future::Future;
use std::pin::Pin;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use yadorilink_replica_domain::ids::DeltaHash;

use yadorilink_replica_domain::authorization_checkpoint::{
    AuthorizationCheckpoint, CheckpointAdmissionError,
};

/// What the authority is asked to issue a checkpoint for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointPurpose {
    /// Publication evidence for a writer's own deltas; any current writer may have one issued.
    Publication,
    /// A native-checkpoint seal that a replica with no state adopts as complete: authorized
    /// writers are trusted for the completeness of what they seal, so any current writer may
    /// have one issued and a viewer may not.
    Seal,
}

/// How this device obtains a signed [`AuthorizationCheckpoint`] for a
/// batch of its own pending Changes. [`ProductionCheckpointSource`]
/// (below) is the real implementation; tests supply a fake.
pub trait CheckpointSource: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn request_authorization_checkpoint<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        request_id: &'a str,
        merkle_root: [u8; 32],
        leaf_count: u64,
        purpose: CheckpointPurpose,
    ) -> CheckpointFuture<'a>;
}

/// What [`CheckpointSource::request_authorization_checkpoint`] resolves to: the signed checkpoint and
/// its signature, or `None` when none could be obtained.
pub type CheckpointFuture<'a> =
    Pin<Box<dyn Future<Output = Option<(AuthorizationCheckpoint, [u8; 64])>> + Send + 'a>>;

/// Resolves the authority key for a checkpoint's `(key_id, policy_head)`.
pub type AuthorityKeyResolver<'a> =
    dyn Fn(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey> + Send + Sync + 'a;

/// The real [`CheckpointSource`] — a thin wrapper over
/// `coordination_client::request_authorization_checkpoint`, holding plain
/// values rather than an `Arc<DaemonState>` back-reference.
pub struct ProductionCheckpointSource {
    coordination_addr: String,
    auth: yadorilink_fapi_client::CoordinationAuth,
}

impl ProductionCheckpointSource {
    pub fn new(coordination_addr: String, auth: yadorilink_fapi_client::CoordinationAuth) -> Self {
        Self { coordination_addr, auth }
    }
}

impl CheckpointSource for ProductionCheckpointSource {
    fn request_authorization_checkpoint<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        request_id: &'a str,
        merkle_root: [u8; 32],
        leaf_count: u64,
        purpose: CheckpointPurpose,
    ) -> CheckpointFuture<'a> {
        Box::pin(async move {
            crate::coordination_client::request_authorization_checkpoint(
                &self.coordination_addr,
                &self.auth,
                group_id,
                device_id,
                request_id,
                merkle_root,
                leaf_count,
                purpose,
            )
            .await
        })
    }
}

/// Deterministic `request_id` for a pending batch: SHA-256 of
/// `group_id || device_id || sorted change hashes`. Two calls presented
/// with the EXACT SAME pending set (the common case: an isolate crashed
/// or a response was lost before this device could attach the returned
/// evidence, so the same Changes are still pending on the next attempt)
/// derive the SAME `request_id` and therefore replay the SAME decision
/// — no local persistence
/// of in-flight request state is needed for this property to hold.
///
/// If the pending set has changed (more Changes accumulated locally
/// before the retry), this naturally derives a DIFFERENT `request_id`,
/// which `decideCheckpointIssuance` correctly treats as a new logical
/// request — re-evaluating current writer status, exactly as it should
/// for content the previous attempt never actually covered.
pub fn pending_batch_request_id(group_id: &str, device_id: &str, hashes: &[DeltaHash]) -> String {
    let mut sorted: Vec<&DeltaHash> = hashes.iter().collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    hasher.update(group_id.as_bytes());
    hasher.update([0u8]); // separator -- group_id/device_id are variable-length,
    hasher.update(device_id.as_bytes()); // this hash need not be a signed preimage,
    hasher.update([0u8]); // only collision-resistant for THIS module's own use.
    for hash in sorted {
        hasher.update(hash.0);
    }
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushOutcome {
    /// Nothing was pending; no request was made.
    NothingPending,
    /// A checkpoint was obtained (or replayed), verified against every
    /// Change it covers, and evidence attached for all of them.
    Flushed { batch_size: usize, checkpoint_seq: u64 },
    /// The source refused or was unreachable — e.g. not currently a
    /// writer. The pending set is unchanged; a later call will retry the
    /// SAME batch (assuming nothing new was captured meanwhile) via the
    /// same deterministic `request_id`.
    Refused,
    /// Shutdown began while the batch was being verified. Nothing was
    /// attached; the next flush redoes the same batch.
    Interrupted,
}

/// Everything that can stop a flush from attaching evidence. Distinct
/// from [`FlushOutcome::Refused`] on purpose: a refusal is an EXPECTED
/// outcome (not currently a writer, transient network failure) a caller
/// retries later exactly as-is; [`FlushError::CheckpointDidNotVerify`] is
/// NOT expected under normal operation — it means the coordination plane
/// returned a checkpoint that fails independent verification against the
/// Changes it claims to cover, which should never happen from a
/// correctly-behaving server and is worth surfacing loudly (a bug, a
/// misconfigured authority key, or active tampering) rather than folded
/// into the same quiet-retry path as an ordinary permission refusal.
#[derive(Debug)]
pub enum FlushError {
    Storage(yadorilink_sync_sqlite::SyncSqliteError),
    CheckpointDidNotVerify { change_index: usize, error: CheckpointAdmissionError },
}

impl std::fmt::Display for FlushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "checkpoint flush storage error: {e}"),
            Self::CheckpointDidNotVerify { change_index, error } => write!(
                f,
                "checkpoint returned by coordination plane failed verification for batch leaf \
                 {change_index}: {error:?} -- refusing to attach any evidence from this batch"
            ),
        }
    }
}

impl std::error::Error for FlushError {}

impl From<yadorilink_sync_sqlite::SyncSqliteError> for FlushError {
    fn from(e: yadorilink_sync_sqlite::SyncSqliteError) -> Self {
        Self::Storage(e)
    }
}

#[cfg(test)]
mod tests;
