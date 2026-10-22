//! The synchronous half of native replication over protocol 5: what one
//! side answers when it receives a message, and how a received batch of
//! published deltas is admitted. The async driver
//! ([`crate::native_replication_driver`]) owns streams and the database
//! handle; everything here takes a `&Connection` so no connection is held
//! across an `.await`.
//!
//! Only three message kinds move state: `Summary*` (hints), `FrontierDiff*`
//! (what the requester lacks) and `DeltaBatch` (the deltas themselves, each
//! with its authorization evidence). Protocol 5 has no "request these
//! deltas" message, so the answer to a `FrontierDiffRequest` is a
//! `FrontierDiffResponse` *and* the missing deltas, pushed as `DeltaBatch`
//! messages on streams of their own. The requester acknowledges nothing:
//! admission is idempotent, a delta whose predecessor has not arrived is
//! held and released, and a later summary round confirms convergence.

use rusqlite::Connection;

use yadorilink_replica_domain::authorization_checkpoint::{
    decode_checkpoint, AuthorizationCheckpoint,
};
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::limits::MAX_ENCODED_VERSION_BYTES;
use yadorilink_replica_domain::protocol5::{
    self, DeltaBatchEntry, Message, ProtocolError, RefusalReason, RequestId,
};
use yadorilink_sync_sqlite::native_admission::NativeAdmission;
use yadorilink_sync_sqlite::native_replication::{self, ServeRefusal};
use yadorilink_sync_sqlite::SyncSqliteError;

/// A resolver for a delta's or checkpoint's author key, live.
pub type KeyFor<'a> = dyn Fn(&yadorilink_replica_domain::author::AuthorId) -> Option<ed25519_dalek::VerifyingKey>
    + Send
    + Sync
    + 'a;

/// The group-policy authority key resolver: `(group, signer key id, policy
/// head)` to that authority's verifying key.
pub type GroupAuthorityKeyFor<'a> = dyn Fn(&FolderGroupId, &[u8; 32], &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey>
    + Send
    + Sync
    + 'a;

/// Whether the verified policy chain of a group vouches for a checkpoint's
/// pinned policy point: `(group, checkpoint)`. The chain must hold the pinned
/// head at the pinned sequence and the checkpoint's device must have been a
/// writer under the checkpoint's key there.
pub type GroupPolicyPointFor<'a> =
    dyn Fn(&FolderGroupId, &AuthorizationCheckpoint) -> bool + Send + Sync + 'a;

/// Most entries in one pushed `DeltaBatch`, and the byte budget beside it
/// (protocol 5 bounds a message to 4096 entries and 16 MiB).
const BATCH_ENTRIES: usize = 128;
const BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Most deltas one `FrontierDiffRequest` is answered with; the requester
/// asks again while it is behind.
const SERVE_LIMIT: usize = 2048;
/// Most bytes one answer builds in memory before its first push: the deltas
/// and everything they carry. Beyond it the requester asks again.
const SERVE_BYTES: usize = 16 * 1024 * 1024;

/// What this side knows about the peer it is talking to.
pub struct PeerAccess<'a> {
    /// Whether `group` is hosted here and shared with the peer. A group the
    /// peer may not read is answered `Unauthorized`; a delta batch for one is
    /// ignored.
    pub shares_group: &'a (dyn Fn(&FolderGroupId) -> bool + Sync),
    /// A live lookup of an author's verifying key, for releasing held
    /// deltas.
    pub key_for: &'a KeyFor<'a>,
    /// The group-policy authority key resolver.
    pub authority_key: &'a GroupAuthorityKeyFor<'a>,
    /// Whether the group's policy chain vouches for a checkpoint's pinned
    /// policy point; a checkpoint it does not vouch for authorizes nothing,
    /// whoever signed it.
    pub policy_point: &'a GroupPolicyPointFor<'a>,
}

pub fn new_request_id() -> RequestId {
    RequestId(rand::random())
}

/// A `SummaryRequest` for `group_id`.
pub fn summary_request(group_id: &FolderGroupId) -> Result<(RequestId, Vec<u8>), ProtocolError> {
    let request_id = new_request_id();
    let bytes = protocol5::encode_message(&Message::SummaryRequest {
        request_id,
        group_id: group_id.clone(),
    })?;
    Ok((request_id, bytes))
}

/// A `FrontierDiffRequest` naming everything this replica already has.
pub fn frontier_diff_request(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<(RequestId, Vec<u8>), ReplicationError> {
    let request_id = new_request_id();
    let since = native_replication::frontier_since(conn, group_id)?;
    let bytes = protocol5::encode_message(&Message::FrontierDiffRequest {
        request_id,
        group_id: group_id.clone(),
        since,
    })?;
    Ok((request_id, bytes))
}

/// Whether a received `SummaryResponse` describes exactly this replica's
/// live state. Anything else is a hint that a frontier diff may find work.
pub fn summary_matches(
    conn: &Connection,
    group_id: &FolderGroupId,
    response: &Message,
) -> Result<bool, ReplicationError> {
    let Message::SummaryResponse { namespace_root, author_state_root, .. } = response else {
        return Ok(false);
    };
    let local = native_replication::summary_roots(conn, group_id)?;
    tracing::debug!(
        group = %group_id.0,
        namespace_equal = local.namespace_root == *namespace_root,
        author_state_equal = local.author_state_root == *author_state_root,
        "native replication: compared summaries"
    );
    Ok(local.namespace_root == *namespace_root && local.author_state_root == *author_state_root)
}

/// What answering one message produced.
#[derive(Debug, Default)]
pub struct Answer {
    /// The reply for the same stream (a summary, a frontier diff or a
    /// refusal).
    pub reply: Option<Vec<u8>>,
    /// `DeltaBatch` messages to push, each on a stream of its own.
    pub pushes: Vec<Vec<u8>>,
    /// The group the pushes are for, checked again before each is sent.
    pub push_group: Option<FolderGroupId>,
    /// Set when the message was a `DeltaBatch` that was admitted here.
    pub ingested: Option<IngestReport>,
    /// Set when the peer asked for this device's state sealed for recovery;
    /// answering it needs the network (the authority), so the driver does it.
    pub recovery_request: Option<(RequestId, FolderGroupId)>,
    /// Set when the message was one chunk of a recovery bundle the peer is
    /// sending; the driver assembles the chunks.
    pub recovery_chunk: Option<RecoveryChunkIn>,
    /// Set when the peer, having accepted a recovery request, could not seal its state after
    /// all: the request will not be answered, so the next round may ask again.
    pub recovery_refused: Option<RequestId>,
}

/// One received chunk of a recovery bundle.
#[derive(Debug)]
pub struct RecoveryChunkIn {
    pub request_id: RequestId,
    pub group_id: FolderGroupId,
    pub index: u32,
    pub count: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum ReplicationError {
    Storage(yadorilink_sync_sqlite::SyncSqliteError),
    Protocol(ProtocolError),
}

impl std::fmt::Display for ReplicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "native replication storage error: {error}"),
            Self::Protocol(error) => write!(f, "native replication protocol error: {error}"),
        }
    }
}

impl std::error::Error for ReplicationError {}

impl From<yadorilink_sync_sqlite::SyncSqliteError> for ReplicationError {
    fn from(error: yadorilink_sync_sqlite::SyncSqliteError) -> Self {
        Self::Storage(error)
    }
}

impl From<ProtocolError> for ReplicationError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Whether answering `message` writes to the database. Everything but a
/// delta batch only reads, so the driver answers those from a read snapshot
/// and keeps the writer gate for the batches that need it.
pub fn answer_writes(message: &Message) -> bool {
    matches!(message, Message::DeltaBatch { .. })
}

/// Answers one received protocol 5 message.
pub fn answer(
    conn: &Connection,
    peer: &PeerAccess<'_>,
    bytes: &[u8],
) -> Result<Answer, ReplicationError> {
    answer_message(conn, peer, protocol5::decode_message(bytes)?)
}

/// Answers one decoded message. `conn` is only written to when
/// [`answer_writes`] says so.
pub fn answer_message(
    conn: &Connection,
    peer: &PeerAccess<'_>,
    message: Message,
) -> Result<Answer, ReplicationError> {
    let refuse = |request_id, reason| -> Result<Answer, ReplicationError> {
        Ok(Answer {
            reply: Some(protocol5::encode_message(&Message::Refused { request_id, reason })?),
            ..Answer::default()
        })
    };
    match message {
        Message::SummaryRequest { request_id, group_id } => {
            if !(peer.shares_group)(&group_id) {
                return refuse(request_id, RefusalReason::Unauthorized);
            }
            let roots = native_replication::summary_roots(conn, &group_id)?;
            Ok(Answer {
                reply: Some(protocol5::encode_message(&Message::SummaryResponse {
                    request_id,
                    group_id,
                    namespace_root: roots.namespace_root,
                    author_state_root: roots.author_state_root,
                })?),
                ..Answer::default()
            })
        }
        Message::FrontierDiffRequest { request_id, group_id, since } => {
            if !(peer.shares_group)(&group_id) {
                return refuse(request_id, RefusalReason::Unauthorized);
            }
            let served = match native_replication::deltas_to_serve_within(
                conn,
                &group_id,
                &since,
                SERVE_LIMIT,
                SERVE_BYTES,
            )? {
                Ok(served) => served,
                Err(ServeRefusal::BodyUnavailable { .. }) => {
                    return refuse(request_id, RefusalReason::NotFound)
                }
                Err(ServeRefusal::HistoryTruncated { checkpoint_id, frontier_root, .. }) => {
                    return refuse(
                        request_id,
                        RefusalReason::HistoryTruncated { checkpoint_id, frontier_root },
                    )
                }
            };
            let entries = native_replication::frontier_newer_than(conn, &group_id, &since)?;
            Ok(Answer {
                reply: Some(protocol5::encode_message(&Message::FrontierDiffResponse {
                    request_id,
                    entries,
                })?),
                pushes: delta_batches(&group_id, served.entries)?,
                push_group: Some(group_id),
                ..Answer::default()
            })
        }
        Message::DeltaBatch { group_id, entries } => {
            if !(peer.shares_group)(&group_id) {
                return Ok(Answer::default());
            }
            Ok(Answer {
                ingested: Some(ingest(conn, peer, &group_id, &entries)),
                ..Answer::default()
            })
        }
        Message::RecoveryRequest { request_id, group_id } => {
            if !(peer.shares_group)(&group_id) {
                return refuse(request_id, RefusalReason::Unauthorized);
            }
            Ok(Answer { recovery_request: Some((request_id, group_id)), ..Answer::default() })
        }
        Message::RecoveryChunk { request_id, group_id, index, count, bytes } => {
            if !(peer.shares_group)(&group_id) {
                return Ok(Answer::default());
            }
            Ok(Answer {
                recovery_chunk: Some(RecoveryChunkIn { request_id, group_id, index, count, bytes }),
                ..Answer::default()
            })
        }
        // A response or a push this session does not act on.
        Message::SummaryResponse { .. } | Message::FrontierDiffResponse { .. } => {
            Ok(Answer::default())
        }
        Message::Refused { request_id, .. } => {
            Ok(Answer { recovery_refused: Some(request_id), ..Answer::default() })
        }
    }
}

/// Bytes an entry or a carried version costs beyond its payload (length
/// prefixes and the fixed hash and signature fields).
const ENTRY_OVERHEAD: usize = 160;
const VERSION_OVERHEAD: usize = 16;

fn entry_base_bytes(entry: &DeltaBatchEntry) -> usize {
    entry.encoded_delta.len()
        + entry.checkpoint_encoded.len()
        + entry.proof_encoded.len()
        + ENTRY_OVERHEAD
}

/// `entry` as one or more entries that each fit the byte budget on their own.
/// A delta whose carried versions are larger than a batch is sent as several
/// entries naming the same delta, the versions spread across them: admission of
/// a delta already admitted or held stores the versions its entry carries, so
/// the receiver ends with all of them.
///
/// A delta carrying a version over [`MAX_ENCODED_VERSION_BYTES`] cannot be
/// delivered whole: sent without that version the receiver would admit the
/// head, find its version missing and ask for the delta again, forever. Such a
/// delta is not sent at all (and an error is logged); no valid version can be
/// that large, since authoring and admission refuse it.
fn split_entry(mut entry: DeltaBatchEntry) -> Vec<DeltaBatchEntry> {
    if let Some(oversized) =
        entry.versions.iter().map(Vec::len).find(|len| *len > MAX_ENCODED_VERSION_BYTES)
    {
        tracing::error!(
            version_bytes = oversized,
            max = MAX_ENCODED_VERSION_BYTES,
            "native replication: a delta names a file version too large to send; not sending it"
        );
        return Vec::new();
    }
    let base = entry_base_bytes(&entry);
    let carried: usize = entry.versions.iter().map(|v| v.len() + VERSION_OVERHEAD).sum();
    if base + carried <= BATCH_BYTES && entry.versions.len() <= protocol5::MAX_VERSIONS_PER_ENTRY {
        return vec![entry];
    }
    let versions = std::mem::take(&mut entry.versions);
    let mut pieces = Vec::new();
    let mut current: Vec<Vec<u8>> = Vec::new();
    let mut bytes = base;
    for version in versions {
        let size = version.len() + VERSION_OVERHEAD;
        if !current.is_empty()
            && (bytes + size > BATCH_BYTES || current.len() >= protocol5::MAX_VERSIONS_PER_ENTRY)
        {
            pieces
                .push(DeltaBatchEntry { versions: std::mem::take(&mut current), ..entry.clone() });
            bytes = base;
        }
        bytes += size;
        current.push(version);
    }
    pieces.push(DeltaBatchEntry { versions: current, ..entry });
    pieces
}

/// Encodes one batch. A batch of a single entry that still exceeds the
/// protocol's message limit cannot be sent at all (its delta and proof alone
/// are that large); it is dropped and reported, instead of failing the whole
/// answer on every retry.
fn encode_batch(
    group_id: &FolderGroupId,
    entries: Vec<DeltaBatchEntry>,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    let single = entries.len() == 1;
    match protocol5::encode_message(&Message::DeltaBatch { group_id: group_id.clone(), entries }) {
        Err(ProtocolError::MessageTooLarge { declared, max }) if single => {
            tracing::warn!(declared, max, "native replication: a delta is too large to send");
            Ok(None)
        }
        other => other.map(Some),
    }
}

/// `entries` cut into `DeltaBatch` messages within the entry and byte
/// budgets, order preserved. The budget counts everything an entry encodes,
/// its carried versions included, so every message is within the protocol's
/// message limit.
pub fn delta_batches(
    group_id: &FolderGroupId,
    entries: Vec<DeltaBatchEntry>,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let mut batches = Vec::new();
    let mut current: Vec<DeltaBatchEntry> = Vec::new();
    let mut bytes = 0usize;
    for entry in entries.into_iter().flat_map(split_entry) {
        let size = entry_base_bytes(&entry)
            + entry.versions.iter().map(|v| v.len() + VERSION_OVERHEAD).sum::<usize>();
        if !current.is_empty() && (current.len() >= BATCH_ENTRIES || bytes + size > BATCH_BYTES) {
            batches.extend(encode_batch(group_id, std::mem::take(&mut current))?);
            bytes = 0;
        }
        bytes += size;
        current.push(entry);
    }
    if !current.is_empty() {
        batches.extend(encode_batch(group_id, current)?);
    }
    Ok(batches)
}

/// The outcome of admitting one received batch.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct IngestReport {
    /// The group the batch was for.
    pub group: String,
    /// Deltas newly applied, including those an admission released.
    pub admitted: usize,
    pub duplicates: usize,
    /// Held for a predecessor that has not arrived.
    pub held: usize,
    /// Refused: bad signature, unauthorized, equivocation, invalid path...
    pub rejected: Vec<String>,
}

/// Stores the content versions a batch entry carried, inside the admission's
/// own transaction.
type StoreVersions =
    dyn Fn(&Connection, &FolderGroupId, &[u8], &[Vec<u8>]) -> Result<usize, SyncSqliteError>;

fn ingest(
    conn: &Connection,
    peer: &PeerAccess<'_>,
    group_id: &FolderGroupId,
    entries: &[DeltaBatchEntry],
) -> IngestReport {
    ingest_with(conn, peer, group_id, entries, &native_replication::store_carried_versions)
}

/// Admits each entry and stores the versions it carries in ONE transaction: a
/// head must never be committed without the versions it names, because
/// reconciliation compares native roots and would then consider the replica
/// complete while materialization of that head fails for good. An entry whose
/// versions cannot be stored is rolled back whole, leaving the delta missing
/// so a later round asks for it again.
fn ingest_with(
    conn: &Connection,
    peer: &PeerAccess<'_>,
    group_id: &FolderGroupId,
    entries: &[DeltaBatchEntry],
    store_versions: &StoreVersions,
) -> IngestReport {
    let mut report = IngestReport { group: group_id.0.clone(), ..IngestReport::default() };
    for entry in entries {
        let proof = match protocol5::decode_proof(&entry.proof_encoded) {
            Ok(proof) => proof,
            Err(error) => {
                report.rejected.push(format!("undecodable proof: {error}"));
                continue;
            }
        };
        // The authority's signature alone does not say the checkpoint's policy
        // point is one the verified chain holds, nor that the device was a
        // writer there. A checkpoint that does not decode is left to admission
        // to refuse.
        if let Ok(checkpoint) = decode_checkpoint(&entry.checkpoint_encoded) {
            if !(peer.policy_point)(group_id, &checkpoint) {
                report.rejected.push(format!(
                    "checkpoint policy point {} is not one the group's policy vouches for",
                    checkpoint.policy_seq
                ));
                continue;
            }
        }
        let tx = match conn.unchecked_transaction() {
            Ok(tx) => tx,
            Err(error) => {
                report.rejected.push(format!("storage: {error}"));
                continue;
            }
        };
        let admission =
            yadorilink_sync_sqlite::native_admission::admit_published_native_delta_on_conn(
                &tx,
                group_id,
                &entry.encoded_delta,
                &entry.checkpoint_hash,
                &entry.checkpoint_encoded,
                &entry.checkpoint_signature,
                &entry.author_signing_public_key,
                &proof,
                peer.key_for,
                |key_id, policy_head| (peer.authority_key)(group_id, key_id, policy_head),
            );
        let admission = match admission {
            Ok(admission) => admission,
            Err(error) => {
                drop(tx);
                report.rejected.push(format!("storage: {error}"));
                continue;
            }
        };
        // A delta that is admitted, already admitted, or held for a predecessor
        // is verified; its versions are needed as soon as it is (or is later
        // released) and no later message re-sends them.
        let verified = matches!(
            admission,
            NativeAdmission::Admitted { .. }
                | NativeAdmission::Duplicate
                | NativeAdmission::Held { .. }
        );
        if verified {
            if let Err(error) = store_versions(&tx, group_id, &entry.encoded_delta, &entry.versions)
            {
                // Dropping `tx` rolls the admission back with the versions.
                drop(tx);
                report.rejected.push(format!("versions not stored: {error}"));
                continue;
            }
        }
        if let Err(error) = tx.commit() {
            report.rejected.push(format!("storage: {error}"));
            continue;
        }
        match admission {
            NativeAdmission::Admitted { released, .. } => {
                report.admitted += 1 + released.len();
            }
            NativeAdmission::Duplicate => report.duplicates += 1,
            NativeAdmission::Held { .. } => report.held += 1,
            other => report.rejected.push(format!("{other:?}")),
        }
    }
    report
}

#[cfg(test)]
pub(crate) mod tests;
