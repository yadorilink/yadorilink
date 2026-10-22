//! The storage side of native replication over protocol 5: what this
//! replica tells a peer (`Summary`, its frontier) and which of its
//! published deltas a peer is missing (`DeltaBatch`). No transport and no
//! admission here: the daemon session drives these and feeds received
//! batches to [`crate::native_admission::admit_published_native_delta`].
//!
//! A delta is sendable only when it carries authorization evidence
//! ([`crate::native_publication`]); an author's unpublished tail is not
//! served, and serving an author stops at its first unpublished seq so a
//! receiver never sees a gap it cannot fill.

use rusqlite::Connection;

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId};
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::protocol5::{DeltaBatchEntry, FrontierEntry};
use yadorilink_replica_domain::signed_delta::NativeDelta;

use crate::error::SyncSqliteError;
use crate::{native_publication, native_store};

/// The two roots `SummaryResponse` carries. Hints only: a peer's state
/// advances by verified deltas, never by joining a claimed root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SummaryRoots {
    pub namespace_root: [u8; 32],
    pub author_state_root: [u8; 32],
}

/// This replica's live roots (not a stored checkpoint's, which may be stale).
///
/// Computing them rebuilds the whole namespace trie, so a group whose state is
/// unchanged since the last call is answered from a memo keyed by the group's
/// stored state token (see [`crate::native_summary_cache`]): an idle group costs
/// one indexed read.
pub fn summary_roots(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<SummaryRoots, SyncSqliteError> {
    crate::native_summary_cache::summary_roots(conn, group_id)
}

/// Every author this replica has a delta from, with its position: the
/// `since` of a `FrontierDiffRequest` (tips omitted) or the entries of a
/// response (tips included).
pub fn frontier_entries(
    conn: &Connection,
    group_id: &FolderGroupId,
    with_tips: bool,
) -> Result<Vec<FrontierEntry>, SyncSqliteError> {
    Ok(native_store::load_frontier(conn, group_id)?
        .into_iter()
        .map(|(author, entry)| FrontierEntry {
            author,
            seq: entry.seq,
            tip: with_tips.then_some(entry.tip),
        })
        .collect())
}

/// The authors with a live head whose content version this replica does not
/// hold, each with the lowest seq among those heads. Replication compares
/// native roots, which do not say whether the versions the heads name are
/// stored, so a head whose version never arrived is invisible to a summary
/// comparison; this is how it is found again.
pub fn unresolved_head_positions(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Vec<(AuthorId, AuthorSeq)>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT h.author, h.incarnation, MIN(h.seq) FROM native_heads h \
         WHERE h.group_id = ?1 AND NOT EXISTS ( \
             SELECT 1 FROM file_versions v \
             WHERE v.group_id = h.group_id AND v.version_hash = h.version) \
         GROUP BY h.author, h.incarnation",
    )?;
    let rows = stmt.query_map([group_id.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?))
    })?;
    let mut positions = Vec::new();
    for row in rows {
        let (device, incarnation, seq) = row?;
        let incarnation: [u8; 16] = incarnation.as_slice().try_into().map_err(|_| {
            SyncSqliteError::CorruptState("a native head's incarnation is not 16 bytes".into())
        })?;
        positions.push((
            AuthorId {
                device: yadorilink_replica_domain::ids::DeviceId(device),
                incarnation: yadorilink_replica_domain::author::IncarnationId(incarnation),
            },
            AuthorSeq(seq as u64),
        ));
    }
    Ok(positions)
}

/// The `since` of a `FrontierDiffRequest`: every author this replica has a
/// delta from, at its position, except that an author with a head whose
/// version is not stored is named one seq before that head, so the peer
/// serves the delta again (admission of a delta already held stores the
/// versions it carries) instead of this replica believing it is complete.
pub fn frontier_since(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Vec<FrontierEntry>, SyncSqliteError> {
    let unresolved: std::collections::HashMap<AuthorId, u64> =
        unresolved_head_positions(conn, group_id)?
            .into_iter()
            .map(|(author, seq)| (author, seq.get()))
            .collect();
    Ok(frontier_entries(conn, group_id, false)?
        .into_iter()
        .filter_map(|mut entry| {
            if let Some(lowest) = unresolved.get(&entry.author) {
                let seq = lowest.saturating_sub(1).min(entry.seq.get());
                if seq == 0 {
                    return None;
                }
                entry.seq = AuthorSeq(seq);
            }
            Some(entry)
        })
        .collect())
}

/// A requester's `since` positions, indexed once so that looking up each local
/// author is constant time: `since` is peer-supplied and may hold tens of
/// thousands of entries, which a per-author linear scan would multiply by the
/// number of local authors while the answer is being built. When an author is
/// named more than once the first entry counts, as a front-to-back search
/// would have it.
struct SinceIndex<'a, K> {
    positions: std::collections::HashMap<&'a K, u64>,
}

impl<'a, K: std::hash::Hash + Eq> SinceIndex<'a, K> {
    fn new(since: impl IntoIterator<Item = (&'a K, u64)>) -> Self {
        let mut positions = std::collections::HashMap::new();
        for (author, seq) in since {
            positions.entry(author).or_insert(seq);
        }
        Self { positions }
    }

    /// The position named for `author`, 0 when it names none.
    fn position(&self, author: &K) -> u64 {
        self.positions.get(author).copied().unwrap_or(0)
    }
}

fn since_index(since: &[FrontierEntry]) -> SinceIndex<'_, AuthorId> {
    SinceIndex::new(since.iter().map(|entry| (&entry.author, entry.seq.get())))
}

/// This replica's entries strictly newer than `since`, tips included.
pub fn frontier_newer_than(
    conn: &Connection,
    group_id: &FolderGroupId,
    since: &[FrontierEntry],
) -> Result<Vec<FrontierEntry>, SyncSqliteError> {
    let since = since_index(since);
    Ok(frontier_entries(conn, group_id, true)?
        .into_iter()
        .filter(|entry| entry.seq.get() > since.position(&entry.author))
        .collect())
}

/// Why a range could not be served.
#[derive(Debug, PartialEq, Eq)]
pub enum ServeRefusal {
    /// A delta in a requested range is no longer held here, so the requester
    /// needs a recovery bundle, not this range.
    BodyUnavailable { author: AuthorId, seq: AuthorSeq },
    /// The range starts below the history floor this replica adopted and the
    /// body is gone: what it retains begins at `checkpoint_id`, whose frontier
    /// builds `frontier_root`.
    HistoryTruncated {
        author: AuthorId,
        seq: AuthorSeq,
        checkpoint_id: [u8; 32],
        frontier_root: [u8; 32],
    },
}

/// What [`deltas_to_serve`] found.
#[derive(Debug, Default)]
pub struct Served {
    /// Published deltas the requester lacks, per author in seq order.
    pub entries: Vec<DeltaBatchEntry>,
    /// Authors whose tail beyond the last served seq is unpublished here.
    pub unpublished_tail: Vec<AuthorId>,
}

/// At most `limit` published deltas in `(since, tip]` over the authors, in
/// seq order per author (the requester asks again for the rest, so one
/// answer never builds a whole history). An author with an unpublished delta in its range stops there
/// (later seqs would leave a gap); [`Served::unpublished_tail`] names it.
pub fn deltas_to_serve(
    conn: &Connection,
    group_id: &FolderGroupId,
    since: &[FrontierEntry],
    limit: usize,
) -> Result<Result<Served, ServeRefusal>, SyncSqliteError> {
    deltas_to_serve_within(conn, group_id, since, limit, usize::MAX)
}

/// [`deltas_to_serve`] that also stops once the entries built total
/// `max_bytes` (a delta, its checkpoint, its proof and the versions it
/// carries). The entry that crosses the budget is still served, so an answer
/// always makes progress; the requester asks again for the rest. The count
/// limit alone does not bound memory, because one delta can carry versions of
/// any size up to the protocol's per-version limit.
pub fn deltas_to_serve_within(
    conn: &Connection,
    group_id: &FolderGroupId,
    since: &[FrontierEntry],
    limit: usize,
    max_bytes: usize,
) -> Result<Result<Served, ServeRefusal>, SyncSqliteError> {
    let mut served = Served::default();
    let mut bytes = 0usize;
    let since = since_index(since);
    let withheld_device = withheld_own_device(conn, group_id)?;
    for entry in native_store::load_frontier(conn, group_id)? {
        if served.entries.len() >= limit || bytes >= max_bytes {
            break;
        }
        let (author, position) = entry;
        if withheld_device.as_ref() == Some(&author.device) {
            continue;
        }
        let from = since.position(&author);
        if position.seq.get() <= from {
            continue;
        }
        for seq in (from + 1)..=position.seq.get() {
            if served.entries.len() >= limit || bytes >= max_bytes {
                break;
            }
            let seq = AuthorSeq(seq);
            let Some(body) = native_store::fetch_delta_body(conn, group_id, &author, seq)? else {
                return Ok(Err(missing_body_refusal(conn, group_id, author, seq)?));
            };
            let delta = NativeDelta::from_wire_bytes(&body).map_err(|error| {
                SyncSqliteError::CorruptState(format!("stored delta undecodable: {error}"))
            })?;
            let delta_hash: DeltaHash = delta.delta_hash();
            let Some((checkpoint_hash, proof_encoded)) =
                native_publication::evidence_for(conn, &delta_hash)?
            else {
                served.unpublished_tail.push(author.clone());
                break;
            };
            let Some((checkpoint_encoded, signature, author_signing_public_key)) =
                native_publication::checkpoint_envelope(conn, &checkpoint_hash)?
            else {
                return Err(SyncSqliteError::CorruptState(
                    "a published native delta's checkpoint envelope is missing".into(),
                ));
            };
            let checkpoint_signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
                SyncSqliteError::CorruptState(
                    "a stored checkpoint signature is not 64 bytes".into(),
                )
            })?;
            let versions = carried_versions(conn, group_id, &delta)?;
            bytes = bytes.saturating_add(
                body.len()
                    + checkpoint_encoded.len()
                    + proof_encoded.len()
                    + versions.iter().map(Vec::len).sum::<usize>(),
            );
            served.entries.push(DeltaBatchEntry {
                encoded_delta: body,
                checkpoint_hash,
                checkpoint_encoded,
                checkpoint_signature,
                author_signing_public_key,
                proof_encoded,
                versions,
            });
        }
    }
    Ok(Ok(served))
}

/// Why the body of `author`'s delta at `seq` cannot be served: at or below the history
/// floor it was dropped legitimately and the floor is named, anywhere else it is
/// simply not held.
fn missing_body_refusal(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: AuthorId,
    seq: AuthorSeq,
) -> Result<ServeRefusal, SyncSqliteError> {
    let floor = crate::native_history_floor::history_floor(conn, group_id)?;
    let entry = crate::native_history_floor::floor_entry(conn, group_id, &author)?;
    Ok(match (floor, entry) {
        (Some(floor), Some(entry)) if seq <= entry.seq => ServeRefusal::HistoryTruncated {
            author,
            seq,
            checkpoint_id: floor.checkpoint_id,
            frontier_root: floor.floor_frontier_root,
        },
        _ => ServeRefusal::BodyUnavailable { author, seq },
    })
}

/// The published deltas among `hashes`, as batch entries; a hash that is
/// unknown, truncated or unpublished is skipped (it is not sendable yet).
pub fn entries_for_hashes(
    conn: &Connection,
    group_id: &FolderGroupId,
    hashes: &[DeltaHash],
) -> Result<Vec<DeltaBatchEntry>, SyncSqliteError> {
    let mut entries = Vec::new();
    let withheld_device = withheld_own_device(conn, group_id)?;
    for hash in hashes {
        let Some(body) = native_store::fetch_delta_body_by_hash(conn, group_id, hash)? else {
            continue;
        };
        let Some((checkpoint_hash, proof_encoded)) = native_publication::evidence_for(conn, hash)?
        else {
            continue;
        };
        let Some((checkpoint_encoded, signature, author_signing_public_key)) =
            native_publication::checkpoint_envelope(conn, &checkpoint_hash)?
        else {
            continue;
        };
        let Ok(checkpoint_signature) = <[u8; 64]>::try_from(signature.as_slice()) else { continue };
        let Ok(delta) = NativeDelta::from_wire_bytes(&body) else { continue };
        if withheld_device.as_ref() == Some(&delta.author.device) {
            continue;
        }
        entries.push(DeltaBatchEntry {
            encoded_delta: body,
            checkpoint_hash,
            checkpoint_encoded,
            checkpoint_signature,
            author_signing_public_key,
            proof_encoded,
            versions: carried_versions(conn, group_id, &delta)?,
        });
    }
    Ok(entries)
}

/// This device, while a rebootstrap of `group_id` withholds its own deltas from peers (see
/// [`crate::native_rebootstrap::own_deltas_withheld`]); `None` otherwise.
fn withheld_own_device(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Option<yadorilink_replica_domain::ids::DeviceId>, SyncSqliteError> {
    if !crate::native_rebootstrap::own_deltas_withheld(conn, group_id.as_str())? {
        return Ok(None);
    }
    Ok(Some(crate::author_incarnation::current_author(conn)?.device))
}

/// The content versions `delta`'s puts name that this replica holds, as
/// canonical encodings: what a receiver needs to resolve the heads the delta
/// installs (a version's blocks are not in the delta, only its hash).
fn carried_versions(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
) -> Result<Vec<Vec<u8>>, SyncSqliteError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut versions = Vec::new();
    for op in &delta.ops {
        let Some(put) = &op.put else { continue };
        if !seen.insert(put.version) {
            continue;
        }
        if let Some(version) =
            crate::dag_store::get_file_version(conn, group_id.as_str(), &put.version)?
        {
            versions.push(version.canonical_encoding());
        }
    }
    Ok(versions)
}

/// Stores the versions a delta batch entry carried, for a delta that was
/// admitted: only versions the delta's own puts name, each verified against its
/// own hash. A version that is not one of them, or does not verify, is dropped
/// (it says nothing about the delta); a version that verifies but cannot be
/// written is an error.
pub fn store_carried_versions(
    conn: &Connection,
    group_id: &FolderGroupId,
    encoded_delta: &[u8],
    versions: &[Vec<u8>],
) -> Result<usize, SyncSqliteError> {
    if versions.is_empty() {
        return Ok(0);
    }
    let Ok(delta) = NativeDelta::from_wire_bytes(encoded_delta) else { return Ok(0) };
    let named: std::collections::BTreeSet<_> =
        delta.ops.iter().filter_map(|op| op.put.as_ref().map(|put| put.version)).collect();
    let mut stored = 0;
    for encoded in versions {
        let Ok(version) =
            yadorilink_replica_domain::file::FileVersion::from_canonical_encoding(encoded)
        else {
            continue;
        };
        if !named.contains(&version.version_hash) {
            continue;
        }
        // A write that fails is an error: the delta is admitted and its head
        // would then name content this replica cannot resolve.
        crate::dag_store::put_file_version(conn, group_id.as_str(), &version)?;
        stored += 1;
    }
    Ok(stored)
}

#[cfg(test)]
mod tests;
