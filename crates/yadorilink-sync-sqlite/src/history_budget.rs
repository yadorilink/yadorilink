//! The byte budget of the kept version history.
//!
//! The retention rule keeps a replaced version for 10 generations or 30 days; this adds a third
//! bound on bytes. The *kept-history bytes* of a device are the summed size of the unique blocks
//! that only non-current versions (`superseded` / `trashed`, in any folder) name: a block a
//! current row, a native head, a recovery item or a custody lease also names costs history
//! nothing, because dropping the version would not free it, and a block several kept versions
//! share counts once.
//!
//! When those bytes exceed the budget, the oldest kept versions are dropped (rows only, in one
//! transaction, each recorded in `history_freed`) until they fit again; the garbage collector
//! frees the bytes afterwards, as it does for every dropped row. A version a handoff lease
//! pins is never dropped and does not count. The sweep takes no guard and reads no block.

use std::collections::{HashMap, HashSet};

use yadorilink_replica_domain::file::BlockInfo;

use crate::error::SyncSqliteError;
use crate::file_index::FileIndexRepository;
use crate::history_freed::FreedReason;

/// A kept version that may be dropped.
struct Candidate {
    group_id: String,
    path: String,
    version_seq: i64,
    /// When it stopped being current (its successor's admission); an unknown time sorts oldest.
    anchor: i64,
    /// Its unique blocks with their sizes.
    blocks: Vec<(String, u64)>,
}

/// The versions to drop so that `candidates`' unique bytes (blocks not in `protected`) fit in
/// `budget_bytes`, oldest first. A version whose blocks are all held by something that stays
/// (a current version, a native head, a lease) is not dropped: it frees nothing.
fn choose_drops(
    mut candidates: Vec<Candidate>,
    protected: &HashSet<String>,
    budget_bytes: u64,
) -> Vec<Candidate> {
    let mut holders: HashMap<&str, usize> = HashMap::new();
    let mut size_of: HashMap<&str, u64> = HashMap::new();
    for c in &candidates {
        for (hash, size) in &c.blocks {
            if !protected.contains(hash) {
                *holders.entry(hash.as_str()).or_default() += 1;
                size_of.insert(hash.as_str(), *size);
            }
        }
    }
    let mut total: u64 = holders.keys().map(|h| size_of[h]).sum();
    if total <= budget_bytes {
        return Vec::new();
    }
    // Oldest first; the sequence breaks ties so the order is total.
    let order: Vec<usize> = {
        let mut idx: Vec<usize> = (0..candidates.len()).collect();
        idx.sort_by(|&a, &b| {
            let (a, b) = (&candidates[a], &candidates[b]);
            (a.anchor, &a.group_id, &a.path, a.version_seq).cmp(&(
                b.anchor,
                &b.group_id,
                &b.path,
                b.version_seq,
            ))
        });
        idx
    };
    let mut dropped: Vec<usize> = Vec::new();
    let mut remaining: HashMap<String, usize> =
        holders.iter().map(|(h, n)| ((*h).to_owned(), *n)).collect();
    let sizes: HashMap<String, u64> = size_of.iter().map(|(h, s)| ((*h).to_owned(), *s)).collect();
    for i in order {
        if total <= budget_bytes {
            break;
        }
        // A version none of whose blocks is history's own (all are held by a current version
        // or another protection) frees nothing by going.
        if !candidates[i].blocks.iter().any(|(hash, _)| remaining.contains_key(hash)) {
            continue;
        }
        for (hash, _) in &candidates[i].blocks {
            if let Some(n) = remaining.get_mut(hash) {
                *n -= 1;
                if *n == 0 {
                    total -= sizes[hash];
                }
            }
        }
        dropped.push(i);
    }
    let mut keep: Vec<Option<Candidate>> = candidates.drain(..).map(Some).collect();
    dropped.into_iter().filter_map(|i| keep[i].take()).collect()
}

impl FileIndexRepository {
    /// Drops the oldest kept versions of every folder until the kept-history bytes fit
    /// `budget_bytes`, and returns how many it dropped. The versions a handoff lease protects
    /// are read in the same transaction that chooses and deletes, so a lease granted meanwhile
    /// is never missed.
    pub fn trim_history_over_budget(
        &self,
        budget_bytes: u64,
        now_unix_nanos: i64,
    ) -> Result<usize, SyncSqliteError> {
        self.database().write::<_, SyncSqliteError>(|conn| {
            let tx = conn.transaction()?;
            let dropped = trim_in_tx(&tx, budget_bytes, now_unix_nanos)?;
            tx.commit()?;
            Ok(dropped)
        })
    }
}

impl FileIndexRepository {
    /// The kept-history bytes of this device (see the module doc): the figure the byte budget
    /// bounds, so a status can show it beside the budget. A version a handoff lease pins does
    /// not count, as in the trim.
    pub fn kept_history_bytes(&self, now_unix_nanos: i64) -> Result<u64, SyncSqliteError> {
        self.database().read::<_, SyncSqliteError>(|conn| {
            let (candidates, protected) = candidates_and_protected(conn, now_unix_nanos)?;
            Ok(kept_bytes_in(&candidates, &protected))
        })
    }
}

fn unique_blocks(blocks_json: &str) -> Result<Vec<(String, u64)>, SyncSqliteError> {
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json)?;
    let mut seen = HashSet::new();
    Ok(blocks
        .into_iter()
        .map(|b| (hex::encode(b.hash), u64::from(b.size)))
        .filter(|(hash, _)| seen.insert(hash.clone()))
        .collect())
}

/// The kept versions that may be dropped, and the blocks something that stays also names, read
/// on `tx` so both come from one snapshot.
fn candidates_and_protected(
    tx: &rusqlite::Connection,
    now_unix_nanos: i64,
) -> Result<(Vec<Candidate>, HashSet<String>), SyncSqliteError> {
    let pinned =
        crate::handoff_lease::leased_version_keys_all_groups(tx, now_unix_nanos / 1_000_000_000)?;
    let mut protected = crate::dag_store::native_head_retained_block_hashes_all_groups(tx)?;
    protected.extend(crate::native_recovery_items::retained_block_hashes_all_groups(tx)?);
    protected.extend(crate::remote_custody_lease::retained_block_hashes_all_groups(tx)?);
    let mut candidates = Vec::new();
    {
        let mut stmt = tx.prepare(
            "SELECT group_id, path, version_seq, state, blocks_json, admitted_at_unix_nanos, \
                    next_admitted FROM (
                 SELECT group_id, path, version_seq, state, blocks_json, deleted,
                        admitted_at_unix_nanos,
                        LEAD(admitted_at_unix_nanos) OVER (
                            PARTITION BY group_id, path ORDER BY version_seq
                        ) AS next_admitted
                 FROM files
             ) WHERE deleted = 0",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let group_id: String = r.get(0)?;
            let path: String = r.get(1)?;
            let version_seq: i64 = r.get(2)?;
            let state: String = r.get(3)?;
            let blocks = unique_blocks(&r.get::<_, String>(4)?)?;
            let is_pinned = pinned
                .get(&group_id)
                .is_some_and(|keys| keys.contains(&(path.clone(), version_seq)));
            if state == "current" || is_pinned {
                protected.extend(blocks.into_iter().map(|(hash, _)| hash));
                continue;
            }
            let own: Option<i64> = r.get(5)?;
            let next: Option<i64> = r.get(6)?;
            let anchor = match (own, next) {
                (Some(own), Some(next)) => own.max(next),
                (Some(own), None) => own,
                (None, _) => i64::MIN,
            };
            candidates.push(Candidate { group_id, path, version_seq, anchor, blocks });
        }
    }
    Ok((candidates, protected))
}

/// The bytes the kept history holds that nothing current also holds: what the budget bounds.
fn kept_bytes_in(candidates: &[Candidate], protected: &HashSet<String>) -> u64 {
    let mut unique: HashMap<&str, u64> = HashMap::new();
    for (hash, size) in candidates.iter().flat_map(|c| &c.blocks) {
        if !protected.contains(hash) {
            unique.insert(hash.as_str(), *size);
        }
    }
    unique.values().sum()
}

pub(crate) fn trim_in_tx(
    tx: &rusqlite::Connection,
    budget_bytes: u64,
    now_unix_nanos: i64,
) -> Result<usize, SyncSqliteError> {
    let (candidates, protected) = candidates_and_protected(tx, now_unix_nanos)?;
    let drops = choose_drops(candidates, &protected, budget_bytes);
    let mut by_group: HashMap<String, Vec<(String, i64)>> = HashMap::new();
    for c in &drops {
        by_group.entry(c.group_id.clone()).or_default().push((c.path.clone(), c.version_seq));
    }
    for (group_id, keys) in &by_group {
        crate::file_index::drop_versions_in_tx(
            tx,
            group_id,
            keys,
            FreedReason::OverBudget,
            now_unix_nanos,
        )?;
        crate::history_freed::prune(tx, group_id, now_unix_nanos)?;
    }
    Ok(drops.len())
}

#[cfg(test)]
mod tests;
