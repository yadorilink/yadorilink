//! Responder-side exact-version custody leases.
//!
//! An on-demand device that drops its cached copy of a version needs another
//! full replica to keep exactly that version. The full replica's instantaneous
//! "I hold it" answer is not enough: it may advance and reclaim the version
//! right afterwards. A lease is the durable form of the promise. The row is
//! committed before the acquire is acknowledged, and for as long as it exists
//! every block-store sweep treats the version's blocks as live (see
//! [`retained_block_hashes_all_groups`], read by the one GC live-set
//! computation). It ends only through [`RemoteCustodyLeaseRepository::release`];
//! nothing expires it and nothing infers that it is stale.
//!
//! A lease is identified by the requester device and the exact version it
//! asked this device to keep at a path. The responder is this device, so it
//! is implicit. Acquiring the same lease again returns the existing row.
//!
//! Each acquire carries the requester's attempt token, stored on the lease.
//! A release names the token it ends. A release for an attempt this device
//! never saw (the acquire is still in flight, or was lost) leaves a tombstone
//! for the token, and an acquire presenting a tombstoned token commits
//! nothing, so a late acquire cannot leave a lease its requester has already
//! given up on. A tombstone only has to outlive an acquire request that is
//! still in flight, which rides a live authenticated stream with a bounded
//! timeout and is answered in seconds. So only the newest
//! [`TOMBSTONES_PER_REQUESTER`] of a requester's are kept (no clock is
//! involved), and all of them go with the requester's standing in the group.

use std::collections::BTreeSet;
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- One row per active custody lease this device holds for a requester. A row
        -- exists exactly while the lease is active: release deletes it.
        CREATE TABLE IF NOT EXISTS remote_custody_lease (
            lease_id              TEXT PRIMARY KEY,
            group_id              TEXT NOT NULL,
            requester_device_id   TEXT NOT NULL,
            path                  TEXT NOT NULL,
            version_hash          BLOB NOT NULL,
            -- SHA-256 over the ordered block hashes; identifies the exact block set.
            block_set_digest      BLOB NOT NULL,
            -- JSON array of the hex hashes of the version's blocks. Every block-store
            -- sweep treats them as live for as long as the row exists.
            blocks                TEXT NOT NULL,
            -- The requester's authorization epoch when it acquired.
            membership_generation INTEGER NOT NULL,
            -- The requester's token for the attempt that holds this lease. Only a
            -- release naming it ends the lease.
            attempt_token         BLOB NOT NULL,
            created_at_unix       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_remote_custody_lease_requester
            ON remote_custody_lease(group_id, requester_device_id);
        -- Attempts a requester released: an acquire for one of these tokens is a
        -- no-op. Only the newest TOMBSTONES_PER_REQUESTER per requester are kept
        -- (rowid order); all go with the requester.
        CREATE TABLE IF NOT EXISTS remote_custody_release_tombstone (
            group_id            TEXT NOT NULL,
            requester_device_id TEXT NOT NULL,
            attempt_token       BLOB NOT NULL,
            PRIMARY KEY (group_id, requester_device_id, attempt_token)
        );
        -- The close a granted removal ticket holds on its group: new leases are
        -- refused until the ticket's handoff lease (named here) is released or
        -- the close has run for `close_secs`. Written before the ticket leaves
        -- this device, so a restart cannot forget it. NULL: no length of its
        -- own, it ends only when the ticket is released.
        CREATE TABLE IF NOT EXISTS custody_ticket_close (
            group_id   TEXT NOT NULL,
            lease_id   TEXT NOT NULL,
            close_secs INTEGER,
            PRIMARY KEY (group_id, lease_id)
        );
        "#,
    )?;
    Ok(())
}

/// How many released attempts are remembered per requester and group. An
/// acquire request is abandoned by its requester after one bounded round trip
/// and cannot be delivered once the session carrying it is gone, so it is
/// answered within seconds; that a thousand later attempts of the same
/// requester are released before it is delivered is not a case to remember.
pub const TOMBSTONES_PER_REQUESTER: usize = 1024;

/// How many leases one requester may hold in one group at once. Only a NEW
/// lease is checked: renewing or re-acquiring a held version is never refused
/// and never counted twice, and nothing here expires or evicts a lease (only
/// an explicit release or the requester losing its standing ends one).
///
/// A lease is one row per evicted file's current version, so a legitimate
/// on-demand device needs roughly one per file it has dropped from its cache
/// and still wants kept elsewhere. Ten thousand covers a large working set
/// while keeping an authorized but misbehaving peer, which would otherwise
/// pin an unbounded number of versions on this full replica, to a fixed
/// bounded amount of rows. The budget is per (requester, group), so one peer
/// at the cap cannot starve other requesters or groups. Pinned bytes are not
/// bounded here. Not configurable by design.
pub const MAX_ACTIVE_LEASES_PER_REQUESTER: usize = 10_000;

/// The requester's random identifier of one acquire attempt.
pub type AttemptToken = [u8; 16];

/// What a requester asks this device to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyLeaseRequest {
    pub group_id: String,
    pub requester_device_id: String,
    pub path: String,
    pub version_hash: [u8; 32],
    /// The version's ordered block hashes, hex encoded.
    pub blocks: Vec<String>,
    pub membership_generation: u64,
    pub attempt_token: AttemptToken,
    pub now_unix: i64,
}

/// A committed lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyLease {
    pub lease_id: String,
    pub group_id: String,
    pub requester_device_id: String,
    pub path: String,
    pub version_hash: [u8; 32],
    pub block_set_digest: [u8; 32],
    pub blocks: Vec<String>,
    pub membership_generation: u64,
    pub attempt_token: AttemptToken,
    pub created_at_unix: i64,
}

/// Whether an acquire wrote the lease, found it already committed, or was
/// refused: `Refused` because its attempt had already been released,
/// `CapReached` because the requester is at its lease budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseAcquire {
    Created(CustodyLease),
    Existing(CustodyLease),
    Refused,
    /// A new lease was refused because the requester already holds
    /// [`MAX_ACTIVE_LEASES_PER_REQUESTER`] in the group. Nothing was written
    /// and no existing lease was touched.
    CapReached,
}

impl LeaseAcquire {
    /// The lease the requester now holds; `None` when the acquire was refused.
    pub fn lease(&self) -> Option<&CustodyLease> {
        match self {
            LeaseAcquire::Created(lease) | LeaseAcquire::Existing(lease) => Some(lease),
            LeaseAcquire::Refused | LeaseAcquire::CapReached => None,
        }
    }

    pub fn was_created(&self) -> bool {
        matches!(self, LeaseAcquire::Created(_))
    }
}

/// The stable id of the lease `requester` holds on `version_hash` at `path`.
pub fn lease_id(
    group_id: &str,
    requester_device_id: &str,
    path: &str,
    version_hash: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    for part in [group_id.as_bytes(), requester_device_id.as_bytes(), path.as_bytes(), version_hash]
    {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

fn block_set_digest(blocks: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for block in blocks {
        hasher.update((block.len() as u64).to_be_bytes());
        hasher.update(block.as_bytes());
    }
    hasher.finalize().into()
}

pub struct RemoteCustodyLeaseRepository {
    database: Arc<SyncDatabase>,
}

impl RemoteCustodyLeaseRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Commits the lease and returns it. When the same lease is already
    /// committed the existing row is returned unchanged, so a retry after a
    /// lost acknowledgement is idempotent. The row is durable when this
    /// returns; only then may the responder acknowledge.
    pub fn acquire(&self, request: &CustodyLeaseRequest) -> Result<LeaseAcquire, SyncSqliteError> {
        self.acquire_with_cap(request, MAX_ACTIVE_LEASES_PER_REQUESTER)
    }

    pub(crate) fn acquire_with_cap(
        &self,
        request: &CustodyLeaseRequest,
        cap: usize,
    ) -> Result<LeaseAcquire, SyncSqliteError> {
        let id = lease_id(
            &request.group_id,
            &request.requester_device_id,
            &request.path,
            &request.version_hash,
        );
        let digest = block_set_digest(&request.blocks);
        let blocks_json = serde_json::to_string(&request.blocks)?;
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let released = tx
                .query_row(
                    "SELECT 1 FROM remote_custody_release_tombstone \
                     WHERE group_id = ?1 AND requester_device_id = ?2 AND attempt_token = ?3",
                    rusqlite::params![
                        request.group_id,
                        request.requester_device_id,
                        &request.attempt_token[..]
                    ],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if released {
                return Ok(LeaseAcquire::Refused);
            }
            if let Some(mut existing) = read_lease(tx, &id)? {
                if existing.block_set_digest != digest {
                    return Err(SyncSqliteError::CorruptState(format!(
                        "custody lease {id} names a different block set than its version hash"
                    )));
                }
                if existing.attempt_token != request.attempt_token {
                    // The requester no longer has the attempt that took this lease
                    // (it started a new one): the new attempt owns it from here, and
                    // only its release ends it.
                    tx.execute(
                        "UPDATE remote_custody_lease \
                         SET attempt_token = ?2, membership_generation = ?3 WHERE lease_id = ?1",
                        rusqlite::params![
                            id,
                            &request.attempt_token[..],
                            request.membership_generation as i64
                        ],
                    )?;
                    existing.attempt_token = request.attempt_token;
                    existing.membership_generation = request.membership_generation;
                }
                return Ok(LeaseAcquire::Existing(existing));
            }
            // Counted in the same write transaction as the insert below, so
            // concurrent acquires cannot both pass the check.
            let held: i64 = tx.query_row(
                "SELECT COUNT(*) FROM remote_custody_lease \
                 WHERE group_id = ?1 AND requester_device_id = ?2",
                rusqlite::params![request.group_id, request.requester_device_id],
                |row| row.get(0),
            )?;
            if usize::try_from(held).unwrap_or(usize::MAX) >= cap {
                return Ok(LeaseAcquire::CapReached);
            }
            tx.execute(
                "INSERT INTO remote_custody_lease \
                 (lease_id, group_id, requester_device_id, path, version_hash, \
                  block_set_digest, blocks, membership_generation, attempt_token, \
                  created_at_unix) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    id,
                    request.group_id,
                    request.requester_device_id,
                    request.path,
                    &request.version_hash[..],
                    &digest[..],
                    blocks_json,
                    request.membership_generation as i64,
                    &request.attempt_token[..],
                    request.now_unix,
                ],
            )?;
            Ok(LeaseAcquire::Created(CustodyLease {
                lease_id: id.clone(),
                group_id: request.group_id.clone(),
                requester_device_id: request.requester_device_id.clone(),
                path: request.path.clone(),
                version_hash: request.version_hash,
                block_set_digest: digest,
                blocks: request.blocks.clone(),
                membership_generation: request.membership_generation,
                attempt_token: request.attempt_token,
                created_at_unix: request.now_unix,
            }))
        })
    }

    /// The committed lease for this requester and exact version, if any.
    pub fn find(
        &self,
        group_id: &str,
        requester_device_id: &str,
        path: &str,
        version_hash: &[u8; 32],
    ) -> Result<Option<CustodyLease>, SyncSqliteError> {
        let id = lease_id(group_id, requester_device_id, path, version_hash);
        self.database.read::<_, SyncSqliteError>(|conn| read_lease(conn, &id))
    }

    /// Ends the lease held by the attempt `attempt_token` and remembers the
    /// attempt as released, so an acquire for it that is still on its way
    /// commits nothing. Returns whether a lease was deleted; releasing an
    /// attempt that holds nothing is not an error, so a release can be
    /// retried. A lease held by a different (newer) attempt is left alone.
    pub fn release(
        &self,
        group_id: &str,
        requester_device_id: &str,
        path: &str,
        version_hash: &[u8; 32],
        attempt_token: &AttemptToken,
    ) -> Result<bool, SyncSqliteError> {
        let id = lease_id(group_id, requester_device_id, path, version_hash);
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let deleted = tx.execute(
                "DELETE FROM remote_custody_lease WHERE lease_id = ?1 AND attempt_token = ?2",
                rusqlite::params![id, &attempt_token[..]],
            )? > 0;
            tx.execute(
                "INSERT OR IGNORE INTO remote_custody_release_tombstone \
                 (group_id, requester_device_id, attempt_token) VALUES (?1, ?2, ?3)",
                rusqlite::params![group_id, requester_device_id, &attempt_token[..]],
            )?;
            tx.execute(
                "DELETE FROM remote_custody_release_tombstone \
                 WHERE group_id = ?1 AND requester_device_id = ?2 AND rowid NOT IN ( \
                     SELECT rowid FROM remote_custody_release_tombstone \
                     WHERE group_id = ?1 AND requester_device_id = ?2 \
                     ORDER BY rowid DESC LIMIT ?3)",
                rusqlite::params![group_id, requester_device_id, TOMBSTONES_PER_REQUESTER as i64],
            )?;
            Ok(deleted)
        })
    }

    /// Drops every lease and tombstone `requester_device_id` has in a group it
    /// is no longer part of. Returns how many leases went.
    pub fn forget_requester(
        &self,
        group_id: &str,
        requester_device_id: &str,
    ) -> Result<usize, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "DELETE FROM remote_custody_release_tombstone \
                 WHERE group_id = ?1 AND requester_device_id = ?2",
                [group_id, requester_device_id],
            )?;
            Ok(tx.execute(
                "DELETE FROM remote_custody_lease WHERE group_id = ?1 AND requester_device_id = ?2",
                [group_id, requester_device_id],
            )?)
        })
    }

    /// Drops every lease in a group this device no longer keeps as a full
    /// replica. Returns how many went.
    pub fn drop_group(&self, group_id: &str) -> Result<usize, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute("DELETE FROM remote_custody_lease WHERE group_id = ?1", [group_id])?)
        })
    }

    /// Active leases in one group: what a role change in that group must hand
    /// off.
    pub fn list_active_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<CustodyLease>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(&format!("{LEASE_SELECT} WHERE group_id = ?1"))?;
            let rows = stmt.query_map([group_id], decode_row)?;
            rows.map(|row| finish(row?)).collect()
        })
    }

    /// Every (group, requester) this device keeps something for: a lease or a
    /// remembered released attempt. What a membership change checks for
    /// requesters that have left.
    pub fn requesters_with_state(&self) -> Result<Vec<(String, String)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT group_id, requester_device_id FROM remote_custody_lease \
                 UNION SELECT group_id, requester_device_id \
                 FROM remote_custody_release_tombstone ORDER BY 1, 2",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }

    /// Records the close the removal ticket for handoff lease `lease_id` holds
    /// on `group_id`. Idempotent; durable when this returns.
    pub fn record_ticket_close(
        &self,
        group_id: &str,
        lease_id: &str,
        close_secs: Option<u64>,
    ) -> Result<(), SyncSqliteError> {
        let close_secs = close_secs.map(|secs| i64::try_from(secs).unwrap_or(i64::MAX));
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO custody_ticket_close (group_id, lease_id, close_secs) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(group_id, lease_id) DO UPDATE SET close_secs = excluded.close_secs",
                rusqlite::params![group_id, lease_id, close_secs],
            )?;
            Ok(())
        })
    }

    /// Ends the recorded close of one ticket. Ending one that is not recorded
    /// is not an error, so a release can be repeated.
    pub fn end_ticket_close(&self, group_id: &str, lease_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "DELETE FROM custody_ticket_close WHERE group_id = ?1 AND lease_id = ?2",
                [group_id, lease_id],
            )?;
            Ok(())
        })
    }

    /// Every recorded ticket close: (group, handoff lease id, close length in
    /// seconds).
    pub fn ticket_closes(&self) -> Result<Vec<(String, String, Option<u64>)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT group_id, lease_id, close_secs FROM custody_ticket_close \
                 ORDER BY group_id, lease_id",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get::<_, Option<i64>>(2)?.map(|s| s.max(0) as u64)))
            })?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }

    /// How many released attempts are remembered.
    pub fn tombstone_count(&self) -> Result<usize, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM remote_custody_release_tombstone", [], |r| {
                    r.get(0)
                })?;
            Ok(count as usize)
        })
    }

    /// Every active lease: the set a role change must hand off or refuse on.
    pub fn list_active(&self) -> Result<Vec<CustodyLease>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(LEASE_SELECT)?;
            let rows = stmt.query_map([], decode_row)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(finish(row?)?);
            }
            Ok(out)
        })
    }
}

const LEASE_SELECT: &str = "SELECT lease_id, group_id, requester_device_id, path, version_hash, \
     block_set_digest, blocks, membership_generation, created_at_unix, attempt_token \
     FROM remote_custody_lease";

type RawLease = (String, String, String, String, Vec<u8>, Vec<u8>, String, i64, i64, Vec<u8>);

fn decode_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawLease> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
    ))
}

fn finish(raw: RawLease) -> Result<CustodyLease, SyncSqliteError> {
    let (
        lease_id,
        group_id,
        requester_device_id,
        path,
        version_hash,
        digest,
        blocks,
        generation,
        created,
        token,
    ) = raw;
    let array = |bytes: Vec<u8>, what: &str| -> Result<[u8; 32], SyncSqliteError> {
        bytes.try_into().map_err(|_| {
            SyncSqliteError::CorruptState(format!("custody lease {lease_id}: bad {what} length"))
        })
    };
    let attempt_token: AttemptToken = token.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!("custody lease {lease_id}: bad attempt token length"))
    })?;
    Ok(CustodyLease {
        version_hash: array(version_hash, "version hash")?,
        block_set_digest: array(digest, "block set digest")?,
        attempt_token,
        blocks: serde_json::from_str(&blocks)?,
        membership_generation: generation as u64,
        created_at_unix: created,
        lease_id: lease_id.clone(),
        group_id,
        requester_device_id,
        path,
    })
}

fn read_lease(conn: &Connection, id: &str) -> Result<Option<CustodyLease>, SyncSqliteError> {
    let raw = conn
        .query_row(&format!("{LEASE_SELECT} WHERE lease_id = ?1"), [id], decode_row)
        .optional()?;
    raw.map(finish).transpose()
}

/// The blocks every active lease keeps alive: the root source a block-store
/// sweep adds to the live set. Present exactly while the lease row is.
pub(crate) fn retained_block_hashes_all_groups(
    conn: &Connection,
) -> Result<BTreeSet<String>, SyncSqliteError> {
    let mut stmt = conn.prepare("SELECT blocks FROM remote_custody_lease")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = BTreeSet::new();
    for row in rows {
        let blocks: Vec<String> = serde_json::from_str(&row?).map_err(|e| {
            SyncSqliteError::CorruptState(format!("a custody lease's block list: {e}"))
        })?;
        out.extend(blocks);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
