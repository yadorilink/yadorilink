//! Requester-side record of custody this device may have asked for.
//!
//! An on-demand device that evicts a version asks a full replica to keep it
//! (see [`crate::remote_custody_lease`], the responder's half). A row here
//! means "this peer may hold a lease for me on this exact version". It is
//! the only record of that fact: nothing is derived from absent rows or from
//! leases found at a peer.
//!
//! The row is committed as `requested` before the acquire is sent, so a lease
//! the responder commits can never exist without a row here. It becomes
//! `granted` when the responder acknowledges, before the custody stamp is
//! returned to the eviction. The reconciler deletes the row only after the
//! responder has answered that the lease is gone.

use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;
use crate::remote_custody_lease::AttemptToken;

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- One row per (version, peer) this device asked to hold a custody lease.
        -- A row exists until the peer has confirmed the lease is released.
        CREATE TABLE IF NOT EXISTS remote_custody_hold (
            group_id              TEXT NOT NULL,
            path                  TEXT NOT NULL,
            version_hash          BLOB NOT NULL,
            peer_id               TEXT NOT NULL,
            -- 'requested': the acquire may be in flight or have been committed
            -- by the peer; no stamp was issued for it.
            -- 'granted': the peer acknowledged; a stamp was issued.
            state                 TEXT NOT NULL CHECK (state IN ('requested', 'granted')),
            -- The authorization epoch the acquire was sent under.
            membership_generation INTEGER NOT NULL,
            -- Names the acquire attempt: the peer keys the lease and its release by
            -- it, so a late acquire cannot outlive this row's release.
            attempt_token         BLOB NOT NULL,
            PRIMARY KEY (group_id, path, version_hash, peer_id)
        );
        "#,
    )?;
    Ok(())
}

/// Whether the peer has acknowledged the acquire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldState {
    Requested,
    Granted,
}

impl HoldState {
    fn as_db_str(self) -> &'static str {
        match self {
            HoldState::Requested => "requested",
            HoldState::Granted => "granted",
        }
    }

    fn from_db_str(value: &str) -> Result<Self, SyncSqliteError> {
        match value {
            "requested" => Ok(HoldState::Requested),
            "granted" => Ok(HoldState::Granted),
            other => Err(SyncSqliteError::CorruptState(format!(
                "remote_custody_hold: unknown state {other:?}"
            ))),
        }
    }
}

/// The identity of a hold: the exact version at a path and the peer asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldKey {
    pub group_id: String,
    pub path: String,
    pub version_hash: [u8; 32],
    pub peer_id: String,
}

/// A stored hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCustodyHold {
    pub key: HoldKey,
    pub state: HoldState,
    pub membership_generation: u64,
    pub attempt_token: AttemptToken,
}

pub struct RemoteCustodyHoldRepository {
    database: Arc<SyncDatabase>,
}

impl RemoteCustodyHoldRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Commits a `requested` row. Must be durable before the acquire is sent.
    /// An existing row keeps its state and its attempt token: a `granted` hold
    /// is never taken back to `requested` by a repeated acquire, and the
    /// release that ends the hold names the attempt that first went out.
    /// Returns the token the acquire must carry.
    pub fn record_requested(
        &self,
        key: &HoldKey,
        membership_generation: u64,
        attempt_token: AttemptToken,
    ) -> Result<AttemptToken, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO remote_custody_hold \
                 (group_id, path, version_hash, peer_id, state, membership_generation, \
                  attempt_token) \
                 VALUES (?1, ?2, ?3, ?4, 'requested', ?5, ?6) \
                 ON CONFLICT(group_id, path, version_hash, peer_id) DO NOTHING",
                rusqlite::params![
                    key.group_id,
                    key.path,
                    &key.version_hash[..],
                    key.peer_id,
                    membership_generation as i64,
                    &attempt_token[..],
                ],
            )?;
            let stored: Vec<u8> = tx.query_row(
                "SELECT attempt_token FROM remote_custody_hold \
                 WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3 AND peer_id = ?4",
                rusqlite::params![key.group_id, key.path, &key.version_hash[..], key.peer_id],
                |r| r.get(0),
            )?;
            stored.try_into().map_err(|_| {
                SyncSqliteError::CorruptState(
                    "remote_custody_hold: bad attempt token length".into(),
                )
            })
        })
    }

    /// Moves a `requested` row to `granted`. Fails if the row is not there, so
    /// a stamp is never issued for a hold that is not recorded.
    pub fn mark_granted(&self, key: &HoldKey) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let updated = tx.execute(
                "UPDATE remote_custody_hold SET state = 'granted' \
                 WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3 AND peer_id = ?4",
                rusqlite::params![key.group_id, key.path, &key.version_hash[..], key.peer_id],
            )?;
            if updated == 0 {
                return Err(SyncSqliteError::CorruptState(format!(
                    "remote_custody_hold: no row to grant for {}/{} at {}",
                    key.group_id, key.path, key.peer_id
                )));
            }
            Ok(())
        })
    }

    /// The stored row, if any: one lookup on the table's primary key.
    pub fn get(&self, key: &HoldKey) -> Result<Option<RemoteCustodyHold>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            conn.query_row(
                &format!(
                    "{HOLD_SELECT} WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3 \
                     AND peer_id = ?4"
                ),
                rusqlite::params![key.group_id, key.path, &key.version_hash[..], key.peer_id],
                RawHold::read,
            )
            .optional()?
            .map(RawHold::decode)
            .transpose()
        })
    }

    /// The peers whose hold on exactly this version of this path is `granted`.
    pub fn granted_peers(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &[u8; 32],
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT peer_id FROM remote_custody_hold \
                 WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3 AND state = 'granted' \
                 ORDER BY peer_id",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![group_id, path, &version_hash[..]], |r| {
                    r.get::<_, String>(0)
                })?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }

    /// Whether the hold is recorded and `granted`.
    pub fn is_granted(&self, key: &HoldKey) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let state: Option<String> = conn
                .query_row(
                    "SELECT state FROM remote_custody_hold \
                     WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3 AND peer_id = ?4",
                    rusqlite::params![key.group_id, key.path, &key.version_hash[..], key.peer_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(state.as_deref() == Some(HoldState::Granted.as_db_str()))
        })
    }

    /// Deletes the row. Called only after the peer answered that the lease is
    /// released.
    pub fn delete(&self, key: &HoldKey) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM remote_custody_hold \
                 WHERE group_id = ?1 AND path = ?2 AND version_hash = ?3 AND peer_id = ?4",
                rusqlite::params![key.group_id, key.path, &key.version_hash[..], key.peer_id],
            )?;
            Ok(())
        })
    }

    /// Every hold, for the reconciler.
    pub fn list(&self) -> Result<Vec<RemoteCustodyHold>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt =
                conn.prepare(&format!("{HOLD_SELECT} ORDER BY group_id, path, peer_id"))?;
            let rows = stmt.query_map([], RawHold::read)?;
            rows.map(|row| RawHold::decode(row?)).collect()
        })
    }
}

const HOLD_SELECT: &str = "SELECT group_id, path, version_hash, peer_id, state, \
     membership_generation, attempt_token FROM remote_custody_hold";

/// A row as stored; [`Self::decode`] is the one place its fields are validated.
struct RawHold {
    group_id: String,
    path: String,
    version_hash: Vec<u8>,
    peer_id: String,
    state: String,
    membership_generation: i64,
    attempt_token: Vec<u8>,
}

impl RawHold {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            group_id: row.get(0)?,
            path: row.get(1)?,
            version_hash: row.get(2)?,
            peer_id: row.get(3)?,
            state: row.get(4)?,
            membership_generation: row.get(5)?,
            attempt_token: row.get(6)?,
        })
    }

    fn decode(self) -> Result<RemoteCustodyHold, SyncSqliteError> {
        #[cfg(test)]
        DECODED_ROWS.with(|count| count.set(count.get() + 1));
        let Self {
            group_id,
            path,
            version_hash,
            peer_id,
            state,
            membership_generation,
            attempt_token,
        } = self;
        let version_hash: [u8; 32] = version_hash.try_into().map_err(|_| {
            SyncSqliteError::CorruptState(format!(
                "remote_custody_hold {group_id}/{path}: bad version hash length"
            ))
        })?;
        let attempt_token: AttemptToken = attempt_token.try_into().map_err(|_| {
            SyncSqliteError::CorruptState(format!(
                "remote_custody_hold {group_id}/{path}: bad attempt token length"
            ))
        })?;
        Ok(RemoteCustodyHold {
            key: HoldKey { group_id, path, version_hash, peer_id },
            state: HoldState::from_db_str(&state)?,
            membership_generation: membership_generation as u64,
            attempt_token,
        })
    }
}

// Rows decoded on this thread, so a test can assert the work a pass does.
#[cfg(test)]
thread_local! {
    static DECODED_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_decoded_rows() {
    DECODED_ROWS.with(|count| count.set(0));
}

#[cfg(test)]
fn decoded_rows() -> usize {
    DECODED_ROWS.with(std::cell::Cell::get)
}

#[cfg(test)]
mod tests;
