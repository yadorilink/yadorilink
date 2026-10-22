//! `HeldPathRepository` owns `held_paths`: the paths
//! whose object on disk belongs to no row this device placed, and whose disk
//! the reconciliation pass has not looked at yet.
//!
//! A path is held when a local edit cannot be authored there (this replica's
//! own bucket at the path is full), so the bytes on disk are an edit nothing
//! may publish: authoring them would supersede heads the writer was never
//! shown. A hold is the durable record of that state.
//!
//! While a path is held:
//!
//! - local capture authors nothing for it -- no edit, no offline deletion
//!   (local capture consults [`held_paths`], and every local-authoring
//!   entry point in [`crate::file_index`] refuses a held path in its own
//!   transaction with [`SyncSqliteError::PathAwaitingHeldPathReconciliation`]);
//! - the projection scheduler does not claim it
//!   ([`crate::projection_obligations::claim_runnable_obligations`]), and no
//!   materializer writes it, since writing the row's version would overwrite
//!   whatever is there without looking at it.
//!
//! The reconciliation pass is the one writer of a held path. It classifies
//! the object on disk against the row the index holds there:
//!
//! - nothing there: the row's placeholder is placed;
//! - an untouched placeholder of the row is already its projection and is
//!   kept;
//! - a directory is not the path's to move: its entries are other paths;
//! - anything else is an edit no row accounts for, so it is preserved rather
//!   than authored: it is moved aside to a conflict-copy name, which local
//!   capture then captures as a new file.
//!
//! Then it places the row's projection and releases the hold with
//! [`release_in_tx`]. A change observed at the path after the release is an
//! ordinary local edit: the only thing on disk at that point is what the
//! reconciliation itself placed.

use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension};
pub use yadorilink_replica_domain::session_state::HeldPath;
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;

pub(crate) fn init_held_path_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS held_paths (
            group_id           TEXT NOT NULL,
            path               TEXT NOT NULL,
            held_at_unix_nanos INTEGER NOT NULL,
            -- Moves every time the path is held again, so a reconciliation
            -- that read an earlier hold cannot release one that was renewed.
            generation         INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, path)
        );",
    )?;
    Ok(())
}

/// A boolean SQL expression, true when `{path}` of `{group}` is held. The
/// caller replaces `{group}` and `{path}` with its own column references.
const HELD_SQL: &str = "EXISTS (SELECT 1 FROM held_paths h \
     WHERE h.group_id = {group} AND h.path = {path})";

pub(crate) fn held_sql(group: &str, path: &str) -> String {
    HELD_SQL.replace("{group}", group).replace("{path}", path)
}

/// Whether any live current row of `group_id` lies strictly below `path`:
/// the index's own answer to whether `path` has to be a directory for
/// what is installed under it. "Below" is the namespace relation: the
/// half-open range (`path/`, `path0`), never a `LIKE`.
pub fn has_live_descendant_row(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM files WHERE group_id = ?1 AND path > ?2 AND path < ?3 \
               AND state = 'current' AND deleted = 0 LIMIT 1",
            params![group_id, format!("{path}/"), format!("{path}0")],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Holds `path`: the object on disk there belongs to no row this device
/// placed, so nothing may author it until the reconciliation pass has looked
/// at it. A path already held stays held; its generation moves, so a
/// reconciliation in flight cannot release a hold that was renewed after it
/// read the row.
pub(crate) fn hold_in_tx(
    conn: &Connection,
    group_id: &str,
    path: &str,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT INTO held_paths (group_id, path, held_at_unix_nanos) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(group_id, path) DO UPDATE SET generation = generation + 1",
        params![group_id, path, now_unix_nanos],
    )?;
    Ok(())
}

pub fn is_held(conn: &Connection, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .prepare_cached("SELECT 1 FROM held_paths WHERE group_id = ?1 AND path = ?2")?
        .query_row(params![group_id, path], |_| Ok(()))
        .optional()?
        .is_some())
}

pub fn held_paths(conn: &Connection, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
    let mut stmt =
        conn.prepare("SELECT path FROM held_paths WHERE group_id = ?1 ORDER BY path ASC")?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn list_holds(conn: &Connection, group_id: &str) -> Result<Vec<HeldPath>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path, generation FROM held_paths WHERE group_id = ?1 \
         ORDER BY path ASC",
    )?;
    let rows =
        stmt.query_map([group_id], |r| Ok(HeldPath { path: r.get(0)?, generation: r.get(1)? }))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Releases `path` at `generation`: the reconciliation has left disk holding
/// the projection of the installed row it read (or nothing, where that row
/// is not live). Returns whether it was released -- `false` when the path is
/// not held, or is held at another generation because an install renewed
/// the hold after the reconciliation read it. That hold is left in place.
///
/// In the same transaction, a live installed row gets a pending projection
/// obligation. The scheduler then drives the path to its policy's final
/// state, and until it has, the obligation is what tells the offline-delete
/// scan that a path with nothing under its name is still being placed.
pub fn release_in_tx(
    conn: &Connection,
    group_id: &str,
    path: &str,
    generation: i64,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let removed = conn.execute(
        "DELETE FROM held_paths WHERE group_id = ?1 AND path = ?2 AND generation = ?3",
        params![group_id, path, generation],
    )?;
    if removed == 0 {
        return Ok(false);
    }
    let live: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 \
            AND state = 'current' AND deleted = 0)",
        params![group_id, path],
        |r| r.get(0),
    )?;
    if live {
        // The reconciliation released this hold with the path empty (an
        // entry's content is materialized by the projection scheduled
        // below), so a file or symlink row has no local object: `Remote`.
        // A directory row keeps its state: the directory is the object.
        conn.execute(
            "UPDATE files SET materialization_state = 'remote' \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current' AND deleted = 0 \
               AND materialization_state = 'present' \
               AND COALESCE(record_kind, 'file') IN ('file', 'symlink')",
            params![group_id, path],
        )?;
        crate::projection_obligations::bump_projection_obligations_for_touched_paths(
            conn,
            group_id,
            &[path],
            now_unix_nanos,
        )?;
    }
    Ok(true)
}

/// Refuses a local authoring of `path` while it is held. Called inside the
/// authoring transaction itself, so a capture prepared before an install
/// and committed after it cannot slip past: it is the only point that sees
/// the hold and the authoring atomically.
pub(crate) fn refuse_local_authoring_if_held(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    // A frozen group refuses at the store's install gate, in the same transaction.
    let held: bool = conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM held_paths WHERE group_id = ?1 AND path = ?2)",
        )?
        .query_row(params![group_id, path], |row| row.get(0))?;
    if held {
        return Err(SyncSqliteError::PathAwaitingHeldPathReconciliation {
            group_id: group_id.to_owned(),
            path: path.to_owned(),
        });
    }
    Ok(())
}

pub struct HeldPathRepository {
    database: Arc<SyncDatabase>,
}

impl HeldPathRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    pub fn is_held(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| is_held(conn, group_id, path))
    }

    /// See [`has_live_descendant_row`].
    pub fn has_live_descendant_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| has_live_descendant_row(conn, group_id, path))
    }

    /// Every held path of `group_id`, in path order.
    pub fn held_paths(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| held_paths(conn, group_id))
    }

    pub fn list(&self, group_id: &str) -> Result<Vec<HeldPath>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| list_holds(conn, group_id))
    }

    /// The held paths of `group_id` the reconciliation pass may look at: none while a
    /// rebootstrap freezes the group. That pass moves a divergent disk object aside as a
    /// conflict copy and releases the hold, which is a write the freeze forbids.
    pub fn list_for_reconciliation(
        &self,
        group_id: &str,
    ) -> Result<Vec<HeldPath>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            if crate::native_rebootstrap::group_frozen(conn, group_id)? {
                return Ok(Vec::new());
            }
            list_holds(conn, group_id)
        })
    }

    /// Whether a rebootstrap freezes `group_id`: nothing may write, remove or move an
    /// object of it, and local capture authors nothing, until the rebootstrap finishes.
    pub fn group_frozen(&self, group_id: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::native_rebootstrap::group_frozen(conn, group_id)
        })
    }

    /// Holds `path` for a local edit this replica cannot author there: its
    /// own bucket at the path already holds two versions it was not shown
    /// (`AuthoringRefusal::OwnBucketOverCap`), and a write names only what
    /// it was shown. The hold records no prior placement, because the
    /// object on disk is the edit, not anything a row placed; so the
    /// reconciliation pass classifies it as ambiguous and preserves it as a
    /// conflict copy -- which local capture captures as a new file -- then
    /// places the path's current value and releases the hold. This is the
    /// user-resolvable conflict the live own-head bound calls for (contract,
    /// "Live own-head bound: option B"): nothing is superseded unseen, the
    /// edit is kept, and the path stops blocking what peers send for it.
    pub fn hold_unauthorable_local_edit(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            // The edit is a physical local object, so the row is `Present`
            // (and held); `Present` makes no claim that the object equals
            // the row's version. Reconciliation preserves the edit as a
            // conflict copy and, once the path is empty, releases the hold
            // with the row `Remote`.
            tx.execute(
                "UPDATE files SET materialization_state = 'present', placeholder_dev = NULL, \
                        placeholder_ino = NULL, placeholder_provider_kind = NULL \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current' AND deleted = 0",
                params![group_id, path],
            )?;
            hold_in_tx(tx, group_id, path, crate::dag_store::now_unix_nanos())
        })
    }

    /// See [`release_in_tx`].
    pub fn release(
        &self,
        group_id: &str,
        path: &str,
        generation: i64,
        now_unix_nanos: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            release_in_tx(tx, group_id, path, generation, now_unix_nanos)
        })
    }
}
