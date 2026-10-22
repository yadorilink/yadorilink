//! `PausedItemRepository` owns `paused_items`: the files and folders a user
//! paused from the shell context menu, per linked group.
//!
//! Pausing an item holds exactly two things for every path it covers, and
//! nothing else:
//!
//! - local emission: a local edit is not turned into a change, so no peer
//!   can be served it (local capture consults [`PausedItemRepository::list`]);
//! - remote projection: a remote change is still admitted and stored, and
//!   its projection obligation still opens, but the projection scheduler
//!   does not claim it ([`crate::projection_obligations::claim_runnable_obligations`]).
//!
//! Nothing is dropped while paused, so resume only has to release the hold:
//! the local edits are still on disk, and the remote changes are still
//! pending obligations. The pause itself is durable -- "paused until
//! resumed" must survive a daemon restart -- which is why it is a table and
//! not process memory.
//!
//! Pause is a folder-link feature: a provider root cannot be paused, and no
//! pause row outlives its group's last link or reaches a provider root
//! ([`clear_group_in_tx`]), so provider paths never see one.
//!
//! An item covers its own path and, for a folder, every path beneath it.
//! The empty path is the linked folder's root and covers the whole group.
//! [`path_is_covered`] is the one Rust statement of that rule;
//! [`COVERED_BY_PAUSED_ITEM_SQL`] is the same rule for the claim query, and
//! the tests below pin the two to each other.

use std::sync::Arc;

use rusqlite::Connection;
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;

pub(crate) fn init_paused_items_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS paused_items (
            group_id             TEXT NOT NULL,
            path                 TEXT NOT NULL,
            paused_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );",
    )?;
    Ok(())
}

/// A boolean SQL expression, true when some paused item of `{group}`
/// covers the path `{path}` -- see [`path_is_covered`] for the rule.
/// `{group}` and `{path}` are replaced by the caller's column references.
pub(crate) const COVERED_BY_PAUSED_ITEM_SQL: &str = "EXISTS (SELECT 1 FROM paused_items p \
     WHERE p.group_id = {group} AND (p.path = '' OR {path} = p.path \
       OR substr({path}, 1, length(p.path) + 1) = p.path || '/'))";

pub(crate) fn covered_by_paused_item_sql(group: &str, path: &str) -> String {
    COVERED_BY_PAUSED_ITEM_SQL.replace("{group}", group).replace("{path}", path)
}

/// Whether `path` is covered by one of `paused` (a group's paused items):
/// it is one of them, lies beneath one of them, or the root itself is
/// paused.
pub fn path_is_covered(paused: &[String], path: &str) -> bool {
    paused.iter().any(|item| {
        item.is_empty()
            || path == item
            || path.strip_prefix(item.as_str()).is_some_and(|rest| rest.starts_with('/'))
    })
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Refuses a local authoring of `path` while an item covering it is paused.
/// Called inside the authoring transaction itself: the capture's own pause
/// checks run earlier and can be overtaken by a pause, so this is the only
/// point that sees the pause and the authoring atomically.
pub(crate) fn refuse_local_authoring_if_paused(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    let sql = format!("SELECT {}", covered_by_paused_item_sql("?1", "?2"));
    let paused: bool = conn.prepare_cached(&sql)?.query_row([group_id, path], |row| row.get(0))?;
    if paused {
        return Err(SyncSqliteError::PathPaused {
            group_id: group_id.to_owned(),
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Drops every pause of `group_id` inside the caller's transaction and makes
/// the group's pending projection obligations runnable now.
///
/// A pause is a property of a FOLDER link (the shell resolves Pause/Resume
/// through the folder path, and a provider root refuses to be paused), so no
/// pause may outlive the folder link it was made on: the last link of a
/// group going away, and a group becoming a provider root, both end it here,
/// in the same transaction as the change that makes it stale.
pub(crate) fn clear_group_in_tx(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
) -> Result<(), SyncSqliteError> {
    let removed = tx.execute("DELETE FROM paused_items WHERE group_id = ?1", [group_id])?;
    if removed > 0 {
        tx.execute(
            "UPDATE projection_obligations SET next_attempt_at = 0 \
              WHERE group_id = ?1 AND state = 'pending'",
            [group_id],
        )?;
    }
    Ok(())
}

pub struct PausedItemRepository {
    database: Arc<SyncDatabase>,
}

impl PausedItemRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Pauses `path` in `group_id`. Pausing an already-paused item is a
    /// no-op that keeps its original pause time.
    pub fn pause(&self, group_id: &str, path: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO paused_items (group_id, path, paused_at_unix_nanos) \
                 VALUES (?1, ?2, ?3) ON CONFLICT(group_id, path) DO NOTHING",
                rusqlite::params![group_id, path, now_unix_nanos()],
            )?;
            Ok(())
        })
    }

    /// Resumes `path` in `group_id`, returning whether it was paused.
    ///
    /// In the same transaction, every pending projection obligation the
    /// item covered is made runnable now. A pause does not touch those rows,
    /// but one claimed just before the pause landed can have been deferred
    /// by the pause's own projection guard, and resume must not leave that
    /// catch-up waiting out a retry backoff.
    pub fn resume(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let tx = conn.transaction()?;
            let removed = tx.execute(
                "DELETE FROM paused_items WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
            )?;
            if removed > 0 {
                tx.execute(
                    "UPDATE projection_obligations SET next_attempt_at = 0 \
                      WHERE group_id = ?1 AND state = 'pending' \
                        AND (?2 = '' OR path = ?2 \
                             OR substr(path, 1, length(?2) + 1) = ?2 || '/')",
                    rusqlite::params![group_id, path],
                )?;
            }
            tx.commit()?;
            Ok(removed > 0)
        })
    }

    /// Every paused item of `group_id`, in path order.
    pub fn list(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn
                .prepare("SELECT path FROM paused_items WHERE group_id = ?1 ORDER BY path ASC")?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests;
