//! `PinnedItemRepository` owns `pinned_items`: the files and folders a user
//! marked "Always keep on this device", per linked group.
//!
//! This is the retention policy, and it is kept apart from the
//! materialization state (`Remote`/`Hydrated`): a pin says what the user
//! wants to stay here, never what is stored. It is local to this device and
//! never leaves it -- no change is authored, no peer is told, and no
//! custody or role follows from it. It is durable ("kept until unpinned"
//! must survive a restart), which is why it is a table and not process
//! memory.
//!
//! A pin covers its own path and, for a folder, every path beneath it
//! (including paths that appear later); the empty path is the linked
//! folder's root and covers the whole group. There are no per-child
//! overrides: a path covered only by an ancestor's pin cannot be unpinned
//! by itself. [`path_is_covered`] is the one statement of that rule.
//!
//! The policy is keyed by relative path, not file identity. A pinned path
//! that is renamed or deleted leaves its row behind, and whatever later
//! stands at that path is covered by it.

use std::sync::Arc;

use rusqlite::Connection;
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;

pub(crate) fn init_pinned_items_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pinned_items (
            group_id             TEXT NOT NULL,
            path                 TEXT NOT NULL,
            pinned_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );",
    )?;
    Ok(())
}

/// Whether local space for an item may be reclaimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    Reclaimable,
    Pinned,
}

/// The policy in force at one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    pub policy: RetentionPolicy,
    /// A pin was set at exactly this path (rather than only inherited).
    pub explicit: bool,
}

/// Whether `path` is covered by one of `pinned` (a group's pinned items): it
/// is one of them, lies beneath one of them, or the root itself is pinned.
pub fn path_is_covered(pinned: &[String], path: &str) -> bool {
    pinned.iter().any(|item| {
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

pub struct PinnedItemRepository {
    database: Arc<SyncDatabase>,
}

impl PinnedItemRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Pins `path` in `group_id`. Pinning an already pinned path is a no-op
    /// that keeps its original pin time. In the same transaction the provider items the pin
    /// changes the served permission of are republished to the OS, so a crash can never leave a
    /// pin without its republication.
    pub fn pin(&self, group_id: &str, path: &str) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let added = tx.execute(
                "INSERT INTO pinned_items (group_id, path, pinned_at_unix_nanos) \
                 VALUES (?1, ?2, ?3) ON CONFLICT(group_id, path) DO NOTHING",
                rusqlite::params![group_id, path, now_unix_nanos()],
            )?;
            if added > 0 {
                yadorilink_sqlite_runtime::note_retention_changed(tx, group_id, path)?;
            }
            Ok(())
        })
    }

    /// Removes the pin set at exactly `path`, returning whether there was
    /// one. Content is not touched and a pin of an ancestor stays in force.
    pub fn unpin(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let removed = tx.execute(
                "DELETE FROM pinned_items WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
            )?;
            if removed > 0 {
                yadorilink_sqlite_runtime::note_retention_changed(tx, group_id, path)?;
            }
            Ok(removed > 0)
        })
    }

    /// Every pinned item of `group_id`, in path order.
    pub fn list(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn
                .prepare("SELECT path FROM pinned_items WHERE group_id = ?1 ORDER BY path ASC")?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }

    /// The policy in force at `path`.
    pub fn retention(&self, group_id: &str, path: &str) -> Result<Retention, SyncSqliteError> {
        let pinned = self.list(group_id)?;
        let policy = if path_is_covered(&pinned, path) {
            RetentionPolicy::Pinned
        } else {
            RetentionPolicy::Reclaimable
        };
        Ok(Retention { policy, explicit: pinned.iter().any(|item| item == path) })
    }

    /// Pinned items of `group_id` that lie strictly beneath `prefix` (every
    /// item when `prefix` is the root).
    pub fn pinned_beneath(
        &self,
        group_id: &str,
        prefix: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        Ok(self
            .list(group_id)?
            .into_iter()
            .filter(|item| {
                prefix.is_empty()
                    || item.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
