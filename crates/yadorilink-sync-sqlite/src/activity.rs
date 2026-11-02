//! The recent-activity log behind the apps' Activity page.
//!
//! One append-only table (`activity_events`), written in the same
//! transaction as the `files` row it describes (see
//! [`record_version_in_tx`], called from the one `files` version writer) and
//! pruned on every insert to the newest [`MAX_EVENTS`] rows within
//! [`MAX_AGE_DAYS`]. It is a view for people, not state: nothing here
//! decides sync behavior, and every event is a fact the index already
//! committed. Directories get no event; ignored and internal paths never
//! reach the index, so they get none either.
//!
//! Paths are stored as the index has them and are returned only to the
//! caller of [`FileIndexRepository::list_activity`]; nothing in this module
//! logs one.

use rusqlite::{params, OptionalExtension};

use crate::error::SyncSqliteError;
use crate::file_index::FileIndexRepository;

/// Newest events kept; older ones are dropped on the next insert.
pub const MAX_EVENTS: i64 = 2000;
/// Events older than this are dropped on the next insert.
pub const MAX_AGE_DAYS: i64 = 30;
/// Largest page [`FileIndexRepository::list_activity`] returns.
pub const MAX_PAGE: u32 = 500;

const NANOS_PER_DAY: i64 = 86_400 * 1_000_000_000;

/// What happened to a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityKind {
    Added,
    Updated,
    Deleted,
    Conflict,
    Restored,
}

impl ActivityKind {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Updated => "updated",
            Self::Deleted => "deleted",
            Self::Conflict => "conflict",
            Self::Restored => "restored",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        Some(match value {
            "added" => Self::Added,
            "updated" => Self::Updated,
            "deleted" => Self::Deleted,
            "conflict" => Self::Conflict,
            "restored" => Self::Restored,
            _ => return None,
        })
    }
}

/// One logged event; `id` is the paging cursor (larger is newer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityEvent {
    pub id: i64,
    pub group_id: String,
    pub path: String,
    pub kind: ActivityKind,
    pub origin_device_id: Option<String>,
    pub at_unix_nanos: i64,
}

/// Whose change to list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ActivityOrigin {
    #[default]
    Any,
    /// Authored here: origin is this device, or not known (a local write
    /// that carries no author).
    ThisDevice,
    OtherDevices,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActivityQuery {
    /// Only events strictly older than this cursor (`id`).
    pub before_id: Option<i64>,
    pub limit: u32,
    /// Empty = every kind.
    pub kinds: Vec<ActivityKind>,
    pub origin: ActivityOrigin,
    /// Only these groups (the caller passes the linked ones); empty = none.
    pub group_ids: Vec<String>,
}

/// The superseded `current` row of a path, as the version writer saw it.
pub(crate) struct PreviousRow {
    pub deleted: bool,
    pub record_kind: String,
    pub blocks_json: String,
}

fn now_unix_nanos() -> i64 {
    crate::dag_store::now_unix_nanos()
}

/// Logs the version just written for `path` (its `current` row) and prunes.
/// `previous` is the genuine row it superseded, if any.
pub(crate) fn record_version_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    deleted: bool,
    blocks_json: &str,
    origin: Option<&str>,
    previous: Option<&PreviousRow>,
) -> Result<(), SyncSqliteError> {
    if previous.is_some_and(|p| p.record_kind == "directory") {
        return Ok(());
    }
    let previous_live = previous.is_some_and(|p| !p.deleted);
    let kind = if deleted {
        if !previous_live {
            return Ok(());
        }
        ActivityKind::Deleted
    } else if previous_live {
        // Same blocks: a metadata-only touch, not a change people made.
        if previous.is_some_and(|p| p.blocks_json == blocks_json) {
            return Ok(());
        }
        ActivityKind::Updated
    } else if yadorilink_replica_domain::conflict::is_conflict_copy_path(path) {
        ActivityKind::Conflict
    } else {
        ActivityKind::Added
    };
    insert_in_tx(tx, group_id, path, kind, origin)
}

fn current_version_seq(
    tx: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<(i64, Option<String>)>, SyncSqliteError> {
    Ok(tx
        .prepare_cached(
            "SELECT version_seq, origin_device_id FROM files \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
        )?
        .query_row(params![group_id, path], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?)
}

fn insert_in_tx(
    tx: &rusqlite::Connection,
    group_id: &str,
    path: &str,
    kind: ActivityKind,
    origin: Option<&str>,
) -> Result<(), SyncSqliteError> {
    let Some((version_seq, _)) = current_version_seq(tx, group_id, path)? else {
        return Ok(());
    };
    let now = now_unix_nanos();
    tx.prepare_cached(
        "INSERT INTO activity_events (group_id, path, version_seq, kind, origin_device_id, at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![group_id, path, version_seq, kind.as_db_str(), origin, now])?;
    let id = tx.last_insert_rowid();
    tx.prepare_cached("DELETE FROM activity_events WHERE id <= ?1")?
        .execute(params![id - MAX_EVENTS])?;
    tx.prepare_cached("DELETE FROM activity_events WHERE at_unix_nanos < ?1")?
        .execute(params![now.saturating_sub(MAX_AGE_DAYS * NANOS_PER_DAY)])?;
    Ok(())
}

/// Logs paths that were brand new (version 1, live), the bulk insert's
/// counterpart of [`record_version_in_tx`]; directories are skipped.
pub(crate) fn record_new_paths_in_tx<'a>(
    tx: &rusqlite::Connection,
    group_id: &str,
    origin: Option<&str>,
    paths: impl IntoIterator<Item = (&'a str, bool)>,
) -> Result<(), SyncSqliteError> {
    for (path, is_directory) in paths {
        if is_directory {
            continue;
        }
        let kind = if yadorilink_replica_domain::conflict::is_conflict_copy_path(path) {
            ActivityKind::Conflict
        } else {
            ActivityKind::Added
        };
        insert_in_tx(tx, group_id, path, kind, origin)?;
    }
    Ok(())
}

/// A directory has no event: drops the one logged for the path's current
/// version (a directory's kind is written after its row, so the version
/// writer cannot tell in advance).
pub(crate) fn forget_directory_event_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    tx.prepare_cached(
        "DELETE FROM activity_events WHERE group_id = ?1 AND path = ?2 AND version_seq = \
         (SELECT version_seq FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current')",
    )?
    .execute(params![group_id, path])?;
    Ok(())
}

/// Labels the change just committed for `path` as a restore (of an older
/// version or from the trash); logs one if the version writer logged none.
pub(crate) fn mark_restored_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    let Some((version_seq, origin)) = current_version_seq(tx, group_id, path)? else {
        return Ok(());
    };
    let changed = tx
        .prepare_cached(
            "UPDATE activity_events SET kind = 'restored' WHERE group_id = ?1 AND path = ?2 \
             AND version_seq = ?3",
        )?
        .execute(params![group_id, path, version_seq])?;
    if changed == 0 {
        let kind: String = tx
            .prepare_cached(
                "SELECT record_kind FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            )?
            .query_row(params![group_id, path], |r| r.get(0))?;
        if kind != "directory" {
            insert_in_tx(tx, group_id, path, ActivityKind::Restored, origin.as_deref())?;
        }
    }
    Ok(())
}

impl FileIndexRepository {
    /// Events newest first, honoring `query`. `local_device_id` decides what
    /// "this device" means for [`ActivityOrigin`].
    ///
    /// # Errors
    /// Database failures.
    pub fn list_activity(
        &self,
        query: &ActivityQuery,
        local_device_id: &str,
    ) -> Result<Vec<ActivityEvent>, SyncSqliteError> {
        if query.group_ids.is_empty() {
            return Ok(Vec::new());
        }
        let limit = i64::from(query.limit.clamp(1, MAX_PAGE));
        self.database().read::<_, SyncSqliteError>(|conn| {
            let mut sql = String::from(
                "SELECT id, group_id, path, kind, origin_device_id, at_unix_nanos \
                 FROM activity_events WHERE id < ?1 AND group_id IN (",
            );
            let mut args: Vec<rusqlite::types::Value> =
                vec![query.before_id.unwrap_or(i64::MAX).into()];
            for (i, group) in query.group_ids.iter().enumerate() {
                sql.push_str(if i == 0 { "?" } else { ",?" });
                args.push(group.clone().into());
            }
            sql.push(')');
            if !query.kinds.is_empty() {
                sql.push_str(" AND kind IN (");
                for (i, kind) in query.kinds.iter().enumerate() {
                    sql.push_str(if i == 0 { "?" } else { ",?" });
                    args.push(kind.as_db_str().to_string().into());
                }
                sql.push(')');
            }
            match query.origin {
                ActivityOrigin::Any => {}
                ActivityOrigin::ThisDevice => {
                    sql.push_str(" AND (origin_device_id IS NULL OR origin_device_id = ?)");
                    args.push(local_device_id.to_string().into());
                }
                ActivityOrigin::OtherDevices => {
                    sql.push_str(" AND origin_device_id IS NOT NULL AND origin_device_id <> ?");
                    args.push(local_device_id.to_string().into());
                }
            }
            sql.push_str(" ORDER BY id DESC LIMIT ?");
            args.push(limit.into());
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(args), |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (id, group_id, path, kind, origin_device_id, at_unix_nanos) = row?;
                let Some(kind) = ActivityKind::from_db_str(&kind) else {
                    return Err(SyncSqliteError::CorruptState(format!(
                        "unknown activity kind {kind:?}"
                    )));
                };
                out.push(ActivityEvent {
                    id,
                    group_id,
                    path,
                    kind,
                    origin_device_id,
                    at_unix_nanos,
                });
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests;
