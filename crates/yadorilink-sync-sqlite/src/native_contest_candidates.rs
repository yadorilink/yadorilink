//! The paths whose replicated state is contested right now, kept so that
//! nothing reads the whole group to find them.
//!
//! A path is contested when its live heads are distinct file versions, or a
//! file head holds a path that a live descendant requires as a directory
//! (`Pending(DistinctVersions | DirectoryRequired)` in
//! [`yadorilink_replica_domain::native_project`]). Heads change only at the
//! paths a delta names, so only those paths and their ancestors can start or
//! stop being contested: every install and every arrival of a version record
//! re-judges exactly them. The set is derived data of the replicated state
//! and follows it when a checkpoint replaces that state.
//!
//! `attempted` records that a fork pass has already looked at the row and had
//! nothing it could do for it (the loser's author has to act, or a record has
//! to arrive); a new delta at the path resets it.

use std::collections::{BTreeSet, HashMap};

use rusqlite::Connection;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_project::{project_path, PendingReason, Projection};
use yadorilink_replica_domain::native_state::LiveHead;

use crate::error::SyncSqliteError;

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS native_contest_candidate (
            group_id TEXT NOT NULL,
            path TEXT NOT NULL,
            attempted INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, path)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

fn ancestors_and_self(path: &str) -> Vec<&str> {
    let mut out = vec![path];
    let mut current = path;
    while let Some((parent, _)) = current.rsplit_once('/') {
        out.push(parent);
        current = parent;
    }
    out
}

/// Whether `path` is contested in the state the connection sees.
fn is_contested(
    conn: &Connection,
    group_id: &FolderGroupId,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    let sync = SyncPath(path.to_owned());
    let heads = crate::native_store::native_heads_at(conn, group_id, &sync)?;
    if heads.is_empty() {
        return Ok(false);
    }
    let mut kinds: HashMap<VersionHash, Option<RecordKind>> = HashMap::new();
    for head in &heads {
        if let std::collections::hash_map::Entry::Vacant(slot) = kinds.entry(head.payload.version) {
            let kind =
                crate::dag_store::get_file_version(conn, group_id.as_str(), &head.payload.version)?
                    .map(|version| version.meta.record_kind);
            slot.insert(kind);
        }
    }
    let has_descendant = crate::native_store::native_has_descendant_head(conn, group_id, &sync)?;
    let live = heads.into_iter().map(|head| LiveHead { dot: head.dot, payload: head.payload });
    Ok(matches!(
        project_path(live, |version| kinds.get(version).copied().flatten(), has_descendant),
        Projection::Pending(PendingReason::DistinctVersions | PendingReason::DirectoryRequired)
    ))
}

/// Re-judges `paths` and their ancestors after the heads at `paths` changed:
/// a contested one becomes a candidate (not yet attempted), one that is not
/// stops being one.
pub fn note(conn: &Connection, group_id: &str, paths: &[&str]) -> Result<(), SyncSqliteError> {
    let group = FolderGroupId(group_id.to_owned());
    let mut judged: BTreeSet<&str> = BTreeSet::new();
    for path in paths {
        for candidate in ancestors_and_self(path) {
            if candidate.is_empty() || !judged.insert(candidate) {
                continue;
            }
            if is_contested(conn, &group, candidate)? {
                conn.prepare_cached(
                    "INSERT INTO native_contest_candidate (group_id, path, attempted) \
                     VALUES (?1, ?2, 0) \
                     ON CONFLICT(group_id, path) DO UPDATE SET attempted = 0",
                )?
                .execute(rusqlite::params![group_id, candidate])?;
            } else {
                conn.prepare_cached(
                    "DELETE FROM native_contest_candidate WHERE group_id = ?1 AND path = ?2",
                )?
                .execute(rusqlite::params![group_id, candidate])?;
            }
        }
    }
    Ok(())
}

/// Whether a fork pass has anything new to look at.
pub fn has_unattempted(conn: &Connection, group_id: &str) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .prepare_cached(
            "SELECT 1 FROM native_contest_candidate \
             WHERE group_id = ?1 AND attempted = 0 LIMIT 1",
        )?
        .exists([group_id])?)
}

/// Ends a fork pass: the candidates that are no longer contested go, and the
/// rest are marked as looked at.
pub fn finish_attempt(conn: &Connection, group_id: &str) -> Result<(), SyncSqliteError> {
    let group = FolderGroupId(group_id.to_owned());
    let candidates: Vec<String> = conn
        .prepare_cached("SELECT path FROM native_contest_candidate WHERE group_id = ?1")?
        .query_map([group_id], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    for path in candidates {
        if !is_contested(conn, &group, &path)? {
            conn.prepare_cached(
                "DELETE FROM native_contest_candidate WHERE group_id = ?1 AND path = ?2",
            )?
            .execute(rusqlite::params![group_id, path])?;
        }
    }
    conn.prepare_cached("UPDATE native_contest_candidate SET attempted = 1 WHERE group_id = ?1")?
        .execute([group_id])?;
    Ok(())
}

/// Makes every candidate of the group worth another fork pass: what a pass
/// may do depends on the verified policy, which changed.
pub fn reset_attempts(conn: &Connection, group_id: &str) -> Result<(), SyncSqliteError> {
    conn.prepare_cached("UPDATE native_contest_candidate SET attempted = 0 WHERE group_id = ?1")?
        .execute([group_id])?;
    Ok(())
}

/// How many contested paths the group has now.
pub fn count(conn: &Connection, group_id: &str) -> Result<u64, SyncSqliteError> {
    let count: i64 = conn
        .prepare_cached("SELECT COUNT(*) FROM native_contest_candidate WHERE group_id = ?1")?
        .query_row([group_id], |row| row.get(0))?;
    Ok(count as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::file::{FileMeta, FileVersion};
    use yadorilink_replica_domain::ids::DeviceId;
    use yadorilink_replica_domain::native_fork::copy_path;
    use yadorilink_replica_domain::native_state::{DeltaHash, HeadPayload, NativeState};

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&c).unwrap();
        c
    }

    fn author(name: &str) -> AuthorId {
        AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([1; 16]) }
    }

    fn version(mtime: i64) -> FileVersion {
        FileVersion::new(
            Vec::new(),
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: Some(0o644),
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    }

    fn payload(v: &FileVersion, tag: u8) -> HeadPayload {
        HeadPayload { version: v.version_hash, provenance: DeltaHash([tag; 32]) }
    }

    /// A replica that is not the loser's author (a viewer, or a writer whose
    /// peer has not acted) keeps the path pending and shows it in the status
    /// count; the loser author's fork, once it arrives, settles it.
    #[test]
    fn a_replica_that_cannot_act_shows_the_contest_until_the_fork_arrives() {
        let c = conn();
        let (v1, v2) = (version(1), version(2));
        for v in [&v1, &v2] {
            crate::dag_store::put_file_version(&c, "g", v).unwrap();
        }
        let group = FolderGroupId("g".into());
        let (a, b) = (author("a"), author("b"));
        let mut state = NativeState::new();
        state.put(&a, SyncPath("x".into()), &[], payload(&v1, 1)).unwrap();
        state.put(&b, SyncPath("x".into()), &[], payload(&v2, 2)).unwrap();
        crate::native_store::install_state(&c, &group, &state).unwrap();
        note(&c, "g", &["x"]).unwrap();

        assert_eq!(count(&c, "g").unwrap(), 1, "the contest is shown");
        assert!(has_unattempted(&c, "g").unwrap());
        // A pass that could do nothing marks it looked at, and keeps showing it.
        finish_attempt(&c, "g").unwrap();
        assert_eq!(count(&c, "g").unwrap(), 1);
        assert!(!has_unattempted(&c, "g").unwrap());

        // The loser's author moves its head: a delta at x and at the copy.
        let loser = if v1.version_hash < v2.version_hash { (&a, &v1, 1u8) } else { (&b, &v2, 2u8) };
        let copy = copy_path("x", &loser.1.version_hash);
        let dot = crate::native_store::native_heads_at(&c, &group, &SyncPath("x".into()))
            .unwrap()
            .into_iter()
            .find(|h| h.dot.author == *loser.0)
            .unwrap()
            .dot;
        let mut after = crate::native_store::load_state(&c, &group).unwrap();
        after.delete(loser.0, SyncPath("x".into()), &[dot]).unwrap();
        after.put(loser.0, SyncPath(copy.clone()), &[], payload(loser.1, loser.2 + 10)).unwrap();
        crate::native_store::install_state(&c, &group, &after).unwrap();
        note(&c, "g", &["x", copy.as_str()]).unwrap();

        assert_eq!(count(&c, "g").unwrap(), 0, "the fork settled the path");
    }

    #[test]
    fn a_new_closure_or_policy_makes_every_contest_worth_another_look() {
        let c = conn();
        let (v1, v2) = (version(1), version(2));
        for v in [&v1, &v2] {
            crate::dag_store::put_file_version(&c, "g", v).unwrap();
        }
        let group = FolderGroupId("g".into());
        let mut state = NativeState::new();
        state.put(&author("a"), SyncPath("x".into()), &[], payload(&v1, 1)).unwrap();
        state.put(&author("b"), SyncPath("x".into()), &[], payload(&v2, 2)).unwrap();
        crate::native_store::install_state(&c, &group, &state).unwrap();
        note(&c, "g", &["x"]).unwrap();
        finish_attempt(&c, "g").unwrap();
        assert!(!has_unattempted(&c, "g").unwrap());

        reset_attempts(&c, "g").unwrap();

        assert!(has_unattempted(&c, "g").unwrap());
    }
}
