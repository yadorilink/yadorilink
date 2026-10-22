//! One `Arc<SyncDatabase>`, never a second pool/writer-gate of its own --
//! `pub fn new(database: Arc<SyncDatabase>) -> Self` is the only
//! constructor; there is no `open`.

use std::collections::HashSet;
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};
use yadorilink_replica_domain::file::{BlockInfo, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{DeltaHash, FolderGroupId, VersionHash};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;
use crate::types::{CurrentVersionSnapshot, RetainedVersion, RetainedVersionState};

/// Everything a caller can learn about a path's `state = 'current'` row
/// that a proof or a guard depends on, read as ONE statement.
///
/// They travel together on purpose. A path's version is not a stored
/// column -- it is derived from the row's own content columns (see
/// `FileVersion::compute_hash`) -- so reading "the version" and "the
/// materialization state" separately can observe two different rows if an
/// update lands between them, and a guard built that way would compare a
/// version from one incarnation against a state from another. The same
/// applies to a producer: what it writes and what its proof names have to
/// come from one incarnation, or the proof describes a state that was
/// never assembled anywhere.
#[derive(Debug, Clone)]
pub struct CanonicalCurrentRow {
    pub snapshot: CurrentVersionSnapshot,
    pub materialization_state:
        Option<yadorilink_replica_domain::session_state::MaterializationState>,
    /// The device that produced this row's content. Not part of version
    /// identity -- carried here because a caller that needs it needs it
    /// about the same incarnation as everything else, and a second
    /// `get_origin_device_id` read is a second incarnation.
    pub origin_device_id: Option<String>,
    /// Whether this row's symlink target points outside the linked root.
    /// Also not part of version identity, and carried for the same
    /// reason: it is decided together with `symlink_target`, so reading
    /// the two separately can pair a target with a flag computed for a
    /// different target.
    pub symlink_out_of_root: bool,
}

impl CanonicalCurrentRow {
    /// The version this row names, derived the one canonical way.
    pub fn version_hash(&self) -> VersionHash {
        yadorilink_replica_domain::session_state::CurrentVersionRecord::from(self.snapshot.clone())
            .to_file_version()
            .version_hash
    }
}

/// The current-row column list, in the order [`decode_current_row`] reads it.
const CURRENT_ROW_COLUMNS: &str = "size, mtime_unix_nanos, blocks_json, deleted, record_kind, \
     symlink_target, unix_mode, xattrs_json, materialization_state, origin_device_id, \
     symlink_out_of_root";

/// Decodes the [`CURRENT_ROW_COLUMNS`] starting at column `base` of `r`: the one place the
/// current row's columns are decoded, for the single-path and the set-based reads alike.
fn decode_current_row(
    r: &rusqlite::Row<'_>,
    base: usize,
    path: &str,
) -> Result<CanonicalCurrentRow, SyncSqliteError> {
    let size: u64 = r.get(base)?;
    let mtime: i64 = r.get(base + 1)?;
    let blocks_json: String = r.get(base + 2)?;
    let deleted: i64 = r.get(base + 3)?;
    let record_kind: String = r.get(base + 4)?;
    let symlink_target: Option<Vec<u8>> = r.get(base + 5)?;
    let unix_mode: i64 = r.get(base + 6)?;
    let xattrs_json: String = r.get(base + 7)?;
    let mstate: Option<String> = r.get(base + 8)?;
    let origin_device_id: Option<String> = r.get(base + 9)?;
    let symlink_out_of_root: i64 = r.get(base + 10)?;
    let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "stored block list for current version of {path} is corrupt: {error}"
        ))
    })?;
    Ok(CanonicalCurrentRow {
        snapshot: CurrentVersionSnapshot {
            blocks,
            size,
            mtime_unix_nanos: mtime,
            deleted: deleted != 0,
            record_kind: RecordKind::from_db_str(&record_kind),
            symlink_target,
            unix_mode: crate::file_index::decode_unix_mode_column(unix_mode),
            xattrs: crate::file_index::decode_xattrs_column(&xattrs_json)?,
        },
        materialization_state: mstate
            .as_deref()
            .map(yadorilink_replica_domain::session_state::MaterializationState::from_db_str),
        origin_device_id,
        symlink_out_of_root: symlink_out_of_root != 0,
    })
}

/// The canonical current-row read, over `&Connection` so a caller holding
/// an open `&Transaction` can use it too (a `&Transaction` derefs to
/// `&Connection`). Every reader of the current row goes through this, so
/// the column list and its decoding exist exactly once -- a second copy is
/// how a guard silently starts comparing something subtly different from
/// what the proof records.
pub fn read_canonical_current_row(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<CanonicalCurrentRow>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {CURRENT_ROW_COLUMNS} FROM files \
         WHERE group_id = ?1 AND path = ?2 AND state = 'current'"
    ))?;
    let mut rows = stmt.query(rusqlite::params![group_id, path])?;
    match rows.next()? {
        Some(row) => Ok(Some(decode_current_row(row, 0, path)?)),
        None => Ok(None),
    }
}

/// Paths bound per statement by the set-based reads, well under SQLite's variable limit.
pub(crate) const PATHS_PER_QUERY: usize = 500;

/// [`read_canonical_current_row`] for many paths in few statements: the current row of every
/// path of `paths` that has one, keyed by path. A path with no current row is absent.
pub fn read_canonical_current_rows(
    conn: &Connection,
    group_id: &str,
    paths: &[&str],
) -> Result<std::collections::HashMap<String, CanonicalCurrentRow>, SyncSqliteError> {
    let mut out = std::collections::HashMap::with_capacity(paths.len());
    for chunk in paths.chunks(PATHS_PER_QUERY) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT path, {CURRENT_ROW_COLUMNS} FROM files \
             WHERE group_id = ?1 AND state = 'current' AND path IN ({marks})"
        ))?;
        let params = std::iter::once(group_id).chain(chunk.iter().copied());
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            let path: String = row.get(0)?;
            let decoded = decode_current_row(row, 1, &path)?;
            out.insert(path, decoded);
        }
    }
    Ok(out)
}

pub struct SqliteSyncStore {
    database: Arc<SyncDatabase>,
}

impl SqliteSyncStore {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// The signed deltas the group's live native heads stand on, ascending by
    /// hash: one entry per distinct provenance, whatever number of paths it
    /// put.
    pub fn native_group_heads(&self, group_id: &str) -> Result<Vec<DeltaHash>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT provenance FROM native_heads WHERE group_id = ?1 \
                 ORDER BY provenance",
            )?;
            let rows = stmt.query_map([group_id], |row| row.get::<_, Vec<u8>>(0))?;
            let mut heads = Vec::new();
            for row in rows {
                let bytes = row?;
                let hash: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    SyncSqliteError::CorruptState("a native head provenance is not 32 bytes".into())
                })?;
                heads.push(DeltaHash(hash));
            }
            Ok(heads)
        })
    }

    /// Whether a content-addressed file version is present.
    pub fn has_file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let present: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
                    rusqlite::params![group.as_str(), &hash.0[..]],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(present.is_some())
        })
    }

    /// A stored file version decoded from its canonical bytes -- the block
    /// list, size, and metadata a change op only references by hash.
    pub fn file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let encoded: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT encoded FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
                    rusqlite::params![group.as_str(), &hash.0[..]],
                    |r| r.get(0),
                )
                .optional()?;
            match encoded {
                Some(bytes) => {
                    let version = FileVersion::from_canonical_encoding(&bytes).map_err(|_| {
                        SyncSqliteError::NotFound("stored file version is corrupt".into())
                    })?;
                    if version.version_hash != *hash {
                        return Err(SyncSqliteError::NotFound(
                            "stored file version hash does not match its key".into(),
                        ));
                    }
                    Ok(Some(version))
                }
                None => Ok(None),
            }
        })
    }

    /// Whether verified bytes for `block_hash` were actually obtained
    /// through `group_id`, independently of any peer-supplied metadata
    /// references.
    pub fn group_has_block_provenance(
        &self,
        group: &FolderGroupId,
        block_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM group_block_provenance \
                 WHERE group_id = ?1 AND block_hash = ?2)",
                rusqlite::params![group.as_str(), block_hash],
                |row| row.get(0),
            )?)
        })
    }

    /// Batched form of [`group_has_block_provenance`] -- a single
    /// `IN (...)` query instead of one round-trip per hash, so
    /// `ensure_blocks_present`'s dedup loop does not issue up to hundreds
    /// of separate SQLite queries for one large file (the same batching
    /// `present_blocks` uses). Returns the SUBSET of `block_hashes` that have
    /// recorded provenance for `group` -- callers check `set.contains(hash)`
    /// in place of a per-hash call. Empty input returns an empty set without
    /// touching the database (SQLite's `IN ()` is invalid syntax, and an
    /// empty query set is common at the tail of a mostly-deduped batch).
    pub fn group_has_block_provenance_batch(
        &self,
        group: &FolderGroupId,
        block_hashes: &[Vec<u8>],
    ) -> Result<HashSet<Vec<u8>>, SyncSqliteError> {
        if block_hashes.is_empty() {
            return Ok(HashSet::new());
        }
        // Bounded per statement, well under SQLite's bound-parameter limit,
        // however many hashes a caller asks about at once.
        const HASHES_PER_QUERY: usize = 500;
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut found = HashSet::with_capacity(block_hashes.len());
            for chunk in block_hashes.chunks(HASHES_PER_QUERY) {
                let placeholders =
                    std::iter::repeat_n("?", chunk.len()).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "SELECT block_hash FROM group_block_provenance \
                     WHERE group_id = ? AND block_hash IN ({placeholders})"
                );
                let mut stmt = conn.prepare(&sql)?;
                let mut params: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(1 + chunk.len());
                let group_str = group.as_str();
                params.push(&group_str);
                for hash in chunk {
                    params.push(hash);
                }
                let rows = stmt.query_map(params.as_slice(), |row| row.get::<_, Vec<u8>>(0))?;
                for row in rows {
                    found.insert(row?);
                }
            }
            Ok(found)
        })
    }

    /// spec "Version Listing": every retained version of `path` (current,
    /// superseded, and trashed alike), newest first.
    pub fn list_versions(
        &self,
        group: &FolderGroupId,
        path: &str,
    ) -> Result<Vec<RetainedVersion>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT version_seq, size, mtime_unix_nanos, blocks_json, deleted, state, \
                        origin_device_id, record_kind, symlink_target, unix_mode, xattrs_json \
                 FROM files WHERE group_id = ?1 AND path = ?2 ORDER BY version_seq DESC",
            )?;
            let rows = stmt.query_map(rusqlite::params![group.as_str(), path], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, Option<Vec<u8>>>(8)?,
                    r.get::<_, i64>(9)?,
                    r.get::<_, String>(10)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (
                    version_seq,
                    size,
                    mtime_unix_nanos,
                    blocks_json,
                    deleted,
                    state,
                    origin_device_id,
                    record_kind,
                    symlink_target,
                    unix_mode,
                    xattrs_json,
                ) = row?;
                let blocks: Vec<BlockInfo> =
                    serde_json::from_str(&blocks_json).map_err(|error| {
                        SyncSqliteError::CorruptState(format!(
                            "stored block list for {path} is corrupt: {error}"
                        ))
                    })?;
                out.push(RetainedVersion {
                    path: path.to_string(),
                    version_seq,
                    size,
                    mtime_unix_nanos,
                    blocks,
                    deleted: deleted != 0,
                    state: retained_version_state_from_db_str(&state)?,
                    origin_device_id,
                    record_kind: RecordKind::from_db_str(&record_kind),
                    symlink_target,
                    unix_mode: crate::file_index::decode_unix_mode_column(unix_mode),
                    xattrs: crate::file_index::decode_xattrs_column(&xattrs_json)?,
                });
            }
            Ok(out)
        })
    }

    /// See [`read_canonical_current_row`].
    ///
    /// The `state = 'current'` row of a file, read as one atomic statement.
    pub fn get_current_version_record(
        &self,
        group: &FolderGroupId,
        path: &str,
    ) -> Result<Option<CurrentVersionSnapshot>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(read_canonical_current_row(conn, group.as_str(), path)?.map(|row| row.snapshot))
        })
    }

    pub fn dag_get_file_version(
        &self,
        group_id: &str,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, SyncSqliteError> {
        self.file_version(&FolderGroupId(group_id.to_string()), hash)
    }

    pub fn dag_group_has_block_provenance(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.group_has_block_provenance(&FolderGroupId(group_id.to_string()), block_hash)
    }

    pub fn dag_group_has_block_provenance_batch(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<HashSet<Vec<u8>>, SyncSqliteError> {
        self.group_has_block_provenance_batch(&FolderGroupId(group_id.to_string()), block_hashes)
    }

    pub fn dag_get_current_version_record(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<
        Option<yadorilink_replica_domain::session_state::CurrentVersionRecord>,
        SyncSqliteError,
    > {
        Ok(self
            .get_current_version_record(&FolderGroupId(group_id.to_string()), path)?
            .map(Into::into))
    }

    pub fn dag_list_versions(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<yadorilink_replica_domain::session_state::VersionRecord>, SyncSqliteError> {
        Ok(self
            .list_versions(&FolderGroupId(group_id.to_string()), path)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Folder Rewind's read-only preview for `group_id` at `at_unix_nanos`
    /// -- see [`crate::rewind_plan::compute_rewind_plan`] for the full
    /// semantics, including what an [`yadorilink_replica_domain::rewind::
    /// RewindPathAction::Unavailable`] entry does and does not mean. Runs
    /// in one read snapshot, so its scans (the indexed paths and the
    /// erased, never re-indexed ones) describe a single instant; computes
    /// nothing and writes nothing.
    pub fn compute_rewind_plan(
        &self,
        group_id: &str,
        at_unix_nanos: i64,
        still_excluded: &dyn Fn(&str) -> bool,
    ) -> Result<yadorilink_replica_domain::rewind::RewindPlan, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            crate::rewind_plan::compute_rewind_plan(conn, group_id, at_unix_nanos, still_excluded)
        })
    }

    /// See [`crate::rewind_plan::erased_unindexed_paths`].
    pub fn rewind_erased_unindexed_paths(
        &self,
        group_id: &str,
        at_unix_nanos: i64,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::rewind_plan::erased_unindexed_paths(conn, group_id, at_unix_nanos)
        })
    }

    /// What the structural-directory ledger holds for `(group_id, path)`
    /// -- see [`crate::structural_origin`].
    pub fn dag_structural_directory_origin(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<crate::structural_origin::StructuralDirectoryOrigin, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::structural_directory_origin(conn, group_id, path)
        })
    }

    /// Phase 1 of a structural `mkdir`, committed on its own before the
    /// syscall -- [`crate::structural_origin::record_structural_intent`].
    pub fn dag_record_structural_intent(
        &self,
        group_id: &str,
        path: &str,
        now_unix_nanos: i64,
    ) -> Result<crate::structural_origin::StructuralIntent, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::structural_origin::record_structural_intent(tx, group_id, path, now_unix_nanos)
        })
    }

    /// Phase 2 of a structural `mkdir` that created the directory --
    /// [`crate::structural_origin::complete_structural_origin`].
    pub fn dag_complete_structural_origin(
        &self,
        group_id: &str,
        path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
        now_unix_nanos: i64,
    ) -> Result<crate::structural_origin::StructuralOriginCompletion, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::structural_origin::complete_structural_origin(
                tx,
                group_id,
                path,
                identity,
                now_unix_nanos,
            )
        })
    }

    /// Phase 2 of a structural `mkdir` that found the name taken --
    /// [`crate::structural_origin::abandon_structural_intent`].
    pub fn dag_abandon_structural_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::abandon_structural_intent(conn, group_id, path)
        })
    }

    /// Recovery of interrupted structural `mkdir`s --
    /// [`crate::structural_origin::drop_unresolved_structural_intents`].
    pub fn dag_drop_unresolved_structural_intents(
        &self,
    ) -> Result<Vec<(String, String)>, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::drop_unresolved_structural_intents(conn)
        })
    }

    /// The structural intents of `group_id` (all groups when `None`)
    /// -- [`crate::structural_origin::list_unresolved_structural_intents`].
    pub fn dag_list_unresolved_structural_intents(
        &self,
        group_id: Option<&str>,
    ) -> Result<Vec<crate::structural_origin::UnresolvedStructuralIntent>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::list_unresolved_structural_intents(conn, group_id)
        })
    }

    /// Recovery of interrupted structural `mkdir`s, all in one transaction:
    /// each intent dropped (if still pending) together with the lost
    /// provenance of the directory found at its path --
    /// [`crate::structural_origin::drop_structural_intent_recording_lost_provenance`].
    /// Returns the `(group_id, path)` pairs dropped.
    pub fn dag_drop_structural_intents_recording_lost_provenance(
        &self,
        resolutions: &[(
            crate::structural_origin::UnresolvedStructuralIntent,
            Option<yadorilink_fs_platform::fs_identity::FileIdentity>,
        )],
        now_unix_nanos: i64,
    ) -> Result<Vec<(String, String)>, SyncSqliteError> {
        if resolutions.is_empty() {
            return Ok(Vec::new());
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let mut dropped = Vec::new();
            for (intent, found) in resolutions {
                if crate::structural_origin::drop_structural_intent_recording_lost_provenance(
                    tx,
                    intent,
                    found.as_ref(),
                    now_unix_nanos,
                )? {
                    dropped.push((intent.group_id.clone(), intent.path.clone()));
                }
            }
            Ok(dropped)
        })
    }

    /// Records an existing directory as structural once its explicit
    /// entry is deleted while live descendants keep it on disk --
    /// [`crate::structural_origin::adopt_structural_directory`].
    pub fn dag_adopt_structural_directory(
        &self,
        group_id: &str,
        path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
        now_unix_nanos: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::adopt_structural_directory(
                conn,
                group_id,
                path,
                identity,
                now_unix_nanos,
            )
        })
    }

    /// Follows a structural directory a rename moved --
    /// [`crate::structural_origin::rekey_structural_origin`].
    pub fn dag_rekey_structural_origin(
        &self,
        group_id: &str,
        to_path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
        birth_time_granularity: yadorilink_fs_platform::fs_identity::TimestampGranularity,
        now_unix_nanos: i64,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::rekey_structural_origin(
                conn,
                group_id,
                to_path,
                identity,
                birth_time_granularity,
                now_unix_nanos,
            )
        })
    }

    /// Drops the structural-origin record for a directory that is gone --
    /// [`crate::structural_origin::forget_structural_origin`].
    pub fn dag_forget_structural_origin(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::forget_structural_origin(conn, group_id, path)
        })
    }

    /// Whether anything strictly below `path` holds a live head --
    /// [`crate::native_store::native_has_descendant_head`].
    pub fn dag_has_live_descendant(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::native_store::native_has_descendant_head(
                conn,
                &FolderGroupId(group_id.to_owned()),
                &yadorilink_replica_domain::ids::SyncPath(path.to_owned()),
            )
        })
    }

    /// Records a directory kept on disk although its entry is deleted --
    /// [`crate::structural_origin::record_retained_directory`].
    pub fn record_retained_directory(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        removable: Option<&yadorilink_fs_platform::fs_identity::FileIdentity>,
        now_unix_nanos: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::record_retained_directory(
                conn,
                group_id,
                path,
                reason,
                removable,
                now_unix_nanos,
            )
        })
    }

    /// The retained-directory record for `path` --
    /// [`crate::structural_origin::retained_directory`].
    pub fn retained_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<crate::structural_origin::RetainedDirectory, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::retained_directory(conn, group_id, path)
        })
    }

    /// Drops the retained-directory record for `path` --
    /// [`crate::structural_origin::clear_retained_directory`].
    pub fn clear_retained_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::clear_retained_directory(conn, group_id, path)
        })
    }

    /// Every path retained for `reason` --
    /// [`crate::structural_origin::retained_paths_with_reason`].
    pub fn retained_paths_with_reason(
        &self,
        group_id: &str,
        reason: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::retained_paths_with_reason(conn, group_id, reason)
        })
    }

    /// The reason a directory at `path` is retained, if it is.
    pub fn retained_directory_reason(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::structural_origin::retained_directory_reason(conn, group_id, path)
        })
    }

    /// The fail-closed read entry point for `(group_id, path)`'s
    /// actual-state proof (`materialized_generation::
    /// lookup_materialized_generation`'s own doc comment) -- `None` unless
    /// `published_under_mutation_generation` still equals the path's live
    /// mutation fence. A test-facing delegate (this crate's own tests
    /// already exercise the free function directly; this is for callers
    /// outside this crate, e.g. `yadorilink-peer-session`'s integration
    /// tests asserting what the publication boundary actually wrote).
    pub fn dag_lookup_materialized_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<crate::materialized_generation::DiskGenerationBasis>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::materialized_generation::lookup_materialized_generation(conn, group_id, path)
        })
    }

    /// Whether the regular file at `out_path` is, untouched, what a usable
    /// proof says this device wrote at `(group_id, path)` -- whichever
    /// version the row now names. `MaterializationState::Present` says only
    /// that an object exists; this is the evidence that tells an older
    /// version's bytes still sitting under a newer row (the daemon's own
    /// write, unmodified since) from bytes someone else put there.
    /// Fail-closed: no usable proof, a proof of anything but a regular file,
    /// a changed identity or metadata token, or any error observing the path
    /// is `false`.
    pub fn disk_is_untouched_proven_write_at(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        birth_time_granularity: yadorilink_fs_platform::fs_identity::TimestampGranularity,
    ) -> Result<bool, SyncSqliteError> {
        use crate::materialized_generation::{
            revalidate_identity_against_disk, IdentityRevalidation, MaterializedObjectKind,
        };
        let Some(basis) = self.dag_lookup_materialized_generation(group_id, path)? else {
            return Ok(false);
        };
        if basis.object_kind != MaterializedObjectKind::RegularFile {
            return Ok(false);
        }
        Ok(revalidate_identity_against_disk(&basis, out_path, birth_time_granularity)
            == IdentityRevalidation::Confirmed)
    }

    /// The filesystem identity of the directory most recently published as
    /// materialized for the explicit Directory entry at `(group_id, path)`,
    /// read without the fence check: a later fence bump says the proof no
    /// longer vouches for the path's content, but not that the object it
    /// names was ever a different one. `None` when the last publication for
    /// the path was not an explicit directory, or recorded no identity.
    pub fn dag_materialized_directory_identity(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_fs_platform::fs_identity::FileIdentity>, SyncSqliteError> {
        use crate::materialized_generation::MaterializedObjectKind;
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(crate::materialized_generation::lookup_materialized_generation_diagnostic(
                conn, group_id, path,
            )?
            .filter(|basis| basis.object_kind == MaterializedObjectKind::Directory)
            .and_then(|basis| basis.filesystem_identity))
        })
    }

    /// Whether the proof standing for `(group_id, path)` is a proof about
    /// the version the row currently names -- see
    /// [`crate::exact_materialized_commit::usable_proof_names_current_version`]
    /// for why "a proof exists" is the answer to a different question.
    pub fn dag_usable_proof_names_current_version(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::exact_materialized_commit::usable_proof_names_current_version(
                conn, group_id, path,
            )
        })
    }

    /// Of `paths`, the settled regular files: `Present`, with a usable proof
    /// naming the current version. See
    /// [`crate::exact_materialized_commit::settled_file_paths`].
    pub fn settled_file_paths(
        &self,
        group_id: &str,
        paths: &[&str],
    ) -> Result<std::collections::HashSet<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::exact_materialized_commit::settled_file_paths(conn, group_id, paths)
        })
    }

    /// [`Self::dag_desired_projected_path_state_hash`] from native state:
    /// what native requires at `path`, as the state a materialization proof
    /// records. `NotFound` when a live head's version is not held here (the
    /// path is undecidable, never absent). A write transaction: the plan
    /// assigns placements for what is new on the way.
    pub fn native_desired_projected_path_state_hash(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<[u8; 32], SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::native_desired_state::native_desired_projected_path_state_hash(
                tx, group_id, path,
            )
        })
    }

    /// [`Self::dag_desired_path_state`] from native state (see
    /// [`Self::native_desired_projected_path_state_hash`]).
    pub fn native_desired_path_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<crate::desired_state::DesiredPathState, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::native_desired_state::native_desired_path_state(tx, group_id, path)
        })
    }

    /// How many projection obligations for `group_id` are still pending --
    /// the "outstanding work" count a convergence diagnostic wants, now that
    /// scheduling has exactly one ledger.
    pub fn dag_count_pending_projection_obligations(
        &self,
        group_id: &str,
    ) -> Result<u64, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM projection_obligations \
                 WHERE group_id = ?1 AND state = 'pending'",
                [group_id],
                |r| r.get(0),
            )?;
            Ok(count as u64)
        })
    }

    /// Test-facing read of one path's projection obligation, for callers
    /// outside this crate that need to
    /// assert an obligation was neither touched nor closed by an event at
    /// another layer.
    pub fn dag_lookup_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<crate::projection_obligations::ProjectionObligation>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::lookup_projection_obligation(conn, group_id, path)
        })
    }

    /// Test-facing delegate for
    /// [`crate::projection_obligations::bump_projection_obligations_for_touched_paths`]
    /// -- production admission reaches that free function directly (this
    /// wrapper is for callers outside this crate, e.g. an integration test
    /// that needs a path to have an outstanding, "not yet settled"
    /// obligation without driving a full signed delta admission).
    pub fn dag_bump_projection_obligations_for_touched_paths(
        &self,
        group_id: &str,
        touched_paths: &[&str],
        now_unix_nanos: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                tx,
                group_id,
                touched_paths,
                now_unix_nanos,
            )
        })
    }

    /// Test-facing and scheduler-facing delegate for the
    /// `projection_obligations` claim mechanism. A plain read, exactly like
    /// [`crate::projection_obligations::claim_runnable_obligations`] itself
    /// -- see that function's own doc comment for why no in-flight marking
    /// is needed here.
    pub fn dag_claim_runnable_obligations(
        &self,
        now_unix_nanos: i64,
        per_group_limit: u32,
        total_limit: u32,
    ) -> Result<Vec<crate::projection_obligations::ClaimedObligation>, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::claim_runnable_obligations(
                conn,
                now_unix_nanos,
                per_group_limit,
                total_limit,
            )
        })
    }

    /// Delegate for [`crate::projection_obligations::mark_obligation_attempt_failed`].
    pub fn dag_mark_obligation_attempt_failed(
        &self,
        group_id: &str,
        path: &str,
        claimed_invalidation_generation: i64,
        claimed_obligation_incarnation: i64,
        next_attempt_at: i64,
        now_unix_nanos: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::mark_obligation_attempt_failed(
                conn,
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation,
                next_attempt_at,
                now_unix_nanos,
            )
        })
    }

    /// Delegate for [`crate::projection_obligations::defer_obligation_without_penalty`].
    pub fn dag_defer_obligation_without_penalty(
        &self,
        group_id: &str,
        path: &str,
        claimed_invalidation_generation: i64,
        claimed_obligation_incarnation: i64,
        next_attempt_at: i64,
        now_unix_nanos: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::defer_obligation_without_penalty(
                conn,
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation,
                next_attempt_at,
                now_unix_nanos,
            )
        })
    }

    /// Scheduler-facing delegate for the exact-outcome
    /// compound completion. Runs inside `write_immediate`, never a plain
    /// `write` -- see
    /// [`crate::projection_obligations::complete_obligation_if_exact_proof_current`]'s
    /// own doc comment for why this specific atomicity level is required.
    pub fn dag_complete_obligation_if_exact_proof_current(
        &self,
        group_id: &str,
        path: &str,
        claimed_invalidation_generation: i64,
        claimed_obligation_incarnation: i64,
        desired_resolved_path_state_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::projection_obligations::complete_obligation_if_exact_proof_current(
                tx,
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation,
                desired_resolved_path_state_hash,
            )
        })
    }

    /// Scheduler-facing delegate for the zero-work close, which also
    /// re-anchors the proof it closes against on the current frontier --
    /// see [`crate::exact_materialized_commit::
    /// complete_zero_work_obligation_rebasing_proof`] for why closing alone
    /// leaves the next local edit of the path concurrent with what the
    /// close accepted.
    pub fn dag_complete_zero_work_obligation_rebasing_proof(
        &self,
        group_id: &str,
        path: &str,
        claimed_invalidation_generation: i64,
        claimed_obligation_incarnation: i64,
        desired_resolved_path_state_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::exact_materialized_commit::complete_zero_work_obligation_rebasing_proof(
                tx,
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation,
                desired_resolved_path_state_hash,
                crate::dag_store::now_unix_nanos(),
            )
        })
    }

    /// Scheduler-facing delegate for the non-exact-outcome
    /// compound completion. Same `write_immediate` requirement as
    /// [`Self::dag_complete_obligation_if_exact_proof_current`].
    pub fn dag_complete_obligation_if_non_exact_proof_current(
        &self,
        group_id: &str,
        path: &str,
        claimed_invalidation_generation: i64,
        claimed_obligation_incarnation: i64,
        proof: crate::projection_obligations::NonExactProofKind,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::projection_obligations::complete_obligation_if_non_exact_proof_current(
                tx,
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation,
                proof,
            )
        })
    }

    /// Delegate for [`crate::projection_obligations::list_ignore_blocked_paths`].
    pub fn dag_list_ignore_blocked_paths(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::list_ignore_blocked_paths(conn, group_id)
        })
    }

    /// Delegate for [`crate::projection_obligations::rearm_ignore_blocked_obligation`].
    pub fn dag_rearm_ignore_blocked_obligation(
        &self,
        group_id: &str,
        path: &str,
        now_unix_nanos: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::rearm_ignore_blocked_obligation(
                conn,
                group_id,
                path,
                now_unix_nanos,
            )
        })
    }
}

fn retained_version_state_from_db_str(s: &str) -> Result<RetainedVersionState, SyncSqliteError> {
    match s {
        "current" => Ok(RetainedVersionState::Current),
        "superseded" => Ok(RetainedVersionState::Superseded),
        "trashed" => Ok(RetainedVersionState::Trashed),
        other => Err(SyncSqliteError::CorruptState(format!("unknown files.state value {other:?}"))),
    }
}

#[cfg(test)]
mod tests;
