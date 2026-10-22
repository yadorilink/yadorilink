//! Value types this crate returns from its own retained-version reads.

use yadorilink_replica_domain::file::{BlockInfo, RecordKind};

/// Which of a path's retained rows this one is -- mirrors the `files.state`
/// column's three values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedVersionState {
    /// The live version of the file at this path right now (or, if the
    /// file is deleted, the tombstone itself).
    Current,
    /// A version this file had before a later edit (local or adopted)
    /// superseded it.
    Superseded,
    /// The file's last live content before it was deleted -- recoverable
    /// via `trash restore` until retention expires.
    Trashed,
}

/// One retained version of a file -- every column
/// `yadorilink_replica_domain::file::FileVersion::from_index_row` needs to
/// reconstruct the version's canonical identity, plus the per-row metadata
/// (`path`/`version_seq`/`state`/`origin_device_id`) that identity alone
/// doesn't carry.
#[derive(Debug, Clone, PartialEq)]
pub struct RetainedVersion {
    pub path: String,
    pub version_seq: i64,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub blocks: Vec<BlockInfo>,
    pub deleted: bool,
    pub state: RetainedVersionState,
    pub origin_device_id: Option<String>,
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
}

/// The `state = 'current'` row of a file, read as one atomic statement --
/// every column a `FileVersion` identity binds, from a single coherent row
/// so the derived identity can never be a torn hybrid of two rows.
#[derive(Debug, Clone, PartialEq)]
pub struct CurrentVersionSnapshot {
    pub blocks: Vec<BlockInfo>,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub deleted: bool,
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
}

/// Written here rather than at either caller's own boundary since
/// `yadorilink_replica_domain::session_state::CurrentVersionRecord` is
/// foreign to both of them but local to neither -- this crate already
/// depends on `yadorilink-replica-domain`, so it's the only crate that can
/// legally own this `From` impl (Rust's orphan rule).
impl From<CurrentVersionSnapshot>
    for yadorilink_replica_domain::session_state::CurrentVersionRecord
{
    fn from(snapshot: CurrentVersionSnapshot) -> Self {
        Self {
            blocks: snapshot.blocks,
            size: snapshot.size,
            mtime_unix_nanos: snapshot.mtime_unix_nanos,
            deleted: snapshot.deleted,
            record_kind: snapshot.record_kind,
            symlink_target: snapshot.symlink_target,
            unix_mode: snapshot.unix_mode,
            xattrs: snapshot.xattrs,
        }
    }
}

/// Field-for-field rename, same reasoning as `CurrentVersionSnapshot`'s own
/// `From` impl above -- `version_hash` is a pure re-derivation via the same
/// `FileVersion::from_index_row` call a caller's own `version_record()`
/// helper used to make, not a new decision.
impl From<RetainedVersion> for yadorilink_replica_domain::session_state::VersionRecord {
    fn from(version: RetainedVersion) -> Self {
        use yadorilink_replica_domain::file::FileVersion;
        use yadorilink_replica_domain::session_state::VersionState;

        let version_hash = FileVersion::from_index_row(
            version.blocks.clone(),
            version.size,
            version.mtime_unix_nanos,
            version.record_kind,
            version.unix_mode,
            version.symlink_target.clone(),
            version.xattrs.clone(),
        )
        .version_hash;
        Self {
            path: version.path,
            version_seq: version.version_seq,
            size: version.size,
            mtime_unix_nanos: version.mtime_unix_nanos,
            blocks: version.blocks,
            deleted: version.deleted,
            state: match version.state {
                RetainedVersionState::Current => VersionState::Current,
                RetainedVersionState::Superseded => VersionState::Superseded,
                RetainedVersionState::Trashed => VersionState::Trashed,
            },
            origin_device_id: version.origin_device_id,
            record_kind: version.record_kind,
            symlink_target: version.symlink_target,
            unix_mode: version.unix_mode,
            xattrs: version.xattrs,
            version_hash,
        }
    }
}
