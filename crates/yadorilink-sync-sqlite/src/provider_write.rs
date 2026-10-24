//! The provider write path's transaction: one apply-change request keyed by item,
//! decided and committed in ONE immediate write transaction together with its operation record.
//!
//! What the transaction guarantees:
//!
//! * a replay of an operation returns the stored result and authors nothing; an operation whose
//!   result expired but whose identity is still marked processed is STALE, never a new change;
//! * every check that decides the outcome (the item, the base, name collisions of the folded
//!   name and the whole destination subtree, the delete bound) is made inside the transaction
//!   that writes, so nothing slips in between;
//! * an edit is authored against the version the user SAW (`BaseVersion`), not the row as it
//!   stands: a base the daemon does not know is an opaque stale base that supersedes no heads;
//!   an edit that is not provably made from the current version never changes it: its bytes are
//!   kept durably as a conflict-named file (an operation that carries bytes is never refused
//!   without keeping them);
//! * nothing is ever replaced: a name that is taken is a collision. A recursive directory delete
//!   deletes the subtree the user saw: the directory's echoed token covers its whole subtree (any
//!   descendant change, at any depth, advances it), so an entry added after the view makes the
//!   delete a stale view instead of being swept away unseen. A file
//!   delete destroys only an unambiguous view. A destination folder is an identity, not a view;
//! * no presence evidence is recorded here: what the OS holds is learned only from the ordinary
//!   handoff and membership route.

use std::collections::BTreeSet;

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use yadorilink_replica_domain::file::{
    BlockInfo, FileMeta, FileRecord, FileVersion, RecordKind, VersionBlock,
};
use yadorilink_replica_domain::ids::{BlockHash, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_state::{resolve_winner, NativeCaptureWitness};
use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::error::SyncSqliteError;
use crate::local_author::LocalAuthor;
use crate::provider::{mint_item_in_tx, ItemId, ProviderRepository};

/// How many stored results a root keeps, and for how long.
pub const APPLY_LOG_MAX_ENTRIES: i64 = 4096;
pub const APPLY_LOG_MAX_AGE_MS: i64 = 24 * 3600 * 1000;
/// A session with more processed sequence numbers above its floor than this has the lowest gaps
/// abandoned (the floor jumps over them).
const MAX_ABOVE: usize = 1024;
/// While an operation of the session has a journaled upload (undecided), the floor is held below it
/// and more processed sequences are remembered, up to this many; the session cap bounds the rest.
const MAX_ABOVE_PINNED: usize = 65_536;
const MAX_NAME_BYTES: usize = 255;
/// How many sessions (one small row each) a root remembers. A processed operation identity is
/// kept until the root is removed or rebootstrapped, never aged out, so a late replay of an old
/// unanswered operation can never be applied again; a new session beyond this is refused.
pub const MAX_SESSIONS_PER_ROOT: i64 = 64;
/// The default bound of one recursive delete (rows at and below the directory). The caller sets
/// the bound per request (`ApplyInput::max_subtree`), so it is a knob, not a constant of the
/// transaction.
pub const DEFAULT_MAX_SUBTREE: usize = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Create,
    Modify,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

impl EntryKind {
    fn of(kind: RecordKind) -> Self {
        match kind {
            RecordKind::File => Self::File,
            RecordKind::Directory => Self::Directory,
            RecordKind::Symlink => Self::Symlink,
        }
    }
}

/// The version the user saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseVersion {
    /// The extension named none: the base is UNKNOWN. Nothing is assumed for it (not the
    /// published version, not the current one): an edit is untrusted, a delete is ambiguous.
    Unknown,
    /// The version identifier the extension named (its 32-byte hash part): that version, known to
    /// the daemon or not.
    Opaque(VersionHash),
}

/// Bytes already ingested into the block store.
#[derive(Clone, Debug)]
pub struct ContentInput {
    pub blocks: Vec<BlockInfo>,
    pub size: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MetadataInput {
    pub unix_mode: Option<u32>,
    pub mtime_unix_nanos: Option<i64>,
    /// `Some`: the complete replicated xattr set.
    pub xattrs: Option<Vec<(String, Vec<u8>)>>,
}

#[derive(Clone, Debug)]
pub struct ApplyInput {
    pub root_id: String,
    pub session_id: Vec<u8>,
    pub operation_seq: u64,
    /// Hash of the operation's stable wire fields; a replay is compared by it.
    pub fingerprint: [u8; 32],
    pub kind: ChangeKind,
    pub item_id: Option<ItemId>,
    /// CREATE: the parent (`None` = the root). MODIFY: `None` = unchanged, `Some(None)` = move to
    /// the root, `Some(Some(id))` = move under that item.
    pub new_parent: Option<Option<ItemId>>,
    pub name: Option<String>,
    pub entry_kind: EntryKind,
    pub base: BaseVersion,
    pub content: Option<ContentInput>,
    pub symlink_target: Option<Vec<u8>>,
    pub metadata: MetadataInput,
    pub recursive: bool,
    /// The most rows (the directory and everything below it) one recursive delete may cover;
    /// above it the delete is refused before any row is read into memory.
    pub max_subtree: usize,
    /// The generations of what the OS saw: the item the operation is based on, the
    /// folder a rename or move LEAVES (its place generation), and the domain revision the OS had
    /// observed. ABSENT means UNKNOWN, and unknown is never trusted. A destination folder is an
    /// identity and carries no generation.
    pub base_generation: Option<u64>,
    pub parent_generation: Option<u64>,
    pub observed_revision: Option<u64>,
    pub now_ms: i64,
}

/// The item as the OS must adopt it, read back from the committed rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedItem {
    pub item_id: ItemId,
    pub parent_item_id: Option<ItemId>,
    pub name: String,
    pub kind: EntryKind,
    pub content_version: VersionHash,
    pub metadata_version: [u8; 32],
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub unix_mode: u32,
    pub current: bool,
    pub namespace_revision: u64,
    /// The item's generation: the OS-visible version identifiers carry it.
    pub generation: u64,
    /// The generation of the folder it is in (0 for the root container).
    pub parent_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutcomeKind {
    Applied,
    Concurrent,
    FileSurvived,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyResult {
    pub outcome: OutcomeKind,
    pub item: Option<AppliedItem>,
    /// This is the stored result of an operation applied before.
    pub replayed: bool,
}

#[derive(Serialize, Deserialize)]
struct StoredItem {
    item_id: [u8; 16],
    parent_item_id: Option<[u8; 16]>,
    name: String,
    kind: EntryKind,
    content_version: [u8; 32],
    metadata_version: [u8; 32],
    size: u64,
    mtime_unix_nanos: i64,
    unix_mode: u32,
    current: bool,
    namespace_revision: u64,
    #[serde(default = "first_generation")]
    generation: u64,
    #[serde(default)]
    parent_generation: u64,
}

fn first_generation() -> u64 {
    1
}

#[derive(Serialize, Deserialize)]
struct Stored {
    outcome: OutcomeKind,
    item: Option<StoredItem>,
}

impl From<&AppliedItem> for StoredItem {
    fn from(item: &AppliedItem) -> Self {
        Self {
            item_id: item.item_id,
            parent_item_id: item.parent_item_id,
            name: item.name.clone(),
            kind: item.kind,
            content_version: item.content_version.0,
            metadata_version: item.metadata_version,
            size: item.size,
            mtime_unix_nanos: item.mtime_unix_nanos,
            unix_mode: item.unix_mode,
            current: item.current,
            namespace_revision: item.namespace_revision,
            generation: item.generation,
            parent_generation: item.parent_generation,
        }
    }
}

impl From<StoredItem> for AppliedItem {
    fn from(item: StoredItem) -> Self {
        Self {
            item_id: item.item_id,
            parent_item_id: item.parent_item_id,
            name: item.name,
            kind: item.kind,
            content_version: VersionHash(item.content_version),
            metadata_version: item.metadata_version,
            size: item.size,
            mtime_unix_nanos: item.mtime_unix_nanos,
            unix_mode: item.unix_mode,
            current: item.current,
            namespace_revision: item.namespace_revision,
            generation: item.generation,
            parent_generation: item.parent_generation,
        }
    }
}

#[derive(Debug)]
pub enum ApplyError {
    NotFound(String),
    InvalidName(String),
    NameCollision(String),
    DirectoryNotEmpty(String),
    /// A modify for a retired or unknown item, or an edit that would lose the resolution: nothing
    /// is authored; the bytes are re-sent as a new item. `path` is the path whose conflict-copy
    /// name the extension should use, when known.
    KeepLocal {
        path: Option<String>,
    },
    StaleOperation,
    OperationMismatch,
    /// A generation the operation names does not match the daemon's view (or none was named):
    /// nothing was authored; the OS refreshes and retries with a fresh view.
    StaleView(String),
    /// This device is not a writer of the group: its change would be rejected by every peer.
    NotAuthorized,
    /// The root remembers [`MAX_SESSIONS_PER_ROOT`] sessions already; this one is refused whole.
    TooManySessions,
    Retry(String),
    Db(SyncSqliteError),
}

impl ApplyError {
    /// Whether the database ran out of space (the commit failed, nothing was recorded).
    pub fn is_disk_full(&self) -> bool {
        // rusqlite names the code in its debug form (`DiskFull`); no variant is exposed through
        // the layers this error passes.
        matches!(self, Self::Db(error) if format!("{error:?}").contains("DiskFull"))
    }
}

impl From<SyncSqliteError> for ApplyError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Db(error)
    }
}

impl From<rusqlite::Error> for ApplyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error.into())
    }
}

impl From<r2d2::Error> for ApplyError {
    fn from(error: r2d2::Error) -> Self {
        Self::Db(error.into())
    }
}

impl yadorilink_sqlite_runtime::SqlOperationError for ApplyError {
    fn is_locked(&self) -> bool {
        match self {
            Self::Db(error) => error.is_locked(),
            _ => false,
        }
    }
}

type Tx<'a> = &'a rusqlite::Transaction<'a>;

impl ProviderRepository {
    /// Decides and commits one apply-change request (see the module documentation).
    pub fn apply_change(
        &self,
        input: &ApplyInput,
        author: &LocalAuthor<'_>,
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ApplyResult, ApplyError> {
        let decided = self.database_for_write().write_immediate::<_, ApplyError>(|tx| {
            let result = apply_in_tx(tx, input, author, origin_device_id, false)?;
            permit.verify().map_err(SyncSqliteError::from)?;
            Ok(result)
        });
        // NO refusal consumes the user's bytes: an operation that carries ingested bytes and is
        // refused for its view, a name or a retired target is decided again in a second
        // transaction that keeps those bytes durably as a conflict-named file.
        match decided {
            Err(
                ApplyError::StaleView(_)
                | ApplyError::KeepLocal { .. }
                | ApplyError::NameCollision(_)
                | ApplyError::NotFound(_)
                | ApplyError::InvalidName(_)
                | ApplyError::DirectoryNotEmpty(_),
            ) if input.content.is_some() && input.kind != ChangeKind::Delete => {
                self.database_for_write().write_immediate::<_, ApplyError>(|tx| {
                    let result = apply_in_tx(tx, input, author, origin_device_id, true)?;
                    permit.verify().map_err(SyncSqliteError::from)?;
                    Ok(result)
                })
            }
            other => other,
        }
    }
}

impl ProviderRepository {
    /// Journals the upload of an operation that carries bytes, by operation identity, before the
    /// first transaction: the copy is then never aged out as abandoned, and a retry finds it.
    pub fn journal_pending_ingest(
        &self,
        root_id: &str,
        session_id: &[u8],
        operation_seq: u64,
        ingest_name: &str,
        now_ms: i64,
    ) -> Result<(), ApplyError> {
        self.database_for_write().write_immediate::<_, ApplyError>(|tx| {
            tx.execute(
                "INSERT OR REPLACE INTO provider_pending_ingest \
                 (root_id, session_id, operation_seq, ingest_name, created_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![root_id, session_id, operation_seq as i64, ingest_name, now_ms],
            )?;
            Ok(())
        })
    }

    /// The upload journaled for the operation, if it is not decided yet.
    pub fn pending_ingest_name(
        &self,
        root_id: &str,
        session_id: &[u8],
        operation_seq: u64,
    ) -> Result<Option<String>, ApplyError> {
        self.database_for_write().read::<_, ApplyError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT ingest_name FROM provider_pending_ingest \
                     WHERE root_id = ?1 AND session_id = ?2 AND operation_seq = ?3",
                    rusqlite::params![root_id, session_id, operation_seq as i64],
                    |r| r.get(0),
                )
                .optional()?)
        })
    }

    /// The edits kept beside a file instead of replacing it: how many, and when the first was kept.
    pub fn kept_edits(&self, root_id: &str) -> Result<(u64, Option<i64>), ApplyError> {
        self.database_for_write().read::<_, ApplyError>(|conn| {
            let (count, first): (i64, Option<i64>) = conn
                .query_row(
                    "SELECT kept_edits, kept_edit_first_ms FROM provider_roots WHERE root_id = ?1",
                    [root_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .unwrap_or((0, None));
            Ok((count as u64, first))
        })
    }

    /// The operation was resolved without a decision of its own (a replay of an operation decided
    /// before): its journal row goes.
    pub fn clear_pending_ingest(
        &self,
        root_id: &str,
        session_id: &[u8],
        operation_seq: u64,
    ) -> Result<(), ApplyError> {
        self.database_for_write().write_immediate::<_, ApplyError>(|tx| {
            tx.execute(
                "DELETE FROM provider_pending_ingest \
                 WHERE root_id = ?1 AND session_id = ?2 AND operation_seq = ?3",
                rusqlite::params![root_id, session_id, operation_seq as i64],
            )?;
            Ok(())
        })
    }

    /// How many uploads are retained for undecided operations, and the age of the oldest (to be
    /// surfaced: they are bytes the user may still be waiting on).
    pub fn undecided_uploads(&self, now_ms: i64) -> Result<(u64, u64), ApplyError> {
        self.database_for_write().read::<_, ApplyError>(|conn| {
            let (count, oldest): (i64, Option<i64>) = conn.query_row(
                "SELECT COUNT(*), MIN(created_ms) FROM provider_pending_ingest",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok((count as u64, oldest.map_or(0, |at| (now_ms - at).max(0) as u64)))
        })
    }

    /// Journaled uploads whose root no longer exists (rebootstrap, last link removed): retained, never
    /// aged out, removed only by an explicit [`Self::clear_pending_ingest`]. Count and oldest age.
    pub fn orphaned_uploads(&self, now_ms: i64) -> Result<(u64, u64), ApplyError> {
        self.database_for_write().read::<_, ApplyError>(|conn| {
            let (count, oldest): (i64, Option<i64>) = conn.query_row(
                "SELECT COUNT(*), MIN(created_ms) FROM provider_pending_ingest p \
                 WHERE NOT EXISTS (SELECT 1 FROM provider_roots r WHERE r.root_id = p.root_id)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok((count as u64, oldest.map_or(0, |at| (now_ms - at).max(0) as u64)))
        })
    }

    /// Every upload name that belongs to an undecided operation (the age sweep keeps them).
    pub fn pending_ingest_names(&self) -> Result<std::collections::HashSet<String>, ApplyError> {
        self.database_for_write().read::<_, ApplyError>(|conn| {
            let mut stmt = conn.prepare("SELECT ingest_name FROM provider_pending_ingest")?;
            let names = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
            Ok(names)
        })
    }

    /// Whether the operation was already decided: its stored result (a replay: nothing is
    /// ingested or authored), `Err(OperationMismatch)` for the same identity with another
    /// fingerprint, `Err(StaleOperation)` for a processed operation whose result expired, and
    /// `Ok(None)` for a new operation.
    pub fn check_replay(
        &self,
        root_id: &str,
        session_id: &[u8],
        operation_seq: u64,
        fingerprint: &[u8; 32],
    ) -> Result<Option<ApplyResult>, ApplyError> {
        self.database_for_write().read::<_, ApplyError>(|conn| {
            replay_in(conn, root_id, session_id, operation_seq, fingerprint)
        })
    }
}

fn replay_in(
    conn: &rusqlite::Connection,
    root_id: &str,
    session_id: &[u8],
    operation_seq: u64,
    fingerprint: &[u8; 32],
) -> Result<Option<ApplyResult>, ApplyError> {
    let stored: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT fingerprint, result FROM provider_apply_log \
             WHERE root_id = ?1 AND session_id = ?2 AND operation_seq = ?3",
            rusqlite::params![root_id, session_id, operation_seq as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((stored_fingerprint, result)) = stored {
        if stored_fingerprint != fingerprint {
            return Err(ApplyError::OperationMismatch);
        }
        let stored: Stored = serde_json::from_slice(&result)
            .map_err(|e| ApplyError::Db(SyncSqliteError::CorruptState(e.to_string())))?;
        return Ok(Some(ApplyResult {
            outcome: stored.outcome,
            item: stored.item.map(AppliedItem::from),
            replayed: true,
        }));
    }
    if load_session(conn, root_id, session_id)?.processed(operation_seq) {
        // An operation with a journaled upload is UNDECIDED (its journal row is cleared in the
        // transaction that decides it): the session floor, which abandons gaps, never turns its
        // retry into a stale one.
        let undecided: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_pending_ingest \
             WHERE root_id = ?1 AND session_id = ?2 AND operation_seq = ?3)",
            rusqlite::params![root_id, session_id, operation_seq as i64],
            |r| r.get(0),
        )?;
        if !undecided {
            return Err(ApplyError::StaleOperation);
        }
    }
    Ok(None)
}

fn apply_in_tx(
    tx: &rusqlite::Transaction<'_>,
    input: &ApplyInput,
    author: &LocalAuthor<'_>,
    origin_device_id: &str,
    keep_refused: bool,
) -> Result<ApplyResult, ApplyError> {
    yadorilink_sqlite_runtime::reconcile_provider_liveness(tx)?;
    let group_id: String = tx
        .query_row(
            "SELECT group_id FROM provider_roots WHERE root_id = ?1",
            [&input.root_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| ApplyError::NotFound("unknown provider root".into()))?;

    // A replay: the stored result, never a re-authoring.
    if let Some(replayed) =
        replay_in(tx, &input.root_id, &input.session_id, input.operation_seq, &input.fingerprint)?
    {
        return Ok(replayed);
    }
    let session = load_session(tx, &input.root_id, &input.session_id)?;

    let result = if keep_refused {
        keep_refused_bytes(tx, input, &group_id, author, origin_device_id)?
    } else {
        check_view(tx, input, &group_id)?;
        match input.kind {
            ChangeKind::Create => create(tx, input, &group_id, author, origin_device_id)?,
            ChangeKind::Modify => modify(tx, input, &group_id, author, origin_device_id)?,
            ChangeKind::Delete => delete(tx, input, &group_id, author, origin_device_id)?,
        }
    };

    // The operation is recorded in the same transaction as its change.
    let stored = serde_json::to_vec(&Stored {
        outcome: result.outcome,
        item: result.item.as_ref().map(StoredItem::from),
    })
    .map_err(|e| ApplyError::Db(SyncSqliteError::CorruptState(e.to_string())))?;
    tx.execute(
        "INSERT INTO provider_apply_log \
         (root_id, session_id, operation_seq, fingerprint, result, created_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            input.root_id,
            input.session_id,
            input.operation_seq as i64,
            &input.fingerprint[..],
            stored,
            input.now_ms
        ],
    )?;
    // Decided: the journaled upload is resolved (its bytes are in the store and the log).
    tx.execute(
        "DELETE FROM provider_pending_ingest \
         WHERE root_id = ?1 AND session_id = ?2 AND operation_seq = ?3",
        rusqlite::params![input.root_id, input.session_id, input.operation_seq as i64],
    )?;
    let undecided_min: Option<i64> = tx.query_row(
        "SELECT MIN(operation_seq) FROM provider_pending_ingest \
         WHERE root_id = ?1 AND session_id = ?2",
        rusqlite::params![input.root_id, input.session_id],
        |r| r.get(0),
    )?;
    save_session(
        tx,
        &input.root_id,
        &input.session_id,
        session.with(input.operation_seq, undecided_min.map(|m| m as u64)),
        input.now_ms,
    )?;
    prune_log(tx, &input.root_id, input.now_ms)?;
    Ok(result)
}

// ---- the generations of the view an operation was made against ----

/// The generation of the live item at `path` (`None` for the root container or an unexposed
/// path: the OS cannot have named it).
/// The PLACE generation of the folder at `path`: its generation without the advances that were
/// only a change of its child set. A rename or move names the folder the user saw the item in by
/// this value; a sibling being added does not stale it.
fn generation_at(tx: Tx<'_>, root_id: &str, path: &str) -> Result<Option<u64>, ApplyError> {
    if path.is_empty() {
        return Ok(None);
    }
    Ok(tx
        .query_row(
            "SELECT generation - child_bumps FROM provider_items \
             WHERE root_id = ?1 AND path = ?2 AND live = 1",
            rusqlite::params![root_id, path],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .map(|g| g as u64))
}

fn stale(what: &str, named: Option<u64>, actual: u64) -> ApplyError {
    ApplyError::StaleView(match named {
        Some(named) => format!("{what} is at generation {actual}, the operation saw {named}"),
        None => format!("{what} is at generation {actual}, the operation named none"),
    })
}

/// The item an operation acts on, and the folder it LEAVES, are authored only against a KNOWN,
/// CURRENT view: the item carries the generation the OS saw (inside its token) and the source
/// folder its place generation; an absent generation is unknown, never trusted by the hash alone.
/// A mismatch authors nothing (the transaction rolls back, nothing is recorded) and the OS retries
/// after it refreshed. A DESTINATION folder is a stable identity, not a view: a create or move lands
/// in whatever the destination item id is now, and a destination that is retired
/// or unknown is `NotFound` where the bytes, if any, are kept.
/// A modify that renames and/or moves the item and carries no bytes, no symlink target and no
/// replicated mode or xattrs (an mtime may ride along: it is advisory, see [`advisory_mtime`]). It is a
/// namespace command on the item's identity ("rename or move the CURRENT entity of this item id"), not
/// a statement about a view the OS saw, so it carries no view requirement: neither the item's own
/// generation, nor the place generation of the folder it leaves, nor the observed revision, nor the
/// content version it saw. A modify that ALSO carries content, mode or xattrs is not structural-only
/// and keeps the strict path unchanged.
fn structural_only(input: &ApplyInput) -> bool {
    let moves = input.new_parent.is_some() || input.name.is_some();
    moves && !carries_semantic_edit(input)
}

/// Bytes, a symlink target, a replicated mode or xattrs: the edits that change what the item IS and
/// are decided by provenance and the view, never by identity.
fn carries_semantic_edit(input: &ApplyInput) -> bool {
    input.content.is_some()
        || input.symlink_target.is_some()
        || input.metadata.unix_mode.is_some()
        || input.metadata.xattrs.is_some()
}

/// A modify whose only replicated change is an mtime (with or without a rename or move). The mtime is
/// ADVISORY metadata: it is applied when the content the callback saw is the item's current content,
/// and DROPPED (the call still succeeds) when the content has changed since, so a stale mtime never
/// overwrites a newer version's and never raises an error the OS would badge.
fn advisory_mtime(input: &ApplyInput) -> bool {
    input.metadata.mtime_unix_nanos.is_some() && !carries_semantic_edit(input)
}

fn check_view(tx: Tx<'_>, input: &ApplyInput, group_id: &str) -> Result<(), ApplyError> {
    match input.kind {
        ChangeKind::Create => {}
        ChangeKind::Modify => {
            let item = input.item_id.ok_or_else(|| ApplyError::NotFound("no item".into()))?;
            let Some(row) = item_row(tx, &input.root_id, &item)?.filter(|r| r.live) else {
                return Ok(()); // a retired or unknown item is KEEP_LOCAL, decided by the caller
            };
            // Identity semantics (see `structural_only`) and advisory mtimes (see `advisory_mtime`):
            // nothing about the view is required.
            if structural_only(input) || advisory_mtime(input) {
                return Ok(());
            }
            let moves = input.new_parent.is_some() || input.name.is_some();
            // An edit that carries the user's bytes is never refused for its view: a stale or
            // unknown view makes it untrusted (`edit_base_trusted`), and `modify` then keeps the
            // bytes beside the item as a conflict copy, authored before anything is discarded.
            if (input.content.is_some() || input.symlink_target.is_some()) && !moves {
                return Ok(());
            }
            let actual = item_generation(tx, &input.root_id, &item)?;
            if input.base_generation != Some(actual) {
                return Err(stale("the item", input.base_generation, actual));
            }
            announced_after(tx, input, &item)?;
            if moves {
                // The folder it leaves.
                let (parent_path, _) = split(&row.path);
                if let Some(actual) = generation_at(tx, &input.root_id, parent_path)? {
                    if input.parent_generation != Some(actual) {
                        return Err(stale("the folder it leaves", input.parent_generation, actual));
                    }
                }
            }
        }
        ChangeKind::Delete => {}
    }
    let _ = group_id;
    Ok(())
}

/// The domain revision the OS had observed is a hint that can only tighten: an operation issued
/// before the announcement of the item's current version cannot have known it.
fn announced_after(tx: Tx<'_>, input: &ApplyInput, item: &ItemId) -> Result<(), ApplyError> {
    let announced: Option<i64> = tx
        .query_row(
            "SELECT announce_seq FROM provider_items WHERE root_id = ?1 AND item_id = ?2",
            rusqlite::params![input.root_id, &item[..]],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    match (input.observed_revision, announced) {
        (Some(observed), Some(announced)) if (observed as i64) < announced => {
            Err(ApplyError::StaleView(format!(
                "the operation observed revision {observed}, before the announcement at {announced}"
            )))
        }
        _ => Ok(()),
    }
}

// ---- the operation identity: stored results and the processed floor ----

struct Session {
    floor: u64,
    above: BTreeSet<u64>,
}

impl Session {
    fn processed(&self, seq: u64) -> bool {
        seq <= self.floor || self.above.contains(&seq)
    }

    fn with(mut self, seq: u64, undecided_min: Option<u64>) -> Self {
        // The floor is MONOTONE: it never decreases, and nothing at or below it is remembered
        // (it is processed by the floor alone), so a late resolution of an old sequence can never
        // move the floor backward and make a pruned, decided operation look new.
        if seq > self.floor {
            self.above.insert(seq);
        }
        while self.above.contains(&(self.floor + 1)) {
            self.floor += 1;
            self.above.remove(&self.floor);
        }
        // Bounded: the lowest gaps are abandoned (an operation that never came is not waited for).
        // The floor never passes the lowest UNDECIDED operation (one with a journaled upload) of the
        // session, so its retry is not stale; once its journal row is gone the floor catches up.
        while self.above.len() > MAX_ABOVE {
            let Some(lowest) = self.above.iter().next().copied() else { break };
            if undecided_min.is_some_and(|min| lowest > min) && self.above.len() <= MAX_ABOVE_PINNED
            {
                break;
            }
            self.floor = self.floor.max(lowest);
            self.above.remove(&lowest);
        }
        self
    }
}

fn load_session(
    conn: &rusqlite::Connection,
    root_id: &str,
    session_id: &[u8],
) -> Result<Session, ApplyError> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT floor_seq, above FROM provider_apply_sessions \
             WHERE root_id = ?1 AND session_id = ?2",
            rusqlite::params![root_id, session_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        None => Session { floor: 0, above: BTreeSet::new() },
        Some((floor, above)) => Session {
            floor: floor as u64,
            above: above
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| u64::from_be_bytes(*c))
                .filter(|&seq| seq > floor as u64)
                .collect(),
        },
    })
}

fn save_session(
    tx: Tx<'_>,
    root_id: &str,
    session_id: &[u8],
    session: Session,
    now_ms: i64,
) -> Result<(), ApplyError> {
    let known: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_apply_sessions WHERE root_id = ?1 AND session_id = ?2)",
        rusqlite::params![root_id, session_id],
        |r| r.get(0),
    )?;
    if !known {
        let sessions: i64 = tx.query_row(
            "SELECT COUNT(*) FROM provider_apply_sessions WHERE root_id = ?1",
            [root_id],
            |r| r.get(0),
        )?;
        if sessions >= MAX_SESSIONS_PER_ROOT {
            return Err(ApplyError::TooManySessions);
        }
    }
    let above: Vec<u8> = session.above.iter().flat_map(|s| s.to_be_bytes()).collect();
    tx.execute(
        "INSERT OR REPLACE INTO provider_apply_sessions \
         (root_id, session_id, floor_seq, above, seen_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![root_id, session_id, session.floor as i64, above, now_ms],
    )?;
    Ok(())
}

fn prune_log(tx: Tx<'_>, root_id: &str, now_ms: i64) -> Result<(), ApplyError> {
    tx.execute(
        "DELETE FROM provider_apply_log WHERE root_id = ?1 AND created_ms < ?2",
        rusqlite::params![root_id, now_ms - APPLY_LOG_MAX_AGE_MS],
    )?;
    tx.execute(
        "DELETE FROM provider_apply_log WHERE root_id = ?1 AND (session_id, operation_seq) IN ( \
            SELECT session_id, operation_seq FROM provider_apply_log WHERE root_id = ?1 \
            ORDER BY created_ms DESC, operation_seq DESC LIMIT -1 OFFSET ?2)",
        rusqlite::params![root_id, APPLY_LOG_MAX_ENTRIES],
    )?;
    Ok(())
}

// ---- helpers over the committed rows ----

struct ItemRow {
    path: String,
    live: bool,
}

fn item_row(tx: Tx<'_>, root_id: &str, item: &ItemId) -> Result<Option<ItemRow>, ApplyError> {
    Ok(tx
        .query_row(
            "SELECT path, live FROM provider_items WHERE root_id = ?1 AND item_id = ?2",
            rusqlite::params![root_id, &item[..]],
            |r| Ok(ItemRow { path: r.get(0)?, live: r.get::<_, i64>(1)? != 0 }),
        )
        .optional()?)
}

fn live_row(
    tx: Tx<'_>,
    group_id: &str,
    path: &str,
) -> Result<Option<crate::store::CanonicalCurrentRow>, ApplyError> {
    Ok(crate::store::read_canonical_current_row(tx, group_id, path)?
        .filter(|row| !row.snapshot.deleted))
}

/// Live current rows at `path` and below it, parent before child.
fn live_rows_under(
    tx: Tx<'_>,
    group_id: &str,
    path: &str,
) -> Result<Vec<(String, crate::store::CanonicalCurrentRow)>, ApplyError> {
    let mut stmt = tx.prepare(
        "SELECT path FROM files WHERE group_id = ?1 AND state = 'current' AND deleted = 0 \
         AND (path = ?2 OR (path > ?2 || '/' AND path < ?2 || '0')) ORDER BY path",
    )?;
    let paths: Vec<String> = stmt
        .query_map(rusqlite::params![group_id, path], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        if let Some(row) = live_row(tx, group_id, &p)? {
            out.push((p, row));
        }
    }
    Ok(out)
}

fn is_directory(tx: Tx<'_>, group_id: &str, path: &str) -> Result<bool, ApplyError> {
    match live_row(tx, group_id, path)? {
        Some(row) => Ok(row.snapshot.record_kind == RecordKind::Directory),
        // A structural directory: classified by one indexed EXISTS, never by loading its subtree.
        None => Ok(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM files WHERE group_id = ?1 AND state = 'current' \
             AND deleted = 0 AND path > ?2 || '/' AND path < ?2 || '0')",
            rusqlite::params![group_id, path],
            |r| r.get(0),
        )?),
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn parent_path(tx: Tx<'_>, root_id: &str, parent: Option<ItemId>) -> Result<String, ApplyError> {
    let Some(parent) = parent else { return Ok(String::new()) };
    match item_row(tx, root_id, &parent)? {
        Some(row) if row.live => Ok(row.path),
        _ => Err(ApplyError::NotFound("the parent is gone".into())),
    }
}

fn validate_name(name: &str) -> Result<(), ApplyError> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
        || name.len() > MAX_NAME_BYTES;
    if bad {
        return Err(ApplyError::InvalidName("not a single valid path component".into()));
    }
    Ok(())
}

/// Whether the destination may take `new_path`: nothing live at it or below it, no live file as
/// an ancestor, and no live entry whose folded (case, NFC/NFD) name equals it. `moving` is the
/// subtree being moved: it is not a collision with itself.
fn check_destination(
    tx: Tx<'_>,
    group_id: &str,
    new_path: &str,
    moving: Option<&str>,
) -> Result<(), ApplyError> {
    if yadorilink_fs_platform::reserved_namespace::wire_path_admission_refusal(new_path).is_some() {
        return Err(ApplyError::InvalidName("a reserved or non-portable name".into()));
    }
    let inside_moving = |path: &str| {
        moving.is_some_and(|from| {
            path == from
                || (path.starts_with(from) && path.as_bytes().get(from.len()) == Some(&b'/'))
        })
    };
    for (path, _) in live_rows_under(tx, group_id, new_path)? {
        if !inside_moving(&path) {
            return Err(ApplyError::NameCollision(format!("{new_path} is taken")));
        }
    }
    let mut ancestor = new_path;
    while let Some((parent, _)) = ancestor.rsplit_once('/') {
        if let Some(row) = live_row(tx, group_id, parent)? {
            if row.snapshot.record_kind != RecordKind::Directory && !inside_moving(parent) {
                return Err(ApplyError::NameCollision(format!("{parent} is not a directory")));
            }
        }
        ancestor = parent;
    }
    let (_, canonical) = crate::file_index::name_fold_keys(new_path);
    for key in [crate::file_index::NameFoldKey::Canonical, crate::file_index::NameFoldKey::Case] {
        let folded = match key {
            crate::file_index::NameFoldKey::Canonical => canonical.clone(),
            crate::file_index::NameFoldKey::Case => crate::file_index::name_fold_keys(new_path).0,
        };
        for other in crate::file_index::name_fold_matches_on(tx, group_id, key, &folded, new_path)?
        {
            if !inside_moving(&other) {
                return Err(ApplyError::NameCollision(format!("{other} has the same folded name")));
            }
        }
    }
    Ok(())
}

fn replicated_xattr_allowed(name: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        name.starts_with("user.")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        false
    }
}

fn clean_xattrs(xattrs: Vec<(String, Vec<u8>)>) -> Vec<(String, Vec<u8>)> {
    let mut kept: Vec<(String, Vec<u8>)> =
        xattrs.into_iter().filter(|(name, _)| replicated_xattr_allowed(name)).collect();
    kept.sort_by(|a, b| a.0.cmp(&b.0));
    kept.dedup_by(|a, b| a.0 == b.0);
    kept
}

fn witness(path: &str, shown: Option<VersionHash>) -> NativeCaptureWitness {
    NativeCaptureWitness {
        path: SyncPath(path.to_owned()),
        shown_class: Vec::new(),
        shown_version: shown,
        row_version: shown,
    }
}

pub(crate) fn meta_columns(version: &FileVersion) -> LocalFileMetaColumns {
    LocalFileMetaColumns {
        record_kind: version.meta.record_kind,
        symlink_target: version.meta.symlink_target.clone(),
        symlink_out_of_root: false,
        unix_mode: version.meta.unix_mode,
        xattrs: version.meta.xattrs.clone(),
    }
}

pub(crate) fn block_infos(version: &FileVersion) -> Vec<BlockInfo> {
    let mut offset = 0u64;
    version
        .blocks
        .iter()
        .map(|b| {
            let info = BlockInfo { hash: b.hash.0.clone(), offset, size: b.size };
            offset += u64::from(b.size);
            info
        })
        .collect()
}

fn version_blocks(blocks: &[BlockInfo]) -> Vec<VersionBlock> {
    blocks.iter().map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size }).collect()
}

fn upsert_of(
    path: &str,
    version: &FileVersion,
    witness: Option<NativeCaptureWitness>,
) -> PreparedLocalMutation {
    PreparedLocalMutation::Upsert {
        record: FileRecord {
            path: path.to_owned(),
            size: version.size,
            mtime_unix_nanos: version.meta.mtime_unix_nanos,
            blocks: block_infos(version),
            deleted: false,
        },
        op: Op::Put { path: SyncPath(path.to_owned()), version: version.version_hash },
        version: version.clone(),
        meta: Some(meta_columns(version)),
        native_witness: witness,
    }
}

fn delete_of(
    path: &str,
    row: &crate::store::CanonicalCurrentRow,
    shown: VersionHash,
    now_ns: i64,
) -> PreparedLocalMutation {
    PreparedLocalMutation::Delete {
        record: FileRecord {
            path: path.to_owned(),
            size: row.snapshot.size,
            mtime_unix_nanos: now_ns,
            blocks: row.snapshot.blocks.clone(),
            deleted: true,
        },
        op: Op::Delete { path: SyncPath(path.to_owned()) },
        native_witness: Some(witness(path, Some(shown))),
    }
}

fn current_version_of(row: &crate::store::CanonicalCurrentRow) -> FileVersion {
    yadorilink_replica_domain::session_state::CurrentVersionRecord::from(row.snapshot.clone())
        .to_file_version()
}

pub(crate) fn metadata_version(version: &FileVersion) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "{:?}|{}|{:?}|{:?}",
        version.meta.unix_mode,
        version.meta.mtime_unix_nanos,
        version.meta.record_kind,
        version.meta.xattrs
    ));
    hasher.finalize().into()
}

fn commit_one_group(
    tx: Tx<'_>,
    group_id: &str,
    mutations: &[PreparedLocalMutation],
    origin_device_id: &str,
    author: &LocalAuthor<'_>,
) -> Result<(), ApplyError> {
    let evidence = vec![None; mutations.len()];
    crate::file_index::commit_local_mutation_group_checked_in_tx(
        tx,
        group_id,
        mutations,
        &evidence,
        origin_device_id,
        author,
        false,
    )?;
    // A provider row holds no local object: its state is `Remote` whatever the authoring wrote.
    for mutation in mutations {
        tx.execute(
            "UPDATE files SET materialization_state = 'remote' \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
               AND materialization_state = 'present'",
            rusqlite::params![group_id, mutation.record().path],
        )?;
    }
    Ok(())
}

/// Whether the version `version` is the winner of the path's live heads after the edit.
fn wins(tx: Tx<'_>, group_id: &str, path: &str, version: VersionHash) -> Result<bool, ApplyError> {
    let heads = crate::native_store::native_heads_at(
        tx,
        &FolderGroupId(group_id.to_owned()),
        &SyncPath(path.to_owned()),
    )?;
    Ok(resolve_winner(heads.iter()).is_some_and(|winner| winner.payload.version == version))
}

fn namespace_revision(tx: Tx<'_>, root_id: &str) -> Result<u64, ApplyError> {
    Ok(tx.query_row(
        "SELECT namespace_revision FROM provider_roots WHERE root_id = ?1",
        [root_id],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

/// The item as committed: name, parent, kind and versions read from the rows.
fn applied_item(
    tx: Tx<'_>,
    root_id: &str,
    group_id: &str,
    item: ItemId,
    expect: Option<VersionHash>,
) -> Result<AppliedItem, ApplyError> {
    let row = item_row(tx, root_id, &item)?
        .filter(|r| r.live)
        .ok_or_else(|| ApplyError::Retry("the item vanished".into()))?;
    let current = live_row(tx, group_id, &row.path)?
        .ok_or_else(|| ApplyError::Retry("the item has no current row".into()))?;
    let version = current_version_of(&current);
    let (parent, name) = split(&row.path);
    let parent_item_id =
        if parent.is_empty() { None } else { Some(mint_item_in_tx(tx, root_id, parent)?) };
    let content_version = expect.unwrap_or(version.version_hash);
    Ok(AppliedItem {
        item_id: item,
        parent_item_id,
        name: name.to_owned(),
        kind: EntryKind::of(current.snapshot.record_kind),
        content_version,
        metadata_version: metadata_version(&version),
        size: current.snapshot.size,
        mtime_unix_nanos: current.snapshot.mtime_unix_nanos,
        unix_mode: current.snapshot.unix_mode.unwrap_or(0),
        current: version.version_hash == content_version,
        namespace_revision: namespace_revision(tx, root_id)?,
        generation: item_generation(tx, root_id, &item)?,
        parent_generation: generation_at(tx, root_id, parent)?.unwrap_or(0),
    })
}

fn item_generation(tx: Tx<'_>, root_id: &str, item: &ItemId) -> Result<u64, ApplyError> {
    Ok(tx.query_row(
        "SELECT generation FROM provider_items WHERE root_id = ?1 AND item_id = ?2",
        rusqlite::params![root_id, &item[..]],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

/// The edit this device just authored is what the OS shows and holds: it is published, the
/// item's served summary becomes `Single` of that content on this write's OWN path (the OS
/// supplied those bytes and holds exactly them; never applied to a mixed item), and, when it
/// changes what the item shows, the generation advances, and the version is recorded as handed
/// over (the presence ledger). All in the transaction of the change.
fn set_published(
    tx: Tx<'_>,
    root_id: &str,
    item: &ItemId,
    version: &FileVersion,
    advance_generation: bool,
) -> Result<(), ApplyError> {
    tx.execute(
        "UPDATE provider_items SET published_version_hash = ?3, \
         announce_version_hash = NULL, announce_seq = NULL, pending_since = NULL, exposed = 1, \
         generation = generation + ?4 WHERE root_id = ?1 AND item_id = ?2",
        rusqlite::params![
            root_id,
            &item[..],
            &version.version_hash.0[..],
            i64::from(advance_generation)
        ],
    )?;
    crate::provider_provenance::authored_in_tx(
        tx,
        root_id,
        item,
        &crate::provider_provenance::content_sig(version),
    )?;
    // The OS holds exactly these bytes, so the edit is also the ledger's handoff of the version:
    // an item authored here is present, never offered back to the OS as a download.
    if version.meta.record_kind != RecordKind::Directory {
        crate::provider::record_handoff_in_tx(tx, root_id, item, version.version_hash)?;
    }
    Ok(())
}

fn now_ns(input: &ApplyInput) -> i64 {
    input.now_ms.saturating_mul(1_000_000)
}

fn replicated_mode(mode: Option<u32>) -> Option<u32> {
    mode.map(|m| m & 0o777)
}

fn mtime_for(input: &ApplyInput) -> i64 {
    input.metadata.mtime_unix_nanos.filter(|m| *m >= 0).unwrap_or_else(|| now_ns(input))
}

// ---- CREATE ----

/// Whether the live row `existing` is already what the create `input` asks for (see `create`).
fn create_is_already_satisfied(
    input: &ApplyInput,
    existing: &crate::store::CanonicalCurrentRow,
) -> bool {
    let kind = existing.snapshot.record_kind;
    match input.entry_kind {
        EntryKind::Directory => kind == RecordKind::Directory,
        EntryKind::File => {
            let Some(content) = &input.content else { return false };
            if kind != RecordKind::File || existing.snapshot.size != content.size {
                return false;
            }
            let version = current_version_of(existing);
            let same_blocks = version.blocks.len() == content.blocks.len()
                && version
                    .blocks
                    .iter()
                    .zip(&content.blocks)
                    .all(|(have, want)| have.hash.0 == want.hash && have.size == want.size);
            let same_mode = replicated_mode(input.metadata.unix_mode)
                .is_none_or(|mode| existing.snapshot.unix_mode == Some(mode));
            same_blocks && same_mode
        }
        EntryKind::Symlink => false,
    }
}

fn create(
    tx: Tx<'_>,
    input: &ApplyInput,
    group_id: &str,
    author: &LocalAuthor<'_>,
    origin_device_id: &str,
) -> Result<ApplyResult, ApplyError> {
    let name = input.name.as_deref().ok_or_else(|| ApplyError::InvalidName("no name".into()))?;
    validate_name(name)?;
    let parent = parent_path(tx, &input.root_id, input.new_parent.flatten())?;
    if !parent.is_empty() {
        if let Some(row) = live_row(tx, group_id, &parent)? {
            if row.snapshot.record_kind != RecordKind::Directory {
                return Err(ApplyError::NotFound("the parent is not a directory".into()));
            }
        }
    }
    let path = join(&parent, name);
    // A create that names an entry which already is exactly what it asks for is adopted, not refused:
    // the OS re-sends creates it never saw answered (a crash, a replay, a retry after it stopped
    // retrying), and a refusal would badge the existing item. A directory at the same place is the
    // same directory. A file is the same when its bytes (and the mode, when one is named) are equal.
    // Anything else (other bytes, another kind) is still a collision.
    if let Some(existing) = live_row(tx, group_id, &path)? {
        if create_is_already_satisfied(input, &existing) {
            let item = mint_item_in_tx(tx, &input.root_id, &path)?;
            let applied = applied_item(tx, &input.root_id, group_id, item, None)?;
            return Ok(ApplyResult {
                outcome: OutcomeKind::Applied,
                item: Some(applied),
                replayed: false,
            });
        }
    }
    check_destination(tx, group_id, &path, None)?;

    let mode = replicated_mode(input.metadata.unix_mode);
    let version = match input.entry_kind {
        EntryKind::Directory => FileVersion::directory(mode),
        EntryKind::Symlink => {
            let target = input
                .symlink_target
                .clone()
                .filter(|t| !t.is_empty())
                .ok_or_else(|| ApplyError::InvalidName("a symlink needs a target".into()))?;
            let size = target.len() as u64;
            FileVersion::new(
                Vec::new(),
                size,
                FileMeta {
                    mtime_unix_nanos: mtime_for(input),
                    unix_mode: mode,
                    symlink_target: Some(target),
                    record_kind: RecordKind::Symlink,
                    xattrs: Vec::new(),
                },
            )
        }
        EntryKind::File => {
            let (blocks, size) = match &input.content {
                Some(content) => (version_blocks(&content.blocks), content.size),
                None => (Vec::new(), 0),
            };
            FileVersion::new(
                blocks,
                size,
                FileMeta {
                    mtime_unix_nanos: mtime_for(input),
                    unix_mode: mode,
                    symlink_target: None,
                    record_kind: RecordKind::File,
                    xattrs: clean_xattrs(input.metadata.xattrs.clone().unwrap_or_default()),
                },
            )
        }
    };
    commit_one_group(tx, group_id, &[upsert_of(&path, &version, None)], origin_device_id, author)?;
    let item = mint_item_in_tx(tx, &input.root_id, &path)?;
    set_published(tx, &input.root_id, &item, &version, false)?;
    yadorilink_sqlite_runtime::note_child_set_change(tx, &input.root_id, &parent)?;
    let applied = applied_item(tx, &input.root_id, group_id, item, Some(version.version_hash))?;
    Ok(ApplyResult { outcome: OutcomeKind::Applied, item: Some(applied), replayed: false })
}

// ---- MODIFY ----

/// The provenance gate of an edit: when OUR OWN durable state does not prove where the user's bytes
/// come from, the edit authors nothing over the canonical version and the bytes are kept beside it
/// (`Some(result)`); `None` means the base is trusted and the edit goes on.
fn keep_untrusted_edit_beside(
    tx: Tx<'_>,
    input: &ApplyInput,
    group_id: &str,
    author: &LocalAuthor<'_>,
    origin_device_id: &str,
    (item, from, current): (&ItemId, &str, &FileVersion),
    base: Option<VersionHash>,
) -> Result<Option<ApplyResult>, ApplyError> {
    let announce_in_flight: bool = tx.query_row(
        "SELECT announce_version_hash IS NOT NULL FROM provider_items \
         WHERE root_id = ?1 AND item_id = ?2",
        rusqlite::params![input.root_id, &item[..]],
        |r| r.get(0),
    )?;
    let base_content_sig = match base {
        Some(base) if base == current.version_hash => {
            Some(crate::provider_provenance::content_sig(current))
        }
        Some(base) => crate::dag_store::get_file_version(tx, group_id, &base)?
            .map(|v| crate::provider_provenance::content_sig(&v)),
        None => None,
    };
    let provenance = crate::provider_provenance::ProvenanceInput {
        base,
        current: current.version_hash,
        base_content_sig,
        item_generation: item_generation(tx, &input.root_id, item)?,
        base_generation: input.base_generation,
        announce_in_flight,
        served: crate::provider_provenance::served_in(tx, &input.root_id, item)?,
    };
    if crate::provider_provenance::edit_base_trusted(&provenance) {
        return Ok(None);
    }
    keep_beside(tx, input, group_id, author, origin_device_id, item, from, current).map(Some)
}

fn modify(
    tx: Tx<'_>,
    input: &ApplyInput,
    group_id: &str,
    author: &LocalAuthor<'_>,
    origin_device_id: &str,
) -> Result<ApplyResult, ApplyError> {
    let item = input.item_id.ok_or_else(|| ApplyError::NotFound("no item".into()))?;
    let Some(row) = item_row(tx, &input.root_id, &item)? else {
        return Err(ApplyError::KeepLocal { path: None });
    };
    if !row.live {
        return Err(ApplyError::KeepLocal { path: Some(row.path) });
    }
    let from = row.path.clone();
    let Some(current_row) = live_row(tx, group_id, &from)? else {
        // A directory that is only structural has no row of its own.
        return modify_structural(tx, input, group_id, author, origin_device_id, &item, &from);
    };
    let current = current_version_of(&current_row);
    let kind = current_row.snapshot.record_kind;

    // Where it goes.
    let (parent, old_name) = split(&from);
    let new_parent = match input.new_parent {
        None => parent.to_owned(),
        Some(target) => parent_path(tx, &input.root_id, target)?,
    };
    let new_name = input.name.as_deref().unwrap_or(old_name);
    if input.name.is_some() {
        validate_name(new_name)?;
    }
    let to = join(&new_parent, new_name);
    let renamed = to != from;
    if renamed {
        if to.starts_with(&format!("{from}/")) {
            return Err(ApplyError::InvalidName("a directory cannot move into itself".into()));
        }
        check_destination(tx, group_id, &to, Some(&from))?;
    }

    // The version the user saw.
    let base = match input.base {
        BaseVersion::Opaque(hash) => Some(hash),
        BaseVersion::Unknown => None,
    };
    // An advisory mtime is applied only over the content it was set on; over newer content it is
    // dropped and the rest of the call (a rename or move, or nothing) proceeds.
    // "The content it was set on" is compared by CONTENT (bytes, kind, symlink target), not by the full
    // version hash: a peer's mode-only change makes the hashes differ without changing the content, and
    // the user's mtime must still apply (over the CURRENT version, so the peer's mode is kept).
    let advisory = advisory_mtime(input);
    let same_content = advisory
        && match base {
            Some(hash) if hash == current.version_hash => true,
            Some(hash) => {
                crate::dag_store::get_file_version(tx, group_id, &hash)?.is_some_and(|saw| {
                    crate::provider_provenance::content_sig(&saw)
                        == crate::provider_provenance::content_sig(&current)
                })
            }
            None => false,
        };
    let base = if same_content { Some(current.version_hash) } else { base };
    let mut effective;
    let input = if advisory && !same_content {
        effective = input.clone();
        effective.metadata.mtime_unix_nanos = None;
        &effective
    } else {
        input
    };
    let has_content = input.content.is_some() || input.symlink_target.is_some();
    let has_metadata = input.metadata.unix_mode.is_some()
        || input.metadata.mtime_unix_nanos.is_some()
        || input.metadata.xattrs.is_some();
    let puts = has_content || has_metadata;
    let dropped_mtime = advisory && !puts;
    // A modify that carries no bytes and no structural change (metadata-less, move-less) acts on the
    // CURRENT version and applies only when the version the user saw is that version. A pure rename
    // or move is exempt (`structural_only`): it acts on the item's identity.
    if !puts && !dropped_mtime && !structural_only(input) && base != Some(current.version_hash) {
        return Err(ApplyError::StaleView(
            "the version the user saw is not the current version".into(),
        ));
    }

    // An edit changes the canonical version only when OUR OWN durable state proves where the
    // user's bytes come from (option B of the design): one predicate decides. An untrusted edit
    // authors NOTHING here (the bytes stay with the user, KEEP_LOCAL); the extension re-sends them
    // as a new file beside the item, and the canonical version is never touched.
    // (An advisory mtime over the content it was set on needs no provenance: it changes no bytes.)
    if puts && !advisory {
        if let Some(kept) = keep_untrusted_edit_beside(
            tx,
            input,
            group_id,
            author,
            origin_device_id,
            (&item, &from, &current),
            base,
        )? {
            return Ok(kept);
        }
    }

    // Past the gate an edit's base is the known current version (a base that is not is untrusted
    // and was kept beside the item above); a rename carries no bytes and acts on the current one.
    let base = base.unwrap_or(current.version_hash);
    let new_version = if puts {
        // What the new version is built over: the base version when it is known (the user
        // edited THAT), else, for a content edit, nothing of it is needed.
        let basis: Option<FileVersion> = if base == current.version_hash {
            Some(current.clone())
        } else {
            crate::dag_store::get_file_version(tx, group_id, &base)?
        };
        let (blocks, size) = match &input.content {
            Some(content) => (version_blocks(&content.blocks), content.size),
            None => match &basis {
                Some(basis) => (basis.blocks.clone(), basis.size),
                // A metadata-only edit of a version the daemon does not know: nothing to build on.
                None => return Err(ApplyError::Retry("the base version is unknown".into())),
            },
        };
        let meta_from = basis.as_ref().map(|b| b.meta.clone()).unwrap_or(current.meta.clone());
        let symlink_target = input.symlink_target.clone().or(meta_from.symlink_target.clone());
        let size = if kind == RecordKind::Symlink {
            symlink_target.as_ref().map_or(0, |t| t.len() as u64)
        } else {
            size
        };
        let meta = FileMeta {
            mtime_unix_nanos: if kind == RecordKind::Directory {
                0
            } else {
                input.metadata.mtime_unix_nanos.filter(|m| *m >= 0).unwrap_or_else(|| {
                    if has_content {
                        now_ns(input)
                    } else {
                        meta_from.mtime_unix_nanos
                    }
                })
            },
            unix_mode: replicated_mode(input.metadata.unix_mode).or(meta_from.unix_mode),
            symlink_target,
            record_kind: kind,
            xattrs: match &input.metadata.xattrs {
                Some(x) => clean_xattrs(x.clone()),
                None => meta_from.xattrs.clone(),
            },
        };
        Some(if kind == RecordKind::Directory {
            FileVersion::directory(meta.unix_mode)
        } else {
            FileVersion::new(
                if kind == RecordKind::Symlink { Vec::new() } else { blocks },
                size,
                meta,
            )
        })
    } else {
        None
    };

    let now = now_ns(input);
    let mut outcome = OutcomeKind::Applied;
    match (&new_version, renamed) {
        (Some(version), false) => {
            let mutation = upsert_of(&from, version, Some(witness(&from, Some(base))));
            commit_one_group(tx, group_id, &[mutation], origin_device_id, author)?;
            if !wins(tx, group_id, &from, version.version_hash)? {
                // Refused whole: the transaction rolls back and the bytes are kept by the OS.
                return Err(ApplyError::KeepLocal { path: Some(from) });
            }
            if base != current.version_hash {
                outcome = OutcomeKind::Concurrent;
            }
            set_published(tx, &input.root_id, &item, version, true)?;
        }
        (version, true) => {
            let rows = live_rows_under(tx, group_id, &from)?;
            let mut mutations = Vec::with_capacity(rows.len() * 2);
            for (path, entry) in &rows {
                let dest = format!("{to}{}", &path[from.len()..]);
                let entry_version = current_version_of(entry);
                let is_item = *path == from;
                let (put_version, shown) = match (is_item, version) {
                    (true, Some(v)) => (v.clone(), base),
                    _ => (entry_version.clone(), entry_version.version_hash),
                };
                mutations.push(delete_of(path, entry, shown, now));
                mutations.push(upsert_of(&dest, &put_version, None));
            }
            let evidence = vec![None; mutations.len()];
            crate::file_index::commit_recursive_operation_in_tx(
                tx,
                group_id,
                &RecursiveOperationKind::RenameTree {
                    from: SyncPath(from.clone()),
                    to: SyncPath(to.clone()),
                },
                &mutations,
                &evidence,
                origin_device_id,
                author,
                false,
            )?;
            if let Some(version) = version {
                if base != current.version_hash {
                    outcome = OutcomeKind::Concurrent;
                }
                if !wins(tx, group_id, &to, version.version_hash)? {
                    return Err(ApplyError::KeepLocal { path: Some(from) });
                }
                set_published(tx, &input.root_id, &item, version, true)?;
            }
        }
        (None, false) => {
            // Nothing to change at all: the item as it is.
        }
    }
    let applied = applied_item(
        tx,
        &input.root_id,
        group_id,
        item,
        new_version.as_ref().map(|v| v.version_hash),
    )?;
    Ok(ApplyResult { outcome, item: Some(applied), replayed: false })
}

/// An UNTRUSTED edit (our own state cannot prove where its bytes come from): the current version
/// stays the canonical item and the user's bytes are authored as a NEW FILE at the conflict-copy
/// name, in this transaction, with their own item and event. The edit is therefore never a head
/// of the canonical path, so no version-hash ordering can demote the current version. A rename
/// combined with an untrusted edit, a metadata-only edit, a directory or a symlink carries no
/// bytes to keep beside the item: nothing is authored (KEEP_LOCAL), the OS retries.
#[allow(clippy::too_many_arguments)]
fn keep_beside(
    tx: Tx<'_>,
    input: &ApplyInput,
    group_id: &str,
    author: &LocalAuthor<'_>,
    origin_device_id: &str,
    item: &ItemId,
    from: &str,
    current: &FileVersion,
) -> Result<ApplyResult, ApplyError> {
    // A rename or move that came with the bytes is not applied: the bytes are what is kept.
    let content = match (&input.content, current.meta.record_kind) {
        (Some(content), RecordKind::File) => content,
        _ => return Err(ApplyError::KeepLocal { path: Some(from.to_owned()) }),
    };
    let meta = FileMeta {
        mtime_unix_nanos: mtime_for(input),
        unix_mode: replicated_mode(input.metadata.unix_mode).or(current.meta.unix_mode),
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: match &input.metadata.xattrs {
            Some(x) => clean_xattrs(x.clone()),
            None => current.meta.xattrs.clone(),
        },
    };
    let version = FileVersion::new(version_blocks(&content.blocks), content.size, meta);
    let canonical = |tx: Tx<'_>| -> Result<ApplyResult, ApplyError> {
        let applied = applied_item(tx, &input.root_id, group_id, *item, None)?;
        Ok(ApplyResult { outcome: OutcomeKind::Concurrent, item: Some(applied), replayed: false })
    };
    // The same bytes AND the same replicated metadata as the canonical version: nothing to keep
    // (another mode or xattr is the user's data and is kept).
    if kept_edit_semantic_key(&version) == kept_edit_semantic_key(current) {
        return canonical(tx);
    }
    author_copy(tx, input, group_id, author, origin_device_id, from, &version)?;
    canonical(tx)
}

/// What makes two kept edits the SAME kept edit: the bytes and the replicated SEMANTIC metadata (mode
/// and the replicated xattr set). Retry-varying values (mtime, staging names, the clock) are not
/// part of it, so retries of one operation collapse to one copy while the same bytes with another
/// mode or xattr are a different user's data and keep their own copy. Provenance's `content_sig`
/// deliberately excludes the metadata and is not used for this.
fn kept_edit_semantic_key(version: &FileVersion) -> String {
    let mut key = crate::provider_provenance::content_sig(version);
    key.push_str(&format!("|mode:{:?}", version.meta.unix_mode));
    let mut xattrs: Vec<_> = version.meta.xattrs.iter().collect();
    xattrs.sort();
    for (name, value) in xattrs {
        key.push_str(&format!("|x:{}:{}={}", name.len(), name, hex::encode(value)));
    }
    key
}

/// Authors `version` as a new file at the conflict-copy name of `from`, once: the name derives from
/// the bytes' identity and the original path (never from the clock or the mtime), so the same bytes
/// retried at any time find the copy that is already there. Returns the copy's item.
fn author_copy(
    tx: Tx<'_>,
    input: &ApplyInput,
    group_id: &str,
    author: &LocalAuthor<'_>,
    origin_device_id: &str,
    from: &str,
    version: &FileVersion,
) -> Result<ItemId, ApplyError> {
    use sha2::{Digest, Sha256};
    let sig = kept_edit_semantic_key(version);
    let key: [u8; 32] =
        Sha256::new().chain_update(sig.as_bytes()).chain_update(from.as_bytes()).finalize().into();
    // A name for the copy: the same bytes already kept there are kept once; a different file
    // under the name takes the next label.
    let mut path = None;
    for label in std::iter::once("local".to_owned()).chain((2..=1000).map(|n| format!("local-{n}")))
    {
        let candidate = yadorilink_replica_domain::conflict::native_copy_path(from, &label, &key);
        match live_row(tx, group_id, &candidate)? {
            Some(existing) if kept_edit_semantic_key(&current_version_of(&existing)) == sig => {
                return mint_item_in_tx(tx, &input.root_id, &candidate).map_err(Into::into);
            }
            Some(_) => continue,
            None => {}
        }
        if check_destination(tx, group_id, &candidate, None).is_ok() {
            path = Some(candidate);
            break;
        }
    }
    // A thousand names taken: a durable quarantine entry named by the bytes' key, in a quarantine
    // folder chosen deterministically: when something incompatible occupies the entry or its folder
    // (a user file, a directory with colliding children) the next folder name is used, so the copy
    // is never refused.
    let path = match path {
        Some(path) => path,
        None => {
            let mut chosen = None;
            for n in 0..10_000u32 {
                let folder =
                    if n == 0 { "Kept bytes".to_owned() } else { format!("Kept bytes ({n})") };
                let entry = format!("{folder}/{}", hex::encode(key));
                if let Some(existing) = live_row(tx, group_id, &entry)? {
                    if kept_edit_semantic_key(&current_version_of(&existing)) == sig {
                        return mint_item_in_tx(tx, &input.root_id, &entry).map_err(Into::into);
                    }
                    continue;
                }
                if check_destination(tx, group_id, &entry, None).is_ok() {
                    chosen = Some(entry);
                    break;
                }
            }
            chosen.ok_or_else(|| ApplyError::Retry("no free quarantine entry".into()))?
        }
    };
    commit_one_group(tx, group_id, &[upsert_of(&path, version, None)], origin_device_id, author)?;
    let kept = mint_item_in_tx(tx, &input.root_id, &path)?;
    set_published(tx, &input.root_id, &kept, version, false)?;
    yadorilink_sqlite_runtime::note_child_set_change(tx, &input.root_id, split(&path).0)?;
    let parent_item = {
        let (parent, _) = split(&path);
        if parent.is_empty() {
            Vec::new()
        } else {
            mint_item_in_tx(tx, &input.root_id, parent)?.to_vec()
        }
    };
    crate::provider::append_event(tx, &input.root_id, "upsert", &kept[..], &parent_item, None)?;
    tx.execute(
        "UPDATE provider_roots SET kept_edits = kept_edits + 1, \
         kept_edit_first_ms = COALESCE(kept_edit_first_ms, ?2) WHERE root_id = ?1",
        rusqlite::params![input.root_id, input.now_ms],
    )?;
    Ok(kept)
}

/// The second decision of an operation that carries ingested bytes and was refused: the bytes are
/// authored as a conflict-named file, never dropped. A modify of a live file keeps them beside it;
/// a create (refused for its parent view or its name) or a modify of a retired or unknown item keeps
/// them next to where the user put them (the requested or the old path), or at the root when that
/// place is gone. The result is the kept copy as a concurrent outcome.
fn keep_refused_bytes(
    tx: Tx<'_>,
    input: &ApplyInput,
    group_id: &str,
    author: &LocalAuthor<'_>,
    origin_device_id: &str,
) -> Result<ApplyResult, ApplyError> {
    let content =
        input.content.as_ref().ok_or_else(|| ApplyError::NotFound("no bytes to keep".into()))?;
    if input.kind == ChangeKind::Modify {
        if let Some(item) = input.item_id {
            if let Some(row) = item_row(tx, &input.root_id, &item)?.filter(|r| r.live) {
                if let Some(current_row) = live_row(tx, group_id, &row.path)? {
                    let current = current_version_of(&current_row);
                    if current.meta.record_kind == RecordKind::File {
                        return keep_beside(
                            tx,
                            input,
                            group_id,
                            author,
                            origin_device_id,
                            &item,
                            &row.path,
                            &current,
                        );
                    }
                }
            }
        }
    }
    // Where the user put the bytes: the requested place (create) or the old path (modify).
    let requested = match input.kind {
        ChangeKind::Create => {
            let parent =
                parent_path(tx, &input.root_id, input.new_parent.flatten()).unwrap_or_default();
            let name = input.name.as_deref().filter(|n| validate_name(n).is_ok()).unwrap_or("file");
            join(&parent, name)
        }
        _ => match input.item_id.map(|i| item_row(tx, &input.root_id, &i)).transpose()?.flatten() {
            Some(row) => row.path,
            None => "file".to_owned(),
        },
    };
    let meta = FileMeta {
        mtime_unix_nanos: mtime_for(input),
        unix_mode: replicated_mode(input.metadata.unix_mode),
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: clean_xattrs(input.metadata.xattrs.clone().unwrap_or_default()),
    };
    let version = FileVersion::new(version_blocks(&content.blocks), content.size, meta);
    let from = if live_row(tx, group_id, &requested)?.is_some()
        || check_destination(tx, group_id, &requested, None).is_ok()
    {
        requested
    } else {
        join("", split(&requested).1)
    };
    let kept = author_copy(tx, input, group_id, author, origin_device_id, &from, &version)?;
    let applied = applied_item(tx, &input.root_id, group_id, kept, None)?;
    Ok(ApplyResult { outcome: OutcomeKind::Concurrent, item: Some(applied), replayed: false })
}

/// A MODIFY of an item whose path has no row of its own (a structural directory): only a
/// rename or move applies, over its descendants.
fn modify_structural(
    tx: Tx<'_>,
    input: &ApplyInput,
    group_id: &str,
    author: &LocalAuthor<'_>,
    origin_device_id: &str,
    item: &ItemId,
    from: &str,
) -> Result<ApplyResult, ApplyError> {
    // The version the user saw is the structural directory's own; anything else is a stale view
    // (not asked of a pure rename or move, which acts on the item's identity).
    let structural = crate::provider_enumerate::structural_version().version_hash;
    if !structural_only(input)
        && !advisory_mtime(input)
        && input.base != BaseVersion::Opaque(structural)
    {
        return Err(ApplyError::StaleView(
            "the directory the user saw is not the current directory".into(),
        ));
    }
    // Bounded BEFORE any row is loaded, like a recursive delete.
    let counted: i64 = tx.query_row(
        "SELECT COUNT(*) FROM (SELECT 1 FROM files WHERE group_id = ?1 AND state = 'current' \
         AND deleted = 0 AND path > ?2 || '/' AND path < ?2 || '0' LIMIT ?3)",
        rusqlite::params![group_id, from, input.max_subtree as i64 + 1],
        |r| r.get(0),
    )?;
    if counted as usize > input.max_subtree {
        return Err(ApplyError::DirectoryNotEmpty(format!(
            "the directory holds more than {} entries; move it in parts",
            input.max_subtree
        )));
    }
    let rows = live_rows_under(tx, group_id, from)?;
    if rows.is_empty() {
        return Err(ApplyError::KeepLocal { path: Some(from.to_owned()) });
    }
    let (parent, old_name) = split(from);
    let new_parent = match input.new_parent {
        None => parent.to_owned(),
        Some(target) => parent_path(tx, &input.root_id, target)?,
    };
    let new_name = input.name.as_deref().unwrap_or(old_name);
    validate_name(new_name)?;
    let to = join(&new_parent, new_name);
    if to == from {
        let applied = applied_structural(tx, input, item, from)?;
        return Ok(ApplyResult {
            outcome: OutcomeKind::Applied,
            item: Some(applied),
            replayed: false,
        });
    }
    if to.starts_with(&format!("{from}/")) {
        return Err(ApplyError::InvalidName("a directory cannot move into itself".into()));
    }
    check_destination(tx, group_id, &to, Some(from))?;
    let now = now_ns(input);
    let mut mutations = Vec::new();
    for (path, entry) in &rows {
        let dest = format!("{to}{}", &path[from.len()..]);
        let version = current_version_of(entry);
        mutations.push(delete_of(path, entry, version.version_hash, now));
        mutations.push(upsert_of(&dest, &version, None));
    }
    let evidence = vec![None; mutations.len()];
    crate::file_index::commit_recursive_operation_in_tx(
        tx,
        group_id,
        &RecursiveOperationKind::RenameTree {
            from: SyncPath(from.to_owned()),
            to: SyncPath(to.clone()),
        },
        &mutations,
        &evidence,
        origin_device_id,
        author,
        false,
    )?;
    let applied = applied_structural(tx, input, item, &to)?;
    Ok(ApplyResult { outcome: OutcomeKind::Applied, item: Some(applied), replayed: false })
}

fn applied_structural(
    tx: Tx<'_>,
    input: &ApplyInput,
    item: &ItemId,
    path: &str,
) -> Result<AppliedItem, ApplyError> {
    let (parent, name) = split(path);
    let version = FileVersion::directory(None);
    Ok(AppliedItem {
        item_id: *item,
        parent_item_id: if parent.is_empty() {
            None
        } else {
            Some(mint_item_in_tx(tx, &input.root_id, parent)?)
        },
        name: name.to_owned(),
        kind: EntryKind::Directory,
        content_version: version.version_hash,
        metadata_version: metadata_version(&version),
        size: 0,
        mtime_unix_nanos: 0,
        unix_mode: 0,
        current: true,
        namespace_revision: namespace_revision(tx, &input.root_id)?,
        generation: item_generation(tx, &input.root_id, item)?,
        parent_generation: generation_at(tx, &input.root_id, parent)?.unwrap_or(0),
    })
}

// ---- DELETE ----

/// Whether deleting the item's CURRENT version destroys only what the user could have seen: no
/// announcement is in flight, and what we may have served is nothing or exactly this content (a
/// mixed item, or other content, may still be what the OS shows, so the delete is ambiguous).
fn delete_is_unambiguous(
    tx: Tx<'_>,
    root_id: &str,
    item: &ItemId,
    current: &FileVersion,
) -> Result<bool, ApplyError> {
    use crate::provider_provenance::{content_sig, served_in, Served};
    let announced: bool = tx.query_row(
        "SELECT announce_version_hash IS NOT NULL FROM provider_items \
         WHERE root_id = ?1 AND item_id = ?2",
        rusqlite::params![root_id, &item[..]],
        |r| r.get(0),
    )?;
    Ok(!announced
        && match served_in(tx, root_id, item)? {
            Served::Never => true,
            Served::Single(sig) => sig == content_sig(current),
            Served::Mixed => false,
        })
}

fn delete(
    tx: Tx<'_>,
    input: &ApplyInput,
    group_id: &str,
    author: &LocalAuthor<'_>,
    origin_device_id: &str,
) -> Result<ApplyResult, ApplyError> {
    let item = input.item_id.ok_or_else(|| ApplyError::NotFound("no item".into()))?;
    let done = |outcome| -> Result<ApplyResult, ApplyError> {
        Ok(ApplyResult { outcome, item: None, replayed: false })
    };
    let Some(row) = item_row(tx, &input.root_id, &item)? else { return done(OutcomeKind::Deleted) };
    if !row.live {
        return done(OutcomeKind::Deleted);
    }
    let path = row.path.clone();
    let now = now_ns(input);
    let directory = is_directory(tx, group_id, &path)?;

    if !directory {
        let Some(current_row) = live_row(tx, group_id, &path)? else {
            return done(OutcomeKind::Deleted);
        };
        let current = current_version_of(&current_row).version_hash;
        let bound = match input.base {
            BaseVersion::Opaque(hash) => Some(hash),
            BaseVersion::Unknown => None,
        };
        // A delete destroys only when it is UNAMBIGUOUS: the view is current, the user deleted
        // the current version, no announcement is in flight, and nothing but the current content
        // was ever served (or nothing at all: they could only have seen the name). Anything else
        // and the file survives; the item they deleted is retired and the survivor is projected
        // anew.
        if input.base_generation != Some(item_generation(tx, &input.root_id, &item)?)
            || bound != Some(current)
            || !delete_is_unambiguous(tx, &input.root_id, &item, &current_version_of(&current_row))?
        {
            tx.execute(
                "UPDATE provider_items SET live = 0, published_version_hash = NULL \
                 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![input.root_id, &item[..]],
            )?;
            tx.execute(
                "UPDATE provider_roots SET change_seq = change_seq + 1 WHERE root_id = ?1",
                [&input.root_id],
            )?;
            return done(OutcomeKind::FileSurvived);
        }
        let mutation = delete_of(&path, &current_row, current, now);
        commit_one_group(tx, group_id, &[mutation], origin_device_id, author)?;
        return done(OutcomeKind::Deleted);
    }

    // A directory is deleted only on the view the user saw: the echoed token (the directory's shown
    // version hash and its generation, which advances whenever anything below it changes) must be
    // the current one. An unknown, absent or old token deletes nothing.
    // The CURRENT directory version (not what was last published or announced): a token whose
    // hash is an older view never passes, even paired with a newer generation.
    let shown_hash = Some(match live_row(tx, group_id, &path)? {
        Some(row) => current_version_of(&row).version_hash,
        None => crate::provider_enumerate::structural_version().version_hash,
    });
    let named = match input.base {
        BaseVersion::Opaque(hash) => Some(hash),
        BaseVersion::Unknown => None,
    };
    if named.is_none()
        || named != shown_hash
        || input.base_generation != Some(item_generation(tx, &input.root_id, &item)?)
    {
        return Err(ApplyError::StaleView(
            "the directory the user saw is not the current directory".into(),
        ));
    }

    // The subtree is bounded BEFORE any row is loaded: one write transaction never holds an
    // unbounded subtree.
    let counted: i64 = tx.query_row(
        "SELECT COUNT(*) FROM (SELECT 1 FROM files WHERE group_id = ?1 AND state = 'current' \
         AND deleted = 0 AND (path = ?2 OR (path > ?2 || '/' AND path < ?2 || '0')) LIMIT ?3)",
        rusqlite::params![group_id, path, input.max_subtree as i64 + 1],
        |r| r.get(0),
    )?;
    if counted as usize > input.max_subtree {
        return Err(ApplyError::DirectoryNotEmpty(format!(
            "the directory holds more than {} entries; delete it in parts",
            input.max_subtree
        )));
    }
    let rows = live_rows_under(tx, group_id, &path)?;
    let descendants = rows.iter().filter(|(p, _)| *p != path).count();
    if descendants > 0 && !input.recursive {
        return Err(ApplyError::DirectoryNotEmpty("the directory is not empty".into()));
    }
    let mut mutations = Vec::with_capacity(rows.len());
    for (entry_path, entry) in rows.iter().rev() {
        // The user deleted this folder's subtree on the view they saw (checked above): every
        // descendant goes, each bound to the version it has now. A descendant's own provenance or
        // listing state is not a veto.
        let current = current_version_of(entry).version_hash;
        mutations.push(delete_of(entry_path, entry, current, now));
    }
    if mutations.is_empty() {
        return done(OutcomeKind::Deleted);
    }
    let evidence = vec![None; mutations.len()];
    crate::file_index::commit_recursive_operation_in_tx(
        tx,
        group_id,
        &RecursiveOperationKind::RmTree { root: SyncPath(path) },
        &mutations,
        &evidence,
        origin_device_id,
        author,
        false,
    )?;
    done(OutcomeKind::Deleted)
}

#[cfg(test)]
mod tests;
