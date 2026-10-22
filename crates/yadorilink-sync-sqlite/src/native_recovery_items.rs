//! Recovery items: remote-only versions a rebootstrap would otherwise destroy.
//!
//! A rebootstrap installs a checkpoint that does not contain every head this
//! replica holds. A live head of another author that the target lacks is on disk
//! and equal to the index, so nothing re-asserts it, and the install would remove
//! it; if that author never returns, the group's last copy would be gone. Before
//! the destructive step every such head is therefore saved as a local recovery
//! item: the version record, the bytes when this replica holds them, and why it
//! was saved. Nothing is authored for it, ever.
//!
//! Items live apart from the rebootstrap's transient area, in a store of their
//! own (`<items root>/<group digest>/<item id>/`), and their rows are not touched
//! by the install. Only [`discard_recovery_item`] deletes one. Restoring is a
//! user action that authors one ordinary put with a new dot.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{
    AuthorSeq, BlockHash, DeviceId, FolderGroupId, SyncPath, VersionHash,
};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_frontier::AuthorState;
use yadorilink_replica_domain::native_state::{DeltaHash, Dot};

use crate::error::SyncSqliteError;
use crate::local_author::LocalAuthor;
use crate::native_authoring::AuthoredPuts;
use crate::native_bootstrap::VerifiedNativeBootstrap;
use crate::native_rebootstrap::BlockedReason;
use crate::native_rebootstrap::Crash;
use crate::native_rebootstrap_recovery::{
    create_dirs_durably, ensure_private_dir_durably, group_dir_name, io_chunk, lstat_no_link,
    open_regular, read_regular, refuse_synced_location, remove_private_tree, sha256,
    sha256_regular, write_durable, write_durable_with, AreaError, ManifestRemoteOnly,
};

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- One row per saved item, written only after its files are durable. Never cleared
        -- by an install; only an explicit discard deletes a row.
        CREATE TABLE IF NOT EXISTS native_recovery_item (
            group_id           TEXT NOT NULL,
            item_id            TEXT NOT NULL,
            kind               TEXT NOT NULL,
            path               TEXT NOT NULL,
            -- The head's identity: all four present for a saved head, all four absent for a
            -- late edit, which was never a head (the CHECK below).
            author_device      TEXT,
            author_incarnation BLOB,
            seq                INTEGER,
            provenance         BLOB,
            version_hash       BLOB NOT NULL,
            content            TEXT NOT NULL,
            size               INTEGER NOT NULL,
            content_sha256     BLOB NOT NULL,
            -- JSON array of the hex hashes of the version's blocks this replica holds. Every
            -- block-store sweep treats them as live for as long as the row exists.
            retained_blocks    TEXT NOT NULL,
            source_recovery_id TEXT NOT NULL,
            created_at         INTEGER NOT NULL,
            PRIMARY KEY (group_id, item_id),
            CHECK (
                (kind = 'late_edit'
                    AND author_device IS NULL AND author_incarnation IS NULL
                    AND seq IS NULL AND provenance IS NULL)
                OR (kind <> 'late_edit'
                    AND author_device IS NOT NULL AND author_incarnation IS NOT NULL
                    AND seq IS NOT NULL AND provenance IS NOT NULL)
            )
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

/// Why a head is saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemKind {
    /// A head of another author that the target does not contain.
    RemoteOnly,
    /// A head above the cutoff at which the target closes its author: inadmissible
    /// old-incarnation data, and possibly the last copy of its bytes.
    BeyondClosureCutoff,
    /// An edit made during a rebootstrap's freeze, after the barrier, to a path whose
    /// original the install removed. Never a head: it has no dot and no provenance.
    LateEdit,
}

impl ItemKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::RemoteOnly => "remote_only",
            Self::BeyondClosureCutoff => "beyond_closure_cutoff",
            Self::LateEdit => "late_edit",
        }
    }

    fn parse(text: &str) -> Result<Self, SyncSqliteError> {
        match text {
            "remote_only" => Ok(Self::RemoteOnly),
            "beyond_closure_cutoff" => Ok(Self::BeyondClosureCutoff),
            "late_edit" => Ok(Self::LateEdit),
            other => Err(corrupt(format!("unknown recovery item kind {other:?}"))),
        }
    }
}

/// What the item holds of the version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemContent {
    /// The record and the bytes (none for a directory or a symlink).
    Complete,
    /// The record is held, the bytes are not all held. The blocks that are held are kept.
    Unavailable,
    /// Not even the version record is held.
    RecordUnavailable,
}

impl ItemContent {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Unavailable => "unavailable",
            Self::RecordUnavailable => "record_unavailable",
        }
    }

    fn parse(text: &str) -> Result<Self, SyncSqliteError> {
        match text {
            "complete" => Ok(Self::Complete),
            "unavailable" => Ok(Self::Unavailable),
            "record_unavailable" => Ok(Self::RecordUnavailable),
            other => Err(corrupt(format!("unknown recovery item content {other:?}"))),
        }
    }
}

fn corrupt(detail: impl Into<String>) -> SyncSqliteError {
    SyncSqliteError::CorruptState(detail.into())
}

/// A head the target lacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteOnlyHead {
    pub path: SyncPath,
    pub dot: Dot,
    pub provenance: DeltaHash,
    pub version: VersionHash,
    pub kind: ItemKind,
}

impl RemoteOnlyHead {
    /// Names the item: the same head always has the same id, so saving it twice is one item.
    pub fn item_id(&self, group: &FolderGroupId) -> String {
        let mut bytes = Vec::new();
        for field in [
            group.as_str().as_bytes(),
            self.kind.as_str().as_bytes(),
            self.path.as_str().as_bytes(),
            self.dot.author.device.0.as_bytes(),
            &self.dot.author.incarnation.0,
            &self.dot.seq.get().to_be_bytes(),
            &self.provenance.0,
            &self.version.0,
        ] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        hex::encode(sha256(&bytes))
    }
}

/// Where a saved item comes from: a head of the group's history, or an edit that never was one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemOrigin {
    Head { dot: Dot, provenance: DeltaHash },
    LateEdit,
}

/// A saved item as the user sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryItem {
    pub item_id: String,
    pub kind: ItemKind,
    pub path: SyncPath,
    pub origin: ItemOrigin,
    /// The version record the item holds (for a late edit, one built from the saved bytes).
    pub version: VersionHash,
    pub content: ItemContent,
    pub size: u64,
    /// Hex hashes of the version's blocks this replica holds, kept alive by the item.
    pub retained_blocks: Vec<String>,
    pub source_recovery_id: String,
}

impl RecoveryItem {
    /// The dot of the head this item saved; none for a late edit.
    pub fn dot(&self) -> Option<&Dot> {
        match &self.origin {
            ItemOrigin::Head { dot, .. } => Some(dot),
            ItemOrigin::LateEdit => None,
        }
    }
}

// --- what to save ----------------------------------------------------------------------------------

/// The live heads of `group` that `target` lacks, by head identity `(path, dot, provenance)`.
///
/// A head the target holds under an identical identity is not saved again. Comparing an
/// author's sequence with the target's entry proves nothing about which chain a head sits on,
/// so a position never excuses a head; it only decides the reason: a head above the cutoff at
/// which the target closes its author is `BeyondClosureCutoff`, any other is `RemoteOnly`.
/// `replayed` holds the deltas of this device's own uncovered intent; their heads are replayed
/// as new deltas, not saved.
pub fn plan_remote_only(
    conn: &Connection,
    group: &FolderGroupId,
    target: &VerifiedNativeBootstrap,
    replayed: &BTreeSet<DeltaHash>,
) -> Result<Vec<RemoteOnlyHead>, SyncSqliteError> {
    let local = crate::native_store::load_state(conn, group)?;
    let mut out = Vec::new();
    for (path, heads) in &local.heads {
        for (dot, payload) in heads {
            if replayed.contains(&payload.provenance) {
                continue;
            }
            let contained = target
                .state()
                .heads
                .get(path)
                .and_then(|theirs| theirs.get(dot))
                .is_some_and(|theirs| theirs.provenance == payload.provenance);
            if contained {
                continue;
            }
            let beyond = match target.author_state(&dot.author) {
                Some(AuthorState::Closed { frontier }) => {
                    dot.seq.get() > frontier.map_or(0, |entry| entry.seq.get())
                }
                _ => false,
            };
            out.push(RemoteOnlyHead {
                path: path.clone(),
                dot: dot.clone(),
                provenance: payload.provenance,
                version: payload.version,
                kind: if beyond { ItemKind::BeyondClosureCutoff } else { ItemKind::RemoteOnly },
            });
        }
    }
    Ok(out)
}

// --- the store -------------------------------------------------------------------------------------

const RECORD_FILE: &str = "record.bin";
const CONTENT_FILE: &str = "content";

fn is_item_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn group_dir(items_root: &Path, group: &FolderGroupId) -> PathBuf {
    items_root.join(group_dir_name(group))
}

pub(crate) fn item_dir(items_root: &Path, group: &FolderGroupId, item_id: &str) -> PathBuf {
    group_dir(items_root, group).join(item_id)
}

fn remove_dir(dir: &Path) -> Result<(), AreaError> {
    if lstat_no_link(dir)?.is_some() {
        remove_private_tree(dir)?;
    }
    Ok(())
}

/// What one item holds, as it is written.
pub(crate) struct ItemBody<'a> {
    pub content: ItemContent,
    pub record: Option<FileVersion>,
    /// The bytes of a complete file item, streamed to the store and never held whole; `None`
    /// for an item with no bytes.
    pub held: Option<crate::native_rebootstrap::HeldContent<'a>>,
    /// Hex hashes of the blocks of `record` that are held locally.
    pub retained_blocks: Vec<String>,
}

impl ItemBody<'_> {
    fn size(&self) -> u64 {
        self.held.as_ref().map_or(0, |h| h.size)
    }

    fn sha256(&self) -> [u8; 32] {
        self.held.as_ref().map_or_else(|| sha256(&[]), |h| h.sha256)
    }
}

/// Makes the group's directory of the store, refusing a location inside a synced root.
pub(crate) fn open_store(
    items_root: &Path,
    group: &FolderGroupId,
    sync_roots: &[PathBuf],
) -> Result<(), AreaError> {
    if let Some(parent) = items_root.parent() {
        create_dirs_durably(parent)?;
    }
    ensure_private_dir_durably(items_root)?;
    refuse_synced_location(items_root, sync_roots)?;
    ensure_private_dir_durably(&group_dir(items_root, group))
}

/// Removes what a crash left in the group's store that no row names: files written for an item
/// whose row never landed. A registered item is never touched.
pub(crate) fn sweep_unregistered(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
) -> Result<(), SyncSqliteError> {
    let dir = group_dir(items_root, group);
    let area = |e: AreaError| corrupt(e.to_string());
    if lstat_no_link(&dir).map_err(area)?.is_none() {
        return Ok(());
    }
    let registered: BTreeSet<String> = registered_ids(conn, group)?;
    for entry in fs::read_dir(&dir).map_err(|e| corrupt(e.to_string()))? {
        let entry = entry.map_err(|e| corrupt(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !registered.contains(&name) {
            let path = entry.path();
            if path.is_dir() {
                remove_dir(&path).map_err(area)?;
            }
        }
    }
    Ok(())
}

/// The blocks every item of every group keeps alive: the one root source a block-store sweep
/// adds to the live set. Present exactly while the item's row is.
pub(crate) fn retained_block_hashes_all_groups(
    conn: &Connection,
) -> Result<BTreeSet<String>, SyncSqliteError> {
    let mut stmt = conn.prepare("SELECT retained_blocks FROM native_recovery_item")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = BTreeSet::new();
    for row in rows {
        let blocks: Vec<String> = serde_json::from_str(&row?)
            .map_err(|e| corrupt(format!("a recovery item's retained blocks: {e}")))?;
        out.extend(blocks);
    }
    Ok(out)
}

fn registered_ids(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<BTreeSet<String>, SyncSqliteError> {
    let mut stmt = conn.prepare("SELECT item_id FROM native_recovery_item WHERE group_id = ?1")?;
    let ids = stmt.query_map([group.as_str()], |row| row.get::<_, String>(0))?;
    Ok(ids.collect::<Result<_, _>>()?)
}

/// How much of a version an item holds: a stronger item is never replaced by a weaker one.
fn strength(content: ItemContent) -> u8 {
    match content {
        ItemContent::RecordUnavailable => 0,
        ItemContent::Unavailable => 1,
        ItemContent::Complete => 2,
    }
}

/// Why saving an item did not finish.
#[derive(Debug)]
pub(crate) enum SaveError {
    Area(AreaError),
    Crashed,
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for SaveError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

impl From<rusqlite::Error> for SaveError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

impl From<AreaError> for SaveError {
    fn from(error: AreaError) -> Self {
        Self::Area(error)
    }
}

/// The manifest's statement of the item already registered under `item_id`, if any.
fn stored_entry(
    conn: &Connection,
    group: &FolderGroupId,
    head: &RemoteOnlyHead,
    item_id: &str,
) -> Result<Option<ManifestRemoteOnly>, SyncSqliteError> {
    let row: Option<(String, i64, Vec<u8>)> = conn
        .query_row(
            "SELECT content, size, content_sha256 FROM native_recovery_item \
             WHERE group_id = ?1 AND item_id = ?2",
            (group.as_str(), item_id),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((content, size, digest)) = row else { return Ok(None) };
    ItemContent::parse(&content)?;
    let content_sha256: [u8; 32] =
        digest.try_into().map_err(|_| corrupt("an item's digest is not 32 bytes"))?;
    Ok(Some(ManifestRemoteOnly {
        item_id: item_id.to_owned(),
        kind: head.kind.as_str().into(),
        path: head.path.as_str().to_owned(),
        author: head.dot.author.clone(),
        seq: head.dot.seq.get(),
        provenance: head.provenance,
        version: head.version,
        content,
        size: size as u64,
        content_sha256,
    }))
}

/// Saves one remote-only head as an item: files durable, then the row, and returns what the
/// manifest states. This is the only way an item's files or row are written, and it is
/// monotonic: an item already registered with more content (`Complete` over `Unavailable` over
/// `RecordUnavailable`) is left exactly as it is and is what is returned, whatever the
/// incoming evidence; an item that is as strong but whose files do not read back is damaged,
/// and is reported rather than rebuilt from the same or weaker input. `between` runs after the
/// files and before the row.
#[allow(clippy::too_many_arguments)]
pub(crate) fn save_item(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    head: &RemoteOnlyHead,
    item_id: &str,
    body: &mut ItemBody<'_>,
    source_recovery_id: &str,
    now: i64,
    between: &mut dyn FnMut() -> Result<(), Crash>,
) -> Result<ManifestRemoteOnly, SaveError> {
    // One write transaction for the decision, the files and the row, so a concurrent completion
    // of the same item cannot change what was decided on.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let conn = &*tx;
    let wanted = manifest_entry(group, head, body);
    if let Some(stored) = stored_entry(conn, group, head, item_id)? {
        let stored_content = ItemContent::parse(&stored.content)?;
        if strength(stored_content) > strength(body.content) {
            if !item_is_durable(conn, items_root, group, &stored)? {
                return Err(corrupt(
                    "a saved item holds more than is offered, but its files do not read back",
                )
                .into());
            }
            return Ok(stored);
        }
        if stored_content == ItemContent::Complete
            && !item_is_durable(conn, items_root, group, &wanted)?
        {
            return Err(corrupt("a complete saved item's files do not read back").into());
        }
    }
    if item_is_durable(conn, items_root, group, &wanted)? {
        // The files stand; the blocks this replica holds only ever grow, and every one of
        // them is a sweep root while the row names it.
        extend_retained_blocks(conn, group, item_id, &body.retained_blocks)?;
        tx.commit()?;
        return Ok(wanted);
    }
    write_item_files(items_root, group, item_id, body)?;
    between().map_err(|_| SaveError::Crashed)?;
    register_item(conn, group, head, item_id, body, source_recovery_id, now)?;
    tx.commit()?;
    Ok(wanted)
}

/// Adds `blocks` to the retained blocks the row of `item_id` names (a union; nothing leaves).
fn extend_retained_blocks(
    conn: &Connection,
    group: &FolderGroupId,
    item_id: &str,
    blocks: &[String],
) -> Result<(), SyncSqliteError> {
    let stored: String = conn.query_row(
        "SELECT retained_blocks FROM native_recovery_item WHERE group_id = ?1 AND item_id = ?2",
        (group.as_str(), item_id),
        |row| row.get(0),
    )?;
    let mut all: BTreeSet<String> = serde_json::from_str::<Vec<String>>(&stored)
        .map_err(|e| corrupt(format!("a recovery item's retained blocks: {e}")))?
        .into_iter()
        .collect();
    let before = all.len();
    all.extend(blocks.iter().cloned());
    if all.len() == before {
        return Ok(());
    }
    let merged: Vec<String> = all.into_iter().collect();
    conn.execute(
        "UPDATE native_recovery_item SET retained_blocks = ?3 WHERE group_id = ?1 AND item_id = ?2",
        (
            group.as_str(),
            item_id,
            serde_json::to_string(&merged).map_err(|e| corrupt(e.to_string()))?,
        ),
    )?;
    Ok(())
}

/// Writes the files of one item, each durable, and the chain of names to them. The item's
/// directory is either new (a store sweeps unregistered directories before saving) or the one
/// of an item being upgraded.
fn write_item_files(
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
    body: &mut ItemBody<'_>,
) -> Result<(), AreaError> {
    // Each file replaces its name atomically and nothing is removed first: the item an upgrade
    // replaces keeps its record until the new one is in place.
    let dir = item_dir(items_root, group, item_id);
    ensure_private_dir_durably(&dir)?;
    if let Some(record) = &body.record {
        write_durable(&dir, RECORD_FILE, &record.canonical_encoding())?;
    }
    if body.content == ItemContent::Complete {
        // Streamed under the digest the source established; nothing is published unless the
        // stream was exactly that content, so a failed read leaves the previous file (if any).
        let (size, digest) = (body.size(), body.sha256());
        let mut none = std::io::empty();
        let reader: &mut dyn std::io::Read = match body.held.as_mut() {
            Some(held) => &mut *held.reader,
            None => &mut none,
        };
        write_durable_with(&dir, CONTENT_FILE, |out| {
            crate::native_rebootstrap_recovery::copy_checked(reader, out, size, &digest)
        })?;
    }
    Ok(())
}

/// Registers an item whose files are durable. The row is replaced only by one that holds at
/// least as much: this is how an item whose bytes were missing before becomes complete, and it
/// never removes a row. A weaker row than the stored one changes nothing and is an error.
fn register_item(
    conn: &Connection,
    group: &FolderGroupId,
    head: &RemoteOnlyHead,
    item_id: &str,
    body: &ItemBody<'_>,
    source_recovery_id: &str,
    now: i64,
) -> Result<(), SyncSqliteError> {
    let changed = conn.execute(
        "INSERT INTO native_recovery_item \
         (group_id, item_id, kind, path, author_device, author_incarnation, seq, provenance, \
          version_hash, content, size, content_sha256, retained_blocks, source_recovery_id, \
          created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
         ON CONFLICT (group_id, item_id) DO UPDATE SET \
          kind = excluded.kind, path = excluded.path, author_device = excluded.author_device, \
          author_incarnation = excluded.author_incarnation, seq = excluded.seq, \
          provenance = excluded.provenance, version_hash = excluded.version_hash, \
          content = excluded.content, size = excluded.size, \
          content_sha256 = excluded.content_sha256, retained_blocks = excluded.retained_blocks, \
          source_recovery_id = excluded.source_recovery_id, created_at = excluded.created_at \
         WHERE (CASE excluded.content WHEN 'complete' THEN 2 WHEN 'unavailable' THEN 1 ELSE 0 END) \
            >= (CASE native_recovery_item.content WHEN 'complete' THEN 2 \
                     WHEN 'unavailable' THEN 1 ELSE 0 END)",
        rusqlite::params![
            group.as_str(),
            item_id,
            head.kind.as_str(),
            head.path.as_str(),
            head.dot.author.device.0,
            &head.dot.author.incarnation.0[..],
            head.dot.seq.get() as i64,
            &head.provenance.0[..],
            &head.version.0[..],
            body.content.as_str(),
            body.size() as i64,
            &body.sha256()[..],
            serde_json::to_string(&body.retained_blocks).map_err(|e| corrupt(e.to_string()))?,
            source_recovery_id,
            now,
        ],
    )?;
    if changed == 0 {
        return Err(corrupt("a saved item would be replaced by one that holds less"));
    }
    Ok(())
}

/// The manifest's statement of a saved item.
pub(crate) fn manifest_entry(
    group: &FolderGroupId,
    head: &RemoteOnlyHead,
    body: &ItemBody<'_>,
) -> ManifestRemoteOnly {
    ManifestRemoteOnly {
        item_id: head.item_id(group),
        kind: head.kind.as_str().into(),
        path: head.path.as_str().to_owned(),
        author: head.dot.author.clone(),
        seq: head.dot.seq.get(),
        provenance: head.provenance,
        version: head.version,
        content: body.content.as_str().into(),
        size: body.size(),
        content_sha256: body.sha256(),
    }
}

/// Whether the item `entry` names is a registered row and its files read back as written.
pub(crate) fn item_is_durable(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    entry: &ManifestRemoteOnly,
) -> Result<bool, SyncSqliteError> {
    let registered = conn
        .query_row(
            "SELECT kind, path, author_device, author_incarnation, seq, provenance, version_hash, \
                    content, size, content_sha256 \
             FROM native_recovery_item WHERE group_id = ?1 AND item_id = ?2",
            (group.as_str(), &entry.item_id),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((kind, path, device, incarnation, seq, provenance, version, content, size, digest)) =
        registered
    else {
        return Ok(false);
    };
    let row_content = ItemContent::parse(&content)?;
    let entry_content = ItemContent::parse(&entry.content)?;
    let same_head = kind == entry.kind
        && path == entry.path
        && device.as_deref() == Some(entry.author.device.0.as_str())
        && incarnation.as_deref() == Some(&entry.author.incarnation.0[..])
        && seq == Some(entry.seq as i64)
        && provenance.as_deref() == Some(&entry.provenance.0[..])
        && version == entry.version.0;
    // An item only ever gains content, so a row that holds more than the entry states (an
    // unavailable item completed after the manifest was written) still keeps what the entry
    // promises; one that holds less does not. The files are checked against the row's own
    // statement.
    if !same_head
        || strength(row_content) < strength(entry_content)
        || (row_content == entry_content
            && (size as u64 != entry.size || digest != entry.content_sha256))
    {
        return Ok(false);
    }
    let digest: [u8; 32] =
        digest.try_into().map_err(|_| corrupt("an item's digest is not 32 bytes"))?;
    let dir = item_dir(items_root, group, &entry.item_id);
    Ok(verify_item(&dir, row_content, &entry.version, &digest, size as u64).is_ok())
}

/// Reads an item's record back and checks it against the version it was saved under.
fn read_item_record(
    dir: &Path,
    content: ItemContent,
    version: &VersionHash,
) -> Result<Option<FileVersion>, AreaError> {
    if content == ItemContent::RecordUnavailable {
        return Ok(None);
    }
    let bytes = read_regular(&dir.join(RECORD_FILE))?;
    let record = FileVersion::from_canonical_encoding(&bytes)
        .map_err(|e| AreaError::Inconsistent(format!("an item record does not decode: {e:?}")))?;
    if record.version_hash != *version || record.verify_hash().is_err() {
        return Err(AreaError::Inconsistent("an item record does not hash to its version".into()));
    }
    Ok(Some(record))
}

/// Reads an item's record and bytes back and checks both against what was saved.
fn read_item(
    dir: &Path,
    content: ItemContent,
    version: &VersionHash,
    content_sha256: &[u8; 32],
) -> Result<(Option<FileVersion>, Vec<u8>), AreaError> {
    let record = read_item_record(dir, content, version)?;
    let bytes = if content == ItemContent::Complete {
        let bytes = read_regular(&dir.join(CONTENT_FILE))?;
        if sha256(&bytes) != *content_sha256 {
            return Err(AreaError::Inconsistent("an item's bytes are not the ones saved".into()));
        }
        bytes
    } else {
        Vec::new()
    };
    Ok((record, bytes))
}

/// [`read_item`]'s checks without its bytes: the content is hashed through one fixed buffer,
/// so verifying an item of any size holds none of it.
fn verify_item(
    dir: &Path,
    content: ItemContent,
    version: &VersionHash,
    content_sha256: &[u8; 32],
    size: u64,
) -> Result<(), AreaError> {
    read_item_record(dir, content, version)?;
    if content == ItemContent::Complete {
        let (digest, len) = sha256_regular(&dir.join(CONTENT_FILE))?;
        if digest != *content_sha256 || len != size {
            return Err(AreaError::Inconsistent("an item's bytes are not the ones saved".into()));
        }
    }
    Ok(())
}

/// Every named item is durable, or the first that is not.
pub(crate) fn verify_items(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    entries: &[ManifestRemoteOnly],
) -> Result<(), BlockedReason> {
    for entry in entries {
        let durable = item_is_durable(conn, items_root, group, entry).map_err(|e| {
            BlockedReason::PreservationFailed(crate::native_rebootstrap::PreservationFailure::Io {
                detail: e.to_string(),
            })
        })?;
        if !durable {
            return Err(BlockedReason::RemoteOnlyUnpreserved { item: entry.item_id.clone() });
        }
    }
    Ok(())
}

// --- late edits ----------------------------------------------------------------------------------

/// An edit nobody captured, found at a quarantined path: a regular file's bytes or a symlink's
/// target. A regular file's bytes are not held here: they are streamed from the root into the
/// item store, and `size` and `sha256` are what the root observed them to be.
pub(crate) struct LateEdit<'a> {
    pub path: &'a str,
    pub symlink: bool,
    /// The length of the content (a symlink's target length, for a symlink).
    pub size: u64,
    /// The SHA-256 of the content.
    pub sha256: [u8; 32],
    /// A symlink's target (a small byte string); empty for a regular file.
    pub symlink_target: &'a [u8],
    /// What the file's metadata was; a symlink carries none.
    pub meta: Option<LateEditMeta>,
}

/// The metadata of a late-edited regular file, as observed (or inherited where the platform
/// cannot observe it): what restoring the edit gives back.
#[derive(Clone, Debug)]
pub(crate) struct LateEditMeta {
    pub mtime_unix_nanos: i64,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
}

/// Why a late edit could not be made ready.
#[derive(Debug)]
pub(crate) enum LateEditError {
    /// The content could not be read from where it lives, or was not what was observed. The
    /// original stays and recovery is blocked.
    Source(String),
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for LateEditError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

/// A late edit made ready to register: its item and, unless the item is already registered
/// with files that read back, what to register.
pub(crate) struct PreparedLateEdit {
    item_id: String,
    path: String,
    registration: Option<Registration>,
}

struct Registration {
    record: FileVersion,
    size: u64,
    sha256: [u8; 32],
}

impl LateEdit<'_> {
    /// Names the item: the same edit at the same path is always the same item, so saving it
    /// again after a crash is one item.
    /// The observed metadata is part of the name: the same bytes under another mode, xattrs or
    /// mtime are another edit, and a retry that finds the file unchanged is the same one.
    fn item_id(&self, group: &FolderGroupId) -> String {
        let mut bytes = Vec::new();
        let mode = self.meta.as_ref().and_then(|m| m.unix_mode);
        let mode = mode.map_or_else(Vec::new, |m| m.to_be_bytes().to_vec());
        let mtime =
            self.meta.as_ref().map_or_else(Vec::new, |m| m.mtime_unix_nanos.to_be_bytes().to_vec());
        let mut xattrs = Vec::new();
        for (name, value) in self.meta.iter().flat_map(|m| &m.xattrs) {
            for part in [name.as_bytes(), value.as_slice()] {
                xattrs.extend_from_slice(&(part.len() as u64).to_be_bytes());
                xattrs.extend_from_slice(part);
            }
        }
        for field in [
            b"late_edit".as_slice(),
            group.as_str().as_bytes(),
            self.path.as_bytes(),
            &[u8::from(self.symlink)],
            &self.sha256,
            &mode,
            &mtime,
            &xattrs,
        ] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        hex::encode(sha256(&bytes))
    }

    /// The version record of the saved bytes, so that restoring is the ordinary restore of a
    /// complete item. `blocks` are the block descriptors computed while the content was copied
    /// (ignored for a symlink, which has none).
    fn record(&self, now_unix: i64, blocks: Vec<VersionBlock>) -> FileVersion {
        let mtime_unix_nanos = now_unix.saturating_mul(1_000_000_000);
        if self.symlink {
            let meta = FileMeta {
                mtime_unix_nanos,
                unix_mode: None,
                symlink_target: Some(self.symlink_target.to_vec()),
                record_kind: RecordKind::Symlink,
                xattrs: Vec::new(),
            };
            return FileVersion::new(Vec::new(), self.size, meta);
        }
        let observed = self.meta.clone();
        let meta = FileMeta {
            mtime_unix_nanos: observed.as_ref().map_or(mtime_unix_nanos, |m| m.mtime_unix_nanos),
            unix_mode: observed.as_ref().and_then(|m| m.unix_mode),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: observed.map(|m| m.xattrs).unwrap_or_default(),
        };
        FileVersion::new(blocks, self.size, meta)
    }
}

/// Why a streamed copy stopped.
#[derive(Debug)]
pub(crate) enum CopyError {
    Read(std::io::Error),
    Write(std::io::Error),
    /// The content is not the length or digest it was observed to be.
    Changed,
}

/// Copies `reader` to `out` through one `chunk`-sized buffer while computing, in the same pass,
/// the content's digest and its block descriptors under the ordinary fixed-size rule (blocks of
/// `block_size`, the last one short). Succeeds only if the content is exactly `size` bytes with
/// digest `sha256`; nothing but the one buffer and the descriptors is held.
pub(crate) fn copy_with_blocks(
    reader: &mut dyn std::io::Read,
    out: &mut dyn std::io::Write,
    chunk: usize,
    block_size: usize,
    size: u64,
    expected_sha256: &[u8; 32],
) -> Result<Vec<VersionBlock>, CopyError> {
    use sha2::{Digest, Sha256};
    let block_size = block_size.max(1);
    let mut buf = vec![0u8; chunk.max(1)];
    let mut whole = Sha256::new();
    let mut block = Sha256::new();
    let mut in_block = 0usize;
    let mut total = 0u64;
    let mut blocks = Vec::new();
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CopyError::Read(e)),
        };
        total += n as u64;
        if total > size {
            return Err(CopyError::Changed);
        }
        out.write_all(&buf[..n]).map_err(CopyError::Write)?;
        whole.update(&buf[..n]);
        let mut piece = &buf[..n];
        while !piece.is_empty() {
            let take = piece.len().min(block_size - in_block);
            block.update(&piece[..take]);
            in_block += take;
            piece = &piece[take..];
            if in_block == block_size {
                blocks.push(VersionBlock {
                    hash: BlockHash(block.finalize_reset().to_vec()),
                    size: in_block as u32,
                });
                in_block = 0;
            }
        }
    }
    if in_block > 0 {
        blocks.push(VersionBlock {
            hash: BlockHash(block.finalize_reset().to_vec()),
            size: in_block as u32,
        });
    }
    let digest: [u8; 32] = whole.finalize().into();
    if total != size || digest != *expected_sha256 {
        return Err(CopyError::Changed);
    }
    Ok(blocks)
}

/// Makes the permanent files of a late edit durable in the item store, unless the item is
/// already registered and reads back. Nothing is registered here: until the row lands, a crash
/// leaves files [`sweep_unregistered`] removes.
///
/// A regular file's content is streamed from `open` straight into the item's content file
/// through one fixed buffer, the digest and block descriptors computed on the way, and read
/// back the same way. A read error or a content that is not what was observed fails the
/// preparation (nothing is registered, so the original stays).
pub(crate) fn prepare_late_edit<'s>(
    conn: &Connection,
    items_root: &Path,
    sync_roots: &[PathBuf],
    group: &FolderGroupId,
    edit: &LateEdit<'_>,
    open: &dyn Fn() -> Result<Box<dyn std::io::Read + 's>, String>,
    now_unix: i64,
) -> Result<PreparedLateEdit, LateEditError> {
    let item_id = edit.item_id(group);
    let path = edit.path.to_owned();
    if late_edit_is_durable(conn, items_root, group, &item_id)? {
        return Ok(PreparedLateEdit { item_id, path, registration: None });
    }
    let store = |e: AreaError| LateEditError::Store(corrupt(e.to_string()));
    open_store(items_root, group, sync_roots).map_err(store)?;
    let dir = item_dir(items_root, group, &item_id);
    remove_dir(&dir).map_err(store)?;
    ensure_private_dir_durably(&dir).map_err(store)?;
    let mut source = open().map_err(LateEditError::Source)?;
    let block_size = yadorilink_local_storage::block_size_for(edit.size);
    let mut failure: Option<LateEditError> = None;
    let mut blocks = Vec::new();
    let written = write_durable_with(&dir, CONTENT_FILE, |out| {
        match copy_with_blocks(&mut *source, out, io_chunk(), block_size, edit.size, &edit.sha256) {
            Ok(found) => {
                blocks = found;
                Ok(())
            }
            Err(CopyError::Read(e)) => {
                failure = Some(LateEditError::Source(e.to_string()));
                Err(AreaError::Io(e))
            }
            Err(CopyError::Changed) => {
                failure = Some(LateEditError::Source(format!(
                    "{} changed while it was being read",
                    edit.path
                )));
                Err(AreaError::Inconsistent("the content is not what was observed".into()))
            }
            Err(CopyError::Write(e)) => Err(AreaError::Io(e)),
        }
    });
    drop(source);
    let finish = (|| -> Result<FileVersion, LateEditError> {
        if let Err(e) = written {
            return Err(failure.take().unwrap_or_else(|| store(e)));
        }
        let record = edit.record(now_unix, blocks);
        write_durable(&dir, RECORD_FILE, &record.canonical_encoding()).map_err(store)?;
        // Read back before anything may rely on it: the original is removed on the strength of
        // this.
        verify_item(&dir, ItemContent::Complete, &record.version_hash, &edit.sha256, edit.size)
            .map_err(store)?;
        Ok(record)
    })();
    match finish {
        Ok(record) => Ok(PreparedLateEdit {
            item_id,
            path,
            registration: Some(Registration { record, size: edit.size, sha256: edit.sha256 }),
        }),
        Err(e) => {
            // Best effort: a crash-left directory is the sweep's.
            let _ = remove_dir(&dir);
            Err(e)
        }
    }
}

impl PreparedLateEdit {
    /// The id of the item this edit is: the one a crash-resume must confirm.
    pub(crate) fn item_id(&self) -> &str {
        &self.item_id
    }

    /// Registers the item; run in the transaction that lets the original be removed.
    pub(crate) fn register(
        &self,
        conn: &Connection,
        group: &FolderGroupId,
        source_recovery_id: &str,
        now_unix: i64,
    ) -> Result<(), SyncSqliteError> {
        let Some(registration) = &self.registration else { return Ok(()) };
        conn.execute(
            "INSERT OR REPLACE INTO native_recovery_item \
             (group_id, item_id, kind, path, author_device, author_incarnation, seq, provenance, \
              version_hash, content, size, content_sha256, retained_blocks, source_recovery_id, \
              created_at) \
             VALUES (?1, ?2, 'late_edit', ?3, NULL, NULL, NULL, NULL, ?4, 'complete', ?5, ?6, \
                     '[]', ?7, ?8)",
            rusqlite::params![
                group.as_str(),
                self.item_id,
                self.path,
                &registration.record.version_hash.0[..],
                registration.size as i64,
                &registration.sha256[..],
                source_recovery_id,
                now_unix,
            ],
        )?;
        Ok(())
    }
}

/// Whether `item_id` is a registered late edit whose files read back as registered.
fn late_edit_is_durable(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
) -> Result<bool, SyncSqliteError> {
    let row: Option<(Vec<u8>, Vec<u8>, i64)> = conn
        .query_row(
            "SELECT version_hash, content_sha256, size FROM native_recovery_item \
             WHERE group_id = ?1 AND item_id = ?2 AND kind = 'late_edit' AND content = 'complete'",
            (group.as_str(), item_id),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((version, digest, size)) = row else { return Ok(false) };
    let (Ok(version), Ok(digest)) =
        (<[u8; 32]>::try_from(version.as_slice()), <[u8; 32]>::try_from(digest.as_slice()))
    else {
        return Ok(false);
    };
    let dir = item_dir(items_root, group, item_id);
    Ok(verify_item(&dir, ItemContent::Complete, &VersionHash(version), &digest, size as u64)
        .is_ok())
}

/// Whether `item_id` is a registered late edit of `path` whose files read back as registered.
pub(crate) fn late_edit_item_is_durable(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    path: &str,
    item_id: &str,
) -> Result<bool, SyncSqliteError> {
    let at_path: Option<String> = conn
        .query_row(
            "SELECT path FROM native_recovery_item \
             WHERE group_id = ?1 AND item_id = ?2 AND kind = 'late_edit'",
            (group.as_str(), item_id),
            |row| row.get(0),
        )
        .optional()?;
    if at_path.as_deref() != Some(path) {
        return Ok(false);
    }
    late_edit_is_durable(conn, items_root, group, item_id)
}

// --- listing, discarding, restoring --------------------------------------------------------------

type Row = (
    String,
    String,
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Vec<u8>,
    String,
    i64,
    String,
    String,
);

pub fn list_recovery_items(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<Vec<RecoveryItem>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT item_id, kind, path, author_device, author_incarnation, seq, provenance, \
                version_hash, content, size, source_recovery_id, retained_blocks \
         FROM native_recovery_item WHERE group_id = ?1 ORDER BY created_at, item_id",
    )?;
    let rows = stmt.query_map([group.as_str()], |row| {
        Ok::<Row, rusqlite::Error>((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
        ))
    })?;
    let hash = |bytes: Vec<u8>| -> Result<[u8; 32], SyncSqliteError> {
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| corrupt("a recovery item hash is not 32 bytes"))
    };
    let mut out = Vec::new();
    for row in rows {
        let (
            item_id,
            kind,
            path,
            device,
            incarnation,
            seq,
            provenance,
            version,
            content,
            size,
            source,
            retained,
        ) = row?;
        let kind = ItemKind::parse(&kind)?;
        let origin = match (kind, device, incarnation, seq, provenance) {
            (ItemKind::LateEdit, None, None, None, None) => ItemOrigin::LateEdit,
            (_, Some(device), Some(incarnation), Some(seq), Some(provenance))
                if kind != ItemKind::LateEdit =>
            {
                let incarnation = <[u8; 16]>::try_from(incarnation.as_slice())
                    .map_err(|_| corrupt("a recovery item incarnation is not 16 bytes"))?;
                ItemOrigin::Head {
                    dot: Dot {
                        author: AuthorId {
                            device: DeviceId(device),
                            incarnation: IncarnationId(incarnation),
                        },
                        seq: AuthorSeq(seq as u64),
                    },
                    provenance: DeltaHash(hash(provenance)?),
                }
            }
            _ => return Err(corrupt("a recovery item's head identity does not match its kind")),
        };
        out.push(RecoveryItem {
            item_id,
            kind,
            path: SyncPath(path),
            origin,
            version: VersionHash(hash(version)?),
            content: ItemContent::parse(&content)?,
            size: size as u64,
            retained_blocks: serde_json::from_str(&retained)
                .map_err(|e| corrupt(format!("a recovery item's retained blocks: {e}")))?,
            source_recovery_id: source,
        });
    }
    Ok(out)
}

fn find_item(
    conn: &Connection,
    group: &FolderGroupId,
    item_id: &str,
) -> Result<Option<(RecoveryItem, [u8; 32])>, SyncSqliteError> {
    if !is_item_id(item_id) {
        return Ok(None);
    }
    let digest: Option<Vec<u8>> = conn
        .query_row(
            "SELECT content_sha256 FROM native_recovery_item WHERE group_id = ?1 AND item_id = ?2",
            (group.as_str(), item_id),
            |row| row.get(0),
        )
        .optional()?;
    let Some(digest) = digest else { return Ok(None) };
    let digest = <[u8; 32]>::try_from(digest.as_slice())
        .map_err(|_| corrupt("a recovery item digest is not 32 bytes"))?;
    Ok(list_recovery_items(conn, group)?
        .into_iter()
        .find(|item| item.item_id == item_id)
        .map(|item| (item, digest)))
}

/// The bytes an item holds, read back and checked against the digest it was saved under.
pub fn read_item_content(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
) -> Result<Vec<u8>, SyncSqliteError> {
    let (item, digest) = find_item(conn, group, item_id)?
        .ok_or_else(|| SyncSqliteError::NotFound("no such recovery item".into()))?;
    read_item(&item_dir(items_root, group, item_id), item.content, &item.version, &digest)
        .map(|(_, bytes)| bytes)
        .map_err(|e| corrupt(e.to_string()))
}

/// The only operation that deletes an item: its row, then its files. Refused while the group is
/// frozen by a rebootstrap. Returns whether an item was found.
pub fn discard_recovery_item(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
) -> Result<bool, SyncSqliteError> {
    if crate::native_rebootstrap::group_frozen(conn, group.as_str())? {
        return Err(SyncSqliteError::GroupFrozen { group_id: group.as_str().to_owned() });
    }
    if !is_item_id(item_id) {
        return Ok(false);
    }
    let removed = conn.execute(
        "DELETE FROM native_recovery_item WHERE group_id = ?1 AND item_id = ?2",
        (group.as_str(), item_id),
    )?;
    remove_dir(&item_dir(items_root, group, item_id)).map_err(|e| corrupt(e.to_string()))?;
    Ok(removed > 0)
}

/// Why an unavailable item could not be completed.
#[derive(Debug)]
pub enum CompleteError {
    NotFound,
    /// The item is not `Unavailable`: there is nothing to complete.
    NotUnavailable,
    /// The bytes are not the item's version.
    WrongBytes,
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for CompleteError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

/// The items of `group` that hold a version record but not all of its bytes, with the record.
pub fn unavailable_items(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
) -> Result<Vec<(RecoveryItem, FileVersion)>, SyncSqliteError> {
    let mut out = Vec::new();
    for item in list_recovery_items(conn, group)? {
        if item.content != ItemContent::Unavailable {
            continue;
        }
        let dir = item_dir(items_root, group, &item.item_id);
        let bytes = read_regular(&dir.join(RECORD_FILE)).map_err(|e| corrupt(e.to_string()))?;
        let record = FileVersion::from_canonical_encoding(&bytes)
            .map_err(|e| corrupt(format!("an item record does not decode: {e:?}")))?;
        if record.version_hash != item.version || record.verify_hash().is_err() {
            return Err(corrupt("an item record does not hash to its version"));
        }
        out.push((item, record));
    }
    Ok(out)
}

/// Makes an `Unavailable` item `Complete` once its version's bytes are held: the bytes are
/// checked block by block against the record, written durably beside it, and only then does the
/// row say `complete` and keep every block alive. A crash between the two leaves the item
/// unavailable with a stray content file that the next completion overwrites.
pub fn complete_unavailable_item(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
    mut held: crate::native_rebootstrap::HeldContent<'_>,
) -> Result<(), CompleteError> {
    let (item, record) = unavailable_items(conn, items_root, group)?
        .into_iter()
        .find(|(item, _)| item.item_id == item_id)
        .ok_or_else(|| match find_item(conn, group, item_id) {
            Ok(Some(_)) => CompleteError::NotUnavailable,
            Ok(None) => CompleteError::NotFound,
            Err(error) => CompleteError::Store(error),
        })?;
    let dir = item_dir(items_root, group, &item.item_id);
    // Checked block by block against the record while it is streamed beside it: nothing is
    // published unless every block, and the length, are exactly the record's.
    let mut wrong = false;
    let mut size = 0u64;
    let mut whole = [0u8; 32];
    let written = write_durable_with(&dir, CONTENT_FILE, |out| {
        let found = copy_blocks_checked(&mut *held.reader, out, &record).map_err(|e| match e {
            BlocksError::Io(e) => AreaError::Io(e),
            BlocksError::Wrong => {
                wrong = true;
                AreaError::Inconsistent("the bytes are not the version's".into())
            }
        })?;
        (size, whole) = found;
        Ok(())
    });
    if wrong {
        return Err(CompleteError::WrongBytes);
    }
    written.map_err(|e| corrupt(e.to_string()))?;
    let retained = serde_json::to_string(&hex_block_hashes(&record))
        .map_err(|e| CompleteError::Store(corrupt(e.to_string())))?;
    conn.execute(
        "UPDATE native_recovery_item \
         SET content = 'complete', size = ?3, content_sha256 = ?4, retained_blocks = ?5 \
         WHERE group_id = ?1 AND item_id = ?2 AND content = 'unavailable'",
        rusqlite::params![group.as_str(), item_id, size as i64, &whole[..], retained],
    )
    .map_err(SyncSqliteError::from)?;
    Ok(())
}

enum BlocksError {
    Io(std::io::Error),
    Wrong,
}

/// Copies `reader` to `out` one record block at a time through one fixed buffer, succeeding only
/// if each block hashes to the record's and nothing follows the last. Returns the total length
/// and the digest of everything copied.
fn copy_blocks_checked(
    reader: &mut dyn std::io::Read,
    out: &mut dyn std::io::Write,
    record: &FileVersion,
) -> Result<(u64, [u8; 32]), BlocksError> {
    use sha2::{Digest, Sha256};
    let mut whole = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; io_chunk().max(1)];
    for block in &record.blocks {
        let mut hasher = Sha256::new();
        let mut left = u64::from(block.size);
        while left > 0 {
            let want = buf.len().min(left as usize);
            let n = match reader.read(&mut buf[..want]) {
                Ok(0) => return Err(BlocksError::Wrong),
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(BlocksError::Io(e)),
            };
            hasher.update(&buf[..n]);
            whole.update(&buf[..n]);
            out.write_all(&buf[..n]).map_err(BlocksError::Io)?;
            left -= n as u64;
            total += n as u64;
        }
        if hasher.finalize()[..] != block.hash.0[..] {
            return Err(BlocksError::Wrong);
        }
    }
    let mut extra = [0u8; 1];
    loop {
        match reader.read(&mut extra) {
            Ok(0) => break,
            Ok(_) => return Err(BlocksError::Wrong),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(BlocksError::Io(e)),
        }
    }
    if total != record.size {
        return Err(BlocksError::Wrong);
    }
    Ok((total, whole.finalize().into()))
}

fn hex_block_hashes(record: &FileVersion) -> Vec<String> {
    record.blocks.iter().map(|block| hex::encode(&block.hash.0)).collect()
}

/// Every group that has a recovery item or an own unit a rebootstrap did not replay, whether or
/// not the group is still linked here: the data outlives the group.
pub fn groups_with_preserved_data(
    conn: &Connection,
) -> Result<BTreeSet<FolderGroupId>, SyncSqliteError> {
    let mut groups = BTreeSet::new();
    for table in ["native_recovery_item", "native_unreplayed_unit"] {
        let mut stmt = conn.prepare(&format!("SELECT DISTINCT group_id FROM {table}"))?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            groups.insert(FolderGroupId(row?));
        }
    }
    Ok(groups)
}

/// Takes a restored version's bytes into the caller's block store.
pub type ImportBytes<'a> =
    dyn FnMut(&FileVersion, &mut dyn std::io::Read) -> Result<(), String> + 'a;

#[derive(Debug)]
pub enum RestoreError {
    NotFound,
    /// The item holds no version record.
    RecordUnavailable,
    /// The item holds the record but not the bytes.
    ContentUnavailable,
    /// What the store holds is not what was saved.
    Corrupt(String),
    /// The caller could not take the bytes into its block store.
    Import(String),
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for RestoreError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

/// Authors one ordinary put of the item's version at its original path, as `author`, after
/// `import` has taken the bytes into the caller's block store. A new dot is minted; the
/// original dot and provenance are not restored, and the put follows the ordinary rules for a
/// path that is occupied or contested. The item stays. Refused while the group is frozen.
pub fn restore_recovery_item(
    conn: &Connection,
    items_root: &Path,
    group: &FolderGroupId,
    item_id: &str,
    author: &LocalAuthor<'_>,
    import: &mut ImportBytes<'_>,
) -> Result<AuthoredPuts, RestoreError> {
    if crate::native_rebootstrap::group_frozen(conn, group.as_str())? {
        return Err(RestoreError::Store(SyncSqliteError::GroupFrozen {
            group_id: group.as_str().to_owned(),
        }));
    }
    let (item, digest) = find_item(conn, group, item_id)?.ok_or(RestoreError::NotFound)?;
    match item.content {
        ItemContent::RecordUnavailable => return Err(RestoreError::RecordUnavailable),
        ItemContent::Unavailable => return Err(RestoreError::ContentUnavailable),
        ItemContent::Complete => {}
    }
    // The record and the content are checked against what was saved first, the content by
    // hashing it through one fixed buffer; the import then streams it, so none of it is held
    // whole.
    let dir = item_dir(items_root, group, item_id);
    let corrupt_item = |e: AreaError| RestoreError::Corrupt(e.to_string());
    let record = read_item_record(&dir, item.content, &item.version).map_err(corrupt_item)?;
    let record =
        record.ok_or_else(|| RestoreError::Corrupt("a complete item has no record".into()))?;
    let (found, _) = sha256_regular(&dir.join(CONTENT_FILE)).map_err(corrupt_item)?;
    if found != digest {
        return Err(corrupt_item(AreaError::Inconsistent(
            "an item's bytes are not the ones saved".into(),
        )));
    }
    if record.meta.record_kind == RecordKind::File {
        let mut file = open_regular(&dir.join(CONTENT_FILE)).map_err(corrupt_item)?;
        import(&record, &mut file).map_err(RestoreError::Import)?;
    }
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .map_err(SyncSqliteError::from)?;
    crate::dag_store::put_file_version(&tx, group.as_str(), &record)?;
    let op = Op::Put { path: item.path.clone(), version: item.version };
    // The restore saw nothing at the path: it lands beside whatever is live there
    // and supersedes none of it (only this device's own heads, if the row shows
    // one), so a newer version a peer wrote is never replaced without a conflict.
    let witness = crate::native_capture::absent_native_witness(item.path.as_str());
    let authored =
        crate::native_authoring::author_op_witnessed(&tx, group, author, &op, Some(&witness))?;
    tx.commit().map_err(SyncSqliteError::from)?;
    Ok(authored)
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use std::io::Read;

    /// Content with no repeating period near the buffer sizes under test.
    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) ^ (i >> 3)) as u8).collect()
    }

    /// The rule the in-memory path applied: `chunks(block_size)` of the whole content.
    fn expected_blocks(bytes: &[u8], block_size: usize) -> Vec<VersionBlock> {
        bytes
            .chunks(block_size)
            .map(|c| VersionBlock { hash: BlockHash(sha256(c).to_vec()), size: c.len() as u32 })
            .collect()
    }

    /// Hands out at most `step` bytes per read, as a slow file does.
    struct Trickle<'a>(&'a [u8], usize);
    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.len().min(buf.len()).min(self.1);
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    const CHUNK: usize = 7;

    #[test]
    fn copy_matches_the_in_memory_blocks_and_digest_at_every_boundary() {
        for block_size in [5, CHUNK, 16, 4 * CHUNK] {
            for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 10 * CHUNK + 3, 200] {
                for step in [usize::MAX, 1, 3] {
                    let bytes = data(len);
                    let mut out = Vec::new();
                    let blocks = copy_with_blocks(
                        &mut Trickle(&bytes, step),
                        &mut out,
                        CHUNK,
                        block_size,
                        len as u64,
                        &sha256(&bytes),
                    )
                    .unwrap();
                    assert_eq!(out, bytes, "len {len} block {block_size} step {step}");
                    assert_eq!(
                        blocks,
                        expected_blocks(&bytes, block_size),
                        "len {len} block {block_size} step {step}"
                    );
                }
            }
        }
    }

    #[test]
    fn copy_refuses_content_that_is_not_what_was_observed() {
        let bytes = data(50);
        let digest = sha256(&bytes);
        let copy = |content: &[u8], size: u64| {
            copy_with_blocks(&mut &content[..], &mut Vec::new(), CHUNK, 16, size, &digest)
        };
        assert!(copy(&bytes, 50).is_ok());
        assert!(matches!(copy(&bytes[..49], 50), Err(CopyError::Changed)), "shorter");
        assert!(matches!(copy(&data(51), 50), Err(CopyError::Changed)), "longer");
        let mut other = bytes.clone();
        other[20] ^= 1;
        assert!(matches!(copy(&other, 50), Err(CopyError::Changed)), "same length, other bytes");
    }

    #[test]
    fn copy_reports_a_read_error_as_one() {
        struct Fails(usize);
        impl Read for Fails {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("disk gone"));
                }
                let n = buf.len().min(self.0);
                buf[..n].fill(1);
                self.0 -= n;
                Ok(n)
            }
        }
        let result = copy_with_blocks(&mut Fails(20), &mut Vec::new(), CHUNK, 16, 100, &[0; 32]);
        assert!(matches!(result, Err(CopyError::Read(_))), "{result:?}");
    }

    #[test]
    fn the_hashing_helpers_stream_through_a_forced_tiny_buffer() {
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 9 * CHUNK + 2] {
            let bytes = data(len);
            let (digest, n) = crate::native_rebootstrap_recovery::sha256_stream(
                &mut Trickle(&bytes, usize::MAX),
                CHUNK,
            )
            .unwrap();
            assert_eq!((digest, n), (sha256(&bytes), len as u64));
        }
    }
}
