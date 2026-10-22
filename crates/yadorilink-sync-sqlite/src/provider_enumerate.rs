//! What the OS is shown of a provider root: the children of a folder, one item, in the shown
//! view.
//!
//! The authoritative namespace is the group's `files` rows plus the structural directories
//! (`provider_dirs`), read by parent through the `files_parent_path` index, never
//! `provider_items`, which only holds items that were exposed. An enumeration page is READ FIRST:
//! when every child already has an item and a published view the page is answered from a read
//! (a repeat open of an exposed folder never takes the writer); otherwise one short write
//! transaction mints the missing items, publishes the unpublished ones at exactly the version
//! shown and appends a first-publication event for each, and records the folder as enumerated.

use rusqlite::OptionalExtension;
use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::ids::VersionHash;

use crate::error::SyncSqliteError;
use crate::provider::{
    append_event, current_version, item_id_from, mint_item_in_tx, publication_in, split_parent,
    ItemId, ProviderRepository, Publication,
};
use crate::provider_write::metadata_version;

/// An item as the OS is shown it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShownItem {
    pub item_id: ItemId,
    /// Empty = the root container.
    pub parent_item_id: Vec<u8>,
    pub name: String,
    pub kind: RecordKind,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub unix_mode: u32,
    pub content_version: VersionHash,
    pub metadata_version: [u8; 32],
    pub content_pending: bool,
    pub symlink_target: Vec<u8>,
    /// The item's generation.
    pub generation: u64,
    /// The generation of the folder it is shown in (0 for the root container).
    pub parent_generation: u64,
    /// The engine permits the OS to drop its own local copy of this item (a user's "Remove
    /// Download"). Decided from current state each time the item is read; false whenever the state
    /// that decides it cannot be read.
    pub eviction_allowed: bool,
}

impl ShownItem {
    /// A bound on the encoded size of the item (name, target and the fixed fields).
    pub fn encoded_estimate(&self) -> usize {
        self.name.len() + self.symlink_target.len() + 160
    }
}

#[derive(Debug)]
pub struct ChildrenPage {
    pub items: Vec<ShownItem>,
    /// The last path of the page when more follow (the keyset cursor).
    pub next_after: Option<String>,
    /// The event sequence read by this page's transaction.
    pub anchor: u64,
}

#[derive(Debug)]
pub enum EnumerateError {
    NotFound,
    NotADirectory,
    Db(SyncSqliteError),
}

impl From<SyncSqliteError> for EnumerateError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Db(error)
    }
}

impl From<r2d2::Error> for EnumerateError {
    fn from(error: r2d2::Error) -> Self {
        Self::Db(error.into())
    }
}

impl From<rusqlite::Error> for EnumerateError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error.into())
    }
}

impl yadorilink_sqlite_runtime::SqlOperationError for EnumerateError {
    fn is_locked(&self) -> bool {
        match self {
            Self::Db(error) => error.is_locked(),
            _ => false,
        }
    }
}

/// The version a structural directory (one with no row of its own) is shown at.
pub(crate) fn structural_version() -> FileVersion {
    FileVersion::directory(Some(0o755))
}

struct Candidate {
    path: String,
    /// No `files` row: a directory only because something lives below it.
    structural: bool,
}

/// The children of `parent_path` after `after`, by path, at most `limit`: the rows of the parent
/// index merged with the structural directories that have no row.
fn candidates(
    conn: &rusqlite::Connection,
    group_id: &str,
    parent_path: &str,
    after: &str,
    limit: usize,
) -> Result<Vec<Candidate>, SyncSqliteError> {
    let mut rows = conn.prepare_cached(
        "SELECT path FROM files WHERE group_id = ?1 AND state = 'current' AND deleted = 0 \
         AND version_seq > 0 AND rtrim(rtrim(path, replace(path, '/', '')), '/') = ?2 \
         AND path > ?3 ORDER BY path LIMIT ?4",
    )?;
    let rows: Vec<String> = rows
        .query_map(rusqlite::params![group_id, parent_path, after, limit as i64], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut dirs = conn.prepare_cached(
        "SELECT d.path FROM provider_dirs d WHERE d.group_id = ?1 AND d.parent_path = ?2 \
         AND d.path > ?3 \
         AND NOT EXISTS (SELECT 1 FROM files f WHERE f.group_id = d.group_id AND f.path = d.path \
                         AND f.state = 'current' AND f.deleted = 0 AND f.version_seq > 0) \
         ORDER BY d.path LIMIT ?4",
    )?;
    let dirs: Vec<String> = dirs
        .query_map(rusqlite::params![group_id, parent_path, after, limit as i64], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut merged: Vec<Candidate> = rows
        .into_iter()
        .map(|path| Candidate { path, structural: false })
        .chain(dirs.into_iter().map(|path| Candidate { path, structural: true }))
        .collect();
    merged.sort_by(|a, b| a.path.cmp(&b.path));
    merged.truncate(limit);
    Ok(merged)
}

struct ItemState {
    item_id: ItemId,
    generation: u64,
    exposed: bool,
    published: Option<VersionHash>,
    announce: Option<VersionHash>,
}

type ItemRowBytes = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, i64, bool);

fn item_state(
    conn: &rusqlite::Connection,
    root_id: &str,
    path: &str,
) -> Result<Option<ItemState>, SyncSqliteError> {
    let row: Option<ItemRowBytes> = conn
        .query_row(
            "SELECT item_id, published_version_hash, announce_version_hash, generation, exposed \
             FROM provider_items WHERE root_id = ?1 AND path = ?2 AND live = 1",
            rusqlite::params![root_id, path],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    row.map(|(id, published, announce, generation, exposed)| {
        Ok(ItemState {
            item_id: item_id_from(&id)?,
            generation: generation as u64,
            exposed,
            published: published.map(|b| crate::provider::hash_from(&b)).transpose()?,
            announce: announce.map(|b| crate::provider::hash_from(&b)).transpose()?,
        })
    })
    .transpose()
}

/// The version the OS is shown for the item at `path`: the announced version, else the published
/// one, else (never shown) the current one, else (a structural directory) the synthesized one.
fn shown_version(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
    state: Option<&ItemState>,
) -> Result<Option<FileVersion>, SyncSqliteError> {
    if let Some(hash) = state.and_then(|s| s.announce.or(s.published)) {
        return Ok(Some(crate::dag_store::get_file_version(conn, group_id, &hash)?.ok_or_else(
            || SyncSqliteError::CorruptState("the shown version of an item is gone".into()),
        )?));
    }
    match current_version(conn, group_id, path)? {
        Some(version) => Ok(Some(version)),
        None => {
            let has_children: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_dirs WHERE group_id = ?1 AND path = ?2)",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )?;
            Ok(has_children.then(structural_version))
        }
    }
}

/// Whether the OS may drop its own copy of the item at `path` without being asked by the engine.
/// Only a file, or a folder, that the user is not keeping on this device: a path covered by a pin,
/// and a folder with a pin beneath it, are refused. Symlinks have no content to drop. A read
/// failure is an error, never a permission.
fn os_may_drop_copy(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
    kind: RecordKind,
) -> Result<bool, SyncSqliteError> {
    if !matches!(kind, RecordKind::File | RecordKind::Directory) {
        return Ok(false);
    }
    let kept: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pinned_items \
          WHERE group_id = ?1 AND ( \
            path = '' OR path = ?2 OR substr(?2, 1, length(path) + 1) = path || '/' \
            OR (?3 AND substr(path, 1, length(?2) + 1) = ?2 || '/')))",
        rusqlite::params![group_id, path, kind == RecordKind::Directory],
        |r| r.get(0),
    )?;
    Ok(!kept)
}

fn shown_item(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
    item_id: ItemId,
    state: &ItemState,
    parent_item_id: Vec<u8>,
) -> Result<Option<ShownItem>, SyncSqliteError> {
    let Some(version) = shown_version(conn, group_id, path, Some(state))? else {
        return Ok(None);
    };
    let pending = match state.published {
        Some(published) => matches!(
            publication_in(
                conn,
                group_id,
                path,
                Some(published.0.to_vec()),
                state.announce.map(|a| a.0.to_vec()),
            )?,
            Publication::ContentPending
        ),
        None => false,
    };
    Ok(Some(ShownItem {
        item_id,
        parent_item_id,
        name: split_parent(path).1.to_owned(),
        kind: version.meta.record_kind,
        size: version.size,
        mtime_unix_nanos: version.meta.mtime_unix_nanos,
        unix_mode: version.meta.unix_mode.unwrap_or(0) & 0o7777,
        content_version: version.version_hash,
        metadata_version: metadata_version(&version),
        content_pending: pending,
        symlink_target: version.meta.symlink_target.clone().unwrap_or_default(),
        generation: state.generation,
        eviction_allowed: os_may_drop_copy(conn, group_id, path, version.meta.record_kind)?,
        parent_generation: {
            let parent_path = split_parent(path).0;
            if parent_path.is_empty() {
                0
            } else {
                conn.query_row(
                    "SELECT generation - child_bumps FROM provider_items \
                     WHERE group_id = ?1 AND path = ?2 AND live = 1",
                    rusqlite::params![group_id, parent_path],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
                .unwrap_or(0) as u64
            }
        },
    }))
}

fn parent_of_item(
    conn: &rusqlite::Connection,
    root_id: &str,
    parent_path: &str,
) -> Result<Vec<u8>, SyncSqliteError> {
    if parent_path.is_empty() {
        return Ok(Vec::new());
    }
    Ok(conn
        .query_row(
            "SELECT item_id FROM provider_items WHERE root_id = ?1 AND path = ?2 AND live = 1",
            rusqlite::params![root_id, parent_path],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default())
}

fn namespace_revision(conn: &rusqlite::Connection, root_id: &str) -> Result<u64, SyncSqliteError> {
    Ok(conn.query_row(
        "SELECT namespace_revision FROM provider_roots WHERE root_id = ?1",
        [root_id],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

/// The folder `parent` (`""` = the root container) as a path of the group, or why it is none.
fn resolve_parent(
    conn: &rusqlite::Connection,
    root_id: &str,
    group_id: &str,
    parent: &[u8],
) -> Result<String, EnumerateError> {
    if parent.is_empty() {
        return Ok(String::new());
    }
    let path: Option<String> = conn
        .query_row(
            "SELECT path FROM provider_items WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
            rusqlite::params![root_id, parent],
            |r| r.get(0),
        )
        .optional()?;
    let path = path.ok_or(EnumerateError::NotFound)?;
    let is_dir: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_dirs WHERE group_id = ?1 AND path = ?2) \
         OR EXISTS(SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                   AND deleted = 0 AND record_kind = 'directory')",
        rusqlite::params![group_id, path],
        |r| r.get(0),
    )?;
    if is_dir {
        Ok(path)
    } else {
        Err(EnumerateError::NotADirectory)
    }
}

impl ProviderRepository {
    /// One page of the children of `parent`, after the keyset cursor `after`, bounded by `limit`
    /// items and `max_bytes` of encoded items (always at least one item).
    pub fn enumerate_children(
        &self,
        root_id: &str,
        parent: &[u8],
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<ChildrenPage, EnumerateError> {
        let group_id = self.group_of_root(root_id)?.ok_or(EnumerateError::NotFound)?;
        // Read first: a repeat open of an exposed folder is answered without the writer.
        let read = self.read_settled_enum(|conn| {
            page_in(conn, None, root_id, &group_id, parent, after, limit, max_bytes)
        })?;
        if let Some(page) = read {
            return Ok(page);
        }
        self.database_for_write().write_immediate::<_, EnumerateError>(|tx| {
            yadorilink_sqlite_runtime::reconcile_provider_liveness(tx)?;
            let page = page_in(tx, Some(tx), root_id, &group_id, parent, after, limit, max_bytes)?;
            Ok(page.expect("a write pass always answers"))
        })
    }

    /// The item the OS asks about by id (`item(for:)`), in the shown view; `None` for an item
    /// that is not live. A lookup is not a listing: nothing is minted or published.
    pub fn lookup_item(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<Option<(ShownItem, u64)>, EnumerateError> {
        let group_id = self.group_of_root(root_id)?.ok_or(EnumerateError::NotFound)?;
        self.read_settled_enum(|conn| {
            let row: Option<String> = conn
                .query_row(
                    "SELECT path FROM provider_items WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(path) = row else { return Ok(None) };
            let state = item_state(conn, root_id, &path)?.expect("the live item just read");
            let parent = parent_of_item(conn, root_id, split_parent(&path).0)?;
            let item = shown_item(conn, &group_id, &path, *item_id, &state, parent)?;
            Ok(item.map(|item| (item, namespace_revision(conn, root_id).unwrap_or(0))))
        })
    }

    fn read_settled_enum<T>(
        &self,
        mut read: impl FnMut(&rusqlite::Connection) -> Result<T, EnumerateError>,
    ) -> Result<T, EnumerateError> {
        let mut failure = None;
        let answer = self.read_settled(|conn| match read(conn) {
            Ok(value) => Ok(Some(value)),
            Err(EnumerateError::Db(error)) => Err(error),
            Err(other) => {
                failure = Some(other);
                Ok(None)
            }
        })?;
        match (answer, failure) {
            (Some(value), _) => Ok(value),
            (None, Some(error)) => Err(error),
            (None, None) => unreachable!("a read answers or fails"),
        }
    }
}

/// One page. `writer` is `None` for the read pass, which answers `None` as soon as a child
/// needs a write (no item, or no published view); with a writer it mints, publishes, logs and
/// records the folder as enumerated, and always answers.
#[allow(clippy::too_many_arguments)]
fn page_in(
    conn: &rusqlite::Connection,
    writer: Option<&rusqlite::Transaction<'_>>,
    root_id: &str,
    group_id: &str,
    parent: &[u8],
    after: Option<&str>,
    limit: usize,
    max_bytes: usize,
) -> Result<Option<ChildrenPage>, EnumerateError> {
    let parent_path = resolve_parent(conn, root_id, group_id, parent)?;
    // The first opening of a folder is recorded even when it is empty (a first child created
    // later must be logged); once recorded, repeat opens stay writes-free.
    if writer.is_none() && !is_enumerated(conn, root_id, parent)? {
        return Ok(None);
    }
    let found = candidates(conn, group_id, &parent_path, after.unwrap_or(""), limit + 1)?;
    let more_exists = found.len() > limit;
    let mut items = Vec::new();
    let mut bytes = 0usize;
    let mut last = None;
    for candidate in found.into_iter().take(limit) {
        let state = item_state(conn, root_id, &candidate.path)?;
        let mut state = match (state, writer) {
            (Some(state), _) => state,
            (None, Some(tx)) => {
                let item_id = mint_item_in_tx(tx, root_id, &candidate.path)?;
                ItemState {
                    item_id,
                    generation: 1,
                    exposed: false,
                    published: None,
                    announce: None,
                }
            }
            (None, None) => return Ok(None),
        };
        if state.published.is_some() && !state.exposed {
            // Re-exposed (it left the working set and is shown again): its history of published
            // versions is KEPT, so an item whose current version moved on is pending again
            // instead of looking freshly consistent; it is told as an upsert.
            let Some(tx) = writer else { return Ok(None) };
            tx.execute(
                "UPDATE provider_items SET exposed = 1 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, &state.item_id[..]],
            )?;
            append_event(tx, root_id, "upsert", &state.item_id, parent, None)?;
        }
        if state.published.is_none() {
            let Some(tx) = writer else { return Ok(None) };
            // First shown: published at exactly the version shown, and told as an upsert so a
            // walk that started before this moment is closed by the change feed.
            let version = if candidate.structural {
                let version = structural_version();
                crate::dag_store::put_file_version(tx, group_id, &version)?;
                Some(version)
            } else {
                current_version(conn, group_id, &candidate.path)?
            };
            if let Some(version) = version {
                tx.execute(
                    "UPDATE provider_items SET published_version_hash = ?3, exposed = 1 \
                     WHERE root_id = ?1 AND item_id = ?2",
                    rusqlite::params![root_id, &state.item_id[..], &version.version_hash.0[..]],
                )?;
                state.published = Some(version.version_hash);
                append_event(tx, root_id, "upsert", &state.item_id, parent, None)?;
            }
        }
        let Some(item) =
            shown_item(conn, group_id, &candidate.path, state.item_id, &state, parent.to_vec())?
        else {
            continue;
        };
        let size = item.encoded_estimate();
        if !items.is_empty() && bytes + size > max_bytes {
            // The byte bound ends the page here; this child starts the next one.
            return Ok(Some(finish(conn, writer, root_id, parent, items, last, true)?));
        }
        bytes += size;
        last = Some(candidate.path);
        items.push(item);
    }
    Ok(Some(finish(conn, writer, root_id, parent, items, last, more_exists)?))
}

fn finish(
    conn: &rusqlite::Connection,
    writer: Option<&rusqlite::Transaction<'_>>,
    root_id: &str,
    parent: &[u8],
    items: Vec<ShownItem>,
    last: Option<String>,
    more: bool,
) -> Result<ChildrenPage, EnumerateError> {
    if let Some(tx) = writer {
        // The folder is recorded as opened (even when empty: a first child created later must
        // be logged).
        tx.execute(
            "INSERT OR IGNORE INTO provider_enumerated_parents (root_id, parent_item_id) \
             VALUES (?1, ?2)",
            rusqlite::params![root_id, parent],
        )?;
    }
    Ok(ChildrenPage {
        items,
        next_after: if more { last } else { None },
        anchor: namespace_revision(conn, root_id)?,
    })
}

// ---- changes since an anchor, and the working set ----

/// Which enumerator asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeScope {
    /// The working-set enumerator: every logged event (the OS asks for changes only here).
    WorkingSet,
    /// One folder's enumerator (the empty id is the root container).
    Container(Vec<u8>),
}

#[derive(Debug)]
pub struct ChangesPage {
    pub upserts: Vec<ShownItem>,
    pub removed: Vec<ItemId>,
    /// The last event sequence this page consumed (the revision read when none was left).
    pub next_anchor: u64,
    pub more: bool,
}

#[derive(Debug)]
pub enum ChangesError {
    /// The anchor is below the retained floor, above the current revision, or the root is
    /// unknown: the OS enumerates in full.
    AnchorExpired,
    Db(SyncSqliteError),
}

impl From<SyncSqliteError> for ChangesError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Db(error)
    }
}
impl From<rusqlite::Error> for ChangesError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error.into())
    }
}
impl From<r2d2::Error> for ChangesError {
    fn from(error: r2d2::Error) -> Self {
        Self::Db(error.into())
    }
}
impl yadorilink_sqlite_runtime::SqlOperationError for ChangesError {
    fn is_locked(&self) -> bool {
        match self {
            Self::Db(error) => error.is_locked(),
            _ => false,
        }
    }
}

/// The id of the live item at `parent_path`: `Some(empty)` for the root container, `None` when
/// the folder has no live item (it was never exposed).
fn parent_id_of(
    conn: &rusqlite::Connection,
    root_id: &str,
    parent_path: &str,
) -> Result<Option<Vec<u8>>, SyncSqliteError> {
    if parent_path.is_empty() {
        return Ok(Some(Vec::new()));
    }
    Ok(conn
        .query_row(
            "SELECT item_id FROM provider_items WHERE root_id = ?1 AND path = ?2 AND live = 1",
            rusqlite::params![root_id, parent_path],
            |r| r.get(0),
        )
        .optional()?)
}

fn is_enumerated(
    conn: &rusqlite::Connection,
    root_id: &str,
    parent_id: &[u8],
) -> Result<bool, SyncSqliteError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_enumerated_parents \
         WHERE root_id = ?1 AND parent_item_id = ?2)",
        rusqlite::params![root_id, parent_id],
        |r| r.get(0),
    )?)
}

struct EventRow {
    seq: u64,
    item_id: Vec<u8>,
}

/// What the OS must be told about one item NOW, relative to the scope.
enum Report {
    Upsert(ShownItem),
    Remove,
}

fn report_item(
    conn: &rusqlite::Connection,
    writer: Option<&rusqlite::Transaction<'_>>,
    root_id: &str,
    group_id: &str,
    item_bytes: &[u8],
    scope: &ChangeScope,
) -> Result<Option<Report>, ChangesError> {
    let live: Option<String> = conn
        .query_row(
            "SELECT path FROM provider_items WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
            rusqlite::params![root_id, item_bytes],
            |r| r.get(0),
        )
        .optional()?;
    let Some(path) = live else { return Ok(Some(Report::Remove)) };
    let parent = parent_id_of(conn, root_id, split_parent(&path).0)?;
    // Where the item stands relative to the enumerator that asks.
    let reachable = match (scope, &parent) {
        (ChangeScope::Container(p), Some(now)) => p == now,
        (ChangeScope::Container(_), None) => false,
        (ChangeScope::WorkingSet, Some(now)) => is_enumerated(conn, root_id, now)?,
        (ChangeScope::WorkingSet, None) => false,
    };
    if !reachable {
        // Moved into a folder the OS never opened: it can no longer reach the item, and its
        // membership of the working set ends (published view cleared) so a later listing shows
        // it afresh. A container scope only says "not here any more".
        if matches!(scope, ChangeScope::WorkingSet) {
            let Some(tx) = writer else { return Ok(None) };
            // Membership ends; the history of what was published and handed does NOT.
            tx.execute(
                "UPDATE provider_items SET exposed = 0 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, item_bytes],
            )?;
        }
        return Ok(Some(Report::Remove));
    }
    let item_id = item_id_from(item_bytes)?;
    let mut state = item_state(conn, root_id, &path)?.expect("the live item just read");
    if state.published.is_some() && !state.exposed {
        let Some(tx) = writer else { return Ok(None) };
        tx.execute(
            "UPDATE provider_items SET exposed = 1 WHERE root_id = ?1 AND item_id = ?2",
            rusqlite::params![root_id, item_bytes],
        )?;
    }
    if state.published.is_none() && state.announce.is_none() {
        // First reported by this page: published at the version shown, like a listing.
        let Some(tx) = writer else { return Ok(None) };
        let version = match current_version(conn, group_id, &path)? {
            Some(version) => Some(version),
            None => shown_version(conn, group_id, &path, None)?,
        };
        if let Some(version) = version {
            crate::dag_store::put_file_version(tx, group_id, &version)?;
            tx.execute(
                "UPDATE provider_items SET published_version_hash = ?3, exposed = 1 \
                 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, item_bytes, &version.version_hash.0[..]],
            )?;
            state.published = Some(version.version_hash);
        }
    }
    let parent_bytes = parent.unwrap_or_default();
    Ok(shown_item(conn, group_id, &path, item_id, &state, parent_bytes)?
        .map(Report::Upsert)
        .or(Some(Report::Remove)))
}

#[allow(clippy::too_many_arguments)]
fn changes_in(
    conn: &rusqlite::Connection,
    writer: Option<&rusqlite::Transaction<'_>>,
    root_id: &str,
    group_id: &str,
    scope: &ChangeScope,
    since: u64,
    limit: usize,
    max_bytes: usize,
) -> Result<Option<ChangesPage>, ChangesError> {
    let (floor, current): (i64, i64) = conn.query_row(
        "SELECT change_floor, namespace_revision FROM provider_roots WHERE root_id = ?1",
        [root_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if (since as i64) < floor || (since as i64) > current {
        return Err(ChangesError::AnchorExpired);
    }
    let events: Vec<EventRow> = {
        let (sql, container): (&str, Option<&[u8]>) = match scope {
            ChangeScope::WorkingSet => (
                "SELECT seq, item_id FROM provider_change_events \
                 WHERE root_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
                None,
            ),
            ChangeScope::Container(parent) => (
                "SELECT seq, item_id FROM provider_change_events \
                 WHERE root_id = ?1 AND seq > ?2 AND (parent_item_id = ?4 OR old_parent_item_id = ?4) \
                 ORDER BY seq LIMIT ?3",
                Some(parent.as_slice()),
            ),
        };
        let mut stmt = conn.prepare_cached(sql)?;
        let map = |r: &rusqlite::Row<'_>| {
            Ok(EventRow { seq: r.get::<_, i64>(0)? as u64, item_id: r.get(1)? })
        };
        let rows = match container {
            None => stmt
                .query_map(rusqlite::params![root_id, since as i64, limit as i64], map)?
                .collect::<Result<_, _>>()?,
            Some(parent) => stmt
                .query_map(rusqlite::params![root_id, since as i64, limit as i64, parent], map)?
                .collect::<Result<_, _>>()?,
        };
        rows
    };
    let exhausted = events.len() < limit;
    let mut upserts = Vec::new();
    let mut removed = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut bytes = 0usize;
    let mut consumed = since;
    let mut cut_short = false;
    for event in &events {
        if seen.insert(event.item_id.clone()) {
            match report_item(conn, writer, root_id, group_id, &event.item_id, scope)? {
                None => return Ok(None),
                Some(Report::Remove) => {
                    removed.push(item_id_from(&event.item_id)?);
                    bytes += 32;
                }
                Some(Report::Upsert(item)) => {
                    let size = item.encoded_estimate();
                    if !upserts.is_empty() && bytes + size > max_bytes {
                        cut_short = true;
                        break;
                    }
                    bytes += size;
                    upserts.push(item);
                }
            }
        }
        consumed = event.seq;
    }
    let more = cut_short || !exhausted;
    let next_anchor = if more { consumed } else { current as u64 };
    Ok(Some(ChangesPage { upserts, removed, next_anchor, more }))
}

#[derive(Debug)]
pub struct WorkingSetPage {
    pub items: Vec<ShownItem>,
    /// The last item id of the page when more follow (the keyset cursor).
    pub next_after: Option<ItemId>,
    /// The event sequence read by this page's transaction.
    pub anchor: u64,
}

impl ProviderRepository {
    /// Changes of the root since `since` for one enumerator. A request
    /// that finds nothing to write is answered from a read.
    #[allow(clippy::too_many_arguments)]
    pub fn enumerate_changes(
        &self,
        root_id: &str,
        scope: &ChangeScope,
        since: u64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<ChangesPage, ChangesError> {
        let Some(group_id) = self.group_of_root(root_id)? else {
            return Err(ChangesError::AnchorExpired);
        };
        let mut failure = None;
        let read = self.read_settled(|conn| {
            match changes_in(conn, None, root_id, &group_id, scope, since, limit, max_bytes) {
                Ok(page) => Ok(page),
                Err(ChangesError::Db(error)) => Err(error),
                Err(other) => {
                    failure = Some(other);
                    Ok(None)
                }
            }
        })?;
        if let Some(page) = read {
            return Ok(page);
        }
        if let Some(error) = failure {
            return Err(error);
        }
        self.database_for_write().write_immediate::<_, ChangesError>(|tx| {
            yadorilink_sqlite_runtime::reconcile_provider_liveness(tx)?;
            Ok(changes_in(tx, Some(tx), root_id, &group_id, scope, since, limit, max_bytes)?
                .expect("a write pass always answers"))
        })
    }

    /// One page of the working set: every live item the OS was shown (a published view), by item
    /// id. `after` is the keyset cursor.
    pub fn enumerate_working_set(
        &self,
        root_id: &str,
        after: Option<&ItemId>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<WorkingSetPage, EnumerateError> {
        let group_id = self.group_of_root(root_id)?.ok_or(EnumerateError::NotFound)?;
        self.read_settled_enum(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT item_id, path FROM provider_items WHERE root_id = ?1 AND live = 1 \
                 AND exposed = 1 AND item_id > ?2 ORDER BY item_id LIMIT ?3",
            )?;
            let start: Vec<u8> = after.map(|a| a.to_vec()).unwrap_or_default();
            let rows: Vec<(Vec<u8>, String)> = stmt
                .query_map(rusqlite::params![root_id, start, limit as i64 + 1], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .collect::<Result<_, _>>()?;
            let more_exists = rows.len() > limit;
            let mut items = Vec::new();
            let mut bytes = 0usize;
            let mut last = None;
            let mut cut_short = false;
            for (id_bytes, path) in rows.into_iter().take(limit) {
                let item_id = item_id_from(&id_bytes)?;
                let state = item_state(conn, root_id, &path)?.expect("the live item just read");
                let parent =
                    parent_id_of(conn, root_id, split_parent(&path).0)?.unwrap_or_default();
                let Some(item) = shown_item(conn, &group_id, &path, item_id, &state, parent)?
                else {
                    last = Some(item_id);
                    continue;
                };
                let size = item.encoded_estimate();
                if !items.is_empty() && bytes + size > max_bytes {
                    cut_short = true;
                    break;
                }
                bytes += size;
                last = Some(item_id);
                items.push(item);
            }
            Ok(WorkingSetPage {
                items,
                next_after: if more_exists || cut_short { last } else { None },
                anchor: namespace_revision(conn, root_id)?,
            })
        })
    }
}

impl ProviderRepository {
    /// Drops the oldest change events of the root beyond `keep` (and any older than
    /// `older_than_s` seconds since the epoch), only ever from the front, and raises
    /// `change_floor` to the last sequence dropped: an anchor below it is expired.
    pub fn prune_change_events(
        &self,
        root_id: &str,
        keep: usize,
        older_than_s: i64,
    ) -> Result<usize, SyncSqliteError> {
        self.database_for_write().write_immediate::<_, SyncSqliteError>(|tx| {
            // The first sequence that must stay: not older than the age bound, and within the
            // newest `keep`.
            let by_count: Option<i64> = tx
                .query_row(
                    "SELECT seq FROM provider_change_events WHERE root_id = ?1 \
                     ORDER BY seq DESC LIMIT 1 OFFSET ?2",
                    rusqlite::params![root_id, keep as i64],
                    |r| r.get(0),
                )
                .optional()?;
            let by_age: Option<i64> = tx.query_row(
                "SELECT MAX(seq) FROM provider_change_events WHERE root_id = ?1 AND at_s < ?2",
                rusqlite::params![root_id, older_than_s],
                |r| r.get(0),
            )?;
            let drop_through = by_count.into_iter().chain(by_age).max();
            let Some(through) = drop_through else { return Ok(0) };
            let dropped = tx.execute(
                "DELETE FROM provider_change_events WHERE root_id = ?1 AND seq <= ?2",
                rusqlite::params![root_id, through],
            )?;
            tx.execute(
                "UPDATE provider_roots SET change_floor = MAX(change_floor, ?2) WHERE root_id = ?1",
                rusqlite::params![root_id, through],
            )?;
            Ok(dropped)
        })
    }
}
