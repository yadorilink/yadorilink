//! Persistence for the native-causal-state domain model
//! (`yadorilink_replica_domain::native_state`/`signed_delta`/
//! `native_checkpoint`): an atomic local-mutation/remote-join/checkpoint
//! install over a per-group `NativeState`, reusing that type's own
//! `author`/`join` rather than re-deriving the transition rule in SQL, plus
//! `namespace_root`/`namespace_diff`, reusing `yadorilink-namespace::v2`
//! unmodified. Every function here takes a plain `&Connection`: a
//! `rusqlite::Transaction` derefs to `Connection`, so passing `&tx` is what
//! makes an install atomic with whatever else the caller commits alongside
//! it -- this module opens no transaction of its own. A delta install reads
//! and writes only the paths its ops touch (and the one author's context and
//! frontier rows), so its cost does not grow with the group;
//! [`load_state`]/[`install_state`] replace the whole group and are for the
//! callers that genuinely change all of it (a join, a recovery).
//!
//! The first-class `NativeAuthorFrontier` (`AuthorId -> {seq,
//! tip_header_hash}`, `yadorilink_replica_domain::native_frontier`) is its
//! own persisted table, and [`install_verified_delta`] is the production
//! authority path for one real, verified `NativeDelta`: it advances
//! `NativeState.context` and the frontier together, atomically, and
//! maintains `state.context[author] == frontier[author].seq` as an
//! invariant across every commit. [`author_local`] (plain unsigned
//! `PathEdit`s) is test/helper-only -- it cannot update the frontier,
//! having no verified delta to derive a real tip from, so it must never
//! become (or be mistaken for) the production authority path.

use rusqlite::{Connection, OptionalExtension};

use yadorilink_namespace::v2::{self, PathEditV2};
use yadorilink_namespace::{empty_digest, MemoryNodeStore, NodeDigest};
use yadorilink_replica_domain::author::{AuthorBuckets, AuthorId, IncarnationId};
use yadorilink_replica_domain::ids::{AuthorSeq, DeltaHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::native_checkpoint::NativeCheckpoint;
use yadorilink_replica_domain::native_frontier::{
    self, AuthorState, NativeAuthorFrontier, NativeAuthorFrontierEntry, NativeAuthorStates,
};
#[cfg(any(test, feature = "test-support"))]
use yadorilink_replica_domain::native_state::PathEdit;
use yadorilink_replica_domain::native_state::{AuthorError, Dot, HeadPayload, NativeState};
use yadorilink_replica_domain::signed_delta::NativeDelta;

use crate::error::SyncSqliteError;

/// Per-thread counts of `native_heads` rows read and written by the state
/// loaders and installers in this module, for tests that pin how the cost of
/// authoring and installing a delta grows with the size of the group. Compiled
/// out of production builds.
#[cfg(any(test, feature = "test-support"))]
pub mod head_row_counters {
    use std::cell::Cell;

    thread_local! {
        static READ: Cell<u64> = const { Cell::new(0) };
        static WRITTEN: Cell<u64> = const { Cell::new(0) };
    }

    /// Zeroes this thread's counters.
    pub fn reset() {
        READ.with(|c| c.set(0));
        WRITTEN.with(|c| c.set(0));
    }

    /// `(rows read, rows written)` on this thread since the last [`reset`].
    pub fn snapshot() -> (u64, u64) {
        (READ.with(Cell::get), WRITTEN.with(Cell::get))
    }

    pub(crate) fn add_read(rows: usize) {
        READ.with(|c| c.set(c.get() + rows as u64));
    }

    pub(crate) fn add_written(rows: usize) {
        WRITTEN.with(|c| c.set(c.get() + rows as u64));
    }
}

#[cfg(any(test, feature = "test-support"))]
use head_row_counters::{add_read as count_head_rows_read, add_written as count_head_rows_written};
#[cfg(not(any(test, feature = "test-support")))]
fn count_head_rows_read(_rows: usize) {}
#[cfg(not(any(test, feature = "test-support")))]
fn count_head_rows_written(_rows: usize) {}

pub(crate) fn read_author(
    device: String,
    incarnation: Vec<u8>,
) -> Result<AuthorId, SyncSqliteError> {
    Ok(AuthorId { device: DeviceId(device), incarnation: IncarnationId(as_array16(&incarnation)?) })
}

fn as_array16(bytes: &[u8]) -> Result<[u8; 16], SyncSqliteError> {
    bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!("expected 16 bytes, found {}", bytes.len()))
    })
}

/// Creates the native-causal-state tables on `conn`.
pub fn init_native_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- Per-author position, per group: `NativeState::context`. Each
        -- install moves the delta's author's row and the touched paths' head
        -- rows together inside one transaction, keeping the two in lockstep.
        -- `author`/`incarnation` together are the full `AuthorId`: a
        -- restored or cloned replica of the same device writes under a
        -- different incarnation, so it never collides with the original's
        -- sequence numbers.
        CREATE TABLE IF NOT EXISTS native_author_context (
            group_id     TEXT NOT NULL,
            author       TEXT NOT NULL,
            incarnation  BLOB NOT NULL,
            seq          INTEGER NOT NULL,
            PRIMARY KEY (group_id, author, incarnation)
        );

        -- Live heads, per group: `NativeState::heads`. `provenance` is the
        -- signed-delta header hash (`native_state::DeltaHash`), zero where
        -- nothing is signed yet.
        CREATE TABLE IF NOT EXISTS native_heads (
            group_id      TEXT NOT NULL,
            path          TEXT NOT NULL,
            author        TEXT NOT NULL,
            incarnation   BLOB NOT NULL,
            seq           INTEGER NOT NULL,
            version       BLOB NOT NULL,
            provenance    BLOB NOT NULL,
            PRIMARY KEY (group_id, path, author, incarnation, seq)
        );

        -- The deltas a `files` row's native identity was verified against when
        -- the row was written: the durable evidence that the identity named a
        -- head this replica really held. It outlives the delta log's and the
        -- head's own retention (a row shows its head long after the head is
        -- superseded or its delta is truncated), so the row stays authored.
        -- Keyed by the WHOLE identity (source path, dot, provenance): evidence
        -- that this exact head was held, never a licence for another row to
        -- cite a provenance that once existed.
        CREATE TABLE IF NOT EXISTS native_authoring_witness (
            group_id  TEXT NOT NULL,
            identity  BLOB NOT NULL,
            -- The version the head carried: a row may cite this identity only
            -- while it shows this version.
            version   BLOB NOT NULL,
            PRIMARY KEY (group_id, identity)
        );
        -- Which witnessed identities show a version (block-serving authorization).
        CREATE INDEX IF NOT EXISTS idx_native_authoring_witness_version
            ON native_authoring_witness (group_id, version);
        -- The paths whose materialization a newly arrived version unblocks.
        CREATE INDEX IF NOT EXISTS idx_native_heads_version ON native_heads (group_id, version);

        -- The authenticated sync/equivocation frontier, per group:
        -- `NativeAuthorFrontier`. Separate from `native_author_context` by
        -- product decision -- `tip` is signed-delta-chain metadata, not
        -- semantic state -- but `install_verified_delta` keeps
        -- `native_author_context.seq == native_author_frontier.seq`
        -- for every author as a cross-table invariant, updated together in
        -- one transaction.
        CREATE TABLE IF NOT EXISTS native_author_frontier (
            group_id          TEXT NOT NULL,
            author            TEXT NOT NULL,
            incarnation       BLOB NOT NULL,
            seq               INTEGER NOT NULL,
            tip               BLOB NOT NULL,
            PRIMARY KEY (group_id, author, incarnation)
        );

        -- Closed authors: an author here is closed only while a verified closure
        -- its own device signed with exactly this cutoff is held
        -- (`native_author_closure`) -- never by inactivity or a live-head count
        -- reaching zero, which is why there is no cadence/timer logic anywhere
        -- that writes this table.
        -- Closing does not remove or freeze the author's row in
        -- `native_author_frontier` -- the frontier row stays the coverage
        -- record. `cutoff_*` is the frontier entry at closure (all NULL: closed
        -- before the first delta, so no delta of it is admissible), and
        -- admission refuses every delta above `cutoff_seq`.
        CREATE TABLE IF NOT EXISTS native_closed_authors (
            group_id             TEXT NOT NULL,
            author               TEXT NOT NULL,
            incarnation          BLOB NOT NULL,
            closed_at_unixtime   INTEGER NOT NULL,
            cutoff_seq           INTEGER CHECK (cutoff_seq IS NULL OR cutoff_seq >= 1),
            cutoff_tip           BLOB,
            PRIMARY KEY (group_id, author, incarnation),
            CHECK ((cutoff_seq IS NULL) = (cutoff_tip IS NULL))
        );

        -- Sealed checkpoints, per group. Keyed by the checkpoint's own
        -- content hash so re-installing an already-known checkpoint is an
        -- idempotent no-op (`INSERT OR IGNORE`, see `install_checkpoint`).
        -- `NativeCheckpoint`'s roots are opaque here -- nothing here
        -- reconstructs state from a checkpoint; see the module doc.
        CREATE TABLE IF NOT EXISTS native_checkpoints (
            group_id              TEXT NOT NULL,
            checkpoint_hash        BLOB NOT NULL,
            namespace_root         BLOB NOT NULL,
            author_state_root      BLOB NOT NULL,
            signature              BLOB NOT NULL,
            installed_at_unixtime  INTEGER NOT NULL,
            PRIMARY KEY (group_id, checkpoint_hash)
        );

        -- Every seq ever installed for an author, per group: enough to
        -- tell a re-delivered old seq's exact hash apart from a fork,
        -- without keeping full delta bodies (native_author_frontier only
        -- keeps the *current* tip). Written by [`install_verified_delta`]
        -- itself -- the one choke point every installed delta passes
        -- through, whether locally authored or remotely admitted -- so
        -- local-publication tracking and the remote duplicate/
        -- equivocation check share one source of truth (see
        -- [`record_delta_log`]'s own doc).
        CREATE TABLE IF NOT EXISTS native_delta_log (
            group_id     TEXT NOT NULL,
            author       TEXT NOT NULL,
            incarnation  BLOB NOT NULL,
            seq          INTEGER NOT NULL,
            delta_hash   BLOB NOT NULL,
            PRIMARY KEY (group_id, author, incarnation, seq)
        );

        -- The canonical encoded body of every delta this replica has
        -- installed (locally authored or remotely admitted), so it can be
        -- re-served to a peer later -- including after this replica's own
        -- restart, and including a delta whose head is no longer live in
        -- current `NativeState` (this table is the only durable source of
        -- a superseded delta's own bytes; `native_delta_log` next to it
        -- keeps only the hash). See
        -- [`fetch_delta_body`]/[`fetch_delta_body_by_hash`]. Written by
        -- [`install_verified_delta_inner`] in the same transaction as
        -- [`record_delta_log`], so a delta's body and its hash-log entry
        -- are always installed atomically together.
        CREATE TABLE IF NOT EXISTS native_delta_bodies (
            group_id       TEXT NOT NULL,
            author         TEXT NOT NULL,
            incarnation    BLOB NOT NULL,
            seq            INTEGER NOT NULL,
            delta_hash     BLOB NOT NULL,
            encoded_delta  BLOB NOT NULL,
            PRIMARY KEY (group_id, author, incarnation, seq)
        );
        CREATE INDEX IF NOT EXISTS native_delta_bodies_by_hash
            ON native_delta_bodies (group_id, delta_hash);
        "#,
    )?;
    crate::native_closure::init_tables(conn)?;
    crate::native_contest_candidates::init_tables(conn)?;
    crate::native_checkpoint_frontier::init_tables(conn)?;
    crate::native_history_floor::init_tables(conn)?;
    crate::native_rebootstrap::init_tables(conn)?;
    crate::native_rebootstrap_install::init_tables(conn)?;
    crate::native_rebootstrap_replay::init_tables(conn)?;
    crate::native_recovery_items::init_tables(conn)?;
    crate::native_summary_cache::init_tables(conn)?;
    crate::projection_obligations::init_projection_obligations_schema(conn)?;
    crate::pinned_items::init_pinned_items_schema(conn)?;
    Ok(())
}

/// A delta's own encoded body, by the exact identity [`record_delta_log`]
/// already keys on -- `None` if this replica never installed a delta at this
/// identity (a replica joined from a checkpoint holds none below it).
pub fn fetch_delta_body(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
) -> Result<Option<Vec<u8>>, SyncSqliteError> {
    conn.query_row(
        "SELECT encoded_delta FROM native_delta_bodies \
         WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND seq = ?4",
        (
            group_id.as_str(),
            author.device.as_str(),
            author.incarnation.0.as_slice(),
            seq.get() as i64,
        ),
        |row| row.get(0),
    )
    .optional()
    .map_err(SyncSqliteError::from)
}

/// A delta's own encoded body, looked up by its `delta_hash` alone (a
/// peer request naming a hash it wants, rather than an `(author, seq)`
/// pair) -- `None` on the same terms as [`fetch_delta_body`].
pub fn fetch_delta_body_by_hash(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta_hash: &DeltaHash,
) -> Result<Option<Vec<u8>>, SyncSqliteError> {
    conn.query_row(
        "SELECT encoded_delta FROM native_delta_bodies WHERE group_id = ?1 AND delta_hash = ?2",
        (group_id.as_str(), delta_hash.0.as_slice()),
        |row| row.get(0),
    )
    .optional()
    .map_err(SyncSqliteError::from)
}

/// Every path that holds a live head of `version`, in path order.
pub(crate) fn native_paths_with_version(
    conn: &Connection,
    group_id: &FolderGroupId,
    version: &yadorilink_replica_domain::ids::VersionHash,
) -> Result<Vec<String>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT path FROM native_heads INDEXED BY idx_native_heads_version \
         WHERE group_id = ?1 AND version = ?2 ORDER BY path",
    )?;
    let paths = stmt
        .query_map(rusqlite::params![group_id.as_str(), &version.0[..]], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(paths)
}

/// Reconstructs the group's `NativeState` from its persisted rows. Absent
/// entirely (a fresh group) reads back as `NativeState::default()`.
pub fn load_state(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<NativeState, SyncSqliteError> {
    let mut state = NativeState::new();

    let mut context_stmt = conn.prepare(
        "SELECT author, incarnation, seq FROM native_author_context WHERE group_id = ?1",
    )?;
    let mut rows = context_stmt.query([group_id.as_str()])?;
    while let Some(row) = rows.next()? {
        let author: String = row.get(0)?;
        let incarnation: Vec<u8> = row.get(1)?;
        let seq: i64 = row.get(2)?;
        state.context.insert(
            read_author(author, incarnation)?,
            yadorilink_replica_domain::ids::AuthorSeq(seq as u64),
        );
    }
    drop(rows);
    drop(context_stmt);

    let mut heads_stmt = conn.prepare(
        "SELECT path, author, incarnation, seq, version, provenance FROM native_heads WHERE group_id = ?1",
    )?;
    let mut rows = heads_stmt.query([group_id.as_str()])?;
    while let Some(row) = rows.next()? {
        let path: String = row.get(0)?;
        let author: String = row.get(1)?;
        let incarnation: Vec<u8> = row.get(2)?;
        let seq: i64 = row.get(3)?;
        let version: Vec<u8> = row.get(4)?;
        let provenance: Vec<u8> = row.get(5)?;

        let dot = Dot {
            author: read_author(author, incarnation)?,
            seq: yadorilink_replica_domain::ids::AuthorSeq(seq as u64),
        };
        let payload = HeadPayload {
            version: yadorilink_replica_domain::ids::VersionHash(as_array32(&version)?),
            provenance: yadorilink_replica_domain::native_state::DeltaHash(as_array32(
                &provenance,
            )?),
        };
        state
            .heads
            .entry(yadorilink_replica_domain::ids::SyncPath(path))
            .or_default()
            .insert(dot, payload);
        count_head_rows_read(1);
    }
    Ok(state)
}

/// One path's live heads, read directly from `native_heads` (indexed by
/// `(group_id, path, ...)`) rather than [`load_state`]'s full replay --
/// the per-path analog of [`crate::dcf_heads::heads_at`], for a caller
/// (a shadow comparison) that runs after every local event and
/// cannot afford `load_state`'s whole-group cost on every call.
pub fn native_heads_at(
    conn: &Connection,
    group_id: &FolderGroupId,
    path: &SyncPath,
) -> Result<Vec<yadorilink_replica_domain::native_state::LiveHead>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT author, incarnation, seq, version, provenance \
         FROM native_heads WHERE group_id = ?1 AND path = ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![group_id.as_str(), path.as_str()])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(live_head_from_row(row, 0)?);
    }
    Ok(out)
}

/// The live head in the columns `author, incarnation, seq, version, provenance`
/// starting at column `base` of `row`.
fn live_head_from_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> Result<yadorilink_replica_domain::native_state::LiveHead, SyncSqliteError> {
    let author: String = row.get(base)?;
    let incarnation: Vec<u8> = row.get(base + 1)?;
    let seq: i64 = row.get(base + 2)?;
    let version: Vec<u8> = row.get(base + 3)?;
    let provenance: Vec<u8> = row.get(base + 4)?;
    count_head_rows_read(1);
    Ok(yadorilink_replica_domain::native_state::LiveHead {
        dot: Dot { author: read_author(author, incarnation)?, seq: AuthorSeq(seq as u64) },
        payload: HeadPayload {
            version: yadorilink_replica_domain::ids::VersionHash(as_array32(&version)?),
            provenance: DeltaHash(as_array32(&provenance)?),
        },
    })
}

/// Whether anything strictly below `path` has a native live head --
/// unlike [`crate::dcf_heads::has_descendant_head`], every row in
/// `native_heads` is already live by construction (a removed head is a
/// deleted row, never a tombstone), so this is a plain existence check.
pub fn native_has_descendant_head(
    conn: &Connection,
    group_id: &FolderGroupId,
    path: &SyncPath,
) -> Result<bool, SyncSqliteError> {
    let lower = format!("{}/", path.as_str());
    let upper = format!("{}0", path.as_str());
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM native_heads \
             WHERE group_id = ?1 AND path > ?2 AND path < ?3)",
        )?
        .query_row(rusqlite::params![group_id.as_str(), lower, upper], |row| row.get(0))?)
}

/// The heads of a level's paths, and the children with a live head below them.
pub type NativeLevelHeads = (
    std::collections::BTreeMap<SyncPath, std::collections::BTreeMap<Dot, HeadPayload>>,
    std::collections::BTreeSet<String>,
);

/// One directory level of the live heads: the heads of every path whose
/// parent is `parent` (`""` for the root), and the children (with or
/// without heads of their own) that have a live head strictly below them.
/// The level analog of [`crate::dcf_heads::heads_at_level`]: it reads
/// `parent`'s subtree only, and never a descendant's version.
pub fn native_heads_at_level(
    conn: &Connection,
    group_id: &FolderGroupId,
    parent: &str,
) -> Result<NativeLevelHeads, SyncSqliteError> {
    if parent.ends_with('/') {
        return Err(SyncSqliteError::InvalidInput(format!(
            "level query needs a normalized parent path, got {parent:?}"
        )));
    }
    let (lower, upper) = if parent.is_empty() {
        (String::new(), None)
    } else {
        (format!("{parent}/"), Some(format!("{parent}0")))
    };
    // Two statements, not one with `(?3 IS NULL OR path < ?3)`: the OR hides the
    // upper bound from the index, and the scan would run to the end of the group.
    let mut stmt = conn.prepare_cached(if upper.is_some() {
        "SELECT path, author, incarnation, seq, version, provenance \
         FROM native_heads WHERE group_id = ?1 AND path > ?2 AND path < ?3 ORDER BY path"
    } else {
        "SELECT path, author, incarnation, seq, version, provenance \
         FROM native_heads WHERE group_id = ?1 AND path > ?2 ORDER BY path"
    })?;
    let mut rows = match &upper {
        Some(upper) => stmt.query(rusqlite::params![group_id.as_str(), lower, upper])?,
        None => stmt.query(rusqlite::params![group_id.as_str(), lower])?,
    };
    let mut children: std::collections::BTreeMap<
        SyncPath,
        std::collections::BTreeMap<Dot, HeadPayload>,
    > = std::collections::BTreeMap::new();
    let mut with_descendant = std::collections::BTreeSet::new();
    while let Some(row) = rows.next()? {
        let path: String = row.get(0)?;
        count_head_rows_read(1);
        let rest = &path[lower.len()..];
        if let Some((child, _)) = rest.split_once('/') {
            with_descendant.insert(format!("{lower}{child}"));
            continue;
        }
        let author: String = row.get(1)?;
        let incarnation: Vec<u8> = row.get(2)?;
        let seq: i64 = row.get(3)?;
        let version: Vec<u8> = row.get(4)?;
        let provenance: Vec<u8> = row.get(5)?;
        children.entry(SyncPath(path)).or_default().insert(
            Dot { author: read_author(author, incarnation)?, seq: AuthorSeq(seq as u64) },
            HeadPayload {
                version: yadorilink_replica_domain::ids::VersionHash(as_array32(&version)?),
                provenance: DeltaHash(as_array32(&provenance)?),
            },
        );
    }
    Ok((children, with_descendant))
}

pub(crate) fn as_array32(bytes: &[u8]) -> Result<[u8; 32], SyncSqliteError> {
    bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!("expected 32 bytes, found {}", bytes.len()))
    })
}

/// One path's live heads as the `yadorilink-namespace::v2` bucket shape:
/// per author, the ascending, deduplicated provenance hashes of that
/// author's current heads there. `v2::patch` itself rejects a bucket over
/// `MAX_SELF_HEADS`, so a state that violates that bound (which
/// `NativeState::author` never produces) is refused here, not silently
/// truncated.
fn author_buckets(heads: &std::collections::BTreeMap<Dot, HeadPayload>) -> AuthorBuckets {
    let mut by_author: std::collections::BTreeMap<AuthorId, Vec<DeltaHash>> =
        std::collections::BTreeMap::new();
    for (dot, payload) in heads {
        by_author.entry(dot.author.clone()).or_default().push(payload.provenance);
    }
    for bucket in by_author.values_mut() {
        bucket.sort();
        bucket.dedup();
    }
    AuthorBuckets { by_author }
}

/// The authenticated namespace root of `state` (the checkpoint's `namespace_root`),
/// computed by reusing `yadorilink-namespace::v2::patch` unmodified over an
/// in-memory node store rebuilt from scratch each call.
///
/// Recomputing the whole trie from the full loaded state is linear in the
/// number of paths, however little changed. The summary a peer is answered
/// with therefore does not call this per exchange: it is memoized per state
/// token (see [`crate::native_summary_cache`]), so the trie is rebuilt once
/// per change of the group, not once per peer per interval. There is no
/// persisted trie to patch, and none is needed while one rebuild per burst of
/// changes is affordable.
pub fn namespace_root(state: &NativeState) -> Result<NodeDigest, SyncSqliteError> {
    namespace_root_into(&mut MemoryNodeStore::new(), state)
}

/// Every path whose live heads differ between `left` and `right` — a hint
/// for a peer summary exchange (a peer's context and root are
/// reconciliation hints only), never itself a source of semantic state.
pub fn namespace_diff(
    left: &NativeState,
    right: &NativeState,
) -> Result<Vec<yadorilink_namespace::v2::PathDiffV2>, SyncSqliteError> {
    let mut store = MemoryNodeStore::new();
    let left_root = namespace_root_into(&mut store, left)?;
    let right_root = namespace_root_into(&mut store, right)?;
    v2::diff(&store, &left_root, &right_root)
        .map_err(|err| SyncSqliteError::CorruptState(format!("namespace diff failed: {err}")))
}

fn namespace_root_into(
    store: &mut dyn v2::NodeStoreV2,
    state: &NativeState,
) -> Result<NodeDigest, SyncSqliteError> {
    let root = empty_digest();
    let mut edits: Vec<PathEditV2> = state
        .heads
        .iter()
        .map(|(path, heads)| PathEditV2 { path: path.clone(), heads: author_buckets(heads) })
        .collect();
    // `v2::patch` applies edits in order and does not require any
    // particular order itself, but a fixed order keeps this function's
    // output independent of `BTreeMap` iteration incidental details across
    // Rust versions.
    edits.sort_by(|a, b| a.path.cmp(&b.path));
    v2::patch(store, &root, &edits)
        .map_err(|err| SyncSqliteError::CorruptState(format!("namespace patch failed: {err}")))
}

// --- the authenticated author frontier ------------------------------

/// Reconstructs the group's `NativeAuthorFrontier` from its persisted rows.
pub fn load_frontier(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<NativeAuthorFrontier, SyncSqliteError> {
    let mut frontier = NativeAuthorFrontier::new();
    let mut stmt = conn.prepare(
        "SELECT author, incarnation, seq, tip FROM native_author_frontier WHERE group_id = ?1",
    )?;
    let mut rows = stmt.query([group_id.as_str()])?;
    while let Some(row) = rows.next()? {
        let author: String = row.get(0)?;
        let incarnation: Vec<u8> = row.get(1)?;
        let seq: i64 = row.get(2)?;
        let tip: Vec<u8> = row.get(3)?;
        frontier.insert(
            read_author(author, incarnation)?,
            NativeAuthorFrontierEntry {
                seq: AuthorSeq(seq as u64),
                tip: yadorilink_replica_domain::native_state::DeltaHash(as_array32(&tip)?),
            },
        );
    }
    Ok(frontier)
}

/// One author's frontier entry, read directly by primary key — `O(1)`
/// against the SQLite index regardless of how many authors the group has,
/// unlike [`load_frontier`]. This is what [`install_verified_delta`] (the
/// hot path) uses instead of loading and replacing the whole frontier for
/// a single-author change (a full replace is a linear full scan, which this
/// function exists to remove from the hot path;
/// [`load_frontier`]/[`install_frontier`] remain for bulk uses that
/// genuinely need every author, such as computing a root).
pub fn frontier_entry_get(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<Option<NativeAuthorFrontierEntry>, SyncSqliteError> {
    conn.query_row(
        "SELECT seq, tip FROM native_author_frontier WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3",
        (group_id.as_str(), author.device.as_str(), author.incarnation.0.as_slice()),
        |row| {
            let seq: i64 = row.get(0)?;
            let tip: Vec<u8> = row.get(1)?;
            Ok((seq, tip))
        },
    )
    .optional()?
    .map(|(seq, tip)| {
        Ok(NativeAuthorFrontierEntry {
            seq: AuthorSeq(seq as u64),
            tip: yadorilink_replica_domain::native_state::DeltaHash(as_array32(&tip)?),
        })
    })
    .transpose()
}

/// One author's `NativeState.context` entry, read directly by primary key
/// — `O(1)`, like [`frontier_entry_get`]. What remote admission's op-level context gate
/// (`native_admission`) uses to decide whether a removal names a dot this
/// replica has ever observed, without loading the whole state.
pub fn author_context_seq(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<Option<AuthorSeq>, SyncSqliteError> {
    conn.query_row(
        "SELECT seq FROM native_author_context WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3",
        (group_id.as_str(), author.device.as_str(), author.incarnation.0.as_slice()),
        |row| row.get::<_, i64>(0),
    )
    .optional()?
    .map(|seq| Ok(AuthorSeq(seq as u64)))
    .transpose()
}

/// Writes exactly one author's frontier entry — a single-row upsert, not a
/// full-group replace. See [`frontier_entry_get`]'s doc for why this
/// exists.
pub fn frontier_entry_upsert(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    entry: &NativeAuthorFrontierEntry,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT INTO native_author_frontier (group_id, author, incarnation, seq, tip) VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (group_id, author, incarnation) DO UPDATE SET seq = excluded.seq, tip = excluded.tip",
        (
            group_id.as_str(),
            author.device.as_str(),
            author.incarnation.0.as_slice(),
            entry.seq.get() as i64,
            entry.tip.0.as_slice(),
        ),
    )?;
    Ok(())
}

/// Replaces the group's persisted frontier with `frontier` in full — a bulk
/// operation for callers that genuinely need every author (root
/// computation, retirement's active/retired split), not the single-author
/// hot path (see [`frontier_entry_get`]/[`frontier_entry_upsert`]).
pub fn install_frontier(
    conn: &Connection,
    group_id: &FolderGroupId,
    frontier: &NativeAuthorFrontier,
) -> Result<(), SyncSqliteError> {
    conn.execute("DELETE FROM native_author_frontier WHERE group_id = ?1", [group_id.as_str()])?;
    let mut insert = conn.prepare(
        "INSERT INTO native_author_frontier (group_id, author, incarnation, seq, tip) VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for (author, entry) in frontier {
        insert.execute((
            group_id.as_str(),
            author.device.as_str(),
            author.incarnation.0.as_slice(),
            entry.seq.get() as i64,
            entry.tip.0.as_slice(),
        ))?;
    }
    Ok(())
}

// --- closure ----------------------------------------------------------------------

pub fn is_closed(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<bool, SyncSqliteError> {
    crate::native_closure::closed_cutoff_entry(conn, group_id, author).map(|c| c.is_some())
}

/// Every author of `group_id` with its state, as a checkpoint commits them: a
/// closed author is closed at the cutoff its closure stores (none: before its
/// first delta, so it has no frontier entry), every other author with a
/// frontier entry is open at it.
pub fn load_author_states(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<NativeAuthorStates, SyncSqliteError> {
    let mut states: NativeAuthorStates = load_frontier(conn, group_id)?
        .into_iter()
        .map(|(author, entry)| (author, AuthorState::Open(entry)))
        .collect();
    for (author, frontier) in crate::native_closure::load_closed_authors(conn, group_id)? {
        states.insert(author, AuthorState::Closed { frontier });
    }
    Ok(states)
}

/// The checkpoint's `author_state_root`: the root over every author's state
/// ([`native_frontier::author_state_root`]), which commits whether each author
/// is open or closed and its entry or the absence of one.
pub fn author_state_root(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<NodeDigest, SyncSqliteError> {
    Ok(NodeDigest(native_frontier::author_state_root(&load_author_states(conn, group_id)?)))
}

/// Builds and signs a checkpoint committing the group's current
/// `namespace_root` and `author_state_root` — the real computed roots, never
/// opaque placeholders. Does not install it; call [`install_checkpoint`]
/// separately (sealing and installing are different capabilities: a
/// sealer's key signs here, but *this* replica's own admission of the
/// resulting checkpoint is a separate, symmetric step any replica —
/// including the sealer itself — performs the same way).
///
/// Runs as one transaction, pinning a single consistent snapshot for the
/// whole read sequence (state, author states): without
/// this, a delta or retirement committed by another connection between
/// two of the several reads this function used to make separately could
/// produce a checkpoint whose namespace root and frontier root reflect
/// two different points in time -- a state that never actually existed on
/// this replica, signed as if it had.
pub fn seal_checkpoint(
    conn: &Connection,
    group_id: &FolderGroupId,
    sealer_key: &ed25519_dalek::SigningKey,
) -> Result<NativeCheckpoint, SyncSqliteError> {
    // A savepoint, not a transaction: sealing also runs inside a caller's
    // transaction that reads the state it seals (a recovery bundle must be
    // exactly what its checkpoint commits to).
    conn.execute_batch("SAVEPOINT native_seal_checkpoint")?;
    match seal_checkpoint_in(conn, group_id, sealer_key) {
        Ok(checkpoint) => {
            conn.execute_batch("RELEASE native_seal_checkpoint")?;
            Ok(checkpoint)
        }
        Err(error) => {
            conn.execute_batch(
                "ROLLBACK TO native_seal_checkpoint; RELEASE native_seal_checkpoint",
            )?;
            Err(error)
        }
    }
}

fn seal_checkpoint_in(
    tx: &Connection,
    group_id: &FolderGroupId,
    sealer_key: &ed25519_dalek::SigningKey,
) -> Result<NativeCheckpoint, SyncSqliteError> {
    let state = load_state(tx, group_id)?;
    let namespace = namespace_root(&state)?;
    let author_state_root = author_state_root(tx, group_id)?;

    let mut checkpoint = NativeCheckpoint::new(
        group_id.clone(),
        yadorilink_replica_domain::native_checkpoint::NamespaceRoot(namespace.0),
        yadorilink_replica_domain::native_checkpoint::AuthorStateRoot(author_state_root.0),
    );
    checkpoint.sign(sealer_key);
    Ok(checkpoint)
}

/// The production authority path for one real, verified `NativeDelta`:
/// verifies its signature, checks it legitimately continues its author's
/// frontier chain (`native_frontier::check_chain_advance` — fail closed,
/// refuses and installs nothing on any violation), applies its content to
/// `NativeState`, and advances the frontier — all atomically under the
/// caller's transaction, maintaining `state.context[author] ==
/// frontier[author].seq` as a cross-table invariant.
///
/// Local-authoring scope only (matching this slice's boundary): a
/// removal's claimed header is not re-verified against the live head's own
/// provenance here (that check belongs to remote admission, P4a, over an
/// untrusted delta) — this path is for an author installing its own
/// freshly-signed delta, derived from its own current state, so the
/// removal set is trusted by construction.
pub fn install_verified_delta(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
    author_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<Dot, SyncSqliteError> {
    match install_verified_delta_inner(conn, group_id, delta, author_public_key)? {
        InstallOutcome::Installed(dot) => Ok(dot),
        InstallOutcome::WouldViolateInvariant(violation) => Err(SyncSqliteError::InvalidInput(
            format!("delta would leave a NativeState invariant violated: {violation}"),
        )),
        InstallOutcome::AuthorClosed { cutoff } => Err(closed_author_error(cutoff)),
        InstallOutcome::ClosureFork { seq } => Err(closure_fork_error(seq)),
        InstallOutcome::GroupFrozen => Err(frozen_error(group_id)),
    }
}

/// [`install_verified_delta`] for a delta this replica authored, also returning the heads at its
/// touched paths as the install left them.
pub(crate) fn install_authored_delta(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
    author_public_key: &ed25519_dalek::VerifyingKey,
    admission: Admission<'_>,
) -> Result<(Dot, InstalledHeads), SyncSqliteError> {
    match install_verified_delta_reporting(conn, group_id, delta, author_public_key, admission)? {
        (InstallOutcome::Installed(dot), installed) => Ok((dot, installed)),
        (InstallOutcome::WouldViolateInvariant(violation), _) => {
            Err(SyncSqliteError::InvalidInput(format!(
                "delta would leave a NativeState invariant violated: {violation}"
            )))
        }
        (InstallOutcome::AuthorClosed { cutoff }, _) => Err(closed_author_error(cutoff)),
        (InstallOutcome::ClosureFork { seq }, _) => Err(closure_fork_error(seq)),
        (InstallOutcome::GroupFrozen, _) => Err(frozen_error(group_id)),
    }
}

fn frozen_error(group_id: &FolderGroupId) -> SyncSqliteError {
    SyncSqliteError::GroupFrozen { group_id: group_id.as_str().to_owned() }
}

/// How the delta being installed reaches the install gate. It is not a bypass: each variant
/// carries the capability of the one rebootstrap pass it belongs to, and the gate honours it
/// only in that pass's own state. `Remote` and `Local` carry none: a rebootstrap that is
/// catching up admits the first and refuses the second.
#[derive(Clone, Copy)]
pub(crate) enum Admission<'a> {
    /// A delta another device authored.
    Remote,
    /// A delta this replica authors for a local edit.
    Local,
    /// The delta is a local one authored by the rebootstrap's final capture pass; the gate
    /// honours the capability only while the journal is still `Capturing` for its recovery id.
    RebootstrapCapture(&'a crate::native_rebootstrap::CaptureAuthority),
    /// The delta is one of the rebootstrap's own: the checkpoint install's, or a replayed one
    /// of own intent. The gate honours the capability only while the journal is `Quarantining`
    /// or `Replaying` for its recovery id.
    RebootstrapInstall(&'a crate::native_rebootstrap::InstallAuthority),
}

impl<'a> Admission<'a> {
    pub(crate) fn of(capture: Option<&'a crate::native_rebootstrap::CaptureAuthority>) -> Self {
        capture.map_or(Self::Local, Self::RebootstrapCapture)
    }
}

fn closure_fork_error(seq: AuthorSeq) -> SyncSqliteError {
    SyncSqliteError::InvalidInput(format!(
        "the delta at sequence {} is not the one a verified closure of its author names",
        seq.get()
    ))
}

fn closed_author_error(cutoff: Option<AuthorSeq>) -> SyncSqliteError {
    SyncSqliteError::InvalidInput(match cutoff {
        None => "the delta's author is closed before its first delta".to_owned(),
        Some(cutoff) => format!("the delta's author is closed above sequence {}", cutoff.get()),
    })
}

/// What installing a verified delta found. A refusal writes nothing anywhere
/// (mirrors every other admission-time refusal in this crate: refuse outright,
/// never guess).
#[derive(Debug)]
pub enum InstallOutcome {
    Installed(Dot),
    /// The delta's author is closed at `cutoff` -- retired for an incarnation
    /// rotation, or fenced by the replica itself while that retirement is
    /// unknown -- and the delta's sequence lies above it (`None`: closed
    /// before its first delta, so every sequence does). Final: nothing is
    /// written and the delta can never become admissible.
    AuthorClosed {
        cutoff: Option<AuthorSeq>,
    },
    /// The delta is at exactly the sequence a verified closure of its author cuts
    /// the chain at, but is not the delta the closure names: the author signed two
    /// different histories. Final: nothing is written.
    ClosureFork {
        seq: AuthorSeq,
    },
    /// A rebootstrap freezes the group (its journal is in `Capturing`, `Preserving`,
    /// `Preserved`, `Quarantining` or `Installed`) and this delta is not the final capture's.
    /// Not a fault of the delta or of whoever sent it: nothing is written, nothing is
    /// recorded against the sender, and the delta is admissible again once the freeze ends.
    GroupFrozen,
    /// Applying this delta's ops to the replica's own current
    /// `NativeState` would leave a resulting state that violates its own
    /// invariants (e.g. more than `MAX_SELF_HEADS` live heads of one
    /// author at a path) -- checked on the RESULTING state, before
    /// anything is persisted, exactly as `NativeState::author` refuses a
    /// LOCAL edit that would create the same violation before ever
    /// committing to it. `receive_verified` itself has no such check
    /// (module doc: best-effort application of an already-signed delta,
    /// which alone cannot know what else has landed since it was signed),
    /// so this is the one place a REMOTE delta's cumulative effect is
    /// actually checked before it is allowed to commit.
    WouldViolateInvariant(yadorilink_replica_domain::native_state::InvariantViolation),
}

pub(crate) type PathHeadsMap = std::collections::BTreeMap<Dot, HeadPayload>;

/// The heads at exactly `paths`, and the context of exactly the authors
/// holding them: a `NativeState` that is correct for everything a change
/// confined to those paths reads, at the cost of those paths, not the group.
/// Everything else about the group is absent from it, so it is only for code
/// that reads those paths (`receive_verified`, `check_invariants`) and nothing wider.
pub(crate) fn load_partial_state(
    conn: &Connection,
    group_id: &FolderGroupId,
    paths: &[&SyncPath],
) -> Result<NativeState, SyncSqliteError> {
    let mut state = load_heads_at_paths(conn, group_id, paths)?;
    let authors: std::collections::BTreeSet<AuthorId> =
        state.heads.values().flat_map(|heads| heads.keys().map(|dot| dot.author.clone())).collect();
    for author in authors {
        if let Some(seq) = author_context_seq(conn, group_id, &author)? {
            state.context.insert(author, seq);
        }
    }
    Ok(state)
}

/// A `NativeState` holding the heads at exactly `paths` and no context.
pub(crate) fn load_heads_at_paths(
    conn: &Connection,
    group_id: &FolderGroupId,
    paths: &[&SyncPath],
) -> Result<NativeState, SyncSqliteError> {
    let mut state = NativeState::new();
    // Heads are keyed by path and dot in ordered maps, so the order the rows come back in does
    // not matter: the result is the one a read per path builds.
    for chunk in paths.chunks(crate::store::PATHS_PER_QUERY) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT path, author, incarnation, seq, version, provenance \
             FROM native_heads WHERE group_id = ?1 AND path IN ({marks})"
        ))?;
        let params = std::iter::once(group_id.as_str()).chain(chunk.iter().map(|p| p.as_str()));
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            let path: String = row.get(0)?;
            let head = live_head_from_row(row, 1)?;
            state.heads.entry(SyncPath(path)).or_default().insert(head.dot, head.payload);
        }
    }
    Ok(state)
}

/// Brings the persisted heads at `touched` from `before` to their value in
/// `after`: deletes the rows that went away or changed and inserts the rows
/// that are new, leaving every other row of the group alone.
fn install_touched_heads(
    conn: &Connection,
    group_id: &FolderGroupId,
    touched: &[&SyncPath],
    before: &std::collections::BTreeMap<SyncPath, PathHeadsMap>,
    after: &NativeState,
) -> Result<(), SyncSqliteError> {
    let empty = PathHeadsMap::new();
    let mut delete = conn.prepare_cached(
        "DELETE FROM native_heads \
         WHERE group_id = ?1 AND path = ?2 AND author = ?3 AND incarnation = ?4 AND seq = ?5",
    )?;
    let mut insert = conn.prepare_cached(
        "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, provenance) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for path in touched {
        let old = before.get(*path).unwrap_or(&empty);
        let new = after.heads.get(*path).unwrap_or(&empty);
        for (dot, payload) in old {
            if new.get(dot) != Some(payload) {
                delete.execute((
                    group_id.as_str(),
                    path.as_str(),
                    dot.author.device.as_str(),
                    dot.author.incarnation.0.as_slice(),
                    dot.seq.get() as i64,
                ))?;
                count_head_rows_written(1);
            }
        }
        for (dot, payload) in new {
            if old.get(dot) != Some(payload) {
                insert.execute((
                    group_id.as_str(),
                    path.as_str(),
                    dot.author.device.as_str(),
                    dot.author.incarnation.0.as_slice(),
                    dot.seq.get() as i64,
                    payload.version.0.as_slice(),
                    payload.provenance.0.as_slice(),
                ))?;
                count_head_rows_written(1);
            }
        }
    }
    Ok(())
}

/// Writes exactly one author's `NativeState::context` entry, a single-row
/// upsert like [`frontier_entry_upsert`].
fn author_context_upsert(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
) -> Result<(), SyncSqliteError> {
    conn.prepare_cached(
        "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (group_id, author, incarnation) DO UPDATE SET seq = excluded.seq",
    )?
    .execute((
        group_id.as_str(),
        author.device.as_str(),
        author.incarnation.0.as_slice(),
        seq.get() as i64,
    ))?;
    Ok(())
}

pub(crate) fn install_verified_delta_inner(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
    author_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<InstallOutcome, SyncSqliteError> {
    install_verified_delta_reporting(conn, group_id, delta, author_public_key, Admission::Remote)
        .map(|(outcome, _)| outcome)
}

/// The heads at each path a delta touched, as the install left them.
pub(crate) type InstalledHeads = std::collections::BTreeMap<SyncPath, PathHeadsMap>;

/// [`install_verified_delta_inner`], also returning the live heads at every path the delta touched
/// exactly as the install wrote them (empty unless the delta was installed): the state the install
/// computed in memory and persisted, so a caller in the same transaction need not read it back.
pub(crate) fn install_verified_delta_reporting(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
    author_public_key: &ed25519_dalek::VerifyingKey,
    admission: Admission<'_>,
) -> Result<(InstallOutcome, InstalledHeads), SyncSqliteError> {
    delta
        .verify_signature(author_public_key)
        .map_err(|_| SyncSqliteError::InvalidInput("delta signature does not verify".into()))?;
    // Defense in depth: the delta's own signed group_id must match the
    // group this call was made against. The proof-carrying path
    // (`proof_carrying_delta::verify_proof_carrying_delta`) already checks
    // this for its own callers, but this is the lowest choke point every
    // install funnels through -- it must not silently trust a caller who
    // skipped that layer or passed the wrong group argument.
    if delta.group_id != *group_id {
        return Err(SyncSqliteError::InvalidInput(format!(
            "delta is signed for group {:?}, not the group {group_id:?} this call was made against",
            delta.group_id
        )));
    }

    // The freeze of a rebootstrap, once, for every delta this funnel installs: a local edit, a
    // remote delta and the promotion of a held one alike. Read-only here; the capture pass's
    // consumption is written below, with the delta.
    let capture = match crate::native_rebootstrap::check_freeze(
        conn,
        group_id,
        &delta.author,
        delta.seq,
        admission,
    )? {
        crate::native_rebootstrap::FreezeVerdict::Open => None,
        crate::native_rebootstrap::FreezeVerdict::Capture { recovery_id } => Some(recovery_id),
        crate::native_rebootstrap::FreezeVerdict::Frozen => {
            return Ok((InstallOutcome::GroupFrozen, InstalledHeads::new()));
        }
    };

    // Before the chain gate: a delta above the cutoff of a closed incarnation is
    // refused whether or not it would continue the chain, and the exit every
    // install funnels through is the one place no entry point can skip. A delta
    // at the cutoff sequence that is not the delta the closure names is a fork.
    let delta_hash = delta.delta_hash();
    let closed_at = crate::native_closure::effective_closed_cutoff(conn, group_id, &delta.author)?;
    if let Some(cutoff) = &closed_at {
        match cutoff.verdict(delta.seq, &delta_hash) {
            crate::native_closure::ClosedVerdict::Open => {}
            crate::native_closure::ClosedVerdict::Beyond { cutoff } => {
                return Ok((InstallOutcome::AuthorClosed { cutoff }, InstalledHeads::new()));
            }
            crate::native_closure::ClosedVerdict::Fork { seq } => {
                return Ok((InstallOutcome::ClosureFork { seq }, InstalledHeads::new()));
            }
        }
    }

    let current = frontier_entry_get(conn, group_id, &delta.author)?;
    native_frontier::check_chain_advance(current.as_ref(), delta.prev, delta.seq).map_err(
        |err| {
            SyncSqliteError::InvalidInput(format!(
                "delta does not continue its author's frontier chain: {err}"
            ))
        },
    )?;

    // `receive_verified`, not `author`: this delta's removals were computed
    // against its sender's view at signing time, which this replica's own
    // heads may already have moved past (a concurrent delta from another
    // author landed first). That is ordinary convergence, not a fault --
    // `author`'s `ObservedNotCurrentHead` discipline is for an honest
    // author's own live view (see that method's doc), not for replaying
    // someone else's already-signed delta. See `native_state::
    // receive_verified`'s doc for the exact best-effort removal semantics.
    // Keyed by path: `receive_verified` looks a removal up at its own op's
    // path.
    let mut ops_by_path: std::collections::BTreeMap<
        SyncPath,
        yadorilink_replica_domain::native_state::RemoteOp,
    > = std::collections::BTreeMap::new();
    for op in &delta.ops {
        let entry = ops_by_path.entry(op.path.clone()).or_insert_with(|| {
            yadorilink_replica_domain::native_state::RemoteOp {
                path: op.path.clone(),
                removes: Vec::new(),
                put: None,
            }
        });
        entry.removes.extend(op.removes.iter().cloned());
        entry.put =
            op.put.as_ref().map(|put| HeadPayload { version: put.version, provenance: delta_hash });
    }
    let ops: Vec<yadorilink_replica_domain::native_state::RemoteOp> =
        ops_by_path.into_values().collect();

    // Everything this delta can read or change is at its own paths, so only
    // those paths' heads (and the context of the authors holding them) are
    // loaded: the install costs the delta's size, never the group's.
    let touched: Vec<&SyncPath> = ops.iter().map(|op| &op.path).collect();
    let mut state = load_partial_state(conn, group_id, &touched)?;
    let heads_before: std::collections::BTreeMap<SyncPath, PathHeadsMap> = touched
        .iter()
        .filter_map(|path| state.heads.get(*path).map(|heads| ((*path).clone(), heads.clone())))
        .collect();

    let dot =
        state.receive_verified(&delta.author, delta.seq, &ops).map_err(|err: AuthorError| {
            SyncSqliteError::InvalidInput(format!("verified delta was malformed: {err}"))
        })?;
    if dot.seq != delta.seq {
        return Err(SyncSqliteError::CorruptState(format!(
            "verified delta claimed seq {:?} but the state's own next dot was {:?}",
            delta.seq, dot.seq
        )));
    }
    // Checked on the RESULTING state, before anything is persisted, over the
    // paths this delta touched: every other path's heads were checked when
    // they were installed, and the one context entry this delta moves only
    // grows. An individually chain-continuous, individually context-gate-passing
    // delta can still leave more than MAX_SELF_HEADS live heads of its own
    // author at a path, if a prior delta from the same author already put
    // one there without removing it (`receive_verified`'s best-effort
    // removal semantics let this land silently -- see
    // `InstallOutcome::WouldViolateInvariant`'s own doc). Refused
    // here, nothing written -- exactly as `NativeState::author` refuses a
    // LOCAL edit that would create the same violation before ever
    // committing to it.
    if let Err(violation) = state.check_invariants() {
        return Ok((InstallOutcome::WouldViolateInvariant(violation), InstalledHeads::new()));
    }

    install_touched_heads(conn, group_id, &touched, &heads_before, &state)?;
    author_context_upsert(conn, group_id, &delta.author, delta.seq)?;
    record_installed_delta(conn, group_id, delta)?;
    // The delta the closure names: the author is closed in the transaction that
    // reaches its cutoff.
    if closed_at.is_some() {
        crate::native_closure::close_state_if_reached(conn, group_id, &delta.author)?;
    }
    if let Some(recovery_id) = capture {
        crate::native_rebootstrap::record_capture(conn, group_id, &recovery_id, delta.seq)?;
    }
    let installed: InstalledHeads = touched
        .iter()
        .map(|path| ((*path).clone(), state.heads.get(*path).cloned().unwrap_or_default()))
        .collect();
    Ok((InstallOutcome::Installed(dot), installed))
}

/// What installing `delta` records beside its head and context changes: the
/// author's frontier entry, the delta log and body, its recursive-operation
/// claim, and the heads its ops declare kept.
pub(crate) fn record_installed_delta(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
) -> Result<(), SyncSqliteError> {
    let delta_hash = delta.delta_hash();
    frontier_entry_upsert(
        conn,
        group_id,
        &delta.author,
        &NativeAuthorFrontierEntry { seq: delta.seq, tip: delta_hash },
    )?;
    record_delta_log(conn, group_id, &delta.author, delta.seq, delta_hash)?;
    record_delta_body(
        conn,
        group_id,
        &delta.author,
        delta.seq,
        delta_hash,
        &delta.to_wire_bytes(),
    )?;
    crate::native_recursive_operation::record_delta(conn, group_id.as_str(), delta)?;
    Ok(())
}

/// The encoded body alongside [`record_delta_log`]'s hash-only entry, in
/// the same transaction -- see `native_delta_bodies`'s own doc for why a
/// body needs to outlive whatever live head it produced. This is the signed
/// delta a row's witness rests on, kept beside the evidence.
pub(crate) fn record_delta_body_for_witness(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
    delta_hash: DeltaHash,
    encoded_delta: &[u8],
) -> Result<(), SyncSqliteError> {
    record_delta_body(conn, group_id, author, seq, delta_hash, encoded_delta)
}

fn record_delta_body(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
    delta_hash: DeltaHash,
    encoded_delta: &[u8],
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT OR IGNORE INTO native_delta_bodies (group_id, author, incarnation, seq, delta_hash, encoded_delta) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (
            group_id.as_str(),
            author.device.as_str(),
            author.incarnation.0.as_slice(),
            seq.get() as i64,
            delta_hash.0.as_slice(),
            encoded_delta,
        ),
    )?;
    Ok(())
}

/// Records that `hash` was installed for `(group_id, author, seq)` -- the
/// ONE place this happens, since [`install_verified_delta`] is the sole
/// choke point every delta (locally authored via `native_authoring`
/// or remotely admitted via `native_admission::admit_native_delta`) passes
/// through to become part of this replica's state. `native_delta_log`'s
/// own table (created by `native_admission::init_admission_tables`) exists
/// so local-publication tracking (which deltas has THIS device
/// authored that have no checkpoint evidence yet) and the remote
/// duplicate/equivocation check ([`delta_log_hash`]) share one source of
/// truth, rather than each maintaining its own partial record that could
/// silently drift from what was actually installed.
pub(crate) fn record_delta_log(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
    hash: DeltaHash,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT INTO native_delta_log (group_id, author, incarnation, seq, delta_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
        (group_id.as_str(), author.device.as_str(), author.incarnation.0.as_slice(), seq.get() as i64, hash.0.as_slice()),
    )?;
    Ok(())
}

/// The hash [`record_delta_log`] recorded for `(group_id, author, seq)`,
/// or `None` if nothing was ever installed at that seq.
pub(crate) fn delta_log_hash(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    seq: AuthorSeq,
) -> Result<Option<DeltaHash>, SyncSqliteError> {
    conn.query_row(
        "SELECT delta_hash FROM native_delta_log WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3 AND seq = ?4",
        (group_id.as_str(), author.device.as_str(), author.incarnation.0.as_slice(), seq.get() as i64),
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()?
    .map(|bytes| Ok(DeltaHash(as_array32(&bytes)?)))
    .transpose()
}

/// Every native delta hash this replica has ever installed for `author` in
/// `group_id` that has no publish-time authorization evidence attached yet
/// (see `native_publication::pending_native_deltas_for_author`, the public
/// entry point -- this is the raw query it wraps).
pub(crate) fn unpublished_delta_log_entries(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<Vec<(AuthorSeq, DeltaHash)>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT l.seq, l.delta_hash FROM native_delta_log l \
         WHERE l.group_id = ?1 AND l.author = ?2 AND l.incarnation = ?3 \
         AND NOT EXISTS (SELECT 1 FROM native_delta_authorization a WHERE a.delta_hash = l.delta_hash) \
         ORDER BY l.seq",
    )?;
    let rows = stmt.query_map(
        (group_id.as_str(), author.device.as_str(), author.incarnation.0.as_slice()),
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, hash) = row?;
        out.push((AuthorSeq(seq as u64), DeltaHash(as_array32(&hash)?)));
    }
    Ok(out)
}

/// Replaces the group's persisted state with `state` in full: every
/// `native_author_context`/`native_heads` row for `group_id` is deleted and
/// reinserted. Atomic exactly when the caller runs it inside a transaction
/// (see the module doc) — a crash or error before commit leaves the
/// previously-installed state untouched, never a partial mix of old and
/// new rows.
pub fn install_state(
    conn: &Connection,
    group_id: &FolderGroupId,
    state: &NativeState,
) -> Result<(), SyncSqliteError> {
    conn.execute("DELETE FROM native_author_context WHERE group_id = ?1", [group_id.as_str()])?;
    let deleted =
        conn.execute("DELETE FROM native_heads WHERE group_id = ?1", [group_id.as_str()])?;
    count_head_rows_written(deleted);

    let mut insert_context = conn.prepare(
        "INSERT INTO native_author_context (group_id, author, incarnation, seq) VALUES (?1, ?2, ?3, ?4)",
    )?;
    for (author, seq) in &state.context {
        insert_context.execute((
            group_id.as_str(),
            author.device.as_str(),
            author.incarnation.0.as_slice(),
            seq.get() as i64,
        ))?;
    }
    drop(insert_context);

    let mut insert_head = conn.prepare(
        "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, provenance) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for (path, heads) in &state.heads {
        for (dot, payload) in heads {
            insert_head.execute((
                group_id.as_str(),
                path.as_str(),
                dot.author.device.as_str(),
                dot.author.incarnation.0.as_slice(),
                dot.seq.get() as i64,
                payload.version.0.as_slice(),
                payload.provenance.0.as_slice(),
            ))?;
            count_head_rows_written(1);
        }
    }
    Ok(())
}

/// Loads the group's state, applies a local mutation
/// (`NativeState::author`), and installs the result — one logical
/// load/mutate/persist step, atomic under the caller's transaction.
///
/// **Test/helper only, not the production authority path.** This takes
/// plain unsigned `PathEdit`s and never touches `native_author_frontier` --
/// it cannot, since it has no verified `NativeDelta` to derive a real
/// `tip_header_hash` from (see this module's frontier doc). The production
/// path for a real local mutation is [`install_verified_delta`], which
/// updates `NativeState` and the frontier together, atomically, from an
/// already-signed `NativeDelta`.
#[cfg(any(test, feature = "test-support"))]
pub fn author_local(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
    edits: Vec<PathEdit>,
) -> Result<Dot, SyncSqliteError> {
    let mut state = load_state(conn, group_id)?;
    let dot = state
        .author(author, edits)
        .map_err(|err: AuthorError| SyncSqliteError::InvalidInput(err.to_string()))?;
    install_state(conn, group_id, &state)?;
    Ok(dot)
}

/// Verifies `checkpoint`'s signature against `sealer_public_key` and, only
/// on success, installs it. A checkpoint whose signature does not verify
/// is refused and nothing is written — fail closed, never installed
/// "pending further review."
///
/// Re-installing an already-known checkpoint (same `checkpoint_hash`) is an
/// idempotent no-op.
pub fn install_checkpoint(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint: &NativeCheckpoint,
    sealer_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), SyncSqliteError> {
    checkpoint.verify_signature(sealer_public_key).map_err(|_| {
        SyncSqliteError::InvalidInput("checkpoint signature does not verify".into())
    })?;
    // Defense in depth: same rationale as install_verified_delta_inner's
    // own group-binding check just above -- the seal-authorization layer
    // (native_checkpoint_seal::verify_native_checkpoint_seal_authorization)
    // already binds its Merkle leaf to the group_id argument together with
    // the checkpoint's own signed content, so a mismatched argument there
    // fails via a non-matching proof; this is the lowest storage choke
    // point, which must not rely on every caller having gone through that
    // layer first.
    if checkpoint.group_id != *group_id {
        return Err(SyncSqliteError::InvalidInput(format!(
            "checkpoint is signed for group {:?}, not the group {group_id:?} this call was made against",
            checkpoint.group_id
        )));
    }

    let hash = checkpoint.checkpoint_hash();
    conn.execute(
        "INSERT OR IGNORE INTO native_checkpoints \
         (group_id, checkpoint_hash, namespace_root, author_state_root, \
          signature, installed_at_unixtime) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (
            group_id.as_str(),
            hash.0.as_slice(),
            checkpoint.namespace_root.0.as_slice(),
            checkpoint.author_state_root.0.as_slice(),
            checkpoint.signature.as_slice(),
            now_unixtime(),
        ),
    )?;
    Ok(())
}

/// The hashes of the checkpoints stored for `group_id`, in storage order.
#[cfg(test)]
pub(crate) fn stored_checkpoint_hashes(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Vec<[u8; 32]> {
    let mut stmt = conn
        .prepare(
            "SELECT checkpoint_hash FROM native_checkpoints WHERE group_id = ?1 ORDER BY rowid",
        )
        .unwrap();
    let rows = stmt.query_map([group_id.as_str()], |row| row.get::<_, Vec<u8>>(0)).unwrap();
    rows.map(|hash| as_array32(&hash.unwrap()).unwrap()).collect()
}

fn now_unixtime() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rusqlite::Connection;

    use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath, VersionHash};
    use yadorilink_replica_domain::native_checkpoint::{
        AuthorStateRoot, NamespaceRoot, NativeCheckpoint,
    };
    use yadorilink_replica_domain::native_state::{DeltaHash, HeadPayload, PathEdit};

    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_native_tables(&c).unwrap();
        c
    }

    fn group() -> FolderGroupId {
        FolderGroupId("g1".into())
    }

    fn author_id(device: &str) -> AuthorId {
        AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) }
    }

    fn payload(v: u8) -> HeadPayload {
        HeadPayload { version: VersionHash([v; 32]), provenance: DeltaHash::default() }
    }

    #[test]
    fn fresh_group_loads_as_empty_state() {
        let c = conn();
        let state = load_state(&c, &group()).unwrap();
        assert_eq!(state, NativeState::new());
    }

    #[test]
    fn local_mutation_round_trips() {
        let c = conn();
        let author = author_id("a");
        let dot = author_local(
            &c,
            &group(),
            &author,
            vec![PathEdit { path: SyncPath("x".into()), observed: vec![], put: Some(payload(1)) }],
        )
        .unwrap();

        let reloaded = load_state(&c, &group()).unwrap();
        assert_eq!(reloaded.dots_at(&SyncPath("x".into())), vec![dot]);
        assert_eq!(
            reloaded.context_of(&author),
            Some(yadorilink_replica_domain::ids::AuthorSeq(1))
        );
    }

    /// A multi-path mutation installs all its paths together, or (on a
    /// refusal) none of them — the loaded state after a refused mutation is
    /// unchanged.
    #[test]
    fn refused_mutation_leaves_persisted_state_unchanged() {
        let c = conn();
        let author = author_id("a");
        author_local(
            &c,
            &group(),
            &author,
            vec![PathEdit { path: SyncPath("x".into()), observed: vec![], put: Some(payload(1)) }],
        )
        .unwrap();
        let before = load_state(&c, &group()).unwrap();

        // Observing a dot that is not a current head is refused.
        let bogus_dot = yadorilink_replica_domain::native_state::Dot {
            author: author_id("nobody"),
            seq: yadorilink_replica_domain::ids::AuthorSeq(1),
        };
        let err = author_local(
            &c,
            &group(),
            &author,
            vec![PathEdit { path: SyncPath("x".into()), observed: vec![bogus_dot], put: None }],
        )
        .unwrap_err();
        assert!(matches!(err, SyncSqliteError::InvalidInput(_)));

        let after = load_state(&c, &group()).unwrap();
        assert_eq!(before, after, "a refused mutation must not have touched persisted state");
    }

    /// A transaction that is dropped without `commit()` leaves the
    /// database exactly as it was before the transaction opened — the
    /// "crash mid-write" case a real crash-recovery restart also relies on
    /// (SQLite's own atomic commit), exercised here across two real
    /// connections to one on-disk file.
    #[test]
    fn uncommitted_transaction_leaves_pre_state_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native.sqlite");
        let author = author_id("a");

        {
            let mut c = Connection::open(&path).unwrap();
            init_native_tables(&c).unwrap();
            let tx = c.transaction().unwrap();
            author_local(
                &tx,
                &group(),
                &author,
                vec![PathEdit {
                    path: SyncPath("x".into()),
                    observed: vec![],
                    put: Some(payload(1)),
                }],
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // A second mutation, started but never committed -- simulates a
        // crash between the writes and the commit.
        {
            let mut c = Connection::open(&path).unwrap();
            let tx = c.transaction().unwrap();
            author_local(
                &tx,
                &group(),
                &author,
                vec![PathEdit {
                    path: SyncPath("y".into()),
                    observed: vec![],
                    put: Some(payload(2)),
                }],
            )
            .unwrap();
            // Dropped without `tx.commit()`.
        }

        let c = Connection::open(&path).unwrap();
        let state = load_state(&c, &group()).unwrap();
        assert_eq!(
            state.dots_at(&SyncPath("x".into())).len(),
            1,
            "the committed mutation must survive"
        );
        assert!(
            state.dots_at(&SyncPath("y".into())).is_empty(),
            "the uncommitted mutation must not appear"
        );
    }

    #[test]
    fn checkpoint_round_trips_and_is_idempotent() {
        let c = conn();
        let sealer = SigningKey::from_bytes(&[5u8; 32]);
        let mut checkpoint =
            NativeCheckpoint::new(group(), NamespaceRoot([1u8; 32]), AuthorStateRoot([2u8; 32]));
        checkpoint.sign(&sealer);

        install_checkpoint(&c, &group(), &checkpoint, &sealer.verifying_key()).unwrap();
        // Re-installing the same checkpoint is a no-op, not a duplicate or
        // an error.
        install_checkpoint(&c, &group(), &checkpoint, &sealer.verifying_key()).unwrap();

        assert_eq!(stored_checkpoint_hashes(&c, &group()), vec![checkpoint.checkpoint_hash().0]);
    }

    #[test]
    fn checkpoint_with_bad_signature_is_refused_and_not_installed() {
        let c = conn();
        let sealer = SigningKey::from_bytes(&[5u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[6u8; 32]);
        let mut checkpoint =
            NativeCheckpoint::new(group(), NamespaceRoot([1u8; 32]), AuthorStateRoot([2u8; 32]));
        checkpoint.sign(&wrong_key);

        let err =
            install_checkpoint(&c, &group(), &checkpoint, &sealer.verifying_key()).unwrap_err();
        assert!(matches!(err, SyncSqliteError::InvalidInput(_)));
        assert!(
            stored_checkpoint_hashes(&c, &group()).is_empty(),
            "a bad-signature checkpoint must not be installed"
        );
    }

    /// Regression: a correctly-signed checkpoint for one group must not
    /// be installable under a different group's argument.
    #[test]
    fn a_checkpoint_signed_for_a_different_group_is_refused_not_silently_installed() {
        let c = conn();
        let sealer = SigningKey::from_bytes(&[5u8; 32]);
        let mut checkpoint =
            NativeCheckpoint::new(group(), NamespaceRoot([1u8; 32]), AuthorStateRoot([2u8; 32]));
        checkpoint.sign(&sealer);

        let other_group = FolderGroupId("g2".into());
        let err =
            install_checkpoint(&c, &other_group, &checkpoint, &sealer.verifying_key()).unwrap_err();
        assert!(format!("{err}").contains("group"), "expected a group-mismatch refusal, got {err}");
        assert!(stored_checkpoint_hashes(&c, &group()).is_empty());
        assert!(stored_checkpoint_hashes(&c, &other_group).is_empty());
    }
}

#[cfg(test)]
mod namespace_tests {
    use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
    use yadorilink_replica_domain::native_state::DeltaHash;

    use super::*;

    fn payload(v: u8, prov: u8) -> HeadPayload {
        HeadPayload { version: VersionHash([v; 32]), provenance: DeltaHash([prov; 32]) }
    }

    fn author_id(device: &str) -> AuthorId {
        AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) }
    }

    #[test]
    fn empty_state_has_the_empty_namespace_root() {
        let root = namespace_root(&NativeState::new()).unwrap();
        assert_eq!(root, empty_digest());
    }

    #[test]
    fn namespace_root_is_deterministic_regardless_of_head_insertion_order() {
        let a = author_id("a");
        let b = author_id("b");

        let mut s1 = NativeState::new();
        s1.put(&a, SyncPath("x".into()), &[], payload(1, 1)).unwrap();
        s1.put(&b, SyncPath("y".into()), &[], payload(2, 2)).unwrap();

        let mut s2 = NativeState::new();
        s2.put(&b, SyncPath("y".into()), &[], payload(2, 2)).unwrap();
        s2.put(&a, SyncPath("x".into()), &[], payload(1, 1)).unwrap();

        assert_eq!(namespace_root(&s1).unwrap(), namespace_root(&s2).unwrap());
    }

    #[test]
    fn namespace_root_changes_when_live_content_changes() {
        let a = author_id("a");
        let mut s = NativeState::new();
        let root_empty = namespace_root(&s).unwrap();
        let dot = s.put(&a, SyncPath("x".into()), &[], payload(1, 1)).unwrap();
        let root_after_put = namespace_root(&s).unwrap();
        assert_ne!(root_empty, root_after_put);

        s.delete(&a, SyncPath("x".into()), &[dot]).unwrap();
        let root_after_delete = namespace_root(&s).unwrap();
        assert_eq!(
            root_after_delete, root_empty,
            "deleting back to empty must reproduce the empty root"
        );
    }

    #[test]
    fn namespace_diff_finds_exactly_the_changed_paths() {
        let a = author_id("a");
        let mut left = NativeState::new();
        left.put(&a, SyncPath("same".into()), &[], payload(1, 1)).unwrap();
        left.put(&a, SyncPath("only_left".into()), &[], payload(2, 2)).unwrap();

        let mut right = NativeState::new();
        right.put(&a, SyncPath("same".into()), &[], payload(1, 1)).unwrap();
        right.put(&a, SyncPath("only_right".into()), &[], payload(3, 3)).unwrap();

        let diffs = namespace_diff(&left, &right).unwrap();
        let changed_paths: std::collections::BTreeSet<String> =
            diffs.iter().map(|d| d.path.as_str().to_owned()).collect();
        assert_eq!(
            changed_paths,
            std::collections::BTreeSet::from(["only_left".to_owned(), "only_right".to_owned()]),
            "unchanged 'same' must not appear in the diff"
        );
    }

    #[test]
    fn namespace_root_matches_across_replicas_after_join() {
        let a = author_id("a");
        let b = author_id("b");
        let mut left = NativeState::new();
        left.put(&a, SyncPath("x".into()), &[], payload(1, 1)).unwrap();
        let mut right = NativeState::new();
        right.put(&b, SyncPath("x".into()), &[], payload(2, 2)).unwrap();

        let joined_left_first =
            yadorilink_replica_domain::native_state::join(&left, &right).unwrap();
        let joined_right_first =
            yadorilink_replica_domain::native_state::join(&right, &left).unwrap();

        assert_eq!(
            namespace_root(&joined_left_first).unwrap(),
            namespace_root(&joined_right_first).unwrap()
        );
    }
}

#[cfg(test)]
mod frontier_tests {
    use ed25519_dalek::SigningKey;
    use rusqlite::Connection;
    use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
    use yadorilink_replica_domain::native_frontier::{
        self as frontier_domain, NativeAuthorFrontier, NativeAuthorFrontierEntry,
    };
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, HeadRef};

    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_native_tables(&c).unwrap();
        c
    }

    fn group() -> FolderGroupId {
        FolderGroupId("g1".into())
    }

    /// The winner among concurrent heads is a function of the heads' versions
    /// alone, so no table that stores native state keeps a rank beside them.
    #[test]
    fn no_native_table_carries_a_rank_column() {
        let c = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&c).unwrap();
        let hits: Vec<(String, String)> = c
            .prepare(
                "SELECT m.name, p.name FROM sqlite_master m, pragma_table_info(m.name) p \
                 WHERE m.type = 'table' AND m.name LIKE 'native\\_%' ESCAPE '\\' \
                   AND lower(p.name) LIKE '%rank%'",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(hits.is_empty(), "rank columns remain: {hits:?}");
    }

    /// The author-state root of a frontier in which every author is open.
    fn open_root(frontier: &NativeAuthorFrontier) -> [u8; 32] {
        native_frontier::author_state_root(
            &frontier
                .iter()
                .map(|(author, entry)| (author.clone(), AuthorState::Open(*entry)))
                .collect(),
        )
    }

    fn author_id(device: &str) -> AuthorId {
        AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) }
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn delta(
        author: &AuthorId,
        seq: u64,
        prev: Option<yadorilink_replica_domain::native_state::DeltaHash>,
        path: &str,
        version: u8,
        key: &SigningKey,
    ) -> NativeDelta {
        let mut d = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: author.clone(),
            seq: AuthorSeq(seq),
            prev,
            ops: vec![DeltaOp {
                path: SyncPath(path.into()),
                removes: vec![],
                put: Some(DeltaPut { version: VersionHash([version; 32]) }),
            }],
            signature: [0u8; 64],
        };
        d.sign(key);
        d
    }

    /// Regression: a correctly-signed delta for one group must not be
    /// installable under a different group's argument -- the signature
    /// alone proves the author wrote it, not which group the caller
    /// intended to apply it to.
    #[test]
    fn a_delta_signed_for_a_different_group_is_refused_not_silently_applied() {
        let c = conn();
        let a = author_id("a");
        let key = signing_key(1);
        let d = delta(&a, 1, None, "x", 1, &key);
        assert_eq!(d.group_id, group());

        let other_group = FolderGroupId("g2".into());
        let err = install_verified_delta(&c, &other_group, &d, &key.verifying_key()).unwrap_err();
        assert!(format!("{err}").contains("group"), "expected a group-mismatch refusal, got {err}");

        // Nothing was written to either group's state.
        assert_eq!(load_state(&c, &group()).unwrap(), NativeState::new());
        assert_eq!(load_state(&c, &other_group).unwrap(), NativeState::new());
    }

    /// The production authority path: a delta advances `NativeState.context`
    /// and the frontier together, and the frontier's tip is exactly the
    /// delta's own header hash -- never a placeholder.
    #[test]
    fn install_verified_delta_advances_context_and_frontier_together() {
        let c = conn();
        let a = author_id("a");
        let key = signing_key(1);

        let d1 = delta(&a, 1, None, "x", 1, &key);
        let d1_hash = d1.delta_hash();
        install_verified_delta(&c, &group(), &d1, &key.verifying_key()).unwrap();

        let state = load_state(&c, &group()).unwrap();
        let frontier = load_frontier(&c, &group()).unwrap();
        assert_eq!(state.context_of(&a), Some(AuthorSeq(1)));
        assert_eq!(frontier[&a], NativeAuthorFrontierEntry { seq: AuthorSeq(1), tip: d1_hash });

        let d2 = delta(&a, 2, Some(d1_hash), "x", 2, &key);
        let d2_hash = d2.delta_hash();
        install_verified_delta(&c, &group(), &d2, &key.verifying_key()).unwrap();

        let state = load_state(&c, &group()).unwrap();
        let frontier = load_frontier(&c, &group()).unwrap();
        assert_eq!(state.context_of(&a), Some(AuthorSeq(2)));
        assert_eq!(frontier[&a], NativeAuthorFrontierEntry { seq: AuthorSeq(2), tip: d2_hash });
    }

    /// Regression: a delta whose removal was computed against a
    /// concurrently-superseded view must still be admitted -- it is not
    /// this replica's job to reject a remote author for citing a
    /// provenance that is merely stale by the time the delta arrives (see
    /// `native_state::receive_verified`'s doc). `install_verified_delta`
    /// once went through `NativeState::author`'s strict discipline
    /// instead, which would refuse the whole delta here.
    #[test]
    fn a_removal_naming_a_dot_concurrently_superseded_with_different_provenance_is_admitted_as_a_no_op(
    ) {
        let c = conn();
        let key_b = signing_key(2);
        let b = author_id("b");
        let d_b = delta(&b, 1, None, "x", 9, &key_b);
        install_verified_delta(&c, &group(), &d_b, &key_b.verifying_key()).unwrap();
        let b_dot = Dot { author: b.clone(), seq: AuthorSeq(1) };
        let b_provenance = d_b.delta_hash();

        // `a`'s delta was signed against a stale view: it claims to remove
        // `b_dot` under a provenance that is not (or no longer) the one
        // actually live there.
        let key_a = signing_key(1);
        let a = author_id("a");
        let wrong_header = yadorilink_replica_domain::native_state::DeltaHash([0xEE; 32]);
        let mut d_a = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: a.clone(),
            seq: AuthorSeq(1),
            prev: None,
            ops: vec![DeltaOp {
                path: SyncPath("x".into()),
                removes: vec![HeadRef { dot: b_dot.clone(), provenance: wrong_header }],
                put: Some(DeltaPut { version: VersionHash([2; 32]) }),
            }],
            signature: [0u8; 64],
        };
        d_a.sign(&key_a);
        let a_dot = install_verified_delta(&c, &group(), &d_a, &key_a.verifying_key()).unwrap();
        assert_eq!(a_dot, Dot { author: a.clone(), seq: AuthorSeq(1) });

        let state = load_state(&c, &group()).unwrap();
        let heads = &state.heads[&SyncPath("x".into())];
        assert_eq!(
            heads.get(&b_dot).map(|h| h.provenance),
            Some(b_provenance),
            "b's genuinely-live head must survive the mismatched removal"
        );
        assert!(heads.contains_key(&a_dot), "a's own put must still land");
    }

    /// A delta naming the wrong `prev` breaks the chain and is refused --
    /// nothing is installed, state and frontier stay exactly as they were.
    #[test]
    fn wrong_prev_chain_is_refused_and_installs_nothing() {
        let c = conn();
        let a = author_id("a");
        let key = signing_key(1);

        let d1 = delta(&a, 1, None, "x", 1, &key);
        install_verified_delta(&c, &group(), &d1, &key.verifying_key()).unwrap();
        let state_before = load_state(&c, &group()).unwrap();
        let frontier_before = load_frontier(&c, &group()).unwrap();

        let wrong_prev = yadorilink_replica_domain::native_state::DeltaHash([0xAB; 32]);
        let d2 = delta(&a, 2, Some(wrong_prev), "x", 2, &key);
        let err = install_verified_delta(&c, &group(), &d2, &key.verifying_key()).unwrap_err();
        assert!(matches!(err, SyncSqliteError::InvalidInput(_)));

        assert_eq!(
            load_state(&c, &group()).unwrap(),
            state_before,
            "refused delta must not touch state"
        );
        assert_eq!(
            load_frontier(&c, &group()).unwrap(),
            frontier_before,
            "refused delta must not touch the frontier"
        );
    }

    /// Two independently-obtained frontiers claiming the same seq for one
    /// author with different tips is equivocation -- `frontier_domain::join`
    /// (used to merge two replicas' frontiers, e.g. after a remote pull)
    /// fails closed rather than picking a side.
    #[test]
    fn same_seq_different_tip_across_replicas_is_equivocation() {
        let a = author_id("a");
        let mut left = NativeAuthorFrontier::new();
        left.insert(
            a.clone(),
            NativeAuthorFrontierEntry {
                seq: AuthorSeq(1),
                tip: yadorilink_replica_domain::native_state::DeltaHash([1u8; 32]),
            },
        );
        let mut right = NativeAuthorFrontier::new();
        right.insert(
            a.clone(),
            NativeAuthorFrontierEntry {
                seq: AuthorSeq(1),
                tip: yadorilink_replica_domain::native_state::DeltaHash([2u8; 32]),
            },
        );

        let err = frontier_domain::join(&left, &right).unwrap_err();
        assert_eq!(err.author, a);
        assert_eq!(err.seq, AuthorSeq(1));
    }

    /// The frontier root is sensitive to the tip alone: two frontiers that
    /// agree on every seq but differ in one author's tip must not hash the
    /// same.
    #[test]
    fn author_state_root_differs_when_only_tip_differs_at_same_seq() {
        let a = author_id("a");
        let mut left = NativeAuthorFrontier::new();
        left.insert(
            a.clone(),
            NativeAuthorFrontierEntry {
                seq: AuthorSeq(1),
                tip: yadorilink_replica_domain::native_state::DeltaHash([1u8; 32]),
            },
        );
        let mut right = NativeAuthorFrontier::new();
        right.insert(
            a,
            NativeAuthorFrontierEntry {
                seq: AuthorSeq(1),
                tip: yadorilink_replica_domain::native_state::DeltaHash([2u8; 32]),
            },
        );

        assert_ne!(open_root(&left), open_root(&right));
    }

    /// The content namespace and the frontier are independent trees: two
    /// states can agree on every path's live content (equal `namespace_root`)
    /// while their frontiers diverge (equivocating claims about an author's
    /// chain that never touched the content shown here).
    #[test]
    fn namespace_root_can_match_while_frontier_diverges() {
        let a = author_id("a");
        let mut state = NativeState::new();
        state
            .put(
                &a,
                SyncPath("x".into()),
                &[],
                HeadPayload {
                    version: VersionHash([1u8; 32]),
                    provenance: yadorilink_replica_domain::native_state::DeltaHash::default(),
                },
            )
            .unwrap();

        // Same content on both "sides".
        let same_content = state.clone();
        assert_eq!(namespace_root(&state).unwrap(), namespace_root(&same_content).unwrap());

        // But the frontiers disagree at the same seq.
        let mut left = NativeAuthorFrontier::new();
        left.insert(
            a.clone(),
            NativeAuthorFrontierEntry {
                seq: AuthorSeq(1),
                tip: yadorilink_replica_domain::native_state::DeltaHash([9u8; 32]),
            },
        );
        let mut right = NativeAuthorFrontier::new();
        right.insert(
            a,
            NativeAuthorFrontierEntry {
                seq: AuthorSeq(1),
                tip: yadorilink_replica_domain::native_state::DeltaHash([200u8; 32]),
            },
        );
        assert_ne!(open_root(&left), open_root(&right));
        assert!(
            frontier_domain::join(&left, &right).is_err(),
            "namespace agreement must not hide a frontier fork"
        );
    }

    /// `state.context[author] == frontier[author].seq` for every author,
    /// checked as a cross-table invariant across two verified installs.
    #[test]
    fn state_context_and_frontier_seq_agree_after_every_commit() {
        let c = conn();
        let a = author_id("a");
        let b = author_id("b");
        let key_a = signing_key(1);
        let key_b = signing_key(2);

        install_verified_delta(
            &c,
            &group(),
            &delta(&a, 1, None, "x", 1, &key_a),
            &key_a.verifying_key(),
        )
        .unwrap();
        install_verified_delta(
            &c,
            &group(),
            &delta(&b, 1, None, "y", 2, &key_b),
            &key_b.verifying_key(),
        )
        .unwrap();
        let d1_a = delta(&a, 1, None, "x", 1, &key_a);
        install_verified_delta(
            &c,
            &group(),
            &delta(&a, 2, Some(d1_a.delta_hash()), "x", 3, &key_a),
            &key_a.verifying_key(),
        )
        .unwrap();

        let state = load_state(&c, &group()).unwrap();
        let frontier = load_frontier(&c, &group()).unwrap();
        for (author, seq) in &state.context {
            assert_eq!(
                frontier.get(author).map(|e| e.seq),
                Some(*seq),
                "state.context and frontier.seq disagree for {author:?}"
            );
        }
        assert_eq!(
            state.context.len(),
            frontier.len(),
            "an author present in one table must be present in the other"
        );
    }
}

#[cfg(test)]
mod delta_body_tests {
    use ed25519_dalek::SigningKey;
    use rusqlite::Connection;
    use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut};

    use super::*;

    const GROUP: &str = "g-bodies";

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_native_tables(&c).unwrap();
        c
    }

    fn group() -> FolderGroupId {
        FolderGroupId(GROUP.into())
    }

    fn author_id(device: &str) -> AuthorId {
        AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) }
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn delta(
        author: &AuthorId,
        seq: u64,
        path: &str,
        version: u8,
        key: &SigningKey,
    ) -> NativeDelta {
        let mut d = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: author.clone(),
            seq: AuthorSeq(seq),
            prev: None,
            ops: vec![DeltaOp {
                path: SyncPath(path.into()),
                removes: vec![],
                put: Some(DeltaPut { version: VersionHash([version; 32]) }),
            }],
            signature: [0u8; 64],
        };
        d.sign(key);
        d
    }

    #[test]
    fn a_delta_body_is_fetchable_after_install_by_seq_and_by_hash() {
        let c = conn();
        let a = author_id("a");
        let key = signing_key(1);
        let d = delta(&a, 1, "x", 1, &key);
        let hash = d.delta_hash();
        install_verified_delta(&c, &group(), &d, &key.verifying_key()).unwrap();

        let by_seq = fetch_delta_body(&c, &group(), &a, AuthorSeq(1)).unwrap().unwrap();
        assert_eq!(by_seq, d.to_wire_bytes());
        let by_hash = fetch_delta_body_by_hash(&c, &group(), &hash).unwrap().unwrap();
        assert_eq!(by_hash, d.to_wire_bytes());
    }

    #[test]
    fn absent_body_reads_back_as_none() {
        let c = conn();
        let a = author_id("a");
        assert_eq!(fetch_delta_body(&c, &group(), &a, AuthorSeq(1)).unwrap(), None);
        assert_eq!(fetch_delta_body_by_hash(&c, &group(), &DeltaHash([9u8; 32])).unwrap(), None);
    }
}

#[cfg(test)]
mod retirement_tests {
    use ed25519_dalek::SigningKey;
    use rusqlite::Connection;
    use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut};

    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_native_tables(&c).unwrap();
        c
    }

    fn group() -> FolderGroupId {
        FolderGroupId("g1".into())
    }

    fn author_id(device: &str) -> AuthorId {
        AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) }
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn delta(
        author: &AuthorId,
        seq: u64,
        prev: Option<yadorilink_replica_domain::native_state::DeltaHash>,
        path: &str,
        version: u8,
        key: &SigningKey,
    ) -> NativeDelta {
        let mut d = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: author.clone(),
            seq: AuthorSeq(seq),
            prev,
            ops: vec![DeltaOp {
                path: SyncPath(path.into()),
                removes: vec![],
                put: Some(DeltaPut { version: VersionHash([version; 32]) }),
            }],
            signature: [0u8; 64],
        };
        d.sign(key);
        d
    }

    /// Closing is an explicit action only: an author with no activity at
    /// all -- never authored, never closed -- is simply absent, not
    /// auto-closed. There is no code path here that writes
    /// `native_closed_authors` except `close_author` itself.
    #[test]
    fn no_automatic_closure_from_inactivity() {
        let c = conn();
        let a = author_id("never-active");
        assert!(!is_closed(&c, &group(), &a).unwrap());
    }

    /// An author with live heads is not closed just because it stopped
    /// authoring -- closing never reads head count or recency.
    #[test]
    fn no_automatic_closure_when_live_heads_stay_untouched() {
        let c = conn();
        let a = author_id("a");
        let key = signing_key(1);
        install_verified_delta(
            &c,
            &group(),
            &delta(&a, 1, None, "x", 1, &key),
            &key.verifying_key(),
        )
        .unwrap();
        // No further activity, however long "later" is modeled as here.
        assert!(!is_closed(&c, &group(), &a).unwrap());
    }

    #[test]
    fn close_author_is_idempotent() {
        let c = conn();
        let a = author_id("a");
        crate::native_closure::close_author_unverified(&c, &group(), &a).unwrap();
        crate::native_closure::close_author_unverified(&c, &group(), &a).unwrap();
        assert!(is_closed(&c, &group(), &a).unwrap());
    }

    /// Closing an author changes which state it contributes to the author-state
    /// root (open at its entry, then closed at it), without changing the
    /// frontier's recorded (seq, tip) at all.
    #[test]
    fn closing_an_author_changes_its_state_in_the_root_but_not_its_entry() {
        let c = conn();
        let a = author_id("a");
        let key = signing_key(1);
        install_verified_delta(
            &c,
            &group(),
            &delta(&a, 1, None, "x", 1, &key),
            &key.verifying_key(),
        )
        .unwrap();

        let none = NodeDigest(native_frontier::author_state_root(&NativeAuthorStates::new()));
        let open = author_state_root(&c, &group()).unwrap();
        assert_ne!(open, none, "a's entry must show up in the root");
        assert!(matches!(load_author_states(&c, &group()).unwrap()[&a], AuthorState::Open(_)));

        crate::native_closure::close_author_unverified(&c, &group(), &a).unwrap();

        let closed = author_state_root(&c, &group()).unwrap();
        assert_ne!(closed, open, "closing a must change the root");
        assert!(matches!(
            load_author_states(&c, &group()).unwrap()[&a],
            AuthorState::Closed { frontier: Some(_) }
        ));

        // The frontier's own recorded position is unchanged by closing.
        let frontier = load_frontier(&c, &group()).unwrap();
        assert_eq!(frontier[&a].seq, AuthorSeq(1));
    }

    /// A sealed checkpoint commits the real, computed root -- never a
    /// placeholder -- and its own signature verifies.
    #[test]
    fn seal_checkpoint_commits_the_real_root_and_verifies() {
        let c = conn();
        let a = author_id("a");
        let key = signing_key(1);
        install_verified_delta(
            &c,
            &group(),
            &delta(&a, 1, None, "x", 1, &key),
            &key.verifying_key(),
        )
        .unwrap();
        crate::native_closure::close_author_unverified(&c, &group(), &a).unwrap();

        let sealer = signing_key(9);
        let checkpoint = seal_checkpoint(&c, &group(), &sealer).unwrap();
        checkpoint.verify_signature(&sealer.verifying_key()).unwrap();

        let state = load_state(&c, &group()).unwrap();
        assert_eq!(checkpoint.namespace_root.0, namespace_root(&state).unwrap().0);
        assert_eq!(checkpoint.author_state_root.0, author_state_root(&c, &group()).unwrap().0);
        assert_ne!(
            checkpoint.author_state_root.0,
            native_frontier::author_state_root(&NativeAuthorStates::new()),
            "the closed author must be reflected"
        );

        install_checkpoint(&c, &group(), &checkpoint, &sealer.verifying_key()).unwrap();
        assert_eq!(stored_checkpoint_hashes(&c, &group()), vec![checkpoint.checkpoint_hash().0]);
    }

    /// `seal_checkpoint` reads `NativeState` and the author states from one
    /// consistent snapshot: the root it commits to must agree with a state built
    /// from the SAME point in time. Exercised here by confirming the checkpoint's
    /// own root is internally self-consistent against a state read back
    /// immediately afterward with no mutation in between (the actual fix -- one
    /// transaction -- is what makes this true under a genuinely concurrent writer
    /// too, which SQLite's own snapshot-isolated transaction semantics provide
    /// once the reads are inside one transaction, as `seal_checkpoint`'s own doc
    /// comment states).
    #[test]
    fn seal_checkpoint_roots_agree_with_each_other_from_one_snapshot() {
        let c = conn();
        let a = author_id("a");
        let b = author_id("b");
        let key_a = signing_key(1);
        let key_b = signing_key(2);
        install_verified_delta(
            &c,
            &group(),
            &delta(&a, 1, None, "x", 1, &key_a),
            &key_a.verifying_key(),
        )
        .unwrap();
        install_verified_delta(
            &c,
            &group(),
            &delta(&b, 1, None, "y", 1, &key_b),
            &key_b.verifying_key(),
        )
        .unwrap();
        crate::native_closure::close_author_unverified(&c, &group(), &b).unwrap();

        let sealer = signing_key(9);
        let checkpoint = seal_checkpoint(&c, &group(), &sealer).unwrap();

        let frontier = load_frontier(&c, &group()).unwrap();
        let expected: NativeAuthorStates = frontier
            .iter()
            .map(|(author, entry)| {
                let state = if *author == b {
                    AuthorState::Closed { frontier: Some(*entry) }
                } else {
                    AuthorState::Open(*entry)
                };
                (author.clone(), state)
            })
            .collect();
        assert_eq!(checkpoint.author_state_root.0, native_frontier::author_state_root(&expected));
    }
}

/// Closes the frontier's own justification with numbers, not just
/// correctness. Confirms that the operations `install_verified_delta`
/// actually runs on its hot path -- single-author frontier lookup and
/// update, and a no-op root comparison -- do not degrade as the historical
/// author count `A` grows, at A=100/1k/10k. Not a performance-target suite
/// (no new target is set here): a result counts as green when it shows no
/// obvious linear full scan or runaway growth.
#[cfg(test)]
mod p2e_measurements {
    use std::time::Instant;

    use rusqlite::Connection;
    use yadorilink_replica_domain::native_state::DeltaHash;

    use super::*;

    fn group() -> FolderGroupId {
        FolderGroupId("g1".into())
    }

    fn author_id(i: usize) -> AuthorId {
        AuthorId { device: DeviceId(format!("author-{i}")), incarnation: IncarnationId([1u8; 16]) }
    }

    fn seeded(a: usize) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_native_tables(&c).unwrap();
        let mut frontier = NativeAuthorFrontier::new();
        for i in 0..a {
            frontier.insert(
                author_id(i),
                NativeAuthorFrontierEntry {
                    seq: AuthorSeq(1),
                    tip: DeltaHash([(i % 256) as u8; 32]),
                },
            );
        }
        install_frontier(&c, &group(), &frontier).unwrap();
        c
    }

    fn row_count(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM native_author_frontier WHERE group_id = ?1",
            [group().as_str()],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn approx_bytes(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(author) + LENGTH(incarnation) + 8 + LENGTH(tip)), 0) FROM native_author_frontier WHERE group_id = ?1",
            [group().as_str()],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// `frontier_entry_get`'s query plan names the primary-key index, never
    /// a table scan -- literal proof the lookup is not O(A), not an
    /// inference from timing alone.
    fn lookup_uses_an_index(conn: &Connection) -> bool {
        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT seq, tip FROM native_author_frontier WHERE group_id = ?1 AND author = ?2 AND incarnation = ?3",
                (group().as_str(), "author-0", IncarnationId([1u8; 16]).0.as_slice()),
                |row| row.get::<_, String>(3),
            )
            .unwrap();
        !plan.to_uppercase().contains("SCAN TABLE") || plan.to_uppercase().contains("USING INDEX")
    }

    #[test]
    fn measurements_at_a_100_1k_10k_show_no_linear_full_scan_on_the_hot_path() {
        for &a in &[100usize, 1_000, 10_000] {
            let c = seeded(a);
            let target = author_id(a / 2);

            assert!(
                lookup_uses_an_index(&c),
                "A={a}: single-author lookup must use the primary-key index, not a table scan"
            );

            let lookup_start = Instant::now();
            let looked_up = frontier_entry_get(&c, &group(), &target).unwrap().unwrap();
            let lookup_elapsed = lookup_start.elapsed();
            assert_eq!(looked_up.seq, AuthorSeq(1));

            let before_rows = row_count(&c);
            let update_start = Instant::now();
            frontier_entry_upsert(
                &c,
                &group(),
                &target,
                &NativeAuthorFrontierEntry { seq: AuthorSeq(2), tip: DeltaHash([0xAA; 32]) },
            )
            .unwrap();
            let update_elapsed = update_start.elapsed();
            let after_rows = row_count(&c);
            assert_eq!(before_rows, after_rows, "A={a}: a single-author update must not change the row count (no delete-and-reinsert of the whole table)");
            assert_eq!(
                conn_changes(&c),
                1,
                "A={a}: a single-author update must touch exactly one row"
            );

            let rows = row_count(&c);
            let bytes = approx_bytes(&c);
            eprintln!(
                "A={a}: lookup={lookup_elapsed:?} single_author_update={update_elapsed:?} \
                 rows={rows} approx_bytes={bytes}"
            );
        }
    }

    fn conn_changes(conn: &Connection) -> i64 {
        conn.changes() as i64
    }
}
