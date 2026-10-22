//! The persistent block index: the store's canonical metadata.
//!
//! This database -- not a scan of the segment files -- is what says which
//! blocks exist and where. That is the whole reason startup is
//! `O(segments)` rather than `O(bytes)`: nothing ever re-derives the
//! mapping by reading payloads.
//!
//! # The invariant every write here upholds
//!
//! **A mapping this index holds always points at bytes that are already
//! durable in their segment.** The commit sequence enforces it by
//! ordering, not by checking: a segment's `fsync` completes before the
//! transaction that records any of its new blocks begins. A crash before
//! that transaction leaves durable bytes with no mapping (recovery
//! truncates them); a crash after it leaves a mapping whose bytes were
//! fsynced strictly earlier. There is no interleaving that produces a
//! mapping to non-durable bytes.
//!
//! `synchronous = FULL` under WAL, inherited from the shared SQLite
//! runtime, is what makes "the transaction committed" mean the commit
//! survives power loss -- without it this index would report mappings that
//! a crash could take back while the segment bytes they point at stayed.

use std::collections::HashSet;
use std::path::Path;

use rusqlite::OptionalExtension;
use yadorilink_sqlite_runtime::{DatabaseError, SyncDatabase};

use crate::error::StorageError;
use crate::segment_store::format::{RAW_HASH_LEN, RECORD_HEADER_LEN, SEGMENT_HEADER_LEN};

/// The store format this build writes. A store stamped with any other
/// value is refused outright -- there is no migration path, by design.
pub(crate) const STORE_FORMAT_VERSION: i64 = 2;

const META_FORMAT_VERSION: &str = "format_version";
const META_NEXT_SEGMENT_ID: &str = "next_segment_id";

/// A segment's lifecycle. Only `Active` is appended to; only `Retired` may
/// have its file removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegmentState {
    /// Currently (or most recently) appended to by this store.
    Active,
    /// Closed to further appends; still holds live blocks or is awaiting a
    /// compaction decision.
    Sealed,
    /// Every block it held has been superseded or removed. Its file may be
    /// deleted as soon as no reader is using it.
    Retired,
}

impl SegmentState {
    fn as_str(self) -> &'static str {
        match self {
            SegmentState::Active => "active",
            SegmentState::Sealed => "sealed",
            SegmentState::Retired => "retired",
        }
    }

    fn parse(raw: &str) -> Result<Self, StorageError> {
        match raw {
            "active" => Ok(SegmentState::Active),
            "sealed" => Ok(SegmentState::Sealed),
            "retired" => Ok(SegmentState::Retired),
            other => Err(StorageError::CorruptStore(format!("unknown segment state {other:?}"))),
        }
    }
}

/// One segment's accounting row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SegmentRow {
    pub(crate) segment_id: u64,
    pub(crate) state: SegmentState,
    /// Bytes of this file that are both fsynced and index-covered. Every
    /// byte at or beyond this offset is, by definition, not referenced by
    /// any mapping and may be truncated at any time.
    pub(crate) durable_end: u64,
    pub(crate) live_blocks: u64,
    /// Summed payload lengths of this segment's live blocks -- what
    /// `StorageUsage::total_bytes` reports.
    pub(crate) live_payload_bytes: u64,
    /// Summed *record* lengths (framing included) of this segment's live
    /// blocks -- the numerator of the dead-ratio compaction decides on,
    /// since the framing of a dead block is just as dead as its payload.
    pub(crate) live_record_bytes: u64,
}

impl SegmentRow {
    /// Physical bytes this segment occupies that a compaction could
    /// reclaim: everything written past the file header that no live block
    /// still needs.
    pub(crate) fn dead_bytes(&self) -> u64 {
        self.durable_end.saturating_sub(SEGMENT_HEADER_LEN).saturating_sub(self.live_record_bytes)
    }

    /// Fraction of this segment's records that are dead, in `0.0..=1.0`.
    pub(crate) fn dead_ratio(&self) -> f64 {
        let written = self.durable_end.saturating_sub(SEGMENT_HEADER_LEN);
        if written == 0 {
            return 0.0;
        }
        self.dead_bytes() as f64 / written as f64
    }
}

/// Where one block's bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockLocation {
    pub(crate) segment_id: u64,
    pub(crate) record_offset: u64,
    pub(crate) length: u32,
}

impl BlockLocation {
    pub(crate) fn payload_offset(&self) -> u64 {
        self.record_offset + RECORD_HEADER_LEN as u64
    }
}

/// One block a group commit is about to record.
#[derive(Debug, Clone)]
pub(crate) struct NewBlockRow {
    pub(crate) hash: [u8; RAW_HASH_LEN],
    pub(crate) record_offset: u64,
    pub(crate) payload_len: u32,
    pub(crate) record_len: u64,
    pub(crate) added_at_nanos: i64,
}

/// Everything one group commit appended to a single segment.
#[derive(Debug, Clone)]
pub(crate) struct SegmentAppend {
    pub(crate) segment_id: u64,
    /// Whether this group created the segment file (so its row must be
    /// inserted, not updated).
    pub(crate) created: bool,
    /// The segment's new `durable_end` -- the offset just past the last
    /// record this group appended, which is already fsynced by the time
    /// this plan is committed.
    pub(crate) durable_end: u64,
    pub(crate) blocks: Vec<NewBlockRow>,
}

/// The complete index change one group commit makes. Applied in a single
/// transaction so a crash can never leave part of a group recorded.
#[derive(Debug, Clone, Default)]
pub(crate) struct GroupCommitPlan {
    pub(crate) appends: Vec<SegmentAppend>,
    /// Segments this group sealed by rolling over off them.
    pub(crate) sealed: Vec<u64>,
    pub(crate) next_segment_id: u64,
}

/// What a relocation (compaction) transaction re-pointed.
#[derive(Debug, Clone)]
pub(crate) struct RelocationPlan {
    /// The appends that put the copies in their new segment. Exactly the
    /// same shape a fresh group commit uses -- a relocated block is an
    /// ordinary appended record.
    pub(crate) group: GroupCommitPlan,
    /// Source segments every relocated block came out of.
    pub(crate) sources: Vec<u64>,
}

/// How many blocks and bytes a removal freed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RemovalSummary {
    pub(crate) blocks_removed: u64,
    pub(crate) payload_bytes_removed: u64,
}

/// Aggregate store accounting, straight out of the segment rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IndexUsage {
    pub(crate) live_blocks: u64,
    pub(crate) live_payload_bytes: u64,
    pub(crate) live_record_bytes: u64,
    pub(crate) physical_bytes: u64,
    pub(crate) active_segments: u64,
    pub(crate) sealed_segments: u64,
    pub(crate) retired_segments: u64,
}

impl IndexUsage {
    pub(crate) fn dead_bytes(&self) -> u64 {
        self.physical_bytes.saturating_sub(self.live_record_bytes)
    }
}

/// The index database handle.
pub(crate) struct BlockIndex {
    db: SyncDatabase,
}

fn to_storage(error: DatabaseError) -> StorageError {
    StorageError::Index(error.to_string())
}

impl BlockIndex {
    /// Opens (creating if absent) the index at `path`, bootstrapping the
    /// schema and refusing any store whose stamped format version is not
    /// this build's.
    pub(crate) fn open(path: &Path) -> Result<Self, StorageError> {
        let db = SyncDatabase::open(path, |conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS store_meta (
                     key   TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 ) WITHOUT ROWID;

                 CREATE TABLE IF NOT EXISTS segments (
                     segment_id         INTEGER PRIMARY KEY,
                     state              TEXT    NOT NULL,
                     durable_end        INTEGER NOT NULL,
                     live_blocks        INTEGER NOT NULL,
                     live_payload_bytes INTEGER NOT NULL,
                     live_record_bytes  INTEGER NOT NULL
                 );

                 -- Raw 32-byte keys, not 64-character hex: half the bytes
                 -- to store and compare on a table that holds one row per
                 -- block in the store. WITHOUT ROWID so the primary key IS
                 -- the table, rather than a separate index into one.
                 CREATE TABLE IF NOT EXISTS blocks (
                     hash          BLOB    PRIMARY KEY,
                     segment_id    INTEGER NOT NULL,
                     record_offset INTEGER NOT NULL,
                     payload_len   INTEGER NOT NULL,
                     record_len    INTEGER NOT NULL,
                     added_at      INTEGER NOT NULL
                 ) WITHOUT ROWID;

                 -- Compaction reads a whole segment's live blocks; GC
                 -- retires a segment by emptying it. Both are
                 -- segment-scoped scans, and neither should walk the
                 -- whole store to do it.
                 CREATE INDEX IF NOT EXISTS blocks_by_segment ON blocks(segment_id);",
            )?;
            Ok(())
        })
        .map_err(to_storage)?;

        let index = Self { db };
        index.check_or_stamp_format_version()?;
        Ok(index)
    }

    /// Reads the store format marker, stamping it on a store that has none
    /// yet (a fresh one) and failing closed on any value this build does
    /// not write. There is deliberately no migration branch: an older
    /// store is refused, not converted.
    fn check_or_stamp_format_version(&self) -> Result<(), StorageError> {
        self.db
            .write_immediate(|tx| {
                let stamped: Option<String> = tx
                    .query_row(
                        "SELECT value FROM store_meta WHERE key = ?1",
                        [META_FORMAT_VERSION],
                        |row| row.get(0),
                    )
                    .optional()?;
                match stamped {
                    None => {
                        tx.execute(
                            "INSERT INTO store_meta (key, value) VALUES (?1, ?2)",
                            rusqlite::params![
                                META_FORMAT_VERSION,
                                STORE_FORMAT_VERSION.to_string()
                            ],
                        )?;
                        Ok(())
                    }
                    Some(raw) if raw.trim().parse::<i64>().ok() == Some(STORE_FORMAT_VERSION) => {
                        Ok(())
                    }
                    Some(raw) => Err(DatabaseError::CorruptSchema(format!(
                        "block store format version {raw:?} is not this build's \
                         v{STORE_FORMAT_VERSION}; this build does not migrate older stores"
                    ))),
                }
            })
            .map_err(to_storage)
    }

    /// The highest segment id ever handed out, as recorded. The caller
    /// reconciles this against what is actually on disk at open (see
    /// `recovery`), because a segment file can exist that no committed
    /// transaction ever mentioned.
    /// Folds the index's write-ahead log into its main file.
    pub(crate) fn checkpoint(&self) -> Result<(), StorageError> {
        self.db.checkpoint_truncate().map_err(to_storage)
    }

    pub(crate) fn recorded_next_segment_id(&self) -> Result<u64, StorageError> {
        self.db
            .read(|conn| {
                let stored: Option<String> = conn
                    .query_row(
                        "SELECT value FROM store_meta WHERE key = ?1",
                        [META_NEXT_SEGMENT_ID],
                        |row| row.get(0),
                    )
                    .optional()?;
                let from_meta = stored.and_then(|raw| raw.trim().parse::<u64>().ok()).unwrap_or(1);
                let from_rows: Option<i64> =
                    conn.query_row("SELECT MAX(segment_id) FROM segments", [], |row| row.get(0))?;
                Ok::<u64, DatabaseError>(
                    from_meta.max(from_rows.map(|id| id as u64 + 1).unwrap_or(1)),
                )
            })
            .map_err(to_storage)
    }

    /// Every segment row, ordered by id.
    pub(crate) fn segments(&self) -> Result<Vec<SegmentRow>, StorageError> {
        let rows = self
            .db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT segment_id, state, durable_end, live_blocks, live_payload_bytes, \
                     live_record_bytes FROM segments ORDER BY segment_id",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(0)? as u64,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)? as u64,
                            row.get::<_, i64>(3)? as u64,
                            row.get::<_, i64>(4)? as u64,
                            row.get::<_, i64>(5)? as u64,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, DatabaseError>(rows)
            })
            .map_err(to_storage)?;
        rows.into_iter()
            .map(|(segment_id, state, durable_end, live_blocks, live_payload, live_record)| {
                Ok(SegmentRow {
                    segment_id,
                    state: SegmentState::parse(&state)?,
                    durable_end,
                    live_blocks,
                    live_payload_bytes: live_payload,
                    live_record_bytes: live_record,
                })
            })
            .collect()
    }

    pub(crate) fn segment(&self, segment_id: u64) -> Result<Option<SegmentRow>, StorageError> {
        Ok(self.segments()?.into_iter().find(|row| row.segment_id == segment_id))
    }

    /// Where one block lives, or `None` if this store does not hold it.
    pub(crate) fn lookup(
        &self,
        hash: &[u8; RAW_HASH_LEN],
    ) -> Result<Option<BlockLocation>, StorageError> {
        self.db
            .read(|conn| {
                conn.query_row(
                    "SELECT segment_id, record_offset, payload_len FROM blocks WHERE hash = ?1",
                    [&hash[..]],
                    |row| {
                        Ok(BlockLocation {
                            segment_id: row.get::<_, i64>(0)? as u64,
                            record_offset: row.get::<_, i64>(1)? as u64,
                            length: row.get::<_, i64>(2)? as u32,
                        })
                    },
                )
                .optional()
                .map_err(DatabaseError::from)
            })
            .map_err(to_storage)
    }

    /// Locations for many hashes at once, in the caller's order. One
    /// connection checkout and one prepared statement for the whole slice,
    /// rather than a checkout per hash -- this is both the group commit's
    /// dedup step and `present_blocks`.
    pub(crate) fn lookup_many(
        &self,
        hashes: &[[u8; RAW_HASH_LEN]],
    ) -> Result<Vec<Option<BlockLocation>>, StorageError> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }
        self.db
            .read(|conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT segment_id, record_offset, payload_len FROM blocks WHERE hash = ?1",
                )?;
                let mut out = Vec::with_capacity(hashes.len());
                for hash in hashes {
                    out.push(
                        stmt.query_row([&hash[..]], |row| {
                            Ok(BlockLocation {
                                segment_id: row.get::<_, i64>(0)? as u64,
                                record_offset: row.get::<_, i64>(1)? as u64,
                                length: row.get::<_, i64>(2)? as u32,
                            })
                        })
                        .optional()?,
                    );
                }
                Ok::<_, DatabaseError>(out)
            })
            .map_err(to_storage)
    }

    /// [`Self::lookup_many`] for a put: every block found is also stamped as added `now_nanos`
    /// (never earlier than it was), in the same write transaction, so a sweep that chooses
    /// its candidates afterwards finds it inside the grace window and the sweep's own removal
    /// (see [`Self::remove_swept_blocks`]) rechecks the stamp. A block that is gone by the time
    /// the transaction runs is reported absent, so the caller writes it again.
    pub(crate) fn lookup_many_refreshing(
        &self,
        hashes: &[[u8; RAW_HASH_LEN]],
        now_nanos: i64,
    ) -> Result<Vec<Option<BlockLocation>>, StorageError> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }
        self.db
            .write_immediate(|tx| {
                let mut touch = tx.prepare_cached(
                    "UPDATE blocks SET added_at = MAX(added_at, ?2) WHERE hash = ?1",
                )?;
                let mut find = tx.prepare_cached(
                    "SELECT segment_id, record_offset, payload_len FROM blocks WHERE hash = ?1",
                )?;
                let mut out = Vec::with_capacity(hashes.len());
                for hash in hashes {
                    let found = if touch.execute(rusqlite::params![&hash[..], now_nanos])? == 1 {
                        find.query_row([&hash[..]], |row| {
                            Ok(BlockLocation {
                                segment_id: row.get::<_, i64>(0)? as u64,
                                record_offset: row.get::<_, i64>(1)? as u64,
                                length: row.get::<_, i64>(2)? as u32,
                            })
                        })
                        .optional()?
                    } else {
                        None
                    };
                    out.push(found);
                }
                Ok(out)
            })
            .map_err(to_storage)
    }

    /// Applies one group commit's mappings, segment accounting and
    /// segment-id watermark in a single transaction.
    ///
    /// Every byte this records was fsynced before the call; see the module
    /// doc for why that ordering is the whole contract.
    ///
    /// `INSERT OR IGNORE` on the mappings, with the live counters derived
    /// from what actually inserted: a hash that is somehow already mapped
    /// keeps its existing (equally valid, equally durable) location, and
    /// the freshly appended copy becomes dead bytes for compaction to
    /// reclaim rather than an error that fails an otherwise-good group.
    ///
    /// `mid_transaction` is the crash-injection seam: it runs after the
    /// rows are staged and before the commit, and a `Some` return aborts
    /// the transaction. It exists so a test can prove that a crash *inside*
    /// the transaction leaves the index exactly as it was -- the one
    /// boundary where the store's invariant would be broken by a partial
    /// apply rather than by a wrong ordering.
    pub(crate) fn commit_group(
        &self,
        plan: &GroupCommitPlan,
        mid_transaction: &dyn Fn() -> Option<String>,
    ) -> Result<(), StorageError> {
        self.db
            .write_immediate(|tx| {
                for segment_id in &plan.sealed {
                    tx.execute(
                        "UPDATE segments SET state = ?2 WHERE segment_id = ?1 AND state = ?3",
                        rusqlite::params![
                            *segment_id as i64,
                            SegmentState::Sealed.as_str(),
                            SegmentState::Active.as_str()
                        ],
                    )?;
                }
                for append in &plan.appends {
                    if append.created {
                        tx.execute(
                            "INSERT OR IGNORE INTO segments (segment_id, state, durable_end, \
                             live_blocks, live_payload_bytes, live_record_bytes) \
                             VALUES (?1, ?2, ?3, 0, 0, 0)",
                            rusqlite::params![
                                append.segment_id as i64,
                                SegmentState::Active.as_str(),
                                SEGMENT_HEADER_LEN as i64
                            ],
                        )?;
                    }
                    let (inserted_blocks, inserted_payload, inserted_record) =
                        Self::insert_new_blocks(tx, append)?;
                    tx.execute(
                        "UPDATE segments SET durable_end = ?2, \
                         live_blocks = live_blocks + ?3, \
                         live_payload_bytes = live_payload_bytes + ?4, \
                         live_record_bytes = live_record_bytes + ?5 \
                         WHERE segment_id = ?1",
                        rusqlite::params![
                            append.segment_id as i64,
                            append.durable_end as i64,
                            inserted_blocks,
                            inserted_payload,
                            inserted_record,
                        ],
                    )?;
                }
                tx.execute(
                    "INSERT INTO store_meta (key, value) VALUES (?1, ?2) \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    rusqlite::params![META_NEXT_SEGMENT_ID, plan.next_segment_id.to_string()],
                )?;
                if let Some(injected) = mid_transaction() {
                    return Err(DatabaseError::CorruptSchema(injected));
                }
                Ok(())
            })
            .map_err(to_storage)
    }

    /// Inserts one append's block rows, returning how many blocks and
    /// payload/record bytes actually inserted (an already-mapped hash keeps
    /// its existing location and is not counted).
    fn insert_new_blocks(
        tx: &rusqlite::Transaction<'_>,
        append: &SegmentAppend,
    ) -> rusqlite::Result<(i64, i64, i64)> {
        let mut inserted_blocks = 0i64;
        let mut inserted_payload = 0i64;
        let mut inserted_record = 0i64;
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO blocks (hash, segment_id, record_offset, \
             payload_len, record_len, added_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for block in &append.blocks {
            let changed = stmt.execute(rusqlite::params![
                &block.hash[..],
                append.segment_id as i64,
                block.record_offset as i64,
                block.payload_len as i64,
                block.record_len as i64,
                block.added_at_nanos,
            ])?;
            if changed == 1 {
                inserted_blocks += 1;
                inserted_payload += i64::from(block.payload_len);
                inserted_record += block.record_len as i64;
            }
        }
        Ok((inserted_blocks, inserted_payload, inserted_record))
    }

    /// Re-points one relocation append's hashes at their new copies and
    /// debits each source segment, returning how many blocks and
    /// payload/record bytes actually moved.
    fn repoint_relocated_blocks(
        tx: &rusqlite::Transaction<'_>,
        append: &SegmentAppend,
    ) -> rusqlite::Result<(i64, i64, i64)> {
        let mut moved_blocks = 0i64;
        let mut moved_payload = 0i64;
        let mut moved_record = 0i64;
        let mut debit = tx.prepare_cached(
            "UPDATE segments SET live_blocks = live_blocks - 1, \
             live_payload_bytes = live_payload_bytes - ?2, \
             live_record_bytes = live_record_bytes - ?3 WHERE segment_id = ?1",
        )?;
        let mut repoint = tx.prepare_cached(
            "UPDATE blocks SET segment_id = ?2, record_offset = ?3 \
             WHERE hash = ?1 AND segment_id = ?4",
        )?;
        let mut source_of = tx.prepare_cached("SELECT segment_id FROM blocks WHERE hash = ?1")?;
        for block in &append.blocks {
            // Re-read the source under this transaction rather than trusting
            // the snapshot the copy was planned from: a delete that landed in
            // between must win, and moving a mapping that no longer exists
            // must be a no-op, not a resurrection.
            let source: Option<i64> =
                source_of.query_row([&block.hash[..]], |row| row.get(0)).optional()?;
            let Some(source) = source else { continue };
            let changed = repoint.execute(rusqlite::params![
                &block.hash[..],
                append.segment_id as i64,
                block.record_offset as i64,
                source,
            ])?;
            if changed == 1 {
                debit.execute(rusqlite::params![
                    source,
                    i64::from(block.payload_len),
                    block.record_len as i64,
                ])?;
                moved_blocks += 1;
                moved_payload += i64::from(block.payload_len);
                moved_record += block.record_len as i64;
            }
        }
        Ok((moved_blocks, moved_payload, moved_record))
    }

    /// Re-points a set of hashes at freshly appended copies, and debits the
    /// segments they came from -- one transaction, so a crash either leaves
    /// every mapping on the old copy or every mapping on the new one.
    pub(crate) fn commit_relocation(
        &self,
        plan: &RelocationPlan,
        mid_transaction: &dyn Fn() -> Option<String>,
    ) -> Result<(), StorageError> {
        self.db
            .write_immediate(|tx| {
                // A relocation can roll over onto a new segment just as an
                // ingest can, and the segment it rolled off has to be
                // sealed here too -- a segment left marked active while a
                // different one actually is would be skipped by every
                // later compaction, since compaction never touches the
                // active segment.
                for segment_id in &plan.group.sealed {
                    tx.execute(
                        "UPDATE segments SET state = ?2 WHERE segment_id = ?1 AND state = ?3",
                        rusqlite::params![
                            *segment_id as i64,
                            SegmentState::Sealed.as_str(),
                            SegmentState::Active.as_str()
                        ],
                    )?;
                }
                for append in &plan.group.appends {
                    if append.created {
                        tx.execute(
                            "INSERT OR IGNORE INTO segments (segment_id, state, durable_end, \
                             live_blocks, live_payload_bytes, live_record_bytes) \
                             VALUES (?1, ?2, ?3, 0, 0, 0)",
                            rusqlite::params![
                                append.segment_id as i64,
                                SegmentState::Active.as_str(),
                                SEGMENT_HEADER_LEN as i64
                            ],
                        )?;
                    }
                    let (moved_blocks, moved_payload, moved_record) =
                        Self::repoint_relocated_blocks(tx, append)?;
                    tx.execute(
                        "UPDATE segments SET durable_end = ?2, \
                         live_blocks = live_blocks + ?3, \
                         live_payload_bytes = live_payload_bytes + ?4, \
                         live_record_bytes = live_record_bytes + ?5 \
                         WHERE segment_id = ?1",
                        rusqlite::params![
                            append.segment_id as i64,
                            append.durable_end as i64,
                            moved_blocks,
                            moved_payload,
                            moved_record,
                        ],
                    )?;
                }
                // A source segment with nothing live left is retired here,
                // in the same transaction that emptied it -- never in a
                // later one that a crash could skip.
                for source in &plan.sources {
                    tx.execute(
                        "UPDATE segments SET state = ?2 WHERE segment_id = ?1 \
                         AND live_blocks = 0 AND state != ?3",
                        rusqlite::params![
                            *source as i64,
                            SegmentState::Retired.as_str(),
                            SegmentState::Active.as_str()
                        ],
                    )?;
                }
                tx.execute(
                    "INSERT INTO store_meta (key, value) VALUES (?1, ?2) \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    rusqlite::params![META_NEXT_SEGMENT_ID, plan.group.next_segment_id.to_string()],
                )?;
                if let Some(injected) = mid_transaction() {
                    return Err(DatabaseError::CorruptSchema(injected));
                }
                Ok(())
            })
            .map_err(to_storage)
    }

    /// [`Self::remove_blocks`] for one block, but only while its row still points at
    /// `location`: a mapping repaired or replaced since the caller looked is left alone
    /// (returns whether a row was removed).
    pub(crate) fn remove_block_at(
        &self,
        hash: &[u8; RAW_HASH_LEN],
        location: &BlockLocation,
    ) -> Result<bool, StorageError> {
        self.db
            .write_immediate(|tx| {
                let row: Option<(i64, i64)> = tx
                    .query_row(
                        "SELECT payload_len, record_len FROM blocks \
                         WHERE hash = ?1 AND segment_id = ?2 AND record_offset = ?3",
                        rusqlite::params![
                            &hash[..],
                            location.segment_id as i64,
                            location.record_offset as i64
                        ],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let Some((payload_len, record_len)) = row else { return Ok(false) };
                tx.execute("DELETE FROM blocks WHERE hash = ?1", [&hash[..]])?;
                tx.execute(
                    "UPDATE segments SET live_blocks = live_blocks - 1, \
                     live_payload_bytes = live_payload_bytes - ?2, \
                     live_record_bytes = live_record_bytes - ?3 WHERE segment_id = ?1",
                    rusqlite::params![location.segment_id as i64, payload_len, record_len],
                )?;
                Ok(true)
            })
            .map_err(to_storage)
    }

    /// Drops mappings for `hashes` and debits their segments. Physical
    /// bytes stay where they are -- reclaiming them is compaction's job,
    /// and is deliberately not coupled to a delete.
    pub(crate) fn remove_blocks(
        &self,
        hashes: &[[u8; RAW_HASH_LEN]],
    ) -> Result<RemovalSummary, StorageError> {
        self.remove_blocks_added_by(hashes, None)
    }

    /// [`Self::remove_blocks`] for a sweep: a block whose ingest stamp is later than
    /// `cutoff_nanos` when it comes to be removed (a put refreshed it after the candidates
    /// were chosen) is left alone.
    pub(crate) fn remove_swept_blocks(
        &self,
        hashes: &[[u8; RAW_HASH_LEN]],
        cutoff_nanos: i64,
    ) -> Result<RemovalSummary, StorageError> {
        self.remove_blocks_added_by(hashes, Some(cutoff_nanos))
    }

    fn remove_blocks_added_by(
        &self,
        hashes: &[[u8; RAW_HASH_LEN]],
        cutoff_nanos: Option<i64>,
    ) -> Result<RemovalSummary, StorageError> {
        if hashes.is_empty() {
            return Ok(RemovalSummary::default());
        }
        self.db
            .write_immediate(|tx| {
                let mut summary = RemovalSummary::default();
                let mut lookup = tx.prepare_cached(
                    "SELECT segment_id, payload_len, record_len, added_at FROM blocks \
                     WHERE hash = ?1",
                )?;
                let mut delete = tx.prepare_cached("DELETE FROM blocks WHERE hash = ?1")?;
                let mut debit = tx.prepare_cached(
                    "UPDATE segments SET live_blocks = live_blocks - 1, \
                     live_payload_bytes = live_payload_bytes - ?2, \
                     live_record_bytes = live_record_bytes - ?3 WHERE segment_id = ?1",
                )?;
                for hash in hashes {
                    let row: Option<(i64, i64, i64, i64)> = lookup
                        .query_row([&hash[..]], |row| {
                            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                        })
                        .optional()?;
                    let Some((segment_id, payload_len, record_len, added_at)) = row else {
                        continue;
                    };
                    if cutoff_nanos.is_some_and(|cutoff| added_at > cutoff) {
                        continue;
                    }
                    delete.execute([&hash[..]])?;
                    debit.execute(rusqlite::params![segment_id, payload_len, record_len])?;
                    summary.blocks_removed += 1;
                    summary.payload_bytes_removed += payload_len as u64;
                }
                Ok(summary)
            })
            .map_err(to_storage)
    }

    /// Hashes not in `live` whose ingest time is at or before
    /// `cutoff_nanos` -- the grace-window rule GC applies, evaluated in the
    /// index rather than against filesystem mtimes that a segment rewrite
    /// would reset.
    pub(crate) fn sweep_candidates(
        &self,
        live: &HashSet<[u8; RAW_HASH_LEN]>,
        cutoff_nanos: i64,
    ) -> Result<Vec<([u8; RAW_HASH_LEN], u64)>, StorageError> {
        let rows = self
            .db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT hash, payload_len FROM blocks WHERE added_at <= ?1 ORDER BY hash",
                )?;
                let rows = stmt
                    .query_map([cutoff_nanos], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)? as u64))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, DatabaseError>(rows)
            })
            .map_err(to_storage)?;
        let mut out = Vec::new();
        for (raw, payload_len) in rows {
            let hash = raw_hash(&raw)?;
            if !live.contains(&hash) {
                out.push((hash, payload_len));
            }
        }
        Ok(out)
    }

    /// Up to `limit` of a segment's live blocks, in record order, starting
    /// after `after_offset` -- compaction's input, paged.
    ///
    /// Paged rather than returned whole because a segment can hold millions
    /// of records: a 1 GiB segment of 50-byte blocks is about ten million
    /// of them, and materialising that list (let alone their payloads)
    /// would make compacting one segment cost more memory than the whole
    /// daemon is expected to use. Compaction walks a segment in bounded
    /// batches, each its own transaction.
    pub(crate) fn live_blocks_in_segment(
        &self,
        segment_id: u64,
        after_offset: Option<u64>,
        limit: usize,
    ) -> Result<Vec<([u8; RAW_HASH_LEN], BlockLocation)>, StorageError> {
        let after = after_offset.map(|offset| offset as i64).unwrap_or(-1);
        let rows = self
            .db
            .read(|conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT hash, record_offset, payload_len FROM blocks \
                     WHERE segment_id = ?1 AND record_offset > ?2 \
                     ORDER BY record_offset LIMIT ?3",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![segment_id as i64, after, limit as i64], |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)? as u64,
                            row.get::<_, i64>(2)? as u32,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, DatabaseError>(rows)
            })
            .map_err(to_storage)?;
        rows.into_iter()
            .map(|(raw, record_offset, length)| {
                Ok((raw_hash(&raw)?, BlockLocation { segment_id, record_offset, length }))
            })
            .collect()
    }

    /// Every hash whose hex form starts with `prefix`. Translated into a
    /// raw-key range so SQLite answers it from the primary key rather than
    /// by scanning and re-encoding every row.
    pub(crate) fn hashes_with_hex_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<crate::traits::ContentHash>, StorageError> {
        let (low, high) = raw_key_range_for_hex_prefix(prefix)?;
        let rows = self
            .db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT hash FROM blocks WHERE hash >= ?1 AND hash <= ?2 ORDER BY hash",
                )?;
                let rows = stmt
                    .query_map([&low[..], &high[..]], |row| row.get::<_, Vec<u8>>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, DatabaseError>(rows)
            })
            .map_err(to_storage)?;
        Ok(rows.into_iter().map(hex::encode).collect())
    }

    /// Aggregate accounting, computed from the segment rows -- `O(number
    /// of segments)`, never a walk of the blocks table or of the files.
    pub(crate) fn usage(&self) -> Result<IndexUsage, StorageError> {
        let mut usage = IndexUsage::default();
        for segment in self.segments()? {
            match segment.state {
                SegmentState::Active => usage.active_segments += 1,
                SegmentState::Sealed => usage.sealed_segments += 1,
                SegmentState::Retired => {
                    usage.retired_segments += 1;
                    // A retired segment's file is pending deletion and
                    // holds nothing live. Counting its bytes as physical
                    // would make `dead_bytes` include space that is
                    // already accounted for as reclaimable elsewhere.
                    continue;
                }
            }
            usage.live_blocks += segment.live_blocks;
            usage.live_payload_bytes += segment.live_payload_bytes;
            usage.live_record_bytes += segment.live_record_bytes;
            usage.physical_bytes += segment.durable_end.saturating_sub(SEGMENT_HEADER_LEN);
        }
        Ok(usage)
    }

    /// Rewrites one block's recorded ingest time. Exists for the GC
    /// grace-window tests, which otherwise could not reach the "older than
    /// the grace window" branch without waiting out a real grace window.
    pub(crate) fn set_block_added_at(
        &self,
        hash: &[u8; RAW_HASH_LEN],
        added_at_nanos: i64,
    ) -> Result<(), StorageError> {
        self.db
            .write(|conn| {
                conn.execute(
                    "UPDATE blocks SET added_at = ?2 WHERE hash = ?1",
                    rusqlite::params![&hash[..], added_at_nanos],
                )?;
                Ok::<_, DatabaseError>(())
            })
            .map_err(to_storage)
            .map(|_| ())
    }

    pub(crate) fn set_segment_state(
        &self,
        segment_id: u64,
        state: SegmentState,
    ) -> Result<(), StorageError> {
        self.db
            .write(|conn| {
                conn.execute(
                    "UPDATE segments SET state = ?2 WHERE segment_id = ?1",
                    rusqlite::params![segment_id as i64, state.as_str()],
                )?;
                Ok::<_, DatabaseError>(())
            })
            .map_err(to_storage)
            .map(|_| ())
    }

    /// Drops every mapping into `segment_id`, returning how many there
    /// were. Recovery's response to a segment file that is gone: the
    /// blocks are not there, so the index must stop saying they are.
    pub(crate) fn drop_segment_mappings(&self, segment_id: u64) -> Result<u64, StorageError> {
        self.db
            .write_immediate(|tx| {
                let dropped =
                    tx.execute("DELETE FROM blocks WHERE segment_id = ?1", [segment_id as i64])?;
                tx.execute(
                    "UPDATE segments SET live_blocks = 0, live_payload_bytes = 0, \
                     live_record_bytes = 0 WHERE segment_id = ?1",
                    [segment_id as i64],
                )?;
                Ok(dropped as u64)
            })
            .map_err(to_storage)
    }

    /// Reconciles a segment that lost bytes: drops exactly the mappings
    /// whose records no longer fit inside `file_len`, recomputes the live
    /// counters from what survived, and lowers `durable_end` to the end of
    /// the last surviving record.
    ///
    /// Recomputing rather than decrementing is deliberate. This runs only
    /// after damage, where the stored counters are exactly the thing that
    /// might already be wrong.
    pub(crate) fn repair_segment_to_length(
        &self,
        segment_id: u64,
        file_len: u64,
    ) -> Result<u64, StorageError> {
        self.db
            .write_immediate(|tx| {
                let dropped = tx.execute(
                    "DELETE FROM blocks WHERE segment_id = ?1 \
                     AND record_offset + record_len > ?2",
                    rusqlite::params![segment_id as i64, file_len as i64],
                )?;
                let (blocks, payload, record, end): (i64, i64, i64, i64) = tx.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(payload_len), 0), \
                     COALESCE(SUM(record_len), 0), \
                     COALESCE(MAX(record_offset + record_len), ?2) \
                     FROM blocks WHERE segment_id = ?1",
                    rusqlite::params![segment_id as i64, SEGMENT_HEADER_LEN as i64],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
                tx.execute(
                    "UPDATE segments SET live_blocks = ?2, live_payload_bytes = ?3, \
                     live_record_bytes = ?4, durable_end = ?5 WHERE segment_id = ?1",
                    rusqlite::params![segment_id as i64, blocks, payload, record, end],
                )?;
                Ok(dropped as u64)
            })
            .map_err(to_storage)
    }

    /// Retires a segment that holds nothing live. Guarded on
    /// `live_blocks = 0` inside the transaction so a block that landed
    /// between the decision and the write keeps its segment alive.
    pub(crate) fn retire_empty_segment(&self, segment_id: u64) -> Result<(), StorageError> {
        self.db
            .write(|conn| {
                conn.execute(
                    "UPDATE segments SET state = ?2 WHERE segment_id = ?1 AND live_blocks = 0 \
                     AND state != ?3",
                    rusqlite::params![
                        segment_id as i64,
                        SegmentState::Retired.as_str(),
                        SegmentState::Active.as_str()
                    ],
                )?;
                Ok::<_, DatabaseError>(())
            })
            .map_err(to_storage)
            .map(|_| ())
    }

    /// Forgets a retired segment entirely, once its file is gone.
    pub(crate) fn forget_segment(&self, segment_id: u64) -> Result<(), StorageError> {
        self.db
            .write_immediate(|tx| {
                tx.execute("DELETE FROM blocks WHERE segment_id = ?1", [segment_id as i64])?;
                tx.execute("DELETE FROM segments WHERE segment_id = ?1", [segment_id as i64])?;
                Ok(())
            })
            .map_err(to_storage)
    }
}

/// The no-op crash hook a test that is not injecting anything passes.
#[cfg(test)]
fn no_injected_fault() -> Option<String> {
    None
}

/// Converts a stored key back into a fixed-width raw hash, refusing any
/// row whose key is not exactly the expected width rather than silently
/// padding or truncating it.
fn raw_hash(raw: &[u8]) -> Result<[u8; RAW_HASH_LEN], StorageError> {
    <[u8; RAW_HASH_LEN]>::try_from(raw).map_err(|_| {
        StorageError::CorruptStore(format!(
            "block index holds a {}-byte key where {RAW_HASH_LEN} bytes are required",
            raw.len()
        ))
    })
}

/// The inclusive raw-key range covering every hash whose hex encoding
/// starts with `prefix`. An odd-length prefix constrains only the high
/// nibble of its final byte, which is why the bounds are built nibble-wise
/// rather than from a plain `hex::decode`.
fn raw_key_range_for_hex_prefix(
    prefix: &str,
) -> Result<([u8; RAW_HASH_LEN], [u8; RAW_HASH_LEN]), StorageError> {
    if prefix.len() > RAW_HASH_LEN * 2 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(StorageError::InvalidPath(format!("not a valid hex prefix: {prefix:?}")));
    }
    let mut low = [0x00u8; RAW_HASH_LEN];
    let mut high = [0xFFu8; RAW_HASH_LEN];
    for (nibble_index, ch) in prefix.chars().enumerate() {
        let value = ch.to_digit(16).expect("hex digit, just validated") as u8;
        let byte = nibble_index / 2;
        if nibble_index % 2 == 0 {
            low[byte] = value << 4;
            high[byte] = (value << 4) | 0x0F;
        } else {
            low[byte] |= value;
            high[byte] = (high[byte] & 0xF0) | value;
        }
    }
    Ok((low, high))
}

#[cfg(test)]
mod tests;
