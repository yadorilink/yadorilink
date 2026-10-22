//! The `files` rows of brand-new paths, written in their final form.
//!
//! A capture that puts a file at a path this replica has never known runs the same chain per
//! file as an edit of an existing one: the version insert, the metadata update, the hydration
//! stamp and the re-read that checks the row shows the head it was produced from. For a path with
//! no earlier row, no hold, no native head, every one of
//! those is determined before the first statement runs, so a chunk of such paths is written as
//! one multi-row insert of the finished rows (and one multi-row authoring witness), and checked
//! once, set-based, afterwards. Everything else stays on the per-path chain.

use std::collections::HashSet;

use rusqlite::Connection;

use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::native_plan::NativeRowIdentity;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, MaterializationState};

use crate::error::SyncSqliteError;
use crate::file_index::{encode_unix_mode_column, encode_xattrs_column, now_unix_nanos_checked};
use crate::store::PATHS_PER_QUERY;

/// Rows one insert binds: ten parameters each, under SQLite's variable limit.
const ROWS_PER_INSERT: usize = 100;

/// A path put as a new file: what the finished row and its witness are written from.
pub(crate) struct NewPathRow<'a> {
    pub record: &'a FileRecord,
    pub meta: &'a LocalFileMetaColumns,
    pub identity: &'a NativeRowIdentity,
}

/// Whether the new-path insert may be used; a test turns it off to run the per-path chain over the
/// same mutations and compare.
pub(crate) fn enabled() -> bool {
    #[cfg(test)]
    {
        !tests_support::ROWS_DISABLED.with(|flag| flag.get())
    }
    #[cfg(not(test))]
    {
        true
    }
}

/// Whether the proofs and obligation closes of new paths may be written in batches from what the
/// authoring holds; a test turns it off for the same comparison.
pub(crate) fn settlement_enabled() -> bool {
    #[cfg(test)]
    {
        !tests_support::SETTLEMENT_DISABLED.with(|flag| flag.get())
    }
    #[cfg(not(test))]
    {
        true
    }
}

/// The paths of `paths` that are new in every respect the insert relies on: no `files` row of any
/// version (the metadata scaffold included), no hold, no native head, and no placement, binding or
/// kept copy naming the path. One query per table and chunk of paths.
///
/// Read BEFORE the paths' heads are authored: the check is that nothing was there, and authoring
/// is what puts the first head.
pub(crate) fn brand_new_paths(
    conn: &Connection,
    group_id: &str,
    paths: &[&str],
) -> Result<HashSet<String>, SyncSqliteError> {
    let mut fresh = HashSet::with_capacity(paths.len());
    for chunk in paths.chunks(PATHS_PER_QUERY) {
        let mut taken: HashSet<String> = HashSet::new();
        for (table, column) in TABLES_NAMING_A_PATH {
            let marks = vec!["?"; chunk.len()].join(",");
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {column} FROM {table} WHERE group_id = ?1 AND {column} IN ({marks})"
            ))?;
            let params = std::iter::once(group_id).chain(chunk.iter().copied());
            let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
            while let Some(row) = rows.next()? {
                taken.insert(row.get(0)?);
            }
        }
        fresh.extend(chunk.iter().filter(|path| !taken.contains(**path)).map(|p| p.to_string()));
    }
    Ok(fresh)
}

/// Every table and column whose rows a path of the new-path insert must not appear in.
const TABLES_NAMING_A_PATH: [(&str, &str); 3] =
    [("files", "path"), ("held_paths", "path"), ("native_heads", "path")];

/// Writes the finished `files` row of every entry of `rows`, with the authoring witness each cites,
/// and then checks, set-based, that each row shows the version of the head it was produced from.
/// The rows are what a per-path insert, metadata update and hydration stamp would leave for a
/// path with no earlier row: version 1, current, `Present`, every column the record does not
/// carry at its default.
pub(crate) fn insert_hydrated_rows(
    tx: &Connection,
    group_id: &str,
    origin_device_id: &str,
    rows: &[NewPathRow<'_>],
) -> Result<(), SyncSqliteError> {
    if rows.is_empty() {
        return Ok(());
    }
    #[cfg(test)]
    tests_support::ROWS_WRITTEN.with(|n| n.set(n.get() + rows.len()));
    record_witnesses(tx, group_id, rows)?;
    let origin: Option<&str> =
        if origin_device_id.is_empty() { None } else { Some(origin_device_id) };
    // One reading for the whole chunk: the rows are one admission.
    let admitted_at_unix_nanos = now_unix_nanos_checked();
    for chunk in rows.chunks(ROWS_PER_INSERT) {
        let values: Vec<String> = (0..chunk.len())
            .map(|i| {
                let b = 5 + 12 * i;
                format!(
                    "(?1, ?{}, ?{}, ?{}, ?{}, 0, 1, 'current', ?2, ?3, ?{}, ?4, ?{}, ?{}, ?{}, \
                     ?{}, ?{}, ?{}, ?{})",
                    b,
                    b + 1,
                    b + 2,
                    b + 3,
                    b + 4,
                    b + 5,
                    b + 6,
                    b + 7,
                    b + 8,
                    b + 9,
                    b + 10,
                    b + 11
                )
            })
            .collect();
        let mut stmt = tx.prepare_cached(&format!(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
             version_seq, state, origin_device_id, admitted_at_unix_nanos, \
             native_authoring_identity, materialization_state, record_kind, symlink_target, \
             symlink_out_of_root, unix_mode, xattrs_json, case_fold_key, canonical_fold_key) \
             VALUES {}",
            values.join(", ")
        ))?;
        let mut params: Vec<rusqlite::types::Value> = Vec::with_capacity(4 + 12 * chunk.len());
        params.push(group_id.to_owned().into());
        params.push(origin.map(str::to_owned).into());
        params.push(admitted_at_unix_nanos.into());
        params.push(MaterializationState::Present.as_db_str().to_owned().into());
        for row in chunk {
            params.push(row.record.path.clone().into());
            let size = i64::try_from(row.record.size)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            params.push(size.into());
            params.push(row.record.mtime_unix_nanos.into());
            params.push(serde_json::to_string(&row.record.blocks)?.into());
            params.push(row.identity.to_bytes().into());
            params.push(row.meta.record_kind.as_db_str().to_owned().into());
            params.push(row.meta.symlink_target.clone().into());
            params.push((row.meta.symlink_out_of_root as i64).into());
            params.push(encode_unix_mode_column(row.meta.unix_mode).into());
            params.push(encode_xattrs_column(&row.meta.xattrs).into());
            let (case_key, canonical_key) = crate::file_index::name_fold_keys(&row.record.path);
            params.push(case_key.into());
            params.push(canonical_key.into());
        }
        stmt.execute(rusqlite::params_from_iter(params))?;
    }
    require_rows_show_native_heads(tx, group_id, rows)
}

/// The authoring witness of each row's identity, from the head it names, in one statement per
/// chunk. A row whose head is not live gets none, and the authoring trigger refuses it.
fn record_witnesses(
    tx: &Connection,
    group_id: &str,
    rows: &[NewPathRow<'_>],
) -> Result<(), SyncSqliteError> {
    for chunk in rows.chunks(ROWS_PER_INSERT) {
        let values: Vec<String> = (0..chunk.len())
            .map(|i| {
                let b = 2 + 6 * i;
                format!("(?{}, ?{}, ?{}, ?{}, ?{}, ?{})", b, b + 1, b + 2, b + 3, b + 4, b + 5)
            })
            .collect();
        let values = values.join(", ");
        let mut stmt = tx.prepare_cached(&format!(
            "INSERT OR IGNORE INTO native_authoring_witness (group_id, identity, version) \
             WITH v(identity, path, author, incarnation, seq, provenance) AS (VALUES {values}) \
             SELECT ?1, v.identity, h.version FROM v CROSS JOIN native_heads h \
             ON h.group_id = ?1 AND h.path = v.path AND h.author = v.author \
             AND h.incarnation = v.incarnation AND h.seq = v.seq AND h.provenance = v.provenance"
        ))?;
        let mut params: Vec<rusqlite::types::Value> = Vec::with_capacity(1 + 6 * chunk.len());
        params.push(group_id.to_owned().into());
        for row in chunk {
            let identity = row.identity;
            params.push(identity.to_bytes().into());
            params.push(identity.source_path.as_str().to_owned().into());
            params.push(identity.dot.author.device.0.clone().into());
            params.push(identity.dot.author.incarnation.0.to_vec().into());
            params.push((identity.dot.seq.get() as i64).into());
            params.push(identity.provenance.0.to_vec().into());
        }
        stmt.execute(rusqlite::params_from_iter(params))?;
    }
    Ok(())
}

/// [`crate::file_index::require_row_shows_native_head`] for every row of `rows`: the current row
/// at each path is read back with its witness, and refused when it shows another version than the
/// head it cites.
fn require_rows_show_native_heads(
    tx: &Connection,
    group_id: &str,
    rows: &[NewPathRow<'_>],
) -> Result<(), SyncSqliteError> {
    let paths: Vec<&str> = rows.iter().map(|row| row.record.path.as_str()).collect();
    let current = crate::store::read_canonical_current_rows(tx, group_id, &paths)?;
    let mut recorded: std::collections::HashMap<Vec<u8>, Vec<u8>> =
        std::collections::HashMap::with_capacity(rows.len());
    for chunk in rows.chunks(PATHS_PER_QUERY) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = tx.prepare_cached(&format!(
            "SELECT identity, version FROM native_authoring_witness \
             WHERE group_id = ?1 AND identity IN ({marks})"
        ))?;
        let params = std::iter::once(rusqlite::types::Value::from(group_id.to_owned()))
            .chain(chunk.iter().map(|row| row.identity.to_bytes().into()));
        let mut found = stmt.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = found.next()? {
            recorded.insert(row.get(0)?, row.get(1)?);
        }
    }
    for row in rows {
        let path = row.record.path.as_str();
        let Some(current) = current.get(path) else { continue };
        if current.snapshot.deleted {
            continue;
        }
        crate::file_index::refuse_row_not_showing_head(
            path,
            current,
            recorded.get(&row.identity.to_bytes()).map(Vec::as_slice),
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests_support {
    use std::cell::Cell;

    thread_local! {
        pub(crate) static ROWS_DISABLED: Cell<bool> = const { Cell::new(false) };
        pub(crate) static SETTLEMENT_DISABLED: Cell<bool> = const { Cell::new(false) };
        /// New-path rows written finished, and proofs published in batches, on this thread.
        pub(crate) static ROWS_WRITTEN: Cell<usize> = const { Cell::new(0) };
        pub(crate) static PROOFS_BATCHED: Cell<usize> = const { Cell::new(0) };
        /// Whether the batched settlement checks, in tests, the facts it took from memory against
        /// the database (a measurement turns it off: the checks are statements too).
        pub(crate) static CROSS_CHECK_OFF: Cell<bool> = const { Cell::new(false) };
    }

    /// Runs `body` without the settlement's own cross-check against the database.
    pub(crate) fn without_cross_check<T>(body: impl FnOnce() -> T) -> T {
        let before = CROSS_CHECK_OFF.with(|flag| flag.replace(true));
        let out = body();
        CROSS_CHECK_OFF.with(|flag| flag.set(before));
        out
    }

    /// Runs `body` with the new-path insert and the batched settlement both off.
    pub(crate) fn without<T>(body: impl FnOnce() -> T) -> T {
        let rows = ROWS_DISABLED.with(|flag| flag.replace(true));
        let settlement = SETTLEMENT_DISABLED.with(|flag| flag.replace(true));
        let out = body();
        ROWS_DISABLED.with(|flag| flag.set(rows));
        SETTLEMENT_DISABLED.with(|flag| flag.set(settlement));
        out
    }

    /// Runs `body` with only the batched settlement off.
    pub(crate) fn without_settlement<T>(body: impl FnOnce() -> T) -> T {
        let before = SETTLEMENT_DISABLED.with(|flag| flag.replace(true));
        let out = body();
        SETTLEMENT_DISABLED.with(|flag| flag.set(before));
        out
    }
}
