//! Folder Rewind's read-only planning layer: given a group and a wall-clock
//! target T, computes the deterministic [`RewindPlan`] describing what would
//! have to change, per path, to bring the group's desired state back to what
//! this device held at T.
//!
//! Read-only in the strongest sense. Nothing in this module emits a signed
//! `NativeDelta`, writes to the filesystem, creates a projection or
//! materialization obligation, or touches native admission in any way. It runs
//! a fixed handful of `SELECT`s and does arithmetic on the rows.
//!
//! # Why this does not replay native history
//!
//! A group's head-set at T is a GROUP-level answer. Turning one into "what
//! should path X contain at T" requires resolving that path against a
//! historical frontier -- a per-path history walk, which is expensive at
//! 100k-file scale, and across every path in a whole-folder rewind would
//! make plan computation proportional to the group's history.
//!
//! So the plan is computed from `files.admitted_at_unix_nanos` instead --
//! a plain, unindexed, per-row local timestamp that every writer of a
//! `files` row stamps (see `file_index::upsert_file_in_tx`'s own doc
//! comment for the enumerated set and the invariant it upholds). Every
//! query below is a single `WHERE group_id = ?1` scan producing one row per
//! path; none is issued per path, and there is no history traversal anywhere
//! in this file. Their number is fixed -- it does not grow with the group's
//! path count, its history depth, or the rewind distance.
//!
//! There is deliberately no index on `admitted_at_unix_nanos` itself. These
//! queries read every row of one group and rank within each path, which the
//! `(group_id, path, version_seq)` primary key already clusters correctly;
//! a secondary index would add write cost to the same per-path admission
//! hot path this design exists to keep clear of, and buy nothing a
//! group-scoped scan does not already have.
//! `rewind_plan_scale_benchmark.rs` measures the resulting shape (linear in
//! the group's own path count, flat against everything else) rather than
//! assuming it.

use std::collections::HashMap;

use rusqlite::Connection;

use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::rewind::{
    RewindPathAction, RewindPathEntry, RewindPlan, RewindRenameCandidate, RewindUnavailableReason,
};
use yadorilink_replica_domain::session_state::VersionRecord;

use crate::error::SyncSqliteError;
use crate::file_index::version_record;

/// The column list every row-shaped query below selects, in the exact order
/// [`row_to_version_record`] reads it. Shared so the two full-row queries
/// cannot drift apart in shape.
const VERSION_ROW_COLUMNS: &str = "path, version_seq, size, mtime_unix_nanos, blocks_json, \
                                   deleted, state, origin_device_id, record_kind, \
                                   symlink_target, unix_mode, xattrs_json";

/// Decodes one `VERSION_ROW_COLUMNS`-shaped row into a [`VersionRecord`],
/// deriving its `version_hash` through the same
/// `FileVersion::from_index_row` path every other version identity in this
/// crate comes from -- so a hash compared here is the canonical one, never
/// a value re-derived from a different subset of columns.
fn row_to_version_record(row: &rusqlite::Row<'_>) -> Result<VersionRecord, rusqlite::Error> {
    let path: String = row.get(0)?;
    let version_seq: i64 = row.get(1)?;
    let size: u64 = row.get(2)?;
    let mtime_unix_nanos: i64 = row.get(3)?;
    let blocks_json: String = row.get(4)?;
    let deleted: i64 = row.get(5)?;
    let state: String = row.get(6)?;
    let origin_device_id: Option<String> = row.get(7)?;
    let record_kind: String = row.get(8)?;
    let symlink_target: Option<Vec<u8>> = row.get(9)?;
    let unix_mode: i64 = row.get(10)?;
    let xattrs_json: String = row.get(11)?;
    // `version_record` fails closed on a corrupt `blocks_json`/`xattrs_json`
    // column. Surfaced through rusqlite's own callback error channel so a
    // corrupt row aborts the whole listing rather than being skipped -- a
    // plan built from a partially-decoded index would be silently wrong,
    // which is worse than a hard, diagnosable failure.
    version_record(
        path,
        version_seq,
        size,
        mtime_unix_nanos,
        &blocks_json,
        deleted,
        &state,
        origin_device_id,
        &record_kind,
        symlink_target,
        unix_mode,
        &xattrs_json,
    )
    .map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

/// Every path's `state = 'current'` row for `group_id`, as one scan.
///
/// Every path this device indexes for this group right now, tombstones
/// included: retention only ever expires `superseded`/`trashed` rows (see
/// `FileIndexRepository::expire_superseded_and_trashed_versions`), and a
/// deleted path's `current` row becomes a tombstone rather than
/// disappearing. It is NOT every path this device has ever indexed: the
/// ignore sweep erases all rows of a path
/// (`FileIndexRepository::remove_file`), and a path erased and never
/// indexed again has no row here. [`erased_unindexed_paths`] lists those,
/// and [`compute_rewind_plan`] adds them to the plan's universe.
///
/// Carries full version identity, which `FileIndexRepository::list_files`
/// (the other reader of this same row set) deliberately does not: its
/// `FileRecord` has no `version_seq` and no `version_hash`, and rebuilding
/// those afterwards would mean one follow-up lookup per path -- precisely
/// the per-path query shape this module exists to avoid.
fn current_rows(conn: &Connection, group_id: &str) -> Result<Vec<VersionRecord>, SyncSqliteError> {
    let sql = format!(
        "SELECT {VERSION_ROW_COLUMNS} FROM files \
         WHERE group_id = ?1 AND state = 'current' ORDER BY path"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([group_id], row_to_version_record)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// The `current` rows of `paths` (tombstones included), keyed by path: the
/// rows [`current_rows`] would return for them, read in the caller's
/// transaction. A rewind's commit compares them with its plan.
pub(crate) fn current_rows_at(
    conn: &Connection,
    group_id: &str,
    paths: &[&str],
) -> Result<HashMap<String, VersionRecord>, SyncSqliteError> {
    let mut out = HashMap::with_capacity(paths.len());
    for chunk in paths.chunks(crate::store::PATHS_PER_QUERY) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {VERSION_ROW_COLUMNS} FROM files \
             WHERE group_id = ?1 AND state = 'current' AND path IN ({marks})"
        ))?;
        let params = std::iter::once(group_id).chain(chunk.iter().copied());
        let rows = stmt.query_map(rusqlite::params_from_iter(params), row_to_version_record)?;
        for row in rows {
            let row = row?;
            out.insert(row.path.clone(), row);
        }
    }
    Ok(out)
}

/// The retained row `version_seq` of `path`, whatever its state.
pub(crate) fn version_row(
    conn: &Connection,
    group_id: &str,
    path: &str,
    version_seq: i64,
) -> Result<Option<VersionRecord>, SyncSqliteError> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .prepare_cached(&format!(
            "SELECT {VERSION_ROW_COLUMNS} FROM files \
             WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3"
        ))?
        .query_row(rusqlite::params![group_id, path, version_seq], row_to_version_record)
        .optional()?)
}

/// The version of each path that was this device's current one at
/// `at_unix_nanos`: for every path, the most recently admitted row at or
/// before that instant. One row per path, one indexed scan.
///
/// Uses the same `ROW_NUMBER() OVER (PARTITION BY path ORDER BY ...)`
/// shape `expire_superseded_and_trashed_versions` already establishes over
/// this table -- same partition, same "rank 1 is the one I want" reading,
/// with the ordering column swapped from `version_seq` to
/// `admitted_at_unix_nanos` and the filter narrowed to the rewind target.
///
/// `version_seq DESC` is a tie-break, not decoration, and it is load-
/// bearing in two distinct situations. Two rows for one path can share an
/// `admitted_at_unix_nanos` when the clock's granularity is coarser than
/// the gap between two writes. Without a
/// second ordering key the winner would be arbitrary, making
/// the plan nondeterministic for that path. `version_seq` is strictly
/// increasing per path, and the `current` row holds its maximum (maintained
/// by `file_index::upsert_file_in_tx`, whose supersede-then-insert pair
/// flips the prior `current` row to `superseded`/`trashed` and inserts the
/// new one at `old_seq + 1`, and preserved by a snapshot built from an index
/// that already satisfies it), so it is the correct total
/// secondary order and resolves a whole-history tie to exactly the row the
/// "now" side is comparing against.
///
/// A row whose `admitted_at_unix_nanos` is NULL is excluded here (SQL
/// `NULL <= ?2` is not true), which is deliberate: an unknown admission
/// time is not evidence of anything, and the caller turns its absence into
/// an explicit [`RewindPathAction::Unavailable`] rather than a guess.
fn rows_at_or_before(
    conn: &Connection,
    group_id: &str,
    at_unix_nanos: i64,
) -> Result<Vec<VersionRecord>, SyncSqliteError> {
    let sql = format!(
        "SELECT {VERSION_ROW_COLUMNS} FROM (
             SELECT {VERSION_ROW_COLUMNS},
                    ROW_NUMBER() OVER (
                        PARTITION BY path
                        ORDER BY admitted_at_unix_nanos DESC, version_seq DESC
                    ) AS rnk
             FROM files
             WHERE group_id = ?1 AND admitted_at_unix_nanos <= ?2
         )
         WHERE rnk = 1 ORDER BY path"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params![group_id, at_unix_nanos], row_to_version_record)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Per-path evidence about what history this device still *has*, for the
/// paths [`rows_at_or_before`] found nothing for. One grouped scan.
///
/// `min_version_seq` distinguishes the two very different reasons a path can
/// have no row at or before T:
///
/// * the path's own first-ever version (`version_seq` 1, or the transient
///   `0` bootstrap scaffold) was admitted after T -- the path genuinely did
///   not exist yet, which is a real answer, not a gap; versus
/// * the earliest row this device still holds is already a later version,
///   so whatever came before it is not here to answer with. Two different
///   causes produce that, and the reported reason must not claim to know
///   which: retention expired the earlier versions
///   (`expire_superseded_and_trashed_versions`), or this device never held
///   them in the first place -- it joined the group late, and its local
///   history for this path simply starts above version 1.
///
/// Both readings are about THIS device's own admission history, which is
/// what makes them meaningful, and both stop being about it below the
/// group's local history floor ([`local_history_floor`]) -- below which the
/// numbering in `files` began on someone else's terms, because this
/// device joined an existing group. [`classify_without_history`] tests that boundary before
/// it reads either one.
///
/// `history_erased` is set when this device once erased every row of the
/// path ([`record_path_history_erased`]). Its numbering then restarted at 1,
/// so `min_version_seq` no longer says anything about the path's own first
/// version; [`classify_without_history`] tests it before reading
/// `min_version_seq`.
///
/// `unstamped_rows` counts rows with no admission timestamp at all. Any such
/// row makes this path's history unreadable for rewind purposes regardless
/// of `min_version_seq`, since an unstamped row could have been the one at
/// T.
///
/// This is only consulted when [`rows_at_or_before`] found nothing, and
/// that is sufficient rather than merely convenient: unstamped rows can
/// only ever be a PREFIX of a path's version history. The column is
/// NULL exactly for rows written before it existed -- every writer of a
/// `files` row stamps it (see `file_index::upsert_file_in_tx`'s "stamping
/// invariant" section) -- so a stamped row is always newer than every
/// unstamped one for the same path. It follows that whenever a stamped row
/// at or before T exists, it really is the newest version at or before T --
/// no unstamped row can be hiding in between.
struct PathHistoryFloor {
    min_version_seq: i64,
    unstamped_rows: i64,
    history_erased: bool,
}

fn history_floors(
    conn: &Connection,
    group_id: &str,
) -> Result<HashMap<String, PathHistoryFloor>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT f.path, MIN(f.version_seq), \
                SUM(CASE WHEN f.admitted_at_unix_nanos IS NULL THEN 1 ELSE 0 END), \
                EXISTS (SELECT 1 FROM path_local_history_erased e \
                        WHERE e.group_id = ?1 AND e.path = f.path) \
         FROM files f WHERE f.group_id = ?1 GROUP BY f.path",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            PathHistoryFloor {
                min_version_seq: r.get(1)?,
                unstamped_rows: r.get(2)?,
                history_erased: r.get(3)?,
            },
        ))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (path, floor) = row?;
        out.insert(path, floor);
    }
    Ok(out)
}

/// Records `floor_unix_nanos` as the instant this device's own *continuous*
/// local `files` history for `group_id` begins -- the single writer of
/// `group_local_history_floor`, shared by both of the events that can start
/// one (see that table's own comment for the pair).
///
/// One statement, no read-back, no derivation: the caller already holds the
/// instant, because in both cases it is the same clock read the event itself
/// is stamped from. Must be called inside the caller's own transaction, so
/// the floor and whatever the event writes alongside it commit together or
/// not at all -- a committed boundary event with no floor is precisely the
/// state the floor exists to prevent.
///
/// A later floor always replaces an earlier one (`ON CONFLICT DO UPDATE`),
/// because only the most recent boundary bounds the history that actually
/// survives, and a floor is only ever moved FORWARD in practice -- every
/// caller passes a fresh clock read. Moving a floor forward can only make a
/// later answer more conservative, never more confident, which is the safe
/// direction for the one thing this value is read for.
pub(crate) fn record_local_history_floor(
    conn: &Connection,
    group_id: &str,
    floor_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT INTO group_local_history_floor (group_id, floor_unix_nanos) \
         VALUES (?1, ?2) \
         ON CONFLICT(group_id) DO UPDATE SET floor_unix_nanos = excluded.floor_unix_nanos",
        rusqlite::params![group_id, floor_unix_nanos],
    )?;
    Ok(())
}

/// Records the current instant as `group_id`'s local history floor when
/// this device is linking that group without already holding any of its
/// files -- the "my numbering for this group is about to start from
/// scratch" case, which is what the floor exists to bound.
///
/// Every link commit for a group this device did not originate itself goes
/// through here: the enrollment path's `Join` marker, and the plain link
/// commit that `share accept` and `yadorilink link` use (which carries no
/// marker at all, so the group it names -- resolved from an invite, or from
/// the account's shared-folder listing -- can have arbitrary history behind
/// it). Deliberately NOT reached by a locally originated folder: that
/// commits through the enrollment path with a `Create` marker, whose
/// `version_seq = 1` rows really are this device's own first admissions.
///
/// The "holds no rows yet" test is what keeps this precise rather than
/// merely cautious. Re-linking a folder this device already has an index
/// for -- an unlink followed by a link, or a repeated `share accept` --
/// does NOT restart `version_seq`: `upsert_file_in_tx` numbers up from the
/// rows already there (there is no whole-group `DELETE FROM files`). Moving the floor
/// forward in that case would throw away real, answerable history for no
/// gain, so this writes nothing.
///
/// A clock that cannot be read at all (before the Unix epoch) writes no
/// floor and leaves any earlier one in place: rows admitted by such a device carry no admission stamp either,
/// which the reader already reports as unanswerable on its own.
///
/// Must be called inside the caller's own link-commit transaction -- see
/// [`record_local_history_floor`].
pub(crate) fn record_local_history_floor_for_a_first_link(
    conn: &Connection,
    group_id: &str,
) -> Result<(), SyncSqliteError> {
    let already_holds_rows: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM files WHERE group_id = ?1)",
        [group_id],
        |row| row.get(0),
    )?;
    if already_holds_rows {
        return Ok(());
    }
    let Some(floor_unix_nanos) = crate::file_index::now_unix_nanos_checked() else {
        return Ok(());
    };
    record_local_history_floor(conn, group_id, floor_unix_nanos)
}

/// The instant this group's *continuous* local `files` history begins on
/// this device, if anything has ever started that history somewhere other
/// than at this device's own first observation of each path. `None` -- a
/// group this device created locally -- means
/// nothing has, so the history in `files` runs unbroken back to whatever
/// this device first indexed.
///
/// At most one row per group, written by [`record_local_history_floor`] when
/// this device links a group it did not originate and holds no files for yet
/// (both link commits that can name one, via
/// [`record_local_history_floor_for_a_first_link`]). See
/// `group_local_history_floor`'s own table comment.
///
/// A single-row primary-key lookup and nothing else -- deliberately not a
/// derivation, and specifically not anything that replays native history.
/// [`classify_without_history`] compares the rewind target against this
/// value and that comparison is the entire use of it.
fn local_history_floor(conn: &Connection, group_id: &str) -> Result<Option<i64>, SyncSqliteError> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .query_row(
            "SELECT floor_unix_nanos FROM group_local_history_floor WHERE group_id = ?1",
            [group_id],
            |row| row.get(0),
        )
        .optional()?)
}

/// Records that this device has just erased every `files` row of `path`
/// (see `path_local_history_erased`'s table comment). Must be called inside
/// the erasing transaction, so the erasure never commits without it: an
/// erased path with no record is exactly the state in which a later
/// re-index from `version_seq = 1` reads as "created after the target".
///
/// Stamps the erasure with this device's clock, never earlier than
/// `newest_erased_admission` (the latest admission stamp among the erased
/// rows), so a clock that stepped back cannot date the erasure before
/// history it took away. A later erasure of the same path replaces the
/// stamp. A clock that cannot be read stores `i64::MAX`, so every target
/// reads as before the erasure (unanswerable), never after.
pub(crate) fn record_path_history_erased(
    conn: &Connection,
    group_id: &str,
    path: &str,
    newest_erased_admission: Option<i64>,
) -> Result<(), SyncSqliteError> {
    let now = crate::file_index::now_unix_nanos_checked().unwrap_or(i64::MAX);
    let erased_at = now.max(newest_erased_admission.unwrap_or(i64::MIN));
    record_path_history_erased_at(conn, group_id, path, erased_at)
}

fn record_path_history_erased_at(
    conn: &Connection,
    group_id: &str,
    path: &str,
    erased_at_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT INTO path_local_history_erased (group_id, path, erased_at_unix_nanos) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(group_id, path) DO UPDATE SET \
             erased_at_unix_nanos = excluded.erased_at_unix_nanos",
        rusqlite::params![group_id, path, erased_at_unix_nanos],
    )?;
    Ok(())
}

/// The paths whose rows this device erased after `at_unix_nanos` and that
/// it has not indexed again since: no `files` row at all, so
/// [`current_rows`] does not see them. At the target each was held here,
/// and nothing records what it held. One scan of the erasure records,
/// sorted by path.
///
/// A path erased at or before the target is not listed: then it had no
/// entry here at the target and has none now, which is absent on both
/// sides.
pub fn erased_unindexed_paths(
    conn: &Connection,
    group_id: &str,
    at_unix_nanos: i64,
) -> Result<Vec<String>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT e.path FROM path_local_history_erased e \
         WHERE e.group_id = ?1 AND e.erased_at_unix_nanos > ?2 \
           AND NOT EXISTS (SELECT 1 FROM files f WHERE f.group_id = ?1 AND f.path = e.path) \
         ORDER BY e.path",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id, at_unix_nanos], |r| r.get(0))?;
    Ok(rows.collect::<Result<Vec<String>, _>>()?)
}

/// Computes the read-only [`RewindPlan`] for `group_id` at `at_unix_nanos`.
///
/// # What the plan covers
///
/// Exactly the paths this device has itself indexed for this group at least
/// once -- no more and no less. A path that exists in the group but that
/// this device has never observed (an ordinary situation for a partial
/// replica, or for a device that joined after the path was already deleted)
/// does not appear in the plan at all, on either side. That is the correct
/// outcome, not a gap: this device has no basis on which to say anything
/// about a path it never held. It is called out explicitly because the
/// absence is easy to misread -- a caller must NOT interpret "not in the
/// plan" as "unchanged". The plan describes what THIS device would do to
/// ITS OWN desired state.
///
/// # How each path is classified
///
/// The "now" side is every path's `current` row; the "at T" side is the
/// most recently admitted row at or before `at_unix_nanos`. With both in
/// hand, per path:
///
/// * present at T, absent now -> [`RewindPathAction::Create`]
/// * absent at T, present now -> [`RewindPathAction::Delete`]
/// * present in both with different `version_hash` -> [`RewindPathAction::Replace`]
/// * present in both with the same `version_hash`, or absent in both ->
///   [`RewindPathAction::Unchanged`]
/// * no readable evidence about T -> [`RewindPathAction::Unavailable`]
///
/// "Absent" means a tombstone (`deleted = 1`) or no row, uniformly on both
/// sides.
///
/// [`RewindPathAction::Unavailable`] is an honest classification and never
/// a fallback: a rewind target older than a path's surviving history has no
/// answer for that path, and the plan says so rather than substituting the
/// closest version it can still see or quietly reporting `Unchanged`. Three
/// things produce it:
///
/// * history expired by retention (`RETENTION_MAX_VERSIONS` versions OR
///   `RETENTION_MAX_AGE_DAYS` days, union-retain/intersection-expire; see
///   `FileIndexRepository::expire_superseded_and_trashed_versions`);
/// * history this device never held -- it joined the group after the path
///   already had versions. That boundary is recorded, at the instant it
///   happens, by [`record_local_history_floor`]. A target before it is
///   genuinely unanswerable HERE, which is not the same as unanswerable
///   anywhere; a peer that holds the history can still answer it. (A target
///   AFTER that boundary is answered normally: every row admitted since
///   carries this device's own admission stamp, so it is ordinary
///   evidence.)
/// * history this device erased itself -- the path was excluded from sync
///   (`.yadorilinkignore`) and its rows dropped, then indexed again. That
///   is recorded per path by [`record_path_history_erased`]; the rows
///   admitted since are ordinary evidence, anything before them is gone.
/// * a row with no recorded admission timestamp -- only possible in a
///   database whose first-ever schema init crashed before the column
///   existed, since every writer stamps it.
///
/// A group with no admission history at all before `at_unix_nanos` is not a
/// special case in the code: every live path simply resolves to
/// [`RewindPathAction::Delete`], because nothing existed yet at T. (That is
/// the per-path counterpart of what
/// `dag_store::frontier_heads_at_or_before` reports as `None` for the
/// analogous group-level question -- a semantic parallel only; this
/// function does not call it, for the reasons in this module's own header.)
/// The one thing that turns that answer back into `Unavailable` is a group
/// whose own local history on this device did not yet exist at T -- it
/// joined the group after T
/// -- which is exactly what [`local_history_floor`] records. That
/// distinction is what keeps a freshly-joined device from reporting a
/// folder full of files as "everything was created since T".
///
/// # Cost
///
/// At most five group-scoped `SELECT`s total (two of them only when some
/// path has no row at or before the target, one of those a single-row
/// primary-key lookup; one over the erasure records alone), independent of
/// path count, plus O(paths) in-memory work. Nothing here is issued per
/// path, and nothing here walks native history.
///
/// # Paths erased and not indexed again
///
/// A path the ignore sweep erased after the target and that has no row now
/// ([`erased_unindexed_paths`]) existed here at the target, and nothing
/// says what it held: it is [`RewindPathAction::Unavailable`], so the
/// rewind is refused rather than silently leaving it out. The one
/// exception is a path `still_excluded` reports as excluded from sync
/// today: an excluded path is outside the plan like any other ignored path,
/// or ignoring a folder would block every rewind to before the ignore.
/// Such an entry has no current row, so its `current_version_seq` is `0`
/// and its `current_version_hash` all zeros.
pub fn compute_rewind_plan(
    conn: &Connection,
    group_id: &str,
    at_unix_nanos: i64,
    still_excluded: &dyn Fn(&str) -> bool,
) -> Result<RewindPlan, SyncSqliteError> {
    let now_rows = current_rows(conn, group_id)?;
    let at_t_rows = rows_at_or_before(conn, group_id, at_unix_nanos)?;

    let at_t: HashMap<&str, &VersionRecord> =
        at_t_rows.iter().map(|r| (r.path.as_str(), r)).collect();

    // Only paid for when some path actually has no row at or before T. In
    // the ordinary case -- a target inside every path's own retained
    // history -- the two queries above have already answered everything and
    // these two extra lookups are skipped entirely.
    let (floors, local_floor) = if now_rows.iter().any(|r| !at_t.contains_key(r.path.as_str())) {
        (history_floors(conn, group_id)?, local_history_floor(conn, group_id)?)
    } else {
        (HashMap::new(), None)
    };

    let mut entries = Vec::with_capacity(now_rows.len());
    // Content of the paths that would go away, and content of the paths that
    // would come back -- the two sides the rename heuristic pairs up. Built
    // during the same walk, so the heuristic costs no extra pass over the
    // database.
    let mut deleted_by_hash: HashMap<VersionHash, Vec<String>> = HashMap::new();
    let mut created_by_hash: HashMap<VersionHash, Vec<String>> = HashMap::new();

    for now in &now_rows {
        let action = match at_t.get(now.path.as_str()) {
            Some(then) => classify_with_history(now, then),
            None => classify_without_history(
                now,
                floors.get(now.path.as_str()),
                local_floor,
                at_unix_nanos,
            ),
        };
        match &action {
            RewindPathAction::Delete => {
                // The path is live now (a tombstone-now path can never be
                // classified `Delete`), so its current content is what a
                // rename would be moving FROM.
                deleted_by_hash.entry(now.version_hash).or_default().push(now.path.clone());
            }
            RewindPathAction::Create { version_hash, .. } => {
                created_by_hash.entry(*version_hash).or_default().push(now.path.clone());
            }
            _ => {}
        }
        entries.push(RewindPathEntry {
            path: now.path.clone(),
            current_version_seq: now.version_seq,
            current_version_hash: now.version_hash,
            action,
        });
    }

    let indexed = entries.len();
    for path in erased_unindexed_paths(conn, group_id, at_unix_nanos)? {
        if still_excluded(&path) {
            continue;
        }
        entries.push(RewindPathEntry {
            path,
            current_version_seq: 0,
            current_version_hash: VersionHash([0; 32]),
            // Dropped when the path was excluded from sync, and not
            // indexed since.
            action: RewindPathAction::Unavailable {
                reason: RewindUnavailableReason::ExcludedFromSync,
            },
        });
    }
    if entries.len() != indexed {
        entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    }

    Ok(RewindPlan {
        group_id: group_id.to_string(),
        target_unix_nanos: at_unix_nanos,
        rename_candidates: pair_renames(&deleted_by_hash, &created_by_hash),
        entries,
    })
}

/// Classifies a path this device has a readable "at T" row for.
fn classify_with_history(now: &VersionRecord, then: &VersionRecord) -> RewindPathAction {
    match (then.deleted, now.deleted) {
        // Absent both sides.
        (true, true) => RewindPathAction::Unchanged,
        // Absent at T, live now: the rewind would remove it again.
        (true, false) => RewindPathAction::Delete,
        // Live at T, absent now: the rewind would bring it back.
        (false, true) => RewindPathAction::Create {
            version_seq: then.version_seq,
            version_hash: then.version_hash,
        },
        // Live both sides -- content decides. Compared by `version_hash`,
        // not `version_seq`: a path edited and then edited back to its
        // earlier content has a higher `version_seq` but identical content,
        // and rewinding it would be a no-op, so it is honestly `Unchanged`.
        (false, false) => {
            if now.version_hash == then.version_hash {
                RewindPathAction::Unchanged
            } else {
                RewindPathAction::Replace {
                    to_version_seq: then.version_seq,
                    to_version_hash: then.version_hash,
                }
            }
        }
    }
}

/// Classifies a path with no readable row at or before T, using what this
/// device still knows about the path's own history floor -- and, first,
/// whether this device's own history for the whole GROUP even reaches back
/// to T.
///
/// `local_floor` is [`local_history_floor`]'s value for the group. The order
/// of the two checks is load-bearing. `min_version_seq <= 1` is read as
/// "this path's first-ever version was admitted after T, so at T it did not
/// exist here" -- a real answer, and the only inference in this module that
/// turns an ABSENCE of rows into a positive claim. That reading is only
/// sound while `version_seq` counts this device's own admissions from the
/// path's own beginning, and two ordinary events break that:
///
/// * this device JOINED an existing group. `upsert_file_in_tx` numbers every
///   path it sees for the first time from 1, so every file the group already
///   held when this device arrived -- however old, however often edited
///   elsewhere -- lands here as `version_seq = 1`.
///
/// `local_history_floor` below closes this. The inference
/// would otherwise report the never-modified majority of an
/// ordinary folder as having been created after T -- inventing information
/// rather than declining to give it. Below `local_floor` this device simply
/// has no history of its own to reason from, whatever any surviving row's
/// `version_seq` says, so the answer is [`RewindPathAction::Unavailable`]
/// and the `min_version_seq` inference is never reached.
///
/// * this device ERASED the path's rows. The ignore sweep
///   ([`FileIndexRepository::remove_file`](crate::file_index::FileIndexRepository::remove_file))
///   drops every row of a path that became excluded from sync; un-ignoring
///   it re-indexes it from `version_seq = 1`. The erasure is recorded per
///   path ([`record_path_history_erased`]), and for such a path a missing
///   row at T says nothing either -- at T the path either had rows that are
///   gone now or had no index entry here at all -- so the answer is again
///   [`RewindPathAction::Unavailable`].
fn classify_without_history(
    now: &VersionRecord,
    floor: Option<&PathHistoryFloor>,
    local_floor: Option<i64>,
    at_unix_nanos: i64,
) -> RewindPathAction {
    let unavailable = |reason| RewindPathAction::Unavailable { reason };
    let Some(floor) = floor else {
        // The grouped scan covers every row of this group, and `now` came
        // from that same table, so this is unreachable in practice. Report
        // it as unanswerable rather than assuming either way.
        return unavailable(RewindUnavailableReason::NoHistory);
    };
    if floor.unstamped_rows > 0 {
        return unavailable(RewindUnavailableReason::NoAdmissionTime);
    }
    if let Some(local_floor) = local_floor {
        // Checked ahead of `min_version_seq` for both of that value's
        // readings, not just the inference one: below this instant nothing
        // in `files` is this device's own observation, so "retention expired
        // the earlier versions" is not a possible cause here either and
        // naming it would be a wrong explanation rather than a cautious one.
        // The floor is set when this device joins a group it did not create
        // and when a re-establishment replaces its history wholesale; either
        // way another device may hold what this one does not.
        if at_unix_nanos < local_floor {
            return unavailable(RewindUnavailableReason::JoinedAfter);
        }
    }
    if floor.history_erased {
        return unavailable(RewindUnavailableReason::ExcludedFromSync);
    }
    if floor.min_version_seq <= 1 {
        // The path's first-ever version on this device was admitted after
        // T, so at T the path did not exist here. That is a real answer
        // only because neither a late join (checked above against
        // `local_floor`) nor an erasure of this path's rows (checked just
        // above) restarted the numbering.
        if now.deleted {
            RewindPathAction::Unchanged
        } else {
            RewindPathAction::Delete
        }
    } else {
        // This device's own history for the path starts above its first
        // version, and the target is not below the group's local history
        // floor: this device held the path's history continuously since
        // before T and numbered its versions from 1. The versions below the
        // earliest one left were therefore removed here, and with an erasure
        // ruled out above, retention is what removes rows.
        unavailable(RewindUnavailableReason::RemovedByRetention)
    }
}

/// Pairs the would-be-deleted and would-be-created paths that share content.
///
/// A pure in-memory `HashMap<VersionHash, _>` join over the two sets, with
/// no additional query. Only unambiguous pairs are emitted -- exactly one
/// path on each side for a given hash. Two files that coincidentally hold
/// identical content produce an ambiguous group, and guessing which one
/// "moved" would be inventing information; the affected paths keep their
/// own authoritative `Create`/`Delete` entries either way, which is why
/// dropping the guess costs nothing. Output is sorted for determinism.
fn pair_renames(
    deleted_by_hash: &HashMap<VersionHash, Vec<String>>,
    created_by_hash: &HashMap<VersionHash, Vec<String>>,
) -> Vec<RewindRenameCandidate> {
    let mut out = Vec::new();
    for (version_hash, from_paths) in deleted_by_hash {
        let Some(to_paths) = created_by_hash.get(version_hash) else { continue };
        if from_paths.len() != 1 || to_paths.len() != 1 {
            continue;
        }
        out.push(RewindRenameCandidate {
            from_path: from_paths[0].clone(),
            to_path: to_paths[0].clone(),
            version_hash: *version_hash,
        });
    }
    out.sort_by(|a, b| (&a.from_path, &a.to_path).cmp(&(&b.from_path, &b.to_path)));
    out
}

#[cfg(test)]
mod tests;
