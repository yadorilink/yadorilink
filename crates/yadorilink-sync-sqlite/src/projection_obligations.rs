//! The desired-side fence and the Convergence Engine's own live claim
//! source. `projection_obligations` records, per `(group_id, path)`, a
//! durable `invalidation_generation` bumped by exactly one statement
//! whenever a genuine native state transition (a delta admitted from a
//! peer, or a local delta authored) touches that path, plus the obligation-native retry/
//! backoff state (`attempt_count`/`next_attempt_at`) and the parked
//! `'ignore_blocked'` state a path settles into when its own materialization
//! is excluded by ignore policy rather than genuinely completed.
//! `materialization_jobs` (`materialization_jobs.rs`) is a retired, no
//! longer scheduled-off-of table now — the engine claims and drives
//! entirely from this one.
//!
//! Network redelivery of an already-admitted delta never reaches
//! [`bump_projection_obligations_for_touched_paths`] at all: it is called
//! only from the durable-transition seams in `native_desired_state`
//! (`arm_projection_for_delta` and its siblings), never from message/batch
//! receipt. This is what makes "a delta receipt is not a projection event" a
//! property of the call graph, not a runtime check.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;

pub fn init_projection_obligations_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS projection_obligations (
            group_id                TEXT NOT NULL,
            path                    TEXT NOT NULL,
            invalidation_generation INTEGER NOT NULL,
            state                   TEXT NOT NULL,
            created_at              INTEGER NOT NULL,
            updated_at              INTEGER NOT NULL,
            attempt_count           INTEGER NOT NULL DEFAULT 0,
            next_attempt_at         INTEGER NOT NULL DEFAULT 0,
            obligation_incarnation  INTEGER NOT NULL DEFAULT 0,
            -- Which bump seam last touched this row; `'remote'` is the
            -- veto-preserving value (see `ObligationOrigin`).
            origin                  TEXT NOT NULL DEFAULT 'remote',
            PRIMARY KEY (group_id, path)
        );
        -- Backs `obligation_incarnation` below: a real SQLite `AUTOINCREMENT`
        -- sequence (via `sqlite_sequence`) never reuses a value, unlike a
        -- plain table's own implicit rowid, which SQLite CAN reassign to a
        -- later row once the row that held it is deleted. That reuse is
        -- exactly what `obligation_incarnation` exists to rule out for
        -- `projection_obligations` itself (see `bump_projection_obligations_
        -- for_touched_paths`'s own doc comment for the ABA this closes), so
        -- the identity source it depends on has to genuinely never repeat.
        CREATE TABLE IF NOT EXISTS projection_obligation_incarnations (
            id INTEGER PRIMARY KEY AUTOINCREMENT
        );
        "#,
    )?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_projection_obligations_runnable
             ON projection_obligations (state, group_id, updated_at, path, next_attempt_at);
         CREATE INDEX IF NOT EXISTS idx_projection_obligations_due
             ON projection_obligations (state, group_id, next_attempt_at, updated_at, path);",
    )?;
    // The claim below reads it, so it exists wherever obligations do.
    crate::paused_items::init_paused_items_schema(conn)?;
    crate::held_path::init_held_path_schema(conn)?;
    crate::native_rebootstrap::init_tables(conn)?;
    Ok(())
}

/// Bumps (or creates, at generation 1) the projection obligation for every
/// path in `touched_paths`, via one `INSERT ... ON CONFLICT DO UPDATE` per
/// path. Called from the `native_desired_state` seams with the paths the
/// delta or state change touched.
///
/// Runs inside whatever transaction the caller is already in -- this
/// function opens none of its own. A no-op for an empty
/// `touched_paths`.
///
/// **Obligation row-incarnation ABA**: `invalidation_
/// generation` alone identifies a claim only for as long as the row it was
/// read from keeps existing. The completion primitives below all `DELETE`
/// the row on success (`IgnoreExcluded` is the one exception -- see its own
/// doc comment), and a fresh `INSERT` here after that delete has no memory
/// of what generation the deleted row was last at, so it restarts at `1` --
/// identical to any still-in-flight claim issued back when the path's very
/// first obligation was created. `claim_runnable_obligations`'s own doc
/// comment already documents that two workers concurrently holding a claim
/// on the same STILL-OUTSTANDING obligation is expected and tolerated; that
/// reasoning silently assumed the row underneath both claims stays the same
/// row for the obligation's whole lifetime, which delete-then-reinsert
/// breaks. `obligation_incarnation` closes this the same way `invalidation_
/// generation` closes staleness WITHIN a row's lifetime: it identifies the
/// row's OWN lifetime, assigned fresh (from `projection_obligation_
/// incarnations`, an `AUTOINCREMENT` sequence that never repeats a value)
/// only on a genuine fresh `INSERT`, and left untouched by the `ON CONFLICT`
/// arm so an ordinary bump of a still-existing row keeps its incarnation
/// while `invalidation_generation` increments underneath it. Every
/// completion-family primitive's CAS now matches on `(group_id, path,
/// invalidation_generation, obligation_incarnation)` together, so a claim
/// issued against a since-deleted incarnation can never match a later,
/// unrelated incarnation that happens to share the same generation number.
pub fn bump_projection_obligations_for_touched_paths(
    conn: &Connection,
    group_id: &str,
    touched_paths: &[&str],
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    bump_projection_obligations_with_origin(
        conn,
        group_id,
        touched_paths,
        now_unix_nanos,
        ObligationOrigin::Remote,
    )
    .map(|_| ())
}

/// An obligation as a bump left it: `pending`, at the generation and incarnation it now holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArmedObligation {
    pub invalidation_generation: i64,
    pub obligation_incarnation: i64,
}

/// [`bump_projection_obligations_for_touched_paths`] writing `origin` on both the fresh
/// `INSERT` and the `ON CONFLICT` arm. Every bump is `Remote` (the conservative default: the row
/// describes desired content this device has not necessarily placed) except the one for a delta
/// this device authored itself, whose bytes were on its own disk before the delta existed;
/// writing that origin in the bump itself leaves the row exactly as bumping and then overwriting
/// its origin in a second statement would. A later remote bump resets a `Local` row to `Remote`.
pub(crate) fn bump_projection_obligations_with_origin(
    conn: &Connection,
    group_id: &str,
    touched_paths: &[&str],
    now_unix_nanos: i64,
    origin: ObligationOrigin,
) -> Result<std::collections::BTreeMap<String, ArmedObligation>, SyncSqliteError> {
    if touched_paths.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    // Always allocates a fresh incarnation for every path, even on the (far more common)
    // `ON CONFLICT` bump-in-place path where it goes unused: wasting `i64` SEQUENCE VALUES is
    // free, while a conditional allocation would need to know in advance whether the upsert
    // is about to insert or update, which a single upsert statement does not expose. The ROWS
    // the allocation creates are deleted again right away, or the allocator table would grow
    // by one permanent row per touched-path event, in proportion to total admitted mutations
    // rather than live obligations. That is safe: SQLite's `AUTOINCREMENT` tracks the
    // high-water mark in `sqlite_sequence` independently of which rows currently exist, so
    // deleting the rows can never let a later `INSERT` reuse an incarnation.
    //
    // One statement allocates the whole block: the rows of a single `INSERT ... SELECT` take
    // consecutive ids, so path `i` gets `first + i`, each unique and above everything
    // allocated before. The delete must find exactly the block it allocated, or the ids were
    // not the consecutive block the upsert below assumes.
    let count = touched_paths.len() as i64;
    conn.prepare_cached(
        "INSERT INTO projection_obligation_incarnations (id) \
         SELECT NULL FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n \
         WHERE i < ?1) SELECT i FROM n)",
    )?
    .execute(rusqlite::params![count])?;
    let last = conn.last_insert_rowid();
    let first = last - count + 1;
    let released = conn
        .prepare_cached(
            "DELETE FROM projection_obligation_incarnations WHERE id BETWEEN ?1 AND ?2",
        )?
        .execute(rusqlite::params![first, last])?;
    if released as i64 != count {
        return Err(SyncSqliteError::CorruptState(format!(
            "allocated {count} obligation incarnations but found {released} in {first}..={last}"
        )));
    }
    let paths = serde_json::to_string(touched_paths)
        .map_err(|error| SyncSqliteError::InvalidInput(error.to_string()))?;
    // `origin` is written on BOTH the fresh `INSERT` and the `ON CONFLICT` bump-in-place arm: a
    // later REMOTE-authored admission bumping a path an earlier LOCAL emission had marked must
    // reset origin back to `'remote'`, since the row now again describes desired content this
    // device has not necessarily placed -- see `ObligationOrigin`'s own doc comment for why a
    // stale `'local'` tag across a subsequent remote bump would be unsound.
    let mut stmt = conn.prepare_cached(
        "INSERT INTO projection_obligations
            (group_id, path, invalidation_generation, state, attempt_count,
             next_attempt_at, created_at, updated_at, obligation_incarnation, origin)
         SELECT ?1, value, 1, 'pending', 0, ?3, ?3, ?3, ?4 + key, ?5 FROM json_each(?2) WHERE true
         ON CONFLICT (group_id, path) DO UPDATE SET
            invalidation_generation = invalidation_generation + 1,
            state = 'pending',
            attempt_count = 0,
            next_attempt_at = ?3,
            updated_at = ?3,
            origin = ?5
         RETURNING path, invalidation_generation, obligation_incarnation",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![group_id, paths, now_unix_nanos, first, origin.as_db_str()],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                ArmedObligation {
                    invalidation_generation: row.get(1)?,
                    obligation_incarnation: row.get(2)?,
                },
            ))
        },
    )?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Diagnostic/test-only read of one path's current obligation, or `None` if
/// no admission has ever touched it. Not consumed by any production
/// scheduling path -- production claims go through
/// [`claim_runnable_obligations`].
pub fn lookup_projection_obligation(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<ProjectionObligation>, SyncSqliteError> {
    conn.query_row(
        "SELECT invalidation_generation, state, attempt_count, next_attempt_at, created_at,
                updated_at, obligation_incarnation, origin
           FROM projection_obligations WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
        |r| {
            Ok(ProjectionObligation {
                invalidation_generation: r.get(0)?,
                state: r.get(1)?,
                attempt_count: r.get(2)?,
                next_attempt_at: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                obligation_incarnation: r.get(6)?,
                origin: ObligationOrigin::from_db_str(&r.get::<_, String>(7)?),
            })
        },
    )
    .optional()
    .map_err(SyncSqliteError::from)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionObligation {
    pub invalidation_generation: i64,
    pub state: String,
    pub attempt_count: i64,
    pub next_attempt_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    /// See [`bump_projection_obligations_for_touched_paths`]'s own doc
    /// comment (obligation row-incarnation ABA).
    pub obligation_incarnation: i64,
    /// Which of the four admission seams' bump most recently touched this
    /// row. See [`ObligationOrigin`]'s own doc comment for what this
    /// distinguishes and why it exists.
    pub origin: ObligationOrigin,
}

/// Which kind of native admission most recently bumped a `projection_
/// obligations` row -- the distinction the offline-delete-vs-not-yet-placed
/// tombstone veto was missing.
///
/// `bump_projection_obligations_for_touched_paths` bumps identically for
/// EVERY admission -- a delta received from a peer or a local
/// emission -- because both are
/// equally genuine "desired state changed" events from the Convergence
/// Engine's scheduling point of view. But they are NOT equally ambiguous
/// for the *offline-delete-vs-not-yet-placed* question the tombstone veto
/// (`has_unsettled_projection_obligation`, in both
/// `yadorilink-local-capture`'s restart scan and
/// `yadorilink-filesystem-sync`'s interrupted-materialization repair pass)
/// exists to answer: a remotely admitted delta
/// describes content that arrived from a PEER -- this
/// device may not yet have written those bytes anywhere, so the path's
/// absence from disk is genuinely ambiguous between "never materialized
/// yet" and "deleted after materializing." A LOCAL emission is different by
/// construction: the caller already observed the
/// bytes on this device's own disk (that observation IS the local capture
/// that produced the delta) before the delta was ever admitted -- there
/// is no fetch/materialize step for content this device authored itself,
/// so an obligation whose most recent bump was a local emission can never
/// represent "not yet placed." Its path's absence from disk at scan/repair
/// time can only mean a genuine subsequent deletion.
///
/// `Remote` is the fail-closed default (see the schema migration's own doc
/// comment and `bump_projection_obligations_for_touched_paths`'s own doc
/// comment on why the `ON CONFLICT` arm always resets to `Remote`): only
/// the bump for a delta this device authored itself
/// ([`bump_projection_obligations_with_origin`]) ever produces `Local`, and
/// any later remote bump overwrites it back to
/// `Remote` -- so a path that ever again needs content from elsewhere loses
/// its `Local` tag the instant that need is recorded, never leaving a stale
/// `Local` tag protecting the wrong generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationOrigin {
    /// This device authored the delta itself; the desired bytes were
    /// already on this device's own disk (observed directly by local
    /// capture) before the obligation was ever created. Never a "not yet
    /// placed" veto reason.
    Local,
    /// The delta came from (or through) a peer. This device may
    /// not have the desired bytes on disk yet. The veto-preserving default.
    Remote,
}

impl ObligationOrigin {
    /// Any value other than the literal `"local"` this crate itself ever
    /// writes -- including a value from some future, not-yet-understood
    /// migration path -- reads as `Remote`, matching the column's own
    /// fail-closed `DEFAULT 'remote'`.
    fn as_db_str(self) -> &'static str {
        match self {
            ObligationOrigin::Local => "local",
            ObligationOrigin::Remote => "remote",
        }
    }

    fn from_db_str(s: &str) -> Self {
        match s {
            "local" => ObligationOrigin::Local,
            _ => ObligationOrigin::Remote,
        }
    }
}

/// One obligation a claim call handed to a worker: enough to drive an
/// attempt (`group_id`, `path`) and enough to close it afterward
/// (`invalidation_generation`, the generation `G` this claim observed).
/// Deliberately carries no version hash: unlike `MaterializationJob`, the
/// desired state is always recomputed fresh at resolve time, never carried
/// from claim time, so there is nothing here that could go stale between
/// claim and close other than `G` itself and `obligation_incarnation`,
/// which the completion primitives re-check directly (`G` alone is not
/// enough -- see `bump_projection_obligations_for_touched_
/// paths`'s own doc comment for the row-incarnation ABA this closes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedObligation {
    pub group_id: String,
    pub path: String,
    pub invalidation_generation: i64,
    /// Identifies the specific row incarnation this claim's `invalidation_
    /// generation` was read from. Carried alongside `invalidation_
    /// generation` into every completion-family call so a claim issued
    /// against a since-deleted-and-recreated row can never match its
    /// replacement merely because the replacement's own generation counter
    /// happened to start over at the same number.
    pub obligation_incarnation: i64,
    /// How many prior attempts at this SAME `invalidation_generation` have
    /// already failed (`mark_obligation_attempt_failed`) -- 0 for an
    /// obligation that has never failed, or that a fresh admission just
    /// reset. A caller computes its own backoff duration from this (see
    /// `yadorilink-daemon`'s reuse of `next_backoff`), the same way
    /// `MaterializationJob::attempt` already drives the legacy scheduler's
    /// backoff.
    pub attempt_count: i64,
}

impl ClaimedObligation {
    /// The part of this claim a completion re-checks.
    pub fn token(&self) -> ObligationClaimToken {
        ObligationClaimToken {
            invalidation_generation: self.invalidation_generation,
            obligation_incarnation: self.obligation_incarnation,
        }
    }
}

/// What a completion must find unchanged on an obligation row to close it:
/// the generation and the row incarnation its claim read. Carried by a
/// worker from the claim to whichever transaction closes the obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObligationClaimToken {
    pub invalidation_generation: i64,
    pub obligation_incarnation: i64,
}

/// Every currently-runnable obligation (`state = 'pending'` AND its
/// `next_attempt_at` backoff deadline has passed), fairly windowed per group
/// exactly like `materialization_jobs::claim_runnable_jobs`. This is a plain
/// read, not a claim-and-mark-in-flight operation: `state` stays purely
/// advisory here (a fresh admission's bump unconditionally resets it back to
/// `'pending'` regardless of what a claim observed), so nothing about this
/// function's correctness depends on the row's `state` surviving between
/// this read and the eventual completion call -- that safety is entirely
/// the completion primitive's `invalidation_generation` CAS's job. A worker
/// that reclaims the same still-outstanding obligation on a later tick
/// before a prior attempt finishes is therefore a performance question
/// (redundant concurrent work), never a correctness one.
///
/// A path covered by a paused item (see `crate::paused_items`) is not
/// runnable: its obligation stays exactly as admission left it, pending,
/// until the item is resumed. Excluded here rather than skipped after the
/// claim, because a paused row skipped later would still take a slot of
/// its group's per-group window on every tick, and the oldest rows fill
/// that window first -- a paused folder with enough held changes would
/// starve every other path of its group.
///
/// A held path (see `crate::held_path`) is
/// excluded the same way, for a stronger reason: projecting the row's
/// version would overwrite whatever is on disk there, and until the
/// reconciliation has looked at it that may be an edit nobody has
/// captured.
///
/// A group a rebootstrap freezes (see `crate::native_rebootstrap::group_frozen`) is
/// excluded as a whole: its rows wait, unclaimed, until the freeze ends.
pub fn claim_runnable_obligations(
    conn: &Connection,
    now_unix_nanos: i64,
    per_group_limit: u32,
    total_limit: u32,
) -> Result<Vec<ClaimedObligation>, SyncSqliteError> {
    // The first `per_group_limit` runnable rows of each group, in claim
    // order, then the first `total_limit` of those in claim order. That is
    // the set a per-group rank filter followed by a global limit keeps, at a
    // cost of the groups times the window rather than the table. Paused and
    // held paths are excluded in each statement's own WHERE clause (so they
    // never take a window slot) and a frozen group is skipped whole. The
    // caller runs this inside one read snapshot, so every statement sees
    // the same database.
    if total_limit == 0 || per_group_limit == 0 {
        return Ok(Vec::new());
    }
    let mut candidates: Vec<(i64, ClaimedObligation)> = Vec::new();
    for group_id in pending_group_ids(conn)? {
        if crate::native_rebootstrap::group_frozen(conn, &group_id)? {
            continue;
        }
        // A provider group's obligations belong to the provider projector alone: the engine
        // lanes cannot project a group that has no directory.
        if is_provider_group(conn, &group_id)? {
            continue;
        }
        candidates.extend(group_window(conn, &group_id, now_unix_nanos, per_group_limit)?);
    }
    sort_in_claim_order(&mut candidates);
    candidates.truncate(total_limit as usize);
    Ok(candidates.into_iter().map(|(_, claimed)| claimed).collect())
}

/// Whether `group_id` has a provider root (a database without the provider tables has none).
fn is_provider_group(conn: &Connection, group_id: &str) -> Result<bool, SyncSqliteError> {
    let has_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'provider_roots')",
        [],
        |r| r.get(0),
    )?;
    if !has_table {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_roots WHERE group_id = ?1)",
        [group_id],
        |r| r.get(0),
    )?)
}

/// How many due rows the due-first probe reads before concluding the due
/// set is too large to order in memory.
const DUE_PROBE_ROWS: u32 = 128;

fn sort_in_claim_order(rows: &mut [(i64, ClaimedObligation)]) {
    rows.sort_by(|(at_a, a), (at_b, b)| {
        at_a.cmp(at_b).then_with(|| a.path.cmp(&b.path)).then_with(|| a.group_id.cmp(&b.group_id))
    });
}

/// Every group holding a pending row, seeking from one group to the next.
fn pending_group_ids(conn: &Connection) -> Result<Vec<String>, SyncSqliteError> {
    let mut first = conn.prepare_cached(
        "SELECT group_id FROM projection_obligations INDEXED BY idx_projection_obligations_runnable \
         WHERE state = 'pending' ORDER BY group_id ASC LIMIT 1",
    )?;
    let mut next = conn.prepare_cached(
        "SELECT group_id FROM projection_obligations INDEXED BY idx_projection_obligations_runnable \
         WHERE state = 'pending' AND group_id > ?1 ORDER BY group_id ASC LIMIT 1",
    )?;
    let mut groups = Vec::new();
    let mut current = first.query_row([], |r| r.get::<_, String>(0)).optional()?;
    while let Some(group_id) = current {
        current = next.query_row([&group_id], |r| r.get::<_, String>(0)).optional()?;
        groups.push(group_id);
    }
    Ok(groups)
}

fn runnable_filters_sql() -> String {
    format!(
        "AND NOT {paused} AND NOT {held}",
        paused = crate::paused_items::covered_by_paused_item_sql(
            "projection_obligations.group_id",
            "projection_obligations.path",
        ),
        held = crate::held_path::held_sql(
            "projection_obligations.group_id",
            "projection_obligations.path",
        ),
    )
}

/// How many index rows the ordered walk may pass over, runnable or not,
/// before the due-index pass takes over.
const WALK_ROWS: u32 = 1024;

/// A row ordered by claim order within one group, for the bounded heap.
struct ByClaimOrder(i64, ClaimedObligation);

impl PartialEq for ByClaimOrder {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}
impl Eq for ByClaimOrder {}
impl PartialOrd for ByClaimOrder {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ByClaimOrder {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0).then_with(|| self.1.path.cmp(&other.1.path))
    }
}

/// One group's first `limit` runnable rows in claim order, each with its
/// `updated_at`. Three access paths, none of which walks a large population
/// that cannot qualify:
///
/// 1. a due-first probe (an index leading with `next_attempt_at`, so a group
///    whose deadlines all lie in the future costs a seek) that orders the
///    due set in memory when it is small;
/// 2. otherwise a walk of the claim-ordered index that stops at `limit`
///    qualifying rows -- dense, and so cheap, when most rows are due -- but
///    gives up after [`WALK_ROWS`] rows passed;
/// 3. otherwise one pass over exactly the due rows, keeping the best `limit`
///    in a bounded heap, so a few due rows behind a very large number of older
///    not-yet-due ones cost the due rows, not the population.
fn group_window(
    conn: &Connection,
    group_id: &str,
    now_unix_nanos: i64,
    limit: u32,
) -> Result<Vec<(i64, ClaimedObligation)>, SyncSqliteError> {
    let decode = |r: &rusqlite::Row<'_>| -> rusqlite::Result<(i64, ClaimedObligation)> {
        Ok((
            r.get::<_, i64>(5)?,
            ClaimedObligation {
                group_id: r.get(0)?,
                path: r.get(1)?,
                invalidation_generation: r.get(2)?,
                obligation_incarnation: r.get(3)?,
                attempt_count: r.get(4)?,
            },
        ))
    };
    let columns = "group_id, path, invalidation_generation, obligation_incarnation, \
                   attempt_count, updated_at";
    let filters = runnable_filters_sql();
    let mut probe = conn.prepare_cached(&format!(
        "SELECT {columns} FROM projection_obligations INDEXED BY idx_projection_obligations_due \
         WHERE state = 'pending' AND group_id = ?1 AND next_attempt_at <= ?2 {filters} \
         LIMIT ?3"
    ))?;
    let mut due = probe
        .query_map(rusqlite::params![group_id, now_unix_nanos, DUE_PROBE_ROWS + 1], decode)?
        .collect::<Result<Vec<_>, _>>()?;
    if due.len() <= DUE_PROBE_ROWS as usize {
        sort_in_claim_order(&mut due);
        due.truncate(limit as usize);
        return Ok(due);
    }

    let mut walk = conn.prepare_cached(&format!(
        "SELECT {columns}, next_attempt_at, (1 {filters}) \
         FROM projection_obligations INDEXED BY idx_projection_obligations_runnable \
         WHERE state = 'pending' AND group_id = ?1 \
         ORDER BY updated_at ASC, path ASC"
    ))?;
    let mut walked = Vec::new();
    let mut passed = 0u32;
    let mut rows = walk.query([group_id])?;
    while let Some(r) = rows.next()? {
        passed += 1;
        if r.get::<_, i64>(6)? <= now_unix_nanos && r.get::<_, bool>(7)? {
            walked.push(decode(r)?);
            if walked.len() >= limit as usize {
                return Ok(walked);
            }
        }
        if passed >= WALK_ROWS {
            break;
        }
    }
    if passed < WALK_ROWS {
        // The walk reached the end of the group: what it found is the lot.
        return Ok(walked);
    }
    drop(rows);

    let mut due_pass = conn.prepare_cached(&format!(
        "SELECT {columns} FROM projection_obligations INDEXED BY idx_projection_obligations_due \
         WHERE state = 'pending' AND group_id = ?1 AND next_attempt_at <= ?2 {filters}"
    ))?;
    let mut best: std::collections::BinaryHeap<ByClaimOrder> = std::collections::BinaryHeap::new();
    let mut rows = due_pass.query(rusqlite::params![group_id, now_unix_nanos])?;
    while let Some(r) = rows.next()? {
        let (updated_at, claimed) = decode(r)?;
        best.push(ByClaimOrder(updated_at, claimed));
        if best.len() > limit as usize {
            best.pop();
        }
    }
    Ok(best.into_sorted_vec().into_iter().map(|ByClaimOrder(at, c)| (at, c)).collect())
}

/// The original whole-table form of [`claim_runnable_obligations`], kept as
/// the oracle the streaming form is checked against.
#[cfg(test)]
pub(crate) fn claim_runnable_obligations_oracle(
    conn: &Connection,
    now_unix_nanos: i64,
    per_group_limit: u32,
    total_limit: u32,
) -> Result<Vec<ClaimedObligation>, SyncSqliteError> {
    let mut stmt = conn.prepare(&format!(
        "WITH runnable AS ( \
            SELECT group_id, path, invalidation_generation, obligation_incarnation, \
                   attempt_count, updated_at, \
                   ROW_NUMBER() OVER ( \
                PARTITION BY group_id ORDER BY updated_at ASC, path ASC \
            ) AS group_rank \
            FROM projection_obligations \
            WHERE state = 'pending' AND next_attempt_at <= ?1 \
              AND NOT {paused} \
              AND NOT {held} \
              AND NOT {frozen} \
         ) \
         SELECT group_id, path, invalidation_generation, obligation_incarnation, attempt_count \
         FROM runnable \
         WHERE group_rank <= ?2 \
         ORDER BY updated_at ASC, path ASC \
         LIMIT ?3",
        paused = crate::paused_items::covered_by_paused_item_sql(
            "projection_obligations.group_id",
            "projection_obligations.path",
        ),
        held = crate::held_path::held_sql(
            "projection_obligations.group_id",
            "projection_obligations.path",
        ),
        frozen = crate::native_rebootstrap::frozen_group_sql("projection_obligations.group_id"),
    ))?;
    let rows =
        stmt.query_map(rusqlite::params![now_unix_nanos, per_group_limit, total_limit], |r| {
            Ok(ClaimedObligation {
                group_id: r.get(0)?,
                path: r.get(1)?,
                invalidation_generation: r.get(2)?,
                obligation_incarnation: r.get(3)?,
                attempt_count: r.get(4)?,
            })
        })?;
    let claimed = rows.collect::<Result<Vec<_>, _>>()?;
    Ok(claimed)
}

/// Records a failed attempt at exactly `claimed_invalidation_generation`:
/// increments `attempt_count` and sets `next_attempt_at` to the caller-
/// computed backoff deadline (`next_backoff`-style, mirroring `materialization_
/// jobs`'s own `materialization_mark_backoff`). Conditioned on the
/// generation being UNCHANGED since the claim -- exactly like the
/// completion primitives -- so a concurrent fresh admission that already
/// reset this path's attempt state (a new desired state must never be
/// delayed by an old generation's backoff) is never overwritten by a
/// stale failure report arriving after it. Returns whether the row was
/// actually still at that generation; `Ok(false)` is not an error, merely
/// "already superseded, nothing to do."
///
/// Deliberately only ever called for a genuine transient `RetryRequired`
/// outcome -- a `HazardHeld`/`IgnoreExcluded` settlement has its own
/// dedicated re-arm liveness (the hazard-recheck sweep, the ignore-set
/// refresh) and must never be folded into this generic backoff, or a path
/// correctly held for policy reasons would incorrectly inherit an
/// unrelated exponential retry delay on top of its own liveness mechanism.
pub fn mark_obligation_attempt_failed(
    conn: &Connection,
    group_id: &str,
    path: &str,
    claimed_invalidation_generation: i64,
    claimed_obligation_incarnation: i64,
    next_attempt_at: i64,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let affected = conn.execute(
        "UPDATE projection_obligations
            SET attempt_count = attempt_count + 1,
                next_attempt_at = ?5,
                updated_at = ?6
          WHERE group_id = ?1 AND path = ?2 AND invalidation_generation = ?3
            AND obligation_incarnation = ?4",
        rusqlite::params![
            group_id,
            path,
            claimed_invalidation_generation,
            claimed_obligation_incarnation,
            next_attempt_at,
            now_unix_nanos
        ],
    )?;
    Ok(affected == 1)
}

/// Reschedules a short, fixed delay with NO attempt penalty -- unlike
/// [`mark_obligation_attempt_failed`], `attempt_count` is left untouched.
/// For the "this tick learned nothing reliable" case (every candidate this
/// tick was skipped by guard contention, or every read raced a concurrent
/// admission): the obligation itself was never actually re-examined, so
/// treating it as a real failed attempt would needlessly accelerate its
/// backoff toward the cap for a systemic scheduling condition that has
/// nothing to do with this specific path. Same generation-gating as
/// [`mark_obligation_attempt_failed`].
pub fn defer_obligation_without_penalty(
    conn: &Connection,
    group_id: &str,
    path: &str,
    claimed_invalidation_generation: i64,
    claimed_obligation_incarnation: i64,
    next_attempt_at: i64,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let affected = conn.execute(
        "UPDATE projection_obligations
            SET next_attempt_at = ?5,
                updated_at = ?6
          WHERE group_id = ?1 AND path = ?2 AND invalidation_generation = ?3
            AND obligation_incarnation = ?4",
        rusqlite::params![
            group_id,
            path,
            claimed_invalidation_generation,
            claimed_obligation_incarnation,
            next_attempt_at,
            now_unix_nanos
        ],
    )?;
    Ok(affected == 1)
}

/// The single atomic compound completion for an EXACT outcome (a real
/// `path_materialized_generations` proof). Establishes, at one instant --
/// the instant this `DELETE` commits, not at any earlier read -- all of:
///
/// (a) desired-side currency: `invalidation_generation` still equals the
///     claimed generation `G`;
/// (b) filesystem-side currency of the proof: its
///     `published_under_mutation_generation` still equals the path's
///     LIVE `mutation_generation`, read as part of THIS statement;
/// (c) the proof still describes the state this obligation claims: its
///     `resolved_path_state_hash` still equals `desired_hash`.
///
/// Zero rows affected (`Ok(false)`) is the verdict "not closed" -- the
/// obligation is left exactly where it was, at `G` (or already re-armed
/// at some `G' > G` if a fresh admission moved it), to be re-claimed and
/// re-resolved from scratch on a later tick. This must run inside a
/// `write_immediate` transaction (never a plain `write`, never DEFERRED)
/// so that no fence bump, publication, or obligation bump from another
/// writer can land between this statement's read and its write -- the
/// whole point of "one instant" is that this single `DELETE`'s own
/// atomicity is what provides it, not a lock this function takes itself.
/// (c) is checked even though (b) alone rules out "same fence generation,
/// different content" under the current invariants -- kept as defense in
/// depth: it is cheap, locally checkable, and is exactly the check that
/// still fails closed if a future mutator is ever added that moves bytes
/// without moving the fence, which is the premise (b) alone depends on.
pub fn complete_obligation_if_exact_proof_current(
    conn: &Connection,
    group_id: &str,
    path: &str,
    claimed_invalidation_generation: i64,
    claimed_obligation_incarnation: i64,
    desired_resolved_path_state_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    let affected = conn.execute(
        "DELETE FROM projection_obligations
          WHERE group_id = ?1 AND path = ?2
            AND invalidation_generation = ?3
            AND obligation_incarnation = ?4
            AND EXISTS (
                 SELECT 1
                   FROM path_materialized_generations g
                   JOIN path_actual_mutation_fences f
                     ON f.group_id = g.group_id AND f.path = g.path
                  WHERE g.group_id = ?1 AND g.path = ?2
                    AND g.published_under_mutation_generation = f.mutation_generation
                    AND g.resolved_path_state_hash = ?5
            )",
        rusqlite::params![
            group_id,
            path,
            claimed_invalidation_generation,
            claimed_obligation_incarnation,
            desired_resolved_path_state_hash
        ],
    )?;
    Ok(affected == 1)
}

/// One close for [`complete_obligations_if_exact_proofs_current`]: the claim on a path's
/// obligation and the desired state the path must be proven to hold.
pub(crate) struct ExactClose<'a> {
    pub path: &'a str,
    pub claimed_invalidation_generation: i64,
    pub claimed_obligation_incarnation: i64,
    pub desired_resolved_path_state_hash: [u8; 32],
}

/// [`complete_obligation_if_exact_proof_current`] for many paths in one statement per chunk: each
/// close deletes its path's obligation under exactly the conditions the single close names (the
/// claimed generation and incarnation still hold, and the path's published proof was minted under
/// the live fence and carries the desired hash). Returns the paths whose obligation was closed.
pub(crate) fn complete_obligations_if_exact_proofs_current(
    conn: &Connection,
    group_id: &str,
    closes: &[ExactClose<'_>],
) -> Result<std::collections::HashSet<String>, SyncSqliteError> {
    let mut closed = std::collections::HashSet::with_capacity(closes.len());
    for chunk in closes.chunks(100) {
        let values: Vec<String> = (0..chunk.len())
            .map(|i| {
                let b = 2 + 4 * i;
                format!("(?{}, ?{}, ?{}, ?{})", b, b + 1, b + 2, b + 3)
            })
            .collect();
        let mut stmt = conn.prepare_cached(&format!(
            "WITH c(path, generation, incarnation, hash) AS (VALUES {}) \
             DELETE FROM projection_obligations \
              WHERE group_id = ?1 AND path IN ( \
                SELECT c.path FROM c \
                  CROSS JOIN projection_obligations o \
                    ON o.group_id = ?1 AND o.path = c.path \
                   AND o.invalidation_generation = c.generation \
                   AND o.obligation_incarnation = c.incarnation \
                  CROSS JOIN path_materialized_generations g \
                    ON g.group_id = ?1 AND g.path = c.path \
                   AND g.resolved_path_state_hash = c.hash \
                  CROSS JOIN path_actual_mutation_fences f \
                    ON f.group_id = ?1 AND f.path = c.path \
                   AND g.published_under_mutation_generation = f.mutation_generation) \
             RETURNING path",
            values.join(", ")
        ))?;
        let mut params: Vec<rusqlite::types::Value> = Vec::with_capacity(1 + 4 * chunk.len());
        params.push(group_id.to_owned().into());
        for close in chunk {
            params.push(close.path.to_owned().into());
            params.push(close.claimed_invalidation_generation.into());
            params.push(close.claimed_obligation_incarnation.into());
            params.push(close.desired_resolved_path_state_hash.to_vec().into());
        }
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            closed.insert(row.get::<_, String>(0)?);
        }
    }
    Ok(closed)
}

/// Which durable, live proof to re-check in the SAME transaction as the
/// close, for an outcome that never publishes to
/// `path_materialized_generations` at all and so has nothing for the
/// exact-outcome check's (b)/(c) to compare against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonExactProofKind {
    /// Closes against the path's EXISTING `files` row being `Remote` or
    /// `Present`: the policy owes this device no content for it (an on-demand
    /// device records the version and fetches nothing until it is opened).
    /// A row that is hydrated between the worker's decision and this close
    /// leaves the path MORE satisfied than the obligation required (benign
    /// to miss closing this tick; the next admission or the periodic repair
    /// candidate scan re-examines it regardless) -- this direction of
    /// staleness is harmless, unlike the hazard-hold direction below.
    ContentNotOwed,
    /// Closes against the EXISTING `held_reason` on the path's current
    /// `files` row (any non-NULL reason, not a specific one -- logic that
    /// decided this exact reason no longer applies would itself already
    /// have cleared `held_reason` and re-driven `materialize`, which is a
    /// fresh attempt with its own fresh claim, not this one). A hold
    /// lifted between decision and this close is the HARMFUL direction
    /// (the path now needs real work, and nothing re-arms a closed
    /// obligation on its own) -- the same-transaction re-read here closes
    /// the narrow race at the instant of THIS close, but the broader
    /// "what re-arms a path whose hold is lifted later" gap is a real,
    /// separately-tracked one, out of scope here; that re-arming is the
    /// hazard engine's own responsibility, not this completion
    /// primitive's.
    HazardHeld,
    /// Unlike `Remote`/`HazardHeld`, an ignore-policy decision has NO
    /// durable, queryable proof row at all -- `is_locally_ignored` is a
    /// live, in-memory, per-session check against the current ignore sets,
    /// never persisted to `files` or anywhere else. There is therefore
    /// nothing for a same-transaction SQL re-read to compare against for
    /// this outcome: this variant's completion checks ONLY (a) -- the
    /// desired-side generation CAS.
    ///
    /// This variant does NOT delete the obligation row the way the other
    /// two do: it transitions `state` to `'ignore_blocked'` instead,
    /// leaving the row (and its `invalidation_generation`) in place. An
    /// ignore-policy decision has no durable proof to invalidate the way a
    /// lifted hazard hold does, so nothing can tell a fresh admission's own
    /// bump apart from an unrelated one -- deleting the row here would mean
    /// NOTHING durably remembers this path was ever ignore-blocked, and a
    /// later `.yadorilinkignore` edit un-ignoring it would have no
    /// obligation left to re-arm at all. Parking it in `'ignore_blocked'`
    /// instead gives a periodic re-check sweep (`yadorilink-daemon`'s
    /// ignore-recheck loop, mirroring the existing hazard-recheck loop) a
    /// durable row to find and `rearm_ignore_blocked_obligation` back to
    /// `'pending'` once the path is no longer locally ignored.
    IgnoreExcluded,
    /// Closes against the path's EXISTING retained-directory record
    /// (`crate::structural_origin::record_retained_directory`): the
    /// replicated entry is settled as deleted, and the physical directory
    /// stays because it is not empty. A record cleared between the
    /// decision and this close (the directory was removed, or the path
    /// took an entry again) leaves the obligation for re-resolution.
    RetainedDirectory,
}

/// The non-exact-outcome counterpart of
/// [`complete_obligation_if_exact_proof_current`]. Re-reads the outcome's
/// own durable proof (per [`NonExactProofKind`]) in the SAME transaction
/// as the close -- never a value read earlier in the worker's attempt --
/// so that an independent actor changing that proof between the worker's
/// decision and this commit is observed here, not assumed away. Same
/// `write_immediate`-only requirement as the exact-outcome primitive.
///
/// "Close" means "remove the row" for `Remote`/`HazardHeld`, but NOT
/// for `IgnoreExcluded` -- see that variant's own doc comment for why it
/// transitions to `'ignore_blocked'` instead of deleting.
pub fn complete_obligation_if_non_exact_proof_current(
    conn: &Connection,
    group_id: &str,
    path: &str,
    claimed_invalidation_generation: i64,
    claimed_obligation_incarnation: i64,
    proof: NonExactProofKind,
) -> Result<bool, SyncSqliteError> {
    let affected = match proof {
        NonExactProofKind::ContentNotOwed => conn.execute(
            "DELETE FROM projection_obligations
              WHERE group_id = ?1 AND path = ?2
                AND invalidation_generation = ?3
                AND obligation_incarnation = ?4
                AND EXISTS (
                     SELECT 1 FROM files
                      WHERE group_id = ?1 AND path = ?2 AND state = 'current'
                        AND materialization_state IN ('remote', 'present')
                )",
            rusqlite::params![
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation
            ],
        )?,
        NonExactProofKind::HazardHeld => conn.execute(
            "DELETE FROM projection_obligations
              WHERE group_id = ?1 AND path = ?2
                AND invalidation_generation = ?3
                AND obligation_incarnation = ?4
                AND EXISTS (
                     SELECT 1 FROM files
                      WHERE group_id = ?1 AND path = ?2 AND state = 'current'
                        AND held_reason IS NOT NULL
                )",
            rusqlite::params![
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation
            ],
        )?,
        // See NonExactProofKind::IgnoreExcluded's own doc comment: no
        // durable proof row exists to re-read, so only (a) is checked --
        // and unlike the other two, this parks the row rather than
        // deleting it, so a later re-check sweep has something durable to
        // find and re-arm. Still incarnation-gated: a stale claim from a
        // DIFFERENT, already-deleted incarnation of this same path must
        // never be able to park a brand-new incarnation as ignore-blocked
        // just because the generation numbers happen to coincide.
        NonExactProofKind::RetainedDirectory => conn.execute(
            "DELETE FROM projection_obligations
              WHERE group_id = ?1 AND path = ?2
                AND invalidation_generation = ?3
                AND obligation_incarnation = ?4
                AND EXISTS (
                     SELECT 1 FROM retained_directories
                      WHERE group_id = ?1 AND path = ?2
                )",
            rusqlite::params![
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation
            ],
        )?,
        NonExactProofKind::IgnoreExcluded => conn.execute(
            "UPDATE projection_obligations
                SET state = 'ignore_blocked'
              WHERE group_id = ?1 AND path = ?2
                AND invalidation_generation = ?3
                AND obligation_incarnation = ?4
                AND state = 'pending'",
            rusqlite::params![
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation
            ],
        )?,
    };
    Ok(affected == 1)
}

/// Every path in `group_id` currently parked at `'ignore_blocked'` -- the
/// candidate set a periodic re-check sweep re-examines via an ordinary
/// `reconcile_paths_directly` call, exactly like the hazard-recheck loop's
/// own `list_held_paths`.
pub fn list_ignore_blocked_paths(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<String>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path FROM projection_obligations WHERE group_id = ?1 AND state = 'ignore_blocked'",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id], |r| r.get(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Re-arms one `'ignore_blocked'` obligation back to `'pending'` (and
/// immediately claimable, `next_attempt_at` reset to `now`) once a
/// re-check sweep confirms the path is no longer locally ignored.
/// Deliberately does NOT bump `invalidation_generation`: the
/// desired state never actually changed while this path sat blocked, only
/// the LOCAL policy that was blocking it did, so the existing generation
/// still correctly describes what a fresh resolve must satisfy. Guarded on
/// `state = 'ignore_blocked'` (not a generation check, unlike the
/// backoff/completion primitives) -- a fresh admission's own bump already
/// unconditionally resets straight to `'pending'` regardless of the
/// row's prior state, so if one raced this call and got there first, this
/// call correctly becomes a no-op rather than re-arming something already
/// re-armed (or worse, un-doing a newer state).
pub fn rearm_ignore_blocked_obligation(
    conn: &Connection,
    group_id: &str,
    path: &str,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let affected = conn.execute(
        "UPDATE projection_obligations
            SET state = 'pending',
                next_attempt_at = ?3,
                updated_at = ?3
          WHERE group_id = ?1 AND path = ?2 AND state = 'ignore_blocked'",
        rusqlite::params![group_id, path, now_unix_nanos],
    )?;
    Ok(affected == 1)
}

#[cfg(test)]
mod tests;

/// Direct, deterministic tests for the compound completion primitives, at
/// the persistence/API level, before any production scheduling change
/// wires them in.
#[cfg(test)]
mod completion_tests;
