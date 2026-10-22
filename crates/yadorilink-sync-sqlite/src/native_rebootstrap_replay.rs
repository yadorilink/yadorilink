//! What follows the install: the bounded catch-up, then the replay of own intent.
//!
//! One machine, in this order:
//!
//! 1. the install replaces the group's state and moves the journal to `CatchingUp`;
//! 2. remote admission is open again (materialization and local authoring are not);
//! 3. [`catch_up`] drains whatever the connected peers can give now, bounded by
//!    [`CatchUpLimits`]; there is no frontier it must reach;
//! 4. the journal moves to `Replaying` and [`replay_own_intent`] authors the preserved own
//!    deltas, unit by unit, as deltas of the new incarnation;
//! 5. [`crate::native_rebootstrap::finish_rebootstrap`] ends the freeze.
//!
//! The journal state and the rows of `native_rebootstrap_delta` are the durable record of the
//! machine, so a crash at any boundary resumes where it was: nothing is authored twice and no
//! step is lost.
//!
//! # The replay
//!
//! The manifest lists the old own deltas in a topological order of their dependencies. A
//! [`ReplayStep`] is one of them with the [`ReplayIntent`]s of its ops, and the unit it belongs
//! to: a connected component over the removal edges, joined across the parts of one recursive
//! operation, so a put is never separated from the delete that removes it. Intents are derived
//! from the old signed delta and never the other way round. A step is replayed as ONE new delta
//! whose sequence number, chain link, provenance and head identities are those of the new
//! incarnation; removals are recomputed against the state the install left:
//!
//! * a removal of a head an earlier step put names the new delta that carries that put;
//! * a removal of any other head stays only while that head is live;
//! * an op left with neither a put nor a removal is dropped, and a step left with no op is
//!   `moot`.
//!
//! The residual parts of a partially covered recursive operation are a fresh operation: a new
//! id, parts numbered from zero, the residual count.
//!
//! The authority is asked again before each unit, never inside one. A unit it refuses is not
//! authored: its steps are recorded `unreplayed`, and the recovery area keeps its deltas and the
//! copies of its versions. The unit's transaction authors every step or none.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_state::{DeltaHash, Dot, NativeState};
use yadorilink_replica_domain::recursive_operation::RecursiveOperationId;
use yadorilink_replica_domain::signed_delta::{
    DeltaOp, DeltaPut, HeadRef, NativeDelta, RecursivePart,
};

use crate::error::SyncSqliteError;
use crate::local_author::LocalAuthor;
use crate::native_rebootstrap::{
    acquire, rebootstrap_status, resume_preserved, set_state, BlockedReason, BusyOrStore, Crash,
    InstallAuthority, ReassertAuthority, Reassertability, RebootstrapState,
};
use crate::native_rebootstrap_recovery::{sha256, Manifest, ManifestRecursive, RecoveryArea};
use crate::native_store::Admission;

/// The most passes of the catch-up.
pub const CATCHUP_MAX_PASSES: u32 = 8;
/// The most time the catch-up takes in all.
pub const CATCHUP_BUDGET: Duration = Duration::from_secs(60);
/// The most time one pass takes.
pub const CATCHUP_PASS_CAP: Duration = Duration::from_secs(10);

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- A unit of own intent the replay did not author, with the recovery area that still
        -- holds its signed deltas and the copies of its versions. Survives the end of the
        -- rebootstrap; nothing deletes a row but the user's own action.
        CREATE TABLE IF NOT EXISTS native_unreplayed_unit (
            group_id    TEXT NOT NULL,
            recovery_id TEXT NOT NULL,
            unit        INTEGER NOT NULL,
            -- Whether an original of the unit left the sync root: read from what the
            -- quarantine did, in the transaction that records the unit, because the
            -- quarantine rows end with the rebootstrap and this row does not.
            originals_quarantined INTEGER NOT NULL,
            PRIMARY KEY (group_id, recovery_id, unit)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

// --- the catch-up ---------------------------------------------------------------------------

/// The bounds of one catch-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatchUpLimits {
    pub max_passes: u32,
    pub budget: Duration,
    pub per_pass: Duration,
}

impl Default for CatchUpLimits {
    fn default() -> Self {
        Self { max_passes: CATCHUP_MAX_PASSES, budget: CATCHUP_BUDGET, per_pass: CATCHUP_PASS_CAP }
    }
}

/// What one pass over the connected peers obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatchUpPass {
    /// Deltas admitted by the pass.
    pub obtained: u64,
}

/// The ordinary incremental sync, run once and awaited: peers serve the deltas above this
/// replica's frontier and they go through ordinary admission. The group's remote admission is
/// open for it (the journal is `CatchingUp`).
pub trait CatchUpSource {
    /// One pass, taking at most `cap`. An error ends the catch-up: it is best effort.
    fn pass(&mut self, cap: Duration) -> Result<CatchUpPass, String>;
}

/// Why the catch-up ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatchUpEnd {
    /// A pass obtained nothing more.
    Drained,
    PassLimit,
    Budget,
    /// The source failed; what it had obtained stands.
    SourceFailed,
    /// The catch-up had ended before (a restart after it): nothing was run.
    AlreadyOver,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatchUpReport {
    pub passes: u32,
    pub end: CatchUpEnd,
}

/// A point at which a test may stop the process, to see what survives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachinePoint {
    /// The catch-up pass with this number (from 1) has returned.
    AfterPass(u32),
    /// The catch-up is over; the journal still says `CatchingUp`.
    BeforeReplaying,
    /// About to ask the authority and replay the unit.
    BeforeUnit(usize),
    /// Inside the unit's transaction, after the step with this ordinal was authored.
    InUnit { unit: usize, ordinal: usize },
    /// The unit is committed.
    AfterUnit(usize),
    /// A retried unit's preserved bytes are in the block store; nothing is authored yet.
    AfterImport(usize),
    /// A retried unit is authored and its record deleted; the transaction is not committed.
    BeforeResolve(usize),
}

#[derive(Debug)]
pub enum ReplayError {
    /// No such rebootstrap, or it is not at a stage this runs from.
    NotRunnable(String),
    Blocked(BlockedReason),
    Crashed,
    /// Another call holds this group's rebootstrap.
    Busy,
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for ReplayError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

impl From<rusqlite::Error> for ReplayError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

/// Runs the bounded catch-up of the rebootstrap `recovery_id` of `group`, which must be
/// `CatchingUp` (or already `Replaying`, in which case nothing is run), and moves the journal
/// to `Replaying`. A crash in `CatchingUp` runs it again with a fresh bound: admission is
/// idempotent.
pub fn catch_up(
    conn: &Connection,
    group: &FolderGroupId,
    recovery_id: &str,
    source: &mut dyn CatchUpSource,
    limits: CatchUpLimits,
    now_unix: i64,
    hook: &mut dyn FnMut(MachinePoint) -> Result<(), Crash>,
) -> Result<CatchUpReport, ReplayError> {
    let status = rebootstrap_status(conn, group)?
        .filter(|s| s.recovery_id == recovery_id)
        .ok_or_else(|| ReplayError::NotRunnable("no such rebootstrap".into()))?;
    match status.state {
        RebootstrapState::Replaying => {
            return Ok(CatchUpReport { passes: 0, end: CatchUpEnd::AlreadyOver })
        }
        RebootstrapState::CatchingUp => {}
        other => return Err(ReplayError::NotRunnable(format!("it is {other:?}"))),
    }
    let _busy = match acquire(conn, group) {
        Ok(guard) => guard,
        Err(BusyOrStore::Busy) => return Err(ReplayError::Busy),
        Err(BusyOrStore::Store(error)) => return Err(ReplayError::Store(error)),
    };
    let started = Instant::now();
    let mut passes = 0u32;
    let end = loop {
        if passes >= limits.max_passes {
            break CatchUpEnd::PassLimit;
        }
        let Some(left) = limits.budget.checked_sub(started.elapsed()).filter(|d| !d.is_zero())
        else {
            break CatchUpEnd::Budget;
        };
        let pass = source.pass(limits.per_pass.min(left));
        passes += 1;
        let pass = match pass {
            Ok(pass) => pass,
            Err(_) => break CatchUpEnd::SourceFailed,
        };
        hook(MachinePoint::AfterPass(passes)).map_err(|_| ReplayError::Crashed)?;
        if pass.obtained == 0 {
            break CatchUpEnd::Drained;
        }
    };
    hook(MachinePoint::BeforeReplaying).map_err(|_| ReplayError::Crashed)?;
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let still = rebootstrap_status(&tx, group)?;
    if still.as_ref().map(|s| (&s.state, s.recovery_id.as_str()))
        != Some((&RebootstrapState::CatchingUp, recovery_id))
    {
        return Err(ReplayError::NotRunnable("the stage moved".into()));
    }
    set_state(&tx, group, "replaying", now_unix)?;
    tx.commit()?;
    Ok(CatchUpReport { passes, end })
}

// --- the steps ------------------------------------------------------------------------------

/// What one op of an old own delta intends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayIntent {
    pub path: SyncPath,
    pub put: Option<VersionHash>,
    /// The heads the old op removed, as the old delta named them.
    pub removes: Vec<HeadRef>,
}

/// One old own delta of the manifest, the intents of its ops and its unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayStep {
    /// The step's place in the manifest's order, and its row of the replay table.
    pub ordinal: usize,
    pub old_delta: DeltaHash,
    pub old_author: AuthorId,
    pub unit: usize,
    pub recursive: Option<ManifestRecursive>,
    pub intents: Vec<ReplayIntent>,
}

/// The replay steps of `manifest`, in the manifest's order.
pub fn replay_steps(manifest: &Manifest) -> Vec<ReplayStep> {
    let mut intents: BTreeMap<DeltaHash, Vec<(usize, ReplayIntent)>> = BTreeMap::new();
    for item in &manifest.items {
        intents.entry(item.delta).or_default().push((
            item.op_index,
            ReplayIntent {
                path: SyncPath(item.path.clone()),
                put: item.put_version,
                removes: item
                    .removes
                    .iter()
                    .map(|r| HeadRef {
                        dot: Dot { author: r.author.clone(), seq: AuthorSeq(r.seq) },
                        provenance: r.header,
                    })
                    .collect(),
            },
        ));
    }
    manifest
        .delta_order
        .iter()
        .enumerate()
        .map(|(ordinal, hash)| {
            let delta = &manifest.deltas[ordinal];
            let mut ops = intents.remove(hash).unwrap_or_default();
            ops.sort_by_key(|(index, _)| *index);
            ReplayStep {
                ordinal,
                old_delta: *hash,
                old_author: delta.author.clone(),
                unit: delta.unit,
                recursive: delta.recursive,
                intents: ops.into_iter().map(|(_, intent)| intent).collect(),
            }
        })
        .collect()
}

/// The number of steps no outcome is recorded for: the replay is complete at zero.
pub fn outstanding_steps(conn: &Connection, group: &FolderGroupId) -> Result<u64, SyncSqliteError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM native_rebootstrap_delta WHERE group_id = ?1 AND outcome IS NULL",
        [group.as_str()],
        |row| row.get::<_, i64>(0),
    )? as u64)
}

/// The units of `group`'s recovery areas that were not replayed, as `(recovery id, unit)`.
pub fn unreplayed_units(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<Vec<(String, usize)>, SyncSqliteError> {
    Ok(held_unit_rows(conn, group)?.into_iter().map(|(id, unit, _)| (id, unit)).collect())
}

/// `(recovery id, unit, originals quarantined)` of every held unit.
fn held_unit_rows(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<Vec<(String, usize, bool)>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT recovery_id, unit, originals_quarantined FROM native_unreplayed_unit \
         WHERE group_id = ?1 ORDER BY recovery_id, unit",
    )?;
    let rows = stmt.query_map([group.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize, row.get::<_, i64>(2)? != 0))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// An own unit of a rebootstrap that was not replayed, and what remains of it on this device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldOwnUnit {
    pub recovery_id: String,
    pub unit: usize,
    /// The paths the unit's operations touch.
    pub paths: Vec<String>,
    /// An original of the unit was moved out of the folder into the recovery area, as the
    /// quarantine recorded it (a unit that only failed later left them in place).
    pub originals_quarantined: bool,
}

/// The own units `group`'s rebootstraps did not replay, read from their recovery areas. The
/// areas hold the signed deltas and the bytes of these units; nothing sweeps them while a unit
/// is listed.
pub fn held_own_units(
    conn: &Connection,
    recovery_root: &Path,
    group: &FolderGroupId,
) -> Result<Vec<HeldOwnUnit>, SyncSqliteError> {
    let mut out = Vec::new();
    for (recovery_id, unit, originals_quarantined) in held_unit_rows(conn, group)? {
        let area = RecoveryArea::open_existing(recovery_root, group, &recovery_id)
            .map_err(|e| SyncSqliteError::CorruptState(e.to_string()))?;
        let manifest = Manifest::from_bytes(
            &area
                .read_manifest_bytes()
                .map_err(|e| SyncSqliteError::CorruptState(e.to_string()))?,
        )
        .map_err(|e| SyncSqliteError::CorruptState(e.to_string()))?;
        let mut paths: Vec<String> = manifest
            .items
            .iter()
            .filter(|item| item.unit == unit)
            .map(|item| item.path.clone())
            .collect();
        paths.sort();
        paths.dedup();
        out.push(HeldOwnUnit { recovery_id, unit, paths, originals_quarantined });
    }
    Ok(out)
}

/// The units of `manifest` this device may replay, judged now: the plan's label and the
/// authority asked again for every path of the unit.
pub(crate) fn units_replayable_now(
    manifest: &Manifest,
    authority: &dyn ReassertAuthority,
) -> Vec<bool> {
    let mut ok: Vec<bool> = manifest.units.iter().map(|unit| unit.reassertable).collect();
    for item in &manifest.items {
        if ok[item.unit]
            && authority.classify(&SyncPath(item.path.clone())) != Reassertability::Reassertable
        {
            ok[item.unit] = false;
        }
    }
    ok
}

// --- the replay -----------------------------------------------------------------------------

pub struct ReplayContext<'a> {
    pub recovery_root: &'a Path,
    /// Asked again before each unit.
    pub authority: &'a dyn ReassertAuthority,
    /// The new incarnation and its key. The capture capability is not used.
    pub author: &'a LocalAuthor<'a>,
    pub now_unix: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Steps authored as a delta of the new incarnation by this call.
    pub authored: usize,
    /// Steps recorded moot by this call.
    pub moot: usize,
    /// Units recorded as not replayed by this call.
    pub unreplayed_units: Vec<usize>,
}

/// How a removal of an old op is resolved when the unit is planned.
enum Removal {
    /// The head an earlier step put, named through the new delta that carries the put.
    Mapped(DeltaHash),
    Exact(HeadRef),
}

struct PlannedOp {
    path: SyncPath,
    put: Option<VersionHash>,
    removes: Vec<Removal>,
}

/// Replays what remains of the own intent of the rebootstrap `recovery_id` of `group`, which
/// must be `Replaying`. Units are replayed in ascending order, each whole in one transaction;
/// the authority is asked before each. A crash resumes at the first unit with a step that has no
/// outcome. Returns when none is left; [`crate::native_rebootstrap::finish_rebootstrap`] ends
/// the freeze.
pub fn replay_own_intent(
    conn: &Connection,
    ctx: &ReplayContext<'_>,
    group: &FolderGroupId,
    recovery_id: &str,
    hook: &mut dyn FnMut(MachinePoint) -> Result<(), Crash>,
) -> Result<ReplayReport, ReplayError> {
    let status = rebootstrap_status(conn, group)?
        .filter(|s| s.recovery_id == recovery_id)
        .ok_or_else(|| ReplayError::NotRunnable("no such rebootstrap".into()))?;
    if status.state != RebootstrapState::Replaying {
        return Err(ReplayError::NotRunnable(format!("it is {:?}", status.state)));
    }
    let _busy = match acquire(conn, group) {
        Ok(guard) => guard,
        Err(BusyOrStore::Busy) => return Err(ReplayError::Busy),
        Err(BusyOrStore::Store(error)) => return Err(ReplayError::Store(error)),
    };
    let preserved =
        resume_preserved(conn, ctx.recovery_root, group).map_err(ReplayError::Blocked)?;
    let area = RecoveryArea::open_dir(&preserved.dir)
        .map_err(|e| ReplayError::Blocked(crate::native_rebootstrap::area_failure(e)))?;
    let manifest = area
        .read_intent()
        .map_err(|e| ReplayError::Blocked(crate::native_rebootstrap::area_failure(e)))?
        .manifest;
    let steps = replay_steps(&manifest);
    let mut by_unit: BTreeMap<usize, Vec<&ReplayStep>> = BTreeMap::new();
    for step in &steps {
        by_unit.entry(step.unit).or_default().push(step);
    }
    let mut report = ReplayReport::default();
    loop {
        let decided = decided_ordinals(conn, group)?;
        let Some((&unit, members)) = by_unit
            .iter()
            .find(|(_, members)| members.iter().any(|s| !decided.contains(&s.ordinal)))
        else {
            break;
        };
        hook(MachinePoint::BeforeUnit(unit)).map_err(|_| ReplayError::Crashed)?;
        // The authority is asked here, immediately before the unit and never inside it.
        let authorized = manifest.units[unit].reassertable
            && members.iter().flat_map(|s| &s.intents).all(|intent| {
                ctx.authority.classify(&intent.path) == Reassertability::Reassertable
            });
        let replayed = if authorized {
            replay_unit(conn, ctx, group, recovery_id, unit, members, hook)?
        } else {
            None
        };
        match replayed {
            Some(outcome) => {
                report.authored += outcome.authored;
                report.moot += outcome.moot;
                hook(MachinePoint::AfterUnit(unit)).map_err(|_| ReplayError::Crashed)?;
            }
            None => {
                record_unreplayed(conn, group, recovery_id, unit, members)?;
                report.unreplayed_units.push(unit);
            }
        }
    }
    Ok(report)
}

#[derive(Debug)]
pub enum RetryError {
    /// No held unit has this recovery id and number: it never was one, or it was resolved.
    NotHeld,
    /// This device is not a Writer for every path of the unit now.
    NotAWriter,
    /// A rebootstrap of the group is running; it owns the group until it ends.
    RebootstrapRunning,
    /// The installed state refuses the unit; it stays held.
    Refused,
    Blocked(BlockedReason),
    /// The unit's preserved bytes could not be imported; the unit stays held.
    Import(String),
    Crashed,
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for RetryError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

impl From<rusqlite::Error> for RetryError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

/// Retries one own unit a rebootstrap held, once its rebootstrap is over: the authority is asked
/// now for every path of the unit, and the unit goes through the same scheduler as the replay
/// (whole in one transaction, recomputed against the installed state, authored as the current
/// incarnation). The unit's record is deleted in that transaction, so a crash leaves it held
/// with nothing authored, or authored and resolved, never both authored and held. The
/// recovery area stays: only the user's own action deletes preserved data.
///
/// The bytes of the unit's put versions live in the recovery area, not in the block store (the
/// install dropped the references the old heads held), so before anything is authored each of
/// them is read back from the area, checked against the manifest and handed to `import`, which
/// stores its blocks and records their provenance in this transaction. The caller holds the
/// block store's write-activity guard across the whole call, so no sweep can delete what was
/// imported before the authored heads reference it. An import that fails ends the retry with
/// nothing authored; blocks already stored are unreferenced and the next retry stores them again.
pub fn retry_replay_unit(
    conn: &Connection,
    ctx: &ReplayContext<'_>,
    group: &FolderGroupId,
    recovery_id: &str,
    unit: usize,
    import: &mut UnitImport<'_>,
    hook: &mut dyn FnMut(MachinePoint) -> Result<(), Crash>,
) -> Result<ReplayReport, RetryError> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    if rebootstrap_status(&tx, group)?.is_some() {
        return Err(RetryError::RebootstrapRunning);
    }
    let held: i64 = tx.query_row(
        "SELECT COUNT(*) FROM native_unreplayed_unit \
         WHERE group_id = ?1 AND recovery_id = ?2 AND unit = ?3",
        (group.as_str(), recovery_id, unit as i64),
        |row| row.get(0),
    )?;
    if held == 0 {
        return Err(RetryError::NotHeld);
    }
    let area = RecoveryArea::open_existing(ctx.recovery_root, group, recovery_id)
        .map_err(|e| RetryError::Blocked(crate::native_rebootstrap::area_failure(e)))?;
    let manifest = Manifest::from_bytes(
        &area
            .read_manifest_bytes()
            .map_err(|e| RetryError::Blocked(crate::native_rebootstrap::area_failure(e)))?,
    )
    .map_err(|e| SyncSqliteError::CorruptState(e.to_string()))?;
    let steps = replay_steps(&manifest);
    let members: Vec<&ReplayStep> = steps.iter().filter(|step| step.unit == unit).collect();
    // The same question the replay asks before each unit, asked now.
    if !members
        .iter()
        .flat_map(|s| &s.intents)
        .all(|intent| ctx.authority.classify(&intent.path) == Reassertability::Reassertable)
    {
        return Err(RetryError::NotAWriter);
    }
    import_unit_versions(&area, &manifest, &members, import)?;
    hook(MachinePoint::AfterImport(unit)).map_err(|_| RetryError::Crashed)?;
    let outcome =
        match author_unit(&tx, ctx, group, recovery_id, unit, &members, Admission::Local, hook) {
            Ok(Some(outcome)) => outcome,
            Ok(None) => return Err(RetryError::Refused),
            Err(ReplayError::Crashed) => return Err(RetryError::Crashed),
            Err(ReplayError::Store(error)) => return Err(RetryError::Store(error)),
            Err(ReplayError::Busy) => return Err(RetryError::RebootstrapRunning),
            Err(ReplayError::Blocked(reason)) => return Err(RetryError::Blocked(reason)),
            Err(ReplayError::NotRunnable(why)) => {
                return Err(RetryError::Store(SyncSqliteError::CorruptState(why)))
            }
        };
    tx.execute(
        "DELETE FROM native_unreplayed_unit WHERE group_id = ?1 AND recovery_id = ?2 AND unit = ?3",
        (group.as_str(), recovery_id, unit as i64),
    )?;
    hook(MachinePoint::BeforeResolve(unit)).map_err(|_| RetryError::Crashed)?;
    tx.commit()?;
    Ok(ReplayReport {
        authored: outcome.authored,
        moot: outcome.moot,
        unreplayed_units: Vec::new(),
    })
}

/// Stores one preserved file version's bytes: its record and the whole content, already checked
/// against the manifest. Returns why it could not.
pub type UnitImport<'a> =
    dyn FnMut(&FileVersion, &mut dyn std::io::Read) -> Result<(), String> + 'a;

/// Reads every file version the unit puts back from the recovery area, checks it against the
/// manifest, and imports it. A version the manifest does not list, or lists without bytes, is
/// an inconsistent area: the unit is not authored over content that cannot be obtained.
fn import_unit_versions(
    area: &RecoveryArea,
    manifest: &Manifest,
    members: &[&ReplayStep],
    import: &mut UnitImport<'_>,
) -> Result<(), RetryError> {
    let inconsistent =
        |detail: String| RetryError::Blocked(BlockedReason::ManifestInconsistent { detail });
    let blocked = |e| RetryError::Blocked(crate::native_rebootstrap::area_failure(e));
    let mut seen = BTreeSet::new();
    for version in members.iter().flat_map(|s| &s.intents).filter_map(|i| i.put) {
        if !seen.insert(version) {
            continue;
        }
        let entry = manifest
            .versions
            .iter()
            .find(|v| v.version == version)
            .ok_or_else(|| inconsistent("a put version is not in the manifest".into()))?;
        let record = area.read_record(&version).map_err(blocked)?;
        if entry.record_kind != record.meta.record_kind.as_db_str() {
            return Err(inconsistent("a version record does not match the manifest".into()));
        }
        if record.meta.record_kind != RecordKind::File {
            continue;
        }
        if !entry.has_bytes {
            return Err(inconsistent("a file version of the unit has no preserved bytes".into()));
        }
        // Checked against the manifest by hashing through one fixed buffer, then streamed to
        // the import: the preserved bytes are never held whole.
        if !area.version_matches(&version, &entry.sha256, entry.size).map_err(blocked)? {
            return Err(inconsistent("a preserved version does not match the manifest".into()));
        }
        let mut file = area.open_version(&version).map_err(blocked)?;
        import(&record, &mut file).map_err(RetryError::Import)?;
    }
    Ok(())
}

fn decided_ordinals(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<BTreeSet<usize>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT ordinal FROM native_rebootstrap_delta WHERE group_id = ?1 AND outcome IS NOT NULL",
    )?;
    let rows = stmt.query_map([group.as_str()], |row| Ok(row.get::<_, i64>(0)? as usize))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn record_unreplayed(
    conn: &Connection,
    group: &FolderGroupId,
    recovery_id: &str,
    unit: usize,
    members: &[&ReplayStep],
) -> Result<(), SyncSqliteError> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    for step in members {
        tx.execute(
            "UPDATE native_rebootstrap_delta SET outcome = 'unreplayed' \
             WHERE group_id = ?1 AND ordinal = ?2 AND outcome IS NULL",
            (group.as_str(), step.ordinal as i64),
        )?;
    }
    let mut quarantined = false;
    for step in members {
        for intent in &step.intents {
            quarantined |= tx.query_row(
                "SELECT COUNT(*) FROM native_rebootstrap_quarantine \
                 WHERE group_id = ?1 AND recovery_id = ?2 AND path = ?3 \
                   AND status IN ('removed', 'removed_late_edit', 'retained')",
                (group.as_str(), recovery_id, intent.path.as_str()),
                |row| row.get::<_, i64>(0),
            )? > 0;
        }
    }
    tx.execute(
        "INSERT OR IGNORE INTO native_unreplayed_unit \
         (group_id, recovery_id, unit, originals_quarantined) VALUES (?1, ?2, ?3, ?4)",
        (group.as_str(), recovery_id, unit as i64, quarantined),
    )?;
    tx.commit()?;
    Ok(())
}

struct UnitOutcome {
    authored: usize,
    moot: usize,
}

/// The id of the fresh operation the residual parts of an old operation become: the same on
/// every attempt, so a resume never splits an operation across two ids.
fn fresh_operation_id(
    recovery_id: &str,
    old_author: &AuthorId,
    old: [u8; 16],
) -> RecursiveOperationId {
    let mut bytes = Vec::new();
    bytes.extend(b"replayed recursive operation");
    for part in [
        recovery_id.as_bytes(),
        old_author.device.as_str().as_bytes(),
        &old_author.incarnation.0,
        &old,
    ] {
        bytes.extend((part.len() as u64).to_be_bytes());
        bytes.extend(part);
    }
    let digest = sha256(&bytes);
    RecursiveOperationId(digest[..16].try_into().expect("16 bytes"))
}

fn is_live(state: &NativeState, path: &SyncPath, head: &HeadRef) -> bool {
    state.heads_at(path).any(|h| h.dot == head.dot && h.payload.provenance == head.provenance)
}

/// Authors every step of `unit` in one transaction. `None`: the unit cannot be authored (a
/// delta the install refuses), nothing was written, and the caller records it unreplayed.
fn replay_unit(
    conn: &Connection,
    ctx: &ReplayContext<'_>,
    group: &FolderGroupId,
    recovery_id: &str,
    unit: usize,
    members: &[&ReplayStep],
    hook: &mut dyn FnMut(MachinePoint) -> Result<(), Crash>,
) -> Result<Option<UnitOutcome>, ReplayError> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let still = rebootstrap_status(&tx, group)?;
    if still.as_ref().map(|s| (&s.state, s.recovery_id.as_str()))
        != Some((&RebootstrapState::Replaying, recovery_id))
    {
        return Err(ReplayError::NotRunnable("the stage moved".into()));
    }
    let marker = InstallAuthority::issue(&tx, group, recovery_id)?;
    let outcome = author_unit(
        &tx,
        ctx,
        group,
        recovery_id,
        unit,
        members,
        Admission::RebootstrapInstall(&marker),
        hook,
    )?;
    if outcome.is_some() {
        tx.commit()?;
    }
    Ok(outcome)
}

/// The scheduler of one unit, inside the caller's transaction, which the caller commits: every
/// step of the unit is planned against the installed state and authored, or none is. Used by
/// the replay and by the retry of a held unit, so there is one way a unit is authored.
#[allow(clippy::too_many_arguments)]
fn author_unit(
    tx: &Connection,
    ctx: &ReplayContext<'_>,
    group: &FolderGroupId,
    recovery_id: &str,
    unit: usize,
    members: &[&ReplayStep],
    admission: Admission<'_>,
    hook: &mut dyn FnMut(MachinePoint) -> Result<(), Crash>,
) -> Result<Option<UnitOutcome>, ReplayError> {
    if decided_ordinals(tx, group)?.iter().any(|o| members.iter().any(|s| s.ordinal == *o)) {
        return Err(ReplayError::Store(SyncSqliteError::CorruptState(
            "a unit of the replay is partly decided".into(),
        )));
    }
    let author = &ctx.author.author;
    if crate::author_incarnation::current_author(tx)? != *author {
        return Err(ReplayError::NotRunnable(
            "the replay is not signed by this device's current incarnation".into(),
        ));
    }

    // The head map: the new delta that carries the put of each old delta authored so far.
    let mut head_map: BTreeMap<DeltaHash, HeadRef> = BTreeMap::new();
    {
        let mut stmt = tx.prepare(
            "SELECT old_delta_hash, new_seq, new_delta_hash FROM native_rebootstrap_delta \
             WHERE group_id = ?1 AND outcome = 'authored'",
        )?;
        let rows = stmt.query_map([group.as_str()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?))
        })?;
        for row in rows {
            let (old, seq, new) = row?;
            head_map.insert(
                DeltaHash(crate::native_store::as_array32(&old)?),
                HeadRef {
                    dot: Dot { author: author.clone(), seq: AuthorSeq(seq as u64) },
                    provenance: DeltaHash(crate::native_store::as_array32(&new)?),
                },
            );
        }
    }

    // Plan every step of the unit against the state the install left.
    let paths: Vec<&SyncPath> =
        members.iter().flat_map(|s| s.intents.iter().map(|i| &i.path)).collect();
    let state = crate::native_store::load_heads_at_paths(tx, group, &paths)?;
    let mut mapped_old: BTreeSet<DeltaHash> = head_map.keys().copied().collect();
    let mut planned: Vec<Option<Vec<PlannedOp>>> = Vec::new();
    for step in members {
        let mut ops = Vec::new();
        for intent in &step.intents {
            let removes: Vec<Removal> = intent
                .removes
                .iter()
                .filter_map(|head| {
                    if mapped_old.contains(&head.provenance) {
                        Some(Removal::Mapped(head.provenance))
                    } else if is_live(&state, &intent.path, head) {
                        Some(Removal::Exact(head.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            if intent.put.is_some() || !removes.is_empty() {
                ops.push(PlannedOp { path: intent.path.clone(), put: intent.put, removes });
            }
        }
        if ops.is_empty() {
            planned.push(None);
        } else {
            mapped_old.insert(step.old_delta);
            planned.push(Some(ops));
        }
    }

    // The residual parts of one old operation: a fresh operation, numbered from zero.
    let mut part_total: BTreeMap<[u8; 16], u32> = BTreeMap::new();
    for (step, plan) in members.iter().zip(&planned) {
        if let (Some(part), Some(_)) = (step.recursive, plan) {
            *part_total.entry(part.operation_id).or_default() += 1;
        }
    }
    let mut part_next: BTreeMap<[u8; 16], u32> = BTreeMap::new();

    let mut authored = 0usize;
    let mut moot = 0usize;
    for (step, plan) in members.iter().zip(planned) {
        let Some(plan) = plan else {
            tx.execute(
                "UPDATE native_rebootstrap_delta SET outcome = 'moot' \
                 WHERE group_id = ?1 AND ordinal = ?2",
                (group.as_str(), step.ordinal as i64),
            )?;
            moot += 1;
            continue;
        };
        let ops: Vec<DeltaOp> = plan
            .into_iter()
            .map(|op| DeltaOp {
                path: op.path,
                removes: op
                    .removes
                    .into_iter()
                    .filter_map(|removal| match removal {
                        Removal::Exact(head) => Some(head),
                        Removal::Mapped(old) => head_map.get(&old).cloned(),
                    })
                    .collect(),
                put: op.put.map(|version| DeltaPut { version }),
            })
            .collect();
        let recursive_part = step.recursive.map(|part| {
            let index = part_next.entry(part.operation_id).or_default();
            let fresh = RecursivePart {
                operation_id: fresh_operation_id(recovery_id, &step.old_author, part.operation_id),
                part_index: *index,
                part_count: part_total[&part.operation_id],
            };
            *index += 1;
            fresh
        });
        let current = crate::native_store::frontier_entry_get(tx, group, author)?;
        let seq = match &current {
            None => AuthorSeq::FIRST,
            Some(entry) => entry.seq.checked_next().ok_or_else(|| {
                SyncSqliteError::InvalidInput("the author has reached the highest sequence".into())
            })?,
        };
        let mut delta = NativeDelta {
            recursive_part,
            group_id: group.clone(),
            author: author.clone(),
            seq,
            prev: current.map(|entry| entry.tip),
            ops,
            signature: [0; 64],
        };
        delta.sign(ctx.author.signing_key);
        match crate::native_store::install_authored_delta(
            tx,
            group,
            &delta,
            &ctx.author.signing_key.verifying_key(),
            admission,
        ) {
            Ok(_) => {}
            // The installed state refuses this delta (a bound the old state did not reach):
            // the unit stays unreplayed, and nothing of it is written.
            Err(SyncSqliteError::InvalidInput(_)) => return Ok(None),
            Err(other) => return Err(other.into()),
        }
        crate::native_desired_state::arm_projection_for_delta(tx, group.as_str(), &delta, true)?;
        head_map
            .insert(step.old_delta, HeadRef { dot: delta.dot(), provenance: delta.delta_hash() });
        tx.execute(
            "UPDATE native_rebootstrap_delta SET outcome = 'authored', new_seq = ?3, \
             new_delta_hash = ?4 WHERE group_id = ?1 AND ordinal = ?2",
            (
                group.as_str(),
                step.ordinal as i64,
                delta.seq.get() as i64,
                delta.delta_hash().0.as_slice(),
            ),
        )?;
        authored += 1;
        hook(MachinePoint::InUnit { unit, ordinal: step.ordinal })
            .map_err(|_| ReplayError::Crashed)?;
    }
    Ok(Some(UnitOutcome { authored, moot }))
}
