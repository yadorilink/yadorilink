//! The record of versions this device no longer keeps.
//!
//! A path's retained versions are not necessarily an unbroken run: the retention expiry removes the
//! old ones around a version a lease still protects. Without a record, asking for the state of a
//! path at a time that falls in such a gap silently selects the nearest surviving older version, and
//! asking for a removed version by sequence cannot tell it from one that never existed. So whatever
//! the index drops is recorded here, one row per event (one expiry's removal of one run of one
//! path's versions), never merged when written, in the transaction that drops the rows.
//!
//! A row covers a span of time, `[from_unix_nanos, to_unix_nanos)`: the time the dropped versions
//! were current, from the admission of the oldest dropped one to the admission of the version that
//! followed the newest. Boundaries and neighbours are taken in the order the rewind planner uses,
//! `(admitted_at DESC, version_seq DESC)`. The clock can run backwards (admission times come from
//! the system clock), so when the dropped versions and their neighbours are not in the same order
//! by time and by sequence the span is widened to cover every time at which the planner could land
//! on one of them. A missing admission time makes that side unbounded (NULL): never narrower than
//! the truth. A row also covers a range of sequence numbers `[from_seq, to_seq)` for the explicit
//! restore of a version by number.

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;

use crate::error::SyncSqliteError;

const NANOS_PER_SEC: i64 = 1_000_000_000;
const NANOS_PER_DAY: i64 = 86_400 * NANOS_PER_SEC;
/// A row whose path has no version left in the index is removed once the end of its span is older
/// than this (the same bound as the retention age).
const ABSENT_PATH_AGE_DAYS: i64 = 30;

/// Why a version is not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FreedReason {
    /// The retention rule removed it (older than 30 days and more than 10 newer versions).
    Expired,
    /// There was no room on the disk to keep it.
    LowSpace,
}

impl FreedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            FreedReason::Expired => "Expired",
            FreedReason::LowSpace => "LowSpace",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "Expired" => Some(FreedReason::Expired),
            "LowSpace" => Some(FreedReason::LowSpace),
            _ => None,
        }
    }

    /// What a person is told.
    pub fn words(self) -> &'static str {
        match self {
            FreedReason::Expired => "the retention period ended",
            FreedReason::LowSpace => "the disk was nearly full",
        }
    }
}

/// One recorded event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreedSpan {
    pub reason: FreedReason,
    /// First instant at which a dropped version was current; `None` is unbounded below.
    pub from_unix_nanos: Option<i64>,
    /// Instant the version after the dropped ones was admitted; `None` is unbounded above.
    pub to_unix_nanos: Option<i64>,
    pub from_seq: i64,
    pub to_seq: i64,
    pub recorded_unix: i64,
}

impl FreedSpan {
    /// Whether a rewind to `at_unix_nanos` lands inside this span.
    pub fn covers_time(&self, at_unix_nanos: i64) -> bool {
        self.from_unix_nanos.is_none_or(|from| from <= at_unix_nanos)
            && self.to_unix_nanos.is_none_or(|to| at_unix_nanos < to)
    }

    /// Whether version number `seq` lies in the range of versions this event dropped.
    pub fn covers_seq(&self, seq: i64) -> bool {
        self.from_seq <= seq && seq < self.to_seq
    }
}

/// One stored version of a path, as the span computation needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Member {
    pub seq: i64,
    pub admitted: Option<i64>,
}

/// The rows to write for the dropped versions `dropped` of one path whose complete set of rows is
/// `rows`: one run (and one row) per maximal stretch, in the planner's order, of dropped versions.
pub(crate) fn runs(rows: &[Member], dropped: &HashSet<i64>) -> Vec<Run> {
    // The planner's order: newest admission first, a larger sequence first on a tie; an unstamped
    // row (no admission time) sorts as the oldest.
    let mut order: Vec<Member> = rows.to_vec();
    order.sort_by(|a, b| {
        b.admitted.unwrap_or(i64::MIN).cmp(&a.admitted.unwrap_or(i64::MIN)).then(b.seq.cmp(&a.seq))
    });
    let mut out = Vec::new();
    let mut i = 0;
    while i < order.len() {
        if !dropped.contains(&order[i].seq) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j + 1 < order.len() && dropped.contains(&order[j + 1].seq) {
            j += 1;
        }
        out.push(run_of(&order, rows, i, j));
        i = j + 1;
    }
    out
}

/// A run's span, before it is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Run {
    pub from_unix_nanos: Option<i64>,
    pub to_unix_nanos: Option<i64>,
    pub from_seq: i64,
    pub to_seq: i64,
}

fn run_of(order: &[Member], all: &[Member], i: usize, j: usize) -> Run {
    let segment = &order[i..=j];
    let successor = if i > 0 { Some(order[i - 1]) } else { None };
    let older = order.get(j + 1).copied();
    let (min_seq, max_seq) =
        segment.iter().fold((i64::MAX, i64::MIN), |(lo, hi), m| (lo.min(m.seq), hi.max(m.seq)));
    // The neighbours by sequence, which differ from the neighbours by time when the clock ran
    // backwards.
    let in_segment: HashSet<i64> = segment.iter().map(|m| m.seq).collect();
    let below = all
        .iter()
        .filter(|m| m.seq < min_seq && !in_segment.contains(&m.seq))
        .max_by_key(|m| m.seq);
    let above = all
        .iter()
        .filter(|m| m.seq > max_seq && !in_segment.contains(&m.seq))
        .min_by_key(|m| m.seq);

    let mut considered: Vec<Member> = segment.to_vec();
    considered.extend(successor);
    considered.extend(older);
    considered.extend(below.copied());
    considered.extend(above.copied());
    considered.sort_by_key(|m| m.seq);
    considered.dedup_by_key(|m| m.seq);

    let mut by_time = considered.clone();
    by_time.sort_by(|a, b| {
        b.admitted.unwrap_or(i64::MIN).cmp(&a.admitted.unwrap_or(i64::MIN)).then(b.seq.cmp(&a.seq))
    });
    let mut by_seq = considered.clone();
    by_seq.sort_by_key(|m| std::cmp::Reverse(m.seq));
    let ordered = by_time == by_seq;

    if ordered {
        let oldest = order[j];
        return Run {
            from_unix_nanos: oldest.admitted,
            to_unix_nanos: successor.and_then(|s| s.admitted),
            from_seq: min_seq,
            to_seq: successor.map_or(i64::MAX, |s| s.seq),
        };
    }
    // Widened: every time at which the planner could land on a dropped version.
    let from = if considered.iter().any(|m| m.admitted.is_none()) {
        None
    } else {
        considered.iter().filter_map(|m| m.admitted).min()
    };
    let to = if successor.is_some_and(|s| s.admitted.is_none()) || successor.is_none() {
        None
    } else {
        considered.iter().filter_map(|m| m.admitted).max()
    };
    Run {
        from_unix_nanos: from,
        to_unix_nanos: to,
        from_seq: considered.iter().map(|m| m.seq).min().unwrap_or(min_seq),
        to_seq: considered.iter().map(|m| m.seq).max().map_or(i64::MAX, |m| m.saturating_add(1)),
    }
}

/// Records the removal of `dropped` from `path` (whose rows, all of them, are `rows`), in the
/// caller's transaction. One row per run. `now_unix_nanos` stamps the rows.
pub(crate) fn record(
    tx: &Connection,
    group_id: &str,
    path: &str,
    rows: &[Member],
    dropped: &HashSet<i64>,
    reason: FreedReason,
    now_unix_nanos: i64,
) -> Result<usize, SyncSqliteError> {
    let recorded_unix = now_unix_nanos.div_euclid(NANOS_PER_SEC);
    let runs = runs(rows, dropped);
    for run in &runs {
        tx.execute(
            "INSERT INTO history_freed (group_id, path, from_unix_nanos, to_unix_nanos, from_seq, \
             to_seq, reason, recorded_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                group_id,
                path,
                run.from_unix_nanos,
                run.to_unix_nanos,
                run.from_seq,
                run.to_seq,
                reason.as_str(),
                recorded_unix,
            ],
        )?;
    }
    Ok(runs.len())
}

/// Removes rows that no longer say anything: those about a path with no version left in the index
/// whose span ended more than the retention age ago. A row is never dropped for its age alone: the
/// rewind planner has no lookback limit, so a gap whose record is gone would be answered with the
/// nearest older survivor again.
pub(crate) fn prune(
    tx: &Connection,
    group_id: &str,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "DELETE FROM history_freed WHERE group_id = ?1 AND to_unix_nanos IS NOT NULL \
         AND to_unix_nanos < ?2 \
         AND NOT EXISTS (SELECT 1 FROM files f WHERE f.group_id = history_freed.group_id \
                         AND f.path = history_freed.path)",
        rusqlite::params![
            group_id,
            now_unix_nanos.saturating_sub(ABSENT_PATH_AGE_DAYS * NANOS_PER_DAY)
        ],
    )?;
    Ok(())
}

fn span_of_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<FreedSpan>> {
    let reason: String = row.get(4)?;
    let Some(reason) = FreedReason::parse(&reason) else { return Ok(None) };
    Ok(Some(FreedSpan {
        from_unix_nanos: row.get(0)?,
        to_unix_nanos: row.get(1)?,
        from_seq: row.get(2)?,
        to_seq: row.get(3)?,
        reason,
        recorded_unix: row.get(5)?,
    }))
}

/// How many versions of the group were not kept for lack of space, among the events recorded at or
/// after `since_unix` (seconds). One `LowSpace` row is one version.
pub fn count_low_space_since(
    conn: &Connection,
    group_id: &str,
    since_unix: i64,
) -> Result<u32, SyncSqliteError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM history_freed \
         WHERE group_id = ?1 AND reason = 'LowSpace' AND recorded_unix >= ?2",
        rusqlite::params![group_id, since_unix],
        |r| r.get(0),
    )?;
    Ok(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Every recorded event of the group, by path.
pub fn spans_by_path(
    conn: &Connection,
    group_id: &str,
) -> Result<HashMap<String, Vec<FreedSpan>>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT from_unix_nanos, to_unix_nanos, from_seq, to_seq, reason, recorded_unix, path \
         FROM history_freed WHERE group_id = ?1 ORDER BY event_id",
    )?;
    let rows = stmt.query_map([group_id], |r| Ok((span_of_row(r)?, r.get::<_, String>(6)?)))?;
    let mut out: HashMap<String, Vec<FreedSpan>> = HashMap::new();
    for row in rows {
        let (span, path) = row?;
        if let Some(span) = span {
            out.entry(path).or_default().push(span);
        }
    }
    Ok(out)
}

/// The recorded event that dropped version number `seq` of `path`, if one did.
pub fn span_covering_seq(
    conn: &Connection,
    group_id: &str,
    path: &str,
    seq: i64,
) -> Result<Option<FreedSpan>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT from_unix_nanos, to_unix_nanos, from_seq, to_seq, reason, recorded_unix \
         FROM history_freed WHERE group_id = ?1 AND path = ?2 AND from_seq <= ?3 AND ?3 < to_seq \
         ORDER BY event_id DESC",
    )?;
    let mut rows = stmt.query_map(rusqlite::params![group_id, path, seq], span_of_row)?;
    match rows.next() {
        Some(row) => Ok(row?),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests;
