//! The history floor: which trusted checkpoint a replica treats as the boundary of
//! the history it keeps.
//!
//! The marker only names a checkpoint. The per-author floor is read through it, from
//! that checkpoint's rows in `native_checkpoint_frontier`: for an author-incarnation
//! the floor sequence and floor tip are the sequence and tip of its row there.
//!
//! Trusted checkpoints are partially ordered by frontier dominance, not by the time
//! they were adopted: two writers sealing during a partition produce checkpoints
//! neither of which covers the other. Every decision here reads dominance only.
//!
//! Nothing in this module discards anything. It records the floor, answers what the
//! floor is, and states the pure rule for when a further trusted checkpoint may
//! become the floor; no background task calls that rule.

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::native_frontier::{NativeAuthorFrontier, NativeAuthorFrontierEntry};

use crate::error::SyncSqliteError;
use crate::native_checkpoint_frontier::{checkpoint_coverage, checkpoint_frontier};

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- Which trusted checkpoint is this replica's history floor: one row per
        -- group, naming the checkpoint and committing to the frontier root its
        -- rows recompute to. The per-author floor is that checkpoint's rows in
        -- native_checkpoint_frontier, never stored here.
        CREATE TABLE IF NOT EXISTS native_history_floor (
            group_id              TEXT PRIMARY KEY,
            checkpoint_id         BLOB NOT NULL,
            floor_frontier_root   BLOB NOT NULL,
            adopted_at_unixtime   INTEGER NOT NULL
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

/// The history floor marker of a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryFloor {
    pub checkpoint_id: [u8; 32],
    /// The author-state root the checkpoint's rows recompute to.
    pub floor_frontier_root: [u8; 32],
    pub adopted_at_unixtime: i64,
}

/// The floor marker of `group_id`, if one was adopted.
pub fn history_floor(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Option<HistoryFloor>, SyncSqliteError> {
    let row = conn
        .query_row(
            "SELECT checkpoint_id, floor_frontier_root, adopted_at_unixtime \
             FROM native_history_floor WHERE group_id = ?1",
            [group_id.as_str()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?)),
        )
        .optional()?;
    row.map(|(id, root, at)| {
        Ok(HistoryFloor {
            checkpoint_id: crate::native_store::as_array32(&id)?,
            floor_frontier_root: crate::native_store::as_array32(&root)?,
            adopted_at_unixtime: at,
        })
    })
    .transpose()
}

/// The retained frontier: the per-author vector of the checkpoint the floor marker
/// names. Empty when no floor was adopted.
pub fn retained_frontier(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<NativeAuthorFrontier, SyncSqliteError> {
    match history_floor(conn, group_id)? {
        Some(floor) => checkpoint_frontier(conn, group_id, &floor.checkpoint_id),
        None => Ok(NativeAuthorFrontier::new()),
    }
}

/// The floor entry of one author-incarnation: its row in the floor checkpoint's
/// frontier, or `None` when there is no floor or the checkpoint holds no position
/// for the author.
pub fn floor_entry(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<Option<NativeAuthorFrontierEntry>, SyncSqliteError> {
    conn.query_row(
        "SELECT f.seq, f.tip \
             FROM native_history_floor m \
             JOIN native_checkpoint_frontier f \
               ON f.group_id = m.group_id AND f.checkpoint_id = m.checkpoint_id \
             WHERE m.group_id = ?1 AND f.author = ?2 AND f.incarnation = ?3 \
               AND f.seq IS NOT NULL",
        (group_id.as_str(), author.device.as_str(), author.incarnation.0.as_slice()),
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )
    .optional()?
    .map(|(seq, tip)| {
        Ok::<_, SyncSqliteError>(NativeAuthorFrontierEntry {
            seq: yadorilink_replica_domain::ids::AuthorSeq(seq as u64),
            tip: yadorilink_replica_domain::native_state::DeltaHash(
                crate::native_store::as_array32(&tip)?,
            ),
        })
    })
    .transpose()
}

/// Whether `newer` is at least as far as `older` for every author `older` holds:
/// the same or a higher sequence, and the same tip where the sequences are equal.
pub fn frontier_covers(newer: &NativeAuthorFrontier, older: &NativeAuthorFrontier) -> bool {
    older.iter().all(|(author, old)| {
        newer
            .get(author)
            .is_some_and(|new| new.seq > old.seq || (new.seq == old.seq && new.tip == old.tip))
    })
}

/// Names `checkpoint_id` as this replica's history floor.
///
/// Refused, with nothing written, unless the checkpoint is trusted (adopted with
/// verified seal evidence), its frontier rows are present and recompute to the
/// roots it committed, this replica's own frontier reaches every position in it, and
/// its frontier covers the current floor's: the floor never moves back. Naming the
/// checkpoint that already is the floor changes nothing.
pub fn adopt_history_floor(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint_id: &[u8; 32],
) -> Result<(), SyncSqliteError> {
    let refuse =
        |detail: &str| SyncSqliteError::InvalidInput(format!("history floor refused: {detail}"));
    let trusted: Option<Vec<u8>> = conn
        .query_row(
            "SELECT c.author_state_root \
             FROM native_checkpoints c \
             JOIN native_checkpoint_seal_evidence e \
               ON e.group_id = c.group_id AND e.checkpoint_hash = c.checkpoint_hash \
             WHERE c.group_id = ?1 AND c.checkpoint_hash = ?2",
            (group_id.as_str(), checkpoint_id.as_slice()),
            |row| row.get(0),
        )
        .optional()?;
    let Some(signed_root) = trusted else {
        return Err(refuse("the checkpoint is not a trusted checkpoint of this group"));
    };
    let coverage = checkpoint_coverage(conn, group_id, checkpoint_id)?;
    if coverage.check_against_root(&signed_root).is_err() {
        return Err(refuse("the checkpoint's stored author states do not build its root"));
    }
    let covered = coverage.frontier();
    if !frontier_covers(&crate::native_store::load_frontier(conn, group_id)?, &covered) {
        return Err(refuse("this replica's state does not descend from the checkpoint"));
    }
    if history_floor(conn, group_id)?.is_some_and(|floor| floor.checkpoint_id == *checkpoint_id) {
        return Ok(());
    }
    let current = retained_frontier(conn, group_id)?;
    if !frontier_covers(&covered, &current) {
        return Err(refuse("the checkpoint does not cover the current floor"));
    }
    conn.execute(
        "INSERT INTO native_history_floor \
         (group_id, checkpoint_id, floor_frontier_root, adopted_at_unixtime) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(group_id) DO UPDATE SET checkpoint_id = excluded.checkpoint_id, \
           floor_frontier_root = excluded.floor_frontier_root, \
           adopted_at_unixtime = excluded.adopted_at_unixtime",
        (group_id.as_str(), checkpoint_id.as_slice(), signed_root.as_slice(), now_unixtime()),
    )?;
    Ok(())
}

/// Checks the stored marker against the rows it names: they still recompute to the
/// root the marker committed.
/// `Ok(())` when there is no marker.
pub fn verify_history_floor(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<(), SyncSqliteError> {
    let Some(floor) = history_floor(conn, group_id)? else { return Ok(()) };
    let coverage = checkpoint_coverage(conn, group_id, &floor.checkpoint_id)?;
    if coverage.recomputed_root() != floor.floor_frontier_root {
        return Err(SyncSqliteError::CorruptState(
            "the history floor's author states no longer build the root it committed".into(),
        ));
    }
    // The checkpoint's own signed root is the one the marker committed.
    let signed_root: Vec<u8> = conn.query_row(
        "SELECT author_state_root FROM native_checkpoints \
         WHERE group_id = ?1 AND checkpoint_hash = ?2",
        (group_id.as_str(), floor.checkpoint_id.as_slice()),
        |row| row.get(0),
    )?;
    coverage.check_against_root(&signed_root).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "the history floor's stored checkpoint rows no longer match its signed root: {error}"
        ))
    })?;
    Ok(())
}

/// When a newer trusted checkpoint may become the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryHorizon {
    /// How long this replica must have trusted a checkpoint before it can be the
    /// floor.
    pub min_age_days: u64,
    /// How many other trusted checkpoints strictly further (whose frontier covers
    /// this one's and is not covered by it) must exist.
    pub min_newer_generations: usize,
    /// The retained bytes are over their cap: the age and generation requirements
    /// are waived, and a floor chosen only because of that is reported as
    /// [`FloorChoice::byte_limit`].
    pub pressure_override: bool,
}

impl Default for HistoryHorizon {
    fn default() -> Self {
        Self { min_age_days: 30, min_newer_generations: 2, pressure_override: false }
    }
}

/// A trusted checkpoint as the floor rule sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloorCandidate {
    pub checkpoint_id: [u8; 32],
    pub adopted_at_unixtime: i64,
    pub frontier: NativeAuthorFrontier,
}

/// The checkpoint the floor may advance to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloorChoice {
    pub checkpoint_id: [u8; 32],
    /// Chosen only because the pressure override waived the horizon: status reports
    /// `retention_degraded` with reason `byte_limit`.
    pub byte_limit: bool,
}

const SECONDS_PER_DAY: i64 = 86_400;

/// Whether `newer` is strictly further than `older`: it covers `older`'s frontier
/// and `older` does not cover its. Checkpoints are only partially ordered by this
/// (two writers sealing during a partition produce frontiers neither of which
/// covers the other), so "newer" never means "adopted later".
fn dominates(newer: &NativeAuthorFrontier, older: &NativeAuthorFrontier) -> bool {
    frontier_covers(newer, older) && !frontier_covers(older, newer)
}

/// The furthest of `candidates`: one no other of them dominates, the greatest
/// checkpoint id among those, so the answer is a function of the set alone.
fn furthest<'a>(candidates: &[&'a FloorCandidate]) -> Option<&'a FloorCandidate> {
    candidates
        .iter()
        .filter(|candidate| {
            !candidates.iter().any(|other| dominates(&other.frontier, &candidate.frontier))
        })
        .max_by_key(|candidate| candidate.checkpoint_id)
        .copied()
}

/// The candidate the floor may advance to, or `None`. Pure, and a function of the
/// set of candidates: their order and their adoption times (beyond the age
/// requirement) decide nothing.
///
/// `candidates` are every trusted checkpoint, in any order. A candidate qualifies
/// when its frontier strictly dominates the current floor's (the floor never moves
/// back or sideways), and either the normal horizon holds (trusted for
/// `min_age_days`, with `min_newer_generations` other trusted checkpoints whose
/// frontiers strictly dominate its own) or the pressure override is on. Of the
/// candidates that qualify, the choice is one no other qualifying candidate
/// dominates.
pub fn choose_floor(
    candidates: &[FloorCandidate],
    current_floor: Option<&FloorCandidate>,
    now_unixtime: i64,
    horizon: &HistoryHorizon,
) -> Option<FloorChoice> {
    let empty = NativeAuthorFrontier::new();
    let floor_frontier = current_floor.map_or(&empty, |floor| &floor.frontier);
    let qualifying: Vec<&FloorCandidate> = candidates
        .iter()
        .filter(|candidate| {
            current_floor.is_none_or(|floor| floor.checkpoint_id != candidate.checkpoint_id)
                && dominates(&candidate.frontier, floor_frontier)
        })
        .collect();
    let normal = |candidate: &&FloorCandidate| {
        let age = now_unixtime.saturating_sub(candidate.adopted_at_unixtime);
        let newer = candidates
            .iter()
            .filter(|other| dominates(&other.frontier, &candidate.frontier))
            .count();
        age >= (horizon.min_age_days as i64).saturating_mul(SECONDS_PER_DAY)
            && newer >= horizon.min_newer_generations
    };
    let by_horizon: Vec<&FloorCandidate> = qualifying.iter().copied().filter(normal).collect();
    if let Some(candidate) = furthest(&by_horizon) {
        return Some(FloorChoice { checkpoint_id: candidate.checkpoint_id, byte_limit: false });
    }
    if horizon.pressure_override {
        let candidate = furthest(&qualifying)?;
        return Some(FloorChoice { checkpoint_id: candidate.checkpoint_id, byte_limit: true });
    }
    None
}

/// The checkpoint `group_id`'s floor may advance to at `now_unixtime` under
/// `horizon`, if any. Reads the stored trusted checkpoints and applies
/// [`choose_floor`]; it changes nothing and no background task calls it.
pub fn eligible_floor(
    conn: &Connection,
    group_id: &FolderGroupId,
    now_unixtime: i64,
    horizon: &HistoryHorizon,
) -> Result<Option<[u8; 32]>, SyncSqliteError> {
    Ok(eligible_floor_choice(conn, group_id, now_unixtime, horizon)?.map(|c| c.checkpoint_id))
}

/// [`eligible_floor`] with whether the pressure override was needed.
pub fn eligible_floor_choice(
    conn: &Connection,
    group_id: &FolderGroupId,
    now_unixtime: i64,
    horizon: &HistoryHorizon,
) -> Result<Option<FloorChoice>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT c.checkpoint_hash, c.installed_at_unixtime \
         FROM native_checkpoints c \
         JOIN native_checkpoint_seal_evidence e \
           ON e.group_id = c.group_id AND e.checkpoint_hash = c.checkpoint_hash \
         WHERE c.group_id = ?1 ORDER BY c.checkpoint_hash",
    )?;
    let rows = stmt
        .query_map([group_id.as_str()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut candidates = Vec::with_capacity(rows.len());
    for (id, adopted_at_unixtime) in rows {
        let checkpoint_id = crate::native_store::as_array32(&id)?;
        candidates.push(FloorCandidate {
            checkpoint_id,
            adopted_at_unixtime,
            frontier: checkpoint_frontier(conn, group_id, &checkpoint_id)?,
        });
    }
    let current = match history_floor(conn, group_id)? {
        Some(floor) => Some(FloorCandidate {
            checkpoint_id: floor.checkpoint_id,
            adopted_at_unixtime: floor.adopted_at_unixtime,
            frontier: checkpoint_frontier(conn, group_id, &floor.checkpoint_id)?,
        }),
        None => None,
    };
    Ok(choose_floor(&candidates, current.as_ref(), now_unixtime, horizon))
}

fn now_unixtime() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use yadorilink_replica_domain::author::IncarnationId;
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId};
    use yadorilink_replica_domain::native_state::DeltaHash;

    use super::*;

    const DAY: i64 = SECONDS_PER_DAY;
    const NOW: i64 = 100 * DAY;

    fn frontier(seq: u64) -> NativeAuthorFrontier {
        let author = AuthorId { device: DeviceId("a".into()), incarnation: IncarnationId([1; 16]) };
        let entry =
            NativeAuthorFrontierEntry { seq: AuthorSeq(seq), tip: DeltaHash([seq as u8; 32]) };
        [(author, entry)].into_iter().collect()
    }

    #[test]
    fn a_frontier_covers_another_only_at_a_higher_sequence_or_the_same_tip() {
        let (low, high) = (frontier(1), frontier(2));
        assert!(frontier_covers(&high, &low), "a higher sequence covers");
        assert!(frontier_covers(&low, &low), "the same entry covers");
        assert!(!frontier_covers(&low, &high), "a lower sequence does not");
        let mut forked = frontier(2);
        for entry in forked.values_mut() {
            entry.tip = DeltaHash([0xee; 32]);
        }
        assert!(!frontier_covers(&forked, &high), "the same sequence with another tip");
        assert!(!frontier_covers(&high, &forked));
        assert!(!frontier_covers(&NativeAuthorFrontier::new(), &low), "a missing author");
        assert!(frontier_covers(&low, &NativeAuthorFrontier::new()), "nothing to cover");
    }

    /// The `n`th generation: covers the first `n`, adopted `age_days` ago.
    fn generation(n: u8, age_days: i64) -> FloorCandidate {
        FloorCandidate {
            checkpoint_id: [n; 32],
            adopted_at_unixtime: NOW - age_days * DAY,
            frontier: frontier(n as u64),
        }
    }

    fn pick(
        candidates: &[FloorCandidate],
        floor: Option<&FloorCandidate>,
        horizon: &HistoryHorizon,
    ) -> Option<FloorChoice> {
        choose_floor(candidates, floor, NOW, horizon)
    }

    #[test]
    fn the_default_horizon_is_thirty_days_and_two_newer_generations() {
        let horizon = HistoryHorizon::default();
        assert_eq!(horizon.min_age_days, 30);
        assert_eq!(horizon.min_newer_generations, 2);
        assert!(!horizon.pressure_override);
    }

    #[test]
    fn a_checkpoint_old_enough_with_two_newer_generations_is_eligible() {
        let all = [generation(1, 40), generation(2, 20), generation(3, 5)];
        let choice = pick(&all, None, &HistoryHorizon::default()).unwrap();
        assert_eq!(choice, FloorChoice { checkpoint_id: [1; 32], byte_limit: false });
    }

    #[test]
    fn the_newest_eligible_checkpoint_wins() {
        let all = [
            generation(1, 70),
            generation(2, 60),
            generation(3, 40),
            generation(4, 5),
            generation(5, 1),
        ];
        let choice = pick(&all, None, &HistoryHorizon::default()).unwrap();
        assert_eq!(choice.checkpoint_id, [3; 32]);
    }

    #[test]
    fn too_young_a_checkpoint_is_not_eligible() {
        let all = [generation(1, 29), generation(2, 10), generation(3, 5)];
        assert_eq!(pick(&all, None, &HistoryHorizon::default()), None);
        let at_the_limit = [generation(1, 30), generation(2, 10), generation(3, 5)];
        assert!(pick(&at_the_limit, None, &HistoryHorizon::default()).is_some());
    }

    #[test]
    fn fewer_than_two_newer_generations_is_not_eligible() {
        let all = [generation(1, 90), generation(2, 80)];
        assert_eq!(pick(&all, None, &HistoryHorizon::default()), None);
        let one_newer_is_enough_if_asked =
            HistoryHorizon { min_newer_generations: 1, ..HistoryHorizon::default() };
        assert_eq!(pick(&all, None, &one_newer_is_enough_if_asked).unwrap().checkpoint_id, [1; 32]);
    }

    #[test]
    fn a_generation_that_is_not_as_far_does_not_count_as_newer() {
        // Two later checkpoints, but of a different author's progress: the first one
        // is covered by neither.
        let mut sideways = generation(2, 20);
        sideways.frontier = {
            let other =
                AuthorId { device: DeviceId("b".into()), incarnation: IncarnationId([1; 16]) };
            frontier(1)
                .into_iter()
                .chain([(other, frontier(2).into_values().next().unwrap())])
                .collect()
        };
        let mut sideways2 = sideways.clone();
        sideways2.checkpoint_id = [3; 32];
        let mut lacking = generation(1, 40);
        lacking.frontier = frontier(9);
        let all = [lacking, sideways, sideways2];
        assert_eq!(pick(&all, None, &HistoryHorizon::default()), None);
    }

    #[test]
    fn the_floor_never_moves_back_or_to_itself() {
        let all = [generation(1, 90), generation(2, 80), generation(3, 70), generation(4, 5)];
        let floor = generation(3, 70);
        // 1 and 2 are behind the floor; 3 is the floor; 4 is too young.
        assert_eq!(pick(&all, Some(&floor), &HistoryHorizon::default()), None);
        let all = [
            generation(1, 90),
            generation(2, 80),
            generation(3, 70),
            generation(4, 60),
            generation(5, 50),
        ];
        let choice = pick(&all, Some(&generation(2, 80)), &HistoryHorizon::default()).unwrap();
        assert_eq!(choice.checkpoint_id, [3; 32]);
    }

    #[test]
    fn the_pressure_override_waives_the_horizon_and_reports_the_byte_limit() {
        let all = [generation(1, 3), generation(2, 2), generation(3, 1)];
        let pressured = HistoryHorizon { pressure_override: true, ..HistoryHorizon::default() };
        let choice = pick(&all, None, &pressured).unwrap();
        assert_eq!(choice, FloorChoice { checkpoint_id: [3; 32], byte_limit: true });
        // Under pressure the normal horizon still wins when it has an answer.
        let old = [generation(1, 60), generation(2, 50), generation(3, 1)];
        let choice = pick(&old, None, &pressured).unwrap();
        assert_eq!(choice, FloorChoice { checkpoint_id: [1; 32], byte_limit: false });
        // Without it nothing is eligible.
        assert_eq!(pick(&all, None, &HistoryHorizon::default()), None);
    }

    #[test]
    fn the_override_still_never_moves_the_floor_back() {
        let all = [generation(1, 3), generation(2, 2)];
        let pressured = HistoryHorizon { pressure_override: true, ..HistoryHorizon::default() };
        assert_eq!(pick(&all, Some(&generation(2, 2)), &pressured), None);
    }

    /// A checkpoint over two authors at the given sequences.
    fn candidate_at(id: u8, age_days: i64, a_seq: u64, b_seq: u64) -> FloorCandidate {
        let author = |name: &str| AuthorId {
            device: DeviceId(name.into()),
            incarnation: IncarnationId([1; 16]),
        };
        let entry = |seq: u64| NativeAuthorFrontierEntry {
            seq: AuthorSeq(seq),
            tip: DeltaHash([seq as u8; 32]),
        };
        FloorCandidate {
            checkpoint_id: [id; 32],
            adopted_at_unixtime: NOW - age_days * DAY,
            frontier: [(author("a"), entry(a_seq)), (author("b"), entry(b_seq))]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn a_checkpoint_with_the_same_frontier_is_not_a_newer_generation() {
        // Three distinct checkpoints over one frontier: none is further than another.
        let all = [candidate_at(1, 40, 2, 2), candidate_at(2, 5, 2, 2), candidate_at(3, 4, 2, 2)];
        assert_eq!(pick(&all, None, &HistoryHorizon::default()), None);
    }

    #[test]
    fn only_checkpoints_that_dominate_count_as_newer_not_incomparable_or_later_ones() {
        let old = candidate_at(1, 40, 2, 2);
        let dominating = candidate_at(2, 5, 3, 2);
        // Adopted later, but each is ahead in one author and behind in the other.
        let beside_a = candidate_at(3, 4, 3, 1);
        let beside_b = candidate_at(4, 3, 1, 3);
        let all = [old.clone(), dominating.clone(), beside_a, beside_b];
        assert_eq!(
            pick(&all, None, &HistoryHorizon::default()),
            None,
            "one dominating, two beside"
        );
        let second = candidate_at(5, 2, 2, 3);
        let all = [old, dominating, second];
        assert_eq!(pick(&all, None, &HistoryHorizon::default()).unwrap().checkpoint_id, [1; 32]);
    }

    #[test]
    fn the_floor_never_moves_to_an_incomparable_checkpoint() {
        let floor = candidate_at(1, 90, 2, 1);
        // Old, with two dominators of its own, but it does not cover the floor.
        let beside = candidate_at(2, 80, 1, 2);
        let all = [floor.clone(), beside, candidate_at(3, 10, 1, 3), candidate_at(4, 9, 1, 4)];
        let pressured = HistoryHorizon { pressure_override: true, ..HistoryHorizon::default() };
        for horizon in [HistoryHorizon::default(), pressured] {
            assert_eq!(pick(&all, Some(&floor), &horizon), None);
        }
    }

    #[test]
    fn the_choice_does_not_depend_on_the_order_the_checkpoints_were_adopted_in() {
        let floor = candidate_at(1, 90, 1, 1);
        let (left, right) = (candidate_at(2, 3, 2, 1), candidate_at(3, 2, 1, 2));
        let pressured = HistoryHorizon { pressure_override: true, ..HistoryHorizon::default() };
        let forward = pick(&[floor.clone(), left.clone(), right.clone()], Some(&floor), &pressured);
        let reversed =
            pick(&[right.clone(), left.clone(), floor.clone()], Some(&floor), &pressured);
        assert!(forward.is_some());
        assert_eq!(forward, reversed, "a later adoption won over an incomparable earlier one");

        let old = [candidate_at(4, 70, 1, 1), candidate_at(5, 60, 2, 1), candidate_at(6, 50, 3, 1)];
        let other_old = [
            candidate_at(7, 70, 1, 1),
            candidate_at(8, 60, 1, 2),
            candidate_at(9, 50, 2, 2),
            candidate_at(10, 40, 1, 3),
            candidate_at(11, 30, 3, 3),
        ];
        let mut all: Vec<_> = old.iter().chain(other_old.iter()).cloned().collect();
        let horizon = HistoryHorizon::default();
        let expected = pick(&all, None, &horizon);
        all.reverse();
        assert_eq!(pick(&all, None, &horizon), expected);
        all.rotate_left(3);
        assert_eq!(pick(&all, None, &horizon), expected);
    }

    #[test]
    fn no_candidates_means_no_floor() {
        let pressured = HistoryHorizon { pressure_override: true, ..HistoryHorizon::default() };
        assert_eq!(pick(&[], None, &pressured), None);
    }
}
