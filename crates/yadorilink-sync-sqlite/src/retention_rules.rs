//! `RetentionRuleRepository` owns `retention_rules`: what a person decided about keeping the
//! copy of a path on this device, per linked group. A rule is `keep` ("Always keep on this
//! device") or `online_only` (free the copy here, open it on demand from the other devices).
//!
//! This is the retention policy, and it is kept apart from the materialization state
//! (`Remote`/`Hydrated`): a rule says what the user wants, never what is stored. It is local to
//! this device and never leaves it -- no change is authored, no peer is told, and no custody or
//! role follows from it. It is durable, which is why it is a table and not process memory.
//!
//! **One rule table, longest prefix wins.** A rule covers its own path and, for a folder, every
//! path beneath it (including paths that appear later); the empty path is the linked folder's
//! root and covers the whole group. The rule in force at a path is the nearest explicit rule at
//! or above it ([`RuleSet::nearest`]); where there is none, the folder's own mode decides, which
//! this module does not know (an eager folder keeps, an on-demand folder is online-only). The
//! readers that only ask "is this path kept?" ask [`RuleSet::is_kept`] or its SQL twin
//! [`kept_by_rule_sql`]; an `online_only` rule nearer than a `keep` rule above it makes the path
//! not kept.
//!
//! Setting a rule at a path ([`RetentionRuleRepository::set`]) clears the rules strictly beneath
//! it and gives the row a new generation; clearing a rule removes only the row at exactly that
//! path. The rule belongs to the path, not the content: a renamed or deleted path leaves its row
//! behind, and whatever later stands at that path is covered by it.
//!
//! Only `keep` is reachable from outside today (the pin of "Always keep on this device"); the
//! `online_only` rule is read correctly everywhere a rule is read, and gets its entry point with
//! the control surface that activates it.

use std::sync::Arc;

use rusqlite::Connection;
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;

pub(crate) fn init_retention_rules_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS retention_rules (
            group_id           TEXT NOT NULL,
            path               TEXT NOT NULL,
            rule               TEXT NOT NULL CHECK (rule IN ('keep', 'online_only')),
            generation         INTEGER NOT NULL,
            set_at_unix_nanos  INTEGER NOT NULL,
            apply_state        TEXT NOT NULL DEFAULT 'none'
                               CHECK (apply_state IN ('none', 'pending', 'done')),
            -- When the apply pass claimed the rule (NULL: nobody holds it); a claim older than the
            -- lease is reclaimable, so a pass that died never strands the rule.
            claimed_at_unix_nanos INTEGER,
            -- Raised whenever something that a finished pass could have missed happens (a download
            -- of a freed path settled, a skipped file became clean, Free Up Space ran): a pass
            -- completes only against the value it claimed.
            rearm_seq          INTEGER NOT NULL DEFAULT 0,
            -- What the last pass did, for the status line.
            done_count         INTEGER NOT NULL DEFAULT 0,
            skipped_count      INTEGER NOT NULL DEFAULT 0,
            retryable_count    INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, path)
        );
        -- The last generation handed out in a group: a generation is never reused, even after
        -- the row that held it is gone, so a job holding an old one can never mistake a newer rule
        -- for the one it claimed.
        CREATE TABLE IF NOT EXISTS retention_rule_generations (
            group_id TEXT PRIMARY KEY,
            last     INTEGER NOT NULL
        );",
    )?;
    Ok(())
}

/// What a person decided for a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Always keep the copy on this device.
    Keep,
    /// Free the copy here; it opens on demand from the other devices.
    OnlineOnly,
}

impl Rule {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::OnlineOnly => "online_only",
        }
    }

    fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "keep" => Some(Self::Keep),
            "online_only" => Some(Self::OnlineOnly),
            _ => None,
        }
    }
}

/// Whether local space for an item may be reclaimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    Reclaimable,
    Pinned,
    /// An `online_only` rule frees the copy in the folder; the blocks stay for a custodian.
    OnlineOnly,
}

/// The policy in force at one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    pub policy: RetentionPolicy,
    /// The rule in force was set at exactly this path (rather than only inherited).
    pub explicit: bool,
}

/// Whether `rule_path` covers `path`: it is the path itself, a folder above it, or the root.
fn covers(rule_path: &str, path: &str) -> bool {
    rule_path.is_empty()
        || path == rule_path
        || path.strip_prefix(rule_path).is_some_and(|rest| rest.starts_with('/'))
}

/// Whether `path` lies strictly beneath `prefix` (everything, when `prefix` is the root).
fn is_beneath(prefix: &str, path: &str) -> bool {
    if prefix.is_empty() {
        !path.is_empty()
    } else {
        path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
    }
}

/// A group's explicit rules, read once: the one Rust statement of the longest-prefix rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<(String, Rule)>,
}

impl RuleSet {
    pub fn new(rules: impl IntoIterator<Item = (String, Rule)>) -> Self {
        Self { rules: rules.into_iter().collect() }
    }

    /// The nearest explicit rule at or above `path`, with the path it was set at; `None` when
    /// no rule covers it (the folder's mode decides then).
    pub fn nearest(&self, path: &str) -> Option<(&str, Rule)> {
        self.rules
            .iter()
            .filter(|(at, _)| covers(at, path))
            .max_by_key(|(at, _)| at.len())
            .map(|(at, rule)| (at.as_str(), *rule))
    }

    /// Whether the rule in force at `path` is an explicit `keep` (the pin term every reader asks).
    pub fn is_kept(&self, path: &str) -> bool {
        matches!(self.nearest(path), Some((_, Rule::Keep)))
    }

    /// Whether the nearest rule at or above `path` is an explicit `online_only`.
    pub fn is_online_only(&self, path: &str) -> bool {
        matches!(self.nearest(path), Some((_, Rule::OnlineOnly)))
    }

    /// Whether any rule is `online_only`.
    pub fn has_online_only(&self) -> bool {
        self.rules.iter().any(|(_, rule)| *rule == Rule::OnlineOnly)
    }

    /// Whether the directory `dir` contains something effectively kept: it is kept itself, or a
    /// `keep` rule sits strictly beneath it (an exception under an online-only ancestor counts).
    /// An ancestor's own rule is not enough to authorise dropping a directory's copy.
    pub fn kept_below(&self, dir: &str) -> bool {
        self.is_kept(dir)
            || self.rules.iter().any(|(at, rule)| *rule == Rule::Keep && is_beneath(dir, at))
    }

    /// Paths of the `keep` rules.
    pub fn kept_paths(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().filter(|(_, rule)| *rule == Rule::Keep).map(|(at, _)| at.as_str())
    }

    /// The rules strictly beneath `prefix` (every rule when `prefix` is the root).
    pub fn beneath(&self, prefix: &str) -> Vec<(&str, Rule)> {
        let mut found: Vec<_> = self
            .rules
            .iter()
            .filter(|(at, _)| is_beneath(prefix, at))
            .map(|(at, rule)| (at.as_str(), *rule))
            .collect();
        found.sort_by(|a, b| a.0.cmp(b.0));
        found
    }
}

/// The SQL twin of [`RuleSet::is_kept`]: an `EXISTS(...)` that is true when the nearest rule at
/// or above `path_expr` (a SQL expression) in group `group_expr` is `keep`. A `keep` row counts
/// only when no `online_only` row nearer to the path than it covers the path.
pub fn kept_by_rule_sql(group_expr: &str, path_expr: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM retention_rules k WHERE k.group_id = {group_expr} \
           AND k.rule = 'keep' \
           AND (k.path = '' OR {path_expr} = k.path \
                OR substr({path_expr}, 1, length(k.path) + 1) = k.path || '/') \
           AND NOT EXISTS (SELECT 1 FROM retention_rules o WHERE o.group_id = k.group_id \
                AND o.rule = 'online_only' AND length(o.path) > length(k.path) \
                AND (o.path = '' OR {path_expr} = o.path \
                     OR substr({path_expr}, 1, length(o.path) + 1) = o.path || '/')))"
    )
}

/// The mirror of [`kept_by_rule_sql`]: true when the nearest rule at or above `path_expr` is
/// `online_only` (an `online_only` row no nearer `keep` row shadows).
pub fn online_only_by_rule_sql(group_expr: &str, path_expr: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM retention_rules o WHERE o.group_id = {group_expr} \
           AND o.rule = 'online_only' \
           AND (o.path = '' OR {path_expr} = o.path \
                OR substr({path_expr}, 1, length(o.path) + 1) = o.path || '/') \
           AND NOT EXISTS (SELECT 1 FROM retention_rules k WHERE k.group_id = o.group_id \
                AND k.rule = 'keep' AND length(k.path) > length(o.path) \
                AND (k.path = '' OR {path_expr} = k.path \
                     OR substr({path_expr}, 1, length(k.path) + 1) = k.path || '/')))"
    )
}

/// The SQL twin of [`RuleSet::kept_below`]'s second term: true when a `keep` row lies strictly
/// beneath the directory `dir_expr` in group `group_expr`.
pub fn keep_rule_beneath_sql(group_expr: &str, dir_expr: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM retention_rules b WHERE b.group_id = {group_expr} \
           AND b.rule = 'keep' \
           AND substr(b.path, 1, length({dir_expr}) + 1) = {dir_expr} || '/')"
    )
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Reads a group's rules inside a transaction or connection.
pub(crate) fn read_rules(conn: &Connection, group_id: &str) -> Result<RuleSet, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT path, rule FROM retention_rules WHERE group_id = ?1 ORDER BY path",
    )?;
    let rows =
        stmt.query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut rules = Vec::new();
    for row in rows {
        let (path, rule) = row?;
        if let Some(rule) = Rule::from_db_str(&rule) {
            rules.push((path, rule));
        }
    }
    Ok(RuleSet { rules })
}

/// An `online_only` rule whose copies have not all been freed yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRule {
    pub group_id: String,
    pub path: String,
    pub generation: i64,
}

/// A pass's hold on a pending rule: the generation it claimed, the re-arm count it saw, and the
/// token of its lease. A pass whose lease ran out and was taken over holds a token that no longer
/// matches, so it can neither release nor complete the new holder's claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleClaim {
    pub generation: i64,
    pub rearm_seq: i64,
    pub token: i64,
}

/// The rules of one group, added up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleSummary {
    /// Explicit rules of either kind.
    pub rule_count: u64,
    pub online_only_count: u64,
    /// `online_only` rules whose apply pass has not finished.
    pub pending_count: u64,
    /// Outcomes of the last passes, summed over the `online_only` rules.
    pub counts: ApplyCounts,
}

/// What a pass did with the files under a rule, kept on the rule for the status line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyCounts {
    /// Freed (or already without a copy).
    pub done: u32,
    /// Deliberately left: unsynced edits, held or conflicted, open, refused by the eviction path.
    pub skipped: u32,
    /// Could not be tried (host or provider not ready): the rule stays pending and retries.
    pub retryable: u32,
}

/// One rule as stored, for a job that re-reads it before it acts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleRow {
    pub rule: Rule,
    pub generation: i64,
    pub pending: bool,
    pub rearm_seq: i64,
    pub counts: ApplyCounts,
}

pub struct RetentionRuleRepository {
    database: Arc<SyncDatabase>,
}

impl RetentionRuleRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Sets the rule at `path` in `group_id`, or (`None`) clears the rule set at exactly that
    /// path. Setting clears every rule strictly beneath `path` and gives the row a new
    /// generation; setting the rule that is already there, with nothing beneath it, changes
    /// nothing. A cleared rule leaves rules beneath it and the rules above it alone. Returns
    /// whether anything changed. In the same transaction the provider items the change touches
    /// are republished to the OS, so a crash can never leave a rule without its republication.
    pub fn set(
        &self,
        group_id: &str,
        path: &str,
        rule: Option<Rule>,
    ) -> Result<bool, SyncSqliteError> {
        self.write_rule(group_id, path, rule, true)
    }

    fn write_rule(
        &self,
        group_id: &str,
        path: &str,
        rule: Option<Rule>,
        clear_beneath: bool,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let changed = match rule {
                Some(rule) => {
                    let existing: Option<String> = tx
                        .query_row(
                            "SELECT rule FROM retention_rules WHERE group_id = ?1 AND path = ?2",
                            rusqlite::params![group_id, path],
                            |r| r.get(0),
                        )
                        .map(Some)
                        .or_else(|e| match e {
                            rusqlite::Error::QueryReturnedNoRows => Ok(None),
                            other => Err(other),
                        })?;
                    let beneath =
                        if clear_beneath { read_rules(tx, group_id)?.beneath(path).len() } else { 0 };
                    if existing.as_deref() == Some(rule.as_db_str()) && beneath == 0 {
                        false
                    } else {
                        tx.execute(
                            "INSERT INTO retention_rule_generations (group_id, last) VALUES (?1, 1) \
                             ON CONFLICT(group_id) DO UPDATE SET last = last + 1",
                            [group_id],
                        )?;
                        let generation: i64 = tx.query_row(
                            "SELECT last FROM retention_rule_generations WHERE group_id = ?1",
                            [group_id],
                            |r| r.get(0),
                        )?;
                        if clear_beneath {
                            tx.execute(
                                "DELETE FROM retention_rules WHERE group_id = ?1 AND ( \
                                   (?2 = '' AND path <> '') \
                                   OR substr(path, 1, length(?2) + 1) = ?2 || '/')",
                                rusqlite::params![group_id, path],
                            )?;
                        }
                        tx.execute(
                            "INSERT INTO retention_rules \
                               (group_id, path, rule, generation, set_at_unix_nanos, apply_state) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                             ON CONFLICT(group_id, path) DO UPDATE SET rule = excluded.rule, \
                               generation = excluded.generation, \
                               set_at_unix_nanos = excluded.set_at_unix_nanos, \
                               claimed_at_unix_nanos = NULL, \
                               apply_state = excluded.apply_state",
                            rusqlite::params![
                                group_id,
                                path,
                                rule.as_db_str(),
                                generation,
                                now_unix_nanos(),
                                if rule == Rule::OnlineOnly { "pending" } else { "none" },
                            ],
                        )?;
                        true
                    }
                }
                None => {
                    tx.execute(
                        "DELETE FROM retention_rules WHERE group_id = ?1 AND path = ?2",
                        rusqlite::params![group_id, path],
                    )? > 0
                }
            };
            if changed {
                yadorilink_sqlite_runtime::note_retention_changed(tx, group_id, path)?;
            }
            Ok(changed)
        })
    }

    /// Pins `path` ("Always keep on this device"). Unlike [`Self::set`] this leaves the rules
    /// beneath `path` alone: a pin set on a child stays when its folder is pinned and unpinned
    /// (the behaviour of the pin before rules existed, until the control surface that sets rules
    /// replaces it).
    pub fn pin(&self, group_id: &str, path: &str) -> Result<(), SyncSqliteError> {
        self.write_rule(group_id, path, Some(Rule::Keep), false).map(drop)
    }

    /// Removes the rule set at exactly `path` (unpins it), returning whether there was one.
    /// Content is not touched and a rule above it stays in force.
    pub fn unpin(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.set(group_id, path, None)
    }

    /// Every rule of `group_id`.
    pub fn rules(&self, group_id: &str) -> Result<RuleSet, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| read_rules(conn, group_id))
    }

    /// The `online_only` rules not yet applied (`pending`), in a stable order.
    pub fn pending_rules(&self) -> Result<Vec<PendingRule>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT group_id, path, generation FROM retention_rules \
                 WHERE rule = 'online_only' AND apply_state = 'pending' \
                 ORDER BY group_id, path",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(PendingRule { group_id: r.get(0)?, path: r.get(1)?, generation: r.get(2)? })
            })?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }

    /// The rule stored at exactly `path`, if any.
    pub fn rule_row(&self, group_id: &str, path: &str) -> Result<Option<RuleRow>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row = conn.query_row(
                "SELECT rule, generation, apply_state, rearm_seq, done_count, skipped_count, \
                        retryable_count \
                 FROM retention_rules WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, i64>(6)?,
                    ))
                },
            );
            match row {
                Ok((rule, generation, state, rearm_seq, done, skipped, retryable)) => {
                    Ok(Rule::from_db_str(&rule).map(|rule| RuleRow {
                        rule,
                        generation,
                        pending: state == "pending",
                        rearm_seq,
                        counts: ApplyCounts {
                            done: done.max(0) as u32,
                            skipped: skipped.max(0) as u32,
                            retryable: retryable.max(0) as u32,
                        },
                    }))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
    }

    /// Claims the pending `online_only` rule at `path` for one pass: only at the `generation` the
    /// caller read, and only when nobody holds it or the holder's claim is older than `lease`.
    /// `None` when the rule changed, was applied, or is held.
    pub fn claim_rule(
        &self,
        group_id: &str,
        path: &str,
        generation: i64,
        now_unix_nanos: i64,
        lease: std::time::Duration,
    ) -> Result<Option<RuleClaim>, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let oldest_reclaimable = now_unix_nanos.saturating_sub(lease.as_nanos() as i64);
            let claimed = tx.execute(
                "UPDATE retention_rules SET claimed_at_unix_nanos = ?4 \
                 WHERE group_id = ?1 AND path = ?2 AND generation = ?3 \
                   AND rule = 'online_only' AND apply_state = 'pending' \
                   AND (claimed_at_unix_nanos IS NULL OR claimed_at_unix_nanos <= ?5)",
                rusqlite::params![group_id, path, generation, now_unix_nanos, oldest_reclaimable],
            )?;
            if claimed == 0 {
                return Ok(None);
            }
            let rearm_seq: i64 = tx.query_row(
                "SELECT rearm_seq FROM retention_rules WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )?;
            Ok(Some(RuleClaim { generation, rearm_seq, token: now_unix_nanos }))
        })
    }

    /// Ends a claim without finishing: the rule stays pending (a later pass tries again), with the
    /// counts of what this pass did. Only for the generation that was claimed.
    pub fn release_rule(
        &self,
        group_id: &str,
        path: &str,
        claim: RuleClaim,
        counts: ApplyCounts,
    ) -> Result<bool, SyncSqliteError> {
        self.write_counts(group_id, path, claim, counts, false)
    }

    /// Finishes the rule: `pending(generation, rearm_seq)` becomes `done`, only if both are still
    /// what the pass claimed. A re-arm or a newer rule during the pass leaves the rule pending and
    /// returns `false`.
    pub fn complete_rule(
        &self,
        group_id: &str,
        path: &str,
        claim: RuleClaim,
        counts: ApplyCounts,
    ) -> Result<bool, SyncSqliteError> {
        self.write_counts(group_id, path, claim, counts, true)
    }

    fn write_counts(
        &self,
        group_id: &str,
        path: &str,
        claim: RuleClaim,
        counts: ApplyCounts,
        finish: bool,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let changed = tx.execute(
                "UPDATE retention_rules SET claimed_at_unix_nanos = NULL, \
                   done_count = ?5, skipped_count = ?6, retryable_count = ?7, \
                   apply_state = CASE WHEN ?8 AND rearm_seq = ?4 THEN 'done' ELSE apply_state END \
                 WHERE group_id = ?1 AND path = ?2 AND generation = ?3 AND rule = 'online_only' \
                   AND apply_state = 'pending' AND claimed_at_unix_nanos = ?9",
                rusqlite::params![
                    group_id,
                    path,
                    claim.generation,
                    claim.rearm_seq,
                    counts.done,
                    counts.skipped,
                    counts.retryable,
                    finish,
                    claim.token,
                ],
            )?;
            if changed == 0 {
                return Ok(false);
            }
            if finish {
                let done: bool = tx.query_row(
                    "SELECT apply_state = 'done' FROM retention_rules \
                     WHERE group_id = ?1 AND path = ?2",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )?;
                return Ok(done);
            }
            Ok(true)
        })
    }

    /// Something a finished or running pass could have missed happened at `path` (a download of a
    /// freed path settled, a skipped file became clean): every `online_only` rule covering it is
    /// pending again and its re-arm count moves, so a pass that claimed an older count cannot
    /// complete.
    pub fn rearm(&self, group_id: &str, path: &str) -> Result<usize, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            Ok(tx.execute(
                "UPDATE retention_rules SET rearm_seq = rearm_seq + 1, apply_state = 'pending' \
                 WHERE group_id = ?1 AND rule = 'online_only' \
                   AND (path = '' OR ?2 = path OR substr(?2, 1, length(path) + 1) = path || '/')",
                rusqlite::params![group_id, path],
            )?)
        })
    }

    /// [`Self::rearm`] for every `online_only` rule of the group (Free Up Space on the folder).
    pub fn rearm_group(&self, group_id: &str) -> Result<usize, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            Ok(tx.execute(
                "UPDATE retention_rules SET rearm_seq = rearm_seq + 1, apply_state = 'pending' \
                 WHERE group_id = ?1 AND rule = 'online_only'",
                [group_id],
            )?)
        })
    }

    /// What the group's rules add up to, for the status line.
    pub fn summary(&self, group_id: &str) -> Result<RuleSummary, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row = conn.query_row(
                "SELECT COUNT(*), \
                        COALESCE(SUM(rule = 'online_only'), 0), \
                        COALESCE(SUM(rule = 'online_only' AND apply_state = 'pending'), 0), \
                        COALESCE(SUM(CASE WHEN rule = 'online_only' THEN done_count END), 0), \
                        COALESCE(SUM(CASE WHEN rule = 'online_only' THEN skipped_count END), 0), \
                        COALESCE(SUM(CASE WHEN rule = 'online_only' THEN retryable_count END), 0) \
                 FROM retention_rules WHERE group_id = ?1",
                [group_id],
                |r| {
                    Ok(RuleSummary {
                        rule_count: r.get::<_, i64>(0)?.max(0) as u64,
                        online_only_count: r.get::<_, i64>(1)?.max(0) as u64,
                        pending_count: r.get::<_, i64>(2)?.max(0) as u64,
                        counts: ApplyCounts {
                            done: r.get::<_, i64>(3)?.max(0) as u32,
                            skipped: r.get::<_, i64>(4)?.max(0) as u32,
                            retryable: r.get::<_, i64>(5)?.max(0) as u32,
                        },
                    })
                },
            )?;
            Ok(row)
        })
    }

    /// Every pinned path (`keep` rule) of `group_id`, in path order.
    pub fn list(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        let mut paths: Vec<String> =
            self.rules(group_id)?.kept_paths().map(str::to_owned).collect();
        paths.sort();
        Ok(paths)
    }

    /// Every pinned path (`keep` rule) of every group, as `(group_id, path)`.
    pub fn list_all(&self) -> Result<Vec<(String, String)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT group_id, path FROM retention_rules WHERE rule = 'keep' \
                 ORDER BY group_id ASC, path ASC",
            )?;
            let rows =
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }

    /// The policy in force at `path`: pinned when the nearest explicit rule is `keep`.
    pub fn retention(&self, group_id: &str, path: &str) -> Result<Retention, SyncSqliteError> {
        let rules = self.rules(group_id)?;
        let nearest = rules.nearest(path);
        let policy = match nearest {
            Some((_, Rule::Keep)) => RetentionPolicy::Pinned,
            Some((_, Rule::OnlineOnly)) => RetentionPolicy::OnlineOnly,
            None => RetentionPolicy::Reclaimable,
        };
        let explicit = matches!(nearest, Some((at, _)) if at == path);
        Ok(Retention { policy, explicit })
    }

    /// Pinned paths of `group_id` that lie strictly beneath `prefix` (every one when `prefix` is
    /// the root).
    pub fn pinned_beneath(
        &self,
        group_id: &str,
        prefix: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        let rules = self.rules(group_id)?;
        let mut paths: Vec<String> = rules
            .beneath(prefix)
            .into_iter()
            .filter(|(_, rule)| *rule == Rule::Keep)
            .map(|(at, _)| at.to_owned())
            .collect();
        paths.sort();
        Ok(paths)
    }
}

#[cfg(test)]
mod tests;
