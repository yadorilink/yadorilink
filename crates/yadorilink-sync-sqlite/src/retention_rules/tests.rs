#![cfg(test)]

use std::sync::Arc;

use yadorilink_sqlite_runtime::{DatabaseError, SyncDatabase};

use super::*;

fn schema_init(conn: &rusqlite::Connection) -> Result<(), DatabaseError> {
    // The full schema: a rule also republishes provider items, which reads the provider tables.
    crate::replica_tables::init_for_tests(conn)
        .map_err(|e| DatabaseError::CorruptSchema(e.to_string()))?;
    yadorilink_sqlite_runtime::init_schema(conn)?;
    init_retention_rules_schema(conn).map_err(|e| DatabaseError::CorruptSchema(e.to_string()))
}

fn in_memory() -> Arc<SyncDatabase> {
    Arc::new(SyncDatabase::open_in_memory(schema_init).expect("open in-memory db"))
}

fn kept(repo: &RetentionRuleRepository, group: &str, path: &str) -> bool {
    repo.retention(group, path).unwrap().policy == RetentionPolicy::Pinned
}

fn set_of(rules: &[(&str, Rule)]) -> RuleSet {
    RuleSet::new(rules.iter().map(|(p, r)| ((*p).to_owned(), *r)))
}

/// The path table: a rule covers itself and what is beneath it, on whole path components, and the
/// root covers everything; the table is the same for separators, case, Unicode and wildcard
/// characters (a rule is a path, never a pattern).
#[test]
fn a_rule_covers_itself_and_its_subtree_but_not_a_sibling_sharing_its_prefix() {
    let rules = set_of(&[("dir", Rule::Keep), ("notes.txt", Rule::Keep)]);
    for (path, expect) in [
        ("dir", true),
        ("dir/a.txt", true),
        ("dir/sub/b.txt", true),
        ("notes.txt", true),
        ("dir2/a.txt", false),
        ("dir.txt", false),
        ("notes.txt.bak", false),
        ("other/dir/a.txt", false),
        // Case and Unicode are exact bytes of the path; a wildcard is an ordinary character.
        ("Dir/a.txt", false),
        ("dir\u{301}/a.txt", false),
        ("di*/a.txt", false),
    ] {
        assert_eq!(rules.is_kept(path), expect, "{path}");
    }
    assert!(set_of(&[("", Rule::Keep)]).is_kept("anything/at/all.txt"), "the root covers all");
    assert!(!set_of(&[]).is_kept("dir/a.txt"));
    assert!(set_of(&[("資料/日本語", Rule::Keep)]).is_kept("資料/日本語/ファイル.txt"));
    assert!(set_of(&[("a*b", Rule::Keep)]).is_kept("a*b/c"));
    assert!(!set_of(&[("a*b", Rule::Keep)]).is_kept("axxb/c"));
}

/// Longest prefix wins, in both directions.
#[test]
fn the_nearest_rule_wins() {
    let rules = set_of(&[
        ("a", Rule::OnlineOnly),
        ("a/b", Rule::Keep),
        ("a/b/c", Rule::OnlineOnly),
        ("k", Rule::Keep),
        ("k/o", Rule::OnlineOnly),
    ]);
    assert_eq!(rules.nearest("a/x"), Some(("a", Rule::OnlineOnly)));
    assert_eq!(rules.nearest("a/b/x"), Some(("a/b", Rule::Keep)));
    assert_eq!(rules.nearest("a/b/c/d"), Some(("a/b/c", Rule::OnlineOnly)));
    assert_eq!(rules.nearest("z"), None, "no rule: the folder's mode decides");
    assert!(rules.is_kept("a/b/x"));
    assert!(!rules.is_kept("a/x"), "an online-only folder is not kept");
    assert!(!rules.is_kept("a/b/c/d"));
    assert!(rules.is_kept("k/x"));
    assert!(!rules.is_kept("k/o/x"), "an online-only exception under a kept folder");
}

/// `kept_below`: an exception under an online-only ancestor counts; the ancestor's own rule does
/// not authorise dropping the directory.
#[test]
fn a_directory_with_a_kept_descendant_is_kept_below() {
    let rules = set_of(&[("a", Rule::OnlineOnly), ("a/b", Rule::Keep)]);
    assert!(rules.kept_below("a"), "a/b is kept");
    assert!(rules.kept_below("a/b"));
    assert!(rules.kept_below("a/b/deeper"), "kept through its own rule");
    assert!(!rules.kept_below("a/c"));
    assert!(!set_of(&[("a", Rule::OnlineOnly)]).kept_below("a"));
    assert!(set_of(&[("a/b", Rule::Keep)]).kept_below("a"));
    assert!(!set_of(&[("a/b", Rule::Keep)]).kept_below("a/bc"));
    assert!(set_of(&[("", Rule::Keep)]).kept_below("x"));
    assert!(set_of(&[("a/b", Rule::Keep)]).kept_below(""), "beneath the root is every rule");
}

#[test]
fn retention_is_reclaimable_until_kept_and_reports_whether_the_rule_is_explicit() {
    let repo = RetentionRuleRepository::new(in_memory());
    assert_eq!(
        repo.retention("g", "dir/a.txt").unwrap(),
        Retention { policy: RetentionPolicy::Reclaimable, explicit: false }
    );
    repo.pin("g", "dir").unwrap();
    assert_eq!(
        repo.retention("g", "dir").unwrap(),
        Retention { policy: RetentionPolicy::Pinned, explicit: true }
    );
    assert_eq!(
        repo.retention("g", "dir/a.txt").unwrap(),
        Retention { policy: RetentionPolicy::Pinned, explicit: false },
        "a descendant inherits, also one that did not exist when the folder was kept"
    );
    assert!(!kept(&repo, "g", "dir2/a.txt"));
    assert!(!kept(&repo, "other-group", "dir/a.txt"), "a rule belongs to its group");
}

#[test]
fn a_rule_survives_reopening_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.db");
    {
        let database = Arc::new(SyncDatabase::open(&path, schema_init).unwrap());
        RetentionRuleRepository::new(database).pin("g", "dir").unwrap();
    }
    let database = Arc::new(SyncDatabase::open(&path, schema_init).unwrap());
    let repo = RetentionRuleRepository::new(database);
    assert_eq!(repo.list("g").unwrap(), vec!["dir".to_string()]);
    assert!(kept(&repo, "g", "dir/deep/file.txt"));
    assert!(repo.unpin("g", "dir").unwrap(), "clear reports that there was a rule");
    assert!(!kept(&repo, "g", "dir/deep/file.txt"));
    assert!(!repo.unpin("g", "dir").unwrap(), "clearing a path with no rule is a no-op");
}

#[test]
fn setting_the_same_rule_twice_keeps_one_row_and_one_generation() {
    let repo = RetentionRuleRepository::new(in_memory());
    assert!(repo.set("g", "a", Some(Rule::Keep)).unwrap());
    let first = generation_of(&repo, "g", "a");
    assert!(!repo.set("g", "a", Some(Rule::Keep)).unwrap(), "a repeat is a no-op");
    assert_eq!(repo.list("g").unwrap(), vec!["a".to_string()]);
    assert_eq!(generation_of(&repo, "g", "a"), first, "a no-op does not make a new generation");
}

fn generation_of(repo: &RetentionRuleRepository, group: &str, path: &str) -> i64 {
    repo.database
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT generation FROM retention_rules WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group, path],
                |r| r.get(0),
            )?)
        })
        .unwrap()
}

/// Setting a rule clears the rules beneath it and makes a new generation; a generation is never
/// reused, even after its row is gone.
#[test]
fn setting_a_rule_clears_what_is_beneath_and_never_reuses_a_generation() {
    let repo = RetentionRuleRepository::new(in_memory());
    repo.set("g", "dir/a", Some(Rule::Keep)).unwrap();
    repo.set("g", "dir/b/c", Some(Rule::OnlineOnly)).unwrap();
    repo.set("g", "dir2", Some(Rule::Keep)).unwrap();
    let before = generation_of(&repo, "g", "dir2");
    repo.set("g", "dir", Some(Rule::OnlineOnly)).unwrap();
    let rules = repo.rules("g").unwrap();
    assert_eq!(rules.beneath("dir"), Vec::<(&str, Rule)>::new(), "beneath it is cleared");
    assert_eq!(rules.nearest("dir2/x"), Some(("dir2", Rule::Keep)), "a sibling is untouched");
    let at_dir = generation_of(&repo, "g", "dir");
    assert!(at_dir > before);
    repo.unpin("g", "dir").unwrap();
    repo.set("g", "dir", Some(Rule::OnlineOnly)).unwrap();
    assert!(
        generation_of(&repo, "g", "dir") > at_dir,
        "the old generation is not handed out again"
    );
    // The root clears everything else in the group, and only that group.
    repo.set("other", "x", Some(Rule::Keep)).unwrap();
    repo.set("g", "", Some(Rule::Keep)).unwrap();
    assert_eq!(repo.rules("g").unwrap().kept_paths().collect::<Vec<_>>(), vec![""]);
    assert!(kept(&repo, "other", "x"));
}

/// An online-only rule is pending until the apply job completes it; a keep rule has nothing to apply.
#[test]
fn an_online_only_rule_is_pending_and_a_keep_rule_is_not() {
    let repo = RetentionRuleRepository::new(in_memory());
    repo.set("g", "a", Some(Rule::OnlineOnly)).unwrap();
    repo.set("g", "b", Some(Rule::Keep)).unwrap();
    let state = |path: &str| -> String {
        repo.database
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn.query_row(
                    "SELECT apply_state FROM retention_rules WHERE group_id = 'g' AND path = ?1",
                    [path],
                    |r| r.get(0),
                )?)
            })
            .unwrap()
    };
    assert_eq!(state("a"), "pending");
    assert_eq!(state("b"), "none");
}

/// There is no per-child override of a `keep`: a path covered only by an ancestor stays kept when
/// cleared by itself, and a rule set on a child before its ancestor was set is gone with it.
#[test]
fn clear_removes_only_the_rule_set_at_that_exact_path() {
    let repo = RetentionRuleRepository::new(in_memory());
    repo.pin("g", "dir").unwrap();
    assert!(!repo.unpin("g", "dir/a.txt").unwrap(), "nothing was set at the child");
    assert!(kept(&repo, "g", "dir/a.txt"), "the ancestor's rule still covers it");

    repo.pin("g", "dir/keep.txt").unwrap();
    assert!(repo.unpin("g", "dir").unwrap());
    assert!(!kept(&repo, "g", "dir/a.txt"));
    assert!(kept(&repo, "g", "dir/keep.txt"), "the child's own rule is untouched");
}

#[test]
fn kept_beneath_lists_strict_descendants_only() {
    let repo = RetentionRuleRepository::new(in_memory());
    for p in ["dir", "dir2/c.txt", "dirx", "a", "b/x"] {
        repo.pin("g", p).unwrap();
    }
    repo.set("g", "dir/online", Some(Rule::OnlineOnly)).unwrap();
    repo.pin("other", "dir/z.txt").unwrap();
    assert_eq!(
        repo.pinned_beneath("g", "dir").unwrap(),
        Vec::<String>::new(),
        "dir/online is not a keep"
    );
    repo.pin("g", "b/x/y").unwrap();
    assert_eq!(
        repo.pinned_beneath("g", "b").unwrap(),
        vec!["b/x".to_string(), "b/x/y".to_string()],
        "a pin set beneath a pin is kept"
    );
    repo.set("g", "b/x", Some(Rule::Keep)).unwrap();
    assert_eq!(
        repo.pinned_beneath("g", "b").unwrap(),
        vec!["b/x".to_string()],
        "setting a rule (not pinning) clears what was beneath it"
    );
    assert_eq!(
        repo.pinned_beneath("g", "").unwrap().len(),
        5,
        "beneath the root is every keep rule"
    );
}

/// The SQL twin agrees with the Rust statement of the rule on every combination.
#[test]
fn the_sql_twin_agrees_with_the_rust_rule() {
    let paths = ["", "a", "a/b", "a/b/c", "a/b/c/d", "ab", "a/bc", "k", "k/o", "k/o/x", "z", "a/x"];
    let rule_sets: [&[(&str, Rule)]; 5] = [
        &[],
        &[("a", Rule::Keep)],
        &[("a", Rule::OnlineOnly), ("a/b", Rule::Keep), ("a/b/c", Rule::OnlineOnly)],
        &[("k", Rule::Keep), ("k/o", Rule::OnlineOnly)],
        &[("", Rule::Keep), ("a", Rule::OnlineOnly)],
    ];
    for rules in rule_sets {
        let repo = RetentionRuleRepository::new(in_memory());
        // Rows are inserted directly: `set` clears beneath, and the rule sets above are the shape
        // the table can hold only through nested sets in the right order.
        repo.database
            .write_immediate::<_, SyncSqliteError>(|tx| {
                for (path, rule) in rules {
                    tx.execute(
                        "INSERT INTO retention_rules (group_id, path, rule, generation, set_at_unix_nanos) \
                         VALUES ('g', ?1, ?2, 1, 0)",
                        rusqlite::params![path, rule.as_db_str()],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        let rust = repo.rules("g").unwrap();
        for path in paths {
            let sql_kept: bool = repo
                .database
                .read::<_, SyncSqliteError>(|conn| {
                    Ok(conn.query_row(
                        &format!("SELECT {}", kept_by_rule_sql("'g'", "?1")),
                        [path],
                        |r| r.get(0),
                    )?)
                })
                .unwrap();
            assert_eq!(sql_kept, rust.is_kept(path), "{rules:?} at {path:?}");
            let sql_online_only: bool = repo
                .database
                .read::<_, SyncSqliteError>(|conn| {
                    Ok(conn.query_row(
                        &format!("SELECT {}", online_only_by_rule_sql("'g'", "?1")),
                        [path],
                        |r| r.get(0),
                    )?)
                })
                .unwrap();
            assert_eq!(
                sql_online_only,
                rust.is_online_only(path),
                "online-only: {rules:?} at {path:?}"
            );
            let sql_below: bool = repo
                .database
                .read::<_, SyncSqliteError>(|conn| {
                    Ok(conn.query_row(
                        &format!(
                            "SELECT {} OR (1 AND {})",
                            kept_by_rule_sql("'g'", "?1"),
                            keep_rule_beneath_sql("'g'", "?1")
                        ),
                        [path],
                        |r| r.get(0),
                    )?)
                })
                .unwrap();
            // The root has no "beneath" in the SQL twin (an old behaviour the directory check
            // keeps): compare everywhere else.
            if !path.is_empty() {
                assert_eq!(sql_below, rust.kept_below(path), "below: {rules:?} at {path:?}");
            }
        }
    }
}

/// A pin does not clear the pins beneath it: pinning a folder and unpinning it leaves a child's
/// own pin in force, as before rules existed.
#[test]
fn pinning_a_folder_keeps_a_childs_own_pin() {
    let repo = RetentionRuleRepository::new(in_memory());
    repo.pin("g", "docs/a").unwrap();
    repo.pin("g", "docs").unwrap();
    assert!(repo.unpin("g", "docs").unwrap());
    assert!(kept(&repo, "g", "docs/a"), "the child's pin survived the folder's");
}

// --- the apply pass's hold on a rule ---

const LEASE: std::time::Duration = std::time::Duration::from_secs(600);

fn pending_online_only(repo: &RetentionRuleRepository, path: &str) -> PendingRule {
    repo.set("g", path, Some(Rule::OnlineOnly)).unwrap();
    repo.pending_rules().unwrap().into_iter().find(|rule| rule.path == path).expect("pending")
}

/// Only an `online_only` rule is ever pending; a `keep` rule has nothing to apply.
#[test]
fn only_an_online_only_rule_is_pending() {
    let repo = RetentionRuleRepository::new(in_memory());
    repo.set("g", "keep", Some(Rule::Keep)).unwrap();
    let rule = pending_online_only(&repo, "free");
    assert_eq!(repo.pending_rules().unwrap(), vec![rule]);
}

/// One pass holds a rule at a time; a held rule is reclaimable only after the lease, and only at
/// the generation the pass read.
#[test]
fn a_claim_is_exclusive_until_its_lease_runs_out_and_is_tied_to_the_generation() {
    let repo = RetentionRuleRepository::new(in_memory());
    let rule = pending_online_only(&repo, "free");
    let now = 1_000_000_000_000i64;
    let first = repo.claim_rule("g", "free", rule.generation, now, LEASE).unwrap();
    assert!(first.is_some());
    assert!(
        repo.claim_rule("g", "free", rule.generation, now + 1, LEASE).unwrap().is_none(),
        "held"
    );
    let after_lease = now + LEASE.as_nanos() as i64 + 1;
    assert!(
        repo.claim_rule("g", "free", rule.generation, after_lease, LEASE).unwrap().is_some(),
        "a claim older than the lease is reclaimable"
    );
    assert!(
        repo.claim_rule(
            "g",
            "free",
            rule.generation + 1,
            after_lease + LEASE.as_nanos() as i64,
            LEASE
        )
        .unwrap()
        .is_none(),
        "another generation is not this rule"
    );
}

/// A pass finishes a rule only against what it claimed: a re-arm during the pass, or a newer rule
/// at the path, leaves it pending.
#[test]
fn completing_is_a_compare_and_set_on_the_generation_and_the_rearm_count() {
    let repo = RetentionRuleRepository::new(in_memory());
    let rule = pending_online_only(&repo, "free/dir");
    let counts = ApplyCounts { done: 3, skipped: 1, retryable: 0 };

    // A clean pass completes and leaves its counts.
    let claim = repo.claim_rule("g", "free/dir", rule.generation, 10, LEASE).unwrap().unwrap();
    assert!(repo.complete_rule("g", "free/dir", claim, counts).unwrap());
    let row = repo.rule_row("g", "free/dir").unwrap().unwrap();
    assert!(!row.pending);
    assert_eq!(row.counts, counts);
    assert!(repo.pending_rules().unwrap().is_empty());

    // A download of a freed path settles: the rule is pending again and the count moved.
    assert_eq!(repo.rearm("g", "free/dir/a.bin").unwrap(), 1);
    let row = repo.rule_row("g", "free/dir").unwrap().unwrap();
    assert!(row.pending && row.rearm_seq == claim.rearm_seq + 1);

    // A re-arm DURING a pass: the pass cannot complete, the rule stays pending, the counts are
    // still recorded and the claim is released.
    let claim = repo.claim_rule("g", "free/dir", rule.generation, 20, LEASE).unwrap().unwrap();
    repo.rearm("g", "free/dir/b.bin").unwrap();
    assert!(!repo.complete_rule("g", "free/dir", claim, counts).unwrap());
    assert!(repo.rule_row("g", "free/dir").unwrap().unwrap().pending);
    assert!(
        repo.claim_rule("g", "free/dir", rule.generation, 21, LEASE).unwrap().is_some(),
        "the failed completion released the claim"
    );

    // A keep then online-only again is a newer rule: the older pass cannot complete it.
    let old = repo.claim_rule("g", "free/dir", rule.generation, 10_000_000_000_000, LEASE);
    let old =
        old.unwrap().unwrap_or(RuleClaim { generation: rule.generation, rearm_seq: 0, token: 0 });
    repo.set("g", "free/dir", Some(Rule::Keep)).unwrap();
    repo.set("g", "free/dir", Some(Rule::OnlineOnly)).unwrap();
    assert!(!repo.complete_rule("g", "free/dir", old, counts).unwrap(), "an older generation");
    assert!(repo.rule_row("g", "free/dir").unwrap().unwrap().pending);
}

/// A pass that could not try some files releases the rule pending, with its counts; a re-arm
/// reaches every rule that covers the path, and Free Up Space re-arms the whole group.
#[test]
fn a_released_rule_stays_pending_and_a_rearm_reaches_every_covering_rule() {
    let repo = RetentionRuleRepository::new(in_memory());
    repo.set("g", "a", Some(Rule::OnlineOnly)).unwrap();
    repo.set("g", "b", Some(Rule::OnlineOnly)).unwrap();
    repo.set("g", "k", Some(Rule::Keep)).unwrap();
    let a = repo.pending_rules().unwrap().into_iter().find(|r| r.path == "a").unwrap();
    let claim = repo.claim_rule("g", "a", a.generation, 1, LEASE).unwrap().unwrap();
    let counts = ApplyCounts { done: 1, skipped: 0, retryable: 2 };
    assert!(repo.release_rule("g", "a", claim, counts).unwrap());
    let row = repo.rule_row("g", "a").unwrap().unwrap();
    assert!(row.pending && row.counts == counts);

    // Finish both, then re-arm by path: only the covering rule is pending again.
    for path in ["a", "b"] {
        let rule = repo.pending_rules().unwrap().into_iter().find(|r| r.path == path).unwrap();
        let claim = repo.claim_rule("g", path, rule.generation, 2, LEASE).unwrap().unwrap();
        assert!(repo.complete_rule("g", path, claim, ApplyCounts::default()).unwrap());
    }
    assert_eq!(repo.rearm("g", "a/x.bin").unwrap(), 1);
    assert_eq!(
        repo.pending_rules().unwrap().iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        ["a"]
    );
    assert_eq!(
        repo.rearm("g", "ab/x.bin").unwrap(),
        0,
        "a sibling sharing a prefix is not covered"
    );
    // Free Up Space on the folder re-arms every online-only rule of the group, and no keep rule.
    assert_eq!(repo.rearm_group("g").unwrap(), 2);
    assert_eq!(repo.pending_rules().unwrap().len(), 2);
    assert!(!repo.rule_row("g", "k").unwrap().unwrap().pending);
}

/// A pass whose lease ran out and was taken over can no longer release or complete the rule, and
/// a rule replaced while claimed is claimable at once rather than after the old lease.
#[test]
fn a_taken_over_claim_is_dead_and_a_replaced_rule_is_not_held_by_the_old_lease() {
    let repo = RetentionRuleRepository::new(in_memory());
    let rule = pending_online_only(&repo, "free");
    let a = repo.claim_rule("g", "free", rule.generation, 1, LEASE).unwrap().unwrap();
    let later = 1 + LEASE.as_nanos() as i64 + 1;
    let b = repo.claim_rule("g", "free", rule.generation, later, LEASE).unwrap().unwrap();
    assert!(
        !repo.complete_rule("g", "free", a, ApplyCounts::default()).unwrap(),
        "A's token is stale"
    );
    assert!(!repo.release_rule("g", "free", a, ApplyCounts::default()).unwrap());
    assert!(
        repo.claim_rule("g", "free", rule.generation, later + 1, LEASE).unwrap().is_none(),
        "A did not clear B's lease"
    );
    assert!(repo.complete_rule("g", "free", b, ApplyCounts::default()).unwrap());

    // Replace a held rule: the new generation is claimable immediately.
    let rule = pending_online_only(&repo, "other");
    repo.claim_rule("g", "other", rule.generation, 5, LEASE).unwrap().unwrap();
    repo.set("g", "other", Some(Rule::Keep)).unwrap();
    repo.set("g", "other", Some(Rule::OnlineOnly)).unwrap();
    let fresh = repo.pending_rules().unwrap().into_iter().find(|r| r.path == "other").unwrap();
    assert!(repo.claim_rule("g", "other", fresh.generation, 6, LEASE).unwrap().is_some());
}

/// The status line's totals: every explicit rule counts, only `online_only` rules carry apply
/// state and outcome counts.
#[test]
fn the_summary_adds_up_rules_pending_state_and_outcomes() {
    let repo = RetentionRuleRepository::new(in_memory());
    assert_eq!(repo.summary("g").unwrap(), RuleSummary::default());
    repo.set("g", "keep", Some(Rule::Keep)).unwrap();
    repo.set("g", "a", Some(Rule::OnlineOnly)).unwrap();
    repo.set("g", "b", Some(Rule::OnlineOnly)).unwrap();
    let a = repo.pending_rules().unwrap().into_iter().find(|r| r.path == "a").unwrap();
    let claim = repo.claim_rule("g", "a", a.generation, 1, LEASE).unwrap().unwrap();
    let counts = ApplyCounts { done: 4, skipped: 2, retryable: 0 };
    assert!(repo.complete_rule("g", "a", claim, counts).unwrap());

    let summary = repo.summary("g").unwrap();
    assert_eq!((summary.rule_count, summary.online_only_count, summary.pending_count), (3, 2, 1));
    assert_eq!(summary.counts, counts);
    assert_eq!(repo.summary("other").unwrap(), RuleSummary::default());
}

/// `retention` names the rule in force: keep, online-only, or none, and whether it was set here.
#[test]
fn retention_reports_online_only_and_whether_the_rule_is_explicit() {
    let repo = RetentionRuleRepository::new(in_memory());
    repo.set("g", "docs", Some(Rule::OnlineOnly)).unwrap();
    let inherited = repo.retention("g", "docs/a.bin").unwrap();
    assert_eq!((inherited.policy, inherited.explicit), (RetentionPolicy::OnlineOnly, false));
    let explicit = repo.retention("g", "docs").unwrap();
    assert_eq!((explicit.policy, explicit.explicit), (RetentionPolicy::OnlineOnly, true));
    assert_eq!(repo.retention("g", "other").unwrap().policy, RetentionPolicy::Reclaimable);
}
