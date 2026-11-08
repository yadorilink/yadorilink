#![cfg(test)]

//! The apply pass of an online-only rule: it frees the OS copies under the rule through the
//! ordinary eviction path, counts what it did on the rule, and never frees what a nearer rule or
//! a newer generation says to leave.

use std::sync::Arc;

use yadorilink_sync_sqlite::Rule;

use super::*;
use crate::provider_auto_reclaim::tests::Rig;
use crate::provider_evict::ProviderEvictor;
use crate::provider_publication::EvictOutcome as HostAnswer;
use crate::provider_reclaim::tests::GROUP;

fn apply_for(rig: &Rig) -> RetentionApply {
    let reclaim = rig.fx.reclaim();
    let evictor = Arc::new(ProviderEvictor::new(
        rig.fx.state.clone(),
        rig.fx.host.clone(),
        reclaim,
        rig.fx.membership.clone(),
    ));
    RetentionApply::new(
        rig.fx.state.clone(),
        evictor,
        rig.fx.membership.clone(),
        Arc::new(SystemEnvironment),
    )
    .with_pace(Duration::ZERO)
}

fn rules(rig: &Rig) -> &yadorilink_sync_sqlite::RetentionRuleRepository {
    rig.fx.state.replica_coordinator.retention_rules()
}

fn evictions(rig: &Rig) -> usize {
    rig.fx.log.lock().unwrap().iter().filter(|e| *e == "host_evict").count()
}

/// The copies under the rule go, through the eviction path, and nothing else does; the rule ends
/// `done` with the counts on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pass_frees_the_copies_under_the_rule_and_completes_it() {
    let rig = Rig::new();
    rig.downloaded("docs/free/a.bin", 1, 4096);
    rig.downloaded("docs/free/deeper/b.bin", 2, 2048);
    rig.downloaded("docs/other.bin", 3, 1024);
    rig.host_reports();
    rules(&rig).set(GROUP, "docs/free", Some(Rule::OnlineOnly)).unwrap();

    let outcomes = apply_for(&rig).run_pass().await;

    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0].1,
        RuleOutcome::Completed(ApplyCounts { done: 2, skipped: 0, retryable: 0 })
    );
    assert_eq!(evictions(&rig), 2, "only the two files under the rule were handed to the host");
    let row = rules(&rig).rule_row(GROUP, "docs/free").unwrap().unwrap();
    assert!(!row.pending);
    assert_eq!(row.counts.done, 2);
    // Finished: the next pass has nothing to do.
    assert!(apply_for(&rig).run_pass().await.is_empty());
}

/// A kept exception under the rule is not this rule's to free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kept_exception_under_the_rule_is_left_alone() {
    let rig = Rig::new();
    rig.downloaded("docs/free/a.bin", 1, 4096);
    rig.downloaded("docs/free/keep.bin", 2, 2048);
    rig.host_reports();
    rules(&rig).set(GROUP, "docs/free", Some(Rule::OnlineOnly)).unwrap();
    rules(&rig).pin(GROUP, "docs/free/keep.bin").unwrap();

    let outcomes = apply_for(&rig).run_pass().await;

    assert_eq!(
        outcomes[0].1,
        RuleOutcome::Completed(ApplyCounts { done: 1, skipped: 0, retryable: 0 })
    );
    assert_eq!(evictions(&rig), 1, "the kept file was never offered to the host");
}

/// A rule on a single file names the file itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_on_one_file_frees_that_file() {
    let rig = Rig::new();
    rig.downloaded("a.bin", 1, 4096);
    rig.downloaded("b.bin", 2, 4096);
    rig.host_reports();
    rules(&rig).set(GROUP, "a.bin", Some(Rule::OnlineOnly)).unwrap();

    let outcomes = apply_for(&rig).run_pass().await;
    assert_eq!(
        outcomes[0].1,
        RuleOutcome::Completed(ApplyCounts { done: 1, skipped: 0, retryable: 0 })
    );
    assert_eq!(evictions(&rig), 1);
}

/// What the host refuses on purpose (a file with unsynced changes, open) is skipped and counted,
/// and does not stop the rest or keep the rule pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_the_host_refuses_is_skipped_and_counted_and_the_rest_are_freed() {
    let rig = Rig::new();
    rig.downloaded("free/a.bin", 1, 4096);
    rig.downloaded("free/b.bin", 2, 4096);
    rig.host_reports();
    rig.fx.host.answers.lock().unwrap().push_back(HostAnswer::Busy);
    rules(&rig).set(GROUP, "free", Some(Rule::OnlineOnly)).unwrap();

    let outcomes = apply_for(&rig).run_pass().await;

    assert_eq!(
        outcomes[0].1,
        RuleOutcome::Completed(ApplyCounts { done: 1, skipped: 1, retryable: 0 }),
        "{outcomes:?}"
    );
    assert!(!rules(&rig).rule_row(GROUP, "free").unwrap().unwrap().pending);
}

/// A host that is not connected is not an error to give up on: the rule stays pending and the next
/// pass frees the files.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_is_not_connected_leaves_the_rule_pending_until_it_is() {
    let rig = Rig::new();
    rig.downloaded("free/a.bin", 1, 4096);
    rig.host_reports();
    rules(&rig).set(GROUP, "free", Some(Rule::OnlineOnly)).unwrap();
    let apply = apply_for(&rig);

    rig.fx.host.connected.store(false, std::sync::atomic::Ordering::SeqCst);
    let first = apply.run_pass().await;
    assert_eq!(first[0].1, RuleOutcome::Pending(ApplyCounts { done: 0, skipped: 0, retryable: 1 }));
    assert!(rules(&rig).rule_row(GROUP, "free").unwrap().unwrap().pending);
    assert_eq!(evictions(&rig), 0);

    rig.fx.host.connected.store(true, std::sync::atomic::Ordering::SeqCst);
    let second = apply.run_pass().await;
    assert_eq!(
        second[0].1,
        RuleOutcome::Completed(ApplyCounts { done: 1, skipped: 0, retryable: 0 })
    );
}

/// A pass that read an older generation applies nothing: a keep then online-only again is a newer
/// rule, and the older read cannot claim it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_holding_an_older_generation_applies_nothing() {
    let rig = Rig::new();
    rig.downloaded("free/a.bin", 1, 4096);
    rig.host_reports();
    rules(&rig).set(GROUP, "free", Some(Rule::OnlineOnly)).unwrap();
    let stale = rules(&rig).pending_rules().unwrap().remove(0);
    rules(&rig).set(GROUP, "free", Some(Rule::Keep)).unwrap();
    rules(&rig).set(GROUP, "free", Some(Rule::OnlineOnly)).unwrap();

    let outcome = apply_for(&rig).apply_rule(&stale).await;

    assert_eq!(outcome, RuleOutcome::NotApplied);
    assert_eq!(evictions(&rig), 0, "the older generation freed nothing");
    // The current generation is applied normally.
    let outcomes = apply_for(&rig).run_pass().await;
    assert!(matches!(outcomes[0].1, RuleOutcome::Completed(_)));
}

/// A rule turned back to keep while nothing has run is never applied: it is not pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_changed_to_keep_before_the_pass_is_never_applied() {
    let rig = Rig::new();
    rig.downloaded("free/a.bin", 1, 4096);
    rig.host_reports();
    rules(&rig).set(GROUP, "free", Some(Rule::OnlineOnly)).unwrap();
    rules(&rig).set(GROUP, "free", Some(Rule::Keep)).unwrap();

    assert!(apply_for(&rig).run_pass().await.is_empty());
    assert_eq!(evictions(&rig), 0);
}

/// The rule that frees a path is checked again right before the host is asked: a rule cleared or
/// replaced after the pass's own check drops nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_evictor_drops_nothing_once_the_rule_is_no_longer_what_frees_the_path() {
    let rig = Rig::new();
    rig.downloaded("free/a.bin", 1, 4096);
    rig.host_reports();
    rules(&rig).set(GROUP, "free", Some(Rule::OnlineOnly)).unwrap();
    let stale = rules(&rig).pending_rules().unwrap().remove(0);
    let reclaim = rig.fx.reclaim();
    let evictor = ProviderEvictor::new(
        rig.fx.state.clone(),
        rig.fx.host.clone(),
        reclaim,
        rig.fx.membership.clone(),
    );
    rules(&rig).set(GROUP, "free", None).unwrap();

    let hold = crate::provider_evict::RuleHold { rule_path: "free", generation: stale.generation };
    let result = evictor.evict_applying(GROUP, "free/a.bin", None, Some(hold)).await;

    assert!(result.is_err(), "{result:?}");
    assert_eq!(evictions(&rig), 0);
}
