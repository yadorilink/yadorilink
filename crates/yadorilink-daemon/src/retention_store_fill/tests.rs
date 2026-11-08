#![cfg(test)]

//! The store-only fetch: on a full-replica folder the blocks of online-only paths keep coming in,
//! no copy is placed, nothing is marked present, and an on-demand folder or a low disk does
//! nothing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_sync_sqlite::Rule;

use super::*;
use crate::provider_auto_reclaim::tests::Rig;
use crate::provider_reclaim::tests::{data_of, GROUP};

struct Env {
    low_disk: AtomicBool,
}

impl FillEnvironment for Env {
    fn low_disk(&self) -> bool {
        self.low_disk.load(Ordering::SeqCst)
    }
}

fn fill_for(rig: &Rig) -> (RetentionStoreFill, Arc<Env>) {
    let env = Arc::new(Env { low_disk: AtomicBool::new(false) });
    (RetentionStoreFill::new(rig.fx.state.clone(), env.clone()), env)
}

fn make_eager(rig: &Rig) {
    rig.fx
        .state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy("/provider/photos", MaterializationPolicy::Eager)
        .unwrap();
}

fn hashes_of(rig: &Rig, path: &str) -> Vec<String> {
    let record = rig
        .fx
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, path)
        .unwrap()
        .unwrap();
    record.blocks.iter().map(|b| hex::encode(&b.hash)).collect()
}

fn materialization(
    rig: &Rig,
    path: &str,
) -> Option<yadorilink_replica_domain::session_state::MaterializationState> {
    rig.fx
        .state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(GROUP, path)
        .unwrap()
}

/// With nothing online-only there is nothing to fill, whatever the folder holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_an_online_only_rule_nothing_is_looked_at() {
    let rig = Rig::new();
    make_eager(&rig);
    rig.downloaded("a.bin", 1, 4096);
    let (fill, _) = fill_for(&rig);
    assert_eq!(fill.run_pass().await, FillSummary::default());
}

/// The blocks of an online-only path are checked, a complete version is trusted, and nothing is
/// marked present or placed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_complete_version_under_an_online_only_rule_is_checked_and_nothing_is_placed() {
    let rig = Rig::new();
    make_eager(&rig);
    rig.fx.commit("free/a.bin", 1, &[&data_of(1, 4096)]);
    rig.fx.commit("kept.bin", 2, &[&data_of(2, 4096)]);
    rig.fx.item("free/a.bin");
    rig.fx.item("kept.bin");
    rig.fx
        .state
        .replica_coordinator
        .retention_rules()
        .set(GROUP, "free", Some(Rule::OnlineOnly))
        .unwrap();
    let before = materialization(&rig, "free/a.bin");
    let (fill, _) = fill_for(&rig);

    let first = fill.run_pass().await;

    assert_eq!(first, FillSummary { checked: 1, complete: 1, incomplete: 0, stopped_early: false });
    assert_eq!(
        materialization(&rig, "free/a.bin"),
        before,
        "block availability is not OS residency"
    );
    // A version already verified is trusted on the next pass.
    let second = fill.run_pass().await;
    assert_eq!((second.checked, second.complete), (1, 1));
}

/// A block that is missing and cannot be fetched (no peer) leaves the version incomplete, and the
/// next pass completes it once the block is here: the reconcile is level-triggered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_block_is_incomplete_until_it_is_here() {
    let rig = Rig::new();
    make_eager(&rig);
    let data = data_of(7, 4096);
    rig.fx.commit("free/a.bin", 1, &[&data]);
    rig.fx.item("free/a.bin");
    rig.fx
        .state
        .replica_coordinator
        .retention_rules()
        .set(GROUP, "free", Some(Rule::OnlineOnly))
        .unwrap();
    let hash = hashes_of(&rig, "free/a.bin").remove(0);
    rig.fx.state.block_store.delete(&hash).unwrap();
    let (fill, _) = fill_for(&rig);

    let first = fill.run_pass().await;
    assert_eq!((first.checked, first.complete, first.incomplete), (1, 0, 1));

    rig.fx.state.block_store.put(&data).unwrap();
    // An unavailable version is backed off, not retried (and charged to the budget) every pass.
    let second = fill.run_pass().await;
    assert_eq!((second.checked, second.complete, second.incomplete), (1, 0, 1));
    // After the back-off it is looked at again and found complete.
    let mut done = FillSummary::default();
    for _ in 0..BACKOFF_PASSES {
        done = fill.run_pass().await;
        if done.complete == 1 {
            break;
        }
    }
    assert_eq!((done.checked, done.complete, done.incomplete), (1, 1, 0));
}

/// An on-demand folder is not a custodian: the job does nothing there, rules or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_on_demand_folder_is_skipped() {
    let rig = Rig::new();
    rig.fx.commit("free/a.bin", 1, &[&data_of(1, 4096)]);
    rig.fx.item("free/a.bin");
    rig.fx
        .state
        .replica_coordinator
        .retention_rules()
        .set(GROUP, "free", Some(Rule::OnlineOnly))
        .unwrap();
    let (fill, _) = fill_for(&rig);
    assert_eq!(fill.run_pass().await, FillSummary::default());
}

/// A low disk pauses the fill without looking at anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_low_disk_pauses_the_fill() {
    let rig = Rig::new();
    make_eager(&rig);
    rig.fx.commit("free/a.bin", 1, &[&data_of(1, 4096)]);
    rig.fx.item("free/a.bin");
    rig.fx
        .state
        .replica_coordinator
        .retention_rules()
        .set(GROUP, "free", Some(Rule::OnlineOnly))
        .unwrap();
    let (fill, env) = fill_for(&rig);
    env.low_disk.store(true, Ordering::SeqCst);
    let paused = fill.run_pass().await;
    assert!(paused.stopped_early && paused.checked == 0);
    env.low_disk.store(false, Ordering::SeqCst);
    assert_eq!(fill.run_pass().await.checked, 1);
}

/// A newer version supersedes the one being fetched: the next pass asks about the new blocks, and
/// an older version never settles its replacement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_newer_version_is_checked_afresh() {
    let rig = Rig::new();
    make_eager(&rig);
    rig.fx.commit("free/a.bin", 1, &[&data_of(1, 4096)]);
    rig.fx.item("free/a.bin");
    rig.fx
        .state
        .replica_coordinator
        .retention_rules()
        .set(GROUP, "free", Some(Rule::OnlineOnly))
        .unwrap();
    let (fill, _) = fill_for(&rig);
    assert_eq!(fill.run_pass().await.complete, 1);

    // The newer version's block is not here.
    let newer = data_of(9, 4096);
    rig.fx.commit("free/a.bin", 2, &[&newer]);
    let hash = hashes_of(&rig, "free/a.bin").remove(0);
    rig.fx.state.block_store.delete(&hash).unwrap();
    let summary = fill.run_pass().await;
    assert_eq!((summary.complete, summary.incomplete), (0, 1), "{summary:?}");
}

/// Files that cannot be completed at the front of the scan do not keep the ones behind them from
/// being tried: a pass that runs out of budget resumes where it stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_that_ran_out_of_budget_resumes_behind_the_files_it_could_not_finish() {
    let rig = Rig::new();
    make_eager(&rig);
    let total = FETCHES_PER_PASS + 6;
    for n in 0..total {
        let path = format!("free/f{n:03}.bin");
        rig.fx.commit(&path, n as i64 + 1, &[&data_of(n as u8, 1024 + n)]);
        rig.fx.item(&path);
    }
    rig.fx
        .state
        .replica_coordinator
        .retention_rules()
        .set(GROUP, "free", Some(Rule::OnlineOnly))
        .unwrap();
    let (fill, _) = fill_for(&rig);

    let first = fill.run_pass().await;
    assert!(first.stopped_early, "{first:?}");
    assert_eq!(first.checked, FETCHES_PER_PASS + 1, "the budget stopped the pass: {first:?}");
    // The second pass picks up behind the first: the remaining files are checked, not the first
    // ones again.
    let second = fill.run_pass().await;
    assert!(!second.stopped_early, "{second:?}");
    assert_eq!(second.checked, total - FETCHES_PER_PASS, "{second:?}");
    // And then the scan starts over from the front.
    let third = fill.run_pass().await;
    assert!(third.checked >= FETCHES_PER_PASS, "{third:?}");
}
