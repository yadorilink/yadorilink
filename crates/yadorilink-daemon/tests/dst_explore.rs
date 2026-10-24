//! Unattended exploration of fault sequences at the capture boundary
//! (`dst_support::explore`): the promoted regressions, the budgeted
//! exploration, and the replay of one failure file.
//!
//! * `promoted_explore_regressions_pass` runs in every lane: each JSON file
//!   under `tests/dst_corpus/explore/` is a minimized walk that once failed, and
//!   must pass now.
//! * `explore_budgeted` is `#[ignore]`d and driven by `cargo dst-explore`
//!   (`DST_EXPLORE_SECONDS`, `DST_EXPLORE_SEED`, `DST_EXPLORE_MAX_SEEDS`,
//!   `DST_EXPLORE_OUT`). It writes `report.md` and `failures/` into the output
//!   directory and fails if any walk failed.
//! * `explore_replay` is `#[ignore]`d and driven by
//!   `cargo dst-explore --replay <file>` (`DST_EXPLORE_REPLAY`): it fails with
//!   the violation if the file's walk still fails.

#![cfg(turmoil)]

mod dst_support;

use std::path::PathBuf;
use std::time::Duration;

use dst_support::boundary_device::Defect;
use dst_support::explore::{check, explore, load_corpus, write_report, ExploreConfig, Replay};

fn sim<F: std::future::Future<Output = ()> + 'static>(f: impl FnOnce() -> F + 'static) {
    dst_support::sim::block_on(1, f);
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/dst_corpus/explore")
}

#[test]
fn promoted_explore_regressions_pass() {
    sim(|| async {
        let mut failures = Vec::new();
        for (path, replay) in load_corpus(&corpus_dir()) {
            if let Err(why) = check(&replay.acts, Defect::None).await {
                failures.push(format!("{}: {why}", path.display()));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}

#[test]
#[ignore = "driven by `cargo dst-explore`"]
fn explore_budgeted() {
    sim(|| async {
        let out = PathBuf::from(
            std::env::var("DST_EXPLORE_OUT").unwrap_or_else(|_| "target/dst-explore".into()),
        );
        let config = ExploreConfig {
            start_seed: env_u64("DST_EXPLORE_SEED", 0),
            max_seeds: env_u64("DST_EXPLORE_MAX_SEEDS", u64::MAX / 2),
            budget: Duration::from_secs(env_u64("DST_EXPLORE_SECONDS", 60)),
            max_failures: env_u64("DST_EXPLORE_MAX_FAILURES", 5) as usize,
            defect: Defect::None,
        };
        let report = explore(&config).await;
        let path = write_report(&report, &out, "cargo dst-explore --replay")
            .expect("the report must be writable");
        eprintln!(
            "dst-explore: {} seeds from {} in {:.0}s, {} failure(s); report {}",
            report.seeds_run,
            report.config_start,
            report.elapsed.as_secs_f64(),
            report.failures.len(),
            path.display()
        );
        assert!(
            report.failures.is_empty(),
            "{} failing walk(s); see {}",
            report.failures.len(),
            path.display()
        );
    });
}

#[test]
#[ignore = "driven by `cargo dst-explore --replay`"]
fn explore_replay() {
    sim(|| async {
        let file = std::env::var("DST_EXPLORE_REPLAY").expect("DST_EXPLORE_REPLAY names the file");
        let text = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{file}: {e}"));
        let replay: Replay = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
        check(&replay.acts, Defect::None)
            .await
            .unwrap_or_else(|why| panic!("the walk still fails: {why}\nacts: {:#?}", replay.acts));
        eprintln!("dst-explore: the walk in {file} passes");
    });
}
