//! Short random state-transition sequences against the independent model,
//! with shrinking to a minimal replayable case.
//!
//! A sequence is 5 to 15 steps over a few names: write, delete, rename,
//! pause (hold the debounce window) and retry (flush what was held). It is
//! generated from a seed alone, run on the real capture pipeline
//! (`boundary_device::Device`), and compared with `directory_model`'s
//! `ExplicitModel`; neither the model nor the comparison is duplicated here.
//!
//! # Why not `proptest-state-machine`
//!
//! The crate is not in the dependency tree (`Cargo.lock`), so adopting it
//! means a new dev-dependency to vet against the dependency and licence
//! guards, and its value here is generation plus shrinking, which this suite
//! already has in a smaller, deterministic form: a seeded generator that
//! only emits steps the model finds well-formed, and a delta-debugging
//! shrinker (chunks, then single steps) in the style of `shrinker.rs`, which
//! cannot be reused directly because it is bound to the `Case` IR and the
//! IR has no pause or retry step. A sequence is a plain `Vec<Step>`: a
//! shrunk failure is printed as that vector and pasted into a regression
//! test, replayable with no seed, no generator and no dependency. Decision:
//! in-tree generator and shrinker; revisit only if sequences need
//! model-based stateful strategies a seed cannot express.
//!
//! The PR gate runs a fixed number of seeds plus the kept regressions;
//! `DST_SEQUENCES=<n>` widens the seed sweep for periodic exploration.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use super::boundary_device::{compare, Defect, Device, Step};
use super::case_ir::Op;
use super::directory_model::{ExplicitModel, ModelEntry};

fn sim<F: std::future::Future<Output = ()> + 'static>(f: impl FnOnce() -> F + 'static) {
    super::sim::block_on(1, f);
}

const NAMES: [&str; 3] = ["a", "b", "c"];

/// 5 to 15 steps, deterministic from `seed`. Ops are drawn against a running
/// copy of the model so most are well-formed; the runner skips any that are
/// not, so shrinking can drop a step without making the rest invalid.
pub fn generate(seed: u64) -> Vec<Step> {
    let mut rng = StdRng::seed_from_u64(seed);
    let len = rng.random_range(5..=15);
    let mut model = ExplicitModel::default();
    let mut steps = Vec::with_capacity(len);
    for _ in 0..len {
        let name = NAMES[rng.random_range(0..NAMES.len())].to_string();
        let live: Vec<String> = model
            .entries()
            .iter()
            .filter(|(_, e)| matches!(e, ModelEntry::File { .. }))
            .map(|(p, _)| p.clone())
            .collect();
        let step = match rng.random_range(0..10) {
            0..=3 => Step::Op(Op::Write { path: name, content_id: rng.random_range(1..=4) }),
            4 | 5 if !live.is_empty() => {
                Step::Op(Op::Delete { path: live[rng.random_range(0..live.len())].clone() })
            }
            6 | 7 if !live.is_empty() => Step::Op(Op::Rename {
                from: live[rng.random_range(0..live.len())].clone(),
                to: name,
            }),
            8 => Step::Pause,
            9 => Step::Retry,
            _ => Step::Op(Op::Write { path: name, content_id: rng.random_range(1..=4) }),
        };
        if let Step::Op(op) = &step {
            let _ = model.apply(op);
        }
        steps.push(step);
    }
    steps
}

/// Runs `steps` on a fresh device and compares with the model.
pub async fn check(steps: &[Step], defect: Defect) -> Result<(), String> {
    let device = Device::new();
    let model = device.run_steps(ExplicitModel::default(), steps, defect).await;
    compare(&device, &model)
}

/// Delta-debugging shrinker: drop chunks of halving size, then single steps,
/// until no removal still fails. `still_fails` is the reproduce check; the
/// result is a sequence it fails on and from which no one step can be
/// removed.
pub async fn shrink<F, Fut>(mut steps: Vec<Step>, mut still_fails: F) -> Vec<Step>
where
    F: FnMut(Vec<Step>) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut chunk = steps.len().div_ceil(2).max(1);
    loop {
        let mut removed_any = false;
        let mut start = 0;
        while start < steps.len() {
            let end = (start + chunk).min(steps.len());
            let mut candidate = steps.clone();
            candidate.drain(start..end);
            if still_fails(candidate.clone()).await {
                steps = candidate;
                removed_any = true;
            } else {
                start = end;
            }
        }
        if chunk == 1 && !removed_any {
            return steps;
        }
        chunk = if removed_any { chunk } else { (chunk / 2).max(1) };
    }
}

fn sequence_count() -> u64 {
    std::env::var("DST_SEQUENCES").ok().and_then(|v| v.parse().ok()).unwrap_or(40)
}

/// The sweep: every generated sequence ends where the model says.
#[test]
fn random_sequences_end_where_the_model_says() {
    sim(|| async {
        let mut failures = Vec::new();
        for seed in 0..sequence_count() {
            let steps = generate(seed);
            assert!((5..=15).contains(&steps.len()));
            if let Err(why) = check(&steps, Defect::None).await {
                let minimal = shrink(steps, |candidate| async move {
                    check(&candidate, Defect::None).await.is_err()
                })
                .await;
                failures.push(format!("seed {seed}: {why}\n  minimal: {minimal:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}

/// Generation is a function of the seed, and sequences vary.
#[test]
fn generation_is_deterministic_and_varied() {
    assert_eq!(format!("{:?}", generate(7)), format!("{:?}", generate(7)));
    let distinct: std::collections::HashSet<String> =
        (0..20).map(|s| format!("{:?}", generate(s))).collect();
    assert!(distinct.len() > 10);
    assert!((0..200).any(|s| generate(s).iter().any(|x| matches!(x, Step::Pause))));
    assert!((0..200).any(|s| generate(s).iter().any(|x| matches!(x, Step::Retry))));
}

/// A deliberately broken pipeline is found by the sweep and shrunk to the
/// smallest sequence that still shows it. Each defect has its known minimum.
#[test]
fn a_broken_pipeline_is_found_and_shrunk_to_a_minimal_sequence() {
    sim(|| async {
        for (defect, expected) in [
            (Defect::DropRemovals, regression_dropped_removal()),
            (Defect::DropCreations, regression_dropped_creation()),
        ] {
            let mut found = None;
            for seed in 0..sequence_count().max(60) {
                let steps = generate(seed);
                if check(&steps, defect).await.is_err() {
                    found = Some(steps);
                    break;
                }
            }
            let failing = found.unwrap_or_else(|| panic!("{defect:?} went unnoticed"));
            let minimal =
                shrink(
                    failing,
                    |candidate| async move { check(&candidate, defect).await.is_err() },
                )
                .await;
            assert_eq!(minimal.len(), expected.len(), "{defect:?}: {minimal:?}");
            assert!(check(&minimal, defect).await.is_err());
            assert!(
                check(&minimal, Defect::None).await.is_ok(),
                "the shrunk case fails the healthy pipeline"
            );
        }
    });
}

// ---- kept regressions: shrunk cases, replayed with no seed -------------

/// Shrunk from a sweep with `Defect::DropRemovals`: a delete whose removal
/// never reaches the pipeline leaves the file live.
fn regression_dropped_removal() -> Vec<Step> {
    vec![
        Step::Op(Op::Write { path: "a".into(), content_id: 1 }),
        Step::Op(Op::Delete { path: "a".into() }),
    ]
}

/// Shrunk from a sweep with `Defect::DropCreations`: a write that never
/// reaches the pipeline is lost.
fn regression_dropped_creation() -> Vec<Step> {
    vec![Step::Op(Op::Write { path: "a".into(), content_id: 1 })]
}

#[test]
fn kept_regressions_fail_the_broken_pipeline_and_pass_the_real_one() {
    sim(|| async {
        for (defect, steps) in [
            (Defect::DropRemovals, regression_dropped_removal()),
            (Defect::DropCreations, regression_dropped_creation()),
        ] {
            assert!(check(&steps, defect).await.is_err(), "{defect:?} no longer found");
            check(&steps, Defect::None).await.expect("the real pipeline lost something");
        }
    });
}
