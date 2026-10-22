//! Differential checks of an implementation against the oracle.
//!
//! An implementation is a function from a universe and a delivery order of
//! changes to the heads it computes (typically by folding its transition
//! rule over the order from an empty state). [`check`] runs it on every
//! replica history of many generated scenarios, in the authoring order and
//! in random valid delivery orders, and compares with
//! [`heads_of_history`]. [`check_join`] does the same for a two-sided join.

use std::fmt;
use std::ops::Range;

use crate::generate::{generate, random_delivery_order, GenConfig, Rng, Scenario};
use crate::model::{ChangeId, Heads, History, Universe};
use crate::semantics::{heads_of_history, join, normalize};

/// Which runs [`check`] and [`check_join`] perform.
#[derive(Clone, Debug)]
pub struct CheckConfig {
    /// One scenario per seed.
    pub seeds: Range<u64>,
    pub generator: GenConfig,
    /// Random delivery orders tried per history, besides the authoring
    /// order.
    pub shuffled_orders: usize,
}

impl Default for CheckConfig {
    fn default() -> Self {
        Self { seeds: 0..200, generator: GenConfig::default(), shuffled_orders: 2 }
    }
}

/// What a successful check covered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CheckReport {
    pub scenarios: usize,
    pub comparisons: usize,
}

/// The first disagreement between an implementation and the oracle.
#[derive(Clone, Debug)]
pub struct Mismatch {
    pub scenario: Scenario,
    /// The delivery orders the implementation was given (one for
    /// [`check`], left and right for [`check_join`]).
    pub inputs: Vec<Vec<ChangeId>>,
    pub expected: Heads,
    pub actual: Heads,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "heads differ from the oracle (seed {})", self.scenario.seed)?;
        for (i, input) in self.inputs.iter().enumerate() {
            writeln!(f, "input {i}: {input:?}")?;
        }
        let paths: std::collections::BTreeSet<_> =
            self.expected.keys().chain(self.actual.keys()).collect();
        for path in paths {
            let e = self.expected.get(path);
            let a = self.actual.get(path);
            if e != a {
                writeln!(f, "  {path}: expected {e:?}, got {a:?}")?;
            }
        }
        for change in self.scenario.universe.changes() {
            writeln!(f, "  {change:?}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Mismatch {}

/// The replica histories of `scenario` plus the history of all changes.
fn histories(scenario: &Scenario) -> Vec<History> {
    let mut all = scenario.replicas.clone();
    all.push(scenario.all());
    all
}

/// Delivery orders to try for `history`.
fn orders(
    scenario: &Scenario,
    history: &History,
    config: &CheckConfig,
    rng: &mut Rng,
) -> Vec<Vec<ChangeId>> {
    let mut out = vec![scenario.authoring_order(history)];
    for _ in 0..config.shuffled_orders {
        out.push(random_delivery_order(&scenario.universe, history, rng));
    }
    out
}

/// Compares `implementation`'s heads with the oracle's on generated
/// histories.
///
/// `implementation` receives the universe and a valid delivery order of one
/// history (each change after its author's earlier changes and its basis
/// members) and returns its heads; empty head sets are ignored.
///
/// # Errors
///
/// The first mismatch, with the scenario that produced it.
pub fn check<F>(config: &CheckConfig, mut implementation: F) -> Result<CheckReport, Box<Mismatch>>
where
    F: FnMut(&Universe, &[ChangeId]) -> Heads,
{
    let mut report = CheckReport::default();
    for seed in config.seeds.clone() {
        let scenario = generate(seed, &config.generator);
        let mut rng = Rng::new(seed ^ 0x5EED);
        for history in histories(&scenario) {
            let expected = heads_of_history(&scenario.universe, &history);
            for order in orders(&scenario, &history, config, &mut rng) {
                let actual = normalize(implementation(&scenario.universe, &order));
                report.comparisons += 1;
                if actual != expected {
                    return Err(Box::new(Mismatch {
                        scenario,
                        inputs: vec![order],
                        expected,
                        actual,
                    }));
                }
            }
        }
        report.scenarios += 1;
    }
    Ok(report)
}

/// Compares `implementation`'s join with the oracle's heads of the union,
/// over every ordered pair of replica histories (a replica with itself
/// included) of generated scenarios.
///
/// `implementation` receives the universe and a valid delivery order of
/// each side and returns the heads of the joined state.
///
/// # Errors
///
/// The first mismatch, with the scenario that produced it.
pub fn check_join<F>(
    config: &CheckConfig,
    mut implementation: F,
) -> Result<CheckReport, Box<Mismatch>>
where
    F: FnMut(&Universe, &[ChangeId], &[ChangeId]) -> Heads,
{
    let mut report = CheckReport::default();
    for seed in config.seeds.clone() {
        let scenario = generate(seed, &config.generator);
        let mut rng = Rng::new(seed ^ 0x101);
        let sides = histories(&scenario);
        for left in &sides {
            for right in &sides {
                let expected = heads_of_history(&scenario.universe, &join(left, right));
                let l = random_delivery_order(&scenario.universe, left, &mut rng);
                let r = random_delivery_order(&scenario.universe, right, &mut rng);
                let actual = normalize(implementation(&scenario.universe, &l, &r));
                report.comparisons += 1;
                if actual != expected {
                    return Err(Box::new(Mismatch {
                        scenario,
                        inputs: vec![l, r],
                        expected,
                        actual,
                    }));
                }
            }
        }
        report.scenarios += 1;
    }
    Ok(report)
}
