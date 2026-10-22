//! The one place a DST scenario constructs its simulated runtime.
//!
//! Keeping that construction here, rather than inline in every scenario,
//! means no scenario file carries its own copy of seed handling or time
//! budget to drift.
//!
//! The substrate is turmoil, selected with `--cfg turmoil`. The real `tokio`
//! this crate normally compiles against is kept; determinism comes from
//! turmoil's stepped runtime and its paused clock, and simulated sockets are
//! opt-in per call site rather than global.
//!
//! It is not a default: a plain `cargo test` does not set the cfg and never
//! compiles this file at all.
//!
//! # What is deliberately *not* promised
//!
//! A seed reproduces a run *on this substrate*. Equivalence with any other
//! execution is asserted at the level the Case IR already defines: the same
//! serialized `Case` must satisfy the same oracle. See `case_ir.rs`.

#![cfg(turmoil)]
#![allow(dead_code)] // not every scenario has been migrated onto this yet

use std::future::Future;
use std::time::Duration;

/// The wall-clock instant every simulated run starts from, so a scenario
/// that formats or records a timestamp produces the same bytes across runs.
/// turmoil takes the epoch explicitly.
#[cfg(turmoil)]
const SIM_EPOCH: std::time::SystemTime = std::time::UNIX_EPOCH;

/// Default simulated-time budget for one scenario run. A scenario that
/// genuinely needs longer passes its own; this is the value the migrated
/// scenarios were already using inline.
pub const DEFAULT_TIME_LIMIT: Duration = Duration::from_secs(60);

/// Runs one seeded scenario to completion on whichever substrate this
/// binary was built for, returning the scenario's own verdict.
///
/// `body` is taken as a closure rather than a future so the future is
/// constructed *inside* the simulated runtime: a future built outside it
/// that eagerly touches a timer or a channel would bind to the wrong
/// runtime, and that failure is silent rather than loud.
pub fn run_seeded<F, Fut>(seed: u64, time_limit: Duration, body: F) -> Result<(), String>
where
    F: FnOnce() -> Fut + 'static,
    Fut: Future<Output = Result<(), String>> + 'static,
{
    run_seeded_impl(seed, time_limit, body)
}

/// [`run_seeded`] with the default time budget.
pub fn run_scenario<F, Fut>(seed: u64, body: F) -> Result<(), String>
where
    F: FnOnce() -> Fut + 'static,
    Fut: Future<Output = Result<(), String>> + 'static,
{
    run_seeded(seed, DEFAULT_TIME_LIMIT, body)
}

/// Drives `body` to completion on the simulated clock, for a `#[test]` whose
/// subject is an async primitive rather than a scenario -- the fault
/// scheduler's own timing, the disk injector's delay, `settle_until`'s
/// budget. These need virtual time (a 60s budget must not cost 60s) but have
/// no verdict to carry out, so they panic on the spot like any other unit
/// test rather than threading a `Result` back.
pub fn block_on<F, Fut>(seed: u64, body: F)
where
    F: FnOnce() -> Fut + 'static,
    Fut: Future<Output = ()> + 'static,
{
    run_seeded(seed, DEFAULT_TIME_LIMIT, move || async move {
        body().await;
        Ok(())
    })
    .unwrap_or_else(|e| panic!("simulated runtime did not complete the test body: {e}"));
}

/// turmoil's unit of work is a *host*, not a bare future, so a scenario
/// body runs here as the simulation's single client. `run()` drives every host until that client resolves.
///
/// Two differences worth naming rather than discovering:
///
/// * The client's own `Err` and a simulation-level failure (the time budget
///   running out) both surface through the same `run()` result. They are
///   separated here so a scenario failure never reads as a harness timeout,
///   and vice versa.
/// * `enable_random_order` is what makes distinct seeds explore distinct
///   host orderings. Without it a seed only varies turmoil's network
///   latency draws, which for a single-host scenario is no variation at all.
/// * Two peers placed on the *same* host do not talk over the simulated
///   network at all: turmoil delivers same-host traffic directly. So a
///   scenario that puts both devices on one host to "remove a variable" has
///   removed the network instead, and neither a partition nor a latency draw
///   will reach it. Two devices that must be able to lose each other need
///   two hosts.
#[cfg(turmoil)]
fn run_seeded_impl<F, Fut>(seed: u64, time_limit: Duration, body: F) -> Result<(), String>
where
    F: FnOnce() -> Fut + 'static,
    Fut: Future<Output = Result<(), String>> + 'static,
{
    use std::cell::RefCell;
    use std::rc::Rc;

    let mut sim = turmoil::Builder::new()
        .rng_seed(seed)
        .enable_random_order()
        .simulation_duration(time_limit)
        .epoch(SIM_EPOCH)
        .build();

    // The scenario's verdict has to come back out of the simulation, and
    // turmoil's own error channel is `Box<dyn Error>` -- round-tripping a
    // multi-line violation report through that would lose its shape. The
    // cell carries the verdict; `run()`'s result only says whether the
    // simulation itself held together.
    let verdict: Rc<RefCell<Option<Result<(), String>>>> = Rc::new(RefCell::new(None));
    let sink = verdict.clone();

    sim.client("dst", async move {
        *sink.borrow_mut() = Some(body().await);
        Ok(())
    });

    let sim_result = sim.run();

    let scenario_verdict = verdict.borrow_mut().take();
    match scenario_verdict {
        Some(verdict) => verdict,
        // The client never finished: the simulated-time budget ran out, or
        // turmoil stopped the run for a reason of its own.
        None => Err(match sim_result {
            Err(e) => format!("turmoil run ended before the scenario finished: {e}"),
            Ok(()) => "turmoil run ended without the scenario producing a verdict".to_string(),
        }),
    }
}
