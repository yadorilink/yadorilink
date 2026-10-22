//! Named job types for this daemon's daemon-wide periodic maintenance
//! tasks (see `maintenance_coordinator.rs`'s own doc comment for the
//! full roster). Each job is a small struct holding
//! the narrowest real dependency it needs, with its actual sweep/check
//! logic in a `run_once` method -- `maintenance_coordinator::start`
//! retains every job's own loop-shape/interval/supervision strategy
//! unchanged, now calling into `run_once` instead of inlining the sweep
//! body directly in the spawned closure.
//!
//! No shared generic "loop runner" here: these jobs have genuinely
//! different signatures -- some `async` (membership recovery, disk
//! reconcile), one sync-but-blocking-offloaded (retention expiry), some
//! that unify a real startup call with the periodic loop (update-check,
//! retention expiry, membership recovery) and some that must NOT gain
//! one (materialization repair, degraded-link recheck, disk-reconcile
//! backstop, GC idle -- these must not gain a startup run). Forcing all of that through one trait/runner would
//! either hide those real differences or need enough escape hatches to
//! stop being a meaningful abstraction. `LinkRuntimeController` is a
//! plain struct with individual methods for the same reason; this
//! mirrors that pragmatic shape.

pub(crate) mod degraded_link_recheck;
pub(crate) mod disk_reconcile_backstop;
pub(crate) mod durability_confirmation;
pub(crate) mod gc_idle;
pub(crate) mod link_volume;
pub(crate) mod materialization_repair;
pub(crate) mod pause_expiry;
pub(crate) mod recovery;
pub(crate) mod replacement_confirm;
pub(crate) mod retention_expiry;
// The update-check scheduler never spawns under `test` builds
// (see `maintenance_coordinator.rs`'s own spawn site) -- `UpdateCheckJob`
// would otherwise sit unconstructed in every such build, warning as dead
// code.
#[cfg(not(test))]
pub(crate) mod update_check;
