//! The Convergence Engine: a durable, persistent-state process that plans,
//! fetches, and materializes native-resolved file content independently of
//! message handling.
//!
//! Native admission records a genuine state transition for a path as a
//! `projection_obligations` row (see `yadorilink_sync_sqlite`), and the peer
//! session returns, releasing its bounded `message_slots` permit without
//! awaiting network or disk content I/O. The scheduler in `engine.rs` claims
//! the runnable obligations and turns them into on-disk bytes on its own
//! schedule, decoupled from any peer's message-processing capacity. The old
//! `materialization_jobs` table is retired and nothing schedules from it.

pub mod backoff;
#[path = "engine_wrapper.rs"]
pub mod engine;
#[path = "engine.rs"]
mod engine_impl;
pub(crate) use engine_impl::parse_reconcile_paths;

#[cfg(test)]
mod receive_budget_tests;
#[cfg(test)]
mod receive_commit_fault_sequence_tests;
#[cfg(test)]
mod receive_completion_tests;
#[cfg(test)]
mod receive_cost_tests;
#[cfg(test)]
mod receive_disk_pressure_sequence_tests;
#[cfg(test)]
mod receive_kernel_bench;
#[cfg(test)]
mod receive_low_space_retention_tests;
#[cfg(test)]
mod retention_batch_tests;

// `engine.rs` drives both via `DaemonState`. `availability`/`scheduler` as
// their own modules are stage-3/stage-2 concerns (block-availability
// advertisement, source-side serve credit) not yet built — `engine.rs`'s
// own scheduling loop is small enough for stage 1 that splitting it out
// prematurely would be an empty file, not a real module boundary.
