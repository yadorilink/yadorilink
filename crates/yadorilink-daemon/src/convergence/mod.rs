//! The Convergence Engine: a durable, persistent-state process that plans,
//! fetches, and materializes native-resolved file content independently of
//! message handling.
//!
//! `peer_session.rs`'s `handle_message` does authentication, native admission,
//! and writes a `materialization_jobs` row (see
//! `yadorilink_sync_sqlite::materialization_jobs`), then returns — releasing
//! its bounded `message_slots` permit without ever awaiting network or disk
//! content I/O. This module is what turns that row into on-disk bytes, on
//! its own schedule, decoupled from any specific peer's message-processing
//! capacity.

pub mod backoff;
#[path = "engine_wrapper.rs"]
pub mod engine;
#[path = "engine.rs"]
mod engine_impl;

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

// `engine.rs` drives both via `DaemonState`. `availability`/`scheduler` as
// their own modules are stage-3/stage-2 concerns (block-availability
// advertisement, source-side serve credit) not yet built — `engine.rs`'s
// own scheduling loop is small enough for stage 1 that splitting it out
// prematurely would be an empty file, not a real module boundary.
