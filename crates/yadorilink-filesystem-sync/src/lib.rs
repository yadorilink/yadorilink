//! Real filesystem execution: the platform-level commit adapter that
//! atomically swaps a prepared replacement into a live filesystem
//! location.

pub mod block_deletion;
pub mod block_liveness;
pub mod debounce;
pub mod device_boundary;
pub mod held_path_reconcile;
pub mod materialization_eviction;
pub mod materialization_execution;
pub mod materialization_repair;
pub mod watcher;
#[cfg_attr(not(windows), allow(dead_code))]
mod win_watch;
