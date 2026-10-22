//! The sync primitives of the sections the Shuttle explorer compiles from this crate by
//! `#[path]` (see `start_gate_core`). Here they are `std`; `xtask/tests/shuttle_races.rs`
//! defines a module of the same name backed by Shuttle's scheduler-aware types.

pub(crate) use std::sync::atomic::{AtomicUsize, Ordering};
pub(crate) use std::sync::{Mutex, MutexGuard};
