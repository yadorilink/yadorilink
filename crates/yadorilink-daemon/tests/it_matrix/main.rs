//! The long multi-device convergence matrices of the daemon tests that hold no process-global
//! state of their own (see `tests/README.md`), consolidated into one target.
//!
//! They are apart from `it` so that tests with tight waits are not run next to them and starved
//! of CPU. Run one module with `cargo test -p yadorilink-daemon --test it_matrix -- <module>::`.

#[path = "../support/mod.rs"]
mod support;

mod collision_matrix;
mod directory_conflict_matrix;
mod hazard_collision_convergence;
mod multiway_conflict_matrix;
mod partition_reconnect_matrix;
mod storage_mode_orchestration;
mod taguchi_collision_matrix;
mod taguchi_collision_matrix_v2;
mod taguchi_collision_matrix_v3;
mod three_way_concurrent_edit_conflict;
mod topology_n_m_w;
mod unlink_and_removal_durability;
