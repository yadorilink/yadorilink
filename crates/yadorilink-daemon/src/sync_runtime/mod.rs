//! In-memory, never-persisted runtime-coordination state owned by
//! `ReplicaCoordinator`: none of these types touch SQLite.
//!
//! These types live in `yadorilink-daemon` rather than a shared lower crate
//! because they are daemon-composition-root owned, the same reasoning
//! applied to `ReplicaCoordinator` itself: they coordinate in-process state
//! across daemon subsystems and have no meaning outside the daemon's own
//! runtime.
pub mod group_wake;
pub mod materialization_wake;
pub mod path_locks;
pub mod schema;
pub mod startup_readiness;
