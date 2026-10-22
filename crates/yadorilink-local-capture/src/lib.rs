//! Bridges a raw local filesystem event into an indexed, chunked
//! `FileRecord` — `LocalChangeProcessor` and the disk-reconcile/debounce-
//! flush machinery around it. `VerifiedRoot` comes from
//! `yadorilink-root-authority`. This crate's
//! own `tests/` (external) fixtures build a `ReplicaCoordinator` directly
//! via a dev-only back-edge onto `yadorilink-daemon`; this crate's own
//! internal `#[cfg(test)]` code (in
//! `local_change.rs`/`ports/local_mutation.rs`) goes through
//! `test_support::TestReplica` instead -- see that module's own doc
//! comment for why a bare `ReplicaCoordinator` does not compile there.

pub mod error;
pub mod local_change;
pub mod ports;
pub(crate) mod reconcile_gate;
pub(crate) mod scan_block_staging;
#[cfg(test)]
pub(crate) mod test_support;
pub mod unreadable;

pub use error::LocalCaptureError;
pub use local_change::{FlushOutcome, LocalChangeOutcome, LocalChangeProcessor};

/// Deterministic race injection for other crates' test builds.
#[cfg(any(test, feature = "test-support"))]
pub mod test_hooks {
    pub use crate::local_change::{
        arm_content_read_race_hook, arm_post_capture_race_hook, arm_post_identity_race_hook,
        disarm_content_read_race_hook, disarm_post_capture_race_hook,
        disarm_post_identity_race_hook,
    };
}
