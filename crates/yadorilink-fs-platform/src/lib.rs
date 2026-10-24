//! The generic filesystem layer shared by every crate that touches a
//! user-visible directory tree.
//!
//! * [`durable_dir`]: the one place that changes the namespace durably
//!   (write-through move on Windows, rename plus directory sync on Unix).
//! * [`fs_capabilities`]: per-volume filesystem capability probes.
//! * [`fs_identity`]: file and directory identity observation.
//! * [`reserved_namespace`]: the on-disk artefact names reserved beside user
//!   objects, and the wire-path admission rules built on them.
//! * [`canonical_fold`]: the case/normalization-folded path equivalence key.
//! * [`ignore_patterns`]: ignore-file matching.
//! * [`join_timeline`]: measurement-only share-join milestone timeline.
//!
//! Nothing here depends on root authority: leases, permits, sync-root locks
//! and root identity live in `yadorilink-root-authority`, which builds on
//! this crate.

pub mod canonical_fold;
pub mod durable_dir;
pub mod flush;
pub mod fs_capabilities;
pub mod fs_identity;
pub mod generation;
pub mod ignore_patterns;
pub mod join_timeline;
pub mod long_path;
pub mod reserved_namespace;
pub mod state_dir;
pub mod usn;
pub mod volume_identity;
pub mod windows_name;
pub mod write_exclusion;
