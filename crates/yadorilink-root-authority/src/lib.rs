//! The root-mutation capability every daemon-originated local
//! filesystem/index/native state/materialization-state write must hold
//! ([`root_commit::RootLease`]/[`root_commit::RootCommitPermit`]), backed
//! by an OS-level advisory exclusive lock on the sync root
//! ([`sync_root_lock::SyncRootLock`]) and the filesystem-identity comparisons
//! (from `yadorilink-fs-platform`) that detect a root being replaced out from
//! under an active lock. The generic filesystem layer itself (durable
//! namespace changes, capability probes, identity, the reserved artefact
//! namespace) lives in `yadorilink-fs-platform`, which this crate builds on.
//! Unlike the native admission-outcome types in
//! `yadorilink-replica-domain`, this is not a pure value type: `RootLease` wraps a real, live
//! `SyncRootLock`, so it could not simply move into
//! `yadorilink-replica-domain`. No SQLite, no daemon-specific coupling: a
//! lease's *lifecycle* (when a link starts/stops/restarts, i.e. when an
//! `Arc<RootLease>` is actually constructed and hands out permits) stays
//! `yadorilink-daemon`'s `link_manager` territory, unchanged by this move
//! -- see [`root_commit`]'s own module doc.

pub mod error;
pub mod root_commit;
/// Sync-root identity: proves the directory a scan is about to treat as
/// authoritative is really this link's folder, and not the bare mountpoint
/// an unmounted volume leaves behind.
pub mod root_identity;
pub mod sync_root_lock;

pub use error::RootAuthorityError;
