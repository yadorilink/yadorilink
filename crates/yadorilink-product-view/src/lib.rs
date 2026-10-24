//! Product-facing DTO layer for the desktop and CLI product shells.
//!
//! `FolderSummary`/`DeviceSummary` and their derivation from
//! `yadorilink-ipc-proto`'s `LinkStatus`/`StatusResponse` and the
//! coordination plane's per-group member listing live here. Every
//! derivation here is pure: the member listing is fetched by the caller
//! (see `device.rs`), so this crate depends on no interface crate. It
//! must never depend on `yadorilink-transport`, `yadorilink-peer-session`,
//! `yadorilink-sync-substrate`, or any other sync-engine crate, and must
//! never pull in a GUI toolchain (`eframe`/`tao`/`tray-icon`) — both are
//! enforced by this crate's `Cargo.toml` simply not listing them as
//! dependencies, not by any lint here.

pub mod attention;
pub mod availability;
pub mod conflict;
pub mod device;
pub mod folder;
pub mod protection;
pub mod summary;

pub use attention::{
    Attention, AttentionItem, AttentionKind, AttentionScope, AttentionSeverity, ProductAction,
};
pub use availability::{Availability, AvailabilitySummary};
pub use conflict::{conflict_detail, ConflictDetail, ConflictReason};
pub use device::{
    can_manage_device, device_summaries, distinct_group_ids, full_replica_holders, peer_count,
    peer_counts, DeviceSummary,
};
pub use folder::{
    DegradedCause, DurabilityStatus, FetchAvailability, FolderMode, FolderState, FolderSummary,
    FolderTransfer, LocalStorageState,
};
pub use protection::{Protection, ProtectionSummary};
pub use summary::{AttentionReason, ProductState, ProductStatusSummary};
