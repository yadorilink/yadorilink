//! On-device content-addressed block store.
//!
//! Blocks live in append-only segment files with a persistent SQLite
//! index; many blocks share one durability barrier. See
//! [`segment_store`]'s module documentation for the design and for the
//! `staged -> durable -> authoritative` contract every caller depends on.

pub mod chunker;
mod content_ports;
pub mod daemon_lock;
pub mod device_config;
pub mod disk_verification;
mod error;
pub mod free_space;
mod fs_ops;
pub use fs_ops::{
    move_no_replace_durably, remove_durably, remove_empty_dir, remove_empty_dir_in,
    EmptyDirectoryRemoval,
};
pub mod handoff;
pub mod install_check;
pub mod io_diag;
/// Shared link preflight model (folder existence/empty-state/free-space/
/// ignored-summary/risky-location checks) used by both `yadorilink-cli`'s
/// client-side dry-run/confirmation gate and `yadorilink-daemon`'s
/// defense-in-depth re-check. Placed here rather than
/// `yadorilink-root-authority` because
/// it needs both this crate's own `free_space` and
/// `yadorilink_fs_platform::ignore_patterns` --
/// `yadorilink-local-storage` already depends on
/// `yadorilink-root-authority` (for `fs_identity::bytes_to_target`), so
/// the reverse edge root-authority-depends-on-local-storage that the
/// nominal destination would require is a real crate-dependency cycle, not
/// just inconvenient.
pub mod link_preflight;
pub mod materialize_write;
pub mod ownership;
mod received_flush;
pub mod release_descriptor;
pub mod replacement_unconfirmed;
pub mod resource_lock;
pub mod segment_store;
pub mod service_registrations;
pub mod startup_refusal;
mod traits;

#[cfg(target_os = "linux")]
pub use chunker::read_replicated_xattrs_strict;
pub use chunker::{
    block_size_for, chunk_file, chunk_file_content_defined,
    chunk_file_content_defined_with_callback, chunk_file_fixed_with_callback, chunk_open_file,
    chunk_open_file_content_defined_with_callback, chunk_open_file_fixed_with_callback,
    hash_file_blocks, hash_open_file_blocks, read_replicated_xattrs, unix_mode_from_metadata,
    CDC_AVG_SIZE, CDC_MAX_SIZE, CDC_MIN_SIZE, CDC_SIZE_THRESHOLD, DEFAULT_BLOCK_SIZE,
};
pub use content_ports::{BlockContentStore, BlockReclamationStore};
pub use disk_verification::{
    check_disk_headroom, disk_bytes_match_indexed_blocks, disk_content_comparison,
    disk_content_comparison_observed, disk_matches_expected_object, file_content_comparison,
    intent_target_hash, intent_target_hash_for_bytes, DiskContentComparison, ExpectedObject,
};
pub use error::StorageError;
pub use free_space::{FreeSpaceState, VolumeFreeSpace};
#[cfg(unix)]
pub use materialize_write::materialize_symlink;
#[cfg(unix)]
pub use materialize_write::materialize_symlink_in;
#[cfg(windows)]
pub use materialize_write::materialize_symlink_windows;
#[cfg(windows)]
pub use materialize_write::materialize_symlink_windows_in;
pub use materialize_write::{
    apply_file_metadata, apply_file_metadata_verified, apply_unix_mode, apply_xattrs,
    create_dir_all_never_through_a_symlink, create_explicit_directory, create_or_defer_placeholder,
    discard_temp_file, mint_windows_placeholder_generation, mtime_already_matches_disk,
    persist_reconstructed_file, persist_reconstructed_file_durable, persist_reconstructed_file_in,
    reconstruct_file, reconstruct_file_in, reconstruct_file_to_temp, reconstruct_file_to_temp_in,
    reconstruct_file_to_temp_observed, reconstruct_file_to_temp_observed_durable,
    remove_evicted_object, rename_no_replace, resolve_read_path_without_traversal,
    stamp_mtime_at_path, sync_parent_dir, unix_mode_already_matches_disk,
    verify_delete_target_within_canonical_root, verify_delete_target_within_root,
    verify_replicated_xattrs_exact, verify_write_target_within_canonical_root,
    verify_write_target_within_root, xattrs_already_match_disk, AppliedFileMetadata, Durability,
    ExplicitDirectoryCreation, NoTempLedger, PlaceholderDiskIdentity, PlaceholderIdentityToRecord,
    StructuralDirectoryLedger, TempFileLedger, XattrEvidence, XattrProofRefused,
    XattrsConfirmedInAttempt, XattrsNotConfirmed, WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
};
#[cfg(any(test, feature = "test-support"))]
pub use received_flush::{completed_flushes_under, fail_received_flushes_of, FailReceivedFlushes};
pub use received_flush::{
    flush_received_files, flush_received_objects, object_key, ObjectKey, ReceivedFlushMode,
    ReceivedFlushOutcome,
};
pub use segment_store::{
    CommitPoint, CompactionReport, DurableReceipt, FaultPlan, GroupCommitLimits, RecoveryReport,
    SegmentBlockStore, SegmentStoreUsage, COMPACTION_DEAD_RATIO, COMPACTION_MIN_DEAD_BYTES,
    DEFAULT_CACHED_SEGMENT_READERS,
};
pub use traits::{
    hash_block_bytes, BlockStore, ContentHash, GcReport, LocallyHashedBlock, StorageUsage,
};
