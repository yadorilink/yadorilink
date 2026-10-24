//! Library surface for `yadorilink-daemon`, split out so integration tests
//! (and `main.rs`) share the same modules.
//!
//! Without the `process-model` feature this is the engine alone, for a host that embeds it
//! (see [`embedded_host`]). The application commands the control socket drives are then not
//! reached from inside the crate: the host's API will drive them as it grows.
#![cfg_attr(
    not(feature = "process-model"),
    allow(
        dead_code,
        reason = "the commands the control socket drives have no caller until the embedded host exposes them"
    )
)]

pub mod adapters;
#[cfg(feature = "process-model")]
pub mod app;
#[cfg(feature = "process-model")]
pub mod app_group;
pub mod application;
pub mod author_identity;
pub mod author_sidecar;
pub mod background_custody;
pub mod change_auth;
pub mod change_policy;
pub mod checkpoint_source;
pub mod connection_trace;
pub mod contest_fork;
pub mod control_context;
#[cfg(feature = "process-model")]
pub mod control_socket;
pub mod convergence;
pub mod coordination_client;
pub mod credential_store;
pub mod custody_handoff;
pub mod custody_holds;
pub mod daemon_state;
pub mod device_config;
#[cfg(feature = "process-model")]
pub mod diagnostics_ipc;
pub mod durability_service;
pub mod embedded_host;
pub(crate) mod engine_startup;
pub mod engine_tuning;
pub(crate) mod enrollment_commands;
pub mod error;
#[cfg(feature = "process-model")]
pub mod exe_replaced;
#[cfg(feature = "process-model")]
pub mod exe_watch;
pub mod fd_limit;
pub mod gc;
pub mod gc_state;
pub mod governance_config;
pub mod handoff_proof;
pub mod hydration;
pub mod hydration_single_flight;
pub mod identity;
pub mod install_witness;
pub mod link_registry;
pub mod link_runtime;
pub mod local_convergence;
#[cfg(feature = "process-model")]
pub mod log_roll;
pub mod log_throttle;
pub mod machine_fingerprint;
pub(crate) mod maintenance;
pub mod maintenance_coordinator;
#[cfg(feature = "process-model")]
pub mod malloc_arenas;
pub mod materialization_intent;
pub mod metrics;
#[cfg(feature = "process-model")]
pub mod nas_admin;
#[cfg(feature = "process-model")]
mod nas_admin_bridge;
pub mod native_checkpoint_flush;
pub mod native_rebootstrap;
pub mod native_recovery;
pub mod native_replication_driver;
pub mod native_replication_runtime;
pub mod native_replication_session;
#[cfg(test)]
mod native_test_support;
#[cfg(test)]
pub(crate) mod obligation_tick_metrics;
pub mod path_witness_sink;
pub mod peer_connectivity_runtime;
pub mod peer_orchestrator;
pub mod peer_registry;
#[cfg(windows)]
pub mod placeholder_dehydrate_windows;
#[cfg(windows)]
pub mod placeholder_inspect_windows;
pub mod preserved_items;
pub mod queries;
pub mod receive_diag;
pub mod recent_errors;
pub mod recovery;
pub mod recovery_diagnosis;
pub mod recovery_evidence;
pub mod recovery_snapshot;
/// `ReplicaCoordinator` -- see that module's own doc comment for what it
/// is.
pub mod replica_coordinator;
pub mod reporting;
#[cfg(feature = "process-model")]
pub mod reporting_ipc;
pub mod reporting_retry;
pub mod rewind;
pub mod root_commit_authority;
pub mod route;
pub mod runtime_telemetry;
pub mod space_management_config;
pub(crate) mod status_dimensions;
pub(crate) mod status_report;
pub mod sync_adapter;
pub mod sync_runtime;
// Exclusive OS locks on the block-store root and sync-state database.
pub(crate) mod conflict_resolution;
pub(crate) mod file_actions;
pub(crate) mod pause_deadline;
pub(crate) mod provider_auto_reclaim;
pub(crate) mod provider_eager;
pub(crate) mod provider_evict;
pub(crate) mod provider_evidence;
pub(crate) mod provider_gate;
pub(crate) mod provider_handoff;
pub(crate) mod provider_host_link;
pub(crate) mod provider_ingest;
#[cfg(windows)]
pub(crate) mod provider_ingest_windows;
pub(crate) mod provider_prefetch;
pub(crate) mod provider_projector;
pub(crate) mod provider_publication;
#[cfg(test)]
pub(crate) mod provider_read_fault;
pub(crate) mod provider_reclaim;
pub(crate) mod provider_status;
pub(crate) mod provider_writer;
pub(crate) mod requested_opens;
#[cfg(feature = "process-model")]
pub mod send_transfer;
pub mod shell_context;
pub mod shell_ipc;
pub mod shell_status;
pub(crate) mod start_gate_core;
pub mod supervise;
pub mod sync_error;
pub(crate) mod sync_facade;
// Test-harness boundary, not product surface. `peer_session_fixture` is the
// `ReplicaCoordinator`-backed peer-session fixture, shared during the test
// ownership move with `yadorilink-peer-session`'s own integration binaries
// through their existing dev-dependency on this crate. Nothing outside these
// two cfgs can name anything in here.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod transfer_progress;
#[cfg(feature = "process-model")]
pub mod update;
#[cfg(feature = "process-model")]
pub mod update_ipc;
#[cfg(windows)]
pub(crate) mod windows_fs_security;
#[cfg(windows)]
pub mod windows_pipe_security;
pub(crate) mod windows_sync_roots;
