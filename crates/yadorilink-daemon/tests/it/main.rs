//! The consolidated integration-test target for the daemon tests that hold no process-global
//! state of their own (see `tests/README.md`). The long multi-device matrices are in `it_matrix`.
//!
//! Each module below used to be its own test target, and every target links a complete copy of
//! the daemon (about 130 MB), so a change to the daemon relinked ~100 binaries. Run one module
//! with `cargo test -p yadorilink-daemon --test it -- <module>::`.

#[path = "../native_e2e_support/mod.rs"]
mod native_e2e_support;
#[path = "../support/mod.rs"]
mod support;

mod account_deletion_attention;
mod background_custody_contract;
mod case_only_rename_e2e;
mod chaos_coordination_unreachable;
mod checkpoint_fake_mesh_merge;
mod conflict_burst_restart_e2e;
mod conflict_keep_both_converges;
mod conflict_loser_offline_converges;
mod conflict_resolution;
mod custody_evict_e2e;
mod dst_fidelity_lint;
mod dst_sec_convergence;
mod exec_bit_metadata_conflict;
mod fake_coordination_handoff_routes;
mod fake_coordination_view_overrides;
mod file_only_capture_e2e;
mod folder_volume_outage;
mod folder_volume_swap_real_mount;
mod full_replica_handoff_ready;
mod git_like_conflict_obligation;
mod ignore_pattern_rescan;
mod ignored_path_relay;
mod ios_writes_two_device;
mod live_burst_batching;
mod m5a_acceptance_matrix;
mod metadata_propagation;
mod native_recovery_e2e;
mod native_replication_e2e;
mod native_without_dcf;
mod offline_conflict_refused_flush;
mod ondemand_adoption;
mod pairing_partition_regression;
mod path_escape_defense;
mod peer_delete_is_recoverable;
mod peer_hydration;
mod peer_materialization;
mod pending_approval_attention;
mod provider_cancelled_fetch_then_free;
mod receiver_history_metadata_repro;
mod reconnect_coordinator_scenarios;
mod relay_reachability_publication;
mod release_manifest_chain;
mod removed_device_handoff_ticket;
mod restore_two_device_propagation;
mod revoke_keeps_reads_live;
mod role_loss_saga;
mod send_link_two_device;
mod send_transfer_two_device;
mod sleep_wake_recovery;
mod substrate_advertisement_barrier;
mod topology_pass3_protected_availability;
mod topology_rapid_restart_repro;
mod two_daemons_one_data_dir;
mod unservable_block_adoption;
mod unwritable_root_warning;
mod update_manifest_fixture;
mod update_manifest_pre_field_parser;
mod watcher_decompose_conformance;
mod windows_background_start;
mod windows_local_mutation;
mod windows_path_hazard_conflict;
mod windows_store_path;
