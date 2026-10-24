//! `LinkStatusReadPort` backed by `DaemonState` -- moved verbatim (in
//! logic; only the output type changed, from the IPC-proto `LinkStatus` to
//! the plain `LinkStatusView`) from `control_socket::list_link_statuses`.
//! Still holds `Arc<DaemonState>` (a deliberate strangler step -- see
//! `crate::queries::link_status`'s own doc comment); nothing outside this
//! file and `adapters/query/` is allowed to depend on `DaemonState` for
//! this read model.

use std::sync::Arc;

#[cfg(windows)]
use yadorilink_replica_domain::file::RecordKind;

use crate::daemon_state::DaemonState;
use crate::link_registry::DegradedCause;
use crate::queries::link_status::{
    DegradedLinkView, FetchAvailability, HeldFileView, LinkStatusReadPort, LinkStatusView,
    LinkTransferView, LocalStorageState,
};
use crate::replica_coordinator::ReplicaCoordinator;

/// The most placeholder files whose blocks one status read checks against the local block store.
/// A folder with more is not checked at all (see `locally_held_placeholders`).
pub(super) const LOCAL_BLOCK_CHECK_FILE_BUDGET: usize = 512;

pub(crate) struct DaemonLinkStatusReader {
    state: Arc<DaemonState>,
}

impl DaemonLinkStatusReader {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

/// Independent of `paused`: why this link is degraded, if it is.
fn link_degraded_view(
    state: &DaemonState,
    link: &yadorilink_replica_domain::session_state::FolderLink,
) -> Option<DegradedLinkView> {
    state
        .links
        .watch_limit_reason(link.key())
        // An exhausted OS watch limit: sync is stalled or late, and only
        // the user can raise it, so it outranks the self-clearing causes.
        .map(|reason| DegradedLinkView { reason, cause: DegradedCause::FileWatchLimit })
        .or_else(|| {
            state
                .degraded_link_info(link.key())
                .map(|info| DegradedLinkView { reason: info.reason, cause: info.cause })
        })
        // An orphaned link no longer takes part in sync at all; without a
        // reason here it would read as an idle, up-to-date folder.
        .or_else(|| {
            link.orphaned.then(|| DegradedLinkView {
                reason: crate::link_registry::NOT_JOINED_REASON.to_string(),
                cause: DegradedCause::NotJoined,
            })
        })
}

impl LinkStatusReadPort for DaemonLinkStatusReader {
    fn list_links(&self) -> Result<Vec<LinkStatusView>, crate::sync_error::SyncError> {
        let state = &self.state;
        let links = state.replica_coordinator.link_repository().list_links()?;
        let mut out = Vec::with_capacity(links.len());
        for link in links {
            let files =
                state.replica_coordinator.file_index_repository().list_files(&link.group_id)?;
            // Same targeted query `FileHistoryQueryService::list_conflicts` reads
            // from (not a predicate re-applied to `files` above, which -- unlike
            // this query -- doesn't filter tombstones), so the two can never
            // disagree about which paths count.
            let conflict_count = state
                .replica_coordinator
                .file_index_repository()
                .list_live_conflict_copies(&link.group_id)?
                .len() as u64;
            let conflicts_pending = state
                .replica_coordinator
                .file_index_repository()
                .contested_path_count(&link.group_id)?;
            let materialization = state
                .replica_coordinator
                .materialization_state_repository()
                .materialization_counts(&link.group_id)?;
            // NOT `?`: this resolver refuses an ambiguous group, and propagating
            // that would fail the ENTIRE status listing -- for every group on the
            // device, not just the offending one. Status is the surface that MAKES
            // the ambiguity visible (see `ambiguous_local_paths` below), so letting
            // it be the thing an ambiguous group breaks would hide the refusal
            // behind a bare error string and leave the user with no way to see which
            // folders collided. It would also turn a per-GROUP refusal into a
            // per-DEVICE one, which is exactly what this invariant must never do.
            //
            // `false` is the safe default and costs nothing here: it only classifies
            // symlinks as "skipped" for a cosmetic count, and an ambiguous group is
            // refusing to sync anyway, so there is no materialization for it to be
            // wrong about.
            let windows_symlink_opt_in = state
                .replica_coordinator
                .link_repository()
                .windows_symlink_opt_in_for_group(&link.group_id)
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        group_id = %link.group_id,
                        error = %e,
                        "cannot read this group's symlink policy for status; reporting the default"
                    );
                    false
                });
            let mut held_files = Vec::new();
            let mut skipped_symlink_count = 0u64;
            for file in files.iter().filter(|f| !f.deleted) {
                if let Some(held) = state
                    .replica_coordinator
                    .materialization_state_repository()
                    .get_held_state(&link.group_id, &file.path)?
                {
                    held_files.push(HeldFileView {
                        path: file.path.clone(),
                        reason: held.reason,
                        held_since_unix_nanos: held.since_unix_nanos,
                    });
                }
                if is_skipped_windows_symlink(
                    &state.replica_coordinator,
                    &link.group_id,
                    &file.path,
                    windows_symlink_opt_in,
                )? {
                    skipped_symlink_count += 1;
                }
            }
            // Independent of `paused` (a link can be paused and/or degraded
            // at once -- see `DegradedLinkInfo`'s doc comment).
            let degraded = link_degraded_view(state, &link);
            // This link's active-transfer rollup, if any is currently in
            // flight.
            let transfer =
                state.telemetry.link_transfer_rollup(&link.group_id).map(|r| LinkTransferView {
                    bytes_done: r.bytes_done,
                    bytes_total: r.bytes_total,
                    blocks_done: r.blocks_done,
                    blocks_total: r.blocks_total,
                    eta_seconds: r.eta_seconds,
                });
            let durability_status = state.group_durability_status(&link.group_id);
            let durability_evidence = state.group_durability_evidence(&link.group_id);
            let durability_check_pending = state.group_durability_check_pending(&link.group_id);
            let fully_hydrated_locally = materialization.placeholder == 0
                && materialization.hydrating == 0
                && materialization.evicting == 0;
            let requested_content_count = requested_content_count(state, &link, &materialization);
            let local_storage_state = match link.materialization_policy {
                yadorilink_replica_domain::session_state::MaterializationPolicy::Eager => {
                    if fully_hydrated_locally {
                        LocalStorageState::FullCopy
                    } else {
                        LocalStorageState::PartiallyMaterialized
                    }
                }
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand => {
                    LocalStorageState::OnDemand
                }
            };
            // Local certainty comes first, unconditionally: whether THIS
            // device's own disk state is legible has nothing to do with the
            // daemon-wide "cannot currently confirm PEER custody" facts
            // `daemon_wide_evidence_uncertain` checks -- gating it behind
            // that check (an earlier version of this derivation did) would
            // report `Unknown` for content this daemon already knows for
            // certain is available.
            let fetch_availability = if fully_hydrated_locally
                || placeholders_held_locally(state, &link.group_id, &materialization)
            {
                FetchAvailability::AvailableNow
            } else if state.daemon_wide_evidence_uncertain(&link.group_id) {
                FetchAvailability::Unknown
            } else if state.fetch_available_via_confirmed_peer(&link.group_id) {
                FetchAvailability::AvailableNow
            } else {
                FetchAvailability::UnavailableNow
            };
            // Every live folder registered for this group. More than one is the
            // refusing state; the paths ARE the remedy, since unlinking is keyed by
            // path. An unreadable link table surfaces as "not ambiguous" rather than
            // failing the whole status listing: status must keep rendering, and the
            // group is already refusing to sync on the paths that matter.
            let ambiguous_local_paths = state
                .replica_coordinator
                .link_repository()
                .live_link_paths_for_group(&link.group_id)
                .or_else(|e| match e {
                    // A provider folder has no path to be linked twice at.
                    yadorilink_sync_sqlite::SyncSqliteError::NotFilesystemRoot(_) => Ok(Vec::new()),
                    other => Err(other),
                })
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        group_id = %link.group_id,
                        error = %e,
                        "cannot read this group's links to report whether it is linked twice"
                    );
                    Vec::new()
                });
            let capture_volume = match &link.location {
                yadorilink_replica_domain::session_state::LinkLocation::Folder(_) => {
                    Some(state.replica_coordinator.folder_capture_volume(link.key()))
                }
                _ => None,
            };
            // Exclusive: a folder only the user can confirm is not reported as
            // simply away, whose remedy is to reconnect the disk and wait.
            let capture_volume_unconfirmed = matches!(
                capture_volume,
                Some(Ok(yadorilink_filesystem_sync::device_boundary::VolumeMatch::Unconfirmed))
            );
            let capture_volume_changed = matches!(
                capture_volume,
                Some(Ok(yadorilink_filesystem_sync::device_boundary::VolumeMatch::Other) | Err(_))
            );
            let stranded_directory_count =
                state.replica_coordinator.temp_ledger(&link.group_id).standing_stranded_count()?;
            let provider = match &link.location {
                yadorilink_replica_domain::session_state::LinkLocation::Provider {
                    root_id,
                    ..
                } => {
                    let name = state
                        .replica_coordinator
                        .provider_repository()
                        .root_display_name(root_id)
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    Some((root_id.clone(), name))
                }
                yadorilink_replica_domain::session_state::LinkLocation::Folder(_) => None,
            };
            out.push(LinkStatusView {
                provider,
                local_path: link.key().to_string(),
                group_id: link.group_id.clone(),
                paused: link.paused,
                paused_until_unix: state
                    .replica_coordinator
                    .link_repository()
                    .paused_until(link.key())?
                    .unwrap_or(0),
                conflict_count,
                conflict_note: if (conflict_count > 0 || conflicts_pending > 0)
                    && !yadorilink_sync_sqlite::displacement_guard::destructive_step_durable(
                        std::path::Path::new(link.key()),
                    )
                {
                    "Conflict resolved semantically; local filesystem update is waiting for Windows durability validation."
                        .to_string()
                } else {
                    String::new()
                },
                conflicts_pending,
                materialization_policy: link.materialization_policy.as_db_str().to_string(),
                hydrated_count: materialization.hydrated,
                placeholder_count: materialization.placeholder,
                hydrating_count: materialization.hydrating,
                requested_content_count,
                held_files,
                skipped_symlink_count,
                stranded_directory_count,
                unreadable_files: state.telemetry.unreadable_files(&link.group_id),
                pending_approvals: state.pending_approvals(&link.group_id),
                degraded,
                transfer,
                durability_status,
                durability_evidence,
                durability_check_pending,
                // Surfaces the same staleness gate admission and local emission
                // fail closed on, so a group whose policy this daemon distrusts
                // (own verification failure or coordinator-flagged invalid) is
                // distinguishable in status from a healthy one.
                policy_stale: state.authority.is_group_policy_stale(&link.group_id),
                local_storage_state,
                fetch_availability,
                ambiguous_local_paths,
                capture_volume_changed,
                capture_volume_unconfirmed,
                full_replica_device_ids: state
                    .authority
                    .full_replica_devices_for_group(&link.group_id),
                custody_confirmed_by: state
                    .group_custody_confirmed_peer(&link.group_id)
                    .into_iter()
                    .collect(),
            });
        }
        Ok(out)
    }
}

/// A skipped-on-materialize Windows symlink (real POSIX symlinks
/// materialize via the ordinary atomic temp-path-then-rename path,
/// `chunker::materialize_symlink`) -- moved verbatim, including its
/// platform split, from `control_socket::is_skipped_windows_symlink`.
#[cfg(windows)]
fn is_skipped_windows_symlink(
    state: &ReplicaCoordinator,
    group_id: &str,
    path: &str,
    windows_symlink_opt_in: bool,
) -> Result<bool, crate::sync_error::SyncError> {
    if windows_symlink_opt_in {
        return Ok(false);
    }
    Ok(state
        .file_index_repository()
        .get_record_kind(group_id, path)?
        .is_some_and(|kind| kind == RecordKind::Symlink))
}

#[cfg(not(windows))]
fn is_skipped_windows_symlink(
    _state: &ReplicaCoordinator,
    _group_id: &str,
    _path: &str,
    _windows_symlink_opt_in: bool,
) -> Result<bool, crate::sync_error::SyncError> {
    Ok(false)
}

#[cfg(test)]
mod tests;

/// The full acceptance matrix -- 12 named scenarios (A-L) the
/// directive requires, automated at this domain/read-model level. Each
/// test asserts the FULL cross-dimension tuple (durability_status,
/// local_storage_state, fetch_availability, and where relevant the peer
/// connection/relay facts) for its scenario, not just one field in
/// isolation -- the point of this matrix is proving the dimensions stay
/// correctly independent/correctly coupled exactly where each scenario
/// requires, not re-testing any single formula already covered above.
/// H (last safe-copy removal attempt -> backend rejects) and L (restart
/// with stale cached Protected -> no false green before revalidation) are
/// NOT duplicated here -- they're already covered by dedicated,
/// already-reviewed suites (`tests/unlink_and_removal_durability.rs`'s 10
/// tests and `control_socket.rs`'s `forced_unlink_latches_group_
/// durability_unknown`/friends for H; `daemon_state.rs`'s
/// `restart_never_shows_a_stale_healthy_status` for L) -- each doc
/// comment below says so explicitly rather than re-deriving weaker
/// coverage under a new name. Scenario B (a confirming peer reachable
/// only via relay) and scenario I (a relay anchor's declared capability
/// has zero durability effect) were removed together with the old
/// peer-device relay mechanism. I stays gone: an iroh relay server only
/// forwards packets, holds no custody and declares no capability. B's
/// route exists again as `RouteKind::Relay` (a peer reached only through
/// an iroh relay), and `fetch_available_via_confirmed_peer` counts it like
/// any other connected route, but no scenario below pins a relay row yet.
#[cfg(test)]
mod durability_acceptance_matrix;

/// `LinkStatus.requested_content_count`: requests, not states. Fetches in flight and opens queued
/// for a slot (the same fetch once it has a `Hydrating` row, so the larger of the two), plus a
/// folder-backed Eager link's unmaterialized files (it asks for all of them). A provider root's
/// Eager downloads are tracked by its own status (the OS holds the content, not these rows), and
/// a paused link requests nothing new. Eviction is never a request.
fn requested_content_count(
    state: &DaemonState,
    link: &yadorilink_replica_domain::session_state::FolderLink,
    materialization: &yadorilink_sync_sqlite::MaterializationCounts,
) -> u64 {
    use yadorilink_replica_domain::session_state::{LinkLocation, MaterializationPolicy};
    let is_provider = matches!(&link.location, LinkLocation::Provider { .. });
    let eager_wanted = match link.materialization_policy {
        MaterializationPolicy::Eager if !is_provider && !link.paused => materialization.placeholder,
        _ => 0,
    };
    eager_wanted
        .saturating_add(materialization.hydrating.max(state.requested_opens.count(&link.group_id)))
}

/// Whether every placeholder of the group can be opened from blocks this device already holds:
/// the same local-first test a read applies (the block store has it and this group has recorded
/// provenance for it), so a dataless item whose bytes are local is not reported as needing a
/// peer. Read-only, cheap and bounded: nothing is read back or re-hashed, and a folder with more
/// than [`LOCAL_BLOCK_CHECK_FILE_BUDGET`] placeholders is not checked. Fails closed: a file in
/// flight or being evicted, a placeholder that is not a regular file, a block that is missing or
/// has no provenance, or any error all answer `false`, which leaves the peer-based derivation.
fn placeholders_held_locally(
    state: &DaemonState,
    group_id: &str,
    materialization: &yadorilink_sync_sqlite::MaterializationCounts,
) -> bool {
    if materialization.placeholder == 0
        || materialization.hydrating != 0
        || materialization.evicting != 0
    {
        return false;
    }
    let held = || -> Result<bool, Box<dyn std::error::Error>> {
        let Some(hashes) = state
            .replica_coordinator
            .materialization_state_repository()
            .placeholder_block_hashes(group_id, LOCAL_BLOCK_CHECK_FILE_BUDGET)?
        else {
            return Ok(false);
        };
        let hashes: Vec<Vec<u8>> = hashes.into_iter().collect();
        let hex: Vec<String> = hashes.iter().map(hex::encode).collect();
        if !state.block_store.present_blocks(&hex)?.iter().all(|present| *present) {
            return Ok(false);
        }
        let with_provenance = state
            .replica_coordinator
            .sqlite()
            .dag_group_has_block_provenance_batch(group_id, &hashes)?;
        Ok(hashes.iter().all(|hash| with_provenance.contains(hash)))
    };
    held().unwrap_or_else(|error| {
        tracing::warn!(group_id, %error, "cannot check whether the placeholders are held locally");
        false
    })
}
