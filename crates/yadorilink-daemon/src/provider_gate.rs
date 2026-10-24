//! The per-root provider decision, replacing the global "placeholder pipeline is
//! connected" switch.
//!
//! A root's provider declaration lives on its link. The direct-filesystem pipeline (scan,
//! watcher, flush, hydration, authoring from disk) is for PLAIN roots only: a provider
//! root, ready or not, is closed to it until the provider projection exists (the OS owns
//! the local copy; scanning it would read absence as deletion), and a link that declares a
//! provider whose state is missing is refused with "rebootstrap required".
//!
//! The model: a `ProviderKind::None` root runs the direct-filesystem pipeline and NEVER enters the File
//! Provider capability (it has no on-demand mechanism, so it never holds dataless items); a
//! provider root (`MacFileProvider`, `IosFileProvider` or `WindowsCfapi`) may only when its readiness
//! evidence says Ready. There is no global switch.

use yadorilink_replica_domain::session_state::Readiness;
use yadorilink_sync_sqlite::provider::ProviderDeclaration;

use crate::replica_coordinator::ReplicaCoordinator;
use crate::sync_error::SyncError;

/// Fails closed unless the group is a plain root. Called by every entry that would start,
/// hydrate, evict, author or tombstone from a directory.
pub(crate) fn require_filesystem_root(
    coordinator: &ReplicaCoordinator,
    group_id: &str,
) -> Result<(), SyncError> {
    coordinator
        .provider_repository()
        .require_plain(group_id)
        .map_err(|e| SyncError::NotFilesystemRoot(e.to_string()))
}

/// Whether the root may run OnDemand (hold dataless items, evict): only a READY provider root. A plain root never may; a read error answers `false` (fail closed).
pub(crate) fn root_allows_on_demand(coordinator: &ReplicaCoordinator, group_id: &str) -> bool {
    matches!(
        coordinator.provider_repository().declaration_for_group(group_id),
        Ok(ProviderDeclaration::Provider(root)) if root.readiness() == Readiness::Ready
    )
}

/// The refusal for an on-demand request on a root that cannot hold dataless items. Only a ready
/// provider root (macOS File Provider, Windows Cloud Files) can be on-demand; a regular folder
/// never is, on any platform, so "not available in this build" would send the user looking for
/// an upgrade that does not exist. The same words are used by every refusal site and matched by
/// scripts, so it is one constant.
pub(crate) const ON_DEMAND_REFUSAL: &str = "on-demand storage is not available for a regular \
     folder, only for a provider folder (`yadorilink provider-folder create <name> --on-demand`, \
     macOS and Windows) that is ready; link this folder in eager (full-copy) mode instead";

#[cfg(test)]
mod tests;
