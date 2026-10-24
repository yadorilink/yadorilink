//! The provider roots' lines of `status`: why a root is not ready, its Eager progress, the files
//! that keep failing and the edits kept beside a file. Computed on demand from the daemon's own
//! state; the control socket reads it through a [`ProviderStatusSource`] that the shell side fills
//! in (the control context deliberately holds no daemon state).

use std::sync::{Arc, RwLock};

use yadorilink_ipc_proto::daemonctl::{
    PendingPublication, ProviderRemovalStatus, ProviderRootStatus, StuckFile,
};
use yadorilink_ipc_proto::shellipc::DriverState;
use yadorilink_replica_domain::session_state::{NotReady, Readiness};
use yadorilink_sync_sqlite::provider::{ProviderRepository, ProviderRoot};

use crate::provider_eager::{EagerDriver, EagerInputs, EagerStatus};
use crate::replica_coordinator::ReplicaCoordinator;

type Builder = Arc<dyn Fn() -> Vec<ProviderRootStatus> + Send + Sync>;
type ExtrasBuilder = Arc<dyn Fn() -> (Vec<ProviderRemovalStatus>, Vec<String>) + Send + Sync>;
type PendingBuilder = Arc<dyn Fn(u32) -> Result<Vec<PendingPublication>, String> + Send + Sync>;

/// Where the control socket gets the provider lines; empty until the shell side installs a builder.
#[derive(Default)]
pub struct ProviderStatusSource {
    builder: RwLock<Option<Builder>>,
    pending: RwLock<Option<PendingBuilder>>,
    extras: RwLock<Option<ExtrasBuilder>>,
}

impl ProviderStatusSource {
    pub(crate) fn install(&self, builder: Builder) {
        *self.builder.write().unwrap_or_else(|p| p.into_inner()) = Some(builder);
    }

    pub(crate) fn install_extras(&self, builder: ExtrasBuilder) {
        *self.extras.write().unwrap_or_else(|p| p.into_inner()) = Some(builder);
    }

    /// The removals in progress or done, and the orphan domains the host reported.
    pub(crate) fn extras(&self) -> (Vec<ProviderRemovalStatus>, Vec<String>) {
        let builder = self.extras.read().unwrap_or_else(|p| p.into_inner()).clone();
        builder.map_or_else(Default::default, |build| build())
    }

    pub(crate) fn install_pending(&self, builder: PendingBuilder) {
        *self.pending.write().unwrap_or_else(|p| p.into_inner()) = Some(builder);
    }

    /// Up to `limit` waiting publications per root, oldest first.
    pub(crate) fn pending_items(&self, limit: u32) -> Result<Vec<PendingPublication>, String> {
        let builder = self.pending.read().unwrap_or_else(|p| p.into_inner()).clone();
        builder.map_or_else(|| Ok(Vec::new()), |build| build(limit))
    }

    pub(crate) fn snapshot(&self) -> Vec<ProviderRootStatus> {
        let builder = self.builder.read().unwrap_or_else(|p| p.into_inner()).clone();
        builder.map_or_else(Vec::new, |build| build())
    }
}

/// Why the root is not ready, in words the user can act on.
pub(crate) fn readiness_text(root: &ProviderRoot) -> String {
    match root.readiness() {
        Readiness::Ready if root.namespace_ready => "ready".into(),
        Readiness::Ready => "preparing the folder".into(),
        Readiness::NotReady(NotReady::DomainNotRegistered) => {
            "waiting for the app to register the folder".into()
        }
        Readiness::NotReady(NotReady::ExtensionNotEnabled) => "enable File Provider".into(),
        Readiness::NotReady(NotReady::ProviderError(error)) => {
            format!("File Provider error: {error}")
        }
    }
}

fn eager_state_text(state: DriverState) -> &'static str {
    match state {
        DriverState::Running | DriverState::Unspecified => "running",
        DriverState::PausedLowDisk => "paused (low disk)",
        DriverState::WaitingPeers => "waiting for peers",
        DriverState::WaitingProvider => "waiting for File Provider",
        DriverState::Done => "done",
    }
}

/// Whether an Eager root's download state shows ALL its wanted content on the OS: the scan ended
/// `Done` (no wanted file without current content, none handed out and unsettled, none stuck) and
/// every repository read of the scan succeeded. "Current content on the OS" is the evidence rule
/// of `provider_local_presence`: the daemon handed over the current version and the host app
/// listed the item afterwards. Fail closed: anything else is the reason it is not complete.
pub(crate) fn eager_status_complete(status: &EagerStatus) -> Result<(), String> {
    if status.unreadable {
        return Err("the folder's download state could not be read".into());
    }
    if status.state != DriverState::Done {
        return Err(format!("downloads are {}", eager_state_text(status.state)));
    }
    if status.remote != 0 || status.hydrating != 0 {
        return Err(format!(
            "{} files are not downloaded yet ({} in progress)",
            status.remote, status.hydrating
        ));
    }
    if !status.stuck.is_empty() {
        return Err("some files keep failing to download".into());
    }
    // A held or paused file is left out of the scan, so `Done` says nothing about its content.
    if status.skipped != 0 {
        return Err(format!("{} files are held or paused", status.skipped));
    }
    Ok(())
}

/// Whether the provider root `root_id` holds all its content on the OS, for the replacement
/// confirm: the root is declared, ready, the host app is attached (its membership report is the
/// evidence), and its Eager scan is complete ([`eager_status_complete`]).
pub(crate) fn root_content_complete(
    coordinator: &ReplicaCoordinator,
    eager: &EagerDriver,
    inputs: &EagerInputs<'_>,
    root_id: &str,
) -> Result<(), String> {
    let roots = coordinator
        .provider_repository()
        .list_declared_roots()
        .map_err(|e| format!("the provider folders cannot be read: {e}"))?;
    let Some(root) = roots.iter().find(|r| r.root_id == root_id) else {
        return Err("the provider folder is not set up on this device".into());
    };
    let readiness = readiness_text(root);
    if readiness != "ready" {
        return Err(readiness);
    }
    if !inputs.host_attached {
        return Err("the File Provider app is not running".into());
    }
    match eager.status(inputs, root_id) {
        Some(status) => eager_status_complete(&status),
        None => Err("the provider folder is not kept downloaded (Eager) on this device".into()),
    }
}

fn encode_eager(status: &EagerStatus, line: &mut ProviderRootStatus) {
    line.eager = true;
    line.eager_state = eager_state_text(status.state).to_owned();
    line.eager_remote = status.remote;
    line.eager_hydrating = status.hydrating;
    line.eager_current = status.current;
    line.stuck = status
        .stuck
        .iter()
        .map(|(path, failures)| StuckFile { path: path.clone(), failures: *failures })
        .collect();
}

/// The line for a read that failed. The status must not look emptier or healthier precisely when
/// the provider state cannot be read, so it is never a zero line: the readiness is not "ready",
/// which also makes the rollup ask for attention.
fn unreadable_line(
    root_id: &str,
    display_name: &str,
    what: &str,
    error: &dyn std::fmt::Display,
) -> ProviderRootStatus {
    ProviderRootStatus {
        root_id: root_id.chars().take(8).collect(),
        display_name: display_name.to_owned(),
        readiness: format!("{what} unreadable: {error}"),
        counters_unreadable: true,
        ..Default::default()
    }
}

/// Where the host serves each declared root: root id (hex) to the folder the OS shows it in. The
/// Windows host records the folders it registered in a file; nothing else knows them. Empty where
/// there is no such folder, and when the record cannot be read (the line then carries no path).
#[cfg(windows)]
fn registered_sync_roots() -> std::collections::HashMap<String, std::path::PathBuf> {
    use yadorilink_windows_provider_policy::{host, host_paths};
    if host_paths::check().is_err() {
        return Default::default();
    }
    host::read_registry_at(&host_paths::roots_registry_file()).unwrap_or_else(|error| {
        tracing::warn!(%error, "could not read where the provider folders are registered");
        Default::default()
    })
}

#[cfg(not(windows))]
fn registered_sync_roots() -> std::collections::HashMap<String, std::path::PathBuf> {
    Default::default()
}

/// The folder of `root_id` in `registered`, as text; empty when there is none.
fn sync_root_text(
    registered: &std::collections::HashMap<String, std::path::PathBuf>,
    root_id: &str,
) -> String {
    registered.get(root_id).map(|path| path.to_string_lossy().into_owned()).unwrap_or_default()
}

/// One line per declared provider root, with the root's full id (the line carries only a prefix).
/// Only the repository half of the line; the Eager progress is added by the caller.
fn repository_lines(repo: &ProviderRepository, now_ms: i64) -> Vec<(String, ProviderRootStatus)> {
    let roots = match repo.list_declared_roots() {
        Ok(roots) => roots,
        Err(error) => {
            return vec![(
                String::new(),
                unreadable_line("", "provider roots", "the provider roots", &error),
            )];
        }
    };
    let registered = registered_sync_roots();
    roots
        .iter()
        .map(|root| {
            let counters = repo.kept_edits(&root.root_id).map_err(|e| format!("{e:?}")).and_then(
                |kept| {
                    let (pending, _) = repo
                        .pending_publications(&root.root_id, now_ms, 0)
                        .map_err(|e| e.to_string())?;
                    let unconfirmed = repo
                        .unresolved_publications(&root.root_id, now_ms)
                        .map_err(|e| e.to_string())?;
                    Ok((kept, pending, unconfirmed))
                },
            );
            let line = match counters {
                Ok(((kept, first), pending, unconfirmed)) => ProviderRootStatus {
                    pending_publications: pending.count,
                    pending_oldest_ms: pending.oldest_age_ms,
                    unconfirmed_publications: unconfirmed.count,
                    unconfirmed_oldest_ms: unconfirmed.oldest_age_ms,
                    root_id: root.root_id.chars().take(8).collect(),
                    display_name: root.display_name.clone(),
                    readiness: readiness_text(root),
                    sync_root_path: sync_root_text(&registered, &root.root_id),
                    kept_edits: kept,
                    kept_edits_oldest_ms: first.map_or(0, |at| (now_ms - at).max(0) as u64),
                    ..Default::default()
                },
                Err(error) => {
                    tracing::warn!(root = %root.root_id, %error, "could not read the provider root's state for status");
                    unreadable_line(&root.root_id, &root.display_name, "the provider state", &error)
                }
            };
            (root.root_id.clone(), line)
        })
        .collect()
}

/// One line per declared provider root.
pub(crate) fn provider_root_lines(
    coordinator: &ReplicaCoordinator,
    eager: &EagerDriver,
    inputs: &EagerInputs<'_>,
    now_ms: i64,
) -> Vec<ProviderRootStatus> {
    repository_lines(coordinator.provider_repository(), now_ms)
        .into_iter()
        .map(|(root_id, mut line)| {
            if let Some(status) = eager.status(inputs, &root_id) {
                encode_eager(&status, &mut line);
                if status.unreadable {
                    // Partial counters are not progress: the line is not "ready".
                    line.readiness = "the Eager progress unreadable: see the daemon log".into();
                    line.counters_unreadable = true;
                }
            }
            line
        })
        .collect()
}

/// Up to `limit` publications waiting on the OS per declared root, oldest first. A read that fails
/// is an error, never an empty list: an empty list says nothing is waiting.
pub(crate) fn pending_items(
    coordinator: &ReplicaCoordinator,
    limit: u32,
    now_ms: i64,
) -> Result<Vec<PendingPublication>, String> {
    let repo = coordinator.provider_repository();
    let mut all = Vec::new();
    for root in repo.list_declared_roots().map_err(|e| e.to_string())? {
        let (_, items) = repo
            .pending_publications(&root.root_id, now_ms, limit)
            .map_err(|e| format!("the pending publications of {}: {e}", root.root_id))?;
        let id: String = root.root_id.chars().take(8).collect();
        all.extend(items.into_iter().map(|(path, age_ms)| PendingPublication {
            root_id: id.clone(),
            path,
            age_ms,
        }));
    }
    Ok(all)
}

#[cfg(test)]
mod tests;
