//! Resolves an absolute filesystem path to its `(group_id, relative_path)`
//! pair -- a thin `Arc<SyncState>`-holding wrapper around `shell_status`'s
//! resolver, in the same shape as the other query services so callers go
//! through `context.queries.linked_path` rather than reaching for the free
//! function directly. Shared by `FileHistoryQueryService`'s read paths and
//! (later) the materialization/restore command services, which all resolve
//! the same absolute-path-to-group mapping before doing their own thing
//! with it.

use std::sync::Arc;

use crate::replica_coordinator::ReplicaCoordinator;

pub(crate) struct LinkedPathResolver {
    sync_state: Arc<ReplicaCoordinator>,
    /// The engine's state directory, where the Windows host records its sync roots.
    config_dir: std::path::PathBuf,
}

impl LinkedPathResolver {
    pub(crate) fn new(sync_state: Arc<ReplicaCoordinator>, config_dir: std::path::PathBuf) -> Self {
        Self { sync_state, config_dir }
    }

    pub(crate) fn resolve(&self, absolute_path: &str) -> Option<(String, String)> {
        crate::shell_status::resolve_group_and_rel_path(&self.sync_state, absolute_path)
    }

    /// A plain folder's path, or a path inside a File Provider location: the group and the path
    /// relative to its root, for a command that takes a path wherever the folder is shown.
    pub(crate) fn resolve_any(&self, absolute_path: &str) -> Option<(String, String)> {
        self.resolve(absolute_path).or_else(|| self.resolve_provider(absolute_path))
    }

    /// The folder a person names with a path: a plain linked folder, or a File Provider folder at its
    /// place in the file manager. For a command that acts on a whole folder, so it is strict where
    /// [`Self::resolve_any`] is not: the path must exist as a directory, is looked up by its canonical
    /// spelling (a symlink or `.`/`..` cannot make it name another folder), a File Provider location
    /// must stand where the file manager puts it (`.../Library/CloudStorage/<location>` on macOS), and
    /// a path inside a folder is [`FolderPath::Inside`], not the folder.
    pub(crate) fn resolve_folder(&self, path: &str) -> FolderPath {
        let Ok(canonical) = std::fs::canonicalize(path) else { return FolderPath::NotLinked };
        if !canonical.is_dir() {
            return FolderPath::NotLinked;
        }
        let canonical = canonical.to_string_lossy().into_owned();
        let found = self.resolve(&canonical).or_else(|| self.resolve_provider_folder(&canonical));
        match found {
            Some((group_id, rel)) if rel.is_empty() => FolderPath::Folder(group_id),
            Some((group_id, _)) => FolderPath::Inside(group_id),
            None => FolderPath::NotLinked,
        }
    }

    /// The File Provider folder a canonical path is in, found strictly: on macOS the location must stand
    /// at `<home>/Library/CloudStorage/` and be exactly `YadoriLink-<display name of the group's root>`
    /// (a directory of another provider, or one that only ends in the same letters, is not it); on
    /// Windows the host's own record of its sync roots says where each stands, root included.
    fn resolve_provider_folder(&self, canonical: &str) -> Option<(String, String)> {
        #[cfg(windows)]
        {
            let (root_id, rel) =
                crate::windows_sync_roots::locate_folder(&self.config_dir, canonical)?;
            let group_id =
                self.sync_state.provider_repository().group_of_root(&root_id).ok().flatten()?;
            Some((group_id, rel))
        }
        #[cfg(not(windows))]
        {
            let location = cloud_storage_location(std::path::Path::new(canonical))?;
            let (group_id, rel) = self.resolve_provider(canonical)?;
            let roots = self.sync_state.provider_repository().list_declared_roots().ok()?;
            let root = roots.iter().find(|root| root.group_id == group_id)?;
            (location == format!("{FILE_PROVIDER_LOCATION_PREFIX}-{}", root.display_name))
                .then_some((group_id, rel))
        }
    }

    /// The same for a path inside a File Provider location (a provider root has no directory).
    pub(crate) fn resolve_provider(&self, absolute_path: &str) -> Option<(String, String)> {
        crate::shell_status::resolve_provider_group_and_rel_path(
            &self.sync_state,
            &self.config_dir,
            absolute_path,
        )
    }
}

/// What a path names, as a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FolderPath {
    /// The folder itself: its group.
    Folder(String),
    /// A path inside a linked folder (its group): not the folder.
    Inside(String),
    NotLinked,
}

/// What the file manager calls a YadoriLink folder at `~/Library/CloudStorage`: the extension's name, a
/// dash, and the folder's display name.
#[cfg(not(windows))]
const FILE_PROVIDER_LOCATION_PREFIX: &str = "YadoriLink";

/// The location component of `<...>/Library/CloudStorage/<location>[/...]` in a canonical path, or `None`
/// when the path does not stand where the file manager puts File Provider folders.
#[cfg(not(windows))]
fn cloud_storage_location(canonical: &std::path::Path) -> Option<String> {
    let mut components = canonical.components().map(|c| c.as_os_str());
    let mut previous = None;
    while let Some(component) = components.next() {
        if component == "CloudStorage" && previous == Some(std::ffi::OsStr::new("Library")) {
            return components.next().map(|c| c.to_string_lossy().into_owned());
        }
        previous = Some(component);
    }
    None
}
