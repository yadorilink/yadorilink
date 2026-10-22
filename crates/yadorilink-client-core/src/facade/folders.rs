//! Folder control, files inside linked folders, and linking.

use super::{about, existing_directory, offering_force, ClientCore};
use crate::dto::{
    self, ConflictSummary, EvictOutcome, FileAvailability, FileRetention, FileVersion, FolderMode,
    FolderRestoreOutcome, LinkOutcome, PauseDuration, PinOutcome, PreflightResult,
    ProviderFolderOutcome, StorageModeOutcome, TrashedFile, UnlinkOutcome,
};
use crate::error::DesktopError;
use crate::ops;

fn on_demand(mode: FolderMode) -> bool {
    mode == FolderMode::OnDemand
}

/// The name of the default folder's group.
const DEFAULT_FOLDER_NAME: &str = "YadoriLink Folder";
/// The default folder's directory, under the home directory.
const DEFAULT_FOLDER_DIR: &str = "YadoriLink";

/// The default folder for a home directory (`None` or empty: there is none).
pub(super) fn default_folder_in(
    home: Option<std::ffi::OsString>,
) -> Result<dto::DefaultFolder, DesktopError> {
    let home = home
        .filter(|h| !h.is_empty())
        .ok_or_else(|| DesktopError::invalid_input("this account has no home directory", "home"))?;
    Ok(dto::DefaultFolder {
        name: DEFAULT_FOLDER_NAME.to_owned(),
        path: std::path::PathBuf::from(home)
            .join(DEFAULT_FOLDER_DIR)
            .to_string_lossy()
            .into_owned(),
    })
}

impl ClientCore {
    // ---- conflicts and kept originals ----------------------------------------------

    /// Resolves the conflicted copy at the absolute `copy_path` and returns the absolute path
    /// of the kept content. A copy the daemon does not list as a live conflict is refused.
    ///
    /// # Errors
    /// Refusals and daemon failures.
    pub async fn resolve_conflict(
        &self,
        copy_path: String,
        choice: dto::ConflictChoice,
    ) -> Result<String, DesktopError> {
        let choice = match choice {
            dto::ConflictChoice::KeepThis => ops::files::ConflictChoice::KeepThis,
            dto::ConflictChoice::KeepBoth => ops::files::ConflictChoice::KeepBoth,
        };
        let kept = ops::files::resolve_conflict(&copy_path, choice).await?;
        Ok(kept.to_string_lossy().into_owned())
    }

    /// # Errors
    /// Daemon failures.
    pub async fn list_retained_originals(
        &self,
    ) -> Result<Vec<dto::RetainedOriginal>, DesktopError> {
        Ok(ops::storage::list_retained_originals()
            .await?
            .iter()
            .map(dto::retained_original)
            .collect())
    }

    /// Releases the originals kept for `group_id`, one outcome per original.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn release_retained_originals(
        &self,
        group_id: String,
    ) -> Result<Vec<dto::RetainedRelease>, DesktopError> {
        Ok(ops::storage::release_retained_originals(&group_id)
            .await?
            .iter()
            .map(dto::retained_release)
            .collect())
    }

    // ---- folder control ----------------------------------------------------------

    /// With `expected_group_id` the daemon acts only if the folder at `local_path` still
    /// belongs to that group.
    ///
    /// # Errors
    /// Daemon failures; `Refused{GroupMismatch}` (nothing changed) when the folder belongs to
    /// another group.
    pub async fn pause_folder(
        &self,
        local_path: String,
        duration: PauseDuration,
        expected_group_id: Option<String>,
    ) -> Result<(), DesktopError> {
        Ok(ops::folders::pause_folder(local_path, duration, expected_group_id).await?)
    }

    /// As [`Self::pause_folder`].
    ///
    /// # Errors
    /// Daemon failures; `Refused{GroupMismatch}` as for `pause_folder`.
    pub async fn resume_folder(
        &self,
        local_path: String,
        expected_group_id: Option<String>,
    ) -> Result<(), DesktopError> {
        Ok(ops::folders::resume_folder(local_path, expected_group_id).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn pause_all(&self, duration: PauseDuration) -> Result<(), DesktopError> {
        Ok(ops::folders::pause_all(duration).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn resume_all(&self) -> Result<(), DesktopError> {
        Ok(ops::folders::resume_all().await?)
    }

    /// Stops syncing the folder whose link key is `local_path`, exactly as
    /// the status snapshot reports it: a directory's recorded path, or a
    /// provider-backed folder's synthetic key, which is not a filesystem
    /// path and must reach the daemon unchanged.
    ///
    /// With `expected_group_id` the folder is removed only if it still belongs to that group.
    ///
    /// # Errors
    /// Without `force`, `DurabilityBlocked{can_force: true}` when this device
    /// holds the group's only confirmed complete copy; `Refused{GroupMismatch}` (nothing
    /// changed) when the folder belongs to another group.
    pub async fn unlink_folder(
        &self,
        local_path: String,
        force: bool,
        expected_group_id: Option<String>,
    ) -> Result<UnlinkOutcome, DesktopError> {
        let handoff = ops::links::send_unlink_key(&local_path, force, expected_group_id.as_deref())
            .await
            .map_err(offering_force(force))?;
        Ok(UnlinkOutcome { handoff: handoff.as_ref().map(dto::handoff_summary) })
    }

    /// Confirms that the disk now mounted at the linked folder `local_path`
    /// is that folder's disk, so it syncs again with the disk as it is (what
    /// is missing from it is then deleted on every device).
    ///
    /// # Errors
    /// The daemon refuses a disk with no identity this system can check, a
    /// path that is not a linked folder, and a disk that does not answer.
    pub async fn readopt_folder(&self, local_path: String) -> Result<(), DesktopError> {
        Ok(ops::links::readopt_volume(&local_path).await?)
    }

    /// Switches this device between keeping every file and fetching on
    /// demand for a group it links. The File Provider domain is the front
    /// end's to reconcile afterwards.
    ///
    /// # Errors
    /// `InvalidInput{field: "group_id"}` when the group is not linked here;
    /// `DurabilityBlocked{can_force: false}` when giving up the complete copy
    /// is not safe yet.
    pub async fn set_storage_mode(
        &self,
        group_id: String,
        mode: FolderMode,
    ) -> Result<StorageModeOutcome, DesktopError> {
        let display = group_id.clone();
        let outcome = ops::shares::set_storage_mode_resolved(group_id, on_demand(mode), &display)
            .await
            .map_err(about("group_id"))?;
        Ok(StorageModeOutcome {
            changed: outcome.changed,
            handoff: outcome.handoff_result.as_ref().map(dto::handoff_summary),
        })
    }

    // ---- files -------------------------------------------------------------------

    /// # Errors
    /// Daemon failures.
    pub async fn list_conflicts(
        &self,
        local_path: Option<String>,
    ) -> Result<Vec<ConflictSummary>, DesktopError> {
        let files = ops::files::list_conflicts(local_path.as_deref()).await?;
        Ok(files.iter().map(dto::conflict_summary).collect())
    }

    /// # Errors
    /// Daemon failures.
    pub async fn list_trash(
        &self,
        local_path: Option<String>,
    ) -> Result<Vec<TrashedFile>, DesktopError> {
        let files = ops::files::list_trash(local_path.as_deref()).await?;
        Ok(files.iter().map(dto::trashed_file).collect())
    }

    /// # Errors
    /// Daemon failures.
    pub async fn restore_from_trash(&self, absolute_path: String) -> Result<(), DesktopError> {
        Ok(ops::files::restore_from_trash(absolute_path).await?)
    }

    /// Restores, together, every trashed entry removed by the same
    /// recursive delete or directory rename that removed the entry at
    /// `absolute_path`.
    ///
    /// # Errors
    /// Daemon failures, including an entry that was deleted on its own.
    pub async fn restore_trash_operation(
        &self,
        absolute_path: String,
    ) -> Result<FolderRestoreOutcome, DesktopError> {
        let outcome = ops::files::restore_trash_operation(absolute_path).await?;
        Ok(dto::folder_restore_outcome(&outcome))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn list_versions(
        &self,
        absolute_path: String,
    ) -> Result<Vec<FileVersion>, DesktopError> {
        let versions = ops::files::list_versions(absolute_path).await?;
        Ok(dto::file_versions(&versions))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn restore_version(
        &self,
        absolute_path: String,
        version_seq: Option<i64>,
    ) -> Result<(), DesktopError> {
        Ok(ops::files::restore_version(absolute_path, version_seq).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn file_availability(
        &self,
        absolute_path: String,
    ) -> Result<FileAvailability, DesktopError> {
        let status = ops::files::materialization_status(absolute_path).await?;
        Ok(dto::file_availability(&status))
    }

    /// The retention policy in force at the path.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn file_retention(
        &self,
        absolute_path: String,
    ) -> Result<FileRetention, DesktopError> {
        let status = ops::files::materialization_status(absolute_path).await?;
        Ok(dto::file_retention(status.retention.as_ref()))
    }

    /// Keeps the file or folder on this device: records the choice, then downloads what is not
    /// here yet. A failed download is reported in the outcome and the pin stands.
    ///
    /// # Errors
    /// Daemon failures (the choice could not be recorded).
    pub async fn pin_file(&self, absolute_path: String) -> Result<PinOutcome, DesktopError> {
        let pin = ops::files::pin(absolute_path).await?;
        Ok(dto::pin_outcome(&pin))
    }

    /// Stops keeping the file or folder; its content stays until it is freed.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn unpin_file(&self, absolute_path: String) -> Result<FileRetention, DesktopError> {
        let unpin = ops::files::unpin(absolute_path).await?;
        Ok(dto::file_retention(unpin.retention.as_ref()))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn hydrate_file(&self, absolute_path: String) -> Result<(), DesktopError> {
        Ok(ops::files::hydrate_file(absolute_path).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn evict_file(&self, absolute_path: String) -> Result<EvictOutcome, DesktopError> {
        let evict = ops::files::evict(absolute_path).await?;
        Ok(EvictOutcome {
            evicted: evict.dehydrated,
            blocks_reclaimed: evict.blocks_reclaimed,
            bytes_reclaimed: evict.bytes_reclaimed,
        })
    }

    // ---- linking -------------------------------------------------------------------

    /// The checks a link runs first. Pure apart from a best-effort look at
    /// the folders already linked; an unreachable daemon counts as none.
    ///
    /// # Errors
    /// `InvalidInput{field: "local_path"}` when the path does not resolve.
    pub async fn run_preflight(&self, local_path: String) -> Result<PreflightResult, DesktopError> {
        let (resolved, report) =
            ops::links::run_link_preflight(&local_path).await.map_err(about("local_path"))?;
        Ok(dto::preflight_result(&resolved, &report))
    }

    /// Creates a folder group and links it at `local_path`, as one step the
    /// daemon completes or rolls back.
    ///
    /// # Errors
    /// `InvalidInput{field: "local_path"}` for a path that does not resolve;
    /// daemon and coordination failures.
    pub async fn create_group_and_link(
        &self,
        group_name: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let absolute = existing_directory(&local_path)?;
        let local_path = absolute.to_string_lossy().into_owned();
        let group_id =
            ops::shares::create_and_link(group_name, absolute, on_demand(mode), acknowledge_risks)
                .await?;
        Ok(LinkOutcome { group_id, local_path, mode })
    }

    /// Creates a NEW group and a provider-backed folder (macOS File Provider): no directory is
    /// linked, the OS-managed domain is the folder. `request_token` is the retry identity: the same
    /// request, even after a restart, is answered with the folder it already made.
    ///
    /// # Errors
    /// Daemon failures, including a refusal when provider folders are not available.
    pub async fn create_provider_folder(
        &self,
        group_name: String,
        display_name: String,
        mode: FolderMode,
    ) -> Result<ProviderFolderOutcome, DesktopError> {
        let created =
            ops::shares::create_provider_folder(group_name, display_name.clone(), on_demand(mode))
                .await?;
        Ok(ProviderFolderOutcome {
            group_id: created.group_id,
            root_id: created.root_id,
            display_name,
            mode,
            already_existed: created.already_existed,
        })
    }

    /// Joins an existing group as a provider-backed folder.
    ///
    /// # Errors
    /// As [`ClientCore::create_provider_folder`].
    pub async fn join_provider_folder(
        &self,
        group_id: String,
        group_name: String,
        display_name: String,
        mode: FolderMode,
    ) -> Result<ProviderFolderOutcome, DesktopError> {
        let created = ops::shares::join_provider_folder(
            group_id,
            group_name,
            display_name.clone(),
            on_demand(mode),
        )
        .await?;
        Ok(ProviderFolderOutcome {
            group_id: created.group_id,
            root_id: created.root_id,
            display_name,
            mode,
            already_existed: created.already_existed,
        })
    }

    /// Joins a group this account owns and links it at `local_path`.
    ///
    /// # Errors
    /// As [`ClientCore::create_group_and_link`].
    pub async fn join_group_and_link(
        &self,
        group_id: String,
        group_name: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let absolute = existing_directory(&local_path)?;
        let local_path = absolute.to_string_lossy().into_owned();
        ops::shares::join_resolved(
            group_id.clone(),
            group_name,
            absolute,
            on_demand(mode),
            acknowledge_risks,
        )
        .await?;
        Ok(LinkOutcome { group_id, local_path, mode })
    }

    /// Where [`ClientCore::create_default_folder`] puts the "YadoriLink Folder". Performs no I/O.
    ///
    /// # Errors
    /// `InvalidInput{field: "home"}` when the account has no home directory.
    pub fn default_folder(&self) -> Result<dto::DefaultFolder, DesktopError> {
        let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        default_folder_in(std::env::var_os(var))
    }

    /// Has the daemon create the default "YadoriLink Folder" directory if it is missing, a new group
    /// of that name, and links the directory to it.
    ///
    /// # Errors
    /// As [`ClientCore::create_group_and_link`].
    pub async fn create_default_folder(
        &self,
        mode: FolderMode,
    ) -> Result<LinkOutcome, DesktopError> {
        let folder = self.default_folder()?;
        // The daemon creates the directory when it is missing, so the sync root is only ever
        // made by the engine.
        let group_id = ops::shares::create_and_link_creating_directory(
            folder.name,
            std::path::PathBuf::from(&folder.path),
            on_demand(mode),
        )
        .await?;
        let local_path = existing_directory(&folder.path)
            .map_or(folder.path, |p| p.to_string_lossy().into_owned());
        Ok(LinkOutcome { group_id, local_path, mode })
    }

    /// Links `local_path` into an existing group.
    ///
    /// # Errors
    /// As [`ClientCore::create_group_and_link`].
    pub async fn link_folder(
        &self,
        local_path: String,
        group_id: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let absolute = existing_directory(&local_path)?;
        let local_path = absolute.to_string_lossy().into_owned();
        ops::links::link_resolved_as(
            absolute,
            group_id.clone(),
            on_demand(mode),
            acknowledge_risks,
        )
        .await?;
        Ok(LinkOutcome { group_id, local_path, mode })
    }
}
