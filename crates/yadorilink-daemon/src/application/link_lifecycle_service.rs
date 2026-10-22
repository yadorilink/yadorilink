use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::ports::{LinkCommand, LinkOutcome, LinkRepositoryPort, LinkWatcherPort};
use crate::error::DaemonError;

/// The single entry point for creating a link -- both the plain
/// `yadorilink link` command (the control socket's own `Link` handler)
/// and `EnrollmentService::create_and_link`/`join_and_link` (via
/// `EnrollmentLinkPort`, which calls this service directly rather than
/// looping back into the transport layer) converge here, never a second,
/// independent commit path.
///
/// Owns the real orchestration the daemon's original `link` handler body
/// used to embody: duplicate-group prevention, nested-path preflight, the
/// pending-enrollment marker's same-transaction coupling, watcher setup,
/// and rollback-on-setup-failure. `LinkRepositoryPort`/`LinkWatcherPort`
/// are narrow, mostly-single-`SyncState`-call ports; every decision about
/// WHEN to call which, and how to roll back, lives here.
pub(crate) struct LinkLifecycleService {
    repository: Arc<dyn LinkRepositoryPort>,
    watcher: Arc<dyn LinkWatcherPort>,
    /// One async lock per local path with a `link()` call in flight. Held
    /// across the whole call -- the already-linked check, the commit, the
    /// watcher start and any rollback -- so two concurrent links of one
    /// folder (the CLI and the desktop app, a double submit) run one after
    /// the other. Without it both can pass the check before either runtime
    /// holds the path, and the one that loses the start rolls back a row
    /// the other's running link now depends on. An entry is removed once
    /// no call holds or waits for it.
    path_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl LinkLifecycleService {
    pub(crate) fn new(
        repository: Arc<dyn LinkRepositoryPort>,
        watcher: Arc<dyn LinkWatcherPort>,
    ) -> Self {
        Self { repository, watcher, path_locks: Mutex::new(HashMap::new()) }
    }

    /// Whether `local_path` is CURRENTLY a live link for `group_id`, read
    /// directly from local state rather than inferred from a `link()`
    /// call's own return value. `link()`'s `Err` does not always mean
    /// nothing was committed (see its own doc comment on the rollback-
    /// failure path); callers with no independent state of their own to
    /// classify against (no `enrollment_operations` journal row -- e.g. a
    /// plain, non-enrollment-tracked link commit) use this instead to tell
    /// "genuinely never committed" apart from "may still be committed"
    /// after a failure.
    pub(crate) fn is_linked(
        &self,
        group_id: &str,
        local_path: &str,
    ) -> Result<bool, crate::sync_error::SyncError> {
        Ok(self.repository.live_link_paths_for_group(group_id)?.iter().any(|p| p == local_path))
    }

    /// Keeps a linked folder visible as needing the person after start over could not join its
    /// group again: the link stops taking part in sync (`orphaned`, the state a link in a
    /// cancelled group has) and its runtime stops. The row and the folder's files stay; linking
    /// the folder to its group again clears the mark. Idempotent.
    pub(crate) async fn mark_not_rejoined(
        &self,
        local_path: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        let path_lock = self
            .path_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(local_path.to_owned())
            .or_default()
            .clone();
        let result = {
            let _serialized = path_lock.lock().await;
            // Stopped first, so no runtime ever runs over an orphaned row. A mark that fails after
            // that leaves the folder stopped and unmarked; the caller reports it and is run again.
            self.watcher.stop(local_path).await;
            self.repository.mark_link_orphaned(local_path)
        };
        let mut locks = self.path_locks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if Arc::strong_count(&path_lock) == 2 {
            locks.remove(local_path);
        }
        result
    }

    /// The link preflight for `path` against this device's own links: the
    /// one report both a client's review screen and [`Self::require_risks_acknowledged`]
    /// read. Runs on the path's canonical spelling when it resolves, so a
    /// symlinked spelling gets the same answer as its target; returns that
    /// spelling with the report. Blocking (path resolution and a bounded
    /// directory scan).
    pub(crate) fn preflight(
        &self,
        path: &std::path::Path,
    ) -> Result<
        (std::path::PathBuf, yadorilink_local_storage::link_preflight::LinkPreflightReport),
        DaemonError,
    > {
        let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let existing: Vec<String> = self
            .repository
            .list_link_paths_and_groups()?
            .into_iter()
            .map(|(path, _group)| path)
            .collect();
        let report = yadorilink_local_storage::link_preflight::run_preflight(
            &resolved,
            &existing,
            self.repository.preflight_headroom_override_bytes(),
        );
        Ok((resolved, report))
    }

    /// Refuses a request to link `path` that did not acknowledge the risks
    /// the preflight finds there. Every client's confirmation step (`--yes`,
    /// a review dialog, the web page) is only a way to set
    /// `acknowledged`; this is where it is enforced. Blocking, like
    /// [`Self::preflight`], and run before anything is created.
    pub(crate) fn require_risks_acknowledged(
        &self,
        path: &std::path::Path,
        acknowledged: bool,
    ) -> Result<(), DaemonError> {
        if acknowledged {
            return Ok(());
        }
        let (_, report) = self.preflight(path)?;
        let prohibitions = report.structural_prohibitions();
        if !prohibitions.is_empty() {
            // No acknowledgement would help; say what actually stops it.
            return Err(DaemonError::PathNotAllowed(format!(
                "link refused (unsupported link topology): {}. Linked folders cannot be nested, \
                 and no confirmation overrides this; unlink the other folder first",
                prohibitions.join("; ")
            )));
        }
        let warnings = report.warnings();
        if warnings.is_empty() {
            return Ok(());
        }
        Err(DaemonError::Config(format!(
            "link of {} needs its risks acknowledged first: {}. Review them, then confirm and \
             try again",
            path.display(),
            warnings.join("; ")
        )))
    }

    pub(crate) async fn link(&self, command: LinkCommand) -> Result<LinkOutcome, DaemonError> {
        let path_lock = self
            .path_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(command.local_path.clone())
            .or_default()
            .clone();
        let local_path = command.local_path.clone();
        let result = {
            let _serialized = path_lock.lock().await;
            self.link_serialized(command).await
        };
        let mut locks = self.path_locks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // The map's own reference plus this call's: nobody else holds or
        // waits for it, so the entry can go.
        if Arc::strong_count(&path_lock) == 2 {
            locks.remove(&local_path);
        }
        result
    }

    /// A provider-backed link: no directory, so no topology, recovery-area or watcher step. The link
    /// row, the declared root and the enrollment marker commit in one transaction; the only fallible
    /// step after it is advancing the journal row, which has nothing to undo but the commit itself.
    fn link_provider(&self, command: LinkCommand) -> Result<LinkOutcome, DaemonError> {
        let Some(marker) = &command.pending_enrollment else {
            return Err(DaemonError::Config(
                "a provider folder is only created through a journaled enrollment".to_string(),
            ));
        };
        let live = self.repository.live_link_keys_for_group(&command.group_id)?;
        if live.iter().any(|key| key != &command.local_path) {
            return Err(DaemonError::Config(format!(
                "folder group {} already has a link on this device",
                command.group_id
            )));
        }
        if live.iter().any(|key| key == &command.local_path) {
            return Ok(LinkOutcome::AlreadyLinked);
        }
        self.repository.commit_link_with_pending_enrollment(
            &command.local_path,
            &command.group_id,
            marker,
            command.provider.as_ref(),
        )?;
        if !self.repository.mark_enrollment_activation_pending(&marker.operation_id)? {
            return Err(DaemonError::Config(
                "local setup completed but the enrollment operation could not advance to \
                 ActivationPending; remote activation was not attempted"
                    .to_string(),
            ));
        }
        Ok(LinkOutcome::Linked)
    }

    /// [`Self::link`]'s body, run while this path's lock is held.
    async fn link_serialized(&self, command: LinkCommand) -> Result<LinkOutcome, DaemonError> {
        if command.provider.is_some() {
            return self.link_provider(command);
        }
        // A second live root on one group is never acceptable at any
        // confirmation level, because each root's scan tombstones the
        // other's files on every device.
        //
        // `any(|p| p != &command.local_path)` rather than `!is_empty()`:
        // re-linking the SAME folder to the same group is idempotent and
        // must stay allowed -- it is exactly what a `share join` retry does
        // after a failed link's rollback, and (below) a no-op when that
        // link is already running.
        let live_for_group = self.repository.live_link_paths_for_group(&command.group_id)?;
        if live_for_group.iter().any(|p| p != &command.local_path) {
            return Err(DaemonError::Config(format!(
                "folder group {} is already linked at {}; a folder group can only be linked to \
                 one folder on a device -- two would make each folder's scan delete the other's \
                 files on every device. Unlink the other folder first, or link this folder to a \
                 different group",
                command.group_id,
                live_for_group.join(", ")
            )));
        }
        // The same folder, already linked to this group, with a runtime
        // holding it: settle it here, before anything is committed. The
        // watcher refuses a second start for a path it already holds, so a
        // call that got past this point would always fail at start -- and
        // its rollback would then be undoing a row the running link depends
        // on. This applies to an enrollment re-join (`share join` run again)
        // exactly as to a plain `link`: no second pending marker is written
        // for a link that is already live.
        if live_for_group.iter().any(|path| path == &command.local_path)
            && self.watcher.is_registered(&command.local_path)
        {
            if self.watcher.is_ready(&command.local_path) {
                tracing::info!(
                    local_path = %command.local_path,
                    group_id = %command.group_id,
                    "folder is already linked to this group and running; nothing to do"
                );
                return Ok(LinkOutcome::AlreadyLinked);
            }
            // Still `Starting`: that attempt's fallible work has not landed
            // yet and may still fail and roll back, so reporting "already
            // linked" now could claim a link that is about to disappear.
            // Refuse without touching anything instead; a retry once it has
            // settled gets a definite answer.
            return Err(DaemonError::Config(format!(
                "{} is still being linked to folder group {}; wait for that to finish, then \
                 check `yadorilink status`",
                command.local_path, command.group_id
            )));
        }

        // Nested links, and one folder linked to two groups, are an unsupported
        // topology: refused at every confirmation level, because two linked
        // roots over the same files would each treat the other's changes as
        // their own. No confirmation flag is consulted: those only cover risks
        // a user may knowingly accept (a non-empty folder, a cloud-provider
        // folder). Paths are compared resolved and case-folded, so a symlink
        // or a differently-cased spelling is the same folder.
        let existing_links = self.repository.list_link_paths_and_groups()?;
        let conflicts = yadorilink_local_storage::link_preflight::detect_topology_conflicts(
            std::path::Path::new(&command.local_path),
            &command.group_id,
            &existing_links,
        );
        if !conflicts.is_empty() {
            let conflict_summary =
                conflicts.iter().map(|c| c.refusal()).collect::<Vec<_>>().join("; ");
            return Err(DaemonError::PathNotAllowed(format!(
                "link refused (unsupported link topology): {conflict_summary}. Linked folders \
                 cannot be nested or linked twice, and no confirmation overrides this; unlink \
                 the other folder first"
            )));
        }

        // The recovery area of a rebootstrap and the store of the versions it set aside hold
        // the user's own files outside every synced folder; a folder around either, or
        // inside it, would have the sync read them back as new files.
        for kept in
            [crate::device_config::recovery_root(), crate::device_config::recovery_items_root()]
        {
            if crate::device_config::link_overlaps_recovery_area(
                std::path::Path::new(&command.local_path),
                &kept,
            ) {
                return Err(DaemonError::PathNotAllowed(format!(
                    "link refused: {} would contain or lie within the daemon's recovery area \
                     ({}), which keeps what a rebootstrap saves of your changes and is never \
                     synced",
                    command.local_path,
                    kept.display()
                )));
            }
        }

        // From here on the link (and, if `pending_enrollment` was set, its
        // marker) is durably committed. Every caller treats any `Err` this
        // method returns as "nothing was created", so a failure past this
        // point must roll the just-committed row(s) back rather than return
        // `Err` with local state left behind.
        let link_write = match &command.pending_enrollment {
            None => self.repository.commit_plain_link(&command.local_path, &command.group_id)?,
            Some(marker) => self.repository.commit_link_with_pending_enrollment(
                &command.local_path,
                &command.group_id,
                marker,
                None,
            )?,
        };

        if let Err(e) =
            self.watcher.start(&command.local_path, &command.group_id, command.on_demand).await
        {
            // The rollback undoes exactly what the commit above did to the
            // link row -- deletes a row it inserted, restores a row it
            // updated -- never an unconditional delete of whatever row sits
            // at this path: a re-link of a folder that was already linked
            // updated that existing row, and deleting it would destroy the
            // earlier link and its adopted root token.
            //
            // The rollback itself is best-effort against the same SQLite
            // database the commit above just used, so it is expected to
            // succeed in practice -- but it is not guaranteed to (e.g. a
            // concurrent `SQLITE_BUSY`/`SQLITE_LOCKED` that outlasts the
            // pool's own retry budget). A rollback failure must never be
            // silently swallowed: the caller is about to be told the whole
            // link setup failed and to treat nothing as created, so a link/
            // marker that is actually still committed underneath would be a
            // live, reconcile-eligible link this device's own logs are the
            // only record of.
            let rollback_result = match &command.pending_enrollment {
                None => self.repository.undo_plain_link(
                    &command.local_path,
                    &command.group_id,
                    &link_write,
                ),
                Some(marker) => self.repository.rollback_local_setup_to_cancel_pending(
                    &command.local_path,
                    &command.group_id,
                    &link_write,
                    &marker.operation_id,
                    &e.to_string(),
                ),
            };
            return Err(match rollback_result {
                Ok(undone) => {
                    tracing::warn!(
                        error = %e,
                        local_path = %command.local_path,
                        group_id = %command.group_id,
                        undone,
                        "link setup failed after its commit; rolled back this attempt's local \
                         link state"
                    );
                    e
                }
                Err(rollback_err) => {
                    tracing::error!(
                        error = %rollback_err,
                        local_path = %command.local_path,
                        "failed to roll back a link (and its pending-enrollment marker, if any) \
                         after its post-commit setup failed -- this local link may still be \
                         committed even though link setup is being reported as failed"
                    );
                    DaemonError::Config(format!(
                        "link setup failed ({e}), and rolling back the partially-committed local \
                         state also failed -- this device's local link state may now be \
                         inconsistent with what was reported; check the daemon log and run \
                         `yadorilink link list` to verify before retrying"
                    ))
                }
            });
        }

        // Local setup (watcher registration, on-demand config) is confirmed
        // -- ONLY now may the pending-enrollment reconciler attempt remote
        // activation.
        if let Some(marker) = &command.pending_enrollment {
            let activation_ready =
                match self.repository.mark_enrollment_activation_pending(&marker.operation_id) {
                    Ok(ready) => ready,
                    Err(e) => {
                        // The watcher was already registered; this DB-level
                        // failure to record that must not leave it running.
                        self.watcher.stop(&command.local_path).await;
                        return Err(e.into());
                    }
                };
            if !activation_ready {
                // The row is no longer `LocalSetupPending` -- most likely a
                // concurrent recovery sweep rolled it back to
                // `CancelPending` after this row sat past its age-gate. The
                // local setup that just finished is NOT rolled back here on
                // the theory it may have raced that rollback and lost --
                // rolling it back ourselves risks deleting a link the
                // reconciler's own rollback already deleted (a double-
                // delete is harmless) or, worse, one it never touched
                // (which would then be a wrongly-discarded, fully live
                // link). Reporting failure and refusing to attempt
                // activation is the one response safe under either
                // interpretation. The in-memory watcher IS stopped here
                // regardless.
                self.watcher.stop(&command.local_path).await;
                return Err(DaemonError::Config(
                    "local setup completed but the enrollment operation could not advance to \
                     ActivationPending; remote activation was not attempted -- check `yadorilink \
                     link list` and the daemon log before retrying"
                        .to_string(),
                ));
            }
        }

        Ok(LinkOutcome::Linked)
    }
}
