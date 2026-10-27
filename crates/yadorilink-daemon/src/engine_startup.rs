//! The startup phases the daemon binary and the embedded host share.
//!
//! Each function is one step of the start sequence that both composition roots
//! (`app::run` and `embedded_host`) perform in the same order, so the engine is
//! brought up by the same code on every platform. Process-model concerns (locks,
//! sockets, signals, supervision of essential tasks) stay with the callers.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_local_storage::SegmentBlockStore;

use crate::application::ApplicationServices;
use crate::daemon_state::DaemonState;
use crate::maintenance::recovery::RecoveryJob;
use crate::replica_coordinator::ReplicaCoordinator;

/// Uploads of undecided operations are retained (never aged out): report them, and sweep the
/// unclaimed finished copies now that the journal is known.
#[cfg(any(windows, unix))]
fn report_retained_uploads(
    state: &Arc<crate::daemon_state::DaemonState>,
    handoff: &Arc<crate::provider_handoff::HandoffRoot>,
) {
    let repo = state.replica_coordinator.provider_repository();
    let Ok(names) = repo.pending_ingest_names() else { return };
    handoff.sweep_ingest(Some(&names));
    if names.is_empty() {
        return;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    let (count, oldest_ms) = repo.undecided_uploads(now_ms).unwrap_or((0, 0));
    let (orphans, orphan_oldest_ms) = repo.orphaned_uploads(now_ms).unwrap_or((0, 0));
    tracing::warn!(
        count,
        oldest_ms,
        orphans,
        orphan_oldest_ms,
        "uploads of undecided operations are retained"
    );
}

/// How often `EnrollmentRecoveryService::reconcile_once` re-runs after its first pass at
/// startup. A few minutes: far below `daemon_state`'s hour-scale
/// retention-expiry sweep (retrying a coordination-plane call is cheap, so
/// there's no reason to wait that long), but well above its sub-two-minute
/// materialization-repair/disk-reconcile cadences (this is a crash-recovery
/// backstop for a killed CLI process, not a live sync path racing user-visible
/// staleness).
const PENDING_ENROLLMENT_RECONCILE_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// The opened block store and replica database.
pub(crate) struct OpenedData {
    pub(crate) block_store: Arc<SegmentBlockStore>,
    pub(crate) replica_coordinator: Arc<ReplicaCoordinator>,
}

/// Opens the block store and the replica database, refusing a lost database and recording
/// the refusal for `status` when either cannot be used.
///
/// `_locks` is the proof the block store's recovery needs: it truncates and removes bytes a
/// live writer may have staged, so it runs only while this process holds the data area's
/// `DataResourceLocks` (the daemon and the embedded engine both take them first). Requiring
/// the value keeps a host from opening the store without that exclusion.
pub(crate) fn open_data(
    _locks: &yadorilink_local_storage::resource_lock::DataResourceLocks,
    dir: &Path,
    block_store_root: &Path,
    sync_db_path: &Path,
    tuning: &crate::engine_tuning::EngineTuning,
) -> anyhow::Result<OpenedData> {
    // A severe-error hook for the
    // two fallible startup calls that would otherwise abort startup before
    // `DaemonState` (and therefore `state.reporting`) exists — opens a
    // throwaway `ReportingStorage` over the same config directory rather
    // than waiting for `DaemonState::new`, since a failure here is exactly
    // the kind of thing a maintainer would want a local candidate for.
    // Opening a missing replica database creates an empty one, and an empty
    // database references no blocks: the first idle sweep would then delete
    // every block that survived. Decide, before either is opened, whether a
    // missing database is a new install or a lost one.
    let surviving_blocks = SegmentBlockStore::holds_segment_data(block_store_root)?
        .then_some("the block store still holds data");
    let block_store;
    let replica_coordinator;
    {
        let opened = (|| -> anyhow::Result<_> {
            yadorilink_sqlite_runtime::refuse_lost_database(sync_db_path, surviving_blocks)?;
            let block_store = Arc::new(SegmentBlockStore::open_process_locked_with(
                block_store_root,
                tuning.group_commit,
            )?);
            let coordinator =
                Arc::new(ReplicaCoordinator::open_with(sync_db_path, tuning.clone())?);
            Ok((block_store, coordinator))
        })();
        match opened {
            Ok((store, coordinator)) => {
                block_store = store;
                replica_coordinator = coordinator;
                if let Err(e) = yadorilink_local_storage::startup_refusal::clear(dir) {
                    tracing::warn!(error = %e, "could not clear the recorded startup refusal");
                }
            }
            Err(e) => {
                record_startup_error_best_effort(
                    dir,
                    "daemon_startup",
                    "sync-state",
                    e.to_string(),
                );
                let refusal = data_refusal(&e, sync_db_path, block_store_root);
                tracing::error!("{}", refusal.message());
                if let Err(write_error) =
                    yadorilink_local_storage::startup_refusal::record(dir, &refusal)
                {
                    tracing::warn!(error = %write_error, "could not record the startup refusal");
                }
                return Err(e);
            }
        }
    }
    Ok(OpenedData { block_store, replica_coordinator })
}

/// Settles what a crash may have left in the opened database: stale transient states,
/// interrupted structural intents and unfinished rewinds. Run once, before anything else
/// touches the data.
pub(crate) fn settle_data(
    replica_coordinator: &Arc<ReplicaCoordinator>,
    sync_db_path: &Path,
) -> anyhow::Result<()> {
    yadorilink_sqlite_runtime::record_database_created(sync_db_path)?;

    // Both resets run (each its own transaction) before either result is
    // looked at, and fail independently.
    let (stale_hydrating, stale_evicting) = replica_coordinator.reset_stale_transient_states();
    match stale_hydrating {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "reset stale Hydrating rows to Placeholder on startup"),
        Err(e) => tracing::warn!(error = %e, "failed to reset stale Hydrating rows on startup"),
    }

    // Recover any file left permanently stuck `Evicting` by a crash
    // mid-eviction (before its placeholder commit) — otherwise nothing
    // ever reconciles it and the file is wedged.
    match stale_evicting {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "reset stale Evicting rows to Placeholder on startup"),
        Err(e) => tracing::warn!(error = %e, "failed to reset stale Evicting rows on startup"),
    }

    // A structural `mkdir` interrupted between its intent and its
    // completion: at startup nothing is in flight, so every pending intent
    // is dropped (never completed). The directory it may have created is
    // kept and is of unknown origin -- never removed, never authored.
    match replica_coordinator.drop_interrupted_structural_intents_at_startup() {
        Ok(dropped) if dropped.is_empty() => {}
        Ok(dropped) => tracing::info!(
            count = dropped.len(),
            "dropped interrupted structural-directory intents on startup"
        ),
        Err(e) => {
            tracing::warn!(error = %e, "failed to drop interrupted structural-directory intents")
        }
    }

    // A folder rewind is never resumed. Nothing can have started one in this
    // process yet, so every unfinished run belongs to a process that is gone
    // and is settled from its journal row alone: one that committed a chunk
    // needs a fresh preview, any other changed nothing and failed.
    match replica_coordinator.rewind_run_repository().interrupt_unfinished_runs() {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "settled interrupted folder rewinds on startup"),
        Err(e) => tracing::warn!(error = %e, "failed to settle interrupted folder rewinds"),
    }
    Ok(())
}

/// Resumes watching every previously-linked folder, as listed by
/// `link_repository().list_links()` (read once at startup, failing the start if the table cannot
/// be read).
pub(crate) fn resume_links(
    state: &Arc<DaemonState>,
    links: &[yadorilink_replica_domain::session_state::FolderLink],
) {
    // Resume watching every previously-linked folder (local
    // state persistence across restarts: links survive, and their
    // watchers are simply restarted). An orphaned link's watcher is never
    // restarted here -- it was stopped the moment `pending_enrollment::
    // reconcile` marked it orphaned, and staying stopped across restarts is
    // exactly what "no longer a live sync target" means; its on-disk files
    // are untouched either way.
    let link_runtime_controller =
        crate::adapters::runtime::link_runtime_controller::LinkRuntimeController::new(
            state.clone(),
        );
    for link in links {
        if link.orphaned {
            continue;
        }
        // `LinkRuntimeController::start_inner` runs this link's own startup
        // materialization repair itself (right after acquiring its
        // `SyncRootLock`) and ANDs its own `emit_tombstones` gate down to
        // `false` if repair fails for THIS link -- fail-closed: a
        // crash-mid-materialize that repair could not disambiguate this
        // boot must not be misread as an offline delete and propagated
        // group-wide. `true` here is just this caller's own "no other
        // reason to suppress" default (mirroring `LinkRuntimeController::start`'s
        // identical hardcoded `true`); the additive-scan flag a two-live-
        // roots recovery arms on the survivor is similarly read and ANDed
        // in by `start_inner` itself, not by this caller.
        // A provider link has no directory to watch.
        let Some(folder) = link.folder_path() else { continue };
        if let Err(e) = link_runtime_controller.start_gating_tombstones(
            folder.to_string(),
            link.group_id.clone(),
            true,
        ) {
            // Continuing is deliberate: one unwatchable folder must not stop the
            // daemon for every other link. It is only safe because
            // `start_inner` arms this group's startup gate before any
            // fallible step, so the failure leaves the gate Failed and peer apply
            // for this group defers rather than overwriting un-indexed local
            // content. Error, not warn: this folder syncs nothing until fixed --
            // except a folder whose disk is not there yet, which starts by
            // itself once it is (`LinkVolumeJob`).
            if state.links.is_awaiting_volume(folder) {
                tracing::warn!(error = %e, local_path = %folder, "linked folder is not on its volume yet; it starts syncing once the volume is mounted");
            } else {
                tracing::error!(error = %e, local_path = %folder, "failed to resume watching linked folder; this folder will not sync until startup succeeds for it");
            }
        }
    }
}

/// What [`build_engine`] builds.
pub(crate) struct BuiltEngine {
    pub(crate) state: Arc<DaemonState>,
    pub(crate) application: Arc<ApplicationServices>,
    pub(crate) recovery_job: Arc<RecoveryJob>,
}

/// Builds the daemon state and the application services over it, starts maintenance and
/// wires the device signing key.
pub(crate) fn build_engine(
    config_dir: &Path,
    device_id: String,
    replica_coordinator: &Arc<ReplicaCoordinator>,
    block_store: &Arc<SegmentBlockStore>,
    registered_identity: Option<&yadorilink_transport::DeviceSigningKeyPair>,
) -> BuiltEngine {
    // Construction (`DaemonState::build`) and starting `MaintenanceCoordinator`
    // are two explicit steps here, not the single `DaemonState::new` every
    // test call site uses -- this composition root is the one place that
    // needs to sequence maintenance startup relative to its OWN later setup
    // (headroom enforcement, custody confirmer, signing key), not just get a
    // fully-running `DaemonState` back. Starting maintenance immediately
    // after `build` (before any of that later setup) preserves the exact
    // ordering `DaemonState::new` always had -- this is not a behavior
    // change, just the same two steps made explicit and separately owned.
    let state = DaemonState::build_in(
        config_dir.to_path_buf(),
        device_id.clone(),
        replica_coordinator.clone(),
        block_store.clone(),
    );
    // The one `ApplicationServices` for this daemon: shared by the recovery
    // job and the control socket. It reads `state` lazily, so building it
    // before the setup below is equivalent to building it after.
    let application = crate::adapters::build_application_services(state.clone());
    let recovery_job = crate::maintenance_coordinator::start(&state, Some(&application));
    // Only the real `yadorilink-daemon`
    // binary itself opts into disk-headroom enforcement — see
    // `DaemonState::enable_disk_headroom_enforcement`'s doc comment for why
    // this is not done inside `DaemonState::new` (which every test in this
    // crate also goes through).
    state.enable_disk_headroom_enforcement();

    // Wire the generation-stamped peer custody confirmer. Physical cache
    // reclamation remains disabled until the responder can persist a custody
    // lease as a GC root; the real daemon keeps the exact-version protocol
    // available for diagnostics and that future lease flow.
    state.install_p2p_custody_confirmer();
    // Releases the custody leases this device asked peers to keep and no
    // longer depends on. Runs after the stale-`Evicting` reset above, so every
    // row is judged against settled state.
    crate::custody_holds::spawn_custody_hold_reconciler(&state);

    // Wire this device's change-history signing key once, so linked folders
    // emit signed changes. Only for a registered device (an unregistered one
    // has no identity to attribute changes to).
    if let Some(signing) = registered_identity {
        state.set_device_signing_key(signing.signing.clone());
    }

    BuiltEngine { state, application, recovery_job }
}

/// Builds the provider side (the shell context) and starts its background tasks.
pub(crate) fn start_provider(
    state: &Arc<DaemonState>,
    control_context: &crate::control_context::ControlContext,
    provider_temp_root: Option<PathBuf>,
) -> Arc<crate::shell_context::ShellContext> {
    // The shell extension's hydrate/pin/evict share the control socket's
    // `ApplicationServices` instance rather than reaching `DaemonState`.
    #[cfg(any(windows, unix))]
    let shell_context = std::sync::Arc::new(
        crate::shell_context::ShellContext::new(control_context, state).with_handoff_slot(
            crate::provider_handoff::HandoffSlot::lazy(
                // Resolved again on every access that finds no root: the app group container only
                // exists once the host app has run, which may be after the daemon started.
                // An explicitly configured path (`YADORILINK_PROVIDER_TEMP_ROOT`); otherwise the container the
                // host app reports through the shell socket is adopted (the daemon knows no path of its own).
                Arc::new(move || provider_temp_root.clone()),
                {
                    // Weak: the slot is reachable from the state (through the content probe),
                    // so a strong reference here would keep the state alive for ever.
                    let state = Arc::downgrade(state);
                    Arc::new(move |handoff| {
                        if let Some(state) = state.upgrade() {
                            report_retained_uploads(&state, handoff);
                        }
                    })
                },
            ),
        ),
    );
    // Open it now when it can be (this also reports retained uploads at start-up).
    #[cfg(any(windows, unix))]
    let _ = shell_context.handoff.get();

    #[cfg(any(windows, unix))]
    {
        let context = shell_context.clone();
        crate::supervise::spawn_logged("provider-prefetch", async move {
            crate::provider_prefetch::run(context).await;
            Ok(())
        });
    }

    #[cfg(any(windows, unix))]
    {
        let auto = shell_context.auto_reclaim.clone();
        crate::supervise::spawn_logged("provider-auto-reclaim", async move {
            crate::provider_auto_reclaim::run(auto).await;
            Ok(())
        });
    }

    // The provider projector: the only consumer of a provider group's projection obligations.
    {
        let state = state.clone();
        let publication = shell_context.publication.clone();
        crate::supervise::spawn_logged(
            "provider-projector",
            crate::provider_projector::run(state, publication),
        );
    }

    shell_context
}

/// Records the coordination client configuration and starts the best-effort tasks that keep
/// the coordination plane's view of this device current and finish interrupted enrollments.
pub(crate) fn spawn_coordination_tasks(
    state: &Arc<DaemonState>,
    recovery_job: &Arc<RecoveryJob>,
    cfg: &crate::device_config::DeviceConfig,
    auth: &yadorilink_fapi_client::CoordinationAuth,
) {
    // Best-effort, production-only coordination-plane wiring, spawned
    // before the orchestrator moves `cfg`/`access_token` into its
    // config: keeps the coordination plane's view of this device's iroh
    // address current.
    let addr = cfg.coordination_addr.clone();
    let token = auth.clone();
    let device_id = cfg.device_id.clone();
    let own_address = state.peer_connectivity.local_substrate_reachability.clone();

    // Recorded once, up front, so any control-socket request the
    // CLI issues from this point on (currently only the
    // full-replica-handoff lease request) can make its own
    // coordination-plane calls without needing `coordination_addr`/
    // the credential threaded through as extra parameters -- see
    // `DaemonState::coordination_client_config`'s doc comment.
    state.set_coordination_client_config(addr.clone(), token.clone());

    // Crash-safe create/join enrollment (see
    // `EnrollmentRecoveryService`'s own module doc), run through
    // the daemon's one `RecoveryJob`: finish
    // confirming (or, failing that, cancel) any local link this
    // device committed whose matching coordination-plane
    // activation never got confirmed -- the CLI process that
    // would have done so was killed first, or its own
    // confirmation call never reached the daemon. Runs once
    // immediately (covering a marker left over from before this
    // startup) and then on a fixed interval, so a marker left
    // behind by a killed CLI process is retried without needing a
    // daemon restart to notice it. Best-effort and self-healing: a
    // sweep that can't reach the coordination plane leaves its
    // marker in place for the next one.
    {
        let recovery_job = recovery_job.clone();
        crate::supervise::spawn_logged("pending-enrollment-reconcile", async move {
            let mut interval = tokio::time::interval(PENDING_ENROLLMENT_RECONCILE_SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                recovery_job.run_enrollment_recovery_once().await;
            }
        });
    }

    crate::supervise::spawn_logged("address-report", async move {
        crate::peer_connectivity_runtime::report_own_address(addr, token, device_id, own_address)
            .await;
        Ok(())
    });
}

/// What `status` shows while no daemon answers because the data on disk cannot
/// be opened. Only data this build cannot use is answered with the destructive
/// reset (there is no migration before release); a newer database is answered
/// by running the newer build, and any other failure (permissions, a full disk)
/// is only reported, because the data is not known to be unusable.
pub(crate) fn data_refusal(
    error: &anyhow::Error,
    sync_db_path: &std::path::Path,
    block_store_root: &std::path::Path,
) -> yadorilink_local_storage::startup_refusal::StartupRefusal {
    use yadorilink_local_storage::startup_refusal::{StartOver, StartupRefusal};
    use yadorilink_sqlite_runtime::{DatabaseError, LostDatabaseError};
    let head = format!("The background service cannot open the data on disk: {error}");
    let unusable =
        matches!(error.downcast_ref::<DatabaseError>(), Some(DatabaseError::CorruptSchema(_)))
            || matches!(
                error.downcast_ref::<LostDatabaseError>(),
                Some(
                    LostDatabaseError::MarkerWithoutDatabase { .. }
                        | LostDatabaseError::OtherDataWithoutDatabase { .. }
                )
            );
    if unusable {
        StartupRefusal {
            reason: head,
            start_over: Some(StartOver {
                sync_db: sync_db_path.to_path_buf(),
                marker: yadorilink_sqlite_runtime::creation_marker_path(sync_db_path),
                block_store: block_store_root.to_path_buf(),
            }),
        }
    } else if matches!(
        error.downcast_ref::<DatabaseError>(),
        Some(DatabaseError::UnsupportedSchemaDowngrade { .. })
    ) {
        StartupRefusal::plain(format!(
            "{head}\nIt was written by a newer build: run that build or a newer one."
        ))
    } else {
        StartupRefusal::plain(head)
    }
}

/// Records a severe-error
/// candidate for a startup failure that happens before `DaemonState`
/// exists. Opens its own short-lived `ReportingStorage` handle (cheap —
/// see that type's doc comment on not writing anything just by opening)
/// rather than restructuring startup to build `DaemonState` earlier.
fn record_startup_error_best_effort(dir: &Path, category: &str, subsystem: &str, message: String) {
    let storage = crate::reporting::ReportingStorage::open(crate::reporting::reporting_dir_in(dir));
    crate::reporting::hooks::record_severe_error(&storage, category, subsystem, vec![message]);
}

/// Loads this device's identity config, refusing to start on an unusable one. Run before
/// anything is created or migrated: a newer build may have written the data beside it.
pub(crate) fn load_device_config(
    dir: &Path,
) -> anyhow::Result<Option<crate::device_config::DeviceConfig>> {
    // Validate this device's identity config before any data-plane startup
    // work: everything below this point mutates persistent state. The resource
    // locks create the block-store root and the database's parent directory,
    // `SyncState::open` runs schema migrations, and the repair pass rewrites
    // files inside every linked folder. An unsupported downgrade is precisely
    // the case where none of that may happen — a newer build wrote this
    // config, so a newer database schema is likely on disk beside it, and
    // migrating or repairing that with this build's older understanding is how
    // a downgrade turns into permanent damage. Refusing here is free: `load`
    // reads a single file and depends on neither the database nor the block
    // store, so the only ordering constraint is the instance lock above, which
    // still comes first so a daemon that does not own this config dir never
    // reports on its contents.
    match crate::device_config::load_in(dir) {
        // Genuine absence (`Ok(None)`) legitimately means "not registered
        // yet" and is the only condition allowed to mean that.
        Ok(cfg) => Ok(cfg),
        // Each failure names its own condition and its own remedy. They must
        // not collapse into one message: the remedy for a corrupt file
        // ("remove it and register again") is destructive when applied to a
        // downgrade, where the device *is* registered and re-registering
        // mints a second identity for one physical device that nothing can
        // merge back afterwards (see `DeviceConfigError`'s doc comment).
        // Matched exhaustively with no catch-all arm, so a variant added
        // later must state its own case here instead of silently inheriting
        // a wrong one.
        Err(
            e @ (crate::device_config::DeviceConfigError::UnsupportedConfigDowngrade { .. }
            | crate::device_config::DeviceConfigError::StaleConfigVersion { .. }),
        ) => Err(anyhow::anyhow!(
            "refusing to start: {e}. Nothing on disk has been modified, and this device is \
                 still registered: do not delete device.json and do not register this device \
                 again, which would register a second identity for this one device."
        )),
        Err(e @ crate::device_config::DeviceConfigError::Read { .. }) => Err(anyhow::anyhow!(
            "refusing to start: {e}. device.json exists but could not be read, so this \
                 device's registration is unknown rather than absent -- usually a permissions \
                 problem, and often transient. Restore access to the file and start again rather \
                 than registering this device again."
        )),
        Err(e @ crate::device_config::DeviceConfigError::Corrupt { .. }) => Err(anyhow::anyhow!(
            "refusing to start: {e}. Restore device.json from a backup if one exists. \
                 Registering this device again registers a new identity for this \
                 device rather than recovering the old one, and changes already made under the \
                 previous device id stay attributed to it."
        )),
    }
}

/// Stops generating local changes and drains what is in flight, before the sessions that
/// would otherwise cut it off are torn down.
pub(crate) async fn quiesce(state: &Arc<DaemonState>) {
    // Stop generating new local changes first: shut down every link's
    // runtime (watcher/executor/repair/dirty-journal tasks, then the
    // operation fence) before anything else, so nothing new gets queued
    // while the rest of shutdown runs. `LinkRuntime::shutdown`, not
    // `abort_tasks` -- see that method's own doc for why: this function
    // does not exit the process immediately afterward (it still drains
    // in-flight broadcasts, up to 3s, and checkpoints SQLite), so a
    // still-running scan/flush/backstop operation must be genuinely
    // finished, not merely asked to stop, before its root lock is allowed
    // to drop. Every link shuts down concurrently, not one at a time --
    // each shutdown's own wait is independent of every other link's.
    let link_runtimes = state.links.drain_for_shutdown();
    futures_util::future::join_all(link_runtimes.into_iter().map(|drained| async move {
        let (local_path, runtime) = match drained {
            crate::link_registry::DrainedLink::Ready { local_path, runtime } => {
                (local_path, runtime)
            }
            // A start attempt is genuinely in flight for this path at the
            // moment of shutdown -- rare, but not impossible. There is no
            // `LinkRuntime` to shut down yet; the in-progress `start_link_
            // watch_inner` call runs to completion (or fails) on its own,
            // independent of this drained map entry, and the process is
            // about to exit regardless.
            crate::link_registry::DrainedLink::Starting { local_path } => {
                tracing::debug!(
                    local_path,
                    "graceful_shutdown: a start attempt was still in flight for this link; \
                     nothing to shut down yet"
                );
                return;
            }
        };
        tracing::debug!(local_path, "shutting down link runtime");
        // `link_runtimes` was the only place this `Arc` was ever cloned
        // from, so removing it there (via `drain` above) leaves exactly
        // one strong reference: this one.
        //
        // Admission is closed first, so an operation some other holder starts
        // from here on is refused whether or not the unwrap below succeeds.
        runtime.root_lease().begin_stopping();
        match Arc::try_unwrap(runtime) {
            Ok(runtime) => runtime.shutdown().await,
            Err(shared) => {
                tracing::error!(
                    local_path,
                    refs = Arc::strong_count(&shared),
                    "graceful_shutdown: Arc<LinkRuntime> unexpectedly still shared after \
                     removal from link_runtimes; draining it in place"
                );
                shared.drain_shared().await;
            }
        }
    }))
    .await;

    // Drain in-flight broadcasts (bounded — see
    // `DaemonState::wait_for_broadcasts_to_drain`'s doc comment) before
    // tearing down the sessions that would otherwise cut them off.
    state.wait_for_broadcasts_to_drain(Duration::from_secs(3)).await;
}

/// Closes the substrate endpoint so peers are told this device is going away.
pub(crate) async fn close_substrate(state: &Arc<DaemonState>) {
    // Close the substrate endpoint while the tasks that serve it are still
    // running, so peers are TOLD this device is going away instead of being
    // left to discover it. A peer that is not told keeps its connection, and
    // iroh sends every datagram for a remote down that connection's selected
    // path -- including the handshake of a new dial -- so until that dead
    // connection times out on its own the peer cannot reach this device
    // again, not even after it comes back. `SubstrateNode::shutdown`'s own
    // doc comment says this lifecycle is owned explicitly for exactly that
    // reason; nothing was calling it.
    if let Some(driver) = state.peer_session_driver() {
        driver.stack().shutdown().await;
    }
}

/// Leaves both databases standing alone on disk once nothing writes any more.
pub(crate) async fn checkpoint_data(state: &Arc<DaemonState>) {
    // Nothing writes any more: leave both databases standing alone on disk. Best effort, since
    // an unfolded log is still complete and is replayed at the next open.
    if let Err(detail) =
        crate::adapters::runtime::safe_stop::checkpoint(state, Duration::from_secs(10)).await
    {
        tracing::warn!(detail, "could not checkpoint the databases at shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::data_refusal;

    /// Only data this build cannot use is answered with the destructive reset: a
    /// failure that says nothing about the data (a permission error) is only reported.
    #[test]
    fn a_failure_that_says_nothing_about_the_data_does_not_advise_deleting_it() {
        let io = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        let refusal =
            data_refusal(&io, std::path::Path::new("/d/db"), std::path::Path::new("/d/blocks"));
        assert!(refusal.start_over.is_none());
        let message = refusal.message();
        assert!(
            !message.contains("delete") && !message.contains("remove this device"),
            "{message}"
        );
        let newer = anyhow::Error::new(
            yadorilink_sqlite_runtime::DatabaseError::UnsupportedSchemaDowngrade {
                on_disk_version: 999,
                supported_version: 1,
            },
        );
        let refusal =
            data_refusal(&newer, std::path::Path::new("/d/db"), std::path::Path::new("/d/blocks"));
        let message = refusal.message();
        assert!(message.contains("newer build") && !message.contains("delete"), "{message}");
    }
}
