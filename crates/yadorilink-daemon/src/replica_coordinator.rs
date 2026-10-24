//! `ReplicaCoordinator` is the daemon's composition-root type: it owns the
//! per-table SQLite repositories, the shared connection pool, the path-lock
//! and startup-readiness registries, and the wake channels that drive the
//! materialization/retirement/hazard-recheck loops.
//!
//! # Field ownership
//!
//! Every field here is built fresh in [`ReplicaCoordinator::from_database`]
//! against one shared `Arc<SyncDatabase>` -- never open a second,
//! independent `SyncDatabase` against the same on-disk file, which would
//! split the in-process writer-serialization gate across two connection
//! pools and defeat the mutual exclusion it exists to provide. Callers that
//! need more than one `ReplicaCoordinator` over the same database (for
//! example multiple test fixtures) must share one `Arc<SyncDatabase>` and
//! pass it to `from_database` rather than opening the file twice.
//!
//! # Port impls
//!
//! `ReplicaCoordinator` implements the storage ports the replica/peer
//! session engine depends on. `RootVerificationStatePort` is implemented
//! directly below; `MaterializationExecutionPort` is a large, mechanical
//! set of delegate methods and lives in its own submodule
//! (`materialization_execution`). Custody-verified block reclamation is an
//! inherent operation, in `block_reclamation`. The
//! replica-state operations the local convergence executor drives are
//! inherent methods, in `peer_replica_state`. The materialization-semantic
//! compositions a lane used to assemble from those raw primitives (intent,
//! fence, state, held, proof, placeholder identity) are owner operations,
//! in `materialization_owner`.

mod block_reclamation;
pub mod engine_ports;
pub mod local_commit;
mod local_mutation;
mod materialization_execution;
mod materialization_owner;
#[cfg(test)]
pub(crate) use materialization_owner::plain_file_columns;
pub(crate) use materialization_owner::{
    ContentWriteClose, ContentWriteCloseItem, OwnedContentWriteOpen,
};
mod peer_replica_state;

// Test-only: lets `gc.rs`/`hydration.rs`'s own unit tests reach
// `materialization_execution`'s Windows-native-dehydrate bypass without
// that private submodule itself becoming `pub(crate)` -- see that
// function's own doc comment. Plain `cfg(test)`, not `any(test, feature =
// "test-support"))]`: the function it re-exports is itself `cfg(test)`-only
// (no caller outside this crate's own unit tests needs it), so gating the
// re-export any wider would just be an unused `pub(crate) use` in a build
// that has `test-support` on but `cfg(test)` off.
#[cfg(test)]
pub(crate) use materialization_execution::set_test_windows_dehydrate_confirmed_for_path;
// Test-only: `hydration.rs`'s unit tests arm the access-hydration guard
// directly, without its entry CAS, to simulate an attempt in flight.
#[cfg(test)]
pub(crate) use materialization_owner::HydrationAttempt;
// Test-only: the ordinary-batch directory-lane tests age an intent past it.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::recovery_snapshot::RecoverySnapshotReader;
use crate::sync_error::SyncError;
use crate::sync_runtime::group_wake::GroupWake;
use crate::sync_runtime::materialization_wake::MaterializationWake;
use crate::sync_runtime::path_locks::PathLockRegistry;
use crate::sync_runtime::schema::map_replica_schema_error;
use crate::sync_runtime::startup_readiness::StartupReadinessRegistry;
use yadorilink_replica_domain::file::{FileRecord, FileVersion};
use yadorilink_replica_domain::local_op::PolicyUnavailable;
use yadorilink_replica_domain::session_state::RestoreOperation;
use yadorilink_replica_domain::session_state::StartupFailed;
use yadorilink_root_authority::error::RootAuthorityError;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::RootVerificationStatePort;
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;
use yadorilink_sync_sqlite::native_rebootstrap::CaptureAuthority;

/// Resolves this device's current verified policy_head for a group, or
/// `Err(PolicyUnavailable)` when this device's own policy view for the
/// group is not currently trustworthy (stale/invalid verification, or the
/// group has not resolved yet). NOT a writer-authorization decision --
/// under `AuthorizationCheckpoint` admission, writer authorization happens only at
/// checkpoint issuance; local emission (offline authoring) is always
/// available to any device regardless of writer role, so this gate exists
/// purely to avoid emitting against a policy view this device cannot
/// currently vouch for.
pub(crate) type LocalPolicyHeadProvider =
    dyn Fn(&str) -> Result<[u8; 32], PolicyUnavailable> + Send + Sync + 'static;

/// The daemon's composition-root state: SQLite repositories, connection
/// pool, and the registries/wake channels used to coordinate concurrent
/// access to them. See the module doc comment above for field-ownership
/// invariants.
pub struct ReplicaCoordinator {
    database: Arc<SyncDatabase>,
    sqlite: Arc<yadorilink_sync_sqlite::SqliteSyncStore>,
    link_repository: yadorilink_sync_sqlite::link::LinkRepository,
    provider_repository: yadorilink_sync_sqlite::provider::ProviderRepository,
    enrollment_repository: yadorilink_sync_sqlite::enrollment::EnrollmentRepository,
    file_index_repository: yadorilink_sync_sqlite::file_index::FileIndexRepository,
    materialization_state_repository: yadorilink_sync_sqlite::MaterializationStateRepository,
    materialization_intent_repository: yadorilink_sync_sqlite::MaterializationIntentRepository,
    temp_releases: Arc<yadorilink_sync_sqlite::TempReleaseQueue>,
    policy_watermark_repository: yadorilink_sync_sqlite::PolicyWatermarkRepository,
    offline_peer_authorization_repository:
        yadorilink_sync_sqlite::OfflinePeerAuthorizationRepository,
    offline_group_policy_log_repository: yadorilink_sync_sqlite::OfflineGroupPolicyLogRepository,
    dirty_path_repository: yadorilink_sync_sqlite::DirtyPathRepository,
    paused_item_repository: yadorilink_sync_sqlite::PausedItemRepository,
    pinned_item_repository: yadorilink_sync_sqlite::PinnedItemRepository,
    held_path_repository: yadorilink_sync_sqlite::HeldPathRepository,
    restore_operation_repository: yadorilink_sync_sqlite::RestoreOperationRepository,
    rewind_run_repository: yadorilink_sync_sqlite::RewindRunRepository,
    /// Groups whose retention expiry is held off (see [`Self::pause_retention`]).
    retention_pauses: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    handoff_lease_repository: yadorilink_sync_sqlite::HandoffLeaseRepository,
    remote_custody_lease_repository: yadorilink_sync_sqlite::RemoteCustodyLeaseRepository,
    remote_custody_hold_repository: yadorilink_sync_sqlite::RemoteCustodyHoldRepository,
    role_loss_operation_repository: yadorilink_sync_sqlite::RoleLossOperationRepository,
    membership_operation_repository: yadorilink_sync_sqlite::MembershipOperationRepository,
    recovery_snapshot_reader: RecoverySnapshotReader,
    /// Per-`(group_id, path)` locks serializing local-change indexing
    /// against peer reconciliation for the same path (`crate::sync_runtime::
    /// path_locks`).
    path_lock_registry: Arc<PathLockRegistry>,
    /// Orders the creation of new references to stored blocks (writes,
    /// hydration, custody leases) against physical block deletion. Owned here,
    /// next to the index every live set is read from.
    block_liveness_gate: yadorilink_filesystem_sync::block_liveness::BlockLivenessGate,
    /// Groups this device is handing its custody leases off in: while one is
    /// listed it takes no new lease for it.
    custody_closing: crate::custody_handoff::CustodyClosing,
    /// Wakes the custody-hold reconciler: set when a path settled in a way
    /// that may make a hold obsolete (see `DaemonState::nudge_custody_hold_reconciler`).
    custody_hold_wake: Arc<tokio::sync::Notify>,
    /// Tracks per-group startup readiness so peer-apply (and other
    /// post-startup mutators) can wait until the group's startup
    /// reconciliation has published its results before touching that
    /// group's paths (`crate::sync_runtime::startup_readiness`).
    startup_readiness: Arc<StartupReadinessRegistry>,
    local_policy_head_provider: Mutex<Option<Arc<LocalPolicyHeadProvider>>>,
    /// This replica's author identity, opened when the device's signing key
    /// is wired (see [`Self::open_local_author`]).
    local_author: Mutex<Option<Arc<crate::author_identity::ReplicaAuthor>>>,
    /// The engine's tuning and measurement settings, given at construction (nothing reads the
    /// process environment for them).
    tuning: Arc<crate::engine_tuning::EngineTuning>,
    /// Concurrent receive file assemblies of this engine, sized by the tuning.
    receive_write_gate: Arc<tokio::sync::Semaphore>,
    /// Set while the author identity is refused because the database was
    /// restored or copied (`install_witness`); what status reports.
    database_restored: Mutex<Option<crate::install_witness::Restored>>,
    /// Set while the author identity cannot be opened for any other reason (an installation
    /// witness that cannot be recorded, an unreadable sidecar, a database error): what status
    /// reports, so a device that signs nothing is not shown as healthy.
    author_unavailable: Mutex<bool>,
    /// The groups whose rebootstrap is running its one final capture pass, with the capability
    /// the pass authors under. Present only while the pass runs.
    capture_passes: Mutex<std::collections::HashMap<String, Arc<CaptureAuthority>>>,
    root_adoption_lock: Mutex<()>,
    /// Test-only observation and injection seam -- see
    /// `test_observers`'s own module doc. `#[cfg(test)]`, so neither the
    /// field nor anything that touches it exists in a production build.
    #[cfg(test)]
    pub(crate) test_observers: crate::replica_coordinator::test_observers::TestObservers,
    materialization_wake: MaterializationWake,
    /// Per-group dirty/generation wake driving `HazardHeld` liveness: a held
    /// path has no re-arm event of its own when the sibling that caused its
    /// hold changes, so the "native frontier advanced or a materialization
    /// job completed" wake points trigger a re-check sweep instead.
    hazard_recheck_wake: GroupWake,
    /// Raised when a local edit that could not be authored was held for
    /// reconciliation: every link's live repair pass, which reconciles
    /// holds, runs now rather than at its next interval. A generation
    /// counter, not a `Notify`: a pass that is mid-run when a hold lands
    /// sees the new generation as soon as it waits again, so no wake is
    /// lost.
    held_path_wake: tokio::sync::watch::Sender<u64>,
}

/// Holds a group's final capture pass open: while it lives, local capture of the group is not
/// paused by the rebootstrap's freeze and authors under the pass's capability.
pub(crate) struct CapturePass<'a> {
    coordinator: &'a ReplicaCoordinator,
    group: String,
}

impl Drop for CapturePass<'_> {
    fn drop(&mut self) {
        self.coordinator
            .capture_passes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.group);
    }
}

impl ReplicaCoordinator {
    /// Opens `group`'s final capture pass under `authority`. The capability is the rebootstrap's
    /// own: the store's install gate honours it only while the journal is `Capturing` for its
    /// recovery id, so a pass kept open past that authors nothing.
    pub(crate) fn begin_capture_pass(
        &self,
        group: &str,
        authority: Arc<CaptureAuthority>,
    ) -> CapturePass<'_> {
        self.capture_passes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group.to_owned(), authority);
        CapturePass { coordinator: self, group: group.to_owned() }
    }

    /// The capability of `group`'s running final capture pass, if there is one.
    pub(crate) fn capture_authority(&self, group: &str) -> Option<Arc<CaptureAuthority>> {
        self.capture_passes.lock().unwrap_or_else(|p| p.into_inner()).get(group).cloned()
    }
}

/// The author `handle` signs as.
fn local_author_of(
    handle: &LocalAuthorKey,
) -> yadorilink_sync_sqlite::local_author::LocalAuthor<'_> {
    yadorilink_sync_sqlite::local_author::LocalAuthor::of_key(handle)
}

/// The replica index schema init, as `yadorilink_sync_sqlite` composes it.
/// Used by [`ReplicaCoordinator::open`] and
/// [`ReplicaCoordinator::open_in_memory`] below, the two constructors that
/// open a database from scratch.
fn schema_init(conn: &Connection) -> Result<(), yadorilink_sqlite_runtime::DatabaseError> {
    yadorilink_sync_sqlite::init_replica_schema(conn).map_err(map_replica_schema_error)
}

impl ReplicaCoordinator {
    /// Builds every repository field fresh against the given already-open
    /// `database`, reusing its connection pool and in-process
    /// writer-serialization gate rather than opening a second, independent
    /// `SyncDatabase` against the same file.
    ///
    /// `path_lock_registry`/`startup_readiness` are caller-supplied `Arc`s
    /// (not constructed fresh here) so multiple `ReplicaCoordinator`s built
    /// against the same database can share one registry pair -- sharing is
    /// what gives them real mutual exclusion against each other; two
    /// separate registries would each serialize only their own caller's
    /// access and let concurrent access through the other one race.
    pub fn from_database(
        database: Arc<SyncDatabase>,
        path_lock_registry: Arc<PathLockRegistry>,
        startup_readiness: Arc<StartupReadinessRegistry>,
    ) -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        Self::from_database_with(
            database,
            path_lock_registry,
            startup_readiness,
            Self::beside_database_tuning(),
        )
    }

    /// [`Self::from_database`] with the engine's tuning and measurement settings.
    pub fn from_database_with(
        database: Arc<SyncDatabase>,
        path_lock_registry: Arc<PathLockRegistry>,
        startup_readiness: Arc<StartupReadinessRegistry>,
        tuning: crate::engine_tuning::EngineTuning,
    ) -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        let tuning = Arc::new(tuning);
        let sqlite = Arc::new(yadorilink_sync_sqlite::SqliteSyncStore::new(database.clone()));
        // Closes that outstanding removal tickets hold, back in place before
        // anything can ask for a custody lease.
        let custody_closing = crate::custody_handoff::CustodyClosing::open(
            yadorilink_sync_sqlite::RemoteCustodyLeaseRepository::new(database.clone()),
        )
        .map_err(|error| {
            yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(format!(
                "could not read the custody ticket closes: {error}"
            ))
        })?;
        Ok(Self {
            sqlite,
            link_repository: yadorilink_sync_sqlite::link::LinkRepository::new(database.clone()),
            provider_repository: yadorilink_sync_sqlite::provider::ProviderRepository::new(
                database.clone(),
            ),
            enrollment_repository: yadorilink_sync_sqlite::enrollment::EnrollmentRepository::new(
                database.clone(),
            ),
            file_index_repository: yadorilink_sync_sqlite::file_index::FileIndexRepository::new(
                database.clone(),
            ),
            materialization_state_repository:
                yadorilink_sync_sqlite::MaterializationStateRepository::new(database.clone()),
            materialization_intent_repository:
                yadorilink_sync_sqlite::MaterializationIntentRepository::new(database.clone()),
            temp_releases: Arc::default(),
            policy_watermark_repository: yadorilink_sync_sqlite::PolicyWatermarkRepository::new(
                database.clone(),
            ),
            offline_peer_authorization_repository:
                yadorilink_sync_sqlite::OfflinePeerAuthorizationRepository::new(database.clone()),
            offline_group_policy_log_repository:
                yadorilink_sync_sqlite::OfflineGroupPolicyLogRepository::new(database.clone()),
            dirty_path_repository: yadorilink_sync_sqlite::DirtyPathRepository::new(
                database.clone(),
            ),
            paused_item_repository: yadorilink_sync_sqlite::PausedItemRepository::new(
                database.clone(),
            ),
            pinned_item_repository: yadorilink_sync_sqlite::PinnedItemRepository::new(
                database.clone(),
            ),
            held_path_repository: yadorilink_sync_sqlite::HeldPathRepository::new(database.clone()),
            restore_operation_repository: yadorilink_sync_sqlite::RestoreOperationRepository::new(
                database.clone(),
            ),
            rewind_run_repository: yadorilink_sync_sqlite::RewindRunRepository::new(
                database.clone(),
            ),
            retention_pauses: Arc::default(),
            handoff_lease_repository: yadorilink_sync_sqlite::HandoffLeaseRepository::new(
                database.clone(),
            ),
            remote_custody_lease_repository:
                yadorilink_sync_sqlite::RemoteCustodyLeaseRepository::new(database.clone()),
            remote_custody_hold_repository:
                yadorilink_sync_sqlite::RemoteCustodyHoldRepository::new(database.clone()),
            role_loss_operation_repository:
                yadorilink_sync_sqlite::RoleLossOperationRepository::new(database.clone()),
            membership_operation_repository:
                yadorilink_sync_sqlite::MembershipOperationRepository::new(database.clone()),
            recovery_snapshot_reader: RecoverySnapshotReader::new(database.clone()),
            database,
            path_lock_registry,
            startup_readiness,
            block_liveness_gate: Default::default(),
            custody_closing,
            custody_hold_wake: Arc::new(tokio::sync::Notify::new()),
            local_policy_head_provider: Mutex::new(None),
            local_author: Mutex::new(None),
            receive_write_gate: Arc::new(tokio::sync::Semaphore::new(tuning.receive_write_permits)),
            tuning,
            database_restored: Mutex::new(None),
            author_unavailable: Mutex::new(false),
            capture_passes: Mutex::new(std::collections::HashMap::new()),
            root_adoption_lock: Mutex::new(()),
            #[cfg(test)]
            test_observers: Default::default(),
            materialization_wake: MaterializationWake::new(),
            hazard_recheck_wake: GroupWake::new(),
            held_path_wake: tokio::sync::watch::Sender::new(0),
        })
    }

    /// Opens a standalone, freshly-schema'd in-memory database and builds a
    /// `ReplicaCoordinator` directly against it, with its own fresh
    /// `PathLockRegistry`/`StartupReadinessRegistry`. For test fixtures
    /// only -- the one production caller (`app::run`) goes through
    /// [`ReplicaCoordinator::open`] instead.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_in_memory() -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        let database = Arc::new(SyncDatabase::open_in_memory(schema_init)?);
        Self::from_database(
            database,
            Arc::new(PathLockRegistry::new()),
            Arc::new(StartupReadinessRegistry::new()),
        )
    }

    /// Opens (or creates) a real on-disk database at `path` and builds a
    /// `ReplicaCoordinator` directly against it, with its own fresh
    /// `PathLockRegistry`/`StartupReadinessRegistry` -- the production
    /// counterpart to [`Self::open_in_memory`] above. This is how the
    /// daemon's composition root (`app::run`) builds its one
    /// `ReplicaCoordinator`.
    pub fn open(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        Self::open_with(path, Self::beside_database_tuning())
    }

    /// [`Self::open`] with the engine's tuning and measurement settings.
    pub fn open_with(
        path: impl AsRef<std::path::Path>,
        tuning: crate::engine_tuning::EngineTuning,
    ) -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        let database = Arc::new(SyncDatabase::open_process_locked(path, schema_init)?);
        Self::from_database_with(
            database,
            Arc::new(PathLockRegistry::new()),
            Arc::new(StartupReadinessRegistry::new()),
            tuning,
        )
    }

    /// The tuning of a coordinator opened without one (tests and tools): the defaults, with the
    /// installation witness explicitly beside the database.
    fn beside_database_tuning() -> crate::engine_tuning::EngineTuning {
        crate::engine_tuning::EngineTuning {
            witness: crate::install_witness::WitnessPlacement::BesideDatabase,
            ..crate::engine_tuning::EngineTuning::default()
        }
    }

    // --- Accessors needed by the port impls below, so callers can reach
    // individual repositories without the fields themselves being public. ---

    pub fn provider_repository(&self) -> &yadorilink_sync_sqlite::provider::ProviderRepository {
        &self.provider_repository
    }

    pub fn link_repository(&self) -> &yadorilink_sync_sqlite::link::LinkRepository {
        &self.link_repository
    }

    /// How the volume the folder linked at `local_path` is on now relates to
    /// the one its index was built from (see `VolumeMatch`). A folder that is
    /// gone is on another volume; `Err` when that cannot be told right now
    /// (the link table or the volume could not be read). A link with no
    /// recorded volume yet is on it, unless its volume can never be confirmed.
    pub fn folder_capture_volume(
        &self,
        local_path: &str,
    ) -> Result<yadorilink_filesystem_sync::device_boundary::VolumeMatch, SyncError> {
        use yadorilink_filesystem_sync::device_boundary::{root_volume_match, VolumeMatch};
        let recorded = self.link_repository.capture_volume_identity_for_path(local_path)?;
        match root_volume_match(std::path::Path::new(local_path), recorded.as_deref()) {
            Ok(volume) => Ok(volume),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VolumeMatch::Other),
            Err(e) => Err(SyncError::Io(e)),
        }
    }

    /// Whether the folder linked at `local_path` is on the volume its index was
    /// built from (see [`Self::folder_capture_volume`]).
    pub fn folder_on_capture_volume(&self, local_path: &str) -> Result<bool, SyncError> {
        Ok(self.folder_capture_volume(local_path)?
            == yadorilink_filesystem_sync::device_boundary::VolumeMatch::Same)
    }

    /// Whether the folder linked at `local_path` is no longer on the volume its
    /// index was built from (see [`Self::folder_on_capture_volume`]). The same
    /// test the scan applies before it authors deletions. A link with no
    /// recorded volume yet is never reported, unless its volume can never be
    /// confirmed; anything that cannot be read is, so a claim built on this
    /// fails closed.
    pub fn folder_off_capture_volume(&self, local_path: &str) -> bool {
        !matches!(self.folder_on_capture_volume(local_path), Ok(true))
    }

    /// Whether any folder linked for `group_id` is off its capture volume (see
    /// [`Self::folder_off_capture_volume`]). Content listed in the index under
    /// such a folder is not on this device's disk where the index says it is.
    /// A provider-backed group has no folder and is never reported; an
    /// unreadable link table is reported, so a durability claim built on this
    /// fails closed.
    pub fn group_folder_off_capture_volume(&self, group_id: &str) -> bool {
        match self.link_repository.live_link_paths_for_group(group_id) {
            Ok(paths) => paths.iter().any(|path| self.folder_off_capture_volume(path)),
            Err(yadorilink_sync_sqlite::SyncSqliteError::NotFilesystemRoot(_)) => false,
            Err(_) => true,
        }
    }

    pub fn file_index_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::file_index::FileIndexRepository {
        &self.file_index_repository
    }

    pub fn materialization_state_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MaterializationStateRepository {
        &self.materialization_state_repository
    }

    /// The semaphore bounding this engine's concurrent receive file assemblies.
    pub(crate) fn receive_write_gate(&self) -> Arc<tokio::sync::Semaphore> {
        self.receive_write_gate.clone()
    }

    /// The engine's tuning and measurement settings.
    #[must_use]
    pub fn tuning(&self) -> &crate::engine_tuning::EngineTuning {
        &self.tuning
    }

    /// Whether the receive path's commits run on the blocking pool while the
    /// awaiting task keeps polling (see `SyncDatabase::write_immediate_offloaded`):
    /// on unless the engine's tuning turned it off. A/B knob for the measurement, to be deleted
    /// afterwards.
    pub(crate) fn async_commit(&self) -> bool {
        #[cfg(test)]
        match self.test_observers.async_commit_override.load(std::sync::atomic::Ordering::Relaxed) {
            1 => return true,
            2 => return false,
            _ => {}
        }
        self.tuning.receive_async_commit
    }

    pub fn sqlite(&self) -> &yadorilink_sync_sqlite::SqliteSyncStore {
        &self.sqlite
    }

    // --- Remaining repository/registry accessors: mechanical, no logic of
    // their own -- expose each field so callers outside this module can
    // reach the repository for the same underlying database. ---

    pub fn database(&self) -> Arc<SyncDatabase> {
        self.database.clone()
    }

    /// The author handle `device_id` signs this replica's local changes
    /// with, as `signing_key`: the one already open when it names the same
    /// device and key, else this replica's author identity opened now
    /// (`author_identity::ReplicaAuthor::open`: the incarnation check
    /// against the `<db>.instance` sidecar, which is written before the
    /// handle is handed out).
    pub fn open_local_author(
        &self,
        device_id: &str,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Arc<LocalAuthorKey>, crate::author_identity::AuthorIdentityError> {
        let mut slot = self.local_author.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(author) = slot.as_ref() {
            let current = author.current();
            if current.device_id() == device_id
                && current.signing_key().to_bytes() == signing_key.to_bytes()
            {
                return Ok(current);
            }
        }
        let opened = crate::author_identity::ReplicaAuthor::open(
            &self.database,
            &self.tuning.witness,
            device_id,
            signing_key,
        );
        *self.database_restored.lock().unwrap_or_else(|p| p.into_inner()) = match &opened {
            Err(crate::author_identity::AuthorIdentityError::DatabaseRestored(reason)) => {
                Some(*reason)
            }
            _ => None,
        };
        *self.author_unavailable.lock().unwrap_or_else(|p| p.into_inner()) = matches!(
            &opened,
            Err(error) if !matches!(
                error,
                crate::author_identity::AuthorIdentityError::DatabaseRestored(_)
            )
        );
        let author = Arc::new(opened?);
        let current = author.current();
        *slot = Some(author);
        Ok(current)
    }

    /// Why the author identity is refused as a restored or copied database,
    /// if it is.
    pub(crate) fn database_restored(&self) -> Option<crate::install_witness::Restored> {
        *self.database_restored.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether the author identity cannot be opened for a reason other than a restored database.
    pub(crate) fn author_unavailable(&self) -> bool {
        *self.author_unavailable.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Makes the handle this replica signs with name the author incarnation the database now
    /// holds, and writes its sidecar: for after a rebootstrap's install rotated the
    /// incarnation. Idempotent.
    pub(crate) fn adopt_current_author(
        &self,
    ) -> Result<(), crate::author_identity::AuthorIdentityError> {
        let replica = self.local_author.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(replica) = replica {
            replica.refresh(&self.database)?;
        }
        Ok(())
    }

    /// The handle to sign with in place of `author`: this replica's current
    /// author handle when one is open for the same device and key (a handle
    /// cloned out before a rotation names a retired incarnation, which
    /// authoring refuses); `None` to sign with `author` itself.
    fn current_local_author(&self, author: &LocalAuthorKey) -> Option<Arc<LocalAuthorKey>> {
        let slot = self.local_author.lock().unwrap_or_else(|p| p.into_inner()).clone();
        slot.map(|replica| replica.current()).filter(|current| {
            current.device_id() == author.device_id()
                && current.signing_key().to_bytes() == author.signing_key().to_bytes()
        })
    }

    /// Runs `commit` with this replica's current author handle for `author`
    /// (opening this replica's author identity first when it is not open;
    /// refusing when it is open for a different device or signing key);
    /// when authoring refuses that handle as stale or overtaken by its own
    /// later changes (`StaleAuthor`, `OwnAuthorAhead`), refreshes the
    /// author identity (rotating on an own-author-ahead report, sidecar
    /// written before the swap) and runs `commit` once more with the new
    /// handle. The refused attempt wrote nothing.
    pub(crate) fn with_local_author<T>(
        &self,
        author: &LocalAuthorKey,
        mut commit: impl FnMut(&LocalAuthorKey) -> Result<T, yadorilink_sync_sqlite::SyncSqliteError>,
    ) -> Result<T, yadorilink_sync_sqlite::SyncSqliteError> {
        use yadorilink_replica_domain::author::AuthoringRefusal;
        // A replica whose author identity is not open yet (a handle built
        // before the device's signing key was wired) opens it now, as the
        // daemon does when the key is wired.
        let identity_open = self.local_author.lock().unwrap_or_else(|p| p.into_inner()).is_some();
        let current = match self.current_local_author(author) {
            Some(current) => Some(current),
            None if !identity_open => Some(
                self.open_local_author(author.device_id(), author.signing_key().clone()).map_err(
                    |error| {
                        yadorilink_sync_sqlite::SyncSqliteError::CorruptState(format!(
                            "opening the author identity: {error}"
                        ))
                    },
                )?,
            ),
            // The identity is open for another device or signing key:
            // signing with the caller's handle would publish under a key the
            // open incarnation does not own (authoring checks only the
            // AuthorId, not the key), so refuse instead of falling back.
            None => {
                return Err(yadorilink_sync_sqlite::SyncSqliteError::CorruptState(format!(
                    "author {} does not match this replica's open author identity (device or \
                     signing key differs)",
                    author.device_id()
                )))
            }
        };
        let current = current.as_deref().unwrap_or(author);
        match commit(current) {
            Err(
                error @ yadorilink_sync_sqlite::SyncSqliteError::AuthoringRefused {
                    refusal:
                        AuthoringRefusal::StaleAuthor { .. } | AuthoringRefusal::OwnAuthorAhead { .. },
                },
            ) => {
                let replica = self.local_author.lock().unwrap_or_else(|p| p.into_inner()).clone();
                let Some(replica) = replica else { return Err(error) };
                let refreshed = replica.refresh(&self.database).map_err(|error| {
                    yadorilink_sync_sqlite::SyncSqliteError::CorruptState(format!(
                        "refreshing the author identity after an authoring refusal: {error}"
                    ))
                })?;
                commit(&refreshed)
            }
            other => other,
        }
    }

    pub fn enrollment_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::enrollment::EnrollmentRepository {
        &self.enrollment_repository
    }

    /// Whether `block_hash` belongs to a version justified by publication
    /// evidence -- the block-serving authorization boundary a peer request is
    /// checked against.
    pub fn published_group_file_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, yadorilink_sync_sqlite::SyncSqliteError> {
        self.database.read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::dag_store::published_view::published_group_file_version_references_block(
                conn, group_id, block_hash,
            )
        })
    }

    /// Records blocks whose bytes this device actually obtained through the
    /// group. Peer-provided FileVersion/change metadata never calls this.
    ///
    /// One `IMMEDIATE` transaction for the whole batch: the store inserts one
    /// row per hash, and without it each insert would be its own commit and
    /// its own `fsync`, which for a large file's block list costs seconds.
    /// Every row is `INSERT OR IGNORE`d, so a re-run after a crash is
    /// unaffected, and a crash leaves the batch either fully recorded or not
    /// recorded at all.
    pub fn record_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), yadorilink_sync_sqlite::SyncSqliteError> {
        self.database.write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            yadorilink_sync_sqlite::dag_store::record_group_block_provenance(
                tx,
                group_id,
                block_hashes,
            )
        })
    }

    pub fn materialization_intent_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MaterializationIntentRepository {
        &self.materialization_intent_repository
    }

    /// The temp-file ledger of `group_id`: writers record the temp file they
    /// are about to create in it, and link start removes what a crash left.
    pub fn temp_ledger(&self, group_id: &str) -> yadorilink_sync_sqlite::MaterializationTempLedger {
        yadorilink_sync_sqlite::MaterializationTempLedger::new(
            self.database.clone(),
            group_id,
            self.temp_releases.clone(),
        )
    }

    pub fn policy_watermark_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::PolicyWatermarkRepository {
        &self.policy_watermark_repository
    }

    /// This device's last-known-good record of what a live netmap last
    /// authorized each peer for -- see the repository's own module doc for
    /// why it is a cache of an already-made decision and not an authority.
    pub fn offline_peer_authorization_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::OfflinePeerAuthorizationRepository {
        &self.offline_peer_authorization_repository
    }

    /// The raw signed policy log the coordination plane last sent for each
    /// group -- see the repository's own module doc for why storing it
    /// grants nothing (it is re-verified against the pinned service key and
    /// the rollback watermark before any of it is believed).
    pub fn offline_group_policy_log_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::OfflineGroupPolicyLogRepository {
        &self.offline_group_policy_log_repository
    }

    pub fn dirty_path_repository(&self) -> &yadorilink_sync_sqlite::DirtyPathRepository {
        &self.dirty_path_repository
    }

    /// The items paused from the shell context menu -- see
    /// `yadorilink_sync_sqlite::paused_items` for what a pause holds.
    pub fn paused_item_repository(&self) -> &yadorilink_sync_sqlite::PausedItemRepository {
        &self.paused_item_repository
    }

    /// The items kept on this device by the user's choice -- see
    /// `yadorilink_sync_sqlite::pinned_items` for what a pin means.
    pub fn pinned_item_repository(&self) -> &yadorilink_sync_sqlite::PinnedItemRepository {
        &self.pinned_item_repository
    }

    /// The held paths whose disk state has not yet been reconciled -- see `yadorilink_sync_sqlite::held_path`.
    pub fn held_path_repository(&self) -> &yadorilink_sync_sqlite::HeldPathRepository {
        &self.held_path_repository
    }

    pub fn restore_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::RestoreOperationRepository {
        &self.restore_operation_repository
    }

    /// The folder-rewind execution journal -- see `yadorilink_sync_sqlite::rewind_run`.
    pub fn rewind_run_repository(&self) -> &yadorilink_sync_sqlite::RewindRunRepository {
        &self.rewind_run_repository
    }

    /// Holds off retention expiry for `group_id` until the returned guard
    /// drops, or answers `None` when it is already held (by a rewind of the
    /// same group). In memory only: a restart drops it, which is safe
    /// because an interrupted rewind is never resumed -- the next one
    /// re-verifies its plan and gathers its content again.
    ///
    /// What it protects is a rewind's historical version rows between the
    /// moment its plan is verified and its last change: expiry is the one
    /// remover that deletes such a row (block GC and cache reclaim already
    /// keep every retained row's blocks). [`Self::expire_superseded_and_trashed_versions`]
    /// checks the pause under the same lock it is taken with, so an expiry
    /// cannot pass the check and then delete after the pause is set.
    pub fn pause_retention(&self, group_id: &str) -> Option<RetentionPause> {
        let mut paused = self.retention_pauses.lock().unwrap_or_else(|p| p.into_inner());
        if !paused.insert(group_id.to_string()) {
            return None;
        }
        Some(RetentionPause {
            pauses: self.retention_pauses.clone(),
            group_id: group_id.to_string(),
        })
    }

    /// Whether retention expiry is currently held off for `group_id`.
    pub fn retention_paused(&self, group_id: &str) -> bool {
        self.retention_pauses.lock().unwrap_or_else(|p| p.into_inner()).contains(group_id)
    }

    pub fn handoff_lease_repository(&self) -> &yadorilink_sync_sqlite::HandoffLeaseRepository {
        &self.handoff_lease_repository
    }

    pub fn block_liveness_gate(
        &self,
    ) -> &yadorilink_filesystem_sync::block_liveness::BlockLivenessGate {
        &self.block_liveness_gate
    }

    /// Which groups' custody leases this device is currently moving away.
    pub(crate) fn custody_closing(&self) -> &crate::custody_handoff::CustodyClosing {
        &self.custody_closing
    }

    /// Wakes the custody-hold reconciler. Cheap and coalescing: callers that
    /// settled a path (a newer version arrived, the file was deleted) call it
    /// without checking whether any hold exists.
    pub fn nudge_custody_hold_reconciler(&self) {
        self.custody_hold_wake.notify_one();
    }

    pub(crate) fn custody_hold_wake(&self) -> Arc<tokio::sync::Notify> {
        self.custody_hold_wake.clone()
    }

    /// The custody leases this device holds for other devices.
    pub fn remote_custody_lease_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::RemoteCustodyLeaseRepository {
        &self.remote_custody_lease_repository
    }

    /// The custody this device asked other devices to hold for it.
    pub fn remote_custody_hold_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::RemoteCustodyHoldRepository {
        &self.remote_custody_hold_repository
    }

    pub fn role_loss_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::RoleLossOperationRepository {
        &self.role_loss_operation_repository
    }

    pub fn membership_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MembershipOperationRepository {
        &self.membership_operation_repository
    }

    pub fn recovery_snapshot_reader(&self) -> &RecoverySnapshotReader {
        &self.recovery_snapshot_reader
    }

    /// Test-only helper: plants a malformed membership-operation row so
    /// recovery-inventory tests can exercise the "malformed operation
    /// detected" path.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plant_malformed_membership_operation_for_test(
        &self,
        operation_id: &str,
    ) -> Result<(), SyncError> {
        self.membership_operation_repository
            .plant_malformed_membership_operation_for_test(operation_id)
            .map_err(SyncError::from)
    }

    /// Test-only helper: plants a malformed role-loss-operation row so
    /// recovery-inventory tests can exercise the "malformed operation
    /// detected" path.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plant_malformed_role_loss_operation_for_test(
        &self,
        operation_id: &str,
    ) -> Result<(), SyncError> {
        self.role_loss_operation_repository
            .plant_malformed_role_loss_operation_for_test(operation_id)
            .map_err(SyncError::from)
    }

    /// Test-only helper: adds a link row with a pending "join" enrollment
    /// marker attached, for tests that need a link in that intermediate
    /// state without driving the real enrollment flow.
    #[cfg(any(test, feature = "test-support"))]
    pub fn add_link_with_pending_enrollment_for_test(
        &self,
        local_path: &str,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> Result<(), SyncError> {
        let marker = yadorilink_replica_domain::session_state::PendingEnrollment {
            operation_id: operation_id.to_string(),
            kind: yadorilink_replica_domain::session_state::EnrollmentKind::Join,
            group_id: group_id.to_string(),
            device_id: device_id.to_string(),
            local_path: local_path.to_string(),
        };
        self.enrollment_repository
            .add_link_with_pending_enrollment(local_path, group_id, &marker)
            .map_err(SyncError::from)
    }

    pub fn path_lock_registry(&self) -> &PathLockRegistry {
        &self.path_lock_registry
    }

    pub fn startup_readiness(&self) -> &StartupReadinessRegistry {
        &self.startup_readiness
    }

    pub fn materialization_wake(&self) -> &MaterializationWake {
        &self.materialization_wake
    }

    pub fn hazard_recheck_wake(&self) -> &GroupWake {
        &self.hazard_recheck_wake
    }

    /// A subscription to hold wakes (see the `held_path_wake`
    /// field): `changed()` resolves once for every wake since the
    /// subscription last saw one, including one raised while the
    /// subscriber was not waiting.
    pub fn subscribe_held_path(&self) -> tokio::sync::watch::Receiver<u64> {
        self.held_path_wake.subscribe()
    }

    #[cfg(test)]
    pub(crate) fn held_path_subscribers(&self) -> usize {
        self.held_path_wake.receiver_count()
    }

    /// A hold was recorded that needs reconciling: wakes every link's live
    /// repair pass, now or as soon as it next waits (the pass's interval is
    /// the backstop).
    pub fn notify_held_path(&self) {
        self.held_path_wake.send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    // --- Group/change-history mutation methods: local-emission-gated
    // writes into the file index, change history, and restore-operation
    // tables (see `local_policy_head` below for the gate they all share).
    // ---

    pub fn set_local_policy_head_provider(&self, provider: Arc<LocalPolicyHeadProvider>) {
        *self.local_policy_head_provider.lock().unwrap_or_else(|p| p.into_inner()) = Some(provider);
    }

    /// This device's current verified policy_head for `group_id`, or
    /// `Err(PolicyUnavailable)` when this device's own policy view is not
    /// currently trustworthy -- see [`LocalPolicyHeadProvider`]'s own doc
    /// comment for why this is a data-availability gate, not a writer
    /// check. `pub(crate)`, not private: port impls in this module's
    /// submodules (e.g. `local_mutation`) inline this same pre-check
    /// directly where their trait method's error type is narrower than
    /// the legacy emitting wrappers below can return.
    pub(crate) fn local_policy_head(&self, group_id: &str) -> Result<[u8; 32], PolicyUnavailable> {
        match self.local_policy_head_provider.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            Some(provider) => provider(group_id),
            None => Ok([0u8; 32]),
        }
    }

    /// Fallback when no startup-readiness gate has been registered yet for
    /// `group_id`: succeeds only if the group has no live link at all (so
    /// there is nothing to wait on), otherwise reports that startup is
    /// owed but has not run.
    fn absent_gate_verdict(&self, group_id: &str) -> Result<(), StartupFailed> {
        match self.link_repository.has_live_link_for_group(group_id).map_err(SyncError::from) {
            Ok(false) => Ok(()),
            Ok(true) => Err(StartupFailed {
                group_id: group_id.to_string(),
                reason:
                    "link is live but its startup never registered a gate (watcher start failed \
                         or has not run yet); deferring peer apply until startup completes"
                        .to_string(),
            }),
            Err(e) => Err(StartupFailed {
                group_id: group_id.to_string(),
                reason: format!(
                    "cannot read the link table to decide whether startup is owed: {e}"
                ),
            }),
        }
    }

    /// Waits for `group_id`'s startup (initial import/backfill) to finish
    /// before returning, so peer-applied changes are not processed before
    /// local state is ready. Falls back to [`Self::absent_gate_verdict`]
    /// if no readiness gate was ever registered for this group.
    pub async fn wait_group_ready(&self, group_id: &str) -> Result<(), StartupFailed> {
        match self.startup_readiness.wait_group_ready(group_id).await {
            Some(result) => result,
            None => self.absent_gate_verdict(group_id),
        }
    }

    /// Serializes root-identity adoption for this replica: `open` and
    /// `verify` in `yadorilink_root_authority::root_identity` both take
    /// this lock so `verify` can never observe a torn marker/persisted-
    /// token pair from a concurrent `open` still in flight.
    pub fn root_adoption_lock(&self) -> &Mutex<()> {
        &self.root_adoption_lock
    }

    /// Records a restore operation and emits the corresponding change,
    /// after checking local-emission authorization for the operation's
    /// group. `permit` is verified inside the recording transaction.
    pub fn record_restore_operation_emitting_change(
        &self,
        operation: &RestoreOperation,
        version: &FileVersion,
        emitter: &LocalAuthorKey,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncError> {
        self.local_policy_head(&operation.group_id)?;
        self.with_local_author(emitter, |author| {
            let author = local_author_of(author);
            self.restore_operation_repository
                .record_authored_restore_operation(operation, version, &author, permit)
        })
        .map_err(SyncError::from)
    }

    /// [`Self::record_restore_operation_emitting_change`], deciding in the
    /// same transaction whether the restore writes its entry itself --
    /// see [`yadorilink_sync_sqlite::restore_operation::RestoreOperationRepository::record_restore_placing`].
    pub fn record_restore_placing(
        &self,
        operation: &RestoreOperation,
        version: &FileVersion,
        emitter: &LocalAuthorKey,
        permit: &RootCommitPermit,
        disk_allows_in_place: bool,
    ) -> Result<yadorilink_sync_sqlite::restore_operation::RestorePlacement, SyncError> {
        self.local_policy_head(&operation.group_id)?;
        self.with_local_author(emitter, |author| {
            let author = local_author_of(author);
            self.restore_operation_repository.record_restore_placing(
                operation,
                version,
                &author,
                permit,
                disk_allows_in_place,
            )
        })
        .map_err(SyncError::from)
    }

    /// Commits one chunk of a folder rewind as ordinary signed changes by
    /// `emitter`, after checking local-emission authorization for the
    /// group. See
    /// [`yadorilink_sync_sqlite::RewindRunRepository::commit_chunk`]; a group
    /// with no verified policy loaded is a refusal, like the others.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_rewind_chunk(
        &self,
        run_id: &str,
        group_id: &str,
        chunk_index: u64,
        entries: &[yadorilink_replica_domain::rewind::RewindPathEntry],
        emitter: &LocalAuthorKey,
        permit: &RootCommitPermit,
        writer: bool,
    ) -> Result<
        yadorilink_sync_sqlite::rewind_commit::RewindChunkOutcome,
        yadorilink_sync_sqlite::SyncSqliteError,
    > {
        use yadorilink_sync_sqlite::rewind_commit::{RewindChunkOutcome, RewindChunkStop};
        if self.local_policy_head(group_id).is_err() {
            return Ok(RewindChunkOutcome::Stopped(RewindChunkStop::Refused {
                detail: "no verified policy is currently loaded for this group".to_string(),
            }));
        }
        self.with_local_author(emitter, |author| {
            let author = local_author_of(author);
            self.rewind_run_repository.commit_chunk(
                run_id,
                group_id,
                chunk_index,
                entries,
                &author,
                permit,
                writer,
            )
        })
    }

    /// Moves the losing heads of contested paths of `group_id` to their copy
    /// paths, signing as `emitter` (its own heads always; another author's
    /// only where `eligible` admits it, told whether that author is closed).
    pub fn author_contest_forks(
        &self,
        emitter: &LocalAuthorKey,
        group_id: &str,
        eligible: &dyn Fn(&yadorilink_replica_domain::author::AuthorId, bool) -> bool,
    ) -> Result<yadorilink_sync_sqlite::native_authoring::ForkAuthored, SyncError> {
        let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
        // Nothing new is contested since the last pass: no policy read, no write.
        let work = self.database.read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::native_contest_candidates::has_unattempted(conn, group_id)
        })?;
        if !work {
            return Ok(yadorilink_sync_sqlite::native_authoring::ForkAuthored::default());
        }
        self.local_policy_head(group_id)?;
        self.with_local_author(emitter, |author| {
            let author = local_author_of(author);
            // One transaction: each fork delta is several statements (frontier, log, body,
            // heads), and outside one a stop part-way, or a peer reading between them, sees a
            // frontier position whose delta is not stored.
            self.database.write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                yadorilink_sync_sqlite::native_authoring::author_all_forks(
                    tx, &group, &author, eligible,
                )
            })
        })
        .map_err(SyncError::from)
    }

    /// Expires superseded/trashed file versions older than
    /// `now_unix_nanos`, excluding any version keys currently pinned by a
    /// handoff lease. Expires nothing while the group's retention is paused
    /// ([`Self::pause_retention`]); the pause lock is held across the
    /// expiry so a pause cannot be taken half-way through one.
    pub fn expire_superseded_and_trashed_versions(
        &self,
        group_id: &str,
        now_unix_nanos: i64,
    ) -> Result<usize, SyncError> {
        let paused = self.retention_pauses.lock().unwrap_or_else(|p| p.into_inner());
        if paused.contains(group_id) {
            return Ok(0);
        }
        let now_unix_seconds = now_unix_nanos / 1_000_000_000;
        let pinned = self
            .handoff_lease_repository
            .leased_version_keys_for_group(group_id, now_unix_seconds)?;
        Ok(self.file_index_repository.expire_superseded_and_trashed_versions(
            group_id,
            now_unix_nanos,
            &pinned,
        )?)
    }
}

// --- Port impls implemented directly in this file (the other three live
// in the `peer_replica_state`, `materialization_state`, and
// `materialization_execution` submodules -- see the module doc above). ---

impl RootVerificationStatePort for ReplicaCoordinator {
    fn root_adoption_lock(&self) -> &Mutex<()> {
        ReplicaCoordinator::root_adoption_lock(self)
    }

    fn link_root_token_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, RootAuthorityError> {
        Ok(self.link_repository.link_root_token_for_group(group_id).map_err(SyncError::from)?)
    }

    fn set_link_root_token_for_group(
        &self,
        group_id: &str,
        root_token: &str,
    ) -> Result<(), RootAuthorityError> {
        Ok(self
            .link_repository
            .set_link_root_token_for_group(group_id, root_token)
            .map_err(SyncError::from)?)
    }

    fn root_on_recorded_volume(
        &self,
        root: &std::path::Path,
        group_id: &str,
    ) -> Result<bool, RootAuthorityError> {
        let recorded = self
            .link_repository
            .capture_volume_identity_for_group(group_id)
            .map_err(SyncError::from)?
            .flatten();
        Ok(yadorilink_filesystem_sync::device_boundary::root_on_recorded_volume(
            root,
            recorded.as_deref(),
        )?)
    }

    fn ensure_unambiguous_group(&self, group_id: &str) -> Result<(), RootAuthorityError> {
        // The ONE admission of every disk-touching entry. `VerifiedRoot::open` and `verify` call
        // this before they look at a directory, and every scan, flush, peer apply,
        // materialization, repair, hydration and restore goes through one of them: a provider
        // root (ready or not), or one with inconsistent provider state, is refused here, so no
        // entry can reach its directory.
        self.provider_repository
            .require_plain(group_id)
            .map_err(|e| RootAuthorityError::CorruptState(e.to_string()))?;
        Ok(self.link_repository.ensure_unambiguous_group(group_id).map_err(SyncError::from)?)
    }

    fn live_files(&self, group_id: &str) -> Result<Vec<FileRecord>, RootAuthorityError> {
        Ok(self
            .file_index_repository
            .list_files(group_id)
            .map_err(SyncError::from)?
            .into_iter()
            .filter(|r| !r.deleted)
            .collect())
    }

    fn indexed_path_expects_no_object(
        &self,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<bool, RootAuthorityError> {
        use yadorilink_replica_domain::session_state::MaterializationState;
        Ok(self
            .materialization_state_repository
            .get_materialization_state(group_id, &record.path)
            .map_err(SyncError::from)?
            == Some(MaterializationState::Remote))
    }

    fn indexed_path_is_corroborated(
        &self,
        root: &std::path::Path,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<bool, RootAuthorityError> {
        use yadorilink_replica_domain::file::RecordKind;
        use yadorilink_replica_domain::session_state::MaterializationState;

        let disk_path = root.join(&record.path);
        let Ok(metadata) = disk_path.symlink_metadata() else {
            return Ok(false);
        };
        let kind = self
            .file_index_repository
            .get_record_kind(group_id, &record.path)
            .map_err(SyncError::from)?
            .unwrap_or_default();
        Ok(match kind {
            RecordKind::Directory => metadata.file_type().is_dir(),
            RecordKind::Symlink => {
                metadata.file_type().is_symlink()
                    && std::fs::read_link(&disk_path)
                        .ok()
                        .map(|target| yadorilink_fs_platform::fs_identity::target_to_bytes(&target))
                        == self
                            .file_index_repository
                            .get_symlink_target(group_id, &record.path)
                            .map_err(SyncError::from)?
            }
            RecordKind::File => {
                if !metadata.file_type().is_file() {
                    false
                } else {
                    match self
                        .materialization_state_repository
                        .get_materialization_state(group_id, &record.path)
                        .map_err(SyncError::from)?
                    {
                        Some(MaterializationState::Hydrating)
                        | Some(MaterializationState::Evicting) => false,
                        _ => {
                            metadata.len() == record.size
                                && yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                                    &disk_path,
                                    &record.blocks,
                                )
                                .map_err(|e| RootAuthorityError::corrupt_state(e.to_string()))?
                        }
                    }
                }
            }
        })
    }
}

/// Retention expiry held off for one group; see
/// [`ReplicaCoordinator::pause_retention`]. Released on drop.
#[must_use = "retention resumes as soon as the pause is dropped"]
pub struct RetentionPause {
    pauses: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    group_id: String,
}

impl Drop for RetentionPause {
    fn drop(&mut self) {
        self.pauses.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.group_id);
    }
}

#[cfg(test)]
pub(crate) mod test_observers;

#[cfg(test)]
mod materialization_intent_tests;

#[cfg(test)]
mod root_permit_commit_tests;

#[cfg(test)]
mod held_path_wake_tests {
    use super::ReplicaCoordinator;

    /// An install raised while a repair pass is not waiting (mid-pass) is
    /// not lost: the pass's next wait returns at once, and once only.
    #[tokio::test]
    async fn an_install_raised_while_the_pass_is_not_waiting_wakes_its_next_wait() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let mut first = coordinator.subscribe_held_path();
        let mut second = coordinator.subscribe_held_path();
        coordinator.notify_held_path();
        let wait = std::time::Duration::from_millis(50);
        for installs in [&mut first, &mut second] {
            tokio::time::timeout(wait, installs.changed())
                .await
                .expect("the raised install wakes every pass")
                .unwrap();
            assert!(tokio::time::timeout(wait, installs.changed()).await.is_err(), "and only once");
        }
    }
}
