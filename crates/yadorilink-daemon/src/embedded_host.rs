//! The engine as a library a host process embeds, with an explicit lifecycle.
//!
//! This is the composition root of the build without the `process-model` feature: it brings up the same engine
//! services the desktop daemon's `app::run` does, through the same startup phases
//! (`engine_startup`), without the daemon's process model. It opens no control socket and no
//! shell socket, installs no signal handler, takes no process-lifetime lock and exits no
//! process; the host decides when the engine starts and stops, and reaches it through
//! in-memory provider channels.
//!
//! An [`Engine`] runs on the tokio runtime of the caller of [`Engine::start`], and some of
//! the tasks the engine's services spawn are detached. The host therefore gives each engine
//! its own runtime and drops that runtime after [`Engine::stop`]: that is what guarantees
//! nothing the engine started outlives it. `yadorilink-embedded-host` does exactly that.
//!
//! One engine runs per data area per process. Exclusion across processes is the OS-level
//! `DataResourceLocks` the engine takes before it opens the data and holds until the host
//! releases it (the block store is therefore opened with `open_process_locked_with`, which
//! is what that lock licenses; `open_exclusive` is for a host holding only a writer lease).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::io::DuplexStream;
use tokio::task::JoinSet;

use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;

pub use crate::credential_store::CredentialConfig;
use crate::daemon_state::DaemonState;
pub use crate::engine_tuning::EngineTuning;
pub use crate::install_witness::WitnessPlacement;
pub use crate::instance_nonce::{InstanceNonceKeychain, Nonce as InstanceNonce};
use crate::shell_context::ShellContext;
pub use yadorilink_fapi_client::store::Backend as CredentialBackend;
pub use yadorilink_transport::KeyMirror;

/// Where one engine keeps its data.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// The state directory: the engine's device config, signing key, credential store,
    /// reports, recovery areas and settings live under it. Nothing is read from the process
    /// environment to find it. Engines over different directories run side by side only when
    /// their credential entries differ (a file store inside each directory, or an OS keyring
    /// entry scoped per engine, see `Backend::scoped_keyring` in `yadorilink-fapi-client`); engines that name one entry
    /// over different directories are refused ([`StartError::SharedCredentialStore`]).
    pub config_dir: PathBuf,
    /// Where this engine keeps its credential and whether it mirrors its device key into the
    /// OS keyring. The host decides; nothing is read from the process environment.
    pub credentials: CredentialConfig,
    /// The block store root.
    pub block_store_root: PathBuf,
    /// The replica database.
    pub sync_db_path: PathBuf,
    /// The directory provider items are handed to the OS in and uploaded in.
    pub provider_temp_root: Option<PathBuf>,
    /// An id of this installation that the host supplies and keeps stable for the life of the
    /// installation; the engine detects a database copied to another installation from it
    /// (`machine_fingerprint`). It replaces the platform's machine id. Required on iOS, which
    /// has no hardware id the engine may read: a start without one is refused. An id such as
    /// `identifierForVendor` resets when the app is reinstalled, and the engine's data goes
    /// with it. One id per process: a different one in a later engine is refused.
    pub machine_id: Option<String>,
    /// The engine's tuning and measurement settings. [`EngineTuning::default`] is the production
    /// behaviour; nothing is read from the process environment. `tuning.witness` is required: the
    /// installation witness only detects a restored database when it is kept in a persistent
    /// directory outside the data area and outside what a backup restores, so an engine started
    /// with the default (`Unset`) or a non-persistent placement is refused
    /// ([`StartError::WitnessPlacementRequired`]) rather than given a weaker one; a `Persistent`
    /// directory must be absolute and outside the state directory, the database's directory, the
    /// block store and the provider temp root ([`StartError::WitnessDirUnusable`]).
    pub tuning: crate::engine_tuning::EngineTuning,
}

/// Refuses a machine id the engine could not use, changing nothing: an empty or conflicting
/// one, one that arrives after the platform's id fingerprinted this process, or none on iOS.
fn check_machine_id(machine_id: Option<&str>) -> Result<(), StartError> {
    match machine_id {
        Some(id) => crate::machine_fingerprint::check_host_id(id)
            .map_err(|e| StartError::Other(anyhow::Error::from(e))),
        // apple-cfg: ios-explicit iOS has no machine id of its own; migration detection would be silently off
        None if cfg!(target_os = "ios") => Err(StartError::Other(anyhow::anyhow!(
            "the iOS host must supply a machine id (EngineConfig::machine_id)"
        ))),
        None => Ok(()),
    }
}

/// Makes the host's id the process's machine id. Called last before the first use of the
/// fingerprint, after every refusal that does not need it.
fn install_machine_id(machine_id: Option<&str>) -> Result<(), StartError> {
    match machine_id {
        Some(id) => crate::machine_fingerprint::install_host_id(id)
            .map_err(|e| StartError::Other(anyhow::Error::from(e))),
        None => Ok(()),
    }
}

/// Why an engine did not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Another engine of this process already runs over this database.
    #[error("an engine is already running over {0}")]
    AlreadyRunning(PathBuf),
    /// Another engine of this process runs over a different state directory, and both name the
    /// same credential entry. Their refresh tokens would be rotated under different locks, which
    /// the server treats as token reuse. Stop the other engine, or give each engine its own
    /// credential entry (a file store inside its directory, or a keyring entry scoped to it).
    #[error(
        "an engine over {running} already runs in this process and {requested} would share its \
         credential store"
    )]
    SharedCredentialStore { running: PathBuf, requested: PathBuf },
    /// The host did not name a usable installation witness placement. The witness only detects
    /// a restored database when it is kept outside the data area and outside what a backup of it
    /// restores, and is not purged by the system, so no placement is guessed.
    #[error(
        "the host must name where the installation witness lives (EngineConfig::tuning.witness): \
         `Persistent` with a directory outside the data area that no backup of it restores and \
         the system does not purge (not Caches); `BesideDatabase` only by explicit choice"
    )]
    WitnessPlacementRequired,
    /// The `Persistent` witness directory the host named cannot keep the witness outside the data
    /// area: it is not an absolute path, or it is, or lies inside, the state directory, the
    /// database's directory, the block store or the provider temp root (symlinks resolved).
    #[error("the installation witness directory is unusable: {0}")]
    WitnessDirUnusable(String),
    /// Any other reason; the message says what to do.
    #[error("{0:#}")]
    Other(#[from] anyhow::Error),
}

/// What a running engine claimed in this process.
struct Claim {
    config_dir: PathBuf,
    /// The credential entry it uses.
    entry: Entry,
}

/// A claimed credential entry. A file entry is held by OS locks (see
/// `yadorilink_fapi_client::store::EntryClaim`); engines over one state directory share them.
#[derive(Clone)]
enum Entry {
    /// An OS keyring entry, named by its (canonical) scope; `None` is the shared desktop entry.
    Keyring(Option<String>),
    File(Arc<yadorilink_fapi_client::store::FileEntryLock>),
}

/// The databases whose engine is running in this process.
static RUNNING: Mutex<Option<HashMap<PathBuf, Claim>>> = Mutex::new(None);

/// Holds a database's place in [`RUNNING`] for as long as its engine exists.
struct RunningGuard(PathBuf);

/// Whether two state directories are one directory by the host filesystem's own rules: their
/// canonical paths are equal. A spelling-only comparison (such as the Windows normalization in
/// `state_dir::same_dir`) can call `/data/state` and `/data/STATE` one directory on a
/// case-sensitive volume, where their credential rotation locks are different files. A path
/// that cannot be resolved is treated as different, which refuses rather than admits.
fn same_native_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Claims the credential entry `credentials` names for an engine over `config_dir`.
///
/// Whether two configurations name one entry is decided by the operating system, not by
/// comparing their spellings: a file entry is claimed with OS locks, and a claim that finds the
/// entry held is refused unless a running engine over the same state directory holds it (one
/// directory shares its rotation lock), in which case that engine's locks are shared.
fn claim_entry(
    running: &HashMap<PathBuf, Claim>,
    config_dir: &Path,
    credentials: &CredentialConfig,
) -> Result<Entry, StartError> {
    use yadorilink_fapi_client::store::{EntryClaim, StoreError};
    match credentials.backend.claim_entry() {
        Ok(EntryClaim::Keyring { scope }) => Ok(Entry::Keyring(scope)),
        Ok(EntryClaim::File(lock)) => Ok(Entry::File(Arc::new(lock))),
        Err(StoreError::EntryInUse(contended)) => {
            let holders = || {
                running.values().filter_map(|claim| match &claim.entry {
                    Entry::File(lock) => Some((claim, lock)),
                    Entry::Keyring(_) => None,
                })
            };
            // Only an engine over this same state directory that holds the contended entry
            // itself shares it: an engine over the directory with another credential file
            // does not make this one's file its own.
            if let Some((_, lock)) = holders().find(|(claim, lock)| {
                same_native_dir(&claim.config_dir, config_dir) && lock.holds(&contended)
            }) {
                return Ok(Entry::File(lock.clone()));
            }
            let running_dir = holders()
                .find(|(_, lock)| lock.holds(&contended))
                .map_or_else(|| contended.clone(), |(claim, _)| claim.config_dir.clone());
            Err(StartError::SharedCredentialStore {
                running: running_dir,
                requested: config_dir.to_path_buf(),
            })
        }
        Err(other) => Err(StartError::Other(anyhow::Error::from(other))),
    }
}

/// Records an engine over `config_dir` in `running`, or says why it may not run beside the
/// ones in it.
fn admit(
    running: &mut HashMap<PathBuf, Claim>,
    key: PathBuf,
    config_dir: &Path,
    entry: Entry,
) -> Result<(), StartError> {
    if running.contains_key(&key) {
        return Err(StartError::AlreadyRunning(key));
    }
    // A keyring entry has no file to lock: engines that name one keyring entry must share a
    // state directory (and so its rotation lock), or they would refresh one token under
    // different locks. Its scope is one canonical spelling, so equal scopes are one entry.
    if let Entry::Keyring(scope) = &entry {
        if let Some(other) = running.values().find(|other| {
            matches!(&other.entry, Entry::Keyring(other_scope) if other_scope == scope)
                && !same_native_dir(&other.config_dir, config_dir)
        }) {
            return Err(StartError::SharedCredentialStore {
                running: other.config_dir.clone(),
                requested: config_dir.to_path_buf(),
            });
        }
    }
    running.insert(key, Claim { config_dir: config_dir.to_path_buf(), entry });
    Ok(())
}

impl RunningGuard {
    fn claim(
        db: &Path,
        config_dir: &Path,
        credentials: &CredentialConfig,
    ) -> Result<Self, StartError> {
        // The database does not exist before its first start, so its directory is what is
        // resolved: two spellings of one database must claim the same place.
        let key = match (db.parent(), db.file_name()) {
            (Some(parent), Some(name)) => {
                yadorilink_fs_platform::durable_dir::create_dir_all_durably(parent)
                    .map_err(anyhow::Error::from)?;
                std::fs::canonicalize(parent).map_err(anyhow::Error::from)?.join(name)
            }
            _ => db.to_path_buf(),
        };
        let mut running = RUNNING.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let running = running.get_or_insert_with(HashMap::new);
        if running.contains_key(&key) {
            return Err(StartError::AlreadyRunning(key));
        }
        let entry = claim_entry(running, config_dir, credentials)?;
        admit(running, key.clone(), config_dir, entry)?;
        Ok(Self(key))
    }
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        let mut running = RUNNING.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(map) = running.as_mut() {
            map.remove(&self.0);
        }
    }
}

/// Tells whether an engine's state has been released: nothing holds it any more.
#[derive(Debug, Clone)]
pub struct ReleaseProbe(Weak<DaemonState>);

impl ReleaseProbe {
    /// True once every task and service that held the engine's state has let go of it.
    #[must_use]
    pub fn released(&self) -> bool {
        self.0.strong_count() == 0
    }
}

/// Why an engine command failed: the engine's own message, which says what to do, and a typed
/// kind for the cases a host acts on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CommandError {
    kind: CommandErrorKind,
    message: String,
    operation_id: String,
}

/// What kind of failure a [`CommandError`] is, for the cases a host acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandErrorKind {
    /// The build has no OS watcher, so an ordinary folder cannot be linked: link a provider
    /// folder instead. Nothing was changed.
    NoChangeSource,
    /// A refusal the control socket types too (the share, link and unlink commands): the code
    /// says which. [`CommandError::operation_id`] names the enrollment operation when the
    /// refusal concerns one that must be recovered or retried.
    Refused(ApplicationErrorCode),
    /// A preserved item's own refusal.
    Preserved(PreservedRefusal),
    /// A re-adoption of a marked folder was refused.
    Readopt(ReadoptRefusal),
    /// Any other failure.
    Failed,
}

impl CommandError {
    fn failed(message: impl Into<String>) -> Self {
        Self {
            kind: CommandErrorKind::Failed,
            message: message.into(),
            operation_id: String::new(),
        }
    }

    fn refused(code: ApplicationErrorCode, message: String, operation_id: String) -> Self {
        Self { kind: CommandErrorKind::Refused(code), message, operation_id }
    }

    fn preserved(refusal: PreservedRefusal, message: String) -> Self {
        Self { kind: CommandErrorKind::Preserved(refusal), message, operation_id: String::new() }
    }

    fn readopt(refusal: ReadoptRefusal, message: impl Into<String>) -> Self {
        Self {
            kind: CommandErrorKind::Readopt(refusal),
            message: message.into(),
            operation_id: String::new(),
        }
    }

    fn no_change_source() -> Self {
        Self {
            kind: CommandErrorKind::NoChangeSource,
            message: "ordinary folder links need an OS watcher, which this build does not have; \
                      use provider folders on this platform"
                .to_owned(),
            operation_id: String::new(),
        }
    }

    /// The engine's message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// What kind of failure this is.
    #[must_use]
    pub fn kind(&self) -> CommandErrorKind {
        self.kind
    }

    /// The enrollment operation a refusal concerns; empty when it concerns none.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

pub use crate::adapters::runtime::link_runtime_controller::ordinary_folder_links_supported;

/// Link a folder to a replica group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkFolder {
    pub local_path: String,
    pub group_id: String,
    /// Keep content in the cloud and fetch it on open.
    pub on_demand: bool,
    /// The caller has shown the user the risks the preflight finds in this folder and the user
    /// confirmed. Without it, a folder with risks is refused.
    pub acknowledge_risks: bool,
}

/// Restore a file to one of its earlier versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreVersion {
    pub group_id: String,
    pub path: String,
    /// The version to restore; the most recent superseded one when `None`.
    pub version_seq: Option<i64>,
}

/// One linked folder as the host shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedFolder {
    /// The link's identity key: a path for a folder, a locator for a provider folder.
    pub key: String,
    pub group_id: String,
    pub paused: bool,
    /// The folder keeps content in the cloud and fetches it on open (its configured target; not
    /// the eager full-replica mode).
    pub on_demand: bool,
    pub conflict_count: u64,
    pub hydrated_count: u64,
    pub placeholder_count: u64,
    /// Why the folder is degraded, when it is.
    pub degraded: Option<String>,
}

/// The application commands an embedding host calls: the same services the desktop daemon's
/// control socket drives, without the socket's wire types. Obtained from [`Engine::commands`].
/// It holds the engine's state, so a host keeps one only for as long as the engine runs.
#[derive(Clone)]
pub struct EngineCommands {
    context: Arc<crate::control_context::ControlContext>,
    /// The engine's state directory, where its settings and replacement records live.
    config_dir: PathBuf,
}

impl EngineCommands {
    /// Links a folder.
    ///
    /// # Errors
    /// [`CommandError`] when the link is refused or fails.
    pub async fn link_folder(&self, command: LinkFolder) -> Result<(), CommandError> {
        // Before anything is checked or persisted: a link with no source of changes would
        // report success and then never capture an edit.
        if !ordinary_folder_links_supported() {
            return Err(CommandError::no_change_source());
        }
        if !command.acknowledge_risks {
            let links = self.context.application.link_lifecycle.clone();
            let path = PathBuf::from(&command.local_path);
            tokio::task::spawn_blocking(move || links.require_risks_acknowledged(&path, false))
                .await
                .map_err(|e| CommandError::failed(format!("link preflight did not complete: {e}")))?
                .map_err(|e| CommandError::failed(e.to_string()))?;
        }
        self.context
            .application
            .link_lifecycle
            .link(crate::application::LinkCommand {
                local_path: command.local_path,
                group_id: command.group_id,
                on_demand: command.on_demand,
                pending_enrollment: None,
                provider: None,
            })
            .await
            .map(|_| ())
            .map_err(|e| CommandError::failed(e.to_string()))
    }

    /// Restores a file to an earlier version. `Ok(false)` when there is no earlier version.
    ///
    /// # Errors
    /// [`CommandError`] when the restore fails.
    pub async fn restore_version(&self, command: RestoreVersion) -> Result<bool, CommandError> {
        self.context
            .application
            .version_restore
            .restore_version(&command.group_id, &command.path, command.version_seq)
            .await
            .map_err(|e| CommandError::failed(e.to_string()))
    }

    /// The linked folders and their state.
    ///
    /// # Errors
    /// [`CommandError`] when the link table cannot be read.
    pub fn linked_folders(&self) -> Result<Vec<LinkedFolder>, CommandError> {
        let links = self
            .context
            .queries
            .link_status
            .list_links()
            .map_err(|e| CommandError::failed(e.to_string()))?;
        Ok(links
            .into_iter()
            .map(|link| LinkedFolder {
                key: link.local_path,
                group_id: link.group_id,
                paused: link.paused,
                on_demand: link.materialization_policy != "eager",
                conflict_count: link.conflict_count,
                hydrated_count: link.hydrated_count,
                placeholder_count: link.placeholder_count,
                degraded: link.degraded.map(|d| d.reason),
            })
            .collect())
    }
}

impl EngineCommands {
    /// Keeps the linked folder `key` visible as needing the person after a start over could not
    /// join its group again: it stops taking part in sync and its runtime stops; the row and
    /// the folder's files stay. The mark is cleared only by a path that links the folder to its group
    /// again, which the embedded host does not expose yet. Idempotent, and never deletes or rewrites a file.
    ///
    /// # Errors
    /// [`CommandError`] when the link table cannot be written; the caller reports it and runs
    /// the start over again.
    pub async fn mark_not_rejoined(&self, key: &str) -> Result<(), CommandError> {
        self.context
            .application
            .link_lifecycle
            .mark_not_rejoined(key)
            .await
            .map_err(|e| CommandError::failed(e.to_string()))
    }
}

/// A running engine.
pub struct Engine {
    commands: EngineCommands,
    state: Arc<DaemonState>,
    shell_context: Arc<ShellContext>,
    /// The provider channels' serving tasks; they end with the engine.
    channels: Mutex<JoinSet<()>>,
    /// The peer orchestrator, when this device is registered and signed in.
    background: tokio::sync::Mutex<JoinSet<&'static str>>,
    orchestrator_alive: Arc<AtomicBool>,
    held: Held,
    stall_stop: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

/// What an engine holds exclusively for as long as it exists: its place in this process and
/// the OS locks on its database and block store. [`Engine::into_held`] hands it back so the host
/// can release it after everything the engine detached has ended.
pub struct Held {
    _locks: yadorilink_local_storage::resource_lock::DataResourceLocks,
    _running: RunningGuard,
}

/// The size of an in-memory provider channel's buffer in each direction.
const CHANNEL_BUFFER_BYTES: usize = 256 * 1024;

const TASK_PEER_ORCHESTRATOR: &str = "peer-orchestrator";

impl Engine {
    /// Opens the data, brings the engine up and returns it running.
    ///
    /// # Errors
    /// [`StartError`]; nothing is left running (every fallible step precedes the first task the
    /// engine spawns), and the data is untouched when the reason is an unusable configuration.
    pub async fn start(config: EngineConfig) -> Result<Self, StartError> {
        check_machine_id(config.machine_id.as_deref())?;
        if !matches!(
            config.tuning.witness,
            crate::install_witness::WitnessPlacement::Persistent(_)
                | crate::install_witness::WitnessPlacement::BesideDatabase
        ) {
            return Err(StartError::WitnessPlacementRequired);
        }
        if let crate::install_witness::WitnessPlacement::Persistent(witness_dir) =
            &config.tuning.witness
        {
            let db_dir = config.sync_db_path.parent().unwrap_or_else(|| std::path::Path::new("."));
            let mut areas: Vec<&std::path::Path> =
                vec![&config.config_dir, db_dir, &config.block_store_root];
            areas.extend(config.provider_temp_root.as_deref());
            crate::install_witness::check_persistent_dir(witness_dir, &areas)
                .map_err(StartError::WitnessDirUnusable)?;
        }
        let credentials = config.credentials;
        let dir = config.config_dir;
        // The directory itself (nothing else) exists first: the default credential file lives
        // in it, and a file is identified by where the filesystem resolves it.
        yadorilink_fs_platform::durable_dir::create_dir_all_durably(&dir)
            .map_err(anyhow::Error::from)?;
        let running = RunningGuard::claim(&config.sync_db_path, &dir, &credentials)?;

        // Same order as the daemon: identity config first, so that an unusable one is
        // refused before anything is created or migrated.
        let device_config = crate::engine_startup::load_device_config(&dir)?;
        let registered_identity = if device_config.is_some() {
            Some(
                yadorilink_transport::DeviceSigningKeyPair::load_existing(
                    dir.join("signing_key"),
                    credentials.key_mirror,
                )
                .map_err(anyhow::Error::from)?,
            )
        } else {
            None
        };

        // Before either store is opened or settled: a second engine over the same database or
        // block store, in this or another process, is refused here rather than resetting the
        // first one's state or reclaiming blocks it needs.
        let mut locks = yadorilink_local_storage::resource_lock::DataResourceLocks::acquire(
            &config.block_store_root,
            &config.sync_db_path,
        )?;
        // Everything that can refuse without the fingerprint has passed: from here the id is
        // chosen, and `open_data` is its first use.
        install_machine_id(config.machine_id.as_deref())?;
        let crate::engine_startup::OpenedData { block_store, replica_coordinator } =
            crate::engine_startup::open_data(
                &locks,
                &dir,
                &config.block_store_root,
                &config.sync_db_path,
                &config.tuning,
            )?;
        locks.lock_created_sync_db(&config.sync_db_path)?;
        crate::engine_startup::settle_data(&replica_coordinator, &config.sync_db_path)?;

        // Enumerated once, and the start fails if the table cannot be read: see `app::run`.
        let links =
            replica_coordinator.link_repository().list_links().map_err(anyhow::Error::from)?;

        // Everything that can fail has failed or succeeded by here: from `build_engine` on, the
        // engine spawns tasks that outlive this function's locals, so no `?` may follow, or the
        // locks would be released under tasks that are still working.
        let coordination_auth =
            crate::credential_store::coordination_auth(&dir, &credentials).await?;

        let device_id = device_config.as_ref().map(|c| c.device_id.clone()).unwrap_or_default();
        let crate::engine_startup::BuiltEngine { state, application, recovery_job } =
            crate::engine_startup::build_engine(
                &dir,
                device_id,
                &replica_coordinator,
                &block_store,
                registered_identity.as_ref(),
            );
        // Before coordination starts, as in `app::run`: the folders are scanned and watched
        // before peers can apply changes into them.
        crate::engine_startup::resume_links(&state, &links);
        let control_context = Arc::new(crate::control_context::ControlContext::new(
            application,
            crate::adapters::build_query_services(state.clone()),
            dir.clone(),
        ));
        let commands = EngineCommands { context: control_context.clone(), config_dir: dir.clone() };
        let shell_context = crate::engine_startup::start_provider(
            &state,
            &control_context,
            config.provider_temp_root,
        );

        let mut background = JoinSet::new();
        let orchestrator_alive = Arc::new(AtomicBool::new(false));
        if let Some(cfg) = device_config.as_ref() {
            crate::peer_orchestrator::restore_offline_group_policy_states(
                &state,
                &cfg.coordination_addr,
            );
        }
        match (device_config, coordination_auth) {
            (Some(cfg), Some(auth)) => {
                tracing::info!(device_id = %cfg.device_id, "connecting to coordination plane");
                crate::engine_startup::spawn_coordination_tasks(&state, &recovery_job, &cfg, &auth);
                let orchestrator_config = crate::peer_orchestrator::OrchestratorConfig {
                    coordination_addr: cfg.coordination_addr,
                    auth,
                    device_id: cfg.device_id,
                };
                let state = state.clone();
                state.set_task_alive(TASK_PEER_ORCHESTRATOR, true);
                orchestrator_alive.store(true, Ordering::SeqCst);
                let alive = orchestrator_alive.clone();
                background.spawn(async move {
                    if let Err(error) =
                        crate::peer_orchestrator::run(orchestrator_config, state.clone()).await
                    {
                        tracing::error!(%error, task = TASK_PEER_ORCHESTRATOR, "essential task failed");
                    } else {
                        tracing::warn!(task = TASK_PEER_ORCHESTRATOR, "essential task exited");
                    }
                    state.set_task_alive(TASK_PEER_ORCHESTRATOR, false);
                    alive.store(false, Ordering::SeqCst);
                    TASK_PEER_ORCHESTRATOR
                });
            }
            _ => {
                tracing::warn!(
                    "not signed in or no device registered yet: running with local state only"
                );
                state.forget_offline_peer_authorization();
            }
        }

        Ok(Self {
            commands,
            state,
            shell_context,
            channels: Mutex::new(JoinSet::new()),
            background: tokio::sync::Mutex::new(background),
            orchestrator_alive,
            held: Held { _locks: locks, _running: running },
            stall_stop: Mutex::new(None),
        })
    }

    /// Opens an in-memory provider channel: the host side of the framed provider protocol
    /// the desktop daemon serves over its shell socket. Messages go in and out as the
    /// protocol's length-prefixed frames (`yadorilink_ipc_proto::framing`). The channel ends
    /// when either side drops it or the engine stops. Call it with the engine's runtime
    /// entered.
    #[must_use]
    pub fn open_provider_channel(&self) -> DuplexStream {
        let (host_side, engine_side) = tokio::io::duplex(CHANNEL_BUFFER_BYTES);
        let context = self.shell_context.clone();
        let (read, write) = tokio::io::split(engine_side);
        let mut channels = self.channels.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Finished connections are reaped here so a host that opens many does not accumulate them.
        while channels.try_join_next().is_some() {}
        channels.spawn(async move {
            if let Err(error) = crate::shell_ipc::handle_connection(read, write, context).await {
                tracing::debug!(%error, "provider channel ended");
            }
        });
        host_side
    }

    /// The application commands; see [`EngineCommands`].
    #[must_use]
    pub fn commands(&self) -> EngineCommands {
        self.commands.clone()
    }

    /// Whether the peer orchestrator is running. False for a device that is not registered
    /// and signed in, which has no peers to reach.
    pub fn peer_orchestrator_running(&self) -> bool {
        self.orchestrator_alive.load(Ordering::SeqCst)
    }

    /// Tells whether this engine's state has been released; see [`ReleaseProbe`].
    #[must_use]
    pub fn release_probe(&self) -> ReleaseProbe {
        ReleaseProbe(Arc::downgrade(&self.state))
    }

    /// Stops the engine: ends the provider channels, drains what is in flight, tells peers
    /// this device is leaving, stops its tasks and checkpoints the databases. Unbounded: the
    /// host applies its own deadline to the returned future and, whether it finishes or not,
    /// takes the data area back with [`Self::into_held`] so that it is released only after
    /// everything the engine started has ended.
    pub async fn stop(&self) {
        let stall =
            self.stall_stop.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(stall) = stall {
            let _ = tokio::task::spawn_blocking(move || stall.recv()).await;
        }
        // `send_replace`: the value must change even when nobody has subscribed yet.
        self.state.shutdown_tx.send_replace(true);
        let mut channels = std::mem::take(
            &mut *self.channels.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        channels.shutdown().await;
        crate::engine_startup::quiesce(&self.state).await;
        crate::engine_startup::close_substrate(&self.state).await;
        self.background.lock().await.shutdown().await;
        crate::engine_startup::checkpoint_data(&self.state).await;
    }

    /// Gives up the engine, keeping what it holds exclusively: the host releases the returned
    /// [`Held`] once the engine's runtime has finished.
    #[must_use]
    pub fn into_held(self) -> Held {
        self.held
    }

    /// Whether a link runtime is running for `folder`. For tests of the startup phases.
    #[doc(hidden)]
    #[must_use]
    pub fn has_link_runtime_for_test(&self, folder: &str) -> bool {
        self.state.links.runtime(folder).is_some()
    }

    /// Points the engine's coordination calls at `addr` with `auth`, as a start with a stored
    /// credential would. For tests that serve the coordination plane in process.
    #[doc(hidden)]
    pub fn set_coordination_for_test(
        &self,
        addr: String,
        auth: yadorilink_fapi_client::CoordinationAuth,
    ) {
        self.state.set_coordination_client_config(addr, auth);
    }

    /// Adds a link row for `key` (a path, or a provider locator) without starting anything for
    /// it. For tests of what runs over existing links.
    ///
    /// # Panics
    /// When the row cannot be written.
    #[doc(hidden)]
    pub fn add_link_row_for_test(&self, key: &str, group_id: &str, on_demand: bool) {
        let links = self.state.replica_coordinator.link_repository();
        links.add_link(key, group_id).expect("the link row is written");
        if on_demand {
            links
                .set_materialization_policy(
                    key,
                    yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
                )
                .expect("the policy is set");
        }
    }

    /// Makes [`Self::stop`] wait for `release` first. For tests of a stop that does not finish.
    #[doc(hidden)]
    pub fn stall_stop_for_test(&self, release: std::sync::mpsc::Receiver<()>) {
        *self.stall_stop.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(release);
    }
}

#[cfg(test)]
mod claim_tests {
    use super::*;
    use yadorilink_fapi_client::store::Backend;

    fn admit_into(
        running: &mut HashMap<PathBuf, Claim>,
        name: &str,
        dir: &str,
        shared: bool,
    ) -> Result<(), StartError> {
        // A shared engine names the one process-wide keyring entry; the others each keep their
        // own (a scope of their own, standing for a file inside their directory).
        let scope = if shared { None } else { Some(dir.replace('/', "-")) };
        admit(running, PathBuf::from(name), Path::new(dir), Entry::Keyring(scope))
    }

    fn file_config(path: &Path) -> CredentialConfig {
        CredentialConfig::new(
            Backend::File(path.to_path_buf()),
            yadorilink_transport::KeyMirror::Disabled,
        )
    }

    /// Claims as `Engine::start` does, for a directory that exists.
    fn claim_for(
        running: &mut HashMap<PathBuf, Claim>,
        db: &str,
        dir: &Path,
        credentials: &CredentialConfig,
    ) -> Result<(), StartError> {
        let entry = claim_entry(running, dir, credentials)?;
        admit(running, PathBuf::from(db), dir, entry)
    }

    #[test]
    fn the_os_decides_whether_two_credential_files_are_one_entry() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let shared = t.path().join("shared.json");
        let mut running = HashMap::new();
        claim_for(&mut running, "/a/db", &a, &file_config(&shared)).unwrap();
        let refused = |running: &mut HashMap<PathBuf, Claim>, path: &Path| {
            matches!(
                claim_for(running, "/b/db", &b, &file_config(path)),
                Err(StartError::SharedCredentialStore { .. })
            )
        };
        // The same file by another spelling: a dot segment.
        assert!(refused(&mut running, &t.path().join(".").join("shared.json")));
        // A distinct file is its own entry.
        claim_for(&mut running, "/c/db", &b, &file_config(&t.path().join("own.json"))).unwrap();
        // The same directory shares the holder's locks instead of being refused.
        claim_for(&mut running, "/a/other", &a, &file_config(&shared)).unwrap();
        // Once every engine over it is gone, the entry is free for another directory.
        running.clear();
        claim_for(&mut running, "/b/db", &b, &file_config(&shared)).unwrap();
    }

    #[test]
    fn a_directory_shares_only_the_entry_its_own_engine_holds() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (x, y) = (t.path().join("x.json"), t.path().join("y.json"));
        let mut running = HashMap::new();
        claim_for(&mut running, "/a/db", &a, &file_config(&x)).unwrap();
        claim_for(&mut running, "/b/db", &b, &file_config(&y)).unwrap();
        // Another engine in B naming A's file X: B runs an engine, but not over X.
        assert!(matches!(
            claim_for(&mut running, "/b/other", &b, &file_config(&x)),
            Err(StartError::SharedCredentialStore { .. })
        ));
        // Another engine in A with X, and in B with Y, share their own directory's entry.
        claim_for(&mut running, "/a/other", &a, &file_config(&x)).unwrap();
        claim_for(&mut running, "/b/third", &b, &file_config(&y)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_hard_link_to_a_credential_file_is_the_same_entry_and_a_symlink_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let original = t.path().join("original.json");
        std::fs::write(&original, "{}").unwrap();
        let hard = t.path().join("hard.json");
        std::fs::hard_link(&original, &hard).unwrap();
        let soft = t.path().join("soft.json");
        std::os::unix::fs::symlink(&original, &soft).unwrap();
        let mut running = HashMap::new();
        claim_for(&mut running, "/a/db", &a, &file_config(&original)).unwrap();
        assert!(matches!(
            claim_for(&mut running, "/b/db", &b, &file_config(&hard)),
            Err(StartError::SharedCredentialStore { .. })
        ));
        assert!(matches!(
            claim_for(&mut running, "/b/db", &b, &file_config(&soft)),
            Err(StartError::Other(_))
        ));
    }

    #[test]
    fn two_engines_racing_for_one_credential_file_admit_exactly_one() {
        let t = tempfile::tempdir().unwrap();
        let shared = t.path().join("shared.json");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|name| {
                let dir = t.path().join(name);
                std::fs::create_dir_all(&dir).unwrap();
                let (shared, barrier) = (shared.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    // Each thread has its own view of what runs, as two hosts would not share a
                    // registry: only the OS locks arbitrate.
                    claim_entry(&HashMap::new(), &dir, &file_config(&shared)).map(Some)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let admitted = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            admitted,
            1,
            "exactly one claim wins: {:?}",
            results.iter().map(|r| r.is_ok()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn engines_with_their_own_keyring_scope_run_side_by_side_and_one_scope_is_one_entry() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let config = |scope: Option<&str>| {
            CredentialConfig::new(
                match scope {
                    Some(scope) => Backend::scoped_keyring(scope).unwrap(),
                    None => Backend::Keyring { scope: None },
                },
                yadorilink_transport::KeyMirror::Disabled,
            )
        };
        let mut running = HashMap::new();
        claim_for(&mut running, "/a/db", &a, &config(Some("engine-a"))).unwrap();
        claim_for(&mut running, "/b/db", &b, &config(Some("engine-b"))).unwrap();
        // A scope named by two directories is one credential, so it is refused.
        assert!(matches!(
            claim_for(&mut running, "/c/db", &b, &config(Some("engine-a"))),
            Err(StartError::SharedCredentialStore { .. })
        ));
        // The unscoped keyring entry is a different entry from any scoped one.
        claim_for(&mut running, "/d/db", &b, &config(None)).unwrap();
    }

    #[test]
    fn a_missing_machine_id_is_refused_exactly_where_the_platform_has_none() {
        // apple-cfg: ios-explicit iOS has no machine id of its own
        let refused = check_machine_id(None).is_err();
        assert_eq!(refused, cfg!(target_os = "ios"));
        assert!(check_machine_id(Some(" ")).is_err());
    }

    #[test]
    fn engines_that_share_a_credential_entry_must_share_a_state_directory() {
        // Real directories: sameness is the host filesystem's own (canonical paths).
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a-state"), t.path().join("b-state"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_str().unwrap().to_owned(), b.to_str().unwrap().to_owned());
        let mut running = HashMap::new();
        admit_into(&mut running, "/a/db", &a, true).unwrap();
        assert!(matches!(
            admit_into(&mut running, "/b/db", &b, true),
            Err(StartError::SharedCredentialStore { .. })
        ));
        // The same directory shares its rotation lock: another database over it is allowed,
        // also through a different spelling of the same directory.
        admit_into(&mut running, "/a/other-db", &a, true).unwrap();
        let dotted = format!("{a}/../a-state");
        admit_into(&mut running, "/a/third-db", &dotted, true).unwrap();
        // A directory that cannot be resolved is refused, never assumed equal.
        assert!(matches!(
            admit_into(&mut running, "/c/db", "/does/not/exist/state", true),
            Err(StartError::SharedCredentialStore { .. })
        ));
        // Once the engines over /a are gone, a different directory may start.
        running.clear();
        admit_into(&mut running, "/b/db", &b, true).unwrap();
    }

    #[test]
    fn engines_with_a_credential_entry_inside_their_directory_run_side_by_side() {
        let mut running = HashMap::new();
        admit_into(&mut running, "/a/db", "/a/state", false).unwrap();
        admit_into(&mut running, "/b/db", "/b/state", false).unwrap();
    }

    #[test]
    fn a_directory_scoped_engine_does_not_block_a_shared_one_and_the_reverse() {
        let mut running = HashMap::new();
        admit_into(&mut running, "/a/db", "/a/state", false).unwrap();
        admit_into(&mut running, "/b/db", "/b/state", true).unwrap();
        running.clear();
        admit_into(&mut running, "/b/db", "/b/state", true).unwrap();
        admit_into(&mut running, "/a/db", "/a/state", false).unwrap();
    }

    #[test]
    fn a_second_engine_over_one_database_is_refused() {
        let mut running = HashMap::new();
        admit_into(&mut running, "/a/db", "/a/state", false).unwrap();
        assert!(matches!(
            admit_into(&mut running, "/a/db", "/a/state", false),
            Err(StartError::AlreadyRunning(_))
        ));
    }
}

mod app_commands;
pub use app_commands::{
    CreateShare, DoctorCheck, DoctorStatus, HandoffInfo, JoinGroup, JoinShare, PauseFor, PauseLink,
    PreservedItem, PreservedKind, PreservedRef, PreservedRefusal, ProviderFolder,
    ReadoptMarkedFolder, ReadoptOutcome, ReadoptRefusal, ResumeLink, ShareFolder, ShareOutcome,
    SpaceManagement, UnlinkFolder, UnlinkOutcome,
};

#[cfg(test)]
mod fake_os_tests;
