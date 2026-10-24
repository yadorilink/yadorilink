//! The embedded host exported through UniFFI, for the iOS app and its File Provider extension.
//!
//! Two objects are exported: [`MobileHost`] and [`ProviderChannel`], with the typed
//! records and errors they use. Each wraps its counterpart in `yadorilink-embedded-host`
//! and adds only the bridge:
//!
//! - Lifecycle and command calls block the calling thread until they are done, exactly as
//!   in the host crate. The foreign side calls them off its main thread (Swift: a detached
//!   task or a dispatch queue). They do not touch a runtime of this library: the host owns
//!   the engine's runtime and drops it on suspend and stop.
//! - A command call is bounded by a [`CancelHandle`] (one per call; `cancel` returns at once
//!   and may be called from any thread) and an optional deadline. What cancelling means is
//!   the host crate's rule: a read-only command is aborted, a command that changes state
//!   keeps running and the error says so (`still_running`).
//! - The provider channel carries the provider protocol (`shellipc.proto`) as one encoded
//!   `ShellIpcMessage` per call, without the length prefix the socket form uses. `send` and
//!   `recv` are async and need no runtime of this library; `close` ends a waiting `recv`.
//!   The generated async shim ignores task cancellation, so `close` is how a waiting `recv`
//!   stops.
//! - Nothing panics across the boundary: UniFFI turns a panic of a throwing call into an
//!   error of the foreign side.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message;
use tokio::sync::watch;
use yadorilink_embedded_host as host;
use yadorilink_ipc_proto::shellipc::ShellIpcMessage;

uniffi::setup_scaffolding!();

/// Where the engine keeps its data. Paths are absolute.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EngineConfig {
    /// The state directory (device config, signing key, credential store, reports).
    pub config_dir: String,
    /// The block store root.
    pub block_store_root: String,
    /// The replica database file.
    pub sync_db_path: String,
    /// The directory provider items are handed to the OS in and uploaded in.
    pub provider_temp_root: Option<String>,
    /// Where the engine keeps its sign-in. `Some(scope)`: its own entry in the Data Protection
    /// keychain (account `credentials.<scope>`, in the app's credential access group), so
    /// engines with different scopes cannot read each other's credential; the scope is 1 to 64
    /// of lowercase letters `a-z`, digits, `.`, `_` and `-` (anything else, uppercase included,
    /// is refused when the engine starts), and two engines must not use one scope over
    /// different state directories. `None`: a credential file inside the state directory, with
    /// no keychain use at all.
    pub credential_keyring_scope: Option<String>,
    /// The Authorization Server to use instead of the stored credential's issuer.
    pub auth_server_addr: Option<String>,
    /// The coordination service the account commands (sign-in, device registration, sign-out,
    /// account deletion) talk to. `None`: the build's own address.
    pub coordination_addr: Option<String>,
    /// How this device names itself on the sign-in approval page (for example the device's
    /// name). `None`: a generic label.
    pub host_name: Option<String>,
    /// Where the engine keeps its installation witness, which detects a database restored from a
    /// backup. Required: an absolute path (an empty one counts as none) of a persistent directory
    /// outside the state directory, the database's directory, the block store and the provider temp
    /// root (a start whose directory is inside one of them, symlinks resolved, fails) that no backup of it
    /// restores and the system does not purge (on iOS a separate directory in the app group's
    /// Application Support, excluded from backup; never Caches, which the system may purge). A
    /// start without one fails (`StartFailed`) rather than keeping the witness beside the
    /// database, where a restore would bring it back too. If the witness later goes missing while
    /// the database records one, the engine refuses to open the author identity
    /// (`database_restored:unverifiable`) instead of recording it again. Keep this directory and
    /// the database at one stable absolute path for the installation's life (in the app group, not
    /// the app's own container, whose path can change on update): a different path, or a witness
    /// kept elsewhere before, reads as a missing witness and is refused the same way. The way out of
    /// the refusal is `MobileHost::start_over`.
    pub witness_dir: Option<String>,
    /// An id of this installation, stable for its life (for example one the host generated and
    /// stored in its app group). Required on iOS: a start without it fails.
    pub machine_id: Option<String>,
}

impl From<EngineConfig> for host::EngineConfig {
    fn from(config: EngineConfig) -> Self {
        let config_dir = std::path::PathBuf::from(config.config_dir);
        let (backend, key_mirror) = match config.credential_keyring_scope {
            // Not validated here: an unusable scope is refused when the engine starts.
            Some(scope) => (
                host::CredentialBackend::Keyring { scope: Some(scope) },
                host::KeyMirror::OsKeyring,
            ),
            None => (
                host::CredentialBackend::File(config_dir.join("credentials.json")),
                host::KeyMirror::Disabled,
            ),
        };
        let mut credentials = host::CredentialConfig::new(backend, key_mirror);
        credentials.auth_server_addr = config.auth_server_addr;
        credentials.coordination_addr = config.coordination_addr;
        credentials.host_name = config.host_name;
        Self {
            credentials,
            config_dir,
            block_store_root: config.block_store_root.into(),
            sync_db_path: config.sync_db_path.into(),
            provider_temp_root: config.provider_temp_root.map(Into::into),
            machine_id: config.machine_id,
            tuning: host::EngineTuning {
                // An empty string names nothing (it would be the process's working directory):
                // the same as none, and refused at start.
                witness: config
                    .witness_dir
                    .filter(|dir| !dir.is_empty())
                    .map_or(host::WitnessPlacement::Unset, |dir| {
                        host::WitnessPlacement::Persistent(dir.into())
                    }),
                ..host::EngineTuning::default()
            },
        }
    }
}

/// Where the host is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HostState {
    /// No engine exists. Nothing is open.
    Stopped,
    /// The engine runs.
    Running,
    /// The engine was torn down for the host's suspension and waits to be resumed.
    Suspended,
    /// The engine stopped but work it started is still running, so its data area stays
    /// locked. Call `stop` again to keep waiting.
    Stopping,
}

impl From<host::HostState> for HostState {
    fn from(state: host::HostState) -> Self {
        match state {
            host::HostState::Stopped => Self::Stopped,
            host::HostState::Running => Self::Running,
            host::HostState::Suspended => Self::Suspended,
            host::HostState::Stopping => Self::Stopping,
        }
    }
}

/// Why a lifecycle call failed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum HostFailure {
    /// The call is not allowed in the state the host is in.
    #[error("cannot {operation} while {state:?}")]
    WrongState { operation: String, state: HostState },
    /// Another engine of this process already runs over this database.
    #[error("an engine is already running over {path}")]
    AlreadyRunning { path: String },
    /// Another engine of this process runs over a different state directory and both would
    /// use the same credential entry. Stop the other engine first.
    #[error("an engine over {running} already runs in this process and {requested} would share its credential store")]
    SharedCredentialStore { running: String, requested: String },
    /// The engine did not start for another reason; the message says what to do.
    #[error("{message}")]
    StartFailed { message: String },
    /// The engine's runtime could not be built.
    #[error("{message}")]
    Runtime { message: String },
    /// The engine's blocking work has not finished, so its data area is still locked and the
    /// host is `Stopping`. Call `stop` again to keep waiting.
    #[error("the engine's blocking work is still running; the data area stays locked")]
    Draining,
    /// The provider channel is closed: the engine stopped or the channel was closed.
    #[error("the provider channel is closed")]
    Closed,
}

impl From<host::HostError> for HostFailure {
    fn from(error: host::HostError) -> Self {
        use host::{HostError, StartError};
        match error {
            HostError::WrongState { operation, state } => {
                Self::WrongState { operation: operation.to_owned(), state: state.into() }
            }
            HostError::Start(StartError::AlreadyRunning(path)) => {
                Self::AlreadyRunning { path: path.display().to_string() }
            }
            HostError::Start(StartError::SharedCredentialStore { running, requested }) => {
                Self::SharedCredentialStore {
                    running: running.display().to_string(),
                    requested: requested.display().to_string(),
                }
            }
            HostError::Start(
                other @ (StartError::Other(_)
                | StartError::WitnessPlacementRequired
                | StartError::WitnessDirUnusable(_)),
            ) => Self::StartFailed { message: other.to_string() },
            HostError::Runtime(error) => Self::Runtime { message: error.to_string() },
            HostError::Draining => Self::Draining,
            HostError::Closed => Self::Closed,
        }
    }
}

/// Why a command call did not return the command's output.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CallFailure {
    /// The host is not running an engine.
    #[error("{message}")]
    NotRunning { message: String },
    /// The cancel handle was used before, by another call.
    #[error("the cancel handle already belongs to a call")]
    HandleUsed,
    /// The caller cancelled. `still_running`: the command changes state and was left to
    /// finish; read the state (`list_folders`) to find the outcome.
    #[error("the call was cancelled{}", if *.still_running { "; the command is still running" } else { "" })]
    Cancelled { still_running: bool },
    /// The deadline passed. `still_running` as for `Cancelled`.
    #[error("the call ran out of time{}", if *.still_running { "; the command is still running" } else { "" })]
    DeadlineExceeded { still_running: bool },
    /// The engine stopped before the command finished.
    #[error("the engine stopped before the command finished")]
    EngineStopped,
    /// The build has no OS folder watcher, so an ordinary folder cannot be linked: link a
    /// provider folder instead. Nothing was changed.
    #[error("{message}")]
    NoChangeSource { message: String },
    /// The engine refused the command with a reason the app acts on; nothing was changed.
    /// `operation_id` names the enrollment operation to recover or retry, when the refusal
    /// concerns one (empty otherwise).
    #[error("{message}")]
    Refused { code: RefusalCode, message: String, operation_id: String },
    /// A preserved item's own refusal.
    #[error("{message}")]
    PreservedRefused { reason: PreservedRefusal, message: String },
    /// An account command failed.
    #[error("{}", .error.message)]
    Account { error: AccountError },
    /// The command ran and failed; the message says what to do.
    #[error("{message}")]
    Failed { message: String },
}

impl From<host::CallError> for CallFailure {
    fn from(error: host::CallError) -> Self {
        use host::{CallError, CommandErrorKind};
        match error {
            CallError::Host(message) => Self::NotRunning { message },
            CallError::HandleUsed => Self::HandleUsed,
            CallError::Cancelled { still_running } => Self::Cancelled { still_running },
            CallError::DeadlineExceeded { still_running } => {
                Self::DeadlineExceeded { still_running }
            }
            CallError::EngineStopped => Self::EngineStopped,
            CallError::Failed(failed) => {
                let message = failed.message().to_owned();
                match failed.kind() {
                    CommandErrorKind::NoChangeSource => Self::NoChangeSource { message },
                    CommandErrorKind::Refused(code) => Self::Refused {
                        code: code.into(),
                        message,
                        operation_id: failed.operation_id().to_owned(),
                    },
                    CommandErrorKind::Preserved(reason) => {
                        Self::PreservedRefused { reason: reason.into(), message }
                    }
                    CommandErrorKind::Failed => Self::Failed { message },
                }
            }
            CallError::Account(error) => Self::Account { error: (*error).into() },
        }
    }
}

/// Why a provider channel call failed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ChannelFailure {
    /// The channel is closed: the engine stopped or `close` was called.
    #[error("the provider channel is closed")]
    Closed,
    /// The bytes are not one encoded provider message.
    #[error("not a provider message: {message}")]
    InvalidMessage { message: String },
}

/// Cancels one command call. One handle belongs to one call.
#[derive(uniffi::Object)]
pub struct CancelHandle {
    inner: host::CancelHandle,
}

#[uniffi::export]
impl CancelHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: host::CancelHandle::new() })
    }

    /// Cancels the call this handle belongs to, or the call it is given to later (which then
    /// returns `Cancelled` without starting its command). Returns at once.
    pub fn cancel(&self) {
        self.inner.cancel();
    }
}

pub(crate) fn options(cancel: &CancelHandle, deadline_ms: Option<u64>) -> host::CallOptions {
    host::CallOptions {
        deadline: deadline_ms.map(Duration::from_millis),
        cancel: cancel.inner.clone(),
    }
}

/// Link a folder to a replica group.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LinkFolderRequest {
    pub local_path: String,
    pub group_id: String,
    /// Keep content in the cloud and fetch it on open.
    pub on_demand: bool,
    /// The user confirmed the risks the preflight finds in this folder.
    pub acknowledge_risks: bool,
}

/// Restore a file to one of its earlier versions.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RestoreVersionRequest {
    pub group_id: String,
    pub path: String,
    /// The version to restore; the most recent superseded one when `None`.
    pub version_seq: Option<i64>,
}

/// One linked folder as the host shows it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LinkedFolder {
    /// The link's identity key: a path for a folder, a locator for a provider folder.
    pub key: String,
    pub group_id: String,
    pub paused: bool,
    pub conflict_count: u64,
    pub hydrated_count: u64,
    pub placeholder_count: u64,
    /// Why the folder is degraded, when it is.
    pub degraded: Option<String>,
}

impl From<host::LinkedFolder> for LinkedFolder {
    fn from(folder: host::LinkedFolder) -> Self {
        Self {
            key: folder.key,
            group_id: folder.group_id,
            paused: folder.paused,
            conflict_count: folder.conflict_count,
            hydrated_count: folder.hydrated_count,
            placeholder_count: folder.placeholder_count,
            degraded: folder.degraded,
        }
    }
}

/// Whether this build can link an ordinary folder. False on the mobile build, which has no
/// OS folder watcher: link provider folders.
#[uniffi::export]
#[must_use]
pub fn ordinary_folder_links_supported() -> bool {
    host::ordinary_folder_links_supported()
}

/// The engine and its lifecycle, for one data area.
#[derive(uniffi::Object)]
pub struct MobileHost {
    pub(crate) inner: host::EmbeddedHost,
}

#[uniffi::export]
impl MobileHost {
    /// A host over `config`, with no engine running. Performs no I/O.
    #[uniffi::constructor]
    pub fn new(config: EngineConfig) -> Arc<Self> {
        Arc::new(Self { inner: host::EmbeddedHost::new(config.into()) })
    }

    /// The state the host is in.
    pub fn state(&self) -> HostState {
        self.inner.state().into()
    }

    /// Starts the engine. Allowed when stopped; blocks until it is up.
    ///
    /// # Errors
    /// `StartFailed`, `AlreadyRunning` or `SharedCredentialStore` when the engine does not
    /// come up (the host stays stopped), `WrongState` otherwise.
    pub fn start(&self) -> Result<(), HostFailure> {
        Ok(self.inner.start()?)
    }

    /// Tears the engine down completely for the host's suspension: databases checkpointed
    /// and closed, nothing left open. Allowed when running; blocks until done.
    ///
    /// # Errors
    /// `Draining` when the engine's blocking work did not end in time (call `stop` again),
    /// `WrongState` unless running.
    pub fn suspend(&self) -> Result<(), HostFailure> {
        Ok(self.inner.suspend()?)
    }

    /// Starts the engine again over the same data. Allowed when suspended.
    ///
    /// # Errors
    /// `StartFailed` and its kin (the host stays suspended, so the call can be retried),
    /// `WrongState` unless suspended.
    pub fn resume(&self) -> Result<(), HostFailure> {
        Ok(self.inner.resume()?)
    }

    /// Stops the engine. Allowed in any state; stopping a stopped host does nothing, and a
    /// host that is still `Stopping` waits for its drain again.
    ///
    /// # Errors
    /// `Draining` when the engine's blocking work did not end in time.
    pub fn stop(&self) -> Result<(), HostFailure> {
        Ok(self.inner.stop()?)
    }

    /// Opens a provider channel to the running engine.
    ///
    /// # Errors
    /// `WrongState` unless running.
    pub fn open_provider_channel(&self) -> Result<Arc<ProviderChannel>, HostFailure> {
        let channel = self.inner.open_provider_channel()?;
        let (closed, _) = watch::channel(false);
        Ok(Arc::new(ProviderChannel { channel: Mutex::new(Some(Arc::new(channel))), closed }))
    }

    /// Links a folder. Blocks until done, cancelled or out of time.
    ///
    /// # Errors
    /// `NoChangeSource` for an ordinary folder (nothing was changed), and the other
    /// [`CallFailure`] cases.
    pub fn link_folder(
        &self,
        request: LinkFolderRequest,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        let command = host::Command::LinkFolder(host::LinkFolder {
            local_path: request.local_path,
            group_id: request.group_id,
            on_demand: request.on_demand,
            acknowledge_risks: request.acknowledge_risks,
        });
        match self.inner.execute(command, &options(cancel, deadline_ms))? {
            host::CommandOutput::Linked => Ok(()),
            other => unreachable!("link_folder returned {other:?}"),
        }
    }

    /// Restores a file to one of its earlier versions. Returns whether a version was
    /// restored: false when there was no earlier version. Blocks until done, cancelled or
    /// out of time.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn restore_version(
        &self,
        request: RestoreVersionRequest,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<bool, CallFailure> {
        let command = host::Command::RestoreVersion(host::RestoreVersion {
            group_id: request.group_id,
            path: request.path,
            version_seq: request.version_seq,
        });
        match self.inner.execute(command, &options(cancel, deadline_ms))? {
            host::CommandOutput::Restored(restored) => Ok(restored),
            other => unreachable!("restore_version returned {other:?}"),
        }
    }

    /// Lists the linked folders. Read-only, so cancelling it aborts it.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn list_folders(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<LinkedFolder>, CallFailure> {
        match self.inner.execute(host::Command::ListFolders, &options(cancel, deadline_ms))? {
            host::CommandOutput::Folders(folders) => {
                Ok(folders.into_iter().map(Into::into).collect())
            }
            other => unreachable!("list_folders returned {other:?}"),
        }
    }
}

/// The host's end of the provider channel: messages of the provider protocol, each encoded
/// as one `yadorilink.shellipc.v1.ShellIpcMessage` (`shellipc.proto`), without a length
/// prefix.
#[derive(uniffi::Object)]
pub struct ProviderChannel {
    channel: Mutex<Option<Arc<host::ProviderChannel>>>,
    closed: watch::Sender<bool>,
}

impl ProviderChannel {
    fn open(&self) -> Option<Arc<host::ProviderChannel>> {
        self.channel.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

#[uniffi::export]
impl ProviderChannel {
    /// Sends one encoded message. Waits while the engine's queue is full.
    ///
    /// # Errors
    /// `InvalidMessage` when `message` does not decode (nothing was sent), `Closed` when the
    /// engine stopped or the channel was closed.
    pub async fn send(&self, message: Vec<u8>) -> Result<(), ChannelFailure> {
        let message = ShellIpcMessage::decode(message.as_slice())
            .map_err(|error| ChannelFailure::InvalidMessage { message: error.to_string() })?;
        let channel = self.open().ok_or(ChannelFailure::Closed)?;
        let mut closed = self.closed.subscribe();
        tokio::select! {
            sent = channel.send(message) => sent.map_err(|_| ChannelFailure::Closed),
            _ = closed.wait_for(|closed| *closed) => Err(ChannelFailure::Closed),
        }
    }

    /// Waits for the next encoded message; `None` once the channel is closed (the engine
    /// stopped or `close` was called) and drained.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        let channel = self.open()?;
        let mut closed = self.closed.subscribe();
        tokio::select! {
            message = channel.recv() => message.map(|message| message.encode_to_vec()),
            _ = closed.wait_for(|closed| *closed) => None,
        }
    }

    /// Closes the channel: a waiting `recv` returns `None`, later calls fail with `Closed`,
    /// and the engine side ends. Safe to call more than once.
    pub fn close(&self) {
        self.closed.send_replace(true);
        self.channel.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    }
}

mod app;
pub use app::*;

#[cfg(test)]
mod tests;
