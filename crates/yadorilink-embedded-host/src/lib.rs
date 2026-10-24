//! The engine embedded in a host process, with an explicit lifecycle.
//!
//! [`EmbeddedHost`] owns one engine at a time and the tokio runtime it runs on. The host
//! moves it through [`HostState`] with [`EmbeddedHost::start`], [`EmbeddedHost::suspend`],
//! [`EmbeddedHost::resume`] and [`EmbeddedHost::stop`], and talks to it over an in-process
//! [`ProviderChannel`]. Nothing here opens a socket, installs a signal handler or holds a
//! lock across calls.
//!
//! Suspend and stop both tear the engine down completely: databases checkpointed and closed,
//! tasks ended, the runtime dropped. A process that is suspended may be killed at any moment,
//! so it must hold nothing open while suspended. The two differ in what the host may do next:
//! a suspended host is resumed, a stopped one is started.
//!
//! Giving up the data area is the last step of a teardown, after every task and blocking worker
//! the engine started has ended. If they do not end within the drain bound, the host stays
//! [`HostState::Stopping`] with the data area still locked and the call returns
//! [`HostError::Draining`]; calling [`EmbeddedHost::stop`] again waits again.
//!
//! The lifecycle calls block until the transition is done, so they must not be called from
//! inside an async runtime.

mod account;
mod commands;
mod log_sink;
mod start_over;

/// The product types the account and status commands return.
pub use yadorilink_client_core::dto;

pub use account::{
    AccountCommand, AccountDeletionImpact, AccountDeletionRequest, AccountDeletionStatus,
    AccountStatus, BeginSignIn, DeviceRegistration, LoginEvent, NotRejoined, PollSignIn,
    SignInCancellation, SignInId, SignInStep, SignOutOutcome, StartOverProgress, StartOverReport,
};
pub use commands::{
    ordinary_folder_links_supported, CallError, CallOptions, CancelHandle, Command, CommandError,
    CommandErrorKind, CommandOutput, CreateShare, DesktopError, DoctorCheck, DoctorStatus,
    HandoffInfo, JoinGroup, JoinShare, LinkFolder, LinkedFolder, PauseFor, PauseLink,
    PreservedItem, PreservedKind, PreservedRef, PreservedRefusal, ProviderFolder, RestoreVersion,
    ResumeLink, ShareFolder, ShareOutcome, SpaceManagement, UnlinkFolder, UnlinkOutcome,
};

/// The one parser for invite links and codes, and the reason a permission refusal carries.
pub use yadorilink_client_core::error::{PermissionDeniedReason, RefusalReason};
pub use yadorilink_client_core::wording::{parse_invite_input, InviteLinkError};

pub use log_sink::{install_log_sink, LogLevel, LogSink, LogSinkError};

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;
pub use yadorilink_daemon::embedded_host::{
    CredentialBackend, CredentialConfig, EngineConfig, EngineTuning, KeyMirror, ReleaseProbe,
    StartError, WitnessPlacement,
};
use yadorilink_daemon::embedded_host::{Engine, Held};
pub use yadorilink_ipc_proto::shellipc::ShellIpcMessage;

/// Worker threads of the engine's runtime: a mobile host has little to spare.
const WORKER_THREADS: usize = 2;

/// How long a teardown waits for the engine's blocking work before reporting that it is still
/// draining.
const DEFAULT_DRAIN: Duration = Duration::from_secs(30);

/// Messages a provider channel queues in each direction before it applies back-pressure.
const CHANNEL_QUEUE: usize = 64;

/// Where the host is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    /// No engine exists. Nothing is open.
    Stopped,
    /// The engine runs.
    Running,
    /// The engine was torn down for the host's suspension and waits to be resumed.
    Suspended,
    /// The engine stopped but work it started is still running, so its data area stays locked.
    Stopping,
}

/// Why a host call failed.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The call is not allowed in the state the host is in.
    #[error("cannot {operation} while {state:?}")]
    WrongState { operation: &'static str, state: HostState },
    /// The engine did not start; the host is still in the state it was in.
    #[error(transparent)]
    Start(#[from] StartError),
    /// The runtime could not be built.
    #[error("could not build the engine's runtime: {0}")]
    Runtime(std::io::Error),
    /// The engine's blocking work has not finished, so its data area is still locked and the
    /// host is [`HostState::Stopping`]. Call [`EmbeddedHost::stop`] again to keep waiting.
    #[error("the engine's blocking work is still running; the data area stays locked")]
    Draining,
    /// The channel is closed: the engine stopped or the other side went away.
    #[error("the provider channel is closed")]
    Closed,
}

struct Running {
    runtime: Runtime,
    engine: Engine,
    /// The account commands of this engine; its sign-in ends with it.
    accounts: Arc<account::AccountCommands>,
}

/// A stopped engine whose runtime is still being dropped on another thread: dropping a runtime
/// waits for every blocking closure it runs, however long they take.
struct Draining {
    held: Held,
    done: std::sync::mpsc::Receiver<()>,
}

impl Draining {
    /// Releases the data area once the runtime is gone, or gives `self` back if it is not gone
    /// within `bound`.
    fn settle(self, bound: Duration) -> Result<(), Box<Self>> {
        match self.done.recv_timeout(bound) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(Box::new(self)),
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // The data area is given up last, once nothing the engine started can touch it.
                drop(self.held);
                Ok(())
            }
        }
    }
}

impl Running {
    /// Stops the engine within `bound`, then drops the runtime on a helper thread, which ends
    /// everything the engine's services detached and waits for its blocking work. The data
    /// area is kept through all of it, and the stop and the drain share one deadline.
    fn tear_down(self, bound: Duration) -> Result<(), Box<Draining>> {
        let deadline = Instant::now() + bound;
        let engine = self.engine;
        // Whether or not the stop finished in time, the data area is kept (below).
        let _ = self.runtime.block_on(async { tokio::time::timeout(bound, engine.stop()).await });
        let held = engine.into_held();
        let (done_tx, done) = std::sync::mpsc::channel();
        let runtime = self.runtime;
        std::thread::Builder::new()
            .name("yadorilink-engine-drain".into())
            .spawn(move || {
                drop(runtime);
                let _ = done_tx.send(());
            })
            .expect("the drain thread starts");
        let draining = Draining { held, done };
        // One deadline for the whole teardown: the stop and the drain share the bound.
        draining.settle(deadline.saturating_duration_since(Instant::now()))
    }
}

enum Phase {
    Stopped,
    Running(Box<Running>),
    Suspended,
    Draining(Box<Draining>),
}

impl Phase {
    fn state(&self) -> HostState {
        match self {
            Self::Stopped => HostState::Stopped,
            Self::Running(_) => HostState::Running,
            Self::Suspended => HostState::Suspended,
            Self::Draining(_) => HostState::Stopping,
        }
    }
}

/// Debug check of the bounded-session rule, run as each host call returns: a call must not hand
/// control back to the host while its thread is inside a SQLite write transaction. The other
/// half, that a host which stopped or suspended holds no lock of its own on its data area (the OS may kill
/// a suspended process that holds a lock on a file in a shared container), is
/// [`EmbeddedHost::assert_released`], run where `suspend` and `stop` succeed.
///
/// Created first in a public call, so it drops last, after the call has released the phase.
struct BoundedSession {
    operation: &'static str,
}

impl Drop for BoundedSession {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        debug_assert!(
            !yadorilink_sqlite_runtime::current_thread_in_write_transaction(),
            "{} returned to the host inside a SQLite write transaction",
            self.operation
        );
    }
}

/// An engine and its lifecycle, for one data area.
pub struct EmbeddedHost {
    config: EngineConfig,
    drain: Duration,
    sign_in: account::SignInFactory,
    /// The next sign-in id; it only grows for the life of the host, across engine restarts.
    sign_in_ids: Arc<std::sync::atomic::AtomicU64>,
    phase: Mutex<Phase>,
}

impl EmbeddedHost {
    /// A host over `config`, with no engine running.
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        let sign_in = account::product_sign_in(account::credential_settings(&config.credentials));
        Self {
            config,
            drain: DEFAULT_DRAIN,
            sign_in,
            sign_in_ids: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            phase: Mutex::new(Phase::Stopped),
        }
    }

    /// Replaces the sign-in sessions the account commands start. For tests that script a sign-in.
    #[doc(hidden)]
    #[must_use]
    pub fn with_sign_in_for_test(
        mut self,
        sign_in: impl Fn(
                std::path::PathBuf,
                yadorilink_client_core::dto::LoginOptions,
                bool,
            ) -> Arc<yadorilink_client_core::session::LoginSession>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.sign_in = Arc::new(sign_in);
        self
    }

    /// Changes how long a teardown waits for the engine's blocking work before it reports
    /// [`HostError::Draining`].
    #[must_use]
    pub fn with_drain_bound(mut self, bound: Duration) -> Self {
        self.drain = bound;
        self
    }

    fn phase(&self) -> std::sync::MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The lifecycle lock for a command call: waits for it only as long as the call's handle
    /// and deadline allow, so a pre-cancelled call or a short deadline never sits through
    /// another thread's start, suspend or stop. The wait counts against the call's deadline.
    fn phase_within(
        &self,
        options: &CallOptions,
        start: std::time::Instant,
    ) -> Result<std::sync::MutexGuard<'_, Phase>, CallError> {
        loop {
            if let Some(reason) = options.interrupted(start) {
                return Err(reason);
            }
            match self.phase.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    return Ok(poisoned.into_inner())
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    fn bounded(operation: &'static str) -> BoundedSession {
        BoundedSession { operation }
    }

    /// Debug check that a successful `suspend` or `stop` left this host holding nothing: the
    /// engine's `Held` (its OS locks and place in the process) lives only in the running and
    /// draining phases. It inspects the settled phase through the guard the call still holds,
    /// so another thread's `start` cannot slip in between; another host or process owning the
    /// data area is never inspected.
    fn assert_released(operation: &str, phase: &Phase) {
        debug_assert!(
            matches!(phase, Phase::Stopped | Phase::Suspended),
            "{operation} returned while this host still holds its data area"
        );
    }

    /// The state the host is in.
    #[must_use]
    pub fn state(&self) -> HostState {
        self.phase().state()
    }

    fn launch(&self) -> Result<Running, HostError> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(WORKER_THREADS)
            .thread_name("yadorilink-engine")
            .enable_all()
            .build()
            .map_err(HostError::Runtime)?;
        match runtime.block_on(Engine::start(self.config.clone())) {
            Ok(engine) => {
                let accounts = Arc::new(account::AccountCommands::new(
                    self.config.config_dir.clone(),
                    account::credential_settings(&self.config.credentials),
                    self.sign_in.clone(),
                    self.sign_in_ids.clone(),
                ));
                Ok(Running { runtime, engine, accounts })
            }
            Err(error) => {
                drop(runtime);
                Err(error.into())
            }
        }
    }

    fn wrong_state(operation: &'static str, state: HostState) -> HostError {
        HostError::WrongState { operation, state }
    }

    /// Starts the engine. Allowed when stopped.
    ///
    /// # Errors
    /// [`HostError::Start`] when the engine does not come up; the host stays stopped and has
    /// left nothing running.
    pub fn start(&self) -> Result<(), HostError> {
        let _bounded = Self::bounded("start");
        let mut phase = self.phase();
        match &*phase {
            Phase::Stopped => {
                *phase = Phase::Running(Box::new(self.launch()?));
                Ok(())
            }
            other => Err(Self::wrong_state("start", other.state())),
        }
    }

    /// Suspends the host: ends the engine's provider channels, tears it down completely and
    /// waits for [`Self::resume`]. Allowed when running.
    ///
    /// # Errors
    /// [`HostError::WrongState`] unless running.
    pub fn suspend(&self) -> Result<(), HostError> {
        let _bounded = Self::bounded("suspend");
        let mut phase = self.phase();
        match std::mem::replace(&mut *phase, Phase::Suspended) {
            Phase::Running(running) => match running.tear_down(self.drain) {
                Ok(_) => {
                    Self::assert_released("suspend", &phase);
                    Ok(())
                }
                Err(draining) => {
                    *phase = Phase::Draining(draining);
                    Err(HostError::Draining)
                }
            },
            other => {
                let state = other.state();
                *phase = other;
                Err(Self::wrong_state("suspend", state))
            }
        }
    }

    /// Resumes a suspended host by starting the engine again over the same data. Allowed when
    /// suspended.
    ///
    /// # Errors
    /// [`HostError::Start`] when the engine does not come up; the host stays suspended, so
    /// the call can be retried.
    pub fn resume(&self) -> Result<(), HostError> {
        let _bounded = Self::bounded("resume");
        let mut phase = self.phase();
        match &*phase {
            Phase::Suspended => {
                *phase = Phase::Running(Box::new(self.launch()?));
                Ok(())
            }
            other => Err(Self::wrong_state("resume", other.state())),
        }
    }

    /// Stops the engine. Allowed in any state; stopping a stopped host does nothing. On a host
    /// that is still draining, waits for the drain again.
    ///
    /// # Errors
    /// [`HostError::Draining`] when the engine's blocking work did not finish within the drain
    /// bound; the data area stays locked and the host is [`HostState::Stopping`]. A suspend
    /// that drains too long ends the same way: stop, then start again.
    pub fn stop(&self) -> Result<(), HostError> {
        let _bounded = Self::bounded("stop");
        let mut phase = self.phase();
        let outcome = match std::mem::replace(&mut *phase, Phase::Stopped) {
            Phase::Running(running) => running.tear_down(self.drain),
            Phase::Draining(draining) => draining.settle(self.drain),
            settled @ (Phase::Stopped | Phase::Suspended) => {
                drop(settled);
                Ok(())
            }
        };
        match outcome {
            Ok(_) => {
                Self::assert_released("stop", &phase);
                Ok(())
            }
            Err(draining) => {
                *phase = Phase::Draining(draining);
                Err(HostError::Draining)
            }
        }
    }

    /// Opens a provider channel to the running engine.
    ///
    /// # Errors
    /// [`HostError::WrongState`] unless running.
    pub fn open_provider_channel(&self) -> Result<ProviderChannel, HostError> {
        let _bounded = Self::bounded("open_provider_channel");
        let phase = self.phase();
        let Phase::Running(running) = &*phase else {
            return Err(Self::wrong_state("open a provider channel", phase.state()));
        };
        let _in_engine_runtime = running.runtime.enter();
        let stream = running.engine.open_provider_channel();
        let (mut read, mut write) = tokio::io::split(stream);
        let (outgoing, mut to_write) = mpsc::channel::<ShellIpcMessage>(CHANNEL_QUEUE);
        let (from_read, incoming) = mpsc::channel::<ShellIpcMessage>(CHANNEL_QUEUE);
        // The channel's two pumps run on the engine's runtime, so that waiting for a message
        // is cancel-safe on the host's side: a dropped `recv` loses no half-read frame.
        running.runtime.spawn(async move {
            while let Ok(Some(message)) =
                yadorilink_ipc_proto::framing::read_message::<ShellIpcMessage>(&mut read).await
            {
                if from_read.send(message).await.is_err() {
                    return;
                }
            }
        });
        running.runtime.spawn(async move {
            while let Some(message) = to_write.recv().await {
                if yadorilink_ipc_proto::framing::write_message(&mut write, &message).await.is_err()
                {
                    return;
                }
            }
            let _ = write.shutdown().await;
        });
        Ok(ProviderChannel { outgoing, incoming: tokio::sync::Mutex::new(incoming) })
    }

    /// Runs one application command and waits for it, bounded by `options`: its deadline and
    /// its cancel handle. See [`CallOptions`] and the module docs of what cancelling means.
    /// Calls from different threads run concurrently, and a lifecycle call is not held up by
    /// one that is waiting.
    ///
    /// # Errors
    /// [`CallError`]: the host is not running, the call was cancelled or ran out of time, the
    /// engine stopped, or the command failed.
    pub fn execute(
        &self,
        command: Command,
        options: &CallOptions,
    ) -> Result<CommandOutput, CallError> {
        let _bounded = Self::bounded("execute");
        let start = std::time::Instant::now();
        let read_only = commands::is_read_only(&command);
        // Submitted while the lifecycle lock is held: the engine's services the command owns
        // become a task of the engine's runtime before any stop can begin, and a stop drops that
        // runtime, and the task with it, before it gives up the data area. Nothing of the
        // engine is held while waiting below.
        let submitted = {
            let phase = self.phase_within(options, start)?;
            let Phase::Running(running) = &*phase else {
                return Err(Self::wrong_state("run a command", phase.state()).into());
            };
            commands::submit_command(
                running.runtime.handle(),
                running.engine.commands(),
                running.accounts.clone(),
                command,
                options,
                start,
            )?
        };
        submitted.wait(options, read_only, start)
    }

    /// Tells whether the running engine's state has been released; see [`ReleaseProbe`].
    ///
    /// # Errors
    /// [`HostError::WrongState`] unless running.
    pub fn release_probe(&self) -> Result<ReleaseProbe, HostError> {
        let _bounded = Self::bounded("release_probe");
        let phase = self.phase();
        match &*phase {
            Phase::Running(running) => Ok(running.engine.release_probe()),
            other => Err(Self::wrong_state("probe the engine", other.state())),
        }
    }
}

impl EmbeddedHost {
    /// Whether a link runtime runs for `folder`. For tests of the startup phases.
    #[doc(hidden)]
    pub fn has_link_runtime_for_test(&self, folder: &str) -> Result<bool, HostError> {
        let phase = self.phase();
        let Phase::Running(running) = &*phase else {
            return Err(Self::wrong_state("inspect links", phase.state()));
        };
        Ok(running.engine.has_link_runtime_for_test(folder))
    }

    /// Adds a link row to the running engine's database. For tests of what runs over links.
    #[doc(hidden)]
    pub fn add_link_row_for_test(
        &self,
        key: &str,
        group_id: &str,
        on_demand: bool,
    ) -> Result<(), HostError> {
        let phase = self.phase();
        let Phase::Running(running) = &*phase else {
            return Err(Self::wrong_state("add a link row", phase.state()));
        };
        running.engine.add_link_row_for_test(key, group_id, on_demand);
        Ok(())
    }

    /// Makes the running engine's next stop wait for `release`. For tests of a stop that does
    /// not finish.
    #[doc(hidden)]
    pub fn stall_stop_for_test(
        &self,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Result<(), HostError> {
        let phase = self.phase();
        let Phase::Running(running) = &*phase else {
            return Err(Self::wrong_state("stall the stop", phase.state()));
        };
        running.engine.stall_stop_for_test(release);
        Ok(())
    }

    /// Points the running engine's coordination calls at `addr`. For tests that serve the
    /// coordination plane in process.
    #[doc(hidden)]
    pub fn set_coordination_for_test(
        &self,
        addr: String,
        auth: yadorilink_fapi_client::CoordinationAuth,
    ) -> Result<(), HostError> {
        let phase = self.phase();
        let Phase::Running(running) = &*phase else {
            return Err(Self::wrong_state("set the coordination plane", phase.state()));
        };
        running.engine.set_coordination_for_test(addr, auth);
        Ok(())
    }

    /// Runs `work` on the running engine's blocking pool. For tests of the drain.
    #[doc(hidden)]
    pub fn spawn_blocking_for_test(
        &self,
        work: impl FnOnce() + Send + 'static,
    ) -> Result<(), HostError> {
        let phase = self.phase();
        let Phase::Running(running) = &*phase else {
            return Err(Self::wrong_state("run blocking work", phase.state()));
        };
        drop(running.runtime.spawn_blocking(work));
        Ok(())
    }
}

impl EmbeddedHost {
    /// Runs `work` as a command on the running engine's runtime. For tests of the call bounds.
    #[doc(hidden)]
    pub fn execute_for_test(
        &self,
        read_only: bool,
        work: impl std::future::Future<Output = Result<CommandOutput, CommandError>> + Send + 'static,
        options: &CallOptions,
    ) -> Result<CommandOutput, CallError> {
        self.execute_owning_for_test(read_only, || {}, |_| work, options)
    }

    /// Like [`Self::execute_for_test`], with the engine's commands handed to `make_work` (which
    /// moves them into the work, as a real command does) and `before_submit` run in the window
    /// between obtaining them and submitting the work. For tests of what a stop does then.
    #[doc(hidden)]
    pub fn execute_owning_for_test<W>(
        &self,
        read_only: bool,
        before_submit: impl FnOnce(),
        make_work: impl FnOnce(yadorilink_daemon::embedded_host::EngineCommands) -> W,
        options: &CallOptions,
    ) -> Result<CommandOutput, CallError>
    where
        W: std::future::Future<Output = Result<CommandOutput, CommandError>> + Send + 'static,
    {
        let start = std::time::Instant::now();
        let submitted = {
            let phase = self.phase_within(options, start)?;
            let Phase::Running(running) = &*phase else {
                return Err(Self::wrong_state("run a command", phase.state()).into());
            };
            let work = make_work(running.engine.commands());
            before_submit();
            commands::submit(running.runtime.handle(), options, start, async move {
                work.await.map_err(commands::Failure::from)
            })?
        };
        submitted.wait(options, read_only, start)
    }
}

impl Drop for EmbeddedHost {
    fn drop(&mut self) {
        // A dropped host cannot report: it waits for the drain as long as it takes, because
        // releasing the data area earlier would let another engine in under the old one.
        while self.stop().is_err() {}
    }
}

/// The host's end of an in-process provider channel: the framed provider protocol the
/// desktop daemon serves on its shell socket, without a socket.
pub struct ProviderChannel {
    outgoing: mpsc::Sender<ShellIpcMessage>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<ShellIpcMessage>>,
}

impl ProviderChannel {
    /// Sends one message. Both this and [`Self::recv`] are cancel-safe: dropping the future
    /// loses no message and leaves the channel usable, so the caller applies its own deadline.
    ///
    /// # Errors
    /// [`HostError::Closed`] when the engine stopped.
    pub async fn send(&self, message: ShellIpcMessage) -> Result<(), HostError> {
        self.outgoing.send(message).await.map_err(|_| HostError::Closed)
    }

    /// Waits for the next message; `None` once the channel is closed and drained.
    pub async fn recv(&self) -> Option<ShellIpcMessage> {
        self.incoming.lock().await.recv().await
    }
}
