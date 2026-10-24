// apple-cfg-file: macos-only App Group shell socket of the macOS daemon
//! Long-running sync daemon: loads persistent local state,
//! opens the CLI control socket, and — once logged in and registered —
//! connects to the coordination plane's netmap and establishes peer sync
//! sessions.
//!
//! The whole daemon lifecycle lives here in the library, behind
//! [`run`], rather than inline in `main.rs`. `main.rs` is now only a thin
//! entry point that builds the real (production) tokio runtime and calls
//! [`run`]; keeping the lifecycle in the library is what lets a test drive
//! an in-process daemon instance by calling [`run`] with its own
//! [`DaemonConfig`] directly, instead of going through the real process
//! entry point.
//!
//! Every essential task (control socket, shell-integration IPC,
//! peer orchestrator) is supervised together in one [`EssentialTasks`] set
//! at the bottom of [`run`] — if *any* of them exits or panics, the daemon
//! logs it clearly and exits non-zero so a process supervisor restarts it,
//! instead of coupling liveness solely to the control socket (the old
//! `control_socket_task.await?`) and silently continuing as a zombie with
//! broken sync. The same top-level `select!` also races that
//! against SIGTERM/SIGINT (and the control socket's `Shutdown` request,
//! routed in via `DaemonState::shutdown_tx`) to run a graceful shutdown
//! instead.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_local_storage::daemon_lock::LOCK_FILE_NAME as DAEMON_INSTANCE_LOCK_FILE;

use crate::control_socket;
use crate::daemon_state::DaemonState;
#[cfg(windows)]
use crate::device_config;
#[cfg(any(windows, all(unix, not(target_os = "ios"))))]
use crate::shell_ipc;
use crate::supervise::EssentialTasks;
use crate::{credential_store, peer_orchestrator};

/// Names used both for the essential-task logging and for
/// `DaemonState::task_liveness` (health surface) — kept as
/// constants so the two always agree.
const TASK_CONTROL_SOCKET: &str = "control-socket";
#[cfg(not(target_os = "ios"))]
const TASK_SHELL_IPC: &str = "shell-ipc-server";
const TASK_PEER_ORCHESTRATOR: &str = "peer-orchestrator";

/// Process-lifetime ownership of one config directory. The OS releases the
/// advisory lock when the process exits, including SIGKILL/crash paths; the
/// file itself deliberately remains so restart never relies on PID parsing or
/// stale-file deletion.
#[derive(Debug)]
struct DaemonInstanceLock {
    _file: std::fs::File,
}

impl DaemonInstanceLock {
    fn acquire(config_dir: &std::path::Path) -> anyhow::Result<Self> {
        use std::fs::OpenOptions;

        yadorilink_fs_platform::durable_dir::create_dir_all_durably(config_dir)?;
        let lock_path = config_dir.join(DAEMON_INSTANCE_LOCK_FILE);
        // `truncate(false)` is explicit, not incidental: this is a lock file,
        // never a content file, so an existing file's bytes (if any) are
        // irrelevant and must not be discarded just by opening it.
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))?;
        }
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Self { _file: file }),
            // Compared by raw OS error, not ErrorKind: see resource_lock.rs's
            // take_exclusive_lock doc comment for why ErrorKind::WouldBlock
            // does not reliably match Windows' real contention error.
            Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                anyhow::bail!(
                    "another YadoriLink daemon is already running for {}",
                    config_dir.display()
                )
            }
            Err(error) => Err(anyhow::anyhow!(
                "failed to acquire daemon instance lock {}: {error}",
                lock_path.display()
            )),
        }
    }
}

/// Turns away a daemon whose owner is not the data area's recorded one. The refusal is also
/// written where clients look for why the daemon is not running.
fn gate_ownership(
    identity: &crate::identity::RuntimeIdentity,
    config_dir: &std::path::Path,
) -> anyhow::Result<()> {
    if let Err(refusal) = identity.gate_start(config_dir) {
        let message = refusal.to_string();
        tracing::error!("{message}");
        if let Err(e) = yadorilink_local_storage::startup_refusal::record(config_dir, &message) {
            tracing::warn!(error = %e, "could not record the startup refusal");
        }
        return Err(refusal.into());
    }
    Ok(())
}

/// Filesystem locations the daemon operates over. Extracted from the
/// process environment for the real binary ([`DaemonConfig::from_env`]),
/// but passed in explicitly so a single OS process running many daemon
/// instances can give each its own isolated paths rather than sharing one
/// set of process-global environment variables / socket paths.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Base configuration directory; also where per-daemon config files
    /// (device config, metrics config, ...) are read from.
    pub config_dir: PathBuf,
    pub block_store_root: PathBuf,
    pub sync_db_path: PathBuf,
    /// The fixed directory provider items are handed to the OS in (`handoff/`), uploaded in
    /// (`ingest/`) and assembled in (`staging/`): the macOS app-group container's `provider`
    /// directory. `None` unless configured (`YADORILINK_PROVIDER_TEMP_ROOT`); otherwise the daemon adopts
    /// the container the host app reports through the shell socket (it knows no path of its own).
    pub provider_temp_root: Option<PathBuf>,
    #[cfg(unix)]
    pub control_socket_path: PathBuf,
    // apple-cfg: ios-explicit iOS has no shell socket: the host reaches the engine over in-memory
    // provider channels (`embedded_host`)
    #[cfg(all(unix, not(target_os = "ios")))]
    pub shell_ipc_socket_path: PathBuf,
    /// The engine's tuning and measurement settings, mapped once from the process environment
    /// (the only place the engine's `YADORILINK_*` switches are read).
    pub tuning: crate::engine_tuning::EngineTuning,
}

/// Where the shell IPC socket goes when `YADORILINK_SHELL_IPC_SOCKET` is not
/// set. On macOS, for an installed daemon (no `YADORILINK_CONFIG_DIR`
/// override), that is the App Group container the extensions' clients also
/// use, obtained from the OS (`app_group`); elsewhere it is next to the other
/// state. A macOS daemon the OS gives no container to cannot serve the
/// extensions at all, so that is a startup failure, not a guessed path.
#[cfg(all(unix, not(target_os = "ios")))]
fn default_shell_ipc_socket(config_dir: &std::path::Path) -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    if yadorilink_fs_platform::state_dir::Env::from_process().config_dir.is_none() {
        match crate::app_group::container_url(crate::app_group::MACOS_APP_GROUP) {
            Ok(container) => return crate::app_group::shell_socket_in(&container),
            Err(reason) => panic!("cannot place the shell IPC socket: {reason}"),
        }
    }
    config_dir.join("shell.sock")
}

impl DaemonConfig {
    /// Builds the configuration exactly as the real daemon binary always
    /// has: `config_dir()` plus the same `YADORILINK_*` environment
    /// overrides, each defaulting to a path under the config directory.
    ///
    /// # Errors
    /// The placement refusal of the state directory, or of any per-path override, when this
    /// process may not use it (a packaged process under AppData). Nothing has been created.
    pub fn from_env() -> Result<Self, yadorilink_fs_platform::state_dir::StateDirError> {
        Self::from_placement(&yadorilink_fs_platform::state_dir::Env::from_process())
    }

    /// [`Self::from_env`] over an explicit placement environment. Creates nothing.
    pub fn from_placement(
        env: &yadorilink_fs_platform::state_dir::Env,
    ) -> Result<Self, yadorilink_fs_platform::state_dir::StateDirError> {
        use yadorilink_fs_platform::state_dir::{
            checked_override, checked_state_dir, PathOverride,
        };
        let dir = checked_state_dir(env)?;

        let block_store_root =
            checked_override(env, PathOverride::BlockStore)?.unwrap_or_else(|| dir.join("blocks"));
        let sync_db_path = checked_override(env, PathOverride::SyncDb)?
            .unwrap_or_else(|| dir.join("sync-state.sqlite3"));
        // Every override is checked here, whoever reads it later (the witness, the credential
        // file, the log file), so a refused location stops the start before any state is created.
        for which in PathOverride::ALL {
            checked_override(env, which)?;
        }
        #[cfg(unix)]
        let control_socket_path = std::env::var("YADORILINK_CONTROL_SOCKET")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| dir.join("daemon.sock"));
        #[cfg(all(unix, not(target_os = "ios")))]
        let shell_ipc_socket_path = std::env::var("YADORILINK_SHELL_IPC_SOCKET")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| default_shell_ipc_socket(&dir));
        let provider_temp_root = checked_override(env, PathOverride::ProviderTempRoot)?;
        let mut tuning =
            crate::engine_tuning::EngineTuning::from_lookup(|name| std::env::var(name).ok());
        tuning.witness = match checked_override(env, PathOverride::WitnessDir)? {
            Some(dir) => crate::install_witness::WitnessPlacement::At(dir),
            None => {
                crate::install_witness::WitnessPlacement::platform(|name| std::env::var_os(name))
            }
        };
        Ok(Self {
            config_dir: dir,
            block_store_root,
            sync_db_path,
            provider_temp_root,
            #[cfg(unix)]
            control_socket_path,
            #[cfg(all(unix, not(target_os = "ios")))]
            shell_ipc_socket_path,
            tuning,
        })
    }
}

/// The engine's credential settings as the process environment selects them, read once by
/// [`run`]: the same `YADORILINK_CREDENTIAL_STORE`, `YADORILINK_CREDENTIAL_FILE`,
/// `YADORILINK_DISABLE_OS_KEYRING` and `YADORILINK_AUTH_SERVER_ADDR` the CLI reads.
///
/// # Errors
/// An unknown store name, or a credential file named while the OS keyring is selected.
pub fn credential_config_from_env(
    dir: &std::path::Path,
) -> Result<crate::credential_store::CredentialConfig, yadorilink_fapi_client::store::StoreError> {
    let backend = yadorilink_fapi_client::store::Backend::from_env(dir)?;
    let mut config = crate::credential_store::CredentialConfig::new(
        backend,
        yadorilink_transport::KeyMirror::from_env(),
    );
    config.auth_server_addr = std::env::var(AUTH_SERVER_ADDR_VAR).ok();
    Ok(config)
}

/// Arms the process-global measurement instruments of the lower crates from the diagnostic
/// environment variables. Their setters are called nowhere else, so an embedded host (which
/// never runs this) always gets the production behaviour.
fn arm_process_diagnostics() {
    let flag = |name: &str| std::env::var(name).as_deref() == Ok("1");
    if let Some(bytes) = std::env::var("YADORILINK_DIAGNOSTIC_QUEUE_BUDGET_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|&bytes| bytes > 0)
    {
        yadorilink_local_storage::chunker::set_durability_queue_byte_budget(Some(bytes));
    }
    yadorilink_local_storage::io_diag::set_block_read_probe(flag(
        "YADORILINK_DIAGNOSTIC_BLOCK_READ_PROBE",
    ));
    yadorilink_local_capture::diagnostics::set_force_fixed_chunking(flag(
        "YADORILINK_DIAGNOSTIC_FORCE_FIXED_CHUNKING",
    ));
    if let Some(ms) = std::env::var("YADORILINK_DIAGNOSTIC_SCAN_SNAPSHOT_DELAY_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
    {
        yadorilink_local_capture::diagnostics::set_snapshot_delay_ms(ms);
    }
}

/// Where this installation's Authorization Server lives, when not the stored credential's issuer.
const AUTH_SERVER_ADDR_VAR: &str = "YADORILINK_AUTH_SERVER_ADDR";

/// How a daemon that shut down gracefully ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEnd {
    /// Any ordinary stop: the process exits with status 0.
    Stopped,
    /// The executable-replaced watch's own safe stop committed: exit for a restart.
    RestartRequested,
}

impl RunEnd {
    /// The status the process must exit with instead of returning normally, if any.
    #[must_use]
    pub fn exit_status(self) -> Option<i32> {
        matches!(self, Self::RestartRequested).then_some(crate::exe_replaced::RESTART_EXIT_CODE)
    }
}

/// Runs the daemon to completion (graceful shutdown) or a fatal
/// essential-task death. This is the whole daemon lifecycle; `main` only
/// builds the real runtime and awaits this.
/// Release-only trust-root tripwire, run as the very first step of daemon
/// startup: a binary built with the `enforce-release-trust-root` feature
/// requires compile-time release public-key configuration and refuses to start
/// (hard error, before serving anything) if it is malformed or still pins the
/// forgeable development key, unless the explicit dev override is set.
/// Developer builds (feature off) compile this to a no-op and are unaffected. See
/// `update::manifest::enforce_release_trust_root_gate`.
#[cfg(feature = "enforce-release-trust-root")]
fn enforce_trust_root_gate_at_startup() -> anyhow::Result<()> {
    let override_value =
        std::env::var(crate::update::manifest::ALLOW_PLACEHOLDER_TRUST_ROOT_ENV).ok();
    crate::update::manifest::enforce_release_trust_root_gate(override_value.as_deref()).map_err(
        |reason| {
            anyhow::anyhow!(
                "refusing to start: update trust-root release gate rejected this build: {reason}"
            )
        },
    )
}

/// A boolean-flag-shaped env var is "set" (the flag is on) for any value
/// other than `0`/`false` (case-insensitive), including an empty string --
/// merely setting `YADORILINK_HTTP_API_DISABLE=` is treated as intent to
/// disable, not as an accidental no-op. Unset is always "not set". A pure
/// function over `std::env::var`'s own `Result` (rather than reading the
/// env var itself) so this convention is unit-testable without mutating
/// process-global env state.
fn env_disable_flag_is_set(value: Result<String, std::env::VarError>) -> bool {
    match value {
        Ok(v) => {
            let v = v.trim();
            !(v == "0" || v.eq_ignore_ascii_case("false"))
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod env_disable_flag_tests {
    use super::env_disable_flag_is_set;

    fn set(v: &str) -> Result<String, std::env::VarError> {
        Ok(v.to_string())
    }
    fn unset() -> Result<String, std::env::VarError> {
        Err(std::env::VarError::NotPresent)
    }

    #[test]
    fn unset_is_not_disabled() {
        assert!(!env_disable_flag_is_set(unset()));
    }

    #[test]
    fn merely_setting_it_including_empty_disables() {
        assert!(env_disable_flag_is_set(set("")));
        assert!(env_disable_flag_is_set(set("1")));
        assert!(env_disable_flag_is_set(set("yes")));
    }

    #[test]
    fn explicit_falsy_values_do_not_disable() {
        assert!(!env_disable_flag_is_set(set("0")));
        assert!(!env_disable_flag_is_set(set("false")));
        assert!(!env_disable_flag_is_set(set("False")));
        assert!(!env_disable_flag_is_set(set("FALSE")));
        assert!(!env_disable_flag_is_set(set(" 0 ")));
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "daemon startup sequence, and the sequence itself is the invariant: \
              instance lock -> device-config preflight -> signing-key validation -> \
              data-resource locks -> block store/DB open -> state wiring -> link \
              resumption -> essential-task spawn. Every step depends on the previous \
              one having already succeeded or already failed closed, so extracting \
              phases into helpers would hide the ordering that makes an aborted \
              startup leave nothing on disk mutated."
)]
pub async fn run(config: DaemonConfig) -> anyhow::Result<RunEnd> {
    // apple-cfg: ios-explicit the process model (sockets, self-update, log files) is desktop-only
    if cfg!(target_os = "ios") {
        anyhow::bail!(
            "the daemon process model does not run on iOS; the host embeds the engine \
             (yadorilink-embedded-host)"
        );
    }
    #[cfg(feature = "enforce-release-trust-root")]
    enforce_trust_root_gate_at_startup()?;

    // Before anything else observable: if this daemon was asked to record
    // which carriers its transfers use, the request has to be complete. A
    // half-configured instrument would start cleanly and then write a file
    // that reads like evidence, which is worse than not measuring at all.
    crate::path_witness_sink::configure(
        std::env::var_os(crate::path_witness_sink::PATH_VAR),
        std::env::var(crate::path_witness_sink::EXPECT_VAR).ok(),
    )?;
    arm_process_diagnostics();

    // `YADORILINK_DIAGNOSTIC_IO_COUNTERS=1` arms `yadorilink_local_storage
    // ::io_diag`'s process-global durability/pipeline counters for this
    // process's whole lifetime -- unset (every production process) leaves
    // them off, at the cost of one relaxed atomic load per instrumented
    // site (see io_diag's own module doc). Read once here, same shape as
    // `fs_backend::fsync_diagnostically_disabled`'s `OnceLock`, rather than
    // scattering the env lookup: this is the one place able to arm it
    // before any block-store I/O happens. The recorded totals are dumped
    // in `graceful_shutdown`, the one path every shutdown route funnels
    // through.
    if std::env::var("YADORILINK_DIAGNOSTIC_IO_COUNTERS").as_deref() == Ok("1") {
        yadorilink_local_storage::io_diag::set_enabled(true);
    }
    // `YADORILINK_DIAGNOSTIC_RECEIVE_BUDGET=1` arms the receive serial
    // budget (`receive_diag`): path lock wait/hold per site and the SQLite
    // body/commit split. It also arms the `io_diag` counters above, because
    // the file and directory fsync and rename counters live there and the
    // dump below is gated on them. Unset (every production process) all of
    // it stays off at the cost of one relaxed load per instrumented site.
    if std::env::var("YADORILINK_DIAGNOSTIC_RECEIVE_BUDGET").as_deref() == Ok("1") {
        crate::receive_diag::set_enabled(true);
        yadorilink_local_storage::io_diag::set_enabled(true);
        yadorilink_sqlite_runtime::writer_gate_stats::set_split_enabled(true);
    }
    // Reads those same totals on demand rather than only at shutdown; see
    // the function's own doc comment. No-op unless the line above armed
    // them, so a production daemon installs nothing.
    spawn_io_diag_mark_listener();

    let dir = config.config_dir;
    let tuning = config.tuning;
    refuse_unusable_state_dir(&yadorilink_fs_platform::state_dir::Env::from_process(), &dir)?;
    // The one place the credential settings are read from the environment; everything below
    // is handed this value.
    let credentials = credential_config_from_env(&dir)?;
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(&dir)?;
    // Acquire before opening the block store/SQLite or touching either Unix
    // socket. In particular, a losing process must never unlink the live
    // daemon's socket before discovering that it does not own this config.
    let _instance_lock = DaemonInstanceLock::acquire(&dir)?;
    // Under the lock nothing else runs, so this is where a second owner is turned away, before
    // anything below can touch the data.
    let identity = std::sync::Arc::new(crate::identity::RuntimeIdentity::detect(
        Some(dir.clone()),
        tuning.install_source.as_deref(),
    ));
    gate_ownership(&identity, &dir)?;
    // The HTTP API port file describes this run's listener only: a file left
    // by an earlier run must be gone before anything starts serving, and
    // must not survive a start where the dashboard is disabled or fails to
    // bind.
    let http_api_port_path = dir.join(yadorilink_http_api::PORT_FILE_NAME);
    if let Err(e) = std::fs::remove_file(&http_api_port_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, path = %http_api_port_path.display(), "failed to remove the previous HTTP API port file");
        }
    }

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
    let device_config = crate::engine_startup::load_device_config(&dir)?;

    let block_store_root = config.block_store_root;
    let sync_db_path = config.sync_db_path;

    // Registration makes both private keys immutable identity state. Validate
    // them together before acquiring data-resource locks, opening the block
    // store/SQLite, running migrations, or repairing linked files. Keep this
    // exact loaded value for later wiring so no second read can observe a
    // different file after persistent startup work has begun.
    //
    // One key, not two. It signs this device's change history and it
    // authenticates its transport, and a registered device that cannot load
    // it must fail rather than mint a replacement -- see `KeyLoadError`.
    let registered_identity = if device_config.is_some() {
        Some(yadorilink_transport::DeviceSigningKeyPair::load_existing(
            dir.join("signing_key"),
            credentials.key_mirror,
        )?)
    } else {
        None
    };

    // Additive to the config-dir lock above: take exclusive OS locks on the
    // block-store root and the sync-state database *before* opening either
    // (`SegmentBlockStore::new`/`SyncState::open` below), so a losing daemon never
    // mutates them. The config-dir lock alone does not cover this: the store
    // root and database paths are independently overridable, so two daemons
    // with distinct config dirs could otherwise be aimed at the same store/DB
    // and corrupt them. Deterministic acquisition order (config dir → block
    // store → DB) prevents cross-instance deadlock; on conflict the
    // already-acquired lock is released (RAII) as `run` returns the error.
    let mut data_resource_locks =
        yadorilink_local_storage::resource_lock::DataResourceLocks::acquire(
            &block_store_root,
            &sync_db_path,
        )?;

    let provider_temp_root = config.provider_temp_root;
    #[cfg(unix)]
    let control_socket_path = config.control_socket_path;
    #[cfg(all(unix, not(target_os = "ios")))]
    let shell_ipc_socket_path = config.shell_ipc_socket_path;

    let crate::engine_startup::OpenedData { block_store, replica_coordinator } =
        crate::engine_startup::open_data(&dir, &block_store_root, &sync_db_path, &tuning)?;
    data_resource_locks.lock_created_sync_db(&sync_db_path)?;
    crate::engine_startup::settle_data(&replica_coordinator, &sync_db_path)?;

    // Per-link interrupted-materialization/restore-operation repair and the
    // removal of the temp files a crash left run inside the daemon's own
    // `LinkRuntimeController::start_inner`, immediately after that specific
    // link's `SyncRootLock` is acquired, so they go through the same
    // `RootLease` every other mutation for that link uses.
    // Enumerate the links ONCE, for both `start_link_watch_gating_
    // tombstones` below and the watcher resume loop further down, and fail
    // startup if the table cannot be read. Collapsing this error into
    // "there are no links" would silently skip both -- no watcher or
    // startup scan for any folder -- while the peer path, which resolves
    // its roots from the same table independently, would carry on applying
    // changes into folders this boot never scanned. A daemon that cannot
    // read its own link table has nothing safe to do, so it must not
    // pretend it has no work.
    let links = replica_coordinator.link_repository().list_links()?;

    let device_id = device_config.as_ref().map(|c| c.device_id.clone()).unwrap_or_default();

    let crate::engine_startup::BuiltEngine { state, application, recovery_job } =
        crate::engine_startup::build_engine(
            &dir,
            device_id.clone(),
            &replica_coordinator,
            &block_store,
            registered_identity.as_ref(),
        );

    // Opt-in `/metrics`
    // endpoint — off/localhost-only by default. The env var (if set)
    // always wins over the persisted `metrics_config.json` toggle
    // (`yadorilink daemon metrics`), so an operator's explicit env-based
    // override takes precedence, with the persisted config as this
    // binary's own additional, CLI-settable fallback.
    let metrics_addr = std::env::var("YADORILINK_DAEMON_METRICS_ADDR").ok().or_else(|| {
        let config =
            yadorilink_reporting::metrics_config::MetricsConfigStore::new(&dir).load_or_default();
        config.enabled.then_some(config.bind_addr)
    });
    if let Some(metrics_addr) = metrics_addr {
        match tokio::net::TcpListener::bind(&metrics_addr).await {
            Ok(metrics_listener) => {
                let metrics = crate::metrics::DaemonMetrics::new(state.clone());
                tracing::info!(addr = metrics_addr, "yadorilink-daemon metrics listening");
                crate::supervise::spawn_logged("daemon-metrics-http", async move {
                    serve_metrics(metrics_listener, metrics).await;
                    Ok(())
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, addr = metrics_addr, "failed to bind daemon metrics listener; metrics endpoint disabled for this run");
            }
        }
    }

    crate::engine_startup::resume_links(&state, &links);

    // Every essential task lives in this one supervisor set instead
    // of a bare `tokio::spawn` with its handle dropped (shell-IPC, peer
    // orchestrator) or awaited on its own at the very end (control
    // socket, coupling process liveness to just that one task). Spawning
    // directly into the set (rather than wrapping `supervise::spawn_logged`
    // handles) means `essential.shutdown()` during graceful shutdown
    // actually aborts the running task itself, not just a wrapper awaiting
    // it.
    let mut essential = EssentialTasks::new();

    // `app.rs` is the sole composition root: `application` (built once,
    // above, and shared with the recovery job) and `queries` are handed down
    // through `ControlContext` -- `control_socket::*_transport::serve` does
    // not build either itself.
    let control_context = std::sync::Arc::new(
        crate::control_context::ControlContext::new(
            application,
            crate::adapters::build_query_services(state.clone()),
            dir.clone(),
        )
        .with_identity(identity.clone()),
    );

    #[cfg(unix)]
    {
        let state = state.clone();
        let control_context = control_context.clone();
        let path = control_socket_path.clone();
        state.set_task_alive(TASK_CONTROL_SOCKET, true);
        essential.spawn(async move {
            if let Err(e) = control_socket::unix_transport::serve(&path, control_context).await {
                tracing::error!(error = %e, task = TASK_CONTROL_SOCKET, "essential task failed");
            } else {
                tracing::warn!(task = TASK_CONTROL_SOCKET, "essential task exited");
            }
            state.set_task_alive(TASK_CONTROL_SOCKET, false);
            TASK_CONTROL_SOCKET
        });
    }
    #[cfg(windows)]
    {
        let state = state.clone();
        let control_context = control_context.clone();
        let pipe_name = device_config::control_pipe_name();
        state.set_task_alive(TASK_CONTROL_SOCKET, true);
        essential.spawn(async move {
            if let Err(e) =
                control_socket::windows_transport::serve(&pipe_name, control_context).await
            {
                tracing::error!(error = %e, task = TASK_CONTROL_SOCKET, "essential task failed");
            } else {
                tracing::warn!(task = TASK_CONTROL_SOCKET, "essential task exited");
            }
            state.set_task_alive(TASK_CONTROL_SOCKET, false);
            TASK_CONTROL_SOCKET
        });
    }

    #[cfg(any(windows, unix))]
    let shell_context =
        crate::engine_startup::start_provider(&state, &control_context, provider_temp_root);

    #[cfg(all(unix, not(target_os = "ios")))]
    {
        let state = state.clone();
        let shell_context = shell_context.clone();
        let path = shell_ipc_socket_path.clone();
        state.set_task_alive(TASK_SHELL_IPC, true);
        essential.spawn(async move {
            if let Err(e) = shell_ipc::unix_transport::serve(&path, shell_context).await {
                tracing::error!(error = %e, task = TASK_SHELL_IPC, "essential task failed");
            } else {
                tracing::warn!(task = TASK_SHELL_IPC, "essential task exited");
            }
            state.set_task_alive(TASK_SHELL_IPC, false);
            TASK_SHELL_IPC
        });
    }
    // iOS serves no shell socket (`run` refuses there before this point).
    #[cfg(target_os = "ios")]
    let _ = &shell_context;
    #[cfg(windows)]
    {
        let state = state.clone();
        let shell_context = shell_context.clone();
        let pipe_name = device_config::shell_ipc_pipe_name();
        state.set_task_alive(TASK_SHELL_IPC, true);
        essential.spawn(async move {
            if let Err(e) = shell_ipc::windows_transport::serve(&pipe_name, shell_context).await {
                tracing::error!(error = %e, task = TASK_SHELL_IPC, "essential task failed");
            } else {
                tracing::warn!(task = TASK_SHELL_IPC, "essential task exited");
            }
            state.set_task_alive(TASK_SHELL_IPC, false);
            TASK_SHELL_IPC
        });
    }

    // Localhost HTTP/REST + SSE dashboard, a thin translation layer over
    // this same control socket/pipe (see `yadorilink-http-api`'s own crate
    // doc comment; also documented for operators in the published README's
    // command-line section). Non-essential/best-effort, like
    // NAT-traversal below: a failure to bind (most likely the configured
    // port already in use) must not take down folder sync. Opt-out only,
    // never opt-in, so the dashboard is available by default for a headless
    // Linux box or NAS with no desktop, where the only other way to see
    // sync status is SSH plus the CLI -- `YADORILINK_HTTP_API_DISABLE` is
    // the accidental-opt-out escape hatch (tests that don't want a second
    // listener bound per daemon instance use it). This does shift part of
    // this daemon's trust boundary: the existing control socket is gated by
    // Unix filesystem permissions (owning-uid only), while this dashboard is
    // gated by a bearer token readable by that uid but reachable, as a raw
    // TCP connection, by every local uid -- see the published README for
    // that trade-off written out.
    //
    let http_api_port_path = dir.join(yadorilink_http_api::PORT_FILE_NAME);
    // Where management streams from this account's other devices go: the
    // dashboard started here, in-process. `None` when it is disabled or did
    // not start, which those devices are told as "unavailable".
    let mut nas_admin_dashboard = None;
    if !env_disable_flag_is_set(std::env::var("YADORILINK_HTTP_API_DISABLE")) {
        #[cfg(unix)]
        let control_socket_path = control_socket_path.clone();
        #[cfg(windows)]
        let control_pipe_name = device_config::control_pipe_name();

        const DEFAULT_HTTP_API_PORT: u16 = 8484;
        let port: u16 = match std::env::var("YADORILINK_HTTP_API_PORT") {
            Ok(v) => v.parse().unwrap_or_else(|_| {
                tracing::warn!(
                    value = %v,
                    default = DEFAULT_HTTP_API_PORT,
                    "YADORILINK_HTTP_API_PORT is set but not a valid port number; using the default"
                );
                DEFAULT_HTTP_API_PORT
            }),
            Err(_) => DEFAULT_HTTP_API_PORT,
        };
        // A single explicit dev-server origin, never a wildcard -- see
        // `yadorilink-http-api`'s own security module doc comment.
        let extra_allowed_origins =
            std::env::var("YADORILINK_HTTP_API_DEV_ORIGIN").into_iter().collect();

        let http_api_config = yadorilink_http_api::HttpApiConfig {
            #[cfg(unix)]
            control_socket_path,
            #[cfg(windows)]
            control_pipe_name,
            token_path: dir.join(yadorilink_http_api::TOKEN_FILE_NAME),
            port_path: http_api_port_path,
            port,
            extra_allowed_origins,
        };
        match yadorilink_http_api::bind(&http_api_config).await {
            Ok(handle) => {
                tracing::info!(
                    port = handle.port,
                    token_path = %http_api_config.token_path.display(),
                    "http api listening on 127.0.0.1 (and [::1] where available); bearer token \
                     written to token_path (owner-only on Unix)"
                );
                nas_admin_dashboard = Some(handle.peer_streams());
                crate::supervise::spawn_logged("http-api", async move {
                    yadorilink_http_api::run(handle).await
                });
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "failed to start the localhost HTTP API dashboard; folder sync is unaffected"
                );
            }
        }
    }

    // `?`, not a fallback. A credential store this process cannot read is not
    // the same as a machine nobody has signed in on: the second is an
    // unconnected daemon, which is a supported state, and the first is a
    // daemon that would run as if nobody had signed in while a credential sits
    // there unreadable. Refusing is what keeps a misconfigured store from
    // looking like an ordinary logged-out machine.
    //
    // ONE credential for the whole process, built once here. It is not a
    // token: on the Authorization Server's plane it is a handle on the shared
    // credential manager, so every clone below refreshes through one cache and
    // one cross-process rotation lock instead of holding a five-minute
    // snapshot that dies while the daemon is idle.
    let coordination_auth = credential_store::coordination_auth(&dir, &credentials).await?;

    // Before the orchestrator can start, and whether or not it can reach
    // anything: rebuild the verified group policy state from the signed
    // chains this device stored, re-checking each one against its pinned
    // coordination service key and its rollback watermark. Without it a
    // restart taken while the plane is unreachable rediscovers its peers and
    // then withholds every group anyway, because an introduced group with no
    // verified policy fails closed -- a connection that cannot carry data.
    // The first live netmap of the run replaces all of it.
    if let Some(cfg) = device_config.as_ref() {
        peer_orchestrator::restore_offline_group_policy_states(&state, &cfg.coordination_addr);
    }

    match (device_config, coordination_auth) {
        (Some(cfg), Some(auth)) => {
            tracing::info!(device_id = %cfg.device_id, "connecting to coordination plane");

            crate::engine_startup::spawn_coordination_tasks(&state, &recovery_job, &cfg, &auth);

            // Track Send: waits for the reconciliation stack to bind this
            // device's iroh endpoint, then builds and serves this device's
            // Track Send service on its own ALPN (`yadorilink/send/v1`) --
            // a wholly separate protocol on the same endpoint, never the
            // native-state/materialization machinery the rest of this daemon
            // serves. Not
            // an `essential.spawn` task: a device that cannot yet (or ever)
            // establish coordination-plane connectivity should not bring
            // the whole daemon down over a feature that itself has no
            // effect on linked-folder sync.
            {
                let state = state.clone();
                let config_dir = dir.clone();
                crate::supervise::spawn_logged("send-transfer-inbound", async move {
                    crate::send_transfer::run(state, config_dir).await
                });
            }

            // Management of this device by the account's other devices, on
            // its own ALPN over the same endpoint. Best-effort, like Track
            // Send: it has no effect on folder sync. Only where the headless
            // profile offers it; elsewhere the endpoint has no queue for it.
            if state.tuning().offer_nas_admin {
                let state = state.clone();
                let dashboard = nas_admin_dashboard.clone();
                crate::supervise::spawn_logged("nas-admin-inbound", async move {
                    crate::nas_admin::run(state, dashboard).await
                });
            }

            let orchestrator_config = peer_orchestrator::OrchestratorConfig {
                coordination_addr: cfg.coordination_addr,
                auth,
                device_id: cfg.device_id,
            };
            let state = state.clone();
            state.set_task_alive(TASK_PEER_ORCHESTRATOR, true);
            essential.spawn(async move {
                if let Err(e) = peer_orchestrator::run(orchestrator_config, state.clone()).await
                {
                    tracing::error!(error = %e, task = TASK_PEER_ORCHESTRATOR, "essential task failed");
                } else {
                    tracing::warn!(task = TASK_PEER_ORCHESTRATOR, "essential task exited");
                }
                state.set_task_alive(TASK_PEER_ORCHESTRATOR, false);
                TASK_PEER_ORCHESTRATOR
            });
        }
        _ => {
            tracing::warn!(
                "not logged in or no device registered yet — running with local link management only; run `yadorilink login` and `yadorilink device register` to enable P2P sync"
            );
            // Signed out, or not a registered device: there is no account
            // relationship left for a last-known-good peer authorization to
            // continue, so the snapshot is deleted rather than left on disk
            // for a later restart to act on. This is also what makes
            // `yadorilink logout` (which clears the credential store from
            // another process) reach the snapshot: the next daemon start
            // finds no credential and drops it.
            state.forget_offline_peer_authorization();
        }
    }

    #[cfg(all(unix, not(target_os = "ios")))]
    let socket_paths = vec![control_socket_path.clone(), shell_ipc_socket_path.clone()];
    #[cfg(target_os = "ios")]
    let socket_paths = vec![control_socket_path.clone()];
    #[cfg(windows)]
    let socket_paths: Vec<PathBuf> = Vec::new(); // named pipes have no filesystem entry to remove

    // Started only here, once startup is complete and this task is about to wait for a stop: a
    // watch that committed its safe stop during startup would leave admission closed with
    // nothing to carry the stop out. (The baseline of the replaced-watch was taken earlier, by
    // `exe_replaced::arm`, so a swap during startup still counts.)
    // An installation that is deleted or replaced under a running daemon stops it, safely.
    if let Some(path) = identity.watched_path() {
        let lifecycle = control_context.application.lifecycle.clone();
        let mut shutdown = state.shutdown_tx.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                () = crate::exe_watch::watch(path, crate::exe_watch::ExeWatchConfig::default(), lifecycle) => {}
                _ = shutdown.wait_for(|stopped| *stopped) => {}
            }
        });
    }

    // A supervised daemon whose executable was replaced stops safely and exits for a restart.
    crate::exe_replaced::spawn_if_supervised(
        control_context.application.lifecycle.clone(),
        state.shutdown_tx.subscribe(),
    );

    tokio::select! {
        reason = wait_for_shutdown_request(&state.shutdown_tx, wait_for_os_signal()) => {
            tracing::info!(reason, "shutdown requested; starting graceful shutdown");
            graceful_shutdown(&state, &socket_paths, &mut essential).await;
            // The commit that fired the shutdown recorded its reason first (safe_stop), so
            // this read, which comes after the signal, cannot miss it.
            Ok(if state.restart_on_exit.load(std::sync::atomic::Ordering::SeqCst) {
                RunEnd::RestartRequested
            } else {
                RunEnd::Stopped
            })
        }
        Some(joined) = essential.join_next() => {
            // `essential`'s own tasks never panic (each body already
            // catches and logs its inner `Result`), so `joined` is only
            // ever `Err` if the task was aborted from outside — which
            // only happens from `graceful_shutdown` below, by which point
            // we've already returned. Treat any other outcome as fatal.
            let name = joined.unwrap_or("unknown-task");
            tracing::error!(task = name, "essential task died; exiting non-zero so a process supervisor restarts the daemon");
            // An essential
            // supervised task dying is exactly the kind of severe,
            // maintainer-actionable failure this hook exists for — a
            // local-only candidate, never submitted automatically.
            crate::reporting::hooks::record_severe_error(
                &state.reporting,
                "essential_task_died",
                name,
                vec![format!("essential task '{name}' exited or was aborted unexpectedly")],
            );
            // Best-effort: still try to leave sockets/links in a clean
            // state before the hard exit below, but don't let a slow or
            // wedged cleanup delay the non-zero exit indefinitely — a
            // supervisor restarting an unhealthy daemon is the point.
            let cleanup = graceful_shutdown(&state, &socket_paths, &mut essential);
            let _ = tokio::time::timeout(Duration::from_secs(5), cleanup).await;
            std::process::exit(1);
        }
    }
}

/// Records why the daemon refused its placement, for `status` to show while no daemon answers: in
/// the refused state directory (when there is one) and in the default one, where clients look when
/// no override is set. The daemon's start path calls this for the refusal `DaemonConfig::from_env`
/// returns, so a refused override leaves the same record as a refused state directory.
pub fn record_placement_refusal(
    env: &yadorilink_fs_platform::state_dir::Env,
    dir: Option<&std::path::Path>,
    refusal: &yadorilink_fs_platform::state_dir::StateDirError,
) {
    use yadorilink_fs_platform::state_dir;
    let message = refusal.to_string();
    tracing::error!("{message}");
    let dir = dir.map(std::path::Path::to_path_buf).or_else(|| state_dir::resolve(env).ok());
    for place in [dir, state_dir::default_dir(env).ok()].into_iter().flatten() {
        let recorded = yadorilink_fs_platform::durable_dir::create_dir_all_durably(&place)
            .and_then(|()| yadorilink_local_storage::startup_refusal::record(&place, &message));
        if let Err(error) = recorded {
            tracing::warn!(error = %error, "could not record the startup refusal");
        }
    }
}

/// Refuses, before anything is created, a state directory a packaged process may not use (under
/// AppData, where Windows keeps a per-package copy that uninstall deletes). The reason is
/// recorded for `status` in the refused directory and in the default one, where clients look when
/// no override is set. A left-over state directory of the earlier unpackaged build is only
/// reported: it is neither read, moved nor deleted.
fn refuse_unusable_state_dir(
    env: &yadorilink_fs_platform::state_dir::Env,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    use yadorilink_fs_platform::state_dir;
    if let Err(refusal) = state_dir::check_placement(env, dir) {
        record_placement_refusal(env, Some(dir), &refusal);
        return Err(refusal.into());
    }
    if cfg!(windows) {
        if let Some(legacy) = state_dir::legacy_windows_dir_in_use(env) {
            if !state_dir::same_dir(&legacy, dir) {
                tracing::warn!("{}", state_dir::legacy_notice(&legacy, dir));
            }
        }
        if let Some(record) = state_dir::legacy_sync_roots_record_in_use(env, dir) {
            tracing::warn!("{}", state_dir::legacy_sync_roots_notice(&record));
        }
    }
    Ok(())
}

/// Races SIGTERM/SIGINT (Unix) or Ctrl-C (Windows, which has no SIGTERM)
/// against the control socket's `Shutdown` request signaled through
/// `DaemonState::shutdown_tx` — either way, returns a short tag
/// naming which one fired, purely for the log line at the call site.
async fn wait_for_shutdown_request(
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    os_signal: impl std::future::Future<Output = &'static str>,
) -> &'static str {
    // Subscribed only now, long after the stop producers started (the watches, the control
    // socket): `wait_for` looks at the current value first, so a stop requested during startup
    // is not lost, whatever the receiver has "seen".
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::select! {
        signal_name = os_signal => {
            // The signal takes part in the same arbitration as every other stop: marking the
            // shutdown now means a safe stop still committing during the cleanup finds the
            // daemon already stopping, and never turns this stop into a restart.
            shutdown_tx.send_replace(true);
            signal_name
        }
        _ = shutdown_rx.wait_for(|stopped| *stopped) => "control-socket Shutdown request",
    }
}

#[cfg(unix)]
async fn wait_for_os_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    // `signal()` only fails if the underlying OS signal registration
    // fails (e.g. an invalid `SignalKind`, never the case for a constant
    // here) — a daemon that can't even install its shutdown handler is
    // already in a bad enough state that panicking at startup is
    // reasonable, matching how the rest of startup treats setup failures
    // (`?` on `Connection::open`, etc.).
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = tokio::signal::ctrl_c() => "SIGINT",
    }
}

/// Windows has no SIGTERM; a process supervisor there typically stops a
/// service via `Ctrl-C`/service-control events, which `tokio::signal::ctrl_c`
/// already covers cross-platform — no Windows-specific signal API needed
/// for this MVP — cfg-split only where the platforms genuinely differ,
/// e.g. named pipes vs Unix sockets.
#[cfg(windows)]
async fn wait_for_os_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "Ctrl-C"
}

/// Writes every armed `io_diag` counter out as one line per operation
/// class, tagged with `occasion`.
///
/// Shared by the shutdown dump and the SIGUSR1 mark below so the two can
/// never report different counter sets. That is the whole reason this is a
/// function rather than two loops: a benchmark that subtracts a mark from
/// a later mark is subtracting two readings of the same instrument, and a
/// counter present in one dump but not the other would silently turn into
/// a wrong delta rather than a visible error.
///
/// Reads only — `snapshot()` is a row of relaxed loads. Nothing here
/// resets a counter or touches any product state.
fn emit_io_diag_counters(occasion: &str) {
    for op in yadorilink_local_storage::io_diag::snapshot() {
        if op.calls > 0 {
            tracing::info!(
                op = op.name,
                calls = op.calls,
                nanos = op.nanos,
                bytes = op.bytes,
                "io_diag counter at {occasion}"
            );
        }
    }
    emit_custody_counters(occasion);
}

/// The custody-query counters, written in the same shape and on the same
/// occasions as the block-store ones.
///
/// Same shape deliberately: a reader already subtracts one reading of
/// those from another to get a phase's value, and these have to be
/// subtracted the same way to be compared with them. The question they
/// exist to answer -- whether custody read volume grows because more
/// queries arrive or because each answer verifies more -- is only
/// answerable if both sides of the ratio come from the same two instants.
fn emit_custody_counters(occasion: &str) {
    let s = yadorilink_peer_session::custody_diag::stats();
    if s.requests == 0 {
        return;
    }
    for (name, value) in [
        ("custody_requests", s.requests),
        ("custody_requests_for_handoff", s.requests_for_handoff),
        ("custody_unique_versions", s.unique_versions),
        ("custody_blocks_verified", s.blocks_verified),
    ] {
        tracing::info!(
            op = name,
            calls = value,
            nanos = 0,
            bytes = 0,
            "io_diag counter at {occasion}"
        );
    }
}

/// Monotonic sequence number for SIGUSR1 marks, so a reader can tell
/// "mark 3 then mark 4" from "mark 4 arrived, mark 3's lines were lost".
/// Diagnostic-only and never read by the daemon itself.
#[cfg(unix)]
static IO_DIAG_MARK_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Installs a SIGUSR1 listener that dumps `io_diag`'s counters on demand.
///
/// Exists because those counters are process-global totals with exactly
/// one reader — the shutdown dump — which forces a measurement wanting
/// per-phase numbers to stop the daemon between phases. Stopping it is not
/// a neutral act: it drops the page cache and the SQLite cache, and on
/// restart re-scans every file already synced, so the next phase's numbers
/// describe a cold daemon rather than the steady state being measured.
/// A mark lets a benchmark take the difference between two readings of a
/// daemon that never stopped.
///
/// Installed only when the counters are already armed, i.e. only under
/// `YADORILINK_DIAGNOSTIC_IO_COUNTERS=1`. A production daemon installs no
/// handler and keeps SIGUSR1's default disposition, exactly as before.
#[cfg(unix)]
fn spawn_io_diag_mark_listener() {
    use std::sync::atomic::Ordering;
    use tokio::signal::unix::{signal, SignalKind};

    if !yadorilink_local_storage::io_diag::enabled() {
        return;
    }
    tokio::spawn(async move {
        // Unlike the shutdown handler this does not panic on a failed
        // registration: losing the ability to mark costs a measurement,
        // which is not a reason to take down a running daemon.
        let mut sigusr1 = match signal(SignalKind::user_defined1()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGUSR1 io_diag mark handler");
                return;
            }
        };
        while sigusr1.recv().await.is_some() {
            let seq = IO_DIAG_MARK_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
            // Emitted before the counters, so a truncated or interleaved
            // read is detectable rather than silently short.
            tracing::info!(seq, "io_diag mark begin");
            emit_io_diag_counters("mark");
            crate::receive_diag::emit_report("mark");
            tracing::info!(seq, "io_diag mark end");
        }
    });
}

#[cfg(not(unix))]
fn spawn_io_diag_mark_listener() {}

/// The one graceful-shutdown path both SIGTERM/SIGINT and the
/// control socket's `Shutdown` request (via `DaemonState::shutdown_tx`)
/// funnel into — previously the latter was a second, independent path
/// (`std::process::exit(0)` after a sleep) that skipped all of this.
async fn graceful_shutdown(
    state: &Arc<DaemonState>,
    socket_paths: &[PathBuf],
    essential: &mut EssentialTasks,
) {
    // Give an in-flight control-socket response (e.g. this shutdown
    // request's own ack) a moment to actually flush to its client before
    // sockets disappear and tasks get aborted out from under it —
    // matching the old control-socket-only code's 200ms grace period,
    // now applied uniformly to every shutdown path.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Before anything is torn down: the watchers read from live connections,
    // and a verdict taken after the links are closed would be reporting on
    // whatever survived rather than on the transfer. Inert unless this daemon
    // was started with the path-evidence variable set.
    if let Some(sink) = crate::path_witness_sink::sink() {
        sink.flush().await;
    }

    crate::engine_startup::quiesce(state).await;

    // Remove the socket files last, once nothing should be listening
    // through them anymore — a stale socket left behind after an
    // ungraceful kill is already handled by `unix_transport::serve`'s
    // own cleanup-on-bind, but doing it here too means a *graceful* exit
    // never leaves one lying around even briefly.
    for path in socket_paths {
        let _ = std::fs::remove_file(path);
    }

    // Dump `io_diag`'s counters, if `YADORILINK_DIAGNOSTIC_IO_COUNTERS=1`
    // armed them at startup — `snapshot()` itself is just relaxed loads
    // regardless, so this is unconditionally cheap to call and skip when
    // nothing was ever recorded (every `calls == 0`).
    if yadorilink_local_storage::io_diag::enabled() {
        use yadorilink_local_storage::io_diag::Op;
        emit_io_diag_counters("shutdown");
        // Distribution, not just the total. "Did more queue depth make
        // each fsync slower, or just overlap more of them?" is a question
        // about the shape of the latency, and a mean cannot answer it: the
        // same total is produced by every call getting slower and by a few
        // getting much slower, which have different causes and different
        // fixes.
        for op in [
            Op::SegmentFsync,
            Op::GroupCommit,
            Op::IndexCommit,
            Op::CommitBatch,
            Op::SegmentAppend,
            Op::FileFsync,
            Op::DirFsync,
            Op::Rename,
        ] {
            let stat = yadorilink_local_storage::io_diag::stat(op);
            if stat.calls == 0 {
                continue;
            }
            let p = yadorilink_local_storage::io_diag::percentiles(op, &[0.5, 0.95, 0.99]);
            tracing::info!(
                op = stat.name,
                calls = stat.calls,
                p50_us = p[0] / 1000,
                p95_us = p[1] / 1000,
                p99_us = p[2] / 1000,
                "io_diag latency at shutdown"
            );
        }

        // The other half of the same question. `io_diag` instruments the
        // BLOCK store exhaustively and the SQLite write path not at all, so
        // a run whose wall clock exceeds its block work leaves the
        // remainder unattributable -- which is exactly what happened
        // comparing a batched import against an interleaved one: block
        // fsync latency was measurably LOWER in the slower run, while
        // ~283s of a 100k run's wall clock had no instrument pointing at
        // it. `writer_gate_stats` records per-call-site write-transaction
        // counts and gate hold times (see its own doc comment); this is
        // where a daemon reads them out. One `locked_write` is one
        // fsync-backed commit, so `held_micros` per site is the SQLite-side
        // cost that `commit_batch` is to the block side.
        let (gate_acquisitions, gate_wait) = yadorilink_sqlite_runtime::writer_gate_stats::stats();
        tracing::info!(
            write_transactions = gate_acquisitions,
            gate_wait_ms = gate_wait.as_millis() as u64,
            "sqlite_diag totals at shutdown"
        );
        for (site, count, held_micros) in
            yadorilink_sqlite_runtime::writer_gate_stats::hold_site_stats()
        {
            if count > 0 {
                tracing::info!(
                    site = %site,
                    calls = count,
                    held_ms = (held_micros / 1000) as u64,
                    "sqlite_diag write-transaction hold at shutdown"
                );
            }
        }
        // New lines under their own prefix; the `io_diag` and `sqlite_diag`
        // lines above are unchanged. Writes nothing for an instrument that
        // was not armed.
        crate::receive_diag::emit_report("shutdown");
    }

    crate::engine_startup::close_substrate(state).await;

    // Finally, stop the essential tasks themselves (control socket,
    // shell IPC, peer orchestrator) — aborts whichever of them are still
    // running and awaits their abort, so this doesn't return until
    // they're actually gone.
    essential.shutdown().await;

    crate::engine_startup::checkpoint_data(state).await;
}

/// The daemon's `/metrics`
/// listener loop — deliberately a minimal, dependency-free raw-HTTP
/// responder rather than a new framework: "don't invent a different metrics
/// framework" for the daemon and coordination metrics endpoints.
async fn serve_metrics(listener: tokio::net::TcpListener, metrics: crate::metrics::DaemonMetrics) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut stream, peer_addr)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let Ok(n) = stream.read(&mut request).await else { return };
            let first_line = std::str::from_utf8(&request[..n])
                .ok()
                .and_then(|req| req.lines().next())
                .unwrap_or("");
            let (status, body) = if first_line.starts_with("GET /metrics ") {
                ("200 OK", metrics.render_openmetrics())
            } else {
                ("404 Not Found", "not found\n".to_string())
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                tracing::debug!(%peer_addr, "failed to write daemon metrics response");
            }
        });
    }
}

#[cfg(all(test, feature = "enforce-release-trust-root"))]
mod trust_root_startup_tests {
    //! Only compiled/run when the `enforce-release-trust-root` feature is on,
    //! proving that a release-configured build's startup path actually
    //! enforces the update trust-root gate (rather than defining a gate with
    //! no caller). Exercises the exact helper `run` calls as its first step.
    use super::*;

    /// The startup gate's verdict must track
    /// `update::manifest::enforce_release_trust_root_gate` exactly, and when
    /// it rejects it must be a HARD error naming the reason -- so a release
    /// build with an invalid root cannot boot. Conditioned on the live gate
    /// result so it is deterministic
    /// regardless of whether a dev override is set in this environment.
    #[test]
    fn startup_path_enforces_the_trust_root_gate() {
        let startup = enforce_trust_root_gate_at_startup();
        let override_value =
            std::env::var(crate::update::manifest::ALLOW_PLACEHOLDER_TRUST_ROOT_ENV).ok();
        if crate::update::manifest::enforce_release_trust_root_gate(override_value.as_deref())
            .is_ok()
        {
            // A real root is pinned (or the dev override is set): startup allowed.
            assert!(startup.is_ok());
        } else {
            // Placeholder/empty root and no override: startup MUST be refused.
            let err = startup.expect_err("startup must refuse a rejected trust root");
            let msg = format!("{err:#}");
            assert!(msg.contains("refusing to start"), "unexpected error: {msg}");
            assert!(msg.contains("trust-root"), "unexpected error: {msg}");
        }
    }
}

#[cfg(test)]
mod ownership_gate_tests {
    use super::*;
    use crate::identity::{IdentityInputs, OwnershipRefused, RuntimeIdentity};

    fn identity(exe: &str, source: &str) -> RuntimeIdentity {
        RuntimeIdentity::from_inputs(IdentityInputs {
            exe: exe.into(),
            install_source: source.into(),
            pid: 1,
            started_at_unix: 1,
            config_dir: None,
        })
    }

    #[test]
    fn a_second_owner_is_refused_with_a_typed_error_and_the_reason_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let cli = identity("/usr/local/bin/yadorilink-daemon", "script");
        gate_ownership(&cli, dir.path()).unwrap();
        assert_eq!(yadorilink_local_storage::startup_refusal::read(dir.path()), None);

        let app = identity("/Applications/Y.app/Contents/Helpers/yadorilink-daemon", "app_bundle");
        let error = gate_ownership(&app, dir.path()).unwrap_err();
        assert!(error.downcast_ref::<OwnershipRefused>().is_some(), "{error}");
        let reason = yadorilink_local_storage::startup_refusal::read(dir.path()).unwrap();
        assert!(reason.contains("managed by"), "{reason}");

        // The owner itself is still welcome.
        gate_ownership(&cli, dir.path()).unwrap();
    }
}

#[cfg(test)]
mod instance_lock_tests {
    use super::*;

    #[test]
    fn second_daemon_for_the_same_config_is_rejected_until_owner_exits() {
        let dir = tempfile::tempdir().unwrap();
        let owner = DaemonInstanceLock::acquire(dir.path()).unwrap();

        let error = DaemonInstanceLock::acquire(dir.path())
            .expect_err("a second daemon must not acquire the same config lock");
        assert!(error.to_string().contains("already running"));

        drop(owner);
        DaemonInstanceLock::acquire(dir.path())
            .expect("a stale lock file must be reusable after its OS lock is released");
    }

    #[test]
    fn the_probe_sees_the_daemons_own_lock_and_takes_nothing() {
        use yadorilink_local_storage::daemon_lock::{probe, LockProbe};

        let dir = tempfile::tempdir().unwrap();
        assert_eq!(probe(dir.path()), LockProbe::Free);
        let owner = DaemonInstanceLock::acquire(dir.path()).unwrap();
        assert_eq!(probe(dir.path()), LockProbe::Held);
        drop(owner);
        assert_eq!(probe(dir.path()), LockProbe::Free);
        DaemonInstanceLock::acquire(dir.path()).expect("the probe must leave the lock available");
    }

    /// Double-start race (large-tree acceptance, double start): many daemons of different owners start at the
    /// same instant on one data area. The lock admits exactly one, which alone records its owner;
    /// every other one is turned away before it can write anything.
    #[test]
    fn simultaneous_starts_of_both_owners_admit_exactly_one_writer() {
        use crate::identity::{IdentityInputs, RuntimeIdentity};
        use std::sync::{Arc, Barrier};

        let identity = |exe: &str, source: &str| {
            RuntimeIdentity::from_inputs(IdentityInputs {
                exe: exe.into(),
                install_source: source.into(),
                pid: 1,
                started_at_unix: 1,
                config_dir: None,
            })
        };
        for round in 0..20 {
            let dir = tempfile::tempdir().unwrap();
            const STARTERS: usize = 8;
            let barrier = Arc::new(Barrier::new(STARTERS));
            // Winners keep their lock until every starter has tried, as a running daemon would.
            let done = Arc::new(Barrier::new(STARTERS));
            let handles: Vec<_> = (0..STARTERS)
                .map(|i| {
                    let (barrier, done) = (barrier.clone(), done.clone());
                    let path = dir.path().to_path_buf();
                    let me = if i % 2 == 0 {
                        identity("/usr/local/bin/yadorilink-daemon", "script")
                    } else {
                        identity(
                            "/Applications/Y.app/Contents/Helpers/yadorilink-daemon",
                            "app_bundle",
                        )
                    };
                    std::thread::spawn(move || {
                        barrier.wait();
                        let started = DaemonInstanceLock::acquire(&path)
                            .map(|lock| (lock, gate_ownership(&me, &path)));
                        done.wait();
                        // Only the admitted daemon reports; its gate has nothing to refuse yet.
                        started.ok().map(|(_lock, gate)| gate.is_ok())
                    })
                })
                .collect();
            let winners = handles.into_iter().filter_map(|h| h.join().unwrap());
            assert_eq!(winners.collect::<Vec<_>>(), vec![true], "round {round}");
            let yadorilink_local_storage::ownership::RecordState::Present(record) =
                yadorilink_local_storage::ownership::read(dir.path())
            else {
                panic!("round {round}: the one admitted daemon records its owner")
            };
            assert!(
                (record.owner == yadorilink_local_storage::ownership::Owner::Cli)
                    == (record.install_source == "script"),
                "round {round}: one coherent record, not a mix: {record:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejected_second_daemon_cannot_unlink_the_live_control_socket() {
        use std::os::unix::net::{UnixListener, UnixStream};

        // Short enough for `sun_path`: an iOS simulator's temporary directory is not.
        let dir = tempfile::Builder::new().prefix("yl-").tempdir_in("/tmp").unwrap();
        let _owner = DaemonInstanceLock::acquire(dir.path()).unwrap();
        let socket_path = dir.path().join("daemon.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();

        assert!(DaemonInstanceLock::acquire(dir.path()).is_err());
        UnixStream::connect(&socket_path)
            .expect("the rejected process must leave the owner's live socket untouched");
    }

    #[test]
    fn unrelated_lock_open_errors_are_not_reported_as_already_running() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_directory = dir.path().join("plain-file");
        std::fs::write(&not_a_directory, b"x").unwrap();

        let error = DaemonInstanceLock::acquire(&not_a_directory).unwrap_err();
        assert!(!error.to_string().contains("already running"));
    }
}

/// The credential settings map from the environment exactly as the CLI's do, and are read only
/// through `credential_config_from_env`.
#[cfg(test)]
mod credential_config_tests {
    use super::*;
    use crate::test_support::CONFIG_ENV_MUTEX;
    use yadorilink_fapi_client::store::Backend;
    use yadorilink_transport::KeyMirror;

    const VARS: [&str; 4] = [
        "YADORILINK_CREDENTIAL_STORE",
        "YADORILINK_CREDENTIAL_FILE",
        "YADORILINK_DISABLE_OS_KEYRING",
        "YADORILINK_AUTH_SERVER_ADDR",
    ];

    #[tokio::test]
    async fn the_environment_maps_to_the_same_settings_as_the_cli_reads() {
        let _guard = CONFIG_ENV_MUTEX.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("elsewhere.json");
        let clear = || VARS.iter().for_each(|v| std::env::remove_var(v));
        clear();

        let unset = credential_config_from_env(dir.path()).unwrap();
        assert_eq!(unset.backend, Backend::platform_default(dir.path()));
        assert_eq!(unset.key_mirror, KeyMirror::OsKeyring);
        assert_eq!(unset.auth_server_addr, None);

        std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
        std::env::set_var("YADORILINK_CREDENTIAL_FILE", &file);
        std::env::set_var("YADORILINK_DISABLE_OS_KEYRING", "1");
        std::env::set_var("YADORILINK_AUTH_SERVER_ADDR", "http://127.0.0.1:1");
        let set = credential_config_from_env(dir.path()).unwrap();
        assert_eq!(set.backend, Backend::File(file.clone()));
        assert_eq!(set.key_mirror, KeyMirror::Disabled);
        assert_eq!(set.auth_server_addr.as_deref(), Some("http://127.0.0.1:1"));

        std::env::set_var("YADORILINK_CREDENTIAL_STORE", "keyring");
        let refused = credential_config_from_env(dir.path());
        std::env::set_var("YADORILINK_CREDENTIAL_STORE", "nonsense");
        let unknown = credential_config_from_env(dir.path());
        clear();
        assert!(refused.is_err(), "a credential file with the keyring selected is refused");
        assert!(unknown.is_err(), "an unknown store name is refused");
    }
}

/// The daemon binary still honours the `YADORILINK_*` tuning switches: `DaemonConfig::from_env`
/// is the one place they are read, and what it maps is what the engine is built with.
#[cfg(test)]
mod tuning_config_tests {
    use super::*;
    use crate::test_support::CONFIG_ENV_MUTEX;

    const VARS: [&str; 6] = [
        "YADORILINK_CONFIG_DIR",
        "YADORILINK_RECEIVE_WRITE_PERMITS",
        "YADORILINK_RECEIVE_ASYNC_COMMIT",
        "YADORILINK_SYNC_RELAYS",
        "YADORILINK_NAS_ADMIN",
        "YADORILINK_WITNESS_DIR",
    ];

    #[tokio::test]
    async fn the_environment_is_mapped_once_into_the_engine_tuning() {
        let _guard = CONFIG_ENV_MUTEX.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let witness = tempfile::tempdir().unwrap();
        let clear = || VARS.iter().for_each(|v| std::env::remove_var(v));
        clear();
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());

        let unset = DaemonConfig::from_env().unwrap().tuning;
        assert_eq!(
            unset.receive_write_permits,
            crate::engine_tuning::EngineTuning::default().receive_write_permits
        );
        assert!(unset.receive_async_commit);
        assert!(!unset.offer_nas_admin);

        std::env::set_var("YADORILINK_RECEIVE_WRITE_PERMITS", "5");
        std::env::set_var("YADORILINK_RECEIVE_ASYNC_COMMIT", "0");
        std::env::set_var("YADORILINK_SYNC_RELAYS", "none");
        std::env::set_var("YADORILINK_NAS_ADMIN", "1");
        std::env::set_var("YADORILINK_WITNESS_DIR", witness.path());
        let set = DaemonConfig::from_env().unwrap().tuning;
        clear();

        assert_eq!(set.receive_write_permits, 5);
        assert!(!set.receive_async_commit);
        assert_eq!(set.sync_relays.as_deref(), Some("none"));
        assert!(set.offer_nas_admin);
        assert_eq!(
            set.witness,
            crate::install_witness::WitnessPlacement::At(witness.path().to_path_buf())
        );
    }
}

#[cfg(test)]
mod startup_config_validation_tests {
    use super::*;
    use crate::device_config;
    use crate::test_support::CONFIG_ENV_MUTEX;
    use yadorilink_local_storage::SegmentBlockStore;

    /// One complete `run` attempt against a throwaway config directory. The
    /// error is captured as a `String` and the interesting paths are copied
    /// out so every assertion can run *after* the process-global config-dir
    /// env var has been restored — a failing assertion must not leak that var
    /// into whichever test acquires the mutex next.
    struct StartupAttempt {
        error: String,
        sync_db_path: PathBuf,
        _config_dir: tempfile::TempDir,
    }

    /// A syntactically valid `device.json` stamped one version past what this
    /// build supports — the "unsupported downgrade" case.
    fn too_new_device_json() -> String {
        format!(
            r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","signing_public_key":"signing-pub","config_version":{}}}"#,
            device_config::CONFIG_VERSION + 1
        )
    }

    /// Runs daemon startup against a config directory holding exactly
    /// `device_json`.
    async fn start_daemon_with_device_json(device_json: &str) -> StartupAttempt {
        start_daemon_with_device_json_and_keys(device_json, false).await
    }

    async fn start_daemon_with_device_json_and_keys(
        device_json: &str,
        create_signing_key: bool,
    ) -> StartupAttempt {
        let _env_guard = CONFIG_ENV_MUTEX.lock().await;
        let config_dir = tempfile::tempdir().unwrap();
        let block_store_root = config_dir.path().join("blocks");
        let sync_db_path = config_dir.path().join("sync-state.sqlite3");

        // The store/DB paths are pinned explicitly rather than left to
        // `from_env`'s defaults so that a `YADORILINK_BLOCK_STORE` or
        // `YADORILINK_SYNC_DB` already set in the developer's shell cannot
        // aim this test at a real install.
        std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());
        std::env::set_var("YADORILINK_BLOCK_STORE", &block_store_root);
        std::env::set_var("YADORILINK_SYNC_DB", &sync_db_path);

        std::fs::write(config_dir.path().join("device.json"), device_json).unwrap();
        if create_signing_key {
            yadorilink_transport::DeviceSigningKeyPair::generate_and_persist(
                config_dir.path().join("signing_key"),
                yadorilink_transport::KeyMirror::Disabled,
            )
            .unwrap();
        }
        std::fs::create_dir_all(&block_store_root).unwrap();

        let error = run(DaemonConfig::from_env().unwrap())
            .await
            .expect_err("startup must refuse a device.json this build cannot support")
            .to_string();

        std::env::remove_var("YADORILINK_CONFIG_DIR");
        std::env::remove_var("YADORILINK_BLOCK_STORE");
        std::env::remove_var("YADORILINK_SYNC_DB");

        StartupAttempt { error, sync_db_path, _config_dir: config_dir }
    }

    /// The daemon process model (sockets, updater, log file) is desktop-only: on iOS `run`
    /// refuses before it reads or creates anything.
    // apple-cfg: ios-explicit the refusal itself
    #[cfg(target_os = "ios")]
    #[tokio::test]
    async fn run_refuses_on_ios_before_touching_anything() {
        let attempt = start_daemon_with_device_json(&current_device_json()).await;
        assert!(attempt.error.contains("does not run on iOS"), "{}", attempt.error);
        assert!(!attempt.sync_db_path.exists());
    }

    fn current_device_json() -> String {
        format!(
            r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","signing_public_key":"signing-pub","config_version":{}}}"#,
            device_config::CONFIG_VERSION
        )
    }

    /// A registered device's key is validated before anything on disk is
    /// touched. A device has one key now, and it is not optional: without it
    /// this device can neither sign a change nor authenticate a connection,
    /// so startup must abort rather than proceed as a device that appears to
    /// work locally and is rejected by every peer.
    // apple-cfg: ios-explicit `run` refuses on iOS: the daemon process model does not run there
    #[cfg_attr(target_os = "ios", ignore = "the daemon process model does not run on iOS")]
    #[tokio::test]
    async fn a_registered_devices_key_is_validated_before_persistent_startup() {
        let attempt = start_daemon_with_device_json_and_keys(&current_device_json(), false).await;
        assert!(
            !attempt.sync_db_path.exists(),
            "a missing device key must abort before SQLite creation"
        );
    }

    /// A block store that survives while the replica database is gone must
    /// stop startup. Opening a missing database creates an empty one, and an
    /// empty database references no blocks, so the next idle sweep would
    /// delete every stored block.
    // apple-cfg: ios-explicit `run` refuses on iOS: the daemon process model does not run there
    #[cfg_attr(target_os = "ios", ignore = "the daemon process model does not run on iOS")]
    #[tokio::test]
    async fn a_missing_replica_database_beside_a_populated_block_store_aborts_startup() {
        let _env_guard = CONFIG_ENV_MUTEX.lock().await;
        let config_dir = tempfile::tempdir().unwrap();
        let block_store_root = config_dir.path().join("blocks");
        let sync_db_path = config_dir.path().join("sync-state.sqlite3");
        std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());
        std::env::set_var("YADORILINK_BLOCK_STORE", &block_store_root);
        std::env::set_var("YADORILINK_SYNC_DB", &sync_db_path);
        std::fs::write(config_dir.path().join("device.json"), current_device_json()).unwrap();
        yadorilink_transport::DeviceSigningKeyPair::generate_and_persist(
            config_dir.path().join("signing_key"),
            yadorilink_transport::KeyMirror::Disabled,
        )
        .unwrap();
        {
            let store = SegmentBlockStore::new(&block_store_root).unwrap();
            yadorilink_local_storage::BlockStore::put(&store, b"a block that outlived its index")
                .unwrap();
        }

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            run(DaemonConfig::from_env().unwrap()),
        )
        .await;

        std::env::remove_var("YADORILINK_CONFIG_DIR");
        std::env::remove_var("YADORILINK_BLOCK_STORE");
        std::env::remove_var("YADORILINK_SYNC_DB");

        let error = outcome
            .expect("startup must fail closed rather than carry on")
            .expect_err("startup must refuse a missing replica database beside stored blocks")
            .to_string();
        assert!(error.contains("is missing"), "{error}");
        assert!(
            !sync_db_path.exists(),
            "no empty replacement database may be created beside surviving blocks"
        );
    }

    /// A real daemon, asked to stop safely over its control socket, answers, exits cleanly,
    /// releases the config-directory lock and leaves its database without a write-ahead log.
    // apple-cfg: ios-explicit `run` refuses on iOS: the daemon process model does not run there
    #[cfg_attr(target_os = "ios", ignore = "the daemon process model does not run on iOS")]
    #[cfg(unix)]
    #[tokio::test]
    async fn a_running_daemon_stops_safely_on_request_and_releases_everything() {
        use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
        use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
        use yadorilink_ipc_proto::daemonctl::request_safe_stop_response::Outcome;
        use yadorilink_ipc_proto::daemonctl::{
            DaemonControlRequest, DaemonControlResponse, RequestSafeStopRequest,
            CONTROL_PROTOCOL_VERSION,
        };
        use yadorilink_ipc_proto::framing::{read_message, write_message};

        let _env_guard = CONFIG_ENV_MUTEX.lock().await;
        // Short enough for `sun_path`: an iOS simulator's temporary directory is not.
        let config_dir = tempfile::Builder::new().prefix("yl-").tempdir_in("/tmp").unwrap();
        let sync_db_path = config_dir.path().join("sync-state.sqlite3");
        std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());
        std::env::set_var("YADORILINK_BLOCK_STORE", config_dir.path().join("blocks"));
        std::env::set_var("YADORILINK_SYNC_DB", &sync_db_path);
        std::env::set_var("YADORILINK_SYNC_RELAYS", "none");
        std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
        std::fs::write(config_dir.path().join("device.json"), current_device_json()).unwrap();
        yadorilink_transport::DeviceSigningKeyPair::generate_and_persist(
            config_dir.path().join("signing_key"),
            yadorilink_transport::KeyMirror::Disabled,
        )
        .unwrap();
        let config = DaemonConfig::from_env().unwrap();
        let socket = config.control_socket_path.clone();
        let daemon = tokio::spawn(run(config));

        let mut stream = None;
        for _ in 0..200 {
            if let Ok(connected) = tokio::net::UnixStream::connect(&socket).await {
                stream = Some(connected);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if stream.is_none() && daemon.is_finished() {
            panic!("the daemon exited early: {:?}", daemon.await);
        }
        let mut stream = stream.expect("the daemon starts listening");
        write_message(
            &mut stream,
            &DaemonControlRequest {
                payload: Some(ReqPayload::RequestSafeStop(RequestSafeStopRequest {
                    deadline_secs: 10,
                })),
                protocol_version: CONTROL_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let response = read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), daemon).await;

        let record = ownership_record_of(config_dir.path());
        let lock_is_free = DaemonInstanceLock::acquire(config_dir.path()).is_ok();
        let wal = sync_db_path.with_file_name("sync-state.sqlite3-wal");
        let wal_len = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
        let socket_left = socket.exists();
        for variable in [
            "YADORILINK_CONFIG_DIR",
            "YADORILINK_BLOCK_STORE",
            "YADORILINK_SYNC_DB",
            "YADORILINK_SYNC_RELAYS",
            "YADORILINK_CREDENTIAL_STORE",
        ] {
            std::env::remove_var(variable);
        }

        let Some(RespPayload::RequestSafeStop(answer)) = response.payload else {
            panic!("not a safe-stop answer")
        };
        assert!(matches!(answer.outcome, Some(Outcome::Stopping(s)) if !s.already_in_progress));
        outcome
            .expect("the daemon exits within the bound")
            .expect("the task does not panic")
            .expect("the daemon exits with success");
        assert!(lock_is_free, "the config-directory lock is released");
        assert_eq!(wal_len, 0, "no write-ahead log is left behind");
        assert!(!socket_left, "the control socket is removed");
        assert!(record, "the data area's owner was recorded by the daemon that ran");
    }

    #[cfg(unix)]
    fn ownership_record_of(dir: &std::path::Path) -> bool {
        matches!(
            yadorilink_local_storage::ownership::read(dir),
            yadorilink_local_storage::ownership::RecordState::Present(_)
        )
    }

    /// A packaged process refuses an AppData state directory before creating anything there,
    /// and leaves the reason where `status` reads it.
    #[test]
    fn a_packaged_process_refuses_an_appdata_state_directory_and_records_why() {
        let root = tempfile::tempdir().unwrap();
        let appdata = root.path().join("AppData").join("Roaming");
        let env = yadorilink_fs_platform::state_dir::Env {
            home: Some(root.path().join("home").into()),
            userprofile: Some(root.path().join("home").into()),
            appdata: Some(appdata.clone().into()),
            packaged: true,
            ..Default::default()
        };
        let dir = appdata.join("yadorilink");
        let err = refuse_unusable_state_dir(&env, &dir).unwrap_err();
        assert!(err.to_string().contains("AppData"), "{err}");
        let recorded = yadorilink_local_storage::startup_refusal::read(&dir).unwrap();
        assert!(recorded.contains("AppData"), "{recorded}");
        let unpackaged = yadorilink_fs_platform::state_dir::Env { packaged: false, ..env };
        refuse_unusable_state_dir(&unpackaged, &dir).unwrap();
    }

    /// A packaged process gets the typed refusal for the state directory and for each per-path
    /// override under AppData, and building the configuration creates nothing.
    #[test]
    fn a_packaged_process_is_refused_every_appdata_path_before_anything_exists() {
        use yadorilink_fs_platform::state_dir::{Env, PathOverride, StateDirError};
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("ann");
        let appdata = home.join("AppData").join("Roaming");
        let base = Env {
            home: Some(home.clone().into()),
            userprofile: Some(home.clone().into()),
            appdata: Some(appdata.clone().into()),
            localappdata: Some(home.join("AppData").join("Local").into()),
            packaged: true,
            ..Default::default()
        };
        // The state directory itself.
        let moved = Env { config_dir: Some(appdata.join("yl").into()), ..base.clone() };
        assert!(matches!(
            DaemonConfig::from_placement(&moved),
            Err(StateDirError::UnderAppDataWhilePackaged { .. })
        ));
        // Each override, with the state directory allowed.
        for which in PathOverride::ALL {
            let mut env = Env { config_dir: Some(home.join(".yadorilink").into()), ..base.clone() };
            env.overrides[which as usize] = Some(appdata.join("x").into());
            match DaemonConfig::from_placement(&env) {
                Err(StateDirError::OverrideUnderAppDataWhilePackaged { variable, .. }) => {
                    assert_eq!(variable, which.variable());
                }
                other => panic!("{which:?}: {other:?}"),
            }
            // The same override outside AppData is honored.
            env.overrides[which as usize] = Some(home.join("elsewhere").into());
            DaemonConfig::from_placement(&env).unwrap();
        }
        assert!(!home.join(".yadorilink").exists());
        assert!(!home.join("AppData").exists(), "nothing is created under AppData");
    }

    /// A database written by an older build is refused, and the refusal is left
    /// where `status` can show it while no daemon answers: the reason, the exact
    /// data to delete, and the account step. A start that opens its data clears it.
    // apple-cfg: ios-explicit `run` refuses on iOS: the daemon process model does not run there
    #[cfg_attr(target_os = "ios", ignore = "the daemon process model does not run on iOS")]
    #[tokio::test]
    async fn an_older_schema_database_leaves_its_reason_and_reset_steps() {
        let _env_guard = CONFIG_ENV_MUTEX.lock().await;
        let config_dir = tempfile::tempdir().unwrap();
        let block_store_root = config_dir.path().join("blocks");
        let sync_db_path = config_dir.path().join("sync-state.sqlite3");
        std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());
        std::env::set_var("YADORILINK_BLOCK_STORE", &block_store_root);
        std::env::set_var("YADORILINK_SYNC_DB", &sync_db_path);
        std::fs::write(config_dir.path().join("device.json"), current_device_json()).unwrap();
        yadorilink_transport::DeviceSigningKeyPair::generate_and_persist(
            config_dir.path().join("signing_key"),
            yadorilink_transport::KeyMirror::Disabled,
        )
        .unwrap();
        {
            let conn = rusqlite::Connection::open(&sync_db_path).unwrap();
            conn.execute_batch("CREATE TABLE t(x); PRAGMA user_version = 1;").unwrap();
        }

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            run(DaemonConfig::from_env().unwrap()),
        )
        .await;
        let refusal = yadorilink_local_storage::startup_refusal::read(config_dir.path());

        std::env::remove_var("YADORILINK_CONFIG_DIR");
        std::env::remove_var("YADORILINK_BLOCK_STORE");
        std::env::remove_var("YADORILINK_SYNC_DB");

        outcome.expect("startup must fail closed").expect_err("an older schema must be refused");
        let refusal = refusal.expect("the refusal must be left for status to show");
        assert!(refusal.contains("cannot open the data on disk"), "{refusal}");
        assert!(refusal.contains("predates"), "the underlying reason: {refusal}");
        assert!(refusal.contains(&sync_db_path.display().to_string()), "{refusal}");
        assert!(refusal.contains(&block_store_root.display().to_string()), "{refusal}");
        let marker = yadorilink_sqlite_runtime::creation_marker_path(&sync_db_path);
        assert!(refusal.contains(&marker.display().to_string()), "the marker file: {refusal}");
        assert!(refusal.contains("remove this device"), "the account step: {refusal}");
    }

    /// A `device.json` from a newer build must abort startup before anything
    /// on disk changes.
    ///
    /// Asserting only the error type would pass even with the validation
    /// still sequenced *after* the database migration and the repair pass,
    /// so the untouched-state assertions below are the point of this test: a
    /// build that cannot understand this config must not migrate a schema, or
    /// sweep and rewrite files, that a newer build may have written beside it.
    #[tokio::test]
    async fn a_too_new_device_config_aborts_startup_before_touching_disk() {
        let attempt = start_daemon_with_device_json(&too_new_device_json()).await;

        assert!(
            !attempt.sync_db_path.exists(),
            "the sync database must not be created or migrated before device.json is validated, \
             but {} exists after a refused startup",
            attempt.sync_db_path.display()
        );
    }

    /// Every unusable-but-present `device.json` must reach the operator as its
    /// own case. A shared catch-all message is what makes a corrupt or too-new
    /// config read as "this device was never registered" — the one reading
    /// that invites registering a second identity for a device that already
    /// has one, which nothing afterwards can merge back.
    // apple-cfg: ios-explicit `run` refuses on iOS: the daemon process model does not run there
    #[cfg_attr(target_os = "ios", ignore = "the daemon process model does not run on iOS")]
    #[tokio::test]
    async fn each_unusable_device_config_reports_its_own_cause() {
        let corrupt = start_daemon_with_device_json("{ not json").await;
        let too_new = start_daemon_with_device_json(&too_new_device_json()).await;

        assert!(
            corrupt.error.contains("is not a valid current device config"),
            "a corrupt device.json must say so: {}",
            corrupt.error
        );
        assert!(
            too_new.error.contains("newer than this build supports"),
            "a too-new device.json must name the version conflict: {}",
            too_new.error
        );
        for error in [&corrupt.error, &too_new.error] {
            assert!(
                !error.contains("unregistered"),
                "a device.json that exists but cannot be used must never be described as an \
                 unregistered device: {error}"
            );
        }
    }
}

#[cfg(test)]
mod run_end_tests {
    use super::RunEnd;

    #[test]
    fn only_a_requested_restart_has_an_exit_status() {
        assert_eq!(RunEnd::Stopped.exit_status(), None);
        assert_eq!(RunEnd::RestartRequested.exit_status(), Some(75));
    }
}

#[cfg(test)]
mod shutdown_request_tests {
    use super::wait_for_shutdown_request;
    use std::time::Duration;

    fn never() -> impl std::future::Future<Output = &'static str> {
        std::future::pending()
    }

    #[tokio::test]
    async fn a_stop_requested_before_main_subscribed_still_ends_the_wait() {
        // A stop producer (a watch, the control socket) committed during a long startup, before
        // the main task looked at the channel.
        let (tx, _keep) = tokio::sync::watch::channel(false);
        tx.send_replace(true);
        let reason =
            tokio::time::timeout(Duration::from_secs(5), wait_for_shutdown_request(&tx, never()))
                .await
                .expect("an already requested stop must not be waited for");
        assert_eq!(reason, "control-socket Shutdown request");
    }

    #[tokio::test]
    async fn a_stop_requested_while_waiting_ends_the_wait() {
        let (tx, _keep) = tokio::sync::watch::channel(false);
        let tx = std::sync::Arc::new(tx);
        let tx2 = tx.clone();
        let wait = tokio::spawn(async move { wait_for_shutdown_request(&tx2, never()).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send_replace(true);
        assert_eq!(wait.await.unwrap(), "control-socket Shutdown request");
    }

    #[tokio::test]
    async fn a_signal_marks_the_shutdown_so_a_safe_stop_committing_meanwhile_loses() {
        let (tx, _keep) = tokio::sync::watch::channel(false);
        let reason = wait_for_shutdown_request(&tx, std::future::ready("SIGTERM")).await;
        assert_eq!(reason, "SIGTERM");
        assert!(*tx.borrow(), "the signal is part of the stop arbitration");
    }
}

#[cfg(test)]
mod stop_watch_placement_tests {
    /// The watches that ask for a safe stop start only once startup is complete, right before
    /// the task waits for a stop: before that point nothing would carry a committed stop out,
    /// and admission would stay closed. Pinned by source position (the first occurrences are the
    /// production ones).
    #[test]
    fn the_safe_stop_watches_start_after_the_last_startup_await() {
        let src = include_str!("app.rs");
        let at = |needle: &str| src.find(needle).unwrap_or_else(|| panic!("{needle}"));
        let startup_end = at("credential_store::coordination_auth(");
        let wait = at("wait_for_shutdown_request(&state.shutdown_tx");
        for watch in ["exe_replaced::spawn_if_supervised(", "exe_watch::watch("] {
            let p = at(watch);
            assert!(
                p > startup_end && p < wait,
                "{watch} must start after startup, before waiting"
            );
        }
    }
}
