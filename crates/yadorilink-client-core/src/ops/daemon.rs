//! Starting and stopping the local daemon.

use std::path::PathBuf;
use std::time::Duration;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    IdentifyRequest, IdentifyResponse, RequestSafeStopRequest, RequestSafeStopResponse,
    ShutdownRequest, StatusRequest,
};
use yadorilink_local_storage::daemon_lock::{self, LockProbe};
use yadorilink_local_storage::ownership::{self, Owner, StartVerdict};

use crate::daemon::control;
use crate::dto::DaemonLaunch;
use crate::error::CoreError;

/// What [`start_daemon`] found or did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonStartOutcome {
    /// The daemon already answered on the control socket; nothing was
    /// launched.
    AlreadyRunning,
    /// The daemon was launched and then answered.
    Started,
}

// The names of the OS registrations live in one table (`service_registrations`): the launchd label
// of the macOS background service (the app's daemon helper) and the Windows logon task that runs
// the daemon (see `DaemonLaunch::ScheduledTask`).
pub use yadorilink_local_storage::service_registrations::{
    MACOS_DAEMON_AGENT_LABEL, WINDOWS_DAEMON_TASK_NAME,
};

/// How the daemon is started when the caller does not choose: by spawning the
/// `yadorilink-daemon` next to the current executable (a build tree), else, on
/// macOS, through the background service (an installed CLI has no daemon
/// beside it: the daemon is the helper app inside YadoriLink.app), else by
/// spawning `yadorilink-daemon` from PATH.
fn default_launch() -> DaemonLaunch {
    if cfg!(target_os = "macos") && !daemon_binary_path().is_absolute() {
        DaemonLaunch::LaunchAgent { label: MACOS_DAEMON_AGENT_LABEL.into() }
    } else {
        DaemonLaunch::SpawnBinary { path: None }
    }
}

/// Why the daemon last refused to start over the data on disk (the reason and
/// the supported reset steps), if it did and has not started since.
#[must_use]
pub fn startup_refusal() -> Option<String> {
    // Reading a refusal from a directory this process may not use would show another store's.
    let dir = crate::coordination::device_config::config_dir().ok()?;
    yadorilink_local_storage::startup_refusal::read(&dir)
}

/// Launches the daemon if nothing answers the control socket (see
/// [`default_launch`]), then polls every 250 ms, for up to [`START_BUDGET`],
/// until it answers.
pub async fn start_daemon() -> Result<DaemonStartOutcome, CoreError> {
    start_daemon_with(&default_launch()).await
}

/// [`start_daemon`] with a chosen launch strategy (see [`DaemonLaunch`]).
///
/// # Errors
/// [`CoreError::DaemonUnresponsive`] when a daemon is already running but
/// does not answer: nothing is launched, since another copy cannot help.
/// [`CoreError::DaemonNotRunning`] is never returned for a launch failure;
/// every way the daemon could not be brought up is [`CoreError::Other`],
/// naming what was tried.
pub async fn start_daemon_with(launch: &DaemonLaunch) -> Result<DaemonStartOutcome, CoreError> {
    match control::send(ReqPayload::Status(StatusRequest {})).await {
        Ok(_) => return Ok(DaemonStartOutcome::AlreadyRunning),
        Err(CoreError::DaemonUnresponsive) => return Err(CoreError::DaemonUnresponsive),
        Err(_) => {}
    }

    let config_dir = crate::coordination::device_config::config_dir()?;
    let cli_exe = std::env::current_exe().unwrap_or_default();
    gate_launch(&config_dir, launch_owner(launch, &cli_exe))?;
    wait_for_launch(&launch_steps(launch, current_uid()), StartTiming::DEFAULT).await
}

/// The read-only `identify` report of the running daemon: its version, engine build, install
/// source and the data area's recorded owner. Changes nothing.
///
/// # Errors
/// [`CoreError::DaemonNotRunning`] / [`CoreError::DaemonUnresponsive`] when nothing answers.
pub async fn identify() -> Result<IdentifyResponse, CoreError> {
    let resp = control::send(ReqPayload::Identify(IdentifyRequest {})).await?;
    match resp.payload {
        Some(RespPayload::Identify(identity)) => Ok(identity),
        _ => Err(CoreError::Other("unexpected daemon response".into())),
    }
}

/// Asks the daemon to reach a safe point and exit (see the `request_safe_stop` control request).
/// The answer is either that it has begun to exit with success (wait for the process or the
/// data-area lock to go) or that it is busy and keeps running (retry after the hinted wait).
/// `deadline` bounds how long the daemon waits for in-flight writes; `None` takes its default.
///
/// # Errors
/// [`CoreError::DaemonNotRunning`] / [`CoreError::DaemonUnresponsive`] when nothing answers in
/// time (the request itself waits up to the deadline).
pub async fn request_safe_stop(
    deadline: Option<Duration>,
) -> Result<RequestSafeStopResponse, CoreError> {
    let secs = deadline.map_or(0, |d| u32::try_from(d.as_secs().max(1)).unwrap_or(u32::MAX));
    // The daemon may spend the whole deadline before it answers.
    let budget = Duration::from_secs(u64::from(if secs == 0 { 30 } else { secs.min(300) }))
        + Duration::from_secs(15);
    let request =
        control::send(ReqPayload::RequestSafeStop(RequestSafeStopRequest { deadline_secs: secs }));
    let resp = tokio::time::timeout(budget, request)
        .await
        .map_err(|_| CoreError::DaemonUnresponsive)??;
    match resp.payload {
        Some(RespPayload::RequestSafeStop(answer)) => Ok(answer),
        _ => Err(CoreError::Other("unexpected daemon response".into())),
    }
}

/// The distribution whose daemon `launch` would bring up: the app's helper for a LaunchAgent, the
/// named binary for a spawn (the one beside `cli_exe` or on `PATH` is the CLI's own), and the CLI's
/// own for a scheduled task.
fn launch_owner(launch: &DaemonLaunch, cli_exe: &std::path::Path) -> Owner {
    match launch {
        DaemonLaunch::LaunchAgent { .. } => Owner::Gui,
        DaemonLaunch::SpawnBinary { path } => {
            let binary = path.as_ref().map_or_else(daemon_binary_path, PathBuf::from);
            if binary.is_absolute() {
                Owner::of_executable(&binary)
            } else {
                Owner::of_executable(cli_exe)
            }
        }
        DaemonLaunch::ScheduledTask { .. } => Owner::of_executable(cli_exe),
    }
}

/// Refuses to launch a daemon of `owner` over a data area recorded as another owner's, or whose
/// record cannot be read. A data area with no record is launched over: the daemon records itself.
fn gate_launch(config_dir: &std::path::Path, owner: Owner) -> Result<(), CoreError> {
    if let Some(refusal) = yadorilink_local_storage::handoff::start_refusal(config_dir) {
        return Err(CoreError::ManagedElsewhere(refusal.message(config_dir)));
    }
    match ownership::start_verdict(&ownership::read(config_dir), owner) {
        StartVerdict::Proceed | StartVerdict::NoRecord => Ok(()),
        StartVerdict::Refuse(refusal) => {
            Err(CoreError::ManagedElsewhere(refusal.message(config_dir)))
        }
    }
}

/// How long [`wait_for_launch`] waits for the daemon, and how often it repeats
/// a launch that has not taken.
#[derive(Clone, Copy)]
struct StartTiming {
    budget: Duration,
    relaunch_every: Duration,
}

impl StartTiming {
    const DEFAULT: Self = Self { budget: START_BUDGET, relaunch_every: RELAUNCH_EVERY };
}

/// Runs the first step that launches, then polls every 250 ms until the daemon
/// answers or the budget is spent. A step that waits for its program
/// (`launchctl kickstart`) is repeated while nothing answers: launchd can
/// accept a kickstart for a job it is still tearing down, which starts
/// nothing, and a gracefully stopped job is not restarted by itself.
async fn wait_for_launch(
    steps: &[LaunchStep],
    timing: StartTiming,
) -> Result<DaemonStartOutcome, CoreError> {
    let mut failures = Vec::new();
    let mut launched = None;
    for step in steps {
        match run_step(step) {
            Ok(()) => {
                launched = Some(step);
                break;
            }
            Err(e) => failures.push(format!("{}: {e}", step.program.display())),
        }
    }
    let Some(launched) = launched else {
        // One attempt reads as it always has: "failed to launch <path>: <error>".
        return Err(CoreError::Other(format!("failed to launch {}", failures.join("; then "))));
    };

    // Bounded by elapsed time, not by attempts: a probe that connects and
    // then waits on its reply deadline would otherwise stretch each attempt.
    let answered = tokio::time::timeout(timing.budget, async {
        let mut since_launch = Duration::ZERO;
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if daemon_answers().await {
                return;
            }
            since_launch += Duration::from_millis(250);
            if launched.wait && since_launch >= timing.relaunch_every {
                since_launch = Duration::ZERO;
                // A repeat that fails is no news: the budget reports the outcome.
                let _ = run_step(launched);
            }
        }
    })
    .await;
    match answered {
        Ok(()) => Ok(DaemonStartOutcome::Started),
        Err(_) => {
            let mut message =
                "the daemon did not answer after it was started; run `yadorilink daemon start`"
                    .to_string();
            if let Some(refusal) = startup_refusal() {
                message = format!("{message}\n{refusal}");
            }
            Err(CoreError::Other(message))
        }
    }
}

/// How long a freshly launched daemon has to start answering: a first start
/// creates its keys and database before it listens.
pub const START_BUDGET: Duration = Duration::from_secs(30);

/// How long a launch that has not taken is left alone before it is repeated.
const RELAUNCH_EVERY: Duration = Duration::from_secs(3);

/// One way of bringing the daemon up, tried in order until one launches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LaunchStep {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<String>,
    /// Wait for the program and require success (`launchctl`), rather than
    /// spawning it and leaving it running (the daemon itself).
    pub(crate) wait: bool,
}

/// The launch attempts for `launch`. A LaunchAgent is started through
/// `/bin/launchctl`, so this strategy never searches PATH for anything.
pub(crate) fn launch_steps(launch: &DaemonLaunch, uid: u32) -> Vec<LaunchStep> {
    match launch {
        DaemonLaunch::SpawnBinary { path } => vec![LaunchStep {
            program: path.as_ref().map_or_else(daemon_binary_path, PathBuf::from),
            args: Vec::new(),
            wait: false,
        }],
        DaemonLaunch::LaunchAgent { label } => vec![LaunchStep {
            program: PathBuf::from("/bin/launchctl"),
            args: vec!["kickstart".into(), format!("gui/{uid}/{label}")],
            wait: true,
        }],
        DaemonLaunch::ScheduledTask { name } => vec![LaunchStep {
            program: schtasks_path(std::env::var_os("SystemRoot")),
            args: vec!["/Run".into(), "/TN".into(), name.clone()],
            wait: true,
        }],
    }
}

/// `schtasks.exe` under the system directory, so no PATH entry can stand in for it.
fn schtasks_path(system_root: Option<std::ffi::OsString>) -> PathBuf {
    PathBuf::from(system_root.unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
        .join("schtasks.exe")
}

fn run_step(step: &LaunchStep) -> std::io::Result<()> {
    let mut command = std::process::Command::new(&step.program);
    command.args(&step.args);
    no_console_window(&mut command);
    if !step.wait {
        return spawn_detached(command);
    }
    let output = command.stdin(std::process::Stdio::null()).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{} ({})",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// A console-subsystem program started by a GUI process (the packaged app) gets a visible
/// console window of its own unless it is created without one.
fn no_console_window(command: &mut std::process::Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        std::os::windows::process::CommandExt::creation_flags(command, CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = command;
}

/// Starts a program that outlives this call, such as the daemon itself.
/// It gets no stdin and, on Unix, its own process group, so a terminal's
/// Ctrl-C aimed at the starter does not reach it. A thread waits for it, so
/// when it exits it is reaped instead of staying a zombie of a long-lived
/// starter such as the app. Its stdout and stderr stay the starter's, where
/// a daemon started from a terminal logs.
fn spawn_detached(mut command: std::process::Command) -> std::io::Result<()> {
    command.stdin(std::process::Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn()?;
    std::thread::Builder::new().name("yadorilink-daemon-reaper".into()).spawn(move || {
        let _ = child.wait();
    })?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
pub(crate) fn current_uid() -> u32 {
    0
}

async fn daemon_answers() -> bool {
    control::send(ReqPayload::Status(StatusRequest {})).await.is_ok()
}

/// Asks the daemon to shut down cleanly. Under a supervisor that restarts it
/// (the macOS LaunchAgent's `KeepAlive`, the Windows logon task), this is a
/// restart.
pub async fn stop_daemon() -> Result<(), CoreError> {
    control::send(ReqPayload::Shutdown(ShutdownRequest {})).await?;
    Ok(())
}

/// Whether a daemon answers on the control socket.
pub async fn is_running() -> bool {
    daemon_answers().await
}

/// Stops a running daemon and waits until it has stopped answering and released the data-area
/// lock, so the files it runs from may be removed. Does nothing when no daemon is there.
///
/// # Errors
/// [`CoreError::Other`] when the daemon is still there after `budget`.
pub async fn stop_and_wait(budget: Duration) -> Result<(), CoreError> {
    let config_dir = crate::coordination::device_config::config_dir()?;
    // A daemon that holds the lock without answering (starting up, shutting down) is still there.
    if daemon_answers().await {
        stop_daemon().await?;
    }
    let gone = tokio::time::timeout(budget, async {
        while daemon_answers().await || daemon_lock::probe(&config_dir) != LockProbe::Free {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    gone.map_err(|_| CoreError::Other("the running daemon did not stop in time".into()))
}

/// Restarts a daemon that is already running, so it starts again with the
/// device registration and credential that now exist on disk; a daemon
/// reads both only at startup. Does nothing when no daemon answers: the next
/// one to start reads them anyway.
///
/// # Errors
/// [`CoreError::Other`] when the old daemon is still answering after
/// [`RESTART_BUDGET`], or the new one could not be started.
pub(crate) async fn restart_if_running() -> Result<(), CoreError> {
    restart_if_running_with(&default_launch()).await
}

/// [`restart_if_running`] with a chosen launch strategy. Under a supervisor
/// that restarts the daemon by itself the launch finds it already running.
pub(crate) async fn restart_if_running_with(launch: &DaemonLaunch) -> Result<(), CoreError> {
    let config_dir = crate::coordination::device_config::config_dir()?;
    restart_if_running_in(launch, &config_dir, RESTART_BUDGET, LOCK_RELEASE_BUDGET).await
}

/// The restart, with the data area and the two waits chosen. The control socket going quiet does
/// not mean the old daemon has exited: it keeps `.daemon.lock` until its process ends, and a new
/// daemon started before that is refused as "already running" and exits. So the restart waits for
/// the lock to be free, and says so when it is not, instead of launching a daemon that cannot win.
async fn restart_if_running_in(
    launch: &DaemonLaunch,
    config_dir: &std::path::Path,
    stop_budget: Duration,
    lock_budget: Duration,
) -> Result<(), CoreError> {
    if !daemon_answers().await {
        return Ok(());
    }
    stop_daemon().await?;
    let gone = tokio::time::timeout(stop_budget, async {
        while daemon_answers().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if gone.is_err() {
        return Err(CoreError::Other(
            "the running daemon did not stop; restart it with `yadorilink daemon stop` and \
             `yadorilink daemon start`"
                .into(),
        ));
    }
    let released = tokio::time::timeout(lock_budget, async {
        // A supervisor may already have brought the replacement up: it holds the lock and answers.
        while daemon_lock::probe(config_dir) != LockProbe::Free && !daemon_answers().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if released.is_err() {
        return Err(CoreError::Other(
            "the old daemon stopped answering but is still exiting, so the new one cannot start \
             yet; wait a moment and run `yadorilink daemon start`"
                .into(),
        ));
    }
    start_daemon_with(launch).await?;
    Ok(())
}

/// How long a daemon asked to stop has to stop answering.
const RESTART_BUDGET: Duration = Duration::from_secs(10);

/// How long a daemon that stopped answering has to release the data area's lock (exit).
const LOCK_RELEASE_BUDGET: Duration = Duration::from_secs(20);

/// `yadorilink-daemon[.exe]` next to the current executable when it exists
/// there, else the bare name for a PATH lookup.
fn daemon_binary_path() -> PathBuf {
    let name = if cfg!(windows) { "yadorilink-daemon.exe" } else { "yadorilink-daemon" };
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that point the control client at their own socket share the
    /// process-global `YADORILINK_CONTROL_SOCKET`, so they run one at a time.
    #[cfg(unix)]
    static SOCKET_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[test]
    fn a_launch_is_refused_over_another_owners_data_and_allowed_over_its_own() {
        let dir = tempfile::tempdir().unwrap();
        // No record yet: the daemon records itself.
        gate_launch(dir.path(), Owner::Cli).unwrap();
        ownership::write(
            dir.path(),
            &ownership::OwnershipRecord {
                owner: Owner::Gui,
                install_source: "app_bundle".into(),
                install_root: "/Applications/YadoriLink.app".into(),
                release_id: String::new(),
                written_at: 1,
            },
        )
        .unwrap();
        gate_launch(dir.path(), Owner::Gui).unwrap();
        let refused = gate_launch(dir.path(), Owner::Cli).unwrap_err();
        assert!(matches!(&refused, CoreError::ManagedElsewhere(m) if m.contains("YadoriLink app")));
        std::fs::write(dir.path().join(ownership::FILE_NAME), b"{").unwrap();
        for owner in [Owner::Cli, Owner::Gui] {
            assert!(matches!(gate_launch(dir.path(), owner), Err(CoreError::ManagedElsewhere(_))));
        }
    }

    #[test]
    fn a_launch_is_refused_while_a_hand_off_to_the_app_is_half_applied() {
        use yadorilink_local_storage::handoff::journal::{self, Journal, Phase};
        let dir = tempfile::tempdir().unwrap();
        let record = |owner, source: &str| ownership::OwnershipRecord {
            owner,
            install_source: source.into(),
            install_root: "/x".into(),
            release_id: String::new(),
            written_at: 1,
        };
        ownership::write(dir.path(), &record(Owner::Cli, "script")).unwrap();
        let mut j = Journal::new(
            record(Owner::Cli, "script"),
            record(Owner::Gui, "app_bundle"),
            true,
            Vec::new(),
            1,
        );
        for (phase, allowed) in [
            (Phase::Planned, true),
            (Phase::Stopped, true),
            (Phase::Switching, false),
            (Phase::RollingBack, false),
        ] {
            j.phase = phase;
            journal::write(dir.path(), &j).unwrap();
            let result = gate_launch(dir.path(), Owner::Cli);
            assert_eq!(result.is_ok(), allowed, "{phase:?}");
            if let Err(CoreError::ManagedElsewhere(message)) = result {
                assert!(message.contains("release-to-app"), "{message}");
            }
        }
    }

    #[test]
    fn the_owner_of_a_launch_is_the_distribution_of_the_daemon_it_starts() {
        let app_cli =
            std::path::Path::new("/Applications/YadoriLink.app/Contents/MacOS/yadorilink");
        let loose_cli = std::path::Path::new("/usr/local/bin/yadorilink");
        let agent = DaemonLaunch::LaunchAgent { label: MACOS_DAEMON_AGENT_LABEL.into() };
        // An installed CLI that kicks the app's helper is asking the app, whatever the CLI is.
        assert_eq!(launch_owner(&agent, loose_cli), Owner::Gui);
        let bare = DaemonLaunch::SpawnBinary { path: Some("yadorilink-daemon".into()) };
        assert_eq!(launch_owner(&bare, app_cli), Owner::Gui);
        assert_eq!(launch_owner(&bare, loose_cli), Owner::Cli);
        let inside = DaemonLaunch::SpawnBinary {
            path: Some("/Applications/YadoriLink.app/Contents/Helpers/yadorilink-daemon".into()),
        };
        assert_eq!(launch_owner(&inside, loose_cli), Owner::Gui);
    }

    #[test]
    fn launch_agent_is_a_launchctl_kickstart_and_never_uses_path() {
        let agent = DaemonLaunch::LaunchAgent { label: MACOS_DAEMON_AGENT_LABEL.into() };
        assert_eq!(
            launch_steps(&agent, 501),
            vec![LaunchStep {
                program: "/bin/launchctl".into(),
                args: vec!["kickstart".into(), "gui/501/com.juntaki.yadorilink.daemon".into()],
                wait: true,
            }]
        );
    }

    #[test]
    fn scheduled_task_runs_schtasks_from_system32_and_never_uses_path() {
        let task = DaemonLaunch::ScheduledTask { name: WINDOWS_DAEMON_TASK_NAME.into() };
        let steps = launch_steps(&task, 0);
        assert_eq!(steps.len(), 1, "no fallback to spawning a binary");
        assert_eq!(
            steps[0].args,
            vec!["/Run".to_string(), "/TN".into(), "YadoriLinkDaemon".into()]
        );
        assert!(steps[0].wait, "a task that cannot run must fail the launch");
        assert!(steps[0].program.is_absolute() || cfg!(not(windows)));
        assert!(steps[0].program.ends_with("System32/schtasks.exe"), "{:?}", steps[0].program);
        assert_eq!(
            schtasks_path(Some("D:\\Win".into())),
            PathBuf::from("D:\\Win").join("System32").join("schtasks.exe")
        );
        assert_eq!(
            schtasks_path(None),
            PathBuf::from("C:\\Windows").join("System32").join("schtasks.exe")
        );
    }

    #[test]
    fn the_default_launch_is_the_background_service_on_macos_without_a_daemon_beside_the_cli() {
        // A test binary runs from target/<profile>/deps, which holds no `yadorilink-daemon`.
        let expected = if cfg!(target_os = "macos") {
            DaemonLaunch::LaunchAgent { label: MACOS_DAEMON_AGENT_LABEL.into() }
        } else {
            DaemonLaunch::SpawnBinary { path: None }
        };
        assert_eq!(default_launch(), expected);
    }

    #[test]
    fn spawn_binary_uses_the_given_path_else_the_default_lookup() {
        let given = DaemonLaunch::SpawnBinary { path: Some("/opt/y/yadorilink-daemon".into()) };
        assert_eq!(launch_steps(&given, 0)[0].program, PathBuf::from("/opt/y/yadorilink-daemon"));
        let default = DaemonLaunch::SpawnBinary { path: None };
        assert_eq!(launch_steps(&default, 0)[0].program, daemon_binary_path());
    }

    /// The name it looks for is a pure, display-free fact worth pinning; the
    /// "sibling of the current executable, else PATH" resolution needs a real
    /// filesystem layout to test end to end.
    #[test]
    fn daemon_binary_path_uses_the_platform_correct_name() {
        let path = daemon_binary_path();
        let name = path.file_name().unwrap().to_string_lossy();
        if cfg!(windows) {
            assert_eq!(name, "yadorilink-daemon.exe");
        } else {
            assert_eq!(name, "yadorilink-daemon");
        }
    }

    /// A daemon started directly, rather than by a supervisor, is the
    /// starting process's child. When it exits it must be reaped, or a
    /// long-lived app keeps a zombie for the rest of its life.
    #[cfg(unix)]
    #[test]
    fn a_directly_started_daemon_is_reaped_when_it_exits() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let step = LaunchStep {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), format!("echo $$ > '{}'", pid_file.display())],
            wait: false,
        };
        run_step(&step).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let pid = loop {
            if let Some(pid) = std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|text| text.trim().parse::<libc::pid_t>().ok())
            {
                break pid;
            }
            assert!(std::time::Instant::now() < deadline, "the started process never ran");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        // A zombie still accepts signal 0; only a reaped process is gone.
        // SAFETY: signal 0 only checks that the process exists.
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the exited daemon process {pid} was never reaped"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    #[cfg(unix)]
    async fn serve_until_shutdown(listener: &tokio::net::UnixListener) {
        use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
        use yadorilink_ipc_proto::daemonctl::{
            DaemonControlRequest, DaemonControlResponse, ShutdownResponse, StatusResponse,
            CONTROL_PROTOCOL_VERSION,
        };
        use yadorilink_ipc_proto::framing::{read_message, write_message};
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let Ok(Some(request)) = read_message::<DaemonControlRequest>(&mut stream).await else {
                continue;
            };
            let (payload, done) = match request.payload {
                Some(ReqPayload::Shutdown(_)) => (RespPayload::Shutdown(ShutdownResponse {}), true),
                _ => (RespPayload::Status(StatusResponse::default()), false),
            };
            let response = DaemonControlResponse {
                daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
                payload: Some(payload),
            };
            write_message(&mut stream, &response).await.unwrap();
            if done {
                return;
            }
        }
    }

    /// A running daemon read the device registration at startup, so
    /// registering has to restart it: ask it to stop, wait until it is gone,
    /// launch a new one, and return only once that one answers.
    #[cfg(unix)]
    #[tokio::test]
    async fn restart_stops_the_running_daemon_and_launches_a_new_one() {
        let _guard = SOCKET_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let launched = dir.path().join("launched");
        let script = dir.path().join("launch.sh");
        std::fs::write(&script, format!("#!/bin/sh\ntouch '{}'\n", launched.display())).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

        let fake_daemon = tokio::spawn({
            let socket = socket.clone();
            let launched = launched.clone();
            async move {
                serve_until_shutdown(&listener).await;
                drop(listener);
                std::fs::remove_file(&socket).unwrap();
                // The new daemon appears only once it has been launched.
                while !launched.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                serve_until_shutdown(&listener).await;
            }
        });

        let launch = DaemonLaunch::SpawnBinary { path: Some(script.display().to_string()) };
        let result = restart_if_running_in(
            &launch,
            dir.path(),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await;
        std::env::remove_var("YADORILINK_CONTROL_SOCKET");
        fake_daemon.abort();

        result.unwrap();
        assert!(launched.exists(), "the stopped daemon was never launched again");
    }

    /// The old daemon stops answering the control socket but keeps `.daemon.lock` for a while (it
    /// is still exiting). A new daemon started in that window is refused by the lock and never
    /// answers; the restart must wait for the lock to go before it launches.
    #[cfg(unix)]
    #[tokio::test]
    async fn restart_waits_for_the_old_daemon_to_release_the_lock_before_launching() {
        let _guard = SOCKET_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let launched = dir.path().join("launched");
        let script = dir.path().join("launch.sh");
        std::fs::write(&script, format!("#!/bin/sh\ntouch '{}'\n", launched.display())).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);
        let old_lock = daemon_lock::HeldLock::acquire_daemon_lock(dir.path()).unwrap();

        let fake_daemon = tokio::spawn({
            let socket = socket.clone();
            let launched = launched.clone();
            let config_dir = dir.path().to_path_buf();
            async move {
                serve_until_shutdown(&listener).await;
                drop(listener);
                std::fs::remove_file(&socket).unwrap();
                // Still exiting: the lock outlives the socket, and is dropped on its own clock.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(700)).await;
                    drop(old_lock);
                });
                while !launched.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                // The new daemon takes the lock as the real one does, or exits.
                let Ok(_new_lock) = daemon_lock::HeldLock::acquire_daemon_lock(&config_dir) else {
                    return;
                };
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                serve_until_shutdown(&listener).await;
            }
        });
        // A launch before the lock is dropped makes the fake new daemon lose the lock race.
        let launch = DaemonLaunch::SpawnBinary { path: Some(script.display().to_string()) };
        let result = restart_if_running_in(
            &launch,
            dir.path(),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await;
        std::env::remove_var("YADORILINK_CONTROL_SOCKET");
        fake_daemon.abort();
        result.unwrap();
    }

    /// A supervisor that restarts the daemon by itself brings the replacement up while the restart
    /// waits for the lock; the replacement holds the lock for its whole life but answers.
    #[cfg(unix)]
    #[tokio::test]
    async fn restart_accepts_a_replacement_the_supervisor_started() {
        let _guard = SOCKET_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);
        let old_lock = daemon_lock::HeldLock::acquire_daemon_lock(dir.path()).unwrap();
        let fake = tokio::spawn({
            let socket = socket.clone();
            let config_dir = dir.path().to_path_buf();
            async move {
                serve_until_shutdown(&listener).await;
                drop(listener);
                std::fs::remove_file(&socket).unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
                drop(old_lock);
                let _new_lock = daemon_lock::HeldLock::acquire_daemon_lock(&config_dir).unwrap();
                answer_status_forever(tokio::net::UnixListener::bind(&socket).unwrap()).await;
            }
        });
        let launch = DaemonLaunch::SpawnBinary { path: Some("/nonexistent/daemon".into()) };
        let result = restart_if_running_in(
            &launch,
            dir.path(),
            Duration::from_secs(5),
            Duration::from_millis(1500),
        )
        .await;
        std::env::remove_var("YADORILINK_CONTROL_SOCKET");
        fake.abort();
        result.unwrap();
    }

    /// A lock that never goes is reported, and nothing is launched over it.
    #[cfg(unix)]
    #[tokio::test]
    async fn restart_reports_an_old_daemon_that_never_releases_the_lock() {
        let _guard = SOCKET_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let launched = dir.path().join("launched");
        let script = dir.path().join("launch.sh");
        std::fs::write(&script, format!("#!/bin/sh\ntouch '{}'\n", launched.display())).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);
        let _old_lock = daemon_lock::HeldLock::acquire_daemon_lock(dir.path()).unwrap();
        let fake_daemon = tokio::spawn({
            let socket = socket.clone();
            async move {
                serve_until_shutdown(&listener).await;
                drop(listener);
                std::fs::remove_file(&socket).unwrap();
            }
        });
        let launch = DaemonLaunch::SpawnBinary { path: Some(script.display().to_string()) };
        let result = restart_if_running_in(
            &launch,
            dir.path(),
            Duration::from_secs(5),
            Duration::from_millis(400),
        )
        .await;
        std::env::remove_var("YADORILINK_CONTROL_SOCKET");
        fake_daemon.abort();
        let message = result.unwrap_err().to_string();
        assert!(message.contains("yadorilink daemon start"), "{message}");
        assert!(!launched.exists());
    }

    #[cfg(unix)]
    async fn answer_status_forever(listener: tokio::net::UnixListener) {
        use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
        use yadorilink_ipc_proto::daemonctl::{
            DaemonControlRequest, DaemonControlResponse, StatusResponse, CONTROL_PROTOCOL_VERSION,
        };
        use yadorilink_ipc_proto::framing::{read_message, write_message};
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let Ok(Some(_)) = read_message::<DaemonControlRequest>(&mut stream).await else {
                continue;
            };
            let response = DaemonControlResponse {
                daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
                payload: Some(RespPayload::Status(StatusResponse::default())),
            };
            write_message(&mut stream, &response).await.unwrap();
        }
    }

    /// A kickstart launchd accepted while it was still tearing the stopped job
    /// down starts nothing; repeating it is what brings the daemon back.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_launch_that_did_not_take_is_repeated_until_the_daemon_answers() {
        let _guard = SOCKET_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let launches = dir.path().join("launches");
        let script = dir.path().join("launch.sh");
        std::fs::write(&script, format!("#!/bin/sh\necho x >> '{}'\n", launches.display()))
            .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

        // The daemon comes up only from the second launch on.
        let fake_daemon = tokio::spawn({
            let socket = socket.clone();
            let launches = launches.clone();
            async move {
                while std::fs::read_to_string(&launches).map_or(0, |s| s.lines().count()) < 2 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                answer_status_forever(tokio::net::UnixListener::bind(&socket).unwrap()).await;
            }
        });

        let step = LaunchStep { program: script, args: Vec::new(), wait: true };
        let timing = StartTiming {
            budget: Duration::from_secs(30),
            relaunch_every: Duration::from_millis(300),
        };
        let result = wait_for_launch(&[step], timing).await;
        std::env::remove_var("YADORILINK_CONTROL_SOCKET");
        fake_daemon.abort();

        assert_eq!(result.unwrap(), DaemonStartOutcome::Started);
    }

    /// With no daemon running there is nothing to restart and nothing to
    /// launch: the next daemon to start reads the registration anyway.
    #[cfg(unix)]
    #[tokio::test]
    async fn restart_without_a_running_daemon_launches_nothing() {
        let _guard = SOCKET_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let launched = dir.path().join("launched");
        let script = dir.path().join("launch.sh");
        std::fs::write(&script, format!("#!/bin/sh\ntouch '{}'\n", launched.display())).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("absent.sock"));
        let result = restart_if_running_with(&DaemonLaunch::SpawnBinary {
            path: Some(script.display().to_string()),
        })
        .await;
        std::env::remove_var("YADORILINK_CONTROL_SOCKET");
        result.unwrap();
        assert!(!launched.exists());
    }
}
