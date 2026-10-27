//! Long-running sync daemon entry point.
//!
//! This is deliberately thin: it builds the real (production) multi-threaded
//! tokio runtime and hands off to [`yadorilink_daemon::app::run`], which
//! holds the entire daemon lifecycle. Keeping the lifecycle in the library
//! is what lets a test drive an in-process daemon instance by calling
//! `run(..)` directly with its own `DaemonConfig`, instead of going through
//! this real process entry point.

// A background start (logon task, packaged app) must not open a console window, so the Windows
// binary uses the GUI subsystem; `console::attach_parent` gives a start from a terminal its
// console back, and without one the log file (`log_roll`) is where output goes.
#![cfg_attr(windows, windows_subsystem = "windows")]

// `yadorilink-daemon` takes no settings as arguments -- every real
// setting comes from `DaemonConfig::from_env()`, matching this binary's own
// doc comment above. `--restart-on-replace` (a restarting supervisor's
// declaration, see `exe_replaced`) is read in `async_main`. `--help`/`--version` and unknown arguments are handled here
// (`launch_args`, not via `clap`, to keep this genuinely thin): a daemon binary that
// silently ignores `--version` and starts the full sync daemon instead is
// a real footgun for a package build/test step (this repo's own
// `juntaki/homebrew-yadorilink` Formula test, `lintian`, a Docker
// healthcheck) that expects the ordinary `binary --version` convention to
// just print a version and exit, not bind sockets and open a database.
fn handle_launch_args_or_exit() {
    use std::io::Write as _;
    use yadorilink_daemon::launch_args::{classify, usage, LaunchAction};
    match classify(std::env::args().skip(1)) {
        LaunchAction::Run => {}
        LaunchAction::Help => {
            let mut out = std::io::stdout().lock();
            let _ = write!(out, "{}", usage());
            let _ = out.flush();
            std::process::exit(0);
        }
        LaunchAction::Version => {
            // The embedded build identity is printed so a release can check that the binary it
            // ships carries the identity it publishes (`check-engine-artifact.py`).
            let release = yadorilink_local_storage::release_descriptor::embedded_build()
                .map(|b| format!(" (release {})", b.release_id))
                .unwrap_or_default();
            // Written and flushed explicitly: `process::exit` does not run destructors, and a
            // closed or missing stdout must not turn the exit into a panic.
            let mut out = std::io::stdout().lock();
            let _ = writeln!(
                out,
                "{} {} (host api {}){release}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION
            );
            let _ = out.flush();
            std::process::exit(0);
        }
        LaunchAction::Refuse(arg) => {
            let mut err = std::io::stderr().lock();
            let _ =
                writeln!(err, "yadorilink-daemon: unrecognized argument '{arg}'\n\n{}", usage());
            let _ = err.flush();
            std::process::exit(2);
        }
    }
}

fn main() -> anyhow::Result<()> {
    console::attach_parent();
    handle_launch_args_or_exit();
    // Before the runtime spawns its threads: glibc arenas are created per
    // contending thread and an existing arena is never merged away.
    let arena_cap = yadorilink_daemon::malloc_arenas::cap_arenas(
        std::env::var_os("MALLOC_ARENA_MAX").as_deref(),
    );
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(arena_cap))
}

async fn async_main(arena_cap: yadorilink_daemon::malloc_arenas::ArenaCap) -> anyhow::Result<()> {
    {
        use tracing_subscriber::filter::FilterExt as _;
        use tracing_subscriber::layer::{Layer as _, SubscriberExt as _};
        use tracing_subscriber::util::SubscriberInitExt as _;
        let env = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let throttle = yadorilink_daemon::log_throttle::WarnThrottle::default();
        let filter = env.and(throttle);
        // The macOS LaunchAgent logs to a file that rolls by size instead of
        // growing in launchd's unrotated StandardOutPath files.
        let rolling = yadorilink_daemon::log_roll::log_file_path(
            &yadorilink_fs_platform::state_dir::Env::from_process(),
            std::env::var_os("HOME"),
        )
        .and_then(|p| {
            yadorilink_daemon::log_roll::RollingLog::open(p, yadorilink_daemon::log_roll::MAX_BYTES)
                .ok()
        });
        match rolling {
            Some(w) => tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(w)
                        .with_filter(filter),
                )
                .init(),
            None => tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_filter(filter))
                .init(),
        }
    }
    if std::env::args().skip(1).any(|arg| arg == yadorilink_daemon::exe_replaced::SUPERVISED_ARG) {
        yadorilink_daemon::exe_replaced::arm();
    }
    yadorilink_daemon::malloc_arenas::log(arena_cap);
    yadorilink_daemon::fd_limit::raise_nofile_soft_limit();
    let result = match yadorilink_daemon::app::DaemonConfig::from_env() {
        Ok(config) => yadorilink_daemon::app::run(config).await,
        Err(refusal) => {
            let env = yadorilink_fs_platform::state_dir::Env::from_process();
            yadorilink_daemon::app::record_placement_refusal(&env, None, &refusal);
            Err(refusal.into())
        }
    };
    if let Err(error) = &result {
        // The returned error goes to stderr only; the log file is where the
        // service manager's users look.
        tracing::error!(error = %error, "the daemon exited with an error");
        if error.downcast_ref::<yadorilink_daemon::identity::OwnershipRefused>().is_some() {
            // Another owner manages this data area. A service manager that restarts a failed
            // daemon would start this one again at once, forever; waiting before exiting (the
            // data-area lock is already released) spaces those attempts out without hiding the
            // refusal, which stays in the log and in the startup-refusal record. The distinct
            // status, EX_CONFIG, tells a supervisor this is configuration, not a crash.
            tokio::time::sleep(yadorilink_daemon::identity::REFUSAL_BACKOFF).await;
            eprintln!("{error}");
            std::process::exit(yadorilink_daemon::identity::REFUSAL_EXIT_CODE);
        }
    }
    if let Ok(end) = &result {
        if let Some(status) = end.exit_status() {
            // The supervisor restarts a daemon that exits with a non-zero status.
            tracing::info!("executable replaced; restarting");
            std::process::exit(status);
        }
    }
    result.map(|_| ())
}

/// Foreground use from a terminal keeps printing to it although the binary has no console of
/// its own (GUI subsystem on Windows). Elsewhere there is nothing to do.
mod console {
    #[cfg(not(windows))]
    pub fn attach_parent() {}

    #[cfg(windows)]
    pub fn attach_parent() {
        use windows_sys::Win32::Foundation::{
            GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, GetFileType, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_UNKNOWN,
            OPEN_EXISTING,
        };
        use windows_sys::Win32::System::Console::{
            AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
            STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };

        // A GUI-subsystem process is not connected to a console at start, so a handle value
        // inherited for a console (no redirection) is stale: it is non-null yet refers to
        // nothing. Only a handle with a known file type is a real redirection (file, pipe).
        // SAFETY (all calls below): plain Win32 calls with valid arguments.
        let usable = |handle: HANDLE| unsafe {
            !handle.is_null()
                && handle != INVALID_HANDLE_VALUE
                && GetFileType(handle) != FILE_TYPE_UNKNOWN
        };
        let which_handles = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
        // Captured before attaching: attaching may rebind the standard handles to the console
        // and would lose a `> file` or pipe the parent set up.
        let inherited = which_handles.map(|which| unsafe { GetStdHandle(which) });
        unsafe {
            // No parent console (a logon task, the packaged app): stay without one.
            if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
                return;
            }
            for (which, before) in which_handles.into_iter().zip(inherited) {
                if usable(before) {
                    SetStdHandle(which, before);
                    continue;
                }
                let name: Vec<u16> = if which == STD_INPUT_HANDLE {
                    "CONIN$\0".encode_utf16().collect()
                } else {
                    "CONOUT$\0".encode_utf16().collect()
                };
                let handle = CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                );
                if handle != INVALID_HANDLE_VALUE {
                    SetStdHandle(which, handle);
                }
            }
        }
    }
}
