//! Long-running sync daemon entry point.
//!
//! This is deliberately thin: it builds the real (production) multi-threaded
//! tokio runtime and hands off to [`yadorilink_daemon::app::run`], which
//! holds the entire daemon lifecycle. Keeping the lifecycle in the library
//! is what lets a test drive an in-process daemon instance by calling
//! `run(..)` directly with its own `DaemonConfig`, instead of going through
//! this real process entry point.

// `yadorilink-daemon` takes no arguments at all -- every real
// setting comes from `DaemonConfig::from_env()`, matching this binary's own
// doc comment above. `--version`/`-V` is the one argument handled here
// (not via `clap`, to keep this genuinely thin): a daemon binary that
// silently ignores `--version` and starts the full sync daemon instead is
// a real footgun for a package build/test step (this repo's own
// `juntaki/homebrew-yadorilink` Formula test, `lintian`, a Docker
// healthcheck) that expects the ordinary `binary --version` convention to
// just print a version and exit, not bind sockets and open a database.
fn print_version_and_exit_if_requested() {
    if std::env::args().skip(1).any(|arg| arg == "--version" || arg == "-V") {
        // The embedded build identity is printed so a release can check that the binary it ships
        // carries the identity it publishes (`check-engine-artifact.py`).
        let release = yadorilink_local_storage::release_descriptor::embedded_build()
            .map(|b| format!(" (release {})", b.release_id))
            .unwrap_or_default();
        println!(
            "{} {} (host api {}){release}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION
        );
        std::process::exit(0);
    }
}

fn main() -> anyhow::Result<()> {
    print_version_and_exit_if_requested();
    // Before the runtime spawns its threads: glibc arenas are created per
    // contending thread and an existing arena is never merged away.
    let arena_cap = yadorilink_daemon::malloc_arenas::cap_arenas();
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
        let rolling = yadorilink_daemon::log_roll::log_file_path().and_then(|p| {
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
    result
}
