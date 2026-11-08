use yadorilink_client_core::dto::PauseDuration;
use yadorilink_client_core::ops::autostart::{self, Autostart};
use yadorilink_client_core::ops::daemon::{self as ops, DaemonStartOutcome};
use yadorilink_client_core::ops::folders;

use crate::error::CliError;
use crate::i18n::tr;

/// How long `daemon pause --for` pauses.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum PauseFor {
    #[value(name = "2h")]
    TwoHours,
    #[value(name = "8h")]
    EightHours,
    #[value(name = "24h")]
    TwentyFourHours,
}

/// Launches the daemon if it isn't already running (per the `cli` spec's
/// "Start daemon" scenario: "launched (or confirmed already running)").
pub async fn start() -> Result<(), CliError> {
    match ops::start_daemon().await? {
        DaemonStartOutcome::AlreadyRunning => println!("Daemon already running."),
        DaemonStartOutcome::Started => println!("Daemon started."),
    }
    // The daemon is up either way; failing to leave the start-at-login entry is said, not fatal.
    match autostart::ensure() {
        Ok(Autostart::Enabled) => println!("YadoriLink will start by itself when you log in."),
        Ok(Autostart::AlreadyEnabled | Autostart::NotApplicable) => {}
        Err(e) => eprintln!("warning: the daemon will not start by itself at login: {e}"),
    }
    Ok(())
}

/// Whether a command that failed because no daemon answers should start one now: only for a
/// person at a full terminal (see `auth::auto_sign_in_plan`), and never where the daemon belongs
/// to a service manager or a container, whose own tools start it.
pub fn auto_start_plan(
    error: &CliError,
    detect: impl FnOnce() -> super::auth::TerminalEnv,
) -> bool {
    if !matches!(error, CliError::DaemonNotRunning) {
        return false;
    }
    if ops::supervised_by_environment()
        || std::path::Path::new("/etc/systemd/system/yadorilink-headless.service").exists()
    {
        return false;
    }
    super::auth::is_interactive(detect())
}

/// Stops the daemon. With `disable` it also removes the start-at-login entry, and a daemon that
/// was not running is not an error.
pub async fn stop(disable: bool) -> Result<(), CliError> {
    let stopped = ops::stop_daemon().await;
    if stopped.is_ok() {
        println!("{}", tr("Daemon stopping."));
    }
    if disable && autostart::remove()? {
        println!("{}", tr("The daemon will no longer start at login."));
    }
    match stopped {
        Err(yadorilink_client_core::CoreError::DaemonNotRunning) if disable => Ok(()),
        other => Ok(other?),
    }
}

/// Interpreted as pausing every currently-linked folder (the CLI spec's
/// "daemon pause/resume" is a whole-daemon action; the underlying control
/// protocol tracks pause per-link, per the `sync-engine` spec, so this
/// applies it to all of them).
pub async fn pause(duration: Option<PauseFor>) -> Result<(), CliError> {
    let (duration, until) = pause_choice(duration);
    // A pause belongs to each linked folder, so with none there is nothing to pause and
    // `status` rightly stays "Up to date".
    if folders::pause_all(duration).await? == 0 {
        println!("{}", tr("Nothing to pause: no folders are linked."));
    } else {
        println!("Sync paused{until}.");
    }
    Ok(())
}

fn pause_choice(duration: Option<PauseFor>) -> (PauseDuration, &'static str) {
    match duration {
        None => (PauseDuration::UntilResumed, ""),
        Some(PauseFor::TwoHours) => (PauseDuration::TwoHours, " for 2 hours"),
        Some(PauseFor::EightHours) => (PauseDuration::EightHours, " for 8 hours"),
        Some(PauseFor::TwentyFourHours) => (PauseDuration::TwentyFourHours, " for 24 hours"),
    }
}

pub async fn resume() -> Result<(), CliError> {
    if folders::resume_all().await? == 0 {
        println!("{}", tr("Nothing to resume: no folders are linked."));
    } else {
        println!("{}", tr("Sync resumed."));
    }
    Ok(())
}

/// View/toggle the daemon's opt-in `/metrics` endpoint by writing
/// directly to the same `metrics_config.json` `yadorilink-daemon` reads at
/// startup (`yadorilink_reporting::metrics_config::MetricsConfigStore`,
/// which the daemon uses too) — both processes already share the same config directory convention
/// (`crate::device_config::config_dir`), the same way `credential_store`/
/// `device_config` are shared, local-file-based config rather than a
/// control-socket round trip. A running daemon only picks up a change here
/// on its next start (see `DaemonAction::Metrics`'s doc comment in
/// `main.rs`).
pub fn metrics(
    enable: bool,
    disable: bool,
    addr: Option<String>,
    show: bool,
) -> Result<(), CliError> {
    let store = yadorilink_reporting::metrics_config::MetricsConfigStore::new(
        crate::device_config::config_dir()?,
    );
    if show || (!enable && !disable && addr.is_none()) {
        let config = store.load_or_default();
        println!(
            "metrics: {}  addr={}",
            if config.enabled { "enabled" } else { "disabled" },
            config.bind_addr
        );
        return Ok(());
    }
    let enabled = if disable { false } else { enable || addr.is_some() };
    let config = store
        .set(enabled, addr)
        .map_err(|e| CliError::Other(format!("failed to save metrics config: {e}")))?;
    println!(
        "metrics: {}  addr={}  (takes effect on the daemon's next start)",
        if config.enabled { "enabled" } else { "disabled" },
        config.bind_addr
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use PauseFor;

    #[test]
    fn pause_options_map_to_the_core_durations() {
        assert_eq!(pause_choice(None).0, PauseDuration::UntilResumed);
        assert_eq!(pause_choice(Some(PauseFor::TwoHours)).0, PauseDuration::TwoHours);
        assert_eq!(pause_choice(Some(PauseFor::EightHours)).0, PauseDuration::EightHours);
        assert_eq!(pause_choice(Some(PauseFor::TwentyFourHours)).0, PauseDuration::TwentyFourHours);
    }
}

#[cfg(test)]
mod auto_start_tests {
    use super::*;
    use crate::commands::auth::TerminalEnv;

    const TERMINAL: TerminalEnv = TerminalEnv {
        stdin_tty: true,
        stdout_tty: true,
        stderr_tty: true,
        ssh: false,
        ci: false,
        json: false,
        display: true,
    };

    #[test]
    fn only_a_person_at_a_terminal_whose_daemon_is_not_running_gets_it_started() {
        let not_running = CliError::DaemonNotRunning;
        assert!(auto_start_plan(&not_running, || TERMINAL));
        for env in [
            TerminalEnv { stdin_tty: false, ..TERMINAL },
            TerminalEnv { stdout_tty: false, ..TERMINAL },
            TerminalEnv { ci: true, ..TERMINAL },
            TerminalEnv { json: true, ..TERMINAL },
        ] {
            assert!(!auto_start_plan(&not_running, || env), "{env:?}");
        }
        let other = CliError::Other("x".to_owned());
        assert!(!auto_start_plan(&other, || TERMINAL));
    }
}
