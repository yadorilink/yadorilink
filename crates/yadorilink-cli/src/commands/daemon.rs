use yadorilink_client_core::dto::PauseDuration;
use yadorilink_client_core::ops::daemon::{self as ops, DaemonStartOutcome};
use yadorilink_client_core::ops::folders;

use crate::error::CliError;

/// How long `daemon pause --for` pauses.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum PauseFor {
    #[value(name = "30m")]
    ThirtyMinutes,
    #[value(name = "1h")]
    OneHour,
    #[value(name = "tomorrow")]
    Tomorrow,
}

/// Launches the daemon if it isn't already running (per the `cli` spec's
/// "Start daemon" scenario: "launched (or confirmed already running)").
pub async fn start() -> Result<(), CliError> {
    match ops::start_daemon().await? {
        DaemonStartOutcome::AlreadyRunning => println!("Daemon already running."),
        DaemonStartOutcome::Started => println!("Daemon started."),
    }
    Ok(())
}

pub async fn stop() -> Result<(), CliError> {
    ops::stop_daemon().await?;
    println!("Daemon stopping.");
    Ok(())
}

/// Interpreted as pausing every currently-linked folder (the CLI spec's
/// "daemon pause/resume" is a whole-daemon action; the underlying control
/// protocol tracks pause per-link, per the `sync-engine` spec, so this
/// applies it to all of them).
pub async fn pause(duration: Option<PauseFor>) -> Result<(), CliError> {
    let (duration, until) = pause_choice(duration);
    folders::pause_all(duration).await?;
    println!("Sync paused{until}.");
    Ok(())
}

fn pause_choice(duration: Option<PauseFor>) -> (PauseDuration, &'static str) {
    match duration {
        None => (PauseDuration::UntilResumed, ""),
        Some(PauseFor::ThirtyMinutes) => (PauseDuration::ThirtyMinutes, " for 30 minutes"),
        Some(PauseFor::OneHour) => (PauseDuration::OneHour, " for 1 hour"),
        Some(PauseFor::Tomorrow) => (PauseDuration::UntilTomorrow, " until tomorrow"),
    }
}

pub async fn resume() -> Result<(), CliError> {
    folders::resume_all().await?;
    println!("Sync resumed.");
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
        assert_eq!(pause_choice(Some(PauseFor::ThirtyMinutes)).0, PauseDuration::ThirtyMinutes);
        assert_eq!(pause_choice(Some(PauseFor::OneHour)).0, PauseDuration::OneHour);
        assert_eq!(pause_choice(Some(PauseFor::Tomorrow)).0, PauseDuration::UntilTomorrow);
    }
}
