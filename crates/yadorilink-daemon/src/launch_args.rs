//! The daemon's command line, parsed before any state, lock, listener or log file exists.
//!
//! The daemon takes no settings as arguments (they come from `DaemonConfig::from_env()`); the only
//! flags are `--restart-on-replace` (a supervisor's declaration) and the informational
//! `--help`/`-h` and `--version`/`-V`. Anything else is refused rather than ignored, so a typo or
//! an unknown flag can never start a daemon by accident.

use crate::exe_replaced::SUPERVISED_ARG;

/// What the process was asked to do.
#[derive(Debug, PartialEq, Eq)]
pub enum LaunchAction {
    /// Start the daemon.
    Run,
    /// Print the version and exit 0.
    Version,
    /// Print usage and exit 0.
    Help,
    /// Print the refusal and usage to stderr and exit 2; carries the offending argument.
    Refuse(String),
}

/// Classifies the arguments after the program name. Informational flags win over everything else
/// so `--help` is honoured even next to an unknown flag.
pub fn classify<I, S>(args: I) -> LaunchAction
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|a| a.as_ref().to_owned()).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return LaunchAction::Help;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        return LaunchAction::Version;
    }
    match args.into_iter().find(|a| a != SUPERVISED_ARG) {
        Some(unknown) => LaunchAction::Refuse(unknown),
        None => LaunchAction::Run,
    }
}

/// The usage text.
pub fn usage() -> String {
    format!(
        "Usage: yadorilink-daemon [{SUPERVISED_ARG}]\n\n\
         Runs the YadoriLink sync daemon in the foreground. Settings come from the environment, \
         not from arguments.\n\n\
         Options:\n  \
         {SUPERVISED_ARG}  exit with a restart status when the installed executable is replaced\n  \
         -h, --help  print this help and exit\n  \
         -V, --version  print the version and exit\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_and_the_supervisor_flag_run_the_daemon() {
        assert_eq!(classify::<[&str; 0], &str>([]), LaunchAction::Run);
        assert_eq!(classify(["--restart-on-replace"]), LaunchAction::Run);
    }

    #[test]
    fn help_and_version_never_run_the_daemon() {
        assert_eq!(classify(["--help"]), LaunchAction::Help);
        assert_eq!(classify(["-h"]), LaunchAction::Help);
        assert_eq!(classify(["--restart-on-replace", "--bogus", "--help"]), LaunchAction::Help);
        assert_eq!(classify(["-V"]), LaunchAction::Version);
    }

    /// Every argument vector a shipped service definition passes (argv after the program name):
    /// the systemd units, the Docker entrypoint and the Windows launchers pass none, the macOS
    /// helper's launchd plist passes `--restart-on-replace`, and the older macOS installer's plist
    /// passed none. An upgrade leaves those definitions in place, so all must keep starting.
    #[test]
    fn every_shipped_service_definition_still_starts_the_daemon() {
        let shipped: [&[&str]; 2] = [&[], &["--restart-on-replace"]];
        for args in shipped {
            assert_eq!(classify(args.iter().copied()), LaunchAction::Run, "{args:?}");
        }
    }

    #[test]
    fn unknown_arguments_are_refused() {
        assert_eq!(classify(["--bogus"]), LaunchAction::Refuse("--bogus".into()));
        assert_eq!(classify(["stray"]), LaunchAction::Refuse("stray".into()));
    }
}
