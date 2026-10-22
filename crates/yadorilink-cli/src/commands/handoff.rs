//! `yadorilink daemon release-to-app`: hand this machine's data area to the YadoriLink app.
//!
//! The steps, the journal and the roll-back are the engine's
//! (`yadorilink_local_storage::handoff`); this is the command-line surface the app (or a person)
//! drives. It must run from the command-line install that is being released.

use std::path::PathBuf;

use yadorilink_client_core::ops::handoff::{
    self, HandoffError, Outcome, PreviousDaemon, Refused, Request,
};
use yadorilink_local_storage::handoff::journal::{self, JournalState};

use crate::error::CliError;

/// What to do, from the command line.
pub enum Action {
    /// Hand the area to the app, or finish an open hand-off to it.
    Release { to: String, install_root: PathBuf, engine: PathBuf },
    /// The app's daemon runs: verify it and close the hand-off.
    Commit,
    /// Undo the open hand-off and return to the previous setup.
    Rollback,
    /// Show the open hand-off, if any. Changes nothing.
    Status,
}

/// The action the flags ask for. Exactly one of the three modes, or a full release request.
///
/// # Errors
/// [`CliError::Other`] when the flags name neither.
pub fn action_from_flags(
    to: Option<String>,
    app_root: Option<PathBuf>,
    app_engine: Option<PathBuf>,
    commit: bool,
    rollback: bool,
    status: bool,
) -> Result<Action, CliError> {
    match (to, app_root, app_engine, commit, rollback, status) {
        (_, _, _, true, _, _) => Ok(Action::Commit),
        (_, _, _, _, true, _) => Ok(Action::Rollback),
        (_, _, _, _, _, true) => Ok(Action::Status),
        (Some(to), Some(install_root), Some(engine), ..) => {
            Ok(Action::Release { to, install_root, engine })
        }
        _ => Err(CliError::Other(
            "give --to, --app-root and --app-engine to release, or one of --commit, --rollback, \
             --status"
                .into(),
        )),
    }
}

fn say(json: bool, outcome: &str, detail: &str) {
    if json {
        println!("{}", serde_json::json!({ "outcome": outcome, "detail": detail }));
    } else if detail.is_empty() {
        println!("{outcome}");
    } else {
        println!("{detail}");
    }
}

fn previous_note(previous: &PreviousDaemon) -> String {
    match previous {
        PreviousDaemon::NotStarted => {
            "The daemon was not running before, so none was started.".into()
        }
        PreviousDaemon::Restarted => "The previous daemon is running again.".into(),
        PreviousDaemon::FailedToStart(e) => format!(
            "The previous setup is restored, but its daemon could not be started ({e}); no \
             daemon is running. Start it with `yadorilink daemon start`."
        ),
    }
}

fn error_message(error: &HandoffError) -> String {
    match error {
        HandoffError::Refused(refused) => refused.message(),
        HandoffError::RolledBack { reason, previous } => format!(
            "The hand-off failed ({reason}) and was undone: the previous owner, its registrations \
             and your data are as they were. {}",
            previous_note(previous)
        ),
        HandoffError::RollbackFailed { reason, detail } => format!(
            "The hand-off failed ({reason}) and could not be fully undone ({detail}). No daemon is \
             running and none can start until you run `yadorilink daemon release-to-app \
             --rollback` again (it is safe to repeat). Your data was not touched."
        ),
        HandoffError::Crashed => "interrupted".into(),
    }
}

fn cli_error(error: &HandoffError) -> CliError {
    let message = error_message(error);
    match error {
        HandoffError::Refused(
            Refused::PackageManagerOwned(_) | Refused::AlreadyManagedByApp(_),
        ) => CliError::ManagedElsewhere(message),
        _ => CliError::Other(message),
    }
}

pub async fn run(action: Action, json: bool) -> Result<(), CliError> {
    if matches!(action, Action::Status) {
        return status(json);
    }
    if !handoff::running_from_cli_install() {
        return Err(CliError::Other(
            "run this command from the command-line install that is being released (the app's \
             own `yadorilink` cannot stop and restore that install's daemon)"
                .into(),
        ));
    }
    let result = match action {
        Action::Release { to, install_root, engine } => {
            handoff::release(&Request { install_source: to, install_root, engine_exe: engine })
                .await
        }
        Action::Commit => handoff::commit().await,
        Action::Rollback => handoff::rollback().await,
        Action::Status => unreachable!("handled above"),
    };
    match result {
        Ok(Outcome::Released) => say(
            json,
            "released",
            "The data area is released to the app. Register and start the app's daemon, then run \
             `yadorilink daemon release-to-app --commit` (or `--rollback` to go back).",
        ),
        Ok(Outcome::AlreadyReleased) => say(
            json,
            "released",
            "Already released to the app. Run `--commit` once the app's daemon runs, or \
             `--rollback` to go back.",
        ),
        Ok(Outcome::Committed) => say(json, "committed", "The app now manages YadoriLink."),
        Ok(Outcome::RolledBack(previous)) => {
            say(
                json,
                "rolled_back",
                &format!("Back to the previous setup. {}", previous_note(&previous)),
            );
        }
        Err(error) => {
            if json {
                let outcome = match &error {
                    HandoffError::Refused(_) => "refused",
                    HandoffError::RolledBack { .. } => "rolled_back",
                    HandoffError::RollbackFailed { .. } | HandoffError::Crashed => "stuck",
                };
                say(true, outcome, &error_message(&error));
            }
            return Err(cli_error(&error));
        }
    }
    Ok(())
}

fn status(json: bool) -> Result<(), CliError> {
    let config_dir = yadorilink_client_core::coordination::device_config::config_dir()
        .map_err(|e| CliError::Other(e.to_string()))?;
    match journal::read(&config_dir) {
        JournalState::Missing => say(json, "none", "No hand-off is open."),
        JournalState::Present(j) => say(
            json,
            &format!("{:?}", j.phase).to_lowercase(),
            &format!(
                "A hand-off to {} at {} is open (stopped at {:?}).",
                j.target.install_source, j.target.install_root, j.phase
            ),
        ),
        JournalState::Unreadable(reason) => say(json, "unreadable", &reason),
    }
    Ok(())
}
