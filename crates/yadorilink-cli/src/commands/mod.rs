pub mod account;
pub mod auth;
pub mod backup;
pub mod connection_ops;
pub mod daemon;
pub mod device;
pub mod device_names;
pub mod diagnose;
pub mod feedback;
pub mod gc;
pub mod handoff;
pub mod ignore;
pub mod limits;
pub mod link;
pub mod local_time;
pub mod materialization;
pub mod membership_render;
pub mod preserved;
pub mod provider_folder;
pub mod recovery;
pub mod report;
pub mod rewind;
pub mod send;
pub mod share;
pub mod space;
pub mod status;
pub mod uninstall;
pub mod update;
pub mod version_history;
pub mod web;

use std::io::{BufRead, IsTerminal, Write};

use crate::error::CliError;

/// y/N confirmation for an irreversible action. `--yes` skips it; without a
/// terminal to ask, it refuses rather than hang or proceed.
pub(crate) fn confirm_destructive(prompt: &str, yes: bool) -> Result<(), CliError> {
    let stdin = std::io::stdin();
    confirm_with(prompt, yes, stdin.is_terminal(), &mut stdin.lock())
}

fn confirm_with(
    prompt: &str,
    yes: bool,
    interactive: bool,
    reader: &mut impl BufRead,
) -> Result<(), CliError> {
    if yes {
        return Ok(());
    }
    if !interactive {
        return Err(CliError::Cancelled(format!("{prompt} Re-run with --yes to confirm.")));
    }
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let answered_yes = reader.read_line(&mut line).is_ok()
        && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    if answered_yes {
        Ok(())
    } else {
        Err(CliError::Cancelled("Cancelled; nothing was changed.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_without_yes_when_not_interactive() {
        let err = confirm_with("Delete it?", false, false, &mut &b"y\n"[..]).unwrap_err();
        assert!(err.to_string().contains("--yes"), "{err}");
    }

    #[test]
    fn yes_flag_proceeds_without_reading() {
        assert!(confirm_with("Delete it?", true, false, &mut &b""[..]).is_ok());
    }

    #[test]
    fn interactive_accepts_only_y_or_yes() {
        assert!(confirm_with("p", false, true, &mut &b"y\n"[..]).is_ok());
        assert!(confirm_with("p", false, true, &mut &b"YES\n"[..]).is_ok());
        assert!(confirm_with("p", false, true, &mut &b"\n"[..]).is_err());
        assert!(confirm_with("p", false, true, &mut &b"n\n"[..]).is_err());
    }
}
