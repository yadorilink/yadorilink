//! `yadorilink login`, `yadorilink logout` and `yadorilink
//! forget-local-credentials`.
//!
//! The flows themselves live in `yadorilink_client_core::ops::auth`; this
//! module prints each progress step as the flow reports it, in the order it
//! reports them.

use yadorilink_client_core::ops::auth as ops;
use yadorilink_client_core::wording::{login_event_lines, sign_out_line};

use crate::error::CliError;

/// Enrol this installation and sign it in. `device`: sign in with the
/// device-code grant instead of the loopback redirect.
pub async fn login(device: bool) -> Result<(), CliError> {
    ops::login(device, |event| {
        for line in login_event_lines(&event) {
            println!("{line}");
        }
    })
    .await?;
    Ok(())
}

/// What the process runs on, as far as the automatic sign-in decision cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalEnv {
    pub stdin_tty: bool,
    pub stdout_tty: bool,
    pub stderr_tty: bool,
    /// Running over SSH (`SSH_CONNECTION` / `SSH_TTY` set).
    pub ssh: bool,
    /// A local display for a browser plausibly exists (always true off Linux).
    pub display: bool,
}

impl TerminalEnv {
    /// Reads the real process.
    #[must_use]
    pub fn detect() -> Self {
        use std::io::IsTerminal;
        let set = |name: &str| std::env::var_os(name).is_some_and(|v| !v.is_empty());
        Self {
            stdin_tty: std::io::stdin().is_terminal(),
            stdout_tty: std::io::stdout().is_terminal(),
            stderr_tty: std::io::stderr().is_terminal(),
            ssh: set("SSH_CONNECTION") || set("SSH_TTY"),
            display: !cfg!(target_os = "linux") || set("DISPLAY") || set("WAYLAND_DISPLAY"),
        }
    }
}

/// Whether the failed command starts the sign-in by itself, and which flow it uses.
/// Everything the person must see or answer is on a terminal (stdin, stdout and stderr: a piped
/// `--json` run never starts one), the command is not itself a sign-in command (no recursion), and
/// the failure is one signing in settles. The device flow is used where no local browser is
/// plausible (SSH, no display), since the loopback redirect could never arrive there.
#[must_use]
pub fn auto_sign_in_plan(
    error: &CliError,
    is_sign_in_command: bool,
    env: TerminalEnv,
) -> Option<bool> {
    let interactive = env.stdin_tty && env.stdout_tty && env.stderr_tty;
    (interactive && !is_sign_in_command && error.is_sign_in_required())
        .then_some(env.ssh || !env.display)
}

/// The sign-in the failed command starts: the same flow as `yadorilink login`, with every line
/// on stderr so nothing reaches stdout, and a Ctrl-C ends only the sign-in.
pub async fn login_on_stderr(device: bool) -> Result<(), CliError> {
    let flow = ops::login(device, |event| {
        for line in login_event_lines(&event) {
            eprintln!("{line}");
        }
    });
    // Biased: the Ctrl-C handler is installed by its first poll, before the flow can block.
    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => Err(CliError::Cancelled("sign-in cancelled".to_owned())),
        result = flow => Ok(result?),
    }
}

/// Sign out: revoke this installation's authority, confirm it, and only then
/// destroy the local credential. A revocation that cannot be confirmed keeps
/// the credential and fails, rather than deleting it and claiming success.
pub async fn logout(yes: bool) -> Result<(), CliError> {
    super::confirm_destructive(
        "Sign out and revoke this computer's access? This cannot be undone. Files already on \
         this computer stay on disk.",
        yes,
    )?;
    let report = ops::sign_out().await?;
    println!("{}", sign_out_line(&report.kind));
    if let Some(warning) = report.key_cleanup_warning {
        eprintln!("Warning: {warning}. {}", crate::error::CREDENTIAL_CLEANUP_ADVICE);
    }
    Ok(())
}

/// Destroy this machine's stored credential WITHOUT revoking anything.
pub async fn forget_local_credentials() -> Result<(), CliError> {
    let warning = ops::forget_local_credentials().await?;
    println!("{FORGOT_LOCAL_CREDENTIALS}");
    if let Some(warning) = warning {
        eprintln!("Warning: {warning}. {}", crate::error::CREDENTIAL_CLEANUP_ADVICE);
    }
    Ok(())
}

/// Purge this machine's local credential store, for `uninstall.sh --purge-data`.
pub async fn credentials_purge() -> Result<(), CliError> {
    let warning = ops::purge_local_credentials().await?;
    println!("Local credential store purged. Nothing was revoked on the server.");
    if let Some(warning) = warning {
        eprintln!("Warning: {warning}. {}", crate::error::CREDENTIAL_CLEANUP_ADVICE);
    }
    Ok(())
}

const FORGOT_LOCAL_CREDENTIALS: &str = "Local credentials removed. This computer is still \
                                        authorized on the server -- sign out, or remove this \
                                        device from another one, to revoke it.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forget_local_credentials_line_is_pinned_verbatim() {
        assert_eq!(
            FORGOT_LOCAL_CREDENTIALS,
            "Local credentials removed. This computer is still authorized on the server -- sign \
             out, or remove this device from another one, to revoke it."
        );
    }
}

#[cfg(test)]
mod sign_in_offer_tests {
    use super::*;

    fn consent() -> CliError {
        yadorilink_client_core::CoreError::TermsConsentRequired { terms_version: None }.into()
    }

    const TERMINAL: TerminalEnv = TerminalEnv {
        stdin_tty: true,
        stdout_tty: true,
        stderr_tty: true,
        ssh: false,
        display: true,
    };

    #[test]
    fn only_a_full_terminal_outside_the_sign_in_commands_starts_a_sign_in() {
        assert_eq!(auto_sign_in_plan(&consent(), false, TERMINAL), Some(false));
        assert_eq!(auto_sign_in_plan(&consent(), true, TERMINAL), None, "login must not recurse");
        for env in [
            TerminalEnv { stdin_tty: false, ..TERMINAL },
            TerminalEnv { stdout_tty: false, ..TERMINAL },
            TerminalEnv { stderr_tty: false, ..TERMINAL },
        ] {
            assert_eq!(auto_sign_in_plan(&consent(), false, env), None, "{env:?}");
        }
        assert_eq!(auto_sign_in_plan(&CliError::NotLoggedIn, false, TERMINAL), None);
        assert_eq!(auto_sign_in_plan(&CliError::AuthFailed("x".into()), false, TERMINAL), None);
    }

    #[test]
    fn the_device_flow_is_used_where_no_local_browser_is_plausible() {
        assert_eq!(
            auto_sign_in_plan(&consent(), false, TerminalEnv { ssh: true, ..TERMINAL }),
            Some(true)
        );
        assert_eq!(
            auto_sign_in_plan(&consent(), false, TerminalEnv { display: false, ..TERMINAL }),
            Some(true)
        );
    }

    #[test]
    fn both_refusals_are_sign_in_required_with_the_login_command_in_the_message() {
        use yadorilink_client_core::CoreError;
        for e in
            [CoreError::SignInRequired, CoreError::TermsConsentRequired { terms_version: None }]
        {
            let cli: CliError = e.into();
            assert!(cli.is_sign_in_required());
            assert_eq!(cli.exit_code(), 10);
            assert!(cli.to_string().contains("yadorilink login"), "{cli}");
            assert!(!cli.is_reportable());
        }
    }
}
