//! `yadorilink update status|check|download|config` — mirrors
//! `commands::limits`'s exact shape (a thin wrapper per subcommand over
//! `yadorilink_client_core::ops::updates`, printing the daemon's response).

use yadorilink_client_core::ops::updates;
use yadorilink_ipc_proto::daemonctl::UpdateStatusResponse;
use yadorilink_local_storage::ownership::{self, RecordState};

use crate::error::CliError;

/// Shared by `status`/`check` — both end up printing the exact same
/// shape of information ("current version, channel, install
/// source, last check time, available version if any, rollout/holdback
/// state, and last update error if any").
fn print_status(status: &UpdateStatusResponse) {
    println!(
        "version: {}  channel: {}  install_source: {}",
        status.current_version, status.channel, status.install_source
    );
    if let Some(how) = ownership::updater_elsewhere(&status.install_source) {
        println!("updated by: its own updater, not this command; {how}");
    }
    if status.last_check_unix == 0 {
        println!("last check: never");
    } else {
        println!("last check: {} (unix seconds)", status.last_check_unix);
    }
    println!("state: {}", status.state);
    if !status.manifest_generated_at.is_empty() {
        println!("manifest generated: {}", status.manifest_generated_at);
    }
    if status.update_required {
        println!(
            "update required: yes (this version is older than the minimum supported version; \
             it cannot sync with up-to-date devices until updated)"
        );
    }
    if !status.available_version.is_empty() {
        println!("available version: {}", status.available_version);
        if !status.release_notes_url.is_empty() {
            println!("release notes: {}", status.release_notes_url);
        }
        if status.mandatory {
            println!("mandatory: yes (security/compatibility update)");
        }
        if !status.holdback_reason.is_empty() {
            println!("held back: {}", status.holdback_reason);
        }
        println!("download the new version: run `yadorilink update download`");
    }
    if !status.last_error_category.is_empty() {
        println!(
            "last error: {} ({})",
            status.last_error_category,
            if status.last_error_message.is_empty() {
                "no further detail"
            } else {
                &status.last_error_message
            }
        );
    }
    println!("automatic checks: {}", if status.automatic_checks_enabled { "on" } else { "off" });
}

/// `yadorilink update status` (spec "Show update status").
pub async fn status() -> Result<(), CliError> {
    let status = updates::update_status().await?;
    print_status(&status);
    Ok(())
}

/// `yadorilink update check` (spec "Manual update check").
pub async fn check() -> Result<(), CliError> {
    let check = updates::check_for_updates().await?;
    let Some(status) = check.status else {
        return Err(CliError::Other("daemon returned no update status".into()));
    };
    if status.available_version.is_empty() {
        println!("no update available (current version: {})", status.current_version);
    } else {
        println!("update available: {}", status.available_version);
    }
    print_status(&status);
    Ok(())
}

/// The refusal when another updater owns this installation, `None` when this command may go on.
/// The ownership record decides (it is read, never inferred): an unreadable one means the owner is
/// unknown, which fails closed too. Without a record the running daemon's `install_source` is the
/// statement.
fn managed_elsewhere(record: &RecordState, daemon_install_source: &str) -> Option<String> {
    let (source, owner_is_app) = match record {
        RecordState::Present(r) => (r.install_source.as_str(), r.owner == ownership::Owner::Gui),
        RecordState::Missing => (daemon_install_source, false),
        RecordState::Unreadable(reason) => {
            return Some(format!(
                "the owner of YadoriLink on this machine is unknown ({reason}); nothing was \
                 downloaded or changed. Run `yadorilink doctor` for the fix."
            ))
        }
    };
    let how = ownership::updater_elsewhere(source)
        .or(owner_is_app.then_some("open YadoriLink and choose Check for Updates"))?;
    let who = if owner_is_app { "the YadoriLink app" } else { "another updater" };
    Some(format!(
        "YadoriLink on this machine is updated by {who} ({source}); `yadorilink` does not \
         download, replace or remove anything of it. To update: {how}."
    ))
}

/// `yadorilink update download`: v1 ships manual updates, so this prints
/// where to get the new version (the official download page, or the
/// package-manager command for a package-managed install). An installation
/// that another updater owns (the app, the Store, a package manager) is not
/// touched: the command exits with the "managed elsewhere" code and says how
/// that owner updates it.
pub async fn download() -> Result<(), CliError> {
    let record = match yadorilink_client_core::coordination::device_config::config_dir() {
        Ok(config_dir) => ownership::read(&config_dir),
        Err(_) => RecordState::Missing,
    };
    let daemon_source = match &record {
        RecordState::Missing => updates::update_status().await?.install_source,
        _ => String::new(),
    };
    if let Some(message) = managed_elsewhere(&record, &daemon_source) {
        return Err(CliError::ManagedElsewhere(message));
    }
    let resp = updates::download_guidance().await?;
    println!("{}", resp.guidance);
    Ok(())
}

/// `yadorilink update config --checks <on|off>`
/// (spec "Configure automatic updates").
pub async fn config(checks: Option<String>) -> Result<(), CliError> {
    let automatic_checks_enabled = match checks.as_deref() {
        Some("on") => Some(true),
        Some("off") => Some(false),
        Some(other) => {
            return Err(CliError::Other(format!("--checks must be 'on' or 'off', got {other:?}")))
        }
        None => None,
    };
    let config = updates::set_update_config(automatic_checks_enabled).await?;
    println!("automatic checks: {}", if config.automatic_checks_enabled { "on" } else { "off" });
    Ok(())
}

/// The install source that `self-update` acts on: the command-line (one-liner) install.
const SELF_UPDATE_SOURCE: &str = "script";

/// The installer prefix of the running binary. `install.sh` keeps each version under
/// `<prefix>/share/yadorilink/<version dir>/`; `install.ps1` under `<prefix>\\versions\\<version>\\`.
pub(crate) fn prefix_from_exe(exe: &std::path::Path, windows: bool) -> Option<std::path::PathBuf> {
    let parts: Vec<_> = exe.components().collect();
    let at = if windows {
        parts.iter().rposition(|c| c.as_os_str() == "versions")?
    } else {
        parts
            .windows(2)
            .rposition(|w| w[0].as_os_str() == "share" && w[1].as_os_str() == "yadorilink")?
    };
    let prefix: std::path::PathBuf = parts[..at].iter().collect();
    (!prefix.as_os_str().is_empty()).then_some(prefix)
}

/// Single-quotes `text` for a POSIX shell, or for PowerShell (both double an embedded quote
/// differently).
fn shell_quote(text: &str, powershell: bool) -> String {
    if powershell {
        format!("'{}'", text.replace('\'', "''"))
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// The command that installs `version` with the installer's own full verification (signed
/// manifest, hashes, replay and withdrawal checks, atomic switch), into the same prefix as the
/// running install. `self-update` prints it rather than running a downloaded script itself.
fn installer_command(
    version: &str,
    channel: &str,
    prefix: Option<&std::path::Path>,
    powershell: bool,
) -> String {
    let prefix = prefix.and_then(|p| p.to_str());
    if powershell {
        let prefix =
            prefix.map(|p| format!(" -Prefix {}", shell_quote(p, true))).unwrap_or_default();
        format!(
            "& ([scriptblock]::Create((irm https://yadori.link/install.ps1))) -Channel {channel} -Version {version}{prefix}"
        )
    } else {
        let prefix =
            prefix.map(|p| format!(" --prefix {}", shell_quote(p, false))).unwrap_or_default();
        format!(
            "curl -fsSL https://yadori.link/install.sh | sh -s -- --channel {channel} --version {version}{prefix}"
        )
    }
}

/// Only plain release-version and channel text may reach the printed command line.
fn is_plain(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// Who may be self-updated, and to what. `Ok(None)` means already up to date. Only an install the
/// command line owns (`script`) is acted on; every other source, an unknown one included, is
/// refused with how it updates and nothing is touched.
fn self_update_target(
    record: &RecordState,
    daemon_install_source: &str,
    channel: &str,
    available_version: &str,
    requested: Option<&str>,
) -> Result<Option<String>, CliError> {
    let daemon_source = match record {
        RecordState::Missing => daemon_install_source,
        _ => "",
    };
    if let Some(message) = managed_elsewhere(record, daemon_source) {
        return Err(CliError::ManagedElsewhere(message));
    }
    let source = match record {
        RecordState::Present(r) => r.install_source.as_str(),
        _ => daemon_install_source,
    };
    if source != SELF_UPDATE_SOURCE {
        return Err(CliError::ManagedElsewhere(format!(
            "this YadoriLink is not a command-line install (source: {}), so `yadorilink \
             self-update` does not touch it. Update it the way it was installed, or reinstall with \
             the installer from https://yadori.link.",
            if source.is_empty() { "unknown" } else { source }
        )));
    }
    if !matches!(channel, "beta" | "nightly") {
        return Err(CliError::Other(format!(
            "self-update works on the beta and nightly channels, not {channel:?}"
        )));
    }
    let target = requested.unwrap_or(available_version);
    if target.is_empty() {
        return Ok(None);
    }
    if !is_plain(target) {
        return Err(CliError::Other(format!("{target:?} is not a version number")));
    }
    Ok(Some(target.to_owned()))
}

/// A refusal by the daemon's live manifest check becomes exit 4; an allowance passes.
/// Public so the daemon-backed integration test can drive it.
pub fn refuse_unless_allowed(
    check: &yadorilink_ipc_proto::daemonctl::UpdateVersionCheckResponse,
    version: &str,
) -> Result<(), CliError> {
    if check.allowed {
        return Ok(());
    }
    let reason = if check.reason.is_empty() { "no reason given" } else { &check.reason };
    Err(CliError::UpdateRefused(format!(
        "version {version} is not allowed: {reason}. Nothing was downloaded or changed."
    )))
}

/// "Nothing newer" only counts when the check itself worked; a failed fetch or verification is a
/// refusal, never an assurance.
fn refuse_if_check_failed(status: &UpdateStatusResponse) -> Result<(), CliError> {
    if status.state != "failed" && status.last_error_category.is_empty() {
        return Ok(());
    }
    Err(CliError::UpdateRefused(format!(
        "the update check failed ({}: {}), so nothing can be said about newer versions. Nothing was \
         downloaded or changed.",
        status.last_error_category, status.last_error_message
    )))
}

/// `yadorilink self-update [--version X]`: on a command-line install, judges the target version
/// against the daemon's live verified channel manifest (fail closed) and, if allowed, prints the
/// pinned installer command that does the verified download and atomic switch.
pub async fn self_update(requested: Option<String>) -> Result<(), CliError> {
    let record = match yadorilink_client_core::coordination::device_config::config_dir() {
        Ok(config_dir) => ownership::read(&config_dir),
        Err(_) => RecordState::Missing,
    };
    // The recorded owner decides before the daemon is asked anything: a stopped daemon must not
    // hide "the app updates this".
    if matches!(record, RecordState::Present(_) | RecordState::Unreadable(_)) {
        self_update_target(&record, "", "beta", "", None)?;
    }
    let status = if requested.is_some() {
        updates::update_status().await?
    } else {
        updates::check_for_updates()
            .await?
            .status
            .ok_or_else(|| CliError::Other("daemon returned no update status".into()))?
    };
    let Some(target) = self_update_target(
        &record,
        &status.install_source,
        &status.channel,
        &status.available_version,
        requested.as_deref(),
    )?
    else {
        refuse_if_check_failed(&status)?;
        println!("already up to date (version {})", status.current_version);
        return Ok(());
    };
    // A daemon that cannot supply a verified manifest errors or refuses here: either way nothing goes on.
    refuse_unless_allowed(&updates::check_version("pinned_install", &target).await?, &target)?;
    // Only an explicit --version overrides the staged rollout; a plain update waits its turn.
    if requested.is_none() && !status.holdback_reason.is_empty() {
        println!(
            "version {target} is available but held back ({}); nothing was changed. \
             `yadorilink self-update --version {target}` installs it anyway.",
            status.holdback_reason
        );
        return Ok(());
    }
    if target == status.current_version {
        println!("already up to date (version {})", status.current_version);
        return Ok(());
    }
    let prefix = std::env::current_exe().ok().and_then(|exe| {
        prefix_from_exe(&std::fs::canonicalize(&exe).unwrap_or(exe), cfg!(windows))
    });
    println!(
        "version {target} is allowed by the verified {} channel manifest.\nTo install it (the installer \
         verifies the signature and hashes again and switches atomically):\n  {}",
        status.channel,
        installer_command(&target, &status.channel, prefix.as_deref(), cfg!(windows))
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownership::{Owner, OwnershipRecord};

    fn record(owner: Owner, source: &str) -> RecordState {
        RecordState::Present(OwnershipRecord {
            owner,
            install_source: source.into(),
            install_root: "/x".into(),
            release_id: String::new(),
            written_at: 1,
        })
    }

    #[test]
    fn an_installation_another_updater_owns_is_refused_with_how_it_updates() {
        for (owner, source, how) in [
            (Owner::Gui, "app_bundle", "Check for Updates"),
            (Owner::Gui, "microsoft_store", "Store > Library"),
            (Owner::Cli, "homebrew", "brew upgrade"),
            (Owner::Cli, "apt", "apt install --only-upgrade"),
            (Owner::Cli, "winget", "winget upgrade"),
            (Owner::Cli, "container", "newer image"),
            // A leftover command-line install the app took over: the record names the app.
            (Owner::Gui, "script", "Check for Updates"),
        ] {
            let message = managed_elsewhere(&record(owner, source), "script")
                .unwrap_or_else(|| panic!("{source} must be refused"));
            assert!(message.contains(how), "{source}: {message}");
        }
    }

    #[test]
    fn the_command_lines_own_installation_may_go_on() {
        assert_eq!(managed_elsewhere(&record(Owner::Cli, "script"), "apt"), None);
        assert_eq!(managed_elsewhere(&record(Owner::Cli, "standalone"), ""), None);
        assert_eq!(managed_elsewhere(&RecordState::Missing, "script"), None);
    }

    #[test]
    fn without_a_record_the_running_daemon_decides_and_an_unreadable_record_fails_closed() {
        assert!(managed_elsewhere(&RecordState::Missing, "app_bundle").is_some());
        let unknown = managed_elsewhere(&RecordState::Unreadable("garbled".into()), "script")
            .expect("an unknown owner is refused");
        assert!(unknown.contains("unknown") && unknown.contains("doctor"), "{unknown}");
    }

    #[test]
    fn self_update_acts_only_on_the_command_line_install() {
        let ok = |r: &RecordState, ds: &str| self_update_target(r, ds, "beta", "1.2.0", None);
        assert_eq!(ok(&record(Owner::Cli, "script"), "").unwrap().as_deref(), Some("1.2.0"));
        assert_eq!(ok(&RecordState::Missing, "script").unwrap().as_deref(), Some("1.2.0"));
        for (r, ds) in [
            (record(Owner::Cli, "homebrew"), ""),
            (record(Owner::Cli, "apt"), ""),
            (record(Owner::Cli, "winget"), ""),
            (record(Owner::Cli, "container"), ""),
            (record(Owner::Gui, "app_bundle"), ""),
            (record(Owner::Cli, "standalone"), ""),
            (RecordState::Missing, "unknown"),
            (RecordState::Missing, ""),
            (RecordState::Unreadable("garbled".into()), "script"),
        ] {
            let err = ok(&r, ds).expect_err("must be refused");
            assert!(matches!(err, CliError::ManagedElsewhere(_)), "{err:?}");
            assert_eq!(err.exit_code(), 19);
        }
    }

    #[test]
    fn self_update_target_rules() {
        let r = record(Owner::Cli, "script");
        assert_eq!(self_update_target(&r, "", "beta", "", None).unwrap(), None);
        assert_eq!(
            self_update_target(&r, "", "nightly", "2.0.0", Some("1.9.0")).unwrap().as_deref(),
            Some("1.9.0")
        );
        assert!(self_update_target(&r, "", "stable", "2.0.0", None).is_err());
        for bad in ["1.0; rm -rf /", "$(x)", "a b", ""] {
            assert!(
                self_update_target(&r, "", "beta", "2.0.0", Some(bad)).is_ok() == bad.is_empty()
            );
        }
    }

    #[test]
    fn a_refused_version_check_is_exit_4_and_an_allowed_one_passes() {
        use yadorilink_ipc_proto::daemonctl::UpdateVersionCheckResponse as R;
        assert!(refuse_unless_allowed(&R { allowed: true, reason: String::new() }, "1.0.0").is_ok());
        for reason in ["withdrawn", "below the minimum supported version", ""] {
            let err = refuse_unless_allowed(&R { allowed: false, reason: reason.into() }, "1.0.0")
                .unwrap_err();
            assert_eq!(err.exit_code(), 4);
            assert!(err.to_string().contains("Nothing was downloaded"));
        }
    }

    #[test]
    fn a_failed_check_is_never_reported_as_up_to_date() {
        let ok = UpdateStatusResponse { state: "idle".into(), ..Default::default() };
        assert!(refuse_if_check_failed(&ok).is_ok());
        for bad in [
            UpdateStatusResponse { state: "failed".into(), ..Default::default() },
            UpdateStatusResponse { last_error_category: "signature".into(), ..Default::default() },
        ] {
            assert_eq!(refuse_if_check_failed(&bad).unwrap_err().exit_code(), 4);
        }
    }

    #[test]
    fn the_printed_command_pins_version_and_channel() {
        assert_eq!(
            installer_command("1.2.0", "beta", None, false),
            "curl -fsSL https://yadori.link/install.sh | sh -s -- --channel beta --version 1.2.0"
        );
        let exe = std::path::Path::new("/opt/it's/share/yadorilink/1.2.0/bin/yadorilink");
        let prefix = prefix_from_exe(exe, false).expect("installer layout");
        assert_eq!(prefix, std::path::Path::new("/opt/it's"));
        // The separator is the platform's, so the expectation is built from the path itself.
        let quoted = prefix.to_str().expect("utf-8 path").replace('\'', "'\\''");
        assert!(installer_command("1.2.0", "beta", Some(&prefix), false)
            .ends_with(&format!("--prefix '{quoted}'")));
        assert_eq!(
            installer_command("1.2.0", "nightly", Some(std::path::Path::new("D:\\Y'z")), true),
            "& ([scriptblock]::Create((irm https://yadori.link/install.ps1))) -Channel nightly -Version 1.2.0 -Prefix 'D:\\Y''z'"
        );
        assert_eq!(
            prefix_from_exe(
                std::path::Path::new("/srv/share/yadorilink/t/share/yadorilink/1/bin/yadorilink"),
                false
            ),
            Some(std::path::PathBuf::from("/srv/share/yadorilink/t"))
        );
        assert_eq!(prefix_from_exe(std::path::Path::new("/usr/bin/yadorilink"), false), None);
        assert_eq!(
            prefix_from_exe(
                std::path::Path::new("/d/Tools/Y/versions/1.2.0/bin/yadorilink.exe"),
                true
            ),
            Some(std::path::PathBuf::from("/d/Tools/Y"))
        );
        assert_eq!(prefix_from_exe(std::path::Path::new("/c/yadorilink.exe"), true), None);
    }
}
