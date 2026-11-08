// apple-cfg-file: macos-only the login-item switches manage the macOS launchd service
//! The System Settings switches `yadorilink status` names when one is off. macOS only: elsewhere
//! there are no such switches and nothing is printed. Asking the system never fails the command.
//!
//! The extensions' switches are read from PlugInKit (`pluginkit -mAv -i <id>`), the same source the
//! installer elects through. The daemon is not asked: the app, which could report them, may not be
//! running, and the state belongs to the system, not to a file of ours.

// A build may name other ids through the build-time environment variable below; unset, these are the product's ids.
#[cfg(target_os = "macos")]
const FINDER_SYNC_ID: &str = match option_env!("YADORILINK_FINDER_SYNC_ID") {
    Some(id) => id,
    None => "com.juntaki.yadorilink.FinderSync",
};
#[cfg(target_os = "macos")]
const FILE_PROVIDER_ID: &str = match option_env!("YADORILINK_FILE_PROVIDER_ID") {
    Some(id) => id,
    None => "com.juntaki.yadorilink.FileProvider",
};

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SwitchState {
    On,
    Off,
    /// PlugInKit does not know the extension: the app that carries it is not installed (a
    /// command-line-only install), so there is no switch to turn on and nothing to print.
    NotInstalled,
}

/// The state `pluginkit -mAv -i <id>` printed: `+` in the first column is switched on, anything
/// else (`-` switched off, a blank flag with no vote) is not running, and no line at all means
/// PlugInKit does not know the extension (not installed). PlugInKit also keeps the registration
/// of an app that was removed or moved, so a line whose last column names a path that no longer
/// exists is not an installed extension and is ignored (`path_exists` answers that). A line with
/// no path column counts as installed.
#[cfg(target_os = "macos")]
pub(super) fn parse_pluginkit(
    output: &str,
    id: &str,
    path_exists: impl Fn(&str) -> bool,
) -> SwitchState {
    let mut state = SwitchState::NotInstalled;
    for line in output.lines() {
        let mut chars = line.chars();
        let Some(flag) = chars.next() else { continue };
        if !chars.as_str().trim_start().starts_with(id) {
            continue;
        }
        let mut columns = line.split('\t');
        let path = columns.nth(3).map(str::trim).filter(|p| !p.is_empty());
        if path.is_some_and(|p| !path_exists(p)) {
            continue;
        }
        if flag == '+' {
            return SwitchState::On;
        }
        state = SwitchState::Off;
    }
    state
}

/// One line per extension that is off, each with where to turn it on.
#[cfg(target_os = "macos")]
pub(super) fn off_lines(finder: SwitchState, file_provider: SwitchState) -> Vec<String> {
    let mut lines = Vec::new();
    if finder == SwitchState::Off {
        lines.push(
            "Finder extension is off: Finder shows no sync status and no YadoriLink menu. \
             Turn it on in System Settings > General > Login Items & Extensions > Extensions, \
             under Finder."
                .to_string(),
        );
    }
    if file_provider == SwitchState::Off {
        lines.push(
            "File Provider extension is off: online-only files cannot appear in Finder. \
             Turn it on in System Settings > General > Login Items & Extensions > Extensions, \
             under File Providers."
                .to_string(),
        );
    }
    lines
}

/// What to print under `status` about extensions that are off. Empty off macOS, when everything
/// is on, or when PlugInKit cannot be asked.
pub(super) fn extension_lines() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        let (Some(finder), Some(provider)) =
            (pluginkit_state(FINDER_SYNC_ID), pluginkit_state(FILE_PROVIDER_ID))
        else {
            return Vec::new();
        };
        off_lines(finder, provider)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

/// The hint printed when the daemon does not answer: on macOS the daemon runs as the app's
/// background service, which the user can switch off.
pub(super) fn background_service_hint() -> Option<&'static str> {
    cfg!(target_os = "macos").then_some(
        "If YadoriLink is switched off in the background, turn it on in System Settings > General > \
         Login Items & Extensions > Allow in the Background.",
    )
}

#[cfg(target_os = "macos")]
fn pluginkit_state(id: &str) -> Option<SwitchState> {
    let out = std::process::Command::new("/usr/bin/pluginkit")
        .args(["-mAv", "-i", id])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| {
        parse_pluginkit(&String::from_utf8_lossy(&out.stdout), id, |p| {
            std::path::Path::new(p).exists()
        })
    })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    const ID: &str = FINDER_SYNC_ID;

    #[test]
    fn the_first_column_decides() {
        assert_eq!(
            parse_pluginkit(&format!("+    {ID}(1.0)\tUUID\tdate\t/app.appex\n"), ID, |_| true),
            SwitchState::On
        );
        assert_eq!(
            parse_pluginkit(&format!("-    {ID}(1.0)\tUUID\n"), ID, |_| true),
            SwitchState::Off
        );
        assert_eq!(
            parse_pluginkit(&format!("     {ID}(1.0)\tUUID\n"), ID, |_| true),
            SwitchState::Off
        );
    }

    #[test]
    fn an_unknown_or_other_extension_is_not_installed_and_silent() {
        assert_eq!(parse_pluginkit("", ID, |_| true), SwitchState::NotInstalled);
        assert_eq!(
            parse_pluginkit("+    com.other.thing(1)\n", ID, |_| true),
            SwitchState::NotInstalled
        );
        assert!(off_lines(SwitchState::NotInstalled, SwitchState::NotInstalled).is_empty());
    }

    #[test]
    fn a_registration_of_a_removed_app_is_not_installed_and_silent() {
        let out = format!(
            "-    {ID}(0.1.0-beta.1)\tU1\td\t/gone/old.appex\n-    {ID}(0.1.0-beta.7)\tU2\td\t/gone/new.appex\n"
        );
        assert_eq!(parse_pluginkit(&out, ID, |_| false), SwitchState::NotInstalled);
        // The registration that still exists decides, whichever line comes first.
        let out =
            format!("-    {ID}(1)\tU1\td\t/gone/old.appex\n-    {ID}(2)\tU2\td\t/here/new.appex\n");
        assert_eq!(parse_pluginkit(&out, ID, |p| p.starts_with("/here")), SwitchState::Off);
        let out =
            format!("-    {ID}(1)\tU1\td\t/here/old.appex\n+    {ID}(2)\tU2\td\t/here/new.appex\n");
        assert_eq!(parse_pluginkit(&out, ID, |_| true), SwitchState::On);
    }

    #[test]
    fn only_switches_that_are_off_are_named_with_where_to_turn_them_on() {
        assert!(off_lines(SwitchState::On, SwitchState::On).is_empty());
        let finder = off_lines(SwitchState::Off, SwitchState::On);
        assert_eq!(finder.len(), 1);
        assert!(finder[0].starts_with("Finder extension is off"));
        assert!(finder[0].contains("Login Items & Extensions > Extensions"));
        let both = off_lines(SwitchState::Off, SwitchState::Off);
        assert!(both[1].starts_with("File Provider extension is off"));
    }
}
