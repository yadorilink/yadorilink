//! The System Settings switches `yadorilink status` names when one is off. macOS only: elsewhere
//! there are no such switches and nothing is printed. Asking the system never fails the command.
//!
//! The extensions' switches are read from PlugInKit (`pluginkit -mA -i <id>`), the same source the
//! installer elects through. The daemon is not asked: the app, which could report them, may not be
//! running, and the state belongs to the system, not to a file of ours.

#[cfg(target_os = "macos")]
const FINDER_SYNC_ID: &str = "com.juntaki.yadorilink.FinderSync";
#[cfg(target_os = "macos")]
const FILE_PROVIDER_ID: &str = "com.juntaki.yadorilink.FileProvider";

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SwitchState {
    On,
    Off,
}

/// The state `pluginkit -mA -i <id>` printed: `+` in the first column is switched on, anything
/// else (`-` switched off, a blank flag with no vote) is not running, and no line is unknown to
/// PlugInKit (not installed).
#[cfg(target_os = "macos")]
pub(super) fn parse_pluginkit(output: &str, id: &str) -> SwitchState {
    for line in output.lines() {
        let mut chars = line.chars();
        let Some(flag) = chars.next() else { continue };
        if chars.as_str().trim_start().starts_with(id) {
            return if flag == '+' { SwitchState::On } else { SwitchState::Off };
        }
    }
    SwitchState::Off
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
        .args(["-mA", "-i", id])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status.success().then(|| parse_pluginkit(&String::from_utf8_lossy(&out.stdout), id))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    const ID: &str = FINDER_SYNC_ID;

    #[test]
    fn the_first_column_decides() {
        assert_eq!(
            parse_pluginkit(&format!("+    {ID}(1.0)\tUUID\tdate\tpath\n"), ID),
            SwitchState::On
        );
        assert_eq!(parse_pluginkit(&format!("-    {ID}(1.0)\tUUID\n"), ID), SwitchState::Off);
        assert_eq!(parse_pluginkit(&format!("     {ID}(1.0)\tUUID\n"), ID), SwitchState::Off);
    }

    #[test]
    fn an_unknown_or_other_extension_is_off() {
        assert_eq!(parse_pluginkit("", ID), SwitchState::Off);
        assert_eq!(parse_pluginkit("+    com.other.thing(1)\n", ID), SwitchState::Off);
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
