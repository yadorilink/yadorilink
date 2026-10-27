//! Who owns the daemon of one user data area.
//!
//! Exactly one owner installs, updates and starts the daemon of a data area. That owner is
//! recorded in one small file in the config directory (`install-owner.json`), written atomically
//! by whoever set the owner up. The record is read, never inferred: a missing record means no
//! owner has been recorded yet, an unreadable one means the owner is unknown, and an unknown owner
//! fails closed (nothing here ever assumes "standalone").
//!
//! The record decides who may change the daemon; the config-directory lock still decides whether
//! one is running.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The record's file name inside the config directory.
pub const FILE_NAME: &str = "install-owner.json";

/// The kind of distribution that owns a data area.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Owner {
    /// The headless distribution: the one-liner, a package manager, a container, a legacy installer.
    Cli,
    /// The desktop distribution: the macOS app bundle or the Windows Store package.
    Gui,
}

impl Owner {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Owner::Cli => "cli",
            Owner::Gui => "gui",
        }
    }

    /// The owner an `install_source` value belongs to. Unknown values belong to the headless
    /// distribution, whose updaters are the ones that add values over time.
    #[must_use]
    pub fn for_install_source(install_source: &str) -> Self {
        match install_source {
            "app_bundle" | "microsoft_store" | "app_store" => Owner::Gui,
            _ => Owner::Cli,
        }
    }

    /// The owner of the installation `exe` runs from, from its path layout alone.
    #[must_use]
    pub fn of_executable(exe: &Path) -> Self {
        if is_app_bundle_path(exe) || is_windows_store_path(exe) {
            Owner::Gui
        } else {
            Owner::Cli
        }
    }
}

/// How an installation is updated when another updater than this command line owns it, `None`
/// when the command line may act (the one-liner's `script`, or a hand-made `standalone` install).
/// Such an installation is never downloaded, extracted, switched or deleted by `yadorilink`: the
/// owner replaces it as a whole (the app bundle, the Store package, the package manager's files,
/// the image).
#[must_use]
pub fn updater_elsewhere(install_source: &str) -> Option<&'static str> {
    Some(match install_source {
        "app_bundle" => "open YadoriLink and choose Check for Updates",
        "microsoft_store" => "open Store > Library > Updates",
        "homebrew" => "run `brew upgrade --cask yadorilink`",
        "apt" => "run `sudo apt update && sudo apt install --only-upgrade yadorilink`",
        "winget" => "run `winget upgrade yadorilink`",
        "container" => "pull a newer image",
        _ => return None,
    })
}

/// How the owner removes an installation that `yadorilink uninstall` does not remove, `None` when
/// the command line may (`script`). The counterpart of [`updater_elsewhere`].
#[must_use]
pub fn uninstaller_elsewhere(install_source: &str) -> Option<&'static str> {
    Some(match install_source {
        "app_bundle" => "quit YadoriLink, then move YadoriLink.app to the Trash",
        "microsoft_store" => "open Settings > Apps > Installed apps > YadoriLink > Uninstall",
        "homebrew" => "run `brew uninstall --cask yadorilink`",
        "apt" => "run `sudo apt remove yadorilink`",
        "winget" => "run `winget uninstall yadorilink`",
        "container" => "stop and remove the container; its data lives in the volume you mounted",
        _ => return None,
    })
}

/// The configured cargo home: `CARGO_HOME` when set and non-empty, else `<home>/.cargo`.
#[must_use]
pub fn cargo_home(env_cargo_home: Option<&str>, home: Option<&Path>) -> Option<PathBuf> {
    match env_cargo_home.filter(|v| !v.is_empty()) {
        Some(dir) => Some(PathBuf::from(dir)),
        None => home.map(|h| h.join(".cargo")),
    }
}

/// Whether `exe` lies in cargo's install directory: `<cargo_home>/bin` (both canonicalized when
/// they exist), or, whatever the configured home, a `.cargo/bin` path.
#[must_use]
pub fn is_cargo_install_path(exe: &Path, cargo_home: Option<&Path>) -> bool {
    let components: Vec<_> = exe.components().map(|c| c.as_os_str()).collect();
    if components.windows(2).any(|pair| pair[0] == ".cargo" && pair[1] == "bin") {
        return true;
    }
    let Some(bin) = cargo_home.map(|h| h.join("bin")) else { return false };
    let Some(exe_dir) = exe.parent() else { return false };
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    canon(exe_dir) == canon(&bin)
}

/// What to do about a copy that no updater and no installer receipt owns (`standalone`, or an
/// unknown source): the command line neither updates nor removes it. `update` selects the
/// update step, otherwise the removal step. A `cargo install` copy names the cargo commands; any
/// other copy was placed by hand and is replaced or deleted by hand. `cargo_home` is the
/// configured cargo home ([`cargo_home`]), which the caller resolves from its environment.
#[must_use]
pub fn unowned_install_steps(exe: &Path, update: bool, cargo_home: Option<&Path>) -> &'static str {
    match (is_cargo_install_path(exe, cargo_home), update) {
        (true, true) => "repeat the `cargo install --locked --force` command you installed it with (`--path` or `--git`, crate `yadorilink-cli`)",
        (true, false) => "run `cargo uninstall yadorilink-cli`",
        (false, true) => {
            "download the new release from https://github.com/yadorilink/yadorilink/releases and \
             replace the binaries you placed, or reinstall with the installer from https://yadori.link"
        }
        (false, false) => "delete the binaries you placed by hand",
    }
}

/// Whether `exe` lies inside a macOS application bundle: some directory named `*.app` directly
/// followed by `Contents` (the main executable, `Contents/Library/LoginItems/*.app`, `Helpers`).
#[must_use]
pub fn is_app_bundle_path(exe: &Path) -> bool {
    app_bundle_root(exe).is_some()
}

/// The outermost `*.app` bundle directory `exe` lies in, if it lies in one.
#[must_use]
pub fn app_bundle_root(exe: &Path) -> Option<PathBuf> {
    let components: Vec<_> = exe.components().collect();
    let index = components.windows(2).position(|pair| {
        pair[1].as_os_str() == "Contents"
            && pair[0]
                .as_os_str()
                .to_str()
                .is_some_and(|n| n.len() > ".app".len() && n.ends_with(".app"))
    })?;
    Some(components[..=index].iter().collect())
}

/// Whether `exe` lies in a Windows Store (MSIX) package location.
#[must_use]
pub fn is_windows_store_path(exe: &Path) -> bool {
    exe.components().any(|c| c.as_os_str() == "WindowsApps")
}

/// What the owner's installer (or a migration) recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipRecord {
    pub owner: Owner,
    pub install_source: String,
    pub install_root: String,
    /// Empty when the installation carries no engine identity.
    pub release_id: String,
    /// Seconds since the Unix epoch.
    pub written_at: u64,
}

/// What the config directory holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordState {
    /// No record: no owner has been recorded for this data area.
    Missing,
    Present(OwnershipRecord),
    /// A record exists and cannot be read or understood. The owner is unknown.
    Unreadable(String),
}

fn path(config_dir: &Path) -> PathBuf {
    config_dir.join(FILE_NAME)
}

/// Reads the record. Read-only.
#[must_use]
pub fn read(config_dir: &Path) -> RecordState {
    let bytes = match std::fs::read(path(config_dir)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RecordState::Missing,
        Err(e) => return RecordState::Unreadable(format!("cannot read {FILE_NAME}: {e}")),
    };
    match serde_json::from_slice::<OwnershipRecord>(&bytes) {
        Ok(record) => RecordState::Present(record),
        Err(e) => RecordState::Unreadable(format!("{FILE_NAME} is not a valid record: {e}")),
    }
}

/// Writes the record: a temporary file in the config directory, flushed, then published over the
/// old record durably, so a crash leaves the old record or the new one and never a partial one.
///
/// # Errors
/// The temporary file cannot be written or published; the previous record is untouched.
pub fn write(config_dir: &Path, record: &OwnershipRecord) -> std::io::Result<()> {
    use std::io::Write;

    let target = path(config_dir);
    let temporary = config_dir.join(format!(".{FILE_NAME}.tmp-{}", std::process::id()));
    // The name carries this process's id, so a leftover is never another writer's.
    let _ = yadorilink_fs_platform::durable_dir::remove_file_durably(&temporary);
    let body = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().create_new(true).write(true).open(&temporary)?;
        file.write_all(&body)?;
        yadorilink_fs_platform::flush::sync_file(&file)?;
        drop(file);
        yadorilink_fs_platform::durable_dir::publish_durably(
            &temporary,
            &target,
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        )
    })();
    if result.is_err() {
        let _ = yadorilink_fs_platform::durable_dir::remove_file_durably(&temporary);
    }
    result
}

/// Why a start was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another owner is recorded for this data area.
    ManagedElsewhere { recorded: OwnershipRecord },
    /// The record exists and cannot be read: the owner is unknown.
    OwnerUnknown { reason: String },
    /// No owner is recorded and this daemon could not record itself as the owner.
    OwnerRecordUnwritable { reason: String },
    /// The record names the same kind of owner but another installation (another `install_source`,
    /// for example `apt` against `script`, or `microsoft_store` against `app_bundle`): each
    /// installation has its own updater, so the data area belongs to the one recorded.
    InstallSourceMismatch { recorded: Box<OwnershipRecord>, mine: String },
    /// This installation's own release descriptor is unreadable or mixes two builds (see
    /// [`crate::release_descriptor`]). Judged before the record is looked at.
    DescriptorUnusable { problem: crate::release_descriptor::DescriptorProblem },
    /// A hand-off of the data area to the app was interrupted half-way (or its journal cannot be
    /// read): who owns the area is settled by finishing or rolling back that hand-off.
    HandoffUnfinished { reason: String },
}

impl Refusal {
    /// The explanation shown to the user, naming who owns the data area.
    #[must_use]
    pub fn message(&self, config_dir: &Path) -> String {
        let record_path = path(config_dir);
        match self {
            Refusal::ManagedElsewhere { recorded } => {
                let who = match recorded.owner {
                    Owner::Gui => "the YadoriLink app".to_string(),
                    Owner::Cli => format!("a command-line install ({})", recorded.install_source),
                };
                let first = format!(
                    "YadoriLink on this machine is managed by {who} ({}); another copy will not \
                     start a second daemon for the same data.",
                    recorded.install_root
                );
                match recorded.owner {
                    Owner::Gui => format!(
                        "{first} Open the YadoriLink app instead. (The owner is recorded in {}.)",
                        record_path.display()
                    ),
                    Owner::Cli => format!(
                        "{first} Use that install and its own updater. (The owner is recorded \
                         in {}.)",
                        record_path.display()
                    ),
                }
            }
            Refusal::OwnerUnknown { reason } => format!(
                "the owner of YadoriLink's data on this machine is unknown ({reason}); nothing was \
                 started. Restore or remove {}.",
                record_path.display()
            ),
            Refusal::InstallSourceMismatch { recorded, mine } => format!(
                "this YadoriLink installation ({mine}) is not the one that owns the data on this \
                 machine: it belongs to the {} installation at {}, which has its own updater; \
                 nothing was started. Use that installation. To hand the data to this one, stop \
                 the other installation, then delete {} (nothing else is removed).",
                recorded.install_source,
                recorded.install_root,
                record_path.display()
            ),
            Refusal::DescriptorUnusable { problem } => problem.message(),
            Refusal::HandoffUnfinished { reason } => format!(
                "an earlier hand-off of YadoriLink's data to the app was interrupted ({reason}), \
                 so who owns the data is not settled; nothing was started. Finish it with the same \
                 app, or roll it back to return to the previous setup."
            ),
            Refusal::OwnerRecordUnwritable { reason } => format!(
                "this daemon could not record itself as the owner of YadoriLink's data on this \
                 machine: the record could not be written to {} ({reason}); nothing was started. \
                 Check the permissions, the free space, and that the data folder is writable; \
                 there is nothing to restore or remove.",
                record_path.display()
            ),
        }
    }
}

/// What a start may do, given the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartVerdict {
    /// The record names this owner.
    Proceed,
    /// No owner is recorded yet.
    NoRecord,
    Refuse(Refusal),
}

/// Whether a start by `mine` may go ahead. A different owner, or an unreadable record, refuses.
#[must_use]
pub fn start_verdict(state: &RecordState, mine: Owner) -> StartVerdict {
    match state {
        RecordState::Missing => StartVerdict::NoRecord,
        RecordState::Present(record) if record.owner == mine => StartVerdict::Proceed,
        RecordState::Present(record) => {
            StartVerdict::Refuse(Refusal::ManagedElsewhere { recorded: record.clone() })
        }
        RecordState::Unreadable(reason) => {
            StartVerdict::Refuse(Refusal::OwnerUnknown { reason: reason.clone() })
        }
    }
}

/// [`start_verdict`] for a start that knows its own `install_source` (the daemon). The recorded
/// owner must also be this very installation: the same kind of owner with another `install_source`
/// is a different installation with a different updater and is refused too. Install roots are not
/// compared (a self-updating install moves between version directories).
#[must_use]
pub fn start_verdict_for_installation(
    state: &RecordState,
    mine: Owner,
    install_source: &str,
) -> StartVerdict {
    match (start_verdict(state, mine), state) {
        (StartVerdict::Proceed, RecordState::Present(record))
            if record.install_source != install_source =>
        {
            StartVerdict::Refuse(Refusal::InstallSourceMismatch {
                recorded: Box::new(record.clone()),
                mine: install_source.to_string(),
            })
        }
        (verdict, _) => verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_home_prefers_the_environment_then_the_home_directory() {
        let home = Path::new("/home/u");
        assert_eq!(cargo_home(Some("/opt/cargo"), Some(home)), Some(PathBuf::from("/opt/cargo")));
        assert_eq!(cargo_home(Some(""), Some(home)), Some(PathBuf::from("/home/u/.cargo")));
        assert_eq!(cargo_home(None, Some(home)), Some(PathBuf::from("/home/u/.cargo")));
        assert_eq!(cargo_home(None, None), None);
    }

    #[test]
    fn a_custom_cargo_home_bin_is_a_cargo_install_and_an_unrelated_bin_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("opt-cargo");
        std::fs::create_dir_all(home.join("bin")).unwrap();
        std::fs::create_dir_all(dir.path().join("tools")).unwrap();
        let exe = home.join("bin/yadorilink");
        let other = dir.path().join("tools/yadorilink");
        assert!(is_cargo_install_path(&exe, Some(&home)));
        assert!(!is_cargo_install_path(&other, Some(&home)));
        assert!(!is_cargo_install_path(&exe, None));
        assert!(unowned_install_steps(&exe, false, Some(&home)).contains("cargo uninstall"));
        assert!(unowned_install_steps(&other, false, Some(&home)).contains("by hand"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_cargo_home_matches_the_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("opt-cargo");
        std::fs::create_dir_all(home.join("bin")).unwrap();
        let exe = home.join("bin/yadorilink");
        let link = dir.path().join("cargo-link");
        std::os::unix::fs::symlink(&home, &link).unwrap();
        assert!(is_cargo_install_path(&exe, Some(&link)));
    }

    #[test]
    fn the_dot_cargo_bin_layout_is_recognized_without_a_configured_home() {
        assert!(is_cargo_install_path(Path::new("/home/u/.cargo/bin/yadorilink"), None));
        assert!(!is_cargo_install_path(Path::new("/home/u/bin/yadorilink"), None));
    }

    fn record(owner: Owner, source: &str) -> OwnershipRecord {
        OwnershipRecord {
            owner,
            install_source: source.into(),
            install_root: "/opt/yadorilink".into(),
            release_id: "abc:def".into(),
            written_at: 1_700_000_000,
        }
    }

    #[test]
    fn only_the_command_line_owned_sources_may_act_on_their_own() {
        for elsewhere in ["app_bundle", "microsoft_store", "homebrew", "apt", "winget", "container"]
        {
            assert!(updater_elsewhere(elsewhere).is_some(), "{elsewhere}");
        }
        for own in ["script", "standalone", "", "something-new"] {
            assert_eq!(updater_elsewhere(own), None, "{own}");
        }
    }

    #[test]
    fn app_bundle_layouts_are_recognised() {
        for yes in [
            "/Applications/YadoriLink.app/Contents/MacOS/yadorilink",
            "/Applications/YadoriLink.app/Contents/Helpers/yadorilink-daemon",
            "/Applications/YadoriLink.app/Contents/Library/LoginItems/Daemon.app/Contents/MacOS/yadorilink-daemon",
            "/Users/u/Applications/Yadori Link.app/Contents/Resources/bin/yadorilink",
        ] {
            assert!(is_app_bundle_path(Path::new(yes)), "{yes}");
        }
        assert_eq!(
            app_bundle_root(Path::new(
                "/Applications/YadoriLink.app/Contents/Library/LoginItems/D.app/Contents/MacOS/d"
            )),
            Some(PathBuf::from("/Applications/YadoriLink.app"))
        );
        assert_eq!(app_bundle_root(Path::new("/usr/bin/yadorilink")), None);
        for no in [
            "/usr/local/bin/yadorilink-daemon",
            "/Users/u/.local/lib/yadorilink/1.0/yadorilink-daemon",
            "/Applications/YadoriLink.app/yadorilink",
            "/Applications/.app/Contents/yadorilink",
            "/Applications/Other.application/Contents/MacOS/x",
            "/tmp/Contents/YadoriLink.app/yadorilink",
        ] {
            assert!(!is_app_bundle_path(Path::new(no)), "{no}");
        }
    }

    #[test]
    fn owner_follows_the_install_source() {
        assert_eq!(Owner::for_install_source("app_bundle"), Owner::Gui);
        assert_eq!(Owner::for_install_source("microsoft_store"), Owner::Gui);
        assert_eq!(Owner::for_install_source("app_store"), Owner::Gui);
        for s in ["script", "standalone", "homebrew", "apt", "winget", "container", "other"] {
            assert_eq!(Owner::for_install_source(s), Owner::Cli, "{s}");
        }
        assert_eq!(
            Owner::of_executable(Path::new(
                "/Applications/YadoriLink.app/Contents/MacOS/yadorilink"
            )),
            Owner::Gui
        );
        assert_eq!(
            Owner::of_executable(Path::new("C:/Program Files/WindowsApps/Y_1.0/yadorilink.exe")),
            Owner::Gui
        );
        assert_eq!(Owner::of_executable(Path::new("/usr/bin/yadorilink")), Owner::Cli);
    }

    #[test]
    fn a_written_record_reads_back_and_a_missing_one_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(dir.path()), RecordState::Missing);
        let first = record(Owner::Cli, "script");
        write(dir.path(), &first).unwrap();
        assert_eq!(read(dir.path()), RecordState::Present(first));
        let second = record(Owner::Gui, "app_bundle");
        write(dir.path(), &second).unwrap();
        assert_eq!(read(dir.path()), RecordState::Present(second));
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(leftovers, vec![FILE_NAME.to_string()]);
    }

    #[test]
    fn a_damaged_record_is_unreadable_not_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), b"{ not json").unwrap();
        assert!(matches!(read(dir.path()), RecordState::Unreadable(_)));
        std::fs::write(dir.path().join(FILE_NAME), br#"{"owner":"nobody"}"#).unwrap();
        assert!(matches!(read(dir.path()), RecordState::Unreadable(_)));
    }

    #[test]
    fn a_directory_in_place_of_the_record_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(FILE_NAME)).unwrap();
        assert!(matches!(read(dir.path()), RecordState::Unreadable(_)));
    }

    #[test]
    fn a_failed_write_leaves_the_previous_record() {
        let dir = tempfile::tempdir().unwrap();
        let first = record(Owner::Cli, "script");
        write(dir.path(), &first).unwrap();
        // The config directory is gone: the write fails and nothing else changes.
        let gone = dir.path().join("missing-subdir");
        assert!(write(&gone, &record(Owner::Gui, "app_bundle")).is_err());
        assert_eq!(read(dir.path()), RecordState::Present(first));
    }

    /// Power loss during the record write (large-tree acceptance, power loss): whatever point the process
    /// dies at, the record is entirely the old one or entirely the new one, and the next write
    /// goes through.
    #[test]
    fn power_loss_during_the_record_write_leaves_the_old_or_the_new_record() {
        use yadorilink_fs_platform::durable_dir::{arm_failpoint, disarm_failpoint, NsFailpoint};

        for point in [NsFailpoint::AfterStage, NsFailpoint::BeforeMove, NsFailpoint::AfterMove] {
            let dir = tempfile::tempdir().unwrap();
            let old = record(Owner::Cli, "script");
            write(dir.path(), &old).unwrap();
            let new = record(Owner::Gui, "app_bundle");
            arm_failpoint(point);
            let result = write(dir.path(), &new);
            disarm_failpoint();
            assert!(result.is_err(), "{point:?}: the interrupted write reports failure");
            match read(dir.path()) {
                RecordState::Present(r) if r == old || r == new => {}
                other => panic!("{point:?}: neither the old nor the new record: {other:?}"),
            }
            if point != NsFailpoint::AfterMove {
                assert_eq!(read(dir.path()), RecordState::Present(old.clone()), "{point:?}");
            }
            write(dir.path(), &new).unwrap();
            assert_eq!(read(dir.path()), RecordState::Present(new), "{point:?}");
        }
    }

    /// A temporary file torn by an earlier power cut (another process id) is never read as the
    /// record, and does not stop a later write.
    #[test]
    fn a_torn_temporary_from_a_dead_process_is_not_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let old = record(Owner::Cli, "script");
        write(dir.path(), &old).unwrap();
        std::fs::write(dir.path().join(format!(".{FILE_NAME}.tmp-1")), b"{\"owner\":\"gu").unwrap();
        assert_eq!(read(dir.path()), RecordState::Present(old));
        let new = record(Owner::Gui, "app_bundle");
        write(dir.path(), &new).unwrap();
        assert_eq!(read(dir.path()), RecordState::Present(new));
        // With no record yet, a torn temporary is still "missing", not "unreadable".
        let empty = tempfile::tempdir().unwrap();
        std::fs::write(empty.path().join(format!(".{FILE_NAME}.tmp-1")), b"{").unwrap();
        assert_eq!(read(empty.path()), RecordState::Missing);
    }

    #[test]
    fn only_the_recorded_owner_may_start() {
        let cli = RecordState::Present(record(Owner::Cli, "script"));
        let gui = RecordState::Present(record(Owner::Gui, "app_bundle"));
        assert_eq!(start_verdict(&cli, Owner::Cli), StartVerdict::Proceed);
        assert_eq!(start_verdict(&gui, Owner::Gui), StartVerdict::Proceed);
        assert!(matches!(
            start_verdict(&cli, Owner::Gui),
            StartVerdict::Refuse(Refusal::ManagedElsewhere { .. })
        ));
        assert!(matches!(
            start_verdict(&gui, Owner::Cli),
            StartVerdict::Refuse(Refusal::ManagedElsewhere { .. })
        ));
        assert_eq!(start_verdict(&RecordState::Missing, Owner::Cli), StartVerdict::NoRecord);
        for mine in [Owner::Cli, Owner::Gui] {
            assert!(matches!(
                start_verdict(&RecordState::Unreadable("x".into()), mine),
                StartVerdict::Refuse(Refusal::OwnerUnknown { .. })
            ));
        }
    }

    #[test]
    fn the_same_owner_kind_with_another_install_source_is_refused() {
        let state = RecordState::Present(record(Owner::Cli, "script"));
        assert_eq!(
            start_verdict_for_installation(&state, Owner::Cli, "script"),
            StartVerdict::Proceed
        );
        for other in ["apt", "homebrew", "standalone", "container", "winget"] {
            assert!(
                matches!(
                    start_verdict_for_installation(&state, Owner::Cli, other),
                    StartVerdict::Refuse(Refusal::InstallSourceMismatch { .. })
                ),
                "{other}"
            );
        }
        let gui = RecordState::Present(record(Owner::Gui, "app_bundle"));
        assert!(matches!(
            start_verdict_for_installation(&gui, Owner::Gui, "microsoft_store"),
            StartVerdict::Refuse(Refusal::InstallSourceMismatch { .. })
        ));
        // A different owner kind is still reported as managed elsewhere, and the rest is unchanged.
        assert!(matches!(
            start_verdict_for_installation(&gui, Owner::Cli, "script"),
            StartVerdict::Refuse(Refusal::ManagedElsewhere { .. })
        ));
        assert_eq!(
            start_verdict_for_installation(&RecordState::Missing, Owner::Cli, "apt"),
            StartVerdict::NoRecord
        );
        assert!(matches!(
            start_verdict_for_installation(&RecordState::Unreadable("x".into()), Owner::Cli, "apt"),
            StartVerdict::Refuse(Refusal::OwnerUnknown { .. })
        ));
    }

    /// The owner record path as the messages print it (the separator is the platform's).
    fn owner_file() -> String {
        Path::new("/cfg").join("install-owner.json").display().to_string()
    }

    #[test]
    fn the_mismatch_refusal_names_both_installations_and_the_fix() {
        let message = Refusal::InstallSourceMismatch {
            recorded: Box::new(record(Owner::Cli, "script")),
            mine: "apt".into(),
        }
        .message(Path::new("/cfg"));
        assert!(message.contains("(apt)") && message.contains("script"), "{message}");
        assert!(message.contains(&format!("delete {}", owner_file())), "{message}");
    }

    #[test]
    fn the_refusal_names_who_owns_the_data() {
        let app = Refusal::ManagedElsewhere { recorded: record(Owner::Gui, "app_bundle") }
            .message(Path::new("/cfg"));
        assert!(app.contains("YadoriLink app"), "{app}");
        assert!(app.contains(&owner_file()), "{app}");
        let unwritable =
            Refusal::OwnerRecordUnwritable { reason: "x".into() }.message(Path::new("/cfg"));
        assert!(unwritable.contains("could not be written to"), "{unwritable}");
        assert!(!unwritable.contains("Restore or remove"), "{unwritable}");
        let unknown = Refusal::OwnerUnknown { reason: "x".into() }.message(Path::new("/cfg"));
        assert!(unknown.contains(&owner_file()), "{unknown}");
        let brew = Refusal::ManagedElsewhere { recorded: record(Owner::Cli, "homebrew") }
            .message(Path::new("/cfg"));
        assert!(brew.contains("homebrew"), "{brew}");
    }
}
