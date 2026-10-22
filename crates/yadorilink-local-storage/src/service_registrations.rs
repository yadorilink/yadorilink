//! The OS service registrations YadoriLink's installations make, in one table.
//!
//! Each owner registers its daemon with the OS in its own way (a launchd agent, a systemd unit, a
//! Windows scheduled task). A second auto-starter for the same data area would defeat the single
//! owner rule, so every installer and `yadorilink doctor` checks the same list: a registration
//! that belongs to another installation than the recorded one is a conflict to report. This table
//! only names registrations; nothing here registers, removes or changes one.
//!
//! A registration is looked up on disk where the OS keeps its definition, never by running a
//! service manager. Not listed because no label exists yet: the Microsoft Store package's startup
//! task (add it here when the Windows app defines it).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ownership::Owner;

/// How the OS keeps a registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A launchd agent plist named `<name>.plist` in a `LaunchAgents` directory.
    LaunchAgent,
    /// A launchd agent an application registers with `SMAppService`: its plist stays inside the
    /// bundle, at `Contents/Library/LaunchAgents/<name>.plist`, and is never copied out.
    BundledLaunchAgent,
    /// A systemd user unit file.
    SystemdUserUnit,
    /// A systemd system unit file.
    SystemdSystemUnit,
    /// A Windows scheduled task, stored as `System32\Tasks\<name>`.
    WindowsTask,
}

/// One registration an installation makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub kind: Kind,
    /// Launchd label, unit file name or task name.
    pub name: &'static str,
    pub owner: Owner,
    /// The `install_source` values that make this registration.
    pub install_sources: &'static [&'static str],
}

/// The launchd label of the macOS background service: the daemon helper inside YadoriLink.app,
/// registered by the app with `SMAppService`.
pub const MACOS_DAEMON_AGENT_LABEL: &str = "com.juntaki.yadorilink.daemon";

pub const TABLE: &[Registration] = &[
    Registration {
        kind: Kind::BundledLaunchAgent,
        name: MACOS_DAEMON_AGENT_LABEL,
        owner: Owner::Gui,
        install_sources: &["app_bundle"],
    },
    // The agent the macOS `.pkg` installs (retired when the pkg is).
    Registration {
        kind: Kind::LaunchAgent,
        name: "com.yadorilink.daemon",
        owner: Owner::Cli,
        install_sources: &["standalone", "homebrew", "script"],
    },
    Registration {
        kind: Kind::SystemdUserUnit,
        name: "yadorilink-daemon.service",
        owner: Owner::Cli,
        install_sources: &["apt", "script"],
    },
    // The headless service account's unit; its binaries come from the `.deb` or a tarball.
    Registration {
        kind: Kind::SystemdSystemUnit,
        name: "yadorilink-headless.service",
        owner: Owner::Cli,
        install_sources: &["apt", "standalone"],
    },
    Registration {
        kind: Kind::WindowsTask,
        name: WINDOWS_DAEMON_TASK_NAME,
        owner: Owner::Cli,
        install_sources: &["standalone", "winget", "script"],
    },
];

/// The scheduled task that runs the daemon of the Windows installer.
pub const WINDOWS_DAEMON_TASK_NAME: &str = "YadoriLinkDaemon";

/// Where the OS machine keeps its definitions, injected so tests choose a layout.
#[derive(Clone, Debug)]
pub struct Roots {
    pub home: PathBuf,
    /// `C:\Windows` on Windows; unused elsewhere.
    pub system_root: PathBuf,
    /// The application bundles to look in: where the app is installed, and the recorded install
    /// root when it is a bundle.
    pub app_bundles: Vec<PathBuf>,
}

impl Roots {
    /// This machine's roots; `recorded_install_root` is the data area's recorded install root, if
    /// any.
    #[must_use]
    pub fn detect(home: PathBuf, recorded_install_root: Option<&str>) -> Self {
        let mut app_bundles = vec![
            PathBuf::from("/Applications/YadoriLink.app"),
            home.join("Applications/YadoriLink.app"),
        ];
        if let Some(root) = recorded_install_root.map(PathBuf::from) {
            if !app_bundles.contains(&root) {
                app_bundles.push(root);
            }
        }
        let system_root = std::env::var_os("SystemRoot")
            .map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
        Self { home, system_root, app_bundles }
    }
}

impl Registration {
    /// The files whose presence means this registration exists on a machine.
    #[must_use]
    pub fn definition_paths(&self, roots: &Roots) -> Vec<PathBuf> {
        match self.kind {
            Kind::LaunchAgent => {
                let file = format!("{}.plist", self.name);
                vec![
                    roots.home.join("Library/LaunchAgents").join(&file),
                    PathBuf::from("/Library/LaunchAgents").join(file),
                ]
            }
            Kind::BundledLaunchAgent => roots
                .app_bundles
                .iter()
                .map(|b| {
                    b.join("Contents/Library/LaunchAgents").join(format!("{}.plist", self.name))
                })
                .collect(),
            Kind::SystemdUserUnit => vec![
                roots.home.join(".config/systemd/user").join(self.name),
                PathBuf::from("/etc/systemd/user").join(self.name),
                PathBuf::from("/usr/lib/systemd/user").join(self.name),
                PathBuf::from("/lib/systemd/user").join(self.name),
            ],
            Kind::SystemdSystemUnit => vec![
                PathBuf::from("/etc/systemd/system").join(self.name),
                PathBuf::from("/usr/lib/systemd/system").join(self.name),
                PathBuf::from("/lib/systemd/system").join(self.name),
            ],
            Kind::WindowsTask => {
                vec![roots.system_root.join("System32").join("Tasks").join(self.name)]
            }
        }
    }

    #[must_use]
    pub fn is_present(&self, roots: &Roots) -> bool {
        self.definition_paths(roots).iter().any(|p| p.exists())
    }

    /// Whether the installation `install_source` makes this registration.
    #[must_use]
    pub fn belongs_to(&self, install_source: &str) -> bool {
        self.install_sources.contains(&install_source)
    }
}

/// The registrations present on this machine that do not belong to `install_source`: each is a
/// second possible auto-starter beside the recorded installation.
#[must_use]
pub fn conflicting(install_source: &str, roots: &Roots) -> Vec<&'static Registration> {
    TABLE.iter().filter(|r| !r.belongs_to(install_source) && r.is_present(roots)).collect()
}

/// The registrations of `install_source` present on this machine.
#[must_use]
pub fn own(install_source: &str, roots: &Roots) -> Vec<&'static Registration> {
    TABLE.iter().filter(|r| r.belongs_to(install_source) && r.is_present(roots)).collect()
}

/// A step the user takes to remove `registration`, by the OS's own tool.
#[must_use]
pub fn removal_hint(registration: &Registration) -> String {
    match registration.kind {
        Kind::BundledLaunchAgent => format!(
            "quit YadoriLink and delete YadoriLink.app (its agent {} is registered by the app and \
             stays inside the bundle); launchctl cannot unregister it",
            registration.name
        ),
        Kind::LaunchAgent => format!(
            "launchctl bootout gui/$(id -u)/{0} && rm ~/Library/LaunchAgents/{0}.plist",
            registration.name
        ),
        Kind::SystemdUserUnit => format!(
            "systemctl --user disable --now {0}, then remove its definition: `systemctl --user \
             cat {0}` shows the file, and a package-provided unit goes with its package",
            registration.name
        ),
        Kind::SystemdSystemUnit => format!(
            "sudo systemctl disable --now {0}, then remove its definition: `systemctl cat {0}` \
             shows the file, and a package-provided unit goes with its package",
            registration.name
        ),
        Kind::WindowsTask => {
            format!("schtasks /Delete /TN {} /F", registration.name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn roots(home: &Path) -> Roots {
        Roots {
            home: home.to_path_buf(),
            system_root: home.join("win"),
            app_bundles: vec![home.join("Applications/YadoriLink.app")],
        }
    }

    fn install(roots: &Roots, name: &str, kind: Kind) {
        let reg = TABLE.iter().find(|r| r.name == name && r.kind == kind).unwrap();
        let path = reg.definition_paths(roots).into_iter().next().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }

    #[test]
    fn every_name_is_unique_and_every_owner_matches_its_sources() {
        for (i, a) in TABLE.iter().enumerate() {
            for b in &TABLE[i + 1..] {
                assert!(!(a.kind == b.kind && a.name == b.name), "{}", a.name);
            }
            assert!(!a.install_sources.is_empty(), "{}", a.name);
            for source in a.install_sources {
                assert_eq!(Owner::for_install_source(source), a.owner, "{} {source}", a.name);
            }
        }
    }

    #[test]
    fn the_table_matches_the_names_the_installers_use() {
        let names: Vec<_> = TABLE.iter().map(|r| r.name).collect();
        for expected in [
            "com.juntaki.yadorilink.daemon",
            "yadorilink-daemon.service",
            "yadorilink-headless.service",
            "YadoriLinkDaemon",
        ] {
            assert!(names.contains(&expected), "{expected}");
        }
    }

    #[test]
    fn a_clean_machine_has_no_registrations() {
        let home = tempfile::tempdir().unwrap();
        let r = roots(home.path());
        // Only the host's own system paths could add anything; the home and windows roots are empty.
        assert!(own("app_bundle", &r).iter().all(|x| x.kind != Kind::LaunchAgent));
        assert!(TABLE.iter().filter(|x| x.kind == Kind::WindowsTask).all(|x| !x.is_present(&r)));
    }

    #[test]
    fn a_registration_of_another_installation_is_a_conflict_and_the_recorded_ones_are_not() {
        let home = tempfile::tempdir().unwrap();
        let r = roots(home.path());
        install(&r, "com.juntaki.yadorilink.daemon", Kind::BundledLaunchAgent);
        install(&r, "com.yadorilink.daemon", Kind::LaunchAgent);
        let for_app: Vec<_> = conflicting("app_bundle", &r).iter().map(|x| x.name).collect();
        assert!(for_app.contains(&"com.yadorilink.daemon"), "{for_app:?}");
        assert!(!for_app.contains(&"com.juntaki.yadorilink.daemon"), "{for_app:?}");
        let for_pkg: Vec<_> = conflicting("standalone", &r).iter().map(|x| x.name).collect();
        assert!(for_pkg.contains(&"com.juntaki.yadorilink.daemon"), "{for_pkg:?}");
        assert!(!for_pkg.contains(&"com.yadorilink.daemon"), "{for_pkg:?}");
        assert!(own("app_bundle", &r).iter().any(|x| x.name == "com.juntaki.yadorilink.daemon"));
    }

    #[test]
    fn the_apps_agent_is_found_inside_its_bundle_not_in_the_launch_agents_directory() {
        let home = tempfile::tempdir().unwrap();
        let r = roots(home.path());
        install(&r, "com.juntaki.yadorilink.daemon", Kind::BundledLaunchAgent);
        assert!(home
            .path()
            .join("Applications/YadoriLink.app/Contents/Library/LaunchAgents/com.juntaki.yadorilink.daemon.plist")
            .exists());
        let for_pkg: Vec<_> = conflicting("standalone", &r).iter().map(|x| x.name).collect();
        assert!(for_pkg.contains(&"com.juntaki.yadorilink.daemon"), "{for_pkg:?}");
        // A bundle at the recorded install root is looked in too.
        let moved = Roots::detect(home.path().to_path_buf(), Some("/Volumes/X/Y.app"));
        assert!(moved.app_bundles.contains(&PathBuf::from("/Volumes/X/Y.app")));
    }

    #[test]
    fn windows_tasks_are_found_under_the_system_task_store() {
        let home = tempfile::tempdir().unwrap();
        let r = roots(home.path());
        install(&r, "YadoriLinkDaemon", Kind::WindowsTask);
        assert!(r.system_root.join("System32/Tasks/YadoriLinkDaemon").exists());
        assert_eq!(
            conflicting("microsoft_store", &r)
                .iter()
                .filter(|x| x.kind == Kind::WindowsTask)
                .count(),
            1
        );
        assert!(conflicting("standalone", &r).iter().all(|x| x.kind != Kind::WindowsTask));
    }

    #[test]
    fn removal_hints_name_the_registration() {
        for r in TABLE {
            assert!(removal_hint(r).contains(r.name), "{}", r.name);
        }
    }
}
