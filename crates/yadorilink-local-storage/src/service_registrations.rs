//! The OS service registrations YadoriLink's installations make, in one table.
//!
//! Each owner registers its daemon with the OS in its own way (a launchd agent, a systemd unit, a
//! Windows scheduled task). A second auto-starter for the same data area would defeat the single
//! owner rule, so every installer and `yadorilink doctor` checks the same list: a registration
//! that belongs to another installation than the recorded one is a conflict to report. This table
//! only names registrations; nothing here registers, removes or changes one.
//!
//! A registration is looked up on disk where the OS keeps its definition, never by running a
//! service manager. The Microsoft Store package's startup task lives in the package manifest, not
//! in the task scheduler: it is present while the user's registry holds its state as enabled, so
//! that state is read once into [`Roots`] and no file stands for it.

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
    /// The startup task a Microsoft Store (MSIX) package declares in its manifest. It has no file
    /// of its own; it is present while Windows records it as enabled for this user
    /// ([`Roots::store_startup_enabled`]). Windows owns it; the user disables it under Settings >
    /// Apps > Startup.
    PackagedStartupTask,
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
// A build may name other ids through the build-time environment variable below; unset, these are the product's ids.
pub const MACOS_DAEMON_AGENT_LABEL: &str = match option_env!("YADORILINK_DAEMON_LABEL") {
    Some(id) => id,
    None => "com.juntaki.yadorilink.daemon",
};

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
    Registration {
        kind: Kind::PackagedStartupTask,
        name: STORE_PACKAGE_FAMILY,
        owner: Owner::Gui,
        install_sources: &["microsoft_store"],
    },
];

/// The package family of the Microsoft Store package, whose manifest declares the startup task
/// `YadoriLinkStartup`.
pub const STORE_PACKAGE_FAMILY: &str = "JumpeiTakiyasu.YadoriLink_3ydcaw70ed9wa";

/// The task id in that package's manifest.
#[cfg(windows)]
const STORE_STARTUP_TASK_ID: &str = "YadoriLinkStartup";

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
    /// Whether this user has the Microsoft Store package's startup task enabled (Windows keeps its
    /// state in the user's registry); always `false` off Windows.
    pub store_startup_enabled: bool,
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
        Self {
            home,
            system_root: PathBuf::from("C:\\Windows"),
            app_bundles,
            store_startup_enabled: store_startup_enabled(),
        }
    }

    /// These roots with the Windows system root the caller read from its environment
    /// (`%SystemRoot%`), when it set one, instead of the conventional `C:\Windows`.
    #[must_use]
    pub fn with_system_root(mut self, system_root: Option<std::ffi::OsString>) -> Self {
        if let Some(root) = system_root {
            self.system_root = PathBuf::from(root);
        }
        self
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
            Kind::PackagedStartupTask => Vec::new(),
        }
    }

    #[must_use]
    pub fn is_present(&self, roots: &Roots) -> bool {
        if self.kind == Kind::PackagedStartupTask {
            return roots.store_startup_enabled;
        }
        self.definition_paths(roots).iter().any(|p| p.exists())
    }

    /// Whether the installation `install_source` makes this registration.
    #[must_use]
    pub fn belongs_to(&self, install_source: &str) -> bool {
        self.install_sources.contains(&install_source)
    }
}

/// `StartupTaskState` values Windows records for the Store package's task: enabled, or enabled by
/// policy.
#[cfg(any(windows, test))]
fn startup_state_is_enabled(state: u32) -> bool {
    matches!(state, 2 | 4)
}

/// Whether the Store package's startup task is enabled for the current user. Windows keeps the state
/// under `HKCU\Software\Classes\Local Settings\...\SystemAppData\<family>\<task id>`, written
/// when the app first asks for the task; a missing key means it was never enabled.
#[cfg(windows)]
fn store_startup_enabled() -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let key = wide(&format!(
        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\{STORE_PACKAGE_FAMILY}\\{STORE_STARTUP_TASK_ID}"
    ));
    let value = wide("State");
    let mut data: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as u32;
    // SAFETY: both strings are NUL-terminated and outlive the call; `data` and `len` describe a
    // 4-byte buffer.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            std::ptr::addr_of_mut!(data).cast(),
            &mut len,
        )
    };
    status == 0 && startup_state_is_enabled(data)
}

#[cfg(not(windows))]
fn store_startup_enabled() -> bool {
    false
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
        Kind::PackagedStartupTask => format!(
            "turn YadoriLink off under Settings > Apps > Startup, or uninstall the Store app \
             (package family {}) under Settings > Apps > Installed apps",
            registration.name
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn macos_daemon_agent_label_follows_the_build_identity() {
        assert_eq!(
            super::MACOS_DAEMON_AGENT_LABEL,
            option_env!("YADORILINK_DAEMON_LABEL").unwrap_or("com.juntaki.yadorilink.daemon")
        );
    }

    use super::*;
    use std::path::Path;

    fn roots(home: &Path) -> Roots {
        Roots {
            home: home.to_path_buf(),
            system_root: home.join("win"),
            app_bundles: vec![home.join("Applications/YadoriLink.app")],
            store_startup_enabled: false,
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
            "JumpeiTakiyasu.YadoriLink_3ydcaw70ed9wa",
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
    fn the_store_package_startup_task_is_a_conflict_for_every_other_installation() {
        let home = tempfile::tempdir().unwrap();
        let mut r = roots(home.path());
        assert!(conflicting("script", &r).iter().all(|x| x.name != STORE_PACKAGE_FAMILY));
        r.store_startup_enabled = true;
        let names = |source| conflicting(source, &r).iter().map(|x| x.name).collect::<Vec<_>>();
        assert!(names("standalone").contains(&STORE_PACKAGE_FAMILY));
        assert!(names("script").contains(&STORE_PACKAGE_FAMILY));
        assert!(!names("microsoft_store").contains(&STORE_PACKAGE_FAMILY));
        assert!(own("microsoft_store", &r).iter().any(|x| x.name == STORE_PACKAGE_FAMILY));
        let hint = removal_hint(TABLE.iter().find(|x| x.name == STORE_PACKAGE_FAMILY).unwrap());
        assert!(hint.contains("Startup"), "{hint}");
    }

    #[cfg(windows)]
    #[test]
    fn the_registry_read_is_false_without_a_state_key() {
        // A development machine has no Store package, so no state key: the read must succeed and say no.
        assert!(!store_startup_enabled());
    }

    #[test]
    fn only_an_enabled_startup_state_counts() {
        // Windows' StartupTaskState: Disabled, DisabledByUser, Enabled, DisabledByPolicy, EnabledByPolicy.
        let enabled: Vec<u32> = (0..6).filter(|s| startup_state_is_enabled(*s)).collect();
        assert_eq!(enabled, [2, 4]);
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
