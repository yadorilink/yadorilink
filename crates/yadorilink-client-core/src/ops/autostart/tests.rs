use std::cell::RefCell;

use super::*;

struct Recorder {
    calls: RefCell<Vec<String>>,
    enabled: bool,
    /// What `schtasks /Query /XML` prints; `None` when there is no such task.
    task: RefCell<Option<String>>,
}

impl Recorder {
    fn new(enabled: bool) -> Self {
        Self { calls: RefCell::new(Vec::new()), enabled, task: RefCell::new(None) }
    }
}

impl Runner for Recorder {
    fn run(&self, program: &str, args: &[&str]) -> bool {
        self.calls.borrow_mut().push(format!("{program} {}", args.join(" ")));
        !(args.contains(&"is-enabled") && !self.enabled)
    }

    fn output(&self, program: &str, args: &[&str]) -> Option<String> {
        self.calls.borrow_mut().push(format!("{program} {}", args.join(" ")));
        self.task.borrow().clone()
    }
}

#[test]
fn the_launch_agent_starts_the_daemon_at_login_and_never_keeps_it_alive() {
    let plist = launch_agent_plist(Path::new("/opt/y & z/bin/yadorilink-daemon"));
    assert!(plist.contains("<string>com.yadorilink.daemon</string>"));
    assert!(plist.contains("<string>/opt/y &amp; z/bin/yadorilink-daemon</string>"));
    assert!(plist.contains(PLIST_MARKER));
    assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"));
    assert!(!plist.contains("KeepAlive"), "a stopped daemon must stay stopped");
}

#[test]
fn a_macos_entry_is_written_once_and_removed_with_the_daemon_stopped_on_purpose() {
    let home = tempfile::tempdir().expect("home");
    let daemon = Path::new("/usr/local/bin/yadorilink-daemon");
    let runner = Recorder::new(true);
    assert_eq!(
        ensure_in(Platform::MacOs, home.path(), daemon, &runner).unwrap(),
        Autostart::Enabled
    );
    let plist = home.path().join("Library/LaunchAgents/com.yadorilink.daemon.plist");
    assert!(plist.exists());
    assert_eq!(
        ensure_in(Platform::MacOs, home.path(), daemon, &runner).unwrap(),
        Autostart::AlreadyEnabled
    );
    // Nothing is loaded now: the daemon is already running.
    assert!(runner.calls.borrow().is_empty());
    assert!(remove_in(Platform::MacOs, home.path(), &runner).unwrap());
    assert!(!plist.exists());
    assert!(!remove_in(Platform::MacOs, home.path(), &runner).unwrap());
}

#[test]
fn a_plist_this_module_did_not_write_is_left_alone() {
    let home = tempfile::tempdir().expect("home");
    let plist = home.path().join("Library/LaunchAgents/com.yadorilink.daemon.plist");
    std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
    std::fs::write(&plist, "<plist>someone else's</plist>").unwrap();
    assert!(!remove_in(Platform::MacOs, home.path(), &Recorder::new(true)).unwrap());
    assert!(plist.exists());
}

#[test]
fn a_moved_daemon_rewrites_the_entry() {
    let home = tempfile::tempdir().expect("home");
    let runner = Recorder::new(true);
    ensure_in(Platform::MacOs, home.path(), Path::new("/a/yadorilink-daemon"), &runner).unwrap();
    assert_eq!(
        ensure_in(Platform::MacOs, home.path(), Path::new("/b/yadorilink-daemon"), &runner)
            .unwrap(),
        Autostart::Enabled
    );
}

#[test]
fn the_unit_restarts_after_a_crash_and_starts_at_login() {
    let unit = systemd_unit(Path::new("/home/u/.local/bin/yadorilink-daemon"));
    assert!(unit.starts_with(UNIT_MARKER));
    assert!(unit.contains("ExecStart=\"/home/u/.local/bin/yadorilink-daemon\""));
    assert!(unit.contains("Restart=on-failure"));
    assert!(unit.contains("RestartPreventExitStatus=78"), "a duplicate must not be restarted");
    assert!(unit.contains("WantedBy=default.target"));
}

#[test]
fn a_linux_unit_is_written_enabled_and_removed_only_when_it_is_ours() {
    let home = tempfile::tempdir().expect("home");
    let daemon = Path::new("/home/u/.local/bin/yadorilink-daemon");
    let runner = Recorder::new(false);
    assert_eq!(
        ensure_in(Platform::Linux, home.path(), daemon, &runner).unwrap(),
        Autostart::Enabled
    );
    let unit = home.path().join(".config/systemd/user/yadorilink-daemon.service");
    assert!(unit.exists());
    let calls = runner.calls.borrow().join("\n");
    assert!(calls.contains("systemctl --user daemon-reload"), "{calls}");
    assert!(calls.contains("systemctl --user enable yadorilink-daemon.service"), "{calls}");
    assert!(!calls.contains("--now"), "the daemon is already running: {calls}");

    assert!(remove_in(Platform::Linux, home.path(), &runner).unwrap());
    assert!(!unit.exists());

    // A unit somebody else wrote stays.
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(&unit, "[Service]\nExecStart=/x\n").unwrap();
    let calls_before = runner.calls.borrow().len();
    assert!(!remove_in(Platform::Linux, home.path(), &runner).unwrap());
    assert!(unit.exists());
    assert_eq!(
        runner.calls.borrow().len(),
        calls_before,
        "a hand-made unit is not disabled either"
    );
}

#[test]
fn a_machine_without_a_user_manager_gets_no_entry() {
    struct NoManager;
    impl Runner for NoManager {
        fn run(&self, _: &str, _: &[&str]) -> bool {
            false
        }
        fn output(&self, _: &str, _: &[&str]) -> Option<String> {
            None
        }
    }
    let home = tempfile::tempdir().expect("home");
    let result =
        ensure_in(Platform::Linux, home.path(), Path::new("/d/yadorilink-daemon"), &NoManager);
    assert_eq!(result.unwrap(), Autostart::NotApplicable);
    assert!(!home.path().join(".config/systemd/user").exists());
}

#[test]
fn the_unit_escapes_what_systemd_expands() {
    let unit = systemd_unit(Path::new("/opt/50%/a$b/yadorilink-daemon"));
    assert!(unit.contains("ExecStart=\"/opt/50%%/a$$b/yadorilink-daemon\""), "{unit}");
}

#[test]
fn a_packaged_units_program_is_read_from_its_exec_start() {
    assert_eq!(
        exec_start("[Service]\nExecStart=/usr/bin/yadorilink-daemon --x\n").as_deref(),
        Some("/usr/bin/yadorilink-daemon")
    );
    assert_eq!(exec_start("[Service]\nExecStart=\"/a b/d\"\n").as_deref(), Some("/a"));
}

/// A prefix as the installers lay it out: the programs in a version directory, and `bin` reaching
/// them (a link to each program on Unix, a junction to the version directory on Windows).
/// Returns the prefix, the real program and the program as `bin` names it.
fn installed_prefix() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let prefix = tempfile::tempdir().expect("prefix");
    let version = prefix.path().join("share").join("yadorilink").join("versions").join("1.0");
    std::fs::create_dir_all(&version).unwrap();
    let real = version.join(DAEMON_NAME);
    std::fs::write(&real, "x").unwrap();
    let bin = prefix.path().join("bin");
    #[cfg(unix)]
    {
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(&real, bin.join(DAEMON_NAME)).unwrap();
    }
    #[cfg(windows)]
    {
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&bin)
            .arg(&version)
            .output()
            .expect("cmd");
        assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
    }
    let link = bin.join(DAEMON_NAME);
    (prefix, real, link)
}

#[test]
fn the_entry_names_the_prefix_link_not_the_version_directory_an_upgrade_removes() {
    let (prefix, real, link) = installed_prefix();
    // Not on PATH, and the CLI resolved to the version directory.
    let found = stable_path_for(&real, &[]).unwrap();
    let root = without_verbatim_prefix(std::fs::canonicalize(prefix.path()).unwrap());
    assert_eq!(found, root.join("bin").join(DAEMON_NAME));
    // On PATH: that entry.
    assert_eq!(stable_path_for(&real, std::slice::from_ref(&link)).unwrap(), link);
}

#[test]
fn an_enable_that_fails_is_an_error() {
    struct Failing;
    impl Runner for Failing {
        fn run(&self, _: &str, args: &[&str]) -> bool {
            args.contains(&"show-environment")
        }
        fn output(&self, _: &str, _: &[&str]) -> Option<String> {
            None
        }
    }
    let home = tempfile::tempdir().expect("home");
    let result =
        ensure_in(Platform::Linux, home.path(), Path::new("/d/yadorilink-daemon"), &Failing);
    assert!(result.is_err());
}

const WIN_DAEMON: &str = r"C:\Users\a & b\AppData\Local\YadoriLink\bin\yadorilink-daemon.exe";

#[test]
fn the_windows_task_starts_the_daemon_at_the_users_logon_with_the_users_own_rights() {
    let xml = windows_task_xml(Path::new(WIN_DAEMON), r"PC\a");
    assert!(xml.contains(TASK_MARKER));
    assert!(xml.contains(
        r"<Command>C:\Users\a &amp; b\AppData\Local\YadoriLink\bin\yadorilink-daemon.exe</Command>"
    ));
    assert!(xml.contains(r"<LogonTrigger><Enabled>true</Enabled><UserId>PC\a</UserId>"));
    assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
    assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
    assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
}

#[test]
fn a_windows_task_is_made_from_a_utf16_file_and_not_made_twice() {
    let scratch = tempfile::tempdir().expect("scratch");
    let runner = Recorder::new(true);
    let daemon = Path::new(WIN_DAEMON);
    assert_eq!(
        ensure_windows_task(daemon, r"PC\a", scratch.path(), &runner).unwrap(),
        Autostart::Enabled
    );
    let calls = runner.calls.borrow().clone();
    assert!(calls[0].ends_with("/Query /TN YadoriLinkDaemon /XML"));
    assert!(calls[1].contains("/Create /TN YadoriLinkDaemon /XML"), "{calls:?}");
    assert!(calls[1].ends_with("/F"));
    // The definition file does not outlive the call.
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);

    *runner.task.borrow_mut() = Some(windows_task_xml(daemon, r"PC\a"));
    assert_eq!(
        ensure_windows_task(daemon, r"PC\a", scratch.path(), &runner).unwrap(),
        Autostart::AlreadyEnabled
    );
    // A moved daemon rewrites it.
    assert_eq!(
        ensure_windows_task(
            Path::new(r"D:\y\yadorilink-daemon.exe"),
            r"PC\a",
            scratch.path(),
            &runner
        )
        .unwrap(),
        Autostart::Enabled
    );
}

#[test]
fn an_installers_windows_task_is_left_alone() {
    let scratch = tempfile::tempdir().expect("scratch");
    let runner = Recorder::new(true);
    *runner.task.borrow_mut() = Some("<Task><Description>MSI</Description></Task>".to_owned());
    assert_eq!(
        ensure_windows_task(Path::new(WIN_DAEMON), r"PC\a", scratch.path(), &runner).unwrap(),
        Autostart::NotApplicable
    );
    assert!(!remove_windows_task(r"PC\a", &runner).unwrap());
    assert!(runner.calls.borrow().iter().all(|c| !c.contains("/Create") && !c.contains("/Delete")));
}

#[test]
fn only_a_task_this_module_made_is_deleted() {
    let runner = Recorder::new(true);
    assert!(!remove_windows_task(r"PC\a", &runner).unwrap(), "no task");
    *runner.task.borrow_mut() = Some(windows_task_xml(Path::new(WIN_DAEMON), r"PC\a"));
    assert!(remove_windows_task(r"PC\a", &runner).unwrap());
    assert!(runner.calls.borrow().last().unwrap().ends_with("/Delete /TN YadoriLinkDaemon /F"));
}

#[test]
fn a_verbatim_prefix_is_dropped_only_from_a_drive_path() {
    assert_eq!(
        without_verbatim_prefix(PathBuf::from(r"\\?\C:\x\d.exe")),
        PathBuf::from(r"C:\x\d.exe")
    );
    assert_eq!(
        without_verbatim_prefix(PathBuf::from(r"\\?\UNC\srv\share\d.exe")),
        PathBuf::from(r"\\?\UNC\srv\share\d.exe")
    );
}

#[test]
fn another_accounts_or_a_disabled_windows_task_is_handled_by_owner_and_state() {
    let scratch = tempfile::tempdir().expect("scratch");
    let runner = Recorder::new(true);
    let daemon = Path::new(WIN_DAEMON);
    // Another account's task of ours is left as it is.
    *runner.task.borrow_mut() = Some(windows_task_xml(daemon, r"PC\bob"));
    assert_eq!(
        ensure_windows_task(daemon, r"PC\alice", scratch.path(), &runner).unwrap(),
        Autostart::NotApplicable
    );
    // A task switched off is made again.
    let off = windows_task_xml(daemon, r"PC\alice")
        .replace("<Enabled>true</Enabled></Settings>", "<Enabled>false</Enabled></Settings>");
    *runner.task.borrow_mut() = Some(off);
    assert_eq!(
        ensure_windows_task(daemon, r"PC\alice", scratch.path(), &runner).unwrap(),
        Autostart::Enabled
    );
    assert!(
        task_is_ours(&windows_task_xml(daemon, r"PC\Alice"), r"pc\alice"),
        "case is not significant"
    );
}
