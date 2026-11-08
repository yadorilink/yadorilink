// apple-cfg-file: macos-only the start-at-login entry is a launchd agent, which only macOS has
//! Starting the daemon at login, for an installation the command line owns.
//!
//! `yadorilink daemon start` starts the daemon now; for a command-line install it also leaves the
//! OS entry that starts it at every login, so sync does not stop being on after a restart. The
//! entries are the ones named in `yadorilink_local_storage::service_registrations::TABLE` (the
//! launchd agent `com.yadorilink.daemon`, the systemd user unit `yadorilink-daemon.service`).
//! The entry is only written, never loaded now: the daemon is already running, and a second
//! starter would lose the data-area lock and exit.
//!
//! The app's own background service is the other owner's and is never touched: a computer has one
//! owner, and this module does nothing for an executable inside an app bundle or a Store package,
//! nor where a supervisor (a container) already keeps the daemon running.
//!
//! On Windows the entry is the per-user scheduled task `YadoriLinkDaemon` (a logon trigger for the
//! current user, no elevation needed). A task of that name that this module did not write
//! (an installer's) is left alone.

use std::path::{Path, PathBuf};

use yadorilink_local_storage::ownership::Owner;

use crate::error::CoreError;

/// The launchd label, the systemd unit and the scheduled task this module owns.
const LAUNCH_AGENT_LABEL: &str = "com.yadorilink.daemon";
const SYSTEMD_UNIT: &str = "yadorilink-daemon.service";
const WINDOWS_TASK: &str =
    yadorilink_local_storage::service_registrations::WINDOWS_DAEMON_TASK_NAME;
/// First line of a unit this module wrote, so removal never deletes one a package or a person made.
const PLIST_MARKER: &str = "Managed by yadorilink";
const UNIT_MARKER: &str = "# Managed by yadorilink: removed by `yadorilink daemon stop --disable`.";
const TASK_MARKER: &str = "Managed by yadorilink";

/// The OS entries this module can make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
    Windows,
}

impl Platform {
    /// This build's platform, when it has an entry to make.
    #[must_use]
    pub fn current() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::MacOs)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else if cfg!(windows) {
            Some(Self::Windows)
        } else {
            None
        }
    }
}

/// What [`ensure`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Autostart {
    /// The entry was made or changed: the daemon now starts at login.
    Enabled,
    /// The entry was already there as it should be.
    AlreadyEnabled,
    /// Nothing to do for this installation (another owner, a supervisor, another OS).
    NotApplicable,
}

/// Runs a service-manager command and says whether it succeeded.
pub trait Runner {
    fn run(&self, program: &str, args: &[&str]) -> bool;
    /// What the command printed, when it succeeded.
    fn output(&self, program: &str, args: &[&str]) -> Option<String>;
}

struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> bool {
        std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn output(&self, program: &str, args: &[&str]) -> Option<String> {
        let out = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Makes the start-at-login entry for this installation. Call after the daemon was started.
///
/// # Errors
/// The entry could not be written.
pub fn ensure() -> Result<Autostart, CoreError> {
    let Some(platform) = Platform::current() else { return Ok(Autostart::NotApplicable) };
    let Ok(exe) = std::env::current_exe() else { return Ok(Autostart::NotApplicable) };
    if Owner::of_executable(&exe) != Owner::Cli || crate::ops::daemon::supervised_by_environment() {
        return Ok(Autostart::NotApplicable);
    }
    // Whoever manages this data area decides: an entry for the command line over the app's data
    // (or an unfinished hand-off) would start a second daemon beside the owner's.
    let Ok(config_dir) = crate::coordination::device_config::config_dir() else {
        return Ok(Autostart::NotApplicable);
    };
    if crate::ops::daemon::gate_launch(&config_dir, Owner::Cli).is_err() {
        return Ok(Autostart::NotApplicable);
    }
    let Some(daemon) = stable_daemon_path() else { return Ok(Autostart::NotApplicable) };
    let Some(home) = home_dir() else { return Ok(Autostart::NotApplicable) };
    ensure_in(platform, &home, &daemon, &SystemRunner)
}

/// Removes the start-at-login entry this command line made. Safe to repeat; the app's own
/// background service is never touched. Says whether an entry was removed.
///
/// # Errors
/// The entry could not be removed.
pub fn remove() -> Result<bool, CoreError> {
    let Some(platform) = Platform::current() else { return Ok(false) };
    let Ok(exe) = std::env::current_exe() else { return Ok(false) };
    if Owner::of_executable(&exe) != Owner::Cli {
        return Ok(false);
    }
    let Some(home) = home_dir() else { return Ok(false) };
    remove_in(platform, &home, &SystemRunner)
}

/// [`ensure`] with the platform, home directory, daemon program and service manager chosen.
pub fn ensure_in(
    platform: Platform,
    home: &Path,
    daemon: &Path,
    runner: &dyn Runner,
) -> Result<Autostart, CoreError> {
    match platform {
        Platform::MacOs => write_if_changed(&launch_agent_path(home), &launch_agent_plist(daemon)),
        Platform::Windows => {
            let Some(user) = windows_user() else { return Ok(Autostart::NotApplicable) };
            // The definition file goes in the user's own data directory, which only they (and
            // administrators) can write: a shared temp directory would let another account swap
            // the file between writing it and `schtasks` reading it.
            let Ok(scratch) = crate::coordination::device_config::config_dir() else {
                return Ok(Autostart::NotApplicable);
            };
            ensure_windows_task(daemon, &user, &scratch, runner)
        }
        Platform::Linux => {
            // Without a user manager (no systemd, no user bus) there is nothing to register with.
            if !runner.run("systemctl", &["--user", "show-environment"]) {
                return Ok(Autostart::NotApplicable);
            }
            // A packaged unit that runs this very daemon is only enabled. One that runs another
            // install's daemon (a `.deb` beside a script install) is not ours to use: the user
            // unit of the same name takes precedence over it.
            let packaged = packaged_unit_runs(daemon);
            let changed = if packaged {
                Autostart::AlreadyEnabled
            } else {
                let unit = user_unit_path(home);
                let changed = write_if_changed(&unit, &systemd_unit(daemon))?;
                if changed == Autostart::Enabled {
                    runner.run("systemctl", &["--user", "daemon-reload"]);
                }
                changed
            };
            if runner.run("systemctl", &["--user", "is-enabled", "--quiet", SYSTEMD_UNIT]) {
                Ok(changed)
            } else {
                enable_unit(runner)
            }
        }
    }
}

/// [`remove`] with the platform, home directory and service manager chosen. Only an entry this
/// module wrote (it carries the marker) is deleted or disabled. Says whether one was removed.
pub fn remove_in(platform: Platform, home: &Path, runner: &dyn Runner) -> Result<bool, CoreError> {
    match platform {
        Platform::MacOs => {
            let plist = launch_agent_path(home);
            if !std::fs::read_to_string(&plist).is_ok_and(|text| text.contains(PLIST_MARKER)) {
                return Ok(false);
            }
            // A session that already loaded the agent forgets it; the file is what a login reads.
            if let Some(uid) = current_uid() {
                runner.run(
                    "/bin/launchctl",
                    &["bootout", &format!("gui/{uid}/{LAUNCH_AGENT_LABEL}")],
                );
            }
            remove_file(&plist)?;
            Ok(true)
        }
        Platform::Windows => {
            let Some(user) = windows_user() else { return Ok(false) };
            remove_windows_task(&user, runner)
        }
        Platform::Linux => {
            let unit = user_unit_path(home);
            let ours = std::fs::read_to_string(&unit).is_ok_and(|t| t.starts_with(UNIT_MARKER));
            let hand_made = unit.exists() && !ours;
            if hand_made {
                return Ok(false);
            }
            let disabled = runner.run("systemctl", &["--user", "disable", SYSTEMD_UNIT]);
            if ours {
                remove_file(&unit)?;
                runner.run("systemctl", &["--user", "daemon-reload"]);
            }
            Ok(ours || disabled)
        }
    }
}

/// Deletes the logon task when it is the one this module made for `user`.
fn remove_windows_task(user: &str, runner: &dyn Runner) -> Result<bool, CoreError> {
    let schtasks = schtasks_program();
    let Some(existing) = runner.output(&schtasks, &["/Query", "/TN", WINDOWS_TASK, "/XML"]) else {
        return Ok(false);
    };
    if !task_is_ours(&existing, user) {
        return Ok(false);
    }
    if runner.run(&schtasks, &["/Delete", "/TN", WINDOWS_TASK, "/F"]) {
        Ok(true)
    } else {
        Err(CoreError::Other(format!(
            "could not remove the daemon's scheduled task (`schtasks /Delete /TN {WINDOWS_TASK} /F`)"
        )))
    }
}

/// Makes the per-user logon task that starts `daemon`, unless it already does. A task of this name
/// that this module did not write belongs to an installer and is left as it is.
fn ensure_windows_task(
    daemon: &Path,
    user: &str,
    scratch: &Path,
    runner: &dyn Runner,
) -> Result<Autostart, CoreError> {
    let schtasks = schtasks_program();
    if let Some(existing) = runner.output(&schtasks, &["/Query", "/TN", WINDOWS_TASK, "/XML"]) {
        // The name is machine-wide: a task an installer made, or another account's, stays.
        if !task_is_ours(&existing, user) {
            return Ok(Autostart::NotApplicable);
        }
        // A task someone switched off in Task Scheduler is made again, not reported as working.
        if existing.contains(&xml_escape(&daemon.display().to_string()))
            && !existing.contains("<Enabled>false</Enabled>")
        {
            return Ok(Autostart::AlreadyEnabled);
        }
    }
    // schtasks reads the definition from a file, in UTF-16.
    let file = scratch.join(format!("yadorilink-daemon-task-{}.xml", std::process::id()));
    remove_file(&file)?;
    let utf16: Vec<u8> = std::iter::once(0xFEFF_u16)
        .chain(windows_task_xml(daemon, user).encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file)
            .and_then(|mut f| f.write_all(&utf16))
            .map_err(|e| CoreError::Io(e.to_string()))?;
    }
    let file_arg = file.display().to_string();
    let created = runner.run(&schtasks, &["/Create", "/TN", WINDOWS_TASK, "/XML", &file_arg, "/F"]);
    remove_file(&file)?;
    if created {
        Ok(Autostart::Enabled)
    } else {
        Err(CoreError::Other(format!(
            "could not make the daemon's scheduled task (`schtasks /Create /TN {WINDOWS_TASK}`)"
        )))
    }
}

/// Whether the task definition `xml` is the one this module made for `user`.
fn task_is_ours(xml: &str, user: &str) -> bool {
    xml.contains(TASK_MARKER) && xml.to_lowercase().contains(&xml_escape(user).to_lowercase())
}

/// The scheduled task: starts `daemon` when `user` logs on, with that user's own rights and no
/// time limit, and never twice at once.
#[must_use]
pub fn windows_task_xml(daemon: &Path, user: &str) -> String {
    let user = xml_escape(user);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
         <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
         <RegistrationInfo><Description>{TASK_MARKER}: removed by `yadorilink daemon stop \
         --disable`.</Description></RegistrationInfo>\n\
         <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger>\
         </Triggers>\n\
         <Principals><Principal id=\"Author\"><UserId>{user}</UserId>\
         <LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal>\
         </Principals>\n\
         <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\
         <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\
         <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\
         <ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings>\n\
         <Actions Context=\"Author\"><Exec><Command>{}</Command></Exec></Actions>\n\
         </Task>\n",
        xml_escape(&daemon.display().to_string())
    )
}

/// `DOMAIN\user` of the account this process runs as, with the domain Windows itself gives (the
/// computer's name for a local account; `USERDOMAIN` is not that in every session).
#[cfg(windows)]
fn windows_user() -> Option<String> {
    use windows_sys::Win32::Security::Authentication::Identity::{
        GetUserNameExW, NameSamCompatible,
    };
    let mut buffer = [0_u16; 257];
    let mut len = u32::try_from(buffer.len()).ok()?;
    // SAFETY: `buffer` is writable for `len` UTF-16 units, which is what the call is told.
    let ok = unsafe { GetUserNameExW(NameSamCompatible, buffer.as_mut_ptr(), &raw mut len) };
    ok.then(|| String::from_utf16_lossy(&buffer[..len as usize]))
}

#[cfg(not(windows))]
fn windows_user() -> Option<String> {
    None
}

fn schtasks_program() -> String {
    crate::ops::daemon::schtasks_path(std::env::var_os("SystemRoot")).display().to_string()
}

fn enable_unit(runner: &dyn Runner) -> Result<Autostart, CoreError> {
    if runner.run("systemctl", &["--user", "enable", SYSTEMD_UNIT]) {
        Ok(Autostart::Enabled)
    } else {
        Err(CoreError::Other(
            "could not enable the daemon's systemd user unit (`systemctl --user enable \
             yadorilink-daemon`)"
                .to_owned(),
        ))
    }
}

fn write_if_changed(path: &Path, content: &str) -> Result<Autostart, CoreError> {
    if std::fs::read_to_string(path).is_ok_and(|existing| existing == content) {
        return Ok(Autostart::AlreadyEnabled);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| CoreError::Io(e.to_string()))?;
    }
    std::fs::write(path, content).map_err(|e| CoreError::Io(e.to_string()))?;
    Ok(Autostart::Enabled)
}

fn remove_file(path: &Path) -> Result<(), CoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CoreError::Io(e.to_string())),
    }
}

fn launch_agent_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents").join(format!("{LAUNCH_AGENT_LABEL}.plist"))
}

fn user_unit_path(home: &Path) -> PathBuf {
    home.join(".config/systemd/user").join(SYSTEMD_UNIT)
}

/// Whether a package installed the unit and it runs `daemon`.
fn packaged_unit_runs(daemon: &Path) -> bool {
    ["/usr/lib/systemd/user", "/lib/systemd/user", "/etc/systemd/user"].iter().any(|dir| {
        std::fs::read_to_string(Path::new(dir).join(SYSTEMD_UNIT))
            .ok()
            .and_then(|text| exec_start(&text))
            .is_some_and(|program| Path::new(&program) == daemon)
    })
}

/// The program of a unit's `ExecStart=`, without quotes.
fn exec_start(unit: &str) -> Option<String> {
    let line = unit.lines().find_map(|line| line.trim().strip_prefix("ExecStart="))?;
    let program = line.split_whitespace().next()?;
    Some(program.trim_matches('"').to_owned())
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// The launchd agent: starts the daemon at login. No `KeepAlive`: a daemon that was stopped on
/// purpose stays stopped, and a second copy started by launchd would only lose the lock.
#[must_use]
pub fn launch_agent_plist(daemon: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <!-- {PLIST_MARKER}: removed by `yadorilink daemon stop --disable`. -->\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\t<string>{LAUNCH_AGENT_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{}</string>\n\t</array>\n\
         \t<key>RunAtLoad</key>\n\t<true/>\n\
         \t<key>ProcessType</key>\n\t<string>Background</string>\n\
         </dict>\n\
         </plist>\n",
        xml_escape(&daemon.display().to_string())
    )
}

/// The systemd user unit for an install without a package: starts the daemon at login and
/// restarts it after a crash.
#[must_use]
pub fn systemd_unit(daemon: &Path) -> String {
    let program = daemon
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    format!(
        "{UNIT_MARKER}\n\
         [Unit]\n\
         Description=YadoriLink sync daemon\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart=\"{program}\"\n\
         Restart=on-failure\n\
         RestartPreventExitStatus=78\n\
         RestartSec=2\n\n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

/// The daemon program an entry should name: the one beside this command line, by a path that
/// survives an upgrade (a `PATH` entry, or the `bin/` link of the prefix it is installed under)
/// when there is one, else its own path.
fn stable_daemon_path() -> Option<PathBuf> {
    let sibling = std::env::current_exe().ok()?.parent()?.join(DAEMON_NAME);
    let on_path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).map(|dir| dir.join(DAEMON_NAME)).collect())
        .unwrap_or_default();
    stable_path_for(&sibling, &on_path)
}

const DAEMON_NAME: &str = if cfg!(windows) { "yadorilink-daemon.exe" } else { "yadorilink-daemon" };

/// [`stable_daemon_path`] for a chosen `sibling` and `PATH` candidates.
fn stable_path_for(sibling: &Path, on_path: &[PathBuf]) -> Option<PathBuf> {
    let real = std::fs::canonicalize(sibling).ok()?;
    let same = |candidate: &Path| {
        candidate.is_absolute() && std::fs::canonicalize(candidate).is_ok_and(|p| p == real)
    };
    if let Some(found) = on_path.iter().find(|candidate| same(candidate)) {
        return Some(found.clone());
    }
    // A version directory is replaced by the next upgrade, but the install's `bin/` link is not.
    let linked = real
        .ancestors()
        .skip(1)
        .map(|dir| dir.join("bin").join(DAEMON_NAME))
        .find(|candidate| same(candidate));
    Some(without_verbatim_prefix(linked.unwrap_or(real)))
}

/// `C:\x` for the `\\?\C:\x` that canonicalizing gives on Windows; a task or a unit names the
/// plain form.
fn without_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
}

fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var).filter(|home| !home.is_empty()).map(PathBuf::from)
}

fn current_uid() -> Option<u32> {
    cfg!(unix).then(crate::ops::daemon::current_uid)
}

#[cfg(test)]
mod tests;
