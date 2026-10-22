//! Size-capped rolling log file for the macOS LaunchAgent and the Windows background daemon.
//!
//! launchd's `StandardOutPath` files are never rotated, and a plist cannot
//! name a path under the user's home. So the daemon logs to a file of its own
//! (`YADORILINK_LOG_FILE`, else [`log_file_path`]'s default): once the file
//! passes [`MAX_BYTES`] it is renamed to `<file>.1` (replacing the previous
//! one) and a fresh file is started, so at most about 2 * MAX_BYTES is kept.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const MAX_BYTES: u64 = 10 * 1024 * 1024;

struct Inner {
    path: PathBuf,
    file: File,
    len: u64,
    max: u64,
}

#[derive(Clone)]
pub struct RollingLog(Arc<Mutex<Inner>>);

/// The file the daemon logs to, if it should log to a file at all:
/// `YADORILINK_LOG_FILE` when set; otherwise, on Windows, the daemon without a terminal
/// (and no `YADORILINK_CONFIG_DIR` override) uses `<state dir>/logs/daemon.log`; on macOS, the installed daemon
/// started by launchd (no `YADORILINK_CONFIG_DIR` override, stderr not a
/// terminal) uses `~/Library/Logs/yadorilink/daemon.log`. Anywhere else it
/// logs to stderr.
pub fn log_file_path() -> Option<PathBuf> {
    use yadorilink_fs_platform::state_dir::{process_override, PathOverride};
    // A refused log location logs to stderr; the daemon's start reports the refusal.
    match process_override(PathOverride::LogFile) {
        Err(_) => return None,
        Ok(Some(path)) => return Some(path),
        Ok(None) => {}
    }
    if cfg!(windows) {
        // A logon task or packaged start has no console, so without a file its failures are
        // invisible. A refused state directory logs to stderr like a refused log location.
        let env = yadorilink_fs_platform::state_dir::Env::from_process();
        let dir = yadorilink_fs_platform::state_dir::checked_state_dir(&env).ok();
        return windows_default_log_file(dir, env.config_dir.is_some(), io::stderr().is_terminal());
    }
    if !cfg!(target_os = "macos") {
        return None;
    }
    default_log_file(
        std::env::var_os("HOME"),
        yadorilink_fs_platform::state_dir::Env::from_process().config_dir.is_some(),
        io::stderr().is_terminal(),
    )
}

/// Logs can hold local paths: a directory made for them is private to the user.
fn create_private_dir(dir: &std::path::Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

fn open_log_file(path: &std::path::Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

fn default_log_file(
    home: Option<OsString>,
    config_dir_overridden: bool,
    stderr_is_terminal: bool,
) -> Option<PathBuf> {
    if config_dir_overridden || stderr_is_terminal {
        return None;
    }
    home.map(|h| PathBuf::from(h).join("Library/Logs/yadorilink/daemon.log"))
}

fn windows_default_log_file(
    state_dir: Option<PathBuf>,
    config_dir_overridden: bool,
    stderr_is_terminal: bool,
) -> Option<PathBuf> {
    if config_dir_overridden || stderr_is_terminal {
        return None;
    }
    state_dir.map(|dir| yadorilink_fs_platform::state_dir::daemon_log_file(&dir))
}

impl RollingLog {
    pub fn open(path: PathBuf, max: u64) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let file = open_log_file(&path)?;
        let len = file.metadata()?.len();
        Ok(Self(Arc::new(Mutex::new(Inner { path, file, len, max }))))
    }
}

impl Write for &RollingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if g.len >= g.max {
            let mut rolled = g.path.clone().into_os_string();
            rolled.push(".1");
            // Best effort: on failure keep appending to the current file.
            if fs::rename(&g.path, &rolled).is_ok() {
                if let Ok(f) = open_log_file(&g.path) {
                    g.file = f;
                    g.len = 0;
                }
            }
        }
        let n = g.file.write(buf)?;
        g.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).file.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RollingLog {
    type Writer = &'a RollingLog;
    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_log_file_is_for_a_launchd_started_installed_daemon_only() {
        let home = || Some(OsString::from("/Users/u"));
        assert_eq!(
            default_log_file(home(), false, false),
            Some(PathBuf::from("/Users/u/Library/Logs/yadorilink/daemon.log"))
        );
        assert_eq!(
            default_log_file(home(), true, false),
            None,
            "a config dir override is a test or dev run"
        );
        assert_eq!(default_log_file(home(), false, true), None, "a terminal gets the logs");
        assert_eq!(default_log_file(None, false, false), None);
    }

    #[test]
    fn windows_default_log_file_is_under_the_state_dir_for_a_background_daemon_only() {
        let dir = || Some(PathBuf::from("state"));
        assert_eq!(
            windows_default_log_file(dir(), false, false),
            Some(PathBuf::from("state").join("logs").join("daemon.log"))
        );
        assert_eq!(windows_default_log_file(dir(), true, false), None);
        assert_eq!(windows_default_log_file(dir(), false, true), None, "a terminal gets the logs");
        assert_eq!(windows_default_log_file(None, false, false), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_log_and_its_directory_are_private_also_after_a_roll() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("ylog-private-{}", std::process::id()));
        let path = root.join("logs/daemon.log");
        let log = RollingLog::open(path.clone(), 4).unwrap();
        (&log).write_all(b"01234").unwrap();
        (&log).write_all(b"a").unwrap();
        let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert!(root.join("logs/daemon.log.1").exists(), "the log rolled");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rolls_once_past_the_cap() {
        let dir = std::env::temp_dir().join(format!("ylog-roll-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.log");
        let log = RollingLog::open(path.clone(), 10).unwrap();
        (&log).write_all(b"0123456789").unwrap();
        (&log).write_all(b"abc").unwrap();
        assert_eq!(fs::read(dir.join("daemon.log.1")).unwrap(), b"0123456789");
        assert_eq!(fs::read(&path).unwrap(), b"abc");
        fs::remove_dir_all(dir).unwrap();
    }
}
