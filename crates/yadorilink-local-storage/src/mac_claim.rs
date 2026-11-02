//! One build per Mac: the direct build and the Mac App Store build must not be used on the same
//! Mac at the same time.
//!
//! The data-area guards (`DaemonInstanceLock`, the install-source ownership record) cannot see
//! across the two builds, because the sandboxed store build keeps its data in its own container.
//! What both builds share is the team's App Group container, so the claim lives there:
//!
//! * `mac-owner-<channel>.lock`: while a daemon of a channel runs it holds a **shared** advisory
//!   lock on its channel's file. Any number of daemons of one channel can coexist (each still has
//!   its own data-area lock); a daemon of the other channel finds the file held and is refused.
//!   The kernel releases the lock on any exit, so there is nothing stale to clean up and no PID is
//!   ever read.
//! * `mac-owner.json`: the channel that completed setup on this Mac (`configured_channel`). It
//!   outlives the process: the other build's File Provider domain stays registered while its
//!   daemon is stopped. Only an explicit [`release`] by its own channel or an explicit
//!   [`take_over`] by the other one changes it.
//!
//! This module decides nothing about the data; it only answers "may this daemon start".

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const RECORD_FILE: &str = "mac-owner.json";
const GUARD_FILE: &str = "mac-owner.guard";
const RECORD_VERSION: u32 = 1;

/// Which kind of installation a daemon belongs to for this rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Every installation that is not the Mac App Store build: the DMG app, a script, Homebrew.
    Direct,
    /// The Mac App Store build.
    Store,
}

impl Channel {
    /// The channel of an (already refined) install source. Only `app_store` is the store build.
    #[must_use]
    pub fn for_install_source(install_source: &str) -> Self {
        if install_source == "app_store" {
            Channel::Store
        } else {
            Channel::Direct
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Direct => "direct",
            Channel::Store => "store",
        }
    }

    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Channel::Direct => Channel::Store,
            Channel::Store => Channel::Direct,
        }
    }

    fn lock_file(self) -> String {
        format!("mac-owner-{}.lock", self.as_str())
    }
}

/// Why a daemon may not start. The other channel is always named.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// A daemon of the other channel is running on this Mac.
    #[error("the {} version of YadoriLink is running on this Mac", .0.as_str())]
    OtherChannelRunning(Channel),
    /// The other channel completed setup on this Mac and has not been released.
    #[error("this Mac is already set up with the {} version of YadoriLink", .0.as_str())]
    OtherChannelConfigured(Channel),
    /// A daemon of this very channel is still running, so it cannot give the Mac up.
    #[error("the {} version of YadoriLink is still running on this Mac", .0.as_str())]
    StillRunning(Channel),
    /// The claim could not be read or written; nothing starts on a guess.
    #[error("cannot check which version of YadoriLink is set up on this Mac: {0}")]
    Unavailable(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    version: u32,
    configured_channel: Channel,
}

/// A daemon's claim, held for its whole life. Dropping it (or exiting) releases the running part;
/// the configured part stays.
#[derive(Debug)]
pub struct Claim {
    _lock: File,
    channel: Channel,
}

impl Claim {
    #[must_use]
    pub fn channel(&self) -> Channel {
        self.channel
    }
}

fn record_path(container: &Path) -> PathBuf {
    container.join(RECORD_FILE)
}

fn io_err(what: &str, path: &Path, e: &std::io::Error) -> Refusal {
    Refusal::Unavailable(format!("{what} {}: {e}", path.display()))
}

fn open_lock(container: &Path, channel: Channel) -> Result<(File, PathBuf), Refusal> {
    let path = container.join(channel.lock_file());
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| io_err("cannot open", &path, &e))?;
    Ok((file, path))
}

/// Serialises the probe-and-record step among starts, take-overs and releases on this Mac, so two daemons of one
/// channel cannot refuse each other through their momentary exclusive probes and two writers never share a
/// staging file. Held only for those few steps, never for a daemon's life.
fn guard(container: &Path) -> Result<File, Refusal> {
    let path = container.join(GUARD_FILE);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| io_err("cannot open", &path, &e))?;
    fs2::FileExt::lock_exclusive(&file).map_err(|e| io_err("cannot lock", &path, &e))?;
    Ok(file)
}

fn contended(error: &std::io::Error) -> bool {
    error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

/// What the record says: `Ok(None)` when no setup is recorded. An unreadable or unknown record is an
/// error, never "nothing configured".
fn read_record(container: &Path) -> Result<Option<Channel>, Refusal> {
    let path = record_path(container);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err("cannot read", &path, &e)),
    };
    let record: Record = serde_json::from_slice(&bytes)
        .map_err(|e| Refusal::Unavailable(format!("{} is unreadable: {e}", path.display())))?;
    if record.version != RECORD_VERSION {
        return Err(Refusal::Unavailable(format!(
            "{} has version {}, this build understands {RECORD_VERSION}",
            path.display(),
            record.version
        )));
    }
    Ok(Some(record.configured_channel))
}

fn write_record(container: &Path, channel: Channel) -> Result<(), Refusal> {
    let path = record_path(container);
    // Callers hold the guard, so one staging name per process cannot be shared by two writers.
    let staged = container.join(format!("{RECORD_FILE}.{}.tmp", std::process::id()));
    let json = serde_json::to_vec(&Record { version: RECORD_VERSION, configured_channel: channel })
        .map_err(|e| Refusal::Unavailable(e.to_string()))?;
    let result = (|| {
        let mut file = File::create(&staged)?;
        file.write_all(&json)?;
        yadorilink_fs_platform::flush::sync_file(&file)?;
        yadorilink_fs_platform::durable_dir::publish_durably(
            &staged,
            &path,
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        )
    })();
    result.map_err(|e| {
        let _ = yadorilink_fs_platform::durable_dir::remove_file_durably(&staged);
        io_err("cannot write", &path, &e)
    })
}

/// Takes this daemon's claim, or says why it may not start. Call it before the daemon opens its
/// own data area.
///
/// Order matters: this channel's shared lock is taken first, then the other channel's file is probed
/// with a non-blocking exclusive lock. If two daemons of different channels start together, each
/// holds its own shared lock when it probes, so at least one (usually both) is refused and retries;
/// two can never both proceed.
pub fn acquire(container: &Path, channel: Channel) -> Result<Claim, Refusal> {
    let _guard = guard(container)?;
    let (mine, mine_path) = open_lock(container, channel)?;
    fs2::FileExt::try_lock_shared(&mine).map_err(|e| io_err("cannot lock", &mine_path, &e))?;

    let other = channel.other();
    let (probe, probe_path) = open_lock(container, other)?;
    match fs2::FileExt::try_lock_exclusive(&probe) {
        Ok(()) => {
            // Nobody of the other channel is running; the probe lock is only a check.
            fs2::FileExt::unlock(&probe).map_err(|e| io_err("cannot release", &probe_path, &e))?;
        }
        Err(e) if contended(&e) => return Err(Refusal::OtherChannelRunning(other)),
        Err(e) => return Err(io_err("cannot probe", &probe_path, &e)),
    }

    match read_record(container)? {
        Some(configured) if configured != channel => {
            Err(Refusal::OtherChannelConfigured(configured))
        }
        Some(_) => Ok(Claim { _lock: mine, channel }),
        None => {
            write_record(container, channel)?;
            Ok(Claim { _lock: mine, channel })
        }
    }
}

/// The owning channel gives up the Mac (sign-out or removal, after pending edits were refused or kept).
/// Refused unless `channel` is the configured one and no daemon of that channel is running.
pub fn release(container: &Path, channel: Channel) -> Result<(), Refusal> {
    let _guard = guard(container)?;
    match read_record(container)? {
        Some(configured) if configured == channel => {
            let (probe, path) = open_lock(container, channel)?;
            match fs2::FileExt::try_lock_exclusive(&probe) {
                Ok(()) => {
                    fs2::FileExt::unlock(&probe).map_err(|e| io_err("cannot release", &path, &e))?
                }
                Err(e) if contended(&e) => return Err(Refusal::StillRunning(channel)),
                Err(e) => return Err(io_err("cannot probe", &path, &e)),
            }
            let record = record_path(container);
            yadorilink_fs_platform::durable_dir::remove_file_durably(&record)
                .map_err(|e| io_err("cannot remove", &record, &e))
        }
        Some(other) => Err(Refusal::OtherChannelConfigured(other)),
        None => Ok(()),
    }
}

/// The user confirmed switching to this build: replaces the other channel's configured record.
/// Refused while any daemon of the other channel runs (the lock is the proof nothing is using it);
/// the caller holds its own [`Claim`] only after this returns, so this takes the shared lock itself.
pub fn take_over(container: &Path, channel: Channel) -> Result<Claim, Refusal> {
    let _guard = guard(container)?;
    let (mine, mine_path) = open_lock(container, channel)?;
    fs2::FileExt::try_lock_shared(&mine).map_err(|e| io_err("cannot lock", &mine_path, &e))?;
    let other = channel.other();
    let (probe, probe_path) = open_lock(container, other)?;
    match fs2::FileExt::try_lock_exclusive(&probe) {
        Ok(()) => {
            fs2::FileExt::unlock(&probe).map_err(|e| io_err("cannot release", &probe_path, &e))?
        }
        Err(e) if contended(&e) => return Err(Refusal::OtherChannelRunning(other)),
        Err(e) => return Err(io_err("cannot probe", &probe_path, &e)),
    }
    // An unreadable or unknown record is not something to overwrite on a guess.
    read_record(container)?;
    write_record(container, channel)?;
    Ok(Claim { _lock: mine, channel })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn only_the_app_store_source_is_the_store_channel() {
        assert_eq!(Channel::for_install_source("app_store"), Channel::Store);
        for s in ["app_bundle", "script", "homebrew", "standalone", "apt", ""] {
            assert_eq!(Channel::for_install_source(s), Channel::Direct, "{s}");
        }
    }

    #[test]
    fn the_first_start_records_its_channel_and_a_second_daemon_of_that_channel_may_start() {
        let d = dir();
        let first = acquire(d.path(), Channel::Direct).unwrap();
        let second = acquire(d.path(), Channel::Direct).unwrap();
        assert_eq!(read_record(d.path()).unwrap(), Some(Channel::Direct));
        drop((first, second));
    }

    #[test]
    fn the_other_channel_is_refused_while_a_daemon_runs() {
        let d = dir();
        let _direct = acquire(d.path(), Channel::Direct).unwrap();
        assert_eq!(
            acquire(d.path(), Channel::Store).unwrap_err(),
            Refusal::OtherChannelRunning(Channel::Direct)
        );
        // A refused start leaves the record alone.
        assert_eq!(read_record(d.path()).unwrap(), Some(Channel::Direct));
    }

    #[test]
    fn a_stopped_daemon_still_leaves_its_channel_configured() {
        let d = dir();
        drop(acquire(d.path(), Channel::Direct).unwrap());
        assert_eq!(
            acquire(d.path(), Channel::Store).unwrap_err(),
            Refusal::OtherChannelConfigured(Channel::Direct)
        );
        assert!(acquire(d.path(), Channel::Direct).is_ok());
    }

    #[test]
    fn release_by_the_owner_frees_the_mac_for_the_other_channel() {
        let d = dir();
        let claim = acquire(d.path(), Channel::Direct).unwrap();
        // Still running: it cannot give the Mac up.
        assert_eq!(
            release(d.path(), Channel::Direct).unwrap_err(),
            Refusal::StillRunning(Channel::Direct)
        );
        drop(claim);
        release(d.path(), Channel::Direct).unwrap();
        assert!(acquire(d.path(), Channel::Store).is_ok());
    }

    #[test]
    fn release_by_the_wrong_channel_changes_nothing() {
        let d = dir();
        drop(acquire(d.path(), Channel::Direct).unwrap());
        assert_eq!(
            release(d.path(), Channel::Store).unwrap_err(),
            Refusal::OtherChannelConfigured(Channel::Direct)
        );
        assert_eq!(read_record(d.path()).unwrap(), Some(Channel::Direct));
    }

    #[test]
    fn take_over_needs_the_other_channel_to_be_stopped() {
        let d = dir();
        let running = acquire(d.path(), Channel::Direct).unwrap();
        assert_eq!(
            take_over(d.path(), Channel::Store).unwrap_err(),
            Refusal::OtherChannelRunning(Channel::Direct)
        );
        drop(running);
        let store = take_over(d.path(), Channel::Store).unwrap();
        assert_eq!(read_record(d.path()).unwrap(), Some(Channel::Store));
        assert_eq!(
            acquire(d.path(), Channel::Direct).unwrap_err(),
            Refusal::OtherChannelRunning(Channel::Store)
        );
        drop(store);
        assert_eq!(
            acquire(d.path(), Channel::Direct).unwrap_err(),
            Refusal::OtherChannelConfigured(Channel::Store)
        );
    }

    #[test]
    fn take_over_does_not_overwrite_an_unreadable_record() {
        let d = dir();
        std::fs::write(record_path(d.path()), b"garbage").unwrap();
        assert!(matches!(take_over(d.path(), Channel::Store), Err(Refusal::Unavailable(_))));
        assert_eq!(std::fs::read(record_path(d.path())).unwrap(), b"garbage");
    }

    #[test]
    fn many_daemons_of_one_channel_start_together_without_refusing_each_other() {
        let d = dir();
        let path = d.path().to_path_buf();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || acquire(&path, Channel::Direct).map(std::mem::forget))
            })
            .collect();
        for h in handles {
            h.join().unwrap().unwrap();
        }
    }

    #[test]
    fn a_take_over_and_a_daemon_start_never_both_win() {
        // The takeover (store) and the old channel's daemon start (direct) race 50 times: after both finished the record
        // is the store's, and a direct start that came after the take over was refused; a direct start that came
        // first was then turned away from the store's take over while it ran.
        for _ in 0..50 {
            let d = dir();
            drop(acquire(d.path(), Channel::Direct).unwrap());
            let path = d.path().to_path_buf();
            let start = {
                let path = path.clone();
                std::thread::spawn(move || acquire(&path, Channel::Direct))
            };
            let took = take_over(&path, Channel::Store);
            let started = start.join().unwrap();
            match (&took, &started) {
                // the daemon started first and still runs: the take over was refused
                (Err(Refusal::OtherChannelRunning(Channel::Direct)), Ok(_)) => {}
                // the take over won: the daemon is refused (running store claim or the configured record)
                (
                    Ok(_),
                    Err(
                        Refusal::OtherChannelRunning(Channel::Store)
                        | Refusal::OtherChannelConfigured(Channel::Store),
                    ),
                ) => {}
                // the daemon started and stopped before the take over: nothing running, the take over then succeeded,
                // and the record is the store's
                (Ok(_), Ok(_)) => {
                    panic!("both won: a direct daemon runs while the Mac was taken over")
                }
                other => panic!("unexpected outcome {other:?}"),
            }
        }
    }

    #[test]
    fn an_unreadable_or_unknown_record_fails_closed() {
        let d = dir();
        std::fs::write(record_path(d.path()), b"not json").unwrap();
        assert!(matches!(acquire(d.path(), Channel::Direct), Err(Refusal::Unavailable(_))));
        std::fs::write(record_path(d.path()), br#"{"version":99,"configured_channel":"direct"}"#)
            .unwrap();
        assert!(matches!(acquire(d.path(), Channel::Direct), Err(Refusal::Unavailable(_))));
    }

    #[test]
    fn a_killed_process_releases_the_running_claim() {
        // Hold the store claim in a child process, kill it, and the direct channel is then only blocked by
        // the configured record, not by a stale lock.
        let d = dir();
        let exe = std::env::current_exe().unwrap();
        let mut child = std::process::Command::new(exe)
            .args(["--exact", "mac_claim::tests::child_holds_the_store_claim", "--nocapture"])
            .env("YL_MAC_CLAIM_DIR", d.path())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            use std::io::BufRead as _;
            assert!(
                out.read_line(&mut line).unwrap() > 0,
                "the child exited before holding the claim"
            );
            if line.contains("HELD") {
                break;
            }
        }
        assert_eq!(
            acquire(d.path(), Channel::Direct).unwrap_err(),
            Refusal::OtherChannelRunning(Channel::Store)
        );
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            acquire(d.path(), Channel::Direct).unwrap_err(),
            Refusal::OtherChannelConfigured(Channel::Store)
        );
    }

    #[test]
    // Does nothing unless a_killed_process_releases_the_running_claim started it with the directory set.
    fn child_holds_the_store_claim() {
        let Ok(dir) = std::env::var("YL_MAC_CLAIM_DIR") else { return };
        let _claim = acquire(Path::new(&dir), Channel::Store).unwrap();
        println!("HELD");
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
