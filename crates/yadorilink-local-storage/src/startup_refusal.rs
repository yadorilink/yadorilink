//! Why the daemon last refused to start over the data on disk.
//!
//! A daemon that cannot open its data (an index database written by a different
//! build, a database lost beside a populated block store) exits at once, and
//! every client then only sees "daemon is not running". The daemon leaves the
//! reason, with the exact reset steps, in one small file in the config
//! directory; `status`, diagnostics and the app read it while no daemon answers.
//! A start that gets past opening the data removes the file.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE_NAME: &str = "startup-refusal.json";

fn path(config_dir: &Path) -> PathBuf {
    config_dir.join(FILE_NAME)
}

/// Why the daemon refused to start, and the step that settles it when there is one. The text
/// names no command: a front end words the step for itself ([`StartupRefusal::message`] is the
/// neutral wording).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupRefusal {
    /// What was refused and why.
    pub reason: String,
    /// The supported reset, when the data on disk is known to be unusable by this build.
    pub start_over: Option<StartOver>,
}

/// The supported reset of unusable data: what to delete, with the service stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartOver {
    pub sync_db: PathBuf,
    pub marker: PathBuf,
    pub block_store: PathBuf,
}

impl StartupRefusal {
    /// A refusal with no step of its own.
    #[must_use]
    pub fn plain(reason: impl Into<String>) -> Self {
        Self { reason: reason.into(), start_over: None }
    }

    /// The whole explanation in host-neutral words.
    #[must_use]
    pub fn message(&self) -> String {
        match &self.start_over {
            None => self.reason.clone(),
            Some(reset) => format!(
                "{}\nThere is no migration before release. To start over: stop the background \
                 service, delete the index database {} (and its -wal and -shm files), its marker \
                 file {} and the block store {}, then start the service and link your folders \
                 again. If this device is signed in, remove this device from your account's \
                 device list first and register it again afterwards.",
                self.reason,
                reset.sync_db.display(),
                reset.marker.display(),
                reset.block_store.display()
            ),
        }
    }
}

/// Records `refusal` as the reason the daemon refused to start.
pub fn record(config_dir: &Path, refusal: &StartupRefusal) -> std::io::Result<()> {
    let json = serde_json::to_vec(refusal).map_err(std::io::Error::other)?;
    std::fs::write(path(config_dir), json)
}

/// Forgets a recorded refusal: the data opened. An empty file reads as none,
/// so nothing is removed from the namespace.
pub fn clear(config_dir: &Path) -> std::io::Result<()> {
    if path(config_dir).exists() {
        std::fs::write(path(config_dir), "")?;
    }
    Ok(())
}

/// The recorded reason, if the last start was refused. An unreadable file reads
/// as none: this only explains a failure, it never gates anything.
#[must_use]
pub fn read(config_dir: &Path) -> Option<StartupRefusal> {
    serde_json::from_slice(&std::fs::read(path(config_dir)).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_refusal_is_read_until_cleared() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(dir.path()), None);
        record(dir.path(), &StartupRefusal::plain("why")).unwrap();
        assert_eq!(read(dir.path()), Some(StartupRefusal::plain("why")));
        clear(dir.path()).unwrap();
        assert_eq!(read(dir.path()), None);
        clear(dir.path()).unwrap();
    }

    #[test]
    fn the_reset_steps_survive_the_record_and_the_neutral_text_names_no_command() {
        let dir = tempfile::tempdir().unwrap();
        let refusal = StartupRefusal {
            reason: "cannot open".into(),
            start_over: Some(StartOver {
                sync_db: "/d/db".into(),
                marker: "/d/marker".into(),
                block_store: "/d/blocks".into(),
            }),
        };
        record(dir.path(), &refusal).unwrap();
        let read = read(dir.path()).unwrap();
        assert_eq!(read, refusal);
        let message = read.message();
        assert!(message.contains("/d/db") && message.contains("/d/blocks"), "{message}");
        assert!(!message.contains("yadorilink"), "{message}");
    }
}
