//! Why the daemon last refused to start over the data on disk.
//!
//! A daemon that cannot open its data (an index database written by a different
//! build, a database lost beside a populated block store) exits at once, and
//! every client then only sees "daemon is not running". The daemon leaves the
//! reason, with the exact reset steps, in one small file in the config
//! directory; `status`, diagnostics and the app read it while no daemon answers.
//! A start that gets past opening the data removes the file.

use std::path::{Path, PathBuf};

const FILE_NAME: &str = "startup-refusal.txt";

fn path(config_dir: &Path) -> PathBuf {
    config_dir.join(FILE_NAME)
}

/// Records `message` as the reason the daemon refused to start.
pub fn record(config_dir: &Path, message: &str) -> std::io::Result<()> {
    std::fs::write(path(config_dir), message)
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
pub fn read(config_dir: &Path) -> Option<String> {
    std::fs::read_to_string(path(config_dir)).ok().filter(|s| !s.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_refusal_is_read_until_cleared() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(dir.path()), None);
        record(dir.path(), "why").unwrap();
        assert_eq!(read(dir.path()).as_deref(), Some("why"));
        clear(dir.path()).unwrap();
        assert_eq!(read(dir.path()), None);
        clear(dir.path()).unwrap();
    }
}
