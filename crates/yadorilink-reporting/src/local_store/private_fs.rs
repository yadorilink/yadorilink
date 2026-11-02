//! Private files and directories for the reporting stores.
//!
//! Consent state, queued reports and error candidates can describe what a user did and what
//! went wrong on their machine, so they are created readable by the owner only (directories
//! 0700, files 0600), with the mode given when the file is created rather than left to the
//! process umask, and anything an older version created more widely is tightened when a store
//! is opened. Nothing here creates a directory or a file that was not already going to exist:
//! opening a store on a fresh install still writes nothing. On non-Unix platforms the modes do
//! not exist and these are the plain operations.

use std::io;
use std::path::Path;

/// Creates `dir` (and any missing parents, durably) and makes `dir` itself owner-only.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(dir)?;
    set_mode(dir, 0o700)
}

/// Creates (or truncates) `path` as an owner-only file, writable, with the mode set at creation.
pub fn create_private_file(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    // A file that already existed keeps the mode it had; make it owner-only as well.
    set_mode(path, 0o600)?;
    Ok(file)
}

/// `std::fs::write` for an owner-only file.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    create_private_file(path)?.write_all(contents)
}

/// Makes what already exists under `dir` owner-only: `dir` and every directory below it 0700,
/// every regular file 0600. Symlinks are left alone (a mode change would follow them). Best
/// effort and silent when `dir` does not exist; a failure is logged, never raised, because a
/// store that cannot tighten an old file must still work.
pub fn tighten_existing(dir: &Path) {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        _ => return,
    }
    if let Err(error) = tighten_dir(dir) {
        tracing::warn!(error = %error, dir = %dir.display(), "reporting: could not restrict a directory to its owner");
    }
}

fn tighten_dir(dir: &Path) -> io::Result<()> {
    // One entry that cannot be changed (another owner, removed meanwhile) must not leave the
    // rest wide open: each failure is logged and the walk goes on.
    let log = |path: &Path, error: &io::Error| {
        tracing::warn!(error = %error, path = %path.display(), "reporting: could not restrict a path to its owner");
    };
    if let Err(error) = set_mode(dir, 0o700) {
        log(dir, &error);
    }
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => {
                if let Err(error) = tighten_dir(&path) {
                    log(&path, &error);
                }
            }
            Ok(t) if t.is_file() => {
                if let Err(error) = set_mode(&path, 0o600) {
                    log(&path, &error);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Makes the one regular file `path` owner-only if it exists (best effort, a symlink is left
/// alone); for a file that lives in a directory this crate does not own.
pub fn tighten_existing_file(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file()) {
        if let Err(error) = set_mode(path, 0o600) {
            tracing::warn!(error = %error, path = %path.display(), "reporting: could not restrict a file to its owner");
        }
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_created_directory_and_file_are_owner_only_whatever_the_umask() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("reporting");
        create_private_dir(&dir).unwrap();
        write_private_file(&dir.join("a.json"), b"{}").unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("a.json")), 0o600);
    }

    #[test]
    fn a_wide_open_file_that_is_rewritten_becomes_owner_only() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("old.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&path, b"new").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn tightening_restricts_everything_below_and_follows_no_symlink() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("reporting");
        let sub = dir.join("error-candidates");
        std::fs::create_dir_all(&sub).unwrap();
        let outside = root.path().join("outside.txt");
        std::fs::write(&outside, b"not ours").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
        for p in [&dir.join("consent.json"), &sub.join("x.json"), &sub.join("x.redaction")] {
            std::fs::write(p, b"{}").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();

        tighten_existing(&dir);

        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&sub), 0o700);
        assert_eq!(mode(&dir.join("consent.json")), 0o600);
        assert_eq!(mode(&sub.join("x.json")), 0o600);
        assert_eq!(mode(&sub.join("x.redaction")), 0o600);
        assert_eq!(mode(&outside), 0o644, "a symlink target must not be changed");
    }

    #[test]
    fn tightening_a_missing_directory_creates_nothing() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("never-created");
        tighten_existing(&dir);
        assert!(!dir.exists());
    }
}
