//! Removing a file only after the volume of *that very file* was judged.
//!
//! A verdict taken on a directory path and an unlink by path are two lookups: if the directory
//! is swapped for a junction (or a mount point, or the file for another one) between them, the
//! unlink lands on a volume nobody judged. On Windows the file is therefore opened once without
//! following a final link, the verdict is asked about the directory that handle names (by volume
//! GUID, so it cannot lead to a different volume), and the removal is made through the same
//! handle. Elsewhere the verdict does not depend on the volume and the path is removed.

use std::io;
use std::path::Path;

/// Why [`remove_file_judged`] did not remove the file.
#[derive(Debug)]
pub enum JudgedRemoveError {
    /// The verdict refused the volume of the file; nothing was removed.
    Refused,
    /// The file could not be opened or removed (`NotFound` among them).
    Io(io::Error),
}

/// Removes the file at `path` once `judge` has accepted the directory that holds it. `judge` is
/// given a path that names the volume of the object about to be removed, not `path`'s parent as
/// the caller spelled it.
pub fn remove_file_judged(
    path: &Path,
    judge: impl FnOnce(&Path) -> bool,
) -> Result<(), JudgedRemoveError> {
    #[cfg(windows)]
    {
        super::probe::remove_file_through_handle(path, judge)
    }
    #[cfg(not(windows))]
    {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        if !judge(parent) {
            return Err(JudgedRemoveError::Refused);
        }
        std::fs::remove_file(path).map_err(JudgedRemoveError::Io)
    }
}

/// Asks `judge` about the volume of the already-open `file` (reached by `path`) before the caller
/// deletes bytes through that handle, e.g. by truncating it. On Windows the verdict is about the
/// handle's own volume, so a retargeted directory cannot redirect it; elsewhere it does not
/// depend on the volume and `path`'s parent is judged.
pub fn judge_open_file(
    file: &std::fs::File,
    path: &Path,
    judge: impl FnOnce(&Path) -> bool,
) -> Result<(), JudgedRemoveError> {
    #[cfg(windows)]
    {
        let _ = path;
        super::probe::judge_open_file(file, judge)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        if judge(path.parent().unwrap_or_else(|| Path::new("."))) {
            Ok(())
        } else {
            Err(JudgedRemoveError::Refused)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_file_is_judged_by_its_own_volume() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert!(matches!(
            judge_open_file(&file, &path, |_| false),
            Err(JudgedRemoveError::Refused)
        ));
        judge_open_file(&file, &path, |_| true).unwrap();
    }

    #[test]
    fn a_refused_volume_leaves_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(remove_file_judged(&file, |_| false), Err(JudgedRemoveError::Refused)));
        assert!(file.exists());
    }

    #[test]
    fn an_accepted_volume_removes_the_file_and_a_missing_one_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        remove_file_judged(&file, |_| true).unwrap();
        assert!(!file.exists());
        match remove_file_judged(&file, |_| true) {
            Err(JudgedRemoveError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            other => panic!("{other:?}"),
        }
    }

    /// The file that was judged is the file that is removed, even when another file takes its
    /// name between the verdict and the removal.
    #[cfg(windows)]
    #[test]
    fn the_judged_object_is_the_one_removed_when_the_name_is_taken_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let (file, moved) = (dir.path().join("seg"), dir.path().join("moved"));
        std::fs::write(&file, b"judged").unwrap();
        remove_file_judged(&file, |_| {
            std::fs::rename(&file, &moved).unwrap();
            std::fs::write(&file, b"impostor").unwrap();
            true
        })
        .unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"impostor", "the new file at the name stays");
        assert!(!moved.exists(), "the judged object is gone");
    }

    /// A directory that is a junction to another volume is judged by the volume it leads to.
    /// Needs a second NTFS volume at `D:\`; the test does nothing where there is none.
    #[cfg(windows)]
    #[test]
    fn a_junction_to_another_volume_is_judged_by_the_target_volume() {
        let other = Path::new(r"D:\");
        let Ok(target) = tempfile::Builder::new().prefix("judged-").tempdir_in(other) else {
            return;
        };
        let home = tempfile::tempdir().unwrap();
        let link = home.path().join("segments");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        std::fs::write(target.path().join("seg"), b"x").unwrap();
        let guid_prefix = |p: &Path| p.to_string_lossy().split('\\').nth(3).map(str::to_owned);
        let mut judged = None;
        remove_file_judged(&link.join("seg"), |dir| {
            judged = guid_prefix(dir);
            true
        })
        .unwrap();
        let home_volume = super::super::probe::volume_guid_path_for_test(home.path());
        assert!(judged.as_deref().is_some_and(|g| g.starts_with("Volume{")), "{judged:?}");
        assert_ne!(judged, guid_prefix(Path::new(&home_volume)), "judged the junction's volume");
        assert!(!target.path().join("seg").exists());
    }
}
