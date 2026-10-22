//! Device (mount) boundary rule for everything that feeds capture.
//!
//! A sync root never indexes across a filesystem boundary: a nested mount
//! under the root is not part of the replica. If it were, unmounting it would
//! leave an empty mountpoint and the offline-tombstone logic would sign
//! group-wide Deletes for the whole former subtree.
//!
//! Policy: walks never descend into a directory whose device differs from the
//! root's. On unix the mountpoint directory itself is skipped as well (it is
//! `foreign`); on Windows walkdir's `same_file_system` yields it as an empty
//! directory and does not descend. Either way nothing beneath it is captured,
//! and rows already indexed beneath a foreign device are never tombstoned
//! (see [`path_crosses_device_boundary`]).

use std::path::Path;

/// True if `dir` is on a different device than `root` (unix: `st_dev`).
/// Non-unix walks rely on walkdir's `same_file_system(true)` instead.
pub fn is_foreign_device_dir(root: &Path, dir: &Path) -> bool {
    #[cfg(any(test, feature = "test-support"))]
    if seam::is_foreign(dir) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(r), Ok(d)) = (std::fs::metadata(root), std::fs::symlink_metadata(dir)) {
            return r.dev() != d.dev();
        }
    }
    let _ = (root, dir);
    false
}

pub use yadorilink_fs_platform::volume_identity::VolumeMatch;

/// The volume the sync root itself is on, as a stable string (see
/// [`yadorilink_fs_platform::volume_identity`]: the filesystem's own UUID or
/// fsid, a share's source, the Windows volume serial, or `unknown` for a
/// filesystem that has no identity surviving a remount, qualified by the mount
/// it was seen on where the kernel names one). An observation that fails is an
/// error, never a weaker identity.
///
/// Persisted per link and compared before the folder is written or any
/// tombstone is authored: if the root's volume is not the one the index was
/// built from (a swapped volume, an unmounted root leaving an empty
/// mountpoint), the folder is not ours to change and absence on disk is not
/// delete evidence. One predicate for every platform.
pub fn root_volume_identity(root: &Path) -> std::io::Result<String> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(over) = seam::root_identity_override(root) {
        return over.ok_or_else(|| std::io::Error::other("volume unobservable (test seam)"));
    }
    Ok(yadorilink_fs_platform::volume_identity::StableVolumeId::observe(root)?.to_string())
}

/// How the volume `root` is on now relates to `recorded`, the identity
/// persisted for its link (see [`VolumeMatch`]). Nothing recorded yet (a link
/// whose first full scan has not completed) is not a mismatch, unless the
/// volume is one that can never be confirmed. An error means the volume could
/// not be observed (the root is gone, or a transient failure), recorded or
/// not: the first capture must not start on a volume that was never
/// identified, so callers that gate a write treat it as "not on the volume"
/// and retry later.
pub fn root_volume_match(root: &Path, recorded: Option<&str>) -> std::io::Result<VolumeMatch> {
    match (recorded, root_volume_identity(root)) {
        (_, Ok(observed)) => Ok(VolumeMatch::of(recorded, &observed)),
        (_, Err(e)) => Err(e),
    }
}

/// Whether `root` is on `recorded`: [`root_volume_match`] is
/// [`VolumeMatch::Same`].
pub fn root_on_recorded_volume(root: &Path, recorded: Option<&str>) -> std::io::Result<bool> {
    Ok(root_volume_match(root, recorded)? == VolumeMatch::Same)
}

/// True if `rel_path` (root-relative) is, or lies under, a directory that is
/// currently on another device than `root`. Such a path is not ours to judge:
/// its absence from a walk is not delete evidence.
pub fn path_crosses_device_boundary(root: &Path, rel_path: &str) -> bool {
    let mut cur = root.to_path_buf();
    for component in Path::new(rel_path).components() {
        cur.push(component);
        if is_foreign_device_dir(root, &cur) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unobservable_root_with_nothing_recorded_is_an_error_not_the_same_volume() {
        let dir = tempfile::tempdir().unwrap();
        seam::set_root_identity(dir.path(), None);
        let first = root_volume_match(dir.path(), None);
        let on_recorded = root_on_recorded_volume(dir.path(), None);
        seam::clear_root_identity(dir.path());
        assert!(first.is_err(), "{first:?}");
        assert!(on_recorded.is_err(), "{on_recorded:?}");
        seam::set_root_identity(dir.path(), Some("unix:1"));
        let later = root_volume_match(dir.path(), None);
        seam::clear_root_identity(dir.path());
        assert_eq!(later.unwrap(), VolumeMatch::Same);
    }
}

/// Test-only seam simulating a device boundary without a real mount.
#[cfg(any(test, feature = "test-support"))]
pub mod seam {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static FOREIGN: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    /// Marks `dir` (and everything under it) as another device.
    pub fn mark_foreign(dir: &Path) {
        FOREIGN.lock().unwrap().push(dir.to_path_buf());
    }

    pub fn clear(dir: &Path) {
        FOREIGN.lock().unwrap().retain(|p| p != dir);
    }

    static ROOT_IDENTITY: Mutex<Vec<(PathBuf, Option<String>)>> = Mutex::new(Vec::new());

    /// Makes `root` report `identity` (`None`: unobservable) as its volume.
    pub fn set_root_identity(root: &Path, identity: Option<&str>) {
        let mut all = ROOT_IDENTITY.lock().unwrap();
        all.retain(|(p, _)| p != root);
        all.push((root.to_path_buf(), identity.map(str::to_owned)));
    }

    pub fn clear_root_identity(root: &Path) {
        ROOT_IDENTITY.lock().unwrap().retain(|(p, _)| p != root);
    }

    pub(super) fn root_identity_override(root: &Path) -> Option<Option<String>> {
        ROOT_IDENTITY.lock().unwrap().iter().find(|(p, _)| p == root).map(|(_, v)| v.clone())
    }

    pub(super) fn is_foreign(dir: &Path) -> bool {
        FOREIGN.lock().unwrap().iter().any(|p| dir.starts_with(p))
    }
}
