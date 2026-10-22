//! The file backend: owner-only, atomically replaced, and refused outright if
//! anyone else can read it.
//!
//! This is a supported backend, not a canary fallback. It is what makes a
//! headless Linux host deployable, and it is held to the same standard as the
//! OS keyring: the secret is never visible to another user, and a write that
//! is interrupted leaves the previous document intact rather than a truncated
//! one.
//!
//! # Why a permissive mode is refused rather than repaired
//!
//! `chmod 600` on a file that has already been group-readable does not
//! un-read it. Whoever could read it has had the refresh token and the client
//! private key, which together are the authority to continue the session
//! Silently tightening the mode and
//! carrying on would hide exactly the event that should send the user to
//! revoke the registration, so the store refuses and says so.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use yadorilink_fs_platform::durable_dir::{publish_durably, remove_file_durably, Replace};

use super::{StoreError, StoreResult};

fn io(path: &Path) -> impl Fn(std::io::Error) -> StoreError + '_ {
    move |source| StoreError::Io { path: path.to_path_buf(), source }
}

/// The document, or `None` when the file has never been written.
pub(super) fn read(path: &Path) -> StoreResult<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            check_permissions(path)?;
            Ok(Some(contents))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(path)(e)),
    }
}

/// Replaces the document atomically.
///
/// Write a sibling temporary file with the final mode already on it, flush it
/// to the platform, then `rename` over the target. The temporary file is
/// created in the same directory so the rename is within one filesystem and
/// therefore atomic; a `/tmp` staging file would silently degrade to a
/// copy-then-delete on a host where the config directory is a different mount.
pub(super) fn write(path: &Path, contents: &str) -> StoreResult<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(parent).map_err(io(parent))?;

    let temporary = temporary_path(path);
    // A leftover from a crashed write would otherwise make `create_new` fail
    // forever; the name carries this process's id, so removing it cannot
    // disturb another process's in-flight write.
    let _ = std::fs::remove_file(&temporary);

    let result = (|| -> std::io::Result<()> {
        let mut file = owner_only(&temporary)?;
        file.write_all(contents.as_bytes())?;
        // Durable before the rename, or a crash can leave the new name
        // pointing at an empty file while the old document is already gone.
        file.sync_all()?;
        drop(file);
        // Published by a durable move: the new name is on disk when this
        // returns. That matters specifically for a rotated refresh token --
        // `CredentialStore::rotate_refresh_token` reports success as soon as
        // this call returns, and the spent token it just replaced is dead at
        // the server, so a name that reverts here strands the store holding a
        // token the Authorization Server has already refused.
        publish_durably(&temporary, path, Replace::Yes)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(io(path))
}

pub(super) fn clear(path: &Path) -> StoreResult<()> {
    remove_file_durably(path).map_err(io(path))
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path.file_name().map_or_else(|| "credentials".into(), |n| n.to_string_lossy());
    path.with_file_name(format!(".{name}.tmp-{}", std::process::id()))
}

#[cfg(unix)]
fn owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // `mode` applies at creation and is masked by the process umask, so the
    // permissions are also set explicitly below -- a umask of 0 would
    // otherwise be the difference between 0600 and 0666.
    let file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)?;
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    // On Windows the file inherits the directory's ACL, and the config
    // directory is already under the user's profile. There is no mode to set.
    std::fs::OpenOptions::new().create_new(true).write(true).open(path)
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> StoreResult<()> {
    use std::os::unix::fs::MetadataExt as _;
    let mode = std::fs::metadata(path).map_err(io(path))?.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(StoreError::Permissions { path: path.to_path_buf(), mode });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> StoreResult<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn a_written_credential_file_is_owner_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("credentials.json");
        write(&path, "{}").expect("write");
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a credential file must not be readable by anyone else");
    }

    #[test]
    fn a_group_readable_credential_file_is_refused_rather_than_repaired() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("credentials.json");
        write(&path, "{}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("widen the mode");

        let err = read(&path).expect_err("a readable-by-others credential is refused");
        assert!(matches!(err, StoreError::Permissions { mode: 0o640, .. }), "got {err}");
        // And it is still 0640: refusing must not quietly repair, because the
        // exposure has already happened and the user needs to know.
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn a_world_readable_credential_file_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("credentials.json");
        write(&path, "{}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o604)).expect("widen");
        assert!(matches!(read(&path), Err(StoreError::Permissions { .. })));
    }

    /// The replace is atomic, so a reader never sees a half-written document
    /// and a failed write never destroys the previous one.
    #[test]
    fn replacing_the_document_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("credentials.json");
        write(&path, r#"{"a":1}"#).expect("first write");
        write(&path, r#"{"a":2}"#).expect("second write");

        assert_eq!(read(&path).expect("read").expect("present"), r#"{"a":2}"#);
        let stray: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "credentials.json")
            .collect();
        assert!(stray.is_empty(), "a temporary file survived the replace: {stray:?}");
    }

    #[test]
    fn a_write_over_a_leftover_temporary_file_still_succeeds() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("credentials.json");
        std::fs::write(temporary_path(&path), "junk from a crashed write").expect("leftover");
        write(&path, r#"{"a":1}"#).expect("write must not be wedged by a leftover");
        assert_eq!(read(&path).expect("read").expect("present"), r#"{"a":1}"#);
    }
}
