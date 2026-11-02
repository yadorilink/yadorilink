//! Whether the account the daemon runs as can write a linked folder, and the one text that says
//! what to do when it cannot (shared by the daemon's startup warning and `yadorilink status`
//! and by the CLI's permission-denied mapping, so the three never drift apart).
//!
//! The usual cause is a NAS bind mount owned by another uid: the folder looks fine to its owner
//! but the daemon (a different uid in a container) can neither take the root lock nor write
//! received files.

use std::path::Path;

/// The uid and gid this process, and so the daemon, runs as.
#[cfg(unix)]
#[must_use]
pub fn daemon_account() -> Option<(u32, u32)> {
    // SAFETY: geteuid/getegid take no arguments and cannot fail.
    Some(unsafe { (libc::geteuid(), libc::getegid()) })
}

#[cfg(not(unix))]
#[must_use]
pub fn daemon_account() -> Option<(u32, u32)> {
    None
}

/// What to do about a folder the daemon's account cannot write, in the words of this operating
/// system. `folder` is shown in the example commands.
#[must_use]
pub fn remedy(folder: &str) -> String {
    #[cfg(target_vendor = "apple")]
    {
        let _ = folder;
        "Allow it in System Settings > Privacy & Security > Files and Folders (or Full Disk \
         Access), and make sure your account may write the folder."
            .to_owned()
    }
    #[cfg(windows)]
    {
        let _ = folder;
        "Give the account YadoriLink runs as write access to the folder.".to_owned()
    }
    #[cfg(not(any(target_vendor = "apple", windows)))]
    {
        format!(
            "Make the folder owned by (or writable for) that account, for example \
             `chown -R <uid>:<gid> {folder}`, or run the daemon as the folder's owner: in Docker \
             set PUID and PGID to the owner's ids (`ls -ln {folder}`) in compose.yaml, or use \
             `user:`."
        )
    }
}

/// The note for a linked folder the daemon's account cannot write, or `None` when it can (or
/// when the folder is missing, which is a different problem with its own report).
#[must_use]
pub fn unwritable_root_note(root: &Path) -> Option<String> {
    let owner = match probe(root) {
        Probe::Writable | Probe::Missing => return None,
        Probe::Unwritable(owner) => owner,
    };
    let path = root.display();
    let account = match daemon_account() {
        Some((uid, gid)) => format!("uid {uid}, gid {gid}"),
        None => "its own account".to_owned(),
    };
    let owner = owner.map_or(String::new(), |(uid, gid, mode)| {
        format!(" The folder belongs to uid {uid}, gid {gid} (mode {mode:o}).")
    });
    Some(format!(
        "{path} is not writable by the daemon, which runs as {account}.{owner} Nothing in it \
         can sync until that changes. {}",
        remedy(&path.to_string())
    ))
}

enum Probe {
    Writable,
    Missing,
    /// Not writable; the folder's owner uid, gid and permission bits when they could be read.
    #[cfg_attr(not(unix), allow(dead_code))]
    Unwritable(Option<(u32, u32, u32)>),
}

#[cfg(unix)]
fn probe(root: &Path) -> Probe {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(root) else {
        return Probe::Missing;
    };
    let Ok(c_path) = std::ffi::CString::new(root.as_os_str().as_bytes()) else {
        return Probe::Writable;
    };
    // The effective ids, which are the daemon's: it never changes them after start.
    // SAFETY: `c_path` is a valid NUL-terminated string for the whole call.
    let ok = unsafe {
        libc::faccessat(libc::AT_FDCWD, c_path.as_ptr(), libc::W_OK | libc::X_OK, libc::AT_EACCESS)
    } == 0;
    if ok {
        Probe::Writable
    } else {
        Probe::Unwritable(Some((meta.uid(), meta.gid(), meta.mode() & 0o7777)))
    }
}

#[cfg(not(unix))]
fn probe(root: &Path) -> Probe {
    // Windows ACLs are not probed without writing; a refusal there surfaces as the access error
    // the CLI maps at link time.
    if root.exists() {
        Probe::Writable
    } else {
        Probe::Missing
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn running_as_root() -> bool {
        daemon_account().is_some_and(|(uid, _)| uid == 0)
    }

    #[test]
    fn a_writable_folder_has_no_note_and_a_missing_one_has_none_either() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(unwritable_root_note(dir.path()), None);
        assert_eq!(unwritable_root_note(&dir.path().join("gone")), None);
    }

    #[test]
    fn a_read_only_folder_is_named_with_the_account_the_owner_and_the_remedy() {
        if running_as_root() {
            return; // root writes anything
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let note = unwritable_root_note(dir.path()).expect("a 0555 folder is not writable");
        let (uid, gid) = daemon_account().unwrap();
        assert!(note.contains(&dir.path().display().to_string()), "{note}");
        assert!(note.contains(&format!("uid {uid}, gid {gid}")), "{note}");
        assert!(note.contains("mode 555"), "{note}");
        #[cfg(not(target_vendor = "apple"))]
        for hint in ["chown", "PUID", "PGID", "user:"] {
            assert!(note.contains(hint), "{hint} missing: {note}");
        }
        #[cfg(target_vendor = "apple")]
        assert!(note.contains("Privacy & Security"), "{note}");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// What it means, and what to do, when a linked folder is on a filesystem that cannot prove that
/// a file or directory seen again is the same one (tmpfs, some network and overlay mounts). The
/// one text shared by the link preflight and `yadorilink status`.
#[must_use]
pub fn unproven_identity_note() -> String {
    "This folder is on a filesystem that cannot tell a replaced file from the same file (for \
     example tmpfs). Deleting or renaming files here from your other devices will not be applied \
     to this folder. Use a folder on a disk-backed location instead."
        .to_owned()
}
