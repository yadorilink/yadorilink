//! The macOS App Group container, obtained the way the OS requires.
//!
//! Since macOS 15 a process only receives the group-container access token
//! when it asks `NSFileManager` for the group's URL; a hand-built
//! `~/Library/Group Containers/<group>` path is refused (EPERM) even though the
//! signature and profile are valid. So the daemon resolves the container with
//! `containerURLForSecurityApplicationGroupIdentifier:` and fails loudly when
//! the system returns nil instead of guessing a path.

use std::path::{Path, PathBuf};

/// The App Group shared with the Finder and File Provider extensions.
pub const MACOS_APP_GROUP: &str = "group.com.juntaki.yadorilink.shared";

/// The shell socket inside a group container.
pub fn shell_socket_in(container: &Path) -> PathBuf {
    container.join("shell.sock")
}

/// Turns the system's answer into the container path, or a clear error.
pub fn container_or_error(answer: Option<PathBuf>, group: &str) -> Result<PathBuf, String> {
    answer.ok_or_else(|| {
        format!(
            "the system returned no container for App Group {group}: the signed app lacks the \
             application-groups entitlement or its provisioning profile does not authorize it"
        )
    })
}

/// Asks the OS for the group container (macOS only).
#[cfg(target_os = "macos")]
pub fn container_url(group: &str) -> Result<PathBuf, String> {
    use objc2_foundation::{NSFileManager, NSString};
    let manager = NSFileManager::defaultManager();
    let id = NSString::from_str(group);
    let url = manager.containerURLForSecurityApplicationGroupIdentifier(&id);
    let path = url.and_then(|u| u.path()).map(|p| PathBuf::from(p.to_string()));
    container_or_error(path, group)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_is_directly_inside_the_container() {
        assert_eq!(shell_socket_in(Path::new("/c/g")), PathBuf::from("/c/g/shell.sock"));
    }

    #[test]
    fn nil_answer_is_a_clear_error_not_a_guessed_path() {
        let err = container_or_error(None, "group.x").unwrap_err();
        assert!(err.contains("group.x") && err.contains("entitlement"));
        assert_eq!(container_or_error(Some("/c".into()), "g").unwrap(), PathBuf::from("/c"));
    }
}
