//! Whether an executable lies inside a macOS application bundle.

use std::path::{Path, PathBuf};

/// Whether `exe` lies inside a macOS application bundle: some directory named `*.app` directly
/// followed by `Contents` (the main executable, `Contents/Library/LoginItems/*.app`, `Helpers`).
#[must_use]
pub fn is_app_bundle_path(exe: &Path) -> bool {
    app_bundle_root(exe).is_some()
}

/// The outermost `*.app` bundle directory `exe` lies in, if it lies in one.
#[must_use]
pub fn app_bundle_root(exe: &Path) -> Option<PathBuf> {
    let components: Vec<_> = exe.components().collect();
    let index = components.windows(2).position(|pair| {
        pair[1].as_os_str() == "Contents"
            && pair[0]
                .as_os_str()
                .to_str()
                .is_some_and(|n| n.len() > ".app".len() && n.ends_with(".app"))
    })?;
    Some(components[..=index].iter().collect())
}
