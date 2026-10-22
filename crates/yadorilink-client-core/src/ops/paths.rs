//! Client-side path resolution. The daemon runs in its own working directory
//! (under a service manager, often `/`), so every path a request carries must
//! already be absolute, and link paths must be spelled exactly the way
//! `link` recorded them.

use std::path::{Component, Path, PathBuf};

use crate::error::CoreError;

/// Resolves `raw` to the spelling `link` records: the canonical path when the
/// folder exists. A folder that is already gone (the usual reason to unlink)
/// is resolved through its longest existing ancestor, so symlinked prefixes
/// (`/tmp` vs `/private/tmp`) and trailing or relative components still map
/// onto the recorded link.
pub fn resolve_link_path(raw: &str) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(raw) {
        return canonical;
    }
    let absolute = std::path::absolute(raw).unwrap_or_else(|_| PathBuf::from(raw));
    let mut missing: Vec<Component<'_>> = Vec::new();
    let mut probe: &Path = &absolute;
    loop {
        if let Ok(canonical) = std::fs::canonicalize(probe) {
            let mut resolved = canonical;
            resolved.extend(missing.iter().rev());
            return resolved;
        }
        match (probe.parent(), probe.components().next_back()) {
            (Some(parent), Some(last)) => {
                missing.push(last);
                probe = parent;
            }
            _ => return absolute,
        }
    }
}

/// Makes a user-typed path absolute against this process's working
/// directory, without requiring it to exist or resolving symlinks.
pub fn absolute_path(raw: &str) -> Result<String, CoreError> {
    if raw.is_empty() {
        return Err(CoreError::InvalidInput("path must not be empty".into()));
    }
    let absolute = std::path::absolute(raw)
        .map_err(|e| CoreError::InvalidInput(format!("cannot resolve {raw}: {e}")))?;
    Ok(absolute.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_folder_spellings_all_resolve_to_the_canonical_path() {
        let dir = tempfile::tempdir().unwrap();
        let folder = std::fs::canonicalize(dir.path()).unwrap().join("Docs");
        std::fs::create_dir(&folder).unwrap();
        let canonical = std::fs::canonicalize(&folder).unwrap();

        let trailing = format!("{}/", folder.display());
        assert_eq!(resolve_link_path(&trailing), canonical);
        let dotted = format!("{}/./../Docs", folder.display());
        assert_eq!(resolve_link_path(&dotted), canonical);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_spelling_resolves_to_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(dir.path()).unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        assert_eq!(resolve_link_path(alias.to_str().unwrap()), real);
    }

    #[cfg(unix)]
    #[test]
    fn a_deleted_folder_resolves_through_its_symlinked_parent() {
        let dir = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(dir.path()).unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        let gone = format!("{}/gone/", alias.display());
        assert_eq!(resolve_link_path(&gone), real.join("gone"));
    }

    #[test]
    fn a_relative_spelling_of_a_missing_folder_becomes_absolute() {
        let resolved = resolve_link_path("definitely-missing-folder-xyz");
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("definitely-missing-folder-xyz"));
    }

    #[test]
    fn transfer_paths_are_made_absolute_against_the_clients_directory() {
        let resolved = absolute_path("notes.txt").unwrap();
        assert!(Path::new(&resolved).is_absolute());
        assert!(resolved.ends_with("notes.txt"));
        assert!(matches!(absolute_path(""), Err(CoreError::InvalidInput(_))));
        let already = if cfg!(windows) { r"C:\x\y.txt" } else { "/x/y.txt" };
        assert_eq!(absolute_path(already).unwrap(), already);
    }
}
