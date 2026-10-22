//! Where the Windows Cloud Files host put each provider root's sync root folder.
//!
//! A provider root has no directory the daemon reads, but the folder the user sees is a path
//! like any other, and a command that names a file in it (`yadorilink evict <path>`) has to be
//! turned into the root and the namespace path of that file. The host records every sync root
//! it serves as one `<root id hex>\t<folder path>` line in `cfapi_sync_roots.txt` in the
//! engine state directory, so a restarted host reconnects each root at the same place. The same
//! file answers this question, exactly, without re-deriving a folder name from a display name.

#![cfg_attr(not(windows), allow(dead_code))]

use std::path::PathBuf;

use yadorilink_fs_platform::generation;
use yadorilink_fs_platform::windows_name::windows_name_key as name_key;

/// The host's record of its sync roots: the base name of its generation files
/// (`cfapi_sync_roots.txt.<seq>`, see `yadorilink_fs_platform::generation`).
pub(crate) fn registry_file() -> Option<PathBuf> {
    yadorilink_fs_platform::state_dir::state_dir().ok().map(|dir| dir.join("cfapi_sync_roots.txt"))
}

/// Whether the host serves its sync roots from an older generation of the record because the
/// newest one is torn (the host takes the previous complete one; see
/// `yadorilink_windows_provider_policy::host::read_registry_at`). The lookup below stays closed
/// in that case. It clears when the host publishes its next generation.
pub(crate) fn registry_restored() -> bool {
    registry_file().is_some_and(|base| registry_restored_at(&base))
}

fn registry_restored_at(base: &std::path::Path) -> bool {
    matches!(
        generation::read_latest(base, |text| generation::unseal(text).map(str::to_string)),
        generation::Latest::Loaded { skipped_newer: true, .. }
    )
}

/// `(root id hex, path relative to the root with `/` separators)` of an absolute path inside one
/// of the host's sync roots. `None` when no root holds it, or when it names the root itself.
pub(crate) fn locate(absolute_path: &str) -> Option<(String, String)> {
    locate_at(&registry_file()?, absolute_path)
}

/// Reads the registry the way the host does: the newest complete generation. Anything that
/// leaves the record unproven (no generation, unreadable, none complete, or a newer generation
/// that is torn so the one read may predate a root) finds no root, never a guess.
fn locate_at(base: &std::path::Path, absolute_path: &str) -> Option<(String, String)> {
    match generation::read_latest(base, |text| generation::unseal(text).map(str::to_string)) {
        generation::Latest::Loaded { value, skipped_newer: false, .. } => {
            well_formed(&value).then(|| locate_in(&value, absolute_path)).flatten()
        }
        _ => None,
    }
}

/// The host's own rule for a registry it can trust (`cfapi_host::parse_registry`): every line is
/// a 32 lowercase hex root id and a path, and no root or folder is recorded twice. A record that
/// breaks it is not partly used: which root a path belongs to would be a guess.
fn well_formed(registry: &str) -> bool {
    let mut roots = std::collections::HashSet::new();
    let mut paths = std::collections::HashSet::new();
    registry.lines().all(|line| {
        let Some((root, path)) = line.split_once('\t') else { return false };
        root.len() == 32
            && root.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            && !path.trim().is_empty()
            && roots.insert(root)
            && paths.insert(components(path.trim()))
    })
}

fn components(path: &str) -> Vec<String> {
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    path.split(['\\', '/']).filter(|c| !c.is_empty()).map(name_key).collect()
}

fn components_keeping_case(path: &str) -> Vec<String> {
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    path.split(['\\', '/']).filter(|c| !c.is_empty()).map(str::to_string).collect()
}

pub(crate) fn locate_in(registry: &str, absolute_path: &str) -> Option<(String, String)> {
    let wanted = components(absolute_path);
    let original = components_keeping_case(absolute_path);
    let mut best: Option<(&str, usize)> = None;
    for line in registry.lines() {
        let Some((root_id, root_path)) = line.split_once('\t') else { continue };
        let root = components(root_path.trim());
        if root.is_empty() || root.len() >= wanted.len() || wanted[..root.len()] != root[..] {
            continue;
        }
        if best.is_none_or(|(_, depth)| root.len() > depth) {
            best = Some((root_id.trim(), root.len()));
        }
    }
    let (root_id, depth) = best?;
    Some((root_id.to_string(), original[depth..].join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REGISTRY_BODY: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tC:\\Users\\me\\YadoriLink\\Photos\n";
    const REGISTRY: &str = "aaaa\tC:\\Users\\me\\YadoriLink\\Photos\nbbbb\tC:\\Users\\me\\YadoriLink\\Photos (bbbb0001)\n\nbroken line\n";

    fn base(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("cfapi_sync_roots.txt")
    }

    #[test]
    fn a_registry_published_as_generation_files_is_located() {
        let dir = tempfile::tempdir().unwrap();
        generation::publish_next(&base(dir.path()), &generation::seal("zzzz\tD:\\old\n")).unwrap();
        generation::publish_next(&base(dir.path()), &generation::seal(REGISTRY_BODY)).unwrap();
        assert_eq!(
            locate_at(&base(dir.path()), r"C:\Users\me\YadoriLink\Photos\docs\a.txt"),
            Some((ID_A.into(), "docs/a.txt".into()))
        );
    }

    #[test]
    fn a_registry_the_host_would_refuse_is_not_partly_used() {
        let dir = tempfile::tempdir().unwrap();
        let p = r"C:\Users\me\YadoriLink\Photos\a.txt";
        let sigma = "C:\\Users\\me\\Photos\u{3c3}\\a.txt";
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        for body in [
            format!("{REGISTRY_BODY}broken line\n"),
            format!("{REGISTRY_BODY}{b}\tc:/users/me/yadorilink/photos/\n"),
            format!("{ID_A}\tC:\\Users\\me\\Photos\u{3c3}\n{b}\tC:\\Users\\me\\Photos\u{3a3}\n"),
            format!("{REGISTRY_BODY}{ID_A}\tC:\\other\n"),
            format!("{REGISTRY_BODY}ABCD\tC:\\other\n"),
        ] {
            let base = base(&tempfile::tempdir_in(dir.path()).unwrap().keep());
            generation::publish_next(&base, &generation::seal(&body)).unwrap();
            assert_eq!(locate_at(&base, p), None, "{body}");
            assert_eq!(locate_at(&base, sigma), None, "{body}");
        }
    }

    #[test]
    fn the_unsuffixed_file_and_a_missing_record_are_not_a_registry() {
        let dir = tempfile::tempdir().unwrap();
        let p = r"C:\Users\me\YadoriLink\Photos\a.txt";
        assert_eq!(locate_at(&base(dir.path()), p), None);
        std::fs::write(base(dir.path()), REGISTRY_BODY).unwrap();
        assert_eq!(locate_at(&base(dir.path()), p), None);
    }

    #[test]
    fn a_damaged_newest_generation_does_not_fall_back_to_an_older_one() {
        let dir = tempfile::tempdir().unwrap();
        let p = r"C:\Users\me\YadoriLink\Photos\a.txt";
        generation::publish_next(&base(dir.path()), &generation::seal(REGISTRY_BODY)).unwrap();
        std::fs::write(dir.path().join("cfapi_sync_roots.txt.2"), "aaaa\tC:\\torn").unwrap();
        assert_eq!(locate_at(&base(dir.path()), p), None);
    }

    #[test]
    fn a_registry_read_from_an_older_generation_is_reported_as_restored() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!registry_restored_at(&base(dir.path())), "no record");
        generation::publish_next(&base(dir.path()), &generation::seal(REGISTRY_BODY)).unwrap();
        assert!(!registry_restored_at(&base(dir.path())), "newest generation complete");
        std::fs::write(dir.path().join("cfapi_sync_roots.txt.2"), "aaaa\tC:\\torn").unwrap();
        assert!(registry_restored_at(&base(dir.path())), "newest generation torn");
        // The host's next publish is newer than the torn one: nothing is restored any more.
        generation::publish_next(&base(dir.path()), &generation::seal(REGISTRY_BODY)).unwrap();
        assert!(!registry_restored_at(&base(dir.path())));
        // Only torn generations and nothing complete: no registry to restore.
        let none = tempfile::tempdir().unwrap();
        std::fs::write(none.path().join("cfapi_sync_roots.txt.1"), "torn").unwrap();
        assert!(!registry_restored_at(&base(none.path())));
    }

    #[test]
    fn a_path_inside_a_sync_root_is_split_into_the_root_and_the_namespace_path() {
        assert_eq!(
            locate_in(REGISTRY, r"C:\Users\me\YadoriLink\Photos\docs\a.txt"),
            Some(("aaaa".into(), "docs/a.txt".into()))
        );
    }

    #[test]
    fn the_extended_length_prefix_and_letter_case_do_not_matter_but_the_namespace_path_keeps_its_case(
    ) {
        assert_eq!(
            locate_in(REGISTRY, r"\\?\c:\users\ME\yadorilink\photos\Docs\A.txt"),
            Some(("aaaa".into(), "Docs/A.txt".into()))
        );
    }

    #[test]
    fn a_sibling_folder_with_the_same_prefix_is_not_the_root() {
        assert_eq!(
            locate_in(REGISTRY, r"C:\Users\me\YadoriLink\Photos (bbbb0001)\x.txt"),
            Some(("bbbb".into(), "x.txt".into()))
        );
        assert_eq!(locate_in(REGISTRY, r"C:\Users\me\YadoriLink\PhotosX\x.txt"), None);
    }

    #[test]
    fn the_root_itself_and_unrelated_paths_are_not_items() {
        assert_eq!(locate_in(REGISTRY, r"C:\Users\me\YadoriLink\Photos"), None);
        assert_eq!(locate_in(REGISTRY, r"C:\Users\me\Documents\a.txt"), None);
    }
}
