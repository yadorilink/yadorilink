#![cfg(test)]

use super::*;

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// The "Non-empty folder warning" scenario: a folder with real content
/// is flagged risky and produces a specific warning.
#[test]
fn non_empty_folder_is_risky_with_a_warning() {
    let dir = tempdir();
    std::fs::write(dir.path().join("photo.jpg"), b"data").unwrap();
    let report = run_preflight(dir.path(), &[], Some(0));
    assert!(report.path_exists);
    assert_eq!(report.entry_count, 1);
    assert!(report.is_risky());
    assert!(report.warnings().iter().any(|w| w.contains("not empty")));
}

/// Fail-closed: an unreadable ignore file (here, invalid UTF-8 in
/// `.yadorilinkignore`) must be surfaced as a risky condition with its
/// own warning, not silently swallowed by falling back to defaults —
/// otherwise files the user meant to exclude could start syncing without
/// any indication at link time.
#[test]
fn unreadable_ignore_file_is_flagged_risky_with_a_warning() {
    let dir = tempdir();
    // Invalid UTF-8 makes `load_for_link_root` return an error rather than
    // `NotFound` (which would legitimately mean "no user patterns").
    std::fs::write(dir.path().join(".yadorilinkignore"), [0xff, 0xfe, 0xfd]).unwrap();

    let report = run_preflight(dir.path(), &[], Some(0));

    assert!(report.ignore_rules_unreadable);
    assert!(report.is_risky());
    assert!(
        report.warnings().iter().any(|w| w.contains("ignore rules could not be read")),
        "warnings: {:?}",
        report.warnings()
    );
}

/// An empty folder, with no other risk factors, is not risky.
#[test]
fn empty_folder_with_no_other_risk_is_not_risky() {
    let dir = tempdir();
    let report = run_preflight(dir.path(), &[], Some(0));
    assert!(report.is_empty_folder());
    assert!(!report.is_risky(), "warnings: {:?}", report.warnings());
}

/// Ignored-file summary: built-in-ignored entries (e.g.
/// `.DS_Store`) don't count toward "non-empty", but are reported
/// separately.
#[test]
fn ignored_entries_dont_count_as_non_empty_but_are_summarized() {
    let dir = tempdir();
    std::fs::write(dir.path().join(".DS_Store"), b"x").unwrap();
    let report = run_preflight(dir.path(), &[], Some(0));
    assert_eq!(report.entry_count, 0);
    assert_eq!(report.ignored_entry_count, 1);
    assert!(report.is_empty_folder());
    assert!(!report.is_risky());
}

/// A pre-existing file whose name collides with the reserved artefact
/// namespace must be reported BY PATH, not silently folded into the
/// ordinary ignored-file count where a user has no way to discover it
/// (design's `Blocked(ReservedNamespaceCollision)` requirement: a
/// collision must name the path). It still counts as ignored (it will
/// never sync either way), but `reserved_namespace_blocked_paths` and
/// the warning text are what let a user actually find and rename it
/// before linking.
#[test]
fn reserved_namespace_collision_is_named_not_only_counted_as_ignored() {
    let dir = tempdir();
    let artefact_name = yadorilink_fs_platform::reserved_namespace::artefact_component_name(
        yadorilink_fs_platform::reserved_namespace::ArtefactKind::Stage,
        "deadbeef",
    )
    .unwrap();
    std::fs::write(dir.path().join(&artefact_name), b"pre-existing content").unwrap();

    let report = run_preflight(dir.path(), &[], Some(0));
    assert_eq!(report.entry_count, 0, "must not count as ordinary syncable content");
    assert_eq!(report.ignored_entry_count, 1);
    assert_eq!(report.reserved_namespace_blocked_paths, vec![artefact_name.clone()]);
    assert!(report.is_risky());
    assert!(
        report.warnings().iter().any(|w| w.contains(&artefact_name)),
        "warnings must name the exact colliding path: {:?}",
        report.warnings()
    );
}

/// A folder that was linked before still carries the daemon's own top-level
/// files: the sync-root lock file (it outlives the lock it held) and the root
/// identity marker. Neither syncs, so both count as ignored -- but neither is
/// a collision the user created or should rename, so preflight must not warn
/// about them. It used to name the lock file on every re-link.
#[test]
fn the_daemons_own_root_lock_and_marker_are_ignored_not_reported_as_collisions() {
    let dir = tempdir();
    std::fs::write(
        dir.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME),
        b"",
    )
    .unwrap();
    std::fs::write(
        dir.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        b"marker",
    )
    .unwrap();

    let report = run_preflight(dir.path(), &[], Some(0));
    assert_eq!(report.entry_count, 0, "must not count as ordinary syncable content");
    assert_eq!(report.ignored_entry_count, 2);
    assert!(
        report.reserved_namespace_blocked_paths.is_empty(),
        "the daemon's own files are not collisions: {:?}",
        report.reserved_namespace_blocked_paths
    );
    assert!(!report.is_risky(), "warnings: {:?}", report.warnings());
}

/// Converse: a legacy-marker LOOK-ALIKE (not a genuine artefact — see
/// `reserved_namespace`'s "Two predicates, not one") is excluded the
/// same as an ordinary ignore-pattern match, but must NOT be reported
/// as a reserved-namespace collision — nothing about it collides with
/// a name the engine itself would ever construct, so calling it out as
/// one would be misleading about what the user needs to do.
#[test]
fn legacy_marker_look_alike_is_not_reported_as_a_reserved_namespace_collision() {
    let dir = tempdir();
    std::fs::write(dir.path().join("report.yadorilink-tmp.old"), b"my notes").unwrap();

    let report = run_preflight(dir.path(), &[], Some(0));
    assert_eq!(report.ignored_entry_count, 1);
    assert!(report.reserved_namespace_blocked_paths.is_empty());
}

/// The "Low disk space warning" scenario: constructed via a headroom
/// override large enough that any real test volume is "critical"
/// relative to it, deterministically (not dependent on actual free
/// space on the machine running the test).
#[test]
fn low_disk_space_is_risky_with_a_warning() {
    let dir = tempdir();
    let huge_headroom = u64::MAX / 2;
    let report = run_preflight(dir.path(), &[], Some(huge_headroom));
    assert_eq!(report.free_space_state(), Some(FreeSpaceState::Critical));
    assert!(report.is_risky());
    assert!(report.warnings().iter().any(|w| w.contains("low free space")));
}

/// Nested-link ancestor: linking a subfolder of an already-linked
/// folder.
#[test]
fn linking_a_subfolder_of_an_existing_link_is_an_ancestor_conflict() {
    let dir = tempdir();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let existing = vec![dir.path().to_string_lossy().to_string()];
    let report = run_preflight(&sub, &existing, Some(0));
    assert_eq!(report.nested_conflicts.len(), 1);
    assert_eq!(report.nested_conflicts[0].relation, NestedLinkRelation::Ancestor);
    // A structural prohibition, not a risk an acknowledgement can accept.
    assert!(!report.is_risky());
    assert_eq!(report.structural_prohibitions().len(), 1);
}

/// Nested-link descendant: linking a folder that already contains an
/// existing link.
#[test]
fn linking_a_parent_of_an_existing_link_is_a_descendant_conflict() {
    let dir = tempdir();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let existing = vec![sub.to_string_lossy().to_string()];
    let report = run_preflight(dir.path(), &existing, Some(0));
    assert_eq!(report.nested_conflicts.len(), 1);
    assert_eq!(report.nested_conflicts[0].relation, NestedLinkRelation::Descendant);
    // The folder is non-empty (it holds the linked one), so it is risky for
    // that reason alone; the nesting is a prohibition, never a warning.
    assert!(!report.warnings().iter().any(|w| w.contains("already linked")));
    assert_eq!(report.structural_prohibitions().len(), 1);
}

/// Re-linking the exact same path that's already linked.
#[test]
fn relinking_the_same_path_is_a_same_conflict() {
    let dir = tempdir();
    let existing = vec![dir.path().to_string_lossy().to_string()];
    let report = run_preflight(dir.path(), &existing, Some(0));
    assert_eq!(report.nested_conflicts.len(), 1);
    assert_eq!(report.nested_conflicts[0].relation, NestedLinkRelation::Same);
}

/// An unrelated existing link (sibling, not ancestor/descendant)
/// produces no conflict at all.
#[test]
fn sibling_links_are_not_conflicts() {
    let dir = tempdir();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    let existing = vec![a.to_string_lossy().to_string()];
    let report = run_preflight(&b, &existing, Some(0));
    assert!(report.nested_conflicts.is_empty());
    assert!(!report.is_risky());
}

/// The "Risky folder location" scenario: a well-known
/// cloud-provider-managed folder name anywhere in the path is flagged.
#[test]
fn cloud_provider_folder_is_flagged_risky() {
    let dir = tempdir();
    let dropbox = dir.path().join("Dropbox").join("Photos");
    std::fs::create_dir_all(&dropbox).unwrap();
    let report = run_preflight(&dropbox, &[], Some(0));
    assert_eq!(report.risky_location, Some(RiskyLocation::CloudProviderFolder("Dropbox")));
    assert!(report.is_risky());
    assert!(report.warnings().iter().any(|w| w.contains("Dropbox")));
}

/// A folder with no risk factors at all is not risky and has no
/// warnings.
#[test]
fn no_risk_factors_means_no_warnings() {
    let dir = tempdir();
    let report = run_preflight(dir.path(), &[], Some(0));
    assert!(report.warnings().is_empty());
}

/// A nonexistent path is itself reported as risky during the folder
/// existence check with a clear warning, rather than silently
/// reporting an empty folder.
#[test]
fn nonexistent_path_is_risky() {
    let dir = tempdir();
    let missing = dir.path().join("does-not-exist");
    let report = run_preflight(&missing, &[], None);
    assert!(!report.path_exists);
    assert!(report.is_risky());
    assert_eq!(report.warnings(), vec!["path does not exist".to_string()]);
}

/// A symlink spelling of an already-linked folder is the same folder.
#[cfg(unix)]
#[test]
fn a_symlink_spelling_of_a_linked_folder_is_a_conflict() {
    let dir = tempdir();
    let real = dir.path().join("real");
    std::fs::create_dir_all(real.join("inner")).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let existing = vec![(real.to_string_lossy().to_string(), "g1".to_string())];

    let same = detect_topology_conflicts(&alias, "g2", &existing);
    assert_eq!(same.len(), 1);
    assert_eq!(same[0].relation, NestedLinkRelation::Same);
    let inside = detect_topology_conflicts(&alias.join("inner"), "g2", &existing);
    assert_eq!(inside.len(), 1);
    assert_eq!(inside[0].relation, NestedLinkRelation::Ancestor);
}

/// The same folder linked again to the SAME group is an idempotent re-link,
/// not a conflict; to a different group it is.
#[test]
fn the_same_folder_conflicts_only_with_a_different_group() {
    let dir = tempdir();
    let path = dir.path().to_string_lossy().to_string();
    let existing = vec![(path, "g1".to_string())];
    assert!(detect_topology_conflicts(dir.path(), "g1", &existing).is_empty());
    assert_eq!(detect_topology_conflicts(dir.path(), "g2", &existing).len(), 1);
}

/// Where the platform's filesystems fold case, a differently-cased spelling
/// is the same folder, even for a folder that does not exist yet.
#[cfg(any(target_vendor = "apple", windows))]
#[test]
fn a_case_folded_spelling_is_the_same_folder() {
    let dir = tempdir();
    let existing = vec![(dir.path().join("Photos").to_string_lossy().to_string(), "g1".into())];
    let conflicts =
        detect_topology_conflicts(&dir.path().join("PHOTOS").join("raw"), "g2", &existing);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].relation, NestedLinkRelation::Ancestor);
}
