#![cfg(test)]

use super::{
    case_insensitivity_within, normalization_insensitivity_within, probe_in_named_dir,
    CASE_PROBE_LEAF_NAME, NORMALIZATION_PROBE_LEAF_NAME,
};
use std::ffi::OsStr;
use std::path::Path;
use yadorilink_fs_platform::reserved_namespace::{
    artefact_component_name, is_reserved_component, path_has_reserved_component, ArtefactKind,
};

/// Every name either probe puts on disk sits under a component the
/// engine's own exclusion predicate recognizes, so the watcher, the
/// initial scan and local change processing skip it without needing an
/// ignore rule. Asserted on the real minting function, not on a
/// hand-written literal: the property that matters is that what the
/// probe actually creates is excluded.
#[test]
fn the_probe_directory_name_is_a_reserved_component() {
    let name = yadorilink_fs_platform::fs_capabilities::probe_artefact_name("case").unwrap();
    assert!(
        is_reserved_component(OsStr::new(&name)),
        "{name:?} must be excluded from indexing by the reserved-namespace predicate"
    );
}

/// Both probes create a *second* spelling of their leaf name (an
/// all-uppercase variant; a decomposed variant) that they never create
/// themselves but do test for existence. Neither leaf spelling needs a
/// reserved name of its own: the exclusion predicate matches on any
/// component of a relative path, so the reserved parent directory covers
/// every leaf under it, in every spelling.
#[test]
fn every_leaf_spelling_either_probe_uses_is_excluded_under_its_reserved_parent() {
    let parent = yadorilink_fs_platform::fs_capabilities::probe_artefact_name("case").unwrap();
    let decomposed: String = {
        use unicode_normalization::UnicodeNormalization;
        NORMALIZATION_PROBE_LEAF_NAME.nfd().collect()
    };
    for leaf in [
        CASE_PROBE_LEAF_NAME.to_string(),
        CASE_PROBE_LEAF_NAME.to_uppercase(),
        NORMALIZATION_PROBE_LEAF_NAME.to_string(),
        decomposed,
    ] {
        let relative = Path::new(&parent).join(&leaf);
        assert!(
            path_has_reserved_component(&relative),
            "{relative:?} must be excluded from indexing"
        );
    }
}

/// The discipline this module's probes exist under: an entry at the
/// candidate probe name that this process did not create belongs to
/// someone else — possibly a user file — and must be neither removed nor
/// truncated. A collision is reported as `AlreadyExists` so the caller
/// can retry under a fresh name; the entry itself is left exactly as it
/// was found.
#[test]
fn a_pre_existing_entry_at_the_probe_name_is_neither_deleted_nor_truncated() {
    for probe in [
        &case_insensitivity_within as &dyn Fn(&Path) -> std::io::Result<bool>,
        &normalization_insensitivity_within,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let name = artefact_component_name(ArtefactKind::Probe, "collision").unwrap();
        let occupied = dir.path().join(&name);
        std::fs::write(&occupied, b"irreplaceable user content").unwrap();

        let outcome = probe_in_named_dir(dir.path(), &name, probe);

        // Asserted before the outcome itself: what must hold is that the
        // entry survived, whatever the probe decided to do or report.
        assert!(occupied.is_file(), "the pre-existing entry must not be deleted");
        assert_eq!(
            std::fs::read(&occupied).unwrap(),
            b"irreplaceable user content",
            "the pre-existing entry must not be truncated or overwritten"
        );

        let err = outcome.expect_err("a collision must not be resolved by taking the path over");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    }
}

/// The successful path's counterpart: a probe that ran to completion
/// removes the directory it created, and everything inside it.
#[test]
fn a_completed_probe_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let name = artefact_component_name(ArtefactKind::Probe, "cleanup").unwrap();
    probe_in_named_dir(dir.path(), &name, case_insensitivity_within).unwrap();
    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(entries.is_empty(), "the probe directory must be cleaned up: {entries:?}");
}

/// A probe whose inner work fails still owns the directory it created,
/// so it must still remove it — otherwise a failing volume accumulates
/// abandoned artefacts in the user's sync directory.
#[test]
fn a_failed_probe_still_removes_the_directory_it_created() {
    let dir = tempfile::tempdir().unwrap();
    let name = artefact_component_name(ArtefactKind::Probe, "failure").unwrap();
    let err = probe_in_named_dir(dir.path(), &name, |_probe_dir| {
        Err::<bool, _>(std::io::Error::other("probe failed halfway"))
    })
    .expect_err("the inner failure must propagate");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(entries.is_empty(), "the probe directory must be cleaned up: {entries:?}");
}
