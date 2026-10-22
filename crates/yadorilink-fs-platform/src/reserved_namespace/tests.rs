#![cfg(test)]

use super::*;

#[test]
fn builds_and_parses_each_kind_round_trip() {
    for kind in ArtefactKind::ALL {
        let name = artefact_component_name(kind, "abc123").unwrap();
        let (parsed_kind, id) = parse_artefact_component(&name).unwrap();
        assert_eq!(parsed_kind, kind);
        assert_eq!(id, "abc123");
    }
}

#[test]
fn recognizes_each_kind_as_reserved() {
    for kind in ArtefactKind::ALL {
        let name = artefact_component_name(kind, "id").unwrap();
        assert!(is_reserved_component(OsStr::new(&name)), "{name} should be reserved");
        assert_eq!(
            classify_component(OsStr::new(&name)),
            Some(ReservedComponent::Artefact { kind, id: "id" })
        );
    }
}

#[test]
fn case_folded_ascii_only() {
    assert!(is_reserved_component(OsStr::new(".YADORILINK-V1-STAGE.x")));
    assert!(is_reserved_component(OsStr::new(".Yadorilink-V1-Preimage.42")));
    let (kind, id) = parse_artefact_component(".YADORILINK-V1-BACKUP.id7").unwrap();
    assert_eq!(kind, ArtefactKind::Backup);
    assert_eq!(id, "id7");
}

#[test]
fn whole_component_matching_not_substring() {
    // A user file that merely contains the marker text is not reserved —
    // only a component that *is* the artefact name.
    assert!(!is_reserved_component(OsStr::new("notes.yadorilink-v1-stage.x.txt")));
    assert!(!is_reserved_component(OsStr::new("prefix.yadorilink-v1-stage.x")));
    assert!(!is_reserved_component(OsStr::new(".yadorilink-v1-stage.x.suffix")));
}

/// Windows drops trailing `.`/` ` in most Win32 path APIs, so a peer
/// that spells the reserved name with one trailing dot or space types
/// a name that is not literally the reserved name but lands on disk,
/// on a Windows device, as exactly the reserved name. The predicate
/// must catch it regardless of which platform is running the check.
#[test]
fn trailing_dot_or_space_still_classifies_as_the_artefact() {
    let base = artefact_component_name(ArtefactKind::Stage, "abc").unwrap();

    let trailing_space = format!("{base} ");
    assert!(is_artefact_component(OsStr::new(&trailing_space)));
    assert_eq!(
        classify_component(OsStr::new(&trailing_space)),
        Some(ReservedComponent::Artefact { kind: ArtefactKind::Stage, id: "abc" })
    );

    let trailing_dot = format!("{base}.");
    assert!(is_artefact_component(OsStr::new(&trailing_dot)));
    assert_eq!(
        classify_component(OsStr::new(&trailing_dot)),
        Some(ReservedComponent::Artefact { kind: ArtefactKind::Stage, id: "abc" })
    );

    // Multiple trailing dots/spaces, and a mix of both, still strip down
    // to the reserved name.
    let trailing_mix = format!("{base}. . ");
    assert!(is_artefact_component(OsStr::new(&trailing_mix)));

    // A LEADING dot/space is not Windows trailing normalization and
    // must not be stripped — this is not the same bug in reverse.
    let leading_space = format!(" {base}");
    assert!(!is_artefact_component(OsStr::new(&leading_space)));
}

#[test]
fn unknown_kind_token_is_not_reserved() {
    assert!(!is_reserved_component(OsStr::new(".yadorilink-v1-bogus.x")));
    // No id at all is not a valid artefact name.
    assert!(!is_reserved_component(OsStr::new(".yadorilink-v1-stage.")));
    assert!(!is_reserved_component(OsStr::new(".yadorilink-v1-stage")));
}

#[test]
fn nested_component_makes_whole_path_reserved() {
    let path = Path::new("a/b/.yadorilink-v1-preimage.deadbeef/c.txt");
    assert!(path_has_reserved_component(path));
    assert!(!path_has_reserved_component(Path::new("a/b/c.txt")));
}

#[test]
fn length_bound_is_an_error_not_a_truncation() {
    let long_id = "x".repeat(MAX_COMPONENT_BYTES);
    match artefact_component_name(ArtefactKind::Stage, &long_id) {
        Err(ArtefactNameError::TooLong { id, actual_bytes }) => {
            assert_eq!(id, long_id);
            assert!(actual_bytes > MAX_COMPONENT_BYTES);
        }
        other => panic!("expected TooLong, got {other:?}"),
    }

    let short_id = "x".repeat(4);
    assert!(artefact_component_name(ArtefactKind::Stage, &short_id).is_ok());
}

#[test]
fn id_alphabet_is_restricted_so_reparsing_is_unambiguous() {
    assert!(matches!(
        artefact_component_name(ArtefactKind::Stage, "has.dot"),
        Err(ArtefactNameError::InvalidId { .. })
    ));
    assert!(matches!(
        artefact_component_name(ArtefactKind::Stage, "has/slash"),
        Err(ArtefactNameError::InvalidId { .. })
    ));
    assert!(matches!(
        artefact_component_name(ArtefactKind::Stage, ""),
        Err(ArtefactNameError::InvalidId { .. })
    ));
    assert!(artefact_component_name(ArtefactKind::Stage, "abc-123_XYZ").is_ok());
}

#[test]
fn legacy_marker_is_reserved_but_distinguishable() {
    let legacy_name = "report.yadorilink-tmp.12345.7";
    assert!(is_reserved_component(OsStr::new(legacy_name)));
    assert_eq!(classify_component(OsStr::new(legacy_name)), Some(ReservedComponent::Legacy));

    // Case-folded too.
    assert!(is_reserved_component(OsStr::new("REPORT.YADORILINK-TMP.12345.7")));

    // Never confused with a versioned artefact.
    let v1_name = artefact_component_name(ArtefactKind::Backup, "id").unwrap();
    assert_ne!(classify_component(OsStr::new(&v1_name)), Some(ReservedComponent::Legacy));
}

#[test]
fn path_level_finds_the_specific_component() {
    let path = Path::new("dir/report.yadorilink-tmp.1.2/leaf.txt");
    assert_eq!(find_reserved_component(path), Some(ReservedComponent::Legacy));
}

/// The rejection predicate (`is_artefact_component`/
/// `path_has_artefact_component`) must be `false` for a legacy-marked
/// path even though the exclusion predicate
/// (`is_reserved_component`/`path_has_reserved_component`) is `true`
/// for the same path — see the module doc's "Two predicates, not one"
/// section. This is what lets native admission and peer materialization
/// (which must key on the rejection predicate) leave a legacy-marked
/// path alone, while the watcher/scan/import (which key on exclusion)
/// still keep it out of ordinary sync. Mutation-checked: this fails if
/// either call site is pointed back at `path_has_reserved_component`.
#[test]
fn artefact_predicate_excludes_the_legacy_marker() {
    let legacy_name = "report.yadorilink-tmp.12345.7";
    assert!(!is_artefact_component(OsStr::new(legacy_name)));
    assert!(is_reserved_component(OsStr::new(legacy_name)));

    let legacy_path = Path::new("dir/report.yadorilink-tmp.1.2/leaf.txt");
    assert!(!path_has_artefact_component(legacy_path));
    assert!(path_has_reserved_component(legacy_path));

    // A versioned artefact is caught by both.
    let v1_name = artefact_component_name(ArtefactKind::Stage, "id").unwrap();
    assert!(is_artefact_component(OsStr::new(&v1_name)));
    assert!(is_reserved_component(OsStr::new(&v1_name)));
}

/// NTFS `filename::$DATA` addresses `filename`'s own default stream —
/// the same on-disk object — and `filename:stream:$DATA` addresses a
/// named stream on it; both mutate `filename` itself. Neither is
/// component-exact against the un-suffixed reserved name, so the wire
/// predicate must strip the ADS suffix before matching, or a peer can
/// alias the artefact without ever spelling its exact name.
#[test]
fn wire_predicate_strips_an_alternate_data_stream_suffix() {
    let base = artefact_component_name(ArtefactKind::Stage, "deadbeef").unwrap();

    let default_stream = format!("{base}::$DATA");
    assert!(is_artefact_wire_component(&default_stream));
    assert!(path_has_artefact_component_in_wire_path(&default_stream));

    let named_stream = format!("{base}:payload:$DATA");
    assert!(is_artefact_wire_component(&named_stream));
    assert!(path_has_artefact_component_in_wire_path(&format!("some/dir/{named_stream}")));

    // The un-suffixed name is unaffected.
    assert!(is_artefact_wire_component(&base));
}

/// `change::validate_path` accepts both `/` and `\` as separators, so
/// component boundaries in a wire path must not depend on which OS is
/// running the check — using the host `Path` type here would make
/// `safe\.yadorilink-v1-stage.x` one component on Unix (admitted) and
/// two on Windows (rejected), splitting the group along platform
/// lines. The wire predicate must reject it on every host.
#[test]
fn wire_predicate_splits_on_both_separators_regardless_of_host() {
    let artefact = artefact_component_name(ArtefactKind::Preimage, "cafef00d").unwrap();

    let backslash_path = format!("safe\\{artefact}");
    assert!(
        path_has_artefact_component_in_wire_path(&backslash_path),
        "a backslash-delimited artefact component must be found on every host"
    );

    let forward_slash_path = format!("safe/{artefact}");
    assert!(path_has_artefact_component_in_wire_path(&forward_slash_path));

    // An ORDINARY backslash-containing path (no reserved component at
    // all) must classify identically regardless of host: not reserved
    // either way. This is the direct converse of the split-brain bug —
    // proving the predicate doesn't just reject everything with a
    // backslash in it.
    assert!(!path_has_artefact_component_in_wire_path("safe\\ordinary-file.txt"));
    assert!(!path_has_artefact_component_in_wire_path("safe/ordinary-file.txt"));
}

/// Converse of both wire tests above: the ADS-suffix and
/// separator-splitting normalization must not widen the narrow
/// artefact predicate into the broad exclusion predicate. A
/// legacy-marker look-alike with either suffix, or split across a
/// backslash, is still just a substring match and must not be
/// reachable through the wire artefact predicate.
#[test]
fn wire_predicate_still_excludes_the_legacy_marker_with_ads_and_backslash_suffixes() {
    assert!(!is_artefact_wire_component("report.yadorilink-tmp.old::$DATA"));
    assert!(!path_has_artefact_component_in_wire_path("safe\\report.yadorilink-tmp.old"));
}

/// Same property as the test above, for the trailing-dot/space
/// normalization instead of the ADS/backslash forms: it must not widen
/// the narrow artefact predicate into the broad exclusion predicate
/// either. A legacy-marker look-alike with a trailing space is still
/// just a substring match and must not be reachable through the wire
/// artefact predicate.
///
/// Pinned directly against the artefact predicate, not through
/// `dag_store::admit_change` or `PeerSyncSession::materialize`: at
/// those entry points, `path_has_non_portable_wire_component`
/// unconditionally refuses any trailing-dot/space path before the
/// artefact-vs-legacy classification is ever reached (see
/// `dag_store::tests::admit_change_rejects_a_non_portable_path_even_when_it_also_looks_like_a_legacy_marker`
/// and its `peer_session` sibling), so this specific combination can no
/// longer be exercised through the full pipeline — the artefact
/// predicate's own narrower contract still holds independently of that,
/// and is what this test pins.
#[test]
fn wire_predicate_still_excludes_the_legacy_marker_with_a_trailing_space() {
    assert!(!is_artefact_wire_component("report.yadorilink-tmp.old "));
}

#[test]
fn non_portable_predicate_catches_trailing_dot_or_space() {
    assert!(path_has_non_portable_wire_component("a "));
    assert!(path_has_non_portable_wire_component("a."));
    assert!(path_has_non_portable_wire_component("dir. /leaf"));
    assert!(!path_has_non_portable_wire_component("ordinary/path.txt"));
}

#[test]
fn non_portable_predicate_catches_a_literal_colon_anywhere_in_a_component() {
    assert!(path_has_non_portable_wire_component("notes:draft"));
    assert!(path_has_non_portable_wire_component("notes::$DATA"));
    assert!(path_has_non_portable_wire_component("dir/notes:draft"));
    assert!(!path_has_non_portable_wire_component("ordinary/path.txt"));
}

#[test]
fn non_portable_predicate_catches_reserved_windows_device_names() {
    for name in [
        "CON", "con", "PRN", "AUX", "NUL", "COM1", "com9", "LPT1", "lpt9", "CONIN$", "conin$",
        "CONOUT$", "conout$",
    ] {
        assert!(path_has_non_portable_wire_component(name), "{name} should be non-portable");
        assert!(
            path_has_non_portable_wire_component(&format!("{name}.txt")),
            "{name}.txt should be non-portable (matched by stem, not whole name)"
        );
    }
    // The reserved name must match the whole stem, not merely appear
    // within it — "CONTACT" is not "CON", and "economics.txt"'s stem
    // is not "COM9".
    assert!(!path_has_non_portable_wire_component("CONTACT.txt"));
    assert!(!path_has_non_portable_wire_component("economics.txt"));
}

#[test]
fn non_portable_predicate_catches_win32_reserved_filename_characters() {
    for ch in ['<', '>', '"', '|', '?', '*'] {
        let path = format!("notes{ch}draft.txt");
        assert!(path_has_non_portable_wire_component(&path), "{path:?} should be non-portable");
    }
    assert!(!path_has_non_portable_wire_component("ordinary/path.txt"));
}

/// Win32 only strips a *trailing* dot or space — a leading or interior
/// one round-trips exactly and must not be swept up by an overly broad
/// "no spaces/dots" rule (that would make ordinary, working Unix
/// filenames unsyncable for no reason).
#[test]
fn non_portable_predicate_leaves_leading_and_interior_whitespace_and_dots_alone() {
    assert!(!path_has_non_portable_wire_component(" leading-space.txt"));
    assert!(!path_has_non_portable_wire_component("two  spaces.txt"));
    assert!(!path_has_non_portable_wire_component("v1.2.3.txt"));
    assert!(!path_has_non_portable_wire_component(".hidden-dotfile"));
}

#[test]
fn non_portable_predicate_catches_superscript_reserved_device_names() {
    for name in
        ["COM\u{00B9}", "COM\u{00B2}", "COM\u{00B3}", "LPT\u{00B9}", "LPT\u{00B2}", "LPT\u{00B3}"]
    {
        assert!(path_has_non_portable_wire_component(name), "{name} should be non-portable");
        assert!(
            path_has_non_portable_wire_component(&format!("{name}.txt")),
            "{name}.txt should be non-portable (matched by stem)"
        );
    }
    // A superscript digit not among the reserved three, or trailing
    // rather than replacing an ASCII digit, is not a reserved spelling.
    assert!(!path_has_non_portable_wire_component("COM\u{2074}")); // superscript 4
    assert!(!path_has_non_portable_wire_component("COM1\u{00B9}"));
}

#[test]
fn non_portable_predicate_catches_ascii_control_characters() {
    assert!(path_has_non_portable_wire_component("notes\u{0001}draft.txt"));
    assert!(path_has_non_portable_wire_component("notes\u{001f}draft.txt"));
    assert!(path_has_non_portable_wire_component("notes\tdraft.txt")); // U+0009, TAB
    assert!(!path_has_non_portable_wire_component("ordinary/path.txt"));
}

/// A Windows volume with 8.3 short-name generation enabled mints an
/// automatic alias, shaped `NAME~N` or `NAME~N.EXT`, for any long
/// filename it materializes. A separate peer-authored path spelled in
/// exactly that shape can then resolve to the same on-disk object as
/// the long name once it materializes — refusing the shape outright,
/// rather than trying to compute the specific alias (see
/// [`wire_component_is_non_portable`]'s doc comment for why the actual
/// algorithm can't be evaluated host-independently), is what closes
/// that gap.
#[test]
fn non_portable_predicate_catches_short_name_alias_shape() {
    assert!(path_has_non_portable_wire_component("REPORT~1.TXT"));
    assert!(path_has_non_portable_wire_component("report~1.txt"));
    assert!(path_has_non_portable_wire_component("REPORT~1"));
    // Prefix shrinks to keep the 8-character basename bound as the
    // numeric tail grows past a single digit.
    assert!(path_has_non_portable_wire_component("TEXTF~10.TXT"));
    assert!(path_has_non_portable_wire_component("dir/REPORT~1.TXT"));
}

/// The over-rejection direction: an ordinary filename that merely
/// contains a tilde, or a tilde-digit run too long to be a real 8.3
/// alias, must not be refused.
#[test]
fn non_portable_predicate_leaves_ordinary_tilde_names_alone() {
    // Not digits after the tilde.
    assert!(!path_has_non_portable_wire_component("my~notes.txt"));
    // Digits after the tilde, but the basename exceeds the 8-character
    // 8.3 bound, so it can never be a generated alias.
    assert!(!path_has_non_portable_wire_component("backup~2020.txt"));
    // A leading tilde has no prefix for the alias to have been
    // generated from.
    assert!(!path_has_non_portable_wire_component("~1.txt"));
    // More than one dot is not the single-extension 8.3 shape.
    assert!(!path_has_non_portable_wire_component("v~1.2.3.txt"));
    // An extension longer than three characters is not 8.3-shaped.
    assert!(!path_has_non_portable_wire_component("REPORT~1.TEXT"));
}

/// Mirrors `root_identity::only_the_top_level_marker_is_recognized`: a
/// same-named file nested in a subdirectory is ordinary user content and
/// must keep syncing, only the root-level lock file is this module's.
#[test]
fn only_the_top_level_lock_file_is_recognized() {
    assert!(is_sync_root_lock_relative_path(".yadorilink-root.lock"));
    assert!(is_sync_root_lock_relative_path("./.yadorilink-root.lock"));
    assert!(!is_sync_root_lock_relative_path("nested/.yadorilink-root.lock"));
    assert!(!is_sync_root_lock_relative_path(".yadorilink-root.lock/inner.txt"));
    assert!(!is_sync_root_lock_relative_path("notes.txt"));
}

#[test]
fn parsing_a_non_ascii_name_never_panics() {
    for name in [
        "",
        ".",
        "日本語",
        ".yadorilink-v1-日本語.x",
        ".yadorilink-v1-s日.x",
        "é.yadorilink",
        "\u{1F600}",
    ] {
        let _ = parse_artefact_component(name);
    }
}
