#![cfg(test)]

use super::*;

fn ignored(set: &EffectiveIgnoreSet, path: &str, is_dir: bool) -> bool {
    set.is_ignored(Path::new(path), is_dir)
}

#[test]
fn comments_blank_lines_and_malformed_lines_are_ignored() {
    let set = EffectiveIgnoreSet::from_user_patterns("\n  # comment\n!\nfoo//bar\n.\nvalid.log\n");
    assert!(ignored(&set, "valid.log", false));
    assert!(!ignored(&set, "foo/bar", false));
}

#[test]
fn star_double_star_and_question_mark_match_relative_paths() {
    let set = EffectiveIgnoreSet::from_user_patterns("build/*.tmp\ncache/**/blob-?.bin\n");
    assert!(ignored(&set, "build/a.tmp", false));
    assert!(!ignored(&set, "build/nested/a.tmp", false));
    assert!(ignored(&set, "cache/a/b/blob-1.bin", false));
    assert!(ignored(&set, "cache/blob-x.bin", false));
    assert!(!ignored(&set, "cache/blob-long.bin", false));
}

#[test]
fn later_patterns_override_and_negation_reincludes() {
    let set = EffectiveIgnoreSet::from_user_patterns("*.log\n!important.log\nimportant.log\n");
    assert!(ignored(&set, "debug.log", false));
    assert!(ignored(&set, "important.log", false));

    let set = EffectiveIgnoreSet::from_user_patterns("*.log\n!important.log\n");
    assert!(!ignored(&set, "important.log", false));
    let matched = set.match_path("important.log", false).unwrap();
    assert_eq!(matched.pattern.original(), "!important.log");
    assert!(!matched.ignored);
}

#[test]
fn directory_only_patterns_match_directories_and_descendants() {
    let set = EffectiveIgnoreSet::from_user_patterns("node_modules/\n");
    assert!(ignored(&set, "node_modules", true));
    assert!(ignored(&set, "node_modules/pkg/index.js", false));
    assert!(ignored(&set, "app/node_modules/pkg/index.js", false));
    assert!(!ignored(&set, "node_modules.txt", false));
}

#[test]
fn built_in_defaults_are_always_active() {
    let set = EffectiveIgnoreSet::defaults_only();
    assert!(ignored(&set, ".DS_Store", false));
    assert!(ignored(&set, "nested/._resource", false));
    assert!(ignored(&set, "Thumbs.db", false));
    assert!(ignored(&set, "desktop.ini", false));
    assert!(ignored(&set, "swap.swp", false));
    assert!(ignored(&set, "backup~", false));
    assert!(ignored(&set, ".Spotlight-V100/store", false));
    assert!(ignored(&set, ".Trashes/501/file", false));
}

#[test]
fn loading_missing_ignore_file_falls_back_to_defaults_only() {
    let dir = tempfile::tempdir().unwrap();
    let set = EffectiveIgnoreSet::load_for_link_root(dir.path()).unwrap();
    assert_eq!(set.patterns().len(), BUILT_IN_DEFAULT_PATTERNS.len());
    assert!(ignored(&set, ".DS_Store", false));
}

#[test]
fn loading_ignore_file_merges_defaults_then_user_patterns() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(IGNORE_FILE_NAME), "*.log\n!.keep.log\n").unwrap();
    let set = EffectiveIgnoreSet::load_for_link_root(dir.path()).unwrap();
    assert_eq!(set.patterns().len(), BUILT_IN_DEFAULT_PATTERNS.len() + 2);
    assert!(ignored(&set, ".DS_Store", false));
    assert!(ignored(&set, "debug.log", false));
    assert!(!ignored(&set, ".keep.log", false));
}

#[test]
fn parent_or_absolute_paths_do_not_match() {
    let set = EffectiveIgnoreSet::from_user_patterns("*.log\n");
    assert!(!ignored(&set, "../debug.log", false));
    assert!(!ignored(&set, "/tmp/debug.log", false));
}

// -- include directives -----------------------------------------------

#[test]
fn include_directive_splices_patterns_at_the_directive_point() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("shared.yadorilinkignore"), "*.log\n!keep.log\n").unwrap();
    fs::write(dir.path().join(IGNORE_FILE_NAME), "#include shared.yadorilinkignore\nkeep.log\n")
        .unwrap();
    let set = EffectiveIgnoreSet::load_for_link_root(dir.path()).unwrap();
    // Document order: *.log, !keep.log (from the include), then the
    // top-level file's own `keep.log` re-ignores it again — proving
    // includes are spliced in place, not appended after the file.
    assert!(ignored(&set, "debug.log", false));
    assert!(ignored(&set, "keep.log", false));
}

#[test]
fn include_cycle_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(IGNORE_FILE_NAME), "#include a.ignore\n").unwrap();
    fs::write(dir.path().join("a.ignore"), "#include b.ignore\n").unwrap();
    fs::write(dir.path().join("b.ignore"), "#include a.ignore\n").unwrap();
    let err = EffectiveIgnoreSet::load_for_link_root_checked(dir.path()).unwrap_err();
    assert!(matches!(err, IgnoreConfigError::IncludeCycle(_)), "{err:?}");
}

#[test]
fn include_self_reference_is_rejected_as_a_cycle() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(IGNORE_FILE_NAME), format!("#include {IGNORE_FILE_NAME}\n")).unwrap();
    let err = EffectiveIgnoreSet::load_for_link_root_checked(dir.path()).unwrap_err();
    assert!(matches!(err, IgnoreConfigError::IncludeCycle(_)), "{err:?}");
}

#[test]
fn include_escaping_the_root_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(IGNORE_FILE_NAME), "#include ../outside.ignore\n").unwrap();
    let err = EffectiveIgnoreSet::load_for_link_root_checked(dir.path()).unwrap_err();
    assert!(matches!(err, IgnoreConfigError::IncludeEscapesRoot(_)), "{err:?}");

    let dir2 = tempfile::tempdir().unwrap();
    fs::write(dir2.path().join(IGNORE_FILE_NAME), "#include /etc/passwd\n").unwrap();
    let err2 = EffectiveIgnoreSet::load_for_link_root_checked(dir2.path()).unwrap_err();
    assert!(matches!(err2, IgnoreConfigError::IncludeEscapesRoot(_)), "{err2:?}");
}

#[test]
fn missing_include_target_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(IGNORE_FILE_NAME), "#include nope.ignore\n").unwrap();
    let err = EffectiveIgnoreSet::load_for_link_root_checked(dir.path()).unwrap_err();
    assert!(matches!(err, IgnoreConfigError::MissingInclude(_)), "{err:?}");
}

#[test]
fn non_utf8_ignore_file_is_reported_as_invalid_encoding() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(IGNORE_FILE_NAME), [0x2a, 0xff, 0xfe, 0x0a]).unwrap();
    let err = EffectiveIgnoreSet::load_for_link_root_checked(dir.path()).unwrap_err();
    assert!(matches!(err, IgnoreConfigError::InvalidEncoding(_)), "{err:?}");
}

#[test]
fn a_line_that_merely_starts_with_include_is_not_misparsed_as_a_directive() {
    let set = EffectiveIgnoreSet::from_user_patterns("#includes an explanation\n*.log\n");
    assert!(ignored(&set, "debug.log", false));
}

#[test]
fn case_insensitive_marker_matches_regardless_of_case() {
    let set = EffectiveIgnoreSet::from_user_patterns("(?i)*.LOG\n");
    assert!(ignored(&set, "debug.log", false));
    assert!(ignored(&set, "DEBUG.LOG", false));
    assert!(ignored(&set, "Debug.Log", false));
}

#[test]
fn without_the_marker_matching_stays_case_sensitive() {
    let set = EffectiveIgnoreSet::from_user_patterns("*.LOG\n");
    assert!(ignored(&set, "debug.LOG", false));
    assert!(!ignored(&set, "debug.log", false));
}

#[test]
fn reload_falls_back_to_previous_set_on_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(IGNORE_FILE_NAME), "*.log\n").unwrap();
    let good = EffectiveIgnoreSet::load_for_link_root(dir.path()).unwrap();
    assert!(ignored(&good, "debug.log", false));

    fs::write(dir.path().join(IGNORE_FILE_NAME), "#include missing.ignore\n").unwrap();
    let (reloaded, err) = EffectiveIgnoreSet::reload_for_link_root(dir.path(), &good);
    assert!(matches!(err, Some(IgnoreConfigError::MissingInclude(_))));
    // Still the last-known-good set, not defaults-only or an error
    // that silences ignore matching entirely.
    assert!(ignored(&reloaded, "debug.log", false));
}

#[test]
fn explain_path_reports_matched_rule_source_and_line() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("included.ignore"), "# comment\n*.log\n").unwrap();
    fs::write(dir.path().join(IGNORE_FILE_NAME), "#include included.ignore\n").unwrap();
    let set = EffectiveIgnoreSet::load_for_link_root(dir.path()).unwrap();

    let explanation = set.explain_path("debug.log", false).unwrap();
    assert!(explanation.matched);
    assert!(explanation.ignored);
    assert_eq!(explanation.rule_text, "*.log");
    assert_eq!(explanation.source, IgnorePatternSource::User);
    assert_eq!(explanation.source_file, "included.ignore");
    assert_eq!(explanation.include_chain, vec![IGNORE_FILE_NAME.to_string()]);
    assert_eq!(explanation.line, 2);
    assert!(!explanation.case_insensitive);
}

#[test]
fn explain_path_reports_no_match_distinctly_from_a_negated_match() {
    let set = EffectiveIgnoreSet::from_user_patterns("*.log\n!keep.log\n");

    let no_match = set.explain_path("notes.md", false).unwrap();
    assert!(!no_match.matched);
    assert!(!no_match.ignored);

    let negated = set.explain_path("keep.log", false).unwrap();
    assert!(negated.matched);
    assert!(!negated.ignored);
    assert_eq!(negated.rule_text, "!keep.log");
    assert_eq!(negated.line, 2);
}

#[test]
fn explain_path_reports_built_in_source_for_default_patterns() {
    let set = EffectiveIgnoreSet::defaults_only();
    let explanation = set.explain_path(".DS_Store", false).unwrap();
    assert!(explanation.ignored);
    assert_eq!(explanation.source, IgnorePatternSource::BuiltIn);
    assert_eq!(explanation.source_file, BUILT_IN_SOURCE_LABEL);
    assert!(explanation.include_chain.is_empty());
}
