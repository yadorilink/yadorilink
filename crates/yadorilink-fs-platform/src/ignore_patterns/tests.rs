#![cfg(test)]

use super::*;

fn ignored(set: &EffectiveIgnoreSet, path: &str, is_dir: bool) -> bool {
    set.is_ignored(Path::new(path), is_dir)
}

#[test]
fn comments_and_blank_lines_are_skipped() {
    let set = EffectiveIgnoreSet::from_text("\n  # comment\nvalid.log\n").unwrap();
    assert!(ignored(&set, "valid.log", false));
}

/// A line the parser cannot use is an error naming it, never silently dropped.
#[test]
fn an_unusable_line_is_an_error_that_names_the_line() {
    for (text, line) in [
        ("a.log\n!\n", 2),
        ("foo//bar\n", 1),
        ("# c\n\n.\n", 3),
        ("(?i)\n", 1),
        ("ok\n../escape\n", 2),
        ("/\n", 1),
    ] {
        let err = EffectiveIgnoreSet::from_text(text).unwrap_err();
        assert!(
            matches!(&err, IgnoreConfigError::InvalidLine { line: l, .. } if *l == line),
            "{text:?}: {err:?}"
        );
        assert!(err.to_string().starts_with(&format!("line {line}:")), "{err}");
    }
}

#[test]
fn star_double_star_and_question_mark_match_relative_paths() {
    let set = EffectiveIgnoreSet::from_text("build/*.tmp\ncache/**/blob-?.bin\n").unwrap();
    assert!(ignored(&set, "build/a.tmp", false));
    assert!(!ignored(&set, "build/nested/a.tmp", false));
    assert!(ignored(&set, "cache/a/b/blob-1.bin", false));
    assert!(ignored(&set, "cache/blob-x.bin", false));
    assert!(!ignored(&set, "cache/blob-long.bin", false));
}

#[test]
fn later_patterns_override_and_negation_reincludes() {
    let set = EffectiveIgnoreSet::from_text("*.log\n!important.log\nimportant.log\n").unwrap();
    assert!(ignored(&set, "debug.log", false));
    assert!(ignored(&set, "important.log", false));

    let set = EffectiveIgnoreSet::from_text("*.log\n!important.log\n").unwrap();
    assert!(!ignored(&set, "important.log", false));
    let matched = set.match_path("important.log", false).unwrap();
    assert_eq!(matched.pattern.original(), "!important.log");
    assert!(!matched.ignored);
}

#[test]
fn directory_only_patterns_match_directories_and_descendants() {
    let set = EffectiveIgnoreSet::from_text("node_modules/\n").unwrap();
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
fn loading_a_missing_rules_file_falls_back_to_defaults_only() {
    let dir = tempfile::tempdir().unwrap();
    let set = EffectiveIgnoreSet::load_file(dir.path().join("none")).unwrap();
    assert_eq!(set.patterns().len(), BUILT_IN_DEFAULT_PATTERNS.len());
    assert!(ignored(&set, ".DS_Store", false));
}

#[test]
fn loading_a_rules_file_merges_defaults_then_user_patterns() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rules");
    fs::write(&file, "*.log\n!.keep.log\n").unwrap();
    let set = EffectiveIgnoreSet::load_file(&file).unwrap();
    assert_eq!(set.patterns().len(), BUILT_IN_DEFAULT_PATTERNS.len() + 2);
    assert!(ignored(&set, ".DS_Store", false));
    assert!(ignored(&set, "debug.log", false));
    assert!(!ignored(&set, ".keep.log", false));
}

#[test]
fn a_rules_file_that_is_not_utf8_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rules");
    fs::write(&file, [0x2a, 0xff, 0xfe, 0x0a]).unwrap();
    assert!(matches!(EffectiveIgnoreSet::load_file(&file), Err(IgnoreConfigError::Io(_))));
}

#[test]
fn parent_or_absolute_paths_do_not_match() {
    let set = EffectiveIgnoreSet::from_text("*.log\n").unwrap();
    assert!(!ignored(&set, "../debug.log", false));
    assert!(!ignored(&set, "/tmp/debug.log", false));
}

#[test]
fn case_insensitive_marker_matches_regardless_of_case() {
    let set = EffectiveIgnoreSet::from_text("(?i)*.LOG\n").unwrap();
    assert!(ignored(&set, "debug.log", false));
    assert!(ignored(&set, "DEBUG.LOG", false));
    assert!(ignored(&set, "Debug.Log", false));
}

#[test]
fn without_the_marker_matching_stays_case_sensitive() {
    let set = EffectiveIgnoreSet::from_text("*.LOG\n").unwrap();
    assert!(ignored(&set, "debug.LOG", false));
    assert!(!ignored(&set, "debug.log", false));
}

#[test]
fn reload_falls_back_to_previous_set_on_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rules");
    fs::write(&file, "*.log\n").unwrap();
    let good = EffectiveIgnoreSet::load_file(&file).unwrap();
    assert!(ignored(&good, "debug.log", false));

    fs::write(&file, "*.log\na//b\n").unwrap();
    let (reloaded, err) = EffectiveIgnoreSet::reload_file(&file, &good);
    assert!(matches!(err, Some(IgnoreConfigError::InvalidLine { line: 2, .. })));
    // Still the last-known-good set, not defaults-only or an error
    // that silences ignore matching entirely.
    assert!(ignored(&reloaded, "debug.log", false));
}

#[test]
fn explain_path_reports_the_matched_rule_and_line() {
    let set = EffectiveIgnoreSet::from_text("# comment\n*.log\n").unwrap();

    let explanation = set.explain_path("debug.log", false).unwrap();
    assert!(explanation.matched);
    assert!(explanation.ignored);
    assert_eq!(explanation.rule_text, "*.log");
    assert_eq!(explanation.source, IgnorePatternSource::User);
    assert_eq!(explanation.line, 2);
    assert!(!explanation.case_insensitive);
}

#[test]
fn explain_path_reports_no_match_distinctly_from_a_negated_match() {
    let set = EffectiveIgnoreSet::from_text("*.log\n!keep.log\n").unwrap();

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
}

mod store {
    use super::*;

    #[test]
    fn rules_round_trip_through_the_store_and_a_group_with_none_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = IgnoreRulesStore::new(dir.path());
        assert_eq!(store.read("g1").unwrap(), "");
        store.write("g1", "*.tmp\n").unwrap();
        store.write("g2", "*.log\n").unwrap();
        assert_eq!(store.read("g1").unwrap(), "*.tmp\n");
        assert!(ignored(&store.load("g1").unwrap(), "a.tmp", false));
        assert!(!ignored(&store.load("g1").unwrap(), "a.log", false));
        // Replacing is wholesale.
        store.write("g1", "").unwrap();
        assert_eq!(store.read("g1").unwrap(), "");
    }

    #[test]
    fn invalid_text_is_refused_with_its_line_and_the_stored_rules_stay() {
        let dir = tempfile::tempdir().unwrap();
        let store = IgnoreRulesStore::new(dir.path());
        store.write("g", "keep.me\n").unwrap();
        let err = store.write("g", "ok\nbad//line\n").unwrap_err();
        assert!(matches!(err, IgnoreConfigError::InvalidLine { line: 2, .. }), "{err:?}");
        assert_eq!(store.read("g").unwrap(), "keep.me\n");
    }

    #[test]
    fn a_group_id_cannot_name_another_directory() {
        let dir = tempfile::tempdir().unwrap();
        let store = IgnoreRulesStore::new(dir.path());
        let path = store.path("../../escape");
        assert_eq!(path.parent().unwrap(), dir.path().join("ignore"));
    }
}
