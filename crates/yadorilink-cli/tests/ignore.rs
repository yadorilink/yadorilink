use yadorilink_cli::commands::ignore::{explain_path_output, pattern_lines, test_path_output};
use yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet;

#[test]
fn ignore_list_includes_defaults_and_user_patterns_in_order() {
    let set = EffectiveIgnoreSet::from_text("node_modules/\n!important.log\n").unwrap();

    let lines = pattern_lines(&set);

    assert_eq!(lines.first().map(String::as_str), Some("builtin\t.DS_Store"));
    assert!(lines.iter().any(|line| line == "builtin\tThumbs.db"));
    assert_eq!(
        &lines[lines.len() - 2..],
        ["user\tnode_modules/".to_string(), "user\t!important.log".to_string()]
    );
}

#[test]
fn ignore_test_reports_matching_pattern_or_explicit_no_match() {
    let set = EffectiveIgnoreSet::from_text("*.tmp\n!keep.tmp\n").unwrap();

    assert_eq!(
        test_path_output(&set, None, "scratch.tmp"),
        "ignored: scratch.tmp (matched user pattern `*.tmp`)"
    );
    assert_eq!(
        test_path_output(&set, None, "keep.tmp"),
        "not ignored: keep.tmp (matched user pattern `!keep.tmp`)"
    );
    assert_eq!(
        test_path_output(&set, None, "notes.md"),
        "not ignored: notes.md (no matching pattern)"
    );
}

/// `ignore explain` reports the winning rule's line number, distinct from `test`'s plainer
/// "matched user pattern" wording.
#[test]
fn ignore_explain_reports_the_line_number() {
    let set = EffectiveIgnoreSet::from_text("# comment\n*.tmp\n!keep.tmp\n").unwrap();

    assert_eq!(
        explain_path_output(&set, None, "scratch.tmp"),
        "ignored: scratch.tmp (rule `*.tmp` at line 2)"
    );
    assert_eq!(
        explain_path_output(&set, None, "keep.tmp"),
        "not ignored: keep.tmp (rule `!keep.tmp` at line 3)"
    );
    assert_eq!(
        explain_path_output(&set, None, "notes.md"),
        "not ignored: notes.md (no matching pattern)"
    );
    assert_eq!(
        explain_path_output(&set, None, ".DS_Store"),
        "ignored: .DS_Store (rule `.DS_Store` at built-in default)"
    );
}

/// A trailing `/` names a directory when the folder has none on this disk, so a directory-only
/// rule applies to it.
#[test]
fn a_trailing_slash_names_a_directory_for_a_directory_only_rule() {
    let set = EffectiveIgnoreSet::from_text("node_modules/\n").unwrap();
    assert_eq!(
        test_path_output(&set, None, "node_modules/"),
        "ignored: node_modules/ (matched user pattern `node_modules/`)"
    );
    assert_eq!(
        test_path_output(&set, None, "node_modules"),
        "not ignored: node_modules (no matching pattern)"
    );
}
