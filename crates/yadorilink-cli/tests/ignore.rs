#[test]
fn ignore_list_includes_defaults_and_user_patterns_in_order() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".yadorilinkignore"), "node_modules/\n!important.log\n")
        .unwrap();

    let lines = yadorilink_cli::commands::ignore::pattern_lines(dir.path()).unwrap();

    assert_eq!(lines.first().map(String::as_str), Some("builtin\t.DS_Store"));
    assert!(lines.iter().any(|line| line == "builtin\tThumbs.db"));
    assert_eq!(
        &lines[lines.len() - 2..],
        ["user\tnode_modules/".to_string(), "user\t!important.log".to_string()]
    );
}

#[test]
fn ignore_test_reports_matching_pattern_or_explicit_no_match() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".yadorilinkignore"), "*.tmp\n!keep.tmp\n").unwrap();

    let ignored =
        yadorilink_cli::commands::ignore::test_path_output(&dir.path().join("scratch.tmp"))
            .unwrap();
    assert_eq!(ignored, "ignored: scratch.tmp (matched user pattern `*.tmp`)");

    let re_included =
        yadorilink_cli::commands::ignore::test_path_output(&dir.path().join("keep.tmp")).unwrap();
    assert_eq!(re_included, "not ignored: keep.tmp (matched user pattern `!keep.tmp`)");

    let no_match =
        yadorilink_cli::commands::ignore::test_path_output(&dir.path().join("notes.md")).unwrap();
    assert_eq!(no_match, "not ignored: notes.md (no matching pattern)");
}

/// `ignore explain` reports the winning rule's source file and line
/// number, distinct from `test`'s plainer "matched user pattern" wording.
#[test]
fn ignore_explain_reports_source_file_and_line_number() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".yadorilinkignore"), "# comment\n*.tmp\n!keep.tmp\n").unwrap();

    let ignored =
        yadorilink_cli::commands::ignore::explain_path_output(&dir.path().join("scratch.tmp"))
            .unwrap();
    assert_eq!(ignored, "ignored: scratch.tmp (rule `*.tmp` at .yadorilinkignore:2)");

    let re_included =
        yadorilink_cli::commands::ignore::explain_path_output(&dir.path().join("keep.tmp"))
            .unwrap();
    assert_eq!(re_included, "not ignored: keep.tmp (rule `!keep.tmp` at .yadorilinkignore:3)");

    let no_match =
        yadorilink_cli::commands::ignore::explain_path_output(&dir.path().join("notes.md"))
            .unwrap();
    assert_eq!(no_match, "not ignored: notes.md (no matching pattern)");
}
