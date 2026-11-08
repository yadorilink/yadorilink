#![cfg(test)]

use super::*;

fn kept(explicit: bool) -> RetentionState {
    RetentionState { policy: RetentionPolicy::Pinned as i32, explicit }
}

fn reclaimable() -> RetentionState {
    RetentionState { policy: RetentionPolicy::Reclaimable as i32, explicit: false }
}

#[test]
fn a_hydrate_report_claims_a_download_only_when_one_happened() {
    assert_eq!(hydrate_report("a.bin", true), "Downloaded a.bin");
    let text = hydrate_report("a.bin", false);
    assert!(!text.contains("Downloaded") && text.contains("already on this device"), "{text}");
}

#[test]
fn a_keep_report_says_the_path_is_kept() {
    let report = keep_report(
        "photos/a.jpg",
        &SetRetentionRuleResponse { retention: Some(kept(true)), ..Default::default() },
    );
    assert_eq!(report, "photos/a.jpg is always kept on this device");
}

/// The pin stands whether or not the download worked; a failure must read as a failure to
/// download, never as a failure to pin.
#[test]
fn a_keep_report_names_a_failed_download_and_still_says_the_pin_stands() {
    let report = keep_report(
        "photos",
        &SetRetentionRuleResponse {
            retention: Some(kept(true)),
            download_error: "no peer has the content. It will be retried automatically".into(),
            ..Default::default()
        },
    );
    assert_eq!(
        report,
        "photos is always kept on this device, but it could not be downloaded yet: no peer has \
         the content. It will be retried automatically."
    );
}

/// A pin whose files are not all held in the store yet still says the pin stands, and says what to
/// do, instead of leaving the user to find out when an edit loses a version.
#[test]
fn a_keep_report_says_when_previous_versions_are_not_yet_kept() {
    let changing = keep_report(
        "photos",
        &SetRetentionRuleResponse {
            retention: Some(kept(true)),
            history_not_kept_reason: "changing_retry".into(),
            ..Default::default()
        },
    );
    assert!(changing.starts_with("photos is always kept on this device. "), "{changing}");
    assert!(changing.contains("previous versions are not safely kept yet"), "{changing}");
    assert!(changing.contains("run the command again"), "{changing}");

    let unchecked = keep_report(
        "photos",
        &SetRetentionRuleResponse {
            retention: Some(kept(true)),
            history_not_kept_reason: "not_kept_error".into(),
            ..Default::default()
        },
    );
    assert!(unchecked.contains("could not be checked"), "{unchecked}");
}

#[test]
fn an_default_report_says_nothing_was_removed() {
    let report = default_report(
        "photos/a.jpg",
        &SetRetentionRuleResponse { retention: Some(reclaimable()), ..Default::default() },
    );
    assert_eq!(report, "photos/a.jpg has no rule of its own. Its content stays until you free it.");
}

/// Removing the rule of a file whose folder is kept changes nothing.
#[test]
fn an_default_report_says_when_a_folder_above_still_keeps_the_path() {
    let report = default_report(
        "photos/a.jpg",
        &SetRetentionRuleResponse { retention: Some(kept(false)), ..Default::default() },
    );
    assert_eq!(
        report,
        "photos/a.jpg is still kept on this device because a folder above it is. Change that \
         folder's rule to stop keeping it."
    );
}

#[test]
fn the_status_line_names_the_policy_only_when_the_path_is_kept() {
    assert_eq!(retention_suffix(None), "");
    assert_eq!(retention_suffix(Some(&reclaimable())), "");
    assert_eq!(retention_suffix(Some(&kept(true))), ", always kept on this device");
    assert_eq!(
        retention_suffix(Some(&kept(false))),
        ", always kept on this device (by a folder above)"
    );
}

/// A pin that is recorded but did not download, or whose versions are not yet in the store, needs
/// another run: the exit status says so, with the same message.
#[test]
fn a_pin_that_needs_another_run_is_an_error() {
    let complete = SetRetentionRuleResponse { retention: Some(kept(true)), ..Default::default() };
    assert_eq!(keep_outcome("a", &complete).unwrap(), "a is always kept on this device".to_owned());
    let not_downloaded = SetRetentionRuleResponse {
        download_error: "no peer has the content".into(),
        ..complete.clone()
    };
    assert!(keep_outcome("a", &not_downloaded)
        .unwrap_err()
        .to_string()
        .contains("could not be downloaded"));
    let history =
        SetRetentionRuleResponse { history_not_kept_reason: "changing_retry".into(), ..complete };
    assert!(keep_outcome("a", &history).is_err());
}

fn online_only(explicit: bool) -> RetentionState {
    RetentionState { policy: RetentionPolicy::OnlineOnly as i32, explicit }
}

#[test]
fn the_status_line_names_an_online_only_rule_and_where_it_comes_from() {
    assert_eq!(retention_suffix(Some(&online_only(true))), ", online only");
    assert_eq!(retention_suffix(Some(&online_only(false))), ", online only (by a folder above)");
}

#[test]
fn an_online_only_report_says_the_content_stays_available() {
    let report = online_only_report(
        "photos",
        &SetRetentionRuleResponse { retention: Some(online_only(true)), ..Default::default() },
    );
    assert!(report.starts_with("photos is now online only."), "{report}");
    assert!(report.contains("stays available online"), "{report}");
}

#[test]
fn a_default_report_names_an_online_only_folder_above() {
    let report = default_report(
        "photos/a.jpg",
        &SetRetentionRuleResponse { retention: Some(online_only(false)), ..Default::default() },
    );
    assert!(report.contains("online only"), "{report}");
}
