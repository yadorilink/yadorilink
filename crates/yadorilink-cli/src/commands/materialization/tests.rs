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
fn a_pin_report_says_the_path_is_kept() {
    let report = pin_report(
        "photos/a.jpg",
        &PinItemResponse { retention: Some(kept(true)), ..Default::default() },
    );
    assert_eq!(report, "photos/a.jpg is always kept on this device");
}

/// The pin stands whether or not the download worked; a failure must read as a failure to
/// download, never as a failure to pin.
#[test]
fn a_pin_report_names_a_failed_download_and_still_says_the_pin_stands() {
    let report = pin_report(
        "photos",
        &PinItemResponse {
            retention: Some(kept(true)),
            download_error: "no peer has the content".into(),
            ..Default::default()
        },
    );
    assert_eq!(
        report,
        "photos is always kept on this device, but it could not be downloaded yet: no peer has \
         the content. Run `yadorilink pin photos` again to retry."
    );
}

/// A pin whose files are not all held in the store yet still says the pin stands, and says what to
/// do, instead of leaving the user to find out when an edit loses a version.
#[test]
fn a_pin_report_says_when_previous_versions_are_not_yet_kept() {
    let changing = pin_report(
        "photos",
        &PinItemResponse {
            retention: Some(kept(true)),
            history_not_kept_reason: "changing_retry".into(),
            ..Default::default()
        },
    );
    assert!(changing.starts_with("photos is always kept on this device. "), "{changing}");
    assert!(changing.contains("previous versions are not safely kept yet"), "{changing}");
    assert!(changing.contains("run the pin again"), "{changing}");

    let unchecked = pin_report(
        "photos",
        &PinItemResponse {
            retention: Some(kept(true)),
            history_not_kept_reason: "not_kept_error".into(),
            ..Default::default()
        },
    );
    assert!(unchecked.contains("could not be checked"), "{unchecked}");
}

#[test]
fn an_unpin_report_says_nothing_was_removed() {
    let report =
        unpin_report("photos/a.jpg", &UnpinItemResponse { retention: Some(reclaimable()) });
    assert_eq!(
        report,
        "photos/a.jpg is no longer kept on this device. Its content stays until you free it."
    );
}

/// There are no per-file overrides: unpinning a file whose folder is kept changes nothing.
#[test]
fn an_unpin_report_says_when_a_folder_above_still_keeps_the_path() {
    let report = unpin_report("photos/a.jpg", &UnpinItemResponse { retention: Some(kept(false)) });
    assert_eq!(
        report,
        "photos/a.jpg is still kept on this device because a folder above it is. Unpin that \
         folder to stop keeping it."
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
    let complete = PinItemResponse { retention: Some(kept(true)), ..Default::default() };
    assert_eq!(pin_outcome("a", &complete).unwrap(), "a is always kept on this device".to_owned());
    let not_downloaded =
        PinItemResponse { download_error: "no peer has the content".into(), ..complete.clone() };
    assert!(pin_outcome("a", &not_downloaded)
        .unwrap_err()
        .to_string()
        .contains("could not be downloaded"));
    let history = PinItemResponse { history_not_kept_reason: "changing_retry".into(), ..complete };
    assert!(pin_outcome("a", &history).is_err());
}
