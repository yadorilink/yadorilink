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
        &PinItemResponse { retention: Some(kept(true)), download_error: String::new() },
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
        },
    );
    assert_eq!(
        report,
        "photos is always kept on this device, but it could not be downloaded yet: no peer has \
         the content. Run `yadorilink pin photos` again to retry."
    );
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
