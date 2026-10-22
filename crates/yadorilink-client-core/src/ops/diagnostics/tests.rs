#![cfg(test)]

use super::*;

#[test]
fn limited_bundle_has_required_top_level_fields() {
    let (bundle, _) = limited_bundle();
    for key in [
        "schema_version",
        "generated_at",
        "yadorilink_version",
        "platform",
        "daemon",
        "links",
        "recent_errors",
        "updates",
        "resources",
        "environment",
        "desktop_ui",
        "redaction",
    ] {
        assert!(bundle.get(key).is_some(), "missing key {key}");
    }
    assert_eq!(bundle["daemon"]["reachable"], false);
    // The font section must always be present with a state, so a machine
    // rendering boxes is never silently indistinguishable from one that
    // resolved a font fine.
    assert!(bundle["desktop_ui"]["font"].is_object());
}
