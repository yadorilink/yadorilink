#![cfg(test)]

use super::*;

#[test]
fn feedback_message_points_at_the_issue_templates_and_privacy_path() {
    let msg = feedback_message();
    // Points at the existing issue templates, not a new system.
    assert!(msg.contains(ISSUE_TEMPLATES_URL));
    assert!(msg.contains("issue templates"));
    assert!(msg.contains("no separate in-app feedback system"));
    // Reminds the tester crash reporting is local, reviewable, and consent-gated.
    assert!(msg.contains("report error --last"));
    assert!(msg.contains("consent"));
}
