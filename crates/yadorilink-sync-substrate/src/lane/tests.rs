#![cfg(test)]

use super::Lane;

#[test]
fn tags_round_trip_and_are_distinct() {
    let mut seen = Vec::new();
    for lane in Lane::ALL {
        let tag = lane.tag();
        assert!(!seen.contains(&tag), "duplicate lane tag {tag}");
        seen.push(tag);
        assert_eq!(Lane::from_tag(tag), Some(lane));
    }
}

#[test]
fn every_lane_has_a_concurrency_budget() {
    let limits = super::LaneLimits::default();
    assert_eq!(limits.for_lane(Lane::Block), limits.block);
    assert_eq!(limits.for_lane(Lane::Service), limits.service);
}

#[test]
fn unknown_tag_is_rejected_not_guessed() {
    assert_eq!(Lane::from_tag(0), None);
    // Tags of lanes that no longer exist stay refused rather than reused.
    assert_eq!(Lane::from_tag(1), None);
    assert_eq!(Lane::from_tag(2), None);
    assert_eq!(Lane::from_tag(5), None);
    assert_eq!(Lane::from_tag(u8::MAX), None);
}
