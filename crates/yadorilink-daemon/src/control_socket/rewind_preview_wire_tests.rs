#![cfg(test)]

use super::*;
use prost::Message;
use yadorilink_ipc_proto::framing::MAX_FRAME_LEN;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::rewind::{
    RewindPathAction, RewindPathEntry, RewindPlan, RewindRenameCandidate, RewindUnavailableReason,
};

/// A plan far past the scale the read-side benchmark measures, built to
/// be as expensive to encode as a real one can plausibly be: long
/// nested paths, and an `unavailable` reason on every path that can
/// carry one.
fn huge_plan(paths: usize) -> RewindPlan {
    let entries = (0..paths)
        .map(|i| {
            let action = match i % 4 {
                0 => RewindPathAction::Unchanged,
                1 => RewindPathAction::Delete,
                2 => RewindPathAction::Replace {
                    to_version_seq: 4,
                    to_version_hash: VersionHash([1u8; 32]),
                },
                // The longest reason there is.
                _ => RewindPathAction::Unavailable { reason: RewindUnavailableReason::JoinedAfter },
            };
            RewindPathEntry {
                path: format!("some/reasonably/deep/project/directory/tree/file-{i:07}.bin"),
                current_version_seq: 9,
                current_version_hash: VersionHash([3u8; 32]),
                action,
            }
        })
        .collect();
    RewindPlan {
        group_id: "group-with-a-lot-in-it".to_string(),
        target_unix_nanos: 1_750_000_000_000_000_000,
        entries,
        rename_candidates: (0..paths / 10)
            .map(|i| RewindRenameCandidate {
                from_path: format!("some/reasonably/deep/moved/from-{i:07}.bin"),
                to_path: format!("some/reasonably/deep/moved/to-{i:07}.bin"),
                version_hash: VersionHash([2u8; 32]),
            })
            .collect(),
    }
}

/// The response has to fit in one frame or the CLI cannot read it at
/// all -- the reader rejects an oversized frame outright, and now so
/// does the writer. Asserted at a scale well past the 50k the read-side
/// benchmark covers, in BOTH modes: the `unchanged` filter is the
/// ordinary saving, but the byte budget is what makes the guarantee
/// unconditional.
#[test]
fn a_huge_plan_still_produces_a_response_that_fits_in_one_frame() {
    for include_unchanged in [false, true] {
        let response = rewind_preview_to_proto(crate::rewind::trim_for_wire(
            huge_plan(200_000),
            include_unchanged,
        ));
        let encoded_len = response.encoded_len();
        assert!(
            encoded_len < MAX_FRAME_LEN as usize,
            "include_unchanged={include_unchanged}: response of {encoded_len} bytes would \
             not fit in a {MAX_FRAME_LEN}-byte frame"
        );
        // The summary must still describe the WHOLE plan, or the
        // trimming would have quietly changed the answer.
        let counts = response.counts.as_ref().expect("counts are always sent");
        assert_eq!(response.total_entry_count, 200_000);
        assert_eq!(
            counts.create + counts.delete + counts.replace + counts.unchanged + counts.unavailable,
            200_000
        );
        assert!(response.listing_truncated, "a listing this big cannot have fit whole");
    }
}

/// The ordinary case: a folder small enough to describe completely must
/// come back complete, with nothing flagged as cut.
#[test]
fn a_small_plan_is_delivered_whole() {
    let response = rewind_preview_to_proto(crate::rewind::trim_for_wire(huge_plan(40), true));
    assert_eq!(response.entries.len(), 40);
    assert_eq!(response.rename_candidates.len(), 4);
    assert!(!response.listing_truncated);
    assert!(response.encoded_len() < MAX_FRAME_LEN as usize);
}

/// The id on the wire is the whole plan's, in full, whichever listing the
/// response carries.
#[test]
fn the_response_carries_the_full_plans_id() {
    let plan = huge_plan(200_000);
    let full_id = plan.plan_id();
    for include_unchanged in [false, true] {
        let response =
            rewind_preview_to_proto(crate::rewind::trim_for_wire(plan.clone(), include_unchanged));
        assert!(response.listing_truncated);
        assert_eq!(response.plan_id, full_id.0.to_vec());
    }
}

/// A `replace` entry's "from" side on the wire is the path's current
/// version.
#[test]
fn a_replace_entry_reports_its_current_version_as_the_from_side() {
    let response = rewind_preview_to_proto(crate::rewind::trim_for_wire(huge_plan(4), true));
    let replace = response.entries.iter().find(|e| e.action == "replace").unwrap();
    assert_eq!(replace.from_version_seq, Some(9));
    assert_eq!(replace.to_version_seq, Some(4));
}

/// The unavailable paths reach the wire counted by cause over the whole plan
/// (not the trimmed listing), in the one wording the replica domain owns.
#[test]
fn the_response_carries_the_whole_plans_unavailable_paths_by_cause() {
    let plan = huge_plan(200_000);
    let expected = plan.unavailable().message();
    let response = rewind_preview_to_proto(crate::rewind::trim_for_wire(plan, false));
    assert!(response.entries.len() < 150_000, "the listing was trimmed");
    assert_eq!(response.unavailable_message, expected);
    assert!(expected.starts_with("50000 files unavailable; rewind cannot start: 50000 because"));

    let none = rewind_preview_to_proto(crate::rewind::trim_for_wire(huge_plan(0), false));
    assert_eq!(none.unavailable_message, "");
}
