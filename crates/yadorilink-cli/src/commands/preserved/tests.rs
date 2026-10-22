#![cfg(test)]

use yadorilink_ipc_proto::daemonctl::PreservedItem;

use super::format_item;

fn version(content: &str, held: u32, total: u32) -> PreservedItem {
    PreservedItem {
        kind: "remote_only".into(),
        group_id: "g".into(),
        item_id: "ab".repeat(32),
        path: "doc.txt".into(),
        content: content.into(),
        size: 12,
        blocks_held: held,
        blocks_total: total,
        ..Default::default()
    }
}

#[test]
fn a_complete_version_says_so() {
    let line = format_item(&version("complete", 1, 1));
    assert!(
        line.contains("doc.txt") && line.contains("content complete") && line.contains("12 bytes")
    );
}

#[test]
fn an_unavailable_version_says_how_many_blocks_are_held() {
    let line = format_item(&version("unavailable", 1, 3));
    assert!(line.contains("content unavailable (1 of 3 blocks)"), "{line}");
}

#[test]
fn a_record_less_version_is_never_called_restorable() {
    assert!(format_item(&version("record_unavailable", 0, 0)).contains("record unavailable"));
}

#[test]
fn an_own_unit_names_its_paths_and_where_its_files_are() {
    let item = PreservedItem {
        kind: "own_unit".into(),
        group_id: "g".into(),
        group_removed: true,
        item_id: "rec:0".into(),
        paths: vec!["a.txt".into(), "b/c.txt".into()],
        recovery_id: "rec".into(),
        originals_quarantined: true,
        ..Default::default()
    };
    let line = format_item(&item);
    assert!(line.contains("a.txt, b/c.txt") && line.contains("group removed"));
    assert!(line.contains("moved out of the folder into recovery area rec"), "{line}");
}

use yadorilink_ipc_proto::daemonctl::{RetainedOriginal, RetainedRelease};

use super::{format_release, format_retained, RETAINED_EXPLANATION};

fn retained(size: u64, reachable: bool) -> RetainedOriginal {
    RetainedOriginal {
        group_id: "g".into(),
        group_removed: !reachable,
        path: "docs/old.txt".into(),
        recovery_id: "rid".into(),
        size,
        reachable,
    }
}

#[test]
fn a_retained_original_names_its_path_group_and_size() {
    let line = format_retained(&retained(12, true));
    assert!(line.contains("docs/old.txt") && line.contains("group=g"), "{line}");
    assert!(line.contains("12 B"), "{line}");
}

#[test]
fn an_unreachable_retained_original_says_its_size_is_unknown() {
    let line = format_retained(&retained(0, false));
    assert!(line.contains("size unknown") && line.contains("group removed"), "{line}");
    assert!(!line.contains("0 bytes"), "{line}");
}

#[test]
fn each_release_outcome_is_worded_and_a_left_row_says_why() {
    let release = |outcome: &str, detail: &str| {
        format_release(&RetainedRelease {
            path: "a.txt".into(),
            outcome: outcome.into(),
            detail: detail.into(),
        })
    };
    assert!(release("removed", "").contains("released"));
    assert!(release("gone", "").contains("nothing was left"));
    assert!(release("still_retained", "").contains("kept"));
    let saved = release("saved_then_removed", "");
    assert!(saved.contains("saved") && saved.contains("preserved list"), "{saved}");
    assert!(release("saved_still_retained", "").contains("saved"));
    let left = release("left", "the row records no digest");
    assert!(left.contains("left") && left.contains("the row records no digest"), "{left}");
}

#[test]
fn the_retained_list_says_why_and_when_to_release() {
    assert!(RETAINED_EXPLANATION.contains("could not be proved safe"));
    assert!(RETAINED_EXPLANATION.contains("once nothing is writing to it"));
}
