use super::*;

const RECLAIMABLE: Option<Retention> = Some(Retention { pinned: false, explicit: false });
const KEPT: Option<Retention> = Some(Retention { pinned: true, explicit: true });
const KEPT_BY_FOLDER: Option<Retention> = Some(Retention { pinned: true, explicit: false });

fn facts() -> ItemFacts {
    ItemFacts {
        known: true,
        current_content_present: true,
        in_transition: false,
        is_file: true,
        provider_folder: true,
        reclaim_gate_open: true,
        retention: RECLAIMABLE,
    }
}

#[test]
fn a_downloaded_reclaimable_provider_file_offers_free_up_space_and_keep() {
    assert_eq!(
        available_actions(&facts()),
        vec![FileAction::FreeUpSpace, FileAction::KeepOnDevice]
    );
    assert!(free_up_space_offered(&facts()));
}

#[test]
fn a_kept_file_is_never_offered_free_up_space() {
    let kept = ItemFacts { retention: KEPT, ..facts() };
    assert_eq!(available_actions(&kept), vec![FileAction::StopKeeping]);
    assert!(!free_up_space_offered(&kept));
}

#[test]
fn a_file_kept_by_a_folder_above_has_neither_keep_action() {
    let inherited = ItemFacts { retention: KEPT_BY_FOLDER, ..facts() };
    assert!(available_actions(&inherited).is_empty());
    assert!(!free_up_space_offered(&inherited));
}

#[test]
fn an_unreadable_retention_offers_nothing_that_depends_on_it() {
    let unknown = ItemFacts { retention: None, ..facts() };
    assert!(available_actions(&unknown).is_empty());
    assert!(!free_up_space_offered(&unknown));
}

#[test]
fn an_ordinary_folder_downloads_a_placeholder_but_never_gives_space_back() {
    let placeholder =
        ItemFacts { provider_folder: false, current_content_present: false, ..facts() };
    assert_eq!(
        available_actions(&placeholder),
        vec![FileAction::Download, FileAction::KeepOnDevice]
    );
    let hydrated = ItemFacts { provider_folder: false, ..facts() };
    assert_eq!(available_actions(&hydrated), vec![FileAction::KeepOnDevice]);
}

#[test]
fn a_provider_placeholder_is_downloaded_by_the_system_so_only_keep_is_offered() {
    let placeholder = ItemFacts { current_content_present: false, ..facts() };
    assert_eq!(available_actions(&placeholder), vec![FileAction::KeepOnDevice]);
}

#[test]
fn nothing_is_offered_for_an_unknown_item_or_during_a_transition() {
    assert!(available_actions(&ItemFacts { known: false, ..facts() }).is_empty());
    let moving = ItemFacts { in_transition: true, ..facts() };
    assert!(available_actions(&moving).is_empty());
    assert!(!free_up_space_offered(&moving));
}

#[test]
fn free_up_space_needs_an_open_gate_a_file_and_current_content() {
    assert!(!free_up_space_offered(&ItemFacts { reclaim_gate_open: false, ..facts() }));
    assert!(!free_up_space_offered(&ItemFacts { is_file: false, ..facts() }));
    assert!(!free_up_space_offered(&ItemFacts { current_content_present: false, ..facts() }));
}
