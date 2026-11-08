use super::*;

const RECLAIMABLE: Option<Retention> =
    Some(Retention { pinned: false, online_only: false, explicit: false });
const KEPT: Option<Retention> =
    Some(Retention { pinned: true, online_only: false, explicit: true });
const KEPT_BY_FOLDER: Option<Retention> =
    Some(Retention { pinned: true, online_only: false, explicit: false });

fn facts() -> ItemFacts {
    ItemFacts {
        known: true,
        current_content_present: true,
        in_transition: false,
        is_file: true,
        is_folder: false,
        provider_folder: true,
        reclaim_gate_open: true,
        retention: RECLAIMABLE,
    }
}

#[test]
fn a_downloaded_reclaimable_provider_file_offers_free_up_space_and_keep() {
    assert_eq!(
        available_actions(&facts()),
        vec![FileAction::FreeUpSpace, FileAction::KeepOnDevice, FileAction::OnlineOnly]
    );
    assert!(free_up_space_offered(&facts()));
}

#[test]
fn a_kept_file_is_never_offered_free_up_space() {
    let kept = ItemFacts { retention: KEPT, ..facts() };
    assert_eq!(
        available_actions(&kept),
        vec![FileAction::OnlineOnly, FileAction::Default],
        "a kept file can be made online only or have its rule removed, never freed directly"
    );
    assert!(!free_up_space_offered(&kept));
}

#[test]
fn a_file_kept_by_a_folder_above_can_only_be_made_an_online_only_exception() {
    let inherited = ItemFacts { retention: KEPT_BY_FOLDER, ..facts() };
    assert_eq!(available_actions(&inherited), vec![FileAction::OnlineOnly]);
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
    assert_eq!(
        available_actions(&placeholder),
        vec![FileAction::KeepOnDevice, FileAction::OnlineOnly]
    );
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

#[test]
fn an_online_only_file_can_be_kept_or_have_its_rule_removed_and_a_present_copy_can_be_freed() {
    let online_only = Some(Retention { pinned: false, online_only: true, explicit: true });
    let present = ItemFacts { retention: online_only, ..facts() };
    assert_eq!(
        available_actions(&present),
        vec![FileAction::FreeUpSpace, FileAction::KeepOnDevice, FileAction::Default]
    );
    let inherited = Some(Retention { pinned: false, online_only: true, explicit: false });
    let by_folder = ItemFacts { retention: inherited, current_content_present: false, ..facts() };
    assert_eq!(available_actions(&by_folder), vec![FileAction::KeepOnDevice]);
}

#[test]
fn online_only_is_a_provider_folders_choice_only() {
    let plain = ItemFacts { provider_folder: false, ..facts() };
    assert!(!available_actions(&plain).contains(&FileAction::OnlineOnly));
}

/// A folder is offered its rule choices, and Free Up Space only while an online-only rule covers
/// it (the request runs that rule again and refuses a folder no rule covers).
#[test]
fn a_provider_folder_offers_its_rules_and_free_up_space_only_under_an_online_only_rule() {
    let folder = ItemFacts {
        is_file: false,
        is_folder: true,
        known: false,
        current_content_present: false,
        ..facts()
    };
    assert_eq!(
        available_actions(&folder),
        vec![FileAction::KeepOnDevice, FileAction::OnlineOnly],
        "no rule: nothing to run again"
    );
    let online_only = Some(Retention { pinned: false, online_only: true, explicit: true });
    assert_eq!(
        available_actions(&ItemFacts { retention: online_only, ..folder }),
        vec![FileAction::FreeUpSpace, FileAction::KeepOnDevice, FileAction::Default]
    );
    let closed = ItemFacts { retention: online_only, reclaim_gate_open: false, ..folder };
    assert!(!available_actions(&closed).contains(&FileAction::FreeUpSpace));
    let unreadable = ItemFacts { retention: None, ..folder };
    assert!(available_actions(&unreadable).is_empty());
}

/// A plain linked directory with files not downloaded yet still offers Download (the daemon
/// hydrates it recursively), as before folders got their own rule branch.
#[test]
fn a_known_plain_directory_with_undownloaded_files_still_offers_download() {
    let directory = ItemFacts {
        is_file: false,
        is_folder: true,
        provider_folder: false,
        current_content_present: false,
        ..facts()
    };
    assert_eq!(available_actions(&directory), vec![FileAction::Download, FileAction::KeepOnDevice]);
}
