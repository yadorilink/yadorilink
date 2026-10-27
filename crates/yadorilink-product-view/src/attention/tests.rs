use super::*;

const ALL: [AttentionItem; 40] = [
    AttentionItem::FolderStopped,
    AttentionItem::WaitingForDiskSpace,
    AttentionItem::LinkedTwice,
    AttentionItem::OwnershipLost,
    AttentionItem::NotJoined,
    AttentionItem::FileWatchLimit,
    AttentionItem::VolumeChanged,
    AttentionItem::VolumeUnconfirmed,
    AttentionItem::NoSafeCopy,
    AttentionItem::SafeCopyUnconfirmed,
    AttentionItem::ContentUnavailable,
    AttentionItem::ContentAvailabilityUnknown,
    AttentionItem::ConflictNeedsReview,
    AttentionItem::ApprovalPending,
    AttentionItem::FileHeld,
    AttentionItem::UnsupportedFilename,
    AttentionItem::FileNotReadable,
    AttentionItem::StrandedDirectory,
    AttentionItem::UnreadableFiles,
    AttentionItem::ProviderNotReady,
    AttentionItem::ProviderFilesFailing,
    AttentionItem::EditsKeptBeside,
    AttentionItem::ProviderOrphan,
    AttentionItem::DiskFull,
    AttentionItem::DiskLow,
    AttentionItem::PeerUnavailable,
    AttentionItem::RetryableFailure,
    AttentionItem::UpdateFailed,
    AttentionItem::UpdateRequired,
    AttentionItem::ProviderRegistryRestored,
    AttentionItem::DatabaseRestored,
    AttentionItem::AuthorUnavailable,
    AttentionItem::ReplacementUnconfirmed,
    AttentionItem::ReplacementSignInRequired,
    AttentionItem::ReplacementWaiting,
    AttentionItem::TermsConsentRequired,
    AttentionItem::SignInRequired,
    AttentionItem::AccountDeletionPending,
    AttentionItem::AccountDeletionUrgent,
    AttentionItem::Unrecognized,
];

/// A distinct number per item. The match has no wildcard, so adding an `AttentionItem` fails to
/// compile here until it is numbered, and `all_lists_every_item` then fails until it is in `ALL`
/// (the list every key/sentence contract test walks).
fn ordinal(item: AttentionItem) -> usize {
    use AttentionItem as I;
    match item {
        I::FolderStopped => 0,
        I::WaitingForDiskSpace => 1,
        I::LinkedTwice => 2,
        I::OwnershipLost => 3,
        I::VolumeChanged => 4,
        I::VolumeUnconfirmed => 5,
        I::NoSafeCopy => 6,
        I::SafeCopyUnconfirmed => 7,
        I::ContentUnavailable => 8,
        I::ContentAvailabilityUnknown => 9,
        I::ConflictNeedsReview => 10,
        I::ApprovalPending => 11,
        I::FileHeld => 12,
        I::UnsupportedFilename => 13,
        I::FileNotReadable => 14,
        I::StrandedDirectory => 15,
        I::UnreadableFiles => 16,
        I::ProviderNotReady => 17,
        I::ProviderFilesFailing => 18,
        I::EditsKeptBeside => 19,
        I::ProviderOrphan => 20,
        I::DiskFull => 21,
        I::DiskLow => 22,
        I::PeerUnavailable => 23,
        I::RetryableFailure => 24,
        I::UpdateFailed => 25,
        I::UpdateRequired => 26,
        I::ProviderRegistryRestored => 27,
        I::DatabaseRestored => 28,
        I::AuthorUnavailable => 29,
        I::ReplacementUnconfirmed => 30,
        I::ReplacementSignInRequired => 31,
        I::ReplacementWaiting => 32,
        I::NotJoined => 33,
        I::FileWatchLimit => 34,
        I::TermsConsentRequired => 36,
        I::SignInRequired => 37,
        I::AccountDeletionPending => 38,
        I::AccountDeletionUrgent => 39,
        I::Unrecognized => 35,
    }
}

#[test]
fn all_lists_every_item() {
    let mut seen: Vec<usize> = ALL.iter().map(|i| ordinal(*i)).collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..40).collect::<Vec<_>>());
}

#[test]
fn keys_are_unique_snake_case() {
    let mut seen = std::collections::HashSet::new();
    for item in ALL {
        assert!(seen.insert(item.key()), "duplicate {}", item.key());
        assert!(item.key().bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
    }
}

#[test]
fn every_rollup_code_the_daemon_emits_is_recognized() {
    for raw in [
        "degraded:g",
        "terms_consent_required",
        "sign_in_required",
        "account_deletion_pending",
        "account_deletion_urgent",
        "waiting_for_disk_space:g",
        "file_watch_limit:g",
        "ambiguous:g",
        "ownership_lost:g",
        "not_joined:g",
        "volume_changed:g",
        "volume_unconfirmed:g",
        "durability_at_risk:g",
        "durability_unknown:g",
        "fetch_unavailable:g",
        "fetch_availability_unknown:g",
        "conflict:g",
        "conflict_pending:g",
        "approval_pending:g",
        "held:g",
        "stranded_directory:g",
        "unreadable_files:g",
        "provider_not_ready:r",
        "provider_not_ready:removals",
        "provider_stuck:r",
        "kept_edits:r",
        "provider_orphan_domain:d",
        "low_disk_critical:/p",
        "low_disk:/p",
        "peer_disconnected:dev",
        "recent_error:cat",
        "update_failed:cat",
        "peer_update_required:dev",
        "update_required",
        "provider_registry_restored:older_generation",
        "database_restored:older_generation",
        "author_unavailable",
    ] {
        assert_ne!(Attention::from_reason(raw).item, AttentionItem::Unrecognized, "{raw}");
    }
}

#[test]
fn scope_is_the_reported_subject() {
    let a = Attention::from_reason("low_disk:/data:x");
    assert_eq!(a.item, AttentionItem::DiskLow);
    assert_eq!(a.scope, AttentionScope::Volume("/data:x".into()));
    assert_eq!(
        Attention::from_reason("conflict_pending:g1").scope,
        AttentionScope::Folder("g1".into())
    );
    assert_eq!(
        Attention::from_reason("peer_disconnected:d1").scope,
        AttentionScope::Device("d1".into())
    );
    assert_eq!(Attention::from_reason("recent_error:cat").scope, AttentionScope::General);
}

#[test]
fn an_unknown_code_is_unrecognized_and_offers_details() {
    let a = Attention::from_reason("brand_new:x");
    assert_eq!(a.item, AttentionItem::Unrecognized);
    assert_eq!(a.item.primary_action(), ProductAction::ViewDetails);
}

#[test]
fn held_reasons_read_their_code_before_the_detail() {
    for raw in [
        "case_collision: collides with 'A'",
        "invalid_name: bad",
        "normalization_collision",
        "case_and_normalization_collision",
    ] {
        assert_eq!(Attention::from_held_reason(raw).item, AttentionItem::UnsupportedFilename);
    }
    assert_eq!(
        Attention::from_held_reason("metadata_unprovable: x").item,
        AttentionItem::FileNotReadable
    );
    assert_eq!(Attention::from_held_reason("other").item, AttentionItem::FileHeld);
}

#[test]
fn actions_follow_the_kind() {
    assert_eq!(AttentionItem::DiskLow.primary_action(), ProductAction::FreeUpSpace);
    assert_eq!(AttentionItem::ConflictNeedsReview.primary_action(), ProductAction::ReviewConflict);
    assert_eq!(AttentionItem::PeerUnavailable.kind(), AttentionKind::Waiting);
    assert_eq!(AttentionItem::RetryableFailure.kind(), AttentionKind::Retryable);
    assert_eq!(
        AttentionItem::RetryableFailure.secondary_action(),
        Some(ProductAction::ViewDetails)
    );
    assert_eq!(AttentionItem::DiskLow.secondary_action(), None);
}

/// A disk only the user can confirm offers exactly that, and says nothing
/// changes until then.
#[test]
fn an_unconfirmed_disk_asks_the_user_to_confirm_it() {
    let attention = Attention::from_reason("volume_unconfirmed:g");
    assert_eq!(attention.item, AttentionItem::VolumeUnconfirmed);
    assert_eq!(attention.scope, AttentionScope::Folder("g".to_owned()));
    assert_eq!(attention.item.kind(), AttentionKind::Permanent);
    assert_eq!(attention.item.primary_action(), ProductAction::ConfirmDisk);
}

/// The disk-space wait is its own item, not a stopped folder: informational, waiting, folder
/// scope, and free-up-space only where a reclaim can succeed.
#[test]
fn file_watch_limit_is_typed_and_not_a_stopped_folder() {
    let a = Attention::from_reason("file_watch_limit:g");
    assert_eq!(a.item, AttentionItem::FileWatchLimit);
    assert_eq!(a.item.key(), "file_watch_limit");
    assert_eq!(a.scope, AttentionScope::Folder("g".into()));
    assert_eq!(a.item.severity(), AttentionSeverity::Critical);
}

#[test]
fn waiting_for_disk_space_is_typed_and_not_a_stopped_folder() {
    let a = Attention::from_reason("waiting_for_disk_space:g");
    assert_eq!(a.item, AttentionItem::WaitingForDiskSpace);
    assert_eq!(a.item.key(), "waiting_for_disk_space");
    assert_eq!(a.scope, AttentionScope::Folder("g".to_owned()));
    assert_eq!(a.item.kind(), AttentionKind::Waiting);
    assert_eq!(a.item.severity(), AttentionSeverity::Info);
    assert_eq!(a.item.offered_action(true), ProductAction::FreeUpSpace);
    assert_eq!(a.item.offered_action(false), ProductAction::ViewDetails);
    assert_ne!(a.item, Attention::from_reason("degraded:g").item);
}

/// Severity is the rollup's own split: the codes the daemon files under its degraded state are
/// critical, a wait for something outside the user's hands is informational, the rest need a look.
#[test]
fn severity_follows_the_rollups_degraded_split() {
    for raw in [
        "degraded:g",
        "ambiguous:g",
        "ownership_lost:g",
        "not_joined:g",
        "durability_at_risk:g",
        "low_disk_critical:/p",
    ] {
        assert_eq!(
            Attention::from_reason(raw).item.severity(),
            AttentionSeverity::Critical,
            "{raw}"
        );
    }
    for raw in ["durability_unknown:g", "fetch_unavailable:g", "peer_disconnected:d"] {
        assert_eq!(Attention::from_reason(raw).item.severity(), AttentionSeverity::Info, "{raw}");
    }
    for raw in [
        "conflict:g",
        "low_disk:/p",
        "recent_error:c",
        "volume_unconfirmed:g",
        "held:g",
        "unreadable_files:g",
    ] {
        assert_eq!(
            Attention::from_reason(raw).item.severity(),
            AttentionSeverity::Warning,
            "{raw}"
        );
    }
    for item in ALL {
        if item.severity() == AttentionSeverity::Info {
            assert_eq!(item.kind(), AttentionKind::Waiting, "{}", item.key());
        }
    }
}

/// Arguments name the subject by what it is, so a shell fills its sentence without parsing codes.
#[test]
fn scope_names_its_argument() {
    let name = |raw: &str| Attention::from_reason(raw).scope.arg_name();
    assert_eq!(name("conflict:g"), "folder");
    assert_eq!(name("provider_stuck:r"), "provider_folder");
    assert_eq!(name("peer_disconnected:d"), "device");
    assert_eq!(name("low_disk:/p"), "volume");
    assert_eq!(name("recent_error:c"), "category");
}

/// Resume belongs to a paused folder, never to a problem report.
#[test]
fn no_attention_item_offers_resume() {
    for item in ALL {
        assert_ne!(item.primary_action(), ProductAction::Resume, "{}", item.key());
        assert_ne!(item.secondary_action(), Some(ProductAction::Resume), "{}", item.key());
    }
}

/// A device on another version is online, so it is neither a wait nor `peer_unavailable`: the
/// user has to update, and the item says so.
#[test]
fn a_version_mismatch_is_update_required_not_offline() {
    let peer = Attention::from_reason("peer_update_required:d1");
    assert_eq!(peer.item, AttentionItem::UpdateRequired);
    assert_eq!(peer.scope, AttentionScope::Device("d1".into()));
    assert_ne!(peer.item, Attention::from_reason("peer_disconnected:d1").item);

    let local = Attention::from_reason("update_required");
    assert_eq!(local.item, AttentionItem::UpdateRequired);
    assert_eq!(local.scope, AttentionScope::General);

    let item = AttentionItem::UpdateRequired;
    assert_eq!(item.key(), "update_required");
    assert_eq!(item.kind(), AttentionKind::Permanent);
    assert_eq!(item.severity(), AttentionSeverity::Warning);
    assert_eq!(item.primary_action(), ProductAction::DownloadUpdate);
}

/// The Windows host read its sync-root registry from an older generation because the newest one
/// was torn: a warning the user can look at, additive, with the generic details action.
#[test]
fn a_registry_restored_from_an_older_generation_is_a_warning() {
    let attention = Attention::from_reason("provider_registry_restored:older_generation");
    assert_eq!(attention.item, AttentionItem::ProviderRegistryRestored);
    assert_eq!(attention.item.key(), "provider_registry_restored");
    assert_eq!(attention.item.severity(), AttentionSeverity::Warning);
    assert_eq!(attention.item.primary_action(), ProductAction::ViewDetails);
    assert_eq!(attention.scope, AttentionScope::General);
}

/// A restored or copied replica database is refused: critical, permanent, and the offered action
/// is the one that ends the refusal (start over as a new device), not a details view.
#[test]
fn a_restored_database_is_critical_and_permanent() {
    let attention = Attention::from_reason("database_restored:older_generation");
    assert_eq!(attention.item, AttentionItem::DatabaseRestored);
    assert_eq!(attention.item.key(), "database_restored");
    assert_eq!(attention.item.severity(), AttentionSeverity::Critical);
    assert_eq!(attention.item.kind(), AttentionKind::Permanent);
    assert_eq!(attention.item.primary_action(), ProductAction::StartOverAsNewDevice);
    assert_eq!(attention.scope, AttentionScope::General);
}

/// An author identity that cannot be opened is critical, permanent, details action.
#[test]
fn an_unopenable_author_identity_is_critical_and_permanent() {
    let attention = Attention::from_reason("author_unavailable");
    assert_eq!(attention.item, AttentionItem::AuthorUnavailable);
    assert_eq!(attention.item.key(), "author_unavailable");
    assert_eq!(attention.item.severity(), AttentionSeverity::Critical);
    assert_eq!(attention.item.kind(), AttentionKind::Permanent);
    assert_eq!(attention.item.primary_action(), ProductAction::ViewDetails);
}

/// The replacement-unconfirmed codes are known items with their own cause and action, not
/// `Unrecognized`.
#[test]
fn unconfirmed_replacement_codes_are_known_items() {
    let waiting = Attention::from_reason("replacement_unconfirmed");
    assert_eq!(waiting.item, AttentionItem::ReplacementUnconfirmed);
    assert_eq!(waiting.item.key(), "replacement_unconfirmed");
    assert_eq!(waiting.item.kind(), AttentionKind::Waiting);
    let why =
        Attention::from_reason("replacement_unconfirmed_waiting:g1: startup has not finished");
    assert_eq!(why.item, AttentionItem::ReplacementWaiting);
    assert_eq!(why.item.key(), "replacement_unconfirmed_waiting");
    assert_eq!(why.item.kind(), AttentionKind::Waiting);
    assert_eq!(why.item.severity(), AttentionSeverity::Info);
    let sign_in = Attention::from_reason("replacement_unconfirmed_sign_in_required");
    assert_eq!(sign_in.item, AttentionItem::ReplacementSignInRequired);
    assert_eq!(sign_in.item.kind(), AttentionKind::Permanent);
    assert_eq!(sign_in.item.severity(), AttentionSeverity::Warning);
}

/// A request waiting on the owner is a warning the owner clears by deciding; the item points at
/// the review, scoped to the folder group.
#[test]
fn a_waiting_approval_request_asks_the_owner_to_review_it() {
    let attention = Attention::from_reason("approval_pending:g1");
    assert_eq!(attention.item, AttentionItem::ApprovalPending);
    assert_eq!(attention.item.key(), "approval_pending");
    assert_eq!(attention.scope, AttentionScope::Folder("g1".into()));
    assert_eq!(attention.item.kind(), AttentionKind::Permanent);
    assert_eq!(attention.item.severity(), AttentionSeverity::Warning);
    assert_eq!(attention.item.primary_action(), ProductAction::ReviewApproval);
    assert_eq!(attention.item.offered_action(false), ProductAction::ReviewApproval);
}

/// Free up space is advertised only where a reclaim can succeed; otherwise the item falls back to
/// its details. No other item's action depends on it.
#[test]
fn free_up_space_is_offered_only_where_it_can_succeed() {
    let reclaim_items =
        [AttentionItem::DiskLow, AttentionItem::DiskFull, AttentionItem::WaitingForDiskSpace];
    for item in reclaim_items {
        assert_eq!(item.offered_action(true), ProductAction::FreeUpSpace);
        assert_eq!(item.offered_action(false), ProductAction::ViewDetails);
    }
    for item in ALL {
        if !reclaim_items.contains(&item) {
            assert_eq!(item.offered_action(false), item.primary_action(), "{}", item.key());
            assert_eq!(item.offered_action(true), item.primary_action(), "{}", item.key());
        }
    }
}

#[test]
fn the_consent_and_sign_in_items_offer_the_sign_in_and_are_permanent() {
    for (code, item) in [
        ("terms_consent_required", AttentionItem::TermsConsentRequired),
        ("sign_in_required", AttentionItem::SignInRequired),
    ] {
        let attention = Attention::from_reason(code);
        assert_eq!((attention.item, attention.scope), (item, AttentionScope::General));
        assert_eq!(item.key(), code);
        assert_eq!(item.kind(), AttentionKind::Permanent);
        assert_eq!(item.primary_action(), ProductAction::SignIn);
    }
}

#[test]
fn account_deletion_items_are_general_permanent_and_urgent_ranks_higher() {
    for (code, item, severity) in [
        (
            "account_deletion_pending",
            AttentionItem::AccountDeletionPending,
            AttentionSeverity::Warning,
        ),
        (
            "account_deletion_urgent",
            AttentionItem::AccountDeletionUrgent,
            AttentionSeverity::Critical,
        ),
    ] {
        let attention = Attention::from_reason(code);
        assert_eq!((attention.item, attention.scope), (item, AttentionScope::General));
        assert_eq!(item.key(), code);
        assert_eq!(item.kind(), AttentionKind::Permanent);
        assert_eq!(item.severity(), severity);
        assert_eq!(item.primary_action(), ProductAction::ViewDetails);
    }
}
