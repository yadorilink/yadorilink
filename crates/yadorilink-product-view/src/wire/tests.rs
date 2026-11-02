use super::*;
use crate::availability::Availability;
use crate::protection::Protection;

fn full() -> ProductStatusSummary {
    ProductStatusSummary {
        state: ProductState::NeedsAttention,
        attention_count: 2,
        paused_count: 1,
        syncing_count: 3,
        waiting_count: 4,
        attention_reasons: Vec::new(),
        general_attention: Vec::new(),
        bytes_remaining: Some(0),
        availability: AvailabilitySummary {
            availability: Availability::WaitingForPeer,
            reachable_device_ids: vec!["a".into()],
            offline_device_ids: vec!["b".into()],
            update_required_device_ids: vec!["c".into()],
        },
        protection: ProtectionSummary {
            protection: Protection::Pending,
            device_ids: vec!["d".into()],
        },
        next_action: Some(ProductAction::ReviewConflict),
    }
}

#[test]
fn a_summary_survives_the_wire() {
    let summary = full();
    assert_eq!(ProductStatusSummary::from_wire(&summary.to_wire()), summary);
}

#[test]
fn zero_bytes_left_differs_from_an_unknown_figure() {
    let known = full();
    let unknown = ProductStatusSummary { bytes_remaining: None, ..full() };
    assert_eq!(ProductStatusSummary::from_wire(&known.to_wire()).bytes_remaining, Some(0));
    assert_eq!(ProductStatusSummary::from_wire(&unknown.to_wire()).bytes_remaining, None);
}

#[test]
fn every_state_and_action_round_trips() {
    for state in [
        ProductState::UpToDate,
        ProductState::Syncing,
        ProductState::Waiting,
        ProductState::NeedsAttention,
        ProductState::Paused,
    ] {
        assert_eq!(ProductState::from_wire(state.to_wire()), state);
    }
    for action in [
        ProductAction::Retry,
        ProductAction::ReviewConflict,
        ProductAction::ReviewApproval,
        ProductAction::FreeUpSpace,
        ProductAction::RevealPath,
        ProductAction::OpenSettings,
        ProductAction::DownloadUpdate,
        ProductAction::ConfirmDisk,
        ProductAction::Resume,
        ProductAction::ViewDetails,
        ProductAction::StartOverAsNewDevice,
        ProductAction::SignIn,
    ] {
        assert_eq!(ProductAction::from_wire(action.to_wire()), Some(action));
    }
    assert_eq!(ProductAction::from_wire(Action::None), None);
}

#[test]
fn a_status_nobody_computed_never_reads_up_to_date() {
    assert_eq!(
        ProductStatusSummary::from_wire(&ProductStatus::default()).state,
        ProductState::NeedsAttention
    );
}
