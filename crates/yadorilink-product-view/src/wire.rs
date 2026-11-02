//! The product status on the control protocol (`ProductStatus`): the daemon computes a
//! [`ProductStatusSummary`] once and sends it, and every reader maps it back instead of deriving
//! the state again.
//!
//! The wire message carries what a front end shows: the state, the four counts, the figure of
//! bytes left, the one action to offer, availability and protection with their devices. The
//! reasons behind a state travel as the daemon's `attention_reasons` and the per-folder flags
//! they come from, so a summary read back from the wire has no `attention_reasons` of its own.

use yadorilink_ipc_proto::daemonctl::product_status::{Action, State};
use yadorilink_ipc_proto::daemonctl::{ProductStatus, StatusResponse};

use crate::attention::ProductAction;
use crate::availability::{Availability, AvailabilitySummary};
use crate::protection::{Protection, ProtectionSummary};
use crate::summary::{ProductState, ProductStatusSummary};

impl ProductState {
    pub fn to_wire(self) -> State {
        match self {
            ProductState::UpToDate => State::UpToDate,
            ProductState::Syncing => State::Syncing,
            ProductState::Waiting => State::Waiting,
            ProductState::NeedsAttention => State::NeedsAttention,
            ProductState::Paused => State::Paused,
        }
    }

    /// An unset state (a message that was never filled) reads as needing attention: a front end
    /// must not show "up to date" for a status nobody computed.
    pub fn from_wire(wire: State) -> Self {
        match wire {
            State::UpToDate => ProductState::UpToDate,
            State::Syncing => ProductState::Syncing,
            State::Waiting => ProductState::Waiting,
            State::Paused => ProductState::Paused,
            State::NeedsAttention | State::Unspecified => ProductState::NeedsAttention,
        }
    }
}

impl ProductAction {
    pub fn to_wire(self) -> Action {
        match self {
            ProductAction::Retry => Action::Retry,
            ProductAction::ReviewConflict => Action::ReviewConflict,
            ProductAction::ReviewApproval => Action::ReviewApproval,
            ProductAction::FreeUpSpace => Action::FreeUpSpace,
            ProductAction::RevealPath => Action::RevealPath,
            ProductAction::OpenSettings => Action::OpenSettings,
            ProductAction::DownloadUpdate => Action::DownloadUpdate,
            ProductAction::ConfirmDisk => Action::ConfirmDisk,
            ProductAction::Resume => Action::Resume,
            ProductAction::ViewDetails => Action::ViewDetails,
            ProductAction::StartOverAsNewDevice => Action::StartOverAsNewDevice,
            ProductAction::SignIn => Action::SignIn,
        }
    }

    /// `None` for "nothing to offer".
    pub fn from_wire(wire: Action) -> Option<Self> {
        Some(match wire {
            Action::None => return None,
            Action::Retry => ProductAction::Retry,
            Action::ReviewConflict => ProductAction::ReviewConflict,
            Action::ReviewApproval => ProductAction::ReviewApproval,
            Action::FreeUpSpace => ProductAction::FreeUpSpace,
            Action::RevealPath => ProductAction::RevealPath,
            Action::OpenSettings => ProductAction::OpenSettings,
            Action::DownloadUpdate => ProductAction::DownloadUpdate,
            Action::ConfirmDisk => ProductAction::ConfirmDisk,
            Action::Resume => ProductAction::Resume,
            Action::ViewDetails => ProductAction::ViewDetails,
            Action::StartOverAsNewDevice => ProductAction::StartOverAsNewDevice,
            Action::SignIn => ProductAction::SignIn,
        })
    }
}

impl ProductStatusSummary {
    /// The message the daemon sends.
    pub fn to_wire(&self) -> ProductStatus {
        ProductStatus {
            state: self.state.to_wire() as i32,
            attention_count: self.attention_count,
            paused_count: self.paused_count,
            syncing_count: self.syncing_count,
            waiting_count: self.waiting_count,
            bytes_remaining_known: self.bytes_remaining.is_some(),
            bytes_remaining: self.bytes_remaining.unwrap_or(0),
            next_action: self.next_action.map_or(Action::None, ProductAction::to_wire) as i32,
            availability: self.availability.availability.to_wire() as i32,
            availability_reachable_device_ids: self.availability.reachable_device_ids.clone(),
            availability_offline_device_ids: self.availability.offline_device_ids.clone(),
            availability_update_required_device_ids: self
                .availability
                .update_required_device_ids
                .clone(),
            protection: self.protection.protection.to_wire() as i32,
            protection_device_ids: self.protection.device_ids.clone(),
        }
    }

    /// The summary a reader shows, from the message the daemon sent. `attention_reasons` and
    /// `general_attention` stay empty: the wire carries the counts and the action, and the
    /// reasons come from the status reply's own `attention_reasons` and the folders' flags.
    pub fn from_wire(wire: &ProductStatus) -> Self {
        ProductStatusSummary {
            state: ProductState::from_wire(wire.state()),
            attention_count: wire.attention_count,
            paused_count: wire.paused_count,
            syncing_count: wire.syncing_count,
            waiting_count: wire.waiting_count,
            attention_reasons: Vec::new(),
            general_attention: Vec::new(),
            bytes_remaining: wire.bytes_remaining_known.then_some(wire.bytes_remaining),
            availability: AvailabilitySummary {
                availability: Availability::from_wire(wire.availability()),
                reachable_device_ids: wire.availability_reachable_device_ids.clone(),
                offline_device_ids: wire.availability_offline_device_ids.clone(),
                update_required_device_ids: wire.availability_update_required_device_ids.clone(),
            },
            protection: ProtectionSummary {
                protection: Protection::from_wire(wire.protection()),
                device_ids: wire.protection_device_ids.clone(),
            },
            next_action: ProductAction::from_wire(wire.next_action()),
        }
    }
}

/// Computes the product status of every folder and of the whole device, once, from a finished
/// reply, and stores it on the reply. The daemon calls it last, so the device-level reasons it
/// counts are the ones the reply carries; it reads only what the reply already holds and adds no
/// read of its own to the status path.
pub fn fill_product_status(response: &mut StatusResponse) {
    for link in &mut response.links {
        link.product = Some(ProductStatusSummary::for_folder(link).to_wire());
    }
    response.product = Some(ProductStatusSummary::global_of(response).to_wire());
}

#[cfg(test)]
mod tests;
