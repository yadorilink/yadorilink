//! Which file actions a front end may offer for one item.
//!
//! The daemon decides eligibility; a shell or app only presents the answer. Every rule here is
//! the same gate the matching request enforces (`Evict` refuses a kept file and an ordinary
//! folder; a provider folder downloads through the operating system), so an offered action is
//! never a promise a later request would refuse. Anything unknown offers nothing.

use yadorilink_ipc_proto::daemonctl::FileAction;

/// What the daemon knows about one item's local copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ItemFacts {
    /// The daemon has a materialization row for the item.
    pub known: bool,
    /// The current version's bytes are on this device.
    pub current_content_present: bool,
    /// A hydrate or evict is under way.
    pub in_transition: bool,
    /// The item is a regular file (not a folder, link or missing).
    pub is_file: bool,
    /// The item is inside a provider folder (the operating system downloads and removes its
    /// downloads).
    pub provider_folder: bool,
    /// The daemon's own eviction gate accepts the item's root.
    pub reclaim_gate_open: bool,
    /// `Some(pinned, explicit)`; `None` when the policy could not be read.
    pub retention: Option<Retention>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Retention {
    pub pinned: bool,
    /// The pin was set at exactly this path rather than inherited from a folder above.
    pub explicit: bool,
}

/// Free Up Space is offered only for a file whose current bytes are here, that nothing is
/// moving, that is not kept, and whose root the eviction gate accepts.
pub(crate) fn free_up_space_offered(facts: &ItemFacts) -> bool {
    facts.reclaim_gate_open
        && facts.is_file
        && facts.current_content_present
        && !facts.in_transition
        && facts.retention.is_some_and(|r| !r.pinned)
}

/// The actions available for the item, in presentation order.
pub(crate) fn available_actions(facts: &ItemFacts) -> Vec<FileAction> {
    if !facts.known || facts.in_transition {
        return Vec::new();
    }
    let mut actions = Vec::new();
    if facts.current_content_present {
        if facts.provider_folder && free_up_space_offered(facts) {
            actions.push(FileAction::FreeUpSpace);
        }
    } else if !facts.provider_folder {
        actions.push(FileAction::Download);
    }
    // A file kept only because a folder above is has neither keep action: that folder is what
    // to release.
    match facts.retention {
        Some(Retention { pinned: false, .. }) => actions.push(FileAction::KeepOnDevice),
        Some(Retention { pinned: true, explicit: true }) => actions.push(FileAction::StopKeeping),
        Some(Retention { pinned: true, explicit: false }) | None => {}
    }
    actions
}

#[cfg(test)]
mod tests;
