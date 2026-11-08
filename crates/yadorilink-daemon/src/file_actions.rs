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
    /// The item is a directory.
    pub is_folder: bool,
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
    /// An `online_only` rule frees the item's copy.
    pub online_only: bool,
    /// The rule was set at exactly this path rather than inherited from a folder above.
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
    // A folder is not freed itself, but its rules are: Free Up Space on an online-only folder
    // runs the rule again for what it left behind.
    let folder_free_up_space = facts.is_folder
        && facts.provider_folder
        && facts.reclaim_gate_open
        && facts.retention.is_some_and(|r| r.online_only);
    if !facts.known || facts.in_transition {
        // A folder the daemon holds no state for still has its rules to choose from.
        if facts.is_folder && !facts.in_transition {
            let mut actions = Vec::new();
            if folder_free_up_space {
                actions.push(FileAction::FreeUpSpace);
            }
            if let Some(retention) = facts.retention {
                actions.extend(rule_actions(facts, retention));
            }
            return actions;
        }
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
    if folder_free_up_space {
        actions.push(FileAction::FreeUpSpace);
    }
    // Each rule is offered where it would change something. A rule inherited from a folder above
    // is replaced by setting another one here (an exception); "Default" is offered only where a
    // rule stands at exactly this path. Online only needs an operating-system copy to drop, so it
    // is a provider folder's choice.
    if let Some(retention) = facts.retention {
        actions.extend(rule_actions(facts, retention));
    }
    actions
}

/// The rule choices that would change something for an item.
fn rule_actions(facts: &ItemFacts, retention: Retention) -> Vec<FileAction> {
    let mut actions = Vec::new();
    if !retention.pinned {
        actions.push(FileAction::KeepOnDevice);
    }
    if facts.provider_folder && !retention.online_only {
        actions.push(FileAction::OnlineOnly);
    }
    if retention.explicit {
        actions.push(FileAction::Default);
    }
    actions
}

#[cfg(test)]
mod tests;
