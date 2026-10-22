//! Prints a `ReplicaMembershipCommandOutcome` (`device remove`, `share
//! revoke`, `share revoke <edge-id>`): completed handoffs to stdout, and a
//! forced operation's data-loss warnings to stderr.
//!
//! The sentences themselves are `yadorilink_client_core::wording`'s, shared
//! with the desktop app, so a data-loss warning is never paraphrased into
//! something milder on one surface.

use std::io::Write;

use yadorilink_ipc_proto::daemonctl::ReplicaMembershipCommandOutcome;

use yadorilink_client_core::wording::{membership_outcome_notices, membership_outcome_warnings};

pub fn render_membership_outcome(action: &str, outcome: &ReplicaMembershipCommandOutcome) {
    render_membership_outcome_to(action, outcome, &mut std::io::stdout(), &mut std::io::stderr());
}

/// Testable core: writes to the given sinks instead of the real
/// stdout/stderr so tests can pin the exact rendered text.
fn render_membership_outcome_to(
    action: &str,
    outcome: &ReplicaMembershipCommandOutcome,
    out: &mut impl Write,
    err: &mut impl Write,
) {
    for notice in membership_outcome_notices(outcome) {
        let _ = writeln!(out, "{notice}");
    }
    for warning in membership_outcome_warnings(action, outcome) {
        let _ = writeln!(err, "{warning}");
    }
}

#[cfg(test)]
mod tests;
