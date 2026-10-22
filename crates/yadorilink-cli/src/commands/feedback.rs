//! `yadorilink feedback`: the
//! in-product pointer to the existing public-repo issue templates. This
//! is a *pointer*, not a new feedback system -- it only
//! tells a beta tester where to file structured feedback and reminds them how
//! automatic crash reporting stays local and consent-gated.

use crate::error::CliError;

/// The public repository's issue-template chooser -- the canonical entry point
/// for the existing bug/feedback templates. Kept as a constant so the pointer
/// and its test never drift.
pub const ISSUE_TEMPLATES_URL: &str = "https://github.com/yadorilink/yadorilink/issues/new/choose";

/// The rendered pointer text, kept separate from [`run`] so it is testable
/// without capturing stdout.
pub fn feedback_message() -> String {
    format!(
        "Beta feedback goes through the project's GitHub issue templates -- \
         yadorilink has no separate in-app feedback system.\n\n\
         Open a report:\n  {ISSUE_TEMPLATES_URL}\n\n\
         Found a crash? yadorilink captures a redacted, local-only crash report \
         automatically. Review exactly what it contains before anything leaves \
         your machine:\n  yadorilink report error --last\n\
         Nothing is ever submitted without your consent (see \
         `yadorilink report consent`)."
    )
}

pub fn run() -> Result<(), CliError> {
    println!("{}", feedback_message());
    Ok(())
}

#[cfg(test)]
mod tests;
