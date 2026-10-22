//! Builds the `ReportEnvironment` every generated report
//! envelope needs (`yadorilink-reporting::builder::ReportEnvironment`),
//! gathered once here from this process's own build/platform constants
//! and the caller-supplied consent state, rather than read directly by
//! `yadorilink-reporting` itself (see that crate's module doc comment for
//! why it stays platform-detection-free).
//!
//! `os_version_bucket` is deliberately `"unknown"`: there is no existing
//! dependency-free way in this workspace to read a coarse OS version
//! string (e.g. "14.x", "24.04") across macOS/Windows/Linux, and adding a
//! new dependency (e.g. `os_info`) for one field is out of scope. This
//! field is documented as "coarse, e.g....", not guaranteed-present, so
//! `"unknown"` is a valid, honest coarse bucket rather than a fabricated
//! one, rather than a silent guess.

use crate::builder::ReportEnvironment;
use crate::consent::ConsentState;
use crate::schema::OsFamily;

fn os_family() -> OsFamily {
    match std::env::consts::OS {
        "macos" => OsFamily::Macos,
        "windows" => OsFamily::Windows,
        "linux" => OsFamily::Linux,
        _ => OsFamily::Other,
    }
}

/// The current process's environment facts, for use in a freshly-built
/// report envelope. `consent.anonymous_reporter_id` is threaded straight
/// through — absent until the user opts in, never generated here.
pub fn current(consent: &ConsentState) -> ReportEnvironment {
    ReportEnvironment {
        generated_at: super::time::now_rfc3339(),
        yadorilink_version: env!("CARGO_PKG_VERSION").to_string(),
        os_family: os_family(),
        os_version_bucket: "unknown".to_string(),
        arch: std::env::consts::ARCH.to_string(),
        install_channel: None,
        anonymous_reporter_id: consent.anonymous_reporter_id.clone(),
    }
}

#[cfg(test)]
mod tests;
