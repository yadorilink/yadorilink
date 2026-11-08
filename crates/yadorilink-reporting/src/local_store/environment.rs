//! Builds the `ReportEnvironment` every generated report
//! envelope needs (`yadorilink-reporting::builder::ReportEnvironment`),
//! gathered once here from this process's own build/platform constants
//! and the caller-supplied consent state, rather than read directly by
//! `yadorilink-reporting` itself (see that crate's module doc comment for
//! why it stays platform-detection-free).
//!
//! `os_version_bucket` is the OS's major version ("27.x" on macOS, "10.x" or "11.x" on Windows),
//! read dependency-free from the system's own version command. Elsewhere it is `"unknown"`, a
//! valid coarse bucket rather than a guess. Never a build or patch level.

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

/// The OS's major version as a coarse bucket such as `"27.x"`, or `"unknown"`.
///
/// Asked of the system once per process: this runs for every report, including the one a panic
/// hook records, where starting a process again is best avoided.
pub fn os_version_bucket() -> String {
    static BUCKET: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BUCKET.get_or_init(read_os_version_bucket).clone()
}

fn read_os_version_bucket() -> String {
    // apple-cfg: macos-only sw_vers; iOS has no such command
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) =
            std::process::Command::new("/usr/bin/sw_vers").arg("-productVersion").output()
        {
            if out.status.success() {
                if let Some(bucket) = bucket_from_dotted(&String::from_utf8_lossy(&out.stdout)) {
                    return bucket;
                }
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(out) = std::process::Command::new("cmd").args(["/C", "ver"]).output() {
            if let Some(bucket) = bucket_from_windows_ver(&String::from_utf8_lossy(&out.stdout)) {
                return bucket;
            }
        }
    }
    "unknown".to_string()
}

/// The text of `cmd /C ver` ("Microsoft Windows [Version 10.0.26100.1234]") -> "11.x" for build
/// 22000 and later, "10.x" before it (Windows 11 still reports kernel version 10.0).
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn bucket_from_windows_ver(text: &str) -> Option<String> {
    let version = text
        .split("Version")
        .nth(1)?
        .trim_start()
        .split(|c: char| c == ']' || c.is_whitespace())
        .next()?;
    let mut parts = version.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let _minor: u32 = parts.next()?.parse().ok()?;
    let build: u32 = parts.next()?.parse().ok()?;
    Some(if major == 10 && build >= 22000 { "11.x".to_string() } else { format!("{major}.x") })
}

/// "27.0.1" -> "27.x"; anything that does not start with a number is no bucket.
// apple-cfg: macos-only sw_vers; iOS has no such command
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn bucket_from_dotted(version: &str) -> Option<String> {
    let major = version.trim().split('.').next()?;
    (!major.is_empty() && major.len() <= 4 && major.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("{major}.x"))
}

/// The current process's environment facts, for use in a freshly-built
/// report envelope. `consent.anonymous_reporter_id` is threaded straight
/// through — absent until the user opts in, never generated here.
pub fn current(consent: &ConsentState) -> ReportEnvironment {
    ReportEnvironment {
        generated_at: super::time::now_rfc3339(),
        yadorilink_version: env!("CARGO_PKG_VERSION").to_string(),
        os_family: os_family(),
        os_version_bucket: os_version_bucket(),
        arch: std::env::consts::ARCH.to_string(),
        install_channel: None,
        anonymous_reporter_id: consent.anonymous_reporter_id.clone(),
    }
}

#[cfg(test)]
mod tests;
