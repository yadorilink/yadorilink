//! The installer a script install keeps for `yadorilink self-update` to run.
//!
//! In short: the verifier of what gets
//! installed is the installer, and only the installer. A bundle for a script install carries the
//! installer script; the installer proves it with the rest of the bundle (SHA256SUMS, the engine
//! identity, the signed manifest), keeps a copy under `<share>/installer/` and records, in the
//! install receipt, the hash it was proven to have. This module never downloads or verifies a
//! bundle. It checks one thing before running the kept copy: that the file is still the bytes the
//! installer recorded. The bytes it checked are the bytes it runs (they are handed to the shell on
//! standard input), so the file cannot change between the check and the run.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use sha2::{Digest as _, Sha256};

/// What to do about the kept installer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// No installer was recorded (an install from before bundles carried one): print the command, as before.
    Print,
    /// The verified bytes of the kept installer.
    Run(Vec<u8>),
    /// Do not run anything: why, with the way out.
    Refuse(String),
}

/// Where a user re-runs the installer from when the kept copy cannot be used.
const REINSTALL: &str = "curl -fsSL https://yadori.link/install.sh | sh";

/// The directory the installer keeps its receipt and kept copy in: `<prefix>/share/yadorilink`.
pub(crate) fn install_dir(prefix: &Path) -> std::path::PathBuf {
    prefix.join("share").join("yadorilink")
}

fn receipt_get(receipt: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    receipt
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::to_owned)
        .filter(|v| !v.is_empty())
}

fn refuse(why: &str) -> Plan {
    Plan::Refuse(format!(
        "the installer kept for updating does not match what was verified when it was installed \
         ({why}); nothing was run and nothing was changed. Run the one-line installer again to \
         reinstall: {REINSTALL}"
    ))
}

/// Decides from the receipt under `share` (`<prefix>/share/yadorilink`) and the file it names.
pub(crate) fn plan_in(share: &Path) -> Plan {
    let Ok(receipt) = std::fs::read_to_string(share.join("install-receipt")) else {
        return Plan::Print;
    };
    let Some(recorded) = receipt_get(&receipt, "installer_sha256") else {
        return Plan::Print;
    };
    if recorded.len() != 64 || !recorded.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return refuse("the receipt's recorded hash is malformed");
    }
    // The path is derived from the install directory, never taken from the receipt.
    let path = share.join("installer").join("install.sh");
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return refuse("the file is missing");
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return refuse("it is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if meta.permissions().mode() & 0o022 != 0 {
            return refuse("other users can write to it");
        }
        if let Ok(dir) = std::fs::metadata(share) {
            if dir.uid() != meta.uid() {
                return refuse("it is not owned by the user who owns the install");
            }
        }
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return refuse("it cannot be read");
    };
    let actual: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    if actual != recorded {
        return refuse("its contents changed");
    }
    Plan::Run(bytes)
}

/// How the installer is called: its arguments.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Call {
    pub args: Vec<String>,
}

/// Runs the verified installer bytes with `call`, output and exit status passed through. Returns
/// the status. The script goes to the shell on standard input.
pub(crate) fn run(script: &[u8], call: &Call) -> std::io::Result<i32> {
    let args = &call.args;
    let mut child =
        Command::new("sh").arg("-s").arg("--").args(args).stdin(Stdio::piped()).spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        // A script that exits before reading all of itself closes the pipe: not an error here.
        let _ = stdin.write_all(script);
    }
    let status = child.wait()?;
    Ok(status.code().unwrap_or(1))
}

/// The installer's own status for "the live manifest is signed with a key this installer does not
/// pin": the installation is too far behind to update itself.
pub(crate) const STATUS_KEY_NOT_PINNED: i32 = 22;

/// A line to add after the installer's own output for a status that has a standing answer.
pub(crate) fn guidance_for(status: i32) -> Option<String> {
    (status == STATUS_KEY_NOT_PINNED).then(|| {
        format!(
            "This installation is too far behind to update itself: the release keys have changed \
             since it was installed. Nothing was changed. Run the one-line installer again, which \
             comes with the current keys: {REINSTALL}"
        )
    })
}

#[cfg(test)]
mod tests;
