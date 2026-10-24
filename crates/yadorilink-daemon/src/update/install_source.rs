//! Install-source detection, reported in `PlatformInfo::install_source`
//! and in the update-check request. The daemon is notification-only today
//! (no download/install), so this exists only to tell the user, and the
//! manifest's applicability rules, how this copy was installed. `yadorilink
//! self-update` covers script installs; GUI installs are updated by their app
//! updater:
//! `standalone`, `apt` (Linux, via `dpkg-query -S`), `homebrew` (macOS,
//! via the Cask-written marker), `microsoft_store` / `winget` (Windows), `app_store` (iOS),
//! and, on every platform, `app_bundle` (the executable lies inside a macOS
//! application bundle), `container` (the image sets
//! `YADORILINK_INSTALL_SOURCE=container`) and `script` (the one-liner's
//! `install-receipt.json` sits beside the binaries): see [`refine`].
//!
//! The Windows and macOS parts have not been verified on a real machine
//! with the respective package manager; they are compile- and
//! unit-checked only.

use std::path::Path;
use std::process::Output;

/// Official download page for new versions (the daemon is notification-only today).
pub const DOWNLOAD_PAGE_URL: &str = "https://github.com/yadorilink/yadorilink/releases";

/// What to tell the user when a new version is available: package-managed
/// installs upgrade through their package manager, everything else
/// downloads the new version from [`DOWNLOAD_PAGE_URL`].
pub fn manual_update_guidance(install_source: &str) -> String {
    match install_source {
        "homebrew" => "This install is managed by Homebrew; run `brew upgrade --cask yadorilink`.".to_string(),
        "apt" => "This install is managed by apt; run `sudo apt update && sudo apt install --only-upgrade yadorilink`.".to_string(),
        "winget" => "This install is managed by WinGet; run `winget upgrade yadorilink`.".to_string(),
        "microsoft_store" => "This install is managed by the Microsoft Store; open Store > Library > Updates.".to_string(),
        "app_store" => "This install is managed by the App Store; updates arrive through the App Store.".to_string(),
        "app_bundle" => "This install is managed by the YadoriLink app; open YadoriLink and choose Check for Updates.".to_string(),
        "container" => "This install is managed by its container image; pull a newer image.".to_string(),
        _ => format!("Download the new version from {DOWNLOAD_PAGE_URL}"),
    }
}

/// The page to open for a new version, for installs that are not
/// package-managed. `None` for a package-managed install, whose steps are the
/// guidance.
pub fn manual_update_page(install_source: &str) -> Option<&'static str> {
    match install_source {
        "homebrew" | "apt" | "winget" | "microsoft_store" | "app_store" | "app_bundle"
        | "container" => None,
        _ => Some(DOWNLOAD_PAGE_URL),
    }
}

/// File the one-liner installer writes beside the installed binaries.
pub const SCRIPT_RECEIPT_FILE: &str = "install-receipt.json";

/// Environment variable an image sets to declare itself a container install.
pub const INSTALL_SOURCE_ENV: &str = "YADORILINK_INSTALL_SOURCE";

/// The path of the running executable with symlinks resolved. The one-liner installs a link
/// (`<prefix>/bin/yadorilink-daemon`) to the real program in its version directory, and on macOS
/// `current_exe()` reports the path the process was started by, i.e. the link; everything that
/// looks for files beside the program (the receipt, the engine identity) or records where the
/// install lives must use the real location. Falls back to the unresolved path. Not on Windows:
/// there `canonicalize` yields `\\?\` verbatim paths, and the installer's `bin` junction shows the
/// version directory's files (receipt, identity) beside the program anyway.
#[must_use]
pub fn running_exe() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    if cfg!(windows) {
        return exe;
    }
    std::fs::canonicalize(&exe).unwrap_or(exe)
}

/// Applies the platform-independent installation facts to what the platform's own detection
/// found (`detected`). Order: a container declaration, then a bundle path layout, then a
/// one-liner receipt (only over `standalone`, which is the absence of every other marker).
/// `env_value` is the value of [`INSTALL_SOURCE_ENV`]; only `container` is honoured.
pub fn refine(detected: String, exe: &Path, env_value: Option<&str>) -> String {
    if env_value == Some("container") {
        return "container".to_string();
    }
    if yadorilink_local_storage::ownership::is_app_bundle_path(exe) {
        return "app_bundle".to_string();
    }
    if detected == "standalone" && script_receipt_present(exe) {
        return "script".to_string();
    }
    detected
}

/// Whether `install-receipt.json` beside `exe` names the one-liner (`"source": "script"`).
/// Anything else, including an unreadable receipt, is not a script install.
fn script_receipt_present(exe: &Path) -> bool {
    let Some(dir) = exe.parent() else { return false };
    let Ok(bytes) = std::fs::read(dir.join(SCRIPT_RECEIPT_FILE)) else { return false };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("source").and_then(|s| s.as_str()).map(|s| s == "script"))
        .unwrap_or(false)
}

/// Injectable process runner so detection is unit-testable without the
/// platform tool on `PATH`. `SystemCommandRunner` is what production
/// code uses.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output>;
}

pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        std::process::Command::new(program).args(args).output()
    }
}

// ---- Linux --------------------------------------------------------------

/// Returns whether `dpkg-query -S <path>` reports `path` as owned by the
/// `yadorilink` package specifically. `path` must already be the exact
/// string `dpkg-query` would report — i.e. canonicalized — since dpkg
/// records the real, symlink-resolved path a package's files were
/// installed to, never a `PATH` symlink that happens to point at one.
fn dpkg_owns_path(runner: &dyn CommandRunner, path: &str) -> bool {
    let Ok(output) = runner.run("dpkg-query", &["-S", path]) else {
        return false;
    };
    if !output.status.success() {
        // Covers both: the path isn't owned by any package (the
        // coexisting-standalone-binary case this scoping exists for), and
        // dpkg-query missing entirely (non-Debian-family distros).
        return false;
    }
    // Each matching line looks like "<pkg>[, <pkg>...]: <path>" (dpkg
    // lists every package via a diversion, comma-separated, before the
    // colon; ordinarily just one).
    String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.split_once(':')
            .map(|(pkgs, listed_path)| {
                listed_path.trim() == path && pkgs.split(',').any(|p| p.trim() == "yadorilink")
            })
            .unwrap_or(false)
    })
}

/// `"apt"` when the exact binary currently running (`current_exe`,
/// canonicalized) is a file `dpkg-query -S` reports as owned by the
/// `yadorilink` package, else `"standalone"` — the same two-value shape
/// the Windows Store-vs-standalone split and the macOS
/// Homebrew check use, so `manager::PlatformInfo::install_source` stays a
/// plain, stable string across platforms.
///
/// Canonicalization failure (a deleted/replaced binary, or a `current_exe`
/// this process could not resolve at all) falls back to the path as given
/// — `dpkg-query -S` will then simply fail to match it, correctly falling
/// through to `"standalone"` rather than erroring.
pub fn detect_linux_install_source(runner: &dyn CommandRunner, current_exe: &Path) -> String {
    let canonical =
        std::fs::canonicalize(current_exe).unwrap_or_else(|_| current_exe.to_path_buf());
    let Some(path_str) = canonical.to_str() else {
        return "standalone".to_string();
    };
    if dpkg_owns_path(runner, path_str) {
        "apt".to_string()
    } else {
        "standalone".to_string()
    }
}

// ---- macOS --------------------------------------------------------------

/// Marker file this project's own Homebrew Cask (`Casks/yadorilink.rb` in
/// the `juntaki/homebrew-yadorilink` tap) writes from a `postflight`
/// block, and removes from an `uninstall`/`zap` block, after driving the
/// exact same signed `.pkg` a manual download would run. Root-owned
/// (Cask `pkg` installs always elevate via `sudo`, same as a manual
/// double-click), so a non-privileged process can only read it, never
/// forge it.
///
/// Unlike the Microsoft Store (a structural, unforgeable path signal) or
/// apt (dpkg already tracks package identity natively), a Homebrew Cask
/// wrapping a `.pkg` has no path- or receipt-based signal: `brew install
/// --cask` and a manual `.pkg` double-click both run `installer -pkg ...
/// -target /` and land the exact same files in the exact same places.
/// This marker, written by the Cask itself rather than by
/// the macOS installer's post-install script (which runs identically either
/// way and so cannot distinguish them), is the only reliable signal.
pub const HOMEBREW_MARKER_PATH: &str = "/etc/yadorilink/install_source";

/// `"homebrew"` when the Cask's marker file is present and contains
/// exactly that value, else `"standalone"` — the same shape
/// the Linux/Windows
/// Store-vs-standalone split use. A missing file (by far the common
/// case: a manual `.pkg` download, or a build predating this marker) is
/// not an error — it's the default, fully-supported path.
pub fn detect_macos_install_source() -> String {
    detect_macos_install_source_at(Path::new(HOMEBREW_MARKER_PATH))
}

/// Path-parameterized so tests exercise the real file-reading logic
/// against a tempdir path instead of mutating process-wide environment
/// state (this crate's test suite runs multi-threaded; a global env-var
/// override here would race exactly like the scan-hook tests this
/// workspace already isolates for that reason — see
/// `.github/workflows/release.yml`'s "Scan-hook lib tests"
/// step).
fn detect_macos_install_source_at(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(contents) if contents.trim() == "homebrew" => "homebrew".to_string(),
        _ => "standalone".to_string(),
    }
}

// ---- Windows ------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallSource {
    Standalone,
    MicrosoftStore,
    /// An iOS install: the App Store (or TestFlight) is the only source, so the engine never
    /// offers a download.
    AppStore,
}

impl InstallSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            InstallSource::Standalone => "standalone",
            InstallSource::MicrosoftStore => "microsoft_store",
            InstallSource::AppStore => "app_store",
        }
    }
}

/// Detects whether the currently-running executable was installed via
/// the Microsoft Store (MSIX packages are placed under
/// `%ProgramFiles%\WindowsApps\...` regardless of the app's own install
/// logic) or is a standalone install (a directly
/// installed `%ProgramFiles%\yadorilink\` layout). Spec "Microsoft Store install
/// delegates update": a Store install must never fetch or run a
/// standalone installer, so this detection gates that entirely — see
/// `manager::PlatformInfo::detect`.
///
/// The Windows app ships through the Microsoft Store as an MSIX package, and
/// that is what detects as `MicrosoftStore`; any other Windows install
/// detects as `Standalone`. The values `standalone` and `microsoft_store` are
/// what the Windows app and the update manifest already use, so they stay.
pub fn detect_windows_install_source(current_exe_path: &Path) -> InstallSource {
    let path_str = current_exe_path.to_string_lossy();
    if path_str.contains("WindowsApps") {
        InstallSource::MicrosoftStore
    } else {
        InstallSource::Standalone
    }
}

/// Registry location the Windows installer writes to when it is invoked with a `/PACKAGEMANAGER=<name>` command-line
/// parameter. `HKEY_LOCAL_MACHINE` (not `HKCU`) because the installer itself
/// always runs elevated (`PrivilegesRequired=admin`) and the value must be
/// readable regardless of which user account the daemon later runs as.
pub const PACKAGE_MANAGER_MARKER_KEY: &str = r"Software\yadorilink";
pub const PACKAGE_MANAGER_MARKER_VALUE: &str = "InstallSource";

/// Reads the package-manager marker this project's own installer writes
/// under [`PACKAGE_MANAGER_MARKER_KEY`]/[`PACKAGE_MANAGER_MARKER_VALUE`]
/// when driven by a `/PACKAGEMANAGER=<name>` switch — the mechanism a
/// WinGet manifest's `InstallerSwitches.Silent` string uses to tell this
/// installer it is being run by `winget` rather than by hand.
///
/// Unlike the Microsoft Store (whose MSIX layout is a structural,
/// unforgeable signal — see [`detect_windows_install_source`] above), WinGet runs
/// this exact same installer a manual download would, into the
/// exact same `%ProgramFiles%\yadorilink` layout: there is no path-based
/// signal to key off. This explicit, installer-written marker is the only
/// reliable way to tell the two apart. Returns `None` when the value is
/// absent — a manual/standalone install, or a build predating this
/// marker — and callers must treat that as "standalone", never as an
/// error: a missing marker is the overwhelmingly common, fully-supported
/// case.
///
/// **Not yet verified against a real Windows machine or a real WinGet
/// install** — matching this module's own header comment about
/// `detect_windows_install_source`'s verification status. the Windows installer's `README.md`
/// tracks this as an open verification item.
#[cfg(windows)]
pub fn detect_package_manager_marker() -> Option<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    unsafe {
        let subkey = to_wide(PACKAGE_MANAGER_MARKER_KEY);
        let mut hkey = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey)
            != ERROR_SUCCESS
        {
            return None;
        }

        let value_name = to_wide(PACKAGE_MANAGER_MARKER_VALUE);
        // Generous fixed buffer: this value is always a short ASCII
        // package-manager name ("winget"), never user-controlled free text.
        let mut buf = [0u16; 256];
        let mut buf_len = (buf.len() * std::mem::size_of::<u16>()) as u32;
        let mut value_type = 0u32;
        let status = RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            std::ptr::null(),
            &mut value_type,
            buf.as_mut_ptr().cast::<u8>(),
            &mut buf_len,
        );
        RegCloseKey(hkey);

        if status != ERROR_SUCCESS || value_type != REG_SZ {
            return None;
        }
        let chars = (buf_len as usize) / std::mem::size_of::<u16>();
        let s = String::from_utf16_lossy(&buf[..chars]);
        let s = s.trim_end_matches('\0').trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    }
}

/// Non-Windows stub so this module still compiles cross-platform;
/// never called outside a `#[cfg(windows)]` call site in `manager.rs`.
#[cfg(not(windows))]
pub fn detect_package_manager_marker() -> Option<String> {
    None
}

#[cfg(test)]
mod tests;
