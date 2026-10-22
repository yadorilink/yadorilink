//! The one place that decides where the engine keeps its state: the device
//! identity and config, the sync database, the block store, logs, the
//! credential-file fallback, and the names of the local IPC endpoints derived
//! from it. Every process (daemon, CLI, client core, the Cloud Files host)
//! asks here; nothing else reads `YADORILINK_CONFIG_DIR`, the per-path overrides
//! ([`PathOverride`]) or an application data variable (a test over the source tree keeps it so).
//!
//! On Windows the directory is `%USERPROFILE%\.yadorilink` for every install
//! type. A packaged (MSIX) process that creates files under `%APPDATA%` or
//! `%LOCALAPPDATA%` writes into a per-package virtualized store that is
//! deleted on uninstall and invisible to unpackaged processes, so state kept
//! there would silently vanish or split in two. A packaged process therefore
//! refuses to run with a state directory under AppData ([`check_placement`]). The refusal is a
//! property of the resolver: [`state_dir`] and [`checked_override`] return the typed
//! [`StateDirError`] instead of a path, so a caller cannot create or write anything first.
//! Elsewhere the directory is the per-OS application data directory.
//!
//! The path logic is pure over [`Env`] so it is tested on every platform.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The environment the decision reads. [`Env::from_process`] fills it from the
/// real process; tests inject their own.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// `YADORILINK_CONFIG_DIR`.
    pub config_dir: Option<OsString>,
    pub home: Option<OsString>,
    pub xdg_data_home: Option<OsString>,
    pub userprofile: Option<OsString>,
    pub appdata: Option<OsString>,
    pub localappdata: Option<OsString>,
    /// The per-path overrides, indexed by [`PathOverride`].
    pub overrides: [Option<OsString>; PathOverride::ALL.len()],
    /// Whether the process runs with package (MSIX) identity.
    pub packaged: bool,
}

impl Env {
    #[must_use]
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
        Self {
            config_dir: var("YADORILINK_CONFIG_DIR"),
            home: var("HOME"),
            xdg_data_home: var("XDG_DATA_HOME"),
            userprofile: var("USERPROFILE"),
            appdata: var("APPDATA"),
            localappdata: var("LOCALAPPDATA"),
            overrides: PathOverride::ALL.map(|which| var(which.variable())),
            packaged: has_package_identity(),
        }
    }
}

/// The environment variables that move one part of the state away from the state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathOverride {
    BlockStore,
    SyncDb,
    ProviderTempRoot,
    WitnessDir,
    /// `YADORILINK_CREDENTIAL_FILE`: where the credential file backend keeps its document.
    CredentialFile,
    /// `YADORILINK_LOG_FILE`: the daemon's log file.
    LogFile,
}

impl PathOverride {
    pub const ALL: [Self; 6] = [
        Self::BlockStore,
        Self::SyncDb,
        Self::ProviderTempRoot,
        Self::WitnessDir,
        Self::CredentialFile,
        Self::LogFile,
    ];

    /// The variable that carries the override.
    #[must_use]
    pub const fn variable(self) -> &'static str {
        match self {
            Self::BlockStore => "YADORILINK_BLOCK_STORE",
            Self::SyncDb => "YADORILINK_SYNC_DB",
            Self::ProviderTempRoot => "YADORILINK_PROVIDER_TEMP_ROOT",
            Self::WitnessDir => "YADORILINK_WITNESS_DIR",
            Self::CredentialFile => "YADORILINK_CREDENTIAL_FILE",
            Self::LogFile => "YADORILINK_LOG_FILE",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Why the state directory could not be decided or may not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateDirError {
    #[error("no home directory is available to place the YadoriLink state directory")]
    NoHome,
    #[error(
        "the YadoriLink state directory {dir} is under AppData, which a packaged app cannot \
         keep data in: Windows stores such files in a per-app copy that is deleted when the \
         app is uninstalled and that other programs cannot see. Unset YADORILINK_CONFIG_DIR \
         to use {default}, or point it outside AppData."
    )]
    UnderAppDataWhilePackaged { dir: PathBuf, default: PathBuf },
    #[error(
        "{variable} points to {path}, which is under AppData. A packaged app cannot keep data \
         there: Windows stores such files in a per-app copy that is deleted when the app is \
         uninstalled and that other programs cannot see. Unset {variable} or point it outside \
         AppData."
    )]
    OverrideUnderAppDataWhilePackaged { variable: &'static str, path: PathBuf },
}

/// The state directory for `env`, ignoring the packaged-placement rule.
pub fn resolve(env: &Env) -> Result<PathBuf, StateDirError> {
    if let Some(dir) = &env.config_dir {
        let dir = PathBuf::from(dir);
        // A relative override would name a different place in each process's working directory.
        #[cfg(windows)]
        let dir = std::path::absolute(&dir).unwrap_or(dir);
        return Ok(dir);
    }
    default_dir(env)
}

/// The directory used when `YADORILINK_CONFIG_DIR` is not set.
pub fn default_dir(env: &Env) -> Result<PathBuf, StateDirError> {
    default_dir_for(env, cfg!(windows))
}

fn default_dir_for(env: &Env, windows: bool) -> Result<PathBuf, StateDirError> {
    if windows {
        let profile = env.userprofile.as_ref().ok_or(StateDirError::NoHome)?;
        return Ok(PathBuf::from(profile).join(".yadorilink"));
    }
    let home = env.home.as_ref().ok_or(StateDirError::NoHome)?;
    let home = PathBuf::from(home);
    let base = if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support")
    } else if cfg!(target_os = "linux") {
        env.xdg_data_home.as_ref().map_or_else(|| home.join(".local").join("share"), PathBuf::from)
    } else {
        home
    };
    Ok(base.join("yadorilink"))
}

/// Refuses a state directory under AppData for a process with package identity.
pub fn check_placement(env: &Env, dir: &Path) -> Result<(), StateDirError> {
    if !env.packaged {
        return Ok(());
    }
    let roots = app_data_roots(env);
    if roots.iter().any(|root| is_within(dir, root)) {
        let default = default_dir_for(env, true)
            .unwrap_or_else(|_| PathBuf::from(r"%USERPROFILE%\.yadorilink"));
        return Err(StateDirError::UnderAppDataWhilePackaged { dir: dir.to_path_buf(), default });
    }
    Ok(())
}

/// The directory an earlier (unpackaged installer) build kept its state in on
/// Windows: `%APPDATA%\yadorilink`. It is never read, migrated or deleted.
pub fn legacy_windows_dir(env: &Env) -> Option<PathBuf> {
    env.appdata.as_ref().map(|a| PathBuf::from(a).join("yadorilink"))
}

/// Names the legacy directory when it still exists and holds engine state.
pub fn legacy_windows_dir_in_use(env: &Env) -> Option<PathBuf> {
    let dir = legacy_windows_dir(env)?;
    (dir.join("device.json").exists() || dir.join("blocks").exists()).then_some(dir)
}

/// The text shown for the left-over legacy directory.
#[must_use]
pub fn legacy_notice(legacy: &Path, current: &Path) -> String {
    format!(
        "An earlier YadoriLink build kept its data in {}. That data is not used and was not \
         changed: this version keeps its state in {} and starts from scratch. Remove the old \
         folder yourself once you no longer need it.",
        legacy.display(),
        current.display()
    )
}

/// The record an earlier build's Cloud Files host kept of its registered sync roots, in
/// `%LOCALAPPDATA%\yadorilink`. It is the base name of the record's generation files.
pub fn legacy_sync_roots_record(env: &Env) -> Option<PathBuf> {
    env.localappdata.as_ref().map(|l| PathBuf::from(l).join("yadorilink").join(SYNC_ROOTS_RECORD))
}

const SYNC_ROOTS_RECORD: &str = "cfapi_sync_roots.txt";

/// Names that record when it still holds a record (a complete or an unreadable generation; a
/// retired one does not count) and is not the current state directory's own record.
pub fn legacy_sync_roots_record_in_use(env: &Env, current: &Path) -> Option<PathBuf> {
    let record = legacy_sync_roots_record(env)?;
    if same_dir(record.parent()?, current) {
        return None;
    }
    let latest = crate::generation::read_latest(&record, |t| {
        crate::generation::unseal(t).map(str::to_string)
    });
    (!matches!(latest, crate::generation::Latest::Missing)).then_some(record)
}

/// The text shown when an earlier build's sync-root record is left behind. The roots it names
/// may still be registered with Windows; they are only unregistered on request.
#[must_use]
pub fn legacy_sync_roots_notice(record: &Path) -> String {
    format!(
        "An earlier YadoriLink build recorded its Windows sync roots in {}. This version does \
         not read that record, so those roots may still be registered with Windows without a \
         host to serve them. To unregister them (your files are not touched), run \
         `yadorilink-cfapi-host --unregister-legacy-roots`; it is safe to run again.",
        record.display()
    )
}

/// AppData and the folders below it that the packaging layer virtualizes: the two variables, the
/// `AppData` folder that holds them (which also covers `LocalLow`) and the profile's own
/// `AppData`, so a missing or redirected variable cannot hide it.
fn app_data_roots(env: &Env) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for (value, leaf) in [(&env.appdata, "roaming"), (&env.localappdata, "local")] {
        let Some(value) = value else { continue };
        let root = PathBuf::from(value);
        // Only a variable that really names `...\AppData\<leaf>` yields its parent; otherwise
        // the parent could be a drive root or any unrelated folder.
        let parts = components(&root);
        if parts.len() >= 2 && parts.last().is_some_and(|l| l == leaf) {
            let parent = parts[..parts.len() - 1].join(r"\");
            if parts[parts.len() - 2] == "appdata" {
                roots.push(PathBuf::from(parent));
            }
        }
        roots.push(root);
    }
    if let Some(profile) = &env.userprofile {
        roots.push(PathBuf::from(profile).join("AppData"));
    }
    roots
}

/// A path as Windows compares it, lexically: `\` and `/` are one separator, the `\\?\`, `\\.\`
/// and `\??\` prefixes are dropped (`\\?\UNC\` becomes a UNC path), `.` and `..` are applied,
/// trailing dots and spaces of a name are ignored (Windows strips them), and case is folded.
fn components(path: &Path) -> Vec<String> {
    let text = path.to_string_lossy().replace('/', r"\");
    let mut rest = text.as_str();
    let mut unc =
        rest.starts_with(r"\\") && !rest.starts_with(r"\\?\") && !rest.starts_with(r"\\.\");
    for prefix in [r"\\?\", r"\\.\", r"\??\"] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped;
            break;
        }
    }
    // `get` yields `None` when the cut is not on a character boundary, so a multi-byte name
    // can neither panic nor match.
    if rest.get(..4).is_some_and(|head| head.eq_ignore_ascii_case(r"unc\")) {
        rest = &rest[4..];
        unc = true;
    }
    let mut parts: Vec<String> = Vec::new();
    if unc {
        parts.push(r"\\".to_string());
    }
    for name in rest.split('\\') {
        match name {
            "" | "." => {}
            ".." => {
                if parts.len() > 1 {
                    parts.pop();
                }
            }
            _ => {
                let name = name.trim_end_matches(['.', ' ']).to_lowercase();
                if !name.is_empty() {
                    parts.push(name);
                }
            }
        }
    }
    parts
}

/// `path` as the file system sees it: absolute, with short (8.3) names, junctions and symbolic
/// links of its existing part resolved, so a spelling cannot hide where it really points.
fn physical(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let mut tail = Vec::new();
        let mut current = absolute.clone();
        loop {
            if let Ok(resolved) = std::fs::canonicalize(&current) {
                return tail.iter().rev().fold(resolved, |acc, name| acc.join(name));
            }
            match (current.file_name().map(ToOwned::to_owned), current.parent()) {
                (Some(name), Some(parent)) => {
                    tail.push(name);
                    current = parent.to_path_buf();
                }
                _ => return absolute,
            }
        }
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

/// Whether two spellings name one directory (Windows rules, see [`components`]).
pub fn same_dir(a: &Path, b: &Path) -> bool {
    components(&physical(a)) == components(&physical(b))
}

/// Windows path containment of the spelled path and of where it really points.
fn is_within(path: &Path, root: &Path) -> bool {
    let contains = |path: &Path, root: &Path| {
        let (path, root) = (components(path), components(root));
        !root.is_empty() && path.starts_with(&root)
    };
    contains(path, root) || contains(&physical(path), &physical(root))
}

/// The usable state directory for `env`: [`resolve`] then [`check_placement`]. This is the only
/// way to obtain the directory, so a refused placement never becomes a path.
pub fn checked_state_dir(env: &Env) -> Result<PathBuf, StateDirError> {
    let dir = resolve(env)?;
    check_placement(env, &dir)?;
    Ok(dir)
}

/// The daemon's default log file inside `state_dir` where it logs to a file (Windows):
/// `<state dir>/logs/daemon.log`.
#[must_use]
pub fn daemon_log_file(state_dir: &Path) -> PathBuf {
    state_dir.join("logs").join("daemon.log")
}

/// The state directory of this process: `YADORILINK_CONFIG_DIR`, else the default, checked.
pub fn state_dir() -> Result<PathBuf, StateDirError> {
    checked_state_dir(&Env::from_process())
}

/// The usable path of a per-path override, `None` when it is not set.
pub fn checked_override(env: &Env, which: PathOverride) -> Result<Option<PathBuf>, StateDirError> {
    let Some(value) = &env.overrides[which.index()] else { return Ok(None) };
    let path = PathBuf::from(value);
    if check_placement(env, &path).is_err() {
        return Err(StateDirError::OverrideUnderAppDataWhilePackaged {
            variable: which.variable(),
            path,
        });
    }
    Ok(Some(path))
}

/// [`checked_override`] for this process.
pub fn process_override(which: PathOverride) -> Result<Option<PathBuf>, StateDirError> {
    checked_override(&Env::from_process(), which)
}

/// The suffix that makes a local IPC endpoint name specific to one state
/// directory, so a daemon and every client reading the same directory find
/// each other and two directories never share an endpoint.
#[must_use]
pub fn endpoint_suffix(dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let key = components(&physical(dir)).join(r"\");
    let digest = Sha256::digest(key.as_bytes());
    digest.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Windows named-pipe name for `kind` (`ctl`, `shell`) of the state directory `dir`.
#[must_use]
pub fn pipe_name(kind: &str, user: &str, dir: &Path) -> String {
    format!(r"\\.\pipe\yadorilink-{kind}-{user}-{}", endpoint_suffix(dir))
}

/// Control pipe of this process's state directory.
#[must_use]
pub fn control_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_CONTROL_PIPE") {
        return name;
    }
    pipe_name("ctl", &user_name(), &state_dir_or_default())
}

/// Shell/provider IPC pipe of this process's state directory.
#[must_use]
pub fn shell_ipc_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_SHELL_IPC_PIPE") {
        return name;
    }
    pipe_name("shell", &user_name(), &state_dir_or_default())
}

/// Daemon-to-cfapi-host dehydrate pipe of this process's state directory. The override is
/// debug builds only, as before.
#[must_use]
pub fn dehydrate_pipe_name() -> String {
    #[cfg(debug_assertions)]
    if let Ok(name) = std::env::var("YADORILINK_DEHYDRATE_PIPE") {
        return name;
    }
    pipe_name("dehydrate", &user_name(), &state_dir_or_default())
}

/// The directory a pipe name is derived from. A name creates nothing, so a refused directory
/// still names its (unconnectable) endpoint; the client that would use it fails at the check.
fn state_dir_or_default() -> PathBuf {
    resolve(&Env::from_process()).unwrap_or_else(|_| PathBuf::from("."))
}

fn user_name() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "default".into())
}

/// Whether this process runs with package identity.
#[must_use]
pub fn has_package_identity() -> bool {
    #[cfg(feature = "test-support")]
    if PACKAGE_IDENTITY_FOR_TEST.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentPackageFullName(length: *mut u32, name: *mut u16) -> i32;
        }
        const APPMODEL_ERROR_NO_PACKAGE: i32 = 15700;
        let mut length = 0u32;
        // SAFETY: a zero length with a null buffer only asks for the size.
        let status = unsafe { GetCurrentPackageFullName(&mut length, std::ptr::null_mut()) };
        status != APPMODEL_ERROR_NO_PACKAGE
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Makes this process claim package identity (tests of callers on any platform).
#[cfg(feature = "test-support")]
static PACKAGE_IDENTITY_FOR_TEST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "test-support")]
pub fn set_package_identity_for_test(packaged: bool) {
    PACKAGE_IDENTITY_FOR_TEST.store(packaged, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests;
