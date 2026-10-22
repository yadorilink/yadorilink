//! `yadorilink uninstall`: removes a command-line (one-liner, `install_source=script`) install.
//!
//! What it removes is what the installer put there and recorded in its receipt: the two links in
//! `<prefix>/bin`, the version tree `<prefix>/share/yadorilink`, and the PATH block the installer
//! added to the shell profile. It never removes the user's synced folders. The data directory
//! (device identity, sync database, saved versions, block store) is kept unless `--purge-data`
//! is given. Every other install source is owned by another channel and is refused with that
//! owner's own uninstall steps, exactly as `self-update` refuses it. Nothing is inferred from
//! leftovers: an unreadable ownership record, a missing receipt or a path outside the recorded
//! install root stops the command before anything is removed.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use yadorilink_client_core::ops::{daemon, folders};
use yadorilink_fs_platform::state_dir::{self, PathOverride};
use yadorilink_local_storage::daemon_lock::{self, AcquireError, HeldLock};
use yadorilink_local_storage::ownership::{self, RecordState};
use yadorilink_sqlite_runtime::{read_link_registry, RegisteredLink};

use crate::error::CliError;

const STOP_BUDGET: Duration = Duration::from_secs(15);
const BINARIES: [&str; 2] = ["yadorilink", "yadorilink-daemon"];

/// What an uninstall removes. Built, and checked against the guards, before anything changes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub prefix: PathBuf,
    /// The version tree, `<prefix>/share/yadorilink`.
    pub share: PathBuf,
    /// Links in `<prefix>/bin` that point into `share`.
    pub links: Vec<PathBuf>,
    /// A shell profile holding the installer's PATH block.
    pub profile: Option<PathBuf>,
    /// The data directory, only with `--purge-data`.
    pub purge: Option<PathBuf>,
}

/// A linked folder as far as the removal warning needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FolderFacts {
    pub path: String,
    pub on_demand: bool,
    pub placeholders: u64,
}

fn refuse(message: String) -> CliError {
    CliError::ManagedElsewhere(message)
}

fn receipt_get(receipt: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    receipt
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::to_owned)
        .filter(|v| !v.is_empty())
}

/// Whose uninstall this is. `Err` is a refusal that changes nothing.
fn gate_on_record(record: &RecordState) -> Result<(), CliError> {
    match record {
        RecordState::Missing => Ok(()),
        RecordState::Unreadable(reason) => Err(refuse(format!(
            "the owner of YadoriLink on this machine is unknown ({reason}); nothing was stopped \
             or removed. Run `yadorilink doctor` for the fix."
        ))),
        RecordState::Present(r) => {
            if let Some(how) = ownership::uninstaller_elsewhere(&r.install_source) {
                return Err(refuse(format!(
                    "YadoriLink on this machine is installed by another channel ({}); `yadorilink \
                     uninstall` does not stop or remove anything of it. To uninstall: {how}. Your \
                     synced folders and YadoriLink's data are kept either way.",
                    r.install_source
                )));
            }
            if r.owner == ownership::Owner::Gui || r.install_source != "script" {
                return Err(refuse(format!(
                    "this YadoriLink is not a command-line install (source: {}), so `yadorilink \
                     uninstall` does not touch it. Remove it the way it was installed.",
                    if r.install_source.is_empty() { "unknown" } else { &r.install_source }
                )));
            }
            Ok(())
        }
    }
}

/// The installer prefix of `exe`, which must be the installer's layout.
fn prefix_of(exe: &Path) -> Result<PathBuf, CliError> {
    super::update::prefix_from_exe(exe, false).ok_or_else(|| {
        CliError::Other(
            "this `yadorilink` does not run from an installer layout (<prefix>/share/yadorilink/…), \
             so nothing was removed. Run `uninstall` from the installed copy."
                .into(),
        )
    })
}

fn canon(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Builds and checks the plan. Read-only.
pub(crate) fn build_plan(
    record: &RecordState,
    exe: &Path,
    home: &Path,
    config_dir: &Path,
    purge: bool,
) -> Result<Plan, CliError> {
    gate_on_record(record)?;
    let exe = canon(exe);
    let prefix = prefix_of(&exe)?;
    let share = prefix.join("share").join("yadorilink");
    let meta = std::fs::symlink_metadata(&share).map_err(|e| {
        CliError::Other(format!("cannot read {}: {e}; nothing was removed", share.display()))
    })?;
    if !meta.is_dir() {
        return Err(CliError::Other(format!(
            "{} is not a directory; nothing was removed",
            share.display()
        )));
    }
    let share = canon(&share);
    // The receipt is the installer's own statement of what it installed.
    let receipt_path = share.join("install-receipt");
    let receipt = std::fs::read_to_string(&receipt_path).map_err(|e| {
        CliError::Other(format!(
            "no readable install receipt at {} ({e}), so what the installer put here is not \
             known; nothing was removed. Remove {} and the `yadorilink` links in {} by hand, or \
             run the installer with `--uninstall`.",
            receipt_path.display(),
            share.display(),
            prefix.join("bin").display()
        ))
    })?;
    if receipt_get(&receipt, "install_source").as_deref() != Some("script") {
        return Err(refuse(
            "the install receipt does not say this is a command-line (script) install; nothing \
             was removed. Remove it the way it was installed."
                .into(),
        ));
    }
    if let RecordState::Present(r) = record {
        if !canon(Path::new(&r.install_root)).starts_with(&share) {
            return Err(CliError::Other(format!(
                "the recorded install root {} is not inside {}; nothing was removed",
                r.install_root,
                share.display()
            )));
        }
    }
    let bin = prefix.join("bin");
    let mut links = Vec::new();
    for name in BINARIES {
        let link = bin.join(name);
        if let Ok(target) = std::fs::read_link(&link) {
            let target = if target.is_relative() { bin.join(&target) } else { target };
            if target.starts_with(&share) || canon(&target).starts_with(&share) {
                links.push(link);
            }
        }
    }
    let profile = receipt_get(&receipt, "path_profile")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.starts_with(home) && p.is_file())
        .filter(|p| {
            std::fs::read_to_string(p).is_ok_and(|t| !path_block_ranges(&t, &prefix).is_empty())
        });
    // The program tree is deleted whole: the data directory must not live inside it (or contain it).
    let data = canon(config_dir);
    if data.starts_with(&share) || share.starts_with(&data) {
        return Err(CliError::Other(format!(
            "YadoriLink's data directory {} overlaps the program tree {}; removing the programs \
             would delete the data, so nothing was removed. Move the data directory out first.",
            data.display(),
            share.display()
        )));
    }
    let purge = purge.then(|| config_dir.to_path_buf());
    Ok(Plan { prefix, share, links, profile, purge })
}

/// Line ranges `[begin, end]` of the installer's PATH blocks for `prefix`.
fn path_block_ranges(text: &str, prefix: &Path) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut open: Option<usize> = None;
    for (i, line) in text.lines().enumerate() {
        if let Some(p) =
            line.strip_prefix("# >>> yadorilink (").and_then(|l| l.strip_suffix(") >>>"))
        {
            if open.is_none() && canon(Path::new(p)) == prefix {
                open = Some(i);
            }
        } else if let Some(p) =
            line.strip_prefix("# <<< yadorilink (").and_then(|l| l.strip_suffix(") <<<"))
        {
            if let Some(start) = open {
                if canon(Path::new(p)) == prefix {
                    ranges.push((start, i));
                    open = None;
                }
            }
        }
    }
    ranges
}

fn without_path_blocks(text: &str, prefix: &Path) -> String {
    let ranges = path_block_ranges(text, prefix);
    let mut out = String::new();
    for (i, line) in text.lines().enumerate() {
        if !ranges.iter().any(|&(a, b)| (a..=b).contains(&i)) {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The warnings about files that would become unreadable, and whether they need an explicit
/// `--yes`. `None` folders means the daemon could not be asked, so the count is unknown.
pub(crate) fn placeholder_warnings(folders: Option<&[FolderFacts]>) -> (Vec<String>, bool) {
    let Some(folders) = folders else {
        return (
            vec!["The daemon is not running, so YadoriLink cannot count files that were never \
                 downloaded to this computer (On-Demand placeholders). Such files cannot be \
                 opened here once YadoriLink is removed; they remain on your other devices. \
                 Start the daemon (`yadorilink daemon start`) to count them, or pass --yes to \
                 continue."
                .to_string()],
            true,
        );
    };
    let mut lines = Vec::new();
    for f in folders.iter().filter(|f| f.placeholders > 0) {
        lines.push(format!(
            "{}: {} file(s) were never downloaded to this computer{}.",
            f.path,
            f.placeholders,
            if f.on_demand { " (On-Demand folder)" } else { "" }
        ));
    }
    if !lines.is_empty() {
        lines.push(
            "These files cannot be opened here once YadoriLink is removed; they remain on your \
             other devices. Download the ones you need first, or pass --yes to continue."
                .to_string(),
        );
    }
    let needs_yes = !lines.is_empty();
    (lines, needs_yes)
}

fn describe(plan: &Plan) -> Vec<String> {
    let mut lines = Vec::new();
    for l in &plan.links {
        lines.push(format!("remove link {}", l.display()));
    }
    lines.push(format!("remove program files {}", plan.share.display()));
    if let Some(p) = &plan.profile {
        lines.push(format!("remove the PATH lines the installer added to {}", p.display()));
    }
    if let Some(d) = &plan.purge {
        lines.push(format!("DELETE YadoriLink's data directory {} (identity, sync database, saved versions, downloaded content)", d.display()));
    }
    lines
}

/// Removes what `plan` lists. The caller has stopped the daemon.
pub(crate) fn execute(plan: &Plan) -> std::io::Result<()> {
    for l in &plan.links {
        std::fs::remove_file(l)?;
    }
    if let Some(p) = &plan.profile {
        let text = std::fs::read_to_string(p)?;
        std::fs::write(p, without_path_blocks(&text, &plan.prefix))?;
    }
    std::fs::remove_dir_all(&plan.share)?;
    // Only an empty bin directory goes; anything else in it is not ours.
    let _ = std::fs::remove_dir(plan.prefix.join("bin"));
    if let Some(d) = &plan.purge {
        purge_dir(d)?;
    }
    Ok(())
}

/// Empties the data directory but leaves the directory and the daemon lock file (which this
/// process holds) in place: unlinking the lock file at any point would let a daemon that starts
/// meanwhile create and lock a fresh one beside the deletion. What remains is an empty
/// directory with one empty lock file, the state a first install starts from.
fn purge_dir(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name() == daemon_lock::LOCK_FILE_NAME {
            continue;
        }
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Where the stopped daemon keeps its state, from the same placement rules the daemon uses.
#[derive(Debug, Clone)]
pub(crate) struct StateLayout {
    pub config_dir: PathBuf,
    pub sync_db: PathBuf,
    pub block_store: PathBuf,
    pub provider_temp: Option<PathBuf>,
}

impl StateLayout {
    fn from_env() -> Result<Self, CliError> {
        let env = state_dir::Env::from_process();
        let config_dir = state_dir::checked_state_dir(&env)
            .map_err(|e| CliError::Other(format!("{e}; nothing was removed")))?;
        let over = |which| {
            state_dir::checked_override(&env, which)
                .map_err(|e| CliError::Other(format!("{e}; nothing was removed")))
        };
        Ok(Self {
            sync_db: over(PathOverride::SyncDb)?
                .unwrap_or_else(|| config_dir.join("sync-state.sqlite3")),
            block_store: over(PathOverride::BlockStore)?
                .unwrap_or_else(|| config_dir.join("blocks")),
            provider_temp: over(PathOverride::ProviderTempRoot)?,
            config_dir,
        })
    }
}

/// `p` with symlinks resolved as far as it exists, so a path that is not (yet) there still
/// compares by where it would be.
fn resolve(p: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        if let Ok(c) = std::fs::canonicalize(&cur) {
            return rest.iter().rev().fold(c, |acc, n| acc.join(n));
        }
        match (cur.file_name().map(std::ffi::OsStr::to_owned), cur.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                cur = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
}

fn overlaps(a: &Path, b: &Path) -> bool {
    let (a, b) = (resolve(a), resolve(b));
    a.starts_with(&b) || b.starts_with(&a)
}

/// Checks, from the registered `links` (every one, orphaned and provider included) and the
/// state layout, that the removal reaches no linked folder, no provider root and no data
/// directory it does not own. `Err` changes nothing. `--yes` has no say here.
pub(crate) fn check_removal_clear(
    plan: &Plan,
    layout: &StateLayout,
    links: &[RegisteredLink],
) -> Result<(), CliError> {
    for l in links {
        let kind = if l.provider_kind == "none" {
            "synced folder".to_string()
        } else {
            format!("{} provider root", l.provider_kind)
        };
        if overlaps(Path::new(&l.local_path), &plan.share) {
            return Err(CliError::Other(format!(
                "{kind} {} overlaps the program tree {}; removing the programs would delete it, \
                 so nothing was removed",
                l.local_path,
                plan.share.display()
            )));
        }
        if plan.purge.is_some() && overlaps(Path::new(&l.local_path), &layout.config_dir) {
            return Err(CliError::Other(format!(
                "{kind} {} overlaps the data directory {}; --purge-data would delete it, so \
                 nothing was removed",
                l.local_path,
                layout.config_dir.display()
            )));
        }
    }
    let state = [
        ("data directory", Some(&layout.config_dir)),
        ("sync database", Some(&layout.sync_db)),
        ("block store", Some(&layout.block_store)),
        ("provider temp directory", layout.provider_temp.as_ref()),
    ];
    for (what, path) in state {
        if let Some(p) = path.filter(|p| overlaps(p, &plan.share)) {
            return Err(CliError::Other(format!(
                "YadoriLink's {what} {} overlaps the program tree {}; removing the programs would \
                 delete it, so nothing was removed. Move it out first.",
                p.display(),
                plan.share.display()
            )));
        }
    }
    Ok(())
}

/// The registered links from the stopped daemon's on-disk state, read without starting it.
/// If they cannot be read the removal is refused: unknown is not "none".
fn registered_links(layout: &StateLayout) -> Result<Vec<RegisteredLink>, CliError> {
    match read_link_registry(&layout.sync_db) {
        Ok(links) => Ok(links.unwrap_or_default()),
        Err(why) => Err(CliError::Other(format!(
            "cannot tell which folders YadoriLink syncs, so it cannot be sure that removing the \
             programs deletes none of them: {why}. Nothing was removed. Start the daemon \
             (`yadorilink daemon start`) or repair/remove that database, then run this again; \
             --yes does not skip this check."
        ))),
    }
}

/// Takes the data area's runtime lock, the one a daemon holds for its whole life, so none can
/// start until this process ends. Another taker (a probe, a daemon coming up) is waited out
/// briefly; if the lock cannot be had the removal does not happen.
fn take_daemon_lock(config_dir: &Path) -> Result<HeldLock, CliError> {
    // A machine whose daemon never ran has no data directory yet; the lock file needs one.
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(config_dir).map_err(|e| {
        CliError::Other(format!(
            "cannot create the data directory {} to take the data-area lock ({e}); nothing was \
             removed",
            config_dir.display()
        ))
    })?;
    let mut tries = 0;
    loop {
        match HeldLock::acquire_daemon_lock(config_dir) {
            Ok(lock) => return Ok(lock),
            Err(AcquireError::Contended) if tries < 10 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(AcquireError::Contended) => {
                return Err(CliError::Other(
                    "a YadoriLink daemon is running or starting (the data-area lock is held), so \
                     nothing was removed. Stop it with `yadorilink daemon stop` and run this \
                     again."
                        .into(),
                ))
            }
            Err(AcquireError::Unusable(why)) => {
                return Err(CliError::Other(format!(
                    "cannot take the data-area lock to keep a daemon from starting ({why}); \
                     nothing was removed"
                )))
            }
        }
    }
}

/// The removal itself, after the daemon is stopped: holds the daemon lock until it returns,
/// re-checks the registered state under that lock, then removes. `locked` runs once the lock is
/// held, before the check (tests use it to act as a competing daemon).
pub(crate) fn remove_under_lock(
    plan: &Plan,
    layout: &StateLayout,
    locked: impl FnOnce(),
) -> Result<(), CliError> {
    let _lock = take_daemon_lock(&layout.config_dir)?;
    locked();
    check_removal_clear(plan, layout, &registered_links(layout)?)?;
    execute(plan).map_err(|e| {
        CliError::Other(format!("removal stopped part-way: {e}. Run `yadorilink uninstall` again, or the installer with --uninstall."))
    })
}

fn confirm(question: &str) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Cancelled(format!(
            "{question} -- no terminal to ask on; nothing was removed. Re-run with --yes."
        )));
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer).ok();
    if matches!(answer.trim(), "y" | "Y" | "yes") {
        Ok(())
    } else {
        Err(CliError::Cancelled("cancelled; nothing was removed".into()))
    }
}

/// `yadorilink uninstall [--dry-run] [--yes] [--purge-data]`.
pub async fn uninstall(dry_run: bool, yes: bool, purge_data: bool) -> Result<(), CliError> {
    if cfg!(windows) {
        return Err(CliError::Other(
            "on Windows, remove a script install with the installer: `& ([scriptblock]::Create((irm \
             https://yadori.link/install.ps1))) -Uninstall`. Your synced folders and data are kept."
                .into(),
        ));
    }
    let layout = StateLayout::from_env()?;
    let config_dir = layout.config_dir.clone();
    let record = ownership::read(&config_dir);
    let exe = std::env::current_exe()
        .map_err(|e| CliError::Other(format!("cannot find the running program: {e}")))?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Other("HOME is not set".into()))?;
    let plan = build_plan(&record, &exe, &home, &config_dir, purge_data)?;

    let facts: Option<Vec<FolderFacts>> = if daemon::is_running().await {
        folders::status().await.ok().map(|s| {
            s.links
                .iter()
                .map(|l| FolderFacts {
                    path: l.local_path.clone(),
                    on_demand: l.materialization_policy == "ondemand",
                    placeholders: l.placeholder_count,
                })
                .collect()
        })
    } else {
        None
    };
    let (warnings, needs_yes) = placeholder_warnings(facts.as_deref());
    // Before asking anything: the running daemon's list, or else the stopped daemon's own
    // registry. The check is repeated under the lock before anything is removed.
    let known: Vec<RegisteredLink> = match &facts {
        Some(f) => f
            .iter()
            .map(|f| RegisteredLink {
                local_path: f.path.clone(),
                provider_kind: "none".into(),
                orphaned: false,
            })
            .collect(),
        None if daemon::is_running().await => Vec::new(),
        None => registered_links(&layout)?,
    };
    check_removal_clear(&plan, &layout, &known)?;

    println!("{}:", if dry_run { "Would remove" } else { "About to remove" });
    for line in describe(&plan) {
        println!("  {line}");
    }
    println!("Never removed: your synced folders.");
    if !purge_data {
        println!(
            "Kept: YadoriLink's data directory {}. Remove it later with `rm -rf` on that \
             directory, or uninstall again with --purge-data.",
            config_dir.display()
        );
    }
    for w in &warnings {
        println!("WARNING: {w}");
    }
    if dry_run {
        println!("Dry run: nothing was changed.");
        return Ok(());
    }
    if needs_yes && !yes {
        return Err(CliError::Cancelled(
            "nothing was removed; re-run with --yes to continue".into(),
        ));
    }
    if !yes {
        let question = if purge_data {
            "Also delete the data directory, including saved versions that no other device may hold?"
        } else {
            "Uninstall YadoriLink?"
        };
        confirm(question)?;
    } else if purge_data {
        println!("--purge-data with --yes: the data directory will be deleted.");
    }

    daemon::stop_and_wait(STOP_BUDGET).await?;
    remove_under_lock(&plan, &layout, || {})?;
    println!("Removed. Your device is still registered with your account; run `yadorilink logout` before uninstalling to revoke it, or remove it from another device.");
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ownership::{Owner, OwnershipRecord};

    struct Tree {
        _dir: tempfile::TempDir,
        root: PathBuf,
        exe: PathBuf,
        home: PathBuf,
        config: PathBuf,
        profile: PathBuf,
        outside: PathBuf,
    }

    fn script_record(root: &Path) -> RecordState {
        RecordState::Present(OwnershipRecord {
            owner: Owner::Cli,
            install_source: "script".into(),
            install_root: root.display().to_string(),
            release_id: String::new(),
            written_at: 1,
        })
    }

    fn tree() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let prefix = home.join(".local");
        let vdir = prefix.join("share/yadorilink/1.0.0");
        std::fs::create_dir_all(&vdir).unwrap();
        std::fs::create_dir_all(prefix.join("bin")).unwrap();
        let exe = vdir.join("yadorilink");
        std::fs::write(&exe, b"cli").unwrap();
        std::fs::write(vdir.join("yadorilink-daemon"), b"daemon").unwrap();
        for n in BINARIES {
            std::os::unix::fs::symlink(vdir.join(n), prefix.join("bin").join(n)).unwrap();
        }
        let profile = home.join(".profile");
        std::fs::write(
            &profile,
            format!(
                "export A=1\n# >>> yadorilink ({p}) >>>\nexport PATH=\"{p}/bin:$PATH\"\n# <<< yadorilink ({p}) <<<\nexport B=2\n",
                p = prefix.display()
            ),
        )
        .unwrap();
        std::fs::write(
            prefix.join("share/yadorilink/install-receipt"),
            format!(
                "version=1.0.0\ndir={}\ninstall_source=script\npath_profile={}\n",
                vdir.display(),
                profile.display()
            ),
        )
        .unwrap();
        let config = home.join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("device.json"), b"{}").unwrap();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), b"mine").unwrap();
        Tree { _dir: dir, root, exe, home, config, profile, outside }
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn snapshot(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        fn walk(p: &Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(p).unwrap() {
                let e = e.unwrap();
                out.push(e.path().display().to_string());
                if e.file_type().unwrap().is_dir() {
                    walk(&e.path(), out);
                }
            }
        }
        walk(dir, &mut out);
        out.sort();
        out
    }

    #[test]
    fn plan_lists_exactly_what_the_installer_put_there() {
        let t = tree();
        let plan =
            build_plan(&script_record(t.exe.parent().unwrap()), &t.exe, &t.home, &t.config, false)
                .unwrap();
        assert_eq!(plan.share, t.home.join(".local/share/yadorilink"));
        assert_eq!(plan.links.len(), 2);
        assert_eq!(plan.profile.as_deref(), Some(t.profile.as_path()));
        assert_eq!(plan.purge, None);
        // Planning changes nothing.
        assert!(t.exe.exists());
    }

    #[test]
    fn executing_removes_programs_links_and_path_lines_but_keeps_data_and_other_files() {
        let t = tree();
        let before_outside = snapshot(&t.outside);
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        execute(&plan).unwrap();
        assert!(!t.home.join(".local/share/yadorilink").exists());
        assert!(!t.home.join(".local/bin").exists(), "empty bin goes");
        assert_eq!(std::fs::read_to_string(&t.profile).unwrap(), "export A=1\nexport B=2\n");
        assert!(t.config.join("device.json").exists(), "data kept by default");
        assert_eq!(snapshot(&t.outside), before_outside);
    }

    #[test]
    fn a_foreign_file_in_bin_survives_and_keeps_the_directory() {
        let t = tree();
        std::fs::write(t.home.join(".local/bin/other-tool"), b"x").unwrap();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        execute(&plan).unwrap();
        assert!(t.home.join(".local/bin/other-tool").exists());
    }

    #[test]
    fn a_link_pointing_elsewhere_is_not_ours_and_is_left() {
        let t = tree();
        let link = t.home.join(".local/bin/yadorilink");
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(t.outside.join("keep.txt"), &link).unwrap();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        assert_eq!(plan.links.len(), 1);
        execute(&plan).unwrap();
        assert!(std::fs::symlink_metadata(&link).is_ok());
        assert!(t.outside.join("keep.txt").exists());
    }

    #[test]
    fn purge_data_is_the_only_way_the_data_directory_goes() {
        let t = tree();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, true).unwrap();
        assert_eq!(plan.purge.as_deref(), Some(t.config.as_path()));
        execute(&plan).unwrap();
        assert!(!t.config.join("device.json").exists());
        assert!(t.outside.join("keep.txt").exists());
    }

    fn layout(t: &Tree) -> StateLayout {
        StateLayout {
            config_dir: t.config.clone(),
            sync_db: t.config.join("sync-state.sqlite3"),
            block_store: t.config.join("blocks"),
            provider_temp: None,
        }
    }

    fn link(path: &Path, kind: &str) -> RegisteredLink {
        RegisteredLink {
            local_path: path.display().to_string(),
            provider_kind: kind.into(),
            orphaned: false,
        }
    }

    fn register(t: &Tree, links: &[(&Path, &str)]) {
        let rows: Vec<(String, &str, bool)> =
            links.iter().map(|(p, k)| (p.display().to_string(), *k, false)).collect();
        let rows: Vec<(&str, &str, bool)> =
            rows.iter().map(|(p, k, o)| (p.as_str(), *k, *o)).collect();
        yadorilink_sqlite_runtime::write_registry_for_test(
            &t.config.join("sync-state.sqlite3"),
            &rows,
        );
    }

    #[test]
    fn a_link_overlapping_the_program_tree_or_the_purged_data_refuses() {
        let t = tree();
        let l = layout(&t);
        let share = t.home.join(".local/share/yadorilink");
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, true).unwrap();
        for bad in [share.join("sync"), t.home.join(".local"), share.clone()] {
            let err = check_removal_clear(&plan, &l, &[link(&bad, "none")]).unwrap_err();
            assert!(err.to_string().contains("program tree"), "{}: {err}", bad.display());
        }
        // A provider root and an orphaned link count the same.
        assert!(check_removal_clear(&plan, &l, &[link(&share.join("p"), "fileprovider")]).is_err());
        // Purge: a folder inside or around the data directory.
        for bad in [t.config.join("sync"), t.home.clone()] {
            assert!(check_removal_clear(&plan, &l, &[link(&bad, "none")]).is_err());
        }
        // Without purge, a folder in the data directory is not touched.
        let keep = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        assert!(check_removal_clear(&keep, &l, &[link(&t.config.join("sync"), "none")]).is_ok());
        assert!(check_removal_clear(&plan, &l, &[link(&t.outside, "none")]).is_ok());
    }

    #[test]
    fn state_placed_inside_the_program_tree_refuses() {
        let t = tree();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        let mut l = layout(&t);
        l.block_store = t.home.join(".local/share/yadorilink/blocks");
        assert!(check_removal_clear(&plan, &l, &[]).is_err());
        let mut l = layout(&t);
        l.provider_temp = Some(t.home.join(".local/share/yadorilink/tmp"));
        assert!(check_removal_clear(&plan, &l, &[]).is_err());
    }

    #[test]
    fn stopped_daemon_with_a_folder_in_the_program_tree_is_refused_and_nothing_is_deleted() {
        let t = tree();
        let sync = t.home.join(".local/share/yadorilink/my-sync");
        std::fs::create_dir_all(&sync).unwrap();
        std::fs::write(sync.join("doc.txt"), b"precious").unwrap();
        register(&t, &[(&sync, "none")]);
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, true).unwrap();
        let err = remove_under_lock(&plan, &layout(&t), || {}).unwrap_err();
        assert!(err.to_string().contains("my-sync"), "{err}");
        assert!(
            sync.join("doc.txt").exists()
                && t.exe.exists()
                && t.config.join("device.json").exists()
        );
    }

    #[test]
    fn unreadable_or_unknown_state_refuses_and_nothing_is_deleted() {
        let t = tree();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, true).unwrap();
        let db = t.config.join("sync-state.sqlite3");
        std::fs::write(&db, b"not a database, just some bytes to be unreadable").unwrap();
        let err = remove_under_lock(&plan, &layout(&t), || {}).unwrap_err();
        assert!(err.to_string().contains("--yes does not skip"), "{err}");
        assert!(t.exe.exists() && t.config.join("device.json").exists());
        // A database of another schema generation is unknown too.
        std::fs::remove_file(&db).unwrap();
        // An empty file is a database SQLite reads as version 0: not this build's schema.
        std::fs::File::create(&db).unwrap();
        assert!(remove_under_lock(&plan, &layout(&t), || {}).is_err());
        assert!(t.exe.exists() && t.config.join("device.json").exists());
    }

    #[test]
    fn clean_state_proceeds_and_removes() {
        let t = tree();
        register(&t, &[(&t.outside, "none")]);
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, true).unwrap();
        remove_under_lock(&plan, &layout(&t), || {}).unwrap();
        assert!(!t.home.join(".local/share/yadorilink").exists());
        assert_eq!(listing(&t.config), vec![".daemon.lock".to_string()]);
        assert!(t.outside.join("keep.txt").exists());
        // No database at all: nothing was ever registered.
        let t = tree();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        remove_under_lock(&plan, &layout(&t), || {}).unwrap();
        assert!(!t.home.join(".local/share/yadorilink").exists());
    }

    #[test]
    fn an_absent_data_directory_is_created_for_the_lock_and_purge_leaves_only_the_lock_file() {
        let t = tree();
        std::fs::remove_dir_all(&t.config).unwrap();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        remove_under_lock(&plan, &layout(&t), || {}).unwrap();
        assert!(!t.home.join(".local/share/yadorilink").exists());
        let t = tree();
        std::fs::create_dir_all(t.config.join("blocks/ab")).unwrap();
        std::fs::write(t.config.join("blocks/ab/x"), b"b").unwrap();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, true).unwrap();
        remove_under_lock(&plan, &layout(&t), || {}).unwrap();
        // Emptied, but the lock file stays so exclusion never lapses during the purge.
        assert_eq!(listing(&t.config), vec![".daemon.lock".to_string()]);
    }

    #[test]
    fn a_daemon_start_during_removal_is_refused_and_removal_is_not_interleaved() {
        use yadorilink_local_storage::daemon_lock::{probe, LockProbe};
        let t = tree();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        let share = t.home.join(".local/share/yadorilink");
        let mut start_result = None;
        remove_under_lock(&plan, &layout(&t), || {
            // The daemon's own start takes this lock and is refused; nothing is removed yet.
            start_result = Some(HeldLock::acquire_daemon_lock(&t.config));
            assert_eq!(probe(&t.config), LockProbe::Held);
            assert!(share.exists());
        })
        .unwrap();
        assert_eq!(start_result.unwrap().unwrap_err(), AcquireError::Contended);
        assert!(!share.exists());
        // Released once the removal is over.
        assert!(HeldLock::acquire_daemon_lock(&t.config).is_ok());
    }

    #[test]
    fn failing_to_take_the_lock_deletes_nothing() {
        let t = tree();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, true).unwrap();
        // Held by a daemon.
        let held = HeldLock::acquire_daemon_lock(&t.config).unwrap();
        let err = remove_under_lock(&plan, &layout(&t), || panic!("must not run")).unwrap_err();
        assert!(err.to_string().contains("lock is held"), "{err}");
        assert!(t.exe.exists() && t.config.join("device.json").exists());
        drop(held);
        // Unusable lock file.
        std::fs::remove_file(t.config.join(".daemon.lock")).unwrap();
        std::fs::create_dir(t.config.join(".daemon.lock")).unwrap();
        let err = remove_under_lock(&plan, &layout(&t), || panic!("must not run")).unwrap_err();
        assert!(err.to_string().contains("cannot take the data-area lock"), "{err}");
        assert!(t.exe.exists() && t.config.join("device.json").exists());
    }

    #[test]
    fn a_data_directory_inside_the_program_tree_refuses_even_without_purge() {
        let t = tree();
        let inside = t.home.join(".local/share/yadorilink/data");
        std::fs::create_dir_all(&inside).unwrap();
        let err = build_plan(&RecordState::Missing, &t.exe, &t.home, &inside, false).unwrap_err();
        assert!(err.to_string().contains("overlaps the program tree"));
        assert!(inside.exists());
    }

    #[test]
    fn other_sources_refuse_with_the_owners_steps_and_touch_nothing() {
        for (source, owner, step) in [
            ("app_bundle", Owner::Gui, "Trash"),
            ("microsoft_store", Owner::Gui, "Installed apps"),
            ("homebrew", Owner::Cli, "brew uninstall"),
            ("apt", Owner::Cli, "apt remove"),
            ("winget", Owner::Cli, "winget uninstall"),
            ("container", Owner::Cli, "container"),
        ] {
            let t = tree();
            let before = snapshot(&t.root);
            let record = RecordState::Present(OwnershipRecord {
                owner,
                install_source: source.into(),
                install_root: "/x".into(),
                release_id: String::new(),
                written_at: 1,
            });
            let err = build_plan(&record, &t.exe, &t.home, &t.config, true).unwrap_err();
            assert!(
                matches!(&err, CliError::ManagedElsewhere(m) if m.contains(step)),
                "{source}: {err}"
            );
            assert_eq!(snapshot(&t.root), before);
        }
    }

    #[test]
    fn an_unreadable_record_a_missing_receipt_or_a_foreign_receipt_refuse() {
        let t = tree();
        let err =
            build_plan(&RecordState::Unreadable("bad".into()), &t.exe, &t.home, &t.config, false)
                .unwrap_err();
        assert!(matches!(err, CliError::ManagedElsewhere(_)));
        let receipt = t.home.join(".local/share/yadorilink/install-receipt");
        std::fs::write(&receipt, "install_source=apt\n").unwrap();
        assert!(build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).is_err());
        std::fs::remove_file(&receipt).unwrap();
        let err = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap_err();
        assert!(err.to_string().contains("no readable install receipt"));
        assert!(t.exe.exists());
    }

    #[test]
    fn a_recorded_install_root_outside_the_install_tree_refuses() {
        let t = tree();
        let err =
            build_plan(&script_record(&t.outside), &t.exe, &t.home, &t.config, false).unwrap_err();
        assert!(err.to_string().contains("not inside"));
        assert!(t.outside.join("keep.txt").exists());
    }

    #[test]
    fn a_binary_outside_an_installer_layout_refuses() {
        let t = tree();
        let stray = t.outside.join("yadorilink");
        std::fs::write(&stray, b"x").unwrap();
        assert!(build_plan(&RecordState::Missing, &stray, &t.home, &t.config, false).is_err());
    }

    #[test]
    fn a_profile_outside_home_or_a_block_for_another_prefix_is_left_alone() {
        let t = tree();
        let foreign = t.outside.join("profile");
        std::fs::write(
            &foreign,
            "x\n# >>> yadorilink (/other) >>>\n# <<< yadorilink (/other) <<<\n",
        )
        .unwrap();
        let receipt = t.home.join(".local/share/yadorilink/install-receipt");
        std::fs::write(
            &receipt,
            format!("install_source=script\npath_profile={}\n", foreign.display()),
        )
        .unwrap();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        assert_eq!(plan.profile, None);
        std::fs::write(
            &receipt,
            format!("install_source=script\npath_profile={}\n", t.profile.display()),
        )
        .unwrap();
        std::fs::write(
            &t.profile,
            "# >>> yadorilink (/other) >>>\nkeep\n# <<< yadorilink (/other) <<<\n",
        )
        .unwrap();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, false).unwrap();
        assert_eq!(plan.profile, None);
    }

    #[test]
    fn placeholders_need_yes_and_an_unknown_count_does_too() {
        let f = |n| FolderFacts { path: "/sync/a".into(), on_demand: true, placeholders: n };
        let (w, needs) = placeholder_warnings(Some(&[f(0)]));
        assert!(w.is_empty() && !needs);
        let (w, needs) = placeholder_warnings(Some(&[f(0), f(7)]));
        assert!(needs && w.iter().any(|l| l.contains("7 file(s)") && l.contains("/sync/a")));
        let (w, needs) = placeholder_warnings(None);
        assert!(needs && w[0].contains("not running"));
    }

    #[test]
    fn dry_run_description_names_every_removal() {
        let t = tree();
        let plan = build_plan(&RecordState::Missing, &t.exe, &t.home, &t.config, true).unwrap();
        let text = describe(&plan).join("\n");
        assert!(
            text.contains("share/yadorilink")
                && text.contains("PATH lines")
                && text.contains("DELETE")
        );
        assert_eq!(text.matches("remove link").count(), 2);
    }
}
