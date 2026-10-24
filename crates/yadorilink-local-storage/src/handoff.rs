//! Releasing a data area from the command-line install to the desktop app.
//!
//! A data area has exactly one owner. When the app is added to a machine whose daemon is managed
//! by the command-line install, the app takes over management of the same data; this module is
//! the engine-side half of that, shared by every front end. The user's data (state database,
//! block store, credentials, device identity, synced folders) is never moved, rewritten or
//! deleted. Only the ownership record and the OS service registrations change:
//!
//! 1. Preflight, nothing changed: the record names a command-line install that can be handed
//!    over (not a package manager's), the target is an intact app installation of a compatible
//!    release, no registration of an unknown installation is present, doctor's checks pass.
//! 2. The daemon is asked to stop at a safe point (never killed) and this operation takes the
//!    data-area lock, so nobody can start a daemon until it is let go.
//! 3. Each mutation (disable a registration, rewrite the record) is journaled with its inverse
//!    before it runs. The record is rewritten last: it is the moment the app owns the area.
//! 4. The lock is released. The app registers its launcher, starts its daemon and calls
//!    [`commit`]; if it cannot, it calls [`rollback`].
//!
//! The journal ([`journal`]) is the only recovery input. At any interruption the area has one
//! owner record and no daemon, or one daemon: a start is refused while the journal says the
//! switch is half-applied, and the operation re-run (or rolled back) finishes it.

pub mod journal;
pub mod services;

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::daemon_lock::{self, AcquireError, HeldLock, LockProbe};
use crate::install_check::{self, Facts, RunningInstall, Severity};
use crate::ownership::{self, Owner, OwnershipRecord, RecordState};
use crate::release_descriptor::{
    self, DescriptorProblem, IdentityFile, ReleaseDescriptor, StateRefusal, StateSchema,
};
use crate::service_registrations::{self, Kind, Roots};
use journal::{Journal, JournalState, MutationKind, MutationState, Phase, RegistrationPlan};
use services::ServiceManager;

/// The `install_source` values a command-line install may be handed over from. Package-manager
/// owned installs are not: the app cannot remove or disable what another updater owns.
pub const RELEASABLE_SOURCES: &[&str] = &["script", "standalone"];
/// The `install_source` values of the app, i.e. the targets of a hand-off.
pub const TARGET_SOURCES: &[&str] = &["app_bundle", "microsoft_store"];

/// What the daemon answered to the safe-stop request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopAnswer {
    /// It is at a safe point and has begun to exit.
    Stopping,
    /// It keeps running: in-flight work did not finish in time.
    Busy { detail: String },
    /// Nothing answers on the control socket.
    NotRunning,
    /// Something is there but did not answer in time.
    Unresponsive(String),
}

/// Everything the engine needs from the program it runs in.
#[allow(async_fn_in_trait)]
pub trait Host {
    fn services(&self) -> &dyn ServiceManager;
    /// Asks the running daemon, whoever owns it, to reach a safe point and exit.
    async fn safe_stop(&self, deadline: Duration) -> StopAnswer;
    /// Starts the daemon of the previous installation (`previous`, as recorded) again and waits
    /// until it answers. It must be that installation's daemon, not whatever this program would
    /// start by default.
    async fn start_previous(&self, previous: &OwnershipRecord) -> Result<(), String>;
    /// What the running daemon reports about itself, `None` when nothing answers.
    async fn identify(&self) -> Option<RunningInstall>;
    /// The descriptor of the program that runs this operation.
    fn local_descriptor(&self) -> Result<ReleaseDescriptor, DescriptorProblem>;
    /// Fault injection: returning `true` ends the operation here as a crashed process would,
    /// with no clean-up. Called after every journal write and every external effect.
    fn crash_point(&self, _label: &str) -> bool {
        false
    }
}

/// Where the engine works and how long it waits.
#[derive(Clone, Debug)]
pub struct Context {
    pub config_dir: PathBuf,
    /// The sync index database the daemon opens (the default in `config_dir`, or the path an
    /// override names).
    pub sync_db: PathBuf,
    pub roots: Roots,
    /// How long the daemon may take to reach a safe point.
    pub stop_deadline: Duration,
    /// How long to wait for the data-area lock after the daemon began to exit.
    pub lock_wait: Duration,
    pub now: u64,
}

/// The app installation to hand the data area to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// `app_bundle` or `microsoft_store`.
    pub install_source: String,
    /// The app bundle or package directory.
    pub install_root: PathBuf,
    /// The app's bundled engine executable; its release descriptor is read from beside it.
    pub engine_exe: PathBuf,
}

/// Why nothing was changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    AnotherHandoffRunning,
    /// A lock or the journal could not be used for a reason outside the hand-off's control.
    Unusable(String),
    JournalUnreadable(String),
    /// A hand-off to another target is open.
    OtherHandoffOpen {
        target: Box<OwnershipRecord>,
    },
    /// A roll-back was interrupted; finish it first.
    RollbackUnfinished,
    OwnerUnknown(String),
    AlreadyManagedByApp(Box<OwnershipRecord>),
    PackageManagerOwned(Box<OwnershipRecord>),
    TargetInvalid(String),
    TargetIncompatible(String),
    /// The app's engine cannot open the state database the current install has written
    /// (a downgrade, or a generation it no longer reads).
    StateIncompatible(StateRefusal),
    /// The previous installation's engine identity cannot be read, so a roll-back to it cannot
    /// be judged.
    PreviousUnreadable(String),
    /// Failed doctor checks, each with its fix.
    Preflight(Vec<String>),
    RegistrationNotRemovable {
        name: String,
        hint: String,
    },
    UnknownRegistration {
        name: String,
        hint: String,
    },
    /// The record on disk is neither the one the journal started from nor the one it writes.
    RecordChanged(String),
    DaemonBusy(String),
    DaemonWedged(String),
    DaemonDidNotRelease,
    /// An unfinished hand-off had stopped the previous daemon and it could not be started again.
    PreviousDaemonNotStarted(String),
    NothingToDo,
    NotReleased(Phase),
    VerificationFailed(String),
}

/// Whether the previous owner's daemon runs again after a roll-back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviousDaemon {
    /// It was not running when the hand-off began, so none was started.
    NotStarted,
    Restarted,
    /// It could not be started: no daemon runs. The old owner is fully restored.
    FailedToStart(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The area is released to the app; the app commits or rolls back.
    Released,
    AlreadyReleased,
    Committed,
    RolledBack(PreviousDaemon),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandoffError {
    /// Nothing was changed (or only the daemon was stopped, and it is running again).
    Refused(Refused),
    /// A step failed after something was changed; everything is back as it was.
    RolledBack { reason: String, previous: PreviousDaemon },
    /// A step failed and the roll-back failed too. No daemon runs and none can start until
    /// `rollback` succeeds.
    RollbackFailed { reason: String, detail: String },
    /// The process was interrupted (fault injection only).
    Crashed,
}

/// Internal: how a step ended.
enum Step {
    Refused(Refused),
    Failed(String),
    Crashed,
}

impl From<Refused> for Step {
    fn from(r: Refused) -> Self {
        Step::Refused(r)
    }
}

type Res<T> = Result<T, Step>;

fn crash<H: Host>(host: &H, label: &str) -> Res<()> {
    if host.crash_point(label) {
        Err(Step::Crashed)
    } else {
        Ok(())
    }
}

fn save(ctx: &Context, journal: &Journal) -> Res<()> {
    journal::write(&ctx.config_dir, journal)
        .map_err(|e| Step::Failed(format!("cannot write the hand-off journal: {e}")))
}

// ---------------------------------------------------------------------------------------------
// Preflight

struct Plan {
    previous: OwnershipRecord,
    target: OwnershipRecord,
    mutations: Vec<MutationKind>,
    daemon_running: bool,
}

/// The app installation as a daemon launched from it would report itself.
struct Target {
    identity: release_descriptor::EngineIdentity,
    /// The `install_root` that daemon reports (and so the record names): the outermost bundle, or
    /// the directory of the executable.
    install_root: PathBuf,
}

/// Whether two paths name the same place, compared after resolving links where possible.
fn same_path(a: &Path, b: &Path) -> bool {
    match (resolved(a), resolved(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The path with links resolved, in the spelling a program reports for itself (Windows
/// canonicalizes to the verbatim `\\?\C:\...` form, which no daemon reports).
fn resolved(path: &Path) -> std::io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    let plain = strip_verbatim(&canonical.to_string_lossy()).map(PathBuf::from);
    Ok(plain.unwrap_or(canonical))
}

/// `C:\x` for `\\?\C:\x`; `None` for anything else (a UNC share keeps its prefix).
fn strip_verbatim(text: &str) -> Option<&str> {
    text.strip_prefix(r"\\?\").filter(|rest| rest.as_bytes().get(1) == Some(&b':'))
}

/// Validates the requested app on the resolved paths, so neither `..` nor a link inside the
/// requested directory can make another installation's engine stand for it.
fn resolve_target(req: &Request) -> Result<Target, Refused> {
    let invalid = |reason: String| Refused::TargetInvalid(reason);
    let root = resolved(&req.install_root)
        .map_err(|e| invalid(format!("{} cannot be read: {e}", req.install_root.display())))?;
    let engine = resolved(&req.engine_exe)
        .map_err(|e| invalid(format!("{} cannot be read: {e}", req.engine_exe.display())))?;
    if !root.is_dir() {
        return Err(invalid(format!("{} is not a directory", root.display())));
    }
    match req.install_source.as_str() {
        "app_bundle" => {
            if ownership::app_bundle_root(&root.join("Contents")).as_ref() != Some(&root) {
                return Err(invalid(format!(
                    "{} is not an application bundle (a directory named *.app)",
                    root.display()
                )));
            }
        }
        "microsoft_store" => {
            if !ownership::is_windows_store_path(&root) {
                return Err(invalid(format!(
                    "{} is not a Windows Store package location",
                    root.display()
                )));
            }
        }
        other => {
            return Err(invalid(format!(
                "{other} is not an app install source (app_bundle or microsoft_store)"
            )));
        }
    }
    if !engine.starts_with(&root) || !engine.is_file() {
        return Err(invalid(format!(
            "the engine {} is not a file inside {}",
            engine.display(),
            root.display()
        )));
    }
    let install_root = ownership::app_bundle_root(&engine)
        .or_else(|| engine.parent().map(Path::to_path_buf))
        .unwrap_or_default();
    if req.install_source == "app_bundle" && install_root != root {
        return Err(invalid(format!(
            "the engine {} belongs to {}, not to {}",
            engine.display(),
            install_root.display(),
            root.display()
        )));
    }
    let dir = release_descriptor::identity_dir(&engine);
    match release_descriptor::read_identity(dir.as_deref()) {
        IdentityFile::Present(identity) if !identity.release_id.is_empty() => {
            Ok(Target { identity, install_root })
        }
        IdentityFile::Present(_) | IdentityFile::Absent => {
            Err(Refused::TargetIncompatible(format!(
                "the app at {} carries no engine identity, so its release cannot be checked; \
                 reinstall the app",
                root.display()
            )))
        }
        IdentityFile::Unreadable(reason) => Err(Refused::TargetIncompatible(format!(
            "the app's engine identity cannot be read ({reason}); reinstall the app"
        ))),
    }
}

/// Whether this program may move the registration aside: the kinds that live in the user's own
/// account, with the definition under the user's home. A system-wide agent or a package's unit
/// needs privileges and belongs to whoever installed it. A Windows task has no file to move (it
/// is exported and deleted through the task scheduler).
fn removable_by_us(kind: Kind, definition: &Path, home: &Path) -> bool {
    match kind {
        Kind::WindowsTask => true,
        Kind::LaunchAgent | Kind::SystemdUserUnit => definition.starts_with(home),
        Kind::BundledLaunchAgent | Kind::SystemdSystemUnit => false,
    }
}

/// The one definition to move aside, `None` when there is none this program may move or when a
/// copy elsewhere would keep starting the daemon after it. Every existing copy counts: a user
/// definition beside a system-wide one is not removable.
fn movable_definition(kind: Kind, existing: &[PathBuf], home: &Path) -> Option<PathBuf> {
    match (kind, existing) {
        // The task scheduler's own store has one copy; it is exported and deleted, not moved.
        (Kind::WindowsTask, [only]) => Some(only.clone()),
        (Kind::WindowsTask, _) => None,
        (_, [only]) if removable_by_us(kind, only, home) => Some(only.clone()),
        _ => None,
    }
}

/// Whether a hand-off journal exists in any state (also an unreadable one). While one does, the
/// ownership record belongs to that hand-off: it is rewritten only by the hand-off.
#[must_use]
pub fn is_open(config_dir: &Path) -> bool {
    !matches!(journal::read(config_dir), JournalState::Missing)
}

/// The refusal that keeps a daemon from starting while a hand-off is half-applied, `None` when
/// no journal blocks it. An unreadable journal blocks too: how far a hand-off got is unknown.
#[must_use]
pub fn start_refusal(config_dir: &Path) -> Option<ownership::Refusal> {
    match journal::read(config_dir) {
        JournalState::Missing => None,
        JournalState::Present(j) if !j.blocks_daemon_start() => None,
        JournalState::Present(j) => Some(ownership::Refusal::HandoffUnfinished {
            reason: format!("it stopped at {:?}", j.phase),
        }),
        JournalState::Unreadable(reason) => Some(ownership::Refusal::HandoffUnfinished { reason }),
    }
}

/// The version stamped on the sync index database at `path` (`PRAGMA user_version`), `None` when there is
/// no database, it is unstamped, or it cannot be read. Read-only and WAL-aware: a running
/// daemon's committed stamp may live only in the write-ahead log, so the main file's header is
/// not enough.
fn persisted_state_version(path: &Path) -> Option<u32> {
    use rusqlite::OpenFlags;
    if !path.is_file() {
        return None;
    }
    let conn = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    conn.busy_timeout(Duration::from_secs(2)).ok()?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).ok()?;
    u32::try_from(version).ok().filter(|v| *v > 0)
}

/// The state database generations the previous installation's engine declares, read from the
/// identity beside its daemon. An installation that ships no identity declares nothing; one that
/// is gone, or whose identity cannot be read, cannot be judged and is refused.
fn previous_state_schema(previous: &OwnershipRecord) -> Result<Option<StateSchema>, Refused> {
    let root = Path::new(&previous.install_root);
    if !root.is_dir() {
        return Err(Refused::PreviousUnreadable(format!("{} is gone", root.display())));
    }
    let daemon = root.join("yadorilink-daemon");
    match release_descriptor::read_identity(release_descriptor::identity_dir(&daemon).as_deref()) {
        IdentityFile::Absent => Ok(None),
        IdentityFile::Present(identity) => Ok(identity.state_schema),
        IdentityFile::Unreadable(reason) => Err(Refused::PreviousUnreadable(reason)),
    }
}

async fn preflight<H: Host>(host: &H, ctx: &Context, req: &Request) -> Result<Plan, Refused> {
    let previous = match ownership::read(&ctx.config_dir) {
        RecordState::Missing => {
            return Err(Refused::OwnerUnknown(
                "no owner is recorded for this data area; start the daemon you manage it with \
                 once so that it records itself, then try again"
                    .into(),
            ))
        }
        RecordState::Unreadable(reason) => return Err(Refused::OwnerUnknown(reason)),
        RecordState::Present(record) => record,
    };
    if previous.owner == Owner::Gui {
        return Err(Refused::AlreadyManagedByApp(Box::new(previous)));
    }
    if !RELEASABLE_SOURCES.contains(&previous.install_source.as_str()) {
        return Err(Refused::PackageManagerOwned(Box::new(previous)));
    }

    let resolved = resolve_target(req)?;
    let identity = resolved.identity;
    let local = host.local_descriptor();
    if let Ok(local) = &local {
        if identity.engine_api_version < local.engine_api_version {
            return Err(Refused::TargetIncompatible(format!(
                "the app speaks engine API {} but the current install speaks {}; handing the \
                 data to an older engine could not read it back. Update the app first",
                identity.engine_api_version, local.engine_api_version
            )));
        }
    }
    // The state database on disk must be readable by the app's engine. The stamp is read from
    // the database itself: the installed bundle may have been updated without its daemon having
    // opened (and so restamped) the data.
    if let Some(persisted) = persisted_state_version(&ctx.sync_db) {
        StateSchema::check_readable(persisted, identity.state_schema)
            .map_err(Refused::StateIncompatible)?;
    }

    let running = host.identify().await;
    let lock = daemon_lock::probe(&ctx.config_dir);
    let record_state = RecordState::Present(previous.clone());
    let rows = install_check::check(&Facts {
        config_dir: &ctx.config_dir,
        record: &record_state,
        lock: &lock,
        running: running.as_ref(),
        local: &local,
        roots: &ctx.roots,
    });
    let failed: Vec<String> = rows
        .iter()
        .filter(|r| r.severity == Severity::Error && r.check != install_check::CHECK_REGISTRATIONS)
        .map(|r| format!("{}: {}", r.check, r.detail))
        .collect();
    if !failed.is_empty() {
        return Err(Refused::Preflight(failed));
    }

    // Registrations of the previous installation are moved aside; the app's own may exist
    // already; anything else is unknown and stops the hand-off.
    for registration in service_registrations::conflicting(&previous.install_source, &ctx.roots) {
        if !registration.belongs_to(&req.install_source) {
            return Err(Refused::UnknownRegistration {
                name: registration.name.to_string(),
                hint: service_registrations::removal_hint(registration),
            });
        }
    }
    let mut mutations = Vec::new();
    for registration in service_registrations::own(&previous.install_source, &ctx.roots) {
        let existing: Vec<PathBuf> =
            registration.definition_paths(&ctx.roots).into_iter().filter(|p| p.exists()).collect();
        let Some(definition) = movable_definition(registration.kind, &existing, &ctx.roots.home)
        else {
            return Err(Refused::RegistrationNotRemovable {
                name: registration.name.to_string(),
                hint: service_registrations::removal_hint(registration),
            });
        };
        let mut plan = RegistrationPlan {
            kind: registration.kind,
            name: registration.name.to_string(),
            definition,
            backup: journal::backup_path(&ctx.config_dir, registration.name),
            was_active: false,
        };
        plan.was_active = host
            .services()
            .is_active(&plan)
            .map_err(|e| Refused::Preflight(vec![format!("service manager: {e}")]))?;
        mutations.push(MutationKind::DisableRegistration { plan });
    }
    mutations.push(MutationKind::RewriteRecord);

    let target = OwnershipRecord {
        owner: Owner::Gui,
        install_source: req.install_source.clone(),
        install_root: resolved.install_root.display().to_string(),
        release_id: identity.release_id,
        written_at: ctx.now,
    };
    Ok(Plan {
        previous,
        target,
        mutations,
        daemon_running: running.is_some() || lock != LockProbe::Free,
    })
}

// ---------------------------------------------------------------------------------------------
// Stop and lock

async fn wait_for_daemon_lock(ctx: &Context) -> Result<HeldLock, Refused> {
    let deadline = tokio::time::Instant::now() + ctx.lock_wait;
    loop {
        match HeldLock::acquire_daemon_lock(&ctx.config_dir) {
            Ok(lock) => return Ok(lock),
            // Contended also covers a probe running at this instant.
            Err(AcquireError::Contended) => {}
            Err(AcquireError::Unusable(reason)) => return Err(Refused::Unusable(reason)),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Refused::DaemonDidNotRelease);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Stops whichever daemon runs (never kills it) and takes the data-area lock.
async fn stop_and_lock<H: Host>(host: &H, ctx: &Context) -> Result<HeldLock, Refused> {
    match HeldLock::acquire_daemon_lock(&ctx.config_dir) {
        Ok(lock) => return Ok(lock),
        Err(AcquireError::Contended) => {}
        Err(AcquireError::Unusable(reason)) => return Err(Refused::Unusable(reason)),
    }
    match host.safe_stop(ctx.stop_deadline).await {
        StopAnswer::Stopping | StopAnswer::NotRunning => {}
        StopAnswer::Busy { detail } => return Err(Refused::DaemonBusy(detail)),
        StopAnswer::Unresponsive(reason) => return Err(Refused::DaemonWedged(reason)),
    }
    wait_for_daemon_lock(ctx).await
}

// ---------------------------------------------------------------------------------------------
// Apply and undo

fn current_record_is(config_dir: &Path, allowed: &[&OwnershipRecord]) -> Result<(), String> {
    match ownership::read(config_dir) {
        RecordState::Present(r) if allowed.contains(&&r) => Ok(()),
        RecordState::Present(r) => Err(format!(
            "the ownership record names {} ({}) which this hand-off did not write",
            r.install_source, r.install_root
        )),
        RecordState::Missing => Err("the ownership record is gone".into()),
        RecordState::Unreadable(reason) => Err(reason),
    }
}

fn apply_one<H: Host>(host: &H, ctx: &Context, journal: &Journal, kind: &MutationKind) -> Res<()> {
    match kind {
        MutationKind::DisableRegistration { plan } => {
            host.services().disable(plan).map_err(Step::Failed)
        }
        MutationKind::RewriteRecord => {
            current_record_is(&ctx.config_dir, &[&journal.previous, &journal.target])
                .map_err(Step::Failed)?;
            ownership::write(&ctx.config_dir, &journal.target)
                .map_err(|e| Step::Failed(format!("cannot write the ownership record: {e}")))
        }
    }
}

fn undo_one<H: Host>(host: &H, ctx: &Context, journal: &Journal, kind: &MutationKind) -> Res<()> {
    match kind {
        MutationKind::DisableRegistration { plan } => {
            host.services().restore(plan).map_err(Step::Failed)
        }
        MutationKind::RewriteRecord => {
            current_record_is(&ctx.config_dir, &[&journal.previous, &journal.target])
                .map_err(Step::Failed)?;
            ownership::write(&ctx.config_dir, &journal.previous)
                .map_err(|e| Step::Failed(format!("cannot restore the ownership record: {e}")))
        }
    }
}

fn apply_all<H: Host>(host: &H, ctx: &Context, journal: &mut Journal) -> Res<()> {
    for i in 0..journal.mutations.len() {
        if journal.mutations[i].state == MutationState::Done {
            continue;
        }
        journal.mutations[i].state = MutationState::Intended;
        save(ctx, journal)?;
        crash(host, "intended")?;
        let kind = journal.mutations[i].kind.clone();
        apply_one(host, ctx, journal, &kind)?;
        crash(host, "applied")?;
        journal.mutations[i].state = MutationState::Done;
        save(ctx, journal)?;
        crash(host, "done")?;
    }
    Ok(())
}

/// Undoes every mutation that was intended or done, last first, then removes the journal.
fn undo_all<H: Host>(host: &H, ctx: &Context, journal: &mut Journal) -> Res<()> {
    journal.phase = Phase::RollingBack;
    save(ctx, journal)?;
    crash(host, "rolling_back")?;
    for i in (0..journal.mutations.len()).rev() {
        if journal.mutations[i].state == MutationState::Pending {
            continue;
        }
        let kind = journal.mutations[i].kind.clone();
        undo_one(host, ctx, journal, &kind)?;
        crash(host, "undone")?;
        journal.mutations[i].state = MutationState::Pending;
        save(ctx, journal)?;
        crash(host, "undone_saved")?;
    }
    journal::remove(&ctx.config_dir)
        .map_err(|e| Step::Failed(format!("cannot remove the hand-off journal: {e}")))?;
    crash(host, "journal_removed")
}

/// Rolls back with the lock held, lets the lock go and restarts the old daemon when it ran.
async fn finish_rollback<H: Host>(
    host: &H,
    ctx: &Context,
    journal: &mut Journal,
    lock: HeldLock,
) -> Res<PreviousDaemon> {
    undo_all(host, ctx, journal)?;
    drop(lock);
    if !journal.daemon_was_running {
        return Ok(PreviousDaemon::NotStarted);
    }
    Ok(match host.start_previous(&journal.previous).await {
        Ok(()) => PreviousDaemon::Restarted,
        Err(e) => PreviousDaemon::FailedToStart(e),
    })
}

/// A step failed after the journal exists: roll everything back, with the lock if this
/// operation still has it.
async fn fail_into_rollback<H: Host>(
    host: &H,
    ctx: &Context,
    journal: &mut Journal,
    lock: HeldLock,
    reason: String,
) -> HandoffError {
    match finish_rollback(host, ctx, journal, lock).await {
        Ok(previous) => HandoffError::RolledBack { reason, previous },
        Err(Step::Crashed) => HandoffError::Crashed,
        Err(Step::Failed(detail)) => HandoffError::RollbackFailed { reason, detail },
        Err(Step::Refused(r)) => HandoffError::RollbackFailed { reason, detail: r.message() },
    }
}

fn into_error(step: Step) -> HandoffError {
    match step {
        Step::Refused(r) => HandoffError::Refused(r),
        Step::Failed(message) => HandoffError::Refused(Refused::Unusable(message)),
        Step::Crashed => HandoffError::Crashed,
    }
}

// ---------------------------------------------------------------------------------------------
// Public operations

/// Hands the data area to the app described by `req`, or resumes an open hand-off to the same
/// app. Idempotent: running it again after a crash, or after success, is safe.
///
/// # Errors
/// [`HandoffError`]: a refusal with nothing changed, or a failure with everything restored.
pub async fn release<H: Host>(
    host: &H,
    ctx: &Context,
    req: &Request,
) -> Result<Outcome, HandoffError> {
    let _operation = HeldLock::acquire(&ctx.config_dir, journal::LOCK_FILE_NAME).map_err(|e| {
        HandoffError::Refused(match e {
            AcquireError::Contended => Refused::AnotherHandoffRunning,
            AcquireError::Unusable(reason) => Refused::Unusable(reason),
        })
    })?;

    let open = match journal::read(&ctx.config_dir) {
        JournalState::Unreadable(reason) => {
            return Err(HandoffError::Refused(Refused::JournalUnreadable(reason)))
        }
        JournalState::Missing => None,
        JournalState::Present(j) => Some(*j),
    };
    if let Some(j) = open {
        // The same app, judged on the same resolved paths as when the hand-off was planned.
        let resolved = resolve_target(req).map_err(HandoffError::Refused)?;
        if j.target.install_source != req.install_source
            || Path::new(&j.target.install_root) != resolved.install_root
        {
            return Err(HandoffError::Refused(Refused::OtherHandoffOpen {
                target: Box::new(j.target),
            }));
        }
        match j.phase {
            Phase::RollingBack => return Err(HandoffError::Refused(Refused::RollbackUnfinished)),
            Phase::Switched => {
                current_record_is(&ctx.config_dir, &[&j.target])
                    .map_err(|reason| HandoffError::Refused(Refused::RecordChanged(reason)))?;
                return Ok(Outcome::AlreadyReleased);
            }
            Phase::Switching => return resume_switching(host, ctx, j).await,
            // Nothing was changed: the previous owner's daemon, if it was stopped for the
            // attempt, runs again before the hand-off is planned afresh.
            Phase::Planned | Phase::Stopped => {
                abandon_unmutated(host, ctx, &j).await.map_err(HandoffError::Refused)?;
            }
        }
    }

    let plan = preflight(host, ctx, req).await.map_err(HandoffError::Refused)?;
    let mut journal =
        Journal::new(plan.previous, plan.target, plan.daemon_running, plan.mutations, ctx.now);
    let planned: Res<()> = (|| {
        save(ctx, &journal)?;
        crash(host, "planned")
    })();
    if let Err(step) = planned {
        return Err(into_error(step));
    }

    let lock = match stop_and_lock(host, ctx).await {
        Ok(lock) => lock,
        Err(refused) => {
            // Nothing was changed. The daemon may have been asked to stop; start it again.
            if journal.daemon_was_running
                && !matches!(refused, Refused::DaemonBusy(_) | Refused::DaemonWedged(_))
            {
                let _ = host.start_previous(&journal.previous).await;
            }
            let _ = journal::remove(&ctx.config_dir);
            return Err(HandoffError::Refused(refused));
        }
    };
    journal.phase = Phase::Stopped;
    match save(ctx, &journal).and_then(|()| crash(host, "stopped")) {
        Ok(()) => {}
        Err(Step::Crashed) => return Err(HandoffError::Crashed),
        Err(step) => {
            // The journal could not be written, so nothing was changed: let the lock go and
            // start the daemon again, which this attempt had stopped.
            drop(lock);
            let _ = journal::remove(&ctx.config_dir);
            let restart = if journal.daemon_was_running {
                host.start_previous(&journal.previous).await.err()
            } else {
                None
            };
            let refused = match (into_error(step), restart) {
                (_, Some(reason)) => Refused::PreviousDaemonNotStarted(reason),
                (HandoffError::Refused(refused), None) => refused,
                (_, None) => Refused::Unusable("the hand-off could not be recorded".into()),
            };
            return Err(HandoffError::Refused(refused));
        }
    }
    switch(host, ctx, journal, lock).await
}

/// An earlier attempt got no further than stopping the daemon: nothing was changed. Starts the
/// daemon again when it ran and does not now, and drops the journal.
async fn abandon_unmutated<H: Host>(
    host: &H,
    ctx: &Context,
    journal: &Journal,
) -> Result<(), Refused> {
    if journal.daemon_was_running && daemon_lock::probe(&ctx.config_dir) == LockProbe::Free {
        host.start_previous(&journal.previous).await.map_err(Refused::PreviousDaemonNotStarted)?;
    }
    journal::remove(&ctx.config_dir).map_err(|e| Refused::Unusable(e.to_string()))
}

async fn resume_switching<H: Host>(
    host: &H,
    ctx: &Context,
    journal: Journal,
) -> Result<Outcome, HandoffError> {
    current_record_is(&ctx.config_dir, &[&journal.previous, &journal.target])
        .map_err(|reason| HandoffError::Refused(Refused::RecordChanged(reason)))?;
    let lock = stop_and_lock(host, ctx).await.map_err(HandoffError::Refused)?;
    switch(host, ctx, journal, lock).await
}

/// Applies the mutations under the lock and marks the area released.
async fn switch<H: Host>(
    host: &H,
    ctx: &Context,
    mut journal: Journal,
    lock: HeldLock,
) -> Result<Outcome, HandoffError> {
    journal.phase = Phase::Switching;
    let applied: Res<()> = (|| {
        save(ctx, &journal)?;
        crash(host, "switching")?;
        apply_all(host, ctx, &mut journal)?;
        journal.phase = Phase::Switched;
        save(ctx, &journal)?;
        crash(host, "switched")
    })();
    match applied {
        Ok(()) => {
            drop(lock);
            Ok(Outcome::Released)
        }
        Err(Step::Crashed) => Err(HandoffError::Crashed),
        Err(Step::Failed(reason)) => {
            Err(fail_into_rollback(host, ctx, &mut journal, lock, reason).await)
        }
        Err(Step::Refused(r)) => {
            let reason = r.message();
            Err(fail_into_rollback(host, ctx, &mut journal, lock, reason).await)
        }
    }
}

/// Undoes an open hand-off in any phase: stops whichever daemon runs (the app's, once it has
/// started), restores the previous record and registrations, and starts the previous owner's
/// daemon again when it ran before. Idempotent.
///
/// # Errors
/// [`HandoffError`]; after `RollbackFailed` or a refusal the journal is kept and the call can be
/// repeated.
pub async fn rollback<H: Host>(host: &H, ctx: &Context) -> Result<Outcome, HandoffError> {
    let _operation = HeldLock::acquire(&ctx.config_dir, journal::LOCK_FILE_NAME).map_err(|e| {
        HandoffError::Refused(match e {
            AcquireError::Contended => Refused::AnotherHandoffRunning,
            AcquireError::Unusable(reason) => Refused::Unusable(reason),
        })
    })?;
    let mut journal = match journal::read(&ctx.config_dir) {
        JournalState::Missing => return Err(HandoffError::Refused(Refused::NothingToDo)),
        JournalState::Unreadable(reason) => {
            return Err(HandoffError::Refused(Refused::JournalUnreadable(reason)))
        }
        JournalState::Present(j) => *j,
    };
    // The previous engine must be able to open the data as it now stands: the app's daemon may
    // have restamped it. The engine judged is the one `start_previous` will start, the
    // installation the journal recorded, not the program that runs this call. Judged before
    // anything is stopped, so a refusal leaves the app running.
    if let Some(persisted) = persisted_state_version(&ctx.sync_db) {
        let declared = previous_state_schema(&journal.previous).map_err(HandoffError::Refused)?;
        StateSchema::check_readable(persisted, declared)
            .map_err(|refusal| HandoffError::Refused(Refused::StateIncompatible(refusal)))?;
    }
    let lock = stop_and_lock(host, ctx).await.map_err(HandoffError::Refused)?;
    match finish_rollback(host, ctx, &mut journal, lock).await {
        Ok(previous) => Ok(Outcome::RolledBack(previous)),
        Err(Step::Crashed) => Err(HandoffError::Crashed),
        Err(Step::Failed(detail)) => Err(HandoffError::RollbackFailed {
            reason: "the roll-back was requested".into(),
            detail,
        }),
        Err(Step::Refused(r)) => Err(HandoffError::Refused(r)),
    }
}

/// The app's daemon runs and the app is satisfied: checks that the data area is the app's and
/// closes the hand-off by removing the journal.
///
/// # Errors
/// [`Refused::VerificationFailed`] and the like, with nothing changed: the app rolls back.
pub async fn commit<H: Host>(host: &H, ctx: &Context) -> Result<Outcome, HandoffError> {
    let _operation = HeldLock::acquire(&ctx.config_dir, journal::LOCK_FILE_NAME).map_err(|e| {
        HandoffError::Refused(match e {
            AcquireError::Contended => Refused::AnotherHandoffRunning,
            AcquireError::Unusable(reason) => Refused::Unusable(reason),
        })
    })?;
    let journal = match journal::read(&ctx.config_dir) {
        JournalState::Missing => return Err(HandoffError::Refused(Refused::NothingToDo)),
        JournalState::Unreadable(reason) => {
            return Err(HandoffError::Refused(Refused::JournalUnreadable(reason)))
        }
        JournalState::Present(j) => *j,
    };
    if journal.phase != Phase::Switched {
        return Err(HandoffError::Refused(Refused::NotReleased(journal.phase)));
    }
    let verify = async {
        current_record_is(&ctx.config_dir, &[&journal.target])?;
        let running =
            host.identify().await.ok_or("no daemon answers; start the app's daemon first")?;
        if !same_path(Path::new(&running.install_root), Path::new(&journal.target.install_root)) {
            return Err(format!(
                "the running daemon is installed at {}, not at {}",
                running.install_root, journal.target.install_root
            ));
        }
        if running.install_source != journal.target.install_source {
            return Err(format!(
                "the running daemon is installed as {} ({}), not as {}",
                running.install_source, running.install_root, journal.target.install_source
            ));
        }
        if running.release_id != journal.target.release_id {
            return Err(format!(
                "the running daemon is release {} but the app carries {}",
                running.release_id, journal.target.release_id
            ));
        }
        Ok(())
    };
    verify.await.map_err(|reason| HandoffError::Refused(Refused::VerificationFailed(reason)))?;
    journal::remove(&ctx.config_dir)
        .map_err(|e| HandoffError::Refused(Refused::Unusable(e.to_string())))?;
    Ok(Outcome::Committed)
}

impl Refused {
    /// The explanation shown to the user: what stopped, that nothing was changed unless said
    /// otherwise, and what to do.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Refused::AnotherHandoffRunning => "another hand-off of this data area is running; \
                 wait for it to finish. Nothing was changed."
                .into(),
            Refused::Unusable(reason) => format!("the hand-off could not proceed: {reason}"),
            Refused::JournalUnreadable(reason) => format!(
                "the hand-off journal cannot be read ({reason}), so it is unknown how far an \
                 earlier hand-off got; nothing was changed. Restore {} from a backup, or, once \
                 you have checked that {} still names the owner you want and that the daemon \
                 starts, delete the journal.",
                journal::FILE_NAME,
                ownership::FILE_NAME
            ),
            Refused::OtherHandoffOpen { target } => format!(
                "a hand-off to {} at {} is already open; finish it with the app or run \
                 `yadorilink daemon release-to-app --rollback` first. Nothing was changed.",
                target.install_source, target.install_root
            ),
            Refused::RollbackUnfinished => "an earlier roll-back was interrupted; run \
                 `yadorilink daemon release-to-app --rollback` again to finish it."
                .into(),
            Refused::OwnerUnknown(reason) => {
                format!("the owner of this data area is unknown ({reason}); nothing was changed.")
            }
            Refused::AlreadyManagedByApp(record) => format!(
                "this data area is already managed by the app ({} at {}); nothing to do.",
                record.install_source, record.install_root
            ),
            Refused::PackageManagerOwned(record) => format!(
                "this daemon belongs to the {} install at {}, which has its own updater; the app \
                 cannot take it over. Stop using it (uninstall it with its package manager; your \
                 data stays), then try again. Nothing was changed.",
                record.install_source, record.install_root
            ),
            Refused::TargetInvalid(reason) => {
                format!("the app to hand over to is not usable: {reason}; nothing was changed.")
            }
            Refused::TargetIncompatible(reason) => {
                format!(
                    "the app is not compatible with this data area: {reason}; nothing was changed."
                )
            }
            Refused::PreviousUnreadable(reason) => format!(
                "the previous installation cannot be checked against the data on this device: \
                 {reason}; nothing was changed."
            ),
            Refused::StateIncompatible(refusal) => {
                format!("the app is not compatible with this data area: {}.", refusal.message())
            }
            Refused::Preflight(rows) => format!(
                "the installation checks failed, so nothing was changed:\n  {}",
                rows.join("\n  ")
            ),
            Refused::RegistrationNotRemovable { name, hint } => format!(
                "{name} starts the current daemon but cannot be removed by this program (it is \
                 outside your user account or provided by a package); nothing was changed. \
                 Remove it yourself ({hint}), then try again."
            ),
            Refused::UnknownRegistration { name, hint } => format!(
                "{name} belongs to another YadoriLink installation and would start a second \
                 daemon; nothing was changed. Remove it first ({hint}), then try again."
            ),
            Refused::RecordChanged(reason) => format!(
                "the ownership record changed during the hand-off ({reason}); nothing more was \
                 done. Check {} and run `yadorilink daemon release-to-app --rollback`.",
                ownership::FILE_NAME
            ),
            Refused::DaemonBusy(detail) => format!(
                "the daemon is busy and keeps running ({detail}); nothing was changed. Try again \
                 in a moment."
            ),
            Refused::DaemonWedged(reason) => format!(
                "a daemon holds the data area but does not answer ({reason}); nothing was \
                 changed and it was not killed. Stop it with the tool that started it, then try \
                 again."
            ),
            Refused::DaemonDidNotRelease => "the daemon was asked to stop but did not release the \
                 data area in time; nothing was changed. Try again, or stop it with the tool that \
                 started it."
                .into(),
            Refused::PreviousDaemonNotStarted(reason) => format!(
                "an earlier attempt stopped the daemon and it could not be started again \
                 ({reason}); nothing was changed. Start it with `yadorilink daemon start`, then \
                 try again."
            ),
            Refused::NothingToDo => "no hand-off is open; nothing to do.".into(),
            Refused::NotReleased(phase) => format!(
                "the hand-off is not finished (it stopped at {phase:?}); run `yadorilink daemon \
                 release-to-app` again to finish it, or `--rollback` to undo it."
            ),
            Refused::VerificationFailed(reason) => format!(
                "the app's daemon did not verify ({reason}); the hand-off stays open. Fix it, or \
                 run `yadorilink daemon release-to-app --rollback` to return to the previous \
                 setup."
            ),
        }
    }
}

#[cfg(test)]
mod tests;
