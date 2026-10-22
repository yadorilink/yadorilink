use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::journal::{self, JournalState, Phase};
use super::services::{CommandOutput, CommandRunner, OsServices, ServiceManager};
use super::*;

const NOW: u64 = 1_700_000_000;
const OLD_RELEASE: &str = "oldsha:1";
const APP_RELEASE: &str = "appsha:2";
const PLIST: &str = "com.yadorilink.daemon";
const UNIT: &str = "yadorilink-daemon.service";

// ---- fake service tools ------------------------------------------------------------------

#[derive(Default)]
struct FakeRunner {
    calls: Mutex<Vec<String>>,
    /// Any call whose command line contains this fails.
    fail_pattern: Mutex<Option<String>>,
}

impl CommandRunner for FakeRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String> {
        let line = format!("{program} {}", args.join(" "));
        self.calls.lock().unwrap().push(line.clone());
        let failing =
            self.fail_pattern.lock().unwrap().as_deref().is_some_and(|p| line.contains(p));
        Ok(CommandOutput {
            success: !failing,
            stdout: b"<Task/>".to_vec(),
            stderr: if failing { "injected".into() } else { String::new() },
        })
    }
}

struct Shared(Arc<FakeRunner>);

impl CommandRunner for Shared {
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String> {
        self.0.run(program, args)
    }
}

// ---- fake host: a daemon is a held lock --------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DaemonKind {
    Old,
    App,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopBehavior {
    Normal,
    Busy,
    Unresponsive,
    /// Says "stopping" and never lets go.
    KeepsLock,
}

struct Inner {
    config: PathBuf,
    runner: Arc<FakeRunner>,
    services: OsServices<Shared>,
    daemon: Mutex<Option<(HeldLock, DaemonKind)>>,
    stop: Mutex<StopBehavior>,
    crash_at: Mutex<Option<usize>>,
    points: AtomicUsize,
    labels: Mutex<Vec<String>>,
    start_fails: AtomicBool,
    /// Where the app daemon says it is installed.
    app_root: Mutex<String>,
    break_journal_writes: AtomicBool,
    started_old: AtomicUsize,
}

#[derive(Clone)]
struct Fake(Arc<Inner>);

impl Fake {
    fn new(config: &Path) -> Self {
        let runner = Arc::new(FakeRunner::default());
        Self(Arc::new(Inner {
            config: config.to_path_buf(),
            services: OsServices { runner: Shared(runner.clone()), uid: 501 },
            runner,
            daemon: Mutex::new(None),
            stop: Mutex::new(StopBehavior::Normal),
            crash_at: Mutex::new(None),
            points: AtomicUsize::new(0),
            labels: Mutex::new(Vec::new()),
            start_fails: AtomicBool::new(false),
            app_root: Mutex::new(String::new()),
            break_journal_writes: AtomicBool::new(false),
            started_old: AtomicUsize::new(0),
        }))
    }

    fn start(&self, kind: DaemonKind) -> Result<(), String> {
        let lock = HeldLock::acquire_daemon_lock(&self.0.config)
            .map_err(|e| format!("another daemon is already running: {e:?}"))?;
        *self.0.daemon.lock().unwrap() = Some((lock, kind));
        Ok(())
    }

    fn running(&self) -> Option<DaemonKind> {
        self.0.daemon.lock().unwrap().as_ref().map(|(_, k)| *k)
    }

    fn crash_at(&self, n: Option<usize>) {
        *self.0.crash_at.lock().unwrap() = n;
        self.0.points.store(0, Ordering::SeqCst);
    }

    fn points_seen(&self) -> usize {
        self.0.points.load(Ordering::SeqCst)
    }
}

impl Host for Fake {
    fn services(&self) -> &dyn ServiceManager {
        &self.0.services
    }

    async fn safe_stop(&self, _deadline: Duration) -> StopAnswer {
        match *self.0.stop.lock().unwrap() {
            StopBehavior::Busy => return StopAnswer::Busy { detail: "writes in progress".into() },
            StopBehavior::Unresponsive => return StopAnswer::Unresponsive("timed out".into()),
            StopBehavior::KeepsLock => return StopAnswer::Stopping,
            StopBehavior::Normal => {}
        }
        match self.0.daemon.lock().unwrap().take() {
            Some(_) => StopAnswer::Stopping,
            None => StopAnswer::NotRunning,
        }
    }

    async fn start_previous(&self, previous: &OwnershipRecord) -> Result<(), String> {
        // It is the recorded installation's daemon that is started.
        assert_eq!(previous.install_source, "script");
        if self.0.start_fails.load(Ordering::SeqCst) {
            return Err("the daemon binary is gone".into());
        }
        self.0.started_old.fetch_add(1, Ordering::SeqCst);
        self.start(DaemonKind::Old)
    }

    async fn identify(&self) -> Option<RunningInstall> {
        let kind = self.running()?;
        Some(match kind {
            DaemonKind::Old => RunningInstall {
                install_source: "script".into(),
                install_root: "/home/u/.local/lib/yadorilink".into(),
                version: "1.0.0".into(),
                release_id: OLD_RELEASE.into(),
                engine_api_version: 1,
            },
            DaemonKind::App => RunningInstall {
                install_source: "app_bundle".into(),
                install_root: self.0.app_root.lock().unwrap().clone(),
                version: "1.1.0".into(),
                release_id: APP_RELEASE.into(),
                engine_api_version: 1,
            },
        })
    }

    fn local_descriptor(&self) -> Result<ReleaseDescriptor, DescriptorProblem> {
        Ok(ReleaseDescriptor {
            version: "1.0.0".into(),
            channel: String::new(),
            install_source: "script".into(),
            release_id: OLD_RELEASE.into(),
            engine_api_version: 1,
        })
    }

    fn crash_point(&self, label: &str) -> bool {
        // Makes every later journal write fail, as a full disk would.
        if label == "planned" && self.0.break_journal_writes.load(Ordering::SeqCst) {
            let temporary =
                self.0.config.join(format!(".{}.tmp-{}", journal::FILE_NAME, std::process::id()));
            std::fs::create_dir(temporary).unwrap();
        }
        let n = self.0.points.fetch_add(1, Ordering::SeqCst);
        self.0.labels.lock().unwrap().push(label.to_string());
        *self.0.crash_at.lock().unwrap() == Some(n)
    }
}

// ---- a machine -----------------------------------------------------------------------------

struct Env {
    _dir: tempfile::TempDir,
    config: PathBuf,
    home: PathBuf,
    app: PathBuf,
    engine: PathBuf,
    previous: OwnershipRecord,
    host: Fake,
}

fn write_identity(dir: &Path, api: u32, sha: &str, digest: &str) {
    std::fs::write(
        dir.join(release_descriptor::ENGINE_IDENTITY_FILE),
        format!(
            r#"{{"public_commit_sha":"{sha}","build_config_digest":"{digest}","engine_api_version":{api}}}"#
        ),
    )
    .unwrap();
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let home = dir.path().join("home");
        let app = dir.path().join("Applications/YadoriLink.app");
        let macos = app.join("Contents/MacOS");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&macos).unwrap();
        let engine = macos.join("yadorilink-daemon");
        std::fs::write(&engine, b"engine").unwrap();
        write_identity(&macos, 1, "appsha", "2");
        // User data the hand-off must never touch.
        std::fs::write(config.join("sync-state.sqlite3"), b"state").unwrap();
        std::fs::write(config.join("device.json"), b"device").unwrap();
        // The command-line install's two registrations.
        let agents = home.join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::write(agents.join(format!("{PLIST}.plist")), b"<plist/>").unwrap();
        let units = home.join(".config/systemd/user");
        std::fs::create_dir_all(&units).unwrap();
        std::fs::write(units.join(UNIT), b"[Service]").unwrap();
        let previous = OwnershipRecord {
            owner: Owner::Cli,
            install_source: "script".into(),
            install_root: "/home/u/.local/lib/yadorilink".into(),
            release_id: OLD_RELEASE.into(),
            written_at: 1,
        };
        ownership::write(&config, &previous).unwrap();
        // The hand-off judges paths as the OS resolves them (a temp dir may sit behind a link).
        let app = resolved(&app).unwrap();
        let engine = app.join("Contents/MacOS/yadorilink-daemon");
        let host = Fake::new(&config);
        *host.0.app_root.lock().unwrap() = app.display().to_string();
        host.start(DaemonKind::Old).unwrap();
        Self { _dir: dir, config, home, app, engine, previous, host }
    }

    fn ctx(&self) -> Context {
        Context {
            config_dir: self.config.clone(),
            roots: Roots {
                home: self.home.clone(),
                system_root: self.home.join("win"),
                app_bundles: vec![self.app.clone()],
            },
            stop_deadline: Duration::from_secs(1),
            lock_wait: Duration::from_millis(300),
            now: NOW,
        }
    }

    fn request(&self) -> Request {
        Request {
            install_source: "app_bundle".into(),
            install_root: self.app.clone(),
            engine_exe: self.engine.clone(),
        }
    }

    fn plist(&self) -> PathBuf {
        self.home.join(format!("Library/LaunchAgents/{PLIST}.plist"))
    }

    fn unit(&self) -> PathBuf {
        self.home.join(format!(".config/systemd/user/{UNIT}"))
    }

    fn definitions_present(&self) -> usize {
        [self.plist(), self.unit()].iter().filter(|p| p.exists()).count()
    }

    fn backups_present(&self) -> usize {
        [PLIST, UNIT].iter().filter(|n| journal::backup_path(&self.config, n).exists()).count()
    }

    fn record(&self) -> RecordState {
        ownership::read(&self.config)
    }

    fn journal(&self) -> JournalState {
        journal::read(&self.config)
    }

    fn user_data(&self) -> (Vec<u8>, Vec<u8>) {
        (
            std::fs::read(self.config.join("sync-state.sqlite3")).unwrap(),
            std::fs::read(self.config.join("device.json")).unwrap(),
        )
    }

    fn target(&self) -> OwnershipRecord {
        OwnershipRecord {
            owner: Owner::Gui,
            install_source: "app_bundle".into(),
            install_root: self.app.display().to_string(),
            release_id: APP_RELEASE.into(),
            written_at: NOW,
        }
    }

    /// Everything the hand-off may have touched, to compare before and after a refusal.
    fn snapshot(&self) -> (RecordState, usize, usize, bool, Option<DaemonKind>) {
        (
            self.record(),
            self.definitions_present(),
            self.backups_present(),
            matches!(self.journal(), JournalState::Missing),
            self.host.running(),
        )
    }

    async fn release(&self) -> Result<Outcome, HandoffError> {
        release(&self.host, &self.ctx(), &self.request()).await
    }

    async fn rollback(&self) -> Result<Outcome, HandoffError> {
        rollback(&self.host, &self.ctx()).await
    }

    async fn commit(&self) -> Result<Outcome, HandoffError> {
        commit(&self.host, &self.ctx()).await
    }

    /// The area as it was before: previous owner, both registrations in place, no hand-off open.
    fn assert_as_before(&self, daemon: Option<DaemonKind>) {
        assert_eq!(self.record(), RecordState::Present(self.previous.clone()));
        assert_eq!(self.definitions_present(), 2);
        assert_eq!(self.backups_present(), 0);
        assert_eq!(self.journal(), JournalState::Missing);
        assert_eq!(self.host.running(), daemon);
        assert_eq!(self.user_data(), (b"state".to_vec(), b"device".to_vec()));
    }

    /// The area as released: the app owns it, no registration of the old install is active.
    fn assert_released(&self) {
        assert_eq!(self.record(), RecordState::Present(self.target()));
        assert_eq!(self.definitions_present(), 0);
        assert_eq!(self.backups_present(), 2);
        assert!(matches!(self.journal(), JournalState::Present(j) if j.phase == Phase::Switched));
        assert_eq!(self.host.running(), None);
        assert_eq!(self.user_data(), (b"state".to_vec(), b"device".to_vec()));
    }

    /// At no instant is the area split: either the journal says a switch is in progress (and no
    /// daemon may start), or the area is wholly the previous owner's or wholly the app's.
    fn assert_never_split(&self, what: &str) {
        let blocked = start_refusal(&self.config).is_some();
        let record = self.record();
        let regs = self.definitions_present();
        let is_previous = record == RecordState::Present(self.previous.clone());
        let is_target = record == RecordState::Present(self.target());
        assert!(is_previous || is_target || blocked, "{what}: record is neither owner's");
        if !blocked {
            assert!(
                (is_previous && regs == 2 && self.backups_present() == 0)
                    || (is_target && regs == 0 && self.backups_present() == 2),
                "{what}: split area (previous={is_previous} regs={regs}) and nothing blocks a start"
            );
        }
        assert_eq!(self.user_data(), (b"state".to_vec(), b"device".to_vec()), "{what}");
    }
}

// ---- the happy path -------------------------------------------------------------------------

#[tokio::test]
async fn release_hands_the_area_to_the_app_and_keeps_every_user_file() {
    let env = Env::new();
    assert_eq!(env.release().await, Ok(Outcome::Released));
    env.assert_released();
    // The previous daemon is stopped and nobody holds the lock: the app may start its own.
    env.host.start(DaemonKind::App).unwrap();
    assert!(start_refusal(&env.config).is_none());
    // The registrations were disabled through the OS tools, then moved aside, not deleted.
    let calls = env.host.0.runner.calls.lock().unwrap().join("\n");
    assert!(calls.contains("launchctl bootout gui/501/com.yadorilink.daemon"), "{calls}");
    assert!(calls.contains("systemctl --user disable --now yadorilink-daemon.service"), "{calls}");
    assert_eq!(std::fs::read(journal::backup_path(&env.config, PLIST)).unwrap(), b"<plist/>");
    assert_eq!(env.commit().await, Ok(Outcome::Committed));
    assert_eq!(env.journal(), JournalState::Missing);
    assert_eq!(env.record(), RecordState::Present(env.target()));
}

#[tokio::test]
async fn releasing_twice_is_safe_and_changes_nothing_the_second_time() {
    let env = Env::new();
    env.release().await.unwrap();
    let after_first = env.snapshot();
    assert_eq!(env.release().await, Ok(Outcome::AlreadyReleased));
    assert_eq!(env.snapshot(), after_first);
}

#[tokio::test]
async fn a_stopped_daemon_is_not_started_by_a_rollback() {
    let env = Env::new();
    drop(env.host.0.daemon.lock().unwrap().take());
    env.release().await.unwrap();
    assert_eq!(env.rollback().await, Ok(Outcome::RolledBack(PreviousDaemon::NotStarted)));
    env.assert_as_before(None);
    assert_eq!(env.host.0.started_old.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rollback_after_the_app_started_stops_the_apps_daemon_and_restarts_the_old_one() {
    let env = Env::new();
    env.release().await.unwrap();
    env.host.start(DaemonKind::App).unwrap();
    assert_eq!(env.rollback().await, Ok(Outcome::RolledBack(PreviousDaemon::Restarted)));
    env.assert_as_before(Some(DaemonKind::Old));
}

#[tokio::test]
async fn commit_verifies_the_apps_daemon_and_otherwise_leaves_the_hand_off_open() {
    let env = Env::new();
    env.release().await.unwrap();
    // No daemon answers yet.
    let refused = env.commit().await.unwrap_err();
    assert!(
        matches!(refused, HandoffError::Refused(Refused::VerificationFailed(_))),
        "{refused:?}"
    );
    // The previous daemon answering is not the app's.
    env.host.start(DaemonKind::Old).unwrap();
    let refused = env.commit().await.unwrap_err();
    assert!(
        matches!(refused, HandoffError::Refused(Refused::VerificationFailed(_))),
        "{refused:?}"
    );
    assert!(matches!(env.journal(), JournalState::Present(_)));
    drop(env.host.0.daemon.lock().unwrap().take());
    env.host.start(DaemonKind::App).unwrap();
    assert_eq!(env.commit().await, Ok(Outcome::Committed));
    // Nothing is open any more.
    assert_eq!(env.commit().await.unwrap_err(), HandoffError::Refused(Refused::NothingToDo));
}

#[tokio::test]
async fn commit_before_the_switch_is_refused() {
    let env = Env::new();
    assert_eq!(env.commit().await.unwrap_err(), HandoffError::Refused(Refused::NothingToDo));
    env.host.crash_at(Some(0));
    assert_eq!(env.release().await, Err(HandoffError::Crashed));
    env.host.crash_at(None);
    assert!(matches!(
        env.commit().await.unwrap_err(),
        HandoffError::Refused(Refused::NotReleased(Phase::Planned))
    ));
}

// ---- refusals change nothing ------------------------------------------------------------

async fn refused_with_nothing_changed(env: &Env) -> Refused {
    let before = env.snapshot();
    let error = env.release().await.unwrap_err();
    assert_eq!(env.snapshot(), before, "{error:?}");
    assert_eq!(env.user_data(), (b"state".to_vec(), b"device".to_vec()));
    match error {
        HandoffError::Refused(refused) => {
            assert!(!refused.message().is_empty());
            refused
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn set_record(env: &Env, owner: Owner, source: &str) {
    ownership::write(
        &env.config,
        &OwnershipRecord {
            owner,
            install_source: source.into(),
            install_root: "/x".into(),
            release_id: OLD_RELEASE.into(),
            written_at: 1,
        },
    )
    .unwrap();
}

#[tokio::test]
async fn package_manager_owned_daemons_are_refused() {
    for source in ["homebrew", "apt", "winget", "container", "other"] {
        let env = Env::new();
        set_record(&env, Owner::Cli, source);
        let refused = refused_with_nothing_changed(&env).await;
        assert!(matches!(refused, Refused::PackageManagerOwned(_)), "{source}: {refused:?}");
    }
}

#[tokio::test]
async fn an_unknown_or_app_owner_is_refused() {
    let env = Env::new();
    std::fs::remove_file(env.config.join(ownership::FILE_NAME)).unwrap();
    assert!(matches!(refused_with_nothing_changed(&env).await, Refused::OwnerUnknown(_)));
    std::fs::write(env.config.join(ownership::FILE_NAME), b"{ not json").unwrap();
    assert!(matches!(refused_with_nothing_changed(&env).await, Refused::OwnerUnknown(_)));
    set_record(&env, Owner::Gui, "app_bundle");
    assert!(matches!(refused_with_nothing_changed(&env).await, Refused::AlreadyManagedByApp(_)));
}

#[tokio::test]
async fn an_unusable_target_is_refused() {
    let env = Env::new();
    // Not an app install source.
    let mut req = env.request();
    req.install_source = "script".into();
    assert!(matches!(
        release(&env.host, &env.ctx(), &req).await.unwrap_err(),
        HandoffError::Refused(Refused::TargetInvalid(_))
    ));
    // Not a bundle.
    let mut req = env.request();
    req.install_root = env.config.clone();
    req.engine_exe = env.config.join("device.json");
    assert!(matches!(
        release(&env.host, &env.ctx(), &req).await.unwrap_err(),
        HandoffError::Refused(Refused::TargetInvalid(_))
    ));
    // The engine is outside the bundle.
    let mut req = env.request();
    req.engine_exe = env.config.join("device.json");
    assert!(matches!(
        release(&env.host, &env.ctx(), &req).await.unwrap_err(),
        HandoffError::Refused(Refused::TargetInvalid(_))
    ));
    // A Store package is not a bundle.
    let mut req = env.request();
    req.install_source = "microsoft_store".into();
    assert!(matches!(
        release(&env.host, &env.ctx(), &req).await.unwrap_err(),
        HandoffError::Refused(Refused::TargetInvalid(_))
    ));
    assert_eq!(env.definitions_present(), 2);
    assert_eq!(env.host.running(), Some(DaemonKind::Old));
}

#[tokio::test]
async fn an_engine_outside_the_requested_app_is_refused_however_the_path_is_spelled() {
    let env = Env::new();
    // A second, complete app next to the first.
    let other = env.app.parent().unwrap().join("Other.app");
    let other_macos = other.join("Contents/MacOS");
    std::fs::create_dir_all(&other_macos).unwrap();
    std::fs::write(other_macos.join("yadorilink-daemon"), b"e").unwrap();
    write_identity(&other_macos, 1, "othersha", "9");
    let mut req = env.request();
    // Lexically inside the requested bundle, really in the other one.
    req.engine_exe = env.app.join("../Other.app/Contents/MacOS/yadorilink-daemon");
    assert!(matches!(
        release(&env.host, &env.ctx(), &req).await.unwrap_err(),
        HandoffError::Refused(Refused::TargetInvalid(_))
    ));
    #[cfg(unix)]
    {
        let link = env.app.join("Contents/MacOS/linked");
        std::os::unix::fs::symlink(&other_macos, &link).unwrap();
        req.engine_exe = link.join("yadorilink-daemon");
        assert!(matches!(
            release(&env.host, &env.ctx(), &req).await.unwrap_err(),
            HandoffError::Refused(Refused::TargetInvalid(_))
        ));
    }
    assert_eq!(env.definitions_present(), 2);
    assert_eq!(env.host.running(), Some(DaemonKind::Old));
    assert_eq!(env.journal(), JournalState::Missing);
}

#[tokio::test]
async fn commit_refuses_a_daemon_of_the_right_release_started_from_another_copy_of_the_app() {
    let env = Env::new();
    env.release().await.unwrap();
    *env.host.0.app_root.lock().unwrap() = "/Volumes/Other/YadoriLink.app".into();
    env.host.start(DaemonKind::App).unwrap();
    let refused = env.commit().await.unwrap_err();
    assert!(
        matches!(&refused, HandoffError::Refused(Refused::VerificationFailed(m)) if m.contains("not at")),
        "{refused:?}"
    );
    assert!(matches!(env.journal(), JournalState::Present(_)));
}

#[tokio::test]
async fn an_app_without_a_readable_or_compatible_release_is_refused() {
    let macos = |env: &Env| env.app.join("Contents/MacOS");
    let env = Env::new();
    std::fs::remove_file(macos(&env).join(release_descriptor::ENGINE_IDENTITY_FILE)).unwrap();
    assert!(matches!(refused_with_nothing_changed(&env).await, Refused::TargetIncompatible(_)));
    std::fs::write(macos(&env).join(release_descriptor::ENGINE_IDENTITY_FILE), b"nope").unwrap();
    assert!(matches!(refused_with_nothing_changed(&env).await, Refused::TargetIncompatible(_)));
    // An engine older than the install's would not understand the data it is handed.
    write_identity(&macos(&env), 0, "appsha", "2");
    assert!(matches!(refused_with_nothing_changed(&env).await, Refused::TargetIncompatible(_)));
}

#[tokio::test]
async fn a_registration_of_an_unknown_installation_is_refused() {
    let env = Env::new();
    let mut req = env.request();
    // A Store target: the app bundle's own agent belongs to neither the script install nor it.
    let store = env._dir.path().join("WindowsApps/YadoriLink");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("engine.exe"), b"e").unwrap();
    write_identity(&store, 1, "appsha", "2");
    req.install_source = "microsoft_store".into();
    req.install_root = store.clone();
    req.engine_exe = store.join("engine.exe");
    let agent = env.app.join(format!(
        "Contents/Library/LaunchAgents/{}.plist",
        service_registrations::MACOS_DAEMON_AGENT_LABEL
    ));
    std::fs::create_dir_all(agent.parent().unwrap()).unwrap();
    std::fs::write(&agent, b"<plist/>").unwrap();
    let before = env.snapshot();
    let error = release(&env.host, &env.ctx(), &req).await.unwrap_err();
    assert!(
        matches!(error, HandoffError::Refused(Refused::UnknownRegistration { .. })),
        "{error:?}"
    );
    assert_eq!(env.snapshot(), before);
}

#[tokio::test]
async fn doctor_findings_stop_the_hand_off() {
    let env = Env::new();
    // The running daemon is another install than the record says.
    env.host.0.daemon.lock().unwrap().as_mut().unwrap().1 = DaemonKind::App;
    let refused = refused_with_nothing_changed(&env).await;
    assert!(matches!(refused, Refused::Preflight(ref rows) if !rows.is_empty()), "{refused:?}");
}

#[test]
fn a_registration_with_a_copy_outside_the_users_account_is_not_movable() {
    let home = Path::new("/Users/u");
    let user = PathBuf::from("/Users/u/Library/LaunchAgents/a.plist");
    let system = PathBuf::from("/Library/LaunchAgents/a.plist");
    assert_eq!(
        movable_definition(Kind::LaunchAgent, std::slice::from_ref(&user), home),
        Some(user.clone())
    );
    assert_eq!(movable_definition(Kind::LaunchAgent, std::slice::from_ref(&system), home), None);
    // Moving the user copy would leave the system-wide one starting the daemon.
    assert_eq!(movable_definition(Kind::LaunchAgent, &[user, system], home), None);
    assert_eq!(movable_definition(Kind::LaunchAgent, &[], home), None);
}

#[test]
fn the_verbatim_windows_spelling_is_stripped_only_for_drive_paths() {
    assert_eq!(
        strip_verbatim(r"\\?\C:\Program Files\WindowsApps\X"),
        Some(r"C:\Program Files\WindowsApps\X")
    );
    assert_eq!(strip_verbatim(r"\\?\UNC\host\share"), None);
    assert_eq!(strip_verbatim("/Applications/YadoriLink.app"), None);
}

#[test]
fn only_registrations_in_the_users_account_can_be_moved_aside() {
    let home = Path::new("/Users/u");
    assert!(removable_by_us(
        Kind::LaunchAgent,
        Path::new("/Users/u/Library/LaunchAgents/a.plist"),
        home
    ));
    assert!(!removable_by_us(Kind::LaunchAgent, Path::new("/Library/LaunchAgents/a.plist"), home));
    assert!(removable_by_us(
        Kind::SystemdUserUnit,
        Path::new("/Users/u/.config/systemd/user/a"),
        home
    ));
    assert!(!removable_by_us(Kind::SystemdUserUnit, Path::new("/usr/lib/systemd/user/a"), home));
    assert!(!removable_by_us(Kind::SystemdSystemUnit, Path::new("/etc/systemd/system/a"), home));
    assert!(!removable_by_us(Kind::BundledLaunchAgent, Path::new("/Users/u/x"), home));
    assert!(removable_by_us(Kind::WindowsTask, Path::new("C:/Windows/System32/Tasks/X"), home));
}

// ---- the daemon will not stop ------------------------------------------------------------

#[tokio::test]
async fn a_busy_or_wedged_daemon_aborts_with_the_old_daemon_untouched() {
    for behavior in [StopBehavior::Busy, StopBehavior::Unresponsive, StopBehavior::KeepsLock] {
        let env = Env::new();
        *env.host.0.stop.lock().unwrap() = behavior;
        let before_data = env.user_data();
        let error = env.release().await.unwrap_err();
        assert!(matches!(error, HandoffError::Refused(_)), "{behavior:?}: {error:?}");
        assert_eq!(env.record(), RecordState::Present(env.previous.clone()), "{behavior:?}");
        assert_eq!(env.definitions_present(), 2, "{behavior:?}");
        assert_eq!(env.backups_present(), 0, "{behavior:?}");
        assert_eq!(env.journal(), JournalState::Missing, "{behavior:?}");
        assert_eq!(env.host.running(), Some(DaemonKind::Old), "{behavior:?}: still the old daemon");
        assert_eq!(env.user_data(), before_data);
    }
}

#[tokio::test]
async fn a_journal_that_cannot_be_written_after_the_stop_restarts_the_daemon() {
    let env = Env::new();
    env.host.0.break_journal_writes.store(true, Ordering::SeqCst);
    let error = env.release().await.unwrap_err();
    assert!(matches!(error, HandoffError::Refused(Refused::Unusable(_))), "{error:?}");
    // The daemon the attempt stopped is running again; nothing else changed.
    assert_eq!(env.host.running(), Some(DaemonKind::Old));
    assert_eq!(env.host.0.started_old.load(Ordering::SeqCst), 1);
    assert_eq!(env.record(), RecordState::Present(env.previous.clone()));
    assert_eq!(env.definitions_present(), 2);
    assert_eq!(env.backups_present(), 0);
    // And if it cannot be restarted either, that is said.
    let env = Env::new();
    env.host.0.break_journal_writes.store(true, Ordering::SeqCst);
    env.host.0.start_fails.store(true, Ordering::SeqCst);
    let error = env.release().await.unwrap_err();
    assert!(
        matches!(error, HandoffError::Refused(Refused::PreviousDaemonNotStarted(_))),
        "{error:?}"
    );
}

// ---- failures at every step ------------------------------------------------------------------

#[tokio::test]
async fn a_failure_at_any_step_rolls_everything_back() {
    for pattern in
        ["launchctl bootout", "systemctl --user disable", "systemctl --user daemon-reload"]
    {
        let env = Env::new();
        *env.host.0.runner.fail_pattern.lock().unwrap() = Some(pattern.into());
        // Restoring re-enables with other commands; only the injected one keeps failing.
        let result = env.release().await;
        *env.host.0.runner.fail_pattern.lock().unwrap() = None;
        match result {
            Err(HandoffError::RolledBack { previous, .. }) => {
                assert_eq!(previous, PreviousDaemon::Restarted, "{pattern}");
            }
            // The roll-back needed the failing command too: it is repeatable once the tool works.
            Err(HandoffError::RollbackFailed { .. }) => {
                assert!(start_refusal(&env.config).is_some(), "{pattern}: a start must be blocked");
                assert!(matches!(env.rollback().await, Ok(Outcome::RolledBack(_))), "{pattern}");
            }
            other => panic!("{pattern}: {other:?}"),
        }
        env.assert_as_before(Some(DaemonKind::Old));
    }
}

#[tokio::test]
async fn a_record_that_cannot_be_written_rolls_back_and_the_roll_back_can_be_repeated() {
    let env = Env::new();
    // A directory where the writer's temporary file goes makes every record write fail.
    let obstacle = env.config.join(format!(".{}.tmp-{}", ownership::FILE_NAME, std::process::id()));
    std::fs::create_dir(&obstacle).unwrap();
    let error = env.release().await.unwrap_err();
    // The registrations were disabled first; the roll-back needs the record writer too, so it
    // stops half-way, with the area closed to every daemon.
    assert!(matches!(error, HandoffError::RollbackFailed { .. }), "{error:?}");
    assert!(start_refusal(&env.config).is_some());
    assert_eq!(env.host.running(), None, "no daemon runs, and none can start");
    assert_eq!(env.user_data(), (b"state".to_vec(), b"device".to_vec()));
    // Repeating it before the obstacle is gone fails the same way, without harm.
    assert!(matches!(env.rollback().await.unwrap_err(), HandoffError::RollbackFailed { .. }));
    std::fs::remove_dir(&obstacle).unwrap();
    assert_eq!(env.rollback().await, Ok(Outcome::RolledBack(PreviousDaemon::Restarted)));
    env.assert_as_before(Some(DaemonKind::Old));
}

#[tokio::test]
async fn when_the_old_daemon_cannot_be_started_again_the_old_owner_is_still_restored() {
    let env = Env::new();
    *env.host.0.runner.fail_pattern.lock().unwrap() = Some("systemctl --user disable".into());
    env.host.0.start_fails.store(true, Ordering::SeqCst);
    let error = env.release().await.unwrap_err();
    *env.host.0.runner.fail_pattern.lock().unwrap() = None;
    assert!(
        matches!(
            error,
            HandoffError::RolledBack { previous: PreviousDaemon::FailedToStart(_), .. }
        ),
        "{error:?}"
    );
    // No daemon runs, the old owner is fully restored, and nothing is open.
    env.assert_as_before(None);
}

// ---- interruption at every point ---------------------------------------------------------------

async fn points_of_a_clean_release() -> usize {
    let env = Env::new();
    env.host.crash_at(None);
    env.release().await.unwrap();
    env.host.points_seen()
}

#[tokio::test]
async fn an_interruption_at_every_point_ends_in_one_owner_and_at_most_one_daemon() {
    let points = points_of_a_clean_release().await;
    assert!(points >= 10, "{points}: the matrix must cover every journal write");
    for k in 0..points {
        // Resume: running the same hand-off again finishes it.
        let env = Env::new();
        env.host.crash_at(Some(k));
        assert_eq!(env.release().await, Err(HandoffError::Crashed), "point {k}");
        env.host.crash_at(None);
        env.assert_never_split(&format!("after a crash at point {k}"));
        assert!(env.host.0.daemon.lock().unwrap().is_none() || env.host.running().is_some());
        match env.release().await {
            Ok(Outcome::Released | Outcome::AlreadyReleased) => {}
            other => panic!("point {k}: resume gave {other:?}"),
        }
        env.assert_released();
        env.host.start(DaemonKind::App).unwrap();
        assert_eq!(env.commit().await, Ok(Outcome::Committed), "point {k}");

        // Roll back: the previous owner is restored whatever was done.
        let env = Env::new();
        env.host.crash_at(Some(k));
        assert_eq!(env.release().await, Err(HandoffError::Crashed), "point {k}");
        env.host.crash_at(None);
        match env.rollback().await {
            Ok(Outcome::RolledBack(_)) => {}
            other => panic!("point {k}: roll-back gave {other:?}"),
        }
        env.assert_as_before(Some(DaemonKind::Old));
    }
}

#[tokio::test]
async fn an_interrupted_rollback_can_be_repeated_at_every_point() {
    // Count the points of a roll-back after a full release.
    let counting = Env::new();
    counting.release().await.unwrap();
    counting.host.crash_at(None);
    counting.rollback().await.unwrap();
    let points = counting.host.points_seen();
    assert!(points >= 6, "{points}");
    for j in 0..points {
        let env = Env::new();
        env.release().await.unwrap();
        env.host.crash_at(Some(j));
        assert_eq!(env.rollback().await, Err(HandoffError::Crashed), "rollback point {j}");
        env.host.crash_at(None);
        env.assert_never_split(&format!("after a roll-back crashed at point {j}"));
        assert_eq!(env.host.running(), None);
        match env.rollback().await {
            Ok(Outcome::RolledBack(_)) => {}
            // The crash came after the journal was removed.
            Err(HandoffError::Refused(Refused::NothingToDo)) => {
                // The old daemon was not restarted by the crashed run; a start is allowed.
                assert!(start_refusal(&env.config).is_none());
                env.host.start(DaemonKind::Old).unwrap();
            }
            other => panic!("rollback point {j}: {other:?}"),
        }
        env.assert_as_before(Some(DaemonKind::Old));
    }
}

#[tokio::test]
async fn a_half_applied_switch_blocks_a_start_of_either_owner_until_it_is_settled() {
    // Find a crash point inside the switch: after the intent of the second mutation.
    let points = points_of_a_clean_release().await;
    let mut seen_block = false;
    for k in 0..points {
        let env = Env::new();
        env.host.crash_at(Some(k));
        let _ = env.release().await;
        let in_switch =
            matches!(env.journal(), JournalState::Present(ref j) if j.phase == Phase::Switching);
        if in_switch {
            seen_block = true;
            let refusal = start_refusal(&env.config).expect("a start must be blocked");
            assert!(matches!(refusal, ownership::Refusal::HandoffUnfinished { .. }));
            assert!(refusal.message(&env.config).contains("release-to-app"));
        }
    }
    assert!(seen_block);
}

#[tokio::test]
async fn a_record_somebody_else_wrote_is_never_overwritten_by_resume_or_rollback() {
    // Crash in the middle of the switch, then a third party records another owner.
    let points = points_of_a_clean_release().await;
    let mut checked = 0;
    for k in 0..points {
        let env = Env::new();
        env.host.crash_at(Some(k));
        let _ = env.release().await;
        env.host.crash_at(None);
        if !matches!(env.journal(), JournalState::Present(ref j) if j.phase == Phase::Switching) {
            continue;
        }
        let foreign = OwnershipRecord {
            owner: Owner::Cli,
            install_source: "apt".into(),
            install_root: "/usr".into(),
            release_id: String::new(),
            written_at: 7,
        };
        ownership::write(&env.config, &foreign).unwrap();
        let record_touched = matches!(env.journal(), JournalState::Present(ref j)
            if j.mutations.iter().any(|m| m.kind == journal::MutationKind::RewriteRecord
                && m.state != journal::MutationState::Pending));
        let resumed = env.release().await.unwrap_err();
        assert!(matches!(resumed, HandoffError::Refused(Refused::RecordChanged(_))), "{resumed:?}");
        let rolled = env.rollback().await;
        if record_touched {
            // The journal may have written over the record: it will not write over another's.
            assert!(matches!(rolled, Err(HandoffError::RollbackFailed { .. })), "{rolled:?}");
            assert!(start_refusal(&env.config).is_some());
        }
        assert_eq!(env.record(), RecordState::Present(foreign));
        checked += usize::from(record_touched);
    }
    assert!(checked > 0);
}

// ---- power loss: a damaged journal fails closed ----------------------------------------------------

#[tokio::test]
async fn a_journal_cut_off_at_any_length_is_refused_and_nothing_is_touched() {
    let points = points_of_a_clean_release().await;
    for k in 0..points {
        let env = Env::new();
        env.host.crash_at(Some(k));
        let _ = env.release().await;
        env.host.crash_at(None);
        let path = env.config.join(journal::FILE_NAME);
        let Ok(full) = std::fs::read(&path) else { continue };
        let cuts = [0, 1, full.len() / 3, full.len() / 2, full.len() - 1];
        for cut in cuts {
            std::fs::write(&path, &full[..cut]).unwrap();
            assert!(matches!(env.journal(), JournalState::Unreadable(_)), "point {k} cut {cut}");
            let before = (
                env.record(),
                env.definitions_present(),
                env.backups_present(),
                env.host.running(),
            );
            for result in [env.release().await, env.rollback().await, env.commit().await] {
                assert!(
                    matches!(result, Err(HandoffError::Refused(Refused::JournalUnreadable(_)))),
                    "point {k} cut {cut}: {result:?}"
                );
            }
            // A daemon may not start either: how far the switch got is unknown.
            assert!(start_refusal(&env.config).is_some());
            assert_eq!(
                before,
                (
                    env.record(),
                    env.definitions_present(),
                    env.backups_present(),
                    env.host.running()
                )
            );
            assert_eq!(env.user_data(), (b"state".to_vec(), b"device".to_vec()));
        }
    }
}

/// The journal is replaced atomically and durably: a power cut at any point of a write leaves the
/// previous journal or the new one, never a half-trusted file (large-tree acceptance, power loss).
#[test]
fn power_loss_during_a_journal_write_leaves_the_old_or_the_new_journal() {
    use yadorilink_fs_platform::durable_dir::{arm_failpoint, disarm_failpoint, NsFailpoint};

    let env = Env::new();
    let (cli, app) = (env.target(), env.target());
    let journal_in = |phase| {
        let mut j = journal::Journal::new(cli.clone(), app.clone(), true, Vec::new(), NOW);
        j.phase = phase;
        j
    };
    for point in [NsFailpoint::AfterStage, NsFailpoint::BeforeMove, NsFailpoint::AfterMove] {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = (journal_in(Phase::Planned), journal_in(Phase::Switching));
        journal::write(dir.path(), &old).unwrap();
        arm_failpoint(point);
        let result = journal::write(dir.path(), &new);
        disarm_failpoint();
        assert!(result.is_err(), "{point:?}");
        match journal::read(dir.path()) {
            JournalState::Present(j) if *j == old || *j == new => {}
            other => panic!("{point:?}: neither the old nor the new journal: {other:?}"),
        }
        if point != NsFailpoint::AfterMove {
            assert!(matches!(journal::read(dir.path()), JournalState::Present(j) if *j == old));
        }
        journal::write(dir.path(), &new).unwrap();
        assert!(matches!(journal::read(dir.path()), JournalState::Present(j) if *j == new));
    }
}

// ---- concurrency ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_second_hand_off_while_one_runs_is_refused() {
    let env = Env::new();
    let _running = HeldLock::acquire(&env.config, journal::LOCK_FILE_NAME).unwrap();
    assert_eq!(
        env.release().await.unwrap_err(),
        HandoffError::Refused(Refused::AnotherHandoffRunning)
    );
    assert_eq!(
        env.rollback().await.unwrap_err(),
        HandoffError::Refused(Refused::AnotherHandoffRunning)
    );
    assert_eq!(
        env.commit().await.unwrap_err(),
        HandoffError::Refused(Refused::AnotherHandoffRunning)
    );
    assert_eq!(env.record(), RecordState::Present(env.previous.clone()));
    assert_eq!(env.host.running(), Some(DaemonKind::Old));
}

#[test]
fn two_concurrent_hand_offs_release_the_area_once() {
    for round in 0..8 {
        let env = Env::new();
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    scope.spawn(|| {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap()
                            .block_on(env.release())
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let released = results.iter().filter(|r| matches!(r, Ok(Outcome::Released))).count();
        assert_eq!(released, 1, "round {round}: {results:?}");
        for r in &results {
            assert!(
                matches!(
                    r,
                    Ok(Outcome::Released | Outcome::AlreadyReleased)
                        | Err(HandoffError::Refused(Refused::AnotherHandoffRunning))
                ),
                "round {round}: {r:?}"
            );
        }
        env.assert_released();
    }
}

/// One attempt to start a daemon: the lock first, then the gate; what the gate lets through must
/// be a settled area.
fn try_a_start(env: &Env) {
    let Ok(lock) = HeldLock::acquire_daemon_lock(&env.config) else { return };
    if start_refusal(&env.config).is_none() {
        let record = env.record();
        if record == RecordState::Present(env.target()) {
            assert_eq!(env.definitions_present(), 0, "app start saw old registrations");
        } else {
            assert_eq!(record, RecordState::Present(env.previous.clone()));
            assert_eq!(env.definitions_present(), 2, "old start saw a half switch");
        }
    }
    drop(lock);
}

#[test]
fn an_app_start_racing_the_hand_off_only_ever_sees_a_settled_area() {
    // A "daemon start" is: take the data-area lock, then pass the start gate. Whenever it
    // passes for the app, the area must be wholly the app's; whenever it passes for the old
    // install, wholly the old one's. The lock the hand-off holds keeps the two apart.
    for round in 0..6 {
        let env = Env::new();
        drop(env.host.0.daemon.lock().unwrap().take());
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let racer = scope.spawn(|| {
                while !done.load(Ordering::SeqCst) {
                    try_a_start(&env);
                    std::thread::sleep(Duration::from_micros(300));
                }
            });
            let outcome = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(env.release());
            done.store(true, Ordering::SeqCst);
            racer.join().unwrap();
            assert_eq!(outcome, Ok(Outcome::Released), "round {round}");
        });
        env.assert_released();
    }
}

// ---- the real service tools, driven through a recording runner --------------------------------------------

fn plan(kind: Kind, env: &Env, name: &str, definition: PathBuf) -> journal::RegistrationPlan {
    journal::RegistrationPlan {
        kind,
        name: name.into(),
        definition,
        backup: journal::backup_path(&env.config, name),
        was_active: true,
    }
}

#[test]
fn every_service_operation_is_idempotent() {
    let env = Env::new();
    let services = &env.host.0.services;
    for (kind, name, definition) in
        [(Kind::LaunchAgent, PLIST, env.plist()), (Kind::SystemdUserUnit, UNIT, env.unit())]
    {
        let plan = plan(kind, &env, name, definition.clone());
        let original = std::fs::read(&definition).unwrap();
        services.disable(&plan).unwrap();
        services.disable(&plan).unwrap();
        assert!(!definition.exists() && plan.backup.exists());
        services.restore(&plan).unwrap();
        services.restore(&plan).unwrap();
        assert_eq!(std::fs::read(&definition).unwrap(), original);
        assert!(!plan.backup.exists());
    }
}

#[test]
fn an_agent_that_is_already_unloaded_is_not_unloaded_again() {
    let env = Env::new();
    let services = &env.host.0.services;
    let p = plan(Kind::LaunchAgent, &env, PLIST, env.plist());
    // launchctl no longer knows the agent (an earlier run unloaded it, then died).
    *env.host.0.runner.fail_pattern.lock().unwrap() = Some("launchctl print".into());
    services.disable(&p).unwrap();
    let calls = env.host.0.runner.calls.lock().unwrap().join("\n");
    assert!(!calls.contains("bootout"), "{calls}");
    assert!(p.backup.exists() && !env.plist().exists());
}

#[test]
fn a_vanished_or_doubled_definition_is_never_guessed_at() {
    let env = Env::new();
    let services = &env.host.0.services;
    let p = plan(Kind::LaunchAgent, &env, PLIST, env.plist());
    std::fs::remove_file(env.plist()).unwrap();
    assert!(services.disable(&p).unwrap_err().contains("disappeared"));
    assert!(services.restore(&p).is_err());
    // Both the definition and its backup exist: restore refuses to choose.
    std::fs::write(env.plist(), b"a").unwrap();
    std::fs::create_dir_all(p.backup.parent().unwrap()).unwrap();
    std::fs::write(&p.backup, b"b").unwrap();
    assert!(services.restore(&p).unwrap_err().contains("refusing to choose"));
    assert_eq!(std::fs::read(env.plist()).unwrap(), b"a");
    assert_eq!(std::fs::read(&p.backup).unwrap(), b"b");
}

#[test]
fn a_windows_task_is_exported_before_it_is_deleted_and_recreated_from_the_export() {
    let env = Env::new();
    let services = &env.host.0.services;
    let definition = env.home.join("win/System32/Tasks/YadoriLinkDaemon");
    std::fs::create_dir_all(definition.parent().unwrap()).unwrap();
    std::fs::write(&definition, b"task").unwrap();
    let task = plan(Kind::WindowsTask, &env, "YadoriLinkDaemon", definition);
    services.disable(&task).unwrap();
    let calls = env.host.0.runner.calls.lock().unwrap().clone();
    let query = calls.iter().position(|c| c.contains("schtasks /Query")).unwrap();
    let delete = calls.iter().position(|c| c.contains("schtasks /Delete")).unwrap();
    assert!(query < delete);
    assert_eq!(std::fs::read(&task.backup).unwrap(), b"<Task/>");
    // A failed export deletes nothing.
    std::fs::remove_file(&task.backup).unwrap();
    *env.host.0.runner.fail_pattern.lock().unwrap() = Some("/Query".into());
    let before = env.host.0.runner.calls.lock().unwrap().len();
    assert!(services.disable(&task).is_err());
    let after = env.host.0.runner.calls.lock().unwrap().clone();
    assert!(after[before..].iter().all(|c| !c.contains("/Delete")), "{after:?}");
    *env.host.0.runner.fail_pattern.lock().unwrap() = None;
    services.disable(&task).unwrap();
    services.restore(&task).unwrap();
    assert!(env
        .host
        .0
        .runner
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.contains("/Create /TN YadoriLinkDaemon /XML")));
    assert!(!task.backup.exists());
}

#[test]
fn registrations_this_program_cannot_move_are_refused_by_the_service_layer_too() {
    let env = Env::new();
    for kind in [Kind::BundledLaunchAgent, Kind::SystemdSystemUnit] {
        let p = plan(kind, &env, "x", env.plist());
        assert!(env.host.0.services.disable(&p).is_err());
        assert!(env.host.0.services.restore(&p).is_err());
        assert!(env.host.0.services.is_active(&p).is_err());
    }
}
