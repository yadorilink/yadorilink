//! Golden tests for what the `yadorilink` binary writes to stdout and stderr,
//! and the exit code it returns.
//!
//! Each case runs the real binary as a child process, with every environment
//! variable it reads pointed at a per-test temporary directory, and compares
//! the complete stdout, the complete stderr and the exit code against fixed
//! expectations. The library-level tests elsewhere check what a command does;
//! these check what a person at a terminal (or a script parsing its output)
//! actually sees, so a refactor that moves command logic around cannot change
//! a byte of it unnoticed.
//!
//! Cases that need a daemon run one in-process on a per-test control socket,
//! the same harness `tests/limits.rs` and `tests/link_library_surface.rs` use.
//! Cases that need the coordination plane only exercise the paths that fail
//! before any request is made (not signed in, invalid arguments), because no
//! in-repo coordination server exists to answer the rest.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

/// What one run of the binary produced.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn new(code: i32, stdout: &str, stderr: &str) -> Self {
        Run { code, stdout: stdout.to_owned(), stderr: stderr.to_owned() }
    }
}

/// An isolated environment for one run: its own config directory, credential
/// file, home directory and control socket path.
struct Env {
    dir: tempfile::TempDir,
    socket: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        Env { dir, socket }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_yadorilink"));
        command
            .args(args)
            .env_clear()
            .env("HOME", self.root())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            // Local times in the output are the same wherever this runs.
            .env("TZ", "UTC")
            .env("YADORILINK_CONFIG_DIR", self.root().join("config"))
            .env("YADORILINK_CONTROL_SOCKET", &self.socket)
            .env("YADORILINK_CREDENTIAL_STORE", "file")
            .env("YADORILINK_CREDENTIAL_FILE", self.root().join("credentials.json"))
            // A coordination address nothing listens on: every case here must
            // fail (or finish) before it would contact the coordination plane.
            .env("YADORILINK_COORDINATION_ADDR", "http://127.0.0.1:9");
        command
    }

    /// Runs the binary and replaces this environment's temporary directory
    /// (canonical and as given) with `<TMP>` in both streams.
    fn run_blocking(&self, args: &[&str]) -> Run {
        let output = self.command(args).output().expect("run the yadorilink binary");
        let canonical = self.root().canonicalize().unwrap();
        let normalize = |bytes: &[u8]| {
            String::from_utf8(bytes.to_vec())
                .expect("utf-8 output")
                .replace(&canonical.to_string_lossy().to_string(), "<TMP>")
                .replace(&self.root().to_string_lossy().to_string(), "<TMP>")
        };
        Run {
            code: output.status.code().expect("exit code"),
            stdout: normalize(&output.stdout),
            stderr: normalize(&output.stderr),
        }
    }

    async fn run(self: &Arc<Self>, args: &[&str]) -> Run {
        let env = Arc::clone(self);
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        tokio::task::spawn_blocking(move || {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            env.run_blocking(&args)
        })
        .await
        .unwrap()
    }
}

/// Starts an in-process daemon serving `env`'s control socket.
async fn start_daemon(env: &Env) -> Arc<DaemonState> {
    // The daemon's own config (governance limits) lives under the same
    // config directory the child process is pointed at.
    std::env::set_var("YADORILINK_CONFIG_DIR", env.root().join("config"));
    std::fs::create_dir_all(env.root().join("config")).unwrap();
    let store = Arc::new(SegmentBlockStore::new(env.root().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(env.root().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    state.set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);

    let serve_path = env.socket.clone();
    let serve_context =
        Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(state.clone()));
    tokio::spawn(async move {
        let _ =
            yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_context)
                .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&env.socket).await;
    state
}

/// Links `folder` to `group_id` directly over the control socket, bypassing
/// the CLI (and so the coordination plane, which the plain `Link` request
/// does not need).
async fn link_directly(env: &Env, folder: &Path, group_id: &str) {
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::{
        DaemonControlRequest, DaemonControlResponse, LinkRequest, PendingEnrollmentKind,
    };
    use yadorilink_ipc_proto::framing::{read_message, write_message};

    let mut stream = tokio::net::UnixStream::connect(&env.socket).await.unwrap();
    let request = DaemonControlRequest {
        payload: Some(ReqPayload::Link(LinkRequest {
            local_path: folder.canonicalize().unwrap().to_string_lossy().to_string(),
            group_id: group_id.to_owned(),
            on_demand: false,
            acknowledge_risks: true,
            pending_enrollment_operation_id: String::new(),
            pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
            pending_enrollment_device_id: String::new(),
        })),
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    write_message(&mut stream, &request).await.unwrap();
    let response = read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap();
    assert!(
        !matches!(
            response.payload,
            Some(yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload::Error(_))
        ),
        "linking the fixture folder failed: {response:?}"
    );
}

/// The in-process daemon reads `YADORILINK_CONFIG_DIR` from this process's
/// environment, so daemon-backed cases must not overlap.
static DAEMON_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const NOT_LOGGED_IN: &str = "error: not logged in — run `yadorilink login`\n";
const DAEMON_NOT_RUNNING: &str =
    "error: yadorilink daemon is not running — run `yadorilink daemon start`, or `systemctl start <service>` where a system service runs it\n";

// ---- no daemon, not signed in --------------------------------------------

#[test]
fn coordination_commands_report_not_logged_in_with_exit_code_10() {
    let env = Env::new();
    for args in [
        &["share", "members", "photos"][..],
        &["share", "list"],
        &["share", "joinable"],
        &["share", "invites"],
        &["share", "pending"],
        &["share", "approve", "photos", "device-1"],
        &["share", "deny", "photos", "device-1"],
        &["share", "revoke", "photos", "device-1", "--yes"],
        &["share", "invite", "photos"],
        &["share", "cancel-invite", "invite-1"],
        &["share", "change-role", "photos", "device-1", "--role", "viewer"],
        &["share", "set-storage-mode", "photos", "--mode", "eager"],
        &["share", "grant", "photos", "device-1"],
        &["share", "delete", "photos", "--yes"],
        &["device", "list"],
        &["device", "register", "--name", "laptop"],
        &["account", "delete", "status"],
        &["account", "delete", "request"],
        &["account", "delete", "cancel"],
        &["account", "delete", "confirm", "token"],
        &["account", "export"],
        &["logout", "--yes"],
        &["forget-local-credentials"],
    ] {
        assert_eq!(env.run_blocking(args), Run::new(10, "", NOT_LOGGED_IN), "yadorilink {args:?}");
    }
}

#[test]
fn daemon_commands_report_daemon_not_running_with_exit_code_4() {
    let env = Env::new();
    for args in [
        &["links"][..],
        &["unlink", "/nowhere"],
        &["daemon", "stop"],
        &["daemon", "pause"],
        &["daemon", "resume"],
        &["limits", "show"],
        &["limits", "set", "--up", "1", "--down", "2"],
        &["gc", "--dry-run"],
        &["inbox"],
        &["send", "/nowhere", "device-1"],
        &["receive", "transfer-1"],
        &["trash", "list"],
        &["conflicts", "list"],
        &["versions", "/nowhere"],
        &["evict", "/nowhere"],
        &["materialization-status", "/nowhere"],
        &["update", "status"],
        &["update", "check"],
        &["web", "status"],
        &["device", "remove", "device-1", "--yes"],
        &["share", "revoke", "edge-1", "--yes"],
    ] {
        assert_eq!(
            env.run_blocking(args),
            Run::new(4, "", DAEMON_NOT_RUNNING),
            "yadorilink {args:?}"
        );
    }
}

#[test]
fn a_role_owner_is_refused_before_any_request() {
    let env = Env::new();
    let run = env.run_blocking(&["share", "change-role", "photos", "device-1", "--role", "owner"]);
    assert_eq!(run.code, 1);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr.starts_with(
            "error: invalid --role \"owner\" (expected viewer or editor); owner is not available \
             via this command yet\n"
        ),
        "{run:?}"
    );
}

#[test]
fn an_invalid_storage_mode_is_refused_before_any_request() {
    let env = Env::new();
    for args in [
        &["share", "join", "photos", "--path", "/nowhere", "--storage-mode", "bogus"][..],
        &["share", "accept", "code", "--path", "/nowhere", "--storage-mode", "bogus"],
        &["share", "set-storage-mode", "photos", "--mode", "bogus"],
    ] {
        let run = env.run_blocking(args);
        assert_eq!(run.code, 1, "yadorilink {args:?}: {run:?}");
        assert_eq!(run.stdout, "", "yadorilink {args:?}");
        assert!(
            run.stderr.starts_with(
                "error: invalid --storage-mode \"bogus\" (expected eager or on-demand)\n"
            ),
            "yadorilink {args:?}: {run:?}"
        );
    }
}

#[test]
fn linking_a_missing_directory_names_it() {
    let env = Env::new();
    let run = env.run_blocking(&["link", "/definitely/not/here", "photos", "--dry-run"]);
    assert_eq!(run.code, 1, "{run:?}");
    assert_eq!(run.stdout, "");
    assert!(run.stderr.starts_with("error: no such directory: /definitely/not/here\n"), "{run:?}");
}

// ---- with a daemon --------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_backed_commands_print_their_results() {
    let _guard = DAEMON_MUTEX.lock().await;
    let env = Arc::new(Env::new());
    let _state = start_daemon(&env).await;

    assert_eq!(env.run(&["links"]).await, Run::new(0, "No linked folders.\n", ""));
    assert_eq!(env.run(&["daemon", "pause"]).await, Run::new(0, "Sync paused.\n", ""));
    assert_eq!(env.run(&["daemon", "resume"]).await, Run::new(0, "Sync resumed.\n", ""));
    assert_eq!(
        env.run(&["limits", "show"]).await,
        Run::new(0, "up=unlimited  down=unlimited\n", "")
    );
    assert_eq!(
        env.run(&["limits", "set", "--up", "1024", "--down", "0"]).await,
        Run::new(0, "Limits updated: up=1024 bytes/sec  down=unlimited\n", "")
    );
    assert_eq!(
        env.run(&["limits", "show"]).await,
        Run::new(0, "up=1024 bytes/sec  down=unlimited\n", "")
    );
    // Without coordination-plane connectivity the daemon refuses the inbox
    // listing; that refusal is an ordinary reportable command failure.
    assert_eq!(
        env.run(&["inbox"]).await,
        Run::new(
            1,
            "",
            "error: Track Send is not ready yet (this device has no coordination-plane \
             connectivity established)\nhint: run `yadorilink report error --last --preview` to \
             see what would be reported (nothing is sent automatically)\n"
        )
    );
    assert_eq!(env.run(&["trash", "list"]).await, Run::new(0, "Trash is empty.\n", ""));
    assert_eq!(env.run(&["conflicts", "list"]).await, Run::new(0, "No conflicted files.\n", ""));
    assert_eq!(
        env.run(&["gc", "--dry-run"]).await,
        Run::new(0, "Dry run: would delete 0 block(s), reclaiming 0 bytes\n", "")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn links_then_unlink_print_the_folder() {
    let _guard = DAEMON_MUTEX.lock().await;
    let env = Arc::new(Env::new());
    let _state = start_daemon(&env).await;
    let folder = env.root().join("photos");
    std::fs::create_dir_all(&folder).unwrap();
    link_directly(&env, &folder, "group-1").await;

    assert_eq!(
        env.run(&["links"]).await,
        Run::new(0, "<TMP>/photos  group=group-1  syncing\n", "")
    );
    assert_eq!(
        env.run(&["daemon", "pause"]).await,
        Run::new(0, "Sync paused.\n", ""),
        "pausing with one link"
    );
    assert_eq!(env.run(&["links"]).await, Run::new(0, "<TMP>/photos  group=group-1  paused\n", ""));

    let canonical = folder.canonicalize().unwrap().to_string_lossy().to_string();
    assert_eq!(
        env.run(&["unlink", &canonical, "--force"]).await,
        Run::new(
            0,
            "Unlinked <TMP>/photos\n",
            "warning: --force set -- if this device is the sole complete copy for this folder's \
             group with no other confirmed-ready complete copy, unlinking anyway may permanently lose \
             the only copy of that data\n"
        )
    );
    assert_eq!(env.run(&["links"]).await, Run::new(0, "No linked folders.\n", ""));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_dry_run_prints_the_preflight_report() {
    let _guard = DAEMON_MUTEX.lock().await;
    let env = Arc::new(Env::new());
    let _state = start_daemon(&env).await;
    let folder = env.root().join("notes");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"a").unwrap();

    let run = env.run(&["link", &folder.to_string_lossy(), "photos", "--dry-run"]).await;
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.stderr, "");
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines[0], "preflight: non-empty folder (1 entry)");
    // The free-space line carries this machine's real numbers; pin its shape.
    assert!(lines[1].starts_with("preflight: "), "{lines:?}");
    assert!(lines[1].contains(" free space on target volume ("), "{lines:?}");
    assert!(lines[1].contains(" bytes free, headroom "), "{lines:?}");
    assert!(
        lines.iter().any(|l| l.starts_with("warning: ") && l.contains("not empty")),
        "{lines:?}"
    );
    assert_eq!(*lines.last().unwrap(), "dry run: no link registered (risky conditions found)");
}

#[test]
fn destructive_commands_refuse_without_yes_when_stdin_is_not_a_terminal() {
    let env = Env::new();
    for args in [
        &["logout"][..],
        &["device", "remove", "device-1"],
        &["share", "delete", "photos"],
        &["share", "revoke", "photos", "device-1"],
        &["share", "revoke", "edge-1"],
    ] {
        let run = env.run_blocking(args);
        assert_eq!(run.code, 1, "yadorilink {args:?}: {run:?}");
        assert_eq!(run.stdout, "", "yadorilink {args:?}");
        assert!(run.stderr.contains("Re-run with --yes to confirm."), "{args:?}: {run:?}");
    }
}

#[test]
fn a_missing_backup_file_names_the_path_not_the_daemon() {
    let env = Env::new();
    let run = env.run_blocking(&["backup", "import", "missing.json"]);
    assert_eq!(run.code, 1, "{run:?}");
    assert!(run.stderr.contains("cannot read missing.json"), "{run:?}");
    assert!(!run.stderr.contains("daemon"), "{run:?}");
}

#[test]
fn help_lists_the_exit_codes() {
    let env = Env::new();
    let run = env.run_blocking(&["--help"]);
    assert!(run.stdout.contains("Exit codes:"), "{run:?}");
    assert!(run.stdout.contains("10  not logged in"), "{run:?}");
}

// ---- rewind ----------------------------------------------------------------

const REWIND_TARGET: &str = "1750000000000000000";

#[test]
fn rewind_without_a_daemon_reports_it_is_not_running() {
    let env = Env::new();
    let run = env.run_blocking(&["rewind", "somewhere", "--at", REWIND_TARGET]);
    assert_eq!(run, Run::new(4, "", DAEMON_NOT_RUNNING));
}

#[test]
fn rewind_flag_combinations_that_would_run_an_unseen_plan_are_usage_errors() {
    let env = Env::new();
    for args in [
        &["rewind", "f", "--at", "1h", "--execute", "--yes"][..],
        &["rewind", "f", "--at", "1h", "--yes", "--plan", "ab"],
        &["rewind", "f", "--at", "1h", "--plan", "ab"],
        &["rewind", "f"],
    ] {
        let run = env.run_blocking(args);
        assert_eq!(run.code, 2, "yadorilink {args:?}: {run:?}");
        assert_eq!(run.stdout, "", "yadorilink {args:?}");
    }
}

#[test]
fn help_lists_the_rewind_exit_codes() {
    let env = Env::new();
    let run = env.run_blocking(&["--help"]);
    for code in 11..=18 {
        assert!(run.stdout.contains(&format!("{code}  rewind:")), "{code}: {run:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewind_previews_a_linked_folder_and_refuses_to_run_without_confirmation() {
    let _guard = DAEMON_MUTEX.lock().await;
    let env = Arc::new(Env::new());
    let state = start_daemon(&env).await;
    allow_writes(&state, "group-1");
    let folder = env.root().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    link_directly(&env, &folder, "group-1").await;
    let place = folder.to_string_lossy().to_string();
    let shown = place
        .replace(&env.root().canonicalize().unwrap().to_string_lossy().to_string(), "<TMP>")
        .replace(&env.root().to_string_lossy().to_string(), "<TMP>");

    assert_eq!(
        env.run(&["rewind", "elsewhere", "--at", REWIND_TARGET]).await,
        Run::new(
            1,
            "",
            "error: elsewhere is not a linked folder\nhint: run `yadorilink report error --last \
             --preview` to see what would be reported (nothing is sent automatically)\n"
        )
    );
    assert_eq!(
        env.run(&["rewind", "status", &place]).await,
        Run::new(0, &format!("No rewind has been run for {shown}.\n"), "")
    );

    let preview = env.run(&["rewind", &place, "--at", REWIND_TARGET]).await;
    assert_eq!(preview.code, 0, "{preview:?}");
    let plan_id = plan_id_of(&preview.stdout);
    assert_eq!(
        preview.stdout,
        format!(
            "Rewind preview for {shown} (nothing has been changed)\n  \
             Target time: 2025-06-15 15:06:40 (--at {REWIND_TARGET})\n  \
             Plan id: {plan_id}\n  \
             0 to create, 0 to delete, 0 to replace, 0 unchanged, 0 unavailable\n  \
             No renames detected.\n"
        )
    );

    // Nobody to ask: the flow stops before anything is started.
    let refused = env.run(&["rewind", &place, "--at", REWIND_TARGET, "--execute"]).await;
    assert_eq!(
        refused,
        Run::new(
            18,
            &preview.stdout,
            "error: Not confirmed; nothing was changed. To run without a terminal, pass --yes \
             together with --plan <plan id>.\n"
        )
    );

    // A plan that is not the folder's current one is refused by the daemon.
    let stale = env
        .run(&[
            "rewind",
            &place,
            "--at",
            REWIND_TARGET,
            "--execute",
            "--yes",
            "--plan",
            &"00".repeat(32),
        ])
        .await;
    assert_eq!(stale.code, 11, "{stale:?}");
    assert_eq!(stale.stderr, "error: the folder changed since the rewind preview; preview again\n");
}

/// The real thing, end to end: an actual daemon watches a folder, the folder
/// is edited, and the command line previews and runs the rewind that undoes
/// the edits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewind_restores_a_watched_folder_through_the_command_line() {
    let _guard = DAEMON_MUTEX.lock().await;
    let env = Arc::new(Env::new());
    let state = start_daemon(&env).await;
    allow_writes(&state, "group-1");
    let folder = env.root().join("work").canonicalize_after_create();
    let place = folder.to_string_lossy().to_string();
    let shown = place
        .replace(&env.root().canonicalize().unwrap().to_string_lossy().to_string(), "<TMP>")
        .replace(&env.root().to_string_lossy().to_string(), "<TMP>");
    state.replica_coordinator.link_repository().add_link(&place, "group-1").unwrap();
    yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController::new(
        state.clone(),
    )
    .start(place.clone(), "group-1".to_string())
    .unwrap();

    std::fs::write(folder.join("report.txt"), "first draft").unwrap();
    std::fs::write(folder.join("notes.txt"), "keep me").unwrap();
    wait_for_rows(&state, "group-1", &[("report.txt", 1, false), ("notes.txt", 1, false)]).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let target = unix_nanos_now();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    std::fs::write(folder.join("report.txt"), "second draft").unwrap();
    std::fs::remove_file(folder.join("notes.txt")).unwrap();
    std::fs::write(folder.join("scratch.txt"), "new").unwrap();
    wait_for_rows(
        &state,
        "group-1",
        &[("report.txt", 2, false), ("notes.txt", 2, true), ("scratch.txt", 1, false)],
    )
    .await;

    let at = target.to_string();
    let preview = env.run(&["rewind", &place, "--at", &at]).await;
    assert_eq!(preview.code, 0, "{preview:?}");
    assert!(
        preview
            .stdout
            .contains("1 to create, 1 to delete, 1 to replace, 0 unchanged, 0 unavailable"),
        "{preview:?}"
    );
    let plan_id = plan_id_of(&preview.stdout);

    let executed =
        env.run(&["rewind", &place, "--at", &at, "--execute", "--yes", "--plan", &plan_id]).await;
    assert_eq!(executed.code, 0, "{executed:?}");
    assert_eq!(executed.stderr, "");
    assert!(
        executed.stdout.ends_with("Rewind finished: 2 files restored, 1 files removed.\n"),
        "{executed:?}"
    );

    // The run only authors the changes; the projection writes the disk after it reports
    // finished, so wait for the folder to show them.
    let restored = || {
        std::fs::read_to_string(folder.join("report.txt")).is_ok_and(|text| text == "first draft")
            && std::fs::read_to_string(folder.join("notes.txt")).is_ok_and(|text| text == "keep me")
            && !folder.join("scratch.txt").exists()
    };
    for _ in 0..600 {
        if restored() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(std::fs::read_to_string(folder.join("report.txt")).unwrap(), "first draft");
    assert_eq!(std::fs::read_to_string(folder.join("notes.txt")).unwrap(), "keep me");
    assert!(!folder.join("scratch.txt").exists());

    assert_eq!(
        env.run(&["rewind", "status", &place]).await.stdout,
        format!(
            "Latest rewind of {shown}\n  Target time: {} (--at {at})\n  Plan id: {plan_id}\n  \
             Rewind finished: 2 files restored, 1 files removed.\n",
            format_utc(target)
        )
    );

    // The plan that was run describes a folder that has since changed.
    let again =
        env.run(&["rewind", &place, "--at", &at, "--execute", "--yes", "--plan", &plan_id]).await;
    assert_eq!(again.code, 11, "{again:?}");
}

fn allow_writes(state: &Arc<DaemonState>, group: &str) {
    use yadorilink_daemon::change_policy::{GroupPolicyState, WriterRole};
    state.authority.install_test_group_policy(
        group,
        GroupPolicyState::with_members_for_tests(&[("device-under-test", WriterRole::Editor)]),
    );
}

fn plan_id_of(preview: &str) -> String {
    preview
        .lines()
        .find_map(|line| line.trim().strip_prefix("Plan id: "))
        .expect("the preview prints its plan id")
        .to_string()
}

fn unix_nanos_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i64
}

/// `YYYY-MM-DD HH:MM:SS` in UTC (the test runs the binary with `TZ=UTC`).
fn format_utc(unix_nanos: i64) -> String {
    let secs = unix_nanos.div_euclid(1_000_000_000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

trait CreateDir {
    fn canonicalize_after_create(self) -> PathBuf;
}

impl CreateDir for PathBuf {
    fn canonicalize_after_create(self) -> PathBuf {
        std::fs::create_dir_all(&self).unwrap();
        self.canonicalize().unwrap()
    }
}

/// Waits until the folder's index holds exactly these current rows:
/// (path, version_seq, deleted).
async fn wait_for_rows(state: &Arc<DaemonState>, group: &str, expected: &[(&str, i64, bool)]) {
    let rows = || -> Vec<(String, i64, bool)> {
        let database = state.replica_coordinator.database();
        let conn = database.pool_for_test().get().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT path, version_seq, deleted FROM files \
                 WHERE group_id = ?1 AND state = 'current' ORDER BY path",
            )
            .unwrap();
        stmt.query_map([group], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let mut want: Vec<(String, i64, bool)> =
        expected.iter().map(|(p, s, d)| ((*p).to_owned(), *s, *d)).collect();
    want.sort();
    for _ in 0..600 {
        if rows() == want {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the index never held {want:?}; it holds {:?}", rows());
}
