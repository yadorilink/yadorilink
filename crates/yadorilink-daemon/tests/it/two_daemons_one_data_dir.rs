//! Two real `yadorilink-daemon` processes aimed at the same data. Invariant: exactly one
//! writer. The locks themselves are unit-tested (`app.rs`, `resource_lock.rs`,
//! `yadorilink-root-authority` `sync_root_lock`); what only real processes show is that they
//! hold when the processes really race to start, when the holder is killed with SIGKILL, and
//! when the second daemon has a different state directory but the same sync root.
//!
//! The daemon is started unregistered (no device, no credential): it runs "with local link
//! management only", which is all the lock paths need, and needs no coordination plane.

#![cfg(unix)]

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UnixStream;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, StatusRequest, StatusResponse,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::daemon_lock::{probe, LockProbe};

const READY_TIMEOUT: Duration = Duration::from_secs(60);

/// One daemon's data: the state directory and the files it keeps beside it.
struct Data {
    /// Holds the short-named socket directory too: a unix socket path must fit in ~100 bytes.
    _root: tempfile::TempDir,
    config_dir: PathBuf,
    sync_db: PathBuf,
    blocks: PathBuf,
    control_socket: PathBuf,
    shell_socket: PathBuf,
    witness_dir: PathBuf,
    home: PathBuf,
}

impl Data {
    fn new() -> Self {
        let root = tempfile::Builder::new().prefix("yl").tempdir_in("/tmp").unwrap();
        let p = root.path().to_path_buf();
        let data = Self {
            config_dir: p.join("cfg"),
            sync_db: p.join("cfg/sync.sqlite3"),
            blocks: p.join("blocks"),
            control_socket: p.join("c.sock"),
            shell_socket: p.join("s.sock"),
            witness_dir: p.join("witness"),
            home: p.join("home"),
            _root: root,
        };
        std::fs::create_dir_all(&data.config_dir).unwrap();
        std::fs::create_dir_all(&data.home).unwrap();
        data
    }

    /// Starts one daemon process over this data, with nothing from the developer's environment.
    fn spawn(&self) -> Daemon {
        let mut child = Command::new(env!("CARGO_BIN_EXE_yadorilink-daemon"))
            .env_clear()
            .env("HOME", &self.home)
            .env("YADORILINK_CONFIG_DIR", &self.config_dir)
            .env("YADORILINK_SYNC_DB", &self.sync_db)
            .env("YADORILINK_BLOCK_STORE", &self.blocks)
            .env("YADORILINK_CONTROL_SOCKET", &self.control_socket)
            .env("YADORILINK_SHELL_IPC_SOCKET", &self.shell_socket)
            .env("YADORILINK_WITNESS_DIR", &self.witness_dir)
            .env("YADORILINK_CREDENTIAL_STORE", "file")
            .env("YADORILINK_SYNC_RELAYS", "none")
            .env("YADORILINK_HTTP_API_DISABLE", "1")
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawning the daemon binary");
        let output = Arc::new(Mutex::new(String::new()));
        for stream in [
            child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
            child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let output = output.clone();
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    output.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            });
        }
        Daemon { child, output }
    }

    /// The sync database as a second process sees it: every table readable, none corrupt.
    fn assert_database_intact(&self) {
        let conn = rusqlite::Connection::open_with_flags(
            &self.sync_db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("the sync database must open");
        let verdict: String =
            conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap();
        assert_eq!(verdict, "ok", "the sync database is corrupt");
    }

    async fn status(&self) -> StatusResponse {
        let mut stream = UnixStream::connect(&self.control_socket).await.unwrap();
        write_message(
            &mut stream,
            &DaemonControlRequest {
                payload: Some(ReqPayload::Status(StatusRequest {})),
                protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let response = read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap();
        let Some(RespPayload::Status(status)) = response.payload else {
            panic!("expected a status response");
        };
        status
    }
}

struct Daemon {
    child: Child,
    /// Everything the process printed, stdout and stderr together.
    output: Arc<Mutex<String>>,
}

impl Daemon {
    fn output(&self) -> String {
        // The reader threads may still be draining a process that just exited.
        std::thread::sleep(Duration::from_millis(100));
        self.output.lock().unwrap().clone()
    }

    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().unwrap()
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.exited() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon is still running after {timeout:?}:\n{}",
                self.output()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// SIGKILL: no shutdown path runs, so only the OS can release what the daemon held.
    fn kill9(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Waits until this daemon serves its control socket, failing if it exits first.
async fn wait_serving(daemon: &mut Daemon, data: &Data) {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Some(status) = daemon.exited() {
            panic!("the daemon exited ({status}) before serving:\n{}", daemon.output());
        }
        if UnixStream::connect(&data.control_socket).await.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never served its control socket:\n{}",
            daemon.output()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Seeds a link of `root` into the database of `data`, the way an earlier run left it, so the
/// daemon resumes watching the folder at startup.
fn seed_link(data: &Data, root: &Path, group: &str) {
    let coordinator =
        yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open(&data.sync_db).unwrap();
    coordinator.link_repository().add_link(&root.to_string_lossy(), group).unwrap();
}

/// Several processes started at once over one state directory: exactly one runs, the others
/// refuse and leave the winner's socket, lock and database alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_starts_over_one_state_directory_leave_exactly_one_daemon() {
    const STARTERS: usize = 6;
    for round in 0..3 {
        let data = Data::new();
        let mut daemons: Vec<Daemon> = (0..STARTERS).map(|_| data.spawn()).collect();

        // The losers exit on their own; the winner keeps running.
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let exited = daemons.iter_mut().filter_map(|d| d.exited()).count();
            if exited == STARTERS - 1 {
                break;
            }
            assert!(
                exited < STARTERS,
                "round {round}: every daemon exited:\n{}",
                daemons.iter().map(Daemon::output).collect::<Vec<_>>().join("\n---\n")
            );
            assert!(
                Instant::now() < deadline,
                "round {round}: {exited} of {STARTERS} exited; the rest are still starting"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let winner_index = daemons.iter_mut().position(|d| d.exited().is_none()).unwrap();
        for (i, daemon) in daemons.iter_mut().enumerate() {
            if i == winner_index {
                continue;
            }
            let status = daemon.exited().unwrap();
            let output = daemon.output();
            assert!(!status.success(), "round {round}: a losing daemon exited cleanly:\n{output}");
            assert!(
                output.contains("already running"),
                "round {round}: a losing daemon must say why it refused:\n{output}"
            );
        }

        // The winner owns the data and still serves it: the losers did not unlink its socket,
        // take its lock or touch its database.
        let winner = &mut daemons[winner_index];
        wait_serving(winner, &data).await;
        assert_eq!(probe(&data.config_dir), LockProbe::Held, "round {round}");
        data.status().await;
        assert!(winner.exited().is_none(), "round {round}: the winner died:\n{}", winner.output());
        data.assert_database_intact();

        // SIGKILL leaves no cleanup: the lock must come free by itself, and the data must be
        // usable by the next daemon.
        daemons[winner_index].kill9();
        assert_eq!(probe(&data.config_dir), LockProbe::Free, "round {round}");
        let mut successor = data.spawn();
        wait_serving(&mut successor, &data).await;
        assert_eq!(probe(&data.config_dir), LockProbe::Held, "round {round}");
        data.status().await;
        successor.kill9();
        data.assert_database_intact();
    }
}

/// A second daemon started while the first is alive is refused at once, and stays refused for as
/// long as the first lives. Once the first is killed, the next start succeeds: nothing stale
/// blocks it and nothing it left behind is corrupt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_daemon_is_refused_until_the_holder_is_killed() {
    let data = Data::new();
    let mut holder = data.spawn();
    wait_serving(&mut holder, &data).await;

    for attempt in 0..3 {
        let mut second = data.spawn();
        let status = second.wait_for_exit(READY_TIMEOUT);
        let output = second.output();
        assert!(!status.success(), "attempt {attempt}: the second daemon ran:\n{output}");
        assert!(output.contains("already running"), "attempt {attempt}:\n{output}");
        data.status().await;
        assert!(holder.exited().is_none(), "attempt {attempt}: the holder died");
    }

    holder.kill9();
    let mut next = data.spawn();
    wait_serving(&mut next, &data).await;
    data.status().await;
    next.kill9();
    data.assert_database_intact();
}

/// Different state directories, the same data underneath: one block store and one database path
/// given to two daemons (the override variables make this possible). The second must be refused
/// by the data-resource locks, since the state-directory lock cannot see it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_state_directory_over_the_same_database_and_store_is_refused() {
    let first = Data::new();
    let mut second = Data::new();
    // The second daemon's own state directory, the first's database and block store.
    second.sync_db = first.sync_db.clone();
    second.blocks = first.blocks.clone();

    let mut holder = first.spawn();
    wait_serving(&mut holder, &first).await;

    let mut refused = second.spawn();
    let status = refused.wait_for_exit(READY_TIMEOUT);
    let output = refused.output();
    assert!(!status.success(), "the second daemon ran over the same database:\n{output}");
    assert!(
        output.contains("already in use") || output.contains("already running"),
        "the refusal must name the held resource:\n{output}"
    );
    first.status().await;
    assert!(holder.exited().is_none());

    holder.kill9();
    let mut next = second.spawn();
    wait_serving(&mut next, &second).await;
    next.kill9();
    first.assert_database_intact();
}

/// Different state directories and databases, one sync root. Both daemons run, but only the
/// first may watch, index or write the folder; the second keeps its link out of service. When
/// the first is killed the folder is free again for a daemon that starts afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_daemon_never_takes_a_sync_root_the_first_one_holds() {
    let first = Data::new();
    let second = Data::new();
    let root = tempfile::Builder::new().prefix("yl-root").tempdir_in("/tmp").unwrap();
    let group = "two-daemons-group";
    seed_link(&first, root.path(), group);
    seed_link(&second, root.path(), group);

    let mut holder = first.spawn();
    wait_serving(&mut holder, &first).await;
    // The holder resumed the link: its root now carries the daemon's lock file.
    let lock_file =
        root.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    let deadline = Instant::now() + READY_TIMEOUT;
    while !lock_file.exists() {
        assert!(
            Instant::now() < deadline,
            "the first daemon never took the root:\n{}",
            holder.output()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let before = listing(root.path());

    let mut rival = second.spawn();
    wait_serving(&mut rival, &second).await;
    // The refusal is logged at link start, which happens during startup, before or just after
    // the socket serves.
    let deadline = Instant::now() + READY_TIMEOUT;
    while !rival.output().contains("already in use") {
        assert!(
            Instant::now() < deadline,
            "the second daemon never refused the held root:\n{}",
            rival.output()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(rival.exited().is_none(), "the rival should keep running, link out of service");

    // A file written now is the holder's to index; the rival must not write anything into the
    // folder (its own markers, temp files, materialized content).
    std::fs::write(root.path().join("user.txt"), b"mine").unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let after = listing(root.path());
    let mut expected = before.clone();
    expected.push("user.txt".to_string());
    expected.sort();
    assert_eq!(after, expected, "something other than the holder and the user wrote to the root");
    assert_eq!(std::fs::read(root.path().join("user.txt")).unwrap(), b"mine");

    // The holder is killed without any cleanup; the lock is the OS's to release.
    holder.kill9();
    rival.kill9();
    let mut successor = second.spawn();
    wait_serving(&mut successor, &second).await;
    // Give the link the time it needs to start; no refusal now.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !successor.output().contains("already in use"),
        "the root stayed locked after its holder was killed:\n{}",
        successor.output()
    );
    successor.kill9();
    first.assert_database_intact();
    second.assert_database_intact();
}

fn listing(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}
