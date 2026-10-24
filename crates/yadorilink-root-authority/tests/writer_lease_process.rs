//! Writer-lease behaviour across genuine OS processes: crash takeover and stale-writer
//! refusal. Time is injected, so no test waits for a real term to run out: the child holds a
//! long real-clock lease and the parent's fake clock jumps past it.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use yadorilink_root_authority::writer_lease::{
    read_state, FakeLeaseClock, LeaseClock, SystemLeaseClock, WriterLease,
};
use yadorilink_root_authority::RootAuthorityError;

const DIR_ENV: &str = "YADORILINK_TEST_WRITER_LEASE_DIR";
const HOUR: Duration = Duration::from_secs(3600);

/// Child mode: take a long real-clock lease, report readiness, then verify the fence each
/// time the parent sends a line and report the outcome.
fn run_child(dir: &Path) {
    let lease = WriterLease::acquire(dir, HOUR, Arc::new(SystemLeaseClock)).expect("child acquire");
    let mut out = std::io::stdout();
    writeln!(out, "ready {}", lease.generation()).unwrap();
    out.flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        line.unwrap();
        let verdict = match lease.verify() {
            Ok(()) => "ok".to_string(),
            Err(RootAuthorityError::StaleWriter(_)) => "stale".to_string(),
            Err(other) => format!("other {other}"),
        };
        writeln!(out, "{verdict}").unwrap();
        out.flush().unwrap();
    }
    // Leak: stdin closing must not release the lease, the parent kills us.
    std::mem::forget(lease);
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn spawn_child(test: &str, dir: &Path) -> (Child, BufReader<std::process::ChildStdout>) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture"])
        .env(DIR_ENV, dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawning the child writer");
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("child output");
        if line.starts_with("ready") {
            break;
        }
        assert!(!line.is_empty() && Instant::now() < deadline, "child never became ready");
    }
    (child, reader)
}

fn future_clock() -> Arc<FakeLeaseClock> {
    FakeLeaseClock::new(SystemLeaseClock.now_ms() + 2 * 3600 * 1000)
}

#[test]
fn a_writer_killed_without_releasing_is_taken_over_after_its_term() {
    if let Ok(dir) = std::env::var(DIR_ENV) {
        run_child(Path::new(&dir));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (mut child, _out) =
        spawn_child("a_writer_killed_without_releasing_is_taken_over_after_its_term", dir.path());

    // While the child is alive and its term runs, a second process fails closed.
    let err = WriterLease::acquire(dir.path(), HOUR, Arc::new(SystemLeaseClock)).unwrap_err();
    assert!(matches!(err, RootAuthorityError::WriterLeaseHeld(_)), "{err}");
    assert_eq!(read_state(dir.path()).unwrap().unwrap().generation, 1);

    child.kill().unwrap();
    child.wait().unwrap();

    // The record still names the dead child, so a real-clock open still waits out the term.
    assert!(WriterLease::acquire(dir.path(), HOUR, Arc::new(SystemLeaseClock)).is_err());
    // Past the term it is taken over with a higher fence.
    let taken = WriterLease::acquire(dir.path(), HOUR, future_clock()).unwrap();
    assert_eq!(taken.generation(), 2);
}

#[test]
fn a_writer_that_outlived_its_lease_is_refused_at_commit() {
    if let Ok(dir) = std::env::var(DIR_ENV) {
        run_child(Path::new(&dir));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (mut child, mut out) =
        spawn_child("a_writer_that_outlived_its_lease_is_refused_at_commit", dir.path());
    let mut stdin = child.stdin.take().unwrap();

    let ask = |stdin: &mut std::process::ChildStdin,
               out: &mut BufReader<std::process::ChildStdout>| {
        writeln!(stdin, "verify").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        line.trim().to_string()
    };

    assert_eq!(ask(&mut stdin, &mut out), "ok");
    let taker = WriterLease::acquire(dir.path(), HOUR, future_clock()).unwrap();
    assert_eq!(taker.generation(), 2);
    assert_eq!(ask(&mut stdin, &mut out), "stale");
    taker.verify().unwrap();

    child.kill().unwrap();
    child.wait().unwrap();
}
