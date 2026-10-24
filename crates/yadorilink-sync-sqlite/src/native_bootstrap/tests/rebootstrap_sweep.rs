//! A checkpoint install, crashed at every step inside its transaction, against a physical sweep
//! reading the live set from another connection at that very step.
//!
//! The sweep's roots are read from one snapshot (`live_set`); the install is one transaction. A
//! reader that overlaps the install must therefore see the whole old state or the whole new one,
//! never the cleared middle: an empty or half-installed set would let the sweep delete blocks a
//! head still names. The reader is a real thread with its own connection to the same file; the
//! install is parked at the step, the reader runs, and only then does the install go on or crash.
//! No sleeps: both sides hand over through channels.

use std::collections::HashSet;
use std::sync::mpsc;

use crate::native_rebootstrap::Crash;
use crate::native_rebootstrap_install::{InstallError, InstallPoint, InstallStep};

use super::history_lifecycle_red::{put_op, rem, scenario};
use super::rebootstrap_install::{install, install_with, FsRoot};
use super::rebootstrap_preserve::{begin_custom, no_hook, private_tempdir, Setup, Writer};
use super::*;

const TX_STEPS: [InstallStep; 5] = [
    InstallStep::NativeStateCleared,
    InstallStep::TargetInstalled,
    InstallStep::ProjectionArmed,
    InstallStep::Rotated,
    InstallStep::Recorded,
];

type Live = HashSet<String>;

fn live_of(c: &Connection) -> Live {
    crate::materialization_state::live_set(c, || {}).unwrap().into_iter().collect()
}

/// A sweep: reads the live set of the database file on request, one snapshot per request, from
/// its own connection, and answers on a channel.
struct Sweeper {
    ask: Option<mpsc::Sender<()>>,
    answer: mpsc::Receiver<Live>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sweeper {
    fn spawn(path: std::path::PathBuf) -> Self {
        let (ask, asked) = mpsc::channel::<()>();
        let (reply, answer) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let conn = Connection::open(&path).unwrap();
            while asked.recv().is_ok() {
                let snapshot = conn.unchecked_transaction().unwrap();
                reply.send(live_of(&snapshot)).unwrap();
            }
        });
        Self { ask: Some(ask), answer, thread: Some(thread) }
    }

    fn read_roots(&self) -> Live {
        self.ask.as_ref().unwrap().send(()).unwrap();
        self.answer.recv().unwrap()
    }
}

impl Drop for Sweeper {
    fn drop(&mut self) {
        self.ask.take();
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

struct FileScenario {
    db_dir: tempfile::TempDir,
    b: Connection,
    sealer: Connection,
    recovery_root: tempfile::TempDir,
    root: tempfile::TempDir,
}

fn file_backed_preserved_scenario() -> FileScenario {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let db_dir = tempfile::tempdir().unwrap();
    let path = db_dir.path().join("state.db");
    w.b.execute("VACUUM INTO ?1", [path.to_str().unwrap()]).unwrap();
    let b = Connection::open(&path).unwrap();
    b.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(())).unwrap();
    let recovery_root = private_tempdir();
    begin_custom(&b, built(&w.sealer), recovery_root.path(), &Setup::default(), &mut no_hook)
        .unwrap();
    FileScenario { db_dir, b, sealer: w.sealer, recovery_root, root: tempfile::tempdir().unwrap() }
}

impl FileScenario {
    fn path(&self) -> std::path::PathBuf {
        self.db_dir.path().join("state.db")
    }
}

/// Whatever step the install is parked at, a sweep reads the old live set whole, and after a
/// crash there the old live set is still all there is; the resumed install then yields the
/// target's, whole.
#[test]
fn a_sweep_overlapping_a_crashed_install_sees_the_old_live_set_and_then_the_new_one() {
    for step in TX_STEPS {
        let s = file_backed_preserved_scenario();
        let sweeper = Sweeper::spawn(s.path());
        let old = live_of(&s.b);
        let target = live_of(&s.sealer);
        assert!(
            !old.is_empty() && !target.is_empty() && old != target,
            "sanity: {old:?} {target:?}"
        );
        let fs_root = FsRoot::new(s.root.path());

        let seen = std::cell::RefCell::new(Vec::new());
        let crashed = install_with(&s.b, s.recovery_root.path(), &fs_root, &Writer, &mut |point| {
            if point == InstallPoint::InTransaction(step) {
                seen.borrow_mut().push(sweeper.read_roots());
                Err(Crash)
            } else {
                Ok(())
            }
        });
        assert!(matches!(crashed, Err(InstallError::Crashed)), "{step:?}: {crashed:?}");
        assert_eq!(
            seen.borrow().as_slice(),
            std::slice::from_ref(&old),
            "{step:?}: the sweep saw a torn set"
        );
        assert_eq!(sweeper.read_roots(), old, "{step:?}: a crash changed what the sweep roots");

        // The restart: the same file, a fresh connection, the install resumes and completes.
        drop(sweeper);
        let restarted = Connection::open(s.path()).unwrap();
        assert_eq!(live_of(&restarted), old, "{step:?}");
        let sweeper = Sweeper::spawn(s.path());
        install(&restarted, s.recovery_root.path(), &fs_root).unwrap();
        assert_eq!(
            sweeper.read_roots(),
            target,
            "{step:?}: the completed install roots the target"
        );
    }
}

/// Without a crash: every step before the commit shows the old set, the commit point and after
/// shows the new one, and no observation is anything else.
#[test]
fn a_sweep_during_a_completing_install_sees_only_the_old_or_the_new_live_set() {
    let s = file_backed_preserved_scenario();
    let sweeper = Sweeper::spawn(s.path());
    let old = live_of(&s.b);
    let target = live_of(&s.sealer);
    let fs_root = FsRoot::new(s.root.path());

    let seen = std::cell::RefCell::new(Vec::new());
    install_with(&s.b, s.recovery_root.path(), &fs_root, &Writer, &mut |point| {
        seen.borrow_mut().push((point, sweeper.read_roots()));
        Ok(())
    })
    .unwrap();

    let seen = seen.into_inner();
    assert!(seen.iter().any(|(p, _)| *p == InstallPoint::AfterCommit));
    for (point, live) in &seen {
        let expected = if *point == InstallPoint::AfterCommit { &target } else { &old };
        assert_eq!(live, expected, "{point:?}");
    }
}
