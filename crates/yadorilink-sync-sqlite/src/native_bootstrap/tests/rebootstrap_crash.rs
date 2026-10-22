//! A rebootstrap stopped at each failpoint without warning: the workload and the
//! verifier for the crash experiments, with the checks that run off Windows.
//!
//! The workload builds the usual scenario, moves the replica database to a file
//! under the test root, and runs the rebootstrap with a hook that, at the chosen
//! failpoint, claims it to the collector and then waits to be killed. The
//! verifier reopens the database and the recovery area after the restart and
//! asks the product's own restart path what to do: before the barrier it must
//! abandon the half-written area and leave the old state exactly as it was; at
//! the barrier it must resume from a complete area.

use std::io;
use std::path::Path;

use crate::native_rebootstrap::{
    rebootstrap_status, recover_after_restart, BeginError, Crash, Failpoint, RestartOutcome,
};
use crate::native_rebootstrap_recovery::ensure_private_dir_durably;
use crate::windows_durability_harness::{Claim, Op, Report, Violation};

use super::history_lifecycle_red::{offline_base, put_op, rem, scenario};
use super::rebootstrap_preserve::{begin_with, items_root_of, private_tempdir, recovery_dirs_of};
use super::*;

/// The replica and sealer databases of a scenario. The remote-only scenario
/// (point names prefixed `ro:`) holds a head the target lacks, so it also passes
/// the item-writing failpoints.
fn databases(point: &str) -> (Connection, Connection) {
    if point.starts_with(REMOTE_ONLY) {
        let o = offline_base(true);
        (o.b, o.sealer)
    } else {
        let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
        (w.b, w.sealer)
    }
}

const REMOTE_ONLY: &str = "ro:";

/// Every failpoint the scenarios pass, in order, named as the workload takes them.
pub(super) fn reachable_points() -> Vec<String> {
    let mut names = Vec::new();
    for prefix in ["", REMOTE_ONLY] {
        let (b, sealer) = databases(prefix);
        let area = private_tempdir();
        begin_with(&b, built(&sealer), area.path(), &mut |point| {
            names.push(format!("{prefix}{point:?}"));
            Ok(())
        })
        .unwrap();
    }
    names
}

fn point_name(point: Failpoint) -> String {
    format!("{point:?}")
}

/// The failpoint's own name, without the scenario prefix.
fn bare(name: &str) -> &str {
    name.strip_prefix(REMOTE_ONLY).unwrap_or(name)
}

/// A durable file copy of `source`, opened.
fn persist_db(source: &Connection, path: &Path) -> io::Result<Connection> {
    source.execute("VACUUM INTO ?1", [path.to_str().unwrap()]).map_err(io::Error::other)?;
    std::fs::OpenOptions::new().write(true).open(path)?.sync_all()?;
    if let Some(parent) = path.parent() {
        yadorilink_fs_platform::durable_dir::durable_flush_directory(parent)?;
    }
    Connection::open(path).map_err(io::Error::other)
}

fn roots_hex(c: &Connection) -> String {
    let (namespace, authors) = roots_of(c);
    format!("{}{}", hex::encode(namespace), hex::encode(authors))
}

/// Runs the rebootstrap under `root` until `point`, claims it through `emit`,
/// calls `park` (which on the real run never returns) and then stops there as a
/// crash would.
pub(super) fn soak_run(
    root: &Path,
    point: &str,
    emit: &mut dyn FnMut(&Claim) -> io::Result<()>,
    park: &mut dyn FnMut(),
) -> Result<(), String> {
    crate::native_rebootstrap_recovery::create_dirs_durably(root).map_err(|e| e.to_string())?;
    let (b, sealer) = databases(point);
    let db = persist_db(&b, &root.join("state.db")).map_err(|e| e.to_string())?;
    let recovery = root.join("recovery");
    ensure_private_dir_durably(&recovery).map_err(|e| e.to_string())?;
    let old_roots = roots_hex(&db);
    let mut emit_failed = None;
    let outcome = begin_with(&db, built(&sealer), &recovery, &mut |reached| {
        if point_name(reached) != bare(point) {
            return Ok(());
        }
        let claim = Claim { seq: 1, op: Op::Failpoint, path: point.into(), arg: old_roots.clone() };
        if let Err(error) = emit(&claim) {
            emit_failed = Some(error.to_string());
        }
        park();
        Err(Crash)
    });
    match (outcome, emit_failed) {
        (_, Some(error)) => Err(error),
        (Err(BeginError::Crashed), None) => Ok(()),
        (other, None) => Err(format!("failpoint {point} was not reached: {other:?}")),
    }
}

/// Checks what the restart finds under `root` against the failpoint claim.
pub(super) fn verify_run(root: &Path, claims: &[Claim]) -> Report {
    let mut violations = Vec::new();
    let Some(claim) = claims.iter().rev().find(|c| c.op == Op::Failpoint) else {
        return Report { claims: claims.len(), violations };
    };
    let mut fail = |kind| {
        violations.push(Violation { seq: claim.seq, path: claim.path.clone(), kind });
    };
    let recovery = root.join("recovery");
    let at_barrier = bare(&claim.path) == point_name(Failpoint::AtPreserved);
    match Connection::open(root.join("state.db")) {
        Err(_) => fail("state_lost"),
        Ok(db) => match recover_after_restart(&db, &recovery, &group()) {
            Err(_) => fail("restart_failed"),
            Ok(RestartOutcome::Abandoned { .. }) if at_barrier => fail("barrier_lost"),
            Ok(RestartOutcome::Abandoned { .. }) => {
                if roots_hex(&db) != claim.arg {
                    fail("old_state_changed");
                }
                let items = items_root_of(&recovery);
                if recovery_dirs_of(&recovery).iter().any(|dir| !dir.starts_with(&items)) {
                    fail("area_leaked");
                }
                if rebootstrap_status(&db, &group()).ok().flatten().is_some() {
                    fail("journal_left");
                }
            }
            Ok(RestartOutcome::Preserved(preserved)) => {
                if !preserved.dir.join("manifest.json").is_file() {
                    fail("preserved_incomplete");
                }
            }
            Ok(RestartOutcome::Blocked(_)) => fail("preserved_incomplete"),
            Ok(RestartOutcome::Idle) => fail("journal_lost"),
            Ok(_) => fail("unexpected_state"),
        },
    }
    Report { claims: claims.len(), violations }
}

fn stop_at(root: &Path, point: &str) -> Vec<Claim> {
    let mut claims = Vec::new();
    soak_run(
        root,
        point,
        &mut |claim| {
            claims.push(claim.clone());
            Ok(())
        },
        &mut || {},
    )
    .unwrap();
    claims
}

#[test]
fn the_scenarios_pass_every_kind_of_failpoint_with_unique_names() {
    let names = reachable_points();
    let unique: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(unique.len(), names.len());
    for wanted in [
        "BeforeCapture",
        "AfterTargetDurable",
        "BeforeManifest",
        "AfterManifest",
        "AtPreserved",
        "AfterRecoveryItem(0)",
        "ro:AfterRemoteOnlyFiles(0)",
        "ro:AfterRemoteOnlyRow(0)",
    ] {
        assert!(names.iter().any(|n| n == wanted), "{wanted} missing from {names:?}");
    }
    println!("points: {names:?}");
}

#[test]
fn a_stop_at_every_failpoint_restarts_clean() {
    for point in reachable_points() {
        let root = private_tempdir();
        let claims = stop_at(root.path(), &point);
        let report = verify_run(root.path(), &claims);
        assert_eq!(report.violations, vec![], "{point}");
        assert_eq!(report.claims, 1);
    }
}

#[test]
fn a_barrier_that_did_not_hold_or_an_old_state_that_changed_is_detected() {
    let at = "AtPreserved".to_string();

    let root = private_tempdir();
    let claims = stop_at(root.path(), &at);
    let area = recovery_dirs_of(&root.path().join("recovery")).remove(0);
    std::fs::remove_file(area.join("manifest.json")).unwrap();
    let kinds: Vec<_> =
        verify_run(root.path(), &claims).violations.iter().map(|v| v.kind).collect();
    assert_eq!(
        kinds,
        vec!["preserved_incomplete"],
        "a Preserved journal over an area without a manifest"
    );

    let root = private_tempdir();
    let claims = stop_at(root.path(), &at);
    Connection::open(root.path().join("state.db"))
        .unwrap()
        .execute("DELETE FROM native_rebootstrap_journal", [])
        .unwrap();
    let kinds: Vec<_> =
        verify_run(root.path(), &claims).violations.iter().map(|v| v.kind).collect();
    assert_eq!(kinds, vec!["journal_lost"]);

    let root = private_tempdir();
    let mut claims = stop_at(root.path(), "BeforeManifest");
    claims[0].arg = "00".repeat(64);
    let kinds: Vec<_> =
        verify_run(root.path(), &claims).violations.iter().map(|v| v.kind).collect();
    assert_eq!(kinds, vec!["old_state_changed"]);
}

/// Windows entry points; driven from outside like the primitive workload.
#[cfg(windows)]
mod windows_entry {
    use std::io::Write;

    use super::*;
    use crate::windows_durability_harness::net::{env, fetch_claims, send_verdict, session};

    /// Runs the rebootstrap to `YADORILINK_CRASH_POINT`, claims it and waits to be killed.
    #[test]
    #[ignore = "driven by the maintainer Windows crash driver; waits at the failpoint until the machine is killed"]
    fn windows_rebootstrap_soak() {
        let mut s = session();
        let point = env("YADORILINK_CRASH_POINT");
        writeln!(s.stream, "hello {} {}", s.cycle, s.mode).unwrap();
        let cycle = s.cycle.clone();
        let mut stream = s.stream.try_clone().unwrap();
        soak_run(
            &s.root,
            &point,
            &mut |claim| writeln!(stream, "{}", claim.to_line(&cycle)),
            &mut || loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            },
        )
        .unwrap();
    }

    /// After the restart: asks the product's restart path and checks the outcome.
    #[test]
    #[ignore = "driven by the maintainer Windows crash driver after the machine restarted"]
    fn windows_rebootstrap_verify() {
        let mut s = session();
        let claims = fetch_claims(&mut s);
        let report = verify_run(&s.root, &claims);
        let verdict = report.to_json(&s.cycle, &s.mode);
        send_verdict(&mut s, &verdict);
        assert!(!claims.is_empty(), "no failpoint claim");
        assert!(report.violations.is_empty(), "{} violations", report.violations.len());
    }
}
