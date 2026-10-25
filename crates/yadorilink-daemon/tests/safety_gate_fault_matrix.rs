//! One table-driven fault-injection harness across the data-safety gates.
//!
//! Every row of `safety_gate_fault_matrix.table` is one injection at one named
//! failure point of one gate. A `case` row is executed here; a `delegate` row
//! names an existing exhaustive sweep that already injects at its points (the
//! guard checks the named test exists); an `exempt` row says why a gate or a
//! seam cannot be driven from here. `.github/checks/check-safety-gate-matrix.py`
//! fails when a section of `SAFETY_INVARIANTS.md`, a variant of a watched
//! failpoint or refusal enum, or a test-injection seam has no row, so a new
//! gate cannot land without a case.
//!
//! Every case is the same four steps, so a gate cannot pass by being quiet:
//!
//! 1. inject the fault and attempt the guarded operation: it must be REFUSED
//!    with the named typed refusal (an accepted attempt is a silent success);
//! 2. the data-safety invariant holds right after the refusal (nothing lost,
//!    nothing half written, the evidence that triggered the refusal untouched);
//! 3. the fault is cleared (the user's recovery step, or the same retry) and
//!    the attempt succeeds;
//! 4. the invariant still holds after the recovery.
//!
//! Nothing here sleeps, polls or repeats: each fault is a value, a failpoint or
//! a file mode set before the call.

use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use yadorilink_daemon::install_witness::{
    judge, FileWitnessStore, SideCopy, Verdict, WitnessStore,
};
use yadorilink_daemon::update::manifest::{
    self, check_appcast_item, check_pinned_install, select_applicable, Applicability, LocalContext,
    ManifestError, ReleaseEntry, SignedManifestEnvelope, TrustedKey, UpdateManifest,
};
use yadorilink_fs_platform::durable_dir::{
    arm_failpoint, disarm_failpoint, DiscardOutcome, DurableNamespace, NameLedger, NoLedger,
    NsError, NsFailpoint, Replace, RetainReason,
};
use yadorilink_fs_platform::generation::{self, Latest};
use yadorilink_fs_platform::volume_identity::{StableVolumeId, VolumeMatch};
use yadorilink_local_storage::disk_verification::check_disk_headroom;
use yadorilink_local_storage::free_space::VolumeFreeSpace;
#[cfg(unix)]
use yadorilink_local_storage::materialize_write::{
    verify_write_target_within_root, StructuralDirectoryLedger,
};
use yadorilink_local_storage::replacement_unconfirmed::{self, Record};
use yadorilink_local_storage::{
    hash_block_bytes, BlockStore, CommitPoint, FaultPlan, GroupCommitLimits, LocallyHashedBlock,
    SegmentBlockStore,
};
use yadorilink_sqlite_runtime::{check_replica_schema_generation, DatabaseError, SCHEMA_VERSION};
use yadorilink_sync_sqlite::author_incarnation::InstallWitness;

const TABLE: &str = include_str!("safety_gate_fault_matrix.table");

// ---- the four-step shape ------------------------------------------------------------

enum Answer {
    Refused(String),
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    AfterRefusal,
    AfterRetry,
}

struct Scenario {
    /// The typed refusal the faulted attempt must answer with (`a|b`: either).
    refusal: &'static str,
    faulted: Box<dyn FnMut() -> Answer>,
    intact: Box<dyn FnMut(Phase) -> Result<(), String>>,
    retry: Box<dyn FnMut() -> Answer>,
    /// Temp dirs and other state the closures borrow by path.
    keep: Vec<Box<dyn Any>>,
}

enum Built {
    Run(Scenario),
    /// The environment cannot make the fault (for example file modes are not
    /// enforced for root). Reported on stderr; the case is not a pass.
    // Only the Unix file-mode cases can find the environment unable to make their fault.
    #[cfg_attr(not(unix), allow(dead_code))]
    Skip(&'static str),
}

fn run(mut s: Scenario) -> Result<(), String> {
    match (s.faulted)() {
        Answer::Done => return Err("silent success: the faulted attempt was accepted".into()),
        Answer::Refused(got) if !s.refusal.split('|').any(|r| r == got) => {
            return Err(format!("wrong refusal: expected {}, got {got}", s.refusal))
        }
        Answer::Refused(_) => {}
    }
    (s.intact)(Phase::AfterRefusal)
        .map_err(|e| format!("data not intact after the refusal: {e}"))?;
    match (s.retry)() {
        Answer::Done => {}
        Answer::Refused(got) => {
            return Err(format!("the retry did not recover: refused with {got}"))
        }
    }
    (s.intact)(Phase::AfterRetry).map_err(|e| format!("data not intact after the retry: {e}"))?;
    drop(s.keep);
    Ok(())
}

fn name_of(value: &dyn Debug) -> String {
    format!("{value:?}").chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect()
}

fn refuse<T, E: Debug>(result: Result<T, E>) -> Answer {
    match result {
        Ok(_) => Answer::Done,
        Err(e) => Answer::Refused(name_of(&e)),
    }
}

fn ok_when(condition: bool, what: impl FnOnce() -> String) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(what())
    }
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn only_entry(dir: &Path) -> PathBuf {
    let names = names_in(dir);
    assert_eq!(names.len(), 1, "expected exactly one entry in {}: {names:?}", dir.display());
    dir.join(&names[0])
}

// ---- 2.9 restored or copied database: the installation witness ----------------------

#[derive(Clone, Copy)]
enum WitnessFault {
    SideUnreadable,
    SideOfAnotherInstall,
    SideAheadOfDatabase,
    DatabasePredatesWitness,
}

fn witness_case(fault: WitnessFault) -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("sync.sqlite3");
    let side_dir = dir.path().join("outside-the-backup-set");
    let store = FileWitnessStore::new(&side_dir, &db_path);
    let mine = InstallWitness { token: [1; 16], generation: 5 };
    let (database, side, refusal) = match fault {
        WitnessFault::SideUnreadable => (Some(mine), mine, "unverifiable"),
        WitnessFault::SideOfAnotherInstall => {
            (Some(mine), InstallWitness { token: [2; 16], generation: 5 }, "different_install")
        }
        WitnessFault::SideAheadOfDatabase => {
            (Some(mine), InstallWitness { token: [1; 16], generation: 9 }, "older_generation")
        }
        WitnessFault::DatabasePredatesWitness => (None, mine, "different_install"),
    };
    store.write(&side).unwrap();
    let side_file = only_entry(&side_dir);
    if matches!(fault, WitnessFault::SideUnreadable) {
        std::fs::write(&side_file, b"torn").unwrap();
    }
    let before = std::fs::read(&side_file).unwrap();
    let store = Rc::new(store);

    let (probe, again) = (store.clone(), store.clone());
    let faulted = move || match judge(database, probe.read().unwrap(), false, [9; 16]) {
        Verdict::Refuse(why) => Answer::Refused(why.category().to_string()),
        Verdict::Record(_) => Answer::Done,
    };
    // The recovery is the start over: the database holds no author of this
    // device any more, so the stale side copy is leftover and the witness is
    // recorded afresh, then the next open accepts it.
    let retry = move || {
        let Verdict::Record(fresh) = judge(database, again.read().unwrap(), true, [9; 16]) else {
            return Answer::Refused("start_over_refused".into());
        };
        again.write(&fresh).unwrap();
        match judge(Some(fresh), again.read().unwrap(), false, [8; 16]) {
            Verdict::Record(_) => Answer::Done,
            Verdict::Refuse(why) => Answer::Refused(why.category().to_string()),
        }
    };
    let check = store;
    let intact = move |phase: Phase| match phase {
        Phase::AfterRefusal => ok_when(std::fs::read(&side_file).unwrap() == before, || {
            "a refused open rewrote the witness kept outside the database".into()
        }),
        Phase::AfterRetry => ok_when(
            matches!(check.read().unwrap(), SideCopy::Present(w) if w.generation >= 1),
            || "the recovered witness was not recorded".into(),
        ),
    };
    Scenario {
        refusal,
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

// ---- 2.9 replacement confirmation record ---------------------------------------------

#[derive(Clone, Copy)]
enum ReplacementFault {
    RecordUnreadable,
    PossibleLossNotAcknowledged,
}

fn replacement_case(fault: ReplacementFault) -> Scenario {
    let dir = Rc::new(tempfile::tempdir().unwrap());
    let record = |acknowledged| Record {
        old_device_id: "old".into(),
        new_device_id: "new".into(),
        unconfirmed_group_ids: vec!["g".into()],
        acknowledged_possible_loss: acknowledged,
    };
    replacement_unconfirmed::write(dir.path(), &record(false)).unwrap();
    let file = only_entry(dir.path());
    if matches!(fault, ReplacementFault::RecordUnreadable) {
        std::fs::write(&file, b"{ not a record").unwrap();
    }
    let before = std::fs::read(&file).unwrap();
    let (a, b, c) = (dir.clone(), dir.clone(), dir.clone());
    let faulted = move || {
        if replacement_unconfirmed::acknowledgement_required(a.path()) {
            Answer::Refused("acknowledgement_required".into())
        } else {
            Answer::Done
        }
    };
    let retry = move || {
        // A readable record is acknowledged by the person; an unreadable one
        // is replaced by the start over writing it again.
        match fault {
            ReplacementFault::RecordUnreadable => {
                replacement_unconfirmed::write(b.path(), &record(true)).unwrap();
            }
            ReplacementFault::PossibleLossNotAcknowledged => {
                assert!(replacement_unconfirmed::acknowledge_possible_loss(b.path()).unwrap());
            }
        }
        if replacement_unconfirmed::acknowledgement_required(b.path()) {
            Answer::Refused("acknowledgement_required".into())
        } else {
            Answer::Done
        }
    };
    let intact = move |phase: Phase| match phase {
        Phase::AfterRefusal => ok_when(
            replacement_unconfirmed::pending(c.path()) && std::fs::read(&file).unwrap() == before,
            || "the waiting replacement record was dropped or rewritten by the refusal".into(),
        ),
        Phase::AfterRetry => ok_when(replacement_unconfirmed::pending(c.path()), || {
            "confirming the acknowledgement must not drop the record".into()
        }),
    };
    Scenario {
        refusal: "acknowledgement_required",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

// ---- 3 durable namespace: named failpoints --------------------------------------------

fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| format!("<unreadable: {e}>"))
}

fn ns_publish_case(point: NsFailpoint) -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("file");
    std::fs::write(&target, "old").unwrap();
    // The failpoints sit inside the operations, not in the volume probe.
    let ns = DurableNamespace::unchecked_for_tests();
    let (t1, t2, t3) = (target.clone(), target.clone(), target);
    let faulted = move || {
        arm_failpoint(point);
        let result = ns.create_file(&t1, Replace::Yes, &NoLedger, |f| f.write_all(b"new"));
        disarm_failpoint();
        refuse(result)
    };
    let retry =
        move || refuse(ns.create_file(&t2, Replace::Yes, &NoLedger, |f| f.write_all(b"new")));
    let intact = move |phase: Phase| {
        // Never a half-written or missing name: the old version until the
        // move happened, the whole new one after it.
        let want = match phase {
            Phase::AfterRetry => "new",
            Phase::AfterRefusal if point == NsFailpoint::AfterMove => "new",
            Phase::AfterRefusal => "old",
        };
        let got = read_text(&t3);
        ok_when(got == want, || format!("{point:?}: the target reads {got:?}, want {want:?}"))
    };
    Scenario {
        refusal: "Crashed",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

#[derive(Default)]
struct RecordingLedger(RefCell<Vec<PathBuf>>);

impl NameLedger for RecordingLedger {
    fn record(&self, path: &Path) -> std::io::Result<()> {
        self.0.borrow_mut().push(path.to_path_buf());
        Ok(())
    }
    fn release(&self, path: &Path) {
        self.0.borrow_mut().retain(|p| p != path);
    }
}

fn ns_discard_case() -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("file");
    std::fs::write(&target, "user data").unwrap();
    let ns = DurableNamespace::unchecked_for_tests();
    let ledger = Rc::new(RecordingLedger::default());
    let retained: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    let (l1, r1) = (ledger.clone(), retained.clone());
    let faulted = move || {
        let discarded = ns.discard(&target, l1.as_ref()).unwrap();
        arm_failpoint(NsFailpoint::AfterDiscardBeforeUnlink);
        let outcome = discarded.finish(&ns, l1.as_ref());
        disarm_failpoint();
        match outcome {
            DiscardOutcome::Retained { path, reason: RetainReason::RemovalFailed } => {
                *r1.borrow_mut() = Some(path);
                Answer::Refused("Retained".into())
            }
            _ => Answer::Done,
        }
    };
    let (l2, r2) = (ledger.clone(), retained.clone());
    let retry = move || {
        // What the next start's recovery does with the recorded name.
        let path = r2.borrow().clone().unwrap();
        match ns.remove_file(&path, l2.as_ref()) {
            Ok(DiscardOutcome::Removed) => {
                l2.release(&path);
                Answer::Done
            }
            other => Answer::Refused(name_of(&other)),
        }
    };
    let (l3, r3) = (ledger, retained);
    let intact = move |phase: Phase| {
        let path = r3.borrow().clone().unwrap();
        match phase {
            Phase::AfterRefusal => {
                ok_when(read_text(&path) == "user data" && l3.0.borrow().contains(&path), || {
                    "the committed removal lost the bytes or forgot the leftover's name".into()
                })
            }
            // Windows documents no durability for an unlink, so it keeps the record of the
            // name it just removed (the next recovery finds the name absent and drops it):
            // what must hold there is that no recorded name is still an object.
            Phase::AfterRetry => ok_when(
                !path.exists()
                    && l3.0.borrow().iter().all(|p| !p.exists())
                    // Windows keeps exactly the record of the name it just unlinked.
                    && l3.0.borrow().len() == usize::from(cfg!(windows)),
                || "the recovered removal left the object or its record".into(),
            ),
        }
    };
    Scenario {
        refusal: "Retained",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

// ---- 3 durable namespace: the volume probe verdict ------------------------------------

fn ns_probe_unknown_case() -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let volume = dir.path().join("volume-not-mounted-yet");
    let (v1, v2, v3) = (volume.clone(), volume.clone(), volume);
    let faulted = move || match DurableNamespace::open(&v1) {
        Err(NsError::Unavailable(reason, _)) => Answer::Refused(name_of(&reason)),
        other => Answer::Refused(format!("not_a_typed_refusal:{}", name_of(&other))),
    };
    let retry = move || {
        std::fs::create_dir(&v2).unwrap();
        // The probe ran and judged the volume: either answer is a verdict. A
        // memory-backed temp dir is judged Unsupported, which is also a
        // refusal that does not depend on a transient failure.
        match DurableNamespace::open(&v2) {
            Ok(_) => Answer::Done,
            Err(NsError::Unavailable(
                yadorilink_fs_platform::durable_dir::UnavailableReason::Unsupported,
                _,
            )) => Answer::Done,
            Err(other) => Answer::Refused(name_of(&other)),
        }
    };
    let intact = move |phase: Phase| match phase {
        // Probing a volume that is not there creates nothing in its place.
        Phase::AfterRefusal => ok_when(!v3.exists(), || "the failed probe created the path".into()),
        Phase::AfterRetry => ok_when(names_in(&v3).is_empty(), || {
            format!("the probe left residue behind: {:?}", names_in(&v3))
        }),
    };
    Scenario {
        refusal: "Unknown",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

// ---- AccessDenied: a refused namespace change keeps the data and leaves no residue ----

#[cfg(unix)]
struct RestoreMode(PathBuf);

#[cfg(unix)]
impl Drop for RestoreMode {
    fn drop(&mut self) {
        set_mode(&self.0, 0o755);
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn access_denied_case(remove: bool) -> Built {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    let file = parent.join("file");
    if remove {
        std::fs::write(&file, "keep me").unwrap();
    }
    set_mode(&parent, 0o555);
    let restore = RestoreMode(parent.clone());
    if std::fs::write(parent.join("probe"), b"").is_ok() {
        return Built::Skip("file modes are not enforced here (running as root)");
    }
    let ns = DurableNamespace::unchecked_for_tests();
    let (p1, f1, p2, f2, f3) = (parent.clone(), file.clone(), parent.clone(), file.clone(), file);
    let denied = |e: NsError| match e {
        NsError::Io(io) => Answer::Refused(format!("{:?}", io.kind())),
        other => Answer::Refused(name_of(&other)),
    };
    let faulted = move || {
        let _ = &p1;
        let result = if remove {
            ns.remove_file(&f1, &NoLedger).map(|_| ())
        } else {
            ns.create_file(&f1, Replace::No, &NoLedger, |f| f.write_all(b"new"))
        };
        result.map_or_else(denied, |()| Answer::Done)
    };
    let retry = move || {
        set_mode(&p2, 0o755);
        let result = if remove {
            ns.remove_file(&f2, &NoLedger).map(|_| ())
        } else {
            ns.create_file(&f2, Replace::No, &NoLedger, |f| f.write_all(b"new"))
        };
        refuse(result)
    };
    let parent_for_check = parent;
    let intact = move |phase: Phase| match (remove, phase) {
        (true, Phase::AfterRefusal) => ok_when(read_text(&f3) == "keep me", || {
            "a denied removal lost or changed the file".into()
        }),
        (true, Phase::AfterRetry) => ok_when(!f3.exists(), || "the removal never happened".into()),
        (false, Phase::AfterRefusal) => ok_when(names_in(&parent_for_check).is_empty(), || {
            format!("a denied publish left residue: {:?}", names_in(&parent_for_check))
        }),
        (false, Phase::AfterRetry) => ok_when(read_text(&f3) == "new", || {
            "the retried publish is not the whole new file".into()
        }),
    };
    Built::Run(Scenario {
        refusal: "PermissionDenied",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(restore), Box::new(dir)],
    })
}

// ---- 3 mount / volume identity ----------------------------------------------------------

fn volume_observe_case() -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("detached-disk");
    let (f1, f2) = (folder.clone(), folder);
    let faulted = move || match StableVolumeId::observe(&f1) {
        Ok(_) => Answer::Done,
        // A failed observation is an error to retry, never a weaker identity.
        Err(e) => Answer::Refused(format!("{:?}", e.kind())),
    };
    let retry = move || {
        std::fs::create_dir(&f2).unwrap();
        refuse(StableVolumeId::observe(&f2))
    };
    Scenario {
        refusal: "NotFound",
        faulted: Box::new(faulted),
        intact: Box::new(|_| Ok(())),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

fn volume_match_case(
    recorded: &'static str,
    observed: &'static str,
    want: VolumeMatch,
) -> Scenario {
    let faulted = move || match VolumeMatch::of(Some(recorded), observed) {
        VolumeMatch::Same => Answer::Done,
        other => Answer::Refused(name_of(&other)),
    };
    // Back on the recorded disk, or re-adopted by the user (nothing recorded).
    let retry = move || {
        let back = match want {
            VolumeMatch::Other => VolumeMatch::of(Some(recorded), recorded),
            _ => VolumeMatch::of(None, "uuid:readopted"),
        };
        if back == VolumeMatch::Same {
            Answer::Done
        } else {
            Answer::Refused(name_of(&back))
        }
    };
    let intact = move |_| {
        // An unknown identity is never the same volume as another one, and
        // with no mount to name it, never the same as itself.
        ok_when(
            VolumeMatch::of(Some("unknown:mount-1"), "unknown:mount-2") == VolumeMatch::Unconfirmed
                && VolumeMatch::of(Some("unknown"), "unknown") == VolumeMatch::Unconfirmed,
            || "an unknown volume matched another mount or itself".into(),
        )
    };
    Scenario {
        refusal: if want == VolumeMatch::Other { "Other" } else { "Unconfirmed" },
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: Vec::new(),
    }
}

// ---- disk pressure -------------------------------------------------------------------------

fn block(tag: &str, len: usize) -> LocallyHashedBlock {
    let mut payload = vec![b'.'; len];
    let bytes = tag.as_bytes();
    payload[..bytes.len().min(len)].copy_from_slice(&bytes[..bytes.len().min(len)]);
    LocallyHashedBlock::from_bytes(payload)
}

fn limits() -> GroupCommitLimits {
    GroupCommitLimits { segment_target_bytes: 4096, ..GroupCommitLimits::default() }
}

fn tree_snapshot(root: &Path) -> Vec<(PathBuf, u64)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, u64)>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push((path.clone(), std::fs::metadata(&path).map_or(0, |m| m.len())));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out.sort();
    out
}

/// The headroom a write must leave is larger than the volume: every write is refused.
const IMPOSSIBLE_HEADROOM: u64 = u64::MAX / 2;

fn disk_pressure_block_store_case() -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let store = Rc::new(
        SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), |_| true).unwrap(),
    );
    store.set_headroom_enforced(true);
    store.set_headroom_override_bytes(Some(IMPOSSIBLE_HEADROOM));
    let victim = block("incoming", 600);
    let before = tree_snapshot(dir.path());
    let (s1, s2, s3) = (store.clone(), store.clone(), store);
    let (v1, v2) = (victim.clone(), victim.clone());
    let root = dir.path().to_path_buf();
    let faulted = move || refuse(s1.put_durable_batch(std::slice::from_ref(&v1)));
    let retry = move || {
        s2.set_headroom_override_bytes(Some(1));
        refuse(s2.put_durable_batch(std::slice::from_ref(&v2)))
    };
    let intact = move |phase: Phase| match phase {
        Phase::AfterRefusal => {
            ok_when(!s3.exists(victim.hash()).unwrap() && tree_snapshot(&root) == before, || {
                "a write refused for disk pressure left bytes or files behind".into()
            })
        }
        Phase::AfterRetry => ok_when(s3.get(victim.hash()).unwrap() == victim.bytes(), || {
            "the write retried after space returned is not readable".into()
        }),
    };
    Scenario {
        refusal: "DiskPressure",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

fn disk_pressure_preflight_case() -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let target = root.join("incoming.bin");
    let (r1, t1, r2, t2, r3) = (root.clone(), target.clone(), root.clone(), target, root);
    let faulted = move || refuse(check_disk_headroom(&r1, &t1, 4096, Some(IMPOSSIBLE_HEADROOM)));
    let retry = move || refuse(check_disk_headroom(&r2, &t2, 4096, Some(1)));
    let intact = move |_| {
        ok_when(names_in(&r3).is_empty(), || {
            format!("the admission check created files: {:?}", names_in(&r3))
        })
    };
    Scenario {
        refusal: "DiskPressure",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

fn disk_pressure_boundary_case(hysteresis: bool) -> Scenario {
    let space = |available_bytes| VolumeFreeSpace {
        available_bytes,
        total_bytes: 100_000,
        headroom_bytes: 1_000,
    };
    let faulted = move || {
        if hysteresis {
            // Just above the admission line, below the resume margin: the
            // "waiting for disk space" state must not clear yet.
            if space(1_100).recovered() {
                Answer::Done
            } else {
                Answer::Refused("still_waiting".into())
            }
        } else if space(1_100).would_breach(100) {
            // available - n == headroom: the line itself is refused.
            Answer::Refused("would_breach".into())
        } else {
            Answer::Done
        }
    };
    let retry = move || {
        if hysteresis {
            if space(1_300).recovered() {
                Answer::Done
            } else {
                Answer::Refused("still_waiting".into())
            }
        } else if space(1_101).would_breach(100) {
            Answer::Refused("would_breach".into())
        } else {
            Answer::Done
        }
    };
    Scenario {
        refusal: if hysteresis { "still_waiting" } else { "would_breach" },
        faulted: Box::new(faulted),
        intact: Box::new(|_| Ok(())),
        retry: Box::new(retry),
        keep: Vec::new(),
    }
}

// ---- 2.1 / 2.3 deletion of local bytes needs a durable volume ----------------------------------

fn non_durable_volume_case() -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let durable = Arc::new(AtomicBool::new(false));
    let flag = durable.clone();
    let store = Rc::new(
        SegmentBlockStore::with_limits_and_verdict(dir.path(), limits(), move |_| {
            flag.load(Ordering::SeqCst)
        })
        .unwrap(),
    );
    let kept = block("cached", 600);
    store.put_durable_batch(std::slice::from_ref(&kept)).unwrap();
    let hash = kept.hash().to_string();
    let (s1, s2, s3) = (store.clone(), store.clone(), store);
    let (h1, h2, h3) = (hash.clone(), hash.clone(), hash);
    let faulted = move || refuse(s1.reclaim_cached_blocks(std::slice::from_ref(&h1)));
    let retry = move || {
        durable.store(true, Ordering::SeqCst);
        refuse(s2.reclaim_cached_blocks(std::slice::from_ref(&h2)))
    };
    let intact = move |phase: Phase| match phase {
        Phase::AfterRefusal => {
            ok_when(s3.exists(&h3).unwrap() && s3.get(&h3).unwrap() == kept.bytes(), || {
                "a deletion refused on a non-durable volume still lost the block".into()
            })
        }
        Phase::AfterRetry => {
            ok_when(!s3.exists(&h3).unwrap(), || "the permitted deletion did not happen".into())
        }
    };
    Scenario {
        refusal: "DeletionRefused",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

// ---- 3 block store: a crash at every commit boundary ------------------------------------------

fn block_commit_case(point: CommitPoint) -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let baseline: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("baseline-{i}"), 600)).collect();
    let victim: Vec<LocallyHashedBlock> =
        (0..8).map(|i| block(&format!("victim-{i}"), 600)).collect();
    let open = {
        let path = dir.path().to_path_buf();
        move || SegmentBlockStore::with_limits_and_verdict(&path, limits(), |_| true).unwrap()
    };
    let store = Rc::new(RefCell::new(Some(open())));
    store.borrow().as_ref().unwrap().put_durable_batch(&baseline).unwrap();
    if matches!(point, CommitPoint::AfterSegmentStaged | CommitPoint::AfterSegmentPublished) {
        store.borrow().as_ref().unwrap().seal_active_segment().unwrap();
    }
    let (st1, st2, st3) = (store.clone(), store.clone(), store);
    let victim_for_fault = victim.clone();
    let faulted = move || {
        let guard = st1.borrow();
        let live = guard.as_ref().unwrap();
        live.arm_commit_fault_for_tests(FaultPlan::crash_at(point));
        let outcome = live.put_durable_batch(&victim_for_fault);
        // A dead process serves nothing further.
        assert!(live.is_halted_for_tests(), "{point:?}: the crash did not halt the store");
        refuse(outcome)
    };
    let retry = move || {
        let guard = st2.borrow();
        refuse(guard.as_ref().unwrap().put(b"written after recovery"))
    };
    let reopen = open.clone();
    let intact = move |phase: Phase| {
        if phase == Phase::AfterRefusal {
            // Restart: drop without any graceful shutdown, then recover.
            drop(st3.borrow_mut().take());
            *st3.borrow_mut() = Some(reopen());
        }
        let guard = st3.borrow();
        let live = guard.as_ref().unwrap();
        for committed in &baseline {
            ok_when(live.get(committed.hash()).ok().as_deref() == Some(committed.bytes()), || {
                format!("{point:?}: a block committed before the crash was lost")
            })?;
        }
        if phase == Phase::AfterRefusal {
            // All or nothing: only past the index commit is the group there.
            let want = matches!(point, CommitPoint::AfterIndexCommitBeforeReceipt);
            for interrupted in &victim {
                ok_when(live.exists(interrupted.hash()).unwrap() == want, || {
                    format!("{point:?}: the interrupted group is not all-or-nothing")
                })?;
            }
        }
        let report = live.verify_store(true).map_err(|e| e.to_string())?;
        ok_when(
            report.unbacked_mappings.is_empty()
                && report.corrupt_records.is_empty()
                && report.segments_with_incomplete_tail.is_empty(),
            || format!("{point:?}: the index names a block that is not durable"),
        )?;
        for hash in live.list_by_prefix("").unwrap() {
            let bytes = live.get(&hash).map_err(|e| format!("indexed block unreadable: {e}"))?;
            ok_when(hash_block_bytes(&bytes) == hash, || "an indexed block hashes wrong".into())?;
        }
        Ok(())
    };
    Scenario {
        refusal: "Io|Index",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

// ---- 2.6 a peer cannot make this device write outside the synced folder ---------------------------

#[cfg(unix)]
struct NoDirectoryLedger;

#[cfg(unix)]
impl StructuralDirectoryLedger for NoDirectoryLedger {
    fn record_intent(&self, _: &str) -> Result<(), yadorilink_local_storage::StorageError> {
        Ok(())
    }
    fn complete(
        &self,
        _: &str,
        _: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        Ok(())
    }
    fn abandon(&self, _: &str) -> Result<(), yadorilink_local_storage::StorageError> {
        Ok(())
    }
    fn interrupted(&self, _: &str) -> Result<(), yadorilink_local_storage::StorageError> {
        Ok(())
    }
}

#[cfg(unix)]
fn path_escape_case() -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("sync-root");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("planted")).unwrap();
    let (r1, r2, o, r3) = (root.clone(), root.clone(), outside.clone(), root);
    let faulted = move || {
        let target = r1.join("planted").join("deep").join("file");
        refuse(verify_write_target_within_root(&target, &r1, &NoDirectoryLedger))
    };
    let retry = move || {
        // The planted link is removed; a real directory is written through.
        std::fs::remove_file(r2.join("planted")).unwrap();
        let target = r2.join("planted").join("deep").join("file");
        refuse(verify_write_target_within_root(&target, &r2, &NoDirectoryLedger))
    };
    let intact = move |phase: Phase| match phase {
        Phase::AfterRefusal => ok_when(names_in(&o).is_empty(), || {
            format!("a refused write created entries outside the root: {:?}", names_in(&o))
        }),
        Phase::AfterRetry => {
            ok_when(r3.join("planted/deep").is_dir() && names_in(&o).is_empty(), || {
                "the retried write did not stay inside the root".into()
            })
        }
    };
    Scenario {
        refusal: "PathEscapesRoot",
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

// ---- 2.10 database generation (schema version) -------------------------------------------------

#[derive(Clone, Copy)]
enum SchemaFault {
    NewerDatabase,
    OlderDatabase,
    UnstampedWithTables,
}

fn schema_case(fault: SchemaFault) -> Scenario {
    let conn = Rc::new(rusqlite::Connection::open_in_memory().unwrap());
    let version = |c: &rusqlite::Connection| -> i32 {
        c.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap()
    };
    match fault {
        SchemaFault::NewerDatabase => {
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();
        }
        SchemaFault::OlderDatabase => {
            conn.pragma_update(None, "user_version", SCHEMA_VERSION - 1).unwrap();
        }
        SchemaFault::UnstampedWithTables => {
            conn.execute_batch("CREATE TABLE leftovers (x INTEGER);").unwrap();
        }
    }
    let stamped_before = version(&conn);
    let (c1, c2, c3) = (conn.clone(), conn.clone(), conn);
    let faulted = move || match check_replica_schema_generation(&c1) {
        Ok(()) => Answer::Done,
        Err(DatabaseError::UnsupportedSchemaDowngrade { .. }) => {
            Answer::Refused("UnsupportedSchemaDowngrade".into())
        }
        Err(DatabaseError::CorruptSchema(_)) => Answer::Refused("CorruptSchema".into()),
        Err(other) => Answer::Refused(name_of(&other)),
    };
    let retry = move || {
        // The matching build, or a fresh database after delete and re-import.
        match fault {
            SchemaFault::NewerDatabase | SchemaFault::OlderDatabase => {
                c2.pragma_update(None, "user_version", SCHEMA_VERSION).unwrap();
            }
            SchemaFault::UnstampedWithTables => {
                c2.execute_batch("DROP TABLE leftovers;").unwrap();
            }
        }
        refuse(check_replica_schema_generation(&c2))
    };
    let intact = move |phase: Phase| match phase {
        // A refused open never stamps, migrates or adopts the database.
        Phase::AfterRefusal => ok_when(version(&c3) == stamped_before, || {
            "a refused open changed the schema version stamp".into()
        }),
        Phase::AfterRetry => Ok(()),
    };
    Scenario {
        refusal: match fault {
            SchemaFault::NewerDatabase => "UnsupportedSchemaDowngrade",
            SchemaFault::OlderDatabase | SchemaFault::UnstampedWithTables => "CorruptSchema",
        },
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: Vec::new(),
    }
}

// ---- 2.10 update manifest: verification, rollout, kill switch, withdrawal --------------------------

fn entry(version: &str) -> ReleaseEntry {
    ReleaseEntry {
        channel: "beta".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        install_source: "standalone".into(),
        version: version.into(),
        minimum_supported_version: "0.1.0".into(),
        rollout_percentage: 100,
        kill_switch: false,
        mandatory: false,
        artifact_url: "https://updates.yadorilink.example/beta/a.tar".into(),
        artifact_sha256: "0".repeat(64),
        artifact_size: 1024,
        artifact_publisher_identity: String::new(),
        release_notes_url: "https://updates.yadorilink.example/beta/notes.html".into(),
        state_schema_version: None,
        state_schema_min_readable: None,
        sparkle_build: None,
    }
}

fn manifest_of(entry: ReleaseEntry, withdrawn: &[&str]) -> UpdateManifest {
    UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-04T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        withdrawn_versions: withdrawn.iter().map(|v| (*v).to_string()).collect(),
        releases: vec![entry],
    }
}

fn context(bucket: u8) -> LocalContext {
    LocalContext {
        current_version: semver::Version::parse("0.1.5").unwrap(),
        channel: "beta".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        install_source: "standalone".into(),
        rollout_bucket: bucket,
        state_schema_version: 10,
    }
}

#[derive(Clone, Copy)]
enum Rollout {
    InvalidVersion,
    Withdrawn,
    KillSwitched,
    BelowMinimum,
    NotOffered,
    NotServed,
    HeldBack,
}

/// A manifest that must refuse, and the manifest or context of the next
/// publication that allows it.
fn rollout_case(fault: Rollout) -> Scenario {
    let served = "0.2.0";
    let appcast = move |m: &UpdateManifest, ctx: &LocalContext, item: &str| {
        refuse(check_appcast_item(m, ctx, item))
    };
    let (bad, bad_ctx, item, good, good_ctx, refusal): (_, _, &str, _, _, &'static str) =
        match fault {
            Rollout::InvalidVersion => (
                manifest_of(entry(served), &[]),
                context(0),
                "not-a-version",
                manifest_of(entry(served), &[]),
                context(0),
                "InvalidVersion",
            ),
            Rollout::Withdrawn => (
                manifest_of(entry(served), &[served]),
                context(0),
                served,
                manifest_of(entry(served), &[]),
                context(0),
                "Withdrawn",
            ),
            Rollout::KillSwitched => (
                manifest_of(ReleaseEntry { kill_switch: true, ..entry(served) }, &[]),
                context(0),
                served,
                manifest_of(entry(served), &[]),
                context(0),
                "KillSwitched",
            ),
            Rollout::BelowMinimum => (
                manifest_of(entry(served), &[]),
                context(0),
                "0.0.9",
                manifest_of(entry(served), &[]),
                context(0),
                "BelowMinimum",
            ),
            Rollout::NotOffered => (
                manifest_of(ReleaseEntry { channel: "stable".into(), ..entry(served) }, &[]),
                context(0),
                served,
                manifest_of(entry(served), &[]),
                context(0),
                "NotOffered",
            ),
            Rollout::NotServed => (
                manifest_of(entry("0.3.0"), &[]),
                context(0),
                served,
                manifest_of(entry(served), &[]),
                context(0),
                "NotServed",
            ),
            Rollout::HeldBack => (
                manifest_of(ReleaseEntry { rollout_percentage: 10, ..entry(served) }, &[]),
                context(50),
                served,
                manifest_of(ReleaseEntry { rollout_percentage: 60, ..entry(served) }, &[]),
                context(50),
                "HeldBack",
            ),
        };
    let bad_for_intact = bad.clone();
    let faulted = move || match fault {
        Rollout::BelowMinimum => refuse(check_pinned_install(
            &manifest_of(
                ReleaseEntry { minimum_supported_version: "0.1.0".into(), ..entry(served) },
                &[],
            ),
            &context(0),
            item,
        )),
        _ => appcast(&bad, &bad_ctx, item),
    };
    let retry = move || match fault {
        Rollout::BelowMinimum => refuse(check_pinned_install(&good, &good_ctx, served)),
        _ => appcast(&good, &good_ctx, served),
    };
    let intact = move |_| {
        // A refused update changes nothing about the running version: the
        // selector never offers anything that is not strictly newer.
        let none = select_applicable(&manifest_of(entry("0.1.5"), &[]), &context(0));
        let older = select_applicable(&manifest_of(entry("0.1.4"), &[]), &context(0));
        let _ = &bad_for_intact;
        ok_when(none == Applicability::UpToDate && older == Applicability::UpToDate, || {
            "an equal or older version was offered as an update".into()
        })
    };
    Scenario {
        refusal,
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: Vec::new(),
    }
}

struct SignedFixture {
    key: ed25519_dalek::SigningKey,
    trusted: Vec<TrustedKey>,
}

impl SignedFixture {
    fn new() -> Self {
        use ed25519_dalek::SigningKey;
        let mut seed = [0u8; 32];
        rand::fill(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        let trusted = vec![TrustedKey {
            key_id: "matrix-throwaway-key",
            public_key_hex: Box::leak(hex::encode(key.verifying_key().to_bytes()).into_boxed_str()),
        }];
        Self { key, trusted }
    }

    fn sign(&self, manifest: &UpdateManifest) -> SignedManifestEnvelope {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let manifest_json = serde_json::to_string_pretty(manifest).unwrap();
        let signature = self.key.sign(manifest_json.as_bytes());
        SignedManifestEnvelope {
            key_id: "matrix-throwaway-key".into(),
            manifest_json,
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
            trust_chain: Vec::new(),
        }
    }

    fn verify(&self, envelope: &SignedManifestEnvelope) -> Result<UpdateManifest, ManifestError> {
        manifest::verify_and_parse_with_keys(
            &serde_json::to_string(envelope).unwrap(),
            &self.trusted,
        )
    }
}

#[derive(Clone, Copy)]
enum ManifestFault {
    TamperedBody,
    UnknownKey,
    WrongSchema,
}

fn manifest_verification_case(fault: ManifestFault) -> Scenario {
    let fixture = Rc::new(SignedFixture::new());
    let good = fixture.sign(&manifest_of(entry("0.2.0"), &[]));
    let bad = match fault {
        ManifestFault::TamperedBody => SignedManifestEnvelope {
            manifest_json: good.manifest_json.replace("0.2.0", "9.9.9"),
            ..good.clone()
        },
        ManifestFault::UnknownKey => {
            SignedManifestEnvelope { key_id: "some-other-id".into(), ..good.clone() }
        }
        ManifestFault::WrongSchema => fixture.sign(&UpdateManifest {
            schema_version: manifest::MANIFEST_SCHEMA_VERSION - 1,
            ..manifest_of(entry("0.2.0"), &[])
        }),
    };
    let (f1, f2) = (fixture.clone(), fixture);
    let faulted = move || refuse(f1.verify(&bad));
    let retry = move || refuse(f2.verify(&good));
    Scenario {
        refusal: match fault {
            ManifestFault::TamperedBody => "SignatureVerificationFailed",
            ManifestFault::UnknownKey => "UnknownKey",
            ManifestFault::WrongSchema => "UnsupportedSchemaVersion",
        },
        faulted: Box::new(faulted),
        intact: Box::new(|_| Ok(())),
        retry: Box::new(retry),
        keep: Vec::new(),
    }
}

// ---- generation files: a record is never read as a first run ----------------------------------------

#[derive(Clone, Copy)]
enum GenerationFault {
    TornNewest,
    UnreadableNewest,
    ResurrectedAfterRetirement,
}

fn generation_case(fault: GenerationFault) -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("record");
    let sealed = |body: &str| generation::seal(&format!("{body}\n"));
    let decode = |text: &str| generation::unseal(text).map(str::to_owned);
    generation::publish_next(&base, &sealed("first")).unwrap();
    generation::publish_next(&base, &sealed("second")).unwrap();
    let newest = dir.path().join("record.2");
    let older = dir.path().join("record.1");
    let older_bytes = std::fs::read(&older).unwrap();
    let mut resurrect_bytes = None;
    match fault {
        GenerationFault::TornNewest => {
            let bytes = std::fs::read(&newest).unwrap();
            std::fs::write(&newest, &bytes[..bytes.len() / 2]).unwrap();
        }
        GenerationFault::UnreadableNewest => {
            std::fs::remove_file(&newest).unwrap();
            std::fs::create_dir(&newest).unwrap();
        }
        GenerationFault::ResurrectedAfterRetirement => {
            resurrect_bytes = Some(older_bytes.clone());
            generation::remove_all(&base).unwrap();
        }
    }
    let (b1, b2, b3) = (base.clone(), base.clone(), base);
    let faulted = move || {
        if let Some(bytes) = &resurrect_bytes {
            // A lost unlink or an old generation coming back after a crash.
            std::fs::write(&older, bytes).unwrap();
        }
        match generation::read_latest(&b1, decode) {
            Latest::Loaded { skipped_newer: false, .. } => Answer::Done,
            Latest::Loaded { skipped_newer: true, .. } => Answer::Refused("skipped_newer".into()),
            Latest::Invalid(_) => Answer::Refused("Invalid".into()),
            Latest::Missing => Answer::Refused("Missing".into()),
        }
    };
    let retry = move || {
        generation::publish_next(&b2, &sealed("third")).unwrap();
        match generation::read_latest(&b2, decode) {
            Latest::Loaded { value, skipped_newer: false, .. } if value.contains("third") => {
                Answer::Done
            }
            other => Answer::Refused(format!("{other:?}")),
        }
    };
    let older_for_check = dir.path().join("record.1");
    let intact = move |phase: Phase| match (fault, phase) {
        (GenerationFault::ResurrectedAfterRetirement, _) => {
            // The retirement stays in force until a new record is published.
            let latest = generation::read_latest(&b3, |t| generation::unseal(t).map(str::to_owned));
            ok_when(matches!(latest, Latest::Missing) == (phase == Phase::AfterRefusal), || {
                format!("retirement state wrong in {phase:?}: {latest:?}")
            })
        }
        (_, Phase::AfterRefusal) => ok_when(
            std::fs::read(&older_for_check).ok().as_deref() == Some(older_bytes.as_slice()),
            || "the older complete generation was lost".into(),
        ),
        (_, Phase::AfterRetry) => Ok(()),
    };
    Scenario {
        refusal: match fault {
            GenerationFault::TornNewest => "skipped_newer",
            GenerationFault::UnreadableNewest => "Invalid",
            GenerationFault::ResurrectedAfterRetirement => "Missing",
        },
        faulted: Box::new(faulted),
        intact: Box::new(intact),
        retry: Box::new(retry),
        keep: vec![Box::new(dir)],
    }
}

// ---- the table ---------------------------------------------------------------------------------------

type Builder = Box<dyn Fn() -> Built>;

fn run_scenario(build: impl Fn() -> Scenario + 'static) -> Builder {
    Box::new(move || Built::Run(build()))
}

fn cases() -> Vec<(String, Builder)> {
    let mut cases: Vec<(String, Builder)> = Vec::new();
    let mut add = |id: &str, builder: Builder| cases.push((id.to_string(), builder));

    add("witness.side_unreadable", run_scenario(|| witness_case(WitnessFault::SideUnreadable)));
    add("witness.other_install", run_scenario(|| witness_case(WitnessFault::SideOfAnotherInstall)));
    add(
        "witness.older_generation",
        run_scenario(|| witness_case(WitnessFault::SideAheadOfDatabase)),
    );
    add(
        "witness.database_predates_witness",
        run_scenario(|| witness_case(WitnessFault::DatabasePredatesWitness)),
    );
    add(
        "replacement.record_unreadable",
        run_scenario(|| replacement_case(ReplacementFault::RecordUnreadable)),
    );
    add(
        "replacement.possible_loss_not_acknowledged",
        run_scenario(|| replacement_case(ReplacementFault::PossibleLossNotAcknowledged)),
    );

    for (name, point) in [
        ("AfterStage", NsFailpoint::AfterStage),
        ("BeforeMove", NsFailpoint::BeforeMove),
        ("AfterMove", NsFailpoint::AfterMove),
    ] {
        add(&format!("ns_failpoint.{name}"), run_scenario(move || ns_publish_case(point)));
    }
    add("ns_failpoint.AfterDiscardBeforeUnlink", run_scenario(ns_discard_case));
    add("ns_probe.unknown_volume", run_scenario(ns_probe_unknown_case));

    #[cfg(unix)]
    {
        add("access_denied.publish", Box::new(|| access_denied_case(false)));
        add("access_denied.remove", Box::new(|| access_denied_case(true)));
        add("path_escape.planted_symlink", run_scenario(path_escape_case));
    }

    add("volume.observe_fails", run_scenario(volume_observe_case));
    add(
        "volume.other_disk",
        run_scenario(|| volume_match_case("uuid:aaaa", "uuid:bbbb", VolumeMatch::Other)),
    );
    add(
        "volume.recorded_unknown",
        run_scenario(|| {
            volume_match_case("unknown:mount-1", "uuid:aaaa", VolumeMatch::Unconfirmed)
        }),
    );
    add(
        "volume.observed_unknown",
        run_scenario(|| volume_match_case("uuid:aaaa", "unknown", VolumeMatch::Unconfirmed)),
    );

    add("disk_pressure.block_store", run_scenario(disk_pressure_block_store_case));
    add("disk_pressure.preflight", run_scenario(disk_pressure_preflight_case));
    add("disk_pressure.admission_line", run_scenario(|| disk_pressure_boundary_case(false)));
    add("disk_pressure.hysteresis", run_scenario(|| disk_pressure_boundary_case(true)));
    add("deletion.non_durable_volume", run_scenario(non_durable_volume_case));

    for (name, point) in [
        ("BeforeAppend", CommitPoint::BeforeAppend),
        ("AfterSegmentStaged", CommitPoint::AfterSegmentStaged),
        ("AfterSegmentPublished", CommitPoint::AfterSegmentPublished),
        ("MidRecordAppend", CommitPoint::MidRecordAppend),
        ("AfterAppendBeforeFsync", CommitPoint::AfterAppendBeforeFsync),
        ("AfterFsyncBeforeIndex", CommitPoint::AfterFsyncBeforeIndex),
        ("DuringIndexTransaction", CommitPoint::DuringIndexTransaction),
        ("AfterIndexCommitBeforeReceipt", CommitPoint::AfterIndexCommitBeforeReceipt),
        ("DuringRollover", CommitPoint::DuringRollover),
    ] {
        add(&format!("block_commit.{name}"), run_scenario(move || block_commit_case(point)));
    }

    add("schema.newer_database", run_scenario(|| schema_case(SchemaFault::NewerDatabase)));
    add("schema.older_database", run_scenario(|| schema_case(SchemaFault::OlderDatabase)));
    add(
        "schema.unstamped_with_tables",
        run_scenario(|| schema_case(SchemaFault::UnstampedWithTables)),
    );

    for (name, fault) in [
        ("InvalidVersion", Rollout::InvalidVersion),
        ("Withdrawn", Rollout::Withdrawn),
        ("KillSwitched", Rollout::KillSwitched),
        ("BelowMinimum", Rollout::BelowMinimum),
        ("NotOffered", Rollout::NotOffered),
        ("NotServed", Rollout::NotServed),
        ("HeldBack", Rollout::HeldBack),
    ] {
        add(&format!("rollout.{name}"), run_scenario(move || rollout_case(fault)));
    }
    add(
        "manifest.tampered_body",
        run_scenario(|| manifest_verification_case(ManifestFault::TamperedBody)),
    );
    add(
        "manifest.unknown_key",
        run_scenario(|| manifest_verification_case(ManifestFault::UnknownKey)),
    );
    add(
        "manifest.wrong_schema",
        run_scenario(|| manifest_verification_case(ManifestFault::WrongSchema)),
    );

    add("generation.torn_newest", run_scenario(|| generation_case(GenerationFault::TornNewest)));
    add(
        "generation.unreadable_newest",
        run_scenario(|| generation_case(GenerationFault::UnreadableNewest)),
    );
    add(
        "generation.resurrected_after_retirement",
        run_scenario(|| generation_case(GenerationFault::ResurrectedAfterRetirement)),
    );
    cases
}

/// The `case` rows of the table: id and section.
fn table_cases() -> Vec<(String, String)> {
    TABLE
        .lines()
        .filter(|line| line.trim_start().starts_with("case |"))
        .map(|line| {
            let fields: Vec<&str> = line.split('|').map(str::trim).collect();
            assert!(
                fields.len() >= 5,
                "a case row needs id, section, covers and invariant: {line}"
            );
            (fields[1].to_string(), fields[2].to_string())
        })
        .collect()
}

#[test]
fn every_table_row_is_executed_and_every_case_has_a_row() {
    let in_table: BTreeSet<String> = table_cases().into_iter().map(|(id, _)| id).collect();
    let in_code: BTreeSet<String> = cases().into_iter().map(|(id, _)| id).collect();
    #[cfg(not(unix))]
    let in_table: BTreeSet<String> = in_table
        .into_iter()
        .filter(|id| !id.starts_with("access_denied.") && !id.starts_with("path_escape."))
        .collect();
    let missing_case: Vec<_> = in_table.difference(&in_code).collect();
    let missing_row: Vec<_> = in_code.difference(&in_table).collect();
    assert!(
        missing_case.is_empty() && missing_row.is_empty(),
        "table rows without a case: {missing_case:?}; cases without a table row: {missing_row:?}"
    );
}

#[test]
fn each_injection_is_refused_keeps_the_data_and_recovers_on_retry() {
    let mut failures = Vec::new();
    let mut skipped = Vec::new();
    let mut ran = 0usize;
    for (id, build) in cases() {
        match build() {
            Built::Skip(why) => skipped.push(format!("{id}: {why}")),
            Built::Run(scenario) => {
                ran += 1;
                if let Err(problem) = run(scenario) {
                    failures.push(format!("{id}: {problem}"));
                }
            }
        }
    }
    for line in &skipped {
        eprintln!("SKIPPED {line}");
    }
    assert!(
        failures.is_empty(),
        "{} of {ran} cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(ran >= 40, "only {ran} cases ran; the matrix shrank");
}

/// The negative control: the runner itself reports a gate that accepts the
/// faulted attempt, one that loses data, and one that does not recover.
#[test]
fn the_runner_catches_a_quiet_a_lossy_and_a_stuck_gate() {
    let scenario = |faulted: Answer, intact: Result<(), String>, retry: Answer| {
        let (mut f, i, mut r) = (Some(faulted), Some(intact), Some(retry));
        Scenario {
            refusal: "Refused",
            faulted: Box::new(move || f.take().unwrap()),
            intact: Box::new(move |_| i.clone().unwrap()),
            retry: Box::new(move || r.take().unwrap()),
            keep: Vec::new(),
        }
    };
    let refused = || Answer::Refused("Refused".into());
    assert!(run(scenario(refused(), Ok(()), Answer::Done)).is_ok());
    let quiet = run(scenario(Answer::Done, Ok(()), Answer::Done)).unwrap_err();
    assert!(quiet.contains("silent success"), "{quiet}");
    let wrong = run(scenario(Answer::Refused("Other".into()), Ok(()), Answer::Done)).unwrap_err();
    assert!(wrong.contains("wrong refusal"), "{wrong}");
    let lossy = run(scenario(refused(), Err("gone".into()), Answer::Done)).unwrap_err();
    assert!(lossy.contains("not intact"), "{lossy}");
    let stuck = run(scenario(refused(), Ok(()), refused())).unwrap_err();
    assert!(stuck.contains("did not recover"), "{stuck}");
}
