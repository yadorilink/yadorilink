#![cfg(test)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::model::{torn_files, Model, Profile};
use super::trace::{self, Event};
use super::*;

/// Records what the ledger was asked for; `live()` is the records a crash
/// would have left behind (recorded and not released).
#[derive(Default)]
struct Ledger {
    recorded: Mutex<Vec<PathBuf>>,
    released: Mutex<Vec<PathBuf>>,
}

impl Ledger {
    fn live(&self) -> Vec<PathBuf> {
        let released = self.released.lock().unwrap();
        self.recorded.lock().unwrap().iter().filter(|p| !released.contains(p)).cloned().collect()
    }
}

impl NameLedger for Ledger {
    fn record(&self, path: &Path) -> io::Result<()> {
        self.recorded.lock().unwrap().push(path.to_path_buf());
        Ok(())
    }
    fn release(&self, path: &Path) {
        self.released.lock().unwrap().push(path.to_path_buf());
    }
}

/// After a Stage or Discard object was unlinked: Unix released its record (the unlink and the
/// parent sync prove the absence); Windows documents no durability for an unlink, so the record
/// stays for a restart to find the path absent.
fn assert_record_after_an_unlink(ledger: &Ledger) {
    assert_eq!(ledger.live().len(), usize::from(cfg!(windows)), "{:?}", ledger.live());
}

fn ns() -> DurableNamespace {
    DurableNamespace::unchecked_for_tests()
}

fn put(target: &Path, bytes: &'static [u8]) -> impl FnOnce(&mut fs::File) -> io::Result<()> {
    let _ = target;
    move |f| f.write_all(bytes)
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into())
        .collect();
    names.sort();
    names
}

fn reserved(dir: &Path) -> Vec<String> {
    names(dir)
        .into_iter()
        .filter(|n| crate::reserved_namespace::is_reserved_component(n.as_ref()))
        .collect()
}

#[test]
fn a_file_is_published_whole_and_its_stage_name_is_recorded_then_released() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a.txt"), Ledger::default());
    ns().create_file(&target, Replace::No, &ledger, put(&target, b"hello")).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"hello");
    assert_eq!(names(dir.path()), ["a.txt"]);
    assert_eq!(ledger.recorded.lock().unwrap().len(), 1);
    assert!(ledger.live().is_empty());
}

#[test]
fn no_replace_never_touches_an_existing_target() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a.txt"), Ledger::default());
    fs::write(&target, b"old").unwrap();
    let error = ns().create_file(&target, Replace::No, &ledger, put(&target, b"new")).unwrap_err();
    assert!(matches!(error, NsError::AlreadyExists), "{error:?}");
    assert_eq!(fs::read(&target).unwrap(), b"old");
    assert_eq!(names(dir.path()), ["a.txt"], "the stage name is removed");
    assert_record_after_an_unlink(&ledger);
}

#[test]
fn replace_swaps_the_content_without_a_gap() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a.txt"), Ledger::default());
    fs::write(&target, b"old").unwrap();
    ns().create_file(&target, Replace::Yes, &ledger, put(&target, b"new")).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert_eq!(names(dir.path()), ["a.txt"]);
}

#[test]
fn a_failed_write_leaves_no_target_and_no_stage() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a.txt"), Ledger::default());
    let error = ns()
        .create_file(&target, Replace::No, &ledger, |_| Err(io::Error::other("disk full")))
        .unwrap_err();
    assert!(matches!(error, NsError::Io(_)));
    assert!(names(dir.path()).is_empty());
    assert_record_after_an_unlink(&ledger);
}

#[test]
fn a_directory_chain_is_built_one_published_level_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a/b/c"), Ledger::default());
    ns().create_dir_all(&target, &ledger).unwrap();
    assert!(target.is_dir());
    assert_eq!(ledger.recorded.lock().unwrap().len(), 3);
    assert!(ledger.live().is_empty());
    assert!(reserved(dir.path()).is_empty() && reserved(&dir.path().join("a")).is_empty());
    // Already there is fine for the chain, not for a single directory.
    ns().create_dir_all(&target, &ledger).unwrap();
    assert!(matches!(ns().create_dir(&target, &ledger), Err(NsError::AlreadyExists)));
}

#[test]
fn a_file_in_the_way_of_a_chain_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a"), b"x").unwrap();
    let error = ns().create_dir_all(&dir.path().join("a/b"), &NoLedger).unwrap_err();
    assert!(matches!(error, NsError::AlreadyExists | NsError::Io(_)), "{error:?}");
    assert!(dir.path().join("a").is_file());
}

#[cfg(unix)]
#[test]
fn a_link_as_a_parent_is_followed() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
    let ledger = Ledger::default();
    // A sync root may be given by a link: its directory is the one that counts.
    ns().create_file(&dir.path().join("link/f"), Replace::No, &ledger, put(Path::new(""), b"x"))
        .unwrap();
    assert_eq!(fs::read(real.join("f")).unwrap(), b"x");
    ns().create_dir_all(&dir.path().join("link/sub/deeper"), &ledger).unwrap();
    assert!(real.join("sub/deeper").is_dir());
    // The moved entry may itself be a link: it is moved, not followed.
    std::os::unix::fs::symlink("nowhere", dir.path().join("l2")).unwrap();
    ns().durable_move(&dir.path().join("l2"), &dir.path().join("l3"), Replace::No).unwrap();
    assert!(fs::symlink_metadata(dir.path().join("l3")).unwrap().file_type().is_symlink());
}

#[test]
fn discard_commits_the_removal_and_finish_removes_the_object() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a.txt"), Ledger::default());
    fs::write(&target, b"x").unwrap();
    let discarded = ns().discard(&target, &ledger).unwrap();
    assert!(!target.exists());
    assert!(discarded.path().exists());
    assert_eq!(ledger.live(), [discarded.path().to_path_buf()], "named before it existed");
    assert_eq!(
        ns().discard(&target, &ledger).unwrap_err().to_string(),
        NsError::NotFound.to_string()
    );
    assert_eq!(discarded.finish(&ns(), &ledger), DiscardOutcome::Removed);
    assert!(names(dir.path()).is_empty());
    assert_record_after_an_unlink(&ledger);
}

#[test]
fn an_empty_directory_is_discarded_and_a_directory_with_children_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::default();
    let (empty, full) = (dir.path().join("empty"), dir.path().join("full"));
    fs::create_dir(&empty).unwrap();
    fs::create_dir(&full).unwrap();
    fs::write(full.join("child"), b"x").unwrap();
    assert!(matches!(ns().discard(&full, &ledger), Err(NsError::NotEmpty)));
    assert!(full.join("child").exists());
    assert!(ledger.recorded.lock().unwrap().is_empty(), "a refused discard records nothing");
    let discarded = ns().discard(&empty, &ledger).unwrap();
    assert_eq!(discarded.finish(&ns(), &ledger), DiscardOutcome::Removed);
    assert_eq!(names(dir.path()), ["full"]);
}

#[test]
fn a_child_that_appears_after_the_move_puts_the_directory_back() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("d"), Ledger::default());
    fs::create_dir(&target).unwrap();
    let discarded = ns().discard(&target, &ledger).unwrap();
    // A writer that held the old path creates a child after the emptiness check.
    fs::write(discarded.path().join("late"), b"data").unwrap();
    assert_eq!(discarded.finish(&ns(), &ledger), DiscardOutcome::Restored);
    assert_eq!(fs::read(target.join("late")).unwrap(), b"data", "nothing was deleted");
    assert_eq!(names(dir.path()), ["d"]);
    assert!(ledger.live().is_empty());
}

#[test]
fn an_occupied_original_is_never_replaced_and_the_directory_stays_discarded() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("d"), Ledger::default());
    fs::create_dir(&target).unwrap();
    let discarded = ns().discard(&target, &ledger).unwrap();
    let path = discarded.path().to_path_buf();
    fs::write(path.join("late"), b"data").unwrap();
    fs::write(&target, b"someone else").unwrap();
    assert_eq!(
        discarded.finish(&ns(), &ledger),
        DiscardOutcome::Retained { path: path.clone(), reason: RetainReason::OriginalOccupied }
    );
    assert_eq!(fs::read(&target).unwrap(), b"someone else");
    assert_eq!(fs::read(path.join("late")).unwrap(), b"data");
    assert_eq!(ledger.live(), [path], "the record stays");
}

#[test]
fn stage_and_discard_names_are_reserved_and_beside_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::default();
    let target = dir.path().join("a.txt");
    ns().create_file(&target, Replace::No, &ledger, put(&target, b"x")).unwrap();
    let discarded = ns().discard(&target, &ledger).unwrap();
    let recorded = ledger.recorded.lock().unwrap().clone();
    assert_eq!(recorded.len(), 2);
    for path in &recorded {
        assert_eq!(path.parent(), Some(dir.path()));
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(crate::reserved_namespace::is_reserved_component(name.as_ref()), "{name}");
    }
    let kind = |p: &Path| {
        crate::reserved_namespace::parse_artefact_component(
            &p.file_name().unwrap().to_string_lossy(),
        )
        .map(|(k, _)| k)
    };
    assert_eq!(kind(&recorded[0]), Some(ArtefactKind::Stage));
    assert_eq!(kind(discarded.path()), Some(ArtefactKind::Discard));
}

// --- failpoints at each operation boundary, then "restart" = look at the disk ---

fn crash<T>(failpoint: NsFailpoint, op: impl FnOnce() -> Result<T, NsError>) {
    arm_failpoint(failpoint);
    let result = op();
    disarm_failpoint();
    assert!(
        matches!(result, Err(NsError::Crashed(f)) if f == failpoint),
        "{failpoint:?} did not fire"
    );
}

#[test]
fn a_crash_after_the_stage_leaves_a_recorded_stage_and_no_target() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a.txt"), Ledger::default());
    crash(NsFailpoint::AfterStage, || {
        ns().create_file(&target, Replace::No, &ledger, put(&target, b"x"))
    });
    assert!(!target.exists());
    let left = reserved(dir.path());
    assert_eq!(left.len(), 1);
    assert_eq!(ledger.live(), [dir.path().join(&left[0])], "the leftover is claimed by a record");
}

#[test]
fn a_crash_around_the_move_leaves_the_old_or_the_new_content_never_neither() {
    for (failpoint, expect) in [
        (NsFailpoint::AfterStage, &b"old"[..]),
        (NsFailpoint::BeforeMove, b"old"),
        (NsFailpoint::AfterMove, b"new"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (target, ledger) = (dir.path().join("a.txt"), Ledger::default());
        fs::write(&target, b"old").unwrap();
        crash(failpoint, || ns().create_file(&target, Replace::Yes, &ledger, put(&target, b"new")));
        assert_eq!(fs::read(&target).unwrap(), expect, "{failpoint:?}");
    }
}

#[test]
fn a_crash_before_the_discard_move_keeps_the_object_and_its_record() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a.txt"), Ledger::default());
    fs::write(&target, b"x").unwrap();
    crash(NsFailpoint::BeforeMove, || ns().discard(&target, &ledger));
    assert!(target.exists());
    assert_eq!(ledger.live().len(), 1, "a record for a name that never came to exist is harmless");
}

#[test]
fn a_crash_after_the_discard_before_the_unlink_leaves_a_recorded_hidden_object() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a.txt"), Ledger::default());
    fs::write(&target, b"x").unwrap();
    let discarded = ns().discard(&target, &ledger).unwrap();
    let path = discarded.path().to_path_buf();
    arm_failpoint(NsFailpoint::AfterDiscardBeforeUnlink);
    let outcome = discarded.finish(&ns(), &ledger);
    disarm_failpoint();
    assert_eq!(
        outcome,
        DiscardOutcome::Retained { path: path.clone(), reason: RetainReason::RemovalFailed }
    );
    assert!(!target.exists());
    assert!(path.exists());
    assert_eq!(ledger.live(), [path]);
    assert_eq!(reserved(dir.path()).len(), 1);
}

#[test]
fn a_crash_between_levels_of_a_chain_leaves_only_published_levels() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ledger) = (dir.path().join("a/b"), Ledger::default());
    // The failpoint fires once, at the first level's move.
    crash(NsFailpoint::BeforeMove, || ns().create_dir_all(&target, &ledger));
    assert!(!dir.path().join("a").exists());
    assert_eq!(reserved(dir.path()).len(), 1);
}

// --- the gate and the probe ---

/// With the Windows gate open, the volume's probe verdict is what decides: a supported volume
/// opens, any other verdict is an `Unavailable` error, and the answer is never the closed gate's.
#[cfg(windows)]
#[test]
fn an_open_windows_gate_leaves_each_volume_to_its_probe() {
    let dir = tempfile::tempdir().unwrap();
    match (probe::cached_verdict(dir.path()).verdict, DurableNamespace::open(dir.path())) {
        (Capability::Supported, Ok(_)) => {}
        (Capability::Unsupported, Err(NsError::Unavailable(UnavailableReason::Unsupported, _))) => {
        }
        (Capability::Unknown, Err(NsError::Unavailable(UnavailableReason::Unknown, _))) => {}
        (verdict, opened) => panic!("verdict {verdict:?} but open gave {opened:?}"),
    }
}

/// Only a `Supported` verdict yields a handle; the other two verdicts are refusals that no
/// caller can turn into a handle or a plain-rename fallback.
#[test]
fn only_a_supported_verdict_opens_a_handle() {
    use UnavailableReason::{Unknown, Unsupported};
    let dir = tempfile::tempdir().unwrap();
    assert!(DurableNamespace::from_verdict(Capability::Supported, Default::default(), dir.path())
        .is_ok());
    for (verdict, reason) in
        [(Capability::Unsupported, Unsupported), (Capability::Unknown, Unknown)]
    {
        let refused = DurableNamespace::from_verdict(verdict, Default::default(), dir.path());
        assert!(matches!(&refused, Err(NsError::Unavailable(r, _)) if *r == reason), "{refused:?}");
        let fallback = DurableNamespace::only_a_closed_gate_may_fall_back(refused);
        assert!(matches!(fallback, Err(NsError::Unavailable(r, _)) if r == reason), "{fallback:?}");
    }
}

/// A directory whose volume cannot be identified is refused, on every platform and with the
/// gate open: not as a closed gate, and never with a handle.
#[test]
fn a_directory_that_cannot_be_probed_is_refused_as_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no").join("such").join("directory");
    assert!(matches!(
        DurableNamespace::open(&missing),
        Err(NsError::Unavailable(UnavailableReason::Unknown, _))
    ));
    assert!(matches!(
        DurableNamespace::open_unless_gate_closed(&missing),
        Err(NsError::Unavailable(UnavailableReason::Unknown, _))
    ));
    #[cfg(windows)]
    {
        assert!(!volume_offers_durable_namespace(Some(&missing)));
        assert!(!volume_offers_durable_namespace(None));
    }
}

#[cfg(unix)]
#[test]
fn a_unix_volume_is_probed_once_and_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    DurableNamespace::open(dir.path()).unwrap();
    DurableNamespace::open(dir.path()).unwrap();
    assert!(names(dir.path()).is_empty());
    assert_eq!(probe::probe(dir.path()), Capability::Supported);
}

// --- the power-loss model (M series) ---

// Windows takes no directory flush (it has only the write-through move), so the
// directory-sync profile describes the Unix mechanism alone.
#[cfg(unix)]
const PROFILES: [Profile; 2] = [Profile::WriteThroughMove, Profile::DirectorySync];
#[cfg(not(unix))]
const PROFILES: [Profile; 1] = [Profile::WriteThroughMove];

#[test]
fn m1_a_created_file_is_never_torn_and_is_durable_when_the_call_returns() {
    for profile in PROFILES {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        trace::take();
        let model = Model::from_dir(root, profile);
        let target = root.join("a.txt");
        ns().create_file(&target, Replace::No, &NoLedger, put(&target, b"x")).unwrap();
        let views = model.crash_views(&trace::take());
        for (i, view) in views.iter().enumerate() {
            assert!(torn_files(view).is_empty(), "{profile:?} step {i}: {view:?}");
        }
        let last = views.last().unwrap();
        assert!(last.get(&target).is_some_and(|n| !n.dir && n.flushed), "{profile:?}: {last:?}");
    }
}

#[test]
fn m2_a_replaced_target_is_present_at_every_crash_point() {
    for profile in PROFILES {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let target = root.join("a.txt");
        fs::write(&target, b"old").unwrap();
        trace::take();
        let model = Model::from_dir(root, profile);
        ns().create_file(&target, Replace::Yes, &NoLedger, put(&target, b"new")).unwrap();
        let views = model.crash_views(&trace::take());
        for (i, view) in views.iter().enumerate() {
            assert!(view.get(&target).is_some_and(|n| n.flushed), "{profile:?} step {i}: {view:?}");
            assert!(torn_files(view).is_empty());
        }
    }
}

#[test]
fn m3_a_discarded_object_does_not_come_back_once_the_discard_returned() {
    for profile in PROFILES {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let target = root.join("a.txt");
        fs::write(&target, b"x").unwrap();
        trace::take();
        let model = Model::from_dir(root, profile);
        let discarded = ns().discard(&target, &NoLedger).unwrap();
        let committed = trace::take();
        discarded.finish(&ns(), &NoLedger);
        let mut steps = committed.clone();
        steps.extend(trace::take());
        let views = model.crash_views(&steps);
        // Before the commit the object is either still there or already moved.
        for view in &views[committed.len()..] {
            assert!(!view.contains_key(&target), "{profile:?}: resurrected: {view:?}");
        }
        assert!(views[0].contains_key(&target));
    }
}

#[test]
fn m4_a_created_directory_is_durable_when_the_call_returns() {
    for profile in PROFILES {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        trace::take();
        let model = Model::from_dir(root, profile);
        let target = root.join("d");
        ns().create_dir(&target, &NoLedger).unwrap();
        let views = model.crash_views(&trace::take());
        assert!(views.last().unwrap().get(&target).is_some_and(|n| n.dir), "{profile:?}");
    }
}

#[test]
fn m5_every_level_of_a_chain_and_a_file_below_it_is_durable_when_the_calls_return() {
    for profile in PROFILES {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        trace::take();
        let model = Model::from_dir(root, profile);
        let leaf = root.join("a/b/c");
        ns().create_dir_all(&leaf, &NoLedger).unwrap();
        let file = leaf.join("f");
        ns().create_file(&file, Replace::No, &NoLedger, put(&file, b"x")).unwrap();
        let views = model.crash_views(&trace::take());
        let last = views.last().unwrap();
        for path in [root.join("a"), root.join("a/b"), leaf.clone(), file.clone()] {
            assert!(last.contains_key(&path), "{profile:?}: {path:?} lost: {last:?}");
        }
        assert!(views.iter().all(|v| torn_files(v).is_empty()));
    }
}

#[test]
fn m6_a_put_back_directory_and_its_children_survive() {
    for profile in PROFILES {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let target = root.join("d");
        fs::create_dir(&target).unwrap();
        trace::take();
        let model = Model::from_dir(root, profile);
        let discarded = ns().discard(&target, &NoLedger).unwrap();
        let child = discarded.path().join("late");
        fs::write(&child, b"data").unwrap();
        assert_eq!(discarded.finish(&ns(), &NoLedger), DiscardOutcome::Restored);
        let views = model.crash_views(&trace::take());
        assert!(views.last().unwrap().get(&target).is_some_and(|n| n.dir), "{profile:?}");
    }
}

#[test]
fn the_model_has_the_power_to_catch_the_shapes_it_replaces() {
    let root = PathBuf::from("/m");
    let target = root.join("a");
    let stage = root.join("s");
    let create = Event::Create { path: stage.clone(), dir: false };
    let rename =
        |write_through| Event::Move { from: stage.clone(), to: target.clone(), write_through };
    let flush = Event::FlushFile { path: stage.clone() };

    // Published without flushing the content first: torn.
    let model = model_at(&root, Profile::WriteThroughMove);
    let views = model.crash_views(&[create.clone(), rename(true)]);
    assert!(!torn_files(views.last().unwrap()).is_empty());

    // A plain rename after a flush: nothing reaches the crash view.
    let model = model_at(&root, Profile::WriteThroughMove);
    let views = model.crash_views(&[create.clone(), flush.clone(), rename(false)]);
    assert!(!views.last().unwrap().contains_key(&target));

    // The right shape.
    let model = model_at(&root, Profile::WriteThroughMove);
    let views = model.crash_views(&[create, flush, rename(true)]);
    assert!(views.last().unwrap().get(&target).is_some_and(|n| n.flushed));
}

fn model_at(root: &Path, profile: Profile) -> Model {
    let dir = tempfile::tempdir().unwrap();
    let mut model = Model::from_dir(dir.path(), profile);
    model.retarget(root);
    model
}

#[cfg(unix)]
#[test]
fn a_handle_refuses_a_move_on_a_volume_it_was_not_validated_for() {
    let dir = tempfile::tempdir().unwrap();
    let mut handle = DurableNamespace::open(dir.path()).unwrap();
    // A volume other than the one the directory is on.
    handle.volume = handle.volume.map(|v| v ^ 1);
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    fs::write(&a, b"x").unwrap();
    assert!(matches!(handle.durable_move(&a, &b, Replace::No), Err(NsError::CrossVolume)));
    assert!(a.exists() && !b.exists());
}

// --- remove_file / remove_empty_dir ---

#[cfg(not(windows))]
#[test]
fn m7_a_removal_is_durable_when_remove_returns() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (file, sub) = (root.join("f"), root.join("d"));
    fs::write(&file, b"x").unwrap();
    fs::create_dir(&sub).unwrap();
    trace::take();
    let model = Model::from_dir(root, Profile::DirectorySync);

    assert_eq!(ns().remove_file(&file, &NoLedger).unwrap(), DiscardOutcome::Removed);
    assert_eq!(ns().remove_empty_dir(&sub, &NoLedger).unwrap(), DiscardOutcome::Removed);

    let views = model.crash_views(&trace::take());
    let last = views.last().unwrap();
    assert!(!last.contains_key(&file) && !last.contains_key(&sub), "{last:?}");
    assert!(views[0].contains_key(&file));
}

#[test]
fn remove_refuses_the_wrong_kind_and_a_directory_with_children() {
    let dir = tempfile::tempdir().unwrap();
    let (file, sub, full) = (dir.path().join("f"), dir.path().join("d"), dir.path().join("full"));
    fs::write(&file, b"x").unwrap();
    fs::create_dir(&sub).unwrap();
    fs::create_dir(&full).unwrap();
    fs::write(full.join("child"), b"y").unwrap();

    assert!(
        matches!(ns().remove_file(&sub, &NoLedger), Err(NsError::Io(e)) if e.kind() == io::ErrorKind::IsADirectory)
    );
    assert!(
        matches!(ns().remove_empty_dir(&file, &NoLedger), Err(NsError::Io(e)) if e.kind() == io::ErrorKind::NotADirectory)
    );
    assert!(matches!(ns().remove_empty_dir(&full, &NoLedger), Err(NsError::NotEmpty)));
    assert!(matches!(
        ns().remove_empty_dir(&dir.path().join("none"), &NoLedger),
        Err(NsError::NotFound)
    ));
    assert!(file.exists() && sub.exists() && full.join("child").exists());
}

#[cfg(not(windows))]
#[test]
fn removing_what_is_already_gone_still_syncs_the_parent() {
    let dir = tempfile::tempdir().unwrap();
    trace::take();
    assert_eq!(
        ns().remove_file(&dir.path().join("gone"), &NoLedger).unwrap(),
        DiscardOutcome::Removed
    );
    assert!(trace::take().iter().any(|e| matches!(e, Event::FlushDir { .. })));
}

/// The Windows move is a rename on a held handle with POSIX semantics (a target with an open
/// reader is replaced), replacing only for a replacing move; there is no copy fallback.
#[test]
fn the_windows_rename_replaces_only_when_asked_and_with_posix_semantics() {
    // The documented values of the FILE_RENAME_FLAG_* constants.
    const REPLACE_IF_EXISTS: u32 = 0x1;
    const POSIX_SEMANTICS: u32 = 0x2;
    const IGNORE_READONLY: u32 = 0x40;
    assert_eq!(raw::windows_rename_flags(Replace::No), POSIX_SEMANTICS);
    assert_eq!(
        raw::windows_rename_flags(Replace::Yes),
        POSIX_SEMANTICS | REPLACE_IF_EXISTS | IGNORE_READONLY
    );
}

#[test]
fn the_windows_gate_is_open_and_windows_offers_durable_namespace_changes() {
    // Closing it again is a deliberate act: this test and the ones that pin the closed
    // behaviour change with it.
    const { assert!(WINDOWS_DIRECTORY_DURABILITY_VALIDATED) };
    assert_eq!(platform_offers_durable_namespace(), cfg!(any(unix, windows)));
}

#[test]
fn a_kind_specific_removal_never_removes_the_other_kind() {
    // What the caller saw may have been replaced since: the removal itself
    // refuses the wrong kind.
    let dir = tempfile::tempdir().unwrap();
    let (file, sub) = (dir.path().join("f"), dir.path().join("d"));
    fs::write(&file, b"x").unwrap();
    fs::create_dir(&sub).unwrap();
    assert!(ops::remove_dir(&file).is_err());
    assert!(ops::remove_file(&sub).is_err());
    assert!(file.is_file() && sub.is_dir());
}

// --- publish_durably / remove_file_durably ---

#[cfg(unix)]
#[test]
fn publish_durably_replaces_or_refuses_and_remove_file_durably_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, b"new").unwrap();
    fs::write(&target, b"old").unwrap();
    assert_eq!(
        publish_durably(&staged, &target, Replace::No).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&target).unwrap(), b"old");
    assert!(!staged.exists(), "a failed publish does not leave its staged file");
    fs::write(&staged, b"new").unwrap();
    publish_durably(&staged, &target, Replace::Yes).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert!(!staged.exists());
    remove_file_durably(&target).unwrap();
    remove_file_durably(&target).unwrap();
    assert!(names(dir.path()).is_empty());
}

/// A reader that has the target open (a second device of the same process, a virus scanner, the
/// search indexer) does not make a replacing publish wait or fail: the name becomes the new file
/// at once and the reader keeps the old bytes it has open (POSIX rename semantics).
#[cfg(windows)]
#[test]
fn a_replacing_move_does_not_wait_for_a_reader_that_has_the_target_open() {
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&target, b"old").unwrap();
    fs::write(&staged, b"new").unwrap();
    let mut reader = fs::File::open(&target).unwrap();
    raw::move_entry(&staged, &target, Replace::Yes).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert!(!staged.exists());
    let mut old = Vec::new();
    reader.read_to_end(&mut old).unwrap();
    assert_eq!(old, b"old");
}

/// A refused no-replace move releases the source: it can be renamed again afterwards.
#[cfg(windows)]
#[test]
fn a_no_replace_move_onto_an_existing_name_leaves_both_files() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&target, b"old").unwrap();
    fs::write(&staged, b"new").unwrap();
    let error = raw::move_entry(&staged, &target, Replace::No).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
    assert_eq!(fs::read(&target).unwrap(), b"old");
    assert_eq!(fs::read(&staged).unwrap(), b"new");
    fs::rename(&staged, dir.path().join("free")).unwrap();
}

#[test]
fn the_fallback_publish_replaces_or_refuses_like_the_durable_one() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, b"first").unwrap();
    publish_without_a_durable_move(&staged, &target, Replace::No).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"first");
    assert!(!staged.exists());
    fs::write(&staged, b"second").unwrap();
    assert_eq!(
        publish_without_a_durable_move(&staged, &target, Replace::No).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(!staged.exists(), "a failed publish does not leave its staged file");
    fs::write(&staged, b"second").unwrap();
    publish_without_a_durable_move(&staged, &target, Replace::Yes).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"second");
}

/// The no-replace fallback is an atomic no-replace move, not a hard link: it needs nothing of
/// the volume but the move (a volume without hard links, FAT or exFAT, publishes too), and an
/// object a hard link cannot name, a directory, publishes the same way.
#[test]
fn the_no_replace_fallback_needs_no_hard_link() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::create_dir(&staged).unwrap();
    fs::write(staged.join("inside"), b"x").unwrap();
    publish_without_a_durable_move(&staged, &target, Replace::No).unwrap();
    assert_eq!(fs::read(target.join("inside")).unwrap(), b"x");
    assert!(!staged.exists());
    fs::create_dir(&staged).unwrap();
    assert_eq!(
        publish_without_a_durable_move(&staged, &target, Replace::No).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(!staged.exists(), "a failed publish does not leave its staged object");
}

#[test]
fn move_durably_moves_a_file_or_a_directory_and_never_replaces_with_no_replace() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b, d, e) =
        (dir.path().join("a"), dir.path().join("b"), dir.path().join("d"), dir.path().join("e"));
    fs::write(&a, b"a").unwrap();
    fs::create_dir(&d).unwrap();
    fs::write(d.join("child"), b"c").unwrap();
    move_durably(&a, &b, Replace::No).unwrap();
    move_durably(&d, &e, Replace::No).unwrap();
    assert_eq!(fs::read(&b).unwrap(), b"a");
    assert_eq!(fs::read(e.join("child")).unwrap(), b"c");
    fs::write(&a, b"again").unwrap();
    assert_eq!(move_durably(&a, &b, Replace::No).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&a).unwrap(), b"again", "a refused move leaves the source alone");
    assert_eq!(fs::read(&b).unwrap(), b"a");
}

#[test]
fn only_a_closed_gate_lets_a_writer_fall_back_to_a_plain_rename() {
    use UnavailableReason::{GateClosed, Unknown, Unsupported};
    let fall_back = DurableNamespace::only_a_closed_gate_may_fall_back;
    assert!(matches!(
        fall_back(Err(NsError::Unavailable(GateClosed, Default::default()))),
        Ok(None)
    ));
    assert!(matches!(fall_back(Ok(ns())), Ok(Some(_))));
    // A refused volume (ReFS, exFAT, SMB, a failed probe) is an error, never the plain path.
    for reason in [Unsupported, Unknown] {
        assert!(matches!(
            fall_back(Err(NsError::Unavailable(reason, Default::default()))),
            Err(NsError::Unavailable(r, _)) if r == reason
        ));
    }
    assert!(matches!(fall_back(Err(NsError::NotFound)), Err(NsError::NotFound)));
}

#[test]
fn a_removal_releases_its_record_only_where_an_unlink_is_proven_durable() {
    // Unix: the unlink and the parent sync are the proof. Windows documents none: the record
    // outlives the removal, and a restart finds the path absent (drops it) or present (removes
    // it again).
    for (durable, released) in [(true, true), (false, false)] {
        let dir = tempfile::tempdir().unwrap();
        let (path, ledger) = (dir.path().join("x.stage"), Ledger::default());
        fs::write(&path, b"x").unwrap();
        ledger.record(&path).unwrap();
        remove_and_release_with(&path, &ledger, durable).unwrap();
        assert!(!path.exists());
        assert_eq!(ledger.live().is_empty(), released, "durable={durable}");
    }
}

#[test]
fn local_bytes_are_deletable_only_when_every_named_volume_is_durable() {
    let block_store = Path::new("/blocks");
    let sync_root = Path::new("/sync");
    let verdict = |blocks: bool, sync: bool| {
        move |dir: Option<&Path>| match dir {
            Some(d) if d == Path::new("/blocks") => blocks,
            Some(d) if d == Path::new("/sync") => sync,
            _ => false,
        }
    };
    let both = [Some(block_store), Some(sync_root)];
    assert!(all_volumes_durable(verdict(true, true), &both));
    assert!(!all_volumes_durable(verdict(false, true), &both), "block store refused");
    assert!(!all_volumes_durable(verdict(true, false), &both), "sync root refused");
    assert!(all_volumes_durable(verdict(true, false), &[Some(block_store)]));
    assert!(!all_volumes_durable(verdict(true, true), &[None, Some(sync_root)]), "unnamed volume");
}

/// Swaps the file at `path` for an empty directory, the way another process can between the
/// caller's look and the removal.
fn swap_file_for_empty_dir_before_removal(path: &Path) {
    let path = path.to_path_buf();
    before_next_remove_object(move || {
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
    });
}

/// A caller that records the path absent after `Ok` must never get `Ok` while an object still
/// occupies the path. Windows: the directory is moved aside, put back, and `remove_file` says
/// `Ok(Restored)`, which the callers accept as removed. Unix removes by kind and refuses.
#[test]
fn a_file_swapped_for_a_directory_is_not_reported_removed() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("f");
    fs::write(&target, b"x").unwrap();
    swap_file_for_empty_dir_before_removal(&target);
    let result = remove_file_with(&ns(), &target);
    assert!(target.is_dir(), "the user's directory is still there");
    assert!(result.is_err(), "Ok would let the caller record an occupied path as absent");
}

/// The Discard name is left behind when the physical removal fails after the commit point; with
/// no ledger nothing would ever clean it up. Either the caller learns of it or it is removed.
#[test]
fn a_failed_physical_removal_without_a_ledger_leaves_no_discard_file() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("f");
    fs::write(&target, b"secret").unwrap();
    arm_failpoint(NsFailpoint::AfterDiscardBeforeUnlink);
    let result = remove_file_with(&ns(), &target);
    disarm_failpoint();
    assert!(!target.exists());
    // Whatever the caller is told, nothing unrecorded may stay behind (the failpoint skipped only
    // the first unlink; a cleanup attempt succeeds).
    let _ = result;
    assert!(names(dir.path()).is_empty(), "unledgered leftover: {:?}", names(dir.path()));
}

/// Only a removal, or a leftover the ledger will finish, reads as removed; anything that
/// leaves an object beside an occupied path is an error naming the leftover.
#[test]
fn only_a_removal_or_a_ledgered_leftover_reads_as_removed() {
    let left = |reason| DiscardOutcome::Retained { path: PathBuf::from("d"), reason };
    assert!(DiscardOutcome::Removed.removed().is_ok());
    assert!(left(RetainReason::RemovalFailed).removed().is_ok());
    assert!(DiscardOutcome::Restored.removed().is_err());
    let err = left(RetainReason::OriginalOccupied).removed().unwrap_err();
    assert!(err.to_string().contains('d'), "{err}");
}

/// A closed gate says so in the message, with the flag that closes it.
#[test]
fn a_closed_gate_refusal_names_its_cause() {
    let message = NsError::Unavailable(
        UnavailableReason::GateClosed,
        RefusalCause::new("WINDOWS_DIRECTORY_DURABILITY_VALIDATED is false"),
    )
    .to_string();
    assert!(message.contains("GateClosed") && message.contains("VALIDATED"), "{message}");
}

/// A parent directory renamed away and replaced by a link to another directory after the move
/// opened its parents must not redirect the rename: the entry moves inside the directory that
/// was opened (and flushed), and the directory the link leads to is untouched.
#[cfg(unix)]
#[test]
fn a_parent_swapped_after_it_was_opened_does_not_redirect_the_move() {
    let dir = tempfile::tempdir().unwrap();
    let (parent, held, other) =
        (dir.path().join("p"), dir.path().join("p-held"), dir.path().join("other"));
    fs::create_dir(&parent).unwrap();
    fs::create_dir(&other).unwrap();
    fs::write(parent.join("staged"), b"new").unwrap();
    let (swap_parent, swap_held, swap_other) = (parent.clone(), held.clone(), other.clone());
    before_next_move(move || {
        fs::rename(&swap_parent, &swap_held).unwrap();
        std::os::unix::fs::symlink(&swap_other, &swap_parent).unwrap();
    });

    ns().durable_move(&parent.join("staged"), &parent.join("final"), Replace::No)
        .expect("the move acts on the directory it opened");

    assert_eq!(
        fs::read(held.join("final")).unwrap(),
        b"new",
        "it moved inside the opened directory"
    );
    assert!(!held.join("staged").exists());
    assert!(names(&other).is_empty(), "the directory the swapped-in link leads to was touched");
}

/// The same swap of a parent, for the replacing publish. The directory the link leads to holds a
/// decoy of the same two names: the exchange, its parking rename and the removal must all act in the
/// directory that was opened (and is flushed), so the decoys are never touched. (The reads that decide
/// the outcome still go by path and may see the decoys, so the publish may be refused; it is never
/// done in the wrong directory.)
#[cfg(unix)]
#[test]
fn a_parent_swapped_after_it_was_opened_does_not_redirect_a_replacing_publish() {
    let dir = tempfile::tempdir().unwrap();
    let (parent, held, other) =
        (dir.path().join("p"), dir.path().join("p-held"), dir.path().join("other"));
    fs::create_dir(&parent).unwrap();
    fs::create_dir(&other).unwrap();
    fs::write(parent.join("staged"), b"new").unwrap();
    fs::write(parent.join("target"), b"old").unwrap();
    fs::write(other.join("staged"), b"decoy-new").unwrap();
    fs::write(other.join("target"), b"decoy-old").unwrap();
    let (swap_parent, swap_held, swap_other) = (parent.clone(), held.clone(), other.clone());
    before_next_move(move || {
        fs::rename(&swap_parent, &swap_held).unwrap();
        std::os::unix::fs::symlink(&swap_other, &swap_parent).unwrap();
    });

    let result =
        ns().replace_if_unchanged(&parent.join("staged"), &parent.join("target"), true, &|_| true);

    assert_eq!(names(&other), vec!["staged".to_owned(), "target".to_owned()], "{result:?}");
    assert_eq!(fs::read(other.join("staged")).unwrap(), b"decoy-new", "{result:?}");
    assert_eq!(fs::read(other.join("target")).unwrap(), b"decoy-old", "{result:?}");
    // In the opened directory the publish either happened or was refused whole.
    let target = fs::read(held.join("target")).unwrap();
    if result.is_ok() {
        assert_eq!(target, b"new");
        assert!(!held.join("staged").exists());
    } else {
        assert_eq!(target, b"old", "{result:?}");
        assert_eq!(fs::read(held.join("staged")).unwrap(), b"new");
    }
}

/// A name that ends in a separator or in `/.` names a directory by that syntax, which the
/// descriptor-relative rename would drop: it is refused rather than moved as a plain name.
#[cfg(unix)]
#[test]
fn a_name_with_a_trailing_separator_is_refused_not_moved() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("f"), b"x").unwrap();
    for spelled in ["f/", "f/."] {
        let from = std::path::PathBuf::from(format!("{}/{spelled}", dir.path().display()));
        let result = ns().durable_move(&from, &dir.path().join("g"), Replace::No);
        assert!(result.is_err(), "{spelled} was moved");
        assert!(dir.path().join("f").exists() && !dir.path().join("g").exists());
    }
}

/// A move between two different directories renames in the opened source and target and flushes both.
#[cfg(unix)]
#[test]
fn a_move_between_two_directories_flushes_both_of_them() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    fs::write(a.join("f"), b"x").unwrap();
    trace::take();
    ns().durable_move(&a.join("f"), &b.join("g"), Replace::No).unwrap();
    assert_eq!(fs::read(b.join("g")).unwrap(), b"x");
    let flushed: Vec<_> = trace::take()
        .into_iter()
        .filter_map(|e| match e {
            Event::FlushDir { dir } => Some(dir),
            _ => None,
        })
        .collect();
    assert!(flushed.contains(&a) && flushed.contains(&b), "{flushed:?}");
}

/// The rename names its target in a buffer built by hand; a name of any length (odd or even, short or
/// long, ASCII or not) must be published. An exact-fit buffer failed with "the filename ... syntax is
/// incorrect" for some paths only.
#[cfg(windows)]
#[test]
fn a_move_works_whatever_the_length_of_the_target_name() {
    let dir = tempfile::tempdir().unwrap();
    for length in 1..=64 {
        for unit in ["x", "\u{e9}"] {
            let (staged, target) =
                (dir.path().join("staged"), dir.path().join(unit.repeat(length)));
            fs::write(&staged, b"s").unwrap();
            raw::move_entry(&staged, &target, Replace::No)
                .unwrap_or_else(|error| panic!("a {length}-character {unit:?} name: {error}"));
            assert!(target.exists() && !staged.exists());
        }
    }
}

/// A drive the product cannot sync into is classified by a machine reason and worded in English for
/// the command line and the logs; NTFS on a local disk is not refused.
#[test]
fn an_unsupported_drive_has_a_reason_key_and_words() {
    assert_eq!(super::classify_drive("NTFS", true), None);
    assert_eq!(super::classify_drive("ntfs", true), None);
    for (fs, fixed, key) in [
        ("ReFS", true, "refs"),
        ("exFAT", true, "exfat"),
        ("FAT32", true, "fat"),
        ("FAT", true, "fat"),
        ("UDF", true, "other"),
        ("NTFS", false, "not_local_fixed"),
        ("ReFS", false, "not_local_fixed"),
    ] {
        let drive = super::classify_drive(fs, fixed).unwrap();
        assert_eq!(drive.reason.key(), key, "{fs} fixed={fixed}");
        assert_eq!(drive.file_system, fs);
        assert!(drive.message().contains("NTFS") && drive.message().contains("not supported yet"));
    }
    let refs = super::classify_drive("ReFS", true).unwrap().message();
    assert!(refs.contains("ReFS / Dev Drive"), "{refs}");
    let other = super::classify_drive("UDF", true).unwrap().message();
    assert!(other.contains("UDF"), "{other}");
}

// --- moves on Windows: long names, relative paths, holders, flush failures ---

/// The marker of a move that happened and whose flush failed is told from every other error, and
/// keeps the flush error as its cause.
#[test]
fn a_move_whose_flush_failed_is_told_from_one_that_did_not_happen() {
    let flush = io::Error::new(io::ErrorKind::PermissionDenied, "flush refused");
    let marked = io::Error::new(flush.kind(), raw::MovedButNotFlushed(flush));
    assert!(raw::moved_but_not_flushed(&marked));
    assert_eq!(marked.kind(), io::ErrorKind::PermissionDenied);
    assert!(marked.to_string().contains("moved") && marked.to_string().contains("flush refused"));
    assert!(!raw::moved_but_not_flushed(&io::Error::from(io::ErrorKind::PermissionDenied)));
    assert!(!raw::moved_but_not_flushed(&io::Error::other("plain")));
}

/// Names whose full path is far beyond MAX_PATH (a 255-character name under a deep directory) are
/// moved: the paths are given the `\\?\` form, and the buffer holds a name of any length.
#[cfg(windows)]
#[test]
fn a_move_works_for_names_beyond_the_old_path_limit() {
    let dir = tempfile::tempdir().unwrap();
    let mut deep = dir.path().to_path_buf();
    for _ in 0..3 {
        deep.push("d".repeat(80));
    }
    let deep = crate::long_path::for_win32(&deep);
    fs::create_dir_all(&deep).unwrap();
    for length in [241usize, 250, 255] {
        let (staged, target) = (deep.join("staged"), deep.join("n".repeat(length)));
        fs::write(&staged, b"s").unwrap();
        raw::move_entry(&staged, &target, Replace::No)
            .unwrap_or_else(|error| panic!("a {length}-character name: {error}"));
        assert!(target.exists() && !staged.exists());
        fs::write(&staged, b"t").unwrap();
        raw::move_entry(&staged, &target, Replace::Yes).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"t");
    }
}

/// A bare file name (the current directory) is moved.
#[cfg(windows)]
#[test]
fn a_move_works_for_relative_paths() {
    let id = format!("{}-{:?}", std::process::id(), std::thread::current().id());
    let (staged, target) =
        (PathBuf::from(format!("rel-staged-{id}")), PathBuf::from(format!("rel-target-{id}")));
    fs::write(&staged, b"s").unwrap();
    let result = raw::move_entry(&staged, &target, Replace::No);
    let (moved, content) = (target.exists(), fs::read(&target).ok());
    let _ = fs::remove_file(&staged);
    let _ = fs::remove_file(&target);
    result.unwrap();
    assert!(moved);
    assert_eq!(content.as_deref(), Some(&b"s"[..]));
}

/// A holder that opened the target without delete sharing (C `fopen`, .NET `FileShare.Read`, a
/// scanner) delays a replacing move instead of failing it: the move is retried while the holder
/// lets go, and refused with the system's error when it never does.
#[cfg(windows)]
#[test]
fn a_replacing_move_waits_for_a_holder_that_does_not_share_delete() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&target, b"old").unwrap();
    fs::write(&staged, b"new").unwrap();
    let holder = fs::OpenOptions::new().read(true).share_mode(1 | 2).open(&target).unwrap(); // read | write, no delete
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(60));
        drop(holder);
    });
    raw::move_entry(&staged, &target, Replace::Yes).unwrap();
    releaser.join().unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"new");

    // A holder that stays: the move is refused, and nothing changed.
    fs::write(&staged, b"newer").unwrap();
    let holder = fs::OpenOptions::new().read(true).share_mode(1 | 2).open(&target).unwrap();
    let error = raw::move_entry(&staged, &target, Replace::Yes).unwrap_err();
    assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert_eq!(fs::read(&staged).unwrap(), b"newer");
    drop(holder);
}

/// A move directly under a volume root (`C:\name`): the parent directory handle used for the flush
/// is opened with only the access a flush needs, which a root accepts. Skipped where the account
/// may not create files in the root of the system drive.
#[cfg(windows)]
#[test]
fn a_move_directly_under_a_volume_root_works() {
    let root = PathBuf::from(format!("{}\\", std::env::var("SystemDrive").unwrap_or("C:".into())));
    let id = std::process::id();
    let (staged, target) =
        (root.join(format!("yl-root-staged-{id}")), root.join(format!("yl-root-target-{id}")));
    if fs::write(&staged, b"s").is_err() {
        return;
    }
    let result = raw::move_entry(&staged, &target, Replace::No);
    let moved = target.exists();
    let _ = fs::remove_file(&staged);
    let _ = fs::remove_file(&target);
    result.unwrap();
    assert!(moved);
}

/// The errors a Cloud Files provider that is not connected makes the platform answer are told
/// apart from every other error, so a publish can report "not available now" and leave the path
/// as it was.
#[test]
fn the_provider_unavailable_errors_are_recognised_and_others_are_not() {
    use std::io::Error;
    assert!(is_cloud_provider_unavailable(&Error::from_raw_os_error(-2145452027)));
    assert!(is_cloud_provider_unavailable(&Error::from_raw_os_error(0x17B)));
    assert!(!is_cloud_provider_unavailable(&Error::from_raw_os_error(5)));
    assert!(!is_cloud_provider_unavailable(&Error::other("not an os error")));
}
