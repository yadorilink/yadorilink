//! From the preserved barrier to an installed target under the freeze: the
//! quarantine of what may no longer be authored, the install transaction and what
//! survives a crash anywhere in between.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::local_author::LocalAuthor;
use crate::native_checkpoint_install::{CLEARED_BY_INSTALL, PRESERVED_BY_INSTALL};
use crate::native_rebootstrap::{
    rebootstrap_status, recover_after_restart, BlockedReason, CaptureBarrier, Crash,
    PreservationFailure, PreserveContext, Preserved, RebootstrapState, RestartOutcome,
};
use crate::native_rebootstrap_install::{
    install_rebootstrap, open_excluding_writers, quarantined_items, unlink_exclusively,
    InstallContext, InstallError, InstallPoint, InstallStep, Installed, Observed, QuarantineRoot,
    QuarantineStatus, Removal, Unlinked, WriteExclusion,
};
use crate::native_rebootstrap_recovery::RecoveryArea;
use crate::native_rebootstrap_replay::held_own_units;
use crate::native_recovery_items::{
    groups_with_preserved_data, list_recovery_items, read_item_content, restore_recovery_item,
    ItemKind, ItemOrigin, RecoveryItem,
};

use super::history_lifecycle_red::{
    dots_at, frontier_seq, incarnation_of, offline_base, put_op, rem, scenario, signed, Scenario,
};
use super::rebootstrap_preserve::{
    begin_custom, begin_with, device_b, no_hook, private_tempdir, publish_past_the_freeze,
    recovery_dirs_of, SeedContent, Setup, Viewer, Writer,
};
use super::*;

// --- the harness ------------------------------------------------------------------------------

/// A sync root on a real directory: what the daemon's root-confined operations
/// reach, minus the confinement.
pub(super) struct FsRoot<'a> {
    pub(super) dir: PathBuf,
    pub(super) removed: RefCell<Vec<String>>,
    /// Run just before anything is removed.
    before_remove: Option<&'a dyn Fn(&str)>,
    /// A crash just after the object was moved aside, before it is verified: the move stays,
    /// the call fails, and nothing else runs.
    pub(super) crash_after_move: std::cell::Cell<bool>,
    /// Run between the move aside and the verification: the object under the private name is
    /// written, as a program holding it open could.
    after_move: Option<&'a dyn Fn(&Path)>,
    /// Run after the moved object was verified and before it is unlinked: a program that held
    /// the object open for writing since before the move writes into it.
    before_unlink: Option<&'a dyn Fn(&Path)>,
    /// Run when the unlink is about to happen (the exclusion held and nothing is kept).
    pub(super) crash_before_unlink: std::cell::Cell<bool>,
    /// Use the platform's real exclusion. Off, the root stands in for a platform that grants it,
    /// so the removal tests mean the same on every host.
    real_exclusion: bool,
}

impl<'a> FsRoot<'a> {
    pub(super) fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            removed: RefCell::new(Vec::new()),
            before_remove: None,
            crash_after_move: std::cell::Cell::new(false),
            after_move: None,
            before_unlink: None,
            crash_before_unlink: std::cell::Cell::new(false),
            real_exclusion: false,
        }
    }

    pub(super) fn writing_after_move(dir: &Path, after_move: &'a dyn Fn(&Path)) -> Self {
        Self { after_move: Some(after_move), ..Self::new(dir) }
    }

    pub(super) fn writing_before_unlink(dir: &Path, before_unlink: &'a dyn Fn(&Path)) -> Self {
        Self { before_unlink: Some(before_unlink), real_exclusion: true, ..Self::new(dir) }
    }

    fn checking(dir: &Path, before_remove: &'a dyn Fn(&str)) -> Self {
        Self { before_remove: Some(before_remove), ..Self::new(dir) }
    }
}

impl FsRoot<'_> {
    fn observe_at(&self, full: &Path) -> Result<Observed, String> {
        let Ok(meta) = fs::symlink_metadata(full) else { return Ok(Observed::Absent) };
        if meta.file_type().is_symlink() {
            let target = fs::read_link(full).map_err(|e| e.to_string())?;
            return Ok(Observed::Symlink {
                target: yadorilink_fs_platform::fs_identity::target_to_bytes(&target),
            });
        }
        if meta.is_dir() {
            return Ok(Observed::Directory);
        }
        if meta.is_file() {
            return crate::native_rebootstrap_install::observe_regular_file(
                fs::File::open(full).map_err(|e| e.to_string())?,
            );
        }
        Ok(Observed::Other)
    }
}

impl FsRoot<'_> {
    pub(super) fn aside(&self, path: &str, claim: &str) -> PathBuf {
        self.dir.join(format!(".{}.{claim}.quarantining", path.replace('/', "_")))
    }
}

impl QuarantineRoot for FsRoot<'_> {
    fn observe(&self, path: &str) -> Result<Observed, String> {
        self.observe_at(&self.dir.join(path))
    }

    fn open_file(&self, path: &str) -> Result<Box<dyn std::io::Read>, String> {
        Ok(Box::new(fs::File::open(self.dir.join(path)).map_err(|e| e.to_string())?))
    }

    fn remove(&self, path: &str, expected: &Observed, claim: &str) -> Result<Removal, String> {
        if self.observe(path)? != *expected {
            return Err(format!("{path} changed since it was observed"));
        }
        if let Some(check) = self.before_remove {
            check(path);
        }
        // As a real root does: rename aside inside the root, verify, then unlink.
        let full = self.dir.join(path);
        let aside = self.aside(path, claim);
        fs::rename(&full, &aside).map_err(|e| e.to_string())?;
        if let Some(after_move) = self.after_move {
            after_move(&aside);
        }
        if self.crash_after_move.get() {
            return Err("crash after the move aside".into());
        }
        let removal = if fs::symlink_metadata(&aside).map_err(|e| e.to_string())?.is_file() {
            let hook = || {
                if let Some(before_unlink) = self.before_unlink {
                    before_unlink(&aside);
                }
            };
            let unlink = |p: &Path| {
                if self.crash_before_unlink.get() {
                    // The process dies as the unlink begins: the name stays.
                    return Err(std::io::Error::other("crash at the unlink"));
                }
                fs::remove_file(p)
            };
            let open = |p: &Path| -> std::io::Result<WriteExclusion> {
                if self.real_exclusion {
                    open_excluding_writers(p)
                } else {
                    Ok(WriteExclusion::assumed(fs::File::open(p)?))
                }
            };
            match unlink_exclusively(&aside, expected, &open, &hook, &unlink)? {
                Unlinked::Done(removal) => removal,
                Unlinked::ChangedBeforeUnlink => {
                    fs::rename(&aside, &full).map_err(|e| e.to_string())?;
                    return Err(format!("{path} changed while it was being removed"));
                }
            }
        } else {
            if FsRoot::new(&self.dir).observe_at(&aside)? != *expected {
                fs::rename(&aside, &full).map_err(|e| e.to_string())?;
                return Err(format!("{path} changed while it was being removed"));
            }
            fs::remove_file(&aside).map_err(|e| e.to_string())?;
            Removal::Removed
        };
        if removal == Removal::Removed {
            self.removed.borrow_mut().push(path.to_owned());
        }
        Ok(removal)
    }

    fn release_claim(&self, path: &str, claim: &str) -> Result<(), String> {
        let aside = self.aside(path, claim);
        if !aside.exists() {
            return Ok(());
        }
        let full = self.dir.join(path);
        if full.symlink_metadata().is_ok() {
            return Err(format!("{path} is occupied again"));
        }
        fs::rename(&aside, &full).map_err(|e| e.to_string())
    }
}

fn preserve_context<'a>(
    recovery_root: &'a Path,
    capture: CaptureBarrier,
    authority: &'a dyn crate::native_rebootstrap::ReassertAuthority,
) -> PreserveContext<'a> {
    PreserveContext {
        recovery_root,
        items_root: super::rebootstrap_preserve::items_root_of(recovery_root),
        sync_roots: &[],
        available_bytes: None,
        capture,
        final_capture: &super::rebootstrap_preserve::NoCapture,
        content: &SeedContent,
        authority,
        now_unix: 2000,
    }
}

/// Installs the rebootstrap the journal of `local` names, from the barrier.
pub(super) fn install_with(
    local: &Connection,
    recovery_root: &Path,
    root: &dyn QuarantineRoot,
    authority: &dyn crate::native_rebootstrap::ReassertAuthority,
    hook: &mut dyn FnMut(InstallPoint) -> Result<(), Crash>,
) -> Result<Installed, InstallError> {
    let status = rebootstrap_status(local, &group()).unwrap().expect("a rebootstrap");
    let preserve = preserve_context(recovery_root, CaptureBarrier::Completed, authority);
    // A writer: this device signs the closure of its old incarnation.
    let own = crate::author_incarnation::current_author(local).unwrap().device;
    let key = device_key(device_seed(own.as_str()));
    install_rebootstrap(
        local,
        &InstallContext { preserve: &preserve, root, closure_key: Some(&key) },
        &group(),
        &status.recovery_id,
        hook,
    )
}

pub(super) fn install(
    local: &Connection,
    recovery_root: &Path,
    root: &dyn QuarantineRoot,
) -> Result<Installed, InstallError> {
    install_with(local, recovery_root, root, &Writer, &mut |_| Ok(()))
}

fn crash_on(point: InstallPoint) -> impl FnMut(InstallPoint) -> Result<(), Crash> {
    move |reached| if reached == point { Err(Crash) } else { Ok(()) }
}

/// The scenario every test starts from: a device `B` whose undelivered edit of
/// `x` (v2) the sealer's target does not cover, preserved.
struct Preserved2 {
    w: Scenario,
    recovery_root: tempfile::TempDir,
    root: tempfile::TempDir,
    preserved: Preserved,
}

fn preserved_scenario(authority: &dyn crate::native_rebootstrap::ReassertAuthority) -> Preserved2 {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    let setup = Setup { authority, ..Setup::default() };
    let preserved =
        begin_custom(&w.b, built(&w.sealer), recovery_root.path(), &setup, &mut no_hook).unwrap();
    Preserved2 { w, recovery_root, root, preserved }
}

fn heads_of(c: &Connection) -> yadorilink_replica_domain::native_state::NativeState {
    crate::native_store::load_state(c, &group()).unwrap()
}

// --- the install ---------------------------------------------------------------------------------

/// The native state becomes the target's, this device authors as a new
/// incarnation, the old one is fenced at the target's position, and the group
/// stays frozen until the rebootstrap is finished.
#[test]
fn the_install_replaces_the_native_state_rotates_and_fences_and_the_group_stays_frozen() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let old_author = crate::author_incarnation::current_author(&p.w.b).unwrap();
    let before_roots = roots_of(&p.w.b);
    assert_ne!(before_roots, roots_of(&p.w.sealer), "sanity: B has state the target lacks");

    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    // The target's state, whole.
    assert_eq!(roots_of(&p.w.b), roots_of(&p.w.sealer));
    assert_eq!(heads_of(&p.w.b), heads_of(&p.w.sealer));
    // A new incarnation, minted for this, and the old one fenced at the target's position.
    let record = crate::author_incarnation::incarnation_record(&p.w.b).unwrap().unwrap();
    assert_eq!(
        record.minted_reason,
        yadorilink_replica_domain::author::IncarnationMintReason::Rebootstrap
    );
    assert_eq!(record.previous, Some(old_author.incarnation));
    assert_ne!(record.author, old_author);
    assert_eq!(installed.new_author, record.author);
    assert_eq!(installed.old_authors, vec![old_author.clone()]);
    assert_eq!(
        unexported_rotation_cutoff(&p.w.b, &group(), &old_author),
        Some(Some(yadorilink_replica_domain::ids::AuthorSeq(1))),
        "the fence is the old author's position in the target"
    );
    // The changes of the old incarnation the target lacks are gone from the log, but
    // not from the recovery area.
    assert_eq!(frontier_seq(&p.w.b, &old_author), Some(1));
    assert!(crate::native_store::fetch_delta_body(
        &p.w.b,
        &group(),
        &old_author,
        yadorilink_replica_domain::ids::AuthorSeq(2)
    )
    .unwrap()
    .is_none());
    let area = RecoveryArea::open_dir(&p.preserved.dir).unwrap();
    assert!(area.read_delta(&p.w.undelivered.delta_hash()).is_ok(), "the area keeps the old delta");
    // The journal, and the freeze it keeps.
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::CatchingUp
    );
    assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
    let _ = dots_at(&p.w.b, "x");
}

/// Installing again after the install is the same answer, and changes nothing.
#[test]
fn installing_twice_is_idempotent() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let first = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    let state = heads_of(&p.w.b);

    let second = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    assert_eq!(second, first);
    assert_eq!(heads_of(&p.w.b), state);
    assert_eq!(
        crate::author_incarnation::current_author(&p.w.b).unwrap(),
        first.new_author,
        "a second install must not rotate again"
    );
}

// --- crash safety ----------------------------------------------------------------------------------

const TX_STEPS: [InstallStep; 5] = [
    InstallStep::NativeStateCleared,
    InstallStep::TargetInstalled,
    InstallStep::ProjectionArmed,
    InstallStep::Rotated,
    InstallStep::Recorded,
];

/// A crash anywhere inside the transaction leaves the old state, the old
/// incarnation, no fence and the journal at `quarantining`; the install then
/// completes from there.
#[test]
fn a_crash_inside_the_install_transaction_changes_nothing_and_the_install_resumes() {
    for step in TX_STEPS {
        let p = preserved_scenario(&Writer);
        let fs_root = FsRoot::new(p.root.path());
        let old_author = crate::author_incarnation::current_author(&p.w.b).unwrap();
        let state = heads_of(&p.w.b);
        let roots = roots_of(&p.w.b);

        let crashed = install_with(
            &p.w.b,
            p.recovery_root.path(),
            &fs_root,
            &Writer,
            &mut crash_on(InstallPoint::InTransaction(step)),
        );

        assert!(matches!(crashed, Err(InstallError::Crashed)), "{step:?}: {crashed:?}");
        assert_eq!(heads_of(&p.w.b), state, "{step:?}: the state changed");
        assert_eq!(roots_of(&p.w.b), roots, "{step:?}");
        assert_eq!(
            crate::author_incarnation::current_author(&p.w.b).unwrap(),
            old_author,
            "{step:?}"
        );
        assert_eq!(
            unexported_rotation_cutoff(&p.w.b, &group(), &old_author),
            None,
            "{step:?}: a fence was written by a transaction that did not commit"
        );
        assert_eq!(
            rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
            RebootstrapState::Quarantining,
            "{step:?}"
        );
        assert!(
            crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap(),
            "{step:?}: the freeze survives the crash"
        );

        let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
        assert_eq!(roots_of(&p.w.b), roots_of(&p.w.sealer), "{step:?}");
        assert_eq!(installed.old_authors, vec![old_author], "{step:?}");
    }
}

/// A crash right after the commit finds it committed: the install is done and a
/// second call does nothing.
#[test]
fn a_crash_after_the_commit_finds_the_install_done() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());

    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Writer,
        &mut crash_on(InstallPoint::AfterCommit),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    let author = crate::author_incarnation::current_author(&p.w.b).unwrap();

    let restart = recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::CatchingUp(_)), "{restart:?}");
    let again = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    assert_eq!(again.new_author, author);
}

// --- the freeze comes first -----------------------------------------------------------------------------

/// The journal says `Quarantining` (the group has been frozen since the capture)
/// before any original leaves the root.
#[test]
fn the_quarantine_is_recorded_before_the_first_original_leaves_the_root() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    write_original(&p.root.path().join("x"));

    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterBeginQuarantine),
    );

    assert!(matches!(crashed, Err(InstallError::Crashed)));
    assert!(fs_root.removed.borrow().is_empty(), "an original left before the quarantine began");
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Quarantining
    );
    assert!(p.root.path().join("x").exists());
}

// --- quarantine ---------------------------------------------------------------------------------------------

/// An original this device may no longer author leaves the root once its verified
/// copy is in the area, and is reported with its recovery id and path.
#[test]
fn an_unauthorable_original_leaves_the_root_after_its_copy_is_verified() {
    let p = preserved_scenario(&Viewer);
    // At the moment the original leaves, the journal says the root is being
    // modified and the group is frozen.
    let hold_stands = |_: &str| {
        assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
        assert_eq!(
            rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
            RebootstrapState::Quarantining
        );
    };
    let fs_root = FsRoot::checking(p.root.path(), &hold_stands);
    write_original(&p.root.path().join("x"));

    let installed =
        install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    assert!(!p.root.path().join("x").exists(), "the original is still in the root");
    assert_eq!(*fs_root.removed.borrow(), vec!["x".to_string()]);
    let area = RecoveryArea::open_dir(&p.preserved.dir).unwrap();
    let manifest = area.read_intent().unwrap().manifest;
    let items = quarantined_items(&p.w.b, &group(), Some(&manifest)).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].path, "x");
    assert_eq!(items[0].recovery_id, p.preserved.recovery_id);
    assert_eq!(items[0].status, QuarantineStatus::Removed);
    assert!(!items[0].versions.is_empty(), "the status names the versions the area holds");
    // Nothing re-authors it: the installed projection decides what stands there.
    assert_eq!(installed.old_authors.len(), 1);
}

/// An edit made after the barrier is not the copy in the area: it is saved under
/// its own digest before the original leaves.
#[test]
fn an_edit_made_after_the_barrier_is_kept_before_the_original_leaves() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), b"typed after the barrier").unwrap();

    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    assert!(!p.root.path().join("x").exists());
    let digest: [u8; 32] = Sha256::digest(b"typed after the barrier").into();
    let items = quarantined_items(&p.w.b, &group(), None).unwrap();
    assert_eq!(items[0].status, QuarantineStatus::RemovedLateEdit { sha256: digest });
    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "the edit is a permanent recovery item before the install ends");
    assert_eq!(saved[0].path.as_str(), "x");
    assert_eq!(late_content(&p, &saved[0]), b"typed after the barrier");
}

/// A regular file's late edit prepared from bytes held by the test.
fn prepare_late_edit_of_bytes(
    conn: &Connection,
    items_root: &Path,
    path: &str,
    bytes: &[u8],
    meta: Option<crate::native_recovery_items::LateEditMeta>,
) -> Result<
    crate::native_recovery_items::PreparedLateEdit,
    crate::native_recovery_items::LateEditError,
> {
    let edit = crate::native_recovery_items::LateEdit {
        path,
        symlink: false,
        size: bytes.len() as u64,
        sha256: crate::native_rebootstrap_recovery::sha256(bytes),
        symlink_target: &[],
        meta,
    };
    let open = || -> Result<Box<dyn std::io::Read + '_>, String> { Ok(Box::new(bytes)) };
    crate::native_recovery_items::prepare_late_edit(
        conn,
        items_root,
        &[],
        &group(),
        &edit,
        &open,
        1,
    )
}

struct RefusesRemoval<'a>(FsRoot<'a>);
impl QuarantineRoot for RefusesRemoval<'_> {
    fn observe(&self, path: &str) -> Result<Observed, String> {
        self.0.observe(path)
    }
    fn open_file(&self, path: &str) -> Result<Box<dyn std::io::Read>, String> {
        self.0.open_file(path)
    }
    fn remove(&self, _: &str, _: &Observed, _: &str) -> Result<Removal, String> {
        Err("crash before the removal".into())
    }
    fn release_claim(&self, path: &str, claim: &str) -> Result<(), String> {
        self.0.release_claim(path, claim)
    }
}

fn late_edits_of(c: &Connection) -> Vec<RecoveryItem> {
    list_recovery_items(c, &group())
        .unwrap()
        .into_iter()
        .filter(|item| item.kind == ItemKind::LateEdit)
        .collect()
}

fn late_content(p: &Preserved2, item: &RecoveryItem) -> Vec<u8> {
    let items_root = super::rebootstrap_preserve::items_root_of(p.recovery_root.path());
    read_item_content(&p.w.b, &items_root, &group(), &item.item_id).unwrap()
}

/// The edit stays listed and restorable after the rebootstrap finished and its
/// transient recovery area is gone; no sweep takes it.
#[test]
fn a_late_edit_outlives_the_finished_rebootstrap_and_can_be_restored() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), b"typed after the barrier").unwrap();
    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    super::rebootstrap_replay::complete_machine(
        &p.w.b,
        p.recovery_root.path(),
        &p.preserved.recovery_id,
        &Viewer,
    );
    fs::remove_dir_all(&p.preserved.dir).unwrap();
    let items_root = super::rebootstrap_preserve::items_root_of(p.recovery_root.path());
    crate::native_recovery_items::sweep_unregistered(&p.w.b, &items_root, &group()).unwrap();

    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(saved[0].origin, ItemOrigin::LateEdit);
    assert_eq!(late_content(&p, &saved[0]), b"typed after the barrier");
    assert!(groups_with_preserved_data(&p.w.b).unwrap().contains(&group()));

    let author = crate::author_incarnation::current_author(&p.w.b).unwrap();
    let key = device_key(2);
    let local = LocalAuthor { author: author.clone(), signing_key: &key, capture: None };
    let mut imported = Vec::new();
    restore_recovery_item(
        &p.w.b,
        &items_root,
        &group(),
        &saved[0].item_id,
        &local,
        &mut |version, bytes| {
            let mut bytes_read = Vec::new();
            std::io::Read::read_to_end(bytes, &mut bytes_read).unwrap();
            imported.push((version.version_hash, bytes_read));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(imported, vec![(saved[0].version, b"typed after the barrier".to_vec())]);
    let state = crate::native_store::load_state(&p.w.b, &group()).unwrap();
    assert!(
        state.heads[&SyncPath("x".into())]
            .iter()
            .any(|(dot, payload)| dot.author == author && payload.version == saved[0].version),
        "the restore authored no put of the saved bytes: {state:?}"
    );
    assert_eq!(late_edits_of(&p.w.b), saved, "restoring removed the item");
}

/// What the saved late edit would restore as: the metadata of its version record.
#[cfg(unix)]
fn late_meta(p: &Preserved2, item: &RecoveryItem) -> yadorilink_replica_domain::file::FileMeta {
    let items_root = super::rebootstrap_preserve::items_root_of(p.recovery_root.path());
    let author = crate::author_incarnation::current_author(&p.w.b).unwrap();
    let key = device_key(2);
    let local = LocalAuthor { author, signing_key: &key, capture: None };
    let mut meta = None;
    restore_recovery_item(&p.w.b, &items_root, &group(), &item.item_id, &local, &mut |v, _| {
        meta = Some(v.meta.clone());
        Ok(())
    })
    .unwrap();
    meta.expect("the restore imported the version")
}

/// Ends the rebootstrap and drops its transient area, as a finished one is.
#[cfg(unix)]
fn finish(p: &Preserved2) {
    super::rebootstrap_replay::complete_machine(
        &p.w.b,
        p.recovery_root.path(),
        &p.preserved.recovery_id,
        &Viewer,
    );
    fs::remove_dir_all(&p.preserved.dir).unwrap();
}

/// The preserved version of `x` has these bytes and this mtime (the scenario's version 2).
#[cfg(unix)]
const PRESERVED_MTIME: i64 = 2_000;

/// Writes a file as it was when preserved as version `seed`: the same bytes and the same
/// mtime, so it is no edit.
fn write_original_of(path: &std::path::Path, seed: u8) {
    fs::write(path, [seed]).unwrap();
    // The version's mode is 0o644; the umask must not decide whether this is an edit.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(seed as u64 * 1_000);
    fs::OpenOptions::new().write(true).open(path).unwrap().set_modified(at).unwrap();
}

fn write_original(path: &std::path::Path) {
    write_original_of(path, 2);
}

/// Installs over a root whose `x` the user left as `content` with `mode` and `mtime` (ns).
#[cfg(unix)]
fn install_over_x(content: &[u8], mode: u32, mtime: i64) -> (Preserved2, FsRoot<'static>) {
    use std::os::unix::fs::PermissionsExt;
    let p = preserved_scenario(&Viewer);
    let x = p.root.path().join("x");
    fs::write(&x, content).unwrap();
    fs::set_permissions(&x, fs::Permissions::from_mode(mode)).unwrap();
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(mtime as u64);
    fs::OpenOptions::new().write(true).open(&x).unwrap().set_modified(at).unwrap();
    let fs_root = FsRoot::new(p.root.path());
    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    (p, fs_root)
}

/// A chmod after the barrier leaves the bytes of the preserved version, and is still an
/// edit nobody captured.
#[cfg(unix)]
#[test]
fn a_mode_only_edit_after_the_barrier_is_kept_as_a_late_edit() {
    let (p, _root) = install_over_x(&[2], 0o755, PRESERVED_MTIME);
    finish(&p);

    assert!(!p.root.path().join("x").exists());
    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "the chmod was lost with the original: {saved:?}");
    assert_eq!(late_content(&p, &saved[0]), [2]);
    assert_eq!(late_meta(&p, &saved[0]).unix_mode, Some(0o755));
}

/// Bytes and mode both changed: the item restores both.
#[cfg(unix)]
#[test]
fn a_late_edit_keeps_the_mode_and_mtime_the_file_had() {
    let mtime = 5_000_000_000;
    let (p, _root) = install_over_x(b"typed after the barrier", 0o750, mtime);
    finish(&p);

    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "{saved:?}");
    let meta = late_meta(&p, &saved[0]);
    assert_eq!(meta.unix_mode, Some(0o750));
    assert_eq!(meta.mtime_unix_nanos, mtime, "the mtime was the install clock");
}

/// A touch: the same bytes, mode and xattrs under another mtime is a distinct version for
/// ordinary capture, so it is an edit here too, and restores with the touched mtime.
#[cfg(unix)]
#[test]
fn a_touch_only_edit_after_the_barrier_is_kept_as_a_late_edit() {
    let touched = 9_000_000_000;
    let (p, _root) = install_over_x(&[2], 0o644, touched);
    finish(&p);

    assert!(!p.root.path().join("x").exists());
    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "the touch was lost with the original: {saved:?}");
    assert_eq!(late_content(&p, &saved[0]), [2]);
    assert_eq!(late_meta(&p, &saved[0]).mtime_unix_nanos, touched);
}

/// The cheap path stays cheap: the same bytes and the same mode are the preserved copy.
#[cfg(unix)]
#[test]
fn an_unchanged_original_is_removed_without_a_late_edit() {
    let (p, _root) = install_over_x(&[2], 0o644, PRESERVED_MTIME);

    assert!(!p.root.path().join("x").exists());
    assert!(late_edits_of(&p.w.b).is_empty());
    let items = quarantined_items(&p.w.b, &group(), None).unwrap();
    assert_eq!(items[0].status, QuarantineStatus::Removed);
}

/// An extended attribute set after the barrier is an edit as well.
#[cfg(target_os = "linux")]
#[test]
fn an_xattr_only_edit_after_the_barrier_is_kept_as_a_late_edit() {
    let p = preserved_scenario(&Viewer);
    let x = p.root.path().join("x");
    fs::write(&x, [2]).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&x, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(PRESERVED_MTIME as u64);
    fs::OpenOptions::new().write(true).open(&x).unwrap().set_modified(at).unwrap();
    yadorilink_local_storage::apply_xattrs(&x, &[("user.note".to_owned(), b"kept".to_vec())])
        .unwrap();
    let fs_root = FsRoot::new(p.root.path());
    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    finish(&p);

    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "the xattr was lost with the original: {saved:?}");
    assert_eq!(late_meta(&p, &saved[0]).xattrs, vec![("user.note".to_owned(), b"kept".to_vec())]);
}

#[cfg(unix)]
#[test]
fn a_late_symlink_edit_is_kept_as_an_item_too() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    std::os::unix::fs::symlink("elsewhere", p.root.path().join("x")).unwrap();
    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    super::rebootstrap_replay::complete_machine(
        &p.w.b,
        p.recovery_root.path(),
        &p.preserved.recovery_id,
        &Viewer,
    );
    fs::remove_dir_all(&p.preserved.dir).unwrap();

    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(late_content(&p, &saved[0]), b"elsewhere");
}

/// The row is registered, the original not yet removed: the item is listed and the
/// original still stands. Retrying the crashed path leaves one item.
#[test]
fn a_failed_removal_after_the_item_is_registered_keeps_one_item_and_the_original() {
    let p = preserved_scenario(&Viewer);
    fs::write(p.root.path().join("x"), b"typed after the barrier").unwrap();
    for _ in 0..2 {
        let refused = RefusesRemoval(FsRoot::new(p.root.path()));
        let result =
            install_with(&p.w.b, p.recovery_root.path(), &refused, &Viewer, &mut |_| Ok(()));
        assert!(matches!(result, Err(InstallError::Blocked(_))), "{result:?}");
        assert_eq!(late_edits_of(&p.w.b).len(), 1);
        assert!(p.root.path().join("x").exists(), "the original left before its item landed");
    }
    install_with(&p.w.b, p.recovery_root.path(), &FsRoot::new(p.root.path()), &Viewer, &mut |_| {
        Ok(())
    })
    .unwrap();
    assert!(!p.root.path().join("x").exists());
    assert_eq!(late_edits_of(&p.w.b).len(), 1, "a retry made a second item");
}

/// Files written for an item whose row never landed are crash residue the store's sweep owns,
/// and the install runs it before saving anything; the install never infers an edit from them.
#[test]
fn item_files_without_a_row_are_swept_by_the_install_and_never_become_an_edit() {
    let p = preserved_scenario(&Viewer);
    let items_root = super::rebootstrap_preserve::items_root_of(p.recovery_root.path());
    prepare_late_edit_of_bytes(&p.w.b, &items_root, "x", b"written, never registered", None)
        .unwrap();
    assert!(late_edits_of(&p.w.b).is_empty(), "no row was registered");
    fs::write(p.root.path().join("x"), b"typed after the barrier").unwrap();

    install_with(&p.w.b, p.recovery_root.path(), &FsRoot::new(p.root.path()), &Viewer, &mut |_| {
        Ok(())
    })
    .unwrap();

    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(late_content(&p, &saved[0]), b"typed after the barrier");
    let group_dir = fs::read_dir(&items_root).unwrap().next().unwrap().unwrap().path();
    assert_eq!(fs::read_dir(group_dir).unwrap().count(), 1, "the orphan's files stayed");
}

/// The user saves again between a crash and its resume: both edits are kept, each as its own
/// item.
#[test]
fn an_edit_changed_again_after_a_crash_is_kept_beside_the_first() {
    let p = preserved_scenario(&Viewer);
    fs::write(p.root.path().join("x"), b"first").unwrap();
    let refused = RefusesRemoval(FsRoot::new(p.root.path()));
    install_with(&p.w.b, p.recovery_root.path(), &refused, &Viewer, &mut |_| Ok(())).unwrap_err();
    fs::write(p.root.path().join("x"), b"second").unwrap();

    install_with(&p.w.b, p.recovery_root.path(), &FsRoot::new(p.root.path()), &Viewer, &mut |_| {
        Ok(())
    })
    .unwrap();

    let mut contents: Vec<Vec<u8>> =
        late_edits_of(&p.w.b).iter().map(|item| late_content(&p, item)).collect();
    contents.sort();
    assert_eq!(contents, vec![b"first".to_vec(), b"second".to_vec()]);
}

/// The removal happened and its status did not, but the item is gone: nothing may continue
/// on the strength of a leftover file.
#[test]
fn a_recorded_late_edit_without_its_item_blocks_instead_of_continuing() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), b"typed after the barrier").unwrap();
    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterOriginalRemoved(0)),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)), "{crashed:?}");
    p.w.b.execute("DELETE FROM native_recovery_item WHERE kind = 'late_edit'", []).unwrap();

    let resumed = install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(()));
    assert!(matches!(resumed, Err(InstallError::Blocked(_))), "{resumed:?}");
}

/// Two late edits of one path can share bytes and differ only in metadata. The crash-resume
/// confirms the exact item the quarantine row recorded, so the other version's item, though
/// durable and of the same path and bytes, confirms nothing.
#[test]
fn a_same_bytes_late_edit_of_other_metadata_does_not_confirm_the_recorded_item() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    let bytes: &[u8] = b"typed after the barrier";
    fs::write(p.root.path().join("x"), bytes).unwrap();
    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterOriginalRemoved(0)),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)), "{crashed:?}");
    // The recorded item is lost; the other version of the same path and bytes is durable.
    p.w.b.execute("DELETE FROM native_recovery_item WHERE kind = 'late_edit'", []).unwrap();
    let items_root = super::rebootstrap_preserve::items_root_of(p.recovery_root.path());
    let prepared = prepare_late_edit_of_bytes(
        &p.w.b,
        &items_root,
        "x",
        bytes,
        Some(crate::native_recovery_items::LateEditMeta {
            mtime_unix_nanos: 42_000_000_000,
            unix_mode: Some(0o600),
            xattrs: Vec::new(),
        }),
    )
    .unwrap();
    prepared.register(&p.w.b, &group(), "another-source", 1).unwrap();
    assert_eq!(late_edits_of(&p.w.b).len(), 1);

    let resumed = install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(()));

    assert!(matches!(resumed, Err(InstallError::Blocked(_))), "{resumed:?}");
}

/// A held own unit says whether an original really left the folder: a directory in its place
/// is left alone, so nothing was moved although the plan judged the unit not replayable.
#[test]
fn a_held_unit_reports_originals_quarantined_from_what_the_quarantine_did() {
    let moved = preserved_scenario(&Viewer);
    write_original(&moved.root.path().join("x"));
    let kept = preserved_scenario(&Viewer);
    fs::create_dir(kept.root.path().join("x")).unwrap();
    for (p, expected) in [(&moved, true), (&kept, false)] {
        let fs_root = FsRoot::new(p.root.path());
        install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
        super::rebootstrap_replay::complete_machine(
            &p.w.b,
            p.recovery_root.path(),
            &p.preserved.recovery_id,
            &Viewer,
        );
        let held = held_own_units(&p.w.b, p.recovery_root.path(), &group()).unwrap();
        assert_eq!(held.len(), 1, "{held:?}");
        assert_eq!(held[0].originals_quarantined, expected, "{held:?}");
    }
}

/// An original already gone, or a directory in its place, is never an error and
/// never removes anything it should not.
#[test]
fn an_absent_original_and_a_directory_in_its_place_are_handled() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    assert_eq!(
        quarantined_items(&p.w.b, &group(), None).unwrap()[0].status,
        QuarantineStatus::AlreadyAbsent
    );

    let q = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(q.root.path());
    fs::create_dir(q.root.path().join("x")).unwrap();
    fs::write(q.root.path().join("x/inside"), b"another path").unwrap();
    install_with(&q.w.b, q.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    assert_eq!(
        quarantined_items(&q.w.b, &group(), None).unwrap()[0].status,
        QuarantineStatus::LeftInPlace
    );
    assert!(q.root.path().join("x/inside").exists());
}

/// A change this device may still author keeps its file in the root.
#[test]
fn a_reassertable_original_is_never_removed() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    write_original(&p.root.path().join("x"));

    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    assert!(p.root.path().join("x").exists(), "a re-assertable file was removed");
    assert!(fs_root.removed.borrow().is_empty());
    assert!(quarantined_items(&p.w.b, &group(), None).unwrap().is_empty());
}

/// A crash between two quarantine steps removes each original exactly once on
/// the way to the install.
#[test]
fn a_crash_between_quarantine_steps_removes_each_original_exactly_once() {
    let o = offline_base(false);
    let d1 = signed(&o.b1, 1, None, vec![put_op("p", 2, Vec::new())]);
    let d2 = signed(&o.b1, 2, Some(d1.delta_hash()), vec![put_op("q", 3, Vec::new())]);
    for d in [&d1, &d2] {
        publish(&o.b, &o.b1, &device_key(2), d.clone());
    }
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    write_original_of(&root.path().join("p"), 2);
    write_original_of(&root.path().join("q"), 3);
    let setup = Setup { authority: &Viewer, ..Setup::default() };
    begin_custom(&o.b, built(&o.sealer), recovery_root.path(), &setup, &mut no_hook).unwrap();
    let fs_root = FsRoot::new(root.path());

    let crashed = install_with(
        &o.b,
        recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterQuarantineItem(0)),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    assert_eq!(fs_root.removed.borrow().len(), 1);

    install_with(&o.b, recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    let mut removed = fs_root.removed.borrow().clone();
    removed.sort();
    assert_eq!(removed, vec!["p".to_string(), "q".to_string()], "each original is removed once");
}

// --- the install runs from the stored target and nothing else -------------------------------------------

/// A later, different target is offered while the first waits at the barrier. The
/// install takes the recovery id and installs what is stored there.
#[test]
fn installing_uses_the_preserved_target_not_a_later_received_one() {
    let p = preserved_scenario(&Writer);
    let first_roots = roots_of(&p.w.sealer);
    // The sealer moves on: a later target exists, and nothing ever hands it to the install.
    let c = incarnation_of("device-c", 1);
    publish(&p.w.sealer, &c, &device_key(3), signed(&c, 1, None, vec![put_op("w", 5, Vec::new())]));
    assert_ne!(roots_of(&p.w.sealer), first_roots);
    let fs_root = FsRoot::new(p.root.path());

    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    assert_eq!(roots_of(&p.w.b), first_roots, "the later target was installed");
    assert!(dots_at(&p.w.b, "w").is_empty());
}

/// A stored bundle that was changed after the barrier is refused before anything
/// is touched.
#[test]
fn a_stored_target_that_changed_is_not_installed() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let bundle = p.preserved.dir.join("target.bundle");
    let mut bytes = fs::read(&bundle).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&bundle, bytes).unwrap();
    let state = heads_of(&p.w.b);

    let outcome = install(&p.w.b, p.recovery_root.path(), &fs_root);

    assert!(matches!(outcome, Err(InstallError::Blocked(_))), "{outcome:?}");
    assert_eq!(heads_of(&p.w.b), state);
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Preserved,
        "the quarantine began for a target that cannot be installed"
    );
}

/// The install is for the recovery id the journal names.
#[test]
fn another_recovery_id_is_not_installable() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let preserve = preserve_context(p.recovery_root.path(), CaptureBarrier::Completed, &Writer);
    let outcome = install_rebootstrap(
        &p.w.b,
        &InstallContext { preserve: &preserve, root: &fs_root, closure_key: None },
        &group(),
        "00000000000000000000000000000000",
        &mut |_| Ok(()),
    );
    assert!(matches!(outcome, Err(InstallError::NotInstallable(_))), "{outcome:?}");
}

// --- the protected set is checked when the root is about to change --------------------------------------

/// Something written past the freeze between the barrier and the install makes
/// what the barrier protected stale: the install refuses before it touches
/// anything, and the old state, the area and the root stay as they were.
#[test]
fn a_write_past_the_freeze_stops_the_install_before_anything_changes() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let d3 =
        signed(&p.w.b1, 3, Some(p.w.undelivered.delta_hash()), vec![put_op("z", 5, Vec::new())]);
    publish_past_the_freeze(&p.w.b, &p.w.b1, &device_key(2), d3);
    let state = heads_of(&p.w.b);

    let outcome = install(&p.w.b, p.recovery_root.path(), &fs_root);

    assert!(matches!(outcome, Err(InstallError::FrontierChanged)), "{outcome:?}");
    assert_eq!(heads_of(&p.w.b), state, "the old state was cleared");
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Preserved,
        "the quarantine began over a stale barrier"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    assert!(fs_root.removed.borrow().is_empty());
}

/// A capture pass that did not complete is no basis for the install.
#[test]
fn a_partial_capture_pass_blocks_the_install() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let status = rebootstrap_status(&p.w.b, &group()).unwrap().unwrap();
    let preserve = preserve_context(
        p.recovery_root.path(),
        CaptureBarrier::Partial { detail: "unreadable directory".into() },
        &Writer,
    );

    let outcome = install_rebootstrap(
        &p.w.b,
        &InstallContext { preserve: &preserve, root: &fs_root, closure_key: None },
        &group(),
        &status.recovery_id,
        &mut |_| Ok(()),
    );

    assert!(matches!(
        outcome,
        Err(InstallError::Blocked(BlockedReason::PreservationFailed(
            PreservationFailure::CapturePartial { .. }
        )))
    ));
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Preserved
    );
}

// --- restart ------------------------------------------------------------------------------------------------

/// After a crash the restart reports where the machine is, and a new target is
/// refused once the root may have been modified.
#[test]
fn a_restart_in_quarantining_resumes_and_no_other_target_is_accepted() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    write_original(&p.root.path().join("x"));
    let _ = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterQuarantineItem(0)),
    );

    let restart = recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Quarantining(_)), "{restart:?}");

    let c = incarnation_of("device-c", 1);
    publish(&p.w.sealer, &c, &device_key(3), signed(&c, 1, None, vec![put_op("w", 5, Vec::new())]));
    let other = begin_with(&p.w.b, built(&p.w.sealer), p.recovery_root.path(), &mut no_hook);
    assert!(
        matches!(other, Err(crate::native_rebootstrap::BeginError::TargetFixed(_))),
        "{other:?}"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
}

// --- the install keeps the rebootstrap's own state ----------------------------------------------------------------

/// Every table with a `group_id` column is either cleared by the install or kept
/// by it, and the lists say which: a new table has to be classified before it
/// can be shipped.
#[test]
fn every_group_table_is_classified_as_cleared_or_preserved_by_the_install() {
    let c = conn();
    let mut tables: BTreeSet<String> = BTreeSet::new();
    let names: Vec<String> = {
        let mut stmt = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0)).unwrap().map(Result::unwrap).collect()
    };
    for name in names {
        let has_group_id = c
            .prepare(&format!("PRAGMA table_info({name})"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .any(|column| column == "group_id");
        if has_group_id {
            tables.insert(name);
        }
    }
    let cleared: BTreeSet<String> = CLEARED_BY_INSTALL.iter().map(|t| t.to_string()).collect();
    let kept: BTreeSet<String> = PRESERVED_BY_INSTALL.iter().map(|t| t.to_string()).collect();
    assert!(cleared.is_disjoint(&kept), "a table is both: {:?}", cleared.intersection(&kept));
    let unclassified: Vec<&String> =
        tables.iter().filter(|t| !cleared.contains(*t) && !kept.contains(*t)).collect();
    assert!(unclassified.is_empty(), "not classified as cleared or preserved: {unclassified:?}");
    let unknown: Vec<&String> =
        cleared.iter().chain(kept.iter()).filter(|t| !tables.contains(*t)).collect();
    assert!(unknown.is_empty(), "classified but without a group_id column: {unknown:?}");
}

/// The install clears the replicated and derived state of the group, and the
/// rebootstrap's own bookkeeping, the fence and the other groups' state stay.
#[test]
fn the_install_clears_native_state_but_keeps_the_rebootstraps_own_bookkeeping() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    // Another group's native state must not be touched.
    let other_group = FolderGroupId("another-group".into());
    p.w.b
        .execute(
            "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
             VALUES (?1, 'device-z', X'00000000000000000000000000000001', 1)",
            [other_group.as_str()],
        )
        .unwrap();
    let items_before: i64 =
        p.w.b
            .query_row(
                "SELECT COUNT(*) FROM native_rebootstrap_recovery_item WHERE group_id = ?1",
                [group().as_str()],
                |row| row.get(0),
            )
            .unwrap();
    let deltas_before: i64 =
        p.w.b
            .query_row(
                "SELECT COUNT(*) FROM native_rebootstrap_delta WHERE group_id = ?1",
                [group().as_str()],
                |row| row.get(0),
            )
            .unwrap();
    assert!(items_before > 0 && deltas_before > 0);

    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    let count = |table: &str, group: &str| -> i64 {
        p.w.b
            .query_row(&format!("SELECT COUNT(*) FROM {table} WHERE group_id = ?1"), [group], |r| {
                r.get(0)
            })
            .unwrap()
    };
    assert_eq!(count("native_rebootstrap_recovery_item", group().as_str()), items_before);
    assert_eq!(count("native_rebootstrap_delta", group().as_str()), deltas_before);
    assert_eq!(count("native_rebootstrap_journal", group().as_str()), 1);
    assert_eq!(count("native_author_closure", group().as_str()), 1);
    assert_eq!(count("native_author_context", other_group.as_str()), 1, "another group's state");
}

// --- the sidecar -----------------------------------------------------------------------------------------

/// The rotation commits with the install; the `<db>.instance` sidecar is written
/// after it. A crash between the two leaves the database on the new incarnation
/// and the sidecar on the old one. The restart repairs the sidecar: it does not
/// mint another incarnation, which would orphan what was authored under the
/// first.
#[test]
fn install_commits_b2_then_crash_before_sidecar_rewrite_restart_keeps_b2_and_does_not_mint_b3() {
    use crate::author_incarnation::{
        ensure_incarnation, incarnation_record, IncarnationEnvironment, InstanceSidecar,
    };
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let before = incarnation_record(&p.w.b).unwrap().unwrap();
    let stale_sidecar = InstanceSidecar::for_record(&before);

    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    let environment = |sidecar| IncarnationEnvironment {
        device_id: before.author.device.clone(),
        sidecar,
        machine_fingerprint: before.machine_fingerprint.clone(),
    };

    // The restart finds the sidecar of the incarnation that was rotated away.
    let restarted = ensure_incarnation(&p.w.b, &environment(Some(stale_sidecar))).unwrap();

    assert_eq!(restarted.author, installed.new_author, "another incarnation was minted");
    assert_eq!(
        restarted.minted_reason,
        yadorilink_replica_domain::author::IncarnationMintReason::Rebootstrap
    );
    assert_eq!(incarnation_record(&p.w.b).unwrap().unwrap(), restarted);
    // The caller writes the sidecar of what it was given; with that, the next
    // start is quiet.
    let again =
        ensure_incarnation(&p.w.b, &environment(Some(InstanceSidecar::for_record(&restarted))))
            .unwrap();
    assert_eq!(again, restarted);
}

/// Only the sidecar of the incarnation this rotation replaced is accepted: any
/// other mismatch is still a restored or copied database.
#[test]
fn a_sidecar_that_is_not_the_replaced_incarnations_still_mints_a_restore() {
    use crate::author_incarnation::{ensure_incarnation, IncarnationEnvironment, InstanceSidecar};
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let before = crate::author_incarnation::incarnation_record(&p.w.b).unwrap().unwrap();
    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    let foreign = InstanceSidecar {
        db_instance_nonce: [9; 16],
        incarnation: yadorilink_replica_domain::author::IncarnationId([9; 16]),
    };

    for sidecar in [None, Some(foreign)] {
        let minted = ensure_incarnation(
            &p.w.b,
            &IncarnationEnvironment {
                device_id: before.author.device.clone(),
                sidecar,
                machine_fingerprint: before.machine_fingerprint.clone(),
            },
        )
        .unwrap();
        assert_ne!(minted.author, installed.new_author, "{sidecar:?}: no restore was detected");
        assert_eq!(
            minted.minted_reason,
            yadorilink_replica_domain::author::IncarnationMintReason::Restore
        );
        // Put the rebootstrap's incarnation back for the next case.
        p.w.b
            .execute(
                "UPDATE author_incarnation SET incarnation = ?1, minted_reason = 'rebootstrap', \
                 previous = ?2",
                (
                    installed.new_author.incarnation.0.as_slice(),
                    before.author.incarnation.0.as_slice(),
                ),
            )
            .unwrap();
    }
}

// --- what stops the install, and what it arms -----------------------------------------------------------------

/// A copy in the area that does not read back as it was written stops the
/// quarantine before the original leaves the root, whether the damage was there
/// when the install began or happened after the area was checked.
#[test]
fn a_damaged_copy_stops_the_quarantine_before_the_original_leaves() {
    for damaged_before_the_install in [true, false] {
        let p = preserved_scenario(&Viewer);
        let fs_root = FsRoot::new(p.root.path());
        write_original(&p.root.path().join("x"));
        let area = RecoveryArea::open_dir(&p.preserved.dir).unwrap();
        let manifest = area.read_intent().unwrap().manifest;
        let version = manifest.items.iter().find_map(|item| item.put_version).unwrap();
        let copy = p.preserved.dir.join("versions").join(hex::encode(version.0));
        if damaged_before_the_install {
            fs::write(&copy, [0xff]).unwrap();
        }

        let outcome =
            install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |point| {
                if !damaged_before_the_install && point == InstallPoint::AfterBeginQuarantine {
                    fs::write(&copy, [0xff]).unwrap();
                }
                Ok(())
            });

        assert!(matches!(outcome, Err(InstallError::Blocked(_))), "{outcome:?}");
        assert!(fs_root.removed.borrow().is_empty(), "an original left with a bad copy behind it");
        assert!(p.root.path().join("x").exists());
    }
}

/// The join refuses the stored target: nothing the transaction did stays, and the
/// journal is where the attempt found it.
#[test]
fn a_target_the_join_refuses_leaves_everything_as_it_was() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    // This replica fenced the sealer's author before its first delta; the target holds it.
    let s = incarnation_of("device-s", 1);
    rotation_closure_at(&p.w.b, &group(), &s, None);
    // The fence stands for a closure learned before the barrier: the barrier records it.
    let sealed: i64 =
        p.w.b
            .query_row(
                "SELECT COALESCE(capture_high_seq, -1) FROM native_rebootstrap_journal",
                [],
                |r| r.get(0),
            )
            .unwrap();
    let hash = crate::native_rebootstrap::frozen_frontier_hash(
        &p.w.b,
        &group(),
        &p.preserved.manifest_sha256,
        (sealed >= 0).then_some(sealed),
    )
    .unwrap();
    p.w.b
        .execute(
            "UPDATE native_rebootstrap_journal SET frozen_frontier_hash = ?1",
            [hash.as_slice()],
        )
        .unwrap();
    let state = heads_of(&p.w.b);
    let author = crate::author_incarnation::current_author(&p.w.b).unwrap();

    let outcome = install(&p.w.b, p.recovery_root.path(), &fs_root);

    assert!(matches!(outcome, Err(InstallError::BundleRefused(_))), "{outcome:?}");
    assert_eq!(heads_of(&p.w.b), state, "the refused install changed the state");
    assert_eq!(crate::author_incarnation::current_author(&p.w.b).unwrap(), author);
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Quarantining
    );
}

/// The projection is armed for every path whose heads changed, including the
/// ones that only the old state had.
#[test]
fn the_install_arms_the_projection_for_every_path_that_changed() {
    let o = offline_base(false);
    let d1 = signed(&o.b1, 1, None, vec![put_op("only-here", 2, Vec::new())]);
    publish(&o.b, &o.b1, &device_key(2), d1);
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    begin_with(&o.b, built(&o.sealer), recovery_root.path(), &mut no_hook).unwrap();
    o.b.execute("DELETE FROM projection_obligations", []).unwrap();

    install(&o.b, recovery_root.path(), &FsRoot::new(root.path())).unwrap();

    let armed: BTreeSet<String> =
        o.b.prepare("SELECT path FROM projection_obligations WHERE group_id = ?1")
            .unwrap()
            .query_map([group().as_str()], |row| row.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
    assert!(armed.contains("x"), "the target's path: {armed:?}");
    assert!(
        armed.contains("only-here"),
        "a path only the old state had must be armed to follow the target: {armed:?}"
    );
}

/// The freeze is derived from the journal row: it is there after the database is
/// closed and opened again, and the scheduler still keeps the group's paths out of
/// its claim.
#[test]
fn the_freeze_and_the_journal_survive_a_restart_of_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.db");
    {
        let c = Connection::open(&path).unwrap();
        crate::replica_tables::init_for_tests(&c).unwrap();
        c.execute(
            "INSERT INTO native_rebootstrap_journal \
             (group_id, recovery_id, state, target_checkpoint_hash, started_at, updated_at) \
             VALUES (?1, '00000000000000000000000000000001', 'quarantining', ?2, 1, 1)",
            (group().as_str(), [7u8; 32].as_slice()),
        )
        .unwrap();
    }

    let c = Connection::open(&path).unwrap();
    crate::replica_tables::init_for_tests(&c).unwrap();

    assert!(crate::native_rebootstrap::group_frozen(&c, group().as_str()).unwrap());
    assert!(!crate::native_rebootstrap::group_frozen(&c, "another-group").unwrap());
    assert_eq!(
        rebootstrap_status(&c, &group()).unwrap().unwrap().state,
        RebootstrapState::Quarantining
    );
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        &c,
        group().as_str(),
        &["d/p", "e"],
        1000,
    )
    .unwrap();
    let claim = |c: &Connection| -> Vec<String> {
        crate::projection_obligations::claim_runnable_obligations(c, 10_000, 100, 100)
            .unwrap()
            .into_iter()
            .map(|o| o.path)
            .collect()
    };
    assert!(claim(&c).is_empty(), "a frozen group's rows were claimed");
    c.execute("UPDATE native_rebootstrap_journal SET state = 'replaying'", []).unwrap();
    assert!(crate::native_rebootstrap::finish_rebootstrap(
        &c,
        &group(),
        "00000000000000000000000000000001"
    )
    .unwrap());
    assert_eq!(claim(&c), vec!["d/p".to_string(), "e".to_string()]);
}

// --- review of the install: nothing may downgrade, lose or duplicate ---------------------------------------

#[cfg(unix)]
fn make_manifest_unreadable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir.join("manifest.json"), fs::Permissions::from_mode(0o644)).unwrap();
}

#[cfg(unix)]
fn make_manifest_readable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir.join("manifest.json"), fs::Permissions::from_mode(0o600)).unwrap();
}

/// A block raised while the root is being modified is an overlay on the stage, not
/// a replacement of it: when the area reads back again the machine is still where
/// it was, no other target is accepted, nothing is planned again, and the
/// originals that already left the root are still in the area.
#[cfg(unix)]
#[test]
fn a_block_raised_while_quarantining_keeps_the_stage_and_the_area() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    write_original(&p.root.path().join("x"));
    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterQuarantineItem(0)),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    assert!(!p.root.path().join("x").exists(), "sanity: the original left the root");

    make_manifest_unreadable(&p.preserved.dir);
    let restart = recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Blocked(_)), "{restart:?}");
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Quarantining,
        "a block replaced the stage the machine had reached"
    );
    make_manifest_readable(&p.preserved.dir);

    let again = begin_with(&p.w.b, built(&p.w.sealer), p.recovery_root.path(), &mut no_hook);
    assert!(
        matches!(again, Err(crate::native_rebootstrap::BeginError::TargetFixed(_))),
        "{again:?}"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    let area = RecoveryArea::open_dir(&p.preserved.dir).unwrap();
    let manifest = area.read_intent().unwrap().manifest;
    assert!(
        manifest
            .versions
            .iter()
            .filter(|v| v.has_bytes)
            .all(|v| area.read_version(&v.version).is_ok()),
        "the quarantined original is no longer recoverable"
    );
    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::CatchingUp
    );
}

/// The same for an installed target: its own log is gone, so a "stale preserved
/// set" must never be read into it and its area must never be swept.
#[cfg(unix)]
#[test]
fn a_block_raised_after_the_install_keeps_the_stage_and_the_area() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();

    make_manifest_unreadable(&p.preserved.dir);
    let restart = recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Blocked(_)), "{restart:?}");
    make_manifest_readable(&p.preserved.dir);

    let again = install(&p.w.b, p.recovery_root.path(), &fs_root);
    assert_eq!(again.as_ref().ok(), Some(&installed), "{again:?}");
    let other = begin_with(&p.w.b, built(&p.w.sealer), p.recovery_root.path(), &mut no_hook);
    assert!(
        matches!(other, Err(crate::native_rebootstrap::BeginError::TargetFixed(_))),
        "{other:?}"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::CatchingUp
    );
    assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
}

/// Giving a rebootstrap up on purpose is only possible before the root was
/// touched.
#[test]
fn discarding_is_refused_once_the_root_may_have_changed() {
    // A journal that never reached the barrier is discarded by the restart.
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let recovery_root = private_tempdir();
    w.b.execute(
        "INSERT INTO native_rebootstrap_journal \
         (group_id, recovery_id, state, target_checkpoint_hash, started_at, updated_at) \
         VALUES (?1, '00000000000000000000000000000001', 'planning', ?2, 1, 1)",
        (group().as_str(), [7u8; 32].as_slice()),
    )
    .unwrap();
    recover_after_restart(&w.b, recovery_root.path(), &group()).unwrap();
    assert!(rebootstrap_status(&w.b, &group()).unwrap().is_none());

    // A journal past the quarantine is not discardable.
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    assert!(!crate::native_rebootstrap::discard_blocked_rebootstrap(
        &p.w.b,
        p.recovery_root.path(),
        &group()
    )
    .unwrap());
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
}

/// From the final capture until the rebootstrap is finished the whole group is
/// frozen: nothing materializes over the root, and the freeze outlives the install
/// itself.
#[test]
fn the_group_is_frozen_until_the_rebootstrap_is_finished() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Writer,
        &mut crash_on(InstallPoint::AfterBeginQuarantine),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    let frozen = |c: &Connection| {
        crate::native_rebootstrap::refuse_materialization_if_frozen(c, group().as_str()).is_err()
    };
    assert!(frozen(&p.w.b), "a lane could write while the group is quarantining");

    let installed = install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    assert!(frozen(&p.w.b), "the install ended the freeze");

    let finish = |c: &Connection, id: &str| {
        crate::native_rebootstrap::finish_rebootstrap(c, &group(), id).unwrap()
    };
    assert!(!finish(&p.w.b, "another-rebootstrap"), "another recovery id finished it");
    assert!(frozen(&p.w.b));
    assert!(!finish(&p.w.b, &installed.recovery_id), "the catch-up and the replay come first");
    assert!(frozen(&p.w.b));
    super::rebootstrap_replay::complete_machine(
        &p.w.b,
        p.recovery_root.path(),
        &installed.recovery_id,
        &Writer,
    );
    assert!(!frozen(&p.w.b), "finishing did not end the freeze");
    assert!(rebootstrap_status(&p.w.b, &group()).unwrap().is_none());
}

/// A rebootstrap that has not installed yet is never finished: the freeze ends
/// only after the install.
#[test]
fn a_rebootstrap_is_not_finished_before_it_is_installed() {
    let p = preserved_scenario(&Writer);
    let id = &p.preserved.recovery_id;
    assert!(!crate::native_rebootstrap::finish_rebootstrap(&p.w.b, &group(), id).unwrap());
    let fs_root = FsRoot::new(p.root.path());
    let _ = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Writer,
        &mut crash_on(InstallPoint::AfterBeginQuarantine),
    );
    assert!(!crate::native_rebootstrap::finish_rebootstrap(&p.w.b, &group(), id).unwrap());
    assert!(crate::native_rebootstrap::group_frozen(&p.w.b, group().as_str()).unwrap());
}

/// Should a delta reach the log after the quarantine began anyway (a writer that
/// does not check the freeze), the install does not clear it away: it stops before
/// the clear.
#[test]
fn a_write_past_the_freeze_after_the_quarantine_stops_the_install_before_the_clear() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Writer,
        &mut crash_on(InstallPoint::AfterBeginQuarantine),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)));
    let late = signed(
        &p.w.b1,
        3,
        Some(p.w.undelivered.delta_hash()),
        vec![put_op("unheld", 5, Vec::new())],
    );
    publish_past_the_freeze(&p.w.b, &p.w.b1, &device_key(2), late.clone());
    let state = heads_of(&p.w.b);

    let outcome = install(&p.w.b, p.recovery_root.path(), &fs_root);

    assert!(matches!(outcome, Err(InstallError::FrontierChanged)), "{outcome:?}");
    assert_eq!(heads_of(&p.w.b), state);
    assert!(crate::native_store::fetch_delta_body(
        &p.w.b,
        &group(),
        &p.w.b1,
        yadorilink_replica_domain::ids::AuthorSeq(3)
    )
    .unwrap()
    .is_some());
}

/// The edit copy is referenced before its original can disappear: a crash between
/// the removal and the status update still finds it recorded.
#[test]
fn a_crash_between_removing_a_late_edit_and_recording_it_still_references_the_copy() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    fs::write(p.root.path().join("x"), b"typed after the barrier").unwrap();

    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &fs_root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterOriginalRemoved(0)),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)), "{crashed:?}");
    assert!(!p.root.path().join("x").exists());

    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    let digest: [u8; 32] = Sha256::digest(b"typed after the barrier").into();
    assert_eq!(
        quarantined_items(&p.w.b, &group(), None).unwrap()[0].status,
        QuarantineStatus::RemovedLateEdit { sha256: digest },
        "the edit's copy is in the area but nothing points at it"
    );
}

/// Every incarnation of this device whose changes were preserved is fenced, each at
/// its own position in the target.
#[test]
fn every_old_incarnation_is_fenced_not_only_the_current_one() {
    let o = offline_base(false);
    let d1 = signed(&o.b1, 1, None, vec![put_op("p", 2, Vec::new())]);
    publish(&o.b, &o.b1, &device_key(2), d1);
    let b2 = crate::author_incarnation::rotate_incarnation(
        &o.b,
        yadorilink_replica_domain::author::IncarnationMintReason::Restore,
    )
    .unwrap()
    .author;
    let e1 = signed(&b2, 1, None, vec![put_op("q", 3, Vec::new())]);
    publish(&o.b, &b2, &device_key(2), e1);
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    begin_with(&o.b, built(&o.sealer), recovery_root.path(), &mut no_hook).unwrap();

    let installed = install(&o.b, recovery_root.path(), &FsRoot::new(root.path())).unwrap();

    let mut olds = installed.old_authors.clone();
    olds.sort();
    let mut expected = vec![o.b1.clone(), b2.clone()];
    expected.sort();
    assert_eq!(olds, expected);
    for old in [&o.b1, &b2] {
        assert!(
            unexported_rotation_cutoff(&o.b, &group(), old).is_some(),
            "{old:?} is reported as fenced but is not"
        );
    }
}

/// Two calls for one group never run together: the second is turned away while the
/// first holds the journal, and the first completes undisturbed.
#[test]
fn a_second_call_while_an_install_is_running_is_turned_away() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let inner: RefCell<Option<Result<Installed, InstallError>>> = RefCell::new(None);

    let outer = install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Writer, &mut |point| {
        if point == InstallPoint::AfterBeginQuarantine && inner.borrow().is_none() {
            *inner.borrow_mut() = Some(install(&p.w.b, p.recovery_root.path(), &fs_root));
        }
        Ok(())
    });

    assert!(outer.is_ok(), "{outer:?}");
    let inner = inner.into_inner().expect("the hook ran");
    assert!(
        matches!(inner, Err(InstallError::Busy)),
        "a concurrent call ran alongside the install: {inner:?}"
    );
}

/// The quarantine rows belong to one rebootstrap: a row left by another does not
/// make this one skip its originals.
#[test]
fn a_quarantine_row_of_another_rebootstrap_does_not_skip_this_ones() {
    let p = preserved_scenario(&Viewer);
    let fs_root = FsRoot::new(p.root.path());
    write_original(&p.root.path().join("x"));
    p.w.b
        .execute(
            "INSERT INTO native_rebootstrap_quarantine (group_id, recovery_id, path, status) \
             VALUES (?1, 'another-rebootstrap', 'x', 'removed')",
            [group().as_str()],
        )
        .unwrap();

    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();

    assert!(!p.root.path().join("x").exists(), "a stale row made the quarantine skip the original");
}

/// The removal contract: an object that changed after it was observed is put back
/// and the call fails, so the next attempt sees (and saves) the new content.
#[test]
fn a_file_changed_between_observation_and_removal_is_put_back() {
    let dir = tempfile::tempdir().unwrap();
    let root = FsRoot::new(dir.path());
    fs::write(dir.path().join("x"), b"observed").unwrap();
    let observed = root.observe("x").unwrap();
    fs::write(dir.path().join("x"), b"saved a moment later").unwrap();

    assert!(root.remove("x", &observed, "0011223344556677").is_err());

    assert_eq!(fs::read(dir.path().join("x")).unwrap(), b"saved a moment later");
    assert!(root.removed.borrow().is_empty());
}

/// A journal blocked at the barrier is taken back to it when its area reads
/// again, but not once the group changed while it was blocked: a blocked journal
/// does not freeze the group, so what the barrier protected is no longer known.
#[cfg(unix)]
#[test]
fn a_blocked_journal_is_not_taken_back_to_the_barrier_after_the_group_changed() {
    let p = preserved_scenario(&Writer);
    make_manifest_unreadable(&p.preserved.dir);
    recover_after_restart(&p.w.b, p.recovery_root.path(), &group()).unwrap();
    assert!(matches!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Blocked(_)
    ));
    let late =
        signed(&p.w.b1, 3, Some(p.w.undelivered.delta_hash()), vec![put_op("z", 5, Vec::new())]);
    publish(&p.w.b, &p.w.b1, &device_key(2), late);
    make_manifest_readable(&p.preserved.dir);

    let outcome = begin_with(&p.w.b, built(&p.w.sealer), p.recovery_root.path(), &mut no_hook);

    assert!(outcome.is_err(), "a journal over a changed group was taken back to the barrier");
    assert!(matches!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Blocked(_)
    ));
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
}

/// Starting a new journal never replaces one whose root was modified.
#[test]
fn a_new_journal_never_replaces_one_past_the_barrier() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    install(&p.w.b, p.recovery_root.path(), &fs_root).unwrap();
    let (verified, stored) = crate::native_rebootstrap_target::verify_and_prepare_target(
        built(&p.w.sealer),
        &group(),
        &Policy,
    )
    .unwrap();
    let preserve = preserve_context(p.recovery_root.path(), CaptureBarrier::Completed, &Writer);

    let outcome = crate::native_rebootstrap::start_journal_and_preserve(
        &p.w.b,
        &device_b(),
        &group(),
        &verified,
        &stored,
        &preserve,
        Some(p.preserved.recovery_id.clone()),
        &mut no_hook,
    );

    assert!(
        matches!(outcome, Err(crate::native_rebootstrap::BeginError::TargetFixed(_))),
        "{outcome:?}"
    );
    assert_eq!(recovery_dirs_of(p.recovery_root.path()), vec![p.preserved.dir.clone()]);
    assert_eq!(
        rebootstrap_status(&p.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::CatchingUp
    );
}

// --- the closure of the old incarnation ------------------------------------------------------------

/// The install of the journal of `local`, as a device that signs with `key` (or
/// holds no authority to sign, `None`).
fn install_signing_with(
    local: &Connection,
    recovery_root: &Path,
    root: &dyn QuarantineRoot,
    key: Option<&ed25519_dalek::SigningKey>,
) -> Result<Installed, InstallError> {
    let status = rebootstrap_status(local, &group()).unwrap().expect("a rebootstrap");
    let preserve = preserve_context(recovery_root, CaptureBarrier::Completed, &Writer);
    install_rebootstrap(
        local,
        &InstallContext { preserve: &preserve, root, closure_key: key },
        &group(),
        &status.recovery_id,
        &mut |_| Ok(()),
    )
}

#[test]
fn rotating_devices_own_closure_creates_the_same_row_and_no_fence_table_exists() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());
    let old_author = crate::author_incarnation::current_author(&p.w.b).unwrap();
    let key = device_key(2);

    install_signing_with(&p.w.b, p.recovery_root.path(), &fs_root, Some(&key)).unwrap();

    let rows = crate::native_closure::all_closures(&p.w.b, &group()).unwrap();
    assert_eq!(rows.len(), 1, "the rotation signs one closure of the old incarnation");
    let closure = &rows[0];
    assert_eq!(closure.closure.author, old_author);
    let target = crate::native_store::frontier_entry_get(&p.w.sealer, &group(), &old_author)
        .unwrap()
        .expect("the target holds the old author");
    assert_eq!(closure.closure.cutoff, Some(target), "the cutoff is the old author's position");
    assert_eq!(closure.author_public_key, key.verifying_key().to_bytes());
    closure.verify(GROUP, |id, head| Policy.resolve_authority_key(id, head)).unwrap();
    // The one record: gating admission at once, outside every outward path.
    let (source, replacement): (String, Option<Vec<u8>>) =
        p.w.b
            .query_row(
                "SELECT source, replacement_checkpoint_hash FROM native_author_closure",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
    assert_eq!((source.as_str(), replacement), ("rotation", None));
    assert!(crate::native_closure::closures_for_export(&p.w.b, &group()).unwrap().is_empty());
    assert_eq!(
        crate::native_closure::effective_closed_cutoff(&p.w.b, &group(), &old_author)
            .unwrap()
            .map(|cutoff| cutoff.seq),
        Some(Some(AuthorSeq(1)))
    );
    let fence_tables: i64 =
        p.w.b
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'native_incarnation_fence'",
                [],
                |row| row.get(0),
            )
            .unwrap();
    assert_eq!(fence_tables, 0, "the fence table is replaced by the closure evidence store");
}

#[test]
fn author_closure_is_not_cleared_by_install() {
    assert!(PRESERVED_BY_INSTALL.contains(&"native_author_closure"));
    assert!(!CLEARED_BY_INSTALL.contains(&"native_author_closure"));
}

#[test]
fn rebootstrap_without_authority_never_signs_a_closure() {
    let p = preserved_scenario(&Writer);
    let fs_root = FsRoot::new(p.root.path());

    install_signing_with(&p.w.b, p.recovery_root.path(), &fs_root, None).unwrap();

    assert!(crate::native_closure::all_closures(&p.w.b, &group()).unwrap().is_empty());
}

#[test]
fn an_existing_closure_row_survives_the_install() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    // A closure of another device's old incarnation, verified before the rebootstrap.
    let other = incarnation_of("device-c", 9);
    let seed = device_seed("device-c");
    let closure = closure_signed(&other, None, seed, "device-c", seed);
    crate::native_closure::store_bundle_closure(&w.b, &group(), &closure, [3; 32], &Policy)
        .unwrap();
    let recovery_root = private_tempdir();
    let root = tempfile::tempdir().unwrap();
    let setup = Setup { authority: &Writer, ..Setup::default() };
    begin_custom(&w.b, built(&w.sealer), recovery_root.path(), &setup, &mut no_hook).unwrap();

    install(&w.b, recovery_root.path(), &FsRoot::new(root.path())).unwrap();

    let held = crate::native_closure::all_closures(&w.b, &group()).unwrap();
    assert!(held.contains(&closure), "the install cleared a verified closure");
}

// --- bounded-memory file content -------------------------------------------------------------------

/// Forces a tiny I/O buffer for the thread, so small files cross buffer boundaries.
struct TinyChunk;
impl TinyChunk {
    fn of(size: usize) -> Self {
        crate::native_rebootstrap_recovery::IO_CHUNK_OVERRIDE.with(|c| c.set(Some(size)));
        Self
    }
}
impl Drop for TinyChunk {
    fn drop(&mut self) {
        crate::native_rebootstrap_recovery::IO_CHUNK_OVERRIDE.with(|c| c.set(None));
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(131) ^ (i >> 2)) as u8).collect()
}

#[test]
fn observing_a_file_hashes_it_identically_at_every_buffer_boundary() {
    const CHUNK: usize = 8;
    let _tiny = TinyChunk::of(CHUNK);
    let dir = tempfile::tempdir().unwrap();
    for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 5 * CHUNK + 3] {
        let bytes = pattern(len);
        let path = dir.path().join(format!("f{len}"));
        fs::write(&path, &bytes).unwrap();
        let observed =
            crate::native_rebootstrap_install::observe_regular_file(fs::File::open(&path).unwrap())
                .unwrap();
        let Observed::File { size, sha256, .. } = observed else { panic!("{observed:?}") };
        assert_eq!(size, len as u64);
        assert_eq!(sha256, crate::native_rebootstrap_recovery::sha256(&bytes), "len {len}");
    }
}

/// The read-back of the preserved copies and the unchanged-original path run through the
/// forced tiny buffer too.
#[cfg(unix)]
#[test]
fn an_unchanged_original_is_removed_through_a_tiny_buffer() {
    let _tiny = TinyChunk::of(1);
    let (p, _root) = install_over_x(&[2], 0o644, PRESERVED_MTIME);

    assert!(!p.root.path().join("x").exists());
    assert!(late_edits_of(&p.w.b).is_empty());
}

/// The version record of a saved late edit, read from its item directory.
fn late_record(
    p: &Preserved2,
    item: &RecoveryItem,
) -> yadorilink_replica_domain::file::FileVersion {
    let items_root = super::rebootstrap_preserve::items_root_of(p.recovery_root.path());
    let dir = crate::native_recovery_items::item_dir(&items_root, &group(), &item.item_id);
    yadorilink_replica_domain::file::FileVersion::from_canonical_encoding(
        &fs::read(dir.join("record.bin")).unwrap(),
    )
    .unwrap()
}

/// A late edit larger than several buffers is streamed into the item store: same bytes, and the
/// block descriptors of the ordinary fixed-size rule, through the real quarantine path.
#[test]
fn a_multi_chunk_late_edit_round_trips_through_the_quarantine() {
    let _tiny = TinyChunk::of(5);
    let p = preserved_scenario(&Viewer);
    let bytes = pattern(1013);
    fs::write(p.root.path().join("x"), &bytes).unwrap();

    install_with(&p.w.b, p.recovery_root.path(), &FsRoot::new(p.root.path()), &Viewer, &mut |_| {
        Ok(())
    })
    .unwrap();

    assert!(!p.root.path().join("x").exists());
    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(late_content(&p, &saved[0]), bytes);
    let record = late_record(&p, &saved[0]);
    let block_size = yadorilink_local_storage::block_size_for(bytes.len() as u64);
    let expected: Vec<_> = bytes
        .chunks(block_size)
        .map(|c| yadorilink_replica_domain::file::VersionBlock {
            hash: yadorilink_replica_domain::ids::BlockHash(
                crate::native_rebootstrap_recovery::sha256(c).to_vec(),
            ),
            size: c.len() as u32,
        })
        .collect();
    assert_eq!(record.blocks, expected);
    assert_eq!(record.size, bytes.len() as u64);
    let items = quarantined_items(&p.w.b, &group(), None).unwrap();
    assert_eq!(
        items[0].status,
        QuarantineStatus::RemovedLateEdit {
            sha256: crate::native_rebootstrap_recovery::sha256(&bytes)
        }
    );
}

/// How a root's file stream misbehaves.
#[derive(Clone, Copy)]
enum Fault {
    /// A read error after this many bytes.
    ErrorAfter(usize),
    /// The file's bytes differ from what was observed (a save between observing and copying).
    OtherBytes,
}

struct FaultyRoot<'a>(FsRoot<'a>, Fault);
struct FaultyStream {
    inner: fs::File,
    read: usize,
    fault: Fault,
}
impl std::io::Read for FaultyStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.fault {
            Fault::ErrorAfter(limit) => {
                if self.read >= limit {
                    return Err(std::io::Error::other("injected read error"));
                }
                let room = buf.len().min(limit - self.read);
                let n = self.inner.read(&mut buf[..room])?;
                self.read += n;
                Ok(n)
            }
            Fault::OtherBytes => {
                let n = self.inner.read(buf)?;
                buf[..n].iter_mut().for_each(|b| *b ^= 1);
                Ok(n)
            }
        }
    }
}
impl QuarantineRoot for FaultyRoot<'_> {
    fn observe(&self, path: &str) -> Result<Observed, String> {
        self.0.observe(path)
    }
    fn open_file(&self, path: &str) -> Result<Box<dyn std::io::Read>, String> {
        let inner = fs::File::open(self.0.dir.join(path)).map_err(|e| e.to_string())?;
        Ok(Box::new(FaultyStream { inner, read: 0, fault: self.1 }))
    }
    fn remove(&self, path: &str, expected: &Observed, claim: &str) -> Result<Removal, String> {
        self.0.remove(path, expected, claim)
    }
    fn release_claim(&self, path: &str, claim: &str) -> Result<(), String> {
        self.0.release_claim(path, claim)
    }
}

/// Fail closed: a file that cannot be read in full, or is not what was observed, stays where it
/// is, nothing is registered for it, and the install is blocked; a healthy retry then saves it.
#[test]
fn a_failure_while_streaming_a_late_edit_keeps_the_original_and_blocks() {
    let _tiny = TinyChunk::of(5);
    for fault in [Fault::ErrorAfter(0), Fault::ErrorAfter(500), Fault::OtherBytes] {
        let p = preserved_scenario(&Viewer);
        let bytes = pattern(1013);
        fs::write(p.root.path().join("x"), &bytes).unwrap();
        let faulty = FaultyRoot(FsRoot::new(p.root.path()), fault);

        let blocked =
            install_with(&p.w.b, p.recovery_root.path(), &faulty, &Viewer, &mut |_| Ok(()));

        assert!(
            matches!(
                blocked,
                Err(InstallError::Blocked(BlockedReason::PreservationFailed(
                    PreservationFailure::Io { .. }
                )))
            ),
            "{blocked:?}"
        );
        assert_eq!(fs::read(p.root.path().join("x")).unwrap(), bytes, "the original was lost");
        assert!(late_edits_of(&p.w.b).is_empty(), "an item was registered");
        let items = quarantined_items(&p.w.b, &group(), None).unwrap();
        assert!(
            !matches!(items[0].status, QuarantineStatus::RemovedLateEdit { .. }),
            "{:?}",
            items[0].status
        );

        install_with(
            &p.w.b,
            p.recovery_root.path(),
            &FsRoot::new(p.root.path()),
            &Viewer,
            &mut |_| Ok(()),
        )
        .unwrap();
        let saved = late_edits_of(&p.w.b);
        assert_eq!(saved.len(), 1);
        assert_eq!(late_content(&p, &saved[0]), bytes);
    }
}

/// The original is moved aside, the user's newer save lands in the moved object, and the
/// process dies before the verification. The path is absent, but the moved object is owned by the
/// quarantine row: the resume gives it back and keeps its bytes as a late edit instead of
/// accepting the earlier item and leaving the newer bytes under an unrecorded name.
#[test]
fn a_crash_after_the_move_aside_never_loses_the_newer_bytes_of_the_moved_object() {
    let p = preserved_scenario(&Viewer);
    fs::write(p.root.path().join("x"), b"first late edit").unwrap();
    let write_newer = |aside: &Path| fs::write(aside, b"newer bytes after the move").unwrap();
    let crashing = FsRoot::writing_after_move(p.root.path(), &write_newer);
    crashing.crash_after_move.set(true);
    let crashed = install_with(&p.w.b, p.recovery_root.path(), &crashing, &Viewer, &mut |_| Ok(()));
    assert!(matches!(crashed, Err(InstallError::Blocked(_))), "{crashed:?}");
    assert!(!p.root.path().join("x").exists());

    install_with(&p.w.b, p.recovery_root.path(), &FsRoot::new(p.root.path()), &Viewer, &mut |_| {
        Ok(())
    })
    .unwrap();

    let mut contents: Vec<Vec<u8>> =
        late_edits_of(&p.w.b).iter().map(|item| late_content(&p, item)).collect();
    contents.sort();
    assert_eq!(contents, vec![b"first late edit".to_vec(), b"newer bytes after the move".to_vec()]);
    let leftovers: Vec<_> = fs::read_dir(p.root.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".quarantining"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// A resume that finds the path taken again while the claimed object is still aside blocks
/// rather than choosing between the two.
#[test]
fn a_claimed_object_whose_path_is_occupied_again_blocks_the_resume() {
    let p = preserved_scenario(&Viewer);
    fs::write(p.root.path().join("x"), b"first late edit").unwrap();
    let crashing = FsRoot::new(p.root.path());
    crashing.crash_after_move.set(true);
    install_with(&p.w.b, p.recovery_root.path(), &crashing, &Viewer, &mut |_| Ok(())).unwrap_err();
    fs::write(p.root.path().join("x"), b"saved again").unwrap();

    let resumed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &FsRoot::new(p.root.path()),
        &Viewer,
        &mut |_| Ok(()),
    );

    assert!(matches!(resumed, Err(InstallError::Blocked(_))), "{resumed:?}");
    assert_eq!(fs::read(p.root.path().join("x")).unwrap(), b"saved again");
}

/// A symlink target that is not UTF-8 is observed and saved as its exact bytes.
#[cfg(unix)]
#[test]
fn a_non_utf8_symlink_target_is_observed_and_kept_byte_for_byte() {
    use std::os::unix::ffi::OsStrExt;
    let p = preserved_scenario(&Viewer);
    let target = [b'e', 0xff, 0xfe, b'x'];
    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&target), p.root.path().join("x"))
        .unwrap();
    let fs_root = FsRoot::new(p.root.path());
    assert_eq!(fs_root.observe("x").unwrap(), Observed::Symlink { target: target.to_vec() });
    install_with(&p.w.b, p.recovery_root.path(), &fs_root, &Viewer, &mut |_| Ok(())).unwrap();
    super::rebootstrap_replay::complete_machine(
        &p.w.b,
        p.recovery_root.path(),
        &p.preserved.recovery_id,
        &Viewer,
    );
    fs::remove_dir_all(&p.preserved.dir).unwrap();

    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(late_content(&p, &saved[0]), target);
}

/// A program that opened the file for writing before the move writes after the moved object was
/// verified. Its bytes must stay reachable: no platform can fence such a writer, so the object is
/// not unlinked, it stays under its claim (the row records that) and the install completes.
#[test]
fn a_write_through_a_handle_opened_before_the_move_lands_after_verification_and_is_kept() {
    use std::io::{Seek, Write};
    let p = preserved_scenario(&Viewer);
    let path = p.root.path().join("x");
    fs::write(&path, b"first late edit").unwrap();
    let external = fs::OpenOptions::new().write(true).open(&path).unwrap();
    let write_newer = |_aside: &Path| {
        let mut handle = &external;
        handle.rewind().unwrap();
        handle.write_all(b"NEWER bytes written after the verification").unwrap();
        handle.sync_all().unwrap();
    };
    let root = FsRoot::writing_before_unlink(p.root.path(), &write_newer);

    install_with(&p.w.b, p.recovery_root.path(), &root, &Viewer, &mut |_| Ok(())).unwrap();

    assert!(!path.exists());
    let retained = retained_objects(p.root.path());
    assert_eq!(retained.len(), 1, "{retained:?}");
    assert_eq!(fs::read(&retained[0]).unwrap(), b"NEWER bytes written after the verification");
    // The external program keeps writing; it still reaches the retained object.
    {
        let mut handle = &external;
        handle.rewind().unwrap();
        handle.write_all(b"AND LATER STILL").unwrap();
    }
    assert!(fs::read(&retained[0]).unwrap().starts_with(b"AND LATER STILL"));
    let items = quarantined_items(&p.w.b, &group(), None).unwrap();
    assert_eq!(items[0].status, QuarantineStatus::Retained);
    let claim: Option<String> =
        p.w.b
            .query_row("SELECT removal_claim FROM native_rebootstrap_quarantine", [], |r| r.get(0))
            .unwrap();
    assert!(claim.is_some(), "a retained object must stay owned by its row");

    // Finishing the rebootstrap clears its bookkeeping, but not the record of a retained object.
    super::rebootstrap_replay::complete_machine(
        &p.w.b,
        p.recovery_root.path(),
        &p.preserved.recovery_id,
        &Viewer,
    );
    let rows: i64 =
        p.w.b
            .query_row(
                "SELECT COUNT(*) FROM native_rebootstrap_quarantine WHERE status = 'retained' \
             AND removal_claim IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(rows, 1, "the retained object lost its owner when the rebootstrap finished");
}

/// The process dies after a writer's bytes landed and the install was interrupted anywhere
/// between the removal and its record: the resume gives the retained object back and saves the
/// bytes as a late edit.
#[test]
fn a_crash_after_a_retained_removal_keeps_the_writers_bytes() {
    use std::io::{Seek, Write};
    let p = preserved_scenario(&Viewer);
    let path = p.root.path().join("x");
    fs::write(&path, b"first late edit").unwrap();
    let external = fs::OpenOptions::new().write(true).open(&path).unwrap();
    let write_newer = |_aside: &Path| {
        let mut handle = &external;
        handle.rewind().unwrap();
        handle.write_all(b"NEWER bytes before the crash!").unwrap();
        handle.sync_all().unwrap();
    };
    let root = FsRoot::writing_before_unlink(p.root.path(), &write_newer);
    let crashed = install_with(
        &p.w.b,
        p.recovery_root.path(),
        &root,
        &Viewer,
        &mut crash_on(InstallPoint::AfterOriginalRemoved(0)),
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)), "{crashed:?}");

    install_with(&p.w.b, p.recovery_root.path(), &FsRoot::new(p.root.path()), &Viewer, &mut |_| {
        Ok(())
    })
    .unwrap();

    let mut contents: Vec<Vec<u8>> =
        late_edits_of(&p.w.b).iter().map(|item| late_content(&p, item)).collect();
    contents.sort();
    let mut expected = vec![b"first late edit".to_vec(), b"NEWER bytes before the crash!".to_vec()];
    expected.sort();
    assert_eq!(contents, expected);
}

/// The crash falls exactly as the unlink begins (only where the platform grants the exclusion
/// that makes it): the object is still under its claim, the resume gives it back and removes it.
#[test]
fn a_crash_at_the_unlink_leaves_the_claimed_object_for_the_resume() {
    let p = preserved_scenario(&Viewer);
    fs::write(p.root.path().join("x"), b"first late edit").unwrap();
    let crashing = FsRoot::new(p.root.path());
    crashing.crash_before_unlink.set(true);
    let first = install_with(&p.w.b, p.recovery_root.path(), &crashing, &Viewer, &mut |_| Ok(()));
    assert!(first.is_err(), "{first:?}");
    install_with(&p.w.b, p.recovery_root.path(), &FsRoot::new(p.root.path()), &Viewer, &mut |_| {
        Ok(())
    })
    .unwrap();
    let saved = late_edits_of(&p.w.b);
    assert_eq!(saved.len(), 1);
    assert_eq!(late_content(&p, &saved[0]), b"first late edit");
}

fn retained_objects(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".quarantining"))
        .collect()
}

/// With no other program holding the object, it is unlinked where the platform can prove that
/// (Linux, Windows) and retained where it cannot (anywhere else); never lost either way.
#[test]
fn an_unheld_original_is_unlinked_only_where_the_platform_proves_no_writer() {
    let p = preserved_scenario(&Viewer);
    fs::write(p.root.path().join("x"), b"first late edit").unwrap();
    let nothing = |_: &Path| {};
    let real = FsRoot::writing_before_unlink(p.root.path(), &nothing);
    install_with(&p.w.b, p.recovery_root.path(), &real, &Viewer, &mut |_| Ok(())).unwrap();
    let kept = retained_objects(p.root.path());
    let items = quarantined_items(&p.w.b, &group(), None).unwrap();
    if cfg!(any(target_os = "linux", windows)) {
        assert!(kept.is_empty(), "{kept:?}");
        assert!(matches!(items[0].status, QuarantineStatus::RemovedLateEdit { .. }));
    } else {
        assert_eq!(kept.len(), 1);
        assert_eq!(items[0].status, QuarantineStatus::Retained);
    }
}

#[test]
fn unlink_exclusively_keeps_a_file_a_writer_still_holds_and_refuses_a_changed_one() {
    use std::io::{Seek, Write};
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("f");
    fs::write(&file_path, b"before").unwrap();
    let external = fs::OpenOptions::new().write(true).open(&file_path).unwrap();
    let expected = crate::native_rebootstrap_install::observe_regular_file(
        fs::File::open(&file_path).unwrap(),
    )
    .unwrap();
    let write = || {
        let mut handle = &external;
        handle.rewind().unwrap();
        handle.write_all(b"AFTER!").unwrap();
    };
    let unlinked = unlink_exclusively(
        &file_path,
        &expected,
        &open_excluding_writers,
        &write,
        &yadorilink_fs_platform::durable_dir::remove_file_durably,
    )
    .unwrap();
    assert_eq!(unlinked, Unlinked::Done(Removal::Retained));
    assert_eq!(fs::read(&file_path).unwrap(), b"AFTER!");

    // The file is not what was verified: nothing is unlinked.
    let unlinked =
        unlink_exclusively(&file_path, &expected, &open_excluding_writers, &|| {}, &|p| {
            fs::remove_file(p)
        })
        .unwrap();
    assert_eq!(unlinked, Unlinked::ChangedBeforeUnlink);
    assert!(file_path.exists());
}

/// The identity comparison before an unlink fails closed: an identity that cannot be read,
/// or a different object, is never "the same".
#[test]
fn the_name_check_fails_closed_when_an_identity_is_unreadable_or_different() {
    use crate::native_rebootstrap_install::{judge_identities, NameCheck};
    use yadorilink_fs_platform::fs_identity::FileIdentity;
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    fs::write(&a, b"one").unwrap();
    fs::write(&b, b"two").unwrap();
    let by_name = |p: &Path| FileIdentity::observe_path(p);
    let by_handle = |p: &Path| FileIdentity::observe_handle(&fs::File::open(p).unwrap());
    assert_eq!(judge_identities(by_name(&a), by_handle(&a)), NameCheck::Same);
    assert_eq!(judge_identities(by_name(&b), by_handle(&a)), NameCheck::Different);
    let unreadable = || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert_eq!(judge_identities(unreadable(), by_handle(&a)), NameCheck::Unverifiable);
    assert_eq!(judge_identities(by_name(&a), unreadable()), NameCheck::Unverifiable);
    assert_eq!(judge_identities(unreadable(), unreadable()), NameCheck::Unverifiable);
    // A name that no longer exists cannot be proved to be the verified object either.
    let held = fs::File::open(&a).unwrap();
    fs::remove_file(&a).unwrap();
    assert_ne!(crate::native_rebootstrap_install::name_check(&a, &held), NameCheck::Same);
}

/// The claimed name is swapped for another file between the verification and the unlink:
/// nothing is unlinked. On Windows the held handle shares delete, so the swap succeeds.
#[test]
fn a_name_swapped_after_the_verification_is_not_unlinked() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("f");
    fs::write(&file_path, b"verified").unwrap();
    let expected = crate::native_rebootstrap_install::observe_regular_file(
        fs::File::open(&file_path).unwrap(),
    )
    .unwrap();
    let swap = || {
        fs::rename(&file_path, dir.path().join("moved")).unwrap();
        fs::write(&file_path, b"someone else's").unwrap();
    };
    let unlinked = std::cell::Cell::new(false);
    let result = unlink_exclusively(&file_path, &expected, &open_excluding_writers, &swap, &|p| {
        unlinked.set(true);
        fs::remove_file(p)
    });
    if cfg!(any(unix, windows)) {
        // Where the platform refuses the exclusion the object is retained before the check.
        match result {
            Ok(Unlinked::Done(Removal::Retained)) => {}
            other => assert!(other.is_err(), "{other:?}"),
        }
        assert!(!unlinked.get(), "the swapped-in file must not be unlinked");
        assert_eq!(fs::read(&file_path).unwrap(), b"someone else's");
    }
}

// --- retained originals: listing and cleanup ----------------------------------------------------

mod retained {
    use super::*;
    use crate::native_rebootstrap_retained::{
        cleanup_retained, retained_originals, unlink_claimed_exclusively, ClaimedUnlink,
        RetainedContext, RetainedOutcome, RetainedRoot,
    };
    use std::io::{Seek, Write};

    struct RetainedFs<'a> {
        fs: FsRoot<'a>,
        /// A platform that grants the exclusion; off, the platform's real one (which an open
        /// writer defeats everywhere).
        assume_exclusion: bool,
    }

    impl RetainedRoot for RetainedFs<'_> {
        fn observe_claimed(&self, path: &str, claim: &str) -> Result<Observed, String> {
            self.fs.observe_at(&self.fs.aside(path, claim))
        }
        fn open_claimed(&self, path: &str, claim: &str) -> Result<Box<dyn std::io::Read>, String> {
            Ok(Box::new(fs::File::open(self.fs.aside(path, claim)).map_err(|e| e.to_string())?))
        }
        fn unlink_claimed(
            &self,
            path: &str,
            claim: &str,
            expected: &[u8; 32],
        ) -> Result<ClaimedUnlink, String> {
            let open = |p: &Path| -> std::io::Result<WriteExclusion> {
                if self.assume_exclusion {
                    Ok(WriteExclusion::assumed(fs::File::open(p)?))
                } else {
                    open_excluding_writers(p)
                }
            };
            unlink_claimed_exclusively(&self.fs.aside(path, claim), expected, &open, &|p| {
                fs::remove_file(p)
            })
        }
    }

    /// A finished rebootstrap that kept the original of `x` because a program holds it open for
    /// writing (the program is the returned handle).
    fn finished_with_a_retained_original() -> (Preserved2, fs::File) {
        let p = preserved_scenario(&Viewer);
        let path = p.root.path().join("x");
        fs::write(&path, b"first late edit").unwrap();
        let external = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let root = FsRoot::writing_before_unlink(p.root.path(), &|_: &Path| {});
        install_with(&p.w.b, p.recovery_root.path(), &root, &Viewer, &mut |_| Ok(())).unwrap();
        super::super::rebootstrap_replay::complete_machine(
            &p.w.b,
            p.recovery_root.path(),
            &p.preserved.recovery_id,
            &Viewer,
        );
        assert!(rebootstrap_status(&p.w.b, &group()).unwrap().is_none(), "the rebootstrap ended");
        (p, external)
    }

    fn cleanup(p: &Preserved2, assume_exclusion: bool) -> Vec<RetainedOutcome> {
        let root = RetainedFs { fs: FsRoot::new(p.root.path()), assume_exclusion };
        let items_root = super::super::rebootstrap_preserve::items_root_of(p.recovery_root.path());
        let ctx = RetainedContext {
            items_root: &items_root,
            sync_roots: &[],
            now_unix: 3000,
            root: &root,
        };
        cleanup_retained(&p.w.b, &ctx, &group()).unwrap().into_iter().map(|(_, o)| o).collect()
    }

    #[test]
    fn a_retained_original_is_listed_after_the_rebootstrap_finished() {
        let (p, _external) = finished_with_a_retained_original();
        let listed = retained_originals(&p.w.b, &group()).unwrap();
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0].path, "x");
        assert_eq!(listed[0].recovery_id, p.preserved.recovery_id);
        assert_eq!(retained_objects(p.root.path()).len(), 1);
    }

    #[test]
    fn an_unchanged_object_is_removed_only_under_a_proven_exclusion_and_the_row_cleared() {
        let (p, external) = finished_with_a_retained_original();
        // The program still holds the file open: the platform's own exclusion is refused.
        assert_eq!(cleanup(&p, false), vec![RetainedOutcome::StillRetained]);
        assert_eq!(retained_originals(&p.w.b, &group()).unwrap().len(), 1);
        assert_eq!(retained_objects(p.root.path()).len(), 1);
        drop(external);
        // Exclusion proved (a stand-in for a platform that grants it): removed, and idempotent.
        assert_eq!(cleanup(&p, true), vec![RetainedOutcome::Removed]);
        assert!(retained_objects(p.root.path()).is_empty());
        assert!(retained_originals(&p.w.b, &group()).unwrap().is_empty());
        assert!(cleanup(&p, true).is_empty());
    }

    #[test]
    fn changed_bytes_are_saved_as_a_recovery_item_before_the_object_is_removed() {
        let (p, external) = finished_with_a_retained_original();
        {
            let mut handle = &external;
            handle.rewind().unwrap();
            handle.write_all(b"NEWER bytes the program wrote").unwrap();
            handle.sync_all().unwrap();
        }
        let before = late_edits_of(&p.w.b).len();
        assert_eq!(cleanup(&p, true), vec![RetainedOutcome::PreservedChange { removed: true }]);
        let saved = late_edits_of(&p.w.b);
        assert_eq!(saved.len(), before + 1, "{saved:?}");
        assert!(saved.iter().any(|item| late_content(&p, item).starts_with(b"NEWER bytes")));
        assert!(retained_objects(p.root.path()).is_empty());
        assert!(retained_originals(&p.w.b, &group()).unwrap().is_empty());
    }

    #[test]
    fn changed_bytes_are_saved_once_when_the_exclusion_is_still_refused() {
        let (p, external) = finished_with_a_retained_original();
        {
            let mut handle = &external;
            handle.rewind().unwrap();
            handle.write_all(b"NEWER bytes the program wrote").unwrap();
            handle.sync_all().unwrap();
        }
        let before = late_edits_of(&p.w.b).len();
        assert_eq!(cleanup(&p, false), vec![RetainedOutcome::PreservedChange { removed: false }]);
        assert_eq!(late_edits_of(&p.w.b).len(), before + 1);
        assert_eq!(retained_objects(p.root.path()).len(), 1);
        // The object is still owned, and its new bytes are not saved a second time.
        assert_eq!(cleanup(&p, false), vec![RetainedOutcome::StillRetained]);
        assert_eq!(late_edits_of(&p.w.b).len(), before + 1);
        drop(external);
        assert_eq!(cleanup(&p, true), vec![RetainedOutcome::Removed]);
        assert_eq!(late_edits_of(&p.w.b).len(), before + 1);
    }

    #[test]
    fn a_row_without_a_recorded_digest_is_left_alone() {
        let (p, _external) = finished_with_a_retained_original();
        p.w.b.execute("DELETE FROM native_rebootstrap_retained_digest", []).unwrap();
        let outcomes = cleanup(&p, true);
        assert!(matches!(outcomes.as_slice(), [RetainedOutcome::Left(_)]), "{outcomes:?}");
        assert_eq!(retained_objects(p.root.path()).len(), 1);
        assert_eq!(retained_originals(&p.w.b, &group()).unwrap().len(), 1);
    }

    #[test]
    fn nothing_under_the_claim_clears_the_row() {
        let (p, external) = finished_with_a_retained_original();
        drop(external);
        for object in retained_objects(p.root.path()) {
            fs::remove_file(object).unwrap();
        }
        assert_eq!(cleanup(&p, true), vec![RetainedOutcome::Gone]);
        assert!(retained_originals(&p.w.b, &group()).unwrap().is_empty());
    }

    #[test]
    fn an_object_whose_recovery_item_was_discarded_is_saved_again_before_it_is_removed() {
        let (p, external) = finished_with_a_retained_original();
        drop(external);
        assert_eq!(late_edits_of(&p.w.b).len(), 1);
        p.w.b.execute("DELETE FROM native_recovery_item", []).unwrap();
        assert!(late_edits_of(&p.w.b).is_empty());
        assert_eq!(cleanup(&p, true), vec![RetainedOutcome::PreservedChange { removed: true }]);
        let saved = late_edits_of(&p.w.b);
        assert_eq!(saved.len(), 1, "{saved:?}");
        assert_eq!(late_content(&p, &saved[0]), b"first late edit");
        assert!(retained_objects(p.root.path()).is_empty());
    }

    #[test]
    fn a_name_that_leads_to_another_object_than_the_verified_one_is_not_unlinked() {
        let (p, external) = finished_with_a_retained_original();
        drop(external);
        let kept = retained_objects(p.root.path()).remove(0);
        let digest = crate::native_rebootstrap_retained::kept_fingerprint(
            &FsRoot::new(p.root.path()).observe_at(&kept).unwrap(),
        )
        .unwrap();
        let open = |path: &Path| -> std::io::Result<WriteExclusion> {
            let held = WriteExclusion::assumed(fs::File::open(path)?);
            // Between the verification and the unlink the name is given to another file.
            fs::rename(path, path.with_extension("moved"))?;
            fs::write(path, b"first late edit")?;
            Ok(held)
        };
        let result = unlink_claimed_exclusively(&kept, &digest, &open, &|p| fs::remove_file(p));
        assert!(result.is_err(), "{result:?}");
        assert!(kept.exists());
    }

    #[test]
    fn a_metadata_only_edit_is_saved_before_the_object_is_removed() {
        let (p, external) = finished_with_a_retained_original();
        drop(external);
        let kept = retained_objects(p.root.path()).remove(0);
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        fs::File::options().write(true).open(&kept).unwrap().set_modified(later).unwrap();
        let before = late_edits_of(&p.w.b).len();
        assert_eq!(cleanup(&p, true), vec![RetainedOutcome::PreservedChange { removed: true }]);
        assert_eq!(late_edits_of(&p.w.b).len(), before + 1);
        assert!(retained_objects(p.root.path()).is_empty());
    }
}
