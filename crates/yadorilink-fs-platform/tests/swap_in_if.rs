//! `swap_in_if`: replacing a name only while it still leads to the object the caller decided
//! to replace, with the check made on the object the exchange captured, so there is no moment
//! between the check and the replacement in which a save can be lost.
use std::fs;
use std::path::Path;

use yadorilink_fs_platform::durable_dir::{swap_in_if, SwapIn};

fn read(path: &Path) -> String {
    String::from_utf8(fs::read(path).unwrap()).unwrap()
}

fn retained_siblings(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("retained"))
        .collect()
}

#[test]
fn the_expected_object_is_replaced_and_the_staged_name_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();
    fs::write(&target, "old").unwrap();

    let outcome = swap_in_if(&staged, &target, &|captured| read(captured) == "old").unwrap();

    if outcome == SwapIn::Unsupported {
        return; // a file system without an exchange: the caller's checked rename stands in
    }
    assert_eq!(outcome, SwapIn::Replaced);
    assert_eq!(read(&target), "new");
    assert!(!staged.exists(), "the replaced object does not linger under the staged name");
    assert!(retained_siblings(dir.path()).is_empty(), "nothing is left beside the target");
}

#[test]
fn another_object_is_put_back_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();
    fs::write(&target, "the user's file").unwrap();

    let outcome = swap_in_if(&staged, &target, &|_| false).unwrap();

    if outcome == SwapIn::Unsupported {
        return;
    }
    assert_eq!(outcome, SwapIn::Refused);
    assert_eq!(read(&target), "the user's file");
    assert_eq!(read(&staged), "new", "the staged file is as it was");
}

/// A write through a handle the user already had open lands right after the exchange (on the
/// object now under the staged name): the verification sees it, the exchange is undone, and the
/// write is in the file under the target.
#[test]
fn a_write_through_an_open_handle_right_after_the_exchange_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();
    fs::write(&target, "old").unwrap();
    let handle = fs::OpenOptions::new().write(true).open(&target).unwrap();
    let moved_since = |captured: &Path| {
        use std::io::Write;
        (&handle).write_all(b"!").unwrap();
        (&handle).flush().unwrap();
        read(captured) == "old"
    };

    let outcome = swap_in_if(&staged, &target, &moved_since).unwrap();

    if outcome == SwapIn::Unsupported {
        return;
    }
    assert_eq!(outcome, SwapIn::Refused);
    assert_eq!(read(&target), "!ld", "the write is in the user's file");
    assert_eq!(read(&staged), "new");
}

/// A newer save replaces the replacement before the exchange can be undone: neither the saved
/// file nor the captured object is lost; the captured object is kept beside it.
#[test]
fn a_save_over_the_replacement_before_the_undo_keeps_both() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();
    fs::write(&target, "the first version").unwrap();
    let save = dir.path().join("editor-temp");
    let saved_over = |_captured: &Path| {
        fs::write(&save, "saved meanwhile").unwrap();
        fs::rename(&save, &target).unwrap();
        false
    };

    let outcome = swap_in_if(&staged, &target, &saved_over).unwrap();

    if outcome == SwapIn::Unsupported {
        return;
    }
    assert_eq!(outcome, SwapIn::Refused);
    assert_eq!(read(&target), "saved meanwhile");
    let kept = retained_siblings(dir.path());
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(read(&dir.path().join(&kept[0])), "the first version");
    assert!(!staged.exists());
}

/// The user edits the newly published file in place before the exchange can be undone: the
/// edit is theirs, so the file is not moved to the disposable staged name; the object that was
/// captured is kept beside it.
#[test]
fn an_edit_to_the_replacement_before_the_undo_is_kept_under_the_name() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();
    fs::write(&target, "the first version").unwrap();
    let edited_in_place = |_captured: &Path| {
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&target, "new, then the user's words").unwrap();
        false
    };

    let outcome = swap_in_if(&staged, &target, &edited_in_place).unwrap();

    if outcome == SwapIn::Unsupported {
        return;
    }
    assert_eq!(outcome, SwapIn::Refused);
    assert_eq!(read(&target), "new, then the user's words");
    let kept = retained_siblings(dir.path());
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(read(&dir.path().join(&kept[0])), "the first version");
    assert!(!staged.exists(), "the edited file is not left under the disposable name");
}

#[test]
fn a_missing_target_is_refused_and_nothing_moves() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();

    let outcome = swap_in_if(&staged, &target, &|_| true).unwrap();

    assert!(matches!(outcome, SwapIn::Refused | SwapIn::Unsupported), "{outcome:?}");
    assert!(!target.exists());
    assert_eq!(read(&staged), "new");
}

/// A read-only file the replacement was refused over is still read-only: the replace has to
/// clear the mark to go through, and putting the file back puts the mark back.
#[cfg(windows)]
#[test]
fn a_refused_read_only_target_stays_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();
    fs::write(&target, "the user's file").unwrap();
    let mut permissions = fs::metadata(&target).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&target, permissions).unwrap();

    let outcome = swap_in_if(&staged, &target, &|_| false).unwrap();

    assert_eq!(outcome, SwapIn::Refused);
    assert_eq!(read(&target), "the user's file");
    assert!(fs::metadata(&target).unwrap().permissions().readonly());
    assert_eq!(read(&staged), "new");
}

/// A read-only file that is replaced stays read-only: its mark travels to the new file.
#[cfg(windows)]
#[test]
fn a_replaced_read_only_target_keeps_its_mark() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();
    fs::write(&target, "old").unwrap();
    let mut permissions = fs::metadata(&target).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&target, permissions).unwrap();

    let outcome = swap_in_if(&staged, &target, &|captured| read(captured) == "old").unwrap();

    assert_eq!(outcome, SwapIn::Replaced);
    assert_eq!(read(&target), "new");
    assert!(fs::metadata(&target).unwrap().permissions().readonly());
}

/// A rename refuses to put a file over a directory; an exchange would not. A directory on either
/// side is left to the checked rename, so a person's directory is never turned into a file.
#[test]
fn a_directory_is_never_exchanged_with_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(target.join("child"), "x").unwrap();

    let outcome = swap_in_if(&staged, &target, &|_| true).unwrap();

    assert_eq!(outcome, SwapIn::Unsupported);
    assert_eq!(read(&target.join("child")), "x");
    assert_eq!(read(&staged), "new");

    let (staged_dir, file_target) = (dir.path().join("staged-dir"), dir.path().join("file"));
    fs::create_dir(&staged_dir).unwrap();
    fs::write(&file_target, "a file").unwrap();
    let outcome = swap_in_if(&staged_dir, &file_target, &|_| true).unwrap();
    assert_eq!(outcome, SwapIn::Unsupported);
    assert_eq!(read(&file_target), "a file");
}

/// `ReplaceFileW` follows a link to the file it points at, so a link on either side is left to
/// the checked rename, which replaces the name itself: the file a link points at is never
/// touched, and a dangling link is not "gone". (Windows only; skipped where the account may not
/// create symlinks.)
#[cfg(windows)]
#[test]
fn a_symlink_is_never_exchanged_by_replacing_the_file_it_points_at() {
    let dir = tempfile::tempdir().unwrap();
    let pointed_at = dir.path().join("pointed-at");
    fs::write(&pointed_at, "the pointed-at file").unwrap();
    let (staged, target) = (dir.path().join("staged"), dir.path().join("target"));
    fs::write(&staged, "new").unwrap();
    if std::os::windows::fs::symlink_file(&pointed_at, &target).is_err() {
        eprintln!("skipped: this account may not create symlinks");
        return;
    }

    let outcome = swap_in_if(&staged, &target, &|_| true).unwrap();

    assert_eq!(outcome, SwapIn::Unsupported);
    assert_eq!(read(&pointed_at), "the pointed-at file");
    assert_eq!(read(&staged), "new");
    assert!(fs::symlink_metadata(&target).unwrap().file_type().is_symlink());

    // A link that points at nothing is a link too.
    let dangling = dir.path().join("dangling");
    std::os::windows::fs::symlink_file(dir.path().join("nothing-here"), &dangling).unwrap();
    let outcome = swap_in_if(&staged, &dangling, &|_| true).unwrap();
    assert_eq!(outcome, SwapIn::Unsupported);
    assert!(fs::symlink_metadata(&dangling).unwrap().file_type().is_symlink());

    // A staged link is left to the checked rename as well.
    let (staged_link, file_target) = (dir.path().join("staged-link"), dir.path().join("file"));
    std::os::windows::fs::symlink_file(&pointed_at, &staged_link).unwrap();
    fs::write(&file_target, "a file").unwrap();
    let outcome = swap_in_if(&staged_link, &file_target, &|_| true).unwrap();
    assert_eq!(outcome, SwapIn::Unsupported);
    assert_eq!(read(&file_target), "a file");
}
