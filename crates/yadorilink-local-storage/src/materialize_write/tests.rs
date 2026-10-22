#![cfg(test)]

use super::*;
use std::sync::Mutex;
use yadorilink_fs_platform::fs_identity::{FileIdentity, ObjectKind};

/// One call the materializer made on its structural-directory ledger, and
/// what was on disk at the path when it made it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LedgerCall {
    /// `record_intent`, and whether anything was at the path already.
    Intent {
        path: String,
        existed: bool,
    },
    /// `complete`, and whether the identity it was handed is the
    /// directory now at the path.
    Complete {
        path: String,
        identity_is_the_directory_there: bool,
    },
    Abandon {
        path: String,
    },
    Interrupted {
        path: String,
    },
}

/// A ledger that records every call, against a root it can look at, and
/// can be told to act or fail at a chosen call.
/// A hook run inside `record_intent` for one path.
type IntentHook = Box<dyn Fn(&Path) + Send + Sync>;

#[derive(Default)]
struct RecordingLedger {
    root: Option<std::path::PathBuf>,
    calls: Mutex<Vec<LedgerCall>>,
    /// Runs inside `record_intent` for this path, after the call is
    /// recorded: what a user's `mkdir` racing the materializer's does.
    on_intent: Option<(String, IntentHook)>,
    fail_intent_for: Option<String>,
    fail_complete_for: Option<String>,
    panic_in_complete_for: Option<String>,
    /// The Stage names recorded for the directories it was asked to create.
    held: HeldLedger,
}

impl RecordingLedger {
    fn over(root: &Path) -> Self {
        Self { root: Some(root.to_path_buf()), ..Self::default() }
    }

    fn calls(&self) -> Vec<LedgerCall> {
        self.calls.lock().unwrap().clone()
    }

    fn at(&self, rel_path: &str) -> std::path::PathBuf {
        self.root.as_ref().expect("a ledger that looks at disk needs its root").join(rel_path)
    }
}

impl StructuralDirectoryLedger for RecordingLedger {
    fn names(&self) -> &dyn TempFileLedger {
        &self.held
    }

    fn record_intent(&self, rel_path: &str) -> Result<(), StorageError> {
        if self.fail_intent_for.as_deref() == Some(rel_path) {
            return Err(StorageError::Io(std::io::Error::other("injected intent failure")));
        }
        let existed = self.root.is_some() && fs::symlink_metadata(self.at(rel_path)).is_ok();
        self.calls.lock().unwrap().push(LedgerCall::Intent { path: rel_path.to_string(), existed });
        if let Some((path, hook)) = &self.on_intent {
            if path == rel_path {
                hook(&self.at(rel_path));
            }
        }
        Ok(())
    }

    fn complete(&self, rel_path: &str, identity: &FileIdentity) -> Result<(), StorageError> {
        let identity_is_the_directory_there = identity.object_kind == ObjectKind::Directory
            && self.root.is_some()
            && FileIdentity::observe_path(&self.at(rel_path))
                .is_ok_and(|now| now.object_id == identity.object_id);
        self.calls.lock().unwrap().push(LedgerCall::Complete {
            path: rel_path.to_string(),
            identity_is_the_directory_there,
        });
        if self.panic_in_complete_for.as_deref() == Some(rel_path) {
            panic!("injected panic between the mkdir and its completion");
        }
        if self.fail_complete_for.as_deref() == Some(rel_path) {
            return Err(StorageError::Io(std::io::Error::other("injected completion failure")));
        }
        Ok(())
    }

    fn abandon(&self, rel_path: &str) -> Result<(), StorageError> {
        self.calls.lock().unwrap().push(LedgerCall::Abandon { path: rel_path.to_string() });
        Ok(())
    }

    fn interrupted(&self, rel_path: &str) -> Result<(), StorageError> {
        self.calls.lock().unwrap().push(LedgerCall::Interrupted { path: rel_path.to_string() });
        Ok(())
    }
}

fn intent(path: &str) -> LedgerCall {
    LedgerCall::Intent { path: path.to_string(), existed: false }
}

fn completed(path: &str) -> LedgerCall {
    LedgerCall::Complete { path: path.to_string(), identity_is_the_directory_there: true }
}

/// Every directory the materializer creates for a descendant is bracketed
/// in the ledger: the intent is recorded while nothing is at the path
/// yet, and the completion carries the identity of the directory the
/// `mkdir` made. Ancestors that already exist are not claimed.
#[test]
fn materializer_mkdir_records_structural_origin_around_create() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("existing")).unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger::over(&canonical_root);

    let out_path = root.path().join("existing/a/b/file.txt");
    verify_write_target_within_root(&out_path, root.path(), &ledger).unwrap();

    assert!(root.path().join("existing/a/b").is_dir());
    assert_eq!(
        ledger.calls(),
        vec![
            intent("existing/a"),
            completed("existing/a"),
            intent("existing/a/b"),
            completed("existing/a/b"),
        ]
    );
}

/// Crash window 1: the intent could not be made durable. Nothing may be
/// created, or a directory would exist that no record says this device
/// made.
#[test]
fn a_structural_mkdir_whose_intent_fails_creates_nothing() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger {
        fail_intent_for: Some("a".to_string()),
        ..RecordingLedger::over(&canonical_root)
    };

    let result =
        verify_write_target_within_root(&root.path().join("a/f.txt"), root.path(), &ledger);

    assert!(result.is_err());
    assert!(!root.path().join("a").exists(), "no mkdir may run without a durable intent");
}

/// Crash window 2: the directory was created but its completion was not
/// recorded. The error surfaces (the write does not proceed as if the
/// origin were recorded) and the directory stays; the pending intent is
/// the ledger's to recover.
#[test]
fn a_structural_mkdir_whose_completion_fails_surfaces_the_error() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger {
        fail_complete_for: Some("a".to_string()),
        ..RecordingLedger::over(&canonical_root)
    };

    let result =
        verify_write_target_within_root(&root.path().join("a/b/f.txt"), root.path(), &ledger);

    assert!(result.is_err());
    assert!(root.path().join("a").is_dir());
    assert!(!root.path().join("a/b").exists(), "nothing below may be created past the failure");
    assert_eq!(
        ledger.calls(),
        vec![intent("a"), completed("a"), LedgerCall::Interrupted { path: "a".to_string() }],
        "a completion that fails leaves the intent to be resolved, not pending"
    );
}

/// A panic unwinding between the `mkdir` and its completion resolves the
/// intent on the way out: nothing is left pending for a sweep to age out.
#[test]
fn a_panic_between_mkdir_and_completion_resolves_the_intent() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger {
        panic_in_complete_for: Some("a".to_string()),
        ..RecordingLedger::over(&canonical_root)
    };

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = verify_write_target_within_root(&root.path().join("a/f.txt"), root.path(), &ledger);
    }));

    assert!(outcome.is_err());
    assert_eq!(ledger.calls().last(), Some(&LedgerCall::Interrupted { path: "a".to_string() }));
}

/// A user's `mkdir` of the same name between the intent and the
/// materializer's own `mkdir`: the materializer's `mkdir` finds the name
/// taken, so the directory there is not one it created, and it claims no
/// origin for it. It still goes on to create what is missing below.
#[test]
fn mkdir_eexist_race_with_user_mkdir_does_not_claim_origin() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger {
        on_intent: Some((
            "a".to_string(),
            Box::new(|path: &Path| fs::create_dir(path).expect("the user's mkdir")),
        )),
        ..RecordingLedger::over(&canonical_root)
    };

    verify_write_target_within_root(&root.path().join("a/b/f.txt"), root.path(), &ledger).unwrap();

    assert!(root.path().join("a/b").is_dir());
    assert_eq!(
        ledger.calls(),
        vec![
            intent("a"),
            LedgerCall::Abandon { path: "a".to_string() },
            intent("a/b"),
            completed("a/b"),
        ]
    );
}

/// An explicit directory's missing ancestors are structural and recorded;
/// the directory itself is the replicated entry and is not.
#[test]
fn an_explicit_directory_records_only_its_ancestors_as_structural() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger::over(&canonical_root);

    let created =
        create_explicit_directory(&canonical_root.join("a/b"), &canonical_root, &ledger).unwrap();

    assert_eq!(created, ExplicitDirectoryCreation::Created);
    assert!(root.path().join("a/b").is_dir());
    assert_eq!(ledger.calls(), vec![intent("a"), completed("a")]);

    let again =
        create_explicit_directory(&canonical_root.join("a/b"), &canonical_root, &ledger).unwrap();
    assert_eq!(again, ExplicitDirectoryCreation::AlreadyDirectory);
}

/// A file where the directory belongs is neither replaced nor followed.
#[test]
fn an_explicit_directory_over_a_file_is_refused_and_the_file_kept() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    fs::write(root.path().join("a"), b"a user's file").unwrap();

    let result = create_explicit_directory(
        &canonical_root.join("a"),
        &canonical_root,
        &RecordingLedger::over(&canonical_root),
    );

    assert!(matches!(
        result,
        Err(StorageError::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read(root.path().join("a")).unwrap(), b"a user's file");
}

#[test]
fn remove_empty_dir_removes_an_empty_directory() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("empty")).unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("empty")).unwrap(),
        crate::EmptyDirectoryRemoval::Removed
    );
    assert!(!root.path().join("empty").exists());
}

/// A directory holding anything -- here the OS junk every Finder
/// window leaves behind -- is never emptied on anyone's behalf.
#[test]
fn remove_empty_dir_keeps_a_directory_holding_os_junk_and_the_junk() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("a")).unwrap();
    fs::write(root.path().join("a/.DS_Store"), b"finder state").unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("a")).unwrap(),
        crate::EmptyDirectoryRemoval::NotEmpty
    );
    assert_eq!(fs::read(root.path().join("a/.DS_Store")).unwrap(), b"finder state");
}

#[test]
fn remove_empty_dir_reports_an_absent_path() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("gone")).unwrap(),
        crate::EmptyDirectoryRemoval::Absent
    );
}

#[test]
fn remove_empty_dir_never_removes_a_file() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("f"), b"x").unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("f")).unwrap(),
        crate::EmptyDirectoryRemoval::NotADirectory
    );
    assert!(root.path().join("f").exists());
}

/// A symlink to an empty directory is not a directory to remove: neither
/// the link nor its target is touched.
#[cfg(unix)]
#[test]
fn remove_empty_dir_never_follows_a_symlink() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("target")).unwrap();
    std::os::unix::fs::symlink(root.path().join("target"), root.path().join("link")).unwrap();
    assert_eq!(
        crate::remove_empty_dir(&root.path().join("link")).unwrap(),
        crate::EmptyDirectoryRemoval::NotADirectory
    );
    assert!(root.path().join("link").symlink_metadata().is_ok());
    assert!(root.path().join("target").is_dir());
}

/// `reconstruct_file_to_temp` + `persist_reconstructed_file` must
/// together produce exactly what the composed `reconstruct_file` always
/// did -- and, critically, the temp-write half alone must never touch
/// `out_path` at all, since a caller batching several paths' SQLite
/// commits relies on being able to run this half for many paths without
/// any of them becoming visible until the (separate, later) publish
/// half runs.
#[test]
fn reconstruct_file_to_temp_then_persist_matches_reconstruct_file() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = crate::SegmentBlockStore::new(store_dir.path()).unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("file.bin");
    let content: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    fs::write(&src_path, &content).unwrap();
    let blocks = crate::chunker::chunk_file(&store, &src_path).unwrap();

    let out_path = src_dir.path().join("reconstructed.bin");
    let tmp_path = reconstruct_file_to_temp(&store, &out_path, &blocks, -1).unwrap();

    assert!(!out_path.exists(), "the temp-write half must not touch out_path at all");
    assert!(tmp_path.exists());
    assert_eq!(fs::read(&tmp_path).unwrap(), content);

    persist_reconstructed_file(&tmp_path, &out_path).unwrap();

    assert!(!tmp_path.exists(), "the temp path must be gone after a successful publish");
    assert_eq!(fs::read(&out_path).unwrap(), content);
}

/// Where no native provider exists a `Remote` row has no local object: the
/// creation call writes nothing, records nothing and reports no object.
#[cfg(not(windows))]
#[test]
fn without_a_native_provider_no_object_is_written_or_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("placeholder.bin");

    let outcome = create_or_defer_placeholder(&out_path);

    assert_eq!(outcome, PlaceholderIdentityToRecord::Clear);
    assert!(!outcome.is_deferred_to_a_separate_process());
    assert!(!outcome.placed_an_object());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0, "nothing may be created");
}

/// An object already at the path is never touched by the creation call.
#[test]
fn an_existing_object_is_left_alone_by_placeholder_creation() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("occupied.bin");
    fs::write(&out_path, b"user bytes").unwrap();

    let _ = create_or_defer_placeholder(&out_path);

    assert_eq!(fs::read(&out_path).unwrap(), b"user bytes");
}

/// A deferred creation (Windows, or the test hook) writes NOTHING to disk
/// and mints a CfAPI generation to record only if absent.
#[test]
fn a_deferred_creation_writes_nothing_and_records_a_generation_if_absent() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("deferred.bin");
    set_test_force_deferred_placeholder_for_path(&out_path, true);

    let outcome = create_or_defer_placeholder(&out_path);
    set_test_force_deferred_placeholder_for_path(&out_path, false);

    assert!(!out_path.exists(), "creation is the provider's, not this call's");
    assert!(outcome.is_deferred_to_a_separate_process());
    assert!(matches!(
        outcome,
        PlaceholderIdentityToRecord::RecordIfAbsent {
            provider_kind: WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
            ..
        }
    ));
}

/// A re-create at the same path must not reuse a stale generation a live
/// CfAPI comparison could mistake for the old placeholder.
#[test]
fn successive_deferred_creations_mint_different_generations() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("deferred.bin");
    set_test_force_deferred_placeholder_for_path(&out_path, true);

    let first = create_or_defer_placeholder(&out_path);
    let second = create_or_defer_placeholder(&out_path);
    set_test_force_deferred_placeholder_for_path(&out_path, false);

    assert_ne!(first, second, "a re-deferred placeholder must mint a fresh generation");
}

/// `materialize_symlink` creates a real, correctly-targeted symlink at
/// `out_path`, atomically (via `random_tmp_path` + rename — no
/// partial/temp artifact left behind at the final path).
#[cfg(unix)]
#[test]
fn materialize_symlink_creates_a_real_symlink_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("link.txt");

    materialize_symlink(&out_path, b"../outside/target.txt").unwrap();

    let link_meta = fs::symlink_metadata(&out_path).unwrap();
    assert!(link_meta.file_type().is_symlink(), "must be a real symlink, not a regular file");
    assert_eq!(fs::read_link(&out_path).unwrap(), Path::new("../outside/target.txt"));
}

/// Re-materializing the same path (e.g. a re-sent index
/// update for an unchanged symlink record) must cleanly replace the
/// old link via the same atomic rename, not error on "already exists".
#[cfg(unix)]
#[test]
fn materialize_symlink_can_replace_an_existing_link_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("link.txt");

    materialize_symlink(&out_path, b"old-target.txt").unwrap();
    materialize_symlink(&out_path, b"new-target.txt").unwrap();

    assert_eq!(fs::read_link(&out_path).unwrap(), Path::new("new-target.txt"));
}

#[test]
fn stamp_mtime_at_path_actually_changes_disk_mtime() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.txt");
    fs::write(&path, b"content").unwrap();
    // A multiple of 100: Windows' FILETIME, and therefore `std::fs::
    // FileTimes`, only has 100ns resolution, so any other value would
    // round-trip through `stamp_mtime_at_path` as a different number there
    // and fail the exact-match assertion below for a reason unrelated to
    // what this test checks.
    let desired = 1_700_000_123_456_700i64;

    assert!(!mtime_already_matches_disk(&path, desired).unwrap());
    stamp_mtime_at_path(&path, desired).unwrap();
    assert!(mtime_already_matches_disk(&path, desired).unwrap());
}

/// A negative `desired_mtime_unix_nanos` (the "no authoritative
/// mtime to stamp" sentinel) is trivially satisfied regardless of
/// whatever the disk actually holds -- there is nothing to compare
/// against, mirroring `unix_mode_already_matches_disk`'s own
/// `unix_mode: None` treatment.
#[test]
fn mtime_already_matches_disk_is_trivially_true_for_a_negative_sentinel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.txt");
    fs::write(&path, b"content").unwrap();
    assert!(mtime_already_matches_disk(&path, -1).unwrap());
}

/// Changing the requested mode actually changes the on-disk permission
/// bits, and is idempotent (calling it again with the same value
/// doesn't error or otherwise misbehave). `None` is a deliberate no-op
/// — never fabricates a mode for a version that carries none.
#[cfg(unix)]
#[test]
fn apply_unix_mode_sets_and_clears_permission_bits() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("script.sh");
    fs::write(&path, b"#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    apply_unix_mode(&path, Some(0o744)).unwrap();
    let mode_after_set = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode_after_set & 0o777, 0o744, "owner-exec bit must be set");

    // Idempotent: setting it again when already set is a harmless no-op.
    apply_unix_mode(&path, Some(0o744)).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o744);

    apply_unix_mode(&path, Some(0o644)).unwrap();
    let mode_after_clear = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode_after_clear & 0o777, 0o644, "owner-exec bit must be cleared");

    // `None` is a no-op — the mode from the last real apply survives.
    apply_unix_mode(&path, None).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);
}

/// `apply_unix_mode` must never error on a plain file — this
/// runs unconditionally (not `#[cfg(unix)]`-gated) so the non-Unix
/// no-op arm is at least compiled and exercised on every platform this
/// crate builds for; on this dev machine it's the `#[cfg(unix)]`-arm's
/// real permission-changing behavior above that's exercised.
#[test]
fn apply_unix_mode_never_errors_on_a_plain_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.txt");
    fs::write(&path, b"hello").unwrap();
    apply_unix_mode(&path, Some(0o755)).unwrap();
    apply_unix_mode(&path, None).unwrap();
}

/// `create_dir_all(parent)` follows symlinks like any other `mkdir`
/// chain, so a symlink planted at an intermediate component (`escape ->
/// outside`) would let a naive directory-creation step create real
/// directories on the far side of it, entirely outside the sync root, before the `canonicalize`+
/// `starts_with` check that runs after it could ever refuse the
/// write. The `Err` result alone (already covered by
/// `materialize_symlink_at_refuses_a_root_whose_marker_no_longer_
/// matches`-style tests elsewhere) is not enough to prove this --
/// the whole point is that side effects outside the root must never
/// happen at all, error or not.
#[cfg(unix)]
#[test]
fn verify_write_target_within_root_creates_no_directories_through_an_escape_symlink() {
    let sync_root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), sync_root.path().join("escape")).unwrap();

    let out_path = sync_root.path().join("escape").join("a").join("b").join("pwned.txt");
    let result =
        verify_write_target_within_root(&out_path, sync_root.path(), &RecordingLedger::default());

    assert!(result.is_err(), "a write target reached only through a symlink must be refused");
    assert!(
        !outside.path().join("a").exists(),
        "no directory must ever be created on the far side of the escape symlink, \
         regardless of whether the write itself is correctly refused"
    );
}

/// The non-escaping case must keep working exactly as before: nested
/// directories that genuinely need creating under the real root are
/// still created, component by component, with no regression from
/// the old single `create_dir_all` call.
#[test]
fn verify_write_target_within_root_still_creates_genuine_nested_directories() {
    let sync_root = tempfile::tempdir().unwrap();
    let out_path = sync_root.path().join("a").join("b").join("c").join("file.txt");

    verify_write_target_within_root(&out_path, sync_root.path(), &RecordingLedger::default())
        .unwrap();

    assert!(sync_root.path().join("a").join("b").join("c").is_dir());
}

/// `apply_xattrs` must both set every attribute in the supplied list
/// AND remove any `user.*` attribute already on disk that the list no
/// longer carries -- the same "set exactly what's replicated, nothing
/// left over from a prior version" contract `apply_unix_mode` gives
/// for permission bits.
#[cfg(target_os = "linux")]
#[test]
fn apply_xattrs_sets_new_attributes_and_removes_stale_ones() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    apply_xattrs(&path, &[("user.keep".to_string(), b"v1".to_vec())]).unwrap();
    assert_eq!(
        crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()),
        vec![("user.keep".to_string(), b"v1".to_vec())]
    );

    // A later version drops "user.keep" and adds "user.new" -- the
    // stale attribute must not survive the second call.
    apply_xattrs(&path, &[("user.new".to_string(), b"v2".to_vec())]).unwrap();
    assert_eq!(
        crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()),
        vec![("user.new".to_string(), b"v2".to_vec())]
    );
}

/// An empty attribute list is a real, meaningful target state (this
/// version genuinely carries no extended attributes) -- confirms it
/// clears whatever was already on disk rather than being silently
/// treated as "nothing to do."
#[cfg(target_os = "linux")]
#[test]
fn apply_xattrs_with_an_empty_list_clears_existing_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    apply_xattrs(&path, &[("user.gone".to_string(), b"v".to_vec())]).unwrap();
    apply_xattrs(&path, &[]).unwrap();

    assert_eq!(crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()), Vec::new());
}

/// Regression: `apply_xattrs`'s removal side and its set side both
/// restrict themselves to `user.*`, rather than handing every incoming
/// name straight to `fsetxattr` -- defense-in-depth for the same
/// allow-list `FileMeta::decode` rejects a violation of at the wire-decode
/// boundary (a second, independent layer, in case some future caller
/// ever builds an `xattrs` list some other way). Confirmed genuinely
/// RED by temporarily hardcoding this to `true` for every name: it no
/// longer distinguished the allow-listed namespace from any other.
#[cfg(target_os = "linux")]
#[test]
fn is_replicated_xattr_name_only_accepts_the_user_namespace() {
    assert!(is_replicated_xattr_name("user.foo"));
    assert!(!is_replicated_xattr_name("security.selinux"));
    assert!(!is_replicated_xattr_name("trusted.overlay"));
    assert!(!is_replicated_xattr_name("system.posix_acl_access"));
    assert!(!is_replicated_xattr_name("com.apple.quarantine"));
}

/// The `ExactObject` proof gate's positive case: an attribute set
/// genuinely applied end to end verifies as an exact match.
#[cfg(target_os = "linux")]
#[test]
fn verify_replicated_xattrs_exact_confirms_a_genuine_match() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    let desired = vec![("user.a".to_string(), b"1".to_vec())];

    apply_xattrs(&path, &desired).unwrap();

    assert!(verify_replicated_xattrs_exact(&path, &desired).unwrap());
}

/// Regression: a desired attribute that never actually landed on disk (standing in
/// for `apply_xattrs`'s own `fsetxattr` silently failing, which it
/// never surfaces as an `Err`) must never verify as an exact match.
/// Confirmed genuinely RED by temporarily hardcoding this function's
/// comparison to `true`: the mismatch below went undetected.
#[cfg(target_os = "linux")]
#[test]
fn verify_replicated_xattrs_exact_detects_an_attribute_that_never_landed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    let desired = vec![("user.missing".to_string(), b"1".to_vec())];

    // No `apply_xattrs` call at all -- disk carries none of what is
    // desired, exactly what a silently-swallowed `fsetxattr` failure
    // would also leave behind.

    assert!(!verify_replicated_xattrs_exact(&path, &desired).unwrap());
}

/// The mirror case: a stale attribute still on disk that the desired
/// version no longer carries (standing in for `apply_xattrs`'s
/// `fremovexattr` silently failing) must also never verify as exact.
#[cfg(target_os = "linux")]
#[test]
fn verify_replicated_xattrs_exact_detects_a_stale_attribute_that_should_be_gone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    apply_xattrs(&path, &[("user.stale".to_string(), b"v".to_vec())]).unwrap();
    // The version this file is meant to now exactly hold desires no
    // attributes at all -- as if `apply_xattrs(&path, &[])`'s own
    // `fremovexattr` call for "user.stale" had silently failed.

    assert!(!verify_replicated_xattrs_exact(&path, &[]).unwrap());
}

/// A same-name attribute whose VALUE differs must also fail exactness
/// -- name-only comparison would wrongly accept this.
#[cfg(target_os = "linux")]
#[test]
fn verify_replicated_xattrs_exact_detects_a_value_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    apply_xattrs(&path, &[("user.a".to_string(), b"old".to_vec())]).unwrap();

    assert!(
        !verify_replicated_xattrs_exact(&path, &[("user.a".to_string(), b"new".to_vec())]).unwrap()
    );
}

/// The proof gate fails closed where the best-effort reader does not:
/// a file whose attribute listing succeeds but whose attribute read is
/// refused. The best-effort reader drops the attribute it could not
/// read, so a version that carries no attributes would compare equal to
/// a file that really does carry one; the strict comparison must be an
/// `Err` instead, never a match.
///
/// Listing a file's attribute names needs no permission on the file,
/// but reading a `user.` attribute's value needs read permission, so a
/// write-only descriptor on a mode 0o200 file reaches exactly that state
/// deterministically. The path-based `verify_replicated_xattrs_exact`
/// opens read-only and so cannot be driven there; the comparison it
/// delegates to is tested directly. A process that ignores file
/// permissions (root) cannot be refused the read, so the test has
/// nothing to check there and returns early.
#[cfg(target_os = "linux")]
#[test]
fn the_exact_xattr_comparison_fails_closed_where_the_best_effort_reader_sees_no_attributes() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    apply_xattrs(&path, &[("user.present".to_string(), b"v".to_vec())]).unwrap();
    assert!(verify_replicated_xattrs_exact(&path, &[("user.present".to_string(), b"v".to_vec())])
        .unwrap());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o200)).unwrap();
    if fs::File::open(&path).is_ok() {
        // Permissions are not enforced for this process: nothing to test.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }
    let write_only = fs::OpenOptions::new().write(true).open(&path).unwrap();

    let best_effort = crate::chunker::read_replicated_xattrs(&write_only);
    let strict = replicated_xattrs_exactly_match(&write_only, &[]);

    drop(write_only);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        best_effort.is_empty(),
        "precondition: the best-effort reader drops the attribute it cannot read: {best_effort:?}"
    );
    assert!(
        strict.is_err(),
        "an attribute set that could not be read must not compare as a match: {strict:?}"
    );
}

// The non-Linux `verify_replicated_xattrs_exact` arm (always
// `Ok(true)`, unconditionally treating xattrs as retained-only on a
// backend with no replicated-xattr support -- see its own doc
// comment for the target-projection-contract reasoning) is `#[cfg(not(
// target_os = "linux"))]`, so it never compiles on the Linux machines
// this workspace is actually developed/tested on and has no dedicated
// test here; it is now a single unconditional return with no branch
// left to exercise.

/// A replicated mode that takes the owner's read (or write) permission
/// away must not stop the replicated attributes from landing: the
/// attributes are applied while the file still has the mode it was
/// written with, and the mode last. Applying the mode first made
/// `apply_xattrs` fail with EACCES on a `0o200` file.
#[cfg(target_os = "linux")]
#[test]
fn apply_file_metadata_sets_attributes_even_when_the_mode_revokes_read() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    let xattrs = vec![("user.keep".to_string(), b"v1".to_vec())];

    apply_file_metadata(&path, Some(0o200), &xattrs).unwrap();

    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o200);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(crate::read_replicated_xattrs(&fs::File::open(&path).unwrap()), xattrs);
}

/// `xattrs_already_match_disk` only chooses between a snapshot and a
/// mutating attempt, so a file whose mode denies its owner read access is
/// "not known to match" -- never a hard error that stops the caller.
#[cfg(target_os = "linux")]
#[test]
fn xattrs_already_match_disk_reports_an_unreadable_file_as_not_matching() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o200)).unwrap();

    let result = xattrs_already_match_disk(&path, &[]);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(result, Ok(false)), "got {result:?}");
}

/// A ledger that remembers every name it was asked to hold.
#[derive(Default)]
struct HeldLedger {
    held: std::sync::Mutex<Vec<PathBuf>>,
    stranded: std::sync::Mutex<Vec<PathBuf>>,
    refuse: bool,
}
/// After a temp or Discard object was unlinked: Unix released its record; Windows documents no
/// durability for an unlink, so the record stays until a restart finds the path absent.
fn assert_record_after_an_unlink(ledger: &HeldLedger) {
    assert_eq!(ledger.held.lock().unwrap().len(), usize::from(cfg!(windows)));
}

impl TempFileLedger for HeldLedger {
    fn record(&self, tmp_path: &Path) -> Result<(), StorageError> {
        if self.refuse {
            return Err(StorageError::Io(std::io::Error::other("refused")));
        }
        self.held.lock().unwrap().push(tmp_path.to_path_buf());
        Ok(())
    }
    fn release(&self, tmp_path: &Path) {
        self.held.lock().unwrap().retain(|p| p != tmp_path);
    }
    fn strand(&self, dir_path: &Path) -> Result<(), StorageError> {
        if self.refuse {
            return Err(StorageError::Io(std::io::Error::other("refused")));
        }
        self.stranded.lock().unwrap().push(dir_path.to_path_buf());
        Ok(())
    }
}

/// A directory a durable removal could not put back is reported to the ledger
/// by the path it stands at, and the removal says `Stranded` with that path.
#[test]
fn a_stranded_directory_is_recorded_with_the_ledger() {
    let ledger = HeldLedger::default();
    let aside = PathBuf::from("/root/.d.discard");
    let outcome = crate::fs_ops::stranded(Path::new("/root/d"), aside.clone(), &ledger).unwrap();
    assert_eq!(outcome, crate::EmptyDirectoryRemoval::Stranded(aside.clone()));
    assert_eq!(*ledger.stranded.lock().unwrap(), [aside]);
}

/// A directory moved aside whose removal failed is stranded only if it still
/// holds something (or cannot be read).
#[test]
fn a_moved_aside_directory_counts_as_stranded_only_if_it_holds_something() {
    let root = tempfile::tempdir().unwrap();
    let (empty, full) = (root.path().join("empty"), root.path().join("full"));
    fs::create_dir(&empty).unwrap();
    fs::create_dir(&full).unwrap();
    fs::write(full.join("late"), b"x").unwrap();
    assert!(!crate::fs_ops::holds_entries_or_unreadable(&empty));
    assert!(crate::fs_ops::holds_entries_or_unreadable(&full));
    assert!(crate::fs_ops::holds_entries_or_unreadable(&root.path().join("gone")));
}

/// A removal that cannot record the directory it stranded fails rather than
/// reporting a state nobody can see.
#[test]
fn a_stranded_directory_that_cannot_be_recorded_is_an_error() {
    let ledger = HeldLedger { refuse: true, ..Default::default() };
    let outcome =
        crate::fs_ops::stranded(Path::new("/root/d"), PathBuf::from("/root/.d.discard"), &ledger);
    assert!(outcome.is_err());
}

/// The record is made before the file exists and is released with the file on
/// every exit: a failed assembly leaves neither.
#[test]
fn a_failed_assembly_removes_its_temp_file_and_its_record() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = crate::SegmentBlockStore::new(store_dir.path()).unwrap();
    let missing = vec![BlockInfo { hash: vec![7; 32], offset: 0, size: 4 }];
    let ledger = HeldLedger::default();

    let result = reconstruct_file_to_temp_in(&store, &dir.path().join("f"), &missing, 0, &ledger);

    assert!(result.is_err());
    assert_record_after_an_unlink(&ledger);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// A name that could not be made durable is never created.
#[test]
fn a_refused_record_creates_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = crate::SegmentBlockStore::new(store_dir.path()).unwrap();
    let ledger = HeldLedger { refuse: true, ..Default::default() };

    let result = reconstruct_file_to_temp_in(&store, &dir.path().join("f"), &[], 0, &ledger);

    assert!(result.is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// A rename that fails removes the temp file and releases its record.
#[test]
fn a_failed_publish_removes_the_temp_file_and_its_record() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = crate::SegmentBlockStore::new(store_dir.path()).unwrap();
    let ledger = HeldLedger::default();
    let out = dir.path().join("target");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("occupant"), b"x").unwrap();
    let tmp = reconstruct_file_to_temp_in(&store, &out, &[], 0, &ledger).unwrap();
    assert_eq!(ledger.held.lock().unwrap().len(), 1);

    assert!(persist_reconstructed_file_in(&tmp, &out, &ledger).is_err());

    assert!(!tmp.exists());
    assert_record_after_an_unlink(&ledger);
}

/// A temp file that cannot be removed keeps its record, so the next link
/// start tries again.
#[test]
fn a_failed_removal_keeps_the_record() {
    let dir = tempfile::tempdir().unwrap();
    let stuck = dir.path().join("stuck");
    std::fs::create_dir(&stuck).unwrap();
    let ledger = HeldLedger::default();
    ledger.record(&stuck).unwrap();

    discard_temp_file(&stuck, &ledger);

    assert_eq!(ledger.held.lock().unwrap().len(), 1);
}

/// A symlink is published only once its parent directory entry is durable: a
/// parent that cannot be flushed (write+search but not read, so it cannot be
/// opened to fsync) makes the publish an error instead of a silent success the
/// caller would record as present.
#[cfg(unix)]
#[test]
fn materialize_symlink_fails_when_the_parent_cannot_be_flushed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("unreadable");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).unwrap();
    if fs::read_dir(&parent).is_ok() {
        return; // running as root: permissions do not apply
    }

    let result = materialize_symlink(&parent.join("link"), b"target");

    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err(), "an unflushable parent must not report the link as published");
}

// --- publishing by a durable move ---------------------------------------------------------

fn staged_file(dir: &Path, name: &str, bytes: &[u8], ledger: &HeldLedger) -> PathBuf {
    let tmp = dir.join(name);
    ledger.record(&tmp).unwrap();
    fs::write(&tmp, bytes).unwrap();
    tmp
}

#[test]
fn a_reconstructed_file_is_published_by_a_durable_move_and_its_record_released() {
    use yadorilink_fs_platform::durable_dir::trace::{self, Event};
    let dir = tempfile::tempdir().unwrap();
    let (out, ledger) = (dir.path().join("f"), HeldLedger::default());
    fs::write(&out, b"old").unwrap();
    let tmp = staged_file(dir.path(), "f.yadorilink-tmp.1.1", b"new", &ledger);
    trace::take();

    persist_reconstructed_file_in(&tmp, &out, &ledger).unwrap();

    assert_eq!(fs::read(&out).unwrap(), b"new");
    assert!(!tmp.exists());
    assert!(ledger.held.lock().unwrap().is_empty());
    let steps = trace::take();
    assert!(
        steps
            .iter()
            .any(|e| matches!(e, Event::Move { from, to, .. } if *from == tmp && *to == out)),
        "{steps:?}"
    );
}

/// A kill right before the move leaves the old file and a recorded temp file; right
/// after it, the new file. Neither leaves the path without content.
#[test]
fn a_crash_around_the_publish_leaves_the_old_or_the_new_file() {
    use yadorilink_fs_platform::durable_dir::{arm_failpoint, disarm_failpoint, NsFailpoint};
    for (failpoint, expected, record_held) in
        [(NsFailpoint::BeforeMove, &b"old"[..], true), (NsFailpoint::AfterMove, b"new", true)]
    {
        let dir = tempfile::tempdir().unwrap();
        let (out, ledger) = (dir.path().join("f"), HeldLedger::default());
        fs::write(&out, b"old").unwrap();
        let tmp = staged_file(dir.path(), "f.yadorilink-tmp.1.1", b"new", &ledger);

        arm_failpoint(failpoint);
        let result = persist_reconstructed_file_in(&tmp, &out, &ledger);
        disarm_failpoint();

        assert!(result.is_err(), "{failpoint:?}");
        assert_eq!(fs::read(&out).unwrap(), expected, "{failpoint:?}");
        // The record is released only by a publish that finished: a restart
        // clears it, and nothing guesses from the name.
        assert_eq!(ledger.held.lock().unwrap().len(), usize::from(record_held), "{failpoint:?}");
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_is_published_by_a_durable_move() {
    use yadorilink_fs_platform::durable_dir::trace::{self, Event};
    let dir = tempfile::tempdir().unwrap();
    let (out, ledger) = (dir.path().join("l"), HeldLedger::default());
    trace::take();

    materialize_symlink_in(&out, b"target", &ledger).unwrap();

    assert!(fs::symlink_metadata(&out).unwrap().file_type().is_symlink());
    assert!(ledger.held.lock().unwrap().is_empty());
    let steps = trace::take();
    assert!(steps.iter().any(|e| matches!(e, Event::Move { to, .. } if *to == out)), "{steps:?}");
}

#[test]
fn directories_are_published_by_durable_moves_and_their_stage_names_released() {
    use yadorilink_fs_platform::durable_dir::trace::{self, Event};
    let root = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger::over(&canonical);
    let out = canonical.join("a/b/leaf");
    trace::take();

    let created = create_explicit_directory(&out, &canonical, &ledger).unwrap();

    assert_eq!(created, ExplicitDirectoryCreation::Created);
    assert!(out.is_dir());
    let published: Vec<PathBuf> = trace::take()
        .into_iter()
        .filter_map(|e| match e {
            Event::Move { to, .. } => Some(to),
            _ => None,
        })
        .collect();
    assert_eq!(published, [canonical.join("a"), canonical.join("a/b"), out.clone()]);
    assert_eq!(fs::read_dir(&canonical).unwrap().count(), 1, "no Stage name is left");
    assert!(ledger.held.held.lock().unwrap().is_empty(), "every Stage record was released");
}

/// A kill between a Stage directory and its publication leaves a recorded empty
/// directory and no directory at the name; the structural intent is resolved by
/// the writer leaving, as for any other failed `mkdir`.
#[test]
fn a_crash_between_the_stage_directory_and_its_publication_creates_nothing_visible() {
    use yadorilink_fs_platform::durable_dir::{arm_failpoint, disarm_failpoint, NsFailpoint};
    let root = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(root.path()).unwrap();
    let ledger = RecordingLedger::over(&canonical);

    arm_failpoint(NsFailpoint::AfterStage);
    let result = create_explicit_directory(&canonical.join("a/b"), &canonical, &ledger);
    disarm_failpoint();

    assert!(result.is_err());
    assert!(!canonical.join("a").exists());
    let leftovers: Vec<_> = fs::read_dir(&canonical).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    assert_eq!(*ledger.held.held.lock().unwrap(), leftovers, "a record names the Stage directory");
    assert!(
        !ledger.calls().iter().any(|c| matches!(c, LedgerCall::Complete { .. })),
        "nothing is claimed for a directory that was not published"
    );
}

#[test]
fn remove_durably_removes_a_file_and_a_gone_file_is_fine() {
    use yadorilink_fs_platform::durable_dir::trace;
    let dir = tempfile::tempdir().unwrap();
    let (file, ledger) = (dir.path().join("f"), HeldLedger::default());
    fs::write(&file, b"x").unwrap();
    trace::take();

    crate::remove_durably(&file, &ledger).unwrap();
    crate::remove_durably(&file, &ledger).unwrap();

    assert!(!file.exists());
    #[cfg(unix)]
    {
        use yadorilink_fs_platform::durable_dir::trace::Event;
        let steps = trace::take();
        assert!(
            matches!(steps.first(), Some(Event::Remove { path }) if *path == file),
            "{steps:?}"
        );
        assert!(steps.iter().any(|e| matches!(e, Event::FlushDir { .. })));
    }
    assert_record_after_an_unlink(&ledger);
}

#[test]
fn remove_durably_never_removes_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("d");
    fs::create_dir(&sub).unwrap();
    assert!(crate::remove_durably(&sub, &HeldLedger::default()).is_err());
    assert!(sub.is_dir());
}

#[test]
fn a_no_replace_move_is_durable_and_refuses_an_occupied_name() {
    use yadorilink_fs_platform::durable_dir::trace::{self, Event};
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    fs::write(&a, b"a").unwrap();
    fs::write(&b, b"b").unwrap();
    assert_eq!(
        crate::move_no_replace_durably(&a, &b).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&b).unwrap(), b"b");
    fs::remove_file(&b).unwrap();
    trace::take();

    crate::move_no_replace_durably(&a, &b).unwrap();

    assert_eq!(fs::read(&b).unwrap(), b"a");
    assert!(trace::take().iter().any(|e| matches!(e, Event::Move { to, .. } if *to == b)));
}

#[test]
fn remove_empty_dir_in_removes_only_what_is_empty() {
    use crate::{remove_empty_dir_in, EmptyDirectoryRemoval};
    let root = tempfile::tempdir().unwrap();
    let ledger = HeldLedger::default();
    fs::create_dir(root.path().join("empty")).unwrap();
    fs::create_dir(root.path().join("full")).unwrap();
    fs::write(root.path().join("full/child"), b"x").unwrap();
    assert_eq!(
        remove_empty_dir_in(&root.path().join("empty"), &ledger).unwrap(),
        EmptyDirectoryRemoval::Removed
    );
    assert_eq!(
        remove_empty_dir_in(&root.path().join("full"), &ledger).unwrap(),
        EmptyDirectoryRemoval::NotEmpty
    );
    assert!(root.path().join("full/child").exists());
    assert_eq!(
        remove_empty_dir_in(&root.path().join("empty"), &ledger).unwrap(),
        EmptyDirectoryRemoval::Absent
    );
}

#[test]
fn remove_durably_treats_a_missing_parent_as_already_removed() {
    let dir = tempfile::tempdir().unwrap();
    crate::remove_durably(&dir.path().join("gone/dir/file"), &HeldLedger::default()).unwrap();
}

/// A volume `DurableNamespace::open` refused (`Unsupported`, `Unknown`) is not turned into the
/// plain rename or `mkdir` a closed gate keeps: the visible target is left as it was.
mod a_refused_volume_fails_closed {
    use super::*;
    use yadorilink_fs_platform::durable_dir::UnavailableReason;

    fn refused(reason: UnavailableReason) -> impl Drop {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                crate::fs_ops::set_test_namespace_refusal(None);
            }
        }
        crate::fs_ops::set_test_namespace_refusal(Some(reason));
        Reset
    }

    const REASONS: [UnavailableReason; 2] =
        [UnavailableReason::Unsupported, UnavailableReason::Unknown];

    #[test]
    fn a_replacing_publish_keeps_the_old_bytes_and_creates_nothing_by_a_plain_rename() {
        for reason in REASONS {
            let dir = tempfile::tempdir().unwrap();
            let (out, ledger) = (dir.path().join("f"), HeldLedger::default());
            fs::write(&out, b"old").unwrap();
            let tmp = staged_file(dir.path(), "f.yadorilink-tmp.1.1", b"new", &ledger);
            let _refusal = refused(reason);
            assert!(persist_reconstructed_file_in(&tmp, &out, &ledger).is_err(), "{reason:?}");
            assert_eq!(fs::read(&out).unwrap(), b"old", "{reason:?}");
            // The documented contract: on any failure the temp object is removed and its record
            // released (Windows keeps the record of an unlink until a restart finds it absent).
            assert!(!tmp.exists(), "{reason:?}: the Stage temp leaked");
            assert_record_after_an_unlink(&ledger);
        }
    }

    #[test]
    fn a_new_name_is_not_created_by_a_plain_rename() {
        for reason in REASONS {
            let dir = tempfile::tempdir().unwrap();
            let (out, ledger) = (dir.path().join("f"), HeldLedger::default());
            let tmp = staged_file(dir.path(), "f.yadorilink-tmp.1.1", b"new", &ledger);
            let _refusal = refused(reason);
            assert!(persist_reconstructed_file_in(&tmp, &out, &ledger).is_err(), "{reason:?}");
            assert!(!out.exists(), "{reason:?}");
        }
    }

    #[test]
    fn a_directory_is_not_created() {
        for reason in REASONS {
            let dir = tempfile::tempdir().unwrap();
            let canonical_root = dir.path().canonicalize().unwrap();
            let target = canonical_root.join("d");
            let _refusal = refused(reason);
            let result =
                create_explicit_directory(&target, &canonical_root, &RecordingLedger::default());
            assert!(result.is_err(), "{reason:?}");
            assert!(!target.exists(), "{reason:?}");
        }
    }

    #[test]
    fn a_relative_path_with_no_relative_ancestor_is_not_created_by_a_plain_mkdir() {
        for reason in REASONS {
            let name = format!("yl-rel-refused-{}-{reason:?}", std::process::id());
            let relative = Path::new(&name).join("blocks");
            let _refusal = refused(reason);
            let result = crate::fs_ops::create_dir_all_durably(&relative);
            let created = relative.exists();
            let _ = fs::remove_dir_all(&name);
            assert!(result.is_err(), "{reason:?}");
            assert!(!created, "{reason:?}");
        }
    }

    #[test]
    fn a_removal_and_a_move_leave_their_objects() {
        for reason in REASONS {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("f");
            fs::write(&file, b"x").unwrap();
            let _refusal = refused(reason);
            assert!(crate::remove_durably(&file, &HeldLedger::default()).is_err(), "{reason:?}");
            assert!(file.exists(), "{reason:?}");
            assert!(
                crate::remove_empty_dir_in(dir.path(), &HeldLedger::default()).is_err(),
                "{reason:?}"
            );
            assert!(file.exists());
        }
    }
}

// ---- temp names: unpredictable, bounded, never over someone else's object ----

fn names_from(names: Vec<PathBuf>) -> impl FnMut(&Path) -> PathBuf {
    let mut names = names.into_iter();
    move |_| names.next().expect("more temp names asked for than the test supplied")
}

fn empty_store() -> (tempfile::TempDir, crate::SegmentBlockStore) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = crate::SegmentBlockStore::new(store_dir.path()).unwrap();
    (store_dir, store)
}

fn assemble_named(
    store: &crate::SegmentBlockStore,
    out_path: &Path,
    ledger: &dyn TempFileLedger,
    names: Vec<PathBuf>,
) -> Result<PathBuf, StorageError> {
    reconstruct_file_to_named_temp(store, out_path, &[], 0, ledger, &|_| {}, names_from(names))
}

/// A ledger that already holds some names for another writer.
#[derive(Default)]
struct SharedNamesLedger {
    others: Vec<PathBuf>,
    mine: Mutex<Vec<PathBuf>>,
    released: Mutex<Vec<PathBuf>>,
}

impl TempFileLedger for SharedNamesLedger {
    fn record(&self, tmp_path: &Path) -> Result<(), StorageError> {
        if self.others.iter().any(|p| p == tmp_path) {
            return Err(StorageError::Io(std::io::Error::from(std::io::ErrorKind::AlreadyExists)));
        }
        self.mine.lock().unwrap().push(tmp_path.to_path_buf());
        Ok(())
    }
    fn release(&self, tmp_path: &Path) {
        self.released.lock().unwrap().push(tmp_path.to_path_buf());
        self.mine.lock().unwrap().retain(|p| p != tmp_path);
    }
    fn strand(&self, _dir_path: &Path) -> Result<(), StorageError> {
        Ok(())
    }
}

#[test]
fn a_temp_name_is_fixed_length_unpredictable_and_still_reserved() {
    let a = random_tmp_path(Path::new("/r/short"));
    let b = random_tmp_path(Path::new(&format!("/r/{}", "n".repeat(255))));
    let (a_name, b_name) = (a.file_name().unwrap(), b.file_name().unwrap());
    assert_eq!(a_name.len(), b_name.len());
    assert!(a_name.len() < 64);
    assert_ne!(a_name, b_name);
    assert!(yadorilink_fs_platform::reserved_namespace::is_reserved_component(a_name));
    assert_eq!(a.parent(), Some(Path::new("/r")));
}

#[test]
fn names_of_240_and_255_bytes_materialize() {
    let (_s, store) = empty_store();
    for len in [240, 255] {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("a".repeat(len));
        reconstruct_file(&store, &out, &[], 0).unwrap();
        assert!(out.is_file(), "{len}-byte name");
        #[cfg(unix)]
        {
            let link = dir.path().join("l".repeat(len));
            materialize_symlink(&link, b"target").unwrap();
            assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        }
    }
}

#[test]
fn an_existing_file_at_the_temp_name_is_never_overwritten_or_removed() {
    let (_s, store) = empty_store();
    let dir = tempfile::tempdir().unwrap();
    let taken = dir.path().join(".yadorilink-tmp.taken");
    fs::write(&taken, b"someone else's").unwrap();
    let fresh = dir.path().join(".yadorilink-tmp.fresh");
    let ledger = SharedNamesLedger::default();

    let tmp =
        assemble_named(&store, &dir.path().join("f"), &ledger, vec![taken.clone(), fresh.clone()])
            .unwrap();

    assert_eq!(tmp, fresh);
    assert_eq!(fs::read(&taken).unwrap(), b"someone else's");
    // Only the record made for the occupied name was given back, never the file.
    assert_eq!(*ledger.released.lock().unwrap(), vec![taken]);
    assert_eq!(*ledger.mine.lock().unwrap(), vec![fresh]);
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_temp_name_is_not_followed() {
    let (_s, store) = empty_store();
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    fs::write(&victim, b"precious").unwrap();
    let absent = outside.path().join("never-created");
    let to_file = dir.path().join(".yadorilink-tmp.to-file");
    let dangling = dir.path().join(".yadorilink-tmp.dangling");
    std::os::unix::fs::symlink(&victim, &to_file).unwrap();
    std::os::unix::fs::symlink(&absent, &dangling).unwrap();
    let fresh = dir.path().join(".yadorilink-tmp.fresh");

    let tmp = assemble_named(
        &store,
        &dir.path().join("f"),
        &NoTempLedger,
        vec![to_file.clone(), dangling.clone(), fresh.clone()],
    )
    .unwrap();

    assert_eq!(tmp, fresh);
    assert_eq!(fs::read(&victim).unwrap(), b"precious");
    assert!(!absent.exists(), "a dangling link must not be created through");
    assert!(fs::symlink_metadata(&to_file).unwrap().file_type().is_symlink());
    assert!(fs::symlink_metadata(&dangling).unwrap().file_type().is_symlink());
}

#[cfg(unix)]
#[test]
fn a_symlink_materialization_does_not_replace_a_planted_temp_name() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    fs::write(&victim, b"precious").unwrap();
    let planted = dir.path().join(".yadorilink-tmp.planted");
    std::os::unix::fs::symlink(&victim, &planted).unwrap();
    let ledger = SharedNamesLedger::default();

    let created = create_recorded_tmp(
        &dir.path().join("l"),
        &ledger,
        names_from(vec![planted.clone(), dir.path().join(".yadorilink-tmp.fresh")]),
        |tmp| std::os::unix::fs::symlink("t", tmp),
    )
    .unwrap();

    assert_ne!(created.0, planted);
    assert_eq!(fs::read(&victim).unwrap(), b"precious");
    assert_eq!(fs::read_link(&planted).unwrap(), victim);
}

#[test]
fn a_name_the_ledger_holds_for_another_owner_is_skipped_and_never_released() {
    let (_s, store) = empty_store();
    let dir = tempfile::tempdir().unwrap();
    let held = dir.path().join(".yadorilink-tmp.held");
    let fresh = dir.path().join(".yadorilink-tmp.fresh");
    let ledger = SharedNamesLedger { others: vec![held.clone()], ..Default::default() };

    let tmp =
        assemble_named(&store, &dir.path().join("f"), &ledger, vec![held.clone(), fresh.clone()])
            .unwrap();

    assert_eq!(tmp, fresh);
    assert!(!held.exists(), "nothing is created at a name the ledger holds");
    assert!(
        ledger.released.lock().unwrap().is_empty(),
        "another owner's record is not ours to release"
    );
}

#[test]
fn running_out_of_unused_names_fails_closed_without_touching_anything() {
    let (_s, store) = empty_store();
    let dir = tempfile::tempdir().unwrap();
    let held = dir.path().join(".yadorilink-tmp.held");
    let ledger = SharedNamesLedger { others: vec![held.clone()], ..Default::default() };

    let result = reconstruct_file_to_named_temp(
        &store,
        &dir.path().join("f"),
        &[],
        0,
        &ledger,
        &|_| {},
        |_| held.clone(),
    );

    assert!(
        matches!(result, Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    assert!(ledger.released.lock().unwrap().is_empty());
}

/// A restart resets every counter the old scheme counted from, so the old
/// names were reused. Leftovers named that way are neither reused nor harmed.
#[test]
fn leftovers_named_by_the_old_scheme_survive_a_restart() {
    let (_s, store) = empty_store();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("f");
    let leftovers: Vec<PathBuf> = (0..64)
        .map(|n| dir.path().join(format!("f.yadorilink-tmp.{}.{n}", std::process::id())))
        .collect();
    for leftover in &leftovers {
        fs::write(leftover, b"left by a crash").unwrap();
    }

    for _ in 0..8 {
        let tmp = reconstruct_file_to_temp(&store, &out, &[], 0).unwrap();
        assert!(!leftovers.contains(&tmp));
        persist_reconstructed_file(&tmp, &out).unwrap();
    }
    for leftover in &leftovers {
        assert_eq!(fs::read(leftover).unwrap(), b"left by a crash");
    }
}

#[test]
fn concurrent_materializations_of_one_path_get_distinct_temp_files() {
    let (_s, store) = empty_store();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("f");
    let paths: Vec<PathBuf> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..16)
            .map(|_| scope.spawn(|| reconstruct_file_to_temp(&store, &out, &[], 0).unwrap()))
            .collect();
        workers.into_iter().map(|w| w.join().unwrap()).collect()
    });
    let distinct: std::collections::HashSet<_> = paths.iter().collect();
    assert_eq!(distinct.len(), 16);
    assert!(paths.iter().all(|p| p.is_file()));
}

/// A deferred write leaves the file in place and its temp name's record held
/// for the batch; the full write releases it as before.
#[cfg(unix)]
#[test]
fn a_deferred_publish_keeps_the_temp_record_for_the_batch() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = crate::SegmentBlockStore::new(store_dir.path()).unwrap();
    let hash = store.put(b"hello").unwrap();
    let blocks = vec![BlockInfo { hash: hex::decode(hash).unwrap(), offset: 0, size: 5 }];
    for (durability, held) in [(Durability::Full, 0), (Durability::DeferredToBatch, 1)] {
        let ledger = HeldLedger::default();
        let out = dir.path().join(format!("f{held}"));
        let tmp = reconstruct_file_to_temp_observed_durable(
            &store,
            &out,
            &blocks,
            0,
            &ledger,
            &|_| {},
            durability,
        )
        .unwrap();
        persist_reconstructed_file_durable(&tmp, &out, &ledger, durability).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"hello");
        assert!(!tmp.exists());
        assert_eq!(ledger.held.lock().unwrap().len(), held);
    }
}

#[cfg(unix)]
#[test]
fn the_batch_flush_answers_for_each_file() {
    use crate::{flush_received_files, ReceivedFlushMode, ReceivedFlushOutcome};
    let dir = tempfile::tempdir().unwrap();
    let kept = dir.path().join("kept");
    std::fs::write(&kept, b"x").unwrap();
    let gone = dir.path().join("gone");
    let failing = dir.path().join("flush-fails");
    std::fs::write(&failing, b"x").unwrap();
    let _fail = crate::fail_received_flushes_of("flush-fails");
    for mode in [ReceivedFlushMode::FullFsyncEach, ReceivedFlushMode::FsyncThenOneFullFsync] {
        let files = vec![kept.clone(), gone.clone(), failing.clone()];
        let outcomes = flush_received_files(&files, mode, 2);
        assert_eq!(outcomes[0], ReceivedFlushOutcome::Flushed);
        assert_eq!(outcomes[1], ReceivedFlushOutcome::Gone);
        assert!(matches!(outcomes[2], ReceivedFlushOutcome::Failed(_)));
    }
}

/// A file that vanished first in the batch does not fail the single drive
/// barrier for the files that are still there.
#[cfg(unix)]
#[test]
fn a_vanished_first_file_does_not_fail_the_single_barrier() {
    use crate::{flush_received_files, ReceivedFlushMode, ReceivedFlushOutcome};
    let dir = tempfile::tempdir().unwrap();
    let kept = dir.path().join("kept-after-gone");
    std::fs::write(&kept, b"x").unwrap();
    let files = vec![dir.path().join("vanished"), kept];
    let outcomes = flush_received_files(&files, ReceivedFlushMode::FsyncThenOneFullFsync, 2);
    assert_eq!(outcomes, vec![ReceivedFlushOutcome::Gone, ReceivedFlushOutcome::Flushed]);
}

/// A path that now names another object than the one received is not flushed
/// in its place.
#[cfg(unix)]
#[test]
fn the_batch_flush_refuses_another_object_at_the_path() {
    use crate::{flush_received_objects, object_key, ReceivedFlushMode, ReceivedFlushOutcome};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("received");
    std::fs::write(&path, b"x").unwrap();
    let key = object_key(&path);
    let outcomes = flush_received_objects(
        std::slice::from_ref(&path),
        &[key],
        ReceivedFlushMode::FullFsyncEach,
        1,
    );
    assert_eq!(outcomes, vec![ReceivedFlushOutcome::Flushed]);

    std::fs::rename(&path, dir.path().join("moved")).unwrap();
    std::fs::write(&path, b"someone else's").unwrap();
    let outcomes = flush_received_objects(
        std::slice::from_ref(&path),
        &[key],
        ReceivedFlushMode::FullFsyncEach,
        1,
    );
    assert!(matches!(outcomes[0], ReceivedFlushOutcome::Failed(_)), "{outcomes:?}");
}
