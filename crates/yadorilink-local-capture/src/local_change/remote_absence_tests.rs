#![cfg(test)]

//! A path's absence is delete evidence only for a `Present` object. A
//! `Remote` row has no local object by definition, so nothing missing from
//! the user tree says anything about it; `Hydrating` and `Evicting` rows are
//! in the middle of producing or removing the object. Only an explicit
//! delete by the user or a platform provider removes such an item.

use super::*;
use crate::test_support::TestReplica;
use std::sync::Arc;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::admission::LocalAuthorKey;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "remote-absence-group";

struct Fixture {
    proc: LocalChangeProcessor,
    state: Arc<TestReplica>,
    root: std::path::PathBuf,
    _store_dir: tempfile::TempDir,
    _root_dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(TestReplica::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&root.to_string_lossy(), GROUP).unwrap();
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
        let proc = LocalChangeProcessor::new(
            state.clone(),
            store,
            "device-a".into(),
            Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(Arc::new(LocalAuthorKey::for_tests(
            "device-a",
            ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]),
        )));
        let coordinator: &yadorilink_daemon::replica_coordinator::ReplicaCoordinator = &state;
        yadorilink_root_authority::root_identity::VerifiedRoot::open(&root, GROUP, coordinator)
            .unwrap();
        state
            .link_repository()
            .set_capture_volume_identity_for_group(
                GROUP,
                &yadorilink_filesystem_sync::device_boundary::root_volume_identity(&root).unwrap(),
            )
            .unwrap();
        Self { proc, state, root, _store_dir: store_dir, _root_dir: root_dir }
    }

    fn event(&self, path: &str, kind: FsChangeKind) -> FsChangeEvent {
        FsChangeEvent { path: self.root.join(path), kind }
    }

    /// `path` as this device has it: written, captured (a `Present` row).
    async fn captured(&self, path: &str) {
        std::fs::write(self.root.join(path), format!("content of {path}")).unwrap();
        self.proc
            .process_event(GROUP, &self.root, &self.event(path, FsChangeKind::CreatedOrModified))
            .await
            .unwrap();
        assert_eq!(self.materialization_state(path), Some(MaterializationState::Present));
    }

    fn set_state(&self, path: &str, state: MaterializationState) {
        self.state
            .materialization_state_repository()
            .set_materialization_state(GROUP, path, state, &RootCommitPermit::for_tests())
            .unwrap();
    }

    fn materialization_state(&self, path: &str) -> Option<MaterializationState> {
        self.state
            .materialization_state_repository()
            .get_materialization_state(GROUP, path)
            .unwrap()
    }

    fn remove(&self, path: &str) {
        std::fs::remove_file(self.root.join(path)).unwrap();
    }

    fn is_tombstoned(&self, path: &str) -> bool {
        self.state
            .file_index_repository()
            .get_file(GROUP, path)
            .unwrap()
            .is_some_and(|row| row.deleted)
    }

    /// The user's delete of `path` (as the provider reports it), begun and
    /// carried out at once.
    async fn semantic_delete(&self, path: &str) {
        let delete = self.proc.begin_semantic_delete(GROUP, &self.root, path).unwrap();
        self.proc.process_semantic_delete(GROUP, &self.root, &delete).await.unwrap();
    }

    async fn dir(&self, path: &str) {
        std::fs::create_dir(self.root.join(path)).unwrap();
        self.proc
            .process_event(GROUP, &self.root, &self.event(path, FsChangeKind::CreatedOrModified))
            .await
            .unwrap();
    }

    fn scan(&self) -> Vec<FileRecord> {
        self.proc.scan_existing_files(GROUP, &self.root).unwrap()
    }
}

/// A `Remote` row whose path holds nothing, with no intent and no unsettled
/// obligation, is not a deleted file: a full scan authors no tombstone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remote_row_with_no_object_is_not_tombstoned_by_a_full_scan() {
    let fx = Fixture::new();
    fx.captured("remote.txt").await;
    fx.set_state("remote.txt", MaterializationState::Remote);
    fx.remove("remote.txt");

    let records = fx.scan();

    assert!(
        !records.iter().any(|r| r.path == "remote.txt" && r.deleted),
        "the absence of a Remote row's object was read as a delete: {records:?}"
    );
    assert!(!fx.is_tombstoned("remote.txt"));
}

/// The row becomes `Remote` (an eviction lands) after the scan accepted the
/// path as a tombstone candidate and before its chunk commits: the final
/// re-verification, taken under the path lock, must veto it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_that_becomes_remote_before_the_tombstone_commits_is_not_tombstoned() {
    let fx = Fixture::new();
    fx.captured("racing.txt").await;
    fx.remove("racing.txt");
    {
        let state = fx.state.clone();
        scan_test_hooks::set_pre_chunk_commit_recheck_hook(Some(Arc::new(
            move |group: &str, path: &str| {
                if group == GROUP && path == "racing.txt" {
                    state
                        .materialization_state_repository()
                        .set_materialization_state(
                            GROUP,
                            path,
                            MaterializationState::Remote,
                            &RootCommitPermit::for_tests(),
                        )
                        .unwrap();
                }
            },
        )));
    }

    let records = fx.scan();
    scan_test_hooks::set_pre_chunk_commit_recheck_hook(None);

    assert!(
        !records.iter().any(|r| r.path == "racing.txt" && r.deleted),
        "a path that became Remote under the scan was tombstoned anyway: {records:?}"
    );
    assert!(!fx.is_tombstoned("racing.txt"));
}

/// The daemon's own eviction removes the object and then the watcher reports
/// the removal. The row is `Remote` by then, and the echo must not author a
/// delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_eviction_echo_on_a_remote_row_is_not_a_delete() {
    let fx = Fixture::new();
    fx.captured("evicted.txt").await;
    fx.set_state("evicted.txt", MaterializationState::Remote);
    fx.remove("evicted.txt");

    let outcome = fx
        .proc
        .process_event(GROUP, &fx.root, &fx.event("evicted.txt", FsChangeKind::ObservedRemoval))
        .await
        .unwrap();

    assert_eq!(outcome, LocalChangeOutcome::None, "the eviction echo authored something");
    assert!(!fx.is_tombstoned("evicted.txt"));
}

/// A platform provider's delete of an item that has no local object IS a
/// delete: the user removed the item, whatever its local state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_provider_delete_of_a_remote_item_tombstones_it() {
    let fx = Fixture::new();
    fx.captured("provider-deleted.txt").await;
    fx.set_state("provider-deleted.txt", MaterializationState::Remote);
    fx.remove("provider-deleted.txt");

    fx.semantic_delete("provider-deleted.txt").await;

    assert!(fx.is_tombstoned("provider-deleted.txt"), "an explicit delete was dropped");
}

/// The old behaviour that must stay: a `Present` file that is deleted is
/// tombstoned, by the watcher's event and by the scan alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_present_file_still_tombstones_it() {
    let fx = Fixture::new();
    fx.captured("by-event.txt").await;
    fx.captured("by-scan.txt").await;
    fx.remove("by-event.txt");
    fx.remove("by-scan.txt");

    fx.proc
        .process_event(GROUP, &fx.root, &fx.event("by-event.txt", FsChangeKind::ObservedRemoval))
        .await
        .unwrap();
    let records = fx.scan();

    assert!(fx.is_tombstoned("by-event.txt"), "the watcher's delete of a Present file was dropped");
    assert!(
        fx.is_tombstoned("by-scan.txt")
            || records.iter().any(|r| r.path == "by-scan.txt" && r.deleted),
        "the scan's delete of a Present file was dropped"
    );
}

/// A crash between `Evicting` and `Remote` leaves a row whose object may or
/// may not be gone. Neither the stranded `Evicting` row nor the `Remote` row
/// the startup reset turns it into is delete evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absence_after_a_crash_between_evicting_and_remote_is_not_evidence() {
    let fx = Fixture::new();
    fx.captured("crashed.txt").await;
    fx.set_state("crashed.txt", MaterializationState::Evicting);
    fx.remove("crashed.txt");

    let before_reset = fx.scan();
    assert!(!before_reset.iter().any(|r| r.path == "crashed.txt" && r.deleted), "{before_reset:?}");

    fx.state.materialization_state_repository().reset_stale_transients(&[], &[]).unwrap();
    assert_eq!(fx.materialization_state("crashed.txt"), Some(MaterializationState::Remote));
    let after_reset = fx.scan();

    assert!(!after_reset.iter().any(|r| r.path == "crashed.txt" && r.deleted), "{after_reset:?}");
    assert!(!fx.is_tombstoned("crashed.txt"));
}

/// An eager device stopped in the middle of its run holds rows whose objects
/// were never produced (`Remote`) or are being produced (`Hydrating`). On
/// restart none of them is a delete; a `Present` row whose object is gone
/// still is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_an_eager_device_had_not_materialized_yet_are_not_tombstoned_on_restart() {
    let fx = Fixture::new();
    for name in ["not-fetched.txt", "mid-fetch.txt", "was-present.txt"] {
        fx.captured(name).await;
        fx.remove(name);
    }
    fx.set_state("not-fetched.txt", MaterializationState::Remote);
    fx.set_state("mid-fetch.txt", MaterializationState::Hydrating);

    let records = fx.scan();

    let deleted: Vec<&str> =
        records.iter().filter(|r| r.deleted).map(|r| r.path.as_str()).collect();
    assert_eq!(deleted, vec!["was-present.txt"], "only the Present row's absence is evidence");
    assert!(!fx.is_tombstoned("not-fetched.txt"));
    assert!(!fx.is_tombstoned("mid-fetch.txt"));
}

/// A directory removed by the user takes with it what this device had on
/// disk under it. An entry that is `Remote` was never on disk here: nobody
/// removed it, and the directory's removal must not delete it for every
/// device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_directory_does_not_tombstone_its_remote_entries() {
    let fx = Fixture::new();
    std::fs::create_dir(fx.root.join("dir")).unwrap();
    fx.proc
        .process_event(GROUP, &fx.root, &fx.event("dir", FsChangeKind::CreatedOrModified))
        .await
        .unwrap();
    fx.captured("dir/present.txt").await;
    fx.captured("dir/remote.txt").await;
    fx.set_state("dir/remote.txt", MaterializationState::Remote);
    std::fs::remove_dir_all(fx.root.join("dir")).unwrap();

    fx.proc
        .process_event(GROUP, &fx.root, &fx.event("dir", FsChangeKind::ObservedRemoval))
        .await
        .unwrap();

    assert!(fx.is_tombstoned("dir/present.txt"), "a Present entry went with its directory");
    assert!(!fx.is_tombstoned("dir/remote.txt"), "a Remote entry was deleted with the directory");
}

/// A peer's newer version that changes only the mode (bytes identical) lands
/// over this device's own untouched write of the older version. The disk
/// still carries the older mode, but that is the daemon's own write, not a
/// chmod: neither the watcher's fast path nor the scan may author it as a
/// local metadata change over the newer version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_untouched_older_write_is_not_authored_as_a_metadata_only_edit() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let fx = Fixture::new();
    fx.captured("mode.sh").await;
    fx.state
        .file_index_repository()
        .set_unix_mode(GROUP, "mode.sh", Some(0o755), &RootCommitPermit::for_tests())
        .unwrap();
    assert!(
        crate::ports::LocalMutationStore::disk_is_untouched_proven_write(
            fx.state.as_ref(),
            GROUP,
            "mode.sh",
            &fx.root,
            &fx.root.join("mode.sh"),
        )
        .unwrap(),
        "setup: the capture's own proof must vouch for the object"
    );

    let by_event = fx
        .proc
        .process_event(GROUP, &fx.root, &fx.event("mode.sh", FsChangeKind::CreatedOrModified))
        .await
        .unwrap();
    let by_scan = fx.scan();

    assert_eq!(by_event, LocalChangeOutcome::None, "the watcher authored the older mode");
    assert!(
        !by_scan.iter().any(|r| r.path == "mode.sh"),
        "the scan authored the older mode over the newer version: {by_scan:?}"
    );
}

/// A platform provider's delete of a directory is a semantic delete of the
/// logical namespace under it, not an observation of what was on disk: every
/// descendant row goes, `Remote` ones included (the user saw them in the
/// provider's tree). The sibling test above, where the watcher observes the
/// directory vanish, must keep leaving `Remote` entries alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_delete_of_a_directory_tombstones_its_remote_entries_too() {
    let fx = Fixture::new();
    std::fs::create_dir(fx.root.join("dir")).unwrap();
    fx.proc
        .process_event(GROUP, &fx.root, &fx.event("dir", FsChangeKind::CreatedOrModified))
        .await
        .unwrap();
    fx.captured("dir/present.txt").await;
    fx.captured("dir/remote.txt").await;
    fx.set_state("dir/remote.txt", MaterializationState::Remote);
    std::fs::remove_dir_all(fx.root.join("dir")).unwrap();

    fx.semantic_delete("dir").await;

    assert!(fx.is_tombstoned("dir/present.txt"));
    assert!(fx.is_tombstoned("dir/remote.txt"), "the provider's delete skipped a Remote child");
    assert!(fx.is_tombstoned("dir"));
}

/// The delete covers what the user saw. A child a peer admitted after the
/// delete event, one whose version changed since, and a sibling directory that
/// merely shares the name as a prefix all survive; the children the delete did
/// see, `Remote` or `Present`, go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_semantic_directory_delete_is_bound_to_the_versions_it_saw() {
    let fx = Fixture::new();
    fx.dir("dir").await;
    fx.dir("dir2").await;
    fx.captured("dir/seen-present.txt").await;
    fx.captured("dir/seen-remote.txt").await;
    fx.captured("dir/changed-later.txt").await;
    fx.captured("dir2/sibling.txt").await;
    fx.set_state("dir/seen-remote.txt", MaterializationState::Remote);

    let delete = fx.proc.begin_semantic_delete(GROUP, &fx.root, "dir").unwrap();

    // After the delete event: a new child, and a new version of an old one.
    fx.captured("dir/admitted-later.txt").await;
    std::fs::write(fx.root.join("dir/changed-later.txt"), "a newer version from a peer").unwrap();
    fx.proc
        .process_event(
            GROUP,
            &fx.root,
            &fx.event("dir/changed-later.txt", FsChangeKind::CreatedOrModified),
        )
        .await
        .unwrap();
    std::fs::remove_dir_all(fx.root.join("dir")).unwrap();

    fx.proc.process_semantic_delete(GROUP, &fx.root, &delete).await.unwrap();

    assert!(fx.is_tombstoned("dir/seen-present.txt"));
    assert!(fx.is_tombstoned("dir/seen-remote.txt"), "a Remote child the user saw survived");
    assert!(fx.is_tombstoned("dir"));
    assert!(
        !fx.is_tombstoned("dir/admitted-later.txt"),
        "a child admitted after the delete event was deleted"
    );
    assert!(
        !fx.is_tombstoned("dir/changed-later.txt"),
        "a version the delete never saw was deleted"
    );
    assert!(!fx.is_tombstoned("dir2"), "a prefix sibling was deleted");
    assert!(!fx.is_tombstoned("dir2/sibling.txt"), "a prefix sibling's child was deleted");
}

/// The same bound holds for a single file: a version that arrived after the
/// delete event is not what the user deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_semantic_file_delete_spares_a_version_it_did_not_see() {
    let fx = Fixture::new();
    fx.captured("file.txt").await;
    let delete = fx.proc.begin_semantic_delete(GROUP, &fx.root, "file.txt").unwrap();
    std::fs::write(fx.root.join("file.txt"), "newer").unwrap();
    fx.proc
        .process_event(GROUP, &fx.root, &fx.event("file.txt", FsChangeKind::CreatedOrModified))
        .await
        .unwrap();
    fx.remove("file.txt");

    fx.proc.process_semantic_delete(GROUP, &fx.root, &delete).await.unwrap();

    assert!(!fx.is_tombstoned("file.txt"));
}

/// An OBSERVED removal of a directory spares its `Remote` children: only the
/// `Present` ones were seen going.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_observed_directory_removal_spares_remote_children() {
    let fx = Fixture::new();
    fx.dir("dir").await;
    fx.captured("dir/present.txt").await;
    fx.captured("dir/remote.txt").await;
    fx.set_state("dir/remote.txt", MaterializationState::Remote);
    std::fs::remove_dir_all(fx.root.join("dir")).unwrap();

    fx.proc
        .process_event(GROUP, &fx.root, &fx.event("dir", FsChangeKind::ObservedRemoval))
        .await
        .unwrap();

    assert!(fx.is_tombstoned("dir/present.txt"));
    assert!(!fx.is_tombstoned("dir/remote.txt"), "an observed removal deleted a Remote child");
}

/// A journaled removal is an observed one, across a restart: replaying the
/// journal deletes a `Present` path and leaves a `Remote` one alone, and the
/// stored kind round-trips.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_journaled_removal_replays_as_an_observed_removal() {
    use super::dirty_journal::{dirty_kind_from_str, dirty_kind_str};
    assert_eq!(
        dirty_kind_from_str(dirty_kind_str(FsChangeKind::ObservedRemoval)),
        FsChangeKind::ObservedRemoval
    );
    let fx = Fixture::new();
    fx.captured("was-present.txt").await;
    fx.captured("was-remote.txt").await;
    fx.set_state("was-remote.txt", MaterializationState::Remote);
    fx.remove("was-present.txt");
    fx.remove("was-remote.txt");
    for path in ["was-present.txt", "was-remote.txt"] {
        fx.state
            .dirty_path_repository()
            .record_dirty_path(
                GROUP,
                path,
                dirty_kind_str(FsChangeKind::ObservedRemoval),
                1,
                &RootCommitPermit::for_tests(),
            )
            .unwrap();
    }

    fx.proc.redrive_dirty_journal(GROUP, &fx.root).await.unwrap();

    assert!(fx.is_tombstoned("was-present.txt"));
    assert!(!fx.is_tombstoned("was-remote.txt"), "a replayed observation deleted a Remote row");
}

// ---- a provider root's delete binds to the PUBLISHED view (design 2.3) ----

mod published_view_delete {
    use super::*;

    /// `path` as the OS was told it (V1), then a newer version V2 arrives that the user never saw.
    async fn published_then_updated(fx: &Fixture, root_id: &str, path: &str) -> [u8; 16] {
        fx.captured(path).await;
        let provider = fx.state.provider_repository();
        let item = provider.mint_item(root_id, path).unwrap();
        provider
            .publish_first(
                root_id,
                &item,
                provider.current_version_hash(root_id, &item).unwrap().unwrap(),
            )
            .unwrap();
        std::fs::write(fx.root.join(path), format!("a newer version of {path}, longer")).unwrap();
        fx.proc
            .process_event(GROUP, &fx.root, &fx.event(path, FsChangeKind::CreatedOrModified))
            .await
            .unwrap();
        item
    }

    async fn delete_what_the_user_saw(fx: &Fixture, root_id: &str, path: &str) {
        let bound = fx.state.provider_repository().published_bound(root_id, path).unwrap();
        let delete = fx.proc.begin_semantic_delete_bound(GROUP, &fx.root, path, &bound).unwrap();
        // The user's delete lands; whatever the disk shows is gone with it.
        let abs = fx.root.join(path);
        if abs.is_dir() {
            std::fs::remove_dir_all(&abs).unwrap();
        } else {
            let _ = std::fs::remove_file(&abs);
        }
        fx.proc.process_semantic_delete(GROUP, &fx.root, &delete).await.unwrap();
    }

    fn declared(fx: &Fixture) -> String {
        fx.state.provider_repository().declare_state_only_for_tests(GROUP, "P").unwrap()
    }

    /// (b) The user deleted V1; the V2 they never saw survives, and is a NEW item.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delete_of_the_published_version_does_not_erase_the_newer_one() {
        let fx = Fixture::new();
        let root_id = declared(&fx);
        let old = published_then_updated(&fx, &root_id, "f.txt").await;

        delete_what_the_user_saw(&fx, &root_id, "f.txt").await;

        assert!(!fx.is_tombstoned("f.txt"), "the delete erased a version the user never saw");
        let provider = fx.state.provider_repository();
        provider.retire_item(&root_id, &old).unwrap();
        let new = provider.mint_item(&root_id, "f.txt").unwrap();
        assert_ne!(new, old, "the surviving version reused the deleted item's id");
    }

    /// (a delete with nothing newer) is an ordinary delete: the same path tombstones.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delete_of_a_published_version_nothing_replaced_tombstones_it() {
        let fx = Fixture::new();
        let root_id = declared(&fx);
        fx.captured("g.txt").await;
        let provider = fx.state.provider_repository();
        let item = provider.mint_item(&root_id, "g.txt").unwrap();
        provider
            .publish_first(
                &root_id,
                &item,
                provider.current_version_hash(&root_id, &item).unwrap().unwrap(),
            )
            .unwrap();

        delete_what_the_user_saw(&fx, &root_id, "g.txt").await;

        assert!(fx.is_tombstoned("g.txt"));
    }

    /// (c) A directory delete binds each child to its own published view; a prefix sibling is untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_directory_delete_binds_every_child_to_what_was_published() {
        let fx = Fixture::new();
        let root_id = declared(&fx);
        fx.dir("dir").await;
        fx.dir("dir2").await;
        published_then_updated(&fx, &root_id, "dir/pending.txt").await;
        fx.captured("dir/settled.txt").await;
        let provider = fx.state.provider_repository();
        let settled = provider.mint_item(&root_id, "dir/settled.txt").unwrap();
        provider
            .publish_first(
                &root_id,
                &settled,
                provider.current_version_hash(&root_id, &settled).unwrap().unwrap(),
            )
            .unwrap();
        fx.captured("dir2/sibling.txt").await;

        delete_what_the_user_saw(&fx, &root_id, "dir").await;

        assert!(fx.is_tombstoned("dir/settled.txt"), "a child the user saw survived");
        assert!(!fx.is_tombstoned("dir/pending.txt"), "a child with a newer version was erased");
        assert!(!fx.is_tombstoned("dir2/sibling.txt"), "a prefix sibling was deleted");
        assert!(!fx.is_tombstoned("dir2"));
    }

    /// (f) V1 published, V2 then V3 arrive, the delete (of V1) lands: V3 survives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delete_of_v1_after_v2_and_v3_leaves_v3() {
        let fx = Fixture::new();
        let root_id = declared(&fx);
        published_then_updated(&fx, &root_id, "h.txt").await;
        std::fs::write(fx.root.join("h.txt"), "a third version, longer still than the second")
            .unwrap();
        fx.proc
            .process_event(GROUP, &fx.root, &fx.event("h.txt", FsChangeKind::CreatedOrModified))
            .await
            .unwrap();

        delete_what_the_user_saw(&fx, &root_id, "h.txt").await;

        assert!(!fx.is_tombstoned("h.txt"));
    }
}
