#![cfg(test)]
//! Serving a block from the user's file: the file is a source only while it is the version the
//! record describes, a changed file answers "not held" and is put back in front of capture, and
//! none of it widens what a requester may be given.

use std::sync::Arc;

use yadorilink_local_storage::BlockStore;

use yadorilink_peer_session::peer_session::PeerSyncSessionDeps;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use super::FileBlockSource;
use crate::engine_tuning::EngineTuning;
use crate::test_support::peer_session_fixture::{
    expect_found, request_block, spawn_session_configured_with_deps,
    AlwaysValidRootCommitAuthorityProvider, Device, GROUP,
};
use proto::block_response_header::Outcome as BlockOutcome;
use yadorilink_ipc_proto::sync as proto;

const PATH: &str = "doc.bin";

fn tuning(file_block_source: bool) -> EngineTuning {
    EngineTuning {
        file_block_source,
        single_pass: false,
        witness: crate::install_witness::WitnessPlacement::BesideDatabase,
        ..EngineTuning::default()
    }
}

/// A device that holds `data` at `PATH` only as a file: the record is published and present, the
/// store has no copy of the block and the group has no provenance for it.
async fn device_with_file_only(file_block_source: bool, data: &[u8]) -> (Device, Vec<u8>) {
    let device = Device::new_with_tuning("device-a", tuning(file_block_source)).await;
    let record = device.producer().commit_create(GROUP, PATH, data, 0);
    device.publish_pending();
    let hash = record.blocks[0].hash.clone();
    std::fs::write(device.root_path().join(PATH), data).unwrap();
    device
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            PATH,
            MaterializationState::Present,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    // The store copy and the provenance are gone, as for a block this device holds only in a file.
    device.store.delete(&hex::encode(&hash)).unwrap();
    device
        .state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM group_block_provenance WHERE group_id = ?1 AND block_hash = ?2",
                rusqlite::params![GROUP, hash],
            )?;
            Ok(())
        })
        .unwrap();
    (device, hash)
}

fn session_with_file_source(device: &Device, peer: &str) {
    let source = FileBlockSource::new(
        device.state.clone(),
        AlwaysValidRootCommitAuthorityProvider::shared(),
    );
    let deps = PeerSyncSessionDeps {
        block_file_source: Some(Arc::new(source)),
        ..PeerSyncSessionDeps::standalone()
    };
    let _ = spawn_session_configured_with_deps(
        device,
        peer,
        vec![GROUP.to_string()],
        false,
        None,
        Some(deps),
    );
}

async fn ask(
    requester: &Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    path: &str,
    hash: &[u8],
) -> (proto::BlockResponseHeader, Vec<u8>) {
    request_block(requester, "device-a", path, hash).await
}

fn is_dont_have(response: &proto::BlockResponseHeader) -> bool {
    matches!(response.outcome, Some(BlockOutcome::DontHave(_)))
}

fn is_found(response: &proto::BlockResponseHeader) -> bool {
    matches!(response.outcome, Some(BlockOutcome::Found(_)))
}

fn journaled(device: &Device) -> Vec<(String, String, i64)> {
    device
        .state
        .dirty_path_repository()
        .list_dirty_paths(GROUP)
        .unwrap()
        .into_iter()
        .map(|d| (d.path, d.change_kind, d.observed_at_unix_nanos))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_the_store_lacks_is_served_from_the_file() {
    let data = b"a block that exists only in the user's file".to_vec();
    let (device, hash) = device_with_file_only(true, &data).await;
    let requester = device.fake_peer("device-b").await;
    session_with_file_source(&device, "device-b");

    let (response, body) = ask(&requester, PATH, &hash).await;

    let found = expect_found(&response);
    assert_eq!(found.hash, hash);
    assert_eq!(body, data, "the bytes sent are the file's bytes, whole");
    assert!(journaled(&device).is_empty(), "serving a good file marks nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_is_served_from_a_file_unless_the_setting_is_on() {
    let data = b"the same file, with serving from files switched off".to_vec();
    let (device, hash) = device_with_file_only(false, &data).await;
    let requester = device.fake_peer("device-b").await;
    session_with_file_source(&device, "device-b");

    let (response, _) = ask(&requester, PATH, &hash).await;

    assert!(!is_found(&response), "the setting off: no provenance, no block ({response:?})");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_edited_since_its_record_answers_not_held_and_is_journaled() {
    let data = b"original bytes, exactly this long".to_vec();
    let (device, hash) = device_with_file_only(true, &data).await;
    // The same length, different bytes, and the modification time put back: nothing but the
    // content tells it apart.
    let edited = b"altered  bytes, exactly this long".to_vec();
    assert_eq!(edited.len(), data.len());
    let file = device.root_path().join(PATH);
    let mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    std::fs::write(&file, &edited).unwrap();
    std::fs::File::options().write(true).open(&file).unwrap().set_modified(mtime).unwrap();
    let requester = device.fake_peer("device-b").await;
    session_with_file_source(&device, "device-b");

    let (response, body) = ask(&requester, PATH, &hash).await;

    assert!(is_dont_have(&response), "{response:?}");
    assert!(body.is_empty(), "no byte of the edited file left the device");
    let marks = journaled(&device);
    assert_eq!(marks.len(), 1, "{marks:?}");
    assert_eq!((marks[0].0.as_str(), marks[0].1.as_str()), (PATH, "created_or_modified"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_of_another_length_or_a_removed_file_is_not_a_source() {
    let data = b"original bytes".to_vec();
    let (device, hash) = device_with_file_only(true, &data).await;
    let requester = device.fake_peer("device-b").await;
    session_with_file_source(&device, "device-b");
    let file = device.root_path().join(PATH);

    std::fs::write(&file, b"original bytes, and more of them").unwrap();
    let (longer, _) = ask(&requester, PATH, &hash).await;
    assert!(is_dont_have(&longer), "{longer:?}");
    assert_eq!(journaled(&device)[0].1, "created_or_modified");

    std::fs::remove_file(&file).unwrap();
    let (gone, body) = ask(&requester, PATH, &hash).await;
    assert!(is_dont_have(&gone), "{gone:?}");
    assert!(body.is_empty());
    assert_eq!(journaled(&device)[0].1, "removed", "an observed removal is journaled as one");
}

/// Every failure writes a mark that is newer than the one before it, so that capture, which deletes
/// the journal row only up to the value it started from, never removes the mark of an edit it has
/// not read: not when it has started from an earlier mark, and not when a redrive wrote the stored
/// value back unchanged. A second edit that keeps the length and the modification time is found by
/// the request that follows it and is still waiting after capture's delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_failed_request_leaves_a_mark_newer_than_the_last() {
    let data = b"original bytes of a file that is about to change".to_vec();
    let (device, hash) = device_with_file_only(true, &data).await;
    let file = device.root_path().join(PATH);
    std::fs::write(&file, b"original bytes of a file that is about to CHANGE").unwrap();
    let requester = device.fake_peer("device-b").await;
    session_with_file_source(&device, "device-b");

    ask(&requester, PATH, &hash).await;
    let first = journaled(&device);
    assert_eq!(first.len(), 1);
    ask(&requester, PATH, &hash).await;
    let second = journaled(&device);
    assert_eq!(second.len(), 1, "one row per path, however many failures");
    assert!(second[0].2 > first[0].2, "a repeated failure still leaves a newer mark");

    // Capture, started from the first mark, finishes and deletes the row up to that value only.
    device
        .state
        .dirty_path_repository()
        .clear_dirty_paths_conditional_batch(
            GROUP,
            &[(PATH.to_string(), first[0].2)],
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert_eq!(journaled(&device).len(), 1, "the mark of a later failure survives that delete");

    // Capture takes the second mark as well; the next failure writes a new one again.
    device
        .state
        .dirty_path_repository()
        .clear_dirty_paths_conditional_batch(
            GROUP,
            &[(PATH.to_string(), second[0].2)],
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(journaled(&device).is_empty());
    ask(&requester, PATH, &hash).await;
    let again = journaled(&device);
    assert_eq!(again.len(), 1);
    assert!(again[0].2 > second[0].2);
}

/// Capture's redrive writes the stored observation back unchanged and clears that value; a failure
/// found after that write must not be hidden by it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redrive_that_writes_the_stored_value_back_does_not_hide_a_later_failure() {
    let data = b"first state of a file that is edited twice".to_vec();
    let (device, hash) = device_with_file_only(true, &data).await;
    let file = device.root_path().join(PATH);
    std::fs::write(&file, b"FIRST state of a file that is edited twice").unwrap();
    let requester = device.fake_peer("device-b").await;
    session_with_file_source(&device, "device-b");

    ask(&requester, PATH, &hash).await;
    let first = journaled(&device);
    // The redrive journals the stored observation again (the same value) before it reads the file.
    device
        .state
        .dirty_path_repository()
        .record_dirty_path(
            GROUP,
            PATH,
            "created_or_modified",
            first[0].2,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The file is edited again after capture read it, with the same length and time: a request
    // finds it, and the mark it leaves is not the value capture will delete.
    ask(&requester, PATH, &hash).await;
    device
        .state
        .dirty_path_repository()
        .clear_dirty_paths_conditional_batch(
            GROUP,
            &[(PATH.to_string(), first[0].2)],
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert_eq!(journaled(&device).len(), 1, "the later edit is still waiting for capture");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_that_is_not_present_or_not_listed_is_never_a_source() {
    let data = b"a file whose record says it is not on this device".to_vec();
    let (device, hash) = device_with_file_only(true, &data).await;
    let requester = device.fake_peer("device-b").await;
    session_with_file_source(&device, "device-b");

    // The file exists on disk, but the row is a placeholder: not a source, and nothing to journal.
    device
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            PATH,
            MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    let (placeholder, _) = ask(&requester, PATH, &hash).await;
    assert!(!is_found(&placeholder), "{placeholder:?}");
    assert!(journaled(&device).is_empty(), "a placeholder is not a changed file");

    // Present again, but the request names a path whose record does not list the hash: the file of
    // one path never answers for another.
    device
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            PATH,
            MaterializationState::Present,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    std::fs::write(device.root_path().join("other.bin"), &data).unwrap();
    let (other, _) = ask(&requester, "other.bin", &hash).await;
    assert!(!is_found(&other), "{other:?}");
}

/// The rule the duplicate suppression must keep: it never crosses the point where capture starts on
/// the path. Capture rewrites the journal row with its own observation when it starts and deletes
/// the row only up to that value. A second edit that keeps the length and the modification time,
/// found by a request after capture has started, must leave a mark that capture's delete does not
/// remove, or the edit is never captured if its watcher event was missed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_made_while_capture_is_working_on_the_path_is_not_lost() {
    let data = b"first state of a file that is edited twice".to_vec();
    let (device, hash) = device_with_file_only(true, &data).await;
    let file = device.root_path().join(PATH);
    std::fs::write(&file, b"FIRST state of a file that is edited twice").unwrap();
    let requester = device.fake_peer("device-b").await;
    session_with_file_source(&device, "device-b");

    ask(&requester, PATH, &hash).await;
    let first = journaled(&device);
    assert_eq!(first.len(), 1);

    // Capture starts on the path: it journals it under its own observation (the time its watcher
    // event was seen), reads the file, and will delete the row up to that value when it commits.
    let capture_observation = first[0].2 - 1;
    device
        .state
        .dirty_path_repository()
        .record_dirty_path(
            GROUP,
            PATH,
            "created_or_modified",
            capture_observation,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The file is edited again after capture read it, with the same length and time, and a
    // request finds it: the same observation, but the row is no longer the one that was written.
    ask(&requester, PATH, &hash).await;
    let after = journaled(&device);
    assert_eq!(after.len(), 1);
    assert!(
        after[0].2 > capture_observation,
        "the mark is newer than what capture holds ({} vs {capture_observation})",
        after[0].2
    );

    // Capture commits what it read and deletes the row up to its own observation.
    device
        .state
        .dirty_path_repository()
        .clear_dirty_paths_conditional_batch(
            GROUP,
            &[(PATH.to_string(), capture_observation)],
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert_eq!(journaled(&device).len(), 1, "the later edit is still waiting for capture");
}

/// A source whose read fails with an I/O error that is not an end of file.
struct FailingSource;

impl yadorilink_peer_session::ports::BlockFileSourcePort for FailingSource {
    fn read_block(
        &self,
        _group_id: &str,
        _path: &str,
        _hash: &[u8],
    ) -> Result<
        yadorilink_peer_session::ports::FileBlockRead,
        yadorilink_peer_session::PeerSessionError,
    > {
        Err(std::io::Error::other("injected read failure").into())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_that_cannot_be_read_is_not_answered_as_not_held() {
    let data = b"a file whose bytes cannot be read".to_vec();
    let (device, hash) = device_with_file_only(true, &data).await;
    let requester = device.fake_peer("device-b").await;
    let deps = PeerSyncSessionDeps {
        block_file_source: Some(Arc::new(FailingSource)),
        ..PeerSyncSessionDeps::standalone()
    };
    let _ = spawn_session_configured_with_deps(
        &device,
        "device-b",
        vec![GROUP.to_string()],
        false,
        None,
        Some(deps),
    );

    let (response, _) = ask(&requester, PATH, &hash).await;

    assert!(!is_found(&response), "{response:?}");
    assert!(
        !is_dont_have(&response),
        "a read failure is not evidence that the block is not held ({response:?})"
    );
}

/// A hundred failed requests that arrive while capture is working on the path cost one more
/// capture of it, not a hundred, and the latest edit is not lost.
///
/// What bounds it: the journal keeps one row per path (a mark only advances the row's observation),
/// capture processes a journaled path once per pass and deletes the row only up to the observation
/// it read, and a mark wakes nothing, so whatever the number of marks the path is taken again at
/// the next pass, once. The writes are one per failed request, which the serving dispatch and credit
/// bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hundred_failed_requests_during_a_capture_cost_one_more_capture() {
    const REQUESTS: usize = 100;
    let data = b"first state of a file that keeps being asked for".to_vec();
    let (device, hash) = device_with_file_only(true, &data).await;
    std::fs::write(
        device.root_path().join(PATH),
        b"FIRST state of a file that keeps being asked for",
    )
    .unwrap();
    // Counts the writes to the journal, whatever form they take (insert, or the update of an
    // existing row).
    device
        .state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch(
                "CREATE TABLE test_journal_writes (n INTEGER NOT NULL); \
                 INSERT INTO test_journal_writes VALUES (0); \
                 CREATE TRIGGER test_journal_insert AFTER INSERT ON local_dirty_paths \
                   BEGIN UPDATE test_journal_writes SET n = n + 1; END; \
                 CREATE TRIGGER test_journal_update AFTER UPDATE ON local_dirty_paths \
                   BEGIN UPDATE test_journal_writes SET n = n + 1; END;",
            )?;
            Ok(())
        })
        .unwrap();
    let writes = |device: &Device| -> i64 {
        device
            .state
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                Ok(conn.query_row("SELECT n FROM test_journal_writes", [], |r| r.get(0))?)
            })
            .unwrap()
    };
    let requester = device.fake_peer("device-b").await;
    session_with_file_source(&device, "device-b");
    let repository = device.state.dirty_path_repository();

    // The first failure is what capture is driven from.
    ask(&requester, PATH, &hash).await;
    let pass_one = repository.list_dirty_paths(GROUP).unwrap();
    assert_eq!(pass_one.len(), 1);
    let read_by_capture = pass_one[0].observed_at_unix_nanos;
    let writes_before = writes(&device);

    // Capture is working on the path (it has read the row and the file). Meanwhile the requests keep
    // coming, a few at a time as the serving dispatch lets them.
    for chunk in 0..REQUESTS / 10 {
        let mut asked = Vec::new();
        for _ in 0..10 {
            asked.push(ask(&requester, PATH, &hash));
        }
        for (response, _) in futures_util::future::join_all(asked).await {
            assert!(is_dont_have(&response), "chunk {chunk}: {response:?}");
        }
    }
    assert_eq!(
        repository.list_dirty_paths(GROUP).unwrap().len(),
        1,
        "{REQUESTS} marks are still one row"
    );
    assert_eq!(
        writes(&device) - writes_before,
        REQUESTS as i64,
        "one journal write per failed request, no more"
    );

    // Capture commits what it read and deletes the row up to the value it read: the row stays.
    repository
        .clear_dirty_paths_conditional_batch(
            GROUP,
            &[(PATH.to_string(), read_by_capture)],
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    let pass_two = repository.list_dirty_paths(GROUP).unwrap();
    assert_eq!(pass_two.len(), 1, "the later edit is still waiting");
    assert!(pass_two[0].observed_at_unix_nanos > read_by_capture);

    // The next pass takes the path once, with the latest observation, and nothing is left for a
    // third.
    repository
        .clear_dirty_paths_conditional_batch(
            GROUP,
            &[(PATH.to_string(), pass_two[0].observed_at_unix_nanos)],
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(repository.list_dirty_paths(GROUP).unwrap().is_empty(), "no third capture");
}

/// What `open_source` makes of a file on Windows: a plain file is a source and the open leaves it
/// free to be renamed and deleted; a symlink, or a file marked offline, is not a source.
#[cfg(windows)]
mod windows_open {
    use super::super::{open_source, Opened};

    fn is_source(path: &std::path::Path) -> bool {
        matches!(open_source(path), Opened::File(_))
    }

    #[test]
    fn a_plain_file_is_a_source_and_stays_free_to_rename_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.bin");
        std::fs::write(&path, b"bytes").unwrap();
        let Opened::File(held) = open_source(&path) else { panic!("a plain file is a source") };
        let moved = dir.path().join("moved.bin");
        std::fs::rename(&path, &moved).expect("rename while the source handle is open");
        std::fs::remove_file(&moved).expect("delete while the source handle is open");
        drop(held);
    }

    #[test]
    fn an_absent_file_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(open_source(&dir.path().join("absent")), Opened::Gone));
    }

    #[test]
    fn a_file_marked_offline_is_not_a_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("offline.bin");
        std::fs::write(&path, b"bytes").unwrap();
        assert!(is_source(&path), "fixture: the file is a source before it is marked");
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command"])
            .arg(format!("(Get-Item -LiteralPath '{}').Attributes = 'Offline'", path.display()))
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!is_source(&path), "an offline file would be recalled by a read");
    }

    #[test]
    fn a_symlink_is_not_a_source() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.bin");
        std::fs::write(&target, b"bytes").unwrap();
        let link = dir.path().join("link.bin");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            eprintln!("no privilege to create a symlink here; case not exercised");
            return;
        }
        assert!(!is_source(&link), "a reparse point is never read as a source");
    }
}
