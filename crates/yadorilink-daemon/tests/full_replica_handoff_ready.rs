//! `DaemonState::another_full_replica_is_ready` — the durability-handoff gate
//! an eager device must pass before `yadorilink share set-storage-mode
//! --mode on-demand` is allowed to demote it. Exercises the real
//! peer-to-peer `VersionPresentQuery` (like `custody_version_present.rs`)
//! rather than an injected confirmer, since the point of this gate is that
//! it is answered by a live peer, not a local guess.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{
    connect_two_daemons, ensure_device_signing_key, open_file_backed_replica_coordinator,
};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationPolicy;

const GROUP: &str = "handoff-group";

struct Daemon {
    state: Arc<DaemonState>,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
    _root: tempfile::TempDir,
}

fn new_daemon(device_id: &str) -> Daemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.to_string(), Arc::new(sync_state), store);
    ensure_device_signing_key(&state);
    let root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), GROUP)
        .unwrap();
    Daemon { state, _store_dir: store_dir, _index_dir: index_dir, _root: root }
}

fn record_referencing(path: &str, hash_bytes: Vec<u8>, size: u64) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: hash_bytes, offset: 0, size: size as u32 }],
        deleted: false,
    }
}

/// Writes `data`'s block into `daemon`'s block store and records it as
/// obtained through `GROUP` (mirroring what `LocalChangeProcessor` does for
/// a real local edit — see `record_group_block_provenance`'s doc comment),
/// returning the raw hash bytes. Without this, the real peer-to-peer
/// `VersionPresentQuery` this file exercises answers `false` for a block
/// poked directly into the store, since physical presence alone does not
/// prove the block was obtained through the group.
fn put_and_record(daemon: &Daemon, data: &[u8]) -> Vec<u8> {
    let hash_hex = daemon.state.block_store.put(data).unwrap();
    let hash_bytes = hex::decode(&hash_hex).unwrap();
    daemon
        .state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&hash_bytes))
        .unwrap();
    hash_bytes
}

/// A group with no current files at all has nothing to hand off, so it is
/// vacuously ready — trivially true without needing any peer at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_group_is_vacuously_ready() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    assert!(
        a.state.another_full_replica_is_ready(GROUP).await,
        "a group with no files has nothing to hand off, so it is vacuously ready"
    );
}

/// A device with a file but no connected full-replica peer at all cannot
/// confirm anything: fail closed, not ready. This is the "no other full
/// replica" case a `set-storage-mode --mode on-demand` demotion must refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_connected_full_replica_peer_is_not_ready() {
    support::ensure_isolated_config_dir();
    let b = new_daemon("device-b");
    let record = record_referencing("solo.bin", vec![1u8; 32], 4);
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    assert!(
        !b.state.another_full_replica_is_ready(GROUP).await,
        "no peer is connected to confirm this file, so the handoff must fail closed"
    );
}

/// Another full replica that durably holds every current file in the group
/// makes the group ready — the demotion this device would attempt next is
/// allowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ready_when_another_replica_holds_every_file() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // complete copy: durably holds every block
    let b = new_daemon("device-b"); // eager device asking to demote

    let first = b"first file's content";
    let first_bytes = put_and_record(&a, first);
    let first_record = record_referencing("first.bin", first_bytes, first.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &first_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &first_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let second = b"second file's content";
    let second_bytes = put_and_record(&a, second);
    let second_record = record_referencing("second.bin", second_bytes, second.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &second_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &second_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    assert!(
        b.state.another_full_replica_is_ready(GROUP).await,
        "device-a holds every current file's blocks, so the handoff is ready"
    );
}

/// Readiness is per-peer, not per-file: file1 is held only by peer C and
/// file2 only by peer D, so every file IS held by *some* peer — but no
/// SINGLE peer holds both, meaning the group has zero complete durable
/// copies to hand off to. The gate must be FALSE, not fooled into true by
/// stitching a complete replica together across two incomplete peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn not_ready_when_no_single_peer_holds_every_file() {
    support::ensure_isolated_config_dir();
    let b = new_daemon("device-b"); // the device querying readiness
    let c = new_daemon("device-c"); // holds file1 only
    let d = new_daemon("device-d"); // holds file2 only

    // Make B on-demand purely as a test-harness isolation measure: B's own
    // storage mode is irrelevant to `another_full_replica_is_ready` (which
    // only enumerates B's records and queries peers), but an eager B connected
    // to both leaf peers would eager-hydrate file1 from C and file2 from D and
    // then relay each to the other, letting a leaf peer become a complete
    // replica and defeating the "no single peer holds both" scenario. An
    // on-demand B holds and relays nothing, so C stays file1-only and D
    // file2-only, deterministically.
    let b_link = b
        .state
        .replica_coordinator
        .link_repository()
        .list_links()
        .unwrap()
        .into_iter()
        .find(|l| l.group_id == GROUP)
        .unwrap();
    b.state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(b_link.key(), MaterializationPolicy::OnDemand)
        .unwrap();

    // file1: held (indexed + stored) by C, and indexed by B. D never indexes
    // it, so D cannot confirm it.
    let file1 = b"file one's content";
    let file1_bytes = put_and_record(&c, file1);
    let file1_record = record_referencing("file1.bin", file1_bytes, file1.len() as u64);
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &file1_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    c.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &file1_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // file2: held (indexed + stored) by D, and indexed by B. C never indexes
    // it, so C cannot confirm it.
    let file2 = b"file two's content";
    let file2_bytes = put_and_record(&d, file2);
    let file2_record = record_referencing("file2.bin", file2_bytes, file2.len() as u64);
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &file2_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    d.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &file2_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&b.state, "device-b", &c.state, "device-c", &[GROUP.to_string()]).await;
    connect_two_daemons(&b.state, "device-b", &d.state, "device-d", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-c", GROUP, true);
    b.state.authority.set_peer_group_full_replica("device-d", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the sessions establish

    assert!(
        !b.state.another_full_replica_is_ready(GROUP).await,
        "no single peer holds both files, so the group has no complete replica to hand off to"
    );
}

/// The other full replica is missing one file's blocks (behind, or
/// incompletely synced) — fail closed for the whole group, even though every
/// other file is confirmed. One unconfirmed file is enough to refuse the
/// entire demotion.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_ready_when_another_replica_is_missing_one_files_blocks() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");

    let held = b"content device-a actually holds";
    let held_bytes = put_and_record(&a, held);
    let held_record = record_referencing("held.bin", held_bytes, held.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &held_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &held_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Both index this path, but device-a's block store never received the
    // block it references — a behind/incompletely-synced replica.
    let missing_record = record_referencing("missing.bin", vec![9u8; 32], 4);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &missing_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &missing_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    assert!(
        !b.state.another_full_replica_is_ready(GROUP).await,
        "device-a cannot confirm missing.bin's blocks, so the whole handoff must fail closed"
    );
}

/// HandoffReady must cover the group's whole durability-root set — current
/// head PLUS every still-retained superseded version — not just current
/// files. Device-a holds the current version of `a.bin` but never received
/// the superseded version device-b still retains, so the handoff must still
/// refuse even though every CURRENT file is fully covered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_ready_when_peer_holds_current_but_not_a_retained_version() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // candidate complete copy
    let b = new_daemon("device-b"); // querier, has retained history for a.bin

    // The current version's real content -- both devices need the actual
    // bytes in their own block stores for `holds_version_durably`'s final
    // checksum verification to pass for it.
    let current_content = b"a.bin's current content";
    let current_bytes = put_and_record(&a, current_content);
    b.state.block_store.put(current_content).unwrap();
    let current_record = record_referencing("a.bin", current_bytes, current_content.len() as u64);

    // The superseded version's content: device-a never received or stored
    // this block at all -- it never held this version. Written first, then
    // superseded by `current_record` below (same path).
    let superseded_record = FileRecord {
        path: "a.bin".into(),
        size: 32,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: vec![7u8; 32], offset: 0, size: 32 }],
        deleted: false,
    };
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &superseded_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &current_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap(); // supersedes it

    // Device-a only ever indexes the CURRENT version of a.bin -- it never
    // held the superseded one at all.
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &current_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    assert!(
        !b.state.another_full_replica_is_ready(GROUP).await,
        "device-a holds only the current version of a.bin, not the retained superseded root \
         device-b still has, so the whole-group handoff must fail closed"
    );
}

/// The positive counterpart: when the candidate replica holds the retained
/// superseded version TOO (not just current), the handoff is ready — proving
/// the durability-root gate isn't simply "always refuses once there's any
/// history," but genuinely confirms per-version custody via the widened
/// `VersionPresentQuery` responder logic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ready_when_another_replica_holds_current_and_retained_history() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");

    let old_content = b"a.bin's old, now-superseded content";
    let old_bytes = put_and_record(&a, old_content);
    let old_record = record_referencing("a.bin", old_bytes, old_content.len() as u64);

    let new_content = b"a.bin's current content";
    let new_bytes = put_and_record(&a, new_content);
    let new_record = record_referencing("a.bin", new_bytes, new_content.len() as u64);

    // Both devices index the same history: old (now superseded) then new
    // (current) -- and device-a's block store actually holds both.
    for state in [&a.state, &b.state] {
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                GROUP,
                &old_record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                GROUP,
                &new_record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    assert!(
        b.state.another_full_replica_is_ready(GROUP).await,
        "device-a durably holds both a.bin's current version and its retained superseded \
         version, so the whole-group handoff is ready"
    );
}

/// The digest re-confirm `control_socket::ensure_unlink_keeps_a_full_replica`/
/// `set_storage_mode` run immediately before committing a role loss: capture
/// the root-set digest the peer confirmation succeeded against
/// (`full_replica_handoff_ready_digest`), then re-fetch a fresh, purely
/// local digest (`local_durability_roots_digest`) right before the commit —
/// if a local edit landed in between (this device's own durability-root set
/// moved), the two digests must disagree, so the caller's `digest_now ==
/// digest_at_check` check correctly fails closed rather than trusting a
/// confirmation that no longer covers the current set. This drives the
/// exact production methods the daemon-side commit gates call, in the same
/// order, rather than re-implementing the comparison.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_replica_handoff_ready_digest_detects_a_root_set_change_before_commit() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // complete copy: durably holds every file
    let b = new_daemon("device-b"); // eager device asking to demote/unlink

    let content = b"the only file, at check time";
    let bytes = put_and_record(&a, content);
    let record = record_referencing("a.bin", bytes, content.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    // The check: device-a is confirmed to durably hold everything, and the
    // digest that confirmation was made against is captured — mirrors the
    // first half of the commit gate.
    let digest_at_check = b
        .state
        .full_replica_handoff_ready_digest(GROUP)
        .await
        .expect("device-a should be confirmed ready");

    // Re-fetching immediately (nothing changed yet) must still agree —
    // otherwise the gate would spuriously refuse every unaffected commit,
    // not just a genuinely raced one.
    assert_eq!(
        b.state.local_durability_roots_digest(GROUP),
        Some(digest_at_check),
        "with no intervening change, the fresh local digest must still match the confirmed one"
    );

    // A local edit lands in the window between the check and the commit —
    // exactly the race the re-confirm exists to catch.
    let second_record = record_referencing("second.bin", vec![9u8; 32], 4);
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &second_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The re-confirm: a fresh local digest no longer matches the one the
    // peer's confirmation covered, so the caller must fail closed.
    assert_ne!(
        b.state.local_durability_roots_digest(GROUP),
        Some(digest_at_check),
        "a root set that changed after the check must produce a different digest, so the \
         commit gate's re-confirm correctly fails closed"
    );
}

/// Two real daemons, connected: the whole-group durability handoff queries
/// the peer and genuinely confirms it covers the group's roots.
///
/// This used to have a sibling asserting the opposite for a peer that had
/// not advertised a `supports_version_hash_exact` capability bit. That bit
/// is gone, and so is the peer it described: the exact-hash check is part of
/// what this protocol generation IS, and a peer that does not enforce it
/// cannot complete the TLS handshake, let alone answer a query. What is left
/// is this end-to-end confirmation that the query path itself works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handoff_confirms_a_peer_that_durably_holds_the_group() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");

    let content = b"content the capable peer durably holds";
    let bytes = put_and_record(&a, content);
    let record = record_referencing("a.bin", bytes, content.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    assert!(
        b.state.peers.session("device-a").is_some(),
        "the handoff query needs a live session with device-a"
    );
    assert!(
        b.state.another_full_replica_is_ready(GROUP).await,
        "device-a durably holds the file, so the handoff must proceed and confirm readiness"
    );
}
