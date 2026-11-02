//! The embedded host's write commands between two real daemons: an On-Demand "phone" (a provider
//! root, no watched folder) writes through `EngineCommands`, and a full-replica "Mac" (a plain
//! folder) receives. The coordination plane is the in-process fake with signed policy, so the
//! phone is a writer of the group exactly as a joined device is.
//!
//! ```text
//!   B (OnDemand, provider root: the phone)        A (Eager, plain folder: the Mac)
//!   stage (move) + apply create  ------------->   (the Mac is not running yet)
//!   delivery: not delivered, the file exists once on the phone
//!   ... the Mac comes online ...
//!   delivery: delivered, by A           <----->   A holds the same bytes at the same path
//!   rename + move, a folder, delete     ------>   the same tree
//!   an edit made on A first, then B's stale edit -> Concurrent: both versions kept
//!   A loses a block of the version      ------>   delivery: not delivered again
//! ```

use crate::support;

use std::time::Duration;

use sha2::{Digest, Sha256};
use support::fake_coordination::FakeCoordination;
use support::topology::{
    advertise_substrate_endpoints, fully_connected, link_eager, new_node_fast, new_node_fast_in,
    spawn_orchestrator, TopologyHandles, TopologyNode,
};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::change_policy::WriterRole;
use yadorilink_daemon::embedded_host::{
    ApplyChange, DeliveryItem, DeliveryState, EngineCommands, StageMode, StageSource, StagedHow,
};
use yadorilink_daemon::test_support::sync_stack_fixture::fixture_group_policy_granting;
use yadorilink_ipc_proto::shellipc::{
    EntryKind, ProviderApplyChangeRequest, ProviderApplyOutcome, ProviderChangeKind,
    ProviderContentSource,
};
use yadorilink_replica_domain::session_state::ProviderKind;
use yadorilink_sync_sqlite::provider::{ProviderDeclaration, ProviderLinkSpec};

const GROUP: &str = "ios-writes-group";
const SESSION: [u8; 16] = [5; 16];

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Bytes that do not repeat, so every block of the file is distinct.
fn content(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

struct Phone {
    node: TopologyNode,
    commands: EngineCommands,
    root_id: Vec<u8>,
    temp: tempfile::TempDir,
    seq: std::sync::atomic::AtomicU64,
}

impl Phone {
    /// An On-Demand node whose folder is a provider root, linked the way the app links one: a
    /// provider link row and its declared root, no directory and no runtime watching one.
    async fn new(fake: &FakeCoordination) -> Phone {
        let node = new_node_fast("ios-phone");
        register_with_fake(fake, &node.state, &node.device_id, &[GROUP]).await;
        node.state
            .replica_coordinator
            .link_repository()
            .add_provider_link(
                "provider://ios-phone",
                GROUP,
                &ProviderLinkSpec {
                    kind: ProviderKind::MacFileProvider,
                    display_name: "Photos".into(),
                    empty_owner: false,
                    on_demand: true,
                    creation_digest: "test".into(),
                },
            )
            .unwrap();
        let ProviderDeclaration::Provider(root) = node
            .state
            .replica_coordinator
            .provider_repository()
            .declaration_for_group(GROUP)
            .unwrap()
        else {
            panic!("the provider link declares its root");
        };
        let temp = tempfile::tempdir().unwrap();
        let commands =
            EngineCommands::for_state_with_temp_root_for_test(node.state.clone(), temp.path());
        Phone {
            node,
            commands,
            root_id: hex::decode(root.root_id).unwrap(),
            temp,
            seq: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn ingest_dir(&self) -> std::path::PathBuf {
        self.temp.path().join("ingest")
    }

    fn request(&self, kind: ProviderChangeKind) -> ProviderApplyChangeRequest {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ProviderApplyChangeRequest {
            request_id: format!("attempt-{seq}").into_bytes(),
            session_id: SESSION.to_vec(),
            operation_seq: seq,
            root_id: self.root_id.clone(),
            kind: kind as i32,
            ..Default::default()
        }
    }

    async fn apply(
        &self,
        request: ProviderApplyChangeRequest,
    ) -> yadorilink_ipc_proto::shellipc::ProviderApplyChangeResponse {
        self.commands.apply_change(ApplyChange(request)).await.0
    }

    /// Stages `bytes` by moving a file out of a "picked" directory beside the temp root and
    /// returns what a create names.
    async fn stage_moved(&self, name: &str, bytes: &[u8]) -> ProviderContentSource {
        let picked = self.temp.path().parent().unwrap().join(format!("picked-{name}"));
        std::fs::write(&picked, bytes).unwrap();
        let staged = self
            .commands
            .stage_upload(StageSource::Path(picked.clone()), StageMode::Move)
            .await
            .expect("staged");
        assert_eq!(staged.how, StagedHow::Moved, "a file on the same volume is renamed");
        assert!(!picked.exists(), "the source is gone: the file exists once");
        assert_eq!(staged.sha256, sha(bytes));
        ProviderContentSource {
            ingest_name: staged.ingest_name,
            size: staged.size,
            sha256: staged.sha256.to_vec(),
        }
    }

    async fn create_file(&self, parent: Option<&[u8]>, name: &str, bytes: &[u8]) -> Applied {
        let mut create = self.request(ProviderChangeKind::Create);
        create.name = Some(name.into());
        create.entry_kind = EntryKind::File as i32;
        create.parent_item_id = parent.map(<[u8]>::to_vec);
        create.content = Some(self.stage_moved(name, bytes).await);
        let response = self.apply(create).await;
        assert!(response.ok, "{response:?}");
        Applied(response.item.unwrap())
    }

    async fn delivery(&self, item: &Applied) -> (DeliveryState, u32) {
        let report = self
            .commands
            .version_delivery(vec![DeliveryItem {
                root_id: self.root_id.clone(),
                item_id: item.0.item_id.clone(),
                content_version: item.0.content_version.clone(),
            }])
            .await
            .unwrap();
        (report.items.into_iter().next().unwrap().state, report.undelivered_count)
    }
}

struct Applied(yadorilink_ipc_proto::shellipc::ProviderAppliedItem);

fn read(dir: &std::path::Path, relative: &str) -> Option<Vec<u8>> {
    std::fs::read(dir.join(relative)).ok()
}

fn index_of(node: &TopologyNode) -> Vec<String> {
    node.state
        .replica_coordinator
        .file_index_repository()
        .list_files_with_kind(GROUP)
        .map(|rows| {
            rows.into_iter()
                .map(|(r, k)| format!("{} {} del={} {k:?}", r.path, r.size, r.deleted))
                .collect()
        })
        .unwrap_or_default()
}

// One story told in order (create, saved, rename, conflict, lost block, delete); its steps share
// the two live devices, so it is not split.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[cfg_attr(windows, ignore = "the provider write path stages by rename on a Unix host")]
async fn what_the_phone_writes_reaches_the_mac_and_is_saved_only_when_the_mac_holds_it() {
    let Some(tmp) = support::identity_proving_temp_root() else {
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn,yadorilink_daemon=info"))
        .with_test_writer()
        .try_init();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let phone = Phone::new(&fake).await;
    let mac = new_node_fast_in(tmp.path(), "ios-mac");
    register_with_fake(&fake, &mac.state, &mac.device_id, &[GROUP]).await;
    link_eager(&mac, GROUP);
    fake.set_full_replica(&mac.device_id, GROUP, true);
    // Both are writers of the group, as the coordination plane's policy grants them.
    for node in [&phone.node, &mac] {
        fake.grant_role(&node.device_id, GROUP, WriterRole::Editor);
    }

    // Only the phone is online. It learns the group's policy (it is a writer) and writes.
    let mut handles = TopologyHandles::new();
    handles.insert(phone.node.device_id.clone(), spawn_orchestrator(fake.addr(), &phone.node));
    let phone_id = phone.node.device_id.clone();
    wait_until_with_context(
        || {
            phone.node.state.authority.group_policy_state(GROUP).is_some_and(|policy| {
                policy.current_writers().iter().any(|writer| writer.device_id == phone_id)
            })
        },
        Duration::from_secs(60),
        || "the phone never became a writer of the group".into(),
    )
    .await;

    let video = content(11, 6 * 1024 * 1024);
    let created = phone.create_file(None, "clip.mov", &video).await;
    assert_eq!(created.0.size, video.len() as u64);
    assert!(
        std::fs::read_dir(phone.ingest_dir()).unwrap().next().is_none(),
        "the staged file is removed when the change commits: the bytes exist once on the phone"
    );
    let (state, undelivered) = phone.delivery(&created).await;
    assert_eq!(state, DeliveryState::NotDelivered, "nobody holds it but the phone");
    assert_eq!(undelivered, 1);

    // The Mac comes online: it pulls the file, byte for byte.
    handles.insert(mac.device_id.clone(), spawn_orchestrator(fake.addr(), &mac));
    advertise_substrate_endpoints(&[&phone.node, &mac]).await;
    wait_until_with_context(
        || fully_connected(&phone.node.state, &mac.device_id),
        Duration::from_secs(60),
        || "the phone and the Mac never connected".into(),
    )
    .await;
    wait_until_with_context(
        || read(mac.root.path(), "clip.mov").is_some_and(|got| sha(&got) == sha(&video)),
        Duration::from_secs(120),
        || {
            format!(
                "the Mac never received clip.mov byte for byte\nmac index {:?}\nphone index {:?}\nmac dir {:?}",
                index_of(&mac),
                index_of(&phone.node),
                support::real_entry_names(mac.root.path()),
            )
        },
    )
    .await;
    // Saved: the Mac confirms it holds exactly this version. Every call asks the peer afresh, so
    // the count is read from the very report that shows Delivered: a second call is a new
    // question, and a reconnect or a membership change between the two would answer it "not
    // delivered" (the documented fail-closed answer) without anything being wrong.
    let mut confirmed = None;
    for _ in 0..600 {
        let (state, undelivered) = phone.delivery(&created).await;
        if let DeliveryState::Delivered { device_ids } = state {
            confirmed = Some((device_ids, undelivered));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        confirmed,
        Some((vec![mac.device_id.clone()], 0)),
        "the Mac never confirmed it, or the report counted a Delivered item as undelivered"
    );

    // A replay of the same operation returns the stored outcome and authors nothing.
    let mut replay = phone.request(ProviderChangeKind::Create);
    replay.operation_seq = 1;
    replay.request_id = b"replay".to_vec();
    replay.name = Some("clip.mov".into());
    replay.entry_kind = EntryKind::File as i32;
    replay.content = Some(ProviderContentSource {
        ingest_name: "up-gone".into(),
        size: video.len() as u64,
        sha256: sha(&video).to_vec(),
    });
    let replayed = phone.apply(replay).await;
    assert!(replayed.ok && replayed.replayed, "{replayed:?}");

    // A folder, then rename and move into it: the Mac has the same tree.
    let mut folder = phone.request(ProviderChangeKind::Create);
    folder.name = Some("Trips".into());
    folder.entry_kind = EntryKind::Directory as i32;
    let folder = phone.apply(folder).await;
    assert!(folder.ok, "{folder:?}");
    let folder = folder.item.unwrap();
    let mut moved = phone.request(ProviderChangeKind::Modify);
    moved.item_id = created.0.item_id.clone();
    moved.base_version_hash = created.0.content_version.clone();
    moved.name = Some("kyoto.mov".into());
    moved.parent_item_id = Some(folder.item_id.clone());
    let moved = phone.apply(moved).await;
    assert!(moved.ok, "{moved:?}");
    wait_until_with_context(
        || {
            read(mac.root.path(), "Trips/kyoto.mov").is_some_and(|got| sha(&got) == sha(&video))
                && read(mac.root.path(), "clip.mov").is_none()
        },
        Duration::from_secs(60),
        || format!("the rename and move never reached the Mac: {:?}", index_of(&mac)),
    )
    .await;

    // An edit made on the Mac, then the phone's edit of the version it saw: both are kept.
    let on_mac = content(12, 300_000);
    std::fs::write(mac.root.path().join("Trips/kyoto.mov.tmp"), &on_mac).unwrap();
    std::fs::rename(
        mac.root.path().join("Trips/kyoto.mov.tmp"),
        mac.root.path().join("Trips/kyoto.mov"),
    )
    .unwrap();
    wait_until_with_context(
        || {
            phone
                .node
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(GROUP, "Trips/kyoto.mov")
                .ok()
                .flatten()
                .is_some_and(|record| record.size == on_mac.len() as u64)
        },
        Duration::from_secs(60),
        || {
            format!(
                "the phone never saw the Mac's edit: phone {:?} mac {:?} dir {:?}",
                index_of(&phone.node),
                index_of(&mac),
                support::real_entry_names(&mac.root.path().join("Trips")),
            )
        },
    )
    .await;
    let mut stale = phone.request(ProviderChangeKind::Modify);
    stale.item_id = created.0.item_id.clone();
    // The version the phone saw before the Mac's edit.
    stale.base_version_hash = moved.item.as_ref().unwrap().content_version.clone();
    let phone_bytes = content(13, 200_000);
    stale.content = Some(phone.stage_moved("stale", &phone_bytes).await);
    let stale = phone.apply(stale).await;
    assert!(stale.ok, "{stale:?}");
    assert_eq!(stale.outcome, ProviderApplyOutcome::Concurrent as i32, "{stale:?}");
    wait_until_with_context(
        || {
            let contents: Vec<Vec<u8>> = std::fs::read_dir(mac.root.path().join("Trips"))
                .unwrap()
                .filter_map(|e| std::fs::read(e.unwrap().path()).ok())
                .collect();
            contents.contains(&on_mac) && contents.contains(&phone_bytes)
        },
        Duration::from_secs(90),
        || format!("both versions were not kept on the Mac: {:?}", index_of(&mac)),
    )
    .await;

    // The Mac holds the kept version; then it loses a block of it: not delivered again.
    let kept = Applied(stale.item.unwrap());
    let mut saved_again = false;
    for _ in 0..60 {
        if matches!(phone.delivery(&kept).await.0, DeliveryState::Delivered { .. }) {
            saved_again = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(saved_again, "the Mac never confirmed the conflict-kept version");
    let record = mac
        .state
        .replica_coordinator
        .file_index_repository()
        .list_files_with_kind(GROUP)
        .unwrap()
        .into_iter()
        .map(|(record, _)| record)
        .find(|record| !record.deleted && record.size == phone_bytes.len() as u64)
        .expect("the kept version is in the Mac's index");
    support::corrupt_stored_block(mac.store_root(), &hex::encode(&record.blocks[0].hash));
    // The Mac also holds a version as the file in its folder, and a check puts that file's blocks
    // back into the store, so a version is lost only when the folder's bytes are gone as well.
    for entry in std::fs::read_dir(mac.root.path().join("Trips")).unwrap() {
        let path = entry.unwrap().path();
        let Ok(mut bytes) = std::fs::read(&path) else { continue };
        if bytes == on_mac || bytes == phone_bytes {
            bytes[0] ^= 0xff;
            std::fs::write(&path, bytes).unwrap();
        }
    }
    let (state, undelivered) = phone.delivery(&kept).await;
    assert_eq!(state, DeliveryState::NotDelivered, "a lost block must read as not delivered");
    assert_eq!(undelivered, 1);

    // The phone's delete propagates. A folder is deleted only on the view the user saw (its token
    // changes whenever anything below it does); the app deletes with the token it last got, and
    // on STALE_VIEW reads the current one from the listing.
    // Once the phone has settled what the Mac sent back (both versions under the folder).
    wait_until_with_context(
        || {
            index_of(&phone.node)
                .iter()
                .filter(|row| row.starts_with("Trips/") && row.contains("del=false"))
                .count()
                == 2
        },
        Duration::from_secs(60),
        || format!("the phone never settled both versions: {:?}", index_of(&phone.node)),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut stale_delete = phone.request(ProviderChangeKind::Delete);
    stale_delete.item_id = folder.item_id.clone();
    stale_delete.recursive = true;
    stale_delete.base_version_hash = folder.content_version.clone();
    assert_eq!(
        phone.apply(stale_delete).await.failure,
        yadorilink_ipc_proto::shellipc::ProviderApplyFailure::StaleView as i32,
        "an old token deletes nothing"
    );
    // STALE_VIEW means refresh and retry: the app reads the folder's current token from the
    // listing (`lookup_item` is what the listing answers from), and deletes on that. What the Mac
    // sends back can move the token once more, so it is read again.
    let folder_id = <[u8; 16]>::try_from(folder.item_id.as_slice()).unwrap();
    let mut deleted = None;
    for _ in 0..10 {
        let (shown, _) = phone
            .node
            .state
            .replica_coordinator
            .provider_repository()
            .lookup_item(&hex::encode(&phone.root_id), &folder_id)
            .unwrap()
            .expect("the folder is listed");
        let mut token = shown.content_version.0.to_vec();
        token.extend_from_slice(&shown.generation.to_be_bytes());
        let mut delete = phone.request(ProviderChangeKind::Delete);
        delete.item_id = folder.item_id.clone();
        delete.recursive = true;
        delete.base_version_hash = token;
        let response = phone.apply(delete).await;
        if response.ok {
            deleted = Some(response);
            break;
        }
        assert_eq!(
            response.failure,
            yadorilink_ipc_proto::shellipc::ProviderApplyFailure::StaleView as i32,
            "{response:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(deleted.is_some(), "the folder was never deleted on a current token");
    wait_until_with_context(
        || {
            !mac.root.path().join("Trips").exists()
                && support::real_entry_names(mac.root.path()).is_empty()
        },
        Duration::from_secs(60),
        || format!("the delete never reached the Mac: {:?}", index_of(&mac)),
    )
    .await;
    handles.shutdown();
}

/// A reader is refused with a typed refusal and the staged file is left for the app to discard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_refused_by_role_leaves_the_staged_file_to_discard() {
    use yadorilink_ipc_proto::shellipc::ProviderApplyFailure;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    let phone = Phone::new(&fake).await;
    // Not a writer of the group: the policy names only another device.
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    phone.node.state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        GROUP.to_string(),
        fixture_group_policy_granting(&[("someone-else", other)]),
    )]));
    let bytes = content(21, 10_000);
    let source = phone.stage_moved("refused.bin", &bytes).await;
    let mut create = phone.request(ProviderChangeKind::Create);
    create.name = Some("refused.bin".into());
    create.entry_kind = EntryKind::File as i32;
    create.content = Some(source.clone());
    let response = phone.apply(create).await;
    assert!(!response.ok);
    assert_eq!(response.failure, ProviderApplyFailure::NotAuthorized as i32, "{response:?}");
    assert!(phone.ingest_dir().join(&source.ingest_name).exists());
    phone.commands.discard_staged_upload(&source.ingest_name).unwrap();
    assert!(!phone.ingest_dir().join(&source.ingest_name).exists());
}

/// The phone lists the history and the trash of files the Mac wrote and brings them back: the
/// bytes of a version the phone never held are fetched from the Mac, and the restore reaches the
/// Mac as an ordinary new write.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[cfg_attr(windows, ignore = "the provider write path stages by rename on a Unix host")]
async fn the_phone_lists_history_and_restores_what_the_mac_held() {
    use yadorilink_daemon::embedded_host::{DeletedParent, HistoryVersionState};
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let phone = Phone::new(&fake).await;
    let mac = new_node_fast("ios-mac-history");
    register_with_fake(&fake, &mac.state, &mac.device_id, &[GROUP]).await;
    link_eager(&mac, GROUP);
    fake.set_full_replica(&mac.device_id, GROUP, true);
    for node in [&phone.node, &mac] {
        fake.grant_role(&node.device_id, GROUP, WriterRole::Editor);
    }
    let mut handles = TopologyHandles::new();
    handles.insert(phone.node.device_id.clone(), spawn_orchestrator(fake.addr(), &phone.node));
    handles.insert(mac.device_id.clone(), spawn_orchestrator(fake.addr(), &mac));
    advertise_substrate_endpoints(&[&phone.node, &mac]).await;
    wait_until_with_context(
        || fully_connected(&phone.node.state, &mac.device_id),
        Duration::from_secs(60),
        || "the phone and the Mac never connected".into(),
    )
    .await;

    // The Mac writes two versions of one file and a second file that it then deletes.
    let v1 = content(31, 1_500_000);
    let v2 = content(32, 1_900_000);
    let gone = content(33, 900_000);
    let write_on_mac = |name: &str, bytes: &[u8]| {
        std::fs::write(mac.root.path().join(format!("{name}.tmp")), bytes).unwrap();
        std::fs::rename(mac.root.path().join(format!("{name}.tmp")), mac.root.path().join(name))
            .unwrap();
    };
    let phone_sees = |path: &str, size: usize| {
        phone
            .node
            .state
            .replica_coordinator
            .file_index_repository()
            .get_file(GROUP, path)
            .ok()
            .flatten()
            .is_some_and(|record| record.size == size as u64 && !record.deleted)
    };
    write_on_mac("h.bin", &v1);
    wait_until_with_context(
        || phone_sees("h.bin", v1.len()),
        Duration::from_secs(90),
        || format!("the phone never saw h.bin: {:?}", index_of(&phone.node)),
    )
    .await;
    write_on_mac("h.bin", &v2);
    write_on_mac("d.bin", &gone);
    wait_until_with_context(
        || phone_sees("h.bin", v2.len()) && phone_sees("d.bin", gone.len()),
        Duration::from_secs(90),
        || format!("the phone never saw the edit: {:?}", index_of(&phone.node)),
    )
    .await;
    std::fs::remove_file(mac.root.path().join("d.bin")).unwrap();
    wait_until_with_context(
        || {
            phone
                .commands
                .list_deleted_items(&phone.root_id)
                .is_ok_and(|listing| listing.items.iter().any(|d| d.path == "d.bin"))
        },
        Duration::from_secs(90),
        || format!("the phone never listed d.bin as deleted: {:?}", index_of(&phone.node)),
    )
    .await;

    // The file's history: two versions, the earlier one restorable and authored by the Mac.
    let root_hex = hex::encode(&phone.root_id);
    let repo = phone.node.state.replica_coordinator.provider_repository();
    let item = repo.mint_item(&root_hex, "h.bin").unwrap();
    let history = phone.commands.list_item_versions(&phone.root_id, &item).unwrap();
    assert_eq!((history.path.as_str(), history.live), ("h.bin", true));
    let current = history.versions.iter().find(|v| v.state == HistoryVersionState::Current);
    assert_eq!(current.map(|v| (v.size, v.restorable)), Some((v2.len() as u64, false)));
    let earlier = history
        .versions
        .iter()
        .find(|v| v.state == HistoryVersionState::Superseded && v.size == v1.len() as u64)
        .expect("the Mac's earlier version is listed");
    assert!(earlier.restorable);

    // Restore it: the phone does not hold those bytes, so they come from the Mac.
    let earlier_row = phone
        .node
        .state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(GROUP, "h.bin")
        .unwrap()
        .into_iter()
        .find(|v| v.version_hash.0.to_vec() == earlier.version_hash)
        .expect("the earlier version is in the phone's index");
    let held = earlier_row
        .blocks
        .iter()
        .filter(|b| phone.node.state.block_store.exists(&hex::encode(&b.hash)).unwrap_or(false))
        .count();
    assert_eq!(held, 0, "the phone never held the earlier version's bytes");
    let (shown, _) = repo.lookup_item(&root_hex, &item).unwrap().expect("listed");
    let mut token = shown.content_version.0.to_vec();
    token.extend_from_slice(&shown.generation.to_be_bytes());
    let mut restore = phone.request(ProviderChangeKind::Modify);
    restore.item_id = item.to_vec();
    restore.base_version_hash = token;
    restore.restore_from = Some(yadorilink_ipc_proto::shellipc::ProviderRestoreSource {
        path: history.path.clone(),
        version_hash: earlier.version_hash.clone(),
    });
    let restored = phone.apply(restore).await;
    assert!(restored.ok, "{restored:?}");
    assert_eq!(restored.item.as_ref().map(|i| i.size), Some(v1.len() as u64));
    // The restore is the phone's own write: the history now shows it as the live version, authored
    // here, and keeps the version it replaced.
    let after = phone.commands.list_item_versions(&phone.root_id, &item).unwrap();
    let live = after.versions.iter().find(|v| v.state == HistoryVersionState::Current).unwrap();
    assert_eq!(
        (live.size, live.origin_device_id.as_deref()),
        (v1.len() as u64, Some(phone.node.device_id.as_str()))
    );
    assert!(after.versions.iter().any(|v| v.size == v2.len() as u64), "the replaced version stays");
    wait_until_with_context(
        || read(mac.root.path(), "h.bin").is_some_and(|got| sha(&got) == sha(&v1)),
        Duration::from_secs(90),
        || format!("the Mac never got the restored bytes: {:?}", index_of(&mac)),
    )
    .await;

    // The deleted file: listed in the root, brought back by a create, then on the Mac again.
    let listing = phone.commands.list_deleted_items(&phone.root_id).unwrap();
    let entry = listing.items.iter().find(|d| d.path == "d.bin").expect("d.bin is listed");
    assert_eq!((entry.parent.clone(), entry.restorable), (DeletedParent::Root, true));
    let mut back = phone.request(ProviderChangeKind::Create);
    back.name = Some(entry.name.clone());
    back.entry_kind = EntryKind::File as i32;
    back.restore_from = Some(yadorilink_ipc_proto::shellipc::ProviderRestoreSource {
        path: entry.path.clone(),
        version_hash: entry.version_hash.clone(),
    });
    let back = phone.apply(back).await;
    assert!(back.ok, "{back:?}");
    wait_until_with_context(
        || read(mac.root.path(), "d.bin").is_some_and(|got| sha(&got) == sha(&gone)),
        Duration::from_secs(90),
        || format!("the Mac never got d.bin back: {:?}", index_of(&mac)),
    )
    .await;
    assert!(
        phone
            .commands
            .list_deleted_items(&phone.root_id)
            .unwrap()
            .items
            .iter()
            .all(|d| d.path != "d.bin"),
        "a restored file leaves the deleted list"
    );
    handles.shutdown();
}
