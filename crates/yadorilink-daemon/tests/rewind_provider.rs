//! Folder Rewind on a provider (File Provider) folder: the same plan, the same chunked commit and
//! the same safety stops as for a linked folder, under the provider root's own lease (the one the
//! provider write path admits through), not a folder path the root does not have.
//!
//! The "phone/Mac" is one device with a provider link and a declared root, written through the
//! embedded host's write commands exactly as the app writes it.

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use yadorilink_daemon::change_policy::{GroupPolicyState, WriterRole};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::embedded_host::{ApplyChange, EngineCommands, StageMode, StageSource};
use yadorilink_daemon::rewind::{
    execute_rewind, prepare_rewind, preview_rewind, RewindExecuteRequest, RewindHook, RewindPoint,
};
use yadorilink_ipc_proto::shellipc::{
    EntryKind, ProviderAppliedItem, ProviderApplyChangeRequest, ProviderChangeKind,
    ProviderContentSource,
};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::rewind::{RewindFailureKind, RewindRunState};
use yadorilink_replica_domain::session_state::ProviderKind;
use yadorilink_sync_sqlite::provider::{ProviderDeclaration, ProviderLinkSpec};

const GROUP: &str = "rewind-provider-group";
const SESSION: [u8; 16] = [9; 16];

struct Provider {
    state: Arc<DaemonState>,
    commands: EngineCommands,
    root_id: Vec<u8>,
    temp: tempfile::TempDir,
    seq: std::sync::atomic::AtomicU64,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

impl Provider {
    fn new() -> Self {
        support::ensure_isolated_config_dir();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let (coordinator, index_dir) = support::open_file_backed_replica_coordinator();
        let state = yadorilink_daemon::test_support::isolated_daemon_state(
            "provider-a".into(),
            Arc::new(coordinator),
            store,
        );
        support::ensure_device_signing_key(&state);
        state.authority.install_test_group_policy(
            GROUP,
            GroupPolicyState::with_members_for_tests(&[("provider-a", WriterRole::Editor)]),
        );
        state
            .replica_coordinator
            .link_repository()
            .add_provider_link(
                "provider://rewind",
                GROUP,
                &ProviderLinkSpec {
                    kind: ProviderKind::MacFileProvider,
                    display_name: "Folder".into(),
                    empty_owner: false,
                    on_demand: false,
                    creation_digest: "test".into(),
                },
            )
            .unwrap();
        let ProviderDeclaration::Provider(root) =
            state.replica_coordinator.provider_repository().declaration_for_group(GROUP).unwrap()
        else {
            panic!("the provider link declares its root");
        };
        let temp = tempfile::tempdir().unwrap();
        let commands =
            EngineCommands::for_state_with_temp_root_for_test(state.clone(), temp.path());
        Provider {
            state,
            commands,
            root_id: hex::decode(root.root_id).unwrap(),
            temp,
            seq: std::sync::atomic::AtomicU64::new(1),
            _dirs: (store_dir, index_dir),
        }
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

    async fn stage(&self, name: &str, bytes: &[u8]) -> ProviderContentSource {
        // Named after this provider's own temp directory: the tests of this file share the
        // directory above it, and a staged file is moved away.
        let owner = self.temp.path().file_name().unwrap().to_string_lossy().into_owned();
        let picked = self
            .temp
            .path()
            .parent()
            .unwrap()
            .join(format!("picked-{owner}-{name}-{}", bytes.len()));
        std::fs::write(&picked, bytes).unwrap();
        let staged = self
            .commands
            .stage_upload(StageSource::Path(picked), StageMode::Move)
            .await
            .expect("staged");
        ProviderContentSource {
            ingest_name: staged.ingest_name,
            size: staged.size,
            sha256: Sha256::digest(bytes).to_vec(),
        }
    }

    async fn create(&self, name: &str, text: &str) -> ProviderAppliedItem {
        let mut create = self.request(ProviderChangeKind::Create);
        create.name = Some(name.into());
        create.entry_kind = EntryKind::File as i32;
        create.content = Some(self.stage(name, text.as_bytes()).await);
        let response = self.commands.apply_change(ApplyChange(create)).await.0;
        assert!(response.ok, "{response:?}");
        response.item.unwrap()
    }

    async fn modify(&self, item: &ProviderAppliedItem, text: &str) {
        let mut modify = self.request(ProviderChangeKind::Modify);
        modify.item_id = item.item_id.clone();
        modify.base_version_hash = item.content_version.clone();
        modify.content = Some(self.stage("edit", text.as_bytes()).await);
        let response = self.commands.apply_change(ApplyChange(modify)).await.0;
        assert!(response.ok, "{response:?}");
    }

    async fn delete(&self, item: &ProviderAppliedItem) {
        let mut delete = self.request(ProviderChangeKind::Delete);
        delete.item_id = item.item_id.clone();
        delete.base_version_hash = item.content_version.clone();
        let response = self.commands.apply_change(ApplyChange(delete)).await.0;
        assert!(response.ok, "{response:?}");
    }

    /// Path -> (live, content hash of the current version).
    fn index(&self) -> BTreeMap<String, bool> {
        self.state
            .replica_coordinator
            .file_index_repository()
            .list_files_with_kind(GROUP)
            .unwrap()
            .into_iter()
            .map(|(row, _)| (row.path, !row.deleted))
            .collect()
    }

    fn sizes(&self) -> BTreeMap<String, u64> {
        self.state
            .replica_coordinator
            .file_index_repository()
            .list_files_with_kind(GROUP)
            .unwrap()
            .into_iter()
            .filter(|(row, _)| !row.deleted)
            .map(|(row, _)| (row.path, row.size))
            .collect()
    }

    async fn wait_sizes(&self, expected: &BTreeMap<String, u64>) {
        support::wait_until_with_context(
            || self.sizes() == *expected,
            Duration::from_secs(30),
            || format!("the index never reached {expected:?}: {:?}", self.sizes()),
        )
        .await;
    }

    fn own_deltas(&self) -> i64 {
        let database = self.state.replica_coordinator.database();
        let conn = database.pool_for_test().get().unwrap();
        conn.query_row(
            "SELECT count(*) FROM native_delta_log WHERE group_id = ?1 AND author = ?2",
            [GROUP, "provider-a"],
            |r| r.get(0),
        )
        .unwrap()
    }

    async fn request_for(
        &self,
        target: i64,
    ) -> (RewindExecuteRequest, yadorilink_replica_domain::rewind::RewindActionCounts) {
        let preview =
            preview_rewind(self.state.clone(), GROUP.into(), target, false).await.unwrap();
        (
            RewindExecuteRequest {
                group_id: GROUP.into(),
                target_unix_nanos: target,
                plan_id: preview.plan_id,
            },
            preview.counts,
        )
    }

    fn latest_run(&self) -> yadorilink_replica_domain::rewind::RewindRun {
        self.state.replica_coordinator.rewind_run_repository().latest_run(GROUP).unwrap().unwrap()
    }
}

async fn target_now() -> i64 {
    tokio::time::sleep(Duration::from_millis(20)).await;
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        as i64;
    tokio::time::sleep(Duration::from_millis(20)).await;
    at
}

/// Three files, then a mass edit (one overwritten, one deleted, one created). Returns the target
/// and the items.
async fn history(p: &Provider) -> (i64, ProviderAppliedItem, ProviderAppliedItem) {
    let report = p.create("report.txt", "report as it was").await;
    let notes = p.create("notes.txt", "notes as they were").await;
    let target = target_now().await;
    p.modify(&report, "ENCRYPTED").await;
    p.delete(&notes).await;
    p.create("ransom.txt", "pay up").await;
    (target, report, notes)
}

fn sizes(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(p, s)| (p.to_string(), *s)).collect()
}

/// The provider root has a lease of its own, the one object every author of the group admits
/// through, and no folder runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(windows, ignore = "the provider write path stages by rename on a Unix host")]
async fn a_provider_group_has_one_shared_authoring_lease() {
    let p = Provider::new();
    let first = p.state.authoring_root_lease_for(GROUP).expect("a lease for the provider root");
    let second = p.state.authoring_root_lease_for(GROUP).unwrap();
    assert!(Arc::ptr_eq(&first, &second), "one lease, so one mutual exclusion");
    assert!(
        p.state.authoring_root_lease_for("some-other-group").is_none(),
        "unknown groups fail closed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(windows, ignore = "the provider write path stages by rename on a Unix host")]
async fn a_rewind_restores_and_removes_files_of_a_provider_folder() {
    let p = Provider::new();
    let (target, _, _) = history(&p).await;
    assert_eq!(p.sizes(), sizes(&[("report.txt", 9), ("ransom.txt", 6)]));

    let (request, counts) = p.request_for(target).await;
    assert_eq!((counts.replace, counts.create, counts.delete), (1, 1, 1), "{counts:?}");
    let prepared = prepare_rewind(p.state.clone(), request.clone()).await.unwrap();
    let ended = execute_rewind(p.state.clone(), prepared, None).await;
    assert_eq!(ended, Some(RewindRunState::Done), "{:?}", p.latest_run().message());
    let run = p.latest_run();
    assert_eq!((run.restored, run.chunks_done, run.chunks_total), (2, 1, 1));
    p.wait_sizes(&sizes(&[("report.txt", 16), ("notes.txt", 18)])).await;
    assert_eq!(p.index().get("ransom.txt"), Some(&false));

    // A fixed point.
    let (_, counts) = p.request_for(target).await;
    assert_eq!(counts.create + counts.delete + counts.replace, 0, "{counts:?}");
}

/// A change made after the plan was prepared, to a path the rewind restores: nothing is committed
/// and the change stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(windows, ignore = "the provider write path stages by rename on a Unix host")]
async fn a_change_after_the_plan_stops_a_provider_rewind_and_is_kept() {
    let p = Provider::new();
    let (target, report, _) = history(&p).await;
    let (request, _) = p.request_for(target).await;
    let prepared = prepare_rewind(p.state.clone(), request).await.unwrap();

    // The report is edited again (a fresh base: the one the earlier modify produced).
    let shown = p
        .state
        .replica_coordinator
        .provider_repository()
        .lookup_item(
            &hex::encode(&p.root_id),
            &<[u8; 16]>::try_from(report.item_id.as_slice()).unwrap(),
        )
        .unwrap()
        .expect("listed");
    let mut token = shown.0.content_version.0.to_vec();
    token.extend_from_slice(&shown.0.generation.to_be_bytes());
    let mut modify = p.request(ProviderChangeKind::Modify);
    modify.item_id = report.item_id.clone();
    modify.base_version_hash = token;
    modify.content = Some(p.stage("late", b"edited while prepared").await);
    assert!(p.commands.apply_change(ApplyChange(modify)).await.0.ok);
    let deltas = p.own_deltas();

    let ended = execute_rewind(p.state.clone(), prepared, None).await;
    assert_eq!(ended, Some(RewindRunState::Failed));
    assert_eq!(p.latest_run().failure_kind, Some(RewindFailureKind::FolderChanged));
    assert_eq!(p.own_deltas(), deltas, "zero mutations");
    assert_eq!(p.sizes().get("report.txt"), Some(&21), "the later edit is kept");
}

/// A crash before the first chunk commits: the row is settled on restart as needing a new
/// preview, nothing was authored, and a new preview then completes the rewind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(windows, ignore = "the provider write path stages by rename on a Unix host")]
async fn a_crash_mid_run_is_settled_and_a_new_preview_completes_a_provider_rewind() {
    let p = Provider::new();
    let (target, _, _) = history(&p).await;
    let (request, _) = p.request_for(target).await;
    let prepared = prepare_rewind(p.state.clone(), request).await.unwrap();
    let deltas = p.own_deltas();

    let crash: RewindHook = Arc::new(|point| point != RewindPoint::BeforeChunk(0));
    assert_eq!(execute_rewind(p.state.clone(), prepared, Some(crash)).await, None);
    let runs = p.state.replica_coordinator.rewind_run_repository();
    assert_eq!(runs.interrupt_unfinished_runs().unwrap(), 1);
    assert_eq!(
        p.latest_run().state,
        RewindRunState::Failed,
        "no chunk committed: failed, not replan"
    );
    assert_eq!(p.own_deltas(), deltas, "settling authors nothing");
    assert_eq!(p.sizes(), sizes(&[("report.txt", 9), ("ransom.txt", 6)]), "nothing changed");

    let (request, _) = p.request_for(target).await;
    let prepared = prepare_rewind(p.state.clone(), request).await.unwrap();
    assert_eq!(execute_rewind(p.state.clone(), prepared, None).await, Some(RewindRunState::Done));
    p.wait_sizes(&sizes(&[("report.txt", 16), ("notes.txt", 18)])).await;
}
