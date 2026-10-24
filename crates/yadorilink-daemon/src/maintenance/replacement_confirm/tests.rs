use std::sync::Mutex;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_local_capture::unreadable::{UnreadableFile, UnreadableReason};

use super::*;
use crate::durability_service::{DurabilityEvidence, GroupDurabilityStatus};
use crate::queries::link_status::{FetchAvailability, LinkTransferView};

fn view(group_id: &str) -> LinkStatusView {
    LinkStatusView {
        local_path: format!("/data/{group_id}"),
        provider: None,
        group_id: group_id.to_owned(),
        paused: false,
        paused_until_unix: 0,
        conflict_count: 0,
        conflicts_pending: 0,
        conflict_note: String::new(),
        materialization_policy: "eager".to_owned(),
        hydrated_count: 10,
        placeholder_count: 0,
        hydrating_count: 0,
        requested_content_count: 0,
        held_files: Vec::new(),
        skipped_symlink_count: 0,
        stranded_directory_count: 0,
        unreadable_files: Vec::new(),
        pending_approvals: 0,
        degraded: None,
        transfer: None,
        durability_status: GroupDurabilityStatus::Protecting,
        durability_evidence: DurabilityEvidence::None,
        durability_check_pending: false,
        policy_stale: false,
        local_storage_state: LocalStorageState::FullCopy,
        fetch_availability: FetchAvailability::AvailableNow,
        ambiguous_local_paths: Vec::new(),
        capture_volume_changed: false,
        capture_volume_unconfirmed: false,
        full_replica_device_ids: Vec::new(),
        custody_confirmed_by: Vec::new(),
    }
}

struct Fake {
    views: Mutex<Vec<LinkStatusView>>,
    answers: Mutex<Vec<ConfirmAnswer>>,
    confirms: Mutex<Vec<String>>,
    not_started: Mutex<Vec<String>>,
    entries: Mutex<std::collections::HashMap<String, Vec<ExpectedEntry>>>,
    provider: Mutex<Result<(), String>>,
    provider_asked: Mutex<Vec<String>>,
    listing: Mutex<SupersessionsAnswer>,
    listing_calls: Mutex<usize>,
}

impl Fake {
    fn new(views: Vec<LinkStatusView>, answers: Vec<ConfirmAnswer>) -> Self {
        Self {
            views: Mutex::new(views),
            answers: Mutex::new(answers),
            confirms: Mutex::new(Vec::new()),
            not_started: Mutex::new(Vec::new()),
            entries: Mutex::new(std::collections::HashMap::new()),
            provider: Mutex::new(Ok(())),
            provider_asked: Mutex::new(Vec::new()),
            listing: Mutex::new(SupersessionsAnswer::Listed(Vec::new())),
            listing_calls: Mutex::new(0),
        }
    }
}

impl ConfirmPorts for &Fake {
    fn own_device_id(&self) -> String {
        "new-device".to_owned()
    }
    fn links(&self) -> Result<Vec<LinkStatusView>, String> {
        Ok(self.views.lock().unwrap().clone())
    }
    fn group_startup_ready(&self, group_id: &str) -> bool {
        !self.not_started.lock().unwrap().iter().any(|g| g == group_id)
    }
    fn provider_content_complete(&self, root_id: &str) -> Result<(), String> {
        self.provider_asked.lock().unwrap().push(root_id.to_owned());
        self.provider.lock().unwrap().clone()
    }
    fn entry_loader(&self, group_id: &str) -> EntryLoader {
        let entries = self.entries.lock().unwrap().get(group_id).cloned().unwrap_or_default();
        Box::new(move || Ok(entries))
    }
    async fn supersessions(&self) -> SupersessionsAnswer {
        *self.listing_calls.lock().unwrap() += 1;
        self.listing.lock().unwrap().clone()
    }
    async fn confirm(&self, old_device_id: &str) -> ConfirmAnswer {
        self.confirms.lock().unwrap().push(old_device_id.to_owned());
        self.answers.lock().unwrap().remove(0)
    }
}

/// A record the person already acknowledged: the shape every confirm test below starts from.
fn record(groups: &[&str]) -> Record {
    Record { acknowledged_possible_loss: true, ..unacknowledged_record(groups) }
}

fn unacknowledged_record(groups: &[&str]) -> Record {
    Record {
        old_device_id: "old-device".into(),
        new_device_id: "new-device".into(),
        unconfirmed_group_ids: groups.iter().map(|g| (*g).to_owned()).collect(),
        acknowledged_possible_loss: false,
    }
}

fn job<'a>(fake: &'a Fake, dir: &tempfile::TempDir) -> ReplacementConfirmJob<&'a Fake> {
    ReplacementConfirmJob::new(fake, dir.path().to_path_buf())
}

#[tokio::test]
async fn without_a_record_nothing_is_asked() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(vec![view("g1")], vec![]);
    assert_eq!(job(&fake, &dir).run_once().await, Outcome::NoRecord);
    assert!(fake.confirms.lock().unwrap().is_empty());
}

#[tokio::test]
async fn data_not_synced_never_confirms_and_keeps_the_record() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let mut partial = view("g1");
    partial.local_storage_state = LocalStorageState::PartiallyMaterialized;
    partial.placeholder_count = 3;
    let fake = Fake::new(vec![partial], vec![]);
    let outcome = job(&fake, &dir).run_once().await;
    assert!(matches!(outcome, Outcome::Waiting(_)), "{outcome:?}");
    assert!(fake.confirms.lock().unwrap().is_empty());
    assert!(replacement_unconfirmed::pending(dir.path()));
}

#[tokio::test]
async fn one_unsynced_group_among_several_blocks_the_confirm() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1", "g2"])).unwrap();
    let mut on_demand = view("g2");
    on_demand.materialization_policy = "ondemand".into();
    on_demand.local_storage_state = LocalStorageState::OnDemand;
    let fake = Fake::new(vec![view("g1"), on_demand], vec![]);
    let outcome = job(&fake, &dir).run_once().await;
    assert!(matches!(&outcome, Outcome::Waiting(why) if why.starts_with("g2")), "{outcome:?}");
    assert!(fake.confirms.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_group_whose_startup_has_not_finished_blocks_the_confirm() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let fake = Fake::new(vec![view("g1")], vec![ConfirmAnswer::Confirmed]);
    fake.not_started.lock().unwrap().push("g1".into());
    let job = job(&fake, &dir);
    assert!(matches!(job.run_once().await, Outcome::Waiting(why) if why.contains("startup")));
    assert!(fake.confirms.lock().unwrap().is_empty());
    fake.not_started.lock().unwrap().clear();
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

#[tokio::test]
async fn the_reason_a_pass_waits_is_recorded_for_status_and_withdrawn_when_it_ends() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let fake = Fake::new(
        vec![view("g1")],
        vec![ConfirmAnswer::NotYetEagerMember, ConfirmAnswer::Retry, ConfirmAnswer::Confirmed],
    );
    fake.not_started.lock().unwrap().push("g1".into());
    let job = job(&fake, &dir);
    assert!(matches!(job.run_once().await, Outcome::Waiting(_)));
    let reason = replacement_unconfirmed::waiting_reason(dir.path()).unwrap();
    assert!(reason.contains("g1") && reason.contains("startup"), "{reason}");
    fake.not_started.lock().unwrap().clear();
    assert_eq!(job.run_once().await, Outcome::WaitingForMembership);
    assert!(replacement_unconfirmed::waiting_reason(dir.path()).unwrap().contains("member"));
    assert_eq!(job.run_once().await, Outcome::RetryLater);
    assert!(replacement_unconfirmed::waiting_reason(dir.path()).is_some());
    assert_eq!(job.run_once().await, Outcome::Confirmed);
    assert_eq!(replacement_unconfirmed::waiting_reason(dir.path()), None);
    assert!(!dir.path().join(replacement_unconfirmed::WAITING_FILE).exists());
}

#[tokio::test]
async fn waiting_for_the_acknowledgement_leaves_no_wait_reason() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &unacknowledged_record(&["g1"])).unwrap();
    let fake = Fake::new(vec![view("g1")], vec![]);
    let job = job(&fake, &dir);
    replacement_unconfirmed::set_waiting_reason(dir.path(), Some("stale")).unwrap();
    assert_eq!(job.run_once().await, Outcome::AwaitingAcknowledgement);
    assert_eq!(replacement_unconfirmed::waiting_reason(dir.path()), None);
}

#[tokio::test]
async fn a_group_that_is_not_linked_blocks_the_confirm() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1", "g9"])).unwrap();
    let fake = Fake::new(vec![view("g1")], vec![]);
    assert!(matches!(job(&fake, &dir).run_once().await, Outcome::Waiting(_)));
    assert!(fake.confirms.lock().unwrap().is_empty());
}

#[tokio::test]
async fn synced_confirms_once_then_removes_the_record_and_the_attention_clears() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1", "g2"])).unwrap();
    let fake = Fake::new(vec![view("g1"), view("g2")], vec![ConfirmAnswer::Confirmed]);
    let job = job(&fake, &dir);
    assert!(replacement_unconfirmed::pending(dir.path()));
    assert_eq!(job.run_once().await, Outcome::Confirmed);
    assert_eq!(*fake.confirms.lock().unwrap(), ["old-device"]);
    // The status attention reads exactly this.
    assert!(!replacement_unconfirmed::pending(dir.path()));
    // The next pass asks nothing.
    assert_eq!(job.run_once().await, Outcome::NoRecord);
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_409_keeps_waiting_and_a_later_pass_confirms() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let fake = Fake::new(
        vec![view("g1")],
        vec![ConfirmAnswer::NotYetEagerMember, ConfirmAnswer::Confirmed],
    );
    let job = job(&fake, &dir);
    assert_eq!(job.run_once().await, Outcome::WaitingForMembership);
    assert!(replacement_unconfirmed::pending(dir.path()));
    assert_eq!(job.run_once().await, Outcome::Confirmed);
    assert!(!replacement_unconfirmed::pending(dir.path()));
}

#[tokio::test]
async fn a_network_failure_retries_and_keeps_the_record() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let fake = Fake::new(vec![view("g1")], vec![ConfirmAnswer::Retry, ConfirmAnswer::Confirmed]);
    let job = job(&fake, &dir);
    assert_eq!(job.run_once().await, Outcome::RetryLater);
    assert!(replacement_unconfirmed::pending(dir.path()));
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

#[tokio::test]
async fn a_refused_sign_in_raises_the_marker_and_signing_in_again_lowers_it() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let fake = Fake::new(
        vec![view("g1")],
        vec![
            ConfirmAnswer::SignInRequired,
            ConfirmAnswer::NotYetEagerMember,
            ConfirmAnswer::Confirmed,
        ],
    );
    let job = job(&fake, &dir);
    assert_eq!(job.run_once().await, Outcome::SignInRequired);
    assert!(replacement_unconfirmed::sign_in_required(dir.path()));
    // Signed in again: the service answers something else, the request goes away.
    assert_eq!(job.run_once().await, Outcome::WaitingForMembership);
    assert!(!replacement_unconfirmed::sign_in_required(dir.path()));
    assert!(replacement_unconfirmed::pending(dir.path()));
    assert_eq!(job.run_once().await, Outcome::Confirmed);
    assert!(!dir.path().join(replacement_unconfirmed::SIGN_IN_REQUIRED_FILE).exists());
}

#[tokio::test]
async fn an_inconclusive_failure_does_not_withdraw_the_sign_in_request() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let fake =
        Fake::new(vec![view("g1")], vec![ConfirmAnswer::SignInRequired, ConfirmAnswer::Retry]);
    let job = job(&fake, &dir);
    assert_eq!(job.run_once().await, Outcome::SignInRequired);
    assert_eq!(job.run_once().await, Outcome::RetryLater);
    assert!(replacement_unconfirmed::sign_in_required(dir.path()));
}

/// A restart is a new job over the same directory: the record decides, and a confirm that landed
/// before the record could be removed is simply answered again.
#[tokio::test]
async fn after_a_restart_the_record_alone_drives_the_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let first = Fake::new(vec![view("g1")], vec![ConfirmAnswer::NotYetEagerMember]);
    assert_eq!(job(&first, &dir).run_once().await, Outcome::WaitingForMembership);
    drop(first);
    let second = Fake::new(vec![view("g1")], vec![ConfirmAnswer::Confirmed]);
    assert_eq!(job(&second, &dir).run_once().await, Outcome::Confirmed);
    assert!(!replacement_unconfirmed::pending(dir.path()));
}

#[tokio::test]
async fn a_record_for_another_device_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let mut other = record(&["g1"]);
    other.new_device_id = "someone-else".into();
    replacement_unconfirmed::write(dir.path(), &other).unwrap();
    let fake = Fake::new(vec![view("g1")], vec![]);
    assert_eq!(job(&fake, &dir).run_once().await, Outcome::RecordNotUsable);
    assert!(fake.confirms.lock().unwrap().is_empty());
    assert!(replacement_unconfirmed::pending(dir.path()));
}

#[tokio::test]
async fn an_unreadable_record_confirms_nothing_and_stays() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(replacement_unconfirmed::FILE), b"{").unwrap();
    let fake = Fake::new(vec![view("g1")], vec![]);
    assert_eq!(job(&fake, &dir).run_once().await, Outcome::RecordNotUsable);
    assert!(replacement_unconfirmed::pending(dir.path()));
}

#[test]
fn only_a_complete_running_eager_folder_counts_as_synced() {
    assert_eq!(group_is_synced(&view("g")), Ok(()));
    type Break = Box<dyn Fn(&mut LinkStatusView)>;
    let cases: Vec<(&str, Break)> = vec![
        ("provider", Box::new(|v| v.provider = Some(("root".into(), "Root".into())))),
        ("ondemand", Box::new(|v| v.materialization_policy = "ondemand".into())),
        ("partial", Box::new(|v| v.local_storage_state = LocalStorageState::PartiallyMaterialized)),
        ("on-demand state", Box::new(|v| v.local_storage_state = LocalStorageState::OnDemand)),
        ("placeholders", Box::new(|v| v.placeholder_count = 1)),
        ("hydrating", Box::new(|v| v.hydrating_count = 1)),
        ("requested", Box::new(|v| v.requested_content_count = 1)),
        (
            "transfer",
            Box::new(|v| {
                v.transfer = Some(LinkTransferView {
                    bytes_done: 1,
                    bytes_total: 2,
                    blocks_done: 1,
                    blocks_total: 2,
                    eta_seconds: None,
                })
            }),
        ),
        ("paused", Box::new(|v| v.paused = true)),
        (
            "degraded",
            Box::new(|v| {
                v.degraded = Some(crate::queries::link_status::DegradedLinkView {
                    reason: "disk".into(),
                    cause: crate::link_registry::DegradedCause::WaitingForDiskSpace,
                })
            }),
        ),
        ("ambiguous", Box::new(|v| v.ambiguous_local_paths = vec!["/a".into(), "/b".into()])),
        ("volume changed", Box::new(|v| v.capture_volume_changed = true)),
        ("volume unconfirmed", Box::new(|v| v.capture_volume_unconfirmed = true)),
        ("policy stale", Box::new(|v| v.policy_stale = true)),
        ("conflict", Box::new(|v| v.conflicts_pending = 1)),
        (
            "unreadable",
            Box::new(|v| {
                v.unreadable_files = vec![UnreadableFile {
                    path: "a".into(),
                    reason: UnreadableReason::PermissionDenied,
                }]
            }),
        ),
    ];
    for (name, break_it) in cases {
        let mut v = view("g");
        break_it(&mut v);
        assert!(group_is_synced(&v).is_err(), "{name} must not count as synced");
    }
}

/// The status reader lists the group's own folder in `ambiguous_local_paths`, so a group linked
/// once reports one path; that is the normal state and must not count as "linked twice".
#[tokio::test]
async fn a_group_linked_once_is_not_linked_twice() {
    let store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
    let sync_state =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    let root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), "g")
        .unwrap();
    let views = DaemonConfirmPorts::new(state).links().unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].ambiguous_local_paths.len(), 1, "the reader lists the folder itself");
    assert_ne!(group_is_synced(&views[0]), Err("the group is linked twice"));
    let mut twice = view("g");
    twice.ambiguous_local_paths = vec!["/a".into()];
    assert_ne!(group_is_synced(&twice), Err("the group is linked twice"));
}

#[tokio::test]
async fn complete_but_unacknowledged_never_confirms_until_the_person_acknowledges() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &unacknowledged_record(&["g1"])).unwrap();
    let fake = Fake::new(vec![view("g1")], vec![ConfirmAnswer::Confirmed]);
    let job = job(&fake, &dir);
    // Every check passes (index == disk), yet no confirm call is made, however often it runs.
    for _ in 0..3 {
        assert_eq!(job.run_once().await, Outcome::AwaitingAcknowledgement);
    }
    assert!(fake.confirms.lock().unwrap().is_empty());
    assert!(replacement_unconfirmed::pending(dir.path()));
    assert!(replacement_unconfirmed::acknowledgement_required(dir.path()));
    // Incomplete data is still reported as waiting, not as awaiting the acknowledgement.
    let mut partial = view("g1");
    partial.placeholder_count = 1;
    partial.local_storage_state = LocalStorageState::PartiallyMaterialized;
    *fake.views.lock().unwrap() = vec![partial];
    assert!(matches!(job.run_once().await, Outcome::Waiting(_)));
    *fake.views.lock().unwrap() = vec![view("g1")];
    // The acknowledgement releases the confirm; the record is cleared after the 200.
    assert!(replacement_unconfirmed::acknowledge_possible_loss(dir.path()).unwrap());
    assert_eq!(job.run_once().await, Outcome::Confirmed);
    assert_eq!(*fake.confirms.lock().unwrap(), ["old-device"]);
    assert!(!replacement_unconfirmed::pending(dir.path()));
}

#[tokio::test]
async fn the_confirm_call_carries_the_acknowledgement() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/devices/supersessions/old-device/confirm"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    confirm_supersession(
        &server.uri(),
        &yadorilink_fapi_client::test_support::offline_auth(),
        "old-device",
    )
    .await;
    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body, serde_json::json!({ "acknowledgedPossibleLoss": true }));
}

async fn confirm_against(response: ResponseTemplate) -> (ConfirmAnswer, usize) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/devices/supersessions/old-device/confirm"))
        .respond_with(response)
        .mount(&server)
        .await;
    let answer = confirm_supersession(
        &server.uri(),
        &yadorilink_fapi_client::test_support::offline_auth(),
        "old-device",
    )
    .await;
    (answer, server.received_requests().await.unwrap().len())
}

#[tokio::test]
async fn the_confirm_route_answers_are_classified() {
    let healthy = serde_json::json!({
        "oldDeviceId": "old-device", "newDeviceId": "new-device", "supersededAtUnix": 1,
        "protection": "healthy", "unconfirmedGroupIds": []
    });
    let unconfirmed = serde_json::json!({
        "oldDeviceId": "old-device", "newDeviceId": "new-device", "supersededAtUnix": 1,
        "protection": "replacement-unconfirmed", "unconfirmedGroupIds": ["g1"]
    });
    let cases = [
        (ResponseTemplate::new(200).set_body_json(healthy), ConfirmAnswer::Confirmed),
        (ResponseTemplate::new(200).set_body_json(unconfirmed), ConfirmAnswer::Retry),
        (ResponseTemplate::new(200).set_body_string("not json"), ConfirmAnswer::Retry),
        (ResponseTemplate::new(409), ConfirmAnswer::NotYetEagerMember),
        (ResponseTemplate::new(403), ConfirmAnswer::SignInRequired),
        (ResponseTemplate::new(401), ConfirmAnswer::SignInRequired),
        (ResponseTemplate::new(404), ConfirmAnswer::Retry),
        (ResponseTemplate::new(503), ConfirmAnswer::Retry),
    ];
    for (response, expected) in cases {
        let (answer, requests) = confirm_against(response).await;
        assert_eq!(requests, 1);
        assert_eq!(answer, expected);
    }
}

// ---- on-disk verification -------------------------------------------------------------------

use sha2::{Digest, Sha256};
use yadorilink_replica_domain::file::{BlockInfo, RecordKind};

fn file_entry(path: &str, content: &[u8]) -> ExpectedEntry {
    ExpectedEntry {
        path: path.to_owned(),
        kind: RecordKind::File,
        blocks: vec![BlockInfo {
            hash: Sha256::digest(content).to_vec(),
            offset: 0,
            size: content.len() as u32,
        }],
        symlink_target: None,
    }
}

/// A folder on disk holding `a.txt` and `sub/b.txt`, the group's view pointing at it, and a fake
/// whose index lists exactly those two files.
fn restored_folder() -> (tempfile::TempDir, tempfile::TempDir, Fake) {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    write_settled(root.path().join("a.txt"), b"alpha bytes").unwrap();
    write_settled(root.path().join("sub/b.txt"), b"bravo bytes").unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(state_dir.path(), &record(&["g1"])).unwrap();
    let mut v = view("g1");
    v.local_path = root.path().to_string_lossy().into_owned();
    let fake = Fake::new(vec![v], vec![ConfirmAnswer::Confirmed]);
    fake.entries.lock().unwrap().insert(
        "g1".into(),
        vec![file_entry("a.txt", b"alpha bytes"), file_entry("sub/b.txt", b"bravo bytes")],
    );
    (root, state_dir, fake)
}

async fn refused_with_disk_mismatch(root: &tempfile::TempDir, damage: impl FnOnce(&Path)) {
    let (_, state_dir, fake) = restored_folder_at(root);
    damage(root.path());
    let outcome = job(&fake, &state_dir).run_once().await;
    assert!(
        matches!(&outcome, Outcome::Waiting(why) if why.contains("does not match")),
        "{outcome:?}"
    );
    assert!(fake.confirms.lock().unwrap().is_empty(), "must not confirm");
    assert!(replacement_unconfirmed::pending(state_dir.path()));
}

fn restored_folder_at(root: &tempfile::TempDir) -> ((), tempfile::TempDir, Fake) {
    let (_, state_dir, fake) = restored_folder();
    // Repoint the fake at `root`, populated like `restored_folder`.
    std::fs::create_dir_all(root.path().join("sub")).unwrap();
    write_settled(root.path().join("a.txt"), b"alpha bytes").unwrap();
    write_settled(root.path().join("sub/b.txt"), b"bravo bytes").unwrap();
    fake.views.lock().unwrap()[0].local_path = root.path().to_string_lossy().into_owned();
    ((), state_dir, fake)
}

use std::path::Path;

#[tokio::test]
async fn a_missing_file_never_confirms() {
    let root = tempfile::tempdir().unwrap();
    refused_with_disk_mismatch(&root, |r| std::fs::remove_file(r.join("sub/b.txt")).unwrap()).await;
}

#[tokio::test]
async fn a_truncated_file_never_confirms() {
    let root = tempfile::tempdir().unwrap();
    refused_with_disk_mismatch(&root, |r| write_settled(r.join("a.txt"), b"alpha").unwrap()).await;
}

#[tokio::test]
async fn a_file_with_extra_bytes_never_confirms() {
    let root = tempfile::tempdir().unwrap();
    refused_with_disk_mismatch(&root, |r| write_settled(r.join("a.txt"), b"alpha bytes+").unwrap())
        .await;
}

#[tokio::test]
async fn a_file_with_wrong_bytes_never_confirms() {
    let root = tempfile::tempdir().unwrap();
    refused_with_disk_mismatch(&root, |r| write_settled(r.join("a.txt"), b"ALPHA bytes").unwrap())
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn an_unreadable_file_never_confirms() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    // Running as root can read anything; the check is meaningless there.
    refused_with_disk_mismatch_unless_root(&root).await;
    let _ =
        std::fs::set_permissions(root.path().join("a.txt"), std::fs::Permissions::from_mode(0o644));
}

#[cfg(unix)]
async fn refused_with_disk_mismatch_unless_root(root: &tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt;
    let (_, state_dir, fake) = restored_folder_at(root);
    let file = root.path().join("a.txt");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&file).is_ok() {
        return;
    }
    let outcome = job(&fake, &state_dir).run_once().await;
    assert!(
        matches!(&outcome, Outcome::Waiting(why) if why.contains("does not match")),
        "{outcome:?}"
    );
    assert!(fake.confirms.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_directory_where_a_file_belongs_never_confirms() {
    let root = tempfile::tempdir().unwrap();
    refused_with_disk_mismatch(&root, |r| {
        std::fs::remove_file(r.join("a.txt")).unwrap();
        std::fs::create_dir(r.join("a.txt")).unwrap();
    })
    .await;
}

#[tokio::test]
async fn a_folder_that_matches_the_index_confirms_once() {
    let (_root, state_dir, fake) = restored_folder();
    let job = job(&fake, &state_dir);
    assert_eq!(job.run_once().await, Outcome::Confirmed);
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
    assert_eq!(job.run_once().await, Outcome::NoRecord);
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_failed_verification_starts_over_and_confirms_after_the_repair() {
    let (root, state_dir, fake) = restored_folder();
    let damaged = root.path().join("a.txt");
    write_settled(&damaged, b"broken").unwrap();
    let job = job(&fake, &state_dir);
    assert!(matches!(job.run_once().await, Outcome::Waiting(_)));
    write_settled(&damaged, b"alpha bytes").unwrap();
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

fn state_of(entries: Vec<ExpectedEntry>) -> GroupState {
    GroupState::fresh(entries)
}

#[test]
fn verification_is_incremental_and_resumes_from_its_cursor() {
    let root = tempfile::tempdir().unwrap();
    let mut entries = Vec::new();
    for n in 0..5 {
        let content = format!("file {n}");
        write_settled(root.path().join(format!("f{n}")), &content).unwrap();
        entries.push(file_entry(&format!("f{n}"), content.as_bytes()));
    }
    let mut state = state_of(entries);
    assert_eq!(
        content_check::verify_step(root.path(), &mut state, u64::MAX, 2),
        Step::Progress { next: 2 }
    );
    assert_eq!(
        content_check::verify_step(root.path(), &mut state, u64::MAX, 2),
        Step::Progress { next: 4 }
    );
    assert_eq!(content_check::verify_step(root.path(), &mut state, u64::MAX, 2), Step::Complete);
    assert!(state.done);
    // The byte budget bounds a step the same way.
    let mut state = state_of(state.entries);
    assert_eq!(
        content_check::verify_step(root.path(), &mut state, 1, 100),
        Step::Progress { next: 1 }
    );
    // Damage past the cursor is found when the cursor gets there.
    std::fs::remove_file(root.path().join("f3")).unwrap();
    assert!(matches!(
        content_check::verify_step(root.path(), &mut state, u64::MAX, 100),
        Step::Failed { index: 3, .. }
    ));
}

#[test]
fn an_entry_path_outside_the_folder_fails_the_verification() {
    let root = tempfile::tempdir().unwrap();
    for bad in ["../x", "/etc/passwd", ""] {
        let mut state = state_of(vec![file_entry(bad, b"x")]);
        assert!(matches!(
            content_check::verify_step(root.path(), &mut state, u64::MAX, 10),
            Step::Failed { .. }
        ));
    }
}

#[cfg(unix)]
#[test]
fn a_parent_directory_that_is_a_link_fails_the_verification() {
    let outside = tempfile::tempdir().unwrap();
    write_settled(outside.path().join("b.txt"), b"bravo bytes").unwrap();
    let root = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("sub")).unwrap();
    let mut state = state_of(vec![file_entry("sub/b.txt", b"bravo bytes")]);
    assert!(matches!(
        content_check::verify_step(root.path(), &mut state, u64::MAX, 10),
        Step::Failed { .. }
    ));
}

#[test]
fn a_symlink_and_a_directory_are_verified_by_their_own_kind() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("d")).unwrap();
    let entries = vec![ExpectedEntry {
        path: "d".into(),
        kind: RecordKind::Directory,
        blocks: vec![],
        symlink_target: None,
    }];
    let mut state = state_of(entries.clone());
    assert_eq!(content_check::verify_step(root.path(), &mut state, u64::MAX, 10), Step::Complete);
    std::fs::remove_dir(root.path().join("d")).unwrap();
    let mut state = state_of(entries);
    assert!(matches!(
        content_check::verify_step(root.path(), &mut state, u64::MAX, 10),
        Step::Failed { .. }
    ));
}

/// The owner-specified boundary: verification succeeds, the service answers 409, the disk is
/// damaged, the retry must not confirm, and verification restarts (not done until repaired).
#[tokio::test]
async fn a_file_damaged_after_a_409_stops_the_retry_from_confirming() {
    let (root, state_dir, fake) = restored_folder();
    *fake.answers.lock().unwrap() =
        vec![ConfirmAnswer::NotYetEagerMember, ConfirmAnswer::Confirmed];
    let job = job(&fake, &state_dir);
    assert_eq!(job.run_once().await, Outcome::WaitingForMembership);
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
    // Damage: same-size different bytes, then a deletion.
    write_settled(root.path().join("a.txt"), b"ALPHA bytes").unwrap();
    let outcome = job.run_once().await;
    assert!(
        matches!(&outcome, Outcome::Waiting(why) if why.contains("does not match")),
        "{outcome:?}"
    );
    assert_eq!(fake.confirms.lock().unwrap().len(), 1, "no confirm after the corruption");
    assert!(!job.verification.lock().unwrap().get("g1").unwrap().done, "verification restarted");
    std::fs::remove_file(root.path().join("a.txt")).unwrap();
    assert!(matches!(job.run_once().await, Outcome::Waiting(_)));
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
    // Repaired: verified again, then the retry confirms.
    write_settled(root.path().join("a.txt"), b"alpha bytes").unwrap();
    assert_eq!(job.run_once().await, Outcome::Confirmed);
    assert_eq!(fake.confirms.lock().unwrap().len(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn a_same_size_rewrite_with_a_restored_mtime_is_caught_by_ctime_and_inode() {
    let (root, state_dir, fake) = restored_folder();
    *fake.answers.lock().unwrap() =
        vec![ConfirmAnswer::NotYetEagerMember, ConfirmAnswer::Confirmed];
    let job = job(&fake, &state_dir);
    assert_eq!(job.run_once().await, Outcome::WaitingForMembership);
    let file = root.path().join("a.txt");
    let mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    write_settled(&file, b"ALPHA bytes").unwrap();
    std::fs::File::options().write(true).open(&file).unwrap().set_modified(mtime).unwrap();
    assert!(matches!(job.run_once().await, Outcome::Waiting(_)));
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
}

/// Several groups, each needing more passes than any time window, all progress every pass and the
/// confirm is reached in about total / budget passes; a finished group is never redone.
#[tokio::test]
async fn several_large_groups_all_progress_each_pass_and_reach_the_confirm() {
    let state_dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(state_dir.path(), &record(&["g1", "g2", "g3"])).unwrap();
    let mut roots = Vec::new();
    let mut views = Vec::new();
    let fake = Fake::new(vec![], vec![ConfirmAnswer::Confirmed]);
    for group in ["g1", "g2", "g3"] {
        let root = tempfile::tempdir().unwrap();
        let mut list = Vec::new();
        for n in 0..30 {
            let content = format!("{group} file {n}");
            write_settled(root.path().join(format!("f{n}")), &content).unwrap();
            list.push(file_entry(&format!("f{n}"), content.as_bytes()));
        }
        let mut v = view(group);
        v.local_path = root.path().to_string_lossy().into_owned();
        views.push(v);
        fake.entries.lock().unwrap().insert(group.into(), list);
        roots.push(root);
    }
    *fake.views.lock().unwrap() = views;
    // 6 entries per pass shared by 3 groups = 2 each: 30 entries need 15 passes, not 3 * 15.
    let job = job(&fake, &state_dir).with_budgets(u64::MAX, 6);
    let mut passes = 0;
    loop {
        passes += 1;
        match job.run_once().await {
            Outcome::Confirmed => break,
            Outcome::Waiting(_) => {}
            other => panic!("{other:?}"),
        }
        assert!(passes < 40, "starved");
    }
    assert!((15..=17).contains(&passes), "{passes} passes");
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_changing_file_keeps_earlier_progress_and_never_confirms_unverified_data() {
    let (root, state_dir, fake) = restored_folder();
    let job = job(&fake, &state_dir).with_budgets(u64::MAX, 1);
    // First pass verifies a.txt only.
    assert!(matches!(job.run_once().await, Outcome::Waiting(why) if why.contains("1 of 2")));
    write_settled(root.path().join("sub/b.txt"), b"being written").unwrap();
    assert!(
        matches!(job.run_once().await, Outcome::Waiting(why) if why.contains("does not match"))
    );
    {
        let guard = job.verification.lock().unwrap();
        let state = guard.get("g1").unwrap();
        assert_eq!(state.next, 1, "progress before the failing entry is kept");
        assert!(!state.done);
    }
    assert!(fake.confirms.lock().unwrap().is_empty());
    write_settled(root.path().join("sub/b.txt"), b"bravo bytes").unwrap();
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

#[test]
fn one_edit_costs_only_the_changed_entry_not_everything_after_the_cursor() {
    let root = tempfile::tempdir().unwrap();
    let mut entries = Vec::new();
    for n in 0..30 {
        let content = format!("file number {n:02}");
        write_settled(root.path().join(format!("f{n:02}")), &content).unwrap();
        settle(&root.path().join(format!("f{n:02}")));
        entries.push(file_entry(&format!("f{n:02}"), content.as_bytes()));
    }
    let mut state = state_of(entries.clone());
    assert_eq!(content_check::verify_step(root.path(), &mut state, u64::MAX, 100), Step::Complete);
    // A legitimate edit of the first file: disk and index both change.
    write_settled(root.path().join("f00"), b"edited!!file 00").unwrap();
    entries[0] = file_entry("f00", b"edited!!file 00");
    state.resume_at = Some("f00".into());
    state.reload(entries);
    // The byte budget (20) only allows about one file to be hashed: the edit is, the rest are skipped.
    assert_eq!(content_check::verify_step(root.path(), &mut state, 20, 100), Step::Complete);
}

#[tokio::test]
async fn a_transfer_tick_does_not_move_the_cursor_back() {
    let (_root, state_dir, fake) = restored_folder();
    let job = job(&fake, &state_dir).with_budgets(u64::MAX, 1);
    assert!(matches!(job.run_once().await, Outcome::Waiting(why) if why.contains("1 of 2")));
    fake.views.lock().unwrap()[0].requested_content_count = 1;
    assert!(matches!(job.run_once().await, Outcome::Waiting(why) if why.contains("transfer")));
    assert_eq!(job.verification.lock().unwrap().get("g1").unwrap().next, 1);
    fake.views.lock().unwrap()[0].requested_content_count = 0;
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

/// Backdates a file's mtime so its stat is trusted (a file modified moments ago is "racy" and is
/// re-read instead).
fn write_settled(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), bytes)?;
    settle(path.as_ref());
    Ok(())
}

fn settle(path: &Path) {
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    std::fs::File::options().write(true).open(path).unwrap().set_modified(old).unwrap();
}

fn thirty_files(root: &Path) -> Vec<ExpectedEntry> {
    (0..30)
        .map(|n| {
            let content = format!("file number {n:02}");
            write_settled(root.join(format!("f{n:02}")), &content).unwrap();
            settle(&root.join(format!("f{n:02}")));
            file_entry(&format!("f{n:02}"), content.as_bytes())
        })
        .collect()
}

/// Skipped (fingerprint-matching) entries are free: with a budget of one hashed entry per step,
/// one edit costs about two steps, not tail / budget.
#[test]
fn skipped_entries_do_not_consume_the_entry_budget() {
    let root = tempfile::tempdir().unwrap();
    let mut entries = thirty_files(root.path());
    let mut state = state_of(entries.clone());
    while content_check::verify_step(root.path(), &mut state, u64::MAX, 1) != Step::Complete {}
    write_settled(root.path().join("f00"), b"edited!!file 00").unwrap();
    entries[0] = file_entry("f00", b"edited!!file 00");
    state.resume_at = Some("f00".into());
    state.reload(entries);
    let mut steps = 0;
    while content_check::verify_step(root.path(), &mut state, u64::MAX, 1) != Step::Complete {
        steps += 1;
        assert!(steps < 5, "a skipped entry consumed the budget");
    }
}

/// An early file rewritten on every pass (index and disk both) must not make the scan restart
/// from scratch each time: once the writes stop the confirm follows within a few passes.
#[tokio::test]
async fn a_frequently_rewritten_early_file_still_converges_to_the_confirm() {
    let state_dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(state_dir.path(), &record(&["g1"])).unwrap();
    let root = tempfile::tempdir().unwrap();
    let entries = thirty_files(root.path());
    let mut v = view("g1");
    v.local_path = root.path().to_string_lossy().into_owned();
    let fake = Fake::new(vec![v], vec![ConfirmAnswer::Confirmed]);
    fake.entries.lock().unwrap().insert("g1".into(), entries);
    let job = job(&fake, &state_dir).with_budgets(u64::MAX, 2);
    for round in 0..8 {
        let content = format!("rewritten {round:02}!!");
        write_settled(root.path().join("f00"), &content).unwrap();
        fake.entries.lock().unwrap().get_mut("g1").unwrap()[0] =
            file_entry("f00", content.as_bytes());
        assert!(matches!(job.run_once().await, Outcome::Waiting(_)), "round {round}");
    }
    let mut passes = 0;
    while job.run_once().await != Outcome::Confirmed {
        passes += 1;
        assert!(passes < 10, "did not converge");
    }
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
}

/// A fingerprint is carried over only for an entry whose whole expected content is unchanged: when
/// the index content of a path changes while the disk (and so its stat) stays identical, the old
/// disk bytes must not pass against the new index content.
#[test]
fn a_fingerprint_is_not_carried_over_when_the_indexed_content_changed() {
    let root = tempfile::tempdir().unwrap();
    let entries = thirty_files(root.path());
    let mut state = state_of(entries.clone());
    assert_eq!(content_check::verify_step(root.path(), &mut state, u64::MAX, 100), Step::Complete);
    let mut changed = entries;
    changed[3] = file_entry("f03", b"the index now says this");
    state.resume_at = Some(String::new());
    state.reload(changed);
    assert!(state.fingerprints[3].is_none());
    assert!(matches!(
        content_check::verify_step(root.path(), &mut state, u64::MAX, 100),
        Step::Failed { index: 3, .. }
    ));
}

#[tokio::test]
async fn an_index_change_after_the_snapshot_is_noticed_right_before_the_confirm() {
    let (root, state_dir, fake) = restored_folder();
    *fake.answers.lock().unwrap() =
        vec![ConfirmAnswer::NotYetEagerMember, ConfirmAnswer::Confirmed];
    let job = job(&fake, &state_dir);
    assert_eq!(job.run_once().await, Outcome::WaitingForMembership);
    // The index moves on (a peer's edit arrived and was materialized) except the disk copy here.
    fake.entries.lock().unwrap().get_mut("g1").unwrap()[0] = file_entry("a.txt", b"newer index");
    let outcome = job.run_once().await;
    assert!(
        matches!(&outcome, Outcome::Waiting(why) if why.contains("index changed")),
        "{outcome:?}"
    );
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
    write_settled(root.path().join("a.txt"), b"newer index").unwrap();
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

/// A file that changes while it is being hashed is not accepted as verified (neither by the
/// incremental step nor by the pre-confirm refresh, which both go through the same path).
#[test]
fn a_file_changed_while_it_is_hashed_is_not_accepted() {
    let root = tempfile::tempdir().unwrap();
    let mut state = state_of(vec![file_entry("a.txt", b"alpha bytes")]);
    write_settled(root.path().join("a.txt"), b"alpha bytes").unwrap();
    let file = root.path().join("a.txt");
    let result = content_check::verify_one_observed(
        root.path(),
        &mut state,
        0,
        &mut std::collections::HashSet::new(),
        &|| write_settled(&file, b"alpha bytes, then more").unwrap(),
    );
    assert!(result.is_err());
    assert!(state.fingerprints[0].is_none());
    // Left alone, the same entry verifies.
    write_settled(&file, b"alpha bytes").unwrap();
    assert!(content_check::verify_one_observed(
        root.path(),
        &mut state,
        0,
        &mut std::collections::HashSet::new(),
        &|| {}
    )
    .is_ok());
}

/// A same-size rewrite that leaves size and mtime as they were (a coarse timestamp tick, or a
/// restored mtime) is noticed by the refresh, because a file modified moments before it was
/// verified is read again rather than trusted by its stat.
#[test]
fn a_same_size_rewrite_with_the_same_mtime_is_noticed() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("a.txt");
    std::fs::write(&file, b"alpha bytes").unwrap();
    let mut state = state_of(vec![file_entry("a.txt", b"alpha bytes")]);
    assert_eq!(
        content_check::verify_step(root.path(), &mut state, u64::MAX, usize::MAX),
        Step::Complete
    );
    let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
    let write = |bytes: &[u8]| {
        std::fs::write(&file, bytes).unwrap();
        std::fs::File::options().write(true).open(&file).unwrap().set_modified(modified).unwrap();
    };
    write(b"ALPHA bytes");
    let step = content_check::refresh(root.path(), &mut state);
    assert!(matches!(step, Step::Failed { .. }), "{step:?}");
    // Repaired: verifies again.
    write(b"alpha bytes");
    assert_eq!(content_check::refresh(root.path(), &mut state), Step::Complete);
}

/// The final sweep is stat-only: it never reads content, so an entry whose recorded stat is racy
/// fails closed even though its bytes are right (a sweep that hashed would pass it), and it passes
/// once the file has settled and been verified again.
#[test]
fn the_final_sweep_never_reads_content_and_fails_closed_on_a_racy_entry() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("a.txt");
    std::fs::write(&file, b"alpha bytes").unwrap();
    let mut state = state_of(vec![file_entry("a.txt", b"alpha bytes")]);
    assert_eq!(
        content_check::verify_step(root.path(), &mut state, u64::MAX, usize::MAX),
        Step::Complete
    );
    let step = content_check::still_unchanged(root.path(), &state);
    assert!(matches!(&step, Step::Failed { why, .. } if why.contains("changed since")), "{step:?}");
    settle(&file);
    assert_eq!(content_check::refresh(root.path(), &mut state), Step::Complete);
    assert_eq!(content_check::still_unchanged(root.path(), &state), Step::Complete);
}

/// A file of a later group that is still racy while an earlier group's file is modified during
/// the later group's refresh: the stat-only sweep catches the earlier one and fails closed; the
/// racy file alone also waits, and everything confirms once both have settled.
#[tokio::test]
async fn a_racy_later_group_and_damage_to_an_earlier_one_fail_closed() {
    let state_dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(state_dir.path(), &record(&["g1", "g2"])).unwrap();
    let fake = Fake::new(vec![], vec![ConfirmAnswer::Confirmed]);
    let mut roots = Vec::new();
    let mut views = Vec::new();
    for group in ["g1", "g2"] {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("f");
        std::fs::write(&file, format!("{group} bytes")).unwrap();
        if group == "g1" {
            settle(&file);
        }
        let mut v = view(group);
        v.local_path = root.path().to_string_lossy().into_owned();
        views.push(v);
        fake.entries
            .lock()
            .unwrap()
            .insert(group.into(), vec![file_entry("f", format!("{group} bytes").as_bytes())]);
        roots.push(root);
    }
    *fake.views.lock().unwrap() = views;
    let job = job(&fake, &state_dir);
    let g1 = roots[0].path().join("f");
    *job.after_refresh.lock().unwrap() = Some(Box::new(move |group| {
        if group == "g2" {
            write_settled(&g1, b"G1 bytes").unwrap();
        }
    }));
    let outcome = job.run_once().await;
    assert!(
        matches!(&outcome, Outcome::Waiting(why) if why.contains("changed since")),
        "{outcome:?}"
    );
    *job.after_refresh.lock().unwrap() = None;
    write_settled(roots[0].path().join("f"), b"g1 bytes").unwrap();
    // g2 is still racy: waits, never confirms.
    assert!(matches!(job.run_once().await, Outcome::Waiting(_)));
    assert!(fake.confirms.lock().unwrap().is_empty(), "must not confirm");
    settle(&roots[1].path().join("f"));
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

/// A group refreshed early must still be unchanged when the last group's refresh is over: a
/// change made during a later group's (possibly long) re-hash stops the confirm.
#[tokio::test]
async fn damage_during_a_later_groups_refresh_stops_the_confirm() {
    let state_dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(state_dir.path(), &record(&["g1", "g2"])).unwrap();
    let fake = Fake::new(vec![], vec![ConfirmAnswer::Confirmed]);
    let mut roots = Vec::new();
    let mut views = Vec::new();
    for group in ["g1", "g2"] {
        let root = tempfile::tempdir().unwrap();
        write_settled(root.path().join("f"), format!("{group} bytes")).unwrap();
        let mut v = view(group);
        v.local_path = root.path().to_string_lossy().into_owned();
        views.push(v);
        fake.entries
            .lock()
            .unwrap()
            .insert(group.into(), vec![file_entry("f", format!("{group} bytes").as_bytes())]);
        roots.push(root);
    }
    *fake.views.lock().unwrap() = views;
    let job = job(&fake, &state_dir);
    let g1 = roots[0].path().join("f");
    *job.after_refresh.lock().unwrap() = Some(Box::new(move |group| {
        if group == "g2" {
            write_settled(&g1, b"G1 bytes").unwrap();
        }
    }));
    let outcome = job.run_once().await;
    assert!(
        matches!(&outcome, Outcome::Waiting(why) if why.contains("changed since")),
        "{outcome:?}"
    );
    assert!(fake.confirms.lock().unwrap().is_empty(), "must not confirm");
    // Without further interference the next pass re-hashes g1 (damaged: refused) ...
    *job.after_refresh.lock().unwrap() = None;
    assert!(matches!(job.run_once().await, Outcome::Waiting(_)));
    // ... and once repaired it confirms.
    write_settled(roots[0].path().join("f"), b"g1 bytes").unwrap();
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

// ---- re-deriving a lost record from the service ----------------------------------------------

fn supersession(old: &str, new: &str, protection: &str, groups: &[&str]) -> Supersession {
    Supersession {
        old_device_id: old.into(),
        new_device_id: new.into(),
        protection: protection.into(),
        unconfirmed_group_ids: groups.iter().map(|g| (*g).to_owned()).collect(),
    }
}

#[tokio::test]
async fn a_lost_record_is_re_created_from_the_service_and_then_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(vec![view("g1")], vec![ConfirmAnswer::Confirmed]);
    *fake.listing.lock().unwrap() = SupersessionsAnswer::Listed(vec![supersession(
        "old-device",
        "new-device",
        "replacement-unconfirmed",
        &["g1"],
    )]);
    let job = job(&fake, &dir);
    assert_eq!(job.run_once().await, Outcome::Recovered);
    assert_eq!(
        super::replacement_unconfirmed::read(dir.path()).unwrap(),
        Some(unacknowledged_record(&["g1"]))
    );
    // A recovered record is as unproven as the original: no confirm until acknowledged.
    assert_eq!(job.run_once().await, Outcome::AwaitingAcknowledgement);
    assert!(fake.confirms.lock().unwrap().is_empty());
    replacement_unconfirmed::acknowledge_possible_loss(dir.path()).unwrap();
    assert_eq!(job.run_once().await, Outcome::Confirmed);
    assert!(!replacement_unconfirmed::pending(dir.path()));
}

#[tokio::test]
async fn only_an_unconfirmed_replacement_with_this_device_as_the_new_device_is_recovered() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(vec![view("g1")], vec![]);
    *fake.listing.lock().unwrap() = SupersessionsAnswer::Listed(vec![
        supersession("o1", "someone-else", "replacement-unconfirmed", &["g1"]),
        supersession("o2", "new-device", "healthy", &[]),
        supersession("new-device", "someone-else", "replacement-unconfirmed", &["g1"]),
    ]);
    assert_eq!(job(&fake, &dir).run_once().await, Outcome::NoRecord);
    assert!(!replacement_unconfirmed::pending(dir.path()));
}

#[tokio::test]
async fn recovery_never_overwrites_an_existing_record_and_does_not_ask_then() {
    let dir = tempfile::tempdir().unwrap();
    let mut existing = record(&["g1"]);
    existing.old_device_id = "kept".into();
    replacement_unconfirmed::write(dir.path(), &existing).unwrap();
    let fake = Fake::new(vec![view("g1")], vec![ConfirmAnswer::NotYetEagerMember]);
    *fake.listing.lock().unwrap() = SupersessionsAnswer::Listed(vec![supersession(
        "other-old",
        "new-device",
        "replacement-unconfirmed",
        &["g2"],
    )]);
    job(&fake, &dir).run_once().await;
    assert_eq!(*fake.listing_calls.lock().unwrap(), 0);
    assert_eq!(replacement_unconfirmed::read(dir.path()).unwrap(), Some(existing));
}

#[tokio::test]
async fn recovery_asks_at_startup_then_only_once_per_interval() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(vec![], vec![]);
    let throttled = job(&fake, &dir);
    throttled.run_once().await;
    throttled.run_once().await;
    assert_eq!(*fake.listing_calls.lock().unwrap(), 1);
    let eager = job(&fake, &dir).with_recovery_interval(Duration::ZERO);
    eager.run_once().await;
    eager.run_once().await;
    assert_eq!(*fake.listing_calls.lock().unwrap(), 3);
}

#[tokio::test]
async fn an_unavailable_or_refused_listing_creates_nothing_and_unavailable_is_retried_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(vec![], vec![]);
    let job = job(&fake, &dir);
    *fake.listing.lock().unwrap() = SupersessionsAnswer::Unavailable;
    assert_eq!(job.run_once().await, Outcome::NoRecord);
    assert_eq!(job.run_once().await, Outcome::NoRecord);
    assert_eq!(*fake.listing_calls.lock().unwrap(), 2, "unavailable is asked again next tick");
    *fake.listing.lock().unwrap() = SupersessionsAnswer::SignInRequired;
    assert_eq!(job.run_once().await, Outcome::NoRecord);
    assert_eq!(job.run_once().await, Outcome::NoRecord);
    assert_eq!(*fake.listing_calls.lock().unwrap(), 3, "a refused sign-in waits for the interval");
    assert!(!replacement_unconfirmed::pending(dir.path()));
}

#[tokio::test]
async fn recovery_is_idempotent_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(vec![view("g1")], vec![ConfirmAnswer::NotYetEagerMember]);
    *fake.listing.lock().unwrap() = SupersessionsAnswer::Listed(vec![supersession(
        "old-device",
        "new-device",
        "replacement-unconfirmed",
        &["g1"],
    )]);
    assert_eq!(job(&fake, &dir).run_once().await, Outcome::Recovered);
    // A restarted daemon sees the record and does not ask the service again.
    assert_eq!(job(&fake, &dir).run_once().await, Outcome::AwaitingAcknowledgement);
    assert_eq!(*fake.listing_calls.lock().unwrap(), 1);
    assert_eq!(
        replacement_unconfirmed::read(dir.path()).unwrap(),
        Some(unacknowledged_record(&["g1"]))
    );
}

#[tokio::test]
async fn the_supersessions_route_answers_are_classified() {
    let body = serde_json::json!({ "supersessions": [
        { "oldDeviceId": "o", "newDeviceId": "n", "supersededAtUnix": 1,
          "protection": "replacement-unconfirmed", "unconfirmedGroupIds": ["g1"] },
        { "oldDeviceId": "o2", "newDeviceId": "n", "supersededAtUnix": 2,
          "protection": "healthy", "unconfirmedGroupIds": [] }
    ]});
    let cases = [
        (
            ResponseTemplate::new(200).set_body_json(body),
            SupersessionsAnswer::Listed(vec![
                supersession("o", "n", "replacement-unconfirmed", &["g1"]),
                supersession("o2", "n", "healthy", &[]),
            ]),
        ),
        (ResponseTemplate::new(200).set_body_string("nope"), SupersessionsAnswer::Unavailable),
        (ResponseTemplate::new(401), SupersessionsAnswer::SignInRequired),
        (ResponseTemplate::new(403), SupersessionsAnswer::SignInRequired),
        (ResponseTemplate::new(503), SupersessionsAnswer::Unavailable),
    ];
    for (response, expected) in cases {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/supersessions"))
            .respond_with(response)
            .mount(&server)
            .await;
        let answer = fetch_supersessions(
            &server.uri(),
            &yadorilink_fapi_client::test_support::offline_auth(),
        )
        .await;
        assert_eq!(answer, expected);
    }
}

// ---- provider folders --------------------------------------------------------------------------

fn provider_view(group_id: &str) -> LinkStatusView {
    let mut v = view(group_id);
    v.provider = Some((format!("root-{group_id}"), "Photos".into()));
    v.local_path = format!("provider://root-{group_id}");
    // A provider root's index rows are not the OS copy: they may read as placeholders.
    v.local_storage_state = LocalStorageState::PartiallyMaterialized;
    v.placeholder_count = 7;
    v
}

#[tokio::test]
async fn a_provider_only_group_confirms_once_the_provider_evidence_is_complete() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let fake = Fake::new(vec![provider_view("g1")], vec![ConfirmAnswer::Confirmed]);
    assert_eq!(job(&fake, &dir).run_once().await, Outcome::Confirmed);
    assert_eq!(*fake.provider_asked.lock().unwrap(), ["root-g1"]);
    assert_eq!(fake.confirms.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_provider_group_whose_content_is_not_complete_never_confirms() {
    let dir = tempfile::tempdir().unwrap();
    replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
    let fake = Fake::new(vec![provider_view("g1")], vec![ConfirmAnswer::Confirmed]);
    *fake.provider.lock().unwrap() = Err("3 files are not downloaded yet".into());
    let job = job(&fake, &dir);
    let outcome = job.run_once().await;
    assert!(
        matches!(&outcome, Outcome::Waiting(why) if why.contains("not downloaded")),
        "{outcome:?}"
    );
    assert!(fake.confirms.lock().unwrap().is_empty());
    *fake.provider.lock().unwrap() = Ok(());
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

#[tokio::test]
async fn a_provider_group_that_is_not_running_eager_never_confirms() {
    type Break = Box<dyn Fn(&mut LinkStatusView)>;
    let cases: Vec<(&str, Break)> = vec![
        ("ondemand", Box::new(|v| v.materialization_policy = "ondemand".into())),
        ("hydrating", Box::new(|v| v.hydrating_count = 1)),
        ("requested", Box::new(|v| v.requested_content_count = 1)),
        ("paused", Box::new(|v| v.paused = true)),
        ("policy stale", Box::new(|v| v.policy_stale = true)),
        ("conflict", Box::new(|v| v.conflicts_pending = 1)),
        (
            "held",
            Box::new(|v| {
                v.held_files = vec![crate::queries::link_status::HeldFileView {
                    path: "a".into(),
                    reason: "x".into(),
                    held_since_unix_nanos: 0,
                }]
            }),
        ),
    ];
    for (name, break_it) in cases {
        let dir = tempfile::tempdir().unwrap();
        replacement_unconfirmed::write(dir.path(), &record(&["g1"])).unwrap();
        let mut v = provider_view("g1");
        break_it(&mut v);
        let fake = Fake::new(vec![v], vec![ConfirmAnswer::Confirmed]);
        assert!(matches!(job(&fake, &dir).run_once().await, Outcome::Waiting(_)), "{name}");
        assert!(fake.confirms.lock().unwrap().is_empty(), "{name}");
    }
}

#[tokio::test]
async fn a_mixed_group_set_needs_the_disk_and_the_provider_evidence() {
    let (_root, state_dir, fake) = restored_folder();
    replacement_unconfirmed::write(state_dir.path(), &record(&["g1", "g2"])).unwrap();
    fake.views.lock().unwrap().push(provider_view("g2"));
    *fake.provider.lock().unwrap() = Err("downloads are running".into());
    let job = job(&fake, &state_dir);
    assert!(matches!(job.run_once().await, Outcome::Waiting(why) if why.starts_with("g2")));
    assert!(fake.confirms.lock().unwrap().is_empty());
    *fake.provider.lock().unwrap() = Ok(());
    assert_eq!(job.run_once().await, Outcome::Confirmed);
}

#[test]
fn the_folder_predicate_still_refuses_a_provider_folder() {
    assert!(group_is_synced(&provider_view("g")).is_err());
    assert_eq!(provider_group_is_synced(&provider_view("g")), Ok(()));
    assert!(provider_group_is_synced(&view("g")).is_err());
}
