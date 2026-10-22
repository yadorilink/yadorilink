#![cfg(test)]

//! The provider channel on the shell socket: root listing (with registration order),
//! readiness evidence from the host app and the extension.

use std::sync::Arc;

use yadorilink_ipc_proto::shellipc::{
    DomainEvidence, ExtensionHandshake, HydrationPolicy, ListProviderFoldersRequest,
    ProviderDomainState, ProviderError,
};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::{
    MaterializationPolicy, NotReady, ProviderKind, Readiness,
};

use yadorilink_sync_sqlite::provider::ProviderDeclaration;

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

use super::*;

const GROUP: &str = "group-1";

pub(super) fn state_with_root() -> (Arc<DaemonState>, String) {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    state.replica_coordinator.link_repository().add_link("/provider/photos", GROUP).unwrap();
    let root = state
        .replica_coordinator
        .provider_repository()
        .declare_root(GROUP, ProviderKind::MacFileProvider, "Photos")
        .unwrap();
    (state, root)
}

fn readiness(state: &DaemonState) -> Readiness {
    match state.replica_coordinator.provider_repository().declaration_for_group(GROUP).unwrap() {
        ProviderDeclaration::Provider(root) => root.readiness(),
        other => panic!("not a provider root: {other:?}"),
    }
}

pub(super) async fn send(state: &Arc<DaemonState>, payload: Payload) -> Option<ShellIpcMessage> {
    handle_message(
        &ShellContext::from_state(state.clone()),
        ShellIpcMessage { payload: Some(payload) },
    )
    .await
}

async fn folders(state: &Arc<DaemonState>) -> ListProviderFoldersResponse {
    let response = send(
        state,
        Payload::ListProviderFoldersRequest(ListProviderFoldersRequest {
            app_group_container: String::new(),
        }),
    )
    .await
    .unwrap();
    let Some(Payload::ListProviderFoldersResponse(response)) = response.payload else {
        panic!("expected a ListProviderFoldersResponse")
    };
    response
}

/// Registration order: the OS caches an empty root listing, so the daemon says
/// `registration_ready = false` until the root's children are queryable, and the root
/// is identified by `root_id`, never a path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_ready_is_false_until_the_namespace_is_queryable() {
    let (state, root) = state_with_root();

    let before = folders(&state).await;
    assert!(before.snapshot_available);
    assert_eq!(before.folders.len(), 1);
    let folder = &before.folders[0];
    assert_eq!(hex::encode(&folder.root_id), root);
    assert_eq!(folder.display_name, "Photos");
    assert_eq!(folder.hydration_policy, HydrationPolicy::Eager as i32);
    assert!(!folder.registration_ready, "registered before the namespace was queryable");

    state.replica_coordinator.provider_repository().set_namespace_ready(&root, true).unwrap();
    assert!(folders(&state).await.folders[0].registration_ready);

    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy("/provider/photos", MaterializationPolicy::OnDemand)
        .unwrap();
    assert_eq!(folders(&state).await.folders[0].hydration_policy, HydrationPolicy::OnDemand as i32);
}

/// The listing carries the root's permission itself, so an EMPTY folder and a folder not yet
/// enumerated know their role: a Viewer is read-only, an Editor or Owner is writable, and a role change
/// shows on the next listing. One rule with the items' `read_only`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listing_reports_the_roots_permission() {
    use crate::change_policy::{GroupPolicyState, WriterRole};
    let (state, _root) = state_with_root();
    let set_role = |role| {
        state.authority.install_test_group_policy(
            GROUP,
            GroupPolicyState::with_members_for_tests(&[("device-a", role)]),
        );
    };
    for (role, read_only) in [
        (WriterRole::Viewer, true),
        (WriterRole::Editor, false),
        (WriterRole::Viewer, true),
        (WriterRole::Owner, false),
    ] {
        set_role(role);
        let listed = folders(&state).await.folders;
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].read_only, read_only,
            "wrong permission for {role:?} on an empty root"
        );
    }
    // A group whose policy is withheld is not writable: unknown is read-only.
    state.mark_group_policy_stale(GROUP);
    assert!(folders(&state).await.folders[0].read_only, "a withheld policy listed as writable");
}

/// A plain root, and an orphaned one, are not provider folders.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_and_orphaned_roots_are_not_listed() {
    let (state, _root) = state_with_root();
    state.replica_coordinator.link_repository().add_link("/plain", "group-2").unwrap();
    assert_eq!(folders(&state).await.folders.len(), 1, "a plain root was listed");

    state.replica_coordinator.link_repository().mark_link_orphaned("/provider/photos").unwrap();
    assert!(folders(&state).await.folders.is_empty(), "an orphaned root was listed");
}

pub(super) fn evidence_of(registered: bool) -> DomainEvidence {
    if registered {
        DomainEvidence::Registered
    } else {
        DomainEvidence::Removed
    }
}

pub(super) fn domain_state(root_id: &[u8], registered: bool) -> Payload {
    // `false` in these tests means a confirmed removal (the only way a root is replaced).
    Payload::ProviderDomainState(ProviderDomainState {
        root_id: root_id.to_vec(),
        evidence: evidence_of(registered) as i32,
        preserved_location: String::new(),
        last_acked_namespace_revision: 0,
    })
}

pub(super) fn handshake(root_id: &[u8]) -> Payload {
    Payload::ExtensionHandshake(ExtensionHandshake {
        root_id: root_id.to_vec(),
        extension_build: "1".into(),
    })
}

/// Readiness is evidence from the two reporters, in order, with no timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readiness_comes_from_domain_state_handshake_and_error() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    assert_eq!(readiness(&state), Readiness::NotReady(NotReady::DomainNotRegistered));

    send(&state, domain_state(&root_id, true)).await;
    assert_eq!(readiness(&state), Readiness::NotReady(NotReady::ExtensionNotEnabled));

    send(&state, handshake(&root_id)).await;
    assert_eq!(readiness(&state), Readiness::Ready);

    // Nothing arriving is not evidence: a ready root stays ready.
    assert_eq!(readiness(&state), Readiness::Ready);

    send(
        &state,
        Payload::ProviderError(ProviderError {
            root_id: root_id.clone(),
            description: "bad domain".into(),
        }),
    )
    .await;
    assert_eq!(
        readiness(&state),
        Readiness::NotReady(NotReady::ProviderError("bad domain".into()))
    );
}

/// A domain removal rebootstraps the root: the NEXT registration is a new root_id, so a stale
/// extension's delayed handshake for the old one is ignored and cannot ready the new domain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_handshake_cannot_ready_a_re_registered_domain() {
    let (state, root) = state_with_root();
    let old = hex::decode(&root).unwrap();
    send(&state, domain_state(&old, true)).await;
    send(&state, handshake(&old)).await;
    assert_eq!(readiness(&state), Readiness::Ready);

    // The host removes the domain; the root is replaced by a new one.
    send(&state, domain_state(&old, false)).await;
    let new = folders(&state).await.folders[0].root_id.clone();
    assert_ne!(new, old, "a removal did not issue a new root_id");
    assert_eq!(readiness(&state), Readiness::NotReady(NotReady::DomainNotRegistered));
    send(&state, domain_state(&new, true)).await;

    // The old extension's delayed handshake names the old root and is ignored.
    send(&state, handshake(&old)).await;
    assert_eq!(
        readiness(&state),
        Readiness::NotReady(NotReady::ExtensionNotEnabled),
        "a stale handshake marked the new domain ready"
    );
    send(&state, handshake(&new)).await;
    assert_eq!(readiness(&state), Readiness::Ready);
}

/// Evidence for a root that does not exist is ignored (and never creates one).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evidence_for_an_unknown_root_is_ignored() {
    let (state, _root) = state_with_root();
    send(&state, handshake(&[9; 16])).await;
    assert_eq!(readiness(&state), Readiness::NotReady(NotReady::DomainNotRegistered));
    assert_eq!(
        state.replica_coordinator.provider_repository().list_declared_roots().unwrap().len(),
        1
    );
}

// ---- the publication channel end to end over the shell connection's message handling ----

use yadorilink_ipc_proto::shellipc::{EvictResult, ProviderEvictDone, ProviderSignalDone};
use yadorilink_sync_sqlite::provider::Publication;

fn commit(state: &DaemonState, path: &str, seq: i64, size: i64) {
    let blocks = format!(r#"[{{"hash":{:?},"offset":0,"size":{size}}}]"#, vec![size as u8; 32]);
    state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
                 AND state = 'current'",
                rusqlite::params![GROUP, path],
            )?;
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state) VALUES (?1, ?2, ?3, 1, ?5, 0, ?4, 'current')",
                rusqlite::params![GROUP, path, size, seq, blocks],
            )?;
            let row = yadorilink_sync_sqlite::read_canonical_current_row(tx, GROUP, path)?.unwrap();
            let version =
                yadorilink_replica_domain::session_state::CurrentVersionRecord::from(row.snapshot)
                    .to_file_version();
            yadorilink_sync_sqlite::dag_store::put_file_version(tx, GROUP, &version)?;
            Ok(())
        })
        .unwrap();
}

/// The host app attaches with its domain state: the pending publication is REPLAYED to it
/// (evict request, then signal), and each step completes when the app's acknowledgement arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnecting_host_is_sent_every_pending_publication() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    commit(&state, "a.txt", 1, 10);
    let repo = state.replica_coordinator.provider_repository();
    let item = repo.mint_item(&root, "a.txt").unwrap();
    let served = repo.current_version_hash(&root, &item).unwrap().unwrap();
    repo.publish_first(&root, &item, served).unwrap();
    // The setup is not a namespace change this test wants announced.
    if let Some(changes) = repo.unannounced_changes(&root).unwrap() {
        repo.mark_announced(&root, changes).unwrap();
    }
    commit(&state, "a.txt", 2, 99);
    assert_eq!(repo.publication(&root, &item).unwrap(), Some(Publication::ContentPending));

    let context = ShellContext::from_state(state.clone());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    let consumed = provider_channel_message(
        &context,
        &tx,
        &ShellIpcMessage {
            payload: Some(Payload::ProviderDomainState(ProviderDomainState {
                root_id: root_id.clone(),
                evidence: DomainEvidence::Registered as i32,
                preserved_location: String::new(),
                last_acked_namespace_revision: 0,
            })),
        },
    )
    .await;
    assert!(!consumed, "the domain state must still be recorded");

    let Payload::ProviderEvictRequest(request) = next_payload(&mut rx).await else {
        panic!("the first replayed step must be the eviction")
    };
    assert_eq!(request.item_id, item.to_vec());
    // While the eviction is outstanding nothing is published and the OS still sees V1.
    assert_eq!(repo.publication(&root, &item).unwrap(), Some(Publication::ContentPending));
    context.provider_host.complete_evict(&ProviderEvictDone {
        root_id: root_id.clone(),
        request_id: request.request_id.clone(),
        result: EvictResult::Evicted as i32,
        error: String::new(),
    });
    let Payload::ProviderChanged(changed) = next_payload(&mut rx).await else {
        panic!("the signal must follow the eviction")
    };
    assert_eq!(changed.changed_item_ids, [item.to_vec()]);
    assert_eq!(changed.namespace_revision, 1);
    assert_eq!(repo.publication(&root, &item).unwrap(), Some(Publication::ContentPending));
    context.provider_host.complete_signal(&ProviderSignalDone {
        root_id: root_id.clone(),
        namespace_revision: changed.namespace_revision,
        ok: true,
        error: String::new(),
        request_id: changed.request_id.clone(),
    });
    context.publication.idle().await;
    assert_eq!(repo.publication(&root, &item).unwrap(), Some(Publication::Published));
}

/// A host that acknowledged a higher revision than the daemon has means the daemon's database
/// was restored: the root is replaced (new root_id, no items) and the host is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rolled_back_database_is_detected_and_the_root_rebootstrapped() {
    let (state, root) = state_with_root();
    state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO provider_change_events (root_id, seq, kind, item_id, parent_item_id, \
                 at_s) VALUES (?1, 1, 'upsert', x'00', x'', 0)",
                [&root],
            )?;
            tx.execute("UPDATE provider_roots SET namespace_revision = 1", [])?;
            Ok(())
        })
        .unwrap();
    let context = ShellContext::from_state(state.clone());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();

    let consumed = provider_channel_message(
        &context,
        &tx,
        &ShellIpcMessage {
            payload: Some(Payload::ProviderDomainState(ProviderDomainState {
                root_id: hex::decode(&root).unwrap(),
                evidence: DomainEvidence::Registered as i32,
                preserved_location: String::new(),
                last_acked_namespace_revision: 7,
            })),
        },
    )
    .await;
    assert!(consumed);
    // The connected host is prompted to list again (the new root is not in its list yet); it
    // removes the old domain because the old root_id is absent from the next snapshot.
    let Payload::ProviderChanged(prompt) = next_payload(&mut rx).await else {
        panic!("the host was not prompted to list again")
    };
    assert!(prompt.changed_item_ids.is_empty());
    assert_eq!(prompt.root_id, hex::decode(readiness_root(&state)).unwrap());
    let listed = folders(&state).await.folders;
    assert_eq!(listed.len(), 1);
    assert_ne!(listed[0].root_id, hex::decode(&root).unwrap(), "the old root is still listed");
    assert_ne!(readiness_root(&state), root, "the root was not replaced");
}

async fn next_payload(rx: &mut tokio::sync::mpsc::UnboundedReceiver<ShellIpcMessage>) -> Payload {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the daemon sent nothing")
        .unwrap()
        .payload
        .unwrap()
}

fn readiness_root(state: &DaemonState) -> String {
    match state.replica_coordinator.provider_repository().declaration_for_group(GROUP).unwrap() {
        ProviderDeclaration::Provider(root) => root.root_id,
        other => panic!("{other:?}"),
    }
}

/// A declared root whose provider state is gone must not simply vanish from the listing (the
/// host removes domains absent from a confirmed snapshot): the snapshot is unavailable, so the
/// host leaves every domain alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_corrupt_declaration_makes_the_snapshot_unavailable() {
    let (state, _root) = state_with_root();
    assert!(folders(&state).await.snapshot_available);
    state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM provider_roots", [])?;
            Ok(())
        })
        .unwrap();
    let response = folders(&state).await;
    assert!(!response.snapshot_available, "a lost root was reported as a confirmed absence");
    assert!(response.folders.is_empty());
}

// ---- the evidence channel: reports, acks, and the replayable evidence sequence ----

use yadorilink_ipc_proto::shellipc::{ProviderMaterializedItem, ProviderMaterializedReport};

fn report_message(
    root_id: &[u8],
    epoch: u64,
    seq: u64,
    full: bool,
    observed_after: u64,
    items: &[[u8; 16]],
) -> ShellIpcMessage {
    ShellIpcMessage {
        payload: Some(Payload::ProviderMaterializedReport(ProviderMaterializedReport {
            root_id: root_id.to_vec(),
            reporter_epoch: epoch,
            report_seq: seq,
            full,
            observed_after_seq: observed_after,
            upserts: items
                .iter()
                .map(|i| ProviderMaterializedItem { item_id: i.to_vec() })
                .collect(),
            removed: Vec::new(),
            more: false,
        })),
    }
}

/// The host's reports are answered with an ack on its connection: a full snapshot is accepted, a
/// delta in a new epoch without one gets `needs_full`; a report naming a root the daemon no longer
/// knows (a stale root_id after a rebootstrap) is ignored without any answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_are_acknowledged_and_a_stale_root_is_ignored() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    let context = ShellContext::from_state(state.clone());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(context.provider_host.try_attach(tx.clone()));
    let item = [3u8; 16];

    assert!(
        provider_channel_message(&context, &tx, &report_message(&root_id, 5, 1, true, 0, &[item]))
            .await
    );
    let Payload::ProviderReportAck(ack) = next_payload(&mut rx).await else { panic!("no ack") };
    assert_eq!((ack.reporter_epoch, ack.accepted_seq, ack.needs_full), (5, 1, false));

    provider_channel_message(&context, &tx, &report_message(&root_id, 6, 2, false, 0, &[item]))
        .await;
    let Payload::ProviderReportAck(ack) = next_payload(&mut rx).await else { panic!("no ack") };
    assert!(ack.needs_full, "a delta in a new epoch without a full snapshot was accepted");

    // The root is replaced: reports for the old root_id are ignored, silently.
    state.replica_coordinator.provider_repository().rebootstrap_root(GROUP).unwrap();
    provider_channel_message(&context, &tx, &report_message(&root_id, 5, 2, false, 0, &[item]))
        .await;
    assert!(rx.try_recv().is_err(), "a report for a dead root was answered");
}

/// The evidence sequence is replayable STATE (the listing carries it, so the host reads it on
/// connect before it starts enumerating) and each handoff also pushes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_evidence_sequence_is_listed_and_pushed() {
    let (state, root) = state_with_root();
    commit(&state, "a.txt", 1, 10);
    let repo = state.replica_coordinator.provider_repository();
    let item = repo.mint_item(&root, "a.txt").unwrap();
    assert_eq!(folders(&state).await.folders[0].latest_evidence_seq, 0);

    let context = ShellContext::from_state(state.clone());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(context.provider_host.try_attach(tx));
    let version = repo.current_version_hash(&root, &item).unwrap().unwrap();
    let seq = crate::provider_evidence::record_handoff(
        &state.replica_coordinator,
        &context.provider_host,
        &root,
        &item,
        version,
    )
    .unwrap()
    .unwrap();
    assert_eq!(seq, 1);
    let Payload::ProviderEvidenceTick(tick) = next_payload(&mut rx).await else {
        panic!("no tick")
    };
    assert_eq!(tick.evidence_seq, 1);
    assert_eq!(folders(&state).await.folders[0].latest_evidence_seq, 1);
}

// ---- one host connection; unknown roots attach nothing ----

fn domain_state_message(root_id: &[u8], registered: bool, last_acked: u64) -> ShellIpcMessage {
    ShellIpcMessage {
        payload: Some(Payload::ProviderDomainState(ProviderDomainState {
            root_id: root_id.to_vec(),
            evidence: evidence_of(registered) as i32,
            preserved_location: String::new(),
            last_acked_namespace_revision: last_acked,
        })),
    }
}

/// A domain state for a root the daemon does not know attaches nothing; a second connection
/// cannot take the host over while the first is alive, and cannot trigger a rollback rebootstrap;
/// once the first is gone, the next one attaches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stray_connection_cannot_take_the_host_over() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    let context = ShellContext::from_state(state.clone());
    let (first, first_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    let (second, _second_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();

    // An unknown (old) root id attaches nothing.
    assert!(
        provider_channel_message(&context, &second, &domain_state_message(&[7; 16], true, 0)).await
    );
    assert!(context.provider_host.try_attach(first.clone()), "an unknown root attached a host");

    // The first connection is the host; the second is refused.
    assert!(!context.provider_host.try_attach(second.clone()));
    // Its rollback claim is not honoured (nor is its replay): the root is untouched.
    provider_channel_message(&context, &second, &domain_state_message(&root_id, true, 99)).await;
    assert_eq!(readiness_root(&state), root, "a stray connection rebootstrapped the root");

    // The attached host's claim is.
    assert!(
        provider_channel_message(&context, &first, &domain_state_message(&root_id, true, 99)).await
    );
    assert_ne!(readiness_root(&state), root);

    // Once the first connection is gone, another one attaches.
    drop(first_rx);
    assert!(context.provider_host.try_attach(second));
}

// ---- reports are evidence only from the attached host connection, and only while it lives ----

fn present_in_membership(context: &ShellContext, root: &str, item: &[u8; 16]) -> bool {
    crate::provider_evidence::provider_local_presence(
        &context.replica_coordinator,
        &context.membership,
        root,
        item,
    )
    .object_present
}

/// A report from a connection that is not the attached host is not evidence and is not answered;
/// the attached host's is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_report_from_a_stray_connection_is_not_evidence() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    let context = ShellContext::from_state(state.clone());
    let (host, mut host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    let (stray, mut stray_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    let item = [4u8; 16];

    // No host attached yet: nobody's report counts.
    provider_channel_message(&context, &stray, &report_message(&root_id, 1, 1, true, 0, &[item]))
        .await;
    assert!(!present_in_membership(&context, &root, &item));

    assert!(context.provider_host.try_attach(host.clone()));
    provider_channel_message(&context, &stray, &report_message(&root_id, 2, 1, true, 0, &[item]))
        .await;
    assert!(!present_in_membership(&context, &root, &item), "a stray connection reported");
    assert!(
        stray_rx.try_recv().is_err() && host_rx.try_recv().is_err(),
        "a stray report was answered"
    );

    provider_channel_message(&context, &host, &report_message(&root_id, 3, 1, true, 0, &[item]))
        .await;
    assert!(present_in_membership(&context, &root, &item));
    let Payload::ProviderReportAck(ack) = next_payload(&mut host_rx).await else {
        panic!("no ack")
    };
    assert!(!ack.needs_full);
}

/// A report cannot claim to have observed after a handoff that was never issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_report_cannot_claim_an_observation_after_an_unissued_handoff() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    let context = ShellContext::from_state(state.clone());
    let (host, mut host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(context.provider_host.try_attach(host.clone()));
    let item = [5u8; 16];

    // No handoff was ever issued, so the latest evidence sequence is 0: a claim of 5 is invented.
    provider_channel_message(&context, &host, &report_message(&root_id, 1, 1, true, 5, &[item]))
        .await;
    let Payload::ProviderReportAck(ack) = next_payload(&mut host_rx).await else {
        panic!("no ack")
    };
    assert!(ack.needs_full);
    assert!(!present_in_membership(&context, &root, &item));
}

/// When the host connection ends, or another host takes over, nothing it reported stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_goes_away_leaves_no_evidence() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    let context = ShellContext::from_state(state.clone());
    let (host, _host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    let item = [6u8; 16];
    assert!(context.provider_host.try_attach(host.clone()));
    provider_channel_message(&context, &host, &report_message(&root_id, 1, 1, true, 0, &[item]))
        .await;
    assert!(present_in_membership(&context, &root, &item));

    // The connection ends.
    drop(HostDisconnect { context: &context, tx: host.clone() });
    assert!(!present_in_membership(&context, &root, &item), "membership outlived its host");
    assert!(!context.provider_host.is_attached(&host));

    // A new host attaches and reports; then a different connection replaces it (the first one's
    // channel was closed): the replacement starts from nothing.
    let (second, _second_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    provider_channel_message(&context, &second, &domain_state_message(&root_id, true, 0)).await;
    provider_channel_message(&context, &second, &report_message(&root_id, 2, 1, true, 0, &[item]))
        .await;
    assert!(present_in_membership(&context, &root, &item));
    drop(_second_rx);
    let (third, _third_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    provider_channel_message(&context, &third, &domain_state_message(&root_id, true, 0)).await;
    assert!(!present_in_membership(&context, &root, &item), "a replaced host's report survived");
}

// ---- a replaced root prompts the connected host to list again ----

/// When the daemon replaces a root (lost state, a rolled-back database), the connected host is
/// prompted with a `ProviderChanged` for the new root, and the next listing omits the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replaced_root_prompts_the_host_to_list_again() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    let context = ShellContext::from_state(state.clone());
    let (host, mut host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(context.provider_host.try_attach(host.clone()));

    // The host's revision is ahead of the daemon's: the database was restored, the root is replaced.
    provider_channel_message(&context, &host, &domain_state_message(&root_id, true, 99)).await;
    let Payload::ProviderChanged(changed) = next_payload(&mut host_rx).await else {
        panic!("the host was not prompted")
    };
    assert!(changed.changed_item_ids.is_empty());
    assert_ne!(changed.root_id, root_id, "the prompt names the old root");
    let listed = folders(&state).await.folders;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].root_id, changed.root_id, "the listing does not carry the new root");
    assert!(listed.iter().all(|f| f.root_id != root_id), "the old root is still listed");
}

/// A host that removed its domain is prompted too, with the root that replaced it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_domain_prompts_the_host_with_the_replacement() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    let context = ShellContext::from_state(state.clone());
    let (host, mut host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(context.provider_host.try_attach(host.clone()));
    handle_message(&context, ShellIpcMessage { payload: Some(domain_state(&root_id, false)) })
        .await;
    let Payload::ProviderChanged(changed) = next_payload(&mut host_rx).await else {
        panic!("the host was not prompted")
    };
    assert_eq!(changed.root_id, hex::decode(readiness_root(&state)).unwrap());
    assert_ne!(changed.root_id, root_id);
}

// ---- acknowledgements belong to the attached host ----

/// An eviction's acknowledgement completes the waiting step only when it comes from the attached
/// host; a stray connection's does nothing, and a host that goes away fails what it was owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_attached_host_can_acknowledge_an_eviction() {
    use crate::provider_publication::{EvictOutcome, ProviderHost};
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    let context = Arc::new(ShellContext::from_state(state.clone()));
    let (host, mut host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    let (stray, _stray_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(context.provider_host.try_attach(host.clone()));

    let asking = context.clone();
    let root_for_task = root.clone();
    let pending = tokio::spawn(async move {
        asking.provider_host.evict(&root_for_task, [1u8; 16], [0u8; 32]).await
    });
    let Payload::ProviderEvictRequest(request) = next_payload(&mut host_rx).await else {
        panic!("no eviction request")
    };
    let done = |request_id: &[u8]| ShellIpcMessage {
        payload: Some(Payload::ProviderEvictDone(ProviderEvictDone {
            root_id: root_id.clone(),
            request_id: request_id.to_vec(),
            result: EvictResult::Evicted as i32,
            error: String::new(),
        })),
    };
    provider_channel_message(&context, &stray, &done(&request.request_id)).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(!pending.is_finished(), "a stray connection completed an eviction");
    provider_channel_message(&context, &host, &done(&request.request_id)).await;
    assert_eq!(pending.await.unwrap(), EvictOutcome::Evicted);

    // A host that disconnects fails the request it still owed: the item stays pending.
    let asking = context.clone();
    let root_for_task = root.clone();
    let pending = tokio::spawn(async move {
        asking.provider_host.evict(&root_for_task, [2u8; 16], [0u8; 32]).await
    });
    let _ = next_payload(&mut host_rx).await;
    drop(HostDisconnect { context: &context, tx: host.clone() });
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), pending)
        .await
        .expect("the waiter outlived its host")
        .unwrap();
    assert!(matches!(outcome, EvictOutcome::Error(_)), "{outcome:?}");
}

// ---- the Eager driver's query over the host connection ----

struct AlwaysAvailable;

impl crate::provider_eager::EagerEnvironment for AlwaysAvailable {
    fn low_disk(&self, _dir: &std::path::Path, _bytes: u64) -> bool {
        false
    }
    fn peers_available(&self, _group_id: &str) -> bool {
        true
    }
}

fn next_downloads_message(root_id: &[u8], exclude: &[[u8; 16]], max: u32) -> ShellIpcMessage {
    ShellIpcMessage {
        payload: Some(Payload::NextProviderDownloadsRequest(
            yadorilink_ipc_proto::shellipc::NextProviderDownloadsRequest {
                root_id: root_id.to_vec(),
                exclude_item_ids: exclude.iter().map(|i| i.to_vec()).collect(),
                max,
            },
        )),
    }
}

/// The query round trip on the host connection: offers come back, an exclusion is not offered
/// again, a rejection holds an item back, and a stray connection gets no answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_eager_query_round_trip_over_the_host_connection() {
    use yadorilink_ipc_proto::shellipc::{DriverState, ProviderDownloadRejected};
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    send(&state, domain_state(&root_id, true)).await;
    send(&state, handshake(&root_id)).await;
    commit(&state, "a.bin", 1, 10);
    commit(&state, "b.bin", 1, 20);
    let repo = state.replica_coordinator.provider_repository();
    let a = repo.mint_item(&root, "a.bin").unwrap();
    let b = repo.mint_item(&root, "b.bin").unwrap();

    let staging = tempfile::tempdir().unwrap();
    let context = ShellContext::from_state(state.clone())
        .with_handoff_root(Some(
            crate::provider_handoff::HandoffRoot::open(staging.path()).unwrap(),
        ))
        .with_eager(Arc::new(crate::provider_eager::EagerDriver::new(
            Arc::new(AlwaysAvailable),
            crate::provider_eager::EagerConfig::default(),
        )));
    let (host, mut host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    let (stray, mut stray_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(context.provider_host.try_attach(host.clone()));
    // The host's complete snapshot (nothing materialized yet) makes the query answerable.
    provider_channel_message(&context, &host, &report_message(&root_id, 1, 1, true, 0, &[])).await;
    let _ack = next_payload(&mut host_rx).await;

    provider_channel_message(&context, &host, &next_downloads_message(&root_id, &[], 2)).await;
    let Payload::NextProviderDownloadsResponse(response) = next_payload(&mut host_rx).await else {
        panic!("no answer")
    };
    assert_eq!(DriverState::try_from(response.state).unwrap(), DriverState::Running);
    assert_eq!(
        response.downloads.iter().map(|d| d.item_id.clone()).collect::<Vec<_>>(),
        [a.to_vec(), b.to_vec()]
    );

    // With `a` outstanding, only `b` is offered; `a` stays unsettled.
    provider_channel_message(&context, &host, &next_downloads_message(&root_id, &[a], 1)).await;
    let Payload::NextProviderDownloadsResponse(response) = next_payload(&mut host_rx).await else {
        panic!("no answer")
    };
    assert_eq!(response.downloads.len(), 1);
    assert_eq!(response.downloads[0].item_id, b.to_vec());
    assert!(response.settled_item_ids.is_empty());

    // The OS rejected `a`: it settles (held back) instead of being offered again at once.
    provider_channel_message(
        &context,
        &host,
        &ShellIpcMessage {
            payload: Some(Payload::ProviderDownloadRejected(ProviderDownloadRejected {
                root_id: root_id.clone(),
                item_id: a.to_vec(),
                error: "refused".into(),
            })),
        },
    )
    .await;
    provider_channel_message(&context, &host, &next_downloads_message(&root_id, &[a], 2)).await;
    let Payload::NextProviderDownloadsResponse(response) = next_payload(&mut host_rx).await else {
        panic!("no answer")
    };
    assert_eq!(response.settled_item_ids, [a.to_vec()]);
    assert_eq!(
        response.downloads.iter().map(|d| d.item_id.clone()).collect::<Vec<_>>(),
        [b.to_vec()]
    );

    // A connection that is not the attached host is not answered.
    provider_channel_message(&context, &stray, &next_downloads_message(&root_id, &[], 2)).await;
    assert!(stray_rx.try_recv().is_err());
}

/// Only a CONFIRMED removal replaces a root: an unknown state (the OS domain list could not be
/// read) and "not registered yet" change nothing, a registered root stays registered, and the same
/// root id keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_confirmed_removal_replaces_a_root() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    send(&state, domain_state(&root_id, true)).await;
    send(&state, handshake(&root_id)).await;
    assert_eq!(readiness(&state), Readiness::Ready);
    for evidence in [DomainEvidence::Unknown, DomainEvidence::NotRegistered] {
        send(
            &state,
            Payload::ProviderDomainState(ProviderDomainState {
                root_id: root_id.clone(),
                evidence: evidence as i32,
                preserved_location: String::new(),
                last_acked_namespace_revision: 0,
            }),
        )
        .await;
        assert_eq!(readiness(&state), Readiness::Ready, "{evidence:?} changed the root");
        assert_eq!(
            folders(&state).await.folders[0].root_id,
            root_id,
            "{evidence:?} replaced the root"
        );
    }
    send(&state, domain_state(&root_id, false)).await;
    assert_ne!(
        folders(&state).await.folders[0].root_id,
        root_id,
        "a confirmed removal did not replace it"
    );
}

/// An unlink makes the root a REMOVAL in the snapshot (the only authority for the host to
/// remove a domain); the host's removal report finishes it and records where the OS kept the data.
/// A domain of an unknown root is only reported, never listed as a removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unlink_is_a_durable_removal_the_host_finishes() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    assert!(folders(&state).await.removals.is_empty());

    state.replica_coordinator.link_repository().remove_link("/provider/photos").unwrap();
    let snapshot = folders(&state).await;
    assert!(snapshot.folders.is_empty());
    assert_eq!(snapshot.removals.len(), 1, "an unlink did not ask the host to remove the domain");
    assert_eq!(snapshot.removals[0].root_id, root_id);

    let mut report = domain_state(&root_id, false);
    if let Payload::ProviderDomainState(state) = &mut report {
        state.preserved_location = "/Users/u/kept".to_string();
    }
    send(&state, report).await;
    assert!(folders(&state).await.removals.is_empty(), "a finished removal was asked for again");
    let done = state.replica_coordinator.provider_repository().removals().unwrap();
    assert_eq!(done[0].preserved_location.as_deref(), Some("/Users/u/kept"));
}

/// A domain reported for a root the daemon does not know is an orphan: recorded for `status`,
/// attached to nothing, and never turned into a removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_orphan_domain_is_reported_and_kept() {
    let (state, _root) = state_with_root();
    let context = ShellContext::from_state(state.clone());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let unknown = vec![9u8; 16];
    // Attach the host with a known root first.
    let known = hex::decode(
        state.replica_coordinator.provider_repository().list_declared_roots().unwrap()[0]
            .root_id
            .clone(),
    )
    .unwrap();
    provider_channel_message(
        &context,
        &tx,
        &ShellIpcMessage { payload: Some(domain_state(&known, true)) },
    )
    .await;
    let orphan = Payload::ProviderDomainState(ProviderDomainState {
        root_id: unknown.clone(),
        evidence: DomainEvidence::Orphan as i32,
        preserved_location: String::new(),
        last_acked_namespace_revision: 0,
    });
    provider_channel_message(&context, &tx, &ShellIpcMessage { payload: Some(orphan) }).await;
    assert_eq!(context.provider_host.orphans(), [hex::encode(&unknown)]);
    assert!(state.replica_coordinator.provider_repository().removals().unwrap().is_empty());
}

/// Warnings about a refused provider change or fetch carry classes and ids, never the message (which
/// quotes the user's file or folder names): the message is for debug level only.
#[test]
fn warn_lines_of_the_provider_paths_do_not_carry_messages_or_paths() {
    for (name, source) in [
        ("provider_apply.rs", include_str!("provider_apply.rs")),
        ("provider_materialize.rs", include_str!("provider_materialize.rs")),
        ("../shell_status.rs", include_str!("../shell_status.rs")),
    ] {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let mut rest = production;
        while let Some(at) = rest.find("tracing::warn!(") {
            let call = &rest[at..];
            let end = call.find(");").map_or(call.len(), |e| e + 2);
            let call = &call[..end];
            for forbidden in ["failure.error", "absolute_path", "error = %failure"] {
                assert!(
                    !call.contains(forbidden),
                    "{name}: a warn line carries {forbidden}: {call}"
                );
            }
            rest = &rest[at + end.min(rest.len() - at)..];
        }
    }
}

/// The OS dropping its copy without being asked (the user removed the download) reaches the
/// reclaim: the item's blocks are freed once the host reports it left the materialized set, and
/// not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_the_user_removed_frees_the_daemons_blocks() {
    use crate::provider_reclaim::tests::{data_of, eventually, Fx};
    use crate::provider_reclaim::ReclaimQueue;

    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    let item = fx.held_item("a.bin");
    let queue = Arc::new(ReclaimQueue::new(fx.state.clone(), fx.reclaim()));
    let context = ShellContext::from_state(fx.state.clone()).with_reclaim_queue(queue);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(context.provider_host.try_attach(tx.clone()));
    let root_id = hex::decode(&fx.root).unwrap();

    // The OS holds the item: nothing is reclaimed.
    let listed_at = fx
        .state
        .replica_coordinator
        .provider_repository()
        .latest_evidence_seq(&fx.root)
        .unwrap()
        .unwrap();
    provider_channel_message(
        &context,
        &tx,
        &report_message(&root_id, 5, 1, true, listed_at, &[item]),
    )
    .await;
    let Payload::ProviderReportAck(ack) = next_payload(&mut rx).await else { panic!("no ack") };
    assert!(!ack.needs_full);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(fx.cached(&blocks[0]));
    assert_eq!(fx.custody.acquires.load(std::sync::atomic::Ordering::SeqCst), 0);

    // The next report takes it out of the materialized set.
    let mut gone = report_message(&root_id, 5, 2, false, listed_at, &[]);
    if let Some(Payload::ProviderMaterializedReport(report)) = gone.payload.as_mut() {
        report.removed = vec![item.to_vec()];
    }
    provider_channel_message(&context, &tx, &gone).await;
    eventually("the blocks of the dropped item are freed", || !fx.cached(&blocks[0])).await;
}

fn domain_state_with(
    root: &str,
    evidence: DomainEvidence,
    last_acked_namespace_revision: u64,
) -> ShellIpcMessage {
    ShellIpcMessage {
        payload: Some(Payload::ProviderDomainState(ProviderDomainState {
            root_id: hex::decode(root).unwrap(),
            evidence: evidence as i32,
            preserved_location: String::new(),
            last_acked_namespace_revision,
        })),
    }
}

/// A root lookup that fails is not an unknown root: an orphan report is not recorded on it, and
/// the host is not attached on a guess either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_root_lookup_is_not_an_unknown_root() {
    use crate::provider_read_fault::Fault;
    let (state, root) = state_with_root();
    let context = ShellContext::from_state(state.clone());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(context.provider_host.try_attach(tx.clone()));

    let fault = Fault::inject(&state.replica_coordinator, "provider_roots", "group_id");
    let consumed = provider_channel_message(
        &context,
        &tx,
        &domain_state_with(&root, DomainEvidence::Orphan, 0),
    )
    .await;
    assert!(consumed);
    assert!(
        context.provider_host.orphans().is_empty(),
        "a failed lookup recorded an orphan domain"
    );
    fault.restore();
}

/// The rollback check cannot be skipped by a failed revision read: the host is not attached and
/// the message is not accepted until the revision can be compared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_revision_does_not_skip_the_rollback_check() {
    use crate::provider_read_fault::Fault;
    let (state, root) = state_with_root();
    let context = ShellContext::from_state(state.clone());
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();

    let fault = Fault::inject(&state.replica_coordinator, "provider_roots", "namespace_revision");
    let consumed = provider_channel_message(
        &context,
        &tx,
        &domain_state_with(&root, DomainEvidence::Registered, 7),
    )
    .await;
    assert!(consumed, "the message must not fall through to be recorded as evidence");
    assert!(!context.provider_host.is_attached(&tx), "the host was attached unchecked");
    fault.restore();
    assert_eq!(readiness_root(&state), root, "the root was replaced on a failed read");
}

/// A removal list that cannot be read makes the whole folder snapshot unavailable; an empty
/// removal list says no removal is requested.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_removal_list_makes_the_snapshot_unavailable() {
    use crate::provider_read_fault::Fault;
    let (state, _root) = state_with_root();
    let fault = Fault::inject(&state.replica_coordinator, "provider_removals", "state");
    let response = folders(&state).await;
    assert!(!response.snapshot_available, "an unreadable removal list was listed as none");
    assert!(response.folders.is_empty() && response.removals.is_empty());
    fault.restore();
    assert!(folders(&state).await.snapshot_available);
}

// ---- a removal is the engine's verdict, never the host's ----

fn reading(root_id: &[u8], evidence: DomainEvidence) -> ShellIpcMessage {
    ShellIpcMessage {
        payload: Some(Payload::ProviderDomainState(ProviderDomainState {
            root_id: root_id.to_vec(),
            evidence: evidence as i32,
            preserved_location: String::new(),
            last_acked_namespace_revision: 0,
        })),
    }
}

/// One host connection reporting readings of one registered root to one daemon context.
struct Readings {
    state: Arc<DaemonState>,
    context: ShellContext,
    host: tokio::sync::mpsc::UnboundedSender<ShellIpcMessage>,
    host_rx: Option<tokio::sync::mpsc::UnboundedReceiver<ShellIpcMessage>>,
    root_id: Vec<u8>,
}

impl Readings {
    async fn registered() -> Self {
        let (state, root) = state_with_root();
        let root_id = hex::decode(&root).unwrap();
        let context = ShellContext::from_state(state.clone());
        let (host, host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
        let me = Self { state, context, host, host_rx: Some(host_rx), root_id };
        me.report(DomainEvidence::Registered).await;
        me
    }

    async fn report(&self, evidence: DomainEvidence) {
        let consumed =
            provider_channel_message(&self.context, &self.host, &reading(&self.root_id, evidence))
                .await;
        if !consumed {
            handle_message(&self.context, reading(&self.root_id, evidence)).await;
        }
    }

    fn current_root(&self) -> Vec<u8> {
        hex::decode(readiness_root(&self.state)).unwrap()
    }
}

/// The host reports what it READ. One missing-domain reading is never a removal: the root, and so
/// the domain the host keeps for it, stay; the second consecutive reading is the engine's verdict
/// and replaces the root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_absent_reading_never_removes_but_consecutive_readings_do() {
    let fx = Readings::registered().await;
    fx.report(DomainEvidence::Absent).await;
    assert_eq!(fx.current_root(), fx.root_id, "a single absent reading replaced the root");
    fx.report(DomainEvidence::Absent).await;
    assert_ne!(
        fx.current_root(),
        fx.root_id,
        "consecutive absent readings did not reach a verdict"
    );
}

/// Any other reading between two absent ones breaks the run, so a list that was unreadable,
/// racing or showing the domain again never adds up to a removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reading_that_is_not_absent_breaks_the_run() {
    let fx = Readings::registered().await;
    for between in
        [DomainEvidence::Unknown, DomainEvidence::Registered, DomainEvidence::NotRegistered]
    {
        fx.report(DomainEvidence::Absent).await;
        fx.report(between).await;
        fx.report(DomainEvidence::Absent).await;
        assert_eq!(fx.current_root(), fx.root_id, "{between:?} did not break the run");
        fx.report(DomainEvidence::Registered).await;
    }
}

/// A host that registered a domain but disconnected before the daemon recorded the registration
/// remembers the domain; if the user then removes it, the host reports only absence and will not
/// register the old id again. The daemon must not discard those readings, or the folder is
/// stranded: consecutive readings replace the root, so the host registers a fresh domain. A single
/// reading, and readings about a root the daemon does not know, change nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_registration_report_does_not_strand_the_root() {
    let (state, root) = state_with_root();
    let root_id = hex::decode(&root).unwrap();
    let context = ShellContext::from_state(state.clone());
    let (host, _host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    let absent = |id: &[u8]| reading(id, DomainEvidence::Absent);
    // The daemon never recorded a registration for this root.
    provider_channel_message(&context, &host, &absent(&[7u8; 16])).await;
    provider_channel_message(&context, &host, &absent(&[7u8; 16])).await;
    assert_eq!(
        hex::decode(readiness_root(&state)).unwrap(),
        root_id,
        "an unknown root changed something"
    );
    provider_channel_message(&context, &host, &absent(&root_id)).await;
    assert_eq!(
        hex::decode(readiness_root(&state)).unwrap(),
        root_id,
        "one reading replaced the root"
    );
    provider_channel_message(&context, &host, &absent(&root_id)).await;
    assert_ne!(
        hex::decode(readiness_root(&state)).unwrap(),
        root_id,
        "consecutive readings left the root stranded"
    );
}

/// Readings count only from the attached host, and a different host starts the run over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_attached_hosts_consecutive_readings_count() {
    let mut fx = Readings::registered().await;
    let (stray, _stray_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    for _ in 0..3 {
        provider_channel_message(
            &fx.context,
            &stray,
            &reading(&fx.root_id, DomainEvidence::Absent),
        )
        .await;
    }
    assert_eq!(fx.current_root(), fx.root_id, "a stray connection's readings removed a domain");

    fx.report(DomainEvidence::Absent).await;
    // The attached host goes away and another takes over: the first host's reading is not carried over.
    fx.host_rx = None;
    let (second, _second_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    provider_channel_message(&fx.context, &second, &reading(&fx.root_id, DomainEvidence::Absent))
        .await;
    assert_eq!(fx.current_root(), fx.root_id, "a previous host's reading was counted for the next");
}

/// A shell context built for a state must not keep that state alive: the Eager driver is
/// reachable from the state (via the provider content probe), so a strong back-reference was
/// an `Arc` cycle that leaked the state, its block store and their file descriptors for the
/// rest of the process. That exhausted a default `ulimit -n 1024` over the daemon lib lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_state_frees_it_despite_the_shell_context() {
    let (state, _root) = state_with_root();
    let _ = folders(&state).await;
    state.stop_background_tasks_for_tests();
    let weak = Arc::downgrade(&state);
    drop(state);
    for _ in 0..100 {
        if weak.strong_count() == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the daemon state is still referenced after its owner dropped it");
}
