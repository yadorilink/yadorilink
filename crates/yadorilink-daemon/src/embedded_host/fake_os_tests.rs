#![cfg(test)]

//! A fake operating system drives the embedded engine and the desktop daemon's shell path with
//! one callback script and compares what each answers.
//!
//! The script is what a File Provider host sends: domain registration, the extension handshake,
//! then one apply request per OS callback (create, modify, a retried callback, an out-of-order
//! one, one with a stale base version). Both sides serve the same provider handlers
//! (`shell_ipc::handle_connection`) over a framed duplex stream, but each is set up through its
//! own start: the embedded side through [`Engine::start`] over a data area on disk, the desktop
//! side through a daemon state and a shell context built the way the shell socket's server builds
//! them. Any difference in the normalized answers is a divergence between the two start paths.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::DuplexStream;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    DomainEvidence, EntryKind, ExtensionHandshake, ProviderApplyChangeRequest,
    ProviderApplyChangeResponse, ProviderChangeKind, ProviderContentSource, ProviderDomainState,
    ProviderItemMetadata, ShellIpcMessage,
};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::ProviderKind;

use super::{Engine, EngineConfig};
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;
use crate::shell_context::ShellContext;

const GROUP: &str = "group-1";
const DEVICE: &str = "device-a";

/// The group's verified policy, with this device a writer under `key`.
fn writer_policy(
    key: &ed25519_dalek::SigningKey,
) -> std::collections::HashMap<String, crate::change_policy::GroupPolicyState> {
    std::collections::HashMap::from([(
        GROUP.to_string(),
        crate::test_support::sync_stack_fixture::fixture_group_policy_granting(&[(
            DEVICE,
            key.verifying_key(),
        )]),
    )])
}

/// The persisted part both sides start from: one provider-backed link of the group.
fn declare_provider_root(coordinator: &ReplicaCoordinator) -> Vec<u8> {
    coordinator.link_repository().add_link("/provider/photos", GROUP).unwrap();
    let root = coordinator
        .provider_repository()
        .declare_root(GROUP, ProviderKind::MacFileProvider, "Photos")
        .unwrap();
    hex::decode(root).unwrap()
}

/// One OS callback of the script, and the name its answer is reported under.
struct Step {
    label: &'static str,
    request: ProviderApplyChangeRequest,
    /// The copy the extension left in the ingest directory for this request, if any.
    copy: Option<(&'static str, &'static [u8])>,
}

fn sha(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn request(root_id: &[u8], seq: u64, kind: ProviderChangeKind) -> ProviderApplyChangeRequest {
    ProviderApplyChangeRequest {
        request_id: format!("attempt-{seq}-{}", kind as i32).into_bytes(),
        session_id: vec![1; 16],
        operation_seq: seq,
        root_id: root_id.to_vec(),
        kind: kind as i32,
        metadata: Some(ProviderItemMetadata {
            unix_mode: Some(0o644),
            mtime_unix_nanos: Some(1_700_000_000_000_000_000),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn content(name: &str, bytes: &[u8]) -> ProviderContentSource {
    ProviderContentSource { ingest_name: name.into(), size: bytes.len() as u64, sha256: sha(bytes) }
}

/// What the answers to the script look like once identities that are random per engine are
/// replaced by the order they first appear in.
type Normalized = Vec<String>;

struct Client {
    stream: DuplexStream,
    items: Vec<Vec<u8>>,
}

impl Client {
    fn new(stream: DuplexStream) -> Self {
        Self { stream, items: Vec::new() }
    }

    async fn send(&mut self, payload: Payload) {
        write_message(&mut self.stream, &ShellIpcMessage { payload: Some(payload) }).await.unwrap();
    }

    /// The answer to `request_id`; anything else the engine pushes meanwhile is not an answer.
    async fn answer(&mut self, request_id: &[u8]) -> ProviderApplyChangeResponse {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let message = read_message::<ShellIpcMessage>(&mut self.stream)
                    .await
                    .unwrap()
                    .expect("the engine closed the channel");
                if let Some(Payload::ProviderApplyChangeResponse(response)) = message.payload {
                    if response.request_id == request_id {
                        return response;
                    }
                }
            }
        })
        .await
        .expect("the engine answers")
    }

    fn ordinal(&mut self, id: &[u8]) -> String {
        let at = match self.items.iter().position(|seen| seen == id) {
            Some(at) => at,
            None => {
                self.items.push(id.to_vec());
                self.items.len() - 1
            }
        };
        format!("item{at}")
    }

    fn normalize(&mut self, label: &str, response: &ProviderApplyChangeResponse) -> String {
        let item = response.item.as_ref().map(|item| {
            format!(
                "{} name={} parent_root={} kind={} size={} mode={:o} current={} content={} rev={} pgen={}",
                self.ordinal(&item.item_id),
                item.name,
                item.parent_item_id.is_empty(),
                item.entry_kind,
                item.size,
                item.unix_mode,
                item.current,
                hex::encode(&item.content_version),
                item.namespace_revision,
                item.parent_generation,
            )
        });
        format!(
            "{label}: ok={} failure={} outcome={} replayed={} item=[{}]",
            response.ok,
            response.failure,
            response.outcome,
            response.replayed,
            item.unwrap_or_default(),
        )
    }
}

/// Plays the script over `stream`, copying each request's file into `ingest_dir` first.
async fn play(stream: DuplexStream, root_id: &[u8], ingest_dir: &Path) -> Normalized {
    let mut client = Client::new(stream);
    // The host app registers the domain, then the extension says hello: the root is ready.
    client
        .send(Payload::ProviderDomainState(ProviderDomainState {
            root_id: root_id.to_vec(),
            evidence: DomainEvidence::Registered as i32,
            preserved_location: String::new(),
            last_acked_namespace_revision: 0,
        }))
        .await;
    client
        .send(Payload::ExtensionHandshake(ExtensionHandshake {
            root_id: root_id.to_vec(),
            extension_build: "1".into(),
        }))
        .await;

    let mut create_a = request(root_id, 1, ProviderChangeKind::Create);
    create_a.name = Some("a.txt".into());
    create_a.entry_kind = EntryKind::File as i32;
    create_a.content = Some(content("copy-1", b"first"));

    let mut out = Normalized::new();
    let mut created: Option<ProviderApplyChangeResponse> = None;
    let mut script = vec![Step {
        label: "create a.txt",
        request: create_a.clone(),
        copy: Some(("copy-1", b"first")),
    }];
    let mut idx = 0;
    loop {
        let step = &script[idx];
        if let Some((name, bytes)) = step.copy {
            std::fs::write(ingest_dir.join(name), bytes).unwrap();
        }
        let request = step.request.clone();
        let label = step.label;
        client.send(Payload::ProviderApplyChangeRequest(request.clone())).await;
        let response = client.answer(&request.request_id).await;
        out.push(client.normalize(label, &response));
        if created.is_none() {
            created = Some(response.clone());
        }
        idx += 1;
        if idx == 1 {
            // The steps that follow are built from what the first answer said.
            let item = created.as_ref().unwrap().item.clone().expect("a create answers its item");
            let base = item.content_version.clone();
            let base_generation = u64::from_be_bytes(base[32..].try_into().unwrap());

            let mut modify = request_for(root_id, 2, ProviderChangeKind::Modify);
            modify.item_id = item.item_id.clone();
            modify.base_version_hash = base.clone();
            modify.base_generation = Some(base_generation);
            modify.content = Some(content("copy-2", b"second"));

            let mut retried = modify.clone();
            retried.request_id = b"retry-of-2".to_vec();

            // Operation 4 before 3: a gap, then the one that was skipped.
            let mut ahead = request_for(root_id, 4, ProviderChangeKind::Create);
            ahead.name = Some("ahead.txt".into());
            ahead.entry_kind = EntryKind::File as i32;
            let mut late = request_for(root_id, 3, ProviderChangeKind::Create);
            late.name = Some("late.txt".into());
            late.entry_kind = EntryKind::File as i32;

            // The user edits from the version they saw before operation 2 changed it.
            let mut stale = request_for(root_id, 5, ProviderChangeKind::Modify);
            stale.item_id = item.item_id.clone();
            stale.base_version_hash = base;
            stale.base_generation = Some(base_generation);
            stale.content = Some(content("copy-3", b"edit of a stale view"));

            // The same logical operation as 1 with other fields is a different change.
            let mut mismatch = create_a.clone();
            mismatch.request_id = b"mismatch-of-1".to_vec();
            mismatch.name = Some("other.txt".into());

            script.push(Step {
                label: "modify a.txt",
                request: modify,
                copy: Some(("copy-2", b"second")),
            });
            script.push(Step { label: "retried modify", request: retried, copy: None });
            script.push(Step { label: "create ahead.txt (op 4)", request: ahead, copy: None });
            script.push(Step { label: "create late.txt (op 3)", request: late, copy: None });
            script.push(Step {
                label: "modify from a stale base",
                request: stale,
                copy: Some(("copy-3", b"edit of a stale view")),
            });
            script.push(Step {
                label: "same operation, other fields",
                request: mismatch,
                copy: None,
            });
        }
        if idx == script.len() {
            return out;
        }
    }
}

fn request_for(root_id: &[u8], seq: u64, kind: ProviderChangeKind) -> ProviderApplyChangeRequest {
    request(root_id, seq, kind)
}

/// The embedded engine: started over a data area on disk, the way a mobile host starts it.
async fn through_the_embedded_engine() -> (Normalized, ed25519_dalek::SigningKey) {
    use base64::Engine as _;
    let area = tempfile::tempdir().unwrap();
    let config_dir = area.path().join("state");
    std::fs::create_dir_all(&config_dir).unwrap();
    // A registered device: its config, and the signing key persisted where the engine loads it.
    let persisted = yadorilink_transport::DeviceSigningKeyPair::generate_and_persist(
        config_dir.join("signing_key"),
        yadorilink_transport::KeyMirror::Disabled,
    )
    .unwrap();
    std::fs::write(
        config_dir.join("device.json"),
        serde_json::to_vec(&serde_json::json!({
            "device_id": DEVICE,
            "coordination_addr": "http://127.0.0.1:9",
            "signing_public_key": base64::engine::general_purpose::STANDARD
                .encode(persisted.verifying.to_bytes()),
            "config_version": crate::device_config::CONFIG_VERSION,
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::create_dir_all(area.path().join("data")).unwrap();
    let sync_db_path = area.path().join("data/sync.sqlite3");
    let root_id = {
        let coordinator = ReplicaCoordinator::open(&sync_db_path).unwrap();
        declare_provider_root(&coordinator)
    };
    let provider_temp_root = area.path().join("provider-temp");
    std::fs::create_dir_all(&provider_temp_root).unwrap();
    let credentials = crate::credential_store::CredentialConfig::new(
        yadorilink_fapi_client::store::Backend::File(config_dir.join("credentials.json")),
        yadorilink_transport::KeyMirror::Disabled,
    );
    let engine = Engine::start(EngineConfig {
        config_dir,
        credentials,
        block_store_root: area.path().join("blocks"),
        sync_db_path,
        provider_temp_root: Some(provider_temp_root),
        machine_id: Some(crate::machine_fingerprint::TEST_HOST_ID.to_owned()),
        tuning: crate::engine_tuning::EngineTuning {
            witness: crate::install_witness::WitnessPlacement::Persistent(
                area.path().join("witness"),
            ),
            ..crate::engine_tuning::EngineTuning::default()
        },
    })
    .await
    .unwrap();
    engine.state.authority.replace_group_policy_states(writer_policy(&persisted.signing));
    let ingest_dir = engine.shell_context.handoff.get().unwrap().ingest_dir().to_path_buf();
    let stream = engine.open_provider_channel();
    let out = play(stream, &root_id, &ingest_dir).await;
    engine.stop().await;
    // The identity the engine loaded, for the desktop side to author with as well.
    (out, persisted.signing)
}

/// The desktop daemon's shell path: a state and a shell context served by the connection handler
/// the shell socket's server uses.
async fn through_the_desktop_shell_path(key: &ed25519_dalek::SigningKey) -> Normalized {
    let area = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(area.path().join("blocks")).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_id = declare_provider_root(&coordinator);
    let state = DaemonState::new_in(area.path().join("state"), DEVICE.into(), coordinator, store);
    state.set_device_signing_key(key.clone());
    state.authority.replace_group_policy_states(writer_policy(key));
    let handoff = crate::provider_handoff::HandoffRoot::open_with_lifetime(
        &area.path().join("provider-temp"),
        Duration::from_secs(60),
    )
    .unwrap();
    let ingest_dir = handoff.ingest_dir().to_path_buf();
    let context = Arc::new(ShellContext::from_state(state).with_handoff_root(Some(handoff)));
    let (host, engine_side) = tokio::io::duplex(256 * 1024);
    let (read, write) = tokio::io::split(engine_side);
    let served = tokio::spawn(crate::shell_ipc::handle_connection(read, write, context));
    let out = play(host, &root_id, &ingest_dir).await;
    served.abort();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_embedded_engine_answers_the_script_like_the_desktop_shell_path() {
    // One identity for both sides: the embedded engine loads the key it finds in its state
    // directory, and the desktop side is given a copy of it.
    let (embedded, key) = through_the_embedded_engine().await;
    let desktop = through_the_desktop_shell_path(&key).await;
    assert_eq!(desktop.len(), 7);
    // Spot checks on what the script means, so identical nonsense cannot pass.
    assert!(desktop[0].starts_with("create a.txt: ok=true"), "{desktop:#?}");
    assert!(desktop[1].starts_with("modify a.txt: ok=true"), "{desktop:#?}");
    assert!(desktop[2].contains("replayed=true"), "{desktop:#?}");
    assert!(
        desktop[5].contains("outcome=3"),
        "a stale base is kept as a concurrent edit: {desktop:#?}"
    );
    assert!(desktop[6].contains("ok=false"), "{desktop:#?}");
    assert_eq!(embedded, desktop, "the embedded engine diverged from the desktop shell path");
}
