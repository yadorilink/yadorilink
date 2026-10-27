//! Re-adopting a provider folder that a start over marked as needing the person, on a real
//! engine against a coordination plane served in process: the folder joins its group again
//! without a second provider folder, an unconfirmed replacement makes it a full replica, and
//! the refusals change nothing. The provider folder needs a platform with a provider adapter.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_client_core::coordination::device_config::{self, DeviceConfig};
use yadorilink_embedded_host::{
    AccountCommand, CallError, CallOptions, CancelHandle, Command, CommandErrorKind, CommandOutput,
    EmbeddedHost, JoinShare, LinkedFolder, ProviderFolder, ReadoptMarkedFolder, ReadoptRefusal,
    ShareFolder,
};
use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;
use yadorilink_local_storage::replacement_unconfirmed::{self, Record};

mod support;
use support::{area, serialized, Area};

const GROUP: &str = "g-invite";

struct Fake {
    addr: String,
    /// The service no longer lets the device join the group.
    group_gone: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Fake {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let group_gone = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (gone, log) = (group_gone.clone(), requests.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let (gone, log) = (gone.clone(), log.clone());
                std::thread::spawn(move || serve(&mut stream, &gone, &log));
            }
        });
        Self { addr, group_gone, requests }
    }

    fn count(&self, suffix: &str) -> usize {
        self.requests.lock().unwrap().iter().filter(|r| r.ends_with(suffix)).count()
    }
}

fn serve(stream: &mut std::net::TcpStream, gone: &AtomicBool, log: &Mutex<Vec<String>>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head_end, length) = loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while buffer.len() < head_end + length {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut words = head.split_whitespace();
    let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    log.lock().unwrap().push(format!("{method} {path}"));
    let (status, body) = match (method, path) {
        ("POST", "/shares/invites/accept/prepare") => (200, format!(r#"{{"groupId":"{GROUP}"}}"#)),
        ("POST", p) if p.ends_with("/join/prepare") && gone.load(Ordering::SeqCst) => {
            (404, r#"{"error":"no such group"}"#.to_owned())
        }
        ("POST", p) if p.ends_with("/join/prepare") => (200, "{}".to_owned()),
        ("POST", p) if p.ends_with("/storage-mode") => (200, "{}".to_owned()),
        ("POST", p) if p.ends_with("/activate") => (200, r#"{"result":"activated"}"#.to_owned()),
        ("POST", p) if p.ends_with("/cancel") => (200, "{}".to_owned()),
        _ => (404, "{}".to_owned()),
    };
    let response = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn within() -> CallOptions {
    CallOptions { deadline: Some(Duration::from_secs(30)), cancel: CancelHandle::new() }
}

fn register(area: &Area, addr: &str) {
    let dir = &area.config.config_dir;
    std::fs::create_dir_all(dir).unwrap();
    yadorilink_transport::DeviceSigningKeyPair::load_or_generate(
        dir.join("signing_key"),
        yadorilink_transport::KeyMirror::Disabled,
    )
    .unwrap();
    device_config::save_in(
        dir,
        &DeviceConfig {
            device_id: "device-1".into(),
            coordination_addr: addr.into(),
            signing_public_key: String::new(),
            config_version: device_config::CONFIG_VERSION,
        },
    )
    .unwrap();
}

fn start(fake: &Fake, area: &Area) -> EmbeddedHost {
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    host.set_coordination_for_test(
        fake.addr.clone(),
        yadorilink_fapi_client::test_support::offline_auth(),
    )
    .unwrap();
    host
}

fn folders(host: &EmbeddedHost) -> Vec<LinkedFolder> {
    let CommandOutput::Folders(folders) = host.execute(Command::ListFolders, &within()).unwrap()
    else {
        panic!("folders")
    };
    folders
}

/// Marks every folder as a start over does.
fn mark_all(host: &EmbeddedHost) {
    for folder in folders(host) {
        host.execute_owning_for_test(
            false,
            || {},
            move |commands| async move {
                commands.mark_not_rejoined(&folder.key).await.map(|()| CommandOutput::Done)
            },
            &within(),
        )
        .unwrap();
    }
}

fn readopt(host: &EmbeddedHost) -> Result<CommandOutput, CallError> {
    host.execute(
        Command::ReadoptMarkedFolder(ReadoptMarkedFolder { group_id: GROUP.into() }),
        &within(),
    )
}

fn refusal(result: Result<CommandOutput, CallError>) -> ReadoptRefusal {
    let Err(CallError::Failed(error)) = result else { panic!("expected a refusal: {result:?}") };
    match error.kind() {
        CommandErrorKind::Readopt(reason) => reason,
        other => panic!("expected a re-adoption refusal, got {other:?}: {}", error.message()),
    }
}

/// A provider folder of the group, joined by invite on-demand, then marked as a start over does.
fn marked_folder(host: &EmbeddedHost) -> LinkedFolder {
    let join = Command::JoinShare(JoinShare {
        invite_code: "code-1".into(),
        folder: ShareFolder::Provider(ProviderFolder {
            display_name: "Photos".into(),
            request_token: "token-1".into(),
        }),
        on_demand: true,
        acknowledge_risks: false,
    });
    host.execute(join, &within()).unwrap();
    mark_all(host);
    let marked = folders(host);
    assert_eq!(marked.len(), 1);
    assert!(marked[0].degraded.is_some(), "a marked folder is reported as needing action");
    marked[0].clone()
}

fn unconfirmed(area: &Area) {
    replacement_unconfirmed::write(
        &area.config.config_dir,
        &Record {
            old_device_id: "old".into(),
            new_device_id: "device-1".into(),
            unconfirmed_group_ids: vec![GROUP.into()],
            acknowledged_possible_loss: false,
        },
    )
    .unwrap();
}

/// The whole recovery: start over leaves the folder marked, re-adoption joins the group again
/// over the same folder, and because the replacement is unconfirmed the on-demand folder becomes
/// a full replica, which is what lets the replacement be acknowledged and confirmed.
#[test]
#[cfg_attr(
    not(any(target_vendor = "apple", windows)),
    ignore = "needs a provider adapter, which only Apple and Windows have"
)]
fn a_marked_folder_is_readopted_into_its_group_and_promoted_for_an_unconfirmed_replacement() {
    let _serial = serialized();
    let fake = Fake::start();
    let area = area();
    register(&area, &fake.addr);
    let host = start(&fake, &area);
    let marked = marked_folder(&host);
    unconfirmed(&area);

    let CommandOutput::Readopted(outcome) = readopt(&host).unwrap() else { panic!("an outcome") };
    assert_eq!(outcome.group_id, GROUP);
    assert_eq!(outcome.link_key, marked.key);
    assert!(outcome.promoted_to_eager);
    assert!(outcome.provider_root_id.is_some());

    // The same folder (no second provider folder), syncing again, now a full replica.
    let after = folders(&host);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].key, marked.key);
    assert!(after[0].degraded.is_none(), "{:?}", after[0].degraded);
    assert!(!after[0].on_demand);
    // The service saw the join again and the promotion; nothing was cancelled.
    assert_eq!(fake.count("/join/prepare"), 1);
    assert_eq!(fake.count("/join/activate"), 1);
    assert_eq!(fake.count("/storage-mode"), 1);
    assert_eq!(fake.count("/cancel"), 0);

    // The group is now held the way the engine's confirmation needs, so the person's
    // acknowledgement is taken and the record stays for the engine to confirm.
    let CommandOutput::PossibleLossAcknowledged(recorded) =
        host.execute(Command::Account(AccountCommand::AcknowledgePossibleLoss), &within()).unwrap()
    else {
        panic!("an acknowledgement")
    };
    assert!(recorded);

    // Done once: the folder no longer is marked.
    assert_eq!(refusal(readopt(&host)), ReadoptRefusal::NotMarked);
    host.stop().unwrap();
}

/// Without an unconfirmed replacement the folder keeps its storage mode.
#[test]
#[cfg_attr(
    not(any(target_vendor = "apple", windows)),
    ignore = "needs a provider adapter, which only Apple and Windows have"
)]
fn without_an_unconfirmed_replacement_the_folder_keeps_its_mode() {
    let _serial = serialized();
    let fake = Fake::start();
    let area = area();
    register(&area, &fake.addr);
    let host = start(&fake, &area);
    marked_folder(&host);

    let CommandOutput::Readopted(outcome) = readopt(&host).unwrap() else { panic!("an outcome") };
    assert!(!outcome.promoted_to_eager);
    let after = folders(&host);
    assert_eq!(after.len(), 1);
    assert!(after[0].on_demand && after[0].degraded.is_none());
    assert_eq!(fake.count("/storage-mode"), 0);
    host.stop().unwrap();
}

/// The refusals, each of which changes nothing.
#[test]
#[cfg_attr(
    not(any(target_vendor = "apple", windows)),
    ignore = "needs a provider adapter, which only Apple and Windows have"
)]
fn a_re_adoption_the_engine_cannot_do_is_refused_typed_and_changes_nothing() {
    let _serial = serialized();
    let fake = Fake::start();
    let area = area();
    register(&area, &fake.addr);
    let host = start(&fake, &area);

    // No folder of the group.
    assert_eq!(refusal(readopt(&host)), ReadoptRefusal::GroupUnknown);

    // A folder that is not marked.
    host.execute(
        Command::JoinShare(JoinShare {
            invite_code: "code-1".into(),
            folder: ShareFolder::Provider(ProviderFolder {
                display_name: "Photos".into(),
                request_token: "token-1".into(),
            }),
            on_demand: true,
            acknowledge_risks: false,
        }),
        &within(),
    )
    .unwrap();
    assert_eq!(refusal(readopt(&host)), ReadoptRefusal::NotMarked);

    // The service no longer takes the device into the group: refused as a join is, still marked.
    mark_all(&host);
    fake.group_gone.store(true, Ordering::SeqCst);
    let Err(CallError::Failed(error)) = readopt(&host) else { panic!("expected a refusal") };
    assert_eq!(
        error.kind(),
        CommandErrorKind::Refused(ApplicationErrorCode::PreparationRejected),
        "{}",
        error.message()
    );
    let after = folders(&host);
    assert_eq!(after.len(), 1);
    assert!(after[0].degraded.is_some(), "the folder is still marked");
    assert_eq!(fake.count("/activate"), 1, "only the first join was activated");

    // An ordinary folder is never re-adopted by this command.
    host.add_link_row_for_test("/plain/folder", "g-plain", false).unwrap();
    mark_all(&host);
    let plain = Command::ReadoptMarkedFolder(ReadoptMarkedFolder { group_id: "g-plain".into() });
    assert_eq!(refusal(host.execute(plain, &within())), ReadoptRefusal::NotAProviderFolder);
    host.stop().unwrap();
}

/// An engine that still is the identity a start over retired (it reports `database_restored`)
/// is refused until it is restarted.
#[test]
fn an_engine_that_has_not_restarted_after_a_start_over_is_refused() {
    let _serial = serialized();
    let fake = Fake::start();
    let area = area();
    register(&area, &fake.addr);
    let host = start(&fake, &area);
    host.add_link_row_for_test("provider://token-1", GROUP, false).unwrap();
    host.stop().unwrap();
    drop(host);
    // The persistent witness is gone beside a database that records one.
    for entry in std::fs::read_dir(area._dir.path().join("witness")).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let host = start(&fake, &area);
    assert_eq!(refusal(readopt(&host)), ReadoptRefusal::RestartRequired);
    assert_eq!(fake.count("/join/prepare"), 0);
    host.stop().unwrap();
}
