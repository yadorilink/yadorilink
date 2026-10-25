//! The share commands end to end against a coordination plane served in process: the calls the
//! engine makes (prepare, activate, cancel) and what each answer becomes. The fake answers only
//! the enrollment routes. A provider folder needs a platform with a provider adapter, so the
//! happy paths run where there is one.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_embedded_host::{
    CallError, CallOptions, CancelHandle, Command, CommandErrorKind, CommandOutput, CreateShare,
    EmbeddedHost, JoinShare, ProviderFolder, ShareFolder,
};
use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;

mod support;
use support::{area, serialized};

/// What the fake answers the invite's prepare with.
#[derive(Clone, Copy)]
enum Invite {
    Valid,
    Expired,
    AlreadyUsed,
}

struct Fake {
    addr: String,
    invite: Arc<Mutex<Invite>>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Fake {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let invite = Arc::new(Mutex::new(Invite::Valid));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (state, log) = (invite.clone(), requests.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let (state, log) = (state.clone(), log.clone());
                std::thread::spawn(move || serve(&mut stream, &state, &log));
            }
        });
        Self { addr, invite, requests }
    }

    fn set_invite(&self, invite: Invite) {
        *self.invite.lock().unwrap() = invite;
    }

    /// `METHOD path` of every request so far, in order.
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn count(&self, suffix: &str) -> usize {
        self.requests().iter().filter(|r| r.ends_with(suffix)).count()
    }
}

fn serve(stream: &mut std::net::TcpStream, invite: &Mutex<Invite>, log: &Mutex<Vec<String>>) {
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
        ("POST", "/shares/invites/accept/prepare") => match *invite.lock().unwrap() {
            Invite::Valid => (200, r#"{"groupId":"g-invite"}"#),
            Invite::Expired => (400, r#"{"code":"invite_expired","error":"the invite expired"}"#),
            Invite::AlreadyUsed => {
                (400, r#"{"code":"invite_already_used","error":"the invite was used"}"#)
            }
        },
        ("POST", "/shares/groups/prepare") => (200, r#"{"groupId":"g-create"}"#),
        ("POST", p) if p.ends_with("/activate") => (200, r#"{"result":"activated"}"#),
        ("POST", p) if p.ends_with("/cancel") => (200, "{}"),
        _ => (404, "{}"),
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

fn host_against(fake: &Fake) -> (EmbeddedHost, support::Area) {
    let area = area();
    // A registered device: the enrollment journal names the device that runs it.
    std::fs::create_dir_all(&area.config.config_dir).unwrap();
    yadorilink_transport::DeviceSigningKeyPair::load_or_generate(
        area.config.config_dir.join("signing_key"),
        yadorilink_transport::KeyMirror::Disabled,
    )
    .unwrap();
    yadorilink_client_core::coordination::device_config::save_in(
        &area.config.config_dir,
        &yadorilink_client_core::coordination::device_config::DeviceConfig {
            device_id: "device-1".into(),
            coordination_addr: fake.addr.clone(),
            signing_public_key: String::new(),
            config_version: yadorilink_client_core::coordination::device_config::CONFIG_VERSION,
        },
    )
    .unwrap();
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    host.set_coordination_for_test(
        fake.addr.clone(),
        yadorilink_fapi_client::test_support::offline_auth(),
    )
    .unwrap();
    (host, area)
}

fn provider(name: &str, token: &str) -> ShareFolder {
    ShareFolder::Provider(ProviderFolder { display_name: name.into(), request_token: token.into() })
}

fn join(name: &str, token: &str) -> Command {
    Command::JoinShare(JoinShare {
        invite_code: "code-1".into(),
        folder: provider(name, token),
        on_demand: true,
        acknowledge_risks: false,
    })
}

fn folders(host: &EmbeddedHost) -> usize {
    let CommandOutput::Folders(folders) = host.execute(Command::ListFolders, &within()).unwrap()
    else {
        panic!("folders")
    };
    folders.len()
}

fn refusal(result: Result<CommandOutput, CallError>) -> ApplicationErrorCode {
    let Err(CallError::Failed(error)) = result else { panic!("expected a refusal: {result:?}") };
    match error.kind() {
        CommandErrorKind::Refused(code) => code,
        other => panic!("expected a typed refusal, got {other:?}: {}", error.message()),
    }
}

const HAS_PROVIDER: bool = cfg!(any(target_vendor = "apple", windows));

#[test]
fn joining_by_invite_into_a_provider_folder_redeems_the_invite_and_links_it() {
    if !HAS_PROVIDER {
        return;
    }
    let _serial = serialized();
    let fake = Fake::start();
    let (host, _area) = host_against(&fake);
    let CommandOutput::Shared(outcome) =
        host.execute(join("Photos", "token-1"), &within()).unwrap()
    else {
        panic!("a share outcome")
    };
    assert_eq!(outcome.group_id, "g-invite");
    assert!(outcome.provider_root_id.is_some());
    assert!(!outcome.awaiting_approval && !outcome.already_linked);
    assert_eq!(folders(&host), 1);
    assert_eq!(fake.count("/invites/accept/prepare"), 1);
    assert_eq!(fake.count("/invites/accept/activate"), 1);
    assert_eq!(fake.count("/cancel"), 0);
    host.stop().unwrap();
}

#[test]
fn an_expired_or_used_invite_is_refused_typed_and_links_nothing() {
    if !HAS_PROVIDER {
        return;
    }
    let _serial = serialized();
    let fake = Fake::start();
    let (host, _area) = host_against(&fake);
    for (invite, code) in [
        (Invite::Expired, ApplicationErrorCode::InviteExpired),
        (Invite::AlreadyUsed, ApplicationErrorCode::InviteAlreadyUsed),
    ] {
        fake.set_invite(invite);
        assert_eq!(refusal(host.execute(join("Photos", "token-1"), &within())), code);
    }
    assert_eq!(folders(&host), 0);
    assert_eq!(fake.count("/activate"), 0);
    host.stop().unwrap();
}

#[test]
fn a_blank_name_is_refused_and_nothing_is_activated() {
    // The plain-folder refusal below only exists in the embedded shape; a workspace build unifies
    // the daemon's `process-model` feature on (see `embedded_defaults.rs`).
    if !HAS_PROVIDER || support::desktop_shaped_skip() {
        return;
    }
    let _serial = serialized();
    let fake = Fake::start();
    let (host, _area) = host_against(&fake);
    // An empty name is a plain folder, which this build cannot link; a blank one is a provider
    // folder with no usable name.
    let result = host.execute(join("", "token-1"), &within());
    let Err(CallError::Failed(error)) = result else { panic!("expected a refusal: {result:?}") };
    assert_eq!(error.kind(), CommandErrorKind::NoChangeSource);
    let blank = refusal(host.execute(join("   ", "token-2"), &within()));
    assert!(
        matches!(
            blank,
            ApplicationErrorCode::PreparationRejected | ApplicationErrorCode::LocalLinkFailed
        ),
        "{blank:?}"
    );
    assert_eq!(folders(&host), 0);
    assert_eq!(fake.count("/activate"), 0);
    host.stop().unwrap();
}

#[test]
fn a_token_reused_for_another_name_is_refused_and_the_first_folder_stays() {
    if !HAS_PROVIDER {
        return;
    }
    let _serial = serialized();
    let fake = Fake::start();
    let (host, _area) = host_against(&fake);
    host.execute(join("Photos", "token-1"), &within()).unwrap();
    let mismatch = refusal(host.execute(join("Documents", "token-1"), &within()));
    assert_ne!(mismatch, ApplicationErrorCode::Unspecified);
    assert_eq!(folders(&host), 1);
    host.stop().unwrap();
}

#[test]
fn creating_a_provider_share_prepares_activates_and_a_retry_changes_nothing() {
    if !HAS_PROVIDER {
        return;
    }
    let _serial = serialized();
    let fake = Fake::start();
    let (host, _area) = host_against(&fake);
    let create = || {
        Command::CreateShare(CreateShare {
            group_name: "Photos".into(),
            folder: provider("Photos", "token-1"),
            on_demand: true,
            acknowledge_risks: false,
        })
    };
    let CommandOutput::Shared(first) = host.execute(create(), &within()).unwrap() else {
        panic!("a share outcome")
    };
    assert_eq!(first.group_id, "g-create");
    assert!(first.provider_root_id.is_some());
    assert_eq!(fake.count("/shares/groups/prepare"), 1);
    assert_eq!(fake.count("/activate"), 1);
    assert_eq!(folders(&host), 1);

    let CommandOutput::Shared(again) = host.execute(create(), &within()).unwrap() else {
        panic!("a share outcome")
    };
    assert_eq!(again.group_id, first.group_id);
    assert_eq!(folders(&host), 1);
    host.stop().unwrap();
}
