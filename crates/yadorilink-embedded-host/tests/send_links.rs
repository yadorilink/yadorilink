//! The Send commands end to end against a coordination plane served in process: what the
//! service answers (including "Send links are switched off") and what each answer becomes at
//! the host, and the sender's link list across an engine restart. Moving bytes between two
//! devices is covered by the daemon's `embedded_send_commands` test.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_client_core::dto::{SendLinkState, SendLinkTtl};
use yadorilink_embedded_host::{
    CallError, CallOptions, CancelHandle, Command, CommandErrorKind, CommandOutput, EmbeddedHost,
};
use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;

mod support;
use support::{area, serialized};

#[derive(Clone, Copy, PartialEq)]
enum Plane {
    On,
    Off,
    /// On, but every link it held is gone.
    Forgotten,
}

struct Fake {
    addr: String,
    plane: Arc<Mutex<Plane>>,
    /// The id the last create request carried, which the service answers with.
    created: Arc<Mutex<Option<String>>>,
}

impl Fake {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let plane = Arc::new(Mutex::new(Plane::On));
        let shared = plane.clone();
        let created: Arc<Mutex<Option<String>>> = Arc::default();
        let shared_created = created.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let plane = shared.clone();
                let created = shared_created.clone();
                std::thread::spawn(move || serve(&mut stream, &plane, &created));
            }
        });
        Self { addr, plane, created }
    }

    /// The link id the sender chose for the last link it created.
    fn created_id(&self) -> String {
        self.created.lock().unwrap().clone().expect("a link was created")
    }

    fn set(&self, plane: Plane) {
        *self.plane.lock().unwrap() = plane;
    }
}

fn serve(stream: &mut std::net::TcpStream, plane: &Mutex<Plane>, created: &Mutex<Option<String>>) {
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
    let request_body = String::from_utf8_lossy(&buffer[head_end..]).into_owned();
    let known = created.lock().unwrap().clone().unwrap_or_default();
    let (status, body) = if !path.starts_with("/send/links") {
        (404, "{}".to_owned())
    } else if *plane.lock().unwrap() == Plane::Off {
        (404, r#"{"error":"send links are not available","code":"send_links_disabled"}"#.to_owned())
    } else if *plane.lock().unwrap() == Plane::Forgotten && method == "GET" {
        (404, r#"{"error":"send link not found"}"#.to_owned())
    } else {
        match (method, path) {
            ("POST", "/send/links") => {
                // The service answers with the id the request carried.
                let id = request_body
                    .split("\"linkId\":\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    .unwrap_or_default()
                    .to_owned();
                *created.lock().unwrap() = Some(id.clone());
                (200, format!(r#"{{"linkId":"{id}","expiresAt":4102444800}}"#))
            }
            ("GET", p) if !known.is_empty() && p == format!("/send/links/{known}") => {
                (200, format!(r#"{{"linkId":"{known}","state":"open","expiresAt":4102444800}}"#))
            }
            ("DELETE", p) if !known.is_empty() && p == format!("/send/links/{known}") => {
                (200, r#"{"cancelled":true}"#.to_owned())
            }
            _ => (404, r#"{"error":"send link is invalid, expired, or already used"}"#.to_owned()),
        }
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
    point_at(&host, fake);
    (host, area)
}

fn point_at(host: &EmbeddedHost, fake: &Fake) {
    host.set_coordination_for_test(
        fake.addr.clone(),
        yadorilink_fapi_client::test_support::offline_auth(),
    )
    .unwrap();
}

fn refusal(result: Result<CommandOutput, CallError>) -> ApplicationErrorCode {
    let Err(CallError::Failed(error)) = result else { panic!("expected a refusal: {result:?}") };
    match error.kind() {
        CommandErrorKind::Refused(code) => code,
        other => panic!("expected a typed refusal, got {other:?}: {}", error.message()),
    }
}

/// A well-formed code that no link was made for.
const CODE: &str = "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA";

fn create() -> Command {
    Command::CreateSendLink { ttl: SendLinkTtl::OneHour, source_paths: Vec::new() }
}

#[test]
fn a_service_with_send_links_off_is_a_typed_refusal_not_an_invalid_link() {
    let _serial = serialized();
    let fake = Fake::start();
    let (host, _area) = host_against(&fake);
    fake.set(Plane::Off);
    assert_eq!(refusal(host.execute(create(), &within())), ApplicationErrorCode::SendLinksDisabled);
    assert_eq!(
        refusal(host.execute(Command::PreviewSendLink { code: CODE.into() }, &within())),
        ApplicationErrorCode::SendLinksDisabled
    );
    assert_eq!(
        refusal(host.execute(
            Command::RedeemSendLink { code: CODE.into(), device_id: None, destination_dir: None },
            &within()
        )),
        ApplicationErrorCode::SendLinksDisabled
    );
    // Switched on again, the same engine creates a link.
    fake.set(Plane::On);
    let CommandOutput::SendLink(link) = host.execute(create(), &within()).unwrap() else {
        panic!("a link")
    };
    assert_eq!(link.link_id, fake.created_id());
    // An unknown code on a service that has Send links is still just invalid.
    assert_eq!(
        refusal(host.execute(Command::PreviewSendLink { code: CODE.into() }, &within())),
        ApplicationErrorCode::SendLinkInvalid
    );
    host.stop().unwrap();
}

#[test]
fn the_senders_link_list_survives_an_engine_restart() {
    let _serial = serialized();
    let fake = Fake::start();
    let (host, _area) = host_against(&fake);
    let CommandOutput::SendLinks(none) = host.execute(Command::ListSendLinks, &within()).unwrap()
    else {
        panic!("a list")
    };
    assert!(none.is_empty());
    host.execute(create(), &within()).unwrap();

    host.suspend().unwrap();
    host.resume().unwrap();
    point_at(&host, &fake);

    let CommandOutput::SendLinks(links) = host.execute(Command::ListSendLinks, &within()).unwrap()
    else {
        panic!("a list")
    };
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].status.link_id, fake.created_id());
    assert_eq!(links[0].status.state, SendLinkState::Waiting);
    assert_eq!(links[0].file_count, 0);

    // A link the service no longer knows drops out of the list, and stays out.
    fake.set(Plane::Forgotten);
    for _ in 0..2 {
        let CommandOutput::SendLinks(links) =
            host.execute(Command::ListSendLinks, &within()).unwrap()
        else {
            panic!("a list")
        };
        assert!(links.is_empty());
    }
    host.stop().unwrap();
}

#[test]
fn the_inbox_is_empty_on_a_fresh_registered_engine_and_stopping_leaves_nothing_open() {
    let _serial = serialized();
    let fake = Fake::start();
    let (host, _area) = host_against(&fake);
    let probe = host.release_probe().unwrap();
    // The Send service comes up once the engine's endpoint exists; until then the inbox says so.
    let _ = host.execute(Command::ListInbox, &within());
    host.stop().unwrap();
    assert!(support::released(&probe), "the Send service held the engine's state after a stop");
}
