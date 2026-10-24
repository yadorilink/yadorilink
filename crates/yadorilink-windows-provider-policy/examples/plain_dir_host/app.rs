//! The stand-in's process: arguments, the host's loop and its threads.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::time::{Duration, Instant};

use yadorilink_windows_provider_policy::host::{Host, HostEvent, POLL_INTERVAL};
use yadorilink_windows_provider_policy::provider_session::SessionEvent;

use crate::daemon::Socket;
use crate::{backend, control, daemon, eager, plain_fs};

/// The name every root is shown under, ahead of the folder's own name.
const LOCATION_PREFIX: &str = "StandIn";

/// A loop step longer than this is logged.
const SLOW_STEP: Duration = Duration::from_secs(1);

struct Args {
    socket: PathBuf,
    state_dir: PathBuf,
    view_parent: PathBuf,
    control: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut values: HashMap<String, PathBuf> = HashMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        values.insert(flag, PathBuf::from(value));
    }
    let mut take = |flag: &str| {
        values
            .remove(flag)
            .map(|p| std::path::absolute(&p).unwrap_or(p))
            .ok_or_else(|| format!("{flag} is required"))
    };
    Ok(Args {
        socket: take("--socket")?,
        state_dir: take("--state-dir")?,
        view_parent: take("--view-parent")?,
        control: take("--control")?,
    })
}

pub fn run() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("plain-dir-host: {e}");
            std::process::exit(2);
        }
    };
    let container = args.state_dir.join("host");
    let temp_root = container.join("provider");
    let sync_roots_parent = args.view_parent.join("CloudStorage");
    for dir in [&container, &sync_roots_parent] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("plain-dir-host: cannot create {}: {e}", dir.display());
            std::process::exit(2);
        }
    }
    let fs = match plain_fs::PlainFs::open(
        &args.state_dir,
        temp_root.join("ingest"),
        args.view_parent.join(".hydrate-staging"),
    ) {
        Ok(fs) => Arc::new(fs),
        Err(e) => {
            eprintln!("plain-dir-host: cannot open the placeholder record: {e}");
            std::process::exit(2);
        }
    };
    let socket = Socket(args.socket);
    let registry_file = args.state_dir.join("sync_roots.txt");

    let ctl = Arc::new(control::Control {
        fs: fs.clone(),
        socket: socket.clone(),
        registry_file: registry_file.clone(),
        handoff_dir: temp_root.join("handoff"),
        fetches: crate::flight::SingleFlight::default(),
    });
    if let Err(e) = control::serve(ctl.clone(), &args.control) {
        eprintln!("plain-dir-host: cannot serve {}: {e}", args.control.display());
        std::process::exit(2);
    }

    let (events, inbox) = std::sync::mpsc::channel::<HostEvent>();
    let (downloads_tx, downloads) = std::sync::mpsc::channel();
    let link = daemon::spawn(socket.clone(), events.clone(), downloads_tx);
    let backend = backend::PlainBackend {
        fs,
        socket: socket.clone(),
        events,
        state_dir: args.state_dir.clone(),
    };
    let mut host = Host::new(backend, link.clone(), registry_file.clone(), sync_roots_parent);
    eager::spawn(ctl, link, downloads, registry_file, args.state_dir.clone());
    println!("plain-dir-host: started (poll interval {POLL_INTERVAL:?})");
    let snapshot = || {
        daemon::list_provider_folders(&socket, &container.to_string_lossy()).map(
            |(mut folders, removals)| {
                // A location is `<provider>-<folder name>`, as under macOS's CloudStorage.
                for folder in &mut folders {
                    folder.display_name = format!("{LOCATION_PREFIX}-{}", folder.display_name);
                }
                (folders, removals)
            },
        )
    };
    let mut reconcile_due = true;
    let mut last_reconcile = Instant::now();
    loop {
        if reconcile_due {
            host.reconcile(snapshot());
            reconcile_due = false;
            last_reconcile = Instant::now();
        }
        let wait = host.next_deadline(Instant::now(), POLL_INTERVAL);
        let event = inbox.recv_timeout(wait);
        let handled = Instant::now();
        let kind = match &event {
            Ok(HostEvent::Session(SessionEvent::Evict { .. })) => "eviction request",
            Ok(HostEvent::Session(SessionEvent::Changed { .. })) => "namespace change",
            Ok(HostEvent::Session(SessionEvent::EvidenceTick { .. })) => "evidence tick",
            Ok(HostEvent::Session(_)) => "session event",
            Ok(HostEvent::Local { .. }) => "local change",
            Err(_) => "poll",
        };
        match event {
            Ok(HostEvent::Session(SessionEvent::Connected)) => {
                host.on_connected();
                reconcile_due = true;
            }
            Ok(HostEvent::Session(SessionEvent::Closed)) => {
                eprintln!("plain-dir-host: daemon connection closed");
            }
            Ok(HostEvent::Session(SessionEvent::Changed { root, revision, request_id })) => {
                reconcile_due = host.on_changed(&root, revision, &request_id);
            }
            Ok(HostEvent::Session(SessionEvent::Evict {
                root,
                item,
                request_id,
                require_shown_version,
            })) => host.on_evict(&root, &item, &request_id, &require_shown_version),
            Ok(HostEvent::Session(SessionEvent::EvidenceTick { root, seq })) => {
                host.on_evidence(&root, seq);
            }
            Ok(HostEvent::Session(SessionEvent::ReportAck { root, epoch, needs_full })) => {
                host.on_report_ack(&root, epoch, needs_full);
            }
            Ok(HostEvent::Local { root, signal }) => host.on_local(&root, signal),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_reconcile.elapsed() >= POLL_INTERVAL {
            reconcile_due = true;
        }
        host.apply_due_local(Instant::now());
        // A step that held the loop up is the first thing to look at when the daemon waits on
        // this host (its acknowledgements are sent from here).
        if handled.elapsed() >= SLOW_STEP {
            eprintln!(
                "plain-dir-host: [{}] the loop spent {:?} on a {kind}",
                unix_secs(),
                handled.elapsed()
            );
        } else if kind == "eviction request" {
            eprintln!("plain-dir-host: [{}] handled an eviction request", unix_secs());
        }
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
