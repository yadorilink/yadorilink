//! The stand-in for the operating system's open-triggered fetch.
//!
//! A real host fills a placeholder when a process opens it: the OS calls the host, the host asks
//! the daemon for the bytes and hands them to the OS. A plain directory cannot intercept an
//! `open`, so the same step is an explicit request on a small control socket, one line per
//! connection:
//!
//! * `hydrate <path>`: fetch the item's current version from the daemon (progress is logged) and
//!   put it in place; answers `ok <bytes>` or `err <why>`;
//! * `cancel <path>`: abandon the fetch in flight for that path (the daemon aborts the request);
//! * `state <path>`: `placeholder`, `hydrated`, `changed` (edited, not shared yet), `plain` or
//!   `missing`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::MaterializeFailure;
use yadorilink_windows_provider_policy::host::{read_registry_at, unhex};
use yadorilink_windows_provider_policy::provider_client::{
    exchange, materialize_request, note_fetch_activity, runtime, Connect, FetchTarget,
};

use crate::daemon::Socket;
use crate::plain_fs::{hex, PlainFs};

/// A whole file can be large and the peer slow: this bounds one fetch, not a window of it.
const FETCH_TIMEOUT: Duration = Duration::from_secs(1800);

pub struct Control {
    pub fs: Arc<PlainFs>,
    pub socket: Socket,
    pub registry_file: PathBuf,
    pub handoff_dir: PathBuf,
    pub fetches: crate::flight::SingleFlight<PathBuf, Result<u64, String>>,
}

pub fn serve(control: Arc<Control>, path: &Path) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let control = control.clone();
            std::thread::spawn(move || handle(&control, stream));
        }
    });
    Ok(())
}

fn handle(control: &Control, mut stream: UnixStream) {
    let mut line = String::new();
    if BufReader::new(&stream).read_line(&mut line).is_err() {
        return;
    }
    let line = line.trim_end_matches(['\n', '\r']);
    let answer = match line.split_once(' ') {
        Some(("hydrate", path)) => match control.hydrate(Path::new(path)) {
            Ok(bytes) => format!("ok {bytes}"),
            Err(why) => format!("err {why}"),
        },
        Some(("cancel", path)) => {
            if control.fetches.cancel(&PathBuf::from(path)) {
                eprintln!("plain-dir-host: [{}] cancel of {path}", unix_secs());
                "ok cancelled".to_string()
            } else {
                "err nothing in flight".to_string()
            }
        }
        Some(("state", path)) => control.state(Path::new(path)).to_string(),
        _ => "err unknown request".to_string(),
    };
    let _ = writeln!(stream, "{}", answer.replace('\n', " "));
}

impl Control {
    /// The root (id and path) a path is in, from the host's own record of its sync roots.
    fn root_of(&self, path: &Path) -> Option<(Vec<u8>, PathBuf)> {
        let roots = read_registry_at(&self.registry_file).ok()?;
        roots
            .into_iter()
            .find(|(_, root)| path.starts_with(root))
            .and_then(|(id, root)| Some((unhex(&id)?, root)))
    }

    fn state(&self, path: &Path) -> &'static str {
        let Ok(md) = std::fs::symlink_metadata(path) else { return "missing" };
        match self.fs.placeholder_info(path) {
            None => "plain",
            Some(_) if md.is_dir() => "plain",
            Some(info) if info.dehydrated => "placeholder",
            Some(info) if info.in_sync => "hydrated",
            Some(_) => "changed",
        }
    }

    /// A download request for an item: what the OS does for the host app's request. Whether bytes
    /// were fetched now (false: the item already held them, which the OS answers without any
    /// change).
    pub fn download(&self, path: &Path) -> Result<bool, String> {
        let already = self.fs.placeholder_info(path).is_some_and(|info| !info.dehydrated);
        self.hydrate(path).map(|_| !already)
    }

    pub fn hydrate(&self, path: &Path) -> Result<u64, String> {
        let path = path.canonicalize().map_err(|e| format!("{}: {e}", path.display()))?;
        // One fetch per path: a second request joins the first.
        self.fetches.run(&path, |cancel| self.hydrate_once(&path, cancel))
    }

    fn hydrate_once(&self, path: &Path, cancel: &AtomicBool) -> Result<u64, String> {
        let path = path.to_path_buf();
        let (root, _) = self.root_of(&path).ok_or("not in a sync root of this host")?;
        let info = self.fs.placeholder_info(&path).ok_or("not a placeholder")?;
        if info.is_dir {
            return Err("a folder has nothing to fetch".into());
        }
        if !info.dehydrated {
            return if info.in_sync { Ok(info.size) } else { Err("changed locally".into()) };
        }
        // The version the placeholder itself stands for, not what the namespace says by now: the
        // install checks the placeholder still stands for exactly this.
        let (item, version, size) =
            self.fs.placeholder_target(&path).ok_or("the placeholder stands for no version")?;
        let (handoff, size) = self.fetch(&root, &item, version, size, cancel)?;
        let handed = self.handoff_dir.join(&handoff);
        let result = self.fs.hydrate_from(&path, &item, &version, &handed);
        let _ = std::fs::remove_file(&handed);
        let bytes = result?;
        if bytes != size {
            return Err(format!("the handoff held {bytes} bytes, the daemon said {size}"));
        }
        Ok(bytes)
    }

    /// Asks the daemon for the whole file of `version`; returns its handoff name and size.
    fn fetch(
        &self,
        root: &[u8],
        item: &[u8],
        version: [u8; 32],
        size: u64,
        cancel: &AtomicBool,
    ) -> Result<(String, u64), String> {
        note_fetch_activity(&self.socket, root, item);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let request_id =
            format!("standin-{}-{nanos}", hex(&item[..item.len().min(8)])).into_bytes();
        let mut request = materialize_request(
            root,
            item,
            &request_id,
            Some(FetchTarget { version, range: None }),
        );
        request.report_progress = true;
        let response = runtime().block_on(async {
            let work = tokio::time::timeout(FETCH_TIMEOUT, async {
                let mut stream = self.socket.connect().await.ok()?;
                exchange(&mut stream, root, Payload::MaterializeToTempRequest(request), |payload| {
                    match payload {
                        Payload::MaterializeProgress(p) if p.request_id == request_id => {
                            eprintln!(
                                "plain-dir-host: fetch progress {}/{} bytes{}",
                                p.completed,
                                p.total,
                                if p.done { " (verified)" } else { "" }
                            );
                            None
                        }
                        Payload::MaterializeToTempResponse(r) if r.request_id == request_id => {
                            Some(r)
                        }
                        _ => None,
                    }
                })
                .await
            });
            let cancelled = async {
                while !cancel.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            };
            tokio::select! {
                answer = work => answer.ok().flatten(),
                () = cancelled => None,
            }
        });
        let Some(response) = response else {
            return Err(if cancel.load(Ordering::Relaxed) {
                "cancelled".into()
            } else {
                "the daemon did not answer".into()
            });
        };
        if !response.ok {
            let failure = MaterializeFailure::try_from(response.failure)
                .map_or_else(|_| response.failure.to_string(), |f| format!("{f:?}"));
            return Err(format!("{failure}: {}", response.error));
        }
        if response.handoff_name.is_empty() {
            return Err("the daemon answered ok without a handoff file".into());
        }
        // Only the version asked for, whole, of the size the placeholder stands for, is installed.
        if response.version_hash != version || response.size != size || response.ranged {
            let _ = std::fs::remove_file(self.handoff_dir.join(&response.handoff_name));
            return Err("the daemon handed over something other than the requested version".into());
        }
        Ok((response.handoff_name, response.size))
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
