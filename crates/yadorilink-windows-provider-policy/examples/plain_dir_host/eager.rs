//! The Eager driver's host side, as the macOS host app drives it: per root, at most two downloads
//! outstanding, their item ids sent as exclusions with every query, and a slot is freed only when
//! the daemon answers the id as settled or the OS finishes the download. An item the OS already
//! holds is a request the OS answers without any change, so its slot stays taken until the
//! daemon settles it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_ipc_proto::shellipc::NextProviderDownloadsResponse;
use yadorilink_windows_provider_policy::host::{
    read_registry_at, read_shown_at, unhex, LoadedShown,
};

use crate::control::Control;
use crate::daemon::Link;

const ASK_EVERY: Duration = Duration::from_secs(2);
const ANSWER_WITHIN: Duration = Duration::from_secs(5);
const MAX_OUTSTANDING: usize = 2;

pub fn spawn(
    control: Arc<Control>,
    link: Link,
    answers: Receiver<NextProviderDownloadsResponse>,
    registry_file: PathBuf,
    state_dir: PathBuf,
) {
    std::thread::spawn(move || {
        let mut outstanding: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();
        loop {
            std::thread::sleep(ASK_EVERY);
            let Ok(roots) = read_registry_at(&registry_file) else { continue };
            for root in roots.keys().filter_map(|id| unhex(id)) {
                let slots = outstanding.entry(root.clone()).or_default();
                tick(&control, &link, &answers, &state_dir, &root, slots);
            }
        }
    });
}

/// One query of one root and what follows from the answer.
fn tick(
    control: &Control,
    link: &Link,
    answers: &Receiver<NextProviderDownloadsResponse>,
    state_dir: &Path,
    root: &[u8],
    slots: &mut HashSet<Vec<u8>>,
) {
    let room = MAX_OUTSTANDING.saturating_sub(slots.len());
    let request_id = link.next_downloads(root, slots.iter().cloned().collect(), room as u32);
    let trace = std::env::var_os("PLAIN_DIR_HOST_TRACE").is_some();
    let Some(answer) = await_answer(answers, root, &request_id, ANSWER_WITHIN) else {
        if trace {
            eprintln!("plain-dir-host: [{}] eager query unanswered (room={room})", unix_secs());
        }
        // Its late answer, if one comes, names this query's id and is dropped by the next one.
        return;
    };
    for settled in &answer.settled_item_ids {
        slots.remove(settled);
    }
    if trace || !answer.downloads.is_empty() || !answer.settled_item_ids.is_empty() {
        eprintln!(
            "plain-dir-host: [{}] eager query root={} room={room} outstanding={} -> offered={} \
             settled={} state={}",
            unix_secs(),
            crate::plain_fs::hex(&root[..4]),
            slots.len(),
            answer.downloads.len(),
            answer.settled_item_ids.len(),
            answer.state
        );
    }
    for download in answer.downloads {
        if slots.len() >= MAX_OUTSTANDING {
            break;
        }
        let Some(path) = path_of(state_dir, root, &download.item_id) else {
            eprintln!("plain-dir-host: no path is shown for a wanted item");
            continue;
        };
        match control.download(&path) {
            // The OS now holds it: the next report lists it and the slot is free.
            Ok(true) => eprintln!("plain-dir-host: downloaded {}", path.display()),
            // Nothing to fetch: the request is accepted and the slot stays taken.
            Ok(false) => {
                slots.insert(download.item_id);
            }
            Err(why) => eprintln!("plain-dir-host: download of {} failed: {why}", path.display()),
        }
    }
}

/// The answer to the query `request_id` of `root`, or `None` when it does not arrive in time.
/// Answers that name another query (a late answer to one given up on) are dropped.
fn await_answer(
    answers: &Receiver<NextProviderDownloadsResponse>,
    root: &[u8],
    request_id: &[u8],
    within: Duration,
) -> Option<NextProviderDownloadsResponse> {
    let deadline = std::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let answer = answers.recv_timeout(left).ok()?;
        if answer.request_id == request_id && answer.root_id == root {
            return Some(answer);
        }
    }
}

/// Where the host shows `item` of `root`, from the record of what it shows.
fn path_of(state_dir: &Path, root: &[u8], item: &[u8]) -> Option<PathBuf> {
    let file = state_dir.join("authoring").join(crate::plain_fs::hex(root)).join("shown");
    match read_shown_at(&file) {
        LoadedShown::Loaded(shown) => shown.get(item).map(|shown| shown.path.clone()),
        _ => None,
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    fn answer(request_id: &[u8], root: &[u8], settled: &[u8]) -> NextProviderDownloadsResponse {
        NextProviderDownloadsResponse {
            request_id: request_id.to_vec(),
            root_id: root.to_vec(),
            settled_item_ids: vec![settled.to_vec()],
            ..Default::default()
        }
    }

    #[test]
    fn a_late_answer_to_an_earlier_query_is_dropped() {
        let (tx, rx) = channel();
        tx.send(answer(b"old", b"root", b"stale")).unwrap();
        tx.send(answer(b"new", b"other-root", b"wrong-root")).unwrap();
        tx.send(answer(b"new", b"root", b"fresh")).unwrap();
        let got = await_answer(&rx, b"root", b"new", Duration::from_millis(200)).unwrap();
        assert_eq!(got.settled_item_ids, [b"fresh".to_vec()]);
    }

    #[test]
    fn no_matching_answer_times_out_without_reconnecting() {
        let (tx, rx) = channel();
        tx.send(answer(b"old", b"root", b"stale")).unwrap();
        assert!(await_answer(&rx, b"root", b"new", Duration::from_millis(50)).is_none());
        // The next query's own answer is still taken afterwards.
        tx.send(answer(b"next", b"root", b"ok")).unwrap();
        assert!(await_answer(&rx, b"root", b"next", Duration::from_millis(50)).is_some());
    }
}
