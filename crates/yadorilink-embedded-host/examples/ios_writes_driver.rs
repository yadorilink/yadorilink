//! A scripted "phone" for the end-to-end run of the iOS write path.
//!
//! It is the embedded host exactly as the app runs it: an `EmbeddedHost` over a data area, with
//! the provider folder joined as an On-Demand member, and the app's four write calls (stage,
//! apply, discard, delivery) issued as commands. Its identity is the state directory a CLI
//! `login` and `device register` prepared, so it talks to the real coordination Worker and to the
//! other device over the real peer channel.
//!
//! ```text
//! ios_writes_driver --coordination-addr URL --config-dir DIR --data-dir DIR --state-dir DIR [--script FILE]
//! ```
//!
//! One engine runs for the whole script (stdin when `--script` is not given); the process exits
//! when the script ends. A line is one step; every step prints one result line the caller
//! greps for. Item ids, tokens and the next operation number persist in `--state-dir`, the
//! way the app keeps its upload queue, so the next run continues the same session:
//!
//! ```text
//! join GROUP_ID              declare the provider folder of a group the account is a member of
//! mkdir PATH                 create a folder
//! create PATH SRC [MODE]     stage SRC (move|clone|copy, default move) and create a file
//! modify PATH SRC [MODE]     stage SRC and replace the file's contents on the token last saved
//! rename PATH NAME           rename within the folder
//! move PATH PARENT           move into PARENT ("." is the root)
//! delete PATH [r]            delete, recursively for a folder, on the token last saved
//! replay                     send the last change again with the same operation identity
//! delivery PATH              ask once whether a full replica holds the saved version
//! wait-delivered PATH SECS   ask until a full replica holds it or SECS pass
//! sleep SECS                 keep the engine running (sync with the peer)
//! versions PATH              list the retained versions of the item
//! restore-version PATH SIZE  restore the retained version of that size over the live item
//! deleted                    list the deleted items that can be brought back
//! restore-deleted PATH       bring a deleted file or folder back (a folder before what was in it)
//! ```
#![allow(clippy::too_many_lines, reason = "a script driver")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use prost::Message;
use yadorilink_embedded_host::{
    ApplyChange, CallOptions, CancelHandle, Command, CommandOutput, CredentialBackend,
    CredentialConfig, DeletedParent, DeliveryItem, DeliveryState, EmbeddedHost, EngineConfig,
    EngineTuning, HistoryEntryKind, HistoryVersionState, KeyMirror, StageMode, StageSource,
    StagedHow, WitnessPlacement,
};
use yadorilink_ipc_proto::shellipc::{
    EntryKind, ProviderApplyChangeRequest, ProviderApplyFailure, ProviderChangeKind,
    ProviderContentSource, ProviderRestoreSource,
};

/// The file's inode where the platform has one (the script that runs this is a Unix one).
fn inode(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

const SESSION: [u8; 16] = [0xE2; 16];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn die(message: &str) -> ! {
    eprintln!("ios_writes_driver: {message}");
    std::process::exit(2);
}

#[derive(Clone)]
struct Item {
    id: Vec<u8>,
    token: Vec<u8>,
    directory: bool,
}

/// What the app keeps between runs: the root, the next operation number and the items it knows.
struct State {
    dir: PathBuf,
    root_id: Vec<u8>,
    next_seq: u64,
    items: BTreeMap<String, Item>,
}

impl State {
    fn load(dir: &Path) -> State {
        std::fs::create_dir_all(dir).unwrap();
        let mut state =
            State { dir: dir.into(), root_id: Vec::new(), next_seq: 1, items: BTreeMap::new() };
        if let Ok(text) = std::fs::read_to_string(dir.join("state.tsv")) {
            for line in text.lines() {
                let f: Vec<&str> = line.split('\t').collect();
                match f.as_slice() {
                    ["root", id] => state.root_id = unhex(id),
                    ["seq", n] => state.next_seq = n.parse().unwrap(),
                    ["item", path, id, token, kind] => {
                        state.items.insert(
                            (*path).to_owned(),
                            Item { id: unhex(id), token: unhex(token), directory: *kind == "D" },
                        );
                    }
                    _ => {}
                }
            }
        }
        state
    }

    fn save(&self) {
        let mut text = format!("root\t{}\nseq\t{}\n", hex(&self.root_id), self.next_seq);
        for (path, item) in &self.items {
            text += &format!(
                "item\t{path}\t{}\t{}\t{}\n",
                hex(&item.id),
                hex(&item.token),
                if item.directory { "D" } else { "F" }
            );
        }
        let tmp = self.dir.join("state.tsv.tmp");
        std::fs::write(&tmp, text).unwrap();
        std::fs::rename(tmp, self.dir.join("state.tsv")).unwrap();
    }

    fn item(&self, path: &str) -> Item {
        self.items.get(path).cloned().unwrap_or_else(|| die(&format!("no item at {path}")))
    }

    /// The parent folder's item id: empty for the root container.
    fn parent_of(&self, path: &str) -> Vec<u8> {
        match path.rsplit_once('/') {
            Some((parent, _)) => self.item(parent).id,
            None => Vec::new(),
        }
    }

    fn forget_under(&mut self, path: &str) {
        let prefix = format!("{path}/");
        self.items.retain(|p, _| p != path && !p.starts_with(&prefix));
    }

    fn rekey(&mut self, from: &str, to: &str) {
        let prefix = format!("{from}/");
        let moved: Vec<String> =
            self.items.keys().filter(|p| *p == from || p.starts_with(&prefix)).cloned().collect();
        for old in moved {
            let item = self.items.remove(&old).unwrap();
            self.items.insert(format!("{to}{}", &old[from.len()..]), item);
        }
    }
}

struct Driver {
    host: EmbeddedHost,
    state: State,
    ingest_dir: PathBuf,
}

fn within() -> CallOptions {
    CallOptions { deadline: Some(Duration::from_secs(600)), cancel: CancelHandle::new() }
}

impl Driver {
    fn request(&mut self, kind: ProviderChangeKind) -> ProviderApplyChangeRequest {
        let seq = self.state.next_seq;
        self.state.next_seq += 1;
        self.state.save();
        ProviderApplyChangeRequest {
            request_id: format!("attempt-{seq}").into_bytes(),
            session_id: SESSION.to_vec(),
            operation_seq: seq,
            root_id: self.state.root_id.clone(),
            kind: kind as i32,
            ..Default::default()
        }
    }

    /// Stages `source`; prints the staged line, or the refusal and returns `None`.
    fn stage(&self, label: &str, source: &Path, mode: &str) -> Option<ProviderContentSource> {
        let source_inode = inode(source);
        let mode = match mode {
            "move" => StageMode::Move,
            "clone" => StageMode::Clone,
            "copy" => StageMode::Copy,
            other => die(&format!("unknown stage mode {other}")),
        };
        let CommandOutput::Staged(staged) = self
            .host
            .execute(
                Command::StageUpload { source: StageSource::Path(source.into()), mode },
                &within(),
            )
            .unwrap_or_else(|e| die(&format!("stage: {e:?}")))
        else {
            die("stage answered something else")
        };
        match staged {
            Ok(staged) => {
                let same_inode = source_inode.is_some()
                    && inode(&self.ingest_dir.join(&staged.ingest_name)) == source_inode;
                println!(
                    "STAGED {label} how={} same_inode={same_inode} source_exists={} size={} sha256={}",
                    match staged.how {
                        StagedHow::Moved => "Moved",
                        StagedHow::Cloned => "Cloned",
                        StagedHow::Copied => "Copied",
                    },
                    source.exists(),
                    staged.size,
                    hex(&staged.sha256)
                );
                Some(ProviderContentSource {
                    ingest_name: staged.ingest_name,
                    size: staged.size,
                    sha256: staged.sha256.to_vec(),
                })
            }
            Err(refused) => {
                println!("REFUSED {label} stage {:?}", refused.code);
                None
            }
        }
    }

    /// Sends `request` until the engine knows the device is a writer of the group (a fresh engine
    /// learns the group's policy first); any other answer is final. Returns the response.
    fn send(
        &self,
        request: &ProviderApplyChangeRequest,
    ) -> yadorilink_ipc_proto::shellipc::ProviderApplyChangeResponse {
        let started = Instant::now();
        loop {
            let CommandOutput::Applied(response) = self
                .host
                .execute(Command::ApplyChange(Box::new(ApplyChange(request.clone()))), &within())
                .unwrap_or_else(|e| die(&format!("apply: {e:?}")))
            else {
                die("apply answered something else")
            };
            let response = response.0;
            let waiting = matches!(
                ProviderApplyFailure::try_from(response.failure),
                Ok(ProviderApplyFailure::NotAuthorized | ProviderApplyFailure::NotReady)
            );
            if response.ok || !waiting || started.elapsed() > Duration::from_secs(90) {
                return response;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Persists the request (the app's upload queue), sends it and prints the result line.
    fn apply(
        &mut self,
        label: &str,
        request: ProviderApplyChangeRequest,
    ) -> Option<yadorilink_ipc_proto::shellipc::ProviderAppliedItem> {
        std::fs::write(self.state.dir.join("last_request.bin"), request.encode_to_vec()).unwrap();
        let response = self.send(&request);
        self.report(label, &response)
    }

    fn report(
        &self,
        label: &str,
        response: &yadorilink_ipc_proto::shellipc::ProviderApplyChangeResponse,
    ) -> Option<yadorilink_ipc_proto::shellipc::ProviderAppliedItem> {
        if response.ok {
            let outcome = match response.outcome {
                1 => "Applied",
                3 => "Concurrent",
                4 => "FileSurvived",
                _ => "Unspecified",
            };
            let item = response.item.clone();
            println!(
                "OK {label} outcome={outcome} replayed={} item={} token={}",
                response.replayed,
                item.as_ref().map_or_else(String::new, |i| hex(&i.item_id)),
                item.as_ref().map_or_else(String::new, |i| hex(&i.content_version)),
            );
            item
        } else {
            println!(
                "REFUSED {label} {:?} {}",
                ProviderApplyFailure::try_from(response.failure)
                    .unwrap_or(ProviderApplyFailure::None),
                response.error
            );
            None
        }
    }

    fn delivery(&self, path: &str) -> (DeliveryState, u32) {
        let item = self.state.item(path);
        let CommandOutput::Delivery(outcome) = self
            .host
            .execute(
                Command::VersionDelivery {
                    items: vec![DeliveryItem {
                        root_id: self.state.root_id.clone(),
                        item_id: item.id,
                        content_version: item.token,
                    }],
                },
                &within(),
            )
            .unwrap_or_else(|e| die(&format!("delivery: {e:?}")))
        else {
            die("delivery answered something else")
        };
        let state = outcome.report.items.into_iter().next().unwrap().state;
        (state, outcome.report.undelivered_count)
    }

    fn run(&mut self, line: &str) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some((&command, args)) = words.split_first() else { return };
        match (command, args) {
            ("join", [name]) => self.join(name),
            ("mkdir", [path]) => {
                let mut r = self.request(ProviderChangeKind::Create);
                r.name = Some(path.rsplit('/').next().unwrap().to_owned());
                r.entry_kind = EntryKind::Directory as i32;
                r.parent_item_id = Some(self.state.parent_of(path)).filter(|p| !p.is_empty());
                if let Some(item) = self.apply(&format!("mkdir {path}"), r) {
                    self.state.items.insert(
                        (*path).to_owned(),
                        Item { id: item.item_id, token: item.content_version, directory: true },
                    );
                    self.state.save();
                }
            }
            ("create", [path, src, rest @ ..]) => {
                let Some(content) = self.stage(
                    &format!("create {path}"),
                    Path::new(src),
                    rest.first().copied().unwrap_or("move"),
                ) else {
                    return;
                };
                let mut r = self.request(ProviderChangeKind::Create);
                r.name = Some(path.rsplit('/').next().unwrap().to_owned());
                r.entry_kind = EntryKind::File as i32;
                r.parent_item_id = Some(self.state.parent_of(path)).filter(|p| !p.is_empty());
                r.content = Some(content);
                if let Some(item) = self.apply(&format!("create {path}"), r) {
                    self.state.items.insert(
                        (*path).to_owned(),
                        Item { id: item.item_id, token: item.content_version, directory: false },
                    );
                    self.state.save();
                }
            }
            ("modify", [path, src, rest @ ..]) => {
                let item = self.state.item(path);
                let Some(content) = self.stage(
                    &format!("modify {path}"),
                    Path::new(src),
                    rest.first().copied().unwrap_or("move"),
                ) else {
                    return;
                };
                let mut r = self.request(ProviderChangeKind::Modify);
                r.item_id = item.id;
                r.base_version_hash = item.token;
                r.content = Some(content);
                if let Some(applied) = self.apply(&format!("modify {path}"), r) {
                    // A conflict keeps the phone's bytes as a new item beside the file: the app
                    // follows the answer, so the saved token is the answer's.
                    let entry = self.state.items.get_mut(*path).unwrap();
                    entry.id = applied.item_id;
                    entry.token = applied.content_version;
                    self.state.save();
                }
            }
            ("rename", [path, name]) => {
                let item = self.state.item(path);
                let mut r = self.request(ProviderChangeKind::Modify);
                r.item_id = item.id;
                r.base_version_hash = item.token;
                r.name = Some((*name).to_owned());
                if let Some(applied) = self.apply(&format!("rename {path}"), r) {
                    let to = match path.rsplit_once('/') {
                        Some((parent, _)) => format!("{parent}/{name}"),
                        None => (*name).to_owned(),
                    };
                    self.state.rekey(path, &to);
                    self.state.items.get_mut(&to).unwrap().token = applied.content_version;
                    self.state.save();
                }
            }
            ("move", [path, parent]) => {
                let item = self.state.item(path);
                let target = if *parent == "." { Vec::new() } else { self.state.item(parent).id };
                let mut r = self.request(ProviderChangeKind::Modify);
                r.item_id = item.id;
                r.base_version_hash = item.token;
                r.parent_item_id = Some(target);
                if let Some(applied) = self.apply(&format!("move {path}"), r) {
                    let name = path.rsplit('/').next().unwrap();
                    let to =
                        if *parent == "." { name.to_owned() } else { format!("{parent}/{name}") };
                    self.state.rekey(path, &to);
                    self.state.items.get_mut(&to).unwrap().token = applied.content_version;
                    self.state.save();
                }
            }
            ("delete", [path, rest @ ..]) => {
                let item = self.state.item(path);
                let mut r = self.request(ProviderChangeKind::Delete);
                r.item_id = item.id;
                r.base_version_hash = item.token;
                r.recursive = !rest.is_empty();
                let label = format!("delete {path}");
                let request = r;
                std::fs::write(self.state.dir.join("last_request.bin"), request.encode_to_vec())
                    .unwrap();
                let response = self.send(&request);
                self.report(&label, &response);
                if response.ok {
                    self.state.forget_under(path);
                    self.state.save();
                }
            }
            ("replay", []) => {
                let bytes = std::fs::read(self.state.dir.join("last_request.bin"))
                    .unwrap_or_else(|_| die("nothing to replay"));
                let request = ProviderApplyChangeRequest::decode(bytes.as_slice()).unwrap();
                let response = self.send(&request);
                self.report(&format!("replay seq={}", request.operation_seq), &response);
            }
            ("delivery", [path]) => {
                let (state, undelivered) = self.delivery(path);
                println!("DELIVERY {path} {} undelivered={undelivered}", state_name(&state));
            }
            ("wait-delivered", [path, secs]) => {
                let deadline = Instant::now() + Duration::from_secs(secs.parse().unwrap());
                loop {
                    let (state, undelivered) = self.delivery(path);
                    if matches!(state, DeliveryState::Delivered { .. }) || Instant::now() > deadline
                    {
                        println!(
                            "DELIVERY {path} {} undelivered={undelivered}",
                            state_name(&state)
                        );
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            ("sleep", [secs]) => std::thread::sleep(Duration::from_secs(secs.parse().unwrap())),
            ("versions", [path]) => self.versions(path),
            ("restore-version", [path, size]) => self.restore_version(path, size.parse().unwrap()),
            ("deleted", []) => self.deleted(),
            ("restore-deleted", [path]) => self.restore_deleted(path),
            _ => die(&format!("unknown step: {line}")),
        }
    }

    /// The retained versions of the item at `path`, one line each, newest first.
    fn history(&self, path: &str) -> yadorilink_embedded_host::ItemHistory {
        let item = self.state.item(path);
        let CommandOutput::ItemVersions(outcome) = self
            .host
            .execute(
                Command::ListItemVersions { root_id: self.state.root_id.clone(), item_id: item.id },
                &within(),
            )
            .unwrap_or_else(|e| die(&format!("versions: {e:?}")))
        else {
            die("versions answered something else")
        };
        outcome.listing
    }

    fn versions(&self, path: &str) {
        let history = self.history(path);
        println!("VERSIONS {path} live={} count={}", history.live, history.versions.len());
        for v in &history.versions {
            println!(
                "VERSION {path} seq={} state={} size={} kind={} restorable={} origin={} hash={}",
                v.version_seq,
                match v.state {
                    HistoryVersionState::Current => "Current",
                    HistoryVersionState::Superseded => "Superseded",
                    HistoryVersionState::Trashed => "Trashed",
                },
                v.size,
                kind_name(v.kind),
                v.restorable,
                v.origin_device_id.as_deref().unwrap_or("-"),
                hex(&v.version_hash)
            );
        }
    }

    /// Restores the restorable version of `size` bytes as a new write over the live item.
    fn restore_version(&mut self, path: &str, size: u64) {
        let history = self.history(path);
        let Some(version) = history.versions.iter().find(|v| v.restorable && v.size == size) else {
            println!("REFUSED restore-version {path} no restorable version of {size} bytes");
            return;
        };
        let item = self.state.item(path);
        let mut r = self.request(ProviderChangeKind::Modify);
        r.item_id = item.id;
        r.base_version_hash = item.token;
        r.restore_from = Some(ProviderRestoreSource {
            path: history.path.clone(),
            version_hash: version.version_hash.clone(),
        });
        if let Some(applied) = self.apply(&format!("restore-version {path}"), r) {
            let entry = self.state.items.get_mut(path).unwrap();
            entry.token = applied.content_version;
            self.state.save();
            println!("RESTORED {path} size={}", applied.size);
        }
    }

    fn deleted_items(&self) -> yadorilink_embedded_host::DeletedItems {
        let CommandOutput::DeletedItems(outcome) = self
            .host
            .execute(Command::ListDeletedItems { root_id: self.state.root_id.clone() }, &within())
            .unwrap_or_else(|e| die(&format!("deleted: {e:?}")))
        else {
            die("deleted answered something else")
        };
        outcome.listing
    }

    fn deleted(&self) {
        let listing = self.deleted_items();
        println!("DELETED count={} truncated={}", listing.items.len(), listing.truncated);
        for d in &listing.items {
            println!(
                "DELETEDITEM {} parent={} size={} kind={} restorable={} origin={}",
                d.path,
                match &d.parent {
                    DeletedParent::Root => "Root".to_owned(),
                    DeletedParent::Item(id) => format!("Item:{}", hex(id)),
                    DeletedParent::Gone => "Gone".to_owned(),
                },
                d.size,
                kind_name(d.kind),
                d.restorable,
                d.origin_device_id.as_deref().unwrap_or("-"),
            );
        }
    }

    /// Brings a deleted file or folder back under its name and parent.
    fn restore_deleted(&mut self, path: &str) {
        let listing = self.deleted_items();
        let Some(entry) = listing.items.iter().find(|d| d.path == path) else {
            println!("REFUSED restore-deleted {path} not in the deleted list");
            return;
        };
        let parent = match &entry.parent {
            DeletedParent::Root => Vec::new(),
            DeletedParent::Item(id) => id.clone(),
            DeletedParent::Gone => {
                println!(
                    "REFUSED restore-deleted {path} its folder is deleted: restore that first"
                );
                return;
            }
        };
        let directory = entry.kind == HistoryEntryKind::Directory;
        let mut r = self.request(ProviderChangeKind::Create);
        r.name = Some(entry.name.clone());
        r.entry_kind = if directory { EntryKind::Directory } else { EntryKind::File } as i32;
        r.parent_item_id = Some(parent).filter(|p| !p.is_empty());
        r.restore_from = Some(ProviderRestoreSource {
            path: entry.path.clone(),
            version_hash: entry.version_hash.clone(),
        });
        if let Some(item) = self.apply(&format!("restore-deleted {path}"), r) {
            self.state.items.insert(
                path.to_owned(),
                Item { id: item.item_id, token: item.content_version, directory },
            );
            self.state.save();
            println!("RESTORED {path} size={}", item.size);
        }
    }

    /// The account's membership of the group was made by the CLI (a host without a File
    /// Provider refuses provider folders at enrollment); the provider folder itself is declared
    /// the way the app's link is, and the engine restarted so that it runs.
    fn join(&mut self, group_id: &str) {
        let root = self
            .host
            .add_provider_link_for_test(group_id)
            .unwrap_or_else(|e| die(&format!("provider link: {e:?}")));
        self.host.stop().unwrap_or_else(|e| die(&format!("stop: {e:?}")));
        self.host.start().unwrap_or_else(|e| die(&format!("restart: {e:?}")));
        self.state.root_id = unhex(&root);
        self.state.save();
        println!("OK join {group_id} root={root}");
    }
}

fn kind_name(kind: HistoryEntryKind) -> &'static str {
    match kind {
        HistoryEntryKind::File => "File",
        HistoryEntryKind::Directory => "Directory",
        HistoryEntryKind::Symlink => "Symlink",
    }
}

fn state_name(state: &DeliveryState) -> String {
    match state {
        DeliveryState::Delivered { device_ids } => format!("Delivered by={}", device_ids.join(",")),
        DeliveryState::NotDelivered => "NotDelivered".into(),
        DeliveryState::Superseded => "Superseded".into(),
        other => format!("{other:?}"),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut config_dir, mut data_dir, mut state_dir, mut script) = (None, None, None, None);
    let mut coordination = None;
    while let Some(flag) = args.next() {
        let value = args.next().unwrap_or_else(|| die(&format!("{flag} needs a value")));
        match flag.as_str() {
            "--config-dir" => config_dir = Some(PathBuf::from(value)),
            "--data-dir" => data_dir = Some(PathBuf::from(value)),
            "--state-dir" => state_dir = Some(PathBuf::from(value)),
            "--coordination-addr" => coordination = Some(value),
            "--script" => script = Some(PathBuf::from(value)),
            _ => die(&format!("unknown flag {flag}")),
        }
    }
    let config_dir = config_dir.unwrap_or_else(|| die("--config-dir is required"));
    let data_dir = data_dir.unwrap_or_else(|| die("--data-dir is required"));
    let state_dir = state_dir.unwrap_or_else(|| die("--state-dir is required"));
    let coordination = coordination.unwrap_or_else(|| die("--coordination-addr is required"));
    let tmp = data_dir.join("tmp");
    for sub in ["blocks", "db", "witness", "tmp"] {
        std::fs::create_dir_all(data_dir.join(sub)).unwrap();
    }
    let mut credentials = CredentialConfig::new(
        CredentialBackend::File(config_dir.join("credentials.json")),
        KeyMirror::Disabled,
    );
    credentials.coordination_addr = Some(coordination);
    let config = EngineConfig {
        credentials,
        config_dir,
        block_store_root: data_dir.join("blocks"),
        sync_db_path: data_dir.join("db/sync.sqlite3"),
        provider_temp_root: Some(tmp.clone()),
        machine_id: Some("ios-writes-e2e-phone".to_owned()),
        tuning: EngineTuning {
            witness: WitnessPlacement::Persistent(data_dir.join("witness")),
            ..EngineTuning::default()
        },
    };
    let host = EmbeddedHost::new(config);
    host.start().unwrap_or_else(|e| die(&format!("the engine did not start: {e:?}")));
    let mut driver =
        Driver { host, state: State::load(&state_dir), ingest_dir: tmp.join("ingest") };
    let text = match script {
        Some(path) => std::fs::read_to_string(path).unwrap(),
        None => std::io::read_to_string(std::io::stdin()).unwrap(),
    };
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        driver.run(line);
    }
    driver.host.stop().unwrap_or_else(|e| die(&format!("the engine did not stop: {e:?}")));
}
