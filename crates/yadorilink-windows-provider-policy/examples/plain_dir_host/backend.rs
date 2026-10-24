//! The host's operating-system side over a plain directory: what a sync root shows, what it
//! holds, and what the user did in it. The loop and every decision are the real provider host's
//! (`yadorilink_windows_provider_policy::host`); only the placeholder mechanics differ.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_ipc_proto::shellipc::{
    EntryKind, ProviderApplyChangeRequest, ProviderApplyChangeResponse, ProviderItem,
};
use yadorilink_windows_provider_policy::host::{
    encode_shown_record, hex, read_shown_at, Backend, HostEvent, LoadedShown, Signal,
};
use yadorilink_windows_provider_policy::namespace_policy::{
    keep_subtree, needs_update, valid_component, EvictOutcome, ShownItem, ShownItems,
};
use yadorilink_windows_provider_policy::provider_authoring::{self, Api, Authoring};
use yadorilink_windows_provider_policy::provider_client::{
    apply, enumerate_children, set_shown_versions, version_hash_of,
};

use crate::daemon::Socket;
use crate::plain_fs::{mtime_nanos, PlainFs};

pub struct PlainBackend {
    pub fs: Arc<PlainFs>,
    pub socket: Socket,
    pub events: Sender<HostEvent>,
    pub state_dir: PathBuf,
}

struct DaemonApi<'a> {
    backend: &'a PlainBackend,
}

impl Api for DaemonApi<'_> {
    fn apply(
        &self,
        root: &[u8],
        request: ProviderApplyChangeRequest,
    ) -> Option<ProviderApplyChangeResponse> {
        apply(&self.backend.socket, root, request)
    }

    fn save_shown(&self, root: &[u8], shown: &ShownItems) -> bool {
        self.backend.write_shown(root, shown)
    }
}

/// The versions a fetch of each shown item asks the daemon for.
fn publish_shown_versions(root_id: &[u8], shown: &ShownItems) {
    set_shown_versions(
        root_id,
        shown.iter().map(|(id, item)| (id.as_slice(), item.content_version.as_slice())),
    );
}

impl PlainBackend {
    fn authoring_dir(&self, root_id: &[u8]) -> PathBuf {
        self.state_dir.join("authoring").join(hex(root_id))
    }

    fn write_shown(&self, root_id: &[u8], shown: &ShownItems) -> bool {
        publish_shown_versions(root_id, shown);
        // A file the user authored is bound without a version. Once it is shown, it holds what
        // the daemon accepted, so that is the version a later eviction must be able to fetch.
        for (item_id, item) in shown.iter().filter(|(_, item)| !item.directory) {
            if let Some(version) = version_hash_of(&item.content_version) {
                self.fs.record_version(&item.path, item_id, &version);
            }
        }
        let file = self.authoring_dir(root_id).join("shown");
        let written =
            yadorilink_fs_platform::generation::publish_next(&file, &encode_shown_record(shown));
        if let Err(e) = &written {
            eprintln!("plain-dir-host: could not record the shown items: {e}");
        }
        written.is_ok()
    }
}

/// What one walk reads and compares against.
struct Walk<'a> {
    fs: &'a PlainFs,
    socket: &'a Socket,
    root_id: &'a [u8],
    previous: &'a ShownItems,
    protected: &'a HashSet<String>,
}

impl Backend for PlainBackend {
    fn prepare_root(&mut self, path: &Path) -> Result<(), String> {
        std::fs::create_dir_all(path).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn register_and_connect(&mut self, _root_id: &[u8], path: &Path) -> Result<(), String> {
        if path.is_dir() {
            Ok(())
        } else {
            Err(format!("{} is not a folder", path.display()))
        }
    }

    fn unregister(&mut self, _path: &Path) -> Result<(), String> {
        // The files stay where they are, like a removed domain's downloaded data.
        Ok(())
    }

    fn sync_namespace(
        &mut self,
        root_id: &[u8],
        path: &Path,
        previous: &ShownItems,
        protected: &HashSet<String>,
    ) -> Option<ShownItems> {
        let walk = Walk { fs: &self.fs, socket: &self.socket, root_id, previous, protected };
        let mut shown = ShownItems::new();
        let mut complete = true;
        sync_directory(&walk, path, &[], &mut shown, &mut complete);
        complete.then_some(shown)
    }

    fn evict(&mut self, path: &Path, item_id: &[u8]) -> Result<(), EvictOutcome> {
        self.fs.evict(path, item_id)
    }

    fn materialized(&mut self, shown: &ShownItems) -> HashSet<Vec<u8>> {
        shown
            .iter()
            .filter(|(_, item)| !item.directory)
            .filter(|(id, item)| {
                self.fs.placeholder_info(&item.path).is_some_and(|info| {
                    info.item_id.as_deref() == Some(id.as_slice())
                        && !info.is_dir
                        && !info.dehydrated
                        && info.in_sync
                })
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn load_shown(&mut self, root_id: &[u8]) -> LoadedShown {
        let loaded = read_shown_at(&self.authoring_dir(root_id).join("shown"));
        if let LoadedShown::Loaded(shown) = &loaded {
            publish_shown_versions(root_id, shown);
        }
        loaded
    }

    fn save_shown(&mut self, root_id: &[u8], shown: &ShownItems) -> bool {
        self.write_shown(root_id, shown)
    }

    fn volume_identified(&mut self, _path: &Path) -> Result<(), String> {
        Ok(())
    }

    fn namespace_available(&mut self, _path: &Path) -> bool {
        true
    }

    fn is_dir(&mut self, path: &Path) -> bool {
        path.is_dir()
    }

    fn watch(&mut self, key: &str, path: &Path) -> Option<Box<dyn std::any::Any>> {
        Some(Box::new(PollWatch::start(key.to_string(), path.to_path_buf(), self.events.clone())))
    }

    fn author(
        &mut self,
        root_id: &[u8],
        root_path: &Path,
        signals: &BTreeSet<PathBuf>,
        shown: &mut ShownItems,
    ) -> provider_authoring::Report {
        if !root_path.is_dir() {
            eprintln!("plain-dir-host: {} is not there; leaving it", root_path.display());
            return provider_authoring::Report::default();
        }
        match Authoring::open(root_id, root_path, &self.authoring_dir(root_id)) {
            Ok(authoring) => {
                authoring.process(signals, shown, self.fs.as_ref(), &DaemonApi { backend: self })
            }
            Err(e) => {
                eprintln!("plain-dir-host: cannot open the authoring state: {e}");
                provider_authoring::Report {
                    retry: signals.clone(),
                    ..provider_authoring::Report::default()
                }
            }
        }
    }

    fn listing(&mut self, root_path: &Path) -> BTreeSet<PathBuf> {
        fn walk(directory: &Path, out: &mut BTreeSet<PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(directory) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    out.insert(path.clone());
                    if entry.file_type().is_ok_and(|t| t.is_dir()) {
                        walk(&path, out);
                    }
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(root_path, &mut out);
        out
    }

    fn occupied_locally(&mut self, path: &Path) -> bool {
        path.symlink_metadata().is_ok() && self.fs.placeholder_info(path).is_none()
    }
}

fn lower(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

fn sync_directory(
    walk: &Walk<'_>,
    directory: &Path,
    parent_item: &[u8],
    shown: &mut ShownItems,
    complete: &mut bool,
) {
    let Walk { previous, protected, fs, .. } = *walk;
    let Some(items) = enumerate_children(walk.socket, walk.root_id, parent_item) else {
        *complete = false;
        return;
    };
    let wanted: HashMap<String, &ProviderItem> = items
        .iter()
        .filter(|item| {
            let valid = valid_component(&item.name);
            if !valid {
                eprintln!(
                    "plain-dir-host: skipping an item with the unusable name {:?}",
                    item.name
                );
            }
            valid
        })
        .map(|item| (item.name.to_lowercase(), item))
        .collect();

    // What the daemon no longer has goes first, so a name that changed hands is free.
    if let Ok(entries) = std::fs::read_dir(directory) {
        for entry in entries.flatten() {
            let path = entry.path();
            if protected.contains(&lower(&path)) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_lowercase();
            let keep = wanted.get(&name).map(|item| item.item_id.clone());
            remove_if_stale(fs, &path, keep.as_deref());
        }
    }

    for item in wanted.values() {
        let path = directory.join(&item.name);
        let is_dir = item.entry_kind == EntryKind::Directory as i32;
        if protected.contains(&lower(&path)) {
            // The user did something here that has not been reported yet: not touched.
            if let Some(old) = previous.get(&item.item_id) {
                shown.insert(item.item_id.clone(), old.clone());
            }
            let still_folder = fs.placeholder_info(&path).is_some_and(|info| {
                info.is_dir && info.item_id.as_deref() == Some(item.item_id.as_slice())
            });
            if is_dir && still_folder {
                sync_directory(walk, &path, &item.item_id, shown, complete);
            } else if previous.contains_key(&item.item_id) {
                keep_subtree(previous, &item.item_id, shown);
            }
            continue;
        }
        if item.entry_kind == EntryKind::Symlink as i32 {
            eprintln!(
                "plain-dir-host: {:?} is a symbolic link, which has no placeholder",
                item.name
            );
            continue;
        }
        match fs.placeholder_info(&path) {
            None if path.symlink_metadata().is_ok() => {
                eprintln!(
                    "plain-dir-host: {} is occupied by a local item; leaving it",
                    path.display()
                );
                continue;
            }
            None => {
                if let Err(error) = fs.create_placeholder(
                    &path,
                    &item.item_id,
                    item.size,
                    item.mtime_unix_nanos,
                    &version_hash_of(&item.content_version).unwrap_or_default(),
                    is_dir,
                ) {
                    eprintln!("plain-dir-host: could not create {}: {error}", path.display());
                    *complete = false;
                    continue;
                }
            }
            Some(info) if info.item_id.as_deref() == Some(item.item_id.as_slice()) => {
                if !is_dir && needs_update(&info, item, previous.get(&item.item_id)) {
                    if let Err(error) = fs.update_placeholder(
                        &path,
                        &item.item_id,
                        item.size,
                        item.mtime_unix_nanos,
                        &version_hash_of(&item.content_version).unwrap_or_default(),
                    ) {
                        eprintln!("plain-dir-host: could not update {}: {error}", path.display());
                        *complete = false;
                    }
                }
            }
            Some(_) => continue,
        }
        // A file the user changed keeps the version it was changed from: the base of the edit.
        let dirty = fs.placeholder_info(&path).is_some_and(|info| !info.in_sync && !info.is_dir);
        let entry = match previous.get(&item.item_id) {
            Some(old) if dirty => old.clone(),
            _ => ShownItem::of(path.clone(), item),
        };
        shown.insert(item.item_id.clone(), entry);
        if is_dir {
            sync_directory(walk, &path, &item.item_id, shown, complete);
        }
    }
}

/// Removes `path` when it is the placeholder of an item other than `keep`, untouched by the user.
fn remove_if_stale(fs: &PlainFs, path: &Path, keep: Option<&[u8]>) {
    let Some(info) = fs.placeholder_info(path) else { return };
    let Some(item_id) = info.item_id.as_deref() else { return };
    if Some(item_id) == keep || !info.in_sync {
        return;
    }
    if info.is_dir {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                remove_if_stale(fs, &entry.path(), None);
            }
        }
        // Only an empty folder goes: anything the user put in it stays.
        if std::fs::remove_dir(path).is_ok() {
            if let Ok(md) = std::fs::symlink_metadata(path) {
                fs.forget(crate::plain_fs::key_of(&md));
            }
        }
        return;
    }
    let ino = std::fs::symlink_metadata(path).map(|md| crate::plain_fs::key_of(&md)).ok();
    if std::fs::remove_file(path).is_ok() {
        if let Some(ino) = ino {
            fs.forget(ino);
        }
    }
}

/// Looks at the sync root every second and signals the paths whose size, time, mode or identity
/// changed, or that appeared or vanished. Dropping it stops the thread.
struct PollWatch {
    stop: Arc<AtomicBool>,
}

impl Drop for PollWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

type Snapshot = HashMap<PathBuf, (u64, u64, i64, u32)>;

fn snapshot(root: &Path) -> Snapshot {
    fn walk(directory: &Path, out: &mut Snapshot) {
        let Ok(entries) = std::fs::read_dir(directory) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(md) = path.symlink_metadata() else { continue };
            out.insert(path.clone(), (md.ino(), md.len(), mtime_nanos(&md), md.mode()));
            if md.is_dir() {
                walk(&path, out);
            }
        }
    }
    let mut out = Snapshot::new();
    walk(root, &mut out);
    out
}

impl PollWatch {
    fn start(key: String, root: PathBuf, events: Sender<HostEvent>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        std::thread::spawn(move || {
            let mut last = snapshot(&root);
            while !flag.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(1));
                let now = snapshot(&root);
                let mut changed: Vec<PathBuf> = now
                    .iter()
                    .filter(|(path, state)| last.get(*path) != Some(state))
                    .map(|(path, _)| path.clone())
                    .collect();
                changed.extend(last.keys().filter(|path| !now.contains_key(*path)).cloned());
                last = now;
                if !changed.is_empty()
                    && events
                        .send(HostEvent::Local {
                            root: key.clone(),
                            signal: Signal::Paths(changed),
                        })
                        .is_err()
                {
                    return;
                }
            }
        });
        Self { stop }
    }
}
