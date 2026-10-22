//! `yadorilink-cfapi-host`: the long-lived process that owns every provider root's Cloud Filter
//! API sync-root registration and connection, shows the root's namespace as placeholders, and
//! serves `CF_CALLBACK_TYPE_FETCH_DATA` callbacks. See `cfapi.rs`'s module doc and `Cargo.toml`'s
//! `[[bin]]` doc comment for why this is a separate process from the `yadorilink_shell_ext` COM
//! DLL.
//!
//! Usage:
//!  yadorilink-cfapi-host            run the host (default)
//!  yadorilink-cfapi-host --unregister-all
//!                                   unregister every sync root this host has registered (the
//!                                   uninstall path), then exit; does not need the daemon
//!  yadorilink-cfapi-host --unregister-legacy-roots
//!                                   the same for the record an earlier build left in
//!                                   %LOCALAPPDATA%\yadorilink (on request only)
//!  yadorilink-cfapi-host --guard-package-removal <package family> <host pid>
//!                                   started by the running host itself (see `package_removal`);
//!                                   not for people
//!
//! Both unregister commands exit 1 when a recorded root could not be unregistered, so the answer
//! can be relied on.
//!
//! The daemon declares the provider roots of this device. The host asks for them (over the same
//! shell-IPC pipe the shell extension uses), registers and connects one sync root per declared
//! root, and keeps one persistent connection to the daemon that makes it the daemon's attached
//! host: the daemon pushes "the namespace changed" and "drop the old copy of this item", and the
//! host acknowledges after it has done so.
//!
//! The host keeps a record of which sync root path serves which declared root
//! (`host_paths::roots_registry_file`), so a restarted host (or a restarted daemon) reconnects
//! the same roots at the same places.
//!
//! FAIL-CLOSED RECONCILIATION: the root set is only ever reconciled against a *confirmed*
//! snapshot (`ipc_client::list_provider_folders` returned `Some`). A failure to confirm it makes
//! NO change at all: collapsing "cannot confirm" into "confirmed empty" would be a fail-open bug.
//! A registered root the daemon neither lists nor asks to remove is an orphan: it is reported and
//! kept, never removed on that evidence.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{RecvTimeoutError, Sender};
use std::time::Instant;

use yadorilink_fs_platform::generation::{self, unseal};
use yadorilink_ipc_proto::shellipc::{ProviderFolder, ProviderRemoval};
use yadorilink_shell_ext::dir_watch;
use yadorilink_shell_ext::host_paths;
use yadorilink_shell_ext::provider_authoring::{self, Authoring, WindowsLocal};
use yadorilink_shell_ext::provider_namespace::{EvictOutcome, ShownItems};
use yadorilink_shell_ext::provider_session::{self, SessionEvent};
use yadorilink_windows_provider_policy::host::{
    encode_shown_record, hex, read_shown_at, unregister_recorded, Backend, Host, HostEvent,
    LoadedShown, POLL_INTERVAL,
};

/// `--unregister-legacy-roots`: the same cleanup against the record an earlier build left in
/// `%LOCALAPPDATA%\yadorilink`. Only on request; it unregisters roots whose recorded identity
/// still matches and retires that record, and touches no user file.
fn unregister_legacy_roots() -> bool {
    use yadorilink_fs_platform::state_dir::{legacy_sync_roots_record, Env};
    match legacy_sync_roots_record(&Env::from_process()) {
        Some(file) => unregister_recorded_roots(&file, Unregister::Everything),
        None => {
            println!("yadorilink-cfapi-host: LOCALAPPDATA is not set; nothing to unregister");
            true
        }
    }
}

fn unregister_all() -> bool {
    let file = host_paths::roots_registry_file();
    let gone = unregister_recorded_roots(&file, Unregister::Everything);
    use yadorilink_fs_platform::state_dir::{
        legacy_sync_roots_notice, legacy_sync_roots_record_in_use, Env,
    };
    let current = file.parent().map(Path::to_path_buf).unwrap_or_default();
    if let Some(old) = legacy_sync_roots_record_in_use(&Env::from_process(), &current) {
        println!("yadorilink-cfapi-host: {}", legacy_sync_roots_notice(&old));
    }
    gone
}

/// Which recorded roots an unregister run may unregister, and what happens to the record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Unregister {
    /// Every recorded root; the record is retired, so the roots are forgotten.
    Everything,
    /// The cleanup after the package was uninstalled. Not a root that holds an item whose content
    /// is not on this PC (without a provider that item cannot be read, so the root stays
    /// registered for a reinstall to serve). The record is kept: a reinstall finds it and puts
    /// each root back on the folder where it was, which holds the user's files, instead of
    /// starting a second folder next to it.
    AfterUninstall,
}

/// `true`: every recorded root is unregistered (or was not registered any more) and, for
/// [`Unregister::Everything`], the record is retired; or there was no record.
fn unregister_recorded_roots(file: &Path, which: Unregister) -> bool {
    let file = file.to_path_buf();
    let contents = match generation::read_latest(&file, |text| unseal(text).map(str::to_string)) {
        generation::Latest::Loaded { value, .. } => value,
        generation::Latest::Missing => {
            println!("yadorilink-cfapi-host: no recorded sync roots at {}", file.display());
            return true;
        }
        generation::Latest::Invalid(e) => {
            eprintln!("yadorilink-cfapi-host: {e}; nothing is unregistered");
            return false;
        }
    };
    let gone = unregister_recorded(
        &contents,
        &mut yadorilink_shell_ext::cfapi::registered_root_identity,
        &mut |path| {
            if which == Unregister::AfterUninstall
                && yadorilink_shell_ext::package_removal::holds_online_only_items(path)
            {
                return Err("it holds items that are only online (or cannot be read to the end); left registered".into());
            }
            yadorilink_shell_ext::cfapi::unregister(path).map_err(|e| format!("{e:?}"))
        },
    );
    if gone && which == Unregister::Everything {
        if let Err(e) = generation::remove_all(&file) {
            // Not retired: the record stays as the newest it was, and the next run starts from it.
            eprintln!("yadorilink-cfapi-host: cannot retire {}: {e}", file.display());
            return false;
        }
    }
    gone
}

/// The guardian the running host starts (see `package_removal`): it has no package identity and
/// outlives the package. Once the host has ended it watches the package family; if the package was
/// uninstalled it unregisters the roots.
fn guard_package_removal(family: &str, host_pid: u32) -> bool {
    use yadorilink_shell_ext::package_removal::{
        family_installed, removal_confirmed, remove_helper, wait_for_exit, GRACE, POLL, STABLE,
    };
    wait_for_exit(host_pid);
    let removed =
        removal_confirmed(&mut || family_installed(family), POLL, GRACE, STABLE, &mut || {
            std::thread::sleep(POLL)
        });
    let clean = if removed {
        println!("yadorilink-cfapi-host: {family} was uninstalled; unregistering its sync roots");
        unregister_recorded_roots(&host_paths::roots_registry_file(), Unregister::AfterUninstall)
    } else {
        true
    };
    if let Ok(exe) = std::env::current_exe() {
        remove_helper(&exe);
    }
    clean
}

/// `ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT` as an `HRESULT`: the path is not a sync root.
const ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT: windows::core::HRESULT =
    windows::core::HRESULT(0x8007_0186_u32 as i32);

struct RealBackend {
    events: Sender<HostEvent>,
}

/// The daemon as `provider_authoring` asks it.
struct DaemonApi;

impl provider_authoring::Api for DaemonApi {
    fn apply(
        &self,
        root: &[u8],
        request: yadorilink_ipc_proto::shellipc::ProviderApplyChangeRequest,
    ) -> Option<yadorilink_ipc_proto::shellipc::ProviderApplyChangeResponse> {
        yadorilink_shell_ext::provider_client::apply(root, request)
    }

    fn save_shown(&self, root: &[u8], shown: &ShownItems) -> bool {
        write_shown(root, shown)
    }
}

/// Tells the fetch path which version each shown placeholder stands for: a fetch asks the daemon
/// for a window of exactly that version.
fn publish_shown_versions(root_id: &[u8], shown: &ShownItems) {
    yadorilink_shell_ext::provider_client::set_shown_versions(
        root_id,
        shown.iter().map(|(id, item)| (id.as_slice(), item.content_version.as_slice())),
    );
}

/// Records the items shown in `root_id` durably: a new generation, published before the
/// acknowledgement that depends on it (a recorded item whose placeholder is gone reads as the
/// user deleting it).
fn write_shown(root_id: &[u8], shown: &ShownItems) -> bool {
    publish_shown_versions(root_id, shown);
    let file = authoring_state_dir(root_id).join("shown");
    let written = generation::publish_next(&file, &encode_shown_record(shown));
    if let Err(e) = &written {
        eprintln!("yadorilink-cfapi-host: could not record the shown items: {e}");
    }
    written.is_ok()
}

fn authoring_state_dir(root_id: &[u8]) -> PathBuf {
    host_paths::container().join("authoring").join(hex(root_id))
}

impl Backend for RealBackend {
    fn prepare_root(&mut self, path: &Path) -> Result<(), String> {
        yadorilink_fs_platform::durable_dir::create_dir_all_durably(path)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    fn register_and_connect(&mut self, root_id: &[u8], path: &Path) -> Result<(), String> {
        yadorilink_shell_ext::cfapi::register_and_connect_provider(root_id, path)
            .map_err(|e| format!("{e:?}"))
    }

    fn unregister(&mut self, path: &Path) -> Result<(), String> {
        // `cfapi::unregister` already disconnects first. A root that is not registered any more
        // is what was asked for: the unregister is repeated after a failed record update.
        match yadorilink_shell_ext::cfapi::unregister(path) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT => Ok(()),
            Err(e) => Err(format!("{e:?}")),
        }
    }

    fn sync_namespace(
        &mut self,
        root_id: &[u8],
        path: &Path,
        previous: &ShownItems,
        protected: &HashSet<String>,
    ) -> Option<ShownItems> {
        yadorilink_shell_ext::provider_namespace::sync_namespace(root_id, path, previous, protected)
    }

    fn evict(&mut self, path: &Path, item_id: &[u8]) -> Result<(), EvictOutcome> {
        yadorilink_shell_ext::provider_namespace::evict(path, item_id)
    }

    fn materialized(&mut self, shown: &ShownItems) -> HashSet<Vec<u8>> {
        shown
            .iter()
            .filter(|(_, item)| !item.directory)
            .filter(|(id, item)| {
                // The placeholder of exactly this item, with its bytes on the disk and not changed
                // by the user (a plain file put in its place, or an edit, is not the daemon's
                // version). Attribute access only: nothing is fetched.
                yadorilink_shell_ext::provider_namespace::placeholder_info(&item.path).is_some_and(
                    |info| {
                        info.item_id.as_deref() == Some(id.as_slice())
                            && !info.is_dir
                            && !info.dehydrated
                            && info.in_sync
                    },
                )
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn load_shown(&mut self, root_id: &[u8]) -> LoadedShown {
        let loaded = read_shown_at(&authoring_state_dir(root_id).join("shown"));
        if let LoadedShown::Loaded(shown) = &loaded {
            publish_shown_versions(root_id, shown);
        }
        loaded
    }

    fn save_shown(&mut self, root_id: &[u8], shown: &ShownItems) -> bool {
        write_shown(root_id, shown)
    }

    fn volume_identified(&mut self, path: &Path) -> Result<(), String> {
        yadorilink_fs_platform::durable_dir::require_volume_guid_path(path).map_err(|e| {
            if yadorilink_fs_platform::durable_dir::is_no_guid_path(&e) {
                e.to_string()
            } else {
                format!("the volume cannot be identified: {e}")
            }
        })
    }

    fn namespace_available(&mut self, path: &Path) -> bool {
        match yadorilink_shell_ext::provider_namespace::root_offers_durable_namespace(path) {
            Ok(()) => true,
            Err(reason) => {
                eprintln!("yadorilink-cfapi-host: {} is left as it is: {reason}", path.display());
                false
            }
        }
    }

    fn is_dir(&mut self, path: &Path) -> bool {
        path.is_dir()
    }

    fn watch(&mut self, key: &str, path: &Path) -> Option<Box<dyn std::any::Any>> {
        let events = self.events.clone();
        let root = key.to_string();
        match dir_watch::watch(path, move |signal| {
            events.send(HostEvent::Local { root: root.clone(), signal }).is_ok()
        }) {
            Ok(watch) => Some(Box::new(watch)),
            Err(e) => {
                eprintln!("yadorilink-cfapi-host: cannot watch {}: {e}", path.display());
                None
            }
        }
    }

    fn author(
        &mut self,
        root_id: &[u8],
        root_path: &Path,
        signals: &BTreeSet<PathBuf>,
        shown: &mut ShownItems,
    ) -> provider_authoring::Report {
        // A sync root folder that is gone says nothing about its files: never read it as "the
        // user deleted everything".
        if !root_path.is_dir() {
            eprintln!("yadorilink-cfapi-host: {} is not there; leaving it", root_path.display());
            return provider_authoring::Report::default();
        }
        let local = WindowsLocal { ingest_dir: host_paths::ingest_dir() };
        match Authoring::open(root_id, root_path, &authoring_state_dir(root_id)) {
            Ok(authoring) => authoring.process(signals, shown, &local, &DaemonApi),
            Err(e) => {
                eprintln!("yadorilink-cfapi-host: cannot open the authoring state: {e}");
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
        path.symlink_metadata().is_ok()
            && yadorilink_shell_ext::provider_namespace::placeholder_info(path).is_none()
    }
}

/// Runs `dehydrate_server::serve` for the lifetime of this process on a dedicated OS thread with
/// its own single-threaded Tokio runtime. A crashed/panicked server thread does not bring down
/// the whole process; a daemon eviction attempt would simply see every `DehydrateRequest`
/// connection attempt fail closed, which `materialization_eviction.rs`'s Windows path already
/// treats as "leave the file Hydrated, retry later".
fn spawn_dehydrate_server() {
    let pipe_name = yadorilink_shell_ext::dehydrate_server::pipe_name();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the dehydrate pipe server's Tokio runtime");
        if let Err(e) = runtime.block_on(yadorilink_shell_ext::dehydrate_server::serve(&pipe_name))
        {
            eprintln!("yadorilink-cfapi-host: dehydrate pipe server exited: {e}");
        }
    });
}

fn list_snapshot() -> Option<(Vec<ProviderFolder>, Vec<ProviderRemoval>)> {
    let container = host_paths::container();
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(&container).ok()?;
    yadorilink_shell_ext::ipc_client::list_provider_folders(&container.to_string_lossy())
        .map(|snapshot| (snapshot.folders, snapshot.removals))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(refusal) = host_paths::check() {
        eprintln!("yadorilink-cfapi-host: {refusal}");
        std::process::exit(2);
    }
    if args.iter().any(|a| a == "--unregister-legacy-roots") {
        std::process::exit(i32::from(!unregister_legacy_roots()));
    }
    if args.iter().any(|a| a == "--unregister-all") {
        std::process::exit(i32::from(!unregister_all()));
    }
    if let Some(at) =
        args.iter().position(|a| a == yadorilink_shell_ext::package_removal::GUARD_FLAG)
    {
        let (Some(family), Some(pid)) =
            (args.get(at + 1), args.get(at + 2).and_then(|p| p.parse::<u32>().ok()))
        else {
            eprintln!(
                "yadorilink-cfapi-host: {} needs the package family and the host process id",
                args[at]
            );
            std::process::exit(2);
        };
        std::process::exit(i32::from(!guard_package_removal(family, pid)));
    }

    println!("yadorilink-cfapi-host: starting (poll interval {POLL_INTERVAL:?})");
    // The guardian that unregisters the sync roots if the package is uninstalled while this runs.
    match yadorilink_shell_ext::package_removal::watch() {
        Ok(true) => {
            println!("yadorilink-cfapi-host: will unregister its sync roots if the package is uninstalled")
        }
        Ok(false) => {}
        // The host still serves the roots; only the cleanup at uninstall is missing.
        Err(e) => eprintln!("yadorilink-cfapi-host: no cleanup at uninstall: {e}"),
    }
    spawn_dehydrate_server();
    let (events, inbox) = std::sync::mpsc::channel::<HostEvent>();
    let session = provider_session::spawn(events.clone());
    let mut host = Host::new(
        RealBackend { events },
        session,
        host_paths::roots_registry_file(),
        host_paths::sync_roots_parent(),
    );
    let mut reconcile_due = true;
    let mut last_reconcile = Instant::now();
    loop {
        if reconcile_due {
            host.reconcile(list_snapshot());
            reconcile_due = false;
            last_reconcile = Instant::now();
        }
        let wait = host.next_deadline(Instant::now(), POLL_INTERVAL);
        match inbox.recv_timeout(wait) {
            Ok(HostEvent::Session(SessionEvent::Connected)) => {
                host.on_connected();
                reconcile_due = true;
            }
            Ok(HostEvent::Session(SessionEvent::Closed)) => {
                eprintln!("yadorilink-cfapi-host: daemon connection closed");
            }
            Ok(HostEvent::Session(SessionEvent::Changed { root, revision, request_id })) => {
                reconcile_due = host.on_changed(&root, revision, &request_id);
            }
            Ok(HostEvent::Session(SessionEvent::Evict {
                root,
                item,
                request_id,
                require_shown_version,
            })) => {
                host.on_evict(&root, &item, &request_id, &require_shown_version);
            }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_shell_ext::provider_namespace::ShownItem;
    use yadorilink_windows_provider_policy::host::Backend;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("yl-host-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// What the OS holds is read from the sync root: only the placeholder of exactly the item,
    /// with its bytes and unchanged. A dehydrated placeholder is not held; a plain file put where
    /// the placeholder was is not the daemon's version.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn only_an_item_own_hydrated_unchanged_placeholder_counts_as_materialized() {
        let dir = temp_dir("materialized");
        let sync_root = dir.join("root");
        std::fs::create_dir_all(&sync_root).unwrap();
        yadorilink_shell_ext::cfapi::register_and_connect(&sync_root).unwrap();
        let created = yadorilink_shell_ext::cfapi::create_item_placeholder;
        created(
            &yadorilink_fs_platform::durable_dir::NoLedger,
            &sync_root,
            "a.txt",
            &[3; 16],
            5,
            0,
            false,
        )
        .unwrap();
        let path = sync_root.join("a.txt");
        let shown = ShownItems::from([(
            vec![3u8; 16],
            ShownItem {
                path: path.clone(),
                parent_item_id: vec![],
                name: "a.txt".into(),
                directory: false,
                size: 5,
                mtime_unix_nanos: 0,
                content_version: vec![0; 40],
                parent_generation: 0,
            },
        )]);
        let (events, _inbox) = std::sync::mpsc::channel();
        let mut backend = RealBackend { events };
        assert!(backend.materialized(&shown).is_empty(), "a dehydrated placeholder was reported");
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"mine!").unwrap();
        assert!(backend.materialized(&shown).is_empty(), "a plain file was reported as the item");
        std::fs::remove_file(&path).unwrap();
        let _ = yadorilink_shell_ext::cfapi::unregister(&sync_root);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Real Cloud Files: unregistering a folder that is not a sync root is a success, so a
    /// removal whose record update failed can be repeated.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn unregistering_a_folder_that_is_not_a_sync_root_is_a_success() {
        let dir = temp_dir("not-a-root");
        let (events, _rx) = std::sync::mpsc::channel();
        let mut backend = RealBackend { events };
        assert_eq!(backend.unregister(&dir), Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Real Cloud Files: the identity stored at registration is what `--unregister-all` checks.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn a_registered_root_tells_its_identity_and_a_plain_folder_does_not() {
        let dir = temp_dir("identity");
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let plain = dir.join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        let id = vec![0x5a; 16];
        yadorilink_shell_ext::cfapi::register_and_connect_provider(&id, &root).unwrap();
        let seen = yadorilink_shell_ext::cfapi::registered_root_identity(&root);
        let plain_seen = yadorilink_shell_ext::cfapi::registered_root_identity(&plain);
        yadorilink_shell_ext::cfapi::unregister(&root).unwrap();
        assert_eq!(seen, Ok(Some(id)));
        assert_eq!(plain_seen, Ok(None));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
