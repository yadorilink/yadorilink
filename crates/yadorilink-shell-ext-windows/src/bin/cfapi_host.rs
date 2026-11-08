//! `yadorilink-cfapi-host`: the long-lived process that owns every provider root's Cloud Filter
//! API sync-root registration and connection, shows the root's namespace as placeholders, and
//! serves `CF_CALLBACK_TYPE_FETCH_DATA` callbacks. See `cfapi.rs`'s module doc and `Cargo.toml`'s
//! `[[bin]]` doc comment for why this is a separate process from the `yadorilink_shell_ext` COM
//! DLL.
//!
//! Usage:
//!  yadorilink-cfapi-host            run the host (default)
//!  yadorilink-cfapi-host --unregister-all
//!                                   unregister every sync root this host has registered ("Remove
//!                                   from this PC"), then exit; does not need the daemon
//!  yadorilink-cfapi-host --unregister-legacy-roots
//!                                   the same for the record an earlier build left in
//!                                   %LOCALAPPDATA%\yadorilink (on request only)
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
use yadorilink_shell_ext::provider_namespace::{EvictOutcome, PinOutcome, PinWish, ShownItems};
use yadorilink_shell_ext::provider_session::{self, SessionEvent};
use yadorilink_windows_provider_policy::host::{
    encode_pins_record, encode_shown_record, encode_untrusted_pins_record, hex, read_pins_at,
    read_shown_at, unregister_recorded, Backend, Host, HostEvent, LoadedShown, Registration,
    POLL_INTERVAL,
};

/// `--unregister-legacy-roots`: the same cleanup against the record an earlier build left in
/// `%LOCALAPPDATA%\yadorilink`. Only on request; it unregisters roots whose recorded identity
/// still matches and retires that record, and touches no user file.
fn unregister_legacy_roots() -> bool {
    use yadorilink_fs_platform::state_dir::{legacy_sync_roots_record, Env};
    match legacy_sync_roots_record(&Env::from_process()) {
        Some(file) => unregister_recorded_roots(&file),
        None => {
            println!("yadorilink-cfapi-host: LOCALAPPDATA is not set; nothing to unregister");
            true
        }
    }
}

fn unregister_all() -> bool {
    let file = host_paths::roots_registry_file();
    let gone = unregister_recorded_roots(&file);
    use yadorilink_fs_platform::state_dir::{
        legacy_sync_roots_notice, legacy_sync_roots_record_in_use, Env,
    };
    let current = file.parent().map(Path::to_path_buf).unwrap_or_default();
    if let Some(old) = legacy_sync_roots_record_in_use(&Env::from_process(), &current) {
        println!("yadorilink-cfapi-host: {}", legacy_sync_roots_notice(&old));
    }
    gone
}

/// `true`: every recorded root is unregistered (or was not registered any more), and the record is
/// retired so the roots are forgotten; or there was no record.
fn unregister_recorded_roots(file: &Path) -> bool {
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
        &mut |path| yadorilink_shell_ext::cfapi::unregister(path).map_err(|e| format!("{e:?}")),
    );
    if gone {
        if let Err(e) = generation::remove_all(&file) {
            // Not retired: the record stays as the newest it was, and the next run starts from it.
            eprintln!("yadorilink-cfapi-host: cannot retire {}: {e}", file.display());
            return false;
        }
    }
    gone
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

/// Forgets what was recorded of a root whose registration was lost: the items it showed, the pin
/// marks, and the journal of an operation that was sent and not answered. The last matters as much
/// as the others: it was authored against the old registration, and replaying it after the root is
/// registered again could commit a delete the person never made.
fn forget_authoring_state(dir: &Path) -> bool {
    // A root that was never served has no state directory yet: there is nothing to forget (the
    // durable removals below cannot identify the volume of a directory that is not there).
    if !dir.exists() {
        return true;
    }
    let mut forgotten = true;
    for name in ["shown", "pins"] {
        if let Err(e) = generation::remove_all(&dir.join(name)) {
            eprintln!("yadorilink-cfapi-host: could not forget the {name} record: {e}");
            forgotten = false;
        }
    }
    // Durably: a removal that a crash could bring back would replay the delete.
    match yadorilink_fs_platform::durable_dir::remove_file_durably(&dir.join("pending")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!("yadorilink-cfapi-host: could not forget the unanswered operation: {e}");
            forgotten = false;
        }
    }
    forgotten
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

    fn root_registration(&mut self, root_id: &[u8], path: &Path) -> Registration {
        match yadorilink_shell_ext::cfapi::registered_root_identity(path) {
            Ok(Some(identity)) if identity == root_id => Registration::Ours,
            // Not a sync root any more, or one registered with another identity.
            Ok(_) => Registration::Lost,
            // Another provider's root, or a reading that failed: not this host's to judge.
            Err(_) => Registration::Unknown,
        }
    }

    fn forget_root_state(&mut self, root_id: &[u8]) -> bool {
        forget_authoring_state(&authoring_state_dir(root_id))
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

    fn pin(&mut self, path: &Path, item_id: Option<&[u8]>, wish: PinWish) -> PinOutcome {
        yadorilink_shell_ext::provider_namespace::pin(path, item_id, wish)
    }

    fn pin_mark(&mut self, path: &Path) -> Option<PinWish> {
        use yadorilink_fs_platform::cloud_files::{attributes_of, pin_mark, PinMark};
        attributes_of(path).map(|attributes| match pin_mark(attributes) {
            PinMark::Pinned => PinWish::Keep,
            PinMark::Unpinned => PinWish::OnlineOnly,
            PinMark::Unset => PinWish::Clear,
        })
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

    fn load_pins(&mut self, root_id: &[u8]) -> Option<std::collections::HashMap<Vec<u8>, PinWish>> {
        read_pins_at(&authoring_state_dir(root_id).join("pins"))
    }

    fn save_pins(
        &mut self,
        root_id: &[u8],
        marks: Option<&std::collections::HashMap<Vec<u8>, PinWish>>,
    ) -> bool {
        // A new sealed generation, published before it replaces the previous one (the same way
        // the shown record is): a record torn by a crash is never read as marks.
        let file = authoring_state_dir(root_id).join("pins");
        let written = generation::publish_next(
            &file,
            &marks.map_or_else(encode_untrusted_pins_record, encode_pins_record),
        );
        if let Err(e) = &written {
            eprintln!("yadorilink-cfapi-host: could not record the pin marks: {e}");
        }
        written.is_ok()
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
    println!("yadorilink-cfapi-host: starting (poll interval {POLL_INTERVAL:?})");
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
            Ok(HostEvent::Session(SessionEvent::Pin { root, item, request_id, wish })) => {
                host.on_pin(&root, &item, &request_id, wish);
            }
            Ok(HostEvent::Session(SessionEvent::PinPlan { root, entries })) => {
                host.on_pin_plan(&root, &entries);
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
    fn forgetting_a_lost_root_removes_its_records_and_its_unanswered_operation() {
        let dir = temp_dir("forget-state");
        generation::publish_next(&dir.join("shown"), "shown record").unwrap();
        generation::publish_next(&dir.join("shown"), "shown record 2").unwrap();
        generation::publish_next(&dir.join("pins"), "pins record").unwrap();
        std::fs::write(dir.join("pending"), "a journaled delete").unwrap();
        std::fs::write(dir.join("unrelated"), "x").unwrap();

        assert!(forget_authoring_state(&dir));
        assert!(matches!(read_shown_at(&dir.join("shown")), LoadedShown::Missing));
        assert_eq!(read_pins_at(&dir.join("pins")), None);
        assert!(!dir.join("pending").exists(), "an unanswered delete survived to be replayed");
        assert!(dir.join("unrelated").exists());
        // Idempotent: nothing there is not a failure.
        assert!(forget_authoring_state(&dir));
        // A root that was never served has no state directory at all.
        assert!(forget_authoring_state(&dir.join("never-served")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Real Cloud Files: unregistering a sync root takes its unhydrated placeholders with it (the
    /// operating system deletes them), and the host's registration check then reads the root as lost.
    /// What the host sees as "the files are gone" is therefore not the person deleting them.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn an_unregistered_root_loses_its_placeholders_and_the_host_reads_the_registration_as_lost() {
        let dir = temp_dir("registration-lost-real");
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let id = vec![0x6b; 16];
        yadorilink_shell_ext::cfapi::register_and_connect_provider(&id, &root).unwrap();
        for (n, name) in ["free1.bin", "free2.bin", "keep1.bin"].iter().enumerate() {
            yadorilink_shell_ext::cfapi::create_item_placeholder(
                &yadorilink_fs_platform::durable_dir::NoLedger,
                &root,
                name,
                format!("item-{n}").as_bytes(),
                1 << 30,
                0,
                false,
            )
            .unwrap();
        }
        let mut backend = RealBackend { events: std::sync::mpsc::channel().0 };
        assert_eq!(backend.root_registration(&id, &root), Registration::Ours);
        assert_eq!(
            backend.root_registration(&[1; 16], &root),
            Registration::Lost,
            "another identity"
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 3);

        // The registration goes (the lab's experiment did this): the placeholders go with it.
        yadorilink_shell_ext::cfapi::unregister(&root).unwrap();
        let left = std::fs::read_dir(&root).map(|d| d.count()).unwrap_or(0);
        println!("REGISTRATION-LOST placeholders left after unregister: {left}");
        assert_eq!(left, 0, "unhydrated placeholders survived the unregistration");
        assert_eq!(backend.root_registration(&id, &root), Registration::Lost);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
