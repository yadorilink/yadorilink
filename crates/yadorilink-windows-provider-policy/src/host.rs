//! The policy of the provider host's loop: which sync roots are registered and served, when a
//! namespace is shown, when what the user did is authored, what the materialized set reports and
//! how an eviction ends. Everything that touches the operating system sits behind [`Backend`]
//! and everything said to the daemon behind [`Reports`], so the loop is driven by fakes in the
//! tests and by the Cloud Files calls and the daemon session in the Windows host binary.
//!
//! FAIL-CLOSED RECONCILIATION: the root set is only ever reconciled against a *confirmed*
//! snapshot. A failure to confirm it makes NO change at all: collapsing "cannot confirm" into
//! "confirmed empty" would be a fail-open bug. A registered root the daemon neither lists nor
//! asks to remove is an orphan: it is reported and kept, never removed on that evidence.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::namespace_policy::{EvictOutcome, ShownItem, ShownItems};
use crate::provider_authoring;
use crate::provider_report::Reporter;
use crate::provider_session::{self, SessionEvent};
use yadorilink_fs_platform::generation::{self, seal, unseal};
use yadorilink_ipc_proto::shellipc::{
    DomainEvidence, EvictResult, ProviderFolder, ProviderMaterializedReport, ProviderRemoval,
};

/// What the directory watcher reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// These paths (absolute) were touched.
    Paths(Vec<PathBuf>),
    /// Changes were lost: every path may have been touched.
    Overflow,
}

pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// How long a root must be quiet before what the user did in it is applied: an editor's save is a
/// burst of creates, renames and deletes, and it is the end state that means something.
pub const QUIET: Duration = Duration::from_millis(750);
/// How long after news of a handoff or an eviction the materialized set is read at every poll
/// (the OS finishes writing a fetched file a moment after the daemon handed it over).
pub const REPORT_SETTLE: Duration = Duration::from_secs(30);
/// How often the materialized set is read when nothing happened (the user can free space in
/// Explorer without telling anyone).
pub const REPORT_IDLE: Duration = Duration::from_secs(60);

/// Everything the host's loop waits for.
pub enum HostEvent {
    Session(SessionEvent),
    /// The watcher of the root (hex id) says something changed in its sync root.
    Local {
        root: String,
        signal: Signal,
    },
}

impl From<SessionEvent> for HostEvent {
    fn from(event: SessionEvent) -> Self {
        Self::Session(event)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

// ---- the record of registered roots -------------------------------------------------------

/// A provider root id as it is written: exactly 16 bytes as 32 lowercase hex digits.
pub fn is_root_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The registry's contents: root id (hex) -> sync root path. Every line is a root id and a
/// path; anything else (a bare path, a short or upper case id, a root or a path recorded twice)
/// means the record cannot be trusted, since skipping or picking one would forget or mix up a
/// root.
pub fn parse_registry(contents: &str) -> Result<HashMap<String, PathBuf>, String> {
    let mut roots = HashMap::new();
    let mut paths = HashSet::new();
    for line in contents.lines() {
        let malformed = || format!("malformed line {line:?}");
        let (root, path) = line.split_once('\t').ok_or_else(malformed)?;
        if !is_root_id(root) || path.trim().is_empty() {
            return Err(malformed());
        }
        // Two lines for one root are not one record: which path is the root's is unknown.
        if roots.insert(root.to_string(), PathBuf::from(path.trim())).is_some() {
            return Err(format!("root {root} is recorded twice"));
        }
        // One folder cannot be the sync root of two roots (Windows paths do not differ by case).
        if !paths.insert(path_key(Path::new(path.trim()))) {
            return Err(format!("the path {} is recorded for two roots", path.trim()));
        }
    }
    Ok(roots)
}

/// A path as Windows compares it: ignoring case, the kind of separator and a trailing one.
pub fn path_key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    crate::namespace_policy::windows_name_key(text.trim_end_matches('\\'))
}

pub fn render_registry(roots: &HashMap<String, PathBuf>) -> String {
    let mut lines: Vec<String> =
        roots.iter().map(|(root, path)| format!("{root}\t{}\n", path.display())).collect();
    lines.sort();
    lines.concat()
}

/// The registered roots. No generation file is a first run (no roots); a record that cannot be
/// read or understood is an error, never "no roots".
pub fn read_registry_at(file: &Path) -> Result<HashMap<String, PathBuf>, String> {
    match generation::read_latest(file, |text| unseal(text).map(parse_registry)) {
        generation::Latest::Missing => Ok(HashMap::new()),
        // The newest complete generation is the registry; one that parses badly is corruption,
        // not a reason to take an older generation (which may predate a root).
        generation::Latest::Loaded { value, .. } => {
            value.map_err(|e| format!("{}: {e}", file.display()))
        }
        generation::Latest::Invalid(e) => Err(e),
    }
}

/// Publishes the registry as its next generation (see [`generation`]).
pub fn write_registry_at(file: &Path, roots: &HashMap<String, PathBuf>) -> std::io::Result<()> {
    generation::publish_next(file, &seal(&render_registry(roots))).map(drop)
}

/// One shown item as a line: id, path, parent id, name, kind, size, time, version and parent
/// generation, tab separated (text fields hex encoded).
pub fn encode_shown(id: &[u8], item: &ShownItem) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        hex(id),
        hex(item.path.to_string_lossy().as_bytes()),
        hex(&item.parent_item_id),
        hex(item.name.as_bytes()),
        if item.directory { "d" } else { "f" },
        item.size,
        item.mtime_unix_nanos,
        hex(&item.content_version),
        item.parent_generation
    )
}

pub fn decode_shown(line: &str) -> Option<(Vec<u8>, ShownItem)> {
    let mut parts = line.split('\t');
    let id = unhex(parts.next()?)?;
    let path = PathBuf::from(String::from_utf8(unhex(parts.next()?)?).ok()?);
    let parent_item_id = unhex(parts.next()?)?;
    let name = String::from_utf8(unhex(parts.next()?)?).ok()?;
    let directory = parts.next()? == "d";
    let size = parts.next()?.parse().ok()?;
    let mtime_unix_nanos = parts.next()?.parse().ok()?;
    let content_version = unhex(parts.next()?)?;
    let parent_generation = parts.next()?.parse().ok()?;
    Some((
        id,
        ShownItem {
            path,
            parent_item_id,
            name,
            directory,
            size,
            mtime_unix_nanos,
            content_version,
            parent_generation,
        },
    ))
}

/// What the operating system says is registered at a path (`None`: not this host's sync root).
pub type RootIdentity = Result<Option<Vec<u8>>, String>;

/// Unregisters the recorded sync roots that the operating system confirms are this host's, with
/// the recorded root id as their identity. A root that does not match, or a record that cannot be
/// understood, is left alone (it may be another provider's, or the only trace of a root). True
/// when every recorded root is gone, so the record can go too.
pub fn unregister_recorded(
    contents: &str,
    identity_of: &mut dyn FnMut(&Path) -> RootIdentity,
    unregister: &mut dyn FnMut(&Path) -> Result<(), String>,
) -> bool {
    let roots = match parse_registry(contents) {
        Ok(roots) => roots,
        Err(e) => {
            eprintln!("yadorilink-cfapi-host: the record of the sync roots is not trusted ({e}); no root is unregistered");
            return false;
        }
    };
    let mut all_gone = true;
    for (root, path) in roots {
        match identity_of(&path) {
            Ok(None) => {
                println!("yadorilink-cfapi-host: {} is not a sync root any more", path.display())
            }
            Ok(Some(identity)) if unhex(&root).as_deref() == Some(identity.as_slice()) => {
                match unregister(&path) {
                    Ok(()) => {
                        println!("yadorilink-cfapi-host: unregistered sync root {}", path.display())
                    }
                    Err(e) => {
                        all_gone = false;
                        eprintln!(
                            "yadorilink-cfapi-host: failed to unregister sync root {}: {e}",
                            path.display()
                        );
                    }
                }
            }
            Ok(Some(_)) => {
                all_gone = false;
                eprintln!(
                    "yadorilink-cfapi-host: {} is registered for another root; left alone",
                    path.display()
                );
            }
            Err(e) => {
                all_gone = false;
                eprintln!(
                    "yadorilink-cfapi-host: cannot tell what is registered at {}: {e}; left alone",
                    path.display()
                );
            }
        }
    }
    all_gone
}

// ---- the host ------------------------------------------------------------------------------

/// The operating-system side of the host: what it does to sync roots.
pub trait Backend {
    /// Makes sure the folder of a sync root exists. Done before the root is recorded, so that
    /// registering it creates nothing the record does not already cover.
    fn prepare_root(&mut self, path: &Path) -> Result<(), String>;
    fn register_and_connect(&mut self, root_id: &[u8], path: &Path) -> Result<(), String>;
    fn unregister(&mut self, path: &Path) -> Result<(), String>;
    /// Makes the sync root show the root's namespace; `None` when it could not be confirmed.
    fn sync_namespace(
        &mut self,
        root_id: &[u8],
        path: &Path,
        previous: &ShownItems,
        protected: &HashSet<String>,
    ) -> Option<ShownItems>;
    fn evict(&mut self, path: &Path, item_id: &[u8]) -> Result<(), EvictOutcome>;
    /// The items of `shown` the operating system holds bytes of now.
    fn materialized(&mut self, shown: &ShownItems) -> HashSet<Vec<u8>>;
    /// The items an earlier run of the host showed in this root, as it showed them. A record that
    /// exists but cannot be read back is [`LoadedShown::Invalid`], never "nothing was shown".
    fn load_shown(&mut self, root_id: &[u8]) -> LoadedShown;
    /// Records the items shown in this root now. False when it could not be made durable: what
    /// was shown is then not acknowledged (a recorded item whose placeholder is gone reads as the
    /// user deleting it, and an unrecorded one cannot be told from an item another device made).
    fn save_shown(&mut self, root_id: &[u8], shown: &ShownItems) -> bool;
    /// Whether the volume `path` lives on (or will be created on) is named by a volume GUID path.
    /// A volume with only a drive letter or share path is refused: it can be given to another
    /// volume, so a sync folder is neither created nor matched on it. Asked before anything is
    /// prepared, registered or connected.
    fn volume_identified(&mut self, path: &Path) -> Result<(), String>;
    /// Whether the volume of the sync root `path` may be changed at all: false when the
    /// durable-namespace probe refused it (an unsupported or unknown volume). The closed global
    /// gate is not a refusal. Asked before anything is authored or shown there.
    fn namespace_available(&mut self, path: &Path) -> bool;
    /// Whether `path` is an existing folder.
    fn is_dir(&mut self, path: &Path) -> bool;
    /// Starts signalling changes inside the sync root of `key`; dropping the guard stops it.
    fn watch(&mut self, key: &str, path: &Path) -> Option<Box<dyn std::any::Any>>;
    /// Applies what the user did at `signals` to the daemon.
    fn author(
        &mut self,
        root_id: &[u8],
        root_path: &Path,
        signals: &BTreeSet<PathBuf>,
        shown: &mut ShownItems,
    ) -> provider_authoring::Report;
    /// Every path below `root_path`, for a look at everything after the watcher lost changes.
    fn listing(&mut self, root_path: &Path) -> BTreeSet<PathBuf>;
    /// Whether the user's own file or folder (not a placeholder) is at `path`.
    fn occupied_locally(&mut self, path: &Path) -> bool;
}

/// The daemon side of the host: what it tells the daemon.
pub trait Reports {
    fn domain_state(&self, root: &[u8], evidence: DomainEvidence, preserved_location: &str);
    fn signal_done(&self, root: &[u8], revision: u64, request_id: &[u8], error: Option<&str>);
    fn evict_done(&self, root: &[u8], request_id: &[u8], result: EvictResult, error: &str);
    fn materialized(&self, report: ProviderMaterializedReport);
}

/// What the durable record of the shown items says.
#[derive(Debug, PartialEq)]
pub enum LoadedShown {
    /// No record was ever made (a first run).
    Missing,
    /// The whole record was read back.
    Loaded(ShownItems),
    /// A record exists but could not be read or decoded: it is the only evidence of what the user
    /// may have deleted while the host was not running, so it is not a first run.
    Invalid(String),
}

/// The newest complete generation of the shown record at `file` (see [`generation`]).
pub fn read_shown_at(file: &Path) -> LoadedShown {
    match generation::read_latest(file, |text| unseal(text).map(decode_shown_lines)) {
        generation::Latest::Missing => LoadedShown::Missing,
        generation::Latest::Loaded { value: Some(value), .. } => LoadedShown::Loaded(value),
        // Complete (the seal holds) but not understood: that is the newest record, and an older
        // generation may predate what the user deleted. Only a torn generation is skipped.
        generation::Latest::Loaded { value: None, seq, .. } => {
            LoadedShown::Invalid(format!("{}: generation {seq} is malformed", file.display()))
        }
        generation::Latest::Invalid(e) => LoadedShown::Invalid(e),
    }
}

pub fn decode_shown_lines(body: &str) -> Option<ShownItems> {
    body.lines().map(decode_shown).collect()
}

pub fn encode_shown_record(shown: &ShownItems) -> String {
    let mut lines: Vec<String> = shown.iter().map(|(id, item)| encode_shown(id, item)).collect();
    lines.sort();
    seal(&lines.iter().map(|line| format!("{line}\n")).collect::<String>())
}

impl Reports for provider_session::Session {
    fn domain_state(&self, root: &[u8], evidence: DomainEvidence, preserved_location: &str) {
        provider_session::Session::domain_state(self, root, evidence, preserved_location);
    }

    fn signal_done(&self, root: &[u8], revision: u64, request_id: &[u8], error: Option<&str>) {
        provider_session::Session::signal_done(self, root, revision, request_id, error);
    }

    fn evict_done(&self, root: &[u8], request_id: &[u8], result: EvictResult, error: &str) {
        provider_session::Session::evict_done(self, root, request_id, result, error);
    }

    fn materialized(&self, report: ProviderMaterializedReport) {
        provider_session::Session::materialized(self, report);
    }
}

/// One served root.
pub struct Served {
    root_id: Vec<u8>,
    path: PathBuf,
    /// The namespace must be shown again (a new connection, a change, or a failed attempt).
    needs_walk: bool,
    /// The items shown by the last complete walk, with their paths.
    shown: ShownItems,
    /// `shown` is what the last successful `save_shown` (or `load_shown`) recorded. While false,
    /// it is not a base the daemon may be told about: after a crash the older record would be
    /// loaded, and a change authored against `shown` would be judged against another base.
    shown_durable: bool,
    /// Why the durable record of the shown items cannot be trusted (it exists but is unreadable
    /// or corrupt). While set, nothing is shown, authored or acknowledged for this root: showing
    /// the daemon's namespace could put back an item the user deleted while the host was off.
    baseline_untrusted: Option<String>,
    /// A readable record exists and the offline changes have not been judged against it yet
    /// (the root was not ready to be shown). Until they are, nothing is walked or saved: an empty
    /// in-memory baseline would overwrite the record before a deletion was seen.
    baseline_held: bool,
    /// The record was judged (or there was none): it is not looked at again.
    baseline_judged: bool,
    /// What the user did in the sync root and has not been applied yet.
    pending: BTreeSet<PathBuf>,
    /// Changes were lost: look at everything.
    rescan: bool,
    /// When the last signal arrived (a root is applied once it has been quiet for [`QUIET`]).
    last_signal: Option<Instant>,
    /// Paths to look at again after this time (the daemon was busy or a file was changing).
    retry: BTreeSet<PathBuf>,
    retry_after: Option<Instant>,
    /// The materialized-set reporter of this connection (none: the next report is a full snapshot).
    reporter: Option<Reporter>,
    /// The highest handoff sequence the daemon announced for this root.
    latest_seq: u64,
    /// Until when the set is read at every poll, and when it was last read.
    report_settle_until: Option<Instant>,
    last_report: Option<Instant>,
    /// The daemon has pushed something for this root since the host last attached it. Until it
    /// has, the attach is not known to have taken (the daemon ignores a `Registered` it cannot
    /// read its state for, without answering), so it is sent again at every poll.
    ///
    /// Known limit: the daemon accepts reports for any known root once the connection is attached,
    /// so a push for root R does not prove R's own `Registered` was processed. Closing that needs a
    /// per-root `Registered` acknowledgement on the wire, which this host-only change does not add.
    attach_confirmed: bool,
    /// `Registered` was sent since the last poll looked: the next poll waits for the answer once
    /// instead of sending it again.
    attach_fresh: bool,
    /// Keeps the watcher alive.
    _watch: Option<Box<dyn std::any::Any>>,
}

pub struct Host<B: Backend, R: Reports> {
    backend: B,
    reports: R,
    registry_file: PathBuf,
    sync_roots_parent: PathBuf,
    /// Everything ever registered by this host and not yet removed: root id (hex) -> path.
    registry: HashMap<String, PathBuf>,
    /// Why the registry file cannot be trusted (it exists but is unreadable or corrupt). While
    /// set, no root is registered, removed or acknowledged: an empty map would forget them all.
    registry_fault: Option<String>,
    /// The roots connected by this process.
    served: HashMap<String, Served>,
}

impl<B: Backend, R: Reports> Host<B, R> {
    pub fn new(backend: B, reports: R, registry_file: PathBuf, sync_roots_parent: PathBuf) -> Self {
        let mut host = Self {
            backend,
            reports,
            registry_file,
            sync_roots_parent,
            registry: HashMap::new(),
            registry_fault: None,
            served: HashMap::new(),
        };
        host.load_registry();
        host
    }

    /// Reads the registry file; an unreadable one is remembered as a fault and read again later.
    fn load_registry(&mut self) {
        match read_registry_at(&self.registry_file) {
            Ok(registry) => {
                self.registry = registry;
                self.registry_fault = None;
            }
            Err(e) => {
                if self.registry_fault.as_deref() != Some(e.as_str()) {
                    eprintln!(
                        "yadorilink-cfapi-host: the record of the sync roots cannot be read ({e}); \
                         no root is registered or removed until it can"
                    );
                }
                self.registry_fault = Some(e);
            }
        }
    }

    /// Makes `candidate` the registry: durably first, and only then in memory. False (nothing
    /// changed) when it could not be made durable, so nothing is acknowledged that a restart
    /// could not find again.
    fn commit_registry(&mut self, candidate: HashMap<String, PathBuf>) -> bool {
        match write_registry_at(&self.registry_file, &candidate) {
            Ok(()) => {
                self.registry = candidate;
                true
            }
            Err(e) => {
                eprintln!("yadorilink-cfapi-host: could not record the sync roots: {e}");
                false
            }
        }
    }

    /// Reconciles the served roots against the daemon's declarations. `None` snapshot (the
    /// daemon could not confirm one) changes nothing.
    pub fn reconcile(&mut self, snapshot: Option<(Vec<ProviderFolder>, Vec<ProviderRemoval>)>) {
        if self.registry_fault.is_some() {
            self.load_registry();
            if self.registry_fault.is_some() {
                return;
            }
        }
        let Some((folders, removals)) = snapshot else {
            eprintln!(
                "yadorilink-cfapi-host: could not confirm the provider roots this poll (daemon \
                 unreachable, timeout, or unavailable snapshot); leaving the sync roots untouched"
            );
            return;
        };
        // The daemon answered this poll, so it can be told again (while it is unreachable
        // nothing is queued for it).
        let keys: Vec<String> = self.served.keys().cloned().collect();
        for key in keys {
            self.attach_again_if_unconfirmed(&key);
        }
        for removal in &removals {
            self.remove(&removal.root_id);
        }
        for folder in &folders {
            self.serve(folder);
        }
        // A recorded root the daemon neither declares nor asks to remove is an orphan: say so,
        // keep it.
        let declared: Vec<String> = folders.iter().map(|f| hex(&f.root_id)).collect();
        let removed: Vec<String> = removals.iter().map(|r| hex(&r.root_id)).collect();
        for root in self.registry.keys() {
            if !declared.contains(root) && !removed.contains(root) {
                if let Some(id) = unhex(root) {
                    self.reports.domain_state(&id, DomainEvidence::Orphan, "");
                }
            }
        }
    }

    /// Says `Registered` again for a served root the daemon has not pushed anything for since it
    /// was attached (the daemon may have ignored the attach), and asks for a full report so an
    /// answer comes back soon.
    fn attach_again_if_unconfirmed(&mut self, key: &str) {
        let Some(served) = self.served.get_mut(key) else { return };
        if served.attach_confirmed {
            return;
        }
        if std::mem::take(&mut served.attach_fresh) {
            return;
        }
        // A root that cannot report yet (nothing shown) gets no answer to wait for: it is not
        // pestered until it can.
        if served.needs_walk && served.shown.is_empty() {
            return;
        }
        self.reports.domain_state(&served.root_id, DomainEvidence::Registered, "");
        // What the daemon knew of this connection's reports is in doubt: start over.
        served.reporter = None;
        self.report_materialized(key, true);
    }

    /// Connects `folder`'s sync root if it is not connected yet, and shows its namespace when due.
    fn serve(&mut self, folder: &ProviderFolder) {
        let key = hex(&folder.root_id);
        if !self.served.contains_key(&key) {
            // A root this host registered before is reconnected where it was. A NEW root waits
            // until the daemon says its namespace is queryable: the operating system caches the
            // first listing it sees.
            let path = match self.registry.get(&key) {
                Some(path) => path.clone(),
                None if folder.registration_ready => {
                    let taken = self.registry.values().cloned().collect();
                    crate::namespace_policy::choose_root_path(
                        &self.sync_roots_parent,
                        &folder.display_name,
                        &folder.root_id,
                        &taken,
                    )
                }
                None => return,
            };
            if let Err(e) = self.backend.volume_identified(&path) {
                // Neither created nor served, and a record of it is left as it is: the volume
                // is not matched by its drive letter.
                eprintln!(
                    "yadorilink-cfapi-host: the sync root {} is not served: {e}",
                    path.display()
                );
                return;
            }
            if self.registry.contains_key(&key) && !self.backend.is_dir(&path) {
                // A root registered before whose folder is gone (moved or removed while the host
                // was not running): it is not recreated empty, which would read as the user
                // deleting everything in it.
                eprintln!(
                    "yadorilink-cfapi-host: the sync root folder {} is missing; leaving {key} alone",
                    path.display()
                );
                return;
            }
            // The record of the root comes first: it is what a restart finds to retry on the
            // same path, whatever happens to the operating system's registration after it.
            if !self.registry.contains_key(&key) {
                if let Err(e) = self.backend.prepare_root(&path) {
                    eprintln!("yadorilink-cfapi-host: cannot prepare {}: {e}", path.display());
                    return;
                }
                let mut candidate = self.registry.clone();
                candidate.insert(key.clone(), path.clone());
                if !self.commit_registry(candidate) {
                    return;
                }
            }
            if let Err(e) = self.backend.register_and_connect(&folder.root_id, &path) {
                eprintln!(
                    "yadorilink-cfapi-host: failed to register sync root {}: {e}",
                    path.display()
                );
                return;
            }
            println!(
                "yadorilink-cfapi-host: registered+connected sync root {} for {key}",
                path.display()
            );
            let watch = self.backend.watch(&key, &path);
            self.served.insert(
                key.clone(),
                Served {
                    root_id: folder.root_id.clone(),
                    path,
                    needs_walk: true,
                    shown: ShownItems::new(),
                    shown_durable: false,
                    baseline_untrusted: None,
                    baseline_held: false,
                    baseline_judged: false,
                    // The first pass also sends an operation a crash left unanswered.
                    pending: BTreeSet::new(),
                    rescan: false,
                    last_signal: None,
                    retry: BTreeSet::new(),
                    retry_after: None,
                    reporter: None,
                    latest_seq: 0,
                    report_settle_until: None,
                    last_report: None,
                    attach_confirmed: false,
                    attach_fresh: true,
                    _watch: watch,
                },
            );
            self.reports.domain_state(&folder.root_id, DomainEvidence::Registered, "");
        }
        if let Some(served) = self.served.get_mut(&key) {
            served.latest_seq = served.latest_seq.max(folder.latest_evidence_seq);
        }
        self.check_baseline(&key);
        if folder.registration_ready {
            let first = self.served.get(&key).is_some_and(|served| served.last_signal.is_none());
            // An untrusted record is read again at every poll (a transient failure heals).
            let untrusted =
                self.served.get(&key).is_some_and(|served| served.baseline_untrusted.is_some());
            let held = self.served.get(&key).is_some_and(|served| served.baseline_held);
            let judged = (first || untrusted || held) && self.judge_offline_changes(&key);
            self.walk_if_due(&key);
            // The first complete showing of a root is recorded, and whatever the user did in it
            // while the host was not running (and any operation a crash left unanswered) is applied.
            if first && self.served.get(&key).is_some_and(|served| !served.needs_walk) {
                if let Some(served) = self.served.get_mut(&key) {
                    served.last_signal = Some(Instant::now());
                }
                if !judged {
                    self.apply_local(&key, true);
                }
            }
            self.report_materialized(&key, false);
        }
    }

    /// Before the first judgement of a root (and while its record is untrusted) the record of
    /// what was shown is looked at even if the namespace is not ready to be shown: a change
    /// signal or a pushed namespace must not walk over an unreadable record.
    fn check_baseline(&mut self, key: &str) {
        let Some(served) = self.served.get_mut(key) else { return };
        if served.baseline_judged {
            return;
        }
        match self.backend.load_shown(&served.root_id) {
            LoadedShown::Invalid(reason) => {
                served.baseline_untrusted = Some(reason);
                served.needs_walk = true;
            }
            LoadedShown::Loaded(_) if served.baseline_untrusted.is_none() => {
                served.baseline_held = true;
                served.needs_walk = true;
            }
            _ => {}
        }
    }

    /// Tells the daemon which items the OS holds bytes of, when that is due (or `force`).
    fn report_materialized(&mut self, key: &str, force: bool) {
        let now = Instant::now();
        let Some(served) = self.served.get_mut(key) else { return };
        // What is shown is what can be named; before the first complete walk nothing is.
        if served.needs_walk && served.shown.is_empty() {
            return;
        }
        let settling = served.report_settle_until.is_some_and(|until| now < until);
        let idle_due = served.last_report.is_none_or(|at| now.duration_since(at) >= REPORT_IDLE);
        if !(force || settling || idle_due) {
            return;
        }
        // The sequence is read BEFORE the set: a report may only claim to have begun after
        // evidence it had already seen.
        let observed_after = served.latest_seq;
        let materialized = self.backend.materialized(&served.shown);
        served.last_report = Some(now);
        let reporter = served.reporter.get_or_insert_with(Reporter::new);
        for report in reporter.reports(&served.root_id, observed_after, &materialized) {
            self.reports.materialized(report);
        }
    }

    /// News from the daemon that a handoff happened: the set is read at every poll for a while.
    pub fn on_evidence(&mut self, root: &[u8], seq: u64) {
        let key = hex(root);
        let Some(served) = self.served.get_mut(&key) else { return };
        served.attach_confirmed = true;
        served.latest_seq = served.latest_seq.max(seq);
        served.report_settle_until = Some(Instant::now() + REPORT_SETTLE);
        // Read at the next poll: a burst of handoffs is one report, not one per handoff.
    }

    /// The daemon refused a report as out of protocol: the next one starts over.
    pub fn on_report_ack(&mut self, root: &[u8], epoch: u64, needs_full: bool) {
        let key = hex(root);
        let Some(served) = self.served.get_mut(&key) else { return };
        served.attach_confirmed = true;
        if let Some(old) = served.reporter.as_ref().filter(|r| r.needs_restart(epoch, needs_full)) {
            served.reporter = Some(Reporter::after(old.epoch()));
            self.report_materialized(&key, true);
        }
    }

    /// A restart: what the user did while the host was not running is judged against the
    /// namespace this host had SHOWN, before anything is shown, so a placeholder the user deleted
    /// is reported as deleted and not put back. An item another device created in the meantime
    /// was never shown, so it is not a deletion. False when there is nothing to judge against.
    fn judge_offline_changes(&mut self, key: &str) -> bool {
        let Some(served) = self.served.get_mut(key) else { return false };
        let shown = match self.backend.load_shown(&served.root_id) {
            // A record that vanished after it was found unreadable is still not a first run.
            LoadedShown::Missing if served.baseline_untrusted.is_some() => {
                served.needs_walk = true;
                return false;
            }
            // A record read earlier and gone now is as unproven as an unreadable one.
            LoadedShown::Missing if served.baseline_held => {
                served.baseline_untrusted = Some("the record disappeared".into());
                served.needs_walk = true;
                return false;
            }
            LoadedShown::Missing => {
                served.baseline_held = false;
                served.baseline_judged = true;
                return false;
            }
            LoadedShown::Invalid(reason) => {
                if served.baseline_untrusted.as_deref() != Some(reason.as_str()) {
                    eprintln!(
                        "yadorilink-cfapi-host: the record of what was shown in {key} cannot be \
                         read ({reason}); the root is left as it is until it can"
                    );
                }
                served.baseline_untrusted = Some(reason);
                served.needs_walk = true;
                return false;
            }
            LoadedShown::Loaded(shown) => shown,
        };
        served.baseline_untrusted = None;
        served.baseline_held = false;
        served.baseline_judged = true;
        served.shown = shown;
        served.shown_durable = true;
        served.last_signal = Some(Instant::now());
        self.apply_local(key, true);
        true
    }

    fn walk_if_due(&mut self, key: &str) {
        if self.served.get(key).is_some_and(|served| served.needs_walk) {
            self.walk(key);
        }
    }

    /// Shows the namespace of the served root `key`. What the user did that has not been applied
    /// yet is applied first: showing the daemon's namespace would put back a placeholder the user
    /// just deleted before the delete was reported. True when the whole namespace was confirmed.
    fn walk(&mut self, key: &str) -> bool {
        let waiting = self
            .served
            .get(key)
            .is_some_and(|root| !root.pending.is_empty() || root.rescan || !root.retry.is_empty());
        if waiting {
            self.author_local(key, false);
        }
        self.walk_now(key)
    }

    fn walk_now(&mut self, key: &str) -> bool {
        let Some(served) = self.served.get_mut(key) else { return false };
        // An unreadable record of what was shown is not an empty one: nothing is shown over it.
        if served.baseline_untrusted.is_some() || served.baseline_held {
            served.needs_walk = true;
            return false;
        }
        // A refused volume is not shown: nothing is walked, nothing is acknowledged.
        if !self.backend.namespace_available(&served.path) {
            served.needs_walk = true;
            return false;
        }
        // What the user did and has not been reported yet is not touched by the walk: a
        // placeholder deleted there must not be put back before the daemon has been told.
        let mut protected: HashSet<String> = served
            .pending
            .iter()
            .chain(served.retry.iter())
            .map(|path| path.to_string_lossy().to_lowercase())
            .collect();
        // Lost changes are looked at in full later: until then every shown item stays as it is.
        if served.rescan {
            protected.extend(
                served.shown.values().map(|item| item.path.to_string_lossy().to_lowercase()),
            );
        }
        match self.backend.sync_namespace(&served.root_id, &served.path, &served.shown, &protected)
        {
            Some(mut shown) => {
                // An item whose name the user's own file now holds (an editor's save by
                // replacing) is still that item until the change has been applied.
                for (id, old) in &served.shown {
                    if !shown.contains_key(id) && self.backend.occupied_locally(&old.path) {
                        shown.insert(id.clone(), old.clone());
                    }
                }
                println!(
                    "yadorilink-cfapi-host: showing {} item(s) of {key} in {}",
                    shown.len(),
                    served.path.display()
                );
                let recorded = self.backend.save_shown(&served.root_id, &shown);
                served.shown = shown;
                served.shown_durable = recorded;
                // Not recorded: shown again at the next walk, and not acknowledged until then.
                served.needs_walk = !recorded;
                recorded
            }
            None => {
                served.needs_walk = true;
                false
            }
        }
    }

    /// Records a signal from the watcher of root `key`.
    pub fn on_local(&mut self, key: &str, signal: Signal) {
        let Some(served) = self.served.get_mut(key) else { return };
        match signal {
            Signal::Paths(paths) => served.pending.extend(paths),
            Signal::Overflow => served.rescan = true,
        }
        served.last_signal = Some(Instant::now());
    }

    /// How long until some root has something to apply (`max` when nothing is waiting).
    pub fn next_deadline(&self, now: Instant, max: Duration) -> Duration {
        self.served
            .values()
            .flat_map(|served| {
                let changes = (!served.pending.is_empty() || served.rescan)
                    .then(|| served.last_signal.map_or(now, |at| at + QUIET));
                let retry = (!served.retry.is_empty()).then(|| served.retry_after.unwrap_or(now));
                [changes, retry]
            })
            .flatten()
            .map(|at| at.saturating_duration_since(now))
            .min()
            .map_or(max, |wait| wait.clamp(Duration::from_millis(10), max))
    }

    /// Applies what the user did in every root that has been quiet long enough.
    pub fn apply_due_local(&mut self, now: Instant) {
        let due: Vec<String> = self
            .served
            .iter()
            .filter(|(_, served)| {
                let quiet = served.last_signal.is_none_or(|at| now.duration_since(at) >= QUIET);
                let changes = (!served.pending.is_empty() || served.rescan) && quiet;
                let retry =
                    !served.retry.is_empty() && served.retry_after.is_none_or(|at| at <= now);
                changes || retry
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in due {
            self.apply_local(&key, false);
        }
    }

    /// Applies the signalled paths (and the paths to retry) of root `key` to the daemon. With
    /// `everything`, every path of the sync root is looked at: after the watcher lost changes, and
    /// when a root starts (the user may have changed things while the host was not running).
    fn apply_local(&mut self, key: &str, everything: bool) {
        self.author_local(key, everything);
        if self.served.get(key).is_some_and(|root| root.needs_walk) {
            self.walk(key);
        }
    }

    fn author_local(&mut self, key: &str, everything: bool) {
        let Self { backend, served, .. } = self;
        let Some(root) = served.get_mut(key) else { return };
        if !root.shown_durable || !backend.namespace_available(&root.path) {
            // Fail closed: nothing is authored against a base that was not recorded, nor on a
            // volume the durable-namespace probe refused. The signals, the retries and the shown
            // baseline stay where they are and are applied once a walk has recorded the
            // namespace (or the volume is accepted).
            root.rescan |= everything;
            root.needs_walk = true;
            // The next attempt waits for the root to be quiet again instead of spinning.
            root.last_signal = Some(Instant::now());
            if !root.retry.is_empty() {
                root.retry_after = Some(Instant::now() + POLL_INTERVAL);
            }
            return;
        }
        let mut signals = std::mem::take(&mut root.pending);
        signals.append(&mut root.retry);
        root.retry_after = None;
        if everything || std::mem::take(&mut root.rescan) {
            signals.extend(backend.listing(&root.path));
            signals.extend(root.shown.values().map(|item| item.path.clone()));
        }
        let report = backend.author(&root.root_id, &root.path, &signals, &mut root.shown);
        for (path, reason) in &report.refused {
            eprintln!(
                "yadorilink-cfapi-host: the daemon refused the change at {}: {reason}",
                path.display()
            );
        }
        if !report.retry.is_empty() {
            root.retry = report.retry;
            root.retry_after = Some(Instant::now() + POLL_INTERVAL);
        }
        if report.rewalk {
            root.needs_walk = true;
        }
        root.shown_durable = backend.save_shown(&root.root_id, &root.shown);
        if !root.shown_durable {
            root.needs_walk = true;
        }
        if report.applied > 0 {
            println!("yadorilink-cfapi-host: applied {} local change(s) in {key}", report.applied);
        }
    }

    /// The daemon asked for the root's sync root to go: unregister it (the files stay where they
    /// are) and say where they are.
    fn remove(&mut self, root_id: &[u8]) {
        let key = hex(root_id);
        let Some(path) = self.registry.get(&key).cloned() else {
            // Never registered here: the removal is already true.
            self.reports.domain_state(root_id, DomainEvidence::Removed, "");
            return;
        };
        if let Err(e) = self.backend.unregister(&path) {
            eprintln!(
                "yadorilink-cfapi-host: failed to unregister sync root {}: {e}",
                path.display()
            );
            return;
        }
        // Removed only once the record no longer names the root; until then the removal is asked
        // for again (unregistering is idempotent) and not acknowledged.
        // The operating system no longer has the root, so it is not served (and not reported as
        // registered again) whether or not the record could be updated.
        self.served.remove(&key);
        let mut candidate = self.registry.clone();
        candidate.remove(&key);
        if !self.commit_registry(candidate) {
            return;
        }
        println!(
            "yadorilink-cfapi-host: unregistered sync root {} (removal requested)",
            path.display()
        );
        self.reports.domain_state(root_id, DomainEvidence::Removed, &path.to_string_lossy());
    }

    /// A new connection to the daemon: attach every served root again and show the namespaces
    /// again (the daemon may have restarted with a different state).
    pub fn on_connected(&mut self) {
        for served in self.served.values_mut() {
            self.reports.domain_state(&served.root_id, DomainEvidence::Registered, "");
            served.attach_confirmed = false;
            served.attach_fresh = true;
            served.needs_walk = true;
            // The daemon dropped what it knew of the previous connection.
            served.reporter = None;
        }
    }

    pub fn on_changed(&mut self, root: &[u8], revision: u64, request_id: &[u8]) -> bool {
        let key = hex(root);
        if !self.served.contains_key(&key) {
            // The set of provider folders changed (or an unknown root): list them again.
            return true;
        }
        if let Some(served) = self.served.get_mut(&key) {
            served.attach_confirmed = true;
        }
        let ok = self.walk(&key);
        let error = (!ok).then_some("the namespace could not be shown");
        self.reports.signal_done(root, revision, request_id, error);
        false
    }

    pub fn on_evict(
        &mut self,
        root: &[u8],
        item: &[u8],
        request_id: &[u8],
        require_shown_version: &[u8],
    ) {
        let key = hex(root);
        let known = self.served.get(&key).and_then(|s| s.shown.get(item)).map(|s| s.path.clone());
        let mut confirmed = true;
        let path = match known {
            Some(path) => Some(path),
            None if self.served.contains_key(&key) => {
                // After a restart nothing is known yet, but a hydrated copy may be on the disk:
                // look at the namespace, and if that cannot be confirmed say so instead of
                // answering "nothing to evict".
                confirmed = self.walk(&key);
                self.served.get(&key).and_then(|s| s.shown.get(item)).map(|s| s.path.clone())
            }
            None => None,
        };
        // A request that names the version the daemon confirmed is carried out only while the item is shown at
        // that version: a late request must not drop content that arrived meanwhile.
        let shown_version_differs = !require_shown_version.is_empty()
            && !self
                .served
                .get(&key)
                .and_then(|s| s.shown.get(item))
                .is_some_and(|s| s.content_version.starts_with(require_shown_version));
        let (result, error) = match path {
            None if !confirmed => (
                EvictResult::Error,
                "the namespace could not be confirmed, so the item could not be located"
                    .to_string(),
            ),
            _ if shown_version_differs => (EvictResult::NotMaterialized, String::new()),
            None => (EvictResult::NotMaterialized, String::new()),
            Some(path) => match self.backend.evict(&path, item) {
                Ok(()) => (EvictResult::Evicted, String::new()),
                Err(EvictOutcome::NotMaterialized) => (EvictResult::NotMaterialized, String::new()),
                Err(EvictOutcome::Busy) => (EvictResult::Busy, String::new()),
                Err(EvictOutcome::Error(e)) => (EvictResult::Error, e),
                Err(EvictOutcome::Evicted) => (EvictResult::Evicted, String::new()),
            },
        };
        self.reports.evict_done(root, request_id, result, &error);
        if let Some(served) = self.served.get_mut(&key) {
            served.report_settle_until = Some(Instant::now() + REPORT_SETTLE);
        }
        self.report_materialized(&key, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct Recorded {
        registered: Vec<(Vec<u8>, PathBuf)>,
        unregistered: Vec<PathBuf>,
        walks: Vec<Vec<u8>>,
        states: Vec<(Vec<u8>, i32, String)>,
        signals: Vec<(Vec<u8>, u64, bool)>,
        evictions: Vec<(Vec<u8>, i32)>,
        fail_walk: bool,
        fail_register: bool,
        prepared: Vec<PathBuf>,
        steps: Vec<&'static str>,
        fail_save: bool,
        materialized: HashSet<Vec<u8>>,
        reports: Vec<ProviderMaterializedReport>,
        evict_result: Option<EvictOutcome>,
        authored: Vec<BTreeSet<PathBuf>>,
        rewalk_next: bool,
        loaded: Option<ShownItems>,
        load_invalid: Option<String>,
        order: Vec<&'static str>,
        root_missing: bool,
        saved: Vec<ShownItems>,
        namespace_refused: bool,
        volume_unidentified: bool,
    }

    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<Recorded>>);

    impl Backend for Fake {
        fn prepare_root(&mut self, path: &Path) -> Result<(), String> {
            let mut recorded = self.0.borrow_mut();
            recorded.steps.push("prepare");
            recorded.prepared.push(path.to_path_buf());
            Ok(())
        }
        fn register_and_connect(&mut self, root_id: &[u8], path: &Path) -> Result<(), String> {
            let mut recorded = self.0.borrow_mut();
            recorded.steps.push("register");
            if recorded.fail_register {
                return Err("refused".into());
            }
            drop(recorded);
            self.0.borrow_mut().registered.push((root_id.to_vec(), path.to_path_buf()));
            Ok(())
        }
        fn unregister(&mut self, path: &Path) -> Result<(), String> {
            self.0.borrow_mut().unregistered.push(path.to_path_buf());
            Ok(())
        }
        fn sync_namespace(
            &mut self,
            root_id: &[u8],
            path: &Path,
            _previous: &ShownItems,
            _protected: &HashSet<String>,
        ) -> Option<ShownItems> {
            let mut recorded = self.0.borrow_mut();
            recorded.walks.push(root_id.to_vec());
            recorded.order.push("walk");
            if recorded.fail_walk {
                return None;
            }
            Some(ShownItems::from([(
                vec![9u8; 16],
                ShownItem {
                    path: path.join("a.txt"),
                    parent_item_id: vec![],
                    name: "a.txt".into(),
                    directory: false,
                    size: 1,
                    mtime_unix_nanos: 0,
                    content_version: vec![0; 40],
                    parent_generation: 0,
                },
            )]))
        }
        fn evict(&mut self, _path: &Path, _item: &[u8]) -> Result<(), EvictOutcome> {
            match self.0.borrow_mut().evict_result.take() {
                Some(outcome) => Err(outcome),
                None => Ok(()),
            }
        }
        fn materialized(&mut self, _shown: &ShownItems) -> HashSet<Vec<u8>> {
            self.0.borrow().materialized.clone()
        }
        fn load_shown(&mut self, _root_id: &[u8]) -> LoadedShown {
            let recorded = self.0.borrow();
            if let Some(reason) = &recorded.load_invalid {
                return LoadedShown::Invalid(reason.clone());
            }
            recorded.loaded.clone().map_or(LoadedShown::Missing, LoadedShown::Loaded)
        }
        fn save_shown(&mut self, _root_id: &[u8], shown: &ShownItems) -> bool {
            let mut recorded = self.0.borrow_mut();
            if recorded.fail_save {
                return false;
            }
            recorded.saved.push(shown.clone());
            true
        }
        fn volume_identified(&mut self, _path: &Path) -> Result<(), String> {
            if self.0.borrow().volume_unidentified {
                Err("the volume has no volume GUID path".into())
            } else {
                Ok(())
            }
        }
        fn namespace_available(&mut self, _path: &Path) -> bool {
            !self.0.borrow().namespace_refused
        }
        fn is_dir(&mut self, _path: &Path) -> bool {
            !self.0.borrow().root_missing
        }
        fn watch(&mut self, _key: &str, _path: &Path) -> Option<Box<dyn std::any::Any>> {
            None
        }
        fn author(
            &mut self,
            _root_id: &[u8],
            _root_path: &Path,
            signals: &BTreeSet<PathBuf>,
            _shown: &mut ShownItems,
        ) -> provider_authoring::Report {
            let mut recorded = self.0.borrow_mut();
            recorded.authored.push(signals.clone());
            recorded.order.push("author");
            provider_authoring::Report {
                applied: signals.len(),
                rewalk: std::mem::take(&mut recorded.rewalk_next),
                ..Default::default()
            }
        }
        fn listing(&mut self, _root_path: &Path) -> BTreeSet<PathBuf> {
            BTreeSet::from([PathBuf::from("listed")])
        }
        fn occupied_locally(&mut self, _path: &Path) -> bool {
            false
        }
    }

    impl Reports for Fake {
        fn domain_state(&self, root: &[u8], evidence: DomainEvidence, location: &str) {
            self.0.borrow_mut().states.push((root.to_vec(), evidence as i32, location.to_string()));
        }
        fn signal_done(&self, root: &[u8], revision: u64, _id: &[u8], error: Option<&str>) {
            self.0.borrow_mut().signals.push((root.to_vec(), revision, error.is_none()));
        }
        fn materialized(&self, report: ProviderMaterializedReport) {
            self.0.borrow_mut().reports.push(report);
        }
        fn evict_done(&self, root: &[u8], _id: &[u8], result: EvictResult, _error: &str) {
            self.0.borrow_mut().evictions.push((root.to_vec(), result as i32));
        }
    }

    fn folder(root: u8, name: &str, ready: bool) -> ProviderFolder {
        ProviderFolder {
            root_id: vec![root; 16],
            display_name: name.into(),
            registration_ready: ready,
            ..Default::default()
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("yl-host-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    impl Fake {
        fn host_in(fake: &Fake, dir: &Path) -> Host<Fake, Fake> {
            host(fake, dir)
        }
    }

    fn host(fake: &Fake, dir: &Path) -> Host<Fake, Fake> {
        Host::new(fake.clone(), fake.clone(), dir.join("roots.txt"), dir.join("roots"))
    }

    #[test]
    fn a_new_root_is_registered_only_when_its_namespace_is_ready() {
        let dir = temp_dir("ready");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", false)], vec![])));
        assert!(fake.0.borrow().registered.is_empty(), "registered before the namespace was ready");
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let recorded = fake.0.borrow();
        assert_eq!(recorded.registered.len(), 1);
        assert_eq!(recorded.walks.len(), 1);
        assert_eq!(recorded.states[0].1, DomainEvidence::Registered as i32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn registered_count(fake: &Fake, root: u8) -> usize {
        fake.0
            .borrow()
            .states
            .iter()
            .filter(|(id, evidence, _)| {
                *id == vec![root; 16] && *evidence == DomainEvidence::Registered as i32
            })
            .count()
    }

    /// The daemon may ignore a `Registered` (a transient read error) without answering, so
    /// the host says it again at every poll until the daemon pushes anything for the root.
    #[test]
    fn registered_is_sent_again_at_each_poll_until_the_daemon_pushes_for_the_root() {
        type Push = fn(&mut Host<Fake, Fake>, &[u8]);
        let pushes: [(&str, Push); 3] = [
            ("report ack", |host, root| host.on_report_ack(root, 1, false)),
            ("evidence tick", |host, root| host.on_evidence(root, 4)),
            ("changed", |host, root| {
                host.on_changed(root, 7, &[3]);
            }),
        ];
        for (name, push) in pushes {
            let dir = temp_dir(&format!("reattach-{}", name.replace(' ', "-")));
            let fake = Fake::default();
            let mut host = host(&fake, &dir);
            let snapshot = || Some((vec![folder(1, "Photos", true)], vec![]));
            host.reconcile(snapshot());
            assert_eq!(registered_count(&fake, 1), 1, "{name}: the first attach");
            // The first poll after an attach waits for the answer; later ones say it again.
            host.reconcile(snapshot());
            assert_eq!(registered_count(&fake, 1), 1, "{name}: sent twice in a row");
            host.reconcile(snapshot());
            host.reconcile(snapshot());
            assert_eq!(registered_count(&fake, 1), 3, "{name}: unanswered, said again each poll");

            // A push for another root says nothing about this one.
            push(&mut host, &[2; 16]);
            host.reconcile(snapshot());
            assert_eq!(registered_count(&fake, 1), 4, "{name}: another root's push confirmed it");

            push(&mut host, &[1; 16]);
            host.reconcile(snapshot());
            host.reconcile(snapshot());
            assert_eq!(
                registered_count(&fake, 1),
                4,
                "{name}: still said after the daemon answered"
            );

            // A new connection attaches again at once (and only once), and is unconfirmed again.
            host.on_connected();
            assert_eq!(registered_count(&fake, 1), 5, "{name}: not attached on connect");
            host.reconcile(snapshot());
            assert_eq!(registered_count(&fake, 1), 5, "{name}: attached twice on connect");
            host.reconcile(snapshot());
            assert_eq!(registered_count(&fake, 1), 6, "{name}: not re-armed by a connect");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A root that cannot report yet (its namespace was never shown) has no answer to wait
    /// for, so it is not sent `Registered` again every poll.
    #[test]
    fn a_root_that_cannot_report_yet_is_not_attached_again_every_poll() {
        let dir = temp_dir("reattach-no-report");
        let fake = Fake::default();
        fake.0.borrow_mut().fail_walk = true;
        let mut host = host(&fake, &dir);
        for _ in 0..4 {
            host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        }
        assert_eq!(registered_count(&fake, 1), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// While the daemon cannot be reached nothing is queued for it at each poll.
    #[test]
    fn registered_is_not_queued_while_the_daemon_is_unreachable() {
        let dir = temp_dir("reattach-unreachable");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        for _ in 0..4 {
            host.reconcile(None);
        }
        assert_eq!(registered_count(&fake, 1), 1);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(registered_count(&fake, 1), 2, "not said again once the daemon answers");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unconfirmed_snapshot_changes_nothing() {
        let dir = temp_dir("unconfirmed");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let before = fake.0.borrow().registered.len();
        host.reconcile(None);
        let recorded = fake.0.borrow();
        assert_eq!(recorded.registered.len(), before);
        assert!(recorded.unregistered.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restarted host reconnects a root where it was, even before the daemon says its namespace
    /// is ready (it does not register anything new), and does not show a namespace it cannot
    /// confirm.
    #[test]
    fn a_restarted_host_reconnects_the_same_root_at_the_same_place() {
        let dir = temp_dir("restart");
        let first = Fake::default();
        let mut one = host(&first, &dir);
        one.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let place = first.0.borrow().registered[0].1.clone();

        let second = Fake::default();
        let mut two = host(&second, &dir);
        two.reconcile(Some((vec![folder(1, "Photos", false)], vec![])));
        let recorded = second.0.borrow();
        assert_eq!(recorded.registered, vec![(vec![1u8; 16], place)]);
        assert!(recorded.walks.is_empty(), "showed a namespace that was not ready");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_orphan_is_reported_and_kept_and_a_requested_removal_unregisters() {
        let dir = temp_dir("orphan");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true), folder(2, "Docs", true)], vec![])));
        fake.0.borrow_mut().states.clear();

        host.reconcile(Some((vec![folder(2, "Docs", true)], vec![])));
        {
            let recorded = fake.0.borrow();
            assert!(recorded.unregistered.is_empty(), "removed a root on orphan evidence");
            assert!(recorded
                .states
                .iter()
                .any(|s| s.0 == vec![1u8; 16] && s.1 == DomainEvidence::Orphan as i32));
        }

        let removal = ProviderRemoval { root_id: vec![1; 16], display_name: "Photos".into() };
        host.reconcile(Some((vec![folder(2, "Docs", true)], vec![removal])));
        let recorded = fake.0.borrow();
        assert_eq!(recorded.unregistered.len(), 1);
        let removed =
            recorded.states.iter().find(|s| s.1 == DomainEvidence::Removed as i32).unwrap();
        assert!(!removed.2.is_empty(), "the preserved location was not reported");
        assert!(!read_registry_at(&dir.join("roots.txt")).unwrap().contains_key(&hex(&[1u8; 16])));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_walk_is_retried_and_a_change_is_acknowledged_by_its_outcome() {
        let dir = temp_dir("walk");
        let fake = Fake::default();
        fake.0.borrow_mut().fail_walk = true;
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(fake.0.borrow().walks.len(), 2, "a failed walk was not retried");

        let more = host.on_changed(&[1; 16], 7, &[3]);
        assert!(!more);
        assert_eq!(fake.0.borrow().signals, vec![(vec![1u8; 16], 7, false)]);

        fake.0.borrow_mut().fail_walk = false;
        host.on_changed(&[1; 16], 8, &[4]);
        assert_eq!(fake.0.borrow().signals[1], (vec![1u8; 16], 8, true));

        // A change naming a root this host does not serve asks for a new listing.
        assert!(host.on_changed(&[9; 16], 1, &[5]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A namespace whose record of shown items could not be made durable is not acknowledged and is
    /// shown again: an acknowledged but unrecorded item would not be known after a restart.
    #[test]
    fn a_namespace_that_could_not_be_recorded_is_not_acknowledged_and_is_shown_again() {
        let dir = temp_dir("save");
        let fake = Fake::default();
        fake.0.borrow_mut().fail_save = true;
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(fake.0.borrow().walks.len(), 1);
        assert!(fake.0.borrow().saved.is_empty());

        host.on_changed(&[1; 16], 7, &[3]);
        assert_eq!(fake.0.borrow().signals, vec![(vec![1u8; 16], 7, false)]);

        // The next reconcile walks again (the failed record left the walk due) and, once the
        // record can be made, the change is acknowledged.
        fake.0.borrow_mut().fail_save = false;
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.on_changed(&[1; 16], 8, &[4]);
        assert_eq!(fake.0.borrow().signals[1], (vec![1u8; 16], 8, true));
        assert!(!fake.0.borrow().saved.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A root on a volume the durable-namespace probe refused is neither authored against nor
    /// walked: the signals, the retries and the shown baseline stay as they were, and nothing is
    /// acknowledged. Once the volume is accepted they are applied.
    #[test]
    fn a_refused_volume_is_neither_authored_against_nor_walked() {
        let dir = temp_dir("refused");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let key = hex(&[1u8; 16]);
        let shown_before = host.served.get(&key).unwrap().shown.clone();
        fake.0.borrow_mut().namespace_refused = true;
        fake.0.borrow_mut().order.clear();
        fake.0.borrow_mut().authored.clear();
        host.on_local(&key, Signal::Paths(vec![PathBuf::from("a")]));
        let later = Instant::now() + QUIET + Duration::from_millis(5);
        host.apply_due_local(later);
        assert!(!host.on_changed(&[1; 16], 5, &[1]), "acknowledged on a refused volume");
        assert!(fake.0.borrow().authored.is_empty(), "authored on a refused volume");
        assert!(fake.0.borrow().order.is_empty(), "{:?}", fake.0.borrow().order);
        let served = host.served.get(&key).unwrap();
        assert_eq!(served.pending, BTreeSet::from([PathBuf::from("a")]));
        assert_eq!(served.shown, shown_before);
        assert!(served.needs_walk);

        fake.0.borrow_mut().namespace_refused = false;
        host.apply_due_local(later + QUIET);
        host.apply_due_local(later + QUIET * 2);
        assert_eq!(fake.0.borrow().authored, vec![BTreeSet::from([PathBuf::from("a")])]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// While the record of shown items is not durable, what the user did is not authored against
    /// it: a crash would restore an older baseline. The signals wait; once a record is saved they
    /// are applied.
    #[test]
    fn nothing_is_authored_against_a_shown_baseline_that_could_not_be_saved() {
        let dir = temp_dir("baseline");
        let fake = Fake::default();
        fake.0.borrow_mut().fail_save = true;
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let key = hex(&[1u8; 16]);
        host.on_local(&key, Signal::Paths(vec![PathBuf::from("a")]));
        let later = Instant::now() + QUIET + Duration::from_millis(5);
        host.apply_due_local(later);
        assert!(fake.0.borrow().authored.is_empty(), "authored against an unsaved baseline");

        fake.0.borrow_mut().fail_save = false;
        host.apply_due_local(later + QUIET);
        host.apply_due_local(later + QUIET * 2);
        assert!(!fake.0.borrow().saved.is_empty());
        assert_eq!(fake.0.borrow().authored, vec![BTreeSet::from([PathBuf::from("a")])]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The daemon learns what the OS holds: a full snapshot first, a delta when the set or the
    /// evidence moved, a new epoch after a refusal or a new connection.
    #[test]
    fn the_materialized_set_is_reported_as_a_snapshot_then_deltas_and_starts_over_when_refused() {
        let dir = temp_dir("report");
        let fake = Fake::default();
        fake.0.borrow_mut().materialized = HashSet::from([vec![4u8; 16]]);
        let mut host = host(&fake, &dir);
        let mut folder = folder(1, "Photos", true);
        folder.latest_evidence_seq = 2;
        host.reconcile(Some((vec![folder.clone()], vec![])));
        {
            let recorded = fake.0.borrow();
            assert_eq!(recorded.reports.len(), 1);
            let first = &recorded.reports[0];
            assert!(first.full && first.report_seq == 1 && first.observed_after_seq == 2);
            assert_eq!(first.upserts.len(), 1);
        }
        let epoch = fake.0.borrow().reports[0].reporter_epoch;

        // A handoff the daemon announced, and a file the OS has finished writing.
        fake.0.borrow_mut().materialized.insert(vec![5u8; 16]);
        host.on_evidence(&[1; 16], 3);
        assert_eq!(fake.0.borrow().reports.len(), 1, "a handoff alone is read at the next poll");
        host.reconcile(Some((vec![folder.clone()], vec![])));
        {
            let recorded = fake.0.borrow();
            let next = recorded.reports.last().unwrap();
            // Newer evidence lists every member again, in the next epoch.
            assert!(next.full && next.report_seq == 1 && next.reporter_epoch == epoch + 1);
            assert_eq!((next.observed_after_seq, next.upserts.len()), (3, 2));
        }
        let epoch = epoch + 1;

        // Out of protocol: a new epoch and a full snapshot of the whole set.
        host.on_report_ack(&[1; 16], epoch, true);
        {
            let recorded = fake.0.borrow();
            let again = recorded.reports.last().unwrap();
            assert!(again.full && again.report_seq == 1 && again.reporter_epoch > epoch);
            assert_eq!(again.upserts.len(), 2);
        }
        // An answer for another epoch changes nothing.
        let count = fake.0.borrow().reports.len();
        host.on_report_ack(&[1; 16], epoch, true);
        assert_eq!(fake.0.borrow().reports.len(), count);

        // A new connection: the daemon dropped the snapshot, so the next report is a full one.
        host.on_connected();
        host.reconcile(Some((vec![folder], vec![])));
        assert!(fake.0.borrow().reports.last().unwrap().full);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_eviction_request_is_answered_with_what_happened() {
        let dir = temp_dir("evict");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));

        host.on_evict(&[1; 16], &[9; 16], &[1], &[]);
        fake.0.borrow_mut().evict_result = Some(EvictOutcome::Busy);
        host.on_evict(&[1; 16], &[9; 16], &[2], &[]);
        // An item the host does not show counts as not materialized ...
        host.on_evict(&[1; 16], &[8; 16], &[3], &[]);
        // ... but only when the namespace could be confirmed.
        fake.0.borrow_mut().fail_walk = true;
        host.on_evict(&[1; 16], &[7; 16], &[4], &[]);
        fake.0.borrow_mut().fail_walk = false;
        // A request that names another version than the one shown is not carried out ...
        fake.0.borrow_mut().evict_result = Some(EvictOutcome::Error("must not be reached".into()));
        host.on_evict(&[1; 16], &[9; 16], &[5], &[1; 32]);
        fake.0.borrow_mut().evict_result = None;
        // ... and one that names the shown version is.
        host.on_evict(&[1; 16], &[9; 16], &[6], &[0; 32]);
        let results: Vec<i32> = fake.0.borrow().evictions.iter().map(|e| e.1).collect();
        assert_eq!(
            results,
            vec![
                EvictResult::Evicted as i32,
                EvictResult::Busy as i32,
                EvictResult::NotMaterialized as i32,
                EvictResult::Error as i32,
                EvictResult::NotMaterialized as i32,
                EvictResult::Evicted as i32
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the user did is applied once the root has been quiet, with the paths signalled; a
    /// lost-changes signal makes the host look at everything; the first pass after a start does
    /// the same; and a request for a fresh look is honoured.
    #[test]
    fn local_changes_are_applied_after_a_quiet_moment_and_a_start_looks_at_everything() {
        let dir = temp_dir("local");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let key = hex(&[1u8; 16]);
        // The first pass after the start looked at everything (and sent nothing else).
        assert_eq!(fake.0.borrow().authored.len(), 1);
        assert!(fake.0.borrow().authored[0].contains(Path::new("listed")));

        host.on_local(&key, Signal::Paths(vec![PathBuf::from("a"), PathBuf::from("b")]));
        let now = Instant::now();
        host.apply_due_local(now);
        assert_eq!(fake.0.borrow().authored.len(), 1, "applied before the root was quiet");
        assert!(host.next_deadline(now, Duration::from_secs(60)) <= QUIET);
        host.apply_due_local(now + QUIET + Duration::from_millis(5));
        assert_eq!(
            fake.0.borrow().authored[1],
            BTreeSet::from([PathBuf::from("a"), PathBuf::from("b")])
        );

        host.on_local(&key, Signal::Overflow);
        fake.0.borrow_mut().rewalk_next = true;
        let walks = fake.0.borrow().walks.len();
        host.apply_due_local(Instant::now() + QUIET + Duration::from_millis(5));
        assert!(fake.0.borrow().authored[2].contains(Path::new("listed")));
        assert_eq!(fake.0.borrow().walks.len(), walks + 1, "a fresh look was not taken");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restart judges the user's offline changes against the daemon's namespace BEFORE showing
    /// it (so a deleted placeholder is reported, not put back); the very first showing of a root
    /// has nothing to judge against and shows first.
    #[test]
    fn a_restart_judges_offline_changes_before_showing_and_a_first_run_shows_first() {
        let dir = temp_dir("offline");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        // First run: nothing recorded before, so the namespace is shown before the local pass,
        // and what was shown is recorded.
        assert_eq!(fake.0.borrow().order, vec!["walk", "author"]);
        assert!(!fake.0.borrow().saved.is_empty());

        // A restart with a record of what was shown: the local pass comes first.
        let again = Fake::default();
        again.0.borrow_mut().loaded = Some(ShownItems::new());
        let mut restarted = Fake::host_in(&again, &dir);
        restarted.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(again.0.borrow().order, vec!["author", "walk"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A namespace pushed by the daemon never overtakes what the user just did: the pending local
    /// changes are applied before the placeholders are shown again.
    /// A recorded root whose folder is gone is not recreated empty (that would read as the user
    /// deleting everything); a root never seen before is created.
    #[test]
    fn a_missing_registered_root_folder_is_not_recreated() {
        let dir = temp_dir("missing");
        let first = Fake::default();
        host(&first, &dir).reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let again = Fake::default();
        again.0.borrow_mut().root_missing = true;
        again.0.borrow_mut().loaded = Some(ShownItems::new());
        host(&again, &dir).reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(again.0.borrow().registered.is_empty());
        assert!(again.0.borrow().authored.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A volume with no GUID path never gets a sync folder: a new root is not prepared, recorded
    /// or registered there, and a root recorded there before is not reconnected by its drive
    /// letter (its record stays).
    #[test]
    fn a_volume_without_a_guid_path_is_neither_created_on_nor_matched() {
        let dir = temp_dir("no-guid");
        let new = Fake::default();
        new.0.borrow_mut().volume_unidentified = true;
        let mut fresh = host(&new, &dir);
        fresh.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(new.0.borrow().prepared.is_empty());
        assert!(new.0.borrow().registered.is_empty());
        assert!(read_registry_at(&dir.join("roots.txt")).unwrap().is_empty());

        let first = Fake::default();
        host(&first, &dir).reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(first.0.borrow().registered.len(), 1);
        let again = Fake::default();
        again.0.borrow_mut().volume_unidentified = true;
        again.0.borrow_mut().loaded = Some(ShownItems::new());
        host(&again, &dir).reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(again.0.borrow().registered.is_empty());
        assert!(again.0.borrow().authored.is_empty());
        assert_eq!(read_registry_at(&dir.join("roots.txt")).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pushed_namespace_is_shown_only_after_pending_local_changes_are_applied() {
        let dir = temp_dir("pushed");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        fake.0.borrow_mut().order.clear();
        host.on_local(&hex(&[1u8; 16]), Signal::Paths(vec![PathBuf::from("deleted-by-the-user")]));
        host.on_changed(&[1; 16], 5, &[1]);
        assert_eq!(fake.0.borrow().order, vec!["author", "walk"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn offline_delete_host(fake: &Fake, dir: &Path) -> Host<Fake, Fake> {
        let mut host = host(fake, dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host
    }

    /// An existing shown record that cannot be trusted is not a first run: nothing is shown,
    /// authored or acknowledged over it, and it is read again once it can be read.
    #[test]
    fn an_unreadable_shown_record_blocks_the_walk_instead_of_reading_as_a_first_run() {
        let dir = temp_dir("invalid-shown");
        offline_delete_host(&Fake::default(), &dir);
        let again = Fake::default();
        again.0.borrow_mut().load_invalid = Some("corrupt".into());
        let mut restarted = offline_delete_host(&again, &dir);
        {
            let recorded = again.0.borrow();
            assert!(recorded.walks.is_empty(), "walked over an untrusted record");
            assert!(recorded.authored.is_empty());
            assert!(recorded.saved.is_empty(), "acknowledged a baseline over an untrusted record");
        }
        let key = hex(&[1u8; 16]);
        assert!(restarted.served[&key].needs_walk);
        // A pushed namespace is not shown either, and is not acknowledged.
        restarted.on_local(&key, Signal::Paths(vec![PathBuf::from("x")]));
        restarted.on_changed(&[1; 16], 7, &[1]);
        assert!(again.0.borrow().walks.is_empty());
        assert_eq!(again.0.borrow().signals.last().map(|s| s.2), Some(false));
        // The record becomes readable: the offline changes are judged before showing.
        {
            let mut recorded = again.0.borrow_mut();
            recorded.load_invalid = None;
            recorded.loaded = Some(ShownItems::new());
        }
        restarted.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let recorded = again.0.borrow();
        assert_eq!(recorded.order.first(), Some(&"author"));
        assert!(recorded.order.contains(&"walk"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The record stays untrusted when it vanishes after being found unreadable, when the root
    /// is not ready to be shown, and an eviction lookup that could not be confirmed is an error.
    #[test]
    fn an_untrusted_record_holds_for_a_vanished_record_an_unready_root_and_eviction() {
        let dir = temp_dir("untrusted-holds");
        offline_delete_host(&Fake::default(), &dir);
        let again = Fake::default();
        again.0.borrow_mut().load_invalid = Some("corrupt".into());
        let mut restarted = host(&again, &dir);
        // Not ready: the record is still looked at, so a pushed namespace is not shown.
        restarted.reconcile(Some((vec![folder(1, "Photos", false)], vec![])));
        restarted.on_changed(&[1; 16], 3, &[1]);
        let item = [9u8; 16];
        restarted.on_evict(&[1; 16], &item, &[2], &[7u8; 8]);
        assert!(again.0.borrow().walks.is_empty());
        assert_eq!(again.0.borrow().evictions, vec![(vec![1u8; 16], EvictResult::Error as i32)]);
        // The record disappears: still not a first run.
        again.0.borrow_mut().load_invalid = None;
        restarted.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(again.0.borrow().walks.is_empty(), "walked after the record vanished");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A readable record is judged before anything is shown or saved even when the root is not
    /// ready yet and a pushed change arrives: the offline delete is seen, the record is kept.
    #[test]
    fn a_readable_record_is_judged_before_a_pushed_change_can_walk_over_it() {
        let dir = temp_dir("held");
        offline_delete_host(&Fake::default(), &dir);
        let again = Fake::default();
        again.0.borrow_mut().loaded = Some(ShownItems::new());
        let mut restarted = host(&again, &dir);
        restarted.reconcile(Some((vec![folder(1, "Photos", false)], vec![])));
        restarted.on_changed(&[1; 16], 3, &[1]);
        {
            let recorded = again.0.borrow();
            assert!(recorded.walks.is_empty(), "walked before the offline changes were judged");
            assert!(recorded.saved.is_empty(), "overwrote the record before judging");
            assert_eq!(recorded.signals.last().map(|s| s.2), Some(false));
        }
        restarted.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let recorded = again.0.borrow();
        assert_eq!(recorded.order.first(), Some(&"author"));
        assert!(recorded.order.contains(&"walk"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_held_record_that_disappears_is_still_not_a_first_run() {
        let dir = temp_dir("held-gone");
        offline_delete_host(&Fake::default(), &dir);
        let again = Fake::default();
        again.0.borrow_mut().loaded = Some(ShownItems::new());
        let mut restarted = host(&again, &dir);
        restarted.reconcile(Some((vec![folder(1, "Photos", false)], vec![])));
        again.0.borrow_mut().loaded = None;
        restarted.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let recorded = again.0.borrow();
        assert!(recorded.walks.is_empty());
        assert!(recorded.saved.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_shown_record_is_missing_loaded_or_invalid() {
        let dir = temp_dir("shown-file");
        let file = dir.join("shown");
        let generation_1 = dir.join("shown.1");
        assert_eq!(read_shown_at(&file), LoadedShown::Missing);

        let item = ShownItem {
            path: PathBuf::from("a"),
            parent_item_id: vec![],
            name: "a".into(),
            directory: false,
            size: 1,
            mtime_unix_nanos: 0,
            content_version: vec![1; 40],
            parent_generation: 0,
        };
        let mut second = item.clone();
        second.name = "b".into();
        let both = ShownItems::from([(vec![1; 16], item.clone()), (vec![2; 16], second)]);
        let good = encode_shown_record(&both);
        std::fs::write(&generation_1, &good).unwrap();
        assert_eq!(read_shown_at(&file), LoadedShown::Loaded(both.clone()));

        // A complete record of nothing shown carries an explicit zero count.
        std::fs::write(&generation_1, encode_shown_record(&ShownItems::new())).unwrap();
        assert_eq!(read_shown_at(&file), LoadedShown::Loaded(ShownItems::new()));

        let invalid = |content: &str| {
            std::fs::write(&generation_1, content).unwrap();
            matches!(read_shown_at(&file), LoadedShown::Invalid(_))
        };
        // An empty file is not a record of nothing shown.
        assert!(invalid(""));
        // Cut at a line boundary: the first item line alone, and without the trailer.
        let first_line_end = good.find('\n').unwrap() + 1;
        assert!(invalid(&good[..first_line_end]));
        let trailer_start = good.trim_end().rfind('\n').unwrap() + 1;
        assert!(invalid(&good[..trailer_start]));
        // Cut in the middle of a line, and of the trailer.
        assert!(invalid(&good[..good.len() / 2]));
        assert!(invalid(&good[..good.len() - 5]));
        // One malformed line among good ones.
        assert!(invalid(&good.replacen(&good[..4], "zz", 1)));
        assert!(invalid(&format!("garbage\n{good}")));
        // The checksum differs: an item line was changed (same count).
        assert!(invalid(&good.replacen("\t1\t", "\t2\t", 1)));
        // The count differs from the lines.
        let body = &good[..trailer_start];
        let wrong_count = good[trailer_start..].replacen("\tv1\t2\t", "\tv1\t3\t", 1);
        assert!(invalid(&format!("{body}{wrong_count}")));
        // The old format (item lines only) cannot be shown to be complete.
        assert!(invalid(body));
        assert!(invalid(&format!("{}\n", encode_shown(&[1; 16], &item))));
        // The newest generation is torn: the one before it is the record. Nothing complete is
        // Invalid, not a first run.
        std::fs::write(&generation_1, &good).unwrap();
        std::fs::write(dir.join("shown.2"), &good[..good.len() - 5]).unwrap();
        assert_eq!(read_shown_at(&file), LoadedShown::Loaded(both.clone()));
        std::fs::write(&generation_1, "").unwrap();
        assert!(matches!(read_shown_at(&file), LoadedShown::Invalid(_)));
        // The newest generation is complete (the seal holds) but a line is not understood: it is
        // the record, and the older generation is not taken in its place.
        std::fs::write(&generation_1, &good).unwrap();
        std::fs::write(dir.join("shown.2"), seal("garbage\n")).unwrap();
        assert!(matches!(read_shown_at(&file), LoadedShown::Invalid(_)));
        std::fs::remove_file(dir.join("shown.2")).unwrap();
        // A read error other than "not there" (a directory in the place of the file).
        std::fs::remove_file(&generation_1).unwrap();
        std::fs::create_dir(&generation_1).unwrap();
        assert!(matches!(read_shown_at(&file), LoadedShown::Invalid(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_shown_item_survives_the_journal_unchanged() {
        let item = ShownItem {
            path: PathBuf::from(r"C:\Users\a\YadoriLink\Photos\日本語 file.txt"),
            parent_item_id: vec![4; 16],
            name: "日本語 file.txt".into(),
            directory: false,
            size: 12,
            mtime_unix_nanos: -5,
            content_version: vec![9; 40],
            parent_generation: 3,
        };
        let line = encode_shown(&[7; 16], &item);
        assert_eq!(decode_shown(&line), Some((vec![7; 16], item)));
        assert_eq!(decode_shown("not\ta line"), None);
    }

    #[test]
    fn the_registry_round_trips_and_refuses_corruption() {
        let mut roots = HashMap::new();
        roots.insert(hex(&[1u8; 16]), PathBuf::from(r"C:\Users\a\YadoriLink\Photos"));
        let text = render_registry(&roots);
        assert_eq!(parse_registry(&text), Ok(roots.clone()));
        // A bare path (an earlier format) or a short id is not skipped: it is corruption.
        assert!(parse_registry(&format!("{text}C:\\old\\plain\\folder\n")).is_err());
        assert!(parse_registry(&format!("{text}0101\n")).is_err());
        let seen: HashSet<_> = parse_registry(&text).unwrap().into_keys().collect();
        assert_eq!(seen.len(), 1);
        // A line that has a tab but is not a root and a path is corruption, not a legacy line.
        // Not a canonical root id: too short, too long, uppercase.
        for bad in ["01", "0101010101010101010101010101010101", "0A010101010101010101010101010101"]
        {
            assert!(parse_registry(&format!("{text}{bad}\tC:\\x\n")).is_err(), "{bad}");
        }
        // A root recorded twice is corruption, whether or not the paths agree.
        assert!(parse_registry(&format!("{text}{text}")).is_err());
        assert!(parse_registry(&format!("{text}{}\tC:\\other\n", hex(&[1u8; 16]))).is_err());
        assert!(parse_registry(&format!("{text}not-hex\tC:\\x\n")).is_err());
        assert!(parse_registry(&format!("{text}{}\t\n", hex(&[2u8; 16]))).is_err());
        // A record that lost its tab is corruption too.
        assert!(parse_registry(&format!("{text}{}C:\\x\n", hex(&[2u8; 16]))).is_err());
        // One folder for two roots, also when the paths differ only by case or a trailing slash.
        for other in [
            r"C:\Users\a\YadoriLink\Photos",
            r"c:\users\A\yadorilink\PHOTOS\",
            "C:/Users/a/YadoriLink/Photos",
        ] {
            assert!(
                parse_registry(&format!("{text}{}\t{other}\n", hex(&[2u8; 16]))).is_err(),
                "{other}"
            );
        }
    }

    /// `--unregister-all` touches only the roots the operating system says are this host's with
    /// the recorded id, and keeps the record when anything was left.
    /// Folder names differ only by case in the display names of two roots: they get two folders,
    /// and the registry that records them is one the parser accepts.
    #[test]
    fn roots_named_alike_apart_from_case_get_their_own_folders() {
        let dir = temp_dir("case");
        let fake = Fake::default();
        let mut host = host_with(&fake, &dir);
        // Sigma and final sigma are two letters to the volume.
        host.reconcile(Some((
            vec![
                folder(1, "Photos", true),
                folder(2, "photos", true),
                folder(3, "\u{3c3}", true),
                folder(4, "\u{3c2}", true),
            ],
            vec![],
        )));
        assert_eq!(read_registry_at(&dir.join("roots.txt")).unwrap().len(), 4);
        // Sharp s is not "ss" to the volume: two distinct folders.
        let sharp = format!("{}\t{}\n", hex(&[7u8; 16]), "C:\\Stra\u{df}e");
        let double = format!("{}\t{}\n", hex(&[8u8; 16]), "C:\\Strasse");
        assert!(parse_registry(&format!("{sharp}{double}")).is_ok());
        let sigma = format!("{}\t{}\n", hex(&[5u8; 16]), "C:\\x\u{3c3}");
        let final_sigma = format!("{}\t{}\n", hex(&[6u8; 16]), "C:\\x\u{3c2}");
        assert!(parse_registry(&format!("{sigma}{final_sigma}")).is_ok());
        // Sigma and capital sigma are one letter: one folder cannot belong to two roots.
        let capital = format!("{}\t{}\n", hex(&[6u8; 16]), "C:\\x\u{3a3}");
        assert!(parse_registry(&format!("{sigma}{capital}")).is_err());
        // ASCII i and dotless i are two letters to the volume.
        let dotless = format!("{}\t{}\n", hex(&[6u8; 16]), "C:\\x\u{131}");
        let ascii = format!("{}\t{}\n", hex(&[5u8; 16]), "C:\\xI");
        assert!(parse_registry(&format!("{ascii}{dotless}")).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unregister_all_leaves_roots_it_cannot_confirm_alone() {
        let mine = hex(&[1u8; 16]);
        let theirs = hex(&[2u8; 16]);
        let record = format!("{mine}\tC:\\mine\n{theirs}\tC:\\theirs\n");
        let mut unregistered = Vec::new();
        let gone = {
            let mut identity = |path: &Path| -> Result<Option<Vec<u8>>, String> {
                // C:\theirs is registered for another root id (a mismatch).
                Ok(Some(if path == Path::new("C:\\mine") { vec![1; 16] } else { vec![9; 16] }))
            };
            let mut unregister = |path: &Path| {
                unregistered.push(path.to_path_buf());
                Ok(())
            };
            unregister_recorded(&record, &mut identity, &mut unregister)
        };
        assert_eq!(unregistered, vec![PathBuf::from("C:\\mine")]);
        assert!(!gone, "the record of a root left behind was dropped");

        // A root the system will not describe (another provider's) is not gone: the record stays.
        let gone = unregister_recorded(
            &format!("{mine}\tC:\\mine\n"),
            &mut |_| Err("registered by another provider".into()),
            &mut |_| panic!("unregistered a root that was not confirmed"),
        );
        assert!(!gone);

        // Everything confirmed: done, the record can go.
        let mut unregistered = Vec::new();
        let gone = unregister_recorded(
            &format!("{mine}\tC:\\mine\n"),
            &mut |_| Ok(Some(vec![1; 16])),
            &mut |path| {
                unregistered.push(path.to_path_buf());
                Ok(())
            },
        );
        assert!(gone);
        assert_eq!(unregistered.len(), 1);

        // A record with a corrupt, short-id or bare-path line unregisters nothing.
        for bad in ["01\tC:\\theirs\n", "C:\\bare\\path\n", &format!("{theirs}\tC:\\MINE\n")] {
            let mut called = false;
            let gone = unregister_recorded(
                &format!("{mine}\tC:\\mine\n{bad}"),
                &mut |_| Ok(Some(vec![1; 16])),
                &mut |_| {
                    called = true;
                    Ok(())
                },
            );
            assert!(!gone && !called, "{bad}");
        }
    }

    /// Registered roots are replayed from the record: it is committed before the operating
    /// system is asked, a failed commit acknowledges nothing, and a failure after the commit is
    /// retried on the same path.
    #[test]
    fn a_registration_is_acknowledged_only_after_its_record_is_durable() {
        let dir = temp_dir("reg-ack");
        let fake = Fake::default();
        // The record cannot be written: the parent of the file is a regular file.
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, "x").unwrap();
        let mut host =
            Host::new(fake.clone(), fake.clone(), blocker.join("roots.txt"), dir.join("roots"));
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        {
            let recorded = fake.0.borrow();
            assert!(recorded.registered.is_empty(), "registered without a durable record");
            assert!(recorded.states.is_empty(), "acknowledged without a durable record");
            assert!(recorded.walks.is_empty());
        }
        assert!(host.registry.is_empty());

        // The OS registration fails after the record was committed: the record stays, and the
        // retry (also in a restarted host) uses the same path.
        let fake = Fake::default();
        fake.0.borrow_mut().fail_register = true;
        let mut host = host_with(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(fake.0.borrow().states.is_empty());
        assert_eq!(fake.0.borrow().steps, vec!["prepare", "register"]);
        let path = fake.0.borrow().prepared[0].clone();
        let on_disk = read_registry_at(&dir.join("roots.txt")).unwrap();
        assert_eq!(on_disk.get(&hex(&[1u8; 16])), Some(&path));

        let restarted = Fake::default();
        let mut host = host_with(&restarted, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let recorded = restarted.0.borrow();
        assert!(recorded.prepared.is_empty(), "chose or prepared a second path");
        assert_eq!(recorded.registered, vec![(vec![1u8; 16], path)]);
        assert_eq!(recorded.states[0].1, DomainEvidence::Registered as i32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn host_with(fake: &Fake, dir: &Path) -> Host<Fake, Fake> {
        host(fake, dir)
    }

    #[test]
    fn a_removal_is_acknowledged_only_after_its_record_is_durable() {
        let dir = temp_dir("rm-ack");
        let fake = Fake::default();
        let mut host = host_with(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        fake.0.borrow_mut().states.clear();
        // The record cannot be written: a file is where its directory should be.
        let aside = dir.with_extension("aside");
        std::fs::rename(&dir, &aside).unwrap();
        std::fs::write(&dir, "in the way").unwrap();
        let removal = ProviderRemoval { root_id: vec![1; 16], display_name: "Photos".into() };
        host.reconcile(Some((vec![], vec![removal.clone()])));
        std::fs::remove_file(&dir).unwrap();
        std::fs::rename(&aside, &dir).unwrap();
        assert!(
            fake.0.borrow().states.iter().all(|s| s.1 != DomainEvidence::Removed as i32),
            "acknowledged a removal that a restart would not find"
        );
        assert!(host.registry.contains_key(&hex(&[1u8; 16])));
        assert!(!host.served.contains_key(&hex(&[1u8; 16])), "still served after the unregister");
        assert!(read_registry_at(&dir.join("roots.txt")).unwrap().contains_key(&hex(&[1u8; 16])));

        // Retried once the record can be written.
        host.reconcile(Some((vec![], vec![removal])));
        assert!(fake.0.borrow().states.iter().any(|s| s.1 == DomainEvidence::Removed as i32));
        assert!(read_registry_at(&dir.join("roots.txt")).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_registry_is_not_an_empty_one() {
        let dir = temp_dir("reg-read");
        let file = dir.join("roots.txt");
        assert_eq!(read_registry_at(&file), Ok(HashMap::new()));
        let generation_1 = dir.join("roots.txt.1");
        std::fs::write(&generation_1, seal("zz\tC:\\x\n")).unwrap();
        assert!(read_registry_at(&file).is_err());
        // Not sealed (cut short, or written by an older version): not a registry.
        std::fs::write(&generation_1, "zz").unwrap();
        assert!(read_registry_at(&file).is_err());
        std::fs::remove_file(&generation_1).unwrap();
        std::fs::create_dir(&generation_1).unwrap();
        assert!(read_registry_at(&file).is_err());

        // A host that cannot read its record registers and removes nothing, and starts again
        // once the record can be read.
        let fake = Fake::default();
        let mut host = host_with(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(fake.0.borrow().prepared.is_empty());
        assert!(fake.0.borrow().registered.is_empty());
        assert!(fake.0.borrow().states.is_empty());
        std::fs::remove_dir(&generation_1).unwrap();
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(fake.0.borrow().registered.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
