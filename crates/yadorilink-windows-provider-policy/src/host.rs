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

use crate::namespace_policy::{EvictOutcome, PinOutcome, PinWish, ShownItem, ShownItems};
use crate::provider_authoring;
use crate::provider_report::Reporter;
use crate::provider_session::{self, SessionEvent};
use yadorilink_fs_platform::generation::{self, seal, unseal};
use yadorilink_ipc_proto::shellipc::{
    DomainEvidence, EvictResult, PinResult, ProviderFolder, ProviderMaterializedReport,
    ProviderRemoval,
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
/// How long after the host changed a pin mark itself the signals of that change are not reported as the
/// person's: longer than [`QUIET`], which is how long they wait before they are looked at.
pub const PIN_SETTLE: Duration = Duration::from_secs(5);
/// The most pin marks remembered per root. Past it the memory is dropped: a path seen again is then
/// compared with the default, which at worst reports a mark the daemon already holds.
const MAX_REMEMBERED_PIN_MARKS: usize = 200_000;
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

/// Whether the operating system still has a sync root registered as this host registered it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registration {
    /// Registered with the identity of the root.
    Ours,
    /// Not registered, or registered as something else. The placeholders a registration took with
    /// it are gone with it: that is the operating system's doing, not the person's.
    Lost,
    /// It could not be read right now.
    Unknown,
}

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
    /// Applies the person's choice to the item at `path` in the operating system: a keep pins it
    /// (a folder: everything beneath it) so its content is on this PC, online only unpins it, and a
    /// clear sets neither.
    fn pin(&mut self, path: &Path, item_id: Option<&[u8]>, wish: PinWish) -> PinOutcome;
    /// The pin mark `path` carries now, read from the file system without recalling anything; `None`
    /// when it cannot be read or this host has no such mark.
    fn pin_mark(&mut self, path: &Path) -> Option<PinWish>;
    /// The items of `shown` the operating system holds bytes of now.
    fn materialized(&mut self, shown: &ShownItems) -> HashSet<Vec<u8>>;
    /// The items an earlier run of the host showed in this root, as it showed them. A record that
    /// exists but cannot be read back is [`LoadedShown::Invalid`], never "nothing was shown".
    fn load_shown(&mut self, root_id: &[u8]) -> LoadedShown;
    /// Records the items shown in this root now. False when it could not be made durable: what
    /// was shown is then not acknowledged (a recorded item whose placeholder is gone reads as the
    /// user deleting it, and an unrecorded one cannot be told from an item another device made).
    fn save_shown(&mut self, root_id: &[u8], shown: &ShownItems) -> bool;
    /// The pin marks an earlier run recorded for this root, by item id (see [`encode_pins_record`]);
    /// `None` when there is no record that can be trusted.
    fn load_pins(&mut self, _root_id: &[u8]) -> Option<HashMap<Vec<u8>, PinWish>> {
        None
    }
    /// Records the pin marks of this root durably; `None` records that the marks are no longer
    /// known completely, so the next run has no baseline. False when it could not be made durable
    /// (the next run then starts from an older or untrusted baseline, which only ever costs a
    /// report that changes nothing, or a pass that records without reporting).
    fn save_pins(&mut self, _root_id: &[u8], _marks: Option<&HashMap<Vec<u8>, PinWish>>) -> bool {
        true
    }
    /// Whether the operating system has the sync root of `root_id` at `path` registered as this host
    /// registered it. Asked before anything is authored from what is (or is not) in the folder.
    fn root_registration(&mut self, _root_id: &[u8], _path: &Path) -> Registration {
        Registration::Ours
    }
    /// Forgets everything recorded about what this root showed and which pins it carried: after a
    /// lost registration none of it describes what the operating system holds. False when it could
    /// not be made durable.
    fn forget_root_state(&mut self, _root_id: &[u8]) -> bool {
        true
    }
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
    fn pin_done(&self, root: &[u8], request_id: &[u8], result: PinResult, error: &str);
    /// The pin mark of `item` changed in the operating system and the host did not change it.
    fn pin_observed(&self, root: &[u8], item: &[u8], wish: PinWish);
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

/// The pin marks the host last set or saw, per item id, as recorded for the next run. Only items
/// that carry a mark are listed (an item absent carries none). The item id, not its path, names an
/// item: a rename or a change of a path's letter case between runs is not a change of pin. The sync
/// root itself is the item with the empty id.
/// A record that says the marks are not known completely: read as no baseline.
pub fn encode_untrusted_pins_record() -> String {
    seal("untrusted\n")
}

pub fn encode_pins_record(marks: &HashMap<Vec<u8>, PinWish>) -> String {
    let mut lines: Vec<String> = marks
        .iter()
        .filter_map(|(id, wish)| {
            let tag = match wish {
                PinWish::Keep => "k",
                PinWish::OnlineOnly => "o",
                PinWish::Clear => return None,
            };
            Some(format!("{}\t{tag}\n", hex(id)))
        })
        .collect();
    lines.sort();
    seal(&lines.concat())
}

fn decode_pin_line(line: &str) -> Option<(Vec<u8>, PinWish)> {
    let (id, tag) = line.split_once('\t')?;
    let wish = match tag {
        "k" => PinWish::Keep,
        "o" => PinWish::OnlineOnly,
        _ => return None,
    };
    Some((unhex(id)?, wish))
}

/// The newest complete generation of the pin record at `file`. `None` when there is no baseline
/// that can be trusted: no record, a record that is complete but not understood, an unreadable
/// one, or one whose newest generation was torn so that an older one is all that is left (it may
/// predate marks the host has acted on since). An untrusted baseline is never read as marks, and
/// never as "nothing was marked": the pass then records what the file system says without
/// reporting differences, because it cannot tell the person's change from a rule the app changed
/// while the host was down.
pub fn read_pins_at(file: &Path) -> Option<HashMap<Vec<u8>, PinWish>> {
    match generation::read_latest(file, |text| {
        unseal(text).map(|body| body.lines().map(decode_pin_line).collect::<Option<Vec<_>>>())
    }) {
        generation::Latest::Loaded { value: Some(marks), skipped_newer: false, .. } => {
            Some(marks.into_iter().collect())
        }
        _ => None,
    }
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

    fn pin_done(&self, root: &[u8], request_id: &[u8], result: PinResult, error: &str) {
        provider_session::Session::pin_done(self, root, request_id, result, error);
    }

    fn pin_observed(&self, root: &[u8], item: &[u8], wish: PinWish) {
        provider_session::Session::pin_observed(self, root, item, wish);
    }

    fn materialized(&self, report: ProviderMaterializedReport) {
        provider_session::Session::materialized(self, report);
    }
}

/// How many shown items one turn of the pass over the pin marks reads (about a tenth of a second
/// at the measured cost per item).
const PIN_PASS_SLICE: usize = 1_000;

/// How long a failed write of the pin record waits before it is tried again.
const PIN_SAVE_RETRY: Duration = Duration::from_secs(30);

/// A pass over a root's pin marks in progress.
struct PinPass {
    /// Every shown item, and the sync root itself (the empty id), with its path.
    items: Vec<(Vec<u8>, PathBuf)>,
    next: usize,
    /// What the previous run recorded; `None`: nothing that can be trusted.
    baseline: Option<HashMap<Vec<u8>, PinWish>>,
    marks: HashMap<PathBuf, PinWish>,
    /// The items whose mark differs from the baseline and were reported.
    reported: HashSet<Vec<u8>>,
    /// Paths whose pin the host itself changed while the pass was running: not read or reported
    /// by it, and taken from the live marks when it finishes.
    touched: HashSet<PathBuf>,
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
    /// The last pin mark seen or applied per path, for the paths that carry one (a path absent here
    /// carries none). A change the watcher signals is reported to the daemon only when the mark now
    /// differs from this, so a repeated signal costs one read and no message.
    pin_marks: HashMap<PathBuf, PinWish>,
    /// The pass over the root's pin marks that follows its first complete showing has been made:
    /// what the person changed while the host was not running is known to the daemon. Until then
    /// the daemon's pin plan is held, so it cannot overwrite that change.
    pins_reconciled: bool,
    /// The newest pin plan that arrived before the pass was made.
    held_plan: Vec<(Vec<u8>, PinWish)>,
    /// The pass over the root's pin marks, begun and not finished: it reads a slice of the shown
    /// items per turn so that a large root does not hold the host's only loop.
    pin_pass: Option<PinPass>,
    /// `pin_marks` changed since it was last recorded.
    pin_marks_unsaved: bool,
    /// The marks by item id as the next record will say them (the sync root is the empty id),
    /// kept up to date as marks are seen or set, so a moved item keeps its entry.
    recorded: HashMap<Vec<u8>, PinWish>,
    /// Items the pass reported and the daemon has not yet been seen to agree with, with the mark
    /// the previous record had for them (`Clear`: none). The record keeps that old mark until the
    /// daemon's next plan agrees with the item's mark: a report lost with the connection, or not yet
    /// processed by the daemon, is then made again on the next connection or run.
    unconfirmed: HashMap<Vec<u8>, PinWish>,
    /// The "marks not known completely" record has been written.
    pin_untrusted_written: bool,
    /// More items carry a mark than are remembered: the memory was dropped and the record is no
    /// longer rewritten from it (what it holds stays as the last complete state).
    pin_marks_overflowed: bool,
    /// Not before this time is a failed record write tried again.
    pin_save_after: Option<Instant>,
    /// Until when the pin marks in this root are being changed by the host itself: a recursive pin
    /// of a folder passes through marks the person never chose, and the signals it raises must not
    /// be taken for the person's doing. The marks are still read and remembered meanwhile.
    pin_settle_until: Option<Instant>,
    /// Paths signalled while the settle window was open: they are read when it closes, not dropped,
    /// so a change the person makes in the window still reaches the daemon.
    pin_deferred: BTreeSet<PathBuf>,
    /// Changes were lost: look at everything.
    rescan: bool,
    /// The shown files by path, to name the item a signalled path stands for without searching
    /// the whole record; rebuilt after the shown items change.
    path_index: Option<HashMap<PathBuf, Vec<u8>>>,
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
            // A root this host registered before must still be registered with the operating system.
            // If it is not, its placeholders went with the registration, and a recorded namespace
            // judged against the empty folder would read as the person deleting everything:
            // the record is forgotten and the folder shown again from the daemon's namespace.
            if self.registry.contains_key(&key) {
                match self.backend.root_registration(&folder.root_id, &path) {
                    Registration::Ours => {}
                    Registration::Unknown => {
                        eprintln!(
                            "yadorilink-cfapi-host: the registration of {} cannot be read; not serving it yet",
                            path.display()
                        );
                        return;
                    }
                    Registration::Lost => {
                        eprintln!(
                            "yadorilink-cfapi-host: {} is no longer registered; what was recorded of it is forgotten",
                            path.display()
                        );
                        if !self.backend.forget_root_state(&folder.root_id) {
                            eprintln!("yadorilink-cfapi-host: that could not be recorded; not serving {key}");
                            return;
                        }
                    }
                }
            } else if !self.backend.forget_root_state(&folder.root_id) {
                // A root this host has no record of registering cannot have valid records of what it
                // showed: the sync roots are recorded before anything else about a root is. Whatever
                // is found (a reinstall that lost the list of roots but not the rest) describes
                // placeholders that are gone with the registration, and judging it against the
                // folder would read them as deleted.
                eprintln!("yadorilink-cfapi-host: stale records of {key} could not be forgotten; not serving it");
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
                    pin_marks: HashMap::new(),
                    pins_reconciled: false,
                    held_plan: Vec::new(),
                    pin_pass: None,
                    pin_marks_unsaved: false,
                    pin_marks_overflowed: false,
                    recorded: HashMap::new(),
                    unconfirmed: HashMap::new(),
                    pin_untrusted_written: false,
                    pin_save_after: None,
                    pin_settle_until: None,
                    pin_deferred: BTreeSet::new(),
                    rescan: false,
                    path_index: None,
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
            // The pass over the pin marks, once the root has been completely shown (it is
            // continued here when it was not finished, and begun again after a failed showing).
            self.reconcile_pins(&key, Instant::now());
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
        served.path_index = None;
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
                served.path_index = None;
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
                // Deferred pin marks are looked at only against a recorded base (as `observe_pins`
                // does), so they are not a reason to wake while it is not.
                let deferred = (!served.pin_deferred.is_empty() && served.shown_durable)
                    .then(|| served.pin_settle_until.unwrap_or(now));
                // Remembered marks that are not recorded yet are recorded once the host's own pin
                // change has settled (one wake, not a timer).
                let unsaved = (served.pin_marks_unsaved
                    && served.pins_reconciled
                    && served.shown_durable
                    && (!served.pin_marks_overflowed || !served.pin_untrusted_written))
                    .then(|| {
                        let ready = served.pin_settle_until.unwrap_or(now);
                        served.pin_save_after.map_or(ready, |after| after.max(ready))
                    });
                // The next slice of an unfinished pass over the pin marks.
                let pass =
                    served.pin_pass.is_some().then(|| served.pin_settle_until.unwrap_or(now));
                [changes, retry, deferred, unsaved, pass]
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
        // Pin marks signalled while a settle window was open, once it has closed.
        let deferred: Vec<String> = self
            .served
            .iter()
            .filter(|(_, served)| {
                !served.pin_deferred.is_empty()
                    && served.pin_settle_until.is_none_or(|at| at <= now)
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in deferred {
            self.observe_pins(&key, now);
        }
        let unfinished: Vec<String> = self
            .served
            .iter()
            .filter(|(_, served)| served.pin_pass.is_some())
            .map(|(key, _)| key.clone())
            .collect();
        for key in unfinished {
            self.reconcile_pins(&key, now);
        }
        let unsaved: Vec<String> = self
            .served
            .iter()
            .filter(|(_, served)| served.pin_marks_unsaved)
            .map(|(key, _)| key.clone())
            .collect();
        for key in unsaved {
            self.flush_pin_marks(&key, now);
        }
    }

    /// Applies the signalled paths (and the paths to retry) of root `key` to the daemon. With
    /// `everything`, every path of the sync root is looked at: after the watcher lost changes, and
    /// when a root starts (the user may have changed things while the host was not running).
    fn apply_local(&mut self, key: &str, everything: bool) {
        self.observe_pins(key, Instant::now());
        // The files the signals name: whether their bytes are on this computer may have changed
        // (a download finished, a free-up space, an edit), and is reported for those files alone.
        // The paths authoring is about to look at: the signalled ones and those waiting for a retry
        // (a file that could not be inspected at first and is accepted the next time).
        let signalled: BTreeSet<PathBuf> = if everything {
            BTreeSet::new()
        } else {
            self.served
                .get(key)
                .map(|root| root.pending.union(&root.retry).cloned().collect())
                .unwrap_or_default()
        };
        self.author_local(key, everything);
        // The registration may have gone while the pass ran (what was authored before it was
        // noticed was checked item by item): a root that lost it is not walked, nor reported on.
        if !self.registration_holds(key) {
            return;
        }
        if self.served.get(key).is_some_and(|root| root.needs_walk) {
            self.walk(key);
        }
        self.report_materialized_changes(key, &signalled);
    }

    /// The ids of the shown files at `paths`.
    fn shown_files_at(&mut self, key: &str, paths: &BTreeSet<PathBuf>) -> Vec<Vec<u8>> {
        let Some(root) = self.served.get_mut(key) else { return Vec::new() };
        if paths.is_empty() {
            return Vec::new();
        }
        let index = root.path_index.get_or_insert_with(|| {
            root.shown
                .iter()
                .filter(|(_, item)| !item.directory)
                .map(|(id, item)| (item.path.clone(), id.clone()))
                .collect()
        });
        paths.iter().filter_map(|path| index.get(path).cloned()).collect()
    }

    /// Tells the daemon which of the `signalled` files are on this computer now, when that differs
    /// from what it was told. The set of everything shown is not looked at: only the files the
    /// signals name, so a finished download shows within a moment of the last signal and a busy
    /// folder costs one attribute read per file that changed. Before the first report there is
    /// nothing to correct (the full snapshot comes first), and when the daemon has newer evidence
    /// than the last report was read after, the whole set is reported again (see `Reporter`).
    fn report_materialized_changes(&mut self, key: &str, signalled: &BTreeSet<PathBuf>) {
        if signalled.is_empty() {
            return;
        }
        let Some(root) = self.served.get(key) else { return };
        if !root.shown_durable {
            return;
        }
        let Some(reporter) = root.reporter.as_ref() else { return };
        if root.latest_seq > reporter.observed_after() {
            self.report_materialized(key, true);
            return;
        }
        let mut ids = self.shown_files_at(key, signalled);
        let Self { backend, served, reports, .. } = self;
        let Some(root) = served.get_mut(key) else { return };
        // A file the daemon was told is on this computer and that is no longer shown (the user
        // deleted it, or moved a folder holding it away) is taken out whichever path was signalled.
        if let Some(reporter) = root.reporter.as_ref() {
            ids.extend(
                reporter.reported().iter().filter(|id| !root.shown.contains_key(*id)).cloned(),
            );
        }
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            return;
        }
        let subset: ShownItems = ids
            .iter()
            .filter_map(|id| root.shown.get(id).map(|item| (id.clone(), item.clone())))
            .collect();
        let now = backend.materialized(&subset);
        let Some(reporter) = root.reporter.as_mut() else { return };
        for report in reporter.changed(&root.root_id, &ids, &now) {
            reports.materialized(report);
        }
    }

    /// Tells the daemon about the pin marks the person changed among the signalled paths. Only the
    /// paths the watcher named are read (no tree scan, nothing happens while nothing is signalled),
    /// and a path is reported once per change: its mark is compared with the last one seen or applied.
    /// While the host's own pin change is settling (see `pin_settle_until`) nothing is read: the
    /// signalled paths wait until the window closes and are then judged by the mark they carry by
    /// then, so the transient marks of a recursive pin are never taken for the person's and a change
    /// the person made in the window is not lost. After the watcher lost changes, the paths already
    /// known to carry a mark are read too (a pin removed meanwhile shows there; no tree is scanned).
    fn observe_pins(&mut self, key: &str, now: Instant) {
        let Self { backend, served, reports, .. } = self;
        let Some(root) = served.get_mut(key) else { return };
        if !root.shown_durable {
            return;
        }
        if root.pin_pass.is_some() || root.pin_settle_until.is_some_and(|until| now < until) {
            // The pass has not read every mark yet, or the host is changing marks itself: what is
            // signalled waits and is judged by the mark it carries afterwards.
            let signalled = root.pending.iter().cloned();
            root.pin_deferred.extend(signalled);
            return;
        }
        root.pin_settle_until = None;
        let mut paths: BTreeSet<PathBuf> = std::mem::take(&mut root.pin_deferred);
        paths.extend(root.pending.iter().cloned());
        if root.rescan {
            // Changes were lost: every shown item is read, not only the ones already known to
            // carry a mark (a pin set meanwhile, or marks dropped past the memory bound, show there).
            paths.extend(root.shown.values().map(|item| item.path.clone()));
            paths.insert(root.path.clone());
        }
        if paths.is_empty() {
            return;
        }
        // One map of the shown items for the whole batch, not a search per path; the sync root
        // itself is the item with the empty id.
        let mut items: HashMap<&Path, &[u8]> =
            root.shown.iter().map(|(id, item)| (item.path.as_path(), id.as_slice())).collect();
        items.insert(root.path.as_path(), &[]);
        let mut changed: Vec<(PathBuf, PinWish)> = Vec::new();
        for path in &paths {
            let Some(mark) = backend.pin_mark(path) else {
                root.pin_marks.remove(path);
                continue;
            };
            let previous = root.pin_marks.get(path).copied().unwrap_or(PinWish::Clear);
            if mark == PinWish::Clear {
                root.pin_marks.remove(path);
            } else {
                root.pin_marks.insert(path.clone(), mark);
            }
            if let Some(id) = items.get(path.as_path()) {
                if mark == PinWish::Clear {
                    root.recorded.remove(*id);
                } else {
                    root.recorded.insert(id.to_vec(), mark);
                }
            }
            if mark != previous {
                changed.push((path.clone(), mark));
            }
        }
        if root.pin_marks.len() > MAX_REMEMBERED_PIN_MARKS
            || root.recorded.len() > MAX_REMEMBERED_PIN_MARKS
        {
            root.pin_marks.clear();
            root.recorded.clear();
            root.pin_marks_overflowed = true;
        }
        root.pin_marks_unsaved = true;
        for (path, mark) in changed {
            if let Some(item) = items.get(path.as_path()) {
                reports.pin_observed(&root.root_id, item, mark);
            }
        }
    }

    /// The one pass over a root's pin marks, made when the root has been completely shown for the
    /// first time on a connection (the host was not running, or not connected, before: the person
    /// may have pinned or unpinned things meanwhile, and no event for that can be read afterwards).
    /// Every shown item's mark, and the sync root's own, is read once and compared with the record
    /// the previous run left: a mark that differs is the person's doing (the host records what it
    /// sets) and is reported like any observed pin; the marks seen become the remembered ones. From
    /// then on the watcher's signals are the only thing looked at again.
    ///
    /// The pass reads [`PIN_PASS_SLICE`] items per turn and is continued by the next turn (the
    /// poll, or the wake `next_deadline` asks for), so a large root does not keep the host from
    /// answering the daemon. Without a record that can be trusted the marks are recorded and
    /// nothing is reported: a difference could as well be a rule the app changed while the host
    /// was down, which a report would turn back.
    ///
    /// The daemon's pin plan, which would put the rules' pins over the person's change, is held
    /// until the pass is made and skips the items it reported. The record is written only after the
    /// settle window that follows, so a connection lost before the daemon acted on a report finds
    /// the old record again and reports once more.
    fn reconcile_pins(&mut self, key: &str, now: Instant) {
        let finished = {
            let Self { backend, served, reports, .. } = self;
            let Some(root) = served.get_mut(key) else { return };
            // Not before the root has been completely shown on this connection (a loaded record
            // of what was shown does not stand for that while the walk is still due), and not
            // while the host is changing marks itself: a folder's pin passes through marks nobody
            // chose, and the pass would read them.
            if root.pins_reconciled
                || !root.shown_durable
                || root.needs_walk
                || (root.pin_pass.is_some()
                    && root.pin_settle_until.is_some_and(|until| now < until))
            {
                return;
            }
            if root.pin_pass.is_none() {
                let baseline = backend.load_pins(&root.root_id);
                let mut items: Vec<(Vec<u8>, PathBuf)> =
                    root.shown.iter().map(|(id, item)| (id.clone(), item.path.clone())).collect();
                items.push((Vec::new(), root.path.clone()));
                root.pin_pass = Some(PinPass {
                    items,
                    next: 0,
                    baseline,
                    marks: HashMap::new(),
                    reported: HashSet::new(),
                    touched: HashSet::new(),
                });
            }
            let Some(pass) = root.pin_pass.as_mut() else { return };
            let end = (pass.next + PIN_PASS_SLICE).min(pass.items.len());
            for (id, path) in &pass.items[pass.next..end] {
                if pass.touched.contains(path) {
                    continue;
                }
                // A mark that cannot be read is neither remembered nor reported.
                let Some(mark) = backend.pin_mark(path) else { continue };
                if mark != PinWish::Clear {
                    pass.marks.insert(path.clone(), mark);
                }
                if let Some(baseline) = &pass.baseline {
                    let previous = baseline.get(id).copied().unwrap_or(PinWish::Clear);
                    if mark != previous {
                        reports.pin_observed(&root.root_id, id, mark);
                        pass.reported.insert(id.clone());
                    }
                }
            }
            pass.next = end;
            end >= pass.items.len()
        };
        if !finished {
            return;
        }
        let Self { served, .. } = self;
        let Some(root) = served.get_mut(key) else { return };
        let Some(pass) = root.pin_pass.take() else { return };
        let ids: HashMap<&PathBuf, &Vec<u8>> =
            pass.items.iter().map(|(id, path)| (path, id)).collect();
        let mut marks = pass.marks.clone();
        // What the host set itself while the pass ran is what it is now, not what the pass saw.
        for path in &pass.touched {
            match root.pin_marks.get(path) {
                Some(mark) => marks.insert(path.clone(), *mark),
                None => marks.remove(path),
            };
        }
        let recorded: HashMap<Vec<u8>, PinWish> = marks
            .iter()
            .filter_map(|(path, mark)| Some((ids.get(path)?.to_vec(), *mark)))
            .collect();
        let changed = pass.baseline.as_ref().is_none_or(|baseline| &recorded != baseline);
        root.unconfirmed = pass
            .reported
            .iter()
            .map(|id| {
                let old = pass.baseline.as_ref().and_then(|b| b.get(id)).copied();
                (id.clone(), old.unwrap_or(PinWish::Clear))
            })
            .collect();
        root.pin_marks = marks;
        root.recorded = recorded;
        if root.pin_marks.len() > MAX_REMEMBERED_PIN_MARKS
            || root.recorded.len() > MAX_REMEMBERED_PIN_MARKS
        {
            root.pin_marks.clear();
            root.recorded.clear();
            root.pin_marks_overflowed = true;
        }
        root.pins_reconciled = true;
        if changed || root.pin_marks_overflowed {
            root.pin_marks_unsaved = true;
            // Recorded once the daemon has had the reports (and the host's own pins have settled).
            root.pin_settle_until = Some(Instant::now() + PIN_SETTLE);
        }
        let root_id = root.root_id.clone();
        let reported = pass.reported;
        let plan: Vec<(Vec<u8>, PinWish)> = std::mem::take(&mut root.held_plan)
            .into_iter()
            .filter(|(item, _)| !reported.contains(item))
            .collect();
        if !plan.is_empty() {
            self.on_pin_plan(&root_id, &plan);
        }
    }

    /// Records the remembered pin marks of root `key` when they changed and the host is not in the
    /// middle of changing marks itself (the marks a recursive pin passes through are not worth a
    /// record). A record that is out of date is harmless: the pass reports a difference, and where
    /// the host set the mark it equals the daemon's rule, so nothing changes. A write that fails is
    /// tried again after [`PIN_SAVE_RETRY`], not at every turn.
    fn flush_pin_marks(&mut self, key: &str, now: Instant) {
        let Self { backend, served, .. } = self;
        let Some(root) = served.get_mut(key) else { return };
        if !root.pin_marks_unsaved
            || !root.pins_reconciled
            || !root.shown_durable
            || root.pin_settle_until.is_some_and(|until| now < until)
            || root.pin_save_after.is_some_and(|after| now < after)
        {
            return;
        }
        let saved = if root.pin_marks_overflowed {
            // More marks than are remembered: the record can no longer be kept complete, so it says
            // so (once) instead of staying behind as a baseline that has gone stale.
            if root.pin_untrusted_written {
                root.pin_marks_unsaved = false;
                return;
            }
            let saved = backend.save_pins(&root.root_id, None);
            root.pin_untrusted_written |= saved;
            saved
        } else {
            // The items still shown, and the sync root; an item the daemon has not yet agreed with
            // keeps the mark the previous record had for it.
            let mut record: HashMap<Vec<u8>, PinWish> = HashMap::new();
            for id in root.shown.keys().chain(std::iter::once(&Vec::new())) {
                let wish = match root.unconfirmed.get(id) {
                    Some(old) => *old,
                    None => root.recorded.get(id).copied().unwrap_or(PinWish::Clear),
                };
                if wish != PinWish::Clear {
                    record.insert(id.clone(), wish);
                }
            }
            backend.save_pins(&root.root_id, Some(&record))
        };
        if saved {
            root.pin_marks_unsaved = false;
            root.pin_save_after = None;
        } else {
            root.pin_save_after = Some(now + PIN_SAVE_RETRY);
        }
    }

    fn author_local(&mut self, key: &str, everything: bool) {
        // Nothing is authored for a root the operating system no longer has registered: its
        // placeholders went with the registration, and every one of them would read as deleted.
        if !self.registration_holds(key) {
            return;
        }
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
        // The shown items change only when something was applied (or a new showing is due).
        if report.applied > 0 || report.rewalk {
            root.path_index = None;
        }
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

    /// Whether the operating system still has root `key` registered as this host registered it. A
    /// registration that is gone stops the root from being served at once (nothing is authored from
    /// the folder, its pending signals are dropped with it) and is reported as an absent domain;
    /// the next poll serves it again from the daemon's namespace. One that cannot be read leaves the
    /// root as it is and authors nothing now.
    fn registration_holds(&mut self, key: &str) -> bool {
        let Some(served) = self.served.get(key) else { return false };
        match self.backend.root_registration(&served.root_id, &served.path) {
            Registration::Ours => true,
            Registration::Unknown => false,
            Registration::Lost => {
                eprintln!(
                    "yadorilink-cfapi-host: the registration of {} is gone; nothing is authored for it",
                    served.path.display()
                );
                let root_id = served.root_id.clone();
                self.served.remove(key);
                self.reports.domain_state(&root_id, DomainEvidence::Absent, "");
                false
            }
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
            // The daemon dropped what it knew of the previous connection, the pin reports among
            // it: the marks are compared with the record again once the root is shown.
            served.reporter = None;
            served.pins_reconciled = false;
            served.pin_pass = None;
            served.held_plan.clear();
            served.unconfirmed.clear();
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

    /// Applies the person's choice for `item` (empty: the folder itself) in the operating system and
    /// reports what happened. An item the host does not show is [`PinResult::NotFound`] and nothing
    /// is touched; a namespace that could not be confirmed is an error, never "not found".
    pub fn on_pin(&mut self, root: &[u8], item: &[u8], request_id: &[u8], wish: PinWish) {
        let (result, error) = self.apply_pin(root, item, wish);
        self.reports.pin_done(root, request_id, result, &error);
        // The pin may have changed what is on this PC: the materialized set follows.
        self.report_materialized(&hex(root), true);
    }

    /// Makes the operating system agree with the pins the daemon's rules ask for in `root`. Not
    /// acknowledged: an entry that is already as asked changes nothing, an item that is not shown
    /// (yet) is skipped, and the daemon sends the plan again, so what could not be done now is done
    /// at the next one. A failure is logged and does not stop the other entries.
    pub fn on_pin_plan(&mut self, root: &[u8], entries: &[(Vec<u8>, PinWish)]) {
        // Before the pass over the root's pins (see `reconcile_pins`) a plan would put the rules'
        // pins over whatever the person did while the host was not running: it waits. A plan comes
        // in messages of a bounded size, so what waits is their union, a newer entry for an item
        // replacing the older one in place (the order of a plan, ancestors first, is kept).
        if let Some(served) = self.served.get_mut(&hex(root)) {
            if !served.pins_reconciled {
                for (item, wish) in entries {
                    match served.held_plan.iter_mut().find(|(held, _)| held == item) {
                        Some(entry) => entry.1 = *wish,
                        None => served.held_plan.push((item.clone(), *wish)),
                    }
                }
                return;
            }
        }
        for (item, wish) in entries {
            let (result, error) = self.apply_pin(root, item, *wish);
            if result == PinResult::Error {
                eprintln!("yadorilink-cfapi-host: a pin from the daemon's plan failed: {error}");
            }
        }
        // A plan that asks for the mark an item carries is the daemon having acted on the report
        // about it: the record may say so from now on.
        if let Some(served) = self.served.get_mut(&hex(root)) {
            for (item, wish) in entries {
                let current = served.recorded.get(item).copied().unwrap_or(PinWish::Clear);
                if current == *wish && served.unconfirmed.remove(item).is_some() {
                    served.pin_marks_unsaved = true;
                }
            }
        }
    }

    /// After the host set the pin of `path` (whose mark was `before`): remember the mark it carries
    /// now, and if it changed, open the settle window so the signals of the change, and of the
    /// children a folder's pin passes through, are not reported as the person's.
    fn note_own_pin(&mut self, key: &str, path: &Path, item: &[u8], before: Option<PinWish>) {
        let after = self.backend.pin_mark(path);
        let Some(root) = self.served.get_mut(key) else { return };
        match after {
            Some(PinWish::Clear) | None => {
                root.pin_marks.remove(path);
                root.recorded.remove(item);
            }
            Some(mark) => {
                root.pin_marks.insert(path.to_path_buf(), mark);
                root.recorded.insert(item.to_vec(), mark);
            }
        }
        if let Some(pass) = root.pin_pass.as_mut() {
            pass.touched.insert(path.to_path_buf());
        }
        root.pin_marks_unsaved = true;
        if after != before {
            root.pin_settle_until = Some(Instant::now() + PIN_SETTLE);
        }
    }

    /// Resolves `item` in `root` and applies `wish` to it; what happened, as the wire says it.
    fn apply_pin(&mut self, root: &[u8], item: &[u8], wish: PinWish) -> (PinResult, String) {
        let key = hex(root);
        let Some(root_path) = self.served.get(&key).map(|s| s.path.clone()) else {
            return (PinResult::NotFound, String::new());
        };
        let mut confirmed = true;
        let path = if item.is_empty() {
            Some(root_path)
        } else {
            if !self.served.get(&key).is_some_and(|s| s.shown.contains_key(item)) {
                confirmed = self.walk(&key);
            }
            self.served.get(&key).and_then(|s| s.shown.get(item)).map(|s| s.path.clone())
        };
        match path {
            None if !confirmed => (
                PinResult::Error,
                "the namespace could not be confirmed, so the item could not be located"
                    .to_string(),
            ),
            None => (PinResult::NotFound, String::new()),
            Some(path) => {
                let item_id = item;
                let item = (!item.is_empty()).then_some(item);
                let before = self.backend.pin_mark(&path);
                let outcome = self.backend.pin(&path, item, wish);
                self.note_own_pin(&key, &path, item_id, before);
                match outcome {
                    PinOutcome::Done => (PinResult::Done, String::new()),
                    PinOutcome::Downloading => (PinResult::Downloading, String::new()),
                    PinOutcome::Unsupported => (PinResult::Unsupported, String::new()),
                    PinOutcome::Error(e) => (PinResult::Error, e),
                }
            }
        }
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
        /// How many items each look at the materialized set was given.
        materialized_looks: Vec<usize>,
        /// How many items the fake namespace shows (0: the single served item).
        item_count: usize,
        /// An item the next authoring adds to the shown ones.
        author_adds: Option<(Vec<u8>, ShownItem)>,
        /// An item the next authoring takes out of the shown ones (the user deleted the file).
        author_removes: Option<Vec<u8>>,
        /// Authoring applies nothing but what `author_adds` says (an attribute touched by the
        /// system, a finished download), instead of counting every signal as applied.
        quiet_author: bool,
        reports: Vec<ProviderMaterializedReport>,
        evict_result: Option<EvictOutcome>,
        pin_outcome: Option<PinOutcome>,
        pins: Vec<(PathBuf, Option<Vec<u8>>, PinWish)>,
        /// The pin mark each path carries in the fake file system, and what was reported as observed.
        marks: HashMap<PathBuf, PinWish>,
        observed: Vec<(Vec<u8>, PinWish)>,
        pin_results: Vec<(Vec<u8>, i32, String)>,
        authored: Vec<BTreeSet<PathBuf>>,
        rewalk_next: bool,
        loaded: Option<ShownItems>,
        load_invalid: Option<String>,
        order: Vec<&'static str>,
        root_missing: bool,
        saved: Vec<ShownItems>,
        /// What the operating system says about the registration of the root (`None`: it is ours).
        registration: Option<Registration>,
        /// The roots whose recorded state was forgotten.
        forgotten: Vec<Vec<u8>>,
        /// Authoring finds the registration gone when it runs.
        lose_registration_in_author: bool,
        namespace_refused: bool,
        volume_unidentified: bool,
        /// The pin record the fake keeps between runs, and how many times it was written.
        pin_record: Option<HashMap<Vec<u8>, PinWish>>,
        pin_saves: usize,
        pin_untrusted_saves: usize,
        fail_save_pins: bool,
        pin_save_attempts: usize,
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
            // Registering puts the root back under this host's identity.
            recorded.registration = None;
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
            if recorded.item_count > 0 {
                return Some(
                    (0..recorded.item_count)
                        .map(|n| {
                            let mut id = vec![0u8; 16];
                            id[..8].copy_from_slice(&(n as u64 + 1).to_le_bytes());
                            let name = format!("f{n}.txt");
                            (
                                id,
                                ShownItem {
                                    path: path.join(&name),
                                    parent_item_id: vec![],
                                    name,
                                    directory: false,
                                    size: 1,
                                    mtime_unix_nanos: 0,
                                    content_version: vec![0; 40],
                                    parent_generation: 0,
                                },
                            )
                        })
                        .collect(),
                );
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
        fn pin(&mut self, path: &Path, item: Option<&[u8]>, wish: PinWish) -> PinOutcome {
            let mut recorded = self.0.borrow_mut();
            recorded.pins.push((path.to_path_buf(), item.map(<[u8]>::to_vec), wish));
            // The fake file system carries the mark the host set.
            recorded.marks.insert(path.to_path_buf(), wish);
            recorded.pin_outcome.take().unwrap_or(PinOutcome::Done)
        }
        fn pin_mark(&mut self, path: &Path) -> Option<PinWish> {
            Some(self.0.borrow().marks.get(path).copied().unwrap_or(PinWish::Clear))
        }
        fn materialized(&mut self, shown: &ShownItems) -> HashSet<Vec<u8>> {
            let mut recorded = self.0.borrow_mut();
            recorded.materialized_looks.push(shown.len());
            if recorded.item_count == 0 {
                return recorded.materialized.clone();
            }
            // With many files shown the fake answers for the files it was asked about only.
            recorded.materialized.iter().filter(|id| shown.contains_key(*id)).cloned().collect()
        }
        fn load_pins(&mut self, _root_id: &[u8]) -> Option<HashMap<Vec<u8>, PinWish>> {
            self.0.borrow().pin_record.clone()
        }
        fn save_pins(
            &mut self,
            _root_id: &[u8],
            marks: Option<&HashMap<Vec<u8>, PinWish>>,
        ) -> bool {
            let mut recorded = self.0.borrow_mut();
            recorded.pin_save_attempts += 1;
            if recorded.fail_save_pins {
                return false;
            }
            match marks {
                Some(marks) => {
                    recorded.pin_record = Some(marks.clone());
                    recorded.pin_saves += 1;
                }
                None => {
                    recorded.pin_record = None;
                    recorded.pin_untrusted_saves += 1;
                }
            }
            true
        }
        fn root_registration(&mut self, _root_id: &[u8], _path: &Path) -> Registration {
            self.0.borrow().registration.unwrap_or(Registration::Ours)
        }
        fn forget_root_state(&mut self, root_id: &[u8]) -> bool {
            let mut recorded = self.0.borrow_mut();
            recorded.forgotten.push(root_id.to_vec());
            recorded.loaded = None;
            true
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
            shown: &mut ShownItems,
        ) -> provider_authoring::Report {
            let mut recorded = self.0.borrow_mut();
            // The registration goes while the pass runs (a test sets it).
            if recorded.lose_registration_in_author {
                recorded.registration = Some(Registration::Lost);
            }
            // An item the user's new file became (a test sets it).
            let added = recorded.author_adds.take();
            let removed = recorded.author_removes.take();
            let applied = if recorded.quiet_author {
                usize::from(added.is_some() || removed.is_some())
            } else {
                signals.len()
            };
            if let Some(id) = removed {
                shown.remove(&id);
            }
            if let Some((id, item)) = added {
                shown.insert(id, item);
            }
            recorded.authored.push(signals.clone());
            recorded.order.push("author");
            provider_authoring::Report {
                applied,
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
        fn pin_done(&self, root: &[u8], _id: &[u8], result: PinResult, error: &str) {
            self.0.borrow_mut().pin_results.push((root.to_vec(), result as i32, error.to_string()));
        }
        fn pin_observed(&self, root: &[u8], item: &[u8], wish: PinWish) {
            let _ = root;
            self.0.borrow_mut().observed.push((item.to_vec(), wish));
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
    fn a_pin_request_is_applied_to_the_item_or_the_folder_and_answered_with_what_happened() {
        let dir = temp_dir("pin");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));

        // A shown item: pinned for a keep, cleared for a release.
        host.on_pin(&[1; 16], &[9; 16], &[1], PinWish::Keep);
        host.on_pin(&[1; 16], &[9; 16], &[2], PinWish::OnlineOnly);
        host.on_pin(&[1; 16], &[9; 16], &[9], PinWish::Clear);
        // The folder itself (no item): the root path is what is pinned.
        host.on_pin(&[1; 16], &[], &[3], PinWish::Keep);
        // An item that is not shown: nothing is touched.
        host.on_pin(&[1; 16], &[8; 16], &[4], PinWish::Keep);
        // The operating system fetching the content, and a failure, are reported as they are.
        fake.0.borrow_mut().pin_outcome = Some(PinOutcome::Downloading);
        host.on_pin(&[1; 16], &[9; 16], &[5], PinWish::Keep);
        fake.0.borrow_mut().pin_outcome = Some(PinOutcome::Error("no".into()));
        host.on_pin(&[1; 16], &[9; 16], &[6], PinWish::Keep);
        // A namespace that cannot be confirmed is an error, not "not found".
        fake.0.borrow_mut().fail_walk = true;
        host.on_pin(&[1; 16], &[7; 16], &[7], PinWish::Keep);
        // A root the host does not serve.
        host.on_pin(&[2; 16], &[9; 16], &[8], PinWish::Keep);

        let recorded = fake.0.borrow();
        let results: Vec<i32> = recorded.pin_results.iter().map(|r| r.1).collect();
        assert_eq!(
            results,
            vec![
                PinResult::Done as i32,        // keep the item
                PinResult::Done as i32,        // online only
                PinResult::Done as i32,        // clear
                PinResult::Done as i32,        // the folder itself
                PinResult::NotFound as i32,    // not shown
                PinResult::Downloading as i32, // the OS is fetching
                PinResult::Error as i32,       // the OS refused
                PinResult::Error as i32,       // namespace not confirmed
                PinResult::NotFound as i32,    // a root the host does not serve
            ]
        );
        assert_eq!(recorded.pin_results[6].2, "no");
        // What reached the operating system: the shown item with its identity for each wish, then
        // the folder with no item (the sync root itself), and the rest the same item again. An item
        // that is not shown, a root that is not served and an unconfirmed namespace reach nothing.
        let applied: Vec<(Option<Vec<u8>>, PinWish)> =
            recorded.pins.iter().map(|p| (p.1.clone(), p.2)).collect();
        let item = Some(vec![9u8; 16]);
        assert_eq!(
            applied,
            vec![
                (item.clone(), PinWish::Keep),
                (item.clone(), PinWish::OnlineOnly),
                (item.clone(), PinWish::Clear),
                (None, PinWish::Keep),
                (item.clone(), PinWish::Keep),
                (item, PinWish::Keep),
            ]
        );
        assert_ne!(recorded.pins[3].0, recorded.pins[0].0, "the folder and the item are one path");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The path at which the fake namespace shows its item; the marks are set there.
    fn item_path(host: &Host<Fake, Fake>) -> PathBuf {
        host.served.values().next().unwrap().shown.get(&vec![9u8; 16]).unwrap().path.clone()
    }

    #[test]
    fn a_pin_mark_the_person_changes_is_reported_once_and_the_settle_window_defers_instead_of_dropping(
    ) {
        let dir = temp_dir("observe");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::Keep)]); // shows the namespace; Keep set
        let path = item_path(&host);
        let key = hex(&[1; 16]);
        let signal = |host: &mut Host<Fake, Fake>, mark: PinWish, at: Instant| {
            fake.0.borrow_mut().marks.insert(path.clone(), mark);
            host.served.get_mut(&key).unwrap().pending.insert(path.clone());
            host.observe_pins(&key, at);
            host.served.get_mut(&key).unwrap().pending.clear();
        };
        let now = Instant::now();
        let after_settle = now + PIN_SETTLE + Duration::from_secs(1);
        fake.0.borrow_mut().observed.clear();

        // The host set Keep itself and a recursive pin passes through marks nobody chose: inside the
        // settle window nothing is read or reported, the path just waits.
        signal(&mut host, PinWish::OnlineOnly, now);
        assert!(
            fake.0.borrow().observed.is_empty(),
            "a mark inside the settle window was reported"
        );
        // A transient mark that was put right again by the time the window closes is not the
        // person's: judged by what it carries then, it equals what the host applied.
        fake.0.borrow_mut().marks.insert(path.clone(), PinWish::Keep);
        host.observe_pins(&key, after_settle);
        assert!(fake.0.borrow().observed.is_empty(), "a restored transient mark was reported");

        // A change the person makes inside the window is not lost: it is still different when the
        // window closes, and is reported then.
        host.served.get_mut(&key).unwrap().pin_settle_until = Some(now + PIN_SETTLE);
        signal(&mut host, PinWish::OnlineOnly, now);
        assert!(fake.0.borrow().observed.is_empty());
        host.observe_pins(&key, after_settle);
        assert_eq!(fake.0.borrow().observed, vec![(vec![9u8; 16], PinWish::OnlineOnly)]);
        // The same signal again (a second attribute event for one change): nothing more.
        signal(&mut host, PinWish::OnlineOnly, after_settle);
        assert_eq!(fake.0.borrow().observed.len(), 1);

        // Clearing is a change too, and a change back is reported again.
        signal(&mut host, PinWish::Clear, after_settle);
        signal(&mut host, PinWish::Keep, after_settle);
        assert_eq!(
            fake.0.borrow().observed,
            vec![
                (vec![9u8; 16], PinWish::OnlineOnly),
                (vec![9u8; 16], PinWish::Clear),
                (vec![9u8; 16], PinWish::Keep),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    const AFTER_SETTLE: Duration = Duration::from_secs(PIN_SETTLE.as_secs() + 1);

    /// Serves a root once, lets that run record its pin marks, and stops that host: the next one
    /// starts the way a restart does, over the same file system and records. Returns the path of
    /// the item the root serves.
    fn path_of_item_after_a_run(fake: &Fake, dir: &Path) -> PathBuf {
        let mut first = host(fake, dir);
        first.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let path = item_path(&first);
        first.apply_due_local(Instant::now() + AFTER_SETTLE);
        assert!(fake.0.borrow().pin_record.is_some(), "the first run left no record");
        fake.0.borrow_mut().observed.clear();
        path
    }

    fn start(fake: &Fake, dir: &Path) -> Host<Fake, Fake> {
        let mut host = host(fake, dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host
    }

    #[test]
    fn a_pin_the_person_set_while_the_host_was_down_is_reported_once_when_the_root_is_shown() {
        let dir = temp_dir("attach-pass");
        let fake = Fake::default();
        let path = path_of_item_after_a_run(&fake, &dir);

        // The host is not running; the person pins the item. No event for that can be read later.
        fake.0.borrow_mut().marks.insert(path.clone(), PinWish::Keep);
        let mut second = start(&fake, &dir);
        assert_eq!(fake.0.borrow().observed, vec![(vec![9u8; 16], PinWish::Keep)]);

        // Not recorded as the baseline until the daemon is seen to agree: a report that was lost, or
        // not yet processed, is then made again. The settle window passing is not that.
        second.apply_due_local(Instant::now() + AFTER_SETTLE);
        assert_eq!(fake.0.borrow().pin_record.as_ref().unwrap().get(&vec![9u8; 16]), None);
        // The daemon took the pin as a rule and its plan says so.
        second.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::Keep)]);
        second.apply_due_local(Instant::now() + 2 * AFTER_SETTLE);
        assert_eq!(
            fake.0.borrow().pin_record.as_ref().unwrap().get(&vec![9u8; 16]),
            Some(&PinWish::Keep)
        );
        fake.0.borrow_mut().observed.clear();
        let _third = start(&fake, &dir);
        assert!(fake.0.borrow().observed.is_empty(), "an unchanged mark was reported again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_report_the_daemon_may_not_have_acted_on_is_made_again_on_the_next_connection_or_run() {
        let dir = temp_dir("attach-pass-lost");
        let fake = Fake::default();
        let path = path_of_item_after_a_run(&fake, &dir);
        fake.0.borrow_mut().marks.insert(path, PinWish::Keep);
        let mut second = start(&fake, &dir);
        assert_eq!(fake.0.borrow().observed.len(), 1);

        // The connection is lost before the settle window closed: the record is still the old one.
        second.on_connected();
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(
            fake.0.borrow().observed.len(),
            2,
            "a report lost with the connection was not repeated"
        );

        // Likewise a host that stopped before it recorded.
        let _third = start(&fake, &dir);
        assert_eq!(fake.0.borrow().observed.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unpin_made_while_the_host_was_down_is_reported_too() {
        let dir = temp_dir("attach-pass-clear");
        let fake = Fake::default();
        let _ = path_of_item_after_a_run(&fake, &dir);
        // The host had recorded Keep for the item (a rule's pin); the person cleared it meanwhile.
        fake.0.borrow_mut().pin_record.as_mut().unwrap().insert(vec![9u8; 16], PinWish::Keep);
        let mut second = start(&fake, &dir);
        assert_eq!(fake.0.borrow().observed, vec![(vec![9u8; 16], PinWish::Clear)]);
        // No plan can say "no rule" for the item, so the record keeps what it had and the unpin is
        // reported again next time (the daemon finds no rule to clear, and does nothing).
        second.apply_due_local(Instant::now() + AFTER_SETTLE);
        assert_eq!(
            fake.0.borrow().pin_record.as_ref().unwrap().get(&vec![9u8; 16]),
            Some(&PinWish::Keep)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mark_the_host_recorded_is_not_taken_for_the_persons_after_a_restart() {
        let dir = temp_dir("attach-pass-own");
        let fake = Fake::default();
        let path = path_of_item_after_a_run(&fake, &dir);
        fake.0.borrow_mut().marks.insert(path, PinWish::OnlineOnly);
        fake.0.borrow_mut().pin_record.as_mut().unwrap().insert(vec![9u8; 16], PinWish::OnlineOnly);
        let _second = start(&fake, &dir);
        assert!(fake.0.borrow().observed.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_a_record_that_can_be_trusted_the_marks_are_recorded_and_nothing_is_reported() {
        let dir = temp_dir("attach-pass-adopt");
        let fake = Fake::default();
        // The first run leaves its record unwritten (it stopped inside the settle window).
        let mut first = start(&fake, &dir);
        let path = item_path(&first);
        drop(first.served.drain().next());
        assert!(fake.0.borrow().pin_record.is_none());
        // The app changed a rule while the host was down, so the file system still carries the
        // old pin: without a baseline this cannot be told from the person's own pin, and reporting
        // it would turn the rule back.
        fake.0.borrow_mut().marks.insert(path, PinWish::Keep);
        let mut second = start(&fake, &dir);
        assert!(fake.0.borrow().observed.is_empty(), "an untrusted baseline reported a mark");
        second.apply_due_local(Instant::now() + AFTER_SETTLE);
        assert_eq!(
            fake.0.borrow().pin_record.as_ref().unwrap().get(&vec![9u8; 16]),
            Some(&PinWish::Keep),
            "the marks seen were not recorded as the baseline"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_sync_roots_own_pin_changed_while_the_host_was_down_is_reported_and_its_rule_waits() {
        let dir = temp_dir("attach-pass-root");
        let fake = Fake::default();
        let _ = path_of_item_after_a_run(&fake, &dir);
        let root_path = {
            let first = start(&fake, &dir);
            first.served.values().next().unwrap().path.clone()
        };
        fake.0.borrow_mut().observed.clear();
        fake.0.borrow_mut().pins.clear();
        fake.0.borrow_mut().marks.insert(root_path, PinWish::Keep); // the person pinned the folder

        // The root's rule (empty item id) arrives before the pass.
        fake.0.borrow_mut().fail_walk = true;
        let mut second = host(&fake, &dir);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        fake.0.borrow_mut().fail_walk = false;
        second.on_pin_plan(&[1; 16], &[(vec![], PinWish::OnlineOnly)]);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(fake.0.borrow().observed, vec![(vec![], PinWish::Keep)]);
        assert!(fake.0.borrow().pins.is_empty(), "the held root rule overwrote the person's pin");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_pin_plan_that_arrives_before_the_pass_waits_and_skips_what_the_pass_reported() {
        let dir = temp_dir("attach-pass-plan");
        let fake = Fake::default();
        let path = path_of_item_after_a_run(&fake, &dir);
        fake.0.borrow_mut().marks.insert(path.clone(), PinWish::Keep); // the person's pin
        fake.0.borrow_mut().pins.clear();

        // The root is served but its first showing failed, so the pass has not been made. The
        // namespace could be shown by the time the daemon's plan (a rule says online only)
        // arrives, which is how applying it would walk the root and put the rule's pin over the
        // person's: it must wait for the pass instead.
        fake.0.borrow_mut().fail_walk = true;
        let mut second = host(&fake, &dir);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        fake.0.borrow_mut().fail_walk = false;
        second.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::OnlineOnly)]);
        assert!(fake.0.borrow().pins.is_empty(), "a plan was applied before the pass");

        // Shown now: the person's change is reported and the held plan skips that item.
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(fake.0.borrow().observed, vec![(vec![9u8; 16], PinWish::Keep)]);
        assert!(fake.0.borrow().pins.is_empty(), "the held plan overwrote the person's pin");
        assert_eq!(fake.0.borrow().marks.get(&path), Some(&PinWish::Keep));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_showing_that_fails_first_still_reaches_the_pass_and_releases_the_held_plan() {
        let dir = temp_dir("attach-pass-late");
        let fake = Fake::default();
        let _ = path_of_item_after_a_run(&fake, &dir);
        fake.0.borrow_mut().pins.clear();
        fake.0.borrow_mut().fail_walk = true;
        let mut second = host(&fake, &dir);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        // Judging a recorded namespace had already counted as the root's first signal.
        second.served.values_mut().next().unwrap().last_signal = Some(Instant::now());
        fake.0.borrow_mut().fail_walk = false;
        second.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::Keep)]);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(second.served.values().next().unwrap().pins_reconciled);
        assert_eq!(fake.0.borrow().pins.len(), 1, "the held plan was never released");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_plan_sent_in_several_messages_is_held_whole_and_a_newer_entry_replaces_an_older_one() {
        let dir = temp_dir("attach-pass-chunks");
        let fake = Fake::default();
        let _ = path_of_item_after_a_run(&fake, &dir);
        fake.0.borrow_mut().pins.clear();
        fake.0.borrow_mut().fail_walk = true;
        let mut second = host(&fake, &dir);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        fake.0.borrow_mut().fail_walk = false;
        second.on_pin_plan(&[1; 16], &[(vec![], PinWish::Keep)]);
        second.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::Keep)]);
        second.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::OnlineOnly)]);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let applied: Vec<(Option<Vec<u8>>, PinWish)> =
            fake.0.borrow().pins.iter().map(|(_, item, wish)| (item.clone(), *wish)).collect();
        assert_eq!(applied.len(), 2, "an earlier message of the plan was lost: {applied:?}");
        assert_eq!(applied[1], (Some(vec![9u8; 16]), PinWish::OnlineOnly));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_held_plan_is_applied_for_the_items_the_person_did_not_change() {
        let dir = temp_dir("attach-pass-plan-applied");
        let fake = Fake::default();
        let _ = path_of_item_after_a_run(&fake, &dir);
        fake.0.borrow_mut().fail_walk = true;
        let mut second = host(&fake, &dir);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        second.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::OnlineOnly)]);
        fake.0.borrow_mut().fail_walk = false;
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let recorded = fake.0.borrow();
        assert!(recorded.observed.is_empty());
        assert_eq!(recorded.pins.len(), 1, "the held plan is applied once");
        assert_eq!(recorded.pins[0].2, PinWish::OnlineOnly);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_large_root_is_read_in_slices_and_the_host_answers_requests_between_them() {
        let dir = temp_dir("attach-pass-slices");
        let fake = Fake::default();
        fake.0.borrow_mut().item_count = 2 * PIN_PASS_SLICE + 5;
        let mut first = start(&fake, &dir);
        // Settle the first run's pass completely so a record exists.
        for _ in 0..4 {
            first.apply_due_local(Instant::now());
        }
        first.apply_due_local(Instant::now() + AFTER_SETTLE);
        assert!(fake.0.borrow().pin_record.is_some());
        let some_item = first.served.values().next().unwrap().shown.iter().nth(3).unwrap();
        let (some_id, some_path) = (some_item.0.clone(), some_item.1.path.clone());
        drop(first);
        fake.0.borrow_mut().marks.insert(some_path, PinWish::Keep);
        fake.0.borrow_mut().observed.clear();

        let mut second = start(&fake, &dir);
        let key = hex(&[1; 16]);
        {
            let served = second.served.get(&key).unwrap();
            assert!(served.pin_pass.is_some(), "the whole root was read in one turn");
            assert!(!served.pins_reconciled);
        }
        // The next slice is due at once, not at the next poll.
        assert!(
            second.next_deadline(Instant::now(), Duration::from_secs(60))
                <= Duration::from_millis(10)
        );
        // A person's request arriving between the slices is answered now.
        second.on_pin(&[1; 16], &some_id, b"req", PinWish::OnlineOnly);
        assert_eq!(fake.0.borrow().pin_results.len(), 1, "a request waited for the pass");
        // The pass waits out the settle window of the host's own pin (a folder's pin passes
        // through marks nobody chose), then goes on in slices.
        let read_so_far = |host: &Host<Fake, Fake>| {
            host.served.get(&key).unwrap().pin_pass.as_ref().unwrap().next
        };
        let before = read_so_far(&second);
        second.apply_due_local(Instant::now());
        assert_eq!(read_so_far(&second), before, "the pass read marks while the host was pinning");
        assert!(
            second.next_deadline(Instant::now(), Duration::from_secs(60))
                > Duration::from_millis(100),
            "the host keeps waking for a pass that is waiting"
        );
        let mut at = Instant::now() + AFTER_SETTLE;
        for _ in 0..4 {
            second.apply_due_local(at);
            at += Duration::from_millis(1);
        }
        assert!(second.served.get(&key).unwrap().pins_reconciled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn after_the_watcher_lost_changes_every_shown_item_is_read_not_only_the_known_marked_ones() {
        let dir = temp_dir("rescan-all");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let path = item_path(&host);
        let key = hex(&[1; 16]);
        fake.0.borrow_mut().observed.clear();
        // The memory of marks is empty (dropped past its bound, or never filled) and the person
        // pinned the item while events were being lost.
        fake.0.borrow_mut().marks.insert(path, PinWish::Keep);
        host.served.get_mut(&key).unwrap().pin_marks.clear();
        host.served.get_mut(&key).unwrap().rescan = true;
        host.observe_pins(&key, Instant::now() + AFTER_SETTLE);
        assert_eq!(fake.0.borrow().observed, vec![(vec![9u8; 16], PinWish::Keep)]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remembered_marks_are_recorded_once_the_hosts_own_pin_has_settled_not_before() {
        let dir = temp_dir("flush");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.apply_due_local(Instant::now() + AFTER_SETTLE);
        let key = hex(&[1; 16]);
        let saves = fake.0.borrow().pin_saves;
        host.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::Keep)]);
        assert_eq!(
            fake.0.borrow().pin_saves,
            saves,
            "recorded in the middle of the host's own pin"
        );
        assert!(host.next_deadline(Instant::now(), Duration::from_secs(60)) <= PIN_SETTLE);
        host.apply_due_local(Instant::now() + AFTER_SETTLE);
        assert_eq!(fake.0.borrow().pin_saves, saves + 1);
        assert_eq!(
            fake.0.borrow().pin_record.as_ref().unwrap().get(&vec![9u8; 16]),
            Some(&PinWish::Keep)
        );
        // Nothing to record: no wake and no write.
        host.apply_due_local(Instant::now() + 2 * AFTER_SETTLE);
        assert_eq!(fake.0.borrow().pin_saves, saves + 1);
        assert!(!host.served.get(&key).unwrap().pin_marks_unsaved);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_record_write_is_tried_again_later_not_at_every_turn() {
        let dir = temp_dir("flush-fails");
        let fake = Fake::default();
        fake.0.borrow_mut().fail_save_pins = true;
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let at = Instant::now() + AFTER_SETTLE;
        host.apply_due_local(at);
        assert_eq!(fake.0.borrow().pin_save_attempts, 1);
        host.apply_due_local(at + Duration::from_secs(1));
        host.apply_due_local(at + Duration::from_secs(2));
        assert_eq!(fake.0.borrow().pin_save_attempts, 1, "retried at every turn");
        assert!(
            host.next_deadline(at + Duration::from_secs(2), Duration::from_secs(60))
                > Duration::from_secs(10),
            "the host keeps waking for a write that failed"
        );
        fake.0.borrow_mut().fail_save_pins = false;
        host.apply_due_local(at + PIN_SAVE_RETRY + Duration::from_secs(1));
        assert!(fake.0.borrow().pin_record.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_direct_pin_between_slices_is_neither_reported_nor_lost_from_the_record() {
        let dir = temp_dir("attach-pass-direct");
        let fake = Fake::default();
        fake.0.borrow_mut().item_count = 2 * PIN_PASS_SLICE + 5;
        let mut first = start(&fake, &dir);
        for _ in 0..4 {
            first.apply_due_local(Instant::now());
        }
        first.apply_due_local(Instant::now() + AFTER_SETTLE);
        assert!(fake.0.borrow().pin_record.is_some());
        let ids: Vec<Vec<u8>> =
            first.served.values().next().unwrap().shown.keys().cloned().collect();
        drop(first);
        fake.0.borrow_mut().observed.clear();

        let mut second = start(&fake, &dir);
        let key = hex(&[1; 16]);
        assert!(second.served.get(&key).unwrap().pin_pass.is_some(), "not in slices");
        // The person's app pins two items while the pass is part way: one the pass may already
        // have read, one it has not.
        let (early, late) = (ids[0].clone(), ids[ids.len() - 1].clone());
        second.on_pin(&[1; 16], &early, b"r1", PinWish::Keep);
        second.on_pin(&[1; 16], &late, b"r2", PinWish::Keep);
        // The pass waits out the host's own pin, then finishes.
        let mut at = Instant::now() + AFTER_SETTLE;
        for _ in 0..8 {
            second.apply_due_local(at);
            at += AFTER_SETTLE;
        }
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(second.served.get(&key).unwrap().pins_reconciled);
        assert!(
            fake.0.borrow().observed.iter().all(|(item, _)| item != &early && item != &late),
            "the host's own pin was reported as the person's: {:?}",
            fake.0.borrow().observed
        );
        second.on_pin_plan(&[1; 16], &[]);
        second.apply_due_local(at + AFTER_SETTLE);
        let recorded = fake.0.borrow().pin_record.clone().unwrap();
        assert_eq!(recorded.get(&early), Some(&PinWish::Keep));
        assert_eq!(recorded.get(&late), Some(&PinWish::Keep));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_loaded_record_of_the_shown_items_does_not_stand_for_a_complete_showing() {
        let dir = temp_dir("attach-pass-needs-walk");
        let fake = Fake::default();
        let _ = path_of_item_after_a_run(&fake, &dir);
        // The next run judges the recorded shown items, then its walk fails.
        let saved = fake.0.borrow().saved.last().cloned();
        fake.0.borrow_mut().loaded = saved;
        fake.0.borrow_mut().fail_walk = true;
        let mut second = host(&fake, &dir);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let served = second.served.values().next().unwrap();
        assert!(served.needs_walk, "the walk was supposed to have failed");
        assert!(!served.pins_reconciled, "the pass finished over a namespace not shown yet");
        fake.0.borrow_mut().fail_walk = false;
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(second.served.values().next().unwrap().pins_reconciled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_moved_items_mark_stays_in_the_record_across_an_unrelated_save() {
        let dir = temp_dir("record-rename");
        let fake = Fake::default();
        let path = path_of_item_after_a_run(&fake, &dir);
        // The host pins the item; the record says so.
        let mut host = start(&fake, &dir);
        host.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::Keep)]);
        host.apply_due_local(Instant::now() + AFTER_SETTLE);
        assert_eq!(
            fake.0.borrow().pin_record.as_ref().unwrap().get(&vec![9u8; 16]),
            Some(&PinWish::Keep)
        );
        // The item is moved: shown at another path, whose mark is not known to the host's memory.
        let key = hex(&[1; 16]);
        let moved = path.with_file_name("renamed.txt");
        host.served.get_mut(&key).unwrap().shown.get_mut(&vec![9u8; 16]).unwrap().path = moved;
        host.served.get_mut(&key).unwrap().pin_marks_unsaved = true;
        host.apply_due_local(Instant::now() + 3 * AFTER_SETTLE);
        assert_eq!(
            fake.0.borrow().pin_record.as_ref().unwrap().get(&vec![9u8; 16]),
            Some(&PinWish::Keep),
            "an unrelated save dropped the moved item's mark"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn after_the_watcher_lost_changes_the_sync_roots_own_pin_is_read_too() {
        let dir = temp_dir("rescan-root");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let key = hex(&[1; 16]);
        let root_path = host.served.get(&key).unwrap().path.clone();
        fake.0.borrow_mut().observed.clear();
        fake.0.borrow_mut().marks.insert(root_path, PinWish::Keep);
        host.served.get_mut(&key).unwrap().rescan = true;
        host.observe_pins(&key, Instant::now() + AFTER_SETTLE);
        assert_eq!(fake.0.borrow().observed, vec![(Vec::<u8>::new(), PinWish::Keep)]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_pin_record_is_by_item_and_a_torn_foreign_or_missing_one_is_no_baseline() {
        let dir = temp_dir("pin-record");
        let file = dir.join("pins");
        let marks = HashMap::from([
            (vec![1u8; 16], PinWish::Keep),
            (vec![2u8; 16], PinWish::OnlineOnly),
            (Vec::new(), PinWish::Keep), // the sync root itself
        ]);
        assert_eq!(read_pins_at(&file), None, "no record is no baseline");
        generation::publish_next(&file, &encode_pins_record(&marks)).unwrap();
        assert_eq!(read_pins_at(&file), Some(marks.clone()));
        // A record of nothing marked is a baseline (the pass has been made).
        generation::publish_next(&file, &encode_pins_record(&HashMap::new())).unwrap();
        assert_eq!(read_pins_at(&file), Some(HashMap::new()));

        // The newest generation is complete but not understood: not read as marks.
        generation::publish_next(&file, &seal("not-hex\tk\n")).unwrap();
        assert_eq!(read_pins_at(&file), None);
        generation::publish_next(&file, &seal(&format!("{}\tz\n", hex(b"a")))).unwrap();
        assert_eq!(read_pins_at(&file), None);

        // A newest generation torn by a crash while an older complete one exists: that older record
        // may predate marks the host has acted on since, so it is not trusted either.
        let older = HashMap::from([(vec![7u8; 16], PinWish::Keep)]);
        generation::publish_next(&file, &encode_pins_record(&older)).unwrap();
        generation::publish_next(&file, &encode_pins_record(&marks)).unwrap();
        assert_eq!(read_pins_at(&file), Some(marks));
        let newest = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n.starts_with("pins.") && !n.ends_with(".tmp")
                })
            })
            .max_by_key(|path| {
                path.extension().and_then(|e| e.to_str()).and_then(|e| e.parse::<u64>().ok())
            })
            .expect("a generation file");
        let text = std::fs::read_to_string(&newest).unwrap();
        std::fs::write(&newest, &text[..text.len() / 2]).unwrap();
        assert_eq!(
            read_pins_at(&file),
            None,
            "a torn newest generation fell back to an older record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A started host with `item_count` files shown and the first report made; the path and id of
    /// item `n`.
    fn many_files(fake: &Fake, dir: &Path, count: usize) -> Host<Fake, Fake> {
        fake.0.borrow_mut().item_count = count;
        fake.0.borrow_mut().quiet_author = true;
        let host = {
            let mut host = host(fake, dir);
            host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
            host
        };
        assert!(host.served.values().next().unwrap().reporter.is_some(), "no first report");
        host
    }

    fn file(host: &Host<Fake, Fake>, n: usize) -> (PathBuf, Vec<u8>) {
        let mut id = vec![0u8; 16];
        id[..8].copy_from_slice(&(n as u64 + 1).to_le_bytes());
        (host.served.values().next().unwrap().shown.get(&id).unwrap().path.clone(), id)
    }

    fn settle_signals(host: &mut Host<Fake, Fake>) {
        host.apply_due_local(Instant::now() + QUIET + Duration::from_secs(1));
    }

    #[test]
    fn a_finished_download_is_reported_for_that_file_alone_once_its_signals_settle() {
        let dir = temp_dir("report-one");
        let fake = Fake::default();
        let mut host = many_files(&fake, &dir, 50);
        let key = hex(&[1; 16]);
        let (path, id) = file(&host, 3);
        let first = fake.0.borrow().reports.len();
        fake.0.borrow_mut().materialized_looks.clear();

        // The bytes arrive; the watcher names the file.
        fake.0.borrow_mut().materialized.insert(id.clone());
        host.on_local(&key, Signal::Paths(vec![path]));
        settle_signals(&mut host);

        let recorded = fake.0.borrow();
        assert_eq!(recorded.reports.len(), first + 1, "the download was not reported");
        let report = recorded.reports.last().unwrap();
        assert!(!report.full, "a whole set was sent for one file");
        assert_eq!(report.upserts.iter().map(|u| u.item_id.clone()).collect::<Vec<_>>(), [id]);
        assert_eq!(recorded.materialized_looks, vec![1], "more than the signalled file was read");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_left_this_computer_is_removed_by_a_delta_too() {
        let dir = temp_dir("report-removed");
        let fake = Fake::default();
        let mut host = many_files(&fake, &dir, 20);
        let key = hex(&[1; 16]);
        let (path, id) = file(&host, 5);
        // It was materialized at the first report of the next round.
        fake.0.borrow_mut().materialized.insert(id.clone());
        host.on_local(&key, Signal::Paths(vec![path.clone()]));
        settle_signals(&mut host);
        let before = fake.0.borrow().reports.len();

        // The person frees up space (or edits it): it is no longer the daemon's bytes.
        fake.0.borrow_mut().materialized.remove(&id);
        host.on_local(&key, Signal::Paths(vec![path]));
        settle_signals(&mut host);
        let recorded = fake.0.borrow();
        assert_eq!(recorded.reports.len(), before + 1);
        assert_eq!(recorded.reports.last().unwrap().removed, vec![id]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_signal_for_nothing_shown_or_for_a_file_whose_state_did_not_change_sends_nothing() {
        let dir = temp_dir("report-none");
        let fake = Fake::default();
        let mut host = many_files(&fake, &dir, 10);
        let key = hex(&[1; 16]);
        let (path, _) = file(&host, 2);
        let before = fake.0.borrow().reports.len();
        fake.0.borrow_mut().materialized_looks.clear();

        host.on_local(&key, Signal::Paths(vec![PathBuf::from("not-shown.tmp")]));
        settle_signals(&mut host);
        assert!(
            fake.0.borrow().materialized_looks.is_empty(),
            "a path that is no shown file was read"
        );

        // A file shown, signalled, and unchanged (an attribute touched): read, nothing sent.
        host.on_local(&key, Signal::Paths(vec![path]));
        settle_signals(&mut host);
        assert_eq!(fake.0.borrow().reports.len(), before);
        assert_eq!(fake.0.borrow().materialized_looks, vec![1]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn files_shown_after_an_earlier_signal_are_found_by_their_path() {
        let dir = temp_dir("report-index");
        let fake = Fake::default();
        let mut host = many_files(&fake, &dir, 10);
        let key = hex(&[1; 16]);
        let (first_path, _) = file(&host, 0);
        // A first batch builds the path index.
        host.on_local(&key, Signal::Paths(vec![first_path]));
        settle_signals(&mut host);

        // The user's new file becomes a shown item through authoring: a signal for it must be
        // found, not looked up in the index of the items shown before.
        let root_path = host.served.get(&key).unwrap().path.clone();
        let (new_path, new_id) = (root_path.join("new.txt"), vec![0xAA; 16]);
        fake.0.borrow_mut().author_adds = Some((
            new_id.clone(),
            ShownItem {
                path: new_path.clone(),
                parent_item_id: vec![],
                name: "new.txt".into(),
                directory: false,
                size: 1,
                mtime_unix_nanos: 0,
                content_version: vec![0; 40],
                parent_generation: 0,
            },
        ));
        fake.0.borrow_mut().materialized.insert(new_id.clone());
        host.on_local(&key, Signal::Paths(vec![new_path]));
        settle_signals(&mut host);
        assert_eq!(
            fake.0
                .borrow()
                .reports
                .last()
                .unwrap()
                .upserts
                .iter()
                .map(|u| u.item_id.clone())
                .collect::<Vec<_>>(),
            [new_id]
        );

        // And the same after the namespace is shown again with more files.
        let first_looks = fake.0.borrow().materialized_looks.len();
        fake.0.borrow_mut().item_count = 15;
        host.on_changed(&[1; 16], 2, b"req");
        assert!(
            host.served.get(&key).unwrap().path_index.is_none(),
            "the index of the items shown before was kept after a new showing"
        );
        let (later_path, later_id) = file(&host, 12);
        fake.0.borrow_mut().materialized.insert(later_id.clone());
        host.on_local(&key, Signal::Paths(vec![later_path]));
        settle_signals(&mut host);
        assert!(fake.0.borrow().materialized_looks.len() > first_looks);
        assert!(
            fake.0.borrow().reports.iter().any(|r| r.upserts.iter().any(|u| u.item_id == later_id)),
            "a file shown by a later walk was not found"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_deleted_downloaded_file_or_folder_is_taken_out_of_the_reported_set_promptly() {
        let dir = temp_dir("report-deleted");
        let fake = Fake::default();
        let mut host = many_files(&fake, &dir, 10);
        let key = hex(&[1; 16]);
        let (path, id) = file(&host, 3);
        fake.0.borrow_mut().materialized.insert(id.clone());
        host.on_local(&key, Signal::Paths(vec![path.clone()]));
        settle_signals(&mut host);
        assert_eq!(fake.0.borrow().reports.last().unwrap().upserts.len(), 1);

        // The user deletes it: authoring takes it out of the shown items, and the daemon is told
        // it is no longer held without waiting for the next full report.
        fake.0.borrow_mut().author_removes = Some(id.clone());
        fake.0.borrow_mut().materialized.remove(&id);
        host.on_local(&key, Signal::Paths(vec![path]));
        settle_signals(&mut host);
        assert_eq!(fake.0.borrow().reports.last().unwrap().removed, vec![id.clone()]);

        // A folder moved away: only the folder's path is signalled, the files in it leave the shown
        // items with it.
        let (path4, id4) = file(&host, 4);
        fake.0.borrow_mut().materialized.insert(id4.clone());
        host.on_local(&key, Signal::Paths(vec![path4]));
        settle_signals(&mut host);
        fake.0.borrow_mut().author_removes = Some(id4.clone());
        fake.0.borrow_mut().materialized.remove(&id4);
        let folder = host.served.get(&key).unwrap().path.join("a-folder");
        host.on_local(&key, Signal::Paths(vec![folder]));
        settle_signals(&mut host);
        assert_eq!(fake.0.borrow().reports.last().unwrap().removed, vec![id4]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_file_accepted_on_retry_is_reported_without_another_signal() {
        let dir = temp_dir("report-retry");
        let fake = Fake::default();
        let mut host = many_files(&fake, &dir, 10);
        let key = hex(&[1; 16]);
        let (path, id) = file(&host, 6);
        // The first look at it was not possible; no new signal comes, the retry accepts it.
        fake.0.borrow_mut().materialized.insert(id.clone());
        host.served.get_mut(&key).unwrap().retry.insert(path);
        settle_signals(&mut host);
        assert_eq!(
            fake.0
                .borrow()
                .reports
                .last()
                .unwrap()
                .upserts
                .iter()
                .map(|u| u.item_id.clone())
                .collect::<Vec<_>>(),
            [id]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_path_index_is_kept_across_batches_that_changed_nothing() {
        let dir = temp_dir("report-index-kept");
        let fake = Fake::default();
        let mut host = many_files(&fake, &dir, 10);
        let key = hex(&[1; 16]);
        let (path, _) = file(&host, 4);
        host.on_local(&key, Signal::Paths(vec![path.clone()]));
        settle_signals(&mut host);
        // Mark the index, then signal again with nothing applied: the same index is used.
        host.served
            .get_mut(&key)
            .unwrap()
            .path_index
            .as_mut()
            .expect("built")
            .insert(PathBuf::from("mark"), vec![1]);
        host.on_local(&key, Signal::Paths(vec![path]));
        settle_signals(&mut host);
        assert!(
            host.served
                .get(&key)
                .unwrap()
                .path_index
                .as_ref()
                .is_some_and(|i| i.contains_key(Path::new("mark"))),
            "the index of a large folder was rebuilt for a batch that changed nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn newer_evidence_than_the_last_report_sends_the_whole_set_again_not_a_delta() {
        let dir = temp_dir("report-evidence");
        let fake = Fake::default();
        let mut host = many_files(&fake, &dir, 10);
        let key = hex(&[1; 16]);
        let (path, id) = file(&host, 1);
        host.served.get_mut(&key).unwrap().latest_seq += 5;
        fake.0.borrow_mut().materialized.insert(id);
        host.on_local(&key, Signal::Paths(vec![path]));
        settle_signals(&mut host);
        assert!(fake.0.borrow().reports.last().unwrap().full);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The operating system's registration of a root is gone while the host runs: its placeholders went
    /// with it, and every one would read as deleted. Nothing is authored; the root stops being served
    /// and is reported as an absent domain.
    #[test]
    fn a_registration_lost_while_running_authors_nothing_and_stops_serving_the_root() {
        let dir = temp_dir("registration-lost");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let key = hex(&[1; 16]);
        let path = item_path(&host);
        let started = fake.0.borrow().authored.len();

        // As long as the registration holds, a signalled path is looked at and authored.
        host.on_local(&key, Signal::Paths(vec![path.clone()]));
        host.apply_due_local(Instant::now() + QUIET + Duration::from_secs(1));
        assert_eq!(
            fake.0.borrow().authored.len(),
            started + 1,
            "the control: a signal is authored"
        );

        // The registration is gone; the files vanish and the watcher says so.
        fake.0.borrow_mut().registration = Some(Registration::Lost);
        fake.0.borrow_mut().states.clear();
        host.on_local(&key, Signal::Paths(vec![path]));
        host.apply_due_local(Instant::now() + 2 * (QUIET + Duration::from_secs(1)));
        assert_eq!(
            fake.0.borrow().authored.len(),
            started + 1,
            "a lost registration was authored from"
        );
        assert!(!host.served.contains_key(&key), "a root with no registration is still served");
        assert!(
            fake.0.borrow().states.iter().any(|s| s.1 == DomainEvidence::Absent as i32),
            "the lost registration was not reported"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The registration goes while a pass is running: the root is dropped when the pass ends, not
    /// walked, and reported absent.
    #[test]
    fn a_registration_lost_during_the_pass_drops_the_root_when_it_ends() {
        let dir = temp_dir("registration-lost-mid-pass");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let key = hex(&[1; 16]);
        let path = item_path(&host);
        fake.0.borrow_mut().states.clear();
        let walks = fake.0.borrow().walks.len();
        fake.0.borrow_mut().lose_registration_in_author = true;
        host.on_local(&key, Signal::Paths(vec![path]));
        host.apply_due_local(Instant::now() + QUIET + Duration::from_secs(1));
        assert!(!host.served.contains_key(&key), "the root kept being served after the pass");
        assert!(fake.0.borrow().states.iter().any(|s| s.1 == DomainEvidence::Absent as i32));
        assert_eq!(fake.0.borrow().walks.len(), walks, "a root without a registration was walked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A registration that cannot be read is no reason to author: nothing is, and the signals wait.
    #[test]
    fn a_registration_that_cannot_be_read_authors_nothing_and_keeps_the_signals() {
        let dir = temp_dir("registration-unknown");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let key = hex(&[1; 16]);
        let path = item_path(&host);
        let started = fake.0.borrow().authored.len();
        fake.0.borrow_mut().registration = Some(Registration::Unknown);
        host.on_local(&key, Signal::Paths(vec![path.clone()]));
        host.apply_due_local(Instant::now() + QUIET + Duration::from_secs(1));
        assert_eq!(
            fake.0.borrow().authored.len(),
            started,
            "authored with an unreadable registration"
        );
        assert!(host.served.contains_key(&key), "an unreadable registration stopped the root");
        assert!(host.served.get(&key).unwrap().pending.contains(&path), "the signal was dropped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The registration was lost while the host was not running: the folder is empty or nearly, and
    /// the recorded namespace judged against it would read as the person deleting everything. The
    /// record is forgotten first and the root shown again from the daemon's namespace.
    #[test]
    fn a_registration_lost_while_the_host_was_down_forgets_the_record_and_judges_nothing() {
        let dir = temp_dir("registration-lost-restart");
        let fake = Fake::default();
        let mut first = host(&fake, &dir);
        first.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        // What the previous run recorded: an item the daemon's namespace does not show any more, so
        // that judging this record can be told from showing the namespace again.
        let mut stale = fake
            .0
            .borrow()
            .saved
            .last()
            .cloned()
            .expect("a shown record")
            .into_values()
            .next()
            .expect("a shown item");
        stale.path = stale.path.with_file_name("gone-old.txt");
        stale.name = "gone-old.txt".into();
        let old_path = stale.path.clone();
        let recorded: ShownItems = ShownItems::from([(vec![0x77u8; 16], stale)]);
        fake.0.borrow_mut().loaded = Some(recorded.clone());
        fake.0.borrow_mut().authored.clear();
        drop(first);
        let authored_old = |fake: &Fake| {
            fake.0.borrow().authored.iter().any(|signals| signals.contains(&old_path))
        };

        // The first run registered a new root: nothing recorded of it was kept. The next run finds the
        // root's registration gone.
        fake.0.borrow_mut().forgotten.clear();
        fake.0.borrow_mut().registration = Some(Registration::Lost);
        let mut second = host(&fake, &dir);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(fake.0.borrow().forgotten, vec![vec![1u8; 16]], "the record was kept");
        assert!(
            !authored_old(&fake),
            "an item of the forgotten record was judged against the folder"
        );
        assert!(
            second.served.get(&hex(&[1; 16])).is_some_and(|root| !root.shown.is_empty()),
            "the root was not shown again from the daemon's namespace"
        );

        // The control: a registration that holds keeps its record, which is then judged against the
        // folder (the item's path is looked at), as it always did.
        fake.0.borrow_mut().registration = None;
        fake.0.borrow_mut().forgotten.clear();
        fake.0.borrow_mut().loaded = Some(recorded);
        fake.0.borrow_mut().authored.clear();
        let mut third = host(&fake, &dir);
        third.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(fake.0.borrow().forgotten.is_empty());
        assert!(authored_old(&fake), "the control: a kept record is judged against the folder");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reinstall that lost the list of sync roots but not the records of what they showed (the
    /// operating system removed the registration and every online-only placeholder with it): the root
    /// looks new, and the records of the old one describe placeholders that are gone.
    #[test]
    fn records_found_for_a_root_the_host_never_registered_are_forgotten_not_judged() {
        let dir = temp_dir("reinstall-records");
        let fake = Fake::default();
        let mut first = host(&fake, &dir);
        first.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let mut stale =
            fake.0.borrow().saved.last().cloned().unwrap().into_values().next().unwrap();
        stale.path = stale.path.with_file_name("gone-old.txt");
        stale.name = "gone-old.txt".into();
        let old_path = stale.path.clone();
        let records: ShownItems = ShownItems::from([(vec![0x77u8; 16], stale)]);
        drop(first);

        // The records of the old root survive; the list of roots does not (another directory).
        fake.0.borrow_mut().forgotten.clear();
        fake.0.borrow_mut().loaded = Some(records);
        fake.0.borrow_mut().authored.clear();
        let other_dir = temp_dir("reinstall-records-new-registry");
        let mut second = host(&fake, &other_dir);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert_eq!(fake.0.borrow().forgotten, vec![vec![1u8; 16]], "stale records were kept");
        assert!(
            !fake.0.borrow().authored.iter().any(|signals| signals.contains(&old_path)),
            "an item of a stale record was judged against the folder"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other_dir);
    }

    #[test]
    fn a_registration_that_cannot_be_read_at_start_does_not_serve_the_root() {
        let dir = temp_dir("registration-unknown-restart");
        let fake = Fake::default();
        let mut first = host(&fake, &dir);
        first.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        drop(first);
        fake.0.borrow_mut().forgotten.clear();
        fake.0.borrow_mut().registration = Some(Registration::Unknown);
        let mut second = host(&fake, &dir);
        second.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        assert!(second.served.is_empty());
        assert!(fake.0.borrow().forgotten.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_deferred_paths_of_a_closed_window_are_looked_at_without_a_new_signal() {
        let dir = temp_dir("observe-deferred");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::Keep)]);
        let (path, key) = (item_path(&host), hex(&[1; 16]));
        let now = Instant::now();
        // A change made inside the window leaves the path deferred and the root due when it closes.
        fake.0.borrow_mut().marks.insert(path.clone(), PinWish::OnlineOnly);
        {
            let served = host.served.get_mut(&key).unwrap();
            served.pending.insert(path);
            served.pin_settle_until = Some(now + PIN_SETTLE);
        }
        host.observe_pins(&key, now);
        host.served.get_mut(&key).unwrap().pending.clear();
        assert!(host.next_deadline(now, Duration::from_secs(60)) <= PIN_SETTLE);
        host.apply_due_local(now + PIN_SETTLE + Duration::from_secs(1));
        assert_eq!(fake.0.borrow().observed, vec![(vec![9u8; 16], PinWish::OnlineOnly)]);
        assert!(host.served.get(&key).unwrap().pin_deferred.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_sync_root_itself_is_reported_with_the_empty_item_and_an_overflow_rereads_known_pins() {
        let dir = temp_dir("observe-root");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::Keep)]);
        let (path, key) = (item_path(&host), hex(&[1; 16]));
        let root_path = host.served.get(&key).unwrap().path.clone();
        let later = Instant::now() + PIN_SETTLE + Duration::from_secs(1);
        fake.0.borrow_mut().observed.clear();

        // The person pins the whole folder in the file manager.
        fake.0.borrow_mut().marks.insert(root_path.clone(), PinWish::Keep);
        host.served.get_mut(&key).unwrap().pending.insert(root_path);
        host.observe_pins(&key, later);
        host.served.get_mut(&key).unwrap().pending.clear();
        assert_eq!(fake.0.borrow().observed, vec![(Vec::<u8>::new(), PinWish::Keep)]);
        fake.0.borrow_mut().observed.clear();

        // The watcher lost changes (overflow): the path that carried a pin is read again and the
        // unpin that happened meanwhile is found, though nothing names it.
        fake.0.borrow_mut().marks.insert(path, PinWish::Clear);
        host.served.get_mut(&key).unwrap().rescan = true;
        host.observe_pins(&key, later);
        assert_eq!(fake.0.borrow().observed, vec![(vec![9u8; 16], PinWish::Clear)]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deferred_pin_marks_do_not_keep_the_host_awake_while_the_shown_record_is_not_durable() {
        let dir = temp_dir("observe-busy");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.on_pin_plan(&[1; 16], &[]);
        let key = hex(&[1; 16]);
        let now = Instant::now();
        let served = host.served.get_mut(&key).unwrap();
        served.pin_deferred.insert(PathBuf::from("a"));
        served.pin_settle_until = Some(now);
        served.shown_durable = false;
        // Not durable: nothing to wake for, so the wait is the full poll, not a 10 ms spin.
        assert_eq!(host.next_deadline(now, Duration::from_secs(60)), Duration::from_secs(60));
        host.apply_due_local(now + Duration::from_secs(1));
        assert!(host.served.get(&key).unwrap().pin_deferred.contains(Path::new("a")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_remembered_pin_marks_are_bounded() {
        let dir = temp_dir("observe-cap");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.on_pin_plan(&[1; 16], &[(vec![9; 16], PinWish::Keep)]);
        let (path, key) = (item_path(&host), hex(&[1; 16]));
        let served = host.served.get_mut(&key).unwrap();
        for n in 0..=MAX_REMEMBERED_PIN_MARKS {
            served.pin_marks.insert(PathBuf::from(format!("f{n}")), PinWish::Keep);
        }
        served.pending.insert(path);
        host.observe_pins(&key, Instant::now() + PIN_SETTLE + Duration::from_secs(1));
        assert!(host.served.get(&key).unwrap().pin_marks.is_empty(), "the memory is dropped");
        // The record is not rewritten from the memory that was dropped: it keeps the last complete
        // state, so a restart does not read the dropped marks as cleared.
        assert!(host.served.get(&key).unwrap().pin_marks_overflowed);
        // The record says the marks are no longer known completely, once, instead of staying
        // behind as a baseline that has gone stale.
        host.apply_due_local(Instant::now() + Duration::from_secs(600));
        assert!(fake.0.borrow().pin_record.is_none());
        assert_eq!(fake.0.borrow().pin_untrusted_saves, 1);
        host.apply_due_local(Instant::now() + Duration::from_secs(1200));
        assert_eq!(fake.0.borrow().pin_untrusted_saves, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_that_is_no_shown_item_and_a_mark_that_was_never_set_are_not_reported() {
        let dir = temp_dir("observe-none");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        host.on_pin_plan(&[1; 16], &[]);
        let key = hex(&[1; 16]);
        let later = Instant::now() + PIN_SETTLE + Duration::from_secs(1);
        // A path the namespace does not show carrying a mark: nobody to name it to.
        let stray = PathBuf::from("not-shown.txt");
        fake.0.borrow_mut().marks.insert(stray.clone(), PinWish::Keep);
        // A shown path whose mark is the default and was never seen otherwise: not a change.
        let shown = item_path(&host);
        host.served.get_mut(&key).unwrap().pending.extend([stray, shown]);
        host.observe_pins(&key, later);
        assert!(fake.0.borrow().observed.is_empty(), "{:?}", fake.0.borrow().observed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pin_plan_applies_each_entry_it_can_and_skips_the_rest_without_answering() {
        let dir = temp_dir("pinplan");
        let fake = Fake::default();
        let mut host = host(&fake, &dir);
        host.reconcile(Some((vec![folder(1, "Photos", true)], vec![])));
        let before = fake.0.borrow().pin_results.len();

        host.on_pin_plan(
            &[1; 16],
            &[
                (vec![], PinWish::Keep),
                (vec![9; 16], PinWish::OnlineOnly),
                (vec![8; 16], PinWish::Keep), // not shown: skipped
                (vec![9; 16], PinWish::Keep),
            ],
        );
        // A root the host does not serve: nothing is applied.
        host.on_pin_plan(&[2; 16], &[(vec![9; 16], PinWish::Keep)]);

        let recorded = fake.0.borrow();
        assert_eq!(recorded.pin_results.len(), before, "a plan is not answered");
        let applied: Vec<(Option<Vec<u8>>, PinWish)> =
            recorded.pins.iter().map(|p| (p.1.clone(), p.2)).collect();
        assert_eq!(
            applied,
            vec![
                (None, PinWish::Keep),
                (Some(vec![9u8; 16]), PinWish::OnlineOnly),
                (Some(vec![9u8; 16]), PinWish::Keep),
            ],
            "entries reach the operating system in order; an unknown item and an unknown root do not"
        );
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
