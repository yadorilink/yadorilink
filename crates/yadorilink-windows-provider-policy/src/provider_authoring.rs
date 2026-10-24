//! Turning what the user does in a sync root into `ProviderApplyChange` requests.
//!
//! The host does not decide what a change MEANS. A directory watcher only says "something
//! happened at this path"; this module looks at that path and at what the daemon last showed
//! there (the [`ShownItems`]) and derives the one operation that makes the daemon's namespace
//! match what the user did:
//!
//! * a name with no item behind it is a CREATE (a file's bytes first go to a private copy in the
//!   daemon's `ingest` directory, which the daemon then reads under its own checks);
//! * the placeholder of a known item that is no longer where it was, or is no longer called what
//!   it was, is a MODIFY that renames or moves it;
//! * a placeholder the user wrote to (no longer in sync, with a different size or time), or a plain
//!   file that took the place of a known item (an editor's save-by-replacing), is a MODIFY with
//!   the new bytes;
//! * a known item whose name is gone, and which is nowhere else in the sync root either, is a
//!   DELETE.
//!
//! Every request carries the version the user saw as its base, so the daemon, not the host, finds
//! a conflict. The answer is adopted the way the daemon issued it: a created file becomes the
//! placeholder of the item the daemon made, and an accepted edit is marked in sync.
//!
//! One operation is journaled before it is sent and cleared after its answer was adopted AND the
//! resulting shown items were recorded durably, with the
//! (session, sequence) pair the daemon uses to recognize a repeat: after a crash the same request
//! is sent again and the daemon answers it from its record instead of applying it twice.

use std::collections::{BTreeSet, HashSet};

use std::io::Write;
use std::path::{Path, PathBuf};

use yadorilink_fs_platform::durable_dir::{publish_durably, Replace};
use yadorilink_fs_platform::generation::{self, seal, unseal};
use yadorilink_ipc_proto::shellipc::{
    EntryKind, ProviderAppliedItem, ProviderApplyChangeRequest, ProviderApplyChangeResponse,
    ProviderApplyFailure, ProviderApplyOutcome, ProviderChangeKind, ProviderContentSource,
    ProviderItemMetadata,
};

use crate::namespace_policy::{PlaceholderInfo, ShownItem, ShownItems};

/// What the file system says about a path.
#[derive(Clone, Debug)]
pub struct LocalStat {
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    /// The Cloud Files placeholder state, when the entry is a placeholder.
    pub placeholder: Option<PlaceholderInfo>,
    /// The stable identity of the file system object (volume and file index): it survives a
    /// rename and the conversion to a placeholder, and differs for another object at the same path.
    pub file_id: Option<u128>,
}

/// A finished private copy of a file's bytes in the daemon's ingest directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestCopy {
    pub name: String,
    pub size: u64,
    pub sha256: Vec<u8>,
    /// The file's USN while it was copied (equal before and after the copy). A volume without a
    /// usable per-file USN gets no copy at all: nothing else tells a re-save of the same file
    /// object (same id, size and time) from the bytes that were copied.
    pub usn: i64,
}

/// Why a file could not be bound to its item.
#[derive(Debug, PartialEq, Eq)]
pub enum AdoptError {
    /// The file was written to since it was copied: it is not what the daemon accepted.
    Changed,
    Failed(String),
}

#[derive(Debug)]
pub enum CopyError {
    /// The file changed while it was copied, or could not be read right now: copy again later.
    Unstable(String),
    Failed(String),
}

/// The file system side of the host.
pub trait Local {
    fn stat(&self, path: &Path) -> Option<LocalStat>;
    fn children(&self, directory: &Path) -> Vec<PathBuf>;
    fn copy_to_ingest(&self, path: &Path) -> Result<IngestCopy, CopyError>;
    /// Binds `path` to the daemon's item: converts a plain file or folder into a placeholder
    /// carrying the item id, or marks an existing placeholder in sync.
    /// `file_id` is the object that may be bound: another one at `path` is refused. `usn` is the
    /// file's USN when its bytes were copied: a file written to since is not bound
    /// ([`AdoptError::Changed`]). `None` only for a folder, which has no bytes to guard.
    fn adopt(
        &self,
        path: &Path,
        item_id: &[u8],
        file_id: u128,
        usn: Option<i64>,
    ) -> Result<(), AdoptError>;
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()>;
    /// Makes the placeholder at `path` an ordinary file again: its bytes stay, its item identity
    /// goes.
    fn unbind(&self, path: &Path) -> Result<(), String>;
    /// Removes the file at `path` (its bytes are kept elsewhere by the daemon).
    /// Only the object with `file_id` that is still at the copied `usn` is removed.
    fn discard(&self, path: &Path, file_id: u128, usn: Option<i64>) -> Result<(), AdoptError>;
    /// The path of the placeholder of `item_id` anywhere below `root`.
    fn locate(&self, root: &Path, item_id: &[u8]) -> Located;
    /// Whether `path` is confirmed not to exist (`NotFound`). A path that cannot be inspected
    /// (access denied, a sharing violation) is not missing.
    fn confirmed_missing(&self, path: &Path) -> bool;
}

/// The answer to "where is the placeholder of this item".
#[derive(Debug, PartialEq, Eq)]
pub enum Located {
    Found(PathBuf),
    /// The whole sync root was searched and it is nowhere.
    Absent,
    /// Some part of the sync root could not be searched.
    Unknown,
}

/// The daemon side of the host.
pub trait Api {
    /// `None`: the daemon could not be asked or did not answer.
    fn apply(
        &self,
        root: &[u8],
        request: ProviderApplyChangeRequest,
    ) -> Option<ProviderApplyChangeResponse>;
    /// Records `shown` durably; false when it could not be. The journal of an accepted operation
    /// is kept until this succeeds: the accepted operation and the baseline that shows its
    /// result are one handoff, so a crash between them replays the operation (the daemon
    /// answers the same request from its record) instead of authoring a new one against the
    /// older baseline.
    fn save_shown(&self, root: &[u8], shown: &ShownItems) -> bool;
}

/// What a batch of signals led to.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Operations the daemon accepted.
    pub applied: usize,
    /// Paths to look at again later: the daemon was busy, or a file was still changing.
    pub retry: BTreeSet<PathBuf>,
    /// The namespace changed in a way only a fresh look shows (a concurrent edit, a conflict).
    pub rewalk: bool,
    /// Operations the daemon refused for good, with its reason.
    pub refused: Vec<(PathBuf, String)>,
}

/// What an edit of an existing item changes.
#[derive(Default)]
struct Edit {
    /// The folder the item moved to.
    new_parent: Option<Vec<u8>>,
    /// The name the item was given.
    new_name: Option<String>,
    /// New bytes, copied for the daemon to ingest.
    content: bool,
}

/// What one pass works with: the items shown, the file system, the daemon, and the report being
/// built.
struct Ctx<'a> {
    shown: &'a mut ShownItems,
    local: &'a dyn Local,
    api: &'a dyn Api,
    report: Report,
    /// An operation went unanswered and is still journaled: nothing new may start over it.
    blocked: bool,
    /// The disk effect of an accepted answer did not complete: the journal stays and the same
    /// request is settled again before anything new starts.
    effect_failed: bool,
}

impl Ctx<'_> {
    /// Whether a new operation must wait (an earlier one is unanswered); the path is looked at
    /// again later.
    fn hold(&mut self, path: &Path) -> bool {
        if self.blocked {
            self.report.retry.insert(path.to_path_buf());
        }
        self.blocked
    }
}

/// The authoring state of one served root.
pub struct Authoring {
    root_id: Vec<u8>,
    root_path: PathBuf,
    state_dir: PathBuf,
    session: [u8; 16],
}

/// Whether `path` is, or lies below, one of the product's own reserved names (a Stage placeholder
/// the host is publishing): that is never something the user did.
fn is_host_artefact(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root)
        .is_ok_and(yadorilink_fs_platform::reserved_namespace::path_has_artefact_component)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use std::hash::{BuildHasher, Hasher};
    let mut out = [0u8; N];
    for chunk in out.chunks_mut(8) {
        // `RandomState` is seeded from the operating system's generator for each instance.
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        let bytes = hasher.finish().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
}

/// A fresh, unguessable name for a private copy in the ingest directory.
pub fn fresh_ingest_name() -> String {
    format!("c{}", hex(&random_bytes::<16>()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

fn decode_seq(text: &str) -> Option<u64> {
    unseal(text)?.trim().parse().ok()
}

fn seq_unreadable(why: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("the operation sequence cannot be read: {why}"),
    )
}

/// Publishes `contents` at `path`, which must not exist: a journal is written once and is never
/// replaced (a replace cut short could lose the only record of an operation's identity).
fn write_new(path: &Path, contents: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(contents.as_bytes())?;
    yadorilink_fs_platform::flush::sync_file(&file)?;
    drop(file);
    // A durable publish: the journal or sequence file is on disk before the request that
    // depends on it is sent.
    publish_durably(&tmp, path, Replace::No)
}

/// The request of the journaled operation and where its answer lands.
struct Pending {
    request: ProviderApplyChangeRequest,
    path: PathBuf,
    /// The size and modification time (unix nanoseconds) of the file the request describes. The
    /// answer is adopted only if the file still looks like that: a later write is not covered by
    /// what the daemon accepted.
    expect: Option<(u64, i64)>,
    /// The object at `path` when the request was journaled. The disk effect of the answer is
    /// applied only to this object, so a repeat after a crash cannot bind or remove another one.
    file_id: Option<u128>,
    /// The USN of the file when its bytes were copied; present exactly when the request carries
    /// bytes. The disk effect compares it on the handle it marks or deletes through, and an
    /// operation that carries bytes but has no USN (an old journal) never marks or deletes.
    usn: Option<i64>,
}

impl Pending {
    fn encode(&self) -> String {
        let r = &self.request;
        let mut lines = vec![
            format!("path={}", hex(self.path.to_string_lossy().as_bytes())),
            format!("request_id={}", hex(&r.request_id)),
            format!("session={}", hex(&r.session_id)),
            format!("seq={}", r.operation_seq),
            format!("kind={}", r.kind),
            format!("item={}", hex(&r.item_id)),
            format!("entry_kind={}", r.entry_kind),
            format!("base={}", hex(&r.base_version_hash)),
            format!("recursive={}", r.recursive),
        ];
        if let Some(parent) = &r.parent_item_id {
            lines.push(format!("parent={}", hex(parent)));
        }
        if let Some(name) = &r.name {
            lines.push(format!("name={}", hex(name.as_bytes())));
        }
        if let Some(generation) = r.parent_generation {
            lines.push(format!("parent_generation={generation}"));
        }
        if let Some(content) = &r.content {
            lines.push(format!(
                "content={} {} {}",
                content.ingest_name,
                content.size,
                hex(&content.sha256)
            ));
        }
        if let Some(mtime) = r.metadata.as_ref().and_then(|m| m.mtime_unix_nanos) {
            lines.push(format!("mtime={mtime}"));
        }
        if let Some((size, mtime)) = self.expect {
            lines.push(format!("expect={size},{mtime}"));
        }
        if let Some(id) = self.file_id {
            lines.push(format!("fid={id:x}"));
        }
        if let Some(usn) = self.usn {
            lines.push(format!("usn={usn}"));
        }
        lines.push(String::new());
        lines.join("\n")
    }

    fn decode(text: &str, root_id: &[u8]) -> Option<Self> {
        let get = |key: &str| {
            text.lines().find_map(|line| line.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
        };
        let path = PathBuf::from(String::from_utf8(unhex(get("path")?)?).ok()?);
        let content = get("content").and_then(|value| {
            let mut parts = value.split(' ');
            Some(ProviderContentSource {
                ingest_name: parts.next()?.to_string(),
                size: parts.next()?.parse().ok()?,
                sha256: unhex(parts.next()?)?,
            })
        });
        let request = ProviderApplyChangeRequest {
            request_id: unhex(get("request_id")?)?,
            session_id: unhex(get("session")?)?,
            operation_seq: get("seq")?.parse().ok()?,
            root_id: root_id.to_vec(),
            kind: get("kind")?.parse().ok()?,
            item_id: unhex(get("item")?)?,
            parent_item_id: match get("parent") {
                Some(v) => Some(unhex(v)?),
                None => None,
            },
            name: match get("name") {
                Some(v) => Some(String::from_utf8(unhex(v)?).ok()?),
                None => None,
            },
            entry_kind: get("entry_kind")?.parse().ok()?,
            base_version_hash: unhex(get("base")?)?,
            content,
            recursive: get("recursive")? == "true",
            parent_generation: get("parent_generation").and_then(|v| v.parse().ok()),
            metadata: Some(ProviderItemMetadata {
                mtime_unix_nanos: get("mtime").and_then(|v| v.parse().ok()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let expect = get("expect").and_then(|v| {
            let (size, mtime) = v.split_once(',')?;
            Some((size.parse().ok()?, mtime.parse().ok()?))
        });
        let file_id = get("fid").and_then(|v| u128::from_str_radix(v, 16).ok());
        let usn = get("usn").and_then(|v| v.parse().ok());
        Some(Self { request, path, expect, file_id, usn })
    }
}

/// How an answer is acted on.
enum Verdict {
    Accepted(Option<ProviderAppliedItem>, bool),
    /// Ask again later, with the same request.
    Retry,
    /// Nothing there to apply it to (the item is gone) or the observation is obsolete: the request
    /// is retired and the namespace is looked at again.
    Gone,
    /// The daemon wants these bytes kept under another name.
    KeepLocal(String),
    Refused(String),
}

fn verdict(response: &ProviderApplyChangeResponse) -> Verdict {
    if response.ok {
        let concurrent = response.outcome() != ProviderApplyOutcome::Applied;
        return Verdict::Accepted(response.item.clone(), concurrent);
    }
    match response.failure() {
        ProviderApplyFailure::NotReady
        | ProviderApplyFailure::Retry
        | ProviderApplyFailure::IngestUnstable
        | ProviderApplyFailure::LowDisk
        | ProviderApplyFailure::Cancelled => Verdict::Retry,
        // The observation the request was built on is obsolete (or the item is gone): repeating
        // it would be refused the same way. It is retired, and a fresh walk comes first.
        ProviderApplyFailure::NotFound
        | ProviderApplyFailure::InvalidBase
        | ProviderApplyFailure::StaleView
        | ProviderApplyFailure::StaleOperation => Verdict::Gone,
        ProviderApplyFailure::KeepLocal => Verdict::KeepLocal(response.suggested_name.clone()),
        other => Verdict::Refused(format!("{other:?}: {}", response.error)),
    }
}

/// Whether the daemon only asked to be asked again later, which says nothing about whether it
/// has the request on record.
fn transient(response: &ProviderApplyChangeResponse) -> bool {
    matches!(response.failure(), ProviderApplyFailure::NotReady | ProviderApplyFailure::Retry)
}

impl Authoring {
    /// Opens (creating on first use) the authoring state of a root under `state_dir`.
    ///
    /// The session and the sequence are generation records (see
    /// [`yadorilink_fs_platform::generation`]), never replaced. A session and a sequence that
    /// are both readable continue as they were. Anything else (the first use, or a record that
    /// is gone or unreadable) starts a NEW session with the sequence at 0: a (session,
    /// sequence) pair the daemon has seen is never produced again, so a lost record cannot make
    /// an earlier operation identity come back for different content. A journaled operation
    /// keeps the identity it was written with.
    pub fn open(root_id: &[u8], root_path: &Path, state_dir: &Path) -> std::io::Result<Self> {
        let session_base = state_dir.join("session");
        let seq_base = state_dir.join("seq");
        let session = generation::read_latest(&session_base, |text| {
            unhex(unseal(text)?.trim()).and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
        });
        let seq = generation::read_latest(&seq_base, decode_seq);
        let session = match (session, seq) {
            (
                generation::Latest::Loaded { value, skipped_newer: false, .. },
                generation::Latest::Loaded { skipped_newer: false, .. },
            ) => value,
            // Missing, unreadable, or a newer generation that cannot be decoded (the older one
            // may be behind what was sent): a new session, and the sequence starts again under it.
            _ => {
                let fresh = random_bytes::<16>();
                generation::publish_next(&session_base, &seal(&format!("{}\n", hex(&fresh))))?;
                generation::publish_next(&seq_base, &seal("0\n"))?;
                fresh
            }
        };
        Ok(Self {
            root_id: root_id.to_vec(),
            root_path: root_path.to_path_buf(),
            state_dir: state_dir.to_path_buf(),
            session,
        })
    }

    fn pending_file(&self) -> PathBuf {
        self.state_dir.join("pending")
    }

    /// The next sequence number, recorded before it is used so a crash never reuses one. A
    /// record that cannot be read is an error (nothing is sent), never 0.
    fn next_seq(&self) -> std::io::Result<u64> {
        let base = self.state_dir.join("seq");
        let last = match generation::read_latest(&base, decode_seq) {
            generation::Latest::Loaded { value, skipped_newer: false, .. } => value,
            // The newest record is damaged: the last number handed out is not known, and the
            // older one may already have been sent. Nothing is numbered until a new session.
            generation::Latest::Loaded { .. } => {
                return Err(seq_unreadable("the newest record is damaged"))
            }
            generation::Latest::Missing => return Err(seq_unreadable("no sequence record")),
            generation::Latest::Invalid(e) => return Err(seq_unreadable(&e)),
        };
        let next = last.checked_add(1).ok_or_else(|| seq_unreadable("sequence exhausted"))?;
        generation::publish_next(&base, &seal(&format!("{next}\n")))?;
        Ok(next)
    }

    fn request(&self, kind: ProviderChangeKind) -> std::io::Result<ProviderApplyChangeRequest> {
        Ok(ProviderApplyChangeRequest {
            request_id: random_bytes::<16>().to_vec(),
            session_id: self.session.to_vec(),
            operation_seq: self.next_seq()?,
            root_id: self.root_id.clone(),
            kind: kind as i32,
            ..Default::default()
        })
    }

    /// A numbered request for a change at `path`. When it cannot be numbered nothing is sent and
    /// the signal is kept for the next pass. A damaged record needs no special case: the host
    /// opens the authoring state afresh on every pass, and `open` starts a new session over
    /// anything it cannot trust.
    fn begin(
        &self,
        kind: ProviderChangeKind,
        path: &Path,
        cx: &mut Ctx<'_>,
    ) -> Option<ProviderApplyChangeRequest> {
        match self.request(kind) {
            Ok(request) => Some(request),
            Err(error) => {
                eprintln!("yadorilink-cfapi-host: could not number a change: {error}; retrying");
                cx.report.retry.insert(path.to_path_buf());
                None
            }
        }
    }

    /// Sends the operation left by a crash, if any, and adopts its answer.
    pub fn resume(&self, shown: &mut ShownItems, local: &dyn Local, api: &dyn Api) -> Report {
        let mut cx = Ctx {
            shown,
            local,
            api,
            report: Report::default(),
            blocked: false,
            effect_failed: false,
        };
        self.resume_in(&mut cx);
        cx.report
    }

    fn resume_in(&self, cx: &mut Ctx<'_>) {
        let Ok(text) = std::fs::read_to_string(self.pending_file()) else { return };
        match Pending::decode(&text, &self.root_id) {
            Some(pending) => {
                // Already journaled: sent again as it is, never rewritten.
                self.dispatch(pending, cx);
            }
            None => {
                eprintln!("yadorilink-cfapi-host: dropping an unreadable journal entry");
                let _ = std::fs::remove_file(self.pending_file());
            }
        }
    }

    /// Looks at the paths a watcher signalled and applies what the user did to the daemon.
    pub fn process(
        &self,
        signals: &BTreeSet<PathBuf>,
        shown: &mut ShownItems,
        local: &dyn Local,
        api: &dyn Api,
    ) -> Report {
        let mut cx = Ctx {
            shown,
            local,
            api,
            report: Report::default(),
            blocked: false,
            effect_failed: false,
        };
        let cx = &mut cx;
        self.resume_in(cx);
        if self.pending_file().exists() || cx.report.rewalk {
            // The earlier operation is still unanswered, or was retired and the namespace must be
            // walked again before anything is authored from the shown base. It is sent again before anything new,
            // so nothing else is started now and nothing is lost: look at these paths later.
            cx.report.retry.extend(signals.iter().cloned());
            return std::mem::take(&mut cx.report);
        }
        // Parents before children: a new folder must have its item before what is inside it.
        let mut paths: Vec<&PathBuf> = signals
            .iter()
            .filter(|p| p.starts_with(&self.root_path) && **p != self.root_path)
            .filter(|p| !is_host_artefact(&self.root_path, p))
            .collect();
        paths.sort_by_key(|p| p.components().count());

        let mut vanished: Vec<(Vec<u8>, ShownItem)> = Vec::new();
        let mut done: HashSet<PathBuf> = HashSet::new();
        for path in paths {
            if !done.insert(path.clone()) {
                continue;
            }
            match cx.local.stat(path) {
                Some(stat) => self.on_present(path, &stat, cx, &mut done),
                None if !cx.local.confirmed_missing(path) => {
                    // Could not be inspected right now (in use, access denied): not a delete.
                    cx.report.retry.insert(path.clone());
                }
                None => {
                    if let Some((id, item)) = cx.shown.iter().find(|(_, item)| item.path == *path) {
                        vanished.push((id.clone(), item.clone()));
                    }
                }
            }
        }
        // Deletes last, shallowest first, once the items that merely moved have been seen where
        // they went.
        vanished.sort_by_key(|(_, item)| item.path.components().count());
        let mut deleted: Vec<PathBuf> = Vec::new();
        for (id, item) in vanished {
            // Skip what an earlier step already settled (an item that moved is shown at its new
            // path by now) and what lies below a folder deleted in this pass.
            let still_there = cx.shown.get(&id).is_some_and(|current| current.path == item.path);
            if !still_there || deleted.iter().any(|dir| item.path.starts_with(dir)) {
                continue;
            }
            match cx.local.locate(&self.root_path, &id) {
                Located::Found(moved_to) => {
                    // It is still in the sync root, under another path: the move is what happened.
                    if let Some(stat) = cx.local.stat(&moved_to) {
                        done.insert(moved_to.clone());
                        self.on_present(&moved_to, &stat, cx, &mut done);
                    }
                    continue;
                }
                Located::Unknown => {
                    // Only a complete search that finds nothing authorizes a delete.
                    cx.report.retry.insert(item.path.clone());
                    continue;
                }
                Located::Absent => {}
            }
            self.delete(&id, &item, cx);
            deleted.push(item.path.clone());
        }
        std::mem::take(&mut cx.report)
    }

    fn on_present(
        &self,
        path: &Path,
        stat: &LocalStat,
        cx: &mut Ctx<'_>,
        done: &mut HashSet<PathBuf>,
    ) {
        if stat.is_symlink {
            eprintln!(
                "yadorilink-cfapi-host: {} is a symbolic link; it is not synchronized",
                path.display()
            );
            return;
        }
        let Some(parent) = path.parent() else { return };
        let Some(parent_item) = self.item_of_directory(parent, cx.shown, cx.local) else {
            // The folder above has no item yet (it is signalled too and comes first), or is not
            // this root's: nothing to place this under right now.
            cx.report.retry.insert(path.to_path_buf());
            return;
        };
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let known_id = stat.placeholder.as_ref().and_then(|p| p.item_id.clone());
        match known_id {
            Some(id) if cx.shown.contains_key(&id) => {
                self.on_known(path, stat, &id, &parent_item, &name, cx);
            }
            // The placeholder of an item shown after the last look: look again.
            Some(_) => cx.report.rewalk = true,
            None => {
                // A plain file or folder. If an item was shown at exactly this path, the plain
                // entry replaced it (an editor saving by writing a new file over the old one).
                let replaced = cx
                    .shown
                    .iter()
                    .find(|(_, item)| item.path == path && !item.directory && !stat.is_dir)
                    .map(|(id, _)| id.clone());
                match replaced {
                    Some(id) => self.on_replaced(path, stat, &id, cx),
                    None => self.create(path, stat, &parent_item, &name, cx, done),
                }
            }
        }
    }

    /// The item of a folder inside the sync root: empty for the root itself.
    fn item_of_directory(
        &self,
        directory: &Path,
        shown: &ShownItems,
        local: &dyn Local,
    ) -> Option<Vec<u8>> {
        if directory == self.root_path {
            return Some(Vec::new());
        }
        let from_state = shown.iter().find(|(_, item)| item.directory && item.path == directory);
        if let Some((id, _)) = from_state {
            return Some(id.clone());
        }
        local.stat(directory)?.placeholder?.item_id.filter(|id| shown.contains_key(id))
    }
    fn create(
        &self,
        path: &Path,
        stat: &LocalStat,
        parent_item: &[u8],
        name: &str,
        cx: &mut Ctx<'_>,
        done: &mut HashSet<PathBuf>,
    ) {
        if cx.hold(path) {
            return;
        }
        let Some(mut request) = self.begin(ProviderChangeKind::Create, path, cx) else { return };
        request.parent_item_id = Some(parent_item.to_vec());
        request.name = Some(name.to_string());
        request.entry_kind =
            if stat.is_dir { EntryKind::Directory as i32 } else { EntryKind::File as i32 };
        request.metadata = Some(ProviderItemMetadata {
            mtime_unix_nanos: Some(stat.mtime_unix_nanos),
            ..Default::default()
        });
        let mut usn = None;
        if !stat.is_dir {
            match cx.local.copy_to_ingest(path) {
                Ok(copy) => {
                    usn = Some(copy.usn);
                    request.content = Some(content_of(&copy));
                }
                Err(CopyError::Unstable(why)) => {
                    eprintln!(
                        "yadorilink-cfapi-host: {} is still changing ({why})",
                        path.display()
                    );
                    cx.report.retry.insert(path.to_path_buf());
                    return;
                }
                Err(CopyError::Failed(why)) => {
                    cx.report.refused.push((path.to_path_buf(), why));
                    return;
                }
            }
        }
        let Some(file_id) = stat.file_id else {
            // Not an object that can be told from another later: not sent now.
            cx.report.retry.insert(path.to_path_buf());
            return;
        };
        let expect = (!stat.is_dir).then_some((stat.size, stat.mtime_unix_nanos));
        if self.send(
            Pending { request, path: path.to_path_buf(), expect, file_id: Some(file_id), usn },
            cx,
        ) && stat.is_dir
        {
            // What was inside a folder that arrived whole (moved in) never got its own signal.
            for child in cx.local.children(path) {
                if done.insert(child.clone()) {
                    if let Some(child_stat) = cx.local.stat(&child) {
                        self.on_present(&child, &child_stat, cx, done);
                    }
                }
            }
        }
    }

    fn on_replaced(&self, path: &Path, stat: &LocalStat, id: &[u8], cx: &mut Ctx<'_>) {
        let Some(item) = cx.shown.get(id).cloned() else { return };
        self.edit(path, stat, id, &item, Edit { content: true, ..Edit::default() }, cx);
    }
    fn on_known(
        &self,
        path: &Path,
        stat: &LocalStat,
        id: &[u8],
        parent_item: &[u8],
        name: &str,
        cx: &mut Ctx<'_>,
    ) {
        let Some(item) = cx.shown.get(id).cloned() else { return };
        let moved = parent_item != item.parent_item_id.as_slice();
        let renamed = name != item.name;
        let in_sync = stat.placeholder.as_ref().is_none_or(|p| p.in_sync);
        // A placeholder that is not in sync has bytes the daemon has not seen, and size and time
        // cannot rule that out (a same-size save can keep its time): its bytes are always copied,
        // so that the in-sync mark is only ever given for bytes that carry a USN.
        let content_changed = !item.directory && !in_sync;
        if !moved && !renamed && !content_changed {
            return;
        }
        // The name may be held by another item that this file replaced (an editor saving
        // through a temporary file that is renamed over the original): that item goes first.
        let displaced = cx
            .shown
            .iter()
            .find(|(other, shown)| other.as_slice() != id && shown.path == path)
            .map(|(other, shown)| (other.clone(), shown.clone()));
        if let Some((other, shown)) = displaced {
            self.delete(&other, &shown, cx);
            if cx.shown.contains_key(&other) {
                // Not deleted (the daemon was busy): do this again from the start later.
                cx.report.retry.insert(path.to_path_buf());
                return;
            }
        }
        let edit = Edit {
            new_parent: moved.then(|| parent_item.to_vec()),
            new_name: renamed.then(|| name.to_string()),
            content: content_changed,
        };
        self.edit(path, stat, id, &item, edit, cx);
    }
    fn edit(
        &self,
        path: &Path,
        stat: &LocalStat,
        id: &[u8],
        item: &ShownItem,
        edit: Edit,
        cx: &mut Ctx<'_>,
    ) {
        let Edit { new_parent, new_name, content } = edit;
        if cx.hold(path) {
            return;
        }
        let Some(mut request) = self.begin(ProviderChangeKind::Modify, path, cx) else { return };
        request.item_id = id.to_vec();
        request.base_version_hash = item.content_version.clone();
        if new_parent.is_some() || new_name.is_some() {
            // The folder the item leaves is the one the user saw it in.
            request.parent_generation = Some(item.parent_generation);
        }
        request.parent_item_id = new_parent;
        request.name = new_name;
        request.entry_kind =
            if item.directory { EntryKind::Directory as i32 } else { EntryKind::File as i32 };
        request.metadata = Some(ProviderItemMetadata {
            mtime_unix_nanos: Some(stat.mtime_unix_nanos),
            ..Default::default()
        });
        let mut usn = None;
        if content {
            match cx.local.copy_to_ingest(path) {
                Ok(copy) => {
                    usn = Some(copy.usn);
                    request.content = Some(content_of(&copy));
                }
                Err(CopyError::Unstable(why)) => {
                    eprintln!(
                        "yadorilink-cfapi-host: {} is still changing ({why})",
                        path.display()
                    );
                    cx.report.retry.insert(path.to_path_buf());
                    return;
                }
                Err(CopyError::Failed(why)) => {
                    cx.report.refused.push((path.to_path_buf(), why));
                    return;
                }
            }
        }
        let Some(file_id) = stat.file_id else {
            cx.report.retry.insert(path.to_path_buf());
            return;
        };
        let expect = (!item.directory).then_some((stat.size, stat.mtime_unix_nanos));
        self.send(
            Pending { request, path: path.to_path_buf(), expect, file_id: Some(file_id), usn },
            cx,
        );
    }

    fn delete(&self, id: &[u8], item: &ShownItem, cx: &mut Ctx<'_>) {
        if cx.hold(&item.path) {
            return;
        }
        let Some(mut request) = self.begin(ProviderChangeKind::Delete, &item.path, cx) else {
            return;
        };
        request.item_id = id.to_vec();
        request.base_version_hash = item.content_version.clone();
        request.entry_kind =
            if item.directory { EntryKind::Directory as i32 } else { EntryKind::File as i32 };
        request.recursive =
            item.directory && cx.shown.values().any(|other| other.parent_item_id == id);
        self.send(
            Pending { request, path: item.path.clone(), expect: None, file_id: None, usn: None },
            cx,
        );
    }

    /// Journals a new `pending` (no journal exists then: a pass never starts one over another),
    /// sends it, and acts on the answer. True when the daemon accepted it.
    fn send(&self, pending: Pending, cx: &mut Ctx<'_>) -> bool {
        if let Err(error) = write_new(&self.pending_file(), &pending.encode()) {
            cx.report
                .refused
                .push((pending.path.clone(), format!("could not journal the change: {error}")));
            return false;
        }
        self.dispatch(pending, cx)
    }

    /// Sends a journaled operation and acts on the answer. The journal is only ever removed
    /// here, never rewritten: the one record of the operation's identity stays as it was
    /// written until the operation is settled.
    fn dispatch(&self, pending: Pending, cx: &mut Ctx<'_>) -> bool {
        let Some(response) = cx.api.apply(&self.root_id, pending.request.clone()) else {
            // Unanswered: the journal keeps the operation, a later pass sends it again, and
            // nothing else is started over it.
            cx.blocked = true;
            cx.report.retry.insert(pending.path.clone());
            return false;
        };
        let accepted = self.settle(&pending, &response, cx);
        if accepted && (cx.effect_failed || !cx.api.save_shown(&self.root_id, cx.shown)) {
            // The effect or the record of the result is not done: keep the journal. The same request is sent again
            // (same session, sequence and id) and settled before anything new starts.
            eprintln!(
                "yadorilink-cfapi-host: could not record the result of an accepted change; keeping its journal"
            );
            cx.blocked = true;
            cx.report.retry.insert(pending.path.clone());
            return accepted;
        }
        if !accepted && cx.effect_failed {
            // A kept-local step that did not complete (only that path fails an effect without an
            // accepted answer): the same request is settled again, never retired half done.
            cx.blocked = true;
            return false;
        }
        if !accepted && !response.ok && transient(&response) {
            // The daemon was not ready to look at the request (it may have accepted this very
            // request before and lost the answer, or the answer's result was not recorded): the
            // same request is sent again, never retired into a new operation.
            cx.blocked = true;
            return false;
        }
        let _ = std::fs::remove_file(self.pending_file());
        accepted
    }

    /// The effect of an accepted answer on the disk: binding the path to the item, or removing
    /// the file a conflicting answer replaced. It can be run again after a crash: it looks at
    /// what is there, applies the effect only to the object that was journaled (stable file
    /// identity, and the size and time that were sent for a file), and does nothing when the
    /// effect is already there. True when the item must not be shown (it was replaced).
    fn apply_to_disk(
        &self,
        pending: &Pending,
        item: &ProviderAppliedItem,
        concurrent: bool,
        cx: &mut Ctx<'_>,
    ) -> bool {
        let conflict = concurrent && pending.request.content.is_some();
        let Some(now) = cx.local.stat(&pending.path) else {
            let missing = cx.local.confirmed_missing(&pending.path);
            if conflict && missing {
                // Already replaced before a crash. Not shown until the fresh look puts it back.
                cx.shown.remove(&item.item_id);
                return true;
            }
            // Not inspectable right now is not "gone": the object is unknown, nothing is
            // applied or recorded, and the journal stays until it can be told. Only a confirmed
            // missing path is looked at again as it is.
            if !missing {
                // Not shown either: the host saves the shown items after every pass.
                cx.effect_failed = true;
                cx.shown.remove(&item.item_id);
                cx.report.retry.insert(pending.path.clone());
                return true;
            }
            cx.report.retry.insert(pending.path.clone());
            return false;
        };
        if now.file_id.is_none() {
            // Readable, but which object it is cannot be told yet: same as not inspectable.
            cx.effect_failed = true;
            cx.shown.remove(&item.item_id);
            cx.report.retry.insert(pending.path.clone());
            return true;
        }
        // Without a usable identity nothing is applied (a journal from before identities are
        // recorded included).
        let Some(file_id) = pending.file_id.filter(|id| now.file_id == Some(*id)) else {
            // Another object holds the name (or the journaled one cannot be told): it is not
            // bound to the item and not removed. The item is not shown at this path either, so
            // the object there is never read as the item's own; a fresh look decides.
            cx.shown.remove(&item.item_id);
            cx.report.rewalk = true;
            cx.report.retry.insert(pending.path.clone());
            return true;
        };
        let bound = now
            .placeholder
            .as_ref()
            .is_some_and(|p| p.in_sync && p.item_id.as_deref() == Some(item.item_id.as_slice()));
        if bound {
            // Already bound to the item (the effect ran before a crash). A conflicting answer's
            // file is gone and this is the current version: never the file to remove.
            if conflict {
                cx.shown.remove(&item.item_id);
            }
            return conflict;
        }
        let same_object = pending.expect.is_none_or(|(size, mtime)| {
            now.size == size && (now.mtime_unix_nanos - mtime).abs() <= 200
        });
        if !same_object {
            // Not what the request described (written to again while the daemon was answering,
            // or another object holds the name): left as it is and looked at again. The item is
            // shown as the daemon now has it, so the difference is what the next pass sends.
            cx.report.retry.insert(pending.path.clone());
            return false;
        }
        if conflict {
            // The item moved on since the version the user edited: the daemon kept the user's
            // bytes beside it as a conflict copy and answered with the current item. The file is
            // not that item's content, so it is not bound to it; it is removed (the bytes are the
            // conflict copy's) and the fresh look shows the current content and the copy.
            // The bytes must be the copied ones: without a USN of the copy nothing is removed.
            let discarded = match pending.usn {
                Some(usn) => cx.local.discard(&pending.path, file_id, Some(usn)),
                None => Err(AdoptError::Changed),
            };
            match discarded {
                Ok(()) => {}
                // Saved again after the copy (or no USN of the copy was journaled): the file is
                // not the bytes the conflict copy holds, so it is kept, and the journal is
                // retired (a replay could only refuse again). The shown entry stays: it holds
                // the version the user edited, the base of the next save. Dropping it would let
                // the walk re-base the dirty file on the daemon's current version, and the next
                // Modify would overwrite the remote edit.
                Err(AdoptError::Changed) => {
                    cx.report.rewalk = true;
                    cx.report.retry.insert(pending.path.clone());
                    return true;
                }
                Err(AdoptError::Failed(error)) => {
                    eprintln!(
                        "yadorilink-cfapi-host: could not replace {} with the current version: {error}",
                        pending.path.display()
                    );
                    cx.effect_failed = true;
                    cx.report.retry.insert(pending.path.clone());
                    return false;
                }
            }
            // Not shown until the fresh look puts it back: the missing path must not read as
            // the user deleting the current item.
            cx.shown.remove(&item.item_id);
            return true;
        }
        if pending.request.content.is_none() && pending.request.entry_kind == EntryKind::File as i32
        {
            // A rename or move of a file carries no bytes: the placeholder keeps its identity and
            // the daemon took only a namespace operation, so there is nothing to mark in sync (and
            // no USN to guard it with). A file that is not in sync has bytes the daemon has not
            // seen: they are copied, with their USN, by the next pass.
            if !now.placeholder.as_ref().is_none_or(|p| p.in_sync) {
                cx.report.retry.insert(pending.path.clone());
            }
            return false;
        }
        let is_file = pending.request.entry_kind == EntryKind::File as i32;
        // Fail closed: bytes were sent, so the bind needs the USN they were copied at.
        if is_file && pending.usn.is_none() {
            // Not marked, and the journal is retired (a replay could never gain a USN): the file
            // stays not in sync, so the next pass copies it again, with its USN.
            eprintln!(
                "yadorilink-cfapi-host: {} has no recorded USN; not marking it in sync",
                pending.path.display()
            );
            cx.report.retry.insert(pending.path.clone());
            return false;
        }
        match cx.local.adopt(&pending.path, &item.item_id, file_id, pending.usn) {
            Ok(()) => {}
            // Written to after the copy: the file stays not in sync, so the next pass copies it
            // again; the item is shown as the daemon has it, so the difference is what that pass
            // sends. The journal is retired: the answer was acted on, correctly.
            Err(AdoptError::Changed) => {
                cx.report.retry.insert(pending.path.clone());
            }
            Err(AdoptError::Failed(error)) => {
                eprintln!(
                    "yadorilink-cfapi-host: could not bind {} to its item: {error}",
                    pending.path.display()
                );
                cx.effect_failed = true;
                cx.report.rewalk = true;
                cx.report.retry.insert(pending.path.clone());
            }
        }
        false
    }

    /// The daemon wants the user's bytes kept under `suggested`, as a new item of their own. The
    /// step is rename, then unbind, and it can be run again after a failure or a crash: it looks at
    /// the journaled object (`pending.file_id`) and does what is still missing. A repeat may be
    /// given another name, so an object renamed earlier is found by its identity, not by the name.
    /// The journal is retired only once the kept file is unbound (or the step is refused for
    /// good), never inferred from what is left on the disk.
    fn keep_local(&self, pending: &Pending, suggested: &str, cx: &mut Ctx<'_>) {
        let refuse = |cx: &mut Ctx<'_>| {
            cx.report.refused.push((pending.path.clone(), "kept local; no usable name".into()));
        };
        // Not inspectable right now is neither done nor refused: the journal stays, and the kept
        // file (where it is known) is looked at again, so a walk does not take it for stale.
        let unknown = |cx: &mut Ctx<'_>, kept: Option<&Path>| {
            cx.effect_failed = true;
            cx.report.retry.insert(pending.path.clone());
            if let Some(kept) = kept {
                cx.report.retry.insert(kept.to_path_buf());
            }
        };
        let Some(file_id) = pending.file_id else { return refuse(cx) };
        if suggested.is_empty() || !crate::namespace_policy::valid_component(suggested) {
            return refuse(cx);
        }
        let target = pending.path.with_file_name(suggested);
        let holds =
            |stat: &Option<LocalStat>| stat.as_ref().and_then(|s| s.file_id) == Some(file_id);
        // Readable but of unknown identity is not "another object": it is told later.
        let unidentified =
            |stat: &Option<LocalStat>| stat.as_ref().is_some_and(|s| s.file_id.is_none());
        let source = cx.local.stat(&pending.path);
        if (source.is_none() && !cx.local.confirmed_missing(&pending.path)) || unidentified(&source)
        {
            return unknown(cx, None);
        }
        let at_target = cx.local.stat(&target);
        let kept = if holds(&source) {
            if at_target.is_some() {
                // Another object holds the proposed name.
                return refuse(cx);
            }
            if !cx.local.confirmed_missing(&target) {
                return unknown(cx, None);
            }
            if cx.local.rename(&pending.path, &target).is_err() {
                return refuse(cx);
            }
            target
        } else if unidentified(&at_target)
            || (at_target.is_none() && !cx.local.confirmed_missing(&target))
        {
            return unknown(cx, None);
        } else if holds(&at_target) {
            // Renamed before a failure or a crash.
            target
        } else {
            match cx.local.locate(&self.root_path, &pending.request.item_id) {
                Located::Found(found) => {
                    let there = cx.local.stat(&found);
                    if unidentified(&there) {
                        return unknown(cx, Some(&found));
                    }
                    if !holds(&there) {
                        return refuse(cx);
                    }
                    found
                }
                Located::Unknown => return unknown(cx, None),
                // The journaled object is not at the source, the proposed name or anywhere
                // else the old item still marks.
                Located::Absent => return refuse(cx),
            }
        };
        // The kept bytes are the user's own file now, not that item's.
        let Some(now) = cx.local.stat(&kept).filter(|s| s.file_id == Some(file_id)) else {
            return unknown(cx, Some(&kept));
        };
        if now.placeholder.is_some() {
            if let Err(error) = cx.local.unbind(&kept) {
                eprintln!(
                    "yadorilink-cfapi-host: could not unbind {} after keeping it local: {error}",
                    kept.display()
                );
                return unknown(cx, Some(&kept));
            }
        }
        cx.report.rewalk = true;
        cx.report.retry.insert(kept);
    }

    fn settle(
        &self,
        pending: &Pending,
        response: &ProviderApplyChangeResponse,
        cx: &mut Ctx<'_>,
    ) -> bool {
        let request = &pending.request;
        match verdict(response) {
            Verdict::Accepted(item, concurrent) => {
                cx.report.applied += 1;
                cx.report.rewalk |= concurrent;
                // What is inside a folder that moved or was renamed is at new paths now.
                cx.report.rewalk |= request.entry_kind == EntryKind::Directory as i32
                    && request.kind == ProviderChangeKind::Modify as i32
                    && (request.name.is_some() || request.parent_item_id.is_some());
                if request.kind == ProviderChangeKind::Delete as i32 {
                    forget(cx.shown, &request.item_id);
                } else if let Some(item) = item {
                    if self.apply_to_disk(pending, &item, concurrent, cx) {
                        return true;
                    }
                    cx.shown.insert(item.item_id.clone(), shown_of(&pending.path, &item));
                }
                true
            }
            Verdict::Retry => {
                cx.report.retry.insert(pending.path.clone());
                false
            }
            Verdict::Gone => {
                // The shown base is obsolete until the walk: no other change of this pass is
                // authored from it.
                cx.blocked = true;
                if request.kind == ProviderChangeKind::Delete as i32 {
                    // The delete is not repeated or re-authored from a new base the user never
                    // saw: the observation is dropped and the walk shows what the daemon has.
                    forget(cx.shown, &request.item_id);
                    cx.report.rewalk = true;
                } else {
                    // The version the user saw is gone: look again, then judge the file again.
                    cx.report.rewalk = true;
                    cx.report.retry.insert(pending.path.clone());
                }
                false
            }
            Verdict::KeepLocal(suggested) => {
                self.keep_local(pending, &suggested, cx);
                false
            }
            Verdict::Refused(reason) => {
                cx.report.refused.push((pending.path.clone(), reason));
                // A repeat of the same request would be refused the same way; look again instead.
                cx.report.rewalk = true;
                false
            }
        }
    }
}

fn content_of(copy: &IngestCopy) -> ProviderContentSource {
    ProviderContentSource {
        ingest_name: copy.name.clone(),
        size: copy.size,
        sha256: copy.sha256.clone(),
    }
}

fn shown_of(path: &Path, item: &ProviderAppliedItem) -> ShownItem {
    ShownItem {
        path: path.to_path_buf(),
        parent_item_id: item.parent_item_id.clone(),
        name: item.name.clone(),
        directory: item.entry_kind == EntryKind::Directory as i32,
        size: item.size,
        mtime_unix_nanos: item.mtime_unix_nanos,
        content_version: item.content_version.clone(),
        parent_generation: item.parent_generation,
    }
}

/// Removes `id` and everything below it from the shown items.
fn forget(shown: &mut ShownItems, id: &[u8]) {
    let mut gone = vec![id.to_vec()];
    while let Some(next) = gone.pop() {
        shown.remove(&next);
        gone.extend(shown.iter().filter(|(_, i)| i.parent_item_id == next).map(|(k, _)| k.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const ROOT: &str = r"C:\sync";

    /// A path below the fixture root. The fixtures spell separators the Windows way; on another
    /// platform they become the platform's own, so the tests run everywhere.
    fn p(rel: &str) -> PathBuf {
        PathBuf::from(ROOT).join(rel.replace('\\', std::path::MAIN_SEPARATOR_STR))
    }

    fn item(rel: &str, id: u8, parent: u8, directory: bool, size: u64) -> (Vec<u8>, ShownItem) {
        (
            vec![id; 16],
            ShownItem {
                path: p(rel),
                parent_item_id: if parent == 0 { vec![] } else { vec![parent; 16] },
                name: rel.rsplit('\\').next().unwrap().to_string(),
                directory,
                size,
                mtime_unix_nanos: 1_000,
                content_version: vec![id; 40],
                parent_generation: 5,
            },
        )
    }

    #[derive(Default)]
    struct FakeLocal {
        entries: RefCell<HashMap<PathBuf, LocalStat>>,
        children: RefCell<HashMap<PathBuf, Vec<PathBuf>>>,
        adopted: RefCell<Vec<(PathBuf, Vec<u8>)>>,
        copies: RefCell<u32>,
        unstable: RefCell<bool>,
        located: RefCell<HashMap<Vec<u8>, PathBuf>>,
        discarded: RefCell<Vec<PathBuf>>,
        unbound: RefCell<Vec<PathBuf>>,
        unsearchable: RefCell<bool>,
        unreadable: RefCell<HashSet<PathBuf>>,
        ids: RefCell<HashMap<PathBuf, u128>>,
        /// Stops the process at the disk effect, like a crash before it ran.
        crash_at_effect: std::cell::Cell<bool>,
        adopt_fails: std::cell::Cell<bool>,
        /// How many of the next unbinds fail.
        unbind_failures: std::cell::Cell<u32>,
        /// Stops the process at the unbind, like a crash after the rename.
        crash_at_unbind: std::cell::Cell<bool>,
        /// How many times the fake user saved the file again after it was copied: each moves the
        /// file's USN and nothing else (same file id, size and time).
        resaves: std::cell::Cell<i64>,
        /// The path cannot be inspected right now (and is not confirmed missing).
        stat_unavailable: std::rc::Rc<std::cell::Cell<bool>>,
        /// Metadata is readable but the object's identity is not.
        ids_unavailable: std::rc::Rc<std::cell::Cell<bool>>,
    }

    impl FakeLocal {
        fn file(&self, rel: &str, size: u64, placeholder: Option<(u8, bool)>) {
            self.entries.borrow_mut().insert(
                p(rel),
                LocalStat {
                    is_dir: false,
                    is_symlink: false,
                    file_id: None,
                    size,
                    mtime_unix_nanos: 9_999,
                    placeholder: placeholder.map(|(id, in_sync)| PlaceholderInfo {
                        item_id: Some(vec![id; 16]),
                        in_sync,
                        is_dir: false,
                        size,
                        mtime_ticks: 0,
                        dehydrated: false,
                    }),
                },
            );
        }
        fn dir(&self, rel: &str, placeholder: Option<u8>) {
            self.entries.borrow_mut().insert(
                p(rel),
                LocalStat {
                    is_dir: true,
                    is_symlink: false,
                    file_id: None,
                    size: 0,
                    mtime_unix_nanos: 9_999,
                    placeholder: placeholder.map(|id| PlaceholderInfo {
                        item_id: Some(vec![id; 16]),
                        in_sync: true,
                        is_dir: true,
                        size: 0,
                        mtime_ticks: 0,
                        dehydrated: false,
                    }),
                },
            );
        }
    }

    impl Local for FakeLocal {
        fn stat(&self, path: &Path) -> Option<LocalStat> {
            if self.stat_unavailable.get() {
                return None;
            }
            let mut stat = self.entries.borrow().get(path).cloned()?;
            stat.file_id = (!self.ids_unavailable.get())
                .then(|| self.ids.borrow().get(path).copied().unwrap_or(1_000));
            Some(stat)
        }
        fn children(&self, directory: &Path) -> Vec<PathBuf> {
            self.children.borrow().get(directory).cloned().unwrap_or_default()
        }
        fn copy_to_ingest(&self, _path: &Path) -> Result<IngestCopy, CopyError> {
            if *self.unstable.borrow() {
                return Err(CopyError::Unstable("busy".into()));
            }
            *self.copies.borrow_mut() += 1;
            Ok(IngestCopy {
                name: format!("copy{}", self.copies.borrow()),
                size: 3,
                sha256: vec![1; 32],
                usn: 100 + self.resaves.get(),
            })
        }
        fn adopt(
            &self,
            path: &Path,
            item_id: &[u8],
            _file_id: u128,
            usn: Option<i64>,
        ) -> Result<(), AdoptError> {
            assert!(!self.crash_at_effect.get(), "crash before the effect");
            if self.adopt_fails.get() {
                return Err(AdoptError::Failed("busy".into()));
            }
            // A file with bytes is only ever bound with the USN of its copy.
            let is_dir = self.entries.borrow().get(path).is_some_and(|s| s.is_dir);
            assert_eq!(usn.is_some(), !is_dir, "a file is bound with a USN, a folder without");
            if usn.is_some_and(|u| u != 100 + self.resaves.get()) {
                return Err(AdoptError::Changed);
            }
            if let Some(stat) = self.entries.borrow_mut().get_mut(path) {
                stat.placeholder = Some(PlaceholderInfo {
                    item_id: Some(item_id.to_vec()),
                    in_sync: true,
                    is_dir: stat.is_dir,
                    size: stat.size,
                    mtime_ticks: 0,
                    dehydrated: false,
                });
            }
            self.adopted.borrow_mut().push((path.to_path_buf(), item_id.to_vec()));
            Ok(())
        }
        fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            let mut entries = self.entries.borrow_mut();
            let Some(entry) = entries.remove(from) else {
                return Err(std::io::ErrorKind::NotFound.into());
            };
            entries.insert(to.to_path_buf(), entry);
            let mut ids = self.ids.borrow_mut();
            if let Some(id) = ids.remove(from) {
                ids.insert(to.to_path_buf(), id);
            }
            Ok(())
        }
        fn unbind(&self, path: &Path) -> Result<(), String> {
            assert!(!self.crash_at_unbind.get(), "crash before the unbind");
            if self.unbind_failures.get() > 0 {
                self.unbind_failures.set(self.unbind_failures.get() - 1);
                return Err("busy".into());
            }
            if let Some(stat) = self.entries.borrow_mut().get_mut(path) {
                stat.placeholder = None;
            }
            self.unbound.borrow_mut().push(path.to_path_buf());
            Ok(())
        }
        fn discard(&self, path: &Path, _file_id: u128, usn: Option<i64>) -> Result<(), AdoptError> {
            assert!(!self.crash_at_effect.get(), "crash before the effect");
            assert!(usn.is_some(), "a file is discarded only with the USN of its copy");
            if usn.is_some_and(|u| u != 100 + self.resaves.get()) {
                return Err(AdoptError::Changed);
            }
            self.entries.borrow_mut().remove(path);
            self.discarded.borrow_mut().push(path.to_path_buf());
            Ok(())
        }
        fn locate(&self, _root: &Path, item_id: &[u8]) -> Located {
            if *self.unsearchable.borrow() {
                return Located::Unknown;
            }
            match self.located.borrow().get(item_id) {
                Some(path) => Located::Found(path.clone()),
                None => Located::Absent,
            }
        }
        fn confirmed_missing(&self, path: &Path) -> bool {
            !self.stat_unavailable.get() && !self.unreadable.borrow().contains(path)
        }
    }

    #[derive(Default)]
    struct FakeApi {
        requests: RefCell<Vec<ProviderApplyChangeRequest>>,
        answers: RefCell<Vec<Option<ProviderApplyChangeResponse>>>,
        /// Runs after a request arrives and before its answer, like the user writing meanwhile.
        before_answer: RefCell<Option<Box<dyn Fn()>>>,
        /// What the last successful `save_shown` recorded: the file a restart loads.
        durable: RefCell<ShownItems>,
        save_fails: std::cell::Cell<bool>,
    }

    impl FakeApi {
        fn accept(&self, item: ProviderAppliedItem) {
            self.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
                ok: true,
                outcome: ProviderApplyOutcome::Applied as i32,
                item: Some(item),
                ..Default::default()
            }));
        }
        fn accept_delete(&self) {
            self.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
                ok: true,
                outcome: ProviderApplyOutcome::Applied as i32,
                ..Default::default()
            }));
        }
        fn fail(&self, failure: ProviderApplyFailure) {
            self.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
                ok: false,
                failure: failure as i32,
                ..Default::default()
            }));
        }
    }

    impl Api for FakeApi {
        fn save_shown(&self, _root: &[u8], shown: &ShownItems) -> bool {
            if self.save_fails.get() {
                return false;
            }
            *self.durable.borrow_mut() = shown.clone();
            true
        }

        fn apply(
            &self,
            _root: &[u8],
            request: ProviderApplyChangeRequest,
        ) -> Option<ProviderApplyChangeResponse> {
            self.requests.borrow_mut().push(request);
            if let Some(hook) = self.before_answer.borrow_mut().take() {
                hook();
            }
            if self.answers.borrow().is_empty() {
                None
            } else {
                self.answers.borrow_mut().remove(0)
            }
        }
    }

    fn applied(id: u8, parent: u8, name: &str, directory: bool) -> ProviderAppliedItem {
        ProviderAppliedItem {
            item_id: vec![id; 16],
            parent_item_id: if parent == 0 { vec![] } else { vec![parent; 16] },
            name: name.into(),
            entry_kind: if directory {
                EntryKind::Directory as i32
            } else {
                EntryKind::File as i32
            },
            content_version: vec![id; 40],
            size: 3,
            mtime_unix_nanos: 9_999,
            parent_generation: 7,
            ..Default::default()
        }
    }

    fn setup(tag: &str) -> (Authoring, PathBuf) {
        let dir = std::env::temp_dir().join(format!("yl-auth-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap(), dir)
    }

    fn signals(paths: &[PathBuf]) -> BTreeSet<PathBuf> {
        paths.iter().cloned().collect()
    }

    #[test]
    fn a_new_file_is_created_under_its_folder_and_becomes_the_daemons_item() {
        let (auth, dir) = setup("create");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("new.txt", 3, None);
        api.accept(applied(7, 0, "new.txt", false));
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("new.txt")]), &mut shown, &local, &api);
        let request = api.requests.borrow()[0].clone();
        assert_eq!(request.kind, ProviderChangeKind::Create as i32);
        assert_eq!(request.name.as_deref(), Some("new.txt"));
        assert_eq!(request.parent_item_id, Some(vec![]));
        assert_eq!(request.content.as_ref().unwrap().ingest_name, "copy1");
        assert_eq!(report.applied, 1);
        assert_eq!(local.adopted.borrow()[0], (p("new.txt"), vec![7; 16]));
        assert!(shown.contains_key(&vec![7; 16]));
        assert!(!auth.pending_file().exists(), "the journal outlived the answer");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_folder_is_created_before_what_is_inside_it_and_what_moved_in_whole_is_found() {
        let (auth, dir) = setup("folder");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.dir("album", None);
        local.file("album\\a.jpg", 3, None);
        local.children.borrow_mut().insert(p("album"), vec![p("album\\a.jpg")]);
        api.accept(applied(8, 0, "album", true));
        api.accept(applied(9, 8, "a.jpg", false));
        let mut shown = ShownItems::new();
        // Only the folder is signalled; its child arrived inside it.
        auth.process(&signals(&[p("album")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].entry_kind, EntryKind::Directory as i32);
        assert_eq!(requests[1].parent_item_id, Some(vec![8; 16]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_edited_placeholder_is_a_modify_based_on_the_version_the_user_saw() {
        let (auth, dir) = setup("edit");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.accept(applied(3, 0, "doc.txt", false));
        auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        let request = api.requests.borrow()[0].clone();
        assert_eq!(request.kind, ProviderChangeKind::Modify as i32);
        assert_eq!(request.item_id, vec![3; 16]);
        assert_eq!(request.base_version_hash, vec![3; 40]);
        assert!(request.content.is_some());
        assert!(request.name.is_none() && request.parent_item_id.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A file written to after its bytes were copied and before the daemon answered is not marked
    /// in sync: what the daemon accepted is not what is on the disk.
    #[test]
    fn a_file_written_to_while_the_daemon_answers_is_not_adopted_as_in_sync() {
        let (auth, dir) = setup("raced");
        let local = std::rc::Rc::new(FakeLocal::default());
        let api = FakeApi::default();
        local.file("a.txt", 3, None);
        api.accept(applied(7, 0, "a.txt", false));
        let racing = local.clone();
        *api.before_answer.borrow_mut() = Some(Box::new(move || {
            racing.file("a.txt", 99, None); // written to again
        }));
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &*local, &api);
        assert!(local.adopted.borrow().is_empty(), "adopted a file that changed after the copy");
        assert!(report.retry.contains(&p("a.txt")));
        assert!(shown.contains_key(&vec![7; 16]), "the accepted item must be known");
        // The next look sees the plain file at the item's path and sends its new bytes.
        api.accept(applied(7, 0, "a.txt", false));
        auth.process(&signals(&[p("a.txt")]), &mut shown, &*local, &api);
        assert_eq!(api.requests.borrow()[1].kind, ProviderChangeKind::Modify as i32);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The same file object saved again after its bytes were copied: same file id, size and time,
    /// only its USN moved. The old bytes are not what is on the disk, so it is not marked in sync;
    /// the next pass copies the new bytes and only then binds.
    #[test]
    fn a_file_saved_again_after_ingest_with_the_same_id_size_and_time_is_not_adopted() {
        let (auth, dir) = setup("resave");
        let local = std::rc::Rc::new(FakeLocal::default());
        let api = FakeApi::default();
        local.file("a.txt", 3, None);
        api.accept(applied(7, 0, "a.txt", false));
        let racing = local.clone();
        *api.before_answer.borrow_mut() = Some(Box::new(move || racing.resaves.set(1)));
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &*local, &api);
        assert!(local.adopted.borrow().is_empty(), "marked in sync with a stale version");
        assert!(report.retry.contains(&p("a.txt")), "the new bytes must be sent next pass");
        assert!(shown.contains_key(&vec![7; 16]));
        // The next pass copies the file again, at its new USN, and binds that.
        api.accept(applied(7, 0, "a.txt", false));
        auth.process(&signals(&[p("a.txt")]), &mut shown, &*local, &api);
        assert_eq!(local.adopted.borrow().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The same for an edited placeholder, whose in-sync mark is the dangerous one.
    #[test]
    fn an_edited_placeholder_saved_again_after_ingest_stays_not_in_sync() {
        let (auth, dir) = setup("resave-edit");
        let local = std::rc::Rc::new(FakeLocal::default());
        let api = FakeApi::default();
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.accept(applied(3, 0, "doc.txt", false));
        let racing = local.clone();
        *api.before_answer.borrow_mut() = Some(Box::new(move || racing.resaves.set(1)));
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &*local, &api);
        assert!(local.adopted.borrow().is_empty());
        assert!(!local.stat(&p("doc.txt")).unwrap().placeholder.unwrap().in_sync);
        assert!(report.retry.contains(&p("doc.txt")));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A conflicting answer discards the user's file (its bytes are the conflict copy's): not a
    /// file that was saved again after the copy.
    #[test]
    fn a_file_saved_again_after_ingest_is_not_discarded_by_a_conflicting_answer() {
        let (auth, dir) = setup("resave-discard");
        let local = std::rc::Rc::new(FakeLocal::default());
        let api = FakeApi::default();
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.answers.borrow_mut().push(Some(concurrent_answer()));
        let racing = local.clone();
        *api.before_answer.borrow_mut() = Some(Box::new(move || racing.resaves.set(1)));
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &*local, &api);
        assert!(local.stat(&p("doc.txt")).is_some(), "the re-saved file was discarded");
        assert!(report.retry.contains(&p("doc.txt")));
        assert!(!auth.pending_file().exists(), "a journal that can only refuse again was kept");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The user's re-save after a conflicting answer keeps the base the edit was made from: the
    /// item must stay shown at the version the user edited, not at the daemon's current one, or the
    /// next Modify is based on the remote edit and fast-forwards over it.
    #[test]
    fn a_conflict_answer_whose_discard_is_refused_keeps_the_original_base_for_the_next_modify() {
        let (auth, dir) = setup("changed-keeps-base");
        let local = std::rc::Rc::new(FakeLocal::default());
        let api = FakeApi::default();
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        let mut current = applied(3, 0, "doc.txt", false);
        current.content_version = vec![9; 40]; // the remote edit
        api.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
            ok: true,
            outcome: ProviderApplyOutcome::Concurrent as i32,
            item: Some(current),
            ..Default::default()
        }));
        let racing = local.clone();
        *api.before_answer.borrow_mut() = Some(Box::new(move || racing.resaves.set(1)));
        auth.process(&signals(&[p("doc.txt")]), &mut shown, &*local, &api);
        let kept = shown.get(&vec![3; 16]).expect("the item was dropped from the shown items");
        assert_eq!(kept.content_version, vec![3; 40], "the base moved to the remote edit");
        // The next pass sends the re-saved bytes, still based on the version the user edited.
        api.accept(applied(3, 0, "doc.txt", false));
        auth.process(&signals(&[p("doc.txt")]), &mut shown, &*local, &api);
        let next = api.requests.borrow().last().unwrap().clone();
        assert_eq!(next.base_version_hash, vec![3; 40]);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A journal that carries bytes but no USN (never written by this code) fails closed: the
    /// file is not marked in sync.
    #[test]
    fn a_journal_with_bytes_and_no_usn_never_marks_the_file_in_sync() {
        let (auth, dir) = setup("no-usn");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        api.accept(applied(7, 0, "a.txt", false));
        crash_at_effect(&auth, &[p("a.txt")], &mut ShownItems::new(), &local, &api);
        let text = std::fs::read_to_string(auth.pending_file()).unwrap();
        assert!(text.contains("\nusn="), "the journal records the USN");
        let without: String =
            text.lines().filter(|l| !l.starts_with("usn=")).map(|l| format!("{l}\n")).collect();
        std::fs::write(auth.pending_file(), without).unwrap();

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        api.accept(applied(7, 0, "a.txt", false));
        let mut shown = ShownItems::new();
        let report = reopened.resume(&mut shown, &local, &api);
        assert!(local.adopted.borrow().is_empty(), "bound without a USN to compare");
        assert!(report.retry.contains(&p("a.txt")));
        assert!(
            !reopened.pending_file().exists(),
            "an unusable journal blocks every new operation"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A rename carries no bytes, so it never marks the file in sync; a write that lands while the
    /// daemon answers (same size and time) keeps the file dirty and is sent next pass.
    #[test]
    fn a_rename_never_marks_in_sync_a_file_that_became_dirty_while_the_daemon_answered() {
        let (auth, dir) = setup("renameracing");
        let local = std::rc::Rc::new(FakeLocal::default());
        let api = FakeApi::default();
        let mut shown: ShownItems = [item("old.txt", 3, 0, false, 10)].into();
        local.file("new.txt", 10, Some((3, true)));
        local.entries.borrow_mut().get_mut(&p("new.txt")).unwrap().mtime_unix_nanos = 1_000;
        local.located.borrow_mut().insert(vec![3; 16], p("new.txt"));
        api.accept(applied(3, 0, "new.txt", false));
        let racing = local.clone();
        *api.before_answer.borrow_mut() = Some(Box::new(move || {
            racing.file("new.txt", 10, Some((3, false)));
            racing.entries.borrow_mut().get_mut(&p("new.txt")).unwrap().mtime_unix_nanos = 1_000;
        }));
        let report =
            auth.process(&signals(&[p("old.txt"), p("new.txt")]), &mut shown, &*local, &api);
        assert!(api.requests.borrow()[0].content.is_none());
        assert!(local.adopted.borrow().is_empty(), "a rename must not mark the file in sync");
        assert!(report.retry.contains(&p("new.txt")));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A dirty placeholder whose size and time equal the daemon's and that is also renamed: its
    /// bytes are copied and the bind carries the copy's USN.
    #[test]
    fn a_dirty_placeholder_with_the_same_size_and_time_that_is_renamed_is_copied() {
        let (auth, dir) = setup("dirtyrename");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("old.txt", 3, 0, false, 10)].into();
        local.file("new.txt", 10, Some((3, false)));
        let same_time = shown[&vec![3; 16]].mtime_unix_nanos;
        local.entries.borrow_mut().get_mut(&p("new.txt")).unwrap().mtime_unix_nanos = same_time;
        local.located.borrow_mut().insert(vec![3; 16], p("new.txt"));
        api.accept(applied(3, 0, "new.txt", false));
        auth.process(&signals(&[p("old.txt"), p("new.txt")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].content.is_some(), "unsent bytes must be copied, not guessed away");
        assert_eq!(local.adopted.borrow().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A stale edit is answered with the current item and a conflict copy of the user's bytes:
    /// the file must not be bound to the current item as if it held its content.
    #[test]
    fn a_concurrent_answer_replaces_the_file_with_the_current_version_instead_of_adopting_it() {
        let (auth, dir) = setup("concurrent");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
            ok: true,
            outcome: ProviderApplyOutcome::Concurrent as i32,
            item: Some(applied(3, 0, "doc.txt", false)),
            ..Default::default()
        }));
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert!(local.adopted.borrow().is_empty(), "the edit was bound to the canonical item");
        assert_eq!(*local.discarded.borrow(), vec![p("doc.txt")]);
        assert!(report.rewalk, "the current version and the conflict copy must be shown");
        assert!(!shown.contains_key(&vec![3; 16]), "a missing path must not read as a delete");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_placeholder_that_is_in_sync_causes_no_request() {
        let (auth, dir) = setup("quiet");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 10, Some((3, true)));
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow().is_empty());
        assert_eq!(report, Report::default());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The daemon accepted a rename (V2) but the shown items that record it could not be saved,
    /// and the host died. A restart loads the older shown items (V1): the accepted operation must
    /// be sent again as the SAME request, not a new one against V1's base.
    #[test]
    fn an_accepted_change_whose_result_was_not_saved_is_replayed_after_a_restart() {
        let (auth, dir) = setup("unsaved-result");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let v1: ShownItems = [item("old.txt", 3, 0, false, 10)].into();
        *api.durable.borrow_mut() = v1.clone();
        let mut shown = v1.clone();
        local.file("new.txt", 10, Some((3, true)));
        local.located.borrow_mut().insert(vec![3; 16], p("new.txt"));
        api.accept(applied(3, 0, "new.txt", false));
        api.save_fails.set(true);

        let report =
            auth.process(&signals(&[p("old.txt"), p("new.txt")]), &mut shown, &local, &api);
        assert_eq!(report.applied, 1);
        let first = api.requests.borrow()[0].clone();
        assert_eq!(first.name.as_deref(), Some("new.txt"));
        assert!(
            auth.pending_file().exists(),
            "the journal was retired before the result was saved"
        );
        assert_eq!(*api.durable.borrow(), v1, "nothing newer was recorded");

        // Restart: the older shown items are loaded; the daemon answers the repeat from its record.
        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        let mut shown = api.durable.borrow().clone();
        api.save_fails.set(false);
        api.accept(applied(3, 0, "new.txt", false));
        let report =
            reopened.process(&signals(&[p("old.txt"), p("new.txt")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 2, "a new operation was generated: {requests:?}");
        assert_eq!(
            (
                requests[1].session_id.clone(),
                requests[1].operation_seq,
                requests[1].request_id.clone()
            ),
            (first.session_id.clone(), first.operation_seq, first.request_id.clone()),
        );
        assert_eq!(report.applied, 1);
        assert_eq!(shown[&vec![3u8; 16]].name, "new.txt");
        assert_eq!(api.durable.borrow()[&vec![3u8; 16]].name, "new.txt", "V2 is recorded");
        assert!(!reopened.pending_file().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// C9: a CREATE the daemon accepted whose shown record could not be saved keeps its identity
    /// while the host keeps running (no restart): the next pass sends the same request, never a
    /// second CREATE, and a path signalled meanwhile waits behind it.
    #[test]
    fn a_create_whose_shown_save_failed_is_retried_with_the_same_identity_in_process() {
        let (auth, dir) = setup("c9-create");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("new.txt", 3, None);
        local.file("other.txt", 3, None);
        api.accept(applied(7, 0, "new.txt", false));
        api.save_fails.set(true);
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("new.txt")]), &mut shown, &local, &api);
        assert_eq!(report.applied, 1);
        let first = api.requests.borrow()[0].clone();
        assert!(auth.pending_file().exists());
        assert!(report.retry.contains(&p("new.txt")));

        // Still failing: a signal for another path starts nothing new, the same request repeats.
        api.accept(applied(7, 0, "new.txt", false));
        let report =
            auth.process(&signals(&[p("new.txt"), p("other.txt")]), &mut shown, &local, &api);
        assert!(report.retry.contains(&p("other.txt")));
        assert!(auth.pending_file().exists());

        // The save works again: the same request settles and the journal retires.
        api.save_fails.set(false);
        api.accept(applied(7, 0, "new.txt", false));
        auth.process(&signals(&[p("new.txt")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 3, "a different operation was authored: {requests:?}");
        for repeat in &requests[1..] {
            assert_eq!(
                (&repeat.session_id, repeat.operation_seq, &repeat.request_id, repeat.kind),
                (&first.session_id, first.operation_seq, &first.request_id, first.kind),
            );
        }
        assert!(api.durable.borrow().contains_key(&vec![7u8; 16]));
        assert!(!auth.pending_file().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// C9: the daemon accepted a CREATE, its shown record was not saved, and the repeat meets a
    /// transient refusal (it can answer NotReady before it looks up its record of the request):
    /// the journal stays, so the identity is not lost and no second CREATE is authored.
    #[test]
    fn a_transient_answer_to_the_repeat_of_an_accepted_change_keeps_its_journal() {
        for failure in [ProviderApplyFailure::NotReady, ProviderApplyFailure::Retry] {
            let (auth, dir) = setup("c9-transient");
            let (local, api) = (FakeLocal::default(), FakeApi::default());
            local.file("new.txt", 3, None);
            api.accept(applied(7, 0, "new.txt", false));
            api.save_fails.set(true);
            let mut shown = ShownItems::new();
            auth.process(&signals(&[p("new.txt")]), &mut shown, &local, &api);
            let first = api.requests.borrow()[0].clone();

            api.fail(failure);
            auth.process(&signals(&[p("new.txt")]), &mut shown, &local, &api);
            assert!(auth.pending_file().exists(), "{failure:?} retired an accepted change");

            // Restart: the daemon answers the repeat from its record.
            let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
            api.save_fails.set(false);
            api.accept(applied(7, 0, "new.txt", false));
            let mut shown = api.durable.borrow().clone();
            reopened.process(&signals(&[p("new.txt")]), &mut shown, &local, &api);
            let requests = api.requests.borrow();
            assert_eq!(requests.len(), 3, "{failure:?}: {requests:?}");
            assert_eq!(requests[2].request_id, first.request_id);
            assert_eq!(requests[2].operation_seq, first.operation_seq);
            assert!(!reopened.pending_file().exists());
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// C9: a folder CREATE accepted but not recorded holds back what is inside it, so the child's
    /// request cannot take over the journal that carries the folder's identity.
    #[test]
    fn a_folder_create_whose_shown_save_failed_keeps_its_journal_from_its_children() {
        let (auth, dir) = setup("c9-folder");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.dir("album", None);
        local.file("album\\a.jpg", 3, None);
        local.children.borrow_mut().insert(p("album"), vec![p("album\\a.jpg")]);
        api.accept(applied(8, 0, "album", true));
        api.save_fails.set(true);
        let mut shown = ShownItems::new();
        auth.process(&signals(&[p("album")]), &mut shown, &local, &api);
        let first = api.requests.borrow()[0].clone();
        assert_eq!(api.requests.borrow().len(), 1, "the child was authored over the journal");
        assert_eq!(first.entry_kind, EntryKind::Directory as i32);

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        api.save_fails.set(false);
        api.accept(applied(8, 0, "album", true));
        api.accept(applied(9, 8, "a.jpg", false));
        let mut shown = api.durable.borrow().clone();
        reopened.process(&signals(&[p("album")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests[1].request_id, first.request_id);
        assert_eq!(requests[1].operation_seq, first.operation_seq);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Runs `process` and stops it at the first disk effect, as a crash would: the answer was
    /// accepted by the daemon, the journal is still on disk, the effect never ran.
    fn crash_at_effect(
        auth: &Authoring,
        paths: &[PathBuf],
        shown: &mut ShownItems,
        local: &FakeLocal,
        api: &FakeApi,
    ) {
        local.crash_at_effect.set(true);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            auth.process(&signals(paths), shown, local, api)
        }));
        local.crash_at_effect.set(false);
        assert!(outcome.is_err(), "the effect was not reached");
        assert!(auth.pending_file().exists());
    }

    /// The effect of an accepted answer is applied exactly once whether the crash came before it
    /// or after it, and a pass after the replay authors nothing more.
    #[test]
    fn a_folder_whose_binding_a_crash_prevented_is_bound_once_on_replay() {
        let (auth, dir) = setup("replay-dir-before");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.dir("album", None);
        local.ids.borrow_mut().insert(p("album"), 11);
        api.accept(applied(8, 0, "album", true));
        crash_at_effect(&auth, &[p("album")], &mut ShownItems::new(), &local, &api);
        assert!(local.adopted.borrow().is_empty());

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        let mut shown = ShownItems::new();
        api.accept(applied(8, 0, "album", true));
        reopened.process(&signals(&[p("album")]), &mut shown, &local, &api);
        assert_eq!(local.adopted.borrow().len(), 1, "{:?}", local.adopted.borrow());
        assert_eq!(shown[&vec![8u8; 16]].name, "album");
        reopened.process(&signals(&[p("album")]), &mut shown, &local, &api);
        assert_eq!(api.requests.borrow().len(), 2, "another operation was authored");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_whose_binding_a_crash_prevented_is_bound_once_on_replay() {
        let (auth, dir) = setup("replay-file-before");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        api.accept(applied(7, 0, "a.txt", false));
        crash_at_effect(&auth, &[p("a.txt")], &mut ShownItems::new(), &local, &api);

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        let mut shown = ShownItems::new();
        api.accept(applied(7, 0, "a.txt", false));
        reopened.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert_eq!(local.adopted.borrow().len(), 1);
        reopened.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert_eq!(api.requests.borrow().len(), 2, "another operation was authored");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_edited_placeholder_not_yet_marked_in_sync_by_a_crash_is_marked_once_on_replay() {
        let (auth, dir) = setup("replay-edit-before");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let v1: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.accept(applied(3, 0, "doc.txt", false));
        crash_at_effect(&auth, &[p("doc.txt")], &mut v1.clone(), &local, &api);

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        let mut shown = v1;
        api.accept(applied(3, 0, "doc.txt", false));
        reopened.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert_eq!(local.adopted.borrow().len(), 1, "never marked in sync");
        assert!(local.stat(&p("doc.txt")).unwrap().placeholder.unwrap().in_sync);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_crash_after_the_binding_does_not_bind_a_second_time() {
        let (auth, dir) = setup("replay-after");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.dir("album", None);
        local.ids.borrow_mut().insert(p("album"), 11);
        api.accept(applied(8, 0, "album", true));
        api.save_fails.set(true);
        auth.process(&signals(&[p("album")]), &mut ShownItems::new(), &local, &api);
        assert_eq!(local.adopted.borrow().len(), 1);

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        let mut shown = ShownItems::new();
        api.save_fails.set(false);
        api.accept(applied(8, 0, "album", true));
        reopened.process(&signals(&[p("album")]), &mut shown, &local, &api);
        assert_eq!(api.requests.borrow().len(), 2);
        assert_eq!(local.adopted.borrow().len(), 1, "bound twice");
        assert_eq!(shown[&vec![8u8; 16]].name, "album");
        assert!(!reopened.pending_file().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn another_folder_at_the_path_after_a_crash_is_not_bound() {
        let (auth, dir) = setup("replay-other-object");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.dir("album", None);
        local.ids.borrow_mut().insert(p("album"), 11);
        api.accept(applied(8, 0, "album", true));
        crash_at_effect(&auth, &[p("album")], &mut ShownItems::new(), &local, &api);
        // The user swapped another folder onto the name.
        local.ids.borrow_mut().insert(p("album"), 12);

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        api.accept(applied(8, 0, "album", true));
        let mut shown = ShownItems::new();
        let report = reopened.resume(&mut shown, &local, &api);
        assert!(local.adopted.borrow().is_empty(), "bound an object that was not journaled");
        assert!(report.retry.contains(&p("album")) && report.rewalk);
        assert!(shown.is_empty(), "the other folder was shown as the item's own");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_binding_keeps_the_journal_and_is_tried_again() {
        let (auth, dir) = setup("adopt-fails");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.dir("album", None);
        api.accept(applied(8, 0, "album", true));
        local.adopt_fails.set(true);
        let mut shown = ShownItems::new();
        auth.process(&signals(&[p("album")]), &mut shown, &local, &api);
        assert!(auth.pending_file().exists(), "the journal was retired with the folder unbound");
        assert!(api.durable.borrow().is_empty(), "the result was recorded as done");

        local.adopt_fails.set(false);
        api.accept(applied(8, 0, "album", true));
        auth.process(&signals(&[p("album")]), &mut shown, &local, &api);
        assert_eq!(local.adopted.borrow().len(), 1);
        assert!(!auth.pending_file().exists());
        assert!(api.durable.borrow().contains_key(&vec![8u8; 16]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_replaced_file_that_cannot_be_inspected_is_not_taken_as_discarded() {
        let (auth, dir) = setup("discard-unreadable");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let v1: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.answers.borrow_mut().push(Some(concurrent_answer()));
        crash_at_effect(&auth, &[p("doc.txt")], &mut v1.clone(), &local, &api);
        // The file is in use now: it cannot be inspected, and is not confirmed missing.
        local.entries.borrow_mut().remove(&p("doc.txt"));
        local.unreadable.borrow_mut().insert(p("doc.txt"));

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        api.answers.borrow_mut().push(Some(concurrent_answer()));
        reopened.process(&signals(&[]), &mut v1.clone(), &local, &api);
        assert!(reopened.pending_file().exists(), "the journal was retired unverified");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn another_object_already_bound_to_the_item_is_not_taken_as_the_effect_done() {
        let (auth, dir) = setup("replay-bound-other");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.dir("album", None);
        local.ids.borrow_mut().insert(p("album"), 11);
        api.accept(applied(8, 0, "album", true));
        crash_at_effect(&auth, &[p("album")], &mut ShownItems::new(), &local, &api);
        local.dir("album", Some(8));
        local.ids.borrow_mut().insert(p("album"), 12);

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        api.accept(applied(8, 0, "album", true));
        let mut shown = ShownItems::new();
        let report = reopened.resume(&mut shown, &local, &api);
        assert!(shown.is_empty() && report.rewalk);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An accepted CREATE whose object cannot be told apart right after the answer (`stat` fails
    /// transiently, or its identity is unreadable) is not bound and not recorded: the journal
    /// stays, the same request is replayed, and no second CREATE is authored.
    fn unknown_identity_keeps_the_journal(
        tag: &str,
        directory: bool,
        unavailable: fn(&FakeLocal) -> std::rc::Rc<std::cell::Cell<bool>>,
    ) {
        let (auth, dir) = setup(tag);
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let (name, id) = if directory { ("album", 8) } else { ("a.txt", 7) };
        if directory {
            local.dir(name, None);
        } else {
            local.file(name, 3, None);
        }
        api.accept(applied(id, 0, name, directory));
        let flag = unavailable(&local);
        *api.before_answer.borrow_mut() = Some(Box::new(move || flag.set(true)));
        let mut shown = ShownItems::new();
        auth.process(&signals(&[p(name)]), &mut shown, &local, &api);
        assert!(auth.pending_file().exists(), "the journal was retired unbound");
        assert!(api.durable.borrow().is_empty(), "the item was recorded as shown");
        assert!(local.adopted.borrow().is_empty());
        assert!(shown.is_empty(), "the unbound item is in the shown items the host saves");

        unavailable(&local).set(false);
        api.accept(applied(id, 0, name, directory));
        auth.process(&signals(&[p(name)]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 2, "a new operation was authored: {requests:?}");
        assert_eq!(
            (
                requests[1].session_id.clone(),
                requests[1].operation_seq,
                requests[1].request_id.clone()
            ),
            (
                requests[0].session_id.clone(),
                requests[0].operation_seq,
                requests[0].request_id.clone()
            ),
        );
        drop(requests);
        assert_eq!(local.adopted.borrow().len(), 1);
        assert!(!auth.pending_file().exists());
        assert!(api.durable.borrow().contains_key(&vec![id; 16]));
        auth.process(&signals(&[p(name)]), &mut shown, &local, &api);
        assert_eq!(api.requests.borrow().len(), 2, "another operation was authored");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_create_is_not_retired_when_it_cannot_be_inspected_after_the_answer() {
        unknown_identity_keeps_the_journal("file-stat", false, |l| l.stat_unavailable.clone());
    }

    #[test]
    fn a_folder_create_is_not_retired_when_it_cannot_be_inspected_after_the_answer() {
        unknown_identity_keeps_the_journal("folder-stat", true, |l| l.stat_unavailable.clone());
    }

    #[test]
    fn a_file_create_is_not_retired_when_its_identity_is_unreadable_after_the_answer() {
        unknown_identity_keeps_the_journal("file-id", false, |l| l.ids_unavailable.clone());
    }

    #[test]
    fn a_folder_create_is_not_retired_when_its_identity_is_unreadable_after_the_answer() {
        unknown_identity_keeps_the_journal("folder-id", true, |l| l.ids_unavailable.clone());
    }

    fn concurrent_answer() -> ProviderApplyChangeResponse {
        ProviderApplyChangeResponse {
            ok: true,
            outcome: ProviderApplyOutcome::Concurrent as i32,
            item: Some(applied(3, 0, "doc.txt", false)),
            ..Default::default()
        }
    }

    #[test]
    fn a_conflicting_answer_whose_discard_a_crash_prevented_discards_once_on_replay() {
        let (auth, dir) = setup("replay-discard-before");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let v1: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.answers.borrow_mut().push(Some(concurrent_answer()));
        crash_at_effect(&auth, &[p("doc.txt")], &mut v1.clone(), &local, &api);
        assert!(local.discarded.borrow().is_empty());

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        let mut shown = v1;
        api.answers.borrow_mut().push(Some(concurrent_answer()));
        reopened.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert_eq!(local.discarded.borrow().len(), 1);
        assert!(!shown.contains_key(&vec![3; 16]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_crash_after_the_discard_does_not_discard_a_second_time() {
        let (auth, dir) = setup("replay-discard-after");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let v1: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.answers.borrow_mut().push(Some(concurrent_answer()));
        api.save_fails.set(true);
        auth.process(&signals(&[p("doc.txt")]), &mut v1.clone(), &local, &api);
        assert_eq!(local.discarded.borrow().len(), 1);
        // The fresh look put the current version back under the name.
        local.file("doc.txt", 12, Some((3, true)));

        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        let mut shown = v1;
        api.save_fails.set(false);
        api.answers.borrow_mut().push(Some(concurrent_answer()));
        reopened.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert_eq!(local.discarded.borrow().len(), 1, "discarded the current version");
        assert!(local.stat(&p("doc.txt")).is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_rename_and_a_move_are_one_modify_that_names_what_changed() {
        let (auth, dir) = setup("rename");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems =
            [item("old.txt", 3, 0, false, 10), item("sub", 4, 0, true, 0)].into();
        // The file now has a new name and sits in `sub`.
        local.dir("sub", Some(4));
        local.file("sub\\new.txt", 10, Some((3, true)));
        local.entries.borrow_mut().get_mut(&p("sub\\new.txt")).unwrap().mtime_unix_nanos = 1_000;
        local.located.borrow_mut().insert(vec![3; 16], p("sub\\new.txt"));
        api.accept(applied(3, 4, "new.txt", false));
        auth.process(&signals(&[p("old.txt"), p("sub\\new.txt")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 1, "a move was also sent as a delete");
        assert_eq!(requests[0].kind, ProviderChangeKind::Modify as i32);
        assert_eq!(requests[0].parent_item_id, Some(vec![4; 16]));
        assert_eq!(requests[0].name.as_deref(), Some("new.txt"));
        assert_eq!(
            requests[0].parent_generation,
            Some(5),
            "the folder it left, as the user saw it"
        );
        assert!(requests[0].content.is_none(), "a rename must not re-send the bytes");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An editor saves through a temporary file that is renamed over the original: the original's
    /// item is deleted first and the temporary file's item takes its name.
    #[test]
    fn a_file_renamed_over_another_item_deletes_that_item_first() {
        let (auth, dir) = setup("displace");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems =
            [item("doc.txt", 3, 0, false, 10), item("doc.tmp", 4, 0, false, 10)].into();
        // `doc.tmp` (id 4) now sits at `doc.txt`; id 3 is no longer anywhere.
        local.file("doc.txt", 10, Some((4, false)));
        local.entries.borrow_mut().get_mut(&p("doc.txt")).unwrap().mtime_unix_nanos = 1_000;
        api.accept_delete();
        api.accept(applied(4, 0, "doc.txt", false));
        auth.process(&signals(&[p("doc.txt"), p("doc.tmp")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests[0].kind, ProviderChangeKind::Delete as i32);
        assert_eq!(requests[0].item_id, vec![3; 16]);
        assert_eq!(requests[1].kind, ProviderChangeKind::Modify as i32);
        assert_eq!(requests[1].item_id, vec![4; 16]);
        assert_eq!(requests[1].name.as_deref(), Some("doc.txt"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_vanished_item_is_deleted_only_when_it_is_nowhere_in_the_sync_root() {
        let (auth, dir) = setup("delete");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("gone.txt", 3, 0, false, 10)].into();
        api.accept_delete();
        let report = auth.process(&signals(&[p("gone.txt")]), &mut shown, &local, &api);
        let request = api.requests.borrow()[0].clone();
        assert_eq!(request.kind, ProviderChangeKind::Delete as i32);
        assert_eq!(request.base_version_hash, vec![3; 40]);
        assert_eq!(report.applied, 1);
        assert!(shown.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Only a confirmed absence authorizes a delete: a path that cannot be inspected, or a search
    /// of the sync root that could not be completed, is retried.
    #[test]
    fn an_entry_that_cannot_be_inspected_is_never_deleted() {
        let (auth, dir) = setup("uninspectable");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("busy.txt", 3, 0, false, 10)].into();
        local.unreadable.borrow_mut().insert(p("busy.txt"));
        let report = auth.process(&signals(&[p("busy.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow().is_empty(), "a delete was sent for an unreadable entry");
        assert!(report.retry.contains(&p("busy.txt")));

        local.unreadable.borrow_mut().clear();
        *local.unsearchable.borrow_mut() = true;
        let report = auth.process(&signals(&[p("busy.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow().is_empty(), "a delete was sent after an incomplete search");
        assert!(report.retry.contains(&p("busy.txt")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_deleted_folder_is_one_recursive_delete() {
        let (auth, dir) = setup("rmdir");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems =
            [item("d", 4, 0, true, 0), item("d\\x", 5, 4, false, 1), item("d\\y", 6, 4, false, 1)]
                .into();
        api.accept_delete();
        auth.process(&signals(&[p("d"), p("d\\x"), p("d\\y")]), &mut shown, &local, &api);
        let requests = api.requests.borrow();
        assert_eq!(requests.len(), 1, "the children were deleted one by one as well");
        assert!(requests[0].recursive);
        assert!(shown.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_plain_file_that_replaced_an_item_is_a_content_modify_not_a_collision() {
        let (auth, dir) = setup("replace");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 20, None);
        api.accept(applied(3, 0, "doc.txt", false));
        auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        let request = api.requests.borrow()[0].clone();
        assert_eq!(request.kind, ProviderChangeKind::Modify as i32);
        assert_eq!(request.item_id, vec![3; 16]);
        assert!(request.content.is_some());
        assert_eq!(
            local.adopted.borrow()[0].1,
            vec![3; 16],
            "the new file must become the item's placeholder"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_busy_or_silent_daemon_leads_to_a_retry_and_never_to_a_second_operation() {
        let (auth, dir) = setup("retry");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        local.file("b.txt", 3, None);
        let mut shown = ShownItems::new();
        // The daemon does not answer: the operation stays journaled and is the only one sent.
        let report = auth.process(&signals(&[p("a.txt"), p("b.txt")]), &mut shown, &local, &api);
        assert!(report.retry.contains(&p("a.txt")));
        assert_eq!(
            api.requests.borrow().len(),
            1,
            "a second operation started over an unanswered one"
        );
        // Asked again, the same operation goes first; the daemon is not ready for it.
        api.fail(ProviderApplyFailure::NotReady);
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert!(report.retry.contains(&p("a.txt")));
        let requests = api.requests.borrow();
        assert_eq!(
            requests[1].operation_seq, requests[0].operation_seq,
            "the repeat must carry the same sequence"
        );
        assert!(shown.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A daemon that keeps answering StaleView for request A must not see A again: A is retired,
    /// the namespace is walked afresh, and the next request is a new one (B).
    #[test]
    fn an_obsolete_observation_is_retired_and_walked_again_not_repeated() {
        for failure in [
            ProviderApplyFailure::StaleView,
            ProviderApplyFailure::StaleOperation,
            ProviderApplyFailure::InvalidBase,
        ] {
            let (auth, dir) = setup("stale");
            let (local, api) = (FakeLocal::default(), FakeApi::default());
            let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
            local.file("doc.txt", 20, None);
            api.fail(failure);
            let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
            assert!(report.rewalk, "{failure:?}: no fresh walk was asked for");
            assert!(report.retry.contains(&p("doc.txt")));
            assert!(!auth.pending_file().exists(), "{failure:?}: request A stays journaled");
            // The fresh walk has shown the current version; the retry authors one new request.
            shown.get_mut(&vec![3; 16]).unwrap().content_version = vec![8; 40];
            api.fail(failure);
            auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
            let requests = api.requests.borrow();
            assert_eq!(requests.len(), 2);
            assert_ne!(requests[1].request_id, requests[0].request_id, "A was sent again");
            assert_eq!(requests[1].operation_seq, requests[0].operation_seq + 1);
            assert_eq!(requests[1].base_version_hash, vec![8; 40], "B must carry the new base");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// A journaled request retired as stale does not let another change of the same pass be
    /// authored from the obsolete base: the fresh walk comes first.
    #[test]
    fn nothing_new_is_authored_in_the_pass_that_retired_a_stale_request() {
        let (auth, dir) = setup("stale-first");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 20, None);
        local.file("other.txt", 3, None);
        auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert!(auth.pending_file().exists());
        api.fail(ProviderApplyFailure::StaleView);
        let report = auth.process(&signals(&[p("other.txt")]), &mut shown, &local, &api);
        assert!(report.rewalk && report.retry.contains(&p("other.txt")));
        assert_eq!(api.requests.borrow().len(), 2, "a new request used the obsolete base");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A stale answer to a request authored in this pass stops the pass: the other changes wait
    /// for the fresh walk instead of being authored from the obsolete base.
    #[test]
    fn a_stale_answer_stops_the_rest_of_the_pass() {
        let (auth, dir) = setup("stale-rest");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        local.file("b.txt", 3, None);
        let mut shown = ShownItems::new();
        api.fail(ProviderApplyFailure::StaleView);
        let report = auth.process(&signals(&[p("a.txt"), p("b.txt")]), &mut shown, &local, &api);
        assert!(report.rewalk);
        assert_eq!(api.requests.borrow().len(), 1, "a second request used the obsolete base");
        assert!(report.retry.contains(&p("a.txt")) && report.retry.contains(&p("b.txt")));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A recursive delete answered StaleView is retired, not repeated or shrunk to the folder: the
    /// observation is dropped and a fresh walk decides what is shown.
    #[test]
    fn a_stale_recursive_delete_is_retired_with_a_fresh_walk() {
        let (auth, dir) = setup("stale-rmdir");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("d", 4, 0, true, 0), item("d\\x", 5, 4, false, 1)].into();
        api.fail(ProviderApplyFailure::StaleView);
        let report = auth.process(&signals(&[p("d")]), &mut shown, &local, &api);
        assert!(api.requests.borrow()[0].recursive);
        assert!(report.rewalk);
        assert!(!auth.pending_file().exists());
        assert!(shown.is_empty(), "a delete is not authored again from the dropped observation");
        auth.process(&signals(&[p("d")]), &mut shown, &local, &api);
        assert_eq!(api.requests.borrow().len(), 1, "a parent-only delete was authored");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A writer that is open keeps the copy out (the file is looked at again later); nothing is
    /// copied, journaled or sent meanwhile.
    #[test]
    fn a_file_with_an_open_writer_is_not_copied_or_sent() {
        let (auth, dir) = setup("open-writer");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        *local.unstable.borrow_mut() = true; // the share-restricted open is refused
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert!(report.retry.contains(&p("a.txt")));
        assert_eq!(*local.copies.borrow(), 0);
        assert!(api.requests.borrow().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_that_is_still_changing_is_not_sent() {
        let (auth, dir) = setup("unstable");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        *local.unstable.borrow_mut() = true;
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert!(report.retry.contains(&p("a.txt")));
        assert!(api.requests.borrow().is_empty(), "an unstable file was sent");
        assert!(
            !auth.pending_file().exists(),
            "nothing was journaled for a copy that was not made"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// After a crash the journaled request is sent again with the SAME session and sequence, so
    /// the daemon recognizes it instead of applying it twice.
    #[test]
    fn a_crash_between_send_and_answer_replays_the_same_operation() {
        let (auth, dir) = setup("journal");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        let mut shown = ShownItems::new();
        // No answer: the journal stays.
        auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        let first = api.requests.borrow()[0].clone();
        assert!(auth.pending_file().exists());

        // A restart: a new Authoring over the same state directory.
        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        api.accept(applied(7, 0, "a.txt", false));
        let report = reopened.resume(&mut shown, &local, &api);
        let replay = api.requests.borrow()[1].clone();
        assert_eq!(
            (replay.session_id.clone(), replay.operation_seq, replay.request_id.clone()),
            (first.session_id.clone(), first.operation_seq, first.request_id.clone())
        );
        assert_eq!(replay.content, first.content);
        assert_eq!(replay.name, first.name);
        assert_eq!(report.applied, 1);
        assert_eq!(local.adopted.borrow()[0].1, vec![7; 16]);
        assert!(!reopened.pending_file().exists());

        // Sequence numbers keep increasing across the restart.
        local.file("b.txt", 3, None);
        api.accept(applied(8, 0, "b.txt", false));
        reopened.process(&signals(&[p("b.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow()[2].operation_seq > first.operation_seq);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_symbolic_link_and_a_placeholder_of_an_unseen_item_are_not_sent() {
        let (auth, dir) = setup("skip");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.entries.borrow_mut().insert(
            p("link"),
            LocalStat {
                is_dir: false,
                is_symlink: true,
                size: 0,
                mtime_unix_nanos: 0,
                placeholder: None,
                file_id: None,
            },
        );
        local.file("remote.txt", 3, Some((9, true)));
        let mut shown = ShownItems::new();
        let report =
            auth.process(&signals(&[p("link"), p("remote.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow().is_empty());
        assert!(report.rewalk, "an unseen item should lead to a fresh look");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The host's own Stage placeholder (made beside a name and about to be moved onto it) is
    /// never something the user did: not a create, not a move of the item it carries.
    #[test]
    fn a_stage_named_entry_is_never_sent() {
        let (auth, dir) = setup("stage");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let stage = ".yadorilink-v1-stage.1-2-3";
        local.file(stage, 3, None);
        local.file(&format!("album\\{stage}"), 3, Some((9, true)));
        local.dir("album", Some(8));
        let mut shown = ShownItems::new();
        shown.insert(vec![8; 16], item("album", 8, 0, true, 0).1);
        let report = auth.process(
            &signals(&[p(stage), p(&format!("album\\{stage}"))]),
            &mut shown,
            &local,
            &api,
        );
        assert!(api.requests.borrow().is_empty(), "{:?}", api.requests.borrow());
        assert!(!report.rewalk && report.retry.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The item an edit was based on is gone: the bytes are kept under the daemon's suggested
    /// name and become the user's own file again (no item identity), to be sent as a new item.
    #[test]
    fn kept_local_bytes_lose_the_old_items_identity_and_are_sent_again_as_new() {
        let (auth, dir) = setup("keep-local");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        api.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
            ok: false,
            failure: ProviderApplyFailure::KeepLocal as i32,
            suggested_name: "doc (kept).txt".into(),
            ..Default::default()
        }));
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert_eq!(*local.unbound.borrow(), vec![p("doc (kept).txt")]);
        assert!(report.retry.contains(&p("doc (kept).txt")));
        assert!(report.rewalk);
        assert!(local.stat(&p("doc.txt")).is_none() && local.stat(&p("doc (kept).txt")).is_some());
        assert!(!auth.pending_file().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn keep_local_answer(api: &FakeApi) {
        api.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
            ok: false,
            failure: ProviderApplyFailure::KeepLocal as i32,
            suggested_name: "doc (kept).txt".into(),
            ..Default::default()
        }));
    }

    /// An unbind that fails leaves the kept file bound to the old item, so the journal is
    /// kept; the repeat finds the file already renamed (by its journaled file id), does not
    /// rename again, unbinds, and only then retires the journal.
    #[test]
    fn a_failed_unbind_of_kept_local_bytes_keeps_the_journal_and_is_retried() {
        let (auth, dir) = setup("keep-local-unbind-fails");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        local.unbind_failures.set(1);
        keep_local_answer(&api);
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert!(auth.pending_file().exists(), "the journal was retired with the file still bound");
        assert!(local.unbound.borrow().is_empty());
        assert!(
            report.retry.contains(&p("doc (kept).txt")),
            "the renamed file is not protected from a walk"
        );

        keep_local_answer(&api);
        let report = auth.resume(&mut shown, &local, &api);
        assert_eq!(*local.unbound.borrow(), vec![p("doc (kept).txt")]);
        assert!(!auth.pending_file().exists(), "the journal outlived the unbind");
        assert!(report.retry.contains(&p("doc (kept).txt")) && report.rewalk);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The daemon recalculates the answer of a repeat, which may propose another name; the
    /// file renamed under the first one is found by its identity and unbound where it is.
    #[test]
    fn a_repeat_that_proposes_another_name_unbinds_the_file_kept_under_the_first() {
        let (auth, dir) = setup("keep-local-renamed-name");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        local.unbind_failures.set(1);
        keep_local_answer(&api);
        auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert!(auth.pending_file().exists());
        // The renamed placeholder is still the old item's: the walk finds it by its item id.
        local.located.borrow_mut().insert(vec![3; 16], p("doc (kept).txt"));

        api.answers.borrow_mut().push(Some(ProviderApplyChangeResponse {
            ok: false,
            failure: ProviderApplyFailure::KeepLocal as i32,
            suggested_name: "doc (kept 2).txt".into(),
            ..Default::default()
        }));
        let report = auth.resume(&mut shown, &local, &api);
        assert_eq!(*local.unbound.borrow(), vec![p("doc (kept).txt")]);
        assert!(!auth.pending_file().exists());
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A source whose identity cannot be read right now is not another object: the journal
    /// stays and the step is tried again.
    #[test]
    fn kept_local_bytes_whose_identity_is_unreadable_keep_the_journal() {
        let (auth, dir) = setup("keep-local-id-unreadable");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        // The identity becomes unreadable while the daemon answers.
        let flag = local.ids_unavailable.clone();
        *api.before_answer.borrow_mut() = Some(Box::new(move || flag.set(true)));
        keep_local_answer(&api);
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert!(auth.pending_file().exists(), "the journal was retired on an unreadable identity");
        assert!(report.refused.is_empty() && local.unbound.borrow().is_empty());

        local.ids_unavailable.set(false);
        keep_local_answer(&api);
        auth.resume(&mut shown, &local, &api);
        assert_eq!(*local.unbound.borrow(), vec![p("doc (kept).txt")]);
        assert!(!auth.pending_file().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A crash between the rename and the unbind replays to the same end state.
    #[test]
    fn a_crash_between_the_rename_and_the_unbind_of_kept_local_bytes_unbinds_on_replay() {
        let (auth, dir) = setup("keep-local-crash");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        keep_local_answer(&api);
        local.crash_at_unbind.set(true);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api)
        }));
        local.crash_at_unbind.set(false);
        assert!(outcome.is_err(), "the unbind was not reached");
        assert!(auth.pending_file().exists());

        keep_local_answer(&api);
        let report = auth.resume(&mut shown, &local, &api);
        assert_eq!(*local.unbound.borrow(), vec![p("doc (kept).txt")]);
        assert!(!auth.pending_file().exists());
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Another object at the proposed name is never touched, and a name whose bytes are
    /// not the journaled object's is not unbound: refused as before.
    #[test]
    fn kept_local_bytes_are_refused_when_another_object_holds_the_proposed_name() {
        let (auth, dir) = setup("keep-local-occupied");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        let mut shown: ShownItems = [item("doc.txt", 3, 0, false, 10)].into();
        local.file("doc.txt", 12, Some((3, false)));
        local.file("doc (kept).txt", 5, Some((4, true)));
        local.ids.borrow_mut().insert(p("doc (kept).txt"), 2_000);
        keep_local_answer(&api);
        let report = auth.process(&signals(&[p("doc.txt")]), &mut shown, &local, &api);
        assert_eq!(report.refused.len(), 1);
        assert!(local.unbound.borrow().is_empty());
        assert!(local.stat(&p("doc.txt")).is_some());
        assert!(!auth.pending_file().exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_refusal_for_good_is_reported_not_retried() {
        let (auth, dir) = setup("refuse");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        api.fail(ProviderApplyFailure::NotAuthorized);
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert!(report.retry.is_empty());
        assert_eq!(report.refused.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A lost, torn or unreadable sequence record never makes an identity (session, sequence)
    /// the daemon has seen come back: a new session starts instead of reading 0.
    #[test]
    fn a_lost_or_corrupt_sequence_record_never_reuses_an_operation_identity() {
        for damage in ["lost", "torn", "unreadable", "session lost"] {
            let (auth, dir) = setup(&format!("seq-{}", damage.replace(' ', "-")));
            let first = (auth.session.to_vec(), auth.next_seq().unwrap());
            let second = (auth.session.to_vec(), auth.next_seq().unwrap());
            assert!(second.1 > first.1);

            let generations = |name: &str| -> Vec<PathBuf> {
                std::fs::read_dir(&dir)
                    .unwrap()
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with(&format!("{name}.")))
                    })
                    .collect()
            };
            match damage {
                "lost" => generations("seq").iter().for_each(|p| std::fs::remove_file(p).unwrap()),
                "torn" => generations("seq").iter().for_each(|p| std::fs::write(p, "2").unwrap()),
                "unreadable" => generations("seq").iter().for_each(|p| {
                    std::fs::remove_file(p).unwrap();
                    std::fs::create_dir(p).unwrap();
                }),
                _ => generations("session").iter().for_each(|p| std::fs::remove_file(p).unwrap()),
            }
            if damage == "unreadable" {
                // Not even a new generation can be told from the unreadable one: blocked.
                let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir);
                let identity = reopened.and_then(|a| Ok((a.session.to_vec(), a.next_seq()?)));
                if let Ok(identity) = identity {
                    assert_ne!(identity, first, "{damage}");
                    assert_ne!(identity, second, "{damage}");
                    assert_ne!(identity.0, first.0, "{damage}");
                }
                let _ = std::fs::remove_dir_all(dir);
                continue;
            }
            let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
            let again = (reopened.session.to_vec(), reopened.next_seq().unwrap());
            assert_ne!(again, first, "{damage}");
            assert_ne!(again, second, "{damage}");
            if damage != "session lost" {
                assert_ne!(again.0, first.0, "{damage}: the old identity space was continued");
            }
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// The healthy case is unchanged: the session is kept and the sequence only goes up.
    #[test]
    fn a_healthy_restart_keeps_the_session_and_continues_the_sequence() {
        let (auth, dir) = setup("seq-ok");
        let one = auth.next_seq().unwrap();
        let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        assert_eq!(reopened.session, auth.session);
        assert_eq!(reopened.next_seq().unwrap(), one + 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn damage_newest(dir: &Path, name: &str) {
        let newest = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let file = e.file_name().to_string_lossy().into_owned();
                let n: u64 = file.strip_prefix(&format!("{name}."))?.parse().ok()?;
                Some((n, e.path()))
            })
            .max()
            .unwrap()
            .1;
        std::fs::write(newest, "torn").unwrap();
    }

    /// Only the newest generation damaged: the reader skips it for the one before, which is
    /// behind what was already sent. That must not be continued under the same session.
    #[test]
    fn a_damaged_newest_sequence_generation_starts_a_new_session() {
        for record in ["seq", "session"] {
            let (auth, dir) = setup(&format!("newest-{record}"));
            auth.next_seq().unwrap();
            auth.next_seq().unwrap();
            damage_newest(&dir, record);

            let reopened = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
            assert_ne!(reopened.session, auth.session, "{record}");
            let again = reopened.next_seq().unwrap();
            assert_eq!(again, 1, "{record}: restarts under the new session");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// The same damage after the session is open: nothing is numbered.
    #[test]
    fn a_sequence_damaged_after_open_is_never_continued_from_the_older_record() {
        let (auth, dir) = setup("newest-after-open");
        auth.next_seq().unwrap();
        auth.next_seq().unwrap();
        damage_newest(&dir, "seq");
        let error = auth.next_seq().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        // A change signal is kept for the next pass (nothing is sent, nothing is dropped) ...
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        let mut shown = ShownItems::new();
        let report = auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert!(api.requests.borrow().is_empty());
        assert!(report.refused.is_empty());
        assert_eq!(report.retry, signals(&[p("a.txt")]));

        // ... and the next pass opens the state afresh: a new session, numbered from the start.
        let next = Authoring::open(&[1; 16], Path::new(ROOT), &dir).unwrap();
        next.process(&report.retry, &mut shown, &local, &api);
        let sent = api.requests.borrow();
        assert_eq!(sent.len(), 1);
        assert_ne!(sent[0].session_id, auth.session.to_vec());
        assert_eq!(sent[0].operation_seq, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Sending the journaled operation again never rewrites the journal: a crash during a
    /// rewrite could lose the only record of the operation's identity.
    #[test]
    fn a_replay_does_not_rewrite_the_journal() {
        let (auth, dir) = setup("replay-no-rewrite");
        let (local, api) = (FakeLocal::default(), FakeApi::default());
        local.file("a.txt", 3, None);
        let mut shown = ShownItems::new();
        auth.process(&signals(&[p("a.txt")]), &mut shown, &local, &api);
        assert!(auth.pending_file().exists());
        let before = std::fs::read_to_string(auth.pending_file()).unwrap();

        // Anything a rewrite would need (its staging file) is unavailable: the replay still
        // sends, and the journal is as it was until the operation settles.
        std::fs::create_dir(auth.pending_file().with_extension("tmp")).unwrap();
        api.accept(applied(7, 0, "a.txt", false));
        let report = auth.resume(&mut shown, &local, &api);
        assert_eq!((report.applied, report.refused.len()), (1, 0));
        assert_eq!(api.requests.borrow().len(), 2);
        assert!(!auth.pending_file().exists());
        assert!(!before.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
