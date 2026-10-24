//! The per-volume probe: does the set of shapes in [`super`] work on the volume
//! `dir` lives on? The answer is the authority; the file system name is only a
//! precondition (Windows: a local fixed NTFS volume).

use std::io;
use std::path::Path;
use std::sync::Mutex;

use super::{
    describe_io, DiscardOutcome, DurableNamespace, NoLedger, NsError, RefusalCause, Replace,
    RetainReason,
};
use crate::fs_capabilities::Capability;

#[cfg(any(windows, test))]
const DRIVE_FIXED: u32 = 3;

const PROBE_LABEL: &str = "dir-durability";

/// Verdicts per volume, so the probe runs once per volume and process. A probe
/// that could not run (`Unknown`) is not kept.
static VERDICTS: Mutex<Vec<(u64, Probed)>> = Mutex::new(Vec::new());

/// A probe's verdict and, when it is not `Supported`, why: the step, the error and errno, the
/// probed path and its volume. The cause is kept with a cached verdict, so a refusal answered
/// from the cache still says what the probe saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Probed {
    pub(super) verdict: Capability,
    pub(super) cause: RefusalCause,
}

impl Probed {
    fn supported() -> Self {
        Self { verdict: Capability::Supported, cause: RefusalCause::default() }
    }
}

/// The cause of a volume with a DOS path but no GUID path.
pub(super) fn guid_path_cause(dir: &Path, error: &io::Error) -> RefusalCause {
    RefusalCause::new(format!("volume of {dir:?} has no GUID path: {}", describe_io(error)))
}

pub(super) fn cached_verdict(dir: &Path) -> Probed {
    match volume_key(dir) {
        Ok(volume) => verdict_cached(volume, || probe_explained(dir)),
        Err(e) if is_no_guid_path(&e) => {
            Probed { verdict: Capability::Unsupported, cause: guid_path_cause(dir, &e) }
        }
        Err(e) => Probed {
            verdict: Capability::Unknown,
            cause: RefusalCause::new(format!(
                "step volume_key: the volume of {dir:?} could not be identified: {}",
                describe_io(&e)
            )),
        },
    }
}

/// The cached verdict for `volume`, or `probe_now`'s, kept unless it is `Unknown`.
fn verdict_cached(volume: u64, probe_now: impl FnOnce() -> Probed) -> Probed {
    let known = VERDICTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find_map(|(v, c)| (*v == volume).then(|| c.clone()));
    if let Some(known) = known {
        return known;
    }
    let probed = probe_now();
    if probed.verdict != Capability::Unknown {
        VERDICTS.lock().unwrap_or_else(|p| p.into_inner()).push((volume, probed.clone()));
    }
    probed
}

/// [`verdict_cached`] for callers that only want the verdict.
#[cfg(test)]
fn verdict_for(volume: u64, probe_now: impl FnOnce() -> Capability) -> Capability {
    verdict_cached(volume, || Probed {
        verdict: probe_now(),
        cause: RefusalCause::new("test verdict"),
    })
    .verdict
}

/// A number for `key`, the same one every time and never shared with another key,
/// so a volume stays a plain `u64` to the callers.
#[cfg(any(windows, test))]
fn intern(key: String) -> u64 {
    static KEYS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut keys = KEYS.lock().unwrap_or_else(|p| p.into_inner());
    let at = keys.iter().position(|k| *k == key).unwrap_or_else(|| {
        keys.push(key);
        keys.len() - 1
    });
    at as u64
}

/// A volume that has a DOS path but no volume GUID path (a network share, a virtual disk
/// without a mount point). Its drive letter can be given to another volume, so nothing that must
/// stay on one volume (a durable move, a sync folder) is allowed to rest on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoVolumeGuidPath;

impl std::fmt::Display for NoVolumeGuidPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the volume has no volume GUID path (only a drive letter or share path), so it \
             cannot be told from another volume later; YadoriLink does not support it",
        )
    }
}

impl std::error::Error for NoVolumeGuidPath {}

/// Whether `error` says the volume has no GUID path (see [`NoVolumeGuidPath`]).
pub fn is_no_guid_path(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<NoVolumeGuidPath>())
}

/// `(final path, volume path)` from the two spellings of a handle's final path. The volume is
/// always named by its GUID path; a DOS path alone is refused, never used as the name.
#[cfg(any(windows, test))]
fn volume_paths(dos: io::Result<String>, guid: io::Result<String>) -> io::Result<(String, String)> {
    match (dos, guid) {
        (Ok(dos), Ok(guid)) => Ok((dos, guid)),
        (Err(_), Ok(guid)) => Ok((guid.clone(), guid)),
        (Ok(_), Err(_)) => Err(io::Error::new(io::ErrorKind::Unsupported, NoVolumeGuidPath)),
        (Err(e), Err(_)) => Err(e),
    }
}

/// `Ok` when the volume under `path` (or under its nearest existing ancestor, for a folder not
/// made yet) is named by a GUID path. Anything else is refused: a volume with only a DOS path is
/// an error that [`is_no_guid_path`] recognises; a volume that cannot be looked at is the error
/// of the look. Always `Ok` off Windows.
pub fn require_volume_guid_path(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        let mut at = Some(path);
        while let Some(candidate) = at {
            match windows::describe(candidate) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => at = candidate.parent(),
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::from(io::ErrorKind::NotFound))
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
    }
}

/// The identity of a Windows volume: its serial number alone is not unique (two
/// volumes may share one, and a verdict, or a same-volume check, must not carry
/// from one to the other), so the key adds the file system name and the volume
/// part of the final path by volume GUID (`Volume{guid}`, which also tells apart
/// volumes mounted in folders; a share gives `UNC\server\share`).
#[cfg(any(windows, test))]
fn windows_volume_key(serial: u32, fs_name: &str, volume_path: &str) -> String {
    let rest = volume_path.strip_prefix(r"\\?\").unwrap_or(volume_path);
    let volume_part = if rest.get(..4).is_some_and(|head| head.eq_ignore_ascii_case("UNC\\")) {
        rest.splitn(4, '\\').take(3).collect::<Vec<_>>().join("\\")
    } else {
        rest.split('\\').next().unwrap_or(rest).to_owned()
    };
    format!("{serial:08x}|{}|{}", fs_name.to_ascii_lowercase(), volume_part.to_ascii_lowercase())
}

/// Identifies the volume under `dir`: the device number on Unix, on Windows
/// [`windows_volume_key`].
pub(super) fn volume_key(dir: &Path) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(std::fs::metadata(dir)?.dev())
    }
    #[cfg(windows)]
    {
        let d = windows::describe(dir)?;
        Ok(intern(windows_volume_key(d.serial, &d.fs_name, &d.volume_path)))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Runs the probe on `dir`'s volume now.
pub(super) fn probe(dir: &Path) -> Capability {
    probe_explained(dir).verdict
}

/// [`probe`] with the cause of a verdict that is not `Supported`.
fn probe_explained(dir: &Path) -> Probed {
    // Taken before the probe runs: if the directory vanishes meanwhile, the cause still names
    // the volume it was on.
    let identity = match volume_key(dir) {
        Ok(key) => format!("volume key {key}"),
        Err(e) => format!("volume unidentified ({})", describe_io(&e)),
    };
    let refuse = |verdict: Capability, what: String| Probed {
        verdict,
        cause: RefusalCause::new(format!("probe of {dir:?} on {identity}: {what}")),
    };
    #[cfg(windows)]
    {
        let (fs_name, fixed) = match windows::volume_of(dir) {
            Ok(volume) => volume,
            Err(e) if is_no_guid_path(&e) => {
                return refuse(
                    Capability::Unsupported,
                    format!("step volume_of: {}", describe_io(&e)),
                )
            }
            Err(e) => {
                return refuse(Capability::Unknown, format!("step volume_of: {}", describe_io(&e)))
            }
        };
        if !fixed || !fs_name.eq_ignore_ascii_case("NTFS") {
            return refuse(
                Capability::Unsupported,
                format!("step volume_of: file system {fs_name:?}, fixed disk: {fixed}"),
            );
        }
    }
    let base = match crate::fs_capabilities::probe_artefact_name(PROBE_LABEL) {
        Ok(base) => base,
        Err(e) => return refuse(Capability::Unknown, format!("step artefact_name: {e:?}")),
    };
    let work = dir.join(base);
    if let Err(e) = std::fs::create_dir(&work) {
        return refuse(Capability::Unknown, format!("step create_work_dir: {}", describe_io(&e)));
    }
    let outcome = super::quiet(|| try_shapes(&work));
    // A conclusive refusal is kept for the process, so it says what the probe directory held
    // when the volume answered: a wrong answer caused by something else touching it shows here.
    let outcome = outcome.map_err(|fail| match fail {
        Fail::Unsupported(what) => {
            Fail::Unsupported(format!("{what}; probe directory held {}", entry_names(&work)))
        }
        unknown => unknown,
    });
    // Only this probe's own directory, made just above: never a directory found by its name.
    let _ = std::fs::remove_dir_all(&work);
    match outcome {
        Ok(()) => Probed::supported(),
        Err(Fail::Unsupported(what)) => refuse(Capability::Unsupported, what),
        Err(Fail::Unknown(what)) => refuse(Capability::Unknown, what),
    }
}

/// The names in `dir`, for a refusal's cause.
fn entry_names(dir: &Path) -> String {
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            let mut names: Vec<_> = entries.filter_map(Result::ok).map(|e| e.file_name()).collect();
            names.sort();
            format!("{names:?}")
        }
        Err(e) => format!("unreadable ({})", describe_io(&e)),
    }
}

/// The steps of the probe, named in a refusal's cause; a test can make the volume answer "busy"
/// at one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    FirstPublish,
    SecondPublish,
    CreateDir,
    ReplacePublish,
    ReadBack,
    Discard,
    Removal,
}

#[cfg(test)]
thread_local! {
    static BUSY_AT: std::cell::Cell<Option<(Step, io::ErrorKind)>> = const { std::cell::Cell::new(None) };
}

/// Makes the next probe on this thread meet an error of `kind` at `step`
/// (`ResourceBusy` is a sharing violation).
#[cfg(test)]
fn inject_at(step: Step, kind: io::ErrorKind) {
    BUSY_AT.with(|b| b.set(Some((step, kind))));
}

#[cfg(test)]
fn busy_at(step: Step) -> bool {
    BUSY_AT.with(|b| b.get()).is_some_and(|(at, _)| at == step)
}

/// The injected sharing violation of `step`, if a test armed it.
#[cfg(test)]
fn busy_step(step: Step) -> Result<(), Fail> {
    let Some((at, kind)) = BUSY_AT.with(|b| b.get()) else { return Ok(()) };
    if at != step {
        return Ok(());
    }
    let error = io::Error::from(kind);
    Err(fail_at(step, NsError::from_io(error)))
}

/// How a probe step went wrong, with the step and the error. `Unsupported` is a definite wrong
/// answer: the shape succeeded where it must be refused, did something other than it must, or
/// the volume says it cannot do it (`ENOTSUP`/`EINVAL` class). `Unknown` is any other error (a
/// sharing violation or lock from a reader, an indexer or a scanner, a full disk, an I/O
/// error): the volume has not answered, so nothing is concluded, and the verdict is not kept.
enum Fail {
    Unsupported(String),
    Unknown(String),
}

fn fail_at(step: Step, error: NsError) -> Fail {
    let says_unsupported = |e: &io::Error| {
        matches!(e.kind(), io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput)
    };
    let what = match &error {
        NsError::Io(e) | NsError::Busy(e) | NsError::NotDurable(e) => describe_io(e),
        other => other.to_string(),
    };
    let what = format!("step {step:?}: {what}");
    match error {
        // The shape did not do what it must: the entry it just made is not there, a fresh
        // name is occupied, a file is a directory.
        NsError::AlreadyExists | NsError::NotEmpty | NsError::CrossVolume => {
            Fail::Unsupported(what)
        }
        // A missing entry or directory is about the path, not the volume: the directory
        // under probe was removed (a dropped temp dir, a scanner) while the probe ran. It
        // concludes nothing, so it is never kept as "the volume cannot do this".
        NsError::NotFound => Fail::Unknown(what),
        NsError::Io(e) | NsError::NotDurable(e) if says_unsupported(&e) => Fail::Unsupported(what),
        _ => Fail::Unknown(what),
    }
}

fn try_shapes(work: &Path) -> Result<(), Fail> {
    let ns = DurableNamespace::unchecked();
    let (file, sub) = (work.join("f"), work.join("d"));
    let put =
        |content: &'static [u8]| move |f: &mut std::fs::File| io::Write::write_all(f, content);
    #[cfg(test)]
    busy_step(Step::FirstPublish)?;
    ns.create_file(&file, Replace::No, &NoLedger, put(b"probe"))
        .map_err(|e| fail_at(Step::FirstPublish, e))?;
    // The occupied name must be refused as occupied: success, or a refusal of another kind
    // that is not busy, is the wrong answer.
    #[cfg(test)]
    busy_step(Step::SecondPublish)?;
    match ns.create_file(&file, Replace::No, &NoLedger, put(b"again")) {
        Err(NsError::AlreadyExists) => {}
        Err(other) => return Err(fail_at(Step::SecondPublish, other)),
        Ok(()) => {
            return Err(Fail::Unsupported(format!(
                "step {:?}: a no-replace publish over an existing file succeeded",
                Step::SecondPublish
            )))
        }
    }
    #[cfg(test)]
    busy_step(Step::CreateDir)?;
    ns.create_dir(&sub, &NoLedger).map_err(|e| fail_at(Step::CreateDir, e))?;
    #[cfg(test)]
    busy_step(Step::ReplacePublish)?;
    ns.create_file(&file, Replace::Yes, &NoLedger, put(b"second"))
        .map_err(|e| fail_at(Step::ReplacePublish, e))?;
    #[cfg(test)]
    busy_step(Step::ReadBack)?;
    let read = std::fs::read(&file).map_err(|e| fail_at(Step::ReadBack, NsError::from_io(e)))?;
    if read != b"second" {
        return Err(Fail::Unsupported(format!(
            "step {:?}: the replaced file reads back other content",
            Step::ReadBack
        )));
    }
    #[cfg(test)]
    busy_step(Step::Discard)?;
    let discarded = ns.discard(&file, &NoLedger).map_err(|e| fail_at(Step::Discard, e))?;
    #[cfg(test)]
    let outcome = if busy_at(Step::Removal) {
        DiscardOutcome::Retained { path: file.clone(), reason: RetainReason::RemovalFailed }
    } else {
        discarded.finish(&ns, &NoLedger)
    };
    #[cfg(not(test))]
    let outcome = discarded.finish(&ns, &NoLedger);
    match outcome {
        DiscardOutcome::Removed => Ok(()),
        // The removal of a file the probe just moved aside failed: the entry is committed
        // away but a holder kept it, which says nothing about the shapes.
        DiscardOutcome::Retained { reason: RetainReason::RemovalFailed, .. } => Err(Fail::Unknown(
            format!("step {:?}: the moved-aside probe file could not be removed", Step::Removal),
        )),
        other => {
            Err(Fail::Unsupported(format!("step {:?}: discard gave {other:?}", Step::Discard)))
        }
    }
}

/// The verdict on `dir`'s volume without the cache and without the Windows
/// gate, for the evidence runs.
pub fn probe_directory_durability(dir: &Path) -> Capability {
    probe(dir)
}

/// `(file system name, is a local fixed disk)` of the volume that `dir` really
/// lives on, judged from a handle to the directory itself: a junction or
/// symbolic link in the path is followed to its target, so a path that starts on
/// `C:` but ends on a share is not mistaken for local. Windows only; evidence
/// tooling reports it next to the probe's verdict.
#[cfg(windows)]
pub fn local_volume_file_system(dir: &Path) -> io::Result<(String, bool)> {
    windows::volume_of(dir)
}

#[cfg(any(windows, test))]
/// `\\?\C:\dir` is on drive `C:`; `\\?\UNC\server\share` and a volume
/// without a drive letter are not accepted. `drive_type` maps a root such as
/// `C:\` to its Win32 drive type.
fn final_path_is_on_fixed_drive(final_path: &str, drive_type: impl Fn(&str) -> u32) -> bool {
    let Some(rest) = final_path.strip_prefix(r"\\?\") else { return false };
    let bytes = rest.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return false;
    }
    drive_type(&format!("{}:\\", &rest[..1])) == DRIVE_FIXED
}

/// The volume GUID path of the directory `dir`, for tests.
#[cfg(all(windows, test))]
pub(super) fn volume_guid_path_for_test(dir: &Path) -> String {
    windows::describe(dir).unwrap().volume_path
}

/// The Windows removal of [`super::remove_file_judged`]: the file is opened once (a final link is
/// the object, not followed), the verdict is asked about the directory its handle names by
/// volume GUID, and the file is deleted through that handle.
#[cfg(windows)]
pub(super) fn remove_file_through_handle(
    path: &Path,
    judge: impl FnOnce(&Path) -> bool,
) -> Result<(), super::JudgedRemoveError> {
    use super::JudgedRemoveError::Io;
    let file = windows::open_for_delete(path).map_err(Io)?;
    judge_open_file(&file, judge)?;
    windows::delete_through(&file).map_err(Io)
}

/// Asks `judge` about the directory the open `file` lives in, named by volume GUID so it leads to
/// the volume of the object the handle is on, not to wherever a path spelling resolves now.
#[cfg(windows)]
pub(super) fn judge_open_file(
    file: &std::fs::File,
    judge: impl FnOnce(&Path) -> bool,
) -> Result<(), super::JudgedRemoveError> {
    use super::JudgedRemoveError::{Io, Refused};
    let seen = windows::describe_handle(file).map_err(Io)?;
    let named = std::path::PathBuf::from(&seen.volume_path);
    let parent = named.parent().ok_or_else(|| {
        Io(io::Error::new(io::ErrorKind::InvalidInput, "a file has a parent directory"))
    })?;
    let key = windows_volume_key(seen.serial, &seen.fs_name, &seen.volume_path);
    if !judge(parent) {
        return Err(Refused);
    }
    // The directory the verdict looked at must still be on the volume of the object: a swap
    // while the verdict ran is refused rather than trusted.
    let after = windows::describe(parent).map_err(Io)?;
    if windows_volume_key(after.serial, &after.fs_name, &after.volume_path) != key {
        return Err(Refused);
    }
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, FileDispositionInfoEx, GetDriveTypeW, GetFileInformationByHandle,
        GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, SetFileInformationByHandle,
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        VOLUME_NAME_DOS, VOLUME_NAME_GUID,
    };

    /// A handle to the directory itself. Followed on purpose (no
    /// OPEN_REPARSE_POINT): the target is what counts.
    fn open_dir(dir: &Path) -> io::Result<std::fs::File> {
        let handle = std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)?;
        if !handle.metadata()?.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a directory"));
        }
        Ok(handle)
    }

    /// A handle to the file itself, for deleting through it. A final link is not followed.
    pub(super) fn open_for_delete(path: &Path) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    /// Deletes the file `handle` is open on, as soon as the name is released (POSIX semantics
    /// where the file system has them, else on close).
    pub(super) fn delete_through(handle: &std::fs::File) -> io::Result<()> {
        let raw = handle.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        let ex = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // SAFETY: `raw` is open for the call; `ex` is a live FILE_DISPOSITION_INFO_EX.
        let done = unsafe {
            SetFileInformationByHandle(
                raw,
                FileDispositionInfoEx,
                std::ptr::addr_of!(ex).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        };
        if done != 0 {
            return Ok(());
        }
        let ex_error = io::Error::last_os_error();
        let plain = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: as above, with a live FILE_DISPOSITION_INFO.
        let done = unsafe {
            SetFileInformationByHandle(
                raw,
                FileDispositionInfo,
                std::ptr::addr_of!(plain).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if done != 0 {
            Ok(())
        } else {
            // The extended form's error says why, unless the plain one failed differently.
            let plain_error = io::Error::last_os_error();
            Err(if ex_error.raw_os_error() == Some(87) { plain_error } else { ex_error })
        }
    }

    pub(super) struct Described {
        pub serial: u32,
        pub fs_name: String,
        pub final_path: String,
        /// The final path by volume GUID, which names the volume even when it is
        /// mounted in a folder; the DOS path where the volume has no GUID (a share).
        pub volume_path: String,
    }

    /// Serial number, file system name and final path, all read from one handle to `dir`.
    pub(super) fn describe(dir: &Path) -> io::Result<Described> {
        describe_handle(&open_dir(dir)?)
    }

    /// [`describe`] for a handle that is already open.
    pub(super) fn describe_handle(handle: &std::fs::File) -> io::Result<Described> {
        let raw = handle.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;

        // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid out-value.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `raw` is open for the call and `info` is writable.
        if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut fs_name = [0u16; 64];
        // SAFETY: `raw` is open for the call; unused out-parameters are null and
        // `fs_name` is writable for its length.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                raw,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                fs_name.as_mut_ptr(),
                fs_name.len() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let end = fs_name.iter().position(|&c| c == 0).unwrap_or(fs_name.len());
        let name = std::ffi::OsString::from_wide(&fs_name[..end]).to_string_lossy().into_owned();

        let final_path_with = |flags| -> io::Result<String> {
            // A result longer than the buffer is reported by its needed length (with the
            // terminator): ask again with room for it rather than cut the path short.
            let mut path = vec![0u16; 1024];
            loop {
                // SAFETY: `raw` is open for the call; `path` is writable for its length.
                let len = unsafe {
                    GetFinalPathNameByHandleW(raw, path.as_mut_ptr(), path.len() as u32, flags)
                } as usize;
                if len == 0 {
                    return Err(io::Error::last_os_error());
                }
                if len < path.len() {
                    return Ok(String::from_utf16_lossy(&path[..len]));
                }
                path = vec![0u16; len + 1];
            }
        };
        // A volume mounted only in a folder has no DOS path; it is named by its GUID path
        // alone (and is not a drive-letter volume, which `volume_of` then reports).
        let guid = final_path_with(FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
        let dos = final_path_with(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        let (final_path, volume_path) = volume_paths(dos, guid)?;
        Ok(Described { serial: info.dwVolumeSerialNumber, fs_name: name, final_path, volume_path })
    }

    /// `(file system name, is a local fixed disk)` of the volume under `dir`.
    pub(super) fn volume_of(dir: &Path) -> io::Result<(String, bool)> {
        let d = describe(dir)?;
        Ok((
            d.fs_name,
            final_path_is_on_fixed_drive(&d.final_path, |root| {
                let wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
                // SAFETY: `wide` is NUL-terminated.
                unsafe { GetDriveTypeW(wide.as_ptr()) }
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_drive_letter_path_on_a_fixed_drive_is_local() {
        let fixed = |_: &str| DRIVE_FIXED;
        assert!(final_path_is_on_fixed_drive(r"\\?\C:\Users\x", fixed));
        assert!(!final_path_is_on_fixed_drive(r"\\?\UNC\server\share\x", fixed));
        assert!(!final_path_is_on_fixed_drive(r"\\?\Volume{1234}\x", fixed));
        assert!(!final_path_is_on_fixed_drive(r"C:\no\prefix", fixed));
        assert!(!final_path_is_on_fixed_drive(r"\\?\D:\x", |root| {
            assert_eq!(root, "D:\\");
            4 // DRIVE_REMOTE
        }));
    }

    #[test]
    fn a_volume_with_only_a_dos_path_is_refused_with_a_typed_reason() {
        let dos = || Ok(r"\\?\D:\data".to_owned());
        let err = volume_paths(dos(), Err(io::Error::from(io::ErrorKind::NotFound))).unwrap_err();
        assert!(is_no_guid_path(&err), "{err:?}");
        assert!(err.to_string().contains("volume GUID"), "{err}");
        // The GUID path alone (a folder mount) and both together are fine.
        let guid = || Ok(r"\\?\Volume{1}\data".to_owned());
        assert_eq!(
            volume_paths(Err(io::Error::from(io::ErrorKind::NotFound)), guid()).unwrap().1,
            r"\\?\Volume{1}\data"
        );
        assert_eq!(volume_paths(dos(), guid()).unwrap().1, r"\\?\Volume{1}\data");
        // Neither spelling: the handle's own error, not a claim about GUIDs.
        let both = volume_paths(
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            Err(io::Error::from(io::ErrorKind::NotFound)),
        )
        .unwrap_err();
        assert!(!is_no_guid_path(&both));
    }

    /// Real volumes: a local disk is named by its GUID path; the loopback administrative share of
    /// the same disk has only a share path, so it is refused with the typed reason everywhere the
    /// volume is used, not matched by the drive letter behind it.
    #[cfg(windows)]
    #[test]
    fn a_share_path_is_refused_and_a_local_disk_is_not() {
        use crate::durable_dir::{DurableNamespace, NsError, UnavailableReason};
        let dir = tempfile::tempdir().unwrap();
        require_volume_guid_path(dir.path()).unwrap();
        // A folder not made yet is judged by its nearest existing ancestor.
        require_volume_guid_path(&dir.path().join("a").join("b")).unwrap();
        assert!(volume_key(dir.path()).is_ok());

        let text = dir.path().to_string_lossy().into_owned();
        let share = std::path::PathBuf::from(format!(r"\\localhost\{}${}", &text[..1], &text[2..]));
        let error = require_volume_guid_path(&share).unwrap_err();
        assert!(is_no_guid_path(&error), "{error:?}");
        assert!(is_no_guid_path(&volume_key(&share).unwrap_err()));
        assert_eq!(cached_verdict(&share).verdict, Capability::Unsupported);
        assert_eq!(probe(&share), Capability::Unsupported);
        assert!(matches!(
            DurableNamespace::open(&share),
            Err(NsError::Unavailable(UnavailableReason::VolumeWithoutGuidPath, _))
        ));
    }

    #[test]
    fn volume_parsing_never_slices_inside_a_character() {
        for path in [
            "",
            "\\\\?\\",
            "\\\\?\\UNC",
            "\\\\?\\UNC\\",
            "日本語",
            "あ\\x",
            "\u{1F600}",
            "e\u{301}\\x",
            "\\\\?\\日本語\\x",
            "\\\\?\\UNC\\サーバー\\共有\\x",
            "uü\\x",
            "unÿ\\x",
            "Ｃ：＼",
            "\\\\?\\Ｃ：＼x",
            "\\\\?\\\u{1F600}:\\",
        ] {
            let _ = windows_volume_key(1, "NTFS", path);
            let _ = final_path_is_on_fixed_drive(path, |_| 0);
        }
        assert_eq!(
            windows_volume_key(1, "NTFS", r"\\?\UNC\サーバー\共有\x"),
            "00000001|ntfs|unc\\サーバー\\共有".to_lowercase()
        );
    }

    #[test]
    fn volumes_sharing_a_serial_have_different_keys() {
        let ntfs_c = windows_volume_key(0x1234, "NTFS", r"\\?\C:\data");
        assert_ne!(ntfs_c, windows_volume_key(0x1234, "NTFS", r"\\?\D:\data"));
        assert_ne!(ntfs_c, windows_volume_key(0x1234, "FAT32", r"\\?\C:\data"));
        assert_ne!(
            windows_volume_key(0x1234, "NTFS", r"\\?\Volume{a}\x"),
            windows_volume_key(0x1234, "NTFS", r"\\?\Volume{b}\x")
        );
        assert_ne!(
            windows_volume_key(1, "NTFS", r"\\?\UNC\srv\one\x"),
            windows_volume_key(1, "NTFS", r"\\?\UNC\srv\two\x")
        );
        // The same volume reached through different directories is one key.
        assert_eq!(ntfs_c, windows_volume_key(0x1234, "ntfs", r"\\?\c:\other\dir"));
    }

    #[test]
    fn a_verdict_is_not_reused_for_another_volume() {
        let supported = intern(windows_volume_key(7, "NTFS", r"\\?\C:\a"));
        let other = intern(windows_volume_key(7, "NTFS", r"\\?\Volume{zz}\a"));
        assert_ne!(supported, other);
        assert_eq!(verdict_for(supported, || Capability::Supported), Capability::Supported);
        // Not probed again for the same volume ...
        assert_eq!(verdict_for(supported, || panic!("probed twice")), Capability::Supported);
        // ... but a different volume with the same serial gets its own probe.
        assert_eq!(verdict_for(other, || Capability::Unsupported), Capability::Unsupported);
    }

    /// A conclusive "unsupported" is kept for the volume and still refuses the handle.
    #[test]
    fn a_conclusive_unsupported_is_kept_and_refuses() {
        let volume = intern("conclusive-unsupported-test".to_owned());
        assert_eq!(verdict_for(volume, || Capability::Unsupported), Capability::Unsupported);
        assert_eq!(verdict_for(volume, || panic!("probed twice")), Capability::Unsupported);
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            DurableNamespace::from_verdict(
                Capability::Unsupported,
                RefusalCause::default(),
                dir.path()
            ),
            Err(NsError::Unavailable(crate::durable_dir::UnavailableReason::Unsupported, _))
        ));
    }

    /// The directory under probe vanishing mid-probe (a `NotFound` at any step) says nothing
    /// about the volume: `Unknown`, not kept, and a later valid directory on the same volume
    /// is probed fresh and is `Supported`, through the per-volume cache.
    #[test]
    fn a_vanished_probe_directory_does_not_poison_the_volume() {
        for step in [
            Step::FirstPublish,
            Step::SecondPublish,
            Step::CreateDir,
            Step::ReplacePublish,
            Step::ReadBack,
            Step::Discard,
        ] {
            let gone = tempfile::tempdir().unwrap();
            inject_at(step, io::ErrorKind::NotFound);
            let volume = intern(format!("vanished-test-{step:?}"));
            let verdict = verdict_for(volume, || probe(gone.path()));
            BUSY_AT.with(|b| b.set(None));
            assert_eq!(verdict, Capability::Unknown, "{step:?}");
            let valid = tempfile::tempdir().unwrap();
            assert_eq!(
                verdict_for(volume, || probe(valid.path())),
                Capability::Supported,
                "{step:?}"
            );
        }
    }

    #[test]
    fn a_directory_and_its_child_share_one_volume_key() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("child");
        std::fs::create_dir(&child).unwrap();
        assert_eq!(volume_key(dir.path()).unwrap(), volume_key(&child).unwrap());
    }

    /// A sharing violation or a failed removal at any probe step is the volume being busy, not a
    /// wrong answer about the shapes: the verdict is `Unknown`, is not kept, and the next probe
    /// (nothing in the way) is `Supported`.
    #[test]
    fn a_busy_step_is_unknown_and_is_not_kept() {
        for step in [
            Step::FirstPublish,
            Step::SecondPublish,
            Step::CreateDir,
            Step::ReplacePublish,
            Step::ReadBack,
            Step::Discard,
            Step::Removal,
        ] {
            let dir = tempfile::tempdir().unwrap();
            inject_at(step, io::ErrorKind::ResourceBusy);
            let verdict = probe(dir.path());
            BUSY_AT.with(|b| b.set(None));
            assert_eq!(verdict, Capability::Unknown, "{step:?}");
            // Not kept: the same volume is probed again and answers.
            let volume = intern(format!("busy-test-{step:?}"));
            assert_eq!(verdict_for(volume, || verdict), Capability::Unknown);
            assert_eq!(
                verdict_for(volume, || probe(dir.path())),
                Capability::Supported,
                "{step:?}"
            );
        }
    }

    /// Only an error that says the volume cannot do the shape, or a shape that did the wrong
    /// thing, is `Unsupported`; a full disk or an I/O error at any step says nothing about the
    /// shapes and is `Unknown`.
    #[test]
    fn only_a_definite_answer_is_unsupported() {
        for step in [
            Step::FirstPublish,
            Step::SecondPublish,
            Step::CreateDir,
            Step::ReplacePublish,
            Step::ReadBack,
            Step::Discard,
        ] {
            for (kind, expected) in [
                (io::ErrorKind::StorageFull, Capability::Unknown),
                (io::ErrorKind::Other, Capability::Unknown),
                (io::ErrorKind::Unsupported, Capability::Unsupported),
            ] {
                let dir = tempfile::tempdir().unwrap();
                inject_at(step, kind);
                let verdict = probe(dir.path());
                BUSY_AT.with(|b| b.set(None));
                assert_eq!(verdict, expected, "{step:?} {kind:?}");
            }
        }
    }

    fn cause_text(probed: &Probed) -> String {
        probed.cause.detail().expect("a refusal carries its cause").to_owned()
    }

    /// Unsupported: the cause names the probe step, the error with its errno, the probed path
    /// and the volume.
    #[test]
    fn an_unsupported_verdict_carries_step_errno_path_and_volume() {
        let dir = tempfile::tempdir().unwrap();
        inject_at(Step::CreateDir, io::ErrorKind::Unsupported);
        let probed = probe_explained(dir.path());
        BUSY_AT.with(|b| b.set(None));
        assert_eq!(probed.verdict, Capability::Unsupported);
        let text = cause_text(&probed);
        for needle in ["step CreateDir", "errno=", "volume key", &format!("{:?}", dir.path())] {
            assert!(text.contains(needle), "{needle:?} missing from {text}");
        }
        let refused = DurableNamespace::from_verdict(probed.verdict, probed.cause, dir.path());
        let message = refused.unwrap_err().to_string();
        assert!(message.contains("Unsupported") && message.contains("step CreateDir"), "{message}");
    }

    /// A conclusive refusal says what the probe directory held when the volume answered.
    #[test]
    fn an_unsupported_verdict_lists_the_probe_directory() {
        let dir = tempfile::tempdir().unwrap();
        inject_at(Step::CreateDir, io::ErrorKind::Unsupported);
        let probed = probe_explained(dir.path());
        BUSY_AT.with(|b| b.set(None));
        let text = cause_text(&probed);
        assert!(text.contains("probe directory held [\"f\"]"), "{text}");
        assert!(!text.contains("probe directory held") || probed.verdict != Capability::Unknown);
    }

    /// Unknown, from a step of the probe: same.
    #[test]
    fn an_unknown_verdict_from_a_step_carries_step_and_errno() {
        let dir = tempfile::tempdir().unwrap();
        inject_at(Step::Discard, io::ErrorKind::ResourceBusy);
        let probed = probe_explained(dir.path());
        BUSY_AT.with(|b| b.set(None));
        assert_eq!(probed.verdict, Capability::Unknown);
        let text = cause_text(&probed);
        assert!(text.contains("step Discard") && text.contains("errno="), "{text}");
        assert!(text.contains("volume key"), "{text}");
    }

    /// Unknown, because the directory is gone before the volume can be identified: the real
    /// errno of the failing `stat` is in the message.
    #[test]
    fn an_unknown_verdict_for_a_missing_directory_carries_the_errno() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone");
        let probed = cached_verdict(&missing);
        assert_eq!(probed.verdict, Capability::Unknown);
        let text = cause_text(&probed);
        assert!(text.contains("step volume_key") && text.contains("errno=Some("), "{text}");
        assert!(text.contains("gone"), "{text}");
        let message = DurableNamespace::open(&missing).unwrap_err().to_string();
        assert!(message.contains("errno=Some("), "{message}");
    }

    /// The cause survives the cache: a refusal answered without probing still explains itself.
    #[test]
    fn a_cached_refusal_keeps_its_cause() {
        let volume = intern("cached-cause-test".to_owned());
        let cause = RefusalCause::new("step CreateDir: boom [kind=Unsupported, errno=Some(95)]");
        let first = verdict_cached(volume, || Probed {
            verdict: Capability::Unsupported,
            cause: cause.clone(),
        });
        assert_eq!(first.cause, cause);
        assert_eq!(verdict_cached(volume, || panic!("probed twice")).cause, cause);
    }

    /// The gate and no-GUID-path refusals have causes of their own.
    #[test]
    fn gate_and_guid_path_refusals_carry_a_cause() {
        let error = io::Error::new(io::ErrorKind::Unsupported, NoVolumeGuidPath);
        let cause = guid_path_cause(Path::new("D:\\data"), &error);
        let message = NsError::Unavailable(
            crate::durable_dir::UnavailableReason::VolumeWithoutGuidPath,
            cause,
        )
        .to_string();
        assert!(message.contains("no GUID path") && message.contains("errno="), "{message}");
        assert!(message.contains("data"), "{message}");
    }

    /// A probe leaves nothing of its own behind, and it never deletes what it did not create.
    #[test]
    fn a_probe_never_deletes_an_old_directory_it_did_not_make() {
        let dir = tempfile::tempdir().unwrap();
        let name = crate::reserved_namespace::artefact_component_name(
            crate::reserved_namespace::ArtefactKind::Probe,
            &format!("1-1-1-{PROBE_LABEL}"),
        )
        .unwrap();
        let old = dir.path().join(name);
        std::fs::create_dir(&old).unwrap();
        std::fs::write(old.join("keep"), b"x").unwrap();
        assert_eq!(probe(dir.path()), Capability::Supported);
        assert!(old.join("keep").exists());
    }
}
