//! Unregistering the sync roots when the app package is uninstalled.
//!
//! An MSIX package has no uninstall action, and the registration of a Cloud Files sync root
//! outlives the package (verified: after `Remove-AppxPackage` the root is still registered). What
//! the platform does is end every process of the package, children included, within a few tens of
//! milliseconds of announcing the removal: too short to unregister anything, and too short to
//! start a helper reliably from the announcement. So a running host starts its helper early:
//!
//! 1. at start it keeps a copy of its own executable outside the package ([`stage_helper`]),
//! 2. and starts that copy as a guardian that breaks away from the package ([`spawn_detached`]):
//!    it has no package identity and is not ended with it,
//! 3. the guardian (`--guard-package-removal <family> <host pid>`) waits for the host to end
//!    ([`wait_for_exit`]), then watches the package family for a while ([`removal_confirmed`]).
//!    If the family disappears and stays gone, the package was uninstalled: it unregisters the
//!    recorded roots and has itself deleted. If the family is still installed when the grace
//!    period ends (the host was stopped, or updated), it leaves everything as it is and ends.
//!
//! The record of the roots is kept (unlike `--unregister-all`), so that a reinstall puts every root
//! back on the folder where it was instead of starting a second folder next to the user's files.
//!
//! Only a root without online-only items is unregistered ([`holds_online_only_items`]): a
//! placeholder whose bytes are not on this PC would be unreadable with no provider, so such a root
//! stays registered and a reinstall serves it again. Files that are on this PC are plain files
//! once the root is unregistered; nothing of the user's is ever deleted.
//!
//! When no host ran in the last [`GRACE`] before an uninstall nothing runs, and the registration
//! stays until the next install starts a host or `--unregister-all` is run.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, OpenProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT,
    INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, STARTUPINFOEXW,
};

/// The argument of the guardian process: `<flag> <package family> <host process id>`.
pub const GUARD_FLAG: &str = "--guard-package-removal";

const HELPER_DIR: &str = "yadorilink-uninstall-helper";
const HELPER_FILE: &str = "yadorilink-cfapi-host.exe";

/// How often the guardian looks at the package family.
pub const POLL: Duration = Duration::from_millis(250);
/// How long, after its host ended, the guardian waits for the removal to show before it concludes
/// that the package stays (the host was stopped, or the package was updated).
pub const GRACE: Duration = Duration::from_secs(30);
/// How long the family has to stay gone before it counts as removed (an update replaces the
/// version without the family ever being absent; this only guards against a moment's gap).
pub const STABLE: Duration = Duration::from_secs(3);

/// `PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY` and its `..._BREAKAWAY_ENABLE_PROCESS_TREE` value.
const DESKTOP_APP_POLICY_ATTRIBUTE: usize = 0x0002_0012;
const BREAKAWAY_ENABLE_PROCESS_TREE: u32 = 0x1;

const APPMODEL_ERROR_NO_PACKAGE: u32 = 15700;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentPackageFamilyName(length: *mut u32, name: *mut u16) -> u32;
    fn GetPackagesByPackageFamily(
        family: *const u16,
        count: *mut u32,
        full_names: *mut *mut u16,
        buffer_length: *mut u32,
        buffer: *mut u16,
    ) -> u32;
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// The package family of this process, `None` without package identity.
#[must_use]
pub fn current_family() -> Option<String> {
    let mut length = 0u32;
    // SAFETY: a zero length with a null buffer only asks for the size.
    let status = unsafe { GetCurrentPackageFamilyName(&mut length, std::ptr::null_mut()) };
    if status == APPMODEL_ERROR_NO_PACKAGE || length == 0 {
        return None;
    }
    let mut name = vec![0u16; length as usize];
    // SAFETY: the buffer holds `length` UTF-16 units, as asked for above.
    let status = unsafe { GetCurrentPackageFamilyName(&mut length, name.as_mut_ptr()) };
    if status != 0 {
        return None;
    }
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    Some(String::from_utf16_lossy(&name[..end]))
}

/// Whether any package of `family` is installed for the current user.
#[must_use]
pub fn family_installed(family: &str) -> bool {
    let family = wide(std::ffi::OsStr::new(family));
    let (mut count, mut buffer_length) = (0u32, 0u32);
    // SAFETY: null buffers with zero sizes only ask how much room the answer needs.
    let status = unsafe {
        GetPackagesByPackageFamily(
            family.as_ptr(),
            &mut count,
            std::ptr::null_mut(),
            &mut buffer_length,
            std::ptr::null_mut(),
        )
    };
    status == ERROR_INSUFFICIENT_BUFFER || count > 0
}

/// Whether `installed` (asked every `poll`) reports the family gone, and gone for `stable`, within
/// `grace`. `pause` waits one `poll`.
pub fn removal_confirmed(
    installed: &mut dyn FnMut() -> bool,
    poll: Duration,
    grace: Duration,
    stable: Duration,
    pause: &mut dyn FnMut(),
) -> bool {
    let polls = |span: Duration| (span.as_millis() / poll.as_millis().max(1)) as u32;
    let (grace_polls, stable_polls) = (polls(grace), polls(stable));
    let mut gone_for = 0u32;
    for _ in 0..=grace_polls {
        if installed() {
            gone_for = 0;
        } else {
            gone_for += 1;
            if gone_for > stable_polls {
                return true;
            }
        }
        pause();
    }
    false
}

/// Blocks until the process `pid` has ended (immediately if there is no such process).
pub fn wait_for_exit(pid: u32) {
    const SYNCHRONIZE: u32 = 0x0010_0000;
    // SAFETY: plain handle calls; the handle is closed before returning.
    unsafe {
        let handle = OpenProcess(SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            return;
        }
        WaitForSingleObject(handle, INFINITE);
        CloseHandle(handle);
    }
}

/// The executable the helper runs from, kept outside the package and the user's data. The
/// directory is named after the size and time of the executable it copies, so a guardian that is
/// still running from the copy of an earlier version never stands in the way of a newer one.
fn helper_path(temp: &Path, source: &std::fs::Metadata) -> io::Result<PathBuf> {
    let stamp = source.modified()?.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    Ok(temp
        .join(HELPER_DIR)
        .join(format!("{:x}-{:x}", source.len(), stamp.as_nanos()))
        .join(HELPER_FILE))
}

/// Keeps a copy of `exe` ready in `temp` and returns its path.
pub fn stage_helper(exe: &Path, temp: &Path) -> io::Result<PathBuf> {
    let source = std::fs::metadata(exe)?;
    let target = helper_path(temp, &source)?;
    if std::fs::metadata(&target).is_ok_and(|have| have.len() == source.len()) {
        return Ok(target);
    }
    std::fs::create_dir_all(target.parent().expect("the helper path has a directory"))?;
    let partial = target.with_extension("partial");
    std::fs::copy(exe, &partial)?;
    std::fs::rename(&partial, &target)?;
    Ok(target)
}

/// Starts `exe args` as a process that does not belong to this package: no package identity, and
/// not ended when the package is removed.
pub fn spawn_detached(exe: &Path, args: &str) -> io::Result<()> {
    let app = wide(exe.as_os_str());
    let mut command = wide(std::ffi::OsStr::new(&format!("\"{}\" {args}", exe.display())));
    let directory = wide(exe.parent().unwrap_or_else(|| Path::new(".")).as_os_str());
    let mut size = 0usize;
    // SAFETY: the first call only asks for the size of an attribute list of one entry.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    let mut storage = vec![0u64; size.div_ceil(8)];
    let list = storage.as_mut_ptr().cast::<c_void>() as LPPROC_THREAD_ATTRIBUTE_LIST;
    // SAFETY: `storage` is large enough and 8-byte aligned, and outlives every use of `list`.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let policy = BREAKAWAY_ENABLE_PROCESS_TREE;
    // SAFETY: `policy` lives until after CreateProcessW; the value is a 4-byte flag set.
    let updated = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            DESKTOP_APP_POLICY_ATTRIBUTE,
            std::ptr::from_ref(&policy).cast::<c_void>(),
            std::mem::size_of::<u32>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    let result = if updated == 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: all-zero is a valid STARTUPINFOEXW; the fields CreateProcessW reads are set.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = list;
        // SAFETY: all-zero is a valid PROCESS_INFORMATION (an output).
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every pointer is to a NUL-terminated buffer or a struct that outlives the call.
        let created = unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                std::ptr::null(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        if created == 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: both handles came from the successful call above.
            unsafe {
                CloseHandle(info.hProcess);
                CloseHandle(info.hThread);
            }
            Ok(())
        }
    };
    // SAFETY: `list` was initialized above.
    unsafe { DeleteProcThreadAttributeList(list) };
    result
}

/// The file attributes of a placeholder whose bytes are not (all) on this PC.
const RECALL_ATTRIBUTES: u32 = 0x0040_0000 | 0x0004_0000 | 0x0000_1000;

/// Whether `root` holds an item whose content is not on this PC. The attributes come from
/// `attributes_of` (the file system's, except in tests).
pub fn holds_online_only_items_with(
    root: &Path,
    attributes_of: &dyn Fn(&Path) -> io::Result<u32>,
) -> io::Result<bool> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            if attributes_of(&path)? & RECALL_ATTRIBUTES != 0 {
                return Ok(true);
            }
            if entry.file_type()?.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(false)
}

/// [`holds_online_only_items_with`] on the real file system. A root that cannot be read to the
/// end counts as holding such an item: nothing is unregistered on a guess.
#[must_use]
pub fn holds_online_only_items(root: &Path) -> bool {
    holds_online_only_items_with(root, &|path| {
        Ok(std::fs::symlink_metadata(path)?.file_attributes())
    })
    .unwrap_or(true)
}

/// Starts the guardian for this host (see the module documentation). `Ok(false)`: not a packaged
/// process, nothing to guard.
pub fn watch() -> Result<bool, String> {
    let Some(family) = current_family() else { return Ok(false) };
    let exe =
        std::env::current_exe().map_err(|e| format!("cannot find its own executable: {e}"))?;
    // The temporary directory is not part of the virtualized AppData of a package: the copy made here
    // is the real file the unpackaged guardian runs (checked on Windows 11 build 26300).
    let helper = stage_helper(&exe, &std::env::temp_dir())
        .map_err(|e| format!("cannot keep the uninstall helper ready: {e}"))?;
    spawn_detached(&helper, &format!("{GUARD_FLAG} {family} {}", std::process::id()))
        .map_err(|e| format!("cannot start the uninstall guardian: {e}"))?;
    Ok(true)
}

/// Deletes the helper and its directory once this process has ended: a running executable cannot
/// be deleted, so a short-lived `cmd.exe` waits a moment and does it. Best effort: what is left
/// is a few megabytes in the temporary directory.
pub fn remove_helper(exe: &Path) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let Some(directory) = exe.parent() else { return };
    let Some(root) = directory.parent() else { return };
    if root.file_name() != Some(std::ffi::OsStr::new(HELPER_DIR))
        || exe.file_name() != Some(std::ffi::OsStr::new(HELPER_FILE))
    {
        return;
    }
    let system =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let script = format!(
        "ping -n 3 127.0.0.1 >nul & del /f /q \"{}\" & rmdir \"{}\" & rmdir \"{}\"",
        exe.display(),
        directory.display(),
        root.display()
    );
    let _ = std::process::Command::new(system.join("System32").join("cmd.exe"))
        // Not in the directory that is about to go: a working directory keeps it alive.
        .current_dir(system.join("System32"))
        .raw_arg(format!("/d /s /c \"{script}\""))
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("yl-removal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const POLLS: (Duration, Duration, Duration) =
        (Duration::from_millis(250), Duration::from_secs(30), Duration::from_secs(3));

    #[test]
    fn a_family_that_goes_and_stays_gone_is_a_removal() {
        let mut calls = 0;
        let removed = removal_confirmed(
            &mut || {
                calls += 1;
                calls < 5
            },
            POLLS.0,
            POLLS.1,
            POLLS.2,
            &mut || {},
        );
        assert!(removed);
        assert_eq!(calls, 5 + 12, "gone from the fifth look, confirmed after more than 3 seconds");
    }

    #[test]
    fn a_gap_that_closes_and_a_family_that_stays_are_not_removals() {
        let mut calls = 0;
        // Absent for ten looks (2.5 s), then back for good: an update's moment, not a removal.
        let gap = removal_confirmed(
            &mut || {
                calls += 1;
                !(3..13).contains(&calls)
            },
            POLLS.0,
            POLLS.1,
            POLLS.2,
            &mut || {},
        );
        assert!(!gap);
        let mut pauses = 0;
        assert!(!removal_confirmed(&mut || true, POLLS.0, POLLS.1, POLLS.2, &mut || pauses += 1));
        assert_eq!(pauses, 121, "it looks for the whole grace period and then gives up");
    }

    #[test]
    fn waiting_for_a_process_ends_with_it_and_a_missing_one_is_already_over() {
        let cmd =
            Path::new(&std::env::var_os("SystemRoot").unwrap()).join("System32").join("cmd.exe");
        let mut child = std::process::Command::new(cmd)
            .args(["/c", "ping -n 3 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        wait_for_exit(child.id());
        assert!(start.elapsed() >= Duration::from_millis(900), "returned before the process ended");
        assert!(child.try_wait().unwrap().is_some());
        wait_for_exit(child.id());
        wait_for_exit(u32::MAX - 3);
    }

    #[test]
    fn a_nonexistent_family_is_not_installed() {
        assert!(!family_installed("YadoriLink.NoSuchPackage_0000000000000"));
    }

    #[test]
    fn an_unpackaged_test_process_has_no_family() {
        assert_eq!(current_family(), None);
        assert_eq!(watch(), Ok(false));
    }

    #[test]
    fn the_helper_copy_is_kept_until_the_executable_changes() {
        let dir = temp_dir("stage");
        let exe = dir.join("host.exe");
        std::fs::write(&exe, b"one").unwrap();
        let temp = dir.join("temp");
        let staged = stage_helper(&exe, &temp).unwrap();
        assert_eq!(staged.file_name().unwrap(), HELPER_FILE);
        assert_eq!(std::fs::read(&staged).unwrap(), b"one");
        let first = std::fs::metadata(&staged).unwrap().modified().unwrap();
        assert_eq!(stage_helper(&exe, &temp).unwrap(), staged);
        assert_eq!(std::fs::metadata(&staged).unwrap().modified().unwrap(), first);
        // A changed executable gets its own copy; the first stays for whoever runs from it.
        std::fs::write(&exe, b"another").unwrap();
        let second = stage_helper(&exe, &temp).unwrap();
        assert_ne!(second, staged);
        assert_eq!(std::fs::read(&second).unwrap(), b"another");
        assert_eq!(std::fs::read(&staged).unwrap(), b"one");
        assert!(!second.with_extension("partial").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn online_only_items_are_found_at_any_depth_and_plain_files_are_not() {
        let dir = temp_dir("online-only");
        std::fs::create_dir_all(dir.join("a").join("b")).unwrap();
        std::fs::write(dir.join("a").join("b").join("far.txt"), b"x").unwrap();
        std::fs::write(dir.join("near.txt"), b"x").unwrap();
        let plain = |_: &Path| Ok(0x20);
        assert!(!holds_online_only_items_with(&dir, &plain).unwrap());
        let far_is_recall = |p: &Path| Ok(if p.ends_with("far.txt") { 0x0040_0020 } else { 0x20 });
        assert!(holds_online_only_items_with(&dir, &far_is_recall).unwrap());
        let unreadable = |_: &Path| Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(holds_online_only_items_with(&dir, &unreadable).is_err());
        assert!(!holds_online_only_items(&dir));
        assert!(
            holds_online_only_items(&dir.join("missing")),
            "an unreadable root is not unregistered"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_detached_process_is_started_and_the_helper_removes_itself() {
        let dir = temp_dir("spawn");
        let marker = dir.join("ran.txt");
        let cmd =
            Path::new(&std::env::var_os("SystemRoot").unwrap()).join("System32").join("cmd.exe");
        spawn_detached(&cmd, &format!("/c echo done> \"{}\"", marker.display())).unwrap();
        let start = std::time::Instant::now();
        while !marker.exists() && start.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(marker.exists(), "the detached process did not run");

        // A copy under the helper's name deletes itself and its directory; any other file is left.
        let exe = dir.join("not-a-helper.exe");
        std::fs::write(&exe, b"x").unwrap();
        remove_helper(&exe);
        assert!(exe.exists());
        let staged = stage_helper(&cmd, &dir).unwrap();
        remove_helper(&staged);
        let root = staged.parent().unwrap().parent().unwrap().to_path_buf();
        let start = std::time::Instant::now();
        while root.exists() && start.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!root.exists(), "the copy and its directories are removed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
