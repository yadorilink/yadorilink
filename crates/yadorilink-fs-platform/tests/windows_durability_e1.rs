//! API behaviour of the Windows namespace-durability primitives, measured on
//! one volume at a time with no crash involved. Each case prints a JSON line
//! (`{"event":"e1",...}`) for the evidence file; the run fails only if a case
//! that must work on a local fixed NTFS volume does not, or if the probe
//! trusts a volume it should not. The write-through moves are what the product
//! relies on; the directory-flush cases are recorded (`required: false`) and
//! never decide anything.
//!
//! Run on a Windows host, once per volume:
//!   cargo test -p yadorilink-root-authority --test windows_durability_e1 -- --ignored --nocapture
//! `YADORILINK_E1_SECOND_VOLUME_DIR` names a directory on a second volume for
//! `e1_second_volume`; `YADORILINK_E1_ITERATIONS` (default 10) is the repeat count.
#![cfg(windows)]

use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, MoveFileExW, ReplaceFileW, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING,
};
use yadorilink_fs_platform::durable_dir::{
    durable_flush_directory, local_volume_file_system, probe_directory_durability,
    rename_no_replace_durable,
};
use yadorilink_fs_platform::fs_capabilities::Capability;

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn win32<T>(ok: bool, value: T) -> io::Result<T> {
    if ok {
        Ok(value)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Opens `dir` with the given access, closing the handle after `then`.
fn with_dir_handle<T>(
    dir: &Path,
    access: u32,
    then: impl FnOnce(windows_sys::Win32::Foundation::HANDLE) -> io::Result<T>,
) -> io::Result<T> {
    let name = wide(dir);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let result = then(handle);
    // SAFETY: `handle` was opened above and is closed exactly once.
    unsafe { CloseHandle(handle) };
    result
}

fn flush_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<()> {
    // SAFETY: `handle` is open for the duration of the call.
    win32(unsafe { FlushFileBuffers(handle) } != 0, ())
}

fn move_ex(from: &Path, to: &Path, flags: u32) -> io::Result<()> {
    let (from, to) = (wide(from), wide(to));
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    win32(unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } != 0, ())
}

fn replace_file(replacement: &Path, replaced: &Path) -> io::Result<()> {
    let (new, old) = (wide(replacement), wide(replaced));
    // SAFETY: both buffers are NUL-terminated; the optional arguments are null.
    let ok = unsafe {
        ReplaceFileW(
            old.as_ptr(),
            new.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    win32(ok != 0, ())
}

#[derive(Clone, Copy, PartialEq)]
enum Need {
    /// Must succeed on a local fixed NTFS volume.
    Works,
    /// Recorded only.
    Observe,
}

struct Case {
    name: &'static str,
    need: Need,
    run: fn(&Path) -> io::Result<()>,
}

fn file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

const CASES: &[Case] = &[
    Case {
        name: "dir_open_generic_write_backup_reparse",
        need: Need::Works,
        run: |d| with_dir_handle(d, GENERIC_WRITE, |_| Ok(())),
    },
    Case {
        name: "dir_open_generic_read_backup_reparse",
        need: Need::Observe,
        run: |d| with_dir_handle(d, GENERIC_READ, |_| Ok(())),
    },
    Case {
        name: "flush_dir_handle_generic_write",
        need: Need::Works,
        run: |d| with_dir_handle(d, GENERIC_WRITE, flush_handle),
    },
    Case {
        name: "flush_dir_handle_generic_read",
        need: Need::Observe,
        run: |d| with_dir_handle(d, GENERIC_READ, flush_handle),
    },
    Case {
        name: "std_file_open_dir_sync_all",
        need: Need::Observe,
        run: |d| fs::File::open(d)?.sync_all(),
    },
    Case {
        name: "std_open_dir_backup_semantics_read_sync_all",
        need: Need::Observe,
        run: |d| {
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(d)?
                .sync_all()
        },
    },
    Case {
        name: "primitive_durable_flush_directory",
        need: Need::Observe,
        run: durable_flush_directory,
    },
    Case {
        name: "movefileex_replace_no_write_through",
        need: Need::Works,
        run: |d| {
            let (a, b) = (d.join("a"), d.join("b"));
            file(&a, b"new")?;
            file(&b, b"old")?;
            move_ex(&a, &b, MOVEFILE_REPLACE_EXISTING)?;
            check(&b, b"new")
        },
    },
    Case {
        name: "movefileex_replace_write_through",
        need: Need::Works,
        run: |d| {
            let (a, b) = (d.join("a"), d.join("b"));
            file(&a, b"new")?;
            file(&b, b"old")?;
            move_ex(&a, &b, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)?;
            check(&b, b"new")
        },
    },
    Case {
        name: "movefileex_noreplace_write_through_file",
        need: Need::Works,
        run: |d| {
            let (a, b) = (d.join("a"), d.join("b"));
            file(&a, b"new")?;
            move_ex(&a, &b, MOVEFILE_WRITE_THROUGH)?;
            check(&b, b"new")
        },
    },
    Case {
        name: "movefileex_noreplace_write_through_dir",
        need: Need::Works,
        run: |d| {
            let (a, b) = (d.join("da"), d.join("db"));
            fs::create_dir(&a)?;
            file(&a.join("inner"), b"x")?;
            move_ex(&a, &b, MOVEFILE_WRITE_THROUGH)?;
            check(&b.join("inner"), b"x")
        },
    },
    Case {
        name: "movefileex_noreplace_refuses_existing_target",
        need: Need::Works,
        run: |d| {
            let (a, b) = (d.join("a"), d.join("b"));
            file(&a, b"new")?;
            file(&b, b"old")?;
            match move_ex(&a, &b, MOVEFILE_WRITE_THROUGH) {
                Ok(()) => Err(io::Error::other("an existing target was replaced")),
                Err(_) => check(&b, b"old"),
            }
        },
    },
    Case {
        name: "primitive_rename_no_replace_durable",
        need: Need::Works,
        run: |d| {
            let (a, b) = (d.join("a"), d.join("b"));
            file(&a, b"new")?;
            rename_no_replace_durable(&a, &b)?;
            check(&b, b"new")?;
            file(&a, b"again")?;
            match rename_no_replace_durable(&a, &b) {
                Ok(()) => Err(io::Error::other("an existing target was replaced")),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
                Err(error) => Err(error),
            }
        },
    },
    Case {
        name: "replacefilew",
        need: Need::Observe,
        run: |d| {
            let (a, b) = (d.join("a"), d.join("b"));
            file(&a, b"new")?;
            file(&b, b"old")?;
            replace_file(&a, &b)?;
            check(&b, b"new")
        },
    },
    Case {
        name: "mkdir_then_flush_parent",
        need: Need::Observe,
        run: |d| {
            let sub = d.join("sub");
            fs::create_dir(&sub)?;
            durable_flush_directory(d)?;
            durable_flush_directory(&sub)
        },
    },
    Case {
        name: "remove_then_flush_parent",
        need: Need::Observe,
        run: |d| {
            let f = d.join("gone");
            file(&f, b"x")?;
            fs::remove_file(&f)?;
            durable_flush_directory(d)?;
            fs::create_dir(d.join("gonedir"))?;
            fs::remove_dir(d.join("gonedir"))?;
            durable_flush_directory(d)
        },
    },
];

fn check(path: &Path, want: &[u8]) -> io::Result<()> {
    if fs::read(path)? == want {
        Ok(())
    } else {
        Err(io::Error::other(format!("{} has other content", path.display())))
    }
}

fn run_volume(label: &str, base: &Path) {
    let iterations: usize =
        std::env::var("YADORILINK_E1_ITERATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(10);
    let work = base.join(format!("yadorilink-e1-{}", std::process::id()));
    fs::create_dir_all(&work).unwrap();
    let (fs_name, fixed) = local_volume_file_system(&work).unwrap();
    let trusted_shape = fixed && fs_name.eq_ignore_ascii_case("NTFS");
    println!(
        "{}",
        json!({"event": "e1_volume", "volume": label, "dir": work.display().to_string(),
               "file_system": fs_name, "fixed": fixed, "iterations": iterations})
    );
    let mut required_failures = 0;
    for case in CASES {
        let (mut ok, mut codes) = (0, Vec::new());
        for i in 0..iterations {
            let dir = work.join(format!("{}-{i}", case.name));
            fs::create_dir(&dir).unwrap();
            match (case.run)(&dir) {
                Ok(()) => ok += 1,
                Err(error) => codes.push(json!({"iteration": i, "os_error": error.raw_os_error(),
                                                 "message": error.to_string()})),
            }
        }
        println!(
            "{}",
            json!({"event": "e1", "volume": label, "file_system": fs_name, "case": case.name,
                   "required": case.need == Need::Works, "attempts": iterations, "ok": ok,
                   "errors": codes})
        );
        if case.need == Need::Works && ok != iterations {
            required_failures += 1;
        }
    }
    let verdict = probe_directory_durability(&work);
    println!(
        "{}",
        json!({"event": "e1_probe", "volume": label, "file_system": fs_name, "fixed": fixed,
               "probe": format!("{verdict:?}"), "required_case_failures": required_failures})
    );
    let _ = fs::remove_dir_all(&work);
    // The probe is the authority, and it trusts nothing but a local fixed NTFS
    // volume on which the primitives work.
    if trusted_shape {
        assert_eq!(
            verdict == Capability::Supported,
            required_failures == 0,
            "probe and required cases disagree on {label}"
        );
        assert_eq!(required_failures, 0, "a required primitive failed on {label}");
    } else {
        assert_ne!(verdict, Capability::Supported, "{label} ({fs_name}) must not be trusted");
    }
}

#[test]
#[ignore = "Windows evidence run; prints JSON lines for the evidence file"]
fn e1_system_volume() {
    run_volume("system", &std::env::temp_dir());
}

#[test]
#[ignore = "Windows evidence run; needs YADORILINK_E1_SECOND_VOLUME_DIR"]
fn e1_second_volume() {
    match std::env::var("YADORILINK_E1_SECOND_VOLUME_DIR") {
        Ok(dir) => run_volume("second", &PathBuf::from(dir)),
        Err(_) => println!(
            "{}",
            json!({"event": "e1_skipped", "volume": "second",
                                         "reason": "YADORILINK_E1_SECOND_VOLUME_DIR is not set"})
        ),
    }
}
