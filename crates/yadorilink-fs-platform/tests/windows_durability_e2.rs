//! The operations of the trace experiment, run in isolation so an ETW trace can
//! be matched against them. Each iteration prints a marker line with the time
//! (Windows FILETIME, 100 ns ticks) just before the primitive is called and just
//! after it returned:
//!   {"event":"e2","op":"move_wt","i":3,"pid":1234,"begin":...,"end":...}
//! the maintainer trace analyzer then asks whether the trace holds a
//! flush or a forced-unit-access write between `begin` and `end`.
//!
//! `YADORILINK_E2_OP` is one of: move_wt (no-replace write-through move),
//! move_replace_wt (replacing write-through move), move_plain (control: the same
//! move without write-through), replacefile (reference only).
//!
//! This is a sanity check, not a contract: the contract is the documented
//! behaviour of `MoveFileExW(MOVEFILE_WRITE_THROUGH)`. That the expected API and
//! flags are what the product calls is asserted by the unit test
//! `the_windows_move_asks_for_write_through_and_never_for_a_copy`; a flush or a
//! forced-unit-access write inside the call is supporting evidence only, and not
//! seeing one never blocks anything.
//! `YADORILINK_E2_DIR` is the directory to work in (default: the temp dir) and
//! `YADORILINK_E2_ITERATIONS` the count (default 20).
#![cfg(windows)]

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use yadorilink_fs_platform::durable_dir::{durable_flush_directory, rename_no_replace_durable};

fn filetime() -> u64 {
    // 100 ns ticks since 1601-01-01.
    let since_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (since_unix.as_nanos() / 100) as u64 + 116_444_736_000_000_000
}

fn move_ex(from: &Path, to: &Path, flags: u32) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
    let wide = |p: &Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
    let (from, to) = (wide(from), wide(to));
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[test]
#[ignore = "Windows evidence run; needs ETW tracing around it"]
fn e2_trace_ops() {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let op = std::env::var("YADORILINK_E2_OP").expect("YADORILINK_E2_OP");
    let iterations: usize =
        std::env::var("YADORILINK_E2_ITERATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(20);
    let base = std::env::var("YADORILINK_E2_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let work = base.join(format!("yadorilink-e2-{}", std::process::id()));
    fs::create_dir_all(&work).unwrap();
    durable_flush_directory(&work).unwrap();
    for i in 0..iterations {
        let (a, b) = (work.join(format!("a{i}")), work.join(format!("b{i}")));
        // Setup is flushed and then left to settle so the trace of the operation
        // under test is not mixed with the trace of its preparation.
        match op.as_str() {
            "move_wt" | "move_plain" | "replacefile" => fs::write(&a, b"x").unwrap(),
            "move_replace_wt" => {
                fs::write(&a, b"x").unwrap();
                fs::write(&b, b"y").unwrap();
            }
            _ => {}
        }
        if matches!(op.as_str(), "move_wt" | "move_plain" | "move_replace_wt") {
            fs::File::open(&a).unwrap();
            fs::OpenOptions::new().write(true).open(&a).unwrap().sync_all().unwrap();
            if op == "move_replace_wt" {
                fs::OpenOptions::new().write(true).open(&b).unwrap().sync_all().unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(500));
        let begin = filetime();
        match op.as_str() {
            "move_wt" => rename_no_replace_durable(&a, &b).unwrap(),
            "move_replace_wt" => {
                move_ex(&a, &b, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH).unwrap()
            }
            "move_plain" => move_ex(&a, &b, 0).unwrap(),
            "replacefile" => {
                fs::write(&b, b"old").unwrap();
                std::thread::sleep(Duration::from_millis(500));
                let (new, old) = (a.clone(), b.clone());
                use std::os::windows::ffi::OsStrExt;
                let wide =
                    |p: &Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
                let (n, o) = (wide(&new), wide(&old));
                // SAFETY: NUL-terminated buffers that outlive the call; optional arguments are null.
                let ok = unsafe {
                    windows_sys::Win32::Storage::FileSystem::ReplaceFileW(
                        o.as_ptr(),
                        n.as_ptr(),
                        std::ptr::null(),
                        0,
                        std::ptr::null(),
                        std::ptr::null(),
                    )
                };
                assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
            }
            other => panic!("unknown YADORILINK_E2_OP {other}"),
        }
        let end = filetime();
        println!(
            "{}",
            serde_json::json!({"event": "e2", "op": op, "i": i, "pid": std::process::id(),
                               "begin": begin, "end": end})
        );
    }
    let _ = fs::remove_dir_all(&work);
}
