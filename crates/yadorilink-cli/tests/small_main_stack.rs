//! The command line starts on a small main-thread stack.
//!
//! clap builds the full command tree in generated functions with very large frames in an
//! unoptimized build; Windows' 1 MB main thread overflowed on `yadorilink --version`. The real work
//! runs on its own larger thread, so the size of the process's main stack must not matter. This
//! test lowers it to 1 MB (Windows' size) and runs the simplest commands. Unix only: it uses
//! `ulimit -s`, which sets the main thread's stack for the child.
#![cfg(unix)]

use std::process::Command;

fn run_with_main_stack_kb(kb: u32, args: &str) -> (Option<i32>, String) {
    let bin = env!("CARGO_BIN_EXE_yadorilink");
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("ulimit -s {kb} && exec \"{bin}\" {args}"))
        .output()
        .expect("sh runs");
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn version_and_help_run_on_a_one_megabyte_main_stack() {
    for args in ["--version", "--help", "share --help"] {
        let (code, stderr) = run_with_main_stack_kb(1024, args);
        assert_eq!(code, Some(0), "`yadorilink {args}` on a 1 MB main stack: {stderr}");
        assert!(!stderr.contains("overflowed its stack"), "{stderr}");
    }
}

#[test]
fn a_usage_error_still_exits_2_on_a_small_stack() {
    let (code, _) = run_with_main_stack_kb(1024, "--no-such-flag");
    assert_eq!(code, Some(2));
}
