//! A background Windows start (logon task, packaged app) must not open a console window, which
//! needs the GUI subsystem on the daemon binary. That subsystem starts a process without usable
//! standard handles, so `--version` is checked by behaviour: the line must reach a pipe and a
//! redirected file. The subsystem attribute itself cannot be observed from the test, so the
//! source is checked for it on Windows.

use std::process::{Command, Stdio};

fn expected_prefix() -> String {
    format!("{} {} (host api ", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

#[test]
fn version_reaches_a_pipe() {
    let output = Command::new(env!("CARGO_BIN_EXE_yadorilink-daemon"))
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn daemon");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with(&expected_prefix()), "unexpected --version output: {stdout:?}");
    assert!(stdout.ends_with('\n'));
}

#[test]
fn version_reaches_a_redirected_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("version.txt");
    let file = std::fs::File::create(&path).expect("create output file");
    let status = Command::new(env!("CARGO_BIN_EXE_yadorilink-daemon"))
        .arg("-V")
        .stdin(Stdio::null())
        .stdout(file)
        .stderr(Stdio::null())
        .status()
        .expect("spawn daemon");
    assert!(status.success());
    let text = std::fs::read_to_string(&path).expect("read output file");
    assert!(text.starts_with(&expected_prefix()), "unexpected --version output: {text:?}");
}

#[cfg(windows)]
#[test]
fn the_daemon_binary_uses_the_windows_gui_subsystem() {
    let main = include_str!("../src/main.rs");
    assert!(
        main.contains(r#"#![cfg_attr(windows, windows_subsystem = "windows")]"#),
        "the daemon binary must not open a console window for background starts"
    );
    assert!(main.contains("console::attach_parent();"), "terminal starts must regain a console");
}
