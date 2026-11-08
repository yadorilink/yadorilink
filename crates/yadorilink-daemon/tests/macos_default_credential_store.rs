//! A bare `yadorilink-daemon` on macOS (outside the signed app bundle, so without the
//! `keychain-access-groups` entitlement) starts with its default credential settings.
//!
//! Its default store is the owner-only file; the Data Protection Keychain would refuse every
//! access with `-34018` and the daemon would exit before serving. The test runs with the
//! credential variables unset on purpose: that is exactly what a script install does.

// apple-cfg-file: macos-only the bare-engine keychain limit exists on macOS only
#![cfg(target_os = "macos")]

use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_daemon_outside_the_app_bundle_starts_with_the_default_credential_store() {
    let root = tempfile::Builder::new().prefix("yl").tempdir_in("/tmp").unwrap();
    let p = root.path();
    let config_dir = p.join("cfg");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(p.join("home")).unwrap();
    let control_socket = p.join("c.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_yadorilink-daemon"))
        .env_clear()
        .env("HOME", p.join("home"))
        .env("YADORILINK_CONFIG_DIR", &config_dir)
        .env("YADORILINK_SYNC_DB", config_dir.join("sync.sqlite3"))
        .env("YADORILINK_BLOCK_STORE", p.join("blocks"))
        .env("YADORILINK_CONTROL_SOCKET", &control_socket)
        .env("YADORILINK_SHELL_IPC_SOCKET", p.join("s.sock"))
        .env("YADORILINK_SYNC_RELAYS", "none")
        .env("YADORILINK_HTTP_API_DISABLE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawning the daemon binary");

    let deadline = Instant::now() + Duration::from_secs(60);
    let outcome = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Err(format!("the daemon exited ({status}) before serving"));
        }
        if UnixStream::connect(&control_socket).is_ok() {
            break Ok(());
        }
        if Instant::now() > deadline {
            break Err("the daemon never served its control socket".to_owned());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();
    outcome.unwrap();
}
