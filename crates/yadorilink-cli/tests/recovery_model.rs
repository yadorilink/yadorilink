//! Recovery-model guardrails.
//!
//! A lost or replaced device recovers by signing in with Google and
//! registering as a *new* device -- there is no exported identity artifact
//! and no import path that re-establishes an old device identity from a file.
//! These tests pin that model: the CLI source carries none of the removed
//! key-bundle symbols, and the backup guidance describes the
//! Google-login/new-device recovery path.

use std::path::{Path, PathBuf};

/// Key-bundle export/import identifiers (and their crypto primitives) that
/// must not reappear anywhere in the CLI source. Their absence is the
/// assertion that there is no key-bundle import path to re-establish a device
/// identity from a file.
const FORBIDDEN_SYMBOLS: &[&str] = &[
    "export_key_bundle",
    "import_key_bundle",
    "KeyBundle",
    "derive_bundle_key",
    "ChaCha20Poly1305",
    "Argon2",
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// There is no key-bundle import path: none of the removed export/import
/// identifiers survive anywhere in the CLI source.
#[test]
fn no_key_bundle_import_path_remains_in_cli_source() {
    let mut files = Vec::new();
    rust_sources(&src_dir(), &mut files);
    assert!(!files.is_empty(), "expected to scan some CLI source files");

    for file in &files {
        let contents = std::fs::read_to_string(file).unwrap();
        for symbol in FORBIDDEN_SYMBOLS {
            assert!(
                !contents.contains(symbol),
                "{} still references removed key-bundle symbol `{}`; recovery must be via \
new-device registration after Google login, not a key-bundle import",
                file.display(),
                symbol,
            );
        }
    }
}

/// Recovery is via a new device after Google login: the backup guidance says
/// so, and mentions none of the removed key-bundle / recovery-code artifacts.
#[test]
fn backup_guidance_directs_recovery_through_google_login_new_device() {
    let guidance = yadorilink_cli::commands::backup::recovery_guidance();
    let lower = guidance.to_lowercase();
    assert!(guidance.contains("Google"), "recovery guidance must mention Google login");
    assert!(lower.contains("new device"), "recovery guidance must mention a new device");
    assert!(lower.contains("register"), "recovery guidance must mention registering the device");
    // The old recovery artifacts are gone.
    assert!(!lower.contains("key bundle"), "recovery is not via a key bundle");
    assert!(!lower.contains("recovery code"), "recovery is not via recovery codes");
    assert!(!lower.contains("passphrase"), "recovery involves no passphrase");
}
