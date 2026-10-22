#![cfg(test)]

use super::*;

#[test]
fn generate_produces_64_hex_chars_and_varies() {
    let a = generate();
    let b = generate();
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b, "two consecutive tokens must not collide");
}

#[cfg(unix)]
#[test]
fn write_token_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile_dir();
    let path = dir.join("http-api-token");
    write_token_file(&path, "deadbeef").unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "token file must be owner-read/write only");
    let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "token directory must be owner-only");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "deadbeef");
}

#[cfg(unix)]
#[test]
fn write_token_file_narrows_a_pre_existing_wide_open_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile_dir();
    let path = dir.join("http-api-token");
    std::fs::write(&path, "old").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    write_token_file(&path, "new-token").unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new-token");
}

#[cfg(unix)]
fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "yadorilink-http-api-token-test-{}-{}",
        std::process::id(),
        generate()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
