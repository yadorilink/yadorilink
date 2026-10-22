#![cfg(test)]

use super::*;

#[test]
fn redacts_unix_absolute_path() {
    let (out, summary) = redact("failed to read /var/log/yadorilink/daemon.log: permission denied");
    assert!(!out.contains("/var/log"));
    assert!(out.contains("[REDACTED_PATH]"));
    assert!(!summary.is_empty());
}

#[test]
fn redacts_home_directory_fragment_before_generic_absolute_path() {
    let (out, _) = redact("scanning /Users/alice/Documents/secret-project failed");
    assert!(!out.contains("/Users/alice"));
    assert!(!out.contains("alice"));
}

#[test]
fn redacts_windows_home_directory() {
    let (out, _) = redact(r"C:\Users\alice\AppData\Roaming\yadorilink\sync-state.sqlite3");
    assert!(!out.contains("alice"));
}

#[test]
fn redacts_bearer_token() {
    let (out, summary) =
        redact("request failed: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdef123456");
    assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
    assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::BearerToken));
}

#[test]
fn redacts_pem_private_key_block() {
    let key =
        "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQ==\n-----END PRIVATE KEY-----";
    let (out, _) = redact(&format!("dumping state: {key}"));
    assert!(!out.contains("MIIBVQIBADANBgkqhkiG9w0BAQ"));
    assert!(out.contains("[REDACTED_PRIVATE_KEY]"));
}

#[test]
fn redacts_wireguard_style_base64_key() {
    // A syntactically-plausible 32-byte base64 key (44 chars,
    // trailing `=`) — not a real key, just shaped like one.
    let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    assert_eq!(key.len(), 44);
    let (out, summary) = redact(&format!("peer key: {key}"));
    assert!(!out.contains(key));
    assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::WireguardKey));
}

#[test]
fn redacts_ipv4_address() {
    let (out, _) = redact("connecting to peer at 203.0.113.42:51820 failed");
    assert!(!out.contains("203.0.113.42"));
}

#[test]
fn redacts_credentialed_url() {
    let (out, _) = redact("could not reach https://user:hunter2@relay.example.com/ws");
    assert!(!out.contains("hunter2"));
    assert!(!out.contains("user:hunter2"));
}

#[test]
fn redacts_uuid_like_device_or_group_id() {
    let (out, summary) = redact("device 11111111-2222-3333-4444-555555555555 is not authorized");
    assert!(!out.contains("11111111-2222-3333-4444-555555555555"));
    assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::UuidLikeId));
}

#[test]
fn redacts_email_address() {
    let (out, _) = redact("account owner: alice@example.com");
    assert!(!out.contains("alice@example.com"));
}

#[test]
fn leaves_clean_text_completely_unchanged() {
    let text = "sync failed: block hash mismatch on 4 of 12 chunks, retrying with backoff";
    let (out, summary) = redact(text);
    assert_eq!(out, text);
    assert!(summary.is_empty());
}

#[test]
fn redaction_is_idempotent() {
    let text = "user alice@example.com hit /Users/alice/project with token Bearer abcd12345678";
    let (once, _) = redact(text);
    let (twice, summary_twice) = redact(&once);
    assert_eq!(once, twice);
    assert!(summary_twice.is_empty(), "re-redacting already-redacted text should find nothing new");
}

#[test]
fn redact_lines_merges_categories_across_multiple_lines() {
    let lines = vec![
        "line one: /Users/alice/secret".to_string(),
        "line two: token Bearer abcdefgh12345678".to_string(),
    ];
    let (out, summary) = redact_lines(&lines);
    assert_eq!(out.len(), 2);
    assert!(!out[0].contains("alice"));
    assert!(!out[1].contains("abcdefgh12345678"));
    assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::HomeDirectory));
    assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::BearerToken));
}

#[test]
fn known_sensitive_example_fixture_produces_no_leaked_substrings() {
    // A sensitive-pattern redaction snapshot check and
    // privacy-focused regression fixture, in one place:
    // a synthetic log line carrying one of every sensitive category
    // this module claims to catch, asserted to be fully gone after
    // redaction.
    let sensitive_fixture = concat!(
        "panic in sync engine while processing /Users/alice/Documents/taxes.pdf ",
        "for device 11111111-2222-3333-4444-555555555555, ",
        "peer at 203.0.113.42, ",
        "auth Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop, ",
        "wg key AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=, ",
        "reported by alice@example.com, ",
        "relay https://user:hunter2@relay.example.com"
    );
    let (out, summary) = redact(sensitive_fixture);
    let leaked = [
        "alice",
        "taxes.pdf",
        "11111111-2222-3333-4444-555555555555",
        "203.0.113.42",
        "eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "hunter2",
    ];
    for needle in leaked {
        assert!(!out.contains(needle), "fixture leaked sensitive substring: {needle}");
    }
    assert!(summary.categories.len() >= 6, "expected most categories to fire on this fixture");
}

/// Asserts none of `needles` survive redaction of `text`.
fn assert_all_gone(text: &str, needles: &[&str]) {
    let (out, _) = redact(text);
    for needle in needles {
        assert!(!out.contains(needle), "{needle:?} survived in {out:?}");
    }
}

#[test]
fn windows_home_path_loses_folder_and_file_names_not_just_the_user() {
    assert_all_gone(
        r"C:\Users\alice\Clients\Acme Merger\x.docx",
        &["alice", "Clients", "Acme", "Merger", "x.docx", "Users"],
    );
    // JSON-escaped backslashes, as a path looks inside a serialized log line.
    assert_all_gone(
        r#"{"path":"C:\\Users\\alice\\Clients\\Acme Merger\\x.docx"}"#,
        &["alice", "Clients", "Acme", "Merger", "x.docx"],
    );
}

#[test]
fn unix_home_path_with_spaces_loses_folder_and_file_names() {
    assert_all_gone(
        "scanning /Users/alice/Tax Returns/2025.pdf failed",
        &["alice", "Tax", "Returns", "2025.pdf"],
    );
    assert_all_gone(
        "opened /home/bob/Family Photos/Trip 2025",
        &["bob", "Family", "Photos", "Trip"],
    );
}

#[test]
fn a_final_path_segment_with_spaces_is_redacted_whole() {
    assert_all_gone("watching /Users/alice/Acme Merger Notes", &["Acme", "Merger", "Notes"]);
}

#[test]
fn absolute_paths_outside_home_with_spaces_are_redacted_whole() {
    assert_all_gone(
        "synced /Volumes/Work Drive/Tax Returns/2025.pdf ok",
        &["Volumes", "Work", "Tax", "Returns", "2025.pdf"],
    );
    assert_all_gone(r"D:\Clients\Acme Merger\x.docx", &["Clients", "Acme", "Merger", "x.docx"]);
    assert_all_gone(r"\\fileserver\share\Acme Merger\x.docx", &["fileserver", "Acme", "x.docx"]);
}

#[test]
fn a_comma_inside_a_name_does_not_end_the_path() {
    assert_all_gone("error at /Users/alice/Smith, John/notes.pdf", &["Smith", "John", "notes.pdf"]);
}

#[test]
fn text_after_a_clear_delimiter_survives() {
    let (out, _) = redact("failed to read /Users/alice/Tax Returns/a.pdf: permission denied");
    assert!(out.ends_with(": permission denied"), "{out:?}");
    let (out, _) = redact(r#"path "/Users/alice/My Docs/a.txt" is missing"#);
    assert!(out.ends_with(r#"" is missing"#), "{out:?}");
    assert!(!out.contains("My Docs"));
    let (out, _) = redact("a /Users/alice/x\nnext line /etc/passwd stays? no");
    assert!(out.contains("\nnext line "), "{out:?}");
}

#[test]
fn an_apostrophe_inside_a_name_does_not_end_the_path() {
    assert_all_gone("opened /Users/alice/Alice's notes/todo.txt", &["Alice", "notes", "todo.txt"]);
}
