#![cfg(test)]

use std::io::Cursor;

use super::*;

#[test]
fn confirm_with_reader_accepts_y_and_yes_case_insensitively() {
    assert!(confirm_with_reader("ok?", false, &mut Cursor::new(b"y\n".to_vec())));
    assert!(confirm_with_reader("ok?", false, &mut Cursor::new(b"Yes\n".to_vec())));
    assert!(confirm_with_reader("ok?", false, &mut Cursor::new(b"YES\n".to_vec())));
}

#[test]
fn confirm_with_reader_rejects_anything_else() {
    assert!(!confirm_with_reader("ok?", false, &mut Cursor::new(b"n\n".to_vec())));
    assert!(!confirm_with_reader("ok?", false, &mut Cursor::new(b"\n".to_vec())));
    assert!(!confirm_with_reader("ok?", false, &mut Cursor::new(b"".to_vec())));
}

#[test]
fn queue_item_line_renders_every_field() {
    let item = QueueItem {
        report_id: "r-1".into(),
        report_type: "error".into(),
        queued_at: "2026-01-01T00:00:00Z".into(),
        size_bytes: 512,
        submit_attempts: 3,
    };
    assert_eq!(
        queue_item_line(&item),
        "r-1  type=error  queued_at=2026-01-01T00:00:00Z  size=512  attempts=3"
    );
}

/// `assume_yes` (the CLI's
/// `--yes` flag) skips reading the reader entirely, so it works even
/// with a reader that would otherwise reject (proving the flag, not
/// the input, decided the outcome).
#[test]
fn confirm_with_reader_assume_yes_skips_reading_input() {
    assert!(confirm_with_reader("ok?", true, &mut Cursor::new(b"n\n".to_vec())));
    assert!(confirm_with_reader("ok?", true, &mut Cursor::new(b"".to_vec())));
}
