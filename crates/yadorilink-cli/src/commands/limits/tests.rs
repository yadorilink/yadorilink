#![cfg(test)]

use super::*;

#[test]
fn format_limit_zero_is_unlimited() {
    assert_eq!(format_limit(0), "unlimited");
}

#[test]
fn format_limit_nonzero_reports_exact_bytes() {
    assert_eq!(format_limit(1_048_576), "1048576 bytes/sec");
}
