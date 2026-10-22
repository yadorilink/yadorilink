#![cfg(test)]

use yadorilink_ipc_proto::daemonctl::GcResponse;

use super::*;

#[test]
fn dry_run_report_says_would_delete() {
    let report = GcResponse { blocks_deleted: 3, bytes_reclaimed: 1024 };
    let line = format_gc_report(&report, true);
    assert!(line.contains("Dry run"));
    assert!(line.contains("would delete 3 block(s)"));
    assert!(line.contains("1024 bytes"));
}

#[test]
fn real_run_report_says_deleted() {
    let report = GcResponse { blocks_deleted: 3, bytes_reclaimed: 1024 };
    let line = format_gc_report(&report, false);
    assert!(!line.contains("Dry run"));
    assert!(line.contains("Deleted 3 block(s)"));
    assert!(line.contains("1024 bytes"));
}

#[test]
fn zero_blocks_reports_zero_cleanly() {
    let report = GcResponse { blocks_deleted: 0, bytes_reclaimed: 0 };
    let line = format_gc_report(&report, false);
    assert!(line.contains("Deleted 0 block(s), reclaimed 0 bytes"));
}
