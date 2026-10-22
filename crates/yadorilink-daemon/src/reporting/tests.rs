#![cfg(test)]

use super::*;

fn storage() -> (tempfile::TempDir, ReportingStorage) {
    let dir = tempfile::tempdir().unwrap();
    let storage = ReportingStorage::open(dir.path());
    (dir, storage)
}

#[test]
fn opening_storage_does_not_write_any_files_until_something_mutates() {
    let (dir, _storage) = storage();
    // `ReportingCounters::open` reads (best-effort) but must not
    // create the directory just by opening; nothing else does either.
    assert!(!dir.path().exists() || std::fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[test]
fn note_methods_never_return_a_result_a_caller_could_mishandle() {
    let (_dir, storage) = storage();
    // This is mostly a compile-time property (see module doc comment)
    // but exercising every "note_*" call site once demonstrates the
    // pattern a real sync/command call site would follow: no `?`, no
    // `.unwrap`, nothing to propagate.
    storage.note_command_category("link");
    storage.note_sync_state("synced");
    storage.note_error_category("sync_conflict");
    storage.note_transfer_bytes(2048);
    storage.note_latency_millis(120);
    storage.note_peer_count(2);
    storage.note_linked_folders(1, BTreeMap::from([("eager".to_string(), 1)]));
    storage.note_feature_flags(vec!["on-demand-hydration".to_string()]);

    let payload = storage.counters().to_usage_payload();
    assert_eq!(payload.command_category_counts.get("link"), Some(&1));
}

/// reporting-storage failure isolation. Points the
/// reporting directory at a path that can never be created (a plain
/// file already sits where the directory needs to go — portable
/// across Unix and Windows, unlike chmod-based read-only tricks) and
/// asserts every infallible call still returns normally without
/// panicking, logging a warning instead of propagating.
#[test]
fn reporting_storage_failures_are_logged_and_never_propagate() {
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct CapturingWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for CapturingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for CapturingWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let blocked_reporting_dir = dir.path().join("reporting");
    // A plain file sitting where the reporting directory needs to be
    // created makes every `create_dir_all` underneath it fail.
    std::fs::write(&blocked_reporting_dir, b"not a directory").unwrap();

    let writer = CapturingWriter::default();
    let subscriber = tracing_subscriber::fmt().with_writer(writer.clone()).finish();

    tracing::subscriber::with_default(subscriber, || {
        // Constructing storage over an unwritable path must not panic.
        let storage = ReportingStorage::open(&blocked_reporting_dir);

        // A representative sample of the infallible call-site surface:
        // none of these may panic or otherwise abort the "unrelated
        // daemon operation" this simulates being called from.
        storage.note_command_category("link");
        storage.note_error_category("daemon_startup");
        let candidate = ErrorCandidateStore::new(&blocked_reporting_dir);
        let _ = candidate; // constructing doesn't touch disk either

        let consent = storage.consent_or_default();
        assert_eq!(consent, ConsentState::default(), "falls back to the safe default");

        let candidate_id = storage.record_error_candidate_best_effort(sample_error_envelope());
        assert_eq!(candidate_id, None, "failure is reported as None, not a panic/Err");
    });

    let logs = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.to_lowercase().contains("warn") && logs.to_lowercase().contains("reporting"),
        "expected a warning-level reporting log, got: {logs}"
    );
}

fn sample_error_envelope() -> ReportEnvelope {
    use yadorilink_reporting::builder::{
        build_error_envelope, ErrorPayloadBuilder, ReportEnvironment,
    };
    use yadorilink_reporting::schema::OsFamily;
    let env = ReportEnvironment {
        generated_at: "2026-01-01T00:00:00Z".into(),
        yadorilink_version: "0.1.0".into(),
        os_family: OsFamily::Linux,
        os_version_bucket: "24.04".into(),
        arch: "x86_64".into(),
        install_channel: None,
        anonymous_reporter_id: None,
    };
    build_error_envelope(env, ErrorPayloadBuilder::new("daemon_startup", "control_socket")).0
}
