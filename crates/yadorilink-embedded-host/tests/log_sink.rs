//! The host's log sink receives the engine's events and nothing is written to a file. This
//! binary installs the process's one global subscriber, so it holds a single test.

use std::sync::{Arc, Mutex};

use yadorilink_embedded_host::{install_log_sink, LogLevel, LogSinkError};

#[test]
fn events_at_or_above_the_minimum_reach_the_sink_and_a_second_install_is_refused() {
    let seen: Arc<Mutex<Vec<(LogLevel, String, String)>>> = Arc::default();
    let into = Arc::clone(&seen);
    install_log_sink(
        Arc::new(move |level, target, message| {
            into.lock().unwrap().push((level, target.to_owned(), message.to_owned()));
        }),
        LogLevel::Info,
    )
    .unwrap();

    tracing::debug!("below the minimum");
    tracing::warn!(folder = 7, "linked a folder");

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, LogLevel::Warn);
    assert_eq!(seen[0].2, "linked a folder folder=7");

    let second = install_log_sink(Arc::new(|_, _, _| {}), LogLevel::Trace);
    assert!(matches!(second, Err(LogSinkError::AlreadyInstalled)));
}
