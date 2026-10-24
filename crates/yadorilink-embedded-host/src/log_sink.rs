//! The engine's log destination in an embedded host: a callback the host provides.
//!
//! The engine writes `tracing` events and nothing else: it opens no log file, so nothing is
//! written outside the host's own storage, and the desktop daemon's rolling file and stderr
//! logging are not compiled in. The host decides where events go by installing a sink here,
//! typically a function that forwards to `os_log`. Until it does, events are dropped.

use std::fmt::Write as _;
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt as _};
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::Layer;

/// How serious an event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Receives one event: its level, its target (the module that emitted it) and its message with
/// the event's fields appended as `key=value`. It may be called from any thread.
pub type LogSink = Arc<dyn Fn(LogLevel, &str, &str) + Send + Sync>;

/// Why a sink was not installed.
#[derive(Debug, thiserror::Error)]
pub enum LogSinkError {
    /// This process already has a global `tracing` subscriber; only one can exist.
    #[error("a log subscriber is already installed in this process")]
    AlreadyInstalled,
}

struct SinkLayer {
    sink: LogSink,
    min: LogLevel,
}

fn level_of(level: &Level) -> LogLevel {
    match *level {
        Level::TRACE => LogLevel::Trace,
        Level::DEBUG => LogLevel::Debug,
        Level::INFO => LogLevel::Info,
        Level::WARN => LogLevel::Warn,
        Level::ERROR => LogLevel::Error,
    }
}

#[derive(Default)]
struct Text {
    message: String,
    fields: String,
}

impl Text {
    /// The message, then the fields, whatever order the event recorded them in.
    fn render(self) -> String {
        match (self.message.is_empty(), self.fields.is_empty()) {
            (_, true) => self.message,
            (true, false) => self.fields,
            (false, false) => format!("{} {}", self.message, self.fields),
        }
    }
}

impl Visit for Text {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            let _ = write!(self.fields, "{}={value:?}", field.name());
        }
    }
}

impl<S: Subscriber> Layer<S> for SinkLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = level_of(event.metadata().level());
        if level < self.min {
            return;
        }
        let mut text = Text::default();
        event.record(&mut text);
        (self.sink)(level, event.metadata().target(), &text.render());
    }
}

/// Routes the engine's log events at `min` and above to `sink`, for the rest of the process.
///
/// # Errors
/// [`LogSinkError::AlreadyInstalled`] when the process already has a global subscriber.
pub fn install_log_sink(sink: LogSink, min: LogLevel) -> Result<(), LogSinkError> {
    tracing_subscriber::registry()
        .with(SinkLayer { sink, min })
        .try_init()
        .map_err(|_| LogSinkError::AlreadyInstalled)
}
