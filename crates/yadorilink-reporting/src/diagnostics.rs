//! Diagnostics-bundle redaction helpers.
//!
//! This module is intentionally pure and daemon-independent: callers hand it a
//! JSON value or free-text field, and it applies the same conservative
//! denylist pass used for optional reporting before any support bundle is
//! previewed or written.

use serde_json::Value;

use crate::redact::{redact, RedactionCategory, RedactionSummary};

pub fn redact_diagnostics_text(text: &str) -> (String, RedactionSummary) {
    redact(text)
}

pub fn redact_diagnostics_value(value: &Value) -> (Value, RedactionSummary) {
    let mut summary = RedactionSummary::default();
    let redacted = redact_value(value, &mut summary);
    (redacted, summary)
}

fn redact_value(value: &Value, summary: &mut RedactionSummary) -> Value {
    match value {
        Value::String(text) => {
            let (redacted, text_summary) = redact_diagnostics_text(text);
            merge_summary(summary, text_summary);
            Value::String(redacted)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| redact_value(item, summary)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter().map(|(key, value)| (key.clone(), redact_value(value, summary))).collect(),
        ),
        other => other.clone(),
    }
}

fn merge_summary(into: &mut RedactionSummary, incoming: RedactionSummary) {
    for (category, count) in incoming.categories {
        match into.categories.iter_mut().find(|(existing, _)| *existing == category) {
            Some((_, existing_count)) => *existing_count += count,
            None => into.categories.push((category, count)),
        }
    }
}

pub fn diagnostics_summary_count(summary: &RedactionSummary, category: RedactionCategory) -> usize {
    summary
        .categories
        .iter()
        .find_map(|(existing, count)| (*existing == category).then_some(*count))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
