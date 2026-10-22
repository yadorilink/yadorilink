#![cfg(test)]

use super::*;

#[test]
fn included_summary_names_where_the_bundle_came_from() {
    assert_eq!(
        included_summary("daemon"),
        "daemon-assembled bundle: status, links, recent errors, updates, resources, environment"
    );
    assert_eq!(
        included_summary("daemon-partial"),
        "daemon-assembled bundle (partial: generation hit its bounded time budget)"
    );
    assert_eq!(
        included_summary("cli-only-fallback"),
        "schema/build/platform metadata, CLI daemon-unavailable fallback state"
    );
}
