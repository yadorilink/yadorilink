//! The named, stable, CI-repeatable index of the multi-node
//! topology/restart acceptance matrix. This file does not duplicate any
//! scenario's logic -- each scenario lives in its own real test
//! file. This is the
//! single place that names each one and says where it lives, plus a
//! freshness lint (matching `dst_runbook_freshness_lint.rs`'s established
//! idiom) that fails if this index and the actual test files drift apart.
//!
//! Scope: this matrix is specifically the multi-node topology/reconnect/
//! restart resilience surface (real
//! `peer_orchestrator`, real transport, real DAG sync, on the canonical
//! N/M/W topology or its `ReconnectCoordinator`-focused variants). It does
//! NOT re-enumerate the daemon crate's much larger pre-existing test
//! suite (conflict-resolution matrices, DST fault-injection scenarios,
//! control-socket/IPC surface, etc.) -- those are real, valuable, and
//! already independently discoverable via `cargo test -p yadorilink-daemon`;
//! duplicating their listing here would go stale immediately.
//!
//! The 11 scenarios this list originally also named for the peer-device
//! relay mechanism (direct-fails-to-relay-fallback, multi-peer relay
//! fan-in, the A->B->C relay wire path, three relay-role restart
//! scenarios, relay fan-in reconnect chaos, simultaneous-reconnect/relay-
//! hydration-failure) were removed together with that mechanism itself --
//! their own test files are gone, not merely renumbered out of this list.
//!
//! ## Deterministic release gate
//!
//! Every scenario below is deterministic (fixed small topology, no
//! seeded/randomized fault injection) and fast enough to run on every
//! change -- this is the full set `cargo test -p yadorilink-daemon` runs
//! by default (none of these are `#[ignore]`d).
//!
//! 1. Direct happy-path convergence + hydration --
//!    `topology_n_m_w.rs::happy_path_direct_convergence_and_hydration`
//! 2. Full-replica anchor (N) restart never shows a stale Protected status --
//!    `topology_restart_convergence.rs::n_restart_never_shows_a_stale_protected_status`
//! 3. M restart recovers and resyncs with both peers --
//!    `topology_restart_convergence.rs::m_restart_recovers_and_resyncs_with_both_peers`
//! 4. W restart recovers and resyncs with both peers --
//!    `topology_restart_convergence.rs::w_restart_recovers_and_resyncs_with_both_peers`
//! 5. N restart mid-transfer still converges exactly --
//!    `topology_restart_convergence.rs::n_restart_mid_transfer_still_converges_exactly`
//! 6. Safe demotion succeeds when a real peer durably holds everything --
//!    `topology_storage_mode_safety.rs::safe_demotion_succeeds_when_a_real_peer_durably_holds_everything`
//! 7. A version change during lease issuance refuses the demotion (TOCTOU
//!    guard) --
//!    `topology_storage_mode_safety.rs::version_change_during_lease_issuance_refuses_the_demotion`
//! 8. Published data survives a coordination-plane outage on the direct
//!    transport; edits authored during the outage stay durable Pending and
//!    auto-publish + converge once coordination recovers (narrowed from
//!    "coordination plane availability independence" -- new-Change
//!    publication is NOT available during an outage under checkpoint
//!    admission, since checkpoint issuance requires a live
//!    coordination-plane round trip) --
//!    `chaos_coordination_unreachable.rs::published_data_plane_survives_coordination_outage_and_pending_edits_converge_on_recovery`
//! 9. Peer reconnection survives simultaneous multi-peer flapping, mid-sync
//!    revocation, and a whole daemon generation restarting --
//!    `reconnect_coordinator_scenarios.rs::{ten_peers_flap_simultaneously, twenty_peers_lose_connection_simultaneously, reconnect_during_active_sync, reconnect_after_daemon_generation_restart}`
//!
//! ## Randomized / soak lane (separate)
//!
//! Not part of the deterministic gate above -- these are seeded,
//! randomized, or long-running by design and belong to a soak/nightly
//! lane, not every-change CI:
//! - `monkey_chaos.rs` (random multi-device concurrent-op convergence +
//!   `replay_known_failing_seeds` regression corpus)
//! - the `dst_*.rs` turmoil simulation scenarios (seeded Case workloads
//!   with partition/heal, watcher/debounce chaos, etc.)
//! - `row14_strict_acceptance.rs::row14_strict_acceptance` (6-device,
//!   10-round staggered edit/delete/rename convergence under a strict
//!   stall bound -- deterministic in outcome but heavy enough to belong
//!   with the soak lane rather than the fast gate)

use std::collections::BTreeSet;
use std::path::PathBuf;

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Every scenario pointer named in this file's own module doc comment
/// above (the numbered list of scenarios plus the reconnect-coordinator
/// group's five sub-scenarios), parsed straight out of the comment text
/// itself so the check is against what's actually WRITTEN here, not a
/// separately-maintained copy of the same list. A pointer is a
/// backtick-wrapped token of the shape test-file.rs::function-name, or
/// test-file.rs::{a, b, c} for a group of names in one file.
fn scenario_pointers_from_this_file() -> Vec<(String, String)> {
    let source = std::fs::read_to_string(tests_dir().join("m5a_acceptance_matrix.rs"))
        .expect("must be able to read its own source");
    let mut out = Vec::new();
    for line in source.lines() {
        // Skip this function's own doc comment lines -- they describe the
        // pointer shape using the shape itself as a literal example,
        // which would otherwise be mistaken for a real pointer.
        if line.contains("scenario pointer") || line.contains("backtick-wrapped") {
            continue;
        }
        let trimmed = line.trim_start_matches("//!").trim_start_matches("///").trim();
        let mut rest = trimmed;
        while let Some(start) = rest.find('`') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('`') else { break };
            let token = &after[..end];
            if let Some((file_part, fn_part)) = token.split_once(".rs::") {
                let file_name = format!("{file_part}.rs");
                if fn_part.starts_with('{') {
                    for name in fn_part.trim_matches(|c| c == '{' || c == '}').split(',') {
                        out.push((file_name.clone(), name.trim().to_string()));
                    }
                } else {
                    out.push((file_name, fn_part.to_string()));
                }
            }
            rest = &after[end + 1..];
        }
    }
    out
}

#[test]
fn every_named_scenario_file_exists() {
    let pointers = scenario_pointers_from_this_file();
    assert!(
        !pointers.is_empty(),
        "failed to parse any scenario pointers out of this file's own doc comment"
    );
    let dir = tests_dir();
    let missing: Vec<_> = pointers
        .iter()
        .map(|(file, _)| file)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|file| !dir.join(file).is_file())
        .collect();
    assert!(
        missing.is_empty(),
        "m5a_acceptance_matrix.rs names test files that no longer exist under tests/: {missing:?}"
    );
}

/// Whether a required scenario, as WRITTEN in `source`, actually gates
/// every change -- `Missing` if no such function exists at all, `Ignored`
/// if it exists but carries an `#[ignore]`/`#[ignore = "..."]` attribute
/// (present in the file, but never actually run by a plain `cargo test`),
/// `Active` only if it exists with no such attribute. Parses `source`'s
/// real syntax tree (`syn`) rather than a substring search: a plain
/// `source.contains("fn name(")` can see a function EXISTS but can never
/// see whether it's `#[ignore]`d, and can also be fooled by the same text
/// appearing inside a comment or a string literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScenarioStatus {
    Active,
    Ignored,
    Missing,
}

fn scenario_status(source: &str, function: &str) -> ScenarioStatus {
    let file = syn::parse_file(source).expect("test source file must be valid Rust syntax");
    for item in &file.items {
        let syn::Item::Fn(item_fn) = item else { continue };
        if item_fn.sig.ident != function {
            continue;
        }
        let ignored = item_fn.attrs.iter().any(|attr| attr.path().is_ident("ignore"));
        return if ignored { ScenarioStatus::Ignored } else { ScenarioStatus::Active };
    }
    ScenarioStatus::Missing
}

#[test]
fn every_named_scenario_function_exists_in_its_file() {
    let pointers = scenario_pointers_from_this_file();
    let dir = tests_dir();
    let mut missing = Vec::new();
    let mut ignored = Vec::new();
    for (file, function) in &pointers {
        let source = std::fs::read_to_string(dir.join(file))
            .unwrap_or_else(|e| panic!("cannot read tests/{file}: {e}"));
        match scenario_status(&source, function) {
            ScenarioStatus::Active => {}
            ScenarioStatus::Ignored => ignored.push(format!("{file}::{function}")),
            ScenarioStatus::Missing => missing.push(format!("{file}::{function}")),
        }
    }
    assert!(
        missing.is_empty(),
        "m5a_acceptance_matrix.rs names scenarios that no longer exist as written: {missing:?}"
    );
    assert!(
        ignored.is_empty(),
        "m5a_acceptance_matrix.rs names scenarios that are #[ignore]d, so they are NOT actually \
         part of the deterministic gate this file's own doc comment claims they are: {ignored:?}"
    );
}

#[test]
fn scenario_status_reports_missing_for_a_function_that_does_not_exist() {
    let source = "fn something_else() {}\n";
    assert_eq!(scenario_status(source, "required_scenario"), ScenarioStatus::Missing);
}

#[test]
fn scenario_status_reports_ignored_for_a_bare_ignore_attribute() {
    let source = "#[ignore]\n#[tokio::test]\nasync fn required_scenario() {}\n";
    assert_eq!(scenario_status(source, "required_scenario"), ScenarioStatus::Ignored);
}

#[test]
fn scenario_status_reports_ignored_for_an_ignore_attribute_with_a_reason() {
    let source = "#[ignore = \"flaky under CI load\"]\n#[test]\nfn required_scenario() {}\n";
    assert_eq!(scenario_status(source, "required_scenario"), ScenarioStatus::Ignored);
}

#[test]
fn scenario_status_reports_active_for_a_plain_test_function() {
    let source = "#[tokio::test]\nasync fn required_scenario() {}\n";
    assert_eq!(scenario_status(source, "required_scenario"), ScenarioStatus::Active);
}

/// The exact false-negative a plain substring search would miss: the
/// function name appears in a comment, but the real function is
/// `#[ignore]`d -- a substring check (`source.contains("fn name(")`) sees
/// the comment's `fn required_scenario(` text and reports "found", never
/// noticing the actual definition is ignored. The AST-based check must
/// not be fooled by this.
#[test]
fn scenario_status_is_not_fooled_by_a_comment_mentioning_the_function_signature() {
    let source = "// see also fn required_scenario(x: u32) for context\n\
                   #[ignore]\n#[test]\nfn required_scenario() {}\n";
    assert_eq!(scenario_status(source, "required_scenario"), ScenarioStatus::Ignored);
}
