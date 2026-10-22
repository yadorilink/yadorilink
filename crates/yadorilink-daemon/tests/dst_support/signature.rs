//! Stable failure signatures.
//!
//! A signature is `(ViolationKind, normalized path pattern, first-observable
//! location)` rendered as a short string, such that the *same logical failure*
//! signs identically across seeds — so a corpus lookup converts "agent
//! re-derives last week's conclusion" into "agent reads one line" (the design).
//!
//! The location component is the terminal oracle kind (from the first-divergence
//! observer), not the simulated time or event index — those are seed-dependent
//! and would break cross-seed stability. Path normalization replaces the
//! seed-dependent segments (numeric device/file indices, random hex names,
//! conflict-copy decorations) with placeholders.

#![allow(dead_code)]

use super::divergence::FirstDivergence;

/// Compute a failure signature from the violation kind label, the (optional)
/// affected path, and the (optional) first-divergence point.
///
/// Shape: `"<kind>|<normalized-path>@<location>"`. A missing path normalizes to
/// `-`; a missing divergence localizes to `none`.
pub fn compute_signature(
    kind_label: &str,
    path: Option<&str>,
    first: Option<&FirstDivergence>,
) -> String {
    let norm_path = path.map(normalize_path).unwrap_or_else(|| "-".to_string());
    let location = first.map(|f| f.oracle_kind.as_str()).unwrap_or("none");
    format!("{kind_label}|{norm_path}@{location}")
}

/// Replace seed-dependent segments of a path with placeholders so the same
/// logical path signs identically across seeds:
/// - maximal ASCII-digit runs → `N` (device/file indices, round counters);
/// - long lowercase-hex runs (≥ 8 chars) → `X` (random/UUID-ish names);
/// - a `(conflicted copy …)` decoration → `(conflicted copy)` (the device/time
///  inside it is seed-dependent).
pub fn normalize_path(path: &str) -> String {
    let path = collapse_conflict_copy(path);
    let mut out = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();
    while let Some(&c) = chars.peek() {
        if is_hex_lower(c) {
            // Take the maximal run of hex chars (digits count as hex, so a
            // random token that happens to start with a digit is not split).
            let mut run = String::new();
            while chars.peek().is_some_and(|&c| is_hex_lower(c)) {
                run.push(chars.next().unwrap());
            }
            if run.len() >= 8 {
                // A long hex run is a random/UUID-ish token → single placeholder.
                out.push('X');
            } else {
                // A short run is ordinary text (`bin`, `deed`, `02`): keep the
                // letters, collapse only its digit sub-runs to `N`.
                push_with_digit_runs_collapsed(&mut out, &run);
            }
        } else {
            out.push(c);
            chars.next();
        }
    }
    out
}

fn is_hex_lower(c: char) -> bool {
    c.is_ascii_digit() || ('a'..='f').contains(&c)
}

/// Append `s`, replacing each maximal ASCII-digit sub-run with a single `N`.
fn push_with_digit_runs_collapsed(out: &mut String, s: &str) {
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                chars.next();
            }
            out.push('N');
        } else {
            out.push(c);
            chars.next();
        }
    }
}

/// Collapse a `(conflicted copy <device> <timestamp>)` decoration — the naming
/// convention `conflict.rs` uses — down to a stable `(conflicted copy)` so the
/// seed-dependent device/time inside does not perturb the signature.
fn collapse_conflict_copy(path: &str) -> String {
    match (path.find("(conflicted copy"), path.rfind(')')) {
        (Some(start), Some(end)) if end > start => {
            let mut s = String::with_capacity(path.len());
            s.push_str(&path[..start]);
            s.push_str("(conflicted copy)");
            s.push_str(&path[end + 1..]);
            s
        }
        _ => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fd(kind: &str) -> FirstDivergence {
        FirstDivergence { sim_time_nanos: 42, event_index: 7, oracle_kind: kind.into() }
    }

    #[test]
    fn signature_is_stable_across_seeds_with_differing_names() {
        // Same logical failure, two seeds: differing numeric file index and a
        // differing random hex device dir, but the same kind, path shape, and
        // divergence oracle.
        let a = compute_signature(
            "Convergence",
            Some("deadbeefcafe0001/dst-02.bin"),
            Some(&fd("Convergence")),
        );
        let b = compute_signature(
            "Convergence",
            Some("0badf00d12349999/dst-47.bin"),
            Some(&fd("Convergence")),
        );
        assert_eq!(a, b, "seed-varying names must normalize to the same signature");
        assert_eq!(a, "Convergence|X/dst-N.bin@Convergence");
    }

    #[test]
    fn different_kinds_sign_differently() {
        let a = compute_signature("Convergence", Some("a.txt"), Some(&fd("Convergence")));
        let b = compute_signature("Corruption", Some("a.txt"), Some(&fd("Corruption")));
        assert_ne!(a, b);
    }

    #[test]
    fn short_letter_runs_survive_only_digits_and_long_hex_are_placeheld() {
        assert_eq!(normalize_path("dir/report-2024-final.bin"), "dir/report-N-final.bin");
        // `bin`, `txt` are short and kept; the 16-char hex is collapsed.
        assert_eq!(normalize_path("aabbccddeeff0011/note.txt"), "X/note.txt");
    }

    #[test]
    fn conflict_copy_decoration_is_collapsed() {
        let sig = normalize_path("notes (conflicted copy device-7 2026-07-09).md");
        assert_eq!(sig, "notes (conflicted copy).md");
    }

    #[test]
    fn missing_path_and_divergence_degrade_gracefully() {
        assert_eq!(compute_signature("NoLoss", None, None), "NoLoss|-@none");
    }
}
