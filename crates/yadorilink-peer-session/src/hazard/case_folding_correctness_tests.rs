#![cfg(test)]

use super::{canonical_fold, case_fold_collision};
use yadorilink_replica_domain::file::FileRecord;

fn record(path: &str) -> FileRecord {
    FileRecord { path: path.into(), size: 0, mtime_unix_nanos: 0, blocks: vec![], deleted: false }
}

/// The concrete distinguishing pair: `str::to_lowercase`
/// applies Greek final-sigma special-casing (a *display* rule), so
/// lowercasing the all-caps form produces a DIFFERENT string than a
/// name that already contains a literal (non-final-position) sigma --
/// even though a real case-insensitive filesystem's own case-folding
/// collapses both to the same physical name. `case_fold_collision`
/// must use actual Unicode case folding, which ignores that
/// positional context and always folds every sigma to one target.
#[test]
fn folds_greek_final_and_non_final_sigma_to_the_same_target() {
    // No extension, deliberately: `str::to_lowercase`'s final-sigma
    // special-casing is context-sensitive to what FOLLOWS the sigma
    // in the whole string, not just its own path component -- a
    // trailing extension like `.txt` can itself suppress the
    // final-sigma rule for the sigma before it (verified directly:
    // `"ΟΔΟΣ.txt".to_lowercase()` == `"οδοσ.txt"`, already the
    // non-final spelling, same as this test's `incoming`, which
    // would make this test pass "by accident" under the very bug it
    // exists to catch). A bare name with nothing after the sigma is
    // the case unambiguously affected either way.
    let siblings = vec![record("\u{39F}\u{394}\u{39F}\u{3A3}")]; // "ΟΔΟΣ"
                                                                 // A name ending in the non-final sigma "σ" (U+03C3), not the
                                                                 // final-form "ς" (U+03C3 vs U+03C2) `to_lowercase` would produce.
    let incoming = "\u{3BF}\u{3B4}\u{3BF}\u{3C3}"; // "οδοσ"
    assert!(
        case_fold_collision(incoming, &siblings).is_some(),
        "a real case-insensitive filesystem folds these to the same physical name"
    );
}

/// A second concrete divergence: the MICRO SIGN (U+00B5) case-folds to
/// GREEK SMALL LETTER MU (U+03BC) under Unicode's `CaseFolding.txt`,
/// but `str::to_lowercase` leaves the micro sign untouched (it has no
/// lowercase mapping of its own -- it already looks lowercase).
#[test]
fn folds_micro_sign_to_greek_mu() {
    let siblings = vec![record("\u{B5}g.txt")]; // "µg.txt" (MICRO SIGN)
    let incoming = "\u{3BC}g.txt"; // "μg.txt" (GREEK SMALL LETTER MU)
    assert!(
        case_fold_collision(incoming, &siblings).is_some(),
        "MICRO SIGN and GREEK SMALL LETTER MU case-fold to the same target"
    );
}

/// `canonical_fold` (the combined NFC + case-fold `path_lock`'s own
/// fold key uses) must apply the same real case-folding, not
/// `to_lowercase`, for the same reason -- two paths differing only by
/// this exact sigma pair must lock together, or a concurrent
/// materialize of "both" could interleave physically unserialized.
#[test]
fn canonical_fold_also_folds_final_and_non_final_sigma_together() {
    assert_eq!(
        canonical_fold("\u{39F}\u{394}\u{39F}\u{3A3}"),
        canonical_fold("\u{3BF}\u{3B4}\u{3BF}\u{3C3}"),
        "canonical_fold must fold ΟΔΟΣ and οδοσ to the identical key"
    );
}
