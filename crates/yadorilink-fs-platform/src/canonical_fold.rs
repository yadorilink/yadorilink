//! The combined case-fold-and-Unicode-normalization equivalence key two
//! names collide under on a volume that is simultaneously case-insensitive
//! AND normalization-insensitive (the macOS default, both HFS+ and APFS).

/// Folds `path` to the case-insensitive comparison key two names collide
/// under on a case-insensitive volume (Unicode case folding, not the
/// lowercase mapping).
pub fn case_fold(path: &str) -> String {
    caseless::default_case_fold_str(path)
}

/// `path` in Unicode Normalization Form C: the key two names collide under on
/// a normalization-insensitive volume.
pub fn nfc(path: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    path.nfc().collect()
}

/// Folds `path` to the case-and-normalization-insensitive key two
/// differently-encoded names collapse to on such a volume: NFC-normalize,
/// then case-fold (`caseless::default_case_fold_str`, not
/// `str::to_lowercase` -- case folding, not the lowercase *mapping*, is
/// what matches how a case-insensitive filesystem actually collides two
/// names), then NFC-normalize again (case folding can itself introduce a
/// decomposed form).
pub fn canonical_fold(path: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let step1: String = path.nfc().collect();
    let folded = caseless::default_case_fold_str(&step1);
    folded.nfc().collect()
}
