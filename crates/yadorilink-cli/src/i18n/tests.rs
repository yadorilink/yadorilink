use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::*;
use crate::i18n::trf;

/// Runs `body` with Japanese as the language of this thread.
pub(crate) fn in_japanese<T>(body: impl FnOnce() -> T) -> T {
    let before = TEST_LANGUAGE.with(|language| language.replace(Language::Japanese));
    let result = body();
    TEST_LANGUAGE.with(|language| language.set(before));
    result
}

#[test]
fn a_locale_name_selects_its_language() {
    for (locale, language) in [
        ("ja_JP.UTF-8", Language::Japanese),
        ("ja", Language::Japanese),
        ("JA_JP", Language::Japanese),
        ("en_US.UTF-8", Language::English),
        ("C", Language::English),
        ("POSIX", Language::English),
        ("", Language::English),
        ("jam_XX", Language::English),
    ] {
        assert_eq!(Language::from_locale(locale), language, "{locale}");
    }
}

#[test]
fn the_first_variable_that_is_set_decides() {
    let vars = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| (*v).to_owned())
    };
    let from = |pairs| Language::from_variables(vars(pairs));
    assert_eq!(from(&[("LANG", "ja_JP.UTF-8")]), Language::Japanese);
    assert_eq!(from(&[("LC_ALL", "en_US.UTF-8"), ("LANG", "ja_JP.UTF-8")]), Language::English);
    assert_eq!(from(&[("LC_ALL", ""), ("LANG", "ja_JP.UTF-8")]), Language::Japanese);
    assert_eq!(from(&[("LC_MESSAGES", "ja"), ("LANG", "C")]), Language::Japanese);
    assert_eq!(from(&[]), Language::English);
}

#[test]
fn english_is_the_source_text_and_the_fallback() {
    assert_eq!(translate(Language::English, "Next:"), "Next:");
    assert_eq!(translate(Language::Japanese, "Next:"), "対処:");
    // Text with no Japanese entry is shown as written.
    assert_eq!(translate(Language::Japanese, "no such message"), "no such message");
    assert_eq!(tr("Next:"), "Next:");
    in_japanese(|| assert_eq!(tr("Next:"), "対処:"));
}

fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            source_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The value of the Rust string literal that starts right after its opening quote in `rest`.
fn literal_value(rest: &str) -> String {
    let mut message = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next().unwrap() {
                'n' => message.push('\n'),
                't' => message.push('\t'),
                // A backslash at the end of a line drops the line break and the indentation.
                '\n' => {
                    while chars.peek().is_some_and(|c| c.is_whitespace()) {
                        chars.next();
                    }
                }
                other => message.push(other),
            },
            c => message.push(c),
        }
    }
    message
}

/// The messages the code asks for: the string literal in every `tr("...")` and `trf!("...")`.
fn messages_in_source() -> BTreeSet<String> {
    let mut files = Vec::new();
    source_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    let mut found = BTreeSet::new();
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        // This module's own tests and the catalog hold messages as data, not as requests.
        if name == "tests.rs" && file.parent().unwrap().ends_with("i18n")
            || name == "ja.rs"
            || name == "i18n.rs"
        {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap();
        for opener in ["tr(", "trf!("] {
            let mut rest = text.as_str();
            while let Some(at) = rest.find(opener) {
                let preceded_by_word =
                    rest[..at].chars().last().is_some_and(|c| c.is_alphanumeric() || c == '_');
                rest = &rest[at + opener.len()..];
                let after = rest.trim_start();
                if !preceded_by_word && after.starts_with('"') {
                    found.insert(literal_value(&after[1..]));
                }
            }
        }
    }
    found
}

fn placeholders(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}') else { break };
        names.insert(rest[open + 1..open + close].to_owned());
        rest = &rest[open + close..];
    }
    names
}

#[test]
fn a_translation_fills_the_same_placeholders_as_its_english() {
    for (english, japanese) in ja::table() {
        assert_eq!(placeholders(english), placeholders(japanese), "{english}");
    }
}

#[test]
fn every_message_in_the_source_has_a_japanese_text_and_no_entry_is_unused() {
    let asked = messages_in_source();
    let have: BTreeSet<String> = ja::table().iter().map(|(key, _)| (*key).to_owned()).collect();
    let missing: Vec<_> = asked.difference(&have).collect();
    let unused: Vec<_> = have.difference(&asked).collect();
    assert!(missing.is_empty(), "messages with no Japanese text: {missing:#?}");
    assert!(unused.is_empty(), "Japanese entries no code asks for: {unused:#?}");
}

#[test]
fn the_catalog_has_no_duplicate_or_empty_entries() {
    let mut seen = BTreeSet::new();
    for (key, text) in ja::table() {
        assert!(seen.insert(*key), "duplicate entry: {key}");
        assert!(!text.trim().is_empty(), "empty Japanese text for: {key}");
    }
}

#[test]
fn commands_and_placeholders_survive_translation() {
    // A command a person types, or a placeholder the code fills, must be in the Japanese text
    // exactly as in English.
    for (key, text) in ja::table() {
        for word in key.split(|c: char| c.is_whitespace() || "(),".contains(c)) {
            let is_literal = word.starts_with("yadorilink")
                || word.starts_with('<') && word.ends_with('>')
                || word.starts_with("--") && word.len() > 2
                || word == "chmod";
            if is_literal && !word.contains("yadorilink.") {
                assert!(text.contains(word.trim_end_matches([':', '.'])), "{key}: lost {word}");
            }
        }
    }
}

/// Writes the copy review sheet (every English text with its Japanese text) when
/// `YADORILINK_WRITE_JA_REVIEW` names the file to write; otherwise does nothing.
#[test]
fn write_the_japanese_copy_review_sheet_on_request() {
    let Some(path) = std::env::var_os("YADORILINK_WRITE_JA_REVIEW") else { return };
    let mut sheet =
        String::from("# CLI: Japanese copy for review\n\n| English | Japanese |\n|---|---|\n");
    for (english, japanese) in ja::table() {
        let cell = |text: &str| text.replace('|', "\\|");
        sheet.push_str(&format!("| {} | {} |\n", cell(english), cell(japanese)));
    }
    std::fs::write(path, sheet).unwrap();
}

#[test]
fn a_message_with_placeholders_is_filled_in_either_language() {
    let english = trf!("Unlinked {local_path}", local_path = "/data/photos");
    assert_eq!(english, "Unlinked /data/photos");
    let japanese = in_japanese(|| trf!("Unlinked {local_path}", local_path = "/data/photos"));
    assert_eq!(japanese, "/data/photos のリンクを解除しました");
    // The same name twice is filled twice.
    let twice = in_japanese(|| {
        trf!("The old device {old_id} is still listed on your account as signed out. Remove it with `yadorilink device remove {old_id} --force` once the new device has your folders.", old_id = "d1")
    });
    assert_eq!(twice.matches("d1").count(), 2, "{twice}");
}
