//! Human-readable text in the user's language.
//!
//! English is the source text: a message is looked up by its English wording, and a message with
//! no entry for the language in use is shown in English. Only text meant for a person goes
//! through [`tr`]; machine-readable output (`--json`, exit codes, log lines, command names a
//! script or a person types) is never translated.
//!
//! The language comes from the environment (`LC_ALL`, then `LC_MESSAGES`, then `LANG`); `ja`
//! selects Japanese, anything else English.

use std::borrow::Cow;

mod ja;
#[cfg(test)]
pub(crate) mod tests;

/// A language the command line can speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    English,
    Japanese,
}

impl Language {
    /// The language a locale name such as `ja_JP.UTF-8` or `en_US.UTF-8` selects.
    pub(crate) fn from_locale(locale: &str) -> Self {
        let name = locale.split(['_', '.', '@']).next().unwrap_or("");
        if name.eq_ignore_ascii_case("ja") {
            Language::Japanese
        } else {
            Language::English
        }
    }

    /// The language the environment asks for: the first of `LC_ALL`, `LC_MESSAGES` and `LANG`
    /// that `get` returns and is not empty.
    fn from_variables(get: impl Fn(&str) -> Option<String>) -> Self {
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|name| get(name))
            .find(|value| !value.is_empty())
            .map_or(Language::English, |value| Language::from_locale(&value))
    }
}

// Unit tests run in English whatever the developer's environment says; a test that wants
// Japanese asks for it with `tests::in_japanese`.
#[cfg(test)]
thread_local! {
    static TEST_LANGUAGE: std::cell::Cell<Language> = const { std::cell::Cell::new(Language::English) };
}

fn current() -> Language {
    #[cfg(test)]
    return TEST_LANGUAGE.with(|language| language.get());
    #[cfg(not(test))]
    Language::from_variables(|name| std::env::var(name).ok())
}

/// `english` in `language`, or `english` itself when there is no translation.
pub(crate) fn translate(language: Language, english: &'static str) -> Cow<'static, str> {
    match language {
        Language::English => Cow::Borrowed(english),
        Language::Japanese => Cow::Borrowed(ja::lookup(english).unwrap_or(english)),
    }
}

/// `english` in the language of the environment.
pub(crate) fn tr(english: &'static str) -> Cow<'static, str> {
    translate(current(), english)
}

/// `template` with each `{name}` replaced by the value of that name.
pub(crate) fn fill(
    template: Cow<'static, str>,
    values: &[(&str, &dyn std::fmt::Display)],
) -> String {
    let mut text = template.into_owned();
    for (name, value) in values {
        text = text.replace(&format!("{{{name}}}"), &value.to_string());
    }
    text
}

/// `trf!("English with {name}", name = value, ...)`: the message in the language of the
/// environment with its `{name}` placeholders filled in. The Japanese text uses the same names.
macro_rules! trf {
    ($english:literal $(, $name:ident = $value:expr)* $(,)?) => {
        $crate::i18n::fill($crate::i18n::tr($english), &[$((stringify!($name), &$value as &dyn std::fmt::Display)),*])
    };
}
pub(crate) use trf;
