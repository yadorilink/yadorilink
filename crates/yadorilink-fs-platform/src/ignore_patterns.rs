//! Per-folder ignore rules: parsing and matching.
//!
//! This module is intentionally self-contained: it parses a small
//! gitignore-style pattern subset and answers whether a root-relative path
//! is ignored.
//!
//! The rules of a folder are one text, owned by the daemon (one file per folder group in its
//! configuration directory) and replaced only through the daemon's API. A line the parser cannot
//! use is an error naming the line, never silently dropped.
//!
//! A `(?i)` marker makes a line case-insensitive, and `explain_path` reports the winning rule's
//! line number and case-sensitivity mode — the same evaluator
//! `EffectiveIgnoreSet::match_path`/`is_ignored` already use, so explanations can never disagree
//! with actual match behavior.

use std::fs;
use std::io;
use std::path::{Component, Path};

pub const BUILT_IN_DEFAULT_PATTERNS: &[&str] =
    &[".DS_Store", "._*", "Thumbs.db", "desktop.ini", "*.swp", "*~", ".Spotlight-V100", ".Trashes"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnorePatternSource {
    BuiltIn,
    User,
}

/// Why a folder's ignore rules could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoreConfigError {
    /// A line the rules cannot honour: 1-based line number, the line, and why.
    InvalidLine { line: u32, text: String, reason: &'static str },
    /// The rules file could not be read.
    Io(String),
}

impl std::fmt::Display for IgnoreConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IgnoreConfigError::InvalidLine { line, text, reason } => {
                write!(f, "line {line}: {reason}: `{}`", text.trim())
            }
            IgnoreConfigError::Io(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for IgnoreConfigError {}

impl From<IgnoreConfigError> for io::Error {
    fn from(err: IgnoreConfigError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, err.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternSegment {
    DoubleStar,
    Glob(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnorePattern {
    original: String,
    source: IgnorePatternSource,
    /// 1-based line number of this pattern in the rules text (the position in the built-in list
    /// for a built-in default).
    line: u32,
    negated: bool,
    directory_only: bool,
    anchored: bool,
    case_insensitive: bool,
    segments: Vec<PatternSegment>,
}

impl IgnorePattern {
    pub fn original(&self) -> &str {
        &self.original
    }

    pub fn source(&self) -> IgnorePatternSource {
        self.source
    }

    pub fn line(&self) -> u32 {
        self.line
    }

    pub fn is_negated(&self) -> bool {
        self.negated
    }

    pub fn is_directory_only(&self) -> bool {
        self.directory_only
    }

    pub fn is_case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    /// `Ok(None)` for a blank line or a comment, `Err(reason)` for a line that is neither a
    /// pattern nor ignorable.
    fn parse(
        line: &str,
        source: IgnorePatternSource,
        line_number: u32,
    ) -> Result<Option<Self>, &'static str> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(None);
        }

        // A leading `(?i)` marker (Syncthing's own convention) makes this single line
        // case-insensitive, independent of every other line.
        let (case_insensitive, trimmed) =
            trimmed.strip_prefix("(?i)").map_or((false, trimmed), |rest| (true, rest.trim_start()));
        if trimmed.is_empty() {
            return Err("no pattern after (?i)");
        }

        let (negated, body) =
            trimmed.strip_prefix('!').map_or((false, trimmed), |rest| (true, rest.trim_start()));
        let body = body.trim_end();
        if body.is_empty() {
            return Err("no pattern after !");
        }

        let (directory_only, body) =
            body.strip_suffix('/').map_or((false, body), |without_slash| (true, without_slash));
        let body = body.trim_matches('/');
        if body.is_empty() || body == "." {
            return Err("no pattern");
        }
        if body.contains("//") {
            return Err("empty path segment");
        }

        let anchored = body.contains('/');
        let mut segments = Vec::new();
        for segment in body.split('/') {
            if segment == "." || segment == ".." {
                return Err("`.` and `..` are not allowed");
            }
            segments.push(if segment == "**" {
                PatternSegment::DoubleStar
            } else {
                let text =
                    if case_insensitive { segment.to_lowercase() } else { segment.to_string() };
                PatternSegment::Glob(text)
            });
        }

        Ok(Some(IgnorePattern {
            original: trimmed.to_string(),
            source,
            line: line_number,
            negated,
            directory_only,
            anchored,
            case_insensitive,
            segments,
        }))
    }

    fn matches(&self, path_segments: &[String], is_dir: bool) -> bool {
        if path_segments.is_empty() {
            return false;
        }
        if self.case_insensitive {
            let lowered: Vec<String> = path_segments.iter().map(|s| s.to_lowercase()).collect();
            return self.matches_case_normalized(&lowered, is_dir);
        }
        self.matches_case_normalized(path_segments, is_dir)
    }

    fn matches_case_normalized(&self, path_segments: &[String], is_dir: bool) -> bool {
        if self.anchored {
            self.matches_anchored(path_segments, is_dir)
        } else {
            self.matches_unanchored(path_segments, is_dir)
        }
    }

    fn matches_unanchored(&self, path_segments: &[String], is_dir: bool) -> bool {
        let [PatternSegment::Glob(pattern)] = self.segments.as_slice() else {
            return self.matches_anchored(path_segments, is_dir);
        };

        path_segments.iter().enumerate().any(|(index, segment)| {
            segment_matches(pattern, segment)
                && (!self.directory_only || index + 1 < path_segments.len() || is_dir)
        })
    }

    fn matches_anchored(&self, path_segments: &[String], is_dir: bool) -> bool {
        for prefix_len in 1..=path_segments.len() {
            let prefix = &path_segments[..prefix_len];
            if match_segments(&self.segments, prefix)
                && (!self.directory_only || prefix_len < path_segments.len() || is_dir)
            {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreMatch<'a> {
    pub pattern: &'a IgnorePattern,
    pub ignored: bool,
}

/// The full explanation for why a path matched (or didn't
/// match) an `EffectiveIgnoreSet` — built from the exact same winning
/// `IgnorePattern` `match_path`/`is_ignored` use, so a human-facing
/// explanation can never disagree with actual ignore behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreExplanation {
    /// Whether the path is ignored (`false` both when nothing matched and
    /// when the winning rule is a negation).
    pub ignored: bool,
    /// Whether any rule matched at all.
    pub matched: bool,
    pub rule_text: String,
    pub source: IgnorePatternSource,
    pub line: u32,
    pub case_insensitive: bool,
}

impl IgnoreExplanation {
    fn not_matched() -> Self {
        IgnoreExplanation {
            ignored: false,
            matched: false,
            rule_text: String::new(),
            source: IgnorePatternSource::User,
            line: 0,
            case_insensitive: false,
        }
    }

    fn from_match(m: &IgnoreMatch<'_>) -> Self {
        IgnoreExplanation {
            ignored: m.ignored,
            matched: true,
            rule_text: m.pattern.original().to_string(),
            source: m.pattern.source(),
            line: m.pattern.line(),
            case_insensitive: m.pattern.is_case_insensitive(),
        }
    }
}

/// Where the daemon keeps each folder group's ignore rules: one text file per group in
/// `<config dir>/ignore`. The only writer is [`Self::write`], which refuses text the parser
/// rejects, so a stored file always parses.
#[derive(Debug, Clone)]
pub struct IgnoreRulesStore {
    dir: std::path::PathBuf,
}

impl IgnoreRulesStore {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        Self { dir: config_dir.as_ref().join("ignore") }
    }

    /// The file holding `group_id`'s rules. The name is the group id in hex, so no id can name
    /// another directory.
    pub fn path(&self, group_id: &str) -> std::path::PathBuf {
        let name: String = group_id.bytes().map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{name}.yadorilinkignore"))
    }

    /// The group's rules plus the built-in defaults; no file is no rules.
    ///
    /// # Errors
    /// The file could not be read or has an unusable line.
    pub fn load(&self, group_id: &str) -> Result<EffectiveIgnoreSet, IgnoreConfigError> {
        EffectiveIgnoreSet::load_file(self.path(group_id))
    }

    /// The group's rules text; empty when it has none.
    ///
    /// # Errors
    /// The file exists and could not be read as text.
    pub fn read(&self, group_id: &str) -> io::Result<String> {
        match fs::read_to_string(self.path(group_id)) {
            Ok(text) => Ok(text),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(err) => Err(err),
        }
    }

    /// Replaces the group's rules with `text`, durably (a staged file published over the old
    /// one): a reader sees the old rules or the new, and a crash never leaves a half-written
    /// file. Nothing is written when `text` has an unusable line.
    ///
    /// # Errors
    /// [`IgnoreConfigError::InvalidLine`] naming the first unusable line, or the I/O error.
    pub fn write(&self, group_id: &str, text: &str) -> Result<(), IgnoreConfigError> {
        EffectiveIgnoreSet::from_text(text)?;
        // One writer at a time: the staged file has a fixed name beside its target.
        static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _writing = WRITING.lock().unwrap_or_else(|p| p.into_inner());
        let io_error = |err: io::Error| IgnoreConfigError::Io(err.to_string());
        crate::durable_dir::create_dir_all_durably(&self.dir).map_err(io_error)?;
        let target = self.path(group_id);
        let staged = target.with_extension("staged");
        {
            use std::io::Write;
            let mut file = fs::File::create(&staged).map_err(io_error)?;
            file.write_all(text.as_bytes()).map_err(io_error)?;
            crate::flush::sync_file(&file).map_err(io_error)?;
        }
        crate::durable_dir::publish_durably(&staged, &target, crate::durable_dir::Replace::Yes)
            .map_err(io_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveIgnoreSet {
    patterns: Vec<IgnorePattern>,
}

impl EffectiveIgnoreSet {
    pub fn defaults_only() -> Self {
        let patterns = BUILT_IN_DEFAULT_PATTERNS
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| {
                IgnorePattern::parse(pattern, IgnorePatternSource::BuiltIn, (index + 1) as u32)
                    .ok()
                    .flatten()
            })
            .collect();
        EffectiveIgnoreSet { patterns }
    }

    /// The built-in defaults plus the rules in `text`, one pattern per line.
    ///
    /// # Errors
    /// A line that is neither blank, a comment nor a usable pattern: the error names the line.
    pub fn from_text(text: &str) -> Result<Self, IgnoreConfigError> {
        let mut set = Self::defaults_only();
        for (index, line) in text.lines().enumerate() {
            let number = (index + 1) as u32;
            match IgnorePattern::parse(line, IgnorePatternSource::User, number) {
                Ok(Some(pattern)) => set.patterns.push(pattern),
                Ok(None) => {}
                Err(reason) => {
                    return Err(IgnoreConfigError::InvalidLine {
                        line: number,
                        text: line.to_string(),
                        reason,
                    })
                }
            }
        }
        Ok(set)
    }

    /// The rules stored in `path`; a missing file is no rules (the built-in defaults).
    ///
    /// # Errors
    /// The file could not be read, is not UTF-8, or has an unusable line.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, IgnoreConfigError> {
        let path = path.as_ref();
        match fs::read(path) {
            Ok(bytes) => {
                let text = String::from_utf8(bytes).map_err(|_| {
                    IgnoreConfigError::Io(format!("{}: not valid UTF-8", path.display()))
                })?;
                Self::from_text(&text)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self::defaults_only()),
            Err(err) => Err(IgnoreConfigError::Io(format!("{}: {err}", path.display()))),
        }
    }

    /// Reloads `path`, but on any error keeps `previous` instead of leaving the caller with no
    /// usable ignore set at all. Returns the error alongside the (possibly unchanged) set so the
    /// daemon can surface it.
    pub fn reload_file(
        path: impl AsRef<Path>,
        previous: &Self,
    ) -> (Self, Option<IgnoreConfigError>) {
        match Self::load_file(path) {
            Ok(set) => (set, None),
            Err(err) => (previous.clone(), Some(err)),
        }
    }

    pub fn patterns(&self) -> &[IgnorePattern] {
        &self.patterns
    }

    pub fn is_ignored(&self, relative_path: impl AsRef<Path>, is_dir: bool) -> bool {
        self.match_path(relative_path, is_dir).is_some_and(|m| m.ignored)
    }

    pub fn match_path(
        &self,
        relative_path: impl AsRef<Path>,
        is_dir: bool,
    ) -> Option<IgnoreMatch<'_>> {
        let path_segments = normalize_relative_segments(relative_path.as_ref())?;
        let mut result = None;
        for pattern in &self.patterns {
            if pattern.matches(&path_segments, is_dir) {
                result = Some(IgnoreMatch { pattern, ignored: !pattern.negated });
            }
        }
        result
    }

    /// explains why `relative_path` is (or isn't) ignored, using
    /// the exact same evaluator `match_path`/`is_ignored` use — the winning
    /// rule's text, source file, include chain, line number, and
    /// case-sensitivity mode. `None` only when `relative_path` itself can't
    /// be normalized to a link-relative path (absolute, or escaping the
    /// root via `..`); a normalizable path with no matching rule at all
    /// still returns `Some` with `matched: false`.
    pub fn explain_path(
        &self,
        relative_path: impl AsRef<Path>,
        is_dir: bool,
    ) -> Option<IgnoreExplanation> {
        let path_segments = normalize_relative_segments(relative_path.as_ref())?;
        let mut result = IgnoreExplanation::not_matched();
        for pattern in &self.patterns {
            if pattern.matches(&path_segments, is_dir) {
                result = IgnoreExplanation::from_match(&IgnoreMatch {
                    pattern,
                    ignored: !pattern.negated,
                });
            }
        }
        Some(result)
    }
}

fn normalize_relative_segments(path: &Path) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => segments.push(segment.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(segments)
}

fn match_segments(pattern: &[PatternSegment], text: &[String]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }

    match &pattern[0] {
        PatternSegment::DoubleStar => {
            if pattern.len() == 1 {
                return true;
            }
            match_segments(&pattern[1..], text)
                || (!text.is_empty() && match_segments(pattern, &text[1..]))
        }
        PatternSegment::Glob(glob) => {
            !text.is_empty()
                && segment_matches(glob, &text[0])
                && match_segments(&pattern[1..], &text[1..])
        }
    }
}

fn segment_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut pi, mut ti) = (0, 0);
    let mut star = None;
    let mut star_text = 0;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            star_text = ti;
        } else if let Some(star_index) = star {
            pi = star_index + 1;
            star_text += 1;
            ti = star_text;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[cfg(test)]
mod tests;
