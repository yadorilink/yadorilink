//! Per-link `.yadorilinkignore` parsing and matching.
//!
//! This module is intentionally self-contained: it parses a small
//! gitignore-style pattern subset and answers whether a root-relative path
//! is ignored.
//!
//! It also supports `#include` directives (cycle-checked and
//! root-confined), a `(?i)` case-insensitive marker, and an `explain_path`
//! evaluator that reports the winning rule's source file, include chain,
//! line number, and case-sensitivity mode — the same evaluator
//! `EffectiveIgnoreSet::match_path`/`is_ignored` already use, so
//! explanations can never disagree with actual match behavior.

use std::fs;
use std::io;
use std::path::{Component, Path};

use yadorilink_replica_domain::reserved_paths::IGNORE_FILE_NAME;

pub const BUILT_IN_DEFAULT_PATTERNS: &[&str] =
    &[".DS_Store", "._*", "Thumbs.db", "desktop.ini", "*.swp", "*~", ".Spotlight-V100", ".Trashes"];

/// Label used as `IgnorePattern::source_file` for the built-in defaults —
/// never a real root-relative path, so it can't collide with a user file.
const BUILT_IN_SOURCE_LABEL: &str = "<built-in>";

/// Maximum `#include` nesting depth, as a defense-in-depth backstop behind
/// the ancestor-chain cycle check below ("cycle detection"):
/// the chain check alone already rejects any include graph that revisits
/// an ancestor, so this only guards against pathologically long (but
/// acyclic) include chains.
const MAX_INCLUDE_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnorePatternSource {
    BuiltIn,
    User,
}

/// why loading a link root's effective ignore configuration
/// failed. Distinct from a plain `io::Error` so callers that want
/// last-valid-config fallback behavior (`EffectiveIgnoreSet::reload_for_link_root`)
/// can describe the failure to a human without losing structure, and so
/// `load_for_link_root`'s existing `io::Result` callers keep working
/// unchanged (it maps this into an `io::Error` for them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoreConfigError {
    /// A file in the include graph is not valid UTF-8.
    InvalidEncoding(String),
    /// An `#include` directive's target is already an ancestor of the file
    /// containing it (or refers to itself) — following it would recurse
    /// forever.
    IncludeCycle(String),
    /// An `#include` directive's target is absolute or escapes the link
    /// Root via `..` — root confinement forbids both.
    IncludeEscapesRoot(String),
    /// An `#include` directive's target does not exist.
    MissingInclude(String),
    /// The include graph is nested deeper than `MAX_INCLUDE_DEPTH`.
    IncludeTooDeep(String),
    /// Any other I/O error reading a file in the include graph.
    Io(String),
}

impl std::fmt::Display for IgnoreConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IgnoreConfigError::InvalidEncoding(path) => {
                write!(f, "{path}: not valid UTF-8")
            }
            IgnoreConfigError::IncludeCycle(path) => {
                write!(f, "{path}: #include cycle detected")
            }
            IgnoreConfigError::IncludeEscapesRoot(path) => {
                write!(f, "{path}: #include target escapes the link root")
            }
            IgnoreConfigError::MissingInclude(path) => {
                write!(f, "{path}: #include target does not exist")
            }
            IgnoreConfigError::IncludeTooDeep(path) => {
                write!(f, "{path}: #include nesting exceeds {MAX_INCLUDE_DEPTH} levels")
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
    /// Root-relative path of the file this pattern's line came from, or
    /// `BUILT_IN_SOURCE_LABEL` for a built-in default.
    source_file: String,
    /// 1-based line number of this pattern within `source_file`.
    line: u32,
    /// Root-relative paths of every `#include`d file traversed to reach
    /// `source_file`, root (`IGNORE_FILE_NAME`) first — empty for patterns
    /// defined directly in the top-level file, or built-in.
    include_chain: Vec<String>,
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

    pub fn source_file(&self) -> &str {
        &self.source_file
    }

    pub fn line(&self) -> u32 {
        self.line
    }

    pub fn include_chain(&self) -> &[String] {
        &self.include_chain
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

    fn parse(
        line: &str,
        source: IgnorePatternSource,
        source_file: &str,
        line_number: u32,
        include_chain: &[String],
    ) -> Option<Self> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        // a leading `(?i)` marker (Syncthing's
        // own convention) makes this single line case-insensitive,
        // independent of every other line in the same file.
        let (case_insensitive, trimmed) =
            trimmed.strip_prefix("(?i)").map_or((false, trimmed), |rest| (true, rest.trim_start()));
        if trimmed.is_empty() {
            return None;
        }

        let (negated, body) =
            trimmed.strip_prefix('!').map_or((false, trimmed), |rest| (true, rest.trim_start()));
        let body = body.trim_end();
        if body.is_empty() {
            return None;
        }

        let (directory_only, body) =
            body.strip_suffix('/').map_or((false, body), |without_slash| (true, without_slash));
        let body = body.trim_matches('/');
        if body.is_empty() || body == "." || body.contains("//") {
            return None;
        }

        let anchored = body.contains('/');
        let mut segments = Vec::new();
        for segment in body.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return None;
            }
            segments.push(if segment == "**" {
                PatternSegment::DoubleStar
            } else {
                let text =
                    if case_insensitive { segment.to_lowercase() } else { segment.to_string() };
                PatternSegment::Glob(text)
            });
        }

        Some(IgnorePattern {
            original: trimmed.to_string(),
            source,
            source_file: source_file.to_string(),
            line: line_number,
            include_chain: include_chain.to_vec(),
            negated,
            directory_only,
            anchored,
            case_insensitive,
            segments,
        })
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
    /// `"<built-in>"` for a built-in default, else the root-relative path
    /// of the file the winning rule's line came from.
    pub source_file: String,
    /// Root-relative paths of every `#include`d file traversed to reach
    /// `source_file`, root first.
    pub include_chain: Vec<String>,
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
            source_file: String::new(),
            include_chain: Vec::new(),
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
            source_file: m.pattern.source_file().to_string(),
            include_chain: m.pattern.include_chain().to_vec(),
            line: m.pattern.line(),
            case_insensitive: m.pattern.is_case_insensitive(),
        }
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
                IgnorePattern::parse(
                    pattern,
                    IgnorePatternSource::BuiltIn,
                    BUILT_IN_SOURCE_LABEL,
                    (index + 1) as u32,
                    &[],
                )
            })
            .collect();
        EffectiveIgnoreSet { patterns }
    }

    /// Parses `lines` as a single, self-contained ignore file with no
    /// filesystem access — so `#include` directives are never honored here
    /// (there is no root to resolve them against, and no way to report a
    /// missing-include error usefully). Callers that need includes must go
    /// through `load_for_link_root`/`load_for_link_root_checked`.
    pub fn from_user_patterns(lines: &str) -> Self {
        let mut set = Self::defaults_only();
        set.patterns.extend(lines.lines().enumerate().filter_map(|(index, line)| {
            IgnorePattern::parse(
                line,
                IgnorePatternSource::User,
                IGNORE_FILE_NAME,
                (index + 1) as u32,
                &[],
            )
        }));
        set
    }

    /// Loads `root`'s effective ignore set, following `#include` directives.
    /// Preserves the original signature/behavior (`NotFound` on the
    /// top-level file means "no user patterns", any other failure is an
    /// `io::Error`) for the many existing callers across this workspace
    /// that don't care about `IgnoreConfigError`'s extra structure.
    pub fn load_for_link_root(root: impl AsRef<Path>) -> io::Result<Self> {
        Self::load_for_link_root_checked(root).map_err(Into::into)
    }

    /// Same as `load_for_link_root`, but returns the structured
    /// `IgnoreConfigError` instead of collapsing it into a
    /// generic `io::Error`.
    pub fn load_for_link_root_checked(root: impl AsRef<Path>) -> Result<Self, IgnoreConfigError> {
        let root = root.as_ref();
        let full_path = root.join(IGNORE_FILE_NAME);
        match fs::read(&full_path) {
            Ok(bytes) => {
                let contents = String::from_utf8(bytes).map_err(|_| {
                    IgnoreConfigError::InvalidEncoding(IGNORE_FILE_NAME.to_string())
                })?;
                let user_patterns = parse_file_contents(root, IGNORE_FILE_NAME, &contents, &[])?;
                let mut set = Self::defaults_only();
                set.patterns.extend(user_patterns);
                Ok(set)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self::defaults_only()),
            Err(err) => Err(IgnoreConfigError::Io(format!("{IGNORE_FILE_NAME}: {err}"))),
        }
    }

    /// reloads `root`, but on any
    /// `IgnoreConfigError` (bad encoding, include cycle, escaping include,
    /// missing include, too-deep nesting, other I/O) keeps `previous`
    /// instead of leaving the caller with no usable ignore set at all —
    /// a single edit mistake in a `.yadorilinkignore` should never stop
    /// sync from evaluating ignores altogether. Returns the error alongside
    /// the (possibly unchanged) set so the daemon/CLI can surface it.
    pub fn reload_for_link_root(
        root: impl AsRef<Path>,
        previous: &Self,
    ) -> (Self, Option<IgnoreConfigError>) {
        match Self::load_for_link_root_checked(root) {
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

pub fn is_ignore_file_relative_path(relative_path: impl AsRef<Path>) -> bool {
    normalize_relative_segments(relative_path.as_ref())
        .is_some_and(|segments| segments.len() == 1 && segments[0] == IGNORE_FILE_NAME)
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

/// Recognizes a `#include <target>` directive line (already trimmed).
/// Deliberately requires whitespace (or end-of-line) immediately after
/// `#include`, so an ordinary comment like `#includes an explanation` is
/// never misparsed as a directive.
fn strip_include_directive(trimmed: &str) -> Option<&str> {
    let rest = trimmed.strip_prefix("#include")?;
    match rest.chars().next() {
        None => None,
        Some(c) if c.is_whitespace() => {
            let target = rest.trim();
            if target.is_empty() {
                None
            } else {
                Some(target)
            }
        }
        Some(_) => None,
    }
}

/// an `#include` target must normalize to a
/// relative, non-escaping path — same rule `normalize_relative_segments`
/// already enforces for the paths being tested against ignore rules.
fn normalize_include_path(target: &str) -> Option<String> {
    let segments = normalize_relative_segments(Path::new(target))?;
    if segments.is_empty() {
        return None;
    }
    Some(segments.join("/"))
}

fn read_include_contents(root: &Path, relative_path: &str) -> Result<String, IgnoreConfigError> {
    let bytes = fs::read(root.join(relative_path)).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            IgnoreConfigError::MissingInclude(relative_path.to_string())
        } else {
            IgnoreConfigError::Io(format!("{relative_path}: {err}"))
        }
    })?;
    String::from_utf8(bytes)
        .map_err(|_| IgnoreConfigError::InvalidEncoding(relative_path.to_string()))
}

/// Parses `contents` (already read from `relative_path`) into patterns,
/// recursively splicing in any `#include`d file's patterns at the exact
/// point of the directive — this is what makes precedence deterministic
/// The merged list's document order exactly matches what a
/// human reading the top-level file top-to-bottom, jumping into includes
/// as they're reached, would see, and `match_path`'s existing
/// last-match-wins loop needs no special-casing for includes at all.
fn parse_file_contents(
    root: &Path,
    relative_path: &str,
    contents: &str,
    chain: &[String],
) -> Result<Vec<IgnorePattern>, IgnoreConfigError> {
    if chain.len() >= MAX_INCLUDE_DEPTH {
        return Err(IgnoreConfigError::IncludeTooDeep(relative_path.to_string()));
    }

    let mut patterns = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line_number = (index + 1) as u32;
        let trimmed = line.trim();
        if let Some(target) = strip_include_directive(trimmed) {
            let include_rel = normalize_include_path(target)
                .ok_or_else(|| IgnoreConfigError::IncludeEscapesRoot(target.to_string()))?;
            if include_rel == relative_path || chain.iter().any(|ancestor| ancestor == &include_rel)
            {
                return Err(IgnoreConfigError::IncludeCycle(include_rel));
            }
            let nested_contents = read_include_contents(root, &include_rel)?;
            let mut nested_chain = chain.to_vec();
            nested_chain.push(relative_path.to_string());
            patterns.extend(parse_file_contents(
                root,
                &include_rel,
                &nested_contents,
                &nested_chain,
            )?);
            continue;
        }
        if let Some(pattern) =
            IgnorePattern::parse(line, IgnorePatternSource::User, relative_path, line_number, chain)
        {
            patterns.push(pattern);
        }
    }
    Ok(patterns)
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
