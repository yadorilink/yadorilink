use std::path::{Path, PathBuf};

use yadorilink_fs_platform::ignore_patterns::{
    EffectiveIgnoreSet, IgnorePattern, IgnorePatternSource,
};
use yadorilink_replica_domain::reserved_paths::IGNORE_FILE_NAME;

use crate::error::CliError;

pub fn list(link_path: PathBuf) -> Result<(), CliError> {
    for line in pattern_lines(&link_path)? {
        println!("{line}");
    }
    Ok(())
}

pub fn test(path: PathBuf) -> Result<(), CliError> {
    println!("{}", test_path_output(&path)?);
    Ok(())
}

/// `yadorilink ignore explain <path>` — a richer sibling of `test` (kept
/// separate rather than changing `test`'s output, since
/// `test_path_output`'s exact wording has
/// its own fixture tests in `tests/ignore.rs`): the winning rule's source
/// file, `#include` chain, line number, and case-sensitivity mode, using
/// the exact same `EffectiveIgnoreSet` evaluator `test`/`list` use.
pub fn explain(path: PathBuf) -> Result<(), CliError> {
    println!("{}", explain_path_output(&path)?);
    Ok(())
}

pub fn explain_path_output(path: &Path) -> Result<String, CliError> {
    let (link_root, relative_path, is_dir) = resolve_test_path(path)?;
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&link_root)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let display_path = relative_path.to_string_lossy().replace('\\', "/");

    match ignore_set.explain_path(&relative_path, is_dir) {
        Some(explanation) if explanation.matched => {
            let verdict = if explanation.ignored { "ignored" } else { "not ignored" };
            let source = if explanation.source == IgnorePatternSource::BuiltIn {
                "builtin".to_string()
            } else if explanation.include_chain.is_empty() {
                explanation.source_file.clone()
            } else {
                format!(
                    "{} (via {})",
                    explanation.source_file,
                    explanation.include_chain.join(" -> ")
                )
            };
            let case = if explanation.case_insensitive { ", case-insensitive" } else { "" };
            Ok(format!(
                "{verdict}: {display_path} (rule `{}` at {}:{}{case})",
                explanation.rule_text, source, explanation.line
            ))
        }
        _ => Ok(format!("not ignored: {display_path} (no matching pattern)")),
    }
}

pub fn pattern_lines(link_path: &Path) -> Result<Vec<String>, CliError> {
    ensure_directory(link_path)?;
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(link_path)
        .map_err(|e| CliError::Other(e.to_string()))?;
    Ok(ignore_set.patterns().iter().map(format_pattern).collect())
}

pub fn test_path_output(path: &Path) -> Result<String, CliError> {
    let (link_root, relative_path, is_dir) = resolve_test_path(path)?;
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&link_root)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let display_path = relative_path.to_string_lossy().replace('\\', "/");

    match ignore_set.match_path(&relative_path, is_dir) {
        Some(matched) => {
            let verdict = if matched.ignored { "ignored" } else { "not ignored" };
            Ok(format!(
                "{verdict}: {display_path} (matched {} pattern `{}`)",
                source_label(matched.pattern.source()),
                matched.pattern.original()
            ))
        }
        None => Ok(format!("not ignored: {display_path} (no matching pattern)")),
    }
}

fn ensure_directory(path: &Path) -> Result<(), CliError> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| CliError::Other(format!("cannot read {}: {e}", path.display())))?;
    if !metadata.is_dir() {
        return Err(CliError::Other(format!("not a directory: {}", path.display())));
    }
    Ok(())
}

fn resolve_test_path(path: &Path) -> Result<(PathBuf, PathBuf, bool), CliError> {
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(|e| CliError::Other(e.to_string()))?.join(path)
    };
    let is_dir = absolute_path.is_dir();
    let search_start = if is_dir {
        absolute_path.as_path()
    } else {
        absolute_path.parent().unwrap_or_else(|| Path::new("."))
    };
    let link_root = nearest_ignore_root(search_start).unwrap_or_else(|| {
        if path.is_absolute() {
            search_start.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        }
    });
    let relative_path = absolute_path
        .strip_prefix(&link_root)
        .map_err(|_| {
            CliError::Other(format!(
                "{} is not under inferred link root {}",
                absolute_path.display(),
                link_root.display()
            ))
        })?
        .to_path_buf();
    Ok((link_root, relative_path, is_dir))
}

fn nearest_ignore_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|ancestor| ancestor.join(IGNORE_FILE_NAME).is_file())
        .map(Path::to_path_buf)
}

fn format_pattern(pattern: &IgnorePattern) -> String {
    format!("{}\t{}", source_label(pattern.source()), pattern.original())
}

fn source_label(source: IgnorePatternSource) -> &'static str {
    match source {
        IgnorePatternSource::BuiltIn => "builtin",
        IgnorePatternSource::User => "user",
    }
}
