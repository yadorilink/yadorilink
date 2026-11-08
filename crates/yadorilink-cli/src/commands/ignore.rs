//! `yadorilink ignore`: a folder's ignore rules, read and replaced through the daemon (the rules
//! are the daemon's own, per device; no file in the folder holds them).

use std::io::Read;
use std::path::Path;

use yadorilink_client_core::ops;
use yadorilink_fs_platform::ignore_patterns::{
    EffectiveIgnoreSet, IgnorePattern, IgnorePatternSource,
};

use crate::error::CliError;

/// The folder's rules as the engine applies them. `folder` is a folder path or its group id.
async fn load(folder: &str) -> Result<Loaded, CliError> {
    let group = ops::rewind::resolve_folder_group(folder).await?;
    let text = ops::ignore_rules::ignore_rules_get(&group).await?;
    let set = EffectiveIgnoreSet::from_text(&text).map_err(|e| CliError::Other(e.to_string()))?;
    // Where the folder is on this disk, to tell a directory from a file; a folder with no
    // directory (a File Provider folder) has none, and a trailing `/` names a directory then.
    let dir = ops::links::list_links()
        .await?
        .into_iter()
        .find(|link| link.group_id == group)
        .map(|link| link.local_path)
        .filter(|path| !path.is_empty());
    Ok(Loaded { set, dir })
}

struct Loaded {
    set: EffectiveIgnoreSet,
    dir: Option<String>,
}

pub async fn list(folder: String) -> Result<(), CliError> {
    let loaded = load(&folder).await?;
    for line in pattern_lines(&loaded.set) {
        println!("{line}");
    }
    Ok(())
}

pub async fn test(folder: String, path: String) -> Result<(), CliError> {
    let loaded = load(&folder).await?;
    println!("{}", test_path_output(&loaded.set, loaded.dir.as_deref(), &path));
    Ok(())
}

/// `yadorilink ignore explain <folder> <path>` — a richer sibling of `test`: the winning rule's
/// line number and case-sensitivity mode, from the same evaluator `test` and `list` use.
pub async fn explain(folder: String, path: String) -> Result<(), CliError> {
    let loaded = load(&folder).await?;
    println!("{}", explain_path_output(&loaded.set, loaded.dir.as_deref(), &path));
    Ok(())
}

/// `yadorilink ignore set <folder> <file>`: replaces the folder's rules with the text of `file`
/// (`-` reads standard input). An unusable line is refused with its number and nothing changes.
pub async fn set(folder: String, file: String) -> Result<(), CliError> {
    let mut text = String::new();
    if file == "-" {
        std::io::stdin().read_to_string(&mut text)?;
    } else {
        text = std::fs::read_to_string(&file)
            .map_err(|e| CliError::Other(format!("cannot read {file}: {e}")))?;
    }
    let group = ops::rewind::resolve_folder_group(&folder).await?;
    ops::ignore_rules::ignore_rules_set(&group, &text).await?;
    println!("ignore rules replaced for {folder}");
    Ok(())
}

pub fn pattern_lines(set: &EffectiveIgnoreSet) -> Vec<String> {
    set.patterns().iter().map(format_pattern).collect()
}

/// `path` is relative to the folder; a directory is told apart by the folder's own disk, or by a
/// trailing `/`.
fn is_dir(folder_dir: Option<&str>, path: &str) -> bool {
    path.ends_with('/') || folder_dir.is_some_and(|dir| Path::new(dir).join(path).is_dir())
}

pub fn test_path_output(set: &EffectiveIgnoreSet, folder_dir: Option<&str>, path: &str) -> String {
    match set.match_path(path, is_dir(folder_dir, path)) {
        Some(matched) => {
            let verdict = if matched.ignored { "ignored" } else { "not ignored" };
            format!(
                "{verdict}: {path} (matched {} pattern `{}`)",
                source_label(matched.pattern.source()),
                matched.pattern.original()
            )
        }
        None => format!("not ignored: {path} (no matching pattern)"),
    }
}

pub fn explain_path_output(
    set: &EffectiveIgnoreSet,
    folder_dir: Option<&str>,
    path: &str,
) -> String {
    match set.explain_path(path, is_dir(folder_dir, path)) {
        Some(explanation) if explanation.matched => {
            let verdict = if explanation.ignored { "ignored" } else { "not ignored" };
            let source = if explanation.source == IgnorePatternSource::BuiltIn {
                "built-in default".to_string()
            } else {
                format!("line {}", explanation.line)
            };
            let case = if explanation.case_insensitive { ", case-insensitive" } else { "" };
            format!("{verdict}: {path} (rule `{}` at {source}{case})", explanation.rule_text)
        }
        _ => format!("not ignored: {path} (no matching pattern)"),
    }
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
