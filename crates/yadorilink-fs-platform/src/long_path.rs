//! Paths past `MAX_PATH` for the Win32 calls that do not apply the `\\?\`
//! prefix themselves (`CreateFileW`, `MoveFileExW`, ...). Rust's `std::fs`
//! adds it for an absolute path that needs it; a raw wide-character call
//! does not, and fails with "path not found" for any path of 260 or more
//! characters.

/// Below this many UTF-16 units no prefix is added, so the paths that already
/// work are passed on unchanged. (`MAX_PATH` is 260 units; the margin covers
/// the file name a caller appends.)
const NEEDS_PREFIX_AT: usize = 240;

/// The verbatim (`\\?\`) form of an absolute Windows path of
/// `NEEDS_PREFIX_AT` UTF-16 units or more; `None` for everything else, which
/// is used as it is: short, relative, already verbatim or device paths, and
/// any path a verbatim form would read differently from Win32 -- one with a
/// `.`/`..` or empty component, or a component ending in a dot or a space
/// (Win32 strips those; a verbatim path keeps them literally).
pub fn verbatim_form(path: &str) -> Option<String> {
    // Separators first, so a `//?/` prefix is seen for what it is.
    let normalized = path.replace('/', r"\");
    if normalized.starts_with(r"\\?\") || normalized.starts_with(r"\\.\") {
        return None;
    }
    if normalized.encode_utf16().count() < NEEDS_PREFIX_AT {
        return None;
    }
    let bytes = normalized.as_bytes();
    let (rest, prefix) = if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
    {
        (&normalized[3..], format!(r"\\?\{}:\", &normalized[..1]))
    } else {
        let unc = normalized.strip_prefix(r"\\")?;
        (unc, r"\\?\UNC\".to_string())
    };
    let literal = rest.split('\\').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && !component.ends_with('.')
            && !component.ends_with(' ')
    });
    literal.then(|| format!("{prefix}{rest}"))
}

/// [`verbatim_form`] of `path`, or `path` itself.
#[cfg(windows)]
pub fn for_win32(path: &std::path::Path) -> std::path::PathBuf {
    path.to_str()
        .and_then(verbatim_form)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::verbatim_form;

    fn long(prefix: &str) -> String {
        format!("{prefix}{}", "a-long-segment\\".repeat(20)).trim_end_matches('\\').to_string()
    }

    #[test]
    fn a_long_drive_path_gets_the_verbatim_prefix() {
        let path = long(r"C:\root\");
        assert_eq!(verbatim_form(&path), Some(format!(r"\\?\{path}")));
        assert_eq!(verbatim_form(&path.replace('\\', "/")), Some(format!(r"\\?\{path}")));
    }

    #[test]
    fn a_long_unc_path_gets_the_unc_form() {
        let path = long(r"\\server\share\");
        assert_eq!(verbatim_form(&path), Some(format!(r"\\?\UNC\{}", &path[2..])));
    }

    #[test]
    fn short_relative_and_verbatim_paths_are_left_alone() {
        assert_eq!(verbatim_form(r"C:\short\path"), None);
        assert_eq!(verbatim_form(&long("relative\\")), None);
        assert_eq!(verbatim_form(&long(r"\\?\C:\")), None);
        assert_eq!(verbatim_form(&long(r"\\.\C:\")), None);
    }

    #[test]
    fn a_forward_slash_verbatim_prefix_is_recognised_not_misread_as_unc() {
        let path = long(r"C:\root\").replace('\\', "/");
        assert_eq!(verbatim_form(&format!("//?/{path}")), None);
    }

    #[test]
    fn length_is_counted_in_utf16_units_not_bytes() {
        // 130 characters of 3 UTF-8 bytes each: 390 bytes, 130 units.
        let path = format!(r"C:\{}", "\u{65e5}".repeat(130));
        assert_eq!(verbatim_form(&path), None);
        let path = format!(r"C:\{}", "\u{1F600}".repeat(130)); // 260 units
        assert!(verbatim_form(&path).is_some());
    }

    #[test]
    fn a_path_a_verbatim_form_would_read_differently_is_left_alone() {
        assert_eq!(verbatim_form(&format!("{}.", long(r"C:\root\"))), None);
        assert_eq!(verbatim_form(&format!("{} ", long(r"C:\root\"))), None);
        assert_eq!(verbatim_form(&format!(r"{}\..\x", long(r"C:\root\"))), None);
        assert_eq!(verbatim_form(&format!(r"{}\.\x", long(r"C:\root\"))), None);
        assert_eq!(verbatim_form(&format!(r"{}\\x", long(r"C:\root\"))), None);
    }

    #[test]
    fn non_ascii_and_degenerate_long_paths_never_panic() {
        let pad = "日".repeat(300);
        for head in [
            "",
            "C",
            "C:",
            "\\\\",
            "日",
            "日:\\",
            "\u{1F600}:\\",
            "Ｃ:\\",
            "C：\\",
            "e\u{301}:\\",
            "C:\\日本語\\",
            "\\\\サーバー\\共有\\",
            "\\\\\u{1F600}\\",
        ] {
            let _ = verbatim_form(&format!("{head}{pad}"));
            let _ = verbatim_form(&format!("{head}{pad}\\"));
        }
        let drive = format!(r"C:\日本語\{pad}");
        assert_eq!(verbatim_form(&drive), Some(format!(r"\\?\{drive}")));
    }
}
