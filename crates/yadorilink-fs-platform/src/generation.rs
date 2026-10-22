//! Generation files: a private record kept as `<name>.<seq>` files, each published once with a
//! no-replace move and never replaced.
//!
//! A replacing publish can, by an undocumented detail of the file system, leave neither the old
//! nor the new file after a power loss; a record read as absent then reads as a first run. A
//! generation is created by a no-replace publish (a name that did not exist), so the previous
//! generation stays until the next one is published. The reader takes the highest generation
//! whose content is complete ([`seal`] / [`unseal`]).
//!
//! What this gives: no gap in which a record that was acknowledged before has no readable
//! generation (given the durable publish), and "no generation file at all" is the only first run
//! (`Latest::Missing`, also what a retired record reads as); generation files without a readable one are `Latest::Invalid`.
//!
//! What this does not give: a published generation is as durable as the move that published it
//! (it depends on the write-through move contract), and a lost newest generation is not
//! detected: the older one reads normally. There is no independent watermark.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::durable_dir::{create_dir_all_durably, publish_durably, Replace};

/// What the generation files of a record say.
#[derive(Debug, PartialEq, Eq)]
pub enum Latest<T> {
    /// No generation file exists: the record was never written.
    Missing,
    /// The newest complete generation. `skipped_newer`: a generation with a higher number exists
    /// that could not be decoded (torn or corrupt), so `value` may be older than the last
    /// acknowledged one. A caller that must never repeat something it already acted on treats
    /// that like [`Latest::Invalid`].
    Loaded { seq: u64, value: T, skipped_newer: bool },
    /// Generation files exist but none can be trusted (or the directory cannot be read).
    Invalid(String),
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `body` (newline terminated lines) followed by the line that proves it complete: format
/// version, number of lines and the SHA-256 of the lines.
pub fn seal(body: &str) -> String {
    format!("{body}end\tv1\t{}\t{}\n", body.lines().count(), hex(&Sha256::digest(body.as_bytes())))
}

/// The lines of a sealed record, or `None` when it is empty, cut short, changed, or has no seal.
pub fn unseal(text: &str) -> Option<&str> {
    let trailer_start = text.strip_suffix('\n')?.rfind('\n').map_or(0, |at| at + 1);
    let (body, trailer) = text.split_at(trailer_start);
    (*trailer == seal(body)[body.len()..]).then_some(body)
}

fn name_of(base: &Path) -> io::Result<(&Path, &str)> {
    let name = base.file_name().and_then(|n| n.to_str());
    match (base.parent(), name) {
        (Some(dir), Some(name)) => Ok((dir, name)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "not a record path")),
    }
}

/// The generation files of `base` (`<name>.<seq>` beside it), newest first. `Ok(vec![])`: none
/// (or no directory yet).
fn generations(base: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let (dir, name) = name_of(base)?;
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file = entry.file_name();
        let Some(file) = file.to_str() else { continue };
        let Some(seq) = file.strip_prefix(name).and_then(|rest| rest.strip_prefix('.')) else {
            continue;
        };
        if !seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(seq) = seq.parse::<u64>() {
                found.push((seq, entry.path()));
            }
        }
    }
    found.sort_by_key(|g| std::cmp::Reverse(g.0));
    Ok(found)
}

/// Reads the newest generation of `base` that `decode` accepts. A generation `decode` refuses
/// (torn or corrupt) is skipped for the one before it; one that cannot be read at all is not
/// skipped: the record is then unproven.
pub fn read_latest<T>(base: &Path, decode: impl Fn(&str) -> Option<T>) -> Latest<T> {
    let found = match generations(base) {
        Ok(found) => found,
        Err(e) => return Latest::Invalid(format!("{}: {e}", base.display())),
    };
    if found.is_empty() {
        return Latest::Missing;
    }
    for (index, (seq, path)) in found.iter().enumerate() {
        match fs::read_to_string(path) {
            Ok(text) => {
                // A retired record: nothing below the tombstone is read.
                if unseal(&text) == Some(RETIRED) {
                    return Latest::Missing;
                }
                if let Some(value) = decode(&text) {
                    return Latest::Loaded { seq: *seq, value, skipped_newer: index > 0 };
                }
            }
            Err(e) => return Latest::Invalid(format!("{}: {e}", path.display())),
        }
    }
    Latest::Invalid(format!("{}: no complete generation", base.display()))
}

static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

/// A temporary name no other live writer (thread or process) of the same record uses. A leftover
/// of a crashed process with the same pid can still hold the name: staging then takes the next
/// counter value instead of failing.
fn unique_tmp(dir: &Path, name: &str, seq: u64) -> PathBuf {
    let n = NEXT_TMP.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("{name}.{seq}.{}.{n}.tmp", std::process::id()))
}

/// How many times a publish that lost the race for a number looks again.
const PUBLISH_ATTEMPTS: usize = 256;

/// Publishes `text` as the next generation of `base` and returns its number once the publish
/// has returned. The directory is created durably first. The number is only a proposal from a
/// directory scan: each writer stages under its own name, and the no-replace publish decides
/// who gets a number (a writer that finds it taken scans again and tries the next one), so a
/// publish never returns for content another writer's staging file could have replaced.
/// Generations older than the previous one are then removed (an unlink that is not itself made
/// durable: a lost removal leaves an old generation, which no reader prefers).
pub fn publish_next(base: &Path, text: &str) -> io::Result<u64> {
    let (dir, name) = name_of(base)?;
    create_dir_all_durably(dir)?;
    for _ in 0..PUBLISH_ATTEMPTS {
        let found = generations(base)?;
        let seq = found.first().map_or(1, |(newest, _)| newest + 1);
        let (tmp, mut out) = loop {
            let tmp = unique_tmp(dir, name, seq);
            match fs::File::create_new(&tmp) {
                Ok(out) => break (tmp, out),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        };
        out.write_all(text.as_bytes())?;
        out.sync_all()?;
        drop(out);
        match publish_durably(&tmp, &dir.join(format!("{name}.{seq}")), Replace::No) {
            Ok(()) => {
                // A number that was freed by the pruning of a newer publish can be taken again
                // by a writer that scanned before it: that generation is not the newest, so
                // readers would never see it. It is withdrawn and the publish starts over.
                if generations(base)?.first().is_some_and(|(newest, _)| *newest > seq) {
                    let _ = fs::remove_file(dir.join(format!("{name}.{seq}")));
                    continue;
                }
                for (old, path) in found {
                    if old + 1 < seq {
                        let _ = fs::remove_file(path);
                    }
                }
                return Ok(seq);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(format!("{}: no free generation number", base.display())))
}

/// The body of the generation that retires a record.
const RETIRED: &str = "retired\n";

/// Retires the record: publishes a tombstone generation as the newest. It is as durable as any
/// publish, and it outranks every older generation, so an unlink that is lost, or an old
/// generation that comes back after a crash, cannot bring the record back: [`read_latest`]
/// answers [`Latest::Missing`] while the tombstone is the newest. The older generations are then
/// removed (best effort). A failed publish is an error and leaves the record as it was.
pub fn remove_all(base: &Path) -> io::Result<()> {
    let found = generations(base)?;
    if found.is_empty() {
        return Ok(());
    }
    publish_next(base, &seal(RETIRED))?;
    for (_, path) in found.into_iter().rev() {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("yl-gen-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn lines(text: &str) -> Option<Vec<String>> {
        unseal(text).map(|body| body.lines().map(str::to_string).collect())
    }

    #[test]
    fn a_seal_proves_a_record_complete() {
        let sealed = seal("a\nb\n");
        assert_eq!(unseal(&sealed), Some("a\nb\n"));
        assert_eq!(unseal(&seal("")), Some(""));
        assert_eq!(unseal(""), None);
        assert_eq!(unseal("a\nb\n"), None);
        assert_eq!(unseal(&sealed[..sealed.find('\n').unwrap() + 1]), None);
        assert_eq!(unseal(&sealed[..sealed.len() - 3]), None);
        assert_eq!(unseal(&sealed.replacen('a', "c", 1)), None);
    }

    #[test]
    fn no_generation_file_is_a_first_run_and_the_highest_complete_one_wins() {
        let d = dir("read");
        let base = d.join("state");
        assert_eq!(read_latest(&base, lines), Latest::Missing);
        assert_eq!(read_latest(&d.join("nodir/state"), lines), Latest::Missing);

        assert_eq!(publish_next(&base, &seal("one\n")).unwrap(), 1);
        assert_eq!(publish_next(&base, &seal("two\n")).unwrap(), 2);
        assert_eq!(
            read_latest(&base, lines),
            Latest::Loaded { seq: 2, value: vec!["two".to_string()], skipped_newer: false }
        );
        // Not generation files: a temporary file, another record's, the old single file.
        fs::write(d.join("state.9.tmp"), "x").unwrap();
        fs::write(d.join("state"), "x").unwrap();
        fs::write(d.join("other.9"), "x").unwrap();
        assert!(matches!(read_latest(&base, lines), Latest::Loaded { seq: 2, .. }));
        let _ = fs::remove_dir_all(&d);
    }

    /// The states a crash leaves around a publish: before the publish only the previous
    /// generation (and a temporary file); a torn newest generation is skipped; with nothing
    /// complete the record is unproven, not new.
    #[test]
    fn a_torn_or_unpublished_generation_leaves_the_previous_one_readable() {
        let d = dir("torn");
        let base = d.join("state");
        publish_next(&base, &seal("old\n")).unwrap();
        fs::write(d.join("state.2.tmp"), seal("new\n")).unwrap();
        assert!(matches!(read_latest(&base, lines), Latest::Loaded { seq: 1, .. }));

        let torn = seal("new\n");
        fs::write(d.join("state.2"), &torn[..torn.len() - 4]).unwrap();
        assert!(matches!(
            read_latest(&base, lines),
            Latest::Loaded { seq: 1, skipped_newer: true, .. }
        ));
        // The torn number is not reused.
        assert_eq!(publish_next(&base, &seal("newer\n")).unwrap(), 3);

        fs::write(d.join("state.3"), "garbage").unwrap();
        fs::write(d.join("state.1"), "garbage").unwrap();
        fs::write(d.join("state.2"), "garbage").unwrap();
        assert!(matches!(read_latest(&base, lines), Latest::Invalid(_)));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn only_the_two_newest_generations_are_kept_and_a_read_error_is_not_skipped() {
        let d = dir("prune");
        let base = d.join("state");
        for n in 0..5 {
            publish_next(&base, &seal(&format!("{n}\n"))).unwrap();
        }
        let seqs: Vec<u64> = generations(&base).unwrap().iter().map(|g| g.0).collect();
        assert_eq!(seqs, vec![5, 4]);
        // A generation that cannot be read (a directory in its place) is not skipped.
        fs::remove_file(d.join("state.5")).unwrap();
        fs::create_dir(d.join("state.5")).unwrap();
        assert!(matches!(read_latest(&base, lines), Latest::Invalid(_)));
        let _ = fs::remove_dir_all(&d);
    }

    /// Writers racing for the same number each get their own generation and their own content:
    /// no publish returns for bytes another writer staged.
    #[test]
    fn concurrent_writers_each_publish_their_own_generation() {
        let d = dir("race");
        let base = d.join("state");
        let (writers, rounds) = (8, 20);
        let results: Vec<Vec<(u64, String)>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..writers)
                .map(|w| {
                    let base = base.clone();
                    s.spawn(move || {
                        (0..rounds)
                            .map(|r| {
                                let body = format!("w{w}r{r}\n");
                                (publish_next(&base, &seal(&body)).unwrap(), body)
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let mut seqs: Vec<u64> = results.iter().flatten().map(|r| r.0).collect();
        seqs.sort_unstable();
        seqs.dedup();
        assert_eq!(seqs.len(), writers * rounds, "a number was handed out twice");
        // Whatever generation is still there holds exactly what its publisher wrote.
        for (seq, body) in results.iter().flatten() {
            if let Ok(text) = fs::read_to_string(d.join(format!("state.{seq}"))) {
                assert_eq!(unseal(&text), Some(body.as_str()));
            }
        }
        let tmp = fs::read_dir(&d)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(tmp, 0);
        let _ = fs::remove_dir_all(&d);
    }

    /// Retiring publishes a tombstone: an old generation that comes back after a crash (a lost
    /// unlink) is older than it and is never read; a new record outranks it again.
    #[test]
    fn a_retired_record_stays_retired_when_an_old_generation_comes_back() {
        let d = dir("retire");
        let base = d.join("state");
        for n in ["one", "two", "three"] {
            publish_next(&base, &seal(&format!("{n}\n"))).unwrap();
        }
        remove_all(&base).unwrap();
        assert_eq!(read_latest(&base, lines), Latest::Missing);
        // The lost unlink: an old generation is back beside the tombstone.
        fs::write(d.join("state.2"), seal("two\n")).unwrap();
        assert_eq!(read_latest(&base, lines), Latest::Missing);
        // A later record outranks the tombstone.
        let seq = publish_next(&base, &seal("again\n")).unwrap();
        assert!(seq > 3);
        assert!(matches!(read_latest(&base, lines), Latest::Loaded { .. }));
        // Retiring what is not there publishes nothing.
        let other = d.join("none");
        remove_all(&other).unwrap();
        assert!(generations(&other).unwrap().is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    /// Staging files a crashed process left under names this process would use (the same pid)
    /// do not make a publish fail.
    #[test]
    fn leftover_staging_files_of_a_reused_pid_do_not_fail_a_publish() {
        let d = dir("stale");
        let base = d.join("state");
        let start = NEXT_TMP.load(Ordering::Relaxed);
        for n in start..start + 64 {
            fs::write(d.join(format!("state.1.{}.{n}.tmp", std::process::id())), "stale").unwrap();
        }
        assert_eq!(publish_next(&base, &seal("one\n")).unwrap(), 1);
        assert!(matches!(read_latest(&base, lines), Latest::Loaded { seq: 1, .. }));
        let _ = fs::remove_dir_all(&d);
    }
}
