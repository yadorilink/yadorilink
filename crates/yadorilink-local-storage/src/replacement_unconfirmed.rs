//! The record that a device replaced another one (start over) while the old device was the only
//! complete replica of some folder group, and the new device's state has not been confirmed to the
//! service yet. Written by client-core after the service answered `replacement-unconfirmed`, read
//! by the daemon's status so overall status is never healthy while it exists.
//!
//! The file holds no secret: the two device ids and the group ids the service named. Only its
//! presence matters to status, so an unreadable file counts as present (fail closed).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The record's file name in the state directory.
pub const FILE: &str = "replacement-unconfirmed.json";

/// The attention code the daemon reports while the record exists.
pub const ATTENTION_REASON: &str = "replacement_unconfirmed";

/// Present while the daemon's confirmation was refused for lack of a valid sign-in: the person has
/// to sign in again before the confirmation can go through.
pub const SIGN_IN_REQUIRED_FILE: &str = "replacement-unconfirmed.sign-in-required";

/// The extra attention code the daemon reports while [`SIGN_IN_REQUIRED_FILE`] exists next to
/// the record.
pub const SIGN_IN_ATTENTION_REASON: &str = "replacement_unconfirmed_sign_in_required";

/// The attention code the daemon reports while the record exists and the person has not yet
/// acknowledged that changes made after the backup may be missing (see
/// [`Record::acknowledged_possible_loss`]). Appended after the other reasons.
pub const ACKNOWLEDGEMENT_ATTENTION_REASON: &str =
    "replacement_unconfirmed_acknowledgement_required";

/// Holds the reason the daemon's last confirmation pass is still waiting, as one line of text.
/// Status shows it so a wait can be told from a stall; it is only ever read beside a record.
pub const WAITING_FILE: &str = "replacement-unconfirmed.waiting";

/// The attention code (`code:reason`) the daemon reports while [`WAITING_FILE`] exists next to
/// the record.
pub const WAITING_ATTENTION_REASON: &str = "replacement_unconfirmed_waiting";

/// The longest wait reason that is kept; longer text is cut.
const WAITING_REASON_MAX_CHARS: usize = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub old_device_id: String,
    pub new_device_id: String,
    pub unconfirmed_group_ids: Vec<String>,
    /// Whether the person acknowledged that changes made after the backup may be missing. A start
    /// over always begins from a database known to be older than, or foreign to, this install,
    /// and nothing this device holds can prove the groups the old device solely covered are
    /// complete, so the daemon never confirms without it. Absent means not acknowledged.
    #[serde(default)]
    pub acknowledged_possible_loss: bool,
}

fn path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

/// Whether a replacement is waiting for confirmation in the state directory `dir`.
#[must_use]
pub fn pending(dir: &Path) -> bool {
    path(dir).exists()
}

/// Records the replacement durably. Writing the same record again is harmless.
///
/// # Errors
/// The record could not be written.
pub fn write(dir: &Path, record: &Record) -> std::io::Result<()> {
    use yadorilink_fs_platform::durable_dir;
    let staged = dir.join(format!(".{FILE}.tmp-{}", std::process::id()));
    durable_dir::remove_file_durably(&staged)?;
    {
        let mut file = std::fs::File::create(&staged)?;
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(record)?)?;
        file.sync_all()?;
    }
    durable_dir::publish_durably(&staged, &path(dir), durable_dir::Replace::Yes)
}

/// The record, if there is one and it can be read. `Ok(None)` only when no record exists.
///
/// # Errors
/// The record exists and could not be read or parsed.
pub fn read(dir: &Path) -> std::io::Result<Option<Record>> {
    match std::fs::read(path(dir)) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether the record still waits for the person's acknowledgement. An unreadable record counts
/// as waiting (fail closed).
#[must_use]
pub fn acknowledgement_required(dir: &Path) -> bool {
    pending(dir)
        && !read(dir).is_ok_and(|record| record.is_some_and(|r| r.acknowledged_possible_loss))
}

/// Records that the person acknowledged that changes made after the backup may be missing.
/// Returns `false` (and changes nothing) when no replacement is waiting. Acknowledging twice is
/// harmless.
///
/// # Errors
/// The record could not be read or written.
pub fn acknowledge_possible_loss(dir: &Path) -> std::io::Result<bool> {
    let Some(mut record) = read(dir)? else {
        return Ok(false);
    };
    if !record.acknowledged_possible_loss {
        record.acknowledged_possible_loss = true;
        write(dir, &record)?;
    }
    Ok(true)
}

/// Whether the confirmation is waiting for the person to sign in again.
#[must_use]
pub fn sign_in_required(dir: &Path) -> bool {
    pending(dir) && dir.join(SIGN_IN_REQUIRED_FILE).exists()
}

/// Records (or withdraws) that the confirmation needs a fresh sign-in. Withdrawing when nothing
/// was recorded is harmless.
///
/// # Errors
/// The marker could not be written or removed.
pub fn set_sign_in_required(dir: &Path, required: bool) -> std::io::Result<()> {
    let marker = dir.join(SIGN_IN_REQUIRED_FILE);
    if required {
        if marker.exists() {
            return Ok(());
        }
        let staged = dir.join(format!(".{SIGN_IN_REQUIRED_FILE}.tmp-{}", std::process::id()));
        yadorilink_fs_platform::durable_dir::remove_file_durably(&staged)?;
        {
            let file = std::fs::File::create(&staged)?;
            file.sync_all()?;
        }
        yadorilink_fs_platform::durable_dir::publish_durably(
            &staged,
            &marker,
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        )
    } else {
        yadorilink_fs_platform::durable_dir::remove_file_durably(&marker)
    }
}

/// The reason the confirmation is still waiting, when the daemon recorded one beside a record.
#[must_use]
pub fn waiting_reason(dir: &Path) -> Option<String> {
    if !pending(dir) {
        return None;
    }
    let text = std::fs::read_to_string(dir.join(WAITING_FILE)).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Records (or, with `None`, withdraws) why the confirmation is waiting. The reason is flattened
/// to one line and cut to a bounded length. Returns whether anything changed on disk, so a caller
/// can log a change and not every unchanged pass.
///
/// # Errors
/// The file could not be written or removed.
pub fn set_waiting_reason(dir: &Path, reason: Option<&str>) -> std::io::Result<bool> {
    let marker = dir.join(WAITING_FILE);
    let Some(reason) = reason else {
        let existed = marker.exists();
        yadorilink_fs_platform::durable_dir::remove_file_durably(&marker)?;
        return Ok(existed);
    };
    let flat: String = reason
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(WAITING_REASON_MAX_CHARS)
        .collect();
    if std::fs::read_to_string(&marker).is_ok_and(|current| current.trim() == flat) {
        return Ok(false);
    }
    let staged = dir.join(format!(".{WAITING_FILE}.tmp-{}", std::process::id()));
    yadorilink_fs_platform::durable_dir::remove_file_durably(&staged)?;
    {
        let mut file = std::fs::File::create(&staged)?;
        std::io::Write::write_all(&mut file, flat.as_bytes())?;
        file.sync_all()?;
    }
    yadorilink_fs_platform::durable_dir::publish_durably(
        &staged,
        &marker,
        yadorilink_fs_platform::durable_dir::Replace::Yes,
    )?;
    Ok(true)
}

/// Removes the record once the service confirmed the replacement (and the sign-in marker with it).
///
/// The marker goes first: a crash between the two leaves the record, which is pending again and
/// retried, never a marker without a record.
///
/// # Errors
/// The record could not be removed.
pub fn clear(dir: &Path) -> std::io::Result<()> {
    yadorilink_fs_platform::durable_dir::remove_file_durably(&dir.join(WAITING_FILE))?;
    yadorilink_fs_platform::durable_dir::remove_file_durably(&dir.join(SIGN_IN_REQUIRED_FILE))?;
    yadorilink_fs_platform::durable_dir::remove_file_durably(&path(dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_record_is_pending_until_cleared() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!pending(dir.path()));
        let record = Record {
            old_device_id: "old".into(),
            new_device_id: "new".into(),
            unconfirmed_group_ids: vec!["g1".into()],
            acknowledged_possible_loss: false,
        };
        write(dir.path(), &record).unwrap();
        write(dir.path(), &record).unwrap();
        assert!(pending(dir.path()));
        let read: Record =
            serde_json::from_slice(&std::fs::read(dir.path().join(FILE)).unwrap()).unwrap();
        assert_eq!(read, record);
        assert_eq!(super::read(dir.path()).unwrap(), Some(record));
        clear(dir.path()).unwrap();
        clear(dir.path()).unwrap();
        assert!(!pending(dir.path()));
        assert_eq!(super::read(dir.path()).unwrap(), None);
    }

    #[test]
    fn the_sign_in_marker_counts_only_beside_a_record_and_goes_with_it() {
        let dir = tempfile::tempdir().unwrap();
        set_sign_in_required(dir.path(), true).unwrap();
        assert!(!sign_in_required(dir.path()), "no record, nothing to sign in for");
        let record = Record {
            old_device_id: "old".into(),
            new_device_id: "new".into(),
            unconfirmed_group_ids: vec![],
            acknowledged_possible_loss: false,
        };
        write(dir.path(), &record).unwrap();
        assert!(sign_in_required(dir.path()));
        set_sign_in_required(dir.path(), false).unwrap();
        assert!(!sign_in_required(dir.path()));
        set_sign_in_required(dir.path(), true).unwrap();
        clear(dir.path()).unwrap();
        assert!(!dir.path().join(SIGN_IN_REQUIRED_FILE).exists());
    }

    #[test]
    fn the_waiting_reason_shows_only_beside_a_record_is_flat_and_goes_with_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(set_waiting_reason(dir.path(), Some("g1: not linked")).unwrap());
        assert_eq!(waiting_reason(dir.path()), None, "no record, nothing to wait for");
        let record = Record {
            old_device_id: "old".into(),
            new_device_id: "new".into(),
            unconfirmed_group_ids: vec![],
            acknowledged_possible_loss: true,
        };
        write(dir.path(), &record).unwrap();
        assert_eq!(waiting_reason(dir.path()).as_deref(), Some("g1: not linked"));
        assert!(!set_waiting_reason(dir.path(), Some("g1: not linked")).unwrap(), "unchanged");
        assert!(set_waiting_reason(dir.path(), Some("a\n b")).unwrap());
        assert_eq!(waiting_reason(dir.path()).as_deref(), Some("a b"));
        let long = "x".repeat(WAITING_REASON_MAX_CHARS + 50);
        set_waiting_reason(dir.path(), Some(&long)).unwrap();
        assert_eq!(waiting_reason(dir.path()).unwrap().chars().count(), WAITING_REASON_MAX_CHARS);
        assert!(set_waiting_reason(dir.path(), None).unwrap());
        assert!(!set_waiting_reason(dir.path(), None).unwrap());
        assert_eq!(waiting_reason(dir.path()), None);
        set_waiting_reason(dir.path(), Some("again")).unwrap();
        clear(dir.path()).unwrap();
        assert!(!dir.path().join(WAITING_FILE).exists());
    }

    #[test]
    fn an_unparseable_record_is_an_error_not_absence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), b"{").unwrap();
        assert!(pending(dir.path()));
        assert!(super::read(dir.path()).is_err());
    }

    #[test]
    fn acknowledging_is_recorded_once_and_needs_a_record() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!acknowledge_possible_loss(dir.path()).unwrap(), "nothing to acknowledge");
        assert!(!acknowledgement_required(dir.path()));
        let record = Record {
            old_device_id: "old".into(),
            new_device_id: "new".into(),
            unconfirmed_group_ids: vec!["g1".into()],
            acknowledged_possible_loss: false,
        };
        write(dir.path(), &record).unwrap();
        assert!(acknowledgement_required(dir.path()));
        assert!(acknowledge_possible_loss(dir.path()).unwrap());
        assert!(acknowledge_possible_loss(dir.path()).unwrap());
        assert!(!acknowledgement_required(dir.path()));
        assert!(read(dir.path()).unwrap().unwrap().acknowledged_possible_loss);
    }

    #[test]
    fn a_record_without_the_field_or_unreadable_is_not_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(FILE),
            br#"{"old_device_id":"o","new_device_id":"n","unconfirmed_group_ids":[]}"#,
        )
        .unwrap();
        assert!(acknowledgement_required(dir.path()));
        std::fs::write(dir.path().join(FILE), b"not json").unwrap();
        assert!(acknowledgement_required(dir.path()), "fail closed");
    }
}
