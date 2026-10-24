//! Turns every problem `status` can show into its cause and the command to run next. The
//! meaning of a problem comes from the shared `AttentionItem`; only the words and commands are the
//! CLI's.

use yadorilink_client_core::attention::{Attention, AttentionItem};

/// The cause, as one sentence.
fn cause(item: AttentionItem) -> &'static str {
    use AttentionItem as I;
    match item {
        I::FolderStopped => "This folder is paused by a problem and will retry.",
        I::WaitingForDiskSpace => "This folder is waiting for free space on its disk; syncing resumes by itself once there is room.",
        I::FileWatchLimit => "The system's limit on watched files is reached, so changes in this folder are picked up late or not at all until the limit is raised.",
        I::LinkedTwice => "This folder is linked in more than one place, so nothing syncs.",
        I::OwnershipLost => "This folder's ownership marker is gone; re-link or restart to continue.",
        I::NotJoined => "This folder is not joined to its folder group, so it no longer syncs. Its files are kept as they are.",
        I::VolumeChanged => "This folder is no longer on the disk it was set up on, so deletions are not synced until that disk is back or the folder is linked again.",
        I::VolumeUnconfirmed => "This folder's disk has no identity that survives a remount (FAT, exFAT, xfs before Linux 6.5), so after it was mounted again it cannot be told from another disk holding a copy. Nothing syncs until you confirm it is the right disk.",
        I::NoSafeCopy => "This folder has no safe second copy; losing this disk would lose data.",
        I::SafeCopyUnconfirmed => "This folder cannot confirm it is safely stored on disk yet.",
        I::ContentUnavailable => "Immediate fetch from another device is not confirmed. Data already stored on this device may still be readable.",
        I::ContentAvailabilityUnknown => "It is not known yet whether missing files can be fetched.",
        I::ConflictNeedsReview => "Some files have conflicting copies.",
        I::ApprovalPending => "A device is waiting for your approval to join this folder group.",
        I::FileHeld => "Some files were not applied to this device.",
        I::UnsupportedFilename => "Its name cannot be used on this device: it collides with another file's name or is not allowed here.",
        I::FileNotReadable => "The existing file on this device cannot be read by you, so its update was not applied.",
        I::UnreadableFiles => "Some files in this folder cannot be read, so they are skipped and not synced. Nothing was deleted, and the rest of the folder keeps syncing.",
        I::StrandedDirectory => "A folder could not be removed safely and was left under a temporary name; nothing was deleted.",
        I::ProviderNotReady => "This provider folder is not ready to use.",
        I::ProviderFilesFailing => "Some files in this provider folder keep failing to download.",
        I::EditsKeptBeside => "Edits were kept beside a file instead of replacing it.",
        I::ProviderOrphan => "A File Provider folder exists that no linked folder uses.",
        I::DiskFull => "The disk is almost full, so syncing is paused.",
        I::DiskLow => "The disk is running low on space.",
        I::PeerUnavailable => "Another device cannot be reached.",
        I::RetryableFailure => "Something went wrong recently while syncing.",
        I::UpdateFailed => "The last update did not finish.",
        I::UpdateRequired => "Update required: a device is on a different version, so syncing with it is paused until every device is updated. It is online, and nothing is deleted.",
        I::DatabaseRestored => "This device's database was restored from a backup or copied, so it will not sync under its old identity. Start over as a new device; your files stay and the old state is never reused.",
        I::AuthorUnavailable => "This device cannot open the identity it signs changes with, so nothing it edits syncs. The daemon log names the cause; the usual one is that the cache directory holding the install record is not writable.",
        I::ProviderRegistryRestored => "The record of the Windows sync folders was damaged and an older copy was used; a folder added most recently may be missing until it is rewritten.",
        I::ReplacementUnconfirmed => "This device replaced another one that may have held the only complete copy of some folders, and the service has not confirmed the replacement yet. It is retried automatically; your files are kept.",
        I::ReplacementWaiting => "The device replacement cannot be confirmed yet; the reason is in brackets. It is retried every minute and goes through by itself once the reason clears and you have acknowledged that changes made after the backup may be missing (yadorilink device acknowledge-replacement).",
        I::ReplacementSignInRequired => "The confirmation of the device replacement was refused because you are signed out. Sign in again so it can go through; your files are kept.",
        I::TermsConsentRequired => "The service is refusing requests until you accept the updated Terms. Your files, folders and this device are kept and nothing is unlinked; sync of what is already set up keeps its local state. Sign in again to review and accept the Terms in your browser.",
        I::SignInRequired => "Signing in again is required (the Terms may have changed): the service refused to renew this computer's session. Your files, folders and this device are kept. Sign in again to continue.",
        I::Unrecognized => "Needs attention.",
    }
}

/// What to do next, in the CLI's terms.
fn next_step(item: AttentionItem) -> &'static str {
    use AttentionItem as I;
    match item {
        I::LinkedTwice | I::OwnershipLost | I::VolumeChanged => "yadorilink links",
        I::DatabaseRestored => "yadorilink device start-over",
        I::ReplacementSignInRequired | I::TermsConsentRequired | I::SignInRequired => {
            "yadorilink login"
        }
        I::NotJoined => "accept a new invite to the folder group into this folder (yadorilink share accept <invite> --path <folder>), or unlink it (yadorilink unlink)",
        I::VolumeUnconfirmed => {
            "check the right disk is mounted, then: yadorilink readopt <folder>"
        }
        I::ConflictNeedsReview => "yadorilink conflicts list",
        I::ApprovalPending => "yadorilink share pending",
        I::DiskFull | I::DiskLow | I::WaitingForDiskSpace => "yadorilink gc --dry-run",
        I::ContentUnavailable
        | I::ContentAvailabilityUnknown
        | I::PeerUnavailable
        | I::FileWatchLimit => {
            "yadorilink doctor"
        }
        I::UpdateFailed | I::UpdateRequired => "yadorilink update status",
        I::ProviderOrphan => "yadorilink provider-folder --help",
        I::UnsupportedFilename => {
            "rename the file (on the device that has it, if the name is not allowed here)"
        }
        I::FileNotReadable => {
            if cfg!(windows) {
                "make the file readable (grant yourself Read in the file's Security properties, or close the program that has it open)"
            } else {
                "make the file readable (chmod u+r)"
            }
        }
        I::UnreadableFiles => {
            if cfg!(windows) {
                "make the listed files readable (grant yourself Read in each file's Security properties, or close the program that has it open) or move them out of the folder; they are picked up again by the next scan, no restart needed (yadorilink status --details lists them)"
            } else {
                "make the listed files readable (for example chmod u+r <file>) or move them out of the folder; they are picked up again by the next scan, no restart needed (yadorilink status --details lists them)"
            }
        }
        I::FolderStopped
        | I::NoSafeCopy
        | I::SafeCopyUnconfirmed
        | I::FileHeld
        | I::StrandedDirectory
        | I::ProviderNotReady
        | I::ProviderRegistryRestored
        | I::ReplacementUnconfirmed
        | I::ReplacementWaiting
        | I::AuthorUnavailable
        | I::ProviderFilesFailing
        | I::EditsKeptBeside
        | I::RetryableFailure
        | I::Unrecognized => "yadorilink status --details",
    }
}

/// The cause and the next step for a problem. `raw` stays visible only when `verbose`.
pub(super) fn explain(
    attention: &Attention,
    raw: &str,
    subject_name: &str,
    verbose: bool,
) -> String {
    let subject =
        if subject_name.is_empty() { String::new() } else { format!(" [{subject_name}]") };
    let item = attention.item;
    let mut text = if item == AttentionItem::Unrecognized && verbose {
        format!("Needs attention (code: {raw}){subject}")
    } else if item == AttentionItem::Unrecognized {
        format!("Needs attention{subject} Next: {}", next_step(item))
    } else {
        format!("{}{subject} Next: {}", cause(item), next_step(item))
    };
    if verbose && item != AttentionItem::Unrecognized {
        text.push_str(&format!("  (code: {raw})"));
    }
    text
}

/// The cause and next step for one held file's reason.
pub(super) fn explain_held(raw: &str) -> String {
    explain(&Attention::from_held_reason(raw), raw, "", false)
}

/// The cause and next step for one rollup reason (`code[:subject]`).
pub(super) fn explain_reason(raw: &str, subject_name: &str, verbose: bool) -> String {
    explain(&Attention::from_reason(raw), raw, subject_name, verbose)
}

/// A reason code split into its code and its subject (the text after the first `:`).
pub(super) fn split_code(raw: &str) -> (&str, &str) {
    raw.split_once(':').unwrap_or((raw, ""))
}
