//! Turns every problem `status` can show into its cause and the command to run next. The
//! meaning of a problem comes from the shared `AttentionItem`; only the words and commands are the
//! CLI's.

use std::borrow::Cow;

use yadorilink_client_core::attention::{Attention, AttentionItem};

use crate::i18n::tr;

/// The cause, as one sentence.
fn cause(item: AttentionItem) -> Cow<'static, str> {
    use AttentionItem as I;
    match item {
        I::FolderStopped => tr("This folder is paused by a problem and will retry."),
        I::WaitingForDiskSpace => tr("This folder is waiting for free space on its disk; syncing resumes by itself once there is room."),
        I::FileWatchLimit => tr("The system's limit on watched files is reached, so changes in this folder are picked up late or not at all until the limit is raised."),
        I::LinkedTwice => tr("This folder is linked in more than one place, so nothing syncs."),
        I::FolderNeedsRelink => tr("This folder is no longer linked to its shared folder (its ownership marker is gone, or it is not joined), so it does not sync. Its files are kept as they are."),
        I::VolumeChanged => tr("This folder is no longer on the disk it was set up on, so deletions are not synced until that disk is back or the folder is linked again."),
        I::VolumeUnconfirmed => tr("This folder's disk has no identity that survives a remount (FAT, exFAT, xfs before Linux 6.5), so after it was mounted again it cannot be told from another disk holding a copy. Nothing syncs until you confirm it is the right disk."),
        I::NoSafeCopy => tr("This folder has no safe second copy; losing this disk would lose data."),
        I::ContentUnavailable => tr("Immediate fetch from another device is not confirmed. Data already stored on this device may still be readable."),
        I::ContentAvailabilityUnknown => tr("It is not known yet whether missing files can be fetched."),
        I::ConflictNeedsReview => tr("Some files have conflicting copies."),
        I::ApprovalPending => tr("A device is waiting for your approval to join this shared folder."),
        I::FileHeld => tr("Some files were not applied to this device."),
        I::UnsupportedFilename => tr("Its name cannot be used on this device: it collides with another file's name or is not allowed here."),
        I::FileNotReadable => tr("The existing file on this device cannot be read by you, so its update was not applied."),
        I::RebuildNeeded => tr("This device's history of this folder can no longer catch up from the other devices, so it takes a fresh copy of their state from a connected device. Your files here are kept."),
        I::IndexDamaged => tr("A stored record of a file in this folder cannot be read back, so this folder cannot say whether its data is safe or fetchable until the record is repaired."),
        I::UnreadableFiles => tr("Some files in this folder cannot be read, so they are skipped and not synced. Nothing was deleted, and the rest of the folder keeps syncing."),
        I::StrandedDirectory => tr("A folder could not be removed safely and was left under a temporary name; nothing was deleted."),
        I::ProviderNotReady => tr("This File Provider folder is not ready to use."),
        I::ProviderFilesFailing => tr("Some files in this File Provider folder keep failing to download."),
        I::EditsKeptBeside => tr("Edits were kept beside a file instead of replacing it."),
        I::ProviderOrphan => tr("A File Provider folder exists that no linked folder uses."),
        I::DiskFull => tr("The disk is almost full, so syncing is paused."),
        I::DiskLow => tr("The disk is running low on space."),
        I::PeerUnavailable => tr("Another device cannot be reached."),
        I::RetryableFailure => tr("Something went wrong recently while syncing."),
        I::UpdateFailed => tr("The last update did not finish."),
        I::UpdateRequired => tr("Update required: that device runs an older version, so syncing with it is paused until it is updated. It is online, and nothing is deleted."),
        I::UpdateThisDevice => tr("Update this device: that device runs a newer version, so syncing with it is paused until this one is updated. It is online, and nothing is deleted."),
        I::DatabaseRestored => tr("This device's database was restored from a backup or copied, so it will not sync under its old identity. Start over as a new device; your files stay and the old state is never reused."),
        I::AuthorUnavailable => tr("This device cannot open the identity it signs changes with, so nothing it edits syncs. The daemon log names the cause; the usual one is that the cache directory holding the install record is not writable."),
        I::ProviderRegistryRestored => tr("The record of the Windows sync folders was damaged and an older copy was used; a folder added most recently may be missing until it is rewritten."),
        I::ReplacementUnconfirmed => tr("This device replaced another one that may have held the only complete copy of some folders, and the service has not confirmed the replacement yet. It is retried automatically; your files are kept."),
        I::ReplacementAcknowledge => tr("This device replaced another one that may have held the only complete copy of some folders. Acknowledge that changes made after the backup may be missing; the confirmation of the replacement waits for it. Your files are kept."),
        I::ReplacementWaiting => tr("The device replacement cannot be confirmed yet; the reason is in brackets. It is retried every minute and goes through by itself once the reason clears and you have acknowledged that changes made after the backup may be missing (yadorilink device acknowledge-replacement)."),
        I::ReplacementSignInRequired => tr("The confirmation of the device replacement was refused because you are signed out. Sign in again so it can go through; your files are kept."),
        I::TermsConsentRequired => tr("The service is refusing requests until you accept the updated Terms. Your files, folders and this device are kept and nothing is unlinked; sync of what is already set up keeps its local state. Sign in again to review and accept the Terms in your browser."),
        I::SignInRequired => tr("Signing in again is required (the Terms may have changed): the service refused to renew this computer's session. Your files, folders and this device are kept. Sign in again to continue."),
        I::AccountDeletionRequested => tr("Deleting this account was requested on another device. Open the account's settings to cancel it if this was not you."),
        I::AccountDeletionPending => tr("This account is scheduled for deletion. Your files on this computer are kept; the account can still be restored from its settings before the grace period ends."),
        I::AccountDeletionUrgent => tr("This account is about to be deleted: removing it would leave a shared folder without a safe copy, and the deletion goes ahead soon regardless. Review the account's settings now to restore it, or make another device a full copy."),
        I::Unrecognized => tr("Needs attention."),
    }
}

/// What to do next, in the CLI's terms.
fn next_step(item: AttentionItem) -> Cow<'static, str> {
    use AttentionItem as I;
    match item {
        I::LinkedTwice | I::VolumeChanged => "yadorilink links".into(),
        I::ReplacementAcknowledge => "yadorilink device acknowledge-replacement".into(),
        I::DatabaseRestored => "yadorilink device start-over".into(),
        I::ReplacementSignInRequired | I::TermsConsentRequired | I::SignInRequired => {
            "yadorilink login".into()
        }
        I::FolderNeedsRelink => tr("link the folder again: yadorilink links shows it; if it is not joined, accept a new invite into it (yadorilink share accept <invite> --path <folder>), or unlink it (yadorilink unlink)"),
        I::VolumeUnconfirmed => {
            tr("check the right disk is mounted, then: yadorilink readopt <folder>")
        }
        I::ConflictNeedsReview => "yadorilink conflicts list".into(),
        I::ApprovalPending => "yadorilink share pending".into(),
        I::DiskFull | I::DiskLow | I::WaitingForDiskSpace => "yadorilink gc --dry-run".into(),
        I::ContentUnavailable
        | I::ContentAvailabilityUnknown
        | I::PeerUnavailable
        | I::FileWatchLimit => {
            "yadorilink doctor".into()
        }
        I::UpdateFailed | I::UpdateRequired | I::UpdateThisDevice => "yadorilink update status".into(),
        I::ProviderOrphan => "yadorilink provider-folder --help".into(),
        I::UnsupportedFilename => {
            tr("rename the file (on the device that has it, if the name is not allowed here)")
        }
        I::FileNotReadable => {
            if cfg!(windows) {
                tr("make the file readable (grant yourself Read in the file's Security properties, or close the program that has it open)")
            } else {
                tr("make the file readable (chmod u+r)")
            }
        }
        I::UnreadableFiles => {
            if cfg!(windows) {
                tr("make the listed files readable (grant yourself Read in each file's Security properties, or close the program that has it open) or move them out of the folder; they are picked up again by the next scan, no restart needed (yadorilink status --details lists them)")
            } else {
                tr("make the listed files readable (for example chmod u+r <file>) or move them out of the folder; they are picked up again by the next scan, no restart needed (yadorilink status --details lists them)")
            }
        }
        I::FolderStopped
        | I::NoSafeCopy
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
        | I::AccountDeletionRequested
        | I::AccountDeletionPending
        | I::AccountDeletionUrgent
        | I::IndexDamaged
        | I::RebuildNeeded
        | I::Unrecognized => "yadorilink status --details".into(),
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
        format!("{} (code: {raw}){subject}", tr("Needs attention"))
    } else if item == AttentionItem::Unrecognized {
        format!("{}{subject} {} {}", tr("Needs attention"), tr("Next:"), next_step(item))
    } else {
        format!("{}{subject} {} {}", cause(item), tr("Next:"), next_step(item))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::tests::in_japanese;

    #[test]
    fn a_reason_reads_in_japanese_and_keeps_its_command_and_code() {
        let english = explain_reason("conflict:g", "photos", true);
        let japanese = in_japanese(|| explain_reason("conflict:g", "photos", true));
        assert!(english.contains("Next: yadorilink conflicts list"), "{english}");
        assert!(japanese.contains("対処: yadorilink conflicts list"), "{japanese}");
        assert!(japanese.contains("[photos]") && japanese.contains("(code: conflict:g)"));
        assert!(!japanese.contains("Next:"), "{japanese}");
    }

    #[test]
    fn every_reason_has_japanese_text() {
        for raw in [
            "degraded",
            "waiting_for_disk_space",
            "file_watch_limit",
            "ambiguous",
            "folder_needs_relink",
            "conflict",
            "approval_pending",
            "volume_changed",
            "volume_unconfirmed",
            "held",
            "unreadable_files",
            "index_damaged",
            "rebuild_needed",
            "update_required",
            "sign_in_required",
            "terms_consent_required",
            "low_disk",
        ] {
            let japanese = in_japanese(|| explain_reason(raw, "", false));
            let english = explain_reason(raw, "", false);
            assert_ne!(japanese, english, "{raw} is not translated");
        }
    }
}
