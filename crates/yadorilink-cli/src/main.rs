//! `yadorilink` CLI.

use clap::{Parser, Subcommand, ValueEnum};
use yadorilink_cli::commands;
use yadorilink_cli::error::CliError;

#[derive(Parser)]
#[command(
    name = "yadorilink",
    version,
    about = "Peer-to-peer file sync",
    after_help = "Exit codes:\n  \
0   success\n  \
1   command failed\n  \
2   usage error (bad arguments)\n  \
3   cannot reach the YadoriLink server\n  \
4   daemon is not running\n  \
6   reporting needs the daemon\n  \
7   account limit or rate limit hit\n  \
8   operation may still be completing; the daemon will finish it\n  \
9   credential store problem\n  \
10  not logged in or sign-in rejected\n  \
11  rewind: the folder changed since the preview; preview again\n  \
12  rewind: some files cannot be restored, so it cannot start\n  \
13  rewind: a needed device did not answer; retry later\n  \
14  rewind: the folder changed before the rewind began; preview again\n  \
15  rewind: stopped after some changes; review and preview again\n  \
16  rewind: not started or stopped before any change (see the message)\n  \
17  rewind: you declined the confirmation; nothing was changed\n  \
18  rewind: confirmation needs a terminal (or --yes with --plan)\n  \
19  managed elsewhere: the app or another install owns YadoriLink on this machine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct RewindCommand {
    /// The linked folder (its path, or its folder group id).
    #[arg(required = true)]
    folder: Option<String>,
    /// The point in time: a local time (e.g. "2026-10-16 09:30" or "2026-10-16"), an offset back from now (e.g. 90s, 30m, 2h, 7d), or unix nanoseconds (e.g. 1750000000000000000).
    #[arg(long, required = true)]
    at: Option<String>,
    /// List every path and its action, not just a sample.
    #[arg(long)]
    verbose: bool,
    /// Run the rewind after previewing it and confirming.
    #[arg(long)]
    execute: bool,
    /// With --execute: the plan id the preview printed. The rewind runs only if the folder still matches that plan.
    #[arg(long, requires = "execute", value_name = "PLAN_ID")]
    plan: Option<String>,
    /// With --execute and --plan: do not ask for confirmation (for scripts).
    #[arg(long, requires = "plan")]
    yes: bool,
    #[command(subcommand)]
    action: Option<RewindAction>,
}

#[derive(Subcommand)]
enum RewindAction {
    /// Show how the folder's latest rewind stands.
    Status {
        /// The linked folder (its path, or its folder group id).
        folder: String,
    },
}

#[derive(Subcommand)]
enum CredentialsAction {
    /// Remove this computer's stored credentials locally; revokes nothing.
    Purge,
}

#[derive(Subcommand)]
enum Command {
    /// Log in with your Google account in a browser; the first login creates your account.
    Login {
        /// Print a URL and short code to enter on any device, for hosts with no usable browser.
        #[arg(long)]
        device: bool,
    },
    /// Sign out and revoke this computer's access. This cannot be undone.
    Logout {
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
    /// Remove this computer's stored credentials without revoking its access on the server.
    ForgetLocalCredentials,
    /// Local credential store maintenance (used by the uninstaller).
    #[command(hide = true)]
    Credentials {
        #[command(subcommand)]
        action: CredentialsAction,
    },
    /// Manage registered devices.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Manage who can access your folder groups.
    Share {
        #[command(subcommand)]
        action: ShareAction,
    },
    /// Inspect operations that were interrupted and may need attention (read-only).
    Recovery {
        #[command(subcommand)]
        action: RecoveryAction,
    },
    /// Link a local directory to a folder group.
    Link {
        local_path: String,
        group_name: String,
        /// Refused for a regular folder, which always keeps a full copy on this device. For
        /// on-demand storage use `provider-folder create <name> --on-demand`.
        #[arg(long)]
        on_demand: bool,
        /// Check the folder and print any problems without linking it.
        #[arg(long)]
        dry_run: bool,
        /// Proceed past warnings about a non-empty folder, low disk space, or a risky location.
        #[arg(long)]
        yes: bool,
    },
    /// Folders with no directory: the operating system shows them under File Provider (macOS).
    ProviderFolder {
        #[command(subcommand)]
        action: ProviderFolderAction,
    },
    /// Unlink a local directory. Its files stay on disk.
    Unlink {
        local_path: String,
        /// Unlink even if this device holds the only complete copy of the folder. This can permanently lose data.
        #[arg(long)]
        force: bool,
    },
    /// Confirm that the disk mounted at a linked folder is that folder's disk, so it syncs again.
    ///
    /// The folder then syncs with the disk as it is: files missing from it are deleted on every
    /// device. Needed after each remount of a disk without a stable identity (FAT, exFAT, xfs
    /// before Linux 6.5), and to accept a folder moved to another disk.
    Readopt { local_path: String },
    /// List currently linked folders.
    Links,
    /// List every retained version of a file, newest first.
    Versions { local_path: String },
    /// Restore a file to an earlier version (default: the most recent previous one).
    Restore {
        local_path: String,
        /// The version to restore; defaults to the most recent previous version.
        #[arg(long)]
        version: Option<i64>,
    },
    /// List and recover deleted files that are still within the retention window.
    Trash {
        #[command(subcommand)]
        action: TrashAction,
    },
    /// List conflicted copies across all linked folders.
    Conflicts {
        #[command(subcommand)]
        action: ConflictsAction,
    },
    /// Send a file or directory to another device on your account.
    Send { source_path: String, target_device: String },
    /// List transfers other devices have sent to this device.
    Inbox,
    /// List transfers this device has sent, including recent finished ones.
    Outbox,
    /// Accept an incoming transfer into `--to`, or the default inbox directory if omitted.
    Receive {
        transfer_id: String,
        #[arg(long)]
        to: Option<String>,
    },
    /// Stop or restart a transfer, one this device sent or one another device offered to it.
    Transfer {
        #[command(subcommand)]
        action: TransferAction,
    },
    /// Download a file that is stored on demand, so it is available offline.
    Hydrate { local_path: String },
    /// Free local disk space by removing a downloaded file's contents. The file stays listed.
    Evict { local_path: String },
    /// Show whether a file is stored locally or fetched on demand, and whether it is kept.
    MaterializationStatus { local_path: String },
    /// Always keep a file or folder on this device: download it and never free its space.
    Pin { local_path: String },
    /// Stop keeping a file or folder on this device. Its content stays until you free it.
    Unpin { local_path: String },
    /// Control the sync daemon.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Show sync status.
    Status {
        /// Keep refreshing the status instead of printing it once.
        #[arg(long, conflicts_with = "json")]
        watch: bool,
        /// Print the folders' availability and protection as JSON instead of text.
        #[arg(long)]
        json: bool,
        /// Also list up to N publications per provider folder that are waiting on the OS (a file in
        /// use, or a release still pending).
        #[arg(long, value_name = "N")]
        pending_items: Option<u32>,
        /// Also show internal ids and the raw reason codes.
        #[arg(long, visible_alias = "details")]
        verbose: bool,
    },
    /// Delete unused data blocks to free disk space.
    Gc {
        /// Report what would be deleted without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },

    /// List and manage items set aside when a folder group was reset.
    Preserved {
        #[command(subcommand)]
        action: PreservedAction,
    },
    /// Preview, and with --execute run, rewinding a folder to an earlier point in time.
    #[command(
        args_conflicts_with_subcommands = true,
        subcommand_negates_reqs = true,
        after_help = "Without --execute this only previews: it changes nothing.\n\
                      With --execute it previews, asks you to confirm the counts, then runs\n\
                      exactly the plan you saw. For scripts: --execute --yes --plan <plan id>\n\
                      with the exact --at value (unix nanoseconds) the preview printed."
    )]
    Rewind(RewindCommand),
    /// Manage global transfer rate limits.
    Limits {
        #[command(subcommand)]
        action: LimitsAction,
    },
    /// Automatic space management for provider folders.
    Space {
        #[command(subcommand)]
        action: SpaceAction,
    },
    /// Inspect ignore patterns for a linked folder.
    Ignore {
        #[command(subcommand)]
        action: IgnoreAction,
    },
    /// Preview or export usage and error reports, and manage reporting consent.
    Report {
        #[command(subcommand)]
        action: ReportAction,
    },
    /// Show where to send feedback and how crash reporting works.
    Feedback,
    /// Preview or export a privacy-safe diagnostics bundle.
    Diagnose {
        #[command(subcommand)]
        action: DiagnoseAction,
    },
    /// Delete your account or export your account data.
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },
    /// Inspect and manage local backups of your configuration.
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Check for updates and configure update checks.
    Update {
        #[command(subcommand)]
        action: UpdateAction,
    },
    /// Update a command-line (one-liner) install to a version the verified channel manifest allows.
    SelfUpdate {
        /// Pin this version instead of the channel's current one.
        #[arg(long)]
        version: Option<String>,
    },
    /// Remove a command-line install; your folders and data stay.
    Uninstall {
        /// Print what would be removed and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Continue without asking, also when files that were never downloaded would become unreadable here.
        #[arg(long)]
        yes: bool,
        /// Also delete YadoriLink's data directory (identity, sync database, saved versions).
        #[arg(long)]
        purge_data: bool,
    },
    /// Show how to open the local web dashboard, also from another computer over SSH.
    Web {
        #[command(subcommand)]
        action: WebAction,
    },
    /// Check connectivity: daemon, network, sign-in, permissions and clock.
    Doctor,
    /// Show recent connection attempts and addresses found on the local network.
    Connections {
        #[arg(long)]
        peer: Option<String>,
    },
}

/// The local web dashboard.
#[derive(Subcommand)]
enum WebAction {
    /// Print its address, an SSH port-forwarding example and where its token is (never the token).
    Status,
}

/// Check for updates and configure update checks.
#[derive(Subcommand)]
enum UpdateAction {
    /// Show the current version, update channel and update status.
    Status,
    /// Check for an update now.
    Check,
    /// Show where to download the new version (updates are installed manually).
    #[command(alias = "install")]
    Download,
    /// Turn automatic update checks on or off.
    Config {
        /// Automatic checks: `on` or `off`.
        #[arg(long)]
        checks: Option<String>,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Show which configuration backups exist locally and what is missing.
    Status,
    /// Export configuration and linked-folder list. Secrets and device keys are not included.
    Export {
        output_path: std::path::PathBuf,
        /// Overwrite the output file if it already exists.
        #[arg(long)]
        yes: bool,
        /// Export even if the linked-folder list cannot be read; the backup will contain no folders.
        #[arg(long)]
        without_folders: bool,
    },
    /// Import a configuration backup created by `export`.
    Import {
        input_path: std::path::PathBuf,
        /// Confirm overwriting your existing local configuration.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum AccountAction {
    /// Delete your account: request, confirm, cancel, or check status.
    Delete {
        #[command(subcommand)]
        action: AccountDeleteAction,
    },
    /// Export your account data (account, devices, groups, shares) as JSON.
    Export { output_path: Option<std::path::PathBuf> },
}

/// Self-service account-deletion actions.
#[derive(Subcommand)]
enum AccountDeleteAction {
    /// Request account deletion and get a confirmation token. Nothing is deleted yet.
    Request,
    /// Confirm the deletion with your token and start the grace period.
    Confirm { confirmation_token: String },
    /// Cancel a pending deletion during the grace period and keep your account.
    Cancel,
    /// Show whether your account is active or being deleted, and the time left.
    Status,
}

#[derive(Subcommand)]
enum ReportAction {
    /// Preview or export a usage summary. Nothing is sent over the network.
    Usage {
        /// Print the report that would be exported.
        #[arg(long)]
        preview: bool,
        /// Write the report as JSON to this path.
        #[arg(long)]
        export: Option<std::path::PathBuf>,
    },
    /// Preview, export, or submit an error report.
    Error {
        /// Use the most recent error (the default).
        #[arg(long)]
        last: bool,
        /// Use the error with this id.
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        preview: bool,
        #[arg(long)]
        export: Option<std::path::PathBuf>,
        #[arg(long)]
        submit: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Manage reporting consent.
    Consent {
        #[command(subcommand)]
        action: ReportConsentAction,
    },
    /// Manage reports waiting to be retried automatically.
    Queue {
        #[command(subcommand)]
        action: ReportQueueAction,
    },
}

#[derive(Subcommand)]
enum ReportQueueAction {
    /// List queued reports.
    List,
    /// Print one queued report.
    Show { report_id: String },
    /// Remove one queued report without submitting it.
    Delete { report_id: String },
    /// Remove all queued reports without submitting them.
    Flush,
}

#[derive(Subcommand)]
enum DiagnoseAction {
    /// Print a redacted diagnostics summary.
    Preview,
    /// Write a redacted diagnostics bundle to a file.
    Export { output_path: std::path::PathBuf },
}

#[derive(Subcommand)]
enum IgnoreAction {
    /// Print the ignore patterns in effect for a linked folder.
    List { link_path: std::path::PathBuf },
    /// Check whether a path is ignored.
    Test { path: std::path::PathBuf },
    /// Explain which rule ignores a path, and where that rule comes from.
    Explain { path: std::path::PathBuf },
}

#[derive(Subcommand)]
enum PreservedAction {
    /// List preserved items with their state and size.
    List,
    /// Write a preserved version back to its original path as a new version.
    Restore { item_id: String },
    /// Re-submit your own changes that were held back, once this device can write again.
    Retry { item_id: String },
    /// Originals a reset kept in the folder because no writer exclusion could be proved.
    Retained {
        #[command(subcommand)]
        action: RetainedAction,
    },
    /// Permanently delete a preserved item.
    Discard {
        item_id: String,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum RetainedAction {
    /// List the kept originals with the disk they take.
    List,
    /// Try to remove the kept originals; one that may still be written to stays.
    Release {
        /// Only this folder group (default: every group that has any).
        #[arg(long)]
        group: Option<String>,
    },
}

#[derive(Subcommand)]
enum SpaceAction {
    /// Show whether it is on.
    Show,
    /// Turn it on: when free disk space gets low, safe downloaded files are given back.
    On,
    /// Turn it off.
    Off,
    /// Show what it would do now, file by file; nothing is removed.
    Preview,
}

#[derive(Subcommand)]
enum LimitsAction {
    /// Set the upload and download rate limits in bytes per second (0 = unlimited).
    Set {
        #[arg(long)]
        up: u64,
        #[arg(long)]
        down: u64,
    },
    /// Show the current rate limits.
    Show,
}

#[derive(Subcommand)]
enum ReportConsentAction {
    /// Show consent state, queue size, and number of local reports.
    Status,
    /// Opt in to automatic crash and error reporting.
    Enable,
    /// Turn off all report submission.
    Disable,
    /// Show or hide the hint offered after a failure that can be reported (`true` or `false`).
    Prompts {
        // Any explicit `#[arg(...)]` (even value_name-only) opts a `bool`
        // field out of clap's auto-flag inference (which would otherwise
        // make this a presence-only `--enabled` switch): this is meant
        // to be a positional `true`/`false` value instead.
        #[arg(value_name = "true|false")]
        enabled: bool,
    },
}

#[derive(Subcommand)]
enum RecoveryAction {
    /// List interrupted operations.
    List {
        /// Print JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Diagnose one interrupted operation and recommend what to do.
    Show {
        domain: RecoveryDomainArg,
        operation_id: String,
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RecoveryDomainArg {
    Enrollment,
    Membership,
    #[value(name = "role-loss")]
    RoleLoss,
}

impl RecoveryDomainArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enrollment => "enrollment",
            Self::Membership => "membership",
            Self::RoleLoss => "role-loss",
        }
    }
}

#[derive(Subcommand)]
enum DeviceAction {
    /// Register this computer as a device on your account.
    Register {
        /// Name for this device (default: "this device").
        #[arg(long, default_value = "this device")]
        name: String,
    },
    /// List the devices registered on your account.
    List,
    /// Become a new device after this computer's database was restored from a backup or copied.
    ///
    /// Signs this computer out and retires its old device identity (kept on disk, never deleted),
    /// then, once you have signed in again and run this command a second time, registers it as a
    /// new device and joins each linked folder again. Your files and synced history stay where
    /// they are. The old device stays on your account, signed out, until you remove it.
    StartOver {
        /// Name for the new device (default: "this device").
        #[arg(long, default_value = "this device")]
        name: String,
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
    /// Acknowledge that changes made after your backup may be missing, so a replacement device can
    /// be confirmed.
    ///
    /// After `start-over`, this computer cannot prove it holds everything the replaced device held:
    /// anything changed after the backup was taken may be gone. Until you acknowledge that, the
    /// replacement stays unconfirmed and protection never reads healthy. Acknowledging does not
    /// touch any file.
    AcknowledgeReplacement {
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
    /// Remove a device and revoke its access to every folder group.
    Remove {
        device_id: String,
        /// Remove even if this device holds the only complete copy of a folder group. This can permanently lose data.
        #[arg(long)]
        force: bool,
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
    /// Open another device's management page and print its address.
    #[command(hide = true)]
    Manage { device_id: String },
}

#[derive(Subcommand)]
enum ProviderFolderAction {
    /// Create a new group and a provider folder for it.
    Create {
        /// The name the folder shows under the File Provider (macOS) or YadoriLink (Windows) location.
        display_name: String,
        /// The group's name (default: the display name).
        #[arg(long)]
        group_name: Option<String>,
        /// Fetch file contents on first access instead of downloading everything now.
        #[arg(long)]
        on_demand: bool,
    },
    /// Join an existing group as a provider folder (macOS File Provider, Windows Cloud Files).
    Join {
        group_id: String,
        display_name: String,
        #[arg(long)]
        group_name: Option<String>,
        #[arg(long)]
        on_demand: bool,
    },
    /// Remove a provider folder; the downloaded files are kept.
    Remove {
        display_name: String,
        /// Remove even if this device holds the only complete copy. This can permanently lose data.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ShareAction {
    /// Create a folder group and link a local folder to it.
    Create {
        group_name: String,
        /// Local directory to link the new folder group into.
        #[arg(long)]
        path: String,
        /// Proceed past warnings about a non-empty folder, low disk space, or a risky location.
        #[arg(long)]
        yes: bool,
    },
    /// Give one of your own devices access to a folder group.
    Grant {
        group_name: String,
        device_id: String,
        /// The device's role: `viewer` or `editor` (default `editor`).
        #[arg(long)]
        role: Option<String>,
    },
    /// Change the role of a device that already has access to a folder group.
    ChangeRole {
        group_name: String,
        /// A device id from `share members`.
        device_id: String,
        /// The new role: `viewer` or `editor`.
        #[arg(long)]
        role: String,
    },
    /// Revoke a device's access to a folder group, or revoke a share listed by `share list`.
    Revoke {
        /// A folder group name, or a share id from `share list` when no device id is given.
        group_name_or_edge: String,
        device_id: Option<String>,
        /// Revoke even if the device holds the only complete copy of the group. This can permanently lose data.
        #[arg(long)]
        force: bool,
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
    /// Delete a folder group you own, for every member.
    Delete {
        group_name: String,
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        yes: bool,
        /// Required when the group has members from other accounts.
        #[arg(long)]
        acknowledge_cross_account_members: bool,
    },
    /// List the shares you own and the shares of your own devices.
    List,
    /// List the devices with access to a folder group and their roles.
    Members { group_name: String },
    /// List the folder groups you can join on this device.
    Joinable,
    /// Join one of your folder groups on this device and link it to a local folder.
    Join {
        group_name: String,
        /// Local directory to link the folder group into.
        #[arg(long)]
        path: String,
        /// `eager` (store everything). `on-demand` is refused for a regular folder; use `provider-folder`. Defaults to `eager`.
        #[arg(long, default_value = "eager")]
        storage_mode: String,
        /// Proceed past warnings about a non-empty folder, low disk space, or a risky location.
        #[arg(long)]
        yes: bool,
    },
    /// Change how this device stores a folder group: `eager` or `on-demand`.
    SetStorageMode {
        group_name: String,
        /// `eager` (store everything) or `on-demand` (only for a ready provider folder).
        #[arg(long)]
        mode: String,
    },
    /// Create a one-use invite for a folder group you own, for someone on another account.
    Invite {
        group_name: String,
        /// The invited device's role: `viewer` or `editor` (default `viewer`).
        #[arg(long)]
        role: Option<String>,
        /// How long the invite stays valid, in seconds (default 7 days).
        #[arg(long)]
        ttl_secs: Option<u64>,
        /// Require your approval before the recipient gains access; see `share pending`.
        #[arg(long)]
        require_approval: bool,
    },
    /// Accept an invite code or link and link the folder group to a local folder.
    Accept {
        code_or_url: String,
        /// Local directory to link the folder group into.
        #[arg(long)]
        path: String,
        /// `eager` (store everything). `on-demand` is refused for a regular folder; use `provider-folder`. Defaults to `eager`.
        #[arg(long, default_value = "eager")]
        storage_mode: String,
        /// Proceed past warnings about a non-empty folder, low disk space, or a risky location.
        #[arg(long)]
        yes: bool,
    },
    /// List invites you created that have not been accepted yet.
    Invites,
    /// Cancel an invite that has not been accepted.
    CancelInvite {
        /// An invite id from `share invites`.
        invite_id: String,
    },
    /// List devices waiting for your approval to join a folder group.
    Pending,
    /// Approve a device waiting to join a folder group you own.
    Approve {
        group_name: String,
        /// A device id from `share pending`.
        device_id: String,
    },
    /// Turn down a device waiting to join a folder group you own.
    Deny {
        group_name: String,
        /// A device id from `share pending`.
        device_id: String,
    },
}

#[derive(Subcommand)]
enum TransferAction {
    /// Stop a transfer, sent or incoming. Safe to repeat; a finished transfer is left as it is.
    Cancel { transfer_id: String },
    /// Resume a failed incoming transfer, or offer a stopped sent one again.
    Retry { transfer_id: String },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the sync daemon.
    Start,
    /// Stop the sync daemon.
    Stop,
    /// Pause syncing, until you resume or for a set time.
    Pause {
        /// How long to pause: 30m, 1h or tomorrow (until local midnight). Omit to pause until resumed.
        #[arg(long = "for", value_enum)]
        duration: Option<commands::daemon::PauseFor>,
    },
    /// Resume syncing after a pause.
    Resume,
    /// Hand this machine's YadoriLink data to the YadoriLink app. Reversible until committed.
    #[command(name = "release-to-app")]
    ReleaseToApp {
        /// The app's install source: app_bundle (macOS) or microsoft_store (Windows).
        #[arg(long, value_name = "SOURCE", requires_all = ["app_root", "app_engine"])]
        to: Option<String>,
        /// The app bundle (*.app) or package directory.
        #[arg(long, value_name = "PATH")]
        app_root: Option<std::path::PathBuf>,
        /// The app's bundled engine executable (its release identity is read from beside it).
        #[arg(long, value_name = "PATH")]
        app_engine: Option<std::path::PathBuf>,
        /// The app's daemon runs: verify it and close the hand-off.
        #[arg(long, conflicts_with_all = ["to", "rollback", "status"])]
        commit: bool,
        /// Undo the open hand-off and return to the previous setup. The app must unregister its
        /// own launcher first.
        #[arg(long, conflicts_with_all = ["to", "commit", "status"])]
        rollback: bool,
        /// Show the open hand-off without changing anything.
        #[arg(long, conflicts_with_all = ["to", "commit", "rollback"])]
        status: bool,
        /// Print one JSON line with the outcome.
        #[arg(long)]
        json: bool,
    },
    /// Show or change the daemon's metrics endpoint; changes apply on the next start.
    Metrics {
        /// Enable the endpoint on the next start.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable the endpoint on the next start.
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        /// Address to listen on when enabling (default: 127.0.0.1:9184).
        #[arg(long)]
        addr: Option<String>,
        /// Show the saved configuration without changing it.
        #[arg(long)]
        show: bool,
    },
}

/// List and recover deleted files that are still within the retention window.
#[derive(Subcommand)]
enum TrashAction {
    /// List deleted files that can still be recovered.
    List,
    /// Recover a deleted file as a new current version.
    Restore {
        local_path: String,
        /// Also restore everything removed by the same folder delete or rename.
        #[arg(long)]
        folder: bool,
    },
}

#[derive(Subcommand)]
enum ConflictsAction {
    /// List conflicted copies across all linked folders.
    List,
    /// Make a kept copy the file, replacing the other version.
    Keep {
        /// The kept copy, as listed by `conflicts list`.
        copy_path: String,
    },
    /// Keep both versions as separate files with plain names.
    KeepBoth {
        /// The kept copy, as listed by `conflicts list`.
        copy_path: String,
    },
}

impl From<ConflictsAction> for commands::version_history::ConflictsCommand {
    fn from(action: ConflictsAction) -> Self {
        use commands::version_history::ConflictsCommand as C;
        match action {
            ConflictsAction::List => C::List,
            ConflictsAction::Keep { copy_path } => C::Keep(copy_path),
            ConflictsAction::KeepBoth { copy_path } => C::KeepBoth(copy_path),
        }
    }
}

#[tokio::main]
async fn main() {
    // Best-effort: installs a stderr subscriber so `tracing::warn!` audit
    // lines (e.g. a `--force` durability-gate override on
    // `unlink`/`share revoke`/`device remove`) are actually visible, rather
    // than silently dropped with no subscriber registered at all. Ignored on
    // failure (e.g. a test harness that already installed one) since this is
    // purely diagnostic logging, never load-bearing for command behavior.
    let _ = tracing_subscriber::fmt().with_writer(std::io::stderr).try_init();
    let cli = Cli::parse();
    let result = run(cli.command).await;
    if let Err(e) = result {
        eprintln!("error: {e}");
        if let Some(detail) = e.daemon_refusal_detail() {
            eprintln!("{detail}");
        }
        // A reportable failure gets a local-only candidate plus a hint,
        // entirely after the fact — this never changes `e`/the exit code
        // below, and makes no network call (see
        // `commands::report::handle_reportable_error`).
        if e.is_reportable() {
            commands::report::handle_reportable_error(&e).await;
        }
        std::process::exit(e.exit_code());
    }
}

async fn run_provider_folder(action: ProviderFolderAction) -> Result<(), CliError> {
    match action {
        ProviderFolderAction::Create { display_name, group_name, on_demand } => {
            commands::provider_folder::create(display_name, group_name, on_demand).await
        }
        ProviderFolderAction::Join { group_id, display_name, group_name, on_demand } => {
            commands::provider_folder::join(group_id, display_name, group_name, on_demand).await
        }
        ProviderFolderAction::Remove { display_name, force } => {
            commands::provider_folder::remove(display_name, force).await
        }
    }
}

async fn run_preserved(action: PreservedAction) -> Result<(), CliError> {
    match action {
        PreservedAction::List => commands::preserved::list().await,
        PreservedAction::Restore { item_id } => commands::preserved::restore(&item_id).await,
        PreservedAction::Retry { item_id } => commands::preserved::retry(&item_id).await,
        PreservedAction::Retained { action } => match action {
            RetainedAction::List => commands::preserved::retained_list().await,
            RetainedAction::Release { group } => commands::preserved::retained_release(group).await,
        },
        PreservedAction::Discard { item_id, yes } => {
            commands::preserved::discard(&item_id, yes).await
        }
    }
}

async fn run_space(action: SpaceAction) -> Result<(), CliError> {
    match action {
        SpaceAction::Show => commands::space::show().await,
        SpaceAction::On => commands::space::set(true).await,
        SpaceAction::Off => commands::space::set(false).await,
        SpaceAction::Preview => commands::space::preview().await,
    }
}

async fn run_rewind(command: RewindCommand) -> Result<(), CliError> {
    if let Some(RewindAction::Status { folder }) = command.action {
        return commands::rewind::status(folder).await;
    }
    // clap requires both without a subcommand.
    commands::rewind::run(commands::rewind::RewindArgs {
        folder: command.folder.expect("clap requires a folder"),
        at: command.at.expect("clap requires --at"),
        verbose: command.verbose,
        execute: command.execute,
        plan: command.plan,
        yes: command.yes,
    })
    .await
}

async fn run_report(action: ReportAction) -> Result<(), CliError> {
    match action {
        ReportAction::Usage { preview, export } => commands::report::usage(preview, export).await,
        ReportAction::Error { last: _, id, preview, export, submit, yes } => {
            commands::report::error(id, preview, export, submit, yes).await
        }
        ReportAction::Consent { action } => match action {
            ReportConsentAction::Status => commands::report::consent_status().await,
            ReportConsentAction::Enable => commands::report::consent_enable().await,
            ReportConsentAction::Disable => commands::report::consent_disable().await,
            ReportConsentAction::Prompts { enabled } => {
                commands::report::consent_prompts(enabled).await
            }
        },
        ReportAction::Queue { action } => match action {
            ReportQueueAction::List => commands::report::queue_list().await,
            ReportQueueAction::Show { report_id } => commands::report::queue_show(report_id).await,
            ReportQueueAction::Delete { report_id } => {
                commands::report::queue_delete(report_id).await
            }
            ReportQueueAction::Flush => commands::report::queue_flush().await,
        },
    }
}

async fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Login { device } => commands::auth::login(device).await,
        Command::Logout { yes } => commands::auth::logout(yes).await,
        Command::ForgetLocalCredentials => commands::auth::forget_local_credentials().await,
        Command::Credentials { action: CredentialsAction::Purge } => {
            commands::auth::credentials_purge().await
        }
        Command::Device { action } => match action {
            DeviceAction::Register { name } => commands::device::register(name).await,
            DeviceAction::List => commands::device::list().await,
            DeviceAction::StartOver { name, yes } => commands::device::start_over(name, yes).await,
            DeviceAction::AcknowledgeReplacement { yes } => {
                commands::device::acknowledge_replacement(yes)
            }
            DeviceAction::Remove { device_id, force, yes } => {
                commands::device::remove(device_id, force, yes).await
            }
            DeviceAction::Manage { device_id } => commands::device::manage(device_id).await,
        },
        Command::Recovery { action } => match action {
            RecoveryAction::List { json } => commands::recovery::list(json).await,
            RecoveryAction::Show { domain, operation_id, json } => {
                commands::recovery::show(domain.as_str(), operation_id, json).await
            }
        },
        Command::Share { action } => match action {
            ShareAction::Create { group_name, path, yes } => {
                commands::share::create(group_name, path, yes).await
            }
            ShareAction::Grant { group_name, device_id, role } => {
                commands::share::grant(group_name, device_id, role).await
            }
            ShareAction::ChangeRole { group_name, device_id, role } => {
                commands::share::change_role(group_name, device_id, role).await
            }
            ShareAction::Revoke { group_name_or_edge, device_id, force, yes } => match device_id {
                Some(device_id) => {
                    commands::share::revoke(group_name_or_edge, device_id, force, yes).await
                }
                None => commands::share::revoke_edge(group_name_or_edge, force, yes).await,
            },
            ShareAction::Delete { group_name, acknowledge_cross_account_members, yes } => {
                commands::share::delete_group(group_name, acknowledge_cross_account_members, yes)
                    .await
            }
            ShareAction::List => commands::share::list_shares().await,
            ShareAction::Members { group_name } => commands::share::members(group_name).await,
            ShareAction::Joinable => commands::share::list_joinable().await,
            ShareAction::Join { group_name, path, storage_mode, yes } => {
                commands::share::join(group_name, path, storage_mode, yes).await
            }
            ShareAction::SetStorageMode { group_name, mode } => {
                commands::share::set_storage_mode(group_name, mode).await
            }
            ShareAction::Invite { group_name, role, ttl_secs, require_approval } => {
                commands::share::invite(group_name, role, ttl_secs, require_approval).await
            }
            ShareAction::Accept { code_or_url, path, storage_mode, yes } => {
                commands::share::accept(code_or_url, path, storage_mode, yes).await
            }
            ShareAction::Invites => commands::share::list_invites().await,
            ShareAction::Pending => commands::share::list_pending_approvals().await,
            ShareAction::Approve { group_name, device_id } => {
                commands::share::approve(group_name, device_id).await
            }
            ShareAction::Deny { group_name, device_id } => {
                commands::share::deny(group_name, device_id).await
            }
            ShareAction::CancelInvite { invite_id } => {
                commands::share::cancel_invite(invite_id).await
            }
        },
        Command::ProviderFolder { action } => run_provider_folder(action).await,
        Command::Link { local_path, group_name, on_demand, dry_run, yes } => {
            commands::link::link(local_path, group_name, on_demand, dry_run, yes).await
        }
        Command::Unlink { local_path, force } => commands::link::unlink(local_path, force).await,
        Command::Readopt { local_path } => commands::link::readopt(local_path).await,
        Command::Links => commands::link::list().await,
        Command::Versions { local_path } => commands::version_history::versions(local_path).await,
        Command::Restore { local_path, version } => {
            commands::version_history::restore(local_path, version).await
        }
        Command::Trash { action } => match action {
            TrashAction::List => commands::version_history::trash_list().await,
            TrashAction::Restore { local_path, folder: true } => {
                commands::version_history::trash_restore_folder(local_path).await
            }
            TrashAction::Restore { local_path, folder: false } => {
                commands::version_history::trash_restore(local_path).await
            }
        },
        Command::Conflicts { action } => commands::version_history::conflicts(action.into()).await,
        Command::Send { source_path, target_device } => {
            commands::send::send(source_path, target_device).await
        }
        Command::Inbox => commands::send::inbox().await,
        Command::Outbox => commands::send::outbox().await,
        Command::Transfer { action } => match action {
            TransferAction::Cancel { transfer_id } => commands::send::cancel(transfer_id).await,
            TransferAction::Retry { transfer_id } => commands::send::retry(transfer_id).await,
        },
        Command::Receive { transfer_id, to } => commands::send::receive(transfer_id, to).await,
        Command::Hydrate { local_path } => commands::materialization::hydrate(local_path).await,
        Command::Evict { local_path } => commands::materialization::evict(local_path).await,
        Command::MaterializationStatus { local_path } => {
            commands::materialization::status(local_path).await
        }
        Command::Pin { local_path } => commands::materialization::pin(local_path).await,
        Command::Unpin { local_path } => commands::materialization::unpin(local_path).await,
        Command::Daemon { action } => match action {
            DaemonAction::Start => commands::daemon::start().await,
            DaemonAction::Stop => commands::daemon::stop().await,
            DaemonAction::Pause { duration } => commands::daemon::pause(duration).await,
            DaemonAction::Resume => commands::daemon::resume().await,
            DaemonAction::ReleaseToApp {
                to,
                app_root,
                app_engine,
                commit,
                rollback,
                status,
                json,
            } => {
                let action = commands::handoff::action_from_flags(
                    to, app_root, app_engine, commit, rollback, status,
                )?;
                commands::handoff::run(action, json).await
            }
            DaemonAction::Metrics { enable, disable, addr, show } => {
                commands::daemon::metrics(enable, disable, addr, show)
            }
        },
        Command::Status { watch, json, pending_items, verbose } => {
            if json {
                return commands::status::status_as_json().await;
            }
            commands::status::status(watch, verbose).await?;
            match pending_items {
                Some(limit) => commands::status::pending_items(limit, verbose).await,
                None => Ok(()),
            }
        }
        Command::Feedback => commands::feedback::run(),
        Command::Gc { dry_run } => commands::gc::run(dry_run).await,
        Command::Preserved { action } => run_preserved(action).await,
        Command::Rewind(command) => run_rewind(command).await,
        Command::Space { action } => run_space(action).await,
        Command::Limits { action } => match action {
            LimitsAction::Set { up, down } => commands::limits::set(up, down).await,
            LimitsAction::Show => commands::limits::show().await,
        },
        Command::Ignore { action } => match action {
            IgnoreAction::List { link_path } => commands::ignore::list(link_path),
            IgnoreAction::Test { path } => commands::ignore::test(path),
            IgnoreAction::Explain { path } => commands::ignore::explain(path),
        },
        Command::Report { action } => run_report(action).await,
        Command::Diagnose { action } => match action {
            DiagnoseAction::Preview => commands::diagnose::preview().await,
            DiagnoseAction::Export { output_path } => commands::diagnose::export(output_path).await,
        },
        Command::Account { action } => match action {
            AccountAction::Delete { action } => match action {
                AccountDeleteAction::Request => commands::account::delete_request().await,
                AccountDeleteAction::Confirm { confirmation_token } => {
                    commands::account::delete_confirm(confirmation_token).await
                }
                AccountDeleteAction::Cancel => commands::account::delete_cancel().await,
                AccountDeleteAction::Status => commands::account::delete_status().await,
            },
            AccountAction::Export { output_path } => commands::account::export(output_path).await,
        },
        Command::Backup { action } => match action {
            BackupAction::Status => commands::backup::status(),
            BackupAction::Export { output_path, yes, without_folders } => {
                commands::backup::export(output_path, yes, without_folders).await
            }
            BackupAction::Import { input_path, yes } => {
                commands::backup::import(input_path, yes).await
            }
        },
        Command::Update { action } => match action {
            UpdateAction::Status => commands::update::status().await,
            UpdateAction::Check => commands::update::check().await,
            UpdateAction::Download => commands::update::download().await,
            UpdateAction::Config { checks } => commands::update::config(checks).await,
        },
        Command::Uninstall { dry_run, yes, purge_data } => {
            commands::uninstall::uninstall(dry_run, yes, purge_data).await
        }
        Command::SelfUpdate { version } => commands::update::self_update(version).await,
        Command::Web { action: WebAction::Status } => commands::web::status().await,
        Command::Doctor => commands::connection_ops::doctor().await,
        Command::Connections { peer } => commands::connection_ops::traces(peer).await,
    }
}

#[cfg(test)]
mod help_text_tests {
    use super::Cli;
    use clap::CommandFactory;

    /// Words that belong in design notes, not in what a user reads in `--help`.
    const FORBIDDEN: &[&str] = &[
        "spec \"",
        "(spec",
        "on-demand-sync",
        "verb pair",
        "`Link`",
        "precedent",
        "pre-existing",
        "policy-log",
        "evaluator",
        "netmap",
        "QUIC",
        "RFC ",
        "OIDC",
        "coordination plane",
        "coordination-plane",
        "management-authority",
        "round trip",
    ];
    const MAX_ABOUT_CHARS: usize = 110;

    fn check(cmd: &clap::Command, path: &str, offenders: &mut Vec<String>) {
        let mut texts: Vec<(String, String)> = Vec::new();
        for (kind, text) in [("about", cmd.get_about()), ("long_about", cmd.get_long_about())] {
            if let Some(t) = text {
                texts.push((kind.to_string(), t.to_string()));
            }
        }
        for arg in cmd.get_arguments() {
            for (kind, text) in [("help", arg.get_help()), ("long_help", arg.get_long_help())] {
                if let Some(t) = text {
                    texts.push((format!("--{} {kind}", arg.get_id()), t.to_string()));
                }
            }
        }
        for (kind, text) in &texts {
            for marker in FORBIDDEN {
                if text.contains(marker) {
                    offenders.push(format!("{path} [{kind}] contains {marker:?}"));
                }
            }
        }
        if !path.is_empty() {
            match cmd.get_about() {
                None => offenders.push(format!("{path} has no description")),
                Some(a) if a.to_string().trim().is_empty() => {
                    offenders.push(format!("{path} has an empty description"))
                }
                Some(a) if a.to_string().chars().count() > MAX_ABOUT_CHARS => {
                    offenders.push(format!("{path} description is longer than a short sentence"))
                }
                _ => {}
            }
        }
        for sub in cmd.get_subcommands().filter(|s| s.get_name() != "help") {
            check(sub, format!("{path} {}", sub.get_name()).trim(), offenders);
        }
    }

    #[test]
    fn help_text_reads_like_product_text() {
        let mut offenders = Vec::new();
        check(&Cli::command(), "", &mut offenders);
        assert!(
            offenders.is_empty(),
            "{} help-text offenders:\n{}",
            offenders.len(),
            offenders.join("\n")
        );
    }
}
