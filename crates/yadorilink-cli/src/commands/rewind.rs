//! `yadorilink rewind <folder> --at <time> [--execute]` and
//! `yadorilink rewind status <folder>`: Folder Rewind from the command line.
//!
//! Without `--execute` this only previews; nothing is changed. With
//! `--execute` the flow is: preview, a y/N confirmation that names the counts,
//! then the rewind runs with the plan id of the preview that was shown, and
//! its progress is polled until the run ends. `--yes` skips the preview and
//! the question, and is only accepted together with `--plan <id>`, so a
//! script can run only a plan somebody has already seen.
//!
//! Every sentence about why a rewind cannot start, or how a run ended, comes
//! from the daemon (worded once in `yadorilink-replica-domain`); this file
//! only lays them out and picks the exit code.

use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

use yadorilink_client_core::ops::rewind::{self as ops, RewindStart};
use yadorilink_ipc_proto::daemonctl::{
    RewindActionCounts, RewindFailureKind, RewindPreviewResponse, RewindRefusalReason, RewindRun,
    RewindRunState,
};

use yadorilink_replica_domain::rewind::PLAN_STALE_MESSAGE;

use crate::error::{CliError, RewindExit};

/// How many paths a preview lists without `--verbose`.
/// Unix nanoseconds below this (about 1970-01-12) are taken as a unit mistake.
const MIN_PLAUSIBLE_NANOS: i64 = 1_000_000_000_000_000;

const SAMPLE_PATHS: usize = 10;

/// How often the run is looked at while it progresses.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

pub struct RewindArgs {
    pub folder: String,
    pub at: String,
    pub verbose: bool,
    pub execute: bool,
    pub plan: Option<String>,
    pub yes: bool,
}

/// What the flow needs from the daemon. The real one goes through the client
/// layer; the tests substitute one with scripted answers.
trait RewindDaemon {
    async fn preview(
        &self,
        at_unix_nanos: i64,
        include_unchanged: bool,
    ) -> Result<RewindPreviewResponse, CliError>;
    async fn execute(
        &self,
        target_unix_nanos: i64,
        plan_id: Vec<u8>,
    ) -> Result<RewindStart, CliError>;
    async fn status(&self) -> Result<Option<RewindRun>, CliError>;
}

struct Live {
    group: String,
}

impl RewindDaemon for Live {
    async fn preview(
        &self,
        at_unix_nanos: i64,
        include_unchanged: bool,
    ) -> Result<RewindPreviewResponse, CliError> {
        Ok(ops::preview(self.group.clone(), at_unix_nanos, include_unchanged).await?)
    }

    async fn execute(
        &self,
        target_unix_nanos: i64,
        plan_id: Vec<u8>,
    ) -> Result<RewindStart, CliError> {
        Ok(ops::execute(self.group.clone(), target_unix_nanos, plan_id).await?)
    }

    async fn status(&self) -> Result<Option<RewindRun>, CliError> {
        Ok(ops::status(self.group.clone()).await?)
    }
}

/// Where the flow writes and reads, and how fast it polls.
struct Io<'a> {
    out: &'a mut dyn Write,
    input: &'a mut dyn BufRead,
    interactive: bool,
    poll_interval: Duration,
}

pub async fn run(args: RewindArgs) -> Result<(), CliError> {
    let group = ops::resolve_folder_group(&args.folder).await?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut io = Io {
        out: &mut stdout,
        input: &mut input,
        interactive: std::io::stdin().is_terminal(),
        poll_interval: POLL_INTERVAL,
    };
    run_flow(&Live { group }, &mut io, &args, now_unix_nanos()).await
}

pub async fn status(folder: String) -> Result<(), CliError> {
    let group = ops::resolve_folder_group(&folder).await?;
    let mut stdout = std::io::stdout();
    status_flow(&Live { group }, &mut stdout, &folder).await
}

async fn status_flow(
    daemon: &impl RewindDaemon,
    out: &mut dyn Write,
    folder: &str,
) -> Result<(), CliError> {
    match daemon.status().await? {
        None => say(out, format_args!("No rewind has been run for {folder}."))?,
        Some(run) => {
            say(out, format_args!("Latest rewind of {folder}"))?;
            say(out, format_args!("  Target time: {}", describe_time(run.target_unix_nanos)))?;
            say(out, format_args!("  Plan id: {}", hex(&run.plan_id)))?;
            say(out, format_args!("  {}", run.message))?;
        }
    }
    Ok(())
}

async fn run_flow(
    daemon: &impl RewindDaemon,
    io: &mut Io<'_>,
    args: &RewindArgs,
    now_unix_nanos: i64,
) -> Result<(), CliError> {
    let at = parse_at(&args.at, now_unix_nanos)?;
    let plan_from_flag = args.plan.as_deref().map(parse_plan_id).transpose()?;
    if plan_from_flag.is_some() && at.relative {
        return Err(CliError::Other(
            "--plan needs the exact --at value the preview printed (unix nanoseconds), not a \
             time relative to now"
                .into(),
        ));
    }

    // A script that already holds a plan id runs that plan without looking
    // at the folder again; the daemon refuses it if the folder has moved on.
    if args.yes {
        let plan_id = plan_from_flag.expect("clap requires --plan with --yes");
        say(
            io.out,
            format_args!(
                "Rewinding {} to {} (plan {})",
                args.folder,
                describe_time(at.nanos),
                hex(&plan_id)
            ),
        )?;
        return start_and_follow(daemon, io, at.nanos, plan_id).await;
    }

    let preview = daemon.preview(at.nanos, args.verbose).await?;
    say(io.out, format_args!("{}", format_rewind_plan(&preview, &args.folder, args.verbose)))?;
    if !args.execute {
        return Ok(());
    }

    let counts = preview.counts.unwrap_or_default();
    if counts.unavailable > 0 {
        return Err(CliError::Rewind {
            exit: RewindExit::Unavailable,
            message: preview.unavailable_message,
        });
    }
    // The counts asked about below are this preview's, so only this
    // preview's plan may be run on the strength of them.
    if plan_from_flag.as_ref().is_some_and(|plan| *plan != preview.plan_id) {
        return Err(CliError::Rewind {
            exit: RewindExit::PlanStale,
            message: PLAN_STALE_MESSAGE.into(),
        });
    }
    confirm(io, &confirmation_prompt(&args.folder, &counts))?;
    start_and_follow(daemon, io, preview.target_unix_nanos, preview.plan_id.clone()).await
}

async fn start_and_follow(
    daemon: &impl RewindDaemon,
    io: &mut Io<'_>,
    target_unix_nanos: i64,
    plan_id: Vec<u8>,
) -> Result<(), CliError> {
    match daemon.execute(target_unix_nanos, plan_id).await? {
        RewindStart::Started { run_id } => follow(daemon, io, &run_id).await,
        RewindStart::PlanStale { message, .. } => {
            Err(CliError::Rewind { exit: RewindExit::PlanStale, message })
        }
        RewindStart::Refused(refused) => {
            let exit = match RewindRefusalReason::try_from(refused.reason) {
                Ok(RewindRefusalReason::UnavailablePaths) => RewindExit::Unavailable,
                Ok(RewindRefusalReason::FolderSettling) => RewindExit::FolderChanged,
                _ => RewindExit::NotStarted,
            };
            Err(CliError::Rewind { exit, message: refused.message })
        }
    }
}

/// Prints the run's progress as it changes, until it ends.
async fn follow(daemon: &impl RewindDaemon, io: &mut Io<'_>, run_id: &str) -> Result<(), CliError> {
    say(io.out, format_args!("Rewind started."))?;
    let mut last_shown = String::new();
    loop {
        let run = daemon.status().await?.filter(|run| run.run_id == run_id).ok_or_else(|| {
            CliError::Other(yadorilink_client_core::dto::RUN_MISSING_MESSAGE.into())
        })?;
        if run.message != last_shown {
            say(io.out, format_args!("{}", run.message))?;
            last_shown = run.message.clone();
        }
        let state = RewindRunState::try_from(run.state).unwrap_or(RewindRunState::Unspecified);
        match state {
            RewindRunState::Done => return Ok(()),
            RewindRunState::NeedsReplan => {
                return Err(CliError::Rewind {
                    exit: RewindExit::NeedsReplan,
                    message: run.message,
                })
            }
            RewindRunState::Failed => {
                let exit = match RewindFailureKind::try_from(run.failure_kind) {
                    Ok(RewindFailureKind::ContentUnavailable) => RewindExit::Unavailable,
                    Ok(RewindFailureKind::Transient) => RewindExit::Transient,
                    Ok(RewindFailureKind::FolderChanged) => RewindExit::FolderChanged,
                    _ => RewindExit::NotStarted,
                };
                return Err(CliError::Rewind { exit, message: run.message });
            }
            RewindRunState::Planned | RewindRunState::Prefetched | RewindRunState::Committing => {
                tokio::time::sleep(io.poll_interval).await
            }
            RewindRunState::Unspecified => {
                return Err(CliError::Other(
                    "the daemon reported a rewind state this command does not know; check \
                     `yadorilink rewind status`"
                        .into(),
                ))
            }
        }
    }
}

fn confirmation_prompt(folder: &str, counts: &RewindActionCounts) -> String {
    format!(
        "This rewinds {folder}: {} files will be created, {} replaced and {} deleted, as \
         ordinary changes that sync to your other devices. Continue?",
        counts.create, counts.replace, counts.delete
    )
}

fn confirm(io: &mut Io<'_>, prompt: &str) -> Result<(), CliError> {
    if !io.interactive {
        return Err(CliError::Rewind {
            exit: RewindExit::NotConfirmable,
            message: "Not confirmed; nothing was changed. To run without a terminal, pass --yes together \
             with --plan <plan id>."
                .into(),
        });
    }
    write!(io.out, "{prompt} [y/N] ")?;
    io.out.flush()?;
    let mut line = String::new();
    let answered_yes = io.input.read_line(&mut line).is_ok()
        && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    if answered_yes {
        Ok(())
    } else {
        Err(CliError::Rewind {
            exit: RewindExit::Declined,
            message: "Cancelled; nothing was changed.".into(),
        })
    }
}

fn say(out: &mut dyn Write, line: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    writeln!(out, "{line}")?;
    Ok(())
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_plan_id(raw: &str) -> Result<Vec<u8>, CliError> {
    let raw = raw.trim();
    let bad = || {
        CliError::Other(format!(
            "cannot read --plan value {raw:?}: expected the 64-digit plan id the preview printed"
        ))
    };
    if raw.len() != 64 || !raw.is_ascii() {
        return Err(bad());
    }
    (0..32).map(|i| u8::from_str_radix(&raw[2 * i..2 * i + 2], 16).map_err(|_| bad())).collect()
}

/// `YYYY-MM-DD HH:MM:SS` local time with the exact instant, for a nanosecond
/// timestamp.
fn describe_time(unix_nanos: i64) -> String {
    format!(
        "{} (--at {unix_nanos})",
        super::status::format_local_time(unix_nanos.div_euclid(1_000_000_000))
    )
}

/// A parsed `--at`.
#[derive(Debug, PartialEq, Eq)]
struct At {
    nanos: i64,
    /// Measured back from now, so it is a different instant on every run.
    relative: bool,
}

/// Parses `--at` into nanoseconds since the Unix epoch.
///
/// Three accepted forms: a local time (`2026-10-16 09:30`,
/// `2026-10-16T09:30:15`, or just `2026-10-16` for midnight), a relative
/// offset (`90s`, `30m`, `2h`, `7d`) subtracted from `now`, and a bare
/// integer taken as absolute unix nanoseconds (the unit every timestamp on
/// this control protocol uses, and what the preview prints back so a script
/// can name the exact instant).
///
/// Anything before the Unix epoch or after `now` is rejected: a rewind to the
/// future is today's state answered with a confident, useless plan.
fn parse_at(raw: &str, now_unix_nanos: i64) -> Result<At, CliError> {
    let raw = raw.trim();
    const NANOS_PER_SECOND: i64 = 1_000_000_000;
    let (nanos, relative) = if let Ok(absolute) = raw.parse::<i64>() {
        // Nanoseconds since 1970 have been 16 digits since 2001; anything
        // much smaller is a count in some other unit, not a time.
        if absolute < MIN_PLAUSIBLE_NANOS {
            return Err(CliError::Other(format!(
                "--at {raw} is too small to be unix nanoseconds; give a local time, an offset \
                 with a unit (e.g. 2h), or nanoseconds (e.g. 1750000000000000000)"
            )));
        }
        (absolute, false)
    } else if let Some(secs) = parse_local_time(raw) {
        (secs.checked_mul(NANOS_PER_SECOND).ok_or_else(|| invalid_at(raw))?, false)
    } else {
        let (digits, unit_nanos) = match raw.as_bytes().last() {
            Some(b's') => (&raw[..raw.len() - 1], NANOS_PER_SECOND),
            Some(b'm') => (&raw[..raw.len() - 1], 60 * NANOS_PER_SECOND),
            Some(b'h') => (&raw[..raw.len() - 1], 3_600 * NANOS_PER_SECOND),
            Some(b'd') => (&raw[..raw.len() - 1], 86_400 * NANOS_PER_SECOND),
            _ => return Err(invalid_at(raw)),
        };
        let count: i64 = digits.parse().map_err(|_| invalid_at(raw))?;
        if count < 0 {
            return Err(invalid_at(raw));
        }
        let offset = count.checked_mul(unit_nanos).ok_or_else(|| invalid_at(raw))?;
        (now_unix_nanos.saturating_sub(offset), true)
    };
    if nanos < 0 || nanos > now_unix_nanos {
        return Err(invalid_at(raw));
    }
    Ok(At { nanos, relative })
}

fn invalid_at(raw: &str) -> CliError {
    CliError::Other(format!(
        "cannot read --at value {raw:?}: expected a past local time (e.g. \"2026-10-16 09:30\"), \
         an offset back from now (e.g. 90s, 30m, 2h, 7d) or unix nanoseconds"
    ))
}

/// Unix seconds for `YYYY-MM-DD[ T]HH:MM[:SS]` or `YYYY-MM-DD` read as local
/// time (UTC where the platform has no local zone).
fn parse_local_time(raw: &str) -> Option<i64> {
    let (date, time) = match raw.split_once([' ', 'T']) {
        Some((date, time)) => (date, Some(time.trim())),
        None => (raw, None),
    };
    let mut date_parts = date.split('-');
    let year: i32 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || date.len() != 10 {
        return None;
    }
    let (mut hour, mut minute, mut second) = (0u32, 0u32, 0u32);
    if let Some(time) = time {
        let mut parts = time.split(':');
        hour = parts.next()?.parse().ok()?;
        minute = parts.next()?.parse().ok()?;
        if let Some(s) = parts.next() {
            second = s.parse().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
    }
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day > days_in_month {
        return None;
    }
    super::local_time::local_to_unix(year, month, day, hour, minute, second)
}

/// The preview: target time, plan id, what would change by action, the
/// unavailable paths by cause, and a bounded sample of paths (every path in
/// the response with `--verbose`).
///
/// Counts come from the daemon's own tally over the WHOLE plan, never from
/// counting the entries that arrived: the response carries only a subset.
/// `unavailable` is always its own line, never merged into `unchanged`.
fn format_rewind_plan(plan: &RewindPreviewResponse, folder: &str, verbose: bool) -> String {
    let counts = plan.counts.unwrap_or_default();
    let (create, delete, replace, unchanged, unavailable) =
        (counts.create, counts.delete, counts.replace, counts.unchanged, counts.unavailable);

    let mut out = format!("Rewind preview for {folder} (nothing has been changed)\n");
    out.push_str(&format!("  Target time: {}\n", describe_time(plan.target_unix_nanos)));
    out.push_str(&format!("  Plan id: {}\n", hex(&plan.plan_id)));
    out.push_str(&format!(
        "  {create} to create, {delete} to delete, {replace} to replace, \
         {unchanged} unchanged, {unavailable} unavailable\n"
    ));
    if unavailable > 0 {
        out.push_str(&format!("  {}\n", plan.unavailable_message));
    }

    if plan.total_rename_candidate_count == 0 {
        out.push_str("  No renames detected.\n");
    } else {
        out.push_str(&format!(
            "  {} likely rename(s) (matched on identical content; advisory only):\n",
            plan.total_rename_candidate_count
        ));
        for candidate in &plan.rename_candidates {
            out.push_str(&format!("    {} -> {}\n", candidate.from_path, candidate.to_path));
        }
    }

    let listed: Vec<_> =
        plan.entries.iter().filter(|entry| verbose || entry.action != "unchanged").collect();
    let shown = if verbose { listed.len() } else { listed.len().min(SAMPLE_PATHS) };
    if shown > 0 {
        out.push_str("  Paths:\n");
    }
    for entry in &listed[..shown] {
        match entry.unavailable_reason.as_deref() {
            Some(reason) => {
                out.push_str(&format!("    {:<12} {} ({reason})\n", entry.action, entry.path))
            }
            None => out.push_str(&format!("    {:<12} {}\n", entry.action, entry.path)),
        }
    }
    if !verbose {
        let changing = create + delete + replace + unavailable;
        if changing > shown as u64 {
            out.push_str(&format!(
                "    ... and {} more (--verbose lists them all)\n",
                changing - shown as u64
            ));
        }
    } else if plan.listing_truncated {
        // Said out loud rather than letting a partial list read as complete.
        out.push_str(&format!(
            "  Listing shortened to fit: showing {} of {} path(s) and {} of {} rename(s). \
             The counts above still cover every path.\n",
            plan.entries.len(),
            plan.total_entry_count,
            plan.rename_candidates.len(),
            plan.total_rename_candidate_count,
        ));
    }
    if !verbose
        && plan.listing_truncated
        && (plan.rename_candidates.len() as u64) < plan.total_rename_candidate_count
    {
        out.push_str(&format!(
            "  Rename list shortened to fit: showing {} of {} rename(s). The counts above \
             still cover every path.\n",
            plan.rename_candidates.len(),
            plan.total_rename_candidate_count,
        ));
    }
    if unavailable == 0 && create + delete + replace > 0 {
        out.push_str(&format!(
            "  To run it: yadorilink rewind {folder} --at {} --execute\n",
            plan.target_unix_nanos
        ));
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests;
