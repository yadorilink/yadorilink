#![cfg(test)]

use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;

use yadorilink_ipc_proto::daemonctl::{
    RewindActionCounts as WireRewindActionCounts, RewindPathEntry as WireRewindPathEntry,
    RewindRefused, RewindRenameCandidate as WireRewindRenameCandidate,
};
use yadorilink_replica_domain::rewind::{
    RewindFailureKind as Kind, RewindPlanId, RewindRun as DomainRun, RewindRunState as DomainState,
    RewindUnavailable, RewindUnavailableReason,
};

fn entry(path: &str, action: &str, reason: Option<&str>) -> WireRewindPathEntry {
    WireRewindPathEntry {
        path: path.to_string(),
        action: action.to_string(),
        to_version_seq: None,
        from_version_seq: None,
        unavailable_reason: reason.map(str::to_string),
    }
}

/// The verbose-mode shape: every path listed, and the counts (which
/// the daemon always computes over the whole plan) agreeing with them.
fn sample_plan() -> RewindPreviewResponse {
    RewindPreviewResponse {
        group_id: "g".to_string(),
        target_unix_nanos: 1_750_000_000_000_000_000,
        entries: vec![
            entry("a.txt", "create", None),
            entry("b.txt", "delete", None),
            entry("c.txt", "replace", None),
            entry("d.txt", "unchanged", None),
            entry("e.txt", "unavailable", Some("expired by retention")),
        ],
        rename_candidates: vec![WireRewindRenameCandidate {
            from_path: "b.txt".to_string(),
            to_path: "a.txt".to_string(),
        }],
        counts: Some(WireRewindActionCounts {
            create: 1,
            delete: 1,
            replace: 1,
            unchanged: 1,
            unavailable: 1,
        }),
        total_entry_count: 5,
        total_rename_candidate_count: 1,
        listing_truncated: false,
        plan_id: vec![7u8; 32],
        unavailable_message: String::new(),
    }
}

const T: i64 = 1_750_000_000_000_000_000;
const PLAN_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn actionable_plan() -> RewindPreviewResponse {
    let mut plan = sample_plan();
    plan.entries.retain(|e| e.action != "unavailable" && e.action != "unchanged");
    plan.counts = Some(WireRewindActionCounts {
        create: 1,
        delete: 1,
        replace: 1,
        unchanged: 4,
        unavailable: 0,
    });
    plan
}

fn unavailable_plan() -> RewindPreviewResponse {
    let mut plan = sample_plan();
    plan.unavailable_message = RewindUnavailable {
        by_reason: vec![
            (RewindUnavailableReason::JoinedAfter, 2),
            (RewindUnavailableReason::RemovedByRetention, 1),
        ],
    }
    .message();
    plan.counts = Some(WireRewindActionCounts {
        create: 1,
        delete: 0,
        replace: 0,
        unchanged: 0,
        unavailable: 3,
    });
    plan
}

/// A run as the daemon reports it, with the text from the one place that
/// words it.
fn run(
    state: DomainState,
    kind: Option<Kind>,
    chunks: (u64, u64),
    unavailable_files: u64,
    offline: &[&str],
) -> RewindRun {
    let domain = DomainRun {
        run_id: "run-1".into(),
        group_id: "g".into(),
        target_unix_nanos: T,
        plan_id: RewindPlanId([7; 32]),
        state,
        chunks_done: chunks.0,
        unavailable_files,
        failure_kind: kind,
        offline_devices: offline.iter().map(|d| d.to_string()).collect(),
        chunks_total: chunks.1,
        restored: 2,
        deleted: 1,
        created_at_unix_nanos: 0,
    };
    RewindRun {
        run_id: "run-1".into(),
        group_id: "g".into(),
        target_unix_nanos: T,
        plan_id: vec![7; 32],
        state: match state {
            DomainState::Planned => RewindRunState::Planned,
            DomainState::Prefetched => RewindRunState::Prefetched,
            DomainState::Committing => RewindRunState::Committing,
            DomainState::Done => RewindRunState::Done,
            DomainState::NeedsReplan => RewindRunState::NeedsReplan,
            DomainState::Failed => RewindRunState::Failed,
        } as i32,
        chunks_total: chunks.1,
        chunks_done: chunks.0,
        restored: 2,
        deleted: 1,
        unavailable_files,
        failure_kind: match kind {
            None => RewindFailureKind::Unspecified,
            Some(Kind::ContentUnavailable) => RewindFailureKind::ContentUnavailable,
            Some(Kind::Transient) => RewindFailureKind::Transient,
            Some(Kind::FolderChanged) => RewindFailureKind::FolderChanged,
            Some(Kind::CommitRefused) => RewindFailureKind::CommitRefused,
            Some(Kind::Interrupted) => RewindFailureKind::Interrupted,
        } as i32,
        offline_devices: offline.iter().map(|d| d.to_string()).collect(),
        message: domain.message(),
    }
}

struct Fake {
    preview: RewindPreviewResponse,
    start: RewindStart,
    statuses: RefCell<VecDeque<Option<RewindRun>>>,
    previews: RefCell<Vec<(i64, bool)>>,
    executed: RefCell<Vec<(i64, Vec<u8>)>>,
}

impl Fake {
    fn new(preview: RewindPreviewResponse) -> Self {
        Fake {
            preview,
            start: RewindStart::Started { run_id: "run-1".into() },
            statuses: RefCell::new(VecDeque::new()),
            previews: RefCell::new(Vec::new()),
            executed: RefCell::new(Vec::new()),
        }
    }

    fn with_runs(self, runs: Vec<RewindRun>) -> Self {
        *self.statuses.borrow_mut() = runs.into_iter().map(Some).collect();
        self
    }
}

impl RewindDaemon for Fake {
    async fn preview(
        &self,
        at: i64,
        include_unchanged: bool,
    ) -> Result<RewindPreviewResponse, CliError> {
        self.previews.borrow_mut().push((at, include_unchanged));
        Ok(self.preview.clone())
    }

    async fn execute(&self, target: i64, plan_id: Vec<u8>) -> Result<RewindStart, CliError> {
        self.executed.borrow_mut().push((target, plan_id));
        Ok(self.start.clone())
    }

    async fn status(&self) -> Result<Option<RewindRun>, CliError> {
        let mut statuses = self.statuses.borrow_mut();
        // The last answer stands once the script runs out.
        Ok(if statuses.len() > 1 {
            statuses.pop_front().unwrap()
        } else {
            statuses.front().cloned().flatten()
        })
    }
}

fn args(execute: bool, plan: Option<&str>, yes: bool) -> RewindArgs {
    RewindArgs {
        folder: "~/Documents".into(),
        at: T.to_string(),
        verbose: false,
        execute,
        plan: plan.map(str::to_string),
        yes,
    }
}

/// Runs the flow; returns what it printed and how it ended.
fn drive(
    fake: &Fake,
    args: &RewindArgs,
    answer: &str,
    interactive: bool,
) -> (String, Result<(), CliError>) {
    let mut out = Vec::new();
    let mut input = answer.as_bytes();
    let result = {
        let mut io =
            Io { out: &mut out, input: &mut input, interactive, poll_interval: Duration::ZERO };
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        runtime.block_on(run_flow(fake, &mut io, args, T + 1_000_000_000))
    };
    (String::from_utf8(out).unwrap(), result)
}

fn exit_of(result: Result<(), CliError>) -> (i32, String) {
    let error = result.expect_err("the flow should fail");
    (error.exit_code(), error.to_string())
}

fn time_line() -> String {
    format!("  Target time: {}\n", describe_time(T))
}

#[test]
fn preview_prints_target_plan_counts_and_a_path_sample() {
    let fake = Fake::new(actionable_plan());
    let (out, result) = drive(&fake, &args(false, None, false), "", false);
    result.unwrap();
    let expected = format!(
        "Rewind preview for ~/Documents (nothing has been changed)\n\
         {}  Plan id: {PLAN_HEX}\n\
         \x20 1 to create, 1 to delete, 1 to replace, 4 unchanged, 0 unavailable\n\
         \x20 1 likely rename(s) (matched on identical content; advisory only):\n\
         \x20   b.txt -> a.txt\n\
         \x20 Paths:\n\
         \x20   create       a.txt\n\
         \x20   delete       b.txt\n\
         \x20   replace      c.txt\n\
         \x20 To run it: yadorilink rewind ~/Documents --at {T} --execute\n",
        time_line()
    );
    assert_eq!(out, expected.trim_end().to_string() + "\n");
    assert!(fake.executed.borrow().is_empty(), "a preview never executes");
    assert_eq!(*fake.previews.borrow(), vec![(T, false)]);
}

#[test]
fn the_path_sample_is_bounded_and_says_how_many_more() {
    let mut plan = actionable_plan();
    plan.entries = (0..25).map(|i| entry(&format!("f{i:02}.txt"), "create", None)).collect();
    plan.counts = Some(WireRewindActionCounts { create: 25, ..Default::default() });
    let rendered = format_rewind_plan(&plan, "~/Documents", false);
    assert!(rendered.contains("f09.txt") && !rendered.contains("f10.txt"), "{rendered}");
    assert!(rendered.contains("... and 15 more (--verbose lists them all)"), "{rendered}");
    let verbose = format_rewind_plan(&plan, "~/Documents", true);
    assert!(verbose.contains("f24.txt") && !verbose.contains("more ("), "{verbose}");
}

#[test]
fn verbose_asks_for_and_lists_the_unchanged_paths_too() {
    let fake = Fake::new(sample_plan());
    let mut verbose = args(false, None, false);
    verbose.verbose = true;
    let (out, result) = drive(&fake, &verbose, "", false);
    result.unwrap();
    assert!(out.contains("unchanged    d.txt"), "{out}");
    assert_eq!(*fake.previews.borrow(), vec![(T, true)]);
}

#[test]
fn unavailable_paths_are_grouped_by_cause_and_called_out_apart_from_unchanged() {
    let fake = Fake::new(unavailable_plan());
    let (out, result) = drive(&fake, &args(false, None, false), "", false);
    result.unwrap();
    assert!(out.contains("0 unchanged, 3 unavailable"), "{out}");
    assert!(
        out.contains(
            "  3 files unavailable; rewind cannot start: 2 because this device joined after \
             that time; run the rewind from a device that has the history (e.g. your NAS); \
             1 because older versions were removed by retention\n"
        ),
        "{out}"
    );
    assert!(!out.contains("To run it"), "an unrunnable plan offers no command: {out}");
}

#[test]
fn an_unavailable_preview_with_execute_stops_before_asking_and_exits_12() {
    let fake = Fake::new(unavailable_plan());
    let (out, result) = drive(&fake, &args(true, None, false), "y\n", true);
    let (code, message) = exit_of(result);
    assert_eq!(code, 12);
    assert_eq!(message, unavailable_plan().unavailable_message);
    assert!(!out.contains("[y/N]"), "{out}");
    assert!(fake.executed.borrow().is_empty());
}

#[test]
fn execute_confirms_with_the_counts_then_runs_the_previewed_plan_and_reports_progress() {
    let fake = Fake::new(actionable_plan()).with_runs(vec![
        run(DomainState::Planned, None, (0, 0), 0, &[]),
        run(DomainState::Committing, None, (1, 3), 0, &[]),
        run(DomainState::Committing, None, (1, 3), 0, &[]),
        run(DomainState::Done, None, (3, 3), 0, &[]),
    ]);
    let (out, result) = drive(&fake, &args(true, None, false), "y\n", true);
    result.unwrap();
    let tail = out.split("To run it: yadorilink rewind ~/Documents --at ").nth(1).unwrap();
    assert_eq!(
        tail,
        format!(
            "{T} --execute\n\
             This rewinds ~/Documents: 1 files will be created, 1 replaced and 1 deleted, as \
             ordinary changes that sync to your other devices. Continue? [y/N] \
             Rewind started.\n\
             Gathering the content this rewind needs.\n\
             Rewinding: 1 of 3 steps done.\n\
             Rewind finished: 2 files restored, 1 files removed.\n"
        )
    );
    assert_eq!(*fake.executed.borrow(), vec![(T, vec![7u8; 32])]);
}

#[test]
fn declining_the_confirmation_changes_nothing_and_executes_nothing() {
    for answer in ["n\n", "\n", ""] {
        let fake = Fake::new(actionable_plan());
        let (_, result) = drive(&fake, &args(true, None, false), answer, true);
        let (code, message) = exit_of(result);
        assert_eq!((code, message.as_str()), (17, "Cancelled; nothing was changed."));
        assert!(fake.executed.borrow().is_empty());
    }
}

#[test]
fn without_a_terminal_and_without_yes_it_refuses_rather_than_hang() {
    let fake = Fake::new(actionable_plan());
    let (_, result) = drive(&fake, &args(true, None, false), "y\n", false);
    let (code, message) = exit_of(result);
    assert_eq!(code, 18);
    assert!(message.contains("--yes together with --plan"), "{message}");
    assert!(fake.executed.borrow().is_empty());
}

#[test]
fn yes_with_a_plan_runs_that_plan_without_previewing_or_asking() {
    let fake =
        Fake::new(actionable_plan()).with_runs(vec![run(DomainState::Done, None, (3, 3), 0, &[])]);
    let (out, result) = drive(&fake, &args(true, Some(PLAN_HEX), true), "", false);
    result.unwrap();
    assert_eq!(
        out,
        format!(
            "Rewinding ~/Documents to {} (plan {PLAN_HEX})\n\
             Rewind started.\n\
             Rewind finished: 2 files restored, 1 files removed.\n",
            describe_time(T)
        )
    );
    assert!(fake.previews.borrow().is_empty());
    assert_eq!(*fake.executed.borrow(), vec![(T, vec![7u8; 32])]);
}

#[test]
fn a_plan_needs_the_exact_target_not_a_relative_time() {
    let fake = Fake::new(actionable_plan());
    let mut relative = args(true, Some(PLAN_HEX), true);
    relative.at = "2h".into();
    let (_, result) = drive(&fake, &relative, "", false);
    let (code, message) = exit_of(result);
    assert_eq!(code, 1);
    assert!(message.contains("exact --at"), "{message}");
}

#[test]
fn a_malformed_plan_id_is_refused_before_anything_is_asked_of_the_daemon() {
    for bad in ["", "abc", &"zz".repeat(32), &"07".repeat(31)] {
        let fake = Fake::new(actionable_plan());
        let (_, result) = drive(&fake, &args(true, Some(bad), true), "", false);
        assert!(exit_of(result).1.contains("--plan"), "{bad:?}");
        assert!(fake.previews.borrow().is_empty() && fake.executed.borrow().is_empty());
    }
}

#[test]
fn a_stale_plan_prints_the_shared_wording_and_exits_11() {
    let mut fake = Fake::new(actionable_plan());
    fake.start = RewindStart::PlanStale {
        message: "the folder changed since the rewind preview; preview again".into(),
        current_plan_id: vec![9; 32],
        current_counts: WireRewindActionCounts::default(),
    };
    let (_, result) = drive(&fake, &args(true, Some(PLAN_HEX), true), "", false);
    assert_eq!(
        exit_of(result),
        (11, "the folder changed since the rewind preview; preview again".to_string())
    );
}

#[test]
fn refusals_keep_the_daemons_words_and_map_to_distinct_exit_codes() {
    let cases = [
        (RewindRefusalReason::UnavailablePaths, 12),
        (RewindRefusalReason::FolderSettling, 14),
        (RewindRefusalReason::RunActive, 16),
        (RewindRefusalReason::NotAuthorized, 16),
        (RewindRefusalReason::GroupFrozen, 16),
        (RewindRefusalReason::UnknownGroup, 16),
        (RewindRefusalReason::InsufficientSpace, 16),
    ];
    for (reason, code) in cases {
        let mut fake = Fake::new(actionable_plan());
        fake.start = RewindStart::Refused(RewindRefused {
            reason: reason as i32,
            count: 0,
            message: format!("daemon says {reason:?}"),
        });
        let (_, result) = drive(&fake, &args(true, Some(PLAN_HEX), true), "", false);
        assert_eq!(exit_of(result), (code, format!("daemon says {reason:?}")), "{reason:?}");
    }
}

#[test]
fn every_way_a_run_can_end_prints_the_shared_wording_and_has_its_own_exit_code() {
    let cases = [
        (
            run(DomainState::Failed, Some(Kind::ContentUnavailable), (0, 0), 4, &[]),
            12,
            "4 files unavailable; rewind cannot start",
        ),
        (
            run(DomainState::Failed, Some(Kind::Transient), (0, 0), 0, &[]),
            13,
            "Rewind could not be prepared; retry when the required devices are available.",
        ),
        (
            run(DomainState::Failed, Some(Kind::Transient), (0, 0), 0, &["nas"]),
            13,
            "Rewind could not be prepared: nas is offline. Retry when it is available.",
        ),
        (
            run(DomainState::Failed, Some(Kind::FolderChanged), (0, 0), 0, &[]),
            14,
            "The folder changed; wait for sync to settle, then preview again.",
        ),
        (
            run(DomainState::NeedsReplan, None, (1, 3), 0, &[]),
            15,
            "Rewind was interrupted. Review the current state and preview again.",
        ),
        (
            run(DomainState::Failed, Some(Kind::CommitRefused), (0, 0), 0, &[]),
            16,
            "This folder cannot be changed from this device right now; resolve that, then \
             preview again.",
        ),
        (
            run(DomainState::Failed, Some(Kind::Interrupted), (0, 0), 0, &[]),
            16,
            "Rewind was interrupted before anything changed; you can run it again.",
        ),
    ];
    for (ended, code, wording) in cases {
        let fake = Fake::new(actionable_plan()).with_runs(vec![ended]);
        let (out, result) = drive(&fake, &args(true, Some(PLAN_HEX), true), "", false);
        assert_eq!(exit_of(result), (code, wording.to_string()), "{wording}");
        assert!(out.ends_with(&format!("{wording}\n")), "progress shows the same words: {out}");
    }
}

#[test]
fn the_rewind_exit_codes_are_distinct_and_clear_of_the_existing_ones() {
    let codes = [
        RewindExit::PlanStale,
        RewindExit::Unavailable,
        RewindExit::Transient,
        RewindExit::FolderChanged,
        RewindExit::NeedsReplan,
        RewindExit::NotStarted,
        RewindExit::Declined,
        RewindExit::NotConfirmable,
    ]
    .map(RewindExit::code);
    assert_eq!(codes, [11, 12, 13, 14, 15, 16, 17, 18]);
}

#[test]
fn a_run_that_is_not_the_one_started_is_not_reported_as_its_result() {
    let mut other = run(DomainState::Done, None, (3, 3), 0, &[]);
    other.run_id = "someone-else".into();
    let fake = Fake::new(actionable_plan()).with_runs(vec![other]);
    let (_, result) = drive(&fake, &args(true, Some(PLAN_HEX), true), "", false);
    assert_eq!(exit_of(result).0, 1);
}

#[test]
fn status_shows_the_latest_run_or_says_there_is_none() {
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let mut out = Vec::new();
    let none = Fake::new(actionable_plan());
    runtime.block_on(status_flow(&none, &mut out, "~/Documents")).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "No rewind has been run for ~/Documents.\n");

    let mut out = Vec::new();
    let some = Fake::new(actionable_plan()).with_runs(vec![run(
        DomainState::NeedsReplan,
        None,
        (1, 3),
        0,
        &[],
    )]);
    runtime.block_on(status_flow(&some, &mut out, "~/Documents")).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!(
            "Latest rewind of ~/Documents\n\
             {}  Plan id: {PLAN_HEX}\n\
             \x20 Rewind was interrupted. Review the current state and preview again.\n",
            time_line()
        )
    );
}

#[test]
fn at_accepts_unix_nanos_and_offsets_back_from_now() {
    let now = 10_000_000_000_000_000i64;
    assert_eq!(parse_at("1750000000000000000", i64::MAX).unwrap().nanos, T);
    assert!(!parse_at("1750000000000000000", i64::MAX).unwrap().relative);
    let two_hours = parse_at("2h", now).unwrap();
    assert_eq!((two_hours.nanos, two_hours.relative), (now - 7_200_000_000_000, true));
    assert_eq!(parse_at("2s", now).unwrap().nanos, now - 2_000_000_000);
    assert_eq!(parse_at("3m", now).unwrap().nanos, now - 180_000_000_000);
    assert_eq!(parse_at(" 1d ", now).unwrap().nanos, now - 86_400_000_000_000);
}

#[test]
fn at_accepts_an_absolute_local_time() {
    let now = T * 2;
    for (raw, shown) in [
        ("2026-01-02 03:04", "2026-01-02 03:04:00"),
        ("2026-01-02 03:04:05", "2026-01-02 03:04:05"),
        ("2026-01-02T03:04:05", "2026-01-02 03:04:05"),
        ("2026-01-02", "2026-01-02 00:00:00"),
    ] {
        let at = parse_at(raw, now).unwrap_or_else(|e| panic!("{raw}: {e}"));
        assert!(!at.relative);
        assert_eq!(super::super::status::format_local_time(at.nanos / 1_000_000_000), shown);
    }
}

#[test]
fn at_rejects_anything_it_cannot_read_exactly() {
    for raw in [
        "yesterday",
        "2w",
        "",
        "h",
        "-",
        "2026-13-01",
        "2026-01-32",
        "2026-01-02 25:00",
        "2026-1-2",
        "2026-01-02 03",
    ] {
        assert!(parse_at(raw, T).is_err(), "{raw:?} should not parse");
    }
}

/// A target before the epoch or after now is never what someone meant: the
/// first reads every path as a delete, the second today's state as "unchanged".
#[test]
fn at_rejects_a_target_before_the_epoch_or_in_the_future() {
    let now = 10_000_000_000_000i64;
    for raw in ["-1", "-5s", "-3m", "-2h", "-7d", "10000000000001", "2999-01-01"] {
        assert!(parse_at(raw, now).is_err(), "{raw:?} should not parse");
    }
}

#[test]
fn a_plan_that_is_not_the_previewed_one_is_refused_before_asking() {
    let fake = Fake::new(actionable_plan());
    let other = "09".repeat(32);
    let (out, result) = drive(&fake, &args(true, Some(&other), false), "y\n", true);
    assert_eq!(
        exit_of(result),
        (11, "the folder changed since the rewind preview; preview again".to_string())
    );
    assert!(!out.contains("[y/N]"), "{out}");
    assert!(fake.executed.borrow().is_empty());
}

#[test]
fn the_matching_plan_may_be_confirmed_interactively() {
    let fake =
        Fake::new(actionable_plan()).with_runs(vec![run(DomainState::Done, None, (3, 3), 0, &[])]);
    let (_, result) = drive(&fake, &args(true, Some(PLAN_HEX), false), "y\n", true);
    result.unwrap();
    assert_eq!(*fake.executed.borrow(), vec![(T, vec![7u8; 32])]);
}

#[test]
fn an_unknown_run_state_ends_the_wait_with_an_error() {
    let mut odd = run(DomainState::Done, None, (3, 3), 0, &[]);
    odd.state = RewindRunState::Unspecified as i32;
    let fake = Fake::new(actionable_plan()).with_runs(vec![odd]);
    let (_, result) = drive(&fake, &args(true, Some(PLAN_HEX), true), "", false);
    assert_eq!(exit_of(result).0, 1);
}
