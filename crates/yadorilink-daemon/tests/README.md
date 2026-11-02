# Daemon integration tests

Every file directly in this directory is its own test target, and so is each of `it/` and
`it_matrix/` (one target per directory, with a module per former target). A target links a complete
copy of the daemon (about 130 MB), so tests are consolidated where it is safe:

- A test file goes into `it/` or `it_matrix/` only if it holds no process-global state of its own and nothing
  in it depends on being the only test in its process: it sets no environment variable, installs
  no process-wide default, failpoint or log capture, raises no resource limit, does not serialize
  on a lock that guards process-shared state, and measures nothing about the process as a whole
  (timing budgets, memory, descriptors, CPU), and none of its assertions is a latency bound (an
  executor-stall detector, a control-message delay) that other tests' load could trip.
- Everything else stays a separate target in this directory.
- A test daemon is built with `yadorilink_daemon::test_support::isolated_daemon_state` (or
  `isolated_daemon_state_in` with the previous daemon's `config_dir()` when the test restarts one),
  never `DaemonState::new`: each daemon gets a state directory of its own, as in production.
  `support::ensure_isolated_config_dir` points the process-wide `YADORILINK_CONFIG_DIR` at a regular
  file, so any test that still reads or writes the shared directory fails at once.
- Sweep intervals are given to each daemon at construction (`isolated_daemon_state_with`), never
  process-wide: the consolidated targets use `support::fast_daemon_state`, whose one-second
  materialization-repair sweep a convergence scenario needs; a test that needs other intervals
  passes its own `StateIntervals`.
- `it_matrix/` holds the long multi-device convergence matrices and nothing else: tests with tight
  waits are in `it/`, so they are not run next to the matrices and starved of CPU.
- A daemon state forms reference cycles with itself, so it is not freed when its test lets go of
  it. `isolated_daemon_state` parks a guard on the test's runtime that breaks them when the runtime
  ends, and `fixture_fd_release.rs` fails if a process's descriptors grow with the number of tests
  it runs. Without that every test left sixty to a hundred descriptors open until the process exited,
  and one process for all the tests exceeded the 16,384 the CI lanes allow.

Run one consolidated module with
`cargo test -p yadorilink-daemon --test it -- <module>::`. The filter is a substring match on the
full test path, so a module name that is the tail of another's (`collision_matrix` and
`taguchi_collision_matrix`) also selects that one when both are in the target; use `--exact` with
the full test name for a single test. A filter that matches nothing makes `cargo test` pass with
zero tests, so check the reported count.

## What the consolidation changed

Measured on one Mac (Apple silicon, `CARGO_INCREMENTAL=0`, `-j 6`); the test names (390 tests in
the consolidated modules, 3 of them ignored) are the same before and after.

| | one target per file | now |
|---|---|---|
| Daemon integration-test executables | 117 | 51: 49 separate files, `it` (59 modules) and `it_matrix` (12) |
| Their total size | 15.15 GB | 6.8 GB |
| Build directory after a full test build | about 18 GB | about 10 GB |
| `--no-run` after a one-line change to the daemon library | 107 s | 62 to 108 s, depending on what else the machine was doing |
| File descriptors at the peak of a consolidated process | about 21,800 (446 tests in one process, before a test's daemons were freed when it ended) | `it` 1,590, `it_matrix` 2,077 |

The link work is what shrank: 117 test executables of about 130 MB each became 51. A rebuild
after a change to the daemon still compiles the library twice (once as a library, once with its
unit tests), about 50 s on that machine, and that is now most of the wall time, so the end-to-end
gain is smaller than the executable count suggests.

