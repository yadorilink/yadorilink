//! Single-flight execution of the custody proof of one version.
//!
//! Proving a version means reading it into the store (when only its file holds it) and reading
//! every block back. For a multi-GiB version that takes longer than a requester waits, and a
//! requester that gave up asks again. The proof therefore runs on a thread of its own, once per
//! (group, path, version): a request that arrives while it runs waits for it a bounded time and
//! otherwise answers "not held" (the requester asks again later). A proof that finished after
//! its requester stopped waiting is handed to the next request for the version, once. Every
//! other request proves afresh: a result that was delivered is never reused, and a negative
//! result is never kept, because each check of a handoff must read the bytes as they are now.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long a positive proof that nobody has received waits for the retry. The caller re-checks,
/// under the reference guard, that the blocks are still in the store before it relies on it.
const POSITIVE_RESULT_TTL: Duration = Duration::from_secs(300);

/// Proofs running at once. A further request answers "not held" and asks again later: a proof
/// that stalls on a failing disk must not take a thread for every version that is asked about.
const MAX_RUNNING: usize = 4;

/// A proof still running after this long is taken for stalled (its disk read never returns): it
/// no longer counts against [`MAX_RUNNING`] and the next request for its version starts another.
const STALLED_AFTER: Duration = Duration::from_secs(900);

/// How long a request waits for a proof before it answers "not held". Below the time a requester
/// gives a peer, so the answer arrives in time to be read.
pub(super) const DEFAULT_WAIT: Duration = Duration::from_secs(4);

pub(super) enum Verdict {
    Held,
    NotHeld,
    /// The proof is still running; the caller answers "not held" and the requester retries.
    Running,
}

type Key = (String, String, [u8; 32]);

enum State {
    /// `waiters` requests are waiting for the result right now.
    Running {
        waiters: usize,
    },
    Done {
        held: bool,
        at: Instant,
        delivered: bool,
    },
}

struct Flight {
    started: Instant,
    state: Mutex<State>,
    done: Condvar,
}

impl Flight {
    /// Records the result. It counts as delivered when some request is waiting for it: that
    /// request takes it. Otherwise the next request for the version takes it, once.
    fn finish(&self, held: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let delivered = matches!(&*state, State::Running { waiters } if *waiters > 0);
        *state = State::Done { held, at: Instant::now(), delivered };
        self.done.notify_all();
    }
}

pub(super) struct ProofFlights {
    flights: Mutex<HashMap<Key, Arc<Flight>>>,
    wait: Duration,
}

impl ProofFlights {
    pub(super) fn new(wait: Duration) -> Self {
        Self { flights: Mutex::default(), wait }
    }

    /// The verdict of the proof of `key`, starting `work` on its own thread when none is running
    /// or waiting to be taken.
    pub(super) fn run(&self, key: Key, work: impl FnOnce() -> bool + Send + 'static) -> Verdict {
        let (flight, starter) = {
            let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
            // Joins a running proof, takes a finished one nobody has received, drops the rest.
            let mut joined = None;
            flights.retain(|k, flight| {
                let mut state = flight.state.lock().unwrap_or_else(|e| e.into_inner());
                match &mut *state {
                    State::Running { .. } if flight.started.elapsed() > STALLED_AFTER => false,
                    State::Running { waiters } => {
                        if *k == key {
                            *waiters += 1;
                            joined = Some(flight.clone());
                        }
                        true
                    }
                    State::Done { held, at, delivered } => {
                        if *k == key && *held && !*delivered && at.elapsed() < POSITIVE_RESULT_TTL {
                            *delivered = true;
                            joined = Some(flight.clone());
                            return true;
                        }
                        *held && !*delivered && at.elapsed() < POSITIVE_RESULT_TTL
                    }
                }
            });
            match joined {
                Some(flight) => (flight, false),
                None => {
                    let running = flights
                        .values()
                        .filter(|f| {
                            f.started.elapsed() <= STALLED_AFTER
                                && matches!(
                                    &*f.state.lock().unwrap_or_else(|e| e.into_inner()),
                                    State::Running { .. }
                                )
                        })
                        .count();
                    if running >= MAX_RUNNING {
                        return Verdict::Running;
                    }
                    let flight = Arc::new(Flight {
                        started: Instant::now(),
                        state: Mutex::new(State::Running { waiters: 1 }),
                        done: Condvar::new(),
                    });
                    flights.insert(key, flight.clone());
                    (flight, true)
                }
            }
        };
        if starter {
            let job = flight.clone();
            let spawned =
                std::thread::Builder::new().name("custody-proof".into()).spawn(move || {
                    let held = catch_unwind(AssertUnwindSafe(work)).unwrap_or(false);
                    job.finish(held);
                });
            if spawned.is_err() {
                flight.finish(false);
            }
        }
        let deadline = Instant::now() + self.wait;
        let mut state = flight.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match &mut *state {
                State::Done { held, .. } => {
                    return if *held { Verdict::Held } else { Verdict::NotHeld };
                }
                State::Running { waiters } => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        *waiters -= 1;
                        return Verdict::Running;
                    }
                    state = flight
                        .done
                        .wait_timeout(state, remaining)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            }
        }
    }
}
