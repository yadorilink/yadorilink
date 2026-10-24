//! One fetch in flight per path. A second request for a path that is being fetched (an Eager
//! download overlapping an explicit fetch) joins the first and gets its answer, so there is one
//! daemon request, one install and one cancel flag per path, and a cancel always reaches the
//! request that is running.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

struct Flight<T> {
    cancel: AtomicBool,
    answer: Mutex<Option<T>>,
    done: Condvar,
}

pub struct SingleFlight<K, T> {
    flights: Mutex<HashMap<K, Arc<Flight<T>>>>,
}

impl<K, T> Default for SingleFlight<K, T> {
    fn default() -> Self {
        Self { flights: Mutex::new(HashMap::new()) }
    }
}

impl<K: Hash + Eq + Clone, T: Clone> SingleFlight<K, T> {
    /// Runs `work` for `key` unless one is running, in which case its answer is waited for.
    /// `work` gets the flight's cancel flag.
    pub fn run(&self, key: &K, work: impl FnOnce(&AtomicBool) -> T) -> T {
        let (flight, mine) = {
            let mut flights = self.flights.lock().unwrap_or_else(|p| p.into_inner());
            match flights.get(key) {
                Some(flight) => (flight.clone(), false),
                None => {
                    let flight = Arc::new(Flight {
                        cancel: AtomicBool::new(false),
                        answer: Mutex::new(None),
                        done: Condvar::new(),
                    });
                    flights.insert(key.clone(), flight.clone());
                    (flight, true)
                }
            }
        };
        if mine {
            let answer = work(&flight.cancel);
            // Out of the map first: a request that arrives after this starts its own flight.
            self.flights.lock().unwrap_or_else(|p| p.into_inner()).remove(key);
            *flight.answer.lock().unwrap_or_else(|p| p.into_inner()) = Some(answer.clone());
            flight.done.notify_all();
            return answer;
        }
        let mut answer = flight.answer.lock().unwrap_or_else(|p| p.into_inner());
        while answer.is_none() {
            answer = flight.done.wait(answer).unwrap_or_else(|p| p.into_inner());
        }
        answer.clone().expect("the flight answered")
    }

    /// Cancels the flight running for `key`; false when none is.
    pub fn cancel(&self, key: &K) -> bool {
        let flight = self.flights.lock().unwrap_or_else(|p| p.into_inner()).get(key).cloned();
        flight.is_some_and(|flight| {
            flight.cancel.store(true, Ordering::Relaxed);
            true
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// Two requests for one key are one piece of work with one answer, and a cancel reaches it
    /// whichever request started it; the key is free again afterwards.
    #[test]
    fn concurrent_requests_for_a_path_join_one_flight() {
        let flights: Arc<SingleFlight<String, Result<u64, String>>> = Arc::default();
        let runs = Arc::new(AtomicUsize::new(0));
        let started = Arc::new((Mutex::new(false), Condvar::new()));
        let first = {
            let (flights, runs, started) = (flights.clone(), runs.clone(), started.clone());
            std::thread::spawn(move || {
                flights.run(&"p".to_string(), |cancel| {
                    runs.fetch_add(1, Ordering::SeqCst);
                    *started.0.lock().unwrap() = true;
                    started.1.notify_all();
                    while !cancel.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err("cancelled".to_string())
                })
            })
        };
        let mut up = started.0.lock().unwrap();
        while !*up {
            up = started.1.wait(up).unwrap();
        }
        drop(up);
        let second = {
            let (flights, runs) = (flights.clone(), runs.clone());
            std::thread::spawn(move || {
                flights.run(&"p".to_string(), |_| {
                    runs.fetch_add(1, Ordering::SeqCst);
                    Ok(1)
                })
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(flights.cancel(&"p".to_string()), "the running flight is reachable by cancel");
        assert_eq!(first.join().unwrap(), Err("cancelled".to_string()));
        assert_eq!(second.join().unwrap(), Err("cancelled".to_string()), "the joiner shares it");
        assert_eq!(runs.load(Ordering::SeqCst), 1, "one piece of work");
        assert!(!flights.cancel(&"p".to_string()), "nothing left to cancel");
        assert_eq!(flights.run(&"p".to_string(), |_| Ok(7)), Ok(7), "the key is free again");
    }
}
