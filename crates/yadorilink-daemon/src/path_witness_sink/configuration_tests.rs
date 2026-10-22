#![cfg(test)]

use super::*;

/// The environment is process-global and these tests set it, so they
/// share one lock rather than racing each other.
static ENV: Mutex<()> = Mutex::new(());

fn with_env(path: Option<&str>, expect: Option<&str>, check: impl FnOnce()) {
    let _guard = ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: serialised by ENV, and nothing else in this process reads
    // these two variables outside this function.
    unsafe {
        match path {
            Some(value) => std::env::set_var(PATH_VAR, value),
            None => std::env::remove_var(PATH_VAR),
        }
        match expect {
            Some(value) => std::env::set_var(EXPECT_VAR, value),
            None => std::env::remove_var(EXPECT_VAR),
        }
    }
    check();
    unsafe {
        std::env::remove_var(PATH_VAR);
        std::env::remove_var(EXPECT_VAR);
    }
}

/// Not measuring is the ordinary case and must stay free.
#[test]
fn a_daemon_asked_to_measure_nothing_starts_normally() {
    with_env(None, None, || assert!(validate().is_ok()));
}

/// The defect this exists for. A typo in the size used to fall back to a
/// floor of one byte, so the daemon started cleanly and would then
/// certify a connection that carried a single direct byte as a
/// successful gigabyte transfer -- fail-open, in the one component whose
/// whole purpose is to refuse what it cannot stand behind.
#[test]
fn a_mistyped_expected_size_stops_the_daemon_rather_than_lowering_the_bar() {
    with_env(Some("/tmp/evidence.json"), Some("1073741824x"), || {
        let error = match validate() {
            Err(error) => error,
            Ok(_) => panic!("a size that is not a number must not be accepted"),
        };
        assert!(error.to_string().contains("not a byte count"), "{error}");
    });
}

/// A floor of zero is satisfied by a connection that carried nothing,
/// which is indistinguishable from not checking at all.
#[test]
fn an_expected_size_of_zero_is_refused() {
    with_env(Some("/tmp/evidence.json"), Some("0"), || {
        assert!(validate().is_err());
    });
}

/// Asking for evidence without saying how much is expected leaves the
/// same hole the fallback did, so it is refused rather than defaulted.
#[test]
fn asking_for_evidence_without_an_expected_size_is_refused() {
    with_env(Some("/tmp/evidence.json"), None, || {
        let error = match validate() {
            Err(error) => error,
            Ok(_) => panic!("a floor is not optional"),
        };
        assert!(error.to_string().contains("no size to hold the run to"), "{error}");
    });
}

/// Almost certainly a typo in the path variable's name, and the daemon
/// would otherwise measure carefully and write the answer nowhere.
#[test]
fn an_expected_size_with_nowhere_to_write_is_refused() {
    with_env(None, Some("1073741824"), || assert!(validate().is_err()));
}

#[test]
fn a_complete_configuration_is_accepted() {
    with_env(Some("/tmp/evidence.json"), Some("1073741824"), || {
        assert!(validate().is_ok());
    });
}
