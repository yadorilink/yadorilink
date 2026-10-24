use super::*;

const TERM: Duration = Duration::from_secs(30);

fn clock() -> Arc<FakeLeaseClock> {
    FakeLeaseClock::new(1_000_000)
}

#[test]
fn a_second_writer_fails_closed_while_the_term_runs() {
    let dir = tempfile::tempdir().unwrap();
    let clock = clock();
    let first = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap();
    clock.advance(TERM - Duration::from_millis(1));
    let err = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap_err();
    assert!(matches!(err, RootAuthorityError::WriterLeaseHeld(_)), "{err}");
    assert!(err.to_string().contains("already in use"));
    first.verify().unwrap();
}

#[test]
fn an_expired_lease_is_taken_over_with_a_higher_fence_and_the_old_writer_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let clock = clock();
    let old = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap();
    assert_eq!(old.generation(), 1);
    clock.advance(TERM);
    let new = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap();
    assert_eq!(new.generation(), 2);

    assert!(matches!(old.verify(), Err(RootAuthorityError::StaleWriter(_))));
    assert!(matches!(old.renew(), Err(RootAuthorityError::StaleWriter(_))));
    new.verify().unwrap();
}

#[test]
fn renew_extends_the_term_and_blocks_takeover() {
    let dir = tempfile::tempdir().unwrap();
    let clock = clock();
    let lease = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap();
    clock.advance(TERM - Duration::from_millis(1));
    lease.renew().unwrap();
    clock.advance(TERM - Duration::from_millis(1));
    assert!(WriterLease::acquire(dir.path(), TERM, clock.clone()).is_err());
    lease.verify().unwrap();
}

#[test]
fn verify_refuses_a_writer_whose_term_ran_out_even_if_nobody_took_over() {
    let dir = tempfile::tempdir().unwrap();
    let clock = clock();
    let lease = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap();
    clock.advance(TERM);
    assert!(matches!(lease.verify(), Err(RootAuthorityError::StaleWriter(_))));
    // Nobody took over, so renewing is still allowed and restores the fence.
    lease.renew().unwrap();
    lease.verify().unwrap();
}

#[test]
fn release_frees_the_area_at_once_and_never_reuses_a_generation() {
    let dir = tempfile::tempdir().unwrap();
    let clock = clock();
    let first = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap();
    first.release();
    let state = read_state(dir.path()).unwrap().unwrap();
    assert_eq!(state.holder, None);
    let second = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap();
    assert_eq!(second.generation(), 2);
}

#[test]
fn a_stale_writers_drop_does_not_release_the_new_holders_lease() {
    let dir = tempfile::tempdir().unwrap();
    let clock = clock();
    let old = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap();
    clock.advance(TERM);
    let new = WriterLease::acquire(dir.path(), TERM, clock.clone()).unwrap();
    drop(old);
    new.verify().unwrap();
    assert!(WriterLease::acquire(dir.path(), TERM, clock.clone()).is_err());
}

#[test]
fn readers_observe_the_record_without_a_lease() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read_state(dir.path()).unwrap(), None);
    let clock = clock();
    let lease = WriterLease::acquire(dir.path(), TERM, clock).unwrap();
    for _ in 0..3 {
        let state = read_state(dir.path()).unwrap().unwrap();
        assert_eq!(state.generation, lease.generation());
        assert!(state.holder.is_some());
    }
    lease.verify().unwrap();
}

#[test]
fn a_corrupt_record_fails_closed_and_is_not_reset() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(RECORD_FILE), b"{not json").unwrap();
    let err = WriterLease::acquire(dir.path(), TERM, clock()).unwrap_err();
    assert!(matches!(err, RootAuthorityError::CorruptState(_)), "{err}");
    assert_eq!(std::fs::read(dir.path().join(RECORD_FILE)).unwrap(), b"{not json");
}
