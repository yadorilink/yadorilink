#![cfg(test)]

use super::*;

#[allow(clippy::too_many_arguments)]
fn facts(
    latch_load_failed: bool,
    scope_unknown: bool,
    recovery_blocked: bool,
    latched_unknown: bool,
    group_policy_stale: bool,
    materialization: Result<MaterializationHealth, ()>,
    is_local_full_replica: bool,
    any_other_full_replica_peer_configured: bool,
    peer_confirmed_custody: bool,
    ever_confirmation_swept: bool,
) -> DurabilityFacts {
    DurabilityFacts {
        latch_load_failed,
        scope_unknown,
        recovery_blocked,
        latched_unknown,
        group_policy_stale,
        materialization,
        is_local_full_replica,
        any_other_full_replica_peer_configured,
        peer_confirmed_custody,
        ever_confirmation_swept,
        known_unobtainable_required_content: false,
    }
}

/// A full replica, fully caught up locally, with a peer confirmed and
/// fresh, and at least one sweep round already run -- the base
/// "everything checks out" case other cases tweak one field away from.
fn protected_full_replica_facts() -> DurabilityFacts {
    facts(
        false,
        false,
        false,
        false,
        false,
        Ok(MaterializationHealth::FullyLocal),
        true,
        true,
        true,
        true,
    )
}

/// `Unknown` before any check round has run is "not checked yet"; every other
/// reason for `Unknown` (a latch, stale policy, unreadable materialization) or
/// a check that already ran is not.
#[test]
fn first_check_pending_only_before_the_first_round_with_trustworthy_facts() {
    let mut fresh = protected_full_replica_facts();
    fresh.peer_confirmed_custody = false;
    fresh.ever_confirmation_swept = false;
    assert!(first_check_pending(&fresh));

    let mut swept = fresh.clone();
    swept.ever_confirmation_swept = true;
    assert!(!first_check_pending(&swept), "a round has run: Unknown now stands on its own");

    let mut confirmed = fresh.clone();
    confirmed.peer_confirmed_custody = true;
    assert!(!first_check_pending(&confirmed), "confirmed custody is not pending");

    for distrust in [
        |f: &mut DurabilityFacts| f.latched_unknown = true,
        |f: &mut DurabilityFacts| f.latch_load_failed = true,
        |f: &mut DurabilityFacts| f.scope_unknown = true,
        |f: &mut DurabilityFacts| f.recovery_blocked = true,
        |f: &mut DurabilityFacts| f.group_policy_stale = true,
        |f: &mut DurabilityFacts| f.materialization = Err(()),
    ] {
        let mut f = fresh.clone();
        distrust(&mut f);
        assert!(!first_check_pending(&f), "{f:?} is Unknown for a real reason, not pending");
    }
}

/// Table-driven pin of `classify`'s exact precedence, matched against
/// `DaemonState::group_durability_status`'s real, current
/// implementation at the time this was written -- see this module's
/// own doc comment for why the ordering itself is the safety property
/// being pinned, not just the individual outcomes.
#[test]
fn classify_matches_the_real_precedence() {
    let partial = Ok(MaterializationHealth::Partial);
    let unreadable = Err(());

    // latch_load_failed / scope_unknown / recovery_blocked / latched_unknown
    // each win outright, regardless of every other fact.
    assert_eq!(
        classify(&DurabilityFacts { latch_load_failed: true, ..protected_full_replica_facts() }),
        GroupDurabilityStatus::Unknown
    );
    assert_eq!(
        classify(&DurabilityFacts { scope_unknown: true, ..protected_full_replica_facts() }),
        GroupDurabilityStatus::Unknown
    );
    assert_eq!(
        classify(&DurabilityFacts { recovery_blocked: true, ..protected_full_replica_facts() }),
        GroupDurabilityStatus::Unknown
    );
    assert_eq!(
        classify(&DurabilityFacts { latched_unknown: true, ..protected_full_replica_facts() }),
        GroupDurabilityStatus::Unknown
    );
    // group_policy_stale wins outright too, even with an otherwise
    // fresh, current-generation peer confirmation -- an untrusted
    // authorization snapshot invalidates any confirmation it produced.
    assert_eq!(
        classify(&DurabilityFacts { group_policy_stale: true, ..protected_full_replica_facts() }),
        GroupDurabilityStatus::Unknown
    );
    // Unreadable materialization wins outright too, even with an
    // otherwise-confirmed peer.
    assert_eq!(
        classify(&DurabilityFacts {
            materialization: unreadable,
            ..protected_full_replica_facts()
        }),
        GroupDurabilityStatus::Unknown
    );

    // Fresh peer confirmation is Protected -- the ONLY path (whether it
    // came from a real full replica or a vacuous "group is empty"
    // confirmation is invisible at this layer; both set
    // peer_confirmed_custody the same way).
    assert_eq!(classify(&protected_full_replica_facts()), GroupDurabilityStatus::Protected);

    // Never swept yet (daemon just started, no round has run) must NOT
    // jump to AtRisk even with zero peers configured -- it
    // hasn't been checked, so it might turn out empty or protected.
    assert_eq!(
        classify(&DurabilityFacts {
            peer_confirmed_custody: false,
            any_other_full_replica_peer_configured: false,
            ever_confirmation_swept: false,
            ..protected_full_replica_facts()
        }),
        GroupDurabilityStatus::Unknown
    );

    // Local materialization alone, with NO peer confirmation, NO other
    // full-replica peer configured, but AT LEAST ONE sweep round
    // already run, must NOT be Protected -- local completeness is never
    // peer confirmation. It's AtRisk:
    // structurally no peer can ever confirm it.
    assert_eq!(
        classify(&DurabilityFacts {
            peer_confirmed_custody: false,
            any_other_full_replica_peer_configured: false,
            ever_confirmation_swept: true,
            ..protected_full_replica_facts()
        }),
        GroupDurabilityStatus::AtRisk
    );

    // A peer IS configured but hasn't confirmed yet: Unknown for an
    // On-Demand device (materialization irrelevant to it)...
    assert_eq!(
        classify(&DurabilityFacts {
            peer_confirmed_custody: false,
            is_local_full_replica: false,
            materialization: partial,
            ..protected_full_replica_facts()
        }),
        GroupDurabilityStatus::Unknown
    );
    // ...but Protecting for a full-replica device still catching up
    // locally.
    assert_eq!(
        classify(&DurabilityFacts {
            peer_confirmed_custody: false,
            is_local_full_replica: true,
            materialization: partial,
            ..protected_full_replica_facts()
        }),
        GroupDurabilityStatus::Protecting
    );
    // The SAME still-catching-up-locally facts as just above, but with
    // content POSITIVELY confirmed unobtainable from current membership
    // -- must be AtRisk, not Protecting. This precedence step keeps such
    // a group from sitting in Protecting forever: `Partial` materialization alone cannot tell
    // "still trying, may yet succeed" apart from "genuinely,
    // permanently gone", but `known_unobtainable_required_content`
    // can.
    assert_eq!(
        classify(&DurabilityFacts {
            peer_confirmed_custody: false,
            is_local_full_replica: true,
            materialization: partial,
            known_unobtainable_required_content: true,
            ..protected_full_replica_facts()
        }),
        GroupDurabilityStatus::AtRisk
    );
    // A full-replica device that's ALREADY fully caught up locally but
    // has no fresh peer confirmation is Unknown, not Protected -- local
    // completeness alone never proves group-wide coverage.
    assert_eq!(
        classify(&DurabilityFacts {
            peer_confirmed_custody: false,
            ..protected_full_replica_facts()
        }),
        GroupDurabilityStatus::Unknown
    );
}

/// Acceptance requirement: an On-Demand client (not itself a full
/// replica) whose group has a fresh peer-confirmed full replica must
/// report `Protected` ("Protected") -- durability is a group-wide fact,
/// never gated on THIS device's own local storage mode.
#[test]
fn on_demand_device_with_confirmed_peer_replica_is_protected() {
    let facts = DurabilityFacts {
        latch_load_failed: false,
        scope_unknown: false,
        recovery_blocked: false,
        latched_unknown: false,
        group_policy_stale: false,
        materialization: Ok(MaterializationHealth::Partial),
        is_local_full_replica: false,
        any_other_full_replica_peer_configured: true,
        peer_confirmed_custody: true,
        ever_confirmation_swept: true,
        known_unobtainable_required_content: false,
    };
    assert_eq!(
        classify(&facts),
        GroupDurabilityStatus::Protected,
        "an On-Demand device's own permanently-partial local materialization must never \
         prevent Protected once a peer positively confirms whole-group coverage"
    );
}

/// Acceptance requirement: a relay-reachable peer with no verified
/// custody must never read as `Protected` -- this module has no way to
/// even express "reachable" (no `DurabilityFacts` field for it), so
/// this pins that a peer being configured/reachable is never, on its
/// own, sufficient without `peer_confirmed_custody`.
#[test]
fn configured_peer_without_confirmation_is_not_protected() {
    let facts = DurabilityFacts {
        peer_confirmed_custody: false,
        any_other_full_replica_peer_configured: true,
        ..protected_full_replica_facts()
    };
    assert_ne!(
        classify(&facts),
        GroupDurabilityStatus::Protected,
        "a configured/reachable peer must never substitute for a real custody confirmation"
    );
}

#[test]
fn latch_overrides_classify_regardless_of_facts() {
    let service = DurabilityService::new(HashMap::new(), false, false);
    service.latch_unknown("group-1");
    assert_eq!(
        service.classify("group-1", protected_full_replica_facts()),
        GroupDurabilityStatus::Unknown,
        "a latched group must report Unknown even when every fact looks healthy"
    );
    service.clear_unknown("group-1");
    assert_eq!(
        service.classify("group-1", protected_full_replica_facts()),
        GroupDurabilityStatus::Protected,
        "clearing the latch must let the unlatched derivation decide again"
    );
}
