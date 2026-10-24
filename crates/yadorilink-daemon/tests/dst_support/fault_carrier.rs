//! The join between a `Case`'s network faults and the simulated carrier that
//! can actually enforce them.
//!
//! A `Case` names devices by index, because it is a serialized artefact that
//! outlives any particular run and must not hold anything as run-specific as
//! an endpoint identity. The carrier names them by `EndpointId`, because that
//! is what a datagram is addressed to. This module is the table between the
//! two and nothing else: it decides no policy, holds no state of its own, and
//! translates one fault at a time.
//!
//! Kept separate from the carrier deliberately. If a scenario partitions two
//! devices and their blocks flow anyway, the question is whether the mapping
//! was wrong or the carrier was, and those are only separable while they are
//! separate pieces.
//!
//! `Partition`, `Heal`, the one-way cut, duplication and the inbound hold
//! (reordering and delay) are carried across. The unparameterised `Drop`,
//! `Delay`, `Reorder` and `Duplicate` of the decision engine name no link, so
//! they are reported as unimplemented rather than quietly ignored -- see
//! [`CarrierOutcome`].
//!
//! `#[cfg(turmoil)]`: the carrier is a `test-support` type of
//! `yadorilink-lane-ports`, and only the turmoil build is meant to reach it.

#![cfg(turmoil)]
#![allow(dead_code)] // the schedule runtime does not drive this yet

use iroh::EndpointId;
use yadorilink_lane_ports::sim_fault::{HoldPolicy, SimFaultController};

use super::case_ir::{Fault, NetFault, SimNanos};

/// What became of one `Case` fault handed to the carrier.
///
/// An enum rather than `Result<(), E>` because three of these are ordinary
/// outcomes a scenario should record and continue past, and only one is a
/// mistake. Collapsing them would make the mistake invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierOutcome {
    /// The carrier's state changed to match the fault.
    Applied,
    /// A network fault this carrier cannot express yet (`Drop`, `Delay`,
    /// `Reorder`, `Duplicate`). Named so a scenario's coverage report can
    /// say what it did not actually exercise, rather than counting an entry
    /// it silently skipped.
    Unimplemented(&'static str),
    /// Not a network fault. Disk, SQLite, clock and lifecycle faults belong
    /// to other injectors; this one has no opinion about them.
    NotNetwork,
    /// The `Case` named a device this run has no endpoint for.
    ///
    /// Always a mistake, never a shrug. A corpus entry generated for a
    /// three-device topology replayed against two devices would otherwise
    /// partition nothing and pass, and the run would report faults it never
    /// injected.
    UnknownDevice(usize),
}

/// Translates a `Case`'s device indices into the endpoints of one run.
#[derive(Debug, Clone)]
pub struct CarrierFaults {
    controller: SimFaultController,
    /// Endpoint per device index, in the order the `Case`'s topology counts
    /// them.
    endpoints: Vec<EndpointId>,
}

impl CarrierFaults {
    /// `endpoints[i]` is the endpoint for the `Case`'s device `i`.
    pub fn new(controller: SimFaultController, endpoints: Vec<EndpointId>) -> Self {
        Self { controller, endpoints }
    }

    pub fn controller(&self) -> &SimFaultController {
        &self.controller
    }

    pub fn device_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Applies one `Case` fault, reporting what it did.
    pub fn apply(&self, fault: &Fault) -> CarrierOutcome {
        let Fault::Net(net) = fault else {
            return CarrierOutcome::NotNetwork;
        };
        match net {
            NetFault::Partition { device_a, device_b } => match self.pair(*device_a, *device_b) {
                Ok((a, b)) => {
                    self.controller.partition(a, b);
                    CarrierOutcome::Applied
                }
                Err(missing) => CarrierOutcome::UnknownDevice(missing),
            },
            NetFault::Heal { device_a, device_b } => match self.pair(*device_a, *device_b) {
                Ok((a, b)) => {
                    self.controller.heal(a, b);
                    CarrierOutcome::Applied
                }
                Err(missing) => CarrierOutcome::UnknownDevice(missing),
            },
            NetFault::PartitionOneWay { from, to } => match self.pair(*from, *to) {
                Ok((a, b)) => {
                    self.controller.partition_one_way(a, b);
                    CarrierOutcome::Applied
                }
                Err(missing) => CarrierOutcome::UnknownDevice(missing),
            },
            NetFault::HealOneWay { from, to } => match self.pair(*from, *to) {
                Ok((a, b)) => {
                    self.controller.heal_one_way(a, b);
                    CarrierOutcome::Applied
                }
                Err(missing) => CarrierOutcome::UnknownDevice(missing),
            },
            NetFault::DuplicateDatagrams { from, to, every_nth, seed } => {
                match self.pair(*from, *to) {
                    Ok((a, b)) if *every_nth > 0 => {
                        self.controller.duplicate_datagrams(a, b, *every_nth, *seed);
                        CarrierOutcome::Applied
                    }
                    Ok(_) => CarrierOutcome::Unimplemented("DuplicateDatagrams with period 0"),
                    Err(missing) => CarrierOutcome::UnknownDevice(missing),
                }
            }
            NetFault::StopDuplicating { from, to } => match self.pair(*from, *to) {
                Ok((a, b)) => {
                    self.controller.stop_duplicating(a, b);
                    CarrierOutcome::Applied
                }
                Err(missing) => CarrierOutcome::UnknownDevice(missing),
            },
            NetFault::HoldInbound { device, every_nth, release_after, seed } => {
                match self.endpoints.get(*device) {
                    Some(at) if *every_nth > 0 && *release_after > 0 => {
                        self.controller.hold_inbound(
                            *at,
                            HoldPolicy {
                                every_nth: *every_nth,
                                release_after: *release_after,
                                seed: *seed,
                            },
                        );
                        CarrierOutcome::Applied
                    }
                    Some(_) => CarrierOutcome::Unimplemented("HoldInbound with a zero parameter"),
                    None => CarrierOutcome::UnknownDevice(*device),
                }
            }
            NetFault::StopHolding { device } => match self.endpoints.get(*device) {
                Some(at) => {
                    self.controller.stop_holding(*at);
                    CarrierOutcome::Applied
                }
                None => CarrierOutcome::UnknownDevice(*device),
            },
            NetFault::Drop => CarrierOutcome::Unimplemented("Drop"),
            NetFault::Delay { .. } => CarrierOutcome::Unimplemented("Delay"),
            NetFault::Reorder => CarrierOutcome::Unimplemented("Reorder"),
            NetFault::Duplicate => CarrierOutcome::Unimplemented("Duplicate"),
        }
    }

    /// The carrier's evidence per target, keyed by device index, for
    /// crediting scheduled wire faults.
    pub fn wire_evidence(&self) -> super::fault_schedule::WireEvidence {
        let mut evidence = super::fault_schedule::WireEvidence::default();
        for (i, from) in self.endpoints.iter().enumerate() {
            evidence.reordered.insert(i, self.controller.reordered_at(*from));
            for (j, to) in self.endpoints.iter().enumerate().filter(|(j, _)| *j != i) {
                evidence.dropped.insert((i, j), self.controller.dropped_on(*from, *to));
                evidence.duplicated.insert((i, j), self.controller.duplicated_on(*from, *to));
            }
        }
        evidence
    }

    /// Applies a whole schedule's faults in order, returning one outcome per
    /// entry.
    ///
    /// Order only, not timing: when each entry fires is the schedule
    /// runtime's business, and mixing the two here would put a clock in a
    /// lookup table.
    pub fn apply_all(&self, schedule: &[(SimNanos, Fault)]) -> Vec<CarrierOutcome> {
        schedule.iter().map(|(_at, fault)| self.apply(fault)).collect()
    }

    /// The endpoints for a pair of device indices, or the first index that
    /// this run has no endpoint for.
    fn pair(&self, a: usize, b: usize) -> Result<(EndpointId, EndpointId), usize> {
        let first = *self.endpoints.get(a).ok_or(a)?;
        let second = *self.endpoints.get(b).ok_or(b)?;
        Ok((first, second))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn two_devices() -> CarrierFaults {
        CarrierFaults::new(SimFaultController::new(), vec![endpoint(1), endpoint(2)])
    }

    /// The property the whole module exists for: a fault written in a `Case`
    /// reaches the carrier that can enforce it.
    #[test]
    fn a_case_partition_cuts_the_carriers_link_and_a_heal_restores_it() {
        let faults = two_devices();
        let (a, b) = (endpoint(1), endpoint(2));

        assert!(!faults.controller().is_partitioned(a, b), "nothing is cut before the fault");

        assert_eq!(
            faults.apply(&Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 })),
            CarrierOutcome::Applied
        );
        assert!(
            faults.controller().is_partitioned(a, b),
            "a Case's partition did not reach the carrier, so a scenario would report a \
             fault it never injected"
        );

        assert_eq!(
            faults.apply(&Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 })),
            CarrierOutcome::Applied
        );
        assert!(
            !faults.controller().is_partitioned(a, b),
            "a Case's heal did not reach the carrier"
        );
    }

    /// Device indices are the `Case`'s own, and the mapping must respect the
    /// order the topology counts them in rather than any order the carrier
    /// finds convenient.
    #[test]
    fn indices_are_read_in_the_cases_own_order() {
        let faults = CarrierFaults::new(
            SimFaultController::new(),
            vec![endpoint(7), endpoint(8), endpoint(9)],
        );

        faults.apply(&Fault::Net(NetFault::Partition { device_a: 0, device_b: 2 }));

        assert!(faults.controller().is_partitioned(endpoint(7), endpoint(9)));
        assert!(
            !faults.controller().is_partitioned(endpoint(7), endpoint(8)),
            "a partition landed on a link the Case did not name"
        );
    }

    /// A corpus entry generated for a larger topology, replayed against a
    /// smaller one, must say so. Silently partitioning nothing would let the
    /// run pass while reporting faults it never injected -- the exact shape
    /// of failure a deterministic harness exists to rule out.
    #[test]
    fn a_device_this_run_does_not_have_is_reported_not_ignored() {
        let faults = two_devices();

        assert_eq!(
            faults.apply(&Fault::Net(NetFault::Partition { device_a: 0, device_b: 5 })),
            CarrierOutcome::UnknownDevice(5)
        );
        assert_eq!(
            faults.controller().dropped_datagrams(),
            0,
            "a fault naming an unknown device changed the carrier anyway"
        );
    }

    /// The faults this carrier cannot express yet are named, not skipped, so
    /// a coverage report cannot count an entry that did nothing.
    #[test]
    fn unexpressible_net_faults_are_named_rather_than_skipped() {
        let faults = two_devices();

        assert_eq!(
            faults.apply(&Fault::Net(NetFault::Drop)),
            CarrierOutcome::Unimplemented("Drop")
        );
        assert_eq!(
            faults.apply(&Fault::Net(NetFault::Delay { millis: 5 })),
            CarrierOutcome::Unimplemented("Delay")
        );
        assert_eq!(
            faults.apply(&Fault::Net(NetFault::Reorder)),
            CarrierOutcome::Unimplemented("Reorder")
        );
        assert_eq!(
            faults.apply(&Fault::Net(NetFault::Duplicate)),
            CarrierOutcome::Unimplemented("Duplicate")
        );
    }

    /// The wire faults reach the carrier: a one-way cut cuts one direction,
    /// duplication and hold are armed, and each can be lifted again. A zero
    /// period is refused by name, never silently armed.
    #[test]
    fn wire_faults_reach_the_carrier_and_can_be_lifted() {
        let faults = two_devices();
        let (a, b) = (endpoint(1), endpoint(2));
        let apply = |net| faults.apply(&Fault::Net(net));

        assert_eq!(apply(NetFault::PartitionOneWay { from: 0, to: 1 }), CarrierOutcome::Applied);
        assert!(faults.controller().is_cut(a, b) && !faults.controller().is_cut(b, a));
        assert_eq!(apply(NetFault::HealOneWay { from: 0, to: 1 }), CarrierOutcome::Applied);
        assert!(!faults.controller().is_cut(a, b));

        assert_eq!(
            apply(NetFault::DuplicateDatagrams { from: 0, to: 1, every_nth: 1, seed: 0 }),
            CarrierOutcome::Applied
        );
        assert_eq!(
            apply(NetFault::DuplicateDatagrams { from: 0, to: 1, every_nth: 0, seed: 0 }),
            CarrierOutcome::Unimplemented("DuplicateDatagrams with period 0")
        );
        assert_eq!(apply(NetFault::StopDuplicating { from: 0, to: 1 }), CarrierOutcome::Applied);

        assert_eq!(
            apply(NetFault::HoldInbound { device: 1, every_nth: 2, release_after: 1, seed: 0 }),
            CarrierOutcome::Applied
        );
        assert_eq!(apply(NetFault::StopHolding { device: 1 }), CarrierOutcome::Applied);
        assert_eq!(
            apply(NetFault::HoldInbound { device: 9, every_nth: 2, release_after: 1, seed: 0 }),
            CarrierOutcome::UnknownDevice(9)
        );
    }

    /// Faults belonging to other injectors pass through untouched. This one
    /// owning an opinion about disk faults would make two modules responsible
    /// for the same entry.
    #[test]
    fn faults_for_other_injectors_are_left_alone() {
        use super::super::case_ir::DiskFault;

        let faults = two_devices();
        assert_eq!(faults.apply(&Fault::Disk(DiskFault::Enospc)), CarrierOutcome::NotNetwork);
        assert_eq!(
            faults.apply(&Fault::ClockJump { device: 0, to_unix_nanos: 42 }),
            CarrierOutcome::NotNetwork
        );
    }

    /// A schedule's entries arrive in order, and the carrier ends in the
    /// state the last one named -- a partition healed later is healed, not
    /// still cut.
    #[test]
    fn a_schedule_leaves_the_carrier_in_its_final_state() {
        let faults = two_devices();
        let schedule = vec![
            (
                SimNanos::from_nanos(10),
                Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }),
            ),
            (SimNanos::from_nanos(20), Fault::Disk(super::super::case_ir::DiskFault::TornWrite)),
            (SimNanos::from_nanos(30), Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 })),
        ];

        let outcomes = faults.apply_all(&schedule);

        assert_eq!(
            outcomes,
            vec![CarrierOutcome::Applied, CarrierOutcome::NotNetwork, CarrierOutcome::Applied]
        );
        assert!(
            !faults.controller().is_partitioned(endpoint(1), endpoint(2)),
            "the schedule's final heal did not take effect"
        );
    }
}
