//! The one owner of a logical device partition.
//!
//! Two devices are connected by more than one network. Their control traffic
//! rides Turmoil's simulated sockets; their blocks, service RPCs and history
//! ride iroh's custom carrier into `TestNetwork`. Those are separate
//! networks with separate fault machinery, and a `Case` that says
//! `Partition(0, 1)` means neither of them in particular -- it means the two
//! devices cannot reach each other.
//!
//! So `Partition`/`Heal` has exactly one owner, and that owner cuts every
//! plane the devices are connected by. The alternative -- letting the
//! schedule apply the same fault to each plane separately -- is the bug this
//! type exists to make unrepresentable: a scenario that cut one plane and
//! not the other would have a partition in name only, with blocks flowing
//! while control traffic stopped, and would report a device partition it
//! never had.
//!
//! ```text
//! Case NetFault::Partition(0, 1)
//!           │
//!           ▼
//!    DeviceNetworkFaults
//!       ┌───┴──────────┐
//!       ▼              ▼
//! Turmoil host link   Iroh custom carrier
//! (control plane)     (block/service/history)
//! ```
//!
//! The trace records each plane's outcome separately, because a harness bug
//! that cuts one and misses the other is otherwise invisible: the scenario
//! sees "partitioned" either way.

#![cfg(turmoil)]
#![allow(dead_code)] // the control plane has no scenario driving it yet

use super::case_ir::{Fault, NetFault};
use super::fault_carrier::{CarrierFaults, CarrierOutcome};

/// What one `Case` fault did to each plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneOutcomes {
    /// Blocks, service RPCs and history, over iroh's custom carrier.
    pub substrate: CarrierOutcome,
    /// Control traffic, over Turmoil's own network. `None` when this
    /// scenario has no control plane -- which is a statement about the
    /// scenario, not a silent skip.
    pub control: Option<CarrierOutcome>,
}

impl PlaneOutcomes {
    /// Whether every plane this scenario has actually applied the fault.
    ///
    /// A scenario asserting on this is asserting that its devices are
    /// partitioned, rather than that one of their networks is.
    pub fn fully_applied(&self) -> bool {
        self.substrate == CarrierOutcome::Applied
            && self.control.is_none_or(|c| c == CarrierOutcome::Applied)
    }

    /// The first plane that reported an unknown device, if any.
    pub fn unknown_device(&self) -> Option<usize> {
        [Some(self.substrate), self.control].into_iter().flatten().find_map(|outcome| match outcome
        {
            CarrierOutcome::UnknownDevice(device) => Some(device),
            _ => None,
        })
    }
}

/// Turmoil host names by device index.
///
/// Separate from the substrate's `EndpointId` list because they are different
/// names for the same devices, and the `Case`'s index is what joins them. A
/// device is its index; what each plane calls it is that plane's business.
#[derive(Debug, Clone)]
pub struct ControlPlaneHosts {
    hosts: Vec<String>,
}

impl ControlPlaneHosts {
    /// `hosts[i]` is the Turmoil host name for the `Case`'s device `i`.
    pub fn new(hosts: Vec<String>) -> Self {
        Self { hosts }
    }

    fn pair(&self, a: usize, b: usize) -> Result<(&str, &str), usize> {
        let first = self.hosts.get(a).ok_or(a)?;
        let second = self.hosts.get(b).ok_or(b)?;
        Ok((first.as_str(), second.as_str()))
    }

    /// Must be called from inside a Turmoil simulation, which is where a
    /// schedule runs.
    fn apply(&self, net: &NetFault) -> CarrierOutcome {
        match net {
            NetFault::Partition { device_a, device_b } => match self.pair(*device_a, *device_b) {
                Ok((a, b)) => {
                    turmoil::partition(a, b);
                    CarrierOutcome::Applied
                }
                Err(missing) => CarrierOutcome::UnknownDevice(missing),
            },
            NetFault::Heal { device_a, device_b } => match self.pair(*device_a, *device_b) {
                Ok((a, b)) => {
                    turmoil::repair(a, b);
                    CarrierOutcome::Applied
                }
                Err(missing) => CarrierOutcome::UnknownDevice(missing),
            },
            NetFault::Drop => CarrierOutcome::Unimplemented("Drop"),
            NetFault::Delay { .. } => CarrierOutcome::Unimplemented("Delay"),
            NetFault::Reorder => CarrierOutcome::Unimplemented("Reorder"),
            NetFault::Duplicate => CarrierOutcome::Unimplemented("Duplicate"),
        }
    }
}

/// Applies a `Case`'s `Partition`/`Heal` to every network two devices are
/// connected by.
#[derive(Debug, Clone)]
pub struct DeviceNetworkFaults {
    substrate: CarrierFaults,
    control: Option<ControlPlaneHosts>,
}

impl DeviceNetworkFaults {
    /// A scenario whose devices are connected only by the substrate.
    ///
    /// Named rather than defaulted: "this scenario has no control plane" is
    /// a fact about it worth writing down, and the alternative is a reader
    /// assuming the control plane is cut when nothing is cutting it.
    pub fn substrate_only(substrate: CarrierFaults) -> Self {
        Self { substrate, control: None }
    }

    /// A scenario whose devices are connected by both planes.
    pub fn with_control_plane(substrate: CarrierFaults, control: ControlPlaneHosts) -> Self {
        Self { substrate, control: Some(control) }
    }

    pub fn substrate(&self) -> &CarrierFaults {
        &self.substrate
    }

    pub fn has_control_plane(&self) -> bool {
        self.control.is_some()
    }

    /// Applies one `Case` fault to every plane, reporting each.
    ///
    /// Both planes are always attempted; one failing does not stop the
    /// other. A half-applied partition is a worse state than either
    /// outcome alone, and the caller needs to see both to recognise it.
    pub fn apply(&self, fault: &Fault) -> PlaneOutcomes {
        let substrate = self.substrate.apply(fault);
        let control = self.control.as_ref().map(|hosts| match fault {
            Fault::Net(net) => hosts.apply(net),
            _ => CarrierOutcome::NotNetwork,
        });
        PlaneOutcomes { substrate, control }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_lane_ports::sim_fault::SimFaultController;

    fn endpoint(seed: u8) -> iroh::EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn substrate_faults() -> (SimFaultController, CarrierFaults) {
        let controller = SimFaultController::new();
        let carrier = CarrierFaults::new(controller.clone(), vec![endpoint(1), endpoint(2)]);
        (controller, carrier)
    }

    /// A scenario with no control plane says so, and its substrate is still
    /// cut.
    #[test]
    fn substrate_only_reports_no_control_outcome() {
        let (controller, carrier) = substrate_faults();
        let faults = DeviceNetworkFaults::substrate_only(carrier);

        let outcomes = faults.apply(&Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }));

        assert_eq!(outcomes.substrate, CarrierOutcome::Applied);
        assert_eq!(outcomes.control, None, "a scenario with no control plane claimed one");
        assert!(outcomes.fully_applied(), "every plane this scenario has was cut");
        assert!(controller.is_partitioned(endpoint(1), endpoint(2)));
    }

    /// `fully_applied` is about every plane the scenario has, so a
    /// substrate-only scenario is not held to a control plane it does not
    /// have -- and a scenario that does have one is.
    #[test]
    fn a_half_applied_partition_is_not_fully_applied() {
        let (_controller, carrier) = substrate_faults();
        let faults = DeviceNetworkFaults::with_control_plane(
            carrier,
            // One host name for two devices: the control plane cannot name
            // device 1, so it will refuse while the substrate succeeds.
            ControlPlaneHosts::new(vec!["device-a".to_string()]),
        );

        let outcomes = faults.apply(&Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }));

        assert_eq!(outcomes.substrate, CarrierOutcome::Applied, "the substrate was cut");
        assert_eq!(
            outcomes.control,
            Some(CarrierOutcome::UnknownDevice(1)),
            "the control plane should have refused a device it cannot name"
        );
        assert!(
            !outcomes.fully_applied(),
            "a partition that cut one plane and missed the other reported itself as complete"
        );
        assert_eq!(outcomes.unknown_device(), Some(1));
    }

    /// Faults for other injectors reach neither plane.
    #[test]
    fn a_disk_fault_touches_no_network_plane() {
        use super::super::case_ir::DiskFault;

        let (_controller, carrier) = substrate_faults();
        let faults = DeviceNetworkFaults::with_control_plane(
            carrier,
            ControlPlaneHosts::new(vec!["device-a".into(), "device-b".into()]),
        );

        let outcomes = faults.apply(&Fault::Disk(DiskFault::Enospc));

        assert_eq!(outcomes.substrate, CarrierOutcome::NotNetwork);
        assert_eq!(outcomes.control, Some(CarrierOutcome::NotNetwork));
    }
}
