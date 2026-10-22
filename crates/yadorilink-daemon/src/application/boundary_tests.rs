#![cfg(test)]

/// Everything `ApplicationServices` hands the control socket -- the
/// saga-owning services AND the command ports it exposes directly (where a
/// service would only have forwarded 1:1) -- must speak application
/// vocabulary, never the IPC protocol's types. The port files are listed
/// alongside the services because the control socket now calls those
/// ports without an intermediate service to translate for it.
#[test]
fn application_sources_do_not_depend_on_ipc_proto() {
    for (name, source) in [
        ("services", include_str!("services.rs")),
        ("enrollment_service", include_str!("enrollment_service.rs")),
        ("enrollment_recovery_service", include_str!("enrollment_recovery_service.rs")),
        ("replica_membership_service", include_str!("replica_membership_service.rs")),
        ("ports/governance", include_str!("ports/governance.rs")),
        ("ports/group_admin", include_str!("ports/group_admin.rs")),
        ("ports/handoff", include_str!("ports/handoff.rs")),
        ("ports/materialization", include_str!("ports/materialization.rs")),
        ("ports/reporting", include_str!("ports/reporting.rs")),
        ("ports/runtime_control", include_str!("ports/runtime_control.rs")),
        ("ports/update", include_str!("ports/update.rs")),
    ] {
        assert!(
            !source.contains(concat!("yadorilink_", "ipc_proto")),
            "{name} must expose protocol-independent application types"
        );
    }
}
