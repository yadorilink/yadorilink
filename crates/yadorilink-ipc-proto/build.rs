fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    // Generated protobuf enums are wire-schema shaped and cannot box large
    // variants without changing their public Rust API. Keep this lint on for
    // handwritten code while exempting generated types.
    config.type_attribute(".", "#[allow(clippy::large_enum_variant)]");
    config.compile_protos(
        &[
            "proto/sync.proto",
            "proto/shellipc.proto",
            "proto/local_discovery.proto",
            "proto/daemon_control.proto",
            "proto/send.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
