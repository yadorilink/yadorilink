fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    // Generated protobuf enums are wire-schema shaped and cannot box large
    // variants without changing their public Rust API. Keep this lint on for
    // handwritten code while exempting generated types.
    config.type_attribute(".", "#[allow(clippy::large_enum_variant)]");
    // These carry a Send link code, which unlocks the link's file list: Debug is written by hand
    // in `src/lib.rs` and names none of it.
    config.skip_debug([
        ".yadorilink.daemonctl.v1.PreviewSendLinkRequest",
        ".yadorilink.daemonctl.v1.RedeemSendLinkRequest",
        ".yadorilink.daemonctl.v1.CreateSendLinkResponse",
    ]);
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
