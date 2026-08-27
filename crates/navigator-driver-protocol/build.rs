use std::{error::Error, fs, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    let proto = "proto/navigator/driver/v1/driver.proto";
    println!("cargo:rerun-if-changed={proto}");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let out = std::env::var("OUT_DIR")?;
    let descriptor = format!("{out}/driver_descriptor.bin");
    let status = Command::new(protoc)
        .args([
            "--proto_path=proto",
            "--include_imports",
            "--descriptor_set_out",
        ])
        .arg(&descriptor)
        .arg(proto)
        .status()?;
    if !status.success() {
        return Err("protoc failed".into());
    }
    let bytes = fs::read(descriptor)?;
    let set = prost::Message::decode(bytes.as_slice())?;
    tonic_prost_build::configure()
        .build_server(false)
        .boxed(".navigator.driver.v1.ObserveResponse.result.event")
        .compile_fds(set)?;
    Ok(())
}
