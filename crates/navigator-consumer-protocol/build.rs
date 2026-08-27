use std::{env, fs, io, path::PathBuf, process::Command};

use prost::Message;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = PathBuf::from("proto/navigator/consumer/v1/consumer.proto");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is unavailable")?);
    let descriptor_path = out_dir.join("navigator-consumer-v1.bin");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let include = protoc_bin_vendored::include_path()?;

    let status = Command::new(protoc)
        .args(["--include_imports", "--include_source_info"])
        .arg(format!(
            "--descriptor_set_out={}",
            descriptor_path.display()
        ))
        .arg("--proto_path=proto")
        .arg(format!("--proto_path={}", include.display()))
        .arg(&proto)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("vendored protoc failed").into());
    }

    let bytes = fs::read(&descriptor_path)?;
    let descriptor = prost_types::FileDescriptorSet::decode(bytes.as_slice())?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_fds(descriptor)?;

    println!("cargo:rerun-if-changed={}", proto.display());
    Ok(())
}
