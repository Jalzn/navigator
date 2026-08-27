use std::{error::Error, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let plugin = crate_dir.join("typescript/node_modules/.bin/protoc-gen-es");
    if !plugin.is_file() {
        return Err("run npm ci in typescript before generation".into());
    }
    let status = Command::new(protoc_bin_vendored::protoc_bin_path()?)
        .current_dir(&crate_dir)
        .args([
            "--proto_path=proto",
            "--es_out=typescript/gen",
            "--es_opt=target=ts,import_extension=js",
        ])
        .arg(format!("--plugin=protoc-gen-es={}", plugin.display()))
        .arg("proto/navigator/driver/v1/driver.proto")
        .status()?;
    if !status.success() {
        return Err("TypeScript protocol generation failed".into());
    }
    Ok(())
}
