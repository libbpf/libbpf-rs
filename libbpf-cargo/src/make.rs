use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::log_enabled;
use log::Level::Info;

use crate::build;
use crate::gen;

pub fn make(
    manifest_path: Option<&PathBuf>,
    clang: Option<&PathBuf>,
    clang_args: Vec<OsString>,
    cargo_build_args: Vec<String>,
    rustfmt_path: Option<&PathBuf>,
) -> Result<()> {
    debug!("Compiling BPF objects");
    build::build(manifest_path, clang, clang_args).context("Failed to compile BPF objects")?;

    debug!("Generating skeletons");
    gen::gen(manifest_path, None, rustfmt_path).context("Failed to generate skeletons")?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build");
    if !log_enabled!(Info) {
        cmd.arg("--quiet");
    }
    for arg in cargo_build_args {
        cmd.arg(arg);
    }

    let status = cmd.status().context("Failed to spawn child")?;
    if !status.success() {
        let reason = match status.code() {
            Some(rc) => format!("exit code {rc}"),
            None => "killed by signal".to_string(),
        };

        bail!("Failed to `cargo build`: {reason}");
    }

    Ok(())
}
