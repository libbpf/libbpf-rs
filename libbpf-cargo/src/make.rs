use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use tracing::debug;
use tracing::event_enabled;
use tracing::Level;

use crate::build;
use crate::r#gen;


/// Build the project, end-to-end.
pub fn make(
    manifest_path: Option<&Path>,
    clang: Option<&Path>,
    clang_args: Vec<OsString>,
    cargo_build_args: Vec<String>,
    rustfmt_path: Option<&Path>,
) -> Result<()> {
    debug!("Compiling BPF objects");
    build::build_project(manifest_path, clang, clang_args)
        .context("Failed to compile BPF objects")?;

    debug!("Generating skeletons");
    r#gen::generate(manifest_path, None, rustfmt_path).context("Failed to generate skeletons")?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build");
    if !event_enabled!(Level::INFO) {
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
