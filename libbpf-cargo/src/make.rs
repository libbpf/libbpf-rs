use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use crate::build;
use crate::gen;

#[allow(clippy::too_many_arguments)]
pub fn make(
    debug: bool,
    manifest_path: Option<&PathBuf>,
    clang: Option<&PathBuf>,
    clang_args: Vec<OsString>,
    skip_clang_version_checks: bool,
    quiet: bool,
    cargo_build_args: Vec<String>,
    rustfmt_path: Option<&PathBuf>,
) -> Result<()> {
    if !quiet {
        println!("Compiling BPF objects");
    }
    build::build(
        debug,
        manifest_path,
        clang,
        clang_args,
        skip_clang_version_checks,
    )
    .context("Failed to compile BPF objects")?;

    if !quiet {
        println!("Generating skeletons");
    }
    gen::gen(debug, manifest_path, None, rustfmt_path).context("Failed to generate skeletons")?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build");
    if quiet {
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
