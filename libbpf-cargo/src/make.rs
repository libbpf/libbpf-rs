use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{build, gen};

pub fn make(
    debug: bool,
    manifest_path: Option<&PathBuf>,
    clang: &Path,
    skip_clang_version_checks: bool,
    quiet: bool,
    cargo_build_args: Vec<String>,
    rustfmt_path: Option<&PathBuf>,
) -> i32 {
    if !quiet {
        println!("Compiling BPF objects");
    }
    let mut ret = build::build(debug, manifest_path, clang, skip_clang_version_checks);
    if ret != 0 {
        eprintln!("Failed to compile BPF objects");
        return ret;
    }

    if !quiet {
        println!("Generating skeletons");
    }
    ret = gen::gen(debug, manifest_path, None, rustfmt_path);
    if ret != 0 {
        eprintln!("Failed to generate skeletons");
        return ret;
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("build");
    if quiet {
        cmd.arg("--quiet");
    }
    for arg in cargo_build_args {
        cmd.arg(arg);
    }

    let status = match cmd.status() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to spawn child: {}", e);
            return 1;
        }
    };

    if !status.success() {
        let reason = match status.code() {
            Some(rc) => format!("exit code {}", rc),
            None => "killed by signal".to_string(),
        };

        eprintln!("Failed to `cargo build`: {}", reason);
        return 1;
    }

    0
}
