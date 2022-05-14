use std::path::PathBuf;

use anyhow::Result;
use clap::{AppSettings, Parser, Subcommand};

mod btf;
#[doc(hidden)]
mod build;
mod gen;
mod make;
mod metadata;

#[doc(hidden)]
#[derive(Debug, Parser)]
#[clap(version, about)]
#[clap(propagate_version = true)]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
struct Opt {
    #[clap(subcommand)]
    wrapper: Wrapper,
}

// cargo invokes subcommands with the first argument as
// the subcommand name. ie.
//
//     cargo ${command} --help
//
// into
//
//     cargo-${command} ${command} --help
//
// so we must have a dummy subcommand here to eat the arg.
#[doc(hidden)]
#[derive(Debug, Subcommand)]
enum Wrapper {
    #[clap(subcommand)]
    Libbpf(Command),
}

/// cargo-libbpf is a cargo subcommand that helps develop and build eBPF (BPF) programs.
#[doc(hidden)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Build bpf programs
    Build {
        #[clap(short, long)]
        debug: bool,
        #[clap(long, parse(from_os_str))]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
        #[clap(long, parse(from_os_str))]
        /// Path to clang binary
        clang_path: Option<PathBuf>,
        #[clap(long)]
        /// Skip clang version checks
        skip_clang_version_checks: bool,
    },
    /// Generate skeleton files
    Gen {
        #[clap(short, long)]
        debug: bool,
        #[clap(long, parse(from_os_str))]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
        #[clap(long, parse(from_os_str))]
        /// Path to rustfmt binary
        rustfmt_path: Option<PathBuf>,
        #[clap(long, parse(from_os_str))]
        /// Generate skeleton for the specified object file and print results to stdout
        ///
        /// When specified, skeletons for the rest of the project will not be generated
        object: Option<PathBuf>,
    },
    /// Build project
    Make {
        #[clap(short, long)]
        debug: bool,
        #[clap(long, parse(from_os_str))]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
        #[clap(long, parse(from_os_str))]
        /// Path to clang binary
        clang_path: Option<PathBuf>,
        #[clap(long)]
        /// Skip clang version checks
        skip_clang_version_checks: bool,
        #[clap(short, long)]
        /// Quiet output
        quiet: bool,
        /// Arguments to pass to `cargo build`
        ///
        /// Example: cargo libbpf build -- --package mypackage
        cargo_build_args: Vec<String>,
        #[clap(long, parse(from_os_str))]
        /// Path to rustfmt binary
        rustfmt_path: Option<PathBuf>,
    },
}

#[doc(hidden)]
fn main() -> Result<()> {
    let opts = Opt::parse();

    match opts.wrapper {
        Wrapper::Libbpf(cmd) => match cmd {
            Command::Build {
                debug,
                manifest_path,
                clang_path,
                skip_clang_version_checks,
            } => build::build(
                debug,
                manifest_path.as_ref(),
                clang_path.as_ref(),
                skip_clang_version_checks,
            ),
            Command::Gen {
                debug,
                manifest_path,
                rustfmt_path,
                object,
            } => gen::gen(
                debug,
                manifest_path.as_ref(),
                rustfmt_path.as_ref(),
                object.as_ref(),
            ),
            Command::Make {
                debug,
                manifest_path,
                clang_path,
                skip_clang_version_checks,
                quiet,
                cargo_build_args,
                rustfmt_path,
            } => make::make(
                debug,
                manifest_path.as_ref(),
                clang_path.as_ref(),
                skip_clang_version_checks,
                quiet,
                cargo_build_args,
                rustfmt_path.as_ref(),
            ),
        },
    }
}
