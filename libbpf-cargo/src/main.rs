#![allow(clippy::let_unit_value)]
#![warn(clippy::absolute_paths)]

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use clap::Subcommand;

#[doc(hidden)]
mod build;
mod gen;
mod make;
mod metadata;

#[doc(hidden)]
#[derive(Debug, Parser)]
#[command(version, about)]
#[command(propagate_version = true)]
struct Opt {
    #[command(subcommand)]
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
    #[command(subcommand)]
    Libbpf(Command),
}

/// cargo-libbpf is a cargo subcommand that helps develop and build eBPF (BPF) programs.
#[doc(hidden)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Build bpf programs
    Build {
        #[arg(short, long)]
        debug: bool,
        #[arg(long, value_parser)]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
        #[arg(long, value_parser)]
        /// Path to clang binary
        clang_path: Option<PathBuf>,
        #[arg(long)]
        /// Skip clang version checks
        skip_clang_version_checks: bool,
    },
    /// Generate skeleton files
    Gen {
        #[arg(short, long)]
        debug: bool,
        #[arg(long, value_parser)]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
        #[arg(long, value_parser)]
        /// Path to rustfmt binary
        rustfmt_path: Option<PathBuf>,
        #[arg(long, value_parser)]
        /// Generate skeleton for the specified object file and print results to stdout
        ///
        /// When specified, skeletons for the rest of the project will not be generated
        object: Option<PathBuf>,
    },
    /// Build project
    Make {
        #[arg(short, long)]
        debug: bool,
        #[arg(long, value_parser)]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
        #[arg(long, value_parser)]
        /// Path to clang binary
        clang_path: Option<PathBuf>,
        #[arg(long)]
        /// Skip clang version checks
        skip_clang_version_checks: bool,
        #[arg(short, long)]
        /// Quiet output
        quiet: bool,
        /// Arguments to pass to `cargo build`
        ///
        /// Example: cargo libbpf build -- --package mypackage
        cargo_build_args: Vec<String>,
        #[arg(long, value_parser)]
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
