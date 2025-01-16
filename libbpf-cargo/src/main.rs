#![allow(clippy::let_unit_value)]
#![warn(clippy::absolute_paths)]

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::Context as _;
use anyhow::Result;
use clap::ArgAction;
use clap::Args;
use clap::Parser;
use clap::Subcommand;

use libbpf_cargo::__private::build;
use libbpf_cargo::__private::gen;
use libbpf_cargo::__private::make;
use log::Level;


#[doc(hidden)]
#[derive(Debug, Parser)]
#[command(version, about)]
#[command(propagate_version = true)]
struct Opt {
    #[command(subcommand)]
    wrapper: Wrapper,
    /// Increase verbosity (can be supplied multiple times).
    #[clap(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    verbosity: u8,
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

/// A grouping of clang specific options.
#[derive(Debug, Args)]
pub struct ClangOpts {
    /// Path to clang binary
    #[arg(long, value_parser)]
    clang_path: Option<PathBuf>,
    /// Additional arguments to pass to `clang`.
    #[arg(long, value_parser)]
    clang_args: Vec<OsString>,
}

/// cargo-libbpf is a cargo subcommand that helps develop and build eBPF (BPF) programs.
#[doc(hidden)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Build bpf programs
    Build {
        #[arg(long, value_parser)]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
        #[command(flatten)]
        clang_opts: ClangOpts,
    },
    /// Generate skeleton files
    Gen {
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
        #[arg(long, value_parser)]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
        #[command(flatten)]
        clang_opts: ClangOpts,
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
    let Opt { wrapper, verbosity } = opts;

    let level = match verbosity {
        0 => Level::Warn,
        1 => Level::Info,
        2 => Level::Debug,
        _ => Level::Trace,
    };

    let () = env_logger::builder()
        .parse_env(env_logger::Env::default().default_filter_or(level.as_str()))
        .try_init()
        .context("failed to initialize logging infrastructure")?;

    match wrapper {
        Wrapper::Libbpf(cmd) => match cmd {
            Command::Build {
                manifest_path,
                clang_opts:
                    ClangOpts {
                        clang_path,
                        clang_args,
                    },
            } => build::build(manifest_path.as_ref(), clang_path.as_ref(), clang_args),
            Command::Gen {
                manifest_path,
                rustfmt_path,
                object,
            } => gen::gen(
                manifest_path.as_ref(),
                rustfmt_path.as_ref(),
                object.as_ref(),
            ),
            Command::Make {
                manifest_path,
                clang_opts:
                    ClangOpts {
                        clang_path,
                        clang_args,
                    },
                quiet,
                cargo_build_args,
                rustfmt_path,
            } => make::make(
                manifest_path.as_ref(),
                clang_path.as_ref(),
                clang_args,
                quiet,
                cargo_build_args,
                rustfmt_path.as_ref(),
            ),
        },
    }
}
