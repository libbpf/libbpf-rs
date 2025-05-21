//! The `libbpf-cargo` `cargo` sub-command.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::Context as _;
use anyhow::Result;
use clap::ArgAction;
use clap::Args;
use clap::Parser;
use clap::Subcommand;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing::Level;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::FmtSubscriber;

use libbpf_cargo::__private::build;
use libbpf_cargo::__private::make;
use libbpf_cargo::__private::r#gen;


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
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_timer(ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.3f%:z".to_string()))
        .finish();

    let () =
        set_global_subscriber(subscriber).with_context(|| "failed to set tracing subscriber")?;

    match wrapper {
        Wrapper::Libbpf(cmd) => match cmd {
            Command::Build {
                manifest_path,
                clang_opts:
                    ClangOpts {
                        clang_path,
                        clang_args,
                    },
            } => build::build_project(manifest_path.as_deref(), clang_path.as_deref(), clang_args),
            Command::Gen {
                manifest_path,
                rustfmt_path,
                object,
            } => r#gen::generate(
                manifest_path.as_deref(),
                rustfmt_path.as_deref(),
                object.as_deref(),
            ),
            Command::Make {
                manifest_path,
                clang_opts:
                    ClangOpts {
                        clang_path,
                        clang_args,
                    },
                cargo_build_args,
                rustfmt_path,
            } => make::make(
                manifest_path.as_deref(),
                clang_path.as_deref(),
                clang_args,
                cargo_build_args,
                rustfmt_path.as_deref(),
            ),
        },
    }
}
