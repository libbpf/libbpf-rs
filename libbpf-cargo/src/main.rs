use std::path::PathBuf;
use std::process::exit;

use structopt::StructOpt;

#[doc(hidden)]
mod build;
mod gen;
mod metadata;
#[cfg(test)]
mod test;

#[doc(hidden)]
#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(subcommand)]
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
#[derive(Debug, StructOpt)]
enum Wrapper {
    Libbpf(Command),
}

#[doc(hidden)]
#[derive(Debug, StructOpt)]
#[structopt(verbatim_doc_comment)]
///
/// cargo-libbpf is a cargo subcommand that helps develop and build eBPF (BPF) programs.
///
/// libbpf-cargo provides the following Cargo.toml configuration options:
///
///     [package.metadata.libbpf]
///     prog_dir = "src/other_bpf_dir"  # default: <manifest_directory>/src/bpf
///     target_dir = "other_target_dir" # default: <target_dir>/bpf
///
/// `prog_dir`: path relative to package Cargo.toml to search for bpf progs
/// `target_dir`: path relative to workspace target directory to place compiled bpf progs
enum Command {
    /// Build bpf programs
    ///
    /// `cargo libbpf build` compiles `<NAME>.bpf.c` C files into corresponding `<NAME>.bpf.o` ELF
    /// object files. Each object file may contain one or more BPF programs, maps, and associated
    /// metadata. The object file may then be handed over to `libbpf-rs` for loading and interaction.
    ///
    /// cargo-libbpf-build enforces a few conventions:
    ///
    /// * source file names must be in the `<NAME>.bpf.c` format
    /// * object file names will be generated in `<NAME>.bpf.o` format
    /// * there may not be any two identical `<NAME>.bpf.c` file names in any two projects in a
    ///   cargo workspace
    Build {
        #[structopt(short, long)]
        debug: bool,
        #[structopt(long, parse(from_os_str))]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
        #[structopt(long, parse(from_os_str), default_value = "/bin/clang")]
        /// Path to clang binary
        clang_path: PathBuf,
        #[structopt(long)]
        /// Skip clang version checks
        skip_clang_version_checks: bool,
    },
    /// Generate skeleton files
    Gen {
        #[structopt(short, long)]
        debug: bool,
        #[structopt(long, parse(from_os_str))]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
    },
}

#[doc(hidden)]
fn main() {
    let opts = Opt::from_args();

    let rc = match opts.wrapper {
        Wrapper::Libbpf(cmd) => match cmd {
            Command::Build {
                debug,
                manifest_path,
                clang_path,
                skip_clang_version_checks,
            } => build::build(
                debug,
                manifest_path.as_ref(),
                clang_path.as_path(),
                skip_clang_version_checks,
            ),
            Command::Gen {
                debug,
                manifest_path,
            } => gen::gen(debug, manifest_path.as_ref()),
        },
    };

    exit(rc);
}
