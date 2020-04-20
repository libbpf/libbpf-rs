use std::path::PathBuf;
use std::process::exit;

use structopt::StructOpt;

mod build;
#[cfg(test)]
mod test;

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
#[derive(Debug, StructOpt)]
enum Wrapper {
    Libbpf(Command),
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Build bpf programs
    Build {
        #[structopt(short, long)]
        debug: bool,
        #[structopt(long, parse(from_os_str))]
        /// Path to top level Cargo.toml
        manifest_path: Option<PathBuf>,
    },
}

fn main() {
    let opts = Opt::from_args();

    let rc = match opts.wrapper {
        Wrapper::Libbpf(cmd) => match cmd {
            Command::Build {
                debug,
                manifest_path,
            } => build::build(debug, manifest_path.as_ref()),
        },
    };

    exit(rc);
}
