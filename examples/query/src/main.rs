use std::process::exit;

use libbpf_rs::query;
use nix::unistd::Uid;
use structopt::StructOpt;

/// Query the system about BPF-related information
#[derive(Debug, StructOpt)]
enum Command {
    /// Display information about progs
    Prog,
    /// Display information about maps
    Map,
    /// Display information about BTF
    Btf,
}

fn prog() {
    for prog in query::ProgInfoIter::default() {
        println!(
            "name={:<16} type={:<15} run_count={:<2} runtime_ns={}",
            prog.name,
            prog.ty.to_string(),
            prog.run_cnt,
            prog.run_time_ns
        );
    }
}

fn map() {
    for map in query::MapInfoIter::default() {
        println!("name={:<16} type={}", map.name, map.ty.to_string(),);
    }
}

fn btf() {
    for btf in query::BtfInfoIter::default() {
        println!("id={:4} size={}", btf.id, btf.btf_size);
    }
}

fn main() {
    if !Uid::effective().is_root() {
        eprintln!("Must run as root");
        exit(1);
    }

    let opts = Command::from_args();

    match opts {
        Command::Prog => prog(),
        Command::Map => map(),
        Command::Btf => btf(),
    };
}
