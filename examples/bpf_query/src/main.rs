use std::process::exit;

use clap::Parser;
use libbpf_rs::query;
use nix::unistd::Uid;

/// Query the system about BPF-related information
#[derive(Debug, Parser)]
enum Command {
    /// Display information about progs
    Prog,
    /// Display information about maps
    Map,
    /// Display information about BTF
    Btf,
    /// Display information about links
    Link,
}

fn prog() {
    for prog in query::ProgInfoIter::default() {
        println!(
            "name={:<16} type={:<15} run_count={:<2} runtime_ns={}",
            prog.name, prog.ty, prog.run_cnt, prog.run_time_ns
        );
    }
}

fn map() {
    for map in query::MapInfoIter::default() {
        println!("name={:<16} type={}", map.name, map.ty);
    }
}

fn btf() {
    for btf in query::BtfInfoIter::default() {
        println!("id={:4} size={}", btf.id, btf.btf_size);
    }
}

fn link() {
    for link in query::LinkInfoIter::default() {
        let link_type_str = match link.info {
            query::LinkTypeInfo::RawTracepoint(_) => "raw_tracepoint",
            query::LinkTypeInfo::Tracing(_) => "tracing",
            query::LinkTypeInfo::Cgroup(_) => "cgroup",
            query::LinkTypeInfo::Iter => "iter",
            query::LinkTypeInfo::NetNs(_) => "netns",
            query::LinkTypeInfo::Unknown => "unknown",
        };

        println!(
            "id={:4} prog_id={:4} type={}",
            link.id, link.prog_id, link_type_str
        );
    }
}

fn main() {
    if !Uid::effective().is_root() {
        eprintln!("Must run as root");
        exit(1);
    }

    let opts = Command::parse();

    match opts {
        Command::Prog => prog(),
        Command::Map => map(),
        Command::Btf => btf(),
        Command::Link => link(),
    };
}
