//! Example illustrating how to query certain BPF information.

use std::process::exit;

use clap::Parser;
use libbpf_rs::query;
use nix::unistd::Uid;

#[derive(Debug, Parser)]
struct ProgArgs {
    #[arg(short, long)]
    disassemble: bool,
}

/// Query the system about BPF-related information
#[derive(Debug, Parser)]
enum Command {
    /// Display information about progs
    Prog(ProgArgs),
    /// Display information about maps
    Map,
    /// Display information about BTF
    Btf,
    /// Display information about links
    Link,
}

fn prog(args: ProgArgs) {
    let opts = query::ProgInfoQueryOptions::default().include_all();
    for prog in query::ProgInfoIter::with_query_opts(opts) {
        println!(
            "name={:<16} type={:<15?} run_count={:<2} runtime_ns={} recursion_misses={:<2}",
            prog.name.to_string_lossy(),
            prog.ty,
            prog.run_cnt,
            prog.run_time_ns,
            prog.recursion_misses,
        );
        if args.disassemble {
            #[cfg(target_arch = "x86_64")]
            {
                use iced_x86::Formatter;

                let mut d = iced_x86::Decoder::new(64, &prog.jited_prog_insns, 0);
                let mut f = iced_x86::GasFormatter::new();
                while d.can_decode() {
                    let ip = d.ip();
                    let insn = d.decode();
                    let mut f_insn = String::new();
                    f.format(&insn, &mut f_insn);
                    println!("  {ip}: {f_insn}");
                }
            }

            #[cfg(not(target_arch = "x86_64"))]
            {
                println!("   Unable to disassemble on non-x86_64");
            }
        }
    }
}

fn map() {
    for map in query::MapInfoIter::default() {
        println!("name={:<16} type={:?}", map.name.to_string_lossy(), map.ty);
    }
}

fn btf() {
    for btf in query::BtfInfoIter::default() {
        println!(
            "id={:4} name={} size={}",
            btf.id,
            btf.name.to_string_lossy(),
            btf.btf.len()
        );
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
            query::LinkTypeInfo::Netfilter(_) => "netfilter",
            query::LinkTypeInfo::Xdp(_) => "xdp",
            query::LinkTypeInfo::Netkit(_) => "netkit",
            query::LinkTypeInfo::Tcx(_) => "tcx",
            query::LinkTypeInfo::StructOps(_) => "structops",
            query::LinkTypeInfo::KprobeMulti(_) => "kprobemulti",
            query::LinkTypeInfo::UprobeMulti(_) => "uprobemulti",
            query::LinkTypeInfo::SockMap(_) => "sockmap",
            query::LinkTypeInfo::PerfEvent(_) => "perf_event",
        };

        println!(
            "id={:4} prog_id={:4} type={}",
            link.id, link.prog_id, link_type_str
        );

        if let query::LinkTypeInfo::Tracing(ref tracing) = link.info {
            println!(
                "    attach_type={:?} target_obj_id={} target_btf_id={}",
                tracing.attach_type, tracing.target_obj_id, tracing.target_btf_id
            );
        } else if let query::LinkTypeInfo::PerfEvent(perf_event) = link.info {
            match perf_event.event_type {
                query::PerfEventType::Tracepoint { name, cookie } => {
                    let Some(name) = name else {
                        continue;
                    };

                    print!("    tracepoint {}", name.to_string_lossy());
                    if cookie != 0 {
                        print!("  cookie={cookie}");
                    }
                    println!();
                }
                query::PerfEventType::Kprobe {
                    func_name,
                    is_retprobe,
                    addr,
                    offset,
                    missed,
                    cookie,
                } => {
                    let probe_type = if is_retprobe { "kretprobe" } else { "kprobe" };
                    let func_name = func_name.as_ref().map(|s| s.to_string_lossy());

                    print!("    {probe_type}");
                    if addr != 0 {
                        print!(" addr={addr:#x}");
                    }
                    if let Some(func_name) = func_name {
                        print!(" func={func_name}");
                    }
                    if offset != 0 {
                        print!(" offset={offset:#x}");
                    }
                    if missed != 0 {
                        print!(" missed={missed}");
                    }
                    if cookie != 0 {
                        print!(" cookie={cookie}");
                    }
                    println!();
                }
                query::PerfEventType::Uprobe {
                    file_name,
                    is_retprobe,
                    offset,
                    cookie,
                    ref_ctr_offset,
                } => {
                    let probe_type = if is_retprobe { "uretprobe" } else { "uprobe" };
                    let file_name = file_name.as_ref().map(|s| s.to_string_lossy());

                    print!("    {probe_type}");
                    if let Some(file_name) = file_name {
                        print!(" file={file_name}");
                    }
                    if offset != 0 {
                        print!(" offset={offset:#x}");
                    }
                    if cookie != 0 {
                        print!(" cookie={cookie}");
                    }
                    if ref_ctr_offset != 0 {
                        print!(" ref_ctr_offset={ref_ctr_offset}");
                    }
                }
                query::PerfEventType::Event {
                    config,
                    event_type,
                    cookie,
                } => {
                    print!("    event");
                    print!(" type={event_type} config={config}");
                    if cookie != 0 {
                        print!(" cookie={cookie}");
                    }
                }
                query::PerfEventType::Unknown(ty) => {
                    println!("    unknown perf event type: {ty}");
                }
            }
        }
    }
}

fn main() {
    if !Uid::effective().is_root() {
        eprintln!("Must run as root");
        exit(1);
    }

    let opts = Command::parse();

    match opts {
        Command::Prog(args) => prog(args),
        Command::Map => map(),
        Command::Btf => btf(),
        Command::Link => link(),
    };
}
