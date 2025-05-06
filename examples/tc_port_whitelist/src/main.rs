//! An example showing how to block ports using TC.

use std::mem::MaybeUninit;
use std::os::unix::io::AsFd as _;

use anyhow::Context as _;
use anyhow::Result;

use clap::Parser;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore as _;
use libbpf_rs::MapFlags;
use libbpf_rs::TcHookBuilder;
use libbpf_rs::TC_CUSTOM;
use libbpf_rs::TC_EGRESS;
use libbpf_rs::TC_H_CLSACT;
use libbpf_rs::TC_H_MIN_INGRESS;
use libbpf_rs::TC_INGRESS;

use nix::net::if_::if_nametoindex;

mod tc {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/tc.skel.rs"));
}
use tc::TcSkelBuilder;

#[derive(Debug, Parser)]
struct Command {
    /// list of ports to whitelist
    #[arg(short, long)]
    ports: Vec<u16>,

    /// attach a hook
    #[arg(short, long)]
    attach: bool,

    /// detach existing hook
    #[arg(short, long)]
    detach: bool,

    /// destroy all hooks on clsact
    #[arg(short = 'D', long = "destroy")]
    destroy: bool,

    /// query existing hook
    #[arg(short, long)]
    query: bool,

    /// interface to attach to
    #[arg(short = 'i', long = "interface")]
    iface: String,
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let builder = TcSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object)?;
    let skel = open.load()?;
    let ifidx = if_nametoindex(opts.iface.as_str())? as i32;

    let mut tc_builder = TcHookBuilder::new(skel.progs.handle_tc.as_fd());
    tc_builder
        .ifindex(ifidx)
        .replace(true)
        .handle(1)
        .priority(1);

    let mut egress = tc_builder.hook(TC_EGRESS);
    let mut ingress = tc_builder.hook(TC_INGRESS);
    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS).handle(2);

    // we can create a TcHook w/o the builder
    let mut destroy_all = libbpf_rs::TcHook::new(skel.progs.handle_tc.as_fd());
    destroy_all
        .ifindex(ifidx)
        .attach_point(TC_EGRESS | TC_INGRESS);

    if opts.query {
        match custom.query() {
            Err(e) => println!("failed to find custom hook: {e}"),
            Ok(prog_id) => println!("found custom hook prog_id: {prog_id}"),
        }
        match egress.query() {
            Err(e) => println!("failed to find custom hook: {e}"),
            Ok(prog_id) => println!("found custom hook prog_id: {prog_id}"),
        }
        match ingress.query() {
            Err(e) => println!("failed to find custom hook: {e}"),
            Ok(prog_id) => println!("found custom hook prog_id: {prog_id}"),
        }
    }

    if opts.detach {
        if let Err(e) = ingress.detach() {
            println!("failed to detach ingress hook {e}");
        }
        if let Err(e) = egress.detach() {
            println!("failed to detach egress hook {e}");
        }
        if let Err(e) = custom.detach() {
            println!("failed to detach custom hook {e}");
        }
    }

    if opts.attach {
        for (i, port) in opts.ports.iter().enumerate() {
            let key = (i as u32).to_ne_bytes();
            let val = port.to_ne_bytes();
            let () = skel
                .maps
                .ports
                .update(&key, &val, MapFlags::ANY)
                .context("Example limited to 10 ports")?;
        }
        ingress.create()?;

        if let Err(e) = egress.attach() {
            println!("failed to attach egress hook {e}");
        }

        if let Err(e) = ingress.attach() {
            println!("failed to attach ingress hook {e}");
        }

        if let Err(e) = custom.attach() {
            println!("failed to attach custom hook {e}");
        }
    }

    if opts.destroy {
        if let Err(e) = destroy_all.destroy() {
            println!("failed to destroy all {e}");
        }
    }

    Ok(())
}
