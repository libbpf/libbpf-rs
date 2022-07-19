use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{
    MapFlags, TcHookBuilder, TC_CUSTOM, TC_EGRESS, TC_H_CLSACT, TC_H_MIN_INGRESS, TC_INGRESS,
};

mod tc {
    include!(concat!(env!("OUT_DIR"), "/tc.skel.rs"));
}
use tc::*;

#[derive(Debug, Parser)]
struct Command {
    /// list of ports to whitelist
    #[clap(short, long)]
    ports: Vec<u16>,

    /// attach a hook
    #[clap(short, long)]
    attach: bool,

    /// detach existing hook
    #[clap(short, long)]
    detach: bool,

    /// destroy all hooks on clsact
    #[clap(short = 'D', long = "destroy")]
    destroy: bool,

    /// query existing hook
    #[clap(short, long)]
    query: bool,

    /// interface to attach to
    #[clap(short = 'i', long = "interface")]
    iface: String,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}
fn main() -> Result<()> {
    let opts = Command::parse();

    bump_memlock_rlimit()?;

    let builder = TcSkelBuilder::default();
    let open = builder.open()?;
    let mut skel = open.load()?;
    let fd = skel.progs().handle_tc().fd();
    let ifidx = nix::net::if_::if_nametoindex(opts.iface.as_str())? as i32;

    let mut tc_builder = TcHookBuilder::new();
    tc_builder
        .fd(fd)
        .ifindex(ifidx)
        .replace(true)
        .handle(1)
        .priority(1);

    let mut egress = tc_builder.hook(TC_EGRESS);
    let mut ingress = tc_builder.hook(TC_INGRESS);
    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS).handle(2);

    // we can create a TcHook w/o the builder
    let mut destroy_all = libbpf_rs::TcHook::new(fd);
    destroy_all
        .ifindex(ifidx)
        .attach_point(TC_EGRESS | TC_INGRESS);

    if opts.query {
        match custom.query() {
            Err(e) => println!("failed to find custom hook: {}", e),
            Ok(prog_id) => println!("found custom hook prog_id: {}", prog_id),
        }
        match egress.query() {
            Err(e) => println!("failed to find custom hook: {}", e),
            Ok(prog_id) => println!("found custom hook prog_id: {}", prog_id),
        }
        match ingress.query() {
            Err(e) => println!("failed to find custom hook: {}", e),
            Ok(prog_id) => println!("found custom hook prog_id: {}", prog_id),
        }
    }

    if opts.detach {
        if let Err(e) = ingress.detach() {
            println!("failed to detach ingress hook {}", e);
        }
        if let Err(e) = egress.detach() {
            println!("failed to detach egress hook {}", e);
        }
        if let Err(e) = custom.detach() {
            println!("failed to detach custom hook {}", e);
        }
    }

    if opts.attach {
        for (i, port) in opts.ports.iter().enumerate() {
            let key = (i as u32).to_ne_bytes();
            let val = port.to_ne_bytes();
            if let Err(e) = skel.maps_mut().ports().update(&key, &val, MapFlags::ANY) {
                bail!("Example limited to 10 ports: {}", e);
            }
        }
        ingress.create()?;

        if let Err(e) = egress.attach() {
            println!("failed to attach egress hook {}", e);
        }

        if let Err(e) = ingress.attach() {
            println!("failed to attach ingress hook {}", e);
        }

        if let Err(e) = custom.attach() {
            println!("failed to attach custom hook {}", e);
        }
    }

    if opts.destroy {
        if let Err(e) = destroy_all.destroy() {
            println!("failed to destroy all {}", e);
        }
    }

    Ok(())
}
