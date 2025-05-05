//! Example implementing the classic iptables TPROXY target.

use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::os::unix::io::AsFd as _;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::TcHookBuilder;
use libbpf_rs::TC_INGRESS;

mod tproxy {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tproxy.skel.rs"
    ));
}

use tproxy::TproxySkelBuilder;

/// Transparent proxy driver
///
/// The only thing is program does is intercept packets, and if appropriate, redirect
/// them to the actual proxy
#[derive(Debug, Parser)]
struct Command {
    /// Redirect all packets arriving on this port to the proxy
    #[arg(short, long, default_value = "1003")]
    port: u16,
    /// Interface index to proxy on
    #[arg(short, long, default_value = "1")]
    ifindex: i32,
    /// Address the proxy is listening on
    #[arg(long, value_parser, default_value = "127.0.0.1")]
    proxy_addr: String,
    /// Port the proxy is listening on
    #[arg(long, default_value = "9999")]
    proxy_port: u16,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let opts = Command::parse();

    // Install Ctrl-C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let proxy_addr = Ipv4Addr::from_str(&opts.proxy_addr)?;
    let proxy_addr: u32 = proxy_addr.into();

    let mut skel_builder = TproxySkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    // Set constants
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;
    let rodata = open_skel
        .maps
        .rodata_data
        .as_deref_mut()
        .expect("`rodata` is not memory mapped");
    rodata.target_port = opts.port.to_be();
    rodata.proxy_addr = proxy_addr.to_be();
    rodata.proxy_port = opts.proxy_port.to_be();

    // Load into kernel
    let skel = open_skel.load()?;
    // Set up and attach ingress TC hook
    let mut ingress = TcHookBuilder::new(skel.progs.tproxy.as_fd())
        .ifindex(opts.ifindex)
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_INGRESS);
    ingress
        .create()
        .context("Failed to create ingress TC qdisc")?;
    ingress
        .attach()
        .context("Failed to attach ingress TC prog")?;

    // Block until SIGINT
    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0));
    }

    if let Err(e) = ingress.detach() {
        eprintln!("Failed to detach prog: {e}");
    }
    if let Err(e) = ingress.destroy() {
        eprintln!("Failed to destroy TC hook: {e}");
    }

    Ok(())
}
