use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::{TcHookBuilder, TC_INGRESS};

mod tproxy {
    include!(concat!(env!("OUT_DIR"), "/tproxy.skel.rs"));
}

use tproxy::*;

/// Transparent proxy driver
///
/// The only thing is program does is intercept packets, and if appropriate, redirect
/// them to the actual proxy
#[derive(Debug, Parser)]
struct Command {
    /// Redirect all packets arriving on this port to the proxy
    #[clap(short, long, default_value = "1003")]
    port: u16,
    /// Interface index to proxy on
    #[clap(short, long, default_value = "1")]
    ifindex: i32,
    /// Address the proxy is listening on
    #[clap(long, value_parser, default_value = "127.0.0.1")]
    proxy_addr: String,
    /// Port the proxy is listening on
    #[clap(long, default_value = "9999")]
    proxy_port: u16,
    /// Verbose debug output
    #[clap(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let opts = Command::parse();

    // Install Ctrl-C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let proxy_addr = Ipv4Addr::from_str(&opts.proxy_addr)?;
    let proxy_addr: u32 = proxy_addr.into();

    let mut skel_builder = TproxySkelBuilder::default();
    if opts.verbose {
        unsafe {
            // SAFETY:
            // no other thread is running which could cause undefined behaviour due
            // to this call.
            skel_builder.obj_builder.debug(true);
        }
    }

    // Set constants
    let mut open_skel = skel_builder.open()?;
    open_skel.rodata().target_port = opts.port.to_be();
    open_skel.rodata().proxy_addr = proxy_addr.to_be();
    open_skel.rodata().proxy_port = opts.proxy_port.to_be();

    // Load into kernel
    let skel = open_skel.load()?;

    // Set up and attach ingress TC hook
    let mut ingress = TcHookBuilder::new()
        .fd(skel.progs().tproxy().fd())
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
