use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::ErrorExt;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::NetfilterOpts;
use libbpf_rs::NFPROTO_IPV4;
use libbpf_rs::NF_INET_LOCAL_OUT;

mod netfilter {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/netfilter_blocklist.skel.rs"
    ));
}

use netfilter::*;

/// Netfilter Blocklist Example
///
/// Drop specified IP packets in netfilter hook
#[derive(Debug, Parser)]
struct Command {
    /// Add the specified IP to the blocked IP list
    #[arg(long, value_parser, default_value = "1.1.1.1")]
    block_ip: String,

    /// show the value in the debug info
    #[arg(long, value_parser, default_value = "42")]
    value: u32,

    /// Verbose debug output
    #[arg(short, long)]
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

    let mut skel_builder = NetfilterBlocklistSkelBuilder::default();

    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    // Set constants
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    // Load into kernel
    let skel = open_skel.load()?;

    let block_ip = Ipv4Addr::from_str(&opts.block_ip)?;
    let block_ip: u32 = block_ip.into();
    let block_ip_key = types::lpm_key {
        prefixlen: (32_u32),
        addr: block_ip.to_be(),
    };

    let block_ip_key = unsafe { plain::as_bytes(&block_ip_key) };
    let value = opts.value;

    skel.maps
        .block_ips
        .update(block_ip_key, &value.to_le_bytes(), MapFlags::ANY)
        .context("update new record to map fail")?;


    let local_in_netfilter_opt = NetfilterOpts {
        pf: NFPROTO_IPV4,
        hooknum: NF_INET_LOCAL_OUT,
        priority: -128,
        ..NetfilterOpts::default()
    };

    let local_in_link = skel
        .progs
        .netfilter_local_in
        .attach_netfilter(local_in_netfilter_opt)
        .unwrap();

    // Block until SIGINT
    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0));
    }

    local_in_link.detach().unwrap();

    Ok(())
}
