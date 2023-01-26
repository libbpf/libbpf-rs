use std::net::{TcpListener, TcpStream};
use std::os::unix::io::FromRawFd;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Parser;
use nix::sys::socket::{
    bind, listen, setsockopt, socket,
    sockopt::{IpTransparent, ReuseAddr},
    AddressFamily, SockFlag, SockType, SockaddrIn,
};

/// Fake proxy
///
/// This fake proxy will receive tproxied packets and print some information
/// about the remote peer.
#[derive(Debug, Parser)]
struct Command {
    /// Address the proxy is listening on
    #[clap(long, value_parser, default_value = "127.0.0.1")]
    addr: String,
    /// Port to listen on
    #[clap(long, default_value = "9999")]
    port: u16,
}

fn handle_client(client: TcpStream) -> Result<()> {
    let local_addr = client.local_addr().context("Failed to get local addr")?;
    let peer_addr = client.peer_addr().context("Failed to get peer addr")?;

    println!("New connection:");
    println!("\tlocal: {local_addr}");
    println!("\tpeer: {peer_addr}");
    println!();

    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::parse();

    // Create listener socket
    let fd = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .context("Failed to create listener socket")?;

    // Set some sockopts
    setsockopt(fd, ReuseAddr, &true).context("Failed to set SO_REUSEADDR")?;
    setsockopt(fd, IpTransparent, &true).context("Failed to set IP_TRANSPARENT")?;

    // Bind to addr
    let addr = format!("{}:{}", opts.addr, opts.port);
    let addr = SockaddrIn::from_str(&addr).context("Failed to parse socketaddr")?;
    bind(fd, &addr).context("Failed to bind listener")?;

    // Start listening
    listen(fd, 128).context("Failed to listen")?;
    let listener = unsafe { TcpListener::from_raw_fd(fd) };

    for client in listener.incoming() {
        let client = client.context("Failed to connect to client")?;
        handle_client(client).context("Failed to handle client")?;
    }

    Ok(())
}
