use std::net::TcpListener;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd as _;
use std::str::FromStr;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use nix::sys::socket::bind;
use nix::sys::socket::listen;
use nix::sys::socket::setsockopt;
use nix::sys::socket::socket;
use nix::sys::socket::sockopt::IpTransparent;
use nix::sys::socket::sockopt::ReuseAddr;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::Backlog;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::SockaddrIn;

/// Fake proxy
///
/// This fake proxy will receive tproxied packets and print some information
/// about the remote peer.
#[derive(Debug, Parser)]
struct Command {
    /// Address the proxy is listening on
    #[arg(long, value_parser, default_value = "127.0.0.1")]
    addr: String,
    /// Port to listen on
    #[arg(long, default_value = "9999")]
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
    setsockopt(&fd, ReuseAddr, &true).context("Failed to set SO_REUSEADDR")?;
    setsockopt(&fd, IpTransparent, &true).context("Failed to set IP_TRANSPARENT")?;

    // Bind to addr
    let addr = format!("{}:{}", opts.addr, opts.port);
    let addr = SockaddrIn::from_str(&addr).context("Failed to parse socketaddr")?;
    bind(fd.as_raw_fd(), &addr).context("Failed to bind listener")?;

    // Start listening
    listen(&fd, Backlog::new(128).unwrap()).context("Failed to listen")?;
    let listener = TcpListener::from(fd);

    for client in listener.incoming() {
        let client = client.context("Failed to connect to client")?;
        handle_client(client).context("Failed to handle client")?;
    }

    Ok(())
}
