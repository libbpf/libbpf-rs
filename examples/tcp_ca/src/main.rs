// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#![allow(clippy::let_unit_value)]

use std::ffi::c_int;
use std::ffi::c_void;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::fd::AsFd as _;
use std::os::fd::AsRawFd as _;
use std::os::fd::BorrowedFd;
use std::thread;

use clap::Parser;

use libc::setsockopt;
use libc::IPPROTO_TCP;
use libc::TCP_CONGESTION;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::ErrorExt as _;
use libbpf_rs::Result;

use crate::tcp_ca::TcpCaSkelBuilder;

mod tcp_ca {
    include!(concat!(env!("OUT_DIR"), "/tcp_ca.skel.rs"));
}

const TCP_CA_UPDATE: &[u8] = b"tcp_ca_update\0";

/// An example program adding a TCP congestion algorithm.
#[derive(Debug, Parser)]
struct Args {
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

fn set_sock_opt(
    fd: BorrowedFd<'_>,
    level: c_int,
    name: c_int,
    value: *const c_void,
    opt_len: usize,
) -> Result<()> {
    let rc = unsafe { setsockopt(fd.as_raw_fd(), level, name, value, opt_len as _) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

/// Set the `tcp_ca_update` congestion algorithm on the socket represented by
/// the provided file descriptor.
fn set_tcp_ca(fd: BorrowedFd<'_>) -> Result<()> {
    let () = set_sock_opt(
        fd,
        IPPROTO_TCP,
        TCP_CONGESTION,
        TCP_CA_UPDATE.as_ptr().cast(),
        (TCP_CA_UPDATE.len() - 1) as _,
    )
    .context("failed to set TCP_CONGESTION")?;
    Ok(())
}

/// Send and receive a bunch of data over TCP sockets using the `tcp_ca_update`
/// congestion algorithm.
fn send_recv() -> Result<()> {
    let num_bytes = 8 * 1024 * 1024;
    let listener = TcpListener::bind("[::1]:0")?;
    let () = set_tcp_ca(listener.as_fd())?;
    let addr = listener.local_addr()?;

    let send_handle = thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().unwrap();
        let to_send = (0..num_bytes).map(|_| b'x').collect::<Vec<u8>>();
        let () = stream.write_all(&to_send).unwrap();
    });

    let mut received = Vec::new();
    let mut stream = TcpStream::connect(addr)?;
    let () = set_tcp_ca(stream.as_fd())?;
    let _count = stream.read_to_end(&mut received)?;
    let () = send_handle.join().unwrap();

    assert_eq!(received.len(), num_bytes);
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut skel_builder = TcpCaSkelBuilder::default();
    if args.verbose {
        skel_builder.obj_builder.debug(true);
    }

    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    let mut maps = skel.maps_mut();
    let map = maps.ca_update();
    let _link = map.attach_struct_ops()?;

    println!("Registered `tcp_ca_update` congestion algorithm; using it for loopback based data exchange...");

    assert_eq!(skel.bss().ca_cnt, 0);

    // Use our registered TCP congestion algorithm while sending a bunch of data
    // over the loopback device.
    let () = send_recv()?;
    println!("Done.");

    let saved_ca1_cnt = skel.bss().ca_cnt;
    assert_ne!(saved_ca1_cnt, 0);
    Ok(())
}
