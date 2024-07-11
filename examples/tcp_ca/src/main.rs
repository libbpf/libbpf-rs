// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#![allow(clippy::let_unit_value)]

use std::ffi::c_int;
use std::ffi::c_void;
use std::ffi::OsStr;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::mem::MaybeUninit;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::fd::AsFd as _;
use std::os::fd::AsRawFd as _;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::ptr::copy_nonoverlapping;
use std::thread;

use clap::Parser;

use the_original_libbpf_rs::skel::OpenSkel;
use the_original_libbpf_rs::skel::SkelBuilder;
use the_original_libbpf_rs::AsRawLibbpf as _;
use the_original_libbpf_rs::ErrorExt as _;
use the_original_libbpf_rs::ErrorKind;
use the_original_libbpf_rs::Result;

use libc::setsockopt;
use libc::IPPROTO_TCP;
use libc::TCP_CONGESTION;

use crate::tcp_ca::TcpCaSkelBuilder;

mod tcp_ca {
    // Skeleton rely on `libbpf_rs` being present in their "namespace". Because
    // we renamed the libbpf-rs dependency, we have to make it available under
    // the expected name here for the skeleton itself to work. None of this is
    // generally necessary, but it enables some niche use cases.
    use the_original_libbpf_rs as libbpf_rs;

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tcp_ca.skel.rs"
    ));
}

const TCP_CA_UPDATE: &str = "tcp_ca_update";

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
fn set_tcp_ca(fd: BorrowedFd<'_>, tcp_ca: &OsStr) -> Result<()> {
    let bytes = tcp_ca.as_bytes();
    let () = set_sock_opt(
        fd,
        IPPROTO_TCP,
        TCP_CONGESTION,
        bytes.as_ptr().cast(),
        bytes.len() as _,
    )
    .with_context(|| {
        format!(
            "failed to set TCP_CONGESTION algorithm `{}`",
            tcp_ca.to_str().unwrap()
        )
    })?;
    Ok(())
}

/// Send and receive a bunch of data over TCP sockets using the `tcp_ca_update`
/// congestion algorithm.
fn send_recv(tcp_ca: &OsStr) -> Result<()> {
    let num_bytes = 8 * 1024 * 1024;
    let listener = TcpListener::bind("[::1]:0")?;
    let () = set_tcp_ca(listener.as_fd(), tcp_ca)?;
    let addr = listener.local_addr()?;

    let send_handle = thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().unwrap();
        let to_send = (0..num_bytes).map(|_| b'x').collect::<Vec<u8>>();
        let () = stream.write_all(&to_send).unwrap();
    });

    let mut received = Vec::new();
    let mut stream = TcpStream::connect(addr)?;
    let () = set_tcp_ca(stream.as_fd(), tcp_ca)?;
    let _count = stream.read_to_end(&mut received)?;
    let () = send_handle.join().unwrap();

    assert_eq!(received.len(), num_bytes);
    Ok(())
}

fn test(name_to_register: Option<&OsStr>, name_to_use: &OsStr, verbose: bool) -> Result<()> {
    let mut skel_builder = TcpCaSkelBuilder::default();
    if verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;

    if let Some(name) = name_to_register {
        // Here we illustrate the possibility of updating `struct_ops` data before
        // load. That can be used to communicate data to the kernel, e.g., for
        // initialization purposes.
        let ca_update = open_skel.struct_ops.ca_update_mut();
        if name.as_bytes().len() >= ca_update.name.len() {
            panic!(
                "TCP CA name `{}` exceeds maximum length {}",
                name.to_str().unwrap(),
                ca_update.name.len()
            );
        }
        let bytes = name.as_bytes();
        let len = bytes.len();
        let () =
            unsafe { copy_nonoverlapping(bytes.as_ptr(), ca_update.name.as_mut_ptr().cast(), len) };
        let () = ca_update.name[len..].fill(0);
    }

    let ca_update_cong_control2 = open_skel
        .progs
        .ca_update_cong_control2
        .as_libbpf_object()
        .as_ptr();
    let ca_update = open_skel.struct_ops.ca_update_mut();
    ca_update.cong_control = ca_update_cong_control2;

    let mut object = MaybeUninit::uninit();
    let mut skel = open_skel.load(&mut object)?;
    let _link = skel.maps.ca_update.attach_struct_ops()?;

    println!(
        "Registered `{}` congestion algorithm; using `{}` for loopback based data exchange...",
        name_to_register.unwrap_or(name_to_use).to_str().unwrap(),
        name_to_use.to_str().unwrap()
    );

    // NB: At this point `/proc/sys/net/ipv4/tcp_available_congestion_control`
    //     would list the registered congestion algorithm.

    assert_eq!(skel.maps.bss_data.ca_cnt, 0);
    assert!(!skel.maps.bss_data.cong_control);

    // Use our registered TCP congestion algorithm while sending a bunch of data
    // over the loopback device.
    let () = send_recv(name_to_use)?;
    println!("Done.");

    let saved_ca_cnt = skel.maps.bss_data.ca_cnt;
    assert_ne!(saved_ca_cnt, 0);
    // With `ca_update_cong_control2` active, we should have seen the
    // `cong_control` value changed as well.
    assert!(skel.maps.bss_data.cong_control);
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let tcp_ca = OsStr::new(TCP_CA_UPDATE);
    let () = test(None, tcp_ca, args.verbose)?;

    // Use a different name under which the algorithm is registered; just for
    // illustration purposes of how to change `struct_ops` related data before
    // load/attachment.
    let new_ca = OsStr::new("anotherca");
    let () = test(Some(new_ca), new_ca, args.verbose)?;

    // Just to be sure we are not bullshitting with the above, use a different
    // congestion algorithm than what we register. This is expected to fail,
    // because said algorithm to use cannot be found.
    let to_register = OsStr::new("holycowca");
    let err = test(Some(to_register), tcp_ca, args.verbose).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);
    println!("Expected failure: {err:#}");

    Ok(())
}
