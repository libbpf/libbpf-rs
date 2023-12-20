use bitflags::bitflags;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::BorrowedFd;

use crate::util;
use crate::Result;

bitflags! {
    /// Flags to configure the `XDP` operations
    pub struct XdpFlags: u32 {
        /// No flags.
        const NONE              = 0;
        /// See [`libbpf_sys::XDP_FLAGS_UPDATE_IF_NOEXIST`].
        const UPDATE_IF_NOEXIST = libbpf_sys::XDP_FLAGS_UPDATE_IF_NOEXIST as _;
        /// See [`libbpf_sys::XDP_FLAGS_SKB_MODE`].
        const SKB_MODE          = libbpf_sys::XDP_FLAGS_SKB_MODE as _;
        /// See [`libbpf_sys::XDP_FLAGS_DRV_MODE`].
        const DRV_MODE          = libbpf_sys::XDP_FLAGS_DRV_MODE as _;
        /// See [`libbpf_sys::XDP_FLAGS_HW_MODE`].
        const HW_MODE           = libbpf_sys::XDP_FLAGS_HW_MODE as _;
        /// See [`libbpf_sys::XDP_FLAGS_REPLACE`].
        const REPLACE           = libbpf_sys::XDP_FLAGS_REPLACE as _;
        /// See [`libbpf_sys::XDP_FLAGS_MODES`].
        const MODES             = libbpf_sys::XDP_FLAGS_MODES as _;
        /// See [`libbpf_sys::XDP_FLAGS_MASK`].
        const MASK              = libbpf_sys::XDP_FLAGS_MASK as _;
    }

}

/// Represents a XDP program.
///
/// This struct exposes operations to attach, detach and query a XDP program
#[derive(Debug)]
pub struct Xdp<'fd> {
    fd: BorrowedFd<'fd>,
    attach_opts: libbpf_sys::bpf_xdp_attach_opts,
    query_opts: libbpf_sys::bpf_xdp_query_opts,
}

impl<'fd> Xdp<'fd> {
    /// Create a new XDP instance with the given file descriptor of the
    /// `SEC("xdp")` [`Program`][crate::Program].
    pub fn new(fd: BorrowedFd<'fd>) -> Self {
        let mut xdp = Xdp {
            fd,
            attach_opts: libbpf_sys::bpf_xdp_attach_opts::default(),
            query_opts: libbpf_sys::bpf_xdp_query_opts::default(),
        };
        xdp.attach_opts.sz = size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t;
        xdp.query_opts.sz = size_of::<libbpf_sys::bpf_xdp_query_opts>() as libbpf_sys::size_t;
        xdp
    }

    /// Attach the XDP program to the given interface to start processing the
    /// packets
    ///
    /// # Notes
    /// Once a program is attached, it will outlive the userspace program. Make
    /// sure to detach the program if its not desired.
    pub fn attach(&self, ifindex: i32, flags: XdpFlags) -> Result<()> {
        let ret = unsafe {
            libbpf_sys::bpf_xdp_attach(
                ifindex,
                self.fd.as_raw_fd(),
                flags.bits(),
                &self.attach_opts,
            )
        };
        util::parse_ret(ret)
    }

    /// Detach the XDP program from the interface
    pub fn detach(&self, ifindex: i32, flags: XdpFlags) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_xdp_detach(ifindex, flags.bits(), &self.attach_opts) };
        util::parse_ret(ret)
    }

    /// Query to inspect the program
    pub fn query(&self, ifindex: i32, flags: XdpFlags) -> Result<libbpf_sys::bpf_xdp_query_opts> {
        let mut opts = self.query_opts;
        let err = unsafe { libbpf_sys::bpf_xdp_query(ifindex, flags.bits() as i32, &mut opts) };
        util::parse_ret(err).map(|()| opts)
    }

    /// Query to inspect the program identifier (prog_id)
    pub fn query_id(&self, ifindex: i32, flags: XdpFlags) -> Result<u32> {
        let mut prog_id = 0;
        let err =
            unsafe { libbpf_sys::bpf_xdp_query_id(ifindex, flags.bits() as i32, &mut prog_id) };
        util::parse_ret(err).map(|()| prog_id)
    }
}
