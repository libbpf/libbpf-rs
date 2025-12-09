use core::ffi::c_ulong;
use std::io::Error;
use std::io::Read;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::fd::{self};
use std::result::Result;

use crate::libbpf_sys::bpf_prog_stream_read_opts;

/// [`Stream`] instances.
///
/// `streams`s are BPF descriptors that provide a character output
/// interface from the BPF program to userspace.
#[derive(Debug)]
pub(crate) struct Stream<'a> {
    prog_fd: fd::BorrowedFd<'a>,
    stream_id: u32,
}

impl<'a> Stream<'a> {
    /// Default BPF stdout stream id.
    pub(crate) const BPF_STDOUT: u32 = 1;
    /// Default BPF stderr stream id.
    pub(crate) const BPF_STDERR: u32 = 2;

    /// Create a new Stream instance.
    pub(crate) fn new(prog_fd: fd::BorrowedFd<'a>, stream_id: u32) -> Stream<'a> {
        Stream { prog_fd, stream_id }
    }
}

impl Read for Stream<'_> {
    /// Fill in a caller-provided buffer with contents from the stream.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let ret = unsafe {
            let mut c_opts = bpf_prog_stream_read_opts {
                sz: mem::size_of::<bpf_prog_stream_read_opts>() as c_ulong,
            };
            libbpf_sys::bpf_prog_stream_read(
                self.prog_fd.as_raw_fd(),
                self.stream_id,
                buf.as_mut_ptr().cast(),
                buf.len().try_into().unwrap(),
                &raw mut c_opts,
            )
        };
        if ret < 0 {
            return Err(Error::last_os_error());
        }

        Ok(ret as usize)
    }
}
