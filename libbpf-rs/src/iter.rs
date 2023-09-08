use std::io;
use std::os::unix::io::AsFd as _;
use std::os::unix::io::AsRawFd as _;

use nix::errno;
use nix::libc;
use nix::unistd;

use crate::libbpf_sys;
use crate::Error;
use crate::Link;
use crate::Result;

/// Represents a bpf iterator for reading kernel data structures. This requires
/// Linux 5.8.
///
/// This implements [`std::io::Read`] for reading bytes from the iterator.
/// Methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
#[derive(Debug)]
pub struct Iter {
    fd: i32,
}

impl Iter {
    /// Create a new `Iter` wrapping the provided `Link`.
    pub fn new(link: &Link) -> Result<Self> {
        let link_fd = link.as_fd().as_raw_fd();
        let fd = unsafe { libbpf_sys::bpf_iter_create(link_fd) };
        if fd < 0 {
            return Err(Error::from_raw_os_error(errno::errno()));
        }
        Ok(Self { fd })
    }
}

impl io::Read for Iter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if bytes_read < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes_read as usize)
    }
}

impl Drop for Iter {
    fn drop(&mut self) {
        let _ = unistd::close(self.fd);
    }
}
