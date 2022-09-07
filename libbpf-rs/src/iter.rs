use nix::{errno, libc, unistd};
use std::io;

use crate::*;

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
    pub fn new(link: &Link) -> Result<Self> {
        let link_fd = link.fd();
        let fd = unsafe { libbpf_sys::bpf_iter_create(link_fd) };
        if fd < 0 {
            return Err(Error::System(errno::errno()));
        }
        Ok(Self { fd })
    }
}

impl io::Read for Iter {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        let bytes_read = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if bytes_read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(bytes_read as usize)
    }
}

impl Drop for Iter {
    fn drop(&mut self) {
        let _ = unistd::close(self.fd);
    }
}
