use nix::errno;
use std::path::Path;

use crate::*;

/// Represents an attached [`Program`].
///
/// This struct is used to model ownership. The underlying program will be detached
/// when this object is dropped if nothing else is holding a reference count.
pub struct Link {
    ptr: *mut libbpf_sys::bpf_link,
}

impl Link {
    pub(crate) fn new(ptr: *mut libbpf_sys::bpf_link) -> Self {
        Link { ptr }
    }

    /// Takes ownership from pointer.
    ///
    /// # Safety
    ///
    /// It is not safe to manipulate `ptr` after this operation.
    pub unsafe fn from_ptr(ptr: *mut libbpf_sys::bpf_link) -> Self {
        Self::new(ptr)
    }

    /// Replace the underlying prog with `prog`.
    pub fn update_prog(&mut self, prog: Program) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_link__update_program(self.ptr, prog.ptr) };
        if ret != 0 {
            Err(Error::System(errno::errno()))
        } else {
            Ok(())
        }
    }

    /// [Pin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this link to bpffs.
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_link__pin(self.ptr, path_ptr) };
        if ret != 0 {
            // Error code is returned negative, flip to positive to match errno
            Err(Error::System(-ret))
        } else {
            Ok(())
        }
    }

    /// [Unpin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// from bpffs
    pub fn unpin(&mut self) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_link__unpin(self.ptr) };
        if ret != 0 {
            // Error code is returned negative, flip to positive to match errno
            Err(Error::System(-ret))
        } else {
            Ok(())
        }
    }

    /// Returns the file descriptor of the link.
    pub fn get_fd(&self) -> i32 {
        unsafe { libbpf_sys::bpf_link__fd(self.ptr) }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        let _ = unsafe { libbpf_sys::bpf_link__destroy(self.ptr) };
    }
}
