use nix::errno;

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

    /// Replace the underlying prog with `prog`.
    pub fn update_prog(&mut self, prog: Program) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_link__update_program(self.ptr, prog.ptr) };
        if ret != 0 {
            Err(Error::System(errno::errno()))
        } else {
            Ok(())
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        let _ = unsafe { libbpf_sys::bpf_link__destroy(self.ptr) };
    }
}
