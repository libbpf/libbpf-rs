use std::path::{Path, PathBuf};

use crate::*;

/// Represents an attached [`Program`].
///
/// This struct is used to model ownership. The underlying program will be detached
/// when this object is dropped if nothing else is holding a reference count.
#[allow(missing_debug_implementations)]
pub struct Link {
    ptr: *mut libbpf_sys::bpf_link,
}

impl Link {
    pub(crate) fn new(ptr: *mut libbpf_sys::bpf_link) -> Self {
        Link { ptr }
    }

    /// Create link from BPF FS file.
    pub fn open<P: AsRef<Path>>(&mut self, path: P) -> Result<Self> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();
        let ptr = unsafe { libbpf_sys::bpf_link__open(path_ptr) };

        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            return Err(Error::System(err as i32));
        }

        Ok(Link::new(ptr))
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
        util::parse_ret(ret)
    }

    /// Release "ownership" of underlying BPF resource (typically, a BPF program
    /// attached to some BPF hook, e.g., tracepoint, kprobe, etc). Disconnected
    /// links, when destructed through bpf_link__destroy() call won't attempt to
    /// detach/unregisted that BPF resource. This is useful in situations where,
    /// say, attached BPF program has to outlive userspace program that attached it
    /// in the system. Depending on type of BPF program, though, there might be
    /// additional steps (like pinning BPF program in BPF FS) necessary to ensure
    /// exit of userspace program doesn't trigger automatic detachment and clean up
    /// inside the kernel.
    pub fn disconnect(&mut self) {
        unsafe { libbpf_sys::bpf_link__disconnect(self.ptr) }
    }

    /// [Pin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this link to bpffs.
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_link__pin(self.ptr, path_ptr) };
        util::parse_ret(ret)
    }

    /// [Unpin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// from bpffs
    pub fn unpin(&mut self) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_link__unpin(self.ptr) };
        util::parse_ret(ret)
    }

    /// Returns the file descriptor of the link.
    #[deprecated(since = "0.17.0", note = "please use `fd` instead")]
    pub fn get_fd(&self) -> i32 {
        unsafe { libbpf_sys::bpf_link__fd(self.ptr) }
    }

    /// Returns the file descriptor of the link.
    pub fn fd(&self) -> i32 {
        unsafe { libbpf_sys::bpf_link__fd(self.ptr) }
    }

    /// Returns path to BPF FS file or `None` if not pinned.
    pub fn pin_path(&self) -> Option<PathBuf> {
        let path_ptr = unsafe { libbpf_sys::bpf_link__pin_path(self.ptr) };
        if path_ptr.is_null() {
            return None;
        }

        let path = match util::c_ptr_to_string(path_ptr) {
            Ok(p) => p,
            Err(_) => return None,
        };

        Some(PathBuf::from(path.as_str()))
    }

    pub fn detach(&self) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_link__detach(self.ptr) };
        util::parse_ret(ret)
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        let _ = unsafe { libbpf_sys::bpf_link__destroy(self.ptr) };
    }
}
