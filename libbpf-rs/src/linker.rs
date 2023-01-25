use std::path::Path;
use std::ptr::null_mut;

use crate::util::path_to_cstring;
use crate::Error;
use crate::Result;

/// A type used for linking multiple BPF object files into a single one.
///
/// Please refer to
/// <https://lwn.net/ml/bpf/20210310040431.916483-6-andrii@kernel.org/> for
/// additional details.
#[derive(Debug)]
pub struct Linker {
    /// The `libbpf` linker object.
    linker: *mut libbpf_sys::bpf_linker,
}

impl Linker {
    /// Instantiate a `Linker` object.
    pub fn new<P>(output: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let output = path_to_cstring(output)?;
        let opts = null_mut();
        // SAFETY: `output` is a valid pointer and `opts` is accepted as NULL.
        let linker = unsafe { libbpf_sys::bpf_linker__new(output.as_ptr(), opts) };
        // SAFETY: `libbpf_get_error` is always safe to call.
        let err = unsafe { libbpf_sys::libbpf_get_error(linker as *const _) };
        if err != 0 {
            return Err(Error::System(err as i32));
        }

        let slf = Self { linker };
        Ok(slf)
    }

    /// Add a file to the set of files to link.
    pub fn add_file<P>(&mut self, file: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let file = path_to_cstring(file)?;
        let opts = null_mut();
        // SAFETY: `linker` and `file` are a valid pointers.
        let err = unsafe { libbpf_sys::bpf_linker__add_file(self.linker, file.as_ptr(), opts) };
        if err != 0 {
            Err(Error::System(err))
        } else {
            Ok(())
        }
    }

    /// Link all BPF object files [added](Self::add_file) to this object into
    /// a single one.
    pub fn link(&self) -> Result<()> {
        // SAFETY: `linker` is a valid pointer.
        let err = unsafe { libbpf_sys::bpf_linker__finalize(self.linker) };
        if err != 0 {
            return Err(Error::System(err));
        }
        Ok(())
    }
}

// SAFETY: `bpf_linker` can be sent to a different thread.
unsafe impl Send for Linker {}

impl Drop for Linker {
    fn drop(&mut self) {
        // SAFETY: `linker` is a valid pointer returned by `bpf_linker__new`.
        unsafe { libbpf_sys::bpf_linker__free(self.linker) }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Check that `Linker` is `Send`.
    #[test]
    fn linker_is_send() {
        fn test<T>()
        where
            T: Send,
        {
        }

        test::<Linker>();
    }
}
