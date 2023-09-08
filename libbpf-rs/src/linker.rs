use std::path::Path;
use std::ptr::null_mut;
use std::ptr::NonNull;

use crate::util;
use crate::util::path_to_cstring;
use crate::AsRawLibbpf;
use crate::Error;
use crate::ErrorExt as _;
use crate::Result;

/// A type used for linking multiple BPF object files into a single one.
///
/// Please refer to
/// <https://lwn.net/ml/bpf/20210310040431.916483-6-andrii@kernel.org/> for
/// additional details.
#[derive(Debug)]
pub struct Linker {
    /// The `libbpf` linker object.
    linker: NonNull<libbpf_sys::bpf_linker>,
}

impl Linker {
    /// Instantiate a `Linker` object.
    pub fn new<P>(output: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let output = path_to_cstring(output)?;
        util::create_bpf_entity_checked(|| {
            let opts = null_mut();
            // SAFETY: `output` is a valid pointer and `opts` is accepted as NULL.
            unsafe { libbpf_sys::bpf_linker__new(output.as_ptr(), opts) }
        })
        .map(|linker| Self { linker })
    }

    /// Add a file to the set of files to link.
    pub fn add_file<P>(&mut self, file: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let file = path_to_cstring(file)?;
        let opts = null_mut();
        // SAFETY: `linker` and `file` are a valid pointers.
        let err =
            unsafe { libbpf_sys::bpf_linker__add_file(self.linker.as_ptr(), file.as_ptr(), opts) };
        if err != 0 {
            Err(Error::from_raw_os_error(err)).context("bpf_linker__add_file failed")
        } else {
            Ok(())
        }
    }

    /// Link all BPF object files [added](Self::add_file) to this object into
    /// a single one.
    pub fn link(&self) -> Result<()> {
        // SAFETY: `linker` is a valid pointer.
        let err = unsafe { libbpf_sys::bpf_linker__finalize(self.linker.as_ptr()) };
        if err != 0 {
            return Err(Error::from_raw_os_error(err)).context("bpf_linker__finalize failed");
        }
        Ok(())
    }
}

impl AsRawLibbpf for Linker {
    type LibbpfType = libbpf_sys::bpf_linker;

    /// Retrieve the underlying [`libbpf_sys::bpf_linker`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.linker
    }
}

// SAFETY: `bpf_linker` can be sent to a different thread.
unsafe impl Send for Linker {}

impl Drop for Linker {
    fn drop(&mut self) {
        // SAFETY: `linker` is a valid pointer returned by `bpf_linker__new`.
        unsafe { libbpf_sys::bpf_linker__free(self.linker.as_ptr()) }
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
