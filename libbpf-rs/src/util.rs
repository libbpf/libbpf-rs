use std::ffi::CStr;
use std::ffi::CString;
use std::fs;
use std::mem::transmute;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::OnceLock;

use crate::error::IntoError;
use crate::Error;
use crate::Result;

pub fn str_to_cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| Error::with_invalid_data(e.to_string()))
}

pub fn path_to_cstring<P: AsRef<Path>>(path: P) -> Result<CString> {
    let path_str = path.as_ref().to_str().ok_or_else(|| {
        Error::with_invalid_data(format!("{} is not valid unicode", path.as_ref().display()))
    })?;

    str_to_cstring(path_str)
}

pub fn c_ptr_to_string(p: *const c_char) -> Result<String> {
    if p.is_null() {
        return Err(Error::with_invalid_data("Null string"));
    }

    let c_str = unsafe { CStr::from_ptr(p) };
    Ok(c_str
        .to_str()
        .map_err(|e| Error::with_invalid_data(e.to_string()))?
        .to_owned())
}

/// Convert a `[c_char]` into a `CStr`.
pub fn c_char_slice_to_cstr(s: &[c_char]) -> Option<&CStr> {
    // TODO: Switch to using `CStr::from_bytes_until_nul` once we require
    //       Rust 1.69.0.
    let nul_idx = s
        .iter()
        .enumerate()
        .find_map(|(idx, b)| (*b == 0).then_some(idx))?;
    let cstr =
        // SAFETY: `c_char` and `u8` are both just one byte plain old data
        //         types.
        CStr::from_bytes_with_nul(unsafe { transmute::<&[c_char], &[u8]>(&s[0..=nul_idx]) })
            .unwrap();
    Some(cstr)
}

/// Round up a number to the next multiple of `r`
pub fn roundup(num: usize, r: usize) -> usize {
    num.div_ceil(r) * r
}

/// Get the number of CPUs in the system, e.g., to interact with per-cpu maps.
pub fn num_possible_cpus() -> Result<usize> {
    let ret = unsafe { libbpf_sys::libbpf_num_possible_cpus() };
    parse_ret(ret).map(|()| ret as usize)
}

pub fn parse_ret(ret: i32) -> Result<()> {
    if ret < 0 {
        // Error code is returned negative, flip to positive to match errno
        Err(Error::from_raw_os_error(-ret))
    } else {
        Ok(())
    }
}

pub fn parse_ret_i32(ret: i32) -> Result<i32> {
    parse_ret(ret).map(|()| ret)
}


/// Check the returned pointer of a `libbpf` call, extracting any
/// reported errors and converting them.
pub fn validate_bpf_ret<T>(ptr: *mut T) -> Result<NonNull<T>> {
    // SAFETY: `libbpf_get_error` is always safe to call.
    match unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) } {
        0 => {
            debug_assert!(!ptr.is_null());
            // SAFETY: libbpf guarantees that if NULL is returned an
            //         error it set, so we will always end up with a
            //         valid pointer when `libbpf_get_error` returned 0.
            let ptr = unsafe { NonNull::new_unchecked(ptr) };
            Ok(ptr)
        }
        err => Err(Error::from_raw_os_error(-err as i32)),
    }
}

/// An enum describing type of eBPF object.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BpfObjectType {
    /// The object is a map.
    Map,
    /// The object is a program.
    Program,
    /// The object is a BPF link.
    Link,
}

/// Get type of BPF object by fd.
///
/// This information is not exported directly by bpf_*_get_info_by_fd() functions,
/// as kernel relies on the userspace code to know what kind of object it
/// queries. The type of object can be recovered by fd only from the proc
/// filesystem. The same approach is used in bpftool.
pub fn object_type_from_fd(fd: BorrowedFd<'_>) -> Result<BpfObjectType> {
    let fd_link = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let link_type = fs::read_link(fd_link)
        .map_err(|e| Error::with_invalid_data(format!("can't read fd link: {}", e)))?;
    let link_type = link_type
        .to_str()
        .ok_or_invalid_data(|| "can't convert PathBuf to str")?;

    match link_type {
        "anon_inode:bpf-link" => Ok(BpfObjectType::Link),
        "anon_inode:bpf-map" => Ok(BpfObjectType::Map),
        "anon_inode:bpf-prog" => Ok(BpfObjectType::Program),
        other => Err(Error::with_invalid_data(format!(
            "unknown type of BPF fd: {other}"
        ))),
    }
}

// Fix me, If std::sync::LazyLock is stable(https://github.com/rust-lang/rust/issues/109736).
pub(crate) struct LazyLock<T> {
    cell: OnceLock<T>,
    init: fn() -> T,
}

impl<T> LazyLock<T> {
    pub const fn new(f: fn() -> T) -> Self {
        Self {
            cell: OnceLock::new(),
            init: f,
        }
    }
}

impl<T> Deref for LazyLock<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.cell.get_or_init(self.init)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io;
    use std::os::fd::AsFd;

    use tempfile::NamedTempFile;


    #[test]
    fn test_roundup() {
        for i in 1..=256 {
            let up = roundup(i, 8);
            assert!(up % 8 == 0);
            assert!(i <= up);
            assert!(up - i < 8);
        }
    }

    #[test]
    fn test_roundup_multiples() {
        for i in (8..=256).step_by(8) {
            assert_eq!(roundup(i, 8), i);
        }
    }

    #[test]
    fn test_num_possible_cpus() {
        let num = num_possible_cpus().unwrap();
        assert!(num > 0);
    }

    /// Check that we can convert a `[c_char]` into a `CStr`.
    #[test]
    fn c_char_slice_conversion() {
        let slice = [];
        assert_eq!(c_char_slice_to_cstr(&slice), None);

        let slice = [0];
        assert_eq!(c_char_slice_to_cstr(&slice).unwrap(), c"");

        let slice = ['a' as _, 'b' as _, 'c' as _, 0 as _];
        assert_eq!(c_char_slice_to_cstr(&slice).unwrap(), c"abc");

        // Missing terminating NUL byte.
        let slice = ['a' as _, 'b' as _, 'c' as _];
        assert_eq!(c_char_slice_to_cstr(&slice), None);
    }

    /// Check that object_type_from_fd() doesn't allow descriptors of usual
    /// files to be used. Testing with BPF objects requires BPF to be
    /// loaded.
    #[test]
    fn test_object_type_from_fd_with_unexpected_fds() {
        let not_object = NamedTempFile::new().unwrap();

        let _ = object_type_from_fd(not_object.as_fd())
            .expect_err("a common file was treated as a BPF object");
        let _ = object_type_from_fd(io::stdout().as_fd())
            .expect_err("the stdout fd was treated as a BPF object");
    }
}
