use std::any::type_name;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::mem::transmute;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr::NonNull;

use crate::libbpf_sys;
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
    ((num + (r - 1)) / r) * r
}

/// Get the number of CPUs in the system, e.g., to interact with per-cpu maps.
pub fn num_possible_cpus() -> Result<usize> {
    let ret = unsafe { libbpf_sys::libbpf_num_possible_cpus() };
    parse_ret_usize(ret)
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
    if ret < 0 {
        // Error code is returned negative, flip to positive to match errno
        Err(Error::from_raw_os_error(-ret))
    } else {
        Ok(ret)
    }
}

pub fn parse_ret_usize(ret: i32) -> Result<usize> {
    if ret < 0 {
        // Error code is returned negative, flip to positive to match errno
        Err(Error::from_raw_os_error(-ret))
    } else {
        Ok(ret as usize)
    }
}

pub fn create_bpf_entity_checked<B: 'static, F: FnOnce() -> *mut B>(f: F) -> Result<NonNull<B>> {
    create_bpf_entity_checked_opt(f).and_then(|ptr| {
        ptr.ok_or_else(|| {
            Error::with_io_error(
                io::ErrorKind::Other,
                format!(
                    "bpf call {:?} returned NULL",
                    type_name::<F>() // this is usually a library bug, hopefully this will
                                     // help diagnose the bug.
                                     //
                                     // One way to fix the bug might be to change to calling
                                     // create_bpf_entity_checked_opt and handling Ok(None)
                                     // as a meaningful value.
                ),
            )
        })
    })
}

pub fn create_bpf_entity_checked_opt<B: 'static, F: FnOnce() -> *mut B>(
    f: F,
) -> Result<Option<NonNull<B>>> {
    let ptr = f();
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: `libbpf_get_error` is always safe to call.
    match unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) } {
        0 => Ok(Some(unsafe {
            // SAFETY: We checked if the pointer was non null before.
            NonNull::new_unchecked(ptr)
        })),
        err => Err(Error::from_raw_os_error(err as i32)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            c_char_slice_to_cstr(&slice).unwrap(),
            CStr::from_bytes_with_nul(b"\0").unwrap()
        );

        let slice = ['a' as _, 'b' as _, 'c' as _, 0 as _];
        assert_eq!(
            c_char_slice_to_cstr(&slice).unwrap(),
            CStr::from_bytes_with_nul(b"abc\0").unwrap()
        );

        // Missing terminating NUL byte.
        let slice = ['a' as _, 'b' as _, 'c' as _];
        assert_eq!(c_char_slice_to_cstr(&slice), None);
    }
}
