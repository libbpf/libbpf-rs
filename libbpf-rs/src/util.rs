use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;

use crate::*;

pub fn str_to_cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| Error::InvalidInput(e.to_string()))
}

pub fn path_to_cstring<P: AsRef<Path>>(path: P) -> Result<CString> {
    let path_str = path.as_ref().to_str().ok_or_else(|| {
        Error::InvalidInput(format!("{} is not valid unicode", path.as_ref().display()))
    })?;

    str_to_cstring(path_str)
}

pub fn c_ptr_to_string(p: *const c_char) -> Result<String> {
    if p.is_null() {
        return Err(Error::Internal("Null string".to_owned()));
    }

    let c_str = unsafe { CStr::from_ptr(p) };
    Ok(c_str
        .to_str()
        .map_err(|e| Error::Internal(e.to_string()))?
        .to_owned())
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
        Err(Error::System(-ret))
    } else {
        Ok(())
    }
}

pub fn parse_ret_i32(ret: i32) -> Result<i32> {
    if ret < 0 {
        // Error code is returned negative, flip to positive to match errno
        Err(Error::System(-ret))
    } else {
        Ok(ret)
    }
}

pub fn parse_ret_usize(ret: i32) -> Result<usize> {
    if ret < 0 {
        // Error code is returned negative, flip to positive to match errno
        Err(Error::System(-ret))
    } else {
        Ok(ret as usize)
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
}
