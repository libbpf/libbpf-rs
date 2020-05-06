use std::ffi::{CStr, CString};

use crate::*;

pub fn str_to_cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| Error::InvalidInput(e.to_string()))
}

pub fn c_ptr_to_string(p: *const i8) -> Result<String> {
    if p.is_null() {
        return Err(Error::Internal("Null string".to_owned()));
    }

    let c_str = unsafe { CStr::from_ptr(p) };
    Ok(c_str
        .to_str()
        .map_err(|e| Error::Internal(e.to_string()))?
        .to_owned())
}
