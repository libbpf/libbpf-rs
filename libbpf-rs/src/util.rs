use std::ffi::CString;

use crate::*;

pub fn str_to_cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| Error::InvalidInput(e.to_string()))
}
