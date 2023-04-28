use std::ffi::CStr;
use std::os::raw::c_char;
use std::result;

use thiserror::Error;

/// Canonical error type for this crate.
#[derive(Error, Debug)]
pub enum Error {
    /// A system error occurred.
    #[error("System error, errno: {0}{}", error_suffix(*.0))]
    System(i32),
    /// An input was invalid.
    #[error("Input input: {0}")]
    InvalidInput(String),
    /// An internal error occurred.
    #[error("Internal error: {0}")]
    Internal(String),
}

fn errno_to_str(errno: i32) -> Option<&'static str> {
    let s = match errno {
        libc::EPERM => stringify!(EPERM),
        libc::ENOENT => stringify!(ENOENT),
        libc::ESRCH => stringify!(ESRCH),
        libc::EINTR => stringify!(EINTR),
        libc::EIO => stringify!(EIO),
        libc::ENXIO => stringify!(ENXIO),
        libc::E2BIG => stringify!(E2BIG),
        libc::ENOEXEC => stringify!(ENOEXEC),
        libc::EBADF => stringify!(EBADF),
        libc::ECHILD => stringify!(ECHILD),
        libc::EAGAIN => stringify!(EAGAIN),
        libc::ENOMEM => stringify!(ENOMEM),
        libc::EACCES => stringify!(EACCES),
        libc::EFAULT => stringify!(EFAULT),
        libc::ENOTBLK => stringify!(ENOTBLK),
        libc::EBUSY => stringify!(EBUSY),
        libc::EEXIST => stringify!(EEXIST),
        libc::EXDEV => stringify!(EXDEV),
        libc::ENODEV => stringify!(ENODEV),
        libc::ENOTDIR => stringify!(ENOTDIR),
        libc::EISDIR => stringify!(EISDIR),
        libc::EINVAL => stringify!(EINVAL),
        libc::ENFILE => stringify!(ENFILE),
        libc::EMFILE => stringify!(EMFILE),
        libc::ENOTTY => stringify!(ENOTTY),
        libc::ETXTBSY => stringify!(ETXTBSY),
        libc::EFBIG => stringify!(EFBIG),
        libc::ENOSPC => stringify!(ENOSPC),
        libc::ESPIPE => stringify!(ESPIPE),
        libc::EROFS => stringify!(EROFS),
        libc::EMLINK => stringify!(EMLINK),
        libc::EPIPE => stringify!(EPIPE),
        libc::EDOM => stringify!(EDOM),
        libc::ERANGE => stringify!(ERANGE),
        #[allow(unreachable_patterns)]
        libc::EWOULDBLOCK => stringify!(EWOULDBLOCK),
        _ => return None,
    };
    Some(s)
}

fn errno_to_text(errno: i32) -> Option<String> {
    let mut buf = [0 as c_char; 1024];
    // SAFETY: Our `buf` pointer is always valid because it is coming from a
    //         Rust array.
    let rc = unsafe { libc::strerror_r(errno, buf.as_mut_ptr() as *mut _, buf.len() as _) };
    if rc < 0 {
        return None;
    }

    // TODO: Use `CStr::from_bytes_until_nul` once we are at Rust 1.69.
    let cstr = unsafe { CStr::from_ptr(&buf as _) };
    Some(String::from_utf8_lossy(cstr.to_bytes()).to_string())
}

/// Best-effort stringification of errno values to be included in textual
/// representation of errors.
fn error_suffix(errno: i32) -> String {
    match (errno_to_str(errno), errno_to_text(errno)) {
        (Some(s), Some(txt)) => format!(" ({s}: {txt})"),
        (Some(s), None) => format!(" ({s})"),
        (None, Some(txt)) => format!(" ({txt})"),
        (None, None) => String::new(),
    }
}

/// The result type used by this library, defaulting to [`Error`][crate::Error]
/// as the error type.
pub type Result<T> = result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Check that we format system errors as expected.
    #[test]
    pub fn errno_str() {
        let err = Error::System(libc::EPERM);
        assert!(
            err.to_string()
                .ends_with(" (EPERM: Operation not permitted)"),
            "{err}"
        );
    }
}
