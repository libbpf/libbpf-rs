use crate::*;
use lazy_static::lazy_static;
use std::io::{self, Write};
use std::os::raw::c_char;
use std::sync::Mutex;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[repr(u32)]
pub enum PrintLevel {
    Warn = libbpf_sys::LIBBPF_WARN,
    Info = libbpf_sys::LIBBPF_INFO,
    Debug = libbpf_sys::LIBBPF_DEBUG,
}

impl From<libbpf_sys::libbpf_print_level> for PrintLevel {
    fn from(level: libbpf_sys::libbpf_print_level) -> Self {
        match level {
            libbpf_sys::LIBBPF_WARN => Self::Warn,
            libbpf_sys::LIBBPF_INFO => Self::Info,
            libbpf_sys::LIBBPF_DEBUG => Self::Debug,
            // shouldn't happen, but anything unknown becomes the highest level
            _ => Self::Warn,
        }
    }
}

pub type PrintCallback = fn(PrintLevel, String);

/// Mimic the default print functionality of libbpf. This way if the user calls `get_print` when no
/// previous callback had been set, with the intention of restoring it, everything will behave as
/// expected.
fn default_callback(_lvl: PrintLevel, msg: String) {
    let _ = io::stderr().write(msg.as_bytes());
}

// While we can't say that set_print is thread-safe, because we shouldn't assume that of
// libbpf_set_print, we should still make sure that things are sane on the rust side of things.
// Therefore we are using a lock to keep the log level and the callback in sync.
//
// We don't do anything that can panic with the lock held, so we'll unconditionally unwrap() when
// locking the mutex.
//
// Note that default print behavior ignores debug messages.
lazy_static! {
    static ref PRINT_CB: Mutex<Option<(PrintLevel, PrintCallback)>> =
        Mutex::new(Some((PrintLevel::Info, default_callback)));
}

extern "C" fn outer_print_cb(
    level: libbpf_sys::libbpf_print_level,
    fmtstr: *const c_char,
    va_list: *mut libbpf_sys::__va_list_tag,
) -> i32 {
    let level = level.into();
    if let Some((min_level, func)) = { *PRINT_CB.lock().unwrap() } {
        if level <= min_level {
            let msg = match unsafe { vsprintf::vsprintf(fmtstr, va_list) } {
                Ok(s) => s,
                Err(e) => format!("Failed to parse libbpf output: {}", e),
            };
            func(level, msg);
        }
    }
    0 // return value is ignored by libbpf
}

/// Set a callback to receive log messages from libbpf, instead of printing them to stderr.
///
/// # Arguments
///
/// * `callback` - Either a tuple `(min_level, function)` where `min_level` is the lowest priority
///   log message to handle, or `None` to disable all printing.
///
/// This overrides (and is overridden by) [`ObjectBuilder::debug`]
///
/// # Examples
///
/// To pass all messages to the `log` crate:
///
/// ```
/// use log;
/// use libbpf_rs::{PrintLevel, set_print};
///
/// fn print_to_log(level: PrintLevel, msg: String) {
///     match level {
///         PrintLevel::Debug => log::debug!("{}", msg),
///         PrintLevel::Info => log::info!("{}", msg),
///         PrintLevel::Warn => log::warn!("{}", msg),
///     }
/// }
///
/// set_print(Some((PrintLevel::Debug, print_to_log)));
/// ```
///
/// To disable printing completely:
///
/// ```
/// use libbpf_rs::set_print;
/// set_print(None);
/// ```
///
/// To temporarliy suppress output:
///
/// ```
/// use libbpf_rs::set_print;
///
/// let prev = set_print(None);
/// // do things quietly
/// set_print(prev);
/// ```
pub fn set_print(
    mut callback: Option<(PrintLevel, PrintCallback)>,
) -> Option<(PrintLevel, PrintCallback)> {
    let real_cb: libbpf_sys::libbpf_print_fn_t = callback.as_ref().and(Some(outer_print_cb));
    std::mem::swap(&mut callback, &mut *PRINT_CB.lock().unwrap());
    unsafe { libbpf_sys::libbpf_set_print(real_cb) };
    callback
}

/// Return the current print callback and level.
///
/// # Examples
///
/// To temporarliy suppress output:
///
/// ```
/// use libbpf_rs::{get_print, set_print};
///
/// let prev = get_print();
/// set_print(None);
/// // do things quietly
/// set_print(prev);
/// ```
pub fn get_print() -> Option<(PrintLevel, PrintCallback)> {
    *PRINT_CB.lock().unwrap()
}
