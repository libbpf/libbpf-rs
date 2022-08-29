use core::ffi::c_void;
use std::boxed::Box;
use std::slice;
use std::time::Duration;

use crate::*;

// Workaround for `trait_alias`
// (https://doc.rust-lang.org/unstable-book/language-features/trait-alias.html)
// not being available yet. This is just a custom trait plus a blanket implementation.
pub trait SampleCb: FnMut(i32, &[u8]) {}
impl<T> SampleCb for T where T: FnMut(i32, &[u8]) {}

pub trait LostCb: FnMut(i32, u64) {}
impl<T> LostCb for T where T: FnMut(i32, u64) {}

#[allow(missing_debug_implementations)]
struct CbStruct<'b> {
    sample_cb: Option<Box<dyn SampleCb + 'b>>,
    lost_cb: Option<Box<dyn LostCb + 'b>>,
}

/// Builds [`PerfBuffer`] instances.
#[allow(missing_debug_implementations)]
pub struct PerfBufferBuilder<'a, 'b> {
    map: &'a Map,
    pages: usize,
    sample_cb: Option<Box<dyn SampleCb + 'b>>,
    lost_cb: Option<Box<dyn LostCb + 'b>>,
}

impl<'a, 'b> PerfBufferBuilder<'a, 'b> {
    pub fn new(map: &'a Map) -> Self {
        Self {
            map,
            pages: 64,
            sample_cb: None,
            lost_cb: None,
        }
    }
}

impl<'a, 'b> PerfBufferBuilder<'a, 'b> {
    /// Callback to run when a sample is received.
    ///
    /// This callback provides a raw byte slice. You may find libraries such as
    /// [`plain`](https://crates.io/crates/plain) helpful.
    ///
    /// Callback arguments are: `(cpu, data)`.
    pub fn sample_cb<NewCb: SampleCb + 'b>(self, cb: NewCb) -> PerfBufferBuilder<'a, 'b> {
        PerfBufferBuilder {
            map: self.map,
            pages: self.pages,
            sample_cb: Some(Box::new(cb)),
            lost_cb: self.lost_cb,
        }
    }

    /// Callback to run when a sample is received.
    ///
    /// Callback arguments are: `(cpu, lost_count)`.
    pub fn lost_cb<NewCb: LostCb + 'b>(self, cb: NewCb) -> PerfBufferBuilder<'a, 'b> {
        PerfBufferBuilder {
            map: self.map,
            pages: self.pages,
            sample_cb: self.sample_cb,
            lost_cb: Some(Box::new(cb)),
        }
    }

    /// The number of pages to size the ring buffer.
    pub fn pages(self, pages: usize) -> PerfBufferBuilder<'a, 'b> {
        PerfBufferBuilder {
            map: self.map,
            pages,
            sample_cb: self.sample_cb,
            lost_cb: self.lost_cb,
        }
    }

    pub fn build(self) -> Result<PerfBuffer<'b>> {
        if self.map.map_type() != MapType::PerfEventArray {
            return Err(Error::InvalidInput(
                "Must use a PerfEventArray map".to_string(),
            ));
        }

        if !self.pages.is_power_of_two() {
            return Err(Error::InvalidInput(
                "Page count must be power of two".to_string(),
            ));
        }

        let c_sample_cb: libbpf_sys::perf_buffer_sample_fn = if self.sample_cb.is_some() {
            Some(Self::call_sample_cb)
        } else {
            None
        };

        let c_lost_cb: libbpf_sys::perf_buffer_lost_fn = if self.lost_cb.is_some() {
            Some(Self::call_lost_cb)
        } else {
            None
        };

        let callback_struct_ptr = Box::into_raw(Box::new(CbStruct {
            sample_cb: self.sample_cb,
            lost_cb: self.lost_cb,
        }));

        let ptr = unsafe {
            libbpf_sys::perf_buffer__new(
                self.map.fd(),
                self.pages as libbpf_sys::size_t,
                c_sample_cb,
                c_lost_cb,
                callback_struct_ptr as *mut _,
                std::ptr::null(),
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(PerfBuffer {
                ptr,
                _cb_struct: unsafe { Box::from_raw(callback_struct_ptr) },
            })
        }
    }

    unsafe extern "C" fn call_sample_cb(ctx: *mut c_void, cpu: i32, data: *mut c_void, size: u32) {
        let callback_struct = ctx as *mut CbStruct;

        if let Some(cb) = &mut (*callback_struct).sample_cb {
            cb(cpu, slice::from_raw_parts(data as *const u8, size as usize));
        }
    }

    unsafe extern "C" fn call_lost_cb(ctx: *mut c_void, cpu: i32, count: u64) {
        let callback_struct = ctx as *mut CbStruct;

        if let Some(cb) = &mut (*callback_struct).lost_cb {
            cb(cpu, count);
        }
    }
}

/// Represents a special kind of [`Map`]. Typically used to transfer data between
/// [`Program`]s and userspace.
#[allow(missing_debug_implementations)]
pub struct PerfBuffer<'b> {
    ptr: *mut libbpf_sys::perf_buffer,
    // Hold onto the box so it'll get dropped when PerfBuffer is dropped
    _cb_struct: Box<CbStruct<'b>>,
}

impl<'b> PerfBuffer<'b> {
    pub fn epoll_fd(&self) -> i32 {
        unsafe { libbpf_sys::perf_buffer__epoll_fd(self.ptr) }
    }

    pub fn poll(&self, timeout: Duration) -> Result<()> {
        let ret = unsafe { libbpf_sys::perf_buffer__poll(self.ptr, timeout.as_millis() as i32) };
        util::parse_ret(ret)
    }

    pub fn consume(&self) -> Result<()> {
        let ret = unsafe { libbpf_sys::perf_buffer__consume(self.ptr) };
        util::parse_ret(ret)
    }

    pub fn consume_buffer(&self, buf_idx: usize) -> Result<()> {
        let ret = unsafe {
            libbpf_sys::perf_buffer__consume_buffer(self.ptr, buf_idx as libbpf_sys::size_t)
        };
        util::parse_ret(ret)
    }

    pub fn buffer_cnt(&self) -> usize {
        unsafe { libbpf_sys::perf_buffer__buffer_cnt(self.ptr) as usize }
    }

    pub fn buffer_fd(&self, buf_idx: usize) -> Result<i32> {
        let ret =
            unsafe { libbpf_sys::perf_buffer__buffer_fd(self.ptr, buf_idx as libbpf_sys::size_t) };
        util::parse_ret_i32(ret)
    }
}

impl<'b> Drop for PerfBuffer<'b> {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::perf_buffer__free(self.ptr);
        }
    }
}
