use core::ffi::c_void;
use std::boxed::Box;
use std::ptr;
use std::slice;
use std::time::Duration;

use crate::*;

/// The canonical interface for managing a collection of [`RingBuffer`]s.
///
/// `ringbuf`s are a special kind of [`Map`], used to transfer data between
/// [`Program`]s and userspace.  As of Linux 5.8, the `ringbuf` map is now
/// preferred over the `perf buffer`.
pub struct RingBufferManager<F>
where
    F: FnMut(&[u8]) -> i32 + 'static,
{
    ptr: *mut libbpf_sys::ring_buffer,
    ringbufs: Vec<Box<F>>,
}

impl<F> RingBufferManager<F>
where
    F: FnMut(&[u8]) -> i32 + 'static,
{
    /// Add a new ringbuf `map` and associated `callback` to this ring buffer
    /// manager. The callback should take one argument, a slice of raw bytes,
    /// and return an i32.
    ///
    /// Non-zero return values will stop ring buffer consumption early.
    ///
    /// The callback provides a raw byte slice. You may find libraries such as
    /// [`plain`](https://crates.io/crates/plain) helpful.
    pub fn add_ringbuf(&mut self, map: &Map, callback: F) -> Result<&mut Self> {
        let callback = Box::new(callback);
        let c_sample_cb: libbpf_sys::ring_buffer_sample_fn = Some(Self::call_sample_cb);
        let sample_cb_ptr = Box::into_raw(callback);

        if self.ptr.is_null() {
            // Allocate a new ringbuf manager
            self.ptr = unsafe {
                libbpf_sys::ring_buffer__new(
                    map.fd(),
                    c_sample_cb,
                    sample_cb_ptr as *mut _,
                    std::ptr::null_mut(),
                )
            };

            // Handle errors
            let err = unsafe { libbpf_sys::libbpf_get_error(self.ptr as *const _) };
            if err != 0 {
                return Err(Error::System(err as i32));
            }
        } else {
            // Add a ringbuf to the existing ringbuf manager
            let err = unsafe {
                libbpf_sys::ring_buffer__add(
                    self.ptr,
                    map.fd(),
                    c_sample_cb,
                    sample_cb_ptr as *mut _,
                )
            };

            // Handle errors
            if err != 0 {
                return Err(Error::System(err as i32));
            }
        }

        self.ringbufs.push(unsafe { Box::from_raw(sample_cb_ptr) });

        Ok(self)
    }

    /// Poll from all open ring buffers, calling the registered callback for
    /// each one. Polls continually until we either run out of events to consume
    /// or `timeout` is reached.
    pub fn poll(&self, timeout: Duration) -> Result<()> {
        if self.ptr.is_null() {
            return Err(Error::InvalidInput(
                "You must add at least one ring buffer before polling".into(),
            ));
        }

        let ret = unsafe { libbpf_sys::ring_buffer__poll(self.ptr, timeout.as_millis() as i32) };

        if ret < 0 {
            Err(Error::System(-ret))
        } else {
            Ok(())
        }
    }

    /// Greedily consume from all open ring buffers, calling the registered
    /// callback for each one. Consumes continually until we run out of events
    /// to consume or one of the callbacks returns a non-zero integer.
    pub fn consume(&self) -> Result<()> {
        if self.ptr.is_null() {
            return Err(Error::InvalidInput(
                "You must add at least one ring buffer before consuming".into(),
            ));
        }

        let ret = unsafe { libbpf_sys::ring_buffer__consume(self.ptr) };

        if ret < 0 {
            Err(Error::System(-ret))
        } else {
            Ok(())
        }
    }

    unsafe extern "C" fn call_sample_cb(ctx: *mut c_void, data: *mut c_void, size: u64) -> i32 {
        let callback_ptr = ctx as *mut F;
        let callback = &mut *callback_ptr;

        callback(slice::from_raw_parts(data as *const u8, size as usize))
    }
}

impl<F> Default for RingBufferManager<F>
where
    F: FnMut(&[u8]) -> i32,
{
    fn default() -> Self {
        Self {
            ptr: ptr::null_mut(),
            ringbufs: vec![],
        }
    }
}

impl<F> Drop for RingBufferManager<F>
where
    F: FnMut(&[u8]) -> i32,
{
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                libbpf_sys::ring_buffer__free(self.ptr);
            }
        }
    }
}
