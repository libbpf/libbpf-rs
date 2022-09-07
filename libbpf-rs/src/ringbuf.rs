use core::ffi::c_void;
use std::boxed::Box;
use std::os::raw::c_ulong;
use std::ptr;
use std::slice;
use std::time::Duration;

use crate::*;

type Cb<'a> = Box<dyn FnMut(&[u8]) -> i32 + 'a>;

#[allow(missing_debug_implementations)]
struct RingBufferCallback<'a> {
    cb: Cb<'a>,
}

impl<'a> RingBufferCallback<'a> {
    fn new<F>(cb: F) -> Self
    where
        F: FnMut(&[u8]) -> i32 + 'a,
    {
        RingBufferCallback { cb: Box::new(cb) }
    }
}

/// Builds [`RingBuffer`] instances.
///
/// `ringbuf`s are a special kind of [`Map`], used to transfer data between
/// [`Program`]s and userspace.  As of Linux 5.8, the `ringbuf` map is now
/// preferred over the `perf buffer`.
#[derive(Default)]
#[allow(missing_debug_implementations)]
pub struct RingBufferBuilder<'a> {
    fd_callbacks: Vec<(i32, RingBufferCallback<'a>)>,
}

impl<'a> RingBufferBuilder<'a> {
    pub fn new() -> Self {
        RingBufferBuilder {
            fd_callbacks: vec![],
        }
    }

    /// Add a new ringbuf `map` and associated `callback` to this ring buffer
    /// manager. The callback should take one argument, a slice of raw bytes,
    /// and return an i32.
    ///
    /// Non-zero return values in the callback will stop ring buffer consumption early.
    ///
    /// The callback provides a raw byte slice. You may find libraries such as
    /// [`plain`](https://crates.io/crates/plain) helpful.
    pub fn add<NewF>(&mut self, map: &Map, callback: NewF) -> Result<&mut Self>
    where
        NewF: FnMut(&[u8]) -> i32 + 'a,
    {
        if map.map_type() != MapType::RingBuf {
            return Err(Error::InvalidInput("Must use a RingBuf map".into()));
        }
        self.fd_callbacks
            .push((map.fd(), RingBufferCallback::new(callback)));
        Ok(self)
    }

    /// Build a new [`RingBuffer`]. Must have added at least one ringbuf.
    pub fn build(self) -> Result<RingBuffer<'a>> {
        let mut cbs = vec![];
        let mut ptr: *mut libbpf_sys::ring_buffer = ptr::null_mut();
        let c_sample_cb: libbpf_sys::ring_buffer_sample_fn = Some(Self::call_sample_cb);

        for (fd, callback) in self.fd_callbacks {
            let sample_cb_ptr = Box::into_raw(Box::new(callback));
            if ptr.is_null() {
                // Allocate a new ringbuf manager and add a ringbuf to it
                ptr = unsafe {
                    libbpf_sys::ring_buffer__new(
                        fd,
                        c_sample_cb,
                        sample_cb_ptr as *mut _,
                        std::ptr::null_mut(),
                    )
                };

                // Handle errors
                let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
                if err != 0 {
                    return Err(Error::System(err as i32));
                }
            } else {
                // Add a ringbuf to the existing ringbuf manager
                let err = unsafe {
                    libbpf_sys::ring_buffer__add(ptr, fd, c_sample_cb, sample_cb_ptr as *mut _)
                };

                // Handle errors
                if err != 0 {
                    return Err(Error::System(err as i32));
                }
            }

            unsafe { cbs.push(Box::from_raw(sample_cb_ptr)) };
        }

        if ptr.is_null() {
            return Err(Error::InvalidInput(
                "You must add at least one ring buffer map and callback before building".into(),
            ));
        }

        Ok(RingBuffer { ptr, _cbs: cbs })
    }

    unsafe extern "C" fn call_sample_cb(ctx: *mut c_void, data: *mut c_void, size: c_ulong) -> i32 {
        let callback_struct = ctx as *mut RingBufferCallback;
        let callback = (*callback_struct).cb.as_mut();

        callback(slice::from_raw_parts(data as *const u8, size as usize))
    }
}

/// The canonical interface for managing a collection of `ringbuf` maps.
///
/// `ringbuf`s are a special kind of [`Map`], used to transfer data between
/// [`Program`]s and userspace.  As of Linux 5.8, the `ringbuf` map is now
/// preferred over the `perf buffer`.
#[allow(missing_debug_implementations)]
pub struct RingBuffer<'a> {
    ptr: *mut libbpf_sys::ring_buffer,
    #[allow(clippy::vec_box)]
    _cbs: Vec<Box<RingBufferCallback<'a>>>,
}

impl<'a> RingBuffer<'a> {
    /// Poll from all open ring buffers, calling the registered callback for
    /// each one. Polls continually until we either run out of events to consume
    /// or `timeout` is reached.
    pub fn poll(&self, timeout: Duration) -> Result<()> {
        assert!(!self.ptr.is_null());

        let ret = unsafe { libbpf_sys::ring_buffer__poll(self.ptr, timeout.as_millis() as i32) };

        util::parse_ret(ret)
    }

    /// Greedily consume from all open ring buffers, calling the registered
    /// callback for each one. Consumes continually until we run out of events
    /// to consume or one of the callbacks returns a non-zero integer.
    pub fn consume(&self) -> Result<()> {
        assert!(!self.ptr.is_null());

        let ret = unsafe { libbpf_sys::ring_buffer__consume(self.ptr) };

        util::parse_ret(ret)
    }

    /// Get an fd that can be used to sleep until data is available
    pub fn epoll_fd(&self) -> i32 {
        assert!(!self.ptr.is_null());

        unsafe { libbpf_sys::ring_buffer__epoll_fd(self.ptr) }
    }
}

impl<'a> Drop for RingBuffer<'a> {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                libbpf_sys::ring_buffer__free(self.ptr);
            }
        }
    }
}
