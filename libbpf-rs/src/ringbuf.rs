use core::ffi::c_void;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::ops::Deref as _;
use std::ops::DerefMut as _;
use std::os::raw::c_ulong;
use std::os::unix::prelude::AsRawFd;
use std::os::unix::prelude::BorrowedFd;
use std::ptr::null_mut;
use std::ptr::NonNull;
use std::slice;
use std::time::Duration;

use crate::util;
use crate::util::validate_bpf_ret;
use crate::AsRawLibbpf;
use crate::Error;
use crate::ErrorExt as _;
use crate::MapCore;
use crate::MapType;
use crate::Result;

type Cb<'a> = Box<dyn FnMut(&[u8]) -> i32 + 'a>;

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

impl Debug for RingBufferCallback<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let Self { cb } = self;
        f.debug_struct("RingBufferCallback")
            .field("cb", &(cb.deref() as *const _))
            .finish()
    }
}

/// Builds [`RingBuffer`] instances.
///
/// `ringbuf`s are a special kind of [`Map`][crate::Map], used to transfer data
/// between [`Program`][crate::Program]s and userspace. As of Linux 5.8, the
/// `ringbuf` map is now preferred over the `perf buffer`.
#[derive(Debug, Default)]
pub struct RingBufferBuilder<'slf, 'cb> {
    fd_callbacks: Vec<(BorrowedFd<'slf>, RingBufferCallback<'cb>)>,
}

impl<'slf, 'cb: 'slf> RingBufferBuilder<'slf, 'cb> {
    /// Create a new `RingBufferBuilder` object.
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
    pub fn add<NewF>(&mut self, map: &'slf dyn MapCore, callback: NewF) -> Result<&mut Self>
    where
        NewF: FnMut(&[u8]) -> i32 + 'cb,
    {
        if map.map_type() != MapType::RingBuf {
            return Err(Error::with_invalid_data("Must use a RingBuf map"));
        }
        self.fd_callbacks
            .push((map.as_fd(), RingBufferCallback::new(callback)));
        Ok(self)
    }

    /// Build a new [`RingBuffer`]. Must have added at least one ringbuf.
    pub fn build(self) -> Result<RingBuffer<'cb>> {
        let mut cbs = vec![];
        let mut rb_ptr: Option<NonNull<libbpf_sys::ring_buffer>> = None;
        let c_sample_cb: libbpf_sys::ring_buffer_sample_fn = Some(Self::call_sample_cb);

        for (fd, callback) in self.fd_callbacks {
            let mut sample_cb = Box::new(callback);
            match rb_ptr {
                None => {
                    // Allocate a new ringbuf manager and add a ringbuf to it
                    // SAFETY: All pointers are valid or rightly NULL.
                    //         The object referenced by `sample_cb` is
                    //         not modified by `libbpf`
                    let ptr = unsafe {
                        libbpf_sys::ring_buffer__new(
                            fd.as_raw_fd(),
                            c_sample_cb,
                            sample_cb.deref_mut() as *mut _ as *mut _,
                            null_mut(),
                        )
                    };
                    let ptr = validate_bpf_ret(ptr).context("failed to create new ring buffer")?;
                    rb_ptr = Some(ptr)
                }
                Some(mut ptr) => {
                    // Add a ringbuf to the existing ringbuf manager
                    // SAFETY: All pointers are valid or rightly NULL.
                    //         The object referenced by `sample_cb` is
                    //         not modified by `libbpf`
                    let err = unsafe {
                        libbpf_sys::ring_buffer__add(
                            ptr.as_ptr(),
                            fd.as_raw_fd(),
                            c_sample_cb,
                            sample_cb.deref_mut() as *mut _ as *mut _,
                        )
                    };

                    // Handle errors
                    if err != 0 {
                        // SAFETY: The pointer is valid.
                        let () = unsafe { libbpf_sys::ring_buffer__free(ptr.as_mut()) };
                        return Err(Error::from_raw_os_error(err));
                    }
                }
            }

            let () = cbs.push(sample_cb);
        }

        match rb_ptr {
            Some(ptr) => Ok(RingBuffer { ptr, _cbs: cbs }),
            None => Err(Error::with_invalid_data(
                "You must add at least one ring buffer map and callback before building",
            )),
        }
    }

    unsafe extern "C" fn call_sample_cb(ctx: *mut c_void, data: *mut c_void, size: c_ulong) -> i32 {
        let callback_struct = ctx as *mut RingBufferCallback<'_>;
        let callback = unsafe { (*callback_struct).cb.as_mut() };
        let slice = unsafe { slice::from_raw_parts(data as *const u8, size as usize) };

        callback(slice)
    }
}

/// The canonical interface for managing a collection of `ringbuf` maps.
///
/// `ringbuf`s are a special kind of [`Map`][crate::Map], used to transfer data
/// between [`Program`][crate::Program]s and userspace. As of Linux 5.8, the
/// `ringbuf` map is now preferred over the `perf buffer`.
#[derive(Debug)]
pub struct RingBuffer<'cb> {
    ptr: NonNull<libbpf_sys::ring_buffer>,
    #[allow(clippy::vec_box)]
    _cbs: Vec<Box<RingBufferCallback<'cb>>>,
}

impl RingBuffer<'_> {
    /// Poll from all open ring buffers, calling the registered callback for
    /// each one. Polls continually until we either run out of events to consume
    /// or `timeout` is reached. If `timeout` is Duration::MAX, this will block
    /// indefinitely until an event occurs.
    ///
    /// Return the amount of events consumed, or a negative value in case of error.
    pub fn poll_raw(&self, timeout: Duration) -> i32 {
        let mut timeout_ms = -1;
        if timeout != Duration::MAX {
            timeout_ms = timeout.as_millis() as i32;
        }

        unsafe { libbpf_sys::ring_buffer__poll(self.ptr.as_ptr(), timeout_ms) }
    }

    /// Poll from all open ring buffers, calling the registered callback for
    /// each one. Polls continually until we either run out of events to consume
    /// or `timeout` is reached. If `timeout` is Duration::MAX, this will block
    /// indefinitely until an event occurs.
    pub fn poll(&self, timeout: Duration) -> Result<()> {
        let ret = self.poll_raw(timeout);

        util::parse_ret(ret)
    }

    /// Greedily consume from all open ring buffers, calling the registered
    /// callback for each one. Consumes continually until we run out of events
    /// to consume or one of the callbacks returns a non-zero integer.
    ///
    /// Return the amount of events consumed, or a negative value in case of error.
    pub fn consume_raw(&self) -> i32 {
        unsafe { libbpf_sys::ring_buffer__consume(self.ptr.as_ptr()) }
    }

    /// Greedily consume from all open ring buffers, calling the registered
    /// callback for each one. Consumes continually until we run out of events
    /// to consume or one of the callbacks returns a non-zero integer.
    pub fn consume(&self) -> Result<()> {
        let ret = self.consume_raw();

        util::parse_ret(ret)
    }

    /// Get an fd that can be used to sleep until data is available
    pub fn epoll_fd(&self) -> i32 {
        unsafe { libbpf_sys::ring_buffer__epoll_fd(self.ptr.as_ptr()) }
    }
}

impl AsRawLibbpf for RingBuffer<'_> {
    type LibbpfType = libbpf_sys::ring_buffer;

    /// Retrieve the underlying [`libbpf_sys::ring_buffer`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.ptr
    }
}

// SAFETY: `ring_buffer` objects can safely be polled from any thread.
unsafe impl Send for RingBuffer<'_> {}

impl Drop for RingBuffer<'_> {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::ring_buffer__free(self.ptr.as_ptr());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Check that `RingBuffer` is `Send`.
    #[test]
    fn ringbuffer_is_send() {
        fn test<T>()
        where
            T: Send,
        {
        }

        test::<RingBuffer<'_>>();
    }
}
