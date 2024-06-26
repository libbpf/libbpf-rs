use libc::E2BIG;
use libc::ENOSPC;
use std::io;
use std::ops::Deref;
use std::ops::DerefMut;
use std::os::fd::AsRawFd;
use std::os::raw::c_uint;
use std::os::raw::c_void;
use std::ptr::null_mut;
use std::ptr::NonNull;
use std::slice::from_raw_parts;
use std::slice::from_raw_parts_mut;

use crate::AsRawLibbpf;
use crate::Error;
use crate::MapCore;
use crate::MapType;
use crate::Result;

/// A mutable reference to sample from a [`UserRingBuffer`].
///
/// To write to the sample, dereference with `as_mut()` to get a mutable
/// reference to the raw byte slice. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful to convert between raw
/// bytes and structs.
#[derive(Debug)]
pub struct UserRingBufferSample<'slf> {
    // A pointer to an 8-byte aligned reserved region of the user ring buffer
    ptr: NonNull<c_void>,

    // The size of the sample in bytes.
    size: usize,

    // Reference to the owning ring buffer. This is used to discard the sample
    // if it is not submitted before being dropped.
    rb: &'slf UserRingBuffer,

    // Track whether the sample has been submitted.
    submitted: bool,
}

impl Deref for UserRingBufferSample<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { from_raw_parts(self.ptr.as_ptr() as *const u8, self.size) }
    }
}

impl DerefMut for UserRingBufferSample<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, self.size) }
    }
}

impl Drop for UserRingBufferSample<'_> {
    fn drop(&mut self) {
        // If the sample has not been submitted, explicitly discard it.
        // This is necessary to avoid leaking ring buffer memory.
        if !self.submitted {
            unsafe {
                libbpf_sys::user_ring_buffer__discard(self.rb.ptr.as_ptr(), self.ptr.as_ptr());
            }
        }
    }
}

/// Represents a user ring buffer. This is a special kind of map that is used to
/// transfer data between user space and kernel space.
#[derive(Debug)]
pub struct UserRingBuffer {
    // A non-null pointer to the underlying user ring buffer.
    ptr: NonNull<libbpf_sys::user_ring_buffer>,
}

impl UserRingBuffer {
    /// Create a new user ring buffer from a map.
    ///
    /// # Errors
    /// * If the map is not a user ring buffer.
    /// * If the underlying libbpf function fails.
    pub fn new(map: &dyn MapCore) -> Result<Self> {
        if map.map_type() != MapType::UserRingBuf {
            return Err(Error::with_invalid_data("must use a UserRingBuf map"));
        }

        let fd = map.as_fd();
        let raw_ptr = unsafe { libbpf_sys::user_ring_buffer__new(fd.as_raw_fd(), null_mut()) };

        let ptr = NonNull::new(raw_ptr).ok_or_else(|| {
            // Safely get the last OS error after a failed call to user_ring_buffer__new
            io::Error::last_os_error()
        })?;

        Ok(UserRingBuffer { ptr })
    }

    /// Reserve a sample in the user ring buffer.
    ///
    /// Returns a [`UserRingBufferSample`](UserRingBufferSample<'slf>)
    /// that contains a mutable reference to sample that can be written to.
    /// The sample must be submitted via [`UserRingBuffer::submit`] before it is
    /// dropped.
    ///
    /// # Parameters
    /// * `size` - The size of the sample in bytes.
    ///
    /// This function is *not* thread-safe. It is necessary to synchronize
    /// amongst multiple producers when invoking this function.
    pub fn reserve(&self, size: usize) -> Result<UserRingBufferSample<'_>> {
        let sample_ptr =
            unsafe { libbpf_sys::user_ring_buffer__reserve(self.ptr.as_ptr(), size as c_uint) };

        let ptr = NonNull::new(sample_ptr).ok_or_else(|| {
            // Fetch the current value of errno to determine the type of error.
            let errno = io::Error::last_os_error();
            match errno.raw_os_error() {
                Some(E2BIG) => Error::with_invalid_data("requested size is too large"),
                Some(ENOSPC) => Error::with_invalid_data("not enough space in the ring buffer"),
                _ => Error::from(errno),
            }
        })?;

        Ok(UserRingBufferSample {
            ptr,
            size,
            submitted: false,
            rb: self,
        })
    }

    /// Submit a sample to the user ring buffer.
    ///
    /// This function takes ownership of the sample and submits it to the ring
    /// buffer. After submission, the consumer will be able to read the sample
    /// from the ring buffer.
    ///
    /// This function is thread-safe. It is *not* necessary to synchronize
    /// amongst multiple producers when invoking this function.
    pub fn submit(&self, mut sample: UserRingBufferSample<'_>) -> Result<()> {
        unsafe {
            libbpf_sys::user_ring_buffer__submit(self.ptr.as_ptr(), sample.ptr.as_ptr());
        }

        sample.submitted = true;

        // The libbpf API does not return an error code, so we cannot determine
        // if the submission was successful. Return a `Result` to enable future
        // validation while maintaining backwards compatibility.
        Ok(())
    }
}

impl AsRawLibbpf for UserRingBuffer {
    type LibbpfType = libbpf_sys::user_ring_buffer;

    /// Retrieve the underlying [`libbpf_sys::user_ring_buffer`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.ptr
    }
}

impl Drop for UserRingBuffer {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::user_ring_buffer__free(self.ptr.as_ptr());
        }
    }
}
