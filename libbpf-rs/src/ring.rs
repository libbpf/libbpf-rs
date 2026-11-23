use std::cell::UnsafeCell;
use std::ops::Deref;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd as _;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::ptr;
use std::ptr::NonNull;
use std::slice;

use crate::util::validate_bpf_ret;
use crate::AsRawLibbpf;
use crate::Error;
use crate::ErrorExt as _;
use crate::MapCore;
use crate::MapType;
use crate::Result;

/// Copies of the records returned from an overwritable ring buffer.
///
/// The copies are stored in chunks that are never reallocated, so adding a
/// copy does not move the earlier ones.
#[derive(Debug, Default)]
struct Copies {
    chunks: Vec<Vec<u8>>,
}

impl Copies {
    /// Copy `len` bytes from `src` and return a pointer to the copy.
    ///
    /// # Safety
    /// `src` must be valid for reads of `len` bytes.
    unsafe fn push(&mut self, src: *const u8, len: usize, chunk_size: usize) -> *const u8 {
        let fits = self
            .chunks
            .last()
            .is_some_and(|chunk| chunk.capacity() - chunk.len() >= len);
        if !fits {
            let () = self.chunks.push(Vec::with_capacity(len.max(chunk_size)));
        }

        let chunk = self.chunks.last_mut().unwrap();
        let used = chunk.len();
        // SAFETY: The chunk has room for `len` more bytes.
        let dst = unsafe { chunk.as_mut_ptr().add(used) };
        // SAFETY: `src` is valid per the caller and `dst` per the above.
        let () = unsafe { copy_volatile(src, dst, len) };
        // SAFETY: The bytes up to the new length are initialized.
        let () = unsafe { chunk.set_len(used + len) };
        dst
    }

    /// Drop all copies, but keep one chunk for the next ones.
    fn clear(&mut self) {
        let () = self.chunks.truncate(1);
        if let Some(chunk) = self.chunks.first_mut() {
            let () = chunk.clear();
        }
    }
}

/// Copy `len` bytes from memory that the kernel may be writing to.
///
/// # Safety
/// `src` must be valid for reads and `dst` for writes of `len` bytes, and
/// the two must not overlap.
unsafe fn copy_volatile(src: *const u8, dst: *mut u8, len: usize) {
    const WORD: usize = size_of::<usize>();

    let mut off = 0;
    if src.cast::<usize>().is_aligned() {
        while off + WORD <= len {
            // SAFETY: In bounds and aligned per the above.
            let word = unsafe { src.add(off).cast::<usize>().read_volatile() };
            // SAFETY: In bounds; `dst` need not be aligned.
            let () = unsafe { dst.add(off).cast::<usize>().write_unaligned(word) };
            off += WORD;
        }
    }
    while off < len {
        // SAFETY: In bounds.
        let byte = unsafe { src.add(off).read_volatile() };
        // SAFETY: In bounds.
        let () = unsafe { dst.add(off).write(byte) };
        off += 1;
    }
}

/// A single BPF ring buffer that is consumed record by record, without a
/// callback.
///
/// [`next`][Ring::next] returns the next record without consuming it and
/// [`release`][Ring::release] consumes all records returned so far:
///
/// ```no_run
/// # use libbpf_rs::MapCore;
/// # use libbpf_rs::Ring;
/// # fn handle(_data: &[u8]) {}
/// # fn consume(map: &dyn MapCore) -> libbpf_rs::Result<()> {
/// let mut ring = Ring::new(map)?;
/// loop {
///     for record in &ring {
///         handle(&record);
///     }
///     if !ring.release() {
///         break;
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// [`release`][Ring::release] returns `false` once the caller can wait for
/// new data. To wait, poll the file descriptor returned by
/// [`as_fd`][AsFd::as_fd] until it is readable.
///
/// The `Ring` must be the only consumer of its ring buffer. While it exists,
/// don't consume the same map through another `Ring` or a
/// [`RingBuffer`][crate::RingBuffer], in this or any other process.
///
/// # Overwritable ring buffers
///
/// When a ring buffer created with `BPF_F_RB_OVERWRITE` is full, the
/// kernel overwrites its oldest records, possibly while they are being
/// read. For such a ring buffer [`next`][Ring::next] returns a copy of
/// the record. Use the copy only if [`invalidated`][Ring::invalidated]
/// returns `false` afterwards. The `Ring` keeps the copies until
/// [`release`][Ring::release] or [`rewind`][Ring::rewind] is called.
///
/// ```no_run
/// # use libbpf_rs::MapCore;
/// # use libbpf_rs::Ring;
/// # fn handle(_data: &[u8]) {}
/// # fn consume(map: &dyn MapCore) -> libbpf_rs::Result<()> {
/// let mut ring = Ring::new(map)?;
/// loop {
///     for record in &ring {
///         if ring.invalidated() {
///             break;
///         }
///         handle(&record);
///     }
///     if !ring.release() {
///         break;
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
#[doc(alias = "ring")]
pub struct Ring {
    ptr: NonNull<libbpf_sys::ring>,
    /// A duplicate of the map's file descriptor. `ring__new()` does not
    /// take ownership of the descriptor it is given.
    fd: OwnedFd,
    /// The size of the ring buffer in bytes.
    size: usize,
    /// Copies of the records returned since the last release or rewind, if
    /// the ring buffer is overwritable.
    copies: Option<UnsafeCell<Copies>>,
}

impl Ring {
    /// Create a `Ring` for the given ring buffer map.
    ///
    /// # Errors
    /// * If the map is not a ring buffer.
    /// * If the ring buffer is overwritable and the target is 32-bit, which libbpf does not
    ///   support.
    /// * If a system call or the underlying libbpf function fails.
    #[doc(alias = "ring__new")]
    pub fn new(map: &dyn MapCore) -> Result<Self> {
        if map.map_type() != MapType::RingBuf {
            return Err(Error::with_invalid_data("must use a RingBuf map"));
        }

        let flags = map.info()?.info.map_flags;
        let overwritable = flags & libbpf_sys::BPF_F_RB_OVERWRITE != 0;
        if overwritable && cfg!(target_pointer_width = "32") {
            return Err(Error::from_raw_os_error(libc::EOPNOTSUPP));
        }

        let fd = map.as_fd().try_clone_to_owned()?;
        // SAFETY: The file descriptor is valid and `opts` may be NULL.
        let ptr = unsafe { libbpf_sys::ring__new(fd.as_raw_fd(), ptr::null()) };
        let ptr = validate_bpf_ret(ptr).context("failed to create ring")?;
        // SAFETY: The pointer is valid.
        let size = unsafe { libbpf_sys::ring__size(ptr.as_ptr()) };

        Ok(Self {
            ptr,
            fd,
            size,
            copies: overwritable.then(UnsafeCell::default),
        })
    }

    /// Retrieve the next record, without consuming it.
    ///
    /// Returns `None` if there is nothing to consume.
    ///
    /// Records stay valid until [`release`][Ring::release] or
    /// [`rewind`][Ring::rewind] is called, so multiple records can be
    /// processed and then consumed together.
    #[doc(alias = "ring__next")]
    pub fn next(&self) -> Option<RingRecord<'_>> {
        // SAFETY: The pointer is valid.
        let rec = unsafe { libbpf_sys::ring__next(self.ptr.as_ptr()) };
        if rec.is_null() {
            // `ring__next()` also returns NULL on error, but it can't fail
            // for a ring created by `Ring::new`. So NULL means that there is
            // nothing to consume.
            return None;
        }
        // SAFETY: `ring__next()` returned a valid `ring_rec`. Read it out, as
        //         the next `ring__next()` call reuses it.
        let (data, len, pos) = unsafe { ((*rec).data, (*rec).len, (*rec).pos) };
        let data = data.cast::<u8>();
        let len = len as usize;

        let data = if let Some(copies) = &self.copies {
            // SAFETY: `Ring` is not `Sync` and nothing else accesses the
            //         contents of `copies` through `&self`, so the reference
            //         is unique.
            let copies = unsafe { &mut *copies.get() };
            // SAFETY: The record data is `len` bytes of the ring buffer
            //         mapping. The kernel may be writing to it, which is why
            //         it is copied and not handed out.
            unsafe { copies.push(data, len, self.size) }
        } else {
            data
        };
        // SAFETY: `data` points to `len` bytes that don't change while the
        //         returned record borrows the `Ring`, because `release` and
        //         `rewind` take `&mut self`. For a ring buffer that is not
        //         overwritable, `data` is in the ring buffer mapping, and
        //         the kernel reuses the space of a record only after
        //         `release` consumed it, as the `Ring` is the only consumer.
        //         For an overwritable one, `data` is a copy, which only
        //         `release` and `rewind` drop.
        let data = unsafe { slice::from_raw_parts(data, len) };

        Some(RingRecord {
            data,
            pos: pos as usize,
        })
    }

    /// Consume all records returned by [`next`][Ring::next] since the last
    /// release or rewind.
    ///
    /// Call this method before waiting for new data. If it returns `true`,
    /// call [`next`][Ring::next] again instead of waiting, as there may be no
    /// wakeup for records that were committed before the release. If it
    /// returns `false`, the caller can wait.
    #[doc(alias = "ring__release")]
    #[must_use = "if this returns `true`, call `next` again instead of waiting"]
    pub fn release(&mut self) -> bool {
        // SAFETY: The pointer is valid.
        let ret = unsafe { libbpf_sys::ring__release(self.ptr.as_ptr()) };
        debug_assert!(ret >= 0, "ring__release() failed: {ret}");
        let () = self.clear_copies();
        ret > 0
    }

    /// Go back to the first record that was not released, so that
    /// [`next`][Ring::next] returns the same records again.
    #[doc(alias = "ring__rewind")]
    pub fn rewind(&mut self) {
        // SAFETY: The pointer is valid.
        let () = unsafe { libbpf_sys::ring__rewind(self.ptr.as_ptr()) };
        let () = self.clear_copies();
    }

    /// Check if any of the records returned by [`next`][Ring::next] since
    /// the last release or rewind may have been overwritten.
    ///
    /// Always `false` for a ring buffer that is not overwritable.
    #[doc(alias = "ring__invalidated")]
    pub fn invalidated(&self) -> bool {
        // SAFETY: The pointer is valid.
        unsafe { libbpf_sys::ring__invalidated(self.ptr.as_ptr()) }
    }

    /// Retrieve the current consumer position.
    #[doc(alias = "ring__consumer_pos")]
    pub fn consumer_pos(&self) -> usize {
        // SAFETY: The pointer is valid.
        unsafe { libbpf_sys::ring__consumer_pos(self.ptr.as_ptr()) as usize }
    }

    /// Retrieve the current producer position.
    #[doc(alias = "ring__producer_pos")]
    pub fn producer_pos(&self) -> usize {
        // SAFETY: The pointer is valid.
        unsafe { libbpf_sys::ring__producer_pos(self.ptr.as_ptr()) as usize }
    }

    /// Retrieve the amount of data that is not consumed yet, in bytes.
    #[doc(alias = "ring__avail_data_size")]
    pub fn avail_data_size(&self) -> usize {
        // SAFETY: The pointer is valid.
        unsafe { libbpf_sys::ring__avail_data_size(self.ptr.as_ptr()) }
    }

    /// Retrieve the size of the ring buffer, in bytes.
    #[doc(alias = "ring__size")]
    pub fn size(&self) -> usize {
        self.size
    }

    fn clear_copies(&mut self) {
        if let Some(copies) = &mut self.copies {
            let () = copies.get_mut().clear();
        }
    }
}

impl<'ring> Iterator for &'ring Ring {
    type Item = RingRecord<'ring>;

    fn next(&mut self) -> Option<Self::Item> {
        Ring::next(self)
    }
}

impl AsFd for Ring {
    /// Retrieve a file descriptor for the ring buffer map. It is readable
    /// while the ring buffer has data that was not consumed yet.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawLibbpf for Ring {
    type LibbpfType = libbpf_sys::ring;

    /// Retrieve the underlying [`libbpf_sys::ring`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.ptr
    }
}

// SAFETY: A `ring` can be used from any thread, just not from several
//         threads at the same time.
unsafe impl Send for Ring {}

impl Drop for Ring {
    #[doc(alias = "ring__free")]
    fn drop(&mut self) {
        // SAFETY: The pointer is valid and was created by `ring__new()`.
        let () = unsafe { libbpf_sys::ring__free(self.ptr.as_ptr()) };
    }
}

/// A record returned by [`Ring::next`].
///
/// Dereference it to get the record data as a slice of raw bytes. You may
/// find libraries such as [`plain`](https://crates.io/crates/plain) helpful
/// to convert between raw bytes and structs.
#[derive(Clone, Copy, Debug)]
#[doc(alias = "ring_rec")]
pub struct RingRecord<'ring> {
    data: &'ring [u8],
    pos: usize,
}

impl RingRecord<'_> {
    /// Retrieve the position of the record in the ring buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }
}

impl Deref for RingRecord<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Check that `Ring` is `Send`.
    #[test]
    fn ring_is_send() {
        fn test<T>()
        where
            T: Send,
        {
        }

        test::<Ring>();
    }

    /// Check that `copy_volatile` copies all bytes, whatever the alignment.
    #[test]
    fn volatile_copy() {
        let src = (0..64u8).collect::<Vec<_>>();
        for start in 0..9 {
            for len in 0..40 {
                let mut dst = vec![0xffu8; len];
                // SAFETY: Both ranges are in bounds and don't overlap.
                let () = unsafe { copy_volatile(src[start..].as_ptr(), dst.as_mut_ptr(), len) };
                assert_eq!(dst, &src[start..start + len]);
            }
        }
    }

    /// Check that adding copies does not move the earlier ones.
    #[test]
    fn copies_stay_in_place() {
        let mut copies = Copies::default();
        let mut ptrs = Vec::new();
        for i in 0..100u8 {
            let src = [i; 24];
            // SAFETY: `src` is valid for reads of its length.
            let ptr = unsafe { copies.push(src.as_ptr(), src.len(), 64) };
            let () = ptrs.push(ptr);
        }
        // Too large for a chunk.
        let src = [0xaa; 200];
        // SAFETY: `src` is valid for reads of its length.
        let large = unsafe { copies.push(src.as_ptr(), src.len(), 64) };

        for (i, ptr) in ptrs.into_iter().enumerate() {
            // SAFETY: The copy is 24 bytes and `copies` was not cleared.
            let copy = unsafe { slice::from_raw_parts(ptr, 24) };
            assert_eq!(copy, [i as u8; 24]);
        }
        // SAFETY: The copy is 200 bytes and `copies` was not cleared.
        let copy = unsafe { slice::from_raw_parts(large, 200) };
        assert_eq!(copy, [0xaa; 200]);

        let () = copies.clear();
        assert_eq!(copies.chunks.len(), 1);
        assert!(copies.chunks[0].is_empty());
    }
}
