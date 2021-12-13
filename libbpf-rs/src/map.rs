use core::ffi::c_void;
use std::convert::TryFrom;
use std::path::Path;
use std::ptr;

use bitflags::bitflags;
use nix::{errno, unistd};
use num_enum::TryFromPrimitive;
use strum_macros::Display;

use crate::*;

/// Represents a parsed but not yet loaded BPF map.
///
/// This object exposes operations that need to happen before the map is created.
///
/// Some methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
pub struct OpenMap {
    ptr: *mut libbpf_sys::bpf_map,
}

impl OpenMap {
    pub(crate) fn new(ptr: *mut libbpf_sys::bpf_map) -> Self {
        OpenMap { ptr }
    }

    pub fn set_map_ifindex(&mut self, idx: u32) {
        unsafe { libbpf_sys::bpf_map__set_ifindex(self.ptr, idx) };
    }

    pub fn set_initial_value(&mut self, data: &[u8]) -> Result<()> {
        let ret = unsafe {
            libbpf_sys::bpf_map__set_initial_value(
                self.ptr,
                data.as_ptr() as *const std::ffi::c_void,
                data.len() as libbpf_sys::size_t,
            )
        };

        if ret != 0 {
            // Error code is returned negative, flip to positive to match errno
            return Err(Error::System(-ret));
        }

        Ok(())
    }

    pub fn set_max_entries(&mut self, count: u32) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__set_max_entries(self.ptr, count) };

        if ret != 0 {
            // Error code is returned negative, flip to positive to match errno
            return Err(Error::System(-ret));
        }

        Ok(())
    }

    pub fn set_inner_map_fd(&mut self, inner: &Map) {
        unsafe { libbpf_sys::bpf_map__set_inner_map_fd(self.ptr, inner.fd()) };
    }

    /// Reuse an already-pinned map for `self`.
    pub fn reuse_pinned_map<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let cstring = util::path_to_cstring(path)?;

        let fd = unsafe { libbpf_sys::bpf_obj_get(cstring.as_ptr()) };
        if fd < 0 {
            return Err(Error::System(errno::errno()));
        }

        let ret = unsafe { libbpf_sys::bpf_map__reuse_fd(self.ptr, fd) };

        // Always close `fd` regardless of if `bpf_map__reuse_fd` succeeded or failed
        //
        // Ignore errors b/c can't really recover from failure
        let _ = unistd::close(fd);

        if ret != 0 {
            return Err(Error::System(-ret));
        }

        Ok(())
    }
}

/// Represents a created map.
///
/// Some methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
pub struct Map {
    fd: i32,
    name: String,
    ty: libbpf_sys::bpf_map_type,
    key_size: u32,
    value_size: u32,
    ptr: *mut libbpf_sys::bpf_map,
}

impl Map {
    pub(crate) fn new(
        fd: i32,
        name: String,
        ty: libbpf_sys::bpf_map_type,
        key_size: u32,
        value_size: u32,
        ptr: *mut libbpf_sys::bpf_map,
    ) -> Self {
        Map {
            fd,
            name,
            ty,
            key_size,
            value_size,
            ptr,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a file descriptor to the underlying map.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    pub fn map_type(&self) -> MapType {
        match MapType::try_from(self.ty) {
            Ok(t) => t,
            Err(_) => MapType::Unknown,
        }
    }

    /// Key size in bytes
    pub fn key_size(&self) -> u32 {
        self.key_size
    }

    /// Value size in bytes
    pub fn value_size(&self) -> u32 {
        self.value_size
    }

    /// Return the size of one value including padding for interacting with per-cpu
    /// maps. The values are aligned to 8 bytes.
    fn percpu_aligned_value_size(&self) -> usize {
        let val_size = self.value_size() as usize;
        util::roundup(val_size, 8)
    }

    /// Returns the size of the buffer needed for a lookup/update of a per-cpu map.
    fn percpu_buffer_size(&self) -> Result<usize> {
        let aligned_val_size = self.percpu_aligned_value_size();
        let ncpu = util::num_possible_cpus()?;
        Ok(ncpu * aligned_val_size)
    }

    /// [Pin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this map to bpffs.
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_map__pin(self.ptr, path_ptr) };
        if ret != 0 {
            // Error code is returned negative, flip to positive to match errno
            Err(Error::System(-ret))
        } else {
            Ok(())
        }
    }

    /// [Unpin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// from bpffs
    pub fn unpin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_map__unpin(self.ptr, path_ptr) };
        if ret != 0 {
            // Error code is returned negative, flip to positive to match errno
            Err(Error::System(-ret))
        } else {
            Ok(())
        }
    }

    /// Returns map value as `Vec` of `u8`.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    ///
    /// If the map is one of the per-cpu data structures, the function [`Map::lookup_percpu()`]
    /// must be used.
    pub fn lookup(&self, key: &[u8], flags: MapFlags) -> Result<Option<Vec<u8>>> {
        if self.map_type().is_percpu() {
            return Err(Error::InvalidInput(format!(
                "lookup_percpu() must be used for per-cpu maps (type of the map is {})",
                self.map_type(),
            )));
        }

        let out_size = self.value_size() as usize;
        self.lookup_raw(key, flags, out_size)
    }

    /// Returns one value per cpu as `Vec` of `Vec` of `u8` for per per-cpu maps.
    ///
    /// For normal maps, [`Map::lookup()`] must be used.
    pub fn lookup_percpu(&self, key: &[u8], flags: MapFlags) -> Result<Option<Vec<Vec<u8>>>> {
        if !self.map_type().is_percpu() && self.map_type() != MapType::Unknown {
            return Err(Error::InvalidInput(format!(
                "lookup() must be used for maps that are not per-cpu (type of the map is {})",
                self.map_type(),
            )));
        }

        let val_size = self.value_size() as usize;
        let aligned_val_size = self.percpu_aligned_value_size();
        let out_size = self.percpu_buffer_size()?;

        let raw_res = self.lookup_raw(key, flags, out_size)?;
        if let Some(raw_vals) = raw_res {
            let mut out = Vec::new();
            for chunk in raw_vals.chunks_exact(aligned_val_size) {
                out.push(chunk[..val_size].to_vec());
            }
            Ok(Some(out))
        } else {
            Ok(None)
        }
    }

    /// Internal function to return a value from a map into a buffer of the given size.
    fn lookup_raw(&self, key: &[u8], flags: MapFlags, out_size: usize) -> Result<Option<Vec<u8>>> {
        if key.len() != self.key_size() as usize {
            return Err(Error::InvalidInput(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        let mut out: Vec<u8> = Vec::with_capacity(out_size);

        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_elem_flags(
                self.fd as i32,
                key.as_ptr() as *const c_void,
                out.as_mut_ptr() as *mut c_void,
                flags.bits,
            )
        };

        if ret == 0 {
            unsafe {
                out.set_len(out_size);
            }
            Ok(Some(out))
        } else {
            let errno = errno::errno();
            if errno::Errno::from_i32(errno) == errno::Errno::ENOENT {
                Ok(None)
            } else {
                Err(Error::System(errno))
            }
        }
    }

    /// Deletes an element from the map.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != self.key_size() as usize {
            return Err(Error::InvalidInput(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        let ret = unsafe {
            libbpf_sys::bpf_map_delete_elem(self.fd as i32, key.as_ptr() as *const c_void)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(Error::System(errno::errno()))
        }
    }

    /// Same as [`Map::lookup()`] except this also deletes the key from the map.
    ///
    /// Note that this operation is currently only implemented in the kernel for [`MapType::Queue`]
    /// and [`MapType::Stack`].
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn lookup_and_delete(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if key.len() != self.key_size() as usize {
            return Err(Error::InvalidInput(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        let mut out: Vec<u8> = Vec::with_capacity(self.value_size() as usize);

        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_and_delete_elem(
                self.fd as i32,
                key.as_ptr() as *const c_void,
                out.as_mut_ptr() as *mut c_void,
            )
        };

        if ret == 0 {
            unsafe {
                out.set_len(self.value_size() as usize);
            }
            Ok(Some(out))
        } else {
            let errno = errno::errno();
            if errno::Errno::from_i32(errno) == errno::Errno::ENOENT {
                Ok(None)
            } else {
                Err(Error::System(errno))
            }
        }
    }

    /// Update an element.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements. `value` must have exactly
    /// [`Map::value_size()`] elements.
    ///
    /// For per-cpu maps, [`Map::update_percpu()`] must be used.
    pub fn update(&mut self, key: &[u8], value: &[u8], flags: MapFlags) -> Result<()> {
        if self.map_type().is_percpu() {
            return Err(Error::InvalidInput(format!(
                "update_percpu() must be used for per-cpu maps (type of the map is {})",
                self.map_type(),
            )));
        }

        if value.len() != self.value_size() as usize {
            return Err(Error::InvalidInput(format!(
                "value_size {} != {}",
                value.len(),
                self.value_size()
            )));
        };

        self.update_raw(key, value, flags)
    }

    /// Update an element in an per-cpu map with one value per cpu.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements. `value` must have one
    /// element per cpu (see [`num_possible_cpus()`]) with exactly [`Map::value_size()`]
    /// elements each.
    ///
    /// For per-cpu maps, [`Map::update_percpu()`] must be used.
    pub fn update_percpu(&mut self, key: &[u8], values: &[Vec<u8>], flags: MapFlags) -> Result<()> {
        if !self.map_type().is_percpu() && self.map_type() != MapType::Unknown {
            return Err(Error::InvalidInput(format!(
                "update() must be used for maps that are not per-cpu (type of the map is {})",
                self.map_type(),
            )));
        }

        if values.len() != num_possible_cpus()? {
            return Err(Error::InvalidInput(format!(
                "number of values {} != number of cpus {}",
                values.len(),
                num_possible_cpus()?
            )));
        };

        let val_size = self.value_size() as usize;
        let aligned_val_size = self.percpu_aligned_value_size();
        let buf_size = self.percpu_buffer_size()?;

        let mut value_buf = Vec::new();
        value_buf.resize(buf_size, 0);

        for (i, val) in values.iter().enumerate() {
            if val.len() != val_size {
                return Err(Error::InvalidInput(format!(
                    "value size for cpu {} is {} != {}",
                    i,
                    val.len(),
                    val_size
                )));
            }

            value_buf[(i * aligned_val_size)..(i * aligned_val_size + val_size)]
                .copy_from_slice(val);
        }

        self.update_raw(key, &value_buf, flags)
    }

    /// Internal function to update a map. This does not check the length of the
    /// supplied value.
    fn update_raw(&mut self, key: &[u8], value: &[u8], flags: MapFlags) -> Result<()> {
        if key.len() != self.key_size() as usize {
            return Err(Error::InvalidInput(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        let ret = unsafe {
            libbpf_sys::bpf_map_update_elem(
                self.fd as i32,
                key.as_ptr() as *const c_void,
                value.as_ptr() as *const c_void,
                flags.bits,
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(Error::System(errno::errno()))
        }
    }

    /// Returns an iterator over keys in this map
    ///
    /// Note that if the map is not stable (stable meaning no updates or deletes) during iteration,
    /// iteration can skip keys, restart from the beginning, or duplicate keys. In other words,
    /// iteration becomes unpredictable.
    pub fn keys(&self) -> MapKeyIter {
        MapKeyIter::new(self, self.key_size())
    }
}

#[rustfmt::skip]
bitflags! {
    /// Flags to configure [`Map`] operations.
    pub struct MapFlags: u64 {
	const ANY      = 0;
	const NO_EXIST = 1;
	const EXIST    = 1 << 1;
	const LOCK     = 1 << 2;
    }
}

/// Type of a [`Map`]. Maps to `enum bpf_map_type` in kernel uapi.
// If you add a new per-cpu map, also update `is_percpu`.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, TryFromPrimitive, PartialEq, Display)]
pub enum MapType {
    Unspec = 0,
    Hash,
    Array,
    ProgArray,
    PerfEventArray,
    PercpuHash,
    PercpuArray,
    StackTrace,
    CgroupArray,
    LruHash,
    LruPercpuHash,
    LpmTrie,
    ArrayOfMaps,
    HashOfMaps,
    Devmap,
    Sockmap,
    Cpumap,
    Xskmap,
    Sockhash,
    CgroupStorage,
    ReuseportSockarray,
    PercpuCgroupStorage,
    Queue,
    Stack,
    SkStorage,
    DevmapHash,
    StructOps,
    RingBuf,
    /// We choose to specify our own "unknown" type here b/c it's really up to the kernel
    /// to decide if it wants to reject the map. If it accepts it, it just means whoever
    /// using this library is a bit out of date.
    Unknown = u32::MAX,
}

impl MapType {
    /// Returns if the map is of one of the per-cpu types.
    pub fn is_percpu(&self) -> bool {
        matches!(
            self,
            MapType::PercpuArray
                | MapType::PercpuHash
                | MapType::LruPercpuHash
                | MapType::PercpuCgroupStorage
        )
    }
}

pub struct MapKeyIter<'a> {
    map: &'a Map,
    prev: Option<Vec<u8>>,
    next: Vec<u8>,
}

impl<'a> MapKeyIter<'a> {
    fn new(map: &'a Map, key_size: u32) -> Self {
        Self {
            map,
            prev: None,
            next: vec![0; key_size as usize],
        }
    }
}

impl<'a> Iterator for MapKeyIter<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let prev = self.prev.as_ref().map_or(ptr::null(), |p| p.as_ptr());

        let ret = unsafe {
            libbpf_sys::bpf_map_get_next_key(self.map.fd(), prev as _, self.next.as_mut_ptr() as _)
        };
        if ret != 0 {
            None
        } else {
            self.prev = Some(self.next.clone());
            Some(self.next.clone())
        }
    }
}
