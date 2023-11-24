use core::ffi::c_void;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fs::remove_file;
use std::mem;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::BorrowedFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::OwnedFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::ptr;
use std::ptr::NonNull;
use std::slice::from_raw_parts;

use bitflags::bitflags;
use libbpf_sys::bpf_map_info;
use libbpf_sys::bpf_obj_get_info_by_fd;
use nix::errno;
use nix::unistd;
use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;
use strum_macros::Display;

use crate::util;
use crate::util::parse_ret_i32;
use crate::AsRawLibbpf;
use crate::Error;
use crate::ErrorExt as _;
use crate::Link;
use crate::Result;

/// Represents a parsed but not yet loaded BPF map.
///
/// This object exposes operations that need to happen before the map is created.
///
/// Some methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
#[derive(Debug)]
pub struct OpenMap {
    ptr: NonNull<libbpf_sys::bpf_map>,
}

// TODO: Document members.
#[allow(missing_docs)]
impl OpenMap {
    /// Create a new [`OpenMap`] from a ptr to a `libbpf_sys::bpf_map`.
    ///
    /// # Safety
    /// The pointer must point to an opened but not loaded map.
    pub(crate) unsafe fn new(ptr: NonNull<libbpf_sys::bpf_map>) -> Self {
        Self { ptr }
    }

    /// Retrieve the `Map`'s name.
    pub fn name(&self) -> Result<&str> {
        let name_ptr = unsafe { libbpf_sys::bpf_map__name(self.ptr.as_ptr()) };
        let name_c_str = unsafe { CStr::from_ptr(name_ptr) };
        name_c_str.to_str().map_err(Error::with_invalid_data)
    }

    /// Retrieve type of the map.
    pub fn map_type(&self) -> MapType {
        let ty = unsafe { libbpf_sys::bpf_map__type(self.ptr.as_ptr()) };
        match MapType::try_from(ty) {
            Ok(t) => t,
            Err(_) => MapType::Unknown,
        }
    }

    pub fn set_map_ifindex(&mut self, idx: u32) {
        unsafe { libbpf_sys::bpf_map__set_ifindex(self.ptr.as_ptr(), idx) };
    }

    pub fn set_initial_value(&mut self, data: &[u8]) -> Result<()> {
        let ret = unsafe {
            libbpf_sys::bpf_map__set_initial_value(
                self.ptr.as_ptr(),
                data.as_ptr() as *const c_void,
                data.len() as libbpf_sys::size_t,
            )
        };

        util::parse_ret(ret)
    }

    pub fn set_type(&mut self, ty: MapType) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__set_type(self.ptr.as_ptr(), ty as u32) };
        util::parse_ret(ret)
    }

    pub fn set_key_size(&mut self, size: u32) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__set_key_size(self.ptr.as_ptr(), size) };
        util::parse_ret(ret)
    }

    pub fn set_value_size(&mut self, size: u32) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__set_value_size(self.ptr.as_ptr(), size) };
        util::parse_ret(ret)
    }

    pub fn set_max_entries(&mut self, count: u32) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__set_max_entries(self.ptr.as_ptr(), count) };
        util::parse_ret(ret)
    }

    pub fn set_map_flags(&mut self, flags: u32) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__set_map_flags(self.ptr.as_ptr(), flags) };
        util::parse_ret(ret)
    }

    pub fn set_numa_node(&mut self, numa_node: u32) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__set_numa_node(self.ptr.as_ptr(), numa_node) };
        util::parse_ret(ret)
    }

    pub fn set_inner_map_fd(&mut self, inner: &Map) {
        unsafe {
            libbpf_sys::bpf_map__set_inner_map_fd(self.ptr.as_ptr(), inner.as_fd().as_raw_fd())
        };
    }

    pub fn set_map_extra(&mut self, map_extra: u64) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__set_map_extra(self.ptr.as_ptr(), map_extra) };
        util::parse_ret(ret)
    }

    pub fn set_autocreate(&mut self, autocreate: bool) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__set_autocreate(self.ptr.as_ptr(), autocreate) };
        util::parse_ret(ret)
    }

    pub fn set_pin_path<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_map__set_pin_path(self.ptr.as_ptr(), path_ptr) };
        util::parse_ret(ret)
    }

    /// Reuse an fd for a BPF map
    pub fn reuse_fd(&self, fd: i32) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map__reuse_fd(self.ptr.as_ptr(), fd) };
        util::parse_ret(ret)
    }

    /// Reuse an already-pinned map for `self`.
    pub fn reuse_pinned_map<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let cstring = util::path_to_cstring(path)?;

        let fd = unsafe { libbpf_sys::bpf_obj_get(cstring.as_ptr()) };
        if fd < 0 {
            return Err(Error::from_raw_os_error(errno::errno()));
        }
        let reuse_result = self.reuse_fd(fd);

        // Always close `fd` regardless of if `reuse_fd` succeeded or failed
        //
        // Ignore errors b/c can't really recover from failure
        let _ = unistd::close(fd);

        reuse_result
    }
}

impl AsRawLibbpf for OpenMap {
    type LibbpfType = libbpf_sys::bpf_map;

    /// Retrieve the underlying [`libbpf_sys::bpf_map`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.ptr
    }
}

#[derive(Debug)]
enum MapFd {
    Owned(OwnedFd),
    Borrowed(RawFd),
}

impl AsFd for MapFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Owned(o) => o.as_fd(),
            Self::Borrowed(fd) => unsafe {
                // SAFETY
                // This filedescriptor is open because of two invariants:
                // - This variant is only constructed in `Map::new`, which is the entry point for
                // when the map doesn't own the descriptor
                // - That method is crate private and called only by the `Object` which has its own
                // invariant that it outlives every `Map` it owns and cleans then up when dropped,
                // thus this fd must be live.
                BorrowedFd::borrow_raw(*fd)
            },
        }
    }
}

impl AsRawFd for MapFd {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Owned(o) => o.as_raw_fd(),
            Self::Borrowed(fd) => *fd,
        }
    }
}

/// Represents a libbpf-created map.
///
/// Some methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
#[derive(Debug)]
pub struct Map {
    handle: MapHandle,
    ptr: NonNull<libbpf_sys::bpf_map>,
}

impl Map {
    /// Create a [`Map`] from a [`libbpf_sys::bpf_map`].
    ///
    /// # Safety
    ///
    /// The pointer must point to a loaded map.
    pub(crate) unsafe fn new(ptr: NonNull<libbpf_sys::bpf_map>) -> Result<Self> {
        // Get the map name
        // SAFETY:
        // bpf_map__name can return null but only if it's passed a null.
        // We already know ptr is not null.
        let name = unsafe { libbpf_sys::bpf_map__name(ptr.as_ptr()) };
        let name = util::c_ptr_to_string(name)?;

        // Get the map fd
        let fd = unsafe { libbpf_sys::bpf_map__fd(ptr.as_ptr()) };
        if fd < 0 {
            return Err(Error::from_raw_os_error(-fd));
        }

        let ty = MapType::try_from(unsafe { libbpf_sys::bpf_map__type(ptr.as_ptr()) })
            .unwrap_or(MapType::Unknown);
        let key_size = unsafe { libbpf_sys::bpf_map__key_size(ptr.as_ptr()) };
        let value_size = unsafe { libbpf_sys::bpf_map__value_size(ptr.as_ptr()) };

        Ok(Map {
            handle: MapHandle {
                fd: MapFd::Borrowed(fd),
                name,
                ty,
                key_size,
                value_size,
            },
            ptr,
        })
    }

    /// Returns whether map is pinned or not flag
    pub fn is_pinned(&self) -> bool {
        unsafe { libbpf_sys::bpf_map__is_pinned(self.ptr.as_ptr()) }
    }

    /// Returns the pin_path if the map is pinned, otherwise, None is returned
    pub fn get_pin_path(&self) -> Option<&OsStr> {
        let path_ptr = unsafe { libbpf_sys::bpf_map__pin_path(self.ptr.as_ptr()) };
        if path_ptr.is_null() {
            // means map is not pinned
            return None;
        }
        let path_c_str = unsafe { CStr::from_ptr(path_ptr) };
        Some(OsStr::from_bytes(path_c_str.to_bytes()))
    }

    /// [Pin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this map to bpffs.
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_map__pin(self.ptr.as_ptr(), path_ptr) };
        util::parse_ret(ret)
    }

    /// [Unpin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this map from bpffs.
    pub fn unpin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();
        let ret = unsafe { libbpf_sys::bpf_map__unpin(self.ptr.as_ptr(), path_ptr) };
        util::parse_ret(ret)
    }

    /// Attach a struct ops map
    pub fn attach_struct_ops(&self) -> Result<Link> {
        if self.map_type() != MapType::StructOps {
            return Err(Error::with_invalid_data(format!(
                "Invalid map type ({}) for attach_struct_ops()",
                self.map_type(),
            )));
        }

        util::create_bpf_entity_checked(|| unsafe {
            libbpf_sys::bpf_map__attach_struct_ops(self.ptr.as_ptr())
        })
        .map(|ptr| unsafe {
            // SAFETY: the pointer came from libbpf and has been checked for errors
            Link::new(ptr)
        })
    }
}

impl AsRawLibbpf for Map {
    type LibbpfType = libbpf_sys::bpf_map;

    /// Retrieve the underlying [`libbpf_sys::bpf_map`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.ptr
    }
}

impl Deref for Map {
    type Target = MapHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl From<Map> for OwnedFd {
    fn from(map: Map) -> Self {
        match map.handle.fd {
            MapFd::Owned(o) => o,
            MapFd::Borrowed(_) => unreachable!(
                "it shouldn't be possible to have an owned map that doesn't own its fd"
            ),
        }
    }
}

impl AsFd for Map {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.handle.as_fd()
    }
}

/// A handle to a map. Handles can be duplicated and dropped.
///
/// While possible to [created directly][MapHandle::create], in many cases it is
/// useful to create such a handle from an existing [`Map`]:
/// ```no_run
/// # use libbpf_rs::Map;
/// # use libbpf_rs::MapHandle;
/// # let get_map = || -> &Map { todo!() };
/// let map: &Map = get_map();
/// let map_handle = MapHandle::try_clone(map).unwrap();
/// ```
///
/// Some methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
#[derive(Debug)]
pub struct MapHandle {
    fd: MapFd,
    name: String,
    ty: MapType,
    key_size: u32,
    value_size: u32,
}

impl MapHandle {
    /// Create a bpf map whose data is not managed by libbpf.
    pub fn create<T: AsRef<str>>(
        map_type: MapType,
        name: Option<T>,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        opts: &libbpf_sys::bpf_map_create_opts,
    ) -> Result<MapHandle> {
        let (map_name_str, map_name) = match name {
            Some(name) => (
                util::str_to_cstring(name.as_ref())?,
                name.as_ref().to_string(),
            ),

            // The old version kernel don't support specifying map name, we can use 'Option::<&str>::None' for the name argument.
            None => (util::str_to_cstring("")?, "".to_string()),
        };

        let map_name_ptr = {
            if map_name_str.as_bytes().is_empty() {
                ptr::null()
            } else {
                map_name_str.as_ptr()
            }
        };

        let fd = unsafe {
            libbpf_sys::bpf_map_create(
                map_type.into(),
                map_name_ptr,
                key_size,
                value_size,
                max_entries,
                opts,
            )
        };
        let () = util::parse_ret(fd)?;

        Ok(MapHandle {
            fd: MapFd::Owned(unsafe {
                // SAFETY
                // A file descriptor coming from the bpf_map_create function is always suitable for
                // ownership and can be cleaned up with close.
                OwnedFd::from_raw_fd(fd)
            }),
            name: map_name,
            ty: map_type,
            key_size,
            value_size,
        })
    }

    /// Open a previously pinned map from its path.
    ///
    /// # Panics
    /// If the path contains null bytes.
    pub fn from_pinned_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        fn inner(path: &Path) -> Result<MapHandle> {
            let p = CString::new(path.as_os_str().as_bytes()).expect("path contained null bytes");
            let fd = parse_ret_i32(unsafe {
                // SAFETY
                // p is never null since we allocated ourselves.
                libbpf_sys::bpf_obj_get(p.as_ptr())
            })?;
            MapHandle::from_fd(unsafe {
                // SAFETY
                // A file descriptor coming from the bpf_obj_get function is always suitable for
                // ownership and can be cleaned up with close.
                OwnedFd::from_raw_fd(fd)
            })
        }

        inner(path.as_ref())
    }

    /// Open a loaded map from its map id.
    pub fn from_map_id(id: u32) -> Result<Self> {
        parse_ret_i32(unsafe {
            // SAFETY
            // This function is always safe to call.
            libbpf_sys::bpf_map_get_fd_by_id(id)
        })
        .map(|fd| unsafe {
            // SAFETY
            // A file descriptor coming from the bpf_map_get_fd_by_id function is always suitable
            // for ownership and can be cleaned up with close.
            OwnedFd::from_raw_fd(fd)
        })
        .and_then(Self::from_fd)
    }

    fn from_fd(fd: OwnedFd) -> Result<Self> {
        let info = MapInfo::new(fd.as_fd())?;
        Ok(Self {
            fd: MapFd::Owned(fd),
            name: info.name()?.into(),
            ty: info.map_type(),
            key_size: info.info.key_size,
            value_size: info.info.value_size,
        })
    }

    /// Try cloning this handle by duplicating its underlying file descriptor.
    pub fn try_clone(this: &MapHandle) -> Result<Self> {
        let new_fd = this.as_fd().try_clone_to_owned()?;
        let fd = MapFd::Owned(new_fd);
        Ok(MapHandle {
            fd,
            name: this.name.clone(),
            ty: this.ty,
            key_size: this.key_size,
            value_size: this.value_size,
        })
    }

    /// Fetch extra map information
    #[inline]
    pub fn info(&self) -> Result<MapInfo> {
        MapInfo::new(self.fd.as_fd())
    }

    /// Retrieve the `Map`'s name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Retrieve type of the map.
    #[inline]
    pub fn map_type(&self) -> MapType {
        self.ty
    }

    /// Key size in bytes
    #[inline]
    pub fn key_size(&self) -> u32 {
        self.key_size
    }

    /// Value size in bytes
    #[inline]
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
        let ncpu = crate::num_possible_cpus()?;
        Ok(ncpu * aligned_val_size)
    }

    /// Apply a key check and return a null pointer in case of dealing with queue/stack map,
    /// before passing the key to the bpf functions that support the map of type queue/stack.
    fn map_key(&self, key: &[u8]) -> *const c_void {
        if self.key_size() == 0 && matches!(self.map_type(), MapType::Queue | MapType::Stack) {
            return ptr::null();
        }

        key.as_ptr() as *const c_void
    }

    /// Internal function to return a value from a map into a buffer of the given size.
    fn lookup_raw(&self, key: &[u8], flags: MapFlags, out_size: usize) -> Result<Option<Vec<u8>>> {
        if key.len() != self.key_size() as usize {
            return Err(Error::with_invalid_data(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        let mut out: Vec<u8> = Vec::with_capacity(out_size);

        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_elem_flags(
                self.fd.as_raw_fd(),
                self.map_key(key),
                out.as_mut_ptr() as *mut c_void,
                flags.bits(),
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
                Err(Error::from_raw_os_error(errno))
            }
        }
    }

    /// Internal function to update a map. This does not check the length of the
    /// supplied value.
    fn update_raw(&self, key: &[u8], value: &[u8], flags: MapFlags) -> Result<()> {
        if key.len() != self.key_size() as usize {
            return Err(Error::with_invalid_data(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        let ret = unsafe {
            libbpf_sys::bpf_map_update_elem(
                self.fd.as_raw_fd(),
                self.map_key(key),
                value.as_ptr() as *const c_void,
                flags.bits(),
            )
        };

        util::parse_ret(ret)
    }

    /// Returns map value as `Vec` of `u8`.
    ///
    /// `key` must have exactly [`MapHandle::key_size()`] elements.
    ///
    /// If the map is one of the per-cpu data structures, the function [`MapHandle::lookup_percpu()`]
    /// must be used.
    pub fn lookup(&self, key: &[u8], flags: MapFlags) -> Result<Option<Vec<u8>>> {
        if self.map_type().is_percpu() {
            return Err(Error::with_invalid_data(format!(
                "lookup_percpu() must be used for per-cpu maps (type of the map is {})",
                self.map_type(),
            )));
        }

        let out_size = self.value_size() as usize;
        self.lookup_raw(key, flags, out_size)
    }

    /// Returns one value per cpu as `Vec` of `Vec` of `u8` for per per-cpu maps.
    ///
    /// For normal maps, [`MapHandle::lookup()`] must be used.
    pub fn lookup_percpu(&self, key: &[u8], flags: MapFlags) -> Result<Option<Vec<Vec<u8>>>> {
        if !self.map_type().is_percpu() && self.map_type() != MapType::Unknown {
            return Err(Error::with_invalid_data(format!(
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

    /// Deletes an element from the map.
    ///
    /// `key` must have exactly [`MapHandle::key_size()`] elements.
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        if key.len() != self.key_size() as usize {
            return Err(Error::with_invalid_data(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        let ret = unsafe {
            libbpf_sys::bpf_map_delete_elem(self.fd.as_raw_fd(), key.as_ptr() as *const c_void)
        };
        util::parse_ret(ret)
    }

    /// Deletes many elements in batch mode from the map.
    ///
    /// `keys` must have exactly [`MapHandle::key_size()` * count] elements.
    pub fn delete_batch(
        &self,
        keys: &[u8],
        count: u32,
        elem_flags: MapFlags,
        flags: MapFlags,
    ) -> Result<()> {
        if keys.len() as u32 / count != self.key_size() || (keys.len() as u32) % count != 0 {
            return Err(Error::with_invalid_data(format!(
                "batch key_size {} != {} * {}",
                keys.len(),
                self.key_size(),
                count
            )));
        };

        let opts = libbpf_sys::bpf_map_batch_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_batch_opts>() as _,
            elem_flags: elem_flags.bits(),
            flags: flags.bits(),
        };

        let mut count = count;
        let ret = unsafe {
            libbpf_sys::bpf_map_delete_batch(
                self.fd.as_raw_fd(),
                keys.as_ptr() as *const c_void,
                (&mut count) as *mut u32,
                &opts as *const libbpf_sys::bpf_map_batch_opts,
            )
        };
        util::parse_ret(ret)
    }

    /// Same as [`MapHandle::lookup()`] except this also deletes the key from the map.
    ///
    /// Note that this operation is currently only implemented in the kernel for [`MapType::Queue`]
    /// and [`MapType::Stack`].
    ///
    /// `key` must have exactly [`MapHandle::key_size()`] elements.
    pub fn lookup_and_delete(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if key.len() != self.key_size() as usize {
            return Err(Error::with_invalid_data(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        let mut out: Vec<u8> = Vec::with_capacity(self.value_size() as usize);

        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_and_delete_elem(
                self.fd.as_raw_fd(),
                self.map_key(key),
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
                Err(Error::from_raw_os_error(errno))
            }
        }
    }

    /// Update an element.
    ///
    /// `key` must have exactly [`MapHandle::key_size()`] elements. `value` must have exactly
    /// [`MapHandle::value_size()`] elements.
    ///
    /// For per-cpu maps, [`MapHandle::update_percpu()`] must be used.
    pub fn update(&self, key: &[u8], value: &[u8], flags: MapFlags) -> Result<()> {
        if self.map_type().is_percpu() {
            return Err(Error::with_invalid_data(format!(
                "update_percpu() must be used for per-cpu maps (type of the map is {})",
                self.map_type(),
            )));
        }

        if value.len() != self.value_size() as usize {
            return Err(Error::with_invalid_data(format!(
                "value_size {} != {}",
                value.len(),
                self.value_size()
            )));
        };

        self.update_raw(key, value, flags)
    }

    /// Updates many elements in batch mode in the map
    ///
    /// `keys` must have exactly [`MapHandle::key_size()` * count] elements. `value` must have exactly
    /// [`MapHandle::key_size()` * count] elements
    pub fn update_batch(
        &self,
        keys: &[u8],
        values: &[u8],
        count: u32,
        elem_flags: MapFlags,
        flags: MapFlags,
    ) -> Result<()> {
        if keys.len() as u32 / count != self.key_size() || (keys.len() as u32) % count != 0 {
            return Err(Error::with_invalid_data(format!(
                "batch key_size {} != {} * {}",
                keys.len(),
                self.key_size(),
                count
            )));
        };

        if values.len() as u32 / count != self.value_size() || (values.len() as u32) % count != 0 {
            return Err(Error::with_invalid_data(format!(
                "batch value_size {} != {} * {}",
                values.len(),
                self.value_size(),
                count
            )));
        }

        let opts = libbpf_sys::bpf_map_batch_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_batch_opts>() as _,
            elem_flags: elem_flags.bits(),
            flags: flags.bits(),
        };

        let mut count = count;
        let ret = unsafe {
            libbpf_sys::bpf_map_update_batch(
                self.fd.as_raw_fd(),
                keys.as_ptr() as *const c_void,
                values.as_ptr() as *const c_void,
                (&mut count) as *mut u32,
                &opts as *const libbpf_sys::bpf_map_batch_opts,
            )
        };

        util::parse_ret(ret)
    }

    /// Update an element in an per-cpu map with one value per cpu.
    ///
    /// `key` must have exactly [`MapHandle::key_size()`] elements. `value` must have one
    /// element per cpu (see [`num_possible_cpus`][crate::num_possible_cpus])
    /// with exactly [`MapHandle::value_size()`] elements each.
    ///
    /// For per-cpu maps, [`MapHandle::update_percpu()`] must be used.
    pub fn update_percpu(&self, key: &[u8], values: &[Vec<u8>], flags: MapFlags) -> Result<()> {
        if !self.map_type().is_percpu() && self.map_type() != MapType::Unknown {
            return Err(Error::with_invalid_data(format!(
                "update() must be used for maps that are not per-cpu (type of the map is {})",
                self.map_type(),
            )));
        }

        if values.len() != crate::num_possible_cpus()? {
            return Err(Error::with_invalid_data(format!(
                "number of values {} != number of cpus {}",
                values.len(),
                crate::num_possible_cpus()?
            )));
        };

        let val_size = self.value_size() as usize;
        let aligned_val_size = self.percpu_aligned_value_size();
        let buf_size = self.percpu_buffer_size()?;

        let mut value_buf = vec![0; buf_size];

        for (i, val) in values.iter().enumerate() {
            if val.len() != val_size {
                return Err(Error::with_invalid_data(format!(
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

    /// Freeze the map as read-only from user space.
    ///
    /// Entries from a frozen map can no longer be updated or deleted with the
    /// bpf() system call. This operation is not reversible, and the map remains
    /// immutable from user space until its destruction. However, read and write
    /// permissions for BPF programs to the map remain unchanged.
    pub fn freeze(&self) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_map_freeze(self.fd.as_raw_fd()) };

        util::parse_ret(ret)
    }

    /// [Pin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this map to bpffs.
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_obj_pin(self.fd.as_raw_fd(), path_ptr) };
        util::parse_ret(ret)
    }

    /// [Unpin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this map from bpffs.
    pub fn unpin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        remove_file(path).context("failed to remove pin map")
    }

    /// Returns an iterator over keys in this map
    ///
    /// Note that if the map is not stable (stable meaning no updates or deletes) during iteration,
    /// iteration can skip keys, restart from the beginning, or duplicate keys. In other words,
    /// iteration becomes unpredictable.
    pub fn keys(&self) -> MapKeyIter<'_> {
        MapKeyIter::new(self, self.key_size())
    }
}

impl AsFd for MapHandle {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

bitflags! {
    /// Flags to configure [`Map`] operations.
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct MapFlags: u64 {
        /// See [`libbpf_sys::BPF_ANY`].
        const ANY      = libbpf_sys::BPF_ANY as _;
        /// See [`libbpf_sys::BPF_NOEXIST`].
        const NO_EXIST = libbpf_sys::BPF_NOEXIST as _;
        /// See [`libbpf_sys::BPF_EXIST`].
        const EXIST    = libbpf_sys::BPF_EXIST as _;
        /// See [`libbpf_sys::BPF_F_LOCK`].
        const LOCK     = libbpf_sys::BPF_F_LOCK as _;
    }
}

/// Type of a [`Map`]. Maps to `enum bpf_map_type` in kernel uapi.
// If you add a new per-cpu map, also update `is_percpu`.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Display, Debug)]
// TODO: Document members.
#[allow(missing_docs)]
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
    InodeStorage,
    TaskStorage,
    BloomFilter,
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

    /// Detects if host kernel supports this BPF map type.
    ///
    /// Make sure the process has required set of CAP_* permissions (or runs as
    /// root) when performing feature checking.
    pub fn is_supported(&self) -> Result<bool> {
        let ret = unsafe { libbpf_sys::libbpf_probe_bpf_map_type(*self as u32, ptr::null()) };
        match ret {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::from_raw_os_error(-ret)),
        }
    }
}

#[derive(Debug)]
pub struct MapKeyIter<'a> {
    map: &'a MapHandle,
    prev: Option<Vec<u8>>,
    next: Vec<u8>,
}

impl<'a> MapKeyIter<'a> {
    fn new(map: &'a MapHandle, key_size: u32) -> Self {
        Self {
            map,
            prev: None,
            next: vec![0; key_size as usize],
        }
    }
}

impl Iterator for MapKeyIter<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let prev = self.prev.as_ref().map_or(ptr::null(), |p| p.as_ptr());

        let ret = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                self.map.as_fd().as_raw_fd(),
                prev as _,
                self.next.as_mut_ptr() as _,
            )
        };
        if ret != 0 {
            None
        } else {
            self.prev = Some(self.next.clone());
            Some(self.next.clone())
        }
    }
}

/// A convenience wrapper for [`bpf_map_info`][libbpf_sys::bpf_map_info]. It
/// provides the ability to retrieve the details of a certain map.
#[derive(Debug)]
pub struct MapInfo {
    /// The inner [`bpf_map_info`][libbpf_sys::bpf_map_info] object.
    pub info: bpf_map_info,
}

impl MapInfo {
    /// Create a `MapInfo` object from a fd.
    pub fn new(fd: BorrowedFd<'_>) -> Result<Self> {
        // SAFETY: `bpf_map_info` is valid for any bit pattern.
        let mut map_info = unsafe { mem::zeroed::<bpf_map_info>() };
        let mut size = mem::size_of_val(&map_info) as u32;
        // SAFETY: All pointers are derived from references and hence valid.
        let () = util::parse_ret(unsafe {
            bpf_obj_get_info_by_fd(
                fd.as_raw_fd(),
                &mut map_info as *mut bpf_map_info as *mut c_void,
                &mut size as *mut u32,
            )
        })?;
        Ok(Self { info: map_info })
    }

    /// Get the map type
    #[inline]
    pub fn map_type(&self) -> MapType {
        match MapType::try_from(self.info.type_) {
            Ok(t) => t,
            Err(_) => MapType::Unknown,
        }
    }

    /// Get the name of this map.
    ///
    /// Returns error if the underlying data in the structure is not a valid
    /// utf-8 string.
    pub fn name<'a>(&self) -> Result<&'a str> {
        // SAFETY: convert &[i8] to &[u8], and then cast that to &str. i8 and u8 has the same size.
        let char_slice =
            unsafe { from_raw_parts(self.info.name[..].as_ptr().cast(), self.info.name.len()) };

        util::c_char_slice_to_cstr(char_slice)
            .ok_or_else(|| Error::with_invalid_data("no nul byte found"))?
            .to_str()
            .map_err(Error::with_invalid_data)
    }

    /// Get the map flags.
    #[inline]
    pub fn flags(&self) -> MapFlags {
        MapFlags::from_bits_truncate(self.info.map_flags as u64)
    }
}
