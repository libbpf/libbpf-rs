use core::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::mem;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;
use std::ptr::addr_of;
use std::ptr::NonNull;

use crate::map::map_fd;
use crate::set_print;
use crate::util;
use crate::util::validate_bpf_ret;
use crate::Btf;
use crate::ErrorExt as _;
use crate::Map;
use crate::MapMut;
use crate::OpenMap;
use crate::OpenMapMut;
use crate::OpenProgram;
use crate::OpenProgramMut;
use crate::PrintLevel;
use crate::Program;
use crate::ProgramMut;
use crate::Result;


/// An iterator over the maps in a BPF object.
#[derive(Debug)]
pub struct MapIter<'obj> {
    obj: &'obj libbpf_sys::bpf_object,
    last: *mut libbpf_sys::bpf_map,
}

impl<'obj> MapIter<'obj> {
    /// Create a new iterator over the maps of the given BPF object.
    pub fn new(obj: &'obj libbpf_sys::bpf_object) -> Self {
        Self {
            obj,
            last: ptr::null_mut(),
        }
    }
}

impl Iterator for MapIter<'_> {
    type Item = NonNull<libbpf_sys::bpf_map>;

    fn next(&mut self) -> Option<Self::Item> {
        self.last = unsafe { libbpf_sys::bpf_object__next_map(self.obj, self.last) };
        NonNull::new(self.last)
    }
}


/// An iterator over the programs in a BPF object.
#[derive(Debug)]
pub struct ProgIter<'obj> {
    obj: &'obj libbpf_sys::bpf_object,
    last: *mut libbpf_sys::bpf_program,
}

impl<'obj> ProgIter<'obj> {
    /// Create a new iterator over the programs of the given BPF object.
    pub fn new(obj: &'obj libbpf_sys::bpf_object) -> Self {
        Self {
            obj,
            last: ptr::null_mut(),
        }
    }
}

impl Iterator for ProgIter<'_> {
    type Item = NonNull<libbpf_sys::bpf_program>;

    fn next(&mut self) -> Option<Self::Item> {
        self.last = unsafe { libbpf_sys::bpf_object__next_program(self.obj, self.last) };
        NonNull::new(self.last)
    }
}


/// A trait implemented for types that are thin wrappers around `libbpf` types.
///
/// The trait provides access to the underlying `libbpf` (or `libbpf-sys`)
/// object. In many cases, this enables direct usage of `libbpf-sys`
/// functionality when higher-level bindings are not yet provided by this crate.
pub trait AsRawLibbpf {
    /// The underlying `libbpf` type.
    type LibbpfType;

    /// Retrieve the underlying `libbpf` object.
    ///
    /// # Warning
    /// By virtue of working with a mutable raw pointer this method effectively
    /// circumvents mutability and liveness checks. While by-design, usage is
    /// meant as an escape-hatch more than anything else. If you find yourself
    /// making use of it, please consider discussing your workflow with crate
    /// maintainers to see if it would make sense to provide safer wrappers.
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType>;
}

/// Builder for creating an [`OpenObject`]. Typically the entry point into libbpf-rs.
#[derive(Debug)]
pub struct ObjectBuilder {
    name: Option<CString>,
    pin_root_path: Option<CString>,

    opts: libbpf_sys::bpf_object_open_opts,
}

impl Default for ObjectBuilder {
    fn default() -> Self {
        let opts = libbpf_sys::bpf_object_open_opts {
            sz: mem::size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t,
            object_name: ptr::null(),
            relaxed_maps: false,
            pin_root_path: ptr::null(),
            kconfig: ptr::null(),
            btf_custom_path: ptr::null(),
            kernel_log_buf: ptr::null_mut(),
            kernel_log_size: 0,
            kernel_log_level: 0,
            ..Default::default()
        };
        Self {
            name: None,
            pin_root_path: None,
            opts,
        }
    }
}

impl ObjectBuilder {
    /// Override the generated name that would have been inferred from the constructor.
    pub fn name<T: AsRef<str>>(&mut self, name: T) -> Result<&mut Self> {
        self.name = Some(util::str_to_cstring(name.as_ref())?);
        self.opts.object_name = self.name.as_ref().map_or(ptr::null(), |p| p.as_ptr());
        Ok(self)
    }

    /// Set the pin_root_path for maps that are pinned by name.
    ///
    /// By default, this is NULL which bpf translates to /sys/fs/bpf
    pub fn pin_root_path<T: AsRef<Path>>(&mut self, path: T) -> Result<&mut Self> {
        self.pin_root_path = Some(util::path_to_cstring(path)?);
        self.opts.pin_root_path = self
            .pin_root_path
            .as_ref()
            .map_or(ptr::null(), |p| p.as_ptr());
        Ok(self)
    }

    /// Option to parse map definitions non-strictly, allowing extra attributes/data
    pub fn relaxed_maps(&mut self, relaxed_maps: bool) -> &mut Self {
        self.opts.relaxed_maps = relaxed_maps;
        self
    }

    /// Option to print debug output to stderr.
    ///
    /// Note: This function uses [`set_print`] internally and will overwrite any callbacks
    /// currently in use.
    pub fn debug(&mut self, dbg: bool) -> &mut Self {
        if dbg {
            set_print(Some((PrintLevel::Debug, |_, s| print!("{s}"))));
        } else {
            set_print(None);
        }
        self
    }

    /// Open an object using the provided path on the file system.
    pub fn open_file<P: AsRef<Path>>(&mut self, path: P) -> Result<OpenObject> {
        let path = path.as_ref();
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();
        let opts_ptr = self.as_libbpf_object().as_ptr();

        let ptr = unsafe { libbpf_sys::bpf_object__open_file(path_ptr, opts_ptr) };
        let ptr = validate_bpf_ret(ptr)
            .with_context(|| format!("failed to open object from `{}`", path.display()))?;

        let obj = unsafe { OpenObject::from_ptr(ptr) };
        Ok(obj)
    }

    /// Open an object from memory.
    pub fn open_memory(&mut self, mem: &[u8]) -> Result<OpenObject> {
        let opts_ptr = self.as_libbpf_object().as_ptr();
        let ptr = unsafe {
            libbpf_sys::bpf_object__open_mem(
                mem.as_ptr() as *const c_void,
                mem.len() as libbpf_sys::size_t,
                opts_ptr,
            )
        };
        let ptr = validate_bpf_ret(ptr).context("failed to open object from memory")?;
        let obj = unsafe { OpenObject::from_ptr(ptr) };
        Ok(obj)
    }
}

impl AsRawLibbpf for ObjectBuilder {
    type LibbpfType = libbpf_sys::bpf_object_open_opts;

    /// Retrieve the underlying [`libbpf_sys::bpf_object_open_opts`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        // SAFETY: A reference is always a valid pointer.
        unsafe { NonNull::new_unchecked(addr_of!(self.opts).cast_mut()) }
    }
}


/// Represents an opened (but not yet loaded) BPF object file.
///
/// Use this object to access [`OpenMap`]s and [`OpenProgram`]s.
#[derive(Debug)]
#[repr(transparent)]
pub struct OpenObject {
    ptr: NonNull<libbpf_sys::bpf_object>,
}

impl OpenObject {
    /// Takes ownership from pointer.
    ///
    /// # Safety
    ///
    /// Operations on the returned object are undefined if `ptr` is any one of:
    ///     - null
    ///     - points to an unopened `bpf_object`
    ///     - points to a loaded `bpf_object`
    ///
    /// It is not safe to manipulate `ptr` after this operation.
    pub unsafe fn from_ptr(ptr: NonNull<libbpf_sys::bpf_object>) -> Self {
        Self { ptr }
    }

    /// Takes underlying `libbpf_sys::bpf_object` pointer.
    pub fn take_ptr(mut self) -> NonNull<libbpf_sys::bpf_object> {
        let ptr = {
            let Self { ptr } = &mut self;
            *ptr
        };
        // avoid double free of self.ptr
        mem::forget(self);
        ptr
    }

    /// Retrieve the object's name.
    pub fn name(&self) -> Option<&OsStr> {
        // SAFETY: We ensured `ptr` is valid during construction.
        let name_ptr = unsafe { libbpf_sys::bpf_object__name(self.ptr.as_ptr()) };
        // SAFETY: `libbpf_get_error` is always safe to call.
        let err = unsafe { libbpf_sys::libbpf_get_error(name_ptr as *const _) };
        if err != 0 {
            return None
        }
        let name_c_str = unsafe { CStr::from_ptr(name_ptr) };
        let str = OsStr::from_bytes(name_c_str.to_bytes());
        Some(str)
    }

    /// Retrieve an iterator over all BPF maps in the object.
    pub fn maps(&self) -> impl Iterator<Item = OpenMap<'_>> {
        MapIter::new(unsafe { self.ptr.as_ref() }).map(|ptr| unsafe { OpenMap::new(ptr.as_ref()) })
    }

    /// Retrieve an iterator over all BPF maps in the object.
    pub fn maps_mut(&mut self) -> impl Iterator<Item = OpenMapMut<'_>> {
        MapIter::new(unsafe { self.ptr.as_ref() })
            .map(|mut ptr| unsafe { OpenMapMut::new_mut(ptr.as_mut()) })
    }

    /// Retrieve an iterator over all BPF programs in the object.
    pub fn progs(&self) -> impl Iterator<Item = OpenProgram<'_>> {
        ProgIter::new(unsafe { self.ptr.as_ref() })
            .map(|ptr| unsafe { OpenProgram::new(ptr.as_ref()) })
    }

    /// Retrieve an iterator over all BPF programs in the object.
    pub fn progs_mut(&mut self) -> impl Iterator<Item = OpenProgramMut<'_>> {
        ProgIter::new(unsafe { self.ptr.as_ref() })
            .map(|mut ptr| unsafe { OpenProgramMut::new_mut(ptr.as_mut()) })
    }

    /// Load the maps and programs contained in this BPF object into the system.
    pub fn load(self) -> Result<Object> {
        let ret = unsafe { libbpf_sys::bpf_object__load(self.ptr.as_ptr()) };
        let () = util::parse_ret(ret)?;

        let obj = unsafe { Object::from_ptr(self.take_ptr()) };

        Ok(obj)
    }
}

impl AsRawLibbpf for OpenObject {
    type LibbpfType = libbpf_sys::bpf_object;

    /// Retrieve the underlying [`libbpf_sys::bpf_object`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.ptr
    }
}

impl Drop for OpenObject {
    fn drop(&mut self) {
        // `self.ptr` may be null if `load()` was called. This is ok: libbpf noops
        unsafe {
            libbpf_sys::bpf_object__close(self.ptr.as_ptr());
        }
    }
}

/// Represents a loaded BPF object file.
///
/// An `Object` is logically in charge of all the contained [`Program`]s and [`Map`]s as well as
/// the associated metadata and runtime state that underpins the userspace portions of BPF program
/// execution. As a libbpf-rs user, you must keep the `Object` alive during the entire lifetime
/// of your interaction with anything inside the `Object`.
///
/// Note that this is an explanation of the motivation -- Rust's lifetime system should already be
/// enforcing this invariant.
#[derive(Debug)]
#[repr(transparent)]
pub struct Object {
    ptr: NonNull<libbpf_sys::bpf_object>,
}

impl Object {
    /// Takes ownership from pointer.
    ///
    /// # Safety
    ///
    /// If `ptr` is not already loaded then further operations on the returned object are
    /// undefined.
    ///
    /// It is not safe to manipulate `ptr` after this operation.
    pub unsafe fn from_ptr(ptr: NonNull<libbpf_sys::bpf_object>) -> Self {
        Self { ptr }
    }

    /// Retrieve the object's name.
    pub fn name(&self) -> Option<&OsStr> {
        // SAFETY: We ensured `ptr` is valid during construction.
        let name_ptr = unsafe { libbpf_sys::bpf_object__name(self.ptr.as_ptr()) };
        // SAFETY: `libbpf_get_error` is always safe to call.
        let err = unsafe { libbpf_sys::libbpf_get_error(name_ptr as *const _) };
        if err != 0 {
            return None
        }
        let name_c_str = unsafe { CStr::from_ptr(name_ptr) };
        let str = OsStr::from_bytes(name_c_str.to_bytes());
        Some(str)
    }

    /// Parse the btf information associated with this bpf object.
    pub fn btf(&self) -> Result<Option<Btf<'_>>> {
        Btf::from_bpf_object(unsafe { &*self.ptr.as_ptr() })
    }

    /// Retrieve an iterator over all BPF maps in the object.
    pub fn maps(&self) -> impl Iterator<Item = Map<'_>> {
        MapIter::new(unsafe { self.ptr.as_ref() })
            .filter(|ptr| map_fd(*ptr).is_some())
            .map(|ptr| unsafe { Map::new(ptr.as_ref()) })
    }

    /// Retrieve an iterator over all BPF maps in the object.
    pub fn maps_mut(&mut self) -> impl Iterator<Item = MapMut<'_>> {
        MapIter::new(unsafe { self.ptr.as_ref() })
            .filter(|ptr| map_fd(*ptr).is_some())
            .map(|mut ptr| unsafe { MapMut::new_mut(ptr.as_mut()) })
    }

    /// Retrieve an iterator over all BPF programs in the object.
    pub fn progs(&self) -> impl Iterator<Item = Program<'_>> {
        ProgIter::new(unsafe { self.ptr.as_ref() }).map(|ptr| unsafe { Program::new(ptr.as_ref()) })
    }

    /// Retrieve an iterator over all BPF programs in the object.
    pub fn progs_mut(&self) -> impl Iterator<Item = ProgramMut<'_>> {
        ProgIter::new(unsafe { self.ptr.as_ref() })
            .map(|mut ptr| unsafe { ProgramMut::new_mut(ptr.as_mut()) })
    }
}

impl AsRawLibbpf for Object {
    type LibbpfType = libbpf_sys::bpf_object;

    /// Retrieve the underlying [`libbpf_sys::bpf_object`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.ptr
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::bpf_object__close(self.ptr.as_ptr());
        }
    }
}
