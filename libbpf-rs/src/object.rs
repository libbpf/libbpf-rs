use core::ffi::c_void;
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::mem;
use std::path::Path;
use std::ptr;
use std::ptr::NonNull;

use crate::libbpf_sys;
use crate::set_print;
use crate::util;
use crate::Btf;
use crate::Error;
use crate::Map;
use crate::OpenMap;
use crate::OpenProgram;
use crate::PrintLevel;
use crate::Program;
use crate::Result;

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

    /// Get the raw libbpf_sys::bpf_object_open_opts.
    ///
    /// The internal pointers are tied to the lifetime of the
    /// ObjectBuilder, so be wary when copying the struct or otherwise
    /// handing the lifetime over to C.
    pub fn opts(&self) -> &libbpf_sys::bpf_object_open_opts {
        &self.opts
    }

    /// Open an object using the provided path on the file system.
    pub fn open_file<P: AsRef<Path>>(&mut self, path: P) -> Result<OpenObject> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let opts = self.opts();

        util::create_bpf_entity_checked(|| unsafe {
            libbpf_sys::bpf_object__open_file(path_ptr, opts)
        })
        .and_then(|ptr| unsafe { OpenObject::new(ptr) })
    }

    /// Open an object from memory.
    pub fn open_memory(&mut self, mem: &[u8]) -> Result<OpenObject> {
        let opts = self.opts();

        util::create_bpf_entity_checked(|| unsafe {
            libbpf_sys::bpf_object__open_mem(
                mem.as_ptr() as *const c_void,
                mem.len() as libbpf_sys::size_t,
                opts,
            )
        })
        .and_then(|ptr| unsafe { OpenObject::new(ptr) })
    }
}

/// Represents an opened (but not yet loaded) BPF object file.
///
/// Use this object to access [`OpenMap`]s and [`OpenProgram`]s.
#[derive(Debug)]
pub struct OpenObject {
    ptr: NonNull<libbpf_sys::bpf_object>,
    maps: HashMap<String, OpenMap>,
    progs: HashMap<String, OpenProgram>,
}

impl OpenObject {
    /// Create a [`OpenObject`] from a [`libbpf_sys::bpf_object`].
    ///
    /// # Safety
    /// `ptr` must point to an opened but not loaded `bpf_object`
    ///
    /// It is not safe to manipulate `ptr` after this operation.
    unsafe fn new(ptr: NonNull<libbpf_sys::bpf_object>) -> Result<Self> {
        let mut obj = OpenObject {
            ptr,
            maps: HashMap::new(),
            progs: HashMap::new(),
        };

        // Populate obj.maps
        let mut map: *mut libbpf_sys::bpf_map = ptr::null_mut();
        loop {
            // Get the pointer to the next BPF map
            let map_ptr = {
                let next_ptr = unsafe { libbpf_sys::bpf_object__next_map(obj.ptr.as_ptr(), map) };
                match NonNull::new(next_ptr) {
                    Some(map_ptr) => map_ptr,
                    None => break,
                }
            };

            let map_obj = unsafe { OpenMap::new(map_ptr) };

            // Add the map to the hashmap
            obj.maps.insert(map_obj.name()?.into(), map_obj);
            map = map_ptr.as_ptr();
        }

        // Populate obj.progs
        let mut prog: *mut libbpf_sys::bpf_program = ptr::null_mut();
        loop {
            // Get the pointer to the next BPF program
            let prog_ptr = {
                let next_ptr =
                    unsafe { libbpf_sys::bpf_object__next_program(obj.ptr.as_ptr(), prog) };
                match NonNull::new(next_ptr) {
                    Some(ptr) => ptr,
                    None => break,
                }
            };

            let program = unsafe { OpenProgram::new(prog_ptr) }?;

            // Add the program to the hashmap
            obj.progs.insert(program.name()?.into(), program);
            prog = prog_ptr.as_ptr();
        }

        Ok(obj)
    }

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
    pub unsafe fn from_ptr(ptr: NonNull<libbpf_sys::bpf_object>) -> Result<Self> {
        unsafe { Self::new(ptr) }
    }

    /// Takes underlying `libbpf_sys::bpf_object` pointer.
    pub fn take_ptr(mut self) -> NonNull<libbpf_sys::bpf_object> {
        let ptr = {
            // manually free the internal state.
            // using destructuring we make sure we'll get a compiler error if anything in
            // Self changes, which will alert us to change this function as well
            let Self { ptr, maps, progs } = &mut self;
            mem::take(maps);
            mem::take(progs);
            *ptr
        };
        // avoid double free of self.ptr
        mem::forget(self);
        ptr
    }

    /// Retrieve the object's name.
    pub fn name(&self) -> Result<&str> {
        unsafe {
            let ptr = libbpf_sys::bpf_object__name(self.ptr.as_ptr());
            let err = libbpf_sys::libbpf_get_error(ptr as *const _);
            if err != 0 {
                return Err(Error::from_raw_os_error(err as i32));
            }

            CStr::from_ptr(ptr)
                .to_str()
                .map_err(Error::with_invalid_data)
        }
    }

    /// Get a reference to `OpenMap` with the name `name`, if one exists.
    pub fn map<T: AsRef<str>>(&self, name: T) -> Option<&OpenMap> {
        self.maps.get(name.as_ref())
    }

    /// Get a mutable reference to `OpenMap` with the name `name`, if one exists.
    pub fn map_mut<T: AsRef<str>>(&mut self, name: T) -> Option<&mut OpenMap> {
        self.maps.get_mut(name.as_ref())
    }

    /// Get an iterator over references to all `OpenMap`s.
    /// Note that this will include automatically generated .data, .rodata, .bss, and
    /// .kconfig maps.
    pub fn maps_iter(&self) -> impl Iterator<Item = &OpenMap> {
        self.maps.values()
    }

    /// Get an iterator over mutable references to all `OpenMap`s.
    /// Note that this will include automatically generated .data, .rodata, .bss, and
    /// .kconfig maps.
    pub fn maps_iter_mut(&mut self) -> impl Iterator<Item = &mut OpenMap> {
        self.maps.values_mut()
    }

    /// Get a reference to `OpenProgram` with the name `name`, if one exists.
    pub fn prog<T: AsRef<str>>(&self, name: T) -> Option<&OpenProgram> {
        self.progs.get(name.as_ref())
    }

    /// Get a mutable reference to `OpenProgram` with the name `name`, if one exists.
    pub fn prog_mut<T: AsRef<str>>(&mut self, name: T) -> Option<&mut OpenProgram> {
        self.progs.get_mut(name.as_ref())
    }

    /// Get an iterator over references to all `OpenProgram`s.
    pub fn progs_iter(&self) -> impl Iterator<Item = &OpenProgram> {
        self.progs.values()
    }

    /// Get an iterator over mutable references to all `OpenProgram`s.
    pub fn progs_iter_mut(&mut self) -> impl Iterator<Item = &mut OpenProgram> {
        self.progs.values_mut()
    }

    /// Load the maps and programs contained in this BPF object into the system.
    pub fn load(self) -> Result<Object> {
        let ret = unsafe { libbpf_sys::bpf_object__load(self.ptr.as_ptr()) };
        let () = util::parse_ret(ret)?;

        let obj = unsafe { Object::from_ptr(self.take_ptr())? };

        Ok(obj)
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
pub struct Object {
    ptr: NonNull<libbpf_sys::bpf_object>,
    maps: HashMap<String, Map>,
    progs: HashMap<String, Program>,
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
    pub unsafe fn from_ptr(ptr: NonNull<libbpf_sys::bpf_object>) -> Result<Self> {
        let mut obj = Object {
            ptr,
            maps: HashMap::new(),
            progs: HashMap::new(),
        };

        // Populate obj.maps
        let mut map: *mut libbpf_sys::bpf_map = ptr::null_mut();
        loop {
            // Get the pointer to the next BPF map
            let map_ptr = {
                let next_ptr = unsafe { libbpf_sys::bpf_object__next_map(obj.ptr.as_ptr(), map) };
                match NonNull::new(next_ptr) {
                    Some(map_ptr) => map_ptr,
                    None => break,
                }
            };

            if unsafe { libbpf_sys::bpf_map__autocreate(map_ptr.as_ptr()) } {
                let map_obj = unsafe { Map::new(map_ptr) }?;
                obj.maps.insert(map_obj.name().into(), map_obj);
            }

            map = map_ptr.as_ptr();
        }

        // Populate obj.progs
        let mut prog: *mut libbpf_sys::bpf_program = ptr::null_mut();
        loop {
            // Get the pointer to the next BPF program
            let prog_ptr = {
                let next_ptr =
                    unsafe { libbpf_sys::bpf_object__next_program(obj.ptr.as_ptr(), prog) };
                match NonNull::new(next_ptr) {
                    Some(prog_ptr) => prog_ptr,
                    None => break,
                }
            };

            let program = unsafe { Program::new(prog_ptr) }?;

            // Add the program to the hashmap
            obj.progs.insert(program.name().into(), program);
            prog = prog_ptr.as_ptr();
        }

        Ok(obj)
    }

    /// Parse the btf information associated with this bpf object.
    pub fn btf(&self) -> Result<Btf<'_>> {
        Btf::from_bpf_object(unsafe { &*self.ptr.as_ptr() })
    }

    /// Get a reference to `Map` with the name `name`, if one exists.
    pub fn map<T: AsRef<str>>(&self, name: T) -> Option<&Map> {
        self.maps.get(name.as_ref())
    }

    /// Get a mutable reference to `Map` with the name `name`, if one exists.
    pub fn map_mut<T: AsRef<str>>(&mut self, name: T) -> Option<&mut Map> {
        self.maps.get_mut(name.as_ref())
    }

    /// Get an iterator over references to all `Map`s.
    /// Note that this will include automatically generated .data, .rodata, .bss, and
    /// .kconfig maps. You may wish to filter this.
    pub fn maps_iter(&self) -> impl Iterator<Item = &Map> {
        self.maps.values()
    }

    /// Get an iterator over mutable references to all `Map`s.
    /// Note that this will include automatically generated .data, .rodata, .bss, and
    /// .kconfig maps. You may wish to filter this.
    pub fn maps_iter_mut(&mut self) -> impl Iterator<Item = &mut Map> {
        self.maps.values_mut()
    }

    /// Get a reference to `Program` with the name `name`, if one exists.
    pub fn prog<T: AsRef<str>>(&self, name: T) -> Option<&Program> {
        self.progs.get(name.as_ref())
    }

    /// Get a mutable reference to `Program` with the name `name`, if one exists.
    pub fn prog_mut<T: AsRef<str>>(&mut self, name: T) -> Option<&mut Program> {
        self.progs.get_mut(name.as_ref())
    }

    /// Get an iterator over references to all `Program`s.
    pub fn progs_iter(&self) -> impl Iterator<Item = &Program> {
        self.progs.values()
    }

    /// Get an iterator over mutable references to all `Program`s.
    pub fn progs_iter_mut(&mut self) -> impl Iterator<Item = &mut Program> {
        self.progs.values_mut()
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
