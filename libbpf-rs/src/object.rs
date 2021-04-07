use core::ffi::c_void;
use std::collections::HashMap;
use std::ffi::CStr;
use std::mem;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;

use nix::errno;

use crate::util;
use crate::*;

/// Builder for creating an [`OpenObject`]. Typically the entry point into libbpf-rs.
pub struct ObjectBuilder {
    name: String,
    relaxed_maps: bool,
}

impl ObjectBuilder {
    /// Override the generated name that would have been inferred from the constructor.
    pub fn name<T: AsRef<str>>(&mut self, name: T) -> &mut Self {
        self.name = name.as_ref().to_string();
        self
    }

    /// Option to parse map definitions non-strictly, allowing extra attributes/data
    pub fn relaxed_maps(&mut self, relaxed_maps: bool) -> &mut Self {
        self.relaxed_maps = relaxed_maps;
        self
    }

    /// Option to print debug output to stderr.
    pub fn debug(&mut self, dbg: bool) -> &mut Self {
        extern "C" fn cb(
            _level: libbpf_sys::libbpf_print_level,
            fmtstr: *const c_char,
            va_list: *mut libbpf_sys::__va_list_tag,
        ) -> i32 {
            match unsafe { vsprintf::vsprintf(fmtstr, va_list) } {
                Ok(s) => {
                    print!("{}", s);
                    0
                }
                Err(e) => {
                    eprintln!("Failed to parse libbpf output: {}", e);
                    1
                }
            }
        }

        if dbg {
            unsafe { libbpf_sys::libbpf_set_print(Some(cb)) };
        } else {
            unsafe { libbpf_sys::libbpf_set_print(None) };
        }

        self
    }

    /// Used for skeleton -- an end user may not consider this API stable
    #[doc(hidden)]
    pub fn opts(&mut self, name: *const c_char) -> libbpf_sys::bpf_object_open_opts {
        libbpf_sys::bpf_object_open_opts {
            sz: mem::size_of::<libbpf_sys::bpf_object_open_opts>() as libbpf_sys::size_t,
            object_name: name,
            relaxed_maps: self.relaxed_maps,
            relaxed_core_relocs: false,
            pin_root_path: ptr::null(),
            attach_prog_fd: 0,
            kconfig: ptr::null(),
        }
    }

    pub fn open_file<P: AsRef<Path>>(&mut self, path: P) -> Result<OpenObject> {
        // Convert path to a C style pointer
        let path_str = path.as_ref().to_str().ok_or_else(|| {
            Error::InvalidInput(format!("{} is not valid unicode", path.as_ref().display()))
        })?;
        let path_c = util::str_to_cstring(path_str)?;
        let path_ptr = path_c.as_ptr();

        // Convert name to a C style pointer
        //
        // NB: we must hold onto a CString otherwise our pointer dangles
        let name = util::str_to_cstring(&self.name)?;
        let name_ptr = if !self.name.is_empty() {
            name.as_ptr()
        } else {
            ptr::null()
        };

        let opts = self.opts(name_ptr);

        let obj = unsafe { libbpf_sys::bpf_object__open_file(path_ptr, &opts) };
        let err = unsafe { libbpf_sys::libbpf_get_error(obj as *const _) };
        if err != 0 {
            return Err(Error::System(err as i32));
        }

        Ok(OpenObject::new(obj))
    }

    pub fn open_memory<T: AsRef<str>>(&mut self, name: T, mem: &[u8]) -> Result<OpenObject> {
        // Convert name to a C style pointer
        //
        // NB: we must hold onto a CString otherwise our pointer dangles
        let name = util::str_to_cstring(name.as_ref())?;
        let name_ptr = if !name.to_bytes().is_empty() {
            name.as_ptr()
        } else {
            ptr::null()
        };

        let opts = self.opts(name_ptr);

        let obj = unsafe {
            libbpf_sys::bpf_object__open_mem(
                mem.as_ptr() as *const c_void,
                mem.len() as libbpf_sys::size_t,
                &opts,
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(obj as *const _) };
        if err != 0 {
            return Err(Error::System(err as i32));
        }

        Ok(OpenObject::new(obj))
    }
}

impl Default for ObjectBuilder {
    fn default() -> Self {
        ObjectBuilder {
            name: String::new(),
            relaxed_maps: false,
        }
    }
}

fn find_map_in_object(
    obj: *const libbpf_sys::bpf_object,
    name: &str,
) -> Result<Option<*mut libbpf_sys::bpf_map>> {
    let c_name = util::str_to_cstring(name)?;
    let ptr = unsafe { libbpf_sys::bpf_object__find_map_by_name(obj, c_name.as_ptr()) };
    Ok(util::ptr_to_option(ptr))
}

fn find_prog_in_object(
    obj: *const libbpf_sys::bpf_object,
    name: &str,
) -> Result<Option<*mut libbpf_sys::bpf_program>> {
    let c_name = util::str_to_cstring(name)?;
    let ptr = unsafe { libbpf_sys::bpf_object__find_program_by_name(obj, c_name.as_ptr()) };
    Ok(util::ptr_to_option(ptr))
}

/// Represents an opened (but not yet loaded) BPF object file.
///
/// Use this object to access [`OpenMap`]s and [`OpenProgram`]s.
pub struct OpenObject {
    ptr: *mut libbpf_sys::bpf_object,
    maps: HashMap<String, OpenMap>,
    progs: HashMap<String, OpenProgram>,
}

impl OpenObject {
    fn new(ptr: *mut libbpf_sys::bpf_object) -> Self {
        OpenObject {
            ptr,
            maps: HashMap::new(),
            progs: HashMap::new(),
        }
    }

    /// Takes ownership from pointer.
    ///
    /// # Safety
    ///
    /// If `ptr` is unopen or already loaded then further operations on the returned object are
    /// undefined.
    ///
    /// It is not safe to manipulate `ptr` after this operation.
    pub unsafe fn from_ptr(ptr: *mut libbpf_sys::bpf_object) -> Self {
        Self::new(ptr)
    }

    /// Takes underlying `libbpf_sys::bpf_object` pointer.
    pub fn take_ptr(mut self) -> *mut libbpf_sys::bpf_object {
        let ptr = self.ptr;
        self.ptr = ptr::null_mut();
        ptr
    }

    pub fn name(&self) -> Result<&str> {
        unsafe {
            let ptr = libbpf_sys::bpf_object__name(self.ptr);
            let err = libbpf_sys::libbpf_get_error(ptr as *const _);
            if err != 0 {
                return Err(Error::System(err as i32));
            }

            CStr::from_ptr(ptr)
                .to_str()
                .map_err(|e| Error::Internal(e.to_string()))
        }
    }

    pub fn map<T: AsRef<str>>(&mut self, name: T) -> Result<Option<&mut OpenMap>> {
        if self.maps.contains_key(name.as_ref()) {
            Ok(self.maps.get_mut(name.as_ref()))
        } else if let Some(ptr) = find_map_in_object(self.ptr, name.as_ref())? {
            self.maps
                .insert(name.as_ref().to_owned(), OpenMap::new(ptr));
            Ok(self.maps.get_mut(name.as_ref()))
        } else {
            Ok(None)
        }
    }

    /// Same as [`OpenObject::map`] except will panic if `Err` or `None` is encountered.
    pub fn map_unwrap<T: AsRef<str>>(&mut self, name: T) -> &mut OpenMap {
        self.map(name).unwrap().unwrap()
    }

    pub fn prog<T: AsRef<str>>(&mut self, name: T) -> Result<Option<&mut OpenProgram>> {
        if self.progs.contains_key(name.as_ref()) {
            Ok(self.progs.get_mut(name.as_ref()))
        } else if let Some(ptr) = find_prog_in_object(self.ptr, name.as_ref())? {
            let owned_name = name.as_ref().to_owned();
            self.progs.insert(owned_name, OpenProgram::new(ptr));
            Ok(self.progs.get_mut(name.as_ref()))
        } else {
            Ok(None)
        }
    }

    /// Same as [`OpenObject::prog`] except will panic if `Err` or `None` is encountered.
    pub fn prog_unwrap<T: AsRef<str>>(&mut self, name: T) -> &mut OpenProgram {
        self.prog(name).unwrap().unwrap()
    }

    /// Load the maps and programs contained in this BPF object into the system.
    pub fn load(mut self) -> Result<Object> {
        let ret = unsafe { libbpf_sys::bpf_object__load(self.ptr) };
        if ret != 0 {
            // bpf_object__load() returns errno as negative, so flip
            return Err(Error::System(-ret));
        }

        let obj = Object::new(self.ptr);

        // Prevent object from being closed once `self` is dropped
        self.ptr = ptr::null_mut();

        Ok(obj)
    }
}

impl Drop for OpenObject {
    fn drop(&mut self) {
        // `self.ptr` may be null if `load()` was called. This is ok: libbpf noops
        unsafe {
            libbpf_sys::bpf_object__close(self.ptr);
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
pub struct Object {
    ptr: *mut libbpf_sys::bpf_object,
    maps: HashMap<String, Map>,
    progs: HashMap<String, Program>,
}

impl Object {
    fn new(ptr: *mut libbpf_sys::bpf_object) -> Self {
        Object {
            ptr,
            maps: HashMap::new(),
            progs: HashMap::new(),
        }
    }

    /// Takes ownership from pointer.
    ///
    /// # Safety
    ///
    /// If `ptr` is not already loaded then further operations on the returned object are
    /// undefined.
    ///
    /// It is not safe to manipulate `ptr` after this operation.
    pub unsafe fn from_ptr(ptr: *mut libbpf_sys::bpf_object) -> Self {
        Self::new(ptr)
    }

    pub fn map<T: AsRef<str>>(&mut self, name: T) -> Result<Option<&mut Map>> {
        if self.maps.contains_key(name.as_ref()) {
            Ok(self.maps.get_mut(name.as_ref()))
        } else if let Some(ptr) = find_map_in_object(self.ptr, name.as_ref())? {
            let owned_name = name.as_ref().to_owned();
            let fd = unsafe { libbpf_sys::bpf_map__fd(ptr) };
            if fd < 0 {
                Err(Error::System(errno::errno()))
            } else {
                // bpf_map__def can return null but only if it's passed a null. Object::map
                // already error checks that condition for us.
                let def = unsafe { ptr::read(libbpf_sys::bpf_map__def(ptr)) };

                self.maps.insert(
                    owned_name.clone(),
                    Map::new(fd, owned_name, def.type_, def.key_size, def.value_size, ptr),
                );

                Ok(self.maps.get_mut(name.as_ref()))
            }
        } else {
            Ok(None)
        }
    }

    /// Same as [`Object::map`] except will panic if `Err` or `None` is encountered.
    pub fn map_unwrap<T: AsRef<str>>(&mut self, name: T) -> &mut Map {
        self.map(name).unwrap().unwrap()
    }

    pub fn prog<T: AsRef<str>>(&mut self, name: T) -> Result<Option<&mut Program>> {
        if self.progs.contains_key(name.as_ref()) {
            Ok(self.progs.get_mut(name.as_ref()))
        } else if let Some(ptr) = find_prog_in_object(self.ptr, name.as_ref())? {
            let owned_name = name.as_ref().to_owned();

            let title = unsafe { libbpf_sys::bpf_program__title(ptr, false) };
            let err = unsafe { libbpf_sys::libbpf_get_error(title as *const _) };
            if err != 0 {
                return Err(Error::System(err as i32));
            }
            let section = util::c_ptr_to_string(title)?;

            self.progs
                .insert(owned_name.clone(), Program::new(ptr, owned_name, section));

            Ok(self.progs.get_mut(name.as_ref()))
        } else {
            Ok(None)
        }
    }

    /// Same as [`Object::prog`] except will panic if `Err` or `None` is encountered.
    pub fn prog_unwrap<T: AsRef<str>>(&mut self, name: T) -> &mut Program {
        self.prog(name).unwrap().unwrap()
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::bpf_object__close(self.ptr);
        }
    }
}
