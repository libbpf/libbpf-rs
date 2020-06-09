use core::ffi::c_void;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::mem;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;

use bitflags::bitflags;
use nix::{errno, fcntl, unistd};
use num_enum::TryFromPrimitive;

use crate::util;
use crate::*;

/// Sets options for opening a [`Object`]
pub struct ObjectBuilder {
    name: String,
    relaxed_maps: bool,
}

impl ObjectBuilder {
    /// Override the generated name that would have been inferred from the constructor.
    pub fn set_name<T: AsRef<str>>(&mut self, name: T) -> &mut Self {
        self.name = name.as_ref().to_string();
        self
    }

    /// Option to parse map definitions non-strictly, allowing extra attributes/data
    pub fn set_relaxed_maps(&mut self, relaxed_maps: bool) -> &mut Self {
        self.relaxed_maps = relaxed_maps;
        self
    }

    /// Option to print debug output to stderr.
    pub fn set_debug(&mut self, dbg: bool) -> &mut Self {
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

    fn opts(&mut self, name: *const c_char) -> libbpf_sys::bpf_object_open_opts {
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

    pub fn from_path<P: AsRef<Path>>(&mut self, path: P) -> Result<Object> {
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

        let ret = unsafe { libbpf_sys::bpf_object__load(obj) };
        if ret != 0 {
            // bpf_object__load() returns errno as negative, so flip
            return Err(Error::System(-ret));
        }

        Ok(Object::new(obj))
    }

    pub fn from_memory<T: AsRef<str>>(&mut self, name: T, mem: &[u8]) -> Result<Object> {
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

        let ret = unsafe { libbpf_sys::bpf_object__load(obj) };
        if ret != 0 {
            // bpf_object__load() returns errno as negative, so flip
            return Err(Error::System(-ret));
        }

        Ok(Object::new(obj))
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

/// Represents a BPF object file. An object may contain zero or more
/// [`Program`]s and [`Map`]s.
pub struct Object {
    ptr: *mut libbpf_sys::bpf_object,
    maps: HashMap<String, MapBuilder>,
    progs: HashMap<String, ProgramBuilder>,
}

impl Object {
    fn new(ptr: *mut libbpf_sys::bpf_object) -> Self {
        Object {
            ptr,
            maps: HashMap::new(),
            progs: HashMap::new(),
        }
    }

    pub fn name<'a>(&'a self) -> Result<&'a str> {
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

    pub fn map<T: AsRef<str>>(&mut self, name: T) -> Result<Option<&mut MapBuilder>> {
        if self.maps.contains_key(name.as_ref()) {
            Ok(self.maps.get_mut(name.as_ref()))
        } else {
            let c_name = util::str_to_cstring(name.as_ref())?;
            let ptr =
                unsafe { libbpf_sys::bpf_object__find_map_by_name(self.ptr, c_name.as_ptr()) };
            if ptr.is_null() {
                Ok(None)
            } else {
                let btf_fd = unsafe { libbpf_sys::bpf_object__btf_fd(self.ptr) };
                let owned_name = name.as_ref().to_owned();
                self.maps
                    .insert(owned_name.clone(), MapBuilder::new(ptr, owned_name, btf_fd));
                Ok(self.maps.get_mut(name.as_ref()))
            }
        }
    }

    pub fn prog<T: AsRef<str>>(&mut self, name: T) -> Result<Option<&mut ProgramBuilder>> {
        if self.progs.contains_key(name.as_ref()) {
            Ok(self.progs.get_mut(name.as_ref()))
        } else {
            let c_name = util::str_to_cstring(name.as_ref())?;
            let ptr =
                unsafe { libbpf_sys::bpf_object__find_program_by_name(self.ptr, c_name.as_ptr()) };
            if ptr.is_null() {
                Ok(None)
            } else {
                let owned_name = name.as_ref().to_owned();
                self.progs.insert(owned_name, ProgramBuilder::new(ptr));
                Ok(self.progs.get_mut(name.as_ref()))
            }
        }
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        unsafe {
            libbpf_sys::bpf_object__close(self.ptr);
        }
    }
}

/// Represents a parsed but not yet loaded map.
///
/// Some methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
pub struct MapBuilder {
    ptr: *mut libbpf_sys::bpf_map,
    name: String,
    attrs: libbpf_sys::bpf_create_map_attr,
    initial_val: Option<Vec<u8>>,
}

impl MapBuilder {
    fn new(ptr: *mut libbpf_sys::bpf_map, name: String, btf_fd: i32) -> Self {
        // bpf_map__def can return null but only if it's passed a null. Object::map
        // already error checks that condition for us.
        let def = unsafe { ptr::read(libbpf_sys::bpf_map__def(ptr)) };

        let mut attrs = libbpf_sys::bpf_create_map_attr::default();
        attrs.map_type = def.type_;
        attrs.key_size = def.key_size;
        attrs.value_size = def.value_size;
        attrs.max_entries = def.max_entries;
        attrs.map_flags = def.map_flags;

        if attrs.map_type == (MapType::PerfEventArray as u32) && attrs.max_entries == 0 {
            attrs.max_entries = unsafe { libbpf_sys::libbpf_num_possible_cpus() as u32 };
        }

        if btf_fd >= 0 {
            attrs.btf_fd = btf_fd as u32;
            attrs.btf_value_type_id = unsafe { libbpf_sys::bpf_map__btf_value_type_id(ptr) };
            attrs.btf_key_type_id = unsafe { libbpf_sys::bpf_map__btf_key_type_id(ptr) };
        }

        MapBuilder {
            ptr,
            attrs,
            name,
            initial_val: None,
        }
    }

    pub fn set_map_ifindex(&mut self, idx: u32) -> &mut Self {
        self.attrs.map_ifindex = idx;
        self
    }

    pub fn set_max_entries(&mut self, entries: u32) -> &mut Self {
        self.attrs.max_entries = entries;
        self
    }

    pub fn set_initial_value(&mut self, data: &[u8]) -> &mut Self {
        self.initial_val = Some(data.to_vec());
        self
    }

    pub fn set_numa_node(&mut self, node: u32) -> &mut Self {
        self.attrs.numa_node = node;
        self
    }

    pub fn set_inner_map_fd(&mut self, inner: Map) -> &mut Self {
        self.attrs.__bindgen_anon_1.inner_map_fd = inner.fd as u32;
        mem::forget(inner);
        self
    }

    pub fn set_flags(&mut self, flags: MapBuilderFlags) -> &mut Self {
        self.attrs.map_flags = flags.bits;
        self
    }

    pub fn load(&mut self) -> Result<Map> {
        if let Some(val) = &self.initial_val {
            let ret = unsafe {
                libbpf_sys::bpf_map__set_initial_value(
                    self.ptr,
                    val.as_ptr() as *const std::ffi::c_void,
                    val.len() as u64,
                )
            };
            if ret != 0 {
                // Error code is returned negative, flip to positive to match errno
                return Err(Error::System(-ret));
            }
        }

        // Set name here because self.name could be memmoved during object construction
        let name_cstring = util::str_to_cstring(self.name.as_str())?;
        self.attrs.name = name_cstring.as_ptr();

        // libbpf_sys::bpf_object__load() already created the map for us. So we just
        // need to get the FD out.
        let fd = unsafe { libbpf_sys::bpf_map__fd(self.ptr) };
        if fd < 0 {
            Err(Error::System(errno::errno()))
        } else {
            Ok(Map::new(
                fd,
                self.name.clone(),
                self.attrs.map_type,
                self.attrs.key_size,
                self.attrs.value_size,
            ))
        }
    }
}

#[rustfmt::skip]
bitflags! {
    pub struct MapBuilderFlags: u32 {
	const NO_PREALLOC     = 1;
	const NO_COMMON_LRU   = 1 << 1;
	const NUMA_NODE       = 1 << 2;
	const RDONLY          = 1 << 3;
	const WRONLY          = 1 << 4;
	const STACK_BUILD_ID  = 1 << 5;
	const ZERO_SEED       = 1 << 6;
	const RDONLY_PROG     = 1 << 7;
	const WRONLY_PROG     = 1 << 8;
	const CLONE           = 1 << 9;
	const MMAPABLE        = 1 << 10;
    }
}

/// Represents a created map.
///
/// The kernel ensure the atomicity and safety of operations on a `Map`. Therefore,
/// this handle is safe to clone and pass around between threads. This is essentially a
/// file descriptor.
///
/// Some methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
pub struct Map {
    fd: i32,
    name: String,
    ty: libbpf_sys::bpf_map_type,
    key_size: u32,
    value_size: u32,
}

impl Map {
    fn new(
        fd: i32,
        name: String,
        ty: libbpf_sys::bpf_map_type,
        key_size: u32,
        value_size: u32,
    ) -> Self {
        Map {
            fd,
            name,
            ty,
            key_size,
            value_size,
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

    /// Returns map value as `Vec` of `u8`.
    ///
    /// `key` must have exactly [`Map::key_size()`] elements.
    pub fn lookup(&self, key: &[u8], flags: MapFlags) -> Result<Option<Vec<u8>>> {
        if key.len() != self.key_size() as usize {
            return Err(Error::InvalidInput(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        let mut out: Vec<u8> = Vec::with_capacity(self.value_size() as usize);

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
    /// `key` must have exactly [`Map::key_size()`] elements. `value` must have exatly
    /// [`Map::value_size()`] elements.
    pub fn update(&mut self, key: &[u8], value: &[u8], flags: MapFlags) -> Result<()> {
        if key.len() != self.key_size() as usize {
            return Err(Error::InvalidInput(format!(
                "key_size {} != {}",
                key.len(),
                self.key_size()
            )));
        };

        if value.len() != self.value_size() as usize {
            return Err(Error::InvalidInput(format!(
                "value_size {} != {}",
                value.len(),
                self.value_size()
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
}

impl Drop for Map {
    fn drop(&mut self) {
        // Can't report errors here, so ignore result
        let _ = unistd::close(self.fd as i32);
    }
}

impl Clone for Map {
    fn clone(&self) -> Self {
        // No way to report errors here. Regardless, if we've exhausted FDs on system
        // then we're going to crash sooner or later.
        let newfd =
            fcntl::fcntl(self.fd as i32, fcntl::FcntlArg::F_DUPFD_CLOEXEC(0 as i32)).unwrap();
        Map {
            fd: newfd,
            name: self.name.clone(),
            ty: self.ty,
            key_size: self.key_size,
            value_size: self.value_size,
        }
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
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, TryFromPrimitive, PartialEq)]
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
    /// We choose to specify our own "unknown" type here b/c it's really up to the kernel
    /// to decide if it wants to reject the map. If it accepts it, it just means whoever
    /// using this library is a bit out of date.
    Unknown = u32::MAX,
}

/// Represents a parsed but not yet loaded BPF program.
pub struct ProgramBuilder {
    ptr: *mut libbpf_sys::bpf_program,
    license: String,
}

impl ProgramBuilder {
    fn new(ptr: *mut libbpf_sys::bpf_program) -> Self {
        ProgramBuilder {
            ptr,
            license: "GPL".to_owned(),
        }
    }

    pub fn set_license<T: AsRef<str>>(&mut self, license: T) -> &mut Self {
        self.license = license.as_ref().to_owned();
        self
    }

    pub fn set_prog_type(&mut self, prog_type: ProgramType) -> &mut Self {
        unsafe {
            libbpf_sys::bpf_program__set_type(self.ptr, prog_type as u32);
        }
        self
    }

    pub fn set_attach_type(&mut self, attach_type: ProgramAttachType) -> &mut Self {
        unsafe {
            libbpf_sys::bpf_program__set_expected_attach_type(self.ptr, attach_type as u32);
        }
        self
    }

    pub fn set_ifindex(&mut self, idx: u32) -> &mut Self {
        unsafe {
            libbpf_sys::bpf_program__set_ifindex(self.ptr, idx);
        }
        self
    }

    pub fn load(&mut self) -> Result<Program> {
        // libbpf_sys::bpf_object__load() already loads all the programs for us so we don't
        // need to do much work here.

        let name = util::c_ptr_to_string(unsafe { libbpf_sys::bpf_program__name(self.ptr) })?;
        let title = unsafe { libbpf_sys::bpf_program__title(self.ptr, false) };
        let err = unsafe { libbpf_sys::libbpf_get_error(title as *const _) };
        if err != 0 {
            return Err(Error::System(err as i32));
        }

        let section = util::c_ptr_to_string(title)?;

        Ok(Program::new(self.ptr, name, section))
    }
}

/// Type of a [`Program`]. Maps to `enum bpf_prog_type` in kernel uapi.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, TryFromPrimitive)]
pub enum ProgramType {
    Unspec = 0,
    SocketFilter,
    Kprobe,
    SchedCls,
    SchedAct,
    Tracepoint,
    Xdp,
    PerfEvent,
    CgroupSkb,
    CgroupSock,
    LwtIn,
    LwtOut,
    LwtXmit,
    SockOps,
    SkSkb,
    CgroupDevice,
    SkMsg,
    RawTracepoint,
    CgroupSockAddr,
    LwtSeg6local,
    LircMode2,
    SkReuseport,
    FlowDissector,
    CgroupSysctl,
    RawTracepointWritable,
    CgroupSockopt,
    Tracing,
    StructOps,
    Ext,
    Lsm,
    /// See [`MapType::Unknown`]
    Unknown = u32::MAX,
}

/// Attach type of a [`Program`]. Maps to `enum bpf_attach_type` in kernel uapi.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, TryFromPrimitive)]
pub enum ProgramAttachType {
    CgroupInetIngress,
    CgroupInetEgress,
    CgroupInetSockCreate,
    CgroupSockOps,
    SkSkbStreamParser,
    SkSkbStreamVerdict,
    CgroupDevice,
    SkMsgVerdict,
    CgroupInet4Bind,
    CgroupInet6Bind,
    CgroupInet4Connect,
    CgroupInet6Connect,
    CgroupInet4PostBind,
    CgroupInet6PostBind,
    CgroupUdp4Sendmsg,
    CgroupUdp6Sendmsg,
    LircMode2,
    FlowDissector,
    CgroupSysctl,
    CgroupUdp4Recvmsg,
    CgroupUdp6Recvmsg,
    CgroupGetsockopt,
    CgroupSetsockopt,
    TraceRawTp,
    TraceFentry,
    TraceFexit,
    ModifyReturn,
    LsmMac,
    /// See [`MapType::Unknown`]
    Unknown = u32::MAX,
}

/// Represents a loaded [`Program`].
///
/// This struct is not safe to clone because the underlying libbpf resource cannot currently
/// be protected from data races.
///
/// If you attempt to attach a `Program` with the wrong attach method, the `attach_*`
/// method will fail with the appropriate error.
pub struct Program {
    ptr: *mut libbpf_sys::bpf_program,
    name: String,
    section: String,
}

impl Program {
    fn new(ptr: *mut libbpf_sys::bpf_program, name: String, section: String) -> Self {
        Program { ptr, name, section }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Name of the section this `Program` belongs to.
    pub fn section(&self) -> &str {
        &self.section
    }

    pub fn prog_type(&self) -> ProgramType {
        match ProgramType::try_from(unsafe { libbpf_sys::bpf_program__get_type(self.ptr) }) {
            Ok(ty) => ty,
            Err(_) => ProgramType::Unknown,
        }
    }

    /// Returns a file descriptor to the underlying program.
    pub fn fd(&self) -> i32 {
        unsafe { libbpf_sys::bpf_program__fd(self.ptr) }
    }

    pub fn attach_type(&self) -> ProgramAttachType {
        match ProgramAttachType::try_from(unsafe {
            libbpf_sys::bpf_program__get_expected_attach_type(self.ptr)
        }) {
            Ok(ty) => ty,
            Err(_) => ProgramAttachType::Unknown,
        }
    }

    /// Auto-attach based on prog section
    pub fn attach(&mut self) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach(self.ptr) };
        if ptr.is_null() {
            Err(Error::System(errno::errno()))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach this program to a
    /// [cgroup](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).
    pub fn attach_cgroup(&mut self, cgroup_fd: i32) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_cgroup(self.ptr, cgroup_fd) };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach this program to a [perf event](https://linux.die.net/man/2/perf_event_open).
    pub fn attach_perf_event(&mut self, pfd: i32) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_perf_event(self.ptr, pfd) };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach this program to a [userspace
    /// probe](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html).
    pub fn attach_uprobe<T: AsRef<str>>(
        &mut self,
        retprobe: bool,
        pid: i32,
        binary_path: T,
        func_offset: u64,
    ) -> Result<Link> {
        let path = binary_path.as_ref().as_ptr() as *const c_char;
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_uprobe(self.ptr, retprobe, pid, path, func_offset)
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach this program to a [kernel
    /// probe](https://www.kernel.org/doc/html/latest/trace/kprobetrace.html).
    pub fn attach_kprobe<T: AsRef<str>>(&mut self, retprobe: bool, func_name: T) -> Result<Link> {
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_kprobe(
                self.ptr,
                retprobe,
                func_name.as_ref().as_ptr() as *const c_char,
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach this program to a [kernel
    /// tracepoint](https://www.kernel.org/doc/html/latest/trace/tracepoints.html).
    pub fn attach_tracepoint<T: AsRef<str>>(&mut self, tp_category: T, tp_name: T) -> Result<Link> {
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_tracepoint(
                self.ptr,
                tp_category.as_ref().as_ptr() as *const c_char,
                tp_name.as_ref().as_ptr() as *const c_char,
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach this program to a [raw kernel
    /// tracepoint](https://lwn.net/Articles/748352/).
    pub fn attach_raw_tracepoint<T: AsRef<str>>(&mut self, tp_name: T) -> Result<Link> {
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_raw_tracepoint(
                self.ptr,
                tp_name.as_ref().as_ptr() as *const c_char,
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach to an [LSM](https://en.wikipedia.org/wiki/Linux_Security_Modules) hook
    pub fn attach_lsm(&mut self) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_lsm(self.ptr) };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach to a [fentry/fexit kernel probe](https://lwn.net/Articles/801479/)
    pub fn attach_trace(&mut self) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_trace(self.ptr) };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if ptr.is_null() {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }
}

/// Represents an attached [`Program`].
///
/// This struct is used to model ownership. The underlying program will be detached
/// when this object is dropped if nothing else is holding a reference count.
pub struct Link {
    ptr: *mut libbpf_sys::bpf_link,
}

impl Link {
    fn new(ptr: *mut libbpf_sys::bpf_link) -> Self {
        Link { ptr }
    }

    /// Replace the underlying prog with `prog`.
    pub fn update_prog(&mut self, prog: Program) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_link__update_program(self.ptr, prog.ptr) };
        if ret != 0 {
            Err(Error::System(errno::errno()))
        } else {
            Ok(())
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        let _ = unsafe { libbpf_sys::bpf_link__destroy(self.ptr) };
    }
}
