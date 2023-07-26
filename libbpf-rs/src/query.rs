//! Query the host about BPF
//!
//! For example, to list the name of every bpf program running on the system:
//! ```
//! use libbpf_rs::query::ProgInfoIter;
//!
//! let mut iter = ProgInfoIter::default();
//! for prog in iter {
//!     println!("{}", prog.name.to_string_lossy());
//! }
//! ```

use std::convert::TryFrom;
use std::ffi::c_void;
use std::ffi::CString;
use std::mem::size_of_val;
use std::os::raw::c_char;
use std::ptr;
use std::time::Duration;

use nix::errno;
use nix::unistd::close;

use crate::libbpf_sys;
use crate::util;
use crate::MapType;
use crate::ProgramAttachType;
use crate::ProgramType;
use crate::Result;

macro_rules! gen_info_impl {
    // This magic here allows us to embed doc comments into macro expansions
    ($(#[$attr:meta])*
     $name:ident, $info_ty:ty, $uapi_info_ty:ty, $next_id:expr, $fd_by_id:expr) => {
        $(#[$attr])*
        #[derive(Default, Debug)]
        pub struct $name {
            cur_id: u32,
        }

        impl $name {
            // Returns Some(next_valid_fd), None on none left
            fn next_valid_fd(&mut self) -> Option<i32> {
                loop {
                    if unsafe { $next_id(self.cur_id, &mut self.cur_id) } != 0 {
                        return None;
                    }

                    let fd = unsafe { $fd_by_id(self.cur_id) };
                    if fd < 0 {
                        if errno::errno() == errno::Errno::ENOENT as i32 {
                            continue;
                        }

                        return None;
                    }

                    return Some(fd);
                }
            }
        }

        impl Iterator for $name {
            type Item = $info_ty;

            fn next(&mut self) -> Option<Self::Item> {
                let fd = match self.next_valid_fd() {
                    Some(fd) => fd,
                    None => return None,
                };

                // We need to use std::mem::zeroed() instead of just using
                // ::default() because padding bytes need to be zero as well.
                // Old kernels which know about fewer fields than we do will
                // check to make sure every byte past what they know is zero
                // and will return E2BIG otherwise.
                let mut item: $uapi_info_ty = unsafe { std::mem::zeroed() };
                let item_ptr: *mut $uapi_info_ty = &mut item;
                let mut len = size_of_val(&item) as u32;

                let ret = unsafe { libbpf_sys::bpf_obj_get_info_by_fd(fd, item_ptr as *mut c_void, &mut len) };
                let parsed_uapi = if ret != 0 {
                    None
                } else {
                    <$info_ty>::from_uapi(fd, item)
                };

                let _ = close(fd);
                parsed_uapi
            }
        }
    };
}

/// BTF Line information
#[derive(Clone, Debug)]
pub struct LineInfo {
    /// Offset of instruction in vector
    pub insn_off: u32,
    /// File name offset
    pub file_name_off: u32,
    /// Line offset in debug info
    pub line_off: u32,
    /// Line number
    pub line_num: u32,
    /// Line column number
    pub line_col: u32,
}

impl From<&libbpf_sys::bpf_line_info> for LineInfo {
    fn from(item: &libbpf_sys::bpf_line_info) -> Self {
        LineInfo {
            insn_off: item.insn_off,
            file_name_off: item.file_name_off,
            line_off: item.line_off,
            line_num: item.line_col >> 10,
            line_col: item.line_col & 0x3ff,
        }
    }
}

/// Bpf identifier tag
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct Tag([u8; 8]);

/// Information about a BPF program
#[derive(Debug, Clone)]
// TODO: Document members.
#[allow(missing_docs)]
pub struct ProgramInfo {
    pub name: CString,
    pub ty: ProgramType,
    pub tag: Tag,
    pub id: u32,
    pub jited_prog_insns: Vec<u8>,
    pub xlated_prog_insns: Vec<u8>,
    /// Duration since system boot
    pub load_time: Duration,
    pub created_by_uid: u32,
    pub map_ids: Vec<u32>,
    pub ifindex: u32,
    pub gpl_compatible: bool,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub jited_ksyms: Vec<*const c_void>,
    pub jited_func_lens: Vec<u32>,
    pub btf_id: u32,
    pub func_info_rec_size: u32,
    pub func_info: Vec<libbpf_sys::bpf_func_info>,
    pub line_info: Vec<LineInfo>,
    pub jited_line_info: Vec<*const c_void>,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub prog_tags: Vec<Tag>,
    pub run_time_ns: u64,
    pub run_cnt: u64,
}

/// An iterator for the information of loaded bpf programs
#[derive(Default, Debug)]
pub struct ProgInfoIter {
    cur_id: u32,
    opts: ProgInfoQueryOptions,
}

/// Options to query the program info currently loaded
#[derive(Clone, Default, Debug)]
pub struct ProgInfoQueryOptions {
    /// Include the vector of bpf instructions in the result
    include_xlated_prog_insns: bool,
    /// Include the vector of jited instructions in the result
    include_jited_prog_insns: bool,
    /// Include the ids of maps associated with the program
    include_map_ids: bool,
    /// Include source line information corresponding to xlated code
    include_line_info: bool,
    /// Include function type information corresponding to xlated code
    include_func_info: bool,
    /// Include source line information corresponding to jited code
    include_jited_line_info: bool,
    /// Include function type information corresponding to jited code
    include_jited_func_lens: bool,
    /// Include program tags
    include_prog_tags: bool,
    /// Include the jited kernel symbols
    include_jited_ksyms: bool,
}

impl ProgInfoIter {
    /// Generate an iter from more specific query options
    pub fn with_query_opts(opts: ProgInfoQueryOptions) -> Self {
        Self {
            opts,
            ..Self::default()
        }
    }
}

impl ProgInfoQueryOptions {
    /// Include the vector of jited bpf instructions in the result
    pub fn include_xlated_prog_insns(mut self, v: bool) -> Self {
        self.include_xlated_prog_insns = v;
        self
    }

    /// Include the vector of jited instructions in the result
    pub fn include_jited_prog_insns(mut self, v: bool) -> Self {
        self.include_jited_prog_insns = v;
        self
    }

    /// Include the ids of maps associated with the program
    pub fn include_map_ids(mut self, v: bool) -> Self {
        self.include_map_ids = v;
        self
    }

    /// Include source line information corresponding to xlated code
    pub fn include_line_info(mut self, v: bool) -> Self {
        self.include_line_info = v;
        self
    }

    /// Include function type information corresponding to xlated code
    pub fn include_func_info(mut self, v: bool) -> Self {
        self.include_func_info = v;
        self
    }

    /// Include source line information corresponding to jited code
    pub fn include_jited_line_info(mut self, v: bool) -> Self {
        self.include_jited_line_info = v;
        self
    }

    /// Include function type information corresponding to jited code
    pub fn include_jited_func_lens(mut self, v: bool) -> Self {
        self.include_jited_func_lens = v;
        self
    }

    /// Include program tags
    pub fn include_prog_tags(mut self, v: bool) -> Self {
        self.include_prog_tags = v;
        self
    }

    /// Include the jited kernel symbols
    pub fn include_jited_ksyms(mut self, v: bool) -> Self {
        self.include_jited_ksyms = v;
        self
    }

    /// Include everything there is in the query results
    pub fn include_all(self) -> Self {
        Self {
            include_xlated_prog_insns: true,
            include_jited_prog_insns: true,
            include_map_ids: true,
            include_line_info: true,
            include_func_info: true,
            include_jited_line_info: true,
            include_jited_func_lens: true,
            include_prog_tags: true,
            include_jited_ksyms: true,
        }
    }
}

impl ProgramInfo {
    fn load_from_fd(fd: i32, opts: &ProgInfoQueryOptions) -> Result<Self> {
        let mut item = libbpf_sys::bpf_prog_info::default();

        let mut xlated_prog_insns: Vec<u8> = Vec::new();
        let mut jited_prog_insns: Vec<u8> = Vec::new();
        let mut map_ids: Vec<u32> = Vec::new();
        let mut jited_line_info: Vec<*const c_void> = Vec::new();
        let mut line_info: Vec<libbpf_sys::bpf_line_info> = Vec::new();
        let mut func_info: Vec<libbpf_sys::bpf_func_info> = Vec::new();
        let mut jited_func_lens: Vec<u32> = Vec::new();
        let mut prog_tags: Vec<Tag> = Vec::new();
        let mut jited_ksyms: Vec<*const c_void> = Vec::new();

        let item_ptr: *mut libbpf_sys::bpf_prog_info = &mut item;
        let mut len = size_of_val(&item) as u32;

        let ret =
            unsafe { libbpf_sys::bpf_obj_get_info_by_fd(fd, item_ptr as *mut c_void, &mut len) };
        util::parse_ret(ret)?;

        // SANITY: `libbpf` should guarantee NUL termination.
        let name = util::c_char_slice_to_cstr(&item.name).unwrap();
        let ty = match ProgramType::try_from(item.type_) {
            Ok(ty) => ty,
            Err(_) => ProgramType::Unknown,
        };

        if opts.include_xlated_prog_insns {
            xlated_prog_insns.resize(item.xlated_prog_len as usize, 0u8);
            item.xlated_prog_insns = xlated_prog_insns.as_mut_ptr() as *mut c_void as u64;
        } else {
            item.xlated_prog_len = 0;
        }

        if opts.include_jited_prog_insns {
            jited_prog_insns.resize(item.jited_prog_len as usize, 0u8);
            item.jited_prog_insns = jited_prog_insns.as_mut_ptr() as *mut c_void as u64;
        } else {
            item.jited_prog_len = 0;
        }

        if opts.include_map_ids {
            map_ids.resize(item.nr_map_ids as usize, 0u32);
            item.map_ids = map_ids.as_mut_ptr() as *mut c_void as u64;
        } else {
            item.nr_map_ids = 0;
        }

        if opts.include_line_info {
            line_info.resize(
                item.nr_line_info as usize,
                libbpf_sys::bpf_line_info::default(),
            );
            item.line_info = line_info.as_mut_ptr() as *mut c_void as u64;
        } else {
            item.nr_line_info = 0;
        }

        if opts.include_func_info {
            func_info.resize(
                item.nr_func_info as usize,
                libbpf_sys::bpf_func_info::default(),
            );
            item.func_info = func_info.as_mut_ptr() as *mut c_void as u64;
        } else {
            item.nr_func_info = 0;
        }

        if opts.include_jited_line_info {
            jited_line_info.resize(item.nr_jited_line_info as usize, ptr::null());
            item.jited_line_info = jited_line_info.as_mut_ptr() as *mut c_void as u64;
        } else {
            item.nr_jited_line_info = 0;
        }

        if opts.include_jited_func_lens {
            jited_func_lens.resize(item.nr_jited_func_lens as usize, 0);
            item.jited_func_lens = jited_func_lens.as_mut_ptr() as *mut c_void as u64;
        } else {
            item.nr_jited_func_lens = 0;
        }

        if opts.include_prog_tags {
            prog_tags.resize(item.nr_prog_tags as usize, Tag::default());
            item.prog_tags = prog_tags.as_mut_ptr() as *mut c_void as u64;
        } else {
            item.nr_prog_tags = 0;
        }

        if opts.include_jited_ksyms {
            jited_ksyms.resize(item.nr_jited_ksyms as usize, ptr::null());
            item.jited_ksyms = jited_ksyms.as_mut_ptr() as *mut c_void as u64;
        } else {
            item.nr_jited_ksyms = 0;
        }

        let ret =
            unsafe { libbpf_sys::bpf_obj_get_info_by_fd(fd, item_ptr as *mut c_void, &mut len) };
        util::parse_ret(ret)?;

        return Ok(ProgramInfo {
            name: name.to_owned(),
            ty,
            tag: Tag(item.tag),
            id: item.id,
            jited_prog_insns,
            xlated_prog_insns,
            load_time: Duration::from_nanos(item.load_time),
            created_by_uid: item.created_by_uid,
            map_ids,
            ifindex: item.ifindex,
            gpl_compatible: item._bitfield_1.get_bit(0),
            netns_dev: item.netns_dev,
            netns_ino: item.netns_ino,
            jited_ksyms,
            jited_func_lens,
            btf_id: item.btf_id,
            func_info_rec_size: item.func_info_rec_size,
            func_info,
            line_info: line_info.iter().map(|li| li.into()).collect(),
            jited_line_info,
            line_info_rec_size: item.line_info_rec_size,
            jited_line_info_rec_size: item.jited_line_info_rec_size,
            prog_tags,
            run_time_ns: item.run_time_ns,
            run_cnt: item.run_cnt,
        });
    }
}

impl Iterator for ProgInfoIter {
    type Item = ProgramInfo;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if unsafe { libbpf_sys::bpf_prog_get_next_id(self.cur_id, &mut self.cur_id) } != 0 {
                return None;
            }

            let fd = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(self.cur_id) };
            if fd < 0 {
                if errno::errno() == errno::Errno::ENOENT as i32 {
                    continue;
                }
                return None;
            }

            let prog = ProgramInfo::load_from_fd(fd, &self.opts);
            let _ = close(fd);

            match prog {
                Ok(p) => return Some(p),
                // TODO: We should consider bubbling up errors properly.
                Err(_err) => (),
            }
        }
    }
}

/// Information about a BPF map
#[derive(Debug, Clone)]
// TODO: Document members.
#[allow(missing_docs)]
pub struct MapInfo {
    pub name: CString,
    pub ty: MapType,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub ifindex: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}

impl MapInfo {
    fn from_uapi(_fd: i32, s: libbpf_sys::bpf_map_info) -> Option<Self> {
        // SANITY: `libbpf` should guarantee NUL termination.
        let name = util::c_char_slice_to_cstr(&s.name).unwrap();
        let ty = match MapType::try_from(s.type_) {
            Ok(ty) => ty,
            Err(_) => MapType::Unknown,
        };

        Some(Self {
            name: name.to_owned(),
            ty,
            id: s.id,
            key_size: s.key_size,
            value_size: s.value_size,
            max_entries: s.max_entries,
            map_flags: s.map_flags,
            ifindex: s.ifindex,
            btf_vmlinux_value_type_id: s.btf_vmlinux_value_type_id,
            netns_dev: s.netns_dev,
            netns_ino: s.netns_ino,
            btf_id: s.btf_id,
            btf_key_type_id: s.btf_key_type_id,
            btf_value_type_id: s.btf_value_type_id,
        })
    }
}

gen_info_impl!(
    /// Iterator that returns [`MapInfo`]s.
    MapInfoIter,
    MapInfo,
    libbpf_sys::bpf_map_info,
    libbpf_sys::bpf_map_get_next_id,
    libbpf_sys::bpf_map_get_fd_by_id
);

/// Information about BPF type format
#[derive(Debug, Clone)]
pub struct BtfInfo {
    /// The name associated with this btf information in the kernel
    pub name: CString,
    /// The raw btf bytes from the kernel
    pub btf: Vec<u8>,
    /// The btf id associated with this btf information in the kernel
    pub id: u32,
}

impl BtfInfo {
    fn load_from_fd(fd: i32) -> Result<Self> {
        let mut item = libbpf_sys::bpf_btf_info::default();
        let mut btf: Vec<u8> = Vec::new();
        let mut name: Vec<u8> = Vec::new();

        let item_ptr: *mut libbpf_sys::bpf_btf_info = &mut item;
        let mut len = size_of_val(&item) as u32;

        let ret =
            unsafe { libbpf_sys::bpf_obj_get_info_by_fd(fd, item_ptr as *mut c_void, &mut len) };
        util::parse_ret(ret)?;

        // The API gives you the ascii string length while expecting
        // you to give it back space for a nul-terminator
        item.name_len += 1;
        name.resize(item.name_len as usize, 0u8);
        item.name = name.as_mut_ptr() as *mut c_void as u64;

        btf.resize(item.btf_size as usize, 0u8);
        item.btf = btf.as_mut_ptr() as *mut c_void as u64;

        let ret =
            unsafe { libbpf_sys::bpf_obj_get_info_by_fd(fd, item_ptr as *mut c_void, &mut len) };
        util::parse_ret(ret)?;

        Ok(BtfInfo {
            // SANITY: Our buffer contained space for a NUL byte and we set its
            //         contents to 0. Barring a `libbpf` bug a NUL byte will be
            //         present.
            name: CString::from_vec_with_nul(name).unwrap(),
            btf,
            id: item.id,
        })
    }
}

#[derive(Debug, Default)]
/// An iterator for the btf type information of modules and programs
/// in the kernel
pub struct BtfInfoIter {
    cur_id: u32,
}

impl Iterator for BtfInfoIter {
    type Item = BtfInfo;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if unsafe { libbpf_sys::bpf_btf_get_next_id(self.cur_id, &mut self.cur_id) } != 0 {
                return None;
            }

            let fd = unsafe { libbpf_sys::bpf_btf_get_fd_by_id(self.cur_id) };
            if fd < 0 {
                if errno::errno() == errno::Errno::ENOENT as i32 {
                    continue;
                }
                return None;
            }

            let info = BtfInfo::load_from_fd(fd);
            let _ = close(fd);

            match info {
                Ok(i) => return Some(i),
                // TODO: We should consider bubbling up errors properly.
                Err(_err) => (),
            }
        }
    }
}

#[derive(Debug, Clone)]
// TODO: Document members.
#[allow(missing_docs)]
pub struct RawTracepointLinkInfo {
    pub name: String,
}

#[derive(Debug, Clone)]
// TODO: Document members.
#[allow(missing_docs)]
pub struct TracingLinkInfo {
    pub attach_type: ProgramAttachType,
}

#[derive(Debug, Clone)]
// TODO: Document members.
#[allow(missing_docs)]
pub struct CgroupLinkInfo {
    pub cgroup_id: u64,
    pub attach_type: ProgramAttachType,
}

#[derive(Debug, Clone)]
// TODO: Document members.
#[allow(missing_docs)]
pub struct NetNsLinkInfo {
    pub ino: u32,
    pub attach_type: ProgramAttachType,
}

#[derive(Debug, Clone)]
// TODO: Document variants.
#[allow(missing_docs)]
pub enum LinkTypeInfo {
    RawTracepoint(RawTracepointLinkInfo),
    Tracing(TracingLinkInfo),
    Cgroup(CgroupLinkInfo),
    Iter,
    NetNs(NetNsLinkInfo),
    Unknown,
}

/// Information about a BPF link
#[derive(Debug, Clone)]
// TODO: Document members.
#[allow(missing_docs)]
pub struct LinkInfo {
    pub info: LinkTypeInfo,
    pub id: u32,
    pub prog_id: u32,
}

impl LinkInfo {
    fn from_uapi(fd: i32, mut s: libbpf_sys::bpf_link_info) -> Option<Self> {
        let type_info = match s.type_ {
            libbpf_sys::BPF_LINK_TYPE_RAW_TRACEPOINT => {
                let mut buf = [0; 256];
                s.__bindgen_anon_1.raw_tracepoint.tp_name = buf.as_mut_ptr() as u64;
                s.__bindgen_anon_1.raw_tracepoint.tp_name_len = buf.len() as u32;
                let item_ptr: *mut libbpf_sys::bpf_link_info = &mut s;
                let mut len = size_of_val(&s) as u32;

                let ret = unsafe {
                    libbpf_sys::bpf_obj_get_info_by_fd(fd, item_ptr as *mut c_void, &mut len)
                };
                if ret != 0 {
                    return None;
                }

                LinkTypeInfo::RawTracepoint(RawTracepointLinkInfo {
                    name: util::c_ptr_to_string(
                        unsafe { s.__bindgen_anon_1.raw_tracepoint.tp_name } as *const c_char,
                    )
                    .unwrap_or_else(|_| "?".to_string()),
                })
            }
            libbpf_sys::BPF_LINK_TYPE_TRACING => LinkTypeInfo::Tracing(TracingLinkInfo {
                attach_type: ProgramAttachType::try_from(unsafe {
                    s.__bindgen_anon_1.tracing.attach_type
                })
                .unwrap_or(ProgramAttachType::Unknown),
            }),
            libbpf_sys::BPF_LINK_TYPE_CGROUP => LinkTypeInfo::Cgroup(CgroupLinkInfo {
                cgroup_id: unsafe { s.__bindgen_anon_1.cgroup.cgroup_id },
                attach_type: ProgramAttachType::try_from(unsafe {
                    s.__bindgen_anon_1.cgroup.attach_type
                })
                .unwrap_or(ProgramAttachType::Unknown),
            }),
            libbpf_sys::BPF_LINK_TYPE_ITER => LinkTypeInfo::Iter,
            libbpf_sys::BPF_LINK_TYPE_NETNS => LinkTypeInfo::NetNs(NetNsLinkInfo {
                ino: unsafe { s.__bindgen_anon_1.netns.netns_ino },
                attach_type: ProgramAttachType::try_from(unsafe {
                    s.__bindgen_anon_1.netns.attach_type
                })
                .unwrap_or(ProgramAttachType::Unknown),
            }),
            _ => LinkTypeInfo::Unknown,
        };

        Some(Self {
            info: type_info,
            id: s.id,
            prog_id: s.prog_id,
        })
    }
}

gen_info_impl!(
    /// Iterator that returns [`LinkInfo`]s.
    LinkInfoIter,
    LinkInfo,
    libbpf_sys::bpf_link_info,
    libbpf_sys::bpf_link_get_next_id,
    libbpf_sys::bpf_link_get_fd_by_id
);
