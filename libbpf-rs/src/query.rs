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

use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::mem::size_of_val;
use std::mem::zeroed;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::raw::c_char;
use std::ptr;
use std::time::Duration;

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
            fn next_valid_fd(&mut self) -> Option<OwnedFd> {
                loop {
                    if unsafe { $next_id(self.cur_id, &mut self.cur_id) } != 0 {
                        return None;
                    }

                    let fd = unsafe { $fd_by_id(self.cur_id) };
                    if fd < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::NotFound {
                            continue;
                        }

                        return None;
                    }

                    return Some(unsafe { OwnedFd::from_raw_fd(fd)});
                }
            }
        }

        impl Iterator for $name {
            type Item = $info_ty;

            fn next(&mut self) -> Option<Self::Item> {
                let fd = self.next_valid_fd()?;

                // We need to use std::mem::zeroed() instead of just using
                // ::default() because padding bytes need to be zero as well.
                // Old kernels which know about fewer fields than we do will
                // check to make sure every byte past what they know is zero
                // and will return E2BIG otherwise.
                let mut item: $uapi_info_ty = unsafe { std::mem::zeroed() };
                let item_ptr: *mut $uapi_info_ty = &mut item;
                let mut len = size_of_val(&item) as u32;

                let ret = unsafe { libbpf_sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), item_ptr as *mut c_void, &mut len) };
                let parsed_uapi = if ret != 0 {
                    None
                } else {
                    <$info_ty>::from_uapi(fd.as_fd(), item)
                };

                parsed_uapi
            }
        }
    };
}

/// BTF Line information.
#[derive(Clone, Debug)]
pub struct LineInfo {
    /// Offset of instruction in vector.
    pub insn_off: u32,
    /// File name offset.
    pub file_name_off: u32,
    /// Line offset in debug info.
    pub line_off: u32,
    /// Line number.
    pub line_num: u32,
    /// Line column number.
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

/// Bpf identifier tag.
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct Tag(pub [u8; 8]);

/// Information about a BPF program. Maps to `struct bpf_prog_info` in kernel uapi.
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// A user-defined name for the BPF program (null-terminated string).
    pub name: CString,
    /// The type of the program.
    pub ty: ProgramType,
    /// An 8-byte hash (`BPF_TAG_SIZE`) computed from the program's
    /// contents; used to detect changes in the program code.
    pub tag: Tag,
    /// A unique identifier for the program instance.
    pub id: u32,
    /// JIT-compiled instructions.
    pub jited_prog_insns: Vec<u8>,
    /// Translated BPF instructions in an intermediate representation.
    pub xlated_prog_insns: Vec<u8>,
    /// Time (since system boot) at which the program was loaded.
    pub load_time: Duration,
    /// UID of the user who loaded the program.
    pub created_by_uid: u32,
    /// Array of map IDs associated with this program.
    pub map_ids: Vec<u32>,
    /// Network interface index if the program is attached to a specific device.
    pub ifindex: u32,
    /// Whether the program is GPL compatible.
    pub gpl_compatible: bool,
    /// Device ID of the network namespace that the program is associated with.
    pub netns_dev: u64,
    /// Inode number of the network namespace associated with the program.
    pub netns_ino: u64,
    /// Number of kernel symbols in the JITed code (if available).
    pub jited_ksyms: Vec<*const c_void>,
    /// Number of function length records available for the JITed code.
    pub jited_func_lens: Vec<u32>,
    /// Identifier of the associated BTF (BPF Type Format) data.
    pub btf_id: u32,
    /// Size (in bytes) of each record in the function info array.
    pub func_info_rec_size: u32,
    /// Array of function info records for this program.
    pub func_info: Vec<libbpf_sys::bpf_func_info>,
    /// Array of line info records mapping BPF instructions to source code lines.
    pub line_info: Vec<LineInfo>,
    /// Line info records for the JIT-compiled code.
    pub jited_line_info: Vec<*const c_void>,
    /// Size (in bytes) of each line info record.
    pub line_info_rec_size: u32,
    /// Size (in bytes) of each record in the JITed line info array.
    pub jited_line_info_rec_size: u32,
    /// Array of program tags.
    pub prog_tags: Vec<Tag>,
    /// Total accumulated run time (in nanoseconds) for the program's execution.
    pub run_time_ns: u64,
    /// Total number of times the program has been executed.
    pub run_cnt: u64,
    /// Skipped BPF executions due to recursion or concurrent execution prevention.
    pub recursion_misses: u64,
}

/// An iterator for the information of loaded bpf programs.
#[derive(Default, Debug)]
pub struct ProgInfoIter {
    cur_id: u32,
    opts: ProgInfoQueryOptions,
}

/// Options to query the program info currently loaded.
#[derive(Clone, Default, Debug)]
pub struct ProgInfoQueryOptions {
    /// Include the vector of bpf instructions in the result.
    include_xlated_prog_insns: bool,
    /// Include the vector of jited instructions in the result.
    include_jited_prog_insns: bool,
    /// Include the ids of maps associated with the program.
    include_map_ids: bool,
    /// Include source line information corresponding to xlated code.
    include_line_info: bool,
    /// Include function type information corresponding to xlated code.
    include_func_info: bool,
    /// Include source line information corresponding to jited code.
    include_jited_line_info: bool,
    /// Include function type information corresponding to jited code.
    include_jited_func_lens: bool,
    /// Include program tags.
    include_prog_tags: bool,
    /// Include the jited kernel symbols.
    include_jited_ksyms: bool,
}

impl ProgInfoIter {
    /// Generate an iter from more specific query options.
    pub fn with_query_opts(opts: ProgInfoQueryOptions) -> Self {
        Self {
            opts,
            ..Self::default()
        }
    }
}

impl ProgInfoQueryOptions {
    /// Include the vector of jited bpf instructions in the result.
    pub fn include_xlated_prog_insns(mut self, v: bool) -> Self {
        self.include_xlated_prog_insns = v;
        self
    }

    /// Include the vector of jited instructions in the result.
    pub fn include_jited_prog_insns(mut self, v: bool) -> Self {
        self.include_jited_prog_insns = v;
        self
    }

    /// Include the ids of maps associated with the program.
    pub fn include_map_ids(mut self, v: bool) -> Self {
        self.include_map_ids = v;
        self
    }

    /// Include source line information corresponding to xlated code.
    pub fn include_line_info(mut self, v: bool) -> Self {
        self.include_line_info = v;
        self
    }

    /// Include function type information corresponding to xlated code.
    pub fn include_func_info(mut self, v: bool) -> Self {
        self.include_func_info = v;
        self
    }

    /// Include source line information corresponding to jited code.
    pub fn include_jited_line_info(mut self, v: bool) -> Self {
        self.include_jited_line_info = v;
        self
    }

    /// Include function type information corresponding to jited code.
    pub fn include_jited_func_lens(mut self, v: bool) -> Self {
        self.include_jited_func_lens = v;
        self
    }

    /// Include program tags.
    pub fn include_prog_tags(mut self, v: bool) -> Self {
        self.include_prog_tags = v;
        self
    }

    /// Include the jited kernel symbols.
    pub fn include_jited_ksyms(mut self, v: bool) -> Self {
        self.include_jited_ksyms = v;
        self
    }

    /// Include everything there is in the query results.
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
    fn load_from_fd(fd: BorrowedFd<'_>, opts: &ProgInfoQueryOptions) -> Result<Self> {
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

        let ret = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), item_ptr as *mut c_void, &mut len)
        };
        util::parse_ret(ret)?;

        // SANITY: `libbpf` should guarantee NUL termination.
        let name = util::c_char_slice_to_cstr(&item.name).unwrap();
        let ty = ProgramType::from(item.type_);

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

        let ret = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), item_ptr as *mut c_void, &mut len)
        };
        util::parse_ret(ret)?;

        Ok(ProgramInfo {
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
            line_info: line_info.iter().map(Into::into).collect(),
            jited_line_info,
            line_info_rec_size: item.line_info_rec_size,
            jited_line_info_rec_size: item.jited_line_info_rec_size,
            prog_tags,
            run_time_ns: item.run_time_ns,
            run_cnt: item.run_cnt,
            recursion_misses: item.recursion_misses,
        })
    }
}

impl ProgInfoIter {
    fn next_valid_fd(&mut self) -> Option<OwnedFd> {
        loop {
            if unsafe { libbpf_sys::bpf_prog_get_next_id(self.cur_id, &mut self.cur_id) } != 0 {
                return None;
            }

            let fd = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(self.cur_id) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::NotFound {
                    continue;
                }
                return None;
            }

            return Some(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
}

impl Iterator for ProgInfoIter {
    type Item = ProgramInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let fd = self.next_valid_fd()?;
        let prog = ProgramInfo::load_from_fd(fd.as_fd(), &self.opts);
        prog.ok()
    }
}

/// Information about a BPF map. Maps to `struct bpf_map_info` in kernel uapi.
#[derive(Debug, Clone)]
pub struct MapInfo {
    /// A user-defined name for the BPF Map (null-terminated string).
    pub name: CString,
    /// The BPF map type.
    pub ty: MapType,
    /// A unique identifier for this map instance.
    pub id: u32,
    /// Size (in bytes) of the keys stored in the map.
    pub key_size: u32,
    /// Size (in bytes) of the values stored in the map.
    pub value_size: u32,
    /// Maximum number of entries that the map can hold.
    pub max_entries: u32,
    /// Map flags indicating specific properties (e.g., `BPF_F_NO_PREALLOC`).
    pub map_flags: u32,
    /// Network interface index if the map is associated with a specific device. Otherwise, this
    /// may be zero.
    pub ifindex: u32,
    /// BTF (BPF Type Format) type ID for the value type as defined in the vmlinux BTF data.
    pub btf_vmlinux_value_type_id: u32,
    /// Device identifier of the network namespace.
    pub netns_dev: u64,
    /// Inode number of the network namespace.
    pub netns_ino: u64,
    /// BTF ID referencing the BTF data for this map. This helps to verify the correctness of the
    /// map's data structure as per BTF metadata.
    pub btf_id: u32,
    /// BTF type ID for the key type.
    pub btf_key_type_id: u32,
    /// BTF type ID for the value type.
    pub btf_value_type_id: u32,
}

impl MapInfo {
    fn from_uapi(_fd: BorrowedFd<'_>, s: libbpf_sys::bpf_map_info) -> Option<Self> {
        // SANITY: `libbpf` should guarantee NUL termination.
        let name = util::c_char_slice_to_cstr(&s.name).unwrap();
        let ty = MapType::from(s.type_);

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

/// Information about BPF type format.
#[derive(Debug, Clone)]
pub struct BtfInfo {
    /// The name associated with this btf information in the kernel.
    pub name: CString,
    /// The raw btf bytes from the kernel.
    pub btf: Vec<u8>,
    /// The btf id associated with this btf information in the kernel.
    pub id: u32,
}

impl BtfInfo {
    fn load_from_fd(fd: BorrowedFd<'_>) -> Result<Self> {
        let mut item = libbpf_sys::bpf_btf_info::default();
        let mut btf: Vec<u8> = Vec::new();
        let mut name: Vec<u8> = Vec::new();

        let item_ptr: *mut libbpf_sys::bpf_btf_info = &mut item;
        let mut len = size_of_val(&item) as u32;

        let ret = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), item_ptr as *mut c_void, &mut len)
        };
        util::parse_ret(ret)?;

        // The API gives you the ascii string length while expecting
        // you to give it back space for a nul-terminator
        item.name_len += 1;
        name.resize(item.name_len as usize, 0u8);
        item.name = name.as_mut_ptr() as *mut c_void as u64;

        btf.resize(item.btf_size as usize, 0u8);
        item.btf = btf.as_mut_ptr() as *mut c_void as u64;

        let ret = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), item_ptr as *mut c_void, &mut len)
        };
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

impl BtfInfoIter {
    // Returns Some(next_valid_fd), None on none left
    fn next_valid_fd(&mut self) -> Option<OwnedFd> {
        loop {
            if unsafe { libbpf_sys::bpf_btf_get_next_id(self.cur_id, &mut self.cur_id) } != 0 {
                return None;
            }

            let fd = unsafe { libbpf_sys::bpf_btf_get_fd_by_id(self.cur_id) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::NotFound {
                    continue;
                }
                return None;
            }

            return Some(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
}

impl Iterator for BtfInfoIter {
    type Item = BtfInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let fd = self.next_valid_fd()?;
        let info = BtfInfo::load_from_fd(fd.as_fd());
        info.ok()
    }
}

/// Information about a raw tracepoint.
#[derive(Debug, Clone)]
pub struct RawTracepointLinkInfo {
    /// The name of the raw tracepoint.
    pub name: String,
}

/// Information about a tracing link
#[derive(Debug, Clone)]
pub struct TracingLinkInfo {
    /// Attach type of the tracing link.
    pub attach_type: ProgramAttachType,
    /// Target object ID (`prog_id` for [`ProgramType::Ext`], otherwise
    /// BTF object id).
    pub target_obj_id: u32,
    /// BTF type id inside the target object.
    pub target_btf_id: u32,
}

/// Information about a cgroup link
#[derive(Debug, Clone)]
pub struct CgroupLinkInfo {
    /// Identifier of the target cgroup.
    pub cgroup_id: u64,
    /// Attachment type for cgroup-based programs.
    pub attach_type: ProgramAttachType,
}

/// Information about a network namespace link.
#[derive(Debug, Clone)]
pub struct NetNsLinkInfo {
    /// Inode number of the network namespace.
    pub ino: u32,
    /// Attachment type for network namespace programs.
    pub attach_type: ProgramAttachType,
}

/// Information about a BPF netfilter link.
#[derive(Debug, Clone)]
pub struct NetfilterLinkInfo {
    /// Protocol family of the netfilter hook.
    pub protocol_family: u32,
    /// Netfilter hook number.
    pub hooknum: u32,
    /// Priority of the netfilter link.
    pub priority: i32,
    /// Flags used for the netfilter link.
    pub flags: u32,
}

/// Information about a XDP link.
#[derive(Debug, Clone)]
pub struct XdpLinkInfo {
    /// Interface index to which the XDP link is attached.
    pub ifindex: u32,
}

/// Information about a BPF sockmap link.
#[derive(Debug, Clone)]
pub struct SockMapLinkInfo {
    /// The ID of the BPF sockmap.
    pub map_id: u32,
    /// The type of program attached to the sockmap.
    pub attach_type: ProgramAttachType,
}

/// Information about a BPF netkit link.
#[derive(Debug, Clone)]
pub struct NetkitLinkInfo {
    /// Interface index to which the netkit link is attached.
    pub ifindex: u32,
    /// Type of program attached to the netkit link.
    pub attach_type: ProgramAttachType,
}

/// Information about a BPF tc link.
#[derive(Debug, Clone)]
pub struct TcxLinkInfo {
    /// Interface index to which the tc link is attached.
    pub ifindex: u32,
    /// Type of program attached to the tc link.
    pub attach_type: ProgramAttachType,
}

/// Information about a BPF `struct_ops` link.
#[derive(Debug, Clone)]
pub struct StructOpsLinkInfo {
    /// The ID of the BPF map to which the `struct_ops` link is attached.
    pub map_id: u32,
}

/// Information about a multi-kprobe link.
#[derive(Debug, Clone)]
pub struct KprobeMultiLinkInfo {
    /// Count of kprobe targets.
    pub count: u32,
    /// Flags for the link.
    pub flags: u32,
    /// Missed probes count.
    pub missed: u64,
}

/// Information about a multi-uprobe link.
#[derive(Debug, Clone)]
pub struct UprobeMultiLinkInfo {
    /// Size of the path.
    pub path_size: u32,
    /// Count of uprobe targets.
    pub count: u32,
    /// Flags for the link.
    pub flags: u32,
    /// PID to which the uprobe is attached.
    pub pid: u32,
}

/// Information about a perf event link.
#[derive(Debug, Clone)]
pub struct PerfEventLinkInfo {
    /// The specific type of perf event with decoded information.
    pub event_type: PerfEventType,
}

/// Specific types of perf events with decoded information.
#[derive(Debug, Clone)]
pub enum PerfEventType {
    /// A tracepoint event.
    Tracepoint {
        /// The tracepoint name.
        name: Option<CString>,
        /// Attach cookie value for this link.
        cookie: u64,
    },
    /// A kprobe event (includes both kprobe and kretprobe).
    Kprobe {
        /// The function being probed.
        func_name: Option<CString>,
        /// Whether this is a return probe (kretprobe).
        is_retprobe: bool,
        /// Address of the probe.
        addr: u64,
        /// Offset from the function.
        offset: u32,
        /// Number of missed events.
        missed: u64,
        /// Cookie value for the kprobe.
        cookie: u64,
    },
    /// A uprobe event (includes both uprobe and uretprobe).
    Uprobe {
        /// The absolute file path of the binary being probed.
        file_name: Option<CString>,
        /// Whether this is a return probe (uretprobe).
        is_retprobe: bool,
        /// Offset from the binary.
        offset: u32,
        /// Cookie value for the uprobe.
        cookie: u64,
        /// Offset of kernel reference counted USDT semaphore.
        ref_ctr_offset: u64,
    },
    /// An unknown or unsupported perf event type.
    // TODO: Add support for `BPF_PERF_EVENT_EVENT`
    Unknown(u32),
}

/// Information about BPF link types. Maps to the anonymous union in `struct bpf_link_info` in
/// kernel uapi.
#[derive(Debug, Clone)]
pub enum LinkTypeInfo {
    /// Link type for raw tracepoints.
    ///
    /// Contains information about the BPF program directly to a raw tracepoint.
    RawTracepoint(RawTracepointLinkInfo),
    /// Tracing link type.
    Tracing(TracingLinkInfo),
    /// Link type for cgroup programs.
    ///
    /// Contains information about the cgroups and its attachment type.
    Cgroup(CgroupLinkInfo),
    /// Iterator link type.
    Iter,
    /// Network namespace link type.
    NetNs(NetNsLinkInfo),
    /// Link type for XDP programs.
    ///
    /// Contains information about the XDP link, such as the interface index
    /// to which the XDP link is attached.
    Xdp(XdpLinkInfo),
    /// Link type for `struct_ops` programs.
    ///
    /// Contains information about the BPF map to which the `struct_ops` link is
    /// attached.
    StructOps(StructOpsLinkInfo),
    /// Link type for netfilter programs.
    Netfilter(NetfilterLinkInfo),
    /// Link type for kprobe-multi links.
    KprobeMulti(KprobeMultiLinkInfo),
    /// Link type for multi-uprobe links.
    UprobeMulti(UprobeMultiLinkInfo),
    /// Link type for TC programs.
    Tcx(TcxLinkInfo),
    /// Link type for netkit programs.
    Netkit(NetkitLinkInfo),
    /// Link type for sockmap programs.
    SockMap(SockMapLinkInfo),
    /// Link type for perf-event programs.
    ///
    /// Contains information about the perf event configuration including type and config
    /// which can be used to identify tracepoints, kprobes, uprobes, etc.
    PerfEvent(PerfEventLinkInfo),
    /// Unknown link type.
    Unknown,
}

/// Information about a BPF link. Maps to `struct bpf_link_info` in kernel uapi.
#[derive(Debug, Clone)]
pub struct LinkInfo {
    /// Information about the BPF link type.
    pub info: LinkTypeInfo,
    /// Unique identifier of the BPF link.
    pub id: u32,
    /// ID of the BPF program attached via this link.
    pub prog_id: u32,
}

impl LinkInfo {
    /// Create a `LinkInfo` object from a fd.
    pub fn from_fd(fd: BorrowedFd<'_>) -> Result<Self> {
        // See comment in gen_info_impl!() for why we use std::mem::zeroed()
        let mut link_info: libbpf_sys::bpf_link_info = unsafe { zeroed() };
        let item_ptr: *mut libbpf_sys::bpf_link_info = &mut link_info;
        let mut len = size_of_val(&link_info) as u32;

        let ret = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), item_ptr as *mut c_void, &mut len)
        };
        util::parse_ret(ret)?;

        Self::from_uapi(fd, link_info)
            .ok_or_else(|| crate::Error::with_invalid_data("failed to parse link info"))
    }

    fn from_uapi(fd: BorrowedFd<'_>, mut s: libbpf_sys::bpf_link_info) -> Option<Self> {
        let type_info = match s.type_ {
            libbpf_sys::BPF_LINK_TYPE_RAW_TRACEPOINT => {
                let mut buf = [0; 256];
                s.__bindgen_anon_1.raw_tracepoint.tp_name = buf.as_mut_ptr() as u64;
                s.__bindgen_anon_1.raw_tracepoint.tp_name_len = buf.len() as u32;
                let item_ptr: *mut libbpf_sys::bpf_link_info = &mut s;
                let mut len = size_of_val(&s) as u32;

                let ret = unsafe {
                    libbpf_sys::bpf_obj_get_info_by_fd(
                        fd.as_raw_fd(),
                        item_ptr as *mut c_void,
                        &mut len,
                    )
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
                attach_type: ProgramAttachType::from(unsafe {
                    s.__bindgen_anon_1.tracing.attach_type
                }),
                target_obj_id: unsafe { s.__bindgen_anon_1.tracing.target_obj_id },
                target_btf_id: unsafe { s.__bindgen_anon_1.tracing.target_btf_id },
            }),
            libbpf_sys::BPF_LINK_TYPE_CGROUP => LinkTypeInfo::Cgroup(CgroupLinkInfo {
                cgroup_id: unsafe { s.__bindgen_anon_1.cgroup.cgroup_id },
                attach_type: ProgramAttachType::from(unsafe {
                    s.__bindgen_anon_1.cgroup.attach_type
                }),
            }),
            libbpf_sys::BPF_LINK_TYPE_ITER => LinkTypeInfo::Iter,
            libbpf_sys::BPF_LINK_TYPE_NETNS => LinkTypeInfo::NetNs(NetNsLinkInfo {
                ino: unsafe { s.__bindgen_anon_1.netns.netns_ino },
                attach_type: ProgramAttachType::from(unsafe {
                    s.__bindgen_anon_1.netns.attach_type
                }),
            }),
            libbpf_sys::BPF_LINK_TYPE_NETFILTER => LinkTypeInfo::Netfilter(NetfilterLinkInfo {
                protocol_family: unsafe { s.__bindgen_anon_1.netfilter.pf },
                hooknum: unsafe { s.__bindgen_anon_1.netfilter.hooknum },
                priority: unsafe { s.__bindgen_anon_1.netfilter.priority },
                flags: unsafe { s.__bindgen_anon_1.netfilter.flags },
            }),
            libbpf_sys::BPF_LINK_TYPE_XDP => LinkTypeInfo::Xdp(XdpLinkInfo {
                ifindex: unsafe { s.__bindgen_anon_1.xdp.ifindex },
            }),
            libbpf_sys::BPF_LINK_TYPE_NETKIT => LinkTypeInfo::Netkit(NetkitLinkInfo {
                ifindex: unsafe { s.__bindgen_anon_1.netkit.ifindex },
                attach_type: ProgramAttachType::from(unsafe {
                    s.__bindgen_anon_1.netkit.attach_type
                }),
            }),
            libbpf_sys::BPF_LINK_TYPE_TCX => LinkTypeInfo::Tcx(TcxLinkInfo {
                ifindex: unsafe { s.__bindgen_anon_1.tcx.ifindex },
                attach_type: ProgramAttachType::from(unsafe { s.__bindgen_anon_1.tcx.attach_type }),
            }),
            libbpf_sys::BPF_LINK_TYPE_STRUCT_OPS => LinkTypeInfo::StructOps(StructOpsLinkInfo {
                map_id: unsafe { s.__bindgen_anon_1.struct_ops.map_id },
            }),
            libbpf_sys::BPF_LINK_TYPE_KPROBE_MULTI => {
                LinkTypeInfo::KprobeMulti(KprobeMultiLinkInfo {
                    count: unsafe { s.__bindgen_anon_1.kprobe_multi.count },
                    flags: unsafe { s.__bindgen_anon_1.kprobe_multi.flags },
                    missed: unsafe { s.__bindgen_anon_1.kprobe_multi.missed },
                })
            }
            libbpf_sys::BPF_LINK_TYPE_UPROBE_MULTI => {
                LinkTypeInfo::UprobeMulti(UprobeMultiLinkInfo {
                    path_size: unsafe { s.__bindgen_anon_1.uprobe_multi.path_size },
                    count: unsafe { s.__bindgen_anon_1.uprobe_multi.count },
                    flags: unsafe { s.__bindgen_anon_1.uprobe_multi.flags },
                    pid: unsafe { s.__bindgen_anon_1.uprobe_multi.pid },
                })
            }
            libbpf_sys::BPF_LINK_TYPE_SOCKMAP => LinkTypeInfo::SockMap(SockMapLinkInfo {
                map_id: unsafe { s.__bindgen_anon_1.sockmap.map_id },
                attach_type: ProgramAttachType::from(unsafe {
                    s.__bindgen_anon_1.sockmap.attach_type
                }),
            }),
            libbpf_sys::BPF_LINK_TYPE_PERF_EVENT => {
                // Get the BPF perf event type (BPF_PERF_EVENT_*) from the link info.
                let bpf_perf_event_type = unsafe { s.__bindgen_anon_1.perf_event.type_ };

                // Handle two-phase call for perf event string data if needed (this mimics the
                // behavior of bpftool):
                // For tracepoints, kprobes, and uprobes, we need to pass in a buffer to get the
                // name. So we initialize the struct with a buffer pointer, and call
                // `bpf_obj_get_info_by_fd` again to populate the name.
                let mut buf = [0u8; libc::PATH_MAX as usize];
                let call_get_info_again = match bpf_perf_event_type {
                    libbpf_sys::BPF_PERF_EVENT_TRACEPOINT => {
                        s.__bindgen_anon_1
                            .perf_event
                            .__bindgen_anon_1
                            .tracepoint
                            .tp_name = buf.as_mut_ptr() as u64;
                        s.__bindgen_anon_1
                            .perf_event
                            .__bindgen_anon_1
                            .tracepoint
                            .name_len = buf.len() as u32;
                        true
                    }
                    libbpf_sys::BPF_PERF_EVENT_KPROBE | libbpf_sys::BPF_PERF_EVENT_KRETPROBE => {
                        s.__bindgen_anon_1
                            .perf_event
                            .__bindgen_anon_1
                            .kprobe
                            .func_name = buf.as_mut_ptr() as u64;
                        s.__bindgen_anon_1
                            .perf_event
                            .__bindgen_anon_1
                            .kprobe
                            .name_len = buf.len() as u32;
                        true
                    }
                    libbpf_sys::BPF_PERF_EVENT_UPROBE | libbpf_sys::BPF_PERF_EVENT_URETPROBE => {
                        // SAFETY: This field is valid to access in `bpf_link_info`.
                        let uprobe =
                            unsafe { &mut s.__bindgen_anon_1.perf_event.__bindgen_anon_1.uprobe };
                        uprobe.file_name = buf.as_mut_ptr() as u64;
                        uprobe.name_len = buf.len() as u32;
                        true
                    }
                    _ => false,
                };

                if call_get_info_again {
                    let item_ptr: *mut libbpf_sys::bpf_link_info = &mut s;
                    let mut len = size_of_val(&s) as u32;
                    let ret = unsafe {
                        libbpf_sys::bpf_obj_get_info_by_fd(
                            fd.as_raw_fd(),
                            item_ptr as *mut c_void,
                            &mut len,
                        )
                    };
                    if ret != 0 {
                        return None;
                    }
                }

                let event_type = match bpf_perf_event_type {
                    libbpf_sys::BPF_PERF_EVENT_TRACEPOINT => {
                        let tp_name = unsafe {
                            s.__bindgen_anon_1
                                .perf_event
                                .__bindgen_anon_1
                                .tracepoint
                                .tp_name
                        };
                        let cookie = unsafe {
                            s.__bindgen_anon_1
                                .perf_event
                                .__bindgen_anon_1
                                .tracepoint
                                .cookie
                        };
                        let name = (tp_name != 0).then(|| unsafe {
                            CStr::from_ptr(tp_name as *const c_char).to_owned()
                        });

                        PerfEventType::Tracepoint { name, cookie }
                    }
                    libbpf_sys::BPF_PERF_EVENT_KPROBE | libbpf_sys::BPF_PERF_EVENT_KRETPROBE => {
                        let func_name = unsafe {
                            s.__bindgen_anon_1
                                .perf_event
                                .__bindgen_anon_1
                                .kprobe
                                .func_name
                        };
                        let addr =
                            unsafe { s.__bindgen_anon_1.perf_event.__bindgen_anon_1.kprobe.addr };
                        let offset =
                            unsafe { s.__bindgen_anon_1.perf_event.__bindgen_anon_1.kprobe.offset };
                        let missed =
                            unsafe { s.__bindgen_anon_1.perf_event.__bindgen_anon_1.kprobe.missed };
                        let cookie =
                            unsafe { s.__bindgen_anon_1.perf_event.__bindgen_anon_1.kprobe.cookie };
                        let func_name = (func_name != 0).then(|| unsafe {
                            CStr::from_ptr(func_name as *const c_char).to_owned()
                        });

                        let is_retprobe =
                            bpf_perf_event_type == libbpf_sys::BPF_PERF_EVENT_KRETPROBE;
                        PerfEventType::Kprobe {
                            func_name,
                            is_retprobe,
                            addr,
                            offset,
                            missed,
                            cookie,
                        }
                    }
                    libbpf_sys::BPF_PERF_EVENT_UPROBE | libbpf_sys::BPF_PERF_EVENT_URETPROBE => {
                        // SAFETY: This field is valid to access in `bpf_link_info`.
                        let uprobe =
                            unsafe { s.__bindgen_anon_1.perf_event.__bindgen_anon_1.uprobe };
                        // SAFETY: `file_name_ptr` is a valid nul terminated string pointer.
                        let file_name = (uprobe.file_name != 0).then(|| unsafe {
                            CStr::from_ptr(uprobe.file_name as *const c_char).to_owned()
                        });

                        PerfEventType::Uprobe {
                            file_name,
                            is_retprobe: bpf_perf_event_type
                                == libbpf_sys::BPF_PERF_EVENT_URETPROBE,
                            offset: uprobe.offset,
                            cookie: uprobe.cookie,
                            ref_ctr_offset: uprobe.ref_ctr_offset,
                        }
                    }
                    ty => PerfEventType::Unknown(ty),
                };

                LinkTypeInfo::PerfEvent(PerfEventLinkInfo { event_type })
            }
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
