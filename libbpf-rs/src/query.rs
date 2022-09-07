//! Query the host about BPF
//!
//! For example, to list the name of every bpf program running on the system:
//! ```
//! use libbpf_rs::query::ProgInfoIter;
//!
//! let mut iter = ProgInfoIter::default();
//! for prog in iter {
//!     println!("{}", prog.name);
//! }
//! ```

use core::ffi::c_void;
use std::convert::TryFrom;
use std::mem::size_of;
use std::os::raw::c_char;
use std::string::String;
use std::time::Duration;

use nix::{errno, unistd::close};

use crate::*;

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
                let mut len = size_of::<$uapi_info_ty>() as u32;

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

fn name_arr_to_string(a: &[c_char], default: &str) -> String {
    let converted_arr: Vec<u8> = a
        .iter()
        .take_while(|x| **x != 0)
        .map(|x| *x as u8)
        .collect();
    if !converted_arr.is_empty() {
        String::from_utf8(converted_arr).unwrap_or_else(|_| default.to_string())
    } else {
        default.to_string()
    }
}

/// Information about a BPF program
#[derive(Debug)]
pub struct ProgramInfo {
    pub name: String,
    pub ty: ProgramType,
    pub tag: [u8; 8],
    pub id: u32,
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    pub jited_prog_insns: u64,
    pub xlated_prog_insns: u64,
    /// Duration since system boot
    pub load_time: Duration,
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    pub map_ids: u64,
    pub ifindex: u32,
    pub gpl_compatible: bool,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_jited_ksyms: u32,
    pub nr_jited_func_lens: u32,
    pub jited_ksyms: u64,
    pub jited_func_lens: u64,
    pub btf_id: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub nr_func_info: u32,
    pub nr_line_info: u32,
    pub line_info: u64,
    pub jited_line_info: u64,
    pub nr_jited_line_info: u32,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub nr_prog_tags: u32,
    pub prog_tags: u64,
    pub run_time_ns: u64,
    pub run_cnt: u64,
}

impl ProgramInfo {
    fn from_uapi(_fd: i32, s: libbpf_sys::bpf_prog_info) -> Option<Self> {
        let name = name_arr_to_string(&s.name, "(?)");
        let ty = match ProgramType::try_from(s.type_) {
            Ok(ty) => ty,
            Err(_) => ProgramType::Unknown,
        };

        Some(ProgramInfo {
            name,
            ty,
            tag: s.tag,
            id: s.id,
            jited_prog_len: s.jited_prog_len,
            xlated_prog_len: s.xlated_prog_len,
            jited_prog_insns: s.jited_prog_insns,
            xlated_prog_insns: s.xlated_prog_insns,
            load_time: Duration::from_nanos(s.load_time),
            created_by_uid: s.created_by_uid,
            nr_map_ids: s.nr_map_ids,
            map_ids: s.map_ids,
            ifindex: s.ifindex,
            gpl_compatible: s._bitfield_1.get_bit(0),
            netns_dev: s.netns_dev,
            netns_ino: s.netns_ino,
            nr_jited_ksyms: s.nr_jited_ksyms,
            nr_jited_func_lens: s.nr_jited_func_lens,
            jited_ksyms: s.jited_ksyms,
            jited_func_lens: s.jited_func_lens,
            btf_id: s.btf_id,
            func_info_rec_size: s.func_info_rec_size,
            func_info: s.func_info,
            nr_func_info: s.nr_func_info,
            nr_line_info: s.nr_line_info,
            line_info: s.line_info,
            jited_line_info: s.jited_line_info,
            nr_jited_line_info: s.nr_jited_line_info,
            line_info_rec_size: s.line_info_rec_size,
            jited_line_info_rec_size: s.jited_line_info_rec_size,
            nr_prog_tags: s.nr_prog_tags,
            prog_tags: s.prog_tags,
            run_time_ns: s.run_time_ns,
            run_cnt: s.run_cnt,
        })
    }
}

gen_info_impl!(
    /// Iterator that returns [`ProgramInfo`]s.
    ProgInfoIter,
    ProgramInfo,
    libbpf_sys::bpf_prog_info,
    libbpf_sys::bpf_prog_get_next_id,
    libbpf_sys::bpf_prog_get_fd_by_id
);

/// Information about a BPF map
#[derive(Debug)]
pub struct MapInfo {
    pub name: String,
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
        let name = name_arr_to_string(&s.name, "(?)");
        let ty = match MapType::try_from(s.type_) {
            Ok(ty) => ty,
            Err(_) => MapType::Unknown,
        };

        Some(Self {
            name,
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
#[derive(Debug)]
pub struct BtfInfo {
    pub btf: u64,
    pub btf_size: u32,
    pub id: u32,
}

impl BtfInfo {
    fn from_uapi(_fd: i32, s: libbpf_sys::bpf_btf_info) -> Option<Self> {
        Some(Self {
            btf: s.btf,
            btf_size: s.btf_size,
            id: s.id,
        })
    }
}

gen_info_impl!(
    /// Iterator that returns [`BtfInfo`]s.
    BtfInfoIter,
    BtfInfo,
    libbpf_sys::bpf_btf_info,
    libbpf_sys::bpf_btf_get_next_id,
    libbpf_sys::bpf_btf_get_fd_by_id
);

#[derive(Debug)]
pub struct RawTracepointLinkInfo {
    pub name: String,
}

#[derive(Debug)]
pub struct TracingLinkInfo {
    pub attach_type: ProgramAttachType,
}

#[derive(Debug)]
pub struct CgroupLinkInfo {
    pub cgroup_id: u64,
    pub attach_type: ProgramAttachType,
}

#[derive(Debug)]
pub struct NetNsLinkInfo {
    pub ino: u32,
    pub attach_type: ProgramAttachType,
}

#[derive(Debug)]
pub enum LinkTypeInfo {
    RawTracepoint(RawTracepointLinkInfo),
    Tracing(TracingLinkInfo),
    Cgroup(CgroupLinkInfo),
    Iter,
    NetNs(NetNsLinkInfo),
    Unknown,
}

/// Information about a BPF link
#[derive(Debug)]
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
                let mut len = size_of::<libbpf_sys::bpf_link_info>() as u32;

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
