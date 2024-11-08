// `rustdoc` is buggy, claiming that we have some links to private items
// when they are actually public.
#![allow(rustdoc::private_intra_doc_links)]

use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::mem;
use std::mem::size_of;
use std::mem::size_of_val;
use std::mem::transmute;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::io::AsFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::BorrowedFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::OwnedFd;
use std::path::Path;
use std::ptr;
use std::ptr::NonNull;
use std::slice;

use libbpf_sys::bpf_func_id;

use crate::netfilter;
use crate::util;
use crate::util::validate_bpf_ret;
use crate::util::BpfObjectType;
use crate::AsRawLibbpf;
use crate::Error;
use crate::ErrorExt as _;
use crate::Link;
use crate::Mut;
use crate::Result;

/// Options to optionally be provided when attaching to a uprobe.
#[derive(Clone, Debug, Default)]
pub struct UprobeOpts {
    /// Offset of kernel reference counted USDT semaphore.
    pub ref_ctr_offset: usize,
    /// Custom user-provided value accessible through `bpf_get_attach_cookie`.
    pub cookie: u64,
    /// uprobe is return probe, invoked at function return time.
    pub retprobe: bool,
    /// Function name to attach to.
    ///
    /// Could be an unqualified ("abc") or library-qualified "abc@LIBXYZ" name.
    /// To specify function entry, `func_name` should be set while `func_offset`
    /// argument to should be 0. To trace an offset within a function, specify
    /// `func_name` and use `func_offset` argument to specify offset within the
    /// function. Shared library functions must specify the shared library
    /// binary_path.
    pub func_name: String,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

/// Options to optionally be provided when attaching to a USDT.
#[derive(Clone, Debug, Default)]
pub struct UsdtOpts {
    /// Custom user-provided value accessible through `bpf_usdt_cookie`.
    pub cookie: u64,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl From<UsdtOpts> for libbpf_sys::bpf_usdt_opts {
    fn from(opts: UsdtOpts) -> Self {
        let UsdtOpts {
            cookie,
            _non_exhaustive,
        } = opts;
        #[allow(clippy::needless_update)]
        libbpf_sys::bpf_usdt_opts {
            sz: size_of::<Self>() as _,
            usdt_cookie: cookie,
            // bpf_usdt_opts might have padding fields on some platform
            ..Default::default()
        }
    }
}

/// Options to optionally be provided when attaching to a tracepoint.
#[derive(Clone, Debug, Default)]
pub struct TracepointOpts {
    /// Custom user-provided value accessible through `bpf_get_attach_cookie`.
    pub cookie: u64,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl From<TracepointOpts> for libbpf_sys::bpf_tracepoint_opts {
    fn from(opts: TracepointOpts) -> Self {
        let TracepointOpts {
            cookie,
            _non_exhaustive,
        } = opts;

        #[allow(clippy::needless_update)]
        libbpf_sys::bpf_tracepoint_opts {
            sz: size_of::<Self>() as _,
            bpf_cookie: cookie,
            // bpf_tracepoint_opts might have padding fields on some platform
            ..Default::default()
        }
    }
}


/// An immutable parsed but not yet loaded BPF program.
pub type OpenProgram<'obj> = OpenProgramImpl<'obj>;
/// A mutable parsed but not yet loaded BPF program.
pub type OpenProgramMut<'obj> = OpenProgramImpl<'obj, Mut>;

/// Represents a parsed but not yet loaded BPF program.
///
/// This object exposes operations that need to happen before the program is loaded.
#[derive(Debug)]
#[repr(transparent)]
pub struct OpenProgramImpl<'obj, T = ()> {
    ptr: NonNull<libbpf_sys::bpf_program>,
    _phantom: PhantomData<&'obj T>,
}

impl<'obj> OpenProgram<'obj> {
    /// Create a new [`OpenProgram`] from a ptr to a `libbpf_sys::bpf_program`.
    pub fn new(prog: &'obj libbpf_sys::bpf_program) -> Self {
        // SAFETY: We inferred the address from a reference, which is always
        //         valid.
        Self {
            ptr: unsafe { NonNull::new_unchecked(prog as *const _ as *mut _) },
            _phantom: PhantomData,
        }
    }

    /// The `ProgramType` of this `OpenProgram`.
    pub fn prog_type(&self) -> ProgramType {
        ProgramType::from(unsafe { libbpf_sys::bpf_program__type(self.ptr.as_ptr()) })
    }

    /// Retrieve the name of this `OpenProgram`.
    pub fn name(&self) -> &OsStr {
        let name_ptr = unsafe { libbpf_sys::bpf_program__name(self.ptr.as_ptr()) };
        let name_c_str = unsafe { CStr::from_ptr(name_ptr) };
        // SAFETY: `bpf_program__name` always returns a non-NULL pointer.
        OsStr::from_bytes(name_c_str.to_bytes())
    }

    /// Retrieve the name of the section this `OpenProgram` belongs to.
    pub fn section(&self) -> &OsStr {
        // SAFETY: The program is always valid.
        let p = unsafe { libbpf_sys::bpf_program__section_name(self.ptr.as_ptr()) };
        // SAFETY: `bpf_program__section_name` will always return a non-NULL
        //         pointer.
        let section_c_str = unsafe { CStr::from_ptr(p) };
        let section = OsStr::from_bytes(section_c_str.to_bytes());
        section
    }

    /// Returns the number of instructions that form the program.
    ///
    /// Note: Keep in mind, libbpf can modify the program's instructions
    /// and consequently its instruction count, as it processes the BPF object file.
    /// So [`OpenProgram::insn_cnt`] and [`Program::insn_cnt`] may return different values.
    pub fn insn_cnt(&self) -> usize {
        unsafe { libbpf_sys::bpf_program__insn_cnt(self.ptr.as_ptr()) as usize }
    }

    /// Gives read-only access to BPF program's underlying BPF instructions.
    ///
    /// Keep in mind, libbpf can modify and append/delete BPF program's
    /// instructions as it processes BPF object file and prepares everything for
    /// uploading into the kernel. So [`OpenProgram::insns`] and [`Program::insns`] may return
    /// different sets of instructions. As an example, during BPF object load phase BPF program
    /// instructions will be CO-RE-relocated, BPF subprograms instructions will be appended, ldimm64
    /// instructions will have FDs embedded, etc. So instructions returned before load and after it
    /// might be quite different.
    pub fn insns(&self) -> &[libbpf_sys::bpf_insn] {
        let count = self.insn_cnt();
        let ptr = unsafe { libbpf_sys::bpf_program__insns(self.ptr.as_ptr()) };
        unsafe { slice::from_raw_parts(ptr, count) }
    }
}

impl<'obj> OpenProgramMut<'obj> {
    /// Create a new [`OpenProgram`] from a ptr to a `libbpf_sys::bpf_program`.
    pub fn new_mut(prog: &'obj mut libbpf_sys::bpf_program) -> Self {
        Self {
            ptr: unsafe { NonNull::new_unchecked(prog as *mut _) },
            _phantom: PhantomData,
        }
    }

    /// Set the program type.
    pub fn set_prog_type(&mut self, prog_type: ProgramType) {
        let rc = unsafe { libbpf_sys::bpf_program__set_type(self.ptr.as_ptr(), prog_type as u32) };
        debug_assert!(util::parse_ret(rc).is_ok(), "{rc}");
    }

    /// Set the attachment type of the program.
    pub fn set_attach_type(&mut self, attach_type: ProgramAttachType) {
        let rc = unsafe {
            libbpf_sys::bpf_program__set_expected_attach_type(self.ptr.as_ptr(), attach_type as u32)
        };
        debug_assert!(util::parse_ret(rc).is_ok(), "{rc}");
    }

    /// Bind the program to a particular network device.
    ///
    /// Currently only used for hardware offload and certain XDP features such like HW metadata.
    pub fn set_ifindex(&mut self, idx: u32) {
        unsafe { libbpf_sys::bpf_program__set_ifindex(self.ptr.as_ptr(), idx) }
    }

    /// Set the log level for the bpf program.
    ///
    /// The log level is interpreted by bpf kernel code and interpretation may
    /// change with newer kernel versions. Refer to the kernel source code for
    /// details.
    ///
    /// In general, a value of `0` disables logging while values `> 0` enables
    /// it.
    pub fn set_log_level(&mut self, log_level: u32) {
        let rc = unsafe { libbpf_sys::bpf_program__set_log_level(self.ptr.as_ptr(), log_level) };
        debug_assert!(util::parse_ret(rc).is_ok(), "{rc}");
    }

    /// Set whether a bpf program should be automatically loaded by default
    /// when the bpf object is loaded.
    pub fn set_autoload(&mut self, autoload: bool) {
        let rc = unsafe { libbpf_sys::bpf_program__set_autoload(self.ptr.as_ptr(), autoload) };
        debug_assert!(util::parse_ret(rc).is_ok(), "{rc}");
    }

    #[allow(missing_docs)]
    pub fn set_attach_target(
        &mut self,
        attach_prog_fd: i32,
        attach_func_name: Option<String>,
    ) -> Result<()> {
        let ret = if let Some(name) = attach_func_name {
            // NB: we must hold onto a CString otherwise our pointer dangles
            let name_c = util::str_to_cstring(&name)?;
            unsafe {
                libbpf_sys::bpf_program__set_attach_target(
                    self.ptr.as_ptr(),
                    attach_prog_fd,
                    name_c.as_ptr(),
                )
            }
        } else {
            unsafe {
                libbpf_sys::bpf_program__set_attach_target(
                    self.ptr.as_ptr(),
                    attach_prog_fd,
                    ptr::null(),
                )
            }
        };
        util::parse_ret(ret)
    }

    /// Set flags on the program.
    pub fn set_flags(&mut self, flags: u32) {
        let rc = unsafe { libbpf_sys::bpf_program__set_flags(self.ptr.as_ptr(), flags) };
        debug_assert!(util::parse_ret(rc).is_ok(), "{rc}");
    }
}

impl<'obj> Deref for OpenProgramMut<'obj> {
    type Target = OpenProgram<'obj>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `OpenProgramImpl` is `repr(transparent)` and so
        //         in-memory representation of both types is the same.
        unsafe { transmute::<&OpenProgramMut<'obj>, &OpenProgram<'obj>>(self) }
    }
}

impl<T> AsRawLibbpf for OpenProgramImpl<'_, T> {
    type LibbpfType = libbpf_sys::bpf_program;

    /// Retrieve the underlying [`libbpf_sys::bpf_program`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.ptr
    }
}

/// Type of a [`Program`]. Maps to `enum bpf_prog_type` in kernel uapi.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
// TODO: Document variants.
#[allow(missing_docs)]
pub enum ProgramType {
    Unspec = 0,
    SocketFilter = libbpf_sys::BPF_PROG_TYPE_SOCKET_FILTER,
    Kprobe = libbpf_sys::BPF_PROG_TYPE_KPROBE,
    SchedCls = libbpf_sys::BPF_PROG_TYPE_SCHED_CLS,
    SchedAct = libbpf_sys::BPF_PROG_TYPE_SCHED_ACT,
    Tracepoint = libbpf_sys::BPF_PROG_TYPE_TRACEPOINT,
    Xdp = libbpf_sys::BPF_PROG_TYPE_XDP,
    PerfEvent = libbpf_sys::BPF_PROG_TYPE_PERF_EVENT,
    CgroupSkb = libbpf_sys::BPF_PROG_TYPE_CGROUP_SKB,
    CgroupSock = libbpf_sys::BPF_PROG_TYPE_CGROUP_SOCK,
    LwtIn = libbpf_sys::BPF_PROG_TYPE_LWT_IN,
    LwtOut = libbpf_sys::BPF_PROG_TYPE_LWT_OUT,
    LwtXmit = libbpf_sys::BPF_PROG_TYPE_LWT_XMIT,
    SockOps = libbpf_sys::BPF_PROG_TYPE_SOCK_OPS,
    SkSkb = libbpf_sys::BPF_PROG_TYPE_SK_SKB,
    CgroupDevice = libbpf_sys::BPF_PROG_TYPE_CGROUP_DEVICE,
    SkMsg = libbpf_sys::BPF_PROG_TYPE_SK_MSG,
    RawTracepoint = libbpf_sys::BPF_PROG_TYPE_RAW_TRACEPOINT,
    CgroupSockAddr = libbpf_sys::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    LwtSeg6local = libbpf_sys::BPF_PROG_TYPE_LWT_SEG6LOCAL,
    LircMode2 = libbpf_sys::BPF_PROG_TYPE_LIRC_MODE2,
    SkReuseport = libbpf_sys::BPF_PROG_TYPE_SK_REUSEPORT,
    FlowDissector = libbpf_sys::BPF_PROG_TYPE_FLOW_DISSECTOR,
    CgroupSysctl = libbpf_sys::BPF_PROG_TYPE_CGROUP_SYSCTL,
    RawTracepointWritable = libbpf_sys::BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    CgroupSockopt = libbpf_sys::BPF_PROG_TYPE_CGROUP_SOCKOPT,
    Tracing = libbpf_sys::BPF_PROG_TYPE_TRACING,
    StructOps = libbpf_sys::BPF_PROG_TYPE_STRUCT_OPS,
    Ext = libbpf_sys::BPF_PROG_TYPE_EXT,
    Lsm = libbpf_sys::BPF_PROG_TYPE_LSM,
    SkLookup = libbpf_sys::BPF_PROG_TYPE_SK_LOOKUP,
    Syscall = libbpf_sys::BPF_PROG_TYPE_SYSCALL,
    /// See [`MapType::Unknown`][crate::MapType::Unknown]
    Unknown = u32::MAX,
}

impl ProgramType {
    /// Detects if host kernel supports this BPF program type
    ///
    /// Make sure the process has required set of CAP_* permissions (or runs as
    /// root) when performing feature checking.
    pub fn is_supported(&self) -> Result<bool> {
        let ret = unsafe { libbpf_sys::libbpf_probe_bpf_prog_type(*self as u32, ptr::null()) };
        match ret {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::from_raw_os_error(-ret)),
        }
    }

    /// Detects if host kernel supports the use of a given BPF helper from this BPF program type.
    /// * `helper_id` - BPF helper ID (enum bpf_func_id) to check support for
    ///
    /// Make sure the process has required set of CAP_* permissions (or runs as
    /// root) when performing feature checking.
    pub fn is_helper_supported(&self, helper_id: bpf_func_id) -> Result<bool> {
        let ret =
            unsafe { libbpf_sys::libbpf_probe_bpf_helper(*self as u32, helper_id, ptr::null()) };
        match ret {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::from_raw_os_error(-ret)),
        }
    }
}

impl From<u32> for ProgramType {
    fn from(value: u32) -> Self {
        use ProgramType::*;

        match value {
            x if x == Unspec as u32 => Unspec,
            x if x == SocketFilter as u32 => SocketFilter,
            x if x == Kprobe as u32 => Kprobe,
            x if x == SchedCls as u32 => SchedCls,
            x if x == SchedAct as u32 => SchedAct,
            x if x == Tracepoint as u32 => Tracepoint,
            x if x == Xdp as u32 => Xdp,
            x if x == PerfEvent as u32 => PerfEvent,
            x if x == CgroupSkb as u32 => CgroupSkb,
            x if x == CgroupSock as u32 => CgroupSock,
            x if x == LwtIn as u32 => LwtIn,
            x if x == LwtOut as u32 => LwtOut,
            x if x == LwtXmit as u32 => LwtXmit,
            x if x == SockOps as u32 => SockOps,
            x if x == SkSkb as u32 => SkSkb,
            x if x == CgroupDevice as u32 => CgroupDevice,
            x if x == SkMsg as u32 => SkMsg,
            x if x == RawTracepoint as u32 => RawTracepoint,
            x if x == CgroupSockAddr as u32 => CgroupSockAddr,
            x if x == LwtSeg6local as u32 => LwtSeg6local,
            x if x == LircMode2 as u32 => LircMode2,
            x if x == SkReuseport as u32 => SkReuseport,
            x if x == FlowDissector as u32 => FlowDissector,
            x if x == CgroupSysctl as u32 => CgroupSysctl,
            x if x == RawTracepointWritable as u32 => RawTracepointWritable,
            x if x == CgroupSockopt as u32 => CgroupSockopt,
            x if x == Tracing as u32 => Tracing,
            x if x == StructOps as u32 => StructOps,
            x if x == Ext as u32 => Ext,
            x if x == Lsm as u32 => Lsm,
            x if x == SkLookup as u32 => SkLookup,
            x if x == Syscall as u32 => Syscall,
            _ => Unknown,
        }
    }
}

/// Attach type of a [`Program`]. Maps to `enum bpf_attach_type` in kernel uapi.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, Debug)]
// TODO: Document variants.
#[allow(missing_docs)]
pub enum ProgramAttachType {
    CgroupInetIngress = libbpf_sys::BPF_CGROUP_INET_INGRESS,
    CgroupInetEgress = libbpf_sys::BPF_CGROUP_INET_EGRESS,
    CgroupInetSockCreate = libbpf_sys::BPF_CGROUP_INET_SOCK_CREATE,
    CgroupSockOps = libbpf_sys::BPF_CGROUP_SOCK_OPS,
    SkSkbStreamParser = libbpf_sys::BPF_SK_SKB_STREAM_PARSER,
    SkSkbStreamVerdict = libbpf_sys::BPF_SK_SKB_STREAM_VERDICT,
    CgroupDevice = libbpf_sys::BPF_CGROUP_DEVICE,
    SkMsgVerdict = libbpf_sys::BPF_SK_MSG_VERDICT,
    CgroupInet4Bind = libbpf_sys::BPF_CGROUP_INET4_BIND,
    CgroupInet6Bind = libbpf_sys::BPF_CGROUP_INET6_BIND,
    CgroupInet4Connect = libbpf_sys::BPF_CGROUP_INET4_CONNECT,
    CgroupInet6Connect = libbpf_sys::BPF_CGROUP_INET6_CONNECT,
    CgroupInet4PostBind = libbpf_sys::BPF_CGROUP_INET4_POST_BIND,
    CgroupInet6PostBind = libbpf_sys::BPF_CGROUP_INET6_POST_BIND,
    CgroupUdp4Sendmsg = libbpf_sys::BPF_CGROUP_UDP4_SENDMSG,
    CgroupUdp6Sendmsg = libbpf_sys::BPF_CGROUP_UDP6_SENDMSG,
    LircMode2 = libbpf_sys::BPF_LIRC_MODE2,
    FlowDissector = libbpf_sys::BPF_FLOW_DISSECTOR,
    CgroupSysctl = libbpf_sys::BPF_CGROUP_SYSCTL,
    CgroupUdp4Recvmsg = libbpf_sys::BPF_CGROUP_UDP4_RECVMSG,
    CgroupUdp6Recvmsg = libbpf_sys::BPF_CGROUP_UDP6_RECVMSG,
    CgroupGetsockopt = libbpf_sys::BPF_CGROUP_GETSOCKOPT,
    CgroupSetsockopt = libbpf_sys::BPF_CGROUP_SETSOCKOPT,
    TraceRawTp = libbpf_sys::BPF_TRACE_RAW_TP,
    TraceFentry = libbpf_sys::BPF_TRACE_FENTRY,
    TraceFexit = libbpf_sys::BPF_TRACE_FEXIT,
    ModifyReturn = libbpf_sys::BPF_MODIFY_RETURN,
    LsmMac = libbpf_sys::BPF_LSM_MAC,
    TraceIter = libbpf_sys::BPF_TRACE_ITER,
    CgroupInet4Getpeername = libbpf_sys::BPF_CGROUP_INET4_GETPEERNAME,
    CgroupInet6Getpeername = libbpf_sys::BPF_CGROUP_INET6_GETPEERNAME,
    CgroupInet4Getsockname = libbpf_sys::BPF_CGROUP_INET4_GETSOCKNAME,
    CgroupInet6Getsockname = libbpf_sys::BPF_CGROUP_INET6_GETSOCKNAME,
    XdpDevmap = libbpf_sys::BPF_XDP_DEVMAP,
    CgroupInetSockRelease = libbpf_sys::BPF_CGROUP_INET_SOCK_RELEASE,
    XdpCpumap = libbpf_sys::BPF_XDP_CPUMAP,
    SkLookup = libbpf_sys::BPF_SK_LOOKUP,
    Xdp = libbpf_sys::BPF_XDP,
    SkSkbVerdict = libbpf_sys::BPF_SK_SKB_VERDICT,
    SkReuseportSelect = libbpf_sys::BPF_SK_REUSEPORT_SELECT,
    SkReuseportSelectOrMigrate = libbpf_sys::BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
    PerfEvent = libbpf_sys::BPF_PERF_EVENT,
    /// See [`MapType::Unknown`][crate::MapType::Unknown]
    Unknown = u32::MAX,
}

impl From<u32> for ProgramAttachType {
    fn from(value: u32) -> Self {
        use ProgramAttachType::*;

        match value {
            x if x == CgroupInetIngress as u32 => CgroupInetIngress,
            x if x == CgroupInetEgress as u32 => CgroupInetEgress,
            x if x == CgroupInetSockCreate as u32 => CgroupInetSockCreate,
            x if x == CgroupSockOps as u32 => CgroupSockOps,
            x if x == SkSkbStreamParser as u32 => SkSkbStreamParser,
            x if x == SkSkbStreamVerdict as u32 => SkSkbStreamVerdict,
            x if x == CgroupDevice as u32 => CgroupDevice,
            x if x == SkMsgVerdict as u32 => SkMsgVerdict,
            x if x == CgroupInet4Bind as u32 => CgroupInet4Bind,
            x if x == CgroupInet6Bind as u32 => CgroupInet6Bind,
            x if x == CgroupInet4Connect as u32 => CgroupInet4Connect,
            x if x == CgroupInet6Connect as u32 => CgroupInet6Connect,
            x if x == CgroupInet4PostBind as u32 => CgroupInet4PostBind,
            x if x == CgroupInet6PostBind as u32 => CgroupInet6PostBind,
            x if x == CgroupUdp4Sendmsg as u32 => CgroupUdp4Sendmsg,
            x if x == CgroupUdp6Sendmsg as u32 => CgroupUdp6Sendmsg,
            x if x == LircMode2 as u32 => LircMode2,
            x if x == FlowDissector as u32 => FlowDissector,
            x if x == CgroupSysctl as u32 => CgroupSysctl,
            x if x == CgroupUdp4Recvmsg as u32 => CgroupUdp4Recvmsg,
            x if x == CgroupUdp6Recvmsg as u32 => CgroupUdp6Recvmsg,
            x if x == CgroupGetsockopt as u32 => CgroupGetsockopt,
            x if x == CgroupSetsockopt as u32 => CgroupSetsockopt,
            x if x == TraceRawTp as u32 => TraceRawTp,
            x if x == TraceFentry as u32 => TraceFentry,
            x if x == TraceFexit as u32 => TraceFexit,
            x if x == ModifyReturn as u32 => ModifyReturn,
            x if x == LsmMac as u32 => LsmMac,
            x if x == TraceIter as u32 => TraceIter,
            x if x == CgroupInet4Getpeername as u32 => CgroupInet4Getpeername,
            x if x == CgroupInet6Getpeername as u32 => CgroupInet6Getpeername,
            x if x == CgroupInet4Getsockname as u32 => CgroupInet4Getsockname,
            x if x == CgroupInet6Getsockname as u32 => CgroupInet6Getsockname,
            x if x == XdpDevmap as u32 => XdpDevmap,
            x if x == CgroupInetSockRelease as u32 => CgroupInetSockRelease,
            x if x == XdpCpumap as u32 => XdpCpumap,
            x if x == SkLookup as u32 => SkLookup,
            x if x == Xdp as u32 => Xdp,
            x if x == SkSkbVerdict as u32 => SkSkbVerdict,
            x if x == SkReuseportSelect as u32 => SkReuseportSelect,
            x if x == SkReuseportSelectOrMigrate as u32 => SkReuseportSelectOrMigrate,
            x if x == PerfEvent as u32 => PerfEvent,
            _ => Unknown,
        }
    }
}

/// The input a program accepts.
///
/// This type is mostly used in conjunction with the [`Program::test_run`]
/// facility.
#[derive(Debug, Default)]
pub struct Input<'dat> {
    /// The input context to provide.
    ///
    /// The input is mutable because the kernel may modify it.
    pub context_in: Option<&'dat mut [u8]>,
    /// The output context buffer provided to the program.
    pub context_out: Option<&'dat mut [u8]>,
    /// Additional data to provide to the program.
    pub data_in: Option<&'dat [u8]>,
    /// The output data buffer provided to the program.
    pub data_out: Option<&'dat mut [u8]>,
    /// The 'cpu' value passed to the kernel.
    pub cpu: u32,
    /// The 'flags' value passed to the kernel.
    pub flags: u32,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

/// The output a program produces.
///
/// This type is mostly used in conjunction with the [`Program::test_run`]
/// facility.
#[derive(Debug)]
pub struct Output<'dat> {
    /// The value returned by the program.
    pub return_value: u32,
    /// The output context filled by the program/kernel.
    pub context: Option<&'dat mut [u8]>,
    /// Output data filled by the program.
    pub data: Option<&'dat mut [u8]>,
    /// The struct is non-exhaustive and open to extension.
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

/// An immutable loaded BPF program.
pub type Program<'obj> = ProgramImpl<'obj>;
/// A mutable loaded BPF program.
pub type ProgramMut<'obj> = ProgramImpl<'obj, Mut>;


/// Represents a loaded [`Program`].
///
/// This struct is not safe to clone because the underlying libbpf resource cannot currently
/// be protected from data races.
///
/// If you attempt to attach a `Program` with the wrong attach method, the `attach_*`
/// method will fail with the appropriate error.
#[derive(Debug)]
#[repr(transparent)]
pub struct ProgramImpl<'obj, T = ()> {
    pub(crate) ptr: NonNull<libbpf_sys::bpf_program>,
    _phantom: PhantomData<&'obj T>,
}

impl<'obj> Program<'obj> {
    /// Create a [`Program`] from a [`libbpf_sys::bpf_program`]
    pub fn new(prog: &'obj libbpf_sys::bpf_program) -> Self {
        // SAFETY: We inferred the address from a reference, which is always
        //         valid.
        Self {
            ptr: unsafe { NonNull::new_unchecked(prog as *const _ as *mut _) },
            _phantom: PhantomData,
        }
    }

    /// Retrieve the name of this `Program`.
    pub fn name(&self) -> &OsStr {
        let name_ptr = unsafe { libbpf_sys::bpf_program__name(self.ptr.as_ptr()) };
        let name_c_str = unsafe { CStr::from_ptr(name_ptr) };
        // SAFETY: `bpf_program__name` always returns a non-NULL pointer.
        OsStr::from_bytes(name_c_str.to_bytes())
    }

    /// Retrieve the name of the section this `Program` belongs to.
    pub fn section(&self) -> &OsStr {
        // SAFETY: The program is always valid.
        let p = unsafe { libbpf_sys::bpf_program__section_name(self.ptr.as_ptr()) };
        // SAFETY: `bpf_program__section_name` will always return a non-NULL
        //         pointer.
        let section_c_str = unsafe { CStr::from_ptr(p) };
        let section = OsStr::from_bytes(section_c_str.to_bytes());
        section
    }

    /// Retrieve the type of the program.
    pub fn prog_type(&self) -> ProgramType {
        ProgramType::from(unsafe { libbpf_sys::bpf_program__type(self.ptr.as_ptr()) })
    }

    #[deprecated = "renamed to Program::fd_from_id"]
    #[allow(missing_docs)]
    #[inline]
    pub fn get_fd_by_id(id: u32) -> Result<OwnedFd> {
        Self::fd_from_id(id)
    }

    /// Returns program file descriptor given a program ID.
    pub fn fd_from_id(id: u32) -> Result<OwnedFd> {
        let ret = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(id) };
        let fd = util::parse_ret_i32(ret)?;
        // SAFETY
        // A file descriptor coming from the bpf_prog_get_fd_by_id function is always suitable for
        // ownership and can be cleaned up with close.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    // TODO: Remove once 0.25 is cut.
    #[deprecated = "renamed to Program::id_from_fd"]
    #[allow(missing_docs)]
    #[inline]
    pub fn get_id_by_fd(fd: BorrowedFd<'_>) -> Result<u32> {
        Self::id_from_fd(fd)
    }

    /// Returns program ID given a file descriptor.
    pub fn id_from_fd(fd: BorrowedFd<'_>) -> Result<u32> {
        let mut prog_info = libbpf_sys::bpf_prog_info::default();
        let prog_info_ptr: *mut libbpf_sys::bpf_prog_info = &mut prog_info;
        let mut len = size_of::<libbpf_sys::bpf_prog_info>() as u32;
        let ret = unsafe {
            libbpf_sys::bpf_obj_get_info_by_fd(
                fd.as_raw_fd(),
                prog_info_ptr as *mut c_void,
                &mut len,
            )
        };
        util::parse_ret(ret)?;
        Ok(prog_info.id)
    }

    /// Returns fd of a previously pinned program
    ///
    /// Returns error, if the pinned path doesn't represent an eBPF program.
    pub fn fd_from_pinned_path<P: AsRef<Path>>(path: P) -> Result<OwnedFd> {
        let path_c = util::path_to_cstring(&path)?;
        let path_ptr = path_c.as_ptr();

        let fd = unsafe { libbpf_sys::bpf_obj_get(path_ptr) };
        let fd = util::parse_ret_i32(fd).with_context(|| {
            format!(
                "failed to retrieve BPF object from pinned path `{}`",
                path.as_ref().display()
            )
        })?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // A pinned path may represent an object of any kind, including map
        // and link. This may cause unexpected behaviour for following functions,
        // like bpf_*_get_info_by_fd(), which allow objects of any type.
        let fd_type = util::object_type_from_fd(fd.as_fd())?;
        match fd_type {
            BpfObjectType::Program => Ok(fd),
            other => Err(Error::with_invalid_data(format!(
                "retrieved BPF fd is not a program fd: {:#?}",
                other
            ))),
        }
    }

    /// Returns flags that have been set for the program.
    pub fn flags(&self) -> u32 {
        unsafe { libbpf_sys::bpf_program__flags(self.ptr.as_ptr()) }
    }

    /// Retrieve the attach type of the program.
    pub fn attach_type(&self) -> ProgramAttachType {
        ProgramAttachType::from(unsafe {
            libbpf_sys::bpf_program__expected_attach_type(self.ptr.as_ptr())
        })
    }

    /// Return `true` if the bpf program is set to autoload, `false` otherwise.
    pub fn autoload(&self) -> bool {
        unsafe { libbpf_sys::bpf_program__autoload(self.ptr.as_ptr()) }
    }

    /// Return the bpf program's log level.
    pub fn log_level(&self) -> u32 {
        unsafe { libbpf_sys::bpf_program__log_level(self.ptr.as_ptr()) }
    }

    /// Returns the number of instructions that form the program.
    ///
    /// Please see note in [`OpenProgram::insn_cnt`].
    pub fn insn_cnt(&self) -> usize {
        unsafe { libbpf_sys::bpf_program__insn_cnt(self.ptr.as_ptr()) as usize }
    }

    /// Gives read-only access to BPF program's underlying BPF instructions.
    ///
    /// Please see note in [`OpenProgram::insns`].
    pub fn insns(&self) -> &[libbpf_sys::bpf_insn] {
        let count = self.insn_cnt();
        let ptr = unsafe { libbpf_sys::bpf_program__insns(self.ptr.as_ptr()) };
        unsafe { slice::from_raw_parts(ptr, count) }
    }
}

impl<'obj> ProgramMut<'obj> {
    /// Create a [`Program`] from a [`libbpf_sys::bpf_program`]
    pub fn new_mut(prog: &'obj mut libbpf_sys::bpf_program) -> Self {
        Self {
            ptr: unsafe { NonNull::new_unchecked(prog as *mut _) },
            _phantom: PhantomData,
        }
    }

    /// [Pin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this program to bpffs.
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_program__pin(self.ptr.as_ptr(), path_ptr) };
        util::parse_ret(ret)
    }

    /// [Unpin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this program from bpffs
    pub fn unpin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_program__unpin(self.ptr.as_ptr(), path_ptr) };
        util::parse_ret(ret)
    }

    /// Auto-attach based on prog section
    pub fn attach(&self) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach(self.ptr.as_ptr()) };
        let ptr = validate_bpf_ret(ptr).context("failed to attach BPF program")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to a
    /// [cgroup](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).
    pub fn attach_cgroup(&self, cgroup_fd: i32) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_cgroup(self.ptr.as_ptr(), cgroup_fd) };
        let ptr = validate_bpf_ret(ptr).context("failed to attach cgroup")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to a [perf event](https://linux.die.net/man/2/perf_event_open).
    pub fn attach_perf_event(&self, pfd: i32) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_perf_event(self.ptr.as_ptr(), pfd) };
        let ptr = validate_bpf_ret(ptr).context("failed to attach perf event")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to a [userspace
    /// probe](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html).
    pub fn attach_uprobe<T: AsRef<Path>>(
        &self,
        retprobe: bool,
        pid: i32,
        binary_path: T,
        func_offset: usize,
    ) -> Result<Link> {
        let path = util::path_to_cstring(binary_path)?;
        let path_ptr = path.as_ptr();
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_uprobe(
                self.ptr.as_ptr(),
                retprobe,
                pid,
                path_ptr,
                func_offset as libbpf_sys::size_t,
            )
        };
        let ptr = validate_bpf_ret(ptr).context("failed to attach uprobe")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to a [userspace
    /// probe](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html),
    /// providing additional options.
    pub fn attach_uprobe_with_opts(
        &self,
        pid: i32,
        binary_path: impl AsRef<Path>,
        func_offset: usize,
        opts: UprobeOpts,
    ) -> Result<Link> {
        let path = util::path_to_cstring(binary_path)?;
        let path_ptr = path.as_ptr();
        let UprobeOpts {
            ref_ctr_offset,
            cookie,
            retprobe,
            func_name,
            _non_exhaustive,
        } = opts;

        let func_name = util::str_to_cstring(&func_name)?;
        let opts = libbpf_sys::bpf_uprobe_opts {
            sz: size_of::<libbpf_sys::bpf_uprobe_opts>() as _,
            ref_ctr_offset: ref_ctr_offset as libbpf_sys::size_t,
            bpf_cookie: cookie,
            retprobe,
            func_name: func_name.as_ptr(),
            ..Default::default()
        };

        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_uprobe_opts(
                self.ptr.as_ptr(),
                pid,
                path_ptr,
                func_offset as libbpf_sys::size_t,
                &opts as *const _,
            )
        };
        let ptr = validate_bpf_ret(ptr).context("failed to attach uprobe")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to a [kernel
    /// probe](https://www.kernel.org/doc/html/latest/trace/kprobetrace.html).
    pub fn attach_kprobe<T: AsRef<str>>(&self, retprobe: bool, func_name: T) -> Result<Link> {
        let func_name = util::str_to_cstring(func_name.as_ref())?;
        let func_name_ptr = func_name.as_ptr();
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_kprobe(self.ptr.as_ptr(), retprobe, func_name_ptr)
        };
        let ptr = validate_bpf_ret(ptr).context("failed to attach kprobe")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to the specified syscall
    pub fn attach_ksyscall<T: AsRef<str>>(&self, retprobe: bool, syscall_name: T) -> Result<Link> {
        let opts = libbpf_sys::bpf_ksyscall_opts {
            sz: size_of::<libbpf_sys::bpf_ksyscall_opts>() as _,
            retprobe,
            ..Default::default()
        };

        let syscall_name = util::str_to_cstring(syscall_name.as_ref())?;
        let syscall_name_ptr = syscall_name.as_ptr();
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_ksyscall(self.ptr.as_ptr(), syscall_name_ptr, &opts)
        };
        let ptr = validate_bpf_ret(ptr).context("failed to attach ksyscall")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    fn attach_tracepoint_impl(
        &self,
        tp_category: &str,
        tp_name: &str,
        tp_opts: Option<TracepointOpts>,
    ) -> Result<Link> {
        let tp_category = util::str_to_cstring(tp_category)?;
        let tp_category_ptr = tp_category.as_ptr();
        let tp_name = util::str_to_cstring(tp_name)?;
        let tp_name_ptr = tp_name.as_ptr();

        let ptr = if let Some(tp_opts) = tp_opts {
            let tp_opts = libbpf_sys::bpf_tracepoint_opts::from(tp_opts);
            unsafe {
                libbpf_sys::bpf_program__attach_tracepoint_opts(
                    self.ptr.as_ptr(),
                    tp_category_ptr,
                    tp_name_ptr,
                    &tp_opts as *const _,
                )
            }
        } else {
            unsafe {
                libbpf_sys::bpf_program__attach_tracepoint(
                    self.ptr.as_ptr(),
                    tp_category_ptr,
                    tp_name_ptr,
                )
            }
        };

        let ptr = validate_bpf_ret(ptr).context("failed to attach tracepoint")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to a [kernel
    /// tracepoint](https://www.kernel.org/doc/html/latest/trace/tracepoints.html).
    pub fn attach_tracepoint(
        &self,
        tp_category: impl AsRef<str>,
        tp_name: impl AsRef<str>,
    ) -> Result<Link> {
        self.attach_tracepoint_impl(tp_category.as_ref(), tp_name.as_ref(), None)
    }

    /// Attach this program to a [kernel
    /// tracepoint](https://www.kernel.org/doc/html/latest/trace/tracepoints.html),
    /// providing additional options.
    pub fn attach_tracepoint_with_opts(
        &self,
        tp_category: impl AsRef<str>,
        tp_name: impl AsRef<str>,
        tp_opts: TracepointOpts,
    ) -> Result<Link> {
        self.attach_tracepoint_impl(tp_category.as_ref(), tp_name.as_ref(), Some(tp_opts))
    }

    /// Attach this program to a [raw kernel
    /// tracepoint](https://lwn.net/Articles/748352/).
    pub fn attach_raw_tracepoint<T: AsRef<str>>(&self, tp_name: T) -> Result<Link> {
        let tp_name = util::str_to_cstring(tp_name.as_ref())?;
        let tp_name_ptr = tp_name.as_ptr();
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_raw_tracepoint(self.ptr.as_ptr(), tp_name_ptr)
        };
        let ptr = validate_bpf_ret(ptr).context("failed to attach raw tracepoint")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach to an [LSM](https://en.wikipedia.org/wiki/Linux_Security_Modules) hook
    pub fn attach_lsm(&self) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_lsm(self.ptr.as_ptr()) };
        let ptr = validate_bpf_ret(ptr).context("failed to attach LSM")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach to a [fentry/fexit kernel probe](https://lwn.net/Articles/801479/)
    pub fn attach_trace(&self) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_trace(self.ptr.as_ptr()) };
        let ptr = validate_bpf_ret(ptr).context("failed to attach fentry/fexit kernel probe")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach a verdict/parser to a [sockmap/sockhash](https://lwn.net/Articles/731133/)
    pub fn attach_sockmap(&self, map_fd: i32) -> Result<()> {
        let err = unsafe {
            libbpf_sys::bpf_prog_attach(
                self.as_fd().as_raw_fd(),
                map_fd,
                self.attach_type() as u32,
                0,
            )
        };
        util::parse_ret(err)
    }

    /// Attach this program to [XDP](https://lwn.net/Articles/825998/)
    pub fn attach_xdp(&self, ifindex: i32) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_xdp(self.ptr.as_ptr(), ifindex) };
        let ptr = validate_bpf_ret(ptr).context("failed to attach XDP program")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to [netns-based programs](https://lwn.net/Articles/819618/)
    pub fn attach_netns(&self, netns_fd: i32) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_netns(self.ptr.as_ptr(), netns_fd) };
        let ptr = validate_bpf_ret(ptr).context("failed to attach network namespace program")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to [netfilter programs](https://lwn.net/Articles/925082/)
    pub fn attach_netfilter_with_opts(
        &self,
        netfilter_opt: netfilter::NetfilterOpts,
    ) -> Result<Link> {
        let netfilter_opts = libbpf_sys::bpf_netfilter_opts::from(netfilter_opt);

        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_netfilter(
                self.ptr.as_ptr(),
                &netfilter_opts as *const _,
            )
        };

        let ptr = validate_bpf_ret(ptr).context("failed to attach netfilter program")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    fn attach_usdt_impl(
        &self,
        pid: i32,
        binary_path: &Path,
        usdt_provider: &str,
        usdt_name: &str,
        usdt_opts: Option<UsdtOpts>,
    ) -> Result<Link> {
        let path = util::path_to_cstring(binary_path)?;
        let path_ptr = path.as_ptr();
        let usdt_provider = util::str_to_cstring(usdt_provider)?;
        let usdt_provider_ptr = usdt_provider.as_ptr();
        let usdt_name = util::str_to_cstring(usdt_name)?;
        let usdt_name_ptr = usdt_name.as_ptr();
        let usdt_opts = usdt_opts.map(libbpf_sys::bpf_usdt_opts::from);
        let usdt_opts_ptr = usdt_opts
            .as_ref()
            .map(|opts| opts as *const _)
            .unwrap_or_else(ptr::null);

        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_usdt(
                self.ptr.as_ptr(),
                pid,
                path_ptr,
                usdt_provider_ptr,
                usdt_name_ptr,
                usdt_opts_ptr,
            )
        };
        let ptr = validate_bpf_ret(ptr).context("failed to attach USDT")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Attach this program to a [USDT](https://lwn.net/Articles/753601/) probe
    /// point. The entry point of the program must be defined with
    /// `SEC("usdt")`.
    pub fn attach_usdt(
        &self,
        pid: i32,
        binary_path: impl AsRef<Path>,
        usdt_provider: impl AsRef<str>,
        usdt_name: impl AsRef<str>,
    ) -> Result<Link> {
        self.attach_usdt_impl(
            pid,
            binary_path.as_ref(),
            usdt_provider.as_ref(),
            usdt_name.as_ref(),
            None,
        )
    }

    /// Attach this program to a [USDT](https://lwn.net/Articles/753601/) probe
    /// point, providing additional options. The entry point of the program must
    /// be defined with `SEC("usdt")`.
    pub fn attach_usdt_with_opts(
        &self,
        pid: i32,
        binary_path: impl AsRef<Path>,
        usdt_provider: impl AsRef<str>,
        usdt_name: impl AsRef<str>,
        usdt_opts: UsdtOpts,
    ) -> Result<Link> {
        self.attach_usdt_impl(
            pid,
            binary_path.as_ref(),
            usdt_provider.as_ref(),
            usdt_name.as_ref(),
            Some(usdt_opts),
        )
    }

    /// Attach this program to a
    /// [BPF Iterator](https://www.kernel.org/doc/html/latest/bpf/bpf_iterators.html).
    /// The entry point of the program must be defined with `SEC("iter")` or `SEC("iter.s")`.
    pub fn attach_iter(&self, map_fd: BorrowedFd<'_>) -> Result<Link> {
        let mut linkinfo = libbpf_sys::bpf_iter_link_info::default();
        linkinfo.map.map_fd = map_fd.as_raw_fd() as _;
        let attach_opt = libbpf_sys::bpf_iter_attach_opts {
            link_info: &mut linkinfo as *mut libbpf_sys::bpf_iter_link_info,
            link_info_len: size_of::<libbpf_sys::bpf_iter_link_info>() as _,
            sz: size_of::<libbpf_sys::bpf_iter_attach_opts>() as _,
            ..Default::default()
        };
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_iter(
                self.ptr.as_ptr(),
                &attach_opt as *const libbpf_sys::bpf_iter_attach_opts,
            )
        };

        let ptr = validate_bpf_ret(ptr).context("failed to attach iterator")?;
        // SAFETY: the pointer came from libbpf and has been checked for errors.
        let link = unsafe { Link::new(ptr) };
        Ok(link)
    }

    /// Test run the program with the given input data.
    ///
    /// This function uses the
    /// [BPF_PROG_RUN](https://www.kernel.org/doc/html/latest/bpf/bpf_prog_run.html)
    /// facility.
    pub fn test_run<'dat>(&self, input: Input<'dat>) -> Result<Output<'dat>> {
        unsafe fn slice_from_array<'t, T>(items: *mut T, num_items: usize) -> Option<&'t mut [T]> {
            if items.is_null() {
                None
            } else {
                Some(unsafe { slice::from_raw_parts_mut(items, num_items) })
            }
        }

        let Input {
            context_in,
            mut context_out,
            data_in,
            mut data_out,
            cpu,
            flags,
            _non_exhaustive: (),
        } = input;

        let mut opts = unsafe { mem::zeroed::<libbpf_sys::bpf_test_run_opts>() };
        opts.sz = size_of_val(&opts) as _;
        opts.ctx_in = context_in
            .as_ref()
            .map(|data| data.as_ptr().cast())
            .unwrap_or_else(ptr::null);
        opts.ctx_size_in = context_in.map(|data| data.len() as _).unwrap_or(0);
        opts.ctx_out = context_out
            .as_mut()
            .map(|data| data.as_mut_ptr().cast())
            .unwrap_or_else(ptr::null_mut);
        opts.ctx_size_out = context_out.map(|data| data.len() as _).unwrap_or(0);
        opts.data_in = data_in
            .map(|data| data.as_ptr().cast())
            .unwrap_or_else(ptr::null);
        opts.data_size_in = data_in.map(|data| data.len() as _).unwrap_or(0);
        opts.data_out = data_out
            .as_mut()
            .map(|data| data.as_mut_ptr().cast())
            .unwrap_or_else(ptr::null_mut);
        opts.data_size_out = data_out.map(|data| data.len() as _).unwrap_or(0);
        opts.cpu = cpu;
        opts.flags = flags;

        let rc = unsafe { libbpf_sys::bpf_prog_test_run_opts(self.as_fd().as_raw_fd(), &mut opts) };
        let () = util::parse_ret(rc)?;
        let output = Output {
            return_value: opts.retval,
            context: unsafe { slice_from_array(opts.ctx_out.cast(), opts.ctx_size_out as _) },
            data: unsafe { slice_from_array(opts.data_out.cast(), opts.data_size_out as _) },
            _non_exhaustive: (),
        };
        Ok(output)
    }
}

impl<'obj> Deref for ProgramMut<'obj> {
    type Target = Program<'obj>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `ProgramImpl` is `repr(transparent)` and so in-memory
        //         representation of both types is the same.
        unsafe { transmute::<&ProgramMut<'obj>, &Program<'obj>>(self) }
    }
}

impl<T> AsFd for ProgramImpl<'_, T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let fd = unsafe { libbpf_sys::bpf_program__fd(self.ptr.as_ptr()) };
        unsafe { BorrowedFd::borrow_raw(fd) }
    }
}

impl<T> AsRawLibbpf for ProgramImpl<'_, T> {
    type LibbpfType = libbpf_sys::bpf_program;

    /// Retrieve the underlying [`libbpf_sys::bpf_program`].
    fn as_libbpf_object(&self) -> NonNull<Self::LibbpfType> {
        self.ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::discriminant;

    #[test]
    fn program_type() {
        use ProgramType::*;

        for t in [
            Unspec,
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
            SkLookup,
            Syscall,
            Unknown,
        ] {
            // check if discriminants match after a roundtrip conversion
            assert_eq!(discriminant(&t), discriminant(&ProgramType::from(t as u32)));
        }
    }

    #[test]
    fn program_attach_type() {
        use ProgramAttachType::*;

        for t in [
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
            TraceIter,
            CgroupInet4Getpeername,
            CgroupInet6Getpeername,
            CgroupInet4Getsockname,
            CgroupInet6Getsockname,
            XdpDevmap,
            CgroupInetSockRelease,
            XdpCpumap,
            SkLookup,
            Xdp,
            SkSkbVerdict,
            SkReuseportSelect,
            SkReuseportSelectOrMigrate,
            PerfEvent,
            Unknown,
        ] {
            // check if discriminants match after a roundtrip conversion
            assert_eq!(
                discriminant(&t),
                discriminant(&ProgramAttachType::from(t as u32))
            );
        }
    }
}
