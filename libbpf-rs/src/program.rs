use std::convert::TryFrom;
use std::path::Path;
use std::ptr;

use num_enum::TryFromPrimitive;
use strum_macros::Display;

use crate::*;

/// Represents a parsed but not yet loaded BPF program.
///
/// This object exposes operations that need to happen before the program is loaded.
#[allow(missing_debug_implementations)]
pub struct OpenProgram {
    ptr: *mut libbpf_sys::bpf_program,
    section: String,
}

impl OpenProgram {
    pub(crate) fn new(ptr: *mut libbpf_sys::bpf_program, section: String) -> Self {
        Self { ptr, section }
    }

    pub fn set_prog_type(&mut self, prog_type: ProgramType) {
        unsafe {
            libbpf_sys::bpf_program__set_type(self.ptr, prog_type as u32);
        }
    }

    pub fn set_attach_type(&mut self, attach_type: ProgramAttachType) {
        unsafe {
            libbpf_sys::bpf_program__set_expected_attach_type(self.ptr, attach_type as u32);
        }
    }

    pub fn set_ifindex(&mut self, idx: u32) {
        unsafe {
            libbpf_sys::bpf_program__set_ifindex(self.ptr, idx);
        }
    }

    /// Name of the section this `Program` belongs to.
    pub fn section(&self) -> &str {
        &self.section
    }

    pub fn set_autoload(&mut self, autoload: bool) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_program__set_autoload(self.ptr, autoload) };
        util::parse_ret(ret)
    }

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
                    self.ptr,
                    attach_prog_fd,
                    name_c.as_ptr(),
                )
            }
        } else {
            unsafe {
                libbpf_sys::bpf_program__set_attach_target(self.ptr, attach_prog_fd, ptr::null())
            }
        };
        util::parse_ret(ret)
    }

    pub fn set_flags(&self, flags: u32) -> Result<()> {
        let ret = unsafe { libbpf_sys::bpf_program__set_flags(self.ptr, flags) };
        util::parse_ret(ret)
    }

    /// Returns the number of instructions that form the program.
    ///
    /// Note: Keep in mind, libbpf can modify the program's instructions
    /// and consequently its instruction count, as it processes the BPF object file.
    /// So [`OpenProgram::insn_cnt`] and [`Program::insn_cnt`] may return different values.
    ///
    pub fn insn_cnt(&self) -> usize {
        unsafe { libbpf_sys::bpf_program__insn_cnt(self.ptr) as usize }
    }
}

/// Type of a [`Program`]. Maps to `enum bpf_prog_type` in kernel uapi.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, TryFromPrimitive, Display, Debug)]
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
    SkLookup,
    Syscall,
    /// See [`MapType::Unknown`]
    Unknown = u32::MAX,
}

/// Attach type of a [`Program`]. Maps to `enum bpf_attach_type` in kernel uapi.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, TryFromPrimitive, Display, Debug)]
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
#[allow(missing_debug_implementations)]
pub struct Program {
    pub(crate) ptr: *mut libbpf_sys::bpf_program,
    name: String,
    section: String,
}

impl Program {
    pub(crate) fn new(ptr: *mut libbpf_sys::bpf_program, name: String, section: String) -> Self {
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
        match ProgramType::try_from(unsafe { libbpf_sys::bpf_program__type(self.ptr) }) {
            Ok(ty) => ty,
            Err(_) => ProgramType::Unknown,
        }
    }

    /// Returns a file descriptor to the underlying program.
    pub fn fd(&self) -> i32 {
        unsafe { libbpf_sys::bpf_program__fd(self.ptr) }
    }

    /// Returns flags that have been set for the program.
    pub fn flags(&self) -> u32 {
        unsafe { libbpf_sys::bpf_program__flags(self.ptr) }
    }

    pub fn attach_type(&self) -> ProgramAttachType {
        match ProgramAttachType::try_from(unsafe {
            libbpf_sys::bpf_program__expected_attach_type(self.ptr)
        }) {
            Ok(ty) => ty,
            Err(_) => ProgramAttachType::Unknown,
        }
    }

    /// [Pin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this program to bpffs.
    pub fn pin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_program__pin(self.ptr, path_ptr) };
        util::parse_ret(ret)
    }

    /// [Unpin](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs)
    /// this program from bpffs
    pub fn unpin<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path_c = util::path_to_cstring(path)?;
        let path_ptr = path_c.as_ptr();

        let ret = unsafe { libbpf_sys::bpf_program__unpin(self.ptr, path_ptr) };
        util::parse_ret(ret)
    }

    /// Auto-attach based on prog section
    pub fn attach(&mut self) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach(self.ptr) };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
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
    pub fn attach_uprobe<T: AsRef<Path>>(
        &mut self,
        retprobe: bool,
        pid: i32,
        binary_path: T,
        func_offset: usize,
    ) -> Result<Link> {
        let path = util::path_to_cstring(binary_path.as_ref())?;
        let path_ptr = path.as_ptr();
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_uprobe(
                self.ptr,
                retprobe,
                pid,
                path_ptr,
                func_offset as libbpf_sys::size_t,
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
    /// probe](https://www.kernel.org/doc/html/latest/trace/kprobetrace.html).
    pub fn attach_kprobe<T: AsRef<str>>(&mut self, retprobe: bool, func_name: T) -> Result<Link> {
        let func_name = util::str_to_cstring(func_name.as_ref())?;
        let func_name_ptr = func_name.as_ptr();
        let ptr =
            unsafe { libbpf_sys::bpf_program__attach_kprobe(self.ptr, retprobe, func_name_ptr) };
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
        let tp_category = util::str_to_cstring(tp_category.as_ref())?;
        let tp_category_ptr = tp_category.as_ptr();
        let tp_name = util::str_to_cstring(tp_name.as_ref())?;
        let tp_name_ptr = tp_name.as_ptr();
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_tracepoint(self.ptr, tp_category_ptr, tp_name_ptr)
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
        let tp_name = util::str_to_cstring(tp_name.as_ref())?;
        let tp_name_ptr = tp_name.as_ptr();
        let ptr = unsafe { libbpf_sys::bpf_program__attach_raw_tracepoint(self.ptr, tp_name_ptr) };
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
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach a verdict/parser to a [sockmap/sockhash](https://lwn.net/Articles/731133/)
    pub fn attach_sockmap(&self, map_fd: i32) -> Result<()> {
        let err =
            unsafe { libbpf_sys::bpf_prog_attach(self.fd(), map_fd, self.attach_type() as u32, 0) };
        util::parse_ret(err)
    }

    /// Attach this program to [XDP](https://lwn.net/Articles/825998/)
    pub fn attach_xdp(&mut self, ifindex: i32) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_xdp(self.ptr, ifindex) };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach this program to [netns-based programs](https://lwn.net/Articles/819618/)
    pub fn attach_netns(&mut self, netns_fd: i32) -> Result<Link> {
        let ptr = unsafe { libbpf_sys::bpf_program__attach_netns(self.ptr, netns_fd) };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Attach this program to a [USDT](https://lwn.net/Articles/753601/) probe
    /// point. The entry point of the program must be defined with
    /// `SEC("usdt")`.
    pub fn attach_usdt<S: AsRef<str>, T: AsRef<Path>>(
        &mut self,
        pid: i32,
        binary_path: T,
        usdt_provider: S,
        usdt_name: S,
    ) -> Result<Link> {
        let path = util::path_to_cstring(binary_path.as_ref())?;
        let path_ptr = path.as_ptr();
        let usdt_provider = util::str_to_cstring(usdt_provider.as_ref())?;
        let usdt_provider_ptr = usdt_provider.as_ptr();
        let usdt_name = util::str_to_cstring(usdt_name.as_ref())?;
        let usdt_name_ptr = usdt_name.as_ptr();
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_usdt(
                self.ptr,
                pid,
                path_ptr,
                usdt_provider_ptr,
                usdt_name_ptr,
                ptr::null(),
            )
        };
        let err = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(Link::new(ptr))
        }
    }

    /// Returns the number of instructions that form the program.
    ///
    /// Please see note in [`OpenProgram::insn_cnt`].
    ///
    pub fn insn_cnt(&self) -> usize {
        unsafe { libbpf_sys::bpf_program__insn_cnt(self.ptr) as usize }
    }
}
