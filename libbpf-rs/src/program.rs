use std::convert::TryFrom;
use std::os::raw::c_char;

use nix::errno;
use num_enum::TryFromPrimitive;
use strum_macros::Display;

use crate::*;

/// Represents a parsed but not yet loaded BPF program.
///
/// This object exposes operations that need to happen before the program is loaded.
pub struct OpenProgram {
    ptr: *mut libbpf_sys::bpf_program,
}

impl OpenProgram {
    pub(crate) fn new(ptr: *mut libbpf_sys::bpf_program) -> Self {
        OpenProgram { ptr }
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
}

/// Type of a [`Program`]. Maps to `enum bpf_prog_type` in kernel uapi.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, TryFromPrimitive, Display)]
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
#[derive(Clone, TryFromPrimitive, Display)]
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
