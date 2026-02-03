use std::mem::size_of;


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
        Self {
            sz: size_of::<Self>() as _,
            bpf_cookie: cookie,
            // bpf_tracepoint_opts might have padding fields on some platform
            ..Default::default()
        }
    }
}

/// Options to optionally be provided when attaching to a raw tracepoint.
#[derive(Clone, Debug, Default)]
pub struct RawTracepointOpts {
    /// Custom user-provided value accessible through `bpf_get_attach_cookie`.
    pub cookie: u64,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl From<RawTracepointOpts> for libbpf_sys::bpf_raw_tracepoint_opts {
    fn from(opts: RawTracepointOpts) -> Self {
        let RawTracepointOpts {
            cookie,
            _non_exhaustive,
        } = opts;

        #[allow(clippy::needless_update)]
        Self {
            sz: size_of::<Self>() as _,
            cookie,
            // bpf_raw_tracepoint_opts might have padding fields on some platform
            ..Default::default()
        }
    }
}


/// Represents categories of Linux kernel tracepoints.
///
/// This enum provides a list of tracepoint categories that can be used with
/// BPF programs to attach to various kernel events.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum TracepointCategory {
    /// 9P protocol events.
    P9,
    /// Andrew File System events.
    Afs,
    /// Alarm timer events.
    Alarmtimer,
    /// ALSA System-on-Chip audio events.
    Asoc,
    /// Access Vector Cache events.
    Avc,
    /// Bcache events.
    Bcache,
    /// Block layer events.
    Block,
    /// BPF test run events.
    BpfTestRun,
    /// BPF trace events.
    BpfTrace,
    /// Bridge events.
    Bridge,
    /// Btrfs filesystem events.
    Btrfs,
    /// Cachefiles events.
    Cachefiles,
    /// Control groups events.
    Cgroup,
    /// Clock subsystem events.
    Clk,
    /// CMA events.
    Cma,
    /// Memory compaction events.
    Compaction,
    /// Context tracking events.
    ContextTracking,
    /// CPU hotplug events.
    Cpuhp,
    /// CSD events.
    Csd,
    /// Damon events.
    Damon,
    /// Devfreq events.
    Devfreq,
    /// Device link events.
    Devlink,
    /// Distributed lock manager events.
    Dlm,
    /// DMA events.
    Dma,
    /// DMA fence events.
    DmaFence,
    /// EROFS filesystem events.
    Erofs,
    /// Error reporting events.
    ErrorReport,
    /// Ext4 filesystem events.
    Ext4,
    /// F2FS filesystem events.
    F2Fs,
    /// FIB events.
    Fib,
    /// IPv6 FIB events.
    Fib6,
    /// File lock events.
    Filelock,
    /// File mapping events.
    Filemap,
    /// FS-Cache events.
    Fscache,
    /// DAX filesystem events.
    FsDax,
    /// FSI events.
    Fsi,
    /// FSI master Aspeed events.
    FsiMasterAspeed,
    /// FSI master AST-CF events.
    FsiMasterAstCf,
    /// FSI master GPIO events.
    FsiMasterGpio,
    /// FSI master I2CR events.
    FsiMasterI2Cr,
    /// GPIO events.
    Gpio,
    /// GPU memory events.
    GpuMem,
    /// Habana Labs events.
    Habanalabs,
    /// Handshake events.
    Handshake,
    /// Host1X events.
    Host1X,
    /// Huge memory events.
    HugeMemory,
    /// HugeTLB filesystem events.
    Hugetlbfs,
    /// Hardware monitoring events.
    Hwmon,
    /// Hardware pressure events.
    HwPressure,
    /// I2C events.
    I2C,
    /// I2C slave events.
    I2CSlave,
    /// InfiniBand MAD events.
    IbMad,
    /// InfiniBand UMAD events.
    IbUmad,
    /// ICMP events.
    Icmp,
    /// Initialization call events.
    Initcall,
    /// Intel IFS events.
    IntelIfs,
    /// Intel ISH events.
    IntelIsh,
    /// Intel SST events.
    IntelSst,
    /// IO cost events.
    Iocost,
    /// IOMMU events.
    Iommu,
    /// IO uring events.
    IoUring,
    /// Inter-processor interrupt events.
    Ipi,
    /// IRQ events.
    Irq,
    /// IRQ matrix events.
    IrqMatrix,
    /// iSCSI events.
    Iscsi,
    /// JBD2 events.
    Jbd2,
    /// Kernel memory events.
    Kmem,
    /// Kernel same-page merging events.
    Ksm,
    /// KVM events.
    Kvm,
    /// Kyber events.
    Kyber,
    /// Libata events.
    Libata,
    /// Lock events.
    Lock,
    /// Maple tree events.
    MapleTree,
    /// Machine Check Exception events.
    Mce,
    /// MCTP events.
    Mctp,
    /// MDIO events.
    Mdio,
    /// Memory controller events.
    Memcg,
    /// Memory migration events.
    Migrate,
    /// Mellanox switch events.
    Mlxsw,
    /// Memory mapping events.
    Mmap,
    /// Memory map lock events.
    MmapLock,
    /// MMC events.
    Mmc,
    /// Module events.
    Module,
    /// Multipath TCP events.
    Mptcp,
    /// NAPI events.
    Napi,
    /// Network block device events.
    Nbd,
    /// Neighbor events.
    Neigh,
    /// Networking events.
    Net,
    /// Network filesystem events.
    Netfs,
    /// Netlink events.
    Netlink,
    /// NILFS2 filesystem events.
    Nilfs2,
    /// Non-maskable interrupt events.
    Nmi,
    /// Notifier events.
    Notifier,
    /// Object aggregation events.
    Objagg,
    /// Out of memory events.
    Oom,
    /// OS noise events.
    Osnoise,
    /// Page isolation events.
    PageIsolation,
    /// Pagemap events.
    Pagemap,
    /// Page pool events.
    PagePool,
    /// Page reference events.
    PageRef,
    /// Per-CPU events.
    Percpu,
    /// Power management events.
    Power,
    /// Preemption and IRQ events.
    Preemptirq,
    /// Printk events.
    Printk,
    /// PWC events.
    Pwc,
    /// PWM events.
    Pwm,
    /// Queueing discipline events.
    Qdisc,
    /// QLogic adapter events.
    Qla,
    /// QRTR events.
    Qrtr,
    /// Raw syscalls events.
    RawSyscalls,
    /// Read-copy-update events.
    Rcu,
    /// RDMA core events.
    RdmaCore,
    /// Regulator events.
    Regulator,
    /// RPC GSS events.
    Rpcgss,
    /// RPC RDMA events.
    Rpcrdma,
    /// Runtime Power Management events.
    Rpm,
    /// Restartable sequences events.
    Rseq,
    /// Real-time clock events.
    Rtc,
    /// Rust sample events.
    RustSample,
    /// Reduced Virtualization events.
    Rv,
    /// Read-write memory-mapped I/O events.
    Rwmmio,
    /// RxRPC events.
    Rxrpc,
    /// Scheduler events.
    Sched,
    /// Scheduler extensions events.
    SchedExt,
    /// SCMI events.
    Scmi,
    /// SCSI events.
    Scsi,
    /// SCTP protocol events.
    Sctp,
    /// Signal events.
    Signal,
    /// SIOX events.
    Siox,
    /// Socket buffer events.
    Skb,
    /// SMBus events.
    Smbus,
    /// Socket events.
    Sock,
    /// Sound Open Firmware events.
    Sof,
    /// Sound Open Firmware Intel events.
    SofIntel,
    /// SPI events.
    Spi,
    /// System Power Management Interface events.
    Spmi,
    /// SunRPC events.
    Sunrpc,
    /// Sunvnet events.
    Sunvnet,
    /// Software I/O translation buffer events.
    Swiotlb,
    /// System call events.
    Syscalls,
    /// Target events.
    Target,
    /// Task events.
    Task,
    /// TCP (Transmission Control Protocol) events.
    Tcp,
    /// Tegra APB DMA events.
    TegraApbDma,
    /// Transparent Huge Pages events.
    Thp,
    /// Timer events.
    Timer,
    /// Timer migration events.
    TimerMigration,
    /// Timestamp events.
    Timestamp,
    /// Translation Lookaside Buffer events.
    Tlb,
    /// UDP (User Datagram Protocol) events.
    Udp,
    /// Video4Linux2 events.
    V4L2,
    /// Video buffer events.
    Vb2,
    /// Virtual memory allocation events.
    Vmalloc,
    /// Virtual memory scanning events.
    Vmscan,
    /// Virtual socket events.
    Vsock,
    /// Watchdog events.
    Watchdog,
    /// Writeback throttling events.
    Wbt,
    /// Workqueue events.
    Workqueue,
    /// Writeback events.
    Writeback,
    /// XDP events.
    Xdp,
    /// Xen hypervisor events.
    Xen,
    /// Custom type. Tracepoint category that is not predefined.
    Custom(String),
}

impl AsRef<str> for TracepointCategory {
    fn as_ref(&self) -> &str {
        match self {
            Self::P9 => "9p",
            Self::Afs => "afs",
            Self::Alarmtimer => "alarmtimer",
            Self::Asoc => "asoc",
            Self::Avc => "avc",
            Self::Bcache => "bcache",
            Self::Block => "block",
            Self::BpfTestRun => "bpf_test_run",
            Self::BpfTrace => "bpf_trace",
            Self::Bridge => "bridge",
            Self::Btrfs => "btrfs",
            Self::Cachefiles => "cachefiles",
            Self::Cgroup => "cgroup",
            Self::Clk => "clk",
            Self::Cma => "cma",
            Self::Compaction => "compaction",
            Self::ContextTracking => "context_tracking",
            Self::Cpuhp => "cpuhp",
            Self::Csd => "csd",
            Self::Damon => "damon",
            Self::Devfreq => "devfreq",
            Self::Devlink => "devlink",
            Self::Dlm => "dlm",
            Self::Dma => "dma",
            Self::DmaFence => "dma_fence",
            Self::Erofs => "erofs",
            Self::ErrorReport => "error_report",
            Self::Ext4 => "ext4",
            Self::F2Fs => "f2fs",
            Self::Fib => "fib",
            Self::Fib6 => "fib6",
            Self::Filelock => "filelock",
            Self::Filemap => "filemap",
            Self::Fscache => "fscache",
            Self::FsDax => "fs_dax",
            Self::Fsi => "fsi",
            Self::FsiMasterAspeed => "fsi_master_aspeed",
            Self::FsiMasterAstCf => "fsi_master_ast_cf",
            Self::FsiMasterGpio => "fsi_master_gpio",
            Self::FsiMasterI2Cr => "fsi_master_i2cr",
            Self::Gpio => "gpio",
            Self::GpuMem => "gpu_mem",
            Self::Habanalabs => "habanalabs",
            Self::Handshake => "handshake",
            Self::Host1X => "host1x",
            Self::HugeMemory => "huge_memory",
            Self::Hugetlbfs => "hugetlbfs",
            Self::Hwmon => "hwmon",
            Self::HwPressure => "hw_pressure",
            Self::I2C => "i2c",
            Self::I2CSlave => "i2c_slave",
            Self::IbMad => "ib_mad",
            Self::IbUmad => "ib_umad",
            Self::Icmp => "icmp",
            Self::Initcall => "initcall",
            Self::IntelIfs => "intel_ifs",
            Self::IntelIsh => "intel_ish",
            Self::IntelSst => "intel-sst",
            Self::Iocost => "iocost",
            Self::Iommu => "iommu",
            Self::IoUring => "io_uring",
            Self::Ipi => "ipi",
            Self::Irq => "irq",
            Self::IrqMatrix => "irq_matrix",
            Self::Iscsi => "iscsi",
            Self::Jbd2 => "jbd2",
            Self::Kmem => "kmem",
            Self::Ksm => "ksm",
            Self::Kvm => "kvm",
            Self::Kyber => "kyber",
            Self::Libata => "libata",
            Self::Lock => "lock",
            Self::MapleTree => "maple_tree",
            Self::Mce => "mce",
            Self::Mctp => "mctp",
            Self::Mdio => "mdio",
            Self::Memcg => "memcg",
            Self::Migrate => "migrate",
            Self::Mlxsw => "mlxsw",
            Self::Mmap => "mmap",
            Self::MmapLock => "mmap_lock",
            Self::Mmc => "mmc",
            Self::Module => "module",
            Self::Mptcp => "mptcp",
            Self::Napi => "napi",
            Self::Nbd => "nbd",
            Self::Neigh => "neigh",
            Self::Net => "net",
            Self::Netfs => "netfs",
            Self::Netlink => "netlink",
            Self::Nilfs2 => "nilfs2",
            Self::Nmi => "nmi",
            Self::Notifier => "notifier",
            Self::Objagg => "objagg",
            Self::Oom => "oom",
            Self::Osnoise => "osnoise",
            Self::PageIsolation => "page_isolation",
            Self::Pagemap => "pagemap",
            Self::PagePool => "page_pool",
            Self::PageRef => "page_ref",
            Self::Percpu => "percpu",
            Self::Power => "power",
            Self::Preemptirq => "preemptirq",
            Self::Printk => "printk",
            Self::Pwc => "pwc",
            Self::Pwm => "pwm",
            Self::Qdisc => "qdisc",
            Self::Qla => "qla",
            Self::Qrtr => "qrtr",
            Self::RawSyscalls => "raw_syscalls",
            Self::Rcu => "rcu",
            Self::RdmaCore => "rdma_core",
            Self::Regulator => "regulator",
            Self::Rpcgss => "rpcgss",
            Self::Rpcrdma => "rpcrdma",
            Self::Rpm => "rpm",
            Self::Rseq => "rseq",
            Self::Rtc => "rtc",
            Self::RustSample => "rust_sample",
            Self::Rv => "rv",
            Self::Rwmmio => "rwmmio",
            Self::Rxrpc => "rxrpc",
            Self::Sched => "sched",
            Self::SchedExt => "sched_ext",
            Self::Scmi => "scmi",
            Self::Scsi => "scsi",
            Self::Sctp => "sctp",
            Self::Signal => "signal",
            Self::Siox => "siox",
            Self::Skb => "skb",
            Self::Smbus => "smbus",
            Self::Sock => "sock",
            Self::Sof => "sof",
            Self::SofIntel => "sof_intel",
            Self::Spi => "spi",
            Self::Spmi => "spmi",
            Self::Sunrpc => "sunrpc",
            Self::Sunvnet => "sunvnet",
            Self::Swiotlb => "swiotlb",
            Self::Syscalls => "syscalls",
            Self::Target => "target",
            Self::Task => "task",
            Self::Tcp => "tcp",
            Self::TegraApbDma => "tegra_apb_dma",
            Self::Thp => "thp",
            Self::Timer => "timer",
            Self::TimerMigration => "timer_migration",
            Self::Timestamp => "timestamp",
            Self::Tlb => "tlb",
            Self::Udp => "udp",
            Self::V4L2 => "v4l2",
            Self::Vb2 => "vb2",
            Self::Vmalloc => "vmalloc",
            Self::Vmscan => "vmscan",
            Self::Vsock => "vsock",
            Self::Watchdog => "watchdog",
            Self::Wbt => "wbt",
            Self::Workqueue => "workqueue",
            Self::Writeback => "writeback",
            Self::Xdp => "xdp",
            Self::Xen => "xen",
            Self::Custom(category) => category,
        }
    }
}
