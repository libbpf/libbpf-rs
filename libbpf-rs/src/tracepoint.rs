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
        libbpf_sys::bpf_tracepoint_opts {
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
        libbpf_sys::bpf_raw_tracepoint_opts {
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
            TracepointCategory::P9 => "9p",
            TracepointCategory::Afs => "afs",
            TracepointCategory::Alarmtimer => "alarmtimer",
            TracepointCategory::Asoc => "asoc",
            TracepointCategory::Avc => "avc",
            TracepointCategory::Bcache => "bcache",
            TracepointCategory::Block => "block",
            TracepointCategory::BpfTestRun => "bpf_test_run",
            TracepointCategory::BpfTrace => "bpf_trace",
            TracepointCategory::Bridge => "bridge",
            TracepointCategory::Btrfs => "btrfs",
            TracepointCategory::Cachefiles => "cachefiles",
            TracepointCategory::Cgroup => "cgroup",
            TracepointCategory::Clk => "clk",
            TracepointCategory::Cma => "cma",
            TracepointCategory::Compaction => "compaction",
            TracepointCategory::ContextTracking => "context_tracking",
            TracepointCategory::Cpuhp => "cpuhp",
            TracepointCategory::Csd => "csd",
            TracepointCategory::Damon => "damon",
            TracepointCategory::Devfreq => "devfreq",
            TracepointCategory::Devlink => "devlink",
            TracepointCategory::Dlm => "dlm",
            TracepointCategory::Dma => "dma",
            TracepointCategory::DmaFence => "dma_fence",
            TracepointCategory::Erofs => "erofs",
            TracepointCategory::ErrorReport => "error_report",
            TracepointCategory::Ext4 => "ext4",
            TracepointCategory::F2Fs => "f2fs",
            TracepointCategory::Fib => "fib",
            TracepointCategory::Fib6 => "fib6",
            TracepointCategory::Filelock => "filelock",
            TracepointCategory::Filemap => "filemap",
            TracepointCategory::Fscache => "fscache",
            TracepointCategory::FsDax => "fs_dax",
            TracepointCategory::Fsi => "fsi",
            TracepointCategory::FsiMasterAspeed => "fsi_master_aspeed",
            TracepointCategory::FsiMasterAstCf => "fsi_master_ast_cf",
            TracepointCategory::FsiMasterGpio => "fsi_master_gpio",
            TracepointCategory::FsiMasterI2Cr => "fsi_master_i2cr",
            TracepointCategory::Gpio => "gpio",
            TracepointCategory::GpuMem => "gpu_mem",
            TracepointCategory::Habanalabs => "habanalabs",
            TracepointCategory::Handshake => "handshake",
            TracepointCategory::Host1X => "host1x",
            TracepointCategory::HugeMemory => "huge_memory",
            TracepointCategory::Hugetlbfs => "hugetlbfs",
            TracepointCategory::Hwmon => "hwmon",
            TracepointCategory::HwPressure => "hw_pressure",
            TracepointCategory::I2C => "i2c",
            TracepointCategory::I2CSlave => "i2c_slave",
            TracepointCategory::IbMad => "ib_mad",
            TracepointCategory::IbUmad => "ib_umad",
            TracepointCategory::Icmp => "icmp",
            TracepointCategory::Initcall => "initcall",
            TracepointCategory::IntelIfs => "intel_ifs",
            TracepointCategory::IntelIsh => "intel_ish",
            TracepointCategory::IntelSst => "intel-sst",
            TracepointCategory::Iocost => "iocost",
            TracepointCategory::Iommu => "iommu",
            TracepointCategory::IoUring => "io_uring",
            TracepointCategory::Ipi => "ipi",
            TracepointCategory::Irq => "irq",
            TracepointCategory::IrqMatrix => "irq_matrix",
            TracepointCategory::Iscsi => "iscsi",
            TracepointCategory::Jbd2 => "jbd2",
            TracepointCategory::Kmem => "kmem",
            TracepointCategory::Ksm => "ksm",
            TracepointCategory::Kvm => "kvm",
            TracepointCategory::Kyber => "kyber",
            TracepointCategory::Libata => "libata",
            TracepointCategory::Lock => "lock",
            TracepointCategory::MapleTree => "maple_tree",
            TracepointCategory::Mce => "mce",
            TracepointCategory::Mctp => "mctp",
            TracepointCategory::Mdio => "mdio",
            TracepointCategory::Memcg => "memcg",
            TracepointCategory::Migrate => "migrate",
            TracepointCategory::Mlxsw => "mlxsw",
            TracepointCategory::Mmap => "mmap",
            TracepointCategory::MmapLock => "mmap_lock",
            TracepointCategory::Mmc => "mmc",
            TracepointCategory::Module => "module",
            TracepointCategory::Mptcp => "mptcp",
            TracepointCategory::Napi => "napi",
            TracepointCategory::Nbd => "nbd",
            TracepointCategory::Neigh => "neigh",
            TracepointCategory::Net => "net",
            TracepointCategory::Netfs => "netfs",
            TracepointCategory::Netlink => "netlink",
            TracepointCategory::Nilfs2 => "nilfs2",
            TracepointCategory::Nmi => "nmi",
            TracepointCategory::Notifier => "notifier",
            TracepointCategory::Objagg => "objagg",
            TracepointCategory::Oom => "oom",
            TracepointCategory::Osnoise => "osnoise",
            TracepointCategory::PageIsolation => "page_isolation",
            TracepointCategory::Pagemap => "pagemap",
            TracepointCategory::PagePool => "page_pool",
            TracepointCategory::PageRef => "page_ref",
            TracepointCategory::Percpu => "percpu",
            TracepointCategory::Power => "power",
            TracepointCategory::Preemptirq => "preemptirq",
            TracepointCategory::Printk => "printk",
            TracepointCategory::Pwc => "pwc",
            TracepointCategory::Pwm => "pwm",
            TracepointCategory::Qdisc => "qdisc",
            TracepointCategory::Qla => "qla",
            TracepointCategory::Qrtr => "qrtr",
            TracepointCategory::RawSyscalls => "raw_syscalls",
            TracepointCategory::Rcu => "rcu",
            TracepointCategory::RdmaCore => "rdma_core",
            TracepointCategory::Regulator => "regulator",
            TracepointCategory::Rpcgss => "rpcgss",
            TracepointCategory::Rpcrdma => "rpcrdma",
            TracepointCategory::Rpm => "rpm",
            TracepointCategory::Rseq => "rseq",
            TracepointCategory::Rtc => "rtc",
            TracepointCategory::RustSample => "rust_sample",
            TracepointCategory::Rv => "rv",
            TracepointCategory::Rwmmio => "rwmmio",
            TracepointCategory::Rxrpc => "rxrpc",
            TracepointCategory::Sched => "sched",
            TracepointCategory::SchedExt => "sched_ext",
            TracepointCategory::Scmi => "scmi",
            TracepointCategory::Scsi => "scsi",
            TracepointCategory::Sctp => "sctp",
            TracepointCategory::Signal => "signal",
            TracepointCategory::Siox => "siox",
            TracepointCategory::Skb => "skb",
            TracepointCategory::Smbus => "smbus",
            TracepointCategory::Sock => "sock",
            TracepointCategory::Sof => "sof",
            TracepointCategory::SofIntel => "sof_intel",
            TracepointCategory::Spi => "spi",
            TracepointCategory::Spmi => "spmi",
            TracepointCategory::Sunrpc => "sunrpc",
            TracepointCategory::Sunvnet => "sunvnet",
            TracepointCategory::Swiotlb => "swiotlb",
            TracepointCategory::Syscalls => "syscalls",
            TracepointCategory::Target => "target",
            TracepointCategory::Task => "task",
            TracepointCategory::Tcp => "tcp",
            TracepointCategory::TegraApbDma => "tegra_apb_dma",
            TracepointCategory::Thp => "thp",
            TracepointCategory::Timer => "timer",
            TracepointCategory::TimerMigration => "timer_migration",
            TracepointCategory::Timestamp => "timestamp",
            TracepointCategory::Tlb => "tlb",
            TracepointCategory::Udp => "udp",
            TracepointCategory::V4L2 => "v4l2",
            TracepointCategory::Vb2 => "vb2",
            TracepointCategory::Vmalloc => "vmalloc",
            TracepointCategory::Vmscan => "vmscan",
            TracepointCategory::Vsock => "vsock",
            TracepointCategory::Watchdog => "watchdog",
            TracepointCategory::Wbt => "wbt",
            TracepointCategory::Workqueue => "workqueue",
            TracepointCategory::Writeback => "writeback",
            TracepointCategory::Xdp => "xdp",
            TracepointCategory::Xen => "xen",
            TracepointCategory::Custom(category) => category,
        }
    }
}
