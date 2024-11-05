use std::mem::size_of;

/// Netfilter protocol family for IPv4.
pub const NFPROTO_IPV4: i32 = libc::NFPROTO_IPV4;
/// Netfilter protocol family for IPv6.
pub const NFPROTO_IPV6: i32 = libc::NFPROTO_IPV6;

/// Netfilter hook number for pre-routing (0).
pub const NF_INET_PRE_ROUTING: i32 = libc::NF_INET_PRE_ROUTING;
/// Netfilter hook number for local input (1).
pub const NF_INET_LOCAL_IN: i32 = libc::NF_INET_LOCAL_IN;
/// Netfilter hook number for packet forwarding (2).
pub const NF_INET_FORWARD: i32 = libc::NF_INET_FORWARD;
/// Netfilter hook number for local output (3).
pub const NF_INET_LOCAL_OUT: i32 = libc::NF_INET_LOCAL_OUT;
/// Netfilter hook number for post-routing (4).
pub const NF_INET_POST_ROUTING: i32 = libc::NF_INET_POST_ROUTING;

/// Options to be provided when attaching a program to a netfilter hook.
#[derive(Clone, Debug, Default)]
pub struct NetfilterOpts {
    /// Protocol family for netfilter; supported values are `NFPROTO_IPV4` (2) for IPv4
    /// and `NFPROTO_IPV6` (10) for IPv6.
    pub protocol_family: i32,

    /// Hook number for netfilter; supported values include:
    /// - `NF_INET_PRE_ROUTING` (0) - Pre-routing
    /// - `NF_INET_LOCAL_IN` (1) - Local input
    /// - `NF_INET_FORWARD` (2) - Forwarding
    /// - `NF_INET_LOCAL_OUT` (3) - Local output
    /// - `NF_INET_POST_ROUTING` (4) - Post-routing
    pub hooknum: i32,

    /// Priority of the netfilter hook. Lower values are invoked first.
    /// Values `NF_IP_PRI_FIRST` (-2147483648) and `NF_IP_PRI_LAST` (2147483647) are
    /// not allowed. If `BPF_F_NETFILTER_IP_DEFRAG` is set in `flags`, the priority
    /// must be higher than `NF_IP_PRI_CONNTRACK_DEFRAG` (-400).
    pub priority: i32,

    /// Bitmask of flags for the netfilter hook.
    /// - `NF_IP_PRI_CONNTRACK_DEFRAG` - Enables defragmentation of IP fragments. This hook will
    ///   only see defragmented packets.
    pub flags: u32,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

impl From<NetfilterOpts> for libbpf_sys::bpf_netfilter_opts {
    fn from(opts: NetfilterOpts) -> Self {
        let NetfilterOpts {
            protocol_family,
            hooknum,
            priority,
            flags,
            _non_exhaustive,
        } = opts;

        #[allow(clippy::needless_update)]
        libbpf_sys::bpf_netfilter_opts {
            sz: size_of::<Self>() as _,
            pf: protocol_family as u32,
            hooknum: hooknum as u32,
            priority,
            flags,
            ..Default::default()
        }
    }
}
