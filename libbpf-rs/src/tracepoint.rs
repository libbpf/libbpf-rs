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
