//! # libbpf-rs
//!
//! `libbpf-rs` is a safe, idiomatic, and opinionated wrapper around
//! [libbpf](https://github.com/libbpf/libbpf/).
//!
//! libbpf-rs, together with `libbpf-cargo` (libbpf cargo plugin) allow you
//! to write Compile-Once-Run-Everywhere (CO-RE) eBPF programs. Note this document
//! uses "eBPF" and "BPF" interchangeably.
//!
//! More information about CO-RE is [available
//! here](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html).

mod error;
mod link;
mod object;
mod perf_buffer;
mod util;

pub use crate::error::{Error, Result};
pub use crate::link::Link;
pub use crate::object::{
    CgroupAttachFlags, Map, MapBuilder, MapBuilderFlags, MapFlags, MapType, Object, ObjectBuilder,
    Program, ProgramAttachType, ProgramBuilder, ProgramType,
};
pub use crate::perf_buffer::{PerfBuffer, PerfBufferBuilder};
