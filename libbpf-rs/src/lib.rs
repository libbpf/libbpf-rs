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
//!
//! ## High level workflow
//!
//! 1. Create new rust project (via `cargo new` or similar) at path `$PROJ_PATH`
//! 1. Create directory `$PROJ_PATH/src/bpf`
//! 1. Write CO-RE bpf code in `$PROJ_PATH/src/bpf/${MYFILE}.bpf.c`, where `$MYFILE` may be any
//!    valid filename. Note the `.bpf.c` extension is required.
//! 1. Create a [build script](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
//!    that builds and generates a skeleton module using `libbpf_cargo::SkeletonBuilder`
//! 1. Write your userspace code by importing and using the generated module. Import the
//!    module by using the [path
//!    attribute](https://doc.rust-lang.org/reference/items/modules.html#the-path-attribute).
//!    Your userspace code goes in `$PROJ_PATH/src/` as it would in a normal rust project.
//! 1. Continue regular rust workflow (ie `cargo build`, `cargo run`, etc)
//!
//! ## Alternate workflow
//!
//! While using the skeleton is recommended, it is also possible to directly use libbpf-rs.
//!
//! 1. Follow steps 1-3 of "High level workflow"
//! 1. Generate a BPF object file. Options include manually invoking `clang`, creating a build
//!    script to invoke `clang`, or using `libbpf-cargo` cargo plugins.
//! 1. Write your userspace code in `$PROJ_PATH/src/` as you would a normal rust project and point
//!    libbpf-rs at your BPF object file
//! 1. Continue regular rust workflow (ie `cargo build`, `cargo run`, etc)
//!
//! ## Static Compilation
//!
//! By default, programs using libbpf-rs will dynamically link against
//! non-vendored (system/distrubution provided) shared libraries.  These
//! non-vendored libraries will include libbpf.so, libz.so, and libelf.so
//! (please see crate libbpf-sys for more info).
//!
//! To use vendored versions of libbpf, libz and libelf please enable
//! the "static" feature.  With usage of "static", vendored copies of
//! libbpf, libz, and libelf will be compiled and statically linked to your program.
//!
//! Due to the C-library libbpf being tightly coupled to the linux kernel's
//! headers, musl targets will not work with the "static" feature.
//! Please see: https://wiki.musl-libc.org/faq.html section
//! "Why am i getting error: redefinition of..." for more information.
//!
//! To have a fully statically compiled binary, you may be able statically link
//! with the gnu compiler.  To do this, enable the "static" feature
//! and compile your program with the following command:
//!
//! $ RUSTFLAGS='-C target-feature+crt-static' \
//!     cargo build --target x86_64-unknown-linux-gnu
//!
//! ## Design
//!
//! libbpf-rs models various "phases":
//! ```text
//!                from_*()        load()
//!                  |               |
//!                  v               v
//!    ObjectBuilder ->  OpenObject  -> Object
//!                          ^            ^
//!                          |            |
//!              <pre-load modifications> |
//!                                       |
//!                            <post-load interactions>
//! ```
//!
//! The entry point into libbpf-rs is [`ObjectBuilder`]. `ObjectBuilder` helps open the BPF object
//! file. After the object file is opened, you are returned an [`OpenObject`] where you can
//! perform all your pre-load operations. Pre-load means before any BPF maps are created or BPF
//! programs are loaded and verified by the kernel. Finally, after the BPF object is loaded, you
//! are returned an [`Object`] instance where you can read/write to BPF maps, attach BPF programs
//! to hooks, etc.
//!
//! You _must_ keep the [`Object`] alive the entire duration you interact with anything inside the
//! BPF object it represents. This is further documented in [`Object`] documentation.
//!
//! ## Example
//!
//! This is probably the best way to understand how libbpf-rs and libbpf-cargo work together.
//!
//! [See example here](https://github.com/libbpf/libbpf-rs/tree/master/examples/runqslower).

#![allow(clippy::let_unit_value)]
#![warn(
    elided_lifetimes_in_paths,
    missing_debug_implementations,
    missing_docs,
    single_use_lifetimes,
    clippy::wildcard_imports,
    rustdoc::broken_intra_doc_links
)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod btf;
mod error;
mod iter;
mod link;
mod linker;
mod map;
mod object;
mod perf_buffer;
mod print;
mod program;
pub mod query;
mod ringbuf;
mod skeleton;
mod tc;
mod util;

pub use libbpf_sys;

pub use crate::btf::Btf;
pub use crate::btf::HasSize;
pub use crate::btf::ReferencesType;
pub use crate::error::Error;
pub use crate::error::ErrorExt;
pub use crate::error::ErrorKind;
pub use crate::error::Result;
pub use crate::iter::Iter;
pub use crate::link::Link;
pub use crate::linker::Linker;
pub use crate::map::Map;
pub use crate::map::MapFlags;
pub use crate::map::MapHandle;
pub use crate::map::MapInfo;
pub use crate::map::MapType;
pub use crate::map::OpenMap;
pub use crate::object::AsRawLibbpf;
pub use crate::object::Object;
pub use crate::object::ObjectBuilder;
pub use crate::object::OpenObject;
pub use crate::perf_buffer::PerfBuffer;
pub use crate::perf_buffer::PerfBufferBuilder;
pub use crate::print::get_print;
pub use crate::print::set_print;
pub use crate::print::PrintCallback;
pub use crate::print::PrintLevel;
pub use crate::program::OpenProgram;
pub use crate::program::Program;
pub use crate::program::ProgramAttachType;
pub use crate::program::ProgramType;
pub use crate::program::TracepointOpts;
pub use crate::program::UprobeOpts;
pub use crate::program::UsdtOpts;
pub use crate::ringbuf::RingBuffer;
pub use crate::ringbuf::RingBufferBuilder;
pub use crate::tc::TcAttachPoint;
pub use crate::tc::TcHook;
pub use crate::tc::TcHookBuilder;
pub use crate::tc::TC_CUSTOM;
pub use crate::tc::TC_EGRESS;
pub use crate::tc::TC_H_CLSACT;
pub use crate::tc::TC_H_INGRESS;
pub use crate::tc::TC_H_MIN_EGRESS;
pub use crate::tc::TC_H_MIN_INGRESS;
pub use crate::tc::TC_INGRESS;
pub use crate::util::num_possible_cpus;

/// Used for skeleton -- an end user may not consider this API stable
#[doc(hidden)]
pub mod __internal_skel {
    pub use super::skeleton::*;
}

/// Skeleton related definitions.
pub mod skel {
    pub use super::skeleton::OpenSkel;
    pub use super::skeleton::Skel;
    pub use super::skeleton::SkelBuilder;
}
