// Dummy library, so libbpf-cargo can be registered as a dependency in tools like
// https://github.com/facebookincubator/reindeer and so we can add docs to docs.rs.

//! cargo-libbpf is a cargo subcommand that helps develop and build eBPF (BPF) programs.
//!
//! # Configuration
//!
//! libbpf-cargo provides the following Cargo.toml configuration options:
//!
//!     [package.metadata.libbpf]
//!     prog_dir = "src/other_bpf_dir"  # default: <manifest_directory>/src/bpf
//!     target_dir = "other_target_dir" # default: <target_dir>/bpf
//!
//! * `prog_dir`: path relative to package Cargo.toml to search for bpf progs
//! * `target_dir`: path relative to workspace target directory to place compiled bpf progs
//!
//! # Subcommands
//!
//! ## build
//!
//! `cargo libbpf build` compiles `<NAME>.bpf.c` C files into corresponding `<NAME>.bpf.o` ELF
//! object files. Each object file may contain one or more BPF programs, maps, and associated
//! metadata. The object file may then be handed over to `libbpf-rs` for loading and interaction.
//!
//! cargo-libbpf-build enforces a few conventions:
//!
//! * source file names must be in the `<NAME>.bpf.c` format
//! * object file names will be generated in `<NAME>.bpf.o` format
//! * there may not be any two identical `<NAME>.bpf.c` file names in any two projects in a
//!   cargo workspace
//!
//! ## gen
//!
//! `cargo libbpf gen` generates a skeleton module for each BPF object file in the project.  Each
//! `<NAME>.bpf.o` object file will have its own module. One `mod.rs` file is also generated. All
//! output files are placed into `package.metadata.libbpf.prog_dir`.
//!
//! Be careful to run cargo-libbpf-build before running cargo-libbpf-gen. cargo-libbpf-gen reads
//! object files from `package.metadata.libbpf.target_dir`.
//!
//! ## make
//!
//! `cargo libbpf make` sequentially runs cargo-libbpf-build, cargo-libbpf-gen, and `cargo
//! build`. This is a convenience command so you don't forget any steps. Alternatively, you could
//! write a Makefile for your project.

#[doc(hidden)]
pub fn foo() {}
