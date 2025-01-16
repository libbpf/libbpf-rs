//! libbpf-cargo helps you develop and build eBPF (BPF) programs with standard rust tooling.
//!
//! libbpf-cargo supports two interfaces:
//! * [`SkeletonBuilder`] API, for use with [build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
//! * `cargo-libbpf` cargo subcommand, for use with `cargo`
//!
//! The **build script interface is recommended** over the cargo subcommand interface because:
//! * once set up, you cannot forget to update the generated skeletons if your source changes
//! * build scripts are standard practice for projects that include codegen
//! * newcomers to your project can `cargo build` and it will "just work"
//!
//! The following sections in this document describe the `cargo-libbpf` plugin. See the API
//! reference for documentation on the build script interface.
//!
//! # Configuration
//!
//! cargo-libbpf consumes the following Cargo.toml configuration options:
//!
//! ```text
//! [package.metadata.libbpf]
//! prog_dir = "src/other_bpf_dir"  # default: <manifest_directory>/src/bpf
//! target_dir = "other_target_dir" # default: <target_dir>/bpf
//! ```
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
//! * there may not be any two identical `<NAME>.bpf.c` file names in any two projects in a cargo
//!   workspace
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

#![allow(clippy::let_unit_value)]
#![warn(
    elided_lifetimes_in_paths,
    missing_debug_implementations,
    single_use_lifetimes,
    clippy::absolute_paths,
    clippy::wildcard_imports
)]
#![deny(unsafe_op_in_unsafe_fn)]

pub use build::CompilationOutput;

use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context as _;
use anyhow::Result;

use tempfile::tempdir;
use tempfile::TempDir;

mod build;
mod gen;
mod make;
mod metadata;

#[cfg(test)]
mod test;

use build::BpfObjBuilder;


/// `SkeletonBuilder` builds and generates a single skeleton.
///
/// This interface is meant to be used in build scripts.
///
/// # Examples
///
/// ```no_run
/// use libbpf_cargo::SkeletonBuilder;
///
/// SkeletonBuilder::new()
///     .source("myobject.bpf.c")
///     .clang("/opt/clang/clang")
///     .build_and_generate("/output/path")
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct SkeletonBuilder {
    source: Option<PathBuf>,
    obj: Option<PathBuf>,
    clang: Option<PathBuf>,
    clang_args: Vec<OsString>,
    rustfmt: PathBuf,
    dir: Option<TempDir>,
}

impl Default for SkeletonBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SkeletonBuilder {
    pub fn new() -> Self {
        SkeletonBuilder {
            source: None,
            obj: None,
            clang: None,
            clang_args: Vec::new(),
            rustfmt: "rustfmt".into(),
            dir: None,
        }
    }

    /// Point the [`SkeletonBuilder`] to a source file for compilation
    ///
    /// Default is None
    pub fn source<P: AsRef<Path>>(&mut self, source: P) -> &mut SkeletonBuilder {
        self.source = Some(source.as_ref().to_path_buf());
        self
    }

    /// Point the [`SkeletonBuilder`] to an object file for generation
    ///
    /// Default is None
    pub fn obj<P: AsRef<Path>>(&mut self, obj: P) -> &mut SkeletonBuilder {
        self.obj = Some(obj.as_ref().to_path_buf());
        self
    }

    /// Specify which `clang` binary to use
    ///
    /// Default searches `$PATH` for `clang`
    pub fn clang<P: AsRef<Path>>(&mut self, clang: P) -> &mut SkeletonBuilder {
        self.clang = Some(clang.as_ref().to_path_buf());
        self
    }

    /// Pass additional arguments to `clang` when building BPF object file
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use libbpf_cargo::SkeletonBuilder;
    ///
    /// SkeletonBuilder::new()
    ///     .source("myobject.bpf.c")
    ///     .clang_args([
    ///         "-DMACRO=value",
    ///         "-I/some/include/dir",
    ///     ])
    ///     .build_and_generate("/output/path")
    ///     .unwrap();
    /// ```
    pub fn clang_args<A, S>(&mut self, args: A) -> &mut SkeletonBuilder
    where
        A: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.clang_args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect();
        self
    }

    /// Specify which `rustfmt` binary to use
    ///
    /// Default searches `$PATH` for `rustfmt`
    pub fn rustfmt<P: AsRef<Path>>(&mut self, rustfmt: P) -> &mut SkeletonBuilder {
        self.rustfmt = rustfmt.as_ref().to_path_buf();
        self
    }

    /// Build BPF programs and generate the skeleton at path `output`
    pub fn build_and_generate<P: AsRef<Path>>(&mut self, output: P) -> Result<CompilationOutput> {
        let comp_output = self.build()?;
        self.generate(output)?;

        Ok(comp_output)
    }

    // Build BPF programs without generating a skeleton.
    //
    // [`SkeletonBuilder::source`] must be set for this to succeed.
    pub fn build(&mut self) -> Result<CompilationOutput> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| anyhow!("No source file provided"))?;

        let filename = source
            .file_name()
            .ok_or_else(|| anyhow!("Missing file name"))?
            .to_str()
            .ok_or_else(|| anyhow!("Invalid unicode in file name"))?;

        if !filename.ends_with(".bpf.c") {
            return Err(anyhow!(
                "Source `{}` does not have .bpf.c suffix",
                source.display()
            ));
        }

        if self.obj.is_none() {
            let name = filename.split('.').next().unwrap();
            let dir = tempdir().context("failed to create temporary directory")?;
            let objfile = dir.path().join(format!("{name}.o"));
            self.obj = Some(objfile);
            // Hold onto tempdir so that it doesn't get deleted early
            self.dir = Some(dir);
        }

        let mut builder = BpfObjBuilder::default();
        if let Some(clang) = &self.clang {
            builder.compiler(clang);
        }
        builder.compiler_args(&self.clang_args);

        // SANITY: Unwrap is safe here since we guarantee that obj.is_some() above.
        builder
            .build(source, self.obj.as_ref().unwrap())
            .with_context(|| format!("failed to build `{}`", source.display()))
    }

    // Generate a skeleton at path `output` without building BPF programs.
    //
    // [`SkeletonBuilder::obj`] must be set for this to succeed.
    pub fn generate<P: AsRef<Path>>(&mut self, output: P) -> Result<()> {
        let objfile = self.obj.as_ref().ok_or_else(|| anyhow!("No object file"))?;

        gen::gen_single(
            objfile,
            gen::OutputDest::File(output.as_ref()),
            Some(&self.rustfmt),
        )
        .with_context(|| format!("failed to generate `{}`", objfile.display()))?;

        Ok(())
    }
}


/// Implementation details shared with the binary.
///
/// NOT PART OF PUBLIC API SURFACE!
#[doc(hidden)]
pub mod __private {
    pub mod build {
        pub use crate::build::build_project;
    }
    pub mod gen {
        pub use crate::gen::gen;
    }
    pub mod make {
        pub use crate::make::make;
    }
}
