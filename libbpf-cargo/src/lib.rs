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

use std::{
    path::{Path, PathBuf},
    result,
};

use tempfile::{tempdir, TempDir};
use thiserror::Error;

// libbpf-cargo binary is the primary consumer of the following modules. As such,
// we do not use all the symbols. Silence any unused code warnings.
#[allow(dead_code)]
mod btf;
#[allow(dead_code)]
mod build;
#[allow(dead_code)]
mod gen;
#[allow(dead_code)]
mod make;
#[allow(dead_code)]
mod metadata;

#[cfg(test)]
mod test;

/// Canonical error type for this crate.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Error building BPF object file: {0}")]
    Build(String),
    #[error("Error generating skeleton: {0}")]
    Generate(String),
}

pub type Result<T> = result::Result<T, Error>;

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
///     .debug(true)
///     .clang("/opt/clang/clang")
///     .build_and_generate("/output/path")
///     .unwrap();
/// ```
pub struct SkeletonBuilder {
    debug: bool,
    source: Option<PathBuf>,
    obj: Option<PathBuf>,
    clang: Option<PathBuf>,
    clang_args: String,
    skip_clang_version_check: bool,
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
            debug: false,
            source: None,
            obj: None,
            clang: None,
            clang_args: String::new(),
            skip_clang_version_check: false,
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

    /// Turn debug output on or off
    ///
    /// Default is off
    pub fn debug(&mut self, debug: bool) -> &mut SkeletonBuilder {
        self.debug = debug;
        self
    }

    /// Specify which `clang` binary to use
    ///
    /// Default searchs `$PATH` for `clang`
    pub fn clang<P: AsRef<Path>>(&mut self, clang: P) -> &mut SkeletonBuilder {
        self.clang = Some(clang.as_ref().to_path_buf());
        self
    }

    /// Pass additional arguments to `clang` when buildling BPF object file
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use libbpf_cargo::SkeletonBuilder;
    ///
    /// SkeletonBuilder::new()
    ///     .source("myobject.bpf.c")
    ///     .clang_args("-DMACRO=value -I/some/include/dir")
    ///     .build_and_generate("/output/path")
    ///     .unwrap();
    /// ```
    pub fn clang_args<S: AsRef<str>>(&mut self, opts: S) -> &mut SkeletonBuilder {
        self.clang_args = opts.as_ref().to_string();
        self
    }

    /// Specify whether or not to skip clang version check
    ///
    /// Default is `false`
    pub fn skip_clang_version_check(&mut self, skip: bool) -> &mut SkeletonBuilder {
        self.skip_clang_version_check = skip;
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
    pub fn build_and_generate<P: AsRef<Path>>(&mut self, output: P) -> Result<()> {
        self.build()?;
        self.generate(output)?;

        Ok(())
    }

    // Build BPF programs without generating a skeleton.
    //
    // [`SkeletonBuilder::source`] must be set for this to succeed.
    pub fn build(&mut self) -> Result<()> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| Error::Build("No source file".into()))?;

        let filename = source
            .file_name()
            .ok_or_else(|| Error::Build("Missing file name".into()))?
            .to_str()
            .ok_or_else(|| Error::Build("Invalid unicode in file name".into()))?;

        if !filename.ends_with(".bpf.c") {
            return Err(Error::Build(format!(
                "Source file={} does not have .bpf.c suffix",
                source.display()
            )));
        }

        if self.obj.is_none() {
            let name = filename.split('.').next().unwrap();
            let dir = tempdir().map_err(|e| Error::Build(e.to_string()))?;
            let objfile = dir.path().join(format!("{}.o", name));
            self.obj = Some(objfile);
            // Hold onto tempdir so that it doesn't get deleted early
            self.dir = Some(dir);
        }

        build::build_single(
            self.debug,
            source,
            // Unwrap is safe here since we guarantee that obj.is_some() above
            self.obj.as_ref().unwrap(),
            self.clang.as_ref(),
            self.skip_clang_version_check,
            &self.clang_args,
        )
        .map_err(|e| Error::Build(e.to_string()))?;

        Ok(())
    }

    // Generate a skeleton at path `output` without building BPF programs.
    //
    // [`SkeletonBuilder::obj`] must be set for this to succeed.
    pub fn generate<P: AsRef<Path>>(&mut self, output: P) -> Result<()> {
        let objfile = self
            .obj
            .as_ref()
            .ok_or_else(|| Error::Generate("No object file".into()))?;

        gen::gen_single(
            self.debug,
            objfile,
            gen::OutputDest::File(output.as_ref()),
            Some(&self.rustfmt),
        )
        .map_err(|e| Error::Generate(e.to_string()))?;

        Ok(())
    }
}
