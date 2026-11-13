use std::collections::HashSet;
use std::env;
use std::env::consts::ARCH;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use tempfile::tempdir;
use tracing::debug;
use tracing::info;

use crate::metadata;
use crate::metadata::UnprocessedObj;


/// A helper for compiling BPF C code into a loadable BPF object file.
// TODO: Before exposing this functionality publicly, consider whether
//       we should support per-input-file compiler arguments.
#[derive(Debug)]
pub(crate) struct BpfObjBuilder {
    compiler: PathBuf,
    compiler_args: Vec<OsString>,
    extract_vmlinux_header: bool,
}

impl BpfObjBuilder {
    /// Specify which C compiler to use.
    pub fn compiler<P: AsRef<Path>>(&mut self, compiler: P) -> &mut Self {
        self.compiler = compiler.as_ref().to_path_buf();
        self
    }

    /// Pass additional arguments to the compiler when building the BPF object file.
    pub fn compiler_args<A, S>(&mut self, args: A) -> &mut Self
    where
        A: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.compiler_args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect();
        self
    }

    /// Specify whether vmlinux header is generated from the running kernel.
    pub fn extract_vmlinux_header(&mut self, extract: bool) -> &mut Self {
        self.extract_vmlinux_header = extract;
        self
    }

    /// We're essentially going to run:
    /// ```text
    /// clang -g -O2 -target bpf -c -D__TARGET_ARCH_$(ARCH) runqslower.bpf.c -o runqslower.bpf.o
    /// ```
    ///
    /// for each prog.
    fn compile_single(
        src: &Path,
        dst: &Path,
        compiler: &Path,
        compiler_args: &[OsString],
    ) -> Result<()> {
        debug!("Building {}", src.display());

        let mut cmd = Command::new(compiler.as_os_str());
        cmd.args(compiler_args);

        cmd.arg("-g")
            .arg("-O2")
            .arg("-target")
            .arg("bpf")
            .arg("-c")
            .arg(src.as_os_str())
            .arg("-o")
            .arg(dst);

        debug!("Running: `{}`", format_command(&cmd));

        let output = cmd
            .output()
            .with_context(|| format!("failed to execute `{}`", compiler.display()))?;
        if !output.status.success() {
            let err = Err(anyhow!(String::from_utf8_lossy(&output.stderr).to_string()))
                .with_context(|| {
                    format!(
                        "command `{}` failed ({})",
                        format_command(&cmd),
                        output.status
                    )
                })
                .with_context(|| {
                    format!("failed to compile {} from {}", dst.display(), src.display())
                });
            return err;
        }

        if !output.stdout.is_empty() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                info!(target: "compiler-stdout", "{line}");
            }
        }

        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            for line in stderr.lines() {
                info!(target: "compiler-stderr", "{line}");
            }
        }
        Ok(())
    }

    fn with_compiler_args<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&[OsString]) -> Result<R>,
    {
        let mut compiler_args = self.compiler_args.clone();

        let header_parent_dir = tempdir().context("failed to create temporary directory")?;
        let header_dir = extract_libbpf_headers_to_disk(header_parent_dir.path())
            .context("failed to extract libbpf header")?;

        if let Some(dir) = header_dir {
            compiler_args.push(OsString::from("-I"));
            compiler_args.push(dir.into_os_string());
        }

        if self.extract_vmlinux_header {
            let header_dir = extract_vmlinux_header_to_disk(header_parent_dir.path())
                .context("failed to extract vmlinux header")?;

            if let Some(dir) = header_dir {
                compiler_args.push(OsString::from("-I"));
                compiler_args.push(dir.into_os_string());
            }
        }

        // Explicitly disable stack protector logic, which doesn't work with
        // BPF. See https://lkml.org/lkml/2020/2/21/1000.
        compiler_args.push(OsString::from("-fno-stack-protector"));

        if !compiler_args
            .iter()
            .any(|arg| arg.to_string_lossy().contains("__TARGET_ARCH_"))
        {
            // We may end up being invoked by a build script, in which case
            // `CARGO_CFG_TARGET_ARCH` would represent the target architecture.
            let arch = env::var("CARGO_CFG_TARGET_ARCH");
            let arch = arch.as_deref().unwrap_or(ARCH);
            let arch = match arch {
                "x86_64" => "x86",
                "aarch64" => "arm64",
                "powerpc64" => "powerpc",
                "s390x" => "s390",
                "riscv64" => "riscv",
                "loongarch64" => "loongarch",
                "sparc64" => "sparc",
                "mips64" => "mips",
                x => x,
            };
            compiler_args.push(format!("-D__TARGET_ARCH_{arch}").into());
        }

        f(&compiler_args)
    }

    /// Build a BPF object file from a set of input files.
    pub fn build_many<S, P>(&mut self, srcs: S, dst: &Path) -> Result<()>
    where
        S: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let obj_dir = tempdir().context("failed to create temporary directory")?;
        let mut linker = libbpf_rs::Linker::new(dst)
            .context("failed to instantiate libbpf object file linker")?;

        let () = self.with_compiler_args(|compiler_args| {
            srcs.into_iter().try_for_each(|src| {
                let src = src.as_ref();
                let tmp_dst = obj_dir.path().join(src.file_name().with_context(|| {
                    format!(
                        "input path `{}` does not have a proper file name",
                        src.display()
                    )
                })?);

                let () = Self::compile_single(src, &tmp_dst, &self.compiler, compiler_args)
                    .with_context(|| format!("failed to compile `{}`", src.display()))?;

                linker
                    .add_file(tmp_dst)
                    .context("failed to add object file to BPF linker")?;
                Ok(())
            })
        })?;

        // The resulting object file may contain DWARF information
        // that references system specific and temporary paths. That
        // can render our generated skeletons unstable, potentially
        // making them unsuitable for inclusion in version control
        // systems. Linking has the side effect of stripping this
        // information.
        linker.link().context("failed to link object file")?;

        Ok(())
    }

    /// Build a BPF object file.
    pub fn build(&mut self, src: &Path, dst: &Path) -> Result<()> {
        self.build_many([src], dst)
    }
}

impl Default for BpfObjBuilder {
    fn default() -> Self {
        Self {
            compiler: "clang".into(),
            compiler_args: Vec::new(),
            extract_vmlinux_header: false,
        }
    }
}


fn check_progs(objs: &[UnprocessedObj]) -> Result<()> {
    let mut set = HashSet::with_capacity(objs.len());
    for obj in objs {
        // OK to unwrap() file_name() b/c we already checked earlier that this is a valid file
        let dest = obj
            .out
            .as_path()
            .join(obj.path.as_path().file_name().unwrap());
        if !set.insert(dest) {
            bail!(
                "Duplicate obj={} detected",
                obj.path.as_path().file_name().unwrap().to_string_lossy()
            );
        }
    }

    Ok(())
}

/// Extract vendored libbpf header files to a temporary directory.
///
/// Directory and enclosed contents will be removed when return object is dropped.
#[cfg(feature = "default")]
fn extract_libbpf_headers_to_disk(target_dir: &Path) -> Result<Option<PathBuf>> {
    use libbpf_rs::libbpf_sys;
    use std::fs::OpenOptions;
    use std::io::Write;

    let parent_dir = target_dir.join("bpf").join("src");
    let dir = parent_dir.join("bpf");
    fs::create_dir_all(&dir)?;
    for (filename, contents) in libbpf_sys::API_HEADERS.iter() {
        let path = dir.as_path().join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
    }

    Ok(Some(parent_dir))
}

#[cfg(not(feature = "default"))]
fn extract_libbpf_headers_to_disk(_target_dir: &Path) -> Result<Option<PathBuf>> {
    Ok(None)
}

fn extract_vmlinux_header_to_disk(target_dir: &Path) -> Result<Option<PathBuf>> {
    use libbpf_rs::btf::dump::BtfDump;
    use libbpf_rs::btf::dump::EmitTypeDeclOpts;
    use libbpf_rs::btf::types;
    use libbpf_rs::btf::Btf;
    use std::fs::OpenOptions;
    use std::io;
    use std::io::Write;

    let parent_dir = target_dir.join("bpf").join("src");
    fs::create_dir_all(&parent_dir)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(parent_dir.join("vmlinux.h"))?;

    // The logic copied from:
    // https://github.com/libbpf/bpftool/blob/19bb41ccbd7ae7286981035a252a05126e0bab10/src/btf.c#L1095
    write!(
        file,
        concat!(
	    "#ifndef __VMLINUX_H__\n",
	    "#define __VMLINUX_H__\n",
	    "\n",
	    "#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n",
	    "#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)\n",
	    "#endif\n\n",
	    "#ifndef __ksym\n",
	    "#define __ksym __attribute__((section(\".ksyms\")))\n",
	    "#endif\n\n",
	    "#ifndef __weak\n",
	    "#define __weak __attribute__((weak))\n",
	    "#endif\n\n",
	    "#ifndef __bpf_fastcall\n",
	    "#if __has_attribute(bpf_fastcall)\n",
	    "#define __bpf_fastcall __attribute__((bpf_fastcall))\n",
	    "#else\n",
	    "#define __bpf_fastcall\n",
	    "#endif\n",
	    "#endif\n\n",
        ),
    )?;

    {
        let btf = Btf::from_vmlinux()?;
        let mut dump = BtfDump::new(&btf, &file)?;
        for type_id in 1..btf.len() as u32 {
            dump.dump_type(type_id.into())?;
        }
    }

    write!(
        file,
        concat!("\n/* BPF kfuncs */\n", "#ifndef BPF_NO_KFUNC_PROTOTYPES\n",),
    )?;

    let mut kfuncs = vec![];
    let mut fastcalls = HashSet::new();

    let btf = Btf::from_vmlinux()?;

    for type_id in 1..btf.len() as u32 {
        let Some(t) = btf.type_by_id::<types::DeclTag<'_>>(type_id.into()) else {
            continue;
        };
        if t.component_index().is_some() {
            continue;
        }
        let Some(nt) = t.next_type() else {
            continue;
        };
        let Some(ft) = btf.type_by_id::<types::Func<'_>>(nt.type_id()) else {
            continue;
        };
        let Some(name) = t.name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with("bpf_kfunc") {
            kfuncs.push(ft);
        }
        if name.starts_with("bpf_fastcall") {
            fastcalls.insert(ft.type_id());
        }
    }

    for kfunc in kfuncs {
        let Some(name) = kfunc.name() else {
            continue;
        };
        let Some(nt) = kfunc.next_type() else {
            continue;
        };
        write!(file, "extern ")?;

        if fastcalls.contains(&kfunc.type_id()) {
            write!(file, "__bpf_fastcall ")?;
        }

        {
            let field_name = name.to_str().ok_or_else(|| {
                libbpf_rs::Error::from(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kfunc has invalid name",
                ))
            })?;

            let mut dump = BtfDump::new(&btf, &file)?;
            let opts = EmitTypeDeclOpts {
                field_name: Some(field_name.to_string()),
                ..Default::default()
            };
            dump.emit_type_decl(nt.type_id(), opts)?;
        }

        writeln!(file, " __weak __ksym;")?;
    }

    write!(file, "#endif\n\n")?;

    write!(
        file,
        concat!(
            "#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n",
            "#pragma clang attribute pop\n",
            "#endif\n",
            "\n",
            "#endif /* __VMLINUX_H__ */\n",
        ),
    )?;

    Ok(Some(parent_dir))
}

/// Concatenate a command and its arguments into a single string.
fn concat_command<C, A, S>(command: C, args: A) -> OsString
where
    C: AsRef<OsStr>,
    A: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter()
        .fold(command.as_ref().to_os_string(), |mut cmd, arg| {
            cmd.push(OsStr::new(" "));
            cmd.push(arg.as_ref());
            cmd
        })
}

/// Format a command with the given list of arguments as a string.
fn format_command(command: &Command) -> String {
    let prog = command.get_program();
    let args = command.get_args();

    concat_command(prog, args).to_string_lossy().to_string()
}

fn extract_clang_or_default(clang: Option<&Path>) -> PathBuf {
    match clang {
        Some(c) => c.into(),
        // Searches $PATH
        None => "clang".into(),
    }
}

/// Build the project, assuming necessary skeleton files have already
/// been generated.
pub fn build_project(
    manifest_path: Option<&Path>,
    clang: Option<&Path>,
    clang_args: Vec<OsString>,
) -> Result<()> {
    let (_target_dir, to_compile) = metadata::get(manifest_path)?;

    if !to_compile.is_empty() {
        debug!("Found bpf progs to compile:");
        for obj in &to_compile {
            debug!("\t{obj:?}");
        }
    } else if to_compile.is_empty() {
        bail!("Did not find any bpf progs to compile");
    }

    check_progs(&to_compile)?;

    let clang = extract_clang_or_default(clang);
    let () = to_compile.iter().try_for_each(|obj| {
        let stem = obj.path.file_stem().with_context(|| {
            format!(
                "Could not calculate destination name for obj={}",
                obj.path.display()
            )
        })?;

        let mut dest_name = stem.to_os_string();
        dest_name.push(".o");

        let mut dest_path = obj.out.to_path_buf();
        dest_path.push(&dest_name);
        fs::create_dir_all(&obj.out)?;

        BpfObjBuilder::default()
            .compiler(&clang)
            .compiler_args(&clang_args)
            .build(&obj.path, &dest_path)
            .with_context(|| {
                format!(
                    "failed to compile `{}` into `{}`",
                    obj.path.display(),
                    dest_path.display()
                )
            })
    })?;

    Ok(())
}
