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
use log::debug;
use tempfile::tempdir;

use crate::metadata;
use crate::metadata::UnprocessedObj;

/// Contains information about a successful compilation.
#[derive(Debug)]
pub struct CompilationOutput {
    stderr: Vec<u8>,
}

impl CompilationOutput {
    /// Read the stderr from the compilation
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}


/// A helper for compiling BPF C code into a loadable BPF object file.
// TODO: Before exposing this functionality publicly, consider whether
//       we should support per-input-file compiler arguments.
#[derive(Debug)]
pub(crate) struct BpfObjBuilder {
    compiler: PathBuf,
    compiler_args: Vec<OsString>,
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

    /// We're essentially going to run:
    ///
    ///   clang -g -O2 -target bpf -c -D__TARGET_ARCH_$(ARCH) runqslower.bpf.c -o runqslower.bpf.o
    ///
    /// for each prog.
    fn compile_single(
        src: &Path,
        dst: &Path,
        compiler: &Path,
        compiler_args: &[OsString],
    ) -> Result<CompilationOutput> {
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

        Ok(CompilationOutput {
            stderr: output.stderr,
        })
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

    /// Build a BPF object file.
    pub fn build(&mut self, src: &Path, dst: &Path) -> Result<CompilationOutput> {
        let output = self.with_compiler_args(|compiler_args| {
            let output = Self::compile_single(src, dst, &self.compiler, compiler_args)
                .with_context(|| format!("failed to compile `{}`", src.display()))?;

            Ok(output)
        })?;

        // Compilation with clang may contain DWARF information that references
        // system specific and temporary paths. That can render our generated
        // skeletons unstable, potentially rendering them unsuitable for inclusion
        // in version control systems. So strip this information.
        strip_dwarf_info(dst)
            .with_context(|| format!("Failed to strip object file {}", dst.display()))?;

        Ok(output)
    }
}

impl Default for BpfObjBuilder {
    fn default() -> Self {
        Self {
            compiler: "clang".into(),
            compiler_args: Vec::new(),
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

/// Strip DWARF information from the provided BPF object file.
///
/// We rely on the `libbpf` linker here, which removes debug information as a
/// side-effect.
fn strip_dwarf_info(file: &Path) -> Result<()> {
    let mut temp_file = file.as_os_str().to_os_string();
    temp_file.push(".tmp");

    fs::rename(file, &temp_file).context("Failed to rename compiled BPF object file")?;

    let mut linker =
        libbpf_rs::Linker::new(file).context("Failed to instantiate libbpf object file linker")?;
    linker
        .add_file(temp_file)
        .context("Failed to add object file to BPF linker")?;
    linker.link().context("Failed to link object file")?;
    Ok(())
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

fn extract_clang_or_default(clang: Option<&PathBuf>) -> PathBuf {
    match clang {
        Some(c) => c.into(),
        // Searches $PATH
        None => "clang".into(),
    }
}

pub fn build_project(
    manifest_path: Option<&PathBuf>,
    clang: Option<&PathBuf>,
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
    let _output = to_compile
        .iter()
        .map(|obj| {
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
        })
        .collect::<Result<Vec<CompilationOutput>, _>>()?;

    Ok(())
}
