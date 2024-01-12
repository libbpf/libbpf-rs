#![allow(clippy::let_unit_value)]

use std::env;
use std::env::consts::ARCH;
use std::ffi::OsStr;
use std::fs::read_dir;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::ops::Deref as _;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;


/// Format a command with the given list of arguments as a string.
fn format_command<C, A, S>(command: C, args: A) -> String
where
    C: AsRef<OsStr>,
    A: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter().fold(
        command.as_ref().to_string_lossy().into_owned(),
        |mut cmd, arg| {
            cmd += " ";
            cmd += arg.as_ref().to_string_lossy().deref();
            cmd
        },
    )
}

/// Run a command with the provided arguments.
fn run<C, A, S>(command: C, args: A) -> Result<()>
where
    C: AsRef<OsStr>,
    A: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let instance = Command::new(command.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .env_clear()
        .envs(env::vars().filter(|(k, _)| k == "PATH"))
        .args(args.clone())
        .output()
        .map_err(|err| {
            Error::new(
                ErrorKind::Other,
                format!(
                    "failed to run `{}`: {err}",
                    format_command(command.as_ref(), args.clone())
                ),
            )
        })?;

    if !instance.status.success() {
        let code = if let Some(code) = instance.status.code() {
            format!(" ({code})")
        } else {
            " (terminated by signal)".to_string()
        };

        let stderr = String::from_utf8_lossy(&instance.stderr);
        let stderr = stderr.trim_end();
        let stderr = if !stderr.is_empty() {
            format!(": {stderr}")
        } else {
            String::new()
        };

        Err(Error::new(
            ErrorKind::Other,
            format!(
                "`{}` reported non-zero exit-status{code}{stderr}",
                format_command(command, args)
            ),
        ))
    } else {
        Ok(())
    }
}

fn adjust_mtime(path: &Path) -> Result<()> {
    // Note that `OUT_DIR` is only present at runtime.
    let out_dir = env::var("OUT_DIR").unwrap();
    // The $OUT_DIR/output file is (in current versions of Cargo [as of
    // 1.69]) the file containing the reference time stamp that Cargo
    // checks to determine whether something is considered outdated and
    // in need to be rebuild. It's an implementation detail, yes, but we
    // don't rely on it for anything essential.
    let output = Path::new(&out_dir)
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::Other, "OUT_DIR has no parent"))?
        .join("output");

    if !output.exists() {
        // The file may not exist for legitimate reasons, e.g., when we
        // build for the very first time. If there is not reference there
        // is nothing for us to do, so just bail.
        return Ok(())
    }

    let () = run(
        "touch",
        [
            "-m".as_ref(),
            "--reference".as_ref(),
            output.as_os_str(),
            path.as_os_str(),
        ],
    )?;
    Ok(())
}

/// Compile `src` into `dst` using the provided compiler.
fn compile(compiler: &str, src: &Path, dst: &Path, options: &[&str]) {
    let dst = src.with_file_name(dst);
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());

    let () = run(
        compiler,
        options
            .iter()
            .map(OsStr::new)
            .chain([src.as_os_str(), "-o".as_ref(), dst.as_os_str()]),
    )
    .unwrap_or_else(|err| panic!("failed to run `{compiler}`: {err}"));

    let () = adjust_mtime(&dst).unwrap();
}

/// Extract vendored libbpf header files into a directory.
#[cfg(feature = "generate-test-files")]
fn extract_libbpf_headers(target_dir: &Path) {
    use std::fs;
    use std::fs::OpenOptions;
    use std::io::Write;

    let dir = target_dir.join("bpf");
    let () = fs::create_dir_all(&dir).unwrap();
    for (filename, contents) in libbpf_sys::API_HEADERS.iter() {
        let path = dir.as_path().join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }
}

#[cfg(feature = "generate-test-files")]
fn with_bpf_headers<F>(f: F)
where
    F: FnOnce(&Path),
{
    use tempfile::tempdir;

    let header_parent_dir = tempdir().unwrap();
    let () = extract_libbpf_headers(header_parent_dir.path());
    let () = f(header_parent_dir.path());
}

#[cfg(not(feature = "generate-test-files"))]
fn with_bpf_headers<F>(_f: F)
where
    F: FnOnce(&Path),
{
    unimplemented!()
}

/// Prepare the various test files.
fn prepare_test_files(crate_root: &Path) {
    let bin_dir = crate_root.join("tests").join("bin");
    let src_dir = bin_dir.join("src");
    let include = crate_root.join("../vmlinux/include").join(ARCH);

    with_bpf_headers(|bpf_hdr_dir| {
        for result in read_dir(&src_dir).unwrap() {
            let entry = result.unwrap();
            let src = entry.file_name();
            let obj = Path::new(&src).with_extension("o");
            let src = src_dir.join(&src);
            let dst = bin_dir.join(obj);
            let arch = option_env!("CARGO_CFG_TARGET_ARCH").unwrap_or(ARCH);
            let arch = match arch {
                "x86_64" => "x86",
                "aarch64" => "arm64",
                "powerpc64" => "powerpc",
                "s390x" => "s390",
                x => x,
            };

            compile(
                "clang",
                &src,
                &dst,
                &[
                    "-g",
                    "-O2",
                    "-target",
                    "bpf",
                    "-c",
                    "-I",
                    include.to_str().unwrap(),
                    "-I",
                    &format!("{}", bpf_hdr_dir.display()),
                    "-D",
                    &format!("__TARGET_ARCH_{arch}"),
                ],
            );
        }
    })
}

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    if cfg!(feature = "generate-test-files") && !cfg!(feature = "dont-generate-test-files") {
        prepare_test_files(crate_dir.as_ref());
    }
}
