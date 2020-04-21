use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package};
use semver::Version;
use serde::Deserialize;
use serde_json::value::Value;

#[derive(Debug)]
struct UnprocessedProg {
    /// Package the prog belongs to
    package: String,
    /// Path to .c
    path: PathBuf,
    /// Where to place compiled prog
    out: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum PackageMetadata {
    Libbpf(LibbpfPackageMetadata),
}

#[derive(Default, Deserialize)]
struct LibbpfPackageMetadata {
    prog_dir: Option<PathBuf>,
    target_dir: Option<PathBuf>,
}

fn locate_package(
    debug: bool,
    package: &Package,
    workspace_target_dir: &PathBuf,
) -> Result<Vec<UnprocessedProg>> {
    if debug {
        println!("Metadata for package={}", package.name);
        println!("\t{}", package.metadata);
    }

    let package_metadata = if package.metadata != Value::Null {
        let PackageMetadata::Libbpf(lpm) = serde_json::from_value(package.metadata.clone())?;
        lpm
    } else {
        LibbpfPackageMetadata::default()
    };

    // Respect custom target directories specified by package
    let mut package_root = package.manifest_path.clone();
    // Remove "Cargo.toml"
    package_root.pop();
    let in_dir = if let Some(d) = package_metadata.prog_dir {
        if debug {
            println!("Custom prog_dir={}", d.to_string_lossy());
        }
        // Add requested path
        package_root.push(d);
        package_root
    } else {
        // Add default path
        package_root.push("src/bpf");
        package_root
    };

    // Respect custom target directories specified by package
    let mut target_dir = workspace_target_dir.clone();
    let out_dir = if let Some(d) = package_metadata.target_dir {
        if debug {
            println!("Custom target_dir={}", d.to_string_lossy());
        }

        // Add requested path
        target_dir.push(d);
        target_dir
    } else {
        // Add default path
        target_dir.push("bpf");
        target_dir
    };

    // Get an iterator to the input directory. If directory is missing,
    // skip the current project
    let dir_iter = match fs::read_dir(&in_dir) {
        Ok(d) => d,
        Err(e) => {
            if let Some(ec) = e.raw_os_error() {
                // ENOENT == 2
                if ec == 2 {
                    return Ok(vec![]);
                } else {
                    bail!("Invalid directory: {}: {}", in_dir.to_string_lossy(), e);
                }
            } else {
                bail!(e);
            }
        }
    };

    Ok(dir_iter
        .filter_map(|file| {
            let file_path = match file {
                Ok(f) => f.path(),
                Err(_) => return None,
            };

            if file_path.is_file() {
                Some(UnprocessedProg {
                    package: package.name.clone(),
                    path: file_path,
                    out: out_dir.clone(),
                })
            } else {
                None
            }
        })
        .collect())
}

fn locate(debug: bool, metadata: &Metadata) -> Result<Vec<UnprocessedProg>> {
    if metadata.workspace_members.is_empty() {
        bail!("Failed to find targets")
    }

    let mut v: Vec<UnprocessedProg> = Vec::new();
    for id in &metadata.workspace_members {
        for package in &metadata.packages {
            if id == &package.id {
                match &mut locate_package(debug, &package, &metadata.target_directory) {
                    Ok(vv) => v.append(vv),
                    Err(e) => bail!("Failed to process package={}, error={}", package.name, e),
                }
            }
        }
    }

    Ok(v)
}

fn check_clang(debug: bool, clang: &Path, skip_version_checks: bool) -> Result<()> {
    let output = Command::new(clang.as_os_str()).arg("--version").output()?;

    if !output.status.success() {
        bail!("Failed to execute clang binary");
    }

    if skip_version_checks {
        return Ok(());
    }

    // Example output:
    //
    //     clang version 10.0.0
    //     Target: x86_64-pc-linux-gnu
    //     Thread model: posix
    //     InstalledDir: /bin
    //
    let output = String::from_utf8_lossy(&output.stdout);
    let version_str = output
        .split("\n")
        .nth(0)
        .ok_or(anyhow!("Invalid version format"))?
        .split(" ")
        .nth(2)
        .ok_or(anyhow!("Invalid version format"))?;

    let version = Version::parse(version_str)?;
    if debug {
        println!("{} is version {}", clang.display(), version);
    }

    if version < Version::parse("9.0.0").unwrap() {
        bail!(
            "version {} is too old. Use --skip-clang-version-checks to skip verion check",
            version
        );
    }

    Ok(())
}

fn compile(_progs: &[UnprocessedProg], _clang: &Path) -> Result<()> {
    // XXX implement
    Ok(())
}

pub fn build(
    debug: bool,
    manifest_path: Option<&PathBuf>,
    clang: &Path,
    skip_clang_version_checks: bool,
) -> i32 {
    let mut cmd = MetadataCommand::new();

    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    let metadata = match cmd.exec() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to get cargo metadata: {}", e);
            return 1;
        }
    };

    let to_compile = match locate(debug, &metadata) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    };

    if debug && !to_compile.is_empty() {
        println!("Found bpf progs to compile:");
        for prog in &to_compile {
            println!("\t{:?}", prog);
        }
    } else if to_compile.is_empty() {
        eprintln!("Did not find any bpf progs to compile");
        return 1;
    }

    if let Err(e) = check_clang(debug, clang, skip_clang_version_checks) {
        eprintln!("{} is invalid: {}", clang.display(), e);
        return 1;
    }

    match compile(&to_compile, clang) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Failed to compile progs: {}", e);
            1
        }
    }
}
