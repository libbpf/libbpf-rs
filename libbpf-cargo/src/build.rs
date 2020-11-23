use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package};
use regex::Regex;
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

            if !file_path.is_file() {
                return None;
            }

            // Only take files with extension ".bpf.c"
            if let Some(file_name) = file_path.as_path().file_name() {
                if file_name.to_string_lossy().ends_with(".bpf.c") {
                    return Some(UnprocessedProg {
                        package: package.name.clone(),
                        path: file_path,
                        out: out_dir.clone(),
                    });
                }
            }

            None
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

fn check_progs(progs: &[UnprocessedProg]) -> Result<()> {
    let mut set = HashSet::with_capacity(progs.len());
    for prog in progs {
        // OK to unwrap() file_name() b/c we already checked earlier that this is a valid file
        let dest = prog
            .out
            .as_path()
            .join(prog.path.as_path().file_name().unwrap());
        if !set.insert(dest) {
            bail!(
                "Duplicate prog={} detected",
                prog.path.as_path().file_name().unwrap().to_string_lossy()
            );
        }
    }

    Ok(())
}

fn extract_version(output: &str) -> Result<&str> {
    let re = Regex::new(r"clang\s+version\s+(?P<version_str>\d+\.\d+\.\d+)")?;
    let captures = re
        .captures(output)
        .ok_or_else(|| anyhow!("Failed to run regex on version string"))?;

    captures.name("version_str").map_or_else(
        || Err(anyhow!("Failed to find version capture group")),
        |v| Ok(v.as_str()),
    )
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
    let version_str = extract_version(&output)?;
    let version = Version::parse(version_str)?;
    if debug {
        println!("{} is version {}", clang.display(), version);
    }

    if version < Version::parse("10.0.0").unwrap() {
        bail!(
            "version {} is too old. Use --skip-clang-version-checks to skip verion check",
            version
        );
    }

    Ok(())
}

/// We're essentially going to run:
///
///     clang -g -O2 -target bpf -c -D__TARGET_ARCH_$(ARCH) runqslower.bpf.c -o runqslower.bpf.o
///
/// for each prog.
fn compile(debug: bool, progs: &[UnprocessedProg], clang: &Path) -> Result<()> {
    let arch = if std::env::consts::ARCH == "x86_64" {
        "x86"
    } else {
        std::env::consts::ARCH
    };

    for prog in progs {
        let dest_name = if let Some(f) = prog.path.as_path().file_stem() {
            let mut stem = f.to_os_string();
            stem.push(".o");
            stem
        } else {
            bail!(
                "Could not calculate destination name for prog={}",
                prog.path.as_path().display()
            );
        };
        let mut dest_path = prog.out.clone();
        dest_path.push(&dest_name);

        fs::create_dir_all(prog.out.as_path())?;

        if debug {
            println!("Building {}", prog.path.display());
        }

        let output = Command::new(clang.as_os_str())
            .arg("-g")
            .arg("-O2")
            .arg("-target")
            .arg("bpf")
            .arg("-c")
            .arg(format!("-D__TARGET_ARCH_{}", arch))
            .arg(prog.path.as_path().as_os_str())
            .arg("-o")
            .arg(dest_path)
            .output()?;

        if !output.status.success() {
            bail!(
                "Failed to compile prog={} with status={}\n \
                stdout=\n \
                {}\n \
                stderr=\n \
                {}\n",
                dest_name.to_string_lossy(),
                output.status,
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap()
            )
        }
    }

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

    if let Err(e) = check_progs(&to_compile) {
        eprintln!("{}", e);
        return 1;
    }

    if let Err(e) = check_clang(debug, clang, skip_clang_version_checks) {
        eprintln!("{} is invalid: {}", clang.display(), e);
        return 1;
    }

    match compile(debug, &to_compile, clang) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Failed to compile progs: {}", e);
            1
        }
    }
}

#[test]
fn test_extract_version() {
    let upstream_format = r"clang version 10.0.0
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /bin
";
    assert_eq!(extract_version(upstream_format).unwrap(), "10.0.0");

    let ubuntu_format = r"Ubuntu clang version 11.0.1-++20201121072624+973b95e0a84-1~exp1~20201121063303.19
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /bin
";
    assert_eq!(extract_version(ubuntu_format).unwrap(), "11.0.1");

    assert!(extract_version("askldfjwe").is_err());
    assert!(extract_version("my clang version 1.5").is_err());
}
