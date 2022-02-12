use std::fs;
use std::path::Path;
use std::path::PathBuf;

use anyhow::{bail, Result};
use cargo_metadata::{MetadataCommand, Package};
use serde::Deserialize;
use serde_json::value::Value;

#[derive(Default, Deserialize)]
struct LibbpfPackageMetadata {
    prog_dir: Option<PathBuf>,
    target_dir: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
struct PackageMetadata {
    #[serde(default)]
    libbpf: LibbpfPackageMetadata,
}

#[derive(Debug, Clone)]
pub struct UnprocessedObj {
    /// Package the object belongs to
    pub package: String,
    /// Path to .c
    pub path: PathBuf,
    /// Where to place compiled object
    pub out: PathBuf,
    /// Object name (eg: `runqslower.bpf.c` -> `runqslower`)
    pub name: String,
}

fn get_package(
    debug: bool,
    package: &Package,
    workspace_target_dir: &Path,
) -> Result<Vec<UnprocessedObj>> {
    if debug {
        println!("Metadata for package={}", package.name);
        println!("\t{}", package.metadata);
    }

    let package_metadata = if package.metadata != Value::Null {
        let PackageMetadata { libbpf } = serde_json::from_value(package.metadata.clone())?;
        libbpf
    } else {
        LibbpfPackageMetadata::default()
    };

    // Respect custom target directories specified by package
    let mut package_root = package.manifest_path.clone().into_std_path_buf();
    // Remove "Cargo.toml"
    package_root.pop();
    if let Some(d) = package_metadata.prog_dir {
        if debug {
            println!("Custom prog_dir={}", d.to_string_lossy());
        }
        // Add requested path
        package_root.push(d);
    } else {
        // Add default path
        package_root.push("src/bpf");
    };

    // Respect custom target directories specified by package
    let mut target_dir = workspace_target_dir.to_path_buf();
    if let Some(d) = package_metadata.target_dir {
        if debug {
            println!("Custom target_dir={}", d.to_string_lossy());
        }

        // Add requested path
        target_dir.push(d);
    } else {
        // Add default path
        target_dir.push("bpf");
    };

    // Get an iterator to the input directory. If directory is missing,
    // skip the current project
    let dir_iter = match fs::read_dir(&package_root) {
        Ok(d) => d,
        Err(e) => {
            if let Some(ec) = e.raw_os_error() {
                // ENOENT == 2
                if ec == 2 {
                    return Ok(vec![]);
                } else {
                    bail!(
                        "Invalid directory: {}: {}",
                        package_root.to_string_lossy(),
                        e
                    );
                }
            } else {
                bail!(e);
            }
        }
    };

    Ok(dir_iter
        .filter_map(|file| {
            let path = match file {
                Ok(f) => f.path(),
                Err(_) => return None,
            };

            if !path.is_file() {
                return None;
            }

            // Only take files with extension ".bpf.c"
            if let Some(file_name) = path.as_path().file_name() {
                if file_name.to_string_lossy().ends_with(".bpf.c") {
                    let name = path
                        .as_path()
                        .file_stem() // remove ".c" suffix
                        .unwrap() // we already know it's a file
                        .to_string_lossy()
                        .rsplit_once('.')
                        .map(|f| f.0) // take portion of string prior to .bpf
                        .unwrap() // Already know it has enough '.'s
                        .to_string();

                    return Some(UnprocessedObj {
                        package: package.name.clone(),
                        out: target_dir.clone(),
                        path,
                        name,
                    });
                }
            }

            None
        })
        .collect())
}

/// Returns the `target_directory` and a list of objects to compile.
pub fn get(debug: bool, manifest_path: Option<&PathBuf>) -> Result<(PathBuf, Vec<UnprocessedObj>)> {
    let mut cmd = MetadataCommand::new();

    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    let metadata = match cmd.exec() {
        Ok(m) => m,
        Err(e) => bail!("Failed to get cargo metadata: {}", e),
    };

    if metadata.workspace_members.is_empty() {
        bail!("Failed to find targets")
    }

    let target_directory = metadata.target_directory.clone().into_std_path_buf();
    let mut v: Vec<UnprocessedObj> = Vec::new();
    for id in &metadata.workspace_members {
        for package in &metadata.packages {
            if id == &package.id {
                match &mut get_package(debug, package, &target_directory) {
                    Ok(vv) => v.append(vv),
                    Err(e) => bail!("Failed to process package={}, error={}", package.name, e),
                }
            }
        }
    }

    Ok((metadata.target_directory.into_std_path_buf(), v))
}
