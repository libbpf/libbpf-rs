use std::fs::{create_dir, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::{tempdir, TempDir};

use crate::build::build;

/// Creates a temporary directory and initializes a default cargo project inside.
///
/// Returns temp directory object to hold directory open, the path to the cargo
/// project directory, and the path to the project Cargo.toml
fn setup_temp_project() -> (TempDir, PathBuf, PathBuf) {
    let dir = tempdir().expect("failed to create tempdir");
    let proj_dir = dir.path().join("proj");

    // Create default rust project
    let status = Command::new("cargo")
        .arg("new")
        .arg("--bin")
        .arg(proj_dir.clone().into_os_string())
        .status()
        .expect("failed to create new cargo project");
    assert!(status.success());

    let proj_dir = dir.path().join("proj");
    let mut cargo_toml = proj_dir.clone();
    cargo_toml.push("Cargo.toml");

    (dir, proj_dir, cargo_toml)
}

#[test]
fn test_build_default() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // No bpf progs yet
    assert_ne!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), false),
        0
    );

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");
    assert_ne!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), false),
        0
    );

    // Add a prog
    let _prog_file =
        File::create(proj_dir.join("src/bpf/prog.c")).expect("failed to create prog file");

    assert_eq!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), false),
        0
    );

    // XXX validate generated object file
}

#[test]
fn test_build_custom() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add custom build rules
    let mut cargo_toml_file = OpenOptions::new()
        .append(true)
        .open(&cargo_toml)
        .expect("failed to open Cargo.toml");
    writeln!(cargo_toml_file, "[package.metadata.libbpf]").expect("write to Cargo.toml failed");
    writeln!(cargo_toml_file, r#"prog_dir = "src/other_bpf_dir""#)
        .expect("write to Cargo.toml failed");
    writeln!(cargo_toml_file, r#"target_dir = "other_target_dir""#)
        .expect("write to Cargo.toml failed");

    // No bpf progs yet
    assert_ne!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), false),
        0
    );

    // Add a prog
    create_dir(proj_dir.join("src/other_bpf_dir")).expect("failed to create prog dir");
    let _prog_file = File::create(proj_dir.join("src/other_bpf_dir/prog.c"))
        .expect("failed to create prog file");

    assert_eq!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), false),
        0
    );

    // XXX validate generated object file
}
