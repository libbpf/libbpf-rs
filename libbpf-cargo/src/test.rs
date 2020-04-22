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

/// Creates a temporary directory and initializes a cargo workspace with two projects
/// inside. Similar to `setup_temp_project`, just that here there's 2 projects>
///
///
/// Returns temp directory object to hold directory open, the path to the cargo
/// workspace directory, path to first project, and path to second project.
fn setup_temp_workspace() -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
    let dir = tempdir().expect("failed to create tempdir");
    let workspace_cargo_toml = dir.path().join("Cargo.toml");

    // Create first project
    let path_one = dir.path().join("one");
    let status_one = Command::new("cargo")
        .arg("new")
        .arg("--bin")
        .arg(path_one.clone().into_os_string())
        .status()
        .expect("failed to create new cargo project 1");
    assert!(status_one.success());

    // Create second project
    let path_two = dir.path().join("two");
    let status_two = Command::new("cargo")
        .arg("new")
        .arg("--bin")
        .arg(path_two.clone().into_os_string())
        .status()
        .expect("failed to create new cargo project 2");
    assert!(status_two.success());

    // Populate workspace Cargo.toml
    let mut cargo_toml_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&workspace_cargo_toml)
        .expect("failed to open workspace Cargo.toml");
    writeln!(cargo_toml_file, r#"[workspace]"#).expect("write to workspace Cargo.toml failed");
    writeln!(cargo_toml_file, r#"members = ["one", "two"]"#)
        .expect("write to workspace Cargo.toml failed");

    let dir_pathbuf = dir.path().to_path_buf();
    (dir, dir_pathbuf, workspace_cargo_toml, path_one, path_two)
}

#[test]
fn test_build_default() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // No bpf progs yet
    assert_ne!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");
    assert_ne!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );

    // Add a prog
    let _prog_file =
        File::create(proj_dir.join("src/bpf/prog.bpf.c")).expect("failed to create prog file");

    assert_eq!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
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
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );

    // Add a prog
    create_dir(proj_dir.join("src/other_bpf_dir")).expect("failed to create prog dir");
    let _prog_file = File::create(proj_dir.join("src/other_bpf_dir/prog.bpf.c"))
        .expect("failed to create prog file");

    assert_eq!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );

    // XXX validate generated object file
}

#[test]
fn test_enforce_file_extension() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");
    assert_ne!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );

    let _prog_file = File::create(proj_dir.join("src/bpf/prog_BAD_EXTENSION.c"))
        .expect("failed to create prog file");
    assert_ne!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );

    let _prog_file_again = File::create(proj_dir.join("src/bpf/prog_GOOD_EXTENSION.bpf.c"))
        .expect("failed to create prog file");
    assert_eq!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );
}

#[test]
fn test_build_workspace() {
    let (_dir, _, workspace_cargo_toml, proj_one_dir, proj_two_dir) = setup_temp_workspace();

    // No bpf progs yet
    assert_ne!(
        build(
            true,
            Some(&workspace_cargo_toml),
            Path::new("/bin/clang"),
            true
        ),
        0
    );

    // Create bpf prog for project one
    create_dir(proj_one_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_1 = File::create(proj_one_dir.join("src/bpf/prog1.bpf.c"))
        .expect("failed to create prog file 1");

    // Create bpf prog for project two
    create_dir(proj_two_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_2 = File::create(proj_two_dir.join("src/bpf/prog2.bpf.c"))
        .expect("failed to create prog file 2");

    assert_eq!(
        build(
            true,
            Some(&workspace_cargo_toml),
            Path::new("/bin/clang"),
            true
        ),
        0
    );
}

#[test]
fn test_build_workspace_collision() {
    let (_dir, _, workspace_cargo_toml, proj_one_dir, proj_two_dir) = setup_temp_workspace();

    // Create bpf prog for project one
    create_dir(proj_one_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_1 = File::create(proj_one_dir.join("src/bpf/prog.bpf.c"))
        .expect("failed to create prog file 1");

    // Create bpf prog for project two, same name as project one
    create_dir(proj_two_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_2 = File::create(proj_two_dir.join("src/bpf/prog.bpf.c"))
        .expect("failed to create prog file 2");

    assert_ne!(
        build(
            true,
            Some(&workspace_cargo_toml),
            Path::new("/bin/clang"),
            true
        ),
        0
    );
}
