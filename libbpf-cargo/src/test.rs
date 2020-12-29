use std::fs::{create_dir, read, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use goblin::Object;
use tempfile::{tempdir, TempDir};

use crate::{build::build, make::make};

static VMLINUX: &'static str = include_str!("../test_data/vmlinux.h");
static BPF_HELPERS: &'static str = include_str!("../test_data/bpf_helpers.h");
static BPF_HELPER_DEFS: &'static str = include_str!("../test_data/bpf_helper_defs.h");

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
        .arg("--quiet")
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
        .arg("--quiet")
        .arg("--bin")
        .arg(path_one.clone().into_os_string())
        .status()
        .expect("failed to create new cargo project 1");
    assert!(status_one.success());

    // Create second project
    let path_two = dir.path().join("two");
    let status_two = Command::new("cargo")
        .arg("new")
        .arg("--quiet")
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

/// Validate if bpf object file at `path` is a valid bpf object file
fn validate_bpf_o(path: &Path) {
    let buffer = read(path)
        .expect(format!("failed to read object file at path={}", path.display()).as_str());
    match Object::parse(&buffer).expect("failed to parse object file") {
        Object::Elf(_) => (),
        _ => panic!("wrong object file format"),
    }
}

/// Returns the path to the local libbpf-rs
///
/// Warning: hacky! But necessary to run tests. We assume that the current working directory is
/// libbpf-cargo project root. Hopefully this is a cargo-provided invariant. I tried using the
/// file!() macro but it returns a relative path and seems even hackier to make work.
fn get_libbpf_rs_path() -> PathBuf {
    let cwd = std::env::current_dir().expect("failed to get cwd");

    Path::new(&cwd)
        .parent()
        .expect("failed to get parent of cwd")
        .join("libbpf-rs")
        .canonicalize()
        .expect("failed to canonicalize libbpf-rs")
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

    // Validate generated object file
    validate_bpf_o(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path());
}

#[test]
fn test_build_invalid_prog() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");

    // Add a prog
    let mut prog_file =
        File::create(proj_dir.join("src/bpf/prog.bpf.c")).expect("failed to create prog file");
    writeln!(prog_file, "1").expect("write to prog file failed");

    assert_ne!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );
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

    // Validate generated object file
    validate_bpf_o(
        proj_dir
            .as_path()
            .join("target/other_target_dir/prog.bpf.o")
            .as_path(),
    );
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

#[test]
fn test_make_basic() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");

    // Add a prog
    let _prog_file =
        File::create(proj_dir.join("src/bpf/prog.bpf.c")).expect("failed to create prog file");

    assert_eq!(
        make(
            true,
            Some(&cargo_toml),
            Path::new("/bin/clang"),
            true,
            true,
            Vec::new(),
            None,
        ),
        0
    );

    // Validate generated object file
    validate_bpf_o(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path());

    // Check that skeleton exists (other tests will check for skeleton validity)
    assert!(proj_dir
        .as_path()
        .join("src/bpf/prog.skel.rs")
        .as_path()
        .exists());
}

#[test]
fn test_make_workspace() {
    let (_dir, workspace_dir, workspace_cargo_toml, proj_one_dir, proj_two_dir) =
        setup_temp_workspace();

    // Create bpf prog for project one
    create_dir(proj_one_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_1 = File::create(proj_one_dir.join("src/bpf/prog1.bpf.c"))
        .expect("failed to create prog file 1");

    // Create bpf prog for project two, same name as project one
    create_dir(proj_two_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_2 = File::create(proj_two_dir.join("src/bpf/prog2.bpf.c"))
        .expect("failed to create prog file 2");

    assert_eq!(
        make(
            true,
            Some(&workspace_cargo_toml),
            Path::new("/bin/clang"),
            true,
            true,
            Vec::new(),
            None
        ),
        0
    );

    // Validate generated object files
    validate_bpf_o(
        workspace_dir
            .as_path()
            .join("target/bpf/prog1.bpf.o")
            .as_path(),
    );
    validate_bpf_o(
        workspace_dir
            .as_path()
            .join("target/bpf/prog2.bpf.o")
            .as_path(),
    );

    // Check that skeleton exists (other tests will check for skeleton validity)
    assert!(proj_one_dir
        .as_path()
        .join("src/bpf/prog1.skel.rs")
        .as_path()
        .exists());
    assert!(proj_two_dir
        .as_path()
        .join("src/bpf/prog2.skel.rs")
        .as_path()
        .exists());
}

#[test]
fn test_skeleton_empty_source() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");

    // Add a prog
    let _prog_file =
        File::create(proj_dir.join("src/bpf/prog.bpf.c")).expect("failed to create prog file");

    assert_eq!(
        make(
            true,
            Some(&cargo_toml),
            Path::new("/bin/clang"),
            true,
            true,
            Vec::new(),
            None
        ),
        0
    );

    let mut cargo = OpenOptions::new()
        .append(true)
        .open(&cargo_toml)
        .expect("failed to open Cargo.toml");

    // Make test project use our development libbpf-rs version
    writeln!(
        cargo,
        r#"
        libbpf-rs = {{ path = "{}" }}
        "#,
        get_libbpf_rs_path().as_path().display()
    )
    .expect("failed to write to Cargo.toml");

    let mut source = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(proj_dir.join("src/main.rs"))
        .expect("failed to open main.rs");

    write!(
        source,
        r#"
        mod bpf;
        use bpf::*;

        fn main() {{
            let mut builder = ProgSkelBuilder::default();
            let _skel = builder
                .open()
                .expect("failed to open skel")
                .load()
                .expect("failed to load skel");
        }}
        "#,
    )
    .expect("failed to write to main.rs");

    let status = Command::new("cargo")
        .arg("build")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(cargo_toml.into_os_string())
        .status()
        .expect("failed to spawn cargo-build");
    assert!(status.success());
}

#[test]
fn test_skeleton_basic() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");

    // Add a prog
    let mut prog = OpenOptions::new()
        .write(true)
        .create(true)
        .open(proj_dir.join("src/bpf/prog.bpf.c"))
        .expect("failed to open prog.bpf.c");

    write!(
        prog,
        r#"
        #include "vmlinux.h"
        #include "bpf_helpers.h"

        struct {{
                __uint(type, BPF_MAP_TYPE_HASH);
                __uint(max_entries, 1024);
                __type(key, u32);
                __type(value, u64);
        }} mymap SEC(".maps");

        SEC("kprobe/foo")
        int this_is_my_prog(u64 *ctx)
        {{
                return 0;
        }}
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    let mut vmlinux = OpenOptions::new()
        .create(true)
        .write(true)
        .open(proj_dir.join("src/bpf/vmlinux.h"))
        .expect("failed to open vmlinux.h");
    write!(vmlinux, "{}", VMLINUX).expect("failed to write vmlinux.h");

    let mut bpf_helpers = OpenOptions::new()
        .create(true)
        .write(true)
        .open(proj_dir.join("src/bpf/bpf_helpers.h"))
        .expect("failed to open bpf_helpers.h");
    write!(bpf_helpers, "{}", BPF_HELPERS).expect("failed to write bpf_helpers.h");

    let mut bpf_helper_defs = OpenOptions::new()
        .create(true)
        .write(true)
        .open(proj_dir.join("src/bpf/bpf_helper_defs.h"))
        .expect("failed to open bpf_helper_defs.h");
    write!(bpf_helper_defs, "{}", BPF_HELPER_DEFS).expect("failed to write bpf_helper_defs.h");

    assert_eq!(
        make(
            true,
            Some(&cargo_toml),
            Path::new("/bin/clang"),
            true,
            true,
            Vec::new(),
            None
        ),
        0
    );

    let mut cargo = OpenOptions::new()
        .append(true)
        .open(&cargo_toml)
        .expect("failed to open Cargo.toml");

    // Make test project use our development libbpf-rs version
    writeln!(
        cargo,
        r#"
        libbpf-rs = {{ path = "{}" }}
        "#,
        get_libbpf_rs_path().as_path().display()
    )
    .expect("failed to write to Cargo.toml");

    let mut source = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(proj_dir.join("src/main.rs"))
        .expect("failed to open main.rs");

    write!(
        source,
        r#"
        mod bpf;
        use bpf::*;

        fn main() {{
            let mut builder = ProgSkelBuilder::default();
            let mut open_skel = builder
                .open()
                .expect("failed to open skel");

            // Check that we can grab handles to open maps/progs
            let _open_map = open_skel.maps().mymap();
            let _open_prog = open_skel.progs().this_is_my_prog();

            let mut skel = open_skel
                .load()
                .expect("failed to load skel");

            // Check that we can grab handles to loaded maps/progs
            let _map = skel.maps().mymap();
            let _prog = skel.progs().this_is_my_prog();

            // Check that attach() is generated
            skel.attach().expect("failed to attach progs");

            // Check that Option<Link> field is generated
            let _mylink = skel.links.this_is_my_prog.unwrap();
        }}
        "#,
    )
    .expect("failed to write to main.rs");

    let status = Command::new("cargo")
        .arg("build")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(cargo_toml.into_os_string())
        .status()
        .expect("failed to spawn cargo-build");
    assert!(status.success());
}
