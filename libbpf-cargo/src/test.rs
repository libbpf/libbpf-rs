use std::{
    convert::TryInto,
    fs::{create_dir, read, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use goblin::Object;
use memmap2::Mmap;
use tempfile::{tempdir, NamedTempFile, TempDir};

use crate::{btf, btf::Btf, build::build, make::make, SkeletonBuilder};

static VMLINUX: &str = include_str!("../test_data/vmlinux.h");

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
        .arg(proj_dir.into_os_string())
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
        .unwrap_or_else(|_| panic!("failed to read object file at path={}", path.display()));
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

/// Add vmlinux header into `project`'s src/bpf dir
fn add_vmlinux_header(project: &Path) {
    let mut vmlinux = OpenOptions::new()
        .create(true)
        .write(true)
        .open(project.join("src/bpf/vmlinux.h"))
        .expect("failed to open vmlinux.h");
    write!(vmlinux, "{}", VMLINUX).expect("failed to write vmlinux.h");
}

#[test]
fn test_build_default() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // No bpf progs yet
    build(true, Some(&cargo_toml), None, true).unwrap_err();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");
    build(true, Some(&cargo_toml), None, true).unwrap_err();

    // Add a prog
    let _prog_file =
        File::create(proj_dir.join("src/bpf/prog.bpf.c")).expect("failed to create prog file");

    build(true, Some(&cargo_toml), None, true).unwrap();

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

    build(true, Some(&cargo_toml), None, true).unwrap_err();
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
    build(true, Some(&cargo_toml), None, true).unwrap_err();

    // Add a prog
    create_dir(proj_dir.join("src/other_bpf_dir")).expect("failed to create prog dir");
    let _prog_file = File::create(proj_dir.join("src/other_bpf_dir/prog.bpf.c"))
        .expect("failed to create prog file");

    build(true, Some(&cargo_toml), None, true).unwrap();

    // Validate generated object file
    validate_bpf_o(
        proj_dir
            .as_path()
            .join("target/other_target_dir/prog.bpf.o")
            .as_path(),
    );
}

#[test]
fn test_unknown_metadata_section() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add a metadata section that isn't for libbpf.
    let mut cargo_toml_file = OpenOptions::new()
        .append(true)
        .open(&cargo_toml)
        .expect("failed to open Cargo.toml");
    let deb_metadata = r#"[package.metadata.deb]
    prog_dir = "some value that should be ignored"
    some_other_val = true
    "#;
    cargo_toml_file
        .write_all(deb_metadata.as_bytes())
        .expect("write to Cargo.toml failed");

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");
    build(true, Some(&cargo_toml), None, true).unwrap_err();

    // Add a prog
    let _prog_file =
        File::create(proj_dir.join("src/bpf/prog.bpf.c")).expect("failed to create prog file");

    build(true, Some(&cargo_toml), None, true).unwrap();

    // Validate generated object file
    validate_bpf_o(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path());
}

#[test]
fn test_enforce_file_extension() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");
    build(true, Some(&cargo_toml), None, true).unwrap_err();

    let _prog_file = File::create(proj_dir.join("src/bpf/prog_BAD_EXTENSION.c"))
        .expect("failed to create prog file");
    build(true, Some(&cargo_toml), None, true).unwrap_err();

    let _prog_file_again = File::create(proj_dir.join("src/bpf/prog_GOOD_EXTENSION.bpf.c"))
        .expect("failed to create prog file");
    build(true, Some(&cargo_toml), None, true).unwrap();
}

#[test]
fn test_build_workspace() {
    let (_dir, _, workspace_cargo_toml, proj_one_dir, proj_two_dir) = setup_temp_workspace();

    // No bpf progs yet
    build(true, Some(&workspace_cargo_toml), None, true).unwrap_err();

    // Create bpf prog for project one
    create_dir(proj_one_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_1 = File::create(proj_one_dir.join("src/bpf/prog1.bpf.c"))
        .expect("failed to create prog file 1");

    // Create bpf prog for project two
    create_dir(proj_two_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_2 = File::create(proj_two_dir.join("src/bpf/prog2.bpf.c"))
        .expect("failed to create prog file 2");

    build(true, Some(&workspace_cargo_toml), None, true).unwrap();
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

    build(true, Some(&workspace_cargo_toml), None, true).unwrap_err();
}

#[test]
fn test_make_basic() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");

    // Add a prog
    let _prog_file =
        File::create(proj_dir.join("src/bpf/prog.bpf.c")).expect("failed to create prog file");

    make(true, Some(&cargo_toml), None, true, true, Vec::new(), None).unwrap();

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

    make(
        true,
        Some(&workspace_cargo_toml),
        None,
        true,
        true,
        Vec::new(),
        None,
    )
    .unwrap();

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

    make(true, Some(&cargo_toml), None, true, true, Vec::new(), None).unwrap();

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
            let builder = ProgSkelBuilder::default();
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
        #include <bpf/bpf_helpers.h>

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
    add_vmlinux_header(&proj_dir);

    make(true, Some(&cargo_toml), None, true, true, Vec::new(), None).unwrap();

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
            let builder = ProgSkelBuilder::default();
            let mut open_skel = builder
                .open()
                .expect("failed to open skel");

            // Check that we can grab handles to open maps/progs
            let _open_map = open_skel.maps().mymap();
            let _open_prog = open_skel.progs().this_is_my_prog();
            let _open_map_mut = open_skel.maps_mut().mymap();
            let _open_prog_mut = open_skel.progs_mut().this_is_my_prog();

            let mut skel = open_skel
                .load()
                .expect("failed to load skel");

            // Check that we can grab handles to loaded maps/progs
            let _map = skel.maps().mymap();
            let _prog = skel.progs().this_is_my_prog();
            let _map_mut = skel.maps_mut().mymap();
            let _prog_mut = skel.progs_mut().this_is_my_prog();

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

#[test]
fn test_skeleton_generate_datasec_static() {
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
        #include <bpf/bpf_helpers.h>

        SEC("kprobe/foo")
        int this_is_my_prog(u64 *ctx)
        {{
                bpf_printk("this should not cause an error");
                return 0;
        }}
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_vmlinux_header(&proj_dir);

    make(true, Some(&cargo_toml), None, true, true, Vec::new(), None).unwrap();
}

#[test]
fn test_skeleton_datasec() {
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
        #include <bpf/bpf_helpers.h>

        int myglobal = 0;
        void * const myconst = 0;

        SEC("kprobe/foo")
        int this_is_my_prog(u64 *ctx)
        {{
                return 0;
        }}
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_vmlinux_header(&proj_dir);

    make(true, Some(&cargo_toml), None, true, true, Vec::new(), None).unwrap();

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
            let builder = ProgSkelBuilder::default();
            let mut open_skel = builder
                .open()
                .expect("failed to open skel");

            // Check that we set rodata vars before load
            open_skel.rodata().myconst = std::ptr::null_mut();

            // We can always set bss vars
            open_skel.bss().myglobal = 42;

            let mut skel = open_skel
                .load()
                .expect("failed to load skel");

            // We can always set bss vars
            skel.bss().myglobal = 24;

            // Read only for rodata after load
            let _rodata: &prog_rodata_types::rodata = skel.rodata();
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
fn test_skeleton_builder_basic() {
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
        #include <bpf/bpf_helpers.h>

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
    add_vmlinux_header(&proj_dir);

    // Generate skeleton file
    let skel = NamedTempFile::new().unwrap();
    SkeletonBuilder::new()
        .source(proj_dir.join("src/bpf/prog.bpf.c"))
        .debug(true)
        .build_and_generate(skel.path())
        .unwrap();

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
        #[path = "{skel_path}"]
        mod skel;
        use skel::*;

        fn main() {{
            let builder = ProgSkelBuilder::default();
            let mut open_skel = builder
                .open()
                .expect("failed to open skel");

            // Check that we can grab handles to open maps/progs
            let _open_map = open_skel.maps().mymap();
            let _open_prog = open_skel.progs().this_is_my_prog();
            let _open_map_mut = open_skel.maps_mut().mymap();
            let _open_prog_mut = open_skel.progs_mut().this_is_my_prog();


            let mut skel = open_skel
                .load()
                .expect("failed to load skel");

            // Check that we can grab handles to loaded maps/progs
            let _map = skel.maps().mymap();
            let _prog = skel.progs().this_is_my_prog();
            let _map_mut = skel.maps_mut().mymap();
            let _prog_mut = skel.progs_mut().this_is_my_prog();

            // Check that attach() is generated
            skel.attach().expect("failed to attach progs");

            // Check that Option<Link> field is generated
            let _mylink = skel.links.this_is_my_prog.unwrap();
        }}
        "#,
        skel_path = skel.path().display(),
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
fn test_skeleton_builder_clang_opts() {
    let (_dir, proj_dir, _cargo_toml) = setup_temp_project();

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
        #ifndef PURPOSE
        #error "what is my purpose?"
        #endif
        "#,
    )
    .expect("failed to write prog.bpf.c");

    let skel = NamedTempFile::new().unwrap();

    // Should fail b/c `PURPOSE` not defined
    SkeletonBuilder::new()
        .source(proj_dir.join("src/bpf/prog.bpf.c"))
        .debug(true)
        .clang("clang")
        .build_and_generate(skel.path())
        .unwrap_err();

    // Should succeed b/c we defined the macro
    SkeletonBuilder::new()
        .source(proj_dir.join("src/bpf/prog.bpf.c"))
        .debug(true)
        .clang("clang")
        .clang_args("-DPURPOSE=you_pass_the_butter")
        .build_and_generate(skel.path())
        .unwrap();
}

#[test]
fn test_skeleton_builder_arrays_ptrs() {
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
        #include <bpf/bpf_helpers.h>

        struct inner {{
            int a;
        }};

        struct mystruct {{
            int x;
            struct {{
                int b;
            }} y[2];
            struct inner z[2];
        }};

        const volatile struct mystruct my_array[1] = {{ {{0}} }};
        struct mystruct * const my_ptr = NULL;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_vmlinux_header(&proj_dir);

    make(true, Some(&cargo_toml), None, true, true, Vec::new(), None).unwrap();

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
            let builder = ProgSkelBuilder::default();
            let mut open_skel = builder
                .open()
                .expect("failed to open skel");

            // That everything exists and compiled okay
            let _ = open_skel.rodata().my_array[0].x;
            let _ = open_skel.rodata().my_array[0].y[1].b;
            let _ = open_skel.rodata().my_array[0].z[0].a;
            let _ = open_skel.rodata().my_ptr;
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

// -- TEST RUST GENERATION OF BTF PROGRAMS --

/// Searches the Btf struct for a BtfType
/// returns type identifier <u32> if found
/// fails calling test if not found, or if duplicates exist
///
/// usage: -- search for basic struct/union/enum with exact match to name
///        find_type_in_btf!(<Btf to search in>,
///                          <BtfType to search for>,
///                          <&str search name>);
///        eg:
///        let my_type = find_type_in_btf!(btf, Struct, "name");
///    or: -- search for basic struct/union/enum/var containing name substring
///        find_type_in_btf!(<Btf to search in>,
///                          <BtfType to search for>,
///                          <&str search name>,
///                          true);
///        eg:
///        let my_type = find_type_in_btf!(btf, Datasec, "bss", true);
///    or: -- search for a Variable name in a Datasec -- exact match
///        find_type_in_btf!(<Btf to search in>,
///                          Var,
///                          <&str search name>);
///        eg
///        let let my_type = find_type_in_btf!(btf, Var, "name");
macro_rules! find_type_in_btf {
    // match for a named BtfType::Var inside all vars in a Datasec
    ($btf:ident, Var, $name:literal) => {{
        let mut asserted_type: Option<u32> = None;
        for ty in $btf.types().iter() {
            match ty {
                btf::BtfType::Datasec(t) => {
                    for var in &t.vars {
                        let var_ty = $btf
                            .type_by_id(var.type_id)
                            .expect("Failed to lookup datasec var");
                        match var_ty {
                            btf::BtfType::Var(t) => {
                                if t.name == $name {
                                    assert!(asserted_type.is_none()); // No duplicates
                                    asserted_type = Some(var.type_id);
                                }
                            }
                            _ => panic!("Datasec var didn't point to a var. Instead: {}", var_ty),
                        }
                    }
                }
                _ => (),
            }
        }
        asserted_type.unwrap()
    }};

    // match for a named BtfType.
    ($btf:ident, $btf_type:ident, $name:literal) => {{
        find_type_in_btf!($btf, $btf_type, $name, false)
    }};

    // match for a named BtfType.
    // If substr == true then test for substring rather than exact match
    ($btf:ident, $btf_type:ident, $name:literal, $substr:expr) => {{
        let mut asserted_type: Option<u32> = None;

        for (idx, ty) in $btf.types().iter().enumerate() {
            match ty {
                btf::BtfType::$btf_type(t) => {
                    let found = if $substr {
                        t.name.contains($name)
                    } else {
                        t.name == $name
                    };

                    if found {
                        assert!(asserted_type.is_none()); // No duplicates
                        asserted_type = Some(idx.try_into().unwrap());
                    }
                }
                _ => (),
            }
        }
        asserted_type.unwrap()
    }};
}

/// Boiler plate code to build a struct Btf from a raw string
/// returns struct Btf if able to compile
/// fails calling test if unable to compile
fn build_btf_prog(prog_text: &str) -> Btf {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");

    // Add a prog
    let mut prog = OpenOptions::new()
        .write(true)
        .create(true)
        .open(proj_dir.join("src/bpf/prog.bpf.c"))
        .expect("failed to open prog.bpf.c");

    write!(prog, "{}", prog_text).expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_vmlinux_header(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), None, true).expect("failed to compile");

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(!btf.types().is_empty());

    btf
}

/// Tests the type_definition output of a type_id against a given expected output
/// Will trim leading and trailing whitespace from both expected output and from
/// the generated type_definition
/// fails calling text if type_definition does not match expected_output
fn assert_definition(btf: &Btf, btf_item: u32, expected_output: &str) {
    let actual_output = btf
        .type_definition(btf_item)
        .expect("Failed to generate struct Foo defn");
    let ao = actual_output.trim_end().trim_start();
    let eo = expected_output.trim_end().trim_start();

    println!("---------------");
    println!("expected output");
    println!("---------------");
    println!("{}", eo);
    println!("-------------");
    println!("actual output");
    println!("-------------");
    println!("{}", ao);

    assert_eq!(eo, ao);
}

#[test]
fn test_btf_dump_basic() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

int myglobal = 1;

struct Foo {
    int x;
    char y[10];
    void *z;
};

struct Foo foo = {{0}};
"#;

    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub y: [i8; 10],
    pub z: *mut std::ffi::c_void,
}
"#;

    let btf = build_btf_prog(prog_text);

    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");
    let foo = find_type_in_btf!(btf, Var, "foo");
    let myglobal = find_type_in_btf!(btf, Var, "myglobal");

    assert_eq!(
        "Foo",
        btf.type_declaration(foo)
            .expect("Failed to generate foo decl")
    );
    assert_eq!(
        "i32",
        btf.type_declaration(myglobal)
            .expect("Failed to generate myglobal decl")
    );

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_basic_long_array() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

int myglobal = 1;

struct Foo {
    int x;
    char y[33];
    void *z;
};

struct Foo foo = {{0}};
"#;

    let expected_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub y: [i8; 33],
    pub z: *mut std::ffi::c_void,
}
impl Default for Foo {
    fn default() -> Self {
        Foo {
            x: i32::default(),
            y: [i8::default(); 33],
            z: std::ptr::null_mut(),
        }
    }
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our types
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");
    let foo = find_type_in_btf!(btf, Var, "foo");
    let myglobal = find_type_in_btf!(btf, Var, "myglobal");

    assert_eq!(
        "Foo",
        btf.type_declaration(foo)
            .expect("Failed to generate foo decl")
    );
    assert_eq!(
        "i32",
        btf.type_declaration(myglobal)
            .expect("Failed to generate myglobal decl")
    );

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_struct_definition() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Bar {
    u16 x;
};

struct Foo {
    int *ip;
    int **ipp;
    struct Bar bar;
    struct Bar *pb;
    volatile u64 v;
    const volatile s64 cv;
    char * restrict r;
};

struct Foo foo;
"#;

    // Note how there's 6 bytes of padding. It's not necessary on 64 bit archs but
    // we've assumed 32 bit arch during padding generation.
    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub ip: *mut i32,
    pub ipp: *mut *mut i32,
    pub bar: Bar,
    __pad_18: [u8; 6],
    pub pb: *mut Bar,
    pub v: u64,
    pub cv: i64,
    pub r: *mut i8,
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Bar {
    pub x: u16,
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_struct_definition_long_array() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Bar {
    u16 x;
    u16 y[33];
};

struct Foo {
    int *ip;
    int **ipp;
    struct Bar bar;
    struct Bar *pb;
    volatile u64 v;
    const volatile s64 cv;
    char * restrict r;
};

struct Foo foo;
"#;

    // Note how there's 6 bytes of padding. It's not necessary on 64 bit archs but
    // we've assumed 32 bit arch during padding generation.
    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub ip: *mut i32,
    pub ipp: *mut *mut i32,
    pub bar: Bar,
    __pad_84: [u8; 4],
    pub pb: *mut Bar,
    pub v: u64,
    pub cv: i64,
    pub r: *mut i8,
}
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Bar {
    pub x: u16,
    pub y: [u16; 33],
}
impl Default for Bar {
    fn default() -> Self {
        Bar {
            x: u16::default(),
            y: [u16::default(); 33],
        }
    }
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_packed_struct() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    int x;
    char y;
    __s32 z[2];
} __attribute__((packed));

struct Foo foo;
"#;

    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C, packed)]
pub struct Foo {
    pub x: i32,
    pub y: i8,
    pub z: [i32; 2],
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_packed_struct_long_array() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    int x;
    char y;
    __s32 z[33];
} __attribute__((packed));

struct Foo foo;
"#;

    let expected_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct Foo {
    pub x: i32,
    pub y: i8,
    pub z: [i32; 33],
}
impl Default for Foo {
    fn default() -> Self {
        Foo {
            x: i32::default(),
            y: i8::default(),
            z: [i32::default(); 33],
        }
    }
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_bitfield_struct_fails() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    unsigned int x: 2;
    unsigned int y: 3;
};

struct Foo foo;
"#;
    let btf = build_btf_prog(prog_text);

    // Find our struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert!(btf.type_definition(struct_foo).is_err());
}

#[test]
fn test_btf_dump_definition_enum() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum Foo {
    Zero = 0,
    One,
    seven = 7,
};

enum Foo foo;
"#;

    let expected_output = r#"
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum Foo {
    Zero = 0,
    One = 1,
    seven = 7,
}
impl Default for Foo {
    fn default() -> Self {
        Foo::Zero
    }
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let enum_foo = find_type_in_btf!(btf, Enum, "Foo");

    assert_definition(&btf, enum_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_union() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

union Foo {
    int x;
    __u32 y;
    char z[128];
};

union Foo foo;
"#;

    let expected_output = r#"
#[derive(Copy, Clone)]
#[repr(C)]
pub union Foo {
    pub x: i32,
    pub y: u32,
    pub z: [i8; 128],
}
impl std::fmt::Debug for Foo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(???)")
    }
}
impl Default for Foo {
    fn default() -> Self {
        Foo {
            x: i32::default(),
        }
    }
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let union_foo = find_type_in_btf!(btf, Union, "Foo");

    assert_definition(&btf, union_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_shared_dependent_types() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Bar {
    u16 x;
};

struct Foo {
    struct Bar bar;
    struct Bar bartwo;
};

struct Foo foo;
"#;

    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub bar: Bar,
    pub bartwo: Bar,
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Bar {
    pub x: u16,
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_datasec() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    int x;
    char y[10];
    void *z;
};

struct Foo foo = {0};

const int myconstglobal = 0;
"#;

    let bss_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct bss {
    pub foo: Foo,
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub y: [i8; 10],
    pub z: *mut std::ffi::c_void,
}
"#;

    let rodata_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct rodata {
    pub myconstglobal: i32,
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find out types
    let bss = find_type_in_btf!(btf, Datasec, "bss", true);
    let rodata = find_type_in_btf!(btf, Datasec, "rodata", true);

    assert_definition(&btf, bss, bss_output);
    assert_definition(&btf, rodata, rodata_output);
}

#[test]
fn test_btf_dump_definition_datasec_long_array() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    int x;
    char y[33];
    void *z;
};

struct Foo foo = {0};

const int myconstglobal = 0;
"#;

    let bss_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct bss {
    pub foo: Foo,
}
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub y: [i8; 33],
    pub z: *mut std::ffi::c_void,
}
impl Default for Foo {
    fn default() -> Self {
        Foo {
            x: i32::default(),
            y: [i8::default(); 33],
            z: std::ptr::null_mut(),
        }
    }
}
"#;

    let rodata_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct rodata {
    pub myconstglobal: i32,
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our types
    let bss = find_type_in_btf!(btf, Datasec, "bss", true);
    let rodata = find_type_in_btf!(btf, Datasec, "rodata", true);

    assert_definition(&btf, bss, bss_output);
    assert_definition(&btf, rodata, rodata_output);
}

#[test]
fn test_btf_dump_definition_datasec_multiple() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    int x;
    char y[10];
    void *z;
};

struct Foo foo = {0};
struct Foo foo2 = {0};
struct Foo foo3 = {0};

const int ci = 0;
const int ci2 = 0;
const int ci3 = 0;
"#;

    let bss_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct bss {
    pub foo: Foo,
    pub foo2: Foo,
    pub foo3: Foo,
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub y: [i8; 10],
    pub z: *mut std::ffi::c_void,
}
"#;

    let rodata_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct rodata {
    pub ci: i32,
    pub ci2: i32,
    pub ci3: i32,
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our types
    let bss = find_type_in_btf!(btf, Datasec, "bss", true);
    let rodata = find_type_in_btf!(btf, Datasec, "rodata", true);

    assert_definition(&btf, bss, bss_output);
    assert_definition(&btf, rodata, rodata_output);
}

#[test]
fn test_btf_dump_definition_datasec_multiple_long_array() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    int x;
    char y[33];
    void *z;
};

struct Foo foo = {0};
struct Foo foo2 = {0};
struct Foo foo3 = {0};

const int ci = 0;
const int ci2 = 0;
const int ci3 = 0;
"#;

    let bss_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct bss {
    pub foo: Foo,
    pub foo2: Foo,
    pub foo3: Foo,
}
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub y: [i8; 33],
    pub z: *mut std::ffi::c_void,
}
impl Default for Foo {
    fn default() -> Self {
        Foo {
            x: i32::default(),
            y: [i8::default(); 33],
            z: std::ptr::null_mut(),
        }
    }
}
"#;

    let rodata_output = r#"
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct rodata {
    pub ci: i32,
    pub ci2: i32,
    pub ci3: i32,
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our types
    let bss = find_type_in_btf!(btf, Datasec, "bss", true);
    let rodata = find_type_in_btf!(btf, Datasec, "rodata", true);

    assert_definition(&btf, bss, bss_output);
    assert_definition(&btf, rodata, rodata_output);
}

#[test]
fn test_btf_dump_definition_struct_inner_anon_union() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    int x;
    union {
        u8 y[10];
        u16 z[16];
    } bar;
    union {
        u32 w;
        u64 *u;
    } baz;
    int w;
};

struct Foo foo;
"#;

    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub bar: __anon_1,
    __pad_36: [u8; 4],
    pub baz: __anon_2,
    pub w: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union __anon_1 {
    pub y: [u8; 10],
    pub z: [u16; 16],
}
impl std::fmt::Debug for __anon_1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(???)")
    }
}
impl Default for __anon_1 {
    fn default() -> Self {
        __anon_1 {
            y: [u8::default(); 10],
        }
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union __anon_2 {
    pub w: u32,
    pub u: *mut u64,
}
impl std::fmt::Debug for __anon_2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(???)")
    }
}
impl Default for __anon_2 {
    fn default() -> Self {
        __anon_2 {
            w: u32::default(),
        }
    }
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_struct_inner_anon_struct() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    int x;
    struct {
        u8 y[10];
        u16 z[16];
    } bar;
    struct {
        u32 w;
        u64 *u;
    } baz;
    int w;
};

struct Foo foo;
"#;

    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub bar: __anon_1,
    pub baz: __anon_2,
    pub w: i32,
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct __anon_1 {
    pub y: [u8; 10],
    pub z: [u16; 16],
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct __anon_2 {
    pub w: u32,
    __pad_4: [u8; 4],
    pub u: *mut u64,
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_struct_inner_anon_struct_and_union() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    int x;
    struct {
        u8 y[10];
        u16 z[16];
    } bar;
    union {
        char *a;
        int b;
    } zerg;
    struct {
        u32 w;
        u64 *u;
    } baz;
    int w;
    union {
        u8 c;
        u64 d[5];
    } flarg;
};

struct Foo foo;
"#;

    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub bar: __anon_1,
    pub zerg: __anon_2,
    pub baz: __anon_3,
    pub w: i32,
    __pad_76: [u8; 4],
    pub flarg: __anon_4,
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct __anon_1 {
    pub y: [u8; 10],
    pub z: [u16; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union __anon_2 {
    pub a: *mut i8,
    pub b: i32,
}
impl std::fmt::Debug for __anon_2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(???)")
    }
}
impl Default for __anon_2 {
    fn default() -> Self {
        __anon_2 {
            a: std::ptr::null_mut(),
        }
    }
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct __anon_3 {
    pub w: u32,
    __pad_4: [u8; 4],
    pub u: *mut u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union __anon_4 {
    pub c: u8,
    pub d: [u64; 5],
}
impl std::fmt::Debug for __anon_4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(???)")
    }
}
impl Default for __anon_4 {
    fn default() -> Self {
        __anon_4 {
            c: u8::default(),
        }
    }
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find our struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_anon_enum() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef enum {
    FOO = 1,
} test_t;
struct Foo {
    test_t test;
};
struct Foo foo;
"#;

    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub test: __anon_1,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum __anon_1 {
    FOO = 1,
}
impl Default for __anon_1 {
    fn default() -> Self {
        __anon_1::FOO
    }
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find the struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_int_encodings() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct Foo {
    s32 a;
    u16 b;
    s16 c;
    bool d;
    char e;
};
struct Foo foo;
"#;

    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub a: i32,
    pub b: u16,
    pub c: i16,
    pub d: bool,
    pub e: i8,
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find the struct
    let struct_foo = find_type_in_btf!(btf, Struct, "Foo");

    assert_definition(&btf, struct_foo, expected_output);
}

#[test]
fn test_btf_dump_definition_unnamed_union() {
    let prog_text = r#"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// re-typed 'struct bpf_sock_tuple tup' from vmlinux as of kernel 5.15
// with a little bit added for additional complexity testing
struct bpf_sock_tuple_5_15 {
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
			__be16 sport;
			__be16 dport;
		} ipv4;
		struct {
			__be32 saddr[4];
			__be32 daddr[4];
			__be16 sport;
			__be16 dport;
		} ipv6;
	};

    union {
        int a;
        char *b;
    };
};
struct bpf_sock_tuple_5_15 tup;
"#;

    let expected_output = r#"
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct bpf_sock_tuple_5_15 {
    pub __anon_1: __anon_1,
    __pad_36: [u8; 4],
    pub __anon_4: __anon_4,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union __anon_1 {
    pub ipv4: __anon_2,
    pub ipv6: __anon_3,
}
impl std::fmt::Debug for __anon_1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(???)")
    }
}
impl Default for __anon_1 {
    fn default() -> Self {
        __anon_1 {
            ipv4: __anon_2::default(),
        }
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union __anon_4 {
    pub a: i32,
    pub b: *mut i8,
}
impl std::fmt::Debug for __anon_4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(???)")
    }
}
impl Default for __anon_4 {
    fn default() -> Self {
        __anon_4 {
            a: i32::default(),
        }
    }
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct __anon_2 {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct __anon_3 {
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
    pub sport: u16,
    pub dport: u16,
}
"#;

    let btf = build_btf_prog(prog_text);

    // Find the struct
    let struct_bpf_sock_tuple = find_type_in_btf!(btf, Struct, "bpf_sock_tuple_5_15");

    assert_definition(&btf, struct_bpf_sock_tuple, expected_output);
}

#[test]
fn test_btf_dump_float() {
    let prog_text = r#"
float f = 2.16;
double d = 12.15;
"#;

    let btf = build_btf_prog(prog_text);

    let f = find_type_in_btf!(btf, Var, "f");
    let d = find_type_in_btf!(btf, Var, "d");

    assert_eq!(
        "f32",
        btf.type_declaration(f).expect("Failed to generate f decl")
    );
    assert_eq!(
        "f64",
        btf.type_declaration(d).expect("Failed to generate d decl")
    );
}
