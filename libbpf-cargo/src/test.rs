use std::convert::TryInto;
use std::fs::{create_dir, read, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use goblin::Object;
use memmap::Mmap;
use tempfile::{tempdir, NamedTempFile, TempDir};

use crate::btf;
use crate::{btf::Btf, build::build, make::make, SkeletonBuilder};

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

/// Add bpf headers (eg vmlinux.h and bpf_helpers.h) into `project`'s src/bpf dir
fn add_bpf_headers(project: &Path) {
    let mut vmlinux = OpenOptions::new()
        .create(true)
        .write(true)
        .open(project.join("src/bpf/vmlinux.h"))
        .expect("failed to open vmlinux.h");
    write!(vmlinux, "{}", VMLINUX).expect("failed to write vmlinux.h");

    let mut bpf_helpers = OpenOptions::new()
        .create(true)
        .write(true)
        .open(project.join("src/bpf/bpf_helpers.h"))
        .expect("failed to open bpf_helpers.h");
    write!(bpf_helpers, "{}", BPF_HELPERS).expect("failed to write bpf_helpers.h");

    let mut bpf_helper_defs = OpenOptions::new()
        .create(true)
        .write(true)
        .open(project.join("src/bpf/bpf_helper_defs.h"))
        .expect("failed to open bpf_helper_defs.h");
    write!(bpf_helper_defs, "{}", BPF_HELPER_DEFS).expect("failed to write bpf_helper_defs.h");
}

#[test]
fn test_build_default() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // No bpf progs yet
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap_err();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap_err();

    // Add a prog
    let _prog_file =
        File::create(proj_dir.join("src/bpf/prog.bpf.c")).expect("failed to create prog file");

    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

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

    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap_err();
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
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap_err();

    // Add a prog
    create_dir(proj_dir.join("src/other_bpf_dir")).expect("failed to create prog dir");
    let _prog_file = File::create(proj_dir.join("src/other_bpf_dir/prog.bpf.c"))
        .expect("failed to create prog file");

    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

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
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap_err();

    let _prog_file = File::create(proj_dir.join("src/bpf/prog_BAD_EXTENSION.c"))
        .expect("failed to create prog file");
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap_err();

    let _prog_file_again = File::create(proj_dir.join("src/bpf/prog_GOOD_EXTENSION.bpf.c"))
        .expect("failed to create prog file");
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();
}

#[test]
fn test_build_workspace() {
    let (_dir, _, workspace_cargo_toml, proj_one_dir, proj_two_dir) = setup_temp_workspace();

    // No bpf progs yet
    build(
        true,
        Some(&workspace_cargo_toml),
        Path::new("/bin/clang"),
        true,
    )
    .unwrap_err();

    // Create bpf prog for project one
    create_dir(proj_one_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_1 = File::create(proj_one_dir.join("src/bpf/prog1.bpf.c"))
        .expect("failed to create prog file 1");

    // Create bpf prog for project two
    create_dir(proj_two_dir.join("src/bpf")).expect("failed to create prog dir");
    let _prog_file_2 = File::create(proj_two_dir.join("src/bpf/prog2.bpf.c"))
        .expect("failed to create prog file 2");

    build(
        true,
        Some(&workspace_cargo_toml),
        Path::new("/bin/clang"),
        true,
    )
    .unwrap();
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

    build(
        true,
        Some(&workspace_cargo_toml),
        Path::new("/bin/clang"),
        true,
    )
    .unwrap_err();
}

#[test]
fn test_make_basic() {
    let (_dir, proj_dir, cargo_toml) = setup_temp_project();

    // Add prog dir
    create_dir(proj_dir.join("src/bpf")).expect("failed to create prog dir");

    // Add a prog
    let _prog_file =
        File::create(proj_dir.join("src/bpf/prog.bpf.c")).expect("failed to create prog file");

    make(
        true,
        Some(&cargo_toml),
        Path::new("/bin/clang"),
        true,
        true,
        Vec::new(),
        None,
    )
    .unwrap();

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
        Path::new("/bin/clang"),
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

    make(
        true,
        Some(&cargo_toml),
        Path::new("/bin/clang"),
        true,
        true,
        Vec::new(),
        None,
    )
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
    add_bpf_headers(&proj_dir);

    make(
        true,
        Some(&cargo_toml),
        Path::new("/bin/clang"),
        true,
        true,
        Vec::new(),
        None,
    )
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
        #include "bpf_helpers.h"

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
    add_bpf_headers(&proj_dir);

    make(
        true,
        Some(&cargo_toml),
        Path::new("/bin/clang"),
        true,
        true,
        Vec::new(),
        None,
    )
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
    add_bpf_headers(&proj_dir);

    // Generate skeleton file
    let skel = NamedTempFile::new().unwrap();
    SkeletonBuilder::new(proj_dir.join("src/bpf/prog.bpf.c"))
        .debug(true)
        .clang("/bin/clang")
        .generate(skel.path())
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
    SkeletonBuilder::new(proj_dir.join("src/bpf/prog.bpf.c"))
        .debug(true)
        .clang("/bin/clang")
        .generate(skel.path())
        .unwrap_err();

    // Should succeed b/c we defined the macro
    SkeletonBuilder::new(proj_dir.join("src/bpf/prog.bpf.c"))
        .debug(true)
        .clang("/bin/clang")
        .clang_args("-DPURPOSE=you_pass_the_butter")
        .generate(skel.path())
        .unwrap();
}

#[test]
fn test_btf_dump_basic() {
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

        int myglobal = 1;

        struct Foo {{
            int x;
            char y[10];
            void *z;
        }};

        struct Foo foo = {{0}};
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our types
    let mut struct_foo: Option<u32> = None;
    let mut foo: Option<u32> = None;
    let mut myglobal: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Struct(t) => {
                if t.name == "Foo" {
                    assert!(struct_foo.is_none()); // No duplicates
                    struct_foo = Some(idx.try_into().unwrap());
                }
            }
            btf::BtfType::Datasec(t) => {
                for var in &t.vars {
                    let var_ty = btf
                        .type_by_id(var.type_id)
                        .expect("Failed to lookup datasec var");
                    match var_ty {
                        btf::BtfType::Var(t) => {
                            if t.name == "foo" {
                                assert!(foo.is_none());
                                foo = Some(var.type_id);
                            } else if t.name == "myglobal" {
                                assert!(myglobal.is_none());
                                myglobal = Some(var.type_id);
                            }
                        }
                        _ => panic!("Datasec var didn't point to a var. Instead: {}", var_ty),
                    }
                }
            }
            _ => (),
        }
    }

    assert!(struct_foo.is_some());
    assert!(foo.is_some());
    assert!(myglobal.is_some());

    assert_eq!(
        "Foo",
        btf.type_declaration(foo.unwrap())
            .expect("Failed to generate foo decl")
    );
    assert_eq!(
        "i32",
        btf.type_declaration(myglobal.unwrap())
            .expect("Failed to generate myglobal decl")
    );

    let foo_defn = r#"#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub y: [i8; 10],
    pub z: *mut std::ffi::c_void,
}
"#;
    assert_eq!(
        foo_defn,
        btf.type_definition(struct_foo.unwrap())
            .expect("Failed to generate struct Foo defn")
    );
}

#[test]
fn test_btf_dump_struct_definition() {
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

        struct Bar {{
            u16 x;
        }};

        struct Foo {{
            int *ip;
            int **ipp;
            struct Bar bar;
            struct Bar *pb;
            volatile u64 v;
            const volatile s64 cv;
            char * restrict r;
        }};

        struct Foo foo;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our struct
    let mut struct_foo: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Struct(t) => {
                if t.name == "Foo" {
                    assert!(struct_foo.is_none()); // No duplicates
                    struct_foo = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(struct_foo.is_some());

    // Note how there's 6 bytes of padding. It's not necessary on 64 bit archs but
    // we've assumed 32 bit arch during padding generation.
    let foo_defn = r#"#[derive(Debug, Default, Copy, Clone)]
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
    assert_eq!(
        foo_defn,
        btf.type_definition(struct_foo.unwrap())
            .expect("Failed to generate struct Foo defn")
    );
}

#[test]
fn test_btf_dump_definition_packed_struct() {
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

        struct Foo {{
            int x;
            char y;
            __s32 z[2];
        }} __attribute__((packed));

        struct Foo foo;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our struct
    let mut struct_foo: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Struct(t) => {
                if t.name == "Foo" {
                    assert!(struct_foo.is_none()); // No duplicates
                    struct_foo = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(struct_foo.is_some());

    let foo_defn = r#"#[derive(Debug, Default, Copy, Clone)]
#[repr(C, packed)]
pub struct Foo {
    pub x: i32,
    pub y: i8,
    pub z: [i32; 2],
}
"#;
    assert_eq!(
        foo_defn,
        btf.type_definition(struct_foo.unwrap())
            .expect("Failed to generate struct Foo defn")
    );
}

#[test]
fn test_btf_dump_definition_bitfield_struct_fails() {
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

        struct Foo {{
            unsigned int x: 2;
            unsigned int y: 3;
        }};

        struct Foo foo;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our struct
    let mut struct_foo: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Struct(t) => {
                if t.name == "Foo" {
                    assert!(struct_foo.is_none()); // No duplicates
                    struct_foo = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(struct_foo.is_some());
    assert!(btf.type_definition(struct_foo.unwrap()).is_err());
}

#[test]
fn test_btf_dump_definition_enum() {
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

        enum Foo {{
            Zero = 0,
            One,
            seven = 7,
        }};

        enum Foo foo;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our struct
    let mut enum_foo: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Enum(t) => {
                if t.name == "Foo" {
                    assert!(enum_foo.is_none()); // No duplicates
                    enum_foo = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(enum_foo.is_some());

    let foo_defn = r#"#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u32)]
pub enum Foo {
    Zero = 0,
    One = 1,
    seven = 7,
}
"#;
    assert_eq!(
        foo_defn,
        btf.type_definition(enum_foo.unwrap())
            .expect("Failed to generate enum Foo defn")
    );
}

#[test]
fn test_btf_dump_definition_union() {
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

        union Foo {{
            int x;
            __u32 y;
            char z[128];
        }};

        union Foo foo;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our struct
    let mut union_foo: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Union(t) => {
                if t.name == "Foo" {
                    assert!(union_foo.is_none()); // No duplicates
                    union_foo = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(union_foo.is_some());

    let foo_defn = r#"#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub union Foo {
    pub x: i32,
    pub y: u32,
    pub z: [i8; 128],
}
"#;
    assert_eq!(
        foo_defn,
        btf.type_definition(union_foo.unwrap())
            .expect("Failed to generate union Foo defn")
    );
}

#[test]
fn test_btf_dump_definition_shared_dependent_types() {
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

        struct Bar {{
            u16 x;
        }};

        struct Foo {{
            struct Bar bar;
            struct Bar bartwo;
        }};

        struct Foo foo;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our struct
    let mut struct_foo: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Struct(t) => {
                if t.name == "Foo" {
                    assert!(struct_foo.is_none()); // No duplicates
                    struct_foo = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(struct_foo.is_some());

    let foo_defn = r#"#[derive(Debug, Default, Copy, Clone)]
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
    assert_eq!(
        foo_defn,
        btf.type_definition(struct_foo.unwrap())
            .expect("Failed to generate struct Foo defn")
    );
}

#[test]
fn test_btf_dump_definition_datasec() {
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

        struct Foo {{
            int x;
            char y[10];
            void *z;
        }};

        struct Foo foo = {{0}};

        const int myconstglobal = 0;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our types
    let mut bss: Option<u32> = None;
    let mut rodata: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Datasec(t) => {
                if t.name.contains("bss") {
                    assert!(bss.is_none()); // No duplicates
                    bss = Some(idx.try_into().unwrap());
                } else if t.name.contains("rodata") {
                    assert!(rodata.is_none()); // No duplicates
                    rodata = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(bss.is_some());
    assert!(rodata.is_some());

    let bss_defn = r#"#[derive(Debug, Copy, Clone)]
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
    assert_eq!(
        bss_defn,
        btf.type_definition(bss.unwrap())
            .expect("Failed to generate bss")
    );

    let rodata_defn = r#"#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct rodata {
    pub myconstglobal: i32,
}
"#;
    assert_eq!(
        rodata_defn,
        btf.type_definition(rodata.unwrap())
            .expect("Failed to generate rodata")
    );
}

#[test]
fn test_btf_dump_definition_datasec_multiple() {
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

        struct Foo {{
            int x;
            char y[10];
            void *z;
        }};

        struct Foo foo = {{0}};
        struct Foo foo2 = {{0}};
        struct Foo foo3 = {{0}};

        const int ci = 0;
        const int ci2 = 0;
        const int ci3 = 0;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    build(true, Some(&cargo_toml), Path::new("/bin/clang"), true).unwrap();

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our types
    let mut bss: Option<u32> = None;
    let mut rodata: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Datasec(t) => {
                if t.name.contains("bss") {
                    assert!(bss.is_none()); // No duplicates
                    bss = Some(idx.try_into().unwrap());
                } else if t.name.contains("rodata") {
                    assert!(rodata.is_none()); // No duplicates
                    rodata = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(bss.is_some());
    assert!(rodata.is_some());

    let bss_defn = r#"#[derive(Debug, Copy, Clone)]
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
    assert_eq!(
        bss_defn,
        btf.type_definition(bss.unwrap())
            .expect("Failed to generate bss")
    );

    let rodata_defn = r#"#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct rodata {
    pub ci: i32,
    pub ci2: i32,
    pub ci3: i32,
}
"#;
    assert_eq!(
        rodata_defn,
        btf.type_definition(rodata.unwrap())
            .expect("Failed to generate rodata")
    );
}

#[test]
fn test_btf_dump_definition_struct_inner_anon_union() {
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

        struct Foo {{
            int x;
            union {{
                u8 y[10];
                u16 z[16];
            }} bar;
            union {{
                u32 w;
                u64 *u;
            }} baz;
            int w;
        }};

        struct Foo foo;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    assert_eq!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our struct
    let mut struct_foo: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Struct(t) => {
                if t.name == "Foo" {
                    assert!(struct_foo.is_none()); // No duplicates
                    struct_foo = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(struct_foo.is_some());

    let foo_defn = r#"#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct Foo {
    pub x: i32,
    pub bar: __anon_1,
    __pad_36: [u8; 4],
    pub baz: __anon_2,
    pub w: i32,
}
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub union __anon_1 {
    pub y: [u8; 10],
    pub z: [u16; 16],
}
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub union __anon_2 {
    pub w: u32,
    pub u: *mut u64,
}
"#;
    assert_eq!(
        foo_defn,
        btf.type_definition(struct_foo.unwrap())
            .expect("Failed to generate union Foo defn")
    );
}

#[test]
fn test_btf_dump_definition_struct_inner_anon_struct() {
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

        struct Foo {{
            int x;
            struct {{
                u8 y[10];
                u16 z[16];
            }} bar;
            struct {{
                u32 w;
                u64 *u;
            }} baz;
            int w;
        }};

        struct Foo foo;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    assert_eq!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our struct
    let mut struct_foo: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Struct(t) => {
                if t.name == "Foo" {
                    assert!(struct_foo.is_none()); // No duplicates
                    struct_foo = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(struct_foo.is_some());

    let foo_defn = r#"#[derive(Debug, Default, Copy, Clone)]
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
    assert_eq!(
        foo_defn,
        btf.type_definition(struct_foo.unwrap())
            .expect("Failed to generate struct Foo defn")
    );
}

#[test]
fn test_btf_dump_definition_struct_inner_anon_struct_and_union() {
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

        struct Foo {{
            int x;
            struct {{
                u8 y[10];
                u16 z[16];
            }} bar;
            union {{
                char *a;
                int b;
            }} zerg;
            struct {{
                u32 w;
                u64 *u;
            }} baz;
            int w;
            union {{
                u8 c;
                u64 d[5];
            }} flarg;
        }};

        struct Foo foo;
        "#,
    )
    .expect("failed to write prog.bpf.c");

    // Lay down the necessary header files
    add_bpf_headers(&proj_dir);

    // Build the .bpf.o
    assert_eq!(
        build(true, Some(&cargo_toml), Path::new("/bin/clang"), true),
        0
    );

    let obj = OpenOptions::new()
        .read(true)
        .open(proj_dir.as_path().join("target/bpf/prog.bpf.o").as_path())
        .expect("failed to open object file");
    let mmap = unsafe { Mmap::map(&obj) }.expect("Failed to mmap object file");
    let btf = Btf::new("prog", &*mmap)
        .expect("Failed to initialize Btf")
        .expect("Did not find .BTF section");

    assert!(btf.types().len() > 0);

    // Find our struct
    let mut struct_foo: Option<u32> = None;
    for (idx, ty) in btf.types().iter().enumerate() {
        match ty {
            btf::BtfType::Struct(t) => {
                if t.name == "Foo" {
                    assert!(struct_foo.is_none()); // No duplicates
                    struct_foo = Some(idx.try_into().unwrap());
                }
            }
            _ => (),
        }
    }

    assert!(struct_foo.is_some());

    let foo_defn = r#"#[derive(Debug, Default, Copy, Clone)]
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
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub union __anon_2 {
    pub a: *mut i8,
    pub b: i32,
}
#[derive(Debug, Default, Copy, Clone)]
#[repr(C)]
pub struct __anon_3 {
    pub w: u32,
    __pad_4: [u8; 4],
    pub u: *mut u64,
}
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub union __anon_4 {
    pub c: u8,
    pub d: [u64; 5],
}
"#;
    assert_eq!(
        foo_defn,
        btf.type_definition(struct_foo.unwrap())
            .expect("Failed to generate struct Foo defn")
    );
}
