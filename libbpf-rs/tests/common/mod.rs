use std::io;
use std::path::PathBuf;

use libbpf_rs::Map;
use libbpf_rs::MapCore;
use libbpf_rs::MapMut;
use libbpf_rs::Object;
use libbpf_rs::ObjectBuilder;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramMut;

pub fn get_test_object_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::new();
    // env!() macro fails at compile time if var not found
    path.push(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/bin");
    path.push(filename);
    path
}

pub fn open_test_object(filename: &str) -> OpenObject {
    let obj_path = get_test_object_path(filename);
    let obj = ObjectBuilder::default()
        .debug(true)
        .open_file(obj_path)
        .expect("failed to open object");
    obj
}

pub fn bump_rlimit_mlock() {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
    assert_eq!(
        ret,
        0,
        "Setting RLIMIT_MEMLOCK failed with errno: {}",
        io::Error::last_os_error()
    );
}

pub fn get_test_object(filename: &str) -> Object {
    open_test_object(filename)
        .load()
        .expect("failed to load object")
}

/// Find the BPF map with the given name, panic if it does not exist.
#[track_caller]
pub fn get_map<'obj>(object: &'obj Object, name: &str) -> Map<'obj> {
    object
        .maps()
        .find(|map| map.name() == name)
        .unwrap_or_else(|| panic!("failed to find map `{name}`"))
}

/// Find the BPF map with the given name, panic if it does not exist.
#[track_caller]
pub fn get_map_mut<'obj>(object: &'obj mut Object, name: &str) -> MapMut<'obj> {
    object
        .maps_mut()
        .find(|map| map.name() == name)
        .unwrap_or_else(|| panic!("failed to find map `{name}`"))
}

/// Find the BPF program with the given name, panic if it does not exist.
#[track_caller]
pub fn get_prog_mut<'obj>(object: &'obj mut Object, name: &str) -> ProgramMut<'obj> {
    object
        .progs_mut()
        .find(|map| map.name() == name)
        .unwrap_or_else(|| panic!("failed to find program `{name}`"))
}
