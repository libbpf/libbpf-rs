use std::fs;
use std::path::PathBuf;

use libbpf_rs::{MapFlags, Object, ObjectBuilder};

fn get_test_object_path() -> PathBuf {
    let mut path = PathBuf::new();
    // env!() macro fails at compile time if var not found
    path.push(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/bin/runqslower.bpf.o");
    path
}

fn get_test_object() -> Object {
    let obj_path = get_test_object_path();
    let mut builder = ObjectBuilder::default();
    builder.from_path(obj_path).expect("failed to build object")
}

fn bump_rlimit_mlock() {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
    assert!(ret == 0);
}

#[test]
fn test_object_build() {
    get_test_object();
}

#[test]
fn test_object_build_from_memory() {
    let obj_path = get_test_object_path();
    let contents = fs::read(obj_path).expect("failed to read object file");
    let mut builder = ObjectBuilder::default();
    let obj = builder
        .from_memory("memory name", &contents)
        .expect("failed to build object");
    let name = obj.name().expect("failed to get object name");
    assert!(name == "memory name");
}

#[test]
fn test_object_name() {
    let obj_path = get_test_object_path();
    let mut builder = ObjectBuilder::default();
    builder.set_name("test name");
    let obj = builder.from_path(obj_path).expect("failed to build object");
    let obj_name = obj.name().expect("failed to get object name");
    assert!(obj_name == "test name");
}

#[test]
fn test_object_maps() {
    let mut obj = get_test_object();
    obj.map("start")
        .expect("error finding map")
        .expect("failed to find map");
    obj.map("events")
        .expect("error finding map")
        .expect("failed to find map");
    assert!(obj.map("asdf").expect("error finding map").is_none());
}

#[test]
fn test_object_map_load() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let _ = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map")
        .load()
        .expect("failed to load start map");
    let _ = obj
        .map("events")
        .expect("error finding map")
        .expect("failed to find map")
        .load()
        .expect("failed to load events map");
}

#[test]
fn test_object_map_key_value_size() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let mut start = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map")
        .load()
        .expect("failed to load start map");

    assert!(start.lookup(&[1, 2, 3, 4, 5], MapFlags::empty()).is_err());
    assert!(start.delete(&[1]).is_err());
    assert!(start.lookup_and_delete(&[1, 2, 3, 4, 5]).is_err());
    assert!(start
        .update(&[1, 2, 3, 4, 5], &[1], MapFlags::empty())
        .is_err());
}

#[test]
fn test_object_map_empty_lookup() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let start = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map")
        .load()
        .expect("failed to load start map");
    assert!(start
        .lookup(&[1, 2, 3, 4], MapFlags::empty())
        .expect("err in map lookup")
        .is_none());
}

#[test]
fn test_object_map_mutation() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let mut start = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map")
        .load()
        .expect("failed to load start map");

    start
        .update(&[1, 2, 3, 4], &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::empty())
        .expect("failed to write");
    let val = start
        .lookup(&[1, 2, 3, 4], MapFlags::empty())
        .expect("failed to read map")
        .expect("failed to find key");
    assert_eq!(val.len(), 8);
    assert_eq!(val, &[1, 2, 3, 4, 5, 6, 7, 8]);

    start.delete(&[1, 2, 3, 4]).expect("failed to delete key");

    assert!(start
        .lookup(&[1, 2, 3, 4], MapFlags::empty())
        .expect("failed to read map")
        .is_none());
}

#[test]
fn test_object_map_lookup_flags() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let mut start = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map")
        .load()
        .expect("failed to load start map");

    start
        .update(&[1, 2, 3, 4], &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::NO_EXIST)
        .expect("failed to write");
    assert!(start
        .update(&[1, 2, 3, 4], &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::NO_EXIST)
        .is_err());
}

#[test]
fn test_object_programs() {
    let mut obj = get_test_object();
    obj.prog("handle__sched_wakeup")
        .expect("error finding program")
        .expect("failed to find program");
    obj.prog("handle__sched_wakeup_new")
        .expect("error finding program")
        .expect("failed to find program");
    obj.prog("handle__sched_switch")
        .expect("error finding program")
        .expect("failed to find program");
    assert!(obj.prog("asdf").expect("error finding program").is_none());
}
