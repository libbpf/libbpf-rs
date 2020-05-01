use std::fs;
use std::path::PathBuf;

use libbpf_rs::{Object, ObjectBuilder};

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
