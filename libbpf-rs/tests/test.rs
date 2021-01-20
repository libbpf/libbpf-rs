use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use scopeguard::defer;

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
    // Invoke cargo with:
    //
    //     cargo test -- --nocapture
    //
    // To get all the output
    builder.debug(true);
    builder
        .open_file(obj_path)
        .expect("failed to open object")
        .load()
        .expect("failed to load object")
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
fn test_object_build_and_load() {
    get_test_object();
}

#[test]
fn test_object_build_from_memory() {
    let obj_path = get_test_object_path();
    let contents = fs::read(obj_path).expect("failed to read object file");
    let mut builder = ObjectBuilder::default();
    let obj = builder
        .open_memory("memory name", &contents)
        .expect("failed to build object");
    let name = obj.name().expect("failed to get object name");
    assert!(name == "memory name");
}

#[test]
fn test_object_name() {
    let obj_path = get_test_object_path();
    let mut builder = ObjectBuilder::default();
    builder.name("test name");
    let obj = builder.open_file(obj_path).expect("failed to build object");
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
fn test_object_map_key_value_size() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let start = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map");

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
        .expect("failed to find map");

    assert!(start
        .lookup(&[1, 2, 3, 4], MapFlags::empty())
        .expect("err in map lookup")
        .is_none());
}

#[test]
fn test_object_map_mutation() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let start = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map");

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
    let start = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map");

    start
        .update(&[1, 2, 3, 4], &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::NO_EXIST)
        .expect("failed to write");
    assert!(start
        .update(&[1, 2, 3, 4], &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::NO_EXIST)
        .is_err());
}

#[test]
fn test_object_map_key_iter() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let start = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map");

    let key1 = vec![1, 2, 3, 4];
    let key2 = vec![1, 2, 3, 5];
    let key3 = vec![1, 2, 3, 6];

    start
        .update(&key1, &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::empty())
        .expect("failed to write");
    start
        .update(&key2, &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::empty())
        .expect("failed to write");
    start
        .update(&key3, &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::empty())
        .expect("failed to write");

    let mut keys = HashSet::new();
    for key in start.keys() {
        keys.insert(key);
    }
    assert_eq!(keys.len(), 3);
    assert!(keys.contains(&key1));
    assert!(keys.contains(&key2));
    assert!(keys.contains(&key3));
}

#[test]
fn test_object_map_key_iter_empty() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let start = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map");

    let mut count = 0;
    for _ in start.keys() {
        count += 1;
    }
    assert_eq!(count, 0);
}

#[test]
fn test_object_map_pin() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let map = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map");

    let path = "/sys/fs/bpf/mymap";

    // Unpinning a unpinned map should be an error
    assert!(map.unpin(path).is_err());
    assert!(!Path::new(path).exists());

    // Pin and unpin should be successful
    map.pin(path).expect("failed to pin map");
    assert!(Path::new(path).exists());
    map.unpin(path).expect("failed to unpin map");
    assert!(!Path::new(path).exists());
}

#[test]
fn test_object_programs() {
    bump_rlimit_mlock();

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

#[test]
fn test_object_program_pin() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let prog = obj
        .prog("handle__sched_wakeup")
        .expect("error finding program")
        .expect("failed to find program");

    let path = "/sys/fs/bpf/myprog";

    // Unpinning a unpinned prog should be an error
    assert!(prog.unpin(path).is_err());
    assert!(!Path::new(path).exists());

    // Pin should be successful
    prog.pin(path).expect("failed to pin prog");
    assert!(Path::new(path).exists());

    // Backup cleanup method in case test errors
    defer! {
        let _ = fs::remove_file(path);
    }

    // Unpin and unpin should be successful
    prog.unpin(path).expect("failed to unpin prog");
    assert!(!Path::new(path).exists());
}

#[test]
fn test_object_link_pin() {
    bump_rlimit_mlock();

    let mut obj = get_test_object();
    let prog = obj
        .prog("handle__sched_wakeup")
        .expect("error finding program")
        .expect("failed to find program");
    let mut link = prog.attach().expect("failed to attach prog");

    let path = "/sys/fs/bpf/mylink";

    // Unpinning a unpinned prog should be an error
    assert!(link.unpin().is_err());
    assert!(!Path::new(path).exists());

    // Pin should be successful
    link.pin(path).expect("failed to pin prog");
    assert!(Path::new(path).exists());

    // Backup cleanup method in case test errors
    defer! {
        let _ = fs::remove_file(path);
    }

    // Unpin should be successful
    link.unpin().expect("failed to unpin prog");
    assert!(!Path::new(path).exists());
}

#[test]
fn test_object_reuse_pined_map() {
    bump_rlimit_mlock();

    let path = "/sys/fs/bpf/mymap";
    let key = vec![1, 2, 3, 4];
    let val = vec![1, 2, 3, 4, 5, 6, 7, 8];

    // Pin a map
    {
        let mut obj = get_test_object();
        let map = obj
            .map("start")
            .expect("error finding map")
            .expect("failed to find map");

        map.update(&key, &val, MapFlags::empty())
            .expect("failed to write");

        // Pin map
        map.pin(path).expect("failed to pin map");
        assert!(Path::new(path).exists());
    }

    // Backup cleanup method in case test errors somewhere
    defer! {
        let _ = fs::remove_file(path);
    }

    // Reuse the pinned map
    let obj_path = get_test_object_path();
    let mut builder = ObjectBuilder::default();
    builder.debug(true);
    let mut open_obj = builder.open_file(obj_path).expect("failed to open object");

    let start = open_obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map");
    assert!(start.reuse_pinned_map("/asdf").is_err());
    start.reuse_pinned_map(path).expect("failed to reuse map");

    let mut obj = open_obj.load().expect("Failed to load object");
    let reused_map = obj
        .map("start")
        .expect("error finding map")
        .expect("failed to find map");

    let found_val = reused_map
        .lookup(&key, MapFlags::empty())
        .expect("failed to read map")
        .expect("failed to find key");
    assert_eq!(&found_val, &val);

    // Cleanup
    reused_map.unpin(path).expect("failed to unpin map");
    assert!(!Path::new(path).exists());
}
