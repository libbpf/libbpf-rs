#![allow(clippy::let_unit_value)]
#![warn(clippy::absolute_paths)]

mod common;

use std::collections::HashSet;
use std::env::current_exe;
use std::ffi::c_int;
use std::ffi::c_void;
use std::ffi::OsStr;
use std::fs;
use std::hint;
use std::io;
use std::io::Read;
use std::mem::size_of;
use std::mem::size_of_val;
use std::os::unix::io::AsFd;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::ptr::addr_of;
use std::slice;
use std::sync::mpsc::channel;
use std::time::Duration;

use libbpf_rs::num_possible_cpus;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::Iter;
use libbpf_rs::Linker;
use libbpf_rs::Map;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use libbpf_rs::MapInfo;
use libbpf_rs::MapType;
use libbpf_rs::Object;
use libbpf_rs::ObjectBuilder;
use libbpf_rs::Program;
use libbpf_rs::ProgramInput;
use libbpf_rs::ProgramType;
use libbpf_rs::TracepointOpts;
use libbpf_rs::UprobeOpts;
use libbpf_rs::UsdtOpts;
use libbpf_rs::UserRingBuffer;
use plain::Plain;
use probe::probe;
use scopeguard::defer;
use tempfile::NamedTempFile;
use test_tag::tag;

use crate::common::bump_rlimit_mlock;
use crate::common::get_map;
use crate::common::get_map_mut;
use crate::common::get_prog_mut;
use crate::common::get_test_object;
use crate::common::get_test_object_path;
use crate::common::open_test_object;

/// A helper function for instantiating a `RingBuffer` with a callback meant to
/// be invoked when `action` is executed and that is intended to trigger a write
/// to said `RingBuffer` from kernel space, which then reads a single `i32` from
/// this buffer from user space and returns it.
fn with_ringbuffer<F>(map: &Map, action: F) -> i32
where
    F: FnOnce(),
{
    let mut value = 0i32;
    {
        let callback = |data: &[u8]| {
            plain::copy_from_bytes(&mut value, data).expect("Wrong size");
            0
        };

        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder.add(map, callback).expect("failed to add ringbuf");
        let mgr = builder.build().expect("failed to build");

        action();
        mgr.consume().expect("failed to consume ringbuf");
    }

    value
}

#[tag(root)]
#[test]
fn test_object_build_and_load() {
    bump_rlimit_mlock();

    get_test_object("runqslower.bpf.o");
}

#[test]
fn test_object_build_from_memory() {
    let obj_path = get_test_object_path("runqslower.bpf.o");
    let contents = fs::read(obj_path).expect("failed to read object file");
    let mut builder = ObjectBuilder::default();
    let obj = builder
        .name("memory name")
        .unwrap()
        .open_memory(&contents)
        .expect("failed to build object");
    let name = obj.name().expect("failed to get object name");
    assert!(name == "memory name");

    let obj = unsafe { Object::from_ptr(obj.take_ptr()) };
    let name = obj.name().expect("failed to get object name");
    assert!(name == "memory name");
}

#[test]
fn test_object_build_from_memory_empty_name() {
    let obj_path = get_test_object_path("runqslower.bpf.o");
    let contents = fs::read(obj_path).expect("failed to read object file");
    let mut builder = ObjectBuilder::default();
    let obj = builder
        .name("")
        .unwrap()
        .open_memory(&contents)
        .expect("failed to build object");
    let name = obj.name().expect("failed to get object name");
    assert!(name.is_empty());

    let obj = unsafe { Object::from_ptr(obj.take_ptr()) };
    let name = obj.name().expect("failed to get object name");
    assert!(name.is_empty());
}

/// Check that loading an object from an empty file fails as expected.
#[tag(root)]
#[test]
fn test_object_load_invalid() {
    let empty_file = NamedTempFile::new().unwrap();
    let _err = ObjectBuilder::default()
        .debug(true)
        .open_file(empty_file.path())
        .unwrap_err();
}

#[test]
fn test_object_name() {
    let obj_path = get_test_object_path("runqslower.bpf.o");
    let mut builder = ObjectBuilder::default();
    builder.name("test name").unwrap();
    let obj = builder.open_file(obj_path).expect("failed to build object");
    let obj_name = obj.name().expect("failed to get object name");
    assert!(obj_name == "test name");
}

#[tag(root)]
#[test]
fn test_object_maps() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let _map = get_map_mut(&mut obj, "start");
    let _map = get_map_mut(&mut obj, "events");
    assert!(!obj.maps().any(|map| map.name() == OsStr::new("asdf")));
}

#[tag(root)]
#[test]
fn test_object_maps_iter() {
    bump_rlimit_mlock();

    let obj = get_test_object("runqslower.bpf.o");
    for map in obj.maps() {
        eprintln!("{:?}", map.name());
    }
    // This will include .rodata and .bss, so our expected count is 4, not 2
    assert!(obj.maps().count() == 4);
}

#[tag(root)]
#[test]
fn test_object_map_key_value_size() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = get_map_mut(&mut obj, "start");

    assert!(start.lookup(&[1, 2, 3, 4, 5], MapFlags::empty()).is_err());
    assert!(start.delete(&[1]).is_err());
    assert!(start.lookup_and_delete(&[1, 2, 3, 4, 5]).is_err());
    assert!(start
        .update(&[1, 2, 3, 4, 5], &[1], MapFlags::empty())
        .is_err());
}

#[tag(root)]
#[test]
fn test_object_map_update_batch() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = get_map_mut(&mut obj, "start");

    let key1 = 1u32.to_ne_bytes();
    let key2 = 2u32.to_ne_bytes();
    let key3 = 3u32.to_ne_bytes();
    let key4 = 4u32.to_ne_bytes();

    let value1 = 369u64.to_ne_bytes();
    let value2 = 258u64.to_ne_bytes();
    let value3 = 147u64.to_ne_bytes();
    let value4 = 159u64.to_ne_bytes();

    let batch_key1 = key1.into_iter().chain(key2).collect::<Vec<_>>();
    let batch_value1 = value1.into_iter().chain(value2).collect::<Vec<_>>();

    let batch_key2 = key2.into_iter().chain(key3).chain(key4).collect::<Vec<_>>();
    let batch_value2 = value2
        .into_iter()
        .chain(value3)
        .chain(value4)
        .collect::<Vec<_>>();

    // Update batch with wrong key size
    assert!(start
        .update_batch(
            &[1, 2, 3],
            &batch_value1,
            2,
            MapFlags::ANY,
            MapFlags::NO_EXIST
        )
        .is_err());

    // Update batch with wrong value size
    assert!(start
        .update_batch(
            &batch_key1,
            &[1, 2, 3],
            2,
            MapFlags::ANY,
            MapFlags::NO_EXIST
        )
        .is_err());

    // Update batch with wrong count.
    assert!(start
        .update_batch(
            &batch_key1,
            &batch_value1,
            1,
            MapFlags::ANY,
            MapFlags::NO_EXIST
        )
        .is_err());

    // Update batch with 1 key.
    assert!(start
        .update_batch(&key1, &value1, 1, MapFlags::ANY, MapFlags::NO_EXIST)
        .is_ok());

    // Update batch with multiple keys.
    assert!(start
        .update_batch(
            &batch_key2,
            &batch_value2,
            3,
            MapFlags::ANY,
            MapFlags::NO_EXIST
        )
        .is_ok());

    // Update batch with existing keys.
    assert!(start
        .update_batch(
            &batch_key2,
            &batch_value2,
            3,
            MapFlags::NO_EXIST,
            MapFlags::NO_EXIST
        )
        .is_err());
}

#[tag(root)]
#[test]
fn test_object_map_delete_batch() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = get_map_mut(&mut obj, "start");

    let key1 = 1u32.to_ne_bytes();
    assert!(start
        .update(&key1, &9999u64.to_ne_bytes(), MapFlags::ANY)
        .is_ok());
    let key2 = 2u32.to_ne_bytes();
    assert!(start
        .update(&key2, &42u64.to_ne_bytes(), MapFlags::ANY)
        .is_ok());
    let key3 = 3u32.to_ne_bytes();
    assert!(start
        .update(&key3, &18u64.to_ne_bytes(), MapFlags::ANY)
        .is_ok());
    let key4 = 4u32.to_ne_bytes();
    assert!(start
        .update(&key4, &1337u64.to_ne_bytes(), MapFlags::ANY)
        .is_ok());

    // Delete 1 incomplete key.
    assert!(start
        .delete_batch(&[0, 0, 1], 1, MapFlags::empty(), MapFlags::empty())
        .is_err());
    // Delete keys with wrong count.
    assert!(start
        .delete_batch(&key4, 2, MapFlags::empty(), MapFlags::empty())
        .is_err());
    // Delete 1 key successfully.
    assert!(start
        .delete_batch(&key4, 1, MapFlags::empty(), MapFlags::empty())
        .is_ok());
    // Delete remaining 3 keys.
    let keys = key1.into_iter().chain(key2).chain(key3).collect::<Vec<_>>();
    assert!(start
        .delete_batch(&keys, 3, MapFlags::empty(), MapFlags::empty())
        .is_ok());
    // Map should be empty now.
    assert!(start.keys().collect::<Vec<_>>().is_empty())
}

/// Test whether `MapInfo` works properly
#[tag(root)]
#[test]
pub fn test_map_info() {
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_ANY,
        btf_fd: 0,
        btf_key_type_id: 0,
        btf_value_type_id: 0,
        btf_vmlinux_value_type_id: 0,
        inner_map_fd: 0,
        map_extra: 0,
        numa_node: 0,
        map_ifindex: 0,
        // bpf_map_create_opts might have padding fields on some platform
        ..Default::default()
    };

    let map = MapHandle::create(MapType::Hash, Some("simple_map"), 8, 64, 1024, &opts).unwrap();
    let map_info = MapInfo::new(map.as_fd()).unwrap();
    let name_received = map_info.name().unwrap();
    assert_eq!(name_received, "simple_map");
    assert_eq!(map_info.map_type(), MapType::Hash);
    assert_eq!(map_info.flags() & MapFlags::ANY, MapFlags::ANY);

    let map_info = &map_info.info;
    assert_eq!(map_info.key_size, 8);
    assert_eq!(map_info.value_size, 64);
    assert_eq!(map_info.max_entries, 1024);
    assert_eq!(map_info.btf_id, 0);
    assert_eq!(map_info.btf_key_type_id, 0);
    assert_eq!(map_info.btf_value_type_id, 0);
    assert_eq!(map_info.btf_vmlinux_value_type_id, 0);
    assert_eq!(map_info.map_extra, 0);
    assert_eq!(map_info.ifindex, 0);
}

#[tag(root)]
#[test]
fn test_object_percpu_lookup() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = get_map_mut(&mut obj, "percpu_map");
    let res = map
        .lookup_percpu(&(0_u32).to_ne_bytes(), MapFlags::ANY)
        .expect("failed to lookup")
        .expect("failed to find value for key");

    assert_eq!(
        res.len(),
        num_possible_cpus().expect("must be one value per cpu")
    );
    assert_eq!(res[0].len(), size_of::<u32>());
}

#[tag(root)]
#[test]
fn test_object_percpu_invalid_lookup_fn() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = get_map_mut(&mut obj, "percpu_map");

    assert!(map.lookup(&(0_u32).to_ne_bytes(), MapFlags::ANY).is_err());
}

#[tag(root)]
#[test]
fn test_object_percpu_update() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = get_map_mut(&mut obj, "percpu_map");
    let key = (0_u32).to_ne_bytes();

    let mut vals: Vec<Vec<u8>> = Vec::new();
    for i in 0..num_possible_cpus().unwrap() {
        vals.push((i as u32).to_ne_bytes().to_vec());
    }

    map.update_percpu(&key, &vals, MapFlags::ANY)
        .expect("failed to update map");

    let res = map
        .lookup_percpu(&key, MapFlags::ANY)
        .expect("failed to lookup")
        .expect("failed to find value for key");

    assert_eq!(vals, res);
}

#[tag(root)]
#[test]
fn test_object_percpu_invalid_update_fn() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = get_map_mut(&mut obj, "percpu_map");
    let key = (0_u32).to_ne_bytes();

    let val = (1_u32).to_ne_bytes().to_vec();

    assert!(map.update(&key, &val, MapFlags::ANY).is_err());
}

#[tag(root)]
#[test]
fn test_object_percpu_lookup_update() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = get_map_mut(&mut obj, "percpu_map");
    let key = (0_u32).to_ne_bytes();

    let mut res = map
        .lookup_percpu(&key, MapFlags::ANY)
        .expect("failed to lookup")
        .expect("failed to find value for key");

    for e in res.iter_mut() {
        e[0] &= 0xf0;
    }

    map.update_percpu(&key, &res, MapFlags::ANY)
        .expect("failed to update after first lookup");

    let res2 = map
        .lookup_percpu(&key, MapFlags::ANY)
        .expect("failed to lookup")
        .expect("failed to find value for key");

    assert_eq!(res, res2);
}

#[tag(root)]
#[test]
fn test_object_map_empty_lookup() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = get_map_mut(&mut obj, "start");

    assert!(start
        .lookup(&[1, 2, 3, 4], MapFlags::empty())
        .expect("err in map lookup")
        .is_none());
}

/// Test CRUD operations on map of type queue.
#[tag(root)]
#[test]
fn test_object_map_queue_crud() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("tracepoint.bpf.o");
    let queue = get_map_mut(&mut obj, "queue");

    let key: [u8; 0] = [];
    let value1 = 42u32.to_ne_bytes();
    let value2 = 43u32.to_ne_bytes();

    // Test queue, FIFO expected
    queue
        .update(&key, &value1, MapFlags::ANY)
        .expect("failed to update in queue");
    queue
        .update(&key, &value2, MapFlags::ANY)
        .expect("failed to update in queue");

    let mut val = queue
        .lookup(&key, MapFlags::ANY)
        .expect("failed to peek the queue")
        .expect("failed to retrieve value");
    assert_eq!(val.len(), 4);
    assert_eq!(&val, &value1);

    val = queue
        .lookup_and_delete(&key)
        .expect("failed to pop from queue")
        .expect("failed to retrieve value");
    assert_eq!(val.len(), 4);
    assert_eq!(&val, &value1);

    val = queue
        .lookup_and_delete(&key)
        .expect("failed to pop from queue")
        .expect("failed to retrieve value");
    assert_eq!(val.len(), 4);
    assert_eq!(&val, &value2);

    assert!(queue
        .lookup_and_delete(&key)
        .expect("failed to pop from queue")
        .is_none());
}

/// Test CRUD operations on map of type bloomfilter.
#[tag(root)]
#[test]
fn test_object_map_bloom_filter_crud() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("tracepoint.bpf.o");
    let bloom_filter = get_map_mut(&mut obj, "bloom_filter");

    let key: [u8; 0] = [];
    let value1 = 1337u32.to_ne_bytes();
    let value2 = 2674u32.to_ne_bytes();

    bloom_filter
        .update(&key, &value1, MapFlags::ANY)
        .expect("failed to add entry value1 to bloom filter");

    bloom_filter
        .update(&key, &value2, MapFlags::ANY)
        .expect("failed to add entry value2 in bloom filter");

    // Non empty keys should result in an error
    bloom_filter
        .update(&value1, &value1, MapFlags::ANY)
        .expect_err("Non empty key should return an error");

    for inserted_value in [value1, value2] {
        let val = bloom_filter
            .lookup_bloom_filter(&inserted_value)
            .expect("failed retrieve item from bloom filter");

        assert!(val);
    }
    // Test non existing element
    let enoent_found = bloom_filter
        .lookup_bloom_filter(&[1, 2, 3, 4])
        .expect("failed retrieve item from bloom filter");

    assert!(!enoent_found);

    // Calling lookup should result in an error
    bloom_filter
        .lookup(&[1, 2, 3, 4], MapFlags::ANY)
        .expect_err("lookup should fail since we should use lookup_bloom_filter");

    // Deleting should not be possible
    bloom_filter
        .lookup_and_delete(&key)
        .expect_err("Expect delete to fail");
}

/// Test CRUD operations on map of type stack.
#[tag(root)]
#[test]
fn test_object_map_stack_crud() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("tracepoint.bpf.o");
    let stack = get_map_mut(&mut obj, "stack");

    let key: [u8; 0] = [];
    let value1 = 1337u32.to_ne_bytes();
    let value2 = 2674u32.to_ne_bytes();

    stack
        .update(&key, &value1, MapFlags::ANY)
        .expect("failed to update in stack");
    stack
        .update(&key, &value2, MapFlags::ANY)
        .expect("failed to update in stack");

    let mut val = stack
        .lookup(&key, MapFlags::ANY)
        .expect("failed to pop from stack")
        .expect("failed to retrieve value");

    assert_eq!(val.len(), 4);
    assert_eq!(&val, &value2);

    val = stack
        .lookup_and_delete(&key)
        .expect("failed to pop from stack")
        .expect("failed to retrieve value");
    assert_eq!(val.len(), 4);
    assert_eq!(&val, &value2);

    val = stack
        .lookup_and_delete(&key)
        .expect("failed to pop from stack")
        .expect("failed to retrieve value");
    assert_eq!(val.len(), 4);
    assert_eq!(&val, &value1);

    assert!(stack
        .lookup_and_delete(&key)
        .expect("failed to pop from stack")
        .is_none());
}

#[tag(root)]
#[test]
fn test_object_map_mutation() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = get_map_mut(&mut obj, "start");
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

#[tag(root)]
#[test]
fn test_object_map_lookup_flags() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = get_map_mut(&mut obj, "start");
    start
        .update(&[1, 2, 3, 4], &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::NO_EXIST)
        .expect("failed to write");
    assert!(start
        .update(&[1, 2, 3, 4], &[1, 2, 3, 4, 5, 6, 7, 8], MapFlags::NO_EXIST)
        .is_err());
}

#[tag(root)]
#[test]
fn test_object_map_key_iter() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = get_map_mut(&mut obj, "start");

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

#[tag(root)]
#[test]
fn test_object_map_key_iter_empty() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = get_map_mut(&mut obj, "start");
    let mut count = 0;
    for _ in start.keys() {
        count += 1;
    }
    assert_eq!(count, 0);
}

#[tag(root)]
#[test]
fn test_object_map_pin() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let mut map = get_map_mut(&mut obj, "start");
    let path = "/sys/fs/bpf/mymap_test_object_map_pin";

    // Unpinning a unpinned map should be an error
    assert!(map.unpin(path).is_err());
    assert!(!Path::new(path).exists());

    // Pin and unpin should be successful
    map.pin(path).expect("failed to pin map");
    assert!(Path::new(path).exists());
    map.unpin(path).expect("failed to unpin map");
    assert!(!Path::new(path).exists());
}

#[tag(root)]
#[test]
fn test_object_loading_pinned_map_from_path() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let mut map = get_map_mut(&mut obj, "start");
    let path = "/sys/fs/bpf/mymap_test_pin_to_load_from_path";

    map.pin(path).expect("pinning map failed");

    let pinned_map = MapHandle::from_pinned_path(path).expect("loading a map from a path failed");
    map.unpin(path).expect("unpinning map failed");

    assert_eq!(map.name(), pinned_map.name());
    assert_eq!(
        map.info().unwrap().info.id,
        pinned_map.info().unwrap().info.id
    );
}

#[tag(root)]
#[test]
fn test_program_loading_fd_from_pinned_path() {
    bump_rlimit_mlock();

    let path = "/sys/fs/bpf/myprog_test_pin_to_load_from_path";
    let prog_name = "handle__sched_switch";

    let mut obj = get_test_object("runqslower.bpf.o");
    let mut prog = get_prog_mut(&mut obj, prog_name);
    prog.pin(path).expect("pinning prog failed");
    let prog_id = Program::id_from_fd(prog.as_fd()).expect("failed to determine prog id");

    let pinned_prog_fd =
        Program::fd_from_pinned_path(path).expect("failed to get fd of pinned prog");
    let pinned_prog_id =
        Program::id_from_fd(pinned_prog_fd.as_fd()).expect("failed to determine pinned prog id");

    assert_eq!(prog_id, pinned_prog_id);

    prog.unpin(path).expect("unpinning program failed");
}

#[tag(root)]
#[test]
fn test_program_loading_fd_from_pinned_path_with_wrong_pin_type() {
    bump_rlimit_mlock();

    let path = "/sys/fs/bpf/mymap_test_pin_to_load_from_path";
    let map_name = "events";

    let mut obj = get_test_object("runqslower.bpf.o");
    let mut map = get_map_mut(&mut obj, map_name);
    map.pin(path).expect("pinning map failed");

    // Must fail, as the pinned path points to a map, not program.
    let _ = Program::fd_from_pinned_path(path).expect_err("program fd obtained from pinned map");

    map.unpin(path).expect("unpinning program failed");
}

#[tag(root)]
#[test]
fn test_object_loading_loaded_map_from_id() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let map = get_map_mut(&mut obj, "start");
    let id = map.info().expect("to get info from map 'start'").info.id;

    let map_by_id = MapHandle::from_map_id(id).expect("map to load from id");

    assert_eq!(map.name(), map_by_id.name());
    assert_eq!(
        map.info().unwrap().info.id,
        map_by_id.info().unwrap().info.id
    );
}

#[tag(root)]
#[test]
fn test_object_programs() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let _prog = get_prog_mut(&mut obj, "handle__sched_wakeup");
    let _prog = get_prog_mut(&mut obj, "handle__sched_wakeup_new");
    let _prog = get_prog_mut(&mut obj, "handle__sched_switch");
    assert!(!obj.progs().any(|prog| prog.name() == OsStr::new("asdf")));
}

#[tag(root)]
#[test]
fn test_object_programs_iter_mut() {
    bump_rlimit_mlock();

    let obj = get_test_object("runqslower.bpf.o");
    assert!(obj.progs().count() == 3);
}

#[tag(root)]
#[test]
fn test_object_program_pin() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let mut prog = get_prog_mut(&mut obj, "handle__sched_wakeup");
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

    // Unpin should be successful
    prog.unpin(path).expect("failed to unpin prog");
    assert!(!Path::new(path).exists());
}

#[tag(root)]
#[test]
fn test_object_link_pin() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__sched_wakeup");
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

#[tag(root)]
#[test]
fn test_object_reuse_pined_map() {
    bump_rlimit_mlock();

    let path = "/sys/fs/bpf/mymap_test_object_reuse_pined_map";
    let key = vec![1, 2, 3, 4];
    let val = vec![1, 2, 3, 4, 5, 6, 7, 8];

    // Pin a map
    {
        let mut obj = get_test_object("runqslower.bpf.o");
        let mut map = get_map_mut(&mut obj, "start");
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
    let obj_path = get_test_object_path("runqslower.bpf.o");
    let mut builder = ObjectBuilder::default();
    builder.debug(true);
    let mut open_obj = builder.open_file(obj_path).expect("failed to open object");
    let mut start = open_obj
        .maps_mut()
        .find(|map| map.name() == OsStr::new("start"))
        .expect("failed to find `start` map");
    assert!(start.reuse_pinned_map("/asdf").is_err());
    start.reuse_pinned_map(path).expect("failed to reuse map");

    let mut obj = open_obj.load().expect("failed to load object");
    let mut reused_map = get_map_mut(&mut obj, "start");
    let found_val = reused_map
        .lookup(&key, MapFlags::empty())
        .expect("failed to read map")
        .expect("failed to find key");
    assert_eq!(&found_val, &val);

    // Cleanup
    reused_map.unpin(path).expect("failed to unpin map");
    assert!(!Path::new(path).exists());
}

#[tag(root)]
#[test]
fn test_object_ringbuf_raw() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("ringbuf.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getpid");
    let _link = prog.attach().expect("failed to attach prog");

    static mut V1: i32 = 0;
    static mut V2: i32 = 0;

    fn callback1(data: &[u8]) -> i32 {
        let mut value: i32 = 0;
        plain::copy_from_bytes(&mut value, data).expect("Wrong size");

        unsafe {
            V1 = value;
        }

        0
    }

    fn callback2(data: &[u8]) -> i32 {
        let mut value: i32 = 0;
        plain::copy_from_bytes(&mut value, data).expect("Wrong size");

        unsafe {
            V2 = value;
        }

        0
    }

    // Test trying to build without adding any ringbufs
    // Can't use expect_err here since RingBuffer does not implement Debug
    let builder = libbpf_rs::RingBufferBuilder::new();
    assert!(
        builder.build().is_err(),
        "Should not be able to build without adding at least one ringbuf"
    );

    // Test building with multiple map objects
    let mut builder = libbpf_rs::RingBufferBuilder::new();

    // Add a first map and callback
    let map1 = get_map(&obj, "ringbuf1");
    builder
        .add(&map1, callback1)
        .expect("failed to add ringbuf");

    // Add a second map and callback
    let map2 = get_map(&obj, "ringbuf2");
    builder
        .add(&map2, callback2)
        .expect("failed to add ringbuf");

    let mgr = builder.build().expect("failed to build");

    // Call getpid to ensure the BPF program runs
    unsafe { libc::getpid() };

    // Test raw primitives
    let ret = mgr.consume_raw();

    // We can't check for exact return values, since other tasks in the system may call getpid(),
    // triggering the BPF program
    assert!(ret >= 2);

    unsafe { assert_eq!(V1, 1) };
    unsafe { assert_eq!(V2, 2) };

    // Consume from a (potentially) empty ring buffer
    let ret = mgr.consume_raw();
    assert!(ret >= 0);

    // Consume from a (potentially) empty ring buffer using poll()
    let ret = mgr.poll_raw(Duration::from_millis(100));
    assert!(ret >= 0);
}

#[tag(root)]
#[test]
fn test_object_ringbuf_err_callback() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("ringbuf.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getpid");
    let _link = prog.attach().expect("failed to attach prog");

    // Immediately trigger an error that should be reported back to the consume_raw() or poll_raw()
    fn callback1(_data: &[u8]) -> i32 {
        -libc::ENOENT
    }

    // Immediately trigger an error that should be reported back to the consume_raw() or poll_raw()
    fn callback2(_data: &[u8]) -> i32 {
        -libc::EPERM
    }

    // Test trying to build without adding any ringbufs
    // Can't use expect_err here since RingBuffer does not implement Debug
    let builder = libbpf_rs::RingBufferBuilder::new();
    assert!(
        builder.build().is_err(),
        "Should not be able to build without adding at least one ringbuf"
    );

    // Test building with multiple map objects
    let mut builder = libbpf_rs::RingBufferBuilder::new();

    // Add a first map and callback
    let map1 = get_map(&obj, "ringbuf1");
    builder
        .add(&map1, callback1)
        .expect("failed to add ringbuf");

    // Add a second map and callback
    let map2 = get_map(&obj, "ringbuf2");
    builder
        .add(&map2, callback2)
        .expect("failed to add ringbuf");

    let mgr = builder.build().expect("failed to build");

    // Call getpid to ensure the BPF program runs
    unsafe { libc::getpid() };

    // Test raw primitives
    let ret = mgr.consume_raw();

    // The error originated from the first callback executed should be reported here, either
    // from callback1() or callback2()
    assert!(ret == -libc::ENOENT || ret == -libc::EPERM);

    unsafe { libc::getpid() };

    // The same behavior should happen with poll_raw()
    let ret = mgr.poll_raw(Duration::from_millis(100));

    assert!(ret == -libc::ENOENT || ret == -libc::EPERM);
}

#[tag(root)]
#[test]
fn test_object_ringbuf() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("ringbuf.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getpid");
    let _link = prog.attach().expect("failed to attach prog");

    static mut V1: i32 = 0;
    static mut V2: i32 = 0;

    fn callback1(data: &[u8]) -> i32 {
        let mut value: i32 = 0;
        plain::copy_from_bytes(&mut value, data).expect("Wrong size");

        unsafe {
            V1 = value;
        }

        0
    }

    fn callback2(data: &[u8]) -> i32 {
        let mut value: i32 = 0;
        plain::copy_from_bytes(&mut value, data).expect("Wrong size");

        unsafe {
            V2 = value;
        }

        0
    }

    // Test trying to build without adding any ringbufs
    // Can't use expect_err here since RingBuffer does not implement Debug
    let builder = libbpf_rs::RingBufferBuilder::new();
    assert!(
        builder.build().is_err(),
        "Should not be able to build without adding at least one ringbuf"
    );

    // Test building with multiple map objects
    let mut builder = libbpf_rs::RingBufferBuilder::new();

    // Add a first map and callback
    let map1 = get_map(&obj, "ringbuf1");
    builder
        .add(&map1, callback1)
        .expect("failed to add ringbuf");

    // Add a second map and callback
    let map2 = get_map(&obj, "ringbuf2");
    builder
        .add(&map2, callback2)
        .expect("failed to add ringbuf");

    let mgr = builder.build().expect("failed to build");

    // Call getpid to ensure the BPF program runs
    unsafe { libc::getpid() };

    // This should result in both callbacks being called
    mgr.consume().expect("failed to consume ringbuf");

    // Our values should both reflect that the callbacks have been called
    unsafe { assert_eq!(V1, 1) };
    unsafe { assert_eq!(V2, 2) };

    // Reset both values
    unsafe { V1 = 0 };
    unsafe { V2 = 0 };

    // Call getpid to ensure the BPF program runs
    unsafe { libc::getpid() };

    // This should result in both callbacks being called
    mgr.poll(Duration::from_millis(100))
        .expect("failed to poll ringbuf");

    // Our values should both reflect that the callbacks have been called
    unsafe { assert_eq!(V1, 1) };
    unsafe { assert_eq!(V2, 2) };
}

#[tag(root)]
#[test]
fn test_object_ringbuf_closure() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("ringbuf.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getpid");
    let _link = prog.attach().expect("failed to attach prog");

    let (sender1, receiver1) = channel();
    let callback1 = move |data: &[u8]| -> i32 {
        let mut value: i32 = 0;
        plain::copy_from_bytes(&mut value, data).expect("Wrong size");

        sender1.send(value).expect("failed to send value");

        0
    };

    let (sender2, receiver2) = channel();
    let callback2 = move |data: &[u8]| -> i32 {
        let mut value: i32 = 0;
        plain::copy_from_bytes(&mut value, data).expect("Wrong size");

        sender2.send(value).expect("failed to send value");

        0
    };

    // Test trying to build without adding any ringbufs
    // Can't use expect_err here since RingBuffer does not implement Debug
    let builder = libbpf_rs::RingBufferBuilder::new();
    assert!(
        builder.build().is_err(),
        "Should not be able to build without adding at least one ringbuf"
    );

    // Test building with multiple map objects
    let mut builder = libbpf_rs::RingBufferBuilder::new();

    // Add a first map and callback
    let map1 = get_map(&obj, "ringbuf1");
    builder
        .add(&map1, callback1)
        .expect("failed to add ringbuf");

    // Add a second map and callback
    let map2 = get_map(&obj, "ringbuf2");
    builder
        .add(&map2, callback2)
        .expect("failed to add ringbuf");

    let mgr = builder.build().expect("failed to build");

    // Call getpid to ensure the BPF program runs
    unsafe { libc::getpid() };

    // This should result in both callbacks being called
    mgr.consume().expect("failed to consume ringbuf");

    let v1 = receiver1.recv().expect("failed to receive value");
    let v2 = receiver2.recv().expect("failed to receive value");

    assert_eq!(v1, 1);
    assert_eq!(v2, 2);
}

/// Check that `RingBuffer` works correctly even if the map file descriptors
/// provided during construction are closed. This test validates that `libbpf`'s
/// refcount behavior is correctly reflected in our `RingBuffer` lifetimes.
#[tag(root)]
#[test]
fn test_object_ringbuf_with_closed_map() {
    bump_rlimit_mlock();

    fn test(poll_fn: impl FnOnce(&libbpf_rs::RingBuffer)) {
        let mut value = 0i32;

        {
            let mut obj = get_test_object("tracepoint.bpf.o");
            let prog = get_prog_mut(&mut obj, "handle__tracepoint");
            let _link = prog
                .attach_tracepoint("syscalls", "sys_enter_getpid")
                .expect("failed to attach prog");

            let map = get_map_mut(&mut obj, "ringbuf");

            let callback = |data: &[u8]| {
                plain::copy_from_bytes(&mut value, data).expect("Wrong size");
                0
            };

            let mut builder = libbpf_rs::RingBufferBuilder::new();
            builder.add(&map, callback).expect("failed to add ringbuf");
            let ringbuf = builder.build().expect("failed to build");

            drop(obj);

            // Trigger the tracepoint. At this point `map` along with the containing
            // `obj` have been destroyed.
            let _pid = unsafe { libc::getpid() };
            let () = poll_fn(&ringbuf);
        }

        // If we see a 1 here the ring buffer was still working as expected.
        assert_eq!(value, 1);
    }

    test(|ringbuf| ringbuf.consume().expect("failed to consume ringbuf"));
    test(|ringbuf| {
        ringbuf
            .poll(Duration::from_secs(5))
            .expect("failed to poll ringbuf")
    });
}

#[tag(root)]
#[test]
fn test_object_user_ringbuf() {
    #[repr(C)]
    struct MyStruct {
        key: u32,
        value: u32,
    }

    unsafe impl Plain for MyStruct {}

    bump_rlimit_mlock();

    let mut obj = get_test_object("user_ringbuf.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getpid");
    let _link = prog.attach().expect("failed to attach prog");
    let urb_map = get_map_mut(&mut obj, "user_ringbuf");
    let user_ringbuf = UserRingBuffer::new(&urb_map).expect("failed to create user ringbuf");
    let mut urb_sample = user_ringbuf
        .reserve(size_of::<MyStruct>())
        .expect("failed to reserve space");
    let bytes = urb_sample.as_mut();
    let my_struct = plain::from_mut_bytes::<MyStruct>(bytes).expect("failed to convert bytes");
    my_struct.key = 42;
    my_struct.value = 1337;
    user_ringbuf
        .submit(urb_sample)
        .expect("failed to submit sample");

    // Trigger BPF program.
    let _pid = unsafe { libc::getpid() };

    // At this point, the BPF program should have run and consumed the sample in
    // the user ring buffer, and stored the key/value in the samples map.
    let samples_map = get_map_mut(&mut obj, "samples");
    let key: u32 = 42;
    let value: u32 = 1337;
    let res = samples_map
        .lookup(&key.to_ne_bytes(), MapFlags::ANY)
        .expect("failed to lookup")
        .expect("failed to find value for key");

    // The value in the samples map should be the same as the value we submitted
    assert_eq!(res.len(), size_of::<u32>());
    let mut array = [0; size_of::<u32>()];
    array.copy_from_slice(&res[..]);
    assert_eq!(u32::from_ne_bytes(array), value);
}

#[tag(root)]
#[test]
fn test_object_user_ringbuf_reservation_too_big() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("user_ringbuf.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getpid");
    let _link = prog.attach().expect("failed to attach prog");
    let urb_map = get_map_mut(&mut obj, "user_ringbuf");
    let user_ringbuf = UserRingBuffer::new(&urb_map).expect("failed to create user ringbuf");
    let err = user_ringbuf.reserve(1024 * 1024).unwrap_err();
    assert!(
        err.to_string().contains("requested size is too large"),
        "{err:#}"
    );
}

#[tag(root)]
#[test]
fn test_object_user_ringbuf_not_enough_space() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("user_ringbuf.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getpid");
    let _link = prog.attach().expect("failed to attach prog");
    let urb_map = get_map_mut(&mut obj, "user_ringbuf");
    let user_ringbuf = UserRingBuffer::new(&urb_map).expect("failed to create user ringbuf");
    let _ = user_ringbuf
        .reserve(1024 * 3)
        .expect("failed to reserve space");
    let err = user_ringbuf.reserve(1024 * 3).unwrap_err();
    assert!(
        err.to_string()
            .contains("not enough space in the ring buffer"),
        "{err:#}"
    );
}

#[tag(root)]
#[test]
fn test_object_task_iter() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("taskiter.bpf.o");
    let prog = get_prog_mut(&mut obj, "dump_pid");
    let link = prog.attach().expect("failed to attach prog");
    let mut iter = Iter::new(&link).expect("failed to create iterator");

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IndexPidPair {
        i: u32,
        pid: i32,
    }

    unsafe impl Plain for IndexPidPair {}

    let mut buf = Vec::new();
    let bytes_read = iter
        .read_to_end(&mut buf)
        .expect("failed to read from iterator");

    assert!(bytes_read > 0);
    assert_eq!(bytes_read % size_of::<IndexPidPair>(), 0);
    let items: &[IndexPidPair] =
        plain::slice_from_bytes(buf.as_slice()).expect("Input slice cannot satisfy length");

    assert!(!items.is_empty());
    assert_eq!(items[0].i, 0);
    assert!(items.windows(2).all(|w| w[0].i + 1 == w[1].i));
    // Check for init
    assert!(items.iter().any(|&item| item.pid == 1));
}

#[tag(root)]
#[test]
fn test_object_map_iter() {
    bump_rlimit_mlock();

    // Create a map for iteration test.
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
        ..Default::default()
    };
    let map = MapHandle::create(
        MapType::Hash,
        Some("mymap_test_object_map_iter"),
        4,
        8,
        8,
        &opts,
    )
    .expect("failed to create map");

    // Insert 3 elements.
    for i in 0..3 {
        let key = i32::to_ne_bytes(i);
        // We can change i to larger for more robust test, that's why we use a and b.
        let val = [&key[..], &[0_u8; 4]].concat();
        map.update(&key, val.as_slice(), MapFlags::empty())
            .expect("failed to write");
    }

    let mut obj = get_test_object("mapiter.bpf.o");
    let prog = get_prog_mut(&mut obj, "map_iter");
    let link = prog
        .attach_iter(map.as_fd())
        .expect("failed to attach map iter prog");
    let mut iter = Iter::new(&link).expect("failed to create map iterator");

    let mut buf = Vec::new();
    let bytes_read = iter
        .read_to_end(&mut buf)
        .expect("failed to read from iterator");

    assert!(bytes_read > 0);
    assert_eq!(bytes_read % size_of::<u32>(), 0);
    // Convert buf to &[u32]
    let buf =
        plain::slice_from_bytes::<u32>(buf.as_slice()).expect("Input slice cannot satisfy length");
    assert!(buf.contains(&0));
    assert!(buf.contains(&1));
    assert!(buf.contains(&2));
}

#[tag(root)]
#[test]
fn test_object_map_create_and_pin() {
    bump_rlimit_mlock();

    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
        ..Default::default()
    };

    let mut map = MapHandle::create(
        MapType::Hash,
        Some("mymap_test_object_map_create_and_pin"),
        4,
        8,
        8,
        &opts,
    )
    .expect("failed to create map");

    assert_eq!(map.name(), "mymap_test_object_map_create_and_pin");

    let key = vec![1, 2, 3, 4];
    let val = vec![1, 2, 3, 4, 5, 6, 7, 8];
    map.update(&key, &val, MapFlags::empty())
        .expect("failed to write");
    let res = map
        .lookup(&key, MapFlags::ANY)
        .expect("failed to lookup")
        .expect("failed to find value for key");
    assert_eq!(val, res);

    let path = "/sys/fs/bpf/mymap_test_object_map_create_and_pin";

    // Unpinning a unpinned map should be an error
    assert!(map.unpin(path).is_err());
    assert!(!Path::new(path).exists());

    // Pin and unpin should be successful
    map.pin(path).expect("failed to pin map");
    assert!(Path::new(path).exists());
    map.unpin(path).expect("failed to unpin map");
    assert!(!Path::new(path).exists());
}

#[tag(root)]
#[test]
fn test_object_map_create_without_name() {
    bump_rlimit_mlock();

    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
        btf_fd: 0,
        btf_key_type_id: 0,
        btf_value_type_id: 0,
        btf_vmlinux_value_type_id: 0,
        inner_map_fd: 0,
        map_extra: 0,
        numa_node: 0,
        map_ifindex: 0,
        // bpf_map_create_opts might have padding fields on some platform
        ..Default::default()
    };

    let map = MapHandle::create(MapType::Hash, Option::<&str>::None, 4, 8, 8, &opts)
        .expect("failed to create map");

    assert!(map.name().is_empty());

    let key = vec![1, 2, 3, 4];
    let val = vec![1, 2, 3, 4, 5, 6, 7, 8];
    map.update(&key, &val, MapFlags::empty())
        .expect("failed to write");
    let res = map
        .lookup(&key, MapFlags::ANY)
        .expect("failed to lookup")
        .expect("failed to find value for key");
    assert_eq!(val, res);
}

/// Test whether we can obtain multiple `MapHandle`s from a `Map
#[tag(root)]
#[test]
fn test_object_map_handle_clone() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let map = get_map_mut(&mut obj, "events");
    let handle1 = MapHandle::try_from(&map).expect("failed to create handle from Map");
    assert_eq!(map.name(), handle1.name());
    assert_eq!(map.map_type(), handle1.map_type());
    assert_eq!(map.key_size(), handle1.key_size());
    assert_eq!(map.value_size(), handle1.value_size());

    let handle2 = MapHandle::try_from(&handle1).expect("failed to duplicate existing handle");
    assert_eq!(handle1.name(), handle2.name());
    assert_eq!(handle1.map_type(), handle2.map_type());
    assert_eq!(handle1.key_size(), handle2.key_size());
    assert_eq!(handle1.value_size(), handle2.value_size());

    let info1 = map.info().expect("failed to get map info from map");
    let info2 = handle2.info().expect("failed to get map info from handle");
    assert_eq!(
        info1.info.id, info2.info.id,
        "Map and MapHandle have different IDs"
    );
}

#[cfg(not(any(
    all(target_arch = "powerpc64", target_endian = "little"),
    target_arch = "s390x"
)))]
#[tag(root)]
#[test]
fn test_object_usdt() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("usdt.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__usdt");

    let path = current_exe().expect("failed to find executable name");
    let _link = prog
        .attach_usdt(
            unsafe { libc::getpid() },
            &path,
            "test_provider",
            "test_function",
        )
        .expect("failed to attach prog");

    let map = get_map_mut(&mut obj, "ringbuf");
    let action = || {
        // Define a USDT probe point and exercise it as we are attaching to self.
        probe!(test_provider, test_function, 1);
    };
    let result = with_ringbuffer(&map, action);

    assert_eq!(result, 1);
}

#[cfg(not(any(
    all(target_arch = "powerpc64", target_endian = "little"),
    target_arch = "s390x"
)))]
#[tag(root)]
#[test]
fn test_object_usdt_cookie() {
    bump_rlimit_mlock();

    let cookie_val = 1337u16;
    let mut obj = get_test_object("usdt.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__usdt_with_cookie");

    let path = current_exe().expect("failed to find executable name");
    let _link = prog
        .attach_usdt_with_opts(
            unsafe { libc::getpid() },
            &path,
            "test_provider",
            "test_function2",
            UsdtOpts {
                cookie: cookie_val.into(),
                ..UsdtOpts::default()
            },
        )
        .expect("failed to attach prog");

    let map = get_map_mut(&mut obj, "ringbuf");
    let action = || {
        // Define a USDT probe point and exercise it as we are attaching to self.
        probe!(test_provider, test_function2, 1);
    };
    let result = with_ringbuffer(&map, action);

    assert_eq!(result, cookie_val.into());
}

#[tag(root)]
#[test]
fn test_map_probes() {
    bump_rlimit_mlock();

    let supported = MapType::Array
        .is_supported()
        .expect("failed to query if Array map is supported");
    assert!(supported);
    let supported_res = MapType::Unknown.is_supported();
    assert!(supported_res.is_err());
}

#[tag(root)]
#[test]
fn test_program_probes() {
    bump_rlimit_mlock();

    let supported = ProgramType::SocketFilter
        .is_supported()
        .expect("failed to query if SocketFilter program is supported");
    assert!(supported);
    let supported_res = ProgramType::Unknown.is_supported();
    assert!(supported_res.is_err());
}

#[tag(root)]
#[test]
fn test_program_helper_probes() {
    bump_rlimit_mlock();

    let supported = ProgramType::SocketFilter
        .is_helper_supported(libbpf_sys::BPF_FUNC_map_lookup_elem)
        .expect("failed to query if helper supported");
    assert!(supported);
    // redirect should not be supported from socket filter, as it is only used in TC/XDP.
    let supported = ProgramType::SocketFilter
        .is_helper_supported(libbpf_sys::BPF_FUNC_redirect)
        .expect("failed to query if helper supported");
    assert!(!supported);
    let supported_res = MapType::Unknown.is_supported();
    assert!(supported_res.is_err());
}

#[tag(root)]
#[test]
fn test_object_open_program_insns() {
    bump_rlimit_mlock();

    let open_obj = open_test_object("usdt.bpf.o");
    let prog = open_obj
        .progs()
        .find(|prog| prog.name() == OsStr::new("handle__usdt"))
        .expect("failed to find program");

    let insns = prog.insns();
    assert!(!insns.is_empty());
}

#[tag(root)]
#[test]
fn test_object_program_insns() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("usdt.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__usdt");
    let insns = prog.insns();
    assert!(!insns.is_empty());
}

/// Check that we can attach a BPF program to a kernel tracepoint.
#[tag(root)]
#[test]
fn test_object_tracepoint() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("tracepoint.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__tracepoint");
    let _link = prog
        .attach_tracepoint("syscalls", "sys_enter_getpid")
        .expect("failed to attach prog");

    let map = get_map_mut(&mut obj, "ringbuf");
    let action = || {
        let _pid = unsafe { libc::getpid() };
    };
    let result = with_ringbuffer(&map, action);

    assert_eq!(result, 1);
}

/// Check that we can attach a BPF program to a kernel tracepoint, providing
/// additional options.
#[tag(root)]
#[test]
fn test_object_tracepoint_with_opts() {
    bump_rlimit_mlock();

    let cookie_val = 42u16;
    let mut obj = get_test_object("tracepoint.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__tracepoint_with_cookie");

    let opts = TracepointOpts {
        cookie: cookie_val.into(),
        ..TracepointOpts::default()
    };
    let _link = prog
        .attach_tracepoint_with_opts("syscalls", "sys_enter_getpid", opts)
        .expect("failed to attach prog");

    let map = get_map_mut(&mut obj, "ringbuf");
    let action = || {
        let _pid = unsafe { libc::getpid() };
    };
    let result = with_ringbuffer(&map, action);

    assert_eq!(result, cookie_val.into());
}

#[inline(never)]
#[no_mangle]
extern "C" fn uprobe_target() -> usize {
    // Use `black_box` here as an additional barrier to inlining.
    hint::black_box(42)
}

/// Check that we can attach a BPF program to a uprobe.
#[tag(root)]
#[test]
fn test_object_uprobe_with_opts() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("uprobe.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__uprobe");

    let pid = unsafe { libc::getpid() };
    let path = current_exe().expect("failed to find executable name");
    let func_offset = 0;
    let opts = UprobeOpts {
        func_name: "uprobe_target".to_string(),
        ..Default::default()
    };
    let _link = prog
        .attach_uprobe_with_opts(pid, path, func_offset, opts)
        .expect("failed to attach prog");

    let map = get_map_mut(&mut obj, "ringbuf");
    let action = || {
        let _ = uprobe_target();
    };
    let result = with_ringbuffer(&map, action);

    assert_eq!(result, 1);
}

/// Check that we can attach a BPF program to a uprobe and access the cookie
/// provided during attach.
#[tag(root)]
#[test]
fn test_object_uprobe_with_cookie() {
    bump_rlimit_mlock();

    let cookie_val = 5u16;
    let mut obj = get_test_object("uprobe.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__uprobe_with_cookie");

    let pid = unsafe { libc::getpid() };
    let path = current_exe().expect("failed to find executable name");
    let func_offset = 0;
    let opts = UprobeOpts {
        func_name: "uprobe_target".to_string(),
        cookie: cookie_val.into(),
        ..Default::default()
    };
    let _link = prog
        .attach_uprobe_with_opts(pid, path, func_offset, opts)
        .expect("failed to attach prog");

    let map = get_map_mut(&mut obj, "ringbuf");
    let action = || {
        let _ = uprobe_target();
    };
    let result = with_ringbuffer(&map, action);

    assert_eq!(result, cookie_val.into());
}

/// Check that we can link multiple object files.
#[test]
fn test_object_link_files() {
    fn test(files: Vec<PathBuf>) {
        let output_file = NamedTempFile::new().unwrap();

        let mut linker = Linker::new(output_file.path()).unwrap();
        let () = files
            .into_iter()
            .try_for_each(|file| linker.add_file(file))
            .unwrap();
        let () = linker.link().unwrap();

        // Check that we can load the resulting object file.
        let _object = ObjectBuilder::default()
            .debug(true)
            .open_file(output_file.path())
            .unwrap();
    }

    let obj_path1 = get_test_object_path("usdt.bpf.o");
    let obj_path2 = get_test_object_path("ringbuf.bpf.o");

    test(vec![obj_path1.clone()]);
    test(vec![obj_path1, obj_path2]);
}

/// Get access to the underlying per-cpu ring buffer data.
fn buffer<'a>(perf: &'a libbpf_rs::PerfBuffer, buf_idx: usize) -> &'a [u8] {
    let perf_buff_ptr = perf.as_libbpf_object();
    let mut buffer_data_ptr: *mut c_void = ptr::null_mut();
    let mut buffer_size: usize = 0;
    let ret = unsafe {
        libbpf_sys::perf_buffer__buffer(
            perf_buff_ptr.as_ptr(),
            buf_idx as i32,
            ptr::addr_of_mut!(buffer_data_ptr),
            ptr::addr_of_mut!(buffer_size) as *mut libbpf_sys::size_t,
        )
    };
    assert!(ret >= 0);
    unsafe { slice::from_raw_parts(buffer_data_ptr as *const u8, buffer_size) }
}

/// Check that we can see the raw ring buffer of the perf buffer and find a
/// value we have sent.
#[tag(root)]
#[test]
fn test_object_perf_buffer_raw() {
    use memmem::Searcher;
    use memmem::TwoWaySearcher;

    bump_rlimit_mlock();

    let cookie_val = 42u16;
    let mut obj = get_test_object("tracepoint.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__tracepoint_with_cookie_pb");

    let opts = TracepointOpts {
        cookie: cookie_val.into(),
        ..TracepointOpts::default()
    };
    let _link = prog
        .attach_tracepoint_with_opts("syscalls", "sys_enter_getpid", opts)
        .expect("failed to attach prog");

    let map = get_map_mut(&mut obj, "pb");
    let cookie_bytes = cookie_val.to_ne_bytes();
    let searcher = TwoWaySearcher::new(&cookie_bytes[..]);

    let perf = libbpf_rs::PerfBufferBuilder::new(&map)
        .build()
        .expect("failed to build");

    // Make an action that the tracepoint will see
    let _pid = unsafe { libc::getpid() };

    let found_cookie = (0..perf.buffer_cnt()).any(|buf_idx| {
        let buf = buffer(&perf, buf_idx);
        searcher.search_in(buf).is_some()
    });

    assert!(found_cookie);
}

/// Check that we can get map pin status and map pin path
#[tag(root)]
#[test]
fn test_map_pinned_status() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("map_auto_pin.bpf.o");
    let map = get_map_mut(&mut obj, "auto_pin_map");
    let is_pinned = map.is_pinned();
    assert!(is_pinned);
    let expected_path = "/sys/fs/bpf/auto_pin_map";
    let get_path = map.get_pin_path().expect("get map pin path failed");
    assert_eq!(expected_path, get_path.to_str().unwrap());
    // cleanup
    let _ = fs::remove_file(expected_path);
}

/// Change the root_pin_path and see if it works.
#[tag(root)]
#[test]
fn test_map_pinned_status_with_pin_root_path() {
    bump_rlimit_mlock();

    let obj_path = get_test_object_path("map_auto_pin.bpf.o");
    let mut obj = ObjectBuilder::default()
        .debug(true)
        .pin_root_path("/sys/fs/bpf/test_namespace")
        .expect("root_pin_path failed")
        .open_file(obj_path)
        .expect("failed to open object")
        .load()
        .expect("failed to load object");

    let map = get_map_mut(&mut obj, "auto_pin_map");
    let is_pinned = map.is_pinned();
    assert!(is_pinned);
    let expected_path = "/sys/fs/bpf/test_namespace/auto_pin_map";
    let get_path = map.get_pin_path().expect("get map pin path failed");
    assert_eq!(expected_path, get_path.to_str().unwrap());
    // cleanup
    let _ = fs::remove_file(expected_path);
    let _ = fs::remove_dir("/sys/fs/bpf/test_namespace");
}

/// Check that we can get program fd by id and vice versa.
#[tag(root)]
#[test]
fn test_program_get_fd_and_id() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__sched_wakeup");
    let prog_fd = prog.as_fd();
    let prog_id = Program::id_from_fd(prog_fd).expect("failed to get program id from fd");
    let _owned_prog_fd = Program::fd_from_id(prog_id).expect("failed to get program fd from id");
}

/// Check that autocreate disabled maps don't prevent object loading
#[tag(root)]
#[test]
fn test_map_autocreate_disable() {
    bump_rlimit_mlock();

    let mut open_obj = open_test_object("map_auto_pin.bpf.o");
    let mut auto_pin_map = open_obj
        .maps_mut()
        .find(|map| map.name() == OsStr::new("auto_pin_map"))
        .expect("failed to find `auto_pin_map` map");
    auto_pin_map
        .set_autocreate(false)
        .expect("set_autocreate() failed");

    open_obj.load().expect("failed to load object");
}

/// Check that we can resize a map.
#[tag(root)]
#[test]
fn test_map_resize() {
    bump_rlimit_mlock();

    let mut open_obj = open_test_object("map_auto_pin.bpf.o");
    let mut resizable = open_obj
        .maps_mut()
        .find(|map| map.name() == OsStr::new(".data.resizable_data"))
        .expect("failed to find `.data.resizable_data` map");

    let len = resizable.initial_value().unwrap().len();
    assert_eq!(len, size_of::<u64>());

    let () = resizable
        .set_value_size(len as u32 * 2)
        .expect("failed to set value size");
    let new_len = resizable.initial_value().unwrap().len();
    assert_eq!(new_len, len * 2);
}

/// Check that we are able to attach using ksyscall
#[tag(root)]
#[test]
fn test_attach_ksyscall() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("ksyscall.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle__ksyscall");
    let _link = prog
        .attach_ksyscall(false, "kill")
        .expect("failed to attach prog");

    let map = get_map_mut(&mut obj, "ringbuf");
    let action = || {
        // Send `SIGCHLD`, which is ignored by default, to our process.
        let ret = unsafe { libc::kill(libc::getpid(), libc::SIGCHLD) };
        if ret < 0 {
            panic!("kill failed: {}", io::Error::last_os_error());
        }
    };
    let result = with_ringbuffer(&map, action);

    assert_eq!(result, 1);
}

/// Check that we can invoke a program directly.
#[tag(root)]
#[test]
fn test_run_prog_success() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("run_prog.bpf.o");
    let prog = get_prog_mut(&mut obj, "test_1");

    #[repr(C)]
    struct bpf_dummy_ops_state {
        val: c_int,
    }

    let value = 42;
    let state = bpf_dummy_ops_state { val: value };
    let mut args = [addr_of!(state) as u64];
    let input = ProgramInput {
        context_in: Some(unsafe {
            slice::from_raw_parts_mut(&mut args as *mut _ as *mut u8, size_of_val(&args))
        }),
        ..Default::default()
    };
    let output = prog.test_run(input).unwrap();
    assert_eq!(output.return_value, value as _);
}

/// Check that we fail program invocation when providing insufficient arguments.
#[tag(root)]
#[test]
fn test_run_prog_fail() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("run_prog.bpf.o");
    let prog = get_prog_mut(&mut obj, "test_2");

    let input = ProgramInput::default();
    let _err = prog.test_run(input).unwrap_err();
}
