use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::mpsc::channel,
    time::Duration,
};

use nix::errno;
use plain::Plain;
use probe::probe;
use scopeguard::defer;

use libbpf_rs::{num_possible_cpus, Iter, Map, MapFlags, MapType, Object, ObjectBuilder};

fn get_test_object_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::new();
    // env!() macro fails at compile time if var not found
    path.push(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/bin");
    path.push(filename);
    path
}

pub fn get_test_object(filename: &str) -> Object {
    let obj_path = get_test_object_path(filename);
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
        errno::errno()
    );
}

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
        .open_memory("memory name", &contents)
        .expect("failed to build object");
    let name = obj.name().expect("failed to get object name");
    assert!(name == "memory name");
}

#[test]
fn test_object_name() {
    let obj_path = get_test_object_path("runqslower.bpf.o");
    let mut builder = ObjectBuilder::default();
    builder.name("test name");
    let obj = builder.open_file(obj_path).expect("failed to build object");
    let obj_name = obj.name().expect("failed to get object name");
    assert!(obj_name == "test name");
}

#[test]
fn test_object_maps() {
    bump_rlimit_mlock();

    let obj = get_test_object("runqslower.bpf.o");
    obj.map("start").expect("failed to find map");
    obj.map("events").expect("failed to find map");
    assert!(obj.map("asdf").is_none());
}

#[test]
fn test_object_maps_iter() {
    bump_rlimit_mlock();

    let obj = get_test_object("runqslower.bpf.o");
    for map in obj.maps_iter() {
        eprintln!("{}", map.name());
    }
    // This will include .rodata and .bss, so our expected count is 4, not 2
    assert!(obj.maps_iter().count() == 4);
}

#[test]
fn test_object_map_key_value_size() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = obj.map_mut("start").expect("failed to find map");

    assert!(start.lookup(&[1, 2, 3, 4, 5], MapFlags::empty()).is_err());
    assert!(start.delete(&[1]).is_err());
    assert!(start.lookup_and_delete(&[1, 2, 3, 4, 5]).is_err());
    assert!(start
        .update(&[1, 2, 3, 4, 5], &[1], MapFlags::empty())
        .is_err());
}

#[test]
fn test_object_percpu_lookup() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = obj.map_mut("percpu_map").expect("failed to find map");

    let res = map
        .lookup_percpu(&(0_u32).to_ne_bytes(), MapFlags::ANY)
        .expect("failed to lookup")
        .expect("failed to find value for key");

    assert_eq!(
        res.len(),
        num_possible_cpus().expect("must be one value per cpu")
    );
    assert_eq!(res[0].len(), std::mem::size_of::<u32>());
}

#[test]
fn test_object_percpu_invalid_lookup_fn() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = obj.map_mut("percpu_map").expect("failed to find map");

    assert!(map.lookup(&(0_u32).to_ne_bytes(), MapFlags::ANY).is_err());
}

#[test]
fn test_object_percpu_update() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = obj.map_mut("percpu_map").expect("failed to find map");
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

#[test]
fn test_object_percpu_invalid_update_fn() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = obj.map_mut("percpu_map").expect("failed to find map");
    let key = (0_u32).to_ne_bytes();

    let val = (1_u32).to_ne_bytes().to_vec();

    assert!(map.update(&key, &val, MapFlags::ANY).is_err());
}

#[test]
fn test_object_percpu_lookup_update() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("percpu_map.bpf.o");
    let map = obj.map_mut("percpu_map").expect("failed to find map");
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

#[test]
fn test_object_map_empty_lookup() {
    bump_rlimit_mlock();

    let obj = get_test_object("runqslower.bpf.o");
    let start = obj.map("start").expect("failed to find map");

    assert!(start
        .lookup(&[1, 2, 3, 4], MapFlags::empty())
        .expect("err in map lookup")
        .is_none());
}

#[test]
fn test_object_map_mutation() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = obj.map_mut("start").expect("failed to find map");

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

    let mut obj = get_test_object("runqslower.bpf.o");
    let start = obj.map_mut("start").expect("failed to find map");

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

    let mut obj = get_test_object("runqslower.bpf.o");

    let start = obj.map_mut("start").expect("failed to find map");

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

    let obj = get_test_object("runqslower.bpf.o");
    let start = obj.map("start").expect("failed to find map");

    let mut count = 0;
    for _ in start.keys() {
        count += 1;
    }
    assert_eq!(count, 0);
}

#[test]
fn test_object_map_pin() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let map = obj.map_mut("start").expect("failed to find map");

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

#[test]
fn test_object_programs() {
    bump_rlimit_mlock();

    let obj = get_test_object("runqslower.bpf.o");
    obj.prog("handle__sched_wakeup")
        .expect("failed to find program");
    obj.prog("handle__sched_wakeup_new")
        .expect("failed to find program");
    obj.prog("handle__sched_switch")
        .expect("failed to find program");
    assert!(obj.prog("asdf").is_none());
}

#[test]
fn test_object_programs_iter_mut() {
    bump_rlimit_mlock();

    let obj = get_test_object("runqslower.bpf.o");
    assert!(obj.progs_iter().count() == 3);
}

#[test]
fn test_object_program_pin() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let prog = obj
        .prog_mut("handle__sched_wakeup")
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

    // Unpin should be successful
    prog.unpin(path).expect("failed to unpin prog");
    assert!(!Path::new(path).exists());
}

#[test]
fn test_object_link_pin() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("runqslower.bpf.o");
    let prog = obj
        .prog_mut("handle__sched_wakeup")
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

    let path = "/sys/fs/bpf/mymap_test_object_reuse_pined_map";
    let key = vec![1, 2, 3, 4];
    let val = vec![1, 2, 3, 4, 5, 6, 7, 8];

    // Pin a map
    {
        let mut obj = get_test_object("runqslower.bpf.o");
        let map = obj.map_mut("start").expect("failed to find map");

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

    let start = open_obj.map_mut("start").expect("failed to find map");
    assert!(start.reuse_pinned_map("/asdf").is_err());
    start.reuse_pinned_map(path).expect("failed to reuse map");

    let mut obj = open_obj.load().expect("Failed to load object");
    let reused_map = obj.map_mut("start").expect("failed to find map");

    let found_val = reused_map
        .lookup(&key, MapFlags::empty())
        .expect("failed to read map")
        .expect("failed to find key");
    assert_eq!(&found_val, &val);

    // Cleanup
    reused_map.unpin(path).expect("failed to unpin map");
    assert!(!Path::new(path).exists());
}

#[test]
fn test_object_ringbuf() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("ringbuf.bpf.o");
    let prog = obj
        .prog_mut("handle__sys_enter_getpid")
        .expect("failed to find program");
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
    let map1 = obj.map("ringbuf1").expect("Failed to get ringbuf1 map");

    builder.add(map1, callback1).expect("Failed to add ringbuf");

    // Add a second map and callback
    let map2 = obj.map("ringbuf2").expect("Failed to get ringbuf2 map");

    builder.add(map2, callback2).expect("Failed to add ringbuf");

    let mgr = builder.build().expect("Failed to build");

    // Call getpid to ensure the BPF program runs
    unsafe { libc::getpid() };

    // This should result in both callbacks being called
    mgr.consume().expect("Failed to consume ringbuf");

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
        .expect("Failed to poll ringbuf");

    // Our values should both reflect that the callbacks have been called
    unsafe { assert_eq!(V1, 1) };
    unsafe { assert_eq!(V2, 2) };
}

#[test]
fn test_object_ringbuf_closure() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("ringbuf.bpf.o");
    let prog = obj
        .prog_mut("handle__sys_enter_getpid")
        .expect("failed to find program");
    let _link = prog.attach().expect("failed to attach prog");

    let (sender1, receiver1) = channel();
    let callback1 = move |data: &[u8]| -> i32 {
        let mut value: i32 = 0;
        plain::copy_from_bytes(&mut value, data).expect("Wrong size");

        sender1.send(value).expect("Failed to send value");

        0
    };

    let (sender2, receiver2) = channel();
    let callback2 = move |data: &[u8]| -> i32 {
        let mut value: i32 = 0;
        plain::copy_from_bytes(&mut value, data).expect("Wrong size");

        sender2.send(value).expect("Failed to send value");

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
    let map1 = obj.map("ringbuf1").expect("Failed to get ringbuf1 map");

    builder.add(map1, callback1).expect("Failed to add ringbuf");

    // Add a second map and callback
    let map2 = obj.map("ringbuf2").expect("Failed to get ringbuf2 map");

    builder.add(map2, callback2).expect("Failed to add ringbuf");

    let mgr = builder.build().expect("Failed to build");

    // Call getpid to ensure the BPF program runs
    unsafe { libc::getpid() };

    // This should result in both callbacks being called
    mgr.consume().expect("Failed to consume ringbuf");

    let v1 = receiver1.recv().expect("Failed to receive value");
    let v2 = receiver2.recv().expect("Failed to receive value");

    assert_eq!(v1, 1);
    assert_eq!(v2, 2);
}

#[test]
fn test_object_task_iter() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("taskiter.bpf.o");
    let prog = obj.prog_mut("dump_pid").expect("Failed to find program");
    let link = prog.attach().expect("Failed to attach prog");
    let mut iter = Iter::new(&link).expect("Failed to create iterator");

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
        .expect("Failed to read from iterator");

    assert!(bytes_read > 0);
    assert_eq!(bytes_read % std::mem::size_of::<IndexPidPair>(), 0);
    let items: &[IndexPidPair] =
        plain::slice_from_bytes(buf.as_slice()).expect("Input slice cannot satisfy length");

    assert!(!items.is_empty());
    assert_eq!(items[0].i, 0);
    assert!(items.windows(2).all(|w| w[0].i + 1 == w[1].i));
    // Check for init
    assert!(items.iter().any(|&item| item.pid == 1));
}

#[test]
fn test_object_map_create_and_pin() {
    bump_rlimit_mlock();

    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC as u32,
        btf_fd: 0,
        btf_key_type_id: 0,
        btf_value_type_id: 0,
        btf_vmlinux_value_type_id: 0,
        inner_map_fd: 0,
        map_extra: 0,
        numa_node: 0,
        map_ifindex: 0,
    };

    let mut map = Map::create(
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

#[test]
fn test_object_map_create_without_name() {
    bump_rlimit_mlock();

    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC as u32,
        btf_fd: 0,
        btf_key_type_id: 0,
        btf_value_type_id: 0,
        btf_vmlinux_value_type_id: 0,
        inner_map_fd: 0,
        map_extra: 0,
        numa_node: 0,
        map_ifindex: 0,
    };

    let mut map = Map::create(MapType::Hash, Option::<&str>::None, 4, 8, 8, &opts)
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

#[test]
fn test_object_usdt() {
    bump_rlimit_mlock();

    let mut obj = get_test_object("usdt.bpf.o");
    let prog = obj
        .prog_mut("handle__usdt")
        .expect("Failed to find program");

    let path = std::env::current_exe().expect("Failed to find executable name");
    let _link = prog
        .attach_usdt(
            unsafe { libc::getpid() },
            &path,
            "test_provider",
            "test_function",
        )
        .expect("Failed to attach prog");

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    let map = obj.map("ringbuf").expect("Failed to get ringbuf map");

    static mut V: i32 = 0;
    fn callback(data: &[u8]) -> i32 {
        let mut value: i32 = 0;
        plain::copy_from_bytes(&mut value, data).expect("Wrong size");

        unsafe {
            V = value;
        }

        0
    }

    builder.add(map, callback).expect("Failed to add ringbuf");
    let mgr = builder.build().expect("Failed to build");

    // Define a USDT probe point and exercise it as we are attaching to self.
    probe!(test_provider, test_function, 1);

    mgr.consume().expect("Failed to consume ringbuf");

    unsafe { assert_eq!(V, 1) };
}
