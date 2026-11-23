//! Tests for `Ring` and `RingBuffer::wait`.

use std::ffi::OsStr;
use std::os::fd::AsFd as _;
use std::os::fd::AsRawFd as _;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libbpf_rs::MapHandle;
use libbpf_rs::MapType;
use libbpf_rs::Object;
use libbpf_rs::Ring;
use libbpf_rs::RingBufferBuilder;
use test_tag::tag;

use crate::common::get_map;
use crate::common::get_prog_mut;
use crate::common::open_test_object;

/// Size of a record in the ring buffer: an 8-byte header and a `u64`.
const RECORD_SIZE: usize = 16;

/// Load the test program, which writes a record with the next sequence
/// number to its ring buffer for every `getppid` system call made by the
/// current thread. Sequence numbers start at zero.
fn test_object(overwritable: bool) -> Object {
    let mut obj = open_test_object("ring.bpf.o");

    let tid = unsafe { libc::gettid() } as u32;
    let mut rodata = obj
        .maps_mut()
        .find(|map| map.name().to_string_lossy().ends_with(".rodata"))
        .expect("failed to find `.rodata` map");
    let () = rodata
        .set_initial_value(&tid.to_ne_bytes())
        .expect("failed to set `target_tid`");

    if overwritable {
        let mut map = obj
            .maps_mut()
            .find(|map| map.name() == OsStr::new("ring"))
            .expect("failed to find `ring` map");
        let () = map
            .set_map_flags(libbpf_sys::BPF_F_RB_OVERWRITE)
            .expect("failed to set map flags");
    }
    obj.load().expect("failed to load object")
}

/// Make the test program write `cnt` records.
fn trigger(cnt: usize) {
    for _ in 0..cnt {
        let _ppid = unsafe { libc::getppid() };
    }
}

/// Retrieve the sequence number of a record.
fn seq(data: &[u8]) -> usize {
    u64::from_ne_bytes(data.try_into().expect("wrong size")) as usize
}

/// Check whether `poll(2)` reports the ring as readable.
fn readable(ring: &Ring) -> bool {
    let mut pfd = libc::pollfd {
        fd: ring.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
    assert!(ret >= 0, "poll failed");
    ret == 1
}

/// Check that a `Ring` can only be created for a ring buffer map.
#[tag(root)]
#[test]
fn test_ring_wrong_map_type() {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>(),
        ..Default::default()
    };
    let map = MapHandle::create(MapType::Array, Some("array"), 4, 4, 1, &opts)
        .expect("failed to create map");
    let _err = Ring::new(&map).expect_err("created ring for array map");
}

/// Check that records are returned in order, that several can be held at
/// once, and that only a release consumes them.
#[tag(root)]
#[test]
fn test_ring_next_and_release() {
    let mut obj = test_object(false);
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getppid");
    let _link = prog.attach().expect("failed to attach prog");
    let map = get_map(&obj, "ring");
    let mut ring = Ring::new(&map).expect("failed to create ring");

    assert!(ring.next().is_none());
    assert!(!ring.release());

    let () = trigger(3);

    let records = (&ring).collect::<Vec<_>>();
    assert_eq!(records.len(), 3);
    for (i, record) in records.iter().enumerate() {
        assert_eq!(seq(record), i);
        assert_eq!(record.pos(), i * RECORD_SIZE);
    }
    assert!(!ring.invalidated());
    // Nothing is consumed yet.
    assert_eq!(ring.consumer_pos(), 0);

    assert!(!ring.release());
    assert_eq!(ring.consumer_pos(), 3 * RECORD_SIZE);
    assert!(ring.next().is_none());
}

/// Check that a rewind makes `next` return the same records again, and
/// that a release consumes only the records returned so far.
#[tag(root)]
#[test]
fn test_ring_rewind_and_partial_release() {
    let mut obj = test_object(false);
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getppid");
    let _link = prog.attach().expect("failed to attach prog");
    let map = get_map(&obj, "ring");
    let mut ring = Ring::new(&map).expect("failed to create ring");

    let () = trigger(3);

    assert_eq!(seq(&ring.next().expect("no record")), 0);
    assert_eq!(seq(&ring.next().expect("no record")), 1);
    let () = ring.rewind();
    assert_eq!(ring.consumer_pos(), 0);

    assert_eq!(seq(&ring.next().expect("no record")), 0);
    // Two more records are waiting.
    assert!(ring.release());
    assert_eq!(ring.consumer_pos(), RECORD_SIZE);
    assert_eq!(seq(&ring.next().expect("no record")), 1);
}

/// Check the loop from the documentation, and that the ring's file
/// descriptor tells whether there is data.
#[tag(root)]
#[test]
fn test_ring_consume_loop() {
    let mut obj = test_object(false);
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getppid");
    let _link = prog.attach().expect("failed to attach prog");
    let map = get_map(&obj, "ring");
    let mut ring = Ring::new(&map).expect("failed to create ring");

    assert!(!readable(&ring));
    let () = trigger(5);
    assert!(readable(&ring));

    let mut next = 0;
    loop {
        for record in &ring {
            assert_eq!(seq(&record), next);
            next += 1;
        }
        if !ring.release() {
            break
        }
    }
    assert_eq!(next, 5);
    assert_eq!(ring.consumer_pos(), ring.producer_pos());
    assert_eq!(ring.avail_data_size(), 0);
    assert!(!readable(&ring));
}

/// Check that `RingBuffer::wait` reports data without consuming it.
#[tag(root)]
#[test]
fn test_ring_buffer_wait() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);

    let mut obj = test_object(false);
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getppid");
    let _link = prog.attach().expect("failed to attach prog");
    let map = get_map(&obj, "ring");

    let mut builder = RingBufferBuilder::new();
    let _builder = builder
        .add(&map, |_data| {
            let _cnt = CALLS.fetch_add(1, Ordering::SeqCst);
            0
        })
        .expect("failed to add ringbuf");
    let ringbuf = builder.build().expect("failed to build ringbuf");

    assert_eq!(ringbuf.wait(Duration::ZERO).expect("failed to wait"), 0);
    let () = trigger(1);
    assert_eq!(
        ringbuf
            .wait(Duration::from_secs(1))
            .expect("failed to wait"),
        1
    );
    assert_eq!(CALLS.load(Ordering::SeqCst), 0);

    let () = ringbuf.consume().expect("failed to consume ringbuf");
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(ringbuf.wait(Duration::ZERO).expect("failed to wait"), 0);
}

/// Check that only the most recent records of an overwritable ring buffer
/// are returned.
#[tag(root)]
#[test]
#[ignore = "requires kernel with BPF_F_RB_OVERWRITE support (6.19+)"]
fn test_ring_overwritable() {
    let mut obj = test_object(true);
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getppid");
    let _link = prog.attach().expect("failed to attach prog");
    let map = get_map(&obj, "ring");
    let mut ring = Ring::new(&map).expect("failed to create ring");
    let per_ring = ring.size() / RECORD_SIZE;

    // Fill the ring buffer three times over.
    let () = trigger(3 * per_ring);
    assert!(readable(&ring));

    let mut seqs = Vec::new();
    loop {
        for record in &ring {
            if ring.invalidated() {
                break
            }
            let () = seqs.push(seq(&record));
        }
        if !ring.release() {
            break
        }
    }
    // The kernel never lets records fill the whole ring buffer, so fewer
    // than `per_ring` are left.
    let cnt = seqs.len();
    assert!(cnt > 0 && cnt < per_ring, "{cnt}");
    // They are the most recent ones, without gaps.
    assert!(seqs.iter().copied().eq(3 * per_ring - cnt..3 * per_ring));
    assert_eq!(ring.consumer_pos(), ring.producer_pos());
    assert!(!readable(&ring));
}

/// Check that an overwritable ring buffer can be dumped without consuming
/// it.
#[tag(root)]
#[test]
#[ignore = "requires kernel with BPF_F_RB_OVERWRITE support (6.19+)"]
fn test_ring_overwritable_dump() {
    let mut obj = test_object(true);
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getppid");
    let _link = prog.attach().expect("failed to attach prog");
    let map = get_map(&obj, "ring");
    let mut ring = Ring::new(&map).expect("failed to create ring");
    let per_ring = ring.size() / RECORD_SIZE;

    let () = trigger(3 * per_ring);

    let dump = |ring: &Ring| ring.map(|record| seq(&record)).collect::<Vec<_>>();

    let seqs = dump(&ring);
    assert!(!ring.invalidated());
    let cnt = seqs.len();
    assert!(cnt > 0 && cnt < per_ring, "{cnt}");
    assert!(seqs.iter().copied().eq(3 * per_ring - cnt..3 * per_ring));

    // A rewind consumes nothing, so `next` returns the same records again.
    let () = ring.rewind();
    assert_eq!(ring.consumer_pos(), 0);
    assert_eq!(dump(&ring), seqs);
}

/// Check that `Ring::invalidated` notices that a record got overwritten.
#[tag(root)]
#[test]
#[ignore = "requires kernel with BPF_F_RB_OVERWRITE support (6.19+)"]
fn test_ring_overwritable_invalidated() {
    let mut obj = test_object(true);
    let prog = get_prog_mut(&mut obj, "handle__sys_enter_getppid");
    let _link = prog.attach().expect("failed to attach prog");
    let map = get_map(&obj, "ring");
    let mut ring = Ring::new(&map).expect("failed to create ring");
    let per_ring = ring.size() / RECORD_SIZE;

    let () = trigger(1);

    let record = ring.next().expect("no record");
    assert!(!ring.invalidated());
    assert_eq!(seq(&record), 0);

    // Overwrite the record that was returned.
    let () = trigger(2 * per_ring);
    assert!(ring.invalidated());
    // The record is a copy, so it is unchanged.
    assert_eq!(seq(&record), 0);

    // The records that replaced it are waiting.
    assert!(ring.release());
    assert!(!ring.invalidated());
    assert!(seq(&ring.next().expect("no record")) > per_ring);
}
