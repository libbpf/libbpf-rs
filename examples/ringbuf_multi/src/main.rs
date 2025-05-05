// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use core::time::Duration;
use std::ffi::c_int;
use std::mem::MaybeUninit;

use plain::Plain;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Result;

mod ringbuf_multi {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/ringbuf_multi.skel.rs"
    ));
}

use ringbuf_multi::*;

unsafe impl Plain for types::sample {}

fn process_sample(ring: c_int, data: &[u8]) -> i32 {
    let s = plain::from_bytes::<types::sample>(data).unwrap();

    match s.seq {
        0 => {
            assert_eq!(ring, 1);
            assert_eq!(s.value, 333);
            0
        }
        1 => {
            assert_eq!(ring, 2);
            assert_eq!(s.value, 777);
            0
        }
        _ => unreachable!(),
    }
}

fn main() -> Result<()> {
    let skel_builder = RingbufMultiSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    let bss = skel
        .maps
        .bss_data
        .as_deref_mut()
        .expect("`bss` is not memory mapped");

    // Only trigger BPF program for current process.
    let pid = unsafe { libc::getpid() };
    bss.pid = pid;

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.ringbuf1, |data| process_sample(1, data))
        .expect("failed to add ringbuf");
    builder
        .add(&skel.maps.ringbuf2, |data| process_sample(2, data))
        .expect("failed to add ringbuf");
    let ringbuf = builder.build().unwrap();

    let () = skel.attach()?;
    let bss = skel
        .maps
        .bss_data
        .as_deref_mut()
        .expect("`bss` is not memory mapped");

    // trigger few samples, some will be skipped
    bss.target_ring = 0;
    bss.value = 333;
    let _pgid = unsafe { libc::getpgid(pid) };

    // skipped, no ringbuf in slot 1
    bss.target_ring = 1;
    bss.value = 555;
    let _pgid = unsafe { libc::getpgid(pid) };

    bss.target_ring = 2;
    bss.value = 777;
    let _pgid = unsafe { libc::getpgid(pid) };

    // poll for samples, should get 2 ringbufs back
    let n = ringbuf.poll_raw(Duration::MAX);
    assert_eq!(n, 2);
    println!("successfully polled {n} samples");

    // expect extra polling to return nothing
    let n = ringbuf.poll_raw(Duration::from_secs(0));
    assert!(n == 0, "{n}");
    Ok(())
}
