//! Tests for BPF arena global variables.
//!
//! Arena globals are only reachable through a skeleton, so unlike the
//! remaining tests these work with one instead of with
//! [`Object`][libbpf_rs::Object] directly.

use std::mem::MaybeUninit;

use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::ProgramInput;

use test_tag::tag;

#[allow(dead_code)]
mod arena {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/bin/arena.skel.rs"
    ));
}

use arena::ArenaSkelBuilder;


/// Check that `__arena` globals are accessible through the skeleton both
/// before and after load, and that the BPF program sees the very same
/// memory.
#[tag(root)]
#[test]
fn test_arena_globals() {
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = ArenaSkelBuilder::default()
        .open(&mut open_object)
        .expect("failed to open skeleton");

    {
        let data = open_skel
            .maps
            .arena_data
            .as_deref_mut()
            .expect("arena globals are not accessible before load");
        assert_eq!(data.counter, 0);
        assert_eq!(data.sum, 0);

        // Adjusting globals before load has to be reflected in the arena
        // afterwards.
        data.counter = 41;
        data.sum = 100;
    }

    let skel = open_skel.load().expect("failed to load skeleton");

    {
        // Note that globals live at the end of the arena, so reading
        // back what we set also covers the offset calculation.
        let data = skel
            .maps
            .arena_data
            .as_deref()
            .expect("arena globals are not accessible after load");
        assert_eq!(data.counter, 41);
        assert_eq!(data.sum, 100);
    }

    let input = ProgramInput::default();
    let output = skel
        .progs
        .bump_arena_globals
        .test_run(input)
        .expect("failed to run program");
    assert_eq!(output.return_value, 0);

    // Modifications made by the program have to be visible to us.
    let data = skel
        .maps
        .arena_data
        .as_deref()
        .expect("arena globals are not accessible after run");
    assert_eq!(data.counter, 42);
    assert_eq!(data.sum, 110);
}
