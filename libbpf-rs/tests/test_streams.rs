//! Tests for BPF program streams (stdout/stderr).

use std::io::Read;

use libbpf_rs::ProgramInput;
use test_tag::tag;

use crate::common::get_prog_mut;
use crate::common::get_test_object;

/// Test that we can read from a BPF program's stdout stream.
///
/// This test loads a BPF program that triggers the streams mechanism,
/// runs it, and then attempts to read from the stdout stream.
#[tag(root)]
#[test]
#[ignore = "requires kernel with BPF streams support (6.17+)"]
fn test_stream_stdout_read() {
    let mut obj = get_test_object("stream.bpf.o");
    let prog = get_prog_mut(&mut obj, "trigger_streams");

    let input = ProgramInput::default();
    let _output = prog.test_run(input).unwrap();

    let mut stdout = prog.stdout();
    let mut buf = [0u8; 1024];

    let result = stdout.read(&mut buf);
    let cnt = result.unwrap();
    assert_eq!(&buf[..cnt], b"stdout");
}

#[tag(root)]
#[test]
#[ignore = "requires kernel with BPF streams support (6.17+)"]
fn test_stream_stderr_read() {
    let mut obj = get_test_object("stream.bpf.o");
    let prog = get_prog_mut(&mut obj, "trigger_streams");

    let input = ProgramInput::default();
    let _output = prog.test_run(input).unwrap();

    let mut stderr = prog.stderr();
    let mut buf = [0u8; 1024];

    let result = stderr.read(&mut buf);
    let cnt = result.unwrap();
    assert_eq!(&buf[..cnt], b"stderr");
}
