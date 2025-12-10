//! Tests for BPF program streams (stdout/stderr).

mod common;

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
#[ignore]
fn test_stream_stdout_read() {
    let mut obj = get_test_object("stream.bpf.o");
    let prog = get_prog_mut(&mut obj, "trigger_streams");

    let input = ProgramInput::default();
    let _output = prog.test_run(input).unwrap();

    let mut stdout = prog.stdout();
    let mut buf = [0u8; 1024];

    // The read itself should succeed and return 0 bytes
    let result = stdout.read(&mut buf);
    assert!(
        result.is_ok(),
        "Failed to read from stdout stream: {:?}",
        result.err()
    );

    let len = result.unwrap();
    assert!(len == 0, "Found {len} characters in stdout stream");
}

#[tag(root)]
#[test]
#[ignore]
fn test_stream_stderr_read() {
    let mut obj = get_test_object("stream.bpf.o");
    let prog = get_prog_mut(&mut obj, "trigger_streams");

    let input = ProgramInput::default();
    let _output = prog.test_run(input).unwrap();

    let mut stderr = prog.stderr();
    let mut buf = [0u8; 1024];

    // The read should successfully read a non-zero amount of bytes
    let result = stderr.read(&mut buf);
    assert!(
        result.is_ok(),
        "Failed to read from stderr stream: {:?}",
        result.err()
    );

    assert!(result.unwrap() != 0, "No output from stderr stream");
}
