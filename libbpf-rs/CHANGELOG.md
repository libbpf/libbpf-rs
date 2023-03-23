Unreleased
----------
- Added `Map::as_libbpf_bpf_map_ptr` and `Object::as_libbpf_bpf_object_ptr`
  accessors


0.20.0
------
- Added support for USDT probes
- Added BPF linker support with new `Linker` type
- Added `Program::attach_uprobe_with_opts` for attaching Uprobes with additional
  options
- Added `tproxy` example
- Added option to `RingBuffer::poll` to block indefinitely
- Added support for querying BPF program type using `OpenProgram::prog_type`
- Added support for retrieving a BPF program's instructions using
  `OpenProgram::insns` & `Program::insns`
- Added `MapType::is_supported`, `ProgramType::is_supported`, and
  `ProgramType::is_helper_supported` methods
- Added `PerfBuffer::as_libbpf_perf_buffer_ptr` to access underlying
  `libbpf-sys` object
- Adjusted various `Map` methods to work on shared receivers
- Fixed `Link::open` constructor to be a static method
- Fixed unsoundness in skeleton logic caused by aliased `Box` contents
- Implemented `Send` for `PerfBuffer` and `RingBuffer`
- Made more types implement `Clone` and `Debug`
- Run leak sanitizer in CI
- Updated various dependencies


0.19.1
------
- Initial documented release
