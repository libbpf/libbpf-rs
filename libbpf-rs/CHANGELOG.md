0.22.1
------
- Introduced `Xdp` type for working with XDP programs
- Fixed handling of autocreate maps with `Object` type


0.22.0
------
- Reworked `Error` type:
  - Replaced `enum` with data variants with `struct` hiding internal structure
  - Added support for chaining of errors
  - Overhauled how errors are displayed
- Overhauled `query::ProgramInfo` and `query::ProgInfoIter` to make them more
  readily usable
- Added `Btf::from_vmlinux` constructor and adjusted `Btf::from_path` to work
  with both raw and ELF files
- Reworked `ObjectBuilder`:
  - Made `name` method fallible
  - Adjusted `opts` to return a reference to `libbpf_sys::bpf_object_open_opts`
  - Removed object name argument from `open_memory` constructor
  - Added `pin_root_path` setter
- Added `AsRawLibbpf` trait as a unified way to retrieve `libbpf` equivalents
  for `libbpf-rs` objects
- Added `Map::update_batch` method
- Implemented `Send` for `Link`
- Bumped minimum Rust version to `1.65`
- Updated `bitflags` dependency to `2.0`


0.21.2
------
- Enabled key iteration on `MapHandle` objects (formerly possible only on `Map`
  objects)
- Bumped minimum Rust version to `1.64`


0.21.1
------
- Fixed build failures on 32 bit x86 and aarch32


0.21.0
------
- Added `TcHook::get_handle` and `TcHook::get_priority` methods for restoring
  TcHook object
- Added `Program::get_fd_by_id` and `Program::get_id_by_fd` methods for restoring
  bpf management data
- Added `Map::is_pinned` and `Map::get_pin_path` methods for getting map pin status
- Added `Program::attach_iter` for attaching of programs to an iterator
- Added `Map::delete_batch` method for bulk deletion of elements
- Added read/update/delete support for queue and stack `Map` types
- Added a new `MapHandle` which provides most functionality previously found in
  `Map`
- Removed support for creating `Map` objects standalone (i.e. maps not created
  by libbpf)
- Removed various `<object-type>::fd()` methods in favor of
  `<object-type>::as_fd()`
- Improved `btf_type_match!` macro, adding support for most of Rust's `match`
  capabilities
- Added `skel` module exposing skeleton related traits
- Fixed issue where instances of `Map` created or opened without going through
  `Object` would leak file descriptors
- Fixed potential Uprobe attachment failures on optimized builds caused by
  improper `libbpf_sys::bpf_object_open_opts` object initialization
- Adjusted various methods to work with `BorrowedFd` instead of raw file
  descriptors
- Made `RingBufferBuilder::add` enforce that `self` cannot outlive the maps
  passed into it
- Adjusted `Error::System` variant textual representation to include `errno`
  string


0.20.1
------
- Added bindings for BTF via newly introduced `btf` module
- Added `Map` constructors from pinned paths and from map id
- Added `Map::as_libbpf_bpf_map_ptr` and `Object::as_libbpf_bpf_object_ptr`
  accessors
- Added `MapInfo` type as a convenience wrapper around `bpf_map_info`
  - Added `Map::info` to `Map` to make it easier to derive `MapInfo` from a
    `Map` instance
- Added `set_log_level`, `log_level`, and `autoload` methods to `OpenProgram`
- Removed deprecated `Link::get_fd` method
- Bumped minimum Rust version to `1.63`


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
