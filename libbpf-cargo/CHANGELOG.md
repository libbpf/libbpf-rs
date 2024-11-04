0.24.7
------
- Fixed handling of empty unions in BPF types


0.24.6
------
- Fixed incorrect Cargo environment variable query when used in build
  script context


0.24.4
------
- Adjusted skeleton generation code to work around `libbpf` forward
  compatibility issue when an old system `libbpf` is being used instead
  of the vendored copy


0.24.3
------
- Silenced possible `clippy` reported warnings in generated skeleton
  when BPF object file does not contain any maps


0.24.2
------
- Fixed panic on "open" of skeleton with `kconfig` map


0.24.1
------
- Fixed missing BPF object cleanup after skeleton destruction


0.24.0
------
- Reworked generated skeletons to contain publicly accessible maps and
  program members, no longer requiring method calls
- Adjusted skeleton creation logic to generate Rust types for all types
  available in BPF
- Renamed module for generated Rust types from `<project>_types` to just `types`
- Renamed generated `struct_ops` type to `StructOps` and moved it out of `types`
  module
- Fixed Rust code generation logic to properly create `Default` impl for arrays
  of pointers


0.23.3
------
- Fixed generation of `Default` impl in presence of large padding arrays


0.23.1
------
- Added "import injection" escape hatch to generated skeletons


0.23.0
------
- Removed `novendor` feature in favor of having disableable default
  feature
- Added support for `struct_ops` shadow objects for generated skeletons
- Added support for handling custom data sections in generated skeletons
- Adjusted `SkeletonBuilder::clang_args` to accept an iterator of
  arguments instead of a string
- Added `--clang-args` argument to `make` and `build` sub-commands
- Put all generated types into single `<project>_types` module as opposed to
  having multiple modules for various sections (`.bss`, `.rodata`, etc.)
- Fixed potential naming issues by escaping reserved keywords used in
  identifiers
- Fixed potential unsoundness issues in generated skeletons by wrapping "unsafe"
  type in `MaybeUninit`
- Added pointer based ("raw") access to datasec type to generated skeletons
- Added better handling for bitfields to code generation logic
- Updated `libbpf-sys` dependency to `1.4.0`
- Bumped minimum Rust version to `1.71`


0.22.0
------
- Adjusted skeleton creation logic to generate shared and exclusive datasec
  accessor functions
- Removed `Error` enum in favor of `anyhow::Error`
- Bumped minimum Rust version to `1.65`


0.21.2
------
- Added `Default` impl for generated `struct` types containing pointers
- Fixed handling of function prototype type declaration inference in BTF and
  skeleton generation
- Improved error reporting in build script usage
- Bumped minimum Rust version to `1.64`


0.21.1
------
- Adjusted named padding members in generated types to have `pub` visibility


0.21.0
------
- Adjusted skeleton generation code to ensure implementation of `libbpf-rs`'s
  `SkelBuilder`, `OpenSkel`, and `Skel` traits
- Improved error reporting on BPF C file compilation failure


0.20.1
------
- Switched over to using `libbpf-rs`'s BTF support internally for skeleton
  generation
- Fixed potential build failures on systems defaulting to stack
  protector usage by passing `-fno-stack-protector` to `clang`


0.20.0
------
- Fixed mismatch in size of generated types with respect to corresponding C
  types
- Fixed generated skeleton potentially being unstable (changing each time)
- Implemented `Sync` for generated skeletons
- Made formatting using `rustfmt` optional
- Updated various dependencies


0.19.1
------
- Initial documented release
