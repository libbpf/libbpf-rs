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
