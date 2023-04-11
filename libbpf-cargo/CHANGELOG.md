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
