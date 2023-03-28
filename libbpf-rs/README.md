![CI](https://github.com/libbpf/libbpf-rs/workflows/Rust/badge.svg?branch=master)
[![rustc](https://img.shields.io/badge/rustc-1.63+-blue.svg)](https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html)

WARNING: The API is not stable and is subject to breakage. Any breakage will
include a minor version bump pre-1.0 and a major version bump post-1.0.
[Semantic versioning](https://semver.org/) will be followed post-1.0 release.

# libbpf-rs

[![crates.io badge](https://img.shields.io/crates/v/libbpf-rs.svg)](https://crates.io/crates/libbpf-rs)

Idiomatic Rust wrapper around [libbpf](https://github.com/libbpf/libbpf).

- [Changelog](CHANGELOG.md)

To use in your project, add into your `Cargo.toml`:
```toml
[dependencies]
libbpf-rs = "0.20"
```

See [full documentation here](https://docs.rs/libbpf-rs).

## Contributing

We welcome all contributions! Please see the [contributor's
guide](../CONTRIBUTING.md) for more information.
