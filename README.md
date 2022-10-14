![CI](https://github.com/libbpf/libbpf-rs/workflows/Rust/badge.svg?branch=master)
[![rustc](https://img.shields.io/badge/rustc-1.59+-blue.svg)](https://blog.rust-lang.org/2022/02/24/Rust-1.59.0.html)

WARNING: The API is not stable and is subject to breakage. Any breakage will
include a minor version bump pre-1.0 and a major version bump post-1.0.
[Semantic versioning](https://semver.org/) will be followed post-1.0 release.

# libbpf-rs

[![crates.io badge](https://img.shields.io/crates/v/libbpf-rs.svg)](https://crates.io/crates/libbpf-rs)

Idiomatic rust wrapper around
[libbpf](https://github.com/libbpf/libbpf)

To use in your project, add into your `Cargo.toml`:

```toml
[dependencies]
libbpf-rs = "0.18"
```

See [full documentation here](https://docs.rs/libbpf-rs).

# libbpf-cargo

[![crates.io badge](https://img.shields.io/crates/v/libbpf-cargo.svg)](https://crates.io/crates/libbpf-cargo)

Helps you build and develop eBPF programs with standard rust tooling

To use in your project, add into your `Cargo.toml`:

```toml
[build-dependencies]
libbpf-cargo = "0.12"
```

See [full documentation here](https://docs.rs/libbpf-cargo).

## Contributing

We welcome all contributions! Please see the [contributor's
guide](CONTRIBUTING.md) for more information.
