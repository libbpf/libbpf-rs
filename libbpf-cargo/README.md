![CI](https://github.com/libbpf/libbpf-rs/workflows/Rust/badge.svg?branch=master)
[![rustc](https://img.shields.io/badge/rustc-1.63+-blue.svg)](https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html)

# libbpf-cargo

[![crates.io badge](https://img.shields.io/crates/v/libbpf-cargo.svg)](https://crates.io/crates/libbpf-cargo)

Helps you build and develop BPF programs with standard Rust tooling.

- [Changelog](CHANGELOG.md)

To use in your project, add into your `Cargo.toml`:
```toml
[build-dependencies]
libbpf-cargo = "0.20"
```

See [full documentation here](https://docs.rs/libbpf-cargo).

This crate adheres to Cargo's [semantic versioning rules][cargo-semver].

## Contributing

We welcome all contributions! Please see the [contributor's
guide](../CONTRIBUTING.md) for more information.

[cargo-semver]: https://doc.rust-lang.org/cargo/reference/resolver.html#semver-compatibility
