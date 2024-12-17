[![CI](https://github.com/libbpf/libbpf-rs/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/libbpf/libbpf-rs/actions/workflows/test.yml)
[![rustc](https://img.shields.io/badge/rustc-1.71+-blue.svg)](https://blog.rust-lang.org/2023/07/13/Rust-1.71.0.html)

# libbpf-rs

[![crates.io badge](https://img.shields.io/crates/v/libbpf-rs.svg)](https://crates.io/crates/libbpf-rs)

Idiomatic Rust wrapper around [libbpf](https://github.com/libbpf/libbpf).

- [Changelog](CHANGELOG.md)

To use in your project, add into your `Cargo.toml`:
```toml
[dependencies]
libbpf-rs = "=0.25.0-beta.1"
```

See [full documentation here](https://docs.rs/libbpf-rs).

This crate adheres to Cargo's [semantic versioning rules][cargo-semver]. At a
minimum, it builds with the most recent Rust stable release minus five minor
versions ("N - 5"). E.g., assuming the most recent Rust stable is `1.68`, the
crate is guaranteed to build with `1.63` and higher.

## Contributing

We welcome all contributions! Please see the [contributor's
guide](../CONTRIBUTING.md) for more information.

[cargo-semver]: https://doc.rust-lang.org/cargo/reference/resolver.html#semver-compatibility
