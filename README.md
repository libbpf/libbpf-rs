![Rust](https://github.com/danobi/libbpf-rs/workflows/Rust/badge.svg?branch=master)

WARNING: The API is not stable and is subject to breakage. Any breakage will
include a minor version bump pre-1.0 and a major version bump post-1.0.
[Semantic versioning](https://semver.org/) will be followed post-1.0 release.

# libbpf-rs

Idiomatic rust wrapper around
[libbpf](https://github.com/libbpf/libbpf)

To use in your project, add into your `Cargo.toml`:

```toml
[dependencies]
libbpf-rs = "0.1"
```

# libbpf-cargo

Cargo subcommand to build bpf programs

To use:

```
$ cargo install libbpf-cargo
$ cargo libbpf --help
```

XXX link to docs.rs

See [full documentation here](google.com).
