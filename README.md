WARNING: this repo under heavy development. A minimal
prototype will be ready to use and uploaded to crates.io by
June 2020.

# libbpf-rs

Idiomatic rust wrapper around
[libbpf](https://github.com/libbpf/libbpf)

To use in your project, add into your `Cargo.toml`:

```toml
# ...
[dependencies]
libbpf-rs = "0.1"
# ...
```

# libbpf-cargo

Cargo subcommand to build bpf programs

To use:

```
$ cargo install libbpf-cargo
$ cargo libbpf --help
```

`libbpf-cargo` also provides some config options via package metadata
in your package `Cargo.toml`:

```toml
# ...
[package.metadata.libbpf]
# path relative to package Cargo.toml to search for bpf progs
# default=<manifest_directory>/src/bpf
prog_dir = "src/other_bpf_dir"

# path relative to workspace target directory to place compiled bpf progs
# default=<target_dir>/bpf
target_dir = "other_target_dir"
# ...
```
